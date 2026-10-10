"""DRAFT explicit owned worker for aggregate8GiB/offline Cargo; never auto launches."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess
import time

HERE = pathlib.Path(__file__).resolve().parent
IMAGE_BYTES = 8 * 1024**3
RESOURCES = {'cpu.max': '200000 100000', 'memory.max': str(4 * 1024**3), 'pids.max': '128'}
VERIFIED_FENCES = {}


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def file_identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_uid, value.st_nlink, value.st_mode, value.st_gid)


def file_hash(path, maximum_bytes=256 * 1024**2, maximum_seconds=30):
    path = pathlib.Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid not in [0, 1001] or before.st_size > maximum_bytes:
        raise ValueError('bounded regular single-link hash input required')
    prior = VERIFIED_FENCES.get(str(path))
    if prior and prior['kind'] == 'file' and prior['identity'] == list(file_identity(before)):
        # Reuse only this parent's already-hashed exact material identity.
        return prior['sha256']
    started = time.monotonic()
    value = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as source:
        if file_identity(os.fstat(source.fileno())) != file_identity(before): raise ValueError('hash FD identity changed')
        remaining = before.st_size
        while remaining:
            if time.monotonic() - started > maximum_seconds: raise ValueError('hash time bound')
            block = source.read(min(remaining, 65536))
            if not block: raise ValueError('hash input truncated')
            value.update(block); remaining -= len(block)
        if time.monotonic() - started > maximum_seconds or source.read(1): raise ValueError('hash appended/time bound')
        if file_identity(os.fstat(source.fileno())) != file_identity(before): raise ValueError('hash FD changed during read')
    if file_identity(path.lstat()) != file_identity(before): raise ValueError('hash path changed during read')
    VERIFIED_FENCES[str(path)] = {'path': str(path), 'identity': list(file_identity(before)), 'sha256': value.hexdigest(), 'kind': 'file'}
    return value.hexdigest()


def remember_directory(path):
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in [0, 1001] or path.is_symlink(): raise ValueError('verified directory identity')
    VERIFIED_FENCES[str(path)] = {'path': str(path), 'identity': list(file_identity(value)), 'kind': 'directory'}


def verify_fences(receipt, context, reviewed_context_hash):
    if receipt.get('schema') != 'universe-electrs-full-cargo-admission-v1' or receipt.get('contextSha256') != reviewed_context_hash or receipt.get('controllerSha256') != context['controllerSha256']:
        raise ValueError('parent admission source/context binding')
    records = receipt.get('fences', [])
    if not isinstance(records, list) or not 1 <= len(records) <= 200000: raise ValueError('bounded parent admission fences')
    started = time.monotonic(); seen = set()
    for record in records:
        if time.monotonic() - started > 90: raise ValueError('admission fence time bound')
        path = pathlib.Path(record['path'])
        if record['path'] in seen or not path.is_absolute() or path.is_symlink(): raise ValueError('admission path/link/duplicate drift')
        seen.add(record['path'])
        value = path.lstat()
        if list(file_identity(value)) != record['identity']: raise ValueError('verified input changed after parent admission')
        if record['kind'] == 'file' and not stat.S_ISREG(value.st_mode) or record['kind'] == 'directory' and not stat.S_ISDIR(value.st_mode): raise ValueError('admission type changed')
        if record['kind'] not in ['file', 'directory']: raise ValueError('admission fence kind')
    required = [context['sourceRoot'], context['vendorRoot'], context['wrapperBinary'], context['readRootsFile'], context['toolClosureFile'], str(pathlib.Path(context['sourceRoot']) / 'Cargo.lock')]
    if not set(required) <= seen: raise ValueError('required input admission fence absent')
    return {'verifiedUnchangedInputs': len(records), 'rehashRepeated': False}


def read_json(path, expected, maximum=8 * 1024**2):
    if file_hash(path, maximum) != expected: raise ValueError('reviewed JSON raw hash drift')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source: raw = source.read(maximum + 1)
    if len(raw) > maximum or hashlib.sha256(raw).hexdigest() != expected: raise ValueError('JSON changed after hash')
    return json.loads(raw)


def bounded_bytes(path, maximum):
    expected = file_hash(path, maximum)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source: raw = source.read(maximum + 1)
    if len(raw) > maximum or hashlib.sha256(raw).hexdigest() != expected: raise ValueError('bounded raw read changed')
    return raw


def root_identity(root):
    value = root.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 1001 or value.st_mode & 0o077:
        raise ValueError('private UID1001 task directory required')


def under(path, root):
    path = pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts or root not in path.parents:
        raise ValueError('exclusive owned child path required')
    for ancestor in [path, *path.parents]:
        if ancestor.is_symlink(): raise ValueError('linked owned child ancestor')
    return path


def context_check(context, root, verify_bytes=True):
    if context.get('schema') != 'universe-electrs-full-cargo-worker-v1': raise ValueError('worker context schema')
    persistent = str(root).startswith('/home/github-runner/.cache/universe-electrs-api-20261009/')
    if persistent:
        cache = load('persistent_task_admission', 'retained-cargo-cache.py'); cache.persistent_root(root); cache.checked_ancestors(root)
        if verify_bytes:
            lease = read_json(root / 'lease.json', context['taskLeaseSha256'], 8192); cache.validate_lease(lease, root)
    elif not re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp/universe-electrs-build-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', str(root)):
        raise ValueError('owned build root namespace')
    if context.get('taskRoot', str(root)) != str(root): raise ValueError('task root binding')
    if not re.fullmatch(r'universe-electrs-build-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', context.get('executionUnit', root.name)):
        raise ValueError('unique execution unit namespace')
    if not re.fullmatch('[0-9a-f]{40}', context.get('sourceSha', '')) or not re.fullmatch('[0-9a-f]{64}', context.get('cargoLockSha256', '')):
        raise ValueError('full source and final lock binding required')
    if context.get('operation') not in ['test-compile', 'test'] or context.get('profile') != 'unchanged-default': raise ValueError('unreviewed Cargo operation')
    paths = {key: under(context[key], root) for key in ['sourceRoot', 'vendorRoot', 'wrapperBinary', 'readRootsFile', 'packageRoot']}
    if persistent and (paths['sourceRoot'] != root / ('source-' + context['sourceSha']) or paths['vendorRoot'] != root / 'vendor'):
        raise ValueError('persistent source snapshots and canonical vendor paths required')
    if paths['sourceRoot'] == paths['vendorRoot'] or paths['sourceRoot'] in paths['vendorRoot'].parents or paths['vendorRoot'] in paths['sourceRoot'].parents:
        raise ValueError('source/vendor separation')
    if context['vendorLockSha256'] != context['cargoLockSha256']:
        raise ValueError('vendor cannot substitute premerge lock')
    root_identity(root)
    if os.getuid() != 1001 or os.getgid() != 1001: raise ValueError('exact owned runner UID/GID required')
    if verify_bytes and context.get('controllerSha256') != file_hash(pathlib.Path(__file__)): raise ValueError('controller source drift')
    for name in ['sourceRoot', 'vendorRoot', 'packageRoot']:
        value = paths[name].lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != 1001 or value.st_mode & 0o022: raise ValueError('owned immutable input root required')
    if context.get('smallProofQualified') is not True or context.get('expandedWrapperQualified') is not True:
        raise ValueError('observed small mount and expanded confinement proof required')
    for name in ['smallProofReceiptSha256', 'wrapperProofReceiptSha256', 'compilerClosureReceiptSha256', 'sourceManifestSha256', 'vendorManifestSha256', 'wrapperBinarySha256', 'readRootsSha256']:
        if not re.fullmatch('[0-9a-f]{64}', context.get(name, '')): raise ValueError('independently reviewed proof hash required')
    if verify_bytes and file_hash(paths['sourceRoot'] / 'Cargo.lock') != context['cargoLockSha256']: raise ValueError('source lock bytes drift')
    if verify_bytes and (file_hash(paths['wrapperBinary']) != context['wrapperBinarySha256'] or file_hash(paths['readRootsFile']) != context['readRootsSha256']):
        raise ValueError('expanded confinement bytes drift')
    if not re.fullmatch('[0-9a-f]{64}', context.get('offlineConfigSha256', '')) or not isinstance(context.get('offlineConfigUtf8'), str) or len(context['offlineConfigUtf8'].encode()) > 16384:
        raise ValueError('bounded immutable offline config')
    if hashlib.sha256(context['offlineConfigUtf8'].encode()).hexdigest() != context['offlineConfigSha256']:
        raise ValueError('offline config content binding')
    environment = context.get('compilerEnvironment', {})
    if set(environment) != {'RUSTC', 'CC', 'CXX', 'AR', 'LIBCLANG_PATH', 'LD_LIBRARY_PATH'}:
        raise ValueError('exact compiler environment keys')
    for value in environment.values():
        if not isinstance(value, str) or len(value) > 1024 or '\n' in value or '\r' in value or not value.startswith('/') or '..' in value:
            raise ValueError('compiler environment path syntax')
    aliases = context.get('toolAliases', {})
    if not isinstance(aliases, dict) or not aliases or len(aliases) > 32:
        raise ValueError('bounded exact tool alias closure')
    for name, target in aliases.items():
        if not re.fullmatch('[a-zA-Z0-9_+.-]{1,64}', name) or not isinstance(target, str) or not target.startswith('/') or '\n' in target or '..' in target:
            raise ValueError('tool alias syntax')
    closure_path = under(context['toolClosureFile'], root)
    if verify_bytes:
        closure = read_json(closure_path, context['toolClosureSha256'])
        validate_tools(context, closure)
    return paths


def validate_tools(context, closure):
    if closure.get('schema') != 'universe-electrs-reviewed-compiler-closure-v1' or closure.get('compilerClosureQualified') is not True:
        raise ValueError('independently reviewed closed compiler manifest required')
    if closure.get('observationReceiptSha256') != context['compilerClosureReceiptSha256']:
        raise ValueError('compiler observation provenance mismatch')
    leaves = closure.get('leaves', [])
    if not isinstance(leaves, list) or not 1 <= len(leaves) <= 128: raise ValueError('tool closure count')
    by_path = {}; total = 0; started = time.monotonic()
    for leaf in leaves:
        if set(leaf) != {'path', 'sha256', 'bytes', 'executable'} or type(leaf['executable']) is not bool or not isinstance(leaf['bytes'], int): raise ValueError('tool leaf exact shape')
        path = pathlib.Path(leaf['path'])
        if str(path.resolve(strict=True)) != leaf['path'] or leaf['path'] in by_path: raise ValueError('tool resolved path/duplicate')
        total += leaf['bytes']
        if total > 2 * 1024**3 or time.monotonic() - started > 90: raise ValueError('closed tool cumulative/time bound')
        if path.stat().st_size != leaf['bytes'] or file_hash(path, maximum_seconds=max(1, 90 - (time.monotonic() - started))) != leaf['sha256']: raise ValueError('closed tool bytes drift')
        if path.stat().st_mode & 0o022 or bool(path.stat().st_mode & 0o111) != leaf['executable']: raise ValueError('closed tool permission drift')
        by_path[leaf['path']] = leaf
    roles = closure.get('roles', {})
    primary = load('full_role_pins', 'confined-build-plan.py').TOOL_PINS
    if set(roles) != set(primary): raise ValueError('complete requested-to-resolved primary roles required')
    for role, (requested, expected) in primary.items():
        resolved = str(pathlib.Path(requested).resolve(strict=True))
        if roles[role] != {'requestedPath': requested, 'resolvedPath': resolved, 'sha256': expected}:
            raise ValueError('primary role requested/resolved/hash drift')
    validate_tool_roles(context, by_path, roles)
    return by_path


def validate_tool_roles(context, by_path, roles=None):
    primary = load('full_primary_tool_pins', 'confined-build-plan.py').TOOL_PINS
    roles = roles or {role: {'requestedPath': path, 'resolvedPath': path, 'sha256': sha} for role, (path, sha) in primary.items()}
    for role, (path, expected) in primary.items():
        resolved = roles[role]['resolvedPath']
        if roles[role]['requestedPath'] != path or roles[role]['sha256'] != expected or resolved not in by_path or by_path[resolved]['sha256'] != expected:
            raise ValueError('observed primary tool pin missing')
    if context['cargoPath'] != roles['cargo']['resolvedPath']: raise ValueError('arbitrary Cargo executable rejected')
    environment = context['compilerEnvironment']
    for key, role in [('RUSTC', 'rustc'), ('CC', 'cc'), ('CXX', 'cxx')]:
        if environment[key] != roles[role]['resolvedPath']: raise ValueError('compiler role mismatches observed authority')
    if environment['AR'] not in by_path or not by_path[environment['AR']]['executable']: raise ValueError('AR outside closed executable leaves')
    for target in context['toolAliases'].values():
        if target not in by_path or not by_path[target]['executable']: raise ValueError('tool alias outside closed executable leaves')
    dirs = {str(pathlib.PurePosixPath(path).parent) for path in by_path}
    if environment['LIBCLANG_PATH'] != str(pathlib.PurePosixPath(roles['libclang']['resolvedPath']).parent) or not set(environment['LD_LIBRARY_PATH'].split(':')) <= dirs:
        raise ValueError('library environment outside closed leaf directories')
    return True


def setup_log_paths(mountpoint):
    # Actual wrapper source owns cargo.stdout/cargo.stderr via O_EXCL.
    return mountpoint / 'wrapper-setup.stdout', mountpoint / 'wrapper-setup.stderr'


def verify_tree(root, manifest, kind, context):
    if kind == 'source':
        if manifest.get('schema') != 'universe-electrs-full-draft-source-v3' or manifest.get('sourceCommit') != context['sourceSha']:
            raise ValueError('frozen source manifest identity')
        digest_key = 'gitSha256'; prefix = ''
    else:
        if manifest.get('schema') != 'universe-electrs-sealed-linux-vendor-v1' or manifest.get('lockSha256') != context['cargoLockSha256']:
            raise ValueError('sealed final-lock vendor manifest identity')
        digest_key = 'sha256'; prefix = 'vendor/'
    entries = manifest.get('files', [])
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100000: raise ValueError('bounded input manifest files')
    expected = {}; total = 0; started = time.monotonic()
    for entry in entries:
        name = entry['path']
        if prefix:
            if not name.startswith(prefix): raise ValueError('vendor prefix mismatch')
            name = name[len(prefix):]
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or name in expected or not name or not re.fullmatch('[0-9a-f]{64}', entry.get(digest_key, '')):
            raise ValueError('input path/checksum contradiction')
        file = under(root / name, root)
        info = file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 1001 or info.st_nlink != 1 or info.st_mode & 0o222 or info.st_size != entry['bytes']:
            raise ValueError('immutable input mode/owner/size')
        total += info.st_size
        if total > 1024**3 or time.monotonic() - started > 120: raise ValueError('input verification total/time bound')
        if file_hash(file, min(256 * 1024**2, 1024**3 - total + info.st_size)) != entry[digest_key]: raise ValueError('input file bytes drift')
        expected[name] = entry[digest_key]
    actual = set(); stack = [root]; count = 0
    while stack:
        current = stack.pop(); remember_directory(current)
        with os.scandir(current) as directory:
            for item in directory:
                count += 1
                if count > 200000 or time.monotonic() - started > 120: raise ValueError('input path enumeration bound')
                if item.is_symlink(): raise ValueError('input tree contains link')
                if item.is_dir(follow_symlinks=False): stack.append(pathlib.Path(item.path))
                elif item.is_file(follow_symlinks=False): actual.add(pathlib.Path(item.path).relative_to(root).as_posix())
                else: raise ValueError('input tree nonregular entry')
    if actual != set(expected): raise ValueError('input tree extras or omissions')
    return {'files': len(actual), 'bytes': total}


def verify_sdk_trees(closure):
    allowed_trees = {load('full_root_policy', 'confined-build-plan.py').RUST_ROOT + '/lib',
                     '/usr/include', '/usr/lib/gcc/x86_64-linux-gnu/13/include', '/usr/lib/gcc/x86_64-linux-gnu/13/include-fixed'}
    trees = closure.get('reviewedReadOnlyTrees', [])
    if not isinstance(trees, list) or len(trees) > 4 or any(path not in allowed_trees for path in trees):
        raise ValueError('overbroad SDK/toolchain read tree')
    # A reviewed tree is not requalified from its pathname or an old digest alone.
    tree_records = closure.get('trees', [])
    if {entry.get('path') for entry in tree_records} != set(trees): raise ValueError('complete observed SDK tree records absent')
    for entry in tree_records:
        if entry.get('links') != [] or entry.get('present') is not True: raise ValueError('SDK linked/missing tree remains unqualified')
        tree = pathlib.Path(entry['path']); files = entry.get('files', [])
        if not isinstance(files, list) or not 1 <= len(files) <= 50000: raise ValueError('SDK tree bound')
        semantic = {'files': sorted(files, key=lambda record: record['relative']), 'links': []}
        encoded = json.dumps(semantic, sort_keys=True, separators=(',', ':')).encode()
        if hashlib.sha256(encoded).hexdigest() != entry.get('treeManifestSha256'): raise ValueError('SDK manifest digest contradiction')
        tree_expected = set(); total = 0; started = time.monotonic()
        for leaf in files:
            path = under(tree / leaf['relative'], tree)
            if str(path) != leaf['path'] or leaf['relative'] in tree_expected: raise ValueError('SDK leaf path contradiction')
            total += leaf['bytes']
            if total > 2 * 1024**3 or time.monotonic() - started > 90: raise ValueError('SDK cumulative/time bound')
            if path.stat().st_size != leaf['bytes'] or file_hash(path) != leaf['sha256']: raise ValueError('SDK bytes drift')
            tree_expected.add(leaf['relative'])
        actual = set(); stack = [tree]; count = 0
        while stack:
            current = stack.pop(); remember_directory(current)
            with os.scandir(current) as directory:
                for item in directory:
                    count += 1
                    if count > 100000 or time.monotonic() - started > 90: raise ValueError('SDK enumeration bound')
                    if item.is_symlink(): raise ValueError('SDK link introduced after observation')
                    if item.is_dir(follow_symlinks=False): stack.append(pathlib.Path(item.path))
                    elif item.is_file(follow_symlinks=False): actual.add(pathlib.Path(item.path).relative_to(tree).as_posix())
                    else: raise ValueError('SDK nonregular entry')
        if actual != tree_expected: raise ValueError('SDK tree extras/omissions')
    return trees, tree_records


def admission(context, root):
    paths = context_check(context, root)
    receipts = {}
    for role, field in [('small', 'smallProofReceipt'), ('wrapper', 'wrapperProofReceipt'), ('source', 'sourceManifest'), ('vendor', 'vendorManifest')]:
        sha_key = {'small': 'smallProofReceiptSha256', 'wrapper': 'wrapperProofReceiptSha256', 'source': 'sourceManifestSha256', 'vendor': 'vendorManifestSha256'}[role]
        receipts[role] = read_json(under(context[field], root), context[sha_key])
    small = receipts['small']
    if small.get('schema') != 'universe-electrs-small-fuse-image-proof-v1' or small.get('actualSmall8MiBCapacityQualified') is not True or small.get('primaryError') is not None or small.get('cleanupErrors') != []:
        raise ValueError('actual successful small proof absent')
    wrapper = receipts['wrapper']
    required_controls = ['landlock', 'networkDenied', 'uringDenied', 'inheritedFdsClosed', 'outsideWriteDenied', 'privateWriteAllowed', 'directCargoCompatible']
    if wrapper.get('schema') != 'universe-electrs-expanded-cargo-confinement-proof-v1' or wrapper.get('binarySha256') != context['wrapperBinarySha256'] or wrapper.get('controls') != {key: True for key in required_controls}:
        raise ValueError('actual expanded confinement controls absent')
    if wrapper.get('sourceSha') != context['sourceSha'] or wrapper.get('wrapperSourceSha256') != context.get('wrapperSourceSha256') or wrapper.get('staticElf') is not True or wrapper.get('compiledWrapper') is not True:
        raise ValueError('actual expanded wrapper source/compile binding absent')
    source = verify_tree(paths['sourceRoot'], receipts['source'], 'source', context)
    vendor = verify_tree(paths['vendorRoot'], receipts['vendor'], 'vendor', context)
    roots_file = paths['readRootsFile']
    raw = bounded_bytes(roots_file, 32768)
    closure = read_json(under(context['toolClosureFile'], root), context['toolClosureSha256'])
    reviewed_roots = closure.get('readRoots', [])
    if not isinstance(reviewed_roots, list) or not 1 <= len(reviewed_roots) <= 128:
        raise ValueError('read root count')
    for entry in reviewed_roots:
        if set(entry) != {'path', 'executable', 'sha256'} or type(entry['executable']) is not bool or not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
            raise ValueError('read root exact shape')
        if len(entry['path']) > 1024 or not entry['path'].startswith('/') or '..' in pathlib.PurePosixPath(entry['path']).parts:
            raise ValueError('read root path bound')
    trees, tree_records = verify_sdk_trees(closure)
    rendered = ''.join(('X' if entry['executable'] else 'R') + ' ' + entry['path'] + '\n' for entry in reviewed_roots).encode()
    if not reviewed_roots or len(reviewed_roots) > 128 or raw != rendered: raise ValueError('read roots differ from closed reviewed manifest')
    # Never render arbitrary read trees from a syntax-only context.
    for entry in reviewed_roots:
        path = entry['path']
        if path in [str(paths['sourceRoot']), str(paths['vendorRoot'])]:
            if entry['executable']: raise ValueError('unreviewed source/vendor executable-tree grant')
            authority = context['sourceManifestSha256'] if path == str(paths['sourceRoot']) else context['vendorManifestSha256']
            if entry['sha256'] != authority: raise ValueError('read source/vendor manifest binding')
        elif path in trees:
            tree = next(value for value in tree_records if value['path'] == path)
            if entry['executable'] or entry['sha256'] != tree['treeManifestSha256']: raise ValueError('SDK read-only/hash binding')
        elif path not in {leaf['path'] for leaf in closure['leaves']} and path not in trees:
            raise ValueError('read root absent from independently closed manifest')
        else:
            leaf = next(value for value in closure['leaves'] if value['path'] == path)
            if entry['sha256'] != leaf['sha256'] or entry['executable'] and not leaf['executable']: raise ValueError('read leaf permission/hash binding')
    return {'source': source, 'vendor': vendor, 'sourceSha': context['sourceSha'], 'lockSha256': context['cargoLockSha256']}


def actual_scope(root, execution_unit):
    guard = load('full_resource_reads', 'locked-cache-readonly.py')
    groups = [line[3:] for line in guard.bounded_read('/proc/self/cgroup', 4096).splitlines() if line.startswith('0::')]
    if len(groups) != 1 or not groups[0].endswith('/' + execution_unit + '.service'): raise ValueError('own full scope unavailable')
    directory = pathlib.Path('/sys/fs/cgroup' + groups[0])
    for name, expected in RESOURCES.items():
        if guard.bounded_read(directory / name, 4096).strip() != expected: raise ValueError('full scope resource mismatch')
    if guard.bounded_read(directory / 'io.weight', 4096).strip() != 'default 1' or os.getpriority(os.PRIO_PROCESS, 0) != 19:
        raise ValueError('full scope nice/IO mismatch')
    nnp = re.findall(r'^NoNewPrivs:\s+([01])$', guard.bounded_read('/proc/self/status', 32768), flags=re.M)
    if nnp != ['0']: raise ValueError('mount setup inherited NNP contradicts reviewed helper path')
    small = load('full_scope_control_tool', 'small-fuse-image-proof.py'); small.pin(small.CTL_TOOL)
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': '/home/github-runner', 'XDG_RUNTIME_DIR': '/run/user/1001', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1001/bus'}
    # Only our exact generated unit is read; no inventory or other unit writes.
    command = [small.CTL_TOOL['path'], '--user', 'show', execution_unit + '.service', '--property=RuntimeMaxUSec', '--property=KillMode', '--property=TimeoutStopUSec']
    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=3, check=False)
    if result.returncode or len(result.stdout) > 4096 or len(result.stderr) > 4096: raise ValueError('own unit property observation unavailable')
    properties = dict(line.split('=', 1) for line in result.stdout.decode('ascii').splitlines())
    if properties != {'RuntimeMaxUSec': '30min', 'KillMode': 'control-group', 'TimeoutStopUSec': '5s'}:
        raise ValueError('own unit lifetime/settlement properties mismatch')
    return {'controlGroup': groups[0], **RESOURCES, 'ioWeight': 1, 'nice': 19}


def image_check(image, expected=None):
    value = image.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 1001 or value.st_nlink != 1 or value.st_size != IMAGE_BYTES:
        raise ValueError('fixed8GiB owned backing image contradiction')
    result = {'device': value.st_dev, 'inode': value.st_ino, 'logicalBytes': value.st_size,
              'allocatedPhysicalBytes': value.st_blocks * 512}
    if expected and any(result[key] != expected[key] for key in ['device', 'inode', 'logicalBytes']): raise ValueError('backing image replaced')
    if result['allocatedPhysicalBytes'] > IMAGE_BYTES: raise ValueError('backing allocated blocks exceed aggregate ceiling')
    return result


def filesystem_check(mountpoint):
    value = os.statvfs(mountpoint)
    total = value.f_blocks * value.f_frsize
    if total <= 0 or total > IMAGE_BYTES: raise ValueError('actual filesystem capacity exceeds8GiB')
    return {'capacityBytes': total, 'availableBytes': value.f_bavail * value.f_frsize}


def set_image_limit():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (IMAGE_BYTES, IMAGE_BYTES))
    if resource.getrlimit(resource.RLIMIT_FSIZE) != (IMAGE_BYTES, IMAGE_BYTES): raise ValueError('daemon backing-file limit unavailable')


def daemon_file_limit(raw):
    rows = re.findall(r'^Max file size\s+([0-9]+)\s+([0-9]+)\s+bytes\s*$', raw, re.M)
    if rows != [(str(IMAGE_BYTES), str(IMAGE_BYTES))]: raise ValueError('actual daemon file size limit unavailable')
    return IMAGE_BYTES


def settle_owned(root, mountpoint, daemon, owned, small, retain_logs=True):
    errors = []; logs = []; current = None
    try: current = small.read_mount(mountpoint)
    except Exception as error: errors.append('mount observation: ' + type(error).__name__)
    if retain_logs and small.same_mount(current, owned):
        for name in ['cargo.stdout', 'cargo.stderr', 'wrapper-setup.stdout', 'wrapper-setup.stderr']:
            path = mountpoint / name
            try:
                if not path.exists(): continue
                fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
                with os.fdopen(fd, 'rb') as incoming:
                    info = os.fstat(incoming.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 1001 or info.st_nlink != 1: raise ValueError('owned log type/identity')
                    raw = incoming.read(4096)
                with (root / ('retained-' + name)).open('xb') as output: output.write(raw)
                logs.append({'name': name, 'capturedBytes': len(raw), 'truncated': info.st_size > len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            except Exception as error: errors.append('log ' + name + ': ' + type(error).__name__)
    if current:
        if not small.same_mount(current, owned): errors.append('unknown mount retained; no unmount')
        else:
            try: small.run_known([small.FUSE_TOOL['path'], '-u', str(mountpoint)], root, 'unmount', {'LANG': 'C', 'PATH': '/usr/bin:/bin'}, 5)
            except Exception as error: errors.append('unmount: ' + type(error).__name__)
    if daemon is not None:
        try:
            code = daemon.wait(timeout=3)
            if code: errors.append('own daemon nonzero: ' + str(code))
        except subprocess.TimeoutExpired:
            try: daemon.terminate()
            except Exception as error: errors.append('own terminate: ' + type(error).__name__)
            try: daemon.wait(timeout=2)
            except Exception as error: errors.append('own settle: ' + type(error).__name__)
        except Exception as error: errors.append('own wait: ' + type(error).__name__)
    try:
        if small.read_mount(mountpoint): errors.append('mount still present')
    except Exception as error: errors.append('final mount observation: ' + type(error).__name__)
    return logs, errors


def settle_parent(root, small):
    marker = root / 'owned-mount.json'; owned = None; errors = []
    try:
        if marker.exists():
            if marker.lstat().st_uid != 1001: raise ValueError('mount marker owner')
            candidate = json.loads(bounded_bytes(marker, 4096))
            small.validate_owned_mount(candidate, root / 'aggregate8GiB.img', root / 'work')
            owned = candidate
    except Exception as error: errors.append('marker: ' + type(error).__name__)
    _, cleanup = settle_owned(root, root / 'work', None, owned, small, retain_logs=False)
    return errors + cleanup


def worker(root, context, parent_admission, reviewed_context_hash):
    verified_inputs = verify_fences(parent_admission, context, reviewed_context_hash)
    paths = context_check(context, root, verify_bytes=False)
    observed_resources = actual_scope(root, context.get('executionUnit', root.name))
    small = load('reviewed_fuse_primitives', 'small-fuse-image-proof.py')
    binding = load('full_runtime_binding', 'helper-runtime-binding.py').bind(context['packageReport'], context['hostReport'])
    for pin in [small.FUSE_TOOL, small.PYTHON]: small.pin(pin)
    private_lib, private_bin = small.stage_group(binding['executionGroups']['fuse2fs'], root / 'private-runtime', paths['packageRoot'], context['packageReport'])
    host_lib, host_bin = small.stage_group(binding['executionGroups']['mke2fsAndExistingMountHelper'], root / 'host-runtime', paths['packageRoot'], context['packageReport'])
    image = root / 'aggregate8GiB.img'; mountpoint = root / 'work'; mountpoint.mkdir(mode=0o700)
    with image.open('xb') as output: output.truncate(IMAGE_BYTES)
    image.chmod(0o600); initial_image = image_check(image)
    config = root / 'private-mke2fs.conf'
    config.write_text('[defaults]\nbase_features = sparse_super,filetype,large_file,ext_attr,dir_index\nblocksize = 4096\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent,dir_nlink,extra_isize\n}\n')
    setup_env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': str(root), 'MKE2FS_CONFIG': str(config)}
    small.run_known([str(host_lib / 'ld-linux-x86-64.so.2'), '--inhibit-cache', '--library-path', str(host_lib), str(host_bin / 'mke2fs'), '-F', '-q', '-t', 'ext4', '-b', '4096', '-m', '0', str(image)], root, 'format', setup_env, 30)
    image_check(image, initial_image)
    daemon = None; owned = None; failure = None; cleanup = []; cargo_exit = None; observation = None
    try:
        with (root / 'fuse.stdout').open('xb') as out, (root / 'fuse.stderr').open('xb') as err:
            command = [str(private_lib / 'ld-linux-x86-64.so.2'), '--inhibit-cache', '--library-path', str(private_lib), str(private_bin / 'fuse2fs'), '-f', '-o', 'rw,nosuid,nodev,fsname=' + str(image) + ',subtype=universe-electrs-proof', str(image), str(mountpoint)]
            daemon = subprocess.Popen(command, env=setup_env, cwd=root, stdin=subprocess.DEVNULL, stdout=out, stderr=err, preexec_fn=set_image_limit)
        until = time.monotonic() + 5
        while time.monotonic() < until:
            if daemon.poll() is not None: raise ValueError('owned daemon exited')
            candidate = small.read_mount(mountpoint)
            if candidate:
                small.validate_owned_mount(candidate, image, mountpoint); owned = candidate; break
            time.sleep(0.05)
        small.validate_owned_mount(owned, image, mountpoint)
        with (root / 'owned-mount.json').open('x') as output: json.dump(owned, output)
        mountpoint.chmod(0o700)
        observed_capacity = filesystem_check(mountpoint)
        maps = small.staged_file_hashes(binding['executionGroups']['fuse2fs'], private_lib, private_bin)
        daemon_proof = small.own_daemon_maps(daemon.pid, root, maps, observed_resources['controlGroup'], os.getuid(), os.getgid())
        reads = load('actual_daemon_limits', 'locked-cache-readonly.py')
        daemon_proof['actualMaxFileBytes'] = daemon_file_limit(reads.bounded_read('/proc/' + str(daemon.pid) + '/limits', 16384))
        # Every compiler-writable directory and logs are physically inside this FS.
        for name in ['cargo-home', 'target', 'tmp', 'home', 'bin']: (mountpoint / name).mkdir(mode=0o700)
        (mountpoint / 'cargo-home' / 'config.toml').write_text(context['offlineConfigUtf8'])
        if file_hash(mountpoint / 'cargo-home' / 'config.toml') != context['offlineConfigSha256']: raise ValueError('offline config drift')
        # Exact alias and environment bytes are reviewed context, not inherited PATH.
        for name, target in context['toolAliases'].items():
            if not re.fullmatch('[a-zA-Z0-9_+.-]{1,64}', name) or not pathlib.Path(target).is_absolute(): raise ValueError('tool alias syntax')
            (mountpoint / 'bin' / name).symlink_to(target)
        env_file = mountpoint / 'environment'
        values = {**context['compilerEnvironment'], 'PATH': str(mountpoint / 'bin'), 'CARGO_HOME': str(mountpoint / 'cargo-home'),
                  'CARGO_TARGET_DIR': str(mountpoint / 'target'), 'TMPDIR': str(mountpoint / 'tmp'), 'HOME': str(mountpoint / 'home')}
        env_file.write_text(''.join(key + '=' + value + '\n' for key, value in sorted(values.items()))); env_file.chmod(0o600)
        command = [str(paths['wrapperBinary']), str(mountpoint), str(paths['readRootsFile']), str(env_file), context['cargoPath'], str(paths['sourceRoot']), context['operation'], context['sourceSha']]
        # The wrapper exclusively creates cargo.stdout/stderr after policy setup.
        setup_out, setup_err = setup_log_paths(mountpoint)
        with setup_out.open('xb') as out, setup_err.open('xb') as err:
            child = subprocess.Popen(command, env={'LANG': 'C'}, cwd=mountpoint, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
            try: cargo_exit = child.wait(timeout=1700)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, 9); child.wait(timeout=5); raise ValueError('owned Cargo timeout preserved')
        observation = {'resources': observed_resources, 'filesystem': observed_capacity, 'backingImage': image_check(image, initial_image),
                       'daemon': daemon_proof, 'cargoExit': cargo_exit, 'offlineFrozenJobs': 2}
        small.own_daemon_maps(daemon.pid, root, maps, observed_resources['controlGroup'], os.getuid(), os.getgid())
        filesystem_check(mountpoint)
    except Exception as error: failure = type(error).__name__
    finally:
        logs, cleanup = settle_owned(root, mountpoint, daemon, owned, small)
    receipt = {'schema': 'universe-electrs-full-cargo-worker-result-v1', 'sourceSha': context['sourceSha'], 'cargoLockSha256': context['cargoLockSha256'],
               'observation': observation, 'failureType': failure, 'cleanupErrors': cleanup, 'cargoExit': cargo_exit, 'retainedLogMetadata': logs,
               'cargoCompilationSucceeded': failure is None and not cleanup and cargo_exit == 0,
               'testsExecutedSuccessfully': context['operation'] == 'test' and failure is None and not cleanup and cargo_exit == 0,
               'fullBuildQualified': False, 'nativeActions': False}
    with (root / 'result.json').open('x') as output: json.dump(receipt, output, indent=2)
    return 0 if receipt['cargoCompilationSucceeded'] else 1


def launch(root, context, reviewed_hash):
    VERIFIED_FENCES.clear()
    guard = load('full_parent_guard', 'locked-cache-readonly.py')
    source = guard.runtime_guard(); inventory = load('full_parent_git', 'locked-source-inventory.py')
    guard.source_guard(inventory, source)
    if source != context['sourceSha']: raise ValueError('checkout and frozen source differ')
    pressure = load('full_parent_pressure', 'confinement-proof.py')
    observed = guard.headroom_report(pathlib.Path(os.environ['RUNNER_TEMP']))
    pressure.headroom(observed)
    if observed['memoryKiB']['MemAvailable'] < 5 * 1024**2 or observed['freeTempBytes'] < 10 * 1024**3:
        raise ValueError('larger4GiB/8GiB workspace headroom unavailable')
    verified = admission(context, root)
    small = load('full_parent_unit_tools', 'small-fuse-image-proof.py')
    for value in [small.RUN_TOOL, small.CTL_TOOL, small.PYTHON, small.FUSE_TOOL]: small.pin(value)
    for name in ['work', 'aggregate8GiB.img', 'private-runtime', 'host-runtime', 'unit.stdout', 'unit.stderr', 'owned-mount.json', 'result.json']:
        if (root / name).exists() or (root / name).is_symlink(): raise ValueError('exclusive worker destination already present; no retry')
    if file_hash(root / 'context.json', 2 * 1024**2) != reviewed_hash: raise ValueError('context changed before launch')
    # Captured after full verification; no new hash/freshness is asserted by the
    # worker's later inode/mtime/ctime checks. The receipt is exclusive and raw-bound.
    parent_admission = {'schema': 'universe-electrs-full-cargo-admission-v1', 'contextSha256': reviewed_hash,
                        'controllerSha256': context['controllerSha256'], 'inputs': verified,
                        'fences': sorted(VERIFIED_FENCES.values(), key=lambda record: record['path'])}
    admission_raw = json.dumps(parent_admission, sort_keys=True, separators=(',', ':')).encode()
    if len(admission_raw) > 32 * 1024**2: raise ValueError('parent admission receipt bound')
    with (root / 'admission.json').open('xb') as output: output.write(admission_raw)
    admission_hash = hashlib.sha256(admission_raw).hexdigest()
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': '/home/github-runner', 'XDG_RUNTIME_DIR': '/run/user/1001', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1001/bus'}
    unit = context.get('executionUnit', root.name)
    command = [small.RUN_TOOL['path'], '--user', '--unit=' + unit, '--collect', '--wait', '--pipe', '--service-type=exec',
               '--property=CPUQuota=200%', '--property=CPUQuotaPeriodSec=100ms', '--property=MemoryMax=4G', '--property=TasksMax=128',
               '--property=RuntimeMaxSec=1800s', '--property=TimeoutStopSec=5s', '--property=Nice=19', '--property=IOWeight=1',
               '--property=NoNewPrivileges=no', '--property=KillMode=control-group',
               '--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG GLIBC_TUNABLES GCONV_PATH PYTHONPATH PYTHONHOME',
               '--', small.PYTHON['path'], '-B', '-I', '-S', str(pathlib.Path(__file__).resolve()), '--worker-root', str(root), '--reviewed-context-sha256', reviewed_hash, '--parent-admission-sha256', admission_hash]
    # User-unit setup requires mount-helper SUID; independently qualified wrapper
    # sets NNP before any Cargo/build-script execution. No alternative fallback.
    timed_out = False; execution_errors = []; exit_code = 1
    with (root / 'unit.stdout').open('xb') as out, (root / 'unit.stderr').open('xb') as err:
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        try: exit_code = child.wait(timeout=1815)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                stopped = subprocess.run([small.CTL_TOOL['path'], '--user', 'stop', unit], env=env, timeout=5, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if stopped.returncode: execution_errors.append('owned unit stop nonzero: ' + str(stopped.returncode))
            except Exception as error: execution_errors.append('owned unit stop: ' + type(error).__name__)
            try: child.kill()
            except Exception as error: execution_errors.append('own launcher kill: ' + type(error).__name__)
            try: child.wait(timeout=5)
            except Exception as error: execution_errors.append('own launcher settlement: ' + type(error).__name__)
            exit_code = 1
        except Exception as error:
            execution_errors.append('own launcher wait: ' + type(error).__name__)
    cleanup = settle_parent(root, small)
    result = {'schema': 'universe-electrs-full-cargo-parent-result-v1', 'sourceSha': source, 'contextSha256': reviewed_hash,
              'inputs': verified, 'headroom': observed, 'unit': unit, 'exitCode': exit_code, 'watchdogTimeout': timed_out,
              'executionErrors': execution_errors, 'cleanupErrors': cleanup, 'fullBuildQualified': False, 'nativeActions': False}
    with (root / 'parent-result.json').open('x') as output: json.dump(result, output, indent=2)
    return 0 if exit_code == 0 and not cleanup and not execution_errors else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--worker-root', type=pathlib.Path)
    parser.add_argument('--launch-reviewed-root', type=pathlib.Path)
    parser.add_argument('--reviewed-context-sha256'); parser.add_argument('--parent-admission-sha256'); args = parser.parse_args()
    if args.worker_root is None and args.launch_reviewed_root is None:
        print(json.dumps({'preparedOnly': True, 'cargoInvoked': False, 'mounted': False})); return
    if args.worker_root is not None and args.launch_reviewed_root is not None: raise ValueError('one explicit mode only')
    root = args.worker_root or args.launch_reviewed_root; path = root / 'context.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024**2: raise ValueError('bounded reviewed context')
    if file_hash(path) != args.reviewed_context_sha256: raise ValueError('independent reviewed context hash required')
    context = read_json(path, args.reviewed_context_sha256, 2 * 1024**2)
    if args.worker_root:
        if not re.fullmatch('[0-9a-f]{64}', args.parent_admission_sha256 or ''): raise ValueError('explicit verified parent admission required')
        parent = read_json(root / 'admission.json', args.parent_admission_sha256, 32 * 1024**2)
        raise SystemExit(worker(root, context, parent, args.reviewed_context_sha256))
    raise SystemExit(launch(root, context, args.reviewed_context_sha256))


if __name__ == '__main__': main()
