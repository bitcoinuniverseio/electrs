"""Prepared exact-owner retained-image admission; no default read/mount/build."""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
IMAGE_BYTES = 8 * 1024**3
PREFIX = '/home/github-runner/.cache/universe-electrs-api-20261009'


def persistent_root(path):
    value = pathlib.PurePosixPath(str(path))
    if value.parent != pathlib.PurePosixPath(PREFIX) or not re.fullmatch('[0-9a-f]{16}', value.name):
        raise ValueError('exact persistent task namespace required')
    return str(value)


def checked_ancestors(root, allow_missing_task=False):
    persistent_root(root)
    chain = [pathlib.Path('/'), pathlib.Path('/home'), pathlib.Path('/home/github-runner'),
             pathlib.Path('/home/github-runner/.cache'), pathlib.Path(PREFIX), pathlib.Path(root)]
    for path in chain:
        if path.is_symlink(): raise ValueError('persistent ancestor link')
        if not path.exists():
            if allow_missing_task and path in [pathlib.Path(PREFIX), pathlib.Path(root)]: continue
            raise ValueError('persistent task ancestor absent')
        value = path.lstat()
        expected = 0 if str(path) in ['/', '/home'] else 1001
        if not stat.S_ISDIR(value.st_mode) or path.is_symlink() or value.st_uid != expected:
            raise ValueError('persistent task ancestor ownership/link')
        if expected == 1001 and value.st_gid != 1001: raise ValueError('persistent task ancestor group')
        if path in [pathlib.Path(PREFIX), pathlib.Path(root)] and value.st_mode & 0o077:
            raise ValueError('persistent task privacy mode')


def create_task(nonce, source, controller, run_id, attempt):
    """Explicit caller only, after its fresh pressure/source guards; no fallback."""
    if not re.fullmatch('[0-9a-f]{16}', nonce) or not re.fullmatch('[0-9a-f]{40}', source) or not re.fullmatch('[0-9a-f]{64}', controller):
        raise ValueError('task creation exact nonce/source/controller')
    if not re.fullmatch('[0-9]{1,20}', run_id) or not re.fullmatch('[0-9]{1,3}', attempt) or os.getuid() != 1001 or os.getgid() != 1001:
        raise ValueError('task creation owned run')
    root = pathlib.Path(PREFIX) / nonce; checked_ancestors(root, allow_missing_task=True)
    if root.exists() or root.is_symlink(): raise ValueError('exclusive persistent task already exists')
    parent_created = False
    if not root.parent.exists(): root.parent.mkdir(mode=0o700); parent_created = True
    checked_ancestors(root, allow_missing_task=True)
    root.mkdir(mode=0o700); checked_ancestors(root)
    info = root.lstat()
    lease = {'schema': 'universe-electrs-persistent-task-lease-v1', 'taskRoot': str(root), 'createdByRun': run_id,
             'createdByAttempt': attempt, 'createdBySource': source, 'controllerSha256': controller,
             'rootIdentity': {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid, 'mode': info.st_mode},
             'parentCreatedByTask': parent_created, 'nativeActions': False}
    raw = json.dumps(lease, sort_keys=True, separators=(',', ':')).encode()
    with (root / 'lease.json').open('xb') as output: output.write(raw)
    (root / 'lease.json').chmod(0o400)
    return {'taskRoot': str(root), 'leaseSha256': hashlib.sha256(raw).hexdigest(), 'lease': lease}


def validate_lease(lease, root):
    checked_ancestors(root)
    info = pathlib.Path(root).lstat()
    if lease.get('schema') != 'universe-electrs-persistent-task-lease-v1' or lease.get('taskRoot') != str(root): raise ValueError('persistent lease root')
    expected = {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid, 'mode': info.st_mode}
    if lease.get('rootIdentity') != expected or not re.fullmatch('[0-9a-f]{40}', lease.get('createdBySource', '')) or not re.fullmatch('[0-9a-f]{64}', lease.get('controllerSha256', '')):
        raise ValueError('persistent lease original inode/source/controller')
    if not re.fullmatch('[0-9]{1,20}', lease.get('createdByRun', '')) or not re.fullmatch('[0-9]{1,3}', lease.get('createdByAttempt', '')):
        raise ValueError('persistent lease original run')
    return True


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def cache_key(context, closure):
    # Source revision is intentionally excluded: Cargo fingerprints decide which
    # source crates changed. Dependency inputs and their absolute paths are not.
    leaves = sorted([{'path': leaf['path'], 'bytes': leaf['bytes'], 'sha256': leaf['sha256']} for leaf in closure['leaves']], key=lambda item: item['path'])
    trees = sorted([{'path': tree['path'], 'sha256': tree['treeManifestSha256']} for tree in closure.get('trees', [])], key=lambda item: item['path'])
    value = {'lockSha256': context['cargoLockSha256'], 'vendorManifestSha256': context['vendorManifestSha256'],
             'vendorRoot': context['vendorRoot'], 'workRoot': str(pathlib.PurePosixPath(context['taskRoot']) / 'work'),
             'profile': context['profile'], 'wrapperSourceSha256': context['wrapperSourceSha256'],
             'wrapperBinarySha256': context['wrapperBinarySha256'], 'offlineConfigSha256': context['offlineConfigSha256'],
             'compilerRoles': closure['roles'], 'compilerEnvironment': context['compilerEnvironment'],
             'toolAliases': context['toolAliases'], 'leaves': leaves, 'trees': trees}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate(receipt, context, closure):
    if receipt.get('schema') != 'universe-electrs-retained-cargo-cache-v1' or receipt.get('guardPolicy') != 'full-cargo-v2':
        raise ValueError('reviewed retained-cache schema/policy')
    root = pathlib.PurePosixPath(context['taskRoot'])
    if receipt.get('taskRoot') != str(root) or receipt.get('imagePath') != str(root / 'aggregate8GiB.img') or receipt.get('mountPath') != str(root / 'work'):
        raise ValueError('retained cache cannot relocate dependency paths')
    if receipt.get('cacheKeySha256') != cache_key(context, closure): raise ValueError('source-independent dependency cache key changed')
    unit = receipt.get('previousUnit', '')
    if not re.fullmatch(r'universe-electrs-build-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', unit): raise ValueError('previous owned unit namespace')
    if receipt.get('settled') != {'workerCleanupErrors': [], 'parentCleanupErrors': [], 'daemonExit': 0, 'mountAbsent': True, 'unitInactive': True}:
        raise ValueError('interrupted/unsettled image cannot be reused')
    if type(receipt['settled']['daemonExit']) is not int or receipt['settled']['mountAbsent'] is not True or receipt['settled']['unitInactive'] is not True:
        raise ValueError('typed actual settlement proof required')
    if type(receipt.get('previousDaemonPid')) is not int or not 1 <= receipt['previousDaemonPid'] <= 2**31 - 1:
        raise ValueError('known daemon PID required')
    group = receipt.get('previousControlGroup', '')
    if not group.startswith('/') or '..' in pathlib.PurePosixPath(group).parts or not group.endswith('/' + unit + '.service'):
        raise ValueError('previous own cgroup binding')
    image = receipt.get('imageIdentity', {})
    if set(image) != {'device', 'inode', 'size', 'mtimeNs', 'ctimeNs', 'uid', 'gid', 'mode', 'nlink'} or image['size'] != IMAGE_BYTES or image['uid'] != 1001 or image['nlink'] != 1:
        raise ValueError('post-settlement backing image fence required')
    for name in ['previousContextSha256', 'workerResultSha256', 'parentResultSha256']:
        if not re.fullmatch('[0-9a-f]{64}', receipt.get(name, '')): raise ValueError('original execution proof hashes required')
    return {'cacheKeySha256': receipt['cacheKeySha256'], 'dependencyReuseProposed': True,
            'cargoFingerprintValidationStillRequired': True, 'nativeActions': False}


def image_identity(path):
    value = pathlib.Path(path).lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 1001 or value.st_gid != 1001 or value.st_nlink != 1 or value.st_mode & 0o077 or value.st_size != IMAGE_BYTES:
        raise ValueError('private fixed retained backing image identity')
    return {'device': value.st_dev, 'inode': value.st_ino, 'size': value.st_size, 'mtimeNs': value.st_mtime_ns,
            'ctimeNs': value.st_ctime_ns, 'uid': value.st_uid, 'gid': value.st_gid, 'mode': value.st_mode, 'nlink': value.st_nlink}


def observe_settled(receipt):
    small = load('retained_unit_tools', 'small-fuse-image-proof.py'); small.pin(small.CTL_TOOL)
    reads = load('retained_scope_reads', 'locked-cache-readonly.py')
    if os.getuid() != 1001 or os.getgid() != 1001: raise ValueError('exact retained-cache owner')
    for key in ['imagePath', 'mountPath']:
        for ancestor in [pathlib.Path(receipt[key]), *pathlib.Path(receipt[key]).parents]:
            if ancestor.is_symlink(): raise ValueError('retained-image linked ancestor')
    if image_identity(receipt['imagePath']) != receipt['imageIdentity']: raise ValueError('retained backing image changed after settlement')
    if pathlib.Path('/proc/' + str(receipt['previousDaemonPid'])).exists(): raise ValueError('previous daemon PID not absent; no reuse')
    if small.read_mount(pathlib.Path(receipt['mountPath'])) is not None: raise ValueError('retained mount still present')
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': '/home/github-runner', 'XDG_RUNTIME_DIR': '/run/user/1001', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1001/bus'}
    command = [small.CTL_TOOL['path'], '--user', 'show', receipt['previousUnit'] + '.service', '--property=ActiveState', '--property=SubState', '--property=ControlGroup', '--property=LoadState']
    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=3, check=False)
    if result.returncode or len(result.stdout) > 4096 or len(result.stderr) > 4096: raise ValueError('retained own-unit metadata unavailable')
    properties = dict(line.split('=', 1) for line in result.stdout.decode('ascii').splitlines())
    if properties.get('ActiveState') != 'inactive' or properties.get('SubState') != 'dead' or properties.get('ControlGroup') or properties.get('LoadState') not in ['loaded', 'not-found']:
        raise ValueError('previous owned unit not settled')
    group = pathlib.Path('/sys/fs/cgroup' + receipt['previousControlGroup'])
    if group.exists():
        if group.is_symlink() or reads.bounded_read(group / 'cgroup.procs', 4096).strip(): raise ValueError('previous cgroup has active processes')
        events = dict(line.split() for line in reads.bounded_read(group / 'cgroup.events', 4096).splitlines())
        if events.get('populated') != '0': raise ValueError('previous cgroup remains populated')
    if image_identity(receipt['imagePath']) != receipt['imageIdentity']: raise ValueError('retained image changed during absence checks')
    return {'previousUnitInactive': True, 'previousDaemonAbsent': True, 'previousMountAbsent': True,
            'imageFenceUnchanged': True, 'mounted': False, 'cargoInvoked': False}


if __name__ == '__main__':
    print(json.dumps({'preparedOnly': True, 'metadataRead': False, 'mounted': False, 'cargoInvoked': False}))
