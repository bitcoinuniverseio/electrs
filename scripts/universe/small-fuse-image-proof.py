"""UNEXECUTED exact owned8MiB FUSE proof; root-reviewed explicit run only."""
import argparse
import datetime
import errno
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
IMAGE_BYTES = 8 * 1024**2
ATTEMPT_BYTES = 16 * 1024**2
RUN_TOOL = {'path': '/usr/bin/systemd-run', 'sha256': 'dbc8b988a849d5c9d7ef2de7068a6f107021bc6c11e0d7864c73f373eef726a7'}
CTL_TOOL = {'path': '/usr/bin/systemctl', 'sha256': 'e0d3d0e9444da1b2b58c792c3f5028b69f049b77d5ca17b3ec0d09f89117225b'}
FUSE_TOOL = {'path': '/usr/bin/fusermount3', 'sha256': 'd278775c1528dd32efc85c2cb322423ee93aa8dcf76aaa595f7022d427910704'}
PYTHON = {'path': '/usr/bin/python3.12', 'sha256': 'e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f'}


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def digest(path):
    result = hashlib.sha256()
    with pathlib.Path(path).open('rb') as source:
        for block in iter(lambda: source.read(65536), b''): result.update(block)
    return result.hexdigest()


def pin(value):
    path = pathlib.Path(value['path']).resolve(strict=True)
    if str(path) != value['path'] or not path.is_file() or path.stat().st_size > 16 * 1024**2 or digest(path) != value['sha256']: raise ValueError('reviewed exact tool pin unavailable')


def mount_record(raw, mountpoint):
    found = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields: raise ValueError('bounded mount observation invalid')
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        if point != str(mountpoint): continue
        split = fields.index('-')
        if split < 6 or split + 3 >= len(fields): raise ValueError('mount observation separator bound')
        found.append({'id': int(fields[0]), 'path': point, 'filesystem': fields[split + 1], 'source': fields[split + 2], 'options': fields[5] + ',' + fields[split + 3]})
    if len(found) > 1: raise ValueError('multiple mounts at owned path')
    return found[0] if found else None


def read_mount(mountpoint):
    guard = load('mount_guard', 'locked-cache-readonly.py')
    return mount_record(guard.bounded_read('/proc/self/mountinfo', 256 * 1024), mountpoint)


def same_mount(left, right):
    return left is not None and right is not None and all(left[key] == right[key] for key in ['id', 'path', 'filesystem', 'source'])


def validate_owned_mount(candidate, image, mountpoint):
    if candidate is None or candidate['path'] != str(mountpoint) or candidate['filesystem'] != 'fuse.universe-electrs-proof' or candidate['source'] != str(image):
        raise ValueError('observed mount is not the exact owned source/type/path')
    options = set(candidate['options'].split(','))
    if 'allow_other' in options or not {'nosuid', 'nodev'} <= options:
        raise ValueError('observed mount missing nosuid/nodev or permits other users')
    return candidate


def image_identity(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_uid != 1001 or value.st_size != IMAGE_BYTES:
        raise ValueError('exclusive fixed regular owned image identity unavailable')
    return {'device': value.st_dev, 'inode': value.st_ino, 'bytes': value.st_size, 'uid': value.st_uid}


def regular_source(path, expected):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024**2 or digest(path) != expected:
        raise ValueError('qualified runtime source bytes changed')


def stage_group(group, root, package_root, package_report):
    library = root / 'lib'; binary = root / 'bin'; library.mkdir(parents=True); binary.mkdir()
    package_files = {}
    for package in package_report['packages']:
        for path in package['files']: package_files[path] = package['name']
    def copy(record, output):
        source = pathlib.Path(record['sourcePath']) if record['origin'] == 'observed-host-leaf' else package_root / 'packages' / package_files[record['sourcePath']] / record['sourcePath']
        regular_source(source, record['sha256'])
        with source.open('rb') as incoming, output.open('xb') as outgoing: shutil.copyfileobj(incoming, outgoing, 65536)
        if digest(output) != record['sha256']: raise ValueError('runtime copied bytes differ')
        output.chmod(0o555)
    for soname, record in group['providers'].items():
        if not re.fullmatch(r'[A-Za-z0-9_+.-]{1,160}', soname): raise ValueError('runtime SONAME spelling')
        copy(record, library / soname)
    for record in group['executables']: copy(record, binary / pathlib.PurePosixPath(record['sourcePath']).name)
    return library, binary


def run_known(argv, root, name, environment, timeout):
    # Arguments are assembled exclusively from reviewed tool/runtime/owned paths.
    with (root / (name + '.stdout')).open('xb') as out, (root / (name + '.stderr')).open('xb') as err:
        result = subprocess.run(argv, env=environment, cwd=root, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=timeout, check=False)
    if result.returncode: raise ValueError(name + ' controlled process failed: ' + str(result.returncode))


def capacity(stat, image_size):
    total = stat.f_blocks * stat.f_frsize
    if image_size != IMAGE_BYTES or total <= 0 or total > IMAGE_BYTES: raise ValueError('actual image/filesystem upper bound contradiction')
    return total


def resource_guard(root):
    guard = load('actual_scope_reads', 'locked-cache-readonly.py')
    groups = [line[3:] for line in guard.bounded_read('/proc/self/cgroup', 4096).splitlines() if line.startswith('0::')]
    if len(groups) != 1 or not groups[0].endswith('/' + root.name + '.service') or '..' in pathlib.PurePosixPath(groups[0]).parts:
        raise ValueError('actual owned user-unit cgroup unavailable')
    directory = pathlib.Path('/sys/fs/cgroup' + groups[0])
    expected = {'cpu.max': '100000 100000', 'memory.max': '134217728', 'pids.max': '16'}
    for name, value in expected.items():
        if guard.bounded_read(directory / name, 4096).strip() != value: raise ValueError('actual small scope resource mismatch: ' + name)
    io_weight = guard.bounded_read(directory / 'io.weight', 4096).strip()
    if io_weight != 'default 1' or os.getpriority(os.PRIO_PROCESS, 0) != 19:
        raise ValueError('actual scope IO/nice resource mismatch')
    nnp = re.findall(r'^NoNewPrivs:\s+([01])$', guard.bounded_read('/proc/self/status', 32768), flags=re.M)
    if nnp != ['0']: raise ValueError('actual mount setup cannot use existing setuid helper in this inherited NNP scope')
    return {'controlGroup': groups[0], 'cpuMax': expected['cpu.max'], 'memoryMax': expected['memory.max'],
            'pidsMax': expected['pids.max'], 'ioWeight': io_weight, 'nice': 19,
            'mountSetupNoNewPrivileges': False, 'cargoConfinementQualified': False}


def staged_file_hashes(group, library, binary):
    files = {str(library / soname): record['sha256'] for soname, record in group['providers'].items()}
    files.update({str(binary / pathlib.PurePosixPath(record['sourcePath']).name): record['sha256'] for record in group['executables']})
    return files


def daemon_start(guard, pid):
    stat_text = guard.bounded_read('/proc/' + str(pid) + '/stat', 4096)
    tail = stat_text[stat_text.rfind(')') + 2:].split()
    if len(tail) < 20 or not tail[19].isdigit(): raise ValueError('own daemon process-start identity unavailable')
    return tail[19]


def daemon_credentials(raw, uid, gid):
    fields = {}
    for name in ['Uid', 'Gid']:
        matches = re.findall(r'^' + name + r':\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$', raw, flags=re.M)
        if len(matches) != 1 or any(int(value) != (uid if name == 'Uid' else gid) for value in matches[0]): raise ValueError('own daemon credential identity contradiction')
        fields[name] = [int(value) for value in matches[0]]
    for name in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb']:
        matches = re.findall(r'^' + name + r':\s+([0-9a-fA-F]{1,16})$', raw, flags=re.M)
        if len(matches) != 1 or int(matches[0], 16) != 0: raise ValueError('own daemon effective/permitted/inheritable/ambient capabilities must be zero')
        fields[name] = '0'
    return fields


def check_mapped_leaf(path, root, expected_files):
    if root not in path.parents or str(path) not in expected_files or path.is_symlink() or not path.is_file() or digest(path) != expected_files[str(path)]:
        raise ValueError('own daemon loaded unqualified/default or changed staged file')


def own_daemon_maps(pid, root, expected_files, expected_group, uid, gid):
    guard = load('own_daemon_observation', 'locked-cache-readonly.py')
    start = daemon_start(guard, pid)
    credentials = daemon_credentials(guard.bounded_read('/proc/' + str(pid) + '/status', 32768), uid, gid)
    groups = [line[3:] for line in guard.bounded_read('/proc/' + str(pid) + '/cgroup', 4096).splitlines() if line.startswith('0::')]
    if groups != [expected_group]: raise ValueError('own daemon left the exact owned resource cgroup')
    raw = guard.bounded_read('/proc/' + str(pid) + '/maps', 65536)
    mapped = set()
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not fields[5].startswith('/'): continue
        path = pathlib.Path(fields[5])
        check_mapped_leaf(path, root, expected_files)
        mapped.add(str(path))
    if not mapped: raise ValueError('own daemon loaded-file observation unavailable')
    if daemon_start(guard, pid) != start: raise ValueError('own daemon process start changed during observation')
    return {'pid': pid, 'startTicks': start, 'credentials': credentials, 'controlGroup': expected_group,
            'mappedOwnFiles': sorted(mapped), 'mappedByteHashesRevalidated': True}


def write_until_full(mountpoint):
    committed = 0; attempts = 0; operations = 0; files = []; enospc = False
    block = b'OWNED-FUSE-PROOF' * (1024 * 1024 // 16)
    # Multiple files force aggregate exhaustion rather than one-file limit.
    for index in range(16):
        path = mountpoint / ('owned-block-' + str(index))
        try:
            with path.open('xb', buffering=0) as output:
                count = 0
                while count < len(block):
                    operations += 1; attempts += len(block) - count
                    if operations > 16 or attempts > ATTEMPT_BYTES: raise ValueError('bounded write operation budget exhausted without ENOSPC')
                    written = output.write(block[count:])
                    if written is None or written <= 0: raise ValueError('nonprogressing write without ENOSPC')
                    count += written
                os.fsync(output.fileno())
            committed += count
            files.append({'path': path.name, 'bytes': count, 'sha256': digest(path)})
        except OSError as error:
            if error.errno != errno.ENOSPC: raise
            enospc = True
            # Preserve a partial file honestly and include it in readback evidence.
            if path.exists(): files.append({'path': path.name, 'bytes': path.stat().st_size, 'sha256': digest(path), 'partialOnEnospc': True})
            break
    if not enospc or attempts > ATTEMPT_BYTES or committed > IMAGE_BYTES or len(files) < 2: raise ValueError('real aggregate multi-file ENOSPC not observed')
    for item in files:
        if digest(mountpoint / item['path']) != item['sha256']: raise ValueError('mounted data readback mismatch')
    if sum(item['bytes'] for item in files) > IMAGE_BYTES: raise ValueError('actual observed bytes including partial exceed fixed image limit')
    return {'realEnospc': True, 'writeOperations': operations, 'attemptedBytes': attempts,
            'completeCommittedBytes': committed, 'observedFilesBytes': sum(item['bytes'] for item in files), 'files': files}


def owned_package_root(path, temp):
    path = pathlib.Path(path)
    if path.parent != temp or not re.fullmatch(r'universe-electrs-helper-data-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', path.name):
        raise ValueError('exact reviewed owned Linux helper-data transfer root required')
    for ancestor in [path, *path.parents]:
        if ancestor.is_symlink(): raise ValueError('linked helper-data ancestor')
    if not path.is_dir() or path.stat().st_uid != 1001: raise ValueError('owned helper data directory required')
    return path


def worker(root):
    raw_context = (root / 'context.json').read_bytes()
    context = json.loads(raw_context)
    if len(raw_context) > 512 * 1024 or context['sourceSha256'] != digest(pathlib.Path(__file__)) or context['uid'] != os.getuid(): raise ValueError('own scope source/context guard')
    actual_resources = resource_guard(root)  # Before staging or image creation.
    for value in [FUSE_TOOL, PYTHON]: pin(value)
    binding = load('closed_runtime_binding', 'helper-runtime-binding.py').bind(context['packageReport'], context['hostReport'])
    private_lib, private_bin = stage_group(binding['executionGroups']['fuse2fs'], root / 'private-runtime', pathlib.Path(context['packageRoot']), context['packageReport'])
    host_lib, host_bin = stage_group(binding['executionGroups']['mke2fsAndExistingMountHelper'], root / 'host-runtime', pathlib.Path(context['packageRoot']), context['packageReport'])
    image = root / 'owned8MiB.img'; mountpoint = root / 'mount'; mountpoint.mkdir(mode=0o700)
    with image.open('xb') as file: file.truncate(IMAGE_BYTES)
    image.chmod(0o600)
    expected_image = image_identity(image)
    config = root / 'mke2fs-private.conf'
    config.write_text('[defaults]\nbase_features = sparse_super,filetype,large_file,ext_attr,dir_index\nblocksize = 1024\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent,dir_nlink,extra_isize\n}\n')
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': str(root), 'MKE2FS_CONFIG': str(config)}
    loader = host_lib / 'ld-linux-x86-64.so.2'
    run_known([str(loader), '--inhibit-cache', '--library-path', str(host_lib), str(host_bin / 'mke2fs'), '-F', '-q', '-t', 'ext4', '-b', '1024', '-m', '0', str(image)], root, 'format', env, 5)
    if image_identity(image) != expected_image: raise ValueError('image identity changed during formatting')
    daemon = None; owned_mount = None; primary_error = None; cleanup_errors = []; observation = None
    try:
        with (root / 'fuse.stdout').open('xb') as out, (root / 'fuse.stderr').open('xb') as err:
            command = [str(private_lib / 'ld-linux-x86-64.so.2'), '--inhibit-cache', '--library-path', str(private_lib), str(private_bin / 'fuse2fs'), '-f', '-o', 'rw,nosuid,nodev,fsname=' + str(image) + ',subtype=universe-electrs-proof', str(image), str(mountpoint)]
            daemon = subprocess.Popen(command, env=env, cwd=root, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        until = time.monotonic() + 5
        while time.monotonic() < until:
            if daemon.poll() is not None: raise ValueError('own FUSE daemon exited during startup')
            candidate = read_mount(mountpoint)
            if candidate:
                validate_owned_mount(candidate, image, mountpoint)
                owned_mount = candidate  # Assign only after ALL ownership/flag checks.
                break
            time.sleep(0.05)
        validate_owned_mount(owned_mount, image, mountpoint)
        with (root / 'owned-mount.json').open('x') as output: json.dump(owned_mount, output)
        total = capacity(os.statvfs(mountpoint), image.stat().st_size)
        expected_files = staged_file_hashes(binding['executionGroups']['fuse2fs'], private_lib, private_bin)
        daemon_identity = own_daemon_maps(daemon.pid, root, expected_files, actual_resources['controlGroup'], os.getuid(), os.getgid())
        observation = write_until_full(mountpoint)
        daemon_after = own_daemon_maps(daemon.pid, root, expected_files, actual_resources['controlGroup'], os.getuid(), os.getgid())
        if daemon.poll() is not None or daemon_after['startTicks'] != daemon_identity['startTicks']: raise ValueError('own daemon identity/lifetime changed after write/readback')
        observation.update({'mount': owned_mount, 'filesystemCapacityBytes': total, 'imageBytes': image.stat().st_size, 'daemonIdentity': daemon_identity,
                            'successfulOwnFuseIOObserved': True, 'numericProtocolVersionObserved': False})
        if image_identity(image) != expected_image: raise ValueError('fixed backing image changed or grew')
    except Exception as error: primary_error = {'type': type(error).__name__, 'reason': str(error)[:512]}
    finally:
        current = None
        try: current = read_mount(mountpoint)
        except Exception as error: cleanup_errors.append('mount cleanup observation failed: ' + str(error)[:512])
        if current:
            if not same_mount(current, owned_mount): cleanup_errors.append('mount ownership changed; no unmount issued')
            else:
                try: run_known([FUSE_TOOL['path'], '-u', str(mountpoint)], root, 'unmount', {'LANG': 'C', 'PATH': '/usr/bin:/bin'}, 5)
                except Exception as error: cleanup_errors.append(str(error)[:512])
        if daemon is not None:
            try:
                daemon_exit = daemon.wait(timeout=3)
                if daemon_exit: cleanup_errors.append('stored own daemon exited nonzero: ' + str(daemon_exit))
            except subprocess.TimeoutExpired:
                try: daemon.terminate()
                except Exception as error: cleanup_errors.append('stored own daemon termination failed: ' + str(error)[:512])
                cleanup_errors.append('stored own daemon required termination')
                try: daemon.wait(timeout=2)
                except subprocess.TimeoutExpired: cleanup_errors.append('stored own daemon did not settle')
        try:
            if read_mount(mountpoint): cleanup_errors.append('own mount remains present')
        except Exception as error: cleanup_errors.append('mount absence read failed: ' + str(error)[:512])
    receipt = {'schema': 'universe-electrs-small-fuse-image-proof-v1', 'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'sourceSha': context['sourceSha'], 'observation': observation, 'primaryError': primary_error, 'cleanupErrors': cleanup_errors,
               'actualSmall8MiBCapacityQualified': primary_error is None and not cleanup_errors and observation is not None,
               'actualResources': actual_resources,
               'actual8GiBBuildCapacityQualified': False, 'fullRustBuild': False, 'nativeActions': False, 'artifactsPreserved': True}
    with (root / 'proof-receipt.json').open('x') as output: json.dump(receipt, output, indent=2)
    return 0 if receipt['actualSmall8MiBCapacityQualified'] else 1


def launch(package_report, host_report, package_root):
    guard = load('owned_image_source_guard', 'locked-cache-readonly.py'); expected = guard.runtime_guard()
    inventory = load('image_git_guard', 'locked-source-inventory.py'); guard.source_guard(inventory, expected)
    pressure = load('reviewed_image_pressure', 'confinement-proof.py')
    temp = pathlib.Path(os.environ['RUNNER_TEMP']); admission = pressure.headroom(guard.headroom_report(temp))
    package_root = owned_package_root(package_root, temp)
    load('binding_admission', 'helper-runtime-binding.py').bind(package_report, host_report)
    for value in [RUN_TOOL, CTL_TOOL, FUSE_TOOL, PYTHON]: pin(value)
    unit = 'universe-electrs-fuse-proof-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'] + '-' + os.urandom(8).hex()
    if not re.fullmatch(r'universe-electrs-fuse-proof-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', unit): raise ValueError('own unit namespace')
    root = temp / unit; root.mkdir(mode=0o700)
    context = {'sourceSha': expected, 'sourceSha256': digest(pathlib.Path(__file__)), 'uid': os.getuid(),
               'packageRoot': str(package_root), 'packageReport': package_report, 'hostReport': host_report, 'headroom': admission}
    with (root / 'context.json').open('x') as out: json.dump(context, out)
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': '/home/github-runner', 'XDG_RUNTIME_DIR': '/run/user/1001', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1001/bus'}
    command = [RUN_TOOL['path'], '--user', '--unit=' + unit, '--collect', '--wait', '--pipe', '--service-type=exec',
               '--property=CPUQuota=100%', '--property=CPUQuotaPeriodSec=100ms', '--property=MemoryMax=128M', '--property=TasksMax=16', '--property=RuntimeMaxSec=30s',
               '--property=TimeoutStopSec=5s', '--property=Nice=19', '--property=IOWeight=1', '--property=NoNewPrivileges=no',
               '--property=KillMode=control-group', '--', PYTHON['path'], '-B', '-I', '-S', str(pathlib.Path(__file__).resolve()), '--worker-root', str(root)]
    command.insert(command.index('--'), '--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT LD_PROFILE LD_ORIGIN_PATH GLIBC_TUNABLES GCONV_PATH PYTHONPATH PYTHONHOME')
    # NoNewPrivileges=no is isolated mount SETUP ONLY, required for the existing
    # setuid fusermount helper. This is NOT the Cargo confinement scope.
    with (root / 'unit.stdout').open('xb') as out, (root / 'unit.stderr').open('xb') as err:
        process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        try: exitcode = process.wait(timeout=40)
        except subprocess.TimeoutExpired:
            # Stop only this exact generated owned unit, never another service.
            subprocess.run([CTL_TOOL['path'], '--user', 'stop', unit], env=env, timeout=5, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            process.kill(); process.wait(timeout=5); exitcode = 1
    # Parent fail-safe cleanup after unit timeout/worker failure: only a mount
    # whose captured identity is still exact may be unmounted.
    current = read_mount(root / 'mount')
    cleanup = []
    if current:
        marker = root / 'owned-mount.json'
        if not marker.is_file() or not same_mount(current, json.loads(marker.read_bytes())):
            cleanup.append('uncaptured/mismatched own-path mount; no unmount issued')
        else:
            try: run_known([FUSE_TOOL['path'], '-u', str(root / 'mount')], root, 'parent-unmount', {'LANG': 'C', 'PATH': '/usr/bin:/bin'}, 5)
            except Exception as error: cleanup.append(str(error)[:512])
        if read_mount(root / 'mount'): cleanup.append('owned mount remains')
    if cleanup: exitcode = 1
    execution = {'root': str(root), 'unit': unit, 'exitCode': exitcode, 'cleanupErrors': cleanup,
                 'nativeActions': False, 'fullRustBuild': False, 'artifactsPreserved': True}
    with (root / 'launcher-execution.json').open('x') as output: json.dump(execution, output)
    # Emit bounded OWN failure diagnostics before runner cleanup; never an env.
    if exitcode:
        logs = []; remaining = 16384
        for name in ['unit.stderr', 'fuse.stderr', 'format.stderr', 'unmount.stderr', 'parent-unmount.stderr']:
            path = root / name
            if not path.is_file() or path.is_symlink(): continue
            with path.open('rb') as source: raw = source.read(remaining)
            remaining -= len(raw); logs.append({'file': name, 'utf8': raw.decode('utf8', errors='replace'), 'capturedBytes': len(raw)})
            if not remaining: break
        execution['ownFailureLogs'] = logs
    return execution


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--run-proof', action='store_true')
    parser.add_argument('--package-report', type=pathlib.Path); parser.add_argument('--host-report', type=pathlib.Path)
    parser.add_argument('--expected-package-report-sha'); parser.add_argument('--expected-host-report-sha')
    parser.add_argument('--package-root', type=pathlib.Path); parser.add_argument('--worker-root', type=pathlib.Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_root is not None:
        root = args.worker_root
        if not re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp/universe-electrs-fuse-proof-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', str(root)) or root.is_symlink() or root.stat().st_uid != 1001:
            raise ValueError('exact owned worker namespace required')
        try: code = worker(root)
        except Exception as error:
            with (root / 'early-failure.json').open('x') as output: json.dump({'type': type(error).__name__, 'reason': str(error)[:512], 'originalErrorPreserved': True, 'nativeActions': False}, output)
            raise
        raise SystemExit(code)
    if not args.run_proof:
        print(json.dumps({'preparedOnly': True, 'deviceOpened': False, 'mounted': False})); return
    reports = []
    for path, expected in [(args.package_report, args.expected_package_report_sha), (args.host_report, args.expected_host_report_sha)]:
        if path is None or path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024 or not re.fullmatch('[0-9a-f]{64}', expected or '') or digest(path) != expected: raise ValueError('reviewed immutable actual package/host receipts required')
        value = json.loads(path.read_bytes()); reports.append(value.get('metadata', value))
    if args.package_root is None or not args.package_root.is_absolute(): raise ValueError('reviewed private package data root required')
    result = launch(*reports, args.package_root); print(json.dumps(result))
    if result['exitCode']: raise SystemExit(1)


if __name__ == '__main__': main()
