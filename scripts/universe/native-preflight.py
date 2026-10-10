"""Read-only Linux build prerequisite metadata, never an installer or build."""
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys

DRAFT = '42ef9c89e2a4cab2865fdbe8c8bcb37e74256715'
LOCK_SHA = 'a46b82fd06e8fe3858a1722ec0098d528bd2f4920bc3116c7e247ef473613236'
SOURCE = pathlib.Path(__file__).resolve().parents[2]
QUALIFICATION_SHA = '16f4fe4b89454d5d2061b4812ccc046a5aa83aadbbeb29cd56445316e403f26d'
HISTORICAL_QUALIFICATION_SHA = '1a86886fb3a9b687004015877904164f4dd5aefdcd81f2ed8b5c7efba52a65e1'
USER_SHOW = ['--user', 'show', '--property=Version,ControlGroup', '--no-pager']
DOCKER_INFO = ['info', '--format', '{"serverVersion":"{{.ServerVersion}}","cgroupVersion":"{{.CgroupVersion}}","cgroupDriver":"{{.CgroupDriver}}","architecture":"{{.Architecture}}"}']
DOCKER_IMAGES = ['image', 'ls', '--no-trunc', '--digests', '--filter', 'reference=rust:1.89.0*', '--format', '{{json .}}']


def read_small(path, maximum=65536):
    with pathlib.Path(path).open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('metadata size bound')
    return raw.decode('utf8').strip()


def run_metadata(argv, cwd=SOURCE, version_tool=None, metadata_role=None):
    if not argv or not pathlib.Path(argv[0]).is_absolute():
        raise ValueError('absolute existing metadata executable required')
    name = pathlib.Path(argv[0]).name
    tail = argv[1:]
    allowed = name == 'git' and (tail in [['rev-parse', 'HEAD'], ['status', '--porcelain']]
                                or len(tail) == 4 and tail[:3] == ['merge-base', '--is-ancestor', DRAFT])
    allowed = allowed or name == 'rustc' and tail in [['-Vv'], ['--print', 'target-list']]
    version_path = shutil.which(version_tool) if version_tool in ['cc', 'c++', 'clang', 'cmake', 'docker'] else None
    allowed = allowed or (version_path is not None and tail == ['--version']
                          and pathlib.Path(version_path).resolve() == pathlib.Path(argv[0]))
    roles = {'user-manager': ('systemctl', USER_SHOW), 'docker-info': ('docker', DOCKER_INFO),
             'docker-images': ('docker', DOCKER_IMAGES)}
    role = roles.get(metadata_role)
    role_path = shutil.which(role[0]) if role else None
    allowed = allowed or (role_path is not None and tail == role[1]
                          and pathlib.Path(role_path).resolve() == pathlib.Path(argv[0]))
    if not allowed:
        raise ValueError('preflight metadata command only; cargo/install/build forbidden')
    env = None
    if role:
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': str(pathlib.Path.home())}
        if metadata_role == 'user-manager':
            env['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
            env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + env['XDG_RUNTIME_DIR'] + '/bus'
        else:
            env['DOCKER_HOST'] = 'unix:///var/run/docker.sock'
            # Do not read inherited Docker credentials/context/configuration.
            env['DOCKER_CONFIG'] = '/run/user/' + str(os.getuid()) + '/electrs-preflight-no-docker-config'
            if pathlib.Path(env['DOCKER_CONFIG']).exists():
                raise ValueError('unexpected docker configuration path exists')
    result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=5, check=True, env=env)
    if len(result.stdout) > 65536 or len(result.stderr) > 8192:
        raise ValueError('metadata command output bound')
    return result.stdout.decode('utf8').strip()


def file_pin(path, source=SOURCE):
    source = pathlib.Path(source).resolve(strict=True)
    path = pathlib.Path(path).resolve(strict=True)
    if path == source or source in path.parents or not path.is_file():
        raise ValueError('tool must be an existing file outside checkout')
    size = path.stat().st_size
    if size > 256 * 1024 * 1024:
        raise ValueError('tool size bound')
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return {'path': str(path), 'bytes': size, 'sha256': sha.hexdigest()}


def require_rust_version(value):
    lines = value.splitlines()
    if not lines or not re.fullmatch(r'rustc 1\.89\.0 \([0-9a-f]+ [0-9-]+\)', lines[0]):
        raise ValueError('exact existing Rust1.89.0 required; no fallback')
    if 'host: x86_64-unknown-linux-gnu' not in lines:
        raise ValueError('existing Linux x86_64 GNU toolchain required')


def cgroup_location(value):
    rows = [line[3:] for line in value.splitlines() if line.startswith('0::')]
    if len(rows) != 1 or not rows[0].startswith('/') or '..' in pathlib.PurePosixPath(rows[0]).parts:
        raise ValueError('invalid own unified cgroup path')
    return pathlib.Path('/sys/fs/cgroup') / rows[0].lstrip('/')


def cmake_requirement(lock_bytes, app_bytes, qualification_bytes):
    import tomllib
    qualification_sha = hashlib.sha256(qualification_bytes).hexdigest()
    if qualification_sha not in [QUALIFICATION_SHA, HISTORICAL_QUALIFICATION_SHA]:
        raise ValueError('native requirement qualification byte drift')
    value = json.loads(qualification_bytes)
    if value['schema'] not in ['universe-electrs-native-tool-requirements-v1', 'universe-electrs-native-tool-requirements-v2']:
        raise ValueError('unknown native requirement schema')
    if hashlib.sha256(lock_bytes).hexdigest() != value['cargoLockSha256'] or hashlib.sha256(app_bytes).hexdigest() != value['cargoTomlSha256']:
        raise ValueError('unknown lock/feature profile; CMake requirement needs review')
    lock = tomllib.loads(lock_bytes.decode())
    app = tomllib.loads(app_bytes.decode())
    if value['schema'] == 'universe-electrs-native-tool-requirements-v2':
        if qualification_sha != QUALIFICATION_SHA or value['cargoLockSha256'] != LOCK_SHA or value['profileEligibility'] != 'UNQUALIFIED_FINAL233_SELECTION' or value['cmakeRequired'] is not True:
            raise ValueError('final profile cannot waive unresolved native tool selection')
        if not any(package['name'] == 'cmake' and package['version'] == '0.1.54' for package in lock['package']):
            raise ValueError('final CMake lock identity changed')
        return {'required': True, 'qualificationSha256': qualification_sha, 'profileEligibility': value['profileEligibility'],
                'selectionResolved': False, 'primarySourceReceiptSha256': value['sourceQualificationReceiptSha256'],
                'archiveChecksumVerified': True, 'buildQualified': False}
    if any(package['name'] == 'cmake' for package in lock['package']) or 'zlib-ng' in app_bytes.decode():
        raise ValueError('introduced CMake/zlib-ng cannot be waived')
    if app['features'] != {'default': [], 'liquid': ['elements'], 'electrum-discovery': ['electrum-client']}:
        raise ValueError('unknown application features')
    if value['cmakeRequired'] is not False:
        raise ValueError('CMake classification requires review')
    return {'required': False, 'qualificationSha256': HISTORICAL_QUALIFICATION_SHA, 'profileEligibility': 'HISTORICAL_OLD204_ONLY',
            'primarySourceReceiptSha256': value['sourceQualificationReceiptSha256'],
            'archiveChecksumVerified': False, 'buildQualified': False}


def socket_present(path):
    try:
        return stat.S_ISSOCK(pathlib.Path(path).lstat().st_mode)
    except FileNotFoundError:
        return False


def user_manager_metadata():
    uid = os.getuid()
    bus = pathlib.Path('/run/user') / str(uid) / 'bus'
    value = {'busPath': str(bus), 'busSocketPresent': socket_present(bus), 'managerObserved': False,
             'unitCreated': False, 'settingsChanged': False}
    tool = shutil.which('systemctl')
    if tool:
        value['tool'] = file_pin(tool)
    if value['busSocketPresent'] and tool:
        try:
            response = run_metadata([value['tool']['path'], *USER_SHOW], metadata_role='user-manager')
            pairs = dict(line.split('=', 1) for line in response.splitlines() if '=' in line)
            if set(pairs) - {'Version', 'ControlGroup'}:
                raise ValueError('unexpected manager metadata fields')
            value['properties'] = pairs
            value['managerObserved'] = bool(pairs.get('Version'))
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            value['errorType'] = type(error).__name__
            value['exitCode'] = getattr(error, 'returncode', None)
    return value


def docker_metadata():
    value = {'socketPath': '/var/run/docker.sock', 'socketPresent': socket_present('/var/run/docker.sock'),
             'serverObserved': False, 'images': [], 'imagesPulled': False, 'containersStarted': False}
    tool = shutil.which('docker')
    if not tool:
        value['clientPresent'] = False
        return value
    value['clientPresent'] = True
    value['tool'] = file_pin(tool)
    value['clientVersion'] = run_metadata([value['tool']['path'], '--version'], version_tool='docker')
    if not value['socketPresent']:
        return value
    try:
        info = json.loads(run_metadata([value['tool']['path'], *DOCKER_INFO], metadata_role='docker-info'))
        if set(info) != {'serverVersion', 'cgroupVersion', 'cgroupDriver', 'architecture'}:
            raise ValueError('unexpected Docker metadata')
        value['server'] = info
        value['serverObserved'] = True
        rows = run_metadata([value['tool']['path'], *DOCKER_IMAGES], metadata_role='docker-images').splitlines()
        if len(rows) > 32:
            raise ValueError('existing image summary bound')
        for raw in rows:
            item = json.loads(raw)
            if item['Repository'] not in ['rust', 'docker.io/library/rust'] or not re.fullmatch(r'1\.89\.0(?:[-a-z0-9.]+)?', item['Tag']):
                raise ValueError('nonallowlisted image identity')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', item['ID']):
                raise ValueError('invalid existing image ID')
            if item.get('Digest') not in [None, '<none>'] and not re.fullmatch(r'sha256:[0-9a-f]{64}', item['Digest']):
                raise ValueError('invalid existing image digest')
            value['images'].append({key: item.get(key) for key in ['Repository', 'Tag', 'ID', 'Digest']})
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        value['errorType'] = type(error).__name__
        value['exitCode'] = getattr(error, 'returncode', None)
    return value


def collect():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('owned Linux x86_64 runner required')
    if os.environ.get('GITHUB_REPOSITORY') != 'bitcoinuniverseio/electrs':
        raise ValueError('owned fork only')
    if os.environ.get('GITHUB_REF') != 'refs/heads/develop':
        raise ValueError('reviewed draft branch only')
    expected = os.environ.get('EXPECTED_SOURCE_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', expected):
        raise ValueError('full dispatched source SHA required')
    git = shutil.which('git')
    if not git:
        raise ValueError('existing Git absent')
    git_pin = file_pin(git)
    git = git_pin['path']
    head = run_metadata([git, 'rev-parse', 'HEAD'])
    if head != expected or run_metadata([git, 'status', '--porcelain']):
        raise ValueError('source revision/drift')
    run_metadata([git, 'merge-base', '--is-ancestor', DRAFT, head])
    lock = (SOURCE / 'Cargo.lock').read_bytes()
    if hashlib.sha256(lock).hexdigest() != LOCK_SHA:
        raise ValueError('original lock drift')
    cmake = cmake_requirement(lock, (SOURCE / 'Cargo.toml').read_bytes(),
                              pathlib.Path(__file__).with_name('native-tool-requirements.json').read_bytes())
    report = {'schema': 'universe-electrs-linux-preflight-v1',
              'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'sourceSha': head, 'draftAncestor': DRAFT, 'lockSha256': LOCK_SHA,
              'tools': {'git': git_pin}, 'missing': [], 'nativeActions': False, 'cargoInvoked': False,
              'compiled': False, 'dependencyFetch': False, 'installed': False,
              'fullAdapterQualification': False, 'cmakeRequirement': cmake, 'optionalMissing': []}
    home = pathlib.Path.home()
    # Exactly this version/target, never rustup shims, PATH Rust or another version.
    rust_bin = home / '.rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin'
    for name in ['rustc', 'cargo']:
        path = rust_bin / name
        if not path.is_file():
            report['missing'].append('existing-' + name + '-1.89.0')
            continue
        if path.is_symlink():
            raise ValueError('Rust executable must be direct, never rustup/proxy')
        pin = file_pin(path)
        if pathlib.Path(pin['path']).name != name:
            raise ValueError('Rust executable proxy rejected')
        if name == 'rustc':
            version = run_metadata([pin['path'], '-Vv'])
            require_rust_version(version)
            pin['version'] = version
            target = run_metadata([pin['path'], '--print', 'target-list'])
            pin['linuxTargetSupported'] = 'x86_64-unknown-linux-gnu' in target.splitlines()
            lib = rust_bin.parent / 'lib/rustlib/x86_64-unknown-linux-gnu/lib'
            pin['targetStdlibPresent'] = lib.is_dir() and any(lib.glob('libstd-*.rlib'))
            if not pin['linuxTargetSupported']:
                report['missing'].append('existing-rustc-linux-target-support')
            if not pin['targetStdlibPresent']:
                report['missing'].append('existing-rust-linux-target-stdlib')
        else:
            pin['versionNotInvoked'] = True
            pin['versionDirectoryOnlyNotCompilerQualification'] = '1.89.0'
        report['tools'][name] = pin
    for name in ['cc', 'c++', 'clang', 'cmake', 'unshare', 'systemd-run']:
        path = shutil.which(name)
        if not path:
            if name == 'cmake' and not cmake['required']:
                report['optionalMissing'].append('existing-cmake-unrequired-for-exact-reviewed-profile')
            else:
                report['missing'].append('existing-' + name)
            continue
        report['tools'][name] = file_pin(path)
        if name in ['cc', 'c++', 'clang', 'cmake']:
            report['tools'][name]['version'] = run_metadata([report['tools'][name]['path'], '--version'], version_tool=name)[:8192]
    prefix = pathlib.Path(os.environ.get('UNIVERSE_HOST_TOOLS_ROOT', str(home / '.local/universe-host-tools'))) / 'prefix'
    report['hostToolsPrefixPresent'] = prefix.is_dir()
    report['sharedInstallerInvoked'] = False
    # Bounded known libclang locations only, no recursive host inventory.
    libraries = [prefix / 'usr/lib/x86_64-linux-gnu/libclang.so.1',
                 prefix / 'lib/libclang.so', pathlib.Path('/usr/lib/llvm-18/lib/libclang.so.1')]
    report['libclang'] = [file_pin(path) for path in libraries if path.is_file()]
    if not report['libclang']:
        report['missing'].append('existing-libclang-known-paths')
    mem = read_small('/proc/meminfo')
    allowed = ['MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree']
    report['memoryKiB'] = {key: int(re.search(r'^' + key + r':\s+(\d+) kB$', mem, re.M).group(1)) for key in allowed}
    temp = pathlib.Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    if temp == SOURCE or SOURCE in temp.parents or temp == pathlib.Path('/'):
        raise ValueError('runner temp scope invalid')
    report['freeTempBytes'] = shutil.disk_usage(temp).free
    report['pressure'] = {name: read_small('/proc/pressure/' + name, 4096) for name in ['cpu', 'io', 'memory']}
    group = cgroup_location(read_small('/proc/self/cgroup', 4096))
    report['ownCgroup'] = {name: read_small(group / name, 4096) for name in
                          ['cgroup.controllers', 'cgroup.type', 'cpu.max', 'memory.max', 'pids.max'] if (group / name).is_file()}
    report['ownCgroupWritableMetadata'] = os.access(group / 'cgroup.procs', os.W_OK)
    user_limit = pathlib.Path('/proc/sys/user/max_user_namespaces')
    report['maxUserNamespaces'] = int(read_small(user_limit, 64)) if user_limit.is_file() else None
    report['sandboxCreationProven'] = False
    report['userManager'] = user_manager_metadata()
    if not report['userManager']['managerObserved']:
        report['dockerAvailability'] = docker_metadata()
    report['buildAdmissionQualified'] = False
    report['durableHeadroomProven'] = False
    report['nextGates'] = ['Reviewed tool hashes/version and full locked Linux source build',
                           'Controlled owned resource/network sandbox creation proof',
                           'Existing-store/reorg completeness and actual Hyper/RocksDB tests']
    report['metadataToolsPresent'] = not report['missing']
    return report


def main():
    report = collect()
    raw = json.dumps(report, sort_keys=True)
    if len(raw.encode()) > 262144:
        raise ValueError('receipt bound')
    print(raw)
    # Partial metadata survives stdout; absent requirements never trigger installs.
    return 0 if report['metadataToolsPresent'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
