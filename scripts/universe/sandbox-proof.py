"""Root-reviewed controlled15s user-unit proof only. No compile/native action."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import time

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('metadata', HERE / 'native-preflight.py')
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)
RUN_TOOL = {'path': '/usr/bin/systemd-run', 'sha256': 'dbc8b988a849d5c9d7ef2de7068a6f107021bc6c11e0d7864c73f373eef726a7'}
CTL_TOOL = {'path': '/usr/bin/systemctl', 'sha256': 'e0d3d0e9444da1b2b58c792c3f5028b69f049b77d5ca17b3ec0d09f89117225b'}
PROPERTIES = ['ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'RuntimeMaxUSec', 'TimeoutStopUSec',
              'CPUQuotaPerSecUSec', 'MemoryMax', 'TasksMax', 'IOWeight', 'Nice', 'ProtectSystem',
              'ReadWritePaths', 'PrivateNetwork', 'PrivateUsers', 'NoNewPrivileges', 'KillMode']


def hash_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned_tool(expected):
    actual = metadata.file_pin(expected['path'])
    if actual['path'] != expected['path'] or actual['sha256'] != expected['sha256']:
        raise ValueError('observed existing systemd tool drift')
    return actual


def unit_name(run, attempt, nonce):
    if not re.fullmatch('[1-9][0-9]{0,19}', run) or not re.fullmatch('[1-9][0-9]{0,3}', attempt) or not re.fullmatch('[0-9a-f]{16}', nonce):
        raise ValueError('owned job/unit identity malformed')
    return 'universe-electrs-sandbox-probe-' + run + '-' + attempt + '-' + nonce + '.service'


def validate_properties(value, unit, private):
    if set(value) != set(PROPERTIES):
        raise ValueError('actual unit property set mismatch')
    expected = {'ActiveState': 'active', 'SubState': 'running', 'RuntimeMaxUSec': '15s',
                'TimeoutStopUSec': '5s', 'CPUQuotaPerSecUSec': '1s', 'MemoryMax': '67108864',
                'TasksMax': '16', 'IOWeight': '1', 'Nice': '19', 'ProtectSystem': 'strict',
                'ReadWritePaths': str(private), 'PrivateNetwork': 'yes', 'PrivateUsers': 'yes',
                'NoNewPrivileges': 'yes', 'KillMode': 'control-group'}
    if any(value[key] != item for key, item in expected.items()):
        raise ValueError('actual unit enforcement property mismatch')
    if not value['MainPID'].isdigit() or int(value['MainPID']) <= 0 or not value['ControlGroup'].endswith('/' + unit):
        raise ValueError('actual owned unit/PID mismatch')


def child_env():
    uid = os.getuid()
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': str(pathlib.Path.home()),
            'XDG_RUNTIME_DIR': '/run/user/' + str(uid),
            'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(uid) + '/bus'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-proof', action='store_true')
    args = parser.parse_args()
    if not args.run_proof:
        print(json.dumps({'preparedOnly': True, 'unitCreated': False, 'cargoInvoked': False}))
        return
    report = metadata.collect()  # Exact owned source/lock/profile/tool/current bus guards.
    if not report['metadataToolsPresent'] or not report['userManager']['managerObserved']:
        raise ValueError('current source/tools/user manager unavailable; no fallback')
    if os.getuid() != 1001 or report['userManager']['busPath'] != '/run/user/1001/bus' or report['userManager']['properties'] != {'Version': '255.4-1ubuntu8.17', 'ControlGroup': '/github.slice/github-runners.slice/user@1001.service'}:
        raise ValueError('observed owned user-manager context drift')
    run_tool = pinned_tool(RUN_TOOL)
    ctl_tool = pinned_tool(CTL_TOOL)
    python = metadata.file_pin('/usr/bin/python3')
    if pathlib.Path(python['path']).name != 'python3.12':
        raise ValueError('existing Ubuntu Python3.12 context not observed; no fallback')
    version = subprocess.run([python['path'], '--version'], capture_output=True, timeout=3, check=True)
    if len(version.stdout) > 128 or len(version.stderr) > 128:
        raise ValueError('existing Python version metadata bound')
    python['version'] = version.stdout.decode().strip()
    python_qualified = re.fullmatch(rb'Python 3\.12\.[0-9]+\s*', version.stdout) is not None
    print(json.dumps({'schema': 'universe-sandbox-firststage-python-v1', 'sourceSha': report['sourceSha'],
                      'python': python, 'qualifiedForPureStdlibProbe': python_qualified, 'unitCreated': False}), flush=True)
    if not python_qualified:
        raise ValueError('existing Python version not qualified')
    temp = pathlib.Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    if temp.stat().st_uid != os.getuid() or not temp.is_dir() or temp == pathlib.Path('/') or metadata.SOURCE in temp.parents:
        raise ValueError('owned runner temporary root not qualified')
    nonce = os.urandom(8).hex()
    unit = unit_name(os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'], nonce)
    root = temp / unit.removesuffix('.service')
    root.mkdir(mode=0o700)
    private = root / 'private'
    private.mkdir(mode=0o700)
    readonly = root / 'readonly'
    readonly.mkdir(mode=0o700)
    control = readonly / 'control'
    control.write_bytes(b'new-owned-readonly-control')
    control.chmod(0o666)
    source = (HERE / 'sandbox-proof-child.py').read_bytes()
    child = private / 'child.py'
    child.write_bytes(source)
    child.chmod(0o444)
    context = {'unit': unit, 'sourceSha': report['sourceSha'], 'childSha256': hash_bytes(source),
               'pythonPath': python['path'], 'readOnlyControl': str(control),
               'parentNetNamespace': os.readlink('/proc/self/ns/net'),
               'parentUserNamespace': os.readlink('/proc/self/ns/user'),
               'parentCgroup': [line[3:] for line in metadata.read_small('/proc/self/cgroup', 4096).splitlines() if line.startswith('0::')][0]}
    context_path = private / 'context.json'
    context_path.write_text(json.dumps(context))
    context_path.chmod(0o444)
    with (root / 'prelaunch-tool-context.json').open('x') as out:
        json.dump({'sourceSha': report['sourceSha'], 'unit': unit, 'python': python,
                   'systemdRun': run_tool, 'systemctl': ctl_tool,
                   'observedUserManager': report['userManager'], 'unitCreated': False}, out)
    argv = [run_tool['path'], '--user', '--unit=' + unit, '--collect', '--wait', '--pipe', '--service-type=exec',
            '--property=CPUQuota=100%', '--property=CPUQuotaPeriodSec=100ms', '--property=MemoryMax=64M',
            '--property=TasksMax=16', '--property=RuntimeMaxSec=15s', '--property=TimeoutStopSec=5s',
            '--property=Nice=19', '--property=IOWeight=1', '--property=ProtectSystem=strict',
            '--property=ReadOnlyPaths=/', '--property=ReadWritePaths=' + str(private),
            '--property=PrivateNetwork=yes', '--property=PrivateUsers=yes', '--property=NoNewPrivileges=yes',
            '--property=KillMode=control-group', '--setenv=TMPDIR=' + str(private),
            '--setenv=PYTHONDONTWRITEBYTECODE=1', '--', python['path'], '-B', '-I', '-S', str(child), str(context_path)]
    if metadata.file_pin(python['path'])['sha256'] != python['sha256']:
        raise ValueError('Python changed before launch')
    pinned_tool(RUN_TOOL)
    pinned_tool(CTL_TOOL)
    started = time.monotonic()
    process = None
    try:
        with (root / 'unit.stdout').open('xb') as stdout, (root / 'unit.stderr').open('xb') as stderr:
            process = subprocess.Popen(argv, env=child_env(), stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 10
            while not (private / 'child-receipt.json').is_file():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError('scope failed/child proof unavailable; no retry')
                time.sleep(0.02)
            child_report = json.loads(metadata.read_small(private / 'child-receipt.json', 16384))
            # Child source validated actual limits; parent verifies accepted unit policy while alive.
            proof = subprocess.run([ctl_tool['path'], '--user', 'show', unit,
                                    '--property=' + ','.join(PROPERTIES), '--no-pager'],
                                   env=child_env(), capture_output=True, timeout=3, check=True)
            properties = dict(line.split('=', 1) for line in proof.stdout.decode().splitlines() if '=' in line)
            validate_properties(properties, unit, private)
            if child_report['cgroup'] != properties['ControlGroup']:
                raise ValueError('unit/child cgroup differs')
            (private / 'release').write_bytes(b'parent-properties-verified')
            if process.wait(timeout=max(1, 25 - (time.monotonic() - started))) != 0:
                raise ValueError('actual unit completion failed')
        if control.read_bytes() != b'new-owned-readonly-control':
            raise ValueError('controlled readonly bytes changed')
        result = {'schema': 'universe-electrs-controlled-user-sandbox-proof-v1',
                  'sourceSha': report['sourceSha'], 'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'unit': unit, 'python': python, 'systemdRun': run_tool, 'systemctl': ctl_tool,
                  'child': child_report, 'actualProperties': properties, 'elapsedSeconds': time.monotonic() - started,
                  'scopeProofPassed': True, 'cargoInvoked': False, 'compiled': False,
                  'nativeActions': False, 'fullBuildAdmissionQualified': False}
        with (root / 'result.json').open('x') as out:
            json.dump(result, out)
        print(json.dumps(result))
    except BaseException as error:
        # Stop only our exact unique probe if a failed/uncertain client remains. Never retry proof.
        cleanup = None
        cleanup_error = None
        if process is not None and process.poll() is None:
            try:
                cleanup = subprocess.run([ctl_tool['path'], '--user', 'stop', unit], env=child_env(),
                                         capture_output=True, timeout=8)
                with (root / 'cleanup.stdout').open('xb') as out:
                    out.write(cleanup.stdout)
                with (root / 'cleanup.stderr').open('xb') as out:
                    out.write(cleanup.stderr)
                process.wait(timeout=8)
            except BaseException as secondary:
                cleanup_error = type(secondary).__name__ + ': ' + str(secondary)
        with (root / 'failure.json').open('x') as out:
            json.dump({'sourceSha': report['sourceSha'], 'unit': unit, 'scopeProofPassed': False,
                       'errorType': type(error).__name__, 'error': str(error), 'originalLogsRetained': True,
                       'cleanupExitCode': cleanup.returncode if cleanup else None,
                       'cleanupError': cleanup_error, 'retry': False}, out)
        raise


if __name__ == '__main__':
    main()
