"""Unexecuted alternative proof controller. Explicit root-reviewed run only."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import time
import re
import base64

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scope', HERE / 'sandbox-proof.py')
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)
CC = {'path': '/usr/bin/x86_64-linux-gnu-gcc-13', 'sha256': '1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26'}
PYTHON = {'path': '/usr/bin/python3.12', 'sha256': 'e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f'}
PROPERTIES = ['ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'RuntimeMaxUSec', 'TimeoutStopUSec',
              'CPUQuotaPerSecUSec', 'MemoryMax', 'TasksMax', 'IOWeight', 'Nice', 'NoNewPrivileges', 'KillMode']


def headroom(report):
    if report['memoryKiB']['MemAvailable'] < 1048576 or report['freeTempBytes'] < 1073741824:
        raise ValueError('small proof requires1GiB memory and temporary disk headroom')
    maxima = {}
    for kind, maximum in [('cpu', 25.0), ('io', 5.0)]:
        values = re.findall(r'avg(?:10|60|300)=([0-9]+(?:\.[0-9]+)?)', report['pressure'][kind])
        if not values or any(not 0 <= float(value) <= 100 for value in values):
            raise ValueError('unknown pressure metadata')
        maxima[kind] = max(float(value) for value in values)
        if maxima[kind] > maximum:
            raise ValueError('small proof pressure headroom unavailable')
    return {'minimumAvailableMemoryKiB': 1048576, 'minimumTemporaryDiskBytes': 1073741824,
            'observedPressureMaxima': maxima, 'longBuildHeadroomQualified': False}


def failure_output(root):
    names = ['private/compile.stderr', 'private/proof.stderr', 'unit.stderr', 'unit.stdout',
             'private/compile.stdout', 'private/proof.stdout']
    records = []
    remaining = 16384
    for name in names:
        path = pathlib.Path(root) / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError('unexpected owned failure file type')
        with path.open('rb') as stream:
            raw = stream.read(remaining + 1)
        truncated = len(raw) > remaining
        raw = raw[:remaining]
        remaining -= len(raw)
        if re.search(rb'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)', raw):
            records.append({'file': name, 'rawWithheldForSecretPattern': True})
        else:
            record = {'file': name, 'capturedBytes': len(raw), 'capturedSha256': hashlib.sha256(raw).hexdigest(),
                      'truncated': truncated, 'rawBase64': base64.b64encode(raw).decode()}
            try:
                record['rawUtf8'] = raw.decode('utf8')
            except UnicodeError:
                pass
            records.append(record)
        if remaining == 0:
            break
    value = {'root': str(root), 'ownFailureLogs': records, 'originalFilesRetained': True}
    # Prefer human-readable output; retain exact base64 when JSON escaping would
    # otherwise exceed the bounded32KiB envelope.
    if len(json.dumps(value, ensure_ascii=False).encode()) > 32768:
        for record in sorted(records, key=lambda item: len(item.get('rawUtf8', '').encode()), reverse=True):
            record.pop('rawUtf8', None)
            if len(json.dumps(value, ensure_ascii=False).encode()) <= 32768:
                break
    if len(json.dumps(value, ensure_ascii=False).encode()) > 32768:
        raise ValueError('failure output envelope bound')
    return value


def actual_properties(value, unit):
    expected = {'ActiveState': 'active', 'SubState': 'running', 'RuntimeMaxUSec': '15s',
                'TimeoutStopUSec': '5s', 'CPUQuotaPerSecUSec': '1s', 'MemoryMax': '67108864',
                'TasksMax': '16', 'IOWeight': '1', 'Nice': '19', 'NoNewPrivileges': 'yes', 'KillMode': 'control-group'}
    if set(value) != set(PROPERTIES) or any(value[key] != item for key, item in expected.items()):
        raise ValueError('actual resource properties mismatch')
    if not value['MainPID'].isdigit() or int(value['MainPID']) <= 0 or not value['ControlGroup'].endswith('/' + unit):
        raise ValueError('owned resource identity mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-proof', action='store_true')
    args = parser.parse_args()
    if not args.run_proof:
        print(json.dumps({'preparedOnly': True, 'unitCreated': False, 'compiled': False}))
        return
    report = scope.metadata.collect()
    admission = headroom(report)  # Before task directories or unit creation.
    if not report['metadataToolsPresent'] or not report['userManager']['managerObserved'] or os.getuid() != 1001:
        raise ValueError('known source/tool/user context unavailable')
    for pin in [scope.RUN_TOOL, scope.CTL_TOOL, CC, PYTHON]:
        scope.pinned_tool(pin)
    readelf = scope.metadata.file_pin('/usr/bin/readelf')
    version = subprocess.run([readelf['path'], '--version'], capture_output=True, timeout=2, check=True)
    if not version.stdout.startswith(b'GNU readelf') or len(version.stdout) > 4096:
        raise ValueError('existing readelf context not observed')
    readelf['version'] = version.stdout.decode().strip()
    temp = pathlib.Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    if temp.stat().st_uid != os.getuid() or temp == pathlib.Path('/') or scope.metadata.SOURCE in temp.parents:
        raise ValueError('owned temp root invalid')
    unit = scope.unit_name(os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'], os.urandom(8).hex())
    root = temp / unit.removesuffix('.service')
    root.mkdir(mode=0o700)
    private = root / 'private'; private.mkdir(mode=0o700)
    readonly = root / 'readonly'; readonly.mkdir(mode=0o700)
    control = readonly / 'control'; control.write_bytes(b'owned-readonly-control'); control.chmod(0o666)
    source = (HERE / 'confinement-proof.c').read_bytes()
    (private / 'confinement-proof.c').write_bytes(source)
    wrapper = private / 'build-child.py'; wrapper.write_bytes((HERE / 'confinement-build-child.py').read_bytes())
    value = {'sourceCommit': report['sourceSha'], 'unit': unit, 'private': str(private),
             'readonly': str(control), 'sourceSha256': hashlib.sha256(source).hexdigest(),
             'cc': CC, 'readelf': readelf}
    context = private / 'context.json'; context.write_text(json.dumps(value)); context.chmod(0o444)
    with (root / 'prelaunch.json').open('x') as out: json.dump(value, out)
    argv = [scope.RUN_TOOL['path'], '--user', '--unit=' + unit, '--collect', '--wait', '--pipe', '--service-type=exec',
            '--property=CPUQuota=100%', '--property=CPUQuotaPeriodSec=100ms', '--property=MemoryMax=64M',
            '--property=TasksMax=16', '--property=RuntimeMaxSec=15s', '--property=TimeoutStopSec=5s',
            '--property=Nice=19', '--property=IOWeight=1', '--property=NoNewPrivileges=yes', '--property=KillMode=control-group',
            '--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT LD_PROFILE LD_ORIGIN_PATH GLIBC_TUNABLES GCONV_PATH PYTHONPATH PYTHONHOME',
            '--', PYTHON['path'], '-B', '-I', '-S', str(wrapper), str(context)]
    process = None
    try:
        with (root / 'unit.stdout').open('xb') as out, (root / 'unit.stderr').open('xb') as err:
            process = subprocess.Popen(argv, env=scope.child_env(), stdout=out, stderr=err)
            deadline = time.monotonic() + 6
            while not (private / 'resource-receipt.json').is_file():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise ValueError('resource scope unavailable; no compile/proof fallback')
                time.sleep(0.02)
            raw = subprocess.run([scope.CTL_TOOL['path'], '--user', 'show', unit,
                                  '--property=' + ','.join(PROPERTIES), '--no-pager'],
                                 env=scope.child_env(), capture_output=True, timeout=2, check=True)
            properties = dict(line.split('=', 1) for line in raw.stdout.decode().splitlines() if '=' in line)
            actual_properties(properties, unit)
            (private / 'resource-approved').write_bytes(b'actual-unit-properties-verified')
            deadline = time.monotonic() + 8
            while not (private / 'proof.stdout').is_file() or not (private / 'proof.stdout').stat().st_size:
                if process.poll() is not None or time.monotonic() > deadline:
                    raise ValueError('confinement proof failed; preserve original compile/proof logs')
                time.sleep(0.02)
            proof = json.loads(scope.metadata.read_small(private / 'proof.stdout', 4096))
            expected = ['seccompEnforced', 'outsideWriteDenied', 'privateWriteAllowed', 'allNetworkAndUringDenied',
                        'inheritedFdsClosed', 'forkExecPolicyInherited']
            if any(proof.get(field) is not True for field in expected) or proof.get('landlockAbi', 0) < 3:
                raise ValueError('actual confinement assertions missing')
            if proof['coreConnectionAttempted'] is not False or proof['fullBuildQualified'] is not False:
                raise ValueError('incorrect scope claims')
            (private / 'release').write_bytes(b'actual-confinement-proof-read')
            if process.wait(timeout=10) != 0 or control.read_bytes() != b'owned-readonly-control':
                raise ValueError('actual exit/read-only control mismatch')
        compiled = json.loads(scope.metadata.read_small(private / 'compiled-receipt.json', 16384))
        binary = private / 'confinement-proof'
        if binary.stat().st_size > 16777216:
            raise ValueError('tiny control binary size bound')
        actual_binary = hashlib.sha256(binary.read_bytes()).hexdigest()
        if compiled['binarySha256'] != actual_binary or compiled['sourceSha256'] != value['sourceSha256'] or compiled['staticElf'] is not True or compiled['cargoInvoked'] is not False or compiled['cc'] != CC:
            raise ValueError('actual tiny compiled artifact receipt mismatch')
        print(json.dumps({'sourceSha': report['sourceSha'], 'unit': unit, 'root': str(root),
                          'actualResourceProperties': properties, 'proof': proof,
                          'compiledReceipt': compiled, 'readelfPin': readelf, 'headroomAdmission': admission,
                          'compiledTinyControl': True, 'fullRustBuild': False,
                          'fullBuildQualified': False, 'nativeActions': False}))
    except BaseException as error:
        cleanup_error = None
        if process and process.poll() is None:
            try:
                subprocess.run([scope.CTL_TOOL['path'], '--user', 'stop', unit], env=scope.child_env(), timeout=5, check=True)
                process.wait(timeout=5)
            except BaseException as secondary: cleanup_error = type(secondary).__name__
        with (root / 'failure.json').open('x') as out:
            json.dump({'sourceSha': report['sourceSha'], 'unit': unit, 'errorType': type(error).__name__,
                       'error': str(error), 'cleanupErrorType': cleanup_error, 'proofRetried': False}, out)
        print(json.dumps({'unit': unit, 'root': str(root), 'failed': True, 'originalLogsRetained': True}), flush=True)
        try:
            print(json.dumps(failure_output(root), ensure_ascii=False), flush=True)
        except BaseException as diagnostic_error:
            print(json.dumps({'unit': unit, 'failureReceipt': str(root / 'failure.json'),
                              'diagnosticErrorType': type(diagnostic_error).__name__, 'originalFailurePreserved': True}), flush=True)
        raise


if __name__ == '__main__': main()
