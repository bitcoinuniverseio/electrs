"""Read only exact failed38017693834 probe files or its bounded user journal."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess
import selectors
import time
import datetime

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('metadata', HERE / 'native-preflight.py')
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)
OLD_SOURCE = 'ddabecc64aaf542ca3ae511293ff7c5fa5742e0c'
PREVIOUS = pathlib.Path('/opt/github-runners/runner-27/_work/_temp')
PREFIX = 'universe-electrs-sandbox-probe-38017693834-1-'
MAX_BYTES = 32768
FILES = ['unit.stdout', 'unit.stderr', 'failure.json', 'prelaunch-tool-context.json', 'cleanup.stdout', 'cleanup.stderr']


def owned_unit(name):
    return re.fullmatch(re.escape(PREFIX) + r'[0-9a-f]{16}\.service', name) is not None


def secret_free(raw):
    if re.search(rb'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)', raw):
        raise ValueError('potential secret literal; raw diagnostic withheld')


def emit_json(value):
    raw = json.dumps(value, ensure_ascii=False)
    if len(raw.encode('utf8')) > MAX_BYTES:
        raise ValueError('encoded diagnostic output bound')
    print(raw, flush=True)


def source_guard():
    if os.environ.get('GITHUB_REPOSITORY') != 'bitcoinuniverseio/electrs' or os.environ.get('GITHUB_REF') != 'refs/heads/codex/bounded-script-utxo-pages':
        raise ValueError('owned source only')
    expected = os.environ.get('EXPECTED_SOURCE_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', expected):
        raise ValueError('exact source SHA required')
    git = metadata.file_pin('/usr/bin/git')['path']
    if metadata.run_metadata([git, 'rev-parse', 'HEAD']) != expected or metadata.run_metadata([git, 'status', '--porcelain']):
        raise ValueError('source drift')
    return expected


def read_known_folder(folder):
    folder = pathlib.Path(folder)
    if folder.parent != PREVIOUS or not owned_unit(folder.name + '.service'):
        raise ValueError('not exact failed-run folder')
    for item in [folder, *folder.parents]:
        if item.is_symlink():
            raise ValueError('linked failed-run path')
    if folder.stat().st_uid != os.getuid() or not folder.is_dir():
        raise ValueError('failed folder owner/type drift')
    total = 0
    result = []
    for name in FILES:
        path = folder / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError('known diagnostic file type/owner drift')
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES - total + 1)
        total += len(raw)
        if total > MAX_BYTES:
            raise ValueError('aggregate diagnostic byte bound')
        secret_free(raw)
        if name in ['failure.json', 'prelaunch-tool-context.json']:
            record = json.loads(raw)
            if record['sourceSha'] != OLD_SOURCE or record['unit'] != folder.name + '.service':
                raise ValueError('failed source/unit provenance drift')
        result.append({'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                       'rawUtf8': raw.decode('utf8')})
    return {'folder': str(folder), 'unit': folder.name + '.service', 'bytes': total, 'files': result}


def filtered_journal(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('journal byte bound')
    result = []
    for line in raw.splitlines():
        value = json.loads(line)
        units = [value.get('_SYSTEMD_USER_UNIT'), value.get('USER_UNIT')]
        unit = next((unit for unit in units if isinstance(unit, str) and owned_unit(unit)), None)
        if unit is None:
            continue
        timestamp = value.get('__REALTIME_TIMESTAMP')
        lower = int(datetime.datetime(2026, 10, 10, 2, 38, 27, tzinfo=datetime.timezone.utc).timestamp() * 1000000)
        if not isinstance(timestamp, str) or not timestamp.isdigit() or not lower <= int(timestamp) <= lower + 3000000:
            raise ValueError('owned journal timestamp outside exact interval')
        message = value.get('MESSAGE')
        if not isinstance(message, str):
            raise ValueError('unexpected journal message type')
        secret_free(message.encode())
        result.append({'unit': unit, 'timestampMicroseconds': value.get('__REALTIME_TIMESTAMP'), 'message': message})
    return result


def journal_fallback():
    tool = metadata.file_pin('/usr/bin/journalctl')
    if tool['path'] != '/usr/bin/journalctl':
        raise ValueError('unexpected journal CLI path')
    argv = [tool['path'], '--user-unit=' + PREFIX + '*.service',
            '--since=2026-10-10 02:38:27 UTC', '--until=2026-10-10 02:38:30 UTC',
            '--output=json', '--no-pager', '--quiet']
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': str(pathlib.Path.home())}
    process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, 'stdout')
        streams.register(process.stderr, selectors.EVENT_READ, 'stderr')
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        deadline = time.monotonic() + 3
        while streams.get_map():
            if time.monotonic() >= deadline:
                raise ValueError('owned journal read deadline')
            for key, _ in streams.select(timeout=0.05):
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    streams.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(block)
                if len(buffers[key.data]) > (MAX_BYTES if key.data == 'stdout' else 4096):
                    raise ValueError('owned journal output exceeds bound')
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        raw, errors = bytes(buffers['stdout']), bytes(buffers['stderr'])
        if process.returncode != 0:
            raise ValueError('owned journal unavailable')
        return {'tool': tool, 'entries': filtered_journal(raw), 'bytes': len(raw),
                'rawSha256': hashlib.sha256(raw).hexdigest(), 'scope': 'exact previousrun/attempt/3second interval only'}
    finally:
        if process.poll() is None:
            process.kill()  # Only this owned read-only helper, never a unit or native process.
            process.wait(timeout=3)


def recover():
    current = source_guard()
    matches = []
    if PREVIOUS.is_dir():
        matches = [path for path in PREVIOUS.glob(PREFIX + '*') if owned_unit(path.name + '.service')]
    if len(matches) > 1:
        raise ValueError('multiple failed-run folders; no guessed selection')
    result = {'schema': 'universe-exact-failed-user-probe-diagnostic-v1', 'sourceSha': current,
              'failedSourceSha': OLD_SOURCE, 'failedRun': 38017693834, 'failedAttempt': 1,
              'unitCreated': False, 'unitRetry': False, 'buildInvoked': False, 'nativeActions': False}
    if matches:
        result['knownFiles'] = read_known_folder(matches[0])
    else:
        result['folderCleanedOrAbsent'] = True
        result['journal'] = journal_fallback()
    result['scopeProofPassed'] = False
    result['fullBuildAdmissionQualified'] = False
    return result


def emit_failure(folder, unit):
    """Future failure emission, bounded known files only; no journal/operational calls."""
    if not re.fullmatch(r'universe-electrs-sandbox-probe-[1-9][0-9]{0,19}-[1-9][0-9]{0,3}-[0-9a-f]{16}\.service', unit):
        raise ValueError('owned failed unit required')
    folder = pathlib.Path(folder)
    if folder.name != unit.removesuffix('.service') or folder.parent.resolve() != pathlib.Path(os.environ['RUNNER_TEMP']).resolve():
        raise ValueError('future diagnostic outside owned runner temp')
    total = 0
    files = []
    for name in ['unit.stdout', 'unit.stderr']:
        path = pathlib.Path(folder) / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('linked future diagnostic')
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES - total + 1)
        total += len(raw)
        if total > MAX_BYTES:
            raise ValueError('future failure output bound')
        secret_free(raw)
        files.append({'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'rawUtf8': raw.decode()})
    emit_json({'schema': 'universe-owned-probe-failure-output-v1', 'unit': unit,
               'receiptPath': str(pathlib.Path(folder) / 'failure.json'), 'files': files})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recover-only', action='store_true')
    args = parser.parse_args()
    if not args.recover_only:
        print(json.dumps({'preparedOnly': True, 'unitCreated': False, 'unitRetry': False}))
        return
    emit_json(recover())


if __name__ == '__main__':
    main()
