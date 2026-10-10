"""Explicit owned-runner cache observation only. No Cargo/fetch/unit/install/build."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import stat
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
PYTHON = {'path': '/usr/bin/python3.12', 'sha256': 'e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f'}
MAX_OUTPUT = 256 * 1024
CACHE = pathlib.Path('/home/github-runner/.cargo')


def load_source(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def bounded_read(path, maximum=32768):
    with pathlib.Path(path).open('rb') as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('read-only metadata bound')
    return raw.decode('ascii', errors='strict')


def runtime_guard():
    if platform.system() != 'Linux' or os.getuid() != 1001 or os.environ.get('GITHUB_REPOSITORY') != 'bitcoinuniverseio/electrs':
        raise ValueError('exact owned Linux account/repository required')
    if os.environ.get('GITHUB_REF') != 'refs/heads/codex/bounded-script-utxo-pages':
        raise ValueError('owned branch required')
    if not sys.dont_write_bytecode or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError('existing Python -B -I -S required; no bytecode/site effects')
    expected = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', expected):
        raise ValueError('full dispatched source SHA required')
    executable = pathlib.Path(sys.executable).resolve(strict=True)
    if str(executable) != PYTHON['path'] or executable.stat().st_size > 16 * 1024 * 1024 or hashlib.sha256(executable.read_bytes()).hexdigest() != PYTHON['sha256']:
        raise ValueError('observed direct Python pin mismatch')
    return expected


def headroom_report(temp):
    temp = pathlib.Path(temp)
    if not re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp', str(temp)):
        raise ValueError('known owned runner temporary path required')
    for path in [temp, *temp.parents]:
        if path.is_symlink():
            raise ValueError('linked temporary path')
    info = temp.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 1001:
        raise ValueError('owned temporary directory required')
    fields = {}
    for line in bounded_read('/proc/meminfo').splitlines():
        if line.startswith('MemAvailable:'):
            match = re.fullmatch(r'MemAvailable:\s+([0-9]{1,16}) kB', line)
            if not match or 'MemAvailable' in fields:
                raise ValueError('memory metadata malformed')
            fields['MemAvailable'] = int(match[1])
    if 'MemAvailable' not in fields:
        raise ValueError('memory availability missing')
    disk = os.statvfs(temp)
    return {'memoryKiB': fields, 'freeTempBytes': disk.f_bavail * disk.f_frsize,
            'pressure': {kind: bounded_read('/proc/pressure/' + kind, 4096) for kind in ['cpu', 'io']}}


def source_guard(inventory, expected):
    if inventory.git_read(['rev-parse', 'HEAD'], SOURCE) != expected or inventory.git_read(['status', '--porcelain'], SOURCE):
        raise ValueError('source HEAD/drift guard')


def result_gates(report):
    packages = report['packages']
    if len(packages) != 204 or sum(p['source'].startswith('registry+') for p in packages) != 203 or sum(p['source'].startswith('git+') for p in packages) != 1:
        raise ValueError('exact204/203/1 lock denominator required')
    rocks = [p for p in packages if p['name'] == 'librocksdb-sys']
    if len(rocks) != 1:
        raise ValueError('locked RocksDB source ambiguity')
    return {'archiveMissing': [{'name': p['name'], 'version': p['version']} for p in packages if p['state'] == 'archive-missing'],
            'archiveUnqualified': [{'name': p['name'], 'version': p['version'], 'state': p['state'], 'reason': p.get('reason')} for p in packages if p['source'].startswith('registry+') and p['state'] not in ['archive-missing', 'checksum-and-vendor-qualified']],
            'lockedRegistryChecksumsPresent': True,
            'rocksdbVendorAuthorsAndSnappyQualified': rocks[0]['complete'],
            'gitSource': [p for p in packages if p['source'].startswith('git+')],
            'exactVendorMaterializationQualified': False, 'fullBuildAdmissionQualified': False}


def observe():
    expected = runtime_guard()
    inventory = load_source('locked_inventory', HERE / 'locked-source-inventory.py')
    source_guard(inventory, expected)
    # Reuse the independently reviewed strict PSI parser; never call its main.
    proof = load_source('reviewed_pressure', HERE / 'confinement-proof.py')
    resources = headroom_report(os.environ.get('RUNNER_TEMP', ''))
    admission = proof.headroom(resources)  # Before any cache file is read.
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    monotonic = time.monotonic()
    raw = (SOURCE / 'Cargo.lock').read_bytes()
    packages = inventory.parse_lock(raw)
    if len(packages) != 204:
        raise ValueError('exact locked source denominator required')
    report = inventory.inventory(packages, CACHE)
    source_guard(inventory, expected)
    ended = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report.update({'sourceSha': expected, 'observationStartedAt': started, 'observationCompletedAt': ended,
                   'elapsedSeconds': time.monotonic() - monotonic, 'readOnlyHeadroom': admission,
                   'observedResources': {'availableMemoryKiB': resources['memoryKiB']['MemAvailable'],
                                         'freeTemporaryBytes': resources['freeTempBytes']},
                   'gates': result_gates(report), 'unitCreated': False, 'installed': False,
                   'python': PYTHON, 'scope': 'SOURCE_CACHE_AVAILABILITY_ONLY_NOT_NATIVE_QUALIFICATION'})
    output = json.dumps(report, separators=(',', ':'), allow_nan=False).encode()
    if len(output) > MAX_OUTPUT:
        raise ValueError('inventory output payload bound')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observe-owned-cache', action='store_true')
    args = parser.parse_args()
    if not args.observe_owned_cache:
        print(json.dumps({'preparedOnly': True, 'cacheRead': False, 'cargoInvoked': False, 'unitCreated': False}))
        return
    sys.stdout.buffer.write(observe() + b'\n')
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
