"""Trusted tiny-source compiler/exec inside one bounded unit; no Cargo/installs."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 2:
        raise ValueError('owned context required')
    context = pathlib.Path(sys.argv[1]).resolve(strict=True)
    private = context.parent
    value = json.loads(context.read_text())
    if private.name != 'private' or pathlib.Path(value['private']).resolve() != private:
        raise ValueError('owned private path drift')
    group = [line[3:] for line in pathlib.Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::')][0]
    if not group.endswith('/' + value['unit']):
        raise ValueError('not own capped unit')
    root = pathlib.Path('/sys/fs/cgroup') / group.lstrip('/')
    actual = {name: (root / name).read_text().strip() for name in ['cpu.max', 'memory.max', 'pids.max', 'io.weight']}
    if actual != {'cpu.max': '100000 100000', 'memory.max': '67108864', 'pids.max': '16', 'io.weight': 'default 1'}:
        raise ValueError('actual resource limits absent')
    if os.getpriority(os.PRIO_PROCESS, 0) != 19:
        raise ValueError('actual nice mismatch')
    with (private / 'resource-receipt.json').open('x') as out:
        json.dump({'cgroup': group, 'actual': actual, 'nice': 19, 'pid': os.getpid()}, out)
    deadline = time.monotonic() + 4
    while not (private / 'resource-approved').exists():
        if time.monotonic() >= deadline:
            raise ValueError('parent properties not verified')
        time.sleep(0.02)
    source = private / 'confinement-proof.c'
    if digest(source) != value['sourceSha256'] or digest(value['cc']['path']) != value['cc']['sha256']:
        raise ValueError('trusted source/compiler drift')
    binary = private / 'confinement-proof'
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': str(private), 'TMPDIR': str(private)}
    with (private / 'compile.stdout').open('xb') as stdout, (private / 'compile.stderr').open('xb') as stderr:
        subprocess.run([value['cc']['path'], '-std=c11', '-O0', '-static', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(binary)], env=env, cwd=private,
                       stdout=stdout, stderr=stderr, timeout=6, check=True)
    # Static ELF is required, not an automatic dynamic fallback.
    if digest(value['readelf']['path']) != value['readelf']['sha256']:
        raise ValueError('observed readelf drift')
    inspection = subprocess.run([value['readelf']['path'], '-l', str(binary)], env=env, capture_output=True,
                                timeout=2, check=True)
    if b'INTERP' in inspection.stdout or len(inspection.stdout) > 16384:
        raise ValueError('unexpected dynamic ELF or inspection bound')
    with (private / 'compiled-receipt.json').open('x') as out:
        json.dump({'sourceSha256': value['sourceSha256'], 'binarySha256': digest(binary),
                   'cc': value['cc'], 'staticElf': True, 'cargoInvoked': False}, out)
    os.execve(str(binary), [str(binary), str(private), value['readonly']], {'PATH': '/usr/bin:/bin', 'LANG': 'C'})


if __name__ == '__main__':
    main()
