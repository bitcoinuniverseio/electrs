"""Pure stdlib probe inside the sole owned user transient unit. No sockets/build."""
import errno
import hashlib
import json
import os
import pathlib
import sys
import time


def read(path, maximum=65536):
    with pathlib.Path(path).open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('probe metadata bound')
    return raw.decode().strip()


def validate(value, expected):
    if value['netNamespace'] == expected['parentNetNamespace']:
        raise ValueError('network namespace not isolated')
    if value['userNamespace'] == expected['parentUserNamespace']:
        raise ValueError('user namespace not isolated')
    if value['cgroup'] == expected['parentCgroup'] or not value['cgroup'].endswith('/' + expected['unit']):
        raise ValueError('not unique owned probe cgroup')
    quota, period = value['cpuMax'].split()
    if quota == 'max' or int(quota) != int(period) or int(period) != 100000:
        raise ValueError('actual CPU100% quota mismatch')
    if value['memoryMax'] != '67108864' or value['pidsMax'] != '16':
        raise ValueError('actual memory/task limits mismatch')
    if value['ioWeight'] != 'default 1' or value['nice'] != 19:
        raise ValueError('actual scheduling limits mismatch')
    if value['interfaces'] != ['lo']:
        raise ValueError('external network interface present')
    if any(row.split()[0] != 'lo' for row in value['ipv4Routes']):
        raise ValueError('external route present')
    if value['readOnlyControlWriteErrno'] != errno.EROFS:
        raise ValueError('read-only filesystem not proven')


def main():
    if len(sys.argv) != 2:
        raise ValueError('exact owned probe context required')
    context = pathlib.Path(sys.argv[1]).resolve(strict=True)
    private = context.parent
    expected = json.loads(read(context, 16384))
    if hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest() != expected['childSha256']:
        raise ValueError('child source drift')
    if pathlib.Path(sys.executable).resolve() != pathlib.Path(expected['pythonPath']):
        raise ValueError('child interpreter drift')
    group_rows = [line[3:] for line in read('/proc/self/cgroup', 4096).splitlines() if line.startswith('0::')]
    if len(group_rows) != 1 or '..' in pathlib.PurePosixPath(group_rows[0]).parts:
        raise ValueError('own cgroup path malformed')
    group = pathlib.Path('/sys/fs/cgroup') / group_rows[0].lstrip('/')
    value = {'unit': expected['unit'], 'sourceSha': expected['sourceSha'],
             'netNamespace': os.readlink('/proc/self/ns/net'), 'userNamespace': os.readlink('/proc/self/ns/user'),
             'cgroup': group_rows[0], 'cpuMax': read(group / 'cpu.max', 128),
             'memoryMax': read(group / 'memory.max', 128), 'pidsMax': read(group / 'pids.max', 128),
             'ioWeight': read(group / 'io.weight', 128), 'nice': os.getpriority(os.PRIO_PROCESS, 0),
             'interfaces': sorted(line.split(':', 1)[0].strip() for line in read('/proc/net/dev', 4096).splitlines()[2:]),
             'ipv4Routes': read('/proc/net/route', 4096).splitlines()[1:],
             'ipv6RouteSha256': hashlib.sha256(read('/proc/net/ipv6_route', 4096).encode()).hexdigest(),
             'coreConnectionAttempted': False, 'cargoInvoked': False, 'socketsOpened': False}
    control = pathlib.Path(expected['readOnlyControl'])
    if control.parent.parent != private.parent or private in control.parents:
        raise ValueError('controlled readonly path scope')
    try:
        with control.open('ab') as out:
            out.write(b'controlled-unexpected-write')
        value['readOnlyControlWriteErrno'] = None
    except OSError as error:
        value['readOnlyControlWriteErrno'] = error.errno
    validate(value, expected)
    with (private / 'child-receipt.json').open('x') as out:
        json.dump(value, out)
    # Retain unit through parent actual-property observation. No network polling.
    deadline = time.monotonic() + 8
    while not (private / 'release').exists():
        if time.monotonic() >= deadline:
            raise ValueError('parent property proof was not completed')
        time.sleep(0.02)


if __name__ == '__main__':
    main()
