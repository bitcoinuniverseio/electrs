"""Owned-runner storage capability metadata only; never mount/quota/install/build."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
SAFE_OPTIONS = {'rw', 'ro', 'nosuid', 'nodev', 'noexec', 'relatime', 'noatime', 'strictatime',
                'usrquota', 'grpquota', 'prjquota', 'pquota', 'quota', 'noquota'}
TOOLS = ['/usr/bin/fusermount3', '/usr/bin/fusermount', '/usr/bin/mount', '/usr/bin/umount',
         '/usr/sbin/losetup', '/usr/sbin/mke2fs', '/usr/sbin/setquota', '/usr/sbin/xfs_quota',
         '/usr/bin/btrfs', '/usr/bin/sudo']
FUSE2FS_TOOLS = ['/usr/bin/fuse2fs', '/usr/sbin/fuse2fs']
FUSE_REFERENCES = ['/usr/include/fuse3/fuse.h', '/usr/include/fuse/fuse.h', '/usr/include/fuse.h',
                   '/usr/lib/x86_64-linux-gnu/libfuse.so.2', '/usr/lib/x86_64-linux-gnu/libfuse3.so.3']


def wrapper():
    spec = importlib.util.spec_from_file_location('owned_readonly_guard', HERE / 'locked-cache-readonly.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def unescape_mount(value):
    return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)


def mount_for(raw, target):
    """Return only exact mount ID, filesystem and known quota/size flags, never SOURCE."""
    candidates = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 10 or '-' not in parts: raise ValueError('mount metadata malformed')
        separator = parts.index('-')
        if separator < 6 or len(parts) < separator + 4 or not parts[0].isdigit(): raise ValueError('mount metadata shape')
        point = pathlib.PurePosixPath(unescape_mount(parts[4]))
        if not point.is_absolute() or '..' in point.parts: raise ValueError('mountpoint invalid')
        path = pathlib.PurePosixPath(target)
        if point != path and point not in path.parents: continue
        filesystem = parts[separator + 1]
        if not re.fullmatch('[A-Za-z0-9_.+-]{1,40}', filesystem): raise ValueError('filesystem label bound')
        options = set(parts[5].split(',') + parts[separator + 3].split(','))
        filtered = sorted(option for option in options if option in SAFE_OPTIONS or re.fullmatch(r'(?:size|nr_blocks|nr_inodes)=[0-9]{1,20}[kKmMgG]?', option))
        candidates.append((len(point.parts), {'mountId': int(parts[0]), 'mountPoint': str(point), 'filesystem': filesystem,
                                           'allowlistedOptions': filtered, 'rawSourceAndOtherOptionsOmitted': True}))
    if not candidates: raise ValueError('exact temporary mount not found')
    candidates.sort(key=lambda item: item[0], reverse=True)
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]: raise ValueError('ambiguous covering mount')
    return candidates[0][1]


def capability_flags(raw):
    matches = re.findall(r'^CapEff:\s+([0-9a-fA-F]{1,16})$', raw, flags=re.M)
    if len(matches) != 1: raise ValueError('effective capability metadata missing')
    value = int(matches[0], 16)
    return {'CAP_SYS_ADMIN': bool(value & (1 << 21)), 'CAP_SYS_RESOURCE': bool(value & (1 << 24)),
            'CAP_DAC_OVERRIDE': bool(value & (1 << 1)), 'fullMaskOmitted': True}


def tool_metadata(name):
    path = pathlib.Path(name)
    if not path.exists(): return {'requestedPath': name, 'present': False}
    resolved = path.resolve(strict=True)
    if not str(resolved).startswith(('/usr/bin/', '/usr/sbin/')) or not resolved.is_file() or resolved.stat().st_size > 32 * 1024**2:
        raise ValueError('existing storage tool path/type/size unqualified')
    info = resolved.stat()
    return {'requestedPath': name, 'path': str(resolved), 'present': True, 'bytes': info.st_size,
            'sha256': hashlib.sha256(resolved.read_bytes()).hexdigest(), 'setuid': bool(info.st_mode & stat.S_ISUID),
            'executableByRunner': os.access(resolved, os.X_OK)}


def sudo_summary(stdout, returncode):
    if len(stdout) > 32768: raise ValueError('sudo policy output bound')
    if returncode != 0:
        return {'nonInteractiveListingSucceeded': False, 'credentialsRequested': False, 'policyCommandsExecuted': False,
                'rawPolicyWithheld': True, 'privilegedStorageAdmissionQualified': False}
    text = stdout.decode('utf8', errors='strict')
    all_lines = [line for line in text.splitlines() if re.search(r'\((?:ALL\s*(?::\s*ALL)?|root\s*(?::\s*root)?)\)\s+(?:NOPASSWD:\s*)?ALL\s*$', line)]
    mentions = set()
    for command in ['mount', 'umount', 'losetup', 'mke2fs', 'setquota', 'xfs_quota', 'btrfs']:
        if re.search(r'/usr/(?:s)?bin/' + command + r'(?:[\s,]|$)', text): mentions.add(command)
    return {'nonInteractiveListingSucceeded': True, 'unrestrictedAllRuleMentioned': bool(all_lines),
            'unrestrictedNopasswdRuleMentioned': any('NOPASSWD:' in line for line in all_lines),
            'literalStorageCommandMentions': sorted(mentions), 'argumentRestrictionsNotQualified': True,
            'negativeMentionsDoNotProveDeniedPolicy': True,
            'credentialsRequested': False, 'policyCommandsExecuted': False, 'rawPolicyWithheld': True,
            'privilegedStorageAdmissionQualified': False}


def sudo_metadata(tools):
    sudo = next(tool for tool in tools if tool['requestedPath'] == '/usr/bin/sudo')
    if not sudo['present'] or not sudo['executableByRunner']:
        return {'present': sudo['present'], 'listingAttempted': False, 'privilegedStorageAdmissionQualified': False}
    # -n fails instead of prompting; -l lists policy and executes NO policy command.
    argv = [sudo['path'], '-n', '-l']
    env = {'PATH': '/usr/bin:/usr/sbin:/bin', 'LANG': 'C', 'HOME': '/nonexistent'}
    try:
        result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=3, check=False)
        if len(result.stderr) > 8192: raise ValueError('sudo diagnostic size bound')
        if tool_metadata('/usr/bin/sudo')['sha256'] != sudo['sha256']: raise ValueError('sudo tool changed during metadata read')
        return {'present': True, 'listingAttempted': True, 'exitCode': result.returncode,
                **sudo_summary(result.stdout, result.returncode)}
    except subprocess.TimeoutExpired:
        return {'present': True, 'listingAttempted': True, 'timedOut': True,
                'rawPolicyWithheld': True, 'privilegedStorageAdmissionQualified': False}


def fuse_metadata():
    path = pathlib.Path('/dev/fuse')
    if not path.exists(): return {'path': str(path), 'present': False, 'opened': False, 'mountQualified': False}
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISCHR(info.st_mode): raise ValueError('FUSE device type mismatch')
    return {'path': str(path), 'present': True, 'characterDevice': True, 'major': os.major(info.st_rdev),
            'minor': os.minor(info.st_rdev), 'readWriteAccessible': os.access(path, os.R_OK | os.W_OK),
            'opened': False, 'mountQualified': False}


def fuse_reference_metadata(name):
    if name not in FUSE_REFERENCES: raise ValueError('exact reviewed FUSE reference only')
    path = pathlib.Path(name)
    if not path.exists(): return {'requestedPath': name, 'present': False}
    resolved = path.resolve(strict=True)
    if not str(resolved).startswith(('/usr/include/', '/usr/lib/x86_64-linux-gnu/')) or not resolved.is_file() or resolved.stat().st_size > 32 * 1024**2:
        raise ValueError('known FUSE header/library type/path/size required')
    return {'requestedPath': name, 'path': str(resolved), 'present': True, 'bytes': resolved.stat().st_size,
            'sha256': hashlib.sha256(resolved.read_bytes()).hexdigest(), 'readOnlyObserved': True}


def collect():
    guard = wrapper(); expected = guard.runtime_guard()
    inventory = guard.load_source('owned_storage_source_guard', HERE / 'locked-source-inventory.py')
    guard.source_guard(inventory, expected)
    temp = pathlib.Path(os.environ.get('RUNNER_TEMP', ''))
    # This validates exact existing temp ownership/path and gathers bounded local metrics only.
    resources = guard.headroom_report(temp)
    mount = mount_for(guard.bounded_read('/proc/self/mountinfo', 256 * 1024), temp.as_posix())
    caps = capability_flags(guard.bounded_read('/proc/self/status', 32768))
    tools = [tool_metadata(name) for name in TOOLS]
    result = {'schema': 'universe-electrs-storage-enforcement-metadata-v1', 'sourceSha': expected,
              'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'temporaryMount': mount,
              'freeTemporaryBytes': resources['freeTempBytes'], 'effectiveSelfCapabilities': caps,
              'availableMemoryKiB': resources['memoryKiB']['MemAvailable'],
              'fuse': fuse_metadata(), 'tools': tools, 'sudoPolicySummary': sudo_metadata(tools),
              'existingFuse2fs': [tool_metadata(name) for name in FUSE2FS_TOOLS],
              'knownFuseHeadersAndLibraries': [fuse_reference_metadata(name) for name in FUSE_REFERENCES],
              'fixedSizeExt4FuseCandidate': {'toolExecutionObserved': False, 'mountSupported': False,
                                            'smallImageProofExecuted': False, 'aggregateCeilingEnforced': False},
              'aggregate8GiBEnforcementQualified': False, 'capabilityProofExecuted': False,
              'storageCreated': False, 'deviceOpened': False, 'mounted': False, 'quotaChanged': False,
              'unitsCreated': False, 'cargoInvoked': False, 'installed': False, 'nativeActions': False,
              'nextGate': 'Review observed facilities then one isolated owned storage enforcement proof; metadata alone never admits full build'}
    guard.source_guard(inventory, expected)
    raw = json.dumps(result, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 32768: raise ValueError('storage metadata output bound')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observe-owned-storage', action='store_true')
    args = parser.parse_args()
    if not args.observe_owned_storage:
        print(json.dumps({'preparedOnly': True, 'metadataRead': False, 'mounted': False})); return
    import sys
    sys.stdout.buffer.write(collect() + b'\n')


if __name__ == '__main__': main()
