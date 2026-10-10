"""Bounded read-only exact-lock cache inventory. No Cargo/network/extraction."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import time
import tomllib

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
LOCK_SHA = 'd70b0284f71409a27beb6e9f50b3e137c36463fc82aa987c225c8f4ced32a676'
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_TOTAL_ARCHIVE = 256 * 1024 * 1024
MAX_UNPACKED = 256 * 1024 * 1024
MAX_MEMBERS = 30000
MAX_TOTAL_UNPACKED = 1024 * 1024 * 1024
GIT_COMMIT = 'd3792352992a539afffbe11501d1aff9fd5b919d'
GIT_SHA = '2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668'
GIT_CALLS = 0


def bounded_children(path, maximum):
    result = []
    for child in path.iterdir():
        result.append(child)
        if len(result) > maximum:
            raise ValueError('directory enumeration bound')
    return result


def regular_file(path, maximum, single_link=True):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (single_link and info.st_nlink != 1) or info.st_size > maximum:
        raise ValueError('file type/size invalid')
    return info


def safe_directory(path):
    for ancestor in [path, *path.parents]:
        if ancestor.is_symlink():
            raise ValueError('linked directory ancestor')
    if not path.is_dir():
        raise ValueError('directory unavailable')


def git_read(arguments, cwd):
    global GIT_CALLS
    git = pathlib.Path('/usr/bin/git')
    regular_file(git, 16 * 1024 * 1024, single_link=False)
    if hashlib.sha256(git.read_bytes()).hexdigest() != GIT_SHA:
        raise ValueError('observed Git pin mismatch')
    allowed = (arguments == ['rev-parse', 'HEAD'] or arguments == ['status', '--porcelain']
               or arguments == ['cat-file', '-t', GIT_COMMIT]
               or arguments == ['ls-tree', '-r', '--full-tree', GIT_COMMIT])
    if not allowed:
        raise ValueError('non-plumbing Git command prohibited')
    # No aliases, hooks, fsmonitor, credentials, submodule update or fetch.
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}
    GIT_CALLS += 1
    result = subprocess.run([str(git), '--no-pager', '-c', 'core.fsmonitor=false',
                             '-c', 'core.hooksPath=/dev/null', *arguments], cwd=cwd,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=5, check=True)
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 8192:
        raise ValueError('Git output bound')
    return result.stdout.decode('utf-8', errors='strict').strip()


def inspect_git_cache(cargo_home):
    root = cargo_home / 'git/checkouts'
    if not root.exists():
        return {'complete': False, 'state': 'locked-git-checkout-missing'}
    safe_directory(root)
    candidates = [p for p in bounded_children(root, 64) if re.fullmatch(r'rust-electrum-client-[0-9a-f]{1,32}', p.name)]
    if len(candidates) > 4:
        raise ValueError('Git checkout root bound')
    found = []
    for candidate in candidates:
        safe_directory(candidate)
        children = bounded_children(candidate, 8)
        for child in children:
            if not re.fullmatch(r'[0-9a-f]{7,40}', child.name):
                continue
            safe_directory(child)
            safe_directory(child / '.git')
            if git_read(['rev-parse', 'HEAD'], child) != GIT_COMMIT:
                continue
            if git_read(['status', '--porcelain'], child) or git_read(['cat-file', '-t', GIT_COMMIT], child) != 'commit':
                raise ValueError('locked Git checkout dirty/type mismatch')
            tree = git_read(['ls-tree', '-r', '--full-tree', GIT_COMMIT], child)
            lines = tree.splitlines()
            if not lines or len(lines) > MAX_MEMBERS:
                raise ValueError('Git tree bound')
            names = []
            for line in lines:
                match = re.fullmatch(r'100(?:644|755) blob ([0-9a-f]{40})\t(.{1,512})', line)
                if not match:
                    raise ValueError('Git tree link/submodule/type invalid')
                name = pathlib.PurePosixPath(match[2])
                if name.is_absolute() or '..' in name.parts or '\\' in match[2] or ':' in match[2]:
                    raise ValueError('Git tree path invalid')
                names.append(match[2])
            if 'Cargo.toml' not in names:
                raise ValueError('locked Git manifest missing')
            found.append({'path': str(child), 'commit': GIT_COMMIT,
                          'treeListingSha256': hashlib.sha256(tree.encode()).hexdigest(),
                          'treeFiles': len(lines), 'clean': True})
    if len(found) != 1:
        return {'complete': False, 'state': 'locked-git-checkout-missing-or-ambiguous', 'matchingCopies': len(found)}
    # A clean local checkout/object tree is availability, not yet a vendored source closure.
    return {'complete': False, 'state': 'locked-git-tree-present-vendor-pending',
            'lockedGitTree': found[0], 'vendorMaterialized': False}


def parse_lock(raw):
    if hashlib.sha256(raw).hexdigest() != LOCK_SHA:
        raise ValueError('exact original lock required')
    value = tomllib.loads(raw.decode())
    result = []
    for package in value['package']:
        source = package.get('source')
        if source is None:
            continue
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', package['name']) or not re.fullmatch(r'[A-Za-z0-9.+_-]{1,100}', package['version']):
            raise ValueError('locked source name/version invalid')
        if source.startswith('registry+') and source != 'registry+https://github.com/rust-lang/crates.io-index':
            raise ValueError('unreviewed registry')
        if source.startswith('registry+') and not re.fullmatch('[0-9a-f]{64}', package.get('checksum', '')):
            raise ValueError('archive checksum absent')
        result.append(package)
    if len(result) > 512:
        raise ValueError('locked package bound')
    return result


def inspect_archive(path, package):
    info = regular_file(path, MAX_ARCHIVE)
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    if sha.hexdigest() != package['checksum']:
        raise ValueError('original-lock archive checksum mismatch')
    root = package['name'] + '-' + package['version']
    names = set()
    unpacked = 0
    regular_names = set()
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            parsed = pathlib.PurePosixPath(member.name)
            if len(member.name) > 512 or '\x00' in member.name or parsed.is_absolute() or '..' in parsed.parts or '\\' in member.name or ':' in member.name or not parsed.parts or parsed.parts[0] != root:
                raise ValueError('archive path escape')
            if not (member.isfile() or member.isdir()) or member.name in names:
                raise ValueError('archive link/type/duplicate invalid')
            names.add(member.name)
            if member.isdir() and member.size != 0:
                raise ValueError('directory payload invalid')
            if member.isfile():
                regular_names.add(member.name)
            unpacked += member.size
            if len(names) > MAX_MEMBERS or unpacked > MAX_UNPACKED:
                raise ValueError('archive unpacked work bound')
    required = [root + '/Cargo.toml']
    if package['name'] == 'librocksdb-sys':
        required += [root + '/build.rs', root + '/rocksdb/AUTHORS', root + '/snappy/CMakeLists.txt']
    if any(name not in regular_names for name in required):
        raise ValueError('vendor/source completeness missing; implicit fetch forbidden')
    after = regular_file(path, MAX_ARCHIVE)
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('archive changed during inspection')
    if hashlib.sha256(path.read_bytes()).hexdigest() != package['checksum']:
        raise ValueError('archive changed during inspection')
    return {'path': str(path), 'archiveBytes': info.st_size, 'archiveSha256': sha.hexdigest(),
            'members': len(names), 'declaredUnpackedBytes': unpacked,
            'requiredSourceFilesPresent': True, 'extracted': False}


def inventory(packages, cargo_home):
    cargo_home = pathlib.Path(cargo_home)
    if cargo_home != pathlib.Path('/home/github-runner/.cargo'):
        raise ValueError('exact observed account cache only; no credential/config roots')
    cache = cargo_home / 'registry/cache'
    safe_directory(cargo_home)
    registries = []
    if cache.is_dir():
        safe_directory(cache)
        registries = [p for p in bounded_children(cache, 16) if p.is_dir() and not p.is_symlink()
                      and (re.fullmatch(r'index\.crates\.io-[0-9a-f]{1,32}', p.name) or p.name == 'github.com-1ecc6299db9ec823')]
    if len(registries) > 4:
        raise ValueError('registry root bound')
    records = []
    total = 0
    unpacked_total = 0
    started = time.monotonic()
    for package in packages:
        if time.monotonic() - started > 60:
            raise ValueError('inventory observation budget exhausted')
        record = {'name': package['name'], 'version': package['version'], 'source': package['source']}
        if package['source'].startswith('git+'):
            if package['source'] != 'git+https://github.com/Blockstream/rust-electrum-client?rev=' + GIT_COMMIT + '#' + GIT_COMMIT:
                raise ValueError('unreviewed locked Git source')
            record.update(inspect_git_cache(cargo_home))
            records.append(record)
            continue
        paths = [root / (package['name'] + '-' + package['version'] + '.crate') for root in registries]
        found = [path for path in paths if path.exists() or path.is_symlink()]
        if not found:
            record.update({'state': 'archive-missing', 'complete': False})
        elif len(found) > 1:
            record.update({'state': 'ambiguous-cache-copy', 'complete': False})
        else:
            total += regular_file(found[0], MAX_ARCHIVE).st_size
            if total > MAX_TOTAL_ARCHIVE:
                raise ValueError('aggregate archive read bound')
            try:
                record.update(inspect_archive(found[0], package))
                unpacked_total += record['declaredUnpackedBytes']
                if unpacked_total > MAX_TOTAL_UNPACKED:
                    raise ValueError('aggregate declared unpacked work bound')
                record.update({'state': 'checksum-and-vendor-qualified', 'complete': True})
            except (ValueError, OSError, tarfile.TarError) as error:
                record.update({'state': 'archive-unqualified', 'complete': False, 'reason': str(error)})
        records.append(record)
    return {'schema': 'universe-electrs-exact-lock-readonly-cache-inventory-v1', 'lockSha256': LOCK_SHA,
            'packages': records, 'totalArchiveBytes': total,
            'allLockedSourcesComplete': all(record['complete'] for record in records),
            'totalDeclaredUnpackedBytes': unpacked_total,
            'gitInvoked': GIT_CALLS > 0, 'gitPlumbingCalls': GIT_CALLS,
            'cargoInvoked': False, 'networkFetched': False, 'extracted': False,
            'compiled': False, 'fullBuildAdmissionQualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspect-owned-cache', action='store_true')
    args = parser.parse_args()
    if not args.inspect_owned_cache:
        print(json.dumps({'preparedOnly': True, 'cacheRead': False, 'cargoInvoked': False}))
        return
    if os.environ.get('GITHUB_REPOSITORY') != 'bitcoinuniverseio/electrs' or os.getuid() != 1001:
        raise ValueError('owned Linux account/repository only')
    expected = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', expected) or git_read(['rev-parse', 'HEAD'], SOURCE) != expected or git_read(['status', '--porcelain'], SOURCE):
        raise ValueError('exact clean dispatched source required')
    packages = parse_lock((SOURCE / 'Cargo.lock').read_bytes())
    print(json.dumps(inventory(packages, pathlib.Path('/home/github-runner/.cargo'))), flush=True)


if __name__ == '__main__': main()
