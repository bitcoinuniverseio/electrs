"""UNEXECUTED exact-lock dependency acquisition; explicit new owned destination only."""
import argparse
import concurrent.futures
import datetime
import gzip
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import tomllib
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
INVENTORY_SHA = 'fef851f7a12c67f3d0807f669c03d853f9d2c91aa459a61edc0e2ef40f0a5c27'
COMMIT = 'd3792352992a539afffbe11501d1aff9fd5b919d'
GITHUB = 'https://api.github.com/repos/Blockstream/rust-electrum-client/git/'
MAX_ARCHIVE = 32 * 1024**2
MAX_TOTAL = 256 * 1024**2
MAX_GIT_FILES = 2048
MAX_GIT_BYTES = 128 * 1024**2
MAX_REQUESTS = 198  #195 registry archives +commit JSON +tree JSON +Git archive.
SECONDS = 600
WATCHDOG_SECONDS = 660
WINDOWS_GIT = {'path': 'C:/Program Files/Git/cmd/git.exe', 'sha256': '78211c7ed73988da93a6d8a33d47ec6187f464d7ea2a9a00c182bbd7a1ecf30f'}


def load_inventory():
    spec = importlib.util.spec_from_file_location('locked_source_inventory', HERE / 'locked-source-inventory.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build_plan(lock_raw, inventory_raw):
    if sha(inventory_raw) != INVENTORY_SHA:
        raise ValueError('exact actual087c inventory required')
    package_list = load_inventory().parse_lock(lock_raw)
    captured = json.loads(inventory_raw)
    report = captured['report']
    if captured['runId'] != 38024510195 or captured['jobId'] != 114132367991 or captured['ciConclusion'] != 'success' or report['lockSha256'] != load_inventory().LOCK_SHA:
        raise ValueError('actual inventory lineage mismatch')
    current = {(p['name'], p['version'], p['source']): p for p in package_list}
    observed = report['packages']
    if len(current) != 204 or len(observed) != 204 or len({(p['name'], p['version'], p['source']) for p in observed}) != 204:
        raise ValueError('all204 exact locked identities required')
    archives, cached = [], []
    git_count = 0
    git_package = None
    for record in observed:
        key = (record['name'], record['version'], record['source'])
        if key not in current:
            raise ValueError('inventory source substitution')
        package = current[key]
        if package['source'].startswith('git+'):
            if not package['source'].endswith('?rev=' + COMMIT + '#' + COMMIT) or record['state'] != 'locked-git-checkout-missing':
                raise ValueError('exact missingGit d379 required')
            git_count += 1
            git_package = {'name': package['name'], 'version': package['version']}
        elif record['state'] == 'archive-missing' and record['complete'] is False:
            archives.append({'name': package['name'], 'version': package['version'], 'checksum': package['checksum'],
                             'url': 'https://static.crates.io/crates/' + package['name'] + '/' + package['name'] + '-' + package['version'] + '.crate'})
        elif record['state'] == 'checksum-and-vendor-qualified' and record['complete'] is True:
            cached.append({'name': package['name'], 'version': package['version'], 'checksum': package['checksum'],
                           'historicalCacheReference': record['path'], 'copied': False})
        else:
            raise ValueError('unreviewed inventory source state')
    if len(archives) != 195 or len(cached) != 8 or git_count != 1:
        raise ValueError('exact195 missing/8 historical/1Git required')
    return {'schema': 'universe-electrs-locked-acquisition-plan-v1', 'inventorySha256': INVENTORY_SHA,
            'lockSha256': load_inventory().LOCK_SHA, 'registryDownloads': archives,
            'historicalQualifiedCacheReferences': cached, 'gitCommit': COMMIT, 'gitPackage': git_package,
            'limits': {'concurrency': 2, 'seconds': SECONDS, 'requests': MAX_REQUESTS,
                       'archiveBytes': MAX_ARCHIVE, 'totalNetworkBytes': MAX_TOTAL},
            'all204Materialized': False, 'cargoInvoked': False, 'buildAdmissionQualified': False}


def url_allowed(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in [None, 443] or parsed.fragment:
        return False
    if parsed.hostname == 'static.crates.io':
        return not parsed.query and re.fullmatch(r'/crates/([A-Za-z0-9_-]{1,100})/\1-[A-Za-z0-9.+_-]{1,100}\.crate', parsed.path) is not None
    if parsed.hostname == 'codeload.github.com':
        return not parsed.query and parsed.path == '/Blockstream/rust-electrum-client/tar.gz/' + COMMIT
    if parsed.hostname == 'api.github.com':
        return (not parsed.query and parsed.path == '/repos/Blockstream/rust-electrum-client/git/commits/' + COMMIT
                or parsed.query == 'recursive=1' and re.fullmatch('/repos/Blockstream/rust-electrum-client/git/trees/[0-9a-f]{40}', parsed.path) is not None)
    return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('dependency redirects forbidden; no domain/auth fallback')


class Budget:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.start = time.monotonic()
        self.total = 0
        self.requests = 0
        self.unpacked = 0

    def check(self):
        if self.stop.is_set() or time.monotonic() - self.start > SECONDS:
            raise ValueError('acquisition stopped/deadline exhausted')

    def request(self):
        self.check()
        with self.lock:
            self.requests += 1
            if self.requests > MAX_REQUESTS:
                raise ValueError('fixed request count exceeded')

    def charge(self, size):
        self.check()
        with self.lock:
            self.total += size
            if self.total > MAX_TOTAL:
                raise ValueError('aggregate network byte budget exceeded')

    def charge_unpacked(self, size):
        with self.lock:
            self.unpacked += size
            if self.unpacked > 1024 * 1024**2:
                raise ValueError('aggregate archive declared payload budget exceeded')


def download(url, path, budget, maximum, expected=None):
    if not url_allowed(url):
        raise ValueError('unreviewed dependency endpoint')
    if path.exists() or path.is_symlink() or path.with_name(path.name + '.part').exists():
        raise ValueError('immutable target conflict')
    budget.request()
    # No inherited proxy, authentication, cookies, netrc, credential helper or retries.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={'User-Agent': 'UniverseExactLockAcquisition/1', 'Accept': 'application/vnd.github+json'})
    part = path.with_name(path.name + '.part')
    digest = hashlib.sha256()
    total = 0
    with part.open('xb') as output:
        with opener.open(request, timeout=10) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError('exact dependency response required')
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdecimal() or int(length) > maximum):
                raise ValueError('dependency content length bound')
            while True:
                budget.check()
                raw = response.read1(65536)
                if not raw:
                    break
                total += len(raw)
                budget.charge(len(raw))
                if total > maximum:
                    raise ValueError('per-response byte bound')
                digest.update(raw)
                output.write(raw)
    checksum = digest.hexdigest()
    if expected is not None and checksum != expected:
        raise ValueError('original Cargo.lock checksum mismatch; partial retained unparsed')
    if path.exists() or path.is_symlink():
        raise ValueError('immutable target conflict')
    # Atomic no-replace publication even if another actor races the existence check.
    os.link(part, path)
    part.unlink()
    return {'file': path.name, 'url': url, 'bytes': total, 'sha256': checksum}


def gzip_payload_fence(path, budget, maximum):
    # Registry bytes must have passed the original lock checksum first. Before
    # any tar/PAX parser allocation, independently bound the actual decoded stream.
    count = 0
    with gzip.open(path, 'rb') as source:
        while True:
            budget.check()
            raw = source.read(65536)
            if not raw: break
            count += len(raw)
            if count > maximum: raise ValueError('decoded archive stream bound')
    budget.charge_unpacked(count)
    return count


def safe_destination(value):
    path = pathlib.Path(value)
    if not path.is_absolute() or '..' in path.parts or path.exists() or path.is_symlink():
        raise ValueError('absent absolute owned destination required')
    parent = path.parent
    linux = re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp', parent.as_posix())
    windows = parent.as_posix().lower() == 'c:/universe/mempool/audits/implementation-20261009-api'
    if not (linux or windows) or not re.fullmatch(r'electrs-locked-acquisition-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}', path.name):
        raise ValueError('new task namespace outside audited roots')
    for ancestor in [parent, *parent.parents]:
        if ancestor.is_symlink() or (hasattr(ancestor, 'is_junction') and ancestor.is_junction()):
            raise ValueError('linked target ancestor')
    if not parent.is_dir() or parent.resolve(strict=True) != parent:
        raise ValueError('resolved audited parent required')
    if os.name == 'posix' and parent.stat().st_uid != 1001:
        raise ValueError('owned runner parent required')
    return path


def git_object(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def validate_git_archive(path, commit, tree, package=None):
    if commit.get('sha') != COMMIT or not re.fullmatch('[0-9a-f]{40}', commit.get('tree', {}).get('sha', '')):
        raise ValueError('primary publicGitHub commit/tree binding mismatch')
    root_sha = commit['tree']['sha']
    if tree.get('sha') != root_sha or tree.get('truncated') is not False or len(tree.get('tree', [])) > MAX_GIT_FILES:
        raise ValueError('complete bounded primary Git tree required')
    expected = {}
    for record in tree['tree']:
        name = record['path']
        parsed = pathlib.PurePosixPath(name)
        if len(name) > 512 or not name or parsed.is_absolute() or '..' in parsed.parts or '\\' in name or ':' in name or name in expected or len(parsed.parts) > 16:
            raise ValueError('Git tree path invalid')
        if not re.fullmatch('[0-9a-f]{40}', record.get('sha', '')) or (record['mode'], record['type']) not in [('100644', 'blob'), ('100755', 'blob'), ('040000', 'tree')]:
            raise ValueError('Git links/submodules/types unqualified')
        expected[name] = record
    blobs = {}
    manifest = None
    used = 0
    prefix = 'rust-electrum-client-' + COMMIT
    with tarfile.open(path, 'r|gz') as archive:
        entries = 0
        members_seen = set()
        for member in archive:
            entries += 1
            if entries > MAX_GIT_FILES + 1 or len(member.name) > 600:
                raise ValueError('Git archive member bound')
            parsed = pathlib.PurePosixPath(member.name)
            if not parsed.parts or parsed.parts[0] != prefix or '..' in parsed.parts or '\\' in member.name or ':' in member.name or member.name in members_seen:
                raise ValueError('Git archive path escape')
            members_seen.add(member.name)
            if member.isdir():
                if member.size != 0: raise ValueError('Git directory payload')
                name = '/'.join(parsed.parts[1:])
                if name and (name not in expected or expected[name]['type'] != 'tree'): raise ValueError('unexpected Git directory')
                continue
            name = '/'.join(parsed.parts[1:])
            if not member.isfile() or name not in expected or expected[name]['type'] != 'blob' or name in blobs:
                raise ValueError('Git archive unexpected blob/link/duplicate')
            used += member.size
            if member.size > 8 * 1024**2 or used > MAX_GIT_BYTES:
                raise ValueError('Git file/aggregate payload bound')
            raw = archive.extractfile(member).read(member.size + 1)
            mode = '100755' if member.mode & 0o111 else '100644'
            if len(raw) != member.size or git_object('blob', raw) != expected[name]['sha'] or mode != expected[name]['mode']:
                raise ValueError('Git blob/mode mismatch')
            blobs[name] = {'gitBlob': expected[name]['sha'], 'sha256': sha(raw), 'bytes': len(raw)}
            if name == 'Cargo.toml': manifest = raw
    if set(blobs) != {name for name, entry in expected.items() if entry['type'] == 'blob'} or 'Cargo.toml' not in blobs:
        raise ValueError('Git archive complete blob set required')
    if package is not None:
        declared = tomllib.loads(manifest.decode())['package']
        if declared.get('name') != package['name'] or declared.get('version') != package['version']:
            raise ValueError('Git manifest does not match exact locked package')
    # Recompute every tree from verified blobs, including all directory boundaries.
    verified = {name: value['gitBlob'] for name, value in blobs.items()}
    directories = sorted([name for name, entry in expected.items() if entry['type'] == 'tree'] + [''], key=lambda name: name.count('/') + bool(name), reverse=True)
    for directory in directories:
        children = [(name.rsplit('/', 1)[-1], entry) for name, entry in expected.items() if str(pathlib.PurePosixPath(name).parent) == (directory or '.')]
        children.sort(key=lambda value: (value[0] + ('/' if value[1]['type'] == 'tree' else '')).encode())
        payload = b''
        for name, entry in children:
            child = directory + '/' + name if directory else name
            if child not in verified: raise ValueError('Git tree incomplete ancestry')
            payload += ('40000' if entry['type'] == 'tree' else entry['mode']).encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(verified[child])
        result = git_object('tree', payload)
        if result != (root_sha if not directory else expected[directory]['sha']):
            raise ValueError('reconstructed Git tree mismatch')
        verified[directory] = result
    return {'commit': COMMIT, 'tree': root_sha, 'blobs': blobs, 'gitBlobAndTreeHashesVerified': True,
            'commitToTreeTrust': 'Exact pinned commit bound to tree by HTTPS publicGitHub Git API; raw commit object not reconstructed',
            'materialized': False}


def acquire(plan, root):
    # Called only by the parent-owned child after its marker/source proof.
    root = pathlib.Path(root)
    archives = root / 'archives'; archives.mkdir(mode=0o700)
    git = root / 'git-source'; git.mkdir(mode=0o700)
    budget = Budget()
    results = []
    errors = []
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    def one(package):
        budget.check()
        target = archives / (package['name'] + '-' + package['version'] + '.crate')
        value = download(package['url'], target, budget, MAX_ARCHIVE, package['checksum'])
        # Checksum already matched BEFORE the parser sees downloaded bytes.
        value['decodedStreamBytes'] = gzip_payload_fence(target, budget, 256 * 1024**2)
        value['archiveQualification'] = load_inventory().inspect_archive(target, package)
        with (archives / (target.name + '.qualified.json')).open('x', encoding='utf8') as output: json.dump(value, output, sort_keys=True)
        return value
    try:
        iterator = iter(plan['registryDownloads'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            active = {pool.submit(one, next(iterator)) for _ in range(2)}
            while active:
                completed, active = concurrent.futures.wait(active, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in completed:
                    try: results.append(future.result())
                    except Exception as error:
                        errors.append({'type': type(error).__name__, 'reason': str(error)[:512]}); budget.stop.set()
                if budget.stop.is_set():
                    for future in active: future.cancel()
                    continue
                for _ in completed:
                    package = next(iterator, None)
                    if package is not None: active.add(pool.submit(one, package))
        if errors: raise ValueError('registry acquisition failed; no Git request or automatic retry')
        commit_path = git / 'commit.json'
        git_downloads = [download(GITHUB + 'commits/' + COMMIT, commit_path, budget, 65536)]
        commit = json.loads(commit_path.read_bytes())
        tree_sha = commit.get('tree', {}).get('sha', '')
        if commit.get('sha') != COMMIT or not re.fullmatch('[0-9a-f]{40}', tree_sha): raise ValueError('pinned Git commit metadata mismatch')
        tree_path = git / 'tree.json'
        git_downloads.append(download(GITHUB + 'trees/' + tree_sha + '?recursive=1', tree_path, budget, 512 * 1024))
        git_path = git / ('rust-electrum-client-' + COMMIT + '.tar.gz')
        git_downloads.append(download('https://codeload.github.com/Blockstream/rust-electrum-client/tar.gz/' + COMMIT, git_path, budget, MAX_ARCHIVE))
        gzip_payload_fence(git_path, budget, MAX_GIT_BYTES)
        git_proof = validate_git_archive(git_path, commit, json.loads(tree_path.read_bytes()), plan['gitPackage'])
        git_proof['downloadedObjects'] = git_downloads
        with (git / 'tree-qualified.json').open('x', encoding='utf8') as output: json.dump(git_proof, output, sort_keys=True)
    except Exception as error:
        budget.stop.set()
        errors.append({'type': type(error).__name__, 'reason': str(error)[:512]})
    receipt = {'schema': 'universe-electrs-owned-acquisition-v1', 'startedAt': started,
               'completedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'plan': plan,
               'destination': str(root), 'qualifiedRegistryArchives': results, 'errors': errors,
               'networkBytes': budget.total, 'requests': budget.requests, 'automaticRetries': 0,
               'decodedArchiveStreamBytes': budget.unpacked,
               'partialFilesPreserved': True, 'sharedCacheMutated': False, 'cargoInvoked': False,
               'installed': False, 'built': False, 'nativeActions': False, 'all204Materialized': False,
               'status': 'FAILED_PARTIAL_PRESERVED' if errors else 'ACQUIRED195_AND_GIT_TREE_EIGHT_HISTORICAL_CACHE_COPIES_AND_VENDOR_PENDING'}
    with (root / 'acquisition-receipt.json').open('x', encoding='utf8') as output: json.dump(receipt, output, indent=2)
    return {'destination': str(root), 'status': receipt['status'], 'qualifiedRegistryCount': len(results), 'errors': errors}


def local_git(arguments):
    if os.name == 'posix':
        if arguments[:1] == ['show']:
            # Only the immutable exact current lock blob is requested here.
            git = pathlib.Path('/usr/bin/git')
            expected = load_inventory().GIT_SHA
        else:
            return load_inventory().git_read(arguments, SOURCE).encode()
    else:
        git = pathlib.Path(WINDOWS_GIT['path']); expected = WINDOWS_GIT['sha256']
    if arguments not in [['rev-parse', 'HEAD'], ['status', '--porcelain'], ['show', 'HEAD:Cargo.lock']]:
        raise ValueError('read-only source Git command required')
    if not git.is_file() or git.is_symlink() or sha(git.read_bytes()) != expected:
        raise ValueError('existing direct source Git pin mismatch')
    environment = {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0', 'HOME': str(SOURCE / 'nonexistent-home')}
    if os.name == 'nt': environment['SystemRoot'] = os.environ['SystemRoot']
    result = subprocess.run([str(git), '--no-pager', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + os.devnull, *arguments], cwd=SOURCE, env=environment, capture_output=True, check=True, timeout=5)
    if len(result.stdout) > 128 * 1024 or len(result.stderr) > 8192: raise ValueError('source Git output bound')
    return result.stdout


def worker(root, token):
    root = pathlib.Path(root)
    if root.is_symlink() or (hasattr(root, 'is_junction') and root.is_junction()) or not root.is_dir(): raise ValueError('owned child root invalid')
    for filename in ['OWNER.json', 'plan.json']:
        path = root / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024: raise ValueError('owned child metadata type/size')
    owner = json.loads((root / 'OWNER.json').read_bytes())
    if not re.fullmatch('[0-9a-f]{32}', token) or owner['token'] != token or owner['parentPid'] != os.getppid() or owner['scriptSha256'] != sha(pathlib.Path(__file__).read_bytes()):
        raise ValueError('exact parent/source child ownership required')
    if any(os.environ.get(key) for key in ['SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR']): raise ValueError('unexpected TLS trust/logging environment')
    plan = json.loads((root / 'plan.json').read_bytes())
    if sha((root / 'plan.json').read_bytes()) != owner['planSha256']: raise ValueError('immutable child plan mismatch')
    for name in ['acquire-locked-sources.py', 'locked-source-inventory.py']:
        if plan['sourceModulesSha256'].get(name) != sha((HERE / name).read_bytes()): raise ValueError('owned child source module drift')
    result = acquire(plan, root)
    print(json.dumps(result))
    return 1 if result['errors'] else 0


def launch_owned(plan, destination):
    root = safe_destination(destination)
    if any(os.environ.get(key) for key in ['SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR']): raise ValueError('TLS trust/logging override forbidden before admission')
    if shutil.disk_usage(root.parent).free < 1024 * 1024**2:
        raise ValueError('1GiB private acquisition storage headroom required')
    root.mkdir(mode=0o700)
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    with (root / 'plan.json').open('xb') as output: output.write(plan_raw)
    token = os.urandom(16).hex()
    owner = {'parentPid': os.getpid(), 'token': token, 'scriptSha256': sha(pathlib.Path(__file__).read_bytes()), 'planSha256': sha(plan_raw)}
    with (root / 'OWNER.json').open('x', encoding='utf8') as output: json.dump(owner, output)
    environment = {'LANG': 'C'}
    if os.name == 'nt': environment['SystemRoot'] = os.environ['SystemRoot']
    command = [sys.executable, '-B', '-I', '-S', str(pathlib.Path(__file__).resolve()), '--worker-root', str(root), '--worker-token', token]
    child = subprocess.Popen(command, env=environment, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = child.communicate(timeout=WATCHDOG_SECONDS)
        if len(stdout) > 256 * 1024 or len(stderr) > 32768: raise ValueError('owned child output bound')
        with (root / 'child.stdout').open('xb') as output: output.write(stdout)
        with (root / 'child.stderr').open('xb') as output: output.write(stderr)
        return {'destination': str(root), 'childPid': child.pid, 'exitCode': child.returncode, 'watchdogExpired': False}
    except subprocess.TimeoutExpired:
        # The stored Popen child is the only target; it creates no subprocesses.
        child.kill()
        stdout, stderr = child.communicate(timeout=10)
        with (root / 'child.stdout').open('xb') as output: output.write(stdout[:256 * 1024])
        with (root / 'child.stderr').open('xb') as output: output.write(stderr[:32768])
        with (root / 'watchdog-failure.json').open('x', encoding='utf8') as output:
            json.dump({'childPid': child.pid, 'timeoutSeconds': WATCHDOG_SECONDS, 'partialFilesPreserved': True,
                       'stdoutTruncated': len(stdout) > 256 * 1024, 'stderrTruncated': len(stderr) > 32768,
                       'automaticRetries': 0, 'nativeActions': False}, output)
        return {'destination': str(root), 'childPid': child.pid, 'exitCode': 1, 'watchdogExpired': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acquire', action='store_true')
    parser.add_argument('--destination', type=pathlib.Path)
    parser.add_argument('--inventory', type=pathlib.Path)
    parser.add_argument('--source-sha')
    parser.add_argument('--worker-root', type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument('--worker-token', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_root is not None:
        if args.acquire or args.worker_token is None: raise ValueError('internal owned child arguments')
        raise SystemExit(worker(args.worker_root, args.worker_token))
    if not args.acquire:
        print(json.dumps({'preparedOnly': True, 'networkFetched': False, 'destinationCreated': False, 'cargoInvoked': False}))
        return
    if args.destination is None or args.inventory is None: raise ValueError('reviewed inventory and absent destination required')
    if args.inventory.is_symlink() or not args.inventory.is_file() or args.inventory.stat().st_size > 256 * 1024: raise ValueError('bounded original inventory required')
    expected = args.source_sha or os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', expected) or local_git(['rev-parse', 'HEAD']).decode().strip() != expected or local_git(['status', '--porcelain']).strip(): raise ValueError('exact clean source required')
    if os.environ.get('GITHUB_SHA') and (os.environ.get('GITHUB_REPOSITORY') != 'bitcoinuniverseio/electrs' or os.getuid() != 1001): raise ValueError('owned CI source guard')
    plan = build_plan(local_git(['show', 'HEAD:Cargo.lock']), args.inventory.read_bytes())
    plan['sourceSha'] = expected
    plan['sourceModulesSha256'] = {name: sha((HERE / name).read_bytes()) for name in ['acquire-locked-sources.py', 'locked-source-inventory.py']}
    result = launch_owned(plan, args.destination)
    print(json.dumps(result))
    if result['exitCode']: raise SystemExit(1)


if __name__ == '__main__': main()
