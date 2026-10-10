"""UNEXECUTED bounded exact-source vendor materialization. No Cargo/build/network."""
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
import sys
import tarfile
import time

HERE = pathlib.Path(__file__).resolve().parent
FIRST_SHA = '33fe1c8776a4f7d255e2088bfcfadd9c91a2e61c3f88eddea931b374b8de77ff'
EIGHT_SHA = 'd5cfa46f578b8358e330c857796f924f5fe367eef301a40f6eecc83074495642'
GIT_PROOF_SHA = 'b80fc213b0fb1960e7f0b43adc69252995161405aa81423928333415b3263839'
MAX_TOTAL_FILES = 200000
MAX_TOTAL_BYTES = 1024 * 1024**2
MAX_FILE_BYTES = 32 * 1024**2
MAX_SECONDS = 300


def kit():
    spec = importlib.util.spec_from_file_location('qualified_acquisition', HERE / 'acquire-locked-sources.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def raw_json(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024**2:
        raise ValueError('bounded original receipt required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected: raise ValueError('exact original receipt checksum required')
    return json.loads(raw)


def regular_input(path, maximum):
    for parent in [path, *path.parents]:
        if parent.is_symlink() or (hasattr(parent, 'is_junction') and parent.is_junction()): raise ValueError('linked input path')
    if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > maximum: raise ValueError('regular immutable bounded input required')


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''): digest.update(block)
    return digest.hexdigest()


def make_plan(first_path, eight_path, lock_raw):
    acquisition = kit()
    first = raw_json(first_path, FIRST_SHA); eight = raw_json(eight_path, EIGHT_SHA)
    if first['errors'] or eight['errors'] or len(first['qualifiedRegistryArchives']) != 195 or len(eight['qualifiedArchives']) != 8:
        raise ValueError('both exact successful195+8 acquisitions required')
    packages = acquisition.load_inventory().parse_lock(lock_raw)
    if len(packages) != 204: raise ValueError('all204 lock identities required')
    qualified = {}
    for receipt, root, field in [(first, first_path.parent, 'qualifiedRegistryArchives'), (eight, eight_path.parent, 'qualifiedArchives')]:
        for record in receipt[field]:
            filename = record['file']
            if not re.fullmatch(r'[A-Za-z0-9_.+\-]{1,220}\.crate', filename) or filename in qualified:
                raise ValueError('archive filename duplicate/substitution')
            qualified[filename] = {'path': str(root / 'archives' / filename), 'sha256': record['sha256']}
    selected = []
    for package in packages:
        if not package['source'].startswith('registry+'): continue
        filename = package['name'] + '-' + package['version'] + '.crate'
        if filename not in qualified or qualified[filename]['sha256'] != package['checksum']: raise ValueError('exact lock archive coverage/checksum mismatch')
        selected.append({'package': package, **qualified[filename]})
    if len(selected) != 203 or len(qualified) != 203: raise ValueError('all203 exact registry sources required')
    git_packages = [p for p in packages if p['source'].startswith('git+')]
    if len(git_packages) != 1 or not git_packages[0]['source'].endswith('#' + acquisition.COMMIT): raise ValueError('exact d379 Git required')
    git_root = first_path.parent / 'git-source'
    git_receipt = raw_json(git_root / 'tree-qualified.json', GIT_PROOF_SHA)
    downloads = {r['file']: r for r in git_receipt['downloadedObjects']}
    git_inputs = {}
    for filename in ['commit.json', 'tree.json', 'rust-electrum-client-' + acquisition.COMMIT + '.tar.gz']:
        if filename not in downloads: raise ValueError('Git proof object missing')
        git_inputs[filename] = {'path': str(git_root / filename), 'sha256': downloads[filename]['sha256']}
    return {'schema': 'universe-electrs-locked-vendor-plan-v1', 'lockSha256': acquisition.load_inventory().LOCK_SHA,
            'firstAcquisitionSha256': FIRST_SHA, 'eightAcquisitionSha256': EIGHT_SHA,
            'registrySources': selected, 'gitPackage': git_packages[0], 'gitInputs': git_inputs,
            'historicalLinuxCacheReferences': first['plan']['historicalQualifiedCacheReferences'],
            'materialized': False, 'cargoInvoked': False, 'fullBuildQualified': False}


class WorkBudget:
    def __init__(self): self.started = time.monotonic(); self.files = 0; self.bytes = 0; self.members = 0
    def check(self):
        if time.monotonic() - self.started > MAX_SECONDS: raise ValueError('materialization observation deadline')
    def charge(self, size):
        self.check(); self.files += 1; self.bytes += size
        if self.files > MAX_TOTAL_FILES or self.bytes > MAX_TOTAL_BYTES or size > MAX_FILE_BYTES: raise ValueError('vendor file/byte work bound')
    def member(self):
        self.check(); self.members += 1
        if self.members > MAX_TOTAL_FILES: raise ValueError('aggregate vendor member bound')


def safe_relative(name):
    path = pathlib.PurePosixPath(name)
    if not name or len(name) > 512 or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name or '\x00' in name or '.git' in path.parts:
        raise ValueError('vendor path escape')
    for component in path.parts:
        if component.endswith((' ', '.')) or re.fullmatch(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', component, flags=re.I): raise ValueError('nonportable vendor component')
    return path


def extract_package(archive_path, package_root, prefix, budget):
    files = {}
    seen = set()
    with tarfile.open(archive_path, 'r|gz') as archive:
        for member in archive:
            budget.member()
            path = safe_relative(member.name)
            if path.parts[0] != prefix: raise ValueError('source archive root mismatch')
            relative = '/'.join(path.parts[1:])
            if not relative:
                if not member.isdir() or member.size != 0: raise ValueError('package root type')
                continue
            relative_path = safe_relative(relative)
            key = relative.casefold()
            if key in seen: raise ValueError('duplicate/case-alias archive entry')
            seen.add(key)
            if len(seen) > 30000: raise ValueError('package member bound')
            target = package_root.joinpath(*relative_path.parts)
            if member.isdir():
                if member.size != 0: raise ValueError('directory payload')
                target.mkdir(parents=True, exist_ok=True); continue
            if not member.isfile() or relative == '.cargo-checksum.json': raise ValueError('source link/type/checksum injection')
            budget.charge(member.size)
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(); remaining = member.size
            source = archive.extractfile(member)
            with target.open('xb') as output:
                while remaining:
                    budget.check(); block = source.read(min(65536, remaining))
                    if not block: raise ValueError('truncated source payload')
                    output.write(block); digest.update(block); remaining -= len(block)
            # Sealing before future Linux transfer is metadata, not an ACL/integrity claim.
            target.chmod(0o555 if member.mode & 0o111 else 0o444)
            files[relative] = digest.hexdigest()
    if 'Cargo.toml' not in files: raise ValueError('source manifest missing')
    return files


def cargo_config(vendor):
    # Explicit immutable Git source replacement, never dependency patching.
    return ('[net]\noffline = true\n\n[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
            '[source."git+https://github.com/Blockstream/rust-electrum-client?rev=' + kit().COMMIT + '"]\n'
            'git = "https://github.com/Blockstream/rust-electrum-client"\nrev = "' + kit().COMMIT + '"\nreplace-with = "vendored-sources"\n\n'
            '[source.vendored-sources]\ndirectory = ' + json.dumps(vendor.as_posix()) + '\n')


def vendor_destination(destination):
    path = pathlib.Path(destination)
    if not re.fullmatch(r'electrs-locked-vendor-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}', path.name) or path.exists() or path.is_symlink(): raise ValueError('new exclusive vendor destination required')
    # Reuse reviewed exact parent/ancestor/ownership checks; never create the alias.
    kit().safe_destination(path.with_name(path.name.replace('electrs-locked-vendor-', 'electrs-locked-acquisition-', 1)))
    return path


def materialize(plan, destination, prepared=False):
    acquisition = kit()
    # All archive/object digests are verified before the first extracted file.
    budget = WorkBudget(); total_archive = 0
    for source in plan['registrySources']:
        budget.check(); path = pathlib.Path(source['path']); regular_input(path, acquisition.MAX_ARCHIVE)
        total_archive += path.stat().st_size
        if total_archive > acquisition.MAX_TOTAL or digest_file(path) != source['package']['checksum']: raise ValueError('registry archive checksum/aggregate bound')
    for record in plan['gitInputs'].values():
        path = pathlib.Path(record['path']); regular_input(path, acquisition.MAX_ARCHIVE)
        if digest_file(path) != record['sha256']: raise ValueError('Git input digest mismatch')
    git = plan['gitInputs']
    commit = json.loads(pathlib.Path(git['commit.json']['path']).read_bytes())
    tree = json.loads(pathlib.Path(git['tree.json']['path']).read_bytes())
    git_archive = pathlib.Path(git['rust-electrum-client-' + acquisition.COMMIT + '.tar.gz']['path'])
    git_proof = acquisition.validate_git_archive(git_archive, commit, tree, plan['gitPackage'])
    root = pathlib.Path(destination) if prepared else vendor_destination(destination)
    if shutil.disk_usage(root.parent).free < 2 * 1024**3: raise ValueError('2GiB vendor storage headroom required')
    if not prepared: root.mkdir(mode=0o700)
    vendor = root / 'vendor'; vendor.mkdir(mode=0o700)
    records = []; errors = []
    try:
        for source in plan['registrySources']:
            package = source['package']; name = package['name'] + '-' + package['version']
            package_root = vendor / name; package_root.mkdir(mode=0o700)
            files = extract_package(pathlib.Path(source['path']), package_root, name, budget)
            if digest_file(pathlib.Path(source['path'])) != package['checksum']: raise ValueError('archive source changed during extraction')
            checksum = {'files': files, 'package': package['checksum']}
            with (package_root / '.cargo-checksum.json').open('x', encoding='utf8') as output: json.dump(checksum, output, sort_keys=True)
            records.append({'name': package['name'], 'version': package['version'], 'files': files, 'packageChecksum': package['checksum']})
        package = plan['gitPackage']; package_root = vendor / (package['name'] + '-' + package['version']); package_root.mkdir(mode=0o700)
        files = extract_package(git_archive, package_root, 'rust-electrum-client-' + acquisition.COMMIT, budget)
        if digest_file(git_archive) != git['rust-electrum-client-' + acquisition.COMMIT + '.tar.gz']['sha256']: raise ValueError('Git archive changed during extraction')
        if set(files) != set(git_proof['blobs']) or any(files[name] != git_proof['blobs'][name]['sha256'] for name in files): raise ValueError('materialized Git source differs from full verified tree')
        with (package_root / '.cargo-checksum.json').open('x', encoding='utf8') as output: json.dump({'files': files, 'package': None}, output, sort_keys=True)
        records.append({'name': package['name'], 'version': package['version'], 'files': files, 'packageChecksum': None, 'gitCommit': acquisition.COMMIT})
        if len(records) != 204: raise ValueError('all204 vendor packages required')
        config_root = root / 'offline-cargo-home'; config_root.mkdir(mode=0o700)
        with (config_root / 'config.toml').open('x', encoding='utf8') as output: output.write(cargo_config(vendor))
    except Exception as error: errors.append({'type': type(error).__name__, 'reason': str(error)[:512]})
    # Independent reopening verifies all materialized payloads and Cargo checksum files.
    for record in records:
        package_root = vendor / (record['name'] + '-' + record['version'])
        for name, expected in record['files'].items():
            budget.check(); actual = package_root.joinpath(*safe_relative(name).parts)
            regular_input(actual, MAX_FILE_BYTES)
            if digest_file(actual) != expected: raise ValueError('materialized source readback digest mismatch')
        checksum = json.loads((package_root / '.cargo-checksum.json').read_bytes())
        if checksum != {'files': record['files'], 'package': record['packageChecksum']}: raise ValueError('Cargo checksum metadata mismatch')
    receipt = {'schema': 'universe-electrs-locked-vendor-materialization-v1', 'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'plan': plan, 'packages': records, 'payloadFiles': budget.files, 'payloadBytes': budget.bytes, 'archiveMembersCharged': budget.members,
               'errors': errors, 'complete204Sources': not errors and len(records) == 204,
               'cargoInvoked': False, 'offlineResolutionQualified': False, 'fullBuildQualified': False,
               'sharedCacheMutated': False, 'nativeActions': False, 'partialFilesPreserved': True}
    with (root / 'vendor-materialization-receipt.json').open('x', encoding='utf8') as output: json.dump(receipt, output, sort_keys=True, indent=2)
    return {'destination': str(root), 'complete204Sources': receipt['complete204Sources'], 'errors': errors}


def run_child(root):
    if root.is_symlink() or not root.is_dir(): raise ValueError('owned materialization root invalid')
    owner = json.loads((root / 'OWNER.json').read_bytes())
    if owner['parentPid'] != os.getppid() or owner['scriptSha256'] != digest_file(pathlib.Path(__file__)):
        raise ValueError('owned materialization child source/PID mismatch')
    raw = (root / 'plan.json').read_bytes()
    if len(raw) > 512 * 1024 or hashlib.sha256(raw).hexdigest() != owner['planSha256']: raise ValueError('bounded immutable materialization plan required')
    plan = json.loads(raw)
    for name, checksum in owner['sourceModules'].items():
        if name not in ['materialize-locked-vendor.py', 'acquire-locked-sources.py', 'locked-source-inventory.py'] or digest_file(HERE / name) != checksum: raise ValueError('source module drift')
    result = materialize(plan, root, prepared=True)
    print(json.dumps(result)); return 1 if result['errors'] else 0


def launch(plan, destination):
    root = vendor_destination(destination)
    if shutil.disk_usage(root.parent).free < 2 * 1024**3: raise ValueError('2GiB private storage headroom')
    root.mkdir(mode=0o700)
    raw = json.dumps(plan, sort_keys=True).encode()
    with (root / 'plan.json').open('xb') as output: output.write(raw)
    modules = {name: digest_file(HERE / name) for name in ['materialize-locked-vendor.py', 'acquire-locked-sources.py', 'locked-source-inventory.py']}
    with (root / 'OWNER.json').open('x') as output: json.dump({'parentPid': os.getpid(), 'scriptSha256': modules['materialize-locked-vendor.py'], 'planSha256': hashlib.sha256(raw).hexdigest(), 'sourceModules': modules}, output)
    environment = {'LANG': 'C'}
    if os.name == 'nt': environment['SystemRoot'] = os.environ['SystemRoot']
    child = subprocess.Popen([sys.executable, '-B', '-I', '-S', str(pathlib.Path(__file__).resolve()), '--child-root', str(root)], env=environment, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    expired = False
    try: stdout, stderr = child.communicate(timeout=360)
    except subprocess.TimeoutExpired:
        expired = True; child.kill(); stdout, stderr = child.communicate(timeout=10)
    with (root / 'child.stdout').open('xb') as output: output.write(stdout[:256 * 1024])
    with (root / 'child.stderr').open('xb') as output: output.write(stderr[:32768])
    receipt = {'childPid': child.pid, 'exitCode': child.returncode, 'watchdogExpired': expired, 'partialFilesPreserved': True, 'nativeActions': False, 'cargoInvoked': False}
    with (root / 'execution.json').open('x') as output: json.dump(receipt, output)
    return {'destination': str(root), **receipt}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materialize', action='store_true')
    parser.add_argument('--first-receipt', type=pathlib.Path)
    parser.add_argument('--eight-receipt', type=pathlib.Path)
    parser.add_argument('--destination', type=pathlib.Path)
    parser.add_argument('--source-sha')
    parser.add_argument('--child-root', type=pathlib.Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child_root is not None: raise SystemExit(run_child(args.child_root))
    if not args.materialize:
        print(json.dumps({'preparedOnly': True, 'extracted': False, 'cargoInvoked': False})); return
    acquisition = kit()
    if not re.fullmatch('[0-9a-f]{40}', args.source_sha or '') or acquisition.local_git(['rev-parse', 'HEAD']).decode().strip() != args.source_sha or acquisition.local_git(['status', '--porcelain']).strip(): raise ValueError('exact clean source required')
    if args.first_receipt is None or args.eight_receipt is None or args.destination is None: raise ValueError('both reviewed receipts and absent destination required')
    plan = make_plan(args.first_receipt, args.eight_receipt, acquisition.local_git(['show', 'HEAD:Cargo.lock']))
    plan['sourceSha'] = args.source_sha
    result = launch(plan, args.destination)
    print(json.dumps(result))
    if result['exitCode'] or result['watchdogExpired']: raise SystemExit(1)


if __name__ == '__main__': main()
