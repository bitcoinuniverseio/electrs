"""UNEXECUTED three checksum-pinned Ubuntu packages to private namespace only."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CAPSULE_SHA = '4c74e0651fb6cdedd69e30086ae5058fcc6492942ceecb73d838cfdbcd6f2dd7'


def module():
    spec = importlib.util.spec_from_file_location('reviewed_exact_downloads', HERE / 'acquire-locked-sources.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def capsule():
    raw = (HERE / 'fuse-helper-packages.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPSULE_SHA: raise ValueError('exact reviewed package capsule required')
    value = json.loads(raw)
    if value['schema'] != 'universe-electrs-isolated-fuse-helper-packages-v1' or len(value['packages']) != 3 or sum(p['bytes'] for p in value['packages']) != 345514:
        raise ValueError('exact three-package denominator/bytes required')
    return value


def destination(path):
    path = pathlib.Path(path)
    if path.exists() or path.is_symlink() or not re.fullmatch(r'electrs-fuse-helper-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}', path.name): raise ValueError('new exclusive helper namespace required')
    module().safe_destination(path.with_name(path.name.replace('electrs-fuse-helper-', 'electrs-locked-acquisition-', 1)))
    return path


def worker(root):
    kit = module(); value = capsule()
    owner = json.loads((root / 'OWNER.json').read_bytes())
    if root.is_symlink() or owner['parentPid'] != os.getppid() or owner['scriptSha256'] != kit.sha(pathlib.Path(__file__).read_bytes()) or owner['downloadModuleSha256'] != kit.sha((HERE / 'acquire-locked-sources.py').read_bytes()): raise ValueError('owned helper child source/PID guard')
    urls = {package['url'] for package in value['packages']}
    # Isolated module policy specializes the reviewed downloader to these three
    # literal capsule URLs; no shared module/configuration is modified.
    kit.url_allowed = lambda url: url in urls
    kit.MAX_REQUESTS = 3; kit.MAX_TOTAL = 1024 * 1024; kit.SECONDS = 45
    budget = kit.Budget(); records = []; errors = []
    for package in value['packages']:
        try:
            record = kit.download(package['url'], root / package['filename'], budget, package['bytes'], package['sha256'])
            if record['bytes'] != package['bytes']: raise ValueError('exact official package size mismatch')
            records.append(record)
        except Exception as error:
            budget.stop.set(); errors.append({'type': type(error).__name__, 'reason': str(error)[:512]}); break
    receipt = {'schema': 'universe-electrs-isolated-helper-acquisition-v1', 'capsuleSha256': CAPSULE_SHA,
               'packages': records, 'requests': budget.requests, 'networkBytes': budget.total, 'errors': errors,
               'packageMetadataTrust': value['metadataTrust'], 'hostInstalled': False, 'extracted': False,
               'maintainerScriptsExecuted': False, 'helperExecuted': False, 'deviceOpened': False,
               'mounted': False, 'cargoInvoked': False, 'nativeActions': False, 'automaticRetries': 0,
               'runtimeQualified': False, 'hardStorageQualified': False, 'partialFilesPreserved': True}
    with (root / 'acquisition-receipt.json').open('x', encoding='utf8') as output: json.dump(receipt, output, indent=2)
    print(json.dumps({'qualifiedPackages': len(records), 'errors': errors}))
    return 1 if errors else 0


def launch(root):
    kit = module(); value = capsule(); root = destination(root)
    if any(os.environ.get(key) for key in ['SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR']): raise ValueError('TLS override forbidden')
    if shutil.disk_usage(root.parent).free < 16 * 1024**2: raise ValueError('bounded helper private storage headroom')
    root.mkdir(mode=0o700)
    with (root / 'OWNER.json').open('x') as output: json.dump({'parentPid': os.getpid(), 'scriptSha256': kit.sha(pathlib.Path(__file__).read_bytes()), 'downloadModuleSha256': kit.sha((HERE / 'acquire-locked-sources.py').read_bytes())}, output)
    environment = {'LANG': 'C'}
    if os.name == 'nt': environment['SystemRoot'] = os.environ['SystemRoot']
    child = subprocess.Popen([sys.executable, '-B', '-I', '-S', str(pathlib.Path(__file__).resolve()), '--child-root', str(root)], env=environment, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    expired = False
    try: stdout, stderr = child.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        expired = True; child.kill(); stdout, stderr = child.communicate(timeout=10)
    with (root / 'child.stdout').open('xb') as output: output.write(stdout[:32768])
    with (root / 'child.stderr').open('xb') as output: output.write(stderr[:32768])
    execution = {'childPid': child.pid, 'exitCode': child.returncode, 'watchdogExpired': expired, 'partialFilesPreserved': True, 'nativeActions': False}
    with (root / 'execution.json').open('x') as output: json.dump(execution, output)
    return {'destination': str(root), **execution}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acquire', action='store_true'); parser.add_argument('--destination', type=pathlib.Path)
    parser.add_argument('--source-sha'); parser.add_argument('--child-root', type=pathlib.Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child_root is not None: raise SystemExit(worker(args.child_root))
    if not args.acquire:
        print(json.dumps({'preparedOnly': True, 'networkFetched': False, 'installed': False})); return
    kit = module()
    if args.destination is None or not re.fullmatch('[0-9a-f]{40}', args.source_sha or '') or kit.local_git(['rev-parse', 'HEAD']).decode().strip() != args.source_sha or kit.local_git(['status', '--porcelain']).strip(): raise ValueError('exact clean reviewed source/destination required')
    result = launch(args.destination); print(json.dumps(result))
    if result['exitCode'] or result['watchdogExpired']: raise SystemExit(1)


if __name__ == '__main__': main()
