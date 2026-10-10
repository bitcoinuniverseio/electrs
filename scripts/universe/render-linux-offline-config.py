"""Pure Linux path/config renderer; no uploads/extraction/Cargo or mount actions."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
VENDOR_MANIFEST_SHA = '1b86146fbb885080e835aa180ef60783a806f7a2926790281d7f47ec5a4a2c5f'
LOCK_SHA = 'd70b0284f71409a27beb6e9f50b3e137c36463fc82aa987c225c8f4ced32a676'


def rendered(raw, task_root, source_manifest):
    if hashlib.sha256(raw).hexdigest() != VENDOR_MANIFEST_SHA: raise ValueError('exact sealed204 vendor manifest required')
    manifest = json.loads(raw)
    if manifest['schema'] != 'universe-electrs-sealed-linux-vendor-v1' or manifest['packageCount'] != 204 or len(manifest['files']) != 16390 or manifest['lockSha256'] != LOCK_SHA:
        raise ValueError('full204/16390 lock binding required')
    if not re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp/universe-electrs-build-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', task_root): raise ValueError('exact new owned Linux task root required')
    if not re.fullmatch('[0-9a-f]{40}', source_manifest.get('sourceCommit', '')) or source_manifest.get('status') != 'DRAFT_SOURCE_ONLY_FULL_BUILD_UNQUALIFIED': raise ValueError('honest frozen full source manifest required')
    locks = [entry for entry in source_manifest['files'] if entry['path'] == 'Cargo.lock']
    if len(locks) != 1 or locks[0]['gitSha256'] != LOCK_SHA: raise ValueError('source/vendor lock contradiction')
    spec = importlib.util.spec_from_file_location('materializer_config', HERE / 'materialize-locked-vendor.py')
    materializer = importlib.util.module_from_spec(spec); spec.loader.exec_module(materializer)
    vendor = pathlib.PurePosixPath(task_root) / 'vendor'
    config = materializer.cargo_config(vendor).encode()
    return {'schema': 'universe-electrs-linux-offline-path-binding-v1', 'sourceSha': source_manifest['sourceCommit'],
            'vendorManifestSha256': VENDOR_MANIFEST_SHA, 'sourceManifestSha256': hashlib.sha256((json.dumps(source_manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest(),
            'sourceManifestBindingEncoding': 'sorted-key compact JSON semantic binding; raw uploaded source manifest must also be independently pinned',
            'cargoLockSha256': LOCK_SHA, 'sourceRoot': task_root + '/source', 'vendorRoot': str(vendor),
            'workRoot': task_root + '/work', 'cargoHome': task_root + '/work/cargo-home',
            'targetRoot': task_root + '/work/target', 'temporaryRoot': task_root + '/work/tmp',
            'configSha256': hashlib.sha256(config).hexdigest(), 'configUtf8': config.decode(),
            'configWritten': False, 'uploaded': False, 'actualPathSetVerified': False,
            'cargoInvoked': False, 'offlineResolutionQualified': False, 'storageEnforcementQualified': False,
            'fullBuildQualified': False, 'nativeActions': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--review-paths', action='store_true'); parser.add_argument('--task-root')
    parser.add_argument('--vendor-manifest', type=pathlib.Path); parser.add_argument('--source-manifest', type=pathlib.Path)
    args = parser.parse_args()
    if not args.review_paths:
        print(json.dumps({'preparedOnly': True, 'configWritten': False, 'cargoInvoked': False})); return
    for path in [args.vendor_manifest, args.source_manifest]:
        if path is None or path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024**2: raise ValueError('bounded regular source/vendor manifests required')
    raw_source = args.source_manifest.read_bytes()
    value = rendered(args.vendor_manifest.read_bytes(), args.task_root or '', json.loads(raw_source))
    value['rawSourceManifestSha256'] = hashlib.sha256(raw_source).hexdigest()
    print(json.dumps(value))


if __name__ == '__main__': main()
