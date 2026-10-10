"""Pure Linux path/config renderer; no uploads/extraction/Cargo or mount actions."""
import argparse
import hashlib
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
VENDOR_MANIFEST_SHA = '08429b3f5b39688dcb927df81881d2c7843c2fe3942bfe170fbd08082528fd6f'
LOCK_SHA = 'a46b82fd06e8fe3858a1722ec0098d528bd2f4920bc3116c7e247ef473613236'
GIT_COMMIT = '4bbfc612d594fe23282c439d4bdc446cff01ba1c'


def rendered(raw, task_root, source_manifest):
    if hashlib.sha256(raw).hexdigest() != VENDOR_MANIFEST_SHA: raise ValueError('exact sealed233 vendor manifest required')
    manifest = json.loads(raw)
    if manifest['schema'] != 'universe-electrs-sealed-linux-vendor-v2' or manifest['packageCount'] != 233 or len(manifest['files']) != 18580 or manifest['lockSha256'] != LOCK_SHA:
        raise ValueError('full233/18580 lock binding required')
    temporary = re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp/universe-electrs-build-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', task_root)
    persistent = re.fullmatch(r'/home/github-runner/.cache/universe-electrs-api-20261009/[0-9a-f]{16}', task_root)
    if not (temporary or persistent): raise ValueError('exact new owned Linux task root required')
    if not re.fullmatch('[0-9a-f]{40}', source_manifest.get('sourceCommit', '')) or source_manifest.get('status') != 'DRAFT_SOURCE_ONLY_FULL_BUILD_UNQUALIFIED': raise ValueError('honest frozen full source manifest required')
    locks = [entry for entry in source_manifest['files'] if entry['path'] == 'Cargo.lock']
    if len(locks) != 1 or locks[0]['gitSha256'] != LOCK_SHA: raise ValueError('source/vendor lock contradiction')
    vendor = pathlib.PurePosixPath(task_root) / 'vendor'
    config = ('[net]\noffline = true\n\n[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
              '[source."git+https://github.com/mempool/rust-electrum-client?rev=' + GIT_COMMIT + '"]\n'
              'git = "https://github.com/mempool/rust-electrum-client"\nrev = "' + GIT_COMMIT + '"\nreplace-with = "vendored-sources"\n\n'
              '[source.vendored-sources]\ndirectory = ' + json.dumps(str(vendor)) + '\n').encode()
    return {'schema': 'universe-electrs-linux-offline-path-binding-v2', 'sourceSha': source_manifest['sourceCommit'],
            'vendorManifestSha256': VENDOR_MANIFEST_SHA, 'sourceManifestSha256': hashlib.sha256((json.dumps(source_manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest(),
            'sourceManifestBindingEncoding': 'sorted-key compact JSON semantic binding; raw uploaded source manifest must also be independently pinned',
            'cargoLockSha256': LOCK_SHA, 'sourceRoot': task_root + ('/source-' + source_manifest['sourceCommit'] if persistent else '/source'), 'vendorRoot': str(vendor),
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
