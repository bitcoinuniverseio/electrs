"""Pure closed-ELF dependency/version binding; never executes/materializes libraries."""
import argparse
import json
import pathlib


def bind(package_report, host_report):
    if host_report.get('schema') != 'universe-electrs-helper-runtime-leaf-metadata-v1' or not host_report.get('hostAbiVersionDefinitionsObserved'):
        raise ValueError('actual known host ABI metadata required')
    private = {}
    host = {}
    executables = []
    for package in package_report['packages']:
        for path, value in package['files'].items():
            elf = value.get('elf')
            if not elf: continue
            record = {'origin': 'isolated-package', 'sourcePath': path, 'sha256': value['sha256'], 'elf': elf}
            if elf['soname']:
                if elf['soname'] in private: raise ValueError('duplicate private SONAME')
                private[elf['soname']] = record
            elif path == 'usr/bin/fuse2fs': executables.append(record)
            else: raise ValueError('unexpected package executable')
    for record in host_report['libraries']:
        if not record.get('present') or not record.get('abiQualified') or record['soname'] in host:
            raise ValueError('host library missing/unqualified/contradictory')
        host[record['soname']] = {'origin': 'observed-host-leaf', 'sourcePath': record['path'], 'sha256': record['sha256'], 'elf': record['elf']}
    if len(executables) != 1: raise ValueError('one exact fuse2fs executable required')
    mke = host_report['mke2fs']
    mke_record = {'origin': 'observed-host-leaf', 'sourcePath': mke['path'], 'sha256': mke['sha256'], 'elf': mke['elf']}
    mount = host_report.get('fusermount3')
    if mount is None or not mount.get('setuidObserved'): raise ValueError('actual existing fusermount3 metadata required')
    mount_record = {'origin': 'observed-host-leaf', 'sourcePath': mount['path'], 'sha256': mount['sha256'], 'elf': mount['elf']}
    groups = {'fuse2fs': {'providers': {**host, **private}, 'executables': executables},
              'mke2fsAndExistingMountHelper': {'providers': host, 'executables': [mke_record, mount_record]}}
    for group in groups.values(): check_closure(group['providers'], group['executables'])
    return {'schema': 'universe-electrs-helper-closed-elf-binding-v1', 'sourceSha': host_report['sourceSha'],
            'executionGroups': groups, 'metadataDependencyClosureVerified': True,
            'librariesMaterialized': False, 'runtimeExecutionQualified': False, 'helperExecuted': False,
            'mounted': False, 'hardStorageQualified': False, 'nativeActions': False}


def check_closure(providers, executables):
    for record in [*providers.values(), *executables]:
        elf = record['elf']
        if elf.get('interpreter') not in [None, '/lib64/ld-linux-x86-64.so.2']: raise ValueError('loader context contradiction')
        if elf.get('interpreter') and 'ld-linux-x86-64.so.2' not in providers: raise ValueError('exact loader provider missing')
        for needed in elf['needed']:
            if needed not in providers: raise ValueError('undeclared dependency; no default-library fallback: ' + needed)
        for requirement in elf['versionNeeds']:
            provider = providers.get(requirement['library'])
            if provider is None or not set(requirement['versions']) <= set(provider['elf']['versionDefinitions']):
                raise ValueError('exact dependency version set unavailable: ' + requirement['library'])


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--review-binding', action='store_true')
    parser.add_argument('--package-report', type=pathlib.Path); parser.add_argument('--host-report', type=pathlib.Path)
    args = parser.parse_args()
    if not args.review_binding:
        print(json.dumps({'preparedOnly': True, 'helperExecuted': False})); return
    for path in [args.package_report, args.host_report]:
        if path is None or path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024: raise ValueError('bounded regular actual metadata receipts required')
    print(json.dumps(bind(json.loads(args.package_report.read_bytes()), json.loads(args.host_report.read_bytes()))))


if __name__ == '__main__': main()
