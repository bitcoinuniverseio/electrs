"""Fixed host ELF/library metadata only; no helper/loader execution or mount."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
LIBRARIES = {'libc.so.6': '/usr/lib/x86_64-linux-gnu/libc.so.6',
             'libcom_err.so.2': '/usr/lib/x86_64-linux-gnu/libcom_err.so.2',
             'libblkid.so.1': '/usr/lib/x86_64-linux-gnu/libblkid.so.1',
             'libuuid.so.1': '/usr/lib/x86_64-linux-gnu/libuuid.so.1',
             'ld-linux-x86-64.so.2': '/lib64/ld-linux-x86-64.so.2'}
REQUIRED_VERSIONS = {'libc.so.6': {'GLIBC_2.38', 'GLIBC_2.34'}, 'libblkid.so.1': {'BLKID_1.0'}, 'libuuid.so.1': {'UUID_1.0'}}
READELF_SHA = '64c58e15274bbbb5153f31078e455e9e77ee5f51489e709bba5bb788ce9df2b0'
MKE2FS_SHA = '07cd24ce58a410cc9cee93c55ae5ac95986df016c5907dc7a49b55389bd41ed2'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def inspect_library(soname, requested, parser):
    path = pathlib.Path(requested)
    if not path.exists(): return {'soname': soname, 'requestedPath': requested, 'present': False, 'abiQualified': False}
    resolved = path.resolve(strict=True)
    if not str(resolved).startswith('/usr/lib/x86_64-linux-gnu/') or not resolved.is_file() or resolved.stat().st_size > 8 * 1024**2:
        raise ValueError('exact bounded system-library leaf required')
    raw = resolved.read_bytes(); metadata = parser.elf_metadata(raw)
    after = resolved.read_bytes()
    if hashlib.sha256(after).digest() != hashlib.sha256(raw).digest(): raise ValueError('host library changed during observation')
    if metadata['soname'] != soname: raise ValueError('host library SONAME contradiction')
    required = REQUIRED_VERSIONS.get(soname, set())
    return {'soname': soname, 'requestedPath': requested, 'path': str(resolved), 'present': True,
            'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'elf': metadata,
            'requiredVersionDefinitions': sorted(required), 'abiQualified': required <= set(metadata['versionDefinitions'])}


def collect():
    guard = load('owned_runtime_guard', 'locked-cache-readonly.py'); expected = guard.runtime_guard()
    inventory = load('runtime_source_guard', 'locked-source-inventory.py'); guard.source_guard(inventory, expected)
    parser = load('pure_host_elf_parser', 'inspect-fuse-packages.py')
    records = [inspect_library(soname, path, parser) for soname, path in LIBRARIES.items()]
    mke2fs = pathlib.Path('/usr/sbin/mke2fs').resolve(strict=True)
    if str(mke2fs) != '/usr/sbin/mke2fs' or mke2fs.stat().st_size > 8 * 1024**2: raise ValueError('existing mke2fs path/type/size')
    mke_raw = mke2fs.read_bytes()
    if hashlib.sha256(mke_raw).hexdigest() != MKE2FS_SHA: raise ValueError('actual a770 mke2fs pin mismatch')
    mke_elf = parser.elf_metadata(mke_raw)
    readelf = pathlib.Path('/usr/bin/readelf').resolve(strict=True)
    if str(readelf) != '/usr/bin/x86_64-linux-gnu-readelf' or hashlib.sha256(readelf.read_bytes()).hexdigest() != READELF_SHA:
        raise ValueError('previously observed readelf pin mismatch')
    result = {'schema': 'universe-electrs-helper-runtime-leaf-metadata-v1', 'sourceSha': expected,
              'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'libraries': records,
              'readelf': {'path': str(readelf), 'sha256': READELF_SHA, 'executed': False},
              'mke2fs': {'path': str(mke2fs), 'sha256': MKE2FS_SHA, 'elf': mke_elf, 'executed': False},
              'hostAbiVersionDefinitionsObserved': all(record['abiQualified'] for record in records),
              'isolatedPackageAndHostClosureQualified': False, 'helperExecuted': False, 'loaderExecuted': False,
              'deviceOpened': False, 'mounted': False, 'cargoInvoked': False, 'nativeActions': False}
    guard.source_guard(inventory, expected)
    raw = json.dumps(result, separators=(',', ':')).encode()
    if len(raw) > 65536: raise ValueError('runtime metadata envelope bound')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--observe-owned-runtime', action='store_true')
    args = parser.parse_args()
    if not args.observe_owned_runtime:
        print(json.dumps({'preparedOnly': True, 'metadataRead': False, 'helperExecuted': False})); return
    import sys
    sys.stdout.buffer.write(collect() + b'\n')


if __name__ == '__main__': main()
