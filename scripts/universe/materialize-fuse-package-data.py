"""Default-unexecuted private package data extraction; no host/helper execution."""
import argparse
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import tarfile

HERE = pathlib.Path(__file__).resolve().parent


def inspector():
    spec = importlib.util.spec_from_file_location('bounded_package_inspector', HERE / 'inspect-fuse-packages.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def materialize(package_root, destination):
    parser = inspector(); helper = parser.helper()
    name = destination.name
    if not re.fullmatch(r'electrs-fuse-package-data-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}', name) or destination.exists() or destination.is_symlink(): raise ValueError('new exclusive package data directory required')
    helper.destination(destination.with_name(name.replace('electrs-fuse-package-data-', 'electrs-fuse-helper-', 1)))
    sources = []
    # Verify all original package containers/data/type metadata before first write.
    for package in helper.capsule()['packages']:
        path = package_root / package['filename']
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024: raise ValueError('bounded regular original package required')
        decoded = parser.decompress(parser.ar_data(path.read_bytes(), package))
        sources.append((package, decoded, parser.inspect_data(decoded)))
    destination.mkdir(mode=0o700)
    records = []; errors = []
    total = 0
    def charge(size):
        nonlocal total
        total += size
        if total > 16 * 1024**2 or len(records) >= 256: raise ValueError('package materialization byte/file bound before write')
    try:
        for package, data, inspected in sources:
            output_root = destination / 'packages' / package['name']; output_root.mkdir(parents=True)
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                for member in archive:
                    name = member.name.removeprefix('./')
                    if not member.isfile(): continue
                    expected = inspected['files'][name]
                    target = output_root.joinpath(*pathlib.PurePosixPath(name).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    raw = archive.extractfile(member).read(member.size + 1)
                    if hashlib.sha256(raw).hexdigest() != expected['sha256']: raise ValueError('package payload differs from inspected digest')
                    charge(len(raw))
                    with target.open('xb') as output: output.write(raw)
                    records.append({'path': target.relative_to(destination).as_posix(), **expected, 'package': package['name']})
            # Do not create package symlinks; materialize only same-directory
            # library aliases as identical regular bytes, each digest-bound.
            for alias, basename in inspected['sameDirectoryLinks'].items():
                source = output_root / pathlib.PurePosixPath(alias).parent / basename
                target = output_root / alias
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = source.read_bytes(); checksum = hashlib.sha256(raw).hexdigest()
                expected = inspected['files'][str(pathlib.PurePosixPath(alias).parent / basename)]
                if checksum != expected['sha256']: raise ValueError('private library alias source drift')
                charge(len(raw))
                with target.open('xb') as output: output.write(raw)
                records.append({'path': target.relative_to(destination).as_posix(), 'sha256': checksum, 'bytes': len(raw), 'package': package['name'], 'aliasMaterialization': basename})
        for record in records:
            target = destination / record['path']
            if target.is_symlink() or target.stat().st_nlink != 1 or hashlib.sha256(target.read_bytes()).hexdigest() != record['sha256']: raise ValueError('private package data independent readback')
        if sum(r['bytes'] for r in records) > 16 * 1024**2 or len(records) > 256: raise ValueError('package materialization byte/file bound')
    except Exception as error: errors.append({'type': type(error).__name__, 'reason': str(error)[:512]})
    receipt = {'schema': 'universe-electrs-private-helper-package-data-v1', 'files': records, 'errors': errors,
               'excludedCrossPackageDocumentationLinks': [item for _, _, report in sources for item in report['excludedCrossPackageDocumentationLinks']],
               'packageCodeExecuted': False, 'hostInstalled': False, 'controlScriptsParsedOrExecuted': False,
               'hostLibrariesIncluded': False, 'runtimeQualified': False, 'mounted': False, 'nativeActions': False,
               'partialFilesPreserved': True}
    with (destination / 'package-data-receipt.json').open('x', encoding='utf8') as output: json.dump(receipt, output, indent=2)
    return {'destination': str(destination), 'files': len(records), 'errors': errors, 'runtimeQualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--materialize-private', action='store_true')
    parser.add_argument('--package-root', type=pathlib.Path); parser.add_argument('--destination', type=pathlib.Path)
    args = parser.parse_args()
    if not args.materialize_private:
        print(json.dumps({'preparedOnly': True, 'extracted': False, 'helperExecuted': False})); return
    if args.package_root is None or args.destination is None: raise ValueError('owned source and new destination required')
    result = materialize(args.package_root, args.destination); print(json.dumps(result))
    if result['errors']: raise SystemExit(1)


if __name__ == '__main__': main()
