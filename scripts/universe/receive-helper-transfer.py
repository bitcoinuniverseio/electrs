"""Root-reviewed local Linux helper capsule receiver; no network/helper/mount actions."""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import tarfile

ARCHIVE_SHA = '213d548c40f31d3b15c94f3468420a8cf6de4849bc6c3ecafe29f15e79bb224c'
MANIFEST_SHA = 'ac5942baa44753d0e60a7193f8561d5c9489bdd101a7718902339e2cd85c46e8'
RECEIPT_SHA = '023dd8fb53cfa30eb4d15e57b412930183c8d093f37c0c4eb15d5eb1c2db02e7'


def payloads(raw):
    if len(raw) > 2 * 1024**2 or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA:
        raise ValueError('exact sealed helper archive required before parsing')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            path = pathlib.PurePosixPath(member.name)
            if len(files) >= 24 or not member.isfile() or member.size > 2 * 1024**2 or path.is_absolute() or '..' in path.parts or '\\' in member.name or ':' in member.name or member.name in files:
                raise ValueError('exact bounded regular transfer payload required')
            files[member.name] = {'bytes': archive.extractfile(member).read(member.size + 1), 'mode': member.mode}
    if len(files) != 24 or 'PACKAGE-DATA-MANIFEST.json' not in files or 'MATERIALIZATION-RECEIPT.json' not in files:
        raise ValueError('complete24-member capsule required')
    manifest_raw = files['PACKAGE-DATA-MANIFEST.json']['bytes']
    if hashlib.sha256(manifest_raw).hexdigest() != MANIFEST_SHA or hashlib.sha256(files['MATERIALIZATION-RECEIPT.json']['bytes']).hexdigest() != RECEIPT_SHA:
        raise ValueError('reviewed metadata bytes mismatch')
    manifest = json.loads(manifest_raw)
    if len(manifest['files']) != 22: raise ValueError('complete22 helper data files required')
    expected = {row['path']: row for row in manifest['files']}
    if set(files) != set(expected) | {'PACKAGE-DATA-MANIFEST.json', 'MATERIALIZATION-RECEIPT.json'}: raise ValueError('exact manifest path set required')
    for name, row in expected.items():
        value = files[name]
        if not name.startswith('packages/') or len(value['bytes']) != row['bytes'] or hashlib.sha256(value['bytes']).hexdigest() != row['sha256'] or value['mode'] != int(row['linuxMode'], 8):
            raise ValueError('transferred data bytes/mode contradiction')
    if sum(len(value['bytes']) for value in files.values()) > 4 * 1024**2: raise ValueError('aggregate capsule decoded payload bound')
    return files


def receive(archive, destination, temp):
    if destination.parent != temp or not re.fullmatch(r'universe-electrs-helper-data-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', destination.name) or destination.exists() or destination.is_symlink():
        raise ValueError('new exclusive owned helper transfer root required')
    for path in [temp, *temp.parents]:
        if path.is_symlink(): raise ValueError('linked transfer parent')
    if os.getuid() != 1001 or temp.stat().st_uid != 1001 or archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 2 * 1024**2:
        raise ValueError('known owned transfer context required')
    files = payloads(archive.read_bytes())  # Verify ALL payloads before first write.
    destination.mkdir(mode=0o700)
    for name, value in files.items():
        target = destination.joinpath(*pathlib.PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as out: out.write(value['bytes'])
        target.chmod(value['mode'])
    for name, value in files.items():
        target = destination / name
        if target.is_symlink() or not target.is_file() or target.stat().st_nlink != 1 or target.read_bytes() != value['bytes']:
            raise ValueError('independent transferred-file readback failed')
    return {'archiveSha256': ARCHIVE_SHA, 'manifestSha256': MANIFEST_SHA, 'filesVerified': 24,
            'destination': str(destination), 'helperExecuted': False, 'mounted': False, 'nativeActions': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--receive-local', action='store_true')
    parser.add_argument('--archive', type=pathlib.Path); parser.add_argument('--destination', type=pathlib.Path)
    args = parser.parse_args()
    if not args.receive_local:
        print(json.dumps({'preparedOnly': True, 'filesWritten': False, 'networkFetched': False})); return
    if args.archive is None or args.destination is None: raise ValueError('reviewed local archive and absent destination required')
    print(json.dumps(receive(args.archive, args.destination, pathlib.Path(os.environ['RUNNER_TEMP']))))


if __name__ == '__main__': main()
