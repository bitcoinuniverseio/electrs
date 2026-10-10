"""Local synthetic archive guards; no cache, network, Cargo or Linux unit access."""
import hashlib
import importlib.util
import io
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('inventory', HERE / 'locked-source-inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name) / 'fixture.crate'
        self.package = {'name': 'fixture', 'version': '1.0.0'}

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, entries):
        with tarfile.open(self.path, 'w:gz') as output:
            for name, kind in entries:
                member = tarfile.TarInfo(name)
                if kind == 'file':
                    member.size = 3
                    output.addfile(member, io.BytesIO(b'abc'))
                elif kind == 'directory':
                    member.type = tarfile.DIRTYPE
                    output.addfile(member)
                else:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/outside'
                    output.addfile(member)
        self.package['checksum'] = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_verified_archive_not_extracted(self):
        self.archive([('fixture-1.0.0/Cargo.toml', 'file')])
        result = inventory.inspect_archive(self.path, self.package)
        self.assertTrue(result['requiredSourceFilesPresent'])
        self.assertFalse(result['extracted'])
        self.assertEqual(list(pathlib.Path(self.temp.name).iterdir()), [self.path])

    def test_checksum_verified_before_tar(self):
        self.path.write_bytes(b'not a tar file')
        self.package['checksum'] = '0' * 64
        with mock.patch.object(tarfile, 'open', side_effect=AssertionError('must not parse')):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                inventory.inspect_archive(self.path, self.package)

    def test_paths_links_duplicates_and_directory_manifest_rejected(self):
        for entries in [
            [('fixture-1.0.0/../escape', 'file')],
            [('/fixture-1.0.0/Cargo.toml', 'file')],
            [('fixture-1.0.0/Cargo.toml', 'link')],
            [('fixture-1.0.0/Cargo.toml', 'file')] * 2,
            [('fixture-1.0.0/Cargo.toml', 'directory')],
            [('fixture-1.0.0/' + 'a' * 513, 'file')],
        ]:
            with self.subTest(entries=entries):
                self.archive(entries)
                with self.assertRaises(ValueError):
                    inventory.inspect_archive(self.path, self.package)

    def test_rocksdb_authors_required_to_prevent_implicit_git(self):
        self.package.update(name='librocksdb-sys', version='0.17.3+10.4.2')
        root = 'librocksdb-sys-0.17.3+10.4.2/'
        entries = [(root + name, 'file') for name in ['Cargo.toml', 'build.rs', 'snappy/CMakeLists.txt']]
        self.archive(entries)
        with self.assertRaisesRegex(ValueError, 'implicit fetch forbidden'):
            inventory.inspect_archive(self.path, self.package)
        self.archive(entries + [(root + 'rocksdb/AUTHORS', 'file')])
        self.assertTrue(inventory.inspect_archive(self.path, self.package)['requiredSourceFilesPresent'])

    def test_member_work_bound(self):
        self.archive([('fixture-1.0.0/Cargo.toml', 'file'), ('fixture-1.0.0/src/lib.rs', 'file')])
        with mock.patch.object(inventory, 'MAX_MEMBERS', 1):
            with self.assertRaisesRegex(ValueError, 'work bound'):
                inventory.inspect_archive(self.path, self.package)

    def test_original_git_lock_counts_and_git_pin(self):
        raw = subprocess.check_output(['git', 'show', 'HEAD:Cargo.lock'], cwd=HERE.parents[1])
        packages = inventory.parse_lock(raw)
        self.assertGreater(len(packages), 200)
        git_packages = [p for p in packages if p['source'].startswith('git+')]
        self.assertEqual(len(git_packages), 1)
        self.assertTrue(git_packages[0]['source'].endswith('#' + inventory.GIT_COMMIT))
        with self.assertRaisesRegex(ValueError, 'original lock'):
            inventory.parse_lock(raw + b'\n')

    def test_unknown_cache_and_non_plumbing_git_rejected(self):
        with self.assertRaisesRegex(ValueError, 'exact observed'):
            inventory.inventory([], pathlib.Path(self.temp.name))
        with mock.patch.object(inventory, 'regular_file'), mock.patch.object(pathlib.Path, 'read_bytes', return_value=b'x'), mock.patch.object(inventory, 'GIT_SHA', hashlib.sha256(b'x').hexdigest()):
            with self.assertRaisesRegex(ValueError, 'prohibited'):
                inventory.git_read(['fetch'], pathlib.Path(self.temp.name))

    def test_default_mode_performs_no_cache_read(self):
        result = subprocess.run(['python', str(HERE / 'locked-source-inventory.py')], capture_output=True, check=True)
        self.assertIn(b'"preparedOnly": true', result.stdout)
        self.assertIn(b'"cacheRead": false', result.stdout)


if __name__ == '__main__':
    unittest.main()
