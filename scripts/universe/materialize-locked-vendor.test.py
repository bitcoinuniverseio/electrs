"""Pure bounded materialization fixtures; no real204 extraction/Cargo/network."""
import hashlib
import importlib.util
import io
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('vendor', HERE / 'materialize-locked-vendor.py')
vendor = importlib.util.module_from_spec(spec); spec.loader.exec_module(vendor)


class VendorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = pathlib.Path(self.temp.name)
        self.output = self.root / 'package'; self.output.mkdir()
    def tearDown(self): self.temp.cleanup()

    def archive(self, entries):
        path = self.root / 'source.crate'
        with tarfile.open(path, 'w:gz') as archive:
            for name, kind, payload in entries:
                entry = tarfile.TarInfo(name)
                if kind == 'file': entry.size = len(payload); archive.addfile(entry, io.BytesIO(payload))
                elif kind == 'directory': entry.type = tarfile.DIRTYPE; archive.addfile(entry)
                else: entry.type = tarfile.SYMTYPE; entry.linkname = '/outside'; archive.addfile(entry)
        return path

    def test_default_no_extraction(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'materialize-locked-vendor.py')], check=True, capture_output=True)
        self.assertIn(b'"preparedOnly": true', result.stdout)
        self.assertIn(b'"extracted": false', result.stdout)

    def test_exact_payloads_independently_hashed(self):
        path = self.archive([('fixture-1/Cargo.toml', 'file', b'manifest'), ('fixture-1/src/lib.rs', 'file', b'actual')])
        result = vendor.extract_package(path, self.output, 'fixture-1', vendor.WorkBudget())
        self.assertEqual(result['src/lib.rs'], hashlib.sha256(b'actual').hexdigest())
        self.assertEqual((self.output / 'src/lib.rs').read_bytes(), b'actual')

    def test_escape_link_alias_checksum_injection_rejected(self):
        for entries in [[('fixture-1/../escape', 'file', b'x')], [('fixture-1/a', 'link', b'')],
                        [('fixture-1/.cargo-checksum.json', 'file', b'{}')],
                        [('fixture-1/Upper', 'file', b'x'), ('fixture-1/upper', 'file', b'x')]]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                vendor.extract_package(self.archive(entries), self.output, 'fixture-1', vendor.WorkBudget())

    def test_nonportable_or_native_git_paths_rejected(self):
        for name in ['/absolute', '../x', '.git/config', 'src/aux.rs', 'src/ends.', 'src\\file']:
            with self.subTest(name=name), self.assertRaises(ValueError): vendor.safe_relative(name)

    def test_empty_directory_work_counts_globally(self):
        path = self.archive([('fixture-1/a', 'directory', b''), ('fixture-1/b', 'directory', b'')])
        with patch.object(vendor, 'MAX_TOTAL_FILES', 1), self.assertRaisesRegex(ValueError, 'member bound'):
            vendor.extract_package(path, self.output, 'fixture-1', vendor.WorkBudget())

    def test_source_bytes_bound_before_file_create(self):
        path = self.archive([('fixture-1/Cargo.toml', 'file', b'large')])
        with patch.object(vendor, 'MAX_FILE_BYTES', 1), self.assertRaisesRegex(ValueError, 'byte work'):
            vendor.extract_package(path, self.output, 'fixture-1', vendor.WorkBudget())
        self.assertFalse((self.output / 'Cargo.toml').exists())

    def test_archive_checksum_before_any_vendor_create_or_parser(self):
        path = self.root / 'bad.crate'; path.write_bytes(b'not qualified')
        plan = {'registrySources': [{'path': str(path), 'package': {'checksum': '0' * 64}}]}
        with patch.object(vendor, 'vendor_destination', side_effect=AssertionError('no admission')), patch.object(tarfile, 'open', side_effect=AssertionError('no parser')):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                vendor.materialize(plan, self.root / 'vendor')

    def test_config_exact_git_revision_and_offline_no_patch(self):
        import tomllib
        value = tomllib.loads(vendor.cargo_config(pathlib.Path('/owned/vendor')))
        self.assertTrue(value['net']['offline'])
        self.assertNotIn('patch', value)
        git_keys = [name for name in value['source'] if name.startswith('git+')]
        self.assertEqual(len(git_keys), 1)
        git = value['source'][git_keys[0]]
        self.assertEqual(git['rev'], vendor.kit().COMMIT)
        self.assertEqual(value['source']['vendored-sources']['directory'], '/owned/vendor')

    def test_wrong_receipt_bytes_rejected(self):
        path = self.root / 'receipt.json'; path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'original receipt checksum'):
            vendor.raw_json(path, '0' * 64)

    def test_watchdog_targets_only_owned_child_and_preserves_outputs(self):
        destination = self.root / 'new'
        child = Mock(); child.pid = 55; child.returncode = -9
        child.communicate.side_effect = [subprocess.TimeoutExpired('owned', 360), (b'partial', b'original failure')]
        with patch.object(vendor, 'vendor_destination', return_value=destination), patch.object(vendor.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 2 * 1024**3})()), patch.object(vendor.subprocess, 'Popen', return_value=child):
            result = vendor.launch({}, destination)
        child.kill.assert_called_once_with()
        self.assertTrue(result['watchdogExpired'])
        self.assertEqual((destination / 'child.stderr').read_bytes(), b'original failure')


if __name__ == '__main__': unittest.main()
