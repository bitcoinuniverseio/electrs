"""Pure library ABI guard tests; no actual runner library access/helper execution."""
import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import Mock, MagicMock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('runtime', HERE / 'helper-runtime-metadata.py')
runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def file(self, contents):
        fake = MagicMock()
        fake.__str__.return_value = '/usr/lib/x86_64-linux-gnu/libc.so.6'
        fake.is_file.return_value = True
        fake.stat.return_value.st_size = 3
        fake.read_bytes.side_effect = contents
        return fake
    def test_default_no_probe(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'helper-runtime-metadata.py')], capture_output=True, check=True)
        self.assertIn(b'"metadataRead": false', result.stdout)

    def test_exact_fixed_library_paths(self):
        self.assertEqual(set(runtime.LIBRARIES), {'libc.so.6', 'libcom_err.so.2', 'libblkid.so.1', 'libuuid.so.1', 'libext2fs.so.2', 'libe2p.so.2', 'ld-linux-x86-64.so.2'})
        self.assertTrue(all(path.startswith(('/usr/lib/x86_64-linux-gnu/', '/lib64/')) for path in runtime.LIBRARIES.values()))

    def test_missing_library_unqualified(self):
        with patch.object(pathlib.Path, 'exists', return_value=False):
            value = runtime.inspect_library('libc.so.6', runtime.LIBRARIES['libc.so.6'], Mock())
        self.assertFalse(value['abiQualified'])

    def test_soname_and_version_contradictions(self):
        parser = Mock()
        parser.elf_metadata.return_value = {'soname': 'libc.so.6', 'versionDefinitions': ['GLIBC_2.34']}
        fake = self.file([b'abc'] * 4)
        with patch.object(pathlib.Path, 'exists', return_value=True), patch.object(pathlib.Path, 'resolve', return_value=fake):
            self.assertFalse(runtime.inspect_library('libc.so.6', str(fake), parser)['abiQualified'])
            parser.elf_metadata.return_value['soname'] = 'different.so'
            with self.assertRaisesRegex(ValueError, 'SONAME'): runtime.inspect_library('libc.so.6', str(fake), parser)

    def test_drift_and_path_escape_rejected(self):
        fake = self.file([b'abc', b'def'])
        with patch.object(pathlib.Path, 'exists', return_value=True), patch.object(pathlib.Path, 'resolve', return_value=fake):
            with self.assertRaisesRegex(ValueError, 'changed'): runtime.inspect_library('libc.so.6', str(fake), Mock())
        with patch.object(pathlib.Path, 'exists', return_value=True), patch.object(pathlib.Path, 'resolve', return_value=pathlib.Path('/home/github-runner/credentials')):
            with self.assertRaisesRegex(ValueError, 'leaf'): runtime.inspect_library('libc.so.6', str(fake), Mock())


if __name__ == '__main__': unittest.main()
