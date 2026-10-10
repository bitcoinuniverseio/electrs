"""Controlled private extraction fixtures only; never real package/helper/mount."""
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('materializer', HERE / 'materialize-fuse-package-data.py')
materializer = importlib.util.module_from_spec(spec); spec.loader.exec_module(materializer)


class MaterializeTests(unittest.TestCase):
    def test_default_no_extraction(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'materialize-fuse-package-data.py')], check=True, capture_output=True)
        self.assertIn(b'"extracted": false', result.stdout)

    def test_checksum_failure_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            source = pathlib.Path(folder); (source / 'fixture.deb').write_bytes(b'wrong')
            destination = source / 'electrs-fuse-package-data-20261010T000000Z-0123456789abcdef'
            parser = Mock(); helper = Mock(); parser.helper.return_value = helper
            helper.capsule.return_value = {'packages': [{'name': 'fixture', 'filename': 'fixture.deb'}]}
            parser.ar_data.side_effect = ValueError('checksum before parse')
            with patch.object(materializer, 'inspector', return_value=parser), self.assertRaisesRegex(ValueError, 'checksum'): materializer.materialize(source, destination)
            self.assertFalse(destination.exists())

    def test_regular_library_alias_bytes_and_independent_readback(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as tar:
            entry = tarfile.TarInfo('./usr/lib/library.so.1.2'); entry.size = 3; tar.addfile(entry, io.BytesIO(b'abc'))
        digest = hashlib.sha256(b'abc').hexdigest()
        inspected = {'files': {'usr/lib/library.so.1.2': {'sha256': digest, 'bytes': 3}},
                     'sameDirectoryLinks': {'usr/lib/library.so.1': 'library.so.1.2'}, 'excludedCrossPackageDocumentationLinks': []}
        with tempfile.TemporaryDirectory() as folder:
            source = pathlib.Path(folder); (source / 'fixture.deb').write_bytes(b'controlled')
            destination = source / 'electrs-fuse-package-data-20261010T000000Z-0123456789abcdef'
            parser = Mock(); parser.decompress.return_value = raw.getvalue(); parser.inspect_data.return_value = inspected
            parser.helper.return_value.capsule.return_value = {'packages': [{'name': 'fixture', 'filename': 'fixture.deb'}]}
            with patch.object(materializer, 'inspector', return_value=parser): result = materializer.materialize(source, destination)
            self.assertFalse(result['runtimeQualified']); self.assertFalse(result['errors'])
            alias = destination / 'packages/fixture/usr/lib/library.so.1'
            self.assertFalse(alias.is_symlink()); self.assertEqual(alias.read_bytes(), b'abc')
            receipt = json.loads((destination / 'package-data-receipt.json').read_bytes())
            self.assertFalse(receipt['hostInstalled']); self.assertFalse(receipt['hostLibrariesIncluded'])


if __name__ == '__main__': unittest.main()
