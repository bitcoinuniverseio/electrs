"""Pure helper acquisition controls; no packages fetched/extracted/executed."""
import importlib.util
import contextlib
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('helper', HERE / 'acquire-fuse-helper.py')
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)


class HelperTests(unittest.TestCase):
    def test_default_no_acquisition(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'acquire-fuse-helper.py')], check=True, capture_output=True)
        self.assertEqual(json.loads(result.stdout), {'preparedOnly': True, 'networkFetched': False, 'installed': False})

    def test_exact_three_publisher_checksums_and_matched_version(self):
        value = helper.capsule()
        self.assertEqual(len(value['packages']), 3)
        self.assertEqual(sum(p['bytes'] for p in value['packages']), 345514)
        self.assertEqual(value['packages'][0]['version'], value['packages'][1]['version'])
        self.assertEqual({p['role'] for p in value['packages']}, {'fuse2fs', 'matched-ext2fs', 'fuse2-runtime'})
        self.assertTrue(all(p['url'].startswith('https://archive.ubuntu.com/ubuntu/pool/') for p in value['packages']))
        self.assertIn('signed APT release chain not independently checked', value['metadataTrust'])

    def test_capsule_drift_rejected(self):
        with patch.object(pathlib.Path, 'read_bytes', return_value=b'{}'):
            with self.assertRaisesRegex(ValueError, 'reviewed package capsule'): helper.capsule()

    def test_existing_wrong_or_shared_namespace_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in [pathlib.Path(directory), pathlib.Path(directory) / 'wrong-name', pathlib.Path('/home/github-runner/.cargo/helper')]:
                with self.subTest(path=path), self.assertRaises(ValueError): helper.destination(path)

    def test_watchdog_targets_own_child_and_preserves_original_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / 'owned'; child = Mock(pid=77, returncode=-9)
            child.communicate.side_effect = [subprocess.TimeoutExpired('own-helper-child', 60), (b'partial', b'original failure')]
            with patch.object(helper, 'destination', return_value=root), patch.object(helper.shutil, 'disk_usage', return_value=type('Space', (), {'free': 16 * 1024**2})()), patch.object(helper.subprocess, 'Popen', return_value=child):
                result = helper.launch(root)
            child.kill.assert_called_once_with()
            self.assertTrue(result['watchdogExpired'])
            self.assertEqual((root / 'child.stderr').read_bytes(), b'original failure')

    def test_first_unavailable_stops_without_retry_or_helper_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); kit = helper.module()
            owner = {'parentPid': 123, 'scriptSha256': kit.sha((HERE / 'acquire-fuse-helper.py').read_bytes()),
                     'downloadModuleSha256': kit.sha((HERE / 'acquire-locked-sources.py').read_bytes())}
            (root / 'OWNER.json').write_text(json.dumps(owner))
            kit.download = Mock(side_effect=ValueError('controlled unavailable'))
            with patch.object(helper, 'module', return_value=kit), patch.object(helper.os, 'getppid', return_value=123), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(helper.worker(root), 1)
            kit.download.assert_called_once()
            result = json.loads((root / 'acquisition-receipt.json').read_bytes())
            self.assertEqual(result['automaticRetries'], 0)
            self.assertFalse(result['helperExecuted'])
            self.assertFalse(result['hostInstalled'])


if __name__ == '__main__': unittest.main()
