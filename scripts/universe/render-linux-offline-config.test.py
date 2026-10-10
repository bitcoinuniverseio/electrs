"""Pure path/config rendering tests, never Linux transfer/config writes/Cargo."""
import hashlib
import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('renderer', HERE / 'render-linux-offline-config.py')
renderer = importlib.util.module_from_spec(spec); spec.loader.exec_module(renderer)


class RendererTests(unittest.TestCase):
    def fixture(self):
        raw = json.dumps({'schema': 'universe-electrs-sealed-linux-vendor-v1', 'packageCount': 204,
                          'files': [{}] * 16390, 'lockSha256': renderer.LOCK_SHA}).encode()
        source = {'sourceCommit': 'a' * 40, 'status': 'DRAFT_SOURCE_ONLY_FULL_BUILD_UNQUALIFIED',
                  'files': [{'path': 'Cargo.lock', 'gitSha256': renderer.LOCK_SHA}]}
        return raw, source

    def test_fixed_linux_paths_and_no_config_write_or_admission(self):
        raw, source = self.fixture(); root = '/opt/github-runners/runner-10/_work/_temp/universe-electrs-build-123-1-0123456789abcdef'
        with patch.object(renderer, 'VENDOR_MANIFEST_SHA', hashlib.sha256(raw).hexdigest()): value = renderer.rendered(raw, root, source)
        self.assertEqual(value['targetRoot'], root + '/work/target')
        self.assertIn(root + '/vendor', value['configUtf8'])
        self.assertFalse(value['configWritten']); self.assertFalse(value['fullBuildQualified'])

    def test_manifest_drift_wrong_os_native_path_and_lock_fail(self):
        raw, source = self.fixture()
        with self.assertRaisesRegex(ValueError, 'sealed204'): renderer.rendered(raw, '/tmp', source)
        with patch.object(renderer, 'VENDOR_MANIFEST_SHA', hashlib.sha256(raw).hexdigest()):
            for root in ['C:/universe/audit', '/opt/universe-electrs/current', '/home/github-runner/.cargo']:
                with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'Linux task'): renderer.rendered(raw, root, source)
            source['files'][0]['gitSha256'] = 'b' * 64
            with self.assertRaisesRegex(ValueError, 'lock contradiction'):
                renderer.rendered(raw, '/opt/github-runners/runner-10/_work/_temp/universe-electrs-build-123-1-0123456789abcdef', source)


if __name__ == '__main__': unittest.main()
