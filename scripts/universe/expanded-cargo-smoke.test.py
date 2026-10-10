"""Controlled literal/guard tests; no Cargo/compiler/unit execution."""
import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('smoke', pathlib.Path(__file__).with_name('expanded-cargo-smoke.py'))
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class Controls(unittest.TestCase):
    def test_literal_zero_dependency_project_contains_actual_canaries(self):
        path = '/opt/github-runners/runner-27/_work/_temp/universe-electrs-cargo-smoke-123-1-' + 'a' * 16 + '/source/outside-canary'
        files = module.project_bytes(path)
        self.assertEqual(set(files), {'Cargo.toml', 'Cargo.lock', 'build.rs', 'src/lib.rs'})
        self.assertIn(b'[dependencies]\n[profile.dev]', files['Cargo.toml'])
        self.assertEqual(files['Cargo.lock'].count(b'[[package]]'), 1)
        build = files['build.rs'].decode()
        for snippet in ['fcntl(100,1)', 'socket(domain,1,0)', 'syscall(425,1i32,0usize)', 'outside denial must be EACCES', 'private-canary']:
            self.assertIn(snippet, build)
        self.assertNotIn('__OUTSIDE__', build); self.assertIn(path, build)

    def test_unknown_outside_path_not_generated(self):
        for path in ['/etc/passwd', '/home/github-runner/.ssh/id_ed25519', '/tmp/outside-canary']:
            with self.assertRaises(ValueError): module.project_bytes(path)

    def test_pressure_rejection_precedes_tool_hash_or_mkdir(self):
        guard = SimpleNamespace(runtime_guard=lambda: 'a' * 40, source_guard=lambda *_: None, headroom_report=lambda _: {'observed': True})
        full = SimpleNamespace(read_json=lambda *_: (_ for _ in ()).throw(AssertionError('must not hash closure')))
        pressure = SimpleNamespace(headroom=lambda _: (_ for _ in ()).throw(ValueError('actual pressure')))
        def loaded(_, file):
            return {'full-cargo-scope.py': full, 'locked-cache-readonly.py': guard, 'locked-source-inventory.py': SimpleNamespace(), 'confinement-proof.py': pressure}[file]
        with patch.object(module, 'load', side_effect=loaded), patch.dict(module.os.environ, {'RUNNER_TEMP': '/owned/temp'}), \
             patch.object(pathlib.Path, 'mkdir', side_effect=AssertionError('must not create task')), \
             patch.object(module.subprocess, 'Popen', side_effect=AssertionError('must not launch unit')):
            with self.assertRaisesRegex(ValueError, 'actual pressure'): module.launch(pathlib.Path('/owned/closure'), 'b' * 64)


if __name__ == '__main__': unittest.main()
