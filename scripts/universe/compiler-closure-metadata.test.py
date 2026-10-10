"""Pure bounds/diagnostic controls; no host tools or compiler execution."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('closure', HERE / 'compiler-closure-metadata.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class Controls(unittest.TestCase):
    def test_directory_entries_are_bounded_without_files(self):
        budget = module.Budget()
        with self.assertRaises(ValueError): budget.tick(100001)

    def test_elapsed_budget_applies_to_empty_directory(self):
        budget = module.Budget(); budget.started -= 91
        with self.assertRaises(ValueError): budget.tick(0)

    def test_total_hash_bytes_bounded(self):
        with self.assertRaises(ValueError): module.Budget().charge(2 * 1024**3 + 1)

    def test_unknown_resolved_leaf_rejected(self):
        self.assertFalse(module.allowed_leaf(pathlib.Path('/home/github-runner/.ssh/id_ed25519')))
        self.assertFalse(module.allowed_leaf(pathlib.Path('/tmp/ar')))

    def test_pressure_failure_retains_observation_and_never_hashes(self):
        resources = {'pressure': {'cpu': 'actual high pressure'}, 'freeTempBytes': 123}
        guard = SimpleNamespace(runtime_guard=lambda: 'a' * 40, source_guard=lambda *_: None,
                                headroom_report=lambda _: resources)
        pressure = SimpleNamespace(headroom=lambda _: (_ for _ in ()).throw(ValueError('pressure')))
        def loader(_, file):
            if file == 'locked-cache-readonly.py': return guard
            if file == 'locked-source-inventory.py': return SimpleNamespace()
            if file == 'confinement-proof.py': return pressure
            raise AssertionError('compiler hashing must remain withheld')
        with patch.object(module, 'load', side_effect=loader), patch.dict(module.os.environ, {'RUNNER_TEMP': '/owned/temp'}):
            result = module.collect({})
        self.assertIs(result['observedResources'], resources)
        self.assertFalse(result['smallProofHeadroomAvailable'])
        self.assertTrue(result['compilerClosureReadWithheld'])

    def test_directory_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with patch.object(module.os, 'walk', return_value=[(str(root), ['linked'], [])]), \
                 patch.object(pathlib.Path, 'is_symlink', lambda path: path.name == 'linked'):
                with self.assertRaises(ValueError): module.tree_pin(root, module.Budget())

    def test_cumulative_elf_bytes_rejects_before_open(self):
        budget = module.Budget(); budget.elf_bytes = 1024**3
        with self.assertRaises(ValueError): module.elf('/not/opened', None, budget, {'bytes': 1})

    def test_append_rejected_without_reading_unbounded_eof(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'leaf'; path.write_bytes(b'original')
            budget = module.Budget(); tick = budget.tick; calls = 0
            def append(entries=1):
                nonlocal calls
                calls += 1; tick(entries)
                if calls == 3:
                    with path.open('ab') as output: output.write(b'appended')
            with patch.object(module, 'allowed_leaf', return_value=True), patch.object(budget, 'tick', side_effect=append), \
                 patch.object(module.os, 'fstat', side_effect=lambda _: path.lstat()):
                with self.assertRaises(ValueError): module.pin_file(path, budget)

    def test_hash_open_uses_nonblocking_nofollow(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'leaf'; path.write_bytes(b'original')
            actual_open = module.os.open; observed = []
            def checked(path, flags):
                observed.append(flags); return actual_open(path, flags)
            with patch.object(module, 'allowed_leaf', return_value=True), patch.object(module.os, 'open', side_effect=checked), \
                 patch.object(module.os, 'fstat', side_effect=lambda _: path.lstat()):
                module.pin_file(path, module.Budget())
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0] & getattr(module.os, 'O_NONBLOCK', 0), getattr(module.os, 'O_NONBLOCK', 0))
            self.assertEqual(observed[0] & getattr(module.os, 'O_NOFOLLOW', 0), getattr(module.os, 'O_NOFOLLOW', 0))


if __name__ == '__main__': unittest.main()
