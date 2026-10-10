"""Pure larger storage/resource guards; no mount, scope, tool or Cargo action."""
import importlib.util
import pathlib
import unittest
import tempfile
import re
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('full_scope', pathlib.Path(__file__).with_name('full-cargo-scope.py'))
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class Controls(unittest.TestCase):
    def tools(self):
        primary = module.load('test_primary', 'confined-build-plan.py').TOOL_PINS
        leaves = {path: {'sha256': sha, 'executable': role != 'libclang'} for role, (path, sha) in primary.items()}
        ar = '/usr/bin/x86_64-linux-gnu-ar'; leaves[ar] = {'sha256': 'a' * 64, 'executable': True}
        context = {'cargoPath': primary['cargo'][0], 'toolAliases': {'ar': ar, 'cc': primary['cc'][0]},
                   'compilerEnvironment': {'RUSTC': primary['rustc'][0], 'CC': primary['cc'][0], 'CXX': primary['cxx'][0],
                     'AR': ar, 'LIBCLANG_PATH': '/usr/lib/x86_64-linux-gnu', 'LD_LIBRARY_PATH': '/usr/lib/x86_64-linux-gnu'}}
        return context, leaves

    def test_closed_roles_positive_and_unknown_alias(self):
        context, leaves = self.tools(); self.assertTrue(module.validate_tool_roles(context, leaves))
        context['toolAliases']['unknown'] = '/usr/bin/installer'
        with self.assertRaisesRegex(ValueError, 'alias'): module.validate_tool_roles(context, leaves)

    def test_cargo_path_not_syntax_only(self):
        context, leaves = self.tools(); context['cargoPath'] = '/tmp/cargo'
        with self.assertRaisesRegex(ValueError, 'Cargo'): module.validate_tool_roles(context, leaves)

    def test_compiler_role_and_library_drift(self):
        context, leaves = self.tools(); context['compilerEnvironment']['RUSTC'] = '/tmp/rustc'
        with self.assertRaisesRegex(ValueError, 'role'): module.validate_tool_roles(context, leaves)
        context, leaves = self.tools(); context['compilerEnvironment']['LD_LIBRARY_PATH'] += ':/home/github-runner'
        with self.assertRaisesRegex(ValueError, 'library'): module.validate_tool_roles(context, leaves)

    def test_real_wrapper_exclusive_logs_not_precreated(self):
        source = pathlib.Path(__file__).with_name('confined-cargo.c').read_text()
        actual_logs = re.findall(r'open\("(cargo\.(?:stdout|stderr))", O_CREAT \| O_EXCL', source)
        self.assertEqual(set(actual_logs), {'cargo.stdout', 'cargo.stderr'})
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for path in module.setup_log_paths(root):
                with path.open('xb') as out: out.write(b'setup')
            for name in actual_logs:
                with (root / name).open('xb') as out: out.write(b'wrapper created exclusively')
            self.assertEqual(len(list(root.iterdir())), 4)

    def test_hash_detects_append_and_nonblocking_nofollow(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'data'; path.write_bytes(b'original')
            calls = 0; actual_open = module.os.open; flags_seen = []
            def opened(path, flags):
                flags_seen.append(flags); return actual_open(path, flags)
            def clock():
                nonlocal calls
                calls += 1
                if calls == 3:
                    with path.open('ab') as output: output.write(b'appended')
                return 1
            with patch.object(module.time, 'monotonic', side_effect=clock), patch.object(module.os, 'open', side_effect=opened), \
                 patch.object(module.os, 'fstat', side_effect=lambda _: path.lstat()):
                with self.assertRaisesRegex(ValueError, 'appended'): module.file_hash(path)
            self.assertEqual(flags_seen[0] & getattr(module.os, 'O_NOFOLLOW', 0), getattr(module.os, 'O_NOFOLLOW', 0))
            self.assertEqual(flags_seen[0] & getattr(module.os, 'O_NONBLOCK', 0), getattr(module.os, 'O_NONBLOCK', 0))

    def test_hash_bound_rejects_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'data'; path.write_bytes(b'too large')
            with patch.object(module.os, 'open', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError): module.file_hash(path, maximum_bytes=1)

    def test_parent_headroom_rejection_never_creates_unit(self):
        guard = SimpleNamespace(runtime_guard=lambda: 'a' * 40, source_guard=lambda *_: None,
            headroom_report=lambda _: {'memoryKiB': {'MemAvailable': 4 * 1024**2}, 'freeTempBytes': 10 * 1024**3})
        def loaded(_, file):
            if file == 'locked-cache-readonly.py': return guard
            if file == 'locked-source-inventory.py': return SimpleNamespace()
            if file == 'confinement-proof.py': return SimpleNamespace(headroom=lambda _: None)
            raise AssertionError('headroom rejected before unit/tool calls')
        with patch.object(module, 'load', side_effect=loaded), patch.object(module, 'admission', side_effect=AssertionError('pressure must be checked before expensive hashes')) as admission, \
             patch.dict(module.os.environ, {'RUNNER_TEMP': '/owned/temp'}), \
             patch.object(module.subprocess, 'Popen', side_effect=AssertionError('no unit permitted')):
            with self.assertRaisesRegex(ValueError, 'headroom'):
                module.launch(pathlib.Path('/owned'), {'sourceSha': 'a' * 40}, 'b' * 64)
            admission.assert_not_called()

    def test_boolean_does_not_replace_actual_small_receipt(self):
        root = pathlib.Path('/owned')
        context = {key: '/owned/' + key for key in ['smallProofReceipt', 'wrapperProofReceipt', 'sourceManifest', 'vendorManifest']}
        for key in ['smallProofReceiptSha256', 'wrapperProofReceiptSha256', 'sourceManifestSha256', 'vendorManifestSha256']: context[key] = 'a' * 64
        with patch.object(module, 'context_check', return_value={}), patch.object(module, 'under', side_effect=lambda path, _: pathlib.Path(path)), \
             patch.object(module, 'read_json', return_value={'actualSmall8MiBCapacityQualified': True}), \
             patch.object(module.subprocess, 'Popen', side_effect=AssertionError('no unit permitted')):
            with self.assertRaisesRegex(ValueError, 'actual successful small'): module.admission(context, root)

    def test_wrong_uid_task_directory_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with patch.object(pathlib.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)):
                with self.assertRaisesRegex(ValueError, 'UID1001'): module.root_identity(root)

    def test_requested_libclang_alias_resolves_to_pinned_leaf(self):
        context, leaves = self.tools()
        primary = module.load('alias_primary', 'confined-build-plan.py').TOOL_PINS
        roles = {role: {'requestedPath': path, 'resolvedPath': path, 'sha256': sha} for role, (path, sha) in primary.items()}
        requested = primary['libclang'][0]; resolved = '/usr/lib/llvm-18/lib/libclang-18.so.1'
        leaves[resolved] = leaves.pop(requested); roles['libclang']['resolvedPath'] = resolved
        context['compilerEnvironment']['LIBCLANG_PATH'] = '/usr/lib/llvm-18/lib'
        context['compilerEnvironment']['LD_LIBRARY_PATH'] = '/usr/lib/llvm-18/lib'
        self.assertTrue(module.validate_tool_roles(context, leaves, roles))
        roles['libclang']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): module.validate_tool_roles(context, leaves, roles)

    def test_cleanup_observation_error_does_not_skip_daemon_settlement(self):
        calls = []
        daemon = SimpleNamespace(wait=lambda **_: calls.append('wait') or 0)
        small = SimpleNamespace(read_mount=lambda _: (_ for _ in ()).throw(OSError('controlled')),
                                same_mount=lambda *_: False)
        logs, errors = module.settle_owned(pathlib.Path('/owned'), pathlib.Path('/owned/work'), daemon, None, small)
        self.assertEqual(calls, ['wait']); self.assertEqual(logs, [])
        self.assertTrue(any('mount observation' in value for value in errors))

    def test_unknown_mount_not_unmounted_but_own_child_settles(self):
        calls = []
        small = SimpleNamespace(read_mount=lambda _: {'id': 99}, same_mount=lambda *_: False,
            run_known=lambda *_: calls.append('unmount'))
        daemon = SimpleNamespace(wait=lambda **_: calls.append('wait') or 0)
        _, errors = module.settle_owned(pathlib.Path('/owned'), pathlib.Path('/owned/work'), daemon, {'id': 1}, small)
        self.assertEqual(calls, ['wait']); self.assertIn('unknown mount retained; no unmount', errors)

    def test_unchanged_hash_is_reused_then_change_is_rehashed(self):
        module.VERIFIED_FENCES.clear()
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'input'; path.write_bytes(b'first')
            with patch.object(module.os, 'fstat', side_effect=lambda _: path.lstat()): original = module.file_hash(path)
            with patch.object(module.os, 'open', side_effect=AssertionError('unchanged input must not be rehashed')):
                self.assertEqual(module.file_hash(path), original)
            path.write_bytes(b'second changed')
            with patch.object(module.os, 'fstat', side_effect=lambda _: path.lstat()): self.assertNotEqual(module.file_hash(path), original)
        module.VERIFIED_FENCES.clear()

    def test_worker_fences_no_rehash_and_detect_change(self):
        module.VERIFIED_FENCES.clear()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary); source = root / 'source'; source.mkdir(); vendor = root / 'vendor'; vendor.mkdir()
            context = {'sourceRoot': str(source), 'vendorRoot': str(vendor), 'controllerSha256': 'a' * 64}
            for key in ['wrapperBinary', 'readRootsFile', 'toolClosureFile']:
                path = root / key; path.write_bytes(b'fixture'); context[key] = str(path)
                with patch.object(module.os, 'fstat', side_effect=lambda _, path=path: path.lstat()): module.file_hash(path)
            lock = source / 'Cargo.lock'; lock.write_bytes(b'locked')
            with patch.object(module.os, 'fstat', side_effect=lambda _: lock.lstat()): module.file_hash(lock)
            module.remember_directory(source); module.remember_directory(vendor)
            receipt = {'schema': 'universe-electrs-full-cargo-admission-v1', 'contextSha256': 'b' * 64,
                       'controllerSha256': 'a' * 64, 'fences': list(module.VERIFIED_FENCES.values())}
            with patch.object(module.os, 'open', side_effect=AssertionError('worker must use metadata fences, not repeated file reads')):
                self.assertFalse(module.verify_fences(receipt, context, 'b' * 64)['rehashRepeated'])
            lock.write_bytes(b'changed material')
            with self.assertRaisesRegex(ValueError, 'changed after parent'): module.verify_fences(receipt, context, 'b' * 64)
        module.VERIFIED_FENCES.clear()
    def test_exact_daemon_limit_required(self):
        value = module.IMAGE_BYTES
        self.assertEqual(module.daemon_file_limit('Max file size             %d %d bytes\n' % (value, value)), value)
        for raw in ['Max file size unlimited unlimited bytes', 'Max file size 8589934592 9999999999 bytes', '']:
            with self.assertRaises(ValueError): module.daemon_file_limit(raw)

    def test_filesystem_capacity_is_aggregate_not_single_file(self):
        with patch.object(module.os, 'statvfs', return_value=SimpleNamespace(f_blocks=2097152, f_frsize=4096, f_bavail=2000000), create=True):
            self.assertEqual(module.filesystem_check('/owned')['capacityBytes'], module.IMAGE_BYTES)
        with patch.object(module.os, 'statvfs', return_value=SimpleNamespace(f_blocks=2097153, f_frsize=4096, f_bavail=2000000), create=True):
            with self.assertRaises(ValueError): module.filesystem_check('/owned')

    def test_path_escape_rejected(self):
        for path in ['/other/file', '/owned/../escape', '/owned']:
            with self.assertRaises(ValueError): module.under(path, pathlib.Path('/owned'))

    def test_premerge_vendor_rejected_before_any_tool(self):
        root = pathlib.PurePosixPath('/opt/github-runners/runner-27/_work/_temp/universe-electrs-build-123-1-' + 'a' * 16)
        context = {'schema': 'universe-electrs-full-cargo-worker-v1', 'sourceSha': 'a' * 40,
                   'cargoLockSha256': 'b' * 64, 'vendorLockSha256': 'c' * 64, 'profile': 'unchanged-default', 'operation': 'test'}
        for key in ['sourceRoot', 'vendorRoot', 'wrapperBinary', 'readRootsFile', 'packageRoot']: context[key] = str(root / key)
        with patch.object(module, 'under', side_effect=lambda path, _: pathlib.PurePosixPath(path)):
            with self.assertRaisesRegex(ValueError, 'premerge'): module.context_check(context, root)


if __name__ == '__main__': unittest.main()
