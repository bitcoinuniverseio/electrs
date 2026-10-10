"""Controlled controller guards only. No unit/device/format/mount operation."""
import errno
import hashlib
import json
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('proof', HERE / 'small-fuse-image-proof.py')
proof = importlib.util.module_from_spec(spec); spec.loader.exec_module(proof)


class ProofTests(unittest.TestCase):
    def test_default_no_mount(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'small-fuse-image-proof.py')], check=True, capture_output=True)
        self.assertIn(b'"deviceOpened": false', result.stdout)
        self.assertIn(b'"mounted": false', result.stdout)

    def test_actual_capacity_not_per_file_or_directory_measurement(self):
        good = type('Stat', (), {'f_blocks': 8192, 'f_frsize': 1024})()
        self.assertEqual(proof.capacity(good, proof.IMAGE_BYTES), proof.IMAGE_BYTES)
        for size, blocks in [(proof.IMAGE_BYTES + 1, 8192), (proof.IMAGE_BYTES, 8193), (proof.IMAGE_BYTES, 0)]:
            with self.subTest(size=size, blocks=blocks), self.assertRaises(ValueError):
                proof.capacity(type('Stat', (), {'f_blocks': blocks, 'f_frsize': 1024})(), size)

    def test_mount_only_exact_path_and_combined_allow_other_flags(self):
        raw = '1 0 0:1 / / rw - ext4 /dev/source rw\n2 1 0:2 / /own/mount rw,nosuid - fuse.universe-electrs-proof /own/image rw,user_id=1001,allow_other\n'
        value = proof.mount_record(raw, pathlib.PurePosixPath('/own/mount'))
        self.assertEqual(value['id'], 2); self.assertIn('allow_other', value['options'])
        self.assertIsNone(proof.mount_record(raw, pathlib.PurePosixPath('/other')))
        with self.assertRaises(ValueError): proof.mount_record(raw + raw.splitlines()[1] + '\n', pathlib.PurePosixPath('/own/mount'))

    def test_wrong_or_native_helper_data_namespace_rejected(self):
        for path in ['/opt/universe-native/current', '/home/github-runner/.cargo/helper', '/tmp/other']:
            with self.subTest(path=path), self.assertRaises(ValueError): proof.owned_package_root(pathlib.Path(path), pathlib.Path('/runner/temp'))

    def test_write_errno_must_be_real_enospc_not_eio(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(pathlib.Path, 'open', side_effect=OSError(errno.EIO, 'controlled EIO')):
                with self.assertRaises(OSError): proof.write_until_full(pathlib.Path(folder))

    def test_controlled_short_write_then_enospc_preserves_partial_readback(self):
        original = pathlib.Path.open; available = [2 * 1024**2 + 512 * 1024]
        class LimitedWriter:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def write(self, data):
                if available[0] == 0: raise OSError(errno.ENOSPC, 'controlled aggregate fixture')
                count = min(len(data), available[0]); available[0] -= count
                return self.stream.write(data[:count])
        def opening(path, mode='r', *args, **kwargs):
            stream = original(path, mode, *args, **kwargs)
            return LimitedWriter(stream) if mode == 'xb' else stream
        with tempfile.TemporaryDirectory() as folder, patch.object(pathlib.Path, 'open', side_effect=opening, autospec=True):
            result = proof.write_until_full(pathlib.Path(folder))
        self.assertTrue(result['realEnospc'])  # Controlled errno, NOT real filesystem proof.
        self.assertEqual(result['completeCommittedBytes'], 2 * 1024**2)
        self.assertEqual(result['observedFilesBytes'], 2 * 1024**2 + 512 * 1024)
        self.assertTrue(result['files'][-1]['partialOnEnospc'])
        self.assertLessEqual(result['writeOperations'], 16)
        available[0] = 2 * 1024**2 + 512 * 1024
        with tempfile.TemporaryDirectory() as folder, patch.object(pathlib.Path, 'open', side_effect=opening, autospec=True), patch.object(proof, 'IMAGE_BYTES', 2 * 1024**2):
            with self.assertRaisesRegex(ValueError, 'including partial'):
                proof.write_until_full(pathlib.Path(folder))

    def test_mount_cleanup_identity_checks_more_than_reused_id(self):
        left = {'id': 5, 'path': '/own/mount', 'filesystem': 'fuse.universe-electrs-proof', 'source': '/own/image'}
        self.assertTrue(proof.same_mount(left, dict(left)))
        right = dict(left); right['source'] = '/other/image'
        self.assertFalse(proof.same_mount(left, right))

    def test_mount_flags_source_and_type_must_validate_before_capture(self):
        mountpoint = pathlib.PurePosixPath('/own/mount'); image = pathlib.PurePosixPath('/own/image')
        valid = {'id': 5, 'path': str(mountpoint), 'filesystem': 'fuse.universe-electrs-proof', 'source': str(image), 'options': 'rw,nosuid,nodev'}
        self.assertEqual(proof.validate_owned_mount(valid, image, mountpoint), valid)
        for change in [{'source': '/foreign/image'}, {'filesystem': 'ext4'}, {'options': 'rw,nodev'}, {'options': 'rw,nosuid,nodev,allow_other'}]:
            candidate = {**valid, **change}; captured = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                proof.validate_owned_mount(candidate, image, mountpoint)
                captured = candidate
            self.assertIsNone(captured)

    def test_actual_worker_never_unmounts_rejected_unknown_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            ctx = {'sourceSha256': hashlib.sha256((HERE / 'small-fuse-image-proof.py').read_bytes()).hexdigest(), 'uid': 1001,
                   'sourceSha': 'a' * 40, 'packageReport': {}, 'hostReport': {}, 'packageRoot': '/owned/data'}
            (root / 'context.json').write_text(json.dumps(ctx))
            binder = Mock(); binder.bind.return_value = {'executionGroups': {'fuse2fs': {}, 'mke2fsAndExistingMountHelper': {}}}
            daemon = Mock(); daemon.poll.return_value = None; daemon.wait.return_value = 0
            unknown = {'id': 7, 'path': str(root / 'mount'), 'filesystem': 'ext4', 'source': '/foreign', 'options': 'rw,nosuid,nodev'}
            with patch.object(proof, 'load', return_value=binder), patch.object(proof, 'resource_guard', return_value={}), patch.object(proof, 'pin'), patch.object(proof, 'stage_group', return_value=(root / 'lib', root / 'bin')), patch.object(proof, 'image_identity', return_value={'bytes': proof.IMAGE_BYTES}), patch.object(proof.os, 'getuid', create=True, return_value=1001), patch.object(proof, 'run_known') as commands, patch.object(proof.subprocess, 'Popen', return_value=daemon), patch.object(proof, 'read_mount', return_value=unknown):
                self.assertEqual(proof.worker(root), 1)
            self.assertFalse((root / 'owned-mount.json').exists())
            self.assertEqual(commands.call_count, 1)  # Format fixture only, NEVER unmount.
            receipt = json.loads((root / 'proof-receipt.json').read_bytes())
            self.assertIn('mount ownership changed', '\n'.join(receipt['cleanupErrors']))

    def test_daemon_credentials_all_ids_and_active_caps_zero(self):
        good = 'Uid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\n' + ''.join(name + ':\t0000000000000000\n' for name in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb'])
        self.assertEqual(proof.daemon_credentials(good, 1001, 1001)['Uid'], [1001] * 4)
        for bad in [good.replace('Uid:\t1001', 'Uid:\t0'), good.replace('CapAmb:\t0000000000000000', 'CapAmb:\t0000000000000001')]:
            with self.assertRaises(ValueError): proof.daemon_credentials(bad, 1001, 1001)

    def test_mapped_staged_leaf_exact_binding_and_fresh_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); known = root / 'known.so'; known.write_bytes(b'abc')
            bindings = {str(known): hashlib.sha256(b'abc').hexdigest()}
            proof.check_mapped_leaf(known, root, bindings)
            unknown = root / 'unknown.so'; unknown.write_bytes(b'abc')
            with self.assertRaisesRegex(ValueError, 'unqualified'): proof.check_mapped_leaf(unknown, root, bindings)
            known.write_bytes(b'def')
            with self.assertRaisesRegex(ValueError, 'changed'): proof.check_mapped_leaf(known, root, bindings)

    def test_daemon_same_cgroup_and_start_fences_reject_drift(self):
        status = 'Uid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\n' + ''.join(name + ':\t0\n' for name in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb'])
        guard = Mock()
        def read(path, *args):
            if str(path).endswith('/status'): return status
            if str(path).endswith('/cgroup'): return '0::/wrong.service'
            return '0000-0001 r-xp 0 0:0 1 /owned/lib/known.so'
        guard.bounded_read.side_effect = read
        with patch.object(proof, 'load', return_value=guard), patch.object(proof, 'daemon_start', return_value='123'):
            with self.assertRaisesRegex(ValueError, 'exact owned resource cgroup'):
                proof.own_daemon_maps(50, pathlib.Path('/owned'), {}, '/right.service', 1001, 1001)
        guard.bounded_read.side_effect = lambda path, *args: status if str(path).endswith('/status') else '0::/right.service' if str(path).endswith('/cgroup') else '0000-0001 r-xp 0 0:0 1 /owned/lib/known.so'
        with patch.object(proof, 'load', return_value=guard), patch.object(proof, 'daemon_start', side_effect=['123', '124']), patch.object(proof, 'check_mapped_leaf'):
            with self.assertRaisesRegex(ValueError, 'process start changed'):
                proof.own_daemon_maps(50, pathlib.Path('/owned'), {}, '/right.service', 1001, 1001)

    def test_actual_scope_properties_before_image_creation(self):
        root = pathlib.Path('/owned/universe-electrs-fuse-proof-1-1-0123456789abcdef')
        values = {'/proc/self/cgroup': '0::/user.slice/' + root.name + '.service', 'cpu.max': '100000 100000',
                  'memory.max': '134217728', 'pids.max': '16', 'io.weight': 'default 1', '/proc/self/status': 'NoNewPrivs:\t0\n'}
        reader = Mock(); reader.bounded_read.side_effect = lambda path, *args: values.get(str(path), values.get(pathlib.Path(path).name))
        with patch.object(proof, 'load', return_value=reader), patch.object(proof.os, 'getpriority', create=True, return_value=19), patch.object(proof.os, 'PRIO_PROCESS', create=True, new=0):
            self.assertEqual(proof.resource_guard(root)['memoryMax'], '134217728')
            values['pids.max'] = 'max'
            with self.assertRaisesRegex(ValueError, 'resource mismatch'): proof.resource_guard(root)
            values['pids.max'] = '16'; values['/proc/self/status'] = 'NoNewPrivs:\t1\n'
            with self.assertRaisesRegex(ValueError, 'existing setuid'): proof.resource_guard(root)

    def test_controller_has_no_automatic_retry_or_global_stop(self):
        source = (HERE / 'small-fuse-image-proof.py').read_text()
        self.assertIn("'--property=RuntimeMaxSec=30s'", source)
        self.assertIn("'--property=MemoryMax=128M'", source)
        self.assertIn("'--property=NoNewPrivileges=no'", source)
        self.assertNotIn('sudo', source)
        self.assertNotIn('killall', source)
        self.assertNotIn('losetup', source)
        self.assertIn("'actual8GiBBuildCapacityQualified': False", source)


if __name__ == '__main__': unittest.main()
