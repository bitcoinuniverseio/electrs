"""Local prototype source controls only, never compiler/LL/seccomp/unit execution."""
import contextlib
import importlib.util
import io
import pathlib
import unittest
import tempfile
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('alternative', HERE / 'confinement-proof.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ConfinementSourceTests(unittest.TestCase):
    def report(self):
        return {'memoryKiB': {'MemAvailable': 1048576}, 'freeTempBytes': 1073741824,
                'pressure': {'cpu': 'some avg10=25.00 avg60=25.00 avg300=25.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0',
                             'io': 'some avg10=5.00 avg60=5.00 avg300=5.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0'}}

    def test_small_headroom_exact_boundary_is_not_full_build_admission(self):
        result = p.headroom(self.report())
        self.assertFalse(result['longBuildHeadroomQualified'])

    def test_missing_memory_disk_or_high_pressure_before_root_and_unit(self):
        for kind in ['memory', 'disk', 'cpu', 'io', 'unknown']:
            value = self.report()
            if kind == 'memory': value['memoryKiB']['MemAvailable'] -= 1
            elif kind == 'disk': value['freeTempBytes'] -= 1
            elif kind == 'unknown': value['pressure']['io'] = 'unknown'
            else: value['pressure'][kind] = 'some avg10=26.00 avg60=26.00 avg300=26.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0'
            with self.subTest(kind=kind), patch('sys.argv', ['confinement-proof.py', '--run-proof']), \
                    patch.object(p.scope.metadata, 'collect', return_value=value), \
                    patch.object(p.pathlib.Path, 'mkdir') as mkdir, \
                    patch.object(p.subprocess, 'Popen') as launch:
                with self.assertRaises(ValueError): p.main()
                mkdir.assert_not_called()
                launch.assert_not_called()

    def test_failure_cause_prioritized_bounded_and_original_files_retained(self):
        with tempfile.TemporaryDirectory(prefix='confinement-log-test-') as tmp:
            root = pathlib.Path(tmp); private = root / 'private'; private.mkdir()
            error = private / 'compile.stderr'; error.write_text('controlled exact compiler failure')
            (private / 'proof.stderr').write_bytes(b'x' * 40000)
            result = p.failure_output(root)
            self.assertEqual(result['ownFailureLogs'][0]['rawUtf8'], 'controlled exact compiler failure')
            self.assertTrue(result['ownFailureLogs'][1]['truncated'])
            self.assertTrue(result['originalFilesRetained'])
            self.assertEqual(error.read_text(), 'controlled exact compiler failure')
            import json
            self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode()), 32768)

    def test_default_no_unit_metadata_or_compile(self):
        with patch('sys.argv', ['confinement-proof.py']), patch.object(p.scope.metadata, 'collect', side_effect=AssertionError('no metadata')), \
                patch.object(p.subprocess, 'Popen', side_effect=AssertionError('no unit')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            p.main()
        self.assertIn('"compiled": false', output.getvalue())

    def test_actual_resource_contract_cannot_accept_unlimited_or_foreign_group(self):
        unit = 'owned.service'
        value = {'ActiveState': 'active', 'SubState': 'running', 'RuntimeMaxUSec': '15s',
                 'TimeoutStopUSec': '5s', 'CPUQuotaPerSecUSec': '1s', 'MemoryMax': '67108864',
                 'TasksMax': '16', 'IOWeight': '1', 'Nice': '19', 'NoNewPrivileges': 'yes',
                 'KillMode': 'control-group', 'MainPID': '123', 'ControlGroup': '/owned/' + unit}
        p.actual_properties(value, unit)
        for key, wrong in [('MemoryMax', 'max'), ('TasksMax', 'max'), ('NoNewPrivileges', 'no'),
                           ('ControlGroup', '/other.service'), ('MainPID', '0')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.actual_properties({**value, key: wrong}, unit)

    def test_prototype_c_filter_covers_all_socket_and_uring_families(self):
        code = (HERE / 'confinement-proof.c').read_text()
        for name in ['socket', 'socketpair', 'connect', 'bind', 'listen', 'accept', 'accept4', 'sendto',
                     'sendmsg', 'sendmmsg', 'recvfrom', 'recvmsg', 'recvmmsg', 'shutdown',
                     'getsockname', 'getpeername', 'setsockopt', 'getsockopt', 'io_uring_setup',
                     'io_uring_enter', 'io_uring_register', 'pidfd_getfd', 'ptrace']:
            self.assertIn('DENY(SYS_' + name + ')', code)
        self.assertIn('AUDIT_ARCH_X86_64', code)
        self.assertIn('0x40000000U', code)
        self.assertIn('CLOSE_RANGE_UNSHARE', code)
        self.assertIn('LANDLOCK_ACCESS_FS_TRUNCATE', code)
        self.assertIn('abi < 3', code)
        self.assertIn('DENY(SYS_rt_sigqueueinfo)', code)
        self.assertIn('DENY(SYS_rt_tgsigqueueinfo)', code)

    def test_success_receipt_distinguishes_tiny_compile_from_full_rust(self):
        code = (HERE / 'confinement-proof.py').read_text()
        self.assertIn("'compiledReceipt': compiled", code)
        self.assertIn("'readelfPin': readelf", code)
        self.assertIn("'compiledTinyControl': True", code)
        self.assertIn("'fullRustBuild': False", code)

    def test_compiler_static_no_dynamic_fallback_and_clean_child_env(self):
        code = (HERE / 'confinement-build-child.py').read_text()
        self.assertIn("'-static'", code)
        self.assertIn("b'INTERP'", code)
        self.assertIn("os.execve", code)
        self.assertNotIn('cargo ', code)
        self.assertNotIn('rustup', code)
        c = (HERE / 'confinement-proof.c').read_text()
        self.assertIn('clearenv()', c)
        self.assertIn('execve(self, args, clean)', c)

    def test_incomplete_pressure_cannot_admit_the_small_proof(self):
        for raw in ['some avg10=0 avg60=0 avg300=0 total=0',
                    'some avg10=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0',
                    'some avg10=0 avg60=0 avg300=0 total=0\nsome avg10=0 avg60=0 avg300=0 total=0']:
            value = self.report(); value['pressure']['io'] = raw
            with self.subTest(raw=raw), self.assertRaises(ValueError): p.headroom(value)

    def test_current_workflow_keeps_the_owned_gate_without_full_build(self):
        raw = (HERE.parents[1] / '.github/workflows/universe-native-preflight.yml').read_text()
        self.assertIn('locked-cache-readonly.py --observe-owned-cache', raw)
        self.assertNotIn('confinement-proof.py --run-proof', raw)
        self.assertIn("github.repository == 'bitcoinuniverseio/electrs'", raw)
        self.assertIn('timeout-minutes: 5', raw)
        self.assertNotIn('cargo build', raw)
        self.assertNotIn('sudo ', raw)


if __name__ == '__main__':
    unittest.main()
