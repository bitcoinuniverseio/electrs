"""Controlled local source/contract checks, never spawns a unit or child."""
import contextlib
import importlib.util
import io
import pathlib
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


proof = load('proof', 'sandbox-proof.py')
child = load('probe_child', 'sandbox-proof-child.py')


class ProofTests(unittest.TestCase):
    def expected(self):
        return {'unit': 'universe-electrs-sandbox-probe-380-1-aaaaaaaaaaaaaaaa.service',
                'parentNetNamespace': 'net:[1]', 'parentUserNamespace': 'user:[1]', 'parentCgroup': '/runner'}

    def valid_child(self):
        expected = self.expected()
        return {'netNamespace': 'net:[2]', 'userNamespace': 'user:[2]',
                'cgroup': '/owned/' + expected['unit'], 'cpuMax': '100000 100000',
                'memoryMax': '67108864', 'pidsMax': '16', 'ioWeight': 'default 1', 'nice': 19,
                'interfaces': ['lo'], 'ipv4Routes': [], 'readOnlyControlWriteErrno': 30}

    def test_actual_child_contract_positive(self):
        child.validate(self.valid_child(), self.expected())

    def test_missing_isolation_or_limits_fail_closed(self):
        for key, value in [('netNamespace', 'net:[1]'), ('userNamespace', 'user:[1]'),
                           ('cgroup', '/runner'), ('cpuMax', 'max 100000'),
                           ('memoryMax', 'max'), ('pidsMax', 'max'), ('ioWeight', 'default 100'),
                           ('nice', 0), ('interfaces', ['lo', 'eth0']),
                           ('ipv4Routes', ['eth0 00000000 0100007F']), ('readOnlyControlWriteErrno', 13)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                child.validate({**self.valid_child(), key: value}, self.expected())

    def test_unit_name_cannot_address_existing_or_foreign_unit(self):
        self.assertIn('380-1-aaaaaaaaaaaaaaaa', proof.unit_name('380', '1', 'a' * 16))
        for args in [('universe-bitcoin', '1', 'a' * 16), ('380', '../bad', 'a' * 16),
                     ('380', '1', 'bad.service'), ('1' * 100, '1', 'a' * 16)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                proof.unit_name(*args)

    def test_tool_drift_prevents_unit(self):
        with patch.object(proof.metadata, 'file_pin', return_value={'path': '/usr/bin/systemd-run', 'sha256': 'bad'}), \
                patch.object(proof.subprocess, 'Popen') as spawn:
            with self.assertRaises(ValueError):
                proof.pinned_tool(proof.RUN_TOOL)
            spawn.assert_not_called()

    def properties(self):
        private = pathlib.Path('/owned/private')
        value = {'ActiveState': 'active', 'SubState': 'running', 'RuntimeMaxUSec': '15s',
                 'TimeoutStopUSec': '5s', 'CPUQuotaPerSecUSec': '1s', 'MemoryMax': '67108864',
                 'TasksMax': '16', 'IOWeight': '1', 'Nice': '19', 'ProtectSystem': 'strict',
                 'ReadWritePaths': str(private), 'PrivateNetwork': 'yes', 'PrivateUsers': 'yes',
                 'NoNewPrivileges': 'yes', 'KillMode': 'control-group', 'MainPID': '123',
                 'ControlGroup': '/owned/' + self.expected()['unit']}
        return private, value

    def test_parent_actual_unit_property_contract(self):
        private, value = self.properties()
        proof.validate_properties(value, self.expected()['unit'], private)
        for field, wrong in [('RuntimeMaxUSec', 'infinity'), ('MemoryMax', 'max'),
                              ('ProtectSystem', 'no'), ('PrivateUsers', 'no'), ('ReadWritePaths', '/'),
                              ('MainPID', '0')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                proof.validate_properties({**value, field: wrong}, self.expected()['unit'], private)

    def test_default_does_not_spawn_or_collect_metadata(self):
        with patch('sys.argv', ['sandbox-proof.py']), \
                patch.object(proof.metadata, 'collect', side_effect=AssertionError('no metadata')), \
                patch.object(proof.subprocess, 'Popen', side_effect=AssertionError('no unit')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            proof.main()
        self.assertIn('"unitCreated": false', output.getvalue())

    def test_source_child_uses_only_stdlib_and_no_socket_or_cargo_call(self):
        raw = (HERE / 'sandbox-proof-child.py').read_text()
        self.assertNotIn('import socket', raw)
        self.assertNotIn('import subprocess', raw)
        self.assertNotIn('urllib', raw)
        self.assertIn('errno.EROFS', raw)
        parent = (HERE / 'sandbox-proof.py').read_text()
        self.assertIn("'-B', '-I', '-S'", parent)
        self.assertNotIn('sudo', parent)
        self.assertNotIn('cargo ', parent)


if __name__ == '__main__':
    unittest.main()
