"""Pure safe storage metadata controls. No sudo/device/mount/native invocation."""
import importlib.util
import json
import pathlib
import subprocess
import unittest
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('storage', HERE / 'storage-enforcement-metadata.py')
storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)


class StorageTests(unittest.TestCase):
    def test_default_no_metadata_or_action(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'storage-enforcement-metadata.py')], check=True, capture_output=True)
        self.assertEqual(json.loads(result.stdout), {'preparedOnly': True, 'metadataRead': False, 'mounted': False})

    def test_closest_temp_mount_only_no_source_or_secret_options(self):
        raw = ('1 0 8:1 / / rw,relatime - ext4 /dev/host-secret rw,credentials=/secret\n'
               '2 1 0:1 / /opt/github-runners rw,nosuid,nodev - tmpfs private-token size=8G,nr_inodes=200000,password=hidden\n')
        result = storage.mount_for(raw, '/opt/github-runners/runner-10/_work/_temp')
        self.assertEqual(result['mountId'], 2)
        self.assertEqual(result['filesystem'], 'tmpfs')
        self.assertIn('size=8G', result['allowlistedOptions'])
        self.assertNotIn('secret', json.dumps(result))
        self.assertNotIn('hidden', json.dumps(result))
        self.assertNotIn('private-token', json.dumps(result))

    def test_mount_malformed_ambiguous_or_missing_fails_closed(self):
        for raw in ['garbage', '1 0 0:1 / /other rw - ext4 /dev/a rw',
                    '1 0 0:1 / / rw - ext4 /dev/a rw\n2 0 0:2 / / rw - ext4 /dev/b rw']:
            with self.subTest(raw=raw), self.assertRaises(ValueError): storage.mount_for(raw, '/tmp')

    def test_effective_self_caps_only(self):
        value = storage.capability_flags('Name:\tpython\nCapEff:\t0000000000200000\nCapPrm:\tffffffffffffffff\n')
        self.assertTrue(value['CAP_SYS_ADMIN'])
        self.assertFalse(value['CAP_SYS_RESOURCE'])
        for raw in ['', 'CapEff:\tbad-value', 'CapEff:\t0\nCapEff:\t1']:
            with self.subTest(raw=raw), self.assertRaises(ValueError): storage.capability_flags(raw)

    def test_sudo_policy_sanitized_never_approves_execution(self):
        raw = b'Matching Defaults entries: secret=DO_NOT_EXPOSE\n    (ALL : ALL) NOPASSWD: ALL\n    (root) NOPASSWD: /usr/sbin/losetup --specific-private-argument\n'
        result = storage.sudo_summary(raw, 0)
        self.assertTrue(result['unrestrictedAllRuleMentioned'])
        self.assertTrue(result['unrestrictedNopasswdRuleMentioned'])
        self.assertEqual(result['literalStorageCommandMentions'], ['losetup'])
        self.assertFalse(result['privilegedStorageAdmissionQualified'])
        self.assertNotIn('DO_NOT_EXPOSE', json.dumps(result))
        self.assertNotIn('specific-private', json.dumps(result))

    def test_denied_or_oversized_sudo_does_not_leak_output(self):
        result = storage.sudo_summary(b'password or restricted policy', 1)
        self.assertFalse(result['nonInteractiveListingSucceeded'])
        self.assertFalse(result['credentialsRequested'])
        self.assertNotIn('password', json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'output bound'): storage.sudo_summary(b'x' * 32769, 0)

    def test_only_sudo_noninteractive_list_command_and_clean_env(self):
        tool = {'requestedPath': '/usr/bin/sudo', 'path': '/usr/bin/sudo', 'sha256': 'a' * 64, 'present': True, 'executableByRunner': True}
        result = Mock(returncode=0, stdout=b'    (root) NOPASSWD: ALL\n', stderr=b'')
        with patch.object(storage.subprocess, 'run', return_value=result) as run, patch.object(storage, 'tool_metadata', return_value=tool):
            value = storage.sudo_metadata([tool])
        self.assertEqual(run.call_args.args[0], ['/usr/bin/sudo', '-n', '-l'])
        self.assertEqual(set(run.call_args.kwargs['env']), {'PATH', 'LANG', 'HOME'})
        self.assertFalse(value['policyCommandsExecuted'])

    def test_missing_sudo_and_timeout_are_metadata_unqualified(self):
        tool = {'requestedPath': '/usr/bin/sudo', 'present': False}
        with patch.object(storage.subprocess, 'run', side_effect=AssertionError('never invoke')):
            self.assertFalse(storage.sudo_metadata([tool])['listingAttempted'])
        tool.update(present=True, executableByRunner=True, path='/usr/bin/sudo')
        with patch.object(storage.subprocess, 'run', side_effect=subprocess.TimeoutExpired('sudo-list-only', 3)):
            self.assertTrue(storage.sudo_metadata([tool])['timedOut'])


if __name__ == '__main__': unittest.main()
