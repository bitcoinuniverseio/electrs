"""Read-only source controls, no journal/units/host probes executed."""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('diagnostic', HERE / 'sandbox-diagnostic.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DiagnosticTests(unittest.TestCase):
    def test_only_exact_previous_run_attempt_owned_unit(self):
        self.assertTrue(d.owned_unit(d.PREFIX + 'a' * 16 + '.service'))
        for unit in ['universe-bitcoin-signet.service', d.PREFIX + 'a' * 15 + '.service',
                     d.PREFIX.replace('38017693834', '38017693835') + 'a' * 16 + '.service']:
            self.assertFalse(d.owned_unit(unit))

    def test_exact_known_files_source_and_bounded_raw(self):
        with tempfile.TemporaryDirectory(prefix='scope-diag-test-') as tmp:
            base = pathlib.Path(tmp)
            folder = base / (d.PREFIX + 'a' * 16)
            folder.mkdir()
            (folder / 'unit.stderr').write_text('controlled original permission failure')
            record = {'sourceSha': d.OLD_SOURCE, 'unit': folder.name + '.service'}
            (folder / 'failure.json').write_text(json.dumps(record))
            (folder / 'not-allowlisted').write_text('must not be read')
            with patch.object(d, 'PREVIOUS', base), patch.object(d.os, 'getuid', return_value=folder.stat().st_uid, create=True):
                result = d.read_known_folder(folder)
                self.assertEqual([value['file'] for value in result['files']], ['unit.stderr', 'failure.json'])
                (folder / 'unit.stderr').write_bytes(b'x' * (d.MAX_BYTES + 1))
                with self.assertRaises(ValueError):
                    d.read_known_folder(folder)

    def test_wrong_source_in_owned_receipt_rejects(self):
        with tempfile.TemporaryDirectory(prefix='scope-diag-test-') as tmp:
            base = pathlib.Path(tmp)
            folder = base / (d.PREFIX + 'a' * 16)
            folder.mkdir()
            (folder / 'failure.json').write_text(json.dumps({'sourceSha': 'wrong', 'unit': folder.name + '.service'}))
            with patch.object(d, 'PREVIOUS', base), patch.object(d.os, 'getuid', return_value=folder.stat().st_uid, create=True), self.assertRaises(ValueError):
                d.read_known_folder(folder)

    def test_journal_filters_other_units_and_preserves_own_manager_message(self):
        raw = '\n'.join(json.dumps(value) for value in [
            {'_SYSTEMD_USER_UNIT': 'other.service', 'MESSAGE': 'must not output'},
            {'_SYSTEMD_USER_UNIT': 'user@1001.service', 'USER_UNIT': d.PREFIX + 'a' * 16 + '.service',
             'MESSAGE': 'controlled original failure', '__REALTIME_TIMESTAMP': '1791599908000000'}]).encode()
        result = d.filtered_journal(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['message'], 'controlled original failure')

    def test_raw_secret_and_oversized_journal_withheld(self):
        with self.assertRaises(ValueError):
            d.secret_free(b'ghp_' + b'x' * 30)
        with self.assertRaises(ValueError):
            d.filtered_journal(b'x' * (d.MAX_BYTES + 1))

    def test_default_no_source_files_journal_or_subprocess(self):
        with patch('sys.argv', ['sandbox-diagnostic.py']), patch.object(d, 'recover', side_effect=AssertionError('no reads')), \
                patch.object(d.subprocess, 'Popen', side_effect=AssertionError('no command')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            d.main()
        self.assertIn('"preparedOnly": true', output.getvalue())

    def test_workflow_recovery_only_never_proof_retry(self):
        raw = (HERE.parents[1] / '.github/workflows/universe-native-preflight.yml').read_text()
        self.assertIn('sandbox-diagnostic.py --recover-only', raw)
        self.assertNotIn('--run-proof', raw)
        self.assertNotIn('/usr/bin/python3 scripts/universe/native-preflight.py', raw)
        self.assertNotIn('sudo', raw)


if __name__ == '__main__':
    unittest.main()
