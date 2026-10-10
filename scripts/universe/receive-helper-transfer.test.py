"""Pure local transfer parser controls; no Linux writes/uploads/helpers."""
import importlib.util
import json
import pathlib
import subprocess
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('receiver', HERE / 'receive-helper-transfer.py')
receiver = importlib.util.module_from_spec(spec); spec.loader.exec_module(receiver)


class ReceiverTests(unittest.TestCase):
    def test_default_never_receives_or_downloads(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'receive-helper-transfer.py')], check=True, capture_output=True)
        self.assertEqual(json.loads(result.stdout), {'preparedOnly': True, 'filesWritten': False, 'networkFetched': False})

    def test_unreviewed_bytes_rejected_before_parser(self):
        with self.assertRaisesRegex(ValueError, 'before parsing'): receiver.payloads(b'not a reviewed archive')


if __name__ == '__main__': unittest.main()
