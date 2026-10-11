import importlib.util
import hashlib
import json
import pathlib
import sqlite3
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('proof', pathlib.Path(__file__).with_name('local-history-proof.py'))
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
GENESIS_RAW = bytes.fromhex(
    '010000000000000000000000000000000000000000000000000000000000000000000000'
    '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5f'
    'ae77031e8ad222030101000000010000000000000000000000000000000000000000000000'
    '000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e'
    '2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e642062'
    '61696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe'
    '5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f355'
    '04e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000')


class ProofTests(unittest.TestCase):
    def fixture(self, directory, records=1):
        root = pathlib.Path(directory).resolve()
        blocks = root / 'source'
        blocks.mkdir()
        key = bytes.fromhex('0102030405060708')
        (blocks / 'xor.dat').write_bytes(key)
        frame = struct.pack('<II', 0x40cf030a, len(GENESIS_RAW)) + GENESIS_RAW
        raw = proof.xor_bytes(frame * records, key, 0)
        file = blocks / 'blk00000.dat'
        file.write_bytes(raw)
        stat = file.stat()
        profile = {'schemaVersion': 'universe-local-history-proof-job-v1', 'network': 'signet',
                   'genesis': proof.GENESIS, 'rowSchema': 'electrs-TXM-v2', 'blocksDirectory': str(blocks),
                   'magic': 0x40cf030a, 'xorSha256': hashlib.sha256(key).hexdigest(),
                   'targetHeight': 0, 'targetHash': proof.GENESIS,
                   'signetChallenge': '51', 'signetChallengeSha256': hashlib.sha256(b'\x51').hexdigest(),
                   'pruned': False, 'initialBlockDownload': False, 'coreHeaders': 0,
                   'files': [{'name': file.name, 'device': stat.st_dev, 'inode': stat.st_ino,
                              'uid': stat.st_uid, 'bytes': stat.st_size, 'mtimeNs': stat.st_mtime_ns,
                              'appendable': True}]}
        task = root / 'task'
        task.mkdir()
        (task / 'proof-job.json').write_text(json.dumps(profile))
        return task, file, profile

    def test_authoritative_genesis_exact_t_x_m_encoding(self):
        expected = bytes.fromhex(proof.GENESIS)[::-1]
        self.assertEqual(proof.double_hash(GENESIS_RAW[:80]), expected)
        rows = proof.block_rows(GENESIS_RAW, expected, proof.Window())
        self.assertEqual([key[:1] for key, _ in rows], [b'T', b'X', b'M'])
        self.assertEqual(rows[1][1], struct.pack('<Q', 1) + rows[0][0][1:])
        self.assertEqual(rows[2][1], struct.pack('<III', 1, len(GENESIS_RAW), len(GENESIS_RAW) * 4))
        self.assertEqual(rows[0][0][1:], proof.double_hash(rows[0][1]))

    def test_xor_uses_absolute_offset_across_arbitrary_read_boundaries(self):
        key = b'12345678'
        raw = GENESIS_RAW
        encoded = proof.xor_bytes(raw, key, 3)
        self.assertEqual(proof.xor_bytes(encoded[:17], key, 3) + proof.xor_bytes(encoded[17:], key, 20), raw)

    def test_witness_commitment_is_verified_independently_of_header_merkle(self):
        tx = proof.block_rows(GENESIS_RAW, bytes.fromhex(proof.GENESIS)[::-1], proof.Window())[0][1]
        reader = proof.Reader(tx, proof.Window())
        reader.take(4)
        self.assertEqual(reader.count(), 1)
        reader.take(36)
        reader.take(reader.count())
        reader.take(4)
        output_offset = reader.offset
        self.assertEqual(reader.count(), 1)
        reserved = bytes(32)
        commitment = proof.double_hash(bytes(32) + reserved)
        extra = bytes(8) + proof.compact(38) + bytes.fromhex('6a24aa21a9ed') + commitment
        base = tx[:output_offset] + proof.compact(2) + tx[output_offset + 1:-4] + extra + tx[-4:]
        witness = base[:4] + b'\x00\x01' + base[4:-4] + b'\x01\x20' + reserved + base[-4:]
        header = GENESIS_RAW[:36] + proof.double_hash(base) + GENESIS_RAW[68:80]
        block = header + b'\x01' + witness
        self.assertEqual(len(proof.block_rows(block, proof.double_hash(header), proof.Window())), 3)
        changed = bytearray(block)
        changed[-5] ^= 1
        with self.assertRaisesRegex(proof.InvalidProof, 'Witness commitment'):
            proof.block_rows(bytes(changed), proof.double_hash(header), proof.Window())

    def test_merkle_identity_eof_amount_and_compact_corruption_fail_closed(self):
        expected = bytes.fromhex(proof.GENESIS)[::-1]
        for value in [GENESIS_RAW[:-1], GENESIS_RAW + b'0', GENESIS_RAW[:100] + bytes([GENESIS_RAW[100] ^ 1]) + GENESIS_RAW[101:]]:
            with self.assertRaises(proof.InvalidProof):
                proof.block_rows(value, expected, proof.Window())
        with self.assertRaises(proof.InvalidProof):
            proof.block_rows(GENESIS_RAW, bytes(32), proof.Window())
        with self.assertRaises(proof.InvalidProof):
            proof.Reader(b'\xfd\x01\x00', proof.Window()).count()
        with self.assertRaises(proof.InvalidProof):
            proof.merkle([bytes(32), bytes(32)])

    def test_windows_resume_and_generated_packets_preserve_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root, file, _ = self.fixture(directory, 501)
            original = file.read_bytes()
            first = proof.advance(root)
            self.assertEqual(first['visits'], 500)
            self.assertEqual(first['phase'], 'scan')
            second = proof.advance(root)
            self.assertEqual(second['phase'], 'rows-complete')
            self.assertEqual(second['bodyHeight'], 1)
            self.assertFalse(second['ready'])
            packet = (root / 'chunks' / '00000000.row').read_bytes()
            self.assertEqual(packet[:8], b'UPRFROW1')
            self.assertEqual(struct.unpack('<I', packet[48:52])[0], 3)
            self.assertEqual(hashlib.sha256(packet[88:]).digest(), packet[56:88])
            self.assertEqual(file.read_bytes(), original)
            repeated = proof.advance(root)
            self.assertEqual(repeated['chunks'], second['chunks'])

    def test_missing_interior_ancestry_and_wrong_network_never_finish(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, profile = self.fixture(directory)
            profile['targetHash'] = '1' * 64
            (root / 'proof-job.json').write_text(json.dumps(profile))
            with self.assertRaises(proof.InvalidProof):
                proof.advance(root)
        with tempfile.TemporaryDirectory() as directory:
            root, _, profile = self.fixture(directory)
            profile['magic'] = 1
            (root / 'proof-job.json').write_text(json.dumps(profile))
            with self.assertRaises(proof.InvalidProof):
                proof.advance(root)

    def test_profile_changes_and_non_auxiliary_database_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, profile = self.fixture(directory, 501)
            proof.advance(root)
            profile['targetHeight'] = 1
            (root / 'proof-job.json').write_text(json.dumps(profile))
            with self.assertRaises(proof.InvalidProof):
                proof.advance(root)
        with tempfile.TemporaryDirectory() as directory:
            root, _, _ = self.fixture(directory)
            db = sqlite3.connect(root / 'locator.sqlite')
            db.execute('CREATE TABLE canonical_private_data(value TEXT)')
            db.commit()
            db.close()
            original = (root / 'locator.sqlite').read_bytes()
            with self.assertRaises(proof.InvalidProof):
                proof.advance(root)
            self.assertEqual((root / 'locator.sqlite').read_bytes(), original)

    def test_same_task_cannot_have_concurrent_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _ = self.fixture(directory)
            with proof.exclusive_task(root):
                with self.assertRaises(OSError):
                    proof.advance(root)


if __name__ == '__main__':
    unittest.main()
