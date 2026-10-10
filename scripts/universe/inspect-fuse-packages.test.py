"""Synthetic parser controls; never helper execution, package extraction or mount."""
import hashlib
import importlib.util
import io
import pathlib
import struct
import subprocess
import tarfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('inspect_helper', HERE / 'inspect-fuse-packages.py')
inspect_helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(inspect_helper)


class InspectorTests(unittest.TestCase):
    def test_default_no_parse(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'inspect-fuse-packages.py')], check=True, capture_output=True)
        self.assertIn(b'"packagesParsed": false', result.stdout)

    def ar(self, members):
        result = b'!<arch>\n'
        for name, content in members:
            header = (name + '/').ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6) + '644'.ljust(8) + str(len(content)).ljust(10) + '`\n'
            result += header.encode() + content + (b'\n' if len(content) % 2 else b'')
        return result

    def test_checksum_before_ar_and_control_never_decoded(self):
        raw = self.ar([('debian-binary', b'2.0\n'), ('control.tar.zst', b'NEVER_EXECUTE_CONTROL'), ('data.tar.zst', b'data')])
        expected = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        self.assertEqual(inspect_helper.ar_data(raw, expected), b'data')
        expected['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'before ar parser'): inspect_helper.ar_data(raw, expected)

    def test_ar_unknown_duplicate_or_truncated_rejected(self):
        for members in [[('other', b'foo')], [('debian-binary', b'2.0\n')] * 2]:
            raw = self.ar(members)
            with self.assertRaises(ValueError): inspect_helper.ar_data(raw, {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})

    def elf(self):
        raw = bytearray(1024); raw[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
        struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 4, 0, 0x1000, 0, len(raw), len(raw), 4096)
        struct.pack_into('<IIQQQQQQ', raw, 120, 2, 4, 192, 0x10c0, 0, 64, 64, 8)
        strings = b'\0libc.so.6\0'; raw[400:400 + len(strings)] = strings
        for i, pair in enumerate([(5, 0x1190), (10, len(strings)), (1, 1), (0, 0)]): struct.pack_into('<qQ', raw, 192 + i * 16, *pair)
        return bytes(raw)

    def test_pure_elf_dependency_extraction_without_execution(self):
        result = inspect_helper.elf_metadata(self.elf())
        self.assertEqual(result['needed'], ['libc.so.6']); self.assertFalse(result['executed'])

    def test_actual_binary_version_definition_record_and_count_guard(self):
        raw = bytearray(self.elf()); strings = b'\0libc.so.6\0GLIBC_2.38\0'
        raw[400:400 + len(strings)] = strings
        struct.pack_into('<IIQQQQQQ', raw, 120, 2, 4, 192, 0x10c0, 0, 96, 96, 8)
        pairs = [(5, 0x1190), (10, len(strings)), (1, 1), (0x6ffffffc, 0x11e0), (0x6ffffffd, 1), (0, 0)]
        for i, pair in enumerate(pairs): struct.pack_into('<qQ', raw, 192 + i * 16, *pair)
        struct.pack_into('<HHHHIII', raw, 480, 1, 0, 1, 1, 0, 20, 0)
        struct.pack_into('<II', raw, 500, 11, 0)
        self.assertEqual(inspect_helper.elf_metadata(raw)['versionDefinitions'], ['GLIBC_2.38'])
        struct.pack_into('<H', raw, 486, 17)
        with self.assertRaisesRegex(ValueError, 'definition record'): inspect_helper.elf_metadata(raw)

    def test_elf_wrong_machine_oob_strings_and_writable_executable_rejected(self):
        for kind in ['machine', 'offset', 'rwx']:
            raw = bytearray(self.elf())
            if kind == 'machine': struct.pack_into('<H', raw, 18, 183)
            elif kind == 'offset': struct.pack_into('<Q', raw, 200, 0xffffffffffff)
            else: struct.pack_into('<I', raw, 68, 7)
            with self.subTest(kind=kind), self.assertRaises(ValueError): inspect_helper.elf_metadata(raw)

    def tar(self, link):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as tar:
            entry = tarfile.TarInfo('./usr/lib/library.so.1.2'); entry.size = 3; tar.addfile(entry, io.BytesIO(b'abc'))
            entry = tarfile.TarInfo('./usr/lib/library.so.1'); entry.type = tarfile.SYMTYPE; entry.linkname = link; tar.addfile(entry)
        return output.getvalue()

    def test_only_same_directory_resolving_library_links(self):
        result = inspect_helper.inspect_data(self.tar('library.so.1.2'))
        self.assertFalse(result['materialized']); self.assertFalse(result['packageCodeExecuted'])
        for link in ['/etc/shadow', '../../outside', 'missing.so']:
            with self.subTest(link=link), self.assertRaises(ValueError): inspect_helper.inspect_data(self.tar(link))


if __name__ == '__main__': unittest.main()
