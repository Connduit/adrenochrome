"""Run with: python3 builder/tests/test_archive.py /absolute/path/to/builder"""
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

BUILDER = str(pathlib.Path(sys.argv.pop(1)).resolve())


def fixture():
    # Minimal structural PE fixture. Contains data only and is never executed.
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x8664, 1)
    struct.pack_into('<HH', data, 0x94, 240, 0x2000)
    struct.pack_into('<H', data, 0x98, 0x20b)
    entry = 0x98 + 240
    data[entry:entry + 8] = b'12345678'  # No trailing NUL.
    struct.pack_into('<II', data, entry + 16, 512, 512)
    data[512:] = bytes(range(256)) * 2
    return bytes(data)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.source = self.root / 'input.dll'
        self.source.write_bytes(fixture())
        self.archive = self.root / 'sample.axe'

    def run_cli(self, *args, ok=True):
        result = subprocess.run([BUILDER, *map(str, args)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0 if ok else 1, result.stderr)
        return result

    def pack(self):
        self.run_cli('pack', self.source, self.archive)

    def test_round_trip_and_inspection(self):
        self.pack()
        data = self.archive.read_bytes()
        self.assertEqual(data[:8], b'AXEARCH\0')
        self.assertEqual(data[32:], self.source.read_bytes())
        report = self.run_cli('inspect', self.archive).stdout
        self.assertIn('PE machine: 0x8664', report)
        self.assertIn('12345678: offset=512 bytes=512', report)
        output = self.root / 'restored.dll'
        self.run_cli('extract', self.archive, output)
        self.assertEqual(output.read_bytes(), self.source.read_bytes())

    def test_existing_outputs_preserved(self):
        self.pack()
        original = self.archive.read_bytes()
        self.run_cli('pack', self.source, self.archive, ok=False)
        self.assertEqual(self.archive.read_bytes(), original)
        self.run_cli('extract', self.archive, self.source, ok=False)
        self.assertEqual(self.source.read_bytes(), fixture())
        self.run_cli('pack', self.source, self.source, ok=False)
        self.assertEqual(self.source.read_bytes(), fixture())

    def test_rejects_bad_archive_headers_and_payload(self):
        self.pack()
        original = self.archive.read_bytes()
        mutations = [b'', original[:31], original[:-1], original + b'x']
        for offset in (0, 8, 12, 16, 24, 28, 40):
            changed = bytearray(original)
            changed[offset] ^= 1
            mutations.append(bytes(changed))
        for i, data in enumerate(mutations):
            with self.subTest(i=i):
                self.archive.write_bytes(data)
                self.run_cli('inspect', self.archive, ok=False)
                output = self.root / f'rejected-{i}.dll'
                self.run_cli('extract', self.archive, output, ok=False)
                self.assertFalse(output.exists())

    def test_rejects_invalid_pe_input(self):
        invalid = [b'', b'plain text', fixture()[:200]]
        for offset, value, fmt in [(0x3c, 0xffffffff, '<I'), (0x96, 0, '<H'),
                                   (0x98, 0, '<H'), (0x86, 65535, '<H'),
                                   (0x98 + 240 + 20, 0xffffffff, '<I')]:
            data = bytearray(fixture())
            struct.pack_into(fmt, data, offset, value)
            invalid.append(bytes(data))
        for data in invalid:
            with self.subTest(size=len(data), prefix=data[:8]):
                self.source.write_bytes(data)
                self.run_cli('pack', self.source, self.archive, ok=False)
                self.assertFalse(self.archive.exists())

    def test_valid_checksum_does_not_bypass_pe_validation(self):
        self.pack()
        data = bytearray(self.archive.read_bytes())
        data[32] = 0
        checksum = 2166136261
        for byte in data[32:]:
            checksum = ((checksum ^ byte) * 16777619) & 0xffffffff
        struct.pack_into('<I', data, 24, checksum)
        self.archive.write_bytes(data)
        self.run_cli('inspect', self.archive, ok=False)

    def test_pe32_archive(self):
        data = bytearray(fixture())
        struct.pack_into('<H', data, 0x84, 0x14c)
        struct.pack_into('<H', data, 0x98, 0x10b)
        self.source.write_bytes(data)
        self.pack()
        self.assertIn('PE machine: 0x14c', self.run_cli('inspect', self.archive).stdout)

    def test_symlink_output_preserved(self):
        try:
            self.archive.symlink_to(self.source)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks unavailable')
        self.run_cli('pack', self.source, self.archive, ok=False)
        self.assertEqual(self.source.read_bytes(), fixture())
        self.assertTrue(self.archive.is_symlink())

    @unittest.skipUnless(os.environ.get('AXE_EXTRACTOR'), 'Set AXE_EXTRACTOR to test standalone utility')
    def test_standalone_extractor(self):
        extractor = os.environ['AXE_EXTRACTOR']
        self.pack()
        output = self.root / 'standalone.dll'
        result = subprocess.run([extractor, str(self.archive), str(output)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), fixture())
        for args, expected in [([], 2), (['-h'], 0), (['--help'], 0),
                               ([str(self.archive), str(output)], 1)]:
            result = subprocess.run([extractor, *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stderr)
        self.assertEqual(output.read_bytes(), fixture())
        self.archive.write_bytes(b'invalid archive')
        rejected = self.root / 'rejected.dll'
        result = subprocess.run([extractor, str(self.archive), str(rejected)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(rejected.exists())

    def test_help(self):
        for option in ('-h', '--help'):
            result = self.run_cli(option)
            self.assertEqual(result.stderr, '')
            for text in ('pack', 'inspect', 'extract', '256 MiB',
                         'incompatible', 'Exit codes:'):
                self.assertIn(text, result.stdout)

    def test_errors_and_usage(self):
        for args in ([], ['unknown']):
            result = subprocess.run([BUILDER, *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
        self.run_cli('pack', self.root / 'missing.dll', self.archive, ok=False)
        self.run_cli('extract', self.root / 'missing.axe', self.source, ok=False)
        self.run_cli('pack', self.source, self.root / 'missing' / 'out.axe', ok=False)


if __name__ == '__main__':
    unittest.main()
