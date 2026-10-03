#!/usr/bin/env python3
"""Reject missing, ambiguous and diagnostic-only SWD memory observations."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class MemoryRowTest(unittest.TestCase):
    def parse(self, output):
        return subprocess.run(
            ['bash', '-c', '. "$1"; rt700_parse_word 0x20100004', 'test',
             str(ROOT / 'tests/target/lib/rt700_swd.sh')],
            input=output, text=True, capture_output=True, check=False)

    def test_row_among_diagnostics(self):
        result = self.parse('Error @ 0xe0002fd0-0xe0002fff\n'
                            '20100004:  0000009F  |....|\n')
        self.assertEqual((result.returncode, result.stdout), (0, '0000009f\n'))

    def test_error_address_cannot_be_a_word(self):
        result = self.parse('Error reading 0x20100004: FAULT ACK\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_wrong_memory_row(self):
        self.assertNotEqual(self.parse('20100008:  0000009f\n').returncode, 0)

    def test_ambiguous_rows(self):
        self.assertNotEqual(self.parse('20100004:  0000001f\n'
                                       '20100004:  0000009f\n').returncode, 0)

    def test_empty_observation(self):
        self.assertNotEqual(self.parse('').returncode, 0)


class MemoryAddressTest(unittest.TestCase):
    def address(self, base, offset):
        return subprocess.run(
            ['bash', '-c', '. "$1"; rt700_word_address "$2" "$3"', 'test',
             str(ROOT / 'tests/target/lib/rt700_swd.sh'), base, offset],
            text=True, capture_output=True, check=False)

    def test_valid_offsets(self):
        for offset in ('16', '016', '0x10'):
            with self.subTest(offset=offset):
                result = self.address('0x20100000', offset)
                self.assertEqual((result.returncode, result.stdout),
                                 (0, '0x20100010\n'))

    def test_missing_symbol_address(self):
        result = self.address('', '0')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_addresses_are_literals(self):
        for base, offset in (('missing_symbol', '0'), ('0x20100000', ''),
                             ('0x20100000 + 4', '0'), ('0x20100000', '-4'),
                             ('0x20100000', '4 + 4')):
            with self.subTest(base=base, offset=offset):
                result = self.address(base, offset)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_address_overflow(self):
        for base, offset in (('0x100000000', '0'), ('0xffffffff', '1'),
                             ('0x20100000', '4294967296')):
            with self.subTest(base=base, offset=offset):
                result = self.address(base, offset)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
