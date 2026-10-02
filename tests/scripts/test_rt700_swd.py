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


if __name__ == '__main__':
    unittest.main()
