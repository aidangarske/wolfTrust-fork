#!/usr/bin/env python3
"""Keep incomplete Arm reports from satisfying scheduled-test arithmetic."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class ConformanceReports(unittest.TestCase):
    def parse(self, report):
        helper = Path(__file__).resolve().parents[1] / "target/lib/scenario.sh"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "console.log"
            path.write_text(report)
            return subprocess.run(
                ["bash", "-c", 'set -eu; . "$1"; log="$2"; conf_totals; '
                 'printf "%s %s %s\\n" "$conf_passed" "$conf_skipped" "$conf_failed"',
                 "report-test", str(helper), str(path)],
                capture_output=True, text=True, timeout=10)

    def test_wrapped_report_with_peer_console(self):
        result = self.parse("TOTAL PASSED\r\n : 85\r\n"
                            "guest1: done\r\nTOTAL SKIPPED : 4\r\n"
                            "TOTAL FAILED : 0\r\nEND OF ACS\r\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "85 4 0")

    def test_reset_nul_bytes_do_not_pollute_the_report(self):
        result = self.parse("\x00TOTAL PASSED : 85\r\nTOTAL SKIPPED : 4\n"
                            "TOTAL FAILED : 0\x00\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "85 4 0")
        self.assertNotIn("ignored null byte", result.stderr)

    def test_missing_pass_count_cannot_be_offset_by_skip_count(self):
        # The former -1 default plus 18 skips summed to 17 scheduled tests.
        result = self.parse("TOTAL SKIPPED : 18\nTOTAL FAILED : 0\nEND OF ACS\n")
        self.assertNotEqual(result.returncode, 0)

    def test_missing_skip_count_is_incomplete(self):
        self.assertNotEqual(self.parse("TOTAL PASSED : 17\nTOTAL FAILED : 0\n").returncode, 0)

    def test_missing_or_malformed_failure_count_is_incomplete(self):
        for count in ("", "TOTAL FAILED : unavailable\n"):
            with self.subTest(count=count):
                result = self.parse("TOTAL PASSED : 85\nTOTAL SKIPPED : 4\n" + count)
                self.assertNotEqual(result.returncode, 0)

    def test_failed_tests_remain_visible(self):
        result = self.parse("TOTAL PASSED : 16\nTOTAL SKIPPED : 0\nTOTAL FAILED : 1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "16 0 1")


if __name__ == "__main__":
    unittest.main()
