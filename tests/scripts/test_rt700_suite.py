#!/usr/bin/env python3
"""Exercise suite cleanup, failure propagation and exclusive rig ownership."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("flock"), "requires the Linux rig's flock")
class RT700SuiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.target = self.repo / "tests/target"
        self.target.mkdir(parents=True)
        source = Path(__file__).resolve().parents[1] / "target/run_rt700_suite.sh"
        shutil.copyfile(source, self.target / source.name)
        self.script("detect_rt700.sh", "#!/bin/sh\nexit 0\n")
        self.script("run_rt700_hardware.sh", """#!/bin/sh
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
rm -rf "$repo/build"
mkdir -p "$repo/build" "$RT700_WORK"
echo "  [check] PASS  reached $1"
echo "$1" > "$RT700_WORK/result"
test "$1" != broken
""")
        self.env = dict(os.environ, WT_RT700_SCENARIOS="first broken last",
                        RT700_LOCK_FILE=str(self.repo / "rig.lock"))
        self.env.pop("RT700_EVIDENCE_DIR", None)

    def script(self, name, body):
        path = self.target / name
        path.write_text(body)
        path.chmod(0o755)

    def run_suite(self):
        return subprocess.run(["bash", str(self.target / "run_rt700_suite.sh")],
                              env=self.env, capture_output=True, text=True,
                              timeout=10)

    def test_logs_survive_each_build_cleanup_and_failure_propagates(self):
        result = self.run_suite()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        runs = list((self.repo / "test-results/rt700-hardware").iterdir())
        self.assertEqual(len(runs), 1)
        for name in ("first", "broken", "last"):
            self.assertIn("reached " + name, (runs[0] / (name + ".log")).read_text())
            self.assertEqual((runs[0] / name / "result").read_text().strip(), name)
        self.assertIn("PASS: hardware/last", result.stdout)
        self.assertIn("FAIL: hardware/all", result.stdout)

    def test_successful_batch(self):
        self.env["WT_RT700_SCENARIOS"] = "first last"
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: hardware/all", result.stdout)

    def test_reject_evidence_below_build(self):
        self.env["RT700_EVIDENCE_DIR"] = str(self.repo / "build/logs")
        result = self.run_suite()
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be outside build/", result.stdout)

    def test_busy_rig_does_not_start_a_case(self):
        import fcntl
        with open(self.env["RT700_LOCK_FILE"], "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_suite()
        self.assertEqual(result.returncode, 1)
        self.assertIn("already in use", result.stdout)
        self.assertNotIn("RUN: hardware/", result.stdout)


if __name__ == "__main__":
    unittest.main()
