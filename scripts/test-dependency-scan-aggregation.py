#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the real shell scan stage with inert scanners, never Cargo builds."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name("check-rust-dependencies.sh").read_text()


def shell_function(name):
    return re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SOURCE, re.M | re.S)[0]


# Execute the actual tool preconditions and scan commands, not a rewritten model
# of their control flow. Earlier vendor/source/graph guards are outside this test.
STAGE = "set -eu\n" + "\n".join(
    shell_function(name)
    for name in ("fail", "pass", "check_deny_version", "check_audit_version")
)
STAGE += SOURCE[SOURCE.index('CARGO_HOME="$deny_cargo_home" cargo deny --version'):]

MOCK = """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

args = sys.argv[1:]
deny = Path(sys.argv[0]).name == "cargo"
if "--version" in args:
    print("cargo-deny " + os.environ.get("DENY_VERSION", "0.18.6") if deny
          else "cargo-audit " + os.environ.get("AUDIT_VERSION", "0.22.1"))
    sys.exit(0)
fuzz = "fuzz/Cargo.toml" in args or "fuzz/Cargo.lock" in args
index = (0 if deny else 2) + int(fuzz)
with open(os.environ["SCAN_LOG"], "a") as log:
    log.write(str(index) + " " + " ".join(args) + "\\n")
sys.exit(index + 3 if int(os.environ.get("FAIL_MASK", "0")) & (1 << index) else 0)
"""


class ScanAggregationTests(unittest.TestCase):
    def run_stage(self, **overrides):
        with tempfile.TemporaryDirectory(prefix="dependency-scan-test-") as directory:
            root = Path(directory)
            for name in ("cargo", "cargo-audit"):
                executable = root / name
                executable.write_text(MOCK)
                executable.chmod(0o755)
            log = root / "scans.log"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       SCAN_LOG=str(log), deny_cargo_home=str(root),
                       root_deny_config="guarded-root.toml", advisory_database="pinned-db",
                       CARGO_AUDIT=str(root / "cargo-audit"))
            env.update(overrides)
            result = subprocess.run(["sh", "-c", STAGE], env=env, text=True,
                                    capture_output=True, check=False)
            return result, log.read_text().splitlines() if log.exists() else []

    def test_every_combination_runs_all_four_scans_and_preserves_first_failure(self):
        for mask in range(16):
            with self.subTest(mask=mask):
                result, scans = self.run_stage(FAIL_MASK=str(mask))
                self.assertEqual([int(line[0]) for line in scans], [0, 1, 2, 3])
                expected = next((index + 3 for index in range(4) if mask & (1 << index)), 0)
                self.assertEqual(result.returncode, expected, result.stderr)
                for index, line in enumerate(scans):
                    if index < 2:
                        self.assertIn("--locked --offline", line)
                    else:
                        self.assertIn("--no-fetch", line)
                    self.assertEqual("RUSTSEC-2023-0071" in line, index == 2)
                self.assertEqual(result.stdout.count("PASS  "), 5 if mask == 0 else 4 - mask.bit_count())

    def test_tool_preconditions_stop_before_any_scan(self):
        for overrides in [
            {"DENY_VERSION": "0.18.5"},
            {"AUDIT_VERSION": "0.22.0"},
            {"CARGO_AUDIT": "/nonexistent/volparossa-test-cargo-audit"},
        ]:
            with self.subTest(overrides=overrides):
                result, scans = self.run_stage(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(scans, [])


if __name__ == "__main__":
    unittest.main()
