#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the source locator through its CLI on isolated offline Git objects."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("source-context.py").resolve()


class SourceContext(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.git("init", "-q")
        (self.root / "src").mkdir()
        (self.root / "AGENTS.md").write_text("root instructions")
        (self.root / "src/AGENTS.md").write_text("nested instructions")
        self.special = "src/odd:\t\n[name].rs"
        (self.root / self.special).write_text("needle needle\nneedle\n")
        (self.root / "src/other.rs").write_text("needle\n")
        (self.root / "binary").write_bytes(b"\0needle\0")
        (self.root / "outside").write_text("needle\n")
        self.git("add", ".")
        self.git("-c", "user.name=test", "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "fixture")
        self.revision = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", self.root, *args], text=True).strip()

    def cli(self, *args, check=True):
        return subprocess.run([sys.executable, "-B", SCRIPT, *args], cwd=self.root / "src",
                              capture_output=True, text=True, check=check)

    def query(self, *args):
        return json.loads(self.cli(*args).stdout)

    def test_page_counts_scope_and_nested_instructions(self):
        page = self.query("--limit", "1", "needle", "--", "src")
        self.assertEqual((page["commit"], page["total_files"], page["total_matching_lines"]),
                         (self.revision, 2, 3))
        self.assertEqual(page["files"], [{"path": self.special, "matching_lines": 2,
                                          "blob": self.git("rev-parse", f"HEAD:{self.special}")}])
        self.assertEqual(page["instructions"],
                         {p: self.git("rev-parse", f"HEAD:{p}") for p in ("AGENTS.md", "src/AGENTS.md")})
        self.assertEqual(page["next_offset"], 1)
        other = self.query("--rev", self.revision, "--offset", "1", "--limit", "1", "needle", "src")
        self.assertEqual(other["files"][0]["path"], "src/other.rs")
        self.assertIsNone(other["next_offset"])

    def test_literal_revision_ignores_dirty_and_untracked_files(self):
        (self.root / self.special).write_text("changed\n")
        (self.root / "src/new.rs").write_text("needle\n")
        scoped = self.query("needle", self.special)
        self.assertEqual(scoped["total_matching_lines"], 2)
        (self.root / "outside").unlink()
        (self.root / "src/AGENTS.md").write_text("revised instructions")
        self.git("add", "-A")
        self.git("-c", "user.name=test", "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "next")
        self.assertEqual(self.query("--rev", self.revision, "needle")["total_matching_lines"], 4)
        current = self.query("needle")
        self.assertEqual(current["total_matching_lines"], 2)
        self.assertNotEqual(current["instructions"]["src/AGENTS.md"], scoped["instructions"]["src/AGENTS.md"])
        self.assertEqual(self.query("--", "-unknown-term")["total_files"], 0)

    def test_missing_blob_is_an_error_even_if_another_matches(self):
        blob = self.git("rev-parse", f"HEAD:{self.special}")
        (self.root / ".git/objects" / blob[:2] / blob[2:]).unlink()
        result = self.cli("needle", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(result.stdout)

    def test_rejects_invalid_revisions_bounds_and_multiple_patterns(self):
        for args in (("--rev", "absent", "needle"), ("--offset", "-1", "needle"),
                     ("--limit", "101", "needle"), ("needle\nsecond",), ("needle", "../outside")):
            with self.subTest(args=args):
                result = self.cli(*args, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(result.stdout)


if __name__ == "__main__":
    unittest.main()
