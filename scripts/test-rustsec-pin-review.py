#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert RustSec review tests: official API/Git observations are fixtures."""

import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("review", Path(__file__).with_name("review-rustsec-pin.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OLD, NEW = "a" * 40, "b" * 40
SOURCE = "env:\n  RUSTSEC_ADVISORY_DB_REVISION: " + OLD + "\nother: unchanged\n"


def metadata(sha):
    return {"sha": sha, "commit": {"committer": {"date": "2026-01-01T12:34:56Z"},
                                   "verification": {"verified": False}}}


class ReviewTests(unittest.TestCase):
    def compare(self, source=SOURCE, latest=NEW, api_sha=None):
        def run(command, **kwargs):
            self.assertEqual(command, ["git", "ls-remote", "--exit-code", M.ORIGIN, "refs/heads/main"])
            self.assertEqual(kwargs, dict(check=True, capture_output=True, text=True, timeout=30))
            return subprocess.CompletedProcess(command, 0, latest + "\trefs/heads/main\n")
        def fetch(ref):
            self.assertIn(ref, ["main", OLD])
            return metadata((api_sha or latest) if ref == "main" else OLD)
        return M.compare(source, fetch, run)

    def test_update_only_emits_single_pin_patch_and_review_boundary(self):
        changed, summary = self.compare()
        self.assertTrue(changed)
        self.assertIn("-  RUSTSEC_ADVISORY_DB_REVISION: " + OLD, summary)
        self.assertIn("+  RUSTSEC_ADVISORY_DB_REVISION: " + NEW, summary)
        self.assertIn("vendor/RSA scope checks", summary)
        self.assertIn("not an advisory scan", summary)
        self.assertIn("signature verified: `false`", summary)
        self.assertEqual(SOURCE.count(OLD), 1)

    def test_matching_pin_has_no_patch(self):
        changed, summary = self.compare(latest=OLD)
        self.assertFalse(changed)
        self.assertNotIn("```diff", summary)

    def test_moving_or_mismatched_ref_fails(self):
        with self.assertRaisesRegex(ValueError, "identity disagree"):
            self.compare(api_sha="c" * 40)

    def test_malformed_missing_duplicate_or_mutable_pins_fail(self):
        for source in ["", SOURCE + SOURCE, SOURCE.replace(OLD, "main"), SOURCE.replace(OLD, OLD.upper())]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.compare(source=source)

    def test_invalid_ref_response_fails(self):
        with self.assertRaisesRegex(ValueError, "Git ref response"):
            self.compare(latest="not-a-sha")

    def test_invalid_api_date_or_verification_fails(self):
        for field, value in [("committer", {"date": "9999-01-01T00:00:00Z"}),
                             ("committer", {"date": "invalid"}),
                             ("verification", {"verified": "yes"})]:
            data = metadata(OLD)
            data["commit"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                M.commit_metadata(data, OLD)

    def test_api_response_size_is_bounded(self):
        class Response(io.BytesIO):
            url = M.API + "main"
        with patch.object(M.urllib.request, "urlopen", return_value=Response(b"x" * (M.MAX_RESPONSE + 1))):
            with self.assertRaisesRegex(ValueError, "oversized"):
                M.fetch_commit("main")

    def test_unexpected_redirect_is_rejected(self):
        class Response(io.BytesIO):
            url = "https://example.invalid/commits/main"
        with patch.object(M.urllib.request, "urlopen", return_value=Response(b"{}")):
            with self.assertRaisesRegex(ValueError, "redirect"):
                M.fetch_commit("main")


if __name__ == "__main__":
    unittest.main()
