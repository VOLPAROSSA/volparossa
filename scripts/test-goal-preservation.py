#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert source-preservation regressions; no network or native execution."""

from pathlib import Path
import runpy
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = runpy.run_path(str(ROOT / "scripts/verify-goal-preservation.py"))
VERIFY = MODULE["verify"]
GOAL, ARCHIVE = MODULE["GOAL"], MODULE["ARCHIVE"]
SOURCE_GOAL, SOURCE_DPS, SOURCE_STUDIO = (
    MODULE["SOURCE_GOAL"], MODULE["SOURCE_DPS"], MODULE["SOURCE_STUDIO"])
FILES = (GOAL, ARCHIVE, *MODULE["SOURCE_HASHES"])


class Preservation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="goal-preservation-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        for name in FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())

    def replace(self, name, old, new):
        path = self.root / name
        raw = path.read_bytes()
        self.assertIn(old, raw)
        path.write_bytes(raw.replace(old, new, 1))

    def rejected(self, check):
        result = VERIFY(self.root)
        self.assertFalse(result["success"])
        self.assertFalse(result["checks"][check])

    def test_fresh_export_needs_no_git_or_duplicate_goal_files(self):
        self.assertFalse((self.root / ".git").exists())
        result = VERIFY(self.root)
        self.assertTrue(result["success"], result["errors"])
        self.assertEqual(result["payloads"]["studio_hosting"]["bytes"], 18793)

    def test_missing_source_reference_is_rejected(self):
        self.replace(GOAL, b"../archive/requirements-20261023/README.md", b"missing.md")
        self.rejected("goal_source_reference")

    def test_complete_source_snapshot_edit_is_rejected(self):
        self.replace(SOURCE_STUDIO, b"<!-- Source:", b"<!-- source:")
        self.rejected("source_snapshot:" + SOURCE_STUDIO)

    def test_original_goal_edit_is_rejected(self):
        self.replace(SOURCE_GOAL, b"Bouw Project VOLPAROSSA", b"Bouw Project VOLPAROSSa")
        self.rejected("original_goal_payload")

    def test_earlier_amendment_edit_is_rejected(self):
        self.replace(SOURCE_GOAL, b"Consent-O-Matic remains", b"Consent-O-Matic remainS")
        self.rejected("goal_prefix_and_original_hash_metadata")

    def test_previous_dps_incorporation_edit_is_rejected(self):
        self.replace(SOURCE_GOAL, b"### Decentralized Positioning System", b"### Decentralized positioning System")
        self.rejected("complete_pre_studio_goal_preserved")

    def test_dps_archive_edit_is_rejected(self):
        self.replace(ARCHIVE, b"<!-- BEGIN DPS CONTINUATION -->\n### Map", b"<!-- BEGIN DPS CONTINUATION -->\n### map")
        self.rejected("dps_continuation_payload")

    def test_joined_dps_edit_is_rejected(self):
        self.replace(SOURCE_DPS, b"### Map\n", b"### map\n")
        self.rejected("exact_dps_consolidation_and_single_map")

    def test_studio_payload_edit_is_rejected(self):
        self.replace(SOURCE_STUDIO, b"Use the existing open-source Silex", b"Use the existing open-source silex")
        self.rejected("studio_hosting_payload")

    def test_duplicate_studio_source_marker_is_rejected(self):
        marker = b"<!-- BEGIN STUDIO HOSTING REQUIREMENTS -->"
        self.replace(SOURCE_STUDIO, marker, marker + b"\n" + marker)
        self.rejected("studio_hosting_payload")

    def test_missing_studio_source_is_rejected(self):
        (self.root / SOURCE_STUDIO).unlink()
        self.rejected("read:" + SOURCE_STUDIO)

    def test_missing_integrated_section_is_rejected(self):
        for name in ("dps", "studio"):
            with self.subTest(section=name):
                path = self.root / GOAL
                original = path.read_bytes()
                marker = f'<a id="{name}"></a>'.encode()
                self.replace(GOAL, marker, b"")
                self.rejected("goal_integrated_sections")
                path.write_bytes(original)

    def test_empty_integrated_section_is_rejected(self):
        path = self.root / GOAL
        original = path.read_bytes()
        for section in ("dps", "studio"):
            with self.subTest(section=section):
                dps_body = "" if section == "dps" else "Positioning requirements."
                studio_body = "" if section == "studio" else "Studio requirements."
                path.write_text(
                    f'<a id="dps"></a>\n## DPS\n{dps_body}\n## Other\n'
                    f'<a id="studio"></a>\n### Studio\n{studio_body}\n## End\n')
                self.rejected("goal_integrated_sections")
        path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
