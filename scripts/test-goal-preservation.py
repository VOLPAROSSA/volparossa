#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert preservation regressions; no attachments, network or native execution."""

from pathlib import Path
import runpy
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = runpy.run_path(str(ROOT / "scripts/verify-goal-preservation.py"))["verify"]
FILES = (
    "docs/development/GOAL.md", "docs/development/DPS_GOAL_20261021.md",
    "docs/development/DPS_REQUIREMENTS.md", "docs/development/STUDIO_HOSTING_REQUIREMENTS.md",
    "docs/development/PURSUING_GOAL.md",
    "docs/development/GOAL_SOURCE_20261023.md",
    "docs/development/DPS_REQUIREMENTS_SOURCE_20261023.md",
    "docs/development/STUDIO_HOSTING_REQUIREMENTS_SOURCE_20261023.md",
)


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

    def test_fresh_export_needs_no_git_or_attachment(self):
        self.assertFalse((self.root / ".git").exists())
        result = VERIFY(self.root)
        self.assertTrue(result["success"], result["errors"])
        self.assertEqual(result["payloads"]["studio_hosting"]["bytes"], 18793)

    def test_effective_source_link_removal_is_rejected(self):
        for name in ("GOAL", "DPS_REQUIREMENTS", "STUDIO_HOSTING_REQUIREMENTS"):
            with self.subTest(requirement=name):
                active = f"docs/development/{name}.md"
                path = self.root / active
                original = path.read_bytes()
                path.write_bytes(original.replace(
                    f"{name}_SOURCE_20261023.md".encode(), b"missing.md"))
                self.rejected("effective_requirement_source:" + active)
                path.write_bytes(original)

    def test_complete_source_snapshot_edit_is_rejected(self):
        # Even source text outside marked payloads must remain byte-identical.
        name = "docs/development/STUDIO_HOSTING_REQUIREMENTS_SOURCE_20261023.md"
        self.replace(name, b"<!-- Source:", b"<!-- source:")
        self.rejected("source_snapshot:" + name)

    def test_original_goal_edit_is_rejected(self):
        self.replace("docs/development/GOAL_SOURCE_20261023.md", b"Bouw Project VOLPAROSSA", b"Bouw Project VOLPAROSSa")
        self.rejected("original_goal_payload")

    def test_earlier_amendment_edit_is_rejected(self):
        self.replace("docs/development/GOAL_SOURCE_20261023.md", b"Consent-O-Matic remains", b"Consent-O-Matic remainS")
        self.rejected("goal_prefix_and_original_hash_metadata")

    def test_previous_dps_incorporation_edit_is_rejected(self):
        self.replace("docs/development/GOAL_SOURCE_20261023.md", b"### Decentralized Positioning System", b"### Decentralized positioning System")
        self.rejected("complete_pre_studio_goal_preserved")

    def test_dps_archive_edit_is_rejected(self):
        self.replace("docs/development/DPS_GOAL_20261021.md", b"<!-- BEGIN DPS CONTINUATION -->\n### Map", b"<!-- BEGIN DPS CONTINUATION -->\n### map")
        self.rejected("dps_continuation_payload")

    def test_joined_dps_edit_is_rejected(self):
        self.replace("docs/development/DPS_REQUIREMENTS_SOURCE_20261023.md", b"### Map\n", b"### map\n")
        self.rejected("exact_dps_consolidation_and_single_map")

    def test_studio_payload_edit_is_rejected(self):
        self.replace("docs/development/STUDIO_HOSTING_REQUIREMENTS_SOURCE_20261023.md", b"Use the existing open-source Silex", b"Use the existing open-source silex")
        self.rejected("studio_hosting_payload")

    def test_duplicate_studio_marker_is_rejected(self):
        marker = b"<!-- BEGIN STUDIO HOSTING REQUIREMENTS -->"
        self.replace("docs/development/STUDIO_HOSTING_REQUIREMENTS_SOURCE_20261023.md", marker, marker + b"\n" + marker)
        self.rejected("studio_hosting_payload")

    def test_missing_studio_file_is_rejected(self):
        (self.root / "docs/development/STUDIO_HOSTING_REQUIREMENTS.md").unlink()
        self.rejected("read:docs/development/STUDIO_HOSTING_REQUIREMENTS.md")

    def test_missing_goal_incorporation_is_rejected(self):
        path = self.root / "docs/development/GOAL.md"
        path.write_bytes(path.read_bytes().replace(b"STUDIO_HOSTING_REQUIREMENTS.md", b"missing.md"))
        self.rejected("goal_references_studio_hosting")

    def test_ui_without_studio_reference_is_rejected(self):
        path = self.root / "docs/development/PURSUING_GOAL.md"
        path.write_bytes(path.read_bytes().replace(b"STUDIO_HOSTING_REQUIREMENTS.md", b"missing.md"))
        self.rejected("resume_prompt_explicit_scope_and_references")


if __name__ == "__main__":
    unittest.main()
