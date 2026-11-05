#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the real notice collector with synthetic metadata, never Cargo."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from notice_test_fixtures import graph_fixture

ROOT = Path(__file__).resolve().parents[1]
REVISION = "a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5"
SOURCE = "git+https://github.com/virtee/sev?rev=" + REVISION + "#" + REVISION


class PinnedSevNotice(unittest.TestCase):
    def collect(self, *, changes=None, license_bytes=None, license_present=True):
        with tempfile.TemporaryDirectory(prefix="volparossa-sev-notice-") as tmp:
            root = Path(tmp)
            crate = root / "crate"
            crate.mkdir()
            reviewed = (ROOT / "third_party/licenses/virtee-sev-8.0.0-Apache-2.0.txt").read_bytes()
            if license_present:
                (crate / "LICENSE").write_bytes(reviewed if license_bytes is None else license_bytes)
            (crate / "Cargo.toml").write_text('[package]\nname="sev"\nversion="8.0.0"\n')
            package = dict(id="synthetic-package", name="sev", version="8.0.0",
                license="Apache-2.0", license_file=None,
                manifest_path=str(crate / "Cargo.toml"), source=SOURCE)
            package.update(changes or {})
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps(graph_fixture([package])))
            destination = root / "notices"
            result = subprocess.run([str(ROOT / "packaging/collect-cargo-licenses.sh"),
                str(metadata), str(destination)], env={**os.environ, "TMPDIR": tmp},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            notice = destination / "sev-8.0.0/LICENSE"
            summary = destination / "DEPENDENCIES.tsv"
            return result, notice.read_bytes() if notice.exists() else None, summary.read_text()

    def test_exact_source_and_original_license_are_collected(self):
        for license_file in (None, "LICENSE"):
            with self.subTest(license_file=license_file):
                result, notice, summary = self.collect(changes=dict(license_file=license_file))
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(notice,
                    (ROOT / "third_party/licenses/virtee-sev-8.0.0-Apache-2.0.txt").read_bytes())
                self.assertIn("sev\t8.0.0\tApache-2.0\t" + SOURCE + "\n", summary)

    def test_identity_license_and_nonlocal_license_file_mismatches_fail(self):
        for changes in (dict(name="other"), dict(version="8.0.1"), dict(license="MIT"),
                dict(license_file="../unreviewed-license")):
            with self.subTest(changes=changes):
                result, notice, _ = self.collect(changes=changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Pinned SEV package has unexpected license metadata.", result.stderr)
                self.assertIsNone(notice)

    def test_git_revision_origin_and_unpinned_sources_fail(self):
        for source in (SOURCE.replace(REVISION, "0" * 40, 1),
                SOURCE.rsplit("#", 1)[0] + "#" + "0" * 40,
                SOURCE.replace("virtee/sev", "unreviewed/sev"),
                "git+https://github.com/virtee/sev#" + REVISION):
            with self.subTest(source=source):
                result, notice, _ = self.collect(changes=dict(source=source))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Unapproved Cargo source", result.stderr)
                self.assertIsNone(notice)

    def test_missing_or_modified_license_fails_without_fallback(self):
        for kwargs in (dict(license_present=False), dict(license_bytes=b"changed license\n")):
            with self.subTest(kwargs=kwargs):
                result, notice, _ = self.collect(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Pinned SEV license differs", result.stderr)
                self.assertIsNone(notice)


if __name__ == "__main__":
    unittest.main()
