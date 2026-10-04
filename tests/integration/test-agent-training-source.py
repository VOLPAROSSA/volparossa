#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fixed public fixture bytes and actual unprivileged staging; no model/VM claim."""

import hashlib
import json
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / "agent-training-smoke.py"))
ART = runpy.run_path(str(HERE / "agent-artifact-smoke.py"))
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
CATALOG = runpy.run_path(str(HERE / "agent-train-loop-catalog.py"))
LOOP = runpy.run_path(str(HERE / "agent-train-loop-smoke.py"))
REVISION = "a" * 40
# Captured BEFORE the source lookup fix, with the original factories and README
# blob e73ce4055340a7625c123b01838129f487927a61. Includes all fields, Q/A/context
# bytes, ordering and the exact existing TRAIN.write serialization, not just rows.
DATASET_HASHES = {
    "training": (1005, "686384fccc415391f9ae7178bd80bffc7ce59717028ce1b67a727b794219a601"),
    "artifact": (1005, "686384fccc415391f9ae7178bd80bffc7ce59717028ce1b67a727b794219a601"),
    "jobs": (721, "612e538e62a1ac63cfac4e1f791205fa0622ad1a567709510d57f84bba6575b1"),
    "catalog": (1155, "e15f580702f108b62fe1b99c410f68844896f9db9730370faf67aedcc21bfb61"),
    "validation": (641, "a1d0785377a96255038d571bebcf81778d5c19cff20b5ffe8b6f1ecba1211b26"),
}


class PublicTrainingSourceTests(unittest.TestCase):
    def assert_dataset(self, label, value):
        raw = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), DATASET_HASHES[label])

    def test_provenance_and_all_original_dataset_bytes(self):
        source = TRAIN["public_source"]()
        raw = source.encode()
        meta = json.loads((HERE / "agent-training-public-source.json").read_bytes())
        self.assertEqual(meta["revision"], "59238a6f2c2ee8c4c79b136481cd53d5b9b908df")
        self.assertEqual(meta["path"], "README.md")
        self.assertEqual(meta["license"], "GPL-3.0-only")
        self.assertEqual((meta["bytes"], meta["sha256"]), (len(raw), hashlib.sha256(raw).hexdigest()))
        self.assertEqual(meta["git_blob"], hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        self.assert_dataset("training", TRAIN["public_dataset"](REVISION))
        self.assert_dataset("artifact", ART["dataset"](REVISION, source))
        self.assert_dataset("jobs", JOBS["dataset"](REVISION, source))
        self.assert_dataset("catalog", CATALOG["next_dataset"](REVISION, source))
        # Exercise the real validation factory without native/model/network work.
        with tempfile.TemporaryDirectory(prefix="fixed-public-validation-") as name:
            root = Path(name) / "agent-artifact-user"
            root.mkdir(mode=0o700)
            LOOP["validation_input"](root, REVISION)
            self.assert_dataset("validation", json.loads((root / "validation-dataset.json").read_bytes()))

    def test_changed_readme_and_repo_override_do_not_change_training_input(self):
        with tempfile.TemporaryDirectory(prefix="fixed-public-readme-") as name:
            root = Path(name)
            (root / "README.md").write_text("Reader guide with reorganized application documentation.\n")
            # The previous literal README precondition fails, but the fixed
            # loader does not consult this mutable tree, even under REPO override.
            with self.assertRaises(ValueError):
                ART["dataset"](REVISION, (root / "README.md").read_text())
            with patch.dict(TRAIN["public_dataset"].__globals__, REPO=root):
                self.assert_dataset("training", TRAIN["public_dataset"](REVISION))
            (root / "README.md").unlink()
            with patch.dict(TRAIN["public_dataset"].__globals__, REPO=root):
                self.assert_dataset("training", TRAIN["public_dataset"](REVISION))

    def test_actual_guest_staging_loop_and_relocated_loader(self):
        harness = (HERE / "kvm-alpha-topology.sh").read_text()
        start = harness.index("    for artifact_script in agent-artifact-smoke.py agent-training-smoke.py; do\n")
        end = harness.index('    install -d -o root -g root -m 0555 "$WORK/bin/ml"', start)
        staged_loop = harness[start:end]
        self.assertIn('-o root -g root -m 0444 "$source_directory/tests/integration/$training_source"', staged_loop)
        for name in TRAIN["PUBLIC_SOURCE_FILES"]:
            self.assertIn("tests/integration/" + name, harness[:start])
        with tempfile.TemporaryDirectory(prefix="fixed-public-stage-") as name:
            work = Path(name)
            stage = work / "bin"
            stage.mkdir()
            # Only the extracted install loop, at ordinary UID in this disposable
            # directory. Omit ownership changes, retain exact modes and sourcepaths.
            subprocess.run(["sh", "-eu", "-c", 'source_directory=$1; WORK=$2;\n' +
                            staged_loop.replace("-o root -g root ", ""), "stage",
                            str(HERE.parent.parent), str(work)], check=True, timeout=5)
            for filename in TRAIN["PUBLIC_SOURCE_FILES"]:
                self.assertEqual(stat.S_IMODE((stage / filename).stat().st_mode), 0o444)
            loaded = runpy.run_path(str(stage / "agent-training-smoke.py"))
            self.assertFalse((loaded["REPO"] / "README.md").exists())
            with patch.dict(loaded["public_dataset"].__globals__, REPO=work / "absent-source-tree"):
                self.assert_dataset("training", loaded["public_dataset"](REVISION))
            # Repository-launched recovery helpers explicitly read WORK/bin too.
            self.assertEqual(TRAIN["public_source"](stage), loaded["public_source"]())
            # Current-README document tasks retain their independent staging.
            self.assertIn('"$source_directory/README.md" "$WORK/bin/agent-jobs-README.md"', harness)
            document = (HERE / "agent-public-document-smoke.py").read_text()
            self.assertIn('(HERE / "agent-jobs-README.md").read_bytes()', document)

    def test_missing_modified_and_symlinked_source_or_provenance_are_rejected(self):
        for selected in TRAIN["PUBLIC_SOURCE_FILES"]:
            for mutation in ("missing", "modified", "symlink"):
                with self.subTest(file=selected, mutation=mutation), tempfile.TemporaryDirectory(prefix="fixed-public-bad-") as name:
                    stage = Path(name)
                    for filename in TRAIN["PUBLIC_SOURCE_FILES"]:
                        shutil.copyfile(HERE / filename, stage / filename)
                    victim = stage / selected
                    if mutation == "modified":
                        raw = victim.read_bytes()
                        victim.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                    else:
                        victim.unlink()
                        if mutation == "symlink":
                            victim.symlink_to(HERE / selected)
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        TRAIN["public_source"](stage)

    def test_existing_revision_and_literal_context_checks_remain_fail_closed(self):
        source = TRAIN["public_source"]()
        for revision in ("", "G" * 40, "a" * 39):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                TRAIN["public_dataset"](revision)
        for factory in (ART["dataset"], JOBS["dataset"], CATALOG["next_dataset"]):
            with self.subTest(factory=factory.__name__), self.assertRaises(ValueError):
                factory(REVISION, "replacement source lacking the original context")
        self.assertEqual(ART["dataset"](REVISION, source), TRAIN["public_dataset"](REVISION))


if __name__ == "__main__":
    unittest.main()
