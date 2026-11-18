#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Owner-recovery proof contracts. These do not execute the peer or the browser."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "cloud-retained-upload.py"))
UPLOAD = runpy.run_path(str(HERE / "test-cloud-private-upload-smoke.py"))


def write(path, value):
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)


def prepared(root):
    target = root / "o" / ("object-" + "a" * 32)
    target.mkdir(mode=0o700, parents=True)
    for name in ("bundle", "catalog", "journal"):
        (target / name).mkdir(mode=0o700)
    (root / "w").mkdir(mode=0o700)
    for name in ("bundle/receipt.json", "bundle/file.pgp", "catalog/catalog.pgp", "journal/fragments.json", "core.json"):
        write(target / name, b"fixture")
    write(target / "catalog/receipt.json", dict(cipher_sha256="a" * 64))
    for i in range(3):
        fragment = target / f"journal/fragment-{i:04}"
        fragment.mkdir(mode=0o700)
        write(fragment / "replicas.json", dict(copies=[dict(charge=c) for c in (
            ("committed", "uncertain") if i == 0 else ("unattempted", "unattempted"))]))
        for index in range(2):
            directory = fragment / f"copy-{index}"
            directory.mkdir(mode=0o700)
            write(directory / "archive.json", dict(owner_key="fixture", provider_key=str(index),
                grant_hex="bound", archive_id=[i, index], sha256="fixture", ciphertext_bytes=7,
                requested_expiry=123, lease="first" if (i, index) == (0, 0) else None))
    return target


class Retained(unittest.TestCase):
    def test_source_profile_and_original_ui_stay_distinct(self):
        provision = runpy.run_path(str(HERE / "cloud-private-upload-provision.py"))
        self.assertEqual(provision["configured"]()["load_pins"]()["revision"], "178592a3881d49f839f7716a154f7ef446ecbda5")
        new = provision["configured"](True)["load_pins"]()
        self.assertEqual(new["revision"], "720f88f2a639ef5e2eecbba18c7bb2acb93f9645")
        with mock.patch.dict(os.environ, CLOUD_UPLOAD_PROFILE="retained-owner"):
            smoke = runpy.run_path(str(HERE / "cloud-private-upload-smoke.py"))
            self.assertEqual((smoke["PINS"], smoke["REVISION"]), (new, new["revision"]))
        script = HERE / "run-alpha-topology-vm.sh"
        for scenario, expected in (("cloud-private-upload", 0), ("cloud-private-file", 64)):
            run = subprocess.run(["sh", script, "--preview", "--scenario", scenario, "--cloud-owner-resume"],
                                 capture_output=True, timeout=10)
            self.assertEqual(run.returncode, expected)
            if not expected:
                self.assertIn(b"Retained-owner profile", run.stdout)

    def test_interruption_needs_real_selection_and_incomplete_http_result(self):
        value = UPLOAD["ui_failure"]()
        value["uploaded_file_listed"] = value["upload_201_observed"] = False
        output = CHECK["interrupted_ui"](value)
        self.assertEqual(output["puts"], 1)
        for key, invalid in (("stage", "cleanup"), ("uploaded_file_listed", True), ("private_profile_removed", False),
                             ("upload_observation", dict(puts=1, created=1, statuses=[201]))):
            with self.assertRaises(ValueError):
                CHECK["interrupted_ui"](dict(value, **{key: invalid}))

    def test_reopens_identical_journal_and_preserves_preexisting_lease(self):
        for tamper in (None, "lease", "grant_hex", "extra_object", "staging"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                obj = prepared(root)
                if tamper == "staging":
                    (obj / "journal/.fragment-transfer-stranded").mkdir()
                calls = 0

                def command(args, deadline):
                    nonlocal calls
                    self.assertEqual(args[2:5], ["resume-upload", "--config", root / "service.json"])
                    self.assertEqual(json.loads((root / "resume-request.json").read_bytes())["name"], "private-upload.bin")
                    calls += 1
                    if calls == 1:
                        for path in (obj / "journal").rglob("replicas.json"):
                            write(path, {"copies": [{"charge": "committed"}] * 2})
                        for index, path in enumerate(sorted((obj / "journal").rglob("archive.json"))):
                            item = json.loads(path.read_bytes())
                            if tamper in ("lease", "grant_hex") and index == 0:
                                item[tamper] = "replaced"
                            if item["lease"] is None:
                                item["lease"] = str(index)
                            write(path, item)
                        write(obj / "READY.json", dict(version=1, catalogSha256="a" * 64))
                        if tamper == "extra_object":
                            (obj.parent / ("object-" + "b" * 32)).mkdir(mode=0o700)
                    return dict(version=1, kind="volparossa-cloud-owner-upload-resume", state="ready")

                def run():
                    return CHECK["resume"](root, Path("/irrelevant"), "/unused", 7,
                        lambda _: dict(lengths=[2, 2, 3]), dict(bearerToken="fixture"), write, command)

                if tamper:
                    with self.assertRaises(ValueError):
                        run()
                else:
                    recovery = run()
                    self.assertEqual((recovery["committed_before"], recovery["uncertain_before"], calls), (1, 1, 2))
                    interrupted = CHECK["interrupted_ui"](UPLOAD["ui_failure"]())
                    CHECK["validate"](dict(interrupted_ui=interrupted, recovery=recovery), 6)
                    for key, invalid in (("unattempted_before", 0), ("committed_before", 6), ("same_ready_marker", False)):
                        altered = dict(recovery, **{key: invalid})
                        with self.assertRaises(ValueError):
                            CHECK["validate"](dict(interrupted_ui=interrupted, recovery=altered), 6)
                self.assertFalse((root / "resume-request.json").exists())


if __name__ == "__main__":
    unittest.main()
