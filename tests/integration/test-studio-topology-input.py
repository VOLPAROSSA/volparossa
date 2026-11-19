#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-only checks for same-run admission. Runtime separately authenticates and renders."""
import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

MODULE = runpy.run_path(str(Path(__file__).with_name("studio-topology-input.py")))
SHA = MODULE["digest"]
CORE, STUDIO, RUN, ATTEMPT = "a"*40, "b"*40, "101", "2"

def write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)

class StudioInput(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.chart = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + bytes.fromhex("0000040000000300") + bytes(MODULE["CHUNK"])
        self.assets = {MODULE["CHART"]: self.chart, "/index.html": b"index", "/studio-export.html":
                       b'<!doctype html><img src="assets/studio-topology.png">', "/theme.css": b"style"}
        # The admission helper checks the hashed canonical payload boundaries.
        # The production SiteBundle decoder checks the complete protobuf index.
        self.bundle = b"\0\0\0\1x" + b"".join(self.assets.values())
        self.manifest = b"test manifest identity"
        self.evidence = dict(schema=1, kind="silex-topology-handoff", run_id=RUN, run_attempt=ATTEMPT,
            core_revision=CORE, studio_revision=STUDIO, silex_revision=MODULE["SILEX"], asset_count=4,
            assets=[dict(path=p, bytes=len(v), sha256=SHA(v)) for p, v in self.assets.items()],
            bundle_bytes=len(self.bundle), bundle_sha256=SHA(self.bundle), chunk_count=2, manifest_id=SHA(self.manifest),
            publisher_key="3"*64, name=MODULE["NAME"], revision=1, publication_expires_unix_seconds=1, zip_sha256="4"*64)
        write(self.root / "manifest.bin", self.manifest)
        write(self.root / "site.vps", self.bundle)

    def admit(self, evidence=None, context=(RUN, ATTEMPT, STUDIO)):
        raw = (json.dumps(evidence or self.evidence, sort_keys=True) + "\n").encode()
        write(self.root / "evidence.json", raw)
        return MODULE["admit"](self.root, SHA(raw), CORE, context)

    def test_exact_projection_and_independent_range(self):
        result = self.admit()
        self.assertEqual(result["chunks"], 2)
        self.assertEqual(result["byte_range"], dict(path=MODULE["CHART"], start=101, end=4196,
                                                   sha256=SHA(self.chart[101:4197])))
        self.assertEqual(result["assets"][MODULE["CHART"]]["content_type"], "image/png")
        self.assertEqual(result["studio_handoff"], self.evidence)

    def test_rejects_changed_bytes_and_foreign_attempt(self):
        for key, value in (("run_id", "9"), ("run_attempt", "1"), ("core_revision", "d"*40),
                           ("studio_revision", "e"*40), ("silex_revision", "f"*40), ("chunk_count", 9),
                           ("bundle_sha256", "0"*64), ("manifest_id", "1"*64), ("signing_key", "x")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.admit(dict(self.evidence, **{key: value}))
        for changed in ("sha256", "bytes", "path"):
            data = copy.deepcopy(self.evidence)
            data["assets"][0][changed] = {"sha256": "2"*64, "bytes": 1, "path": "/../stolen"}[changed]
            with self.subTest(field=changed), self.assertRaises(ValueError):
                self.admit(data)
        self.admit()
        with self.assertRaises(ValueError):
            MODULE["admit"](self.root, "0"*64, CORE)
        write(self.root / "site.vps", self.bundle[:-1])
        with self.assertRaises(ValueError):
            self.admit()

    def test_joined_report_requires_original_signature_real_browser_and_protected_transfer(self):
        repair = runpy.run_path(str(Path(__file__).with_name("test-content-repair-smoke.py")))
        fixture = repair["fixture"]()
        site = fixture["offline_site"]
        expiry = site["publish"]["expires_unix_seconds"]
        self.evidence["publication_expires_unix_seconds"] = expiry
        expected = self.admit()
        size, chunks = expected["bundle_bytes"], expected["chunks"]
        site["input"] = expected
        key, name, sha = expected["publisher_key"], expected["name"], expected["bundle_sha256"]
        manifest = self.evidence["manifest_id"]
        site["publish"].update(operation="content_contribute", name=name, publisher_key_hex=key, manifest_id=manifest,
                              bytes=size, chunks=chunks, original_signature_reused=True, private_keys_transferred=False,
                              ownership_changed=False, origin_authenticated=False)
        site["acquire"].update(name=name, publisher_key=key, manifest_id=manifest, sha256=sha,
                              bytes=size, peer_bytes=size, chunks=chunks)
        site["acquisition_removed"].update(bytes=size, sha256=sha)
        site["holder"].update(replica_chunks=3 + chunks, replica_bytes=3 * MODULE["CHUNK"] + size)
        viewer = site["viewer"]
        for label in ("ready", "final"):
            viewer[label].update(name=name, publisher_key=key, manifest_id=manifest, sha256=sha, bytes=size,
                                 peer_bytes=size, chunks=chunks, assets=len(self.assets))
        viewer["assets"] = {path: dict(asset, status=200, content_length=str(asset["bytes"]),
                                      security_headers_verified=True) for path, asset in expected["assets"].items()}
        viewer["head"]["content_length"] = str(len(self.chart))
        viewer["byte_range"].update(sha256=expected["byte_range"]["sha256"], content_range=f"bytes 101-4196/{len(self.chart)}")
        viewer["browser_engine_executed"] = True
        viewer["recipient_browser"] = dict(engine="firefox-esr", version="140.16.0", edited_page=True,
            visible_marker=True, computed_37px=True, chart_decoded=True, chart_width=1024, chart_height=768,
            browser_closed=True, profile_removed=True)

        def verify(candidate):
            repair["CHECK"]["validate_offline_site"](candidate, fixture["expected_peers"], fixture["holder_offline"])

        verify(site)
        for location, leaf, value in ((("publish",), "original_signature_reused", False),
                                     (("publish",), "manifest_id", "6"*64),
                                     (("acquire",), "peer_bytes", size - 1),
                                     (("viewer", "recipient_browser"), "chart_decoded", False),
                                     (("viewer", "ready"), "peer_bytes", 0),
                                     (("viewer", "assets", MODULE["CHART"]), "sha256", "7"*64),
                                     (("view", "captures", "exit"), "provider_response_payload_bytes", size-1),
                                     (("boundary",), "pid_listener_and_unit_absent_before_and_after", False)):
            changed = copy.deepcopy(site)
            field = changed
            for part in location:
                field = field[part]
            field[leaf] = value
            with self.subTest(location=location, leaf=leaf), self.assertRaises(ValueError):
                verify(changed)

    def test_host_guards_stop_before_source_probes_and_symlink_cleanup(self):
        script = Path(__file__).with_name("studio-topology-host.sh").resolve()
        git = self.root / "git"
        git.write_text('#!/bin/sh\n: > "$SENTINEL"\nexit 91\n')
        git.chmod(0o700)
        sentinel = self.root / "source-probed"
        env = dict(os.environ, PATH=f'{self.root}:/usr/bin:/bin', SENTINEL=str(sentinel),
            GITHUB_ACTIONS="false", RUNNER_ENVIRONMENT="github-hosted", GITHUB_EVENT_NAME="workflow_dispatch",
            GITHUB_WORKFLOW="Quality", STUDIO_PROOF_MODE="signed-site-topology", STUDIO_CORE_REVISION=CORE, GITHUB_SHA=CORE)
        result = subprocess.run(["bash", str(script), "prepare"], env=env, capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(sentinel.exists())

        # Exercise the exact cleanup branch in a private disposable directory.
        target = self.root / "unrelated"
        target.mkdir(mode=0o700)
        original = target / "site.vps"
        write(original, b"keep this unrelated file")
        link = self.root / "studio-topology-handoff"
        link.symlink_to(target, target_is_directory=True)
        cleanup = script.read_text().split("\ncleanup)\n", 1)[1].split("\n    ;;", 1)[0]
        result = subprocess.run(["bash", "-eu", "-c", cleanup], env=dict(os.environ, stage=str(link)),
                                capture_output=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(original.read_bytes(), b"keep this unrelated file")
        self.assertTrue(link.is_symlink())

    def test_rejects_extra_files_and_links(self):
        extra = self.root / "signing.key"
        write(extra, b"test")
        with self.assertRaises(ValueError):
            self.admit()
        extra.unlink()
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.bin"
            manifest = self.root / "manifest.bin"
            manifest.rename(original)
            manifest.symlink_to(original)
            with self.assertRaises(OSError):
                self.admit()
            manifest.unlink()
            os.link(original, manifest)
            with self.assertRaises(ValueError):
                self.admit()
            manifest.unlink()
            original.rename(manifest)
            manifest.chmod(0o644)
            with self.assertRaises(ValueError):
                self.admit()

if __name__ == "__main__":
    unittest.main()
