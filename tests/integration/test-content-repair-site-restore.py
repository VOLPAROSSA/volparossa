#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert tests of the disposable owner's handoff, independent of native CLI execution."""

import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

MODULE = runpy.run_path(str(Path(__file__).with_name("content-repair-site-restore.py")))
SITE = MODULE["SITE"]


class RestoredOwner(unittest.TestCase):
    def new_owner(self, parent):
        root = Path(parent) / "site-publisher"
        root.mkdir(mode=0o700)
        SITE["initialize"](root)
        SITE["write_new"](root / "identity.key", b"test signer")
        SITE["write_new"](root / "bundle.bin", b"original bytes")
        return root

    def test_owner_files_and_retained_cache_are_gone_before_handoff(self):
        candidate = b"reviewed signed bytes"
        digest = hashlib.sha256(candidate).hexdigest()

        def stage(_cli, scratch, original):
            self.assertEqual(original.read_bytes(), b"original bytes")
            self.assertTrue(all((scratch / name).exists() for name in ("identity.key", "passphrase", "assets")))
            (scratch / "owner-cache").mkdir(mode=0o700)
            for name in (".volparossa-named-manifests-v1", ".volparossa-name-revisions-v1"):
                SITE["write_new"](scratch / "owner-cache" / name, b"private test state")
            SITE["write_new"](scratch / "candidate.pb", candidate)
            return dict(candidate=dict(manifest_id=digest))

        prepare = MODULE["prepare"]
        with tempfile.TemporaryDirectory() as parent:
            root = self.new_owner(parent)
            overrides = dict(SITE_BYTES=len(b"original bytes"), SITE_SHA=hashlib.sha256(b"original bytes").hexdigest(),
                             restore_owner=stage)
            with patch.dict(prepare.__globals__, overrides):
                report = prepare("unused", root)
            self.assertTrue(report["owner_state_removed"])
            self.assertEqual({path.name for path in root.iterdir()}, {"bundle.bin", "manifest.bin"})
            self.assertEqual((root / "manifest.bin").read_bytes(), candidate)
            self.assertEqual((root / "manifest.bin").stat().st_nlink, 1)
            self.assertEqual((root / "bundle.bin").read_bytes(), b"original bytes")
            self.assertTrue(all(SITE["remove_publisher"](root).values()))

    def test_unexpected_input_is_preserved_before_owner_setup(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.new_owner(parent)
            SITE["write_new"](root / "manifest.bin", b"already exists")
            with self.assertRaises(ValueError):
                MODULE["prepare"]("unused", root)
            self.assertEqual((root / "manifest.bin").read_bytes(), b"already exists")
            self.assertEqual((root / "identity.key").read_bytes(), b"test signer")

    def test_published_id_is_derived_from_the_manifest_on_disk(self):
        publish = MODULE["publish"]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            bundle, manifest = work / "bundle.bin", work / "source.pb"
            SITE["write_new"](bundle, b"input")
            SITE["write_new"](manifest, b"disposable test manifest")
            key, sha = "a" * 64, hashlib.sha256(bundle.read_bytes()).hexdigest()
            manifest_id = hashlib.sha256(manifest.read_bytes()).hexdigest()
            signed = dict(operation="offline_content_publish", network_publication=False, name=SITE["NAME"],
                          content_type=SITE["CONTENT_TYPE"], revision=1, bytes=5, chunks=1, publisher_key_hex=key,
                          manifest_id=manifest_id, expires_unix_seconds=12345, cache="/private/cache")
            with patch.dict(publish.__globals__, content=lambda *_args: signed):
                self.assertEqual(publish("unused", work, key, 1, bundle, manifest.name, sha),
                                 dict(manifest_id=manifest_id, bundle_sha256=sha, revision=1, expires_unix_seconds=12345))
                signed["manifest_id"] = "f" * 64
                with self.assertRaises(ValueError):
                    publish("unused", work, key, 1, bundle, manifest.name, sha)


if __name__ == "__main__":
    unittest.main()
