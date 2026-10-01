#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure provision boundary checks, never download, install or run an Cloud snapshot."""

import hashlib
import io
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cloud_provision", HERE / "cloud-private-file-provision.py")
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)


class CloudProvision(unittest.TestCase):
    def test_exact_cloud_and_node_pins_retain_licenses(self):
        pins = PROVISION.load_pins()
        self.assertEqual(pins["revision"], "541cc826fe14ce69cf89a82ecb600ad14dd534c6")
        self.assertEqual(set(pins["files"]), {
            "scripts/cloud-file.mjs", "scripts/private_file.py", "src/private-file.mjs", "src/opencloud-dav.mjs",
            "vendor/volparossa-image/immich_snapshot.py", "vendor/volparossa-image/core-storage.mjs",
            "vendor/volparossa-image/LICENSE", "third_party/volparossa-image-source.json", "LICENSE"})
        self.assertEqual(set(pins["runtime"]["files"]), {"bin/node", "LICENSE"})
        self.assertEqual(pins["runtime"]["version"], "24.19.0")
        self.assertEqual(pins["files"]["vendor/volparossa-image/LICENSE"], pins["files"]["LICENSE"])

    def test_guest_guard_refuses_before_subprocess_or_mutation(self):
        with mock.patch.object(PROVISION.os, "geteuid", return_value=0), \
                mock.patch.object(PROVISION.socket, "gethostname", return_value="developer-host"), \
                mock.patch.object(PROVISION.subprocess, "check_output") as execute:
            with self.assertRaises(ValueError):
                PROVISION.guard()
            execute.assert_not_called()

    def test_download_requires_explicit_flag(self):
        result = subprocess.run([sys.executable, "-B", str(HERE / "cloud-private-file-provision.py"), "provision"],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--download", result.stderr)
        self.assertNotIn("verified", result.stdout)

    def test_exact_file_verification_rejects_mutation_and_links(self):
        with tempfile.TemporaryDirectory(prefix="image-source-check-") as temporary:
            root = Path(temporary)
            source = root / "source.mjs"
            data = b"fixture source, not a runtime proof\n"
            source.write_bytes(data)
            records = {source.name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())}
            PROVISION.verify_files(root, records)
            source.write_bytes(data[:-1] + b"x")
            with self.assertRaises(ValueError):
                PROVISION.verify_files(root, records)
            original = root / "other"
            source.rename(original)
            source.symlink_to(original)
            with self.assertRaises(ValueError):
                PROVISION.verify_files(root, records)

    def test_reused_node_extractor_never_extracts_other_paths(self):
        stage = PROVISION.loader()
        members = {"bin/node": b"test-node", "LICENSE": b"test-license"}
        expected = {name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    for name, data in members.items()}
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode="w") as archive:
            for name, data in {**members, "bin/npm": b"not selected"}.items():
                member = tarfile.TarInfo(stage["NODE"] + "/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        packed.seek(0)
        with tempfile.TemporaryDirectory(prefix="image-runtime-check-") as temporary:
            with tarfile.open(fileobj=packed) as archive:
                stage["extract_runtime"](archive, Path(temporary), expected)
            actual = {str(path.relative_to(temporary)) for path in Path(temporary).rglob("*") if path.is_file()}
            self.assertEqual(actual, set(expected))
            self.assertEqual(os.stat(Path(temporary) / "bin/node").st_mode & 0o777, 0o700)

    def test_reused_node_extractor_rejects_link_target(self):
        stage = PROVISION.loader()
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode="w") as archive:
            member = tarfile.TarInfo(stage["NODE"] + "/bin/node")
            member.type = tarfile.SYMTYPE
            member.linkname = "/bin/sh"
            archive.addfile(member)
        packed.seek(0)
        with tempfile.TemporaryDirectory(prefix="image-runtime-check-") as temporary:
            with tarfile.open(fileobj=packed) as archive, self.assertRaises(ValueError):
                stage["extract_runtime"](archive, Path(temporary), {"bin/node": dict(bytes=0, sha256="0" * 64)})


if __name__ == "__main__":
    unittest.main()
