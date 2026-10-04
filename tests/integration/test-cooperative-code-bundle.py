#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic transfer checks; no runtime or peer execution."""
import hashlib
import io
import json
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest

HERE = Path(__file__).parent
TRANSFER = runpy.run_path(str(HERE / "cooperative-code-bundle.py"))
FIXTURE = runpy.run_path(str(HERE / "test-agent-cooperative-code.py"))


def inputs(root):
    value = FIXTURE["manifest"]()
    for name, record in value["files"].items():
        path = root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = ("synthetic " + name).encode()
        path.write_bytes(data)
        path.chmod(record["mode"])
        record.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    value["opencode_binary_sha256"] = value["files"]["runtime/opencode"]["sha256"]
    raw = json.dumps(value, sort_keys=True).encode()
    (root / "INPUTS.json").write_bytes(raw)
    (root / "INPUTS.json").chmod(0o600)
    return hashlib.sha256(raw).hexdigest(), value


class Transfer(unittest.TestCase):
    def test_exact_inventory_roundtrip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            expected, value = inputs(source)
            archive, output = base / "bundle.tar", base / "unpacked"
            TRANSFER["capture"](source, archive, expected)
            TRANSFER["unpack"](archive, output, expected)
            for name, record in value["files"].items():
                self.assertEqual((source / name).read_bytes(), (output / name).read_bytes())
                self.assertEqual((output / name).stat().st_mode & 0o777, record["mode"])
            self.assertEqual((source / "INPUTS.json").read_bytes(), (output / "INPUTS.json").read_bytes())
            with self.assertRaises(ValueError):
                TRANSFER["capture"](source, archive, expected)
            with self.assertRaises(ValueError):
                TRANSFER["unpack"](archive, output, expected)

    def test_changed_input_and_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            expected, _ = inputs(base)
            with self.assertRaises(ValueError):
                TRANSFER["capture"](base, base / "wrong-pin.tar", "0" * 64)
            (base / "code/LICENSE").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                TRANSFER["capture"](base, base / "changed.tar", expected)

    def test_unlisted_paths_links_and_incomplete_inventory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            expected, _ = inputs(base)
            raw = (base / "INPUTS.json").read_bytes()
            for index, kind in enumerate(("traversal", "link", "incomplete")):
                archive, output = base / f"bad-{index}.tar", base / f"output-{index}"
                with tarfile.open(archive, "w") as bundle:
                    header = tarfile.TarInfo("INPUTS.json")
                    header.size, header.mode = len(raw), 0o600
                    bundle.addfile(header, io.BytesIO(raw))
                    if kind != "incomplete":
                        header = tarfile.TarInfo("../escape" if kind == "traversal" else "code/LICENSE")
                        if kind == "link":
                            header.type, header.linkname = tarfile.SYMTYPE, "/etc/passwd"
                        bundle.addfile(header)
                archive.chmod(0o600)
                with self.assertRaises(ValueError):
                    TRANSFER["unpack"](archive, output, expected)
                self.assertFalse((output / "INPUTS.json").exists())
                self.assertFalse((base / "escape").exists())


if __name__ == "__main__":
    unittest.main()
