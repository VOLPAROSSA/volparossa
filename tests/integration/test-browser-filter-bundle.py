#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert transfer tests: no Firefox, Browser imports, network or VM execution."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import tarfile
import tempfile
import unittest

B = runpy.run_path(str(Path(__file__).with_name("browser-filter-bundle.py")))


class BrowserFilterBundle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="browser-filter-bundle-test-")
        self.root = Path(self.temporary.name).resolve()
        self.source, self.stage = self.root / "source", self.root / "stage"
        self.source.mkdir(mode=0o700)
        self.stage.mkdir(mode=0o700)
        for name in B["SOURCE_FILES"]:
            data = ("synthetic source " + name + "\n").encode()
            if name.startswith("scripts/"):
                data = b"# inert dependency\nraise RuntimeError('capture must never execute this input')\n"
            self.put(self.source / name, data)
        imports = "\n".join("import " + name for name in sorted(B["SCRIPTS"] - {"smoke_filter_delivery"}))
        self.put(self.source / "scripts/smoke_filter_delivery.py", (imports + "\nraise RuntimeError('not executable input')\n").encode())
        for name in B["RUNTIME_FILES"]:
            self.put(self.stage / name, ("synthetic retained runtime " + name + "\n").encode(),
                     0o755 if B["STAGE"] + name in B["EXECUTABLES"] else 0o664)
        self.archive = self.root / "inputs.tar"

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def put(path, data, mode=0o600):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def capture(self):
        return B["capture"](self.source, self.stage, self.archive)

    def unpack(self, receipt, name="unpacked"):
        target = self.root / name
        B["checked_archive"](self.archive, receipt["manifest_sha256"], target)
        return target

    def members(self):
        with tarfile.open(self.archive, "r:") as archive:
            return [(item.name, archive.extractfile(item).read(), item.mode) for item in archive]

    def rewrite(self, entries, suffix=b"\0" * 1024):
        with self.archive.open("wb") as output:
            for name, raw, mode in entries:
                output.write(B["header"](name, len(raw), mode))
                output.write(raw)
                output.write(b"\0" * (-len(raw) % 512))
            output.write(suffix)

    def test_roundtrip_is_deterministic_preserves_xpis_and_never_executes_input(self):
        original = self.stage / "distribution/extensions/uBlock0@raymondhill.net.xpi"
        before = original.read_bytes(), original.stat().st_mode
        receipt = self.capture()
        second = self.root / "second.tar"
        again = B["capture"](self.source, self.stage, second)
        self.assertEqual(receipt, again)
        self.assertEqual(self.archive.read_bytes(), second.read_bytes())
        self.assertEqual(receipt["files"], len(B["FILES"]))
        self.assertEqual(receipt, B["checked_archive"](self.archive, receipt["manifest_sha256"]))
        target = self.unpack(receipt)
        self.assertEqual(original.read_bytes(), (target / B["STAGE"] / original.relative_to(self.stage)).read_bytes())
        self.assertEqual(before, (original.read_bytes(), original.stat().st_mode))
        report = B["verify_tree"](target, receipt["manifest_sha256"])
        self.assertFalse(report["private_output_inspected"])
        for name in B["FILES"]:
            self.assertEqual(stat.S_IMODE((target / name).stat().st_mode), B["mode"](name))
        for directory, subdirs, _files in os.walk(target):
            self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)

    def test_wrong_independent_hash_refuses_before_destination_creation(self):
        self.capture()
        target = self.root / "no-output"
        with self.assertRaises(ValueError):
            B["checked_archive"](self.archive, "f" * 64, target)
        self.assertFalse(target.exists())

    def test_runtime_inventory_is_exact(self):
        self.put(self.stage / "unexpected.so", b"extra")
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse(self.archive.exists())

    def test_missing_runtime_file_is_not_silently_omitted(self):
        (self.stage / "libxul.so").unlink()
        with self.assertRaises(ValueError):
            self.capture()

    def test_missing_or_expanded_python_import_closure_is_rejected(self):
        driver = self.source / "scripts/smoke_filter_delivery.py"
        original = driver.read_bytes()
        for raw in (b"import os\n", original + b"import unpublished_dependency\n", original + b"from . import sibling\n"):
            with self.subTest(raw=raw[-40:]):
                driver.write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.capture()
                self.assertFalse(self.archive.exists())

    def test_unsafe_source_symlink_hardlink_fifo_and_modes_are_rejected(self):
        source = self.source / "defaults/privacy.json"
        original = source.read_bytes()
        source.unlink()
        replacement = self.root / "other.json"
        self.put(replacement, original)
        source.symlink_to(replacement)
        with self.assertRaises(ValueError): self.capture()
        source.unlink()
        os.link(replacement, source)
        with self.assertRaises(ValueError): self.capture()
        source.unlink()
        os.mkfifo(source, 0o600)
        with self.assertRaises(ValueError): self.capture()
        source.unlink()
        self.put(source, original)
        for mode in (0o606, 0o4600, 0o2600, 0o1600):
            source.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.capture()

    def test_existing_archive_and_destination_are_never_overwritten(self):
        receipt = self.capture()
        before = self.archive.read_bytes()
        with self.assertRaises(ValueError): self.capture()
        self.assertEqual(before, self.archive.read_bytes())
        target = self.unpack(receipt)
        with self.assertRaises(ValueError):
            B["checked_archive"](self.archive, receipt["manifest_sha256"], target)

    def test_duplicate_missing_extra_and_trailing_members_are_rejected(self):
        receipt = self.capture()
        entries = self.members()
        cases = (entries + [entries[-1]], entries[:-1],
                 [entries[0], entries[0], *entries[2:]],
                 [*entries, ("../escape", b"bad", 0o600)])
        for entries_ in cases:
            with self.subTest(names=[x[0] for x in entries_[-2:]]):
                self.rewrite(entries_)
                with self.assertRaises(ValueError):
                    B["checked_archive"](self.archive, receipt["manifest_sha256"])
        self.rewrite(entries, suffix=b"\0" * 1024 + b"hidden" + b"\0" * 506)
        with self.assertRaises(ValueError):
            B["checked_archive"](self.archive, receipt["manifest_sha256"])

    def test_payload_corruption_leaves_no_accepted_manifest(self):
        receipt = self.capture()
        entries = self.members()
        name, raw, mode = entries[1]
        entries[1] = name, bytes([raw[0] ^ 1]) + raw[1:], mode
        self.rewrite(entries)
        target = self.root / "partial"
        with self.assertRaises(ValueError):
            B["checked_archive"](self.archive, receipt["manifest_sha256"], target)
        self.assertFalse((target / "INPUTS.json").exists())

    def test_archive_header_modes_and_links_cannot_grant_execution_or_escape(self):
        receipt = self.capture()
        original = self.archive.read_bytes()
        entries = self.members()
        offset = 512 + len(entries[0][1]) + (-len(entries[0][1]) % 512)
        name, raw, mode = entries[1]
        for permissions, kind in ((0o777, tarfile.REGTYPE), (mode, tarfile.SYMTYPE),
                                  (mode, tarfile.LNKTYPE), (mode, tarfile.XHDTYPE)):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.type = len(raw), permissions, kind
            malformed = entry.tobuf(format=tarfile.USTAR_FORMAT)
            self.archive.write_bytes(original[:offset] + malformed + original[offset + 512:])
            with self.subTest(permissions=permissions, kind=kind), self.assertRaises(ValueError):
                B["checked_archive"](self.archive, receipt["manifest_sha256"])

    def test_manifest_schema_duplicate_keys_paths_bounds_and_modes_are_closed(self):
        receipt = self.capture()
        entries = self.members()
        original = json.loads(entries[0][1])
        for fault in ("version", "path", "negative", "huge", "bool_size", "mode", "extra"):
            value = json.loads(entries[0][1])
            name = sorted(value["files"])[0]
            if fault == "version": value["version"] = True
            elif fault == "path": value["files"]["../escape"] = value["files"].pop(name)
            elif fault == "negative": value["files"][name]["bytes"] = -1
            elif fault == "huge": value["files"][name]["bytes"] = B["MAX_FILE"] + 1
            elif fault == "bool_size": value["files"][name]["bytes"] = True
            elif fault == "mode": value["files"][name]["mode"] = 0o777
            else: value["extra"] = "ignored?"
            raw = B["encode"](value)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                B["manifest"](raw, hashlib.sha256(raw).hexdigest())
        raw = entries[0][1].replace(b'"version":1', b'"version":1,"version":1')
        with self.assertRaises(ValueError): B["manifest"](raw, hashlib.sha256(raw).hexdigest())
        value = original
        for name in value["files"]:
            value["files"][name]["bytes"] = B["bound"](name)
        raw = B["encode"](value)
        with self.assertRaises(ValueError): B["manifest"](raw, hashlib.sha256(raw).hexdigest())

    def test_tree_verification_allows_only_named_output_and_detects_input_changes(self):
        receipt = self.capture()
        target = self.unpack(receipt)
        output = target / B["OUTPUT"]
        output.mkdir(mode=0o700)
        self.put(output / "private.log", b"not input evidence")
        B["verify_tree"](target, receipt["manifest_sha256"])
        extra = target / "scripts/unreviewed.py"
        self.put(extra, b"unreviewed")
        with self.assertRaises(ValueError): B["verify_tree"](target, receipt["manifest_sha256"])
        extra.unlink()
        source = target / "defaults/privacy.json"
        source.chmod(0o644)
        with self.assertRaises(ValueError): B["verify_tree"](target, receipt["manifest_sha256"])
        source.chmod(0o600)
        source.write_bytes(b"changed input")
        with self.assertRaises(ValueError): B["verify_tree"](target, receipt["manifest_sha256"])


if __name__ == "__main__":
    unittest.main()
