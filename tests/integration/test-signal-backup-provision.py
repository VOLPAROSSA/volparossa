#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure provisioner bounds/layout checks; no downloads, compilation or native launch."""

import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = runpy.run_path(str(Path(__file__).with_name("signal-backup-provision.py")))
GLOBALS = MODULE["check_pins"].__globals__


class SignalProvision(unittest.TestCase):
    def source_failure(self):
        return dict(version=1, kind="signal-source-staging-failure", phase="archive_fetch",
                    category="http", error_type="http_error", http_status=503)

    def write_source_failure(self, root, value):
        path = root / "build/signal-source-error.json"
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)
        path.chmod(0o600)
        return path

    def test_closed_source_failure_projection_preserves_only_exact_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for category, error_type in (("http", "http_error"), ("tls", "tls_error"),
                    ("timeout", "timeout_error"), ("network", "dns_error"), ("network", "url_error"),
                    ("validation", "invalid_source"), ("io", "os_error"), ("unknown", "unknown_error")):
                value = dict(self.source_failure(), category=category, error_type=error_type, http_status=None)
                path = self.write_source_failure(root, value)
                original = path.read_bytes()
                self.assertEqual(MODULE["source_error_projection"](root), value)
                self.assertEqual(path.read_bytes(), original)
            value = self.source_failure()
            self.write_source_failure(root, value)
            self.assertEqual(MODULE["source_error_projection"](root), value)

    def test_source_failure_rejects_missing_unknown_duplicate_and_wrong_types(self):
        base = self.source_failure()
        invalid = [dict(base, message="private sentinel"), dict(base, version=True), dict(base, version=2),
                   dict(base, kind="unknown"), dict(base, phase="unknown"), dict(base, category="unknown"),
                   dict(base, error_type="private sentinel"), dict(base, http_status="503"),
                   dict(base, http_status=True), dict(base, http_status=503.0), dict(base, http_status=600),
                   dict(base, category="network", error_type="url_error"), dict(base, phase=[]),
                   dict(base, category={}), [], "{", json.dumps(base)[:-1] + ',"version":1}',
                   " " * 513 + json.dumps(base)]
        invalid += [{key: item for key, item in base.items() if key != missing} for missing in base]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(MODULE["source_error_projection"](root))
            for value in invalid:
                with self.subTest(value=value):
                    self.write_source_failure(root, value)
                    self.assertIsNone(MODULE["source_error_projection"](root))

    def test_source_failure_file_tampering_is_not_projected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_source_failure(root, self.source_failure())
            path.chmod(0o644)
            self.assertIsNone(MODULE["source_error_projection"](root))
            path.chmod(0o600)
            moved = path.with_name("private-original.json")
            path.rename(moved)
            path.symlink_to(moved.name)
            self.assertIsNone(MODULE["source_error_projection"](root))
            path.unlink()
            MODULE["os"].link(moved, path)
            self.assertIsNone(MODULE["source_error_projection"](root))

    def test_failed_source_retains_original_failure_and_only_joined_closed_diagnostic(self):
        for joined in (True, False):
            with self.subTest(joined=joined), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "runtime"

                def supervised(*_args, **_kwargs):
                    self.write_source_failure(root, self.source_failure())
                    return dict(result="INSTALL_COMMAND_FAILED", process_group_joined=joined,
                                exit_code=1, elapsed_seconds=0.256)

                supervisor = SimpleNamespace(run_bounded=supervised)
                old_umask = MODULE["os"].umask(0o077)
                try:
                    with patch.dict(GLOBALS, guard=lambda _root: None, fetch=lambda *_args: None,
                                    load_supervisor=lambda _root: supervisor), self.assertRaises(ValueError):
                        MODULE["provision"](root)
                finally:
                    MODULE["os"].umask(old_umask)
                report = json.loads((root / "provision.json").read_text())
                self.assertFalse(report["success"])
                self.assertEqual(report["phase"], "source")
                self.assertEqual(len(report["steps"]), 1)
                self.assertEqual(report["steps"][0]["result"], "INSTALL_COMMAND_FAILED")
                self.assertEqual(report.get("source_error"), self.source_failure() if joined else None)

    def test_fragment_trial_uses_its_exact_separate_source_inventory(self):
        candidate = runpy.run_path(str(Path(__file__).with_name("signal-backup-provision.py")))
        scope = candidate["select_fragment_trial"].__globals__
        entries = {name: dict(bytes=size, sha256=sha) for name, (size, sha) in candidate["FILES"].items()}
        for name in ("overlay/ts/services/backups/volparossa/fragments.node.ts",
                     "overlay/ts/services/backups/volparossa/storage.node.ts",
                     "overlay/ts/test-mock/backups/volparossa-withdrawal.node.ts"):
            entries[name] = dict(bytes=1, sha256="a" * 64)
        value = dict(version=1, chat_revision="a" * 40, signal_revision=candidate["SIGNAL_REVISION"], files=entries)
        with patch.dict(scope, read_json=lambda _path: value):
            candidate["select_fragment_trial"]()
            self.assertEqual(scope["CHAT_REVISION"], "a" * 40)
            self.assertTrue(scope["FRAGMENT_TRIAL"])
            self.assertEqual(len(scope["FILES"]), 17)
        self.assertEqual(MODULE["CHAT_REVISION"], "c897667d76bea8140f0bc5f373404e43cbd54552")
        self.assertEqual(len(MODULE["FILES"]), 14)
        candidate = runpy.run_path(str(Path(__file__).with_name("signal-backup-provision.py")))
        value["signal_revision"] = "b" * 40
        with patch.dict(candidate["select_fragment_trial"].__globals__, read_json=lambda _path: value), self.assertRaises(ValueError):
            candidate["select_fragment_trial"]()

    def test_exact_revision_and_small_source_allowlist_required(self):
        MODULE["check_pins"]()
        for revision in ("", "main", "0" * 40, "f" * 41):
            with patch.dict(GLOBALS, CHAT_REVISION=revision), self.assertRaises(ValueError):
                MODULE["check_pins"]()
        changed = dict(MODULE["FILES"])
        changed["../escape"] = changed.pop("LICENSE")
        with patch.dict(GLOBALS, FILES=changed), self.assertRaises(ValueError):
            MODULE["check_pins"]()

    def test_source_fetch_requires_exact_url_length_and_hash(self):
        url = "https://fixture.invalid/pinned"
        class Response(io.BytesIO):
            def geturl(self):
                return url
        for data, expected, digest, ok in ((b"fixed", 5, hashlib.sha256(b"fixed").hexdigest(), True),
                                          (b"larger", 5, "0" * 64, False),
                                          (b"tiny", 5, "0" * 64, False),
                                          (b"fixed", 5, "0" * 64, False)):
            with tempfile.TemporaryDirectory() as directory, \
                 patch.object(MODULE["urllib"].request, "urlopen", return_value=Response(data)):
                target = Path(directory) / "source"
                if ok:
                    MODULE["fetch"](url, target, expected, digest)
                    self.assertEqual(target.read_bytes(), data)
                    self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                else:
                    with self.assertRaises(ValueError):
                        MODULE["fetch"](url, target, expected, digest)
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(MODULE["urllib"].request, "urlopen", return_value=Response(b"fixed")), \
             self.assertRaises(ValueError):
            MODULE["fetch"]("https://different.invalid/pin", Path(directory) / "source", 5, "0" * 64)

    def test_share_only_runtime_tree_and_preserve_internal_links(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = parent / "runtime"
            runtime.mkdir(mode=0o700)
            private = parent / "private"
            private.mkdir(mode=0o700)
            (private / "secret").write_bytes(b"never shared")
            binary = runtime / "binary"
            binary.write_bytes(b"inert fixture")
            binary.chmod(0o700)
            license = runtime / "LICENSE"
            license.write_bytes(b"retained fixture notice")
            license.chmod(0o600)
            (runtime / "internal-link").symlink_to("binary")
            MODULE["expose_tree"](runtime)
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o555)
            self.assertEqual(binary.stat().st_mode & 0o777, 0o555)
            self.assertEqual(license.stat().st_mode & 0o777, 0o444)
            self.assertEqual((runtime / "internal-link").readlink(), Path("binary"))
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)

    def test_symlink_escape_or_privilege_mode_rejected_before_chmod(self):
        for failure in ("symlink", "setuid"):
            with tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                runtime = parent / "runtime"
                runtime.mkdir(mode=0o700)
                member = runtime / "member"
                if failure == "symlink":
                    (parent / "outside").write_bytes(b"outside")
                    member.symlink_to(parent / "outside")
                else:
                    member.write_bytes(b"inert fixture")
                    member.chmod(0o4755)
                with self.assertRaises(ValueError):
                    MODULE["expose_tree"](runtime)
                self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)

    def test_compilation_receipt_requires_actual_outputs_and_all_four_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / MODULE["CANDIDATE"]
            candidate.mkdir(parents=True)
            output = candidate / "fixture"
            output.write_bytes(b"compiled fixture bytes")
            state = root / "build/signal-candidate-build"
            state.mkdir()
            receipt = state / "attempt-fixture.json"
            report = dict(source=MODULE["SIGNAL_REVISION"], lock_sha256=MODULE["LOCK_SHA256"],
                preparatory_compilation_succeeded=True, native_app_started=False,
                signal_backup_runtime_proven=False, steps=[dict(name=name, succeeded=True,
                    original_source_and_lock_unchanged=True, process_group_joined=True,
                    result="COMPILED", output_sha256={"fixture": MODULE["digest"](output)})
                    for name in ("types", "windows-ucv", "mock-server", "app-assets")])
            receipt.write_text(json.dumps(report))
            self.assertEqual(MODULE["compile_receipt"](root), MODULE["digest"](receipt))
            output.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                MODULE["compile_receipt"](root)
            report["native_app_started"] = True
            receipt.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                MODULE["compile_receipt"](root)

    def test_plan_keeps_native_app_and_preload_execution_separate(self):
        steps = MODULE["STEPS"]
        self.assertEqual([name for name, *_ in steps], ["source", "node", "pnpm", "overlay",
            "dependencies", "electron-archive", "ringrtc-archive", "electron-materialize",
            "ringrtc-materialize", "compile"])
        self.assertTrue(all(script.startswith(("stage_", "apply_", "install_", "build_"))
                            and 0 < timeout <= 2640 for _, script, _, timeout in steps))
        self.assertNotIn("preload", json.dumps(steps))
        self.assertEqual(steps[-1][2], ("--build",))


if __name__ == "__main__":
    unittest.main()
