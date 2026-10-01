#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Narrow native provenance/evidence checks, not a substitute for the live VM."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import selectors
import tempfile
import threading
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
RUNTIME = runpy.run_path(str(HERE / "browser-native-runtime.py"))
EVIDENCE = runpy.run_path(str(HERE / "browser-native-evidence.py"))
OLD = runpy.run_path(str(HERE / "test-browser-network-smoke.py"))


class NativeBrowserTests(unittest.TestCase):
    def test_pinned_marionette_window_handles_are_a_direct_array(self):
        tree = ast.parse((HERE / "browser-native-core.py").read_text())
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == "window_handles")
        namespace = dict(runtime=SimpleNamespace(require=RUNTIME["require"]))
        exec(compile(ast.Module(body=[helper], type_ignores=[]), "native-window-handles", "exec"), namespace)
        calls = []
        def command(name, parameters):
            calls.append((name, parameters))
            return ["fixture-window-a", "fixture-window-b"]
        self.assertEqual(namespace["window_handles"](SimpleNamespace(command=command)),
                         {"fixture-window-a", "fixture-window-b"})
        self.assertEqual(calls, [("WebDriver:GetWindowHandles", {})])
        for malformed in ({"value": ["fixture-window"]}, None, [3]):
            with self.assertRaises(ValueError):
                namespace["window_handles"](SimpleNamespace(command=lambda *_: malformed))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "driver_status":
                self.assertIn(node.args[1].value, OLD["CHECK"]["DRIVER_PHASES"])

    def test_native_stderr_is_bounded_and_exports_no_raw_content(self):
        tree = ast.parse((HERE / "browser-native-core.py").read_text())
        helpers = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                   and node.name in ("stderr_diagnostic", "StartupStderr")]
        namespace = dict(hashlib=hashlib, os=os, selectors=selectors, threading=threading)
        exec(compile(ast.Module(body=helpers, type_ignores=[]), "native-stderr-helpers", "exec"), namespace)
        read_fd, write_fd = os.pipe()
        reader = namespace["StartupStderr"](os.fdopen(read_fd, "rb"))
        payload = b"XPCOMGlueLoad error: private-canary-path\n" + b"x" * 100000
        def write():
            with os.fdopen(write_fd, "wb") as stream:
                stream.write(payload)
        writer = threading.Thread(target=write)
        writer.start()
        writer.join(timeout=3)
        self.assertFalse(writer.is_alive())
        diagnostic = reader.finish()
        self.assertEqual(diagnostic["captured_bytes"], 65536)
        self.assertEqual(diagnostic["total_bytes"], len(payload))
        self.assertTrue(diagnostic["truncated"] and diagnostic["eof"])
        self.assertTrue(diagnostic["observed"]["shared_library_load"])
        self.assertEqual(diagnostic["captured_sha256"], hashlib.sha256(payload[:65536]).hexdigest())
        self.assertNotIn("private-canary-path", json.dumps(diagnostic))

    def test_two_initial_tabs_preserve_exactly_two_new_tabs_and_reject_empty_baseline(self):
        tree = ast.parse((HERE / "browser-native-core.py").read_text())
        helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in ("window_handles", "initial_window_handles")]
        namespace = dict(runtime=SimpleNamespace(require=RUNTIME["require"]))
        exec(compile(ast.Module(body=helpers, type_ignores=[]), "native-tab-baseline", "exec"), namespace)
        replies = iter([["initial-a", "initial-b"], ["initial-a", "initial-b", "route-a", "route-b"]])
        client = SimpleNamespace(command=lambda *_: next(replies))
        initial = namespace["initial_window_handles"](client)
        self.assertEqual(initial, {"initial-a", "initial-b"})
        self.assertEqual(namespace["window_handles"](client) - initial, {"route-a", "route-b"})
        with self.assertRaises(ValueError):
            namespace["initial_window_handles"](SimpleNamespace(command=lambda *_: []))
        # Keep the actual driver check, not merely a two-item synthetic assertion.
        self.assertIn("require(len(handles) == 2)", (HERE / "browser-native-core.py").read_text())

    def test_inventory_excludes_private_proofs_but_rejects_runtime_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "runtime").write_bytes(b"public")
            (root / "build/proofs/session").mkdir(parents=True)
            (root / "build/proofs/session/grant.json").write_text("private-canary")
            self.assertEqual(set(RUNTIME["inventory"](root)), {"runtime"})
            (root / "alias").symlink_to(root / "runtime")
            with self.assertRaises(ValueError):
                RUNTIME["inventory"](root)

    def test_unknown_receipt_fails_without_executing_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "native-bundle.json").write_text('{"version":2}')
            with self.assertRaises(ValueError):
                RUNTIME["validate"](root)

    def fixture(self, root):
        evidence = OLD["fixture"](root)["network"]
        overlay = dict(original_build_receipt_sha256=RUNTIME["BASE_RECEIPT_SHA"],
            original_sha256=RUNTIME["BEFORE_CONTROLLER"], runtime_sha256=RUNTIME["AFTER_CONTROLLER"],
            native_rebuild=False, compatibility_rewrite=False, original_build_modified=False)
        provision = dict(version=1, kind="local-reviewed-native-firefox",
            browser_revision=RUNTIME["checked_pins"]()["revision"],
            original_build_receipt_sha256=RUNTIME["BASE_RECEIPT_SHA"], native_bundle_sha256="a" * 64,
            native_driver_sha256=RUNTIME["digest"](HERE / "browser-native-core.py"),
            local_disposable_only=True, javascript_overlay=overlay)
        browser = evidence["browser"]
        browser.update(kind="native-firefox-core-ordinary-tabs", runtime_version="157.0.1",
            runtime_source_stamp=RUNTIME["FIREFOX_REVISION"], profile_ech_grease_disabled=False,
            native_ech_wire_proven=False, ordinary_tab_bodies_verified=2,
            **{k: provision[k] for k in ("browser_revision", "original_build_receipt_sha256",
                                       "native_bundle_sha256", "javascript_overlay")})
        browser["result"].update(native_ech_abi=True, builtin_modules=True, ordinary_tabs=True)
        evidence["provision"] = provision
        return evidence

    def test_native_requires_native_abi_tabs_and_no_global_ech_override(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.fixture(Path(directory))
            EVIDENCE["validate_browser"](evidence)
            for fields in (dict(runtime_version="140.16.0"), dict(profile_ech_grease_disabled=True),
                           dict(native_ech_wire_proven=True), dict(ordinary_tab_bodies_verified=0),
                           dict(original_build_receipt_sha256="b" * 64)):
                changed = copy.deepcopy(evidence)
                changed["browser"].update(fields)
                with self.assertRaises(ValueError):
                    EVIDENCE["validate_browser"](changed)

    def test_native_does_not_replace_path_or_detach_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.fixture(Path(directory))
            for key in ("native_ech_abi", "builtin_modules", "ordinary_tabs", "independent_attachments",
                        "wrong_scope_blocked", "a_detached", "b_survives_a_detach"):
                changed = copy.deepcopy(evidence)
                changed["browser"]["result"][key] = False
                with self.assertRaises(ValueError):
                    EVIDENCE["validate_browser"](changed)

    def test_native_driver_uses_builtin_controller_ordinary_navigation_and_forwards_bytes(self):
        source = (HERE / "browser-native-core.py").read_text()
        tree = ast.parse(source)
        script = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "SCRIPT" for t in node.targets))
        self.assertIn('resource:///modules/VolparossaBrowserNetwork.sys.mjs', script)
        self.assertIn('browser.loadURI(', script)
        self.assertIn('previous.onDataAvailable(request,copy,offset,count)', script)
        self.assertNotIn('security.tls.ech.grease_probability', source)
        self.assertNotIn('fixture_modules(', source)
        self.assertIn('ordinary_tab_bodies_verified', source)
        for phase in ("browser-spawn", "marionette-connect", "marionette-session", "window-handles", "chrome-context"):
            self.assertIn('"' + phase + '"', source)
        self.assertIn('firefox_exit_before_cleanup', source)
        self.assertIn('firefox_exit_after_cleanup', source)


if __name__ == "__main__":
    unittest.main()
