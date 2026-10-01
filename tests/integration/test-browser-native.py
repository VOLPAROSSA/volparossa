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
import shutil
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
RUNTIME = runpy.run_path(str(HERE / "browser-native-runtime.py"))
EVIDENCE = runpy.run_path(str(HERE / "browser-native-evidence.py"))
OLD = runpy.run_path(str(HERE / "test-browser-network-smoke.py"))


class NativeBrowserTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is needed for the native navigation callback harness")
    def test_navigation_failures_export_only_closed_state_from_all_four_callbacks(self):
        tree = ast.parse((HERE / "browser-native-core.py").read_text())
        script = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "SCRIPT" for t in node.targets))
        navigate = "const navigate=" + script.split("const navigate=", 1)[1].split("  try{\n    await checkpoint", 1)[0]
        harness = r'''
const vm=require("node:vm"), assert=require("node:assert/strict");
const navigate=JSON.parse(require("node:fs").readFileSync(0,"utf8"));
(async()=>{
for(const stage of ["stream-data","stream-stop","window-stop","body-integrity"]){
  let listener,progress;
  const url="https://private-canary.invalid/private-canary";
  const owner={_select:()=>null,status:{state:"overlay"}};
  const previous={onStartRequest(){},onDataAvailable(){},onStopRequest(){}};
  const request={URI:{spec:url},cancel(){},QueryInterface(){return {
    setNewListener(value){listener=value;return previous;}}}};
  const browser={currentURI:{spec:url},removeProgressListener(){},
    addProgressListener(value){progress=value;},loadURI(){
      owner._select(request);
      if(stage==="stream-data") listener.onDataAvailable(request,null,0,11);
      else if(stage==="stream-stop") listener.onStopRequest(request,0x80004004);
      else if(stage==="window-stop"){
        browser.currentURI.spec="about:blank";
        progress.onStateChange(null,request,3,0);
      }else{
        listener.onStopRequest(request,0);
        progress.onStateChange(null,request,3,0);
      }
    }};
  const context=vm.createContext({owner,browser,url,
    Cc:{"@mozilla.org/security/hash;1":{createInstance:()=>({init(){},finish:()=>""})}},
    Ci:{nsICryptoHash:{SHA256:1},nsIWebProgressListener:{STATE_STOP:1,STATE_IS_WINDOW:2},
      nsIWebProgress:{NOTIFY_STATE_WINDOW:3}},
    ChromeUtils:{generateQI:()=>()=>{}},Cr:{NS_ERROR_ABORT:0x80004004},
    Components:{isSuccessCode:status=>status===0},Services:{io:{newURI:()=>({})}},
    principal:{},expectedSha:"not-a-body-hash",expectedBytes:10});
  await assert.rejects(vm.runInContext("let navigationFailure=null;"+navigate+
    ";navigate(owner,browser,url)",context), /ordinary_navigation_failed/);
  const value=JSON.parse(vm.runInContext("JSON.stringify(navigationFailure)",context));
  assert.deepEqual(Object.keys(value).sort(),["stage","nsresult","received_bytes","chunk_bytes",
    "selected","stream_done","window_done","current_uri_matches","owner_overlay"].sort());
  assert.equal(value.stage,stage);assert.equal(value.received_bytes,0);
  assert.equal(value.selected,true);assert.equal(value.owner_overlay,true);
  assert.equal(value.nsresult,stage==="stream-stop"?0x80004004:stage==="window-stop"?0:null);
  assert.equal(value.chunk_bytes,stage==="stream-data"?11:0);
  assert.equal(value.current_uri_matches,stage!=="window-stop");
  assert.equal(value.stream_done,stage==="body-integrity");
  assert.equal(value.window_done,stage==="body-integrity");
  assert.equal(JSON.stringify(value).includes("private-canary"),false);
}
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run([shutil.which("node"), "-e", harness], input=json.dumps(navigate),
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

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
        browser["expected_sha256"] = OLD["CHECK"]["body_hash"](evidence["origin"]["run_id"], native_tabs=True)
        for request in evidence["origin"]["requests"]:
            request["sha256"] = browser["expected_sha256"]
        evidence["provision"] = provision
        return evidence

    def test_native_requires_native_abi_tabs_and_no_global_ech_override(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.fixture(Path(directory))
            EVIDENCE["validate_browser"](evidence)
            for fields in (dict(runtime_version="140.16.0"), dict(profile_ech_grease_disabled=True),
                           dict(native_ech_wire_proven=True), dict(ordinary_tab_bodies_verified=0),
                           dict(original_build_receipt_sha256="b" * 64),
                           dict(expected_sha256=OLD["CHECK"]["body_hash"](evidence["origin"]["run_id"]))):
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
