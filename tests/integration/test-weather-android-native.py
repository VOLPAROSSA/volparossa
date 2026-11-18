#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert launcher tests; no native SDK, emulator, network or policy execution."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
N = runpy.run_path(str(HERE / "weather-android-native.py"))
G = N["main"].__globals__
K = N["K"]
KF = runpy.run_path(str(HERE / "test-weather-android-kvm.py"))
SCRIPT = Path("/inert/weather/scripts/prepare_hosted_android_ci.py")
ARGS = ["--weather-root", "/inert/weather", "--core-commit", "a" * 40,
    "--weather-commit", N["WEATHER_COMMIT"], "--upstream-socket", "/inert/api/core-api.sock"]


class Interrupted(Exception):
    pass


class Native(unittest.TestCase):
    def launch(self, function, *, verify_error=None, load_error=None, snapshots=None):
        output, calls = io.StringIO(), []
        def load(path, **options):
            calls.append((path, options))
            if load_error is not None:
                raise load_error
            return dict(H=SimpleNamespace(Interrupted=Interrupted), main=function)
        def verify(*arguments):
            self.assertEqual(arguments, tuple(ARGS[1::2]))
            if verify_error is not None:
                raise verify_error
            return SCRIPT
        original = sys.argv
        samples = iter(snapshots or [KF["private_fixture"]()])
        with patch.dict(G, verified_script=verify), patch.object(N["runpy"], "run_path", side_effect=load), \
                patch.dict(os.environ, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1"), \
                patch.dict(K, snapshot=lambda: next(samples)), redirect_stdout(output):
            status = N["main"](list(ARGS))
        self.assertIs(sys.argv, original)
        raw = output.getvalue()
        value = None if status == 0 else json.loads(raw.splitlines()[-1].removeprefix(N["PREFIX"]))
        if value is not None:
            self.assertTrue(raw.splitlines()[-1].startswith(N["PREFIX"]))
            self.assertEqual(N["validate_diagnostic"](value), value)
        return status, raw, value, calls

    def test_exact_original_main_and_argv_with_no_success_claim(self):
        calls = []
        status, raw, value, loaded = self.launch(lambda: calls.append(list(sys.argv)))
        self.assertEqual((status, value), (0, None))
        self.assertEqual(K["validate_native"](json.loads(raw.splitlines()[-1][len(K["PREFIX"]):]))["baseline_state"], "rejected")
        self.assertEqual(calls, [[str(SCRIPT), "--run-protected-core", "--upstream-socket", ARGS[-1]]])
        self.assertEqual(loaded, [(str(SCRIPT), dict(run_name="__volparossa_android_native__"))])

    def test_original_early_guard_failure_is_recorded_without_skipping_finally(self):
        cleanup = []
        def main():
            try:
                raise ValueError("HOST_MEMORY_RESERVE")
            finally:
                cleanup.append(True)
        status, raw, value, _ = self.launch(main)
        self.assertEqual(status, 1)
        self.assertEqual((value["category"], value["code"]), ("value", "HOST_MEMORY_RESERVE"))
        self.assertEqual(cleanup, [True])
        self.assertFalse(value["joined_core_acceptance"])
        self.assertNotIn("cleanup", value)
        self.assertLess(len(raw), 4096)

    def test_exact_kvm_error_adds_second_snapshot_before_unchanged_final_diagnostic(self):
        before = KF["private_fixture"]()
        after = dict(before, real_read=False, real_write=False, open_result="eacces")
        def main(): raise ValueError("KVM_REQUIRED_NO_TCG")
        status, raw, diagnostic, _ = self.launch(main, snapshots=[before, after])
        self.assertEqual((status, diagnostic["code"]), (1, "KVM_REQUIRED_NO_TCG"))
        self.assertTrue(raw.splitlines()[-2].startswith(K["PREFIX"]))
        observation = K["validate_native"](json.loads(raw.splitlines()[-2][len(K["PREFIX"]):]))
        self.assertEqual(observation["before_main"]["open_result"], "opened")
        self.assertEqual(observation["at_kvm_guard_failure"]["open_result"], "eacces")
        self.assertFalse(observation["joined_core_acceptance"])
        for secret in ("12345", "23456", "34567", "/dev/kvm"):
            self.assertNotIn(secret, raw)

    def test_other_failure_does_not_trigger_second_probe(self):
        def main(): raise ValueError("HOST_MEMORY_RESERVE")
        _, raw, diagnostic, _ = self.launch(main, snapshots=[KF["private_fixture"]()])
        observed = json.loads(raw.splitlines()[-2][len(K["PREFIX"]):])
        self.assertIsNone(observed["at_kvm_guard_failure"])
        self.assertEqual(diagnostic["code"], "HOST_MEMORY_RESERVE")

    def test_first_observer_failure_never_skips_or_replaces_original_main(self):
        calls = []
        class Samples:
            def __iter__(self): return self
            def __next__(self): raise OSError("PRIVATE_OBSERVER_FAILURE")
        def main():
            calls.append(True)
            raise ValueError("KVM_REQUIRED_NO_TCG")
        status, raw, diagnostic, _ = self.launch(main, snapshots=Samples())
        self.assertEqual(calls, [True])
        self.assertEqual((status, diagnostic["code"]), (1, "KVM_REQUIRED_NO_TCG"))
        self.assertNotIn(K["PREFIX"], raw)
        self.assertNotIn("PRIVATE_OBSERVER_FAILURE", raw)

    def test_observation_error_cannot_replace_original_kvm_failure(self):
        def main(): raise ValueError("KVM_REQUIRED_NO_TCG")
        def broken(): raise OSError("PRIVATE_PROBE")
        before = KF["private_fixture"]()
        counter = [0]
        def snapshot():
            counter[0] += 1
            return before if counter[0] == 1 else broken()
        with patch.dict(K, snapshot=snapshot):
            # launch installs its own finite iterator; use a sequence whose
            # second read raises the same bounded observation exception.
            class Samples:
                def __iter__(self): return self
                def __next__(self): return snapshot()
            _, raw, diagnostic, _ = self.launch(main, snapshots=Samples())
        self.assertEqual(diagnostic["code"], "KVM_REQUIRED_NO_TCG")
        self.assertNotIn("PRIVATE_PROBE", raw)

    def test_private_baseline_is_owned_run_bound_and_never_exported(self):
        with tempfile.TemporaryDirectory() as temporary:
            core = Path(temporary)
            run = core / "weather-client-kvm.Abc123"
            owner = run / "android-owner"; owner.mkdir(parents=True, mode=0o700)
            socket = run / "android-api/core-api.sock"
            path = owner / "kvm-baseline.json"
            selected = KF["IDENTITY"]
            original = K["baseline_record"](selected, KF["private_fixture"]())
            with patch.dict(G, CORE=core):
                self.assertEqual(N["load_kvm_baseline"](socket, selected), (None, "absent"))
                path.write_text(json.dumps(original)); path.chmod(0o600)
                self.assertEqual(N["load_kvm_baseline"](socket, selected), (KF["private_fixture"](), "available"))
                for value in (dict(original, identity=dict(selected, run_attempt="2")),
                        dict(original, secret="PRIVATE"), dict(original, schema=True)):
                    path.write_text(json.dumps(value))
                    self.assertEqual(N["load_kvm_baseline"](socket, selected), (None, "rejected"))
                path.write_text("x" * 16385)
                self.assertEqual(N["load_kvm_baseline"](socket, selected), (None, "rejected"))
                path.write_text(json.dumps(original)); path.chmod(0o644)
                self.assertEqual(N["load_kvm_baseline"](socket, selected), (None, "rejected"))
                target = owner / "secret.json"; path.rename(target); target.chmod(0o600); path.symlink_to(target)
                self.assertEqual(N["load_kvm_baseline"](socket, selected), (None, "rejected"))
                self.assertEqual(N["load_kvm_baseline"]("/private/canary/core-api.sock", selected), (None, "rejected"))

    def test_entry_and_import_failures_also_have_closed_diagnostics(self):
        for kwargs, category, code in (
            (dict(verify_error=ValueError("NATIVE_LAUNCHER_SOURCE")), "value", "NATIVE_LAUNCHER_SOURCE"),
            (dict(load_error=FileNotFoundError("/private/canary")), "os", "UNKNOWN"),
            (dict(load_error=KeyError("PRIVATE_CANARY")), "key", "UNKNOWN")):
            status, raw, value, _ = self.launch(lambda: self.fail("must not execute"), **kwargs)
            self.assertEqual((status, value["category"], value["code"]), (1, category, code))
            self.assertNotIn("canary", raw.lower())

    def test_runtime_output_remains_owned_and_bounded_not_exported_by_launcher(self):
        def main():
            print("private runtime output without newline", end="")
            raise ValueError("CORE_SOCKET_PARENT")
        status, raw, value, _ = self.launch(main)
        self.assertTrue(raw.startswith("private runtime output without newline\n"))
        self.assertEqual((status, value["code"]), (1, "CORE_SOCKET_PARENT"))
        self.assertNotIn("private", json.dumps(value))

    def test_categories_and_exact_code_matching_never_stringify_errors(self):
        class SecretError(ValueError):
            def __str__(self):
                raise AssertionError("must never stringify an exception")
        samples = (
            (Interrupted("HOSTED_ANDROID_CORE_INTERRUPTED"), "interrupted", "HOSTED_ANDROID_CORE_INTERRUPTED"),
            (KeyboardInterrupt("PRIVATE_CANARY"), "interrupted", "UNKNOWN"),
            (subprocess.TimeoutExpired(["PRIVATE_CANARY"], 1), "timeout", "UNKNOWN"),
            (subprocess.CalledProcessError(1, ["PRIVATE_CANARY"], b"private output"), "process", "UNKNOWN"),
            (PermissionError("PRIVATE_CANARY"), "os", "UNKNOWN"),
            (TypeError("PRIVATE_CANARY"), "type", "UNKNOWN"),
            (KeyError("HOST_MEMORY_RESERVE"), "key", "UNKNOWN"),
            (SystemExit("PRIVATE_CANARY"), "system_exit", "UNKNOWN"),
            (RuntimeError("PRIVATE_CANARY"), "unknown", "UNKNOWN"),
            (SecretError("HOST_MEMORY_RESERVE"), "value", "HOST_MEMORY_RESERVE"),
            (ValueError("HOST_MEMORY_RESERVE /private/canary"), "value", "UNKNOWN"),
            (ValueError("UNREVIEWED_UPPERCASE_CODE"), "value", "UNKNOWN"),
            (ValueError("HOST_MEMORY_RESERVE", "PRIVATE_CANARY"), "value", "UNKNOWN"))
        for error, category, code in samples:
            value = N["diagnostic"](error, Interrupted)
            self.assertEqual((value["category"], value["code"]), (category, code))
            self.assertNotIn("CANARY", json.dumps(value))

    def test_record_validator_rejects_extra_or_promoted_fields(self):
        original = N["diagnostic"](ValueError("CORE_SOCKET_PATH"))
        for update in (dict(schema=True), dict(schema=5), dict(outcome="success"), dict(category="ValueError"),
            dict(code="UNREVIEWED_UPPERCASE_CODE"), dict(joined_core_acceptance=True), dict(cleanup=True), dict(raw="private")):
            value = copy.deepcopy(original); value.update(update)
            with self.assertRaises(ValueError): N["validate_diagnostic"](value)

    def test_arguments_are_closed_and_never_echoed(self):
        for arguments in ([], ARGS + ["PRIVATE_CANARY"], ["--wrong", *ARGS[1:]], ARGS[:-2]):
            output = io.StringIO()
            with patch.dict(G, verified_script=lambda *a: self.fail("must not verify")), redirect_stdout(output):
                self.assertEqual(N["main"](arguments), 1)
            self.assertNotIn("PRIVATE_CANARY", output.getvalue())
            self.assertEqual(json.loads(output.getvalue().splitlines()[-1][len(N["PREFIX"]):])["code"],
                "NATIVE_LAUNCHER_ARGUMENTS")

    def test_real_cli_refuses_local_execution_before_runtime_load(self):
        result = subprocess.run([sys.executable, "-B", str(HERE / "weather-android-native.py"), *ARGS],
            env=dict(PATH="/usr/bin:/bin"), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"")
        value = json.loads(result.stdout.decode().splitlines()[-1][len(N["PREFIX"]):])
        self.assertEqual(value["code"], "NATIVE_LAUNCHER_IDENTITY")

    def test_source_preflight_checks_both_commits_clean_trees_and_exact_entrypoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            core = Path(temporary)
            weather = core / "weather"
            script = weather / "scripts/prepare_hosted_android_ci.py"
            script.parent.mkdir(parents=True)
            raw = b"# inert fixture: never imported or executed\n"
            script.write_bytes(raw)
            calls, wrong = [], [None]
            env = dict(GITHUB_ACTIONS="true", RUNNER_OS="Linux", RUNNER_ENVIRONMENT="github-hosted",
                GITHUB_REPOSITORY="VOLPAROSSA/volparossa", GITHUB_WORKFLOW="Weather Android protected core delivery",
                GITHUB_WORKSPACE=str(core), GITHUB_SHA="a" * 40,
                VOLPAROSSA_WEATHER_SOURCE_SHA=N["WEATHER_COMMIT"], GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
            def git(argv, **options):
                calls.append((argv, options))
                root = Path(argv[argv.index("-C") + 1])
                if "rev-parse" in argv:
                    commit = "a" * 40 if root == core else N["WEATHER_COMMIT"]
                    return SimpleNamespace(stdout=(("b" * 40 if wrong[0] == root else commit) + "\n").encode())
                self.assertIn("--no-ext-diff", argv)
                self.assertIn("--quiet", argv)
                if wrong[0] == "dirty":
                    raise subprocess.CalledProcessError(1, argv)
                return SimpleNamespace(returncode=0)
            with patch.dict(G, CORE=core, ENTRYPOINT_SHA256=hashlib.sha256(raw).hexdigest(),
                    owned=lambda path, **_: Path(path)), patch.dict(os.environ, env, clear=True), \
                    patch.object(os, "getuid", return_value=1001), patch.object(os, "geteuid", return_value=1001), \
                    patch.object(N["subprocess"], "run", side_effect=git):
                verify = lambda: N["verified_script"](str(weather), "a" * 40, N["WEATHER_COMMIT"], "/inert/api.sock")
                self.assertEqual(verify(), script)
                self.assertEqual(len(calls), 4)
                self.assertTrue(all(options["timeout"] <= 15 and options["check"] for _, options in calls))
                self.assertTrue(all(options["env"]["GIT_CONFIG_GLOBAL"] == "/dev/null" for _, options in calls))
                for bad in (core, weather):
                    wrong[0] = bad
                    with self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_SOURCE"): verify()
                wrong[0] = "dirty"
                with self.assertRaises(subprocess.CalledProcessError): verify()
                wrong[0] = None
                script.write_bytes(b"# changed source\n")
                with self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_SOURCE"): verify()
                script.write_bytes(raw)
                for key, value in (("GITHUB_SHA", "b" * 40), ("GITHUB_REPOSITORY", "other/repo"),
                    ("GITHUB_WORKFLOW", "other workflow"), ("GITHUB_RUN_ID", "0"),
                    ("VOLPAROSSA_WEATHER_SOURCE_SHA", "b" * 40)):
                    with patch.dict(os.environ, {key: value}), self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_IDENTITY"):
                        verify()
                for socket in ("relative.sock", "/" + "x" * 104, "/private\ncanary"):
                    with self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_PATH"):
                        N["verified_script"](str(weather), "a" * 40, N["WEATHER_COMMIT"], socket)
                for uid, euid in ((0, 0), (1001, 0), (1001, 1002)):
                    with patch.object(os, "getuid", return_value=uid), patch.object(os, "geteuid", return_value=euid), \
                            self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_IDENTITY"):
                        verify()

    def test_owned_inputs_reject_links_and_writable_files_without_executing_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "inert.py"
            script.write_bytes(b"# never executed\n")
            script.chmod(0o600)
            self.assertEqual(N["owned"](script), script)
            self.assertEqual(N["owned"](root, directory=True), root)
            link = root / "linked.py"
            link.symlink_to(script)
            with self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_PATH"): N["owned"](link)
            script.chmod(0o666)
            with self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_PATH"): N["owned"](script)
            script.chmod(0o600)
            os.link(script, root / "hardlink.py")
            with self.assertRaisesRegex(ValueError, "NATIVE_LAUNCHER_PATH"): N["owned"](script)


if __name__ == "__main__":
    unittest.main()
