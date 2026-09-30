#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure receipt/fixture controls, never a substitute for the live Signal regression."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "signal-backup-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-private-storage-replicas-smoke.py"))


def fixture():
    base = BASE["fixture"]()
    value = {key: base[key] for key in ("expected_peers", "layout", "isolation", "deleted_usage")}
    value.update(success=True, **dict.fromkeys(CHECK["FALSE_SCOPE"], False))
    value["prepare"] = dict(providers=2, grant_max_leases_each=1, grant_payload_bytes_each=CHECK["CAPACITY"],
        owner_distinct_from_both_providers=True, owner_secrets_exported=False)
    value["native"] = dict(chat_revision=CHECK["CHAT"], signal_revision=CHECK["SIGNAL"],
        native_test=dict(version=1, tests=1, passes=1, failures=0, pending=0, exact_test=True),
        compiled_runtime_sha256={str(i): "a" * 64 for i in range(7)}, node_sha256="b" * 64,
        compile_receipt_sha256="c" * 64, native_encrypted_export_import=True, original_ciphertext_removed=True,
        upstream_messages_attachments_screenshots_verified=True, registration_and_relink_mock_server_required=True,
        application_egress_loopback_only=True, loopback_ipv4_ipv6_verified=True, capless_app=True,
        control_group_socket_verified=True, native_process_group_joined=True, private_logs_exported=False)
    value["finish"] = dict(logical_ciphertext_bytes=1234567, retained_copies_after_native_import=2,
        physical_payload_charge_before_delete=2469134, reads_nonconsuming=True,
        both_remote_copies_deleted=True, final_payload_charge=0)
    value["private_cleanup"] = dict(owner_identity_removed=True, recovery_keys_removed=True,
        grants_removed=True, profiles_logs_plaintext_removed=True, user_directory_removed=True)
    value["guard"] = dict(app_uid=985, blocked_packets=1, loopback_ipv4_ipv6_only=True)
    value["network"] = base["network"]["upload"]
    return value


class SignalBackupEvidence(unittest.TestCase):
    def test_native_test_and_retained_real_storage_are_both_required(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        for mutation in (
            lambda e: e["native"]["native_test"].update(tests=0, passes=0),
            lambda e: e["native"]["native_test"].update(pending=1),
            lambda e: e["native"]["native_test"].update(exact_test=False),
            lambda e: e["native"].update(chat_revision="f" * 40),
            lambda e: e["native"].update(original_ciphertext_removed=False),
            lambda e: e["native"].update(private_logs_exported=True),
            lambda e: e["finish"].update(retained_copies_after_native_import=1),
            lambda e: e["finish"].update(physical_payload_charge_before_delete=1234567),
            lambda e: e["guard"].update(blocked_packets=0),
            lambda e: e["layout"].update(provider_nodes=["relay4", "relay4"]),
            lambda e: e["network"]["gates"].update(exit_mptcp_tls_completed=5),
            lambda e: e["network"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda e: e["deleted_usage"][1].update(leases=1),
            lambda e: e["private_cleanup"].update(recovery_keys_removed=False),
            lambda e: e.update(server_free_messaging_proven=True),
        ):
            bad = copy.deepcopy(valid); mutation(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](bad)

    def test_report_requires_exact_source_host_and_cleanup(self):
        value = dict(schema_version=1, report_kind="volparossa-signal-backup", source_revision="a" * 40,
            success=True, runner_exit_status=0, phase="signal-backup-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), backup=fixture())
        CHECK["validate_report"](value, "a" * 40)
        for mutation in (lambda e: e.update(source_revision="b" * 40),
                         lambda e: e["cleanup"].update(complete=False),
                         lambda e: e["host_state"].update(unchanged=False)):
            bad = copy.deepcopy(value); mutation(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](bad, "a" * 40)

    def test_native_command_has_exact_test_and_external_containment(self):
        command = CHECK["isolated_command"](Path("/owned"), Path("/candidate"), Path("/node"), Path("/reporter"))
        for argument in ("--unshare-pid", "--cap-drop", "--chdir"):
            self.assertIn(argument, command)
        self.assertNotIn("--unshare-net", command)
        self.assertEqual(command[command.index("--tmpfs") + 1], "/tmp")
        self.assertIn("sandbox", command)
        self.assertEqual(len(command[command.index("sandbox"):]), 6)
        command = CHECK["native_command"](Path("/candidate"), Path("/node"), Path("/reporter"))
        self.assertIn("--forbid-pending", command)
        self.assertIn("--fail-zero", command)
        self.assertEqual(command[command.index("--require") + 1], "/signal-backup-startup.cjs")
        self.assertEqual(command[-1], "ts/test-mock/backups/backups_test.node.ts")
        self.assertEqual(command[command.index("--grep") + 1], "^" + CHECK["TITLE"] + "$")
        reporter = (HERE / "signal-backup-reporter.cjs").read_text()
        self.assertIn(CHECK["TITLE"], reporter)
        self.assertNotIn("error.message", reporter)

    def test_exports_are_closed_and_never_private_native_artifacts(self):
        names = CHECK["EXPORT_NAMES"]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 19)
        self.assertFalse(any(name.endswith((".log", ".err", ".signal", ".key", ".bin")) for name in names))
        self.assertFalse(any("recovery" in name or "profile" in name for name in names))

    def test_singleton_socket_uses_short_child_only_alias_of_owned_temp_tree(self):
        # Actual disposable topology shape, not a long-path test-only configuration.
        root = Path("/opt/va." + "a" * 32 + ".ABCDEF/client-fixtures/signal-backup-user")
        command = CHECK["isolated_command"](root, Path("/candidate"), Path("/node"), Path("/reporter"))
        alias = str(CHECK["NATIVE_TMP"])
        binding = ["--bind", str(root / "tmp"), alias]
        start = next(i for i in range(len(command)) if command[i:i + 3] == binding)
        self.assertGreater(start, command.index("--tmpfs"))
        self.assertEqual(command[start + 3:start + 6], ["--setenv", "TMPDIR", alias])
        self.assertTrue(any(command[i:i + 3] == ["--bind", str(root), str(root)]
                            for i in range(len(command))))
        # Even this conservative short Chromium directory suffix exceeds the old
        # limit. The alias leaves headroom for the actual scoped-directory name.
        suffix = "/scoped_dirABCDEF/SingletonSocket"
        self.assertGreaterEqual(len(os.fsencode(str(root / "tmp") + suffix)), 108)
        self.assertLess(len(os.fsencode(alias + suffix)), 108)
        self.assertIn("temporary-directory", CHECK["SANDBOX_PHASES"])
        self.assertNotIn("--no-sandbox", command)
        for name in ("HOME", "CODEX_HOME"):
            self.assertFalse(any(command[i:i + 2] == ["--setenv", name] for i in range(len(command))))

    def test_private_cleanup_is_idempotent_and_does_not_follow_profile_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "client-fixtures"; parent.mkdir(mode=0o700)
            root = parent / "signal-backup-user"; root.mkdir(mode=0o700)
            external = Path(temporary) / "untouched"; external.write_text("keep")
            (root / "profile-link").symlink_to(external)
            (root / "profile").mkdir(mode=0o700)
            CHECK["create"](root / "profile/private-key", b"private fixture")
            result = CHECK["cleanup"](str(root))
            self.assertTrue(all(result.values()))
            self.assertEqual(CHECK["cleanup"](str(root)), result)
            self.assertEqual(external.read_text(), "keep")
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(parent))

    def test_native_failure_metadata_is_closed_bounded_and_preserves_failed_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            CHECK["sandbox_status"](root, "control-socket", PermissionError(13, "private-canary"))
            CHECK["create"](root / "native.stdout", b"secret-archive-canary\n")
            CHECK["create"](root / "native.stderr", b"bwrap: Can't mkdir parents for /private-canary: Permission denied\n"
                b"Error [ERR_MODULE_NOT_FOUND]: private-key-canary\n")
            result = CHECK["native_diagnostic"](root, False)
            self.assertFalse(result["process_group_joined"])
            self.assertEqual(result["sandbox"]["value"], dict(version=1, phase="control-socket",
                error=dict(kind="os_error", errno=13)))
            self.assertTrue(result["stderr"]["signals"]["bwrap_failure"])
            self.assertTrue(result["stderr"]["signals"]["module_missing"])
            self.assertTrue(result["stderr"]["signals"]["permission_denied"])
            self.assertFalse(result["reporter"]["available"])
            self.assertNotIn("canary", json.dumps(result))
            self.assertNotIn("/private", json.dumps(result))
            self.assertFalse(result["private_logs_exported"])
            CHECK["create"](root / "native-status.json", json.dumps(dict(version=1, phase="reporter-initialized",
                tests=0, passes=0, failures=0, pending=0, exact_test=True, last_failure=None,
                unexpected="secret-canary")).encode())
            self.assertFalse(CHECK["closed_status"](root / "native-status.json", reporter=True)["valid"])
            (root / "native.stdout").write_bytes(b"secret-canary" * 2048)
            self.assertTrue(CHECK["log_classification"](root / "native.stdout")["truncated"])

    def test_reporter_retains_closed_pretest_and_hook_failure_status(self):
        node = os.environ.get("VOLPAROSSA_TEST_NODE") or shutil.which("node")
        if node is None:
            self.skipTest("explicit staged Node or system Node required for pure reporter test")
        script = r"""
const fs = require('node:fs');
const { EventEmitter } = require('node:events');
const Reporter = require(process.argv[1]);
const runner = new EventEmitter();
new Reporter(runner);
const first = JSON.parse(fs.readFileSync(process.env.VOLPAROSSA_BACKUP_STATUS));
if (first.phase !== 'reporter-initialized' || first.tests !== 0) throw new Error('missing initial status');
runner.emit('start');
runner.emit('hook');
runner.emit('fail', { type: 'hook', fullTitle: () => 'private-canary' },
  { message: 'secret-key-canary', stack: 'archive-canary', code: 'ENOENT', errno: -2 });
runner.emit('end');
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = dict(os.environ, VOLPAROSSA_BACKUP_STATUS=str(root / "native-status.json"),
                VOLPAROSSA_BACKUP_RESULT=str(root / "result.json"))
            subprocess.run([node, "-e", script, str((HERE / "signal-backup-reporter.cjs").resolve())],
                cwd=root, env=environment, check=True, timeout=5, capture_output=True)
            result = CHECK["closed_status"](root / "native-status.json", reporter=True)
            self.assertTrue(result["valid"])
            self.assertEqual(result["value"]["phase"], "run-end")
            self.assertEqual(result["value"]["last_failure"], dict(kind="hook", code="ENOENT", errno=-2))
            self.assertEqual(result["value"]["failures"], 1)
            self.assertNotIn("canary", json.dumps(result))
            with self.assertRaises(ValueError):
                CHECK["validate_mocha"](json.loads((root / "result.json").read_text()))

    def test_startup_observer_distinguishes_native_child_and_launcher_without_exporting_errors(self):
        node = os.environ.get("VOLPAROSSA_TEST_NODE") or shutil.which("node")
        if node is None:
            self.skipTest("explicit staged Node or system Node required for pure observer test")
        script = r"""
const fs = require('node:fs');
let forwarded = 0;
console.error = () => { forwarded += 1; };
const observer = require(process.argv[1]);
const native = {name:'Error', message:'electron.launch: Process failed to launch!\n'
  + '<launched> pid=123\n[pid=123][err] crashpad_handler: --database is required\n'
  + '[pid=123][err] /private-canary/electron exited with signal SIGTRAP\n'
  + '<process did exit: exitCode=1, signal=null>\nSECRET_CONFIG_CANARY'};
console.error('Failed to start the app, attempt 1, retrying', native);
console.error('unrelated private-canary', native);
const first = JSON.parse(fs.readFileSync(process.env.VOLPAROSSA_BACKUP_STARTUP));
const timeout = {name:'TimeoutError', message:'<launched> pid=124\nDebugger listening on ws://private-token\nTimeout 30000ms exceeded.'};
console.error('Failed to start the app, attempt 2, retrying', timeout);
const second = JSON.parse(fs.readFileSync(process.env.VOLPAROSSA_BACKUP_STARTUP));
const spawn = observer.classify({name:'Error', code:'ENOENT', errno:-2, message:'spawn /private-canary ENOENT'});
const connect = observer.classify({name:'TimeoutError', message:'<launched> pid=3\nDebugger listening on ws://private\nDevTools listening on ws://private\nWebSocket error: connect ETIMEDOUT\nTimeout 30000ms exceeded.'});
const unknown = observer.classify({name:'private-canary', code:'private-canary', message:'private-canary'});
process.stdout.write(JSON.stringify({forwarded, first, second, spawn, connect, unknown}));
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = dict(os.environ, VOLPAROSSA_BACKUP_STARTUP=str(root / "startup-status.json"))
            completed = subprocess.run([node, "-e", script, str((HERE / "signal-backup-startup.cjs").resolve())],
                cwd=root, env=environment, check=True, timeout=5, capture_output=True, text=True)
            result = json.loads(completed.stdout)
            self.assertEqual(result["forwarded"], 3)
            first = result["first"]
            self.assertEqual(first["failure_class"], "electron_signal")
            self.assertTrue(first["process"]["launcher_started"])
            self.assertEqual(first["process"]["launcher_exit_code"], 1)
            self.assertEqual(first["process"]["electron_exit_signal"], "SIGTRAP")
            self.assertIsNone(first["process"]["launcher_exit_signal"])
            self.assertTrue(first["causes"]["crashpad_database"])
            self.assertFalse(first["cause_unknown"])
            self.assertEqual(result["second"]["failure_class"], "chromium_endpoint_timeout")
            self.assertEqual(result["spawn"]["failure_class"], "spawn_error")
            self.assertFalse(result["spawn"]["process"]["launcher_started"])
            self.assertEqual(result["connect"]["failure_class"], "debugger_connect_timeout")
            self.assertEqual(result["unknown"]["failure_class"], "unknown")
            self.assertTrue(result["unknown"]["cause_unknown"])
            self.assertNotIn("canary", json.dumps(result).lower())
            self.assertNotIn("ws://", json.dumps(result))
            observation = CHECK["bootstrap_diagnostic"](root / "startup-status.json")
            self.assertTrue(observation["valid"])
            self.assertEqual(observation["value"], result["second"])
            self.assertEqual((root / "startup-status.json").stat().st_mode & 0o777, 0o600)
            first["raw_error"] = "private-canary"
            (root / "startup-status.json").write_text(json.dumps(first))
            self.assertFalse(CHECK["bootstrap_diagnostic"](root / "startup-status.json")["valid"])

    def test_startup_fatal_locations_are_bounded_and_never_export_check_values_or_unknown_paths(self):
        node = os.environ.get("VOLPAROSSA_TEST_NODE") or shutil.which("node")
        if node is None:
            self.skipTest("explicit staged Node or system Node required for pure observer test")
        script = r"""
const fs = require('node:fs');
console.error = () => {};
const observer = require(process.argv[1]);
const known = '[pid=20][err] [20:20:0930/153000.123456:FATAL:../../electron/shell/browser/electron_browser_main_parts.cc:322] Check failed: PRIVATE_KEY_CANARY == UNKNOWN_URL_CANARY\n';
const unknown = '[pid=20][err] [0930/153000.123456:FATAL:../../private_canary/user_data.cc(42)] secret-message-canary\n';
console.error('Failed to start the app, attempt 4, retrying', { name:'Error',
  message: known + known + unknown + '/private-canary/electron exited with signal SIGTRAP\n' });
const first = JSON.parse(fs.readFileSync(process.env.VOLPAROSSA_BACKUP_STARTUP));
const many = observer.classify({ message: Array.from({length: 8}, (_, i) =>
  `[FATAL:../../base/logging.cc:${i+1}] NOTREACHED hit. PRIVATE_VALUE_CANARY\n`).join('') });
const malformed = observer.classify({ message:'[FATAL:/private canary/secret.cc(1)] secret\n' });
const v8 = observer.classify({ message:'[pid=20][err] # Fatal error in: ../../v8/src/sandbox/sandbox.cc, line 811\n'
  + '[pid=20][err] # Check failed: SECRET_CANARY\n' });
const truncated = observer.classify({ message: 'x'.repeat(65536) + known });
process.stdout.write(JSON.stringify({first, many, malformed, v8, truncated}));
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "startup-status.json"
            environment = dict(os.environ, VOLPAROSSA_BACKUP_STARTUP=str(path))
            completed = subprocess.run([node, "-e", script, str((HERE / "signal-backup-startup.cjs").resolve())],
                cwd=root, env=environment, check=True, timeout=5, capture_output=True, text=True)
            result = json.loads(completed.stdout)
            first = result["first"]
            self.assertEqual(first["version"], 2)
            self.assertTrue(CHECK["bootstrap_diagnostic"](path)["valid"])
            self.assertEqual(first["fatal"], dict(observed=True, omitted=False, locations=[
                dict(source="electron_browser_main_parts.cc", line=322, category="check_failed",
                    source_sha256=hashlib.sha256(b"electron/shell/browser/electron_browser_main_parts.cc").hexdigest()),
                dict(source="OTHER", line=42, category="fatal_log",
                    source_sha256=hashlib.sha256(b"private_canary/user_data.cc").hexdigest())]))
            self.assertTrue(first["cause_unknown"], "a source location alone does not establish a cause")
            self.assertLess(path.stat().st_size, 4096)
            self.assertEqual(len(result["many"]["fatal"]["locations"]), 4)
            self.assertTrue(result["many"]["fatal"]["omitted"])
            self.assertTrue(all(entry["category"] == "notreached" for entry in result["many"]["fatal"]["locations"]))
            self.assertEqual(result["malformed"]["fatal"], dict(observed=True, omitted=False, locations=[]))
            self.assertEqual(result["v8"]["fatal"], dict(observed=True, omitted=False, locations=[
                dict(source="OTHER", line=811, category="check_failed",
                    source_sha256=hashlib.sha256(b"v8/src/sandbox/sandbox.cc").hexdigest())]))
            self.assertTrue(result["truncated"]["message_truncated"])
            self.assertFalse(result["truncated"]["fatal"]["observed"])
            self.assertNotIn("canary", json.dumps(result).lower())
            self.assertNotIn("Check failed", json.dumps(result))
            self.assertNotIn("../../", json.dumps(result))
            for field, value in (("source", "private_canary.cc"), ("line", 1000001),
                                 ("category", "private-canary"), ("source_sha256", "../private-canary")):
                altered = copy.deepcopy(first)
                altered["fatal"]["locations"][0][field] = value
                path.write_text(json.dumps(altered))
                self.assertFalse(CHECK["bootstrap_diagnostic"](path)["valid"])
            legacy = copy.deepcopy(first)
            legacy["version"] = 1
            del legacy["fatal"]
            path.write_text(json.dumps(legacy))
            self.assertTrue(CHECK["bootstrap_diagnostic"](path)["valid"])


if __name__ == "__main__":
    unittest.main()
