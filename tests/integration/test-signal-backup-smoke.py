#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure receipt/fixture controls, never a substitute for the live Signal regression."""
import copy
from pathlib import Path
import runpy
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


if __name__ == "__main__":
    unittest.main()
