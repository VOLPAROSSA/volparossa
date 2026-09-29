#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic evidence/parser checks only; never a real network/datapath claim."""

import copy
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "private-storage-peer-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-provider-https-smoke.py"))


def fixture():
    base = BASE["fixture"]()
    network = copy.deepcopy(base["cases"]["complete"])
    network["control_privacy"] = network.pop("control")
    network["gates"] = dict(event_baseline_unix_ms=1000, exit_mptcp_tls_completed=16)
    for role, capture in network["privacy"].items():
        capture["provider_application"]["relay5"] = dict.fromkeys(
            capture["provider_application"]["relay5"], 0)
        if role == "exit":
            capture["provider_application"]["relay4"]["response_payload_bytes"] = 2 * CHECK["BYTES"]
    return dict(success=True, **dict.fromkeys(CHECK["SCOPE_FALSE"], False),
        prepare=dict(synthetic_opaque_bytes=True, ciphertext_bytes=CHECK["BYTES"], chunks=3,
            owner_distinct_from_provider=True, grant_max_leases=1, grant_max_payload_bytes=CHECK["BYTES"],
            owner_secrets_exported=False),
        upload=dict(committed=True, ciphertext_bytes=CHECK["BYTES"], chunks_uploaded=3,
            fresh_process_progress=True, committed_retry_same_archive_and_lease=True,
            source_removed_before_restore=True, interrupted_upload_resume_proven=False),
        download=dict(restores=2, ciphertext_bytes=CHECK["BYTES"], whole_archive_sha256_verified=True,
            reads_nonconsuming=True, existing_output_preserved=True, renewal_extended_expiry=True,
            explicit_delete=True, delete_retry_idempotent=True),
        reopen=dict(explicit_listener_stop=True, same_owned_store_reopened=True,
            durable_committed_bytes=CHECK["BYTES"], durable_reserved_bytes=0, durable_leases=1,
            agent_restart_claimed=False), deleted_usage=dict(reserved_bytes=0, committed_bytes=0, leases=0),
        private_cleanup=dict(owner_identity_removed=True, passphrase_removed=True, grant_removed=True,
            private_archive_metadata_removed=True, input_and_outputs_removed=True, user_directory_removed=True),
        isolation=dict(user_uid=985, agent_uid=986, control_gid=987, agent_gid=986,
            agent_cannot_read_user_state=True, client_cannot_read_provider_store=True,
            agent_mount_positive_control=True, provider_key_matches_independent_fixture_peer=True),
        expected_peers=base["expected_peers"], layout=dict(provider_node="relay4",
            control_provider_nodes=["relay4", "relay5"],
            control_relay_peer_id=base["expected_peers"]["relay2"],
            route_context_id=network["selected_route"]["route_context_id"]), network=network)


class PrivateStoragePeerEvidence(unittest.TestCase):
    def test_complete_evidence_requires_bytes_independence_and_cleanup(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        for mutation in (
            lambda e: e["download"].update(restores=1),
            lambda e: e["download"].update(reads_nonconsuming=False),
            lambda e: e["deleted_usage"].update(committed_bytes=1),
            lambda e: e["private_cleanup"].update(passphrase_removed=False),
            lambda e: e["layout"].update(provider_node="relay0"),
            lambda e: e["network"]["gates"].update(exit_mptcp_tls_completed=15),
            lambda e: e["network"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda e: e["network"]["privacy"]["exit"].update(packet_socket_drops=1),
            lambda e: e["network"]["privacy"]["exit"]["provider_application"]["relay4"].update(response_payload_bytes=1),
            lambda e: e.update(signal_backup_proven=True),
        ):
            invalid = copy.deepcopy(valid)
            mutation(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](invalid)

    def test_source_bound_report_requires_success_and_unchanged_host(self):
        report = dict(source_revision="a" * 40, schema_version=1,
            report_kind="volparossa-private-storage-peer", success=True, runner_exit_status=0,
            phase="private-storage-peer-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True),
            storage=fixture())
        CHECK["validate_report"](report, "a" * 40)
        for mutation in (lambda r: r["host_state"].update(unchanged=False),
                         lambda r: r["cleanup"].update(remaining_owned_objects=1),
                         lambda r: r.update(source_revision="b" * 40)):
            invalid = copy.deepcopy(report)
            mutation(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](invalid, "a" * 40)

    def test_owned_private_cleanup_is_idempotent_and_rejects_external_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-storage-user"
            root.mkdir(mode=0o700)
            for name in CHECK["FILES"]:
                CHECK["create"](root / name, b"synthetic fixture")
            archive = root / "archive-state"
            archive.mkdir(mode=0o700)
            CHECK["create"](archive / "archive.json", b"private synthetic metadata")
            result = CHECK["cleanup"](str(root))
            self.assertTrue(all(result.values()))
            self.assertEqual(result, CHECK["cleanup"](str(root)))
            root.mkdir(mode=0o700)
            outside = Path(temporary) / "untouched"
            outside.write_bytes(b"preserve")
            (root / "identity.key").symlink_to(outside)
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(root))
            self.assertEqual(outside.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
