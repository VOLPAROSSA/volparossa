#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic handoff report/cleanup controls; these are not a live overlay proof."""

import copy
import json
import os
from pathlib import Path
import runpy
import tempfile
import time
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "private-storage-handoff-smoke.py"))
OLD = runpy.run_path(str(HERE / "test-private-storage-replicas-smoke.py"))


def fixture():
    old = OLD["fixture"]()
    amount = CHECK["BYTES"]
    phases = {}
    for name, count in CHECK["PHASES"].items():
        phase = copy.deepcopy(old["network"]["upload"])
        phase = {key: phase[key] for key in ("selected_route", "privacy", "control_privacy", "gates")}
        phase["gates"]["exit_mptcp_tls_completed"] = count
        active = {"upload": ("relay4", "relay5"), "pending": ("relay5", "relay3"),
            "complete": ("relay4", "relay5", "relay3"), "restore_b": ("relay5",),
            "restore_c": ("relay3",), "finish": ("relay5", "relay3")}[name]
        for role, capture in phase["privacy"].items():
            for node in CHECK["NODES"]:
                selected = role == "exit" and node in active
                capture["provider_application"][node] = dict(request_packets=20 if selected else 0,
                    response_packets=100 if selected else 0, response_payload_bytes=2 * amount if selected else 0)
        control = phase["control_privacy"]
        pairs = {f"ac{i}": [CHECK["NET"]["PUBLIC_IPS"]["relay2"], CHECK["NET"]["PUBLIC_IPS"][node]]
                 for i, node in enumerate(("relay3", "relay4", "relay5"))}
        control.update(interfaces=list(pairs), content_control_pairs=pairs,
            content_control_packets={name: dict(inbound=50, outbound=50) for name in pairs},
            observed_frames=300, interface_statistics={name: dict(observed_frames=100,
                packet_socket_packets=100, packet_socket_drops=0, intake_stopped=True) for name in pairs})
        phases[name] = phase
    prepare = copy.deepcopy(old["prepare"])
    prepare.pop("owner_distinct_from_both_providers")
    prepare.update(providers=3, owner_distinct_from_all_providers=True)
    result = dict(success=True, **dict.fromkeys(CHECK["SCOPE_FALSE"], False), prepare=prepare,
        upload=old["upload"], network=phases, expected_peers=old["expected_peers"],
        layout={**old["layout"], "provider_nodes": list(CHECK["NODES"])},
        withdrawal=dict(first_provider_stopped_before_replace=True, first_store_retained=True,
            same_first_store_reopened=True, first_provider_stopped_after_confirmed_delete=True,
            second_provider_stopped_before_replacement_restore=True, same_second_store_reopened=True,
            all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True,
            agent_restart_claimed=False),
        finish=dict(reopened_survivor_confirmed=True, exact_selected_deletions=True,
            delete_retry_idempotent=True, final_payload_charge=0, staging_removed=True),
        private_cleanup=dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
            replica_metadata_removed=True, input_and_outputs_removed=True, handoff_staging_removed=True,
            user_directory_removed=True),
        isolation=dict(user_uid=985, agent_uid=986, control_gid=987, agent_gid=986,
            agent_cannot_read_user_state=True, client_cannot_read_any_provider_store=True,
            agent_mount_positive_control=True, all_provider_keys_match_independent_fixture_peers=True,
            three_provider_namespaces_distinct=True))
    for name, pending in (("pending", True), ("complete", False)):
        result[name] = dict(source_absent=True, original_survivor_identity_unchanged=True,
            replacement_full_readback_verified=True, live_lease_expiry_checked=True, staging_removed=True,
            source_delete_confirmed=not pending, source_delete_uncertain=pending,
            physical_payload_charge=(3 if pending else 2) * amount, exact_retry_same_three_identities=True)
    for name, provider in (("restore_b", "B"), ("restore_c", "C")):
        result[name] = dict(restores=2, selected_provider=provider, source_absent=True,
            whole_archive_sha256_verified=True, reads_nonconsuming=True, physical_payload_charge=2 * amount,
            original_and_replacement_identities_retained=True, staging_removed=True)
    full, empty = dict(reserved_bytes=0, committed_bytes=amount, leases=1), dict(reserved_bytes=0, committed_bytes=0, leases=0)
    result.update(pending_usage=[copy.deepcopy(full) for _ in range(3)],
        complete_usage=[copy.deepcopy(empty), copy.deepcopy(full), copy.deepcopy(full)],
        deleted_usage=[copy.deepcopy(empty) for _ in range(3)])
    return result


def write_evidence(root, evidence):
    def write(name, value):
        (root / name).write_text(json.dumps(value, indent=2) + "\n")
    for name in CHECK["SUMMARY_NAMES"]:
        if name not in ("smoke", "evidence"):
            write(f"private-storage-handoff-{name}.json", evidence[name])
    write("a01-expected-peers.json", evidence["expected_peers"])
    for name, phase in evidence["network"].items():
        write(f"private-storage-handoff-{name}-live-selection.json", phase["selected_route"])
        write(f"private-storage-handoff-{name}-gates.json", phase["gates"])
        write(f"content-provider-adaptive-private-storage-handoff-{name}-control.json", phase["control_privacy"])
        for role, capture in phase["privacy"].items():
            write(f"private-storage-handoff-{name}-privacy-{role}.json", capture)


class PrivateStorageHandoffEvidence(unittest.TestCase):
    def test_complete_file_layout_rebuilds_with_exact_three_store_lists(self):
        valid = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, valid)
            self.assertEqual(CHECK["build_evidence"](root), valid)
            self.assertEqual(set(CHECK["EXPORT_NAMES"]) - {"private-storage-handoff-smoke.json",
                "private-storage-handoff-evidence.json"}, {p.name for p in root.iterdir()})
            usage = root / "private-storage-handoff-pending_usage.json"
            for invalid in ({}, [], valid["pending_usage"][:2], valid["pending_usage"] * 2,
                    [dict(reserved_bytes=False, committed_bytes=0, leases=0)] * 3,
                    [dict(reserved_bytes=0, committed_bytes=0, leases=0, owner_key="never")] * 3):
                usage.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    CHECK["build_evidence"](root)
            usage.write_text(json.dumps(valid["pending_usage"]))
            (root / "private-storage-handoff-restore_c-privacy-exit.json").unlink()
            with self.assertRaises(FileNotFoundError):
                CHECK["build_evidence"](root)

    def test_no_early_credit_missing_readback_or_fake_survivor(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        for mutation in (
            lambda e: e["pending"].update(physical_payload_charge=2 * CHECK["BYTES"]),
            lambda e: e["pending"].update(source_delete_confirmed=True),
            lambda e: e["complete"].update(replacement_full_readback_verified=False),
            lambda e: e["complete"].update(staging_removed=False),
            lambda e: e["complete"].update(live_lease_expiry_checked=False),
            lambda e: e["upload"].update(source_removed_before_restore=False),
            lambda e: e["pending_usage"][0].update(committed_bytes=0),
            lambda e: e["complete_usage"][0].update(leases=1),
            lambda e: e["deleted_usage"][2].update(committed_bytes=1),
            lambda e: e["restore_c"].update(reads_nonconsuming=False),
            lambda e: e["withdrawal"].update(second_provider_stopped_before_replacement_restore=False),
            lambda e: e["withdrawal"].update(all_three_store_inodes_preserved=False),
            lambda e: e["layout"].update(provider_nodes=["relay4", "relay5", "relay5"]),
            lambda e: e["layout"].update(control_relay_peer_id=e["expected_peers"]["relay3"]),
            lambda e: e["network"]["pending"]["privacy"]["exit"]["provider_application"]["relay3"].update(response_payload_bytes=1),
            lambda e: e["network"]["complete"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=1),
            lambda e: e["network"]["restore_c"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=1),
            lambda e: e["network"]["restore_b"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=CHECK["BYTES"]),
            lambda e: e["network"]["upload"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda e: e["network"]["finish"]["privacy"]["exit"].update(packet_socket_drops=1),
            lambda e: e["network"]["pending"]["gates"].update(exit_mptcp_tls_completed=9),
            lambda e: e["network"]["pending"]["control_privacy"].update(unexpected_provider_control_packets=1),
            lambda e: e["private_cleanup"].update(handoff_staging_removed=False),
            lambda e: e.update(automatic_contribution_resize=True),
        ):
            invalid = copy.deepcopy(valid)
            mutation(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](invalid)

    def test_exact_source_and_original_host_cleanup_are_required(self):
        report = dict(schema_version=1, report_kind="volparossa-private-storage-handoff", source_revision="a" * 40,
            success=True, runner_exit_status=0, phase="private-storage-handoff-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), storage=fixture())
        CHECK["validate_report"](report, "a" * 40)
        for mutate in (lambda r: r.update(source_revision="b" * 40),
                       lambda r: r.update(report_kind="volparossa-private-storage-replicas"),
                       lambda r: r["cleanup"].update(complete=False),
                       lambda r: r["host_state"].update(unchanged=False)):
            invalid = copy.deepcopy(report)
            mutate(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](invalid, "a" * 40)

    def test_live_cli_receipts_require_original_identity_charge_and_unexpired_copies(self):
        keys = [str(i) * 64 for i in (1, 2, 3)]
        charges = ("uncertain", "committed", "committed")
        value = dict(operation="private_storage_replicas_replace", logical_ciphertext_bytes=CHECK["BYTES"],
            distinct_provider_identities=3, copies=[dict(provider_key=k, charge=c,
                last_confirmed_stored_bytes=CHECK["BYTES"], last_confirmed_expiry=int(time.time()) + 3600)
                for k, c in zip(keys, charges)], read_consumes_archive=False, expired_copies_remain_charged=True,
            operation_complete=False, metadata_overhead_measured=False, independent_failure_domains_proven=False,
            network_contribution_credit=False, automatic_repair=False, reserved_payload_bytes=0,
            committed_payload_bytes=2 * CHECK["BYTES"], uncertain_payload_bytes=CHECK["BYTES"],
            physical_payload_charge_upper_bound=3 * CHECK["BYTES"], handoff=dict(from_provider_key=keys[0],
                replacement_provider_key=keys[2], replacement_readback_required_before_source_delete=True,
                automatic_contribution_resize=False))
        CHECK["validate_cli"](value, "replace", keys, charges, False)
        for mutate in (lambda v: v.update(uncertain_payload_bytes=0),
                       lambda v: v["copies"][2].update(last_confirmed_expiry=1),
                       lambda v: v["handoff"].update(from_provider_key=keys[1])):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_cli"](invalid, "replace", keys, charges, False)

    def test_cleanup_reaps_only_bounded_owned_files_and_never_follows_a_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "private-storage-user"
            root.mkdir(mode=0o700)
            state = root / "replica-set"
            state.mkdir(mode=0o700)
            for name in ("copy-0", "copy-1", "copy-2", ".handoff-transfer-Ab12"):
                directory = state / name
                directory.mkdir(mode=0o700)
                CHECK["create"](directory / ("survivor-1" if name.startswith(".") else "archive.json"), b"synthetic")
            for directory, name in ((root, "passphrase"), (root, "grant-c.bin"), (state, "replicas.json")):
                CHECK["create"](directory / name, b"synthetic")
            outside = parent / "outside"
            outside.write_bytes(b"not-owned-by-fixture")
            bad = root / "restore-c1.bin"
            bad.symlink_to(outside)
            with self.assertRaises(ValueError):
                CHECK["cleanup"](root)
            self.assertTrue((root / "passphrase").exists())  # validates everything before deleting anything
            self.assertEqual(outside.read_bytes(), b"not-owned-by-fixture")
            bad.unlink()
            self.assertTrue(CHECK["cleanup"](root)["handoff_staging_removed"])
            self.assertFalse(root.exists())
            self.assertTrue(CHECK["cleanup"](root)["user_directory_removed"])


if __name__ == "__main__":
    unittest.main()
