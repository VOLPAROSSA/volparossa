#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure fragment receipt/privacy/cleanup contracts, not live datapath evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "private-storage-fragments-smoke.py"))
OLD = runpy.run_path(str(HERE / "test-private-storage-handoff-smoke.py"))


def fixture():
    old = OLD["fixture"]()
    size, chunk = CHECK["BYTES"], CHECK["CHUNK"]
    phases = {}
    for name, count in CHECK["PHASES"].items():
        phase = copy.deepcopy(old["network"]["complete"])
        phase["gates"]["exit_mptcp_tls_completed"] = count
        baseline = phase["gates"]["event_baseline_unix_ms"]
        phase["gates"].update(exit_log_limit=1000, exit_log_records=count + 1,
            exit_log_oldest_unix_ms=baseline, exit_log_newest_unix_ms=baseline + count,
            exit_log_window_covers_baseline=True, exit_mptcp_tls_failed=0)
        for role, capture in phase["privacy"].items():
            for node in CHECK["NODES"]:
                active = role == "exit" and (name != "restore" or node != "relay4")
                capture["provider_application"][node] = dict(request_packets=20 if active else 0,
                    response_packets=100 if active else 0, response_payload_bytes=2 * size if active else 0)
        phases[name] = phase
    usage = [dict(reserved_bytes=0, committed_bytes=n, leases=c)
             for n, c in zip(CHECK["PROVIDER_BYTES"], CHECK["PROVIDER_LEASES"])]
    return dict(success=True, **dict.fromkeys(CHECK["SCOPE_FALSE"], False), network=phases,
        expected_peers=old["expected_peers"], layout=old["layout"], isolation=old["isolation"],
        prepare=dict(synthetic_opaque_bytes=True, ciphertext_bytes=size, fragment_lengths=list(CHECK["LENGTHS"]),
            providers=3, copies_per_fragment=2, grant_payload_bytes=list(CHECK["PROVIDER_BYTES"]),
            grant_max_leases=list(CHECK["PROVIDER_LEASES"]), owner_distinct_from_all_providers=True, owner_secrets_exported=False),
        upload=dict(fragment_count=4, copies_per_fragment=2, committed_fragment_copies=8,
            logical_ciphertext_bytes=size, physical_payload_charge=2 * size, owner_signature_verified=True,
            fresh_process_progress=True, committed_retry_same_identities=True, renewal_confirmed_by_progress=True,
            source_removed_before_restore=True, staging_removed=True),
        restore=dict(restores=2, source_absent=True, fragment_provider_indexes=[1, 1, 2, 1],
            failed_first_provider_attempts=4, whole_archive_sha256_verified=True, reads_nonconsuming=True,
            existing_output_preserved=True, retained_identity_unchanged=True, staging_removed=True,
            physical_payload_charge=2 * size, uncertain_payload_charge=chunk + 73),
        finish=dict(reopened_copies_confirmed=True, all_eight_copies_deleted=True,
            delete_retry_idempotent=True, original_identities_retained=True, final_payload_charge=0, staging_removed=True),
        withdrawal=dict(first_provider_stopped_before_restore=True, first_store_retained=True,
            other_two_providers_serving=True, same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
            all_three_store_inodes_preserved=True, agent_restart_claimed=False),
        uploaded_usage=copy.deepcopy(usage), restored_usage=copy.deepcopy(usage),
        deleted_usage=[dict(reserved_bytes=0, committed_bytes=0, leases=0) for _ in range(3)],
        private_cleanup=dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
            fragment_metadata_removed=True, input_and_outputs_removed=True, fragment_staging_removed=True, user_directory_removed=True))


def write_evidence(root, value):
    def write(name, data):
        (root / name).write_text(json.dumps(data) + "\n")
    for name in CHECK["SUMMARY_NAMES"]:
        if name not in ("smoke", "evidence"):
            write(f"private-storage-fragments-{name}.json", value[name])
    write("a01-expected-peers.json", value["expected_peers"])
    for name, phase in value["network"].items():
        write(f"private-storage-fragments-{name}-live-selection.json", phase["selected_route"])
        write(f"private-storage-fragments-{name}-gates.json", phase["gates"])
        write(f"content-provider-adaptive-private-storage-fragments-{name}-control.json", phase["control_privacy"])
        for role, capture in phase["privacy"].items():
            write(f"private-storage-fragments-{name}-privacy-{role}.json", capture)


def cli_fixture(phase):
    keys = [str(i) * 64 for i in (1, 2, 3)]
    totals = dict(reserved=0, committed=0, uncertain=0)
    by_provider, fragments = [0, 0, 0], []
    for index, size in enumerate(CHECK["LENGTHS"]):
        copies, confirmed = [], 0
        for copy in range(2):
            provider = (index + copy) % 3
            charge = ("unattempted" if phase == "created" else "deleted" if phase == "deleted"
                else "uncertain" if phase == "restore" and provider == 0 and index in (0, 3) else "committed")
            retained = charge not in ("unattempted", "deleted")
            copies.append(dict(provider_key=keys[provider], charge=charge,
                last_confirmed_stored_bytes=size if retained else 0,
                last_confirmed_expiry=int(time.time()) + 3600 if retained else 0,
                last_confirmed_state="Committed" if retained else "Deleted" if charge == "deleted" else None))
            if retained:
                totals[charge] += size
                by_provider[provider] += size
                confirmed += int(charge == "committed")
        fragments.append(dict(index=index, offset=sum(CHECK["LENGTHS"][:index]), ciphertext_bytes=size,
                              confirmed_unexpired_copies=confirmed, copies=copies))
    operation = dict(created="create", committed="deposit", restore="restore", deleted="delete")[phase]
    value = dict(operation="private_storage_fragments_" + operation,
        logical_ciphertext_bytes=CHECK["BYTES"], fragment_count=4, copies_per_fragment=2, distinct_provider_identities=3,
        operation_complete=True, read_consumes_archive=False, owner_signature_verified=True, expired_copies_remain_charged=True,
        **dict.fromkeys(("metadata_overhead_measured", "current_remote_availability_proven", "independent_failure_domains_proven",
            "network_contribution_credit", "automatic_repair", "automatic_handoff", "erasure_coding"), False),
        fragments=fragments, providers=[dict(provider_key=k, physical_payload_charge_upper_bound=c) for k, c in zip(keys, by_provider)],
        physical_payload_charge_upper_bound=sum(totals.values()),
        fragments_with_confirmed_unexpired_copy=sum(f["confirmed_unexpired_copies"] > 0 for f in fragments),
        fully_redundant_from_retained_receipts=all(f["confirmed_unexpired_copies"] == 2 for f in fragments),
        **{key + "_payload_bytes": count for key, count in totals.items()})
    return value, operation, keys


class FragmentEvidence(unittest.TestCase):
    def test_distinct_fragment_geometry_and_exact_nonconsuming_file_bundle(self):
        self.assertEqual(sum(CHECK["LENGTHS"]), CHECK["BYTES"])
        self.assertEqual(hashlib.sha256(CHECK["FIXTURE"]).hexdigest(), CHECK["SHA"])
        self.assertEqual(sum(CHECK["PROVIDER_BYTES"]), 2 * CHECK["BYTES"])
        self.assertEqual(sum(CHECK["PROVIDER_LEASES"]), 8)
        self.assertTrue(all(size < CHECK["BYTES"] for size in CHECK["PROVIDER_BYTES"]))
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            self.assertEqual(CHECK["build_evidence"](root), value)
            self.assertEqual(set(CHECK["EXPORT_NAMES"]) - {"private-storage-fragments-smoke.json",
                "private-storage-fragments-evidence.json"}, {p.name for p in root.iterdir()})
            (root / "private-storage-fragments-restore-privacy-exit.json").unlink()
            with self.assertRaises(FileNotFoundError):
                CHECK["build_evidence"](root)

    def test_whole_replica_substitution_missing_provider_or_privacy_failure_is_rejected(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        for mutate in (
            lambda v: v["upload"].update(fragment_count=1),
            lambda v: v["upload"].update(source_removed_before_restore=False),
            lambda v: v["restore"].update(restores=1),
            lambda v: v["restore"].update(fragment_provider_indexes=[1, 1, 1, 1]),
            lambda v: v["restore"].update(uncertain_payload_charge=0),
            lambda v: v["restored_usage"][0].update(committed_bytes=0),
            lambda v: v["uploaded_usage"][0].update(committed_bytes=CHECK["BYTES"]),
            lambda v: v["deleted_usage"][2].update(leases=1),
            lambda v: v["withdrawal"].update(first_provider_stopped_before_restore=False),
            lambda v: v["withdrawal"].update(all_three_store_inodes_preserved=False),
            lambda v: v["layout"].update(provider_nodes=["relay4", "relay5", "relay5"]),
            lambda v: v["isolation"].update(agent_cannot_read_user_state=False),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay4"].update(response_payload_bytes=1),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay3"].update(response_payload_bytes=CHECK["CHUNK"]),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=2 * CHECK["CHUNK"]),
            lambda v: v["network"]["upload"]["selected_route"].update(transport="tcp"),
            lambda v: v["network"]["upload"]["selected_route"].update(paths=v["network"]["upload"]["selected_route"]["paths"][:1]),
            lambda v: v["network"]["upload"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda v: v["network"]["finish"]["privacy"]["exit"].update(packet_socket_drops=1),
            lambda v: v["network"]["upload"]["gates"].update(exit_mptcp_tls_completed=55),
            lambda v: v["network"]["upload"]["gates"].update(exit_log_window_covers_baseline=False),
            lambda v: v["network"]["upload"]["gates"].update(exit_log_oldest_unix_ms=2**63),
            lambda v: v["network"]["upload"]["gates"].update(exit_log_limit=400),
            lambda v: v["network"]["restore"]["control_privacy"].update(unexpected_provider_application_packets=1),
            lambda v: v["private_cleanup"].update(fragment_staging_removed=False),
            lambda v: v.update(automatic_repair=True),
        ):
            bad = copy.deepcopy(valid)
            mutate(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](bad)
        with self.assertRaises((ValueError, KeyError)):
            CHECK["validate_evidence"](OLD["fixture"]())

    def test_full_log_window_keeps_all_completions_and_refuses_cropped_or_regressed_evidence(self):
        def record(timestamp, event):
            return f"{timestamp}\tlevel=1\tevent={event}\tsession=\tpath=-\n"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private-exit-window.txt"
            baseline = 1000
            lines = [record(baseline, "MPTCP_EXIT_FLOW_COMPLETED")]
            for number in range(56):
                lines.extend(record(baseline + 1 + number, "MPTCP_LIFECYCLE") for _ in range(8))
                lines.append(record(baseline + 1 + number, "MPTCP_EXIT_FLOW_COMPLETED"))
            lines.append(record(baseline + 57, "MPTCP_EXIT_FLOW_FAILED"))
            path.write_text("".join(lines))
            full = CHECK["flow_gates"](path, baseline)
            self.assertEqual(full["exit_mptcp_tls_completed"], 56)
            self.assertEqual(full["exit_mptcp_tls_failed"], 1)
            self.assertTrue(full["exit_log_window_covers_baseline"])
            path.write_text("".join(lines[-400:]))
            cropped = CHECK["flow_gates"](path, baseline)
            self.assertLess(cropped["exit_mptcp_tls_completed"], 56)
            self.assertFalse(cropped["exit_log_window_covers_baseline"])
            phase = fixture()
            phase["network"]["upload"]["gates"] = cropped
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](phase)
            for invalid in ("", "unexpected raw diagnostics\n", "".join(lines * 3),
                            record(1001, "MPTCP_LIFECYCLE") + record(1000, "MPTCP_EXIT_FLOW_COMPLETED")):
                path.write_text(invalid)
                with self.assertRaises(ValueError):
                    CHECK["flow_gates"](path, baseline)
            self.assertNotIn(path.name, CHECK["EXPORT_NAMES"])
        shell = (HERE / "private-storage-fragments-smoke.sh").read_text()
        self.assertIn('logs --limit 1000 >"$WORK/private-storage-fragments-exit-log-window.txt"', shell)
        self.assertIn("FRAGMENTS_EXIT_LOG_WINDOW_TRUNCATED", shell)
        self.assertEqual(CHECK["PHASES"], dict(upload=56, restore=16, finish=16))

    def test_cli_signed_ranges_per_copy_finite_lease_and_conservative_charge(self):
        for phase in ("created", "committed", "restore", "deleted"):
            value, operation, keys = cli_fixture(phase)
            CHECK["validate_cli"](value, operation, keys, phase)
        value, operation, keys = cli_fixture("restore")
        for mutate in (
            lambda v: v.update(operation="private_storage_replicas_restore"),
            lambda v: v.update(owner_signature_verified=False),
            lambda v: v.update(uncertain_payload_bytes=0),
            lambda v: v["providers"][0].update(physical_payload_charge_upper_bound=0),
            lambda v: v["fragments"][1].update(offset=0),
            lambda v: v["fragments"][2]["copies"][0].update(provider_key=keys[1]),
            lambda v: v["fragments"][0]["copies"][0].update(last_confirmed_expiry=1),
            lambda v: v["fragments"][0].update(confirmed_unexpired_copies=2),
        ):
            bad = copy.deepcopy(value)
            mutate(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_cli"](bad, operation, keys, "restore")

    def test_restore_validator_checks_each_survivor_and_exports_only_closed_failure_codes(self):
        value, _operation, keys = cli_fixture("restore")
        value.update(restored=True, whole_archive_sha256_verified=True,
            fragment_outcomes=[dict(index=index, restored=True, provider_key=keys[provider],
                copy_outcomes=(["unavailable_or_restore_unverified", "restored_and_retained"]
                    if index in (0, 3) else ["restored_and_retained"]))
                for index, provider in enumerate((1, 1, 2, 1))])
        CHECK["validate_restore_result"](value, keys)
        for mutate in (lambda v: v.update(whole_archive_sha256_verified=False),
                       lambda v: v["fragment_outcomes"][0].update(provider_key=keys[0]),
                       lambda v: v["fragment_outcomes"][3].update(copy_outcomes=["restored_and_retained"])):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_restore_result"](invalid, keys)
        for error, code in ((ValueError("fragment copy placement or charge differs"), "copy_placement_or_charge"),
                            (ValueError("PRIVATE_SENTINEL command/token/output"), "unclassified"),
                            (KeyError("PRIVATE_SENTINEL"), "report_field_missing"),
                            (OSError("PRIVATE_SENTINEL"), "local_io"),
                            (subprocess.TimeoutExpired("PRIVATE_SENTINEL", 700), "cli_timeout")):
            diagnostic = CHECK["restore_failure"](error)
            self.assertFalse(diagnostic["success"])
            self.assertEqual(diagnostic["code"], code)
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(diagnostic))
            self.assertEqual(set(diagnostic), {"version", "kind", "success", "restore_number", "stage", "code", "cli"})

    def test_incomplete_cli_receipt_is_sanitized_before_nonzero_status_rejection(self):
        report = dict(operation="private_storage_fragments_restore", operation_complete=False,
            restored=False, unavailable_fragment=1, provider_key="PRIVATE_SENTINEL",
            fragment_outcomes=[dict(index=0, restored=True, provider_key="PRIVATE_SENTINEL",
                copy_outcomes=["unavailable_or_restore_unverified", "restored_and_retained"]),
                dict(index=1, restored=False, provider_key="PRIVATE_SENTINEL",
                copy_outcomes=["unavailable_or_restore_unverified", "unavailable_or_grant_invalid"])])
        raw = json.dumps(report).encode()
        process = mock.Mock(returncode=1)
        process.communicate.return_value = (raw, b"PRIVATE_SENTINEL credential/path/error")
        process.poll.return_value = 1
        with mock.patch.object(subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(ValueError, "private replica CLI operation failed") as failure:
                CHECK["restore_invoke"]("unused-cli", "unused-socket", [])
        diagnostic = CHECK["restore_failure"](failure.exception)
        self.assertEqual(diagnostic["code"], "cli_exit")
        self.assertEqual(diagnostic["cli"]["exit_code"], 1)
        self.assertEqual(diagnostic["cli"]["stdout_bytes"], len(raw))
        receipt = diagnostic["cli"]["receipt"]
        self.assertEqual(receipt["report"], "structural")
        self.assertEqual(receipt["completed_fragments"], 1)
        self.assertEqual(receipt["unavailable_fragment"], 1)
        self.assertEqual(receipt["fragment_outcomes"][1]["copy_outcomes"],
                         ["unavailable_or_restore_unverified", "unavailable_or_grant_invalid"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(diagnostic))
        for mutate in (lambda value: value.update(unavailable_fragment=4),
                       lambda value: value.update(operation_complete="PRIVATE_SENTINEL"),
                       lambda value: value["fragment_outcomes"][0].update(index=True),
                       lambda value: value["fragment_outcomes"][0].update(copy_outcomes=["PRIVATE_SENTINEL"]),
                       lambda value: value.update(fragment_outcomes=value["fragment_outcomes"] * 3)):
            invalid = copy.deepcopy(report)
            mutate(invalid)
            self.assertEqual(CHECK["restore_cli_receipt"](json.dumps(invalid).encode()),
                             dict(report="unavailable_or_invalid"))
        for raw in (b"PRIVATE_SENTINEL", b"x" * 16385, b"\xff"):
            self.assertEqual(CHECK["restore_cli_receipt"](raw), dict(report="unavailable_or_invalid"))

    def test_restore_timeout_remains_failure_and_joins_the_same_child(self):
        process = mock.Mock(returncode=-15)
        process.communicate.side_effect = subprocess.TimeoutExpired("PRIVATE_SENTINEL", 700)
        process.poll.return_value = None
        with mock.patch.object(subprocess, "Popen", return_value=process):
            with self.assertRaises(subprocess.TimeoutExpired) as failure:
                CHECK["restore_invoke"]("unused-cli", "unused-socket", [])
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)
        diagnostic = CHECK["restore_failure"](failure.exception)
        self.assertTrue(diagnostic["cli"]["timed_out"])
        self.assertEqual(diagnostic["cli"]["exit_code"], -15)
        self.assertEqual(diagnostic["code"], "cli_timeout")
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(diagnostic))

    def test_report_requires_exact_source_and_cleanup(self):
        report = dict(schema_version=1, report_kind="volparossa-private-storage-fragments", source_revision="a" * 40,
            success=True, runner_exit_status=0, phase="private-storage-fragments-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), storage=fixture())
        CHECK["validate_report"](report, "a" * 40)
        for mutate in (lambda r: r.update(source_revision="b" * 40),
                       lambda r: r.update(report_kind="volparossa-private-storage-replicas"),
                       lambda r: r["cleanup"].update(complete=False),
                       lambda r: r["host_state"].update(unchanged=False)):
            bad = copy.deepcopy(report)
            mutate(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](bad, "a" * 40)

    def test_cleanup_validates_complete_owned_tree_before_deleting_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "private-storage-user"
            root.mkdir(mode=0o700)
            state = root / "fragment-set"
            state.mkdir(mode=0o700)
            CHECK["create"](state / "fragments.json", b"synthetic")
            for index in range(4):
                fragment = state / f"fragment-{index:04}"
                fragment.mkdir(mode=0o700)
                CHECK["create"](fragment / "replicas.json", b"synthetic")
                for copy_index in range(2):
                    directory = fragment / f"copy-{copy_index}"
                    directory.mkdir(mode=0o700)
                    CHECK["create"](directory / "archive.json", b"synthetic")
            staging = state / ".fragment-transfer-Ab12"
            staging.mkdir(mode=0o700)
            CHECK["create"](staging / "restored-fragment", b"synthetic")
            CHECK["create"](root / "passphrase", b"synthetic")
            outside = parent / "outside"
            outside.write_bytes(b"not-owned")
            (root / "restore-1.bin").symlink_to(outside)
            with self.assertRaises(ValueError):
                CHECK["cleanup"](root)
            self.assertTrue((root / "passphrase").exists())
            self.assertEqual(outside.read_bytes(), b"not-owned")
            (root / "restore-1.bin").unlink()
            self.assertTrue(CHECK["cleanup"](root)["fragment_metadata_removed"])
            self.assertFalse(root.exists())
            self.assertTrue(CHECK["cleanup"](root)["user_directory_removed"])


if __name__ == "__main__":
    unittest.main()
