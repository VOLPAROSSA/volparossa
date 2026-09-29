#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic report/parser controls only, not a live network proof."""

import copy
import json
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "private-storage-replicas-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-provider-https-smoke.py"))


def fixture():
    base = BASE["fixture"]()
    amount = CHECK["BYTES"]
    phases = {}
    for name, count in (("upload", 18), ("failover", 4), ("finish", 6)):
        network = copy.deepcopy(base["cases"]["complete"])
        network["control_privacy"] = network.pop("control")
        network["gates"] = dict(event_baseline_unix_ms=1000, exit_mptcp_tls_completed=count)
        app = network["privacy"]["exit"]["provider_application"]
        app["relay5"]["response_payload_bytes"] = 2 * amount
        if name == "failover":
            app["relay4"]["response_payload_bytes"] = 0
        phases[name] = network
    return dict(success=True, **dict.fromkeys(CHECK["SCOPE_FALSE"], False),
        prepare=dict(synthetic_opaque_bytes=True, ciphertext_bytes=amount, providers=2,
            grant_max_leases_each=1, grant_payload_bytes_each=amount,
            owner_distinct_from_both_providers=True, owner_secrets_exported=False),
        upload=dict(committed_copies=2, logical_ciphertext_bytes=amount, physical_payload_charge=2 * amount,
            chunks_per_copy=3, fresh_process_progress=True, committed_retry_same_identities=True,
            renewal_confirmed_by_progress=True, source_removed_before_restore=True),
        failover=dict(restores=2, first_provider_attempt_failed=True, second_provider_restored=True,
            whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
            uncertain_first_copy_remains_charged=True, physical_payload_charge=2 * amount),
        finish=dict(reopened_first_copy_confirmed=True, original_identities_retained=True,
            selected_copy_deleted=True, surviving_copy_restored=True, surviving_payload_charge=amount,
            delete_retry_idempotent=True, final_payload_charge=0),
        withdrawal=dict(first_provider_service_stopped=True, serving=False, retained_committed_bytes=amount,
            retained_reserved_bytes=0, retained_leases=1, second_provider_serving=True,
            same_owned_store_reopened=True, agent_restart_claimed=False),
        deleted_usage=[dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 2,
        private_cleanup=dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
            replica_metadata_removed=True, input_and_outputs_removed=True, user_directory_removed=True),
        isolation=dict(user_uid=985, agent_uid=986, control_gid=987, agent_gid=986,
            agent_cannot_read_user_state=True, client_cannot_read_either_provider_store=True,
            agent_mount_positive_control=True, both_provider_keys_match_independent_fixture_peers=True,
            provider_namespaces_distinct=True),
        expected_peers=base["expected_peers"], layout=dict(provider_nodes=["relay4", "relay5"],
            control_relay_peer_id=base["expected_peers"]["relay2"],
            route_context_id=phases["upload"]["selected_route"]["route_context_id"]), network=phases)


class PrivateStorageReplicaEvidence(unittest.TestCase):
    def test_build_reads_real_file_layout_including_two_usage_objects(self):
        valid = fixture()
        valid["network"] = {phase: {name: values[name] for name in
            ("selected_route", "gates", "control_privacy", "privacy")}
            for phase, values in valid["network"].items()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def write(name, value):
                (root / name).write_text(json.dumps(value, indent=2) + "\n")
            for name in CHECK["SUMMARY_NAMES"]:
                if name not in ("smoke", "evidence"):
                    write(f"private-storage-replicas-{name}.json", valid[name])
            write("a01-expected-peers.json", valid["expected_peers"])
            for phase, values in valid["network"].items():
                write(f"private-storage-replicas-{phase}-live-selection.json", values["selected_route"])
                write(f"private-storage-replicas-{phase}-gates.json", values["gates"])
                write(f"content-provider-private-storage-replicas-{phase}-control.json", values["control_privacy"])
                for role, values_by_role in values["privacy"].items():
                    write(f"private-storage-replicas-{phase}-privacy-{role}.json", values_by_role)
            self.assertEqual(CHECK["build_evidence"](root), valid)
            self.assertEqual(set(CHECK["EXPORT_NAMES"]) - {"private-storage-replicas-smoke.json",
                "private-storage-replicas-evidence.json"}, {path.name for path in root.iterdir()})
            usage_file = root / "private-storage-replicas-deleted_usage.json"
            for invalid in ({}, [], [valid["deleted_usage"][0]], valid["deleted_usage"] * 2,
                            [dict(reserved_bytes=False, committed_bytes=0, leases=0)] * 2,
                            [dict(reserved_bytes=0, committed_bytes=0, leases=0, private_key="never")] * 2):
                write(usage_file.name, invalid)
                with self.assertRaises(ValueError):
                    CHECK["build_evidence"](root)
            write(usage_file.name, valid["deleted_usage"])
            (root / "private-storage-replicas-finish-privacy-exit.json").unlink()
            with self.assertRaises(FileNotFoundError):
                CHECK["build_evidence"](root)

    def test_export_names_are_exact_and_match_bounded_diagnostic_collector(self):
        names = CHECK["EXPORT_NAMES"]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 36)
        driver = (HERE / "run-alpha-topology-vm.sh").read_text()
        start = driver.index('REPLICA_NAMES = ')
        end = driver.index('\n\ndef read_tail', start)
        namespace = {}
        exec(driver[start:end], namespace)
        self.assertEqual(set(names), namespace["REPLICA_NAMES"])
        self.assertFalse(any(name.endswith((".log", ".err", ".bin", ".key")) for name in names))

    def test_two_copies_actual_unavailability_survivor_bytes_and_charge_are_required(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        for mutation in (
            lambda e: e["upload"].update(committed_copies=1),
            lambda e: e["upload"].update(physical_payload_charge=CHECK["BYTES"]),
            lambda e: e["withdrawal"].update(serving=True),
            lambda e: e["withdrawal"].update(retained_committed_bytes=0),
            lambda e: e["failover"].update(first_provider_attempt_failed=False),
            lambda e: e["failover"].update(reads_nonconsuming=False),
            lambda e: e["finish"].update(surviving_copy_restored=False),
            lambda e: e["layout"].update(provider_nodes=["relay4", "relay4"]),
            lambda e: e["network"]["failover"]["privacy"]["exit"]["provider_application"]["relay4"].update(response_payload_bytes=1),
            lambda e: e["network"]["failover"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=1),
            lambda e: e["network"]["finish"]["gates"].update(exit_mptcp_tls_completed=5),
            lambda e: e["network"]["upload"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda e: e["network"]["finish"]["privacy"]["exit"].update(packet_socket_drops=1),
            lambda e: e["deleted_usage"][1].update(leases=1),
            lambda e: e["private_cleanup"].update(grants_removed=False),
            lambda e: e.update(independent_failure_domains_proven=True),
        ):
            invalid = copy.deepcopy(valid)
            mutation(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](invalid)

    def test_exact_source_report_requires_private_and_host_cleanup(self):
        report = dict(schema_version=1, report_kind="volparossa-private-storage-replicas",
            source_revision="a" * 40, success=True, runner_exit_status=0,
            phase="private-storage-replicas-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), storage=fixture())
        CHECK["validate_report"](report, "a" * 40)
        for mutation in (lambda e: e.update(source_revision="b" * 40),
                         lambda e: e["cleanup"].update(remaining_owned_objects=1),
                         lambda e: e["host_state"].update(unchanged=False)):
            invalid = copy.deepcopy(report)
            mutation(invalid)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](invalid, "a" * 40)

    def test_private_nested_cleanup_is_idempotent_and_refuses_external_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-storage-user"
            root.mkdir(mode=0o700)
            for name in CHECK["FILES"]:
                CHECK["create"](root / name, b"synthetic private metadata")
            retained = root / "replica-set"
            retained.mkdir(mode=0o700)
            CHECK["create"](retained / "replicas.json", b"synthetic private metadata")
            for index in range(2):
                child = retained / f"copy-{index}"
                child.mkdir(mode=0o700)
                CHECK["create"](child / "archive.json", b"synthetic private metadata")
            result = CHECK["cleanup"](str(root))
            self.assertTrue(all(result.values()))
            self.assertEqual(result, CHECK["cleanup"](str(root)))
            root.mkdir(mode=0o700)
            outside = Path(temporary) / "untouched"
            outside.write_bytes(b"retain")
            (root / "replica-set").symlink_to(outside)
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(root))
            self.assertEqual(outside.read_bytes(), b"retain")


if __name__ == "__main__":
    unittest.main()
