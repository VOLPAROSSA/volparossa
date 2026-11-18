#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure closed-evidence tests; synthetic receipts never claim real pressure or networking."""
import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "content-provider-pressure-smoke.py"))
ADAPTIVE = runpy.run_path(str(HERE / "test-content-provider-adaptive-smoke.py"))
CONTROLLER = runpy.run_path(str(HERE / "test-content-provider-pressure.py"))
RESOURCE = CHECK["RESOURCE"]


def fixture():
    original = ADAPTIVE["fixture"]()
    controller, _ = CONTROLLER["run"]()
    controller["publication"] = CHECK["publication"](original["publication"])
    budget = dict(schema_version=1, outcome="returned", initial_allowance=8, min_allowance=1,
                  max_allowance=8, min_memory_workers=8, min_fd_workers=64, peak_shared_held=3,
                  admitted_leases=5, denied_leases=0, peak_leases=3, active_leases=0,
                  causes={key: key == "cpu_pressure" for key in CHECK["BUDGET"]["CAUSES"]})
    continuation = dict(schema_version=1, outcome="returned", retired_candidates=2,
                        prepared_continuations=2, admitted_continuations=2,
                        returned_useful_continuations=2, returned_verified_chunks=36,
                        returned_verified_bytes=36*262144, initial_active_workers=0,
                        peak_active_workers=1, final_active_workers=0)
    def diagnostic(kind, record):
        return dict(schema_version=1, kind=kind, phase="pressure", phase_closed=True,
                    complete=True, status="observed", records=[record])
    selected = original["selected_route"]
    output = dict(original["output"], started_monotonic_ns=controller["started_ns"],
                  completed_monotonic_ns=12_000_000_000, started_unix_ms=1_001_000,
                  completed_unix_ms=1_012_000, exact_lookup_started=0, exact_lookup_finished=0,
                  client_nonempty_verified_responses=1)
    providers = {node: dict(reset=dict(serving=False, publications=0),
                           serve=dict(serving=True, publications=1, replication_enabled=False),
                           status=dict(serving=True, publications=1, replication_enabled=False),
                           stop=dict(serving=False, publications=0)) for node in CHECK["NODES"]}
    return dict(schema_version=2, kind="content-provider-pressure-smoke", success=True,
                scope=dict(CHECK["SCOPE"]), publication=original["publication"],
                expected_peers=original["expected_peers"], layout=original["layout"],
                original_selected_route=copy.deepcopy(selected), selected_before=copy.deepcopy(selected),
                selected_route=selected, status_before=original["status_before"],
                status_after=original["status_after"], fetch=original["fetch"], output=output,
                privacy=original["privacy"], control_underlay=original["control_underlay"],
                control_filter=original["control_filter"], providers=providers,
                ready=dict(schema_version=1, kind="content-provider-pressure-ready", cold_cache=True,
                           ready_ns=controller["started_ns"]-1, publication=dict(controller["publication"])),
                controller=controller,
                resource_ready=dict(schema_version=1, kind="content-provider-psi-readiness", phase="pressure",
                    scope=dict(RESOURCE["SCOPE"]), status="ready", deadline_ms=30000,
                    sample_interval_ms=1000, required_consecutive=3, samples=3, consecutive=3,
                    elapsed_ms=2000, last_observation=dict.fromkeys(RESOURCE["THRESHOLDS"], "below_threshold")),
                worker_budget=diagnostic("content-worker-budget-diagnostic", budget),
                continuation=diagnostic("content-provider-continuation-diagnostic", continuation),
                qdisc=dict(profile=copy.deepcopy(CHECK["QDISC_PROFILE"]),
                    before={node: [dict(kind="noqueue", handle="0:", root=True, bytes=0)] for node in CHECK["NODES"]},
                    limited={node: [dict(kind="tbf", handle="884:", root=True,
                        options=dict(rate=250000, burst=131072, lat=250000))] for node in CHECK["NODES"]},
                    after={node: [dict(kind="noqueue", handle="0:", root=True, bytes=100)] for node in CHECK["NODES"]}),
                cleanup=dict(CHECK["CLEANUP"]))


def raw_files(evidence):
    prefix = CHECK["PREFIX"]
    files = {name: evidence[key] for key, name in (
        ("publication", "content-provider-adaptive-publication.json"),
        ("expected_peers", "a01-expected-peers.json"), ("layout", "content-provider-adaptive-layout.json"),
        ("original_selected_route", "content-provider-adaptive-live-selection.json"),
        ("control_filter", "content-provider-adaptive-control-filter.json"))}
    files.update({f"{prefix}-{suffix}.json": evidence[key] for key, suffix in (
        ("selected_before", "selection"), ("selected_route", "live-selection"),
        ("status_before", "status-before"), ("status_after", "status-after"), ("fetch", "fetch"),
        ("output", "object"), ("ready", "ready"), ("controller", "controller"),
        ("resource_ready", "resource-ready"), ("worker_budget", "worker-budget"),
        ("continuation", "continuation"), ("cleanup", "cleanup"))})
    for node, operations in evidence["providers"].items():
        for operation, value in operations.items():
            files[f"{prefix}-{node}-{operation}.json"] = value
    files.update({f"{prefix}-privacy-{role}.json": value for role, value in evidence["privacy"].items()})
    files[f"{prefix}-control-privacy.json"] = evidence["control_underlay"]["capture"]
    for node, directions in evidence["control_underlay"]["routes"].items():
        for direction, value in directions.items():
            files[f"content-provider-adaptive-control-{node}-{direction}.json"] = value
    for phase, value in evidence["qdisc"].items():
        files[f"{prefix}-qdisc-{phase}.json"] = value
    return files


def write_files(work, evidence):
    for name, value in raw_files(evidence).items():
        with (work/name).open("x", encoding="ascii") as output:
            json.dump(value, output)
        (work/name).chmod(0o600)


class PressureEvidence(unittest.TestCase):
    def rejected(self, change):
        evidence = fixture()
        change(evidence)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            CHECK["validate"](evidence)

    def test_complete_pressure_and_serial_useful_continuation(self):
        evidence = fixture()
        self.assertEqual(CHECK["validate"](evidence), evidence)
        self.assertEqual(evidence["controller"]["last_observation"]["cpu"], "pressured")
        self.assertFalse(evidence["scope"]["pressure_recovery_claimed"])
        self.assertFalse(evidence["scope"]["owner_goodput_claimed"])

    def test_fresh_exact_refresh_is_not_reported_as_generic_discovery(self):
        evidence = fixture()
        evidence["output"].update(generic_dht_queries=0, authenticated_upstream_offers=0,
            exact_lookup_started=3, exact_lookup_finished=3,
            client_nonempty_verified_responses=3, client_forwarded_discovery=3)
        self.assertEqual(CHECK["validate"](evidence), evidence)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            write_files(work, evidence)
            self.assertEqual(CHECK["build_evidence"](work), evidence)
        self.assertEqual(evidence["output"]["generic_dht_queries"], 0)
        self.assertEqual(evidence["output"]["authenticated_upstream_offers"], 0)

    def test_exact_finish_without_three_nonempty_verified_responses_is_not_proof(self):
        exact = dict(generic_dht_queries=0, authenticated_upstream_offers=0,
                     exact_lookup_started=3, exact_lookup_finished=3,
                     client_nonempty_verified_responses=3, client_forwarded_discovery=3)
        for key, value in (("exact_lookup_started", 0), ("exact_lookup_finished", 2),
                           ("exact_lookup_finished", 4), ("client_nonempty_verified_responses", 0),
                           ("client_nonempty_verified_responses", 2), ("client_forwarded_discovery", 2),
                           ("authenticated_upstream_offers", 1)):
            with self.subTest(key=key, value=value):
                evidence = fixture()
                evidence["output"].update(exact)
                evidence["output"][key] = value
                with self.assertRaises(ValueError):
                    CHECK["validate"](evidence)

    def test_missing_generic_or_empty_discovery_cannot_pass(self):
        for key, value in (("generic_dht_queries", 0), ("authenticated_upstream_offers", 2),
                           ("client_nonempty_verified_responses", 0), ("client_forwarded_discovery", 0)):
            self.rejected(lambda e: e["output"].__setitem__(key, value))
        for key in CHECK["DISCOVERY_COUNTS"]:
            for value in (-1, True, 1.0, 2**32):
                self.rejected(lambda e: e["output"].__setitem__(key, value))
            self.rejected(lambda e: e["output"].pop(key))
        self.rejected(lambda e: e["output"].__setitem__("unknown", "raw-log"))
        self.rejected(lambda e: e.__setitem__("schema_version", 1))
        self.rejected(lambda e: e["output"].__setitem__("event_baseline_unix_ms", 1_001_001))

    def test_real_shell_counters_exclude_other_phases_and_preserve_event_meanings(self):
        def row(timestamp, event):
            return f"{timestamp}\tlevel=1\tevent={event}\tsession=\tpath=-\n"
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for node in ("client", "relay0", "relay1", "relay2", "relay3", "relay4", "relay5"):
                (work/f"logs-{node}.txt").write_text("", encoding="ascii")
            relay = work/"logs-relay1.txt"
            client = work/"logs-client.txt"
            command = '. "$1"\nWORK=$2\npp_baseline_ms=100\npp_started_unix=200\npp_completed_unix=400\n'
            command += 'content_provider_pressure_discovery_counts\n'
            command += 'printf "%s %s %s %s %s %s\\n" "$pp_queries" "$pp_offers" "$pp_discovered" '
            command += '"$pp_exact_started" "$pp_exact_finished" "$pp_nonempty"\n'
            def count():
                result = subprocess.run(["sh", "-eu", "-c", command, "sh",
                    str(HERE/"content-provider-pressure-smoke.sh"), str(work)],
                    capture_output=True, check=True, timeout=5)
                self.assertEqual(result.stderr, b"")
                return [int(value) for value in result.stdout.split()]
            # Earlier native/HTTPS events and work after this fetch do not count.
            outside = "".join(row(ts, event) for ts in (99, 100, 101, 199, 401)
                for event in ("CONTENT_PROVIDER_QUERY_STARTED", "CONTENT_PROVIDER_OFFER_VERIFIED",
                              "CONTENT_EXACT_LOOKUP_STARTED", "CONTENT_EXACT_LOOKUP_FINISHED"))
            relay.write_text(outside + "".join(row(ts, "CONTENT_EXACT_LOOKUP_STARTED")
                + row(ts+1, "CONTENT_EXACT_LOOKUP_FINISHED") for ts in (200, 250, 399)), encoding="ascii")
            client.write_text("".join(row(ts, event) for ts in (199, 201, 251, 400, 401)
                for event in ("CONTENT_DISCOVERY_RECEIVED_OFFERS", "CONTENT_DISCOVERY_COMPLETED"))
                + row(300, "CONTENT_DISCOVERY_RECEIVED_EMPTY"), encoding="ascii")
            self.assertEqual(count(), [0, 0, 3, 3, 3, 3])
            relay.write_text(outside + row(200, "CONTENT_PROVIDER_QUERY_STARTED")
                + row(300, "CONTENT_PROVIDER_OFFER_VERIFIED") * 3, encoding="ascii")
            client.write_text(row(400, "CONTENT_DISCOVERY_RECEIVED_OFFERS")
                + row(400, "CONTENT_DISCOVERY_COMPLETED"), encoding="ascii")
            self.assertEqual(count(), [1, 3, 1, 0, 0, 1])
            client.write_text(row(400, "CONTENT_DISCOVERY_RECEIVED_EMPTY")
                + row(400, "CONTENT_DISCOVERY_COMPLETED"), encoding="ascii")
            self.assertEqual(count(), [1, 3, 1, 0, 0, 0])

    def test_contraction_requires_three_actual_leases_and_available_resources(self):
        for key, value in (("initial_allowance", 2), ("peak_leases", 2), ("min_allowance", 2),
                           ("min_memory_workers", 2), ("min_fd_workers", None), ("active_leases", 1),
                           ("outcome", "interrupted"), ("initial_allowance", True)):
            with self.subTest(key=key):
                self.rejected(lambda e: e["worker_budget"]["records"][0].__setitem__(key, value))

    def test_cpu_only_pressure_and_observation_are_mandatory(self):
        for cause in CHECK["BUDGET"]["CAUSES"]:
            self.rejected(lambda e: e["worker_budget"]["records"][0]["causes"].__setitem__(
                cause, cause != "cpu_pressure"))
        for key, value in (("success", False), ("cold_begin", False), ("publication", {})):
            self.rejected(lambda e: e["controller"].__setitem__(key, value))

    def test_no_progress_or_undrained_parallel_continuation_is_not_completion(self):
        for key, value in (("returned_useful_continuations", 0), ("retired_candidates", 4),
                           ("returned_verified_chunks", 0), ("returned_verified_bytes", 1),
                           ("initial_active_workers", 1), ("final_active_workers", 1),
                           ("peak_active_workers", 2), ("outcome", "failed")):
            with self.subTest(key=key):
                self.rejected(lambda e: e["continuation"]["records"][0].__setitem__(key, value))

    def test_complete_phase_bounded_diagnostic_not_other_batch_required(self):
        for name in ("worker_budget", "continuation"):
            for key, value in (("phase", "native"), ("complete", False), ("phase_closed", False),
                               ("status", "missing"), ("records", [])):
                self.rejected(lambda e: e[name].__setitem__(key, value))
            self.rejected(lambda e: e[name]["records"].append(copy.deepcopy(e[name]["records"][0])))
        self.rejected(lambda e: e["resource_ready"].__setitem__("phase", "native"))

    def test_ready_seed_and_bounded_real_cpu_event_are_bound_to_fetch(self):
        self.rejected(lambda e: e["ready"].__setitem__("cold_cache", False))
        self.rejected(lambda e: e["ready"]["publication"].__setitem__("manifest_id", "f"*64))
        self.rejected(lambda e: e["ready"].__setitem__("ready_ns", 20_000_000_000))
        self.rejected(lambda e: e["output"].__setitem__("started_monotonic_ns", 3_000_000_000))
        self.rejected(lambda e: e["output"].__setitem__("completed_monotonic_ns", 999_999_999))
        self.rejected(lambda e: e["output"].__setitem__("completed_monotonic_ns", 122_000_000_000))
        self.rejected(lambda e: e["output"].__setitem__("completed_unix_ms", 4_600_000))

    def test_full_correct_object_and_three_useful_providers_still_required(self):
        for key, value in (("bytes", CHECK["BYTES"]-1), ("chunks", 59), ("providers_used", 2),
                           ("peer_bytes", 0), ("origin_body_bytes", 1), ("origin_authenticated", True)):
            self.rejected(lambda e: e["fetch"].__setitem__(key, value))
        self.rejected(lambda e: e["output"].__setitem__("sha256", "0"*64))
        self.rejected(lambda e: e["output"].__setitem__("client_cache_initially_absent", False))
        self.rejected(lambda e: e["privacy"]["exit"]["provider_application"]["relay5"].__setitem__(
            "response_payload_bytes", 0))

    def test_original_route_and_existing_privacy_gates_remain_mandatory(self):
        self.rejected(lambda e: e["selected_route"].__setitem__("route_context_id", "c"*32))
        self.rejected(lambda e: e["selected_before"].__setitem__("new", "unexpected"))
        self.rejected(lambda e: e["privacy"]["client"].__setitem__("direct_client_exit_packets", 1))
        self.rejected(lambda e: e["privacy"]["relay0"].__setitem__("client_leg_wireguard_data_datagrams", 0))
        self.rejected(lambda e: e["privacy"]["exit"].__setitem__("packet_socket_drops", 1))
        evidence = fixture()
        evidence["selected_route"]["paths"][0]["reported_bytes"] = 999
        CHECK["validate"](evidence)  # Counters may grow; ownership and path identities may not.

    def test_exact_owned_qdiscs_restore_config_not_packet_statistics(self):
        self.rejected(lambda e: e["qdisc"]["limited"]["relay3"][0]["options"].__setitem__("rate", 500000))
        self.rejected(lambda e: e["qdisc"]["limited"]["relay4"][0].__setitem__("handle", "885:"))
        self.rejected(lambda e: e["qdisc"]["after"]["relay5"][0].__setitem__("kind", "tbf"))
        self.rejected(lambda e: e["qdisc"]["profile"].__setitem__("queue_latency_ms", 500))
        evidence = fixture()
        for row in evidence["qdisc"]["limited"].values():
            del row[0]["options"]["lat"]
            del row[0]["options"]["burst"]
        CHECK["validate"](evidence)  # Kernel may omit fields; exact commanded profile is retained.

    def test_provider_stop_and_owned_cleanup_are_independent_gates(self):
        for key in CHECK["CLEANUP"]:
            self.rejected(lambda e: e["cleanup"].__setitem__(key, False))
        self.rejected(lambda e: e["providers"]["relay4"]["stop"].__setitem__("serving", True))
        self.rejected(lambda e: e["providers"]["relay5"]["serve"].__setitem__("publications", 2))

    def test_scope_and_unknown_fields_fail_closed(self):
        self.rejected(lambda e: e.__setitem__("unknown", "unexpected"))
        self.rejected(lambda e: e["scope"].__setitem__("owner_goodput_claimed", True))
        self.rejected(lambda e: e["publication"].__setitem__("unknown", "unexpected"))
        self.rejected(lambda e: e["fetch"].__setitem__("origin_body_bytes", False))
        self.rejected(lambda e: e["selected_route"].__setitem__("source", "substituted"))

    def test_builder_reconstructs_only_raw_phase_receipts(self):
        evidence = fixture()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            write_files(work, evidence)
            self.assertEqual(CHECK["build_evidence"](work), evidence)
            target = work/(CHECK["PREFIX"] + "-worker-budget.json")
            target.chmod(0o666)
            with self.assertRaises(ValueError):
                CHECK["build_evidence"](work)

    def test_ready_rejects_duplicate_keys_oversize_and_unpublished_partial(self):
        evidence = fixture()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            write_files(work, evidence)
            target = work/(CHECK["PREFIX"] + "-ready.json")
            target.write_text('{"schema_version":1,"schema_version":1}', encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["ready"](work)
            target.write_text(" " * 4097, encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["ready"](work)
            target.rename(work/("." + target.name + ".part"))
            with self.assertRaises(FileNotFoundError):
                CHECK["ready"](work)

    def test_ready_checks_same_descriptor_modes_links_lifetime_and_atomic_name(self):
        evidence = fixture()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            write_files(work, evidence)
            with patch.object(CHECK["time"], "time", return_value=1001), \
                    patch.object(CHECK["time"], "monotonic_ns", return_value=1_500_000_000):
                self.assertEqual(CHECK["ready"](work), evidence["ready"])
                target = work/(CHECK["PREFIX"] + "-ready.json")
                original = work/"original-ready.json"
                target.rename(original)
                target.symlink_to(original.name)
                with self.assertRaises(OSError):
                    CHECK["ready"](work)
                target.unlink()
                os.link(original, target)
                with self.assertRaises(ValueError):
                    CHECK["ready"](work)
                target.unlink()
                with self.assertRaises(FileNotFoundError):
                    CHECK["ready"](work)
                original.rename(target)
            with patch.object(CHECK["time"], "time", return_value=4600), \
                    patch.object(CHECK["time"], "monotonic_ns", return_value=1_500_000_000):
                with self.assertRaises(ValueError):
                    CHECK["ready"](work)
            with patch.object(CHECK["time"], "time", return_value=1001), \
                    patch.object(CHECK["time"], "monotonic_ns", return_value=31_000_000_000):
                with self.assertRaises(ValueError):
                    CHECK["ready"](work)


if __name__ == "__main__":
    unittest.main()
