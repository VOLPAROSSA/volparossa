#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable pressure-retirement component; not owner-goodput or PSI-recovery proof.

The controller observes real guest CPU PSI after three verified cold-cache chunks.
Production diagnostics independently prove admission contraction and useful serial
continuation. Exact reconstruction and protected-path captures are still mandatory.
Schema 2 distinguishes generic discovery from authenticated recent-provider refresh;
an exact-lookup completion alone is not proof of a nonempty verified response.
"""
import os
from pathlib import Path
import re
import runpy
import sys
import time

HERE = Path(__file__).resolve().parent
ADAPTIVE = runpy.run_path(str(HERE / "content-provider-adaptive-smoke.py"))
CONTROLLER = runpy.run_path(str(HERE / "content-provider-pressure.py"))
BUDGET = runpy.run_path(str(HERE / "content-provider-worker-budget.py"))
RESOURCE = runpy.run_path(str(HERE / "content-provider-resource-ready.py"))
BASE = ADAPTIVE["BASE"]
require, NODES, ROLES = ADAPTIVE["require"], ADAPTIVE["NODES"], ADAPTIVE["ROLES"]
PREFIX = "content-provider-pressure"
BYTES, CHUNKS, SHA = (ADAPTIVE[key] for key in ("BYTES", "CHUNKS", "SHA"))
MAX_FILE = 65536
MAX_EVIDENCE = 262144
SCOPE = dict(disposable_guest=True, real_cpu_pressure=True, synthetic_budget=False,
             pressure_recovery_claimed=False, owner_goodput_claimed=False)
FIELDS = {"schema_version", "kind", "success", "scope", "publication", "expected_peers",
          "layout", "original_selected_route", "selected_before", "selected_route",
          "status_before", "status_after", "fetch", "output", "privacy", "control_underlay",
          "control_filter", "providers", "resource_ready", "ready", "controller",
          "worker_budget", "continuation", "qdisc", "cleanup"}
QDISC_PROFILE = dict(profile="fixed-provider-egress-2mbit",
                     devices={node: f"r{node[-1]}x" for node in NODES}, handle="884:",
                     rate_bits_per_second=2000000, burst_bytes=131072, queue_latency_ms=250)
CLEANUP = dict(controller_reaped=True, fetch_reaped=True, owned_output_removed=True,
               cache_teardown_deferred_to_topology=True, qdisc_restored=True, route_retained=True)
DISCOVERY_COUNTS = {"generic_dht_queries", "authenticated_upstream_offers", "client_forwarded_discovery",
                    "exact_lookup_started", "exact_lookup_finished", "client_nonempty_verified_responses"}
OUTPUT_FIELDS = DISCOVERY_COUNTS | {"sha256", "bytes", "client_cache_initially_absent",
    "client_mount_positive_control", "client_mount_cannot_read_replica_stores",
    "publisher_process_exited_before_fetch", "event_baseline_unix_ms", "started_monotonic_ns",
    "completed_monotonic_ns", "started_unix_ms", "completed_unix_ms"}


def integer(value, low=0, high=2**64-1):
    return type(value) is int and low <= value <= high


def validate_discovery(output):
    require(type(output) is dict and set(output) == OUTPUT_FIELDS
            and all(integer(output[key], 0, 2**32-1) for key in DISCOVERY_COUNTS),
            "closed phase-bound discovery counters required")
    queries, offers, completed = (output[key] for key in
        ("generic_dht_queries", "authenticated_upstream_offers", "client_forwarded_discovery"))
    started, finished, nonempty = (output[key] for key in
        ("exact_lookup_started", "exact_lookup_finished", "client_nonempty_verified_responses"))
    require(finished <= started and 1 <= nonempty <= completed,
            "fresh verified broker response absent or counters inconsistent")
    generic = queries >= 1 and offers >= 3
    # Recent hints are only identities, scoped to this route/policy/control broker.
    # The production client independently checks authority, targets, signatures and
    # expiry before emitting RECEIVED_OFFERS. Exact FINISHED may instead be empty.
    exact = queries == offers == 0 and 3 <= nonempty <= finished <= started
    require(generic or exact, "neither generic discovery nor three authenticated exact refreshes proved")


def publication(value):
    keys = {"report_kind", "publisher_hex", "manifest_id", "object_sha256", "bytes", "chunks",
            "created_unix_seconds", "expires_unix_seconds", "publisher_removed",
            "publisher_private_key_persisted", "recipient_encrypted"}
    keys |= {f"replica_{label}_{kind}" for label in "abc" for kind in ("chunks", "bytes")}
    require(type(value) is dict and set(value) == keys, "unexpected publication envelope")
    require(value["report_kind"] == "volparossa-content-adaptive-provider-seed"
            and value["object_sha256"] == SHA and integer(value["bytes"], BYTES, BYTES)
            and integer(value["chunks"], CHUNKS, CHUNKS)
            and value["publisher_removed"] is True and value["publisher_private_key_persisted"] is False
            and value["recipient_encrypted"] is False, "original public adaptive object missing")
    require(all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
                for key in ("manifest_id", "publisher_hex")), "original publisher/manifest binding invalid")
    require(integer(value["created_unix_seconds"], 1) and integer(value["expires_unix_seconds"], 1)
            and value["expires_unix_seconds"] - value["created_unix_seconds"] == 3600,
            "original publication lifetime changed")
    for label in "abc":
        require(integer(value[f"replica_{label}_chunks"], 20, 20)
                and integer(value[f"replica_{label}_bytes"], 5242880, 5242880),
                "original disjoint provider shard changed")
    return {key: value[key] for key in ("manifest_id", "publisher_hex", "object_sha256")}


def validate_ready(value, seed):
    require(type(value) is dict and set(value) ==
            {"schema_version", "kind", "cold_cache", "ready_ns", "publication"}
            and integer(value["schema_version"], 1, 1)
            and value["kind"] == "content-provider-pressure-ready"
            and value["cold_cache"] is True and integer(value["ready_ns"], 1)
            and value["publication"] == publication(seed), "controller readiness is not bound to cold original input")
    return value


def diagnostic(value, kind, validator):
    require(type(value) is dict and set(value) ==
            {"schema_version", "kind", "phase", "phase_closed", "complete", "status", "records"}
            and integer(value["schema_version"], 1, 1) and value["kind"] == kind
            and value["phase"] == "pressure" and value["phase_closed"] is True
            and value["complete"] is True and value["status"] == "observed"
            and type(value["records"]) is list and len(value["records"]) == 1,
            "one complete phase-bound production diagnostic required")
    return validator(value["records"][0])


def validate_diagnostics(evidence):
    ready = RESOURCE["validate"](evidence["resource_ready"])
    require(ready["phase"] == "pressure" and ready["status"] == "ready",
            "pressure phase lacks real initial resource readiness")
    budget = diagnostic(evidence["worker_budget"], "content-worker-budget-diagnostic", BUDGET["summary"])
    require(budget["outcome"] == "returned"
            and integer(budget["initial_allowance"], 3)
            and integer(budget["min_allowance"], 0, 1)
            and integer(budget["max_allowance"], budget["initial_allowance"])
            and integer(budget["min_memory_workers"], 3) and integer(budget["min_fd_workers"], 3)
            and budget["peak_leases"] >= 3 and budget["active_leases"] == 0
            and budget["causes"] == {key: key == "cpu_pressure" for key in BUDGET["CAUSES"]},
            "three admitted workers did not contract under observed CPU-only pressure")
    continuation = diagnostic(evidence["continuation"], "content-provider-continuation-diagnostic",
                              BUDGET["continuation_summary"])
    require(continuation["outcome"] == "returned"
            and 1 <= continuation["returned_useful_continuations"]
                <= continuation["admitted_continuations"] <= continuation["prepared_continuations"]
                <= continuation["retired_candidates"] <= 3
            and 1 <= continuation["returned_verified_chunks"] <= CHUNKS
            and continuation["returned_verified_bytes"] == continuation["returned_verified_chunks"] * 262144
            and continuation["initial_active_workers"] == continuation["final_active_workers"] == 0
            and continuation["peak_active_workers"] == 1,
            "drained original batch lacks useful single-use serial continuation")


def validate_qdisc(value):
    require(type(value) is dict and set(value) == {"profile", "before", "limited", "after"}
            and value["profile"] == QDISC_PROFILE, "fixed disposable shaping profile changed")
    for key in ("rate_bits_per_second", "burst_bytes", "queue_latency_ms"):
        require(type(value["profile"][key]) is int, "invalid shaping profile number")
    for phase in ("before", "limited", "after"):
        require(type(value[phase]) is dict and set(value[phase]) == set(NODES), "shaping coverage incomplete")
        for node in NODES:
            rows = value[phase][node]
            require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
                    "unexpected disposable egress qdisc")
            row = rows[0]
            require(row["root"] is True, "qdisc is not the selected egress root")
            if "dev" in row:
                require(row["dev"] == QDISC_PROFILE["devices"][node], "qdisc device changed")
            if phase == "limited":
                require(row["kind"] == "tbf" and row["handle"] == "884:"
                        and type(row["options"]) is dict
                        and integer(row["options"]["rate"], 250000, 250000), "fixed egress rate absent")
                for key, expected in (("burst", 131072), ("lat", 250000)):
                    if key in row["options"]:
                        require(integer(row["options"][key], expected, expected), "observed qdisc option changed")
            else:
                require(row["kind"] == "noqueue" and row["handle"] == "0:", "original noqueue not restored")
    for node in NODES:
        # Packet counters/refcounts may legitimately change; root configuration may not.
        config = lambda row: {key: row.get(key) for key in ("kind", "handle", "root", "options", "dev")}
        require(config(value["before"][node][0]) == config(value["after"][node][0]),
                "preexisting egress configuration not restored")


def validate(evidence):
    require(type(evidence) is dict and set(evidence) == FIELDS
            and integer(evidence["schema_version"], 2, 2)
            and evidence["kind"] == "content-provider-pressure-smoke" and evidence["success"] is True
            and evidence["scope"] == SCOPE and all(type(v) is bool for v in evidence["scope"].values()),
            "invalid closed pressure component")
    seed, peers, layout = (evidence[key] for key in ("publication", "expected_peers", "layout"))
    binding = publication(seed)
    ready = validate_ready(evidence["ready"], seed)
    controller = CONTROLLER["validate"](evidence["controller"])
    require(controller["success"] is True and controller["publication"] == binding
            and ready["ready_ns"] <= controller["started_ns"], "real controller completion missing or substituted")
    validate_diagnostics(evidence)
    require(layout["provider_nodes"] == list(NODES) and len(set(peers.values())) == len(peers),
            "three independent provider identities missing")
    control = layout["control_relay_peer_id"]
    nodes = [node for node in ROLES[1:4] if peers[node] == control]
    require(len(nodes) == 1 and control not in {peers[node] for node in NODES}, "broker not independent")
    require(all(evidence[key]["control_relay_peer_id"] == control
                for key in ("status_before", "status_after", "fetch")), "control authority changed")
    fetch, output = evidence["fetch"], evidence["output"]
    validate_discovery(output)
    require(fetch["operation"] == "native_content" and integer(fetch["bytes"], BYTES, BYTES)
            and integer(fetch["chunks"], CHUNKS, CHUNKS) and integer(fetch["providers_used"], 3, 3)
            and type(fetch["provider_peer_ids"]) is list and len(fetch["provider_peer_ids"]) == 3
            and set(fetch["provider_peer_ids"]) == {peers[node] for node in NODES}
            and integer(fetch["peer_bytes"], BYTES, BYTES) and integer(fetch["origin_body_bytes"], 0, 0)
            and integer(fetch["origin_range_requests"], 0, 0) and fetch["origin_authenticated"] is False,
            "full native transfer from three useful protected providers missing")
    require(output["sha256"] == SHA and integer(output["bytes"], BYTES, BYTES)
            and all(output[key] is True for key in ("client_cache_initially_absent", "client_mount_positive_control",
                    "client_mount_cannot_read_replica_stores", "publisher_process_exited_before_fetch"))
            and integer(output["event_baseline_unix_ms"], 1), "cold verified reconstruction/isolation absent")
    for key in ("started_monotonic_ns", "completed_monotonic_ns", "started_unix_ms", "completed_unix_ms"):
        require(integer(output[key], 1), "invalid original fetch clock")
    require(ready["ready_ns"] <= output["started_monotonic_ns"] <= controller["trigger_ns"]
            <= controller["first_pressure_ns"] <= output["completed_monotonic_ns"]
            and 0 < output["completed_monotonic_ns"] - output["started_monotonic_ns"] <= 120_000_000_000
            and seed["created_unix_seconds"] * 1000 <= output["started_unix_ms"]
            and output["event_baseline_unix_ms"] <= output["started_unix_ms"]
            <= output["completed_unix_ms"] < seed["expires_unix_seconds"] * 1000,
            "CPU event occurred outside the original bounded, live-publication fetch")
    original, before, live = (evidence[key] for key in
                              ("original_selected_route", "selected_before", "selected_route"))
    def route_identity(value):
        return dict(value, paths=[{key: item for key, item in path.items()
                                  if key not in {"reported_bytes", "smoothed_rtt_us", "state"}}
                                 for path in value["paths"]])
    require(original == before and route_identity(before) == route_identity(live),
            "original protected route was replaced or rebound")
    BASE["validate_path"](evidence, peers, list(NODES), False)
    for node in NODES:
        count = evidence["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"]
        require(integer(count, ADAPTIVE["SHARD_BYTES"], ADAPTIVE["SHARD_BYTES"] + 131072),
                "provider payload differs from its original disjoint shard")
    ADAPTIVE["validate_control"](evidence, nodes[0])
    ADAPTIVE["validate_filter"](evidence["control_filter"])
    require(type(evidence["providers"]) is dict and set(evidence["providers"]) == set(NODES),
            "provider lifecycle coverage incomplete")
    for provider in evidence["providers"].values():
        require(type(provider) is dict and set(provider) == {"reset", "serve", "status", "stop"},
                "unexpected provider lifecycle records")
        for operation in ("reset", "stop"):
            require(provider[operation]["serving"] is False
                    and integer(provider[operation]["publications"], 0, 0), "provider stop incomplete")
        for operation in ("serve", "status"):
            require(provider[operation]["serving"] is True
                    and integer(provider[operation]["publications"], 1, 1)
                    and provider[operation]["replication_enabled"] is False, "original isolated service missing")
    validate_qdisc(evidence["qdisc"])
    require(evidence["cleanup"] == CLEANUP and all(type(v) is bool for v in evidence["cleanup"].values()),
            "pressure-owned resources not reaped/restored or enclosing cache ownership lost")
    return evidence


def read_at(directory, filename, maximum=MAX_FILE):
    return BUDGET["decode"](CONTROLLER["file_bytes"](directory, filename, os.geteuid(), maximum))


def ready(work):
    work = Path(work)
    require(work.is_absolute() and work.resolve() == work, "unsafe fixture root")
    directory = CONTROLLER["directory"](work, os.geteuid())
    try:
        seed = read_at(directory, "content-provider-adaptive-publication.json", 4096)
        value = validate_ready(read_at(directory, PREFIX + "-ready.json", 4096), seed)
        require(seed["created_unix_seconds"] <= int(time.time()) < seed["expires_unix_seconds"]
                and 0 <= time.monotonic_ns() - value["ready_ns"] < 30_000_000_000,
                "stale ready receipt or expired original publication")
        return value
    finally:
        os.close(directory)


def build_evidence(work):
    work = Path(work)
    require(work.is_absolute() and work.resolve() == work, "unsafe fixture root")
    directory = CONTROLLER["directory"](work, os.geteuid())
    try:
        evidence = dict(schema_version=2, kind="content-provider-pressure-smoke", success=True, scope=dict(SCOPE))
        for key, filename in (("publication", "content-provider-adaptive-publication.json"),
                ("expected_peers", "a01-expected-peers.json"),
                ("layout", "content-provider-adaptive-layout.json"),
                ("original_selected_route", "content-provider-adaptive-live-selection.json"),
                ("control_filter", "content-provider-adaptive-control-filter.json")):
            evidence[key] = read_at(directory, filename)
        for key, suffix in (("selected_before", "selection"), ("selected_route", "live-selection"),
                ("status_before", "status-before"), ("status_after", "status-after"), ("fetch", "fetch"),
                ("output", "object"), ("ready", "ready"), ("controller", "controller"),
                ("resource_ready", "resource-ready"), ("worker_budget", "worker-budget"),
                ("continuation", "continuation"), ("cleanup", "cleanup")):
            evidence[key] = read_at(directory, f"{PREFIX}-{suffix}.json")
        evidence["privacy"] = {role: read_at(directory, f"{PREFIX}-privacy-{role}.json") for role in ROLES}
        evidence["control_underlay"] = dict(capture=read_at(directory, f"{PREFIX}-control-privacy.json"),
            routes={node: {direction: read_at(directory, f"content-provider-adaptive-control-{node}-{direction}.json")
                           for direction in ("out", "back")} for node in NODES})
        evidence["providers"] = {node: {operation: read_at(directory, f"{PREFIX}-{node}-{operation}.json")
                                        for operation in ("reset", "serve", "status", "stop")} for node in NODES}
        evidence["qdisc"] = {phase: read_at(directory, f"{PREFIX}-qdisc-{phase}.json")
                             for phase in ("profile", "before", "limited", "after")}
        return validate(evidence)
    finally:
        os.close(directory)


build = build_evidence


def main(argv):
    try:
        if len(argv) == 3 and argv[1] == "ready":
            ready(Path(argv[2]))
        elif len(argv) == 4 and argv[1] == "evidence":
            value = build_evidence(Path(argv[2]))
            BUDGET["write_private"](Path(argv[3]), value, MAX_EVIDENCE, exclusive=True)
        else:
            raise ValueError("usage: pressure-smoke.py ready WORK | evidence WORK OUTPUT")
        return 0
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, RecursionError):
        print("CONTENT_PROVIDER_PRESSURE_EVIDENCE_INVALID", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
