#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-source P/Q uptake and protected re-serving; not general spare-capacity proof."""

import json
from pathlib import Path
import re
import runpy
import sys

CAPTURE = runpy.run_path(str(Path(__file__).with_name("content-replication-capture.py")))
P_BYTES, Q_BYTES = 524609, 262267
P_SHA = "507a1f72e20863b91dbd92265ad6d58499cc16fab5a9d753676c56bbe87cb836"
Q_SHA = "b5a1801633b0bb108ee611668a11f438f46f4d6d630f0bc394485a41ff2a401d"
ROLES = ("receiver", "relay-a", "relay-b", "exit", "provider")
RELAY_NODES = {"relay0", "relay1", "relay2"}
PHYSICAL_INTERFACES = {
    "client": {"underlay", "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cb1", "cb2"},
    "relay0": {"underlay", "r0c", "r0b1", "r0b2", "r0x", "r0x2", "r0a", "rp0"},
    "relay1": {"underlay", "r1c", "r1b1", "r1b2", "r1x", "r1a", "rp1"},
    "relay2": {"underlay", "r2c", "r2b1", "r2b2", "r2x", "r2a", "rp2"},
    "relay4": {"underlay", "r4c", "r4b1", "r4b2", "r4x", "ar0", "ar1", "ar2"},
    "relay5": {"underlay", "r5c", "r5b1", "r5b2", "r5x", "pr0", "pr1", "pr2"},
    "exit": {"underlay", "xr0", "xr1", "xr2", "xr3", "xr4", "xr5", "xd"},
}
SCOPE = ("full_c03_claimed", "full_c04_claimed", "speed_improvement_claimed",
         "browser_integration_claimed", "full_alpha_acceptance_claimed")
ISOLATION = ("replicator_cannot_read_original_cache", "consumer_cannot_read_either_cache",
             "reserve_manifest_not_supplied_to_replicator", "replica_cache_initially_absent",
             "final_cache_initially_absent", "original_listener_absent_before_final_fetch")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    with Path(path).open("rb") as source:
        data = source.read(2 * 1024 * 1024 + 1)
    require(len(data) <= 2 * 1024 * 1024, "oversized evidence")
    return json.loads(data)


def validate_route(route, peers):
    paths, slots = route["paths"], route["benchmark_slots"]
    selected_relays = {slot["relay_node"] for slot in slots}
    require(route["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and re.fullmatch(r"[0-9a-f]{32}", route["route_context_id"])
            and len(selected_relays) == 2 and selected_relays <= RELAY_NODES
            and [slot["relay_peer_id"] for slot in slots] == [path["relay_peer_id"] for path in paths]
            and all(slot["relay_peer_id"] == peers[slot["relay_node"]] for slot in slots)
            and {path["relay_peer_id"] for path in paths} == {peers[node] for node in selected_relays}
            and all(path["exit_peer_id"] == peers["exit"]
                    and path["route_context_id"] == route["route_context_id"] for path in paths),
            "actual same-Exit two-relay MPTCP route not proven")


def validate_capture(capture, layout, node):
    require(capture["capture_role"] == capture["node"] == node and capture["phase"] == layout["phase"]
            and capture["schema_version"] == 1 and capture["complete"] is True
            and capture["truncated"] is False and capture["observed_frames"] > 0
            and capture["packet_socket_drops"] == 0 and capture["forbidden_packets"] == 0
            and capture["malformed_packets"] == 0 and capture["direct_client_exit_packets"] == 0
            and capture["direct_provider_packets"] == 0,
            "incomplete physical capture or forbidden direct/plain traffic")
    statistics = capture["interface_statistics"]
    require(set(statistics) == set(capture["interfaces"]) == PHYSICAL_INTERFACES[node]
            and len(statistics) == len(capture["interfaces"])
            and all(re.fullmatch(r"underlay|[a-z][a-z0-9]{1,5}", interface)
                    and not interface.startswith("vp") and interface != "lo" for interface in statistics)
            and sum(row["observed_frames"] for row in statistics.values()) == capture["observed_frames"]
            and all(row["intake_stopped"] is True and row["drained"] is True
                    and row["packet_socket_drops"] == 0
                    and row["packet_socket_packets"] == row["observed_frames"]
                    and 4194304 <= row["receive_buffer_bytes"] <= 8388608 for row in statistics.values()),
            "physical packet intake not stopped and drained exactly")


def validate_phase(phase, name, peers):
    layout = phase["layout"]
    CAPTURE["validate_layout"](layout)
    relays = sorted(layout["relays"])
    require(layout["phase"] == name and set(relays) ==
            {slot["relay_node"] for slot in phase["route"]["benchmark_slots"]},
            "phase or selected relay capture substitution")
    validate_route(phase["route"], peers)
    captures = phase["captures"]
    require(set(captures) == set(ROLES), "five-role capture coverage incomplete")
    for role, capture in captures.items():
        node = (layout["client"]["node"] if role == "receiver" else
                layout["provider"]["node"] if role == "provider" else
                relays[0] if role == "relay-a" else relays[1] if role == "relay-b" else role)
        validate_capture(capture, layout, node)
    for slot, relay in zip(("relay-a", "relay-b"), relays):
        require(captures[slot]["client_leg_wireguard_data_datagrams"] > 16
                and captures[slot]["exit_leg_wireguard_data_datagrams"] > 16
                and captures["receiver"][f"{relay}_client_leg_wireguard_data_datagrams"] > 16
                and captures["exit"][f"{relay}_exit_leg_wireguard_data_datagrams"] > 16,
                "both physical WireGuard legs on both paths did not carry data")
    minimum_bytes = P_BYTES + Q_BYTES if name == "uptake" else Q_BYTES
    for role in ("exit", "provider"):
        require(captures[role]["provider_request_packets"] > 0
                and captures[role]["provider_response_packets"] > 0
                and captures[role]["provider_response_payload_bytes"] >= minimum_bytes,
                "actual Exit-to-provider request/response payload missing")
    for role in ("receiver", "relay-a", "relay-b"):
        require(captures[role]["provider_request_packets"] == 0
                and captures[role]["provider_response_packets"] == 0
                and captures[role]["provider_response_payload_bytes"] == 0,
                "provider application bytes escaped the protected path")


def validate_fetch(receipt, count, chunks, provider, control):
    require(receipt["bytes"] == receipt["peer_bytes"] == count and receipt["chunks"] == chunks
            and receipt["providers_used"] == 1 and receipt["provider_peer_ids"] == [provider]
            and receipt["control_relay_peer_id"] in control
            and receipt["origin_authenticated"] is False and receipt["origin_body_bytes"] == 0
            and receipt["origin_range_requests"] == 0,
            "exact independent provider, payload count or control lineage missing")


def validate_evidence(evidence):
    require(evidence["success"] is True, "incomplete transfer")
    seed, peers, output = evidence["publication"], evidence["expected_peers"], evidence["output"]
    require(seed["publisher_removed"] is True and seed["publisher_private_key_persisted"] is False
            and seed["replicator_seeded"] is False, "initial publisher/replicator isolation missing")
    for label, field, size, chunks, digest in (("p", "foreground", P_BYTES, 3, P_SHA),
                                              ("q", "reserve", Q_BYTES, 2, Q_SHA)):
        item = seed[field]
        require(item["label"] == label and item["bytes"] == item["seeded_cache_bytes"] == size
                and item["chunks"] == item["seeded_cache_entries"] == chunks
                and item["object_sha256"] == output[field]["sha256"] == digest
                and output[field]["bytes"] == size
                and item["publisher_removed"] is True and item["publisher_private_key_persisted"] is False
                and re.fullmatch(r"[0-9a-f]{64}", item["publisher_hex"])
                and re.fullmatch(r"[0-9a-f]{64}", item["manifest_id"]), "P/Q publication substitution")
    require(seed["foreground"]["publisher_hex"] == seed["reserve"]["publisher_hex"]
            and seed["foreground"]["manifest_id"] != seed["reserve"]["manifest_id"]
            and all(output[field] is True for field in ISOLATION), "cross-publication trust or isolation missing")
    control = {peers[node] for node in RELAY_NODES}
    require(len({peers[node] for node in ("client", "relay0", "relay1", "relay2", "relay4", "relay5", "exit")}) == 7,
            "fixture identities are not independent")
    validate_fetch(evidence["warm_fetch"], P_BYTES, 3, peers["relay5"], control)
    validate_fetch(evidence["foreground_fetch"], P_BYTES, 3, peers["relay5"], control)
    validate_fetch(evidence["final_fetch"], Q_BYTES, 2, peers["relay4"], control)
    before, after = evidence["before"], evidence["after"]
    require(before["serving"] is True and before["replication_enabled"] is True
            and before["replica_chunks"] == before["replica_bytes"] == before["replica_publications"] == 0
            and after["serving"] is True and after["replication_enabled"] is True
            and after["replica_chunks"] == 2 and after["replica_bytes"] == Q_BYTES
            and after["replica_publications"] == 1 and after["publications"] == 2
            and before["control_relay_peer_id"] == after["control_relay_peer_id"]
            == evidence["foreground_fetch"]["control_relay_peer_id"],
            "actual bounded new Q storage/registration after foreground P not proven")
    for record in (evidence["origin_stop"], evidence["replica_stop"]):
        require(record["serving"] is False and record["publications"] == 0,
                "service withdrawal incomplete")
    require(evidence["origin_offline"] == dict(unit="volparossa-alpha-agent@relay5.service",
            active_state="inactive", main_pid=0, listener_absent=True),
            "original provider agent was not stopped before final retrieval")
    for phase in ("uptake", "reserve-fetch"):
        validate_phase(evidence["phases"][phase], phase, peers)
        selected = evidence["phases"][phase]["route"]
        receipt = evidence["foreground_fetch"] if phase == "uptake" else evidence["final_fetch"]
        require(receipt["control_relay_peer_id"] not in
                {slot["relay_peer_id"] for slot in selected["benchmark_slots"]},
                "control relay was substituted by one of the two data relays")
    require(evidence["phases"]["uptake"]["route"]["route_context_id"] !=
            evidence["phases"]["reserve-fetch"]["route"]["route_context_id"],
            "independent consumer reused another node's route authority")
    events = evidence["events"]
    require(events["replica_chunks_available"] >= 1 and events["exit_mptcp_flows_completed"] >= 4
            and events["replicator_forwarded_discovery"] >= 2 and events["consumer_forwarded_discovery"] >= 1,
            "native replica registration, genuine MPTCP completion or forwarded discovery missing")


def build_evidence(work):
    mapping = {"publication": "publication", "output": "output", "warm_fetch": "warm-fetch",
               "foreground_fetch": "foreground-fetch", "final_fetch": "final-fetch",
               "before": "before", "after": "after", "origin_stop": "origin-stop",
               "origin_offline": "origin-offline", "replica_stop": "replica-stop"}
    evidence = {key: read(work / f"content-replication-{suffix}.json") for key, suffix in mapping.items()}
    evidence.update(success=True, expected_peers=read(work / "a01-expected-peers.json"), phases={})
    for phase, route in (("uptake", "uptake"), ("reserve-fetch", "final")):
        evidence["phases"][phase] = dict(layout=read(work / f"content-replication-{phase}-layout.json"),
            route=read(work / f"content-replication-{route}-live-selection.json"),
            captures={role: read(work / f"content-replication-{phase}-{role}.json") for role in ROLES})
    def event_count(node, event):
        with (work / f"logs-{node}.txt").open("rb") as source:
            data = source.read(2 * 1024 * 1024 + 1)
        require(len(data) <= 2 * 1024 * 1024, "oversized event log")
        return len(re.findall(rb"(?m)^\d+\s+\S+\s+event=" + event.encode("ascii") + rb"(?:\s|$)", data))
    evidence["events"] = dict(replica_chunks_available=event_count("relay4", "CONTENT_REPLICATION_CHUNKS_AVAILABLE"),
        exit_mptcp_flows_completed=event_count("exit", "MPTCP_EXIT_FLOW_COMPLETED"),
        replicator_forwarded_discovery=event_count("relay4", "CONTENT_DISCOVERY_COMPLETED"),
        consumer_forwarded_discovery=event_count("client", "CONTENT_DISCOVERY_COMPLETED"))
    require((work / "content-replication-origin-listeners.txt").stat().st_size == 0,
            "original provider listener remains")
    validate_evidence(evidence)
    return evidence


def validate_report(report, revision):
    require(report["report_kind"] == "volparossa-content-replication" and report["source_revision"] == revision
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision)
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"]
            and re.fullmatch(r"[0-9a-f]{64}", report["host_state"]["before_sha256"])
            and all(report[flag] is False for flag in SCOPE), "wrong revision, cleanup, host state or scope")
    validate_evidence(report["transfer"])


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: evidence WORK OUTPUT | report REPORT REVISION")
        if sys.argv[1] == "evidence":
            result = build_evidence(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as target:
                json.dump(result, target, sort_keys=True, separators=(",", ":"))
        elif sys.argv[1] == "report":
            validate_report(read(sys.argv[2]), sys.argv[3])
        else:
            raise ValueError("unknown command")
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"content replication evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
