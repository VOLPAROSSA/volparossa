#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded evidence checker for native replica transfer, not HTTPS/A01-A15 acceptance."""

import json
from pathlib import Path
import re
import sys

ROLES = ("client", "relay0", "relay1", "relay2", "exit")
DESTINATION = {"ip": "47.163.4.2", "port": 18080}
OBJECT_BYTES = 2 * 1024 * 1024 + 123


def read(path):
    if path.is_symlink():
        raise ValueError("symlink evidence is not accepted")
    with path.open(encoding="ascii") as source:
        text = source.read(1048577)
    if len(text) > 1048576:
        raise ValueError("evidence exceeds its bound")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("evidence must be an object")
    return value


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def validate_transfer(evidence):
    publication = evidence["publication"]
    result = evidence["reconstructed_object"]
    require(publication["publisher_removed"] is True
            and publication["publisher_private_key_persisted"] is False
            and publication["bytes"] == OBJECT_BYTES and publication["chunks"] == 9
            and publication["replica_a_chunks"] == 5 and publication["replica_b_chunks"] == 4
            and re.fullmatch(r"[0-9a-f]{64}", publication["publisher_hex"])
            and re.fullmatch(r"[0-9a-f]{64}", publication["object_sha256"]),
            "publisher or disjoint replica seed not proven")
    require(result["bytes"] == OBJECT_BYTES and result["sha256"] == publication["object_sha256"]
            and result["client_cache_initially_absent"] is True
            and result["client_cannot_read_replica_stores"] is True
            and result["publisher_process_exited_before_fetch"] is True,
            "independent network reconstruction not proven")
    require(len(evidence["phases"]) == 2, "exactly two replica transfers required")
    providers = []
    consumers = []
    for index, phase in enumerate(evidence["phases"]):
        replica = "ab"[index]
        received_chunks = (5, 4)[index]
        received_bytes = (1048699, 1048576)[index]
        provider, consumer = phase["provider"], phase["consumer"]
        selected, gates = phase["selected_route"], phase["protected_gates"]
        providers.append(provider["pid"])
        consumers.append(consumer["pid"])
        require(provider["replica"] == replica and provider["pid"] == gates["serving_pid"]
                and provider["pid"] > 0 and consumer["pid"] > 0
                and provider["listen"] == DESTINATION
                and provider["source"]["ip"] == "47.163.4.1"
                and 0 < provider["source"]["port"] <= 65535,
                "replica identity or Exit-only source not proven")
        require(provider["chunks_sent"] == consumer["chunks_received"] == received_chunks
                and provider["bytes_sent"] == consumer["bytes_received"] == received_bytes
                and provider["missing"] == consumer["missing"] == (4, 0)[index]
                and consumer["cached_chunks"] == (5, 9)[index]
                and consumer["complete"] is bool(index)
                and consumer["output_bytes"] == (0, OBJECT_BYTES)[index]
                and consumer["object_sha256"] == (None, publication["object_sha256"])[index],
                "partial then complete chunk retrieval not proven")
        paths, slots = selected["paths"], selected["benchmark_slots"]
        require(selected["transport"] == "mptcp" and len(paths) == len(slots) == 2
                and re.fullmatch(r"[0-9a-f]{32}", selected["route_context_id"])
                and len({path["relay_peer_id"] for path in paths}) == 2
                and len({path["exit_peer_id"] for path in paths}) == 1
                and all(path["route_context_id"] == selected["route_context_id"]
                        and path["relay_peer_id"] != path["exit_peer_id"] for path in paths)
                and [slot["relay_peer_id"] for slot in slots]
                    == [path["relay_peer_id"] for path in paths],
                "same-Exit two-Relay MPTCP route not proven")
        require(gates["publisher_process_exited_before_fetch"] is True
                and gates["event_baseline_unix_ms"] > 0
                and gates["ingress_completed"] is True
                and gates["exit_mptcp_tls_open_completed"] is True,
                "actual protected ingress/egress gates not proven")
        privacy = phase["privacy"]
        require(set(privacy) == set(ROLES), "privacy coverage incomplete")
        for role, capture in privacy.items():
            require(capture["capture_role"] == role and capture["truncated"] is False
                    and capture["packet_socket_drops"] == 0
                    and capture["observed_frames"] > 0
                    and capture["expected_link_down_notifications"] == 0
                    and capture["unexpected_outer_packets"] == 0,
                    "capture incomplete or unexpected outer traffic")
        require(privacy["client"]["direct_client_exit_packets"] == 0
                and privacy["client"]["internet_destination_outer_packets"] == 0
                and privacy["exit"]["client_public_packets"] == 0
                and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
                and privacy["exit"]["direct_client_exit_packets"] == 0
                and all(privacy[role]["internet_destination_outer_packets"] == 0
                        for role in ("relay0", "relay1", "relay2")),
                "direct destination or client/Exit privacy violation")
        relay_nodes = [slot["relay_node"] for slot in slots]
        require(len(set(relay_nodes)) == 2 and all(node in ROLES[1:4] for node in relay_nodes),
                "invalid physical relay bindings")
        for node in relay_nodes:
            require(privacy[node]["client_leg_wireguard_data_datagrams"] > 16
                    and privacy[node]["exit_leg_wireguard_data_datagrams"] > 16,
                    "selected physical WireGuard legs did not carry sufficient actual data")
        for role, capture in phase["application_captures"].items():
            require(role in {"client", "exit"} and capture["capture_role"] == role
                    and capture["truncated"] is False and capture["observed_frames"] > 0
                    and capture["benchmark_relay_nodes"] == relay_nodes
                    and capture["relay1_wireguard_data_datagrams"] > 0
                    and capture["relay2_wireguard_data_datagrams"] > 0,
                    "application route capture incomplete")
        require(set(phase["application_captures"]) == {"client", "exit"}
                and phase["application_captures"]["client"]["direct_client_exit_packets"] == 0
                and phase["application_captures"]["exit"]["destination_request_segments"] > 0
                and phase["application_captures"]["exit"]["destination_response_segments"] > 0,
                "actual authorized destination transfer not observed")
    require(len(set(providers)) == len(set(consumers)) == 2,
            "two separate provider/client process lifetimes required")


def build_evidence(work):
    phases = []
    for replica in "ab":
        prefix = f"content-{replica}"
        phases.append({
            "provider": read(work / f"{prefix}-provider.json"),
            "consumer": read(work / f"{prefix}-fetch.json"),
            "selected_route": read(work / f"{prefix}-live-selection.json"),
            "protected_gates": read(work / f"{prefix}-gates.json"),
            "privacy": {role: read(work / f"{prefix}-privacy-{role}.json") for role in ROLES},
            "application_captures": {
                role: read(work / f"{prefix}-{role}-capture.json") for role in ("client", "exit")},
        })
    evidence = {"publication": read(work / "content-publication.json"), "phases": phases,
                "reconstructed_object": read(work / "content-object.json")}
    validate_transfer(evidence)
    return {"success": True, **evidence}


def validate_report(report, revision):
    require(report["report_kind"] == "volparossa-native-content-network"
            and report["source_revision"] == revision and report["success"] is True
            and report["runner_exit_status"] == 0
            and report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"]
            and re.fullmatch(r"[0-9a-f]{64}", report["host_state"]["before_sha256"])
            and report["full_alpha_acceptance_claimed"] is False
            and report["distinct_provider_nodes_claimed"] is False
            and report["provider_discovery_claimed"] is False
            and report["https_authentication_claimed"] is False,
            "exact source, cleanup or honest proof scope not established")
    validate_transfer(report["transfer"])


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: evidence WORK OUTPUT | report REPORT EXPECTED_REVISION")
        if sys.argv[1] == "evidence":
            value = build_evidence(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as output:
                output.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        elif sys.argv[1] == "report":
            validate_report(read(Path(sys.argv[2])), sys.argv[3])
        else:
            raise ValueError("unknown evidence mode")
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"content network evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
