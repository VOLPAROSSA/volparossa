#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded native HTTPS/peer evidence, not universal browser or full C08 acceptance."""

import json
from pathlib import Path
import re
import runpy
import sys

COMMON = runpy.run_path(str(Path(__file__).with_name("content-network-smoke.py")))
read, require = COMMON["read"], COMMON["require"]
ROLES = COMMON["ROLES"]
BYTES = COMMON["OBJECT_BYTES"]
SHA = COMMON["FIXTURE_PLAINTEXT_SHA256"]
SCOPE = ("browser_integration_claimed", "provider_discovery_claimed",
         "distinct_provider_nodes_claimed", "speed_improvement_claimed",
         "full_c08_claimed", "full_alpha_acceptance_claimed")


def exit_source(source):
    return bool(re.fullmatch(r"47\.163\.4\.1:[0-9]{1,5}", source)) \
        and 0 < int(source.rsplit(":", 1)[1]) <= 65535


def validate_path(phase):
    selected = phase["selected_route"]
    paths, slots = selected["paths"], selected["benchmark_slots"]
    require(selected["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and re.fullmatch(r"[0-9a-f]{32}", selected["route_context_id"])
            and len({p["relay_peer_id"] for p in paths}) == 2
            and len({p["exit_peer_id"] for p in paths}) == 1
            and all(p["route_context_id"] == selected["route_context_id"]
                    and p["relay_peer_id"] != p["exit_peer_id"] for p in paths)
            and [s["relay_peer_id"] for s in slots] == [p["relay_peer_id"] for p in paths],
            "same-Exit two-Relay selected route not proven")
    privacy = phase["privacy"]
    require(set(privacy) == set(ROLES), "privacy coverage incomplete")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["truncated"] is False
                and capture["observed_frames"] > 0 and capture["packet_socket_drops"] == 0
                and capture["unexpected_outer_packets"] == 0
                and capture["expected_link_down_notifications"] == 0,
                "privacy capture incomplete or unexpected traffic")
        statistics = capture["interface_statistics"]
        require(set(statistics) == set(capture["interfaces"])
                and sum(s["observed_frames"] for s in statistics.values()) == capture["observed_frames"]
                and all(s["intake_stopped"] is True and s["packet_socket_drops"] == 0
                        and s["packet_socket_packets"] == s["observed_frames"]
                        for s in statistics.values()), "privacy sockets not completely drained")
    require(privacy["client"]["direct_client_exit_packets"] == 0
            and privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[role]["internet_destination_outer_packets"] == 0 for role in ROLES[1:4]),
            "Client/Relay/Exit privacy boundary violated")
    nodes = [s["relay_node"] for s in slots]
    require(len(set(nodes)) == 2 and all(n in ROLES[1:4] for n in nodes), "invalid relay binding")
    for node in nodes:
        require(privacy[node]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[node]["exit_leg_wireguard_data_datagrams"] > 16,
                "selected WireGuard legs lack actual data")
    captures = phase["application_captures"]
    require(set(captures) == {"client", "exit"}, "peer application captures missing")
    for role, capture in captures.items():
        require(capture["capture_role"] == role and capture["truncated"] is False
                and capture["observed_frames"] > 0 and capture["benchmark_relay_nodes"] == nodes
                and capture["relay1_wireguard_data_datagrams"] > 0
                and capture["relay2_wireguard_data_datagrams"] > 0, "peer capture has no protected traffic")
    require(captures["client"]["direct_client_exit_packets"] == 0
            and captures["exit"]["destination_request_segments"] > 0
            and captures["exit"]["destination_response_segments"] > 0,
            "authorized peer request/response not observed")


def validate_transfer(evidence):
    publication, origin = evidence["publication"], evidence["origin"]
    require(publication["bytes"] == BYTES and publication["object_sha256"] == SHA
            and publication["chunks"] == 9 and publication["replica_a_chunks"] == 5
            and publication["replica_b_chunks"] == 4
            and publication["publisher_private_key_persisted"] is False
            and 0 < publication["metadata_bytes"] <= 1048576,
            "origin fixture or disjoint replicas invalid")
    records = origin["connections"]
    require(origin["pid"] > 0 and len(records) == 3
            and [r["kind"] for r in records] == ["metadata", "metadata", "body"]
            and [r["payload_bytes"] for r in records] == [publication["metadata_bytes"]] * 2 + [BYTES]
            and all(r["tls13"] is True and r["alpn_http11"] is True
                    and exit_source(r["source"]) for r in records),
            "two genuine origin metadata fetches plus one exact HTTPS fallback not proven")
    phases = evidence["phases"]
    require(len(phases) == 2, "complete and missing cases required")
    for index, phase in enumerate(phases):
        consumer, peers, gates = phase["consumer"], phase["peers"], phase["protected_gates"]
        expected_sessions = ((5, 1048699, 4), (4, 1048576, 0))[:2-index]
        require(consumer["variant"] == ("complete", "missing")[index]
                and consumer["pid"] > 0 and peers["pid"] == gates["peer_pid"] > 0
                and consumer["bytes"] == gates["bytes"] == BYTES
                and consumer["object_sha256"] == gates["object_sha256"] == SHA
                and consumer["peer_chunks"] == (9, 5)[index]
                and consumer["peer_bytes"] == (BYTES, 1048699)[index]
                and consumer["origin_body_bytes"] == (0, BYTES)[index]
                and consumer["fallback_used"] is bool(index)
                and consumer["origin_authenticated_before_peers"] is True
                and consumer["tls_interception_ca_installed"] is False
                and consumer["origin_authority_persisted"] is False
                and consumer["browser_integration_claimed"] is False,
                "authenticated peer completion or actual origin fallback not proven")
        sessions = peers["sessions"]
        require(len(sessions) == len(expected_sessions)
                and [s["replica"] for s in sessions] == ["replica-a", "replica-b"][:2-index]
                and [(s["chunks"], s["bytes"], s["missing"]) for s in sessions] == list(expected_sessions)
                and all(exit_source(s["source"]) for s in sessions)
                and sum(s["bytes"] for s in sessions) == consumer["peer_bytes"],
                "actual partial peer sessions or Exit-only sources not proven")
        require(gates["event_baseline_unix_ms"] > 0 and gates["ingress_completed"] >= 3
                and gates["exit_mptcp_tls_open_completed"] >= 3
                and gates["client_cache_initially_absent"] is True
                and gates["client_cannot_read_origin_or_replica_files"] is True,
                "three fresh protected streams or source isolation missing")
        validate_path(phase)
    require(phases[0]["consumer"]["pid"] != phases[1]["consumer"]["pid"]
            and phases[0]["peers"]["pid"] != phases[1]["peers"]["pid"]
            and phases[0]["selected_route"]["route_context_id"]
                == phases[1]["selected_route"]["route_context_id"],
            "separate consumers/providers and retained route not proven")


def build_evidence(work):
    phases = []
    for variant in ("complete", "missing"):
        prefix = f"content-https-{variant}"
        phases.append({
            "consumer": read(work / f"{prefix}-consumer.json"),
            "peers": read(work / f"{prefix}-peers.json"),
            "protected_gates": read(work / f"{prefix}-gates.json"),
            "selected_route": read(work / f"{prefix}-live-selection.json"),
            "privacy": {r: read(work / f"{prefix}-privacy-{r}.json") for r in ROLES},
            "application_captures": {r: read(work / f"{prefix}-{r}-capture.json") for r in ("client", "exit")},
        })
    evidence = dict(success=True, phases=phases, publication=read(work / "content-https-publication.json"),
                    origin=read(work / "content-https-origin.json"))
    validate_transfer(evidence)
    return evidence


def validate_report(report, revision):
    require(report["report_kind"] == "volparossa-https-content-network"
            and report["source_revision"] == revision and report["success"] is True
            and report["runner_exit_status"] == 0
            and report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"]
            and re.fullmatch(r"[0-9a-f]{64}", report["host_state"]["before_sha256"])
            and all(report[flag] is False for flag in SCOPE), "wrong build, cleanup, host state or scope")
    validate_transfer(report["transfer"])


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: content-https-smoke.py evidence WORK OUTPUT | report REPORT REVISION")
        if sys.argv[1] == "evidence":
            output = build_evidence(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as target:
                json.dump(output, target, sort_keys=True, separators=(",", ":"))
        elif sys.argv[1] == "report":
            validate_report(read(Path(sys.argv[2])), sys.argv[3])
        else:
            raise ValueError("unknown mode")
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise SystemExit(f"HTTPS content evidence rejected: {error}") from error
