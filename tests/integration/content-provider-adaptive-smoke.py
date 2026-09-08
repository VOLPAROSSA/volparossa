#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Three actual protected cache suppliers; no speed or unlimited-worker claim."""

import json
from pathlib import Path
import re
import runpy
import sys

BASE = runpy.run_path(str(Path(__file__).with_name("content-provider-https-smoke.py")))
read, require, ROLES = BASE["read"], BASE["require"], BASE["ROLES"]
NODES = ("relay3", "relay4", "relay5")
BYTES, CHUNKS, SHARD_BYTES = 3932160, 15, 1310720
SHA = "26fc4696f0ebcd7e36a3c0a0369e2d843742b3915a222ad57b49cd53020a9011"
PREFIX = "content-provider-adaptive"


def payload_overlap(capture):
    timing = capture["provider_payload_timing"]
    require(capture["capture_role"] == "exit" and timing["enabled"] is True
            and timing["clock"] == "linux-so-timestampns-new" and timing["errors"] == 0
            and timing["milestones_bytes"] == [65536, 983040]
            and set(timing["providers"]) == set(NODES),
            "three-provider overlap lacks error-free kernel arrival timestamps")
    windows = [timing["providers"][node] for node in NODES]
    require(all(isinstance(window, list) and len(window) == 2
                and all(type(value) is int for value in window)
                and 0 < window[0] < window[1] for window in windows),
            "all three providers must cross both bulk-payload milestones")
    overlap = min(window[1] for window in windows) - max(window[0] for window in windows)
    require(overlap > 0, "three protected provider bulk-payload intervals did not overlap")
    return overlap


def validate_control(evidence, control_node):
    underlay = evidence["control_underlay"]
    capture, routes = underlay["capture"], underlay["routes"]
    addresses = BASE["PUBLIC_IPS"]
    pairs = {f"ac{i}": [addresses[control_node], addresses[node]]
             for i, node in enumerate(NODES)}
    require(capture["capture_role"] == "content-control"
            and capture["content_provider_mode"] is True
            and capture["content_control_pairs"] == pairs
            and set(capture["interfaces"]) == set(pairs)
            and set(capture["content_control_packets"]) == set(pairs)
            and capture["unexpected_provider_control_packets"] == 0
            and capture["unexpected_provider_application_packets"] == 0
            and set(capture["provider_application"]) == set(NODES)
            and all(value == 0 for counters in capture["provider_application"].values()
                    for value in counters.values()),
            "three dedicated broker links carried unexpected traffic")
    BASE["validate_drained"](capture)
    require(set(routes) == set(NODES), "three actual broker route snapshots missing")
    for index, node in enumerate(NODES):
        counts = capture["content_control_packets"][f"ac{index}"]
        require(counts["inbound"] > 0 and counts["outbound"] > 0,
                "a provider lacks actual bidirectional broker control traffic")
        for direction, device, gateway, source, destination in (
                ("out", f"ac{index}", f"10.241.{83+index}.2", addresses[control_node], addresses[node]),
                ("back", f"ap{index}", f"10.241.{83+index}.1", addresses[node], addresses[control_node])):
            rows = routes[node][direction]
            require(isinstance(rows, list) and len(rows) == 1
                    and all(rows[0].get(key) == value for key, value in
                            dict(dev=device, gateway=gateway, prefsrc=source, dst=destination).items()),
                    "actual broker/provider route differs from its exact disposable link")


def validate_filter(snapshot):
    """Exact early Client contact restriction, not a change to production selection."""
    entries = snapshot["nftables"]
    table = "vpa_content_adaptive_client_control"
    require(len(entries) == 8 and len([entry for entry in entries if "metainfo" in entry]) == 1,
            "early Client control filter contains unexpected objects")
    tables = [entry["table"] for entry in entries if "table" in entry]
    chains = [entry["chain"] for entry in entries if "chain" in entry]
    rules = [entry["rule"] for entry in entries if "rule" in entry]
    require(len(tables) == 1 and tables[0]["family"] == "inet" and tables[0]["name"] == table
            and len(chains) == 2 and {chain["name"] for chain in chains} == {"input", "output"}
            and all(chain["family"] == "inet" and chain["table"] == table
                    and chain["type"] == "filter" and chain["hook"] == chain["name"]
                    and chain["prio"] == -25 and chain["policy"] == "accept" for chain in chains)
            and len(rules) == 4, "early Client control filter scope changed")
    actual = []
    for rule in rules:
        require(rule["family"] == "inet" and rule["table"] == table,
                "early filter rule escaped its exact table")
        actual.append((rule["chain"], rule["expr"]))
    for chain, key in (("input", "iifname"), ("output", "oifname")):
        for field in ("sport", "dport"):
            expected = [dict(match=dict(op="==", left=dict(meta=dict(key=key)),
                                        right=dict(set=["cr3", "cr4", "cr5"]))),
                        dict(match=dict(op="==", left=dict(payload=dict(protocol="udp", field=field)),
                                        right=41000)), dict(counter=dict(packets=0, bytes=0)), {"drop": None}]
            require((chain, expected) in actual, "early filter does not block exactly provider discovery contacts")


def validate(evidence):
    require(evidence["success"] is True, "adaptive phase did not complete")
    publication, fetch, output = (evidence[key] for key in ("publication", "fetch", "output"))
    peers, layout = evidence["expected_peers"], evidence["layout"]
    require(publication["report_kind"] == "volparossa-content-adaptive-provider-seed"
            and publication["bytes"] == BYTES and publication["chunks"] == CHUNKS
            and publication["object_sha256"] == SHA
            and publication["publisher_removed"] is True
            and publication["publisher_private_key_persisted"] is False
            and publication["recipient_encrypted"] is False
            and all(re.fullmatch(r"[0-9a-f]{64}", publication[key])
                    for key in ("publisher_hex", "manifest_id"))
            and 0 < publication["created_unix_seconds"] < publication["expires_unix_seconds"]
            and publication["expires_unix_seconds"] - publication["created_unix_seconds"] == 3600
            and all(publication[f"replica_{label}_chunks"] == 5
                    and publication[f"replica_{label}_bytes"] == SHARD_BYTES for label in "abc"),
            "original 15-unique-chunk, three-disjoint-cache seed authority missing")
    require(layout["provider_nodes"] == list(NODES) and len(set(peers.values())) == len(peers),
            "adaptive provider identities are not exactly three distinct spare nodes")
    control = layout["control_relay_peer_id"]
    control_nodes = [node for node in ROLES[1:4] if peers[node] == control]
    require(len(control_nodes) == 1 and control not in {peers[node] for node in NODES},
            "actual control peer is not an independent R0..2 node")
    require(all(evidence[key]["control_relay_peer_id"] == control
                for key in ("status_before", "status_after", "fetch")),
            "actual broker identity changed during the transfer")
    require(fetch["operation"] == "native_content" and fetch["bytes"] == BYTES
            and fetch["chunks"] == CHUNKS and fetch["providers_used"] == 3
            and len(fetch["provider_peer_ids"]) == 3
            and set(fetch["provider_peer_ids"]) == {peers[node] for node in NODES}
            and fetch["peer_bytes"] == BYTES and fetch["origin_body_bytes"] == 0
            and fetch["origin_range_requests"] == 0 and fetch["origin_authenticated"] is False,
            "normal native receipt lacks three useful providers and exact source accounting")
    require(output["sha256"] == SHA and output["bytes"] == BYTES
            and output["client_cache_initially_absent"] is True
            and output["client_mount_positive_control"] is True
            and output["client_mount_cannot_read_replica_stores"] is True
            and output["publisher_process_exited_before_fetch"] is True
            and output["event_baseline_unix_ms"] > 0
            and output["generic_dht_queries"] > 0
            and output["authenticated_upstream_offers"] >= 3
            and output["client_forwarded_discovery"] > 0,
            "cold runtime discovery, filesystem isolation or exact reconstruction missing")
    before, live = evidence["selected_before"], evidence["selected_route"]
    require(before["route_context_id"] == live["route_context_id"]
            != evidence["previous_context"]
            and before["benchmark_slots"] == live["benchmark_slots"]
            and before["transport"] == "mptcp"
            and [{key: path[key] for key in ("route_context_id", "path_id", "relay_peer_id", "exit_peer_id")}
                 for path in before["paths"]]
            == [{key: path[key] for key in ("route_context_id", "path_id", "relay_peer_id", "exit_peer_id")}
                for path in live["paths"]],
            "fresh exact two-path context was replaced or rebound")
    BASE["validate_path"](evidence, peers, list(NODES), False)
    for node in NODES:
        application = evidence["privacy"]["exit"]["provider_application"][node]
        require(SHARD_BYTES <= application["response_payload_bytes"] <= SHARD_BYTES + 131072,
                "provider payload does not match its unique shard plus bounded TLS overhead")
    require(evidence["provider_payload_overlap_ns"] == payload_overlap(evidence["privacy"]["exit"]),
            "reported triple bulk-payload overlap differs from kernel evidence")
    validate_control(evidence, control_nodes[0])
    validate_filter(evidence["control_filter"])
    require(set(evidence["providers"]) == set(NODES), "provider service receipts incomplete")
    for provider in evidence["providers"].values():
        require(provider["before"]["serving"] is False and provider["before"]["publications"] == 0
                and provider["serve"]["serving"] is True and provider["serve"]["publications"] == 1
                and provider["serve"]["replication_enabled"] is False
                and provider["stop"]["serving"] is False and provider["stop"]["publications"] == 0,
                "three normal isolated provider services did not start and stop completely")
    require(evidence["cleanup"] == dict(previous_route_disconnected=True,
                route_disconnected=True, active_contexts=0, paths_empty=True,
                client_output_removed=True, client_manifest_removed=True),
            "previous/new route or owned client-output cleanup incomplete")


def bounded_text(path, maximum=65536):
    require(not path.is_symlink(), "symlink evidence rejected")
    with path.open(encoding="ascii") as source:
        text = source.read(maximum + 1)
    require(len(text) <= maximum, "text evidence exceeds bound")
    return text


def disconnected(work, prefix):
    lines = bounded_text(work / f"{prefix}-final-status.txt").splitlines()
    require("connected: false" in lines and "active contexts: 0" in lines
            and bounded_text(work / f"{prefix}-final-paths.txt") == "",
            "raw final status/paths do not prove complete route retirement")


def build_evidence(work):
    work = Path(work)
    disconnected(work, "content-provider")
    disconnected(work, PREFIX)
    evidence = {key: read(work / f"{PREFIX}-{suffix}.json") for key, suffix in (
        ("publication", "publication"), ("layout", "layout"), ("status_before", "status-before"),
        ("status_after", "status-after"), ("fetch", "fetch"), ("output", "object"),
        ("selected_before", "selection"), ("selected_route", "live-selection"), ("cleanup", "cleanup"),
        ("control_filter", "control-filter"))}
    evidence.update(success=True, expected_peers=read(work / "a01-expected-peers.json"),
                    previous_context=read(work / "content-provider-selection.json")["route_context_id"],
                    providers={node: {operation: read(work / f"{PREFIX}-{node}-{operation}.json")
                                      for operation in ("before", "serve", "stop")} for node in NODES},
                    privacy={role: read(work / f"{PREFIX}-privacy-{role}.json") for role in ROLES},
                    control_underlay=dict(capture=read(work / f"{PREFIX}-control-privacy.json"),
                        routes={node: {direction: json.loads(bounded_text(
                            work / f"{PREFIX}-control-{node}-{direction}.json"))
                            for direction in ("out", "back")} for node in NODES}))
    evidence["provider_payload_overlap_ns"] = payload_overlap(evidence["privacy"]["exit"])
    validate(evidence)
    return evidence


def main():
    if len(sys.argv) != 4 or sys.argv[1] != "evidence":
        raise ValueError("usage: content-provider-adaptive-smoke.py evidence WORK OUTPUT")
    evidence = build_evidence(Path(sys.argv[2]))
    Path(sys.argv[3]).write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="ascii")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"adaptive provider evidence invalid: {error}", file=sys.stderr)
        sys.exit(1)
