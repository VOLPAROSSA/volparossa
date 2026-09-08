#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Three actual protected cache suppliers; no speed or unlimited-worker claim."""

import hashlib
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
REPR_DIGEST = "sha-256=:JvxGlvDrzX42o8CgNp4thDdCs5FaIirVe0nNUwIKkBE=:"


def validate_https_indexes(evidence):
    phase, native = evidence["https"], evidence["publication"]
    require(set(phase["indexes"]) == {"relay4", "relay5"}, "independent B/C indices missing")
    layout = [dict(sha256=hashlib.sha256(bytes([65 + i]) * 262144).hexdigest(), bytes=262144)
              for i in range(CHUNKS)]
    ids, publishers = {native["manifest_id"]}, {native["publisher_hex"]}
    require(phase["a_status"]["serving"] is True and phase["a_status"]["publications"] == 1
            and phase["a_status"]["replication_enabled"] is False, "original A registration changed")
    for shard, node in enumerate(NODES[1:], 1):
        index = phase["indexes"][node]
        publication, binding = index["publication"], index["binding"]
        original, independent = publication["original"], publication["independent"]
        require(publication["report_kind"] == "volparossa-https-independent-index"
                and original["manifest_id"] == native["manifest_id"]
                and original["publisher_hex"] == native["publisher_hex"]
                and re.fullmatch(r"[0-9a-f]{64}", independent["manifest_id"])
                and re.fullmatch(r"[0-9a-f]{64}", independent["publisher_hex"])
                and independent["manifest_id"] not in ids and independent["publisher_hex"] not in publishers
                and publication["publisher_private_key_persisted"] is False
                and publication["temporary_full_copy_removed"] is True,
                "provider transport indices are not three independent original signed envelopes")
        for manifest in (original, independent):
            require(manifest["chunks"] == layout and manifest["object_sha256"] == SHA
                    and manifest["bytes"] == BYTES and manifest["content_type"] == "application/octet-stream"
                    and manifest["name"] == "disposable-adaptive-native-publication" and manifest["revision"] == 1
                    and manifest["created_unix_seconds"] == native["created_unix_seconds"]
                    and manifest["expires_unix_seconds"] == native["expires_unix_seconds"],
                    "independent transport index changed the original layout, object or expiry")
        cache = publication["cache_before"]
        require(cache == publication["cache_after"] and cache["path"] == binding["cache"]
                and cache["device"] > 0 and cache["inode"] > 0
                and cache["entries"] == 5 and cache["bytes"] == SHARD_BYTES
                and cache["chunk_ids"] == [chunk["sha256"] for chunk in layout[shard::3]]
                and Path(cache["path"]).parts[-3:] == (f"state-{node}", "content-adaptive", "cache")
                and Path(binding["manifest_path"]) == Path(cache["path"]).parent / "digest-index" / "manifest.bin"
                and binding["provider_node"] == node
                and binding["provider_peer_id"] == evidence["expected_peers"][node]
                and binding["publisher_hex"] == independent["publisher_hex"]
                and binding["manifest_file_sha256"] == independent["manifest_id"]
                and binding["original_manifest_file_sha256"] == native["manifest_id"]
                and binding["bind_address"] == f"{BASE['PUBLIC_IPS'][node]}:18080"
                and binding["advertised_hostname"] == f"provider-{'a' if shard == 1 else 'b'}.volparossa.test"
                and native["created_unix_seconds"] <= publication["checked_unix_seconds"]
                    <= binding["registered_unix_seconds"] <= phase["application"]["started_unix_ms"] // 1000
                and phase["application"]["completed_unix_ms"] // 1000 < native["expires_unix_seconds"]
                and index["stop"]["serving"] is False and index["stop"]["publications"] == 0
                and index["serve"]["serving"] is True and index["serve"]["publications"] == 1
                and index["serve"]["replication_enabled"] is False,
                "B/C original cache, actual endpoint/index registration or cleanup was substituted")
        ids.add(independent["manifest_id"])
        publishers.add(independent["publisher_hex"])
    return ids


def validate_https(evidence, control_node):
    phase, native = evidence["https"], evidence["publication"]
    publication, fetch, output = (phase[key] for key in ("publication", "fetch", "output"))
    ids = validate_https_indexes(evidence)
    require(publication["report_kind"] == "volparossa-https-content-seed"
            and publication["manifest_id"] == native["manifest_id"]
            and publication["publisher_hex"] == native["publisher_hex"]
            and publication["bytes"] == BYTES and publication["chunks"] == CHUNKS
            and publication["object_sha256"] == SHA and publication["existing_publication_reused"] is True
            and publication["publisher_private_key_persisted"] is False,
            "origin did not independently authorize the existing adaptive representation")
    require(fetch["bytes"] == output["bytes"] == BYTES and fetch["chunks"] == CHUNKS
            and fetch["sha256"] == output["sha256"] == SHA
            and fetch["transport_manifest_id"] in ids and fetch["origin_authenticated"] is True
            and fetch["authentication_scope"] == "origin-repr-digest" and fetch["origin_digest"] is True
            and fetch["origin_authority_persisted"] is False
            and fetch["providers_used"] == len(fetch["provider_peer_ids"]) == 3
            and set(fetch["provider_peer_ids"]) == {evidence["expected_peers"][node] for node in NODES}
            and fetch["peer_bytes"] == BYTES and fetch["origin_body_bytes"] == fetch["origin_range_requests"] == 0
            and phase["application"]["requested_origin_digest"] is True
            and phase["status"]["serving"] is False
            and phase["status"]["control_relay_peer_id"] == fetch["control_relay_peer_id"]
                == evidence["layout"]["control_relay_peer_id"]
            and phase["selected_route"]["route_context_id"] == evidence["selected_route"]["route_context_id"]
            and phase["selected_route"]["benchmark_slots"] == evidence["selected_route"]["benchmark_slots"],
            "three-source normal HTTPS receipt, independent index or original route is missing")
    require(output["user_uid"] == 985 != output["agent_uid"] and output["agent_uid"] > 0
            and output["output_mode"] == "0600" and output["directory_mode"] == output["agent_cache_mode"] == "0700"
            and Path(output["path"]).parts[-2:] == ("adaptive-https-output", "digest-peers-first-object.bin")
            and Path(output["agent_cache"]).parts[-3:] == ("state-client", "content-adaptive", "https-cache")
            and all(output[key] is True for key in ("client_cache_initially_absent", "local_output_initially_absent",
                "no_clobber_verified", "no_clobber_rejected_before_network", "agent_mount_positive_control",
                "agent_cannot_read_user_output_directory", "client_mount_cannot_read_origin"))
            and "already exists" in phase["no_clobber_error"],
            "isolated cold operator storage or early no-clobber rejection missing")
    BASE["validate_application"](phase, browser=False, source_strategy="peers-first")
    application = phase["application"]
    require(application["elapsed_ns"] == application["completed_monotonic_ns"] - application["started_monotonic_ns"]
            and 0 < application["started_unix_ms"] <= application["completed_unix_ms"],
            "HTTPS command elapsed time does not match its actual monotonic interval")
    origin = phase["origin"]
    require(origin["report_kind"] == "volparossa-https-content-origin"
            and origin["request_limit"] == 1 and origin["stop_requested"] is False
            and origin["listener_closed"] is True and origin["inflight_drained"] is True
            and len(origin["connections"]) == 1, "origin must complete exactly one fresh HEAD")
    head = origin["connections"][0]
    require(head["kind"] == "digest_head" and head["method"] == "HEAD" and head["status"] == 200
            and head["payload_bytes"] == 0 and head["content_length"] == BYTES
            and head["representation_digest"] == REPR_DIGEST and head["object_sha256"] == SHA
            and head["tls13"] is True and head["alpn_http11"] is True
            and BASE["origin_exit_source"](head["source"])
            and all(head[key] is None for key in ("range_start", "range_end", "range_total")),
            "fresh HEAD origin/hash/TLS authority or Exit-source boundary is missing")
    BASE["validate_path"](phase, evidence["expected_peers"], list(NODES), False)
    validate_control(dict(control_underlay=dict(capture=phase["control"],
        routes=evidence["control_underlay"]["routes"])), control_node)
    for node in NODES:
        require(SHARD_BYTES <= phase["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"]
                <= SHARD_BYTES + 131072, "HTTPS supplier payload lacks its exact independent shard")
    require(phase["provider_payload_overlap_ns"] == payload_overlap(phase["privacy"]["exit"]),
            "HTTPS triple overlap differs from actual kernel payload timing")
    require(phase["cleanup"] == dict(user_output_removed=True, user_directory_removed=True,
            fixture_ca_removed=True, origin_body_removed=True), "HTTPS private files remain after completion")


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
    validate_https(evidence, control_nodes[0])
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
    prefix = f"{PREFIX}-https"
    evidence["https"] = {key: read(work / f"{prefix}-{suffix}.json") for key, suffix in (
        ("publication", "publication"), ("a_status", "a-status"), ("application", "application"),
        ("fetch", "fetch"), ("output", "output"), ("status", "status"), ("origin", "origin"),
        ("cleanup", "cleanup"), ("selected_route", "live-selection"), ("control", "control-privacy"))}
    phase = evidence["https"]
    phase["indexes"] = {node: {key: read(work / f"{prefix}-{node}-{suffix}.json") for key, suffix in (
        ("publication", "index"), ("binding", "binding"), ("stop", "stop"), ("serve", "serve"))}
        for node in NODES[1:]}
    phase["privacy"] = {role: read(work / f"{prefix}-privacy-{role}.json") for role in ROLES}
    phase["provider_payload_overlap_ns"] = payload_overlap(phase["privacy"]["exit"])
    phase["no_clobber_error"] = bounded_text(work / f"{prefix}-no-clobber.err")
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
