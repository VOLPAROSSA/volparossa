#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact, bounded native-provider runtime proof; not generic NAT/HTTPS or full C02."""

import json
from pathlib import Path
import re
import runpy
import sys

COMMON = runpy.run_path(str(Path(__file__).with_name("content-network-smoke.py")))
read, require = COMMON["read"], COMMON["require"]
ROLES = COMMON["ROLES"]
BYTES, SHA = COMMON["OBJECT_BYTES"], COMMON["FIXTURE_PLAINTEXT_SHA256"]
CANDIDATES = ("relay4", "relay5", "relay3")
PUBLIC_IPS = dict(relay0="42.158.0.1", relay1="44.160.1.1", relay2="45.161.2.1",
                  relay3="48.164.4.1", relay4="49.165.5.1", relay5="50.166.6.1")
SCOPE = ("general_nat_reachability_claimed", "full_c02_claimed", "browser_integration_claimed",
         "arbitrary_https_integration_claimed", "speed_improvement_claimed", "full_alpha_acceptance_claimed")


def read_route(path):
    require(not path.is_symlink(), "symlink route evidence is not accepted")
    with path.open(encoding="ascii") as source:
        text = source.read(65537)
    require(len(text) <= 65536, "route evidence exceeds its bound")
    rows = json.loads(text)
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
            "kernel route evidence must contain exactly one route object")
    return rows


def validate_user_publication(evidence):
    output, publish = evidence["output"], evidence["publish"]
    imported, exported = evidence["import"], evidence["export"]
    fetch, assembled = evidence["fetch"], evidence["assemble"]
    peers, layout = evidence["expected_peers"], evidence["layout"]
    node = output["provider_node"]
    require(evidence["success"] is True and node == layout["provider_nodes"][0]
            and output["bytes"] == publish["bytes"] == fetch["bytes"] == assembled["bytes"] == BYTES
            and output["sha256"] == SHA and publish["chunks"] == fetch["chunks"] == assembled["chunks"] == 9
            and publish["operation"] == "offline_content_publish" and publish["network_publication"] is False
            and assembled["operation"] == "offline_content_assemble" and assembled["network_retrieval"] is False
            and publish["publisher_key_hex"] == assembled["publisher_key_hex"]
            and re.fullmatch(r"[0-9a-f]{64}", publish["publisher_key_hex"])
            and evidence["serve"]["serving"] is True and evidence["serve"]["publications"] == 2,
            "ordinary user publication/registration/reassembly not proven")
    require(re.fullmatch(r"[0-9a-f]{64}", imported["manifest_id"])
            and imported["manifest_id"] == exported["manifest_id"]
            and imported["cache"] == publish["cache"]
            and imported["agent_cache"] != exported["agent_cache"]
            and imported["cache"] != exported["cache"],
            "handoff changed manifest or reused sender/destination caches")
    for result, operation in ((imported, "content_import"), (exported, "content_export")):
        require(result["operation"] == operation and result["complete"] is True
                and result["content_bytes"] == BYTES and result["chunks"] == 9
                and result["public_content"] is True
                and all(result[key] is False for key in (
                    "ownership_changed", "network_transfer", "recipient_decryption_performed",
                    "private_keys_transferred", "ciphertext_format_verified", "origin_authenticated")),
                "local handoff was incomplete or changed ownership/content authority")
    require(fetch["providers_used"] == 1 and fetch["provider_peer_ids"] == [peers[node]]
            and fetch["peer_bytes"] == BYTES and fetch["origin_authenticated"] is False
            and fetch["origin_body_bytes"] == 0
            and fetch["control_relay_peer_id"] == layout["control_relay_peer_id"]
            and evidence["selected_route"]["route_context_id"] == output["route_context_id"],
            "new cache was not filled by exact independent provider through its real route")
    require(output["user_uid"] != output["agent_uid"] and output["control_gid"] != output["agent_gid"]
            and output["cache_modes"] == "0700" and output["output_mode"] == "0600"
            and all(output[key] is True for key in (
                "fresh_destination_cache", "agent_cannot_read_user_state", "user_cannot_read_agent_caches",
                "client_mount_cannot_read_provider_cache", "encrypted_identity_unchanged",
                "publisher_process_exited_before_fetch", "explicit_public_fixture"))
            and output["https_origin_authenticated"] is False and output["mailbox_claimed"] is False
            and evidence["private_cleanup"] == dict(encrypted_identity_removed=True, passphrase_removed=True,
                input_and_output_removed=True, private_directory_removed=True),
            "ordinary user/service isolation or exact temporary-secret cleanup missing")
    # This existing helper validates only real path/capture facts, not HTTPS authority.
    # Provider B was deliberately withdrawn by the preceding HTTPS fallback case.
    path_check = runpy.run_path(str(Path(__file__).with_name("content-provider-https-smoke.py")))
    path_check["validate_path"](evidence, peers, layout["provider_nodes"], True)
    require(evidence["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"] >= BYTES,
            "selected provider did not return the whole ordinary publication over its captured path")


def build_user_publication(work):
    evidence = {name: read(work / f"content-provider-user-{suffix}.json") for name, suffix in (
        ("output", "object"), ("publish", "publish"), ("import", "import"), ("serve", "serve"),
        ("fetch", "fetch"), ("export", "export"), ("assemble", "assemble"),
        ("private_cleanup", "cleanup"), ("selected_route", "selection"))}
    evidence.update(success=True, expected_peers=read(work / "a01-expected-peers.json"),
                    layout=read(work / "content-provider-layout.json"),
                    privacy={r: read(work / f"content-provider-user-privacy-{r}.json") for r in ROLES})
    validate_user_publication(evidence)
    return evidence


def validate_transfer(evidence):
    publication, output, fetch = evidence["publication"], evidence["output"], evidence["fetch"]
    require(publication["bytes"] == output["bytes"] == fetch["bytes"] == BYTES
            and publication["object_sha256"] == output["sha256"] == SHA
            and publication["chunks"] == fetch["chunks"] == 9
            and publication["replica_a_chunks"] == 5 and publication["replica_b_chunks"] == 4
            and publication["publisher_removed"] is True
            and publication["publisher_private_key_persisted"] is False
            and re.fullmatch(r"[0-9a-f]{64}", publication["publisher_hex"]),
            "exact publisher-offline object and complementary stores not proven")
    peers = evidence["expected_peers"]
    layout = evidence["layout"]
    control = layout["control_relay_peer_id"]
    provider_nodes = layout["provider_nodes"]
    require(isinstance(control, str) and control in {peers[f"relay{i}"] for i in range(6)}
            and provider_nodes == [node for node in CANDIDATES if peers[node] != control][:2]
            and len(set(provider_nodes)) == 2
            and evidence["status_before"]["control_relay_peer_id"] == control
            and evidence["status_after"]["control_relay_peer_id"] == control
            and fetch["control_relay_peer_id"] == control,
            "provider selection or unchanged actual control-relay lineage not proven")
    provider_peers = {peers[node] for node in provider_nodes}
    control_node = next(node for node in PUBLIC_IPS if peers[node] == control)
    validate_control_underlay(evidence["control_underlay"], control_node, provider_nodes)
    require(len(provider_peers) == 2 and fetch["providers_used"] == 2
            and len(fetch["provider_peer_ids"]) == 2
            and set(fetch["provider_peer_ids"]) == provider_peers
            and fetch["serving"] is False and control not in provider_peers,
            "two authenticated independent providers did not supply the reconstructed object")
    require(output["client_cache_initially_absent"] is True
            and output["client_mount_cannot_read_replica_stores"] is True
            and output["publisher_process_exited_before_fetch"] is True
            and output["event_baseline_unix_ms"] > 0
            and output["generic_dht_queries"] > 0
            and output["authenticated_upstream_offers"] >= 2
            and output["client_forwarded_discovery"] > 0,
            "real generic discovery, forwarded offers or filesystem isolation not proven")
    require(set(evidence["providers"]) == set(provider_nodes), "independent provider coverage incomplete")
    for provider in evidence["providers"].values():
        require(provider["serve"]["serving"] is True and provider["serve"]["publications"] == 1
                and provider["stop"]["serving"] is False and provider["stop"]["publications"] == 0,
                "explicit provider activation or withdrawal missing")
    selected = evidence["selected_route"]
    paths, slots = selected["paths"], selected["benchmark_slots"]
    require(selected["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and re.fullmatch(r"[0-9a-f]{32}", selected["route_context_id"])
            and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [s["relay_peer_id"] for s in slots] == [p["relay_peer_id"] for p in paths]
            and not provider_peers.intersection({peers["client"], peers["exit"]}
                                               | {p["relay_peer_id"] for p in paths}),
            "same-Exit two-Relay MPTCP route or independent destination providers not proven")
    privacy = evidence["privacy"]
    require(set(privacy) == set(ROLES), "privacy coverage incomplete")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["truncated"] is False and capture["observed_frames"] > 0
                and capture["packet_socket_drops"] == 0
                and capture["unexpected_outer_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and capture["unexpected_provider_application_packets"] == 0,
                "physical capture truncated, dropped or observed forbidden provider app traffic")
        statistics = capture["interface_statistics"]
        require(set(statistics) == set(capture["interfaces"])
                and sum(s["observed_frames"] for s in statistics.values()) == capture["observed_frames"]
                and all(s["intake_stopped"] is True and s["packet_socket_drops"] == 0
                        and s["packet_socket_packets"] == s["observed_frames"] for s in statistics.values()),
                "capture intake not stopped and drained completely")
    require(privacy["client"]["direct_client_exit_packets"] == 0
            and privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == 0
            and privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[r]["internet_destination_outer_packets"] == 0 for r in ROLES[1:4]),
            "original Client/Relay/Exit privacy boundary violated")
    nodes = [s["relay_node"] for s in slots]
    require(len(set(nodes)) == 2 and all(n in ROLES[1:4] for n in nodes), "unexpected selected relay")
    for node in nodes:
        require(privacy[node]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[node]["exit_leg_wireguard_data_datagrams"] > 16,
                "both physical WireGuard legs did not carry genuine data")
    for role in ROLES:
        require(set(privacy[role]["provider_application"]) == set(CANDIDATES),
                "provider application capture coverage incomplete")
    for node in CANDIDATES:
        application = privacy["exit"]["provider_application"][node]
        if node in provider_nodes:
            require(application["request_packets"] > 0 and application["response_packets"] > 0
                    and application["response_payload_bytes"] >= 1048576,
                    "both independent provider endpoints must return useful bytes to the exact Exit")
        else:
            require(all(value == 0 for value in application.values()),
                    "unselected third provider received application traffic")
        for role in ROLES[:-1]:
            require(all(value == 0 for value in privacy[role]["provider_application"][node].values()),
                    "provider application data escaped its protected path")
    https_check = runpy.run_path(str(Path(__file__).with_name("content-provider-https-smoke.py")))
    https_check["validate_evidence"](evidence["https"])
    require(evidence["https"]["native_publication"] == publication
            and evidence["https"]["layout"] == layout
            and evidence["https"]["expected_peers"] == peers
            and all(case["selected_route"]["route_context_id"] == selected["route_context_id"]
                    for case in evidence["https"]["cases"].values()),
            "HTTPS proof does not retain the exact native publication and provider identities")
    ordinary = evidence["ordinary_publication"]
    validate_user_publication(ordinary)
    require(ordinary["expected_peers"] == peers and ordinary["layout"] == layout
            and ordinary["output"]["route_context_id"] == selected["route_context_id"]
            and ordinary["publish"]["publisher_key_hex"] != publication["publisher_hex"],
            "ordinary publication reused fixture publisher or changed the established topology")


def build_evidence(work):
    layout = read(work / "content-provider-layout.json")
    evidence = dict(success=True, publication=read(work / "content-provider-publication.json"),
                    layout=layout,
                    status_before=read(work / "content-provider-status-before.json"),
                    status_after=read(work / "content-provider-status-after.json"),
                    control_underlay=dict(
                        capture=read(work / "content-provider-control-privacy.json"),
                        routes={node: dict(out=read_route(work / f"content-provider-control-{node}-out.json"),
                                           back=read_route(work / f"content-provider-control-{node}-back.json"))
                                for node in CANDIDATES if node in layout["provider_nodes"]}),
                    output=read(work / "content-provider-object.json"),
                    fetch=read(work / "content-provider-fetch.json"),
                    https=read(work / "content-provider-https-evidence.json"),
                    ordinary_publication=read(work / "content-provider-user-publication.json"),
                    expected_peers=read(work / "a01-expected-peers.json"),
                    selected_route=read(work / "content-provider-live-selection.json"),
                    privacy={r: read(work / f"content-provider-privacy-{r}.json") for r in ROLES},
                    providers={node: dict(serve=read(work / f"content-provider-{node}-serve.json"),
                                          stop=read(work / f"content-provider-{node}-stop.json"))
                               for node in CANDIDATES if node in layout["provider_nodes"]})
    validate_transfer(evidence)
    return evidence


def validate_control_underlay(evidence, control_node, provider_nodes):
    capture = evidence["capture"]
    pairs = {f"cp{i}": [PUBLIC_IPS[control_node], PUBLIC_IPS[node]]
             for i, node in enumerate(provider_nodes)}
    require(capture["capture_role"] == "content-control" and capture["content_provider_mode"] is True
            and capture["content_control_pairs"] == pairs
            and set(capture["interfaces"]) == set(pairs)
            and set(capture["content_control_packets"]) == set(pairs)
            and capture["truncated"] is False and capture["observed_frames"] > 0
            and capture["packet_socket_drops"] == 0
            and capture["unexpected_provider_control_packets"] == 0
            and capture["unexpected_provider_application_packets"] == 0
            and all(value == 0 for counters in capture["provider_application"].values()
                    for value in counters.values()),
            "dedicated broker/provider links carried forbidden traffic or lack exact coverage")
    stats = capture["interface_statistics"]
    require(set(stats) == set(pairs)
            and sum(s["observed_frames"] for s in stats.values()) == capture["observed_frames"]
            and all(s["intake_stopped"] is True and s["packet_socket_drops"] == 0
                    and s["packet_socket_packets"] == s["observed_frames"] for s in stats.values())
            and all(c["inbound"] > 0 and c["outbound"] > 0
                    for c in capture["content_control_packets"].values()),
            "both UDP control links were not live, stopped, and fully drained")
    require(set(evidence["routes"]) == set(provider_nodes), "control route coverage incomplete")
    for i, node in enumerate(provider_nodes):
        for direction, source, destination, device, gateway in (
            ("out", PUBLIC_IPS[control_node], PUBLIC_IPS[node], f"cp{i}", f"10.241.{80+i}.2"),
            ("back", PUBLIC_IPS[node], PUBLIC_IPS[control_node], f"pc{i}", f"10.241.{80+i}.1"),
        ):
            routes = evidence["routes"][node][direction]
            require(len(routes) == 1 and routes[0]["dst"] == destination
                    and routes[0]["prefsrc"] == source and routes[0]["dev"] == device
                    and routes[0]["gateway"] == gateway,
                    "actual kernel route does not bind the two advertised public endpoints")


def validate_report(report, revision):
    require(report["report_kind"] == "volparossa-native-content-providers"
            and report["source_revision"] == revision and report["success"] is True
            and report["runner_exit_status"] == 0
            and report["explicit_origin_authenticated_https"] is True
            and report["normal_user_publication"] is True
            and report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"]
            and re.fullmatch(r"[0-9a-f]{64}", report["host_state"]["before_sha256"])
            and all(report[flag] is False for flag in SCOPE), "wrong source, cleanup, host state or scope")
    validate_transfer(report["transfer"])


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: evidence WORK OUTPUT | user-publication WORK OUTPUT | report REPORT REVISION")
        if sys.argv[1] in ("evidence", "user-publication"):
            builder = build_evidence if sys.argv[1] == "evidence" else build_user_publication
            result = builder(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as target:
                json.dump(result, target, sort_keys=True, separators=(",", ":"))
        elif sys.argv[1] == "report":
            validate_report(read(Path(sys.argv[2])), sys.argv[3])
        else:
            raise ValueError("unknown evidence mode")
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"content provider evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
