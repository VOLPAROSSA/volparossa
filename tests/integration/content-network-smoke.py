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
FIXTURE_PLAINTEXT_SHA256 = "add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767"


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


def validate_transfer(evidence, private=False):
    publication = evidence["publication"]
    result = evidence["reconstructed_object"]
    object_bytes = publication["bytes"]
    require((OBJECT_BYTES + 16 <= object_bytes <= OBJECT_BYTES + 1024)
            if private else object_bytes == OBJECT_BYTES,
            "wrong public object or bounded private ciphertext length")
    require(publication["publisher_removed"] is True
            and publication["publisher_private_key_persisted"] is False
            and publication["chunks"] == 9
            and publication["replica_a_chunks"] == 5 and publication["replica_b_chunks"] == 4
            and re.fullmatch(r"[0-9a-f]{64}", publication["publisher_hex"])
            and re.fullmatch(r"[0-9a-f]{64}", publication["object_sha256"]),
            "publisher or disjoint replica seed not proven")
    require(result["bytes"] == object_bytes and result["sha256"] == publication["object_sha256"]
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
        received_bytes = (object_bytes - 1048576, 1048576)[index]
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
                and consumer["output_bytes"] == (0, object_bytes)[index]
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
    if private:
        validate_private_message(evidence)


def validate_private_message(evidence):
    message = evidence["private_message"]
    recipient, isolation = message["recipient"], message["recipient_isolation"]
    opened, output = message["decryption"], message["plaintext_output"]
    require(evidence["publication"]["recipient_encrypted"] is True
            and recipient["operation"] == "message_recipient_key"
            and recipient["profile"] == "volparossa/message-recipient/v1"
            and re.fullmatch(r"[0-9a-f]{64}", recipient["recipient_public_key_hex"])
            and re.fullmatch(r"[0-9a-f]{64}", recipient["identity_public_key_hex"])
            and recipient["private_key_exported"] is False
            and recipient["network_publication"] is False
            and isolation["recipient_uid"] > 0 and isolation["provider_uid"] > 0
            and isolation["recipient_uid"] != isolation["provider_uid"]
            and isolation["private_directory_mode"] == "0700"
            and isolation["encrypted_identity_mode"] == isolation["passphrase_mode"] == "0600"
            and isolation["identity_created_by_normal_cli"] is True
            and isolation["identity_storage"] == "encrypted_identity_store"
            and isolation["raw_recipient_private_key_file"] is False
            and isolation["key_owned_by_recipient"] is True
            and isolation["key_unreadable_by_provider"] is True
            and isolation["passphrase_unreadable_by_provider"] is True,
            "recipient key isolation from the publisher/providers not proven")
    require(opened["plaintext_bytes"] == output["plaintext_bytes"] == OBJECT_BYTES
            and opened["plaintext_sha256"] == output["plaintext_sha256"] == FIXTURE_PLAINTEXT_SHA256
            and opened["normal_cli_open"] is True
            and opened["wrong_recipient_rejected"] is True
            and opened["wrong_recipient_output_absent"] is True
            and opened["no_clobber_verified"] is True
            and opened["encrypted_identities_unchanged"] is True
            and message["cli_result"]["operation"] == "offline_private_message_open"
            and message["cli_result"]["bytes"] == OBJECT_BYTES
            and message["cli_result"]["network_retrieval"] is False
            and output["private_output_mode"] == "0600"
            and output["private_output_owned_by_recipient"] is True
            and evidence["publication"]["object_sha256"] != FIXTURE_PLAINTEXT_SHA256,
            "intended-recipient decryption or wrong-recipient rejection not proven")
    require(message["temporary_cleanup"] == {
        "encrypted_identities_removed": True, "passphrase_removed": True,
        "plaintext_removed": True, "private_directory_removed": True},
        "temporary encrypted identities, passphrase or plaintext were not removed")


def build_evidence(work, private=False):
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
    if private:
        evidence["private_message"] = {
            "recipient": read(work / "content-recipient.json"),
            "recipient_isolation": read(work / "content-recipient-isolation.json"),
            "decryption": read(work / "content-message-open.json"),
            "cli_result": read(work / "content-message-cli-open.json"),
            "plaintext_output": read(work / "content-message-object.json"),
            "temporary_cleanup": read(work / "content-private-cleanup.json"),
        }
    validate_transfer(evidence, private)
    return {"success": True, **evidence}


def validate_report(report, revision, private=False):
    expected_kind = ("volparossa-native-private-content-network" if private
                     else "volparossa-native-content-network")
    require(report["report_kind"] == expected_kind
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
    if private:
        require(report["normal_recipient_cli_claimed"] is True
                and report["encrypted_identity_store_claimed"] is True
                and report["normal_publisher_cli_claimed"] is False
                and report["mailbox_runtime_claimed"] is False and report["full_c07_claimed"] is False,
                "normal encrypted-identity recipient CLI is required, not a product publisher/mailbox claim")
    validate_transfer(report["transfer"], private)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: evidence|message-evidence WORK OUTPUT | report|message-report REPORT EXPECTED_REVISION")
        if sys.argv[1] in {"evidence", "message-evidence"}:
            value = build_evidence(Path(sys.argv[2]), sys.argv[1] == "message-evidence")
            with Path(sys.argv[3]).open("x", encoding="ascii") as output:
                output.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        elif sys.argv[1] in {"report", "message-report"}:
            validate_report(read(Path(sys.argv[2])), sys.argv[3], sys.argv[1] == "message-report")
        else:
            raise ValueError("unknown evidence mode")
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"content network evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
