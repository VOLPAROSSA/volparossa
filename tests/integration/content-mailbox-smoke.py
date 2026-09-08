#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-source mailbox CLI evidence; not an independent sender-node or full C07 claim.

The normal Rust CLI verifies receipt signatures. This checker additionally binds the retained
canonical receipt fields to fixture identities, operations and original message, never treating
a signature-shaped byte array as independent Python cryptographic verification.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

SHARED = runpy.run_path(str(Path(__file__).with_name("content-provider-https-smoke.py")))
read, require, ROLES = SHARED["read"], SHARED["require"], SHARED["ROLES"]
NODES = SHARED["CANDIDATES"]
BYTES, SHA = SHARED["BYTES"], SHARED["SHA"]
HEX = r"[0-9a-f]{64}"


def peer_key(peer):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    require(isinstance(peer, str) and 40 <= len(peer) <= 64, "invalid fixture peer ID")
    value = 0
    for char in peer:
        require(char in alphabet, "invalid peer base58")
        value = value * 58 + alphabet.index(char)
    raw = b"\x00" * (len(peer) - len(peer.lstrip("1"))) + value.to_bytes((value.bit_length() + 7) // 8, "big")
    require(len(raw) == 38 and raw[:6] == bytes.fromhex("002408011220"),
            "provider is not an inline Ed25519 libp2p identity")
    return raw[6:].hex()


def fields(data):
    """Bounded receipt-only protobuf inspection; cryptography stays in the normal Rust CLI."""
    require(isinstance(data, bytes) and len(data) <= 65536, "oversize receipt")
    result, position = {}, 0

    def varint():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            require(position < len(data), "truncated receipt integer")
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                require(shift == 0 or byte != 0, "noncanonical receipt integer")
                return value
        raise ValueError("oversize receipt integer")

    while position < len(data):
        tag = varint()
        require(tag >> 3 > 0 and tag >> 3 not in result, "duplicate receipt field")
        if tag & 7 == 0:
            value = varint()
        else:
            require(tag & 7 == 2, "unexpected receipt field type")
            length = varint()
            require(length <= len(data) - position, "truncated receipt field")
            value = data[position:position + length]
            position += length
        result[tag >> 3] = value
    return result


def receipts(values, keys, operation, message_id=None, ciphertext_bytes=0):
    require(isinstance(values, list) and len(values) == 2 and len(set(values)) == 2,
            "two distinct provider receipts required")
    providers, requests, grants = set(), set(), set()
    for value in values:
        require(isinstance(value, str) and 0 < len(value) <= 131072
                and re.fullmatch(r"[0-9a-f]+", value), "invalid receipt encoding")
        envelope = fields(bytes.fromhex(value))
        require(set(envelope) == {1, 2} and len(envelope[2]) == 64, "invalid signed envelope")
        body = fields(envelope[1])
        require(set(body) == set(range(1, 9)) and body[1] == 1 and body[6] == 4
                and len(body[2]) == len(body[5]) == len(body[7]) == 32
                and 0 < body[4] - body[3] <= 120
                and hashlib.sha256(body[8]).digest() == body[7], "receipt envelope binding invalid")
        payload = fields(body[8])
        require(set(payload).issubset({1, 2, 3, 5, 6, 7, 8})
                and len(payload[1]) == len(payload[2]) == 32 and payload[3] == operation
                and payload.get(5, b"") == (bytes.fromhex(message_id) if message_id else b"")
                and payload.get(8, 0) == ciphertext_bytes and payload[6] > body[3]
                and bool(payload.get(7, 0)) is (operation == 5), "wrong mailbox receipt operation/result")
        providers.add(body[2].hex())
        requests.add(payload[1])
        grants.add(payload[2])
    require(providers == set(keys) and len(requests) == 2 and len(grants) == 1,
            "provider, fresh request or invitation receipt binding mismatch")
    return next(iter(grants))


def validate_phase(phase, peers, nodes, ciphertext, receiving):
    selected = phase["selected_route"]
    paths, slots = selected["paths"], selected["benchmark_slots"]
    control = phase["control_relay_peer_id"]
    controls = [node for node, peer in peers.items() if peer == control]
    require(len(controls) == 1 and controls[0] in SHARED["PUBLIC_IPS"]
            and control not in {peers[node] for node in nodes}, "invalid current control relay")
    require(selected["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and re.fullmatch(r"[0-9a-f]{32}", selected["route_context_id"])
            and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [s["relay_peer_id"] for s in slots] == [p["relay_peer_id"] for p in paths]
            and all(s["relay_node"] in ROLES[1:4]
                    and peers[s["relay_node"]] == s["relay_peer_id"] for s in slots)
            and not {peers[n] for n in nodes}.intersection(
                {peers["client"], peers["exit"], control} | {p["relay_peer_id"] for p in paths}),
            "provider separation or actual two-relay MPTCP route missing")
    privacy = phase["privacy"]
    require(set(privacy) == set(ROLES), "five-role privacy capture incomplete")
    for role, capture in privacy.items():
        SHARED["validate_drained"](capture)
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and capture["unexpected_provider_application_packets"] == 0
                and set(capture["provider_application"]) == set(NODES),
                "unexpected physical outer/provider traffic")
    require(privacy["client"]["direct_client_exit_packets"] == 0
            and privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == 0
            and privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[r]["internet_destination_outer_packets"] == 0 for r in ROLES[1:4]),
            "original Client/Relay/Exit privacy boundary violated")
    for slot in slots:
        capture = privacy[slot["relay_node"]]
        require(capture["client_leg_wireguard_data_datagrams"] > 16
                and capture["exit_leg_wireguard_data_datagrams"] > 16,
                "both selected physical WireGuard legs did not carry actual bytes")
    for node in NODES:
        app = privacy["exit"]["provider_application"][node]
        require((app["request_packets"] > 0 and app["response_packets"] > 0) if node in nodes
                else all(v == 0 for v in app.values()), "missing or unselected provider TCP traffic")
        for role in ROLES[:-1]:
            require(all(v == 0 for v in privacy[role]["provider_application"][node].values()),
                    "application provider bytes outside protected route")
    if receiving:
        require(max(privacy["exit"]["provider_application"][n]["response_payload_bytes"]
                    for n in nodes) >= ciphertext, "no complete ciphertext return observed")
    else:
        require(all(privacy["exit"]["provider_application"][n]["request_packets"] > 16 for n in nodes),
                "two actual provider deposits not observed")
    SHARED["validate_control"](phase["control"], controls[0], nodes, False)
    gates = phase["gates"]
    require(gates["event_baseline_unix_ms"] > 0
            and gates["exit_mptcp_tls_completed"] >= (7 if receiving else 4)
            and gates["exact_provider_lookups"] >= (7 if receiving else 4),
            "fresh exact discovery or genuine MPTCP/TLS completion missing")


def validate_evidence(evidence):
    nodes, keys = evidence["provider_nodes"], evidence["provider_keys"]
    require(len(nodes) == len(set(nodes)) == 2 and all(n in NODES for n in nodes)
            and set(keys) == set(nodes) and len(set(keys.values())) == 2
            and all(re.fullmatch(HEX, k) for k in keys.values())
            and all(peer_key(evidence["expected_peers"][n]) == keys[n] for n in nodes),
            "wrong independently configured provider identities")
    identities = evidence["identities"]
    providers = evidence["providers"]
    require(set(providers) == set(nodes) and len({p["pid"] for p in providers.values()}) == 2
            and all(p["node"] == n and p["pid"] > 0 and p["cache_inode"] > 0
                    and p["cache_mode"] == "700" and p["serve"]["serving"] is True
                    and p["serve"]["replication_enabled"] is False for n, p in providers.items()),
            "two distinct actual mailbox-serving processes not proven")
    owner, sender = identities["owner"], identities["sender"]
    require(re.fullmatch(HEX, owner) and re.fullmatch(HEX, sender)
            and len({owner, sender, *keys.values()}) == 4, "identity separation missing")
    invite, enroll, sent = evidence["invite"], evidence["enroll"], evidence["send"]
    received, empty = evidence["receive"], evidence["receive_empty"]
    require(invite["operation"] == "mailbox_invite" and invite["owner_key_hex"] == owner
            and invite["private_key_exported"] is False and invite["registered_providers"] == 0
            and enroll["operation"] == "mailbox_enroll" and enroll["registered_providers"] == 2
            and enroll["mailbox_id"] == invite["mailbox_id"]
            and enroll["message_capacity_reserved"] is False,
            "explicit invitation/two-provider enrollment missing")
    require(sent["operation"] == "mailbox_send" and sent["confirmed_providers"] == 2
            and sent["retained_providers"] == 2 and sent["already_acknowledged_providers"] == 0
            and sent["plaintext_uploaded"] is False and re.fullmatch(HEX, sent["message_id"])
            and BYTES + 16 <= sent["ciphertext_bytes"] <= BYTES + 1024,
            "two encrypted deposits missing")
    grant = receipts(enroll["storage_receipts"], keys.values(), 1)
    require(receipts(sent["storage_receipts"], keys.values(), 2, sent["message_id"],
                     sent["ciphertext_bytes"]) == grant, "deposit invitation changed")
    for report, count in ((received, 1), (empty, 0)):
        require(report["operation"] == "mailbox_receive"
                and report["messages_discovered"] == report["messages_delivered"] == count
                and report["sender_manifest_supplied"] is False
                and report["directory_mode"] == "0700" and report["output_mode"] == "0600"
                and report["acknowledged_providers_per_message"] == 2
                and report["listed_providers"] == 2 and report["degraded"] is False,
                "manifest-free receive, both-provider ACK or empty second listing missing")
    ack = received["acknowledgement_receipts"]
    require(len(ack) == 1 and ack[0]["message_id"] == sent["message_id"]
            and receipts(ack[0]["receipts"], keys.values(), 5, sent["message_id"]) == grant
            and empty["acknowledgement_receipts"] == [], "two actual ACK receipts missing")
    output = evidence["output"]
    require(output["bytes"] == BYTES and output["sha256"] == SHA
            and output["opaque_filename"] == sent["message_id"]
            and output["file_mode"] == "0600" and output["directory_mode"] == "0700"
            and output["empty_directory_entries"] == 0
            and output["sender_application_exited"] is True
            and output["sender_keys_and_input_removed_before_receive"] is True
            and output["sender_manifest_removed_before_receive"] is True
            and output["no_manifest_or_message_id_argument"] is True
            and output["agent_mount_positive_control"] is True
            and output["agent_cannot_read_user_state"] is True
            and output["client_cannot_read_provider_stores"] is True,
            "independent plaintext, absence or account isolation not proven")
    restart = evidence["restart"]
    require(restart["provider_node"] in nodes and restart["stop"]["serving"] is False
            and restart["reopen"]["serving"] is True and restart["listener_absent_between"] is True
            and restart["cache_inode_before"] == restart["cache_inode_after"] > 0
            and restart["cache_mode"] == "0700" and restart["reuse_cache"] is True,
            "durable provider store stop/reopen not proven")
    require(set(evidence["phases"]) == {"send", "receive"}, "wrong phases")
    for name, phase in evidence["phases"].items():
        validate_phase(phase, evidence["expected_peers"], nodes, sent["ciphertext_bytes"], name == "receive")
    require(evidence["phases"]["send"]["selected_route"]["route_context_id"]
            != evidence["phases"]["receive"]["selected_route"]["route_context_id"]
            and evidence["sender_route_disconnected"] is True
            and evidence["receiver_route_disconnected"] is True,
            "normal sender disconnect and fresh owner route missing")
    require(set(evidence["provider_stop"]) == set(nodes)
            and all(not receipt["serving"] for receipt in evidence["provider_stop"].values()),
            "provider services not stopped")
    require(evidence["private_cleanup"] == {"sender_secrets_removed": True,
            "owner_secrets_removed": True, "plaintext_outputs_removed": True}, "private cleanup incomplete")


def build_evidence(work):
    value = read(work / "content-mailbox-summary.json")
    value.update({key: read(work / f"content-mailbox-{filename}.json") for key, filename in
                  (("invite", "invite"), ("enroll", "enroll"), ("send", "send"),
                   ("receive", "receive"), ("receive_empty", "receive-empty"),
                   ("output", "output"), ("restart", "restart"), ("private_cleanup", "private-cleanup"))})
    value["expected_peers"] = read(work / "a01-expected-peers.json")
    value["provider_stop"] = {n: read(work / f"content-mailbox-{n}-stop.json") for n in value["provider_nodes"]}
    value["providers"] = {n: read(work / f"content-mailbox-{n}-state.json") for n in value["provider_nodes"]}
    value["phases"] = {}
    for name in ("send", "receive"):
        prefix = f"content-mailbox-{name}"
        value["phases"][name] = dict(
            selected_route=read(work / f"{prefix}-live-selection.json"),
            control_relay_peer_id=read(work / f"{prefix}-status.json")["control_relay_peer_id"],
            privacy={r: read(work / f"{prefix}-privacy-{r}.json") for r in ROLES},
            control=read(work / f"content-provider-mailbox-{name}-control.json"),
            gates=read(work / f"{prefix}-gates.json"))
    validate_evidence(value)
    value["success"] = True
    return value


def validate_report(report, revision):
    require(report["report_kind"] == "volparossa-private-mailbox" and report["source_revision"] == revision
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"]
            and re.fullmatch(HEX, report["host_state"]["before_sha256"])
            and report["independent_sender_node_claimed"] is False
            and report["full_c07_claimed"] is False and report["full_alpha_acceptance_claimed"] is False,
            "wrong source, cleanup, host state or scope")
    validate_evidence(report["mailbox"])


def input_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        for index in range(8):
            stream.write(bytes([65 + index]) * 262144)
        stream.write(b"Z" * 123)


def output_file(directory, empty):
    names = list(directory.iterdir())
    require(len(names) == 1 and re.fullmatch(HEX, names[0].name), "not one opaque output filename")
    info = names[0].lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and stat.S_IMODE(directory.stat().st_mode) == 0o700 and info.st_size == BYTES,
            "invalid plaintext file mode/length")
    require(not list(empty.iterdir()) and stat.S_IMODE(empty.stat().st_mode) == 0o700,
            "second receive output not empty/private")
    with names[0].open("rb") as source:
        digest = hashlib.sha256(source.read(BYTES + 1)).hexdigest()
    require(digest == SHA, "plaintext changed")
    return dict(bytes=BYTES, sha256=digest, opaque_filename=names[0].name,
                file_mode="0600", directory_mode="0700", empty_directory_entries=0)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "input":
            input_file(Path(sys.argv[2]))
        elif len(sys.argv) == 4 and sys.argv[1] == "output":
            print(json.dumps(output_file(Path(sys.argv[2]), Path(sys.argv[3]))))
        elif len(sys.argv) == 4 and sys.argv[1] == "evidence":
            result = build_evidence(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as target:
                json.dump(result, target, sort_keys=True, separators=(",", ":"))
        elif len(sys.argv) == 4 and sys.argv[1] == "report":
            validate_report(read(Path(sys.argv[2])), sys.argv[3])
        else:
            raise ValueError("usage: input NEW_FILE | output DIRECTORY EMPTY_DIRECTORY | evidence WORK OUTPUT | report REPORT REVISION")
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"mailbox evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
