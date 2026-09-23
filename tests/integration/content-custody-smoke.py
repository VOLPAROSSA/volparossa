#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual public custody/restart/name-fetch evidence, not promised future availability.

The real CLI verifies Ed25519 receipts. This checker additionally binds their retained
canonical fields to independent fixture identities and raw network/cleanup observations;
its protobuf inspection is not a second cryptographic signature verifier.
"""

import base64
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
CANDIDATES = SHARED["CANDIDATES"]
CHUNK = 262144
FIXTURE = b"".join(bytes([value]) * CHUNK for value in (7, 13, 29, 53, 7, 13, 29, 53)) + bytes([9]) * 123
BYTES, SHA = len(FIXTURE), hashlib.sha256(FIXTURE).hexdigest()
UNIQUE_BYTES, UNIQUE_CHUNKS = 4 * CHUNK + 123, 5
PRIVATE_NAMES = {"identity.key", "passphrase", "manifest.bin", "input.bin", "output.bin"}
CACHE_NAMES = {".volparossa-owner-v1", ".volparossa-index-v1",
               ".volparossa-index-next-v1", ".volparossa-chunk-next-v1"}


def private_root(path, missing=False):
    root = Path(path)
    require(root.is_absolute() and root.name == "custody-user", "wrong disposable private root")
    if missing and not root.exists() and not root.is_symlink():
        return root
    metadata = root.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == os.geteuid(), "private root is not the current user's 0700 directory")
    return root


def private_file(path):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1,
            "refusing non-owned, linked or non-private fixture file")
    return metadata


def create_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(value)


def initialize(path):
    root = private_root(path)
    require(not list(root.iterdir()), "custody user root was not empty")
    create_private(root / "input.bin", FIXTURE)
    create_private(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    return dict(bytes=BYTES, sha256=SHA, chunks=9, unique_chunks=UNIQUE_CHUNKS,
                unique_bytes=UNIQUE_BYTES, explicit_public_fixture=True)


def remove_source(root):
    cache = root / "source-cache"
    if cache.exists() or cache.is_symlink():
        metadata = cache.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700
                and metadata.st_uid == os.geteuid(), "source cache ownership invalid")
        children = list(cache.iterdir())
        require(len(children) <= 32 and (cache / ".volparossa-owner-v1").is_file(),
                "source cache has no ownership marker or exceeds its fixture bound")
        # Validate the entire exact owned directory before deleting any of its files.
        for child in children:
            require(child.name in CACHE_NAMES or re.fullmatch(r"[0-9a-f]{64}", child.name),
                    "unexpected content in disposable source cache")
            private_file(child)
        for child in children:
            child.unlink()
        cache.rmdir()
    source = root / "input.bin"
    if source.exists() or source.is_symlink():
        private_file(source)
        source.unlink()
    return dict(source_cache_removed=not cache.exists(), source_input_removed=not source.exists(),
                publisher_identity_retained=(root / "identity.key").is_file(),
                original_manifest_retained=(root / "manifest.bin").is_file())


def cleanup(path):
    root = private_root(path, missing=True)
    if root.exists():
        # Unknown files stop cleanup; no recursive wildcard deletion of user state.
        children = list(root.iterdir())
        require(all(child.name in PRIVATE_NAMES | {"source-cache"} for child in children),
                "unknown private fixture content")
        for child in children:
            if child.name != "source-cache":
                private_file(child)
        remove_source(root)
        for child in root.iterdir():
            child.unlink()
        root.rmdir()
    return dict(identity_removed=True, passphrase_removed=True, source_removed=True,
                output_removed=True, user_directory_removed=not root.exists())


def output(path):
    root = private_root(path)
    target = root / "output.bin"
    metadata = private_file(target)
    require(metadata.st_size == BYTES and target.read_bytes() == FIXTURE,
            "normal CLI output differs from the original public fixture")
    require(not (root / "source-cache").exists() and not (root / "input.bin").exists(),
            "original source is still available")
    return dict(path=str(target), bytes=BYTES, sha256=SHA, output_mode="0600",
                source_cache_removed=True, source_input_removed=True)


def varint(data, offset):
    start, value, shift = offset, 0, 0
    while offset < len(data) and shift <= 63:
        byte = data[offset]
        offset += 1
        require(shift != 63 or byte <= 1, "overflowing protobuf integer")
        value |= (byte & 127) << shift
        if byte < 128:
            require(offset == start + 1 or byte != 0, "noncanonical protobuf integer")
            return value, offset
        shift += 7
    raise ValueError("truncated protobuf integer")


def fields(data, maximum):
    require(isinstance(data, bytes) and 0 < len(data) <= maximum, "oversized or empty protobuf")
    result, offset, previous = {}, 0, 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        require(number > previous and wire in (0, 2), "duplicate, unordered or unsupported protobuf field")
        previous = number
        value, offset = varint(data, offset)
        if wire == 2:
            require(value > 0 and offset + value <= len(data), "empty or truncated protobuf bytes")
            value, offset = data[offset:offset + value], offset + value
        else:
            require(value > 0, "encoded default scalar is noncanonical")
        result[number] = value
    return result


def peer_key(peer):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    require(isinstance(peer, str) and 40 <= len(peer) <= 64
            and all(char in alphabet for char in peer), "invalid fixture Peer ID")
    number = 0
    for char in peer:
        number = number * 58 + alphabet.index(char)
    decoded = bytes(len(peer) - len(peer.lstrip("1"))) + number.to_bytes((number.bit_length() + 7) // 8, "big")
    require(len(decoded) == 38 and decoded[:6] == bytes.fromhex("002408011220"),
            "fixture Peer ID does not inline an Ed25519 public key")
    return decoded[6:].hex()


def receipt(encoded, provider, publisher, manifest, expiry, operation, state):
    require(isinstance(encoded, str) and re.fullmatch(r"[0-9a-f]{2,4096}", encoded)
            and len(encoded) % 2 == 0, "receipt bytes absent or oversized")
    envelope = fields(bytes.fromhex(encoded), 2048)
    require(set(envelope) == {1, 2} and isinstance(envelope[2], bytes)
            and len(envelope[2]) == 64, "receipt envelope signature missing")
    body = fields(envelope[1], 2048)
    require(set(body) == set(range(1, 9)) and body[1] == 1 and body[6] == 3
            and body[2] == bytes.fromhex(provider) and isinstance(body[5], bytes) and len(body[5]) == 32
            and type(body[3]) is int and type(body[4]) is int
            and 0 < body[4] - body[3] <= 900 and body[3] < expiry and body[4] <= expiry
            and body[7] == hashlib.sha256(body[8]).digest(), "receipt body identity, deadline or hash invalid")
    payload = fields(body[8], 1024)
    require(set(payload).issubset(set(range(1, 12)))
            and set(range(1, 12)) - {5, 6} <= set(payload)
            and payload.get(5, 1) == operation and payload.get(6, 1) == state
            and payload.get(5) != 1 and payload.get(6) != 1,
            "receipt operation/state is noncanonical or differs from the CLI result")
    require(all(isinstance(payload[key], bytes) and len(payload[key]) == 32 for key in (1, 2, 3, 4, 7, 8))
            and payload[3] == body[2] and payload[4] == bytes.fromhex(publisher)
            and payload[7] == bytes.fromhex(manifest) and payload[8].hex() == SHA
            and payload[9] == BYTES and payload[10] == UNIQUE_CHUNKS and payload[11] == expiry,
            "receipt substituted provider, publisher, manifest, complete bytes or original expiry")
    return payload[1].hex(), payload[2].hex()


def validate_operation(result, keys, publication, layout, operation, complete):
    require(result["operation"] == f"content_custody_{operation}"
            and result["manifest_id"] == layout["manifest_id"]
            and result["publisher_key_hex"] == publication["publisher_key_hex"]
            and result["object_bytes"] == BYTES
            and result["original_expiry_unix_seconds"] == publication["expires_unix_seconds"]
            and result["requested_providers"] == 2 and result["failed_providers"] == 0
            and result["confirmed_complete_providers"] == (2 if complete else 0)
            and result["complete"] is complete and len(result["observations"]) == 2
            and all(result[key] is False for key in ("private_keys_transferred", "direct_provider_dial",
                "origin_authenticated", "future_availability_guaranteed")),
            "ordinary CLI custody handoff was incomplete, substituted or overstated")
    observations = result["observations"]
    require({entry["provider_key_hex"] for entry in observations} == set(keys.values()),
            "two independent configured provider identities missing")
    bindings = []
    for entry in observations:
        require(entry["agent_handoff_complete"] is True and entry["error"] is None
                and entry["state"] == ("complete" if complete else "missing")
                and entry["original_expiry_unix_seconds"] == publication["expires_unix_seconds"]
                and entry["object_bytes"] == BYTES and entry["unique_chunks"] == UNIQUE_CHUNKS,
                "signed observation lacks its matching successful agent handoff")
        bindings.append(receipt(entry["signed_receipt_hex"], entry["provider_key_hex"],
            publication["publisher_key_hex"], layout["manifest_id"], publication["expires_unix_seconds"],
            1 if operation == "deposit" else 2, 2 if complete else 1))
    return bindings


def validate_path(phase, peers, layout, name, payload_minimum=UNIQUE_BYTES):
    selected, privacy = phase["selected_route"], phase["privacy"]
    paths, slots, providers = selected["paths"], selected["benchmark_slots"], layout["provider_nodes"]
    require(selected["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and selected["route_context_id"] == layout["route_context_id"]
            and re.fullmatch(r"[0-9a-f]{32}", selected["route_context_id"])
            and len({path["relay_peer_id"] for path in paths}) == 2
            and {path["exit_peer_id"] for path in paths} == {peers["exit"]}
            and all(path["route_context_id"] == selected["route_context_id"] for path in paths)
            and [slot["relay_peer_id"] for slot in slots] == [path["relay_peer_id"] for path in paths],
            "unchanged MPTCP route with two parallel one-relay paths unavailable")
    relays = [slot["relay_node"] for slot in slots]
    require(len(set(relays)) == 2 and all(node in ROLES[1:4] for node in relays)
            and all(peers[slot["relay_node"]] == slot["relay_peer_id"] for slot in slots)
            and not {peers[node] for node in providers}.intersection({peers[node] for node in ROLES}),
            "provider independence or selected physical relay identities differ")
    require(set(privacy) == set(ROLES), "five-role privacy captures missing")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and capture["unexpected_provider_application_packets"] == 0
                and set(capture["provider_application"]) == set(CANDIDATES),
                "unexpected outer traffic or incomplete physical provider coverage")
        SHARED["validate_drained"](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != "exit":
            require(all(value == 0 for application in capture["provider_application"].values()
                        for value in application.values()), "provider application bypassed the protected route")
    require(privacy["client"]["direct_client_exit_packets"] == 0
            and privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == 0
            and privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[node]["internet_destination_outer_packets"] == 0 for node in ROLES[1:4]),
            "Client/Relay/Exit privacy boundary violated")
    for node in relays:
        require(privacy[node]["client_leg_wireguard_data_datagrams"] > (0 if name in ("inspect", "executor-discovery") else 16)
                and privacy[node]["exit_leg_wireguard_data_datagrams"] > (0 if name in ("inspect", "executor-discovery") else 16),
                "selected WireGuard legs did not carry actual protected data")
    payload_bytes = 0
    for node, application in privacy["exit"]["provider_application"].items():
        if node not in providers:
            if name == "executor-discovery":
                # Explicit pre-job eligibility queries may contact ordinary content peers
                # which are not subsequently selected. This exception is never an inference gate.
                require(set(application) == {"request_packets", "response_packets", "response_payload_bytes"}
                        and all(type(value) is int and value >= 0 for value in application.values())
                        and (application["request_packets"] > 0 or all(value == 0 for value in application.values())),
                        "invalid pre-job provider query counters")
            else:
                require(all(value == 0 for value in application.values()), "unselected provider carried application data")
        elif name != "fetch":
            require(application["request_packets"] > (16 if name == "deposit" else 0)
                    and application["response_packets"] > 0 and application["response_payload_bytes"] > 0,
                    "selected custody provider lacks its actual application exchange")
        payload_bytes += application["response_payload_bytes"]
    if name == "fetch":
        require(payload_minimum > 0 and payload_bytes >= payload_minimum,
                "normal provider retrieval did not carry the unique object bytes")
    control = next(node for node in SHARED["PUBLIC_IPS"] if peers[node] == layout["control_relay_peer_id"])
    SHARED["validate_control"](phase["control_privacy"], control, providers, False,
                               require_contacts=name != "fetch")
    require(phase["gates"]["event_baseline_unix_ms"] > 0
            and phase["gates"]["exit_mptcp_tls_completed"] >= {"deposit": 4, "inspect": 2, "fetch": 1, "executor-discovery": 2}[name],
            "fresh production MPTCP/TLS completions missing")


def validate_evidence(evidence):
    if evidence.get("automatic_provider_selection") is True:
        runpy.run_path(str(Path(__file__).with_name("content-retain-smoke.py")))["validate_evidence"](evidence)
        return
    publish, layout, peers = evidence["publish"], evidence["layout"], evidence["expected_peers"]
    nodes, keys = layout["provider_nodes"], layout["provider_keys"]
    require(evidence["success"] is True and len(nodes) == len(set(nodes)) == 2
            and set(nodes) <= set(CANDIDATES) and set(keys) == set(nodes)
            and len(set(keys.values())) == 2 and layout["control_relay_peer_id"] not in {peers[n] for n in nodes}
            and re.fullmatch(r"[0-9a-f]{64}", layout["manifest_id"]), "invalid independent custody layout")
    require(evidence["input"] == dict(bytes=BYTES, sha256=SHA, chunks=9, unique_chunks=UNIQUE_CHUNKS,
                unique_bytes=UNIQUE_BYTES, explicit_public_fixture=True)
            and publish["operation"] == "offline_content_publish" and publish["network_publication"] is False
            and publish["bytes"] == BYTES and publish["chunks"] == 9
            and re.fullmatch(r"[0-9a-f]{64}", publish["publisher_key_hex"])
            and publish["publisher_key_hex"] not in set(keys.values()), "original explicit public publication missing")
    for node in nodes:
        provider = evidence["providers"][node]
        require(keys[node] == peer_key(peers[node]) == provider["public"]["identity_public_key_hex"],
                "provider key was not independently bound to the configured node")
        for label, count in (("empty", 0), ("restored", 1)):
            status = provider[label]
            require(status["serving"] is True and status["replication_enabled"] is True
                    and status["publications"] == status["replica_publications"] == count,
                    "automatic contribution service did not restore its exact retained publication")
        restart = provider["restart"]
        require(restart["node"] == node and restart["pid_before"] > 0 and restart["pid_after"] > 0
                and restart["pid_before"] != restart["pid_after"]
                and restart["cache_before"] == restart["cache_after"]
                and re.fullmatch(r"[0-9]+:[0-9]+", restart["cache_after"])
                and re.fullmatch(r"[0-9]+:[0-9]+", restart["namespace_identity"])
                and restart["executable_verified"] is True and restart["automatic_reopen"] is True
                and provider["stop"]["serving"] is False,
                "actual owned provider restart, same persistent cache or shutdown not proven")
    bindings = []
    for name, operation, complete in (("missing", "inspect", False), ("deposit", "deposit", True), ("inspect", "inspect", True)):
        bindings.extend(validate_operation(evidence[name], keys, publish, layout, operation, complete))
    require(len({request for request, _ in bindings}) == len({challenge for _, challenge in bindings}) == 6,
            "historical receipts or connection challenges were reused")
    require(evidence["source_removed"] == dict(source_cache_removed=True, source_input_removed=True,
                publisher_identity_retained=True, original_manifest_retained=True),
            "original bytes were not removed before provider restart/inspection")
    fetch, result = evidence["fetch"], evidence["output"]
    require(fetch["operation"] == "named_content_download" and fetch["name"] == "disposable-public-custody"
            and fetch["revision"] == 1 and fetch["publisher_key"] == publish["publisher_key_hex"]
            and fetch["manifest_id"] == layout["manifest_id"]
            and fetch["publication_expires_unix_seconds"] == publish["expires_unix_seconds"]
            and fetch["bytes"] == result["bytes"] == BYTES and fetch["sha256"] == result["sha256"] == SHA
            and fetch["chunks"] == 9 and 1 <= fetch["providers_used"] <= 2
            and len(set(fetch["provider_peer_ids"])) == fetch["providers_used"]
            and set(fetch["provider_peer_ids"]) <= {peers[node] for node in nodes}
            and UNIQUE_BYTES <= fetch["peer_bytes"] <= BYTES
            and fetch["control_relay_peer_id"] == layout["control_relay_peer_id"]
            and fetch["origin_authenticated"] is False and fetch["globally_latest"] is False
            and fetch["local_delivery"] is True and fetch["ownership_changed"] is False
            and fetch["output_mode"] == result["output_mode"] == "0600"
            and fetch["local_output"] == result["path"] and fetch["cache"] != result["path"]
            and result["source_cache_removed"] is True and result["source_input_removed"] is True,
            "fresh normal name-based retrieval did not reconstruct the same original publication")
    isolation = evidence["isolation"]
    require(isolation["user_uid"] > 0 and isolation["agent_uid"] > 0
            and isolation["user_uid"] != isolation["agent_uid"]
            and isolation["control_gid"] != isolation["agent_gid"]
            and isolation["cache_mode"] == "0700" and isolation["output_mode"] == "0600"
            and all(isolation[key] is True for key in ("agent_mount_positive_control", "agent_cannot_read_user_state",
                "client_cannot_read_provider_stores", "user_cannot_read_agent_cache", "fresh_consumer_cache"))
            and evidence["private_cleanup"] == dict(identity_removed=True, passphrase_removed=True,
                source_removed=True, output_removed=True, user_directory_removed=True), "account isolation or private cleanup missing")
    require(set(evidence["phases"]) == {"deposit", "inspect", "fetch"}, "custody network phases incomplete")
    for name, phase in evidence["phases"].items():
        validate_path(phase, peers, layout, name)


def build_evidence(work):
    evidence = {name: read(work / f"content-custody-{suffix}.json") for name, suffix in (
        ("input", "input"), ("publish", "publish"), ("layout", "layout"), ("missing", "missing"),
        ("deposit", "deposit"), ("inspect", "inspect"), ("fetch", "fetch"), ("output", "output"),
        ("source_removed", "source-removed"), ("isolation", "isolation"), ("private_cleanup", "private-cleanup"))}
    evidence.update(success=True, expected_peers=read(work / "a01-expected-peers.json"))
    evidence["providers"] = {node: {label: read(work / f"content-custody-{node}-{label}.json")
        for label in ("public", "empty", "restored", "restart", "stop")} for node in evidence["layout"]["provider_nodes"]}
    evidence["phases"] = {name: dict(selected_route=read(work / f"content-custody-{name}-live-selection.json"),
        privacy={role: read(work / f"content-custody-{name}-privacy-{role}.json") for role in ROLES},
        control_privacy=read(work / f"content-provider-custody-{name}-control.json"),
        gates=read(work / f"content-custody-{name}-gates.json")) for name in ("deposit", "inspect", "fetch")}
    validate_evidence(evidence)
    return evidence


def validate_report(report, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report["source_revision"] == revision
            and report["schema_version"] == 1 and report["report_kind"] == "volparossa-public-custody"
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["phase"] == "content-custody-complete" and report["observed_blocker"] is None
            and report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
            and report["host_state"]["unchanged"] is True
            and report["custody"].get("automatic_provider_selection") is True
            and all(report[key] is False for key in ("independent_publisher_node_offline_claimed",
                "future_availability_guaranteed", "full_alpha_acceptance_claimed")),
            "exact-source successful custody report or complete host cleanup unavailable")
    validate_evidence(report["custody"])


def main(arguments):
    command = arguments[0]
    if command == "init" and len(arguments) == 2:
        result = initialize(arguments[1])
    elif command == "drop-source" and len(arguments) == 2:
        result = remove_source(private_root(arguments[1]))
    elif command == "cleanup" and len(arguments) == 2:
        result = cleanup(arguments[1])
    elif command == "output" and len(arguments) == 2:
        result = output(arguments[1])
    elif command == "evidence" and len(arguments) == 3:
        result = build_evidence(Path(arguments[1]))
        Path(arguments[2]).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    elif command == "report" and len(arguments) == 3:
        validate_report(read(Path(arguments[1])), arguments[2])
        result = dict(success=True, report_kind="volparossa-public-custody")
    else:
        raise ValueError("unknown custody evidence command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration) as error:
        print(f"public custody evidence rejected: {error}", file=sys.stderr)
        sys.exit(1)
