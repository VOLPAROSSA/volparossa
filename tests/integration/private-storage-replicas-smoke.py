#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual replica CLI operations and sanitized evidence; synthetic opaque transport data only."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys

BASE = runpy.run_path(str(Path(__file__).with_name("private-storage-peer-smoke.py")))
NET = BASE["SHARED"]
read, require, ROLES = BASE["read"], BASE["require"], BASE["ROLES"]
private_root, private_file, create = BASE["private_root"], BASE["private_file"], BASE["create"]
unlock = BASE["unlock"]
BYTES, SHA, FIXTURE = BASE["BYTES"], BASE["SHA"], BASE["FIXTURE"]
FILES = {"identity.key", "passphrase", "grant-a.bin", "grant-b.bin", "input.bin",
         "restore-a.bin", "restore-b.bin", "restore-survivor.bin", "identities.sha256"}
SCOPE_FALSE = ("signal_backup_proven", "archive_encryption_proven", "independent_failure_domains_proven",
               "automatic_repair", "network_contribution_credit", "full_alpha_acceptance_claimed")
SUMMARY_NAMES = ("smoke", "evidence", "prepare", "upload", "failover", "finish", "withdrawal",
                 "deleted_usage", "private_cleanup", "isolation", "layout")
EXPORT_NAMES = ("a01-expected-peers.json",) + tuple(
    f"private-storage-replicas-{name}.json" for name in SUMMARY_NAMES
) + tuple(name for phase in ("upload", "failover", "finish") for name in (
    f"private-storage-replicas-{phase}-live-selection.json",
    f"private-storage-replicas-{phase}-gates.json",
    f"content-provider-private-storage-replicas-{phase}-control.json",
    *(f"private-storage-replicas-{phase}-privacy-{role}.json" for role in ROLES),
))


def read_deleted_usage(path):
    """The CLI produces exactly two small usage objects, not one evidence object."""
    require(not path.is_symlink(), "symlink usage evidence is not accepted")
    with path.open(encoding="ascii") as source:
        text = source.read(1025)
    require(len(text) <= 1024, "usage evidence exceeds its bound")
    value = json.loads(text)
    require(isinstance(value, list) and len(value) == 2, "two provider usage objects required")
    for usage in value:
        require(isinstance(usage, dict) and set(usage) == {"reserved_bytes", "committed_bytes", "leases"}
                and all(type(count) is int and 0 <= count <= 2**64 - 1 for count in usage.values()),
                "invalid provider usage object")
    return value


def invoke(binary, socket, args, raw=False, expected=0, deadline=180):
    # A failover restore has at most three core exchanges: failed A, B Progress, B ReadRange.
    # Each core exchange retains its own 120s limit. No retry or larger core deadline is added.
    process = subprocess.Popen([binary, "--control-socket", socket, *map(str, args)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=deadline)
        require(process.returncode == expected, "private replica CLI operation failed")
        require(len(stdout) <= 16384 and len(stderr) <= 16384, "replica diagnostics exceeded fixture bound")
        if expected:
            require(not stdout, "failed no-clobber operation emitted a success response")
            return None
        return None if raw else json.loads(stdout)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def existing(root):
    return ["--state", root / "replica-set", *unlock(root)]


def identity_digest(root):
    entries = []
    for index in range(2):
        path = root / f"replica-set/copy-{index}/archive.json"
        require(private_file(path).st_size <= 16384, "private copy metadata exceeded bound")
        value = json.loads(path.read_text())
        entries.append({key: value[key] for key in (
            "provider_key", "owner_key", "grant_hex", "archive_id", "ciphertext_bytes", "sha256", "lease")})
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).digest()


def check_identity(root):
    private_file(root / "identities.sha256")
    require(identity_digest(root) == (root / "identities.sha256").read_bytes(),
            "retained owner/provider/archive/lease identities changed")


def validate_cli(value, operation, keys, charges, complete=True):
    require(value["operation"] == "private_storage_replicas_" + operation
            and value["logical_ciphertext_bytes"] == BYTES
            and value["distinct_provider_identities"] == 2
            and [copy["provider_key"] for copy in value["copies"]] == list(keys)
            and [copy["charge"] for copy in value["copies"]] == list(charges)
            and value["read_consumes_archive"] is False
            and value["expired_copies_remain_charged"] is True
            and value["operation_complete"] is complete
            and all(value[field] is False for field in (
                "metadata_overhead_measured", "independent_failure_domains_proven",
                "network_contribution_credit", "automatic_repair")), "replica result scope changed")
    for category in ("reserved", "committed", "uncertain"):
        require(value[category + "_payload_bytes"] == charges.count(category) * BYTES,
                "replica per-copy payload accounting mismatch")
    require(value["physical_payload_charge_upper_bound"] ==
            sum(charge not in ("deleted", "unattempted") for charge in charges) * BYTES,
            "replica physical payload charge mismatch")


def prepare(root, binary, client, provider_a, provider_b, key_a, key_b):
    require(not list(root.iterdir()) and key_a != key_b, "fixture is not new or providers are equal")
    create(root / "input.bin", FIXTURE)
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner not in (key_a, key_b), "owner is not distinct")
    for label, socket, key in (("a", provider_a, key_a), ("b", provider_b, key_b)):
        result = invoke(binary, socket, ["storage", "peer", "grant", "--provider-key", key,
            "--owner-key", owner, "--max-payload-bytes", BYTES, "--max-leases", 1,
            "--max-retention-seconds", 7200, "--lifetime-seconds", 7200,
            "--output", root / f"grant-{label}.bin"])
        require(result["grant_written"] is True and result["max_payload_bytes"] == BYTES
                and result["max_leases"] == 1 and result["reserved_bytes"] == 0
                and result["network_contribution_credit"] is False, "bounded provider grant missing")
    return dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, providers=2,
                grant_max_leases_each=1, grant_payload_bytes_each=BYTES,
                owner_distinct_from_both_providers=True, owner_secrets_exported=False)


def upload(root, binary, client, key_a, key_b):
    keys = (key_a, key_b)
    created = invoke(binary, client, ["storage", "replicas", "create", *existing(root),
        "--provider-key", key_a, "--grant", root / "grant-a.bin",
        "--provider-key", key_b, "--grant", root / "grant-b.bin", "--input", root / "input.bin",
        "--sha256", SHA, "--already-encrypted", "--lifetime-seconds", 1800])
    require(created["physical_payload_charge_upper_bound"] == 0, "create unexpectedly charged storage")
    command = ["storage", "replicas", "deposit", *existing(root),
               "--input", root / "input.bin", "--already-encrypted"]
    validate_cli(invoke(binary, client, command), "deposit", keys, ("committed", "committed"))
    create(root / "identities.sha256", identity_digest(root))
    for operation, tail in (("progress", []), ("deposit", command[3:]),
                            ("renew", [*existing(root), "--lifetime-seconds", 3600])):
        arguments = tail if tail else existing(root)
        result = invoke(binary, client, ["storage", "replicas", operation, *arguments])
        validate_cli(result, operation, keys, ("committed", "committed"))
        check_identity(root)
    status = invoke(binary, client, ["storage", "replicas", "status", "--state", root / "replica-set"])
    # Status is read-only local accounting and intentionally does not unlock owner credentials.
    validate_cli({**status, "operation_complete": True}, "status", keys, ("committed", "committed"))
    private_file(root / "input.bin")
    (root / "input.bin").unlink()
    return dict(committed_copies=2, logical_ciphertext_bytes=BYTES, physical_payload_charge=2 * BYTES,
                chunks_per_copy=3, fresh_process_progress=True, committed_retry_same_identities=True,
                renewal_confirmed_by_progress=True, source_removed_before_restore=True)


def restore_file(root, binary, client, keys, name, charges, outcomes):
    result = invoke(binary, client, ["storage", "replicas", "restore", *existing(root), "--output", root / name], deadline=420)
    validate_cli(result, "restore", keys, charges)
    require(result["restored"] is True and result["restored_from_provider_key"] == keys[1]
            and result["copy_outcomes"] == outcomes, "restore did not use the expected surviving provider")
    require(private_file(root / name).st_size == BYTES
            and hashlib.sha256((root / name).read_bytes()).hexdigest() == SHA, "whole archive restore mismatch")
    check_identity(root)


def failover(root, binary, client, key_a, key_b):
    require(not (root / "input.bin").exists(), "original source remains before restore")
    for name in ("restore-a.bin", "restore-b.bin"):
        restore_file(root, binary, client, (key_a, key_b), name, ("uncertain", "committed"),
                     ["unavailable_or_restore_unverified", "restored_and_retained"])
    invoke(binary, client, ["storage", "replicas", "restore", *existing(root),
                           "--output", root / "restore-a.bin"], expected=1)
    require(hashlib.sha256((root / "restore-a.bin").read_bytes()).hexdigest() == SHA,
            "failed restore clobbered a completed output")
    return dict(restores=2, first_provider_attempt_failed=True, second_provider_restored=True,
                whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
                uncertain_first_copy_remains_charged=True, physical_payload_charge=2 * BYTES)


def finish(root, binary, client, key_a, key_b):
    keys = (key_a, key_b)
    validate_cli(invoke(binary, client, ["storage", "replicas", "progress", *existing(root)]),
                 "progress", keys, ("committed", "committed"))
    check_identity(root)
    for _ in range(2):
        validate_cli(invoke(binary, client, ["storage", "replicas", "delete", *existing(root),
                                             "--provider-key", key_a]), "delete", keys, ("deleted", "committed"))
    restore_file(root, binary, client, keys, "restore-survivor.bin", ("deleted", "committed"),
                 ["explicitly_deleted", "restored_and_retained"])
    for _ in range(2):
        validate_cli(invoke(binary, client, ["storage", "replicas", "delete", *existing(root),
                                             "--provider-key", key_b]), "delete", keys, ("deleted", "deleted"))
    return dict(reopened_first_copy_confirmed=True, original_identities_retained=True,
                selected_copy_deleted=True, surviving_copy_restored=True,
                surviving_payload_charge=BYTES, delete_retry_idempotent=True, final_payload_charge=0)


def cleanup(path):
    root = private_root(path, missing=True)
    if root.exists():
        files, directories = [], []
        for child in root.iterdir():
            if child.name != "replica-set" and not re.fullmatch(r"\.replicas-[A-Za-z0-9]+", child.name):
                require(child.name in FILES or re.fullmatch(r"\.tmp[A-Za-z0-9]+", child.name), "unexpected private fixture file")
                files.append(child)
                continue
            info = child.lstat()
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_uid == os.geteuid(), "private set ownership changed")
            for entry in child.iterdir():
                if entry.name in ("copy-0", "copy-1"):
                    info = entry.lstat()
                    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                            and info.st_uid == os.geteuid(), "private copy ownership changed")
                    content = list(entry.iterdir())
                    require(len(content) <= 4 and all(p.name == "archive.json" or
                            re.fullmatch(r"\.tmp[A-Za-z0-9]+", p.name) for p in content), "unexpected private copy file")
                    files.extend(content)
                    directories.append(entry)
                else:
                    require(entry.name == "replicas.json" or re.fullmatch(r"\.tmp[A-Za-z0-9]+", entry.name),
                            "unexpected private manifest file")
                    files.append(entry)
            directories.append(child)
        require(len(directories) <= 6, "private cleanup exceeded directory bound")
        require(len(files) <= len(FILES) + 12, "private cleanup exceeded file bound")
        for path in files:
            private_file(path)
        for path in files:
            path.unlink()
        for path in directories:
            path.rmdir()
        root.rmdir()
    return dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
                replica_metadata_removed=True, input_and_outputs_removed=True, user_directory_removed=True)


def validate_network(phase, peers, layout, name, minimum_flows=None):
    selected, privacy = phase["selected_route"], phase["privacy"]
    paths, slots, nodes = selected["paths"], selected["benchmark_slots"], layout["provider_nodes"]
    require(selected["transport"] == "mptcp" and selected["route_context_id"] == layout["route_context_id"]
            and len(paths) == len(slots) == 2 and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [p["relay_peer_id"] for p in paths] == [s["relay_peer_id"] for s in slots],
            "original protected route changed")
    forbidden = {peers["client"], peers["exit"], layout["control_relay_peer_id"]} | {p["relay_peer_id"] for p in paths}
    require(len(nodes) == len(set(nodes)) == 2 and all(node in NET["CANDIDATES"] for node in nodes)
            and len({peers[node] for node in nodes}) == 2 and all(peers[node] not in forbidden for node in nodes),
            "storage providers are not distinct from each other and the route")
    relays = [slot["relay_node"] for slot in slots]
    require(len(set(relays)) == 2 and all(r in ROLES[1:4] for r in relays)
            and all(peers[s["relay_node"]] == s["relay_peer_id"] for s in slots)
            and set(privacy) == set(ROLES), "selected capture/relay identities differ")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == capture["unexpected_provider_application_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and set(capture["provider_application"]) == set(NET["CANDIDATES"]), "unexpected path traffic")
        NET["validate_drained"](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != "exit":
            require(all(value == 0 for counters in capture["provider_application"].values()
                        for value in counters.values()), "provider traffic bypassed Exit")
    require(privacy["client"]["direct_client_exit_packets"] == privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[r]["internet_destination_outer_packets"] == 0 for r in ROLES[1:4]), "privacy boundary violated")
    for relay in relays:
        require(privacy[relay]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[relay]["exit_leg_wireguard_data_datagrams"] > 16, "real two-leg payload missing")
    application = privacy["exit"]["provider_application"]
    for node, counters in application.items():
        if node not in nodes:
            require(all(value == 0 for value in counters.values()), "unselected provider carried storage")
        elif name != "failover" or node == nodes[1]:
            require(counters["request_packets"] > 0 and counters["response_packets"] > 0, "selected provider traffic absent")
    if name == "failover":
        require(application[nodes[0]]["response_payload_bytes"] == 0
                and application[nodes[1]]["response_payload_bytes"] >= 2 * BYTES, "real survivor-only restore data missing")
    if name == "finish":
        require(application[nodes[1]]["response_payload_bytes"] >= BYTES, "surviving copy was not restored after deletion")
    control = next(node for node in NET["PUBLIC_IPS"] if peers[node] == layout["control_relay_peer_id"])
    NET["validate_control"](phase["control_privacy"], control, nodes, True)
    if minimum_flows is None:
        minimum_flows = {"upload": 18, "failover": 4, "finish": 6}[name]
    require(type(minimum_flows) is int and minimum_flows > 0
            and phase["gates"]["event_baseline_unix_ms"] > 0
            and phase["gates"]["exit_mptcp_tls_completed"] >= minimum_flows,
            "protected operation completions missing")


def validate_evidence(value):
    require(value["success"] is True and all(value[field] is False for field in SCOPE_FALSE), "scope overstated")
    require(value["prepare"] == dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, providers=2,
        grant_max_leases_each=1, grant_payload_bytes_each=BYTES,
        owner_distinct_from_both_providers=True, owner_secrets_exported=False), "grant/owner evidence missing")
    require(value["upload"] == dict(committed_copies=2, logical_ciphertext_bytes=BYTES, physical_payload_charge=2 * BYTES,
        chunks_per_copy=3, fresh_process_progress=True, committed_retry_same_identities=True,
        renewal_confirmed_by_progress=True, source_removed_before_restore=True), "two retained copies missing")
    require(value["failover"] == dict(restores=2, first_provider_attempt_failed=True, second_provider_restored=True,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
        uncertain_first_copy_remains_charged=True, physical_payload_charge=2 * BYTES), "non-consuming failover missing")
    require(value["finish"] == dict(reopened_first_copy_confirmed=True, original_identities_retained=True,
        selected_copy_deleted=True, surviving_copy_restored=True, surviving_payload_charge=BYTES,
        delete_retry_idempotent=True, final_payload_charge=0), "selected-copy deletion or retained survivor missing")
    require(value["withdrawal"] == dict(first_provider_service_stopped=True, serving=False,
        retained_committed_bytes=BYTES, retained_reserved_bytes=0, retained_leases=1,
        second_provider_serving=True, same_owned_store_reopened=True, agent_restart_claimed=False),
        "first real provider was not stopped with its copy retained")
    require(value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 2,
            "provider capacity was not reclaimed")
    require(value["private_cleanup"] == dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        replica_metadata_removed=True, input_and_outputs_removed=True, user_directory_removed=True), "private cleanup incomplete")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
            and isolation["control_gid"] != isolation["agent_gid"]
            and all(isolation[field] is True for field in ("agent_cannot_read_user_state",
                "client_cannot_read_either_provider_store", "agent_mount_positive_control",
                "both_provider_keys_match_independent_fixture_peers", "provider_namespaces_distinct")), "isolation missing")
    require(set(value["network"]) == {"upload", "failover", "finish"}, "capture phase missing")
    for name, phase in value["network"].items():
        validate_network(phase, value["expected_peers"], value["layout"], name)


def build_evidence(work):
    value = {name: read(work / f"private-storage-replicas-{name}.json") for name in
             ("prepare", "upload", "failover", "finish", "withdrawal", "private_cleanup", "isolation", "layout")}
    value["deleted_usage"] = read_deleted_usage(work / "private-storage-replicas-deleted_usage.json")
    value.update(success=True, expected_peers=read(work / "a01-expected-peers.json"), **dict.fromkeys(SCOPE_FALSE, False))
    value["network"] = {name: dict(selected_route=read(work / f"private-storage-replicas-{name}-live-selection.json"),
        privacy={role: read(work / f"private-storage-replicas-{name}-privacy-{role}.json") for role in ROLES},
        control_privacy=read(work / f"content-provider-private-storage-replicas-{name}-control.json"),
        gates=read(work / f"private-storage-replicas-{name}-gates.json")) for name in ("upload", "failover", "finish")}
    validate_evidence(value)
    return value


def validate_report(report, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report["source_revision"] == revision
            and report["schema_version"] == 1 and report["report_kind"] == "volparossa-private-storage-replicas"
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["phase"] == "private-storage-replicas-complete" and report["observed_blocker"] is None
            and report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
            and report["host_state"]["unchanged"] is True, "source-bound cleanup report incomplete")
    validate_evidence(report["storage"])


def main(arguments):
    command = arguments[0]
    if command == "export-names" and len(arguments) == 1:
        print("\n".join(EXPORT_NAMES))
        return
    if command == "prepare" and len(arguments) == 8:
        result = prepare(private_root(arguments[1]), *arguments[2:])
    elif command in ("upload", "failover", "finish") and len(arguments) == 6:
        result = globals()[command](private_root(arguments[1]), *arguments[2:])
    elif command == "cleanup" and len(arguments) == 2:
        result = cleanup(arguments[1])
    elif command == "evidence" and len(arguments) == 3:
        result = build_evidence(Path(arguments[1]))
        Path(arguments[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif command == "report" and len(arguments) == 3:
        validate_report(read(Path(arguments[1])), arguments[2])
        result = dict(success=True, report_kind="volparossa-private-storage-replicas")
    else:
        raise ValueError("unknown replica fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("private replica fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError):
        print("private replica fixture failed; private diagnostics not exported", file=sys.stderr)
        sys.exit(1)
