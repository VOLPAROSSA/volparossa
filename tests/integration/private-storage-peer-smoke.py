#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real private-storage CLI fixture and sanitized protected-route evidence.

The opaque deterministic bytes exercise transport/storage only: not a Signal
backup, actual archive encryption, redundancy, or reciprocal storage controller.
"""

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

SHARED = runpy.run_path(str(Path(__file__).with_name("content-provider-https-smoke.py")))
read, require, ROLES = SHARED["read"], SHARED["require"], SHARED["ROLES"]
CHUNK = 262144
FIXTURE = bytes(range(256)) * 2048 + b"synthetic-private-storage-transport!!!"
BYTES = len(FIXTURE)
SHA = hashlib.sha256(FIXTURE).hexdigest()
FILES = {"identity.key", "passphrase", "grant.bin", "input.bin", "restore-a.bin", "restore-b.bin"}
SCOPE_FALSE = ("signal_backup_proven", "archive_encryption_proven", "independent_replication_proven",
               "automatic_replication", "network_contribution_credit", "full_alpha_acceptance_claimed")


def private_root(path, missing=False):
    root = Path(path)
    require(root.is_absolute() and root.name == "private-storage-user", "invalid private fixture root")
    if missing and not root.exists() and not root.is_symlink():
        return root
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.geteuid(), "fixture root must be owned and 0700")
    return root


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid() and info.st_nlink == 1,
            "fixture file must be unlinked, owned and 0600")
    return info


def create(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(data)


def invoke(binary, socket, args, raw=False, expected=0):
    # Never export command strings, owner/grant/archive identifiers, or private stderr.
    process = subprocess.Popen([binary, "--control-socket", socket, *map(str, args)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=180)
        require(process.returncode == expected, "private storage CLI operation failed")
        require(len(stdout) <= 16384 and len(stderr) <= 16384, "CLI diagnostics exceeded fixture bound")
        if expected:
            require(not stdout, "failed operation emitted a success response")
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


def unlock(root):
    return ["--identity", root / "identity.key", "--passphrase-file", root / "passphrase"]


def existing(root, key):
    return ["--state", root / "archive-state", "--provider-key", key, *unlock(root)]


def journal(root):
    path = root / "archive-state/archive.json"
    require(private_file(path).st_size <= 16384, "private journal exceeded bound")
    return json.loads(path.read_text())


def validate_result(value, operation, state="Committed"):
    require(value["operation"] == "private_storage_peer_" + operation
            and value["state"] == state and value["ciphertext_bytes"] == BYTES
            and value["stored_bytes"] == (0 if state == "Deleted" else BYTES)
            and value["provider_copies_addressed"] == 1
            and value["committed"] is (state == "Committed")
            and value["restored"] is (operation == "restore")
            and value["read_consumes_archive"] is False
            and all(value[field] is False for field in ("independent_replication_proven",
                "automatic_replication", "network_contribution_credit")),
            "private CLI returned incomplete or overstated storage result")


def prepare(root, binary, client, provider, key):
    require(not list(root.iterdir()), "private fixture directory was not empty")
    create(root / "input.bin", FIXTURE)
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner != key, "owner identity is not distinct")
    granted = invoke(binary, provider, ["storage", "peer", "grant", "--provider-key", key,
        "--owner-key", owner, "--max-payload-bytes", BYTES, "--max-leases", 1,
        "--max-retention-seconds", 7200, "--lifetime-seconds", 7200,
        "--output", root / "grant.bin"])
    require(granted["grant_written"] is True and granted["max_payload_bytes"] == BYTES
            and granted["max_leases"] == 1 and granted["reserved_bytes"] == 0
            and granted["network_contribution_credit"] is False, "explicit bounded grant missing")
    for name in FILES.intersection({p.name for p in root.iterdir()}):
        private_file(root / name)
    return dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, chunks=3,
                owner_distinct_from_provider=True, grant_max_leases=1,
                grant_max_payload_bytes=BYTES, owner_secrets_exported=False)


def upload(root, binary, client, key):
    command = ["storage", "peer", "deposit", "--grant", root / "grant.bin",
        "--input", root / "input.bin", "--sha256", SHA, "--already-encrypted",
        "--lifetime-seconds", 1800, *existing(root, key)]
    validate_result(invoke(binary, client, command), "deposit")
    first = journal(root)
    validate_result(invoke(binary, client, ["storage", "peer", "progress", *existing(root, key)]), "progress")
    validate_result(invoke(binary, client, [*command, "--resume"]), "deposit")
    second = journal(root)
    require(first == second and first["lease"] is not None, "committed retry changed archive/lease identity")
    private_file(root / "input.bin")
    (root / "input.bin").unlink()
    return dict(committed=True, ciphertext_bytes=BYTES, chunks_uploaded=3,
                fresh_process_progress=True, committed_retry_same_archive_and_lease=True,
                source_removed_before_restore=True, interrupted_upload_resume_proven=False)


def download(root, binary, client, key):
    require(not (root / "input.bin").exists(), "original source remains before restore")
    before = journal(root)
    validate_result(invoke(binary, client, ["storage", "peer", "progress", *existing(root, key)]), "progress")
    for name in ("restore-a.bin", "restore-b.bin"):
        result = invoke(binary, client, ["storage", "peer", "restore", "--output", root / name,
                                        *existing(root, key)])
        validate_result(result, "restore")
        require(private_file(root / name).st_size == BYTES
                and hashlib.sha256((root / name).read_bytes()).hexdigest() == SHA,
                "restored bytes failed independent whole-archive digest")
    after = journal(root)
    require(before == after, "non-consuming restores changed retained archive metadata")
    validate_result(invoke(binary, client, ["storage", "peer", "progress", *existing(root, key)]), "progress")
    # A second restore cannot replace even an existing owned output file.
    invoke(binary, client, ["storage", "peer", "restore", "--output", root / "restore-a.bin",
                           *existing(root, key)], expected=1)
    require(hashlib.sha256((root / "restore-a.bin").read_bytes()).hexdigest() == SHA,
            "failed restore clobbered existing output")
    renewal = invoke(binary, client, ["storage", "peer", "renew", "--lifetime-seconds", 3600,
                                     *existing(root, key)])
    validate_result(renewal, "renew", "Renewed")
    require(renewal["expires_unix_seconds"] > before["last_expiry"], "explicit renewal did not extend expiry")
    for _ in range(2):
        validate_result(invoke(binary, client, ["storage", "peer", "delete", *existing(root, key)]),
                        "delete", "Deleted")
    return dict(restores=2, ciphertext_bytes=BYTES, whole_archive_sha256_verified=True,
                reads_nonconsuming=True, existing_output_preserved=True,
                renewal_extended_expiry=True, explicit_delete=True, delete_retry_idempotent=True)


def cleanup(path):
    root = private_root(path, missing=True)
    if root.exists():
        children = list(root.iterdir())
        require(len(children) <= len(FILES) + 1, "unexpected private fixture content")
        files, directories = [], []
        for child in children:
            if child.name == "archive-state":
                info = child.lstat()
                require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                        and info.st_uid == os.geteuid(), "private archive directory ownership changed")
                entries = list(child.iterdir())
                require(len(entries) <= 4 and all(p.name == "archive.json" or
                        re.fullmatch(r"\.tmp[A-Za-z0-9]+", p.name) for p in entries),
                        "unexpected archive state content")
                files.extend(entries)
                directories.append(child)
            else:
                require(child.name in FILES, "unexpected private fixture file")
                files.append(child)
        for path in files:
            private_file(path)
        for path in files:
            path.unlink()
        for path in directories:
            path.rmdir()
        root.rmdir()
    return dict(owner_identity_removed=True, passphrase_removed=True, grant_removed=True,
                private_archive_metadata_removed=True, input_and_outputs_removed=True,
                user_directory_removed=True)


def validate_evidence(evidence):
    require(evidence["success"] is True and all(evidence[field] is False for field in SCOPE_FALSE),
            "private storage scope overstated")
    prepared, upload_result, restored = evidence["prepare"], evidence["upload"], evidence["download"]
    require(prepared == dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, chunks=3,
                owner_distinct_from_provider=True, grant_max_leases=1,
                grant_max_payload_bytes=BYTES, owner_secrets_exported=False), "fixture/grant evidence changed")
    require(upload_result == dict(committed=True, ciphertext_bytes=BYTES, chunks_uploaded=3,
                fresh_process_progress=True, committed_retry_same_archive_and_lease=True,
                source_removed_before_restore=True, interrupted_upload_resume_proven=False),
            "actual committed upload/retry/source removal missing")
    require(restored == dict(restores=2, ciphertext_bytes=BYTES, whole_archive_sha256_verified=True,
                reads_nonconsuming=True, existing_output_preserved=True,
                renewal_extended_expiry=True, explicit_delete=True, delete_retry_idempotent=True),
            "restore/renew/delete lifecycle missing")
    require(evidence["reopen"] == dict(explicit_listener_stop=True, same_owned_store_reopened=True,
                durable_committed_bytes=BYTES, durable_reserved_bytes=0, durable_leases=1,
                agent_restart_claimed=False) and evidence["deleted_usage"] ==
                dict(reserved_bytes=0, committed_bytes=0, leases=0), "durable reopen or quota reclamation missing")
    require(evidence["private_cleanup"] == dict(owner_identity_removed=True, passphrase_removed=True,
                grant_removed=True, private_archive_metadata_removed=True, input_and_outputs_removed=True,
                user_directory_removed=True), "private fixture cleanup incomplete")
    isolation = evidence["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
            and isolation["control_gid"] != isolation["agent_gid"]
            and all(isolation[field] is True for field in ("agent_cannot_read_user_state",
                "client_cannot_read_provider_store", "agent_mount_positive_control",
                "provider_key_matches_independent_fixture_peer")), "owner/provider isolation missing")
    peers, layout, phase = evidence["expected_peers"], evidence["layout"], evidence["network"]
    selected, privacy = phase["selected_route"], phase["privacy"]
    paths, slots = selected["paths"], selected["benchmark_slots"]
    node = layout["provider_node"]
    require(node in SHARED["CANDIDATES"] and selected["transport"] == "mptcp"
            and selected["route_context_id"] == layout["route_context_id"]
            and len(paths) == len(slots) == 2
            and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [p["relay_peer_id"] for p in paths] == [s["relay_peer_id"] for s in slots]
            and peers[node] not in {peers["client"], peers["exit"], layout["control_relay_peer_id"]}
                | {p["relay_peer_id"] for p in paths}, "independent provider/protected original route missing")
    relays = [slot["relay_node"] for slot in slots]
    require(len(set(relays)) == 2 and all(r in ROLES[1:4] for r in relays)
            and all(peers[s["relay_node"]] == s["relay_peer_id"] for s in slots)
            and set(privacy) == set(ROLES), "selected relay/capture identities differ")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and capture["unexpected_provider_application_packets"] == 0
                and set(capture["provider_application"]) == set(SHARED["CANDIDATES"]),
                "unexpected provider or physical-path traffic")
        SHARED["validate_drained"](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != "exit":
            require(all(value == 0 for counters in capture["provider_application"].values()
                        for value in counters.values()), "private storage bypassed the Exit")
    require(privacy["client"]["direct_client_exit_packets"] == 0
            and privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == 0
            and privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[r]["internet_destination_outer_packets"] == 0 for r in ROLES[1:4]),
            "Client/Relay/Exit privacy boundary violated")
    for relay in relays:
        require(privacy[relay]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[relay]["exit_leg_wireguard_data_datagrams"] > 16,
                "selected WireGuard legs did not carry real data")
    for candidate, counters in privacy["exit"]["provider_application"].items():
        if candidate == node:
            require(counters["request_packets"] > 0 and counters["response_packets"] > 0
                    and counters["response_payload_bytes"] >= 2 * BYTES,
                    "two actual provider restores missing from physical capture")
        else:
            require(all(value == 0 for value in counters.values()), "unselected provider carried private storage")
    control = next(n for n in SHARED["PUBLIC_IPS"] if peers[n] == layout["control_relay_peer_id"])
    SHARED["validate_control"](phase["control_privacy"], control, layout["control_provider_nodes"], True)
    require(phase["gates"]["event_baseline_unix_ms"] > 0
            and phase["gates"]["exit_mptcp_tls_completed"] >= 16,
            "actual protected operation completions missing")


def build_evidence(work):
    evidence = {name: read(work / f"private-storage-peer-{name}.json") for name in
                ("prepare", "upload", "download", "reopen", "deleted_usage", "private_cleanup", "isolation", "layout")}
    evidence.update(success=True, expected_peers=read(work / "a01-expected-peers.json"),
                    **dict.fromkeys(SCOPE_FALSE, False))
    evidence["network"] = dict(selected_route=read(work / "private-storage-peer-live-selection.json"),
        privacy={role: read(work / f"private-storage-peer-privacy-{role}.json") for role in ROLES},
        control_privacy=read(work / "content-provider-private-storage-control.json"),
        gates=read(work / "private-storage-peer-gates.json"))
    validate_evidence(evidence)
    return evidence


def validate_report(report, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report["source_revision"] == revision
            and report["schema_version"] == 1 and report["report_kind"] == "volparossa-private-storage-peer"
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["phase"] == "private-storage-peer-complete" and report["observed_blocker"] is None
            and report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
            and report["host_state"]["unchanged"] is True, "source-bound cleanup report incomplete")
    validate_evidence(report["storage"])


def main(arguments):
    command = arguments[0]
    if command == "prepare" and len(arguments) == 6:
        result = prepare(private_root(arguments[1]), *arguments[2:])
    elif command in ("upload", "download") and len(arguments) == 5:
        result = globals()[command](private_root(arguments[1]), *arguments[2:])
    elif command == "cleanup" and len(arguments) == 2:
        result = cleanup(arguments[1])
    elif command == "evidence" and len(arguments) == 3:
        result = build_evidence(Path(arguments[1]))
        Path(arguments[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif command == "report" and len(arguments) == 3:
        validate_report(read(Path(arguments[1])), arguments[2])
        result = dict(success=True, report_kind="volparossa-private-storage-peer")
    else:
        raise ValueError("unknown private storage fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("private storage fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError):
        # Private process output/paths/keys must not reach exported runner logs.
        print("private storage fixture failed; private diagnostics not exported", file=sys.stderr)
        sys.exit(1)
