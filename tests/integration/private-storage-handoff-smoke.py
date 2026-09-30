#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real owner-driven A/B -> B/C CLI handoff; synthetic opaque transport bytes only.

The existing two-provider fixture keeps its historical meaning. This separate
scenario observes a stopped A, pending three-copy charge, exact retry, and reads
from both survivors. It does not prove encryption, independent hardware or repair.
"""

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
import time

BASE = runpy.run_path(str(Path(__file__).with_name("private-storage-replicas-smoke.py")))
NET = BASE["NET"]
read, require, ROLES = BASE["read"], BASE["require"], BASE["ROLES"]
private_root, private_file, create = BASE["private_root"], BASE["private_file"], BASE["create"]
invoke, existing, unlock = BASE["invoke"], BASE["existing"], BASE["unlock"]
BYTES, SHA = BASE["BYTES"], BASE["SHA"]
NODES = ("relay4", "relay5", "relay3")  # A, unchanged B, replacement C.
PHASES = dict(upload=18, pending=10, complete=7, restore_b=4, restore_c=4, finish=4)
SCOPE_FALSE = (*BASE["SCOPE_FALSE"], "automatic_contribution_resize")
SUMMARY_NAMES = ("smoke", "evidence", "prepare", *PHASES, "withdrawal", "isolation", "layout",
                 "pending_usage", "complete_usage", "deleted_usage", "private_cleanup")
EXPORT_NAMES = ("a01-expected-peers.json", *(f"private-storage-handoff-{name}.json" for name in SUMMARY_NAMES),
    *(name for phase in PHASES for name in (
        f"private-storage-handoff-{phase}-live-selection.json",
        f"private-storage-handoff-{phase}-gates.json",
        f"content-provider-adaptive-private-storage-handoff-{phase}-control.json",
        *(f"private-storage-handoff-{phase}-privacy-{role}.json" for role in ROLES))))
FILES = BASE["FILES"] | {"grant-c.bin", "handoff-identities.sha256",
    "restore-b1.bin", "restore-b2.bin", "restore-c1.bin", "restore-c2.bin"}


def read_usage(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2048,
            "provider usage evidence missing or too large")
    values = json.loads(path.read_text())
    require(isinstance(values, list) and len(values) == 3, "expected exactly three real stores")
    for value in values:
        require(isinstance(value, dict) and set(value) == {"reserved_bytes", "committed_bytes", "leases"}
                and all(type(number) is int and 0 <= number <= (1 << 64) - 1 for number in value.values()),
                "invalid bounded store usage")
    return values


def prepare(root, binary, client, provider_a, provider_b, provider_c, key_a, key_b, key_c):
    require(len({key_a, key_b, key_c}) == 3, "provider identities must be distinct")
    result = BASE["prepare"](root, binary, client, provider_a, provider_b, key_a, key_b)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(owner != key_c, "replacement provider is the owner")
    grant = invoke(binary, provider_c, ["storage", "peer", "grant", "--provider-key", key_c,
        "--owner-key", owner, "--max-payload-bytes", BYTES, "--max-leases", 1,
        "--max-retention-seconds", 7200, "--lifetime-seconds", 7200, "--output", root / "grant-c.bin"])
    require(grant["grant_written"] is True and grant["max_payload_bytes"] == BYTES
            and grant["max_leases"] == 1 and grant["reserved_bytes"] == 0
            and grant["network_contribution_credit"] is False, "replacement grant was not independently issued")
    result.pop("owner_distinct_from_both_providers")
    result.update(providers=3, owner_distinct_from_all_providers=True)
    return result


def identity_digest(root):
    values = []
    for index in range(3):
        path = root / f"replica-set/copy-{index}/archive.json"
        require(private_file(path).st_size <= 16384, "private journal too large")
        value = json.loads(path.read_text())
        require(value["lease"] is not None, "replacement lease is not acknowledged")
        values.append({key: value[key] for key in ("provider_key", "owner_key", "grant_hex",
            "archive_id", "ciphertext_bytes", "sha256", "lease")})
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).digest()


def check_identity(root):
    BASE["check_identity"](root)
    private_file(root / "handoff-identities.sha256")
    require(identity_digest(root) == (root / "handoff-identities.sha256").read_bytes(),
            "handoff retry changed immutable owner/provider/archive/lease identities")


def validate_cli(value, operation, keys, charges, complete=True):
    require(value["operation"] == "private_storage_replicas_" + operation
            and value["logical_ciphertext_bytes"] == BYTES and value["distinct_provider_identities"] == 3
            and [copy["provider_key"] for copy in value["copies"]] == list(keys)
            and [copy["charge"] for copy in value["copies"]] == list(charges)
            and value["read_consumes_archive"] is False and value["expired_copies_remain_charged"] is True
            and value.get("operation_complete", True) is complete
            and all(value[field] is False for field in ("metadata_overhead_measured",
                "independent_failure_domains_proven", "network_contribution_credit", "automatic_repair")),
            "handoff receipt/accounting scope differs")
    for category in ("reserved", "committed", "uncertain"):
        require(value[category + "_payload_bytes"] == charges.count(category) * BYTES,
                "per-provider charged bytes differ")
    require(value["physical_payload_charge_upper_bound"] ==
            sum(charge not in ("deleted", "unattempted") for charge in charges) * BYTES,
            "uncertain physical storage was not fully charged")
    for copy, charge in zip(value["copies"], charges):
        require(copy["last_confirmed_stored_bytes"] == (0 if charge == "deleted" else BYTES)
                and (copy["last_confirmed_expiry"] == 0 if charge == "deleted" else
                     copy["last_confirmed_expiry"] > int(time.time())), "copy is missing or lease expired")
    handoff = value["handoff"]
    require(handoff["from_provider_key"] == keys[0] and handoff["replacement_provider_key"] == keys[2]
            and handoff["replacement_readback_required_before_source_delete"] is True
            and handoff["automatic_contribution_resize"] is False, "exact owner handoff intent changed")


def staged_files_absent(root):
    require(not any(path.name.startswith((".handoff-transfer-", ".handoff-journal-"))
                    for path in (root / "replica-set").iterdir()), "temporary ciphertext handoff staging remains")


def replace(root, binary, client, keys, pending):
    require(not (root / "input.bin").exists(), "original input was not removed")
    BASE["check_identity"](root)
    arguments = [binary, "--control-socket", client, "storage", "replicas", "replace", *map(str, existing(root)),
        "--from-provider-key", keys[0], "--provider-key", keys[2], "--grant", str(root / "grant-c.bin"),
        "--lifetime-seconds", "3600"]
    # At most eleven sequential 120s exchanges on this three-chunk fixture; no
    # product deadline is widened. Partial replacement intentionally returns JSON
    # plus exit 1, unlike the existing no-clobber failure which emits no success JSON.
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=1440)
        require(process.returncode == (1 if pending else 0) and len(stdout) <= 16384 and len(stderr) <= 16384,
                "replacement did not reach its expected terminal state")
        value = json.loads(stdout)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    validate_cli(value, "replace", keys, ("uncertain" if pending else "deleted", "committed", "committed"), not pending)
    require(value["handoff_stage"] == ("source_delete_unconfirmed" if pending else "complete")
            and value["handoff"]["phase"] == ("delete_pending" if pending else "complete")
            and value["pending_handoff"] is pending and value["automatic_contribution_resize"] is False,
            "replacement skipped verified copy or misreported source deletion")
    staged_files_absent(root)
    if pending:
        create(root / "handoff-identities.sha256", identity_digest(root))
    check_identity(root)
    return dict(source_absent=True, original_survivor_identity_unchanged=True,
        replacement_full_readback_verified=True, live_lease_expiry_checked=True, staging_removed=True,
        source_delete_confirmed=not pending, source_delete_uncertain=pending,
        physical_payload_charge=(3 if pending else 2) * BYTES,
        exact_retry_same_three_identities=True)


def restore(root, binary, client, keys, selected):
    require(not (root / "input.bin").exists(), "source unexpectedly recreated")
    charges = ("deleted", "committed" if selected == 1 else "uncertain", "committed")
    outcomes = ["explicitly_deleted", "restored_and_retained"] if selected == 1 else [
        "explicitly_deleted", "unavailable_or_restore_unverified", "restored_and_retained"]
    for number in (1, 2):
        path = root / f"restore-{'b' if selected == 1 else 'c'}{number}.bin"
        value = invoke(binary, client, ["storage", "replicas", "restore", *existing(root), "--output", path], deadline=420)
        validate_cli(value, "restore", keys, charges)
        require(value["restored"] is True and value["restored_from_provider_key"] == keys[selected]
                and value["copy_outcomes"] == outcomes, "restore did not use the expected real provider")
        require(private_file(path).st_size == BYTES and hashlib.sha256(path.read_bytes()).hexdigest() == SHA,
                "full restored ciphertext differs")
        check_identity(root)
    staged_files_absent(root)
    return dict(restores=2, selected_provider="B" if selected == 1 else "C", source_absent=True,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, physical_payload_charge=2 * BYTES,
        original_and_replacement_identities_retained=True, staging_removed=True)


def finish(root, binary, client, key_a, key_b, key_c):
    keys = (key_a, key_b, key_c)
    validate_cli(invoke(binary, client, ["storage", "replicas", "progress", *existing(root)]),
                 "progress", keys, ("deleted", "committed", "committed"))
    for key, charges in ((key_b, ("deleted", "deleted", "committed")), (key_c, ("deleted",) * 3)):
        for _ in range(2):
            validate_cli(invoke(binary, client, ["storage", "replicas", "delete", *existing(root), "--provider-key", key]),
                         "delete", keys, charges)
            check_identity(root)
    staged_files_absent(root)
    return dict(reopened_survivor_confirmed=True, exact_selected_deletions=True, delete_retry_idempotent=True,
                final_payload_charge=0, staging_removed=True)


def cleanup(path):
    root = private_root(path, missing=True)
    files, directories = [], []
    if root.exists():
        def visit(directory, depth):
            require(depth <= 3, "unexpected private directory depth")
            entries = list(directory.iterdir())
            require(len(entries) <= 24, "private cleanup entry bound exceeded")
            for child in entries:
                info = child.lstat()
                if stat.S_ISDIR(info.st_mode):
                    allowed = ((depth == 0 and (child.name == "replica-set" or re.fullmatch(r"\.replicas-[A-Za-z0-9]+", child.name)))
                        or (depth == 1 and (child.name in ("copy-0", "copy-1", "copy-2")
                            or re.fullmatch(r"\.handoff-(transfer|journal)-[A-Za-z0-9]+", child.name))))
                    require(allowed and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
                            "unexpected private cleanup directory")
                    visit(child, depth + 1)
                    directories.append(child)
                else:
                    allowed = ((depth == 0 and child.name in FILES) or (depth == 1 and child.name == "replicas.json")
                        or (depth == 2 and child.name in ("archive.json", "survivor-1"))
                        or re.fullmatch(r"\.tmp[A-Za-z0-9]+", child.name))
                    require(allowed, "unexpected private cleanup file")
                    private_file(child)  # rejects symlinks, hardlinks and wrong owner before any deletion
                    files.append(child)
        visit(root, 0)
        require(len(files) <= 40 and len(directories) <= 10, "private cleanup bound exceeded")
        for entry in files:
            entry.unlink()
        for entry in directories:
            entry.rmdir()
        root.rmdir()
    return dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
                replica_metadata_removed=True, input_and_outputs_removed=True, handoff_staging_removed=True,
                user_directory_removed=True)


def validate_network(phase, peers, layout, name):
    selected, privacy = phase["selected_route"], phase["privacy"]
    paths, slots, nodes = selected["paths"], selected["benchmark_slots"], layout["provider_nodes"]
    require(nodes == list(NODES) and len({peers[node] for node in nodes}) == 3
            and layout["control_relay_peer_id"] in {peers[node] for node in ROLES[1:4]},
            "three providers or ordinary control relay changed")
    require(selected["transport"] == "mptcp" and selected["route_context_id"] == layout["route_context_id"]
            and len(paths) == len(slots) == 2 and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [p["relay_peer_id"] for p in paths] == [s["relay_peer_id"] for s in slots],
            "protected MPTCP route changed")
    forbidden = {peers["client"], peers["exit"], layout["control_relay_peer_id"]} | {p["relay_peer_id"] for p in paths}
    require(all(peers[node] not in forbidden for node in nodes), "provider overlaps a protected route role")
    relays = [slot["relay_node"] for slot in slots]
    require(len(set(relays)) == 2 and all(r in ROLES[1:4] for r in relays)
            and all(peers[s["relay_node"]] == s["relay_peer_id"] for s in slots)
            and set(privacy) == set(ROLES), "physical role capture mismatch")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == capture["unexpected_provider_application_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and set(capture["provider_application"]) == set(NODES), "unexpected application egress")
        NET["validate_drained"](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != "exit":
            require(all(n == 0 for values in capture["provider_application"].values() for n in values.values()),
                    "provider storage bypassed Exit")
    require(privacy["client"]["direct_client_exit_packets"] == privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[r]["internet_destination_outer_packets"] == 0 for r in ROLES[1:4]), "privacy boundary violated")
    for relay in relays:
        require(privacy[relay]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[relay]["exit_leg_wireguard_data_datagrams"] > 16, "real two-leg traffic missing")
    active = {"upload": NODES[:2], "pending": NODES[1:], "complete": NODES,
              "restore_b": (NODES[1],), "restore_c": (NODES[2],), "finish": NODES[1:]}[name]
    app = privacy["exit"]["provider_application"]
    for node in NODES:
        if node in active:
            require(app[node]["request_packets"] > 0 and app[node]["response_packets"] > 0,
                    "active provider did not exchange real protected traffic")
        else:
            require(app[node]["response_payload_bytes"] == 0, "stopped or untouched provider returned payload")
    for node, copies in {"pending": {NODES[1]: 1, NODES[2]: 1},
                         "complete": {NODES[1]: 1, NODES[2]: 1},
                         "restore_b": {NODES[1]: 2}, "restore_c": {NODES[2]: 2}}.get(name, {}).items():
        require(app[node]["response_payload_bytes"] >= copies * BYTES, "full survivor or replacement readback absent")
    control = phase["control_privacy"]
    control_node = next(node for node in ROLES[1:4] if peers[node] == layout["control_relay_peer_id"])
    pairs = {f"ac{i}": [NET["PUBLIC_IPS"][control_node], NET["PUBLIC_IPS"][node]]
             for i, node in enumerate(("relay3", "relay4", "relay5"))}
    require(control["capture_role"] == "content-control" and control["content_provider_mode"] is True
            and control["content_control_pairs"] == pairs and set(control["interfaces"]) == set(pairs)
            and set(control["content_control_packets"]) == set(pairs)
            and control["unexpected_provider_control_packets"] == control["unexpected_provider_application_packets"] == 0
            and set(control["provider_application"]) == set(NODES)
            and all(n == 0 for values in control["provider_application"].values() for n in values.values()),
            "control links carried forbidden application or unknown traffic")
    # Provider control may reuse cached authenticated discovery; an empty but
    # fully drained dedicated capture is valid, never unexpected control traffic.
    NET["validate_drained"](control, allow_empty=True)
    require(phase["gates"]["event_baseline_unix_ms"] > 0
            and phase["gates"]["exit_mptcp_tls_completed"] >= PHASES[name], "protected completion count incomplete")


def validate_evidence(value):
    require(value["success"] is True and all(value[field] is False for field in SCOPE_FALSE), "scope overstated")
    require(value["prepare"] == dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, providers=3,
        grant_max_leases_each=1, grant_payload_bytes_each=BYTES,
        owner_distinct_from_all_providers=True, owner_secrets_exported=False), "independent bounded grants missing")
    require(value["upload"] == dict(committed_copies=2, logical_ciphertext_bytes=BYTES, physical_payload_charge=2 * BYTES,
        chunks_per_copy=3, fresh_process_progress=True, committed_retry_same_identities=True,
        renewal_confirmed_by_progress=True, source_removed_before_restore=True), "initial A/B copies or removal missing")
    for name, pending in (("pending", True), ("complete", False)):
        require(value[name] == dict(source_absent=True, original_survivor_identity_unchanged=True,
            replacement_full_readback_verified=True, live_lease_expiry_checked=True, staging_removed=True,
            source_delete_confirmed=not pending, source_delete_uncertain=pending,
            physical_payload_charge=(3 if pending else 2) * BYTES, exact_retry_same_three_identities=True),
            "owner handoff or uncertainty accounting incomplete")
    for name, provider in (("restore_b", "B"), ("restore_c", "C")):
        require(value[name] == dict(restores=2, selected_provider=provider, source_absent=True,
            whole_archive_sha256_verified=True, reads_nonconsuming=True, physical_payload_charge=2 * BYTES,
            original_and_replacement_identities_retained=True, staging_removed=True), "survivor read proof missing")
    require(value["finish"] == dict(reopened_survivor_confirmed=True, exact_selected_deletions=True,
        delete_retry_idempotent=True, final_payload_charge=0, staging_removed=True), "final selected cleanup missing")
    require(value["withdrawal"] == dict(first_provider_stopped_before_replace=True, first_store_retained=True,
        same_first_store_reopened=True, first_provider_stopped_after_confirmed_delete=True,
        second_provider_stopped_before_replacement_restore=True, same_second_store_reopened=True,
        all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True,
        agent_restart_claimed=False), "actual provider withdrawal/reopen missing")
    full, empty = dict(reserved_bytes=0, committed_bytes=BYTES, leases=1), dict(reserved_bytes=0, committed_bytes=0, leases=0)
    require(value["pending_usage"] == [full, full, full] and value["complete_usage"] == [empty, full, full]
            and value["deleted_usage"] == [empty, empty, empty], "three-store physical usage did not follow exact deletion")
    require(value["private_cleanup"] == dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        replica_metadata_removed=True, input_and_outputs_removed=True, handoff_staging_removed=True,
        user_directory_removed=True), "owner ciphertext/key cleanup incomplete")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
            and isolation["control_gid"] != isolation["agent_gid"]
            and all(isolation[field] is True for field in ("agent_cannot_read_user_state",
                "client_cannot_read_any_provider_store", "agent_mount_positive_control",
                "all_provider_keys_match_independent_fixture_peers", "three_provider_namespaces_distinct")),
            "owner/provider isolation missing")
    require(set(value["network"]) == set(PHASES), "handoff network phase missing")
    for name, phase in value["network"].items():
        validate_network(phase, value["expected_peers"], value["layout"], name)


def build_evidence(work):
    value = {name: read(work / f"private-storage-handoff-{name}.json") for name in SUMMARY_NAMES
             if name not in ("smoke", "evidence", "pending_usage", "complete_usage", "deleted_usage")}
    for name in ("pending_usage", "complete_usage", "deleted_usage"):
        value[name] = read_usage(work / f"private-storage-handoff-{name}.json")
    value.update(success=True, expected_peers=read(work / "a01-expected-peers.json"), **dict.fromkeys(SCOPE_FALSE, False))
    value["network"] = {name: dict(selected_route=read(work / f"private-storage-handoff-{name}-live-selection.json"),
        privacy={role: read(work / f"private-storage-handoff-{name}-privacy-{role}.json") for role in ROLES},
        control_privacy=read(work / f"content-provider-adaptive-private-storage-handoff-{name}-control.json"),
        gates=read(work / f"private-storage-handoff-{name}-gates.json")) for name in PHASES}
    validate_evidence(value)
    return value


def validate_report(report, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report["source_revision"] == revision
            and report["schema_version"] == 1 and report["report_kind"] == "volparossa-private-storage-handoff"
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["phase"] == "private-storage-handoff-complete" and report["observed_blocker"] is None
            and report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
            and report["host_state"]["unchanged"] is True, "source-bound host/guest cleanup incomplete")
    validate_evidence(report["storage"])


def main(arguments):
    command = arguments[0]
    if command == "export-names" and len(arguments) == 1:
        print("\n".join(EXPORT_NAMES))
        return
    if command == "prepare" and len(arguments) == 10:
        result = prepare(private_root(arguments[1]), *arguments[2:])
    elif command == "upload" and len(arguments) == 6:
        result = BASE["upload"](private_root(arguments[1]), *arguments[2:])
    elif command in ("pending", "complete", "restore_b", "restore_c", "finish") and len(arguments) == 7:
        root, binary, client, *keys = private_root(arguments[1]), *arguments[2:]
        if command in ("pending", "complete"):
            result = replace(root, binary, client, keys, command == "pending")
        elif command in ("restore_b", "restore_c"):
            result = restore(root, binary, client, keys, 1 if command == "restore_b" else 2)
        else:
            result = finish(root, binary, client, *keys)
    elif command == "cleanup" and len(arguments) == 2:
        result = cleanup(arguments[1])
    elif command == "evidence" and len(arguments) == 3:
        result = build_evidence(Path(arguments[1]))
        Path(arguments[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif command == "report" and len(arguments) == 3:
        validate_report(read(Path(arguments[1])), arguments[2])
        result = dict(success=True, report_kind="volparossa-private-storage-handoff")
    else:
        raise ValueError("unknown handoff fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("private handoff fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError):
        print("private handoff fixture failed; private diagnostics not exported", file=sys.stderr)
        sys.exit(1)
