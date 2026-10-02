#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Separate native Signal fragment trial; never reinterpret the historical replica proof."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys

HERE = Path(__file__).resolve().parent
NATIVE = runpy.run_path(str(HERE / "signal-backup-smoke.py"))
FRAGMENTS = runpy.run_path(str(HERE / "private-storage-fragments-smoke.py"))
read, require, private_file, create, invoke, unlock = (
    NATIVE[name] for name in ("read", "require", "private_file", "create", "invoke", "unlock"))
NAME = "signal-backup-fragments"
CAPACITY = 1048576
FRAGMENT_LIMIT = 262144
PHASES = dict(upload=32, restore=16, finish=16)
FALSE_SCOPE = (*NATIVE["FALSE_SCOPE"], "automatic_repair", "erasure_coding")
SUMMARY = ("smoke", "evidence", "prepare", "native", "uploaded", "restore", "finish",
           "withdrawal", "uploaded_usage", "restored_usage", "deleted_usage", "isolation", "layout", "guard")
EXPORT_NAMES = ("a01-expected-peers.json", "signal-backup-private_cleanup.json",
    *(f"{NAME}-{name}.json" for name in SUMMARY), *(name for phase in PHASES for name in (
        f"private-storage-fragments-{phase}-live-selection.json",
        f"private-storage-fragments-{phase}-gates.json",
        f"content-provider-adaptive-private-storage-fragments-{phase}-control.json",
        *(f"private-storage-fragments-{phase}-privacy-{role}.json" for role in NATIVE["ROLES"]))))


def chat_revision():
    value = read(HERE / "signal-backup-fragments-pins.json")
    revision = value["chat_revision"]
    require(value["version"] == 1 and re.fullmatch(r"[0-9a-f]{40}", revision)
            and revision != "0" * 40, "reviewed fragment source pin required")
    return revision


def geometry(size):
    require(type(size) is int and 3 < size <= 4 * FRAGMENT_LIMIT, "bounded native ciphertext required")
    chunk = min(FRAGMENT_LIMIT, size // 3)
    lengths = tuple(min(chunk, size - offset) for offset in range(0, size, chunk))
    # This particular trial proves the same four-fragment geometry as the actual
    # native archive. Different geometry needs an explicitly reviewed trial, not
    # silently relaxed peer traffic/accounting expectations.
    require(len(lengths) == 4, "native trial requires four actual fragments")
    counts, charges = [0, 0, 0], [0, 0, 0]
    for index, length in enumerate(lengths):
        for copy in range(2):
            provider = (index + copy) % 3
            counts[provider] += 1
            charges[provider] += length
    return chunk, lengths, counts, charges


def configure_geometry(size):
    chunk, lengths, counts, charges = geometry(size)
    # Isolated runpy namespace: never mutate the historical fixture's process.
    FRAGMENTS["validate_cli"].__globals__.update(BYTES=size, CHUNK=chunk, LENGTHS=lengths,
        PROVIDER_LEASES=tuple(counts), PROVIDER_BYTES=tuple(charges), PHASES=PHASES)
    return lengths, counts, charges


def descriptor(root):
    path = root / "backup/recovery.json"
    require(private_file(path).st_size <= 4096, "bounded owner recovery descriptor required")
    value = read(path)
    keys = [provider["key"] for provider in read(root / "config.json")["providers"]]
    require(value["version"] == 2 and value["storage"] == dict(kind="fragments", providerKeys=keys)
        and len(keys) == len(set(keys)) == 3 and all(re.fullmatch(r"[0-9a-f]{64}", key) for key in keys)
        and re.fullmatch(r"[0-9a-f]{64}", value["ciphertextSha256"]), "native fragment descriptor differs")
    configure_geometry(value["ciphertextBytes"])
    return value, keys


def existing(root):
    return ["--state", root / "backup/fragments", *unlock(root)]


def identity_digest(root):
    state = root / "backup/fragments"
    manifest = state / "fragments.json"
    require(private_file(manifest).st_size <= 1048576, "bounded signed fragment manifest required")
    result = hashlib.sha256(manifest.read_bytes())
    for index in range(4):
        for copy in range(2):
            path = state / f"fragment-{index:04}/copy-{copy}/archive.json"
            require(private_file(path).st_size <= 16384, "bounded owner copy journal required")
            value = read(path)
            require(value["lease"] is not None, "copy lacks an acknowledged lease")
            result.update(json.dumps({key: value[key] for key in ("provider_key", "owner_key", "grant_hex",
                "archive_id", "ciphertext_bytes", "sha256", "lease")}, sort_keys=True).encode())
    return result.digest()


def same_identity(root):
    private_file(root / "identities.sha256")
    require((root / "identities.sha256").read_bytes() == identity_digest(root),
            "signed manifest or original provider/owner/grant/archive/lease changed")


def prepare(root, binary, client, *providers):
    require(len(providers) == 6 and not list(root.iterdir()), "new private owner and three providers required")
    controls, keys = providers[:3], providers[3:]
    require(len(set(keys)) == 3, "distinct providers required")
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner not in keys, "distinct owner required")
    grants = []
    for label, control, key in zip("abc", controls, keys):
        grant = root / f"grant-{label}.bin"
        result = invoke(binary, control, ["storage", "peer", "grant", "--provider-key", key,
            "--owner-key", owner, "--max-payload-bytes", CAPACITY, "--max-leases", 4,
            "--max-retention-seconds", 7200, "--lifetime-seconds", 7200, "--output", grant])
        require(result["grant_written"] is True and result["max_payload_bytes"] == CAPACITY
            and result["max_leases"] == 4 and result["reserved_bytes"] == 0
            and result["network_contribution_credit"] is False, "real bounded fragment grant missing")
        grants.append(dict(key=key, grant=str(grant)))
    create(root / "config.json", json.dumps(dict(executable=binary, controlSocket=client,
        identity=str(root / "identity.key"), passphraseFile=str(root / "passphrase"), providers=grants,
        lifetimeSeconds=1800, fragmentBytes=FRAGMENT_LIMIT)).encode())
    for name in ("backup", "tmp", "config", "cache", "data", "runtime"):
        (root / name).mkdir(mode=0o700)
    return dict(providers=3, grant_max_leases_each=4, grant_payload_bytes_each=CAPACITY,
                owner_distinct_from_all_providers=True, owner_secrets_exported=False)


def uploaded(root, binary, client):
    value, keys = descriptor(root)
    marker = root / "backup/withdrawal-ready.json"
    require(private_file(marker).st_size <= 256
            and read(marker) == dict(version=1, ready=True, provider_key=keys[0]),
            "native export rendezvous missing")
    require(not (root / "backup/archive.signal").exists(), "original ciphertext must be removed")
    result = invoke(binary, client, ["storage", "fragments", "progress", *existing(root)], deadline=900)
    FRAGMENTS["validate_cli"](result, "progress", keys, "committed")
    create(root / "identities.sha256", identity_digest(root))
    size = value["ciphertextBytes"]
    lengths, counts, charges = configure_geometry(size)
    return dict(logical_ciphertext_bytes=size, fragment_lengths=list(lengths), fragment_count=4,
        copies_per_fragment=2, committed_fragment_copies=8, provider_leases=counts,
        provider_payload_bytes=charges, physical_payload_charge=2 * size,
        owner_signature_verified=True, source_removed_before_restore=True,
        native_export_rendezvous_observed=True)


def confirm_withdrawal(root):
    # The privileged harness invokes this only after actual stop/status + usage
    # proofs. The application is waiting; this marker itself is NOT stop proof.
    _, keys = descriptor(root)
    marker = root / "backup/withdrawal-ready.json"
    require(private_file(marker).st_size <= 256
            and read(marker) == dict(version=1, ready=True, provider_key=keys[0]),
            "native ready marker differs")
    target = root / "backup/withdrawal-confirmed.json"
    if target.exists() or target.is_symlink():
        raise FileExistsError("withdrawal confirmation already exists")
    temporary = root / "backup/.withdrawal-confirmed.part"
    create(temporary, json.dumps(dict(version=1, provider_stopped=True, provider_key=keys[0])).encode())
    # Only this harness writes confirmation in the exact owner-private fixture;
    # publish a complete file so the app's strict reader never sees partial JSON.
    temporary.rename(target)
    return dict(confirmation_written=True)


def restore(root, binary, client):
    value, keys = descriptor(root)
    require(not (root / "backup/archive.signal").exists(), "original ciphertext remains")
    same_identity(root)
    output = root / "second-restore.signal"
    result = FRAGMENTS["restore_invoke"](binary, client,
        ["storage", "fragments", "restore", *existing(root), "--output", output], deadline=900)
    FRAGMENTS["validate_restore_result"](result, keys)
    require(private_file(output).st_size == value["ciphertextBytes"]
        and NATIVE["digest"](output) == value["ciphertextSha256"], "second restoration differs")
    same_identity(root)
    output.unlink()
    return dict(second_core_restore=True, native_import_already_completed=True,
        fragment_provider_indexes=[1, 1, 2, 1], whole_archive_sha256_verified=True,
        reads_nonconsuming=True, retained_identity_unchanged=True, ciphertext_removed=True)


def finish(root, binary, client):
    value, keys = descriptor(root)
    same_identity(root)
    for operation, phase in (("progress", "committed"), ("delete", "deleted")):
        result = invoke(binary, client, ["storage", "fragments", operation, *existing(root)], deadline=900)
        FRAGMENTS["validate_cli"](result, operation, keys, phase)
    return dict(logical_ciphertext_bytes=value["ciphertextBytes"], all_eight_fragment_copies_deleted=True,
                final_payload_charge=0)


def validate_evidence(value, revision=None):
    require(value["success"] is True and all(value[field] is False for field in FALSE_SCOPE), "scope overstated")
    native = value["native"]
    NATIVE["validate_mocha"](native["native_test"])
    require(native["chat_revision"] == (revision or chat_revision())
        and native["signal_revision"] == NATIVE["SIGNAL"] and len(native["compiled_runtime_sha256"]) == 7
        and all(re.fullmatch(r"[0-9a-f]{64}", sha) for sha in native["compiled_runtime_sha256"].values())
        and all(re.fullmatch(r"[0-9a-f]{64}", native[name]) for name in ("node_sha256", "compile_receipt_sha256"))
        and all(native[field] is True for field in ("native_encrypted_export_import", "original_ciphertext_removed",
            "upstream_messages_attachments_screenshots_verified", "registration_and_relink_mock_server_required",
            "application_egress_loopback_only", "loopback_ipv4_ipv6_verified", "capless_app",
            "control_group_socket_verified", "native_process_group_joined"))
        and native["private_logs_exported"] is False, "native export/import or exact source proof missing")
    require(value["prepare"] == dict(providers=3, grant_max_leases_each=4, grant_payload_bytes_each=CAPACITY,
        owner_distinct_from_all_providers=True, owner_secrets_exported=False), "real provider grants missing")
    uploaded = value["uploaded"]
    size = uploaded["logical_ciphertext_bytes"]
    lengths, counts, charges = configure_geometry(size)
    require(uploaded == dict(logical_ciphertext_bytes=size, fragment_lengths=list(lengths), fragment_count=4,
        copies_per_fragment=2, committed_fragment_copies=8, provider_leases=counts, provider_payload_bytes=charges,
        physical_payload_charge=2 * size, owner_signature_verified=True, source_removed_before_restore=True,
        native_export_rendezvous_observed=True), "native fragment deposition proof missing")
    require(value["restore"] == dict(second_core_restore=True, native_import_already_completed=True,
        fragment_provider_indexes=[1, 1, 2, 1], whole_archive_sha256_verified=True, reads_nonconsuming=True,
        retained_identity_unchanged=True, ciphertext_removed=True), "survivor-only repeat restore missing")
    require(value["finish"] == dict(logical_ciphertext_bytes=size, all_eight_fragment_copies_deleted=True,
        final_payload_charge=0), "all-copy retirement missing")
    usage = [dict(reserved_bytes=0, committed_bytes=charge, leases=count) for count, charge in zip(counts, charges)]
    require(value["uploaded_usage"] == value["restored_usage"] == usage
        and value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
        "provider physical quota or nonconsuming retention differs")
    require(value["withdrawal"] == dict(first_provider_stopped_before_confirmation=True,
        native_ready_provider_matches_first=True, first_store_retained=True, other_two_providers_serving=True,
        same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True), "actual provider withdrawal proof missing")
    require(value["private_cleanup"] == dict(owner_identity_removed=True, recovery_keys_removed=True,
        grants_removed=True, profiles_logs_plaintext_removed=True, user_directory_removed=True), "private cleanup missing")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
        and isolation["control_gid"] != isolation["agent_gid"]
        and all(isolation[field] is True for field in ("agent_cannot_read_user_state",
            "client_cannot_read_any_provider_store", "agent_mount_positive_control",
            "all_provider_keys_match_independent_fixture_peers", "three_provider_namespaces_distinct")),
        "three independent namespace providers or owner isolation missing")
    require(value["guard"]["app_uid"] == isolation["user_uid"] and value["guard"]["blocked_packets"] > 0
        and value["guard"]["loopback_ipv4_ipv6_only"] is True, "application network guard missing")
    require(set(value["network"]) == set(PHASES), "three complete packet-evidence phases required")
    for phase in PHASES:
        FRAGMENTS["validate_network"](value["network"][phase], value["expected_peers"], value["layout"], phase)


def evidence(work):
    value = {name: read(work / f"{NAME}-{name}.json") for name in
        ("prepare", "native", "uploaded", "restore", "finish", "withdrawal", "isolation", "layout", "guard")}
    value.update(success=True, expected_peers=read(work / "a01-expected-peers.json"),
        private_cleanup=read(work / "signal-backup-private_cleanup.json"), **dict.fromkeys(FALSE_SCOPE, False))
    for name in ("uploaded_usage", "restored_usage", "deleted_usage"):
        value[name] = FRAGMENTS["read_usage"](work / f"{NAME}-{name}.json")
    value["network"] = {phase: dict(
        selected_route=read(work / f"private-storage-fragments-{phase}-live-selection.json"),
        privacy={role: read(work / f"private-storage-fragments-{phase}-privacy-{role}.json") for role in NATIVE["ROLES"]},
        control_privacy=read(work / f"content-provider-adaptive-private-storage-fragments-{phase}-control.json"),
        gates=read(work / f"private-storage-fragments-{phase}-gates.json")) for phase in PHASES}
    validate_evidence(value)
    return value


def validate_report(value, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision
        and value["schema_version"] == 1 and value["report_kind"] == "volparossa-signal-backup-fragments"
        and value["success"] is True and value["runner_exit_status"] == 0
        and value["phase"] == "signal-backup-fragments-complete" and value["observed_blocker"] is None
        and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
        and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"],
        "exact-source/host/cleanup proof missing")
    validate_evidence(value["backup"])


def main(args):
    command = args[0]
    if command == "export-names" and len(args) == 1:
        print("\n".join(EXPORT_NAMES)); return
    if command == "prepare" and len(args) == 10:
        result = prepare(NATIVE["owner_root"](args[1]), *args[2:])
    elif command in ("uploaded", "restore", "finish") and len(args) == 4:
        result = globals()[command](NATIVE["owner_root"](args[1]), *args[2:])
    elif command == "confirm-withdrawal" and len(args) == 2:
        result = confirm_withdrawal(NATIVE["owner_root"](args[1]))
    elif command == "native" and len(args) == 2:
        result = NATIVE["run_native"](NATIVE["owner_root"](args[1]), expected_chat=chat_revision(), withdrawal=True)
    elif command == "evidence" and len(args) == 3:
        result = evidence(Path(args[1])); Path(args[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif command == "report" and len(args) == 3:
        validate_report(read(Path(args[1])), args[2]); result = dict(success=True, report_kind="volparossa-signal-backup-fragments")
    else:
        raise ValueError("unknown native fragment fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("native Signal fragment fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError) as error:
        state = NATIVE["run_native"].__globals__
        print(json.dumps(dict(success=False, failure_stage=state["STAGE"],
            native_exit_status=state["NATIVE_EXIT"], error=NATIVE["closed_error"](error),
            native_diagnostic=state["NATIVE_DIAGNOSTIC"])))
        print("native Signal fragment trial failed; private diagnostics withheld", file=sys.stderr)
        sys.exit(1)
