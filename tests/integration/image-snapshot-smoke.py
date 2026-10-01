#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real pinned Image encryption + Node CLI + core peers; synthetic private data only."""
import base64
import gzip
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

FRAGMENTS = runpy.run_path(str(Path(__file__).with_name("private-storage-fragments-smoke.py")))
require, read = FRAGMENTS["require"], FRAGMENTS["read"]
create, private_file = FRAGMENTS["create"], FRAGMENTS["private_file"]
invoke, unlock = FRAGMENTS["invoke"], FRAGMENTS["unlock"]
REVISION = "e177afebabd99ac0773de2a73d60275346a5de52"
SOURCE_HASHES = {
    "scripts/immich_snapshot.py": "23528a0737cd0a51e88b58a7f61079b3c6aa0f19b96a1f55757a9da49718256f",
    "scripts/snapshot-storage.mjs": "21a2cfe3527a958151be3ea0d7223f366a45d2fe18b09599dae217b83fcc8d4c",
    "src/core-storage.mjs": "5444e9b6e9926f63360ca9ade26bbc0484b5150ba9eb3ea453fc436f5a44d41b",
}
CHUNK = FRAGMENTS["CHUNK"]
SOURCE_FILES = {
    "database.sql.gz": gzip.compress(b"-- Synthetic isolated Image snapshot; no actual user data.\nSELECT 1;\n", mtime=0),
    "upload/synthetic.bin": bytes(range(256)) * (3 * CHUNK // 256) + b"I",
    "thumbs/synthetic.bin": b"VOLPAROSSA synthetic thumbnail fixture, not a user image.\n",
}
SOURCE_DIGESTS = {name: hashlib.sha256(data).hexdigest() for name, data in SOURCE_FILES.items()}
SOURCE_BYTES = sum(map(len, SOURCE_FILES.values()))
FALSE_CLAIMS = ("immich_server_restore_proven", "serverless_immich_proven", "mobile_sync_proven",
    "public_cache_used", "training_data_published", "automatic_placement", "automatic_repair",
    "automatic_contribution_resize", "network_contribution_credit", "independent_failure_domains_proven",
    "erasure_coding", "full_alpha_acceptance_claimed", "owner_secrets_exported")
EXPORT_NAMES = tuple(name for name in FRAGMENTS["EXPORT_NAMES"] if name not in (
    "private-storage-fragments-smoke.json", "private-storage-fragments-evidence.json")) + (
    "image-snapshot-smoke.json", "image-snapshot-evidence.json", "image-snapshot-provision.json")
STAGE = "not_started"


def owner_root(path, missing=False):
    root = Path(path)
    require(root.is_absolute() and root.name == "i" and root.parent != Path("/")
            and not root.is_symlink(), "invalid image owner root")
    if missing and not root.exists():
        return root
    info = root.lstat()
    require(root.resolve() == root and stat.S_ISDIR(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(), "private image owner root required")
    return root


def tools():
    source = Path(os.environ["IMAGE_SOURCE"])
    node = Path(os.environ["IMAGE_NODE"])
    require(source == Path("/opt/volparossa-image") and node == Path("/opt/volparossa-node/bin/node")
            and os.environ["IMAGE_REVISION"] == REVISION, "image provisioning identity differs")
    for name, digest in SOURCE_HASHES.items():
        path = source / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0
                and path.resolve() == path and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                "image source pin differs")
    info = node.lstat()
    runtime = json.loads(Path(__file__).with_name("image-snapshot-pins.json").read_text())["runtime"]["files"]["bin/node"]
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0
            and node.resolve() == node and info.st_size == runtime["bytes"], "image runtime differs")
    with node.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == runtime["sha256"], "image runtime hash differs")
    return source, node


def process_json(command, deadline=900, expected=0):
    # Product commands already own/join their subprocesses. This outer owner
    # supplies a bounded interrupt and never exports raw stdout/stderr on failure.
    process = subprocess.Popen(list(map(str, command)), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=deadline)
        require(len(stdout) <= 65536 and len(stderr) <= 16384 and process.returncode == expected,
                "image application command failed")
        return json.loads(stdout) if expected == 0 else None
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def snapshot(operation, *arguments):
    source, _ = tools()
    return process_json([sys.executable, "-B", source / "scripts/immich_snapshot.py", operation,
        *arguments, "--max-bytes", 2 * 1024 * 1024, "--timeout-seconds", 90], deadline=120)


def bridge(root, operation, *arguments, expected=0):
    source, node = tools()
    value = process_json([node, source / "scripts/snapshot-storage.mjs", operation,
        "--config", root / "storage.json", *arguments], expected=expected)
    if expected:
        return None
    require(value["version"] == 1 and value["operation"] == value["snapshot_operation"] == operation
        and value["status"] == "complete" and value["local_process_joined"] is True
        and value["remote_cleanup_confirmed"] is False
        and value["snapshot_decrypted"] is False and value["immich_restore_proven"] is False,
        "image bridge did not complete its real child")
    return value


def fixture(root):
    private_file(root / "fixture.json")
    value = read(root / "fixture.json")
    configure(value)
    return value


def configure(value):
    require(value["image_revision"] == REVISION and value["source_sha256"] == SOURCE_HASHES
        and value["plaintext_sha256"] == SOURCE_DIGESTS and value["plaintext_bytes"] == SOURCE_BYTES
        and re.fullmatch(r"[0-9a-f]{64}", value["cipher_sha256"]), "synthetic snapshot identity differs")
    FRAGMENTS["configure_payload_geometry"](value["ciphertext_bytes"])
    return FRAGMENTS["configure_payload_geometry"].__globals__


def verify_plain(root):
    require({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()} == set(SOURCE_FILES),
            "restored snapshot file inventory differs")
    for name, data in SOURCE_FILES.items():
        path = root / name
        require(private_file(path).st_size == len(data)
                and hashlib.sha256(path.read_bytes()).hexdigest() == SOURCE_DIGESTS[name],
                "restored snapshot plaintext differs")
    require(gzip.decompress((root / "database.sql.gz").read_bytes()) == gzip.decompress(SOURCE_FILES["database.sql.gz"]),
            "restored synthetic database dump differs")


def prepare(root, binary, client, provider_a, provider_b, provider_c, key_a, key_b, key_c):
    global STAGE
    STAGE = "prepare_plaintext"
    tools()
    keys = (key_a, key_b, key_c)
    require(not list(root.iterdir()) and len(set(keys)) == 3, "new owner and distinct providers required")
    (root / "source").mkdir(mode=0o700)
    for name, data in SOURCE_FILES.items():
        path = root / "source" / name
        path.parent.mkdir(mode=0o700, exist_ok=True)
        create(path, data)
    verify_plain(root / "source")
    STAGE = "encrypt_openpgp"
    receipt = snapshot("create", "--source", root / "source", "--output", root / "bundle", "--quiesced-copy")
    require(receipt["kind"] == "volparossa-immich-snapshot" and receipt["encryption"] == "OpenPGP-AES256"
        and receipt["source_consistency"] == "operator-asserted-quiesced-copy", "actual encrypted snapshot missing")
    ciphertext = root / "bundle/snapshot.pgp"
    require(private_file(ciphertext).st_size == receipt["cipher_bytes"]
        and hashlib.sha256(ciphertext.read_bytes()).hexdigest() == receipt["cipher_sha256"], "ciphertext receipt differs")
    value = dict(image_revision=REVISION, source_sha256=SOURCE_HASHES, plaintext_sha256=SOURCE_DIGESTS,
        plaintext_bytes=SOURCE_BYTES, ciphertext_bytes=receipt["cipher_bytes"], cipher_sha256=receipt["cipher_sha256"])
    geometry = configure(value)
    create(root / "fixture.json", json.dumps(value).encode())
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    STAGE = "owner_grants"
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner not in keys, "owner must be distinct")
    for index, (label, socket, key) in enumerate(zip("abc", (provider_a, provider_b, provider_c), keys)):
        grant = invoke(binary, socket, ["storage", "peer", "grant", "--provider-key", key,
            "--owner-key", owner, "--max-payload-bytes", geometry["PROVIDER_BYTES"][index],
            "--max-leases", geometry["PROVIDER_LEASES"][index], "--max-retention-seconds", 7200,
            "--lifetime-seconds", 7200, "--output", root / f"grant-{label}.bin"])
        require(grant["grant_written"] is True and grant["reserved_bytes"] == 0
            and grant["max_payload_bytes"] == geometry["PROVIDER_BYTES"][index]
            and grant["max_leases"] == geometry["PROVIDER_LEASES"][index]
            and grant["network_contribution_credit"] is False, "exact bounded grant absent")
    config = dict(version=1, coreBinary=binary, controlSocket=client, identity=str(root / "identity.key"),
        passphraseFile=str(root / "passphrase"), stateDirectory=str(root / "fragment-set"),
        providers=[dict(key=key, grant=str(root / f"grant-{label}.bin")) for label, key in zip("abc", keys)],
        copies=2, fragmentBytes=CHUNK, lifetimeSeconds=1800, deadlineMs=900000)
    create(root / "storage.json", json.dumps(config).encode())
    verify_plain(root / "source")
    return dict(**value, archive_encryption_proven=True, original_plaintext_preserved=True,
        owner_distinct_from_all_providers=True, grant_payload_bytes=list(geometry["PROVIDER_BYTES"]),
        grant_max_leases=list(geometry["PROVIDER_LEASES"]), owner_secrets_exported=False)


def raw_status(root, binary, client, keys, phase):
    value = invoke(binary, client, ["storage", "fragments", "status", "--state", root / "fragment-set"])
    FRAGMENTS["validate_cli"](value, "status", keys, phase)
    return value


def check_bridge(value, metadata, phase):
    storage = value["storage"]
    expected = 0 if phase in ("created", "deleted") else 2 * metadata["ciphertext_bytes"]
    require(storage["fragment_count"] == 4 and storage["copies_per_fragment"] == 2
        and storage["distinct_provider_identities"] == 3 and storage["owner_signature_verified"] is True
        and storage["logical_ciphertext_bytes"] == metadata["ciphertext_bytes"]
        and storage["physical_payload_charge_upper_bound"] == expected
        and storage["read_consumes_archive"] is False, "image fragment summary differs")


def upload(root, binary, client, keys):
    global STAGE
    metadata = fixture(root)
    STAGE = "image_create"
    check_bridge(bridge(root, "create", "--bundle", root / "bundle"), metadata, "created")
    raw_status(root, binary, client, keys, "created")
    STAGE = "image_deposit"
    check_bridge(bridge(root, "deposit", "--bundle", root / "bundle"), metadata, "committed")
    raw_status(root, binary, client, keys, "committed")
    create(root / "identities.sha256", FRAGMENTS["identity_digest"](root))
    for operation, arguments in (("progress", []), ("deposit", ["--bundle", root / "bundle"]),
            ("renew", ["--lifetime-seconds", 3600])):
        STAGE = "image_" + operation
        check_bridge(bridge(root, operation, *arguments), metadata, "committed")
        FRAGMENTS["check_identity"](root)
    raw_status(root, binary, client, keys, "committed")
    FRAGMENTS["staged_files_absent"](root)
    verify_plain(root / "source")
    private_file(root / "bundle/snapshot.pgp")
    (root / "bundle/snapshot.pgp").unlink()
    return dict(actual_image_cli=True, committed_fragment_copies=8,
        logical_ciphertext_bytes=metadata["ciphertext_bytes"], physical_payload_charge=2 * metadata["ciphertext_bytes"],
        committed_retry_same_identities=True, renewal_confirmed=True, source_ciphertext_removed=True,
        original_plaintext_preserved=True, temporary_transfer_files_removed=True)


def restore(root, binary, client, keys):
    global STAGE
    metadata = fixture(root)
    require(not (root / "bundle/snapshot.pgp").exists(), "original ciphertext remains")
    hashes = []
    for number in (1, 2):
        STAGE = f"image_restore_{number}"
        output = root / f"restore-{number}"
        value = bridge(root, "restore", "--receipt", root / "bundle/receipt.json", "--output", output)
        check_bridge(value, metadata, "restore")
        require(value["restore_verified"] is True and value["recovery_bundle_ready"] is True
            and value["snapshot_ciphertext_checked"] is True, "image restored bundle is not verified")
        raw_status(root, binary, client, keys, "restore")
        require(hashlib.sha256((output / "snapshot.pgp").read_bytes()).hexdigest() == metadata["cipher_sha256"],
                "restored ciphertext differs")
        private_file(root / "bundle/recovery.key")
        create(output / "recovery.key", (root / "bundle/recovery.key").read_bytes())
        STAGE = f"decrypt_verify_{number}"
        decrypted = snapshot("restore", "--bundle", output, "--output", root / f"plain-{number}",
                             "--expected-sha256", metadata["cipher_sha256"])
        require(decrypted["restored"] is True and decrypted["openpgp_integrity_verified"] is True
            and decrypted["manifest_verified"] is True and decrypted["bytes"] == SOURCE_BYTES,
            "actual authenticated GPG recovery failed")
        verify_plain(root / f"plain-{number}")
        verify_plain(root / "source")
        FRAGMENTS["check_identity"](root)
        hashes.append(dict(SOURCE_DIGESTS))
    STAGE = "existing_output"
    bridge(root, "restore", "--receipt", root / "bundle/receipt.json", "--output", root / "restore-1", expected=1)
    require(hashlib.sha256((root / "restore-1/snapshot.pgp").read_bytes()).hexdigest() == metadata["cipher_sha256"],
            "existing restored ciphertext was replaced")
    FRAGMENTS["staged_files_absent"](root)
    return dict(actual_image_cli=True, restores=2, actual_gpg_decryptions=2, plaintext_sha256=hashes,
        source_ciphertext_absent=True, original_plaintext_preserved=True, openpgp_integrity_verified=True,
        manifest_verified=True, whole_archive_sha256_verified=True, reads_nonconsuming=True,
        existing_output_preserved=True, retained_identity_unchanged=True,
        physical_payload_charge=2 * metadata["ciphertext_bytes"])


def finish(root, binary, client, keys):
    global STAGE
    metadata = fixture(root)
    STAGE = "image_finish"
    check_bridge(bridge(root, "progress"), metadata, "committed")
    raw_status(root, binary, client, keys, "committed")
    for _ in range(2):
        check_bridge(bridge(root, "delete"), metadata, "deleted")
        FRAGMENTS["check_identity"](root)
        raw_status(root, binary, client, keys, "deleted")
    FRAGMENTS["staged_files_absent"](root)
    verify_plain(root / "source")
    return dict(actual_image_cli=True, reopened_copies_confirmed=True, all_eight_copies_deleted=True,
        delete_retry_idempotent=True, original_plaintext_preserved=True, final_payload_charge=0)


def cleanup(path):
    root = owner_root(path, missing=True)
    if root.exists():
        entries = list(root.rglob("*"))
        require(len(entries) <= 128, "image cleanup entry bound exceeded")
        total = 0
        for entry in entries:
            info = entry.lstat()
            require(info.st_uid == os.geteuid() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                and info.st_mode & 0o077 == 0 and entry.resolve() == entry
                and len(entry.relative_to(root).parts) <= 5, "unexpected image cleanup entry")
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, "unexpected image cleanup linked file")
                total += info.st_size
        require(total <= 16 * 1024 * 1024, "image cleanup byte bound exceeded")
        for entry in sorted(entries, key=lambda p: len(p.parts), reverse=True):
            entry.rmdir() if entry.is_dir() else entry.unlink()
        root.rmdir()
    return dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        recovery_keys_removed=True, private_plaintext_removed=True, ciphertext_removed=True,
        fragment_journal_removed=True, user_directory_removed=True)


def build_evidence(work):
    names = ("prepare", "upload", "restore", "finish", "withdrawal", "isolation", "layout", "private_cleanup")
    value = {name: read(work / f"private-storage-fragments-{name}.json") for name in names}
    for name in ("uploaded_usage", "restored_usage", "deleted_usage"):
        value[name] = FRAGMENTS["read_usage"](work / f"private-storage-fragments-{name}.json")
    value.update(success=True, archive_encryption_proven=True, expected_peers=read(work / "a01-expected-peers.json"),
        provision=read(work / "image-snapshot-provision.json"), **dict.fromkeys(FALSE_CLAIMS, False))
    value["network"] = {name: dict(selected_route=read(work / f"private-storage-fragments-{name}-live-selection.json"),
        privacy={role: read(work / f"private-storage-fragments-{name}-privacy-{role}.json") for role in FRAGMENTS["ROLES"]},
        control_privacy=read(work / f"content-provider-adaptive-private-storage-fragments-{name}-control.json"),
        gates=read(work / f"private-storage-fragments-{name}-gates.json")) for name in FRAGMENTS["PHASES"]}
    validate_evidence(value)
    return value


def validate_evidence(value):
    require(value["success"] is True and value["archive_encryption_proven"] is True
        and all(value[field] is False for field in FALSE_CLAIMS), "image scope overstated")
    provision = value["provision"]
    pin_path = Path(__file__).with_name("image-snapshot-pins.json")
    pins = json.loads(pin_path.read_text())
    require(pins["revision"] == REVISION and {name: pins["files"][name]["sha256"] for name in SOURCE_HASHES} == SOURCE_HASHES
        and provision["version"] == 1 and provision["kind"] == "image-snapshot-runtime-provision"
        and provision["pins"] == pins and provision["pins_sha256"] == hashlib.sha256(pin_path.read_bytes()).hexdigest()
        and all(provision[key] is True for key in ("success", "guest_only", "source_files_verified",
            "runtime_files_verified", "original_licenses_retained"))
        and all(provision[key] is False for key in ("snapshot_created", "peer_storage_proven", "immich_server_started")),
        "exact guest source/runtime provisioning absent")
    require(set(provision["tools"]) == {"gpg", "gpg-agent", "gpgconf", "tar"}, "guest crypto tools absent")
    for name, tool in provision["tools"].items():
        require(type(tool["bytes"]) is int and tool["bytes"] > 0 and re.fullmatch(r"[0-9a-f]{64}", tool["sha256"])
            and type(tool["package"]) is str and tool["package"] and type(tool["package_version"]) is str
            and tool["package_version"], "guest crypto tool receipt differs")
    prepare = value["prepare"]
    geometry = configure(prepare)
    size = prepare["ciphertext_bytes"]
    require(prepare["archive_encryption_proven"] is True and prepare["original_plaintext_preserved"] is True
        and prepare["owner_distinct_from_all_providers"] is True and prepare["owner_secrets_exported"] is False
        and prepare["grant_payload_bytes"] == list(geometry["PROVIDER_BYTES"])
        and prepare["grant_max_leases"] == list(geometry["PROVIDER_LEASES"]), "image encryption or grants absent")
    require(value["upload"] == dict(actual_image_cli=True, committed_fragment_copies=8,
        logical_ciphertext_bytes=size, physical_payload_charge=2 * size, committed_retry_same_identities=True,
        renewal_confirmed=True, source_ciphertext_removed=True, original_plaintext_preserved=True,
        temporary_transfer_files_removed=True), "image upload not complete")
    require(value["restore"] == dict(actual_image_cli=True, restores=2, actual_gpg_decryptions=2,
        plaintext_sha256=[SOURCE_DIGESTS, SOURCE_DIGESTS], source_ciphertext_absent=True,
        original_plaintext_preserved=True, openpgp_integrity_verified=True, manifest_verified=True,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
        retained_identity_unchanged=True, physical_payload_charge=2 * size), "actual Image recovery absent")
    require(value["finish"] == dict(actual_image_cli=True, reopened_copies_confirmed=True,
        all_eight_copies_deleted=True, delete_retry_idempotent=True, original_plaintext_preserved=True,
        final_payload_charge=0), "Image deletion absent")
    retained = [dict(reserved_bytes=0, committed_bytes=n, leases=c)
                for n, c in zip(geometry["PROVIDER_BYTES"], geometry["PROVIDER_LEASES"])]
    require(value["uploaded_usage"] == value["restored_usage"] == retained
        and all(entry["committed_bytes"] < size for entry in retained)
        and value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
        "physical Image fragment accounting differs")
    require(value["private_cleanup"] == dict(owner_identity_removed=True, passphrase_removed=True,
        grants_removed=True, recovery_keys_removed=True, private_plaintext_removed=True,
        ciphertext_removed=True, fragment_journal_removed=True, user_directory_removed=True), "private cleanup incomplete")
    require(value["withdrawal"] == dict(first_provider_stopped_before_restore=True, first_store_retained=True,
        other_two_providers_serving=True, same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True, agent_restart_claimed=False), "provider lifecycle missing")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
        and isolation["control_gid"] != isolation["agent_gid"] and all(isolation[field] is True for field in (
        "agent_cannot_read_user_state", "client_cannot_read_any_provider_store", "agent_mount_positive_control",
        "all_provider_keys_match_independent_fixture_peers", "three_provider_namespaces_distinct")), "isolation absent")
    require(set(value["network"]) == set(FRAGMENTS["PHASES"]), "network phase missing")
    for name, phase in value["network"].items():
        FRAGMENTS["validate_network"](phase, value["expected_peers"], value["layout"], name)


def validate_report(report, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report["source_revision"] == revision
        and report["schema_version"] == 1 and report["report_kind"] == "volparossa-image-snapshot"
        and report["success"] is True and report["runner_exit_status"] == 0
        and report["phase"] == "image-snapshot-complete" and report["observed_blocker"] is None
        and report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
        and report["host_state"]["unchanged"] is True, "source-bound host/guest cleanup incomplete")
    validate_evidence(report["image"])


def main(arguments):
    command = arguments[0]
    if command == "export-names" and len(arguments) == 1:
        print("\n".join(EXPORT_NAMES)); return
    if command == "prepare" and len(arguments) == 10:
        result = prepare(owner_root(arguments[1]), *arguments[2:])
    elif command in FRAGMENTS["PHASES"] and len(arguments) == 7:
        result = {"upload": upload, "restore": restore, "finish": finish}[command](
            owner_root(arguments[1]), arguments[2], arguments[3], arguments[4:])
    elif command == "cleanup" and len(arguments) == 2:
        result = cleanup(arguments[1])
    elif command == "evidence" and len(arguments) == 3:
        result = build_evidence(Path(arguments[1]))
        Path(arguments[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif command == "report" and len(arguments) == 3:
        validate_report(read(Path(arguments[1])), arguments[2])
        result = dict(success=True, report_kind="volparossa-image-snapshot")
    else:
        raise ValueError("unknown image snapshot fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("image fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError):
        print(json.dumps(dict(success=False, kind="image-snapshot-failure", stage=STAGE)))
        print("Image snapshot fixture failed; private diagnostics not exported", file=sys.stderr)
        sys.exit(1)
