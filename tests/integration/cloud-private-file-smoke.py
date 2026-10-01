#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pinned Cloud CLI, real GPG and protected core storage; synthetic DAV source only."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys
import threading

IMAGE = runpy.run_path(str(Path(__file__).with_name("image-snapshot-smoke.py")))
FRAGMENTS = IMAGE["FRAGMENTS"]
require, read, create = FRAGMENTS["require"], FRAGMENTS["read"], FRAGMENTS["create"]
private_file, invoke, unlock = FRAGMENTS["private_file"], FRAGMENTS["invoke"], FRAGMENTS["unlock"]
owner_root, cleanup, process_json = IMAGE["owner_root"], IMAGE["cleanup"], IMAGE["process_json"]
REVISION = "541cc826fe14ce69cf89a82ecb600ad14dd534c6"
PIN_PATH = Path(__file__).with_name("cloud-private-file-pins.json")
PINS = json.loads(PIN_PATH.read_text())
SOURCE_HASHES = {name: record["sha256"] for name, record in PINS["files"].items()}
CHUNK = FRAGMENTS["CHUNK"]
CONTENT = bytes(range(256)) * (3 * CHUNK // 256) + b"C"
CONTENT_SHA = hashlib.sha256(CONTENT).hexdigest()
ETAG = '"synthetic-cloud-file-v1"'
DAV_PATH = "/dav/spaces/synthetic-owner/private-file.bin"
FALSE_CLAIMS = ("opencloud_server_started", "serverless_opencloud_proven", "web_client_proven",
    "public_cache_used", "training_data_published", "automatic_placement", "automatic_repair",
    "automatic_contribution_resize", "network_contribution_credit", "independent_failure_domains_proven",
    "erasure_coding", "full_alpha_acceptance_claimed", "owner_secrets_exported")
EXPORT_NAMES = tuple(name for name in FRAGMENTS["EXPORT_NAMES"] if name not in (
    "private-storage-fragments-smoke.json", "private-storage-fragments-evidence.json")) + (
    "cloud-private-file-smoke.json", "cloud-private-file-evidence.json", "cloud-private-file-provision.json",
    "cloud-private-file-route-diagnostic.json")
STAGE = "not_started"


def tools():
    source, node = Path(os.environ["CLOUD_SOURCE"]), Path(os.environ["CLOUD_NODE"])
    require(source == Path("/opt/volparossa-cloud") and node == Path("/opt/volparossa-node/bin/node")
        and os.environ["CLOUD_REVISION"] == REVISION and PINS["revision"] == REVISION,
        "Cloud source or runtime identity differs")
    for path, record in [(source / name, record) for name, record in PINS["files"].items()] + [
            (node, PINS["runtime"]["files"]["bin/node"])]:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0
                and path.resolve() == path and info.st_size == record["bytes"], "Cloud pinned file differs")
        with path.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == record["sha256"], "Cloud file hash differs")
    return source, node


def cloud(root, operation, *arguments, expected=0):
    source, node = tools()
    command = [node, source / "scripts/cloud-file.mjs", operation, "--bundle", root / "bundle"]
    if operation == "import":
        command += ["--source-config", root / "source.private.json"]
    else:
        command += ["--config", root / "storage.json"]
    return process_json([*command, *arguments], expected=expected)


def configure(value):
    require(value["cloud_revision"] == REVISION and value["source_sha256"] == SOURCE_HASHES
        and value["plaintext_sha256"] == CONTENT_SHA and value["plaintext_bytes"] == len(CONTENT)
        and re.fullmatch(r"[0-9a-f]{64}", value["cipher_sha256"]), "synthetic Cloud identity differs")
    FRAGMENTS["configure_payload_geometry"](value["ciphertext_bytes"])
    return FRAGMENTS["configure_payload_geometry"].__globals__


def fixture(root):
    private_file(root / "fixture.json")
    value = read(root / "fixture.json")
    configure(value)
    return value


def import_source(root):
    """A real bounded HTTP endpoint, explicitly synthetic and never external OpenCloud."""
    token = base64.urlsafe_b64encode(os.urandom(32)).decode()
    counts = dict(head=0, ranges=0, bytes=0, rejected=0)

    class DAV(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def handle_one_request(self):
            self.connection.settimeout(5)
            super().handle_one_request()

        def do_HEAD(self):
            if self.path != DAV_PATH or self.headers.get("Authorization") != "Bearer " + token:
                counts["rejected"] += 1
                self.send_error(403); return
            counts["head"] += 1
            self.send_response(200)
            self.send_header("ETag", ETAG)
            self.send_header("Content-Length", str(len(CONTENT)))
            self.end_headers()

        def do_GET(self):
            match = re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers.get("Range", ""))
            if (self.path != DAV_PATH or self.headers.get("Authorization") != "Bearer " + token
                    or self.headers.get("If-Match") != ETAG or match is None):
                counts["rejected"] += 1
                self.send_error(412); return
            start, end = map(int, match.groups())
            if not 0 <= start <= end < len(CONTENT) or end - start + 1 > CHUNK:
                counts["rejected"] += 1
                self.send_error(416); return
            counts["ranges"] += 1
            body = CONTENT[start:end + 1]
            counts["bytes"] += len(body)
            self.send_response(206)
            self.send_header("ETag", ETAG)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(CONTENT)}")
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), DAV)
    origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=0.05))
    thread.start()
    try:
        create(root / "source.private.json", json.dumps(dict(version=1,
            source=dict(origin=origin, bearerToken=token, maxFileBytes=2 * 1024**2,
                maxRequestBytes=CHUNK, allowInsecureLoopbackForTests=True),
            resource=dict(spaceId="synthetic-owner", pathSegments=["private-file.bin"]))).encode())
        receipt = cloud(root, "import")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        require(not thread.is_alive() and server.socket.fileno() == -1, "synthetic DAV did not stop")
        if (root / "source.private.json").exists():
            private_file(root / "source.private.json")
            (root / "source.private.json").unlink()
    require(counts == dict(head=1, ranges=4, bytes=len(CONTENT), rejected=0), "actual authenticated DAV reads differ")
    require(not any(path.name.startswith("import-") for path in root.iterdir()), "private import staging remains")
    return receipt, origin + DAV_PATH


def prepare(root, binary, client, provider_a, provider_b, provider_c, key_a, key_b, key_c):
    global STAGE
    STAGE = "authenticated_dav_import"
    tools()
    keys = (key_a, key_b, key_c)
    require(not list(root.iterdir()) and len(set(keys)) == 3, "new owner and distinct providers required")
    receipt, source_url = import_source(root)
    require(receipt["kind"] == "volparossa-cloud-private-file" and receipt["encryption"] == "OpenPGP-AES256"
        and receipt["source_consistency"] == "strong-etag-conditional-ranges", "actual Cloud encryption absent")
    ciphertext = root / "bundle/file.pgp"
    require(private_file(ciphertext).st_size == receipt["cipher_bytes"]
        and hashlib.sha256(ciphertext.read_bytes()).hexdigest() == receipt["cipher_sha256"], "Cloud ciphertext differs")
    value = dict(cloud_revision=REVISION, source_sha256=SOURCE_HASHES, plaintext_sha256=CONTENT_SHA,
        plaintext_bytes=len(CONTENT), ciphertext_bytes=receipt["cipher_bytes"], cipher_sha256=receipt["cipher_sha256"])
    geometry = configure(value)
    # The synthetic URL stays private; only closed identity/size facts leave this owner.
    create(root / "fixture.json", json.dumps(dict(**value, source_url=source_url)).encode())
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
        fragmentBytes=CHUNK, lifetimeSeconds=1800, deadlineMs=900000)
    create(root / "storage.json", json.dumps(config).encode())
    return dict(**value, archive_encryption_proven=True, authenticated_dav_ranges=4,
        source_stopped_and_joined=True, source_credentials_removed=True, private_import_staging_removed=True,
        owner_distinct_from_all_providers=True, grant_payload_bytes=list(geometry["PROVIDER_BYTES"]),
        grant_max_leases=list(geometry["PROVIDER_LEASES"]), owner_secrets_exported=False)


def raw_status(root, binary, client, keys, phase):
    return IMAGE["raw_status"](root, binary, client, keys, phase)


def check_bridge(value, metadata, phase):
    require(value["version"] == 1 and value["status"] == "complete"
        and value["local_process_joined"] is True and value["remote_cleanup_confirmed"] is False,
        "actual core bridge did not complete")
    IMAGE["check_bridge"](value, metadata, phase)


def maintenance(root, binary, client, keys, operation, phase, *arguments):
    result = invoke(binary, client, ["storage", "fragments", operation,
        *FRAGMENTS["existing"](root), *arguments], deadline=900)
    FRAGMENTS["validate_cli"](result, operation, keys, phase)
    FRAGMENTS["check_identity"](root)


def upload(root, binary, client, keys):
    global STAGE
    metadata = fixture(root)
    STAGE = "cloud_create"
    check_bridge(cloud(root, "create"), metadata, "created")
    raw_status(root, binary, client, keys, "created")
    STAGE = "cloud_deposit"
    check_bridge(cloud(root, "deposit"), metadata, "committed")
    raw_status(root, binary, client, keys, "committed")
    create(root / "identities.sha256", FRAGMENTS["identity_digest"](root))
    maintenance(root, binary, client, keys, "progress", "committed")
    check_bridge(cloud(root, "deposit"), metadata, "committed")
    FRAGMENTS["check_identity"](root)
    maintenance(root, binary, client, keys, "renew", "committed", "--lifetime-seconds", 3600)
    raw_status(root, binary, client, keys, "committed")
    FRAGMENTS["staged_files_absent"](root)
    private_file(root / "bundle/file.pgp")
    (root / "bundle/file.pgp").unlink()
    return upload_report(metadata["ciphertext_bytes"])


def upload_report(size):
    return dict(actual_cloud_cli=True, committed_fragment_copies=8, logical_ciphertext_bytes=size,
        physical_payload_charge=2 * size, committed_retry_same_identities=True, renewal_confirmed=True,
        source_ciphertext_removed=True, source_service_stopped=True, temporary_transfer_files_removed=True)


def verify_plain(path, metadata):
    require({entry.name for entry in path.iterdir()} == {"content.bin", "metadata.json"}, "unexpected restored Cloud entry")
    require(private_file(path / "content.bin").st_size == len(CONTENT)
        and hashlib.sha256((path / "content.bin").read_bytes()).hexdigest() == CONTENT_SHA, "Cloud plaintext differs")
    private_file(path / "metadata.json")
    manifest = read(path / "metadata.json")
    require(manifest == dict(version=1, kind="volparossa-cloud-file-content", content_bytes=len(CONTENT),
        content_sha256=CONTENT_SHA, source=dict(url=metadata["source_url"], size=len(CONTENT), etag=ETAG,
        lastModified=None)), "private source metadata differs")


def restore(root, binary, client, keys):
    global STAGE
    metadata = fixture(root)
    require(not (root / "bundle/file.pgp").exists() and not (root / "source.private.json").exists(),
        "Cloud source or credentials remain")
    for number in (1, 2):
        STAGE = f"cloud_restore_{number}"
        value = cloud(root, "restore", "--output", root / f"restore-{number}")
        check_bridge(value["storage"], metadata, "restore")
        require(value["kind"] == "volparossa-cloud-private-restore" and value["restored"] is True
            and value["bytes"] == len(CONTENT) and value["cipher_sha256"] == metadata["cipher_sha256"]
            and value["openpgp_integrity_verified"] is True and value["manifest_verified"] is True
            and value["storage"]["restore_verified"] is True, "actual Cloud peer decryption absent")
        raw_status(root, binary, client, keys, "restore")
        verify_plain(root / f"restore-{number}", metadata)
        FRAGMENTS["check_identity"](root)
    STAGE = "existing_output"
    cloud(root, "restore", "--output", root / "restore-1", expected=1)
    verify_plain(root / "restore-1", metadata)
    FRAGMENTS["staged_files_absent"](root)
    require(not any(path.name.startswith("receive-") for path in root.iterdir()), "Cloud received ciphertext remains")
    return restore_report(metadata["ciphertext_bytes"])


def restore_report(size):
    return dict(actual_cloud_cli=True, restores=2, actual_gpg_decryptions=2,
        plaintext_sha256=[CONTENT_SHA, CONTENT_SHA], source_ciphertext_absent=True, source_service_stopped=True,
        openpgp_integrity_verified=True, manifest_verified=True, private_source_metadata_verified=True,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
        retained_identity_unchanged=True, physical_payload_charge=2 * size)


def finish(root, binary, client, keys):
    global STAGE
    fixture(root)
    STAGE = "cloud_finish"
    maintenance(root, binary, client, keys, "progress", "committed")
    for _ in range(2):
        maintenance(root, binary, client, keys, "delete", "deleted")
        raw_status(root, binary, client, keys, "deleted")
    FRAGMENTS["staged_files_absent"](root)
    return dict(actual_core_cli=True, reopened_copies_confirmed=True, all_eight_copies_deleted=True,
        delete_retry_idempotent=True, final_payload_charge=0)


def build_evidence(work):
    names = ("prepare", "upload", "restore", "finish", "withdrawal", "isolation", "layout", "private_cleanup")
    value = {name: read(work / f"private-storage-fragments-{name}.json") for name in names}
    for name in ("uploaded_usage", "restored_usage", "deleted_usage"):
        value[name] = FRAGMENTS["read_usage"](work / f"private-storage-fragments-{name}.json")
    value.update(success=True, archive_encryption_proven=True, expected_peers=read(work / "a01-expected-peers.json"),
        provision=read(work / "cloud-private-file-provision.json"), **dict.fromkeys(FALSE_CLAIMS, False))
    value["network"] = {name: dict(selected_route=read(work / f"private-storage-fragments-{name}-live-selection.json"),
        privacy={role: read(work / f"private-storage-fragments-{name}-privacy-{role}.json") for role in FRAGMENTS["ROLES"]},
        control_privacy=read(work / f"content-provider-adaptive-private-storage-fragments-{name}-control.json"),
        gates=read(work / f"private-storage-fragments-{name}-gates.json")) for name in FRAGMENTS["PHASES"]}
    validate_evidence(value)
    return value


def validate_evidence(value):
    require(value["success"] is True and value["archive_encryption_proven"] is True
        and all(value[field] is False for field in FALSE_CLAIMS), "Cloud scope overstated")
    provision = value["provision"]
    require(provision["version"] == 1 and provision["kind"] == "cloud-private-file-runtime-provision"
        and provision["pins"] == PINS and provision["pins_sha256"] == hashlib.sha256(PIN_PATH.read_bytes()).hexdigest()
        and all(provision[key] is True for key in ("success", "guest_only", "source_files_verified",
            "runtime_files_verified", "original_licenses_retained"))
        and all(provision[key] is False for key in ("private_file_created", "peer_storage_proven", "opencloud_server_started")),
        "exact Cloud guest provisioning absent")
    require(set(provision["tools"]) == {"gpg", "gpg-agent", "gpgconf", "tar"}, "guest crypto tools absent")
    for tool in provision["tools"].values():
        require(type(tool["bytes"]) is int and tool["bytes"] > 0 and re.fullmatch(r"[0-9a-f]{64}", tool["sha256"])
            and type(tool["package"]) is str and tool["package"] and type(tool["package_version"]) is str
            and tool["package_version"], "guest crypto tool receipt differs")
    prepare = value["prepare"]
    geometry = configure(prepare)
    size = prepare["ciphertext_bytes"]
    require(prepare["archive_encryption_proven"] is True and prepare["authenticated_dav_ranges"] == 4
        and all(prepare[key] is True for key in ("source_stopped_and_joined", "source_credentials_removed",
            "private_import_staging_removed", "owner_distinct_from_all_providers"))
        and prepare["owner_secrets_exported"] is False
        and prepare["grant_payload_bytes"] == list(geometry["PROVIDER_BYTES"])
        and prepare["grant_max_leases"] == list(geometry["PROVIDER_LEASES"]), "Cloud import or grants absent")
    require(value["upload"] == upload_report(size) and value["restore"] == restore_report(size), "Cloud peer recovery absent")
    require(value["finish"] == dict(actual_core_cli=True, reopened_copies_confirmed=True,
        all_eight_copies_deleted=True, delete_retry_idempotent=True, final_payload_charge=0), "Cloud deletion absent")
    retained = [dict(reserved_bytes=0, committed_bytes=n, leases=c)
        for n, c in zip(geometry["PROVIDER_BYTES"], geometry["PROVIDER_LEASES"])]
    require(value["uploaded_usage"] == value["restored_usage"] == retained
        and all(entry["committed_bytes"] < size for entry in retained)
        and value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
        "Cloud physical fragment accounting differs")
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
        and report["schema_version"] == 1 and report["report_kind"] == "volparossa-cloud-private-file"
        and report["success"] is True and report["runner_exit_status"] == 0
        and report["phase"] == "cloud-private-file-complete" and report["observed_blocker"] is None
        and report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
        and report["host_state"]["unchanged"] is True, "source-bound host/guest cleanup incomplete")
    validate_evidence(report["cloud"])


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
        result = dict(success=True, report_kind="volparossa-cloud-private-file")
    else:
        raise ValueError("unknown Cloud fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("Cloud fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError):
        print(json.dumps(dict(success=False, kind="cloud-private-file-failure", stage=STAGE)))
        print("Cloud private-file fixture failed; private diagnostics not exported", file=sys.stderr)
        sys.exit(1)
