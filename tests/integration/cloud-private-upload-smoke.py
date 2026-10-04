#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Original Files/Uppy uploads through real core fragments; disposable guest only.

The baseline DAV endpoint is explicitly synthetic. No core/storage/UI factory is
injected. Historical cloud-private-file evidence and its exact pins stay separate.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
CLOUD = runpy.run_path(str(HERE / "cloud-private-file-smoke.py"))
BASE = CLOUD["prepare"].__globals__
F = CLOUD["FRAGMENTS"]
require, read, create = F["require"], F["read"], F["create"]
private_file, invoke, unlock = F["private_file"], F["invoke"], F["unlock"]
owner_root = CLOUD["owner_root"]
PINS_PATH = HERE / "cloud-private-upload-pins.json"
PINS = json.loads(PINS_PATH.read_text())
REVISION = PINS["revision"]
HASHES = {name: record["sha256"] for name, record in PINS["files"].items()}
BASE.update(REVISION=REVISION, PINS=PINS, PIN_PATH=PINS_PATH, SOURCE_HASHES=HASHES)
CHUNK = F["CHUNK"]
UPLOAD_CHUNK = CHUNK // 2
UPLOAD = bytes(range(256)) * (CHUNK // 256) + b"U"
UPLOAD_SHA = hashlib.sha256(UPLOAD).hexdigest()
STAGE = "not_started"
UI_STAGE = None
UI_FAILURE = None
EXPORT_NAMES = tuple(name for name in CLOUD["EXPORT_NAMES"] if not name.startswith("cloud-private-file-")) + (
    "cloud-private-upload-smoke.json", "cloud-private-upload-evidence.json",
    "cloud-private-upload-provision.json", "cloud-private-upload-route-diagnostic.json")
FALSE_CLAIMS = CLOUD["FALSE_CLAIMS"] + ("general_writable_sync_proven", "independent_device_recovery_proven")
UI_STAGES = frozenset(("input", "browser_start", "locked_ui", "wrong_token", "unlock", "upload_menu",
    "file_selection", "upload_commit", "reload", "original_download_1", "original_download_2", "logout", "cleanup"))
UI_FAILURE_KINDS = frozenset(("condition_timeout", "transport_timeout", "transport_error",
    "browser_command", "subprocess_error", "boundary_failed"))
UI_FAILURE_FLAGS = ("original_file_input_used", "upload_201_observed", "uploaded_file_listed",
    "browser_stopped_and_joined", "private_profile_removed")


def tools():
    require(type(REVISION) is str and re.fullmatch(r"[0-9a-f]{40}", REVISION)
            and REVISION != "0" * 40, "reviewed Cloud upload source pin required")
    return CLOUD["tools"]()


def fixture(root):
    return CLOUD["fixture"](root)


def prepare(root, binary, client, provider_a, provider_b, provider_c, key_a, key_b, key_c):
    global STAGE
    STAGE = "baseline_import"
    tools()
    require(not list(root.iterdir()) and len({key_a, key_b, key_c}) == 3, "fresh owner and providers required")
    receipt, source_url = CLOUD["import_source"](root)
    require(receipt["version"] == 1 and receipt["encryption"] == "OpenPGP-AES256"
            and receipt["source_consistency"] == "strong-etag-conditional-ranges", "baseline import missing")
    cipher = root / "bundle/file.pgp"
    require(private_file(cipher).st_size == receipt["cipher_bytes"]
            and hashlib.sha256(cipher.read_bytes()).hexdigest() == receipt["cipher_sha256"], "baseline cipher differs")
    value = dict(cloud_revision=REVISION, source_sha256=HASHES, plaintext_sha256=CLOUD["CONTENT_SHA"],
        plaintext_bytes=len(CLOUD["CONTENT"]), ciphertext_bytes=receipt["cipher_bytes"], cipher_sha256=receipt["cipher_sha256"])
    CLOUD["configure"](value)
    create(root / "fixture.json", json.dumps(dict(**value, source_url=source_url)).encode())
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    STAGE = "owner_grants"
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    keys = (key_a, key_b, key_c)
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner not in keys, "owner identity differs")
    for label, socket, key in zip("abc", (provider_a, provider_b, provider_c), keys):
        grant = invoke(binary, socket, ["storage", "peer", "grant", "--provider-key", key, "--owner-key", owner,
            "--max-payload-bytes", 1048576, "--max-leases", 8, "--max-retention-seconds", 7200,
            "--lifetime-seconds", 7200, "--output", root / f"grant-{label}.bin"])
        require(grant["grant_written"] is True and grant["reserved_bytes"] == 0
            and grant["max_payload_bytes"] == 1048576 and grant["max_leases"] == 8
            and grant["network_contribution_credit"] is False, "bounded grant missing")
    config = dict(version=1, coreBinary=binary, controlSocket=client, identity=str(root / "identity.key"),
        passphraseFile=str(root / "passphrase"), providers=[dict(key=key, grant=str(root / f"grant-{label}.bin"))
        for label, key in zip("abc", keys)], fragmentBytes=UPLOAD_CHUNK, lifetimeSeconds=1800, deadlineMs=900000)
    create(root / "upload-storage.json", json.dumps(config).encode())
    create(root / "storage.json", json.dumps(dict(config, stateDirectory=str(root / "fragment-set"), fragmentBytes=CHUNK)).encode())
    return dict(**value, authenticated_dav_ranges=4, source_stopped_and_joined=True,
        source_credentials_removed=True, owner_distinct_from_all_providers=True,
        grant_payload_bytes=[1048576] * 3, grant_max_leases=[8] * 3, owner_secrets_exported=False)


def uploaded_object(root):
    objects = [path for path in (root / "o").iterdir() if path.name != "LOCK"]
    require(len(objects) == 1 and re.fullmatch(r"object-[0-9a-f]{32}", objects[0].name), "one upload required")
    target = objects[0]
    owner_root(target.parent.parent)
    for name in ("READY.json", "core.json", "bundle/receipt.json", "catalog/receipt.json"):
        private_file(target / name)
    ready, catalog = read(target / "READY.json"), read(target / "catalog/receipt.json")
    require(ready == dict(version=1, catalogSha256=catalog["cipher_sha256"]), "durable publication missing")
    config, baseline = read(target / "core.json"), read(root / "upload-storage.json")
    require(config == dict(baseline, stateDirectory=str(target / "journal")), "upload changed core authority")
    receipt = read(target / "bundle/receipt.json")
    require(receipt["version"] == 2 and receipt["kind"] == "volparossa-cloud-private-file"
        and receipt["encryption"] == "OpenPGP-AES256" and receipt["source_consistency"] == "owner-upload-snapshot"
        and 2 * UPLOAD_CHUNK < receipt["cipher_bytes"] <= 3 * UPLOAD_CHUNK
        and re.fullmatch(r"[0-9a-f]{64}", receipt["cipher_sha256"]), "native upload receipt invalid")
    return target, receipt


def upload_identity(target):
    manifest = target / "journal/fragments.json"
    private_file(manifest)
    digest = hashlib.sha256(manifest.read_bytes())
    for index in range(3):
        for copy in range(2):
            path = target / f"journal/fragment-{index:04}/copy-{copy}/archive.json"
            private_file(path)
            value = read(path)
            require(value["lease"] is not None, "unacknowledged upload lease")
            digest.update(json.dumps({key: value[key] for key in ("provider_key", "owner_key", "grant_hex",
                "archive_id", "ciphertext_bytes", "sha256", "lease")}, sort_keys=True).encode())
    return digest.digest()


def validate_upload_status(value, keys, size, operation, phase):
    require(value["operation"] == "private_storage_fragments_" + operation
        and value["logical_ciphertext_bytes"] == size and value["fragment_count"] == 3
        and value["copies_per_fragment"] == 2 and value["distinct_provider_identities"] == 3
        and value.get("operation_complete", True) is True and value["owner_signature_verified"] is True
        and value["read_consumes_archive"] is False and value["expired_copies_remain_charged"] is True,
        "upload fragment operation differs")
    lengths = (UPLOAD_CHUNK, UPLOAD_CHUNK, size - 2 * UPLOAD_CHUNK)
    charges, counts = [0, 0, 0], [0, 0, 0]
    totals, recoverable, redundant = dict(reserved=0, committed=0, uncertain=0), 0, True
    require(len(value["fragments"]) == 3, "upload fragment count differs")
    for index, (fragment, length) in enumerate(zip(value["fragments"], lengths)):
        require(fragment["index"] == index and fragment["offset"] == index * UPLOAD_CHUNK
            and fragment["ciphertext_bytes"] == length and len(fragment["copies"]) == 2, "upload range differs")
        confirmed = 0
        for copy, row in enumerate(fragment["copies"]):
            provider = (index + copy) % 3
            expected = "deleted" if phase == "deleted" else "uncertain" if phase == "restore" and provider == 0 and index == 0 else "committed"
            require(row["provider_key"] == keys[provider] and row["charge"] == expected
                and row["last_confirmed_stored_bytes"] == (0 if phase == "deleted" else length)
                and row["last_confirmed_state"] == ("Deleted" if phase == "deleted" else "Committed")
                and (row["last_confirmed_expiry"] == 0 if phase == "deleted" else row["last_confirmed_expiry"] > int(time.time())),
                "upload copy authority or retained charge differs")
            if phase != "deleted":
                charges[provider] += length
                counts[provider] += 1
                totals[expected] += length
                confirmed += int(expected == "committed")
        require(fragment["confirmed_unexpired_copies"] == confirmed, "upload confirmed copies differ")
        recoverable += int(confirmed > 0)
        redundant &= confirmed == 2
    require(value["fragments_with_confirmed_unexpired_copy"] == recoverable
        and value["fully_redundant_from_retained_receipts"] is redundant
        and all(value[key + "_payload_bytes"] == amount for key, amount in totals.items())
        and all(value[key] is False for key in ("metadata_overhead_measured", "current_remote_availability_proven",
            "independent_failure_domains_proven", "network_contribution_credit", "automatic_repair",
            "automatic_handoff", "erasure_coding")), "upload accounting or scope differs")
    require(value["physical_payload_charge_upper_bound"] == sum(charges)
        and value["providers"] == [dict(provider_key=key, physical_payload_charge_upper_bound=charge)
                                   for key, charge in zip(keys, charges)], "upload physical charge differs")
    return [dict(reserved_bytes=0, committed_bytes=size, leases=count) for size, count in zip(charges, counts)]


def upload_status(root, binary, client, keys, operation="status", phase="committed"):
    target, receipt = uploaded_object(root)
    args = ["storage", "fragments", operation, "--state", target / "journal"]
    if operation != "status":
        args += unlock(root)
    value = invoke(binary, client, args, deadline=900)
    usage = validate_upload_status(value, keys, receipt["cipher_bytes"], operation, phase)
    require(upload_identity(target) == (root / "upload-identities.sha256").read_bytes(), "upload identities changed")
    return usage


def ui_upload_observation(value):
    require(type(value) is dict and set(value) == {"puts", "completed", "created", "last_status", "statuses"}
        and all(type(value[key]) is int and 0 <= value[key] <= 4 for key in ("puts", "completed", "created"))
        and value["created"] <= value["completed"] <= value["puts"]
        and type(value["last_status"]) is int
        and (value["last_status"] == 0 or 100 <= value["last_status"] <= 599), "invalid UI upload observation")
    statuses = value["statuses"]
    require(type(statuses) is list and len(statuses) == value["completed"]
        and all(type(status) is int and (status == 0 or 100 <= status <= 599) for status in statuses)
        and value["created"] == statuses.count(201)
        and value["last_status"] == (statuses[-1] if statuses else 0), "invalid UI upload status sequence")
    return dict(value, statuses=list(statuses))


def ui_upload_receipt(value):
    value = ui_upload_observation(value)
    require(1 <= value["puts"] == value["completed"] <= 4 and value["created"] == 1
        and value["last_status"] == 201 and all(not 200 <= status < 300 for status in value["statuses"][:-1]),
        "original uploader retry sequence incomplete")
    return value


def ui_record(value, mode):
    receipt = ui_upload_receipt(value["upload_receipt"]) if mode == "upload" else None
    expected = dict(version=1, kind="cloud-owner-upload-original-ui", mode=mode, success=True, stage="cleanup",
        original_files_ui=True, synthetic_backend=False, original_file_input_used=mode == "upload",
        upload_201_observed=mode == "upload", uploaded_file_listed=True, reload_reauthenticated=mode == "upload",
        file_downloads_verified=0 if mode == "upload" else 2, wrong_token_denied=True, logout_relocks=True,
        token_absent_from_url_and_web_storage=True, browser_stopped_and_joined=True, private_profile_removed=True,
        browser_version="140.16.0", bytes=len(UPLOAD), sha256=UPLOAD_SHA, peer_storage_proven=False,
        service_restart_owned_by_parent=True, source_shutdown_owned_by_parent=True, owner_secrets_exported=False,
        upload_receipt=receipt)
    require(value == expected, "original upload UI incomplete")
    return value


def closed_ui_failure(value, mode):
    """Select bounded failure metadata only; invalid observations stay unknown."""
    try:
        require(type(value) is dict and mode in ("upload", "download")
            and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "cloud-owner-upload-original-ui" and value["mode"] == mode
            and value["success"] is False and type(value["stage"]) is str
            and value["stage"] in UI_STAGES, "invalid UI failure envelope")
        require(type(value["failure_kind"]) is str and value["failure_kind"] in UI_FAILURE_KINDS
            and all(type(value[key]) is bool for key in UI_FAILURE_FLAGS), "invalid UI failure fields")
        observation = value["upload_observation"]
        if observation is not None:
            observation = ui_upload_observation(observation)
        return dict(failure_kind=value["failure_kind"], upload_observation=observation,
            **{key: value[key] for key in UI_FAILURE_FLAGS})
    except (KeyError, TypeError, ValueError):
        return None


def serve_ui(root, mode):
    global UI_STAGE, UI_FAILURE
    UI_STAGE, UI_FAILURE = None, None
    source, node = tools()
    config = read(root / "service.json")
    service = subprocess.Popen([node, source / "scripts/cloud-serve.mjs", "--config", root / "service.json"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    clean = False
    try:
        require(bool(select.select([service.stdout], [], [], 60)[0]), "Cloud service readiness timeout")
        record = json.loads(service.stdout.readline(4097))
        require(record["version"] == 1 and record["kind"] == "volparossa-cloud-private-read"
            and record["state"] == "listening" and record["readOnly"] is False and record["loopbackOnly"] is True
            and record["originalServerFallback"] is False and record["openCloudAccountService"] is False
            and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", record["origin"]), "owner service not ready")
        command = ["/usr/bin/python3", "-B", source / "scripts/smoke_owner_upload_ui.py", mode, root / "w", "--yes"]
        payload = dict(origin=record["origin"], bearerToken=config["bearerToken"], expectedBytes=len(UPLOAD), expectedSha256=UPLOAD_SHA)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        try:
            stdout, stderr = process.communicate(json.dumps(payload).encode(), timeout=1900)
            require(len(stdout) <= 4096 and len(stderr) <= 16384, "UI output exceeds closed bound")
            value = json.loads(stdout)
            stage = value.get("stage") if type(value) is dict else None
            UI_STAGE = stage if type(stage) is str and stage in UI_STAGES else "unreported"
            UI_FAILURE = closed_ui_failure(value, mode)
            require(process.returncode == 0, "original UI failed")
            result = ui_record(value, mode)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
        clean = True
        return result
    finally:
        if service.poll() is None:
            os.killpg(service.pid, signal.SIGTERM)
        try: stdout, stderr = service.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(service.pid, signal.SIGKILL); service.communicate(timeout=5)
            raise ValueError("Cloud service cleanup unconfirmed") from None
        require(service.returncode == 0 and len(stdout) <= 4096 and not stderr
            and json.loads(stdout) == dict(version=1, kind="volparossa-cloud-private-read", state="closed"),
            "Cloud service cleanup unconfirmed")
        if clean:
            require(not list((root / "w").iterdir()), "private service staging remains")


def upload(root, binary, client, keys):
    global STAGE
    metadata = fixture(root)
    STAGE = "baseline_deposit"
    baseline = CLOUD["upload"](root, binary, client, keys)
    (root / "w").mkdir(mode=0o700)
    (root / "o").mkdir(mode=0o700)
    create(root / "selection.json", json.dumps(dict(version=1, files=[dict(segments=["synthetic-owner", "private-file.bin"],
        bundle=str(root / "bundle"), config=str(root / "storage.json"))])).encode())
    source, node = tools()
    STAGE = "baseline_catalog"
    catalog = CLOUD["process_json"]([node, source / "scripts/cloud-catalog.mjs", "create", "--selection", root / "selection.json",
        "--catalog", root / "catalog", "--work-directory", root / "w"])
    require(catalog["files"] == 1 and catalog["plaintextBytes"] == metadata["plaintext_bytes"]
        and catalog["encrypted"] is True and catalog["sourceFallback"] is False, "baseline catalog absent")
    create(root / "service.json", json.dumps(dict(version=1, catalog=str(root / "catalog"), workDirectory=str(root / "w"),
        bearerToken=base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="), port=0, allowedOrigins=[],
        maxOpenBytes=2 * 1024**2, maxConcurrent=2, requestTimeoutMs=1800000, maxRangeBytes=CHUNK,
        webDist=str(source / "build/web-ui"), ownerUploads=dict(directory=str(root / "o"), space="owner-uploads",
        storageConfig=str(root / "upload-storage.json")))).encode())
    STAGE = "original_ui_upload"
    ui = serve_ui(root, "upload")
    target, receipt = uploaded_object(root)
    cipher = target / "bundle/file.pgp"
    require(private_file(cipher).st_size == receipt["cipher_bytes"]
        and hashlib.sha256(cipher.read_bytes()).hexdigest() == receipt["cipher_sha256"], "upload cipher differs")
    create(root / "upload-identities.sha256", upload_identity(target))
    usage = upload_status(root, binary, client, keys)
    cipher.unlink()
    require(not (root / "bundle/file.pgp").exists(), "baseline cipher remains")
    return dict(baseline=baseline, ui=ui, upload_ciphertext_bytes=receipt["cipher_bytes"], upload_provider_usage=usage,
        service_stopped_and_joined=True, both_local_ciphertexts_removed=True, original_source_stopped=True,
        private_staging_removed=True, committed_fragment_copies=14)


def restore(root, binary, client, keys):
    global STAGE
    metadata = fixture(root)
    target, receipt = uploaded_object(root)
    require(not (root / "bundle/file.pgp").exists() and not (target / "bundle/file.pgp").exists()
            and not (root / "source.private.json").exists(), "local source remains")
    # These baseline reads also prove that enabling uploads did not replace the
    # original imported archive or its retained keys/journal.
    for number in (1, 2):
        STAGE = "baseline_restore"
        value = CLOUD["cloud"](root, "restore", "--output", root / f"restore-{number}")
        CLOUD["check_bridge"](value["storage"], metadata, "restore")
        CLOUD["verify_plain"](root / f"restore-{number}", metadata)
        CLOUD["raw_status"](root, binary, client, keys, "restore")
        F["check_identity"](root)
    STAGE = "restarted_original_ui_downloads"
    ui = serve_ui(root, "download")
    usage = upload_status(root, binary, client, keys, phase="restore")
    return dict(ui=ui, upload_ciphertext_bytes=receipt["cipher_bytes"], upload_provider_usage=usage,
        baseline_restores=2, upload_downloads=2, new_service_and_browser=True, all_reads_nonconsuming=True,
        both_local_ciphertexts_absent=True, original_source_stopped=True, service_stopped_and_joined=True,
        private_staging_removed=True, retained_identities_unchanged=True)


def finish(root, binary, client, keys):
    global STAGE
    fixture(root)
    STAGE = "all_copy_retirement"
    baseline = CLOUD["finish"](root, binary, client, keys)
    upload_status(root, binary, client, keys, operation="progress")
    for _ in range(2):
        upload_status(root, binary, client, keys, operation="delete", phase="deleted")
    return dict(baseline=baseline, all_fourteen_copies_deleted=True, delete_retry_idempotent=True, final_payload_charge=0)


def cleanup(path):
    # Same strict owned-tree cleanup as the read-only fixture, bounded for the
    # additional opaque object/catalog/journal nesting. No glob outside this root.
    root = owner_root(path, missing=True)
    if root.exists():
        entries, total = list(root.rglob("*")), 0
        require(len(entries) <= 256, "upload cleanup entry bound")
        for entry in entries:
            info = entry.lstat()
            require(info.st_uid == os.geteuid() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                and info.st_mode & 0o077 == 0 and entry.resolve() == entry
                and len(entry.relative_to(root).parts) <= 8, "unexpected private upload entry")
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, "linked upload entry")
                total += info.st_size
        require(total <= 32 * 1024**2, "upload cleanup byte bound")
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
        value[name] = F["read_usage"](work / f"private-storage-fragments-{name}.json")
    value.update(success=True, expected_peers=read(work / "a01-expected-peers.json"),
        provision=read(work / "cloud-private-upload-provision.json"), **dict.fromkeys(FALSE_CLAIMS, False))
    value["network"] = {name: dict(selected_route=read(work / f"private-storage-fragments-{name}-live-selection.json"),
        privacy={role: read(work / f"private-storage-fragments-{name}-privacy-{role}.json") for role in F["ROLES"]},
        control_privacy=read(work / f"content-provider-adaptive-private-storage-fragments-{name}-control.json"),
        gates=read(work / f"private-storage-fragments-{name}-gates.json")) for name in F["PHASES"]}
    validate_evidence(value)
    return value


def validate_evidence(value):
    require(value["success"] is True and all(value[k] is False for k in FALSE_CLAIMS), "upload scope overstated")
    provision = value["provision"]
    require(type(REVISION) is str and re.fullmatch(r"[0-9a-f]{40}", REVISION)
        and provision["version"] == 1 and provision["kind"] == "cloud-private-file-runtime-provision"
        and provision["pins"] == PINS and provision["pins_sha256"] == hashlib.sha256(PINS_PATH.read_bytes()).hexdigest()
        and all(provision[k] is True for k in ("success", "guest_only", "source_files_verified", "runtime_files_verified", "original_licenses_retained"))
        and all(provision[k] is False for k in ("private_file_created", "peer_storage_proven", "opencloud_server_started")),
        "upload source provenance missing")
    sdk = provision["sdk"]
    require(re.fullmatch(r"[0-9a-f]{64}", sdk["receipt_sha256"])
        and sdk == dict(pins_sha256=HASHES["third_party/opencloud-web-sdk.json"],
            archive_sha256=CLOUD["SDK_SHA"], receipt_sha256=sdk["receipt_sha256"], files_verified=True,
            files=109, source_build_claimed=False, sdk_reads_proven=False), "published SDK provenance absent")
    ui = provision["ui"]
    require(re.fullmatch(r"[0-9a-f]{64}", ui["build_report_sha256"])
        and ui == dict(source_revision="11e699ac82fda4dd113ac3ceb2ecb2dd74574045",
            source_tree="4f13ceee9b21450659266df69a4fac57f25c3bc9",
            pins_sha256=HASHES["third_party/opencloud-web-ui.json"],
            patch_sha256=HASHES["patches/opencloud-web-owner-recovery.patch"],
            build_report_sha256=ui["build_report_sha256"], source_built=True,
            files_verified=True, ui_execution_proven=False), "original UI source build absent")
    require(provision["browser"] == dict(version="140.16.0",
        source_stamp="d864999404b3032f682d74ccc60d1ce38c9ce609",
        archive_sha256="e32aeabcab2e74fe112332fad10f7d9630e14cd6f4564a596a71073018d24508",
        files_verified=True, browser_execution_proven=False), "original guest browser provenance absent")
    require(set(provision["tools"]) == {"gpg", "gpg-agent", "gpgconf", "tar"}, "guest crypto tools absent")
    for tool in provision["tools"].values():
        require(type(tool["bytes"]) is int and tool["bytes"] > 0 and re.fullmatch(r"[0-9a-f]{64}", tool["sha256"])
            and type(tool["package"]) is str and tool["package"] and type(tool["package_version"]) is str
            and tool["package_version"], "guest crypto tool receipt differs")
    initial = value["prepare"]
    geometry = CLOUD["configure"](initial)
    require(initial["authenticated_dav_ranges"] == 4 and initial["grant_payload_bytes"] == [1048576] * 3
        and initial["grant_max_leases"] == [8] * 3 and initial["owner_secrets_exported"] is False
        and all(initial[k] is True for k in ("source_stopped_and_joined", "source_credentials_removed", "owner_distinct_from_all_providers")),
        "baseline import or grants missing")
    deposited, restored = value["upload"], value["restore"]
    require(deposited["baseline"] == CLOUD["upload_report"](initial["ciphertext_bytes"]), "baseline deposit missing")
    ui_record(deposited["ui"], "upload"); ui_record(restored["ui"], "download")
    size = deposited["upload_ciphertext_bytes"]
    require(type(size) is int and 2 * UPLOAD_CHUNK < size <= 3 * UPLOAD_CHUNK and restored["upload_ciphertext_bytes"] == size
        and deposited["committed_fragment_copies"] == 14 and restored["baseline_restores"] == restored["upload_downloads"] == 2,
        "upload/restore counts differ")
    for record, fields in ((deposited, ("service_stopped_and_joined", "both_local_ciphertexts_removed", "original_source_stopped", "private_staging_removed")),
        (restored, ("new_service_and_browser", "all_reads_nonconsuming", "both_local_ciphertexts_absent", "original_source_stopped",
            "service_stopped_and_joined", "private_staging_removed", "retained_identities_unchanged"))):
        require(all(record[k] is True for k in fields), "source-off service lifecycle incomplete")
    added = [dict(reserved_bytes=0, committed_bytes=n, leases=c) for n, c in zip((size - UPLOAD_CHUNK, 2 * UPLOAD_CHUNK, size - UPLOAD_CHUNK), (2, 2, 2))]
    require(deposited["upload_provider_usage"] == restored["upload_provider_usage"] == added, "upload charge lost")
    combined = [dict(reserved_bytes=0, committed_bytes=n + extra["committed_bytes"], leases=c + extra["leases"])
        for n, c, extra in zip(geometry["PROVIDER_BYTES"], geometry["PROVIDER_LEASES"], added)]
    require(value["uploaded_usage"] == value["restored_usage"] == combined
        and all(row["committed_bytes"] <= 1048576 and row["leases"] <= 8 for row in combined)
        and value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3, "actual provider accounting differs")
    require(value["finish"] == dict(baseline=dict(actual_core_cli=True, reopened_copies_confirmed=True,
        all_eight_copies_deleted=True, delete_retry_idempotent=True, final_payload_charge=0),
        all_fourteen_copies_deleted=True, delete_retry_idempotent=True, final_payload_charge=0), "all-copy retirement missing")
    require(value["private_cleanup"] == dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        recovery_keys_removed=True, private_plaintext_removed=True, ciphertext_removed=True,
        fragment_journal_removed=True, user_directory_removed=True), "private cleanup incomplete")
    require(value["withdrawal"] == dict(first_provider_stopped_before_restore=True, first_store_retained=True,
        other_two_providers_serving=True, same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True, agent_restart_claimed=False), "provider withdrawal missing")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
        and isolation["control_gid"] != isolation["agent_gid"] and all(isolation[k] is True for k in (
        "agent_cannot_read_user_state", "client_cannot_read_any_provider_store", "agent_mount_positive_control",
        "all_provider_keys_match_independent_fixture_peers", "three_provider_namespaces_distinct")), "isolation missing")
    require(set(value["network"]) == set(F["PHASES"]), "network phase missing")
    for name, phase in value["network"].items():
        F["validate_network"](phase, value["expected_peers"], value["layout"], name)
    phase = value["network"]["restore"]
    require(phase["gates"]["exit_mptcp_tls_completed"] >= 28, "four protected reconstructions missing")
    app = phase["privacy"]["exit"]["provider_application"]
    require(app["relay5"]["response_payload_bytes"] >= 2 * (2 * CHUNK + geometry["LENGTHS"][-1] + 2 * UPLOAD_CHUNK)
        and app["relay3"]["response_payload_bytes"] >= 2 * (CHUNK + size - 2 * UPLOAD_CHUNK), "baseline/upload survivor bytes missing")


def validate_report(value, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision
        and value["schema_version"] == 1 and value["report_kind"] == "volparossa-cloud-private-upload"
        and value["phase"] == "cloud-private-upload-complete" and value["runner_exit_status"] == 0
        and value["success"] is True and value["observed_blocker"] is None
        and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
        and value["host_state"]["unchanged"] is True, "upload source/cleanup proof missing")
    validate_evidence(value["cloud"])


def main(args):
    if args == ["export-names"]:
        print("\n".join(EXPORT_NAMES)); return
    if len(args) == 10 and args[0] == "prepare":
        value = prepare(owner_root(args[1]), *args[2:])
    elif len(args) == 7 and args[0] in F["PHASES"]:
        value = {"upload": upload, "restore": restore, "finish": finish}[args[0]](owner_root(args[1]), args[2], args[3], args[4:])
    elif len(args) == 2 and args[0] == "cleanup":
        value = cleanup(args[1])
    elif len(args) == 3 and args[0] == "evidence":
        value = build_evidence(Path(args[1]))
        Path(args[2]).write_text(json.dumps(value, sort_keys=True) + "\n")
    elif len(args) == 3 and args[0] == "report":
        validate_report(read(Path(args[1])), args[2]); value = dict(success=True)
    else:
        raise ValueError("unknown upload fixture command")
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame): raise ValueError("upload fixture interrupted")
    for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, interrupted)
    try: main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError):
        print(json.dumps(dict(success=False, kind="cloud-private-upload-failure", stage=STAGE,
            ui_stage=UI_STAGE, ui_failure=UI_FAILURE)))
        sys.exit(1)
