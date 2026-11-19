# SPDX-License-Identifier: GPL-3.0-only
"""Owner-side cutover assertions for the opt-in real Cloud UI / peer trial."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time


def require(condition, reason="retained owner upload proof incomplete"):
    if not condition:
        raise ValueError(reason)


def read(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_size <= 65536)
    return json.loads(path.read_bytes())


def targets(root):
    result = [p for p in (root / "o").iterdir() if p.name != "LOCK"]
    require(len(result) <= 1)
    for path in result:
        info = path.lstat()
        require(re.fullmatch(r"object-[0-9a-f]{32}", path.name) and path.resolve() == path
                and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and info.st_uid == os.geteuid())
    return result


def stop_at_commit(root, service, browser_driver):
    # The journal is atomically replaced by the real CLI. A copy marked committed
    # has the provider's acknowledgement. No test-side hook changes the deposit.
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        require(service.poll() is None and browser_driver.poll() is None)
        for obj in targets(root):
            require(not (obj / "READY.json").exists())
            path = obj / "journal/fragment-0000/replicas.json"
            try:
                copies = read(path)["copies"]
            except FileNotFoundError:
                continue
            if any(copy["charge"] == "committed" for copy in copies):
                service.send_signal(signal.SIGTERM)
                browser_driver.send_signal(signal.SIGTERM)
                return
        time.sleep(0.05)
    raise ValueError("no committed copy before owner stop")


def interrupted_ui(value):
    require(value["version"] == 1 and value["kind"] == "cloud-owner-upload-original-ui"
            and value["mode"] == "upload" and value["success"] is False and value["stage"] == "upload_commit"
            and value["original_files_ui"] is True and value["synthetic_backend"] is False
            and value["original_file_input_used"] is True and value["wrong_token_denied"] is True
            and value["upload_receipt"] is None and value["upload_201_observed"] is False
            and value["uploaded_file_listed"] is False and value["browser_stopped_and_joined"] is True
            and value["private_profile_removed"] is True and value["browser_version"] == "140.16.0"
            and value["owner_secrets_exported"] is False)
    observation = value["upload_observation"]
    require(observation["puts"] >= 1 and observation["created"] == 0
            and 201 not in observation["statuses"])
    return dict(original_file_input_used=True, wrong_token_denied=True, puts=observation["puts"],
                upload_201_observed=False, browser_stopped_and_joined=True, private_profile_removed=True)


def file_hash(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid() and info.st_nlink == 1 and 0 < info.st_size <= limit)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").digest()


def identity(root, size, count):
    obj, = targets(root)
    directory = obj / "journal"
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
    hashes = tuple(file_hash(obj / name, 1048576) for name in (
        "journal/fragments.json", "catalog/receipt.json", "catalog/catalog.pgp",
        "core.json", "bundle/receipt.json", "bundle/file.pgp"))
    require((obj / "bundle/file.pgp").stat().st_size == size)
    leases, bindings, charges = [], [], []
    for index in range(count):
        fragment = directory / f"fragment-{index:04}"
        copies = read(fragment / "replicas.json")["copies"]
        require(len(copies) == 2)
        for number, copy in enumerate(copies):
            archive = read(fragment / f"copy-{number}/archive.json")
            bindings.append(tuple(archive[k] for k in ("owner_key", "provider_key", "grant_hex",
                                                        "archive_id", "sha256", "ciphertext_bytes", "requested_expiry")))
            leases.append(archive["lease"])
            charge = copy["charge"]
            require(charge in ("committed", "reserved", "unattempted", "uncertain")
                    and (charge != "committed" or archive["lease"] is not None))
            charges.append(charge)
    return (obj.name, info.st_dev, info.st_ino, hashes, bindings), leases, charges


def resume(root, source, node, size, geometry, config, create, run):
    obj, = targets(root)
    require(not (obj / "READY.json").exists() and not list((root / "w").iterdir()))
    require(not any((obj / "journal").glob(".fragment-transfer-*")), "fragment staging survived owner stop")
    count = len(geometry(size)["lengths"])
    first, leases, charges = identity(root, size, count)
    committed = charges.count("committed")
    require(0 < committed < len(charges) and "unattempted" in charges, "partial committed journal missing")
    request = root / "resume-request.json"
    create(request, json.dumps(dict(version=1, space="owner-uploads", name="private-upload.bin",
                                   bearerToken=config["bearerToken"])).encode())
    command = [node, source / "scripts/cloud-serve.mjs", "resume-upload",
               "--config", root / "service.json", "--request", request]
    try:
        marker = None
        for _ in range(2):
            require(run(command, deadline=900) == dict(version=1, kind="volparossa-cloud-owner-upload-resume", state="ready"))
            final, current_leases, current_charges = identity(root, size, count)
            require(first == final and current_charges == ["committed"] * len(charges)
                    and all(new is not None and (old is None or old == new) for old, new in zip(leases, current_leases)),
                    "resumed identities or acknowledgements differ")
            ready = obj / "READY.json"
            ready_hash = file_hash(ready, 256)
            info = ready.stat()
            require(read(ready) == dict(version=1, catalogSha256=read(obj / "catalog/receipt.json")["cipher_sha256"]))
            state = (info.st_dev, info.st_ino, info.st_ctime_ns, ready_hash, current_leases)
            require(marker is None or state == marker)
            marker = state
    finally:
        request.unlink()
    require(not list((root / "w").iterdir()))
    return dict(committed_before=committed, unattempted_before=charges.count("unattempted"),
                reserved_before=charges.count("reserved"), uncertain_before=charges.count("uncertain"),
                total_copies=len(charges), no_ready_before=True, uploader_plaintext_removed=True,
                original_journal_and_bindings_preserved=True, prior_leases_preserved=True,
                same_catalog_and_ciphertext=True, anonymous_staging_released=True,
                owner_command_ready_twice=True, same_ready_marker=True)


def validate(value, total):
    require(set(value) == {"interrupted_ui", "recovery"})
    ui, report = value["interrupted_ui"], value["recovery"]
    puts = ui["puts"]
    require(type(puts) is int and 1 <= puts <= 4 and ui == dict(original_file_input_used=True,
        wrong_token_denied=True, puts=puts, upload_201_observed=False,
        browser_stopped_and_joined=True, private_profile_removed=True))
    counts = [report[name] for name in ("committed_before", "unattempted_before", "reserved_before", "uncertain_before")]
    require(all(type(v) is int and v >= 0 for v in counts) and counts[0] > 0 and counts[1] > 0
            and sum(counts) == total and report["total_copies"] == total)
    rest = {"no_ready_before", "uploader_plaintext_removed", "original_journal_and_bindings_preserved",
            "prior_leases_preserved", "same_catalog_and_ciphertext", "anonymous_staging_released",
            "owner_command_ready_twice", "same_ready_marker"}
    require(set(report) == rest | {"committed_before", "unattempted_before", "reserved_before", "uncertain_before", "total_copies"}
            and all(report[key] is True for key in rest))
