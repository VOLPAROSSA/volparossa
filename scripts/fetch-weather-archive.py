#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify historical Weather release inputs as private, non-executable data.

validate is offline and accepts the blocked schema. fetch refuses blocked before
network or output creation. No URL, admission, module, or authority override exists.
A successful report is the atomic completion marker; interrupted output is never
reused. SIGKILL cannot guarantee cleanup. This is not current product acceptance.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("weather_preservation", ROOT / "scripts/preserve-weather-artifacts.py")
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)
Rejected, require = P.Rejected, P.require
REPOSITORY = "VOLPAROSSA/volparossa"
COMMIT = "89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1"
TAG = "evidence/weather-inputs-2026-10-23"
BASE = "/repos/" + REPOSITORY
LOCK = ROOT / "tests/helper/weather-release-archive-v1.json"
MANIFEST_BYTES = 15987
MANIFEST_SHA = "0201e6187e1aa0e0d50dbd1537449cd8b39c59615c97d3cb1eeef4c84b1a6795"
SNAPSHOTS = {
    "snapshot-drizzli-v4": (P.ADMISSIONS[0], "2011e08002cf756683e8d3c195c6116957005cd65f5b0ab51a28499673bae5d3"),
    "snapshot-overmorrow-v5": (P.ADMISSIONS[1], "ae5737106fa68f9da706e360181b5b46066a867d7b970341e4d2b31bfa4e5a6e"),
    "snapshot-android-v6": (P.ADMISSIONS[2], "e29df84c31447d32727526e926ba96c0c9975326c972069ef619de8faf6efd4d"),
    "snapshot-decoder-abi": (P.ADMISSIONS[3], "d3e676fd67f9c2930dc4d65524b37fa6d53868c3ba1b425ca5719190a3aeed29"),
}
CONSUMERS = {
    "decoder-abi": {"decoder": "decoder"},
    "drizzli-v4": {"decoder": "decoder", "abi": "abi", "assets": "drizzli-assets", "proof": "drizzli-proof"},
    "overmorrow-v5": {"decoder": "decoder", "abi": "abi", "assets": "overmorrow-assets", "proof": "overmorrow-proof"},
    "android-v6": {"decoder": "decoder", "abi": "abi"},
}
FLAGS = {"runtime_executed": False, "current_origin_acquisition_proven": False, "joined_delivery_proven": False}


def same(left, right):
    # JSON equality must not make bool an integer or integer a float.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def positive(value):
    return type(value) is int and 0 < value <= 2**63 - 1


def context():
    snapshots, pins, receipts, provenance_id = P.load_admissions(ROOT)
    records = {}
    for role, (path, expected) in SNAPSHOTS.items():
        raw = snapshots[path]
        require(P.sha256(raw) == expected, "local historical admission differs")
        records[role] = dict(id=None, name=Path(path).name, bytes=len(raw), sha256=expected,
                             origin=None, admission_path=path)
    sources = {
        "decoder": json.loads(snapshots[P.ADMISSIONS[0]])["artifacts"]["decoder"],
        "abi": json.loads(snapshots[P.ADMISSIONS[0]])["artifacts"]["abi"],
        "decoder-provenance": pins[provenance_id],
    }
    for prefix, path in (("drizzli", P.ADMISSIONS[0]), ("overmorrow", P.ADMISSIONS[1])):
        for role in ("proof", "assets"):
            sources[prefix + "-" + role] = json.loads(snapshots[path])["artifacts"][role]
    for role, pin in sources.items():
        origin = dict(repository=pin["repository"], artifact_id=pin["id"], artifact_name=pin["name"],
                      run_id=pin["run_id"], run_attempt=1, commit=pin["commit"])
        records[role] = dict(id=None, name=pin["sha256"] + ".zip", bytes=pin["bytes"],
                             sha256=pin["sha256"], origin=origin, admission_path=None)
    records["preservation-manifest"] = dict(id=None, name="manifest.json", bytes=MANIFEST_BYTES,
        sha256=MANIFEST_SHA, origin=None, admission_path=None)
    return records, snapshots, pins, receipts, provenance_id


def validate(lock):
    expected, *_ = context()
    require(isinstance(lock, dict) and set(lock) == {"schema", "kind", "scope", "state", "blocked_reason",
        "historical_core_commit", "release", "assets"}, "unexpected admission fields")
    require(type(lock["schema"]) is int and lock["schema"] == 1 and
        lock["kind"] == "volparossa-weather-release-archive-admission" and
        lock["scope"] == "historical-weather-ci-inputs-only" and
        lock["historical_core_commit"] == COMMIT, "invalid archive admission scope")
    state = lock["state"]
    require(state in ("blocked", "admitted"), "invalid admission state")
    admitted = state == "admitted"
    require(lock["blocked_reason"] == (None if admitted else "redistribution-review-incomplete"),
            "invalid blocked reason")
    release = lock["release"]
    require(isinstance(release, dict) and set(release) == {"repository", "repository_id", "id", "tag",
        "target_commit", "tag_object"}, "unexpected release admission fields")
    require(release["repository"] == REPOSITORY and release["tag"] == TAG and
            release["target_commit"] == COMMIT, "release scope differs")
    require(all(positive(release[key]) if admitted else release[key] is None
                for key in ("repository_id", "id")), "invalid release identifiers")
    require(same(release["tag_object"], dict(type="commit", sha=COMMIT) if admitted else None),
            "invalid lightweight tag object")
    assets = lock["assets"]
    require(isinstance(assets, dict) and set(assets) == set(expected), "expected exactly twelve archive assets")
    ids = []
    for role, pin in expected.items():
        record = assets[role]
        require(isinstance(record, dict) and set(record) == set(pin), "unexpected asset fields")
        require(positive(record["id"]) if admitted else record["id"] is None, "invalid asset identifier")
        require(same({**record, "id": None}, pin), "asset pin or historical admission differs")
        ids.append(record["id"])
    require(not admitted or len(set(ids)) == 12, "duplicate asset identifier")
    return dict(eligible=admitted, state=state, scope=lock["scope"], **FLAGS)


def read_lock():
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return P.parse_json(P.read_bounded(fd, P.MAX_JSON))
    finally:
        os.close(fd)


def api_paths(lock):
    return {BASE, BASE + "/releases/" + str(lock["release"]["id"]),
            BASE + "/git/ref/tags/" + TAG,
            BASE + "/releases/" + str(lock["release"]["id"]) + "/assets?per_page=100&page=1",
            *(BASE + "/releases/assets/" + str(pin["id"]) for pin in lock["assets"].values())}


class Transport:
    """Only authenticated fixed GitHub GETs; stderr and caller debug env suppressed."""
    def __init__(self, lock):
        self.allowed = api_paths(lock)

    def get(self, endpoint, target, maximum, binary=False, timeout=180):
        require(endpoint in self.allowed, "unapproved API endpoint")
        token = os.environ.get("GH_TOKEN")
        require(isinstance(token, str) and token and "\n" not in token and "\r" not in token,
                "GH_TOKEN required for authenticated archive retrieval")
        env = {key: os.environ[key] for key in ("PATH", "HOME", "SYSTEMROOT") if key in os.environ}
        env.update(GH_TOKEN=token, GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1",
                   GH_NO_EXTENSION_UPDATE_NOTIFIER="1")
        command = ["gh", "api", "--hostname", "github.com", "--method", "GET", "--header",
                   "Accept: " + ("application/octet-stream" if binary else "application/vnd.github+json"), endpoint]
        process = None
        deadline, count = time.monotonic() + timeout, 0
        try:
            with P.publication_signals_blocked():
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "GitHub archive timeout")
                    if not selector.select(min(remaining, 1)):
                        continue
                    data = os.read(process.stdout.fileno(), P.CHUNK)
                    if not data:
                        break
                    count += len(data)
                    require(count <= maximum, "GitHub archive response exceeds cap")
                    target.write(data)
                require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                        "authenticated GitHub archive GET failed")
        finally:
            if process is not None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                process.stdout.close()

    def json(self, endpoint):
        stream = io.BytesIO()
        self.get(endpoint, stream, P.MAX_JSON)
        return P.parse_json(stream.getvalue())


def validate_release(lock, repository, release, tag, assets, now):
    r = lock["release"]
    require(isinstance(repository, dict) and repository.get("full_name") == REPOSITORY and
        positive(repository.get("id")) and repository["id"] == r["repository_id"], "repository identity differs")
    require(isinstance(release, dict) and positive(release.get("id")) and release["id"] == r["id"] and
        release.get("tag_name") == TAG and release.get("draft") is False and
        release.get("immutable") is True and release.get("prerelease") is True,
        "release identity or immutable prerelease state differs")
    require(P.timestamp(release["published_at"]) <= now, "release publication is in the future")
    require(isinstance(tag, dict) and tag.get("ref") == "refs/tags/" + TAG and
        isinstance(tag.get("object"), dict) and tag["object"].get("type") == "commit" and
        tag["object"].get("sha") == COMMIT, "exact lightweight tag target differs")
    require(isinstance(assets, list) and len(assets) == 12, "release must contain exactly twelve assets")
    observed = {}
    for item in assets:
        require(isinstance(item, dict) and positive(item.get("id")) and item["id"] not in observed,
                "invalid or duplicate release asset identifier")
        require(type(item.get("size")) is int and item["size"] > 0 and item.get("state") == "uploaded",
                "invalid release asset size or state")
        observed[item["id"]] = {key: item.get(key) for key in ("name", "size", "digest")}
    expected = {pin["id"]: dict(name=pin["name"], size=pin["bytes"], digest="sha256:" + pin["sha256"])
                for pin in lock["assets"].values()}
    require(same(observed, expected), "release asset set, name, size or digest differs")


def small_asset(transport, pin):
    stream = io.BytesIO()
    transport.get(BASE + "/releases/assets/" + str(pin["id"]), stream, pin["bytes"], binary=True)
    raw = stream.getvalue()
    require(len(raw) == pin["bytes"] and P.sha256(raw) == pin["sha256"], "asset bytes or SHA-256 differs")
    return raw


def validate_manifest(raw, snapshot_bytes):
    records, snapshots, pins, _receipts, _provenance_id = context()
    require(len(raw) == records["preservation-manifest"]["bytes"] and
        P.sha256(raw) == records["preservation-manifest"]["sha256"], "manifest bytes or SHA-256 differs")
    manifest = P.parse_json(raw)
    require(set(manifest) == {"schema", "capture_started_at", "captured_at", "admissions", "artifacts", *P.FLAGS},
            "unexpected preservation manifest fields")
    require(manifest["schema"] == P.SCHEMA and all(manifest[key] is value for key, value in P.FLAGS.items()),
            "invalid historical preservation scope")
    captured = P.timestamp(manifest["captured_at"])
    require(P.timestamp(manifest["capture_started_at"]) <= captured <= P.utcnow(), "invalid historical capture time")
    require(same(manifest["admissions"], {name: P.sha256(raw) for name, raw in snapshots.items()}),
            "manifest historical admissions differ")
    require(snapshot_bytes == snapshots, "release admission snapshot bytes differ")
    require(isinstance(manifest["artifacts"], dict) and set(manifest["artifacts"]) == set(pins),
            "manifest artifact set differs")
    for key, pin in pins.items():
        entry = manifest["artifacts"][key]
        require(isinstance(entry, dict) and set(entry) == {"pin", "metadata", "inspection"} and
                same(entry["pin"], pin), "manifest artifact provenance differs")
        P.validate_metadata(pin, entry["metadata"], captured)  # capture time, never current Actions availability
        inspection = entry["inspection"]
        require(isinstance(inspection, dict) and set(inspection) == {"members", "expanded_bytes", "abi_receipts_checked"}
            and all(type(value) is int and value >= 0 for value in inspection.values()) and
            0 < inspection["members"] <= P.MAX_MEMBERS and inspection["expanded_bytes"] <= P.MAX_EXPANDED,
            "invalid historical ZIP inspection")
    return manifest


def mkdir_child(parent, name):
    os.mkdir(name, mode=0o700, dir_fd=parent)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.fchmod(fd, 0o700)
        P.Store.check_dir(fd)
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        os.rmdir(name, dir_fd=parent)
        raise


def write_file(parent, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def extract(fd, target):
    """Caller has inspected the entire ZIP before any member is written."""
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), "rb") as stream, zipfile.ZipFile(stream) as archive:
        total = 0
        for info in archive.infolist():
            require(not any(ord(c) == 127 for c in info.filename), "control character in ZIP path")
            parts = info.filename.rstrip("/").split("/")
            parent = os.dup(target)
            try:
                for part in parts[:-1]:
                    try:
                        os.mkdir(part, 0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                    P.Store.check_dir(parent)
                if info.is_dir():
                    try:
                        os.mkdir(parts[-1], 0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                    continue
                output = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                os.fchmod(output, 0o600)
                count = 0
                with os.fdopen(output, "wb") as outgoing, archive.open(info) as incoming:
                    while data := incoming.read(P.CHUNK):
                        count += len(data)
                        total += len(data)
                        require(count <= info.file_size and count <= P.MAX_MEMBER and total <= P.MAX_EXPANDED,
                                "extracted ZIP stream exceeds cap")
                        outgoing.write(data)
                    require(count == info.file_size, "extracted ZIP member is truncated")
            finally:
                os.close(parent)


def fetch(lock, consumer, output, transport=None):
    eligibility = validate(lock)
    require(eligibility["eligible"], "archive blocked: redistribution-review-incomplete")
    require(consumer in CONSUMERS, "unknown archive consumer")
    output = Path(output)
    require(output.is_absolute() and str(output) != "/" and ".." not in output.parts and
            not any(ord(c) < 32 or ord(c) == 127 for c in str(output)), "absolute new output directory required")
    transport = transport or Transport(lock)
    release = lock["release"]
    validate_release(lock, transport.json(BASE), transport.json(BASE + "/releases/" + str(release["id"])),
        transport.json(BASE + "/git/ref/tags/" + TAG),
        transport.json(BASE + "/releases/" + str(release["id"]) + "/assets?per_page=100&page=1"), P.utcnow())
    raw = small_asset(transport, lock["assets"]["preservation-manifest"])
    snapshots = {path: small_asset(transport, lock["assets"][role]) for role, (path, _) in SNAPSHOTS.items()}
    manifest = validate_manifest(raw, snapshots)
    parent, root, scratch, provenance = None, None, None, None
    owned = None
    created = False
    try:
        parent = P.directory(output.parent)
        st = os.fstat(parent)
        require(st.st_uid == os.geteuid() and not stat.S_IMODE(st.st_mode) & 0o022, "unsafe output parent")
        with P.publication_signals_blocked():
            root = mkdir_child(parent, output.name)
            created = True
            owned = os.fstat(root)
        scratch = mkdir_child(root, ".pending")
        provenance = mkdir_child(root, "provenance")
        measurements = {}
        # Download and inspect ALL selected ZIPs before extracting ANY selected ZIP.
        for directory, role in CONSUMERS[consumer].items():
            pin = lock["assets"][role]
            fd = os.open(directory + ".zip", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=scratch)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(os.dup(fd), "wb") as incoming:
                    transport.get(BASE + "/releases/assets/" + str(pin["id"]), incoming, pin["bytes"], binary=True)
                inspection = P.inspect_zip(fd, pin)
                # Preservation's path guard predates the DEL control-character guard.
                os.lseek(fd, 0, os.SEEK_SET)
                with os.fdopen(os.dup(fd), "rb") as stream, zipfile.ZipFile(stream) as archive:
                    require(all(not any(ord(c) == 127 for c in row.filename) and row.extract_version < 45
                                for row in archive.infolist()), "ZIP control character or ZIP64 rejected")
                    for row in archive.infolist():
                        offset = 0
                        while offset < len(row.extra):
                            require(offset + 4 <= len(row.extra), "malformed ZIP extra field")
                            kind, size = struct.unpack_from("<HH", row.extra, offset)
                            offset += 4
                            require(kind != 1 and offset + size <= len(row.extra), "ZIP64 or malformed ZIP extra field")
                            offset += size
                original = manifest["artifacts"][str(pin["origin"]["artifact_id"])]["inspection"]
                require(same(inspection, original), "ZIP inspection differs from historical manifest")
                measurements[role] = dict(id=pin["id"], name=pin["name"], bytes=pin["bytes"],
                                          sha256=pin["sha256"], **inspection)
            finally:
                os.close(fd)
        for directory in CONSUMERS[consumer]:
            target = mkdir_child(root, directory)
            fd = os.open(directory + ".zip", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=scratch)
            try:
                extract(fd, target)
            finally:
                os.close(target)
                os.close(fd)
            os.unlink(directory + ".zip", dir_fd=scratch)
        os.close(scratch)
        scratch = None
        os.rmdir(".pending", dir_fd=root)
        # Only bounded, public identities and digests. No host paths, API bodies or credentials.
        report = dict(schema=1, kind="volparossa-weather-archive-input-verification", consumer=consumer,
            scope="historical-input-integrity-only", input_verification_only=True, historical_core_commit=COMMIT,
            repository=REPOSITORY, repository_id=release["repository_id"], release_id=release["id"],
            tag=TAG, tag_object=release["tag_object"], captured_at=manifest["captured_at"],
            verified_at=P.stamp(P.utcnow()), assets={role: {key: pin[key] for key in ("id", "name", "bytes", "sha256")}
                for role, pin in lock["assets"].items()}, received_zips=measurements,
            workflow=dict(commit=os.environ.get("GITHUB_SHA"), run_id=os.environ.get("GITHUB_RUN_ID"),
                          run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT")), **FLAGS)
        for key, pattern in (("commit", r"[0-9a-f]{40}"), ("run_id", r"[1-9][0-9]{0,19}"),
                             ("run_attempt", r"[1-9][0-9]{0,9}")):
            value = report["workflow"][key]
            require(value is None or isinstance(value, str) and re.fullmatch(pattern, value), "invalid current workflow identity")
        pending = ".report-" + secrets.token_hex(8)
        write_file(provenance, pending, P.encoded(report))
        with P.publication_signals_blocked():
            os.link(pending, "archive-report.json", src_dir_fd=provenance, dst_dir_fd=provenance, follow_symlinks=False)
            os.unlink(pending, dir_fd=provenance)
            os.fsync(provenance)
        return report
    except BaseException:
        if created:
            # Never clean a pre-existing path or a replacement inode.
            current = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
            require((current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino), "owned output was replaced")
            shutil.rmtree(output.name, dir_fd=parent)
        raise
    finally:
        for fd in (provenance, scratch, root, parent):
            if fd is not None:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("validate")
    download = commands.add_parser("fetch")
    download.add_argument("--consumer", choices=tuple(CONSUMERS), required=True)
    download.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    handlers = {number: signal.signal(number, P.interrupted) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        lock = read_lock()
        result = validate(lock) if args.operation == "validate" else fetch(lock, args.consumer, args.output)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError,
            subprocess.SubprocessError, zipfile.BadZipFile, struct.error, NotImplementedError) as error:
        print("archive rejected: " + (str(error) if isinstance(error, Rejected) else type(error).__name__), file=sys.stderr)
        return 1
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    sys.exit(main())
