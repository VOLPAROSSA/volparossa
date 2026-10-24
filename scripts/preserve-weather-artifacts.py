#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Preserve pinned Weather CI inputs; never admit, extract, or execute them.

capture --store PRIVATE_DIRECTORY [--repo-root CHECKOUT]
    Uses authenticated gh API GETs, including fresh metadata for preseeded blobs.
    Preseed only blobs/<pinned sha256>.zip (0700 directories, 0600 files).
verify --store PRIVATE_DIRECTORY --manifest-sha256 SEPARATELY_RETAINED_HASH
    Offline integrity and historical provenance only, including after CI expiry.
    The manifest hash must be retained outside the archive as the capture anchor;
    metadata is a historical authenticated API observation, not a signed attestation.

SIGTERM/SIGINT unwind cleanup and roll back incomplete publication. SIGKILL or
host failure cannot run cleanup: preserve that store, start a new private store,
and reuse only independently rehashed blobs; never delete its lock or treat a
partial manifest as a capture anchor. No automatic repair or overwrite occurs.

No existing admission consumer reads this archive or gains an expiry exception.
Only Python's standard library and, for capture, an existing authenticated gh are used.
"""

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import secrets
import signal
import stat
import struct
import subprocess
import sys
import time
import zipfile
import zlib

ADMISSIONS = (
    "tests/integration/weather-public-drizzli-v4.json",
    "tests/integration/weather-public-overmorrow-v5.json",
    "tests/integration/weather-public-android-v6.json",
    "tests/helper/weather-decoder-abi-v1.json",
)
MAX_ZIP = 192 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_EXPANDED = 768 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_JSON = 4 * 1024 * 1024
CHUNK = 64 * 1024
SCHEMA = "volparossa-weather-historical-input-preservation-v1"
FLAGS = {
    "historical_input_preservation_only": True,
    "live_artifact_availability_verified": False,
    "runtime_executed": False,
}


class Rejected(ValueError):
    """An archive or its provenance failed a required check."""


def require(condition, message):
    if not condition:
        raise Rejected(message)


@contextlib.contextmanager
def publication_signals_blocked():
    # Linux target: defer interruption only across a short publication/ownership
    # bookkeeping transaction. Pending signals unwind immediately on unmask.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def interrupted(_number, _frame):
    # A second signal must not interrupt the cleanup/reaping already in progress.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise Rejected("interrupted; incomplete capture has no successful manifest")


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def stamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def timestamp(value):
    require(isinstance(value, str) and value.endswith("Z"), "UTC timestamp required")
    parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    require(parsed.utcoffset() == dt.timedelta(0), "UTC timestamp required")
    return parsed


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "invalid SHA-256")
    return value


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def regular(fd, private=False):
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "regular file without hard links required")
    if private:
        require(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600,
                "archive files must be owned by this user with mode 0600")
    return st


def read_bounded(fd, maximum):
    require(regular(fd).st_size <= maximum, "file exceeds size cap")
    with os.fdopen(os.dup(fd), "rb") as source:
        result = source.read(maximum + 1)
    require(len(result) <= maximum, "file exceeds size cap")
    return result


def directory(path, create=False):
    """Walk with no-follow dirfds, including ancestors; never follow a symlink."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute path without parent traversal required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            if create and index == len(path.parts) - 2:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class Store:
    def __init__(self, path, create=False):
        self.fd = directory(path, create)
        self.dirs = {}
        try:
            self.check_dir(self.fd)
            for name in ("blobs", "admissions"):
                if create:
                    try:
                        os.mkdir(name, 0o700, dir_fd=self.fd)
                    except FileExistsError:
                        pass
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
                self.dirs[name] = fd
                self.check_dir(fd)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def check_dir(fd):
        st = os.fstat(fd)
        require(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
                "archive directories must be owned by this user with mode 0700")

    def close(self):
        for fd in self.dirs.values():
            os.close(fd)
        self.dirs.clear()
        os.close(self.fd)

    def parent(self, section):
        return self.fd if section is None else self.dirs[section]

    def open(self, name, section=None, create=False):
        require(name and "/" not in name and name not in (".", ".."), "invalid store filename")
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDWR | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY)
        fd = os.open(name, flags, 0o600, dir_fd=self.parent(section))
        try:
            regular(fd, private=True)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def read(self, name, section=None):
        fd = self.open(name, section)
        try:
            return read_bounded(fd, MAX_JSON)
        finally:
            os.close(fd)

    def write(self, name, data, section=None):
        # Publish complete bytes without overwriting any existing destination.
        require(name and "/" not in name and name not in (".", ".."), "invalid store filename")
        temporary = ".pending-" + secrets.token_hex(16)
        fd = None
        parent = self.parent(section)
        published = False
        try:
            with publication_signals_blocked():
                fd = self.open(temporary, section, create=True)
            with os.fdopen(os.dup(fd), "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            with publication_signals_blocked():
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                published = True
                os.unlink(temporary, dir_fd=parent)
                os.fsync(parent)
        except BaseException:
            if published:
                os.unlink(name, dir_fd=parent)
            raise
        finally:
            if fd is not None:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass


def load_admissions(root):
    snapshots, pins = {}, {}
    for name in ADMISSIONS:
        path = root / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            raw = read_bounded(fd, MAX_JSON)
        finally:
            os.close(fd)
        snapshots[name] = raw
        record = parse_json(raw)
        if name == ADMISSIONS[-1]:
            abi = record
            continue
        for pin in record["artifacts"].values():
            key = str(pin["id"])
            require(key not in pins or pins[key] == pin, "conflicting admission pins")
            pins[key] = dict(pin)
    decoder = abi["evidence"]["artifacts"]["decoder"]
    require(pins[str(decoder["id"])]["sha256"] == decoder["sha256"], "ABI decoder differs")
    decoder_pin = pins[str(decoder["id"])]
    require(abi["hosted_run"]["attempt"] == 1 and
            abi["hosted_run"]["id"] == decoder_pin["run_id"] and
            abi["weather_commit"] == decoder_pin["commit"], "ABI source/run/attempt differs")
    provenance = abi["evidence"]["artifacts"]["provenance"]
    # This record pins only ID/digest; name/run/source derive from its ABI binding.
    # Exact original ZIP length was independently inventoried before preservation.
    pin = dict(provenance, bytes=35901, repository=pins[str(decoder["id"])]["repository"],
               commit=abi["weather_commit"], run_id=abi["hosted_run"]["id"],
               name="hosted-input-provenance-" + abi["weather_commit"])
    require(str(pin["id"]) not in pins, "duplicate provenance pin")
    pins[str(pin["id"])] = pin
    require(len(pins) == 7, "expected seven distinct Weather artifacts")
    for pin in pins.values():
        require(set(pin) == {"bytes", "repository", "commit", "run_id", "name", "id", "sha256"},
                "unexpected admission pin fields")
        require(type(pin["id"]) is int and pin["id"] > 0 and
                type(pin["run_id"]) is int and pin["run_id"] > 0 and
                type(pin["bytes"]) is int and 0 < pin["bytes"] <= MAX_ZIP, "invalid pin size/IDs")
        require(pin["repository"] in ("VOLPAROSSA/volparossa", "VOLPAROSSA/volparossa-weather"),
                "unexpected repository")
        require(re.fullmatch(r"[0-9a-f]{40}", pin["commit"]), "invalid source commit")
        digest(pin["sha256"])
    receipts = abi["evidence"]["receipts"]
    require(isinstance(receipts, dict) and len(receipts) == 11, "expected eleven ABI receipts")
    for expected in receipts.values():
        digest(expected)
    return snapshots, pins, receipts, str(provenance["id"])


def minimal_metadata(artifact, run):
    a = {k: artifact[k] for k in ("id", "name", "size_in_bytes", "url", "archive_download_url",
                                  "expired", "digest", "created_at", "updated_at", "expires_at")}
    a["workflow_run"] = {k: artifact["workflow_run"][k] for k in
                         ("id", "repository_id", "head_repository_id", "head_sha")}
    r = {k: run[k] for k in ("id", "head_sha", "run_attempt", "status", "conclusion",
                             "created_at", "updated_at", "url")}
    for name in ("repository", "head_repository"):
        r[name] = {k: run[name][k] for k in ("id", "full_name")}
    return {"artifact": a, "run": r}


def validate_metadata(pin, metadata, captured):
    a, r = metadata["artifact"], metadata["run"]
    require(metadata == minimal_metadata(a, r), "unexpected metadata fields")
    base = "https://api.github.com/repos/" + pin["repository"] + "/actions/"
    expected = {"id": pin["id"], "name": pin["name"], "size_in_bytes": pin["bytes"],
                "url": base + "artifacts/" + str(pin["id"]),
                "archive_download_url": base + "artifacts/" + str(pin["id"]) + "/zip",
                "digest": "sha256:" + pin["sha256"]}
    require(all(a.get(k) == v and type(a.get(k)) is type(v) for k, v in expected.items()),
            "artifact identity, digest or size differs from admission")
    require(a["expired"] is False and timestamp(a["expires_at"]) > captured,
            "artifact expired at capture")
    require(type(r["id"]) is int and r["id"] == pin["run_id"] and
            type(r["run_attempt"]) is int and r["run_attempt"] == 1 and
            r["head_sha"] == pin["commit"] and r["status"] == "completed" and
            r["conclusion"] == "success" and r["url"] == base + "runs/" + str(pin["run_id"]),
            "run source, attempt or success differs from admission")
    repo, head = r["repository"], r["head_repository"]
    require(repo == head and repo["full_name"] == pin["repository"] and
            type(repo["id"]) is int and repo["id"] > 0, "run repository differs")
    require(a["workflow_run"] == {"id": pin["run_id"], "head_sha": pin["commit"],
                                     "repository_id": repo["id"], "head_repository_id": repo["id"]},
            "artifact workflow source differs")
    require(timestamp(r["created_at"]) <= timestamp(a["created_at"]) <=
            timestamp(a["updated_at"]) <= timestamp(r["updated_at"]) <= captured,
            "metadata dates are future or inconsistent at capture")


def zip_directory_bound(fd, size):
    # Bound central-directory parsing before ZipFile allocates its entry objects.
    # These seven small archives do not require ZIP64 or multi-disk support.
    tail_size = min(size, 65535 + 22)
    tail = os.pread(fd, tail_size, size - tail_size)
    end = tail.rfind(b"PK\x05\x06")
    require(end >= 0 and len(tail) - end >= 22, "missing ZIP end record")
    _, disk, central_disk, count_disk, count, central_size, offset, comment = struct.unpack(
        "<4s4H2LH", tail[end:end + 22])
    require(end + 22 + comment == len(tail) and disk == central_disk == 0 and
            count == count_disk and 0 < count <= MAX_MEMBERS and
            central_size <= MAX_JSON and offset + central_size == size - tail_size + end,
            "ZIP directory bounds, ZIP64 or multi-disk archive rejected")
    return count


def inspect_zip(fd, pin, receipts=None):
    require(regular(fd).st_size == pin["bytes"], "ZIP size differs")
    os.lseek(fd, 0, os.SEEK_SET)
    hasher, count = hashlib.sha256(), 0
    while data := os.read(fd, CHUNK):
        count += len(data)
        require(count <= pin["bytes"] and count <= MAX_ZIP, "ZIP stream exceeds size cap")
        hasher.update(data)
    require(count == pin["bytes"] and hasher.hexdigest() == pin["sha256"], "ZIP SHA-256 differs")
    expected_count = zip_directory_bound(fd, count)
    os.lseek(fd, 0, os.SEEK_SET)
    members, total, found = {}, 0, {}
    with os.fdopen(os.dup(fd), "rb") as stream, zipfile.ZipFile(stream) as archive:
        infos = archive.infolist()
        require(len(infos) == expected_count, "ZIP member count differs from end record")
        # Preflight the entire directory before any decompression.
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            require(name and name == info.orig_filename and len(name) <= 1024 and
                    not any(ord(c) < 32 for c in name) and "\\" not in name and ":" not in name and
                    not pure.is_absolute() and pure.parts and ".." not in pure.parts and
                    name == pure.as_posix() + ("/" if info.is_dir() else ""), "unsafe ZIP path")
            canonical = name.rstrip("/")
            require(canonical not in members, "duplicate ZIP path")
            kind = stat.S_IFMT(info.external_attr >> 16)
            require(kind in (0, stat.S_IFREG, stat.S_IFDIR) and
                    (kind != stat.S_IFDIR or info.is_dir()) and
                    (kind != stat.S_IFREG or not info.is_dir()) and not info.flag_bits & 1,
                    "ZIP symlink, special or encrypted member")
            require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "unsupported ZIP compression")
            require(0 <= info.file_size <= MAX_MEMBER and
                    (not info.is_dir() or info.file_size == 0), "ZIP member size exceeds cap")
            total += info.file_size
            require(total <= MAX_EXPANDED, "ZIP expanded size exceeds cap")
            members[canonical] = info
        for name, info in members.items():
            require(not any(parent.as_posix() in members and not members[parent.as_posix()].is_dir()
                            for parent in PurePosixPath(name).parents if parent.as_posix() != "."),
                    "ZIP file-directory path collision")
            hasher, count = hashlib.sha256(), 0
            with archive.open(info) as member:
                while data := member.read(CHUNK):
                    count += len(data)
                    require(count <= info.file_size and count <= MAX_MEMBER, "ZIP stream exceeds cap")
                    hasher.update(data)
            require(count == info.file_size, "ZIP member size differs")
            if receipts and name in receipts:
                require(hasher.hexdigest() == digest(receipts[name]), "ABI receipt SHA-256 differs")
                found[name] = hasher.hexdigest()
        require(receipts is None or found == receipts, "missing ABI receipts")
    return {"members": len(members), "expanded_bytes": total, "abi_receipts_checked": len(found)}


def gh_get(endpoint, target, maximum, timeout=180):
    """Bound subprocess output and wall time; suppress stderr and debug/token logs."""
    env = dict(os.environ)
    env.pop("GH_DEBUG", None)
    env["GH_PROMPT_DISABLED"] = "1"
    process = None
    deadline, count = time.monotonic() + timeout, 0
    try:
        with publication_signals_blocked():
            process = subprocess.Popen(["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, env=env, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "GitHub API timeout")
                if not selector.select(min(remaining, 1)):
                    continue
                data = os.read(process.stdout.fileno(), CHUNK)
                if not data:
                    break
                count += len(data)
                require(count <= maximum, "GitHub API response exceeds size cap")
                target.write(data)
            require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                    "authenticated GitHub API GET failed")
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                process.wait()
                process.stdout.close()


def gh_json(endpoint):
    import io
    target = io.BytesIO()
    gh_get(endpoint, target, MAX_JSON)
    return parse_json(target.getvalue())


def capture(root, store):
    snapshots, pins, receipts, provenance_id = load_admissions(root)
    lock = None
    try:
        with publication_signals_blocked():
            lock = store.open("capture.lock", create=True)
        # A successful manifest is immutable. Partial failed captures retain blobs,
        # but never create a successful manifest or replace existing snapshots.
        require("manifest.json" not in os.listdir(store.fd), "manifest already exists")
        require(not os.listdir(store.dirs["admissions"]), "admission snapshots already exist")
        started = utcnow()
        identity = gh_json("/user")
        require(type(identity.get("id")) is int and identity["id"] > 0, "authenticated API identity required")
        entries = {}
        for key, pin in sorted(pins.items()):
            endpoint = "/repos/" + pin["repository"] + "/actions/"
            metadata = minimal_metadata(gh_json(endpoint + "artifacts/" + key),
                                        gh_json(endpoint + "runs/" + str(pin["run_id"])))
            validate_metadata(pin, metadata, utcnow())
            blob = pin["sha256"] + ".zip"
            created, fd = False, None
            try:
                with publication_signals_blocked():
                    try:
                        fd = store.open(blob, "blobs")
                    except FileNotFoundError:
                        fd = store.open(blob, "blobs", create=True)
                        created = True
                if created:
                    with os.fdopen(os.dup(fd), "wb") as target:
                        gh_get(endpoint + "artifacts/" + key + "/zip", target, pin["bytes"])
                        target.flush()
                        os.fsync(target.fileno())
                inspection = inspect_zip(fd, pin, receipts if key == provenance_id else None)
            except BaseException:
                if created:
                    os.unlink(blob, dir_fd=store.dirs["blobs"])
                raise
            finally:
                if fd is not None:
                    os.close(fd)
            entries[key] = {"pin": pin, "metadata": metadata, "inspection": inspection}
        captured = utcnow()
        for key, entry in entries.items():
            validate_metadata(pins[key], entry["metadata"], captured)
        # Persist newly downloaded blob directory entries before their manifest.
        os.fsync(store.dirs["blobs"])
        manifest = {"schema": SCHEMA, "capture_started_at": stamp(started),
                    "captured_at": stamp(captured), "admissions": {k: sha256(v) for k, v in snapshots.items()},
                    "artifacts": entries, **FLAGS}
        raw = encoded(manifest)
        published = []
        try:
            # Keep publication and ownership bookkeeping inseparable on signal.
            # An interrupted/failing finalization rolls back only our own files;
            # preseeded and fully validated blobs remain reusable for a retry.
            with publication_signals_blocked():
                for name, snapshot in snapshots.items():
                    store.write(Path(name).name, snapshot, "admissions")
                    published.append((Path(name).name, "admissions"))
                store.write("manifest.json", raw)
                published.append(("manifest.json", None))
                os.fsync(store.fd)
        except BaseException:
            for name, section in reversed(published):
                os.unlink(name, dir_fd=store.parent(section))
            os.fsync(store.dirs["admissions"])
            os.fsync(store.fd)
            raise
        return {"manifest_sha256": sha256(raw), "artifacts": len(entries), **FLAGS}
    finally:
        if lock is not None:
            os.close(lock)
            os.unlink("capture.lock", dir_fd=store.fd)


def verify(root, store, expected_sha256):
    raw = store.read("manifest.json")
    require(sha256(raw) == digest(expected_sha256), "manifest SHA-256 differs from external anchor")
    manifest = parse_json(raw)
    require(set(manifest) == {"schema", "capture_started_at", "captured_at", "admissions", "artifacts", *FLAGS},
            "unexpected manifest fields")
    require(manifest["schema"] == SCHEMA and all(manifest[k] is v for k, v in FLAGS.items()),
            "not a historical-only preservation manifest")
    captured = timestamp(manifest["captured_at"])
    require(timestamp(manifest["capture_started_at"]) <= captured <= utcnow(), "future capture timestamp")
    snapshots, pins, receipts, provenance_id = load_admissions(root)
    require(manifest["admissions"] == {k: sha256(v) for k, v in snapshots.items()},
            "checked-in admission hashes differ")
    for name, current in snapshots.items():
        require(store.read(Path(name).name, "admissions") == current, "admission snapshot differs")
    require(set(manifest["artifacts"]) == set(pins), "artifact set differs")
    for key, pin in pins.items():
        entry = manifest["artifacts"][key]
        require(set(entry) == {"pin", "metadata", "inspection"} and entry["pin"] == pin,
                "manifest admission pin differs")
        validate_metadata(pin, entry["metadata"], captured)
        fd = store.open(pin["sha256"] + ".zip", "blobs")
        try:
            inspection = inspect_zip(fd, pin, receipts if key == provenance_id else None)
        finally:
            os.close(fd)
        require(inspection == entry["inspection"], "ZIP inspection record differs")
    return {"manifest_sha256": expected_sha256, "artifacts": len(pins),
            "captured_at": manifest["captured_at"], **FLAGS}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("operation", choices=("capture", "verify"))
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest-sha256", help="required external capture anchor for offline verify")
    args = parser.parse_args()
    if args.operation == "verify" and not args.manifest_sha256:
        parser.error("verify requires --manifest-sha256 retained separately from the archive")
    if args.operation == "capture" and args.manifest_sha256:
        parser.error("--manifest-sha256 applies only to verify")
    store = None
    previous_handlers = {number: signal.signal(number, interrupted)
                         for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        store = Store(args.store, create=args.operation == "capture")
        result = capture(args.repo_root, store) if args.operation == "capture" else verify(
            args.repo_root, store, args.manifest_sha256)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile,
            NotImplementedError, RuntimeError, zlib.error, struct.error, subprocess.SubprocessError) as error:
        # Never print upstream response bodies, subprocess stderr or credentials.
        print("preservation rejected: " + (str(error) if isinstance(error, Rejected)
                                            else type(error).__name__), file=sys.stderr)
        return 1
    finally:
        if store is not None:
            store.close()
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
