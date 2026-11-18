#!/usr/bin/env python3
"""Read-only logical lease counts from one stopped, fresh schema-2 fixture store.

Accept the base store or its complete provider authorization layout. Migrated v1
stores have different storage_meta DDL and remain outside this fixture's scope.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path
from urllib.parse import quote

OWNER_NAME = ".volparossa-private-storage-v1"
DB_NAME = "private-storage.sqlite3"
OWNER_MAGIC = b"VPST0001"
APPLICATION_ID = 0x56505331
VERSION = 2
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024
MAX_LEASES = 256
MAX_CAPACITY = 1024 * 1024 * 1024 * 1024
QUERY_SECONDS = 1.0

SCHEMA = {
    "storage_meta": "CREATE TABLE storage_meta ( singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL, store_id BLOB NOT NULL CHECK(length(store_id) = 32), capacity_bytes INTEGER NOT NULL CHECK(capacity_bytes > 0), min_free_bytes INTEGER NOT NULL CHECK(min_free_bytes >= 0), admission_target_bytes INTEGER NOT NULL CHECK(admission_target_bytes >= 0 AND admission_target_bytes <= capacity_bytes) ) STRICT",
    "leases": "CREATE TABLE leases ( lease_id BLOB PRIMARY KEY CHECK(length(lease_id) = 16), ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes >= 0), sha256 BLOB NOT NULL CHECK(length(sha256) = 32), expires INTEGER NOT NULL CHECK(expires > 0), committed INTEGER NOT NULL CHECK(committed IN (0,1)) ) STRICT",
    "chunks": "CREATE TABLE chunks ( lease_id BLOB NOT NULL REFERENCES leases(lease_id) ON DELETE CASCADE, ordinal INTEGER NOT NULL CHECK(ordinal >= 0), sha256 BLOB NOT NULL CHECK(length(sha256) = 32), payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 262144), PRIMARY KEY(lease_id, ordinal) ) STRICT",
}
PROVIDER_SCHEMA = {
    "storage_provider": "CREATE TABLE storage_provider ( singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL CHECK (version = 1), public_key BLOB NOT NULL CHECK (length(public_key) = 32) ) STRICT",
    "storage_grants": "CREATE TABLE storage_grants ( grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 32), capability_id BLOB UNIQUE NOT NULL CHECK (length(capability_id) = 32), owner BLOB NOT NULL CHECK (length(owner) = 32), signed_grant BLOB NOT NULL CHECK (length(signed_grant) BETWEEN 1 AND 2048) ) STRICT",
    "storage_bindings": "CREATE TABLE storage_bindings ( owner BLOB NOT NULL CHECK (length(owner) = 32), archive_id BLOB NOT NULL CHECK (length(archive_id) = 32), grant_id BLOB NOT NULL REFERENCES storage_grants(grant_id), lease_id BLOB UNIQUE NOT NULL CHECK (length(lease_id) = 16), ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes BETWEEN 1 AND 68719476736), sha256 BLOB NOT NULL CHECK (length(sha256) = 32), deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)), PRIMARY KEY (owner, archive_id) ) STRICT",
}
PROVIDER_TRIGGER = "CREATE TRIGGER storage_binding_delete AFTER DELETE ON leases BEGIN UPDATE storage_bindings SET deleted = 1 WHERE lease_id = OLD.lease_id; END"


class Unavailable(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def result(state: str, reason: str | None, counts: tuple[int, int, int] | None) -> dict:
    return {
        "version": 1,
        "state": state,
        "reason": reason,
        "reserved_bytes": counts[0] if counts else None,
        "committed_bytes": counts[1] if counts else None,
        "leases": counts[2] if counts else None,
        "owner_cleanup_proven": False,
    }


def _fail(reason: str) -> None:
    raise Unavailable(reason)


def _path_components(path: Path) -> None:
    if not path.is_absolute() or len(os.fspath(path)) > 4096 or ".." in path.parts:
        _fail("invalid_input")
    cursor = Path("/")
    for part in path.parts[1:]:
        cursor /= part
        try:
            st = os.lstat(cursor)
        except OSError:
            _fail("owner")
        if stat.S_ISLNK(st.st_mode):
            _fail("owner")


def _sidecars(directory_fd: int) -> bool:
    for name in (DB_NAME + "-journal", DB_NAME + "-wal", DB_NAME + "-shm"):
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            pass
        except OSError:
            _fail("sidecar")
    return False


def _metadata(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _schema_check(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA application_id").fetchone() != (APPLICATION_ID,):
        _fail("schema")
    if db.execute("PRAGMA user_version").fetchone() != (VERSION,):
        _fail("schema")
    objects = db.execute(
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    expected_objects = {("table", name): sql for name, sql in SCHEMA.items()}
    expected = {"storage_meta": (6, 1), "leases": (5, 1), "chunks": (4, 1)}
    if len(objects) == 7:
        expected_objects.update({("table", name): sql for name, sql in PROVIDER_SCHEMA.items()})
        expected_objects[("trigger", "storage_binding_delete")] = PROVIDER_TRIGGER
        expected.update({"storage_provider": (3, 1), "storage_grants": (4, 1), "storage_bindings": (7, 1)})
    if {(kind, name) for kind, name, _ in objects} != set(expected_objects):
        _fail("schema")
    for kind, name, sql in objects:
        normalized = " ".join((sql or "").split())
        if normalized != expected_objects[(kind, name)]:
            _fail("schema")
    tables = db.execute("PRAGMA table_list").fetchall()
    seen = {}
    for row in tables:
        # schema, name, type, ncol, wr, strict
        if row[0] != "main":
            continue
        if row[1] in expected and row[2] == "table":
            seen[row[1]] = (row[3], row[5])
        elif row[1] not in expected and not row[1].startswith("sqlite_"):
            _fail("schema")
    if seen != expected:
        _fail("schema")


def _snapshot(path: Path) -> tuple[int, int, int]:
    _path_components(path)
    try:
        dirfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        _fail("owner")
    owner_fd = db_fd = None
    db = None
    try:
        dirst = os.fstat(dirfd)
        if not stat.S_ISDIR(dirst.st_mode) or dirst.st_uid != os.getuid() or stat.S_IMODE(dirst.st_mode) != 0o700:
            _fail("owner")
        names_before = tuple(sorted(os.listdir(dirfd)))
        try:
            owner_fd = os.open(
                OWNER_NAME,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=dirfd,
            )
        except OSError:
            _fail("owner")
        owner_st = os.fstat(owner_fd)
        if (not stat.S_ISREG(owner_st.st_mode) or owner_st.st_uid != os.getuid()
                or stat.S_IMODE(owner_st.st_mode) != 0o600 or owner_st.st_nlink != 1
                or owner_st.st_size != 60):
            _fail("owner")
        try:
            fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                _fail("busy")
            _fail("owner")
        owner_bytes = os.pread(owner_fd, 61, 0)
        if len(owner_bytes) != 60 or owner_bytes[:8] != OWNER_MAGIC:
            _fail("owner")
        owner_id = owner_bytes[8:40]
        recorded = (int.from_bytes(owner_bytes[40:48], "little"),
                    int.from_bytes(owner_bytes[48:56], "little"),
                    int.from_bytes(owner_bytes[56:60], "little"))
        if recorded != (dirst.st_dev, dirst.st_ino, dirst.st_uid):
            _fail("owner")
        if _sidecars(dirfd):
            _fail("sidecar")
        try:
            db_fd = os.open(DB_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dirfd)
        except OSError:
            _fail("database")
        db_st = os.fstat(db_fd)
        if (not stat.S_ISREG(db_st.st_mode) or db_st.st_uid != os.getuid()
                or stat.S_IMODE(db_st.st_mode) != 0o600 or db_st.st_nlink != 1
                or db_st.st_size < 0 or db_st.st_size > MAX_DB_BYTES):
            _fail("database")
        db_path = path / DB_NAME
        uri = "file:" + quote(os.fspath(db_path), safe="/") + "?mode=ro"
        try:
            db = sqlite3.connect(uri, uri=True, timeout=0.1)
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            if db.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                _fail("schema")
            deadline = time.monotonic() + QUERY_SECONDS
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            _schema_check(db)
            meta = db.execute("SELECT version, store_id, capacity_bytes, min_free_bytes, admission_target_bytes FROM storage_meta WHERE singleton=1").fetchall()
            if len(meta) != 1:
                _fail("schema")
            version, store_id, capacity, min_free, target = meta[0]
            if (version != VERSION or store_id != owner_id or not isinstance(capacity, int)
                    or not 0 < capacity <= MAX_CAPACITY or not isinstance(min_free, int) or min_free < 0
                    or min_free > MAX_CAPACITY or not isinstance(target, int) or not 0 <= target <= capacity):
                _fail("schema")
            rows = db.execute(
                "SELECT lease_id, ciphertext_bytes, sha256, expires, committed "
                "FROM leases LIMIT ?",
                (MAX_LEASES + 1,),
            ).fetchall()
            if len(rows) > MAX_LEASES:
                _fail("counts")
            for lease_id, ciphertext_bytes, sha256, expires, committed_flag in rows:
                if (not isinstance(lease_id, bytes) or len(lease_id) != 16
                        or type(ciphertext_bytes) is not int
                        or not 0 <= ciphertext_bytes <= MAX_ARCHIVE_BYTES
                        or not isinstance(sha256, bytes) or len(sha256) != 32
                        or type(expires) is not int or expires <= 0
                        or type(committed_flag) is not int or committed_flag not in (0, 1)):
                    _fail("counts")
            reserved = 0
            committed = 0
            for _, ciphertext_bytes, _, _, committed_flag in rows:
                if committed_flag == 0:
                    reserved += ciphertext_bytes
                else:
                    committed += ciphertext_bytes
                if reserved + committed > capacity:
                    _fail("counts")
            leases = len(rows)
        except Unavailable:
            raise
        except (sqlite3.Error, OSError, OverflowError):
            _fail("query")
        finally:
            if db is not None:
                db.close()
                db = None
        try:
            owner_after = os.fstat(owner_fd)
            db_after = os.stat(DB_NAME, dir_fd=dirfd, follow_symlinks=False)
            dir_after = os.fstat(dirfd)
            owner_bytes_after = os.pread(owner_fd, 61, 0)
            names_after = tuple(sorted(os.listdir(dirfd)))
            if (_metadata(owner_st) != _metadata(owner_after) or owner_bytes != owner_bytes_after
                    or _metadata(db_st) != _metadata(db_after) or dir_after.st_ino != dirst.st_ino
                    or dir_after.st_dev != dirst.st_dev or _metadata(dirst) != _metadata(dir_after)
                    or names_before != names_after
                    or _sidecars(dirfd)):
                _fail("changed")
        except OSError:
            _fail("changed")
        return reserved, committed, leases
    finally:
        if db is not None:
            db.close()
        for fd in (db_fd, owner_fd, dirfd):
            if fd is not None:
                os.close(fd)


def observe(path: str | os.PathLike[str]) -> dict:
    try:
        counts = _snapshot(Path(path))
        return result("observed", None, counts)
    except Unavailable as exc:
        return result("unavailable", exc.reason, None)
    except (OSError, ValueError, TypeError):
        return result("unavailable", "invalid_input", None)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("store_path")
    args = parser.parse_args()
    print(json.dumps(observe(args.store_path), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
