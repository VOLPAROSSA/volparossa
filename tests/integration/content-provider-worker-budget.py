#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed resource diagnostics for the explicit disposable provider fixture only.

The private markers bind byte ranges of one owned agent log. Exported reports
contain only bounded budget summaries, never log envelopes, identifiers or paths.
These observations do not establish transfer completion, concurrency or cleanup.
Continuation records are exported separately from the unchanged budget schema.
Returned progress excludes partial writes from failed or cancelled receives;
zero returned bytes never means that no bytes travelled or entered the cache.
"""
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

TARGET = "volparossa_agent::content::worker_budget"
CODE = "CONTENT_WORKER_BUDGET_SUMMARY"
CONTINUATION_TARGET = "volparossa_agent::content::parallel::continuation"
CONTINUATION_CODE = "CONTENT_PROVIDER_CONTINUATION_SUMMARY"
PHASES = ("native", "https", "pressure")
OUTPUT_PREFIXES = {"native": "content-provider-adaptive",
                   "https": "content-provider-adaptive-https",
                   "pressure": "content-provider-pressure"}
MAX_INPUT = 8 * 1024 * 1024
MAX_LINE = 16384
MAX_LINES = 8192
MAX_BUDGET = 4096
MAX_RECORDS = 16
MAX_OUTPUT = 65536
U32 = 2**32 - 1
OBSERVATIONS = {"initial_allowance", "min_allowance", "max_allowance",
                "min_memory_workers", "min_fd_workers"}
COUNTERS = {"peak_shared_held", "admitted_leases", "denied_leases", "peak_leases", "active_leases"}
CAUSES = {"cpu_pressure", "memory_pressure", "io_pressure", "cpu_unavailable",
          "memory_unavailable", "io_unavailable", "resource_unavailable", "lock_unavailable"}
CONTINUATION_COUNTS = {"retired_candidates", "prepared_continuations", "admitted_continuations",
                       "returned_useful_continuations", "returned_verified_chunks",
                       "initial_active_workers", "peak_active_workers", "final_active_workers"}


def require(condition):
    if not condition:
        raise ValueError("invalid bounded worker-budget evidence")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    def invalid_constant(_value):
        raise ValueError("non-finite JSON")
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def summary(value):
    require(type(value) is dict and set(value) ==
            {"schema_version", "outcome", "causes"} | OBSERVATIONS | COUNTERS)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(type(value["outcome"]) is str and value["outcome"] in ("returned", "failed", "interrupted"))
    for key in OBSERVATIONS | COUNTERS:
        number = value[key]
        require(key in OBSERVATIONS and number is None or type(number) is int and 0 <= number <= U32)
    require(type(value["causes"]) is dict and set(value["causes"]) == CAUSES
            and all(type(flag) is bool for flag in value["causes"].values()))
    low, high = value["min_allowance"], value["max_allowance"]
    require((low is None) == (high is None) and (low is None or low <= high))
    require(value["active_leases"] <= value["peak_leases"] <= value["admitted_leases"])
    return value


def continuation_summary(value):
    require(type(value) is dict and set(value) ==
            {"schema_version", "outcome", "returned_verified_bytes"} | CONTINUATION_COUNTS)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(type(value["outcome"]) is str and value["outcome"] in ("returned", "failed", "interrupted"))
    for key in CONTINUATION_COUNTS | {"returned_verified_bytes"}:
        maximum = 2**64 - 1 if key == "returned_verified_bytes" else U32
        require(type(value[key]) is int and 0 <= value[key] <= maximum)
    require(value["returned_useful_continuations"] <= value["admitted_continuations"]
            <= value["prepared_continuations"] <= value["retired_candidates"])
    require(max(value["initial_active_workers"], value["final_active_workers"])
            <= value["peak_active_workers"])
    return value


def extract(raw, *, continuation=False):
    """Accept complete JSON log lines only; never return an unvalidated raw line."""
    target, code, field, validate = (CONTINUATION_TARGET, CONTINUATION_CODE, "continuation", continuation_summary) \
        if continuation else (TARGET, CODE, "budget", summary)
    require(type(raw) is bytes and len(raw) <= MAX_INPUT)
    records = []
    incomplete = False
    stream = io.BytesIO(raw)
    count = 0
    while line := stream.readline(MAX_LINE + 2):
        count += 1
        require(count <= MAX_LINES and len(line.removesuffix(b"\n")) <= MAX_LINE)
        if not line.endswith(b"\n"):
            incomplete = True
            break
        if not line.strip():
            continue
        event = decode(line)
        require(type(event) is dict)
        if event.get("target") != target:
            continue
        fields = event.get("fields")
        require(type(fields) is dict)
        if fields.get("code") != code:
            continue
        require(event.get("level") == "DEBUG" and set(fields) == {"code", field})
        payload = fields[field]
        require(type(payload) is str and len(payload.encode("utf-8")) <= MAX_BUDGET)
        records.append(validate(decode(payload)))
        require(len(records) <= MAX_RECORDS)
    return records, incomplete


def checked_open(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mode & 0o777 == 0o600)
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def read_private(path, maximum):
    fd, info = checked_open(path)
    try:
        require(info.st_size <= maximum)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        require(len(raw) == info.st_size and after.st_size == info.st_size
                and after.st_mtime_ns == info.st_mtime_ns and after.st_ctime_ns == info.st_ctime_ns)
        return raw
    finally:
        os.close(fd)


def write_private(path, value, maximum, *, exclusive=False):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    require(len(raw) <= maximum)
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as destination:
            destination.write(raw)
        return
    # Output paths are fixed within this fixture's owner-controlled directory.
    # Refuse unexpected targets rather than following or overwriting a link.
    if os.path.lexists(path):
        fd, _ = checked_open(path)
        os.close(fd)
    fd, temporary = tempfile.mkstemp(prefix=".worker-budget-", suffix=".part", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as destination:
            destination.write(raw)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def paths(work, phase):
    require(phase in PHASES)
    return (work / ".content-worker-budget-{}.part".format(phase),
            work / f"{OUTPUT_PREFIXES[phase]}-worker-budget.json")


def continuation_path(work, phase):
    require(phase in PHASES)
    return work / f"{OUTPUT_PREFIXES[phase]}-continuation.json"


def mark(work, phase):
    marker, _ = paths(work, phase)
    fd, info = checked_open(work / "agent-client.log")
    try:
        if info.st_size:
            require(os.pread(fd, 1, info.st_size - 1) == b"\n")
        value = dict(schema_version=1, phase=phase, device=info.st_dev, inode=info.st_ino,
                     start=info.st_size, end=None)
        write_private(marker, value, MAX_BUDGET, exclusive=True)
    finally:
        os.close(fd)


def finish(work, phase, *, pending=False):
    marker, output = paths(work, phase)
    report = dict(schema_version=1, kind="content-worker-budget-diagnostic", phase=phase,
                  phase_closed=not pending, complete=False, status="invalid", records=[])
    continuation_report = dict(report, kind="content-provider-continuation-diagnostic", records=[])
    try:
        value = decode(read_private(marker, MAX_BUDGET))
        require(type(value) is dict and set(value) ==
                {"schema_version", "phase", "device", "inode", "start", "end"})
        require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["phase"] == phase)
        require(all(type(value[key]) is int and value[key] >= 0 for key in ("device", "inode", "start")))
        require(value["end"] is None or type(value["end"]) is int and value["end"] >= value["start"])
        fd, info = checked_open(work / "agent-client.log")
        try:
            require((info.st_dev, info.st_ino) == (value["device"], value["inode"]))
            end = info.st_size if value["end"] is None else value["end"]
            require(value["start"] <= end <= info.st_size and end - value["start"] <= MAX_INPUT)
            raw = os.pread(fd, end - value["start"], value["start"])
            require(len(raw) == end - value["start"] and os.fstat(fd).st_size >= end)
        finally:
            os.close(fd)
        if not pending and value["end"] is None:
            value["end"] = end
            write_private(marker, value, MAX_BUDGET)
        for selected, is_continuation in ((report, False), (continuation_report, True)):
            try:
                records, incomplete = extract(raw, continuation=is_continuation)
                selected.update(records=records, status="incomplete" if incomplete or pending else
                                "observed" if records else "missing",
                                complete=bool(records) and not incomplete and not pending)
            except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
                pass  # Invalid payloads do not erase the other closed diagnostic.
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        pass  # The closed invalid report replaces neither the failure nor absent evidence with success.
    write_private(output, report, MAX_OUTPUT)
    write_private(continuation_path(work, phase), continuation_report, MAX_OUTPUT)
    return report


def finalize(work):
    for phase in PHASES:
        marker, _ = paths(work, phase)
        if os.path.lexists(marker):
            finish(work, phase)


def main(argv):
    require(len(argv) >= 3 and argv[1] in ("mark", "finish", "pending", "finalize"))
    work = Path(argv[2])
    require(work.is_absolute() and work.resolve() == work)
    info = work.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022)
    if argv[1] == "finalize":
        require(len(argv) == 3)
        finalize(work)
    else:
        require(len(argv) == 4)
        if argv[1] == "mark":
            mark(work, argv[3])
        else:
            finish(work, argv[3], pending=argv[1] == "pending")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        print("worker-budget diagnostic unavailable", file=sys.stderr)
        sys.exit(1)
