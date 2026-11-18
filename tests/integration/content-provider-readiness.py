#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded Client advertisement inventory barrier, not route readiness evidence.

Only the existing Client's read-only peers command is queried. No advertisements,
credentials, routes, role changes or discovery records are supplied to the agent.
"""
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time

FIXTURE_ROLES = ("client", "bootstrap1", "bootstrap2", *(f"relay{i}" for i in range(6)), "exit", "exit2")
INVENTORY_ROLES = ("relay0", "relay1", "relay2", "exit")
SCOPE = "client_advertisement_inventory_not_route_readiness"
DEADLINE_SECONDS = 60
MAX_ATTEMPTS = 600
OUTCOMES = {"none", "timeout", "nonzero", "invalid_reply", "partial", "complete", "os_error"}
TERMINAL = {"ready", "deadline", "os_error", "invalid_fixture"}


def require(condition):
    if not condition:
        raise ValueError("content_provider_inventory_rejected")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def expected_inventory(peers):
    require(type(peers) is dict and set(peers) == set(FIXTURE_ROLES))
    require(all(type(value) is str and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,128}", value)
                for value in peers.values()) and len(set(peers.values())) == len(FIXTURE_ROLES))
    return {peers[name]: "0b100" if name == "exit" else "0b010" for name in INVENTORY_ROLES}


def parse_inventory(raw):
    # The pinned CLI validates its bounded RPC frame before printing. Do not
    # accept duplicate identities, role substitutions or a truncated last line.
    if type(raw) is not bytes or len(raw) > 1048576 or (raw and not raw.endswith(b"\n")):
        return None
    try:
        lines = raw.decode("ascii").split("\n")[:-1] if raw else []
    except UnicodeError:
        return None
    if len(lines) > 4096:
        return None
    observed = {}
    for line in lines:
        match = re.fullmatch(r"([1-9A-HJ-NP-Za-km-z]{32,128})\troles=(0b[01]{3})\treachability=([0-3])", line)
        if match is None or match[1] in observed:
            return None
        observed[match[1]] = match[2]
    return observed


def new_record():
    return dict(version=1, scope=SCOPE, deadline_seconds=DEADLINE_SECONDS, attempts=0,
                query_timeouts=0, query_nonzero=0, invalid_replies=0, last_query_outcome="none",
                last_valid_presence=None, outcome="invalid_fixture", ready=False)


def closed_record(value):
    require(type(value) is dict and set(value) == set(new_record()))
    require(type(value["version"]) is int and value["version"] == 1 and value["scope"] == SCOPE
            and type(value["deadline_seconds"]) is int and value["deadline_seconds"] == DEADLINE_SECONDS
            and type(value["ready"]) is bool and value["outcome"] in TERMINAL
            and value["last_query_outcome"] in OUTCOMES)
    require(all(type(value[key]) is int and 0 <= value[key] <= MAX_ATTEMPTS
                for key in ("attempts", "query_timeouts", "query_nonzero", "invalid_replies")))
    require(sum(value[key] for key in ("query_timeouts", "query_nonzero", "invalid_replies")) <= value["attempts"])
    presence = value["last_valid_presence"]
    require(presence is None or (type(presence) is dict and set(presence) == set(INVENTORY_ROLES)
                                and all(type(item) is bool for item in presence.values())))
    require(value["ready"] == (value["outcome"] == "ready"))
    if value["ready"]:
        require(value["attempts"] > 0 and value["last_query_outcome"] == "complete"
                and presence is not None and all(presence.values()))
    return value


def load_fixture(work):
    # Production invocation is additionally guarded by the enclosing disposable
    # Debian/KVM topology. Keep this helper tied to its exact immutable staging.
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha"
            and work.parent == Path("/opt") and re.fullmatch(r"va\.[0-9a-f]{32}\.[A-Za-z0-9]{6}", work.name)
            and work.resolve(strict=True) == work)
    info = work.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    binary = work / "bin/volparossa"
    info = binary.lstat()
    require(binary.resolve(strict=True) == binary and stat.S_ISREG(info.st_mode)
            and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o555)
    source = work / "a01-expected-peers.json"
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 8192)
        raw = stream.read(8193)
        require(len(raw) == info.st_size and os.fstat(stream.fileno()).st_size == info.st_size)
    peers = json.loads(raw, object_pairs_hook=unique_pairs)
    expected_inventory(peers)
    return peers


def await_inventory(work, peers):
    expected = expected_inventory(peers)
    record = new_record()
    command = [str(work / "bin/volparossa"), "--control-socket",
               str(work / "runtime-client/control/agent.sock"), "peers"]
    deadline = time.monotonic() + DEADLINE_SECONDS
    while record["attempts"] < MAX_ATTEMPTS and (remaining := deadline - time.monotonic()) > 0:
        record["attempts"] += 1
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    check=False, timeout=min(2, remaining))
            observed = parse_inventory(result.stdout) if result.returncode == 0 else None
            if result.returncode != 0:
                record["query_nonzero"] += 1
                record["last_query_outcome"] = "nonzero"
            elif observed is None:
                record["invalid_replies"] += 1
                record["last_query_outcome"] = "invalid_reply"
            else:
                record["last_valid_presence"] = {
                    name: observed.get(peers[name]) == expected[peers[name]] for name in INVENTORY_ROLES}
                record["last_query_outcome"] = "complete" if all(record["last_valid_presence"].values()) else "partial"
                if record["last_query_outcome"] == "complete" and time.monotonic() < deadline:
                    record.update(outcome="ready", ready=True)
                    return closed_record(record)
        except subprocess.TimeoutExpired:
            record["query_timeouts"] += 1
            record["last_query_outcome"] = "timeout"
        except OSError:
            record.update(last_query_outcome="os_error", outcome="os_error")
            return closed_record(record)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.1, remaining))
    record["outcome"] = "deadline"
    return closed_record(record)


def main(arguments):
    record = new_record()
    try:
        require(len(arguments) == 1)
        work = Path(arguments[0])
        record = await_inventory(work, load_fixture(work))
    except (OSError, ValueError, TypeError, KeyboardInterrupt):
        # Input/guard failures still yield a closed error record, never the
        # exception text or any fixture IDs, addresses, credentials or paths.
        pass
    print(json.dumps(closed_record(record), sort_keys=True, separators=(",", ":")))
    return 0 if record["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
