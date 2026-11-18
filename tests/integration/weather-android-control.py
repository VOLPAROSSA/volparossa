#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fixed root readiness/finalization doorway for one disposable Android trial.

The host can only read-ready or finalize. Neither operation accepts a path,
command, account, PID or request body. This does not fetch a product or authorize
an Android result; the separate evidence join remains mandatory.
"""
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import stat
import sys
import time

STATE = Path("/run/volparossa-weather-android")
ROOT_UID = 0
WORKER_UID = 985
WORK_PARENT = Path("/opt")
FILES = ("state.json", "ready.json", "endpoint.json")
OWNER_NAME = "weather-android-controller-owned.json"
MAX_FILE = 16384
HEX = re.compile(r"[a-f0-9]{64}")
HELPERS = ("weather-android-api.py", "weather-android-delivery.py", "weather-products-delivery.py",
    "weather-client-delivery.py", "weather-client-bundle.py", "browser-filter-bundle.py",
    "content-provider-https-smoke.py", "content-network-smoke.py", "weather-public-drizzli-v4.json",
    "weather-public-android-v6.json")


def require(value):
    if not value: raise ValueError("weather_android_control_rejected")


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value); value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return dict(device=info.st_dev, inode=info.st_ino)


def owned(path, mode, uid=None, directory=False):
    if uid is None: uid = ROOT_UID
    require(path.is_absolute() and path.resolve(strict=True) == path)
    info = path.lstat()
    require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode)
        and stat.S_IMODE(info.st_mode) == mode and info.st_uid == uid)
    if not directory: require(info.st_nlink == 1)
    return info


def read(path, mode=0o600, uid=None, limit=MAX_FILE):
    if uid is None: uid = ROOT_UID
    before = owned(path, mode, uid)
    require(0 < before.st_size <= limit)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(identity(opened) == identity(before))
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size and all(getattr(before, field) == getattr(after, field)
        for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")))
    return raw


def absent(path):
    try: path.lstat()
    except FileNotFoundError: return True
    return False


def write(path, raw, mode=0o600):
    require(0 < len(raw) <= MAX_FILE)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw); stream.flush()
        info = os.fstat(stream.fileno())
    require(identity(owned(path, mode)) == identity(info))
    return identity(info)


def accounts(group):
    agent, worker = pwd.getpwnam("volparossa"), pwd.getpwnam("volparossa-worker")
    require(type(group) is int and 0 < group <= 65535
        and grp.getgrnam("volparossa-users").gr_gid == group
        and worker.pw_uid == WORKER_UID and 0 < agent.pw_uid != WORKER_UID
        and 0 < agent.pw_gid != group)
    return agent.pw_uid, agent.pw_gid


def work_directory(work):
    require(work.parent == WORK_PARENT and re.fullmatch(r"va\.[a-f0-9]{32}\.[A-Za-z0-9]{6}", work.name))
    return owned(work, 0o755, directory=True)


def api_module(work):
    owned(work / "bin", 0o755, directory=True)
    for name in HELPERS: owned(work / "bin" / name, 0o555)
    return runpy.run_path(str(work / "bin/weather-android-api.py"))


def socket_check(work, ready):
    path = work / "client-fixtures/weather-viewer/socket/core-api.sock"
    owned(path.parent, 0o700, WORKER_UID, directory=True)
    require(path.resolve(strict=True) == path and len(os.fsencode(path)) < 104)
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == WORKER_UID and info.st_nlink == 1
        and ready["socket"] == dict(**identity(info), user_uid=WORKER_UID, mode="0600"))
    return path


def ready_result(state, ready, now):
    remaining = state["expires_at"] - now
    require(0 < remaining <= 840)
    return dict(schema=6, kind="weather-android-guest-ready", manifest_sha256=state["manifest_sha256"],
        core_sha256=state["core_sha256"], prepared_sha256=state["prepared_sha256"],
        deadline_unix_seconds=state["expires_at"], remaining_seconds=remaining,
        api_socket_ready=True, cold_caches_absent=ready["cold_caches_absent"],
        helper_requests=0, joined_delivery_proven=False)


def publish(work, manifest_sha, core_sha, prepared_sha, group, expires_at):
    require(os.geteuid() == ROOT_UID and all(HEX.fullmatch(value) for value in (manifest_sha, core_sha, prepared_sha)))
    require(type(expires_at) is int and 0 < expires_at - int(time.time()) <= 840)
    info = work_directory(work); agent_uid, agent_gid = accounts(group)
    require(info.st_gid == agent_gid)
    require(absent(STATE) and absent(work / OWNER_NAME))
    api = api_module(work)
    prepared_raw = read(work / "weather-android-delivery-prepared.json")
    require(digest(prepared_raw) == prepared_sha)
    prepared = parse(prepared_raw); api["D"]["validate_prepared"](prepared)
    require(prepared["manifest_sha256"] == manifest_sha and prepared["core_sha256"] == core_sha)
    require(read(work / "client-fixtures/weather-viewer/prepared.json", 0o400, WORKER_UID) == prepared_raw)
    # Exactly one complete readiness record; an early final/rejection is not ready.
    raw = read(work / "weather-android-delivery-api.jsonl")
    require(raw.endswith(b"\n") and len(raw.splitlines()) == 1)
    ready = parse(raw); api["validate_record"](ready)
    require(ready["kind"] == "weather-android-api-ready" and ready["manifest_sha256"] == manifest_sha
        and ready["core_sha256"] == core_sha and ready["prepared_sha256"] == prepared_sha
        and ready["config_sha256"] == prepared["config_sha256"] and ready["expires_at"] == expires_at)
    path = socket_check(work, ready)
    layout = api["D"]["paths"](work)
    api["D"]["cache_parent"](layout["cache_parent"], agent_uid, group)
    require(not list(layout["scratch"].iterdir()) and not list(layout["proof"].iterdir()))
    state = dict(schema=6, kind="weather-android-controller", work=str(work), work_identity=identity(info),
        manifest_sha256=manifest_sha, core_sha256=core_sha, prepared_sha256=prepared_sha,
        control_gid=group, expires_at=expires_at, ready_sha256=digest(raw))
    endpoint = dict(schema=1, socket=str(path), control_gid=group, expires_at=expires_at)
    entries, directory = {}, None
    try:
        STATE.mkdir(mode=0o700); directory = identity(owned(STATE, 0o700, directory=True))
        for name, value in (("state.json", encode(state)), ("ready.json", raw), ("endpoint.json", encode(endpoint))):
            entries[name] = write(STATE / name, value)
        result = ready_result(state, ready, int(time.time()))
        write(work / OWNER_NAME, encode(dict(schema=6, prepared_sha256=prepared_sha,
            directory=directory, files=entries)))
        return result
    except BaseException:
        # Only entries successfully created by this call, never a replacement.
        if directory is not None and identity(owned(STATE, 0o700, directory=True)) == directory:
            for name, saved in entries.items():
                if identity(owned(STATE / name, 0o600)) == saved: (STATE / name).unlink()
            STATE.rmdir()
        raise


def current():
    require(os.geteuid() == ROOT_UID)
    directory = owned(STATE, 0o700, directory=True)
    require({path.name for path in STATE.iterdir()} == set(FILES))
    state = parse(read(STATE / "state.json"))
    require(set(state) == {"schema", "kind", "work", "work_identity", "manifest_sha256", "core_sha256",
        "prepared_sha256", "control_gid", "expires_at", "ready_sha256"}
        and type(state["schema"]) is int and state["schema"] == 6 and state["kind"] == "weather-android-controller")
    require(all(type(state[key]) is str and HEX.fullmatch(state[key]) for key in
        ("manifest_sha256", "core_sha256", "prepared_sha256", "ready_sha256")))
    require(type(state["expires_at"]) is int)
    work = Path(state["work"]); info = work_directory(work)
    require(identity(info) == state["work_identity"])
    _, group = accounts(state["control_gid"]); require(info.st_gid == group)
    owner = parse(read(work / OWNER_NAME))
    require(set(owner) == {"schema", "prepared_sha256", "directory", "files"}
        and type(owner["schema"]) is int and owner["schema"] == 6
        and owner["prepared_sha256"] == state["prepared_sha256"]
        and owner["directory"] == identity(directory) and set(owner["files"]) == set(FILES))
    for name in FILES: require(identity(owned(STATE / name, 0o600)) == owner["files"][name])
    raw = read(STATE / "ready.json"); require(digest(raw) == state["ready_sha256"])
    ready = parse(raw); api_module(work)["validate_record"](ready)
    require(ready["kind"] == "weather-android-api-ready" and all(ready[key] == state[key]
        for key in ("manifest_sha256", "core_sha256", "prepared_sha256", "expires_at")))
    path = socket_check(work, ready)
    require(parse(read(STATE / "endpoint.json")) == dict(schema=1, socket=str(path),
        control_gid=state["control_gid"], expires_at=state["expires_at"]))
    return work, state, ready


def read_ready():
    _, state, ready = current()
    return ready_result(state, ready, int(time.time()))


def finalize():
    work, state, ready = current()
    ready_result(state, ready, int(time.time()))
    path = work / "weather-android-api-finalize.json"
    value = dict(schema=6, action="finalize", prepared_sha256=state["prepared_sha256"])
    if absent(path): write(path, encode(value), 0o444)
    else: require(parse(read(path, 0o444)) == value)
    return dict(schema=6, kind="weather-android-finalize-requested", prepared_sha256=state["prepared_sha256"],
        finalize_requested=True, joined_delivery_proven=False)


def remove(work, prepared_sha):
    require(os.geteuid() == ROOT_UID and HEX.fullmatch(prepared_sha)); work_directory(work)
    owner_path = work / OWNER_NAME
    if absent(owner_path):
        require(absent(STATE))
        return dict(schema=6, controller_removed=True, private_proof_exported=False)
    owner = parse(read(owner_path))
    require(set(owner) == {"schema", "prepared_sha256", "directory", "files"}
        and type(owner["schema"]) is int and owner["schema"] == 6 and owner["prepared_sha256"] == prepared_sha
        and set(owner["files"]) == set(FILES))
    if not absent(STATE):
        require(identity(owned(STATE, 0o700, directory=True)) == owner["directory"])
        require({path.name for path in STATE.iterdir()} <= set(FILES))
        # Validate every remaining entry before removing any. Foreign entries,
        # links and replaced inodes leave the controller visibly unclean.
        for name in FILES:
            if not absent(STATE / name): require(identity(owned(STATE / name, 0o600)) == owner["files"][name])
        for name in FILES:
            if not absent(STATE / name): (STATE / name).unlink()
        STATE.rmdir()
    return dict(schema=6, controller_removed=True, private_proof_exported=False)


def main():
    os.umask(0o077)
    action, *args = sys.argv[1:]
    if action == "publish" and len(args) == 6:
        result = publish(Path(args[0]), *args[1:4], int(args[4]), int(args[5]))
    elif action == "read-ready" and not args: result = read_ready()
    elif action == "finalize" and not args: result = finalize()
    elif action == "remove" and len(args) == 2: result = remove(Path(args[0]), args[1])
    else: raise ValueError("weather_android_control_rejected")
    print(encode(result).decode(), end="", flush=True)


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, TypeError, KeyError):
        print('{"schema":6,"kind":"weather-android-controller-rejected","success":false}', flush=True)
        raise SystemExit(1)
