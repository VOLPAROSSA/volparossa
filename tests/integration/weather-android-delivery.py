#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the fixed Android profile-6 API, without starting or fetching anything.

The disposable root driver stages the source, selection and agent-owned cache
parent first. This worker must be UID 985, capless, in the client namespace.
There is deliberately no serve/download command and no runtime admission here.
The caller retains the closed stdout record; original forecasts never enter the
viewer during preparation. Runtime shutdown/receipt retention is a separate step.
"""
from contextlib import contextmanager
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import signal
import stat
import sys
import time

P = runpy.run_path(str(Path(__file__).with_name("weather-products-delivery.py")))
B = P["B"]
require, same, private = P["require"], P["same"], P["private"]
raw_file, boundary = P["raw_file"], P["boundary"]
WORKER_UID = 985
ROOT_UID = 0
MAX_CONFIG = 16384
DIRECTORIES = ("scratch", "socket", "proof")
PROFILE = "android-protected-core-v6"


class PreparationCleanupUnconfirmed(ValueError):
    """Do not hide incomplete cleanup behind the original preparation failure."""


def paths(work):
    viewer = work / "client-fixtures/weather-viewer"
    return dict(work=work, source=work / "client-fixtures/weather-client-source", viewer=viewer,
        binary=work / "bin/volparossa", control=work / "runtime-client/control/agent.sock",
        cache_parent=work / "weather-android-cache", config=viewer / "config.json",
        socket=viewer / "socket/core-api.sock", scratch=viewer / "scratch", proof=viewer / "proof")


def canonical(path):
    require(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink()
        and not re.search(r"[\x00-\x1f\x7f]", str(path)))


def owned(path, kind, mode, uid, gid=None):
    canonical(path)
    info = path.lstat()
    require(kind(info.st_mode) and stat.S_IMODE(info.st_mode) == mode and info.st_uid == uid
        and (gid is None or info.st_gid == gid))
    if not stat.S_ISDIR(info.st_mode): require(info.st_nlink == 1)
    return info


def inode(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def accounts(group):
    require(type(group) is int and 0 < group <= 65535)
    agent = pwd.getpwnam("volparossa")
    worker = pwd.getpwnam("volparossa-worker")
    require(worker.pw_uid == WORKER_UID and 0 < agent.pw_uid != WORKER_UID
        and 0 < agent.pw_gid != group and grp.getgrnam("volparossa-users").gr_gid == group)
    return agent.pw_uid, agent.pw_gid


def validate_work(work, agent_gid):
    require(work.parent == Path("/opt")
        and re.fullmatch(r"va\.[a-f0-9]{32}\.[A-Za-z0-9]{6}", work.name))
    return owned(work, stat.S_ISDIR, 0o755, ROOT_UID, agent_gid)


def absent(path):
    try: path.lstat()
    except FileNotFoundError: return
    raise ValueError("weather_android_path_exists")


def cache_parent(path, agent_uid, group):
    # Root stages this *separate* directory. The worker gets search, never list,
    # write or agent-state access. An unreadable parent is not an absent cache.
    before = owned(path, stat.S_ISDIR, 0o710, agent_uid, group)
    for key in P["PRODUCTS"]: absent(path / P["product"](key)["cache"])
    require(inode(path.lstat()) == inode(before))
    return before


def prerequisites(layout, manifest_sha, group):
    agent_uid, agent_gid = accounts(group)
    validate_work(layout["work"], agent_gid)
    owned(layout["work"] / "bin", stat.S_ISDIR, 0o755, ROOT_UID, agent_gid)
    private(layout["viewer"].parent); private(layout["viewer"])
    require({child.name for child in layout["viewer"].iterdir()} == {"selection.json"})
    require(len(os.fsencode(layout["socket"])) < 104)
    raw = raw_file(layout["source"] / "INPUTS.json", B["MAX_MANIFEST"], 0o400)
    manifest = B["manifest"](raw, manifest_sha)
    same(manifest["version"], 6)
    B["verify_tree"](layout["source"], manifest_sha)
    program = owned(layout["binary"], stat.S_ISREG, 0o555, ROOT_UID, agent_gid)
    core = B["fingerprint"](layout["binary"], 256 * 1024**2, normalized=0o555)
    require(B["identity"](layout["binary"].lstat()) == B["identity"](program))
    owned(layout["control"].parent, stat.S_ISDIR, 0o750, agent_uid, group)
    control = owned(layout["control"], stat.S_ISSOCK, 0o660, agent_uid, group)
    cache = cache_parent(layout["cache_parent"], agent_uid, group)
    selection_path = layout["viewer"] / "selection.json"
    owned(selection_path, stat.S_ISREG, 0o400, WORKER_UID)
    selection_raw = raw_file(selection_path, MAX_CONFIG, 0o400)
    selection = P["validate_selection"](json.loads(selection_raw, object_pairs_hook=B["B"]["unique_pairs"]))
    now = int(time.time())
    require(all(item["publication"]["expires_unix_seconds"] > now for item in selection["products"].values()))
    return dict(agent_uid=agent_uid, agent_gid=agent_gid, cache=cache, control=control,
        core=core, manifest_raw=raw, selection_raw=selection_raw, selection=selection)


def configuration(layout, selection):
    P["validate_selection"](selection)
    def core(key):
        selected = selection["products"][key]
        publication = selected["publication"]
        return dict(mode="core-cache", executable=str(layout["binary"]), controlSocket=str(layout["control"]),
            cache=str(layout["cache_parent"] / P["product"](key)["cache"]), scratchParent=str(layout["scratch"]),
            publisherKey=publication["publisher_key"], name=publication["name"], minRevision=publication["revision"],
            query=selected["query"], cacheMode="create-or-open")
    return dict(core=core("weather"), variables=P["V1"]["VARIABLES"],
        airQuality=dict(core=core("air_quality"), variables=["pm2_5", "pm10"]))


@contextmanager
def creation_window():
    # Do not deliver TERM/INT between exclusive creation and recording ownership.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try: yield
    finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class Additions:
    """Only new direct viewer children, pinned by directory fd and inode."""
    def __init__(self, viewer):
        self.path, self.created = viewer, []
        self.fd = os.open(viewer, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.info = os.fstat(self.fd)
        try: self.check_parent()
        except BaseException:
            os.close(self.fd)
            raise

    def check_parent(self):
        require(inode(private(self.path)) == inode(self.info) == inode(os.fstat(self.fd)))

    def directory(self, name):
        self.check_parent()
        with creation_window():
            os.mkdir(name, mode=0o700, dir_fd=self.fd)
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            self.created.append((name, info, True))
        require(inode(private(self.path / name)) == inode(info))

    def file(self, name, raw):
        self.check_parent()
        fd = None
        try:
            with creation_window():
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
                info = os.fstat(fd)
                self.created.append((name, info, False))
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600)
            remaining = memoryview(raw)
            while remaining:
                count = os.write(fd, remaining)
                require(count > 0)
                remaining = remaining[count:]
            after = os.fstat(fd)
            require(inode(after) == inode(info) and after.st_size == len(raw) and after.st_nlink == 1)
        finally:
            if fd is not None: os.close(fd)

    def rollback(self):
        # Never recurse, follow a symlink or delete a replacement/foreign file.
        # The pinned fd still permits cleanup if the owned viewer was renamed.
        failed = False
        for name, expected, directory in reversed(self.created):
            try:
                actual = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                require(inode(actual) == inode(expected))
                if directory: os.rmdir(name, dir_fd=self.fd)
                else:
                    require(actual.st_nlink == 1)
                    os.unlink(name, dir_fd=self.fd)
            except (OSError, ValueError): failed = True
        if failed: raise PreparationCleanupUnconfirmed("weather_android_prepare_cleanup_unconfirmed")

    def close(self):
        os.close(self.fd)


def prepare(work, manifest_sha, parent, client, group):
    boundary(parent, client, group)
    layout = paths(work)
    before = prerequisites(layout, manifest_sha, group)
    encoded = B["encode"](configuration(layout, before["selection"]))
    require(0 < len(encoded) <= MAX_CONFIG)
    additions = Additions(layout["viewer"])
    try:
        for name in DIRECTORIES: additions.directory(name)
        additions.file("config.json", encoded)
        additions.check_parent()
        for name in DIRECTORIES:
            private(layout["viewer"] / name)
            require(not list((layout["viewer"] / name).iterdir()))
        require({p.name for p in layout["viewer"].iterdir()} == {"selection.json", "config.json", *DIRECTORIES})
        same(raw_file(layout["config"], MAX_CONFIG, 0o600), encoded)
        same(raw_file(layout["viewer"] / "selection.json", MAX_CONFIG, 0o400), before["selection_raw"])
        same(raw_file(layout["source"] / "INPUTS.json", B["MAX_MANIFEST"], 0o400), before["manifest_raw"])
        same(B["fingerprint"](layout["binary"], 256 * 1024**2, normalized=0o555), before["core"])
        require(inode(owned(layout["control"], stat.S_ISSOCK, 0o660, before["agent_uid"], group)) == inode(before["control"]))
        require(inode(cache_parent(layout["cache_parent"], before["agent_uid"], group)) == inode(before["cache"]))
        require(all(item["publication"]["expires_unix_seconds"] > int(time.time())
            for item in before["selection"]["products"].values()))
        result = dict(schema=6, kind="weather-android-prepared", profile=PROFILE, prepared=True,
            manifest_sha256=manifest_sha, core_sha256=before["core"]["sha256"],
            selection_sha256=hashlib.sha256(before["selection_raw"]).hexdigest(),
            config_sha256=hashlib.sha256(encoded).hexdigest(), runtime_executed=False,
            forecast_prefetched=False, native_android_proven=False, joined_delivery_proven=False)
        validate_prepared(result)
        return result
    except BaseException:
        # Cleanup failures supersede the triggering failure, never a success.
        with creation_window(): additions.rollback()
        raise
    finally: additions.close()


def validate_prepared(value):
    fields = {"schema", "kind", "profile", "prepared", "manifest_sha256", "core_sha256", "selection_sha256",
        "config_sha256", "runtime_executed", "forecast_prefetched", "native_android_proven", "joined_delivery_proven"}
    require(type(value) is dict and set(value) == fields)
    same(value["schema"], 6); same(value["kind"], "weather-android-prepared"); same(value["profile"], PROFILE)
    same(value["prepared"], True)
    for field in ("manifest_sha256", "core_sha256", "selection_sha256", "config_sha256"):
        require(B["hex64"](value[field]))
    for field in ("runtime_executed", "forecast_prefetched", "native_android_proven", "joined_delivery_proven"):
        same(value[field], False)


def main():
    action, *args = sys.argv[1:]
    require(action == "prepare" and len(args) == 5)
    def interrupted(_signal, _frame): raise InterruptedError("weather_android_prepare_interrupted")
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        result = prepare(Path(args[0]), args[1], args[2], args[3], int(args[4]))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)


if __name__ == "__main__":
    try: main()
    except PreparationCleanupUnconfirmed:
        print('{"prepared":false,"failure":"weather_android_prepare_cleanup_unconfirmed"}')
        raise SystemExit(1)
    except (OSError, ValueError, TypeError, KeyError):
        print('{"prepared":false,"failure":"weather_android_prepare_rejected"}')
        raise SystemExit(1)
