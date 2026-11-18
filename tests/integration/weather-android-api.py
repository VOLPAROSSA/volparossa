#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Own the fixed profile-6 Unix API until root requests finalization.

No HTTP probe, download, publication, emulator or workflow admission is supplied
here. Root stages prepared.json (worker 0400), captures two bounded JSONL records,
and creates the fixed root-owned finalize marker only after its Android phase.
Raw child output stays bounded in memory. Original private receipts stay in proof/
for the separate joined verifier; lifecycle success is not delivery acceptance.
"""
from contextlib import contextmanager
import ctypes
import hashlib
import json
from itertools import islice
import os
from pathlib import Path
import runpy
import selectors
import signal
import stat
import subprocess
import sys
import time

D = runpy.run_path(str(Path(__file__).with_name("weather-android-delivery.py")))
B, P = D["B"], D["P"]
require, same = D["require"], D["same"]
ROOT_UID = 0
MAX_LIFETIME = 840
STARTUP_SECONDS = 15
TERM_SECONDS = 10
KILL_SECONDS = 5
STDOUT_LIMIT = 4096
STDERR_LIMIT = 16384
READY = dict(listening="http://127.0.0.1:43210", transport="unix", scope="fixed-public-community-forecast")
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Failure(ValueError):
    """Only closed failure codes cross the worker boundary."""


class ApiInterrupted(Exception):
    """Owner cancellation must not be swallowed by selector EINTR handling."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    return json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])


def preflight(work, manifest_sha, prepared_sha, parent, client, group, expires_at):
    D["boundary"](parent, client, group)
    require(B["hex64"](manifest_sha) and B["hex64"](prepared_sha))
    require(type(expires_at) is int and 0 < expires_at - time.time() <= MAX_LIFETIME)
    layout = D["paths"](work)
    layout["prepared"] = layout["viewer"] / "prepared.json"
    layout["finalize"] = work / "weather-android-api-finalize.json"
    agent_uid, agent_gid = D["accounts"](group)
    work_info = D["validate_work"](work, agent_gid)
    D["owned"](work / "bin", stat.S_ISDIR, 0o755, ROOT_UID, agent_gid)
    D["private"](layout["viewer"].parent)
    viewer = D["private"](layout["viewer"])
    require({p.name for p in layout["viewer"].iterdir()} ==
        {"selection.json", "prepared.json", "config.json", *D["DIRECTORIES"]})
    directories = {}
    for name in D["DIRECTORIES"]:
        path = layout["viewer"] / name
        directories[name] = D["private"](path)
        require(not list(path.iterdir()))
    require(len(os.fsencode(layout["socket"])) < 104)
    D["absent"](layout["socket"]); D["absent"](layout["finalize"])
    prepared_raw = D["raw_file"](layout["prepared"], 8192, 0o400)
    D["owned"](layout["prepared"], stat.S_ISREG, 0o400, os.getuid())
    require(digest(prepared_raw) == prepared_sha)
    prepared = parse(prepared_raw); D["validate_prepared"](prepared)
    same(prepared["manifest_sha256"], manifest_sha)
    manifest_raw = D["raw_file"](layout["source"] / "INPUTS.json", B["MAX_MANIFEST"], 0o400)
    same(B["manifest"](manifest_raw, manifest_sha)["version"], 6)
    B["verify_tree"](layout["source"], manifest_sha)
    D["owned"](layout["binary"], stat.S_ISREG, 0o555, ROOT_UID, agent_gid)
    same(B["fingerprint"](layout["binary"], 256 * 1024**2, normalized=0o555)["sha256"], prepared["core_sha256"])
    D["owned"](layout["control"].parent, stat.S_ISDIR, 0o750, agent_uid, group)
    control = D["owned"](layout["control"], stat.S_ISSOCK, 0o660, agent_uid, group)
    cache = D["cache_parent"](layout["cache_parent"], agent_uid, group)
    selection_raw = D["raw_file"](layout["viewer"] / "selection.json", D["MAX_CONFIG"], 0o400)
    D["owned"](layout["viewer"] / "selection.json", stat.S_ISREG, 0o400, os.getuid())
    same(digest(selection_raw), prepared["selection_sha256"])
    selected = P["validate_selection"](parse(selection_raw))
    require(all(expires_at <= item["publication"]["expires_unix_seconds"] for item in selected["products"].values()))
    config_raw = D["raw_file"](layout["config"], D["MAX_CONFIG"], 0o600)
    D["private"](layout["config"], directory=False)
    same(digest(config_raw), prepared["config_sha256"])
    same(config_raw, B["encode"](D["configuration"](layout, selected)))
    require(expires_at > time.time())
    return dict(layout=layout, prepared=prepared, prepared_raw=prepared_raw, selection_raw=selection_raw,
        config_raw=config_raw, manifest_sha=manifest_sha, prepared_sha=prepared_sha, group=group,
        agent_uid=agent_uid, agent_gid=agent_gid, control=control, cache=cache, viewer=viewer,
        work=work_info, directories=directories, expires_at=expires_at, parent=parent, client=client)


def boundary(state):
    D["boundary"](state["parent"], state["client"], state["group"])


@contextmanager
def creating_child():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try: yield previous
    finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextmanager
def retiring_child():
    # An abort already selected its failed result. Repeated owner cancellation
    # must not strand descendants by interrupting the bounded TERM/KILL join.
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in SIGNALS}
    try: yield
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)


def command(state):
    layout = state["layout"]
    return [str(layout["source"] / "runtime/node"), "--max-old-space-size=256",
        str(layout["source"] / B["WEATHER"] / "scripts/serve-provider.mjs"),
        "--config", str(layout["config"]), "--socket", str(layout["socket"]),
        "--proof-profile", D["PROFILE"], "--private-receipt-directory", str(layout["proof"])]


def parent_identities(state):
    layout = state["layout"]
    require(D["inode"](D["private"](layout["viewer"])) == D["inode"](state["viewer"]))
    for name, saved in state["directories"].items():
        require(D["inode"](D["private"](layout["viewer"] / name)) == D["inode"](saved))
    require(D["inode"](D["validate_work"](layout["work"], state["agent_gid"])) == D["inode"](state["work"]))


def ready_socket(state):
    parent_identities(state)
    path = state["layout"]["socket"]
    require({p.name for p in path.parent.iterdir()} == {"core-api.sock"})
    return D["owned"](path, stat.S_ISSOCK, 0o600, os.getuid())


def finalize_requested(state):
    path = state["layout"]["finalize"]
    try: path.lstat()
    except FileNotFoundError: return False
    # The worker cannot create/replace this root entry in the root-owned WORK.
    before = D["owned"](path, stat.S_ISREG, 0o444, ROOT_UID)
    raw = D["raw_file"](path, 1024, 0o444)
    require(B["identity"](path.lstat()) == B["identity"](before))
    same(parse(raw), dict(schema=6, action="finalize", prepared_sha256=state["prepared_sha"]))
    return True


class Child:
    """Single-threaded owner/subreaper for this one child and its descendants."""
    def __init__(self):
        self.process = None
        self.selector = selectors.DefaultSelector()
        self.data = {"stdout": bytearray(), "stderr": bytearray()}
        self.overflow = False
        self.forced = False
        self.children = Path(f"/proc/self/task/{os.getpid()}/children")
        try:
            require(not self.children.read_text().strip() and len(list(Path("/proc/self/task").iterdir())) == 1)
            require(not set(signal.pthread_sigmask(signal.SIG_BLOCK, [])) & set(SIGNALS))
            self.libc = ctypes.CDLL(None, use_errno=True)
            self.old_reaper = ctypes.c_int()
            require(self.libc.prctl(37, ctypes.byref(self.old_reaper), 0, 0, 0) == 0)
            require(self.libc.prctl(36, 1, 0, 0, 0) == 0)
        except BaseException:
            self.selector.close()
            raise

    def start(self, argv, cwd):
        # No inherited Node options, proxy settings, keys or arbitrary environment.
        with creating_child() as previous_mask:
            self.process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                env=dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8"), close_fds=True,
                # The parent blocks cancellation only until it owns the PID.
                # Its single-threaded child must not inherit that blocked mask:
                # doing so would make even a healthy server ignore owner TERM.
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask))
            for name in self.data:
                stream = getattr(self.process, name)
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, name)

    def pump(self, wait=0.05, cleanup=False):
        for key, _ in self.selector.select(wait):
            name = key.data
            limit = STDOUT_LIMIT if name == "stdout" else STDERR_LIMIT
            raw = os.read(key.fileobj.fileno(), min(4096, max(1, limit + 1 - len(self.data[name]))))
            if not raw:
                self.selector.unregister(key.fileobj)
                continue
            if len(self.data[name]) <= limit: self.data[name].extend(raw)
            if len(self.data[name]) > limit:
                self.overflow = True
                # Do not keep reading an unlimited log stream during cleanup.
                self.selector.unregister(key.fileobj); key.fileobj.close()
                if not cleanup: raise Failure("output-limit")

    def signal_group(self, signum):
        # A non-reaped leader still owns this PID. Never target a reused PGID
        # after poll/wait has reaped it; subreaper ownership handles its orphans.
        if self.process is not None and self.process.returncode is None:
            try: os.killpg(self.process.pid, signum)
            except ProcessLookupError: pass

    def orphans(self, signum):
        pending = self.children.read_text().split()
        for child in pending[:64]:
            pid = int(child)
            if self.process is not None and pid == self.process.pid: continue
            # This process had no children before becoming subreaper. Live direct
            # children cannot be PID-reused until this sole owner reaps them.
            if os.waitpid(pid, os.WNOHANG)[0] == 0:
                try: os.kill(pid, signum)
                except ProcessLookupError: pass

    def stop(self):
        drained, checked = False, True
        for signum, duration in ((signal.SIGTERM, TERM_SECONDS), (signal.SIGKILL, KILL_SECONDS)):
            if signum == signal.SIGKILL: self.forced = True
            try: self.signal_group(signum)
            except OSError: checked = False
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                try: self.pump(cleanup=True)
                except (OSError, ValueError): checked = False
                if self.process is not None: self.process.poll()
                try:
                    self.orphans(signum)
                    if not self.children.read_text().strip() and not self.selector.get_map():
                        drained = True
                        break
                except (OSError, ValueError):
                    # A failed ownership check must not skip the second, bounded
                    # KILL stage for the known child process group.
                    checked = False
            if drained: break
        for name in self.data:
            if self.process is not None:
                stream = getattr(self.process, name)
                if stream is not None: stream.close()
        self.selector.close()
        if drained and self.libc.prctl(36, self.old_reaper.value, 0, 0, 0) != 0: checked = False
        return dict(child_reaped=self.process is None or self.process.returncode is not None,
            descendants_reaped=drained, forced_kill=self.forced, drain_checked=checked and not self.overflow)


def retained_files(state):
    """Bounded metadata checks only; never export/delete original private proof."""
    layout = state["layout"]
    allowed = {f"{product}-{ordinal}.{suffix}": limit
        for product in ("weather", "air_quality") for ordinal in (1, 2, 3)
        for suffix, limit in (("receipt.json", 16384), ("observation.json", 2048))}
    entries = list(islice(layout["proof"].iterdir(), 13))
    require(len(entries) <= 12)
    for path in entries:
        require(path.name in allowed)
        info = D["private"](path, directory=False)
        # Zero-length/partial owned files may be retained after a failed write;
        # the separate receipt verifier must reject them as delivery evidence.
        require(0 <= info.st_size <= allowed[path.name])
    return len(entries)


def postflight(state):
    boundary(state)
    layout = state["layout"]
    parent_identities(state)
    D["absent"](layout["socket"])
    require(not list(layout["socket"].parent.iterdir()) and not list(layout["scratch"].iterdir()))
    same(D["raw_file"](layout["prepared"], 8192, 0o400), state["prepared_raw"])
    same(D["raw_file"](layout["config"], D["MAX_CONFIG"], 0o600), state["config_raw"])
    same(D["raw_file"](layout["viewer"] / "selection.json", D["MAX_CONFIG"], 0o400), state["selection_raw"])
    D["owned"](layout["binary"], stat.S_ISREG, 0o555, ROOT_UID, state["agent_gid"])
    same(B["fingerprint"](layout["binary"], 256 * 1024**2, normalized=0o555)["sha256"], state["prepared"]["core_sha256"])
    B["verify_tree"](layout["source"], state["manifest_sha"])
    require(D["inode"](D["owned"](layout["control"], stat.S_ISSOCK, 0o660,
        state["agent_uid"], state["group"])) == D["inode"](state["control"]))
    require(D["inode"](D["owned"](layout["cache_parent"], stat.S_ISDIR, 0o710,
        state["agent_uid"], state["group"])) == D["inode"](state["cache"]))
    return retained_files(state)


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def serve(state, notify=emit):
    owner = Child()
    reason, ready, ready_info, ready_raw = "rejected", False, None, None
    cleanup = dict(child_reaped=False, descendants_reaped=False, forced_kill=False, drain_checked=False)
    checked, retained = False, None
    started = int(time.time() * 1000)
    deadline = time.monotonic() + max(0, state["expires_at"] - time.time())
    try:
        boundary(state)
        owner.start(command(state), state["layout"]["viewer"])
        startup = min(deadline, time.monotonic() + STARTUP_SECONDS)
        while True:
            if time.monotonic() >= deadline or time.time() >= state["expires_at"]: raise Failure("deadline")
            if not ready and time.monotonic() >= startup: raise Failure("startup-timeout")
            owner.pump()
            if owner.process.poll() is not None: raise Failure("child-exited")
            raw = bytes(owner.data["stdout"])
            if not ready and b"\n" in raw:
                same(parse(raw), READY)
                ready_info = ready_socket(state)
                require(not list(state["layout"]["scratch"].iterdir()) and not list(state["layout"]["proof"].iterdir()))
                D["cache_parent"](state["layout"]["cache_parent"], state["agent_uid"], state["group"])
                boundary(state)
                require(time.monotonic() < startup and time.time() < state["expires_at"])
                ready = True
                ready_raw = raw
                record = dict(schema=6, kind="weather-android-api-ready", profile=D["PROFILE"],
                    manifest_sha256=state["manifest_sha"], prepared_sha256=state["prepared_sha"],
                    config_sha256=state["prepared"]["config_sha256"], core_sha256=state["prepared"]["core_sha256"],
                    socket=dict(device=ready_info.st_dev, inode=ready_info.st_ino, user_uid=ready_info.st_uid, mode="0600"),
                    started_at_ms=started, ready_at_ms=int(time.time() * 1000), expires_at=state["expires_at"],
                    cold_caches_absent=True, helper_requests=0, joined_delivery_proven=False)
                validate_record(record); notify(record)
            if ready:
                same(raw, ready_raw)
                require(D["inode"](ready_socket(state)) == D["inode"](ready_info))
                if finalize_requested(state):
                    boundary(state)
                    reason = "finalized"
                    break
    except Failure as error: reason = str(error)
    except ApiInterrupted: reason = "interrupted"
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError): reason = "rejected"
    finally:
        # The outer signal handler cannot interrupt retirement a second time.
        with retiring_child():
            try: cleanup = owner.stop()
            except (OSError, ValueError, subprocess.SubprocessError): reason = "cleanup-unconfirmed"
        if cleanup["child_reaped"] and cleanup["descendants_reaped"]:
            try:
                retained = postflight(state); checked = True
            except (OSError, ValueError, TypeError, KeyError): pass
    # Retirement may continue after expiry to avoid abandoning processes, but
    # finishing late cannot turn an expired lifecycle into successful evidence.
    if reason == "finalized" and (time.monotonic() >= deadline or time.time() >= state["expires_at"]):
        reason = "deadline"
    success = (reason == "finalized" and ready and owner.process is not None
        and owner.process.returncode == 0 and not owner.overflow and not cleanup["forced_kill"]
        and bytes(owner.data["stdout"]) == ready_raw
        and cleanup["child_reaped"] and cleanup["descendants_reaped"] and cleanup["drain_checked"] and checked)
    if reason == "finalized" and not success: reason = "cleanup-unconfirmed"
    result = dict(schema=6, kind="weather-android-api-final", profile=D["PROFILE"], success=success, reason=reason,
        ready=ready, manifest_sha256=state["manifest_sha"], prepared_sha256=state["prepared_sha"],
        exit_status=None if owner.process is None else owner.process.returncode,
        cleanup=dict(**cleanup, inputs_and_private_directories_checked=checked), retained_files=retained,
        stdout_bytes=len(owner.data["stdout"]), stderr_bytes=len(owner.data["stderr"]),
        helper_requests=0, native_android_proven=False, joined_delivery_proven=False)
    validate_record(result); notify(result)
    return result


def validate_record(value):
    require(type(value) is dict)
    same(value["schema"], 6); same(value["profile"], D["PROFILE"])
    same(value["helper_requests"], 0); same(value["joined_delivery_proven"], False)
    for key in ("manifest_sha256", "prepared_sha256"): require(B["hex64"](value[key]))
    common = {"schema", "kind", "profile", "manifest_sha256", "prepared_sha256", "helper_requests", "joined_delivery_proven"}
    if value["kind"] == "weather-android-api-ready":
        require(set(value) == common | {"config_sha256", "core_sha256", "socket", "started_at_ms", "ready_at_ms", "expires_at", "cold_caches_absent"})
        for key in ("config_sha256", "core_sha256"): require(B["hex64"](value[key]))
        same(value["cold_caches_absent"], True)
        require(type(value["socket"]) is dict and set(value["socket"]) == {"device", "inode", "user_uid", "mode"})
        same(value["socket"]["user_uid"], D["WORKER_UID"]); same(value["socket"]["mode"], "0600")
        require(all(type(value["socket"][k]) is int and value["socket"][k] >= 0 for k in ("device", "inode")))
        require(all(type(value[k]) is int and value[k] > 0 for k in ("started_at_ms", "ready_at_ms", "expires_at")))
        require(value["started_at_ms"] <= value["ready_at_ms"] < value["expires_at"] * 1000)
    else:
        same(value["kind"], "weather-android-api-final")
        require(set(value) == common | {"success", "reason", "ready", "exit_status", "cleanup", "retained_files", "stdout_bytes", "stderr_bytes", "native_android_proven"})
        same(value["native_android_proven"], False)
        require(type(value["success"]) is bool and type(value["ready"]) is bool and value["reason"] in
            {"rejected", "deadline", "startup-timeout", "child-exited", "output-limit", "interrupted", "finalized", "cleanup-unconfirmed"})
        require(value["exit_status"] is None or type(value["exit_status"]) is int and -128 <= value["exit_status"] <= 255)
        require(type(value["cleanup"]) is dict and set(value["cleanup"]) ==
            {"child_reaped", "descendants_reaped", "forced_kill", "drain_checked", "inputs_and_private_directories_checked"})
        require(all(type(item) is bool for item in value["cleanup"].values()))
        require(value["retained_files"] is None or type(value["retained_files"]) is int and 0 <= value["retained_files"] <= 12)
        for key, limit in (("stdout_bytes", STDOUT_LIMIT), ("stderr_bytes", STDERR_LIMIT)):
            require(type(value[key]) is int and 0 <= value[key] <= limit + 1)
        if value["success"]:
            same(value["reason"], "finalized"); same(value["ready"], True); same(value["exit_status"], 0)
            same(value["cleanup"], dict(child_reaped=True, descendants_reaped=True, forced_kill=False,
                drain_checked=True, inputs_and_private_directories_checked=True))


def main():
    action, *args = sys.argv[1:]
    require(action == "serve" and len(args) == 7)
    def interrupted(_signal, _frame): raise ApiInterrupted("weather_android_api_interrupted")
    previous = {sig: signal.signal(sig, interrupted) for sig in SIGNALS}
    try:
        state = preflight(Path(args[0]), args[1], args[2], args[3], args[4], int(args[5]), int(args[6]))
        result = serve(state)
        if not result["success"]: raise SystemExit(1)
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, TypeError, KeyError, ApiInterrupted):
        print('{"schema":6,"kind":"weather-android-api-rejected","success":false}', flush=True)
        raise SystemExit(1)
