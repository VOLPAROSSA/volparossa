#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit disposable-guest load fixture; never a product budget or transfer proof.

observe WORK starts before the ordinary native fetch. The ready receipt binds a
cold cache. Only three complete, content-address-verified public fixture chunks
can trigger two capless CPU workers. No cache is opened as a ChunkStore or written.
All production admission, transfer deadlines and continuation decisions stay real.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import runpy
import select
import signal
import socket
import stat
import subprocess
import sys
import time

PSI = runpy.run_path(str(Path(__file__).with_name("content-provider-resource-ready.py")))
PREFIX = "content-provider-pressure"
CHUNK_BYTES = 262144
OBJECT_SHA = "8fd67e1fc14d95b27d5d9be573c6609baf59054a129a669a15a6cd4562b41ecb"
# adaptive.rs::seed publishes A..|, with chunk i stored exclusively by i % 3.
CHUNKS = tuple(hashlib.sha256(bytes([65+i]) * CHUNK_BYTES).hexdigest() for i in range(3))
WAIT_NS = 30_000_000_000
LOAD_NS = 10_000_000_000
ACTIVE_NS = 9_000_000_000  # Final second is reserved for exact owned-child drain.
POLL_NS = 200_000_000
MEMORY_FLOOR = 512 * 1024 * 1024
ADDRESS_SPACE = 128 * 1024 * 1024
MAX_REPORT = 4096
SCOPE = dict(disposable_guest=True, cache_read_only=True, synthetic_budget=False,
             agent_affinity_changed=False, continuation_claimed=False,
             transfer_completion_claimed=False, owner_goodput_claimed=False)
STATUSES = {"observed", "trigger-timeout", "pressure-missing", "resource-unavailable",
            "interrupted", "invalid", "load-failed", "cleanup-failed"}


def require(value):
    if not value:
        raise ValueError("invalid bounded pressure fixture")


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def directory(name, owner, *, parent=None):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022)
        return fd
    except BaseException:
        os.close(fd)
        raise


def file_bytes(parent, name, owner, maximum, *, exact=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 < before.st_size <= maximum
                and (exact is None or before.st_size == exact))
        parts, count = [], 0
        while count <= maximum:
            part = os.read(fd, maximum + 1 - count)
            if not part:
                break
            parts.append(part)
            count += len(part)
        after = os.fstat(fd)
        require(count == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return b"".join(parts)
    finally:
        os.close(fd)


def absent(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def write_record(parent, name, value):
    require(name in (PREFIX + "-ready.json", PREFIX + "-controller.json"))
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    require(len(raw) <= MAX_REPORT)
    temporary = "." + name + ".part"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
        publish(parent, temporary, name)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def publish(parent, temporary, name):
    # Linux guest fixture: atomic visibility, no overwrite and no temporary
    # second hardlink that would violate readers' single-link safety check.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(temporary), parent, os.fsencode(name), 1) != 0:
        raise OSError(ctypes.get_errno(), "private fixture publication failed")


def publication(parent, owner, *, now=None):
    value = decode(file_bytes(parent, "content-provider-adaptive-publication.json", owner, MAX_REPORT))
    require(value["report_kind"] == "volparossa-content-adaptive-provider-seed"
            and value["object_sha256"] == OBJECT_SHA and type(value["bytes"]) is int
            and value["bytes"] == 60 * CHUNK_BYTES and type(value["chunks"]) is int
            and value["chunks"] == 60 and value["publisher_removed"] is True
            and value["publisher_private_key_persisted"] is False
            and value["recipient_encrypted"] is False)
    now = int(time.time()) if now is None else now
    created, expires = value["created_unix_seconds"], value["expires_unix_seconds"]
    require(type(created) is int and type(expires) is int
            and 0 < created <= now < expires and expires-created == 3600)
    for label in "abc":
        require(type(value[f"replica_{label}_chunks"]) is int and value[f"replica_{label}_chunks"] == 20
                and type(value[f"replica_{label}_bytes"]) is int
                and value[f"replica_{label}_bytes"] == 20 * CHUNK_BYTES)
    for key in ("manifest_id", "publisher_hex"):
        require(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key]))
    return dict(manifest_id=value["manifest_id"], publisher_hex=value["publisher_hex"], object_sha256=OBJECT_SHA)


class CacheObserver:
    def __init__(self, work, owner):
        self.owner = owner
        self.root = directory("state-client", owner, parent=work)
        self.parent = None
        self.cache = None
        try:
            self.parent = directory("content-adaptive-pressure", owner, parent=self.root)
            require(stat.S_IMODE(os.fstat(self.parent).st_mode) == 0o700)
            require(absent(self.parent, "cache"))
        except BaseException:
            self.close()
            raise

    def sample(self):
        # Reopening these fixed directories checks replacement, without taking the
        # cache's exclusive mutation lock. No directory scans or index reads.
        current = directory("content-adaptive-pressure", self.owner, parent=self.root)
        try:
            require((os.fstat(current).st_dev, os.fstat(current).st_ino)
                    == (os.fstat(self.parent).st_dev, os.fstat(self.parent).st_ino))
        finally:
            os.close(current)
        if absent(self.parent, "cache"):
            require(self.cache is None)
            return 0
        current = directory("cache", self.owner, parent=self.parent)
        if self.cache is None:
            self.cache = current
        else:
            try:
                require((os.fstat(current).st_dev, os.fstat(current).st_ino)
                        == (os.fstat(self.cache).st_dev, os.fstat(self.cache).st_ino))
            finally:
                os.close(current)
        require(stat.S_IMODE(os.fstat(self.cache).st_mode) == 0o700)
        found = 0
        for name in CHUNKS:
            try:
                raw = file_bytes(self.cache, name, self.owner, CHUNK_BYTES, exact=CHUNK_BYTES)
            except FileNotFoundError:
                continue
            require(hashlib.sha256(raw).hexdigest() == name)
            found += 1
        return found

    def close(self):
        for name in ("cache", "parent", "root"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


def guest(work):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha"
            and work.is_absolute() and work.parent == Path("/opt")
            and re.fullmatch(r"va\.[0-9a-f]{32}\.[A-Za-z0-9]{6}", work.name)
            and work.resolve() == work)
    result = subprocess.run(["/usr/bin/systemd-detect-virt", "--vm"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=False)
    require(result.returncode == 0 and result.stdout == b"kvm\n")
    worker, agent = pwd.getpwnam("volparossa-worker"), pwd.getpwnam("volparossa")
    require(worker.pw_uid > 0 and worker.pw_gid > 0 and agent.pw_uid > 0
            and worker.pw_uid != agent.pw_uid and len(os.sched_getaffinity(0)) >= 2)
    return worker, agent.pw_uid


def memory_available():
    raw = PSI["read_bounded"](Path("/proc/meminfo"))
    rows = [line.split() for line in raw.splitlines() if line.startswith("MemAvailable:")]
    require(len(rows) == 1 and len(rows[0]) == 3 and rows[0][2] == "kB"
            and rows[0][1].isascii() and rows[0][1].isdigit())
    return int(rows[0][1]) * 1024 >= MEMORY_FLOOR


def child(cpu, deadline, parent, uid, gid, acknowledgement, original_mask):
    """Called only after the guarded parent forks; never exposed as a CLI action."""
    libc = ctypes.CDLL(None, use_errno=True)
    def prctl(option, arg=0):
        if libc.prctl(option, arg, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "worker sandbox")
    prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG, before any credential transition.
    require(os.getppid() == parent)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    os.setsid()
    os.umask(0o077)
    prctl(8, 0)  # Never retain capabilities across setuid.
    prctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL.
    for capability in range(64):
        if libc.prctl(24, capability, 0, 0, 0) != 0 and ctypes.get_errno() != errno.EINVAL:
            raise OSError(ctypes.get_errno(), "worker capability drop")
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS.
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    # Credential changes clear PDEATHSIG; restore it after dropping identity.
    prctl(1, signal.SIGKILL)
    require(os.getppid() == parent and os.getresuid() == (uid, uid, uid)
            and os.getresgid() == (gid, gid, gid) and os.getgroups() == [])
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE, ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    os.sched_setaffinity(0, {cpu})
    require(os.sched_getaffinity(0) == {cpu})
    status = Path("/proc/self/status").read_text(encoding="ascii")
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        require(re.search(rf"^{key}:\s+0+$", status, re.MULTILINE) is not None)
    require(re.search(r"^NoNewPrivs:\s+1$", status, re.MULTILINE) is not None)
    # Preserve only the one-byte setup acknowledgement; discard all inherited
    # fixture/cache descriptors and all I/O channels before burning CPU.
    os.dup2(acknowledgement, 3)
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    require(4 <= maximum <= 1_048_576)
    os.closerange(4, maximum)
    null = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    if null > 3:
        os.close(null)
    resource.setrlimit(resource.RLIMIT_NOFILE, (4, 4))
    require(time.monotonic_ns() < deadline)
    os.write(3, b"1")
    os.close(3)
    value = 1
    while time.monotonic_ns() < deadline:
        for _ in range(1024):
            value = (value * 1664525 + 1013904223) & 0xffffffff


class Workers:
    def __init__(self, worker):
        self.worker = worker
        self.children = {}
        self.ready = 0
        self.forced = 0

    def start(self, deadline):
        cpu, parent = min(os.sched_getaffinity(0)), os.getpid()
        for _ in range(2):
            require(time.monotonic_ns() < deadline)
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
            try:
                # A cancellation must not land between fork and recording the
                # exact child we must reap. The child restores the inherited
                # mask only after PDEATHSIG and default handlers are installed.
                original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
                pid = None
                try:
                    pid = os.fork()
                    if pid == 0:
                        try:
                            os.close(read_fd)
                            child(cpu, deadline, parent, self.worker.pw_uid, self.worker.pw_gid,
                                  write_fd, original_mask)
                        except BaseException:
                            os._exit(1)
                        os._exit(0)
                    self.children[pid] = None
                finally:
                    if pid != 0:
                        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
                os.close(write_fd)
                write_fd = None
                remaining = min(1.0, (deadline-time.monotonic_ns()) / 1e9)
                require(remaining > 0 and select.select([read_fd], [], [], remaining)[0])
                require(os.read(read_fd, 2) == b"1")
                self.ready += 1
            finally:
                os.close(read_fd)
                if write_fd is not None:
                    os.close(write_fd)

    def poll(self):
        for pid, code in list(self.children.items()):
            if code is None:
                reaped, status = os.waitpid(pid, os.WNOHANG)
                if reaped:
                    self.children[pid] = os.waitstatus_to_exitcode(status)

    def alive(self):
        self.poll()
        return self.ready == 2 and all(code is None for code in self.children.values())

    def stop(self):
        # Normal cancellation reaps our own direct children. If this controller
        # is SIGKILLed, PDEATHSIG terminates workers but their reap belongs to
        # the guest init; no completed controller receipt is then promised.
        previous = {number: signal.signal(number, signal.SIG_IGN)
                    for number in (signal.SIGTERM, signal.SIGINT)}
        try:
            self._stop()
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)

    def _stop(self):
        # These are unreaped direct children, not PIDs recovered from a pathname.
        # A PID cannot be reused while its owned child has not been waitpid-reaped.
        self.poll()
        for pid, code in self.children.items():
            if code is None:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic_ns() + 1_000_000_000
        gentle = deadline - 750_000_000
        while any(code is None for code in self.children.values()) and time.monotonic_ns() < gentle:
            self.poll()
            time.sleep(0.01)
        self.poll()
        for pid, code in self.children.items():
            if code is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                    self.forced += 1
                except ProcessLookupError:
                    pass
        while any(code is None for code in self.children.values()) and time.monotonic_ns() < deadline:
            self.poll()
            time.sleep(0.01)
        self.poll()
        require(all(code is not None for code in self.children.values()))

    def receipt(self):
        return dict(spawned=len(self.children), ready=self.ready,
                    reaped=sum(code is not None for code in self.children.values()),
                    forced_kills=self.forced, exit_codes=list(self.children.values()))


def coordinate(observer, workers, *, clock=time.monotonic_ns, sleep=time.sleep,
               sampler=PSI["observe"], memory=memory_available):
    start = clock()
    result = dict(schema_version=1, kind="content-provider-pressure-controller", success=False,
                  scope=dict(SCOPE), status="invalid", cold_begin=True, started_ns=start,
                  trigger_ns=None, verified_chunks=0, verified_bytes=0,
                  load_started_ns=None, load_stopped_ns=None, completed_ns=None,
                  wait_limit_ms=30000, load_limit_ms=10000, samples=0,
                  cpu_pressure_observed=False, other_pressure_observed=False,
                  psi_unavailable=False, initial_observation=None, last_observation=None,
                  first_pressure_ns=None, cleanup=None)
    try:
        while clock() < start + WAIT_NS:
            require(memory())
            count = observer.sample()
            require(type(count) is int and 0 <= count <= 3)
            if count == 3:
                require(clock() < start + WAIT_NS)
                result.update(trigger_ns=clock(), verified_chunks=3, verified_bytes=3*CHUNK_BYTES)
                break
            sleep(max(0, min(POLL_NS, start + WAIT_NS-clock())) / 1e9)
        else:
            result["status"] = "trigger-timeout"
            return result
        initial = sampler()
        PSI["validate_observation"](initial)
        result["initial_observation"] = initial
        result["last_observation"] = initial
        if not all(state == "below_threshold" for state in initial.values()):
            result["status"] = "resource-unavailable"
            return result
        require(memory())
        load_started = clock()
        require(load_started < start + WAIT_NS)
        result["load_started_ns"] = load_started
        deadline = result["load_started_ns"] + ACTIVE_NS
        workers.start(deadline)
        while clock() < deadline:
            require(memory())
            if not workers.alive():
                result["status"] = "load-failed"
                break
            observation = sampler()
            PSI["validate_observation"](observation)
            observed_ns = clock()
            if observed_ns >= deadline:
                result["status"] = "observed" if result["cpu_pressure_observed"] else "pressure-missing"
                break
            result["samples"] += 1
            require(result["samples"] <= 46)
            result["last_observation"] = observation
            result["cpu_pressure_observed"] |= observation["cpu"] == "pressured"
            if observation["cpu"] == "pressured" and result["first_pressure_ns"] is None:
                result["first_pressure_ns"] = observed_ns
            result["other_pressure_observed"] |= any(observation[key] == "pressured" for key in ("memory", "io"))
            result["psi_unavailable"] |= "unavailable" in observation.values()
            if result["psi_unavailable"] or result["other_pressure_observed"]:
                result["status"] = "resource-unavailable"
                break
            sleep(max(0, min(POLL_NS, deadline-clock())) / 1e9)
        else:
            result["status"] = "observed" if result["cpu_pressure_observed"] else "pressure-missing"
    except InterruptedError:
        result["status"] = "interrupted"
    except (OSError, ValueError, KeyError, TypeError):
        result["status"] = "invalid"
    finally:
        try:
            workers.stop()
        except (OSError, ValueError):
            result["status"] = "cleanup-failed"
        if result["load_started_ns"] is not None:
            result["load_stopped_ns"] = clock()
            if result["load_stopped_ns"] - result["load_started_ns"] > LOAD_NS:
                result["status"] = "cleanup-failed"
        result["cleanup"] = workers.receipt()
        if result["status"] == "observed" and (
                result["cleanup"]["spawned"] != 2 or result["cleanup"]["ready"] != 2
                or result["cleanup"]["reaped"] != 2
                or any(code not in (0, -signal.SIGTERM) for code in result["cleanup"]["exit_codes"])):
            result["status"] = "load-failed"
        result["completed_ns"] = clock()
        result["success"] = result["status"] == "observed"
    return result


def validate(value):
    keys = {"schema_version", "kind", "success", "scope", "status", "cold_begin", "started_ns",
            "trigger_ns", "verified_chunks", "verified_bytes", "load_started_ns", "load_stopped_ns",
            "completed_ns", "wait_limit_ms", "load_limit_ms", "samples", "cpu_pressure_observed",
            "other_pressure_observed", "psi_unavailable", "initial_observation", "last_observation",
            "first_pressure_ns", "cleanup", "publication"}
    require(type(value) is dict and set(value) == keys and type(value["schema_version"]) is int
            and value["schema_version"] == 1 and value["kind"] == "content-provider-pressure-controller"
            and value["status"] in STATUSES and type(value["success"]) is bool
            and value["success"] == (value["status"] == "observed") and value["scope"] == SCOPE
            and all(type(v) is bool for v in value["scope"].values()) and value["cold_begin"] is True)
    require(value["wait_limit_ms"] == 30000 and type(value["wait_limit_ms"]) is int
            and value["load_limit_ms"] == 10000 and type(value["load_limit_ms"]) is int)
    for key in ("started_ns", "completed_ns", "verified_chunks", "verified_bytes", "samples"):
        require(type(value[key]) is int and 0 <= value[key] <= 2**64-1)
    for key in ("trigger_ns", "load_started_ns", "load_stopped_ns", "first_pressure_ns"):
        require(value[key] is None or type(value[key]) is int and value["started_ns"] <= value[key] <= value["completed_ns"])
    require(value["completed_ns"] >= value["started_ns"] and value["samples"] <= 46)
    for key in ("cpu_pressure_observed", "other_pressure_observed", "psi_unavailable"):
        require(type(value[key]) is bool)
    require(value["verified_chunks"] in (0, 3) and value["verified_bytes"] == value["verified_chunks"] * CHUNK_BYTES)
    require((value["trigger_ns"] is None) == (value["verified_chunks"] == 0))
    if value["trigger_ns"] is not None:
        require(value["trigger_ns"] - value["started_ns"] < WAIT_NS)
    if value["load_started_ns"] is not None:
        require(0 <= value["load_started_ns"] - value["started_ns"] < WAIT_NS)
    if value["last_observation"] is not None:
        PSI["validate_observation"](value["last_observation"])
    if value["initial_observation"] is not None:
        PSI["validate_observation"](value["initial_observation"])
    require((value["first_pressure_ns"] is not None) == value["cpu_pressure_observed"])
    if value["first_pressure_ns"] is not None:
        require(value["load_started_ns"] is not None
                and value["load_started_ns"] <= value["first_pressure_ns"]
                < value["load_started_ns"] + ACTIVE_NS)
        if value["load_stopped_ns"] is not None:
            require(value["first_pressure_ns"] <= value["load_stopped_ns"])
    p = value["publication"]
    require(type(p) is dict and set(p) == {"manifest_id", "publisher_hex", "object_sha256"}
            and p["object_sha256"] == OBJECT_SHA
            and all(type(p[key]) is str and re.fullmatch(r"[0-9a-f]{64}", p[key]) for key in p))
    c = value["cleanup"]
    require(type(c) is dict and set(c) == {"spawned", "ready", "reaped", "forced_kills", "exit_codes"}
            and all(type(c[key]) is int and 0 <= c[key] <= 2 for key in c if key != "exit_codes")
            and 0 <= c["ready"] <= c["spawned"] and c["reaped"] <= c["spawned"]
            and type(c["exit_codes"]) is list and len(c["exit_codes"]) == c["spawned"]
            and all(code is None or type(code) is int and -64 <= code <= 255 for code in c["exit_codes"])
            and sum(code is not None for code in c["exit_codes"]) == c["reaped"])
    if value["success"]:
        require(value["trigger_ns"] is not None and value["load_started_ns"] is not None
                and value["load_stopped_ns"] is not None and value["load_started_ns"] >= value["trigger_ns"]
                and 0 < value["load_stopped_ns"] - value["load_started_ns"] <= LOAD_NS
                and value["cpu_pressure_observed"] and not value["other_pressure_observed"]
                and not value["psi_unavailable"] and value["samples"] > 0
                and value["initial_observation"] == dict.fromkeys(PSI["THRESHOLDS"], "below_threshold")
                and c["spawned"] == c["ready"] == c["reaped"] == 2
                and all(code in (0, -signal.SIGTERM) for code in c["exit_codes"]))
    return value


def observe(work):
    worker, agent_uid = guest(work)
    root = directory(work, 0)
    watcher = None
    try:
        require(absent(root, PREFIX + "-ready.json") and absent(root, PREFIX + "-controller.json"))
        seed = publication(root, 0)
        watcher = CacheObserver(root, agent_uid)
        require(memory_available())
        ready_ns = time.monotonic_ns()
        write_record(root, PREFIX + "-ready.json", dict(schema_version=1, kind="content-provider-pressure-ready",
                     cold_cache=True, ready_ns=ready_ns, publication=seed))
        print("Disposable guest only: two capless worker-UID CPU processes on one guest CPU, "
              "after three verified public chunks; at most ten seconds including drain.", flush=True)
        previous = {}
        def interrupted(_signum, _frame):
            # Further TERM cannot interrupt child drain after the first cancellation.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            raise InterruptedError()
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, interrupted)
            result = coordinate(watcher, Workers(worker))
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        result["publication"] = seed
        validate(result)
        write_record(root, PREFIX + "-controller.json", result)
        return result["success"]
    finally:
        if watcher is not None:
            watcher.close()
        os.close(root)


def main(argv):
    try:
        require(len(argv) == 3 and argv[1] == "observe")
        return 0 if observe(Path(argv[2])) else 1
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        print("CONTENT_PROVIDER_PRESSURE_INVALID", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
