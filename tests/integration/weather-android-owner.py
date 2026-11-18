#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Own one hosted Android/core trial; never request or synthesize a product.

The enclosing VM shell owns QEMU and archive retrieval. This owner launches the
fixed guest-driver SSH process itself, then the fixed API-only tunnel and the
already prepared Weather runtime. `join` runs after the shell retrieves the
closed guest artifact. VM destruction remains a separate acceptance gate.
"""
import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1]
E = runpy.run_path(str(HERE / "weather-android-evidence.py"))
T = runpy.run_path(str(HERE / "weather-android-tunnel.py"))
N = runpy.run_path(str(HERE / "weather-android-native.py"))
K = N["K"]
D = runpy.run_path(str(HERE / "weather-android-inner-diagnostic.py"))
require, same, exact, digest = E["require"], E["same"], E["exact"], E["digest"]
CONTROL = "/usr/local/libexec/volparossa-weather-android-control.py"
PROFILE = "android-protected-core-v6"
FIELDS = {"schema", "core_commit", "weather_commit", "weather_root", "run_directory", "output_directory",
    "source_sha256", "mpquic_sha256", "package_sha256", "weather_archive_sha256", "weather_manifest_sha256"}
SHA40 = re.compile(r"[a-f0-9]{40}")
# This enclosing native budget is intentionally tighter than the pinned
# Weather wrapper's internal limit. It leaves cleanup/finalization time within
# the unchanged tunnel and original publication budgets; a slower run fails,
# rather than extending an authorization or substituting a prepared UI report.
DRIVER_SECONDS, NATIVE_SECONDS, TUNNEL_SECONDS = 2400, 420, 480
TERM_SECONDS, KILL_SECONDS = 30, 5
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
ENV_KEYS = ("GITHUB_ACTIONS", "RUNNER_OS", "RUNNER_ENVIRONMENT", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW",
    "GITHUB_WORKSPACE", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "VOLPAROSSA_WEATHER_SOURCE_SHA")
FAILURE_NAME = "weather-android-owner-failure.json"
NATIVE_PHASES = frozenset(("baseline", "policy-install", "installed-emulator-trial", "complete"))
NATIVE_RECORDS = {
    "result": "build/hosted-android-live-ci/result.json",
    "failure": "build/hosted-android-live-ci/failure.json",
    "emulator_cleanup": "build/overmorrow-hosted-android-live-proof/emulator-cleanup.json",
}
STOP_REASONS = frozenset(("deadline", "driver-exited", "tunnel-exited", "native-exited", "output-limit",
    "interrupted", "io-error", "guard-rejected", "subprocess-error"))
STOP_STAGES = frozenset(("driver", "read-ready", "tunnel", "native-start", "native-wait", "native-result",
    "tunnel-join", "finalize", "driver-join", "complete"))
STOP_BUDGETS = frozenset(("wait", "wall", "owner", "owner-reserve", "read-ready", "socket-ready", "native",
    "tunnel", "tunnel-join", "finalize", "publication-reserve-monotonic", "publication-reserve-wall",
    "publication-join-monotonic", "publication-join-wall", "publication-monotonic", "publication-wall",
    "publication-grace-monotonic", "publication-grace-wall"))


class Failure(ValueError): pass


class Deadline(Failure):
    def __init__(self, budgets):
        super().__init__("deadline")
        self.budgets = tuple(budgets)


def check_deadlines(monotonic, wall=()):
    """Record the actual expired limits at the original decision, not at cleanup."""
    now, utc = time.monotonic(), time.time()
    expired = [name for name, deadline in monotonic if now >= deadline]
    expired.extend(name for name, deadline in wall if utc >= deadline)
    if expired: raise Deadline(expired)


def validate_owner_stop(value):
    if value is None: return None  # No retained pre-cleanup observation; not evidence of a clean run.
    exact(value, ("reason", "stage", "budgets", "children", "output_overflow"))
    require(type(value["reason"]) is str and value["reason"] in STOP_REASONS
        and type(value["stage"]) is str and value["stage"] in STOP_STAGES)
    budgets = value["budgets"]
    require(type(budgets) is list and len(budgets) <= 4
        and all(type(name) is str and name in STOP_BUDGETS for name in budgets)
        and len(set(budgets)) == len(budgets) and bool(budgets) == (value["reason"] == "deadline"))
    exact(value["children"], ("driver", "tunnel", "native"))
    for child in value["children"].values():
        exact(child, ("state", "status", "stdout_open", "stderr_open"))
        require(type(child["state"]) is str and child["state"] in ("not-started", "running", "exited"))
        if child["state"] == "exited": E["integer"](child["status"], -255, 255)
        else: same(child["status"], None)
        require(type(child["stdout_open"]) is bool and type(child["stderr_open"]) is bool)
        if child["state"] == "not-started": require(not child["stdout_open"] and not child["stderr_open"])
    require(type(value["output_overflow"]) is bool)
    return value


def owner_stop(error, stage, pool):
    """Freeze only observations already made by the owner, before it sends TERM.

    Do not poll here: a child may exit between the failed check and cleanup.
    Cached return codes and pipe states describe that observed boundary, not a
    claim that every process was alive at precisely the same instant.
    """
    reason, budgets = "guard-rejected", []
    if isinstance(error, Deadline): reason, budgets = "deadline", list(error.budgets)
    elif isinstance(error, Failure) and error.args and type(error.args[0]) is str \
            and error.args[0] in STOP_REASONS - {"deadline"}:
        reason = error.args[0]
    elif isinstance(error, OSError): reason = "io-error"
    elif isinstance(error, subprocess.SubprocessError): reason = "subprocess-error"
    jobs = {job["name"]: job for job in pool.jobs if job["name"] in ("driver", "tunnel", "native")}
    children = {}
    for name in ("driver", "tunnel", "native"):
        job = jobs.get(name); process = job["process"] if job is not None else None
        status = process.returncode if process is not None else None
        children[name] = dict(state="not-started" if process is None else "running" if status is None else "exited",
            status=status, stdout_open=job is not None and "stdout" in job["open"],
            stderr_open=job is not None and "stderr" in job["open"])
    return validate_owner_stop(dict(reason=reason, stage=stage, budgets=budgets, children=children,
        output_overflow=pool.overflow))


def canonical(path, *, directory=False, mode=None):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path and not re.search(r"[\x00-\x1f\x7f]", str(path)))
    info = path.lstat()
    require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode) and info.st_uid == os.getuid()
        and not info.st_mode & 0o022 and (mode is None or stat.S_IMODE(info.st_mode) == mode))
    if not directory: require(info.st_nlink == 1)
    return path


def read(path, limit=65536, mode=0o600):
    return E["private_bytes"](Path(path), limit, os.getuid(), mode)


def document(path, limit=65536, mode=0o600):
    return E["decode"](read(path, limit, mode), limit)


def write(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(len(raw) <= 65536)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush()
    return digest(raw)


def environment():
    return dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8", PYTHONDONTWRITEBYTECODE="1",
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
        **{key: os.environ[key] for key in ENV_KEYS})


def identity(core_commit, weather_commit):
    return dict(core_commit=core_commit, weather_commit=weather_commit,
        run_id=os.environ["GITHUB_RUN_ID"], run_attempt=os.environ["GITHUB_RUN_ATTEMPT"])


def hosted(core_commit, weather_commit):
    require(os.getuid() == os.geteuid() != 0 and SHA40.fullmatch(core_commit) and SHA40.fullmatch(weather_commit))
    expected = dict(GITHUB_ACTIONS="true", RUNNER_OS="Linux", RUNNER_ENVIRONMENT="github-hosted",
        GITHUB_REPOSITORY="VOLPAROSSA/volparossa", GITHUB_WORKFLOW="Weather Android protected core delivery",
        GITHUB_WORKSPACE=str(CORE), GITHUB_SHA=core_commit, VOLPAROSSA_WEATHER_SOURCE_SHA=weather_commit)
    require(all(os.environ.get(k) == v for k, v in expected.items()))
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get(k, "")) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")))
    # The pinned runtime must install/remove its scoped policy via sudo. Do not
    # inherit the unrelated no-new-privileges wrapper of older VM-only trials.
    require("NoNewPrivs:\t0" in Path("/proc/self/status").read_text().splitlines())


def git_check(root, commit):
    canonical(root, directory=True)
    base = ["/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-C", str(root)]
    result = subprocess.run(base + ["rev-parse", "HEAD"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment(), timeout=10, check=True)
    require(result.stdout == (commit + "\n").encode())
    subprocess.run(base + ["-c", "diff.autoRefreshIndex=false", "diff", "--quiet", "HEAD", "--"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=environment(), timeout=15, check=True)


def prepared(weather, core_commit, weather_commit):
    """Authenticate the existing preparation without running SDK/native code."""
    hosted(core_commit, weather_commit)
    weather = canonical(weather, directory=True)
    require(weather != CORE and weather.is_relative_to(CORE))
    pin = json.loads((HERE / "weather-public-android-v6.json").read_bytes())
    same(weather_commit, pin["sources"]["weather"]["commit"])
    git_check(CORE, core_commit); git_check(weather, weather_commit)
    runtime = runpy.run_path(str(weather / "scripts/prepare_hosted_android_ci.py"))
    helper = runtime["H"].policy_helper()
    value = runtime["prepared_core_inputs"](helper)
    result = dict(schema=6, kind="weather-android-owner-preflight", identity=identity(core_commit, weather_commit),
        prepared_sha256=digest(read(weather / "build/hosted-android-ci/prepared.json", 2 * 1024**2)),
        result_sha256=digest(read(weather / "build/hosted-android-ci/result.json")), apk=value["apk"],
        original_preparation_verified=True, runtime_executed=False, publication_started=False)
    return result


def preflight(weather, core_commit, weather_commit, output, kvm_baseline=None):
    result = prepared(weather, core_commit, weather_commit)
    output = canonical(output, directory=True)
    require(output.is_relative_to(CORE) and output != CORE)
    before = K["snapshot"]()
    if not K["usable"](before):
        write(output / K["NAME"], K["receipt"](identity(core_commit, weather_commit), "preflight", before))
        raise Failure("kvm-unavailable")
    if kvm_baseline is not None:
        selected = Path(kvm_baseline)
        parent = canonical(selected.parent, directory=True, mode=0o700)
        require(parent.is_relative_to(CORE) and parent.parent == output.parent and parent != output
            and re.fullmatch(r"weather-client-kvm\.[A-Za-z0-9]{6}", parent.name)
            and selected == parent / "kvm-before-vm.json")
        acl = K["group_acl"]()
        if not K["group_usable"](acl):
            write(output / K["NAME"], K["continuity_receipt"](identity(core_commit, weather_commit), before,
                acl, "absent", phase="preflight"))
            raise Failure("kvm-group-unavailable")
        write(selected, K["continuity_baseline_record"](identity(core_commit, weather_commit), before, acl))
    return result


def kvm_continuity(run, selected_identity):
    path = Path(run) / "kvm-before-vm.json"
    if not os.path.lexists(path): return "absent", None
    try:
        return "available", K["continuity_baseline"](document(path, 16384), selected_identity)
    except (OSError, ValueError, KeyError, TypeError): return "rejected", None


def config(path):
    value = document(path, 8192); exact(value, FIELDS); same(value["schema"], 6)
    hosted(value["core_commit"], value["weather_commit"])
    for key in ("source_sha256", "mpquic_sha256", "weather_archive_sha256", "weather_manifest_sha256"):
        E["hashes"](value, (key,))
    same(value["package_sha256"], "none")
    weather = canonical(value["weather_root"], directory=True)
    run = canonical(value["run_directory"], directory=True, mode=0o700)
    output = canonical(value["output_directory"], directory=True)
    require(weather.is_relative_to(CORE) and weather != CORE and run.parent == output.parent
        and run.is_relative_to(CORE) and output.is_relative_to(CORE) and output != run
        and re.fullmatch(r"weather-client-kvm\.[A-Za-z0-9]{6}", run.name)
        and Path(path) == run / "android-owner-input.json")
    for name in ("guest-key", "known-hosts"): canonical(run / name, mode=0o600)
    socket = run / "android-api/core-api.sock"
    require(len(os.fsencode(socket)) < 104)
    return value


def ssh(value, suffix):
    run = Path(value["run_directory"])
    base = T["ssh_command"](run / "guest-key", run / "known-hosts")
    return base[:-6] + suffix


def command(value, name, action=None):
    run, weather = Path(value["run_directory"]), Path(value["weather_root"])
    if name == "driver":
        return ssh(value, ["/home/vpci/guest-driver.sh", value["core_commit"], value["source_sha256"],
            value["mpquic_sha256"], "none", "content-provider", "weather-client",
            value["weather_archive_sha256"], value["weather_manifest_sha256"]])
    if name == "controller":
        require(action in ("read-ready", "finalize"))
        return ssh(value, ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", CONTROL, action])
    if name == "tunnel":
        return ["/usr/bin/python3", "-B", str(HERE / "weather-android-tunnel.py"), "host", "--socket",
            str(run / "android-api/core-api.sock"), "--ssh-key", str(run / "guest-key"), "--known-hosts", str(run / "known-hosts")]
    same(name, "native")
    return ["/usr/bin/python3", "-B", str(HERE / "weather-android-native.py"),
        "--weather-root", str(weather), "--core-commit", value["core_commit"],
        "--weather-commit", value["weather_commit"], "--upstream-socket", str(run / "android-api/core-api.sock")]


@contextmanager
def cancellation_blocked():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try: yield previous
    finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class Children:
    """Own only newly spawned sessions; drain pipes and adopted descendants."""
    def __init__(self):
        self.jobs = []; self.selector = selectors.DefaultSelector(); self.overflow = False
        self.children = Path(f"/proc/self/task/{os.getpid()}/children")
        require(not self.children.read_text().strip() and len(list(Path("/proc/self/task").iterdir())) == 1)
        require(not set(signal.pthread_sigmask(signal.SIG_BLOCK, [])) & set(SIGNALS))
        self.libc = ctypes.CDLL(None, use_errno=True); self.old_reaper = ctypes.c_int()
        require(self.libc.prctl(37, ctypes.byref(self.old_reaper), 0, 0, 0) == 0
            and self.libc.prctl(36, 1, 0, 0, 0) == 0)

    def start(self, argv, name, env, cwd, limit=65536):
        job = dict(name=name, process=None, data={"stdout": bytearray(), "stderr": bytearray()}, open=set(), limit=limit)
        self.jobs.append(job)
        with cancellation_blocked() as mask:
            job["process"] = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, cwd=cwd, close_fds=True, start_new_session=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
            for name in job["data"]:
                stream = getattr(job["process"], name); os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, (job, name)); job["open"].add(name)
        return job

    def pump(self, timeout=0.05, *, cleanup=False):
        for entry, _ in self.selector.select(max(0, min(timeout, 0.1))):
            job, name = entry.data
            raw = os.read(entry.fileobj.fileno(), min(65536, max(1, job["limit"] + 1 - len(job["data"][name]))))
            if raw:
                job["data"][name].extend(raw)
                if len(job["data"][name]) <= job["limit"]: continue
                self.overflow = True
            self.selector.unregister(entry.fileobj); job["open"].remove(name); entry.fileobj.close()
            if raw and not cleanup: raise Failure("output-limit")
        for job in self.jobs:
            if job["process"] is not None: job["process"].poll()

    @staticmethod
    def done(job):
        return job["process"] is not None and job["process"].returncode is not None and not job["open"]

    @staticmethod
    def signal(job, sig):
        process = job["process"]
        if process is not None and process.returncode is None:
            try: os.killpg(process.pid, sig)
            except ProcessLookupError: pass

    def wait(self, job, deadline, driver=None, wall_deadline=None, *, deadline_scopes=None, wall_scope="wall"):
        scopes = (("wait", deadline),) if deadline_scopes is None else deadline_scopes
        same(min(limit for _, limit in scopes), deadline)
        while not self.done(job):
            check_deadlines(scopes, () if wall_deadline is None else ((wall_scope, wall_deadline),))
            self.pump()
            if driver is not None and driver["process"].returncode is not None: raise Failure("driver-exited")
        return job["process"].returncode

    def close(self):
        checked, forced, drained = True, False, False
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in SIGNALS}
        try:
            for sig, seconds in ((signal.SIGTERM, TERM_SECONDS), (signal.SIGKILL, KILL_SECONDS)):
                for job in self.jobs:
                    if job["process"] is not None and job["process"].returncode is None:
                        if sig == signal.SIGKILL: forced = True
                        try: self.signal(job, sig)
                        except OSError: checked = False
                until = time.monotonic() + seconds
                while time.monotonic() < until:
                    try:
                        self.pump(cleanup=True)
                        leaders = {job["process"].pid for job in self.jobs if job["process"] is not None}
                        for raw in self.children.read_text().split()[:128]:
                            pid = int(raw)
                            if pid not in leaders and os.waitpid(pid, os.WNOHANG)[0] == 0:
                                if sig == signal.SIGKILL: forced = True
                                try: os.kill(pid, sig)
                                except ProcessLookupError: pass
                        if not self.children.read_text().strip() and not self.selector.get_map():
                            drained = True; break
                    except (OSError, ValueError): checked = False
                if drained: break
            if drained and self.libc.prctl(36, self.old_reaper.value, 0, 0, 0) != 0: checked = False
        finally:
            for job in self.jobs:
                if job["process"] is not None:
                    for name in job["data"]:
                        try: getattr(job["process"], name).close()
                        except OSError: checked = False
            self.selector.close()
            for sig, handler in previous.items(): signal.signal(sig, handler)
        return dict(children_joined=drained, forced_kill=forced, output_drained=checked and not self.overflow)


def ready_record(value, selected, *, historical=False):
    exact(value, ("schema", "kind", "manifest_sha256", "core_sha256", "prepared_sha256", "deadline_unix_seconds",
        "remaining_seconds", "api_socket_ready", "cold_caches_absent", "helper_requests", "joined_delivery_proven"))
    same(value["schema"], 6); same(value["kind"], "weather-android-guest-ready")
    E["hashes"](value, ("manifest_sha256", "core_sha256", "prepared_sha256"))
    same(value["manifest_sha256"], selected["weather_manifest_sha256"])
    same(value["api_socket_ready"], True); same(value["cold_caches_absent"], True)
    same(value["helper_requests"], 0); same(value["joined_delivery_proven"], False)
    E["integer"](value["remaining_seconds"], 600, 840); E["integer"](value["deadline_unix_seconds"], 1)
    if not historical:
        require(599 <= value["deadline_unix_seconds"] - time.time() <= 840
            and abs(value["deadline_unix_seconds"] - int(time.time()) - value["remaining_seconds"]) <= 2)


def tunnel_record(value):
    exact(value, ("schema", "kind", "completed", "requests", "original_response_bytes", "joined_core_acceptance",
        "cleanup_confirmed", "responses"))
    same(value["schema"], 6); same(value["kind"], "weather-android-api-tunnel"); same(value["completed"], 6)
    same(value["requests"], dict.fromkeys(T["ROUTES"], 3)); same(value["original_response_bytes"], True)
    same(value["joined_core_acceptance"], False); same(value["cleanup_confirmed"], True)
    require(type(value["responses"]) is list and len(value["responses"]) == 6)
    seen = set()
    for response in value["responses"]:
        E["validate_response"](response); seen.add((response["product"], response["ordinal"]))
    same(seen == {(key, ordinal) for key in E["PRODUCTS"] for ordinal in (1, 2, 3)}, True)


def native_result(value):
    same(value, dict(schema=1, kind="hosted-android-protected-core-installed-trial", phase="complete", success=True,
        process_drain_confirmed=True, policy_cleanup_complete=True, host_netns_unchanged=True, synthetic=False,
        expiry_proven=False, core_delivery=False, joined_core_acceptance=False, mobile_core=False, production_authority=False))


def native_diagnostic(job):
    """Export only the wrapper's closed final line, never the private streams."""
    absent = dict(state="absent", record=None)
    if job is None: return absent
    try:
        require(job["process"] is not None and job["process"].returncode is not None and not job["open"])
        require(all(len(raw) <= job["limit"] for raw in job["data"].values()))
        raw = bytes(job["data"]["stdout"]); prefix = N["PREFIX"].encode("ascii")
        if prefix not in raw: return absent
        require(raw.endswith(b"\n"))
        line = raw[:-1].rsplit(b"\n", 1)[-1]
        require(line.startswith(prefix) and len(line) <= 4096 and raw.count(prefix) == 1)
        value = E["decode"](line[len(prefix):], 4096)
        N["validate_diagnostic"](value)
        return dict(state="available", record=value)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return dict(state="rejected", record=None)


def tunnel_diagnostic(job):
    """Optional original tunnel facts, never a replacement for owner_stop.

    Only a failed, joined and fully drained child can supply the closed final
    marker. Missing or rejected diagnostics carry no facts or acceptance.
    """
    if job is None: return None
    try:
        require(job["process"] is not None and not job["open"])
        status = job["process"].returncode
        E["integer"](status, -255, 255); require(status != 0)
        require(all(len(raw) <= job["limit"] for raw in job["data"].values()))
        raw = bytes(job["data"]["stdout"]); prefix = T["PREFIX"].encode("ascii")
        require(raw.endswith(b"\n") and raw.count(prefix) == 1)
        line = raw[:-1].rsplit(b"\n", 1)[-1]
        require(line.startswith(prefix) and len(line) + 1 <= T["MAX_DIAGNOSTIC_BYTES"])
        value = E["decode"](line[len(prefix):], T["MAX_DIAGNOSTIC_BYTES"])
        return T["validate_diagnostic"](value)
    except (AttributeError, OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def native_kvm(job, expected_identity):
    """A separate receipt, not an extension of either schema6 failure record."""
    absent = dict(state="absent", record=None)
    if job is None: return absent
    try:
        require(job["process"] is not None and job["process"].returncode is not None and not job["open"])
        require(all(len(raw) <= job["limit"] for raw in job["data"].values()))
        raw = bytes(job["data"]["stdout"]); prefix = K["PREFIX"].encode("ascii")
        if prefix not in raw: return absent
        require(raw.endswith(b"\n") and raw.count(prefix) == 1)
        lines = raw[:-1].rsplit(b"\n", 2)
        diagnostic = native_diagnostic(job)
        if job["process"].returncode != 0:
            require(diagnostic["state"] == "available" and len(lines) >= 2)
            line = lines[-2]
        else: line = lines[-1]
        require(line.startswith(prefix) and len(line) <= 8192)
        value = K["validate_native"](E["decode"](line[len(prefix):], 8192))
        same(value["identity"], expected_identity)
        if value["at_kvm_guard_failure"] is not None:
            require(diagnostic["state"] == "available" and diagnostic["record"]["category"] == "value"
                and diagnostic["record"]["code"] == "KVM_REQUIRED_NO_TCG")
        return dict(state="available", record=value)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return dict(state="rejected", record=None)


def native_facts(name, value):
    """Closed original Weather schemas; these facts grant no acceptance."""
    if name == "result":
        keys = ("schema", "kind", "phase", "success", "process_drain_confirmed", "policy_cleanup_complete",
            "host_netns_unchanged", "synthetic", "expiry_proven", "core_delivery", "joined_core_acceptance",
            "mobile_core", "production_authority")
        exact(value, keys); same(value["schema"], 1)
        same(value["kind"], "hosted-android-protected-core-installed-trial")
        require(type(value["phase"]) is str and value["phase"] in NATIVE_PHASES)
        for key in ("success", "process_drain_confirmed", "policy_cleanup_complete", "host_netns_unchanged"):
            require(type(value[key]) is bool)
        for key in ("synthetic", "expiry_proven", "core_delivery", "joined_core_acceptance", "mobile_core", "production_authority"):
            same(value[key], False)
        if value["success"]: native_result(value)
        return value
    if name == "failure":
        exact(value, ("schema", "phase", "category", "code")); same(value["schema"], 1)
        require(type(value["phase"]) is str and value["phase"] in NATIVE_PHASES)
        require(type(value["category"]) is str and len(value["category"]) <= 128)
        require(type(value["code"]) is str and len(value["code"]) <= 4096)
        categories = {"Interrupted": "interrupted", "KeyboardInterrupt": "interrupted", "ValueError": "value",
            "KeyError": "key", "TypeError": "type", "TimeoutExpired": "timeout", "CalledProcessError": "process",
            "OSError": "os", "FileNotFoundError": "os", "PermissionError": "os", "SystemExit": "system_exit"}
        # Weather's historical receipt can contain exception text. Project it
        # to the same finite code set, never publish that text or its paths.
        return dict(phase=value["phase"], category=categories.get(value["category"], "unknown"),
            code=value["code"] if value["code"] in N["CODES"] else "UNKNOWN")
    same(name, "emulator_cleanup")
    exact(value, ("schema", "direct_children_reaped", "private_avd_removed", "private_android_home_removed",
        "trial_returned", "enclosing_namespace_cleanup_required"))
    same(value["schema"], 1); same(value["enclosing_namespace_cleanup_required"], True)
    for key in ("direct_children_reaped", "private_avd_removed", "private_android_home_removed", "trial_returned"):
        require(type(value[key]) is bool)
    return value


def native_originals(weather, preexisting):
    records = {}
    for name, relative in NATIVE_RECORDS.items():
        path = weather / relative
        if preexisting[name]: records[name] = dict(state="rejected", facts=None); continue
        try:
            path.lstat()
        except FileNotFoundError:
            records[name] = dict(state="absent", facts=None); continue
        except OSError:
            records[name] = dict(state="rejected", facts=None); continue
        try:
            records[name] = dict(state="available", facts=native_facts(name, document(path, 16384)))
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            records[name] = dict(state="rejected", facts=None)
    return records


def export_failure(value, result, pool, preexisting, stop):
    # Called only after the owner has attempted to join every owned child.
    # Outer cleanup and Weather's original cleanup are distinct observations.
    same(result["success"], False)
    jobs = {job["name"]: job for job in pool.jobs if job["name"] in result["statuses"]}
    statuses = {name: job["process"].returncode if (job := jobs.get(name)) is not None
        and job["process"] is not None else None for name in result["statuses"]}
    failure = dict(schema=8, kind="weather-android-owner-failure", identity=result["identity"],
        phase=result["phase"], statuses=statuses, owner_cleanup=result["cleanup"],
        owner_stop=validate_owner_stop(stop),
        tunnel_diagnostic=tunnel_diagnostic(jobs.get("tunnel"))
            if result["cleanup"]["children_joined"] and result["cleanup"]["output_drained"] else None,
        native_diagnostic=native_diagnostic(jobs.get("native")),
        weather_records=native_originals(Path(value["weather_root"]), preexisting),
        diagnostic_only=True, success=False, joined_core_acceptance=False, vm_cleanup_pending=True,
        expiry_proven=False, physical_device=False, production_authority=False)
    write(canonical(value["output_directory"], directory=True) / FAILURE_NAME, failure)


def export_inner_diagnostic(value, expected_identity, preexisting, cleanup):
    """Optional finite facts after child cleanup, never raw child output."""
    records = {}
    for name, relative in D["INPUTS"].items():
        path = Path(value["weather_root"]) / relative
        # A driver receipt may have preceded APK force-stop and an interrupted
        # inner launcher. Read its host-bound inode only after all owned child
        # groups and output pipes are closed, never from a still-writing child.
        if preexisting[name] or name == "driver" and not (
                cleanup.get("children_joined") is True and cleanup.get("output_drained") is True):
            records[name] = dict(state="rejected", facts=None)
            continue
        try:
            path.lstat()
        except FileNotFoundError:
            records[name] = dict(state="absent", facts=None)
            continue
        except OSError:
            records[name] = dict(state="rejected", facts=None)
            continue
        try:
            facts = D["project_record"](name, document(path, D["INPUT_LIMITS"][name]))
            records[name] = dict(state="available", facts=facts)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            records[name] = dict(state="rejected", facts=None)
    result = D["receipt"](expected_identity, records)
    require(len(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()) + 1
        <= D["MAX_BYTES"])
    write(canonical(value["output_directory"], directory=True) / D["NAME"], result)


def preparation_record(value, expected_identity):
    exact(value, ("schema", "kind", "identity", "prepared_sha256", "result_sha256", "apk",
        "original_preparation_verified", "runtime_executed", "publication_started"))
    same(value["schema"], 6); same(value["kind"], "weather-android-owner-preflight")
    same(value["identity"], expected_identity)
    E["hashes"](value, ("prepared_sha256", "result_sha256"))
    exact(value["apk"], ("bytes", "sha256")); E["hashes"](value["apk"], ("sha256",))
    E["integer"](value["apk"]["bytes"], 1, 192 * 1024**2)
    same(value["original_preparation_verified"], True)
    same(value["runtime_executed"], False); same(value["publication_started"], False)


def run(value):
    preparation = prepared(Path(value["weather_root"]), value["core_commit"], value["weather_commit"])
    preparation_record(preparation, identity(value["core_commit"], value["weather_commit"]))
    run_dir, weather = Path(value["run_directory"]), Path(value["weather_root"])
    private, socket_parent = run_dir / "android-owner", run_dir / "android-api"
    private.mkdir(mode=0o700); socket_parent.mkdir(mode=0o700)
    canonical(private, directory=True, mode=0o700); canonical(socket_parent, directory=True, mode=0o700)
    write(private / "preparation.json", preparation)
    kvm_before = K["snapshot"]()
    acl_before = K["group_acl"]()
    baseline_state, initial = kvm_continuity(run_dir, identity(value["core_commit"], value["weather_commit"]))
    write(private / "kvm-baseline.json", K["baseline_record"](
        identity(value["core_commit"], value["weather_commit"]), kvm_before))
    preexisting = {name: os.path.lexists(weather / relative) for name, relative in NATIVE_RECORDS.items()}
    inner_preexisting = {name: os.path.lexists(weather / relative) for name, relative in D["INPUTS"].items()}
    pool = Children(); env = environment(); phase, success, ready = "driver", False, None
    netns = os.readlink("/proc/self/ns/net"); outer = time.monotonic() + DRIVER_SECONDS
    statuses = dict(driver=None, tunnel=None, native=None)
    stage, stop = "driver", None
    try:
        require(K["usable"](kvm_before) and K["group_usable"](acl_before) and baseline_state == "available")
        require(all(K["project"](kvm_before, initial["snapshot"])[key] is True for key in K["COMPARISONS"]))
        driver = pool.start(command(value, "driver"), "driver", env, CORE, 4 * 1024**2)
        phase = stage = "read-ready"
        while ready is None:
            require(len(pool.jobs) < 1202)
            check_deadlines((("owner", outer),))
            probe = pool.start(command(value, "controller", "read-ready"), "controller", env, CORE, 16384)
            ready_deadlines = (("owner", outer), ("read-ready", time.monotonic() + 12))
            status = pool.wait(probe, min(limit for _, limit in ready_deadlines), driver, deadline_scopes=ready_deadlines)
            if status == 0:
                ready = E["decode"](bytes(probe["data"]["stdout"]), 16384); ready_record(ready, value)
                break
            # Failed readiness probes carry no evidence; retain no remote text.
            for raw in probe["data"].values(): raw.clear()
            check_deadlines((("owner", outer),))
            until = min(outer, time.monotonic() + 2)
            while time.monotonic() < until:
                pool.pump()
                if driver["process"].returncode is not None: raise Failure("driver-exited")
        write(private / "ready.json", ready)
        absolute = ready["deadline_unix_seconds"]
        publication_deadline = time.monotonic() + absolute - time.time()
        phase = stage = "tunnel"
        tunnel_started = time.monotonic()
        tunnel = pool.start(command(value, "tunnel"), "tunnel", env, CORE)
        socket = socket_parent / "core-api.sock"
        socket_deadlines = (("owner", outer), ("publication-reserve-monotonic", publication_deadline - 90),
            ("socket-ready", time.monotonic() + 5))
        while not socket.exists():
            check_deadlines(socket_deadlines)
            pool.pump()
            if driver["process"].returncode is not None: raise Failure("driver-exited")
            if tunnel["process"].returncode is not None: raise Failure("tunnel-exited")
        info = T["owned"](socket, stat.S_ISSOCK, 0o600); socket_identity = info.st_dev, info.st_ino
        require(list(socket_parent.iterdir()) == [socket])
        phase = "native"
        stage = "native-start"
        native = pool.start(command(value, "native"), "native", env, weather, 2 * 1024**2)
        stage = "native-wait"
        native_deadlines = (("owner-reserve", outer - 60), ("publication-reserve-monotonic", publication_deadline - 90),
            ("native", tunnel_started + NATIVE_SECONDS))
        while not pool.done(native):
            check_deadlines(native_deadlines, (("publication-reserve-wall", absolute - 90),))
            pool.pump()
            if driver["process"].returncode is not None: raise Failure("driver-exited")
            if tunnel["process"].returncode is not None: raise Failure("tunnel-exited")
        stage = "native-result"
        statuses["native"] = native["process"].returncode
        if statuses["native"] != 0: raise Failure("native-exited")
        native_result(document(weather / "build/hosted-android-live-ci/result.json"))
        require(T["same_socket"](socket, socket_identity))
        phase = stage = "tunnel-join"
        pool.signal(tunnel, signal.SIGTERM)
        tunnel_deadlines = (("publication-join-monotonic", publication_deadline - 60),
            ("tunnel", tunnel_started + TUNNEL_SECONDS), ("tunnel-join", time.monotonic() + 10))
        statuses["tunnel"] = pool.wait(tunnel, min(limit for _, limit in tunnel_deadlines), driver, absolute - 60,
            deadline_scopes=tunnel_deadlines, wall_scope="publication-join-wall")
        same(statuses["tunnel"], 0)
        tunnel_value = E["decode"](bytes(tunnel["data"]["stdout"]), 65536); tunnel_record(tunnel_value)
        require(not socket.exists() and not list(socket_parent.iterdir()))
        write(private / "tunnel.json", tunnel_value)
        phase = stage = "finalize"
        check_deadlines((("publication-monotonic", publication_deadline),), (("publication-wall", absolute),))
        request = pool.start(command(value, "controller", "finalize"), "controller", env, CORE, 16384)
        finalize_deadlines = (("publication-monotonic", publication_deadline), ("finalize", time.monotonic() + 12))
        same(pool.wait(request, min(limit for _, limit in finalize_deadlines), wall_deadline=absolute,
            deadline_scopes=finalize_deadlines, wall_scope="publication-wall"), 0)
        finalized = E["decode"](bytes(request["data"]["stdout"]), 16384)
        same(finalized, dict(schema=6, kind="weather-android-finalize-requested", prepared_sha256=ready["prepared_sha256"],
            finalize_requested=True, joined_delivery_proven=False))
        write(private / "finalize.json", finalized)
        phase = stage = "driver-join"
        driver_deadlines = (("owner", outer), ("publication-grace-monotonic", publication_deadline + 60))
        statuses["driver"] = pool.wait(driver, min(limit for _, limit in driver_deadlines), wall_deadline=absolute + 60,
            deadline_scopes=driver_deadlines, wall_scope="publication-grace-wall")
        same(statuses["driver"], 0)
        phase, stage, success = "complete", "complete", True
    except (Failure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        success = False
        try: stop = owner_stop(error, stage, pool)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            # Losing optional diagnostics must neither mask the original
            # failure nor prevent cleanup and the original failed result.
            stop = None
    finally:
        cleanup = pool.close()
    socket_absent = not (socket_parent / "core-api.sock").exists() and not list(socket_parent.iterdir())
    unchanged = os.readlink("/proc/self/ns/net") == netns
    success = success and all((cleanup["children_joined"], cleanup["output_drained"], not cleanup["forced_kill"], socket_absent, unchanged))
    result = dict(schema=6, kind="weather-android-owner-run", identity=identity(value["core_commit"], value["weather_commit"]),
        success=success, phase=phase, statuses=statuses, cleanup=dict(**cleanup, socket_removed=socket_absent,
        host_netns_unchanged=unchanged), helper_requests=0, joined_core_acceptance=False, vm_cleanup_pending=True)
    write(private / "result.json", result)
    if not success: export_failure(value, result, pool, preexisting, stop)
    native_job = next((job for job in pool.jobs if job["name"] == "native"), None)
    observed = native_kvm(native_job, result["identity"])
    write(Path(value["output_directory"]) / K["NAME"], K["continuity_receipt"](result["identity"], kvm_before,
        acl_before, baseline_state, initial, observed["state"], observed["record"]))
    if not success:
        try: export_inner_diagnostic(value, result["identity"], inner_preexisting, result["cleanup"])
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            # Diagnostic persistence cannot change the original failed result,
            # replace its cleanup record, or introduce acceptance authority.
            pass
    return result


def join(value):
    """Combine only original closed records; QEMU/host teardown is still external."""
    require(not os.path.lexists(Path(value["output_directory"]) / FAILURE_NAME))
    private = Path(value["run_directory"]) / "android-owner"
    weather = Path(value["weather_root"])
    owner = document(private / "result.json")
    expected_identity = identity(value["core_commit"], value["weather_commit"])
    same(owner, dict(schema=6, kind="weather-android-owner-run", identity=expected_identity, success=True,
        phase="complete", statuses=dict(driver=0, tunnel=0, native=0), cleanup=dict(children_joined=True,
        forced_kill=False, output_drained=True, socket_removed=True, host_netns_unchanged=True),
        helper_requests=0, joined_core_acceptance=False, vm_cleanup_pending=True))
    ready = document(private / "ready.json")
    # Historical ready is bound below, not re-authorized after its deadline.
    ready_record(ready, value, historical=True)
    same(document(private / "finalize.json"), dict(schema=6, kind="weather-android-finalize-requested",
        prepared_sha256=ready["prepared_sha256"], finalize_requested=True, joined_delivery_proven=False))
    tunnel = document(private / "tunnel.json"); tunnel_record(tunnel)
    guest_path = Path(value["output_directory"]) / "weather-android-delivery-evidence.json"
    guest_raw = read(guest_path); guest = E["decode"](guest_raw, 65536); E["validate_guest_export"](guest)
    for key in ("manifest_sha256", "core_sha256", "prepared_sha256"): same(guest[key], ready[key])
    # The owner budget starts before publishing and is deliberately shorter
    # than each immutable publication's lifetime. Do not require equal clocks
    # or renew either authorization merely to make the records agree.
    require(ready["deadline_unix_seconds"] <= min(
        item["expires_unix_seconds"] for item in guest["publications"].values()))
    for rows in guest["transfers"].values():
        require(all(row["completed_at_ms"] < ready["deadline_unix_seconds"] * 1000 for row in rows))
    live = weather / "build/hosted-android-live-ci"
    native_result(document(live / "result.json"))
    preparation = document(private / "preparation.json")
    preparation_record(preparation, expected_identity)
    for basename, key in (("prepared.json", "prepared_sha256"), ("result.json", "result_sha256")):
        same(digest(read(weather / "build/hosted-android-ci" / basename, 2 * 1024**2)), preparation[key])
    same(document(live / "admission.json"), dict(schema=1, kind="hosted-android-protected-core-admission",
        identity=expected_identity, prepared_sha256=preparation["prepared_sha256"], result_sha256=preparation["result_sha256"],
        apk=preparation["apk"], core_executed=False, joined_core_acceptance=False))
    proof = weather / "build/overmorrow-hosted-android-live-proof"
    raw = read(proof / "report.json")
    boundary_raw, cleanup_raw = read(proof / "emulator-boundary.json"), read(proof / "emulator-cleanup.json")
    E["decode"](boundary_raw, 65536)  # Only its authenticated digest is exported.
    same(E["decode"](cleanup_raw, 65536), dict(schema=1, direct_children_reaped=True, private_avd_removed=True,
        private_android_home_removed=True, trial_returned=True, enclosing_namespace_cleanup_required=True))
    same(document(live / "installed.json"), dict(schema=1, kind="hosted-android-protected-core-installed",
        identity=expected_identity, apk=preparation["apk"], installed_report_sha256=digest(raw),
        boundary_sha256=digest(boundary_raw), emulator_cleanup_sha256=digest(cleanup_raw), actual_installed_app=True,
        synthetic=False, expiry_proven=False, core_delivery=False, joined_core_acceptance=False, production_authority=False))
    report = E["decode"](raw, 65536)
    observed = E["join_observations"](report, guest["transfers"], tunnel["responses"], guest["publications"])
    result = dict(schema=6, kind="weather-android-owner-join", identity=expected_identity,
        manifest_sha256=ready["manifest_sha256"], core_sha256=ready["core_sha256"], prepared_sha256=ready["prepared_sha256"],
        guest_evidence_sha256=digest(guest_raw), original_android_report_sha256=digest(raw),
        tunnel_sha256=digest(read(private / "tunnel.json")), owner_result_sha256=digest(read(private / "result.json")),
        observations=observed, installed_android_observed=True, original_cli_http_ui_joined=True,
        helper_requests=0, joined_core_acceptance=False, vm_cleanup_pending=True)
    write(Path(value["output_directory"]) / "weather-android-owner-join.json", result)
    return result


def candidate(value, guest, expected_identity, manifest):
    """Validate the closed projection after the original private records vanish."""
    exact(value, ("schema", "kind", "identity", "manifest_sha256", "core_sha256", "prepared_sha256",
        "guest_evidence_sha256", "original_android_report_sha256", "tunnel_sha256", "owner_result_sha256",
        "observations", "installed_android_observed", "original_cli_http_ui_joined", "helper_requests",
        "joined_core_acceptance", "vm_cleanup_pending"))
    same(value["schema"], 6); same(value["kind"], "weather-android-owner-join"); same(value["identity"], expected_identity)
    E["hashes"](value, ("manifest_sha256", "core_sha256", "prepared_sha256", "guest_evidence_sha256",
        "original_android_report_sha256", "tunnel_sha256", "owner_result_sha256"))
    same(value["manifest_sha256"], manifest)
    for key in ("manifest_sha256", "core_sha256", "prepared_sha256"): same(value[key], guest[key])
    for key in ("installed_android_observed", "original_cli_http_ui_joined", "vm_cleanup_pending"): same(value[key], True)
    same(value["helper_requests"], 0); same(value["joined_core_acceptance"], False)
    observed = value["observations"]
    exact(observed, ("schema", "kind", "profile", "products", "matched_original_receipts_and_http_and_ui",
        "joined_core_acceptance", "expiry_proven"))
    same(observed["schema"], 6); same(observed["kind"], "weather-android-observation-join")
    same(observed["profile"], PROFILE); same(observed["matched_original_receipts_and_http_and_ui"], True)
    same(observed["joined_core_acceptance"], False); same(observed["expiry_proven"], False)
    exact(observed["products"], E["PRODUCTS"])
    for key in E["PRODUCTS"]:
        item, publication = observed["products"][key], guest["publications"][key]
        exact(item, ("forecast_sha256", "manifest_id", "cold_receipt_sha256", "original_receipts", "response_sha256",
            "cold_peer_bytes", "warm_peer_bytes", "requests", "native_rows"))
        same(item["forecast_sha256"], publication["sha256"]); same(item["manifest_id"], publication["manifest_id"])
        same(item["original_receipts"], [row["stdout_sha256"] for row in guest["transfers"][key]])
        same(item["cold_receipt_sha256"], item["original_receipts"][0])
        require(type(item["response_sha256"]) is list and len(item["response_sha256"]) == 3
            and all(type(item) is str and E["HEX"].fullmatch(item) for item in item["response_sha256"]))
        same(item["cold_peer_bytes"], publication["bytes"]); same(item["warm_peer_bytes"], 0)
        same(item["requests"], 3); same(item["native_rows"], 4 if key == "weather" else 5)


def accept(output, core_commit, weather_commit, manifest, kvm_cleanup):
    """Promote only after the enclosing owner has joined and removed its VM."""
    require(not os.path.lexists(Path(output) / FAILURE_NAME))
    hosted(core_commit, weather_commit)
    output = canonical(output, directory=True)
    require(output.is_relative_to(CORE) and output != CORE and type(manifest) is str and E["HEX"].fullmatch(manifest))
    expected_identity = identity(core_commit, weather_commit)
    raw = read(output / "weather-android-owner-join.json"); joined = E["decode"](raw, 65536)
    guest_raw = read(output / "weather-android-delivery-evidence.json")
    guest = E["decode"](guest_raw, 65536); E["validate_guest_export"](guest)
    candidate(joined, guest, expected_identity, manifest)
    same(joined["guest_evidence_sha256"], digest(guest_raw))
    vm_raw = read(output / "weather-android-vm-cleanup.json")
    same(E["decode"](vm_raw, 65536), dict(schema=6, kind="weather-android-vm-cleanup", core_commit=core_commit,
        weather_commit=weather_commit, manifest_sha256=manifest, driver_finished=True, qemu_started=True,
        qemu_joined=True, private_guest_state_removed=True, owner_exit_status=0, joined_core_acceptance=False))
    kvm_raw = read(canonical(kvm_cleanup, mode=0o600)); kvm = E["decode"](kvm_raw, 65536)
    exact(kvm, ("schema", "kind", "identity", "baseline_sha256", "restored_sha256", "baseline_bytes", "restored_bytes",
        "original_kvm_acl_restored"))
    same(kvm["schema"], 6); same(kvm["kind"], "weather-android-kvm-cleanup"); same(kvm["identity"], expected_identity)
    E["hashes"](kvm, ("baseline_sha256", "restored_sha256")); same(kvm["baseline_sha256"], kvm["restored_sha256"])
    E["integer"](kvm["baseline_bytes"], 1, 65536); same(kvm["baseline_bytes"], kvm["restored_bytes"])
    same(kvm["original_kvm_acl_restored"], True)
    result = dict(schema=6, kind="weather-android-hosted-acceptance", profile=PROFILE, identity=expected_identity,
        manifest_sha256=manifest, core_sha256=joined["core_sha256"], prepared_sha256=joined["prepared_sha256"],
        owner_join_sha256=digest(raw), guest_evidence_sha256=digest(guest_raw), vm_cleanup_sha256=digest(vm_raw),
        kvm_cleanup_sha256=digest(kvm_raw), observations=joined["observations"], passed=True,
        joined_core_acceptance=True, vm_cleanup_pending=False, helper_requests=0,
        expiry_proven=False, physical_device=False, production_authority=False)
    write(output / "weather-android-hosted-acceptance.json", result)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    first = actions.add_parser("preflight")
    for key in ("weather-root", "core-commit", "weather-commit"): first.add_argument("--" + key, required=True)
    first.add_argument("--kvm-output", required=True, type=Path)
    first.add_argument("--kvm-baseline", type=Path)
    for name in ("run", "join"):
        actions.add_parser(name).add_argument("--config", required=True, type=Path)
    last = actions.add_parser("accept")
    for key in ("output", "core-commit", "weather-commit", "manifest", "kvm-cleanup"):
        last.add_argument("--" + key, required=True)
    args = parser.parse_args()
    def interrupted(*_): raise Failure("interrupted")
    previous = {sig: signal.signal(sig, interrupted) for sig in SIGNALS}
    try:
        if args.action == "preflight": result = preflight(Path(args.weather_root), args.core_commit,
            args.weather_commit, args.kvm_output, args.kvm_baseline)
        elif args.action == "run": result = run(config(args.config))
        elif args.action == "join": result = join(config(args.config))
        else: result = accept(Path(args.output), args.core_commit, args.weather_commit, args.manifest, Path(args.kvm_cleanup))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        if result.get("success") is False: raise SystemExit(1)
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print('{"schema":6,"kind":"weather-android-owner-rejected","success":false}', flush=True)
        raise SystemExit(1) from None
