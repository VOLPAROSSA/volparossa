#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Guest-only requester cancellation and pending-bootstrap shutdown; no network edits."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time

PREFIX = "content-provider-cancellation"
HELPER = "volparossa-alpha-helper@client.service"
AGENT = "volparossa-alpha-agent@client.service"
NAME = "disposable-native-network-publication"
LIMIT = 262144
COOLDOWN_MS = 30000
COOLDOWN_DEADLINE_MS = 35000
COOLDOWN_SCOPE = "fixture-idle-preselection-cooldown-not-route-readiness"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    require(not path.is_symlink() and path.stat().st_size <= LIMIT, "invalid evidence file")
    return json.loads(path.read_bytes())


def write(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    require(len(raw) <= LIMIT, "evidence exceeds bound")
    with path.open("xb") as target:
        os.fchmod(target.fileno(), 0o600)
        target.write(raw)


def guest(work):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha",
            "only the disposable root-owned alpha guest may signal fixture services")
    result = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, timeout=5, check=False)
    require(result.returncode == 0 and result.stdout.strip() == b"kvm", "KVM guest required")
    require(work.is_absolute() and work.resolve() == work and work.parent == Path("/opt")
            and work.name.startswith("va.") and work.is_dir() and work.stat().st_uid == 0,
            "wrong disposable work directory")


def identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return dict(pid=pid, start_ticks=int(fields[19])), fields[0]


def properties(unit, timeout=5):
    result = subprocess.run(["systemctl", "show", unit, "--property=MainPID,InvocationID,ActiveState"],
                            capture_output=True, timeout=timeout, check=True)
    value = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
    require(value["ActiveState"] == "active" and int(value["MainPID"]) > 1
            and re.fullmatch(r"[0-9a-f]{32}", value["InvocationID"]), "unit not active")
    return value


def owned_helper(record, timeout=5):
    current, state = identity(record["process"]["pid"])
    require(current == record["process"], "helper PID was replaced")
    unit = properties(HELPER, timeout)
    require(int(unit["MainPID"]) == current["pid"]
            and unit["InvocationID"] == record["invocation_id"], "helper unit was replaced")
    namespace = os.stat(f"/proc/{current['pid']}/ns/net")
    require(f"{namespace.st_dev}:{namespace.st_ino}" == record["network_namespace_identity"]
            and f"/system.slice/{HELPER}" in [line.split(":", 2)[2] for line in
                Path(f"/proc/{current['pid']}/cgroup").read_text().splitlines()],
            "helper no longer belongs to the exact disposable namespace/unit")
    return state


def cooldown_record():
    return dict(schema_version=1, scope=COOLDOWN_SCOPE, required_ms=COOLDOWN_MS,
                deadline_ms=COOLDOWN_DEADLINE_MS, elapsed_monotonic_ms=0,
                elapsed_wall_ms=0, total_monotonic_ms=0, before_confirmed=False, after_confirmed=False,
                outcome="not-confirmed")


def validate_cooldown(record):
    require(type(record) is dict and set(record) == set(cooldown_record()),
            "wrong fixture cooldown fields")
    require(type(record["schema_version"]) is int and record["schema_version"] == 1
            and record["scope"] == COOLDOWN_SCOPE
            and type(record["required_ms"]) is int and record["required_ms"] == COOLDOWN_MS
            and type(record["deadline_ms"]) is int and record["deadline_ms"] == COOLDOWN_DEADLINE_MS
            and type(record["elapsed_monotonic_ms"]) is int
            and 0 <= record["elapsed_monotonic_ms"] < 2 ** 63
            and type(record["total_monotonic_ms"]) is int
            and record["elapsed_monotonic_ms"] <= record["total_monotonic_ms"] < 2 ** 63
            and type(record["elapsed_wall_ms"]) is int
            and -(2 ** 63) < record["elapsed_wall_ms"] < 2 ** 63
            and type(record["before_confirmed"]) is bool
            and type(record["after_confirmed"]) is bool
            and type(record["outcome"]) is str
            and record["outcome"] in {"not-confirmed", "elapsed", "deadline", "clock-invalid"},
            "invalid fixture cooldown receipt")
    if record["outcome"] == "elapsed":
        require(record["before_confirmed"] and record["after_confirmed"]
                and COOLDOWN_MS <= record["elapsed_monotonic_ms"] < COOLDOWN_DEADLINE_MS
                and record["total_monotonic_ms"] < COOLDOWN_DEADLINE_MS
                and record["elapsed_wall_ms"] >= COOLDOWN_MS,
                "fixture cooldown was not confirmed on both clocks")
    return record


def await_fixture_cooldown(record, confirm, *, monotonic_ns=None, wall_ns=None, sleep=None):
    """Fixture-only separation from an earlier bootstrap; never grants route admission.

    Successful production preselection cools for 30 seconds on both clocks, even
    after Disconnect reports idle. Do not spend the separate eight-second pending
    bootstrap assertion inside that earlier cooldown. No product timer is changed.
    `confirm` rechecks the original services and disconnected state without mutation.
    """
    monotonic_ns = monotonic_ns or time.monotonic_ns
    wall_ns = wall_ns or time.time_ns
    sleep = sleep or time.sleep
    started, wall_started = monotonic_ns(), wall_ns()
    absolute_started = started
    deadline = started + COOLDOWN_DEADLINE_MS * 1000000
    previous, previous_wall = started, wall_started

    def observe():
        nonlocal previous, previous_wall
        current, wall_current = monotonic_ns(), wall_ns()
        record["elapsed_monotonic_ms"] = (current - started) // 1000000
        record["elapsed_wall_ms"] = (wall_current - wall_started) // 1000000
        record["total_monotonic_ms"] = (current - absolute_started) // 1000000
        if current < previous or wall_current < previous_wall:
            record["outcome"] = "clock-invalid"
            raise ValueError("fixture cooldown clock moved backwards")
        previous, previous_wall = current, wall_current
        if current >= deadline:
            record["outcome"] = "deadline"
            raise ValueError("fixture cooldown prerequisite exceeded deadline")
        return (deadline - current) / 1000000000

    # Each subprocess called by confirm receives a fresh remaining-time bound.
    confirm(observe)
    observe()
    # Start the full cooldown only after the idle/service snapshot is confirmed.
    # Confirmation itself still spends the original absolute 35-second budget.
    started, wall_started = previous, previous_wall
    record["before_confirmed"] = True
    while True:
        remaining = observe()
        if min(record["elapsed_monotonic_ms"], record["elapsed_wall_ms"]) >= COOLDOWN_MS:
            break
        sleep(min(0.1, remaining))
    confirm(observe)
    observe()
    record["after_confirmed"] = True
    record["outcome"] = "elapsed"
    validate_cooldown(record)


def resume(work):
    # The outer driver calls this BEFORE any other fixture teardown, including on failure.
    guest(work)
    path = work / f"{PREFIX}-pause.json"
    if not path.exists():
        return
    record = read(path)
    owned_helper(record)
    descriptor = os.pidfd_open(record["process"]["pid"])
    try:
        owned_helper(record)
        signal.pidfd_send_signal(descriptor, signal.SIGCONT)
    finally:
        os.close(descriptor)


def validate(value, publication, named, *, historical=False):
    require(type(value.get("schema_version")) is int
            and value["schema_version"] == (1 if historical else 2),
            "wrong current or historical cancellation schema")
    if historical:
        require("cooldown_prerequisite" not in value, "historical cancellation cannot claim later prerequisite")
    else:
        require(validate_cooldown(value.get("cooldown_prerequisite"))["outcome"] == "elapsed",
                "missing confirmed fixture cooldown prerequisite")
    require(value["success"] is True
            and value["scope"] == "named-pre-ready-cancellation-and-pending-bootstrap-shutdown"
            and value["fresh_cache_initially_absent"] is True and value["fresh_cache_created"] is True
            and value["cancelled_output_absent"] is True, "missing real pre-ready cancellation")
    require(value["initial_status"]["status"] == 0
            and "connected: false" in value["initial_status"]["stdout"].splitlines()
            and "active contexts: 0" in value["initial_status"]["stdout"].splitlines()
            and value["initial_paths"]["status"] == 0 and value["initial_paths"]["stdout"] == "",
            "fixture did not begin without an active client route")
    helper, agent = value["helper"], value["agent"]
    for process in (helper["process"], agent["process"]):
        require(type(process["pid"]) is int and process["pid"] > 1
                and type(process["start_ticks"]) is int and process["start_ticks"] > 0,
                "missing original process identity")
    require(helper["process"]["pid"] != agent["process"]["pid"]
            and helper["unit"] == HELPER and agent["unit"] == AGENT
            and re.fullmatch(r"[0-9a-f]{32}", helper["invocation_id"])
            and re.fullmatch(r"[0-9a-f]{32}", agent["invocation_id"])
            and re.fullmatch(r"[0-9]+:[0-9]+", helper["network_namespace_identity"]),
            "wrong original fixture services")
    for probe in value["busy_probes"]:
        require(probe["status"] != 0 and "CLIENT_ROUTE_BUSY" in probe["stderr"],
                "bootstrap was not actually Connecting")
    require(len(value["busy_probes"]) == 2 and value["helper_stopped_before_shutdown"] is True
            and value["cancelled_cli_status"] == -signal.SIGTERM
            and 0 <= value["cache_only_elapsed_ms"] < 4000,
            "request was not cancelled before a prompt independent cache delivery")
    attempts = value["cache_only_attempts"]
    require(1 <= len(attempts) <= 8 and attempts[-1]["status"] == 0
            and all(item["status"] != 0 and "CONTENT_BUSY" in item["stderr"] for item in attempts[:-1])
            and json.loads(attempts[-1]["stdout"]) == value["cache_only"],
            "cache retry hid a non-busy error or substituted its original receipt")
    cached = value["cache_only"]
    require(cached["operation"] == "named_content_download" and cached["cache_only"] is True
            and cached["publisher_key"] == named["publisher_key"] == publication["publisher_hex"]
            and cached["name"] == named["name"] == NAME and cached["revision"] == named["revision"] == 1
            and cached["manifest_id"] == named["manifest_id"] == publication["manifest_id"]
            and cached["publication_expires_unix_seconds"] == named["publication_expires_unix_seconds"]
            and cached["sha256"] == named["sha256"] == publication["object_sha256"] == value["output"]["sha256"]
            and cached["bytes"] == named["bytes"] == publication["bytes"] == value["output"]["bytes"]
            and cached["peer_bytes"] == cached["providers_used"] == cached["origin_body_bytes"] == 0
            and cached["origin_range_requests"] == 0 and cached["provider_peer_ids"] == []
            and cached["control_relay_peer_id"] == "" and cached["local_delivery"] is True
            and cached["ownership_changed"] is False, "cache-only delivery changed original content or used network")
    shutdown = value["shutdown"]
    require(shutdown["control_eof"] is True and 0 <= shutdown["control_eof_ms"] < 2000
            and 0 <= shutdown["control_probe_lifetime_ms"] < 2000
            and shutdown["helper_still_stopped_at_eof"] is True
            and shutdown["agent_still_original_at_eof"] is True
            and shutdown["systemctl_wait_status"] == 0 and shutdown["original_agent_ended"] is True
            and shutdown["helper_resumed_before_wait_completed"] is True
            and "SHUTDOWN_CLEANUP_FAILED" not in shutdown["original_agent_log_tail"]
            and value["cleanup"] == dict(helper_resumed=True, outputs_removed=True),
            "original agent did not drain successfully before outer cleanup")
    return value


def run(work, binary, uid, gid, control_gid):
    guest(work)
    require(uid > 0 and gid > 0 and control_gid > 0, "ordinary fixture account required")
    require(binary.is_absolute() and binary.resolve() == binary and binary.is_file(), "wrong CLI executable")
    original = read(work / "content-provider-publication.json")
    named = read(work / "content-provider-named-fetch.json")
    helper_unit, agent_unit = properties(HELPER), properties(AGENT)
    helper_process, _ = identity(int(helper_unit["MainPID"]))
    agent_process, _ = identity(int(agent_unit["MainPID"]))
    helper_origin = read(work / "helper-record-client.json")
    require(helper_origin["main_pid"] == helper_process["pid"], "fixture helper was replaced")
    helper = dict(unit=HELPER, process=helper_process, invocation_id=helper_unit["InvocationID"],
                  network_namespace_identity=helper_origin["network_namespace_identity"])
    owned_helper(helper)
    root = work / "client-fixtures/cancellation-output"
    cache = work / "state-client/content/cancellation-cache"
    require(not root.exists() and not root.is_symlink() and not cache.exists() and not cache.is_symlink(),
            "cancellation fixture paths already exist")
    root.mkdir(mode=0o700)
    os.chown(root, uid, gid)
    cancelled, cached = root / "cancelled.bin", root / "cached.bin"
    control = work / "runtime-client/control/agent.sock"
    cli = ["setpriv", f"--reuid={uid}", f"--regid={gid}", f"--groups={control_gid}",
           "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
           str(binary), "--control-socket", str(control)]
    name_args = ["content", "fetch-name", "--publisher-key", original["publisher_hex"],
                 "--name", NAME, "--min-revision", "1"]

    def command(label, args, timeout=3):
        with (work / f"{PREFIX}-{label}.out").open("xb") as stdout, \
                (work / f"{PREFIX}-{label}.err").open("xb") as stderr:
            result = subprocess.run(cli + args, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
        out, err = (work / f"{PREFIX}-{label}.out").read_bytes(), (work / f"{PREFIX}-{label}.err").read_bytes()
        require(len(out) <= LIMIT and len(err) <= 32768, "CLI evidence exceeds bound")
        return dict(status=result.returncode, stdout=out.decode(), stderr=err.decode())

    def busy(label):
        result = command(label, ["disconnect"])
        require(result["status"] != 0 and "CLIENT_ROUTE_BUSY" in result["stderr"], "route not Connecting")
        return result

    initial_status, initial_paths = command("initial-status", ["status"]), command("initial-paths", ["paths"])
    require(initial_status["status"] == initial_paths["status"] == 0
            and "connected: false" in initial_status["stdout"].splitlines()
            and "active contexts: 0" in initial_status["stdout"].splitlines() and initial_paths["stdout"] == "",
            "client did not start idle")
    descriptor = os.pidfd_open(helper_process["pid"])
    children, opened, probe = [], [], None
    evidence = dict(schema_version=2, success=False,
                    scope="named-pre-ready-cancellation-and-pending-bootstrap-shutdown",
                    helper=helper, agent=dict(unit=AGENT, process=agent_process,
                                             invocation_id=agent_unit["InvocationID"]),
                    fresh_cache_initially_absent=True, initial_status=initial_status, initial_paths=initial_paths)

    def confirm_idle(remaining):
        require(owned_helper(helper, timeout=min(5, remaining())) not in {"T", "t", "Z", "X"},
                "original helper is not running before cancellation fixture")
        require(properties(AGENT, timeout=min(5, remaining())) == agent_unit
                and identity(agent_process["pid"])[0] == agent_process,
                "original agent changed before cancellation fixture")
        label = "cooldown-after" if evidence["cooldown_prerequisite"]["before_confirmed"] else "cooldown-before"
        status = command(f"{label}-status", ["status"], timeout=min(3, remaining()))
        paths = command(f"{label}-paths", ["paths"], timeout=min(3, remaining()))
        require(status["status"] == paths["status"] == 0
                and "connected: false" in status["stdout"].splitlines()
                and "active contexts: 0" in status["stdout"].splitlines() and paths["stdout"] == "",
                "client changed from idle during fixture cooldown")

    def interrupted(_signal, _frame):
        raise InterruptedError("disposable cancellation fixture interrupted")

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        evidence["cooldown_prerequisite"] = cooldown_record()
        await_fixture_cooldown(evidence["cooldown_prerequisite"], confirm_idle)
        # Persist exact recovery identity before SIGSTOP, even if the parent is interrupted.
        write(work / f"{PREFIX}-pause.json", helper)
        owned_helper(helper)
        signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
        deadline = time.monotonic() + 2
        while identity(helper_process["pid"])[1] != "T":
            require(time.monotonic() < deadline, "helper did not stop")
            time.sleep(0.01)
        for suffix in ("out", "err"):
            opened.append((work / f"{PREFIX}-cancelled.{suffix}").open("xb"))
        fetching = subprocess.Popen(cli + name_args + ["--cache", str(cache), "--local-output", str(cancelled)],
                                    stdout=opened[0], stderr=opened[1])
        children.append(fetching)
        deadline, attempt = time.monotonic() + 8, 0
        while True:
            require(fetching.poll() is None and time.monotonic() < deadline, "fetch never entered pending bootstrap")
            if cache.is_dir():
                result = command(f"pending-{attempt}", ["disconnect"])
                if result["status"] != 0 and "CLIENT_ROUTE_BUSY" in result["stderr"]:
                    break
                require(result["status"] == 0, "unexpected route precondition failure")
            attempt += 1
            time.sleep(0.02)
        evidence["fresh_cache_created"] = True
        evidence["busy_probes"] = [result]
        fetching.terminate()
        evidence["cancelled_cli_status"] = fetching.wait(timeout=2)
        started = time.monotonic()
        evidence["cache_only_attempts"] = []
        for index in range(8):
            remaining = 4 - (time.monotonic() - started)
            require(remaining > 0, "requester cancellation did not promptly release retrieval")
            receipt = command(f"cached-{index}", name_args + ["--cache", str(work / "state-client/content/named-cache"),
                                "--reuse-cache", "--cache-only", "--local-output", str(cached)], timeout=remaining)
            evidence["cache_only_attempts"].append(receipt)
            if receipt["status"] == 0:
                break
            require("CONTENT_BUSY" in receipt["stderr"], "non-busy cache delivery failure")
            time.sleep(0.02)
        evidence["cache_only_elapsed_ms"] = int(1000 * (time.monotonic() - started))
        require(receipt["status"] == 0, "cancelled requester still blocks retrieval")
        evidence["cache_only"] = json.loads(receipt["stdout"])
        require(stat.S_IMODE(cached.stat().st_mode) == 0o600 and cached.stat().st_uid == uid,
                "cache output changed ordinary account ownership")
        evidence["output"] = dict(bytes=cached.stat().st_size,
                                  sha256=hashlib.sha256(cached.read_bytes()).hexdigest())
        evidence["cancelled_output_absent"] = not cancelled.exists()
        evidence["busy_probes"].append(busy("pending-after-cache"))
        evidence["helper_stopped_before_shutdown"] = owned_helper(helper) == "T"
        require(evidence["helper_stopped_before_shutdown"], "helper resumed early")
        require(command("product-logs", ["logs"])["status"] == 0, "original product logs unavailable")
        log = work / "agent-client.log"
        log_offset = log.stat().st_size
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1.9)
        probe_started = time.monotonic()
        probe.connect(str(control))
        # Confirm admission is live after this idle reader, before the 5s request timeout.
        require(command("pre-shutdown-status", ["status"])["status"] == 0, "agent not serving before shutdown")
        for suffix in ("out", "err"):
            opened.append((work / f"{PREFIX}-shutdown.{suffix}").open("xb"))
        started = time.monotonic()
        stopping = subprocess.Popen(["systemctl", "--wait", "kill", "--kill-whom=main", "--signal=TERM", AGENT],
                                    stdout=opened[2], stderr=opened[3])
        children.append(stopping)
        eof = probe.recv(1) == b""
        shutdown = dict(control_eof=eof, control_eof_ms=int(1000 * (time.monotonic() - started)),
                        control_probe_lifetime_ms=int(1000 * (time.monotonic() - probe_started)),
                        helper_still_stopped_at_eof=owned_helper(helper) == "T",
                        agent_still_original_at_eof=identity(agent_process["pid"])[0] == agent_process)
        require(eof and shutdown["control_eof_ms"] < 2000 and shutdown["helper_still_stopped_at_eof"],
                "control admission did not stop before bootstrap drain")
        shutdown["helper_resumed_before_wait_completed"] = stopping.poll() is None
        signal.pidfd_send_signal(descriptor, signal.SIGCONT)
        shutdown["systemctl_wait_status"] = stopping.wait(timeout=120)
        try:
            shutdown["original_agent_ended"] = identity(agent_process["pid"])[0] != agent_process
        except FileNotFoundError:
            shutdown["original_agent_ended"] = True
        with log.open("rb") as source:
            source.seek(log_offset)
            tail = source.read(32769)
        require(len(tail) <= 32768, "agent shutdown log exceeds bound")
        shutdown["original_agent_log_tail"] = tail.decode(errors="replace")
        evidence["shutdown"] = shutdown
        evidence["success"] = True
    finally:
        # Resume through the original pidfd BEFORE child reaping or any other cleanup.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        resumed = True
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGCONT)
        except ProcessLookupError:
            resumed = False
            evidence["success"] = False
        os.close(descriptor)
        for child in children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
        if probe is not None:
            probe.close()
        for target in opened:
            target.close()
        for target in (cancelled, cached):
            if target.exists():
                require(not target.is_symlink() and stat.S_ISREG(target.stat().st_mode)
                        and target.stat().st_uid == uid, "unexpected output cleanup target")
                target.unlink()
        root.rmdir()
        evidence["cleanup"] = dict(helper_resumed=resumed, outputs_removed=True)
        write(work / f"{PREFIX}.json", evidence)
        signal.signal(signal.SIGTERM, previous_term)
    validate(evidence, original, named)


def sample():
    publication = dict(publisher_hex="a" * 64, manifest_id="b" * 64, object_sha256="c" * 64, bytes=99)
    cached = dict(operation="named_content_download", cache_only=True, publisher_key="a" * 64,
                  name=NAME, revision=1, manifest_id="b" * 64, publication_expires_unix_seconds=99,
                  sha256="c" * 64, bytes=99, peer_bytes=0, providers_used=0, origin_body_bytes=0,
                  origin_range_requests=0, provider_peer_ids=[], control_relay_peer_id="",
                  local_delivery=True, ownership_changed=False)
    cooldown = cooldown_record()
    cooldown.update(elapsed_monotonic_ms=30001, elapsed_wall_ms=30001, total_monotonic_ms=30001,
                    before_confirmed=True, after_confirmed=True, outcome="elapsed")
    value = dict(schema_version=2, success=True, scope="named-pre-ready-cancellation-and-pending-bootstrap-shutdown",
                 cooldown_prerequisite=cooldown,
                 fresh_cache_initially_absent=True, fresh_cache_created=True, cancelled_output_absent=True,
                 initial_status=dict(status=0, stdout="connected: false\nactive contexts: 0\n"),
                 initial_paths=dict(status=0, stdout=""),
                 helper=dict(unit=HELPER, process=dict(pid=42, start_ticks=123), invocation_id="d" * 32,
                             network_namespace_identity="4:12"),
                 agent=dict(unit=AGENT, process=dict(pid=43, start_ticks=124), invocation_id="e" * 32),
                 busy_probes=[dict(status=1, stderr="CLIENT_ROUTE_BUSY")] * 2,
                 helper_stopped_before_shutdown=True, cancelled_cli_status=-signal.SIGTERM,
                 cache_only_elapsed_ms=100, cache_only=cached, output=dict(bytes=99, sha256="c" * 64),
                 cache_only_attempts=[dict(status=0, stdout=json.dumps(cached), stderr="")],
                 shutdown=dict(control_eof=True, control_eof_ms=100, control_probe_lifetime_ms=200,
                               helper_still_stopped_at_eof=True,
                               agent_still_original_at_eof=True, systemctl_wait_status=0, original_agent_ended=True,
                               helper_resumed_before_wait_completed=True, original_agent_log_tail=""),
                 cleanup=dict(helper_resumed=True, outputs_removed=True))
    return value, publication, cached


def self_test():
    value, publication, cached = sample()
    validate(value, publication, cached)
    mutations = [("shutdown", "systemctl_wait_status", 1), ("shutdown", "control_eof_ms", 5000),
                 ("shutdown", "helper_still_stopped_at_eof", False),
                 ("shutdown", "original_agent_log_tail", "SHUTDOWN_CLEANUP_FAILED"),
                 ("cache_only", "manifest_id", "f" * 64), ("cache_only", "peer_bytes", 1),
                 ("cleanup", "helper_resumed", False), ("helper", "unit", AGENT)]
    for section, key, replacement in mutations:
        broken = copy.deepcopy(value)
        broken[section][key] = replacement
        try:
            validate(broken, publication, cached)
        except ValueError:
            continue
        raise AssertionError(f"accepted changed {section}.{key}")
    broken = copy.deepcopy(value)
    broken["busy_probes"][0]["stderr"] = "CONTENT_UNAVAILABLE"
    try:
        validate(broken, publication, cached)
    except ValueError:
        print("content cancellation: 10 inert checks passed")
        return
    raise AssertionError("accepted missing Connecting precondition")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "self-test":
        self_test()
    elif len(sys.argv) == 3 and sys.argv[1] == "resume":
        resume(Path(sys.argv[2]))
    elif len(sys.argv) == 7 and sys.argv[1] == "run":
        run(Path(sys.argv[2]), Path(sys.argv[3]), *map(int, sys.argv[4:7]))
    else:
        raise SystemExit("usage: self-test | resume WORK | run WORK CLI UID GID CONTROL_GID")
