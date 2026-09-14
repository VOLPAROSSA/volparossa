#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual guest-only CPU pressure, cooperative model pause/resume and fixed deadline."""

import copy
import json
import math
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / "agent-training-smoke.py"))
read, write, require = TRAIN["read"], TRAIN["write"], TRAIN["require"]
NAME = "agent-owner-priority"
SCOPE = ("one real CPU LoRA job yields to actual bounded disposable-guest CPU pressure, then resumes "
         "from the same model step and finishes under its original deadline; not all owner activity, "
         "battery/thermal awareness, autonomous training or full B01")
ACK = re.compile(r"compute owner_ack phase=(paused|resumed) sequence=(\d+) step=(\d+) elapsed_ms=(\d+)")


def bounded_text(path, maximum=16384):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "oversized observation")
    return data.decode()


def pressure_average():
    lines = [line for line in bounded_text("/proc/pressure/cpu").splitlines() if line.startswith("some ")]
    require(len(lines) == 1, "missing actual CPU PSI")
    fields = [word[6:] for word in lines[0].split() if word.startswith("avg10=")]
    require(len(fields) == 1, "invalid CPU PSI")
    value = float(fields[0])
    require(math.isfinite(value) and 0 <= value <= 100, "invalid CPU average")
    return value


def acknowledgements(output):
    result = []
    for line in bounded_text(output / "agent-training-worker.stderr", 262144).splitlines():
        match = ACK.fullmatch(line)
        if match:
            phase, sequence, step, elapsed = match.groups()
            result.append(dict(phase=phase, sequence=int(sequence), step=int(step), elapsed_ms=int(elapsed)))
    return result


def worker_ticks(worker):
    text = bounded_text(f"/proc/{worker['pid']}/stat").rsplit(") ", 1)[1].split()
    require(int(text[19]) == worker["start_ticks"], "observed worker identity changed")
    return dict(cpu_ticks=int(text[11]) + int(text[12]), boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))


def spin(cpu, deadline_ns):
    TRAIN["guest_guard"]()
    require(cpu in os.sched_getaffinity(0) and 0 < deadline_ns - time.monotonic_ns() <= 46_000_000_000,
            "invalid owned guest CPU contender")
    os.sched_setaffinity(0, {cpu})  # This process only; no host/global scheduler change.
    accumulator = 0
    while time.monotonic_ns() < deadline_ns:
        busy_until = time.monotonic_ns() + 20_000_000
        while time.monotonic_ns() < busy_until:
            accumulator = (accumulator + 17) % 104729
        # Genuine contention with bounded gaps so the real worker can acknowledge
        # at an execution-thread checkpoint, even when its nice priority is lower.
        time.sleep(0.03)


def exercise_pressure(output):
    TRAIN["guest_guard"](root=True)
    require(output == Path("/home/vpci/alpha-output"), "wrong guest output")
    owner = output.stat()
    require(owner.st_uid != 0, "guest job must be unprivileged")
    isolation = read(output / "agent-training-isolation.json")
    worker, cli = isolation["worker"], isolation["cli"]
    require(TRAIN["alive"](worker) and TRAIN["alive"](cli), "model job already ended")
    cpus = sorted(os.sched_getaffinity(cli["pid"]))
    require(1 <= len(cpus) <= 16, "unexpected disposable CPU set")
    report = dict(success=False, worker=worker, cli=cli, guest_cpu_set=cpus, pressure_processes=[],
                  cpu_samples=[], clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
                  contender_deadline_seconds=45, maximum_observation_seconds=110)
    children = []
    start = time.monotonic()
    end = start + 110

    def interrupted(_number, _frame):
        raise ValueError("pressure observer interrupted")

    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)

    def sample():
        require(time.monotonic() < end and TRAIN["alive"](cli) and TRAIN["alive"](worker), "pressure observation exceeded live job")
        value = pressure_average()
        report["cpu_samples"].append(dict(avg10=value, elapsed_ms=int((time.monotonic() - start) * 1000)))
        require(len(report["cpu_samples"]) <= 1200, "pressure sample bound")
        return acknowledgements(output)

    def stop_children():
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)

    try:
        report["before_pressure"] = worker_ticks(worker)
        initial_sequence = max((ack["sequence"] for ack in acknowledgements(output)), default=0)
        limit = time.monotonic_ns() + 45_000_000_000
        for cpu in cpus:
            for _ in range(2):
                child = subprocess.Popen(["setpriv", f"--reuid={owner.st_uid}", f"--regid={owner.st_gid}",
                    "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
                    "--", sys.executable, "-B", str(Path(__file__).resolve()), "spin", str(cpu), str(limit)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(child)
                report["pressure_processes"].append(TRAIN["identity"](child.pid))
        while True:
            acks = sample()
            paused = next((ack for ack in acks if ack["phase"] == "paused" and ack["sequence"] > initial_sequence), None)
            if paused is not None and any(item["avg10"] >= 20 for item in report["cpu_samples"]):
                break
            require(time.monotonic() - start < 30 and all(child.poll() is None for child in children),
                    "bounded real contention did not produce an acknowledged pause")
            time.sleep(0.1)
        report["paused_ack"] = paused
        report["paused_before"] = worker_ticks(worker)
        hold_until = time.monotonic() + 1.6
        while time.monotonic() < hold_until:
            require(not any(ack["sequence"] > paused["sequence"] for ack in sample()), "worker resumed while pause was being measured")
            time.sleep(0.1)
        report["paused_after"] = worker_ticks(worker)
        stop_children()
        report["contenders_stopped_boottime_ns"] = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        while True:
            resumed = next((ack for ack in sample() if ack["phase"] == "resumed" and ack["sequence"] > paused["sequence"]), None)
            if resumed is not None:
                report["resumed_ack"] = resumed
                break
            time.sleep(0.1)
        while True:
            resumed_ticks = worker_ticks(worker)
            if resumed_ticks["cpu_ticks"] > report["paused_after"]["cpu_ticks"]:
                report["resumed_after"] = resumed_ticks
                break
            sample()
            time.sleep(0.02)
        report["success"] = True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["observed_blocker"] = str(error)[:512]
    finally:
        stop_children()
        report["contenders_reaped"] = all(child.poll() is not None for child in children)
        report["remaining_pressure_processes"] = sum(TRAIN["alive"](item) for item in report["pressure_processes"])
        path = output / f"{NAME}-pressure.json"
        write(path, report)
        os.chown(path, owner.st_uid, owner.st_gid)
    return 0 if report["success"] else 1


def check_owner(proof, worker):
    require(proof["success"] is True and proof["contenders_reaped"] is True
            and proof["remaining_pressure_processes"] == 0, "pressure fixture incomplete")
    require(1 <= len(proof["guest_cpu_set"]) <= 16
            and len(proof["pressure_processes"]) == 2 * len(proof["guest_cpu_set"])
            and len({(x["pid"], x["start_ticks"]) for x in proof["pressure_processes"]}) == len(proof["pressure_processes"])
            and proof["worker"] not in proof["pressure_processes"] and proof["cli"] not in proof["pressure_processes"],
            "wrong owned contender set")
    samples = proof["cpu_samples"]
    require(0 < len(samples) <= 1200 and all(0 <= item["avg10"] <= 100 for item in samples)
            and any(item["avg10"] >= 20 for item in samples) and any(item["avg10"] < 20 for item in samples)
            and proof["contender_deadline_seconds"] == 45 and proof["maximum_observation_seconds"] == 110,
            "actual bounded CPU pressure/recovery missing")
    paused, resumed = proof["paused_ack"], proof["resumed_ack"]
    require(paused["phase"] == "paused" and resumed["phase"] == "resumed"
            and resumed["sequence"] == paused["sequence"] + 1 and 0 < paused["sequence"] <= 127
            and resumed["step"] == paused["step"] < 8
            and 0 <= paused["elapsed_ms"] < resumed["elapsed_ms"] < worker["elapsed_ms"] < 600000,
            "model advanced while paused, resumed without ACK or changed original deadline")
    before, after, active = (proof[key] for key in ("paused_before", "paused_after", "resumed_after"))
    require(1_500_000_000 <= after["boottime_ns"] - before["boottime_ns"]
            and 0 <= after["cpu_ticks"] - before["cpu_ticks"] <= proof["clock_ticks_per_second"] // 5
            and active["cpu_ticks"] > after["cpu_ticks"]
            and proof["before_pressure"]["boottime_ns"] < before["boottime_ns"] < after["boottime_ns"]
            <= proof["contenders_stopped_boottime_ns"] < active["boottime_ns"],
            "actual same-worker pause CPU accounting or resumed work missing")
    control, supervisor = worker["owner_control"], worker["supervisor"]
    require(control["enabled"] is True and control["records_received"] == control["last_sequence"] >= resumed["sequence"]
            and control["pause_count"] >= 1 and control["resume_count"] >= 1
            and control["pause_count"] + control["resume_count"] == control["records_received"]
            and control["paused_ms"] >= resumed["elapsed_ms"] - paused["elapsed_ms"] - 1
            and supervisor["spare_capacity"] is True and supervisor["pause_extends_deadline"] is False
            and supervisor["pressure_action"] == "cooperative-pause-resume-memory-cancel"
            and supervisor["deadline_seconds"] == 600, "unbound actual control/deadline report")


def execute(output, revision):
    status = TRAIN["execute"](output, revision, owner_priority=True)
    training = read(output / "agent-training-smoke.json")
    proof_path = output / f"{NAME}-pressure.json"
    proof = read(proof_path) if proof_path.is_file() else None
    result = dict(report_kind="volparossa-agent-owner-priority", source_revision=revision, scope=SCOPE,
        success=False, training=training, pressure=proof, cleanup=training["cleanup"], host_state=training["host_state"],
        full_b01_claimed=False, battery_thermal_activity_claimed=False, full_alpha_claimed=False)
    try:
        require(status == 0, "real owner-priority training did not complete")
        TRAIN["check_report"](training, revision)
        check_owner(proof, training["worker"])
        require(proof["worker"] == training["isolation"]["worker"] and proof["cli"] == training["isolation"]["cli"],
                "pressure measurements used another job")
        result["success"] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["observed_blocker"] = str(error)[:512]
    write(output / f"{NAME}-smoke.json", result)
    return 0 if result["success"] else 1


def check_report(path, revision):
    report = read(path, 1048576)
    require(report["report_kind"] == "volparossa-agent-owner-priority" and report["source_revision"] == revision
            and report["success"] is True and report["scope"] == SCOPE, "incomplete owner-priority report")
    require(all(report[key] is False for key in ("full_b01_claimed", "battery_thermal_activity_claimed", "full_alpha_claimed")),
            "unsupported owner-priority claim")
    TRAIN["check_bundle"](path.parent / "agent-training-smoke.json", revision)
    require(read(path.parent / "agent-training-smoke.json") == report["training"]
            and read(path.parent / f"{NAME}-pressure.json") == report["pressure"], "raw owner-priority evidence differs")
    require(report["cleanup"] == report["training"]["cleanup"] and report["host_state"] == report["training"]["host_state"]
            and report["pressure"]["worker"] == report["training"]["isolation"]["worker"]
            and report["pressure"]["cli"] == report["training"]["isolation"]["cli"], "job or cleanup lineage differs")
    check_owner(report["pressure"], report["training"]["worker"])


def self_test():
    proof = dict(success=True, contenders_reaped=True, remaining_pressure_processes=0, guest_cpu_set=[0],
        pressure_processes=[dict(pid=1, start_ticks=1), dict(pid=2, start_ticks=1)], worker=dict(pid=3, start_ticks=1),
        cli=dict(pid=4, start_ticks=1), cpu_samples=[dict(avg10=25), dict(avg10=0)], contender_deadline_seconds=45,
        maximum_observation_seconds=110, clock_ticks_per_second=100,
        paused_ack=dict(phase="paused", sequence=2, step=1, elapsed_ms=100),
        resumed_ack=dict(phase="resumed", sequence=3, step=1, elapsed_ms=5100),
        before_pressure=dict(boottime_ns=1), paused_before=dict(boottime_ns=2, cpu_ticks=100),
        paused_after=dict(boottime_ns=1_600_000_002, cpu_ticks=102),
        contenders_stopped_boottime_ns=1_600_000_003, resumed_after=dict(boottime_ns=7_000_000_000, cpu_ticks=103))
    worker = dict(elapsed_ms=10000, owner_control=dict(enabled=True, records_received=3, last_sequence=3,
        pause_count=1, resume_count=2, paused_ms=5000), supervisor=dict(spare_capacity=True, pause_extends_deadline=False,
        pressure_action="cooperative-pause-resume-memory-cancel", deadline_seconds=600))
    check_owner(proof, worker)
    for key, field, value in (("resumed_ack", "step", 2), ("paused_after", "cpu_ticks", 150),
                              ("resumed_after", "cpu_ticks", 102), ("resumed_ack", "sequence", 5)):
        bad = copy.deepcopy(proof)
        bad[key][field] = value
        try:
            check_owner(bad, worker)
        except ValueError:
            continue
        raise AssertionError("invalid owner pause proof accepted")
    bad = copy.deepcopy(worker)
    bad["supervisor"]["pause_extends_deadline"] = True
    try:
        check_owner(proof, bad)
    except ValueError:
        pass
    else:
        raise AssertionError("deadline extension accepted")
    print("owner-priority checker positive + five rejections PASS; no pressure/model/network executed")


def main(args):
    if args == ["self-test"]:
        self_test()
    elif len(args) == 3 and args[0] == "spin":
        spin(int(args[1]), int(args[2]))
    elif len(args) == 2 and args[0] == "pressure":
        return exercise_pressure(Path(args[1]))
    elif len(args) == 3 and args[0] == "execute":
        return execute(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "report":
        check_report(Path(args[1]), args[2])
        print("actual isolated owner-priority pause/resume proof PASS")
    elif len(args) == 4 and args[0] == "failure":
        write(Path(args[1]) / f"{NAME}-smoke.json", dict(report_kind="volparossa-agent-owner-priority",
              source_revision=args[2], scope=SCOPE, success=False, observed_blocker="stopped-before-proof", phase=args[3]))
    else:
        raise ValueError("unsupported owner-priority fixture operation")
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main(sys.argv[1:]))
