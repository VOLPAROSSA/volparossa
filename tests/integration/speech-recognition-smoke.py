#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the normal Core CLI on the two authorized synthetic guest recordings."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
MODEL_SHA = "7ebd0e69e78190ffe1438491fa05cc1f5c1aa3a4c4db3bc1723adbb551ea2395"


def require(ok):
    if not ok:
        raise ValueError("speech trial boundary failed")


def python_worker(root_pid):
    pending, seen = [root_pid], set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        require(len(seen) <= 64)
        proc = Path("/proc", str(pid))
        try:
            with (proc / "cmdline").open("rb") as stream:
                if stream.read(32).startswith(b"/runtime/bin/python3\0-I\0-c\0"):
                    return pid
            for thread in (proc / "task").iterdir():
                pending.extend(int(n) for n in (thread / "children").read_text().split())
        except (FileNotFoundError, ProcessLookupError):
            pass
    return None


def cancelled(command, scratch):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        descriptor = None
        try:
            deadline = time.monotonic() + 30
            while child.poll() is None and time.monotonic() < deadline:
                pid = python_worker(child.pid)
                if pid:
                    descriptor = os.pidfd_open(pid)
                    break
                time.sleep(0.025)
            require(descriptor is not None)
            child.send_signal(signal.SIGINT)
            stdout, stderr = child.communicate(timeout=10)
            require(child.returncode != 0 and not stdout and b"compute_owner_cancelled" in stderr)
            wait = select.poll()
            wait.register(descriptor, select.POLLIN)
            require(bool(wait.poll(0)) and not any(scratch.iterdir()))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)


def execute(root, output, revision):
    require(os.geteuid() != 0 and Path.cwd() == Path("/home/vpci/source")
            and subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() == "kvm")
    command = ["/home/vpci/target/debug/volparossa", "compute", "transcribe",
               "--runtime-root", root / "runtime/venv", "--model-root", root / "runtime/model",
               "--work-parent", root / "work", "--language", "en", "--execute", "--input"]
    fixture = [sys.executable, "-B", str(HERE / "speech-recognition-fixture.py")]
    scratch, recordings = root / "work", root / "recordings"
    scratch.mkdir(mode=0o700)
    subprocess.run([*fixture, "prepare", recordings], timeout=40, check=True)
    receipt = {"version": 1, "source_revision": revision, "model_sha256": MODEL_SHA,
               "scope": "synthetic_english_speech", "passed": False, "phase": "recognition"}
    try:
        for name in ("bicycle", "station"):
            result = subprocess.run([*command, recordings / (name + ".wav")],
                                    stdout=subprocess.PIPE, check=True, timeout=150)
            response = json.loads(result.stdout)
            require(response["max_observed_rss_bytes"] > 0 and response["elapsed_ms"] > 0 and not any(scratch.iterdir()))
            (recordings / (name + ".result.json")).write_bytes(result.stdout)
            (output / ("speech-" + name + ".json")).write_bytes(result.stdout)
        receipt["phase"] = "score"
        score = subprocess.run([*fixture, "score", recordings], stdout=subprocess.PIPE, timeout=15)
        receipt["score"] = json.loads(score.stdout)
        require(score.returncode == 0 and receipt["score"]["passed"])
        receipt["phase"] = "cancellation"
        cancelled([*command, recordings / "bicycle.wav"], scratch)
        receipt.update(passed=True, phase="complete", live_worker_cancelled_and_joined=True)
    finally:
        (output / "speech-recognition-smoke.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")


if __name__ == "__main__":
    execute(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
