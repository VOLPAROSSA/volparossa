#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the normal Core CLI on the two authorized synthetic guest recordings."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import signal
import subprocess
import sys
import time
import wave

HERE = Path(__file__).resolve().parent
MODEL_SHA = "1d7734884874f1a1513ed9aa760a4f8e97aaa02fd6d93a3a85d27b2ae9ca596b"


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


def cancelled(command, scratch, owner_signal):
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
            child.send_signal(owner_signal)
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
    lifecycle = runpy.run_path(str(HERE / "agent-private-conversation.py"))["service_diagnostic"]
    scratch, recordings = root / "work", root / "recordings"
    scratch.mkdir(mode=0o700)
    subprocess.run([*fixture, "prepare", recordings], timeout=40, check=True)
    (output / "speech-reference.json").write_bytes((recordings / "reference.json").read_bytes())
    synthesized = runpy.run_path(str(HERE / "speech-synthesis-smoke.py"))["generate"](root, recordings, output, revision)
    receipt = {"version": 1, "source_revision": revision, "model_sha256": MODEL_SHA,
               "scope": "synthetic_english_speech", "passed": False, "phase": "recognition"}
    try:
        for name in ("bicycle", "station"):
            # The ordinary CLI debug subscriber uses stdout. Keep the full stream private in
            # this synthetic guest and export only the shared closed lifecycle projection.
            trace = recordings / (name + ".log")
            marked_input = synthesized / (name + ".wav")
            input_digest = hashlib.sha256(marked_input.read_bytes()).hexdigest()
            with trace.open("xb") as log:
                result = subprocess.run([*command, marked_input], stdout=log,
                                        env=dict(os.environ, NO_COLOR="1",
                                                 RUST_LOG="off,volparossa::compute::private_diagnostic=debug"),
                                        timeout=150)
            receipt["lifecycle"] = lifecycle(trace)
            if result.returncode:
                raise ValueError("speech worker did not complete")
            lines = trace.read_bytes().splitlines()
            require(len(lines) <= 32 and bool(lines) and len(lines[-1]) <= 16384)
            response = json.loads(lines[-1])
            require(response["max_observed_rss_bytes"] > 0 and response["elapsed_ms"] > 0 and not any(scratch.iterdir()))
            (recordings / (name + ".result.json")).write_bytes(lines[-1] + b"\n")
            original = lines[-1] + b"\n"
            (output / ("speech-" + name + ".json")).write_bytes(original)
            require(hashlib.sha256(marked_input.read_bytes()).hexdigest() == input_digest)
            receipt.setdefault("recognizer_inputs", {})[name] = {
                "marked_wav_sha256": input_digest, "result_file_sha256": hashlib.sha256(original).hexdigest()}
        receipt["phase"] = "score"
        score = subprocess.run([*fixture, "score", recordings], stdout=subprocess.PIPE, timeout=15)
        receipt["score"] = json.loads(score.stdout)
        require(score.returncode in (0, 1) and "clips" in receipt["score"])
        receipt["phase"] = "cancellation"
        for owner_signal in (signal.SIGINT, signal.SIGTERM):
            cancelled([*command, recordings / "bicycle.wav"], scratch, owner_signal)
        receipt.update(live_worker_cancelled_and_joined=True, signals=["SIGINT", "SIGTERM"])
        receipt["phase"] = "silence"
        quiet = recordings / "silence.wav"
        with wave.open(str(quiet), "wb") as stream:
            stream.setparams((1, 2, 16000, 1600, "NONE", "not compressed"))
            stream.writeframes(bytes(1600 * 2))
        denied = subprocess.run([*command, quiet], capture_output=True, timeout=15)
        require(denied.returncode != 0 and not denied.stdout and b"compute_speech_no_signal" in denied.stderr
                and not any(scratch.iterdir()))
        receipt.update(digital_silence_refused=True)
        receipt["phase"] = "acceptance"
        require(score.returncode == 0 and receipt["score"]["passed"])
        receipt.update(passed=True, phase="complete")
    finally:
        (output / "speech-recognition-smoke.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")


if __name__ == "__main__":
    execute(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
