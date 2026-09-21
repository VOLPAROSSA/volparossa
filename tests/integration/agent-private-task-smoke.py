#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable local-private Q/A; all exported answer text is authorized synthetic test data."""

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / "agent-training-smoke.py"))
read, write, require = TRAIN["read"], TRAIN["write"], TRAIN["require"]
NAME = "agent-private-task"
PROFILE = TRAIN["LARGE_MODEL_PROFILE"]
MODEL = TRAIN["inference_profile"](PROFILE)
CLI = "/home/vpci/target/debug/volparossa"
SCOPE = ("one actual local-private synthetic Q/A with observed isolated readonly input/model mounts, "
         "owner controls, EOS and owned temporary cleanup; not confidential remote execution, "
         "a portable signed receipt, general answer quality or completed B04")
ACK = re.compile(rb"compute owner_ack phase=(paused|resumed) sequence=([1-9][0-9]*) step=([0-9]+) elapsed_ms=([0-9]+)")


def identity(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            "input must be an owned private regular file")
    return dict(dev=info.st_dev, inode=info.st_ino, uid=info.st_uid, mode=0o600,
                **TRAIN["file_hash"](path, 65536))


def check_snapshot(value):
    original, snapshot = value["original"], value["snapshot"]
    require(original["uid"] == snapshot["uid"] > 0 and original["mode"] == snapshot["mode"] == 0o600
            and original["bytes"] == snapshot["bytes"] and original["sha256"] == snapshot["sha256"]
            and re.fullmatch(r"[0-9a-f]{64}", original["sha256"])
            and 0 < original["bytes"] <= 65536
            and (original["dev"], original["inode"]) != (snapshot["dev"], snapshot["inode"])
            and value["work_parent_mode"] == value["ephemeral_mode"] == 0o700,
            "private input was not independently snapshotted with exact bytes and permissions")


def observe(pid, output, provision, original, work_parent):
    TRAIN["guest_guard"](root=True)
    owner = TRAIN["identity"](pid)
    initial = identity(original)
    require(Path(f"/proc/{pid}").stat().st_uid == initial["uid"] == output.stat().st_uid != 0,
            "private observer owner mismatch")
    snapshot = None
    for _ in range(100):
        require(TRAIN["identity"](pid) == owner, "private CLI disappeared before observation")
        children = list(work_parent.iterdir())
        require(len(children) <= 1, "unexpected private work-parent contents")
        if children:
            directory = children[0]
            require(directory.name.startswith("private-task-") and not directory.is_symlink()
                    and directory.is_dir(), "wrong ephemeral private directory")
            candidate = directory / "input.json"
            if candidate.is_file():
                snapshot = candidate
                break
        time.sleep(0.1)
    require(snapshot is not None, "private input snapshot was not observed")
    evidence = dict(original=initial, snapshot=identity(snapshot),
                    work_parent_mode=stat.S_IMODE(work_parent.stat().st_mode),
                    ephemeral_mode=stat.S_IMODE(snapshot.parent.stat().st_mode))
    check_snapshot(evidence)
    # The existing observer compares actual /proc/worker/root/dataset.json with this
    # new snapshot inode, not merely with a copied hash or the owner's original file.
    TRAIN["observe"](pid, output / f"{NAME}-isolation.json", provision, snapshot, original)
    require(identity(original) == initial and identity(snapshot) == evidence["snapshot"],
            "observed private input changed")
    target = output / f"{NAME}-snapshot.json"
    write(target, evidence)
    info = original.stat()
    os.chown(target, info.st_uid, info.st_gid)


def owner_controls(raw):
    require(len(raw) <= 65536, "unbounded private diagnostic stream")
    acks, phases = [], []
    for line in raw.splitlines():
        match = ACK.fullmatch(line)
        if match:
            acks.append(dict(phase=match[1].decode(), sequence=int(match[2]), step=int(match[3]),
                             elapsed_ms=int(match[4])))
        elif line in (b"compute phase=preparing", b"compute phase=baseline", b"compute phase=complete",
                      b"compute phase=paused", b"compute phase=resumed"):
            phases.append(line.removeprefix(b"compute phase=").decode())
    require(1 <= len(acks) <= 256 and any(x["phase"] == "resumed" for x in acks)
            and "preparing" in phases and "baseline" in phases and "complete" in phases,
            "actual owner ACK and private inference phases missing")
    require(all(0 <= x["step"] <= 1 and 0 <= x["elapsed_ms"] < 600000 for x in acks)
            and all(a["sequence"] < b["sequence"] for a, b in zip(acks, acks[1:])),
            "invalid actual owner ACK sequence")
    return dict(acks=acks, phases=phases, original_max_seconds=600, threads=2,
                pressure_injected=False, all_owner_activity_claimed=False)


def at_stdout(work_parent, original, expected, isolation):
    require(not list(work_parent.iterdir()), "private temporary input/report still present at stdout")
    require(identity(original) == expected, "original private input changed")
    require(not any(TRAIN["alive"](p) for p in isolation["owned_processes"] if p != isolation["cli"]),
            "actual private worker still alive at stdout")
    return dict(observation_point="first_stdout_read", ephemeral_children=0,
                original=identity(original), observed_worker_lifetimes_ended=True)


def answer(process, deadline, work_parent, original, expected, isolation):
    raw, observed = bytearray(), None
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "private original fixture deadline elapsed")
        require(select.select([process.stdout], [], [], remaining)[0], "private stdout deadline elapsed")
        block = os.read(process.stdout.fileno(), 8192)
        if not block:
            break
        if observed is None:
            observed = at_stdout(work_parent, original, expected, isolation)
        raw.extend(block)
        require(len(raw) <= 65536, "private result exceeds fixture bound")
    code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    require(observed is not None, "private CLI emitted no answer")
    return json.loads(raw), observed, code


def check_answer(value, canary):
    require(value["version"] == 1 and value["operation"] == "compute_private_task"
            and value["model_profile"] == PROFILE and value["answer_status"] == "eos"
            and all(value[k] is True for k in ("execution_complete", "answer_complete", "complete", "local_only", "private_data_supported"))
            and all(value[k] is False for k in ("distributed_execution_claimed", "private_training_claimed",
                                               "semantic_completeness_proven", "model_answer_correctness_proven"))
            and value["cleanup"] == dict(complete=True, retained_input=False, retained_report=False),
            "private answer completion or scope differs")
    out = value["output"]
    TRAIN["check_generation"](out, require_eos=True, model_profile=PROFILE)
    require(out["sample_index"] == 0 and out["text_truncated"] is False
            and isinstance(out["text"], str) and 0 < len(out["text"].encode()) <= MODEL["wire_bytes"]
            and re.fullmatch(r"CANARY[0-9]{8}", canary) and canary in out["text"],
            "actual EOS answer did not reproduce the generated synthetic test identifier")


def check_provision(value):
    pins = read(TRAIN["ML"] / "model-pins.json")
    pins.update(read(TRAIN["ML"] / "model-pins-360m.json"))
    require(value["success"] is True and value["model_profile"] == PROFILE
            and value["model_id"] == MODEL["model"]["model_id"] and value["revision"] == MODEL["model"]["model_revision"]
            and value["installed_wheels"] == len(pins["wheels"]) == 38
            and value["download_bytes"] == sum(x["bytes"] for k in ("files", "wheels") for x in pins[k])
            and value["budget_bytes"] == 3 * 1024**3 and value["training_performed"] is False
            and value["runtime_autofetch_enabled"] is False
            and value["model_pins_sha256"] == hashlib.sha256((json.dumps(pins, indent=2) + "\n").encode()).hexdigest(),
            "private fixture provision is not the exact pinned CPU profile")


def check_report(value, revision):
    require(value["report_kind"] == "volparossa-agent-private-task" and value["source_revision"] == revision
            and value["scope"] == SCOPE and value["success"] is True
            and value["full_b04_claimed"] is False and value["confidential_remote_execution_claimed"] is False
            and value["exported_answer_is_authorized_synthetic_test_data"] is True
            and value["raw_private_input_exported"] is False and value["raw_worker_report_exported"] is False,
            "private fixture scope or completion differs")
    check_provision(value["provision"])
    TRAIN["check_isolation"](value["isolation"])
    check_snapshot(value["snapshot"])
    check_answer(value["answer"], value["test_canary"])
    require(value["on_disk_model_before"] == value["on_disk_model_after"] == MODEL["model"]["base_weights"],
            "actual pinned model changed")
    require(value["public_rejection"] == dict(error="compute_public_data_required", exit_nonzero=True,
            stdout_empty=True, output_absent=True, runtime_lease_absent=True), "private input reached public execution")
    require(value["stdout_boundary"] == dict(observation_point="first_stdout_read", ephemeral_children=0,
            original=value["snapshot"]["original"], observed_worker_lifetimes_ended=True)
            and value["original_after"] == value["snapshot"]["original"] and value["runtime_lock_released"] is True,
            "private snapshot lifetime or original input preservation differs")
    controls = value["owner_controls"]
    reconstructed = b"\n".join(
        [f"compute owner_ack phase={a['phase']} sequence={a['sequence']} step={a['step']} elapsed_ms={a['elapsed_ms']}".encode()
         for a in controls["acks"]] + [f"compute phase={p}".encode() for p in controls["phases"]])
    require(owner_controls(reconstructed) == controls, "owner control proof differs")
    require(value["cleanup"] == dict(complete=True, remaining_owned_objects=0,
            guest_model_and_job_roots_removed=True, observed_worker_lifetimes_ended=True, fallback_signals_used=False)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"],
            "private fixture cleanup or guest network baseline differs")


def check_bundle(path, revision):
    value = read(path, 1048576)
    check_report(value, revision)
    for field in ("provision", "isolation", "snapshot", "answer", "owner_controls", "stdout_boundary"):
        require(read(path.parent / f"{NAME}-{field}.json") == value[field], "original private fixture evidence differs")
    for when in ("before", "after"):
        require(TRAIN["file_hash"](path.parent / f"host-state-{when}.json", 1048576)["sha256"]
                == value["host_state"][f"{when}_sha256"], "original guest state differs")


def execute(output, revision):
    TRAIN["guest_guard"]()
    require(output == Path("/home/vpci/alpha-output") and re.fullmatch(r"[0-9a-f]{40}", revision), "wrong exact guest run")
    provision, jobs = Path("/home/vpci/private-ml-provision"), Path("/home/vpci/private-ml-jobs")
    require(not any(p.exists() or p.is_symlink() for p in (provision, jobs)), "private fixture roots already exist")
    jobs.mkdir(mode=0o700)
    work_parent = jobs / "work"
    work_parent.mkdir(mode=0o700)
    before = TRAIN["snapshot"]()
    write(output / "host-state-before.json", before)
    result = dict(report_kind="volparossa-agent-private-task", source_revision=revision, scope=SCOPE, success=False,
        full_b04_claimed=False, confidential_remote_execution_claimed=False,
        exported_answer_is_authorized_synthetic_test_data=True, raw_private_input_exported=False,
        raw_worker_report_exported=False, phase="provision")
    process, observer, members, fallback = None, None, [], False
    try:
        with (output / f"{NAME}-provision.log").open("w") as log:
            subprocess.run([sys.executable, "-B", str(TRAIN["ML"] / "provision.py"), "--execute", "--yes",
                "--disposable-guest", "--model-profile", PROFILE, "--root", str(provision),
                "--budget-bytes", str(3 * 1024**3)], stdout=log, stderr=subprocess.STDOUT, timeout=1850, check=True)
        result["provision"] = read(provision / "provision-report.json")
        write(output / f"{NAME}-provision.json", result["provision"])
        check_provision(result["provision"])
        canary = "CANARY" + str(int.from_bytes(os.urandom(4)) % 100000000).zfill(8)
        result["test_canary"] = canary
        original = jobs / "private-input.json"
        write(original, dict(version=1, visibility="private_local",
            question="What is the test identifier in the note? Answer with only the identifier.",
            context=f"Synthetic private test note: The test identifier is {canary}. This note contains no real secrets."))
        initial = identity(original)
        model_file = provision / "model/model.safetensors"
        result["on_disk_model_before"] = TRAIN["file_hash"](model_file, MODEL["model"]["base_weights"]["bytes"])
        result["phase"] = "public-input-rejection"
        rejected = jobs / "public-rejected"
        lock = provision / "venv/.volparossa-compute.lock"
        require(not lock.exists(), "runtime already used before private fixture")
        common = ["--runtime-root", str(provision / "venv"), "--model-root", str(provision / "model"),
                  "--model-profile", PROFILE, "--threads", "2", "--max-seconds", "600", "--execute"]
        denial = subprocess.run([CLI, "compute", "run", "--mode", "infer", "--dataset", str(original),
                                "--output", str(rejected), "--steps", "1", *common], capture_output=True, timeout=10)
        require(denial.returncode != 0 and denial.stdout == b"" and denial.stderr.strip() == b"Error: compute_public_data_required"
                and not rejected.exists() and not lock.exists(), "private input not rejected before public runtime admission")
        result["public_rejection"] = dict(error="compute_public_data_required", exit_nonzero=True,
            stdout_empty=True, output_absent=True, runtime_lease_absent=True)
        result["phase"] = "private-infer-and-observe"
        with (jobs / "private.stderr").open("wb") as diagnostics:
            deadline = time.monotonic() + 610
            process = subprocess.Popen([CLI, "compute", "private-task", "--input", str(original),
                "--work-parent", str(work_parent), *common], stdout=subprocess.PIPE, stderr=diagnostics)
            with (jobs / "observer.stderr").open("wb") as observer_diagnostics:
                observer = subprocess.Popen(["sudo", "-n", sys.executable, "-B", str(Path(__file__).resolve()),
                    "observe", str(process.pid), str(output), str(provision), str(original), str(work_parent)],
                    stdout=subprocess.DEVNULL, stderr=observer_diagnostics)
                require(observer.wait(timeout=70) == 0, "actual private worker isolation observation failed")
            result["isolation"] = read(output / f"{NAME}-isolation.json")
            result["snapshot"] = read(output / f"{NAME}-snapshot.json")
            members = result["isolation"]["owned_processes"]
            result["answer"], result["stdout_boundary"], code = answer(
                process, deadline, work_parent, original, initial, result["isolation"])
            # Preserve an actual incomplete answer honestly for diagnosis, not as PASS.
            write(output / f"{NAME}-answer.json", result["answer"])
            write(output / f"{NAME}-stdout_boundary.json", result["stdout_boundary"])
            require(code == 0, "actual private inference did not complete")
        result["owner_controls"] = owner_controls((jobs / "private.stderr").read_bytes())
        write(output / f"{NAME}-owner_controls.json", result["owner_controls"])
        check_answer(result["answer"], canary)
        result["original_after"] = identity(original)
        require(result["original_after"] == initial, "private original changed after answer")
        with lock.open("rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(stream, fcntl.LOCK_UN)
        result["runtime_lock_released"] = True
        result["on_disk_model_after"] = TRAIN["file_hash"](model_file, MODEL["model"]["base_weights"]["bytes"])
        result["phase"] = "cleanup"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # No parser text, private context, report fragments or private filenames in evidence.
        result["observed_blocker"] = type(error).__name__
    finally:
        if process is not None and process.poll() is None:
            members += TRAIN["descendants"](process.pid)
        for child in (process, observer):
            if child is not None and child.poll() is None:
                fallback = True
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
        isolated = output / f"{NAME}-isolation.json"
        if isolated.is_file():
            members += read(isolated).get("owned_processes", [])
        remaining = sum(TRAIN["alive"](member) for member in members)
        if remaining == 0:
            # Only exact newly-created guest roots; never remove files beneath a live worker.
            for owned in (provision, jobs):
                if owned.exists():
                    info = owned.lstat()
                    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "private cleanup root changed")
                    shutil.rmtree(owned)
        remaining += sum(p.exists() for p in (provision, jobs))
        result["cleanup"] = dict(complete=remaining == 0, remaining_owned_objects=remaining,
            guest_model_and_job_roots_removed=not provision.exists() and not jobs.exists(),
            observed_worker_lifetimes_ended=not any(TRAIN["alive"](p) for p in members), fallback_signals_used=fallback)
        after = TRAIN["snapshot"]()
        write(output / "host-state-after.json", after)
        result["host_state"] = dict(unchanged=before == after,
            before_sha256=TRAIN["file_hash"](output / "host-state-before.json", 1048576)["sha256"],
            after_sha256=TRAIN["file_hash"](output / "host-state-after.json", 1048576)["sha256"])
        result["success"] = "observed_blocker" not in result and remaining == 0 and not fallback and before == after
        if result["success"]:
            try:
                check_report(result, revision)
                result["phase"] = "complete"
            except (ValueError, KeyError, TypeError):
                result["success"] = False
                result["observed_blocker"] = "PROOF_BINDING_FAILED"
        write(output / f"{NAME}-smoke.json", result)
    return 0 if result["success"] else 1


def self_test():
    canary = "CANARY12345678"
    value = dict(version=1, operation="compute_private_task", model_profile=PROFILE,
        execution_complete=True, answer_complete=True, complete=True, answer_status="eos", local_only=True,
        private_data_supported=True, distributed_execution_claimed=False, private_training_claimed=False,
        semantic_completeness_proven=False, model_answer_correctness_proven=False,
        cleanup=dict(complete=True, retained_input=False, retained_report=False),
        output=dict(sample_index=0, text=canary, generated_tokens=8, text_truncated=False,
                    generation=dict(version=1, stop_reason="eos", max_new_tokens=256, model_profile=PROFILE)))
    check_answer(value, canary)
    for field, replacement in (("text", "unrelated"), ("text_truncated", True),
                               ("generation", dict(version=1, stop_reason="token_limit", max_new_tokens=256, model_profile=PROFILE))):
        wrong = copy.deepcopy(value)
        wrong["output"][field] = replacement
        try:
            check_answer(wrong, canary)
        except ValueError:
            pass
        else:
            raise ValueError("incomplete/private-unbound answer accepted")
    owner_controls(b"compute owner_ack phase=resumed sequence=1 step=0 elapsed_ms=0\n"
                   b"compute phase=preparing\ncompute phase=baseline\ncompute phase=complete\n")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        original, snapshot = root / "original", root / "snapshot"
        write(original, {"inert": "synthetic"})
        write(snapshot, {"inert": "synthetic"})
        proof = dict(original=identity(original), snapshot=identity(snapshot), work_parent_mode=0o700, ephemeral_mode=0o700)
        # Pure test must also be runnable by a root build account, without root runtime execution.
        proof["original"]["uid"] = proof["snapshot"]["uid"] = 1000
        check_snapshot(proof)
        for key, replacement in (("inode", proof["original"]["inode"]), ("sha256", "0" * 64), ("mode", 0o644)):
            wrong = copy.deepcopy(proof)
            wrong["snapshot"][key] = replacement
            try:
                check_snapshot(wrong)
            except ValueError:
                pass
            else:
                raise ValueError("wrong private snapshot accepted")
        work = root / "work"
        work.mkdir(mode=0o700)
        expected = identity(original)
        isolated = {"owned_processes": [], "cli": {"pid": 0}}
        at_stdout(work, original, expected, isolated)
        (work / "retained-input").mkdir(mode=0o700)
        try:
            at_stdout(work, original, expected, isolated)
        except ValueError:
            pass
        else:
            raise ValueError("retained private input accepted at stdout")
    print("private-task pure snapshot/EOS/canary/cleanup controls PASS; no model executed")


def main():
    if sys.argv[1:] == ["self-test"]:
        self_test()
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "execute":
        def interrupted(_signal, _frame):
            raise InterruptedError("private fixture interrupted")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
        return execute(Path(sys.argv[2]), sys.argv[3])
    if len(sys.argv) == 7 and sys.argv[1] == "observe":
        observe(int(sys.argv[2]), *(Path(x) for x in sys.argv[3:]))
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "report":
        check_bundle(Path(sys.argv[2]), sys.argv[3])
        print("actual local-private synthetic Q/A report PASS; no confidential remote claim")
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "failure":
        write(Path(sys.argv[2]) / f"{NAME}-smoke.json", dict(report_kind="volparossa-agent-private-task",
            source_revision=sys.argv[3], success=False, scope=SCOPE, phase=sys.argv[4],
            observed_blocker="GUEST_PHASE_INCOMPLETE", full_b04_claimed=False,
            confidential_remote_execution_claimed=False))
        return 1
    raise ValueError("usage: self-test | execute OUTPUT SHA | report REPORT SHA | observe PID OUTPUT PROVISION INPUT WORK")


if __name__ == "__main__":
    raise SystemExit(main())
