#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Guest-only manual owner cancellation during real training, never completion proof."""

import copy
import fcntl
import hashlib
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
NAME = "agent-owner-cancel"
SCOPE = ("manual owner-UID SIGINT to the exact live CLI during real pinned-model training, "
         "CLI reaping and all observed owned descendants ended within five seconds, unchanged on-disk base "
         "and private guest cleanup; not completed training, physical battery/thermal awareness, all owner activity or full B01")
LIMIT_NS = 5_000_000_000


def file_record(path, maximum=262144):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum, "invalid bounded raw cancellation file")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "raw cancellation file changed while reading")
    return raw, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def exit_ready(descriptor):
    poller = select.poll()
    poller.register(descriptor, select.POLLIN)
    return bool(poller.poll(0))


def open_identity(member):
    require(TRAIN["identity"](member["pid"]) == member, "owned process identity changed before pidfd")
    descriptor = os.pidfd_open(member["pid"])
    try:
        require(TRAIN["identity"](member["pid"]) == member and not exit_ready(descriptor), "pidfd does not name the original live process")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def observed_family(isolation):
    cli, worker = isolation["cli"], isolation["worker"]
    # The observer's bounded family includes its starting CLI, not just children.
    members = isolation["owned_processes"]
    require(cli in members and worker in members and cli != worker and 2 <= len(members) <= 32
            and len({(m["pid"], m["start_ticks"]) for m in members}) == len(members), "wrong observed process family")
    return members


def cancel(process, isolation, output):
    TRAIN["guest_guard"]()
    cli, worker = isolation["cli"], isolation["worker"]
    owner = os.geteuid()
    require(process.pid == cli["pid"] and owner != 0 and Path(f"/proc/{process.pid}").stat().st_uid == owner,
            "manual signal must originate from the same unprivileged CLI owner")
    members = observed_family(isolation)
    descriptors, proof = [], None
    try:
        # Other observed startup helpers may already have exited normally. Keep
        # their identities for final cleanup, but bind live pidfds specifically
        # to the original CLI and actual model worker being cancelled.
        for member in (cli, worker):
            descriptors.append(open_identity(member))
        started = time.monotonic_ns()
        while True:
            raw, _ = file_record(output / f"{NAME}-worker.stderr")
            if b"compute phase=training" in raw.splitlines():
                break
            require(process.poll() is None and time.monotonic_ns() - started < 580_000_000_000,
                    "actual model never entered training before cancellation")
            time.sleep(0.01)
        require(b"compute phase=complete" not in raw.splitlines() and not any(exit_ready(fd) for fd in descriptors),
                "model completed or a different process ended before manual cancellation")
        prefix_path = output / f"{NAME}-training-prefix.stderr"
        with prefix_path.open("xb") as stream:
            stream.write(raw)
        prefix_path.chmod(0o600)
        proof = {"cli": cli, "worker": worker, "observed_owned_processes": isolation["owned_processes"],
                 "owner_uid": owner, "cli_uid": Path(f"/proc/{process.pid}").stat().st_uid,
                 "signal": "SIGINT", "signal_number": signal.SIGINT, "signal_target": cli,
                 "pidfd_bound": True, "all_selected_pidfds_live_before_signal": True,
                 "training_prefix": file_record(prefix_path)[1], "original_deadline_seconds": 600,
                 "completed_training_claimed": False, "signal_sent": False}
        proof["signal_monotonic_ns"] = time.monotonic_ns()
        signal.pidfd_send_signal(descriptors[0], signal.SIGINT)
        proof["signal_sent"] = True
        # No process-group or model signal is sent here. Only the product's actual
        # supervisor may stop its own sandbox as a consequence of owner cancellation.
        deadline = proof["signal_monotonic_ns"] + LIMIT_NS
        code = process.wait(timeout=max(0.001, (deadline - time.monotonic_ns()) / 1e9))
        proof["cli_reaped_monotonic_ns"] = time.monotonic_ns()
        while not all(exit_ready(fd) for fd in descriptors) or any(TRAIN["alive"](m) for m in members):
            require(time.monotonic_ns() < deadline, "owner cancellation left an observed process after five seconds")
            time.sleep(0.005)
        proof.update(all_ended_monotonic_ns=time.monotonic_ns(), cli_exit_code=code, cli_reaped=True,
                     kernel_pidfds_exited=True, remaining_observed_processes=0, signal_sent_only_to_cli=True)
        check_signal(proof, isolation)
        return proof
    finally:
        if proof is not None:
            # Preserve an actual failed/partial signal attempt as well as success;
            # a timeout never becomes an invented complete cancellation record.
            write(output / f"{NAME}-signal.json", proof)
        for descriptor in descriptors:
            os.close(descriptor)


def check_signal(proof, isolation):
    observed_family(isolation)
    require(proof["cli"] == isolation["cli"] == proof["signal_target"] and proof["worker"] == isolation["worker"]
            and proof["observed_owned_processes"] == isolation["owned_processes"]
            and proof["worker"] in proof["observed_owned_processes"] and proof["cli"] != proof["worker"], "signal/process lineage differs")
    require(type(proof["owner_uid"]) is int and proof["owner_uid"] == proof["cli_uid"] > 0
            and proof["signal"] == "SIGINT" and proof["signal_number"] == 2 and proof["pidfd_bound"] is True
            and proof["signal_sent"] is True
            and proof["signal_sent_only_to_cli"] is True and proof["all_selected_pidfds_live_before_signal"] is True,
            "not an owner-only signal to the exact live CLI")
    require(proof["signal_monotonic_ns"] <= proof["cli_reaped_monotonic_ns"] <= proof["all_ended_monotonic_ns"]
            and 0 <= proof["all_ended_monotonic_ns"] - proof["signal_monotonic_ns"] <= LIMIT_NS
            and proof["cli_reaped"] is True and proof["kernel_pidfds_exited"] is True
            and proof["remaining_observed_processes"] == 0 and proof["cli_exit_code"] != 0,
            "owner cancellation exceeded its observed five-second cleanup budget")
    require(proof["original_deadline_seconds"] == 600 and proof["completed_training_claimed"] is False,
            "manual cancellation misrepresented as extended/completed training")


def output_state(job, runtime):
    files = []
    if job.exists():
        for number, path in enumerate(job.rglob("*")):
            require(number < 32 and not path.is_symlink(), "unbounded cancelled output tree")
            if path.is_file():
                relative = path.relative_to(job).as_posix()
                _, record = file_record(path, 16 * 1048576)
                files.append({"relative_path": relative, **record})
    require(not any(p["relative_path"] in ("report.json", "adapter/adapter_model.safetensors") for p in files),
            "cancelled job unexpectedly produced a completed report/checkpoint")
    lock = runtime / ".volparossa-compute.lock"
    info = lock.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(), "wrong retained runtime lock")
    with lock.open("rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(stream, fcntl.LOCK_UN)
    return {"output_files": files, "complete_checkpoint_present": False, "runtime_lock_released": True,
            "runtime_lock_inode": [info.st_dev, info.st_ino]}


def execute(output, revision):
    TRAIN["guest_guard"]()
    require(output == Path("/home/vpci/alpha-output") and re.fullmatch(r"[0-9a-f]{40}", revision), "wrong exact guest run")
    provision, jobs = Path("/home/vpci/ml-provision"), Path("/home/vpci/ml-jobs")
    require(not provision.exists() and not jobs.exists(), "owned guest model/job roots already exist")
    jobs.mkdir(mode=0o700)
    before = TRAIN["snapshot"]()
    write(output / "host-state-before.json", before)
    result = dict(report_kind="volparossa-agent-owner-cancel", source_revision=revision, scope=SCOPE, success=False,
        full_b01_claimed=False, physical_battery_thermal_claimed=False, all_owner_activity_claimed=False,
        full_alpha_claimed=False, completed_training_claimed=False, phase="provision")
    process, observer = None, None
    fallback_signals = False
    try:
        with (output / f"{NAME}-provision.log").open("w") as log:
            subprocess.run([sys.executable, "-B", str(TRAIN["ML"] / "provision.py"), "--execute", "--yes",
                "--disposable-guest", "--root", str(provision), "--budget-bytes", str(3 * 1024**3)],
                stdout=log, stderr=subprocess.STDOUT, timeout=1850, check=True)
        result["provision"] = read(provision / "provision-report.json")
        write(output / f"{NAME}-provision.json", result["provision"])
        dataset = jobs / "public-dataset.json"
        write(dataset, TRAIN["public_dataset"](revision))
        shutil.copyfile(dataset, output / f"{NAME}-public-dataset.json")
        canary = jobs / "outside-private-canary"
        with canary.open("x") as stream:
            stream.write("Public disposable isolation fixture, not a real private key.\n")
        canary.chmod(0o600)
        model = provision / "model/model.safetensors"
        result["on_disk_model_before"] = TRAIN["file_hash"](model, 269060552)
        result["phase"] = "observe-real-training"
        job = jobs / "train"
        with (output / f"{NAME}-worker.stdout").open("w") as stdout, (output / f"{NAME}-worker.stderr").open("w") as stderr:
            process = subprocess.Popen(["/home/vpci/target/debug/volparossa", "compute", "run", "--mode", "train",
                "--runtime-root", str(provision / "venv"), "--model-root", str(provision / "model"),
                "--dataset", str(dataset), "--output", str(job), "--steps", "64", "--threads", "2",
                "--max-seconds", "600", "--execute"], stdout=stdout, stderr=stderr)
            with (output / f"{NAME}-observer.stderr").open("w") as diagnostics:
                observer = subprocess.Popen(["sudo", "-n", sys.executable, "-B", str(HERE / "agent-training-smoke.py"),
                    "observe", str(process.pid), str(output / f"{NAME}-isolation.json"), str(provision), str(dataset), str(canary)],
                    stdout=subprocess.DEVNULL, stderr=diagnostics)
                require(observer.wait(timeout=70) == 0, "actual model isolation was not observed")
            isolation = read(output / f"{NAME}-isolation.json")
            TRAIN["check_isolation"](isolation)
            result["isolation"] = isolation
            result["phase"] = "owner-signal-and-reap"
            result["signal"] = cancel(process, isolation, output)
        stdout, stdout_hash = file_record(output / f"{NAME}-worker.stdout")
        stderr, stderr_hash = file_record(output / f"{NAME}-worker.stderr")
        require(not stdout.strip() and b"Error: compute_owner_busy" in stderr.splitlines(), "not the actual expected owner-cancellation error")
        result["state"] = {**output_state(job, provision / "venv"), "stdout": stdout_hash, "stderr": stderr_hash,
                           "expected_error": "compute_owner_busy", "dataset": TRAIN["file_hash"](dataset, 1048576)}
        result["on_disk_model_after"] = TRAIN["file_hash"](model, 269060552)
        write(output / f"{NAME}-state.json", result["state"])
        result["phase"] = "cleanup"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result["observed_blocker"] = str(error)[:512]
    finally:
        for child in (observer, process):
            if child is not None and child.poll() is None:
                fallback_signals = True
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        isolated = output / f"{NAME}-isolation.json"
        members = read(isolated).get("owned_processes", []) if isolated.is_file() else []
        remaining = sum(TRAIN["alive"](member) for member in members)
        # Delete only these exact, newly created roots; leave them for VM teardown
        # if an observed process is still live rather than touching active files.
        if remaining == 0:
            for owned in (provision, jobs):
                if owned.exists():
                    info = owned.lstat()
                    require(stat.S_ISDIR(info.st_mode) and not owned.is_symlink() and info.st_uid == os.getuid(), "owned cleanup root changed")
                    shutil.rmtree(owned)
        remaining += sum(path.exists() for path in (provision, jobs))
        result["cleanup"] = dict(complete=remaining == 0, remaining_owned_objects=remaining,
            guest_model_and_job_roots_removed=not provision.exists() and not jobs.exists(),
            observed_worker_lifetimes_ended=not any(TRAIN["alive"](m) for m in members), fallback_signals_used=fallback_signals)
        after = TRAIN["snapshot"]()
        write(output / "host-state-after.json", after)
        result["host_state"] = dict(unchanged=before == after,
            before_sha256=TRAIN["file_hash"](output / "host-state-before.json", 1048576)["sha256"],
            after_sha256=TRAIN["file_hash"](output / "host-state-after.json", 1048576)["sha256"])
        result["success"] = "observed_blocker" not in result and remaining == 0 and not fallback_signals and before == after
        if result["success"]:
            try:
                check_report(result, revision)
                result["phase"] = "complete"
            except (ValueError, KeyError, TypeError) as error:
                result["success"] = False
                result["observed_blocker"] = str(error)[:512]
        write(output / f"{NAME}-smoke.json", result)
    return 0 if result["success"] else 1


def check_report(value, revision):
    require(value["report_kind"] == "volparossa-agent-owner-cancel" and value["source_revision"] == revision
            and value["scope"] == SCOPE and value["success"] is True, "incomplete source-bound manual cancellation")
    require(all(value[k] is False for k in ("full_b01_claimed", "physical_battery_thermal_claimed", "all_owner_activity_claimed",
                                          "full_alpha_claimed", "completed_training_claimed")), "owner cancellation scope overstated")
    TRAIN["check_isolation"](value["isolation"])
    check_signal(value["signal"], value["isolation"])
    require(value["on_disk_model_before"] == value["on_disk_model_after"] == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]},
            "original on-disk model changed")
    state = value["state"]
    require(state["expected_error"] == "compute_owner_busy" and state["runtime_lock_released"] is True
            and state["complete_checkpoint_present"] is False and state["stdout"]["bytes"] == 0
            and not any(p["relative_path"] in ("report.json", "adapter/adapter_model.safetensors") for p in state["output_files"]),
            "cancelled job was advertised as completed or retains its runtime lease")
    require(value["provision"]["success"] is True and value["provision"]["installed_wheels"] == 38
            and value["provision"]["download_bytes"] == 523040250 and value["provision"]["training_performed"] is False,
            "wrong explicit model/backend provision")
    require(value["cleanup"]["complete"] is True and value["cleanup"]["remaining_owned_objects"] == 0
            and value["cleanup"]["guest_model_and_job_roots_removed"] is True and value["cleanup"]["observed_worker_lifetimes_ended"] is True
            and value["cleanup"]["fallback_signals_used"] is False and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "manual-only cancellation or guest cleanup incomplete")


def check_bundle(path, revision):
    value = read(path, 1048576)
    check_report(value, revision)
    output = path.parent
    for field in ("provision", "isolation", "signal", "state"):
        require(read(output / f"{NAME}-{field}.json") == value[field], "raw owner-cancellation evidence differs")
    prefix, prefix_hash = file_record(output / f"{NAME}-training-prefix.stderr")
    stdout, stdout_hash = file_record(output / f"{NAME}-worker.stdout")
    stderr, stderr_hash = file_record(output / f"{NAME}-worker.stderr")
    require(b"compute phase=training" in prefix.splitlines() and b"compute phase=complete" not in prefix.splitlines()
            and stderr.startswith(prefix) and b"Error: compute_owner_busy" in stderr.splitlines() and stdout == b""
            and prefix_hash == value["signal"]["training_prefix"] and stdout_hash == value["state"]["stdout"]
            and stderr_hash == value["state"]["stderr"], "actual training phase/cancellation logs differ")
    dataset = output / f"{NAME}-public-dataset.json"
    require(read(dataset) == TRAIN["public_dataset"](revision) and TRAIN["file_hash"](dataset, 1048576) == value["state"]["dataset"],
            "actual public training source changed")
    require(value["provision"]["model_pins_sha256"] == TRAIN["file_hash"](TRAIN["ML"] / "model-pins.json", 262144)["sha256"],
            "provisioning did not use trusted source model pins")
    for when in ("before", "after"):
        require(TRAIN["file_hash"](output / f"host-state-{when}.json", 1048576)["sha256"] == value["host_state"][f"{when}_sha256"],
                "raw guest state hash differs")


def self_test():
    cli, worker = dict(pid=100, start_ticks=1), dict(pid=101, start_ticks=2)
    isolation = dict(cli=cli, worker=worker, owned_processes=[cli, worker])
    proof = dict(cli=cli, worker=worker, observed_owned_processes=[cli, worker], signal_target=cli, owner_uid=1000, cli_uid=1000,
        signal="SIGINT", signal_number=2, signal_sent=True, pidfd_bound=True, signal_sent_only_to_cli=True, all_selected_pidfds_live_before_signal=True,
        signal_monotonic_ns=1000, cli_reaped_monotonic_ns=2000, all_ended_monotonic_ns=3000,
        cli_reaped=True, kernel_pidfds_exited=True, remaining_observed_processes=0, cli_exit_code=1,
        original_deadline_seconds=600, completed_training_claimed=False)
    check_signal(proof, isolation)
    require(observed_family(isolation) == [cli, worker], "observer family duplicated its starting CLI")
    for family in ([worker], [cli, cli, worker], [cli]):
        invalid = {**isolation, "owned_processes": family}
        try:
            observed_family(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid observed process family accepted")
    for key, changed in (("signal_target", worker), ("owner_uid", 0), ("cli_exit_code", 0),
                         ("all_ended_monotonic_ns", 1001 + LIMIT_NS), ("remaining_observed_processes", 1),
                         ("kernel_pidfds_exited", False), ("completed_training_claimed", True)):
        invalid = copy.deepcopy(proof)
        invalid[key] = changed
        try:
            check_signal(invalid, isolation)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid manual cancellation proof accepted: " + key)
    with tempfile.TemporaryDirectory(prefix="owner-cancel-parser-") as directory:
        root = Path(directory)
        path = root / "empty.stdout"
        path.touch(mode=0o600)
        require(file_record(path)[1] == {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}, "empty failed CLI stdout is valid raw evidence")
        (root / "link").symlink_to(path)
        try:
            file_record(root / "link")
        except ValueError:
            pass
        else:
            raise AssertionError("symlink raw evidence accepted")
    print("owner cancellation checker positives/ten rejections and owned-file checks PASS; no model, signal or network executed")


def main(args):
    if args == ["self-test"]:
        self_test()
        return 0
    if len(args) == 3 and args[0] == "execute":
        return execute(Path(args[1]), args[2])
    if len(args) == 3 and args[0] == "report":
        check_bundle(Path(args[1]), args[2])
        print("actual owner-only training cancellation and guest cleanup PASS")
        return 0
    if len(args) == 4 and args[0] == "failure":
        write(Path(args[1]) / f"{NAME}-smoke.json", dict(report_kind="volparossa-agent-owner-cancel",
            source_revision=args[2], scope=SCOPE, success=False, phase=args[3], observed_blocker="GUEST_PHASE_INCOMPLETE"))
        return 1
    raise ValueError("usage: self-test | execute OUTPUT SHA | report REPORT SHA | failure OUTPUT SHA PHASE")


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main(sys.argv[1:]))
