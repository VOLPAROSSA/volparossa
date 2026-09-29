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
import shutil
import signal
import socket
import stat
import struct
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
SCOPE = ("v2 actual private-serve Unix IPC: one local-private synthetic EOS Q/A plus observed cancel/disconnect, "
         "isolated readonly input/model mounts, owner controls and cleanup before the result frame; "
         "not a Firefox UI proof, confidential remote execution, a portable signed receipt, general answer quality or completed B04")
ACK = re.compile(rb"compute owner_ack phase=(paused|resumed) sequence=([1-9][0-9]*) step=([0-9]+) elapsed_ms=([0-9]+)")

# Only fixed source-defined strings can leave the private job root. Never export
# str(error), traceback, raw observer/service stderr, JSON snippets or worker reports.
CHECK_CODES = {
    "private observer owner mismatch": "OBSERVER_OWNER_MISMATCH",
    "private CLI disappeared before observation": "SERVICE_DISAPPEARED",
    "unexpected private work-parent contents": "SNAPSHOT_EXTRA_CHILDREN",
    "wrong ephemeral private directory": "SNAPSHOT_DIRECTORY_INVALID",
    "private input snapshot was not observed": "SNAPSHOT_NOT_OBSERVED",
    "private input was not independently snapshotted with exact bytes and permissions": "SNAPSHOT_BINDING_FAILED",
    "observed private input changed": "SNAPSHOT_CHANGED",
    "input must be an owned private regular file": "INPUT_FILE_INVALID",
    "invalid artifact file": "INPUT_BYTES_INVALID",
    "observer output/CLI owner mismatch": "OBSERVER_OUTPUT_OWNER_MISMATCH",
    "CLI disappeared before observing worker": "SERVICE_DISAPPEARED",
    "actual isolated Python worker was not observed": "WORKER_NOT_OBSERVED",
    "owned process thread observation limit": "OBSERVER_THREAD_BOUND",
    "owned process child-list limit": "OBSERVER_CHILD_LIST_BOUND",
    "owned descendant process limit": "OBSERVER_PROCESS_BOUND",
    "worker namespace shared with guest": "WORKER_NAMESPACE_SHARED",
    "worker has an external network device": "WORKER_NETWORK_DEVICE",
    "worker has an IPv4 route": "WORKER_IPV4_ROUTE",
    "worker input mount writable": "WORKER_INPUT_WRITABLE",
    "worker output mount missing": "WORKER_OUTPUT_MISSING",
    "worker mounts do not reference the actual supplied files": "WORKER_INPUT_INODE_MISMATCH",
    "host-home/private canary visible": "WORKER_HOST_INPUT_VISIBLE",
    "worker retained capabilities": "WORKER_CAPABILITIES_PRESENT",
    "actual private worker isolation observation failed": "OBSERVER_FAILED",
    "private IPC deadline elapsed": "IPC_DEADLINE",
    "private IPC disconnected before complete response": "IPC_EARLY_DISCONNECT",
    "private IPC response exceeds protocol bound": "IPC_FRAME_BOUND",
    "private IPC response correlation/event differs": "IPC_RESPONSE_MISMATCH",
    "cancel targeted another task": "CANCEL_TASK_MISMATCH",
    "cancel did not end through verified cleanup": "CANCEL_TERMINAL_MISMATCH",
    "private temporary input/report still present at result": "RESULT_STAGING_RETAINED",
    "original private input changed": "ORIGINAL_INPUT_CHANGED",
    "actual private worker still alive at result": "RESULT_WORKER_ALIVE",
    "disconnect did not reap the owned worker": "DISCONNECT_CLEANUP_FAILED",
}
ERROR_CODES = frozenset(CHECK_CODES.values()) | {
    "CHECK_FAILED", "JSON_INVALID", "UTF8_INVALID", "OS_ERROR", "TIMEOUT",
    "REPORT_KEY_MISSING", "REPORT_TYPE_INVALID", "SUBPROCESS_FAILED", "UNCLASSIFIED",
}
OBSERVER_STAGES = frozenset(("guard", "owner", "snapshot-wait", "snapshot-binding", "worker-isolation", "snapshot-recheck", "complete"))
PROTOCOL_EVENTS = frozenset(("capabilities", "admitted", "result", "error", "cancel_requested"))
PROTOCOL_ERRORS = frozenset(("busy", "invalid_request", "handshake_required", "no_such_task",
                             "cancelled", "execution_failed", "cleanup_unconfirmed"))


def safe_failure(error):
    """Classify fixed assertion messages, never copy an arbitrary exception's text."""
    if type(error) is ValueError and str(error) in CHECK_CODES:
        code = CHECK_CODES[str(error)]
    elif isinstance(error, json.JSONDecodeError):
        code = "JSON_INVALID"
    elif isinstance(error, UnicodeError):
        code = "UTF8_INVALID"
    elif isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        code = "TIMEOUT"
    elif isinstance(error, OSError):
        code = "OS_ERROR"
    elif isinstance(error, KeyError):
        code = "REPORT_KEY_MISSING"
    elif isinstance(error, TypeError):
        code = "REPORT_TYPE_INVALID"
    elif isinstance(error, subprocess.SubprocessError):
        code = "SUBPROCESS_FAILED"
    elif isinstance(error, ValueError):
        code = "CHECK_FAILED"
    else:
        code = "UNCLASSIFIED"
    return code


def check_observer_diagnostic(value):
    require(type(value) is dict and set(value) == {"version", "stage", "success", "failure_code"}
            and value["version"] == 1 and type(value["success"]) is bool
            and value["stage"] in OBSERVER_STAGES
            and (value["failure_code"] in ERROR_CODES if not value["success"] else
                 value["failure_code"] is None and value["stage"] == "complete"),
            "invalid fixed observer diagnostic")


def observer_status_path(work_parent, output):
    """Keep the child-to-parent diagnostic outside the exported artifact directory."""
    jobs = work_parent.parent
    destinations = {jobs / "cancel-observation": "cancel",
                    jobs / "disconnect-observation": "disconnect",
                    jobs.parent / "alpha-output": "inference"}
    require(output in destinations, "unexpected private observer proof directory")
    return jobs / f"observer-{destinations[output]}.json"


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


def observe(pid, output, provision, original, work_parent, diagnostic):
    diagnostic["stage"] = "guard"
    TRAIN["guest_guard"](root=True)
    diagnostic["stage"] = "owner"
    owner = TRAIN["identity"](pid)
    initial = identity(original)
    require(Path(f"/proc/{pid}").stat().st_uid == initial["uid"] == output.stat().st_uid != 0,
            "private observer owner mismatch")
    snapshot = None
    diagnostic["stage"] = "snapshot-wait"
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
    diagnostic["stage"] = "snapshot-binding"
    evidence = dict(original=initial, snapshot=identity(snapshot),
                    work_parent_mode=stat.S_IMODE(work_parent.stat().st_mode),
                    ephemeral_mode=stat.S_IMODE(snapshot.parent.stat().st_mode))
    check_snapshot(evidence)
    # The existing observer compares actual /proc/worker/root/dataset.json with this
    # new snapshot inode, not merely with a copied hash or the owner's original file.
    diagnostic["stage"] = "worker-isolation"
    TRAIN["observe"](pid, output / f"{NAME}-isolation.json", provision, snapshot, original)
    diagnostic["stage"] = "snapshot-recheck"
    require(identity(original) == initial and identity(snapshot) == evidence["snapshot"],
            "observed private input changed")
    target = output / f"{NAME}-snapshot.json"
    write(target, evidence)
    info = original.stat()
    os.chown(target, info.st_uid, info.st_gid)


def observe_diagnosed(pid, output, provision, original, work_parent):
    diagnostic = dict(version=1, stage="guard", success=False, failure_code="UNCLASSIFIED")
    try:
        observe(pid, output, provision, original, work_parent, diagnostic)
        diagnostic.update(stage="complete", success=True, failure_code=None)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        diagnostic["failure_code"] = safe_failure(error)
    check_observer_diagnostic(diagnostic)
    # This IPC side channel stays in the exact owned jobs directory, including the
    # inference observer whose ordinary proof files go into alpha-output. Only its
    # validated fixed fields are later included in the existing main smoke report.
    target = observer_status_path(work_parent, output)
    info = target.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid != 0 and stat.S_IMODE(info.st_mode) == 0o700,
            "invalid observer output owner")
    write(target, diagnostic)
    os.chown(target, info.st_uid, info.st_gid)
    return 0 if diagnostic["success"] else 1


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


def at_result(work_parent, original, expected, isolation, point="first_result_frame_byte"):
    require(not list(work_parent.iterdir()), "private temporary input/report still present at result")
    require(identity(original) == expected, "original private input changed")
    require(not any(TRAIN["alive"](p) for p in isolation["owned_processes"] if p != isolation["cli"]),
            "actual private worker still alive at result")
    return dict(observation_point=point, ephemeral_children=0,
                original=identity(original), observed_worker_lifetimes_ended=True)


def send_request(stream, operation):
    request_id = os.urandom(16).hex()
    raw = json.dumps(dict(version=1, id=request_id, operation=operation), separators=(",", ":")).encode()
    require(0 < len(raw) <= 32768, "private fixture request exceeds protocol bound")
    stream.sendall(struct.pack("!I", len(raw)) + raw)
    return request_id


def response(stream, request_id, event, deadline, first_byte=None, diagnostic=None):
    def exact(length):
        raw = bytearray()
        while len(raw) < length:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "private IPC deadline elapsed")
            stream.settimeout(remaining)
            block = stream.recv(length - len(raw))
            require(bool(block), "private IPC disconnected before complete response")
            raw.extend(block)
        return bytes(raw)
    header = exact(1)
    observed = first_byte() if first_byte else None
    length = struct.unpack("!I", header + exact(3))[0]
    require(0 < length <= 65536, "private IPC response exceeds protocol bound")
    value = json.loads(exact(length))
    if diagnostic is not None and type(value) is dict:
        # A worker may have failed while the external observer was waiting. Keep
        # only enumerated protocol states, never an unexpected result body/string.
        diagnostic.clear()
        diagnostic.update(expected_event=event if event in PROTOCOL_EVENTS else "unrecognized",
                          observed_event=value.get("event") if value.get("event") in PROTOCOL_EVENTS else "unrecognized",
                          correlated=value.get("version") == 1 and value.get("id") == request_id)
        code = value.get("code")
        if value.get("event") == "error":
            diagnostic["error_code"] = code if code in PROTOCOL_ERRORS else "unrecognized"
    require(value["version"] == 1 and value["id"] == request_id and value["event"] == event,
            "private IPC response correlation/event differs")
    return value, observed


def expected_capabilities():
    return dict(visibility="private_local", local_only=True, model_profile=PROFILE,
        max_question_bytes=512, max_context_bytes=4096, max_request_bytes=32768, max_response_bytes=65536,
        execution_slots=1, max_connections=8, max_seconds=600, network_access=False, public_cache=False,
        training=False, cloud_fallback=False, model_execution_proven=False, quarantined=False)


def check_capabilities(value):
    require(value == expected_capabilities(), "private service capability scope differs")


def connect_service(path, process):
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(5)
    stream.connect(str(path))
    pid, uid, gid = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(pid == process.pid and uid == os.getuid() and gid == os.getgid(), "private service peer owner differs")
    request_id = send_request(stream, dict(type="capabilities"))
    value, _ = response(stream, request_id, "capabilities", time.monotonic() + 5)
    check_capabilities(value["capabilities"])
    return stream, value["capabilities"]


def runtime_unlocked(lock):
    with lock.open("rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(stream, fcntl.LOCK_UN)


def check_service(value, primary_isolation, original):
    require(value["version"] == 1 and value["protocol"] == "private-local-json-v1"
            and value["one_eos_job"] is True and value["global_busy_observed"] is True
            and value["same_owner_peer_verified"] is True and value["socket_mode"] == 0o600
            and value["socket_parent_mode"] == 0o700 and value["stdout_empty"] is True
            and value["private_prompts_absent_from_diagnostics"] is True
            and value["service_exit_code"] == 0 and value["socket_removed"] is True,
            "private IPC lifecycle proof differs")
    check_capabilities(value["capabilities"])
    for name in ("cancel", "disconnect"):
        proof = value[name]
        TRAIN["check_isolation"](proof["isolation"])
        check_snapshot(proof["snapshot"])
        require(proof["isolation"]["cli"] == primary_isolation["cli"]
                and proof["isolation"]["worker"] != primary_isolation["worker"]
                and proof["snapshot"]["original"] == original
                and proof["runtime_lock_released"] is True
                and proof["cleanup"] == dict(observation_point="cancel_terminal_frame_byte" if name == "cancel" else "disconnect_cleanup",
                    ephemeral_children=0, original=proof["snapshot"]["original"], observed_worker_lifetimes_ended=True),
                "cancel/disconnect did not clean the exact observed worker before later admission")
    require(value["cancel"]["terminal_code"] == "cancelled" and value["cancel"]["cancel_acknowledged"] is True
            and value["disconnect"]["connection_closed_by_owner"] is True
            and value["cancel"]["isolation"]["worker"] != value["disconnect"]["isolation"]["worker"],
            "private service cancellation mechanism differs")


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
            and value["proof_version"] == 2
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
    require(value["result_boundary"] == dict(observation_point="first_result_frame_byte", ephemeral_children=0,
            original=value["snapshot"]["original"], observed_worker_lifetimes_ended=True)
            and value["original_after"] == value["snapshot"]["original"] and value["runtime_lock_released"] is True,
            "private snapshot lifetime or original input preservation differs")
    check_service(value["private_service"], value["isolation"], value["snapshot"]["original"])
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
    for field in ("provision", "isolation", "snapshot", "answer", "owner_controls", "result_boundary", "private_service"):
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
    result = dict(report_kind="volparossa-agent-private-task", proof_version=2, source_revision=revision, scope=SCOPE, success=False,
        full_b04_claimed=False, confidential_remote_execution_claimed=False,
        exported_answer_is_authorized_synthetic_test_data=True, raw_private_input_exported=False,
        raw_worker_report_exported=False, phase="provision")
    process, observer, members, fallback, clients = None, None, [], False, []
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
        private_input = dict(version=1, visibility="private_local",
            question="What is the test identifier in the note? Answer with only the identifier.",
            context=f"Synthetic private test note: The test identifier is {canary}. This note contains no real secrets.")
        # Match serde_json's canonical map ordering used by the service; the root
        # observer will compare the exact snapshot bytes/inode, not a loose semantic match.
        with original.open("xb") as stream:
            stream.write(json.dumps(private_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
        original.chmod(0o600)
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
        result["phase"] = "private-service-start"
        socket_path = jobs / "private.sock"
        with (jobs / "private.stderr").open("wb") as diagnostics, (jobs / "private.stdout").open("wb") as service_stdout:
            process = subprocess.Popen([CLI, "compute", "private-serve", "--socket", str(socket_path),
                "--work-parent", str(work_parent), *common], stdout=service_stdout, stderr=diagnostics)
            for _ in range(100):
                require(process.poll() is None, "private service exited before socket creation")
                if socket_path.exists() and stat.S_IMODE(socket_path.lstat().st_mode) == 0o600:
                    break
                time.sleep(0.1)
            info = socket_path.lstat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600, "private service socket is not owner-only")
            service = dict(version=1, protocol="private-local-json-v1", socket_mode=0o600,
                socket_parent_mode=stat.S_IMODE(jobs.stat().st_mode), same_owner_peer_verified=True)
            result["private_service"] = service

            def service_response(stream, request_id, event, deadline, first_byte=None):
                return response(stream, request_id, event, deadline, first_byte,
                                service.setdefault("last_response", {}))

            def observed(directory, label):
                nonlocal observer
                result["phase"] = f"private-service-{label}-observer-start"
                with (jobs / "observer.stderr").open("wb") as observer_diagnostics:
                    observer = subprocess.Popen(["sudo", "-n", sys.executable, "-B", str(Path(__file__).resolve()),
                        "observe", str(process.pid), str(directory), str(provision), str(original), str(work_parent)],
                        stdout=subprocess.DEVNULL, stderr=observer_diagnostics)
                    result["phase"] = f"private-service-{label}-observer-wait"
                    exit_code = observer.wait(timeout=70)
                status_path = observer_status_path(work_parent, directory)
                diagnostics = result.setdefault("observer_diagnostics", {})
                diagnostics[label] = dict(exit_code=exit_code, status_present=status_path.is_file())
                if status_path.is_file():
                    status = read(status_path, 4096)
                    check_observer_diagnostic(status)
                    diagnostics[label]["status"] = status
                require(exit_code == 0, "actual private worker isolation observation failed")
                result["phase"] = f"private-service-{label}-observer-bind"
                isolation = read(directory / f"{NAME}-isolation.json")
                snapshot = read(directory / f"{NAME}-snapshot.json")
                members.extend(isolation["owned_processes"])
                return isolation, snapshot

            # Two actual sandbox lifetimes are interrupted before the sole complete
            # inference. Later admission and EOS prove these earlier slots were released.
            for mechanism in ("cancel", "disconnect"):
                result["phase"] = f"private-service-{mechanism}-connect"
                stream, caps = connect_service(socket_path, process)
                clients.append(stream)
                service["capabilities"] = caps
                result["phase"] = f"private-service-{mechanism}-admission"
                request_id = send_request(stream, dict(type="submit", question=private_input["question"], context=private_input["context"]))
                service_response(stream, request_id, "admitted", time.monotonic() + 5)
                if mechanism == "cancel":
                    result["phase"] = "private-service-cancel-global-busy"
                    other, _ = connect_service(socket_path, process)
                    clients.append(other)
                    busy_id = send_request(other, dict(type="submit", question="Inert second request?", context="Must not be admitted."))
                    busy, _ = service_response(other, busy_id, "error", time.monotonic() + 5)
                    require(busy["code"] == "busy", "second connection bypassed global single-task admission")
                    other.close()
                    service["global_busy_observed"] = True
                proof_directory = jobs / f"{mechanism}-observation"
                proof_directory.mkdir(mode=0o700)
                isolated, snap = observed(proof_directory, mechanism)
                proof = dict(isolation=isolated, snapshot=snap)
                if mechanism == "cancel":
                    result["phase"] = "private-service-cancel-acknowledgement"
                    cancel_id = send_request(stream, dict(type="cancel", task_id=request_id))
                    acknowledgement, _ = service_response(stream, cancel_id, "cancel_requested", time.monotonic() + 5)
                    require(acknowledgement["task_id"] == request_id, "cancel targeted another task")
                    result["phase"] = "private-service-cancel-terminal-cleanup"
                    terminal, boundary = service_response(stream, request_id, "error", time.monotonic() + 10,
                        lambda: at_result(work_parent, original, initial, isolated, "cancel_terminal_frame_byte"))
                    require(terminal["code"] == "cancelled", "cancel did not end through verified cleanup")
                    proof.update(cancel_acknowledged=True, terminal_code=terminal["code"], cleanup=boundary)
                    stream.close()
                else:
                    result["phase"] = "private-service-disconnect-cleanup"
                    stream.close()
                    deadline = time.monotonic() + 10
                    while list(work_parent.iterdir()) or any(TRAIN["alive"](p) for p in isolated["owned_processes"] if p != isolated["cli"]):
                        require(time.monotonic() < deadline and process.poll() is None, "disconnect did not reap the owned worker")
                        time.sleep(0.05)
                    proof.update(connection_closed_by_owner=True,
                        cleanup=at_result(work_parent, original, initial, isolated, "disconnect_cleanup"))
                result["phase"] = f"private-service-{mechanism}-runtime-unlock"
                runtime_unlocked(lock)
                proof["runtime_lock_released"] = True
                service[mechanism] = proof

            result["phase"] = "private-service-infer-and-observe"
            diagnostics_offset = (jobs / "private.stderr").stat().st_size
            stream, caps = connect_service(socket_path, process)
            clients.append(stream)
            require(caps == service["capabilities"], "capabilities changed after cancellation")
            deadline = time.monotonic() + 610
            request_id = send_request(stream, dict(type="submit", question=private_input["question"], context=private_input["context"]))
            service_response(stream, request_id, "admitted", time.monotonic() + 5)
            result["isolation"], result["snapshot"] = observed(output, "inference")
            result["phase"] = "private-service-inference-terminal-cleanup"
            final, result["result_boundary"] = service_response(stream, request_id, "result", deadline,
                lambda: at_result(work_parent, original, initial, result["isolation"]))
            result["answer"] = final["result"]
            stream.close()
            # Preserve actual incomplete output honestly for diagnosis, never as PASS.
            write(output / f"{NAME}-answer.json", result["answer"])
            write(output / f"{NAME}-result_boundary.json", result["result_boundary"])
            check_answer(result["answer"], canary)
            service["one_eos_job"] = True
            result["owner_controls"] = owner_controls((jobs / "private.stderr").read_bytes()[diagnostics_offset:])
            write(output / f"{NAME}-owner_controls.json", result["owner_controls"])
            process.send_signal(signal.SIGINT)
            service["service_exit_code"] = process.wait(timeout=10)
        raw_diagnostics = (jobs / "private.stderr").read_bytes()
        require(len(raw_diagnostics) <= 65536 and all(text.encode() not in raw_diagnostics for text in
            (private_input["question"], private_input["context"], canary)), "private input leaked into service diagnostics")
        service["private_prompts_absent_from_diagnostics"] = True
        service["stdout_empty"] = (jobs / "private.stdout").stat().st_size == 0
        service["socket_removed"] = not socket_path.exists()
        check_service(service, result["isolation"], initial)
        write(output / f"{NAME}-private_service.json", service)
        result["original_after"] = identity(original)
        require(result["original_after"] == initial, "private original changed after answer")
        runtime_unlocked(lock)
        result["runtime_lock_released"] = True
        result["on_disk_model_after"] = TRAIN["file_hash"](model_file, MODEL["model"]["base_weights"]["bytes"])
        result["phase"] = "cleanup"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # No parser text, private context, report fragments or private filenames in evidence.
        result["observed_blocker"] = safe_failure(error)
    finally:
        for client in clients:
            client.close()
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
    secret = "PRIVATE-CANARY-not-for-diagnostics"
    for error in (ValueError(secret), OSError(secret), KeyError(secret), TypeError(secret),
                  json.JSONDecodeError(secret, secret, 0), RuntimeError(secret)):
        code = safe_failure(error)
        require(code in ERROR_CODES and secret not in code, "exception text escaped fixed classifier")
    require(safe_failure(ValueError("worker mounts do not reference the actual supplied files"))
            == "WORKER_INPUT_INODE_MISMATCH", "known observer failure lost its fixed code")
    observer_failure = dict(version=1, stage="snapshot-binding", success=False, failure_code="SNAPSHOT_BINDING_FAILED")
    check_observer_diagnostic(observer_failure)
    check_observer_diagnostic(dict(version=1, stage="complete", success=True, failure_code=None))
    for field, replacement in (("private_input", secret), ("stage", secret),
                               ("failure_code", secret), ("success", True)):
        invalid = dict(observer_failure)
        invalid[field] = replacement
        try:
            check_observer_diagnostic(invalid)
        except ValueError:
            pass
        else:
            raise ValueError("private/unbound observer diagnostic accepted")
    check_capabilities(expected_capabilities())
    for field, replacement in (("network_access", True), ("public_cache", True),
                               ("quarantined", True), ("execution_slots", 2), ("version", 2)):
        invalid = expected_capabilities()
        invalid[field] = replacement
        try:
            check_capabilities(invalid)
        except ValueError:
            pass
        else:
            raise ValueError("unsafe private service capability accepted")
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
        observer_work = root / "jobs/work"
        for directory in (root / "jobs/cancel-observation", root / "jobs/disconnect-observation", root / "alpha-output"):
            status = observer_status_path(observer_work, directory)
            require(status.parent == observer_work.parent and not status.is_relative_to(root / "alpha-output"),
                    "observer diagnostic escaped into exported artifact directory")
        try:
            observer_status_path(observer_work, root / "unrecognized-output")
        except ValueError:
            pass
        else:
            raise ValueError("unknown observer output scope accepted")
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
        at_result(work, original, expected, isolated)
        (work / "retained-input").mkdir(mode=0o700)
        try:
            at_result(work, original, expected, isolated)
        except ValueError:
            pass
        else:
            raise ValueError("retained private input accepted at result frame")
    # Pure framing controls only; no fake response is counted as actual model evidence.
    request_id = "01" * 16
    for kind in ("valid", "wrong-id", "oversize", "worker-error", "unknown-error", "unexpected-result"):
        left, right = socket.socketpair()
        try:
            frame = dict(version=1, id=request_id if kind != "wrong-id" else "02" * 16, event="admitted")
            if kind in ("worker-error", "unknown-error"):
                frame.update(event="error", code="execution_failed" if kind == "worker-error" else secret,
                             private_input=secret)
            elif kind == "unexpected-result":
                frame.update(event="result", result={"output": {"text": secret}})
            payload = json.dumps(frame).encode()
            left.sendall(struct.pack("!I", 65537 if kind == "oversize" else len(payload)) + payload)
            diagnostic = {}
            try:
                value, observed = response(right, request_id, "admitted", time.monotonic() + 1,
                                           lambda: "checked-before-body", diagnostic)
            except ValueError as error:
                require(kind != "valid", "valid private frame rejected")
                require(safe_failure(error) in ("IPC_RESPONSE_MISMATCH", "IPC_FRAME_BOUND"),
                        "private frame failure lost its fixed classification")
            else:
                require(kind == "valid" and observed == "checked-before-body" and value["id"] == request_id,
                        "invalid private frame accepted")
            require(secret not in json.dumps(diagnostic), "private protocol content escaped diagnostics")
            if kind == "worker-error":
                require(diagnostic == dict(expected_event="admitted", observed_event="error", correlated=True,
                                           error_code="execution_failed"), "worker error code was not safely retained")
            elif kind == "unknown-error":
                require(diagnostic["error_code"] == "unrecognized", "unknown private error escaped allowlist")
        finally:
            left.close()
            right.close()
    print("private-task v2 pure IPC/snapshot/EOS/canary/cleanup/static-diagnostic controls PASS; no model executed")


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
        return observe_diagnosed(int(sys.argv[2]), *(Path(x) for x in sys.argv[3:]))
    if len(sys.argv) == 4 and sys.argv[1] == "report":
        check_bundle(Path(sys.argv[2]), sys.argv[3])
        print("actual local-private synthetic Q/A report PASS; no confidential remote claim")
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "failure":
        write(Path(sys.argv[2]) / f"{NAME}-smoke.json", dict(report_kind="volparossa-agent-private-task",
            proof_version=2, source_revision=sys.argv[3], success=False, scope=SCOPE, phase=sys.argv[4],
            observed_blocker="GUEST_PHASE_INCOMPLETE", full_b04_claimed=False,
            confidential_remote_execution_claimed=False))
        return 1
    raise ValueError("usage: self-test | execute OUTPUT SHA | report REPORT SHA | observe PID OUTPUT PROVISION INPUT WORK")


if __name__ == "__main__":
    raise SystemExit(main())
