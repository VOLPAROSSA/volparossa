#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Two genuinely concurrent public-inference executors; not loss/reassignment proof."""

import base64
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
import time

HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / "agent-training-smoke.py"))
CUSTODY = runpy.run_path(str(HERE / "content-custody-smoke.py"))
read, write, require = TRAIN["read"], TRAIN["write"], TRAIN["require"]
file_hash, identity, alive = TRAIN["file_hash"], TRAIN["identity"], TRAIN["alive"]
SCOPE = ("two distinct node-local fixed-model workers concurrently execute disjoint signed public rows over protected paths; "
         "not automatic reassignment, private offload, distributed training, model-layer sharding or answer quality")
NODES = ("relay3", "relay4", "relay5")
LOSS_SCOPE = ("two protected public peer jobs, one exact observed worker killed in the disposable guest; "
              "original successful result retained and only terminally failed rows explicitly reassigned to the idle surviving peer; "
              "not automatic planning, exactly-once execution, renewed original leases, private offload or full B03")
BROKER_STARTUP_ENUMS = {
    "LoadState": {"stub", "loaded", "not-found", "bad-setting", "error", "merged", "masked"},
    "ActiveState": {"inactive", "activating", "active", "reloading", "deactivating", "failed", "maintenance", "refreshing"},
    "SubState": {"dead", "start-pre", "start", "start-post", "running", "exited", "reload", "reload-signal",
                 "reload-notify", "stop", "stop-watchdog", "stop-sigterm", "stop-sigkill", "stop-post",
                 "final-watchdog", "final-sigterm", "final-sigkill", "failed", "auto-restart",
                 "auto-restart-queued", "dead-before-auto-restart", "failed-before-auto-restart", "cleaning"},
    "Result": {"success", "resources", "protocol", "timeout", "exit-code", "signal", "core-dump",
               "watchdog", "start-limit-hit", "oom-kill", "exec-condition"},
    "CollectMode": {"inactive", "inactive-or-failed"},
}
BROKER_STARTUP_NUMBERS = {"MainPID", "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestampMonotonic",
                          "ExecMainExitTimestampMonotonic", "CPUUsageNSec"}
BROKER_STARTUP_FIELDS = set(BROKER_STARTUP_ENUMS) | BROKER_STARTUP_NUMBERS


def broker_startup_status(raw):
    """Parse only requested fixed systemd fields; never retain unknown values or text."""
    fields = dict.fromkeys(sorted(BROKER_STARTUP_FIELDS))
    if len(raw) > 4096:
        return fields, ["size"]
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return fields, ["encoding"]
    if len(lines) > len(fields):
        return fields, ["field_count"]
    seen, errors = set(), set()
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key not in fields:
            errors.add("unexpected_field")
            continue
        if key in seen:
            fields[key] = None
            errors.add(key)
            continue
        seen.add(key)
        if key in BROKER_STARTUP_ENUMS:
            if value in BROKER_STARTUP_ENUMS[key]:
                fields[key] = value
            else:
                errors.add(key)
        elif key == "CPUUsageNSec" and value in {"[not set]", "18446744073709551615"}:
            # Unavailable accounting is explicitly null, never a measured zero.
            pass
        elif re.fullmatch(r"0|[1-9][0-9]{0,19}", value) and int(value) < 2 ** 64:
            fields[key] = int(value)
        else:
            errors.add(key)
    errors.update(BROKER_STARTUP_FIELDS - seen)
    return fields, sorted(errors)


def broker_startup_record(node, outcome, attempts, started, observed, raw):
    require(node in NODES and outcome in {"start_failed", "unit_failed", "socket_timeout", "socket_ready"},
            "invalid broker startup identity")
    require(type(attempts) is int and 0 <= attempts <= 150
            and type(started) is int and type(observed) is int and 0 < started <= observed < 2 ** 64,
            "invalid broker startup timing")
    status, errors = broker_startup_status(raw)
    return {"version": 1, "node": node, "outcome": outcome, "poll_attempts": attempts,
            "clock": "monotonic", "started_monotonic_ns": started, "observed_monotonic_ns": observed,
            "elapsed_ns": observed - started, "systemd": status, "parse_errors": errors,
            "socket_ready": outcome == "socket_ready", "model_execution_proven": False}


def broker_startup_self_test():
    # Pure service-output fixtures, not a broker/model startup or timing proof.
    fields = {"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "Result": "exit-code",
              "CollectMode": "inactive", "MainPID": "0", "ExecMainCode": "1", "ExecMainStatus": "226",
              "ExecMainStartTimestampMonotonic": "1000", "ExecMainExitTimestampMonotonic": "1100",
              "CPUUsageNSec": "[not set]"}
    encoded = lambda value: "".join(f"{key}={item}\n" for key, item in value.items()).encode()
    failed = broker_startup_record("relay4", "unit_failed", 3, 1000, 2000, encoded(fields))
    require(failed["parse_errors"] == [] and failed["systemd"]["ExecMainStatus"] == 226
            and failed["systemd"]["CPUUsageNSec"] is None and failed["elapsed_ns"] == 1000,
            "failed unit status was lost")
    running = dict(fields, ActiveState="active", SubState="running", Result="success", MainPID="123",
                   ExecMainCode="0", ExecMainStatus="0", ExecMainExitTimestampMonotonic="0", CPUUsageNSec="12000000000")
    waiting = broker_startup_record("relay4", "socket_timeout", 150, 1000, 15000001000, encoded(running))
    ready = broker_startup_record("relay5", "socket_ready", 2, 1000, 2000, encoded(running))
    require(waiting["systemd"]["MainPID"] == 123 and not waiting["socket_ready"]
            and ready["socket_ready"] and not ready["model_execution_proven"], "startup outcomes conflated")
    secret = "/private/not-a-diagnostic/input"
    malformed = [encoded(dict(fields, Result=secret)), encoded(dict(fields, MainPID="-1")),
                 encoded(dict(fields, CPUUsageNSec=str(2 ** 64))), encoded(dict(fields, ExecMainCode="01")),
                 encoded(fields) + f"Environment={secret}\n".encode(), b"X" * 4097, b"\xff", b"",
                 b"MainPID=123\nMainPID=456\n"]
    for raw in malformed:
        value = broker_startup_record("relay4", "start_failed", 0, 1000, 2000, raw)
        require(value["parse_errors"] and secret not in json.dumps(value), "raw service output escaped diagnostic parser")
    for attempts, started, observed in [(151, 1, 2), (True, 1, 2), (0, 2, 1), (0, 0, 1)]:
        try:
            broker_startup_record("relay4", "unit_failed", attempts, started, observed, encoded(fields))
        except ValueError:
            continue
        raise AssertionError("invalid diagnostic bounds accepted")
    print("broker startup fixed-field/timing/privacy parser self-tests PASS; no services or model executed")


def private(path, name):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.name == name and not path.is_symlink()
            and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.getuid() != 0, "wrong private compute fixture root")
    return path


def dataset(revision, source):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "invalid source revision")
    first = "Every parallel path uses exactly one distinct relay between the same client and exit."
    second = "The normal client dataplane never connects directly to an exit."
    text = source.replace("\n", " ")
    require(first in text and second.lower() in text.lower(), "public source text changed")
    return {"version": 1, "visibility": "public", "license": "GPL-3.0-only", "source_revision": revision,
            "train": [], "heldout": [{"question": "Is direct client-to-exit access normal?", "context": second, "answer": "No."}],
            "inference": [{"question": "How many relays does one path use?", "context": first},
                          {"question": "May a normal client directly contact an exit dataplane?", "context": second}]}


def prepare(path, model_profile="smollm2-135m-v1", decoder=None):
    TRAIN["inference_profile"](model_profile)
    require(decoder is None or decoder == "--task-graph-decoder", "unsupported fixture decoder")
    root = private(path, "agent-jobs-user")
    require(not list(root.iterdir()), "provision root already populated")
    profile_args = [] if model_profile == "smollm2-135m-v1" else ["--model-profile", model_profile]
    if decoder is not None:
        profile_args.append(decoder)
    subprocess.run([sys.executable, "-B", str(HERE / "ml/provision.py"), "--execute", "--yes",
                    "--disposable-guest", "--root", str(root / "provision"), "--budget-bytes", str(3 * 1024 ** 3), *profile_args],
                   check=True, timeout=1850)


def source(path, revision):
    root = private(path, "compute-source")
    require(not list(root.iterdir()), "source root already populated")
    write(root / "dataset.json", dataset(revision, (HERE / "agent-jobs-README.md").read_text()))
    with (root / "passphrase").open("xb") as stream:
        stream.write(base64.b64encode(os.urandom(48)) + b"\n")
    (root / "passphrase").chmod(0o600)


def publication(path):
    root = private(path, "compute-source")
    return {"dataset": read(root / "dataset.json"), "dataset_file": file_hash(root / "dataset.json", 1048576),
            "dataset_json": (root / "dataset.json").read_text(),
            "manifest": file_hash(root / "manifest.pb", 65536),
            "manifest_hex": (root / "manifest.pb").read_bytes().hex(), "explicit_public_source": True}


def derive(original, rows, task=None):
    require(rows and rows == sorted(set(rows)) and all(0 <= x < len(original["inference"]) for x in rows), "invalid rows")
    value = copy.deepcopy(original)
    value["inference"] = [copy.deepcopy(original["inference"][x]) for x in rows]
    if task is not None:
        require(task.get("kind") == "answer_public_question_v1" and set(task) == {"kind", "question"}
                and isinstance(task["question"], str) and task["question"].strip()
                and len(task["question"].encode()) <= 512 and "\0" not in task["question"], "invalid explicit public task")
        for row in value["inference"]:
            row["question"] = task["question"]
    # Struct field order is the canonical Rust dataset serialization order.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def guest_work(work):
    TRAIN["guest_guard"](root=True)
    require(work.parent == Path("/opt") and work.name.startswith("va.") and not work.is_symlink(), "wrong owned topology root")


def broker_pid(node):
    raw = subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
                                   f"volparossa-alpha-compute@{node}.service"], text=True).strip()
    require(raw.isdecimal() and int(raw) > 0, "actual broker not running")
    return int(raw)


def worker_snapshot(work, node, broker, expected_dataset_sha256=None):
    require(identity(broker["pid"]) == broker, "broker changed during observation")
    proc = Path(f"/proc/{broker['pid']}")
    require(Path(os.readlink(proc / "exe")).name == "volparossa", "unexpected broker executable")
    service_pid = int(subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
                                               f"volparossa-alpha-agent@{node}.service"], text=True))
    namespace = os.readlink(proc / "ns/net")
    require(namespace == os.readlink(f"/proc/{service_pid}/ns/net"), "broker outside its actual node namespace")
    private_root = work / f"state-{node}/compute"
    family = TRAIN["descendants"](broker["pid"])
    for member in family:
        worker = Path(f"/proc/{member['pid']}")
        try:
            args = (worker / "cmdline").read_bytes().split(b"\0")
            if not args or args[0] != b"/runtime/bin/python3":
                continue
            root = worker / "root"
            mounts = {}
            for line in (worker / "mountinfo").read_text().splitlines():
                fields = line.split()
                if fields[4] in ("/runtime", "/model", "/dataset.json", "/output"):
                    mounts[fields[4]] = fields[5].split(",")
            require(all("ro" in mounts.get(p, []) for p in ("/runtime", "/model", "/dataset.json"))
                    and "rw" in mounts.get("/output", []), "actual worker mounts not isolated")
            datasets = list((private_root / "work").glob("compute-job-*/dataset.json"))
            if expected_dataset_sha256 is not None:
                mounted = (root / "dataset.json").stat()
                datasets = [path for path in datasets if (path.stat().st_dev, path.stat().st_ino)
                            == (mounted.st_dev, mounted.st_ino)]
                if len(datasets) != 1 or file_hash(datasets[0], 1048576)["sha256"] != expected_dataset_sha256:
                    continue
            require(len(datasets) == 1, "expected one actual node-owned job input")
            actual = {"model/model.safetensors": work / "agent-jobs-user/provision/model/model.safetensors",
                      "runtime/pyvenv.cfg": private_root / "runtime/pyvenv.cfg", "dataset.json": datasets[0]}
            inodes = {}
            for mounted, original in actual.items():
                left, right = (root / mounted).stat(), original.stat()
                require((left.st_dev, left.st_ino) == (right.st_dev, right.st_ino), "worker input is not exact node-local file")
                inodes[mounted] = [right.st_dev, right.st_ino]
            namespaces = {kind: os.readlink(worker / "ns" / kind) for kind in ("net", "pid", "ipc", "mnt")}
            guest = {kind: os.readlink(Path("/proc/self/ns") / kind) for kind in namespaces}
            require(all(namespaces[k] != guest[k] for k in namespaces)
                    and namespaces["net"] != namespace, "worker shares node or guest network namespace")
            devices = [line.split(":", 1)[0].strip() for line in (worker / "net/dev").read_text().splitlines()[2:]]
            require(devices == ["lo"] and len((worker / "net/route").read_text().splitlines()) == 1, "worker has external network")
            status = dict(line.split(":", 1) for line in (worker / "status").read_text().splitlines() if ":" in line)
            require(int(status["CapEff"], 16) == 0 and not (root / "home").exists() and not (root / "root").exists(), "worker exposes host authority")
            for other in ("client", *NODES):
                if other != node:
                    hidden = proc / "root" / str(work / f"state-{other}").lstrip("/")
                    visible, original = hidden.stat(), (work / f"state-{other}").stat()
                    require(stat.S_IMODE(visible.st_mode) == 0
                            and (visible.st_dev, visible.st_ino) != (original.st_dev, original.st_ino),
                            "broker mount exposes other node state")
            require(proc.stat().st_uid == private_root.stat().st_uid != 0,
                    "broker is not the unprivileged node owner")
            lock_path = private_root / "runtime/.volparossa-compute.lock"
            lock = lock_path.lstat()
            require(stat.S_ISREG(lock.st_mode) and lock.st_nlink == 1, "runtime lock is aliased")
            with lock_path.open("rb") as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise ValueError("observed worker does not hold its runtime lease")
            return {"node": node, "broker": broker, "service": identity(service_pid), "worker": member,
                    "owned_processes": family, "node_namespace": namespace, "worker_namespaces": namespaces,
                    "guest_namespaces": guest, "network_devices": devices, "ipv4_routes": [], "mounts": mounts,
                    "input_inodes": inodes, "runtime_lock_inode": [lock.st_dev, lock.st_ino], "runtime_lock_held": True,
                    "dataset_json": datasets[0].read_text(), "dataset_file": file_hash(datasets[0], 1048576),
                    "effective_capabilities": 0, "host_home_visible": False, "other_node_state_hidden": True}
        except FileNotFoundError:
            continue
    return None


def check_overlap(observation):
    workers = observation["workers"]
    require(len(workers) == 2 and len({w["node"] for w in workers}) == 2
            and len({w["node_namespace"] for w in workers}) == 2
            and len({w["broker"]["pid"] for w in workers}) == 2
            and len({w["worker"]["pid"] for w in workers}) == 2
            and len({tuple(w["runtime_lock_inode"]) for w in workers}) == 2,
            "not two independent simultaneous executors")
    require(observation["both_alive_before_and_after"] is True
            and observation["last_monotonic_ns"] > observation["first_monotonic_ns"], "worker lifetimes never overlapped")
    for worker in workers:
        require(worker["node"] in NODES and worker["runtime_lock_held"] is True
                and worker["network_devices"] == ["lo"] and worker["ipv4_routes"] == []
                and worker["effective_capabilities"] == 0 and worker["host_home_visible"] is False
                and worker["other_node_state_hidden"] is True, "worker isolation missing")
        require(all(worker["worker_namespaces"][k] != worker["guest_namespaces"][k] for k in ("net", "pid", "ipc", "mnt"))
                and worker["worker_namespaces"]["net"] != worker["node_namespace"], "worker namespace reused")
        require(all("ro" in worker["mounts"][p] for p in ("/runtime", "/model", "/dataset.json")), "writable compute input")
    require(workers[0]["input_inodes"]["model/model.safetensors"] == workers[1]["input_inodes"]["model/model.safetensors"], "base model was downloaded per worker")
    for name in ("runtime/pyvenv.cfg", "dataset.json"):
        require(workers[0]["input_inodes"][name] != workers[1]["input_inodes"][name], "independent worker input aliased")


def observe(work):
    guest_work(work)
    layout = read(work / "agent-jobs-layout.json")
    brokers = {node: identity(broker_pid(node)) for node in layout["provider_nodes"]}
    for _ in range(1200):
        first = time.monotonic_ns()
        values = [worker_snapshot(work, node, broker) for node, broker in brokers.items()]
        if all(values):
            before = all(alive(x["worker"]) and alive(x["broker"]) for x in values)
            last = time.monotonic_ns()
            after = all(alive(x["worker"]) and alive(x["broker"]) for x in values)
            if before and after:
                result = {"workers": values, "both_alive_before_and_after": True,
                          "first_monotonic_ns": first, "last_monotonic_ns": last}
                check_overlap(result)
                write(work / "agent-jobs-observation.json", result)
                return
        time.sleep(0.05)
    raise ValueError("two actual isolated Python worker lifetimes did not overlap")


def cleanup(work):
    guest_work(work)
    observation = work / "agent-jobs-observation.json"
    if observation.is_file():
        require(not any(alive(p) for w in read(observation)["workers"] for p in w["owned_processes"]), "owned compute process alive")
    replacement = work / "agent-jobs-replacement-observation.json"
    if replacement.is_file():
        require(not any(alive(p) for p in read(replacement)["worker"]["owned_processes"]), "owned replacement process alive")
    targets = [work / "agent-jobs-user", work / "state-client/compute-source"]
    targets.extend(work / f"state-{node}/compute" for node in NODES)
    for target in targets:
        if target.exists():
            info = target.lstat()
            require(stat.S_ISDIR(info.st_mode) and not target.is_symlink() and info.st_uid != 0
                    and stat.S_IMODE(info.st_mode) == 0o700, "wrong cleanup root")
            shutil.rmtree(target)
    return {"observed_compute_processes_ended": True, "model_runtime_removed": True,
            "private_job_roots_removed": all(not path.exists() for path in targets), "publisher_key_removed": True}


def boot_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def initial_handles(work):
    root = work / "state-client/compute-source/batch"
    return [{"value": read(root / f"job-{n}.json"), "file": file_hash(root / f"job-{n}.json", 16384)} for n in (0, 1)]


def inject_loss(work):
    guest_work(work)
    layout = read(work / "agent-jobs-layout.json")
    observation = read(work / "agent-jobs-observation.json")
    check_overlap(observation)
    victim = next(w for w in observation["workers"] if w["node"] == layout["provider_nodes"][0])
    survivor = next(w for w in observation["workers"] if w["node"] == layout["provider_nodes"][1])
    handles = initial_handles(work)
    require(handles[0]["value"]["provider_key"] == layout["provider_keys"][victim["node"]]
            and handles[1]["value"]["provider_key"] == layout["provider_keys"][survivor["node"]]
            and all(alive(w["worker"]) and alive(w["broker"]) for w in (victim, survivor)),
            "initial executors changed before injected loss")
    # pidfd plus the original start ticks prevent a PID-reuse signal. Killing this
    # sandbox's actual Python process ends its private PID subtree, never its broker.
    fd = os.pidfd_open(victim["worker"]["pid"])
    try:
        require(identity(victim["worker"]["pid"]) == victim["worker"], "loss target PID was reused")
        current = worker_snapshot(work, victim["node"], victim["broker"])
        require(current is not None and current["worker"] == victim["worker"], "loss target is not the owned sandbox worker")
        result = {"victim": victim, "survivor": survivor, "original_handles": handles,
                  "signal": "SIGKILL", "signal_number": signal.SIGKILL, "pidfd_bound": True,
                  "both_workers_alive_before_signal": True, "signal_sent": False,
                  "worker_exit_observed": False}
        write(work / "agent-jobs-loss-plan.json", result)
        print(f"Disposable guest only: SIGKILL pidfd-bound Python worker {victim['worker']['pid']} "
              f"(start ticks {victim['worker']['start_ticks']}) on {victim['node']}; keep both brokers and survivor alive.", flush=True)
        result["signal_boottime_ns"] = boot_ns()
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        result["signal_sent"] = True
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        require(bool(poller.poll(10000)), "injected worker exit was not kernel-observed")
        result["exit_boottime_ns"] = boot_ns()
        result["worker_exit_observed"] = True
        result["surviving_worker_alive_after_signal"] = alive(survivor["worker"])
        result["both_brokers_alive_after_signal"] = all(alive(w["broker"]) for w in (victim, survivor))
        require(result["surviving_worker_alive_after_signal"] and result["both_brokers_alive_after_signal"],
                "injected worker loss affected another owned executor")
        write(work / "agent-jobs-loss-control.json", result)
    finally:
        os.close(fd)


def arm_resume(work):
    guest_work(work)
    loss = read(work / "agent-jobs-loss-control.json")
    statuses = [read(work / f"agent-jobs-status-{n}.json") for n in (0, 1)]
    require(statuses[0]["state"] == "failed" and statuses[0]["error"] == "worker_failed"
            and statuses[0]["report_json"] is None and statuses[0]["report_sha256"] is None
            and statuses[1]["state"] == "complete", "real failed/complete original terminal receipts required")
    require(all(statuses[n]["binding"] == loss["original_handles"][n]["value"]["binding"] for n in (0, 1)),
            "terminal receipts substituted original bindings")
    require(all(not alive(loss[name]["worker"]) and alive(loss[name]["broker"]) for name in ("victim", "survivor")),
            "original workers not reaped before explicit replacement")
    require(initial_handles(work) == loss["original_handles"], "original handles changed before resume")
    write(work / "agent-jobs-resume-ready.json", {"statuses": statuses, "original_workers_ended": True,
          "both_original_brokers_alive": True, "boottime_ns": boot_ns(), "unix_seconds": int(time.time())})


def observe_replacement(work):
    guest_work(work)
    loss = read(work / "agent-jobs-loss-control.json")
    ready = read(work / "agent-jobs-resume-ready.json")
    original = loss["original_handles"][0]["value"]
    node, broker = loss["survivor"]["node"], loss["survivor"]["broker"]
    for _ in range(1200):
        candidate = work / "state-client/compute-source/resumed/job-0.json"
        if candidate.is_file():
            handle = read(candidate)
            require(handle["provider_key"] == loss["original_handles"][1]["value"]["provider_key"]
                    and handle["binding"]["row_indices"] == original["binding"]["row_indices"]
                    and handle["binding"]["job_id"] != original["binding"]["job_id"], "unexpected reassignment")
            first = boot_ns()
            current = worker_snapshot(work, node, broker, original["binding"]["dataset_sha256"])
            if current and alive(current["worker"]) and alive(current["broker"]):
                require(all(not alive(loss[name]["worker"]) for name in ("victim", "survivor")), "old attempt overlaps new worker")
                last = boot_ns()
                require(last > first and first > ready["boottime_ns"], "replacement observed before authorization")
                result = {"worker": current, "handle": handle, "alive_before_and_after": alive(current["worker"]),
                          "first_boottime_ns": first, "last_boottime_ns": last,
                          "handle_saved_unix_seconds": candidate.stat().st_mtime_ns // 1000000000,
                          "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "original_workers_ended": True}
                require(result["alive_before_and_after"], "replacement ended during observation")
                write(work / "agent-jobs-replacement-observation.json", result)
                return
        time.sleep(0.05)
    raise ValueError("actual reassigned Python worker not observed")


def capture_resume(work):
    guest_work(work)
    root = work / "state-client/compute-source/resumed"
    # Save only public handles/receipts, never the publisher identity or private runtime.
    files = {name: read(root / name) for name in ("original-0.json", "original-1.json", "observation-0.json",
             "observation-1.json", "job-0.json", "retry-0.json", "result.json")}
    require(not (root / "job-1.json").exists() and not (root / "retry-1.json").exists(), "successful original rows were rerun")
    write(work / "agent-jobs-resume-files.json", {"files": files, "successful_rows_reassigned": False,
          "original_handles_after": initial_handles(work), "captured_boottime_ns": boot_ns()})


def source_manifest_id(source, published):
    # Offline publication reports a local manifest path, not a manifest_id field.
    # Bind jobs to the retained original signed bytes. The real CLI verifies the
    # signature; this independent inspection checks the reported publisher/expiry.
    encoded = bytes.fromhex(source["manifest_hex"])
    digest = hashlib.sha256(encoded).hexdigest()
    require(source["manifest"] == {"bytes": len(encoded), "sha256": digest}, "original manifest hash/length differs")
    envelope = CUSTODY["fields"](encoded, 65536)
    require(set(envelope) == {1, 2} and isinstance(envelope[2], bytes) and len(envelope[2]) == 64,
            "original signed manifest envelope missing")
    body = CUSTODY["fields"](envelope[1], 65536)
    require(body[1] == 1 and body[2] == bytes.fromhex(published["publisher_key_hex"])
            and len(body[2]) == 32 and body[4] == published["expires_unix_seconds"],
            "offline publication publisher/expiry differs from signed bytes")
    return digest


def check_evidence(evidence, revision, task=None):
    require(evidence["success"] is True and evidence["source_revision"] == revision, "wrong source-bound job proof")
    require(evidence["provision"]["success"] is True and evidence["provision"]["installed_wheels"] == 38
            and evidence["provision"]["download_bytes"] == 523040250
            and evidence["provision"]["training_performed"] is False, "unverified or repeated provision scope")
    check_overlap(evidence["observation"])
    original, publication = evidence["source"], evidence["publish"]
    manifest_id = source_manifest_id(original, publication)
    require(original["explicit_public_source"] is True and json.loads(original["dataset_json"]) == original["dataset"]
            and original["dataset"]["source_revision"] == revision and len(original["dataset"]["inference"]) == 2
            and original["dataset"]["visibility"] == "public" and original["dataset"]["license"] == "GPL-3.0-only",
            "original explicit public source missing")
    require(hashlib.sha256(original["dataset_json"].encode()).hexdigest() == original["dataset_file"]["sha256"]
            and publication["bytes"] == original["dataset_file"]["bytes"]
            and publication["operation"] == "offline_content_publish"
            and publication["network_publication"] is False, "original publication bytes differ")
    layout, peers, result = evidence["layout"], evidence["peers"], evidence["result"]
    require(set(layout["provider_nodes"]) == {w["node"] for w in evidence["observation"]["workers"]}
            and all(CUSTODY["peer_key"](peers[node]) == key for node, key in layout["provider_keys"].items())
            and layout["control_relay_peer_id"] not in {peers[node] for node in layout["provider_nodes"]}, "provider identity/lineage differs")
    require(result["operation"] == "compute_distribute" and result["complete"] is True and result["provider_count"] == 2
            and result["dataset_manifest_id"] == manifest_id and len(result["jobs"]) == 2,
            "actual distributed batch incomplete")
    require(result.get("task") == task, "batch task binding differs")
    require(all(result[x] is False for x in ("private_data_supported", "model_layer_sharding", "result_truthfulness_guaranteed")), "unsupported compute claim")
    rows, response_bytes = [], {}
    for index, status in enumerate(evidence["statuses"]):
        binding = status["binding"]
        part = next(x for x in result["jobs"] if x["handle"]["binding"]["job_id"] == binding["job_id"])
        handle = part["handle"]
        node = layout["provider_nodes"][index]
        caps = handle["capabilities"]
        require(binding.get("task") == task and (task is None or caps.get("task_derivation_v1") is True),
                "executor does not support the exact requested public task")
        require(caps["model"]["model_id"] == "HuggingFaceTB/SmolLM2-135M-Instruct"
                and caps["model"]["model_revision"] == TRAIN["MODEL_REVISION"]
                and caps["model"]["base_weights"] == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}
                and caps["model"]["adapter_files"] is None and caps["public_inference_only"] is True
                and caps["runtime_slots"] == 1 and caps["max_threads"] == 2
                and caps["model_fingerprint"] == binding["model_fingerprint"], "job not bound to the selected fixed-model profile")
        require(handle["provider_key"] == layout["provider_keys"][node]
                and handle["binding"] == binding and part["state"] == status["state"] == "complete"
                and binding["row_indices"] == [index] and binding["dataset_manifest_id"] == manifest_id
                and binding["expires_unix_seconds"] <= publication["expires_unix_seconds"], "wrong original job binding")
        derived = derive(original["dataset"], binding["row_indices"], task)
        observation = next(w for w in evidence["observation"]["workers"] if w["node"] == node)
        require(observation["dataset_json"] == derived and binding["dataset_sha256"] == hashlib.sha256(derived.encode()).hexdigest(),
                "executor received different or overlapping public rows")
        report_json = status["report_json"]
        require(status["report_sha256"] == part["report_sha256"] == hashlib.sha256(report_json.encode()).hexdigest(), "returned worker report changed")
        report = json.loads(report_json)
        require(report["status"] == "ok" and report["mode"] == "infer" and report["device"] == "cpu"
                and report["threads"] == 2 and report["updates_completed"] == 0
                and report["dataset"]["sha256"] == binding["dataset_sha256"]
                and report["dataset"]["source_revision"] == revision and len(report["outputs"]) == 1,
                "no real source-bound inference result")
        require(report["model"]["files"]["model.safetensors"] == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}
                and report["model"]["revision"] == TRAIN["MODEL_REVISION"], "wrong fixed model")
        supervisor = report["supervisor"]
        require(supervisor["child_reaped"] is True and supervisor["network_access"] is False
                and supervisor["gpu_access"] is False and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"], "worker accounting/cleanup missing")
        output = result["outputs"][index]
        require(output["sample_index"] == index and output["job_id"] == binding["job_id"]
                and output["provider_key"] == handle["provider_key"] and output["text"] == report["outputs"][0]["text"], "original result order was not retained")
        rows.extend(binding["row_indices"])
        response_bytes[node] = len(report_json.encode())
    require(sorted(rows) == [0, 1] and len(set(rows)) == 2, "rows not executed exactly once by distinct peers")
    phase = evidence["path"]
    # Reuse exact graph/role/multipath validation, not its content-operation semantics.
    CUSTODY["validate_path"](phase, peers, layout, "inspect")
    for node in layout["provider_nodes"]:
        application = phase["privacy"]["exit"]["provider_application"][node]
        require(application["request_packets"] > 0
                and application["response_payload_bytes"] >= response_bytes[node], "selected provider did not carry job/result bytes")
    require(all(evidence["cleanup"].values()), "compute private cleanup incomplete")


def read_evidence(work, revision):
    evidence = {name: read(work / f"agent-jobs-{name}.json") for name in ("source", "publish", "layout", "result", "observation", "provision")}
    evidence.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
                    cleanup=read(work / "agent-jobs-private-cleanup.json"),
                    statuses=[read(work / f"agent-jobs-status-{n}.json") for n in (0, 1)],
                    path={"selected_route": read(work / "content-custody-fetch-live-selection.json"),
                          "privacy": {role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
                          "control_privacy": read(work / "content-provider-custody-fetch-control.json"),
                          "gates": read(work / "content-custody-fetch-gates.json")})
    check_evidence(evidence, revision)
    return evidence


def build_evidence(work, revision):
    write(work / "agent-jobs-evidence.json", read_evidence(work, revision))


def check_loss_handle(handle, original, publication, manifest_id, node, layout):
    binding, caps = handle["binding"], handle["capabilities"]
    require(handle["provider_key"] == layout["provider_keys"][node]
            and binding["dataset_manifest_id"] == manifest_id
            and binding["dataset_sha256"] == hashlib.sha256(derive(original, binding["row_indices"]).encode()).hexdigest()
            and binding["expires_unix_seconds"] <= publication["expires_unix_seconds"]
            and re.fullmatch(r"[0-9a-f]{32}", binding["job_id"]), "replacement/original handle source differs")
    require(caps["model"]["model_id"] == "HuggingFaceTB/SmolLM2-135M-Instruct"
            and caps["model"]["model_revision"] == TRAIN["MODEL_REVISION"]
            and caps["model"]["base_weights"] == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}
            and caps["model"]["adapter_files"] is None and caps["public_inference_only"] is True
            and caps["runtime_slots"] == 1 and caps["max_threads"] == 2
            and caps["model_fingerprint"] == binding["model_fingerprint"], "different replacement model/profile")


def check_loss_completed(status, handle, revision, output):
    binding = handle["binding"]
    require(status["binding"] == binding and status["state"] == "complete"
            and status["report_sha256"] == hashlib.sha256(status["report_json"].encode()).hexdigest(), "complete receipt changed")
    report = json.loads(status["report_json"])
    require(report["status"] == "ok" and report["mode"] == "infer" and report["device"] == "cpu"
            and report["threads"] == 2 and report["updates_completed"] == 0
            and report["dataset"]["sha256"] == binding["dataset_sha256"]
            and report["dataset"]["source_revision"] == revision and len(report["outputs"]) == 1
            and report["model"]["files"]["model.safetensors"] == handle["capabilities"]["model"]["base_weights"]
            and report["model"]["revision"] == TRAIN["MODEL_REVISION"], "wrong actual resumed inference")
    supervisor = report["supervisor"]
    require(supervisor["child_reaped"] is True and supervisor["network_access"] is False
            and supervisor["gpu_access"] is False
            and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"], "replacement not reaped/isolated")
    require(output["sample_index"] == binding["row_indices"][0] and output["job_id"] == binding["job_id"]
            and output["provider_key"] == handle["provider_key"] and output["text"] == report["outputs"][0]["text"],
            "resumed output differs from exact received worker report")


def check_loss_evidence(evidence, revision):
    require(evidence["success"] is True and evidence["source_revision"] == revision, "wrong loss source revision")
    require(evidence["provision"]["success"] is True and evidence["provision"]["installed_wheels"] == 38
            and evidence["provision"]["download_bytes"] == 523040250
            and evidence["provision"]["training_performed"] is False, "loss case did not reuse fixed provisioning")
    check_overlap(evidence["observation"])
    source, published = evidence["source"], evidence["publish"]
    manifest_id = source_manifest_id(source, published)
    original = source["dataset"]
    require(source["explicit_public_source"] is True and json.loads(source["dataset_json"]) == original
            and original["visibility"] == "public" and original["license"] == "GPL-3.0-only"
            and original["source_revision"] == revision and len(original["inference"]) == 2
            and hashlib.sha256(source["dataset_json"].encode()).hexdigest() == source["dataset_file"]["sha256"]
            and published["bytes"] == source["dataset_file"]["bytes"]
            and published["operation"] == "offline_content_publish" and published["network_publication"] is False,
            "original signed public source bytes differ")
    layout, peers, loss = evidence["layout"], evidence["peers"], evidence["loss"]
    a, b = layout["provider_nodes"]
    originals = [entry["value"] for entry in loss["original_handles"]]
    require(a != b and all(CUSTODY["peer_key"](peers[n]) == layout["provider_keys"][n] for n in (a, b))
            and layout["control_relay_peer_id"] not in (peers[a], peers[b]), "worker provider lineage differs")
    for index, node in enumerate((a, b)):
        check_loss_handle(originals[index], original, published, manifest_id, node, layout)
        require(originals[index]["binding"]["row_indices"] == [index], "original rows overlap")
        observed = next(w for w in evidence["observation"]["workers"] if w["node"] == node)
        require(loss[("victim", "survivor")[index]] == observed
                and observed["dataset_json"] == derive(original, [index]), "signaled/retained worker lineage differs")
    require(loss["signal"] == "SIGKILL" and loss["signal_number"] == 9 and loss["pidfd_bound"] is True
            and all(loss[k] is True for k in ("signal_sent", "worker_exit_observed", "both_workers_alive_before_signal",
                                             "surviving_worker_alive_after_signal", "both_brokers_alive_after_signal"))
            and 0 < loss["signal_boottime_ns"] <= loss["exit_boottime_ns"], "actual selected worker death not observed")
    first, ready, resumed = evidence["result"], evidence["ready"], evidence["resume"]
    require(first["operation"] == "compute_distribute" and first["complete"] is False
            and first["dataset_manifest_id"] == manifest_id and len(first["jobs"]) == 2
            and first["outputs"][0] is None and first["outputs"][1] is not None, "loss falsely reported successful")
    for index, status in enumerate(evidence["statuses"]):
        part = next(x for x in first["jobs"] if x["handle"] == originals[index])
        require(status["binding"] == originals[index]["binding"] and part["state"] == status["state"], "original terminal receipt differs")
    failed, kept = evidence["statuses"]
    require(failed["state"] == "failed" and failed["error"] == "worker_failed"
            and failed["report_json"] is None and failed["report_sha256"] is None
            and kept["state"] == "complete" and ready["statuses"] == evidence["statuses"]
            and ready["original_workers_ended"] is True and ready["both_original_brokers_alive"] is True
            and ready["boottime_ns"] >= loss["exit_boottime_ns"], "missing terminal proof before reassignment")
    check_loss_completed(kept, originals[1], revision, first["outputs"][1])
    files = evidence["resume_files"]
    require(files["original_handles_after"] == loss["original_handles"] and files["successful_rows_reassigned"] is False
            and files["files"]["original-0.json"] == originals[0] and files["files"]["original-1.json"] == originals[1]
            and files["files"]["result.json"] == resumed, "original handles/output were overwritten")
    require(resumed["operation"] == "compute_resume" and resumed["complete"] is True
            and resumed["dataset_manifest_id"] == manifest_id and resumed["requested_rows"] == [0, 1]
            and resumed["full_dataset_requested"] is True and resumed["maximum_retries_per_part"] == 1
            and all(resumed[k] is False for k in ("exactly_once_execution_guaranteed", "private_data_supported", "result_truthfulness_guaranteed"))
            and len(resumed["jobs"]) == len(resumed["outputs"]) == 2, "resumed result incomplete or overstated")
    prior = next(part for part in resumed["jobs"] if part["retried"] is False)
    retry = next(part for part in resumed["jobs"] if part["retried"] is True)
    handle = retry["handle"]
    check_loss_handle(handle, original, published, manifest_id, b, layout)
    require(prior == {"handle": originals[1], "state": "complete", "retried": False}
            and retry["original_handle"] == originals[0] and retry["original_state"] == "stopped"
            and retry["prior_terminal_receipt_received"] is True and retry["status"] == evidence["replacement_status"]
            and handle == files["files"]["job-0.json"] and retry == files["files"]["retry-0.json"]
            and handle["binding"]["job_id"] not in [h["binding"]["job_id"] for h in originals]
            and handle["binding"]["row_indices"] == [0]
            and handle["binding"]["dataset_sha256"] == originals[0]["binding"]["dataset_sha256"]
            and handle["binding"]["model_fingerprint"] == originals[0]["binding"]["model_fingerprint"]
            and ready["unix_seconds"] < handle["binding"]["expires_unix_seconds"],
            "retry changed rows/model or disguised original lease extension")
    for index, state in enumerate(("stopped", "complete")):
        stored = files["files"][f"observation-{index}.json"]
        require(stored == {"handle": originals[index], "state": state, "status": evidence["statuses"][index]},
                "resume did not observe exact original terminal receipts")
    require(evidence["retained_status"] == kept and resumed["outputs"][1] == first["outputs"][1], "successful original result was replaced")
    check_loss_completed(evidence["replacement_status"], handle, revision, resumed["outputs"][0])
    replacement = evidence["replacement"]
    worker, survivor = replacement["worker"], loss["survivor"]
    require(0 < handle["binding"]["expires_unix_seconds"] - replacement["handle_saved_unix_seconds"] <= 600,
            "replacement attempt exceeded its own bounded lease")
    require(replacement["handle"] == handle and replacement["alive_before_and_after"] is True
            and replacement["original_workers_ended"] is True
            and worker["node"] == b and worker["broker"] == survivor["broker"] and worker["service"] == survivor["service"]
            and worker["node_namespace"] == survivor["node_namespace"]
            and worker["worker"] not in [loss[name]["worker"] for name in ("victim", "survivor")]
            and worker["runtime_lock_inode"] == survivor["runtime_lock_inode"] and worker["runtime_lock_held"] is True
            and worker["dataset_json"] == derive(original, [0])
            and worker["dataset_file"]["sha256"] == handle["binding"]["dataset_sha256"]
            and ready["boottime_ns"] < replacement["first_boottime_ns"] < replacement["last_boottime_ns"],
            "replacement is not a new real worker on the idle surviving node")
    tick_ns = 1000000000 // replacement["clock_ticks_per_second"]
    require(worker["worker"]["start_ticks"] * tick_ns + tick_ns >= ready["boottime_ns"], "replacement began before original terminal receipts")
    require(worker["network_devices"] == ["lo"] and worker["ipv4_routes"] == []
            and worker["effective_capabilities"] == 0 and worker["host_home_visible"] is False
            and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][p] for p in ("/runtime", "/model", "/dataset.json"))
            and all(worker["worker_namespaces"][k] != worker["guest_namespaces"][k] for k in ("net", "pid", "ipc", "mnt"))
            and worker["worker_namespaces"]["net"] != worker["node_namespace"], "replacement isolation not observed")
    CUSTODY["validate_path"](evidence["path"], peers, layout, "inspect")
    responses = evidence["path"]["privacy"]["exit"]["provider_application"]
    require(responses[a]["request_packets"] > 0 and responses[a]["response_payload_bytes"] > 0
            and responses[b]["request_packets"] > 0
            and responses[b]["response_payload_bytes"] >= len(kept["report_json"].encode()) + len(evidence["replacement_status"]["report_json"].encode()),
            "real original/replacement reports did not use protected provider paths")
    require(all(evidence["cleanup"].values()), "loss/replacement cleanup incomplete")


def build_loss_evidence(work, revision):
    evidence = {name: read(work / f"agent-jobs-{name}.json") for name in ("source", "publish", "layout", "result", "observation", "provision")}
    evidence.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
                    cleanup=read(work / "agent-jobs-private-cleanup.json"),
                    statuses=[read(work / f"agent-jobs-status-{n}.json") for n in (0, 1)],
                    path={"selected_route": read(work / "content-custody-fetch-live-selection.json"),
                          "privacy": {role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
                          "control_privacy": read(work / "content-provider-custody-fetch-control.json"),
                          "gates": read(work / "content-custody-fetch-gates.json")})
    for field, filename in {"loss": "loss-control", "ready": "resume-ready", "resume": "resume-result",
                            "resume_files": "resume-files", "replacement": "replacement-observation",
                            "replacement_status": "replacement-status", "retained_status": "retained-status"}.items():
        evidence[field] = read(work / f"agent-jobs-{filename}.json", 1048576)
    check_loss_evidence(evidence, revision)
    write(work / "agent-jobs-loss-evidence.json", evidence)


def finalize_loss(work, revision, status, complete, remaining, phase, blocker):
    path = work / "agent-jobs-loss-evidence.json"
    evidence = read(path, 1048576) if path.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(work / "agent-jobs-loss-smoke.json", {
        "report_kind": "volparossa-public-peer-worker-loss", "source_revision": revision, "scope": LOSS_SCOPE,
        "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and evidence is not None,
        "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker, "runner_exit_status": status,
        "automatic_reassignment_claimed": False, "exactly_once_execution_claimed": False,
        "original_lease_extension_claimed": False, "full_b03_claimed": False, "full_alpha_claimed": False,
        "evidence": evidence, "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host})


def check_loss_report(report, revision):
    require(report["report_kind"] == "volparossa-public-peer-worker-loss" and report["source_revision"] == revision
            and report["success"] is True and report["scope"] == LOSS_SCOPE and report["runner_exit_status"] == 0,
            "incomplete worker-loss/reassignment report")
    require(report["cleanup"] == {"complete": True, "remaining_owned_objects": 0} and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"], "worker-loss cleanup differs")
    require(all(report[k] is False for k in ("automatic_reassignment_claimed", "exactly_once_execution_claimed",
                                            "original_lease_extension_claimed", "full_b03_claimed", "full_alpha_claimed")),
            "worker-loss proof overstated")
    check_loss_evidence(report["evidence"], revision)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    evidence = read(work / "agent-jobs-evidence.json", 1048576) if (work / "agent-jobs-evidence.json").is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(work / "agent-jobs-smoke.json", {
        "report_kind": "volparossa-public-cooperative-jobs", "source_revision": revision, "scope": SCOPE,
        "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and evidence is not None,
        "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker, "runner_exit_status": status,
        "automatic_reassignment_claimed": False, "full_b03_claimed": False, "full_alpha_claimed": False,
        "evidence": evidence, "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host})


def check_report(report, revision):
    require(report["report_kind"] == "volparossa-public-cooperative-jobs" and report["source_revision"] == revision
            and report["success"] is True and report["scope"] == SCOPE and report["runner_exit_status"] == 0, "incomplete job report")
    require(report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"], "guest cleanup differs")
    require(all(report[k] is False for k in ("automatic_reassignment_claimed", "full_b03_claimed", "full_alpha_claimed")), "unsupported broader proof")
    check_evidence(report["evidence"], revision)


def self_test():
    value = dataset("a" * 40, (HERE.parent.parent / "README.md").read_text())
    a, b = (derive(value, [n]) for n in (0, 1))
    require(a != b and json.loads(a)["inference"] == value["inference"][:1]
            and json.loads(b)["inference"] == value["inference"][1:], "disjoint source derivation failed")
    for rows in ([], [0, 0], [1, 0], [2]):
        try:
            derive(value, rows)
        except ValueError:
            continue
        raise AssertionError("invalid source rows accepted")
    for proof in ({"workers": []}, {"workers": [{"node": "relay4"}] * 2}):
        try:
            check_overlap(proof)
        except (ValueError, KeyError):
            continue
        raise AssertionError("absent or same-worker proof accepted")
    # Exercise a complete synthetic contract, then reject altered source, identity,
    # overlap and results. This fixture never counts as actual network/model evidence.
    base = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["fixture"]()
    encoded = json.dumps(value)
    digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
    model = {"model_id": "HuggingFaceTB/SmolLM2-135M-Instruct", "model_revision": TRAIN["MODEL_REVISION"],
             "base_weights": {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}, "adapter_files": None}
    profiles = dict(model=model, model_fingerprint="f" * 64, public_inference_only=True, runtime_slots=1, max_threads=2)
    # Synthetic canonical envelope fields, not a cryptographic validity claim.
    publisher = "9" * 64
    body = b"\x08\x01\x12\x20" + bytes.fromhex(publisher) + b"\x20\xb8\x17"
    manifest = b"\x0a" + bytes([len(body)]) + body + b"\x12\x40" + bytes(64)
    manifest_id = hashlib.sha256(manifest).hexdigest()
    fixture = {"success": True, "source_revision": "a" * 40, "layout": base["layout"], "peers": base["expected_peers"],
               "provision": dict(success=True, installed_wheels=38, download_bytes=523040250, training_performed=False),
               "source": {"dataset": value, "dataset_json": encoded, "dataset_file": {"bytes": len(encoded), "sha256": digest(encoded)},
                          "manifest": {"bytes": len(manifest), "sha256": manifest_id}, "manifest_hex": manifest.hex(), "explicit_public_source": True},
               "publish": {"operation": "offline_content_publish", "network_publication": False,
                           "publisher_key_hex": publisher, "manifest": "/synthetic/manifest.pb", "cache": "/synthetic/cache",
                           "chunks": 1, "bytes": len(encoded), "expires_unix_seconds": 3000},
               "result": dict(operation="compute_distribute", complete=True, provider_count=2, dataset_manifest_id=manifest_id,
                              private_data_supported=False, model_layer_sharding=False, result_truthfulness_guaranteed=False,
                              jobs=[], outputs=[]), "statuses": [], "cleanup": {"done": True},
               "path": base["phases"]["inspect"], "observation": {"workers": [], "both_alive_before_and_after": True,
                                                                   "first_monotonic_ns": 1000, "last_monotonic_ns": 2000}}
    for n, node in enumerate(base["layout"]["provider_nodes"]):
        derived = derive(value, [n])
        binding = dict(job_id=str(n) * 32, row_indices=[n], dataset_manifest_id=manifest_id,
                       dataset_sha256=digest(derived), model_fingerprint="f" * 64, expires_unix_seconds=2000)
        report = dict(status="ok", mode="infer", device="cpu", threads=2, updates_completed=0,
                      dataset=dict(sha256=digest(derived), source_revision="a" * 40),
                      outputs=[dict(text="synthetic public output")],
                      model=dict(revision=TRAIN["MODEL_REVISION"], files={"model.safetensors": model["base_weights"]}),
                      supervisor=dict(child_reaped=True, network_access=False, gpu_access=False,
                                      max_observed_rss_bytes=100, rss_limit_bytes=1000))
        report_json = json.dumps(report)
        handle = dict(provider_key=base["layout"]["provider_keys"][node], binding=binding, capabilities=profiles)
        fixture["result"]["jobs"].append(dict(handle=handle, state="complete", report_sha256=digest(report_json)))
        fixture["result"]["outputs"].append(dict(sample_index=n, provider_key=handle["provider_key"],
                                                 job_id=binding["job_id"], text=report["outputs"][0]["text"]))
        fixture["statuses"].append(dict(binding=binding, state="complete", report_json=report_json, report_sha256=digest(report_json)))
        fixture["observation"]["workers"].append(dict(node=node, broker=dict(pid=100+n), worker=dict(pid=200+n),
            node_namespace=f"net:[{n+1}]", worker_namespaces={k: f"{k}:[{n+20}]" for k in ("net", "pid", "ipc", "mnt")},
            guest_namespaces={k: f"{k}:[30]" for k in ("net", "pid", "ipc", "mnt")}, runtime_lock_inode=[1, n+10],
            runtime_lock_held=True, dataset_json=derived, network_devices=["lo"], ipv4_routes=[],
            mounts={p: ["ro"] for p in ("/runtime", "/model", "/dataset.json")},
            effective_capabilities=0, host_home_visible=False, other_node_state_hidden=True,
            input_inodes={"model/model.safetensors": [1, 100], "runtime/pyvenv.cfg": [1, n+200], "dataset.json": [1, n+300]}))
    require("manifest_id" not in fixture["publish"], "fixture invented an offline publication field")
    check_evidence(fixture, "a" * 40)
    for kind in ("same_lock", "no_overlap", "altered_dataset", "reordered_result", "manifest_hash", "signed_publisher", "signed_expiry"):
        bad = copy.deepcopy(fixture)
        if kind == "same_lock":
            bad["observation"]["workers"][1]["runtime_lock_inode"] = bad["observation"]["workers"][0]["runtime_lock_inode"]
        elif kind == "no_overlap":
            bad["observation"]["both_alive_before_and_after"] = False
        elif kind == "altered_dataset":
            bad["observation"]["workers"][0]["dataset_json"] += " "
        elif kind == "reordered_result":
            bad["result"]["outputs"].reverse()
        elif kind == "manifest_hash":
            bad["source"]["manifest"]["sha256"] = "0" * 64
        elif kind == "signed_publisher":
            bad["publish"]["publisher_key_hex"] = "0" * 64
        else:
            bad["publish"]["expires_unix_seconds"] += 1
        try:
            check_evidence(bad, "a" * 40)
        except ValueError:
            continue
        raise AssertionError(f"invalid synthetic contract accepted: {kind}")
    print("agent-jobs source/subset/complete-contract/overlap/result negative self-tests PASS; no model or network executed")
    return fixture


def loss_self_test():
    # Contract-only source, never an actual killed process or model execution claim.
    value = self_test()
    digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
    original_handles = [copy.deepcopy(part["handle"]) for part in value["result"]["jobs"]]
    for n, worker in enumerate(value["observation"]["workers"]):
        worker["worker"]["start_ticks"] = n + 100
        worker["service"] = {"pid": n + 10, "start_ticks": 5}
    victim, survivor = value["observation"]["workers"]
    handles = [{"value": handle, "file": {"bytes": 100, "sha256": digest(json.dumps(handle))}} for handle in original_handles]
    value["loss"] = {"victim": copy.deepcopy(victim), "survivor": copy.deepcopy(survivor), "original_handles": handles,
                     "signal": "SIGKILL", "signal_number": 9, "pidfd_bound": True, "signal_sent": True,
                     "worker_exit_observed": True, "both_workers_alive_before_signal": True,
                     "surviving_worker_alive_after_signal": True, "both_brokers_alive_after_signal": True,
                     "signal_boottime_ns": 1000000000, "exit_boottime_ns": 2000000000}
    replaced_report = json.loads(value["statuses"][0]["report_json"])
    value["statuses"][0] = {"binding": original_handles[0]["binding"], "state": "failed", "error": "worker_failed",
                             "report_json": None, "report_sha256": None}
    value["result"]["complete"] = False
    value["result"]["outputs"][0] = None
    value["result"]["jobs"][0] = {"handle": original_handles[0], "state": "failed", "error": "worker_failed"}
    value["ready"] = {"statuses": copy.deepcopy(value["statuses"]), "original_workers_ended": True,
                      "both_original_brokers_alive": True, "boottime_ns": 8000000000, "unix_seconds": 1800}
    new_handle = copy.deepcopy(original_handles[0])
    new_handle["provider_key"] = original_handles[1]["provider_key"]
    new_handle["binding"]["job_id"] = "d" * 32
    new_handle["binding"]["expires_unix_seconds"] = 2500
    encoded_report = json.dumps(replaced_report)
    status = {"binding": new_handle["binding"], "state": "complete", "report_json": encoded_report,
              "report_sha256": digest(encoded_report)}
    retry = {"original_handle": original_handles[0], "original_state": "stopped", "handle": new_handle,
             "status": status, "retried": True, "prior_terminal_receipt_received": True}
    value["replacement_status"] = status
    value["retained_status"] = copy.deepcopy(value["statuses"][1])
    value["resume"] = {"operation": "compute_resume", "complete": True, "dataset_manifest_id": source_manifest_id(value["source"], value["publish"]),
                       "requested_rows": [0, 1], "full_dataset_requested": True, "maximum_retries_per_part": 1,
                       "exactly_once_execution_guaranteed": False, "private_data_supported": False, "result_truthfulness_guaranteed": False,
                       "jobs": [{"handle": original_handles[1], "state": "complete", "retried": False}, retry],
                       "outputs": [{"sample_index": 0, "provider_key": new_handle["provider_key"], "job_id": new_handle["binding"]["job_id"],
                                    "text": replaced_report["outputs"][0]["text"]}, copy.deepcopy(value["result"]["outputs"][1])]}
    files = {f"original-{n}.json": original_handles[n] for n in (0, 1)}
    for n, state in enumerate(("stopped", "complete")):
        files[f"observation-{n}.json"] = {"handle": original_handles[n], "state": state, "status": value["statuses"][n]}
    files.update({"job-0.json": new_handle, "retry-0.json": retry, "result.json": value["resume"]})
    value["resume_files"] = {"files": files, "original_handles_after": copy.deepcopy(handles), "successful_rows_reassigned": False}
    worker = copy.deepcopy(survivor)
    worker["worker"] = {"pid": 999, "start_ticks": 900}
    worker["dataset_json"] = derive(value["source"]["dataset"], [0])
    worker["dataset_file"] = {"sha256": digest(worker["dataset_json"])}
    value["replacement"] = {"worker": worker, "handle": new_handle, "alive_before_and_after": True,
                            "original_workers_ended": True, "first_boottime_ns": 10000000000,
                            "last_boottime_ns": 11000000000, "clock_ticks_per_second": 100, "handle_saved_unix_seconds": 2000}
    check_loss_evidence(value, "a" * 40)
    changes = {
        "no_actual_death": lambda x: x["loss"].update(worker_exit_observed=False),
        "wrong_signaled_worker": lambda x: x["loss"]["victim"]["worker"].update(pid=9999),
        "old_worker_overlap": lambda x: x["replacement"].update(original_workers_ended=False),
        "replacement_predates_terminal": lambda x: x["replacement"]["worker"]["worker"].update(start_ticks=1),
        "original_lease_changed": lambda x: x["resume_files"]["original_handles_after"][0]["value"]["binding"].update(expires_unix_seconds=3001),
        "replacement_lease_excess": lambda x: x["replacement"].update(handle_saved_unix_seconds=100),
        "retained_result_changed": lambda x: x["retained_status"].update(report_sha256="0" * 64),
        "source_changed": lambda x: x["source"].update(dataset_json=x["source"]["dataset_json"] + " "),
        "no_cleanup": lambda x: x["cleanup"].update(done=False),
    }
    for name, change in changes.items():
        altered = copy.deepcopy(value)
        change(altered)
        try:
            check_loss_evidence(altered, "a" * 40)
        except ValueError:
            continue
        raise AssertionError(f"invalid loss evidence accepted: {name}")
    print("agent-jobs-loss contract and nine negative checks PASS; no signal, model or network executed")


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        broker_startup_self_test()
        self_test()
    elif args == ["broker-startup-self-test"]:
        broker_startup_self_test()
    elif len(args) == 5 and args[0] == "broker-startup":
        # The shell producer has a two-second timeout. Read at most one bounded record;
        # an oversized/unparseable response yields fixed diagnostics, never raw text.
        raw = sys.stdin.buffer.read(4097)
        print(json.dumps(broker_startup_record(args[1], args[2], int(args[3]), int(args[4]),
                                               time.monotonic_ns(), raw)))
    elif args == ["loss-self-test"]:
        loss_self_test()
    elif len(args) in (2, 3, 4) and args[0] == "prepare":
        prepare(*args[1:])
    elif len(args) == 3 and args[0] == "source":
        source(args[1], args[2])
    elif len(args) == 2 and args[0] == "publication":
        print(json.dumps(publication(args[1])))
    elif len(args) == 2 and args[0] == "observe":
        observe(Path(args[1]))
    elif len(args) == 2 and args[0] == "inject-loss":
        inject_loss(Path(args[1]))
    elif len(args) == 2 and args[0] == "arm-resume":
        arm_resume(Path(args[1]))
    elif len(args) == 2 and args[0] == "observe-replacement":
        observe_replacement(Path(args[1]))
    elif len(args) == 2 and args[0] == "capture-resume":
        capture_resume(Path(args[1]))
    elif len(args) == 2 and args[0] == "cleanup":
        print(json.dumps(cleanup(Path(args[1]))))
    elif len(args) == 3 and args[0] == "evidence":
        build_evidence(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "loss-evidence":
        build_loss_evidence(Path(args[1]), args[2])
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif len(args) == 8 and args[0] == "loss-finalize":
        finalize_loss(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif len(args) == 3 and args[0] == "report":
        report = read(Path(args[1]), 1048576)
        if report["report_kind"] == "volparossa-public-peer-worker-loss":
            check_loss_report(report, args[2])
            print("actual worker loss and explicit failed-row reassignment report PASS")
        else:
            check_report(report, args[2])
            print("actual two-node concurrent signed public job report PASS")
    else:
        raise ValueError("unsupported fixture operation")


if __name__ == "__main__":
    os.umask(0o077)
    main()
