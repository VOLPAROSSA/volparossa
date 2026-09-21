#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One real free broker refills before another original row finishes; guest-only pause."""
import base64
import copy
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
FOLLOW = runpy.run_path(str(HERE / "agent-jobs-follow-smoke.py"))
JOBS, CUSTODY = FOLLOW["JOBS"], FOLLOW["CUSTODY"]
read, write, require = FOLLOW["read"], FOLLOW["write"], FOLLOW["require"]
alive, identity, hashes = FOLLOW["alive"], FOLLOW["identity"], FOLLOW["hash_bytes"]
FIRST = FOLLOW["FIRST"]
PREFIX = "agent-jobs-ready-queue"
KIND = "volparossa-public-ready-row-queue"
SCOPE = ("one signed four-row public source and two actual fixed-model brokers; an explicitly pidfd-paused "
         "guest worker keeps its original lease while the other broker completes its first row and starts "
         "a previously unleased row in the same owner invocation; four ordered original results and an "
         "unchanged completed resume with both brokers stopped. Pause is fixture orchestration, not product "
         "behavior. Not private computation, exactly-once execution, automatic peer discovery, answer "
         "quality, full B03 or full alpha.")


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def workflow(work):
    return work / "state-client/compute-source/ready-queue"


def source(path, revision):
    root = JOBS["private"](path, "compute-source")
    require(not list(root.iterdir()), "source root already populated")
    value = JOBS["dataset"](revision, (HERE / "agent-jobs-README.md").read_text())
    value["inference"].extend([
        dict(question="Does every parallel path have its own relay?", context=value["inference"][0]["context"]),
        dict(question="Is a direct client-to-exit dataplane normal?", context=value["inference"][1]["context"]),
    ])
    write(root / "dataset.json", value)
    with (root / "passphrase").open("xb") as stream:
        stream.write(base64.b64encode(os.urandom(48)) + b"\n")
    (root / "passphrase").chmod(0o600)


def prepare(root, publisher):
    JOBS["private"](root, "compute-source")
    require(re.fullmatch(r"[0-9a-f]{64}", publisher) and len(read(root / "dataset.json")["inference"]) == 4,
            "not the explicitly published four-row source")
    write(root / "ready-queue-plan.json", dict(version=1, packages=[dict(dataset=str(root / "dataset.json"),
          dataset_manifest=str(root / "manifest.pb"), publisher_key=publisher)]))


def owner_process(work, launcher):
    fn = FOLLOW["owner_process"]
    previous = fn.__globals__["workflow"]
    fn.__globals__["workflow"] = workflow
    try:
        return fn(work, launcher)
    finally:
        fn.__globals__["workflow"] = previous


def send_exact(member, action):
    fd = os.pidfd_open(member["pid"])
    try:
        require(identity(member["pid"]) == member, "owned worker PID reused")
        signal.pidfd_send_signal(fd, action)
    finally:
        os.close(fd)


def stopped(member):
    require(alive(member), "original worker vanished")
    return Path(f"/proc/{member['pid']}/stat").read_text().rsplit(")", 1)[1].split()[0] == "T"


def handles(work):
    root = workflow(work) / FIRST
    return [read(root / f"job-{row}.json") for row in (0, 1)]


def pause(work, launcher):
    JOBS["guest_work"](work)
    JOBS["observe"](work)
    owner = owner_process(work, launcher)
    require(owner is not None and alive(owner["identity"]), "original ready owner missing")
    original = handles(work)
    layout, overlap = read(work / "agent-jobs-layout.json"), read(work / "agent-jobs-observation.json")
    enrollment = read(workflow(work) / "workflow.json")
    require(enrollment["scheduling"] == "ready_rows_v1" and original[0]["binding"]["row_indices"] == [0]
            and original[1]["binding"]["row_indices"] == [1], "workflow did not enroll singleton ready rows")
    selected = [next(worker for worker in overlap["workers"]
                     if layout["provider_keys"][worker["node"]] == handle["provider_key"]) for handle in original]
    require(selected[0]["node"] != selected[1]["node"] and all(alive(w["worker"]) for w in selected)
            and all(w["dataset_file"]["sha256"] == h["binding"]["dataset_sha256"] for w,h in zip(selected, original))
            and not (workflow(work) / FIRST / "job-2.json").exists(), "initial exact row workers already changed")
    plan = dict(owner=owner, slow=selected[0], fast=selected[1], original_handles=original,
                pidfd_bound=True, signal="SIGSTOP", fixture_only=True)
    # Record identity before signaling, so error cleanup can always continue this exact worker.
    write(record(work, "pause-plan"), plan)
    print(f"Disposable guest only: pidfd SIGSTOP worker {selected[0]['worker']['pid']} on {selected[0]['node']}; "
          "keep the same owner, other broker and original worker lease unchanged.", flush=True)
    send_exact(selected[0]["worker"], signal.SIGSTOP)
    for _ in range(100):
        if stopped(selected[0]["worker"]):
            break
        time.sleep(0.01)
    require(stopped(selected[0]["worker"]) and alive(selected[1]["worker"]), "fixture did not pause only the first worker")
    write(record(work, "paused"), dict(plan=plan, observed_stopped=True, fast_alive=True,
          boottime_ns=JOBS["boot_ns"](), unix_seconds=int(time.time())))


def observe_ready(work):
    JOBS["guest_work"](work)
    plan = read(record(work, "pause-plan"))
    slow, fast = plan["slow"], plan["fast"]
    originals = plan["original_handles"]
    bound = originals[0]["binding"]["expires_unix_seconds"] - 15
    root = workflow(work) / FIRST
    prior = root / f"receipt-{originals[1]['binding']['job_id']}.json"
    deadline = min(time.monotonic() + 540, time.monotonic() + bound - time.time())
    while time.monotonic() < deadline:
        require(alive(plan["owner"]["identity"]) and stopped(slow["worker"]), "original slow worker/owner ended")
        try:
            if prior.is_file() and (root / "job-2.json").is_file():
                receipt, handle = read(prior), read(root / "job-2.json")
                require(receipt["handle"] == originals[1] and receipt["status"]["state"] == "complete"
                        and handle["binding"]["row_indices"] == [2] and handle["provider_key"] == originals[1]["provider_key"],
                        "freed broker did not admit the first never-leased row")
                current = JOBS["worker_snapshot"](work, fast["node"], fast["broker"], handle["binding"]["dataset_sha256"])
                if current and alive(current["worker"]):
                    require(not alive(fast["worker"]) and current["worker"] != fast["worker"]
                            and not (root / f"receipt-{originals[0]['binding']['job_id']}.json").exists()
                            and handles(work) == originals, "slow row ended or original handles changed before refill")
                    observed = dict(worker=current, handle=handle, completed_receipt=FOLLOW["retained_file"](prior, root.stat().st_uid),
                        slow_still_stopped=stopped(slow["worker"]), slow_receipt_absent=True, original_fast_worker_ended=True,
                        same_owner_alive=alive(plan["owner"]["identity"]), original_handles=originals,
                        boottime_ns=JOBS["boot_ns"](), unix_seconds=int(time.time()))
                    write(record(work, "refill"), observed)
                    # Existing cleanup also checks this actual new process family.
                    write(work / "agent-jobs-replacement-observation.json", dict(worker=current))
                    return
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # A create-new receipt may not yet have completed its durable write.
        time.sleep(0.025)
    raise ValueError("free broker did not refill before original paused lease expired")


def continue_worker(work, cleanup=False):
    JOBS["guest_work"](work)
    path = record(work, "pause-plan")
    if cleanup and not path.is_file():
        return
    plan = read(path)
    original = plan["original_handles"][0]
    if cleanup:
        if alive(plan["slow"]["worker"]):
            send_exact(plan["slow"]["worker"], signal.SIGCONT)
        return
    status, refill = read(record(work, "running-status")), read(record(work, "refill"))
    require(status["state"] == "running" and status["binding"] == original["binding"]
            and status["report_json"] is None and status["report_sha256"] is None
            and stopped(plan["slow"]["worker"]) and alive(plan["owner"]["identity"])
            and refill["unix_seconds"] <= int(time.time()) < original["binding"]["expires_unix_seconds"],
            "original protected Running status or original lease missing")
    before = JOBS["boot_ns"]()
    send_exact(plan["slow"]["worker"], signal.SIGCONT)
    write(record(work, "continued"), dict(worker=plan["slow"]["worker"], owner=plan["owner"], signal="SIGCONT",
          pidfd_bound=True, original_status=status, original_handle=original, boottime_ns=before,
          unix_seconds=int(time.time()), same_owner_alive=alive(plan["owner"]["identity"])))


def retained_tree(root):
    files, uid = {}, root.lstat().st_uid
    for count, path in enumerate(root.rglob("*")):
        name, metadata = path.relative_to(root).as_posix(), path.lstat()
        require(count < 64 and not path.is_symlink() and metadata.st_uid == uid, "ready tree ownership/bound")
        if stat.S_ISDIR(metadata.st_mode):
            require(name in {"package-0000", FIRST[:-1]} and stat.S_IMODE(metadata.st_mode) == 0o700,
                    "unexpected extra round/directory")
        else:
            require(name in {"workflow.json", ".workflow.lock", "package-0000/dataset.json", "package-0000/manifest.bin"}
                    or re.fullmatch(FIRST + r"(?:job-[0-3]|queue-plan|result|receipt-[0-9a-f]{32})\.json", name),
                    "unexpected ready retained file")
            files[name] = FOLLOW["retained_file"](path, uid)
    require(sum(item["bytes"] for item in files.values()) <= 4 * 1048576, "ready retained byte bound")
    return files


def parse_output(raw, resumed=False):
    require(0 < len(raw) <= 1048576, "ready stdout bound")
    values = [json.loads(line) for line in raw.splitlines()]
    require(1 <= len(values) <= 512, "ready stdout records")
    for value in values[:-1]:
        require(value["operation"] == "compute_workflow_progress", "unexpected nonfinal workflow output")
    final = values[-1]
    require(final["operation"] == "compute_workflow" and final["complete"] is True
            and final["scheduling"] == "ready_rows_v1" and final["follow"] is True
            and final["stopped"] == "complete" and final["pending_failure"] is False
            and final["rounds_this_invocation"] == (0 if resumed else 1)
            and final["maximum_rounds_per_window"] == 1 and final["maximum_seconds_per_worker"] == 600
            and final["completed_packages"] == final["package_count"] == 1,
            "one ready round or zero-work completed resume missing")
    return final


def output(path, resumed=False):
    raw = path.read_bytes()
    return dict(result=parse_output(raw, resumed), stdout=dict(**hashes(raw), hex=raw.hex()))


def check_output(value, resumed=False):
    raw = bytes.fromhex(value["stdout"]["hex"])
    require(hashes(raw) == {key:value["stdout"][key] for key in ("bytes", "sha256")}
            and parse_output(raw, resumed) == value["result"], "retained stdout differs from actual summary")


def capture(work):
    JOBS["guest_work"](work)
    owner = read(record(work, "pause-plan"))["owner"]
    require(not alive(owner["identity"]), "original workflow owner not reaped")
    write(record(work, "files"), dict(files=retained_tree(workflow(work)), owner_reaped=True,
          **output(work / f"{PREFIX}-output.jsonl")))


def before_resume(work):
    JOBS["guest_work"](work)
    plan, refill = read(record(work, "pause-plan")), read(record(work, "refill"))
    require(all(not alive(member) for item in (plan["slow"], plan["fast"], refill["worker"])
                for member in item["owned_processes"]), "old broker or worker still alive before completed resume")
    require(retained_tree(workflow(work)) == read(record(work, "files"), 12 * 1048576)["files"],
            "ready files changed while stopping brokers")
    write(record(work, "before-resume"), dict(original_brokers_ended=True, observed_workers_ended=True,
          boottime_ns=JOBS["boot_ns"]()))


def after_resume(work):
    JOBS["guest_work"](work)
    saved = read(record(work, "files"), 12 * 1048576)
    require(read(record(work, "before-resume"))["original_brokers_ended"] is True
            and retained_tree(workflow(work)) == saved["files"], "completed resume rewrote handles/receipts or admitted work")
    resumed = output(work / f"{PREFIX}-resume-output.jsonl", resumed=True)
    require(resumed["result"]["packages"] == saved["result"]["packages"], "completed resume changed exact outputs")
    write(record(work, "resumed"), dict(**resumed, files_unchanged=True, brokers_stopped=True))


def check_progress(plan, paused, refill, continued):
    original = plan["original_handles"]
    require(plan["fixture_only"] is True and plan["pidfd_bound"] is True and plan["signal"] == "SIGSTOP"
            and paused["plan"] == plan and paused["observed_stopped"] is True and paused["fast_alive"] is True,
            "not an explicit exact guest worker pause")
    require(refill["original_handles"] == original and all(refill[key] is True for key in
            ("slow_still_stopped", "slow_receipt_absent", "original_fast_worker_ended", "same_owner_alive"))
            and refill["handle"]["provider_key"] == original[1]["provider_key"]
            and refill["handle"]["binding"]["row_indices"] == [2]
            and refill["handle"]["binding"]["job_id"] not in [h["binding"]["job_id"] for h in original]
            and refill["handle"]["binding"]["model_fingerprint"] == original[0]["binding"]["model_fingerprint"],
            "refill retried an old row or used another model/peer")
    worker, fast = refill["worker"], plan["fast"]
    require(all(worker[key] == fast[key] for key in ("node", "broker", "service", "node_namespace", "runtime_lock_inode"))
            and worker["worker"] != fast["worker"] and worker["worker"] != plan["slow"]["worker"]
            and worker["dataset_file"]["sha256"] == refill["handle"]["binding"]["dataset_sha256"],
            "new row was not executed on actual newly freed broker")
    require(worker["runtime_lock_held"] is True and worker["network_devices"] == ["lo"]
            and worker["ipv4_routes"] == [] and worker["effective_capabilities"] == 0
            and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][path] for path in ("/runtime", "/model", "/dataset.json"))
            and all(worker["worker_namespaces"][kind] != worker["guest_namespaces"][kind]
                    for kind in ("net", "pid", "ipc", "mnt"))
            and worker["worker_namespaces"]["net"] != worker["node_namespace"], "refill worker isolation unobserved")
    status = continued["original_status"]
    require(continued["worker"] == plan["slow"]["worker"] and continued["owner"] == plan["owner"]
            and continued["same_owner_alive"] is True and continued["original_handle"] == original[0]
            and continued["signal"] == "SIGCONT" and continued["pidfd_bound"] is True
            and status["binding"] == original[0]["binding"] and status["state"] == "running"
            and status["report_json"] is None and status["report_sha256"] is None
            and 0 < paused["boottime_ns"] < refill["boottime_ns"] < continued["boottime_ns"]
            and paused["unix_seconds"] <= refill["unix_seconds"] <= continued["unix_seconds"]
            < original[0]["binding"]["expires_unix_seconds"], "slow original completed or lease changed before ready refill")


def check(value, revision):
    require(value["source_revision"] == revision, "wrong ready queue source snapshot")
    provision = value["provision"]
    require(provision["success"] is True and provision["installed_wheels"] == 38
            and provision["download_bytes"] == 523040250 and provision["training_performed"] is False,
            "ready scenario did not reuse one pinned provisioning")
    JOBS["check_overlap"](value["observation"])
    source, published, layout = value["source"], value["publish"], value["layout"]
    manifest = JOBS["source_manifest_id"](source, published)
    require(source["explicit_public_source"] is True and json.loads(source["dataset_json"]) == source["dataset"]
            and hashes(source["dataset_json"].encode()) == source["dataset_file"]
            and source["dataset"]["source_revision"] == revision and source["dataset"]["visibility"] == "public"
            and source["dataset"]["license"] == "GPL-3.0-only" and len(source["dataset"]["inference"]) == 4
            and published["operation"] == "offline_content_publish" and published["network_publication"] is False
            and published["bytes"] == source["dataset_file"]["bytes"], "original signed four-row public source changed")
    require(len(layout["provider_nodes"]) == 2
            and set(layout["provider_nodes"]) == {worker["node"] for worker in value["observation"]["workers"]}
            and all(CUSTODY["peer_key"](value["peers"][node]) == key for node,key in layout["provider_keys"].items())
            and layout["control_relay_peer_id"] not in [value["peers"][node] for node in layout["provider_nodes"]],
            "wrong actual provider graph")
    check_progress(value["pause-plan"], value["paused"], value["refill"], value["continued"])
    plan, retained = value["pause-plan"], value["files"]
    check_output(retained)
    files, decode = retained["files"], FOLLOW["decode"]
    enrollment = decode(files, "workflow.json")
    require(enrollment["scheduling"] == "ready_rows_v1" and enrollment["packages"] == [dict(
        publisher_key=published["publisher_key_hex"], manifest_id=manifest, dataset_sha256=source["dataset_file"]["sha256"], rows=4)]
        and enrollment["provider_keys"] == [layout["provider_keys"][node] for node in layout["provider_nodes"]]
        and decode(files, "package-0000/dataset.json", True) == source["dataset_json"].encode()
        and decode(files, "package-0000/manifest.bin", True) == bytes.fromhex(source["manifest_hex"]),
        "ready enrollment replaced original source or providers")
    result = decode(files, FIRST + "result.json")
    require(result["operation"] == "compute_ready_queue" and result["scheduling"] == "ready_rows_v1"
            and result["complete"] is True and result["dataset_manifest_id"] == manifest
            and result["never_submitted_rows"] == [] and len(result["jobs"]) == len(result["outputs"]) == 4,
            "ready queue did not complete exactly four singleton jobs")
    queue = decode(files, FIRST + "queue-plan.json")
    require(set(queue) == {"version", "scheduling", "publisher_key", "dataset_manifest_id", "dataset_sha256",
            "source_expires_unix_seconds", "model_fingerprint", "task", "provider_keys", "ready_rows",
            "pending_job_ids", "planned_at_unix_seconds"}
            and queue["version"] == 1 and queue["scheduling"] == "ready_rows_v1"
            and queue["publisher_key"] == published["publisher_key_hex"] and queue["dataset_manifest_id"] == manifest
            and queue["dataset_sha256"] == source["dataset_file"]["sha256"]
            and queue["source_expires_unix_seconds"] == published["expires_unix_seconds"]
            and queue["model_fingerprint"] == plan["original_handles"][0]["binding"]["model_fingerprint"]
            and queue["task"] is None and queue["provider_keys"] == enrollment["provider_keys"]
            and queue["ready_rows"] == [0, 1, 2, 3] and queue["pending_job_ids"] == []
            and enrollment["verified_at_unix_seconds"] <= queue["planned_at_unix_seconds"]
            < queue["source_expires_unix_seconds"], "queue plan replaced original source/model or original work set")
    expected = {"workflow.json", ".workflow.lock", "package-0000/dataset.json", "package-0000/manifest.bin",
                FIRST + "queue-plan.json", FIRST + "result.json"}
    jobs, statuses, response_bytes = [], [], dict.fromkeys(layout["provider_nodes"], 0)
    for row in range(4):
        name = FIRST + f"job-{row}.json"
        handle = decode(files, name)
        node = next(node for node,key in layout["provider_keys"].items() if key == handle["provider_key"])
        JOBS["check_loss_handle"](handle, source["dataset"], published, manifest, node, layout)
        require(handle["binding"]["row_indices"] == [row] and handle["binding"].get("task") is None
                and handle["binding"]["model_fingerprint"] == plan["original_handles"][0]["binding"]["model_fingerprint"]
                and 0 < handle["binding"]["expires_unix_seconds"] - files[name]["modified_unix_ns"] // 1000000000 <= 600,
                "row/source/model/lease differs")
        path = FIRST + f"receipt-{handle['binding']['job_id']}.json"
        receipt = decode(files, path)
        require(receipt["version"] == 1 and receipt["handle"] == handle
                and receipt["verified_at_unix_seconds"] >= enrollment["verified_at_unix_seconds"], "unchecked retained receipt")
        status = receipt["status"]
        JOBS["check_loss_completed"](status, handle, revision, result["outputs"][row])
        part = next(item for item in result["jobs"] if item["handle"] == handle)
        require(part["state"] == "complete" and part["report_sha256"] == status["report_sha256"]
                and part["new_submission"] is True, "ready result does not bind its original new singleton")
        jobs.append(handle); statuses.append(status)
        response_bytes[node] += len(status["report_json"].encode())
        expected.update((name, path))
    require(len({h["binding"]["job_id"] for h in jobs}) == 4 and set(files) == expected
            and jobs[:2] == plan["original_handles"] and jobs[2] == value["refill"]["handle"]
            and decode(files, FIRST + f"receipt-{jobs[1]['binding']['job_id']}.json")["status"]["state"] == "complete"
            and files[FIRST + f"receipt-{jobs[1]['binding']['job_id']}.json"] == value["refill"]["completed_receipt"],
            "extra jobs/attempts or original completed receipt changed")
    for row, member in enumerate((plan["slow"], plan["fast"], value["refill"]["worker"])):
        require(member["dataset_json"] == JOBS["derive"](source["dataset"], [row]), "actual worker received wrong singleton row")
    package = retained["result"]["packages"][0]
    require(retained["owner_reaped"] is True and package["complete"] is True and package["attempts"] == 1
            and package["pending_handles"] == [] and package["dataset_manifest_id"] == manifest
            and package["outputs"] == [dict(output, report_sha256=status["report_sha256"])
                                      for output,status in zip(result["outputs"], statuses)], "workflow lost ordered exact outputs")
    resumed = value["resumed"]
    check_output(resumed, resumed=True)
    require(resumed["files_unchanged"] is True and resumed["brokers_stopped"] is True
            and value["before-resume"]["original_brokers_ended"] is True
            and value["before-resume"]["observed_workers_ended"] is True
            and resumed["result"]["rounds_this_invocation"] == 0
            and resumed["result"]["packages"] == retained["result"]["packages"], "completed resume dispatched or replaced results")
    CUSTODY["validate_path"](value["path"], value["peers"], layout, "inspect")
    application = value["path"]["privacy"]["exit"]["provider_application"]
    require(all(application[node]["request_packets"] > 0 and application[node]["response_payload_bytes"] >= count
                for node,count in response_bytes.items()), "protected paths did not carry original reports")
    require(all(value["cleanup"].values()), "owned ready work remains")


def evidence(work, revision):
    JOBS["guest_work"](work)
    value = {name:read(work / f"agent-jobs-{name}.json") for name in ("source", "publish", "layout", "observation", "provision")}
    value.update({name:read(record(work, name), 12 * 1048576) for name in
                  ("pause-plan", "paused", "refill", "continued", "files", "before-resume", "resumed")})
    value.update(source_revision=revision, peers=read(work / "a01-expected-peers.json"),
        cleanup=read(work / "agent-jobs-private-cleanup.json"), path=dict(
        selected_route=read(work / "content-custody-fetch-live-selection.json"),
        privacy={role:read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
        control_privacy=read(work / "content-provider-custody-fetch-control.json"), gates=read(work / "content-custody-fetch-gates.json")))
    check(value, revision)
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    path = record(work, "evidence")
    value = read(path, 16 * 1048576) if path.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(record(work, "smoke"), dict(report_kind=KIND, source_revision=revision, scope=SCOPE,
        success=status == 0 and complete and remaining == 0 and value is not None,
        phase=phase, observed_blocker=None if blocker == "NONE" else blocker, runner_exit_status=status,
        evidence=value, cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host,
        exactly_once_execution_claimed=False, original_lease_extension_claimed=False, full_b03_claimed=False, full_alpha_claimed=False))


def report(value, revision):
    require(value["report_kind"] == KIND and value["scope"] == SCOPE and value["source_revision"] == revision
            and value["success"] is True and value["runner_exit_status"] == 0 and value["observed_blocker"] is None
            and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "ready/cleanup/host proof incomplete")
    require(all(value[key] is False for key in ("exactly_once_execution_claimed", "original_lease_extension_claimed",
                                               "full_b03_claimed", "full_alpha_claimed")), "unsupported ready queue claim")
    check(value["evidence"], revision)


def synthetic_contract():
    """Parser inputs only; fake process records and manifest signature never prove execution."""
    value = JOBS["self_test"]()
    source = value["source"]
    source["dataset"]["inference"] += copy.deepcopy(source["dataset"]["inference"])
    source["dataset_json"] = json.dumps(source["dataset"])
    source["dataset_file"] = hashes(source["dataset_json"].encode())
    value["publish"]["bytes"] = source["dataset_file"]["bytes"]
    originals = [part["handle"] for part in value["result"]["jobs"]]
    model = originals[0]["binding"]["model_fingerprint"]
    jobs, statuses, outputs = [], [], []
    for row in range(4):
        peer = row if row < 2 else (1 if row == 2 else 0)
        handle = copy.deepcopy(originals[peer])
        handle["binding"].update(job_id=str(row) * 32, row_indices=[row],
            dataset_sha256=hashes(JOBS["derive"](source["dataset"], [row]).encode())["sha256"])
        report_value = json.loads(value["statuses"][peer]["report_json"])
        report_value["dataset"]["sha256"] = handle["binding"]["dataset_sha256"]
        raw = json.dumps(report_value)
        status = dict(binding=handle["binding"], state="complete", report_json=raw,
                      report_sha256=hashes(raw.encode())["sha256"])
        jobs.append(handle); statuses.append(status)
        outputs.append(dict(sample_index=row, provider_key=handle["provider_key"],
                            job_id=handle["binding"]["job_id"], text=report_value["outputs"][0]["text"]))
    for row, worker in enumerate(value["observation"]["workers"]):
        worker["service"] = dict(pid=10 + row, start_ticks=100)
        worker["dataset_json"] = JOBS["derive"](source["dataset"], [row])
        worker["dataset_file"] = hashes(worker["dataset_json"].encode())
    slow, fast = value["observation"]["workers"]
    owner = dict(identity=dict(pid=1000, start_ticks=100), operation="compute peer workflow", follow=True,
                 manual_resume=False, maximum_rounds_per_window=1, maximum_seconds_per_worker=600)
    plan = dict(owner=owner, slow=slow, fast=fast, original_handles=jobs[:2], pidfd_bound=True, signal="SIGSTOP", fixture_only=True)
    value["pause-plan"] = copy.deepcopy(plan)
    value["paused"] = dict(plan=copy.deepcopy(plan), observed_stopped=True, fast_alive=True, boottime_ns=1000, unix_seconds=1700)
    files = {}
    def put(name, item):
        raw = item if isinstance(item, bytes) else json.dumps(item).encode()
        files[name] = dict(**hashes(raw), hex=raw.hex(), inode=[1, len(files) + 1], modified_unix_ns=1500 * 1000000000)
    manifest = source["manifest"]["sha256"]
    providers = [value["layout"]["provider_keys"][node] for node in value["layout"]["provider_nodes"]]
    put(".workflow.lock", b"")
    put("workflow.json", dict(version=1, scheduling="ready_rows_v1", verified_at_unix_seconds=1400,
        provider_keys=providers, packages=[dict(publisher_key=value["publish"]["publisher_key_hex"],
            manifest_id=manifest, dataset_sha256=source["dataset_file"]["sha256"], rows=4)]))
    put("package-0000/dataset.json", source["dataset_json"].encode())
    put("package-0000/manifest.bin", bytes.fromhex(source["manifest_hex"]))
    put(FIRST + "queue-plan.json", dict(version=1, scheduling="ready_rows_v1",
        publisher_key=value["publish"]["publisher_key_hex"], dataset_manifest_id=manifest,
        dataset_sha256=source["dataset_file"]["sha256"], source_expires_unix_seconds=value["publish"]["expires_unix_seconds"],
        model_fingerprint=model, task=None, provider_keys=providers, ready_rows=[0, 1, 2, 3],
        pending_job_ids=[], planned_at_unix_seconds=1500))
    for row, (handle, status) in enumerate(zip(jobs, statuses)):
        put(FIRST + f"job-{row}.json", handle)
        put(FIRST + f"receipt-{handle['binding']['job_id']}.json",
            dict(version=1, handle=handle, status=status, verified_at_unix_seconds=1600))
    result = dict(operation="compute_ready_queue", scheduling="ready_rows_v1", complete=True,
        dataset_manifest_id=manifest, never_submitted_rows=[], outputs=outputs,
        jobs=[dict(handle=handle, state="complete", report_sha256=status["report_sha256"], new_submission=True)
              for handle,status in zip(jobs, statuses)])
    put(FIRST + "result.json", result)
    worker = copy.deepcopy(fast)
    worker["worker"] = dict(pid=999, start_ticks=200)
    worker["dataset_json"] = JOBS["derive"](source["dataset"], [2])
    worker["dataset_file"] = hashes(worker["dataset_json"].encode())
    value["refill"] = dict(worker=worker, handle=jobs[2],
        completed_receipt=copy.deepcopy(files[FIRST + f"receipt-{jobs[1]['binding']['job_id']}.json"]),
        slow_still_stopped=True, slow_receipt_absent=True, original_fast_worker_ended=True, same_owner_alive=True,
        original_handles=copy.deepcopy(jobs[:2]), boottime_ns=2000, unix_seconds=1701)
    value["continued"] = dict(worker=copy.deepcopy(slow["worker"]), owner=copy.deepcopy(owner), signal="SIGCONT", pidfd_bound=True,
        original_status=dict(binding=copy.deepcopy(jobs[0]["binding"]), state="running", report_json=None, report_sha256=None),
        original_handle=copy.deepcopy(jobs[0]), boottime_ns=3000, unix_seconds=1702, same_owner_alive=True)
    summary = dict(operation="compute_workflow", scheduling="ready_rows_v1", complete=True, follow=True,
        stopped="complete", pending_failure=False, rounds_this_invocation=1, maximum_rounds_per_window=1,
        maximum_seconds_per_worker=600, completed_packages=1, package_count=1,
        packages=[dict(complete=True, attempts=1, pending_handles=[], dataset_manifest_id=manifest,
            outputs=[dict(item, report_sha256=status["report_sha256"]) for item,status in zip(outputs, statuses)])])
    raw = json.dumps(summary).encode()
    value["files"] = dict(files=files, owner_reaped=True, result=summary, stdout=dict(**hashes(raw), hex=raw.hex()))
    value["before-resume"] = dict(original_brokers_ended=True, observed_workers_ended=True, boottime_ns=4000)
    resumed = dict(summary, rounds_this_invocation=0)
    raw = json.dumps(resumed).encode()
    value["resumed"] = dict(result=resumed, stdout=dict(**hashes(raw), hex=raw.hex()), files_unchanged=True, brokers_stopped=True)
    return value


def self_test():
    value = synthetic_contract()
    check(value, "a" * 40)
    changes = {
        "slow_no_longer_paused": lambda x:x["refill"].update(slow_still_stopped=False),
        "barrier_not_refilled": lambda x:x["refill"]["handle"]["binding"].update(row_indices=[0]),
        "wrong_broker": lambda x:x["refill"]["worker"].update(node=x["pause-plan"]["slow"]["node"]),
        "same_worker": lambda x:x["refill"]["worker"].update(worker=x["pause-plan"]["fast"]["worker"]),
        "original_completed_before_refill": lambda x:x["continued"]["original_status"].update(state="complete"),
        "original_lease_renewed": lambda x:x["continued"]["original_handle"]["binding"].update(expires_unix_seconds=3000),
        "owner_replaced": lambda x:x["continued"]["owner"]["identity"].update(pid=9999),
        "resume_new_work": lambda x:x["resumed"]["result"].update(rounds_this_invocation=1),
        "resume_rewrites_receipts": lambda x:x["resumed"].update(files_unchanged=False),
        "completed_receipt_changed": lambda x:x["refill"]["completed_receipt"].update(sha256="0" * 64),
        "extra_attempt": lambda x:x["files"]["files"].update({"package-0000/attempt-0001/job-0.json":{}}),
        "protected_capture_missing": lambda x:x["path"]["privacy"].pop("exit"),
        "cleanup_incomplete": lambda x:x["cleanup"].update(done=False),
    }
    for name, alter in changes.items():
        bad = copy.deepcopy(value)
        alter(bad)
        try:
            check(bad, "a" * 40)
        except (ValueError, KeyError, StopIteration):
            pass
        else:
            raise AssertionError("invalid ready queue proof accepted: " + name)
    print("ready queue exact refill/lease/receipt/resume positive + 13 negative pure checks PASS; no signal, model or network proof")


def main(args):
    command = args[0]
    if command == "self-test": self_test()
    elif command == "source": source(Path(args[1]), args[2])
    elif command == "prepare": prepare(Path(args[1]), args[2])
    elif command == "pause": pause(Path(args[1]), int(args[2]))
    elif command == "observe-ready": observe_ready(Path(args[1]))
    elif command == "continue-worker": continue_worker(Path(args[1]))
    elif command == "cleanup-worker": continue_worker(Path(args[1]), cleanup=True)
    elif command == "capture": capture(Path(args[1]))
    elif command == "before-resume": before_resume(Path(args[1]))
    elif command == "after-resume": after_resume(Path(args[1]))
    elif command == "evidence": evidence(Path(args[1]), args[2])
    elif command == "finalize": finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif command == "report": report(read(Path(args[1]), 16 * 1048576), args[2])
    else: raise ValueError("unknown fixed ready-queue fixture command")


if __name__ == "__main__":
    main(sys.argv[1:])
