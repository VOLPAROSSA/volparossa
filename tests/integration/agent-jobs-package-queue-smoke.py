#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Two signed packages share real broker slots fairly while one exact worker is paused."""
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
READY = runpy.run_path(str(HERE / "agent-jobs-ready-queue-smoke.py"))
FOLLOW, JOBS, CUSTODY = READY["FOLLOW"], READY["JOBS"], READY["CUSTODY"]
read, write, require = READY["read"], READY["write"], READY["require"]
alive, identity, hashes = READY["alive"], READY["identity"], READY["hashes"]
send_exact, stopped = READY["send_exact"], READY["stopped"]
PREFIX = "agent-jobs-package-queue"
KIND = "volparossa-public-package-ready-queue"
SCOPE = ("two separately signed two-row public packages and two actual fixed-model brokers share one "
         "round-robin ready queue in one owner invocation. Exact guest-only pidfd pause of A0 leaves its "
         "original lease occupied; the free broker finishes B0 and A1 then executes B1 before A0 resumes. "
         "Four original ordered results, source-specific receipts and zero-work completed resume with both "
         "brokers stopped. Pause is fixture orchestration, not product behavior. Not private computation, "
         "exactly-once execution, source discovery, answer quality, full B03 or full alpha.")


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def workflow(work):
    return work / "state-client/compute-source/package-queue"


def attempt(package):
    return f"package-{package:04d}/attempt-0000/"


def second_source(root):
    JOBS["private"](root, "compute-source")
    value = read(root / "dataset.json")
    require(len(value["inference"]) == 2, "first public source must have two rows")
    value["inference"] = [
        dict(question="Does every parallel path have its own relay?", context=value["inference"][0]["context"]),
        dict(question="Is a direct client-to-exit dataplane normal?", context=value["inference"][1]["context"]),
    ]
    write(root / "dataset-b.json", value)


def publication_b(root):
    JOBS["private"](root, "compute-source")
    return dict(dataset=read(root / "dataset-b.json"), dataset_file=JOBS["file_hash"](root / "dataset-b.json", 1048576),
        dataset_json=(root / "dataset-b.json").read_text(), manifest=JOBS["file_hash"](root / "manifest-b.pb", 65536),
        manifest_hex=(root / "manifest-b.pb").read_bytes().hex(), explicit_public_source=True)


def prepare(root, publisher):
    JOBS["private"](root, "compute-source")
    require(re.fullmatch(r"[0-9a-f]{64}", publisher), "invalid shared source publisher")
    write(root / "package-queue-plan.json", dict(version=1, packages=[
        dict(dataset=str(root / dataset), dataset_manifest=str(root / manifest), publisher_key=publisher)
        for dataset,manifest in (("dataset.json", "manifest.pb"), ("dataset-b.json", "manifest-b.pb"))]))


def owner_process(work, launcher):
    for member in JOBS["TRAIN"]["descendants"](launcher):
        try:
            proc = Path(f"/proc/{member['pid']}")
            args = [arg.decode() for arg in (proc / "cmdline").read_bytes().split(b"\0") if arg]
            if Path(os.readlink(proc / "exe")).name != "volparossa" or args[3:6] != ["compute", "peer", "workflow"]:
                continue
            require("--follow" in args and "--resume" not in args and "--execute" in args
                and args[args.index("--max-batches") + 1] == "2"
                and args[args.index("--max-seconds") + 1] == "600"
                and args[args.index("--directory") + 1] == str(workflow(work)), "wrong package queue owner")
            require(proc.stat().st_uid == workflow(work).stat().st_uid != 0, "owner is not node user")
            return dict(identity=member, operation="compute peer workflow", follow=True, manual_resume=False,
                        maximum_rounds_per_window=2, maximum_seconds_per_worker=600)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return None


def initial_handles(work):
    return [read(workflow(work) / attempt(package) / "job-0.json") for package in (0, 1)]


def pause(work, launcher):
    JOBS["guest_work"](work)
    JOBS["observe"](work)
    owner, originals = owner_process(work, launcher), initial_handles(work)
    layout, overlap = read(work / "agent-jobs-layout.json"), read(work / "agent-jobs-observation.json")
    require(owner is not None and alive(owner["identity"]), "original shared queue owner missing")
    enrollment = read(workflow(work) / "workflow.json")
    require(enrollment["scheduling"] == "ready_rows_v1" and len(enrollment["packages"]) == 2
            and all(h["binding"]["row_indices"] == [0] for h in originals), "initial round was not A0+B0")
    selected = [next(w for w in overlap["workers"] if layout["provider_keys"][w["node"]] == h["provider_key"])
                for h in originals]
    require(selected[0]["node"] != selected[1]["node"] and all(alive(w["worker"]) for w in selected)
            and all(w["dataset_file"]["sha256"] == h["binding"]["dataset_sha256"] for w,h in zip(selected, originals))
            and all(not (workflow(work) / attempt(p) / "job-1.json").exists() for p in (0, 1)),
            "two original package workers changed before pause")
    plan = dict(owner=owner, slow=selected[0], fast=selected[1], original_handles=originals,
                pidfd_bound=True, signal="SIGSTOP", fixture_only=True)
    write(record(work, "pause-plan"), plan)
    print(f"Disposable guest only: pidfd SIGSTOP exact package A0 worker {selected[0]['worker']['pid']} on "
          f"{selected[0]['node']}; preserve owner, shared broker slots, both signed sources and original lease.", flush=True)
    send_exact(selected[0]["worker"], signal.SIGSTOP)
    for _ in range(100):
        if stopped(selected[0]["worker"]): break
        time.sleep(0.01)
    require(stopped(selected[0]["worker"]) and alive(selected[1]["worker"]), "pause did not isolate A0")
    write(record(work, "paused"), dict(plan=plan, observed_stopped=True, fast_alive=True,
          boottime_ns=JOBS["boot_ns"](), unix_seconds=int(time.time())))


def observe_ready(work):
    JOBS["guest_work"](work)
    plan = read(record(work, "pause-plan"))
    slow, fast = plan["slow"], plan["fast"]
    originals, root = plan["original_handles"], workflow(work)
    deadline = min(time.monotonic() + 540, time.monotonic() + originals[0]["binding"]["expires_unix_seconds"] - 15 - time.time())
    b0_receipt = root / attempt(1) / f"receipt-{originals[1]['binding']['job_id']}.json"
    intermediate = None
    while time.monotonic() < deadline:
        require(alive(plan["owner"]["identity"]) and stopped(slow["worker"]), "paused A0 worker or original owner ended")
        try:
            a1_path = root / attempt(0) / "job-1.json"
            if b0_receipt.is_file() and a1_path.is_file():
                first_receipt, a1 = read(b0_receipt), read(a1_path)
                require(first_receipt["handle"] == originals[1] and first_receipt["status"]["state"] == "complete"
                        and a1["binding"]["row_indices"] == [1] and a1["provider_key"] == originals[1]["provider_key"],
                        "free broker did not fairly refill package A after package B")
                if intermediate is None:
                    worker = JOBS["worker_snapshot"](work, fast["node"], fast["broker"], a1["binding"]["dataset_sha256"])
                    if worker and alive(worker["worker"]):
                        intermediate = dict(worker=worker, handle=a1, completed_receipt=FOLLOW["retained_file"](b0_receipt, root.stat().st_uid),
                                            boottime_ns=JOBS["boot_ns"](), unix_seconds=int(time.time()))
                        write(record(work, "intermediate"), intermediate)
                a1_receipt = root / attempt(0) / f"receipt-{a1['binding']['job_id']}.json"
                b1_path = root / attempt(1) / "job-1.json"
                if intermediate and a1_receipt.is_file() and b1_path.is_file():
                    receipt, b1 = read(a1_receipt), read(b1_path)
                    require(receipt["handle"] == a1 and receipt["status"]["state"] == "complete"
                            and b1["binding"]["row_indices"] == [1] and b1["provider_key"] == originals[1]["provider_key"],
                            "free broker did not return to the second package")
                    current = JOBS["worker_snapshot"](work, fast["node"], fast["broker"], b1["binding"]["dataset_sha256"])
                    if current and alive(current["worker"]):
                        require(not alive(fast["worker"]) and not alive(intermediate["worker"]["worker"])
                                and not (root / attempt(0) / f"receipt-{originals[0]['binding']['job_id']}.json").exists()
                                and initial_handles(work) == originals, "original work changed before package refill")
                        write(record(work, "refill"), dict(worker=current, handle=b1, intermediate=intermediate,
                            completed_receipt=FOLLOW["retained_file"](a1_receipt, root.stat().st_uid),
                            slow_still_stopped=stopped(slow["worker"]), slow_receipt_absent=True,
                            original_fast_worker_ended=True, intermediate_worker_ended=True,
                            same_owner_alive=alive(plan["owner"]["identity"]), original_handles=originals,
                            boottime_ns=JOBS["boot_ns"](), unix_seconds=int(time.time())))
                        write(work / "agent-jobs-replacement-observation.json", dict(worker=current))
                        return
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.025)
    raise ValueError("A1 then B1 did not execute while original package A0 lease was still occupied")


def retained_tree(root):
    files, uid = {}, root.lstat().st_uid
    directories = {f"package-{p:04d}" for p in (0, 1)} | {attempt(p)[:-1] for p in (0, 1)}
    for count,path in enumerate(root.rglob("*")):
        name, metadata = path.relative_to(root).as_posix(), path.lstat()
        require(count < 96 and not path.is_symlink() and metadata.st_uid == uid, "package tree ownership/bound")
        if stat.S_ISDIR(metadata.st_mode):
            require(name in directories and stat.S_IMODE(metadata.st_mode) == 0o700, "unexpected extra package/attempt")
        else:
            require(name in {"workflow.json", ".workflow.lock"}
                or re.fullmatch(r"package-000[01]/(?:dataset.json|manifest.bin)", name)
                or re.fullmatch(r"package-000[01]/attempt-0000/(?:job-[01]|queue-plan|result|receipt-[0-9a-f]{32})\.json", name),
                "unexpected retained package file")
            files[name] = FOLLOW["retained_file"](path, uid)
    require(sum(f["bytes"] for f in files.values()) <= 4 * 1048576, "retained package byte bound")
    return files


def parse_output(raw, resumed=False):
    require(0 < len(raw) <= 1048576, "package queue stdout bound")
    values = [json.loads(line) for line in raw.splitlines()]
    require(1 <= len(values) <= 512 and all(v["operation"] == "compute_workflow_progress" for v in values[:-1]),
            "unexpected package workflow progress")
    final = values[-1]
    require(final["operation"] == "compute_workflow" and final["complete"] is True
        and final["scheduling"] == "ready_rows_v1" and final["follow"] is True and final["stopped"] == "complete"
        and final["pending_failure"] is False and final["rounds_this_invocation"] == (0 if resumed else 2)
        and final["maximum_rounds_per_window"] == 2 and final["maximum_seconds_per_worker"] == 600
        and final["completed_packages"] == final["package_count"] == 2, "two-package shared round incomplete")
    return final


def check_progress(plan, paused, refill, continued):
    original = plan["original_handles"]
    intermediate = refill["intermediate"]
    require(plan["fixture_only"] is True and plan["pidfd_bound"] is True and plan["signal"] == "SIGSTOP"
        and paused["plan"] == plan and paused["observed_stopped"] is True and paused["fast_alive"] is True
        and refill["original_handles"] == original and all(refill[k] is True for k in
            ("slow_still_stopped", "slow_receipt_absent", "original_fast_worker_ended", "same_owner_alive")),
        "not an exact guest-only original-worker pause")
    require(refill["handle"]["binding"]["row_indices"] == [1]
        and intermediate["handle"]["binding"]["row_indices"] == [1]
        and intermediate["handle"]["binding"]["dataset_manifest_id"] == original[0]["binding"]["dataset_manifest_id"]
        and refill["handle"]["binding"]["dataset_manifest_id"] == original[1]["binding"]["dataset_manifest_id"]
        and original[0]["binding"]["dataset_manifest_id"] != original[1]["binding"]["dataset_manifest_id"]
        and refill["intermediate_worker_ended"] is True
        and paused["boottime_ns"] < intermediate["boottime_ns"] < refill["boottime_ns"]
        and paused["unix_seconds"] <= intermediate["unix_seconds"] <= refill["unix_seconds"],
        "fair A0/B0/A1/B1 source-bound order missing")
    for item in (intermediate, refill):
        worker, handle, fast = item["worker"], item["handle"], plan["fast"]
        require(handle["provider_key"] == original[1]["provider_key"]
            and handle["binding"]["model_fingerprint"] == original[0]["binding"]["model_fingerprint"]
            and handle["binding"]["job_id"] not in [h["binding"]["job_id"] for h in original]
            and all(worker[k] == fast[k] for k in ("node", "broker", "service", "node_namespace", "runtime_lock_inode"))
            and worker["worker"] != fast["worker"] and worker["worker"] != plan["slow"]["worker"]
            and worker["dataset_file"]["sha256"] == handle["binding"]["dataset_sha256"], "refill not on freed broker")
        require(worker["runtime_lock_held"] is True and worker["network_devices"] == ["lo"]
            and worker["ipv4_routes"] == [] and worker["effective_capabilities"] == 0
            and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][p] for p in ("/runtime", "/model", "/dataset.json"))
            and all(worker["worker_namespaces"][k] != worker["guest_namespaces"][k] for k in ("net", "pid", "ipc", "mnt"))
            and worker["worker_namespaces"]["net"] != worker["node_namespace"], "package worker isolation unobserved")
    require(intermediate["worker"]["worker"] != refill["worker"]["worker"], "A1/B1 reused one worker proof")
    status = continued["original_status"]
    require(continued["worker"] == plan["slow"]["worker"] and continued["owner"] == plan["owner"]
        and continued["same_owner_alive"] is True and continued["original_handle"] == original[0]
        and continued["signal"] == "SIGCONT" and continued["pidfd_bound"] is True
        and status["binding"] == original[0]["binding"] and status["state"] == "running"
        and status["report_json"] is None and status["report_sha256"] is None
        and 0 < paused["boottime_ns"] < intermediate["boottime_ns"] < refill["boottime_ns"] < continued["boottime_ns"]
        and paused["unix_seconds"] <= intermediate["unix_seconds"] <= refill["unix_seconds"] <= continued["unix_seconds"]
        < original[0]["binding"]["expires_unix_seconds"], "original A0 not Running under original lease during cross-package refill")


def check(value, revision):
    require(value["source_revision"] == revision, "wrong package queue source snapshot")
    provision, layout = value["provision"], value["layout"]
    require(provision["success"] is True and provision["installed_wheels"] == 38
        and provision["download_bytes"] == 523040250 and provision["training_performed"] is False, "pinned provisioning differs")
    JOBS["check_overlap"](value["observation"])
    require(len(layout["provider_nodes"]) == 2
        and set(layout["provider_nodes"]) == {w["node"] for w in value["observation"]["workers"]}
        and all(CUSTODY["peer_key"](value["peers"][n]) == k for n,k in layout["provider_keys"].items())
        and layout["control_relay_peer_id"] not in [value["peers"][n] for n in layout["provider_nodes"]], "wrong provider graph")
    check_progress(value["pause-plan"], value["paused"], value["refill"], value["continued"])
    retained, plan = value["files"], value["pause-plan"]
    READY["check_output"](retained)
    files, decode = retained["files"], FOLLOW["decode"]
    enrollment = decode(files, "workflow.json")
    providers = [layout["provider_keys"][n] for n in layout["provider_nodes"]]
    require(enrollment["scheduling"] == "ready_rows_v1" and enrollment["provider_keys"] == providers
        and len(enrollment["packages"]) == 2 and retained["owner_reaped"] is True, "shared enrollment/owner mismatch")
    expected, all_jobs, response_bytes = {"workflow.json", ".workflow.lock"}, [], dict.fromkeys(layout["provider_nodes"], 0)
    source_ids = []
    observed = [(plan["slow"], 0, 0), (plan["fast"], 1, 0),
                (value["refill"]["intermediate"]["worker"], 0, 1), (value["refill"]["worker"], 1, 1)]
    for p,(source,published) in enumerate(zip(value["sources"], value["publications"])):
        manifest = JOBS["source_manifest_id"](source, published)
        source_ids.append(manifest)
        package_root, first = f"package-{p:04d}/", attempt(p)
        require(source["explicit_public_source"] is True and json.loads(source["dataset_json"]) == source["dataset"]
            and hashes(source["dataset_json"].encode()) == source["dataset_file"]
            and source["dataset"]["source_revision"] == revision and source["dataset"]["visibility"] == "public"
            and source["dataset"]["license"] == "GPL-3.0-only" and len(source["dataset"]["inference"]) == 2
            and published["operation"] == "offline_content_publish" and published["network_publication"] is False
            and published["bytes"] == source["dataset_file"]["bytes"]
            and published["publisher_key_hex"] == value["publications"][0]["publisher_key_hex"], "signed package changed")
        require(enrollment["packages"][p] == dict(publisher_key=published["publisher_key_hex"], manifest_id=manifest,
            dataset_sha256=source["dataset_file"]["sha256"], rows=2)
            and decode(files, package_root + "dataset.json", True) == source["dataset_json"].encode()
            and decode(files, package_root + "manifest.bin", True) == bytes.fromhex(source["manifest_hex"]), "source package rebound")
        result, queue = decode(files, first + "result.json"), decode(files, first + "queue-plan.json")
        require(result["operation"] == "compute_ready_queue" and result["scheduling"] == "ready_rows_v1"
            and result["complete"] is True and result["dataset_manifest_id"] == manifest
            and result["never_submitted_rows"] == [] and len(result["jobs"]) == len(result["outputs"]) == 2, "package result incomplete")
        require(queue == dict(version=1, scheduling="ready_rows_v1", publisher_key=published["publisher_key_hex"],
            dataset_manifest_id=manifest, dataset_sha256=source["dataset_file"]["sha256"],
            source_expires_unix_seconds=published["expires_unix_seconds"], model_fingerprint=plan["original_handles"][0]["binding"]["model_fingerprint"],
            task=None, provider_keys=providers, ready_rows=[0, 1], pending_job_ids=[], planned_at_unix_seconds=queue["planned_at_unix_seconds"])
            and enrollment["verified_at_unix_seconds"] <= queue["planned_at_unix_seconds"] < queue["source_expires_unix_seconds"],
            "package plan modified source/TTL/model/rows")
        expected.update((package_root + "dataset.json", package_root + "manifest.bin", first + "queue-plan.json", first + "result.json"))
        statuses = []
        for row in (0, 1):
            name = first + f"job-{row}.json"
            handle = decode(files, name)
            node = next(n for n,k in layout["provider_keys"].items() if k == handle["provider_key"])
            JOBS["check_loss_handle"](handle, source["dataset"], published, manifest, node, layout)
            require(handle["binding"]["row_indices"] == [row] and handle["binding"].get("task") is None
                and handle["binding"]["model_fingerprint"] == plan["original_handles"][0]["binding"]["model_fingerprint"]
                and 0 < handle["binding"]["expires_unix_seconds"] - files[name]["modified_unix_ns"] // 1000000000 <= 600,
                "row/model/original lease differs")
            path = first + f"receipt-{handle['binding']['job_id']}.json"
            receipt = decode(files, path)
            require(receipt["version"] == 1 and receipt["handle"] == handle
                    and receipt["verified_at_unix_seconds"] >= enrollment["verified_at_unix_seconds"], "unchecked source receipt")
            status = receipt["status"]
            JOBS["check_loss_completed"](status, handle, revision, result["outputs"][row])
            part = next(item for item in result["jobs"] if item["handle"] == handle)
            require(part["state"] == "complete" and part["report_sha256"] == status["report_sha256"]
                    and part["new_submission"] is True, "not original singleton result")
            wanted = plan["original_handles"][p] if row == 0 else value["refill"]["intermediate"]["handle"] if p == 0 else value["refill"]["handle"]
            require(handle == wanted, "observed handle differs from its retained package")
            if (p,row) == (1,0): require(files[path] == value["refill"]["intermediate"]["completed_receipt"], "B0 receipt rewritten")
            if (p,row) == (0,1): require(files[path] == value["refill"]["completed_receipt"], "A1 receipt rewritten")
            expected.update((name,path)); all_jobs.append(handle); statuses.append(status)
            response_bytes[node] += len(status["report_json"].encode())
        summary = retained["result"]["packages"][p]
        require(summary["complete"] is True and summary["attempts"] == 1 and summary["pending_handles"] == []
            and summary["dataset_manifest_id"] == manifest and summary["outputs"] == [dict(out, report_sha256=s["report_sha256"])
                for out,s in zip(result["outputs"],statuses)], "workflow lost exact ordered package outputs")
    require(len(value["sources"]) == len(value["publications"]) == len(set(source_ids)) == 2
        and len({h["binding"]["job_id"] for h in all_jobs}) == 4 and set(files) == expected, "extra/missing/copied work or source")
    for worker,p,row in observed:
        require(worker["dataset_json"] == JOBS["derive"](value["sources"][p]["dataset"], [row]), "worker received wrong package row")
    resumed = value["resumed"]
    READY["check_output"](resumed, resumed=True)
    require(resumed["files_unchanged"] is True and resumed["brokers_stopped"] is True
        and value["before-resume"]["original_brokers_ended"] is True and value["before-resume"]["observed_workers_ended"] is True
        and resumed["result"]["packages"] == retained["result"]["packages"], "completed resume changed source-specific history")
    CUSTODY["validate_path"](value["path"], value["peers"], layout, "inspect")
    application = value["path"]["privacy"]["exit"]["provider_application"]
    require(all(application[n]["request_packets"] > 0 and application[n]["response_payload_bytes"] >= size
                for n,size in response_bytes.items()) and all(value["cleanup"].values()), "protected reports/cleanup missing")


def evidence(work, revision):
    JOBS["guest_work"](work)
    value = {name:read(work / f"agent-jobs-{name}.json") for name in ("layout", "observation", "provision")}
    value.update(sources=[read(work / "agent-jobs-source.json"), read(record(work, "source-b"))],
                 publications=[read(work / "agent-jobs-publish.json"), read(record(work, "publish-b"))])
    value.update({name:read(record(work,name), 12 * 1048576) for name in
        ("pause-plan", "paused", "refill", "continued", "files", "before-resume", "resumed")})
    value.update(source_revision=revision, peers=read(work / "a01-expected-peers.json"), cleanup=read(work / "agent-jobs-private-cleanup.json"),
        path=dict(selected_route=read(work / "content-custody-fetch-live-selection.json"),
        privacy={r:read(work / f"content-custody-fetch-privacy-{r}.json") for r in CUSTODY["ROLES"]},
        control_privacy=read(work / "content-provider-custody-fetch-control.json"), gates=read(work / "content-custody-fetch-gates.json")))
    check(value, revision)
    write(record(work, "evidence"), value)


def before_resume(work):
    READY["before_resume"](work)
    intermediate = read(record(work, "refill"))["intermediate"]["worker"]
    require(all(not alive(p) for p in intermediate["owned_processes"]), "intermediate package worker remains")


def self_test():
    # Full fixture parser checks use public synthetic observations only; no model,
    # process signal, network or valid manifest signature is created here.
    value = synthetic_contract()
    check(value, "a" * 40)
    changes = {
        "wrong_package_order": lambda x:x["refill"]["intermediate"]["handle"]["binding"].update(dataset_manifest_id="0"*64),
        "same_package_only": lambda x:x["refill"]["handle"]["binding"].update(dataset_manifest_id=x["pause-plan"]["original_handles"][0]["binding"]["dataset_manifest_id"]),
        "slow_completed": lambda x:x["continued"]["original_status"].update(state="complete"),
        "shared_worker": lambda x:x["refill"]["worker"].update(worker=x["refill"]["intermediate"]["worker"]["worker"]),
        "changed_receipt": lambda x:x["refill"]["completed_receipt"].update(sha256="0"*64),
        "expiry_extended": lambda x:x["publications"][1].update(expires_unix_seconds=9999),
        "owner_replaced": lambda x:x["continued"]["owner"]["identity"].update(pid=9999),
        "resume_work": lambda x:x["resumed"]["result"].update(rounds_this_invocation=1),
        "resume_rewrite": lambda x:x["resumed"].update(files_unchanged=False),
        "extra_attempt": lambda x:x["files"]["files"].update({"package-0001/attempt-0001/job-0.json":{}}),
        "missing_privacy": lambda x:x["path"]["privacy"].pop("exit"),
        "cleanup_incomplete": lambda x:x["cleanup"].update(done=False),
    }
    for name,alter in changes.items():
        bad = copy.deepcopy(value); alter(bad)
        try: check(bad, "a" * 40)
        except (ValueError, KeyError, StopIteration): pass
        else: raise AssertionError("invalid package queue proof accepted: " + name)
    print("package queue parser positive + 12 negative pure checks PASS; no worker, signal or network execution proof")


def synthetic_contract():
    base = READY["synthetic_contract"]()
    # Convert the old inert four-row parser input into two distinct signed-source
    # envelopes and source-local singleton indices; real reports come only from VM.
    sources, publications, files, jobs, statuses, outputs = [], [], {}, [], [], []
    decode = FOLLOW["decode"]
    oldfiles = base["files"]["files"]
    oldjobs = [decode(oldfiles, READY["FIRST"] + f"job-{r}.json") for r in range(4)]
    def put(name,item):
        raw = item if isinstance(item,bytes) else json.dumps(item).encode()
        files[name] = dict(**hashes(raw), hex=raw.hex(), inode=[1,len(files)+1], modified_unix_ns=1500*1000000000)
    for p in (0,1):
        source, published = copy.deepcopy(base["source"]), copy.deepcopy(base["publish"])
        source["dataset"]["inference"] = source["dataset"]["inference"][:2]
        if p: source["dataset"]["inference"][0]["question"] = "Does every parallel path use a distinct relay?"
        source["dataset_json"] = json.dumps(source["dataset"]); source["dataset_file"] = hashes(source["dataset_json"].encode())
        encoded = bytes.fromhex(source["manifest_hex"])
        if p: encoded = encoded[:-1] + bytes([encoded[-1] ^ 1])  # inert synthetic signature, not a valid publication
        source["manifest_hex"] = encoded.hex(); source["manifest"] = hashes(encoded)
        published["bytes"] = source["dataset_file"]["bytes"]
        sources.append(source); publications.append(published)
        put(f"package-{p:04d}/dataset.json", source["dataset_json"].encode()); put(f"package-{p:04d}/manifest.bin", encoded)
        for row in (0,1):
            oldrow = p if row == 0 else 2
            handle = copy.deepcopy(oldjobs[oldrow]); handle["binding"].update(job_id=str(p*2+row)*32, row_indices=[row],
                dataset_manifest_id=source["manifest"]["sha256"], dataset_sha256=hashes(JOBS["derive"](source["dataset"],[row]).encode())["sha256"])
            status = copy.deepcopy(decode(oldfiles, READY["FIRST"] + f"receipt-{oldjobs[oldrow]['binding']['job_id']}.json")["status"])
            report_value = json.loads(status["report_json"]); report_value["dataset"]["sha256"] = handle["binding"]["dataset_sha256"]
            raw = json.dumps(report_value); status.update(binding=copy.deepcopy(handle["binding"]), report_json=raw, report_sha256=hashes(raw.encode())["sha256"])
            jobs.append(handle); statuses.append(status)
            outputs.append(dict(sample_index=row, provider_key=handle["provider_key"], job_id=handle["binding"]["job_id"], text=report_value["outputs"][0]["text"]))
            put(attempt(p)+f"job-{row}.json",handle); put(attempt(p)+f"receipt-{handle['binding']['job_id']}.json",
                dict(version=1,handle=handle,status=status,verified_at_unix_seconds=1600))
        queue = decode(oldfiles,READY["FIRST"]+"queue-plan.json")
        queue.update(dataset_manifest_id=source["manifest"]["sha256"],dataset_sha256=source["dataset_file"]["sha256"],ready_rows=[0,1])
        put(attempt(p)+"queue-plan.json",queue)
        result = dict(operation="compute_ready_queue",scheduling="ready_rows_v1",complete=True,dataset_manifest_id=source["manifest"]["sha256"],
            never_submitted_rows=[], outputs=outputs[p*2:p*2+2], jobs=[dict(handle=h,state="complete",report_sha256=s["report_sha256"],new_submission=True)
                for h,s in zip(jobs[p*2:p*2+2],statuses[p*2:p*2+2])])
        put(attempt(p)+"result.json",result)
    enrollment=decode(oldfiles,"workflow.json")
    enrollment["packages"]=[dict(publisher_key=p["publisher_key_hex"],manifest_id=s["manifest"]["sha256"],dataset_sha256=s["dataset_file"]["sha256"],rows=2)
                            for s,p in zip(sources,publications)]
    put("workflow.json",enrollment);put(".workflow.lock",b"")
    plan=base["pause-plan"];plan["original_handles"]=[jobs[0],jobs[2]];plan["owner"]["maximum_rounds_per_window"]=2
    for worker,p,row in ((plan["slow"],0,0),(plan["fast"],1,0)):
        worker["dataset_json"]=JOBS["derive"](sources[p]["dataset"],[row]);worker["dataset_file"]=hashes(worker["dataset_json"].encode())
    base["observation"]["workers"]=[copy.deepcopy(plan["slow"]),copy.deepcopy(plan["fast"])]
    base["paused"]["plan"]=copy.deepcopy(plan)
    mid=copy.deepcopy(base["refill"])
    mid["worker"]["dataset_json"]=JOBS["derive"](sources[0]["dataset"],[1]);mid["worker"]["dataset_file"]=hashes(mid["worker"]["dataset_json"].encode())
    mid.update(handle=jobs[1],completed_receipt=copy.deepcopy(files[attempt(1)+f"receipt-{jobs[2]['binding']['job_id']}.json"]),boottime_ns=1500)
    refill=base["refill"];refill["worker"]["worker"]=dict(pid=998,start_ticks=201)
    refill["worker"]["dataset_json"]=JOBS["derive"](sources[1]["dataset"],[1]);refill["worker"]["dataset_file"]=hashes(refill["worker"]["dataset_json"].encode())
    refill.update(handle=jobs[3],intermediate=mid,intermediate_worker_ended=True,original_handles=copy.deepcopy(plan["original_handles"]),
        completed_receipt=copy.deepcopy(files[attempt(0)+f"receipt-{jobs[1]['binding']['job_id']}.json"]))
    base["continued"].update(owner=copy.deepcopy(plan["owner"]),original_handle=copy.deepcopy(jobs[0]))
    base["continued"]["original_status"]["binding"]=copy.deepcopy(jobs[0]["binding"])
    summary=base["files"]["result"]
    summary.update(rounds_this_invocation=2,maximum_rounds_per_window=2,completed_packages=2,package_count=2,
        packages=[dict(complete=True,attempts=1,pending_handles=[],dataset_manifest_id=sources[p]["manifest"]["sha256"],
        outputs=[dict(o,report_sha256=s["report_sha256"]) for o,s in zip(outputs[p*2:p*2+2],statuses[p*2:p*2+2])]) for p in (0,1)])
    raw=json.dumps(summary).encode();base["files"].update(files=files,stdout=dict(**hashes(raw),hex=raw.hex()))
    resumed=dict(summary,rounds_this_invocation=0);raw=json.dumps(resumed).encode()
    base["resumed"].update(result=resumed,stdout=dict(**hashes(raw),hex=raw.hex()))
    base.update(sources=sources,publications=publications)
    return base


# Each run_path owns an isolated namespace. Reuse only unchanged exact-process,
# captured-output and cleanup/report plumbing, parameterized to this new scenario.
READY["capture"].__globals__.update(record=record,workflow=workflow,retained_tree=retained_tree,
    parse_output=parse_output,check=check,PREFIX=PREFIX,KIND=KIND,SCOPE=SCOPE)


def main(args):
    command=args[0]
    if command=="self-test": self_test()
    elif command=="second-source": second_source(Path(args[1]))
    elif command=="publication-b": print(json.dumps(publication_b(Path(args[1]))))
    elif command=="prepare": prepare(Path(args[1]),args[2])
    elif command=="pause": pause(Path(args[1]),int(args[2]))
    elif command=="observe-ready": observe_ready(Path(args[1]))
    elif command=="before-resume": before_resume(Path(args[1]))
    elif command=="evidence": evidence(Path(args[1]),args[2])
    elif command=="continue-worker": READY["continue_worker"](Path(args[1]))
    elif command=="cleanup-worker": READY["continue_worker"](Path(args[1]),cleanup=True)
    elif command=="capture": READY["capture"](Path(args[1]))
    elif command=="after-resume": READY["after_resume"](Path(args[1]))
    elif command=="finalize": READY["finalize"](Path(args[1]),args[2],int(args[3]),args[4]=="true",int(args[5]),args[6],args[7])
    elif command=="report": READY["report"](read(Path(args[1]),16*1048576),args[2])
    else: raise ValueError("unknown fixed package queue fixture command")


if __name__=="__main__":
    main(sys.argv[1:])
