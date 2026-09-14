#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual public-question jobs and offline retained-result resume, never answer-quality proof."""

import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
QUESTION = "What does this public context say about a normal network path?"
TASK = {"kind": "answer_public_question_v1", "question": QUESTION}
SCOPE = ("one explicit requester-authored public question over two original signed contexts, protected source retrieval, "
         "two actual isolated peer workers and ordered per-context answers; exact retained-result resume after both "
         "brokers and the route stop, not new execution, answer correctness, neural synthesis or full B03")
ATTEMPT = "work/package-0000/attempt-0000"


def task_root(work):
    return work / "state-client/compute-source/public-task"


def admission_handles(paths):
    try:
        result = []
        for path in paths:
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 16384,
                    "incomplete initial handle")
            raw = path.read_bytes()
            value = json.loads(raw)
            require(value["binding"]["task"] == TASK and value["capabilities"]["task_derivation_v1"] is True,
                    "initial handle not yet complete")
            result.append({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        return result
    except (OSError, ValueError, KeyError):
        return None  # A writer may have created the final file but not finished its JSON.


def observe(work, pid):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](pid)
    started = time.monotonic_ns()
    paths = [task_root(work) / ATTEMPT / f"job-{n}.json" for n in (0, 1)]
    # Source fetch plus cancellable read-only capability admission precede Submit.
    # Keep that deadline separate from the unchanged real-worker overlap window.
    # No fixture restart, new task, source reselection or synthetic readiness.
    while time.monotonic_ns() - started < 90_000_000_000:
        handles = admission_handles(paths)
        if handles:
            write(work / "agent-public-task-admission.json", {
                "handles": handles,
                "started_at_monotonic_ns": started,
                "observed_at_monotonic_ns": time.monotonic_ns(),
                "operation": "actual_handles_retained_before_worker_observation"})
            return JOBS["observe"](work)
        require(JOBS["alive"](owner), "public task ended before initial admission; inspect retained task result and fixed agent events")
        time.sleep(0.05)
    raise ValueError("public task did not retain its real handles within the admission deadline")


def snapshot(root):
    require(root.is_dir() and not root.is_symlink(), "missing real task directory")
    result = {}
    for number, path in enumerate(root.rglob("*")):
        require(number < 64 and len(result) < 40, "unbounded retained task tree")
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == root.stat().st_uid, "retained task owner differs")
        if stat.S_ISDIR(info.st_mode):
            continue
        relative = path.relative_to(root).as_posix()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                "unsafe retained task file")
        if relative == "result.json":
            continue  # This one frontend result is intentionally replaced on resume.
        require(info.st_size <= 1048576, "retained task file too large")
        result[relative] = {**JOBS["file_hash"](path, 1048576), "inode": [info.st_dev, info.st_ino]}
    require("task.json" in result and f"{ATTEMPT}/job-0.json" in result
            and f"{ATTEMPT}/job-1.json" in result and f"{ATTEMPT}/result.json" in result,
            "real source and completed attempt missing")
    require(not any("attempt-0001" in name for name in result), "unexpected extra execution attempt")
    return result


def collect(work):
    JOBS["guest_work"](work)
    root = task_root(work)
    attempt = root / ATTEMPT
    handles = [read(attempt / f"job-{n}.json") for n in (0, 1)]
    retained = snapshot(root)
    value = {"task": read(root / "task.json"), "source_receipt": read(root / "source-receipt.json"),
             "source_dataset_hex": (root / "dataset.json").read_bytes().hex(),
             "source_manifest_hex": (root / "dataset.manifest").read_bytes().hex(),
             "workflow_plan": read(root / "workflow-plan.json"), "workflow_enrollment": read(root / "work/workflow.json"),
             "handles": handles, "batch": read(attempt / "result.json"),
             "receipts": [read(attempt / f"receipt-{h['binding']['job_id']}.json") for h in handles],
             "snapshot": retained, "retained_json": {name: (root / name).read_text() for name in retained if name.endswith(".json")},
             "observed_at_monotonic_ns": time.monotonic_ns()}
    write(work / "agent-public-task-files.json", value)
    # Existing raw jobs evidence retains the actual batch result, not a translated
    # or fabricated compute_distribute response built from frontend flags.
    write(work / "agent-jobs-result.json", value["batch"])


def stopped(work, name):
    JOBS["guest_work"](work)
    workers = read(work / "agent-jobs-observation.json")["workers"]
    for worker in workers:
        require(not JOBS["alive"](worker["broker"])
                and not any(JOBS["alive"](member) for member in worker["owned_processes"]),
                "a real executor or descendant remains alive")
        raw = JOBS["subprocess"].check_output(["systemctl", "show", "--property=ActiveState", "--value",
                                               f"volparossa-alpha-compute@{worker['node']}.service"], text=True).strip()
        require(raw in ("inactive", "failed"), "executor unit remains active")
    result = {"brokers": [w["broker"] for w in workers], "all_owned_processes_ended": True,
              "observed_at_monotonic_ns": time.monotonic_ns()}
    if name == "resumed":
        result["snapshot"] = snapshot(task_root(work))
    write(work / f"agent-public-task-{name}.json", result)


def check_frontend(result, task, manifest, files, rounds):
    require(result["operation"] == "compute_public_task" and result["complete"] is True
            and result["task"] == TASK == task["task"] and result["dataset_manifest_id"] == manifest
            and result["publisher_key"] == task["publisher_key"]
            and result["dataset_name"] == task["dataset_name"] == "disposable-agent-jobs",
            "frontend source or public question differs")
    require(result["question_authored_by_requester"] is True
            and result["publisher_signature_covers_original_source_not_question"] is True
            and result["joining"] == "ordered_per_context_answers_not_neural_synthesis"
            and all(result[k] is False for k in ("private_data_supported", "automatic_source_discovery",
                                                "arbitrary_document_splitting", "model_answer_correctness_proven", "full_b03_claimed")),
            "frontend made an unsupported source/answer claim")
    workflow = result["workflow"]
    require(workflow["operation"] == "compute_workflow" and workflow["complete"] is True
            and workflow["pending_failure"] is False and workflow["rounds_this_invocation"] == rounds
            and workflow["completed_packages"] == workflow["package_count"] == 1
            and workflow["stopped"] == "complete" and len(workflow["packages"]) == 1,
            "workflow performed unexpected execution")
    package = workflow["packages"][0]
    require(package["attempts"] == 1 and package["complete"] is True and package["pending_handles"] == []
            and package["dataset_manifest_id"] == manifest and package["task"] == TASK,
            "workflow package/attempt changed")
    original = json.loads(bytes.fromhex(files["source_dataset_hex"]))
    require(len(result["answers"]) == len(package["outputs"]) == len(files["handles"]) == 2, "missing per-context answer")
    for index, (answer, output, handle, receipt) in enumerate(zip(result["answers"], package["outputs"], files["handles"], files["receipts"])):
        status = receipt["status"]
        require(receipt["version"] == 1 and receipt["handle"] == handle and status["binding"] == handle["binding"]
                and status["state"] == "complete" and handle["binding"]["task"] == TASK,
                "retained authenticated receipt binding changed")
        report_json = status["report_json"]
        digest = hashlib.sha256(report_json.encode()).hexdigest()
        require(status["report_sha256"] == digest and answer["report_sha256"] == output["report_sha256"] == digest,
                "answer no longer matches the real report")
        require(answer["source_row"] == output["sample_index"] == index
                and answer["job_id"] == output["job_id"] == handle["binding"]["job_id"]
                and answer["provider_key"] == output["provider_key"] == handle["provider_key"]
                and answer["text"] == output["text"] == json.loads(report_json)["outputs"][0]["text"]
                and answer["context_sha256"] == hashlib.sha256(original["inference"][index]["context"].encode()).hexdigest(),
                "ordered task answer lost original context or executor")


def check_evidence(evidence, revision):
    jobs, files = evidence["jobs"], evidence["files"]
    JOBS["check_evidence"](jobs, revision, TASK)
    require(evidence["success"] is True and evidence["source_revision"] == revision, "wrong public task source")
    manifest = JOBS["source_manifest_id"](jobs["source"], jobs["publish"])
    require(files["source_manifest_hex"] == jobs["source"]["manifest_hex"]
            and bytes.fromhex(files["source_dataset_hex"]) == jobs["source"]["dataset_json"].encode()
            and files["batch"] == jobs["result"], "task source differs from original publisher bytes")
    expected = {"task.json": files["task"], "source-receipt.json": files["source_receipt"],
                "workflow-plan.json": files["workflow_plan"], "work/workflow.json": files["workflow_enrollment"],
                f"{ATTEMPT}/result.json": files["batch"]}
    for index, handle in enumerate(files["handles"]):
        expected[f"{ATTEMPT}/job-{index}.json"] = handle
        expected[f"{ATTEMPT}/receipt-{handle['binding']['job_id']}.json"] = files["receipts"][index]
    for name, value in files["retained_json"].items():
        item = files["snapshot"][name]
        require(item["bytes"] == len(value.encode()) and item["sha256"] == hashlib.sha256(value.encode()).hexdigest(),
                "retained JSON bytes differ from actual file snapshot")
    for name, value in expected.items():
        require(json.loads(files["retained_json"][name]) == value, "exported retained receipt does not match its original bytes")
    admission = evidence["admission"]
    require(admission["operation"] == "actual_handles_retained_before_worker_observation"
            and 0 <= admission["observed_at_monotonic_ns"] - admission["started_at_monotonic_ns"] < 90_000_000_000
            and admission["observed_at_monotonic_ns"] < jobs["observation"]["first_monotonic_ns"]
            and admission["handles"] == [{k: files["snapshot"][f"{ATTEMPT}/job-{n}.json"][k]
                                           for k in ("sha256", "bytes")} for n in (0, 1)],
            "admission did not observe the same exact retained handles before the workers")
    for name in ("dataset.json", "work/package-0000/dataset.json"):
        require(files["retained_json"][name].encode() == bytes.fromhex(files["source_dataset_hex"]), "workflow source changed")
    for name in ("dataset.manifest", "work/package-0000/manifest.bin"):
        require(files["snapshot"][name]["sha256"] == manifest
                and files["snapshot"][name]["bytes"] == len(bytes.fromhex(files["source_manifest_hex"])), "workflow manifest changed")
    task, source = files["task"], files["source_receipt"]
    require(task["version"] == 1 and task["task"] == TASK and task["expected_manifest_id"] == manifest
            and task["publisher_key"] == jobs["publish"]["publisher_key_hex"]
            and task["provider_keys"] == [jobs["layout"]["provider_keys"][node] for node in jobs["layout"]["provider_nodes"]],
            "task enrollment changed source or peer choice")
    enrollment = files["workflow_enrollment"]
    require(enrollment["version"] == 1 and enrollment["provider_keys"] == task["provider_keys"]
            and len(enrollment["packages"]) == 1
            and enrollment["packages"][0] == {"publisher_key": task["publisher_key"], "manifest_id": manifest,
                "dataset_sha256": jobs["source"]["dataset_file"]["sha256"], "rows": 2, "task": TASK},
            "workflow enrollment source/task differs")
    require(source["publisher_key"] == task["publisher_key"] and source["dataset_name"] == task["dataset_name"]
            and source["manifest_id"] == manifest and source["dataset_sha256"] == jobs["source"]["dataset_file"]["sha256"]
            and source["expires_unix_seconds"] == jobs["publish"]["expires_unix_seconds"]
            and source["source_choice_uses_cache_inventory"] is False and source["private_data_supported"] is False,
            "fresh named source receipt lost original authority or expiry")
    received = source["receipt"]
    supplier = jobs["layout"]["provider_nodes"][0]
    require(received["operation"] == "named_content_download" and received["manifest_id"] == manifest
            and received["bytes"] == received["peer_bytes"] == jobs["source"]["dataset_file"]["bytes"]
            and received["sha256"] == source["dataset_sha256"] and received["providers_used"] == 1
            and received["provider_peer_ids"] == [jobs["peers"][supplier]] and received["cache_only"] is False
            and received["origin_body_bytes"] == received["origin_range_requests"] == 0,
            "public task did not actually retrieve its selected source over the protected network")
    deposit = evidence["deposit"]
    require(deposit["operation"] == "content_custody_deposit" and deposit["complete"] is True
            and deposit["manifest_id"] == manifest and deposit["publisher_key_hex"] == task["publisher_key"]
            and deposit["requested_providers"] == deposit["confirmed_complete_providers"] == 1
            and deposit["failed_providers"] == 0 and deposit["original_expiry_unix_seconds"] == source["expires_unix_seconds"]
            and deposit["private_keys_transferred"] is False and deposit["direct_provider_dial"] is False,
            "original public source was not offered through real protected custody")
    observation = deposit["observations"]
    require(len(observation) == 1 and observation[0]["provider_key_hex"] == jobs["layout"]["provider_keys"][supplier]
            and observation[0]["agent_handoff_complete"] is True and observation[0]["state"] == "complete"
            and observation[0]["error"] is None and observation[0]["object_bytes"] == deposit["object_bytes"] == received["bytes"]
            and observation[0]["original_expiry_unix_seconds"] == source["expires_unix_seconds"]
            and isinstance(observation[0]["signed_receipt_hex"], str) and len(observation[0]["signed_receipt_hex"]) > 128,
            "source holder acknowledgement missing")
    # The ordinary custody CLI verifies Ed25519. Independently bind its exact
    # retained signed envelope here; this Python parser does not claim crypto verification.
    fields = JOBS["CUSTODY"]["fields"]
    envelope = fields(bytes.fromhex(observation[0]["signed_receipt_hex"]), 2048)
    require(set(envelope) == {1, 2} and len(envelope[2]) == 64, "custody signature bytes absent")
    body = fields(envelope[1], 2048)
    payload = fields(body[8], 1024)
    require(body[1] == 1 and body[2] == bytes.fromhex(observation[0]["provider_key_hex"]) and body[6] == 3
            and 0 < body[4] - body[3] <= 900 and body[4] <= source["expires_unix_seconds"]
            and body[7] == hashlib.sha256(body[8]).digest() and payload.get(5, 1) == 1 and payload[6] == 2
            and payload[3] == body[2] and payload[4] == bytes.fromhex(task["publisher_key"])
            and payload[7] == bytes.fromhex(manifest) and payload[8] == bytes.fromhex(source["dataset_sha256"])
            and payload[9] == received["bytes"] and payload[10] == observation[0]["unique_chunks"] == 1
            and payload[11] == source["expires_unix_seconds"], "custody signed source/hash/expiry differs")
    check_frontend(evidence["result"], task, manifest, files, 1)
    check_frontend(evidence["resume"], task, manifest, files, 0)
    require(evidence["result"]["answers"] == evidence["resume"]["answers"]
            and evidence["result"]["workflow"]["packages"] == evidence["resume"]["workflow"]["packages"],
            "completed result was rerun or replaced")
    ended, after = evidence["stopped"], evidence["resumed"]
    brokers = [worker["broker"] for worker in jobs["observation"]["workers"]]
    require(ended["brokers"] == after["brokers"] == brokers and ended["all_owned_processes_ended"] is True
            and after["all_owned_processes_ended"] is True
            and files["observed_at_monotonic_ns"] < ended["observed_at_monotonic_ns"] < after["observed_at_monotonic_ns"]
            and files["snapshot"] == after["snapshot"], "resume changed retained files or used a running executor")
    require(len(files["snapshot"]) >= 12 and not any("attempt-0001" in name for name in files["snapshot"]),
            "additional model execution attempt present")
    for index, status in enumerate(jobs["statuses"]):
        require(files["handles"][index]["binding"] == status["binding"]
                and files["receipts"][index]["status"] == status, "poll and retained terminal receipt differ")


def evidence(work, revision):
    jobs = {name: read(work / f"agent-jobs-{name}.json") for name in ("source", "publish", "layout", "result", "observation", "provision")}
    jobs.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
                cleanup=read(work / "agent-jobs-private-cleanup.json"),
                statuses=[read(work / f"agent-jobs-status-{n}.json") for n in (0, 1)],
                path={"selected_route": read(work / "content-custody-fetch-live-selection.json"),
                      "privacy": {role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in JOBS["CUSTODY"]["ROLES"]},
                      "control_privacy": read(work / "content-provider-custody-fetch-control.json"),
                      "gates": read(work / "content-custody-fetch-gates.json")})
    value = {name: read(work / f"agent-public-task-{name}.json", 1048576)
             for name in ("files", "deposit", "result", "resume", "stopped", "resumed", "admission")}
    value.update(success=True, source_revision=revision, jobs=jobs)
    check_evidence(value, revision)
    return value


def finalize(work, revision, status, complete, remaining, phase, blocker):
    found = work / "agent-public-task-evidence.json"
    value = read(found, 2097152) if found.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(work / "agent-public-task-smoke.json", {
        "report_kind": "volparossa-public-task", "source_revision": revision, "scope": SCOPE,
        "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and value is not None,
        "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker, "runner_exit_status": status,
        "answer_quality_proven": False, "neural_synthesis_claimed": False, "full_b03_claimed": False, "full_alpha_claimed": False,
        "evidence": value, "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host})


def report(value, revision):
    require(value["report_kind"] == "volparossa-public-task" and value["source_revision"] == revision
            and value["scope"] == SCOPE and value["success"] is True and value["runner_exit_status"] == 0,
            "incomplete source-bound public task report")
    require(value["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "host or owned cleanup differs")
    require(all(value[key] is False for key in ("answer_quality_proven", "neural_synthesis_claimed", "full_b03_claimed", "full_alpha_claimed")),
            "public task scope overstated")
    check_evidence(value["evidence"], revision)


def self_test():
    # Only parser contracts are synthesized. This never counts as a model,
    # signature, protected transfer, process-death or retained-resume proof.
    jobs = JOBS["self_test"]()
    jobs["result"]["task"] = copy.deepcopy(TASK)
    for index, status in enumerate(jobs["statuses"]):
        part = next(part for part in jobs["result"]["jobs"] if part["handle"]["binding"]["job_id"] == status["binding"]["job_id"])
        binding = status["binding"]
        binding["task"] = copy.deepcopy(TASK)
        derived = JOBS["derive"](jobs["source"]["dataset"], [index], TASK)
        binding["dataset_sha256"] = hashlib.sha256(derived.encode()).hexdigest()
        part["handle"]["binding"] = copy.deepcopy(binding)
        part["handle"]["capabilities"]["task_derivation_v1"] = True
        jobs["observation"]["workers"][index]["dataset_json"] = derived
        output = json.loads(status["report_json"])
        output["dataset"]["sha256"] = binding["dataset_sha256"]
        status["report_json"] = json.dumps(output)
        status["report_sha256"] = part["report_sha256"] = hashlib.sha256(status["report_json"].encode()).hexdigest()
    manifest = jobs["source"]["manifest"]["sha256"]
    task = dict(version=1, task=copy.deepcopy(TASK), expected_manifest_id=manifest, publisher_key=jobs["publish"]["publisher_key_hex"],
                dataset_name="disposable-agent-jobs", provider_keys=list(jobs["layout"]["provider_keys"].values()))
    holder = jobs["layout"]["provider_nodes"][0]
    source = dict(publisher_key=task["publisher_key"], dataset_name=task["dataset_name"], manifest_id=manifest,
        dataset_sha256=jobs["source"]["dataset_file"]["sha256"], expires_unix_seconds=3000,
        source_choice_uses_cache_inventory=False, private_data_supported=False,
        receipt=dict(operation="named_content_download", manifest_id=manifest, bytes=jobs["publish"]["bytes"],
            peer_bytes=jobs["publish"]["bytes"], sha256=jobs["source"]["dataset_file"]["sha256"], providers_used=1,
            provider_peer_ids=[jobs["peers"][holder]], cache_only=False, origin_body_bytes=0, origin_range_requests=0))
    handles = [copy.deepcopy(part["handle"]) for part in jobs["result"]["jobs"]]
    receipts = [dict(version=1, handle=h, status=copy.deepcopy(status)) for h, status in zip(handles, jobs["statuses"])]
    files = dict(task=task, source_receipt=source, source_dataset_hex=jobs["source"]["dataset_json"].encode().hex(),
        source_manifest_hex=jobs["source"]["manifest_hex"], handles=handles, receipts=receipts,
        batch=copy.deepcopy(jobs["result"]), workflow_plan=dict(version=1, packages=[]), observed_at_monotonic_ns=2000,
        workflow_enrollment=dict(version=1, provider_keys=task["provider_keys"], packages=[dict(publisher_key=task["publisher_key"],
            manifest_id=manifest, dataset_sha256=source["dataset_sha256"], rows=2, task=copy.deepcopy(TASK))]))
    original = {"task.json": task, "source-receipt.json": source, "workflow-plan.json": files["workflow_plan"],
                "work/workflow.json": files["workflow_enrollment"], f"{ATTEMPT}/result.json": files["batch"]}
    for index, handle in enumerate(handles):
        original[f"{ATTEMPT}/job-{index}.json"] = handle
        original[f"{ATTEMPT}/receipt-{handle['binding']['job_id']}.json"] = receipts[index]
    raw = {name: json.dumps(value) for name, value in original.items()}
    raw.update({name: jobs["source"]["dataset_json"] for name in ("dataset.json", "work/package-0000/dataset.json")})
    files["retained_json"] = raw
    files["snapshot"] = {name: dict(bytes=len(value.encode()), sha256=hashlib.sha256(value.encode()).hexdigest(), inode=[1, index])
                         for index, (name, value) in enumerate(raw.items())}
    for index, name in enumerate(("dataset.manifest", "work/package-0000/manifest.bin")):
        files["snapshot"][name] = {**jobs["source"]["manifest"], "inode": [1, 100 + index]}
    outputs = [dict(**output, report_sha256=jobs["statuses"][index]["report_sha256"])
               for index, output in enumerate(jobs["result"]["outputs"])]
    answers = [dict(source_row=index, context_sha256=hashlib.sha256(jobs["source"]["dataset"]["inference"][index]["context"].encode()).hexdigest(),
                    **{key: output[key] for key in ("text", "provider_key", "job_id", "report_sha256")}) for index, output in enumerate(outputs)]
    result = dict(operation="compute_public_task", complete=True, task=copy.deepcopy(TASK), dataset_manifest_id=manifest,
        publisher_key=task["publisher_key"], dataset_name=task["dataset_name"], answers=answers, question_authored_by_requester=True,
        publisher_signature_covers_original_source_not_question=True, joining="ordered_per_context_answers_not_neural_synthesis",
        private_data_supported=False, automatic_source_discovery=False, arbitrary_document_splitting=False,
        model_answer_correctness_proven=False, full_b03_claimed=False,
        workflow=dict(operation="compute_workflow", complete=True, pending_failure=False, rounds_this_invocation=1,
            completed_packages=1, package_count=1, stopped="complete", packages=[dict(attempts=1, complete=True,
                pending_handles=[], dataset_manifest_id=manifest, task=copy.deepcopy(TASK), outputs=outputs)]))
    resume = copy.deepcopy(result)
    resume["workflow"]["rounds_this_invocation"] = 0
    wire = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["wire"]
    key = jobs["layout"]["provider_keys"][holder]
    payload = wire({1: b"c" * 32, 2: b"d" * 32, 3: bytes.fromhex(key), 4: bytes.fromhex(task["publisher_key"]), 6: 2,
        7: bytes.fromhex(manifest), 8: bytes.fromhex(source["dataset_sha256"]), 9: jobs["publish"]["bytes"], 10: 1, 11: 3000})
    body = wire({1: 1, 2: bytes.fromhex(key), 3: 1000, 4: 1800, 5: b"n" * 32, 6: 3,
                 7: hashlib.sha256(payload).digest(), 8: payload})
    deposit = dict(operation="content_custody_deposit", complete=True, manifest_id=manifest,
        publisher_key_hex=task["publisher_key"], requested_providers=1, confirmed_complete_providers=1, failed_providers=0,
        original_expiry_unix_seconds=3000, object_bytes=jobs["publish"]["bytes"], private_keys_transferred=False, direct_provider_dial=False,
        observations=[dict(provider_key_hex=key, agent_handoff_complete=True, state="complete", error=None,
            original_expiry_unix_seconds=3000, object_bytes=jobs["publish"]["bytes"], unique_chunks=1,
            signed_receipt_hex=wire({1: body, 2: b"s" * 64}).hex())])
    stopped_value = dict(brokers=[w["broker"] for w in jobs["observation"]["workers"]], all_owned_processes_ended=True, observed_at_monotonic_ns=3000)
    fixture = dict(success=True, source_revision="a" * 40, jobs=jobs, files=files, deposit=deposit, result=result, resume=resume,
        stopped=stopped_value, resumed=dict(**{**stopped_value, "observed_at_monotonic_ns": 4000}, snapshot=copy.deepcopy(files["snapshot"])))
    fixture["admission"] = dict(operation="actual_handles_retained_before_worker_observation",
        started_at_monotonic_ns=jobs["observation"]["first_monotonic_ns"] - 2,
        observed_at_monotonic_ns=jobs["observation"]["first_monotonic_ns"] - 1,
        handles=[{k: files["snapshot"][f"{ATTEMPT}/job-{n}.json"][k] for k in ("sha256", "bytes")} for n in (0, 1)])
    check_evidence(fixture, "a" * 40)
    for name in ("question", "source", "source_bytes", "local_shortcut", "expiry", "capability", "answer", "extra_round", "changed_handle", "new_file", "live_broker", "admission_handle", "late_admission"):
        bad = copy.deepcopy(fixture)
        if name == "question": bad["result"]["task"]["question"] = "Different question"
        elif name == "source": bad["files"]["source_manifest_hex"] += "00"
        elif name == "source_bytes": bad["files"]["source_dataset_hex"] += "20"
        elif name == "local_shortcut": bad["files"]["source_receipt"]["receipt"]["peer_bytes"] = 0
        elif name == "expiry": bad["deposit"]["original_expiry_unix_seconds"] += 1
        elif name == "capability": bad["jobs"]["result"]["jobs"][0]["handle"]["capabilities"]["task_derivation_v1"] = False
        elif name == "answer": bad["resume"]["answers"][0]["text"] = "Different answer"
        elif name == "extra_round": bad["resume"]["workflow"]["rounds_this_invocation"] = 1
        elif name == "changed_handle": bad["files"]["handles"][0]["binding"]["expires_unix_seconds"] += 1
        elif name == "new_file": bad["resumed"]["snapshot"][f"{ATTEMPT}/job-0.json"]["inode"] = [3, 4]
        elif name == "live_broker": bad["stopped"]["all_owned_processes_ended"] = False
        elif name == "admission_handle": bad["admission"]["handles"][0]["sha256"] = "0" * 64
        else: bad["admission"]["observed_at_monotonic_ns"] = bad["jobs"]["observation"]["first_monotonic_ns"]
        try:
            check_evidence(bad, "a" * 40)
        except (ValueError, KeyError):
            continue
        raise AssertionError(f"invalid public task evidence accepted: {name}")
    with tempfile.TemporaryDirectory(prefix="volparossa-task-snapshot-") as temporary:
        root = Path(temporary)
        (root / ATTEMPT).mkdir(parents=True, mode=0o700)
        for name in ("task.json", f"{ATTEMPT}/job-0.json", f"{ATTEMPT}/job-1.json", f"{ATTEMPT}/result.json", "result.json"):
            write(root / name, {"fixture": "parser-only"})
        before = snapshot(root)
        require(before == snapshot(root), "unchanged real receipt file snapshot is unstable")
        require("result.json" not in before, "replaceable frontend output entered immutable receipt snapshot")
        alias = root / "alias.json"
        os.link(root / "task.json", alias)
        try:
            snapshot(root)
        except ValueError:
            pass
        else:
            raise AssertionError("aliased receipt file accepted")
        alias.unlink()
        require(snapshot(root) == before, "owned temporary alias cleanup changed retained files")
    print("agent-public-task synthetic source/task/receipt/resume contract + 13 rejection cases and real temporary snapshot checks PASS; no model or network executed")


def main(args):
    command = args[0]
    if command == "self-test":
        self_test()
    elif command == "report":
        report(read(Path(args[1]), 2097152), args[2])
    elif command == "collect":
        collect(Path(args[1]))
    elif command == "observe":
        observe(Path(args[1]), int(args[2]))
    elif command in ("stopped", "resumed"):
        stopped(Path(args[1]), command)
    elif command == "evidence":
        write(Path(args[1]) / "agent-public-task-evidence.json", evidence(Path(args[1]), args[2]))
    elif command == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    else:
        raise ValueError("unknown public task command")


if __name__ == "__main__":
    main(sys.argv[1:])
