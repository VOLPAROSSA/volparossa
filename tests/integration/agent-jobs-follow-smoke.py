#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One real owner command automatically recovers an observed public peer-worker loss."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
TRAIN, CUSTODY = JOBS["TRAIN"], JOBS["CUSTODY"]
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
identity, alive, file_hash = JOBS["identity"], JOBS["alive"], JOBS["file_hash"]
FIRST = "package-0000/attempt-0000/"
RETRY = "package-0000/attempt-0001/"
KIND = "volparossa-public-peer-job-follow"
SCOPE = ("one explicitly followed public workflow, two concurrent node-local workers, one observed pidfd worker loss, "
         "automatic failed-row reassignment to the idle surviving peer and exact original-result retention; "
         "not neural synthesis, general peer discovery, exactly-once execution, private computation or full B03")


def workflow(work):
    return work / "state-client/compute-source/follow"


def hash_bytes(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def prepare(root, publisher):
    JOBS["private"](root, "compute-source")
    require(re.fullmatch(r"[0-9a-f]{64}", publisher), "invalid enrolled publisher")
    write(root / "follow-plan.json", {"version": 1, "packages": [{
        "dataset": str(root / "dataset.json"), "dataset_manifest": str(root / "manifest.pb"),
        "publisher_key": publisher}]})


def initial_handles(work):
    root = workflow(work) / FIRST
    return [{"value": read(root / f"job-{n}.json"), "file": file_hash(root / f"job-{n}.json", 16384)}
            for n in (0, 1)]


def retained_file(path, uid):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600 and 0 <= metadata.st_size <= 1048576,
            "invalid owner-retained workflow file")
    raw = path.read_bytes()
    require(raw or path.name == ".workflow.lock", "empty retained content")
    return {**hash_bytes(raw), "hex": raw.hex(), "inode": [metadata.st_dev, metadata.st_ino],
            "modified_unix_ns": metadata.st_mtime_ns}


def retained_tree(root):
    uid = root.lstat().st_uid
    result = {}
    for count, path in enumerate(root.rglob("*")):
        require(count < 64, "workflow retained tree bound")
        name = path.relative_to(root).as_posix()
        metadata = path.lstat()
        require(not path.is_symlink() and metadata.st_uid == uid, "workflow symlink or different owner")
        if stat.S_ISDIR(metadata.st_mode):
            require(name in {"package-0000", FIRST[:-1], RETRY[:-1]}
                    and stat.S_IMODE(metadata.st_mode) == 0o700, "unexpected attempt or directory")
        else:
            require(name in {"workflow.json", ".workflow.lock", "package-0000/dataset.json", "package-0000/manifest.bin"}
                    or re.fullmatch(r"package-0000/attempt-000[01]/(?:job-[01]|original-0|observation-0|retry-0|result|receipt-[0-9a-f]{32})\.json", name),
                    "unexpected workflow retained file")
            result[name] = retained_file(path, uid)
    require(sum(item["bytes"] for item in result.values()) <= 4 * 1048576, "workflow retained byte bound")
    return result


def decode(files, name, native=False):
    item = files[name]
    raw = bytes.fromhex(item["hex"])
    require(hash_bytes(raw) == {key: item[key] for key in ("bytes", "sha256")}, "retained file hash differs")
    return raw if native else json.loads(raw)


def owner_process(work, launcher):
    for member in TRAIN["descendants"](launcher):
        try:
            proc = Path(f"/proc/{member['pid']}")
            args = [arg.decode() for arg in (proc / "cmdline").read_bytes().split(b"\0") if arg]
            if Path(os.readlink(proc / "exe")).name != "volparossa" or args[3:6] != ["compute", "peer", "workflow"]:
                continue
            require("--follow" in args and "--resume" not in args and "--execute" in args
                    and args[args.index("--max-batches") + 1] == "1"
                    and args[args.index("--max-seconds") + 1] == "600"
                    and args[args.index("--directory") + 1] == str(workflow(work)), "wrong owner workflow invocation")
            require(proc.stat().st_uid == workflow(work).stat().st_uid != 0, "workflow owner is not the node user")
            return {"identity": member, "operation": "compute peer workflow", "follow": True,
                    "manual_resume": False, "maximum_rounds_per_window": 1, "maximum_seconds_per_worker": 600}
        except (FileNotFoundError, ProcessLookupError):
            continue
    return None


def observe(work, launcher):
    JOBS["guest_work"](work)
    JOBS["observe"](work)
    owner = owner_process(work, launcher)
    require(owner is not None and alive(owner["identity"]), "live original workflow owner missing")
    # Adapt only the actual handle location. Reuse the existing pidfd/identity/
    # sandbox checks and exact one-worker SIGKILL without fabricating batch files.
    inject = JOBS["inject_loss"]
    previous = inject.__globals__["initial_handles"]
    inject.__globals__["initial_handles"] = initial_handles
    try:
        inject(work)
    finally:
        inject.__globals__["initial_handles"] = previous
    loss = read(work / "agent-jobs-loss-control.json")
    write(work / "agent-jobs-follow-owner.json", {**owner, "alive_after_loss": alive(owner["identity"]),
          "observed_boottime_ns": JOBS["boot_ns"]()})
    original = loss["original_handles"][0]["value"]
    node, broker = loss["survivor"]["node"], loss["survivor"]["broker"]
    # Bound this observer by the actual original leases plus one admission window;
    # this never changes or authorizes any execution deadline.
    deadline = min(time.monotonic() + 660, time.monotonic() + max(
        h["value"]["binding"]["expires_unix_seconds"] for h in loss["original_handles"]) - time.time() + 60)
    while time.monotonic() < deadline:
        require(alive(owner["identity"]), "follow owner ended before automatic recovery")
        candidate = workflow(work) / RETRY / "job-0.json"
        if candidate.is_file():
            handle = read(candidate)
            require(handle["provider_key"] == loss["original_handles"][1]["value"]["provider_key"]
                    and handle["binding"]["row_indices"] == [0]
                    and handle["binding"]["job_id"] != original["binding"]["job_id"], "automatic retry did not move failed rows to survivor")
            first = JOBS["boot_ns"]()
            current = JOBS["worker_snapshot"](work, node, broker, original["binding"]["dataset_sha256"])
            if current and alive(current["worker"]) and alive(current["broker"]):
                require(all(not alive(loss[name]["worker"]) for name in ("victim", "survivor")), "old workers overlap replacement")
                initial = initial_handles(work)
                require(initial == loss["original_handles"], "automatic controller overwrote initial handles")
                paths = [workflow(work) / FIRST / f"receipt-{h['value']['binding']['job_id']}.json" for h in initial]
                receipts = [read(path) for path in paths]
                require(receipts[0]["status"]["state"] == "failed" and receipts[1]["status"]["state"] == "complete",
                        "actual initial terminal receipts absent before replacement observation")
                result = {"worker": current, "handle": handle, "alive_before_and_after": alive(current["worker"]),
                          "original_workers_ended": True, "first_boottime_ns": first, "last_boottime_ns": JOBS["boot_ns"](),
                          "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
                          "handle_saved_unix_seconds": candidate.stat().st_mtime_ns // 1000000000,
                          "original_receipts": [retained_file(path, candidate.stat().st_uid) for path in paths],
                          "owner": owner, "same_owner_alive": alive(owner["identity"])}
                require(result["alive_before_and_after"] and result["same_owner_alive"], "replacement/owner ended during observation")
                # Existing jobs cleanup checks this exact real third process family.
                write(work / "agent-jobs-replacement-observation.json", result)
                return
        time.sleep(0.05)
    raise ValueError("automatic replacement worker was not observed before bounded original-lease wait")


def parse_output(raw):
    require(0 < len(raw) <= 1048576, "follow stdout bound")
    lines = raw.splitlines()
    require(1 < len(lines) <= 512, "follow requires progress plus final result")
    values = [json.loads(line) for line in lines]
    for index, value in enumerate(values[:-1]):
        require(value["operation"] == "compute_workflow_progress" and value["event"] == "COMPUTE_WORKFLOW_FOLLOW_WAIT"
                and value["follow_windows"] == index + 1 and value["follow_waits"] == index + 1,
                "invalid ordered follow progress")
    final = values[-1]
    require(final["operation"] == "compute_workflow" and final["complete"] is True and final["follow"] is True
            and final["follow_windows"] == len(values) and final["follow_waits"] == len(values) - 1
            and type(final["rounds_this_invocation"]) is int and 2 <= final["rounds_this_invocation"] <= final["follow_windows"]
            and final["maximum_rounds_per_window"] == 1
            and final["maximum_seconds_per_worker"] == 600 and final["stopped"] == "complete"
            and final["source_admission_expires_unix_seconds"] is None and final["pending_failure"] is False
            and type(final["follow_wait_milliseconds"]) is int and final["follow_wait_milliseconds"] >= 1,
            "single followed workflow did not complete both bounded rounds")
    return values[:-1], final


def capture(work):
    JOBS["guest_work"](work)
    owner = read(work / "agent-jobs-follow-owner.json")
    require(not alive(owner["identity"]), "original workflow owner not reaped")
    stdout = (work / "agent-jobs-follow-output.jsonl").read_bytes()
    events, result = parse_output(stdout)
    write(work / "agent-jobs-follow-result.json", result)
    write(work / "agent-jobs-follow-files.json", {"files": retained_tree(workflow(work)),
          "original_handles_after": initial_handles(work), "owner_reaped": True,
          "stdout": {**hash_bytes(stdout), "hex": stdout.hex()}, "events": events,
          "captured_boottime_ns": JOBS["boot_ns"]()})


def check_evidence(value, revision):
    require(value["success"] is True and value["source_revision"] == revision, "wrong follow source revision")
    require(value["provision"]["success"] is True and value["provision"]["installed_wheels"] == 38
            and value["provision"]["download_bytes"] == 523040250 and value["provision"]["training_performed"] is False,
            "follow case did not reuse pinned provisioning")
    JOBS["check_overlap"](value["observation"])
    source, published, layout, loss = (value[k] for k in ("source", "publish", "layout", "loss"))
    manifest_id = JOBS["source_manifest_id"](source, published)
    require(source["explicit_public_source"] is True and json.loads(source["dataset_json"]) == source["dataset"]
            and source["dataset"]["source_revision"] == revision and len(source["dataset"]["inference"]) == 2
            and source["dataset"]["visibility"] == "public" and source["dataset"]["license"] == "GPL-3.0-only"
            and hash_bytes(source["dataset_json"].encode()) == source["dataset_file"]
            and published["bytes"] == source["dataset_file"]["bytes"]
            and published["operation"] == "offline_content_publish" and published["network_publication"] is False,
            "original source/publication changed")
    a, b = layout["provider_nodes"]
    require(a != b and all(CUSTODY["peer_key"](value["peers"][n]) == layout["provider_keys"][n] for n in (a, b))
            and layout["control_relay_peer_id"] not in (value["peers"][a], value["peers"][b]), "wrong provider lineage")
    originals = [entry["value"] for entry in loss["original_handles"]]
    for index, node in enumerate((a, b)):
        JOBS["check_loss_handle"](originals[index], source["dataset"], published, manifest_id, node, layout)
        seen = next(w for w in value["observation"]["workers"] if w["node"] == node)
        require(originals[index]["binding"]["row_indices"] == [index] and originals[index]["binding"].get("task") is None
                and loss[("victim", "survivor")[index]] == seen
                and seen["dataset_json"] == JOBS["derive"](source["dataset"], [index]), "wrong signaled/source row")
    require(loss["signal"] == "SIGKILL" and loss["signal_number"] == 9 and loss["pidfd_bound"] is True
            and all(loss[k] is True for k in ("signal_sent", "worker_exit_observed", "both_workers_alive_before_signal",
                    "surviving_worker_alive_after_signal", "both_brokers_alive_after_signal"))
            and 0 < loss["signal_boottime_ns"] <= loss["exit_boottime_ns"], "actual worker death unproved")
    retained, files = value["retained"], value["retained"]["files"]
    require(retained["owner_reaped"] is True and retained["original_handles_after"] == loss["original_handles"], "owner/initial handles changed")
    stdout = bytes.fromhex(retained["stdout"]["hex"])
    require(hash_bytes(stdout) == {key: retained["stdout"][key] for key in ("bytes", "sha256")}, "follow stdout changed")
    events, result = parse_output(stdout)
    require(events == retained["events"] and result == value["result"], "final summary differs from actual stdout")
    owner, replacement = value["owner"], value["replacement"]
    require(owner["operation"] == "compute peer workflow" and owner["follow"] is True and owner["manual_resume"] is False
            and owner["maximum_rounds_per_window"] == 1 and owner["maximum_seconds_per_worker"] == 600
            and owner["alive_after_loss"] is True and replacement["same_owner_alive"] is True
            and replacement["owner"] == {k: v for k, v in owner.items() if k not in {"alive_after_loss", "observed_boottime_ns"}},
            "replacement was not followed by the same original live command")
    enrollment = decode(files, "workflow.json")
    require(enrollment["version"] == 1 and enrollment["provider_keys"] == [layout["provider_keys"][n] for n in (a, b)]
            and len(enrollment["packages"]) == 1 and enrollment["packages"][0] == {
                "publisher_key": published["publisher_key_hex"], "manifest_id": manifest_id,
                "dataset_sha256": source["dataset_file"]["sha256"], "rows": 2}, "owner enrollment changed")
    require(decode(files, "package-0000/dataset.json", True) == source["dataset_json"].encode()
            and decode(files, "package-0000/manifest.bin", True) == bytes.fromhex(source["manifest_hex"]), "stored source differs")
    receipts = []
    for index, handle in enumerate(originals):
        require(decode(files, FIRST + f"job-{index}.json") == handle
                and {k: files[FIRST + f"job-{index}.json"][k] for k in ("sha256", "bytes")} == loss["original_handles"][index]["file"],
                "original saved handle/lease mutated")
        path = FIRST + f"receipt-{handle['binding']['job_id']}.json"
        receipt = decode(files, path)
        require(receipt["version"] == 1 and receipt["handle"] == handle
                and receipt["status"]["binding"] == handle["binding"]
                and receipt["verified_at_unix_seconds"] >= enrollment["verified_at_unix_seconds"]
                and files[path] == replacement["original_receipts"][index], "original terminal receipt changed after recovery")
        receipts.append(receipt["status"])
    failed, kept = receipts
    require(failed["state"] == "failed" and failed["error"] == "worker_failed"
            and failed["report_json"] is None and failed["report_sha256"] is None and kept["state"] == "complete",
            "terminal failure/complete proof absent")
    first = decode(files, FIRST + "result.json")
    require(first["operation"] == "compute_distribute" and first["complete"] is False
            and first["dataset_manifest_id"] == manifest_id and first["outputs"][0] is None and len(first["jobs"]) == 2,
            "initial loss presented as success")
    for index in (0, 1):
        part = next(p for p in first["jobs"] if p["handle"] == originals[index])
        require(part["state"] == receipts[index]["state"], "initial result/terminal status differ")
    JOBS["check_loss_completed"](kept, originals[1], revision, first["outputs"][1])
    retry = decode(files, RETRY + "retry-0.json")
    handle, status = retry["handle"], retry["status"]
    JOBS["check_loss_handle"](handle, source["dataset"], published, manifest_id, b, layout)
    require(retry["original_handle"] == originals[0] and retry["original_state"] == "stopped"
            and retry["prior_terminal_receipt_received"] is True and retry["retried"] is True
            and handle["binding"]["row_indices"] == [0] and handle["binding"]["job_id"] not in [h["binding"]["job_id"] for h in originals]
            and handle["binding"]["model_fingerprint"] == originals[0]["binding"]["model_fingerprint"]
            and decode(files, RETRY + "job-0.json") == handle and decode(files, RETRY + "original-0.json") == originals[0]
            and decode(files, RETRY + "observation-0.json") == {"handle": originals[0], "state": "stopped", "status": failed},
            "automatic retry changed source/model or lacked terminal authorization")
    retry_result = decode(files, RETRY + "result.json")
    require(retry_result["operation"] == "compute_resume" and retry_result["complete"] is True
            and retry_result["dataset_manifest_id"] == manifest_id and retry_result["requested_rows"] == [0]
            and retry_result["full_dataset_requested"] is False and retry_result["maximum_retries_per_part"] == 1
            and retry_result["jobs"] == [retry] and len(retry_result["outputs"]) == 1,
            "completed rows were resubmitted or replacement incomplete")
    require(all(retry_result[k] is False for k in ("exactly_once_execution_guaranteed", "private_data_supported", "result_truthfulness_guaranteed")),
            "automatic recovery overstated")
    JOBS["check_loss_completed"](status, handle, revision, retry_result["outputs"][0])
    receipt_path = RETRY + f"receipt-{handle['binding']['job_id']}.json"
    new_receipt = decode(files, receipt_path)
    require(new_receipt["handle"] == handle and new_receipt["status"] == status, "replacement receipt differs")
    required = {".workflow.lock", "workflow.json", "package-0000/dataset.json", "package-0000/manifest.bin",
                FIRST + "job-0.json", FIRST + "job-1.json", FIRST + "result.json",
                *(FIRST + f"receipt-{h['binding']['job_id']}.json" for h in originals),
                *(RETRY + name for name in ("original-0.json", "observation-0.json", "job-0.json", "retry-0.json", "result.json")),
                RETRY + f"receipt-{originals[0]['binding']['job_id']}.json", receipt_path}
    require(set(files) == required, "extra attempt/row or missing original receipt")
    old_observation = decode(files, RETRY + f"receipt-{originals[0]['binding']['job_id']}.json")
    require(old_observation["handle"] == originals[0] and old_observation["status"] == failed, "reconciled old receipt changed")
    for name in files:
        decode(files, name, True)
    require(result["completed_packages"] == result["package_count"] == 1 and len(result["packages"]) == 1,
            "follow package accounting differs")
    package = result["packages"][0]
    outputs = [retry_result["outputs"][0], first["outputs"][1]]
    for output, receipt in zip(outputs, (status, kept)):
        output = dict(output, report_sha256=receipt["report_sha256"])
        require(output in package["outputs"], "workflow did not retain exact source/result provenance")
    require(package["complete"] is True and package["attempts"] == 2 and package["dataset_manifest_id"] == manifest_id
            and package["pending_handles"] == [] and len(package["outputs"]) == 2, "final workflow rows incomplete")
    worker, survivor = replacement["worker"], loss["survivor"]
    require(replacement["handle"] == handle and replacement["alive_before_and_after"] is True
            and replacement["original_workers_ended"] is True and worker["node"] == b
            and worker["broker"] == survivor["broker"] and worker["service"] == survivor["service"]
            and worker["node_namespace"] == survivor["node_namespace"] and worker["runtime_lock_inode"] == survivor["runtime_lock_inode"]
            and worker["worker"] not in [loss[n]["worker"] for n in ("victim", "survivor")]
            and worker["dataset_json"] == JOBS["derive"](source["dataset"], [0])
            and worker["dataset_file"]["sha256"] == handle["binding"]["dataset_sha256"]
            and loss["exit_boottime_ns"] < replacement["first_boottime_ns"] < replacement["last_boottime_ns"],
            "no distinct actual survivor worker carrying only failed rows")
    require(0 < handle["binding"]["expires_unix_seconds"] - replacement["handle_saved_unix_seconds"] <= 600,
            "replacement lease exceeds original per-worker authorization")
    require(all(item["modified_unix_ns"] <= files[RETRY + "job-0.json"]["modified_unix_ns"] for item in replacement["original_receipts"]),
            "replacement handle predates original terminal receipts")
    tick_ns = 1000000000 // replacement["clock_ticks_per_second"]
    require(worker["worker"]["start_ticks"] * tick_ns + tick_ns >= loss["exit_boottime_ns"], "replacement predates observed worker loss")
    require(worker["runtime_lock_held"] is True and worker["network_devices"] == ["lo"] and worker["ipv4_routes"] == []
            and worker["effective_capabilities"] == 0 and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][p] for p in ("/runtime", "/model", "/dataset.json"))
            and all(worker["worker_namespaces"][k] != worker["guest_namespaces"][k] for k in ("net", "pid", "ipc", "mnt"))
            and worker["worker_namespaces"]["net"] != worker["node_namespace"], "replacement sandbox not observed")
    CUSTODY["validate_path"](value["path"], value["peers"], layout, "inspect")
    application = value["path"]["privacy"]["exit"]["provider_application"]
    require(application[a]["request_packets"] > 0 and application[a]["response_payload_bytes"] > 0
            and application[b]["request_packets"] > 0 and application[b]["response_payload_bytes"] >=
            len(kept["report_json"].encode()) + len(status["report_json"].encode()), "protected path did not carry both actual reports")
    require(all(value["cleanup"].values()), "follow private cleanup incomplete")


def build_evidence(work, revision):
    value = {name: read(work / f"agent-jobs-{name}.json") for name in ("source", "publish", "layout", "observation", "provision")}
    value.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
                 cleanup=read(work / "agent-jobs-private-cleanup.json"),
                 loss=read(work / "agent-jobs-loss-control.json"), replacement=read(work / "agent-jobs-replacement-observation.json"),
                 owner=read(work / "agent-jobs-follow-owner.json"), result=read(work / "agent-jobs-follow-result.json"),
                 retained=read(work / "agent-jobs-follow-files.json", 12 * 1048576),
                 path={"selected_route": read(work / "content-custody-fetch-live-selection.json"),
                       "privacy": {role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
                       "control_privacy": read(work / "content-provider-custody-fetch-control.json"),
                       "gates": read(work / "content-custody-fetch-gates.json")})
    check_evidence(value, revision)
    write(work / "agent-jobs-follow-evidence.json", value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    evidence_path = work / "agent-jobs-follow-evidence.json"
    evidence = read(evidence_path, 16 * 1048576) if evidence_path.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(work / "agent-jobs-follow-smoke.json", {
        "report_kind": KIND, "source_revision": revision, "scope": SCOPE,
        "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and evidence is not None,
        "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker, "runner_exit_status": status,
        "automatic_selected_peer_recovery_claimed": evidence is not None,
        "exactly_once_execution_claimed": False, "original_lease_extension_claimed": False,
        "full_b03_claimed": False, "full_alpha_claimed": False,
        "evidence": evidence, "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host})


def check_report(value, revision):
    require(value["report_kind"] == KIND and value["source_revision"] == revision and value["scope"] == SCOPE
            and value["success"] is True and value["runner_exit_status"] == 0 and value["observed_blocker"] is None
            and value["automatic_selected_peer_recovery_claimed"] is True, "incomplete automatic recovery proof")
    require(value["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "follow host/owned cleanup differs")
    require(all(value[k] is False for k in ("exactly_once_execution_claimed", "original_lease_extension_claimed", "full_b03_claimed", "full_alpha_claimed")),
            "follow proof overstated")
    check_evidence(value["evidence"], revision)


def self_test():
    # Pure parsing/storage assertions, never model, signal or network evidence.
    final = {"operation": "compute_workflow", "complete": True, "follow": True, "follow_windows": 2,
             "follow_waits": 1, "follow_wait_milliseconds": 5000, "rounds_this_invocation": 2,
             "maximum_rounds_per_window": 1, "maximum_seconds_per_worker": 600, "stopped": "complete",
             "source_admission_expires_unix_seconds": None, "pending_failure": False}
    event = {"operation": "compute_workflow_progress", "event": "COMPUTE_WORKFLOW_FOLLOW_WAIT", "follow_windows": 1, "follow_waits": 1}
    encode = lambda x: (json.dumps(event) + "\n" + json.dumps(x) + "\n").encode()
    require(parse_output(encode(final)) == ([event], final), "real JSONL output shape rejected")
    for update in ({"follow": False}, {"follow_windows": 1}, {"rounds_this_invocation": 1},
                   {"complete": False}, {"source_admission_expires_unix_seconds": 99}, {"maximum_seconds_per_worker": 1200}):
        try:
            parse_output(encode(dict(final, **update)))
        except ValueError:
            continue
        raise AssertionError("invalid follow output accepted")
    with tempfile.TemporaryDirectory(prefix="volparossa-follow-check-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        write(root / "workflow.json", {"version": 1})
        with (root / ".workflow.lock").open("x"):
            pass
        (root / ".workflow.lock").chmod(0o600)
        tree = retained_tree(root)
        require(decode(tree, "workflow.json") == {"version": 1} and decode(tree, ".workflow.lock", True) == b"", "exact retained bytes differ")
        altered = copy.deepcopy(tree)
        altered["workflow.json"]["sha256"] = "0" * 64
        try:
            decode(altered, "workflow.json")
        except ValueError:
            pass
        else:
            raise AssertionError("changed retained hash accepted")
        (root / "package-0000").symlink_to(root, target_is_directory=True)
        try:
            retained_tree(root)
        except ValueError:
            pass
        else:
            raise AssertionError("retained symlink accepted")
        previous = sys.argv
        try:
            sys.argv = [str(HERE / "agent-jobs-follow-smoke.py"), "finalize", str(root), "a" * 40,
                        "1", "false", "1", "synthetic-failure", "TEST_ONLY"]
            main()
        finally:
            sys.argv = previous
        diagnostic = read(root / "agent-jobs-follow-smoke.json")
        require(diagnostic["success"] is False and diagnostic["evidence"] is None
                and diagnostic["runner_exit_status"] == 1 and diagnostic["observed_blocker"] == "TEST_ONLY",
                "actual eight-argument finalize dispatch lost failure diagnostics")
    value = contract_fixture()
    check_evidence(value, "a" * 40)
    changes = {
        "no_observed_death": lambda x: x["loss"].update(worker_exit_observed=False),
        "different_owner": lambda x: x["replacement"]["owner"]["identity"].update(pid=99999),
        "owner_gone": lambda x: x["replacement"].update(same_owner_alive=False),
        "wrong_replacement_peer": lambda x: x["replacement"]["worker"].update(node=x["layout"]["provider_nodes"][0]),
        "old_worker_overlap": lambda x: x["replacement"].update(original_workers_ended=False),
        "original_deadline_changed": lambda x: x["retained"]["original_handles_after"][0]["value"]["binding"].update(expires_unix_seconds=9999),
        "retained_receipt_changed": lambda x: x["replacement"]["original_receipts"][1].update(sha256="0" * 64),
        "new_lease_overrun": lambda x: x["replacement"].update(handle_saved_unix_seconds=1),
        "extra_attempt": lambda x: x["retained"]["files"].update({"package-0000/attempt-0002/result.json": {}}),
        "missing_capture": lambda x: x["path"]["privacy"].pop("exit"),
        "cleanup_incomplete": lambda x: x["cleanup"].update(done=False),
    }
    for name, change in changes.items():
        altered = copy.deepcopy(value)
        change(altered)
        try:
            check_evidence(altered, "a" * 40)
        except (ValueError, KeyError):
            continue
        raise AssertionError(f"invalid follow evidence accepted: {name}")
    print("follow exact receipt/owner/reassignment plus 11 negative checks PASS; synthetic contracts only, no model, signal or network executed")


def contract_fixture():
    value = JOBS["self_test"]()
    first = copy.deepcopy(value["result"])
    originals = [part["handle"] for part in first["jobs"]]
    failed = {"binding": originals[0]["binding"], "state": "failed", "error": "worker_failed", "report_json": None, "report_sha256": None}
    kept = value["statuses"][1]
    first["complete"] = False
    first["outputs"][0] = None
    first["jobs"][0] = {"handle": originals[0], "state": "failed", "error": "worker_failed"}
    handle = copy.deepcopy(originals[0])
    handle["provider_key"] = originals[1]["provider_key"]
    handle["binding"]["job_id"] = "d" * 32
    handle["binding"]["expires_unix_seconds"] = 2500
    status = dict(value["statuses"][0], binding=handle["binding"])
    retry = {"original_handle": originals[0], "original_state": "stopped", "handle": handle,
             "status": status, "retried": True, "prior_terminal_receipt_received": True}
    resumed_output = dict(value["result"]["outputs"][0], job_id=handle["binding"]["job_id"], provider_key=handle["provider_key"])
    resumed = {"operation": "compute_resume", "complete": True, "dataset_manifest_id": first["dataset_manifest_id"],
               "requested_rows": [0], "full_dataset_requested": False, "maximum_retries_per_part": 1,
               "jobs": [retry], "outputs": [resumed_output], "exactly_once_execution_guaranteed": False,
               "private_data_supported": False, "result_truthfulness_guaranteed": False}
    files = {}
    def put(name, item):
        raw = item if isinstance(item, bytes) else json.dumps(item).encode()
        files[name] = {**hash_bytes(raw), "hex": raw.hex(), "inode": [1, len(files) + 1],
                       "modified_unix_ns": (2100 if name.startswith(RETRY) else 2000) * 1000000000}
    put(".workflow.lock", b"")
    put("workflow.json", {"version": 1, "verified_at_unix_seconds": 1000,
                          "provider_keys": [h["provider_key"] for h in originals],
                          "packages": [{"publisher_key": value["publish"]["publisher_key_hex"], "manifest_id": first["dataset_manifest_id"],
                                        "dataset_sha256": value["source"]["dataset_file"]["sha256"], "rows": 2}]})
    put("package-0000/dataset.json", value["source"]["dataset_json"].encode())
    put("package-0000/manifest.bin", bytes.fromhex(value["source"]["manifest_hex"]))
    for index, receipt in enumerate((failed, kept)):
        put(FIRST + f"job-{index}.json", originals[index])
        put(FIRST + f"receipt-{originals[index]['binding']['job_id']}.json",
            {"version": 1, "handle": originals[index], "status": receipt, "verified_at_unix_seconds": 1500})
    put(FIRST + "result.json", first)
    for name, item in {"original-0.json": originals[0], "observation-0.json": {"handle": originals[0], "state": "stopped", "status": failed},
                       "job-0.json": handle, "retry-0.json": retry, "result.json": resumed}.items():
        put(RETRY + name, item)
    for prior, receipt in ((originals[0], failed), (handle, status)):
        put(RETRY + f"receipt-{prior['binding']['job_id']}.json", {"version": 1, "handle": prior, "status": receipt, "verified_at_unix_seconds": 2100})
    for index, observed in enumerate(value["observation"]["workers"]):
        observed["worker"]["start_ticks"] = 100 + index
        observed["service"] = {"pid": index + 10, "start_ticks": 5}
    victim, survivor = value["observation"]["workers"]
    entries = [{"value": h, "file": {k: files[FIRST + f"job-{n}.json"][k] for k in ("bytes", "sha256")}} for n, h in enumerate(originals)]
    value["loss"] = {"victim": copy.deepcopy(victim), "survivor": copy.deepcopy(survivor), "original_handles": entries,
                     "signal": "SIGKILL", "signal_number": 9, "pidfd_bound": True, "signal_sent": True,
                     "worker_exit_observed": True, "both_workers_alive_before_signal": True,
                     "surviving_worker_alive_after_signal": True, "both_brokers_alive_after_signal": True,
                     "signal_boottime_ns": 1000000000, "exit_boottime_ns": 2000000000}
    owner = {"identity": {"pid": 800, "start_ticks": 5}, "operation": "compute peer workflow", "follow": True,
             "manual_resume": False, "maximum_rounds_per_window": 1, "maximum_seconds_per_worker": 600}
    value["owner"] = dict(copy.deepcopy(owner), alive_after_loss=True, observed_boottime_ns=3000000000)
    worker = copy.deepcopy(survivor)
    worker["worker"] = {"pid": 999, "start_ticks": 900}
    worker["dataset_json"] = JOBS["derive"](value["source"]["dataset"], [0])
    worker["dataset_file"] = hash_bytes(worker["dataset_json"].encode())
    value["replacement"] = {"worker": worker, "handle": handle, "alive_before_and_after": True, "original_workers_ended": True,
                            "first_boottime_ns": 10000000000, "last_boottime_ns": 11000000000, "clock_ticks_per_second": 100,
                            "handle_saved_unix_seconds": 2100, "owner": owner, "same_owner_alive": True,
                            "original_receipts": [copy.deepcopy(files[FIRST + f"receipt-{h['binding']['job_id']}.json"]) for h in originals]}
    value["result"] = {"operation": "compute_workflow", "complete": True, "follow": True, "follow_windows": 2,
                       "follow_waits": 1, "follow_wait_milliseconds": 5000, "rounds_this_invocation": 2,
                       "maximum_rounds_per_window": 1, "maximum_seconds_per_worker": 600, "stopped": "complete",
                       "source_admission_expires_unix_seconds": None, "pending_failure": False, "completed_packages": 1, "package_count": 1,
                       "packages": [{"complete": True, "attempts": 2, "dataset_manifest_id": first["dataset_manifest_id"], "pending_handles": [],
                                     "outputs": [dict(resumed_output, report_sha256=status["report_sha256"]),
                                                 dict(first["outputs"][1], report_sha256=kept["report_sha256"])]}]}
    event = {"operation": "compute_workflow_progress", "event": "COMPUTE_WORKFLOW_FOLLOW_WAIT", "follow_windows": 1, "follow_waits": 1}
    raw = (json.dumps(event) + "\n" + json.dumps(value["result"]) + "\n").encode()
    value["retained"] = {"files": files, "original_handles_after": copy.deepcopy(entries), "owner_reaped": True,
                         "stdout": {**hash_bytes(raw), "hex": raw.hex()}, "events": [event]}
    return value


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        self_test()
    elif args[0] == "prepare" and len(args) == 3:
        prepare(Path(args[1]), args[2])
    elif args[0] == "observe" and len(args) == 3:
        observe(Path(args[1]), int(args[2]))
    elif args[0] == "capture" and len(args) == 2:
        capture(Path(args[1]))
    elif args[0] == "evidence" and len(args) == 3:
        build_evidence(Path(args[1]), args[2])
    elif args[0] == "finalize" and len(args) == 8:
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif args[0] == "report" and len(args) == 3:
        check_report(read(Path(args[1]), 16 * 1048576), args[2])
        print("one-command automatic peer worker-loss recovery report PASS")
    else:
        raise ValueError("invalid agent-jobs-follow collector command")


if __name__ == "__main__":
    main()
