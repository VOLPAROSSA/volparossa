#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual hierarchical peer synthesis observations and original-receipt reconstruction."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import sys
import time

HERE = Path(__file__).resolve().parent
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
PROFILE = "application/vnd.volparossa.agent-derived.v3+json"
CLAIM = "coordinator_verified_local_rpc_status_not_portable_execution_attestation"
ATTEMPT = "work/package-0000/attempt-0000"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def answer(output, handle, status, manifest, start, end, index):
    require(output["sample_index"] == index and isinstance(output["text"], str) and output["text"].strip()
            and len(output["text"].encode()) <= 1024 and "\0" not in output["text"]
            and type(output["generated_tokens"]) is int and 0 <= output["generated_tokens"] <= 64
            and output["text_truncated"] is False, "generated parent is missing, malformed or wire-truncated")
    return {"text": output["text"], "provider_key": handle["provider_key"], "job_id": handle["binding"]["job_id"],
            "report_sha256": status["report_sha256"], "package_manifest_id": manifest,
            "model_fingerprint": handle["binding"]["model_fingerprint"], "output_index": index,
            "source_start": start, "source_end": end, "generated_tokens": output["generated_tokens"], "text_truncated": False}


def observe(work, pid):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](pid)
    root = work / "state-client/compute-source/public-document"
    layout = read(work / "agent-jobs-layout.json")
    brokers = {node: JOBS["identity"](JOBS["broker_pid"](node)) for node in layout["provider_nodes"]}
    observed, identifiers, started = [], set(), time.monotonic()
    while JOBS["alive"](owner) and time.monotonic() - started < 1320:
        for path in sorted(root.glob("synthesis/level-??-group-????/package-????/work/package-0000/attempt-0000/job-?.json")):
            relative = path.relative_to(root).as_posix()
            match = re.fullmatch(r"synthesis/level-([0-9]{2})-group-([0-9]{4})/package-([0-9]{4})/" + ATTEMPT + r"/job-([01])\.json", relative)
            require(match is not None, "unexpected synthesis handle path")
            try:
                handle = read(path)
            except (OSError, json.JSONDecodeError):
                continue  # The real atomic handle publication may be in flight.
            binding = handle["binding"]
            if binding["job_id"] in identifiers:
                continue
            require(handle["capabilities"].get("derived_inference_v3") is True, "peer lacks actual synthesis capability")
            node = next((n for n in brokers if layout["provider_keys"][n] == handle["provider_key"]), None)
            require(node is not None, "unexpected synthesis peer")
            first = time.monotonic_ns()
            current = JOBS["worker_snapshot"](work, node, brokers[node], binding["dataset_sha256"])
            if current and JOBS["alive"](current["worker"]):
                require(json.loads(current["dataset_json"])["version"] == 3, "observed original excerpt as synthesis")
                record = {"level": int(match[1]), "group": int(match[2]), "package": int(match[3]),
                          "handle_path": relative, "handle": handle, "handle_file": JOBS["file_hash"](path, 16384),
                          "worker": current, "first_monotonic_ns": first, "last_monotonic_ns": time.monotonic_ns(),
                          "alive_before_and_after": JOBS["alive"](current["worker"])}
                require(record["alive_before_and_after"], "synthesis worker ended during observation")
                write(work / f"agent-public-document-synthesis-worker-{len(observed):04}.json", record)
                observed.append(record)
                identifiers.add(binding["job_id"])
        time.sleep(0.05)
    require(not JOBS["alive"](owner), "synthesis owner exceeded unchanged fixture window")
    result = read(work / "agent-public-document-result.json", 32 * 1048576)
    levels = result.get("synthesis", {}).get("levels", [])
    require(result["complete"] is True and len(levels) >= 2 and all(level["complete"] is True for level in levels),
            "actual model did not finish at least two reduction levels")
    require({record["level"] for record in observed} == {level["level"] for level in levels},
            "no real isolated worker observed at every actual reduction level")
    write(work / "agent-public-document-synthesis-observation.json", {"owner": owner,
          "owner_reaped": True, "workers": observed, "observed_monotonic_ns": time.monotonic_ns()})


def assert_stopped(work):
    paths = sorted(work.glob("agent-public-document-synthesis-worker-*.json"))
    require(len(paths) <= 128, "unbounded observed synthesis process set")
    identities = []
    for path in paths:
        record = read(path)
        require(not any(JOBS["alive"](member) for member in record["worker"]["owned_processes"]),
                "owned synthesis process remains alive")
        identities.append(record["worker"]["worker"])
    return {"synthesis_workers_ended": True, "synthesis_worker_identities": identities} if paths else {}


def expected_rows(parents, parts, question, offset):
    document = "".join(parent["text"] + "\n" for parent in parents).encode()
    rows = []
    for part in parts:
        start, end, base, inputs = part["start"], part["end"], 0, []
        for index, parent in enumerate(parents):
            length = len((parent["text"] + "\n").encode())
            if start < base + length and end > base:
                inputs.append({**{key: parent[key] for key in ("text", "provider_key", "job_id", "report_sha256",
                    "package_manifest_id", "model_fingerprint", "output_index")}, "parent_index": offset + index,
                    "source_start": parent["source_start"], "source_end": parent["source_end"],
                    "piece_start": max(0, start - base), "piece_end": min(end, base + length) - base})
            base += length
        require(base == len(document) and inputs, "reduction parent coverage missing")
        pieces = b"".join((entry["text"] + "\n").encode()[entry["piece_start"]:entry["piece_end"]] for entry in inputs)
        require(pieces == document[start:end], "reduction piece reconstruction differs")
        rows.append({"question": question, "context": pieces.decode(), "inputs": inputs})
    return document, rows


def check(value, raw, enrollment, parents, response_bytes, job_ids, api):
    load = lambda name: json.loads(raw[name])
    levels = value["result"]["synthesis"]["levels"]
    require(2 <= len(levels) <= 16 and enrollment["synthesize"] is True, "actual hierarchical synthesis was not enrolled/completed")
    observation = value["synthesis_observation"]
    require(observation["owner_reaped"] is True and observation["workers"], "synthesis executor observations missing")
    nodes, layout = {w["node"]: w for w in value["observation"]["workers"]}, value["layout"]
    executed, rounds = {}, 0
    for number, level in enumerate(levels, 1):
        require(level["level"] == number and level["complete"] is True and level["parents"] == len(parents)
                and len(parents) > 1 and len(level["groups"]) == (len(parents) + 63) // 64,
                "reduction level skipped or invented parents")
        following = []
        for group_index, group in enumerate(level["groups"]):
            prefix = f"synthesis/level-{number:02}-group-{group_index:04}"
            previous = parents[group_index * 64:group_index * 64 + 64]
            require(load(prefix + "/parents.json") == previous and raw[prefix + "/parents.json"] == encoded(previous),
                    "original generated parent receipts changed")
            saved_group = load(prefix + "/group.json")
            require(saved_group["version"] == 1 and saved_group["level"] == number
                    and saved_group["parent_offset"] == group_index * 64 and saved_group["parents_sha256"] == sha(encoded(previous))
                    and saved_group["source_manifest_id"] == enrollment["source_manifest_id"]
                    and enrollment["selected_at_unix_seconds"] <= saved_group["created_at_unix_seconds"] < enrollment["expires_at_unix_seconds"],
                    "reduction group authority/time/provenance changed")
            plan = load(prefix + "/document-plan.json")
            combined, rows = expected_rows(previous, plan["parts"], enrollment["public_question"], group_index * 64)
            api["plan"](plan, combined, True)
            require(load(prefix + "/planner-input.json") == {"version": 1, "visibility": "public", "license": enrollment["license"],
                    "document": combined.decode(), "question": enrollment["public_question"], "synthesis": True},
                    "real planner received different intermediate answers/prompt profile")
            planner = load(prefix + "/tokenizer-report.json")
            require(planner["mode"] == "plan_document" and planner["status"] == "ok" and planner["device"] == "cpu"
                    and planner["model_weights_loaded"] is False and planner["updates_completed"] == 0
                    and "outputs" not in planner and "baseline_evaluation" not in planner
                    and planner["dataset"]["sha256"] == sha(raw[prefix + "/planner-input.json"])
                    and planner["dataset"]["synthesis"] is True
                    and load(prefix + "/tokenizer/report.json").items() <= planner.items()
                    and load(prefix + "/tokenizer/document-plan.json") == plan
                    and planner["artifacts"] == [{"relative_path": "document-plan.json",
                        "bytes": len(raw[prefix + "/tokenizer/document-plan.json"]), "sha256": sha(raw[prefix + "/tokenizer/document-plan.json"])}],
                    "real synthesis tokenizer execution/artifact missing")
            api["supervisor"](planner)
            require(group == {"group": group_index, "parents": len(previous), "complete": True,
                    "parts": len(rows), "input_sha256": sha(combined)}, "group completion accounting differs")
            for package_index in range((len(rows) + 3) // 4):
                rounds += 1
                package = prefix + f"/package-{package_index:04}"
                data = load(package + "/dataset.json")
                package_rows = rows[package_index * 4:package_index * 4 + 4]
                require(data == {"version": 3, "visibility": "public", "license": enrollment["license"],
                        "source_manifest_hex": raw["source.manifest"].hex(), "level": number, "claim_scope": CLAIM,
                        "inference": package_rows}, "signed v3 bytes/provenance contain invented, omitted or reordered inputs")
                authority = dict(enrollment, selected_at_unix_seconds=saved_group["created_at_unix_seconds"])
                manifest_id = api["manifest"](raw[package + "/dataset.manifest"], raw[package + "/dataset.json"], authority,
                    f"derived-l{number:02}-g{group_index:04}-p{package_index:04}", PROFILE)
                require(raw[package + "/work/package-0000/dataset.json"] == raw[package + "/dataset.json"]
                        and raw[package + "/work/package-0000/manifest.bin"] == raw[package + "/dataset.manifest"],
                        "workflow received a different signed synthesis input")
                batch = load(package + "/" + ATTEMPT + "/result.json")
                task = {"kind": "answer_public_question_v1", "question": enrollment["public_question"]}
                count = min(2, len(package_rows))
                require(batch["operation"] == "compute_distribute" and batch["complete"] is True
                        and batch["dataset_manifest_id"] == manifest_id and batch["task"] == task
                        and batch["provider_count"] == len(batch["jobs"]) == count and len(batch["outputs"]) == len(package_rows),
                        "real synthesis batch incomplete")
                joined = [None] * len(package_rows)
                for part in batch["jobs"]:
                    handle = part["handle"]
                    binding, caps = handle["binding"], handle["capabilities"]
                    node = next((n for n in nodes if layout["provider_keys"][n] == handle["provider_key"]), None)
                    require(node is not None and caps.get("derived_inference_v3") is True and caps["task_derivation_v1"] is True
                            and binding["task"] == task and binding["dataset_manifest_id"] == manifest_id
                            and binding["expires_unix_seconds"] <= enrollment["expires_at_unix_seconds"], "wrong synthesis peer/capability/lease")
                    slot = layout["provider_nodes"].index(node)
                    selected = binding["row_indices"]
                    require(selected == list(range(slot, len(package_rows), count)) and selected
                            and binding["job_id"] not in job_ids and re.fullmatch(r"[0-9a-f]{32}", binding["job_id"]),
                            "reused or overlapping synthesis job")
                    job_ids.add(binding["job_id"])
                    expected_model = {"model_id": "HuggingFaceTB/SmolLM2-135M-Instruct", "model_revision": JOBS["TRAIN"]["MODEL_REVISION"],
                                      "base_weights": {"bytes": 269060552, "sha256": JOBS["TRAIN"]["WEIGHT_HASH"]}, "adapter_files": None}
                    require(caps["model"] == expected_model and caps["model_fingerprint"] == binding["model_fingerprint"]
                            and caps["public_inference_only"] is True and caps["runtime_slots"] == 1 and caps["max_threads"] == 2,
                            "synthesis model identity changed")
                    derived = copy.deepcopy(data)
                    derived["inference"] = [package_rows[n] for n in selected]
                    derived_raw = encoded(derived)
                    require(binding["dataset_sha256"] == sha(derived_raw), "synthesis worker input hash changed")
                    attempt = package + "/" + ATTEMPT
                    require(load(attempt + f"/job-{slot}.json") == handle, "actual retained synthesis handle changed")
                    receipt = load(attempt + f"/receipt-{binding['job_id']}.json")
                    status = receipt["status"]
                    require(receipt["handle"] == handle and status["binding"] == binding
                            and status["state"] == part["state"] == "complete"
                            and status["report_sha256"] == part["report_sha256"] == sha(status["report_json"].encode()),
                            "synthesis receipt/report changed")
                    actual = json.loads(status["report_json"])
                    require(actual["mode"] == "infer" and actual["status"] == "ok" and actual["device"] == "cpu"
                            and actual["updates_completed"] == 0 and actual["dataset"]["version"] == 3
                            and actual["dataset"]["level"] == number and actual["dataset"]["sha256"] == sha(derived_raw)
                            and actual["dataset"]["source_manifest_sha256"] == enrollment["source_manifest_id"]
                            and actual["baseline_evaluation"] is None and len(actual["outputs"]) == len(selected)
                            and actual["model"]["files"]["model.safetensors"] == expected_model["base_weights"],
                            "no actual v3 inference result")
                    api["supervisor"](actual)
                    response_bytes[node] += len(status["report_json"].encode())
                    executed[binding["job_id"]] = (number, handle, derived_raw, node)
                    for local, row_index in enumerate(selected):
                        output = actual["outputs"][local]
                        reported = batch["outputs"][row_index]
                        require(reported == {"sample_index": row_index, "provider_key": handle["provider_key"],
                                "job_id": binding["job_id"], "text": output["text"]}, "synthesis returned another answer")
                        inputs = package_rows[row_index]["inputs"]
                        joined[row_index] = answer(output, handle, status, manifest_id,
                            min(i["source_start"] for i in inputs), max(i["source_end"] for i in inputs), local)
                require(all(joined), "a synthesis part has no actual model result")
                following.extend(joined)
        require(level["outputs"] == len(following) < len(parents) and level["answers"] == following
                and level["generation_limit_reached"] is any(item["generated_tokens"] == 64 for item in following)
                and load(f"synthesis/level-{number:02}-result.json") == level,
                "hierarchy did not shrink or changed completed results")
        parents = following
    final = value["result"]["synthesis"]
    require(len(parents) == 1 and value["result"]["synthesized_answer"] == parents[0]
            and final["complete"] is True and final["claim_scope"] == CLAIM
            and final["generation_limit_reached"] is (parents[0]["generated_tokens"] == 64)
            and final["model_answer_correctness_proven"] is False and final["semantic_completeness_proven"] is False
            and value["resume"]["synthesis"] == final and value["resume"]["synthesized_answer"] == parents[0],
            "final answer is not the exact real last worker output or offline resume changed it")
    observed_levels, observed_ids, processes = set(), set(), []
    for record in observation["workers"]:
        worker, handle = record["worker"], record["handle"]
        identifier = handle["binding"]["job_id"]
        require(identifier in executed and identifier not in observed_ids, "unknown/duplicate observed synthesis job")
        number, expected, derived_raw, node = executed[identifier]
        require(record["level"] == number and expected == handle and worker["node"] == node
                and worker["dataset_json"].encode() == derived_raw and worker["dataset_file"]["sha256"] == sha(derived_raw)
                and worker["broker"] == nodes[node]["broker"] and worker["service"] == nodes[node]["service"]
                and worker["node_namespace"] == nodes[node]["node_namespace"]
                and worker["input_inodes"]["model/model.safetensors"] == nodes[node]["input_inodes"]["model/model.safetensors"]
                and worker["worker"] not in [entry["worker"] for entry in nodes.values()]
                and worker["worker"] not in processes and record["alive_before_and_after"] is True
                and record["first_monotonic_ns"] < record["last_monotonic_ns"], "actual synthesis worker lineage differs")
        require(worker["runtime_lock_held"] is True and worker["runtime_lock_inode"] == nodes[node]["runtime_lock_inode"]
                and worker["network_devices"] == ["lo"] and worker["ipv4_routes"] == []
                and worker["effective_capabilities"] == 0 and worker["host_home_visible"] is False
                and worker["other_node_state_hidden"] is True
                and all("ro" in worker["mounts"][p] for p in ("/runtime", "/model", "/dataset.json"))
                and all(worker["worker_namespaces"][k] != worker["guest_namespaces"][k] for k in ("net", "pid", "ipc", "mnt"))
                and worker["worker_namespaces"]["net"] != worker["node_namespace"], "synthesis worker isolation missing")
        snapshot = value["files"]["snapshot"][record["handle_path"]]
        require(record["handle_file"] == {key: snapshot[key] for key in ("sha256", "bytes")}
                and load(record["handle_path"]) == handle, "observed synthesis handle changed")
        observed_levels.add(number)
        observed_ids.add(identifier)
        processes.append(worker["worker"])
    require(observed_levels == set(range(1, len(levels) + 1)), "real worker missing at a reduction level")
    for phase in ("stopped", "resumed"):
        require(value[phase]["synthesis_workers_ended"] is True and value[phase]["synthesis_worker_identities"] == processes,
                "actual synthesis family cleanup not retained")
    return rounds


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["self-test"]:
        runpy.run_path(str(HERE / "test-agent-document-synthesis.py"), run_name="__main__")
    else:
        require(len(args) == 3 and args[0] == "observe", "invalid synthesis collector command")
        observe(Path(args[1]), int(args[2]))
