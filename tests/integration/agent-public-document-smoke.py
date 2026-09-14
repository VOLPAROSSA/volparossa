#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual pinned-tokenizer document jobs; receipt joins are not answer-quality proof."""

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
QUESTION = "Summarize the provided public context."
TASK = {"kind": "answer_public_question_v1", "question": QUESTION}
MODEL = "HuggingFaceTB/SmolLM2-135M-Instruct"
TOKENIZER = "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c"
PROFILE = "application/vnd.volparossa.agent-document.v2+json"
ATTEMPT = "work/package-0000/attempt-0000"
MAX_EXPORT = 32 * 1048576
SCOPE = ("explicit public README excerpt, actual pinned tokenizer with byte-complete prompt-bounded ranges, "
         "two simultaneous isolated peer workers over protected paths, bounded package resume and unchanged "
         "completed receipts after brokers/route stop; not protected source retrieval, answer correctness, "
         "neural synthesis, private offload or full B03")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def root_path(work):
    return work / "state-client/compute-source/public-document"


def source_excerpt(raw):
    require(len(raw) >= 5120, "README too short for real multipart fixture")
    # Preserve a literal contiguous UTF-8 prefix, never pad/repeat invented data.
    selected = raw[:5120].decode("utf-8", errors="ignore").encode()
    require(4096 <= len(selected) <= 6144 and raw.startswith(selected), "wrong public excerpt")
    return selected


def public_readme(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o400 and 5120 <= info.st_size <= 1048576,
            "public owner README is not the explicit bounded read-only copy")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "public README changed while reading")
    return raw


def prepare(work):
    # This is the installed unprivileged helper, not the root-only source-tree
    # observer. TRAIN.guest_guard's source-location test deliberately does not
    # apply to a helper whose dependencies live in the owned guest WORK/bin.
    require(TRAIN["socket"].gethostname() == "volparossa-alpha"
            and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
            and os.geteuid() != 0 and work.parent == Path("/opt") and work.name.startswith("va.")
            and not work.is_symlink() and HERE == work / "bin", "wrong installed guest document helper")
    helper = Path(__file__).lstat()
    require(stat.S_ISREG(helper.st_mode) and helper.st_uid == 0 and not helper.st_mode & 0o222,
            "guest helper is not the root-installed read-only source")
    source = JOBS["private"](work / "state-client/compute-source", "compute-source")
    raw = public_readme(source / "document-README.md")
    require(raw == (HERE / "agent-jobs-README.md").read_bytes(), "owner README differs from the original staged public source")
    selected = source_excerpt(raw)
    with (source / "document-input.txt").open("xb") as output:
        output.write(selected)
    (source / "document-input.txt").chmod(0o600)
    owner_model = source / "document-model/model.safetensors"
    peer_model = work / "agent-jobs-user/provision/model/model.safetensors"
    own, peer = owner_model.stat(), peer_model.stat()
    require((own.st_dev, own.st_ino) != (peer.st_dev, peer.st_ino), "owner model copy is aliased")
    require(JOBS["file_hash"](owner_model, 269060552) == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]},
            "owner tokenizer model assets differ from explicit pinned provision")
    print(json.dumps({"source": "README.md", "source_revision_bound_by_runner": True,
                      "readme_sha256": sha(raw), "excerpt_hex": selected.hex(), "excerpt_sha256": sha(selected),
                      "owner_model_inode": [own.st_dev, own.st_ino], "peer_model_inode": [peer.st_dev, peer.st_ino],
                      "private_copies_no_hardlinks": True}))


def observe(work, pid):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](pid)
    started = time.monotonic_ns()
    root = root_path(work)
    # Local real-tokenizer execution has its own original 600-second deadline.
    # The 90-second admission budget starts only once signed document enrollment
    # exists, not while the planner is legitimately loading/tokenizing.
    while not (root / "document.json").is_file():
        require(JOBS["alive"](owner) and time.monotonic_ns() - started < 610_000_000_000,
                "real tokenizer/enrollment did not finish within its existing deadline")
        time.sleep(0.05)
    admitted = time.monotonic_ns()
    for _ in range(1800):
        try:
            paths = [root / "package-0000" / ATTEMPT / f"job-{n}.json" for n in (0, 1)]
            handles = [read(path) for path in paths]
            require(all(h["binding"]["task"] == TASK and h["capabilities"]["task_derivation_v1"] is True
                        for h in handles), "initial handles have another public task")
        except (OSError, ValueError, KeyError):
            require(JOBS["alive"](owner), "document ended before actual peer admission")
            time.sleep(0.05)
            continue
        write(work / "agent-public-document-admission.json", {
            "planner_started_monotonic_ns": started, "enrollment_observed_monotonic_ns": admitted,
            "handles_observed_monotonic_ns": time.monotonic_ns(),
            "handles": [JOBS["file_hash"](path, 16384) for path in paths]})
        return JOBS["observe"](work)
    raise ValueError("document did not retain real peer handles within admission deadline")


def snapshot(root, package_only=False):
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not root.is_symlink(), "wrong retained document root")
    result, total = {}, 0
    for count, path in enumerate(root.rglob("*")):
        require(count < 2048, "unbounded document fixture tree")
        relative = path.relative_to(root).as_posix()
        if not package_only and (relative == "publication-cache" or relative.startswith("publication-cache/")):
            continue  # Native cache is not the completed-receipt state under test.
        item = path.lstat()
        require(item.st_uid == info.st_uid and not path.is_symlink(), "retained file owner/symlink differs")
        if stat.S_ISDIR(item.st_mode):
            continue
        require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and stat.S_IMODE(item.st_mode) == 0o600,
                "unsafe retained document file")
        if not package_only and relative == "result.json":
            continue  # Only the root invocation summary is intentionally replaced.
        require(item.st_size <= 16 * 1048576, "oversized retained document file")
        raw = path.read_bytes()
        require(len(raw) == item.st_size, "retained file changed while reading")
        require(raw or path.name in (".task.lock", ".workflow.lock"), "empty retained result is not an owned lock")
        total += len(raw)
        require(total <= MAX_EXPORT, "document evidence exceeds explicit bound")
        result[relative] = {"bytes": len(raw), "sha256": sha(raw), "inode": [item.st_dev, item.st_ino]}
    require(f"{ATTEMPT}/job-0.json" in result if package_only else "document.json" in result,
            "actual document execution files absent")
    require(not any("attempt-0001" in name for name in result), "unexpected duplicate worker attempt")
    return result


def first(work):
    JOBS["guest_work"](work)
    root = root_path(work)
    result = read(work / "agent-public-document-first.json", MAX_EXPORT)
    require(result["complete"] is False and result["rounds_this_invocation"] == 1
            and len(result["packages"]) >= 2 and result["packages"][0]["complete"] is True
            and all(p["complete"] is False for p in result["packages"][1:]) and len(result["answers"]) == 4,
            "first invocation did not retain exactly one real completed package")
    write(work / "agent-public-document-first-files.json", {
        "snapshot": snapshot(root / "package-0000", True), "observed_monotonic_ns": time.monotonic_ns()})


def collect(work):
    JOBS["guest_work"](work)
    root = root_path(work)
    retained = snapshot(root)
    original = read(work / "agent-public-document-first-files.json", MAX_EXPORT)
    require(snapshot(root / "package-0000", True) == original["snapshot"], "first completed package changed on resume")
    # Exact public bytes make all report/manifest checks reproducible after owned
    # private model/source cleanup. No identity, passphrase or cache is exported.
    raw = {name: (root / name).read_bytes().hex() for name in retained}
    write(work / "agent-public-document-files.json", {
        "snapshot": retained, "raw": raw, "observed_monotonic_ns": time.monotonic_ns()})


def stopped(work, resumed=False):
    JOBS["guest_work"](work)
    workers = read(work / "agent-jobs-observation.json")["workers"]
    for worker in workers:
        require(not JOBS["alive"](worker["broker"])
                and not any(JOBS["alive"](p) for p in worker["owned_processes"]), "owned executor remains alive")
        state = JOBS["subprocess"].check_output(["systemctl", "show", "--property=ActiveState", "--value",
                    f"volparossa-alpha-compute@{worker['node']}.service"], text=True).strip()
        require(state in ("inactive", "failed"), "executor unit is still active")
    value = {"brokers": [w["broker"] for w in workers], "all_owned_processes_ended": True,
             "observed_monotonic_ns": time.monotonic_ns()}
    if resumed:
        value["snapshot"] = snapshot(root_path(work))
    write(work / f"agent-public-document-{'resumed' if resumed else 'stopped'}.json", value)


def check_plan(plan, source):
    require(plan["version"] == 1 and plan["source_bytes"] == len(source) and plan["source_sha256"] == sha(source)
            and plan["question_sha256"] == sha(QUESTION.encode()) and plan["model_id"] == MODEL
            and plan["model_revision"] == TRAIN["MODEL_REVISION"] and plan["tokenizer_sha256"] == TOKENIZER
            and plan["prompt_limit"] == 192 and 4 < len(plan["parts"]) <= 128, "wrong actual tokenizer plan")
    next_byte = 0
    for part in plan["parts"]:
        start, end = part["start"], part["end"]
        require(type(start) is int and type(end) is int and start == next_byte and 0 < end - start <= 4096
                and end <= len(source) and type(part["prompt_tokens"]) is int and 1 <= part["prompt_tokens"] <= 192,
                "document plan omitted/overlapped bytes or exceeded prompt budget")
        source[start:end].decode("utf-8")
        next_byte = end
    require(next_byte == len(source), "document tail was silently omitted")


def manifest(encoded, raw, enrollment, name, content_type):
    fields = CUSTODY["fields"]
    envelope = fields(encoded, 65536)
    require(set(envelope) == {1, 2} and len(envelope[2]) == 64, "original publisher signature bytes absent")
    body = fields(envelope[1], 65536)
    payload = fields(body[8], 65536)
    require(body[1] == 1 and body[2] == bytes.fromhex(enrollment["publisher_key"]) and body[6] == 1
            and body[3] == enrollment["selected_at_unix_seconds"] and body[4] == enrollment["expires_at_unix_seconds"]
            and 0 < body[3] < body[4] and body[7] == hashlib.sha256(body[8]).digest(), "manifest authority/expiry differs")
    require(payload[1] == name.encode() and payload[2] == 1 and payload[3] == content_type.encode()
            and payload[4] == len(raw) and payload[6] == hashlib.sha256(raw).digest(), "signed object bytes differ")
    chunk = fields(payload[5], 64)
    require(chunk[1] == hashlib.sha256(raw).digest() and chunk[2] == len(raw), "signed original chunk differs")
    return sha(encoded)


def check_supervisor(report):
    supervisor = report["supervisor"]
    require(supervisor["child_reaped"] is True and supervisor["network_access"] is False
            and supervisor["gpu_access"] is False and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"],
            "real worker lacks bounded isolation/cleanup accounting")


def check_result(result, enrollment, plan, answers, complete, rounds):
    require(result["operation"] == "compute_public_document" and result["version"] == 1
            and result["complete"] is complete and result["rounds_this_invocation"] == rounds and result["interrupted"] is False
            and result["source_manifest_id"] == enrollment["source_manifest_id"]
            and result["source_sha256"] == plan["source_sha256"] and result["source_bytes"] == plan["source_bytes"]
            and result["public_question"] == QUESTION and result["license"] == "GPL-3.0-only"
            and result["total_parts"] == len(plan["parts"]) and result["answers"] == answers,
            "document invocation changed source, range order or actual result")
    require(result["joining"] == "ordered_source_ranges_not_neural_synthesis"
            and result["content_cache"] == "local_native_signed_publications_not_automatic_network_contribution"
            and all(result[k] is False for k in ("source_selection_uses_cache_inventory", "private_data_supported",
                                                 "model_answer_correctness_proven", "full_b03_claimed")), "document scope overstated")
    require(len(result["packages"]) == len(enrollment["packages"]), "package summary missing")
    for index, (reported, package) in enumerate(zip(result["packages"], enrollment["packages"])):
        require(reported == {"package_index": index, "manifest_id": package["manifest_id"],
                "first_part": package["first_part"], "parts": package["rows"], "complete": complete or index == 0},
                "package summary differs from actual completion")


def check_evidence(value, revision):
    require(value["success"] is True and value["source_revision"] == revision, "wrong document source revision")
    provision = value["provision"]
    require(provision["success"] is True and provision["installed_wheels"] == 38
            and provision["download_bytes"] == 523040250 and provision["training_performed"] is False,
            "not the explicit pinned guest provision")
    files = value["files"]
    raw = {name: bytes.fromhex(data) for name, data in files["raw"].items()}
    require(set(raw) == set(files["snapshot"]), "exported exact files differ")
    for name, data in raw.items():
        require(files["snapshot"][name]["sha256"] == sha(data) and files["snapshot"][name]["bytes"] == len(data),
                "saved original bytes differ from real file snapshot")
    load = lambda name: json.loads(raw[name])
    enrollment, plan = load("document.json"), load("document-plan.json")
    source = raw["source.txt"]
    require(4096 <= len(source) <= 6144 and value["input"]["excerpt_hex"] == source.hex()
            and value["input"]["excerpt_sha256"] == sha(source), "original public README excerpt differs")
    check_plan(plan, source)
    require(load("planner-input.json") == {"version": 1, "visibility": "public", "license": "GPL-3.0-only",
            "document": source.decode(), "question": QUESTION}, "actual planner did not receive the exact public source")
    layout, peers = value["layout"], value["peers"]
    require(enrollment["version"] == 1 and enrollment["source_sha256"] == sha(source)
            and enrollment["source_bytes"] == len(source) and enrollment["plan_sha256"] == sha(raw["document-plan.json"])
            and enrollment["license"] == "GPL-3.0-only" and enrollment["public_question"] == QUESTION
            and enrollment["provider_keys"] == [layout["provider_keys"][n] for n in layout["provider_nodes"]]
            and enrollment["publisher_key"] == value["publish"]["publisher_key_hex"], "original enrollment changed")
    source_id = manifest(raw["source.manifest"], source, enrollment, "document-source", "text/plain")
    require(source_id == enrollment["source_manifest_id"], "source signed manifest changed")
    planner = load("tokenizer-report.json")
    require(planner["mode"] == "plan_document" and planner["status"] == "ok" and planner["device"] == "cpu"
            and planner["model_weights_loaded"] is False and planner["updates_completed"] == 0
            and "outputs" not in planner and "baseline_evaluation" not in planner
            and planner["dataset"]["sha256"] == sha(raw["planner-input.json"])
            and load("tokenizer/report.json").items() <= planner.items()
            and planner["artifacts"] == [{"relative_path": "document-plan.json", "bytes": len(raw["tokenizer/document-plan.json"]),
                                           "sha256": sha(raw["tokenizer/document-plan.json"])}]
            and load("tokenizer/document-plan.json") == plan, "actual tokenizer report/artifact binding missing")
    check_supervisor(planner)
    JOBS["check_overlap"](value["observation"])
    workers = {w["node"]: w for w in value["observation"]["workers"]}
    require(set(workers) == set(layout["provider_nodes"])
            and all(CUSTODY["peer_key"](peers[n]) == k for n, k in layout["provider_keys"].items())
            and layout["control_relay_peer_id"] not in {peers[n] for n in workers}, "provider lineage differs")
    require(value["input"]["private_copies_no_hardlinks"] is True
            and value["input"]["owner_model_inode"] != value["input"]["peer_model_inode"]
            and all(w["input_inodes"]["model/model.safetensors"] == value["input"]["peer_model_inode"] for w in workers.values()),
            "Client tokenizer and real peer model copies were confused")
    answers, job_ids, response_bytes = [], set(), {node: 0 for node in workers}
    require(len(enrollment["packages"]) == (len(plan["parts"]) + 3) // 4, "missing document package")
    for index, package in enumerate(enrollment["packages"]):
        prefix = f"package-{index:04}"
        data = load(f"{prefix}/dataset.json")
        rows = plan["parts"][index * 4:index * 4 + 4]
        expected_rows = [{"question": QUESTION, "context": source[p["start"]:p["end"]].decode(),
                          "start": p["start"], "end": p["end"]} for p in rows]
        require(data == {"version": 2, "visibility": "public", "license": "GPL-3.0-only",
                        "source_manifest_hex": raw["source.manifest"].hex(), "inference": expected_rows}
                and package["dataset_sha256"] == sha(raw[f"{prefix}/dataset.json"])
                and package["first_part"] == index * 4 and package["rows"] == len(rows), "package altered original public ranges")
        manifest_id = manifest(raw[f"{prefix}/dataset.manifest"], raw[f"{prefix}/dataset.json"], enrollment,
                               f"document-package-{index:04}", PROFILE)
        require(manifest_id == package["manifest_id"], "package manifest differs")
        require(raw[f"{prefix}/work/package-0000/dataset.json"] == raw[f"{prefix}/dataset.json"]
                and raw[f"{prefix}/work/package-0000/manifest.bin"] == raw[f"{prefix}/dataset.manifest"],
                "workflow changed the exact signed package source")
        attempt = f"{prefix}/{ATTEMPT}"
        batch = load(f"{attempt}/result.json")
        require(batch["operation"] == "compute_distribute" and batch["complete"] is True
                and batch["dataset_manifest_id"] == manifest_id and batch["task"] == TASK
                and len(batch["outputs"]) == len(rows) and batch["provider_count"] == len(batch["jobs"]) == min(2, len(rows)),
                "actual package execution incomplete")
        seen = []
        for part in batch["jobs"]:
            handle = part["handle"]
            binding, caps = handle["binding"], handle["capabilities"]
            node = next((n for n in workers if layout["provider_keys"][n] == handle["provider_key"]), None)
            require(node is not None and binding["task"] == TASK and caps["task_derivation_v1"] is True
                    and caps.get("document_inference_v2") is True and binding["dataset_manifest_id"] == manifest_id
                    and binding["expires_unix_seconds"] <= enrollment["expires_at_unix_seconds"], "wrong document job capability/binding")
            require(binding["job_id"] not in job_ids and re.fullmatch(r"[0-9a-f]{32}", binding["job_id"]),
                    "job identity reused between independently bound document packages")
            job_ids.add(binding["job_id"])
            require(caps["model"]["model_id"] == MODEL and caps["model"]["model_revision"] == TRAIN["MODEL_REVISION"]
                    and caps["model"]["base_weights"] == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}
                    and caps["model"]["adapter_files"] is None and caps["model_fingerprint"] == binding["model_fingerprint"]
                    and caps["public_inference_only"] is True and caps["runtime_slots"] == 1 and caps["max_threads"] == 2,
                    "peer used a different fixed model")
            selected = binding["row_indices"]
            provider_index = layout["provider_nodes"].index(node)
            require(selected == list(range(provider_index, len(rows), min(2, len(rows))))
                    and load(f"{attempt}/job-{provider_index}.json") == handle, "wrong exact retained handle/row assignment")
            derived = copy.deepcopy(data)
            derived["inference"] = [data["inference"][n] for n in selected]
            derived_raw = json.dumps(derived, ensure_ascii=False, separators=(",", ":")).encode()
            require(binding["dataset_sha256"] == sha(derived_raw), "derived source hash differs")
            receipt = load(f"{attempt}/receipt-{binding['job_id']}.json")
            status = receipt["status"]
            require(receipt["handle"] == handle and status["binding"] == binding and status["state"] == part["state"] == "complete"
                    and status["report_sha256"] == part["report_sha256"] == sha(status["report_json"].encode()), "retained complete receipt differs")
            report = json.loads(status["report_json"])
            require(report["mode"] == "infer" and report["status"] == "ok" and report["device"] == "cpu"
                    and report["updates_completed"] == 0 and report["dataset"]["version"] == 2
                    and report["dataset"]["sha256"] == sha(derived_raw) and report["dataset"]["source_manifest_sha256"] == source_id
                    and report["baseline_evaluation"] is None and len(report["outputs"]) == len(selected)
                    and report["model"]["files"]["model.safetensors"] == caps["model"]["base_weights"], "not actual v2-only inference")
            check_supervisor(report)
            if index == 0:
                require(workers[node]["dataset_json"].encode() == derived_raw
                        and workers[node]["dataset_file"]["sha256"] == sha(derived_raw), "observed worker has another actual source")
                polled = next(s for s in value["statuses"] if s["binding"] == binding)
                require(polled == status, "original terminal poll differs after later package execution")
            response_bytes[node] += len(status["report_json"].encode())
            for local, row in enumerate(selected):
                output = batch["outputs"][row]
                require(output["sample_index"] == row and output["job_id"] == binding["job_id"]
                        and output["provider_key"] == handle["provider_key"] and output["text"] == report["outputs"][local]["text"],
                        "result lost its exact execution report")
                position = index * 4 + row
                planpart = plan["parts"][position]
                answers.append({"source_part": position, "start": planpart["start"], "end": planpart["end"],
                    "context_sha256": sha(source[planpart["start"]:planpart["end"]]), "package_manifest_id": manifest_id,
                    "text": output["text"], "provider_key": handle["provider_key"], "job_id": binding["job_id"],
                    "report_sha256": status["report_sha256"]})
            seen.extend(selected)
        require(sorted(seen) == list(range(len(rows))), "document rows duplicated or omitted")
    answers.sort(key=lambda item: item["source_part"])
    check_result(value["first"], enrollment, plan, answers[:4], False, 1)
    check_result(value["result"], enrollment, plan, answers, True, len(enrollment["packages"]) - 1)
    check_result(value["resume"], enrollment, plan, answers, True, 0)
    first_snapshot = {name.removeprefix("package-0000/"): item for name, item in files["snapshot"].items()
                      if name.startswith("package-0000/")}
    require(value["first_files"]["snapshot"] == first_snapshot and value["resumed"]["snapshot"] == files["snapshot"],
            "resume changed previously completed receipts/inputs")
    brokers = [w["broker"] for w in value["observation"]["workers"]]
    require(value["stopped"]["brokers"] == value["resumed"]["brokers"] == brokers
            and value["stopped"]["all_owned_processes_ended"] is True and value["resumed"]["all_owned_processes_ended"] is True
            and files["observed_monotonic_ns"] < value["stopped"]["observed_monotonic_ns"] < value["resumed"]["observed_monotonic_ns"],
            "completed resume used running executors or wrong process identities")
    admission = value["admission"]
    require(0 < admission["enrollment_observed_monotonic_ns"] - admission["planner_started_monotonic_ns"] < 610_000_000_000
            and 0 <= admission["handles_observed_monotonic_ns"] - admission["enrollment_observed_monotonic_ns"] < 90_000_000_000
            and admission["handles_observed_monotonic_ns"] < value["observation"]["first_monotonic_ns"], "real admission timing missing")
    for index in (0, 1):
        item = files["snapshot"][f"package-0000/{ATTEMPT}/job-{index}.json"]
        require(admission["handles"][index] == {k: item[k] for k in ("bytes", "sha256")}, "initial handle was replaced")
    CUSTODY["validate_path"](value["path"], peers, layout, "inspect")
    for node, size in response_bytes.items():
        application = value["path"]["privacy"]["exit"]["provider_application"][node]
        require(application["request_packets"] > 0 and application["response_payload_bytes"] >= size,
                "selected peer did not actually carry its returned reports")
    require(all(value["cleanup"].values()), "owned model/executor cleanup incomplete")


def evidence(work, revision):
    value = {name.replace("-", "_"): read(work / f"agent-public-document-{name}.json", MAX_EXPORT)
             for name in ("input", "first", "first-files", "files", "result", "resume", "stopped", "resumed", "admission")}
    value.update({name: read(work / f"agent-jobs-{name}.json") for name in ("provision", "publish", "layout", "observation")})
    value.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
        cleanup=read(work / "agent-jobs-private-cleanup.json"),
        statuses=[read(work / f"agent-jobs-status-{n}.json") for n in (0, 1)],
        path={"selected_route": read(work / "content-custody-fetch-live-selection.json"),
              "privacy": {role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
              "control_privacy": read(work / "content-provider-custody-fetch-control.json"),
              "gates": read(work / "content-custody-fetch-gates.json")})
    check_evidence(value, revision)
    return value


def finalize(work, revision, status, complete, remaining, phase, blocker):
    found = work / "agent-public-document-evidence.json"
    value = read(found, MAX_EXPORT) if found.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(work / "agent-public-document-smoke.json", {
        "report_kind": "volparossa-public-document", "source_revision": revision, "scope": SCOPE,
        "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and value is not None,
        "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker, "runner_exit_status": status,
        "answer_quality_proven": False, "neural_synthesis_claimed": False, "full_b03_claimed": False, "full_alpha_claimed": False,
        "evidence": value, "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host})


def report(value, revision):
    require(value["report_kind"] == "volparossa-public-document" and value["source_revision"] == revision
            and value["scope"] == SCOPE and value["success"] is True and value["runner_exit_status"] == 0,
            "incomplete source-bound document report")
    require(value["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "host/owned cleanup differs")
    require(all(value[k] is False for k in ("answer_quality_proven", "neural_synthesis_claimed", "full_b03_claimed", "full_alpha_claimed")),
            "document scope overstated")
    check_evidence(value["evidence"], revision)


def contract_fixture():
    """Synthetic parser input only: never a tokenizer/model/crypto execution claim."""
    jobs = JOBS["self_test"]()
    wire = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["wire"]
    value = {k: copy.deepcopy(jobs[k]) for k in ("success", "source_revision", "provision", "publish", "layout",
                                                "peers", "path", "observation", "cleanup")}
    source = b"public context. " * 300
    plan = {"version": 1, "source_sha256": sha(source), "source_bytes": len(source), "question_sha256": sha(QUESTION.encode()),
            "model_id": MODEL, "model_revision": TRAIN["MODEL_REVISION"], "tokenizer_sha256": TOKENIZER, "prompt_limit": 192,
            "parts": [{"start": n*800, "end": (n+1)*800, "prompt_tokens": 170} for n in range(6)]}
    enrollment = {"version": 1, "source_sha256": sha(source), "source_bytes": len(source),
        "publisher_key": jobs["publish"]["publisher_key_hex"], "provider_keys": list(jobs["layout"]["provider_keys"].values()),
        "selected_at_unix_seconds": 1000, "expires_at_unix_seconds": 3000, "license": "GPL-3.0-only",
        "public_question": QUESTION, "packages": []}
    raw = {}
    save = lambda name, data: raw.update({name: json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode()})
    def signed(body, name, mime):
        payload = wire({1: name.encode(), 2: 1, 3: mime.encode(), 4: len(body),
                        5: wire({1: hashlib.sha256(body).digest(), 2: len(body)}), 6: hashlib.sha256(body).digest()})
        encoded = wire({1: 1, 2: bytes.fromhex(enrollment["publisher_key"]), 3: 1000, 4: 3000,
                        5: b"n"*32, 6: 1, 7: hashlib.sha256(payload).digest(), 8: payload})
        return wire({1: encoded, 2: b"s"*64})
    raw["source.txt"] = source
    raw["source.manifest"] = signed(source, "document-source", "text/plain")
    enrollment["source_manifest_id"] = sha(raw["source.manifest"])
    save("document-plan.json", plan)
    enrollment["plan_sha256"] = sha(raw["document-plan.json"])
    save("planner-input.json", dict(version=1, visibility="public", license="GPL-3.0-only", document=source.decode(), question=QUESTION))
    raw["tokenizer/document-plan.json"] = json.dumps(plan, sort_keys=True).encode()
    planner = dict(mode="plan_document", status="ok", device="cpu", updates_completed=0, model_weights_loaded=False,
        dataset=dict(sha256=sha(raw["planner-input.json"])), artifacts=[dict(relative_path="document-plan.json",
            bytes=len(raw["tokenizer/document-plan.json"]), sha256=sha(raw["tokenizer/document-plan.json"]))])
    save("tokenizer/report.json", planner)
    planner["supervisor"] = dict(child_reaped=True, network_access=False, gpu_access=False,
                                  max_observed_rss_bytes=100, rss_limit_bytes=1000)
    save("tokenizer-report.json", planner)
    answers, value["statuses"] = [], []
    for index in range(2):
        prefix = f"package-{index:04}"
        parts = plan["parts"][index*4:index*4+4]
        dataset = dict(version=2, visibility="public", license="GPL-3.0-only", source_manifest_hex=raw["source.manifest"].hex(),
            inference=[dict(question=QUESTION, context=source[p["start"]:p["end"]].decode(), start=p["start"], end=p["end"]) for p in parts])
        save(f"{prefix}/dataset.json", dataset)
        raw[f"{prefix}/dataset.manifest"] = signed(raw[f"{prefix}/dataset.json"], f"document-package-{index:04}", PROFILE)
        manifest_id = sha(raw[f"{prefix}/dataset.manifest"])
        enrollment["packages"].append(dict(manifest_id=manifest_id, dataset_sha256=sha(raw[f"{prefix}/dataset.json"]),
                                            first_part=index*4, rows=len(parts)))
        raw[f"{prefix}/work/package-0000/dataset.json"] = raw[f"{prefix}/dataset.json"]
        raw[f"{prefix}/work/package-0000/manifest.bin"] = raw[f"{prefix}/dataset.manifest"]
        batch = dict(operation="compute_distribute", complete=True, provider_count=2, dataset_manifest_id=manifest_id,
                     task=TASK, jobs=[], outputs=[None]*len(parts))
        for n, node in enumerate(value["layout"]["provider_nodes"]):
            selected = list(range(n, len(parts), 2))
            derived = copy.deepcopy(dataset)
            derived["inference"] = [dataset["inference"][p] for p in selected]
            encoded = json.dumps(derived, ensure_ascii=False, separators=(",", ":")).encode()
            handle = copy.deepcopy(jobs["result"]["jobs"][n]["handle"])
            handle["capabilities"].update(task_derivation_v1=True, document_inference_v2=True)
            binding = handle["binding"]
            binding.update(job_id=f"{index*2+n+1:032x}", dataset_manifest_id=manifest_id, dataset_sha256=sha(encoded),
                           row_indices=selected, task=TASK)
            actual = json.loads(jobs["statuses"][n]["report_json"])
            actual["dataset"] = dict(version=2, sha256=sha(encoded), source_manifest_sha256=enrollment["source_manifest_id"])
            actual.update(baseline_evaluation=None, outputs=[dict(text=f"synthetic output {index}/{p}") for p in selected])
            report_json = json.dumps(actual)
            status = dict(binding=binding, state="complete", report_json=report_json, report_sha256=sha(report_json.encode()))
            batch["jobs"].append(dict(handle=handle, state="complete", report_sha256=status["report_sha256"]))
            attempt = f"{prefix}/{ATTEMPT}"
            save(f"{attempt}/job-{n}.json", handle)
            save(f"{attempt}/receipt-{binding['job_id']}.json", dict(version=1, handle=handle, status=status))
            if index == 0:
                value["observation"]["workers"][n].update(dataset_json=encoded.decode(), dataset_file=dict(bytes=len(encoded), sha256=sha(encoded)))
                value["statuses"].append(status)
            for local, part_index in enumerate(selected):
                part = parts[part_index]
                output = dict(sample_index=part_index, provider_key=handle["provider_key"], job_id=binding["job_id"], text=actual["outputs"][local]["text"])
                batch["outputs"][part_index] = output
                answers.append(dict(source_part=index*4+part_index, start=part["start"], end=part["end"],
                    context_sha256=sha(source[part["start"]:part["end"]]), package_manifest_id=manifest_id,
                    **{k: output[k] for k in ("text", "provider_key", "job_id")}, report_sha256=status["report_sha256"]))
        save(f"{prefix}/{ATTEMPT}/result.json", batch)
    save("document.json", enrollment)
    answers.sort(key=lambda x: x["source_part"])
    value["files"] = dict(raw={k: v.hex() for k, v in raw.items()}, observed_monotonic_ns=4000,
        snapshot={k: dict(bytes=len(v), sha256=sha(v), inode=[1, n+500]) for n, (k, v) in enumerate(raw.items())})
    value["first_files"] = dict(snapshot={k.removeprefix("package-0000/"): v for k, v in value["files"]["snapshot"].items()
                                                    if k.startswith("package-0000/")}, observed_monotonic_ns=3000)
    value["input"] = dict(excerpt_hex=source.hex(), excerpt_sha256=sha(source), owner_model_inode=[1, 999],
                            peer_model_inode=[1, 100], private_copies_no_hardlinks=True)
    value["admission"] = dict(planner_started_monotonic_ns=1, enrollment_observed_monotonic_ns=100,
        handles_observed_monotonic_ns=500, handles=[{k: value["files"]["snapshot"][f"package-0000/{ATTEMPT}/job-{n}.json"][k]
                                                    for k in ("bytes", "sha256")} for n in (0, 1)])
    brokers = [w["broker"] for w in value["observation"]["workers"]]
    value["stopped"] = dict(brokers=brokers, all_owned_processes_ended=True, observed_monotonic_ns=5000)
    value["resumed"] = dict(brokers=brokers, all_owned_processes_ended=True, observed_monotonic_ns=6000, snapshot=value["files"]["snapshot"])
    for key, complete, rounds in (("first", False, 1), ("result", True, 1), ("resume", True, 0)):
        value[key] = dict(version=1, operation="compute_public_document", complete=complete, interrupted=False,
            source_manifest_id=enrollment["source_manifest_id"], source_sha256=sha(source), source_bytes=len(source),
            public_question=QUESTION, license="GPL-3.0-only", total_parts=len(plan["parts"]), rounds_this_invocation=rounds,
            answers=answers if complete else answers[:4], joining="ordered_source_ranges_not_neural_synthesis",
            content_cache="local_native_signed_publications_not_automatic_network_contribution",
            source_selection_uses_cache_inventory=False, private_data_supported=False, model_answer_correctness_proven=False, full_b03_claimed=False,
            packages=[dict(package_index=n, manifest_id=p["manifest_id"], first_part=p["first_part"], parts=p["rows"],
                           complete=complete or n == 0) for n, p in enumerate(enrollment["packages"])])
    return value


def self_test():
    # Synthetic ranges check the evidence parser only, never the real tokenizer.
    source = ("é public context.\n" * 300).encode()
    length = len("é public context.\n".encode())
    plan = {"version": 1, "source_bytes": len(source), "source_sha256": sha(source), "question_sha256": sha(QUESTION.encode()),
            "model_id": MODEL, "model_revision": TRAIN["MODEL_REVISION"], "tokenizer_sha256": TOKENIZER, "prompt_limit": 192,
            "parts": [{"start": n * length * 30, "end": (n + 1) * length * 30, "prompt_tokens": 170} for n in range(10)]}
    check_plan(plan, source)
    for mutate in (lambda p: p["parts"][1].update(start=0), lambda p: p["parts"][-1].update(end=len(source)-1),
                   lambda p: p["parts"][0].update(prompt_tokens=193), lambda p: p.update(source_sha256="0"*64),
                   lambda p: p.update(question_sha256="0"*64), lambda p: p["parts"][0].update(end=1)):
        invalid = copy.deepcopy(plan)
        mutate(invalid)
        try:
            check_plan(invalid, source)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError("invalid source/range/token proof accepted")
    require(source_excerpt((HERE.parent.parent / "README.md").read_bytes()), "actual public fixture source unavailable")
    fixture = contract_fixture()
    check_evidence(fixture, "a"*40)
    for mutate in (lambda v: v["result"]["answers"][0].update(text="unbound text"),
                   lambda v: v["resume"].update(rounds_this_invocation=1),
                   lambda v: v["observation"].update(both_alive_before_and_after=False),
                   lambda v: v["files"]["raw"].update({"source.txt": b"changed".hex()}),
                   lambda v: v["stopped"].update(all_owned_processes_ended=False)):
        invalid = copy.deepcopy(fixture)
        mutate(invalid)
        try:
            check_evidence(invalid, "a"*40)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid complete document contract accepted")
    with tempfile.TemporaryDirectory(prefix="document-receipt-test-") as directory:
        root = Path(directory)
        public = root / "document-README.md"
        public.write_bytes((HERE.parent.parent / "README.md").read_bytes())
        public.chmod(0o400)
        require(source_excerpt(public_readme(public)) == source_excerpt(public.read_bytes()), "staged public README changed source bytes")
        public.chmod(0o600)
        try:
            public_readme(public)
        except ValueError:
            pass
        else:
            raise AssertionError("writable public README accepted")
        public.unlink()
        write(root / "document.json", {"version": 1})
        (root / ".task.lock").touch(mode=0o600)
        before = snapshot(root)
        require(snapshot(root) == before and before[".task.lock"]["bytes"] == 0, "legitimate empty lock not retained")
        (root / "empty-receipt.json").touch(mode=0o600)
        try:
            snapshot(root)
        except ValueError:
            pass
        else:
            raise AssertionError("empty receipt accepted as a lock")
        (root / "empty-receipt.json").unlink()
        (root / "alias.json").hardlink_to(root / "document.json")
        try:
            snapshot(root)
        except ValueError:
            pass
        else:
            raise AssertionError("hardlinked retained input accepted")
    print("document parser and real owned-file snapshot checks passed; no model or network executed")


def main(args):
    command = args[0]
    if command == "self-test":
        return self_test()
    if command == "report":
        path = Path(args[1])
        value = read(path, MAX_EXPORT)
        report(value, args[2])
        require(evidence(path.parent, args[2]) == value["evidence"],
                "final document summary differs from original exported raw evidence")
        return None
    work = Path(args[1])
    if command == "prepare":
        return prepare(work)
    if command == "observe":
        return observe(work, int(args[2]))
    if command == "first":
        return first(work)
    if command == "collect":
        return collect(work)
    if command in ("stopped", "resumed"):
        return stopped(work, command == "resumed")
    if command == "evidence":
        return write(work / "agent-public-document-evidence.json", evidence(work, args[2]))
    if command == "finalize":
        return finalize(work, args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    raise ValueError("unknown bounded document fixture command")


if __name__ == "__main__":
    main(sys.argv[1:])
