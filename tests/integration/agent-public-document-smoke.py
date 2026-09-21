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
SYNTHESIS = runpy.run_path(str(HERE / "agent-document-synthesis.py"))
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
SYNTHESIS_SCOPE = SCOPE.replace("neural synthesis, ", "") + "; additionally real multi-level peer synthesis, not semantic completeness"
DISCOVERY_SCOPE = SYNTHESIS_SCOPE + "; automatically discovered eligible executors with immutable model and peer selection, not a capacity reservation"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def root_path(work):
    return work / "state-client/compute-source/public-document"


def selected_providers(enrollment, layout, discovered=False):
    expected = [layout["provider_keys"][node] for node in layout["provider_nodes"]]
    selected = enrollment["provider_keys"]
    require(len(expected) == len(selected) == 2 and len(set(selected)) == 2 and set(selected) == set(expected),
            "document selected another executor pool")
    if discovered:
        fingerprint = enrollment.get("model_fingerprint")
        require(isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint)
                and fingerprint != "0" * 64, "automatic executor selection has no frozen model")
    else:
        require(selected == expected, "legacy explicit provider order changed")
    return selected


def check_workflow_selection(raw, prefix, enrollment):
    workflow = json.loads(raw[prefix + "/work/workflow.json"])
    require(workflow["provider_keys"] == enrollment["provider_keys"]
            and workflow.get("model_fingerprint") == enrollment["model_fingerprint"],
            "child workflow changed the enrolled executor/model selection")


def enrollment_start(work):
    JOBS["guest_work"](work)
    write(work / "agent-public-document-enrollment-start.json", {"started_monotonic_ns": time.monotonic_ns()})


def enrolled(work):
    JOBS["guest_work"](work)
    root = root_path(work)
    enrollment = read(root / "document.json")
    selected_providers(enrollment, read(work / "agent-jobs-layout.json"), True)
    result = read(work / "agent-public-document-enrollment.json")
    check_enrollment_result(result, enrollment)
    require(not (root / "synthesis").exists()
            and all(not (root / f"package-{index:04}/work").exists() for index in range(len(enrollment["packages"])))
            and not any(re.search(r"/(?:job-[0-9]+\.json|attempt-[0-9]+/)", path.relative_to(root).as_posix())
                        for path in partial_public_paths(root)), "enrollment-only admitted remote jobs")
    write(work / "agent-public-document-enrollment-observed.json", {
        "enrollment": JOBS["file_hash"](root / "document.json", 1048576),
        "retained_files": snapshot(root, partial=True),
        "no_job_handles": True, "no_workflow_execution_directories": True,
        "owner_returned": True, "observed_monotonic_ns": time.monotonic_ns()})


def check_enrollment_result(result, enrollment):
    require(result == {"operation": "compute_document_enrolled", "execution_started": False,
            "task_complete": False, "source_manifest_id": enrollment["source_manifest_id"],
            "provider_keys": enrollment["provider_keys"], "model_fingerprint": enrollment["model_fingerprint"],
            "package_count": len(enrollment["packages"]), "private_data_supported": False},
            "executor enrollment claimed work or changed the selected peers/model")


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
    # Discovery and the real tokenizer already returned without submitting jobs.
    # This original 90-second window covers only the first retained peer handles.
    prior = read(work / "agent-public-document-enrollment-observed.json")
    enrollment = read(root / "document.json")
    require(prior["owner_returned"] is True and prior["observed_monotonic_ns"] < started,
            "execution overlapped unfinished enrollment")
    selected = selected_providers(enrollment, read(work / "agent-jobs-layout.json"), True)
    selection = {"method": "protected_provider_eligibility_discovery", "provider_keys": selected,
                 "model_fingerprint": enrollment["model_fingerprint"],
                 "enrollment": JOBS["file_hash"](root / "document.json", 1048576)}
    for _ in range(1800):
        try:
            paths = [root / "package-0000" / ATTEMPT / f"job-{n}.json" for n in (0, 1)]
            handles = [read(path) for path in paths]
            require(all(h["binding"]["task"] == TASK and h["capabilities"]["task_derivation_v1"] is True
                        for h in handles), "initial handles have another public task")
            require([h["provider_key"] for h in handles] == selected
                    and all(h["binding"]["model_fingerprint"] == h["capabilities"]["model_fingerprint"]
                            == selection["model_fingerprint"] for h in handles),
                    "initial handles changed the automatically enrolled peers/model")
        except (OSError, ValueError, KeyError):
            require(JOBS["alive"](owner), "document ended before actual peer admission")
            time.sleep(0.05)
            continue
        write(work / "agent-public-document-admission.json", {
            "execution_started_monotonic_ns": started, "executor_selection": selection,
            "enrollment_observed_monotonic_ns": prior["observed_monotonic_ns"],
            "handles_observed_monotonic_ns": time.monotonic_ns(),
            "handles": [JOBS["file_hash"](path, 16384) for path in paths]})
        return JOBS["observe"](work)
    raise ValueError("document did not retain real peer handles within admission deadline")


def partial_public_paths(root):
    """Fixed coordinator outputs only; do not descend into keys, models or native caches."""
    group = r"synthesis/level-[0-9]{2}-group-[0-9]{4}/"
    package = r"(?:" + group + r")?package-[0-9]{4}/"
    directories = re.compile(r"(?:synthesis|" + group[:-1] + r"|(?:" + group + r")?tokenizer(?:-attempt-[0-9]{4})?"
        r"|" + package[:-1] + r"(?:/work(?:/package-0000(?:/attempt-[0-9]{4})?)?)?)")
    root_files = {"source.txt", "source.manifest", "planner-input.json", "document-plan.json",
                  "tokenizer-report.json", "document.json", "result.json", ".task.lock"}
    group_files = {"group.json", "parents.json", "planner-input.json", "document-plan.json", "tokenizer-report.json"}
    regular = re.compile(r"(?:" + package + r"(?:dataset\.json|dataset\.manifest|workflow-plan\.json|last-workflow-report\.json|work/(?:workflow\.json|result\.json|\.workflow\.lock"
        r"|package-0000/(?:dataset\.json|manifest\.bin|attempt-[0-9]{4}/(?:result\.json|(?:job|original|observation|retry)-[0-9]{1,2}\.json|receipt-[0-9a-f]{32}\.json))))"
        r"|(?:" + group + r")?tokenizer(?:-attempt-[0-9]{4})?/(?:report\.json|document-plan\.json))")
    count = 0
    owner = root.lstat().st_uid
    for directory, children, files in os.walk(root, topdown=True, followlinks=False):
        count += len(children) + len(files)
        require(count <= 2048, "unbounded document fixture tree")
        kept = []
        for name in sorted(children):
            path = Path(directory) / name
            if directories.fullmatch(path.relative_to(root).as_posix()):
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid == owner
                        and stat.S_IMODE(info.st_mode) == 0o700, "unsafe partial document directory")
                kept.append(name)
        children[:] = kept
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            match = re.fullmatch(group + r"([^/]+)", relative)
            if relative in root_files or regular.fullmatch(relative) or (match and match[1] in group_files):
                yield path


def snapshot(root, package_only=False, partial=False):
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not root.is_symlink(), "wrong retained document root")
    result, total = {}, 0
    paths = partial_public_paths(root) if partial else root.rglob("*")
    for count, path in enumerate(paths):
        require(count < 2048, "unbounded document fixture tree")
        relative = path.relative_to(root).as_posix()
        if not package_only and (relative == "publication-cache" or relative.startswith("publication-cache/")
                or re.match(r"synthesis/level-[0-9]{2}-group-[0-9]{4}/publication-cache(?:/|$)", relative)):
            continue  # Native cache is not the completed-receipt state under test.
        item = path.lstat()
        require(item.st_uid == info.st_uid and not path.is_symlink(), "retained file owner/symlink differs")
        if stat.S_ISDIR(item.st_mode):
            continue
        require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and stat.S_IMODE(item.st_mode) == 0o600,
                "unsafe retained document file")
        if not partial and not package_only and relative == "result.json":
            continue  # Only the root invocation summary is intentionally replaced.
        require(item.st_size <= 16 * 1048576, "oversized retained document file")
        raw = path.read_bytes()
        require(len(raw) == item.st_size, "retained file changed while reading")
        require(partial or raw or path.name in (".task.lock", ".workflow.lock"), "empty retained result is not an owned lock")
        total += len(raw)
        require(total <= MAX_EXPORT, "document evidence exceeds explicit bound")
        result[relative] = {"bytes": len(raw), "sha256": sha(raw), "inode": [item.st_dev, item.st_ino]}
    if not partial:
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


def partial_files(root, revision, reason, owner_status):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and reason in (
        "synthesis_observer_failed", "synthesis_owner_failed") and type(owner_status) is int
        and 0 <= owner_status <= 255, "invalid fixed partial-document context")
    retained = snapshot(root, partial=True)
    raw = {}
    for name, identity in retained.items():
        content = (root / name).read_bytes()
        require(len(content) == identity["bytes"] and sha(content) == identity["sha256"],
                "partial document bytes changed after snapshot")
        raw[name] = content.hex()
    value = {"version": 1, "source_revision": revision, "partial": True, "success": False,
        "reason": reason, "owner_returned": True, "owner_exit_status": owner_status,
        "snapshot": retained, "raw": raw, "observed_monotonic_ns": time.monotonic_ns(),
        "scope": "public_coordinator_files_after_owner_return_not_complete_execution_evidence",
        "model_runtime_keys_cache_exported": False, "remote_workers_stopped_claimed": False}
    require(len(json.dumps(value, indent=2, allow_nan=False).encode()) + 1 <= MAX_EXPORT,
            "encoded partial document evidence exceeds explicit bound")
    return value


def partial(work, revision, reason, owner_status):
    JOBS["guest_work"](work)
    write(work / "agent-public-document-partial-files.json",
          partial_files(root_path(work), revision, reason, owner_status))


def stopped(work, resumed=False):
    JOBS["guest_work"](work)
    synthesis_cleanup = SYNTHESIS["assert_stopped"](work)
    workers = read(work / "agent-jobs-observation.json")["workers"]
    for worker in workers:
        require(not JOBS["alive"](worker["broker"])
                and not any(JOBS["alive"](p) for p in worker["owned_processes"]), "owned executor remains alive")
        state = JOBS["subprocess"].check_output(["systemctl", "show", "--property=ActiveState", "--value",
                    f"volparossa-alpha-compute@{worker['node']}.service"], text=True).strip()
        require(state in ("inactive", "failed"), "executor unit is still active")
    value = {"brokers": [w["broker"] for w in workers], "all_owned_processes_ended": True,
             "observed_monotonic_ns": time.monotonic_ns()}
    value.update(synthesis_cleanup)
    if resumed:
        value["snapshot"] = snapshot(root_path(work))
    write(work / f"agent-public-document-{'resumed' if resumed else 'stopped'}.json", value)


def check_plan(plan, source, synthesis=False):
    require(plan["version"] == 1 and plan["source_bytes"] == len(source) and plan["source_sha256"] == sha(source)
            and plan["question_sha256"] == sha(QUESTION.encode()) and plan["model_id"] == MODEL
            and plan["model_revision"] == TRAIN["MODEL_REVISION"] and plan["tokenizer_sha256"] == TOKENIZER
            and plan["prompt_limit"] == 192 and plan.get("synthesis", False) is synthesis
            and (1 if synthesis else 5) <= len(plan["parts"]) <= 128, "wrong actual tokenizer plan")
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


def check_result(result, enrollment, plan, answers, complete, rounds, synthesis=False):
    joining = "hierarchical_peer_synthesis" if synthesis else "ordered_source_ranges_not_neural_synthesis"
    if enrollment.get("synthesize", False) and not complete:
        joining = "awaiting_fragments_before_peer_synthesis"
    require(result["operation"] == "compute_public_document" and result["version"] == 2
            and result["execution_complete"] is complete and result["answer_complete"] is complete
            and result["semantic_completeness_proven"] is False
            and result["complete"] is complete and result["rounds_this_invocation"] == rounds and result["interrupted"] is False
            and result["source_manifest_id"] == enrollment["source_manifest_id"]
            and result["source_sha256"] == plan["source_sha256"] and result["source_bytes"] == plan["source_bytes"]
            and result["public_question"] == QUESTION and result["license"] == "GPL-3.0-only"
            and result["total_parts"] == len(plan["parts"]) and result["answers"] == answers,
            "document invocation changed source, range order or actual result")
    require(result["joining"] == joining
            and result["content_cache"] == "local_native_signed_publications_not_automatic_network_contribution"
            and all(result[k] is False for k in ("source_selection_uses_cache_inventory", "private_data_supported",
                                                 "model_answer_correctness_proven", "full_b03_claimed")), "document scope overstated")
    require(len(result["packages"]) == len(enrollment["packages"]), "package summary missing")
    for index, (reported, package) in enumerate(zip(result["packages"], enrollment["packages"])):
        require(reported == {"package_index": index, "manifest_id": package["manifest_id"],
                "first_part": package["first_part"], "parts": package["rows"], "complete": complete or index == 0},
                "package summary differs from actual completion")


def check_evidence(value, revision, discovered=False):
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
    synthesis = enrollment.get("synthesize", False)
    require(type(synthesis) is bool, "invalid enrolled synthesis flag")
    source = raw["source.txt"]
    require(4096 <= len(source) <= 6144 and value["input"]["excerpt_hex"] == source.hex()
            and value["input"]["excerpt_sha256"] == sha(source), "original public README excerpt differs")
    check_plan(plan, source)
    require(load("planner-input.json") == {"version": 1, "visibility": "public", "license": "GPL-3.0-only",
            "document": source.decode(), "question": QUESTION}, "actual planner did not receive the exact public source")
    layout, peers = value["layout"], value["peers"]
    selected = selected_providers(enrollment, layout, discovered)
    require(enrollment["version"] == 1 and enrollment["source_sha256"] == sha(source)
            and enrollment["source_bytes"] == len(source) and enrollment["plan_sha256"] == sha(raw["document-plan.json"])
            and enrollment["license"] == "GPL-3.0-only" and enrollment["public_question"] == QUESTION
            and enrollment["publisher_key"] == value["publish"]["publisher_key_hex"], "original enrollment changed")
    if discovered:
        require(value.get("automatic_executor_selection") is True,
                "automatic executor execution was not recorded")
        selection = value["admission"]["executor_selection"]
        require(selection == {"method": "protected_provider_eligibility_discovery", "provider_keys": selected,
                "model_fingerprint": enrollment["model_fingerprint"],
                "enrollment": {"bytes": len(raw["document.json"]), "sha256": sha(raw["document.json"])}},
                "original automatically selected executor record changed")
        check_enrollment_result(value["enrollment"], enrollment)
        observed = value["enrollment_observed"]
        require(observed["enrollment"] == selection["enrollment"] and observed["owner_returned"] is True
                and observed["no_job_handles"] is True and observed["no_workflow_execution_directories"] is True
                and 0 < observed["observed_monotonic_ns"] - value["enrollment_start"]["started_monotonic_ns"] < 1_320_000_000_000,
                "discovery/enrollment phase lacks pre-job boundary evidence")
        require("document.json" in observed["retained_files"]
                and all("/work/" not in name and not name.startswith("synthesis/")
                        and item == files["snapshot"].get(name) for name, item in observed["retained_files"].items()),
                "pre-job enrollment files changed or already contained remote execution")
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
    answers, leaf_parents, job_ids, response_bytes = [], [], set(), {node: 0 for node in workers}
    require(len(enrollment["packages"]) == (len(plan["parts"]) + 3) // 4, "missing document package")
    for index, package in enumerate(enrollment["packages"]):
        prefix = f"package-{index:04}"
        if discovered:
            check_workflow_selection(raw, prefix, enrollment)
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
            if discovered:
                require(binding["model_fingerprint"] == enrollment["model_fingerprint"],
                        "actual fragment worker changed the automatically selected model")
            selected = binding["row_indices"]
            provider_index = enrollment["provider_keys"].index(handle["provider_key"])
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
                require(SYNTHESIS["generation_fields"](output) == SYNTHESIS["generation_fields"](report["outputs"][local]),
                        "projected output lost its original termination metadata")
                position = index * 4 + row
                planpart = plan["parts"][position]
                answers.append({"source_part": position, "start": planpart["start"], "end": planpart["end"],
                    "context_sha256": sha(source[planpart["start"]:planpart["end"]]), "package_manifest_id": manifest_id,
                    "text": output["text"], "provider_key": handle["provider_key"], "job_id": binding["job_id"],
                    "report_sha256": status["report_sha256"],
                    **SYNTHESIS["generation_fields"](report["outputs"][local], annotated=True)})
                if synthesis:
                    leaf_parents.append((position, SYNTHESIS["answer"](report["outputs"][local], handle, status,
                        manifest_id, planpart["start"], planpart["end"], local)))
            seen.extend(selected)
        require(sorted(seen) == list(range(len(rows))), "document rows duplicated or omitted")
    answers.sort(key=lambda item: item["source_part"])
    synthesis_rounds = 0
    if synthesis:
        leaf_parents.sort(key=lambda item: item[0])
        synthesis_rounds = SYNTHESIS["check"](value, raw, enrollment, [parent for _, parent in leaf_parents],
            response_bytes, job_ids, {"plan": check_plan, "manifest": manifest, "supervisor": check_supervisor,
                                     "discovered": discovered, "workflow_selection": check_workflow_selection})
    check_result(value["first"], enrollment, plan, answers[:4], False, 1)
    check_result(value["result"], enrollment, plan, answers, True, len(enrollment["packages"]) - 1 + synthesis_rounds, synthesis)
    check_result(value["resume"], enrollment, plan, answers, True, 0, synthesis)
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
    if discovered:
        require(admission["enrollment_observed_monotonic_ns"] == value["enrollment_observed"]["observed_monotonic_ns"]
                and admission["execution_started_monotonic_ns"] > admission["enrollment_observed_monotonic_ns"]
                and 0 <= admission["handles_observed_monotonic_ns"] - admission["execution_started_monotonic_ns"] < 90_000_000_000,
                "actual executor admission changed the pre-job phase or exceeded its original window")
    else:
        require(0 < admission["enrollment_observed_monotonic_ns"] - admission["planner_started_monotonic_ns"] < 610_000_000_000
                and 0 <= admission["handles_observed_monotonic_ns"] - admission["enrollment_observed_monotonic_ns"] < 90_000_000_000,
                "real admission timing missing")
    require(admission["handles_observed_monotonic_ns"] < value["observation"]["first_monotonic_ns"], "worker observation preceded actual handles")
    for index in (0, 1):
        item = files["snapshot"][f"package-0000/{ATTEMPT}/job-{index}.json"]
        require(admission["handles"][index] == {k: item[k] for k in ("bytes", "sha256")}, "initial handle was replaced")
    CUSTODY["validate_path"](value["path"], peers, layout, "inspect")
    if discovered:
        CUSTODY["validate_path"](value["discovery_path"], peers, layout, "executor-discovery")
        require(value["discovery_path"]["gates"]["exit_mptcp_tls_completed"] >= 2
                and value["discovery_path"]["gates"]["event_baseline_unix_ms"] < value["path"]["gates"]["event_baseline_unix_ms"],
                "discovery and executor traffic were not independently captured in order")
    for node, size in response_bytes.items():
        application = value["path"]["privacy"]["exit"]["provider_application"][node]
        require(application["request_packets"] > 0 and application["response_payload_bytes"] >= size,
                "selected peer did not actually carry its returned reports")
    require(all(value["cleanup"].values()), "owned model/executor cleanup incomplete")


def evidence(work, revision):
    value = {name.replace("-", "_"): read(work / f"agent-public-document-{name}.json", MAX_EXPORT)
             for name in ("input", "first", "first-files", "files", "result", "resume", "stopped", "resumed", "admission",
                          "enrollment", "enrollment-start", "enrollment-observed")}
    value.update({name: read(work / f"agent-jobs-{name}.json") for name in ("provision", "publish", "layout", "observation")})
    value.update(success=True, automatic_executor_selection=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
        cleanup=read(work / "agent-jobs-private-cleanup.json"),
        statuses=[read(work / f"agent-jobs-status-{n}.json") for n in (0, 1)],
        path={"selected_route": read(work / "content-custody-fetch-live-selection.json"),
              "privacy": {role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
              "control_privacy": read(work / "content-provider-custody-fetch-control.json"),
              "gates": read(work / "content-custody-fetch-gates.json")})
    value["discovery_path"] = {"selected_route": read(work / "content-custody-executor-discovery-live-selection.json"),
        "privacy": {role: read(work / f"content-custody-executor-discovery-privacy-{role}.json") for role in CUSTODY["ROLES"]},
        "control_privacy": read(work / "content-provider-custody-executor-discovery-control.json"),
        "gates": read(work / "content-custody-executor-discovery-gates.json")}
    observed = work / "agent-public-document-synthesis-observation.json"
    require(value["result"]["joining"] == "hierarchical_peer_synthesis" and observed.is_file(),
            "this source's opt-in scenario did not finish actual hierarchical synthesis")
    if observed.is_file():
        value["synthesis_observation"] = read(observed, MAX_EXPORT)
    check_evidence(value, revision, discovered=True)
    return value


def finalize(work, revision, status, complete, remaining, phase, blocker):
    found = work / "agent-public-document-evidence.json"
    value = read(found, MAX_EXPORT) if found.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    synthesis = value is not None and value["result"]["joining"] == "hierarchical_peer_synthesis"
    discovered = value is not None and value.get("automatic_executor_selection") is True
    partial_path = work / "agent-public-document-partial-files.json"
    partial_identity = JOBS["file_hash"](partial_path, MAX_EXPORT) if partial_path.is_file() else None
    write(work / "agent-public-document-smoke.json", {
        "report_kind": "volparossa-public-document", "source_revision": revision,
        "scope": DISCOVERY_SCOPE if discovered and synthesis else SYNTHESIS_SCOPE if synthesis else SCOPE,
        "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and value is not None,
        "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker, "runner_exit_status": status,
        "answer_quality_proven": False, "neural_synthesis_claimed": synthesis, "full_b03_claimed": False, "full_alpha_claimed": False,
        "automatic_executor_selection_claimed": discovered,
        "evidence": value, "partial_files": partial_identity,
        "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host})


def report(value, revision):
    synthesis = value.get("neural_synthesis_claimed") is True
    require(value["report_kind"] == "volparossa-public-document" and value["source_revision"] == revision
            and value["scope"] == DISCOVERY_SCOPE and synthesis and value.get("automatic_executor_selection_claimed") is True
            and value["success"] is True and value["runner_exit_status"] == 0,
            "incomplete source-bound document report")
    require(value["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "host/owned cleanup differs")
    require(all(value[k] is False for k in ("answer_quality_proven", "full_b03_claimed", "full_alpha_claimed"))
            and value["neural_synthesis_claimed"] is synthesis
            and (value["evidence"]["result"]["joining"] == "hierarchical_peer_synthesis") is synthesis,
            "document scope overstated")
    check_evidence(value["evidence"], revision, discovered=True)


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
            actual.update(baseline_evaluation=None, outputs=[dict(text=f"synthetic output {index}/{p}",
                sample_index=local, generated_tokens=12, text_truncated=False,
                generation=dict(version=1, stop_reason="eos", max_new_tokens=64)) for local,p in enumerate(selected)])
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
                output = dict(sample_index=part_index, provider_key=handle["provider_key"], job_id=binding["job_id"],
                    text=actual["outputs"][local]["text"], **SYNTHESIS["generation_fields"](actual["outputs"][local]))
                batch["outputs"][part_index] = output
                answers.append(dict(source_part=index*4+part_index, start=part["start"], end=part["end"],
                    context_sha256=sha(source[part["start"]:part["end"]]), package_manifest_id=manifest_id,
                    **{k: output[k] for k in ("text", "provider_key", "job_id")}, report_sha256=status["report_sha256"],
                    **SYNTHESIS["generation_fields"](actual["outputs"][local], annotated=True)))
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
        value[key] = dict(version=2, operation="compute_public_document", complete=complete, interrupted=False,
            execution_complete=complete, answer_complete=complete, semantic_completeness_proven=False,
            source_manifest_id=enrollment["source_manifest_id"], source_sha256=sha(source), source_bytes=len(source),
            public_question=QUESTION, license="GPL-3.0-only", total_parts=len(plan["parts"]), rounds_this_invocation=rounds,
            answers=answers if complete else answers[:4], joining="ordered_source_ranges_not_neural_synthesis",
            content_cache="local_native_signed_publications_not_automatic_network_contribution",
            source_selection_uses_cache_inventory=False, private_data_supported=False, model_answer_correctness_proven=False, full_b03_claimed=False,
            packages=[dict(package_index=n, manifest_id=p["manifest_id"], first_part=p["first_part"], parts=p["rows"],
                           complete=complete or n == 0) for n, p in enumerate(enrollment["packages"])])
    return value


def discovery_contract_fixture(original, fingerprint=None):
    """Synthetic selection/parser input only, never an actual discovery or model proof."""
    value = copy.deepcopy(original)
    raw = {name: bytes.fromhex(body) for name, body in value["files"]["raw"].items()}
    enrollment = json.loads(raw["document.json"])
    first = json.loads(raw[f"package-0000/{ATTEMPT}/job-0.json"])
    enrollment["model_fingerprint"] = fingerprint or first["capabilities"]["model_fingerprint"]
    encode = lambda body: json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    raw["document.json"] = encode(enrollment)
    for name in list(raw):
        ending = "/work/package-0000/dataset.json"
        if name.endswith(ending):
            raw[name.removesuffix(ending) + "/work/workflow.json"] = encode({
                "provider_keys": enrollment["provider_keys"], "model_fingerprint": enrollment["model_fingerprint"]})
    old = value["files"]["snapshot"]
    value["files"]["raw"] = {name: body.hex() for name, body in raw.items()}
    value["files"]["snapshot"] = {name: {"bytes": len(body), "sha256": sha(body),
        "inode": old.get(name, {}).get("inode", [1, index + 10000])} for index, (name, body) in enumerate(raw.items())}
    value["first_files"]["snapshot"] = {name.removeprefix("package-0000/"): item
        for name, item in value["files"]["snapshot"].items() if name.startswith("package-0000/")}
    value["resumed"]["snapshot"] = copy.deepcopy(value["files"]["snapshot"])
    value["automatic_executor_selection"] = True
    value["admission"]["execution_started_monotonic_ns"] = 200
    value["admission"]["executor_selection"] = {
        "method": "protected_provider_eligibility_discovery", "provider_keys": enrollment["provider_keys"],
        "model_fingerprint": enrollment["model_fingerprint"],
        "enrollment": {"bytes": len(raw["document.json"]), "sha256": sha(raw["document.json"])}}
    value["enrollment"] = {"operation": "compute_document_enrolled", "execution_started": False,
        "task_complete": False, "source_manifest_id": enrollment["source_manifest_id"],
        "provider_keys": enrollment["provider_keys"], "model_fingerprint": enrollment["model_fingerprint"],
        "package_count": len(enrollment["packages"]), "private_data_supported": False}
    value["enrollment_start"] = {"started_monotonic_ns": 1}
    value["enrollment_observed"] = {"enrollment": value["admission"]["executor_selection"]["enrollment"],
        "retained_files": {name: copy.deepcopy(item) for name, item in value["files"]["snapshot"].items()
                           if "/work/" not in name and not name.startswith("synthesis/")},
        "owner_returned": True, "no_job_handles": True, "no_workflow_execution_directories": True,
        "observed_monotonic_ns": value["admission"]["enrollment_observed_monotonic_ns"]}
    # Physical node order must not overwrite the independently enrolled key order.
    value["layout"]["provider_nodes"].reverse()
    pairs = value["path"]["control_privacy"]["content_control_pairs"]
    pairs["cp0"], pairs["cp1"] = pairs["cp1"], pairs["cp0"]
    value["discovery_path"] = copy.deepcopy(value["path"])
    value["discovery_path"]["gates"] = {"event_baseline_unix_ms": 500, "exit_mptcp_tls_completed": 2}
    third = next(node for node in CUSTODY["CANDIDATES"] if node not in value["layout"]["provider_nodes"])
    value["discovery_path"]["privacy"]["exit"]["provider_application"][third] = {
        "request_packets": 2, "response_packets": 2, "response_payload_bytes": 128}
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
    discovered = discovery_contract_fixture(fixture)
    check_evidence(discovered, "a"*40, discovered=True)
    invalid_selection = [discovery_contract_fixture(fixture, "c" * 64)] + [copy.deepcopy(discovered) for _ in range(5)]
    invalid_selection[1]["admission"]["executor_selection"]["provider_keys"] = ["1" * 64] * 2
    invalid_selection[2]["automatic_executor_selection"] = False
    invalid_selection[3]["enrollment"]["execution_started"] = True
    invalid_selection[4]["enrollment_observed"]["no_job_handles"] = False
    invalid_selection[5]["path"]["privacy"]["exit"]["provider_application"] = copy.deepcopy(
        discovered["discovery_path"]["privacy"]["exit"]["provider_application"])
    for invalid in invalid_selection:
        try:
            check_evidence(invalid, "a"*40, discovered=True)
        except ValueError:
            pass
        else:
            raise AssertionError("missing or changed automatic executor selection accepted")
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
    partial_self_test()


def partial_self_test():
    # Actual file capture of synthetic protocol bytes, expressly not execution proof.
    fixture = contract_fixture()
    with tempfile.TemporaryDirectory(prefix="document-partial-test-") as directory:
        root = Path(directory)
        expected = {}
        for name, data in fixture["files"]["raw"].items():
            expected[name] = bytes.fromhex(data)
        group = "synthesis/level-01-group-0000/"
        for name, data in list(expected.items()):
            if name.startswith("package-0000/"):
                expected[group + name] = data
        expected[group + "group.json"] = b'{"version":1}'
        expected[group + "parents.json"] = b'[{"text":"Synthetic public parent output"}]'
        expected[group + "planner-input.json"] = b'{"visibility":"public","synthesis":true}'
        expected["result.json"] = b'{"complete":false}'
        expected[group + "package-0000/work/package-0000/attempt-0000/observation-0.json"] = b'{"state":"failed"}'
        expected[group + "package-0000/last-workflow-report.json"] = b'{"complete":false,"failure_code":"COMPUTE_RPC_UNCONFIRMED"}'
        expected[group + "tokenizer-attempt-0001/report.json"] = b""
        for name, data in expected.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o600)
        for path in root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
        for name in ("identity.key", "passphrase", "publication-cache/private-chunk", group + "publication-cache/private-chunk"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"NEVER_EXPORT_PRIVATE_BYTES")
            path.chmod(0o600)
        # A forbidden directory must never even be traversed by the public collector.
        (root / "model").symlink_to(root / "publication-cache", target_is_directory=True)
        value = partial_files(root, "a" * 40, "synthesis_observer_failed", 1)
        require(value["partial"] is True and value["success"] is False and value["owner_exit_status"] == 1
                and value["remote_workers_stopped_claimed"] is False, "partial snapshot claims completed execution")
        require(set(value["raw"]) == set(expected), "partial public manifests/handles/receipts lost or private files included")
        for name, data in expected.items():
            require(bytes.fromhex(value["raw"][name]) == data and value["snapshot"][name]["sha256"] == sha(data),
                    "partial snapshot changed actual retained bytes")
        require(b"NEVER_EXPORT_PRIVATE_BYTES".hex() not in json.dumps(value), "private bytes escaped public snapshot")
        source = root / "source.manifest"
        source.unlink()
        source.symlink_to(root / "identity.key")
        try:
            partial_files(root, "a" * 40, "synthesis_owner_failed", 1)
        except ValueError:
            pass
        else:
            raise AssertionError("partial snapshot followed a substituted public-path symlink")
    print("partial public snapshot and private exclusion checks passed; failure never relabelled PASS")


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
    if command == "enrollment-start":
        return enrollment_start(work)
    if command == "enrolled":
        return enrolled(work)
    if command == "observe":
        return observe(work, int(args[2]))
    if command == "first":
        return first(work)
    if command == "collect":
        return collect(work)
    if command == "partial":
        try:
            return partial(work, args[2], args[3], int(args[4]))
        except (OSError, ValueError, KeyError, TypeError):
            raise SystemExit("DOCUMENT_PARTIAL_SNAPSHOT_UNAVAILABLE") from None
    if command in ("stopped", "resumed"):
        return stopped(work, command == "resumed")
    if command == "evidence":
        return write(work / "agent-public-document-evidence.json", evidence(work, args[2]))
    if command == "finalize":
        return finalize(work, args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    raise ValueError("unknown bounded document fixture command")


if __name__ == "__main__":
    main(sys.argv[1:])
