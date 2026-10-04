#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One real public source-file proposal, owner-approved edit and original tests.

No model answer, output repair, local model planner or private offload is supplied.
Only closed hashes/counters leave the disposable guest; source and output stay private.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
OLD = runpy.run_path(str(HERE / "agent-cooperative-code.py"))
JOBS, BROWSER = OLD["JOBS"], OLD["BROWSER"]
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
sha, digest, hex64 = OLD["sha"], OLD["digest"], OLD["hex64"]
NAME = "agent-cooperative-code-proposal"
CODE_REVISION = "f27576ebd7e7ded2f1319186f34df87f48e970d7"
PROFILE = "qwen3-0.6b-v1"
MODEL = dict(model_id="Qwen/Qwen3-0.6B", model_revision="c1899de289a04d12100db370d81485cdf75e47ca",
    base_weights=dict(bytes=1503300328, sha256="f47f71177f32bcd101b7573ec9171e6a57f4f4d31148d38e382306f42996874b"),
    adapter_files=None)
FINGERPRINT = sha(BROWSER["encoded"](MODEL))
BUNDLE_FILES = tuple("code/" + name for name in OLD["CODE_FILES"]) + (
    "code/src/public-code-result.cjs", "code/src/public-code-file.cjs", "code/src/workspace-verifier.cjs",
    "code/scripts/smoke_opencode_inference.cjs", "code/scripts/smoke_public_code_proposal.cjs",
    "runtime/node", "runtime/node-LICENSE")
ORIGINAL = b"def add(a, b):\n    return a - b\n"
TEST_SHA = "78a8726db93e31cbe6f87dd58c7cb76d35cd5086d090c40b0e68caf9f0836835"
QUESTION_SHA = "e1c169f57923c644bcdd3d7ac9ce5796049393c6e2c0ccd9938ad155d9bfdd0e"
EXPORT_NAMES = tuple(f"{NAME}-{suffix}.json" for suffix in (
    "smoke", "evidence", "provision", "driver", "observation", "result", "diagnostic", "capacity")) + (
    "a01-expected-peers.json", "agent-jobs-layout.json", "agent-jobs-provision.json", "agent-jobs-private-cleanup.json",
    "content-custody-fetch-live-selection.json", "content-custody-fetch-gates.json",
    "content-provider-custody-fetch-control.json",
    *(f"content-custody-fetch-privacy-{role}.json" for role in JOBS["CUSTODY"]["ROLES"]))
FLAGS = {"passed", "synthetic_model_answers", "synthetic_public_core", "local_planner_used",
    "private_peer_execution_proven", "full_coding_quality_proven", "peer_datapath_proof_owned_by_parent",
    "vm_cleanup_owned_by_parent", "owner_edit_approved", "owner_test_approved", "replacement_applied",
    "original_tests_unchanged", "fixture_changed", "only_selected_file_present", "independent_test_passed",
    "owner_cleanup_confirmed", "project_removed", "original_baseline_failed"}
DRIVER_FIELDS = FLAGS | {"version", "kind", "phase", "failure", "cleanup_failure", "original_source_sha256",
    "original_tests_sha256", "question_sha256", "license", "public_result", "owner_check_status", "elapsed_ms"}
RESULT_HASHES = {"source_sha256", "source_manifest_id", "dataset_sha256", "dataset_manifest_id", "provider_key",
    "model_fingerprint", "report_sha256", "raw_result_sha256", "output_sha256"}
RESULT_FIELDS = RESULT_HASHES | {"tool_call_id", "core_task_id", "model_profile", "source_bytes", "peer_job_id",
    "output_bytes", "proposal_complete", "stop_reason", "generated_tokens", "core_reported_cleanup_confirmed"}


def paths(work):
    return work / "agent-jobs-user/code", work / "state-client/compute-source/public-code"


def capacity(work):
    """Original post-hash service counters, not a prediction of job admission."""
    JOBS["guest_work"](work)
    layout = read(work / "agent-jobs-layout.json")
    require(len(layout["provider_nodes"]) == 1 and layout["provider_nodes"][0] in JOBS["NODES"], "capacity node")
    node = layout["provider_nodes"][0]
    broker = JOBS["identity"](JOBS["broker_pid"](node))
    group = Path("/sys/fs/cgroup/system.slice") / f"volparossa-alpha-compute@{node}.service"
    expected = f"0::/system.slice/{group.name}\n"
    require(Path(f"/proc/{broker['pid']}/cgroup").read_text() == expected, "actual broker cgroup")
    fields = {}
    for name in ("memory.max", "memory.current", "memory.swap.max"):
        value = (group / name).read_text().strip()
        require(re.fullmatch(r"[0-9]{1,20}", value) and int(value) < 2 ** 64, "capacity counter")
        fields[name.replace(".", "_")] = int(value)
    require(fields["memory_max"] == 7 * 1024 ** 3 and fields["memory_swap_max"] == 0, "candidate service bound")
    available = re.search(r"^MemAvailable:\s+([0-9]+) kB$", Path("/proc/meminfo").read_text(), re.MULTILINE)
    require(available is not None, "guest available memory")
    write(work / f"{NAME}-capacity.json", dict(version=1, node=node, **fields,
        guest_mem_available_bytes=int(available[1]) * 1024, native_known_spare_bytes=4608 * 1024 ** 2,
        native_rss_limit_bytes=4 * 1024 ** 3, sampled_after_broker_model_hash=True,
        job_admission_proven=False, scope="post_hash_service_observation_not_full_ancestor_headroom"))


def bundle_manifest(value):
    require(set(value) == {"version", "kind", "code_revision", "node_version", "files"}
        and value["version"] == 1 and value["kind"] == "public-code-proposal-inputs"
        and value["code_revision"] == CODE_REVISION and re.fullmatch("[0-9a-f]{40}", CODE_REVISION)
        and value["node_version"] == "24.19.0" and set(value["files"]) == set(BUNDLE_FILES), "exact proposal bundle")
    total = 0
    for name, row in value["files"].items():
        require(set(row) == {"bytes", "sha256", "mode"} and type(row["bytes"]) is int
            and 0 < row["bytes"] <= (160 * 1048576 if name == "runtime/node" else 1048576)
            and row["mode"] == (0o700 if name == "runtime/node" else 0o600) and hex64(row["sha256"]), "bundle file")
        total += row["bytes"]
    require(total <= 190 * 1048576, "bounded proposal bundle")
    node = read(HERE / "agent-private-conversation-pins.json")["runtime"]["files"]
    for staged, original in (("runtime/node", "bin/node"), ("runtime/node-LICENSE", "LICENSE")):
        require(all(value["files"][staged][key] == node[original][key] for key in ("bytes", "sha256")), "Node pin")


def provision(work, bundle, expected):
    JOBS["guest_work"](work)
    account = pwd.getpwnam("volparossa")
    OLD["checked_file"](bundle / "INPUTS.json", account.pw_uid, 65536)
    require(hex64(expected) and digest(bundle / "INPUTS.json") == expected, "explicit bundle hash")
    selected = read(bundle / "INPUTS.json", 65536)
    bundle_manifest(selected)
    root, _ = paths(work)
    require(not root.exists() and not root.is_symlink(), "new proposal root required")
    root.mkdir(mode=0o700)
    os.chown(root, account.pw_uid, account.pw_gid)
    for name, row in selected["files"].items():
        original = bundle / name
        info = OLD["checked_file"](original, account.pw_uid, row["bytes"])
        require(info.st_size == row["bytes"] and digest(original) == row["sha256"], "source bytes changed")
        target = root / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with original.open("rb") as source, target.open("xb") as output:
            shutil.copyfileobj(source, output, 65536)
        require(digest(target) == row["sha256"], "copy changed")
        target.chmod(row["mode"])
        os.chown(target, account.pw_uid, account.pw_gid)
        for directory in [target.parent, *target.parent.parents]:
            if directory == root:
                break
            directory.chmod(0o700)
            os.chown(directory, account.pw_uid, account.pw_gid)
    (root / "projects").mkdir(mode=0o700)
    os.chown(root / "projects", account.pw_uid, account.pw_gid)
    write(work / f"{NAME}-provision.json", dict(version=1, bundle_manifest_sha256=expected, manifest=selected,
        local_model_planner=False, model_profile=PROFILE))


def driver(value, successful=False):
    require(type(value) is dict and set(value) == DRIVER_FIELDS and value["version"] == 1
        and value["kind"] == "public-code-single-file-trial-v1"
        and value["phase"] in {"prepare", "peer_execution", "edit", "owner_check", "independent_check", "complete"}
        and value["failure"] in {None, "cancelled_or_deadline", "public_code_trial_failed"}
        and value["cleanup_failure"] in {None, "core_cleanup_unconfirmed", "project_cleanup_unconfirmed"}
        and value["owner_check_status"] in {None, "passed", "failed", "unavailable"}
        and type(value["elapsed_ms"]) is int and 0 <= value["elapsed_ms"] <= 2520000
        and all(type(value[key]) is bool for key in FLAGS)
        and all(hex64(value[key]) for key in ("original_source_sha256", "original_tests_sha256", "question_sha256"))
        and value["original_source_sha256"] == sha(ORIGINAL) and value["original_tests_sha256"] == TEST_SHA
        and value["question_sha256"] == QUESTION_SHA and value["license"] == "GPL-3.0-only"
        and not any(value[key] for key in ("synthetic_model_answers", "synthetic_public_core", "local_planner_used",
            "private_peer_execution_proven", "full_coding_quality_proven")), "closed driver fields")
    result = value["public_result"]
    if result is not None:
        require(type(result) is dict and set(result) == RESULT_FIELDS
            and all(hex64(result[key]) for key in RESULT_HASHES)
            and result["tool_call_id"] == "owner-public-code-trial-1"
            and all(re.fullmatch("[0-9a-f]{32}", result[key]) for key in ("core_task_id", "peer_job_id"))
            and result["model_profile"] == PROFILE and result["model_fingerprint"] == FINGERPRINT
            and result["source_bytes"] == len(ORIGINAL) and result["source_sha256"] == sha(ORIGINAL)
            and type(result["output_bytes"]) is int and 0 <= result["output_bytes"] <= 4096
            and type(result["generated_tokens"]) is int and 0 < result["generated_tokens"] <= 1024
            and result["stop_reason"] in {"eos", "token_limit"}
            and type(result["proposal_complete"]) is bool
            and type(result["core_reported_cleanup_confirmed"]) is bool, "closed original result")
    if successful:
        require(value["passed"] and value["phase"] == "complete" and value["failure"] is None
            and value["cleanup_failure"] is None and value["owner_check_status"] == "passed"
            and all(value[key] for key in ("owner_edit_approved", "owner_test_approved", "replacement_applied",
                "original_tests_unchanged", "fixture_changed", "only_selected_file_present", "independent_test_passed",
                "owner_cleanup_confirmed", "project_removed", "original_baseline_failed",
                "peer_datapath_proof_owned_by_parent", "vm_cleanup_owned_by_parent"))
            and result is not None and result["proposal_complete"] and result["stop_reason"] == "eos"
            and result["output_bytes"] > 0 and result["core_reported_cleanup_confirmed"], "owner proposal/test incomplete")
    return value


def retained_result(task, shown, layout, observed):
    raw = BROWSER["exact_bytes"](task / "dataset.json")
    data = json.loads(raw)
    handle = read(task / "execution/job-0.json", 65536)
    binding = handle["binding"]
    receipt = read(task / f"execution/receipt-{binding['job_id']}.json", 1048576)
    status = receipt["status"]
    require(receipt["handle"] == handle and status["binding"] == binding
        and status["state"] == "complete" and not status["cancellation_requested"]
        and binding["row_indices"] == [0] and binding.get("task") is None
        and handle["capabilities"]["code_proposal_v6"] is True
        and handle["capabilities"]["model"] == MODEL
        and binding["model_fingerprint"] == FINGERPRINT
        and handle["provider_key"] == layout["provider_keys"][layout["provider_nodes"][0]], "exact peer receipt")
    report = json.loads(status["report_json"])
    require(sha(status["report_json"].encode()) == status["report_sha256"] == shown["report_sha256"]
        and report["mode"] == "public_code_proposal" and report["purpose"] == "code_proposal"
        and report["output_contract"] == "single_file_replacement_v1" and report["proposal_complete"] is True
        and report["model_weights_loaded"] is True and report["supervisor"]["child_reaped"] is True
        and report["supervisor"]["network_access"] is False and report["private_data_supported"] is False
        and report["public_data_only"] is True and report["artifacts"] == [] and report["updates_completed"] == 0,
        "actual worker result incomplete")
    require(report["model"]["id"] == MODEL["model_id"] and report["model"]["revision"] == MODEL["model_revision"]
        and report["model"]["files"]["model.safetensors"] == MODEL["base_weights"], "actual pinned model")
    require(set(data) == {"version", "visibility", "purpose", "license", "model_profile", "source_manifest_hex",
            "inference", "output_contract"}
        and data["version"] == 6 and data["visibility"] == "public" and data["purpose"] == "code_proposal"
        and data["model_profile"] == PROFILE and data["output_contract"] == "single_file_replacement_v1"
        and data["license"] == "GPL-3.0-only" and len(data["inference"]) == 1
        and data["inference"][0]["context"].encode() == ORIGINAL
        and data["inference"][0]["start"] == 0 and data["inference"][0]["end"] == len(ORIGINAL), "original public source")
    source_manifest = BROWSER["exact_bytes"](task / "source.manifest", 65536)
    require(bytes.fromhex(data["source_manifest_hex"]) == source_manifest
        and sha(raw) == binding["dataset_sha256"] == shown["dataset_sha256"] == report["dataset"]["sha256"]
        and digest(task / "dataset.manifest") == binding["dataset_manifest_id"] == shown["dataset_manifest_id"]
        and sha(source_manifest) == shown["source_manifest_id"] == report["dataset"]["source_manifest_sha256"]
        and report["dataset"]["source_sha256"] == sha(ORIGINAL)
        and shown["peer_job_id"] == binding["job_id"] and shown["provider_key"] == handle["provider_key"], "source/result join")
    outputs = report["outputs"]
    require(len(outputs) == 1 and outputs[0]["sample_index"] == 0, "single original output")
    output = outputs[0]
    require(output["text_truncated"] is False and output["generation"] == dict(version=1, stop_reason="eos",
            max_new_tokens=1024, model_profile=PROFILE)
        and sha(output["text"].encode()) == shown["output_sha256"]
        and len(output["text"].encode()) == shown["output_bytes"]
        and output["generated_tokens"] == shown["generated_tokens"], "unmodified EOS output")
    require(observed is not None and observed["dataset_file"]["sha256"] == sha(raw)
        and observed["dataset_json"].encode() == raw and observed["node"] == layout["provider_nodes"][0], "actual input not observed")
    return dict(shown, exact_receipt_join=True, original_input_observed=True, observed_task_processes_ended=True)


def signed_input_binding(task, publisher):
    # Inspect exact original signed bytes. Signature verification itself is the
    # real content/agent boundary, not a second Python cryptographic implementation.
    fields = JOBS["CUSTODY"]["fields"]
    raw = BROWSER["exact_bytes"](task / "dataset.json")
    source = BROWSER["exact_bytes"](task / "source.manifest", 65536)
    body = fields(fields(source, 65536)[1], 65536)
    authority = dict(publisher_key=publisher, selected_at_unix_seconds=body[3], expires_at_unix_seconds=body[4])
    BROWSER["DOCUMENT"]["manifest"](source, ORIGINAL, authority, "public-code-source", "text/plain")
    BROWSER["DOCUMENT"]["manifest"](BROWSER["exact_bytes"](task / "dataset.manifest", 65536), raw, authority,
        "public-code-proposal", "application/vnd.volparossa.agent-code-proposal.v6+json")


def observe(work, pid):
    JOBS["guest_work"](work)
    root, state = paths(work)
    layout = read(work / "agent-jobs-layout.json")
    require(len(layout["provider_nodes"]) == 1, "one eligible broker required")
    node = layout["provider_nodes"][0]
    broker, owner = JOBS["identity"](JOBS["broker_pid"](node)), JOBS["identity"](pid)
    observed, tasks, phase = None, [], "worker_scan"
    deadline = time.monotonic() + 2460
    try:
        while JOBS["alive"](owner) and time.monotonic() < deadline:
            tasks = BROWSER["task_roots"](state)
            require(len(tasks) <= 1, "one public task only")
            if tasks and observed is None and (tasks[0] / "execution/job-0.json").is_file():
                handle = read(tasks[0] / "execution/job-0.json", 65536)
                observed = JOBS["worker_snapshot"](work, node, broker, handle["binding"]["dataset_sha256"])
            time.sleep(0.05)
        require(not JOBS["alive"](owner), "owner deadline")
        phase = "owner_result"
        shown = driver(read(root / "report.json", 65536), successful=True)
        require(len(tasks) == 1 and observed is not None, "exactly one observed peer task")
        phase = "retained_result"
        signed_input_binding(tasks[0], read(work / "agent-jobs-publish.json")["publisher_key_hex"])
        result = retained_result(tasks[0], shown["public_result"], layout, observed)
        require(sha(json.loads(observed["dataset_json"])["inference"][0]["question"].encode()) == shown["question_sha256"], "question join")
        phase = "worker_cleanup"
        BROWSER["check_task_workers_ended"]([observed])
        write(work / f"{NAME}-result.json", result)
        write(work / f"{NAME}-observation.json", dict(version=1, isolated_live_worker=True,
            observed_task_processes_ended=True, node=node, base_model_sha256=MODEL["base_weights"]["sha256"],
            dataset_sha256=result["dataset_sha256"], worker=observed["worker"], broker=broker))
    finally:
        write(work / f"{NAME}-observer.private", dict(version=1, phase=phase,
            observed_worker=observed is not None, task_count=min(len(tasks), 2)))


def closed_peer_status(state):
    result = dict(task_count=0, handle_present=False, receipt_present=False, job_state=None, job_error=None)
    try:
        tasks = BROWSER["task_roots"](state)
        require(len(tasks) <= 1, "one public task")
        result["task_count"] = len(tasks)
        if not tasks:
            return result
        path = tasks[0] / "execution/job-0.json"
        if not path.is_file():
            return result
        handle = read(path, 65536)
        job_id = handle["binding"]["job_id"]
        require(re.fullmatch("[0-9a-f]{32}", job_id), "bounded job")
        result["handle_present"] = True
        path = tasks[0] / f"execution/receipt-{job_id}.json"
        if path.is_file():
            receipt = read(path, 1048576)
            require(receipt["handle"] == handle and receipt["status"]["state"] in {"running", "complete", "failed", "cancelled"}
                and receipt["status"]["error"] in {None, "invalid", "busy", "missing", "expired", "model_mismatch",
                    "worker_failed", "result_mismatch", "unavailable"}, "closed original job state")
            result.update(receipt_present=True, job_state=receipt["status"]["state"], job_error=receipt["status"]["error"])
        return result
    except (OSError, ValueError, KeyError, TypeError):
        return None


def capture(work, application_status, observer_status):
    JOBS["guest_work"](work)
    require(all(0 <= value <= 255 for value in (application_status, observer_status)), "exit status")
    state = "absent"
    try:
        shown = driver(read(paths(work)[0] / "report.json", 65536))
        write(work / f"{NAME}-driver.json", shown)
        state = "valid"
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError):
        state = "invalid"
    observer = None
    try:
        value = read(work / f"{NAME}-observer.private", 4096)
        require(set(value) == {"version", "phase", "observed_worker", "task_count"}
            and value["version"] == 1 and value["phase"] in {"worker_scan", "owner_result", "retained_result", "worker_cleanup"}
            and type(value["observed_worker"]) is bool and type(value["task_count"]) is int
            and 0 <= value["task_count"] <= 2, "closed observer")
        observer = value
    except (OSError, ValueError, KeyError, TypeError):
        pass
    write(work / f"{NAME}-diagnostic.json", dict(version=1, driver_exit_status=application_status,
        observer_exit_status=observer_status, driver_report=state, observer=observer,
        peer_execution=closed_peer_status(paths(work)[1])))


def evidence(work, revision):
    JOBS["guest_work"](work)
    root, state = paths(work)
    require(not root.exists() and not state.exists() and not (state.parent / "public.sock").exists(), "private state remains")
    value = {key: read(work / f"{NAME}-{key}.json", 1048576) for key in ("provision", "driver", "observation", "result")}
    value.update(source_revision=revision, layout=read(work / "agent-jobs-layout.json"),
        peers=read(work / "a01-expected-peers.json"), private_cleanup=read(work / "agent-jobs-private-cleanup.json"),
        path=dict(selected_route=read(work / "content-custody-fetch-live-selection.json"),
            privacy={role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in JOBS["CUSTODY"]["ROLES"]},
            control_privacy=read(work / "content-provider-custody-fetch-control.json"), gates=read(work / "content-custody-fetch-gates.json")),
        public_service_stopped=True, peer_broker_stopped=True, private_state_removed=True)
    for unit in ("volparossa-alpha-public-code.service", "volparossa-alpha-cooperative-code.service",
            f"volparossa-alpha-compute@{value['layout']['provider_nodes'][0]}.service"):
        require(subprocess.check_output(["systemctl", "show", "--property=ActiveState", "--value", unit], text=True).strip()
            in {"inactive", "failed"}, "service still active")
    check_evidence(value, revision)
    write(work / f"{NAME}-evidence.json", value)


def check_evidence(value, revision):
    require(value["source_revision"] == revision and all(value[key] is True for key in
        ("public_service_stopped", "peer_broker_stopped", "private_state_removed")), "source/cleanup")
    bundle_manifest(value["provision"]["manifest"])
    shown = driver(value["driver"], successful=True)
    require(value["result"] == dict(shown["public_result"], exact_receipt_join=True,
        original_input_observed=True, observed_task_processes_ended=True), "closed original result changed")
    require(value["observation"]["isolated_live_worker"] is True
        and value["observation"]["observed_task_processes_ended"] is True
        and value["observation"]["base_model_sha256"] == MODEL["base_weights"]["sha256"]
        and value["observation"]["dataset_sha256"] == shown["public_result"]["dataset_sha256"]
        and value["layout"]["provider_nodes"] == [value["observation"]["node"]]
        and value["private_cleanup"] == dict(observed_compute_processes_ended=True, model_runtime_removed=True,
            private_job_roots_removed=True, publisher_key_removed=True), "isolated worker/cleanup missing")
    JOBS["CUSTODY"]["validate_path"](value["path"], value["peers"], value["layout"], "fetch", payload_minimum=1)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    file = work / f"{NAME}-evidence.json"
    value = read(file, 1048576) if file.is_file() else None
    if value is not None:
        check_evidence(value, revision)
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    inventory_path = work / "agent-cooperative-browser-inventory.private"
    inventory = BROWSER["closed_inventory"](read(inventory_path, 4096)) if inventory_path.is_file() else None
    write(work / f"{NAME}-smoke.json", dict(report_kind="volparossa-public-code-proposal", schema_version=1,
        source_revision=revision, runner_exit_status=status, phase=phase,
        observed_blocker=None if blocker == "NONE" else blocker, evidence=value, host_state=host,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining), inventory_diagnostic=inventory,
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and value is not None))


def check_report(value, revision):
    require(value["report_kind"] == "volparossa-public-code-proposal" and value["schema_version"] == 1
        and value["source_revision"] == revision and value["success"] is True and value["runner_exit_status"] == 0
        and value["phase"] == f"{NAME}-complete" and value["observed_blocker"] is None
        and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
        and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "successful source-bound guest proof")
    check_evidence(value["evidence"], revision)


def main(args):
    if args == ["export-names"]:
        print("\n".join(EXPORT_NAMES))
    elif len(args) == 2 and args[0] == "await-inventory":
        # Reuse only the existing signed-topology gate (not its model/proof scope).
        BROWSER["main"](["--trial", "discovered-360m", "await-inventory", args[1]])
    elif len(args) == 2 and args[0] == "capacity":
        capacity(Path(args[1]))
    elif len(args) == 4 and args[0] == "provision":
        provision(Path(args[1]), Path(args[2]), args[3])
    elif len(args) == 3 and args[0] == "observe":
        observe(Path(args[1]), int(args[2]))
    elif len(args) == 4 and args[0] == "capture":
        capture(Path(args[1]), int(args[2]), int(args[3]))
    elif len(args) == 3 and args[0] == "evidence":
        evidence(Path(args[1]), args[2])
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif len(args) == 3 and args[0] == "report":
        check_report(read(Path(args[1]), 1048576), args[2])
    else:
        raise ValueError("explicit proposal fixture command required")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        print("public code proposal proof failed; private content withheld", file=sys.stderr)
        raise SystemExit(1)
