#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual public model assessments/cross-reviews; never proof of moral/legal accuracy."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
TRAIN, CUSTODY = JOBS["TRAIN"], JOBS["CUSTODY"]
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
NAME = "agent-policy-assessment"
SUBJECT = "Neighbors voluntarily lend spare computing capacity to help each other, while respecting consent and each device owner's needs.\n"
STAGES = ("assessment-0", "assessment-1", "review-0", "review-1")
SCOPE = ("one exact synthetic public native object fetched through its protected content path, two actual "
         "360M peer assessments and opposite-peer cross-reviews under the seven virtues/vices, bound "
         "to original EOS receipts, then unchanged completed offline replay and full owned cleanup; "
         "not classifier quality, legal correctness, independent semantic judgment, network-policy activation or full B06")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(work, suffix):
    return work / f"{NAME}-{suffix}.json"


def root_path(work):
    return work / "state-client/compute-source/policy-assessment"


def prepare(work):
    require(TRAIN["socket"].gethostname() == "volparossa-alpha"
            and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
            and os.geteuid() != 0, "not the unprivileged disposable guest")
    source = work / "state-client/compute-source"
    require(work.parent == Path("/opt") and work.name.startswith("va.")
            and not work.is_symlink() and HERE == work / "bin"
            and source.stat().st_uid == os.geteuid(), "wrong disposable policy fixture")
    for path in (Path(__file__),):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222,
                "fixture is not root-installed readonly")
    path = source / "policy-input.txt"
    with path.open("xb") as stream:
        stream.write(SUBJECT.encode())
    path.chmod(0o600)
    print(json.dumps({"subject": SUBJECT, "sha256": sha(SUBJECT.encode()), "license": "CC0-1.0",
                      "synthetic_public_fixture": True, "expected_moral_verdict_supplied": False}))


def snapshot(root):
    owner = root.lstat()
    require(stat.S_ISDIR(owner.st_mode) and not root.is_symlink() and owner.st_uid != 0
            and stat.S_IMODE(owner.st_mode) == 0o700, "wrong retained workflow root")
    files, total, entries = {}, 0, 0
    for directory, children, names in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(children):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
                    and info.st_uid == owner.st_uid and stat.S_IMODE(info.st_mode) == 0o700,
                    "unsafe workflow directory")
            # Publication chunks are not task decisions or receipts; never export identities/runtime.
            if relative.endswith("/publication-cache"):
                continue
            require(re.fullmatch(r"(?:assessment|review)-[01](?:/(?:work|poll-[0-9]{2}))?", relative),
                    "unexpected policy workflow directory")
            kept.append(name)
        children[:] = kept
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            require(name in {"subject.txt", "subject.manifest", "subject-download.json", "enrollment.json",
                             "result.json", "context.txt", "context.manifest", "dataset.json", "dataset.manifest",
                             "job-0.json", ".task.lock"}
                    or re.fullmatch(r"receipt-[0-9a-f]{32}\.json", name), "unexpected exported policy file")
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == owner.st_uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1048576,
                    "unsafe retained public proof file")
            raw = path.read_bytes()
            total += len(raw)
            entries += 1
            require(len(raw) == info.st_size and total <= 8 * 1048576 and entries <= 128,
                    "unbounded/changed retained history")
            files[relative] = {"bytes": len(raw), "sha256": sha(raw), "raw_hex": raw.hex(),
                               "inode": [info.st_dev, info.st_ino]}
    return files


def observe(work, pid):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](pid)
    layout = read(work / "agent-jobs-layout.json")
    brokers = {node: JOBS["identity"](JOBS["broker_pid"](node)) for node in layout["provider_nodes"]}
    observed = {}
    deadline = time.monotonic() + 3300
    while JOBS["alive"](owner) and time.monotonic() < deadline:
        for stage in STAGES:
            path = root_path(work) / stage / "work/job-0.json"
            if stage in observed or not path.is_file():
                continue
            handle = read(path)
            nodes = [n for n, key in layout["provider_keys"].items() if key == handle["provider_key"]]
            require(len(nodes) == 1, "job not assigned to one of the selected peers")
            node = nodes[0]
            value = JOBS["worker_snapshot"](work, node, brokers[node], handle["binding"]["dataset_sha256"])
            if value is not None:
                require(JOBS["alive"](value["worker"]), "worker disappeared during observation")
                observed[stage] = {"handle": handle, "observation": value}
                # Preserve useful original observations even when a later model answer is invalid.
                write(record(work, "observed-" + stage), observed[stage])
        time.sleep(0.025)
    write(record(work, "observation"), {"stages": observed})
    require(set(observed) == set(STAGES), "four actual assessment/review workers were not observed")


def collect(work):
    JOBS["guest_work"](work)
    write(record(work, "files"), snapshot(root_path(work)))


def stopped(work):
    JOBS["guest_work"](work)
    stages = read(record(work, "observation"))["stages"]
    require(set(stages) == set(STAGES), "missing observed executions")
    require(all(not JOBS["alive"](p) for stage in stages.values()
                for p in stage["observation"]["owned_processes"]), "observed worker lifetime still alive")
    write(record(work, "stopped"), {"observed_processes_ended": True})


def replay(work):
    JOBS["guest_work"](work)
    before = read(record(work, "files"), 32 * 1048576)
    require(snapshot(root_path(work)) == before, "completed replay changed retained history or added jobs")
    require(read(record(work, "result")) == read(record(work, "resume")), "offline result differs")
    write(record(work, "replay"), {"original_files_unchanged": True, "new_jobs": 0,
                                  "identical_result": True, "brokers_stopped": True})


def decode_file(files, name, json_value=True):
    item = files[name]
    raw = bytes.fromhex(item["raw_hex"])
    require(sha(raw) == item["sha256"] and len(raw) == item["bytes"], "retained bytes differ")
    return json.loads(raw) if json_value else raw


def check_result(value):
    require(value["operation"] == "compute_peer_policy_assessment" and value["complete"] is True
            and value["network_policy_activation"] is False, "model reasoning incomplete or overclaims activation")
    decision = value["decision"]
    require(decision["outcome"] in ("allow", "deny", "undetermined")
            and decision["decision_scope"] == "principle_framework_concept_only"
            and decision["legal_status"] == "not_determined"
            and all(decision[name] is False for name in ("enforcement_authority", "network_policy_changed",
                    "independent_evidence_proven", "semantic_reasoning_correctness_proven")), "unsupported judgment authority")
    require(len(decision["assessments"]) == len(decision["reviews"]) == 2 and len(value["stages"]) == 4,
            "missing actual assessments or cross-reviews")
    records = decision["assessments"] + decision["reviews"]
    require(all(item["scope"] == decision["scope"] for item in records), "decision source bindings differ")
    keys = [item["evidence"]["provider_key"] for item in records]
    require(keys[0] != keys[1] and keys[:2] == keys[2:], "distinct assessors/opposite reviews missing")
    for item in records:
        payload = item.get("assessment", item.get("review"))
        require(payload["version"] == 1 and 1 <= len(payload["reasoning"]) <= 3,
                "model did not produce complete structured reasoning")
        require(all(reason["quote"] and reason["quote"] in SUBJECT and reason["reason"].strip()
                    for reason in payload["reasoning"]), "reasoning is not bound to a literal subject quote")
    return records


def assessment_hash(value):
    # Exact Rust struct field order, not sorted generic JSON. Bind the reviewed
    # original receipt/raw-output digest as well as the interpreted payload.
    ordered = lambda item, keys: {key: item[key] for key in keys}
    payload = ordered(value["assessment"], ("version", "outcome", "reasoning", "counterargument", "uncertainty"))
    payload["reasoning"] = [ordered(item, ("principle", "quote", "reason")) for item in payload["reasoning"]]
    payload["uncertainty"] = ordered(payload["uncertainty"], ("material", "reason"))
    record_value = {
        "scope": ordered(value["scope"], ("source_publisher_key", "source_manifest_id", "source_sha256",
                                          "source_bytes", "framework_version", "framework_sha256")),
        "evidence": ordered(value["evidence"], ("provider_key", "job_id", "report_sha256", "model_fingerprint",
                                                "package_manifest_id")),
        "output_sha256": value["output_sha256"], "assessment": payload,
    }
    return sha(json.dumps(record_value, ensure_ascii=False, separators=(",", ":")).encode())


def check_evidence(value, revision):
    require(value["source_revision"] == revision and value["scope"] == SCOPE, "wrong source/scope")
    result = value["result"]
    records = check_result(result)
    files = value["files"]
    require(decode_file(files, "subject.txt", False) == SUBJECT.encode(), "wrong original subject")
    require(decode_file(files, "result.json") == result, "CLI result differs from retained result")
    subject_manifest = decode_file(files, "subject.manifest", False)
    scope = result["decision"]["scope"]
    require(scope["source_sha256"] == sha(SUBJECT.encode()) and scope["source_bytes"] == len(SUBJECT.encode())
            and scope["source_manifest_id"] == sha(subject_manifest)
            and scope["source_publisher_key"] == value["publication"]["publisher_key_hex"],
            "native subject/version differs")
    native = decode_file(files, "subject-download.json")
    require(native["operation"] == "named_content_download" and native["publisher_key"] == scope["source_publisher_key"]
            and native["manifest_id"] == scope["source_manifest_id"] and native["name"] == "disposable-policy-subject"
            and native["sha256"] == scope["source_sha256"] and native["bytes"] == scope["source_bytes"]
            and native["peer_bytes"] == scope["source_bytes"] and native["providers_used"] == 1
            and native["origin_body_bytes"] == 0 and native["origin_range_requests"] == 0
            and native["provider_peer_ids"] == [value["peers"][value["layout"]["provider_nodes"][0]]]
            and native["control_relay_peer_id"] == value["layout"]["control_relay_peer_id"],
            "exact native subject did not arrive from the selected protected peer on a cache miss")
    for index in range(2):
        require(records[2 + index]["reviewed_assessment_sha256"] == assessment_hash(records[1 - index]),
                "cross-review targets a different original assessment")
    observed = value["observation"]["stages"]
    require(set(observed) == set(STAGES), "missing live worker proof")
    response_bytes = {node: 0 for node in value["layout"]["provider_nodes"]}
    for stage, assessment in zip(STAGES, records):
        handle = decode_file(files, stage + "/work/job-0.json")
        bind = handle["binding"]
        receipt = decode_file(files, stage + "/work/receipt-" + bind["job_id"] + ".json")
        require(receipt["handle"] == handle and receipt["status"]["binding"] == bind
                and receipt["status"]["state"] == "complete", "original actual receipt differs")
        report_json = receipt["status"]["report_json"]
        report = json.loads(report_json)
        require(sha(report_json.encode()) == receipt["status"]["report_sha256"]
                == assessment["evidence"]["report_sha256"], "raw report binding differs")
        require(assessment["evidence"]["provider_key"] == handle["provider_key"]
                and assessment["evidence"]["job_id"] == bind["job_id"]
                and assessment["evidence"]["model_fingerprint"] == bind["model_fingerprint"]
                and assessment["evidence"]["package_manifest_id"] == bind["dataset_manifest_id"], "assessment provenance differs")
        model = TRAIN["inference_profile"]("smollm2-360m-v1")
        require(handle["capabilities"]["model"] == model["model"]
                and report["status"] == "ok" and report["mode"] == "infer" and report["device"] == "cpu"
                and report["updates_completed"] == 0 and len(report["outputs"]) == 1, "not actual pinned public inference")
        output = report["outputs"][0]
        require(output["generation"]["stop_reason"] == "eos" and output["text_truncated"] is False
                and 0 < output["generated_tokens"] <= 256
                and sha(output["text"].encode()) == assessment["output_sha256"]
                and json.loads(output["text"]) == assessment.get("assessment", assessment.get("review")),
                "model output was truncated, repaired or replaced")
        observation = observed[stage]["observation"]
        require(observed[stage]["handle"] == handle
                and sha(observation["dataset_json"].encode()) == bind["dataset_sha256"]
                and report["dataset"]["sha256"] == bind["dataset_sha256"]
                and observation["network_devices"] == ["lo"] and observation["runtime_lock_held"] is True,
                "worker mount/input/isolation does not bind the actual task")
        require(report["supervisor"]["child_reaped"] is True
                and report["supervisor"]["network_access"] is False, "worker cleanup/network differs")
        response_bytes[observation["node"]] += len(report_json.encode())
    CUSTODY["validate_path"](value["path"], value["peers"], value["layout"], "inspect")
    for node, minimum in response_bytes.items():
        require(value["path"]["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"] >= minimum,
                "protected selected provider did not carry the result bytes")
    require(value["replay"] == {"original_files_unchanged": True, "new_jobs": 0, "identical_result": True,
                                "brokers_stopped": True} and value["stopped"]["observed_processes_ended"] is True
            and all(value["cleanup"].values()), "offline replay/private cleanup incomplete")


def evidence(work, revision):
    JOBS["guest_work"](work)
    value = dict(source_revision=revision, scope=SCOPE, result=read(record(work, "result")),
        files=read(record(work, "files"), 32 * 1048576), observation=read(record(work, "observation")),
        publication=read(record(work, "publication")), replay=read(record(work, "replay")),
        stopped=read(record(work, "stopped")), layout=read(work / "agent-jobs-layout.json"),
        peers=read(work / "a01-expected-peers.json"), cleanup=read(work / "agent-jobs-private-cleanup.json"),
        path=dict(selected_route=read(work / "content-custody-fetch-live-selection.json"),
            privacy={role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
            control_privacy=read(work / "content-provider-custody-fetch-control.json"),
            gates=read(work / "content-custody-fetch-gates.json")))
    check_evidence(value, revision)
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    path = record(work, "evidence")
    proof = read(path, 64 * 1048576) if path.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    value = dict(report_kind=NAME, source_revision=revision, scope=SCOPE,
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and proof is not None,
        runner_exit_status=status, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        full_b06_claimed=False, network_policy_activation_claimed=False, evidence=proof,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host)
    write(record(work, "smoke"), value)


def check_report(value, revision):
    require(value["report_kind"] == NAME and value["source_revision"] == revision and value["scope"] == SCOPE
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["full_b06_claimed"] is False and value["network_policy_activation_claimed"] is False,
            "incomplete or overstated policy proof")
    require(value["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "host/guest cleanup changed")
    check_evidence(value["evidence"], revision)


def self_test():
    for value in ({}, {"operation": "compute_peer_policy_assessment", "complete": False,
                      "network_policy_activation": False},
                  {"operation": "compute_peer_policy_assessment", "complete": True,
                   "network_policy_activation": True}):
        try:
            check_result(value)
        except (KeyError, ValueError):
            pass
        else:
            raise ValueError("missing/incomplete/activating result accepted")
    require(0 < len(SUBJECT.encode()) <= 512, "synthetic subject exceeds actual product scope")
    print("PASS: policy fixture incomplete/authority rejection; no real model execution")


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        self_test()
    elif len(args) == 2 and args[0] in ("prepare", "collect", "stopped", "replay"):
        globals()[args[0]](Path(args[1]))
    elif len(args) == 3 and args[0] == "observe":
        observe(Path(args[1]), int(args[2]))
    elif len(args) == 3 and args[0] == "evidence":
        evidence(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "report":
        check_report(read(Path(args[1]), 64 * 1048576), args[2])
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    else:
        raise SystemExit("invalid policy fixture arguments")


if __name__ == "__main__":
    main()
