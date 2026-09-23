#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Guest-only automatic cohort intake, real comparison, warmstart and serving.

Self-test/report inspect inert or retained public evidence; neither executes ML.
The three publisher trainings and their explicit public R5 provisioning reuse
the manual fixture unchanged. No independent-party or general-quality claim.
"""
import copy
import json
import math
import os
from pathlib import Path
import runpy
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
A = runpy.run_path(str(HERE / "agent-adapter-aggregation-smoke.py"))
R, S, JOBS, TRAIN = (A[key] for key in ("R", "S", "JOBS", "TRAIN"))
read, write, require, digest = (A[key] for key in ("read", "write", "require", "digest"))
PREFIX = "agent-autonomous-aggregation"
ROUND = "aggregate-update-0000000000000001"
CYCLE = "cycle-0000000000000001"
CHANNEL = "disposable-autonomous-adapter"
MAX_PROOF = A["MAX_PROOF"]
KIND = "volparossa-owner-opt-in-autonomous-aggregation-warmstart-serving"
SCOPE = ("Three real 8/9/10-step public publisher trainings and explicit unchanged R5 custody. "
    "One owner-opted-in train-loop cold-discovers their exact cohort, really aggregates and compares it, "
    "adopts only an approved candidate and performs one eight-step local warmstart with inherited expiry. "
    "The actual selected approved aggregate or approved local successor is served in a protected peer job. "
    "The same owner-enrolled channel automatically publishes the aggregate as revision 1 and an approved local successor, if any, as revision 2. "
    "Another node cold-fetches the last approved signed publication and really infers with its exact weights. "
    "Restart retains original signatures, revisions and expiry without recomputing or republishing. "
    "After preserving those originals, damage only the genuinely approved local extraction C; "
    "resume restores its original approved aggregate A, a second restart is idempotent, and a protected job uses exact A. "
    "Then damage A's extraction: its pinned-base predecessor is not an approved rollback, so the coordinator blocks and broker admission is withdrawn. "
    "Successful aggregate-to-aggregate rollback is not covered. "
    "No peer-upload, independent-party, general-quality, Byzantine robustness, "
    "full B05 or complete-alpha claim.")


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def root(work):
    return A["private"](work, "relay4") / "autonomous-loop"


def setup(work):
    private = A["private"](work, "relay4")
    selected = read(private / "plan.json")["dataset"]
    source = dict(publisher_key=selected["publisher_key"], name=selected["name"],
        min_revision=selected["revision"], manifest_id=selected["manifest_id"])
    A["owned_json"](private / "source-plan.json", dict(version=1, sources=[source]))
    require(not root(work).exists() and (private / "serving").is_dir(), "wrong fresh loop/serving setup")
    write(record(work, "enrolled-inputs"), dict(source_plan=read(private / "source-plan.json"),
        aggregate_plan=read(private / "plan.json"), validation_source=read(private / "validation-source.json"),
        private_loop_absent=True, explicit_owner_opt_in=True, max_cycles=1, steps=8,
        publication=dict(name=CHANNEL, publisher_key=read(A["record"](work, "layout"))["keys"]["relay4"], first_revision=1)))


def observe_loop(work, pid):
    owner = TRAIN["identity"](pid)
    write(record(work, "loop-owner"), owner)
    aggregate, cycle = root(work) / ROUND, root(work) / CYCLE
    specs = {
        "aggregate": (aggregate / "dataset.json", aggregate / "job", aggregate / "cohort"),
        "aggregate-baseline": (aggregate / "candidate/comparison/dataset.json", aggregate / "candidate/comparison/baseline", None),
        "aggregate-candidate": (aggregate / "candidate/comparison/dataset.json", aggregate / "candidate/comparison/candidate", aggregate / "candidate/import/adapter"),
        "local-training": (cycle / "dataset.json", cycle / "training", aggregate / "candidate/import/adapter"),
        "local-baseline": (cycle / "validation/dataset.json", cycle / "validation/baseline", aggregate / "candidate/import/adapter"),
        "local-candidate": (cycle / "validation/dataset.json", cycle / "validation/candidate", cycle / "training/adapter"),
    }
    observed, deadline = set(), time.monotonic() + 3900
    while time.monotonic() < deadline and TRAIN["alive"](owner):
        for name, (dataset, output, adapter) in specs.items():
            if name in observed or not output.is_dir():
                continue
            found = A["worker_observation"](work, "relay4", owner, dataset, output, adapter)
            if found:
                observed.add(name)
                write(record(work, f"{name}-observation"), found)
        if len(observed) == len(specs):
            return
        time.sleep(0.02)
    if root(work).is_dir():
        write(record(work, "loop-incomplete"), A["snapshot"](root(work)))
    require(False, "automatic intake/gate/warmstart workers not all observed")


def capture(work, resumed=False):
    loop = root(work)
    if resumed:
        first = read(record(work, "first"), MAX_PROOF)
        files = A["snapshot"](loop)
        write(record(work, "resumed"), dict(snapshot={name: {key: item[key] for key in ("bytes", "sha256")}
            for name, item in files.items()}, state=read(loop / "state.json"),
            serving_hex=(A["private"](work, "relay4") / "serving/current.json").read_bytes().hex(),
            original_owner=first["owner"], owner=read(record(work, "resume-owner"))))
    else:
        files = A["snapshot"](loop, (f"{ROUND}/adapter.bundle", f"{CYCLE}/adapter.bundle"))
        output = (work / f"{PREFIX}-first.jsonl").read_bytes()
        require(len(output) <= 262144, "original coordinator output bound")
        summary = json.loads(output.splitlines()[-1])
        require(summary["operation"] == "compute_train_loop", "coordinator final summary missing")
        write(record(work, "first"), dict(files=files, state=read(loop / "state.json"),
            serving_hex=(A["private"](work, "relay4") / "serving/current.json").read_bytes().hex(),
            owner=read(record(work, "loop-owner")), summary=summary))


def observe_resume(work, pid):
    owner = TRAIN["identity"](pid)
    write(record(work, "resume-owner"), owner)
    original = read(record(work, "first"), MAX_PROOF)["state"]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and TRAIN["alive"](owner):
        state = read(root(work) / "state.json")
        if (state["aggregate_updates"]["verified_cohort_polls"] > original["aggregate_updates"]["verified_cohort_polls"]
                and not list(root(work).glob(".aggregate-discovery-*"))):
            require(state["completed"] == 1 and state["next_sequence"] == 2
                and state["aggregate_updates"]["next_sequence"] == 2, "resume repeated completed work")
            for member in TRAIN["descendants"](pid):
                try:
                    require((Path(f"/proc/{member['pid']}/cmdline").read_bytes().split(b"\0")[0]
                        != b"/runtime/bin/python3"), "resume unexpectedly launched an ML worker")
                except FileNotFoundError:
                    pass
            os.kill(pid, signal.SIGINT)
            return
        time.sleep(0.05)
    require(False, "resumed loop did not recheck its enrolled cohort")


def current(work):
    return json.loads(bytes.fromhex(read(record(work, "first"), MAX_PROOF)["serving_hex"]))


def ready(work):
    print("true" if S["capability_ready"](read(record(work, "capabilities")), current(work)["adapter_files"], True) else "false")


def observe_job(work):
    broker = TRAIN["identity"](JOBS["broker_pid"]("relay4"))
    dataset = read(work / "agent-jobs-source.json")["dataset"]
    expected = digest(JOBS["derive"](dataset, [0]).encode())["sha256"]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        found = JOBS["worker_snapshot"](work, "relay4", broker, expected_dataset_sha256=expected)
        if found:
            proc = Path(f"/proc/{found['worker']['pid']}")
            mounted = proc / "root/adapter"
            require(any(parts[4] == "/adapter" and "ro" in parts[5].split(",")
                for line in (proc / "mountinfo").read_text().splitlines() if len(parts := line.split()) > 5),
                "serving adapter not read-only")
            found["adapter_files"] = A["adapter_files"](mounted)
            require(found["adapter_files"] == current(work)["adapter_files"], "serving worker uses an unselected adapter")
            write(record(work, "serving-observation"), found)
            return
        time.sleep(0.02)
    require(False, "actual protected serving job not observed")


def capture_job(work):
    handle = A["private"](work, "client") / "autonomous-job.json"
    write(record(work, "handle"), read(handle))
    write(record(work, "model-after"), A["file_hash"](A["model"](work, "relay4") / "model.safetensors", 300 * 1024 * 1024))
    for node in A["NODES"]:
        original = read(A["record"](work, f"{node}-original"), MAX_PROOF)
        require(A["adapter_files"](A["private"](work, node) / "training/adapter") == original["adapter"],
            "original publisher adapter changed")


def receiver_prepare(work):
    receiver = A["private"](work, "client")
    first = read(record(work, "first"), MAX_PROOF)
    local = first["state"]["latest"] == 1
    name = f"{CYCLE}/publication.pb" if local else f"{ROUND}/publication/publication.pb"
    signed = bytes.fromhex(first["files"][name]["hex"])
    require(not (receiver / "autonomous-cache").exists() and not (receiver / "autonomous-received").exists(),
        "return receiver is not cold")
    write(record(work, "receiver-cold"), dict(cache_absent=True, import_absent=True, no_body_provisioned=True,
        expected_revision=2 if local else 1, expected_manifest_id=digest(signed)["sha256"]))


def observe_receiver(work, pid):
    owner = TRAIN["identity"](pid)
    write(record(work, "receiver-owner"), owner)
    receiver = A["private"](work, "client")
    deadline = time.monotonic() + 650
    while time.monotonic() < deadline and TRAIN["alive"](owner):
        found = A["worker_observation"](work, "client", owner, receiver / "autonomous-received/dataset.json",
            receiver / "autonomous-inference", receiver / "autonomous-received/adapter")
        if found:
            write(record(work, "receiver-observation"), found)
            return
        time.sleep(0.02)
    require(False, "actual returned-adapter inference was not observed")


def capture_return(work):
    receiver = A["private"](work, "client")
    write(record(work, "receiver-files"), A["snapshot"](receiver / "autonomous-received"))
    write(record(work, "receiver-inference-files"), A["snapshot"](receiver / "autonomous-inference"))
    write(record(work, "receiver-model-after"), A["file_hash"](A["model"](work, "client") / "model.safetensors", 300 * 1024 * 1024))


def cleanup_workers(work):
    processes = [read(path) for path in work.glob(f"{PREFIX}-*-owner.json")]
    for path in work.glob(f"{PREFIX}-*-observation.json"):
        processes.extend(read(path)["owned_processes"])
    require(not any(TRAIN["alive"](item) for item in processes), "owned autonomous worker remains alive")
    if not record(work, "process-cleanup").exists():
        write(record(work, "process-cleanup"), dict(owned_processes=processes,
            all_recorded_processes_ended=True, checked_before_private_store_removal=True))


def unchanged_completed(first, resumed):
    original = {name: {key: item[key] for key in ("bytes", "sha256")}
                for name, item in first["files"].items() if name != "state.json"}
    require({name: item for name, item in resumed["snapshot"].items() if name != "state.json"} == original,
        "resume changed completed cohort/training/enrollment bytes")
    before, after = copy.deepcopy(first["state"]), copy.deepcopy(resumed["state"])
    require(after["aggregate_updates"]["next_poll"] > before["aggregate_updates"]["next_poll"], "resume did not poll")
    require(after["aggregate_updates"]["verified_cohort_polls"] == before["aggregate_updates"]["verified_cohort_polls"] + 1,
        "resume did not verify exactly one unchanged original cohort")
    for name in ("next_poll", "verified_cohort_polls"):
        before["aggregate_updates"].pop(name); after["aggregate_updates"].pop(name)
    require(before == after and resumed["serving_hex"] == first["serving_hex"]
        and resumed["owner"] != first["owner"] and resumed["original_owner"] == first["owner"],
        "restart repeated work or changed original selection/expiry")


def local_approval(training, validation, evaluation):
    source = [training[f"{name}_evaluation"] for name in ("baseline", "adapted", "reloaded")]
    heldout = [validation[name] for name in ("baseline", "candidate")]
    for metric in source + heldout:
        require(type(metric["loss"]) in (int, float) and math.isfinite(metric["loss"]) and metric["loss"] >= 0
            and type(metric["target_tokens"]) is int and metric["target_tokens"] > 0, "invalid actual comparison metric")
    require(len({m["target_tokens"] for m in source}) == 1 and heldout[0]["target_tokens"] == heldout[1]["target_tokens"],
        "comparison token sets changed")
    require(abs(source[1]["loss"] - source[2]["loss"]) <= max(1e-6, 1e-5 * max(abs(source[1]["loss"]), abs(source[2]["loss"]))),
        "reloaded loss differs from actual candidate")
    validation_approved = heldout[1]["loss"] < heldout[0]["loss"] - 1e-6
    approved = source[2]["loss"] < source[0]["loss"] - 1e-6 and validation_approved
    require(validation["approved"] is validation_approved and evaluation["approved"] is approved
        and evaluation["validation"] == validation
        and [evaluation[name] for name in ("baseline", "adapted", "reloaded")] == source,
        "approval differs from actual original two-source gate")
    return approved


def publication_identity(signed, bundle, publisher, revision, authority, receipt):
    expires = R["signed_content"](signed, bundle, publisher, CHANNEL, R["ADAPTER_TYPE"], revision)
    envelope = R["CUSTODY"]["fields"](signed, 65536)
    body = R["CUSTODY"]["fields"](envelope[1], 65536)
    require(expires <= authority and expires - body[3] <= 3600, "returned publication renewed original authority")
    identity = dict(manifest_id=digest(signed)["sha256"], manifest_sha256=digest(signed)["sha256"],
        created=body[3], expires=expires)
    require(receipt["operation"] == "content_contribute" and receipt["network_publication"] is True
        and receipt["serving"] is True and receipt["publications"] > 0
        and receipt["manifest_id"] == identity["manifest_id"] and receipt["publisher_key_hex"] == publisher
        and receipt["name"] == CHANNEL and receipt["revision"] == revision
        and receipt["content_type"] == R["ADAPTER_TYPE"] and receipt["bytes"] == len(bundle)
        and receipt["chunks"] == (len(bundle) + 256 * 1024 - 1) // (256 * 1024)
        and receipt["expires_unix_seconds"] == expires and receipt["original_signature_reused"] is True
        and all(receipt[key] is False for key in ("private_keys_transferred", "ownership_changed", "origin_authenticated"))
        and body[3] <= receipt["coordinator_verified_at_unix_seconds"] < expires,
        "automatic publication receipt does not bind the original signature/revision")
    return identity


def check_publication_order(order, local_approved):
    entries = [dict(target=dict(kind="aggregate", sequence=1), revision=1)]
    if local_approved:
        entries.append(dict(target=dict(kind="local", sequence=1), revision=2))
    require(order == dict(version=1, first=1, next_revision=len(entries) + 1, entries=entries),
        "aggregate/local channel revisions collided or were reallocated")


def check_return(value, core, cycle, state, selected, chosen, expiry, enrollment):
    publisher = value["layout"]["keys"]["relay4"]
    require(value["enrolled-inputs"]["publication"] == dict(name=CHANNEL, publisher_key=publisher, first_revision=1)
        and enrollment["publish_name"] == CHANNEL and enrollment["publication_key"] == publisher
        and enrollment["first_publication_revision"] == 1
        and enrollment["aggregate_publication"] == dict(version=1, ordering="shared-local-and-aggregate-revisions",
            first_revision=1, original_authority_required=True), "automatic return was not owner-enrolled")
    local = state["latest"] == 1
    check_publication_order(state["publication_order"], local)
    files = core["files"]
    aggregate_signed, aggregate_bundle = files["publication/publication.pb"], files["adapter.bundle"]
    aggregate_identity = publication_identity(aggregate_signed, aggregate_bundle, publisher, 1, expiry,
        json.loads(files["publication/contribution.json"]))
    require(selected["publication"]["phase"] == "complete"
        and selected["publication"]["manifest"] == json.loads(files["publication/manifest.json"]) == aggregate_identity,
        "original aggregate revision 1 was not really published")
    authorization = json.loads(files["publication/request.json"])
    require(authorization["approval"] == selected["approval"] and authorization["name"] == CHANNEL
        and authorization["revision"] == 1 and authorization["publisher_key"] == publisher
        and authorization["bundle"] == digest(aggregate_bundle) and authorization["expires_not_after"] == expiry,
        "aggregate signature used a different approved object or owner channel")
    chosen_signed, chosen_bundle, chosen_identity = aggregate_signed, aggregate_bundle, aggregate_identity
    if local:
        chosen_signed, chosen_bundle = cycle["publication.pb"], cycle["adapter.bundle"]
        result = json.loads(cycle["result.json"])
        chosen_identity = publication_identity(chosen_signed, chosen_bundle, publisher, 2,
            min(expiry, result["authority_expires_unix_seconds"]), json.loads(cycle["contribution.json"]))
        require(state["cycles"][0]["phase"] == "complete" and state["cycles"][0]["publication"] == dict(
            manifest_id=chosen_identity["manifest_id"], expires=chosen_identity["expires"]), "local revision 2 was not published")
    else:
        require(state["cycles"][0]["phase"] == "rejected" and state["cycles"][0]["publication"] is None
            and "publication.pb" not in cycle and "contribution.json" not in cycle, "rejected local model entered public channel")
    R["check_bundle"](chosen_bundle, chosen, digest(core["dataset_signed"])["sha256"])
    cold = value["receiver-cold"]
    require(cold == dict(cache_absent=True, import_absent=True, no_body_provisioned=True,
        expected_revision=2 if local else 1, expected_manifest_id=chosen_identity["manifest_id"]), "return receiver not cold/exactly selected")
    received = R["raw_files"](value["receiver-files"])
    require(received["dataset.json"] == core["dataset"], "returned adapter used different training source")
    provenance = json.loads(received["provenance.json"])
    require(value["import"] == provenance and provenance["publisher"] == publisher
        and provenance["dataset_publisher"] == value["layout"]["keys"]["relay5"]
        and provenance["adapter_manifest_id"] == chosen_identity["manifest_id"]
        and provenance["expires_unix_seconds"] <= chosen_identity["expires"], "receiver did not retrieve exact original signed publication")
    for name, body, manifest in (("adapter", chosen_bundle, chosen_signed), ("dataset", core["dataset"], core["dataset_signed"])):
        R["check_cold_receipt"](provenance[name + "_receipt"], manifest, body, value["peers"]["relay4"])
    for name in A["FILES"]:
        require({key: value["receiver-files"][f"adapter/{name}"][key] for key in ("bytes", "sha256")} == chosen[name],
            "receiver mounted different returned weights")
    inference = value["receiver-inference"]
    A["check_supervisor"](inference, "infer", core["dataset"])
    A["check_original_report"](inference, R["raw_files"](value["receiver-inference-files"])["report.json"])
    require(inference["updates_completed"] == 0 and inference["input_adapter"]["applied"] is True
        and inference["input_adapter"]["files"] == chosen and inference["outputs"], "cold receiver did not really use returned weights")
    require(value["receiver-model-after"] == value["sources"]["model_before"], "receiver base model changed")
    summary = value["first"]["summary"]
    require(summary["completed_cycles"] == 1 and summary["attempts_this_invocation"] == 1
        and summary["pending_publications"] == 0 and summary["publication_drain"] == "complete", "automatic return queue did not drain")


def check(value, revision):
    require(value["source_revision"] == revision, "wrong automatic aggregation revision")
    first, resumed = value["first"], value["resumed"]
    unchanged_completed(first, resumed)
    raw = R["raw_files"](first["files"])
    require(json.loads(raw["state.json"]) == first["state"], "original state replaced")
    aggregate_files = {name[len(ROUND) + 1:]: entry for name, entry in first["files"].items() if name.startswith(ROUND + "/")}
    core = A["check_aggregate_core"](dict(value, **{"aggregate-files": aggregate_files}), revision, cached_validation=True)
    aggregate, cohort, dataset = core["result"], core["cohort"], core["dataset"]
    expiry = cohort["expires_unix_seconds"]
    require(aggregate["automatic_training_loop_integration"] is True and aggregate["model_activated"] is False
        and aggregate["network_publication"] is False and expiry <= min(core[k] for k in ("source_expiry", "validation_expiry", "original_expiry")),
        "loop aggregation scope/expiry changed")
    R["check_bundle"](core["files"]["adapter.bundle"], aggregate["candidate_files"], digest(core["dataset_signed"])["sha256"])
    state = first["state"]; registry = state["aggregate_updates"]
    require(state["completed"] == 1 and state["next_sequence"] == 2 and len(state["cycles"]) == 1
        and registry["next_sequence"] == 2 and len(registry["rounds"]) == 1, "not exactly one automatic round and local cycle")
    selected = registry["rounds"][0]
    ids = [digest(bytes.fromhex(value["originals"][node]["publication"]))["sha256"] for node in A["NODES"]]
    require(selected["phase"] == "approved" and selected["sequence"] == 1 and selected["expires"] == expiry
        and selected["cohort"] == registry["seen"] == dict(manifest_ids=ids, revisions=[1, 1, 1]), "automatic selection differs from original cohort")
    for field, name in (("cohort_sha256", "cohort.json"), ("comparison_sha256", "candidate/comparison/decision.json"), ("result_sha256", "result.json")):
        require(selected["approval"][field] == digest(core["files"][name])["sha256"], "original aggregate approval changed")
    require(selected["approval"]["adapter_files"] == aggregate["candidate_files"], "approved adapter identities changed")
    enrollment = json.loads(raw["enrollment.json"])
    require(enrollment["aggregate_updates"] == registry["selection"]
        and registry["selection"]["plan"] == value["enrolled-inputs"]["aggregate_plan"]
        and registry["selection"]["validation_source"] == value["enrolled-inputs"]["validation_source"]
        and enrollment["sources"] == value["enrolled-inputs"]["source_plan"]["sources"]
        and value["enrolled-inputs"]["explicit_owner_opt_in"] is True, "loop did not retain exact owner enrollment")
    validation = bytes.fromhex(value["sources"]["validation"])
    validation_signed = bytes.fromhex(value["sources"]["validation_manifest"])
    require(raw["validation-input/dataset.json"] == validation and raw["validation-input/dataset.manifest"] == validation_signed,
        "initial validation source changed")
    R["check_cold_receipt"](json.loads(raw["validation-input/provenance.json"])["source_receipt"],
        validation_signed, validation, value["peers"]["relay5"])
    cycle = {name[len(CYCLE) + 1:]: body for name, body in raw.items() if name.startswith(CYCLE + "/")}
    selection, result, evaluation = (json.loads(cycle[name]) for name in ("selection.json", "result.json", "evaluation.json"))
    predecessor = selection["aggregate_predecessor"]
    require(predecessor["kind"] == "aggregate_update" and predecessor["aggregate_sequence"] == 1
        and predecessor["manifest_ids"] == ids and predecessor["adapter_files"] == aggregate["candidate_files"]
        and predecessor["expires_unix_seconds"] == expiry and predecessor["result_sha256"] == digest(core["files"]["result.json"])["sha256"]
        and evaluation["aggregate_predecessor"] == predecessor and result["authority_expires_unix_seconds"] <= expiry,
        "local cycle did not inherit original approved aggregate")
    training = json.loads(cycle["training-report.json"])
    A["check_supervisor"](training, "train", dataset)
    A["check_original_report"](training, cycle["training/report.json"])
    require(training["updates_completed"] == 8 and training["input_adapter"]["applied"] is True
        and training["input_adapter"]["files"] == aggregate["candidate_files"]
        and training["adapter_weights_changed"] is True and training["checkpoint_reloaded"] is True
        and cycle["dataset.json"] == dataset and cycle["dataset.manifest"] == core["dataset_signed"],
        "local training did not genuinely continue exact aggregate weights")
    local_files = {name: {key: first["files"][f"{CYCLE}/training/adapter/{name}"][key] for key in ("bytes", "sha256")} for name in A["FILES"]}
    A["check_artifacts"](training, local_files)
    local_validation = json.loads(cycle["validation.json"])
    for stage, adapter in (("baseline", aggregate["candidate_files"]), ("candidate", local_files)):
        envelope = json.loads(cycle[f"{stage}-report.json"])
        report_ = envelope["report"]
        A["check_supervisor"](report_, "infer", validation)
        A["check_original_report"](report_, cycle[f"validation/{stage}/report.json"])
        require(report_["input_adapter"]["files"] == adapter
            and local_validation[stage] == report_["baseline_evaluation"]
            and envelope["started_at_unix_seconds"] <= envelope["verified_at_unix_seconds"] <= envelope["deadline_unix_seconds"]
            and envelope["deadline_unix_seconds"] <= expiry, "local comparison changed actual inputs/loss/expiry")
    for checkpoint in (local_validation, evaluation):
        for name, identity in checkpoint["files"].items():
            require(first["files"][f"{CYCLE}/{name}"]["sha256"] == identity["sha256"]
                and first["files"][f"{CYCLE}/{name}"]["bytes"] == identity["bytes"], "local original approval evidence changed")
    require(evaluation["candidate_adapter"] == local_files and evaluation["candidate_parameters"] == training["adapter_after"],
        "local approval selected different trained weights")
    require(local_approval(training, local_validation, evaluation) is (state["latest"] == 1), "local approval pointer changed")
    serving = json.loads(bytes.fromhex(first["serving_hex"]))
    chosen = local_files if state["latest"] == 1 else aggregate["candidate_files"]
    kind = "approved_local_successor" if state["latest"] == 1 else "approved_aggregate"
    require(serving["adapter_files"] == chosen and serving["provenance"]["kind"] == kind
        and serving["provenance"]["approved"] is True and serving["expires_unix_seconds"] <= expiry,
        "serving snapshot does not match actual approved selection")
    require(registry["active"] == (None if state["latest"] == 1 else 1), "aggregate not superseded/retained correctly")
    check_return(value, core, cycle, state, selected, chosen, expiry, enrollment)
    handle, status, caps = value["handle"], value["status"], value["capabilities"]
    require(S["capability_ready"](caps, chosen), "broker did not activate selected adapter")
    derived = JOBS["derive"](value["job-source"]["dataset"], [0]).encode()
    report_ = json.loads(status["report_json"])
    require(status["state"] == "complete" and status["binding"] == handle["binding"]
        and status["report_sha256"] == digest(status["report_json"].encode())["sha256"]
        and handle["provider_key"] == value["layout"]["keys"]["relay4"]
        and handle["binding"]["model_fingerprint"] == caps["model_fingerprint"]
        and handle["binding"]["dataset_sha256"] == digest(derived)["sha256"]
        and handle["binding"]["expires_unix_seconds"] <= serving["expires_unix_seconds"], "protected inference receipt changed")
    A["check_supervisor"](report_, "infer", derived)
    require(report_["updates_completed"] == 0 and report_["input_adapter"]["files"] == chosen and report_["outputs"],
        "protected serving job did not use chosen weights")
    observations = value["observations"]
    require(set(observations) == {"aggregate", "aggregate-baseline", "aggregate-candidate", "local-training", "local-baseline", "local-candidate", "serving", "receiver"},
        "actual loop/serving worker missing")
    originals = value["original-training-observations"]
    require(set(originals) == {f"{node}-train-{node}-train" for node in A["NODES"]}, "missing original training observation")
    for name, observation in dict(observations, **originals).items():
        require(observation["network_devices"] == ["lo"] and observation["ipv4_routes"] == []
            and observation["effective_capabilities"] == 0, "actual worker isolation missing")
        if name != "serving":
            require(observation["exact_input_inodes"] is True, "actual input inode binding missing")
    require(observations["aggregate"]["adapter_files"] == {f"{i}/{name}": core["inputs"][i][name] for i in range(3) for name in A["FILES"]}
        and observations["aggregate-candidate"]["adapter_files"] == aggregate["candidate_files"]
        and observations["local-baseline"]["adapter_files"] == aggregate["candidate_files"]
        and observations["local-candidate"]["adapter_files"] == local_files, "real worker adapter mount changed")
    require(observations["local-training"]["adapter_files"] == aggregate["candidate_files"]
        and observations["local-training"]["dataset"] == digest(dataset)
        and observations["serving"]["adapter_files"] == chosen
        and observations["serving"]["dataset_json"].encode() == derived
        and observations["receiver"]["adapter_files"] == chosen
        and observations["receiver"]["dataset"] == digest(dataset), "actual mounted warmstart/serving/receiver bytes differ")
    for label in ("uptake", "receiver"):
        R["check_network_path"](value["network"][label], "uptake" if label == "uptake" else "reserve-fetch", value["peers"])
    require(value["sources"]["model_before"] == value["model-after"] and all(value["cleanup"].values())
        and value["process-cleanup"]["all_recorded_processes_ended"] is True
        and value["original-process-cleanup"]["all_recorded_processes_ended"] is True,
        "model preservation or full owned cleanup missing")
    summary = value["resume-summary"]
    require(summary["attempts_this_invocation"] == 0 and summary["owner_cancelled"] is True
        and summary["completed_cycles"] == 1 and value["resume-no-source-failure"] is True,
        "resume did not retain/recheck completed work without another model run")
    runpy.run_path(str(HERE / "agent-aggregate-recovery-smoke.py"))["check"](value["recovery"], value)


def evidence(work, revision):
    value = {name: read(record(work, name), MAX_PROOF) for name in ("enrolled-inputs", "first", "resumed", "handle", "status", "capabilities", "model-after", "process-cleanup",
        "receiver-cold", "receiver-files", "receiver-inference-files", "receiver-inference", "receiver-model-after", "import")}
    value.update({name: read(A["record"](work, name), MAX_PROOF) for name in ("layout", "sources")})
    value.update(source_revision=revision, originals={node: read(A["record"](work, f"{node}-original"), MAX_PROOF) for node in A["NODES"]},
        peers=read(work / "a01-expected-peers.json"), **{"job-source": read(work / "agent-jobs-source.json"),
        "original-process-cleanup": read(A["record"](work, "process-cleanup"))},
        **{"original-training-observations": {path.name[len(A["PREFIX"]) + 1:-len("-observation.json")]: read(path)
            for path in work.glob(f"{A['PREFIX']}-*-train-*-observation.json")}},
        observations={path.name[len(PREFIX) + 1:-len("-observation.json")]: read(path)
            for path in work.glob(f"{PREFIX}-*-observation.json")},
        network={label: A["read_network_report"](work, label) for label in ("uptake", "receiver")},
        cleanup=read(work / "agent-jobs-private-cleanup.json"),
        recovery=read(work / "agent-aggregate-recovery-evidence.json", 4 * 1024 * 1024))
    lines = (work / f"{PREFIX}-resume.jsonl").read_bytes()
    errors = (work / f"{PREFIX}-resume.err").read_bytes()
    require(len(lines) <= 262144 and len(errors) <= 262144, "resume diagnostic bound")
    records = [json.loads(line) for line in lines.splitlines()]
    require(len(records) == 1, "resume emitted new model-work records")
    value["resume-summary"] = records[0]
    value["resume-no-source-failure"] = b"aggregate_sources_unavailable" not in errors
    check(value, revision)
    require(len(json.dumps(value, indent=2)) + 1 < MAX_PROOF - 65536, "automatic proof bound exceeded")
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    proof = read(record(work, "evidence"), MAX_PROOF) if record(work, "evidence").exists() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").exists() else {}
    value = dict(report_kind=KIND, scope=SCOPE, source_revision=revision, runner_exit_status=status,
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and proof is not None,
        evidence=proof, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host,
        general_quality_proven=False, automatic_publication=True, full_b05_claimed=False, full_alpha_claimed=False)
    require(len(json.dumps(value, indent=2)) + 1 < MAX_PROOF, "automatic final report bound")
    write(record(work, "smoke"), value)


def report(value, revision):
    require(value["report_kind"] == KIND and value["scope"] == SCOPE and value["source_revision"] == revision
        and value["success"] is True and value["runner_exit_status"] == 0 and value["observed_blocker"] is None
        and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
        and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"]
        and value["automatic_publication"] is True
        and all(value[k] is False for k in ("general_quality_proven", "full_b05_claimed", "full_alpha_claimed")),
        "autonomous aggregation proof/cleanup/scope incomplete")
    check(value["evidence"], revision)


def self_test():
    A["self_test"]()
    runpy.run_path(str(HERE / "agent-aggregate-recovery-smoke.py"))["self_test"]()
    # Only inert byte/state controls, not invented optimizer or network evidence.
    first = dict(files={"state.json": digest(b"old"), "original.json": digest(b"inert")},
        state=dict(completed=1, aggregate_updates=dict(next_poll=10, next_sequence=2, verified_cohort_polls=1)), serving_hex="aa", owner=dict(pid=1, start=1))
    resumed = dict(snapshot={"state.json": digest(b"new"), "original.json": digest(b"inert")},
        state=dict(completed=1, aggregate_updates=dict(next_poll=11, next_sequence=2, verified_cohort_polls=2)), serving_hex="aa",
        owner=dict(pid=2, start=2), original_owner=first["owner"])
    unchanged_completed(first, resumed)
    for change in (lambda v: v["snapshot"]["original.json"].update(sha256="f" * 64),
        lambda v: v["state"]["aggregate_updates"].update(next_sequence=3),
        lambda v: v.update(serving_hex="bb"), lambda v: v.update(owner=first["owner"]),
        lambda v: v["state"]["aggregate_updates"].update(next_poll=10),
        lambda v: v["state"]["aggregate_updates"].update(verified_cohort_polls=1)):
        invalid = copy.deepcopy(resumed); change(invalid)
        try:
            unchanged_completed(first, invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("changed/recomputed or unobserved restart accepted")
    metric = lambda loss: dict(loss=loss, target_tokens=16)
    training = dict(baseline_evaluation=metric(3), adapted_evaluation=metric(2), reloaded_evaluation=metric(2))
    validation = dict(baseline=metric(4), candidate=metric(3), approved=True)
    evaluation = dict(baseline=metric(3), adapted=metric(2), reloaded=metric(2), validation=validation, approved=True)
    require(local_approval(training, validation, evaluation), "actual gate expected approval")
    validation = dict(baseline=metric(4), candidate=metric(5), approved=False)
    evaluation.update(validation=validation, approved=False)
    require(not local_approval(training, validation, evaluation), "worsened held-out candidate promoted")
    evaluation["approved"] = True
    try:
        local_approval(training, validation, evaluation)
    except ValueError:
        pass
    else:
        raise AssertionError("fabricated local approval accepted")
    for local in (False, True):
        entries = [dict(target=dict(kind="aggregate", sequence=1), revision=1)]
        if local:
            entries.append(dict(target=dict(kind="local", sequence=1), revision=2))
        order = dict(version=1, first=1, next_revision=len(entries) + 1, entries=entries)
        check_publication_order(order, local)
        invalid = copy.deepcopy(order)
        invalid["entries"][-1]["revision"] = 1 if local else 2
        try:
            check_publication_order(invalid, local)
        except ValueError:
            pass
        else:
            raise AssertionError("colliding or reassigned return publication revision accepted")
    print("autonomous aggregation inert restart/provenance controls PASS; no model/network executed")


def main(args):
    command, *args = args
    if command == "self-test": self_test(); return
    if command == "report": report(read(Path(args[0]), MAX_PROOF), args[1]); return
    work = Path(args[0]); JOBS["guest_work"](work)
    if command == "setup": setup(work)
    elif command == "observe-loop": observe_loop(work, int(args[1]))
    elif command == "observe-resume": observe_resume(work, int(args[1]))
    elif command == "capture": capture(work)
    elif command == "capture-resume": capture(work, True)
    elif command == "ready": ready(work)
    elif command == "observe-job": observe_job(work)
    elif command == "capture-job": capture_job(work)
    elif command == "receiver-prepare": receiver_prepare(work)
    elif command == "observe-receiver": observe_receiver(work, int(args[1]))
    elif command == "capture-return": capture_return(work)
    elif command == "cleanup-workers": cleanup_workers(work)
    elif command == "evidence": evidence(work, args[1])
    elif command == "finalize": finalize(work, args[1], int(args[2]), S["cleanup_flag"](args[3]), int(args[4]), args[5], args[6])
    else: raise ValueError("unknown autonomous fixture command")


if __name__ == "__main__":
    main(sys.argv[1:])
