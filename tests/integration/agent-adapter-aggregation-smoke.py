#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Three real public trainings -> cold aggregate/gate/publication -> cold inference.

Only self-test/report are host-safe. Owner provisioning of original public
objects to R5 is explicit, not peer upload or remote training attestation.
"""
import copy
import json
import math
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
R = runpy.run_path(str(HERE / "agent-active-recovery-smoke.py"))
S, REP, JOBS, TRAIN, ART = (R[k] for k in ("SUCCESSOR", "REP", "JOBS", "TRAIN", "ART"))
read, write, require, digest, file_hash = (R[k] for k in ("read", "write", "require", "digest", "file_hash"))
FILES = R["FILES"]
PREFIX = "agent-adapter-aggregation"
NODES = ("relay3", "relay4", "relay5")
KIND = "volparossa-three-trained-publisher-adapter-aggregation"
ALGORITHM = "coordinate-median-effective-lora-rank4-v1"
MAX_PROOF = 24 * 1024 * 1024
# One network record combines five separately bounded captures and route/layout
# metadata. Match the existing content-replication evidence reader's 2 MiB cap,
# not the inherited 256 KiB limit for an individual training report.
MAX_NETWORK_REPORT = 2 * 1024 * 1024
SCOPE = ("Three isolated nodes perform 8/9/10 actual optimizer updates on one signed public dataset. "
         "Their unchanged signed artifacts are explicitly owner-provisioned at R5. R4 cold-fetches all three, "
         "aggregates effective deltas, performs a real held-out pinned-base comparison and publishes only if approved. "
         "Client cold-fetches and explicitly infers with that exact approved aggregate. "
         "No peer-upload, remote-training attestation, independent-party, automatic adoption, general quality, "
         "Byzantine robustness, full B05 or complete-alpha claim.")


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def private(work, node):
    require(node in (*NODES, "client"), "unexpected aggregation node")
    return work / ("state-client/compute-source" if node == "client" else f"state-{node}/compute")


def model(work, node):
    return private(work, node) / "model" if node == "client" else work / "agent-jobs-user/provision/model"


def owned_bytes(path, raw, owner):
    require(len(raw) <= 4 * 1024 * 1024, "public fixture input bound")
    with path.open("xb") as output:
        output.write(raw)
    path.chmod(0o600)
    os.chown(path, owner.st_uid, owner.st_gid)


def owned_json(path, value):
    owned_bytes(path, json.dumps(value, sort_keys=True).encode(), path.parent.stat())


def setup(work, revision):
    dataset = ART["dataset"](revision, (work / "bin/agent-jobs-README.md").read_text())
    validation = copy.deepcopy(dataset)
    validation["train"] = []
    validation["heldout"] = [dict(question="Does each permitted parallel route contain one intermediary relay?",
        answer="Exactly one distinct relay.", context=dataset["train"][0]["context"])]
    validation["inference"] = [dict(question="Which node count is permitted per parallel route?",
        context=dataset["train"][0]["context"])]
    keys = {node: read(work / f"agent-jobs-{node}-public.json")["identity_public_key_hex"] for node in NODES}
    require(len(set(keys.values())) == 3, "three original signing identities required")
    write(record(work, "layout"), dict(publishers=list(NODES), keys=keys, supplier="relay5", aggregator="relay4", receiver="client"))
    for node in NODES:
        owned_json(private(work, node) / "dataset.json", dataset)
    owned_json(private(work, "relay5") / "validation.json", validation)
    owned_json(private(work, "relay4") / "enrollment.json", dict(kind="public-empty-aggregation-cache-enrollment", version=1))


def enroll(work):
    keys = read(record(work, "layout"))["keys"]
    source = private(work, "relay5")
    dataset_manifest = (source / "dataset.pb").read_bytes()
    for node in ("relay3", "relay4"):
        owned_bytes(private(work, node) / "dataset.pb", dataset_manifest, private(work, node).stat())
    plan = dict(version=1, dataset=dict(publisher_key=keys["relay5"], name="disposable-aggregate-data", revision=1,
        manifest_id=digest(dataset_manifest)["sha256"]), adapters=[dict(publisher_key=keys[node],
        name=f"disposable-aggregate-{node}", min_revision=1) for node in NODES])
    owned_json(private(work, "relay4") / "plan.json", plan)
    owned_json(private(work, "relay4") / "validation-source.json", dict(publisher_key=keys["relay5"],
        name="disposable-aggregate-validation", min_revision=1, manifest_id=file_hash(source / "validation.pb", 65536)["sha256"]))
    write(record(work, "sources"), dict(dataset=(source / "dataset.json").read_bytes().hex(),
        dataset_manifest=dataset_manifest.hex(), validation=(source / "validation.json").read_bytes().hex(),
        validation_manifest=(source / "validation.pb").read_bytes().hex(), plan=plan,
        model_before=file_hash(model(work, "relay4") / "model.safetensors", 300 * 1024 * 1024)))


def snapshot(root, bundles=()):
    """Retain original proof bytes, not redundant tensor bodies or any keys/runtime."""
    result, total = {}, 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == root.stat().st_uid != 0, "unexpected proof owner/link")
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 1024 * 1024,
                "proof entry not bounded regular file")
        raw, name = path.read_bytes(), path.relative_to(root).as_posix()
        total += len(raw)
        require(total <= 32 * 1024 * 1024 and len(result) < 256, "proof tree bound exceeded")
        result[name] = digest(raw)
        if not name.endswith((".safetensors", ".bundle")) or name in bundles:
            result[name]["hex"] = raw.hex()
    return result


def adapter_files(root):
    return {name: file_hash(root / name, 2 * 1024 * 1024) for name in FILES}


def provision(work, node):
    require(node in NODES, "unknown public artifact producer")
    root, destination = private(work, node), private(work, "relay5") / f"supplier-{node}"
    destination.mkdir(mode=0o700)
    owner = root.stat()
    os.chown(destination, owner.st_uid, owner.st_gid)
    before = S["tree"](root / "original-cache")
    old, new = S["relocate_cache"](root / "original-cache", destination / "cache")
    require(before == S["tree"](destination / "cache"), "owner provision changed cache bytes")
    owned_bytes(destination / "publication.pb", (root / "publication.pb").read_bytes(), owner)
    value = dict(node=node, updates={"relay3": 8, "relay4": 9, "relay5": 10}[node],
        training=read(record(work, f"{node}-train")), files=snapshot(root / "training"),
        adapter=adapter_files(root / "training/adapter"), bundle=(root / "adapter.bundle").read_bytes().hex(),
        publication=(root / "publication.pb").read_bytes().hex(),
        pack=read(record(work, f"{node}-pack")), publication_receipt=read(record(work, f"{node}-publish")),
        provisioning=dict(original_cache_identity=old, supplier_cache_identity=new, files=before,
            original_cache_absent=not os.path.lexists(root / "original-cache"), unchanged_public_objects=True,
            peer_upload_claimed=False, private_keys_transferred=False))
    write(record(work, f"{node}-original"), value)


def worker_observation(work, node, owner, dataset, output, adapter):
    for member in TRAIN["descendants"](owner["pid"]):
        proc = Path(f"/proc/{member['pid']}")
        try:
            if (proc / "cmdline").read_bytes().split(b"\0")[0] != b"/runtime/bin/python3":
                continue
            root = proc / "root"
            if S["inode"](root / "output") != S["inode"](output):
                continue
            inputs = {"dataset.json": dataset, "runtime/pyvenv.cfg": private(work, node) / "runtime/pyvenv.cfg",
                      "model/model.safetensors": model(work, node) / "model.safetensors"}
            require(all(S["inode"](root / name) == S["inode"](path) for name, path in inputs.items()), "worker inputs substituted")
            mounts = {parts[4]: parts[5].split(",") for line in (proc / "mountinfo").read_text().splitlines()
                      if len(parts := line.split()) > 5 and parts[4] in ("/dataset.json", "/runtime", "/model", "/output", "/adapter")}
            require(all("ro" in mounts.get(name, []) for name in ("/dataset.json", "/runtime", "/model"))
                    and "rw" in mounts.get("/output", []), "worker mount isolation differs")
            adapters = None
            if adapter is not None:
                require("ro" in mounts.get("/adapter", []), "adapter writable")
                entries = [f"{n}/{name}" for n in range(3) for name in FILES] if adapter.name == "cohort" else FILES
                require(all(S["inode"](root / "adapter" / name) == S["inode"](adapter / name) for name in entries), "adapter input changed")
                adapters = {name: file_hash(adapter / name, 2 * 1024 * 1024) for name in entries}
            else:
                require(not (root / "adapter").exists(), "unexpected warmstart")
            devices = [line.split(":", 1)[0].strip() for line in (proc / "net/dev").read_text().splitlines()[2:]]
            status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
            require(devices == ["lo"] and len((proc / "net/route").read_text().splitlines()) == 1
                    and int(status["CapEff"], 16) == 0 and proc.stat().st_uid == private(work, node).stat().st_uid != 0,
                    "worker not isolated/unprivileged")
            return dict(node=node, worker=member, owner=owner, owned_processes=TRAIN["descendants"](owner["pid"]),
                dataset=file_hash(dataset, 1048576), adapter_files=adapters, exact_input_inodes=True,
                network_devices=devices, ipv4_routes=[], mounts=mounts, effective_capabilities=0,
                runtime_lock_inode=S["lock_observation"](private(work, node) / "runtime/.volparossa-compute.lock"))
        except FileNotFoundError:
            continue
    return None


def observe(work, node, label, pid):
    owner = TRAIN["identity"](pid)
    write(record(work, f"{label}-owner"), owner)
    root = private(work, node)
    if label == "aggregate":
        base = root / "aggregate"
        specs = {"aggregate": (base / "dataset.json", base / "job", base / "cohort"),
                 "baseline": (base / "candidate/comparison/dataset.json", base / "candidate/comparison/baseline", None),
                 "candidate": (base / "candidate/comparison/dataset.json", base / "candidate/comparison/candidate", base / "candidate/import/adapter")}
    elif label == "inference":
        specs = {label: (root / "received/dataset.json", root / "inference", root / "received/adapter")}
    else:
        require(label == f"{node}-train" and node in NODES, "unexpected worker observation")
        specs = {label: (root / "dataset.json", root / "training", None)}
    observed, deadline = {}, time.monotonic() + (1900 if label == "aggregate" else 650)
    while time.monotonic() < deadline and TRAIN["alive"](owner):
        for name, (dataset, output, adapter) in specs.items():
            if name in observed or not output.is_dir():
                continue
            found = worker_observation(work, node, owner, dataset, output, adapter)
            if found:
                observed[name] = found
                write(record(work, f"{label}-{name}-observation"), found)
        if len(observed) == len(specs):
            return
        time.sleep(0.02)
    # Preserve only exact public fixture artifacts on early failure, before teardown.
    if label == "aggregate" and (root / "aggregate").exists():
        write(record(work, "aggregate-incomplete"), snapshot(root / "aggregate"))
    require(False, "actual model worker phases not all observed")


def network_path(work, label):
    require(label in ("uptake", "receiver"), "unknown aggregation path")
    prefix = f"{PREFIX}-path-{label}"
    value = dict(layout=read(work / f"{prefix}-layout.json"), selected_route=read(work / f"{prefix}-selection.json"),
        route=read(work / f"{prefix}-live-selection.json"),
        captures={role: read(work / f"{prefix}-{role}.json") for role in REP["ROLES"]}, disconnected=True)
    R["check_network_path"](value, "uptake" if label == "uptake" else "reserve-fetch", read(work / "a01-expected-peers.json"))
    require(len(json.dumps(value, indent=2, allow_nan=False)) + 1 <= MAX_NETWORK_REPORT,
            "combined network report exceeds bound")
    write(record(work, f"network-{label}"), value)


def read_network_report(work, label):
    require(label in ("uptake", "receiver"), "unknown aggregation network report")
    return read(record(work, f"network-{label}"), MAX_NETWORK_REPORT)


def receiver_sources(work):
    """Only public trust metadata crosses owners; no aggregate/dataset body shortcut."""
    source, receiver = private(work, "relay4") / "aggregate", private(work, "client")
    for name, path in (("aggregate.pb", source / "publication/publication.pb"),
                       ("aggregate-dataset.pb", source / "peers/0/import/dataset.manifest")):
        owned_bytes(receiver / name, path.read_bytes(), receiver.stat())
    require(not (receiver / "aggregate-cache").exists() and not (receiver / "received").exists(), "receiver is not cold")
    write(record(work, "receiver-cold"), dict(cache_absent=True, import_absent=True, metadata_only_provisioned=True))


def capture(work):
    aggregate = private(work, "relay4") / "aggregate"
    write(record(work, "aggregate-files"), snapshot(aggregate, ("adapter.bundle",)))
    write(record(work, "receiver-files"), snapshot(private(work, "client") / "received"))
    write(record(work, "inference-files"), snapshot(private(work, "client") / "inference"))
    write(record(work, "model-after"), file_hash(model(work, "relay4") / "model.safetensors", 300 * 1024 * 1024))
    for node in NODES:
        original = read(record(work, f"{node}-original"), MAX_PROOF)
        require(adapter_files(private(work, node) / "training/adapter") == original["adapter"], "original trained adapter mutated")


def cleanup_workers(work):
    processes = [read(path) for path in sorted(work.glob(f"{PREFIX}-*-owner.json"))]
    for path in sorted(work.glob(f"{PREFIX}-*-observation.json")):
        processes.extend(read(path)["owned_processes"])
    require(not any(TRAIN["alive"](process) for process in processes), "owned aggregation/model processes alive")
    if not record(work, "process-cleanup").exists():
        write(record(work, "process-cleanup"), dict(owned_processes=processes, all_recorded_processes_ended=True,
                                                   checked_before_private_store_removal=True))


def check_supervisor(worker, mode, dataset):
    require(worker["status"] == "ok" and worker["mode"] == mode and worker["device"] == "cpu" and worker["threads"] == 2
            and worker["model"]["id"] == "HuggingFaceTB/SmolLM2-135M-Instruct"
            and worker["model"]["revision"] == TRAIN["MODEL_REVISION"]
            and worker["model"]["files"]["model.safetensors"]["sha256"] == TRAIN["WEIGHT_HASH"]
            and worker["dataset"]["sha256"] == digest(dataset)["sha256"] and worker["dataset"]["bytes"] == len(dataset),
            "worker did not use exact pinned model/public source")
    supervisor = worker["supervisor"]
    require(supervisor["sandbox"] == "bubblewrap-private-user-net-pid-ipc-mount"
            and supervisor["network_access"] is False and supervisor["gpu_access"] is False
            and supervisor["child_reaped"] is True and supervisor["spare_capacity"] is True
            and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"]
            and 0 < supervisor["deadline_seconds"] <= 600 and 0 < worker["elapsed_ms"] <= supervisor["deadline_seconds"] * 1000,
            "worker ownership/deadline/isolation missing")


def check_distinct_weights(inputs):
    require(len(inputs) == 3 and len({item["adapter_model.safetensors"]["sha256"] for item in inputs}) == 3,
            "three copied/re-signed identical weights are not three trained inputs")


def check_three_trainings(originals, dataset, manifest, keys, revision):
    expiries = []
    for node, steps in zip(NODES, (8, 9, 10)):
        original, report_ = originals[node], originals[node]["training"]
        check_supervisor(report_, "train", dataset)
        require(original["node"] == node and original["updates"] == report_["updates_completed"] == steps
                and len(report_["training_losses"]) == steps
                and all(type(loss) in (int, float) and math.isfinite(loss) and loss > 0 for loss in report_["training_losses"])
                and report_["dataset"]["source_revision"] == revision
                and report_["base_before"] == report_["base_after"] == report_["reloaded_base"]
                and report_["adapter_after"] == report_["reloaded_adapter"] != report_["adapter_before"]
                and all(report_[key] is True for key in ("base_weights_unchanged", "adapter_weights_changed", "checkpoint_reloaded")),
                "three genuine saved/reloaded optimizer runs required")
        files = R["raw_files"](original["files"])
        require(json.loads(files["report.json"]) == {k: v for k, v in report_.items() if k != "supervisor"}, "original worker report changed")
        actual = {entry["relative_path"].removeprefix("adapter/"): {key: entry[key] for key in ("sha256", "bytes")}
                  for entry in report_["artifacts"]}
        require(actual == original["adapter"], "saved training artifacts differ")
        for name in FILES:
            require({k: original["files"][f"adapter/{name}"][k] for k in ("sha256", "bytes")} == actual[name], "retained weights differ")
        bundle = bytes.fromhex(original["bundle"])
        R["check_bundle"](bundle, actual, digest(manifest)["sha256"])
        expiries.append(R["signed_content"](bytes.fromhex(original["publication"]), bundle, keys[node], f"disposable-aggregate-{node}", R["ADAPTER_TYPE"]))
        handoff = original["provisioning"]
        require(handoff["original_cache_identity"] == handoff["supplier_cache_identity"]
                and handoff["original_cache_absent"] is True and handoff["unchanged_public_objects"] is True
                and handoff["peer_upload_claimed"] is False and handoff["private_keys_transferred"] is False,
                "fixture public provisioning misrepresented")
    check_distinct_weights([originals[node]["adapter"] for node in NODES])
    return min(expiries)


def check_original_report(supervised, raw):
    require(json.loads(raw) == {key: value for key, value in supervised.items() if key != "supervisor"},
            "supervised report differs from original worker output")


def check_artifacts(report_, expected):
    artifacts = report_["artifacts"]
    require(len(artifacts) == len(FILES) and {entry["relative_path"] for entry in artifacts} == {"adapter/" + name for name in FILES},
            "adapter artifact set differs")
    require({entry["relative_path"].removeprefix("adapter/"): {key: entry[key] for key in ("bytes", "sha256")}
             for entry in artifacts} == expected, "adapter artifact hashes differ")


def check_aggregate_core(value, revision, cached_validation=False):
    require(value["source_revision"] == revision and value["layout"]["publishers"] == list(NODES), "source/layout mismatch")
    keys, peers = value["layout"]["keys"], value["peers"]
    require(len(set(keys.values())) == 3, "publisher identities repeated")
    sources = value["sources"]
    dataset, dataset_signed = (bytes.fromhex(sources[k]) for k in ("dataset", "dataset_manifest"))
    validation, validation_signed = (bytes.fromhex(sources[k]) for k in ("validation", "validation_manifest"))
    source_expiry = R["signed_content"](dataset_signed, dataset, keys["relay5"], "disposable-aggregate-data", R["DATASET_TYPE"])
    validation_expiry = R["signed_content"](validation_signed, validation, keys["relay5"], "disposable-aggregate-validation", R["DATASET_TYPE"])
    require(json.loads(validation)["train"] == [] and dataset != validation, "validation must be independently pinned held-out source")
    original_expiry = check_three_trainings(value["originals"], dataset, dataset_signed, keys, revision)
    files = R["raw_files"](value["aggregate-files"])
    aggregate, cohort = json.loads(files["aggregate-report.json"]), json.loads(files["cohort.json"])
    inputs = [value["originals"][node]["adapter"] for node in NODES]
    for index, node in enumerate(NODES):
        original = value["originals"][node]
        prefix = f"peers/{index}/import/"
        require(files[prefix + "adapter.manifest"] == bytes.fromhex(original["publication"])
                and value["aggregate-files"][prefix + "adapter.bundle"] == digest(bytes.fromhex(original["bundle"]))
                and files[prefix + "dataset.manifest"] == dataset_signed and files[prefix + "dataset.json"] == dataset,
                "cold imported cohort differs from original signed trainings")
        provenance = json.loads(files[prefix + "provenance.json"])
        R["check_cold_receipt"](provenance["adapter_receipt"], bytes.fromhex(original["publication"]), bytes.fromhex(original["bundle"]), peers["relay5"])
        if index == 0:
            R["check_cold_receipt"](provenance["dataset_receipt"], dataset_signed, dataset, peers["relay5"])
        else:
            receipt = provenance["dataset_receipt"]
            require(receipt["manifest_id"] == digest(dataset_signed)["sha256"] and receipt["sha256"] == digest(dataset)["sha256"]
                    and receipt["peer_bytes"] == 0 and receipt["providers_used"] == 0, "shared exact dataset not efficiently cached")
        require(all({k: value["aggregate-files"][f"cohort/{index}/{name}"][k] for k in ("bytes", "sha256")} == inputs[index][name]
                    for name in FILES), "frozen cohort changed")
    receipt = json.loads(files["validation-input/provenance.json"])["source_receipt"]
    if cached_validation:
        require(receipt["manifest_id"] == digest(validation_signed)["sha256"]
                and receipt["sha256"] == digest(validation)["sha256"] and receipt["bytes"] == len(validation)
                and receipt["peer_bytes"] == receipt["providers_used"] == receipt["origin_body_bytes"] == 0,
                "loop aggregation did not reuse its exact already verified validation source")
    else:
        R["check_cold_receipt"](receipt, validation_signed, validation, peers["relay5"])
    check_supervisor(aggregate, "aggregate_adapter", dataset)
    check_original_report(aggregate, files["job/report.json"])
    require(aggregate["updates_completed"] == 0 and aggregate["model_weights_loaded"] is False
            and aggregate["aggregation"]["algorithm"] == ALGORITHM and aggregate["aggregation"]["combined_modules"] == 60
            and aggregate["aggregation"]["input_files"] == inputs == cohort["input_files"], "not the actual effective-delta aggregation")
    result, decision = json.loads(files["result.json"]), json.loads(files["candidate/comparison/decision.json"])
    check_artifacts(aggregate, result["candidate_files"])
    for name in FILES:
        for prefix in ("job/adapter", "candidate/import/adapter"):
            require({k: value["aggregate-files"][f"{prefix}/{name}"][k] for k in ("bytes", "sha256")} == result["candidate_files"][name],
                    "aggregate candidate is not the original saved worker output")
    require(result["approved"] is True and decision["approved"] is True and result["candidate_files"] == decision["candidate_files"]
            and decision["baseline_origin"]["kind"] == "pinned_base"
            and decision["candidate"]["target_tokens"] == decision["baseline"]["target_tokens"] > 0
            and decision["candidate"]["loss"] < decision["baseline"]["loss"] - 1e-6,
            "actual held-out gate did not approve aggregate against base")
    for name, identity in decision["files"].items():
        require(digest(files[f"candidate/comparison/{name}"]) == identity, "held-out decision evidence changed")
    for stage in ("baseline", "candidate"):
        envelope = json.loads(files[f"candidate/comparison/{stage}-report.json"])
        check_supervisor(envelope["report"], "infer", validation)
        check_original_report(envelope["report"], files[f"candidate/comparison/{stage}/report.json"])
        require(decision[stage] == envelope["report"]["baseline_evaluation"], "approval metrics differ from original measured worker loss")
        require(envelope["started_at"] <= envelope["completed_at"] <= envelope["deadline"] <= min(source_expiry, validation_expiry, original_expiry)
                and envelope["deadline"] - envelope["started_at"] <= 600, "comparison deadline renewed")
        if stage == "candidate":
            require(envelope["report"]["input_adapter"]["files"] == result["candidate_files"], "compared a different adapter")
    return dict(result=result, files=files, cohort=cohort, inputs=inputs, dataset=dataset, dataset_signed=dataset_signed,
                source_expiry=source_expiry, validation_expiry=validation_expiry, original_expiry=original_expiry)


def check_evidence(value, revision):
    checked = check_aggregate_core(value, revision)
    result, files, cohort, inputs, dataset, dataset_signed, source_expiry, validation_expiry, original_expiry = (
        checked[key] for key in ("result", "files", "cohort", "inputs", "dataset", "dataset_signed",
                                "source_expiry", "validation_expiry", "original_expiry"))
    keys, peers = value["layout"]["keys"], value["peers"]
    bundle, signed = files["adapter.bundle"], files["publication/publication.pb"]
    expiry = R["signed_content"](signed, bundle, keys["relay4"], "disposable-approved-aggregate", R["ADAPTER_TYPE"])
    R["check_bundle"](bundle, result["candidate_files"], digest(dataset_signed)["sha256"])
    publication = value["publish"]
    require(publication["operation"] == "compute_publish_aggregate" and publication["content_serving"] is True
            and publication["optimizer_steps"] == 0 and publication["publication"]["manifest_id"] == digest(signed)["sha256"]
            and expiry <= cohort["expires_unix_seconds"] <= min(source_expiry, validation_expiry, original_expiry), "aggregate publication lost original authority")
    received = R["raw_files"](value["receiver-files"])
    require(value["receiver-cold"] == dict(cache_absent=True, import_absent=True, metadata_only_provisioned=True)
            and received["dataset.json"] == dataset, "receiver source shortcut")
    provenance = json.loads(received["provenance.json"])
    for name, raw, manifest in (("adapter", bundle, signed), ("dataset", dataset, dataset_signed)):
        R["check_cold_receipt"](provenance[name + "_receipt"], manifest, raw, peers["relay4"])
    inference = value["inference"]
    check_supervisor(inference, "infer", dataset)
    check_original_report(inference, R["raw_files"](value["inference-files"])["report.json"])
    require(inference["updates_completed"] == 0 and inference["input_adapter"]["applied"] is True
            and inference["input_adapter"]["files"] == result["candidate_files"] and len(inference["outputs"]) > 0,
            "receiver did not actually infer with approved aggregate")
    for name in FILES:
        require({k: value["receiver-files"][f"adapter/{name}"][k] for k in ("bytes", "sha256")} == result["candidate_files"][name], "receiver adapter changed")
    observations = value["observations"]
    require(len(observations) == 7, "missing actual worker phase")
    for observation in observations.values():
        require(observation["exact_input_inodes"] is True and observation["network_devices"] == ["lo"]
                and observation["ipv4_routes"] == [] and observation["effective_capabilities"] == 0, "actual worker isolation missing")
    require(observations["aggregate-aggregate"]["adapter_files"] == {f"{n}/{name}": inputs[n][name] for n in range(3) for name in FILES}
            and observations["aggregate-candidate"]["adapter_files"] == result["candidate_files"]
            and observations["inference-inference"]["adapter_files"] == result["candidate_files"], "actual worker adapter mounts differ")
    for label, phase in (("uptake", "uptake"), ("receiver", "reserve-fetch")):
        R["check_network_path"](value["network"][label], phase, peers)
    require(sources["model_before"] == value["model-after"] and value["process-cleanup"]["all_recorded_processes_ended"] is True
            and value["process-cleanup"]["checked_before_private_store_removal"] is True and all(value["cleanup"].values()),
            "model preservation or owned cleanup incomplete")


def evidence(work, revision):
    names = ("layout", "sources", "aggregate-files", "receiver-files", "inference-files", "receiver-cold", "inference", "publish", "model-after", "process-cleanup")
    value = {name: read(record(work, name), MAX_PROOF) for name in names}
    value.update(source_revision=revision, peers=read(work / "a01-expected-peers.json"),
        originals={node: read(record(work, f"{node}-original"), MAX_PROOF) for node in NODES},
        observations={path.name[len(PREFIX) + 1:-len("-observation.json")]: read(path)
                      for path in work.glob(f"{PREFIX}-*-observation.json")},
        network={name: read_network_report(work, name) for name in ("uptake", "receiver")},
        cleanup=read(work / "agent-jobs-private-cleanup.json"))
    check_evidence(value, revision)
    require(len(json.dumps(value, indent=2)) < MAX_PROOF - 65536, "evidence bound exceeded")
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    proof = read(record(work, "evidence"), MAX_PROOF) if record(work, "evidence").exists() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").exists() else {}
    value = dict(report_kind=KIND, scope=SCOPE, source_revision=revision, runner_exit_status=status,
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and proof is not None,
        phase=phase, observed_blocker=None if blocker == "NONE" else blocker, evidence=proof,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host,
        general_quality_proven=False, remote_training_attestation=False, automatic_adoption=False, full_b05_claimed=False, full_alpha_claimed=False)
    require(len(json.dumps(value, indent=2)) < MAX_PROOF, "report bound exceeded")
    write(record(work, "smoke"), value)


def report(value, revision):
    require(value["report_kind"] == KIND and value["scope"] == SCOPE and value["source_revision"] == revision
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "aggregation proof incomplete")
    require(all(value[key] is False for key in ("general_quality_proven", "remote_training_attestation", "automatic_adoption", "full_b05_claimed", "full_alpha_claimed")), "scope overstated")
    check_evidence(value["evidence"], revision)


def self_test():
    # Inert protocol/retention checks, never numerical/backend execution or success evidence.
    from tempfile import TemporaryDirectory
    raw = b"x" * (3 * 256 * 1024 + 5)
    require(len(R["content_payload"](raw, "fixture", R["ADAPTER_TYPE"], 1)) > 160, "multichunk metadata missing")
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        write(record(root, "model-after"), dict(bytes=1, sha256="a" * 64))
        require(private(root, "client") == root / "state-client/compute-source", "receiver namespace changed")
        try:
            private(root, "host")
        except (AssertionError, ValueError, RuntimeError, SystemExit):
            pass
        else:
            raise AssertionError("unowned node accepted")
        finalize(root, "a" * 40, 1, False, 1, "aggregate", "ACTUAL_GATE_REJECTED")
        failed = read(record(root, "smoke"))
        require(failed["success"] is False and failed["evidence"] is None and failed["general_quality_proven"] is False, "failed run presented as success")
    def reject(call):
        try:
            call()
        except (AssertionError, ValueError, RuntimeError, SystemExit):
            return
        raise AssertionError("changed original evidence accepted")
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        # Actual failure size was 587887 B; also cover the exact composite cap.
        # These inert JSON bytes are not packet observations or success evidence.
        overhead = len(json.dumps(dict(inert=""), indent=2)) + 1
        for size in (587887, MAX_NETWORK_REPORT):
            case = root / str(size)
            case.mkdir()
            value = dict(inert="x" * (size - overhead))
            write(record(case, "network-uptake"), value)
            require(record(case, "network-uptake").stat().st_size == size > 262144,
                    "composite read regression did not exceed old limit")
            reject(lambda: read(record(case, "network-uptake")))
            require(read_network_report(case, "uptake") == value, "bounded composite network report changed")
        write(record(root, "network-receiver"), dict(inert="x" * (MAX_NETWORK_REPORT + 1 - overhead)))
        require(record(root, "network-receiver").stat().st_size == MAX_NETWORK_REPORT + 1,
                "oversized composite boundary not exercised")
        reject(lambda: read_network_report(root, "receiver"))
        require(2 * MAX_NETWORK_REPORT < MAX_PROOF == 24 * 1024 * 1024, "total evidence cap changed")
    original = dict(mode="aggregate_adapter", updates_completed=0, marker="original")
    supervised = dict(original, supervisor=dict(child_reaped=True))
    check_original_report(supervised, json.dumps(original).encode())
    reject(lambda: check_original_report(dict(supervised, marker="changed"), json.dumps(original).encode()))
    expected = {name: digest(name.encode()) for name in FILES}
    artifacts = dict(artifacts=[dict(relative_path="adapter/" + name, **expected[name]) for name in FILES])
    check_artifacts(artifacts, expected)
    altered = copy.deepcopy(artifacts)
    altered["artifacts"][2]["sha256"] = "0" * 64
    reject(lambda: check_artifacts(altered, expected))
    altered = copy.deepcopy(artifacts)
    altered["artifacts"][2] = altered["artifacts"][1]
    reject(lambda: check_artifacts(altered, expected))
    inputs = [{"adapter_model.safetensors": digest(bytes([n]))} for n in range(3)]
    check_distinct_weights(inputs)
    reject(lambda: check_distinct_weights(inputs[:2]))
    reject(lambda: check_distinct_weights([inputs[0], inputs[1], copy.deepcopy(inputs[0])]))
    print("agent-adapter-aggregation inert self-test passed; no model/backend executed")


def main():
    command, *args = sys.argv[1:]
    if command == "self-test":
        self_test()
        return
    if command == "report":
        report(read(Path(args[0]), MAX_PROOF), args[1])
        return
    work = Path(args[0])
    JOBS["guest_work"](work)
    if command == "setup": setup(work, args[1])
    elif command == "enroll": enroll(work)
    elif command == "provision": provision(work, args[1])
    elif command == "observe": observe(work, args[1], args[2], int(args[3]))
    elif command == "network-path": network_path(work, args[1])
    elif command == "receiver-sources": receiver_sources(work)
    elif command == "capture": capture(work)
    elif command == "cleanup-workers": cleanup_workers(work)
    elif command == "evidence": evidence(work, args[1])
    elif command == "finalize": finalize(work, args[1], int(args[2]), S["cleanup_flag"](args[3]), int(args[4]), args[5], args[6])
    else: raise SystemExit("unsupported fixture command")


if __name__ == "__main__":
    main()
