#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable, real selected learning -> idle broker activation -> protected inference."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
ART = runpy.run_path(str(HERE / "agent-artifact-smoke.py"))
COLLECTION = runpy.run_path(str(HERE / "agent-public-collection-smoke.py"))
TRAIN, CUSTODY = JOBS["TRAIN"], JOBS["CUSTODY"]
read, write, require, file_hash = (TRAIN[k] for k in ("read", "write", "require", "file_hash"))
PREFIX = "agent-successor-serving"
KIND = "volparossa-selected-learning-to-peer-serving"
SCOPE = ("one explicit public source, one real eight-update local train-loop and its source-heldout "
         "approval; the same idle broker copies the selected adapter and executes a protected peer job "
         "with exact learned weights while preserving its earlier base-model receipt. Public source-cache "
         "provisioning and the learner's statically enabled Client role are explicit fixture setup; "
         "its exact source is checked through its own cache-only API, not learner-side network discovery. An injected invalid "
         "selection must not replace the approved copy. Not independent quality, automatic global model "
         "adoption, distributed optimization, expiry/restart proof, full B05 or full alpha.")
FILES = ("README.md", "adapter_config.json", "adapter_model.safetensors")
CYCLE = "cycle-0000000000000001"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(raw):
    return dict(bytes=len(raw), sha256=sha(raw))


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def roots(work):
    layout = read(work / "agent-jobs-layout.json")
    learner, publisher = layout["provider_nodes"]
    require(learner != publisher and learner in JOBS["NODES"] and publisher in JOBS["NODES"], "wrong selected nodes")
    return layout, work / f"state-{learner}/compute", work / f"state-{publisher}/compute/successor-source"


def tree(path):
    result = {}
    owner = path.stat().st_uid
    require(owner != 0 and not path.is_symlink(), "cache must belong to unprivileged fixture owner")
    for entry in sorted(path.rglob("*")):
        info = entry.lstat()
        require(not entry.is_symlink() and info.st_uid == owner, "public cache ownership differs")
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and len(result) < 64
                and info.st_size <= 2 * 1024 * 1024, "public cache entry differs")
        raw = entry.read_bytes()
        result[str(entry.relative_to(path))] = digest(raw)
    require(result, "public cache is empty")
    return result


def source(path, revision):
    path = JOBS["private"](path, "successor-source")
    require(not list(path.iterdir()), "wrong public source root")
    write(path / "dataset.json", ART["dataset"](revision, (HERE / "agent-jobs-README.md").read_text()))


def seed(work):
    JOBS["guest_work"](work)
    layout, learner, original = roots(work)
    publication = read(record(work, "publish"))
    fetched = work / "state-client/compute-source/successor-source.json"
    require(fetched.read_bytes() == (original / "dataset.json").read_bytes(), "fetched public source differs")
    cache = work / "state-client/compute-source/successor-cache"
    before = tree(cache)
    shutil.copytree(cache, learner / "source-cache", copy_function=shutil.copy2)
    owner = learner.stat()
    require(owner.st_uid == cache.stat().st_uid != 0, "learner public cache owner differs")
    for path in [learner / "source-cache", *(learner / "source-cache").rglob("*")]:
        os.chown(path, owner.st_uid, owner.st_gid, follow_symlinks=False)
    require(tree(learner / "source-cache") == before, "explicit public cache copy differs")
    write(learner / "plan.json", dict(version=1, sources=[dict(
        publisher_key=layout["provider_keys"][layout["provider_nodes"][1]], name=publication["name"],
        min_revision=1, manifest_id=publication["manifest_id"])]))
    # This is provisioning evidence only. Product verifies the original signed bytes again.
    write(learner / "source-cache-provision.json", dict(explicit_fixture_copy=True,
        learner_network_retrieval_claimed=False, source_cache_files=before,
        copied_cache_files=tree(learner / "source-cache"), dataset=digest(fetched.read_bytes()),
        manifest_id=publication["manifest_id"], original_expiry=publication["expires_unix_seconds"]))
    for name in ("plan.json", "source-cache-provision.json"):
        os.chown(learner / name, owner.st_uid, owner.st_gid)


def lock_observation(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "runtime lock is aliased")
    with path.open("rb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return [info.st_dev, info.st_ino]
    raise ValueError("actual worker did not hold shared runtime lock")


def check_local_source(roles, receipt, publication, dataset):
    require(roles == "client: true\nrelay: true\nexit: false\n", "static learner roles differ")
    require(all(type(receipt[key]) is int for key in ("revision", "bytes", "peer_bytes", "providers_used",
                "origin_body_bytes", "origin_range_requests", "publication_expires_unix_seconds")),
            "invalid cache-only accounting")
    require(receipt["operation"] == "named_content_download" and receipt["cache_only"] is True
            and receipt["local_delivery"] is True and receipt["manifest_id"] == publication["manifest_id"]
            and receipt["publisher_key"] == publication["publisher_key_hex"]
            and receipt["name"] == publication["name"] == "disposable-successor-training"
            and receipt["revision"] == publication["revision"] == 1
            and receipt["publication_expires_unix_seconds"] == publication["expires_unix_seconds"]
            and receipt["bytes"] == dataset["bytes"] and receipt["sha256"] == dataset["sha256"]
            and receipt["peer_bytes"] == receipt["providers_used"] == 0
            and receipt["provider_peer_ids"] == [] and receipt["control_relay_peer_id"] == ""
            and receipt["origin_authenticated"] is False
            and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0,
            "learner cache-only source differs or used network")


def local_source(work):
    JOBS["guest_work"](work)
    layout, learner, original = roots(work)
    require(layout["provider_nodes"][0] == "relay4", "static learner differs")
    roles_path = work / f"{PREFIX}-learner-roles.log"
    file_hash(roles_path, 128)
    roles = roles_path.read_text()
    publication = read(record(work, "publish"))
    expected = file_hash(original / "dataset.json", 1048576)
    require(file_hash(learner / "source-preflight.json", 1048576) == expected, "cached source bytes differ")
    check_local_source(roles, read(record(work, "local-source")), publication, expected)
    write(record(work, "learner-admission"), dict(node="relay4", roles_text=roles,
        source=expected, static_fixture_roles=True, learner_network_retrieval_claimed=False))


def training_owner_identity(pid, lookup=TRAIN["identity"]):
    try:
        return lookup(pid)
    except FileNotFoundError:
        raise ValueError("OWNER_EXITED_BEFORE_WORKER_OBSERVATION") from None


def cycle_diagnostic(learner):
    # Only fixed filenames, file identities and bounded state enums/counts leave
    # the private store. No source/model text, paths or arbitrary error chains.
    files = {}
    names = ("state.json", f"{CYCLE}/selection.json", f"{CYCLE}/source-provenance.json",
             f"{CYCLE}/dataset.json", f"{CYCLE}/dataset.manifest", f"{CYCLE}/training/report.json",
             f"{CYCLE}/training-report.json", f"{CYCLE}/evaluation.json", f"{CYCLE}/result.json")
    for name in names:
        try:
            files[name] = dict(present=True, **file_hash(learner / "loop" / name, 1048576))
        except FileNotFoundError:
            files[name] = dict(present=False)
        except (OSError, ValueError):
            files[name] = dict(present=None, observation="UNREADABLE_OR_INVALID_BOUNDED_FILE")
    summary = None
    if files["state.json"].get("present") is True:
        try:
            state = read(learner / "loop/state.json", 1048576)
            counts = {key: state[key] for key in ("next_sequence", "completed", "promoted", "rejected")}
            require(all(type(count) is int and 0 <= count <= 256 for count in counts.values()), "invalid cycle counts")
            cycles = state["cycles"]
            require(type(cycles) is list and len(cycles) <= 8, "invalid cycle count")
            phases = []
            for cycle in cycles:
                require(type(cycle["sequence"]) is int and 1 <= cycle["sequence"] <= 256
                        and cycle["phase"] in ("running", "failed", "evaluating", "rejected", "trained", "publish_pending",
                                               "publication_expired", "complete"),
                        "invalid cycle phase")
                phases.append(dict(sequence=cycle["sequence"], phase=cycle["phase"]))
            summary = dict(**counts, cycles=phases)
        except (OSError, ValueError, KeyError, TypeError):
            summary = dict(observation="UNREADABLE_OR_INVALID_BOUNDED_STATE")
    return dict(version=1, operation="successor_fixture_cycle_diagnostic", files=files, state=summary,
                exact_failure_cause_known=False, raw_error_or_source_text_exported=False)


def inode(path):
    value = path.stat()
    return [value.st_dev, value.st_ino]


def observe_training(work, owner_pid):
    JOBS["guest_work"](work)
    layout, learner, _ = roots(work)
    owner = training_owner_identity(owner_pid)
    write(record(work, "training-owner"), owner)
    for _ in range(1200):
        require(TRAIN["alive"](owner), "OWNER_EXITED_BEFORE_WORKER_OBSERVATION")
        for member in TRAIN["descendants"](owner_pid):
            process = Path(f"/proc/{member['pid']}")
            try:
                if (process / "cmdline").read_bytes().split(b"\0")[0] != b"/runtime/bin/python3":
                    continue
                mounted = process / "root"
                dataset = learner / "loop" / CYCLE / "dataset.json"
                require(inode(mounted / "dataset.json") == inode(dataset)
                        and inode(mounted / "runtime/pyvenv.cfg") == inode(learner / "runtime/pyvenv.cfg")
                        and inode(mounted / "model/model.safetensors") == inode(work / "agent-jobs-user/provision/model/model.safetensors"),
                        "training did not mount selected source/runtime/model")
                devices = [line.split(":", 1)[0].strip() for line in (process / "net/dev").read_text().splitlines()[2:]]
                require(devices == ["lo"] and len((process / "net/route").read_text().splitlines()) == 1,
                        "training worker has network access")
                mounts = {parts[4]: parts[5].split(",") for line in (process / "mountinfo").read_text().splitlines()
                          if len(parts := line.split()) > 5 and parts[4] in ("/dataset.json", "/model", "/runtime", "/output")}
                require(all("ro" in mounts.get(p, []) for p in ("/dataset.json", "/model", "/runtime"))
                        and "rw" in mounts.get("/output", []), "training mount isolation differs")
                status = dict(line.split(":", 1) for line in (process / "status").read_text().splitlines() if ":" in line)
                require(int(status["CapEff"], 16) == 0, "training worker retained capabilities")
                write(record(work, "training-observation"), dict(worker=member, owner=owner,
                    owned_processes=TRAIN["descendants"](owner_pid),
                    node=layout["provider_nodes"][0], dataset_file=file_hash(dataset, 1048576),
                    runtime_lock_inode=lock_observation(learner / "runtime/.volparossa-compute.lock"),
                    exact_input_inodes=True, network_devices=devices, ipv4_routes=[], mounts=mounts,
                    effective_capabilities=0, observed_unix_seconds=int(time.time())))
                return
            except FileNotFoundError:
                continue
        time.sleep(0.05)
    raise ValueError("actual training worker not observed")


def observe_job(work, label):
    JOBS["guest_work"](work)
    require(label in ("base", "adapted"), "wrong inference label")
    layout, learner, _ = roots(work)
    node = layout["provider_nodes"][0]
    broker = TRAIN["identity"](JOBS["broker_pid"](node))
    dataset = read(work / "agent-jobs-source.json")["dataset"]
    expected = sha(JOBS["derive"](dataset, [0]).encode())
    for _ in range(1200):
        observed = JOBS["worker_snapshot"](work, node, broker, expected_dataset_sha256=expected)
        if observed is not None:
            process = Path(f"/proc/{observed['worker']['pid']}")
            mounted = process / "root/adapter"
            observed["adapter_files"] = None
            if label == "base":
                require(not mounted.exists(), "base job unexpectedly mounted an adapter")
            else:
                selected = read(record(work, "loop"))["current"]
                candidates = [p for p in (learner / "work").iterdir() if p.is_dir()
                              and all((p / name).is_file() for name in FILES)]
                require(len(candidates) == 1, "expected one broker-owned selected copy")
                copied = candidates[0]
                mounts = [line.split() for line in (process / "mountinfo").read_text().splitlines()]
                require(any(parts[4] == "/adapter" and "ro" in parts[5].split(",") for parts in mounts),
                        "adapter mount is not readonly")
                observed["adapter_files"] = {name: file_hash(mounted / name, 2 * 1024 * 1024) for name in FILES}
                require(observed["adapter_files"] == selected["adapter_files"], "worker weights differ from approval")
                observed["adapter_mount_inodes"] = {name: inode(mounted / name) for name in FILES}
                observed["broker_copy_inodes"] = {name: inode(copied / name) for name in FILES}
                observed["trained_adapter_inodes"] = {name: inode(learner / "loop" / CYCLE / "training/adapter" / name) for name in FILES}
                require(observed["adapter_mount_inodes"] == observed["broker_copy_inodes"]
                        and all(observed["adapter_mount_inodes"][name] != observed["trained_adapter_inodes"][name] for name in FILES),
                        "worker did not use its broker-owned copy")
            observed["observed_unix_seconds"] = int(time.time())
            write(record(work, f"{label}-observation"), observed)
            return
        time.sleep(0.05)
    raise ValueError("actual broker worker not observed")


def capture_loop(work):
    JOBS["guest_work"](work)
    _, learner, original = roots(work)
    cycle = learner / "loop" / CYCLE
    state = read(learner / "loop/state.json")
    require(state["latest"] == state["promoted"] == state["completed"] == 1 and state["rejected"] == 0,
            "actual local successor was not approved")
    current = read(learner / "serving/current.json")
    files = {str(p.relative_to(cycle)): file_hash(p, 4 * 1024 * 1024)
             for p in cycle.rglob("*") if p.is_file()}
    names = ("selection.json", "evaluation.json", "result.json", "source-provenance.json", "training-report.json")
    value = dict(state=state, enrollment=read(learner / "loop/enrollment.json"),
        current=current, current_hex=(learner / "serving/current.json").read_bytes().hex(),
        runtime_inode=inode(learner / "runtime"), files=files,
        records={name: (cycle / name).read_text() for name in names},
        dataset_json=(cycle / "dataset.json").read_text(), manifest_hex=(cycle / "dataset.manifest").read_bytes().hex(),
        original_dataset_json=(original / "dataset.json").read_text(),
        original_manifest_hex=(original / "manifest.pb").read_bytes().hex(),
        cache_provision=read(learner / "source-cache-provision.json"))
    write(record(work, "loop"), value)


def capability_ready(caps, adapter, allow_pending_base=False):
    expected = dict(model_id="HuggingFaceTB/SmolLM2-135M-Instruct", model_revision=TRAIN["MODEL_REVISION"],
                    base_weights=dict(bytes=269060552, sha256=TRAIN["WEIGHT_HASH"]), adapter_files=adapter)
    base = dict(expected, adapter_files=None)
    require(type(caps["accepting_work"]) is bool and caps.get("successor_activation_v1") is True
            and caps["public_inference_only"] is True and caps["runtime_slots"] == 1
            and caps["max_threads"] == 2 and caps["max_dataset_bytes"] == 1048576 and caps["max_rows"] == 4
            and type(caps["max_job_seconds"]) is int and 1 <= caps["max_job_seconds"] <= 600
            and all(caps.get(name) is True for name in ("task_derivation_v1", "document_inference_v2", "derived_inference_v3")),
            "unexpected successor broker capability contract")
    # An idle broker may still expose the pinned base while waiting to activate
    # the approved copy. A different base or unselected adapter is never ready.
    require(caps["model"] == expected or (allow_pending_base and caps["model"] == base),
            "capabilities selected an unexpected model")
    selected = expected if caps["model"] == expected else base
    ordered = dict(selected)
    if selected["adapter_files"] is not None:
        ordered["adapter_files"] = {name: dict(bytes=selected["adapter_files"][name]["bytes"],
            sha256=selected["adapter_files"][name]["sha256"]) for name in sorted(selected["adapter_files"])}
    require(caps["model_fingerprint"] == sha(json.dumps(ordered, separators=(",", ":")).encode()),
            "readiness model fingerprint differs from exact weights")
    return caps["accepting_work"] and caps["model"] == expected


def ready(work, label):
    JOBS["guest_work"](work)
    require(label in ("base", "adapted", "invalid"), "unknown successor readiness phase")
    name = {"base": "base-caps", "adapted": "active-caps", "invalid": "invalid-caps"}[label]
    adapter = None if label == "base" else read(record(work, "loop"))["current"]["adapter_files"]
    print("true" if capability_ready(read(record(work, name)), adapter, label == "adapted") else "false")


def cleanup_flag(value):
    require(value in ("true", "false"), "invalid runner cleanup boolean")
    return value == "true"


def invalidate(work):
    JOBS["guest_work"](work)
    _, learner, _ = roots(work)
    path = learner / "serving/current.json"
    original = path.read_bytes()
    changed = json.loads(original)
    require(changed["provenance"]["approved"] is True, "approved pointer missing")
    changed["provenance"]["approved"] = False
    # Explicit negative metadata fault, never represented as a model evaluation result.
    temporary = path.with_name("fixture-invalid.json")
    write(temporary, changed)
    owner = learner.stat()
    os.chown(temporary, owner.st_uid, owner.st_gid)
    os.replace(temporary, path)
    write(learner / "invalid-control.json", dict(kind="injected-unapproved-current-metadata",
        original=digest(original), injected=digest(path.read_bytes()), approved=False,
        original_expiry=changed["expires_unix_seconds"], model_quality_rejection_claimed=False,
        injected_unix_seconds=int(time.time())))


def cleanup_workers(work):
    JOBS["guest_work"](work)
    ended = record(work, "process-cleanup")
    if ended.exists():
        return
    processes = []
    for label in ("training", "base", "adapted"):
        path = record(work, f"{label}-observation")
        if path.exists():
            processes.extend(read(path)["owned_processes"])
    owner = record(work, "training-owner")
    if owner.exists():
        processes.append(read(owner))
    require(not any(TRAIN["alive"](process) for process in processes),
            "owned training/inference process still alive before private-store cleanup")
    diagnostic = record(work, "cycle-diagnostic")
    # Early provisioning failures have no selected learner or loop to inspect.
    if not diagnostic.exists() and (work / "agent-jobs-layout.json").exists():
        _, learner, _ = roots(work)
        write(diagnostic, cycle_diagnostic(learner))
    write(ended, dict(owned_processes=processes, all_recorded_processes_ended=True,
                     checked_before_private_store_removal=True))


def capture(work):
    JOBS["guest_work"](work)
    _, learner, _ = roots(work)
    write(record(work, "handles"), {label: read(work / f"state-client/compute-source/successor-{label}.json")
                                    for label in ("base", "adapted")})
    write(record(work, "invalid-control"), read(learner / "invalid-control.json"))
    processes = [read(record(work, f"{label}-observation"))["worker"] for label in ("base", "adapted")]
    processes.append(read(record(work, "training-observation"))["worker"])
    require(not any(TRAIN["alive"](process) for process in processes), "completed worker still alive")
    write(record(work, "workers-reaped"), dict(workers=processes, all_original_workers_ended=True))


def check_transition(value):
    before, after, invalid = (value[name] for name in ("base-caps", "active-caps", "invalid-caps"))
    current = value["loop"]["current"]
    require(before["successor_activation_v1"] is True and before["accepting_work"] is True
            and before["model"]["adapter_files"] is None
            and after["successor_activation_v1"] is True and after["accepting_work"] is True
            and after["model"]["adapter_files"] == current["adapter_files"]
            and before["model_fingerprint"] != after["model_fingerprint"], "no actual base-to-selected model transition")
    for caps in (before, after, invalid):
        model = caps["model"]
        # Rust ModelIdentity field order is fixed; map of adapter files is BTreeMap.
        ordered = dict(model_id=model["model_id"], model_revision=model["model_revision"],
                       base_weights=model["base_weights"], adapter_files=model["adapter_files"])
        if ordered["adapter_files"] is not None:
            ordered["adapter_files"] = {name: dict(bytes=ordered["adapter_files"][name]["bytes"],
                sha256=ordered["adapter_files"][name]["sha256"]) for name in sorted(ordered["adapter_files"])}
        ordered["base_weights"] = dict(bytes=model["base_weights"]["bytes"], sha256=model["base_weights"]["sha256"])
        require(caps["model_fingerprint"] == sha(json.dumps(ordered, separators=(",", ":")).encode()), "model fingerprint is not exact file identity")
    require(invalid["model_fingerprint"] == after["model_fingerprint"] and invalid["model"] == after["model"]
            and invalid["accepting_work"] is True, "invalid candidate replaced the valid unexpired selection")
    control = value["invalid-control"]
    require(control["kind"] == "injected-unapproved-current-metadata" and control["approved"] is False
            and control["model_quality_rejection_claimed"] is False and control["original"] != control["injected"]
            and control["original_expiry"] == current["expires_unix_seconds"] > control["injected_unix_seconds"],
            "negative metadata control differs")
    require(value["base-status"] == value["base-retained"] and value["base-status"]["state"] == "complete",
            "original base-model receipt was changed by activation")


def check_evidence(value, revision):
    require(value["source_revision"] == revision, "wrong source revision")
    check_transition(value)
    loop, publication = value["loop"], value["publish"]
    records = {name: json.loads(raw) for name, raw in loop["records"].items()}
    evaluation, training = records["evaluation.json"], records["training-report.json"]
    TRAIN["check_worker"](training, revision)
    require(evaluation["approved"] is True and evaluation["policy"] == "source-heldout-loss-v1"
            and evaluation["baseline_kind"] == "pinned_base" and evaluation["predecessor"] is None
            and evaluation["adapted"]["loss"] + evaluation["epsilon"] < evaluation["baseline"]["loss"],
            "real heldout successor approval missing")
    require(evaluation["candidate_adapter"] == loop["current"]["adapter_files"]
            and training["adapter_after"] == evaluation["candidate_parameters"], "selected trained weights differ")
    for name, raw in loop["records"].items():
        require(digest(raw.encode()) == loop["files"][name], "retained exact local decision bytes differ")
    for name, identity in evaluation["files"].items():
        require(loop["files"][name] == identity, "evaluation changed an original training artifact")
    for name in FILES:
        require(loop["files"][f"training/adapter/{name}"] == evaluation["candidate_adapter"][name], "trained adapter files differ")
    raw, signed = loop["dataset_json"].encode(), bytes.fromhex(loop["manifest_hex"])
    require(loop["dataset_json"] == loop["original_dataset_json"] and loop["manifest_hex"] == loop["original_manifest_hex"],
            "loop changed original public source authority")
    envelope = CUSTODY["fields"](signed, 65536)
    body = CUSTODY["fields"](envelope[1], 65536)
    payload = CUSTODY["fields"](body[8], 65536)
    require(body[1] == body[6] == 1 and body[2].hex() == publication["publisher_key_hex"]
            and body[4] - body[3] == 7200 and body[7].hex() == sha(body[8])
            and sha(signed) == publication["manifest_id"] == evaluation["source_manifest_id"]
            and payload[1] == b"disposable-successor-training" and payload[2] == 1
            and payload[3].decode() == ART["DATASET_TYPE"] and payload[4] == len(raw)
            and payload[6].hex() == sha(raw), "original signed training source differs")
    COLLECTION["verify_signature"](envelope[1], envelope[2], body[2], b"VOLPAROSSA/native-content-manifest/v1\0")
    current = loop["current"]
    require(json.loads(bytes.fromhex(loop["current_hex"])) == current and current["provenance"]["kind"] == "approved_local_successor"
            and current["provenance"]["evaluation_sha256"] == loop["files"]["evaluation.json"]["sha256"]
            and current["provenance"]["approved"] is True
            and current["expires_unix_seconds"] == body[4] == records["result.json"]["source_expires_unix_seconds"]
            and [current["owner"]["runtime_device"], current["owner"]["runtime_inode"]] == loop["runtime_inode"],
            "loop serving authorization or original expiry differs")
    require(current["owner"]["runtime"] == loop["enrollment"]["runtime_root"]
            and current["provenance"]["source_manifest_id"] == publication["manifest_id"]
            and current["provenance"]["source_publisher_key"] == publication["publisher_key_hex"]
            and current["provenance"]["adapter_files"] == current["adapter_files"]
            and current["provenance"]["general_quality_proven"] is False
            and current["provenance"]["network_authority_claimed"] is False,
            "serving provenance does not bind original trained source/runtime")
    state = loop["state"]
    require(state["latest"] == state["completed"] == state["promoted"] == 1 and state["rejected"] == 0
            and len(state["cycles"]) == 1 and state["cycles"][0]["phase"] == "complete", "selected durable loop state differs")
    cache = loop["cache_provision"]
    require(cache["explicit_fixture_copy"] is True and cache["learner_network_retrieval_claimed"] is False
            and cache["source_cache_files"] == cache["copied_cache_files"] and cache["dataset"] == digest(raw)
            and cache["manifest_id"] == publication["manifest_id"] and cache["original_expiry"] == body[4]
            and records["source-provenance.json"]["source_receipt"]["peer_bytes"] == 0,
            "explicit original cached-source provisioning differs")
    layout = value["layout"]
    learner = layout["provider_nodes"][0]
    admission = value["learner-admission"]
    require(learner == admission["node"] == "relay4" and admission["static_fixture_roles"] is True
            and admission["learner_network_retrieval_claimed"] is False and admission["source"] == digest(raw),
            "static learner admission proof differs")
    check_local_source(admission["roles_text"], value["local-source"], publication, digest(raw))
    require(publication["publisher_key_hex"] == layout["provider_keys"][layout["provider_nodes"][1]], "training source publisher differs")
    fetched = value["source-fetch"]
    require(fetched["operation"] == "named_content_download" and fetched["manifest_id"] == publication["manifest_id"]
            and fetched["publisher_key"] == publication["publisher_key_hex"] and fetched["sha256"] == sha(raw)
            and fetched["bytes"] == fetched["peer_bytes"] == len(raw) and fetched["origin_body_bytes"] == 0
            and fetched["publication_expires_unix_seconds"] == body[4]
            and fetched["providers_used"] == 1
            and fetched["provider_peer_ids"] == [value["peers"][layout["provider_nodes"][1]]],
            "fixture source cache did not contain the original protected public download")
    original = value["source"]
    job_manifest = JOBS["source_manifest_id"](original, value["job-publish"])
    observations = [value[f"{label}-observation"] for label in ("base", "adapted")]
    runtime_lock = value["training-observation"]["runtime_lock_inode"]
    require(len({observation["broker"]["pid"] for observation in observations}) == 1
            and all(observation["runtime_lock_inode"] == runtime_lock for observation in observations)
            and value["training-observation"]["dataset_file"] == digest(raw), "runtime ownership was not shared")
    for label, observation in zip(("base", "adapted"), observations):
        handle, receipt = value["handles"][label], value[f"{label}-status"]
        binding, caps = handle["binding"], handle["capabilities"]
        model = caps["model"]
        require(model["model_id"] == training["model"]["id"]
                and model["model_revision"] == training["model"]["revision"]
                and model["base_weights"] == training["model"]["files"]["model.safetensors"]
                and caps["runtime_slots"] == 1 and caps["max_threads"] == 2
                and caps["public_inference_only"] is True,
                "peer capability did not retain exact training base and bounded execution profile")
        require(receipt["state"] == "complete" and receipt["binding"] == binding
                and handle["provider_key"] == layout["provider_keys"][learner]
                and binding["row_indices"] == [0] and binding["dataset_manifest_id"] == job_manifest
                and binding["model_fingerprint"] == caps["model_fingerprint"] == value[f"{'active' if label == 'adapted' else 'base'}-caps"]["model_fingerprint"],
                "peer inference was not bound to the exact selected model/source")
        derived = JOBS["derive"](original["dataset"], [0])
        require(observation["dataset_json"] == derived and binding["dataset_sha256"] == sha(derived.encode()), "observed peer input differs")
        require(receipt["report_sha256"] == sha(receipt["report_json"].encode()), "peer report changed")
        report = json.loads(receipt["report_json"])
        require(report["status"] == "ok" and report["mode"] == "infer" and report["updates_completed"] == 0
                and report["dataset"]["sha256"] == binding["dataset_sha256"]
                and report["dataset"]["source_revision"] == revision and report["dataset"]["visibility"] == "public"
                and report["dataset"]["license"] == "GPL-3.0-only" and report["device"] == "cpu" and report["threads"] == 2
                and report["model"]["id"] == model["model_id"] and report["model"]["revision"] == model["model_revision"]
                and report["model"]["files"]["model.safetensors"] == model["base_weights"]
                and report["supervisor"]["child_reaped"] is True and report["supervisor"]["network_access"] is False
                and report["supervisor"]["gpu_access"] is False
                and 0 < report["supervisor"]["max_observed_rss_bytes"] <= report["supervisor"]["rss_limit_bytes"],
                "actual isolated source-bound peer inference missing")
        if label == "adapted":
            require(report["input_adapter"]["applied"] is True and report["input_adapter"]["files"] == current["adapter_files"]
                    and report["input_adapter"]["applied_parameters"] == training["adapter_after"]
                    and observation["adapter_files"] == current["adapter_files"]
                    and observation["adapter_mount_inodes"] == observation["broker_copy_inodes"]
                    and all(observation["adapter_mount_inodes"][name] != observation["trained_adapter_inodes"][name] for name in FILES)
                    and binding["expires_unix_seconds"] <= body[4], "peer worker did not actually reuse selected copied weights")
        else:
            require("input_adapter" not in report and observation["adapter_files"] is None, "original job was not base-only")
    require(value["workers-reaped"]["all_original_workers_ended"] is True and all(value["cleanup"].values()), "owned workers/private stores remain")
    require(value["process-cleanup"]["all_recorded_processes_ended"] is True
            and value["process-cleanup"]["checked_before_private_store_removal"] is True,
            "owned process tree cleanup not confirmed before deleting private stores")
    CUSTODY["validate_path"](value["path"], value["peers"], layout, "inspect")
    application = value["path"]["privacy"]["exit"]["provider_application"][learner]
    require(application["request_packets"] > 0 and application["response_payload_bytes"] >= sum(
        len(value[f"{label}-status"]["report_json"].encode()) for label in ("base", "adapted")), "peer reports did not traverse protected provider path")


def evidence(work, revision):
    JOBS["guest_work"](work)
    names = ("base-caps", "active-caps", "invalid-caps", "base-status", "adapted-status", "base-retained", "loop",
             "publish", "source-fetch", "invalid-control", "handles", "base-observation", "adapted-observation",
             "training-observation", "workers-reaped", "process-cleanup", "learner-admission", "local-source")
    value = {name: read(record(work, name), 4 * 1024 * 1024) for name in names}
    value.update(source_revision=revision, layout=read(work / "agent-jobs-layout.json"),
        source=read(work / "agent-jobs-source.json"), **{"job-publish": read(work / "agent-jobs-publish.json")},
        peers=read(work / "a01-expected-peers.json"), cleanup=read(work / "agent-jobs-private-cleanup.json"),
        path=dict(selected_route=read(work / "content-custody-fetch-live-selection.json"),
            privacy={role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
            control_privacy=read(work / "content-provider-custody-fetch-control.json"), gates=read(work / "content-custody-fetch-gates.json")))
    check_evidence(value, revision)
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    proof = read(record(work, "evidence"), 8 * 1024 * 1024) if record(work, "evidence").is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(record(work, "smoke"), dict(report_kind=KIND, scope=SCOPE, source_revision=revision,
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and proof is not None,
        runner_exit_status=status, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        evidence=proof, cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host,
        model_quality_proven=False, learner_network_acquisition_claimed=False, expiry_restart_proof_claimed=False,
        full_b05_claimed=False, full_alpha_claimed=False))


def report(value, revision):
    require(value["report_kind"] == KIND and value["scope"] == SCOPE and value["source_revision"] == revision
            and value["success"] is True and value["runner_exit_status"] == 0, "learning-serving proof incomplete")
    require(value["cleanup"] == dict(complete=True, remaining_owned_objects=0) and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "guest cleanup differs")
    require(all(value[key] is False for key in ("model_quality_proven", "learner_network_acquisition_claimed",
        "expiry_restart_proof_claimed", "full_b05_claimed", "full_alpha_claimed")), "proof scope overstated")
    check_evidence(value["evidence"], revision)


def self_test():
    # Inert contract controls only: these are never accepted as real model/VM evidence.
    roles = "client: true\nrelay: true\nexit: false\n"
    publication = dict(manifest_id="a" * 64, publisher_key_hex="b" * 64,
                       name="disposable-successor-training", revision=1, expires_unix_seconds=200)
    dataset = digest(b"Explicit public inert test data.")
    receipt = dict(operation="named_content_download", cache_only=True, local_delivery=True,
        manifest_id=publication["manifest_id"], publisher_key=publication["publisher_key_hex"],
        name=publication["name"], revision=1, publication_expires_unix_seconds=200, **dataset,
        peer_bytes=0, providers_used=0, provider_peer_ids=[], control_relay_peer_id="",
        origin_authenticated=False, origin_body_bytes=0, origin_range_requests=0)
    check_local_source(roles, receipt, publication, dataset)
    for change in (dict(cache_only=False), dict(peer_bytes=1), dict(peer_bytes=False), dict(providers_used=1),
                   dict(manifest_id="c" * 64), dict(sha256="d" * 64), dict(publication_expires_unix_seconds=201),
                   dict(publisher_key="e" * 64), dict(origin_body_bytes=1)):
        try:
            check_local_source(roles, dict(receipt, **change), publication, dataset)
        except ValueError:
            continue
        raise AssertionError("incorrect learner cache-only proof accepted")
    try:
        check_local_source(roles.replace("client: true", "client: false"), receipt, publication, dataset)
    except ValueError:
        pass
    else:
        raise AssertionError("relay-only learner accepted")
    assert training_owner_identity(123, lambda pid: dict(pid=pid, start_ticks=456)) == dict(pid=123, start_ticks=456)
    def missing_owner(_pid):
        raise FileNotFoundError("unretained private process path")
    try:
        training_owner_identity(123, missing_owner)
    except ValueError as error:
        assert str(error) == "OWNER_EXITED_BEFORE_WORKER_OBSERVATION"
    else:
        raise AssertionError("missing owner identity accepted")
    with tempfile.TemporaryDirectory(prefix="volparossa-successor-inert-") as directory:
        learner = Path(directory)
        assert all(item == dict(present=False) for item in cycle_diagnostic(learner)["files"].values())
        (learner / "loop" / CYCLE).mkdir(parents=True)
        write(learner / "loop/state.json", dict(next_sequence=2, completed=0, promoted=0, rejected=0,
              cycles=[dict(sequence=1, phase="failed")], private_unexported="Do not export this value"))
        write(learner / "loop" / CYCLE / "selection.json", dict(private_unexported="Do not export this value"))
        diagnostic = cycle_diagnostic(learner)
        assert diagnostic["state"]["cycles"] == [dict(sequence=1, phase="failed")]
        assert diagnostic["files"][f"{CYCLE}/selection.json"]["present"] is True
        assert diagnostic["exact_failure_cause_known"] is False
        assert "Do not export" not in json.dumps(diagnostic)
    model = dict(model_id="HuggingFaceTB/SmolLM2-135M-Instruct", model_revision=TRAIN["MODEL_REVISION"],
                 base_weights=dict(bytes=269060552, sha256=TRAIN["WEIGHT_HASH"]), adapter_files=None)
    adapter = {name: dict(bytes=1, sha256="b" * 64) for name in FILES}
    def caps(files):
        selected = dict(model, adapter_files=files)
        return dict(model=selected, model_fingerprint=sha(json.dumps(selected, separators=(",", ":")).encode()),
                    successor_activation_v1=True, accepting_work=True, public_inference_only=True,
                    runtime_slots=1, max_threads=2, max_job_seconds=600, max_dataset_bytes=1048576, max_rows=4,
                    task_derivation_v1=True, document_inference_v2=True, derived_inference_v3=True)
    assert capability_ready(caps(None), None)
    assert not capability_ready(dict(caps(None), accepting_work=False), None)
    assert not capability_ready(caps(None), adapter, allow_pending_base=True)
    assert capability_ready(caps(adapter), adapter)
    assert not capability_ready(dict(caps(adapter), accepting_work=False), adapter)
    try:
        capability_ready(caps(None), adapter)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid candidate caused a ready base fallback")
    for change in (dict(successor_activation_v1=False), dict(accepting_work="true"),
                   dict(model_fingerprint="f" * 64), dict(max_job_seconds=601),
                   dict(model=dict(model, model_revision="wrong")), dict(model=dict(model, adapter_files=adapter))):
        invalid = dict(caps(None), **change)
        try:
            capability_ready(invalid, None)
        except ValueError:
            continue
        raise AssertionError("invalid ready capability accepted")
    assert cleanup_flag("true") is True and cleanup_flag("false") is False
    for invalid in ("yes", "no", "", "True", "1"):
        try:
            cleanup_flag(invalid)
        except ValueError:
            continue
        raise AssertionError("invalid cleanup boolean accepted")
    selected = caps(adapter)
    fixture = {"base-caps": caps(None), "active-caps": selected, "invalid-caps": copy.deepcopy(selected),
        "loop": dict(current=dict(adapter_files=adapter, expires_unix_seconds=200)),
        "invalid-control": dict(kind="injected-unapproved-current-metadata", approved=False,
            original=dict(bytes=2, sha256="a" * 64), injected=dict(bytes=3, sha256="b" * 64),
            original_expiry=200, injected_unix_seconds=100, model_quality_rejection_claimed=False),
        "base-status": dict(state="complete", binding=dict(model_fingerprint="a" * 64)),
        "base-retained": dict(state="complete", binding=dict(model_fingerprint="a" * 64))}
    check_transition(fixture)
    mutations = (("active-caps", "model_fingerprint", fixture["base-caps"]["model_fingerprint"]),
                 ("invalid-caps", "model_fingerprint", "f" * 64), ("invalid-caps", "accepting_work", False),
                 ("base-retained", "state", "running"), ("invalid-control", "original_expiry", 201),
                 ("invalid-control", "model_quality_rejection_claimed", True),
                 ("invalid-control", "injected_unix_seconds", 200), ("active-caps", "successor_activation_v1", False),
                 ("base-caps", "accepting_work", False))
    for group, key, value in mutations:
        bad = copy.deepcopy(fixture)
        bad[group][key] = value
        try:
            check_transition(bad)
        except ValueError:
            continue
        raise AssertionError("invalid transition contract accepted")
    print("learning-serving static roles/cache-only, bounded diagnostics, readiness and transition controls passed; no model or network executed")


def main():
    command, *args = sys.argv[1:]
    if command == "self-test": self_test()
    elif command == "source": source(Path(args[0]), args[1])
    elif command == "seed": seed(Path(args[0]))
    elif command == "local-source": local_source(Path(args[0]))
    elif command == "observe-job": observe_job(Path(args[0]), args[1])
    elif command == "observe-training": observe_training(Path(args[0]), int(args[1]))
    elif command == "capture-loop": capture_loop(Path(args[0]))
    elif command == "ready": ready(Path(args[0]), args[1])
    elif command == "invalidate": invalidate(Path(args[0]))
    elif command == "capture": capture(Path(args[0]))
    elif command == "cleanup-workers": cleanup_workers(Path(args[0]))
    elif command == "evidence": evidence(Path(args[0]), args[1])
    elif command == "finalize": finalize(Path(args[0]), args[1], int(args[2]), cleanup_flag(args[3]), int(args[4]), args[5], args[6])
    elif command == "report": report(read(Path(args[0]), 8 * 1024 * 1024), args[1])
    else: raise ValueError("unknown fixture command")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(f"SUCCESSOR_SERVING_FIXTURE_INVALID: {error}", file=sys.stderr)
        sys.exit(1)
