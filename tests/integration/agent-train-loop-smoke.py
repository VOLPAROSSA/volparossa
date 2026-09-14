#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable real public seed -> two autonomous cycles -> another peer import.

Pure checker fixtures are not training/network evidence. Model execution is guest-only.
"""

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ART = runpy.run_path(str(HERE / "agent-artifact-smoke.py"))
REP = runpy.run_path(str(HERE / "content-replication-smoke.py"))
TRAIN = ART["TRAIN"]
read, write, require, file_hash = (ART[key] for key in ("read", "write", "require", "file_hash"))
FILES = ("README.md", "adapter_config.json", "adapter_model.safetensors")
CONTENT_FILES = ("selection.json", "dataset.json", "dataset.manifest", "source-provenance.json",
                 "training-report.json", "result.json", "adapter.bundle", "training/report.json",
                 *("training/adapter/" + name for name in FILES))
VALIDATION_FILES = ("validation/dataset.json", "validation/dataset.manifest", "validation/provenance.json",
                    "validation/baseline/report.json", "validation/candidate/report.json", "baseline-report.json",
                    "candidate-report.json", "validation.json")
POLICY = "source-and-second-source-loss-v1"
SCOPE = ("R5 publishes a public training dataset/seed and a separately named, pinned validation-only public dataset; "
         "R4 retrieves all three over protected MPTCP and runs two owner-enabled eight-update cycles on the explicitly "
         "repeated training source. Each cycle also runs real sequential predecessor/candidate inference on exactly the "
         "same second-source bytes. Only candidates improving both measured heldout losses by more than 1e-6 replace "
         "the predecessor and are automatically contributed. Cycle two uses the latest approved adapter "
         "or the original seed. When an update is approved, Main Client imports the latest approved update and original "
         "separately signed dataset through protected MPTCP and performs inference; otherwise no new adapter is adopted "
         "or imported. Current normalized training-question overlap is rejected; shared explicitly provisioned "
         "base/runtime and a repeatedly used second-source selection set, not an independent benchmark, historical "
         "decontamination, general quality improvement, fresh corpus discovery, joint optimization, full B05 or full alpha")


def setup(path, publisher, manifest):
    root = ART["private_root"](path)
    require(TRAIN["HASH"].fullmatch(publisher) and TRAIN["HASH"].fullmatch(manifest), "invalid selected source")
    write(root / "loop-plan.json", {"version": 1, "sources": [{"publisher_key": publisher,
          "name": "disposable-agent-dataset", "min_revision": 1, "manifest_id": manifest}]})
    write(root / "loop-seed.json", {"publisher_key": publisher, "dataset_publisher_key": publisher,
          "name": "disposable-agent-adapter", "dataset_name": "disposable-agent-dataset", "min_revision": 1})
    (root / "loop-passphrase").write_bytes(os.urandom(32).hex().encode() + b"\n")
    (root / "loop-passphrase").chmod(0o600)


def validation_input(path, revision):
    root = ART["private_root"](path)
    require(len(revision) == 40 and all(char in "0123456789abcdef" for char in revision), "invalid validation revision")
    context = "VOLPAROSSA is an open-source, decentralised user-operated network being built for Debian 13 amd64."
    require(context in (HERE / "agent-artifact-README.md").read_text(), "public validation source changed")
    dataset = dict(version=1, visibility="public", license="GPL-3.0-only", source_revision=revision, train=[],
        heldout=[dict(question="Which operating system and architecture is VOLPAROSSA being built for?",
                      context=context, answer="Debian 13 amd64.")],
        inference=[dict(question="What sort of network is VOLPAROSSA?", context=context)])
    write(root / "validation-dataset.json", dataset)


def validation_original(path, publisher):
    root = ART["private_root"](path)
    require(TRAIN["HASH"].fullmatch(publisher), "invalid validation publisher")
    dataset = (root / "validation-dataset.json").read_bytes()
    manifest = (root / "validation.pb").read_bytes()
    require(0 < len(dataset) <= 1048576 and 0 < len(manifest) <= 65536, "invalid validation source bound")
    selection = dict(publisher_key=publisher, name="disposable-agent-validation", min_revision=1,
                     manifest_id=file_digest(manifest)["sha256"])
    write(root / "loop-validation-source.json", selection)
    return dict(selection=selection, dataset=file_digest(dataset), manifest=file_digest(manifest),
                dataset_hex=dataset.hex(), manifest_hex=manifest.hex())


def drop_validation(path):
    root = ART["private_root"](path)
    for name in ("validation-dataset.json", "validation.pb", "validation-cache"):
        target = root / name
        info = target.lstat()
        require(info.st_uid == os.getuid() and not stat.S_ISLNK(info.st_mode), "owned validation source changed")
        if name == "validation-cache":
            require(stat.S_ISDIR(info.st_mode), "validation cache is not the owned directory")
            shutil.rmtree(target)
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "validation input is not an owned regular file")
            target.unlink()
    return dict(validation_source_bytes_removed=True, validation_manifest_original_removed=True,
                validation_publisher_cache_removed=True, selected_public_source_metadata_retained=True)


def readiness_state(root, sequence):
    path = root / "loop/state.json"
    if not path.exists():
        return {"stage": "state_absent", "seed_ready": False, "cycles": []}
    state = read(path)
    require(state["version"] == 2 and isinstance(state["cycles"], list) and len(state["cycles"]) <= 8,
            "invalid durable coordinator readiness state")
    cycles = [{"sequence": row["sequence"], "phase": row["phase"]} for row in state["cycles"]]
    current = next((row for row in cycles if row["sequence"] == sequence), None)
    stage = (current["phase"] if current else "seed_wait" if state["seed"] is None else
             "validation_wait" if state.get("validation") is None else "admission_wait")
    return {"stage": stage, "seed_ready": state["seed"] is not None,
            "validation_ready": state.get("validation") is not None,
            "cycles": cycles, "next_sequence": state["next_sequence"], "completed": state["completed"]}


def bounded_text(path, maximum=16384):
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        return data.decode("ascii") if len(data) <= maximum else None
    except (OSError, UnicodeError):
        return None


def resource_mounts(text):
    if text is None:
        return None
    result = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[4] not in ("/proc", "/sys", "/sys/fs/cgroup"):
            continue
        try:
            separator = fields.index("-")
            require(separator >= 6 and len(fields) >= separator + 4, "invalid observed resource mount")
            result.append({"mount_id": fields[0], "parent_id": fields[1], "root": fields[3],
                           "mountpoint": fields[4], "options": fields[5].split(","),
                           "filesystem": fields[separator + 1]})
        except ValueError:
            return None
    return result if len(result) <= 12 else None


def capacity_diagnostic(pid, read_text=bounded_text):
    process = Path(f"/proc/{pid}")
    view = process / "root"
    def pressure(kind):
        text = read_text(view / "proc/pressure" / kind, 512)
        try:
            some = next(line for line in text.splitlines() if line.startswith("some "))
            value = float(dict(item.split("=", 1) for item in some.split()[1:])["avg10"])
            return value if 0 <= value <= 100 else None
        except (AttributeError, StopIteration, ValueError, KeyError):
            return None
    memory = read_text(view / "proc/meminfo", 16384)
    available = None
    if memory is not None:
        for line in memory.splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[0] == "MemAvailable:" and fields[1].isdigit() and fields[2] == "kB":
                available = int(fields[1]) * 1024
    # Read membership of this exact process, not /proc/self through its root:
    # the latter would resolve to the observer rather than the coordinator.
    membership = read_text(process / "cgroup", 16384)
    cgroup = None
    if membership is not None:
        matches = [line[3:] for line in membership.splitlines() if line.startswith("0::")]
        if len(matches) == 1 and matches[0].startswith("/") and ".." not in Path(matches[0]).parts:
            relative = Path(matches[0].lstrip("/"))
            ancestors = []
            for _ in range(64):
                directory = view / "sys/fs/cgroup" / relative
                ancestors.append({"path": "/" + str(relative).removeprefix("."),
                                  **{name: read_text(directory / name, 4096) for name in
                                     ("memory.current", "memory.max", "cgroup.controllers", "cgroup.subtree_control")}})
                if relative == Path("."):
                    break
                relative = relative.parent
            cgroup = {"membership": matches[0], "ancestors": ancestors}
    mounts = resource_mounts(read_text(process / "mountinfo", 65536))
    return {"view": "coordinator_proc_root", "observed_pid": pid,
            "cpu_some_avg10": pressure("cpu"), "io_some_avg10": pressure("io"),
            "mem_available_bytes": available, "cgroup": cgroup,
            "resource_mounts": mounts,
            "budget_decision_inferred": False}


def save_readiness(path, diagnostic):
    # Fixed owned diagnostic only. Atomic replacement preserves a last observation if the
    # existing shell deadline terminates this observer before its normal finally block.
    owner = path.parent.stat()
    temporary = path.with_name(path.name + ".next")
    write(temporary, diagnostic)
    os.chown(temporary, owner.st_uid, owner.st_gid)
    os.replace(temporary, path)


def await_running(pid, root, sequence, diagnostic_path):
    expected = TRAIN["identity"](pid)
    started = time.monotonic()
    diagnostic = {"version": 1, "sequence": sequence, "cli": expected,
                  "total_first_worker_limit_seconds": 90, "samples": [], "worker_search_started": False}
    while True:
        snapshot = readiness_state(root, sequence)
        observed = capacity_diagnostic(pid)
        diagnostic["latest_cgroup"] = observed.pop("cgroup")
        diagnostic["latest_resource_mounts"] = observed.pop("resource_mounts")
        diagnostic["samples"].append({"elapsed_ms": int((time.monotonic() - started) * 1000),
                                      "state": snapshot, "capacity": observed})
        diagnostic["samples"] = diagnostic["samples"][-92:]
        ready = snapshot["stage"] == "running"
        diagnostic["worker_search_started"] = ready
        save_readiness(diagnostic_path, diagnostic)
        if ready:
            return
        require(TRAIN["alive"](expected), "coordinator exited before a durable Running cycle")
        require(time.monotonic() - started < 90, "coordinator did not admit a Running cycle within existing first-worker budget")
        time.sleep(1)


def observe_loop(pid, path, namespace, service_pid):
    root = ART["private_root"](path) if os.getuid() else Path(path)
    observations = []
    for sequence in (1, 2):
        cycle = root / "loop" / f"cycle-{sequence:016x}"
        output = root / f"loop-{sequence}-isolation.json"
        raw = root / f"loop-{sequence}-isolation.raw.json"
        await_running(pid, root, sequence, root / f"loop-{sequence}-readiness.json")
        ART["observe"](pid, raw, root / "provision", cycle / "dataset.json", root / "private-canary",
                       "training", "relay4", namespace, service_pid)
        evidence = read(raw)
        worker = Path(f"/proc/{evidence['worker']['pid']}")
        # Read the actual predecessor selected before this Running cycle. A rejected
        # first candidate is retained, but must never become the second worker's input.
        state = read(root / "loop/state.json")
        previous = state["latest"]
        require(previous is None or type(previous) is int and 0 < previous < sequence,
                "running cycle has an invalid approved predecessor")
        adapter = root / "loop/seed-input/adapter" if previous is None else root / "loop" / f"cycle-{previous:016x}/training/adapter"
        mounts = [line.split()[5].split(",") for line in (worker / "mountinfo").read_text().splitlines()
                  if line.split()[4] == "/adapter"]
        require(len(mounts) == 1 and "ro" in mounts[0], "warmstart adapter mount is not readonly")
        exact = {}
        for name in FILES:
            mounted, actual = (worker / "root/adapter" / name).stat(), (adapter / name).stat()
            exact[name] = (mounted.st_dev, mounted.st_ino) == (actual.st_dev, actual.st_ino)
        require(all(exact.values()), "worker did not use the exact seed/predecessor adapter")
        evidence = publish_observation(raw, output, sequence, exact, previous)
        owner = output.stat()
        observations.append(evidence)
        if sequence == 1:
            ready = root / "loop-first-worker.ready"
            ready.touch(mode=0o600)
            os.chown(ready, owner.st_uid, owner.st_gid)
        deadline = time.monotonic() + 605
        while TRAIN["alive"](evidence["worker"]):
            require(time.monotonic() < deadline, "observed worker exceeded original wall deadline")
            time.sleep(0.05)
        for stage, selected in (("baseline", adapter), ("candidate", cycle / "training/adapter")):
            observations.append(observe_validation(pid, root, cycle, sequence, stage, selected, namespace, service_pid))
    require(len({(item["worker"]["pid"], item["worker"]["start_ticks"]) for item in observations}) == 6,
            "training and validation stages did not use six distinct actual workers")


def observe_validation(pid, root, cycle, sequence, stage, adapter, namespace, service_pid):
    raw = root / f"loop-{sequence}-{stage}-isolation.raw.json"
    output = root / f"loop-{sequence}-{stage}-isolation.json"
    # ART's 'training' selector only avoids its fixed received/adapter pathname;
    # mode=Infer is established by the actual final report, not this helper label.
    ART["observe"](pid, raw, root / "provision", cycle / "validation/dataset.json", root / "private-canary",
                   "training", "relay4", namespace, service_pid)
    evidence = read(raw)
    process = Path(f"/proc/{evidence['worker']['pid']}")
    mounts = [line.split()[5].split(",") for line in (process / "mountinfo").read_text().splitlines()
              if line.split()[4] == "/adapter"]
    require(len(mounts) == 1 and "ro" in mounts[0], "validation adapter is not readonly")
    expected, actual = (cycle / "validation" / stage).stat(), (process / "root/output").stat()
    require((expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino), "wrong actual validation stage output")
    exact = {}
    for name in FILES:
        expected, actual = (adapter / name).stat(), (process / "root/adapter" / name).stat()
        exact[name] = (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)
    require(all(exact.values()), "validation used another adapter")
    evidence.update(sequence=sequence, validation_stage=stage, adapter_readonly=True,
                    adapter_exact_inodes=exact, output_exact_inode=True)
    write(output, evidence)
    owner = raw.stat()
    os.chown(output, owner.st_uid, owner.st_gid)
    deadline = time.monotonic() + 605
    while TRAIN["alive"](evidence["worker"]):
        require(time.monotonic() < deadline, "actual validation worker exceeded original deadline")
        time.sleep(0.05)
    return evidence


def publish_observation(raw, output, sequence, exact, previous=None):
    require(raw.parent == output.parent and sequence in (1, 2)
            and raw.name == f"loop-{sequence}-isolation.raw.json"
            and output.name == f"loop-{sequence}-isolation.json", "unexpected observer output names")
    owner = raw.lstat()
    require(stat.S_ISREG(owner.st_mode) and stat.S_IMODE(owner.st_mode) == 0o600
            and owner.st_nlink == 1 and owner.st_uid == raw.parent.stat().st_uid,
            "raw observer output ownership differs")
    require(set(exact) == set(FILES) and all(value is True for value in exact.values()), "warmstart inodes differ")
    evidence = read(raw)
    require(previous is None or type(previous) is int and 0 < previous < sequence,
            "invalid observed predecessor sequence")
    evidence.update(sequence=sequence, warmstart_readonly=True, warmstart_exact_inodes=exact,
                    warmstart_predecessor_sequence=previous)
    write(output, evidence)  # Exclusive creation: never overwrite the saved raw or final record.
    os.chown(output, owner.st_uid, owner.st_gid)
    published = output.lstat()
    require((published.st_uid, published.st_gid, stat.S_IMODE(published.st_mode))
            == (owner.st_uid, owner.st_gid, 0o600), "final observation owner or mode differs")
    current = raw.lstat()
    require((current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_size)
            == (owner.st_dev, owner.st_ino, owner.st_uid, owner.st_gid, owner.st_size), "raw observation was replaced")
    return evidence


def bundle_files(cycle, trained):
    files = {name: file_hash(cycle / "training/adapter" / name, 2 * 1024 ** 2) for name in FILES}
    def varint(value):
        result = bytearray()
        while value > 127:
            result.append((value & 127) | 128)
            value >>= 7
        return bytes(result) + bytes([value])
    def integer(tag, value):
        return varint(tag << 3) + varint(value) if value else b""
    def blob(tag, value):
        return varint((tag << 3) | 2) + varint(len(value)) + value
    manifest = file_hash(cycle / "dataset.manifest", 65536)
    index = (integer(1, 1) + blob(2, trained["model"]["id"].encode()) + blob(3, trained["model"]["revision"].encode())
             + blob(4, bytes.fromhex(TRAIN["WEIGHT_HASH"])) + integer(5, 4) + integer(6, 8)
             + blob(7, b"q_proj") + blob(7, b"v_proj") + blob(8, bytes.fromhex(manifest["sha256"])))
    payload = b""
    for name, info in files.items():
        index += blob(9, blob(1, name.encode()) + integer(2, len(payload)) + integer(3, info["bytes"])
                      + blob(4, bytes.fromhex(info["sha256"])))
        payload += (cycle / "training/adapter" / name).read_bytes()
    encoded = len(index).to_bytes(4, "big") + index + payload
    bundle = file_hash(cycle / "adapter.bundle", 4 * 1024 ** 2)
    require(bundle == dict(bytes=len(encoded), sha256=hashlib.sha256(encoded).hexdigest()), "canonical bundle differs from actual files")
    return files, manifest, bundle


def collect(path):
    root = ART["private_root"](path)
    loop = root / "loop"
    cycles = []
    for sequence in (1, 2):
        cycle = loop / f"cycle-{sequence:016x}"
        trained = read(cycle / "training-report.json")
        require(read(cycle / "training/report.json") == {k: v for k, v in trained.items() if k != "supervisor"}, "worker/supervisor report differs")
        files, manifest, bundle = bundle_files(cycle, trained)
        evaluation = read(cycle / "evaluation.json")
        publication = cycle / "publication.pb"
        contributed = cycle / "contribution.json"
        if not evaluation["approved"]:
            require(all(not (cycle / name).exists() and not (cycle / name).is_symlink()
                        for name in ("publication.pb", "publication.json", "contribution.json")),
                    "rejected candidate acquired publication files")
        cycles.append(dict(sequence=sequence, training=trained, isolation=read(root / f"loop-{sequence}-isolation.json"),
                           raw_isolation=read(root / f"loop-{sequence}-isolation.raw.json"),
                           result=read(cycle / "result.json"), provenance=read(cycle / "source-provenance.json"),
                           selection=read(cycle / "selection.json"), adapter_files=files, manifest=manifest, bundle=bundle,
                           dataset=file_hash(cycle / "dataset.json", 1048576),
                           report=file_hash(cycle / "training-report.json", 65536),
                           report_hex=(cycle / "training-report.json").read_bytes().hex(),
                           content_files={name: file_hash(cycle / name, 4 * 1024 ** 2) for name in CONTENT_FILES},
                           validation=dict(files=export_files(cycle, VALIDATION_FILES),
                               stages={stage:dict(isolation=read(root / f"loop-{sequence}-{stage}-isolation.json"),
                                   raw_isolation=read(root / f"loop-{sequence}-{stage}-isolation.raw.json"))
                                   for stage in ("baseline", "candidate")}),
                           evaluation=evaluation, evaluation_file=file_hash(cycle / "evaluation.json", 16384),
                           evaluation_hex=(cycle / "evaluation.json").read_bytes().hex(),
                           publication=file_hash(publication, 65536) if evaluation["approved"] else None,
                           publication_hex=publication.read_bytes().hex() if evaluation["approved"] else None,
                           contribution=read(contributed) if evaluation["approved"] else None,
                           rejected_publication_files_absent=not evaluation["approved"]))
    return dict(state=read(loop / "state.json"), enrollment=read(loop / "enrollment.json"),
                validation_input=export_files(loop / "validation-input", ("dataset.json", "dataset.manifest", "provenance.json")),
                seed=read(loop / "seed-input/provenance.json"), cycles=cycles,
                seed_files={name: file_hash(loop / "seed-input/adapter" / name, 2 * 1024 ** 2) for name in FILES},
                seed_dataset=file_hash(loop / "seed-input/dataset.json", 1048576),
                base_after=file_hash(root / "provision/model/model.safetensors", 300000000))


def export_files(root, names):
    result = {}
    for name in names:
        info = file_hash(root / name, 1048576)
        raw = (root / name).read_bytes()
        require(file_digest(raw) == info, "retained source or validation report changed during export")
        result[name] = dict(info, hex=raw.hex())
    return result


def exported(record):
    raw = bytes.fromhex(record["hex"])
    require(file_digest(raw) == {key:record[key] for key in ("bytes", "sha256")}, "exported original bytes changed")
    return raw


def identities(files):
    return {name:{key:info[key] for key in ("bytes", "sha256")} for name, info in files.items()}


def last_json(path, operation):
    raw = Path(path).read_bytes()
    require(len(raw) <= 1048576, "oversized coordinator output")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    matches = [row for row in rows if row.get("operation") == operation]
    require(len(matches) == 1, "missing or duplicate final coordinator receipt")
    return matches[0]


def check_evaluation(cycle, previous, predecessor, publisher):
    trained, decision = cycle["training"], cycle["evaluation"]
    require(type(decision["approved"]) is bool, "selection approval is not a typed decision")
    for key, field in (("baseline", "baseline_evaluation"), ("adapted", "adapted_evaluation"),
                       ("reloaded", "reloaded_evaluation")):
        metric = trained[field]
        require(set(metric) == {"loss", "target_tokens"} and type(metric["loss"]) in (int, float)
                and math.isfinite(metric["loss"]) and metric["loss"] >= 0
                and type(metric["target_tokens"]) is int and metric["target_tokens"] > 0,
                "invalid actual heldout metric")
        require(decision[key] == metric, "selection substituted the actual heldout metric")
    baseline, adapted, reloaded = (trained[name + "_evaluation"] for name in ("baseline", "adapted", "reloaded"))
    require(baseline["target_tokens"] == adapted["target_tokens"] == reloaded["target_tokens"]
            and math.isclose(adapted["loss"], reloaded["loss"], rel_tol=1e-5, abs_tol=1e-6),
            "heldout target set or actual checkpoint reload differs")
    validation = check_validation(cycle)
    approved = reloaded["loss"] < baseline["loss"] - 1e-6 and validation["approved"]
    require(set(cycle["content_files"]) == set(CONTENT_FILES), "completed candidate file identity set differs")
    for name, actual in (("dataset.json", cycle["dataset"]), ("dataset.manifest", cycle["manifest"]),
                         ("training-report.json", cycle["report"]), ("adapter.bundle", cycle["bundle"]),
                         *(("training/adapter/" + name, info) for name, info in cycle["adapter_files"].items())):
        require(cycle["content_files"][name] == actual, "candidate file identity differs from actual collected bytes")
    raw_report, raw_decision = bytes.fromhex(cycle["report_hex"]), bytes.fromhex(cycle["evaluation_hex"])
    require(file_digest(raw_report) == cycle["report"] and json.loads(raw_report) == trained
            and file_digest(raw_decision) == cycle["evaluation_file"] and json.loads(raw_decision) == decision,
            "raw immutable report or evaluation bytes differ")
    expected = dict(version=1, policy=POLICY,
        scope="source-and-pinned-second-source-selection-only-not-independent-test-benchmark", epsilon=1e-6,
        sequence=cycle["sequence"], predecessor=previous,
        baseline_kind="configured_adapter" if previous is None else "approved_predecessor", approved=approved,
        source_manifest_id=cycle["manifest"]["sha256"], source_publisher_key=publisher,
        source_revision=trained["dataset"]["source_revision"], files=cycle["content_files"],
        model_id=trained["model"]["id"], model_revision=trained["model"]["revision"],
        base_model=trained["model"]["files"]["model.safetensors"], base_parameters=trained["base_after"],
        input_adapter={name: trained["input_adapter"][name] for name in ("files", "applied_parameters")},
        candidate_adapter=cycle["adapter_files"], candidate_parameters=trained["adapter_after"],
        baseline=baseline, adapted=adapted, reloaded=reloaded, validation=validation)
    require(decision == expected and trained["adapter_before"] == predecessor["adapter_after"],
            "evaluation policy, decision, source or predecessor binding differs")
    return approved


def check_validation(cycle):
    files = cycle["validation"]["files"]
    require(set(files) == set(VALIDATION_FILES), "actual validation file set incomplete")
    parsed = {name:json.loads(exported(value)) for name, value in files.items() if name != "validation/dataset.manifest"}
    require(file_digest(exported(files["validation/dataset.manifest"])) == identities(files)["validation/dataset.manifest"],
            "validation manifest export differs")
    source, dataset = parsed["validation/provenance.json"], parsed["validation/dataset.json"]
    require(source["dataset"] == identities(files)["validation/dataset.json"]
            and source["manifest"] == identities(files)["validation/dataset.manifest"]
            and source["manifest_id"] == source["manifest"]["sha256"]
            and source["manifest_id"] != cycle["manifest"]["sha256"]
            and source["dataset"]["sha256"] != cycle["dataset"]["sha256"]
            and dataset["version"] == 1 and dataset["visibility"] == "public" and dataset["license"] == "GPL-3.0-only"
            and dataset["train"] == [] and len(dataset["heldout"]) == len(dataset["inference"]) == 1,
            "validation reused training source or contains training rows")
    trained, reports, previous_end = cycle["training"], {}, None
    for stage in ("baseline", "candidate"):
        envelope = parsed[stage + "-report.json"]
        report = envelope["report"]
        require({key:value for key,value in report.items() if key != "supervisor"}
                == parsed[f"validation/{stage}/report.json"], "actual validation worker report was substituted")
        require(report["version"] == 1 and report["kind"] == "result" and report["status"] == "ok"
                and report["mode"] == "infer" and report["device"] == "cpu" and report["threads"] == 2
                and report["updates_completed"] == 0 and report["artifacts"] == []
                and report["model"] == trained["model"] and report["backend_versions"] == trained["backend_versions"]
                and report["dataset"]["sha256"] == source["dataset"]["sha256"]
                and report["dataset"]["bytes"] == source["dataset"]["bytes"]
                and report["dataset"]["source_revision"] == dataset["source_revision"]
                and report["dataset"]["training_examples"] == 0
                and report["dataset"]["heldout_examples"] == report["dataset"]["inference_examples"] == 1
                and len(report["outputs"]) == 1 and isinstance(report["outputs"][0], str)
                and report["better_answers_claimed"] is False and report["network_policy_changed"] is False,
                "real bounded zero-update inference on exact second-source input missing")
        supervisor = report["supervisor"]
        seconds = supervisor["deadline_seconds"]
        require(supervisor["child_reaped"] is True and supervisor["network_access"] is False
                and supervisor["gpu_access"] is False and supervisor["spare_capacity"] is True
                and supervisor["sandbox"] == "bubblewrap-private-user-net-pid-ipc-mount"
                and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"]
                and type(seconds) is int and 0 < seconds <= 600,
                "validation bypasses real owner bounds or child cleanup")
        require(envelope["version"] == 1 and source["verified_at_unix_seconds"] <= envelope["started_at_unix_seconds"]
                <= envelope["verified_at_unix_seconds"] <= envelope["deadline_unix_seconds"]
                and envelope["deadline_unix_seconds"] == envelope["started_at_unix_seconds"] + seconds
                and envelope["verified_at_unix_seconds"] < min(source["expires_unix_seconds"], cycle["result"]["source_expires_unix_seconds"])
                and envelope["deadline_unix_seconds"] <= min(source["expires_unix_seconds"], cycle["result"]["source_expires_unix_seconds"])
                and 0 <= report["elapsed_ms"] <= seconds * 1000
                and (previous_end is None or envelope["started_at_unix_seconds"] >= previous_end),
                "validation renewed expiry or overlapped sequential stages")
        previous_end = envelope["verified_at_unix_seconds"]
        adapter = report["input_adapter"]
        require(adapter["applied"] is True and adapter["model_id"] == trained["model"]["id"]
                and adapter["model_revision"] == trained["model"]["revision"]
                and adapter["base_parameters_before_apply"] == adapter["base_parameters_after_apply"] == trained["base_before"],
                "validation adapter changed the common base")
        if stage == "baseline":
            require(adapter == trained["input_adapter"], "baseline did not load exact training predecessor")
        else:
            require(adapter["files"] == cycle["adapter_files"] and adapter["applied_parameters"] == trained["adapter_after"],
                    "candidate validation did not load actual newly saved weights")
        metric = report["baseline_evaluation"]
        require(set(metric) == {"loss", "target_tokens"} and type(metric["loss"]) in (int, float)
                and math.isfinite(metric["loss"]) and metric["loss"] >= 0
                and type(metric["target_tokens"]) is int and metric["target_tokens"] > 0, "invalid second-source metric")
        reports[stage] = report
    baseline, candidate = (reports[stage]["baseline_evaluation"] for stage in ("baseline", "candidate"))
    require(baseline["target_tokens"] == candidate["target_tokens"], "second-source evaluation target tokens changed")
    observed_files = {name:info for name,info in identities(files).items() if name != "validation.json"}
    observed_files.update({name:cycle["content_files"][name] for name in
                          ("training-report.json", "result.json", "selection.json", *("training/adapter/" + name for name in FILES))})
    expected = dict(version=1, policy="second-source-heldout-loss-v1",
        scope="explicit-second-source-selection-set-not-independent-benchmark-or-historical-contamination-proof", epsilon=1e-6,
        sequence=cycle["sequence"], approved=candidate["loss"] < baseline["loss"] - 1e-6,
        source_manifest_id=source["manifest_id"], publisher_key=source["selection"]["publisher_key"],
        source_revision=dataset["source_revision"], source_expires_unix_seconds=source["expires_unix_seconds"],
        files=observed_files, model_id=trained["model"]["id"], model_revision=trained["model"]["revision"],
        baseline_input_adapter=reports["baseline"]["input_adapter"], candidate_input_adapter=reports["candidate"]["input_adapter"],
        baseline=baseline, candidate=candidate)
    require(parsed["validation.json"] == expected, "saved second-source validation decision or raw file bindings differ")
    return expected


def check_chain(evidence):
    loop, original = evidence["loop"], evidence["originals"]
    plan, state = loop["enrollment"], loop["state"]
    source, owner = evidence["dataset_publish"]["publisher_key_hex"], evidence["owner_key"]["identity_public_key_hex"]
    require(source != owner, "dataset and trained-update publishers are not independent")
    require(plan["repeat_sources"] is True and plan["source_choice_uses_cache_inventory"] is False
            and plan["sources"] == [{"publisher_key": source, "name": "disposable-agent-dataset", "min_revision": 1,
                                    "manifest_id": original["dataset_manifest_id"]}], "wrong explicitly repeated source plan")
    require(plan["publication_key"] == owner and plan["publish_name"] == "disposable-loop-update"
            and plan["quality_policy"] == POLICY, "wrong enrolled update publisher or selection policy")
    require(state["version"] == 2 and state["completed"] == 2 and state["next_sequence"] == 3
            and len(state["cycles"]) == 2 and state["garbage"] == [], "two retained completed cycles missing")
    summary = evidence["summary"]
    require(summary["operation"] == "compute_train_loop" and summary["completed_cycles"] == 2
            and summary["attempts_this_invocation"] == 2 and summary["pending_publications"] == 0
            and summary["owner_cancelled"] is False, "coordinator did not finish both actual attempts and pending publications")
    require(loop["seed_files"] == original["adapter_files"] and loop["seed_dataset"] == original["dataset"], "wrong received initial seed")
    previous = evidence["training"]
    previous_files = original["adapter_files"]
    latest, approved = None, []
    expiry = evidence["dataset_publish"]["expires_unix_seconds"]
    for index, cycle in enumerate(loop["cycles"], 1):
        trained, result, provenance = cycle["training"], cycle["result"], cycle["provenance"]
        saved = state["cycles"][index - 1]
        require(cycle["sequence"] == saved["sequence"] == index, "wrong durable cycle sequence")
        require(result["operation"] == "compute_train_cycle" and result["complete"] is True
                and result["updates_completed"] == 8 and result["input_adapter_applied"] is True, "actual cycle result missing")
        require(result["dataset_manifest_id"] == provenance["dataset_manifest_id"] == cycle["manifest"]["sha256"]
                == original["dataset_manifest_id"] == result["bundle"]["dataset_manifest_id"], "cycle changed original signed dataset")
        require(result["source_expires_unix_seconds"] == provenance["expires_unix_seconds"] == expiry
                and cycle["dataset"] == original["dataset"], "dataset expiry or bytes changed")
        require(trained["input_adapter"]["files"] == previous_files
                and trained["input_adapter"]["applied_parameters"] == trained["adapter_before"] == previous["adapter_after"]
                and trained["base_before"] == trained["base_after"] == previous["base_after"], "cycle lost exact previous warmstart")
        require(trained["adapter_after"] != previous["adapter_after"]
                and cycle["adapter_files"]["adapter_model.safetensors"] != previous_files["adapter_model.safetensors"], "cycle saved no changed weights")
        require(result["training_report_sha256"] == cycle["report"]["sha256"]
                and result["bundle"]["sha256"] == cycle["bundle"]["sha256"], "actual report/bundle hash differs")
        accepted = check_evaluation(cycle, latest, previous, source)
        require(saved["training"] is None
                and saved["snapshot"] == dict(cycle["content_files"], **{"evaluation.json": cycle["evaluation_file"]},
                                              **identities(cycle["validation"]["files"])),
                "durable candidate snapshot does not bind actual files and immutable evaluation")
        require(saved["phase"] == ("complete" if accepted else "rejected"), "durable phase contradicts measured evaluation")
        if not accepted:
            require(cycle["publication"] is None and cycle["publication_hex"] is None
                    and cycle["contribution"] is None and saved["publication"] is None
                    and cycle["rejected_publication_files_absent"] is True,
                    "rejected candidate was automatically published")
            continue
        contribution = cycle["contribution"]
        require(contribution["manifest_id"] == cycle["publication"]["sha256"]
                == state["cycles"][index - 1]["publication"]["manifest_id"]
                and contribution["publisher_key_hex"] == owner and contribution["network_publication"] is True
                and contribution["serving"] is True and contribution["bytes"] == cycle["bundle"]["bytes"], "automatic own contribution missing")
        require(0 < contribution["expires_unix_seconds"] <= expiry, "new update extends original dataset validity")
        approved.append(index)
        latest = index
        previous, previous_files = trained, cycle["adapter_files"]
    require(state["latest"] == latest and state["promoted"] == len(approved)
            and state["rejected"] == 2 - len(approved), "latest or promotion/rejection counters ignore actual gate")
    require(summary["promoted_cycles"] == len(approved) and summary["rejected_cycles"] == 2 - len(approved)
            and summary["latest_approved_sequence"] == latest and summary["quality_policy"] == POLICY
            and summary["independent_quality_benchmark"] is False, "coordinator summary overstates adoption or quality")
    require(evidence["adoption"] == adoption(loop), "saved adoption outcome differs from actual selection")
    if latest is None:
        require(all(evidence[key] is None for key in ("fetch", "received", "inference", "inference_isolation")),
                "all candidates rejected but a new imported model is claimed")
        return
    fetched = evidence["fetch"]
    require(fetched["publisher"] == owner and fetched["dataset_publisher"] == source
            and fetched["adapter_manifest_id"] == loop["cycles"][latest - 1]["publication"]["sha256"]
            and fetched["dataset_manifest_id"] == original["dataset_manifest_id"]
            and fetched["cache_only"] is False and fetched["model_activated"] is False,
            "different node did not import independently signed update/dataset")
    require(evidence["received"]["adapter_files"] == previous_files
            and evidence["received"]["dataset"] == original["dataset"], "received update bytes differ")
    infer = evidence["inference"]
    require(infer["status"] == "ok" and infer["mode"] == "infer" and infer["updates_completed"] == 0
            and infer["input_adapter"]["files"] == previous_files
            and infer["input_adapter"]["applied_parameters"] == previous["adapter_after"]
            and infer["outputs"] == previous["outputs"] and len(infer["outputs"]) > 0, "imported update was not actually used")


def adoption(loop):
    approved = [cycle["sequence"] for cycle in loop["cycles"] if cycle["evaluation"]["approved"]]
    latest = approved[-1] if approved else None
    require(loop["state"]["latest"] == latest, "latest does not refer to the latest approved update")
    return dict(quality_policy=POLICY, approved_sequences=approved, latest_sequence=latest,
                new_adapter_adopted=latest is not None, protected_import_performed=latest is not None,
                inference_performed=latest is not None,
                no_new_adapter_reason=None if latest is not None else "both_candidates_rejected_by_enrolled_loss_gates",
                independent_evaluation_claimed=False, general_quality_improvement_claimed=False)


def check_evidence(evidence, revision):
    require(evidence["source_revision"] == revision, "wrong source revision")
    check_chain(evidence)
    check_second_source(evidence)
    loop = evidence["loop"]
    for name, mandatory in (("loop-shared", False), ("loop-all-shared", True)):
        shared_updates(loop, evidence["originals"], evidence["owner_key"]["identity_public_key_hex"],
                       evidence["sharing_status"][name], mandatory)
    TRAIN["check_worker"](evidence["training"], revision)
    TRAIN["check_isolation"](evidence["training_isolation"])
    require(evidence["training_isolation"]["node_lineage"]["node"] == "relay5", "seed did not originate on R5")
    node_lineage = None
    previous = None
    validation_workers = []
    for cycle in loop["cycles"]:
        TRAIN["check_worker"](cycle["training"], revision)
        observed = cycle["isolation"]
        require({key: value for key, value in observed.items()
                 if key not in ("sequence", "warmstart_readonly", "warmstart_exact_inodes", "warmstart_predecessor_sequence")} == cycle["raw_isolation"],
                "final observation changed its original raw process/input evidence")
        TRAIN["check_isolation"](observed)
        require(observed["node_lineage"]["node"] == "relay4" and observed["warmstart_readonly"] is True
                and set(observed["warmstart_exact_inodes"]) == set(FILES)
                and all(observed["warmstart_exact_inodes"].values())
                and observed["warmstart_predecessor_sequence"] == previous, "actual approved predecessor mount missing")
        if node_lineage is not None:
            require(observed["node_lineage"] == node_lineage, "coordinator moved to another node")
        node_lineage = observed["node_lineage"]
        require(cycle["training"]["supervisor"]["spare_capacity"] is True, "autonomous worker bypasses owner budget")
        last_worker = observed["worker"]
        for stage in ("baseline", "candidate"):
            saved = cycle["validation"]["stages"][stage]
            actual = saved["isolation"]
            require({key:value for key,value in actual.items() if key not in
                     ("sequence", "validation_stage", "adapter_readonly", "adapter_exact_inodes", "output_exact_inode")}
                    == saved["raw_isolation"], "validation observation changed original process or input evidence")
            TRAIN["check_isolation"](actual)
            require(actual["node_lineage"] == node_lineage and actual["sequence"] == cycle["sequence"]
                    and actual["validation_stage"] == stage and actual["adapter_readonly"] is True
                    and set(actual["adapter_exact_inodes"]) == set(FILES) and all(actual["adapter_exact_inodes"].values())
                    and actual["output_exact_inode"] is True and actual["worker"]["start_ticks"] > last_worker["start_ticks"],
                    "actual sequential second-source stage, private adapter or output inode missing")
            last_worker = actual["worker"]
            validation_workers.append(actual)
        if not cycle["evaluation"]["approved"]:
            continue
        previous = cycle["sequence"]
        encoded = bytes.fromhex(cycle["publication_hex"])
        require(file_digest(encoded) == cycle["publication"], "original publication bytes were relabeled")
        envelope = ART["CUSTODY"]["fields"](encoded, 65536)
        body = ART["CUSTODY"]["fields"](envelope[1], 65536)
        require(len(envelope[2]) == 64 and body[2].hex() == evidence["owner_key"]["identity_public_key_hex"]
                and body[4] == cycle["contribution"]["expires_unix_seconds"]
                and hashlib.sha256(body[8]).digest() == body[7], "signed update publisher/expiry/payload differs")
    latest = loop["state"]["latest"]
    workers = [evidence["training_isolation"], *(cycle["isolation"] for cycle in loop["cycles"])]
    namespaces = [workers[index]["node_lineage"]["network_namespace"] for index in (0, 1)]
    if latest is not None:
        workers.append(evidence["inference_isolation"])
        namespaces.append(workers[-1]["node_lineage"]["network_namespace"])
        TRAIN["check_isolation"](evidence["inference_isolation"])
        require(evidence["inference_isolation"]["node_lineage"]["node"] == "client"
                and evidence["inference_isolation"]["received_adapter_readonly"] is True
                and all(evidence["inference_isolation"]["received_adapter_exact_inodes"].values()), "wrong importer worker")
    workers.extend(validation_workers)
    require(len({(item["worker"]["pid"], item["worker"]["start_ticks"]) for item in workers}) == len(workers), "actual worker identities reused")
    require(len(set(namespaces)) == len(namespaces), "producer/trainer/importer node namespaces overlap")
    require(loop["base_after"] == dict(bytes=269060552, sha256=TRAIN["WEIGHT_HASH"]), "original base weights changed")
    peers = evidence["peers"]
    initial = evidence["initial_fetch"]
    require(initial["manifest_id"] == evidence["originals"]["dataset_manifest_id"]
            and initial["sha256"] == evidence["originals"]["dataset"]["sha256"]
            and initial["bytes"] == initial["peer_bytes"] == evidence["originals"]["dataset"]["bytes"]
            and initial["providers_used"] == 1 and initial["provider_peer_ids"] == [peers["relay5"]],
            "native agent cache was not initialized by the actual selected protected download")
    for kind in ("adapter", "dataset"):
        receipt = loop["seed"][kind + "_receipt"]
        expected = evidence["originals"]["adapter_bundle" if kind == "adapter" else "dataset"]
        require(receipt["manifest_id"] == evidence["originals"][kind + "_manifest_id"]
                and receipt["sha256"] == expected["sha256"] and receipt["bytes"] == expected["bytes"]
                and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0, "seed substituted original public objects")
        if kind == "adapter":
            require(receipt["peer_bytes"] == expected["bytes"] and receipt["provider_peer_ids"] == [peers["relay5"]]
                    and receipt["providers_used"] == 1, "seed adapter bypassed protected R5")
        else:
            require(receipt["peer_bytes"] == 0 and receipt["providers_used"] == 0
                    and receipt["provider_peer_ids"] == [], "seed falsely charges cached dataset bytes as a new transfer")
        if latest is not None:
            receipt = evidence["fetch"][kind + "_receipt"]
            require(receipt["provider_peer_ids"] == [peers["relay4"]] and receipt["providers_used"] == 1
                    and receipt["bytes"] == receipt["peer_bytes"] > 0
                    and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0, "final object bypassed protected R4")
    REP["validate_phase"](evidence["phases"]["uptake"], "uptake", peers,
                          evidence["originals"]["adapter_bundle"]["bytes"] + evidence["originals"]["dataset"]["bytes"]
                          + evidence["validation_original"]["dataset"]["bytes"])
    if latest is not None:
        REP["validate_phase"](evidence["phases"]["reserve-fetch"], "reserve-fetch", peers,
                              loop["cycles"][latest - 1]["bundle"]["bytes"] + evidence["originals"]["dataset"]["bytes"])
    else:
        require(set(evidence["phases"]) == {"uptake"}, "all candidates rejected but an import path is claimed")
    require(evidence["dataset_export"]["manifest_id"] == evidence["dataset_contribute"]["manifest_id"]
            == evidence["originals"]["dataset_manifest_id"]
            and evidence["dataset_export"]["public_content"] is True
            and evidence["dataset_contribute"]["publisher_key_hex"] == evidence["dataset_publish"]["publisher_key_hex"],
            "shared original dataset was resigned or substituted")
    require(evidence["dataset_contribute"]["expires_unix_seconds"] == evidence["dataset_publish"]["expires_unix_seconds"], "shared dataset expiry extended")
    require(evidence["source_stop"]["serving"] is False and evidence["source_stop"]["publications"] == 0,
            "original source provider still serves during independent import")
    require(all(evidence["source_removed"][field] is True for field in
                ("trainer_inputs_removed", "trainer_adapter_removed", "publisher_cache_removed", "publisher_key_removed")),
            "original training files or publisher inputs remain")
    require(evidence["source_restart"]["pid_before"] == evidence["training_isolation"]["node_lineage"]["service"]["pid"]
            and evidence["source_restart"]["pid_before"] != evidence["source_restart"]["pid_after"]
            and evidence["source_restart"]["same_cache"] is True
            and evidence["source_restart"]["restored_publications"] == 3, "original provider restart/reopen missing")
    require(evidence["provision"]["success"] is True and evidence["provision"]["training_performed"] is False,
            "explicit verified guest provisioning missing")
    require(all(evidence["cleanup"].values()) and all(evidence["content_isolation"].values()), "owned cleanup or cross-node storage isolation missing")


def check_second_source(evidence):
    loop, original = evidence["loop"], evidence["validation_original"]
    files = loop["validation_input"]
    require(set(files) == {"dataset.json", "dataset.manifest", "provenance.json"}
            and loop["state"]["validation"] == identities(files), "pinned validation input snapshot changed")
    raw, encoded = exported(files["dataset.json"]), exported(files["dataset.manifest"])
    dataset, provenance = json.loads(raw), json.loads(exported(files["provenance.json"]))
    require(raw.hex() == original["dataset_hex"] and file_digest(raw) == original["dataset"]
            and encoded.hex() == original["manifest_hex"] and file_digest(encoded) == original["manifest"]
            and loop["enrollment"]["validation_source"] == original["selection"] == provenance["selection"]
            and original["selection"]["name"] == "disposable-agent-validation"
            and original["selection"]["publisher_key"] == evidence["dataset_publish"]["publisher_key_hex"]
            == evidence["validation_publish"]["publisher_key_hex"]
            and original["selection"]["manifest_id"] == provenance["manifest_id"] == original["manifest"]["sha256"]
            and provenance["dataset"] == original["dataset"] and provenance["manifest"] == original["manifest"],
            "validation source differs from the separately published and enrolled original")
    fields = ART["CUSTODY"]["fields"]
    envelope = fields(encoded, 65536)
    body = fields(envelope[1], 65536)
    payload = fields(body[8], 65536)
    require(len(envelope[2]) == 64 and body[1] == 1 and body[6] == 1
            and body[2].hex() == original["selection"]["publisher_key"]
            and body[3] <= provenance["verified_at_unix_seconds"] < body[4]
            and body[4] == provenance["expires_unix_seconds"] == evidence["validation_publish"]["expires_unix_seconds"]
            and body[7] == hashlib.sha256(body[8]).digest()
            and payload[1] == b"disposable-agent-validation" and payload[2] == 1
            and payload[3] == ART["DATASET_TYPE"].encode() and payload[4] == len(raw)
            and payload[6] == hashlib.sha256(raw).digest(), "original validation signature bytes/object binding differs")
    train_raw = bytes.fromhex(evidence["training_dataset_hex"])
    training = json.loads(train_raw)
    normalize = lambda text: " ".join(text.split()).lower()
    questions = {normalize(row["question"]) for row in dataset["heldout"] + dataset["inference"]}
    require(file_digest(train_raw) == evidence["originals"]["dataset"] and dataset["train"] == []
            and dataset["source_revision"] == training["source_revision"] == evidence["source_revision"]
            and original["manifest"]["sha256"] != evidence["originals"]["dataset_manifest_id"]
            and original["dataset"]["sha256"] != evidence["originals"]["dataset"]["sha256"]
            and all(normalize(row["question"]) not in questions for row in training["train"]),
            "fixture reused training source or leaked current training questions into second-source rows")
    receipt = provenance["source_receipt"]
    require(receipt["manifest_id"] == provenance["manifest_id"] and receipt["sha256"] == original["dataset"]["sha256"]
            and receipt["bytes"] == receipt["peer_bytes"] == original["dataset"]["bytes"]
            and receipt["chunks"] == receipt["providers_used"] == 1 and receipt["provider_peer_ids"] == [evidence["peers"]["relay5"]]
            and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0,
            "new validation source was not actually retrieved through the protected provider route")
    for cycle in loop["cycles"]:
        for name, value in files.items():
            require(cycle["validation"]["files"]["validation/" + name] == value,
                    "a cycle changed the previously pinned validation input")
        require(provenance["verified_at_unix_seconds"] <= cycle["provenance"]["verified_at_unix_seconds"],
                "validation set was selected after training-source admission")
    require(all(evidence["validation_removed"].values()), "original validation inputs/cache remain")


def file_digest(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def shared_updates(loop, original, owner, status, require_dataset):
    """Exact contributed updates plus accounted optional original replicas.

    Status is aggregate storage accounting, not an inventory API. Approved
    update identities are bound by their actual completed contribution receipts;
    only the independently known source/seed can explain additional accounting.
    The later protected import still proves real serving of the selected update.
    """
    require(status["serving"] is True and status["replication_enabled"] is True
            and len(loop["cycles"]) == len(loop["state"]["cycles"]) == 2, "updates not served by the actual replica runtime")
    required_ids, required_bytes, required_chunks = [], 0, 0
    for index, cycle in enumerate(loop["cycles"], 1):
        saved = loop["state"]["cycles"][index - 1]
        if not cycle["evaluation"]["approved"]:
            require(saved["phase"] == "rejected" and saved["publication"] is None
                    and cycle["publication"] is None and cycle["publication_hex"] is None
                    and cycle["contribution"] is None and cycle["rejected_publication_files_absent"] is True,
                    "rejected candidate appears in served updates")
            continue
        contribution = cycle["contribution"]
        encoded = bytes.fromhex(cycle["publication_hex"])
        require(cycle["sequence"] == saved["sequence"] == index and saved["phase"] == "complete"
                and file_digest(encoded) == cycle["publication"]
                and contribution["manifest_id"] == cycle["publication"]["sha256"] == saved["publication"]["manifest_id"]
                and contribution["publisher_key_hex"] == owner and contribution["revision"] == index
                and contribution["name"] == "disposable-loop-update" and contribution["operation"] == "content_contribute"
                and contribution["network_publication"] is True and contribution["serving"] is True
                and contribution["bytes"] == cycle["bundle"]["bytes"]
                and contribution["chunks"] == 4, "one exact completed update contribution is missing")
        fields = ART["CUSTODY"]["fields"]
        envelope = fields(encoded, 65536)
        body = fields(envelope[1], 65536)
        require(len(envelope[2]) == 64 and body[2].hex() == owner
                and body[4] == contribution["expires_unix_seconds"] == saved["publication"]["expires"]
                and hashlib.sha256(body[8]).digest() == body[7], "contributed update signature bytes or expiry changed")
        required_ids.append(contribution["manifest_id"])
        required_bytes += contribution["bytes"]
        required_chunks += contribution["chunks"]
    extras = []
    for kind, original_field in (("dataset", "dataset"), ("adapter", "adapter_bundle")):
        receipt = loop["seed"][kind + "_receipt"]
        require(receipt["manifest_id"] == original[kind + "_manifest_id"]
                and receipt["bytes"] == original[original_field]["bytes"]
                and receipt["sha256"] == original[original_field]["sha256"]
                and receipt["chunks"] == (1 if kind == "dataset" else 4), "unknown original replica used to explain storage")
        extras.append((receipt["manifest_id"], receipt["bytes"], receipt["chunks"]))
    if loop.get("validation_input") is not None:
        source = json.loads(exported(loop["validation_input"]["provenance.json"]))
        receipt = source["source_receipt"]
        require(receipt["manifest_id"] == source["manifest_id"]
                and receipt["sha256"] == source["dataset"]["sha256"]
                and receipt["bytes"] == source["dataset"]["bytes"] and receipt["chunks"] == 1,
                "unknown validation replica used to explain storage")
        extras.append((receipt["manifest_id"], receipt["bytes"], receipt["chunks"]))
    require(len(set(required_ids + [entry[0] for entry in extras])) == len(required_ids) + len(extras), "original and trained publication identities overlap")
    for mask in range(1 << len(extras)):
        if require_dataset and not mask & 1:
            continue
        selected = [item for index, item in enumerate(extras) if mask & (1 << index)]
        count = len(required_ids) + len(selected)
        if (status["publications"] == status["replica_publications"] == count
                and status["replica_bytes"] == required_bytes + sum(item[1] for item in selected)
                and status["replica_chunks"] == required_chunks + sum(item[2] for item in selected)):
            return {"required_update_manifest_ids": required_ids,
                    "accounted_original_manifest_ids": [item[0] for item in selected],
                    "publications": count, "bytes": status["replica_bytes"], "chunks": status["replica_chunks"],
                    "dataset_required": require_dataset, "aggregate_status_is_manifest_inventory": False}
    raise ValueError("replica accounting is not the approved updates plus an allowed exact original subset")


def shared(work, label, require_dataset):
    require(label in ("loop-shared", "loop-all-shared"), "invalid sharing guard label")
    return shared_updates(read(work / "agent-train-loop-loop.json", 1048576), read(work / "agent-artifact-originals.json"),
                          read(work / "agent-train-loop-owner-key.json")["identity_public_key_hex"],
                          read(work / f"content-custody-relay4-{label}.json"), require_dataset)


def evidence(work, revision):
    names = ("loop", "summary", "owner-key", "adoption", "initial-fetch", "dataset-export", "dataset-contribute", "source-stop",
             "validation-original", "validation-publish", "validation-removed", "content-isolation", "cleanup")
    result = {name.replace("-", "_"): read(work / f"agent-train-loop-{name}.json", 1048576) for name in names}
    for name in ("training", "training-isolation", "originals", "dataset-publish", "adapter-publish", "source-removed", "provision"):
        result[name.replace("-", "_")] = read(work / f"agent-artifact-{name}.json")
    latest = result["loop"]["state"]["latest"]
    for name, prefix in (("fetch", "agent-train-loop"), ("received", "agent-artifact"),
                         ("inference", "agent-artifact"), ("inference-isolation", "agent-artifact")):
        path = work / f"{prefix}-{name}.json"
        if latest is None:
            require(not path.exists() and not path.is_symlink(), "rejected candidates have unexpected import/inference output")
        result[name.replace("-", "_")] = read(path) if latest is not None else None
    result.update(source_revision=revision, peers=read(work / "a01-expected-peers.json"))
    result["training_dataset_hex"] = (work / "agent-artifact-original-dataset.json").read_bytes().hex()
    result["source_restart"] = read(work / "agent-artifact-relay5-restart.json")
    result["sharing_status"] = {name: read(work / f"content-custody-relay4-{name}.json")
                                for name in ("loop-shared", "loop-all-shared")}
    for name, mandatory in (("loop-shared", False), ("loop-all-shared", True)):
        observed = read(work / f"agent-train-loop-{name}-inventory.json")
        require(observed == shared_updates(result["loop"], result["originals"], result["owner_key"]["identity_public_key_hex"],
                                            result["sharing_status"][name], mandatory), "saved sharing accounting differs")
    result["phases"] = {name: dict(route=read(work / f"agent-train-loop-{name}-live-selection.json"),
                                   layout=read(work / f"agent-train-loop-{name}-layout.json"),
                                   captures={role: read(work / f"agent-train-loop-{name}-{role}.json") for role in REP["ROLES"]})
                        for name in (("uptake", "reserve-fetch") if latest is not None else ("uptake",))}
    check_evidence(result, revision)
    write(work / "agent-train-loop-evidence.json", result)


def cleanup(path):
    root = Path(path)
    require(root.is_absolute() and root.name == "agent-artifact-user", "wrong private cleanup root")
    ended = True
    if root.exists():
        ART["private_root"](root)
        for sequence in (1, 2):
            for stage in ("", "-baseline", "-candidate"):
                for suffix in (".raw.json", ".json"):
                    record = root / f"loop-{sequence}{stage}-isolation{suffix}"
                    if record.exists():
                        ended &= all(not TRAIN["alive"](member) for member in read(record)["owned_processes"])
        require(ended, "observed autonomous worker/coordinator still alive")
    return dict(ART["cleanup"](root), autonomous_owned_processes_ended=ended)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    candidate = work / "agent-train-loop-evidence.json"
    raw = read(candidate, 1048576) if candidate.exists() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").exists() else {}
    write(work / "agent-train-loop-smoke.json", dict(report_kind="volparossa-public-agent-train-loop", source_revision=revision,
          success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and raw is not None,
          evidence=raw, phase=phase, observed_blocker=None if blocker == "NONE" else blocker, scope=SCOPE,
          quality_policy=POLICY, independent_evaluation_claimed=False, general_quality_improvement_claimed=False,
          fresh_corpus_discovery_claimed=False, shared_base_distribution_claimed=False, full_b05_claimed=False, full_alpha_claimed=False,
          cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host))


def report(value, revision):
    require(value["report_kind"] == "volparossa-public-agent-train-loop" and value["source_revision"] == revision
            and value["success"] is True and value["scope"] == SCOPE
            and value["quality_policy"] == POLICY, "incomplete source-bound loop report")
    require(value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "guest cleanup differs")
    require(all(value[key] is False for key in ("fresh_corpus_discovery_claimed", "shared_base_distribution_claimed",
                "independent_evaluation_claimed", "general_quality_improvement_claimed", "full_b05_claimed", "full_alpha_claimed")), "unsupported scope")
    check_evidence(value["evidence"], revision)


def synthetic_validation(cycle, publisher, approved):
    def encoded(raw):
        return dict(file_digest(raw), hex=raw.hex())
    def document(value):
        return encoded(json.dumps(value).encode())
    dataset = dict(version=1, visibility="public", license="GPL-3.0-only", source_revision="a" * 40, train=[],
        heldout=[dict(question="A separately selected test question?", context="Public parser fixture.", answer="Yes.")],
        inference=[dict(question="A separate inference?", context="Public parser fixture.")])
    manifest = encoded(b"synthetic second-source manifest, not a signature proof")
    raw_dataset = document(dataset)
    source = dict(version=1, selection=dict(publisher_key=publisher, name="disposable-agent-validation", min_revision=1,
        manifest_id=manifest["sha256"]), manifest_id=manifest["sha256"], verified_at_unix_seconds=100,
        expires_unix_seconds=900, dataset={key:raw_dataset[key] for key in ("sha256", "bytes")},
        manifest={key:manifest[key] for key in ("sha256", "bytes")}, source_receipt={})
    files = {"validation/dataset.json":raw_dataset, "validation/dataset.manifest":manifest,
             "validation/provenance.json":document(source)}
    trained, reports = cycle["training"], {}
    for stage, start in (("baseline", 200), ("candidate", 220)):
        adapter = copy.deepcopy(trained["input_adapter"])
        if stage == "candidate":
            adapter.update(files=cycle["adapter_files"], applied_parameters=trained["adapter_after"])
        report = dict(version=1, kind="result", status="ok", mode="infer", device="cpu", threads=2,
            updates_completed=0, artifacts=[], model=trained["model"], backend_versions=trained["backend_versions"],
            dataset=dict(source["dataset"], source_revision="a" * 40, training_examples=0, heldout_examples=1,
                inference_examples=1, visibility="public", license="GPL-3.0-only"),
            outputs=["Parser fixture only; no model ran."], better_answers_claimed=False, network_policy_changed=False,
            input_adapter=adapter, baseline_evaluation=dict(loss=2.0 if stage == "baseline" else 1.5 if approved else 2.5,
                target_tokens=8), elapsed_ms=1000)
        files[f"validation/{stage}/report.json"] = document(report)
        report["supervisor"] = dict(child_reaped=True, network_access=False, gpu_access=False, spare_capacity=True,
            sandbox="bubblewrap-private-user-net-pid-ipc-mount", max_observed_rss_bytes=1000, rss_limit_bytes=2000,
            deadline_seconds=600)
        envelope = dict(version=1, started_at_unix_seconds=start, verified_at_unix_seconds=start + 10,
                        deadline_unix_seconds=start + 600, report=report)
        files[stage + "-report.json"] = document(envelope)
        reports[stage] = report
    bound = identities(files)
    bound.update({name:cycle["content_files"][name] for name in
        ("training-report.json", "result.json", "selection.json", *("training/adapter/" + name for name in FILES))})
    record = dict(version=1, policy="second-source-heldout-loss-v1",
        scope="explicit-second-source-selection-set-not-independent-benchmark-or-historical-contamination-proof", epsilon=1e-6,
        sequence=cycle["sequence"], approved=approved, source_manifest_id=manifest["sha256"], publisher_key=publisher,
        source_revision="a" * 40, source_expires_unix_seconds=900, files=bound, model_id=trained["model"]["id"],
        model_revision=trained["model"]["revision"], baseline_input_adapter=reports["baseline"]["input_adapter"],
        candidate_input_adapter=reports["candidate"]["input_adapter"], baseline=reports["baseline"]["baseline_evaluation"],
        candidate=reports["candidate"]["baseline_evaluation"])
    files["validation.json"] = document(record)
    cycle["validation"] = dict(files=files)
    return record


def synthetic_chain(decisions=(True, True), losses=None, second_decisions=(True, True)):
    # Parser-only file/metric fixtures, never model execution or network evidence.
    def digest(number, size=100):
        return dict(bytes=size, sha256=f"{number:064x}")
    def adapters(number):
        return {name: digest(number + offset) for offset, name in enumerate(FILES)}
    source, owner = "a" * 64, "b" * 64
    original = dict(dataset=digest(20), adapter_bundle=digest(30), dataset_manifest_id="c" * 64,
                    adapter_manifest_id="d" * 64, adapter_files=adapters(1))
    base = dict(sha256="e" * 64, parameters=123)
    training = dict(adapter_after=dict(sha256="f" * 64, parameters=230400), base_after=base, outputs=["seed fixture"])
    enrollment = dict(repeat_sources=True, source_choice_uses_cache_inventory=False,
                      sources=[dict(publisher_key=source, name="disposable-agent-dataset", min_revision=1,
                                    manifest_id=original["dataset_manifest_id"])],
                      publication_key=owner, publish_name="disposable-loop-update", quality_policy=POLICY)
    state = dict(version=2, completed=2, latest=None, promoted=0, rejected=0, next_sequence=3, cycles=[], garbage=[])
    loop = dict(enrollment=enrollment, state=state, seed_files=original["adapter_files"], seed_dataset=original["dataset"], cycles=[])
    previous, previous_files = training, original["adapter_files"]
    for sequence, locally_approved in enumerate(decisions, 1):
        approved = locally_approved and second_decisions[sequence - 1]
        candidate_loss = losses[sequence - 1] if losses is not None else 1.5 if locally_approved else 2.5
        files = adapters(100 * sequence)
        trained = dict(input_adapter=dict(files=previous_files, applied_parameters=previous["adapter_after"]),
                       adapter_before=previous["adapter_after"], adapter_after=dict(sha256=f"{50 + sequence:064x}", parameters=230400),
                       base_before=base, base_after=base, outputs=["public fixture"],
                       dataset=dict(source_revision="a" * 40),
                       backend_versions=dict(torch="2.14.0+cpu", transformers="5.16.1", peft="0.20.0"),
                       model=dict(id="HuggingFaceTB/SmolLM2-135M-Instruct", revision=TRAIN["MODEL_REVISION"],
                                  files={"model.safetensors":dict(bytes=269060552, sha256=TRAIN["WEIGHT_HASH"])}),
                       baseline_evaluation=dict(loss=2.0, target_tokens=10),
                       adapted_evaluation=dict(loss=candidate_loss, target_tokens=10),
                       reloaded_evaluation=dict(loss=candidate_loss, target_tokens=10))
        trained["input_adapter"].update(applied=True, model_id=trained["model"]["id"], model_revision=TRAIN["MODEL_REVISION"],
                                        base_parameters_before_apply=base, base_parameters_after_apply=base)
        raw_report = json.dumps(trained).encode()
        bundle, publication, report_hash = digest(60 + sequence), digest(70 + sequence), file_digest(raw_report)
        result = dict(operation="compute_train_cycle", complete=True, updates_completed=8, input_adapter_applied=True,
                      dataset_manifest_id=original["dataset_manifest_id"], source_expires_unix_seconds=900,
                      training_report_sha256=report_hash["sha256"],
                      bundle=dict(dataset_manifest_id=original["dataset_manifest_id"], sha256=bundle["sha256"]))
        contribution = dict(manifest_id=publication["sha256"], publisher_key_hex=owner, network_publication=True,
                            serving=True, bytes=bundle["bytes"], expires_unix_seconds=899)
        cycle = dict(sequence=sequence, training=trained, result=result,
                     provenance=dict(dataset_manifest_id=original["dataset_manifest_id"], expires_unix_seconds=900),
                     manifest=dict(sha256=original["dataset_manifest_id"], bytes=100), dataset=original["dataset"], adapter_files=files,
                     report=report_hash, report_hex=raw_report.hex(), bundle=bundle,
                     publication=publication if approved else None, publication_hex="ab" if approved else None,
                     contribution=contribution if approved else None, rejected_publication_files_absent=not approved)
        identities = {name: digest(900 + index) for index, name in enumerate(CONTENT_FILES)}
        identities.update({"dataset.json": cycle["dataset"], "dataset.manifest": cycle["manifest"],
                           "training-report.json": report_hash, "adapter.bundle": bundle,
                           **{"training/adapter/" + name: info for name, info in files.items()}})
        cycle["content_files"] = identities
        validation = synthetic_validation(cycle, source, second_decisions[sequence - 1])
        cycle["evaluation"] = dict(version=1, policy=POLICY,
            scope="source-and-pinned-second-source-selection-only-not-independent-test-benchmark", epsilon=1e-6,
            sequence=sequence, predecessor=state["latest"],
            baseline_kind="configured_adapter" if state["latest"] is None else "approved_predecessor", approved=approved,
            source_manifest_id=original["dataset_manifest_id"], source_publisher_key=source, source_revision="a" * 40,
            files=identities, model_id=trained["model"]["id"], model_revision=TRAIN["MODEL_REVISION"],
            base_model=trained["model"]["files"]["model.safetensors"], base_parameters=base,
            input_adapter={key:trained["input_adapter"][key] for key in ("files", "applied_parameters")},
            candidate_adapter=files, candidate_parameters=trained["adapter_after"], validation=validation,
            baseline=trained["baseline_evaluation"], adapted=trained["adapted_evaluation"], reloaded=trained["reloaded_evaluation"])
        raw_decision = json.dumps(cycle["evaluation"]).encode()
        cycle.update(evaluation_file=file_digest(raw_decision), evaluation_hex=raw_decision.hex())
        loop["cycles"].append(cycle)
        state["cycles"].append(dict(sequence=sequence, phase="complete" if approved else "rejected",
            training=None, snapshot=dict(identities, **{"evaluation.json":cycle["evaluation_file"]},
                **{name:{key:value[key] for key in ("sha256", "bytes")} for name,value in cycle["validation"]["files"].items()}),
            publication=dict(manifest_id=publication["sha256"]) if approved else None))
        if approved:
            state["latest"] = sequence
            state["promoted"] += 1
            previous, previous_files = trained, files
        else:
            state["rejected"] += 1
    value = dict(loop=loop, originals=original, training=training,
                 dataset_publish=dict(publisher_key_hex=source, expires_unix_seconds=900),
                 owner_key=dict(identity_public_key_hex=owner),
                 summary=dict(operation="compute_train_loop", completed_cycles=2, attempts_this_invocation=2,
                              pending_publications=0, owner_cancelled=False, promoted_cycles=state["promoted"],
                              rejected_cycles=state["rejected"], latest_approved_sequence=state["latest"],
                              quality_policy=POLICY, independent_quality_benchmark=False),
                 adoption=adoption(loop), inference_isolation=None,
                 fetch=dict(publisher=owner, dataset_publisher=source,
                            adapter_manifest_id=loop["cycles"][state["latest"] - 1]["publication"]["sha256"] if state["latest"] else None,
                            dataset_manifest_id=original["dataset_manifest_id"], cache_only=False, model_activated=False),
                 received=dict(adapter_files=previous_files, dataset=original["dataset"]),
                 inference=dict(status="ok", mode="infer", updates_completed=0,
                                input_adapter=dict(files=previous_files, applied_parameters=previous["adapter_after"]),
                                outputs=previous["outputs"]))
    if state["latest"] is None:
        value.update(fetch=None, received=None, inference=None)
    return value


def self_test():
    # All four actual-decision branches are parser fixtures, not claimed ML outcomes.
    for decisions in ((True, True), (True, False), (False, True), (False, False)):
        check_chain(synthetic_chain(decisions))
        check_chain(synthetic_chain(second_decisions=decisions))
    check_chain(synthetic_chain((False, True), (2.0 - 1e-6, 0.0)))
    value = synthetic_chain()
    original, training, owner = value["originals"], value["training"], value["owner_key"]["identity_public_key_hex"]
    loop = value["loop"]
    check_chain(value)
    mutations = [
        (("loop", "enrollment", "repeat_sources"), False),
        (("loop", "enrollment", "source_choice_uses_cache_inventory"), True),
        (("summary", "pending_publications"), 1),
        (("loop", "state", "latest"), 1),
        (("loop", "cycles", 1, "result", "updates_completed"), 7),
        (("loop", "cycles", 1, "manifest", "sha256"), "0" * 64),
        (("loop", "cycles", 1, "provenance", "expires_unix_seconds"), 901),
        (("loop", "cycles", 1, "training", "input_adapter", "files"), original["adapter_files"]),
        (("loop", "cycles", 1, "contribution", "network_publication"), False),
        (("loop", "cycles", 1, "contribution", "expires_unix_seconds"), 901),
        (("fetch", "dataset_publisher"), owner),
        (("fetch", "adapter_manifest_id"), loop["cycles"][0]["publication"]["sha256"]),
        (("inference", "input_adapter", "applied_parameters"), training["adapter_after"]),
        (("loop", "cycles", 1, "evaluation", "approved"), False),
        (("loop", "cycles", 1, "evaluation", "predecessor"), None),
        (("loop", "cycles", 1, "evaluation", "epsilon"), 0),
        (("loop", "cycles", 1, "evaluation", "source_publisher_key"), owner),
        (("loop", "cycles", 1, "evaluation", "baseline", "target_tokens"), 11),
        (("loop", "cycles", 1, "evaluation", "reloaded", "loss"), 1.0),
        (("loop", "cycles", 1, "report_hex"), "00"),
        (("loop", "state", "promoted"), 0),
    ]
    for path, replacement in mutations:
        changed = copy.deepcopy(value)
        selected = changed
        for key in path[:-1]:
            selected = selected[key]
        selected[path[-1]] = replacement
        try:
            check_chain(changed)
        except (ValueError, KeyError):
            continue
        raise AssertionError("invalid synthetic coordinator chain accepted: " + repr(path))
    for changed in (synthetic_chain((False, False)), synthetic_chain((True, False))):
        changed["loop"]["cycles"][1]["publication"] = {"sha256":"a" * 64, "bytes":100}
        try:
            check_chain(changed)
        except ValueError:
            continue
        raise AssertionError("rejected candidate publication accepted")
    for filename, field, replacement in (("candidate-report.json", "mode", "train"),
                                         ("candidate-report.json", "updates_completed", 1),
                                         ("baseline-report.json", "input_adapter", {})):
        changed = synthetic_chain()
        files = changed["loop"]["cycles"][0]["validation"]["files"]
        envelope = json.loads(exported(files[filename]))
        envelope["report"][field] = replacement
        raw = json.dumps(envelope).encode()
        files[filename] = dict(file_digest(raw), hex=raw.hex())
        try:
            check_chain(changed)
        except (KeyError, ValueError):
            continue
        raise AssertionError("non-inference or wrong-adapter second-source report accepted")
    print("agent-train-loop checker: both gates/four outcomes, epsilon/zero-loss + 26 rejections PASS; synthetic only")
    observation_file_test()
    shared_updates_test()


def shared_updates_test():
    wire = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["wire"]
    owner = "11" * 32
    loop = {"cycles": [], "state": {"cycles": []}, "seed": {}}
    for sequence in (1, 2):
        payload = bytes([sequence]) * 32
        encoded = wire({1: wire({1: 1, 2: bytes.fromhex(owner), 3: 100, 4: 900,
            7: hashlib.sha256(payload).digest(), 8: payload}), 2: b"s" * 64})
        publication = file_digest(encoded)
        loop["cycles"].append(dict(sequence=sequence, evaluation=dict(approved=True),
            publication=publication, publication_hex=encoded.hex(), bundle=dict(bytes=1000),
            contribution=dict(manifest_id=publication["sha256"], publisher_key_hex=owner, revision=sequence,
                name="disposable-loop-update", operation="content_contribute", network_publication=True,
                serving=True, bytes=1000, chunks=4, expires_unix_seconds=900)))
        loop["state"]["cycles"].append(dict(sequence=sequence, phase="complete", publication=dict(manifest_id=publication["sha256"], expires=900)))
    original = {"dataset_manifest_id": "22" * 32, "adapter_manifest_id": "33" * 32,
                "dataset": dict(bytes=100, sha256="44" * 32), "adapter_bundle": dict(bytes=1000, sha256="55" * 32)}
    for kind, content, chunks in (("dataset", "dataset", 1), ("adapter", "adapter_bundle", 4)):
        loop["seed"][kind + "_receipt"] = dict(manifest_id=original[kind + "_manifest_id"], chunks=chunks, **original[content])
    for mask in range(4):
        status = dict(serving=True, replication_enabled=True, publications=2 + mask.bit_count(),
            replica_publications=2 + mask.bit_count(), replica_bytes=2000 + (100 if mask & 1 else 0) + (1000 if mask & 2 else 0),
            replica_chunks=8 + (1 if mask & 1 else 0) + (4 if mask & 2 else 0))
        matched = shared_updates(loop, original, owner, status, False)
        require(matched["publications"] == status["publications"]
                and matched["aggregate_status_is_manifest_inventory"] is False, "allowed known replica subset rejected")
        if mask & 1:
            shared_updates(loop, original, owner, status, True)
        else:
            try:
                shared_updates(loop, original, owner, status, True)
            except ValueError:
                pass
            else:
                raise AssertionError("required original dataset absent but accepted")
        for key in ("replica_bytes", "replica_chunks", "publications"):
            changed = dict(status)
            changed[key] += 1
            try:
                shared_updates(loop, original, owner, changed, False)
            except ValueError:
                continue
            raise AssertionError("unaccounted replica storage accepted")
    for approved_mask in range(3):
        selected = copy.deepcopy(loop)
        for index, cycle in enumerate(selected["cycles"]):
            if not approved_mask & (1 << index):
                cycle.update(evaluation=dict(approved=False), publication=None, publication_hex=None,
                             contribution=None, rejected_publication_files_absent=True)
                selected["state"]["cycles"][index].update(phase="rejected", publication=None)
        for original_mask in range(4):
            count = approved_mask.bit_count()
            status = dict(serving=True, replication_enabled=True,
                publications=count + original_mask.bit_count(), replica_publications=count + original_mask.bit_count(),
                replica_bytes=1000 * count + (100 if original_mask & 1 else 0) + (1000 if original_mask & 2 else 0),
                replica_chunks=4 * count + (1 if original_mask & 1 else 0) + (4 if original_mask & 2 else 0))
            matched = shared_updates(selected, original, owner, status, bool(original_mask & 1))
            require(len(matched["required_update_manifest_ids"]) == count, "rejected update counted as required")
    with_validation = copy.deepcopy(loop)
    provenance = {"manifest_id":"66" * 32, "dataset":dict(bytes=123, sha256="77" * 32),
                  "source_receipt":dict(manifest_id="66" * 32, bytes=123, chunks=1, sha256="77" * 32)}
    raw = json.dumps(provenance).encode()
    with_validation["validation_input"] = {"provenance.json":dict(file_digest(raw), hex=raw.hex())}
    for mask in range(8):
        expected = dict(serving=True, replication_enabled=True, publications=2 + mask.bit_count(),
            replica_publications=2 + mask.bit_count(), replica_bytes=2000 + (100 if mask & 1 else 0)
                + (1000 if mask & 2 else 0) + (123 if mask & 4 else 0),
            replica_chunks=8 + (1 if mask & 1 else 0) + (4 if mask & 2 else 0) + (1 if mask & 4 else 0))
        shared_updates(with_validation, original, owner, expected, bool(mask & 1))
    wrong = copy.deepcopy(loop)
    wrong["cycles"][1]["contribution"]["manifest_id"] = original["dataset_manifest_id"]
    try:
        shared_updates(wrong, original, owner, status, False)
    except ValueError:
        pass
    else:
        raise AssertionError("wrong contributed update identity accepted")
    print("agent-train-loop exact replica-subset accounting + missing-dataset/storage/identity rejections PASS; synthetic only")


def observation_file_test():
    # Actual exclusive filesystem publication, no model, subprocess or network fixture.
    with tempfile.TemporaryDirectory(prefix="volparossa-loop-observation-") as directory:
        root = Path(directory)
        raw, output = root / "loop-1-isolation.raw.json", root / "loop-1-isolation.json"
        original = dict(observed=True, worker=dict(pid=123, start_ticks=456), exact_input_inodes={"fixture": True})
        write(raw, original)
        before, raw_bytes = raw.stat(), raw.read_bytes()
        exact = dict.fromkeys(FILES, True)
        final = publish_observation(raw, output, 1, exact)
        after = output.stat()
        require(read(output) == final and read(raw) == original and raw.read_bytes() == raw_bytes,
                "raw evidence overwritten or final evidence absent")
        require((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode))
                == (before.st_uid, before.st_gid, 0o600)
                and (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                and final["warmstart_exact_inodes"] == exact, "published file lost owner/inode evidence")
        saved = output.read_bytes()
        try:
            publish_observation(raw, output, 1, exact)
        except FileExistsError:
            pass
        else:
            raise AssertionError("existing final observation overwritten")
        require(output.read_bytes() == saved and raw.read_bytes() == raw_bytes, "replay changed existing evidence")
        invalid = root / "invalid-report.json"
        write(invalid, {"report_kind": "deliberately-invalid-checker-fixture"})
        result = subprocess.run([sys.executable, "-B", str(HERE / "agent-train-loop-smoke.py"),
                                 "report", str(invalid), "a" * 40],
                                check=False, capture_output=True, timeout=10)
        require(result.returncode != 0 and b"incomplete source-bound loop report" in result.stderr
                and b"AttributeError" not in result.stderr, "report CLI failed before validating the actual supplied file")
        require(readiness_state(root, 1)["stage"] == "state_absent", "missing state relabeled ready")
        (root / "loop").mkdir(mode=0o700)
        state = {"version": 2, "cycles": [], "seed": None, "next_sequence": 1, "completed": 0}
        save_readiness(root / "loop/state.json", state)
        require(readiness_state(root, 1)["stage"] == "seed_wait", "unfinished seed relabeled admitted")
        state["seed"] = {"synthetic_metadata_only": True}
        save_readiness(root / "loop/state.json", state)
        require(readiness_state(root, 1)["stage"] == "validation_wait", "unfinished second-source fetch relabeled admitted")
        state["validation"] = {"synthetic_source_metadata_only": True}
        save_readiness(root / "loop/state.json", state)
        require(readiness_state(root, 1)["stage"] == "admission_wait", "seed completion relabeled model execution")
        state["cycles"] = [{"sequence": 1, "phase": "running"}]
        save_readiness(root / "loop/state.json", state)
        require(readiness_state(root, 1)["stage"] == "running", "durable admitted cycle not recognized")
    print("agent-train-loop raw-to-final exclusive observation file test PASS; no model/network")
    capacity_view_test()


def capacity_view_test():
    process = Path("/proc/12345")
    view = process / "root"
    supplied = {
        process / "cgroup": "0::/user.slice/test.scope\n",
        process / "mountinfo": "21 1 0:5 / /proc rw,nosuid - proc proc rw\n"
            "22 1 0:6 / /sys ro,nosuid - sysfs sysfs ro\n"
            "23 22 0:7 / /sys/fs/cgroup ro,nosuid - cgroup2 cgroup2 ro\n",
        view / "proc/pressure/cpu": "some avg10=2.00 avg60=1.00 total=123\n",
        view / "proc/pressure/io": "some avg10=0.00 avg60=0.00 total=0\n",
        view / "proc/meminfo": "MemAvailable: 1048576 kB\n",
        view / "sys/fs/cgroup/user.slice/test.scope/memory.max": "max\n",
        view / "sys/fs/cgroup/user.slice/test.scope/memory.current": "100\n",
        view / "sys/fs/cgroup/user.slice/memory.max": "max\n",
        view / "sys/fs/cgroup/cgroup.controllers": "cpu memory pids\n",
    }
    visited = []
    def selected(path, maximum):
        visited.append(path)
        value = supplied.get(path)
        require(value is None or len(value.encode()) <= maximum, "synthetic resource exceeded read bound")
        return value
    actual = capacity_diagnostic(12345, selected)
    require(actual["view"] == "coordinator_proc_root" and actual["observed_pid"] == 12345
            and actual["cpu_some_avg10"] == 2.0 and actual["io_some_avg10"] == 0.0
            and actual["mem_available_bytes"] == 1073741824
            and actual["resource_mounts"][2]["filesystem"] == "cgroup2"
            and actual["cgroup"]["ancestors"][0]["memory.max"] == "max\n"
            and actual["budget_decision_inferred"] is False, "coordinator resource view not retained")
    require(all(path.is_relative_to(view) or path in (process / "cgroup", process / "mountinfo") for path in visited),
            "observer substituted guest resource files")
    supplied = {process / "cgroup": "0::/user.slice/test.scope\n"}
    missing = capacity_diagnostic(12345, selected)
    require(missing["cpu_some_avg10"] is None and missing["io_some_avg10"] is None
            and missing["mem_available_bytes"] is None and missing["resource_mounts"] is None
            and all(row["memory.max"] is None for row in missing["cgroup"]["ancestors"]),
            "missing coordinator view silently used guest telemetry")
    print("agent-train-loop coordinator-root telemetry selection/missing-view tests PASS; synthetic only")


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        self_test()
    elif len(args) == 4 and args[0] == "shared":
        require(args[3] in ("true", "false"), "invalid shared dataset requirement")
        print(json.dumps(shared(Path(args[1]), args[2], args[3] == "true")))
    elif len(args) == 4 and args[0] == "setup":
        setup(*args[1:])
    elif len(args) == 3 and args[0] == "validation-input":
        validation_input(*args[1:])
    elif len(args) == 3 and args[0] == "validation-original":
        print(json.dumps(validation_original(*args[1:])))
    elif len(args) == 2 and args[0] == "drop-validation":
        print(json.dumps(drop_validation(args[1])))
    elif len(args) == 5 and args[0] == "observe-loop":
        observe_loop(int(args[1]), args[2], Path(args[3]), int(args[4]))
    elif len(args) == 2 and args[0] == "collect":
        print(json.dumps(collect(args[1])))
    elif len(args) == 2 and args[0] == "adoption":
        print(json.dumps(adoption(read(Path(args[1]), 1048576))))
    elif len(args) == 3 and args[0] == "last-json":
        print(json.dumps(last_json(args[1], args[2])))
    elif len(args) == 3 and args[0] == "evidence":
        evidence(Path(args[1]), args[2])
    elif len(args) == 2 and args[0] == "cleanup":
        print(json.dumps(cleanup(args[1])))
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif len(args) == 3 and args[0] == "report":
        report(read(Path(args[1]), 1048576), args[2])
    else:
        raise SystemExit("invalid agent-train-loop fixture command")


if __name__ == "__main__":
    main()
