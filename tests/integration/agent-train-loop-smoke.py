#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable real public seed -> two autonomous cycles -> another peer import.

Pure checker fixtures are not training/network evidence. Model execution is guest-only.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
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
SCOPE = ("R5 publishes a public dataset/seed; R4 independently imports that seed, runs two owner-enabled eight-update "
         "training-loop cycles on the same explicitly repeated dataset, warmstarts cycle two from cycle one and automatically "
         "contributes both owner-signed updates; Main Client imports the second update and original separately signed dataset "
         "through protected MPTCP and performs inference; shared explicitly provisioned base/runtime, not fresh corpus "
         "discovery, joint optimization, model-quality improvement, full B05 or full alpha")


def setup(path, publisher, manifest):
    root = ART["private_root"](path)
    require(TRAIN["HASH"].fullmatch(publisher) and TRAIN["HASH"].fullmatch(manifest), "invalid selected source")
    write(root / "loop-plan.json", {"version": 1, "sources": [{"publisher_key": publisher,
          "name": "disposable-agent-dataset", "min_revision": 1, "manifest_id": manifest}]})
    write(root / "loop-seed.json", {"publisher_key": publisher, "dataset_publisher_key": publisher,
          "name": "disposable-agent-adapter", "dataset_name": "disposable-agent-dataset", "min_revision": 1})
    (root / "loop-passphrase").write_bytes(os.urandom(32).hex().encode() + b"\n")
    (root / "loop-passphrase").chmod(0o600)


def readiness_state(root, sequence):
    path = root / "loop/state.json"
    if not path.exists():
        return {"stage": "state_absent", "seed_ready": False, "cycles": []}
    state = read(path)
    require(state["version"] == 1 and isinstance(state["cycles"], list) and len(state["cycles"]) <= 8,
            "invalid durable coordinator readiness state")
    cycles = [{"sequence": row["sequence"], "phase": row["phase"]} for row in state["cycles"]]
    current = next((row for row in cycles if row["sequence"] == sequence), None)
    stage = current["phase"] if current else "admission_wait" if state["seed"] is not None else "seed_wait"
    return {"stage": stage, "seed_ready": state["seed"] is not None,
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
        adapter = root / "loop/seed-input/adapter" if sequence == 1 else root / "loop/cycle-0000000000000001/training/adapter"
        mounts = [line.split()[5].split(",") for line in (worker / "mountinfo").read_text().splitlines()
                  if line.split()[4] == "/adapter"]
        require(len(mounts) == 1 and "ro" in mounts[0], "warmstart adapter mount is not readonly")
        exact = {}
        for name in FILES:
            mounted, actual = (worker / "root/adapter" / name).stat(), (adapter / name).stat()
            exact[name] = (mounted.st_dev, mounted.st_ino) == (actual.st_dev, actual.st_ino)
        require(all(exact.values()), "worker did not use the exact seed/predecessor adapter")
        evidence = publish_observation(raw, output, sequence, exact)
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
    require(observations[0]["worker"] != observations[1]["worker"], "one worker relabeled as two cycles")


def publish_observation(raw, output, sequence, exact):
    require(raw.parent == output.parent and sequence in (1, 2)
            and raw.name == f"loop-{sequence}-isolation.raw.json"
            and output.name == f"loop-{sequence}-isolation.json", "unexpected observer output names")
    owner = raw.lstat()
    require(stat.S_ISREG(owner.st_mode) and stat.S_IMODE(owner.st_mode) == 0o600
            and owner.st_nlink == 1 and owner.st_uid == raw.parent.stat().st_uid,
            "raw observer output ownership differs")
    require(set(exact) == set(FILES) and all(value is True for value in exact.values()), "warmstart inodes differ")
    evidence = read(raw)
    evidence.update(sequence=sequence, warmstart_readonly=True, warmstart_exact_inodes=exact)
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
        cycles.append(dict(sequence=sequence, training=trained, isolation=read(root / f"loop-{sequence}-isolation.json"),
                           raw_isolation=read(root / f"loop-{sequence}-isolation.raw.json"),
                           result=read(cycle / "result.json"), provenance=read(cycle / "source-provenance.json"),
                           selection=read(cycle / "selection.json"), adapter_files=files, manifest=manifest, bundle=bundle,
                           dataset=file_hash(cycle / "dataset.json", 1048576),
                           report=file_hash(cycle / "training-report.json", 65536),
                           publication=file_hash(cycle / "publication.pb", 65536),
                           publication_hex=(cycle / "publication.pb").read_bytes().hex(),
                           contribution=read(cycle / "contribution.json")))
    return dict(state=read(loop / "state.json"), enrollment=read(loop / "enrollment.json"),
                seed=read(loop / "seed-input/provenance.json"), cycles=cycles,
                seed_files={name: file_hash(loop / "seed-input/adapter" / name, 2 * 1024 ** 2) for name in FILES},
                seed_dataset=file_hash(loop / "seed-input/dataset.json", 1048576),
                base_after=file_hash(root / "provision/model/model.safetensors", 300000000))


def last_json(path, operation):
    raw = Path(path).read_bytes()
    require(len(raw) <= 1048576, "oversized coordinator output")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    matches = [row for row in rows if row.get("operation") == operation]
    require(len(matches) == 1, "missing or duplicate final coordinator receipt")
    return matches[0]


def check_chain(evidence):
    loop, original = evidence["loop"], evidence["originals"]
    plan, state = loop["enrollment"], loop["state"]
    source, owner = evidence["dataset_publish"]["publisher_key_hex"], evidence["owner_key"]["identity_public_key_hex"]
    require(source != owner, "dataset and trained-update publishers are not independent")
    require(plan["repeat_sources"] is True and plan["source_choice_uses_cache_inventory"] is False
            and plan["sources"] == [{"publisher_key": source, "name": "disposable-agent-dataset", "min_revision": 1,
                                    "manifest_id": original["dataset_manifest_id"]}], "wrong explicitly repeated source plan")
    require(plan["publication_key"] == owner and plan["publish_name"] == "disposable-loop-update", "wrong enrolled update publisher")
    require(state["completed"] == 2 and state["latest"] == 2 and state["next_sequence"] == 3
            and len(state["cycles"]) == 2 and state["garbage"] == [], "two retained completed cycles missing")
    summary = evidence["summary"]
    require(summary["operation"] == "compute_train_loop" and summary["completed_cycles"] == 2
            and summary["attempts_this_invocation"] == 2 and summary["pending_publications"] == 0
            and summary["owner_cancelled"] is False, "coordinator did not complete and share two attempts")
    require(loop["seed_files"] == original["adapter_files"] and loop["seed_dataset"] == original["dataset"], "wrong received initial seed")
    previous = evidence["training"]
    previous_files = original["adapter_files"]
    expiry = evidence["dataset_publish"]["expires_unix_seconds"]
    for index, cycle in enumerate(loop["cycles"], 1):
        trained, result, provenance = cycle["training"], cycle["result"], cycle["provenance"]
        require(cycle["sequence"] == state["cycles"][index - 1]["sequence"] == index
                and state["cycles"][index - 1]["phase"] == "complete", "wrong durable cycle phase")
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
        contribution = cycle["contribution"]
        require(contribution["manifest_id"] == cycle["publication"]["sha256"]
                == state["cycles"][index - 1]["publication"]["manifest_id"]
                and contribution["publisher_key_hex"] == owner and contribution["network_publication"] is True
                and contribution["serving"] is True and contribution["bytes"] == cycle["bundle"]["bytes"], "automatic own contribution missing")
        require(0 < contribution["expires_unix_seconds"] <= expiry, "new update extends original dataset validity")
        previous, previous_files = trained, cycle["adapter_files"]
    fetched = evidence["fetch"]
    require(fetched["publisher"] == owner and fetched["dataset_publisher"] == source
            and fetched["adapter_manifest_id"] == loop["cycles"][1]["publication"]["sha256"]
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


def check_evidence(evidence, revision):
    require(evidence["source_revision"] == revision, "wrong source revision")
    check_chain(evidence)
    loop = evidence["loop"]
    for name, mandatory in (("loop-shared", False), ("loop-all-shared", True)):
        shared_updates(loop, evidence["originals"], evidence["owner_key"]["identity_public_key_hex"],
                       evidence["sharing_status"][name], mandatory)
    TRAIN["check_worker"](evidence["training"], revision)
    TRAIN["check_isolation"](evidence["training_isolation"])
    require(evidence["training_isolation"]["node_lineage"]["node"] == "relay5", "seed did not originate on R5")
    node_lineage = None
    for cycle in loop["cycles"]:
        TRAIN["check_worker"](cycle["training"], revision)
        observed = cycle["isolation"]
        require({key: value for key, value in observed.items()
                 if key not in ("sequence", "warmstart_readonly", "warmstart_exact_inodes")} == cycle["raw_isolation"],
                "final observation changed its original raw process/input evidence")
        TRAIN["check_isolation"](observed)
        require(observed["node_lineage"]["node"] == "relay4" and observed["warmstart_readonly"] is True
                and set(observed["warmstart_exact_inodes"]) == set(FILES)
                and all(observed["warmstart_exact_inodes"].values()), "actual private predecessor mount missing")
        if node_lineage is not None:
            require(observed["node_lineage"] == node_lineage, "coordinator moved to another node")
        node_lineage = observed["node_lineage"]
        require(cycle["training"]["supervisor"]["spare_capacity"] is True, "autonomous worker bypasses owner budget")
        encoded = bytes.fromhex(cycle["publication_hex"])
        require(file_digest(encoded) == cycle["publication"], "original publication bytes were relabeled")
        envelope = ART["CUSTODY"]["fields"](encoded, 65536)
        body = ART["CUSTODY"]["fields"](envelope[1], 65536)
        require(len(envelope[2]) == 64 and body[2].hex() == evidence["owner_key"]["identity_public_key_hex"]
                and body[4] == cycle["contribution"]["expires_unix_seconds"]
                and hashlib.sha256(body[8]).digest() == body[7], "signed update publisher/expiry/payload differs")
    workers = [evidence["training_isolation"], *(cycle["isolation"] for cycle in loop["cycles"]), evidence["inference_isolation"]]
    require(len({(item["worker"]["pid"], item["worker"]["start_ticks"]) for item in workers}) == 4, "actual worker identities reused")
    namespaces = [workers[index]["node_lineage"]["network_namespace"] for index in (0, 1, 3)]
    require(len(set(namespaces)) == 3, "producer/trainer/importer are not different node namespaces")
    TRAIN["check_isolation"](evidence["inference_isolation"])
    require(evidence["inference_isolation"]["node_lineage"]["node"] == "client"
            and evidence["inference_isolation"]["received_adapter_readonly"] is True
            and all(evidence["inference_isolation"]["received_adapter_exact_inodes"].values()), "wrong importer worker")
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
        receipt = evidence["fetch"][kind + "_receipt"]
        require(receipt["provider_peer_ids"] == [peers["relay4"]] and receipt["providers_used"] == 1
                and receipt["bytes"] == receipt["peer_bytes"] > 0
                and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0, "final object bypassed protected R4")
    REP["validate_phase"](evidence["phases"]["uptake"], "uptake", peers,
                          evidence["originals"]["adapter_bundle"]["bytes"] + evidence["originals"]["dataset"]["bytes"])
    REP["validate_phase"](evidence["phases"]["reserve-fetch"], "reserve-fetch", peers,
                          loop["cycles"][1]["bundle"]["bytes"] + evidence["originals"]["dataset"]["bytes"])
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
            and evidence["source_restart"]["restored_publications"] == 2, "original provider restart/reopen missing")
    require(evidence["provision"]["success"] is True and evidence["provision"]["training_performed"] is False,
            "explicit verified guest provisioning missing")
    require(all(evidence["cleanup"].values()) and all(evidence["content_isolation"].values()), "owned cleanup or cross-node storage isolation missing")


def file_digest(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def shared_updates(loop, original, owner, status, require_dataset):
    """Exact contributed updates plus accounted optional original replicas.

    Status is aggregate storage accounting, not an inventory API. The two
    update identities are bound by their actual completed contribution receipts;
    only the independently known source/seed can explain additional accounting.
    The later protected import still proves real serving of the selected update.
    """
    require(status["serving"] is True and status["replication_enabled"] is True
            and len(loop["cycles"]) == len(loop["state"]["cycles"]) == 2, "updates not served by the actual replica runtime")
    required_ids, required_bytes, required_chunks = [], 0, 0
    for index, cycle in enumerate(loop["cycles"], 1):
        contribution = cycle["contribution"]
        saved = loop["state"]["cycles"][index - 1]
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
    require(len(set(required_ids + [entry[0] for entry in extras])) == 4, "original and trained publication identities overlap")
    for mask in range(4):
        if require_dataset and not mask & 1:
            continue
        selected = [item for index, item in enumerate(extras) if mask & (1 << index)]
        count = 2 + len(selected)
        if (status["publications"] == status["replica_publications"] == count
                and status["replica_bytes"] == required_bytes + sum(item[1] for item in selected)
                and status["replica_chunks"] == required_chunks + sum(item[2] for item in selected)):
            return {"required_update_manifest_ids": required_ids,
                    "accounted_original_manifest_ids": [item[0] for item in selected],
                    "publications": count, "bytes": status["replica_bytes"], "chunks": status["replica_chunks"],
                    "dataset_required": require_dataset, "aggregate_status_is_manifest_inventory": False}
    raise ValueError("replica accounting is not the two updates plus an allowed exact original subset")


def shared(work, label, require_dataset):
    require(label in ("loop-shared", "loop-all-shared"), "invalid sharing guard label")
    return shared_updates(read(work / "agent-train-loop-loop.json", 1048576), read(work / "agent-artifact-originals.json"),
                          read(work / "agent-train-loop-owner-key.json")["identity_public_key_hex"],
                          read(work / f"content-custody-relay4-{label}.json"), require_dataset)


def evidence(work, revision):
    names = ("loop", "summary", "owner-key", "fetch", "initial-fetch", "dataset-export", "dataset-contribute", "source-stop", "content-isolation", "cleanup")
    result = {name.replace("-", "_"): read(work / f"agent-train-loop-{name}.json", 1048576) for name in names}
    for name in ("training", "training-isolation", "inference", "inference-isolation", "originals", "received", "dataset-publish", "adapter-publish", "source-removed", "provision"):
        result[name.replace("-", "_")] = read(work / f"agent-artifact-{name}.json")
    result.update(source_revision=revision, peers=read(work / "a01-expected-peers.json"))
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
                        for name in ("uptake", "reserve-fetch")}
    check_evidence(result, revision)
    write(work / "agent-train-loop-evidence.json", result)


def cleanup(path):
    root = Path(path)
    require(root.is_absolute() and root.name == "agent-artifact-user", "wrong private cleanup root")
    ended = True
    if root.exists():
        ART["private_root"](root)
        for sequence in (1, 2):
            for suffix in (".raw.json", ".json"):
                record = root / f"loop-{sequence}-isolation{suffix}"
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
          fresh_corpus_discovery_claimed=False, shared_base_distribution_claimed=False, full_b05_claimed=False, full_alpha_claimed=False,
          cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host))


def report(value, revision):
    require(value["report_kind"] == "volparossa-public-agent-train-loop" and value["source_revision"] == revision
            and value["success"] is True and value["scope"] == SCOPE, "incomplete source-bound loop report")
    require(value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "guest cleanup differs")
    require(all(value[key] is False for key in ("fresh_corpus_discovery_claimed", "shared_base_distribution_claimed", "full_b05_claimed", "full_alpha_claimed")), "unsupported scope")
    check_evidence(value["evidence"], revision)


def self_test():
    # Source/ownership/chain regressions only: never a fabricated live training report.
    def digest(number, size=100):
        return dict(bytes=size, sha256=f"{number:064x}")
    def adapters(number):
        return {name: digest(number + offset) for offset, name in enumerate(FILES)}
    source, owner = "a" * 64, "b" * 64
    original = dict(dataset=digest(20), adapter_bundle=digest(30), dataset_manifest_id="c" * 64,
                    adapter_manifest_id="d" * 64, adapter_files=adapters(1))
    base = dict(sha256="e" * 64, parameters=123)
    training = dict(adapter_after=digest(40), base_after=base)
    enrollment = dict(repeat_sources=True, source_choice_uses_cache_inventory=False,
                      sources=[dict(publisher_key=source, name="disposable-agent-dataset", min_revision=1,
                                    manifest_id=original["dataset_manifest_id"])],
                      publication_key=owner, publish_name="disposable-loop-update")
    state = dict(completed=2, latest=2, next_sequence=3, cycles=[], garbage=[])
    loop = dict(enrollment=enrollment, state=state, seed_files=original["adapter_files"], seed_dataset=original["dataset"], cycles=[])
    previous, previous_files = training, original["adapter_files"]
    for sequence in (1, 2):
        files = adapters(100 * sequence)
        trained = dict(input_adapter=dict(files=previous_files, applied_parameters=previous["adapter_after"]),
                       adapter_before=previous["adapter_after"], adapter_after=digest(50 + sequence),
                       base_before=base, base_after=base, outputs=["public fixture"])
        bundle, publication, report_hash = digest(60 + sequence), digest(70 + sequence), digest(80 + sequence)
        result = dict(operation="compute_train_cycle", complete=True, updates_completed=8, input_adapter_applied=True,
                      dataset_manifest_id=original["dataset_manifest_id"], source_expires_unix_seconds=900,
                      training_report_sha256=report_hash["sha256"],
                      bundle=dict(dataset_manifest_id=original["dataset_manifest_id"], sha256=bundle["sha256"]))
        contribution = dict(manifest_id=publication["sha256"], publisher_key_hex=owner, network_publication=True,
                            serving=True, bytes=bundle["bytes"], expires_unix_seconds=899)
        cycle = dict(sequence=sequence, training=trained, result=result,
                     provenance=dict(dataset_manifest_id=original["dataset_manifest_id"], expires_unix_seconds=900),
                     manifest=dict(sha256=original["dataset_manifest_id"]), dataset=original["dataset"], adapter_files=files,
                     report=report_hash, bundle=bundle, publication=publication, contribution=contribution)
        loop["cycles"].append(cycle)
        state["cycles"].append(dict(sequence=sequence, phase="complete", publication=dict(manifest_id=publication["sha256"])))
        previous, previous_files = trained, files
    value = dict(loop=loop, originals=original, training=training,
                 dataset_publish=dict(publisher_key_hex=source, expires_unix_seconds=900),
                 owner_key=dict(identity_public_key_hex=owner),
                 summary=dict(operation="compute_train_loop", completed_cycles=2, attempts_this_invocation=2,
                              pending_publications=0, owner_cancelled=False),
                 fetch=dict(publisher=owner, dataset_publisher=source,
                            adapter_manifest_id=loop["cycles"][1]["publication"]["sha256"],
                            dataset_manifest_id=original["dataset_manifest_id"], cache_only=False, model_activated=False),
                 received=dict(adapter_files=previous_files, dataset=original["dataset"]),
                 inference=dict(status="ok", mode="infer", updates_completed=0,
                                input_adapter=dict(files=previous_files, applied_parameters=previous["adapter_after"]),
                                outputs=previous["outputs"]))
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
    print("agent-train-loop chain checker: positive + 13 rejections PASS; synthetic only")
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
        loop["cycles"].append(dict(sequence=sequence, publication=publication, publication_hex=encoded.hex(), bundle=dict(bytes=1000),
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
        state = {"version": 1, "cycles": [], "seed": None, "next_sequence": 1, "completed": 0}
        save_readiness(root / "loop/state.json", state)
        require(readiness_state(root, 1)["stage"] == "seed_wait", "unfinished seed relabeled admitted")
        state["seed"] = {"synthetic_metadata_only": True}
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
    elif len(args) == 5 and args[0] == "observe-loop":
        observe_loop(int(args[1]), args[2], Path(args[3]), int(args[4]))
    elif len(args) == 2 and args[0] == "collect":
        print(json.dumps(collect(args[1])))
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
