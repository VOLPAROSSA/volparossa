#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual P -> approved peer Q -> local corruption -> automatic P recovery.

Only self-test is host-safe. Every executable phase requires the disposable
guest guard. R4 fetches its signed training sources and Q through its own protected
route. Only R5's seed/cache is explicitly owner-provisioned. No model or decision
is synthesized by this file.
"""
import copy
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SUCCESSOR = runpy.run_path(str(HERE / "agent-successor-serving-smoke.py"))
REP = runpy.run_path(str(HERE / "content-replication-smoke.py"))
JOBS, TRAIN, ART, CUSTODY, COLLECTION = (SUCCESSOR[k] for k in ("JOBS", "TRAIN", "ART", "CUSTODY", "COLLECTION"))
read, write, require, file_hash, digest = (SUCCESSOR[k] for k in ("read", "write", "require", "file_hash", "digest"))
PREFIX = "agent-active-recovery"
KIND = "volparossa-active-local-adapter-integrity-recovery"
SCOPE = ("Actual public training P; a distinct node trains from signed P and publishes approved Q; "
         "the learner independently compares Q with P, then automatically retires only its damaged local Q extraction, "
         "restores original unexpired P, serves a protected job and resumes real training from P. "
         "Original signed bundles, approvals, receipts and enrollment are preserved. R4 cold-fetches signed sources "
         "and Q over its own protected route; only R5 seed/cache is explicitly owner-provisioned. "
         "No publisher ban, general quality, Byzantine recovery, "
         "full B07 or complete-alpha claim.")
FILES = SUCCESSOR["FILES"]
ROUND = "peer-update-0000000000000001"
MAX_PROOF = 24 * 1024 * 1024


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def private(work, node):
    require(node in ("relay4", "relay5"), "unexpected recovery node")
    return work / f"state-{node}/compute"


def layout(work):
    result = read(work / "agent-jobs-layout.json")
    require(result["provider_nodes"] == ["relay4", "relay5"], "unexpected recovery layout")
    require(result["provider_keys"]["relay4"] != result["provider_keys"]["relay5"], "same peer identity")
    return result


def owned_write(path, value, owner):
    write(path, value)
    os.chown(path, owner.st_uid, owner.st_gid)


def source_training_dataset(work, revision):
    # kvm-alpha-topology stages the original README here, not alongside the
    # source helper. Keep this identical to the existing agent-jobs provision.
    return ART["dataset"](revision, (work / "bin/agent-jobs-README.md").read_text())


def sources(work, revision):
    source = private(work, "relay5") / "recovery-source"
    owner = source.parent.stat()
    source.mkdir(mode=0o700)
    os.chown(source, owner.st_uid, owner.st_gid)
    dataset = source_training_dataset(work, revision)
    owned_write(source / "train.json", dataset, owner)
    validation = copy.deepcopy(dataset)
    validation["train"] = []
    validation["heldout"] = [dict(question="Does each permitted parallel route contain one intermediary relay?",
        answer="Exactly one distinct relay.", context=dataset["train"][0]["context"])]
    validation["inference"] = [dict(question="Which node count is permitted per parallel route?",
        context=dataset["train"][0]["context"])]
    owned_write(source / "validation.json", validation, owner)
    subsequent = copy.deepcopy(dataset)
    subsequent["train"][0]["question"] = "What is the relay count in a normal VOLPAROSSA path?"
    subsequent["train"][1]["question"] = "Is bypassing the relay allowed for normal clients?"
    owned_write(source / "next.json", subsequent, owner)


def cache_move(work, node, label, outbound):
    require(node == "relay5", "learner cache must not be fixture-relocated")
    node_cache = private(work, node) / "source-cache"
    transit = work / "state-client/compute-source/recovery-cache"
    source, target = (node_cache, transit) if outbound else (transit, node_cache)
    if outbound and not source.exists():
        require(not os.path.lexists(transit), "another cache relocation is active")
        write(record(work, f"{label}-cache-out"), dict(initial=True, node=node))
        return
    before = SUCCESSOR["tree"](source)
    old, new = SUCCESSOR["relocate_cache"](source, target)
    require(before == SUCCESSOR["tree"](target), "relocation changed public cache bytes")
    write(record(work, f"{label}-cache-{'out' if outbound else 'in'}"), dict(initial=False, node=node,
        before_identity=old, after_identity=new, files=before, source_absent=not os.path.lexists(source),
        explicit_fixture_relocation=True, learner_network_acquisition_claimed=False))


def enroll(work):
    peers = layout(work)
    publisher = peers["provider_keys"]["relay5"]
    source = dict(publisher_key=publisher, name="disposable-recovery-train", min_revision=1,
                  manifest_id=read(record(work, "train-publish"))["manifest_id"])
    validation = dict(publisher_key=publisher, name="disposable-recovery-validation", min_revision=1,
                      manifest_id=read(record(work, "validation-publish"))["manifest_id"])
    for node in ("relay4", "relay5"):
        root = private(work, node)
        plan = (dict(version=2, sources=[], catalogs=[dict(publisher_key=publisher,
                    name="disposable-recovery-catalog", min_revision=1)]) if node == "relay4"
                else dict(version=1, sources=[source]))
        owned_write(root / "plan.json", plan, root.stat())
        owned_write(root / "validation.json", validation, root.stat())
    root = private(work, "relay4")
    owned_write(root / "channels.json", dict(version=1, channels=[dict(publisher_key=publisher,
        name="disposable-recovery-q", min_revision=1)]), root.stat())
    root = private(work, "relay5")
    owned_write(root / "seed.json", dict(publisher_key=peers["provider_keys"]["relay4"],
        dataset_publisher_key=publisher, name="disposable-recovery-p", dataset_name=source["name"], min_revision=1), root.stat())


def catalog(work, revision):
    require(revision in (1, 2), "unexpected catalog revision")
    root = private(work, "relay5") / "recovery-source"
    names = ["train"] if revision == 1 else ["train", "next"]
    rows = [dict(name=f"disposable-recovery-{name}", revision=1,
                 manifest_id=read(record(work, f"{name}-publish"))["manifest_id"]) for name in names]
    owned_write(root / f"catalog-{revision}.json", dict(version=1, visibility="public", purpose="agent_training",
        dataset_profile="application/vnd.volparossa.agent-dataset.v1+json", license="GPL-3.0-only", sources=rows), root.stat())


def learner_isolation(work):
    root = private(work, "relay4")
    pid = int(subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
                                     "volparossa-alpha-agent@relay4.service"], text=True))
    require(pid > 0, "learner service stopped")
    owner_info = root.stat()
    command = ["nsenter", "--target", str(pid), "--mount", "setpriv",
        f"--reuid={owner_info.st_uid}", f"--regid={owner_info.st_gid}", "--clear-groups",
        "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--", "test", "-r"]
    own = subprocess.run([*command, str(root / "plan.json")], timeout=10, check=False).returncode
    remote = {name: subprocess.run([*command, str(path)], timeout=10, check=False).returncode for name, path in
              (("publisher_dataset", private(work, "relay5") / "recovery-source/train.json"),
               ("client_cache", work / "state-client/compute-source/cache"))}
    require(own == 0 and all(code == 1 for code in remote.values()), "learner can read another node's source/cache")
    write(record(work, "learner-isolation"), dict(node="relay4", own_plan_readable=True,
        foreign_sources_unreadable=True, node_mount_namespace=os.readlink(f"/proc/{pid}/ns/mnt"),
        source_cache_files=bounded_tree(root / "source-cache"), cache_initializer=read(record(work, "learner-cache-init"))))


def network_path(work, label):
    require(label in ("p", "adoption", "continued", "job-p", "job-q", "job-restored", "receipts"), "unknown network phase")
    prefix = f"{PREFIX}-path-{label}"
    value = dict(layout=read(work / f"{prefix}-layout.json"),
        selected_route=read(work / f"{prefix}-selection.json"), route=read(work / f"{prefix}-live-selection.json"),
        captures={role: read(work / f"{prefix}-{role}.json") for role in REP["ROLES"]},
        disconnected=True)
    check_network_path(value, "uptake" if label in ("p", "adoption", "continued") else "reserve-fetch",
                       read(work / "a01-expected-peers.json"))
    write(record(work, f"network-{label}"), value)


def check_network_path(value, phase, peers, minimum_bytes=1):
    layout_ = REP["CAPTURE"]["validate_layout"](value["layout"])
    REP["validate_route"](value["selected_route"], peers)
    REP["validate_route"](value["route"], peers)
    require(layout_["phase"] == phase and value["disconnected"] is True
            and value["selected_route"]["route_context_id"] == value["route"]["route_context_id"]
            and set(layout_["relays"]) == {slot["relay_node"] for slot in value["route"]["benchmark_slots"]},
            "network phase changed its selected protected route")
    captures, relays = value["captures"], sorted(layout_["relays"])
    require(set(captures) == set(REP["ROLES"]), "network capture coverage incomplete")
    for role, capture_ in captures.items():
        node = (layout_["client"]["node"] if role == "receiver" else layout_["provider"]["node"] if role == "provider"
                else relays[0] if role == "relay-a" else relays[1] if role == "relay-b" else "exit")
        REP["validate_capture"](capture_, layout_, node)
    # These are small functional messages, not a throughput benchmark. Both
    # real WG legs of each selected path still have to carry encrypted data.
    for role, relay in zip(("relay-a", "relay-b"), relays):
        require(captures[role]["client_leg_wireguard_data_datagrams"] > 0
                and captures[role]["exit_leg_wireguard_data_datagrams"] > 0
                and captures["receiver"][f"{relay}_client_leg_wireguard_data_datagrams"] > 0
                and captures["exit"][f"{relay}_exit_leg_wireguard_data_datagrams"] > 0,
                "selected path did not carry real protected data")
    for role in ("exit", "provider"):
        require(captures[role]["provider_request_packets"] > 0 and captures[role]["provider_response_packets"] > 0
                and captures[role]["provider_response_payload_bytes"] >= minimum_bytes,
                "protected provider transfer not observed")
    for role in ("receiver", "relay-a", "relay-b"):
        require(all(captures[role][key] == 0 for key in ("provider_request_packets", "provider_response_packets",
                                                       "provider_response_payload_bytes")), "provider payload escaped protected path")


def check_cold_receipt(receipt, signed_manifest, payload, provider):
    require(receipt["manifest_id"] == digest(signed_manifest)["sha256"]
            and receipt["sha256"] == digest(payload)["sha256"]
            and receipt["bytes"] == receipt["peer_bytes"] == len(payload) > 0
            and receipt["provider_peer_ids"] == [provider] and receipt["providers_used"] == 1
            and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0
            and receipt["cache_only"] is False, "learner did not acquire exact cold content over its protected route")


def bounded_tree(root, retain_bundle=False):
    result = {}
    total = 0
    owner = root.stat().st_uid
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == owner != 0, "retained tree owner or link differs")
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 1024 * 1024
                and len(result) < 128, "retained evidence unbounded or aliased")
        raw = path.read_bytes()
        total += len(raw)
        require(total <= 8 * 1024 * 1024, "retained evidence too large")
        name = path.relative_to(root).as_posix()
        result[name] = digest(raw)
        # Keep each original signed P/Q bundle once. Repeated state snapshots
        # retain exact hashes, not duplicate megabytes of the same tensor data.
        if not name.endswith((".safetensors", ".bundle")) or (retain_bundle and name == "adapter.bundle"):
            result[name]["hex"] = raw.hex()
    return result


def raw_files(value):
    result = {}
    for name, file in value.items():
        if "hex" not in file:
            continue
        raw = bytes.fromhex(file["hex"])
        require(digest(raw) == {k: file[k] for k in ("bytes", "sha256")}, "retained bytes differ")
        result[name] = raw
    return result


def capture_cycle(work, label, node, sequence):
    root = private(work, node)
    cycle = root / "loop" / f"cycle-{sequence:016x}"
    state = read(root / "loop/state.json", 4 * 1024 * 1024)
    files = bounded_tree(cycle, retain_bundle=label in ("p", "q"))
    evaluation = json.loads(bytes.fromhex(files["evaluation.json"]["hex"]))
    require(evaluation["approved"] is True or label == "continued", "real candidate was not approved")
    if label != "continued":
        require(state["latest"] == sequence and "publication.pb" in files and "adapter.bundle" in files,
                "approved publication missing")
    current = read(root / "serving/current.json") if node == "relay4" else None
    value = dict(node=node, sequence=sequence, state=state, files=files, current=current,
                 enrollment=(root / "loop/enrollment.json").read_bytes().hex())
    if label == "q":
        value["seed"] = bounded_tree(root / "loop/seed-input")
    if label == "p":
        value["validation"] = bounded_tree(root / "loop/validation-input")
    write(record(work, f"{label}-cycle"), value)


def owner(work, label, pid):
    write(record(work, f"{label}-owner"), TRAIN["identity"](pid))


def worker_observation(work, node, identity, dataset, output, expected_adapter):
    for member in TRAIN["descendants"](identity["pid"]):
        proc = Path(f"/proc/{member['pid']}")
        try:
            if (proc / "cmdline").read_bytes().split(b"\0")[0] != b"/runtime/bin/python3":
                continue
            root = proc / "root"
            if SUCCESSOR["inode"](root / "output") != SUCCESSOR["inode"](output):
                continue
            originals = {"/dataset.json": dataset, "/runtime/pyvenv.cfg": private(work, node) / "runtime/pyvenv.cfg",
                         "/model/model.safetensors": work / "agent-jobs-user/provision/model/model.safetensors"}
            require(all(SUCCESSOR["inode"](root / name.lstrip("/")) == SUCCESSOR["inode"](path)
                        for name, path in originals.items()), "wrong actual worker inputs")
            mounts = {parts[4]: parts[5].split(",") for line in (proc / "mountinfo").read_text().splitlines()
                      if len(parts := line.split()) > 5 and parts[4] in ("/dataset.json", "/runtime", "/model", "/output", "/adapter")}
            require(all("ro" in mounts.get(name, []) for name in ("/dataset.json", "/runtime", "/model"))
                    and "rw" in mounts.get("/output", []), "worker mount isolation differs")
            adapter = None
            if expected_adapter is not None:
                require("ro" in mounts.get("/adapter", []), "warmstart adapter is writable")
                require(all(SUCCESSOR["inode"](root / "adapter" / name) == SUCCESSOR["inode"](expected_adapter / name)
                            for name in FILES), "worker did not mount exact selected warmstart")
                adapter = {name: file_hash(root / "adapter" / name, 2 * 1024 * 1024) for name in FILES}
            else:
                require(not (root / "adapter").exists(), "cold training unexpectedly warmstarted")
            devices = [line.split(":", 1)[0].strip() for line in (proc / "net/dev").read_text().splitlines()[2:]]
            require(devices == ["lo"] and len((proc / "net/route").read_text().splitlines()) == 1, "model worker has network")
            status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
            require(int(status["CapEff"], 16) == 0 and proc.stat().st_uid == private(work, node).stat().st_uid != 0,
                    "worker retained capabilities or wrong node owner")
            return dict(node=node, worker=member, owner=identity, owned_processes=TRAIN["descendants"](identity["pid"]),
                dataset=file_hash(dataset, 1048576), adapter_files=adapter, exact_input_inodes=True,
                network_devices=devices, ipv4_routes=[], mounts=mounts, effective_capabilities=0,
                runtime_lock_inode=SUCCESSOR["lock_observation"](private(work, node) / "runtime/.volparossa-compute.lock"),
                observed_unix_seconds=int(time.time()))
        except FileNotFoundError:
            continue
    return None


def early_cycle_snapshot(work, node, sequence):
    # Exact synthetic-public fixture paths only, before private teardown. Never
    # traverse runtime/model/identity files or retain the dataset's plaintext.
    require(type(sequence) is int and 1 <= sequence <= 2, "unexpected recovery cycle")
    root = private(work, node) / "loop"
    cycle = root / f"cycle-{sequence:016x}"
    files = {}
    for name, path, maximum, retain in (
            ("state.json", root / "state.json", 4 * 1024 * 1024, True),
            ("selection.json", cycle / "selection.json", 256 * 1024, True),
            ("source-provenance.json", cycle / "source-provenance.json", 64 * 1024, True),
            ("dataset.json", cycle / "dataset.json", 1024 * 1024, False)):
        if not os.path.lexists(path):
            files[name] = dict(present=False)
            continue
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum
                and info.st_uid == private(work, node).stat().st_uid,
                "unexpected recovery diagnostic file")
        raw = path.read_bytes()
        require(len(raw) <= maximum, "recovery diagnostic changed size")
        files[name] = dict(present=True, **digest(raw), original_retained=retain and len(raw) <= 16384)
        if files[name]["original_retained"]:
            files[name]["hex"] = raw.hex()
    training = cycle / "training"
    training_exists = os.path.lexists(training)
    require(not training_exists or stat.S_ISDIR(training.lstat().st_mode), "unexpected recovery training path")
    result = dict(version=1, node=node, sequence=sequence, files=files,
                  training_directory_present=training_exists, captured_before_private_cleanup=True,
                  synthetic_public_fixture_only=True, training_or_recovery_success_claimed=False)
    require(len(json.dumps(result, indent=2)) < 128 * 1024, "early cycle diagnostic exceeds artifact limit")
    return result


def observe_training(work, label, node, sequence, pid):
    identity = TRAIN["identity"](pid)
    loop = private(work, node) / "loop"
    cycle = loop / f"cycle-{sequence:016x}"
    adapter = None if label == "p" else (loop / "seed-input/adapter" if label == "q"
                                          else loop / "cycle-0000000000000001/training/adapter")
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        if not TRAIN["alive"](identity):
            require(label in ("p", "q", "continued"), "unknown training observation")
            write(record(work, f"{label}-cycle-failure"), early_cycle_snapshot(work, node, sequence))
            raise ValueError("original training coordinator ended before observation")
        found = worker_observation(work, node, identity, cycle / "dataset.json", cycle / "training", adapter)
        if found is not None:
            write(record(work, f"{label}-training-observation"), found)
            return
        time.sleep(0.05)
    raise ValueError("actual training worker not observed within fixed deadline")


def expected_adapter(work, label):
    if label in ("p", "restored"):
        cycle = read(record(work, "p-cycle"), MAX_PROOF)
        return cycle["current"]["adapter_files"]
    require(label == "q", "unknown job stage")
    return read(record(work, "active"), MAX_PROOF)["current"]["adapter_files"]


def wait_ready(work, label, binary):
    peers = layout(work)
    expected = expected_adapter(work, label)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        pid = int(subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
                                         "volparossa-alpha-agent@client.service"], text=True))
        require(pid > 0, "client service stopped")
        owner_info = (work / "state-client").stat()
        command = ["nsenter", "--target", str(pid), "--mount", "--net", "setpriv",
            f"--reuid={owner_info.st_uid}", f"--regid={owner_info.st_gid}", "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--", binary,
            "--control-socket", str(work / "runtime-client/control/agent.sock"), "compute", "peer", "capabilities",
            "--provider-key", peers["provider_keys"]["relay4"]]
        result = subprocess.run(command, capture_output=True, timeout=min(12, max(.1, deadline - time.monotonic())))
        require(result.returncode == 0 and len(result.stdout) <= 65536, "capability probe failed")
        caps = json.loads(result.stdout)
        # A live activation transition may expose the previous *approved* model.
        if caps["model"]["adapter_files"] != expected or not caps["accepting_work"]:
            time.sleep(.25)
            continue
        require(SUCCESSOR["capability_ready"](caps, expected), "wrong fixed broker capability")
        write(record(work, f"{label}-caps"), caps)
        return
    raise ValueError("broker did not expose the exact approved successor")


def observe_job(work, label):
    broker = TRAIN["identity"](JOBS["broker_pid"]("relay4"))
    expected = expected_adapter(work, label)
    dataset = JOBS["derive"](read(work / "agent-jobs-source.json")["dataset"], [0])
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        found = JOBS["worker_snapshot"](work, "relay4", broker, expected_dataset_sha256=digest(dataset.encode())["sha256"])
        if found:
            proc = Path(f"/proc/{found['worker']['pid']}")
            files = {name: file_hash(proc / "root/adapter" / name, 2 * 1024 * 1024) for name in FILES}
            require(files == expected, "inference mounted a different adapter")
            mounts = [line.split() for line in (proc / "mountinfo").read_text().splitlines()]
            require(any(parts[4] == "/adapter" and "ro" in parts[5].split(",") for parts in mounts), "inference adapter writable")
            found["adapter_files"] = files
            write(record(work, f"{label}-job-observation"), found)
            return
        time.sleep(.05)
    raise ValueError("actual protected inference worker not observed")


def snapshot(work):
    root = private(work, "relay4")
    return dict(state=read(root / "loop/state.json", 4 * 1024 * 1024),
        current=read(root / "serving/current.json"),
        enrollment=(root / "loop/enrollment.json").read_bytes().hex(),
        round_files=bounded_tree(root / "loop" / ROUND))


def await_state(work, stage, pid):
    require(stage in ("active", "armed", "restored", "restarted"), "unknown state")
    identity = TRAIN["identity"](pid)
    deadline = time.monotonic() + 900
    seen_workers = []
    root = private(work, "relay4") / "loop"
    while time.monotonic() < deadline:
        require(TRAIN["alive"](identity), "original coordinator exited before selected state")
        state = read(root / "state.json", 4 * 1024 * 1024)
        registry = state["peer_updates"]
        if stage == "active":
            for part, adapter in (("baseline", root / "cycle-0000000000000001/training/adapter"),
                                  ("candidate", root / ROUND / "import/adapter")):
                if not any(entry["stage"] == part for entry in seen_workers):
                    found = worker_observation(work, "relay4", identity, root / ROUND / "comparison/dataset.json",
                                               root / ROUND / f"comparison/{part}", adapter)
                    if found:
                        seen_workers.append(dict(stage=part, **found))
            ready = registry["active"] == 1 and state["latest"] == 1
        elif stage == "armed":
            ready = registry["active"] == 1 and state["latest"] == 1
        else:
            rounds = registry["completed"]
            ready = registry["active"] is None and len(rounds) == 1 and rounds[0].get("retirement") is not None
        if ready:
            value = snapshot(work)
            expected = (read(record(work, "q-cycle"), MAX_PROOF)["files"] if stage in ("active", "armed")
                        else read(record(work, "p-cycle"), MAX_PROOF)["files"])
            files = {name: {key: expected[f"training/adapter/{name}"][key] for key in ("bytes", "sha256")} for name in FILES}
            if value["current"]["adapter_files"] != files:
                time.sleep(.05)
                continue
            if stage == "active":
                require({entry["stage"] for entry in seen_workers} == {"baseline", "candidate"}, "real independent comparison workers missing")
                value["comparison_observations"] = seen_workers
            if stage == "armed":
                prior = read(record(work, "active"), MAX_PROOF)
                require(value["state"]["peer_updates"]["completed"] == prior["state"]["peer_updates"]["completed"]
                        and value["round_files"] == prior["round_files"] and value["enrollment"] == prior["enrollment"]
                        and value["current"]["expires_unix_seconds"] == prior["current"]["expires_unix_seconds"],
                        "clean coordinator restart changed Q original approval/expiry")
            if stage == "restarted":
                prior = read(record(work, "restored"), MAX_PROOF)
                require(value["state"]["peer_updates"]["completed"] == prior["state"]["peer_updates"]["completed"]
                        and value["round_files"] == prior["round_files"] and value["enrollment"] == prior["enrollment"],
                        "restart changed retirement or original evidence")
            value["coordinator"] = identity
            value["observed_unix_seconds"] = int(time.time())
            write(record(work, stage), value)
            return
        if stage == "active" and registry["completed"]:
            require(all(round_["phase"] == "approved" for round_ in registry["completed"]), "actual peer comparison rejected or failed")
        time.sleep(.05)
    raise ValueError("original active/recovery deadline elapsed")


def changed_paths(before, after):
    require(set(before) == set(after), "fault changed the evidence fileset")
    return sorted(name for name in before if before[name] != after[name])


def inject(work):
    root = private(work, "relay4") / "loop" / ROUND
    original = read(record(work, "active"), MAX_PROOF)
    before = bounded_tree(root)
    require(before == original["round_files"], "active evidence changed before injection")
    path = root / "import/adapter/adapter_model.safetensors"
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid != 0 and info.st_nlink == 1
            and 16 < info.st_size <= 2 * 1024 * 1024, "unexpected local extraction")
    # Deliberately change one byte of only the private extracted copy, preserving
    # inode/mode/length. Original signed bundle and comparison are never touched.
    injected_at = int(time.time())
    with path.open("r+b", buffering=0) as stream:
        stream.seek(-1, 2)
        value = stream.read(1)
        stream.seek(-1, 2)
        stream.write(bytes([value[0] ^ 1]))
        os.fsync(stream.fileno())
    after = bounded_tree(root)
    require(changed_paths(before, after) == ["import/adapter/adapter_model.safetensors"], "fault escaped local extracted weights")
    write(record(work, "fault"), dict(kind="fixture-local-extracted-weight-byte-corruption", changed_paths=changed_paths(before, after),
        original=before["import/adapter/adapter_model.safetensors"], injected=after["import/adapter/adapter_model.safetensors"],
        original_bundle=before["import/adapter.bundle"], original_approval=before["comparison/decision.json"],
        injected_unix_seconds=injected_at, publisher_malice_claimed=False))


def capture(work):
    current = snapshot(work)
    restored = read(record(work, "restored"), MAX_PROOF)
    require(current["round_files"] == restored["round_files"], "post-recovery training changed retained original peer evidence")
    write(record(work, "final"), current)
    write(record(work, "handles"), {label: read(work / f"state-client/compute-source/recovery-{label}-handle.json")
                                  for label in ("p", "q", "restored")})


def cleanup_workers(work):
    processes = []
    for path in sorted(work.glob(f"{PREFIX}-*-owner.json")):
        processes.append(read(path))
    for path in sorted(work.glob(f"{PREFIX}-*-observation.json")):
        processes.extend(read(path)["owned_processes"])
    path = record(work, "active")
    if path.exists():
        for observation in read(path, MAX_PROOF)["comparison_observations"]:
            processes.extend(observation["owned_processes"])
    require(not any(TRAIN["alive"](process) for process in processes), "owned recovery/model process still alive")
    if not record(work, "process-cleanup").exists():
        write(record(work, "process-cleanup"), dict(owned_processes=processes, all_recorded_processes_ended=True,
                                                  checked_before_private_store_removal=True))


def check_training(cycle, observation, revision, predecessor=None):
    files = raw_files(cycle["files"])
    training = json.loads(files["training-report.json"])
    TRAIN["check_worker"](training, revision)
    require(training["updates_completed"] == 8 and training["threads"] == 2
            and training["adapter_after"] != training["adapter_before"], "no actual bounded weight updates")
    require(observation["exact_input_inodes"] is True and observation["network_devices"] == ["lo"]
            and observation["ipv4_routes"] == [] and observation["effective_capabilities"] == 0
            and observation["dataset"] == digest(files["dataset.json"]), "observed training input/isolation differs")
    if predecessor is not None:
        require(training["input_adapter"]["applied"] is True
                and training["input_adapter"]["files"] == predecessor
                and observation["adapter_files"] == predecessor, "training did not reuse exact approved P")
    evaluation = json.loads(files["evaluation.json"])
    require(evaluation["candidate_adapter"] == {name: {key: cycle["files"][f"training/adapter/{name}"][key]
                                                      for key in ("bytes", "sha256")} for name in FILES}
            and evaluation["candidate_parameters"] == training["adapter_after"], "approval selected different trained weights")
    for name, identity in evaluation["files"].items():
        require({key: cycle["files"][name][key] for key in ("bytes", "sha256")} == identity,
                "approval changed its original training evidence")
    return files, training, evaluation


def signed_content(signed, raw, publisher, name):
    envelope = CUSTODY["fields"](signed, 65536)
    body = CUSTODY["fields"](envelope[1], 65536)
    payload = CUSTODY["fields"](body[8], 65536)
    require(body[1] == body[6] == 1 and body[2].hex() == publisher
            and body[7].hex() == digest(body[8])["sha256"]
            and payload[1].decode() == name and payload[2] >= 1 and payload[4] == len(raw)
            and payload[6].hex() == digest(raw)["sha256"] and body[4] > body[3],
            "original signed public content binding differs")
    COLLECTION["verify_signature"](envelope[1], envelope[2], body[2], b"VOLPAROSSA/native-content-manifest/v1\0")
    return body[4]


def check_bundle(encoded, expected, manifest):
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
    index = (integer(1, 1) + blob(2, b"HuggingFaceTB/SmolLM2-135M-Instruct")
             + blob(3, TRAIN["MODEL_REVISION"].encode()) + blob(4, bytes.fromhex(TRAIN["WEIGHT_HASH"]))
             + integer(5, 4) + integer(6, 8) + blob(7, b"q_proj") + blob(7, b"v_proj")
             + blob(8, bytes.fromhex(manifest)))
    offset = 0
    for name in FILES:
        identity = expected[name]
        index += blob(9, blob(1, name.encode()) + integer(2, offset) + integer(3, identity["bytes"])
                      + blob(4, bytes.fromhex(identity["sha256"])))
        offset += identity["bytes"]
    require(encoded[:4] == len(index).to_bytes(4, "big") and encoded[4:4 + len(index)] == index
            and len(encoded) == 4 + len(index) + offset, "signed bundle has a different canonical index")
    offset = 4 + len(index)
    for name in FILES:
        identity = expected[name]
        require(digest(encoded[offset:offset + identity["bytes"]]) == identity, "signed bundle weights differ from trained approval")
        offset += identity["bytes"]


def check_recovery(active, restored, fault):
    require(changed_paths(active["round_files"], restored["round_files"])
            == ["import/adapter/adapter_model.safetensors"], "rollback changed original signed/comparison evidence")
    first = active["state"]["peer_updates"]
    second = restored["state"]["peer_updates"]
    require(first["active"] == 1 and second["active"] is None and len(first["completed"]) == len(second["completed"]) == 1,
            "no durable active Q -> predecessor transition")
    before, after = first["completed"][0], second["completed"][0]
    retirement = after["retirement"]
    require({k: v for k, v in after.items() if k != "retirement"} == before
            and before["phase"] == "approved" and "retirement" not in before,
            "retirement rewrote original approval/snapshot")
    require(retirement["version"] == 1 and retirement["scope"] == "local-extracted-adapter-integrity-not-publisher-or-network-ban"
            and retirement["manifest_id"] == before["manifest_id"]
            and retirement["original_snapshot_sha256"] == digest(json.dumps({name: dict(sha256=identity["sha256"], bytes=identity["bytes"])
                for name, identity in sorted(before["snapshot"].items())}, separators=(",", ":")).encode())["sha256"]
            and retirement["restored_origin"] == dict(kind="local_cycle", sequence=1)
            and retirement["observed_at"] >= fault["injected_unix_seconds"]
            and retirement["restored_expires"] == restored["current"]["expires_unix_seconds"] > restored["observed_unix_seconds"],
            "retirement lost original provenance/expiry or claimed a network ban")
    require(fault["publisher_malice_claimed"] is False and fault["changed_paths"] == ["import/adapter/adapter_model.safetensors"],
            "injected fault scope differs")
    require(active["enrollment"] == restored["enrollment"] and active["state"]["latest"] == restored["state"]["latest"] == 1,
            "recovery changed enrollment or forged a local cycle")


def check_evidence(value, revision):
    require(value["source_revision"] == revision, "wrong source revision")
    p, q, later = (value[f"{label}-cycle"] for label in ("p", "q", "continued"))
    p_files, p_training, p_evaluation = check_training(p, value["p-training-observation"], revision)
    p_adapter = p_evaluation["candidate_adapter"]
    q_files, q_training, q_evaluation = check_training(q, value["q-training-observation"], revision, p_adapter)
    later_files, _, _ = check_training(later, value["continued-training-observation"], revision, p_adapter)
    require(p["node"] == later["node"] == "relay4" and q["node"] == "relay5"
            and p_evaluation["approved"] is True and q_evaluation["approved"] is True
            and p_training["adapter_after"] == q_training["adapter_before"], "no distinct genuine P -> Q training")
    require(q_files["adapter.bundle"] != p_files["adapter.bundle"], "Q did not publish new trained weights")
    keys = value["layout"]["provider_keys"]
    require(keys["relay4"] != keys["relay5"], "training/publication identities are not distinct")
    source_expiry = signed_content(p_files["dataset.manifest"], p_files["dataset.json"], keys["relay5"], "disposable-recovery-train")
    require(q_files["dataset.manifest"] == p_files["dataset.manifest"]
            and q_files["dataset.json"] == p_files["dataset.json"], "Q trained on another source")
    p_expiry = signed_content(p_files["publication.pb"], p_files["adapter.bundle"], keys["relay4"], "disposable-recovery-p")
    q_expiry = signed_content(q_files["publication.pb"], q_files["adapter.bundle"], keys["relay5"], "disposable-recovery-q")
    require(p_expiry <= source_expiry and q_expiry <= source_expiry, "publication enlarged original source authority")
    for files, evaluation in ((p_files, p_evaluation), (q_files, q_evaluation)):
        check_bundle(files["adapter.bundle"], evaluation["candidate_adapter"], digest(files["dataset.manifest"])["sha256"])
    next_expiry = signed_content(later_files["dataset.manifest"], later_files["dataset.json"], keys["relay5"], "disposable-recovery-next")
    next_manifest = digest(later_files["dataset.manifest"])["sha256"]
    selection = json.loads(later_files["selection.json"])
    catalog_proof = selection["source_catalog"]
    catalog_raw = bytes.fromhex(catalog_proof["signed_manifest_hex"])
    catalog_body = catalog_proof["catalog_body"].encode()
    catalog_expiry = signed_content(catalog_raw, catalog_body, keys["relay5"], "disposable-recovery-catalog")
    catalog_envelope = CUSTODY["fields"](catalog_raw, 65536)
    catalog_header = CUSTODY["fields"](catalog_envelope[1], 65536)
    catalog_metadata = CUSTODY["fields"](catalog_header[8], 65536)
    next_source = dict(publisher_key=keys["relay5"], name="disposable-recovery-next", min_revision=1, manifest_id=next_manifest)
    require(later["sequence"] == 2 and catalog_metadata[2] == catalog_proof["catalog_revision"] == 2
            and catalog_proof["catalog_manifest_id"] == digest(catalog_raw)["sha256"]
            and catalog_proof["catalog_expires_unix_seconds"] == catalog_expiry
            and catalog_proof["selected_source"] == next_source
            and catalog_proof["verified_at_unix_seconds"] >= value["restarted"]["observed_unix_seconds"]
            and selection["dataset_name"] == next_source["name"]
            and selection["publisher_key"] == keys["relay5"]
            and selection["expected_dataset_manifest_id"] == next_manifest
            and dict(name=next_source["name"], revision=1, manifest_id=next_manifest) in json.loads(catalog_body)["sources"]
            and json.loads(later_files["result.json"])["source_expires_unix_seconds"] == next_expiry,
            "continued training did not use the newly published signed catalog-2 source after recovery/restart")
    raw_files(q["seed"])
    require(all({key: q["seed"][f"adapter/{name}"][key] for key in ("bytes", "sha256")} == p_adapter[name]
                for name in FILES), "Q warmstart was not exact P")
    active, restored = value["active"], value["restored"]
    check_recovery(active, restored, value["fault"])
    original = raw_files(active["round_files"])
    require(active["round_files"]["import/adapter.bundle"] == digest(q_files["adapter.bundle"])
            and original["import/adapter.manifest"] == q_files["publication.pb"], "learner Q is not the original peer publication")
    decision = json.loads(original["comparison/decision.json"])
    validation_expiry = signed_content(original["comparison/dataset.manifest"], original["comparison/dataset.json"],
                                      keys["relay5"], "disposable-recovery-validation")
    validation_files = raw_files(p["validation"])
    require(validation_files["dataset.manifest"] == original["comparison/dataset.manifest"]
            and validation_files["dataset.json"] == original["comparison/dataset.json"],
            "independent comparison changed its enrolled validation source")
    provider = value["peers"]["relay5"]
    for files in (p_files, later_files):
        check_cold_receipt(json.loads(files["result.json"])["source_receipt"],
                           files["dataset.manifest"], files["dataset.json"], provider)
    check_cold_receipt(json.loads(validation_files["provenance.json"])["source_receipt"],
                       validation_files["dataset.manifest"], validation_files["dataset.json"], provider)
    check_cold_receipt(json.loads(original["import/provenance.json"])["adapter_receipt"],
                       q_files["publication.pb"], q_files["adapter.bundle"], provider)
    require(decision["approved"] is True and decision["baseline_origin"] == dict(kind="local_cycle", sequence=1)
            and decision["candidate"]["target_tokens"] == decision["baseline"]["target_tokens"] > 0
            and decision["candidate"]["loss"] < decision["baseline"]["loss"] - 1e-6,
            "Q was not independently measured against P")
    for name, identity in decision["files"].items():
        require(digest(original[f"comparison/{name}"]) == identity, "original independent decision evidence changed")
    for stage, expected in (("baseline", p_adapter), ("candidate", decision["candidate_files"])):
        envelope = json.loads(original[f"comparison/{stage}-report.json"])
        report_ = envelope["report"]
        require(report_["input_adapter"]["applied"] is True and report_["input_adapter"]["files"] == expected
                and report_["supervisor"]["child_reaped"] is True
                and report_["supervisor"]["network_access"] is False
                and envelope["started_at"] <= envelope["completed_at"] <= envelope["deadline"]
                and envelope["deadline"] - envelope["started_at"] <= 600
                and envelope["deadline"] <= min(q_expiry, validation_expiry, source_expiry),
                "real isolated comparison or original bounded deadline missing")
    require(restored["current"]["adapter_files"] == p_adapter
            and restored["current"]["expires_unix_seconds"] == p["current"]["expires_unix_seconds"]
            and value["restarted"]["state"]["peer_updates"]["completed"] == restored["state"]["peer_updates"]["completed"]
            and value["restarted"]["coordinator"] != restored["coordinator"]
            and value["final"]["round_files"] == restored["round_files"], "P expiry/restart/retention changed")
    armed = value["armed"]
    require(armed["state"]["peer_updates"]["active"] == 1
            and armed["state"]["peer_updates"]["completed"] == active["state"]["peer_updates"]["completed"]
            and armed["round_files"] == active["round_files"] and armed["enrollment"] == active["enrollment"]
            and armed["current"]["adapter_files"] == active["current"]["adapter_files"]
            and armed["current"]["expires_unix_seconds"] == active["current"]["expires_unix_seconds"]
            and armed["coordinator"] != active["coordinator"] and armed["coordinator"] == restored["coordinator"]
            and armed["observed_unix_seconds"] <= value["fault"]["injected_unix_seconds"] <= restored["observed_unix_seconds"],
            "corruption/recovery did not occur in the live original-approval coordinator")
    for label in ("p", "q", "restored"):
        handle, receipt = value["handles"][label], value[f"{label}-status"]
        expected = decision["candidate_files"] if label == "q" else p_adapter
        require(receipt["state"] == "complete" and receipt["binding"] == handle["binding"]
                and handle["binding"]["model_fingerprint"] == value[f"{label}-caps"]["model_fingerprint"]
                and handle["capabilities"]["model"]["adapter_files"] == expected,
                "peer job binding lost exact selection")
        report_ = json.loads(receipt["report_json"])
        require(digest(receipt["report_json"].encode())["sha256"] == receipt["report_sha256"]
                and report_["status"] == "ok" and report_["mode"] == "infer"
                and report_["input_adapter"]["applied"] is True and report_["input_adapter"]["files"] == expected
                and report_["supervisor"]["child_reaped"] is True and report_["supervisor"]["network_access"] is False
                and value[f"{label}-job-observation"]["adapter_files"] == expected,
                "useful exact-weight protected inference missing")
        expiry = active["current"]["expires_unix_seconds"] if label == "q" else p["current"]["expires_unix_seconds"]
        require(handle["binding"]["expires_unix_seconds"] <= expiry
                and report_["supervisor"]["deadline_seconds"] <= 600, "job enlarged the original selection/deadline")
    require(value["p-status"] == value["p-retained"] and value["q-status"] == value["q-retained"],
            "activation or retirement rewrote original job receipts")
    require(value["process-cleanup"]["all_recorded_processes_ended"] is True
            and value["process-cleanup"]["checked_before_private_store_removal"] is True
            and all(value["cleanup"].values()), "owned workers or private stores remain")
    isolation = value["learner-isolation"]
    require(isolation["node"] == "relay4" and isolation["own_plan_readable"] is True
            and isolation["foreign_sources_unreadable"] is True and isolation["node_mount_namespace"].startswith("mnt:["),
            "learner source/cache shortcut was not excluded")
    minimums = {"p": len(p_files["dataset.json"]) + len(validation_files["dataset.json"]),
                "adoption": len(q_files["adapter.bundle"]), "continued": len(later_files["dataset.json"])}
    require(set(value["network"]) == {*minimums, "job-p", "job-q", "job-restored", "receipts"},
            "serialized learner/job network phase missing")
    for label, path in value["network"].items():
        check_network_path(path, "uptake" if label in minimums else "reserve-fetch", value["peers"], minimums.get(label, 1))


def evidence(work, revision):
    names = ("p-cycle", "q-cycle", "continued-cycle", "active", "armed", "restored", "restarted", "fault", "final", "handles", "learner-isolation",
             "p-training-observation", "q-training-observation", "continued-training-observation", "process-cleanup",
             "p-caps", "q-caps", "restored-caps", "p-status", "q-status", "restored-status", "p-retained", "q-retained",
             "p-job-observation", "q-job-observation", "restored-job-observation")
    value = {name: read(record(work, name), MAX_PROOF) for name in names}
    value.update(source_revision=revision, layout=layout(work), peers=read(work / "a01-expected-peers.json"),
        cleanup=read(work / "agent-jobs-private-cleanup.json"),
        network={label: read(record(work, f"network-{label}"))
                 for label in ("p", "adoption", "continued", "job-p", "job-q", "job-restored", "receipts")})
    check_evidence(value, revision)
    require(len(json.dumps(value)) < MAX_PROOF, "proof exceeds fixed artifact bound")
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    proof = read(record(work, "evidence"), MAX_PROOF) if record(work, "evidence").exists() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").exists() else {}
    value = dict(report_kind=KIND, scope=SCOPE, source_revision=revision,
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and proof is not None,
        runner_exit_status=status, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        evidence=proof, cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host,
        publisher_ban_claimed=False, model_quality_proven=False, full_b07_claimed=False, full_alpha_claimed=False)
    require(len(json.dumps(value, indent=2)) + 1 <= MAX_PROOF, "final recovery report exceeds bound")
    write(record(work, "smoke"), value)


def report(value, revision):
    require(value["report_kind"] == KIND and value["scope"] == SCOPE and value["source_revision"] == revision
            and value["success"] is True and value["runner_exit_status"] == 0, "active recovery proof incomplete")
    require(value["cleanup"] == dict(complete=True, remaining_owned_objects=0) and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "host cleanup differs")
    require(all(value[key] is False for key in ("publisher_ban_claimed", "model_quality_proven", "full_b07_claimed", "full_alpha_claimed")),
            "recovery scope overstated")
    check_evidence(value["evidence"], revision)


def self_test():
    # Inert structural controls, never presented as live ML/recovery evidence.
    from unittest.mock import patch
    public_source = ("Every parallel path uses exactly one distinct relay between the same client and exit.\n"
                     "The normal client dataplane never connects directly to an exit.")
    with patch.object(Path, "read_text", autospec=True, return_value=public_source) as staged:
        dataset = source_training_dataset(Path("/fixture"), "a" * 40)
        staged.assert_called_once_with(Path("/fixture/bin/agent-jobs-README.md"))
        assert dataset["train"] and dataset["heldout"]
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as temporary:
        work = Path(temporary)
        root = private(work, "relay4") / "loop"
        cycle = root / "cycle-0000000000000001"
        cycle.mkdir(parents=True)
        original = dict(version=1, cycles=[dict(sequence=1, phase="failed")])
        write(root / "state.json", original)
        write(cycle / "selection.json", dict(version=1, private_data_supported=False))
        write(cycle / "source-provenance.json", dict(source_receipt=dict(peer_bytes=123)))
        write(cycle / "dataset.json", dict(visibility="public", synthetic_test_data=True))
        # A nearby file is deliberately outside the retention allowlist.
        write(cycle / "not-an-approved-diagnostic.json", dict(do_not_export="fixture canary"))
        captured = early_cycle_snapshot(work, "relay4", 1)
        assert json.loads(bytes.fromhex(captured["files"]["state.json"]["hex"])) == original
        assert set(captured["files"]) == {"state.json", "selection.json", "source-provenance.json", "dataset.json"}
        assert "hex" not in captured["files"]["dataset.json"]
        assert captured["files"]["dataset.json"]["sha256"] == file_hash(cycle / "dataset.json", 1024)["sha256"]
        assert captured["training_directory_present"] is False
        (cycle / "training").mkdir()
        assert early_cycle_snapshot(work, "relay4", 1)["training_directory_present"] is True
        assert early_cycle_snapshot(work, "relay4", 2)["files"]["selection.json"] == dict(present=False)
        assert "fixture canary" not in json.dumps(captured)
    receipt = dict(manifest_id=digest(b"signed")["sha256"], sha256=digest(b"payload")["sha256"],
                   bytes=7, peer_bytes=7, provider_peer_ids=["R5"], providers_used=1,
                   origin_body_bytes=0, origin_range_requests=0, cache_only=False)
    check_cold_receipt(receipt, b"signed", b"payload", "R5")
    for changed in (dict(peer_bytes=0), dict(provider_peer_ids=["Client"]), dict(origin_body_bytes=1), dict(cache_only=True)):
        try:
            check_cold_receipt({**receipt, **changed}, b"signed", b"payload", "R5")
        except ValueError:
            continue
        raise AssertionError("cache/provisioning or wrong-provider receipt accepted as cold learner fetch")
    before = {"import/adapter/adapter_model.safetensors": {"sha256": "a"}, "import/adapter.bundle": {"sha256": "b"}}
    after = copy.deepcopy(before)
    after["import/adapter/adapter_model.safetensors"]["sha256"] = "c"
    assert changed_paths(before, after) == ["import/adapter/adapter_model.safetensors"]
    try:
        changed_paths(before, {**after, "extra": {}})
    except ValueError:
        pass
    else:
        raise AssertionError("extra evidence path accepted")
    encoded = dict(bytes=3, sha256=digest(b"abc")["sha256"], hex=b"abc".hex())
    assert raw_files({"file": encoded}) == {"file": b"abc"}
    for changed in (dict(bytes=4), dict(sha256="0" * 64), dict(hex=b"abd".hex())):
        try:
            raw_files({"file": {**encoded, **changed}})
        except ValueError:
            continue
        raise AssertionError("altered retained original accepted")
    for invalid in ({}, dict(report_kind=KIND, scope=SCOPE, source_revision="a" * 40, success=False, runner_exit_status=0)):
        try:
            report(invalid, "a" * 40)
        except (ValueError, KeyError):
            continue
        raise AssertionError("incomplete recovery claimed success")
    print("active recovery inert contracts: PASS (no model/VM execution)")


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
    if command == "sources": sources(work, args[1])
    elif command in ("cache-in", "cache-out"): cache_move(work, args[1], args[2], command == "cache-out")
    elif command == "enroll": enroll(work)
    elif command == "catalog": catalog(work, int(args[1]))
    elif command == "learner-isolation": learner_isolation(work)
    elif command == "network-path": network_path(work, args[1])
    elif command == "owner": owner(work, args[1], int(args[2]))
    elif command == "observe-training": observe_training(work, args[1], args[2], int(args[3]), int(args[4]))
    elif command == "capture-cycle": capture_cycle(work, args[1], args[2], int(args[3]))
    elif command == "wait-ready": wait_ready(work, args[1], args[2])
    elif command == "observe-job": observe_job(work, args[1])
    elif command == "await": await_state(work, args[1], int(args[2]))
    elif command == "inject": inject(work)
    elif command == "capture": capture(work)
    elif command == "cleanup-workers": cleanup_workers(work)
    elif command == "evidence": evidence(work, args[1])
    elif command == "finalize": finalize(work, args[1], int(args[2]), SUCCESSOR["cleanup_flag"](args[3]), int(args[4]), args[5], args[6])
    else: raise ValueError("unknown recovery fixture command")


if __name__ == "__main__":
    main()
