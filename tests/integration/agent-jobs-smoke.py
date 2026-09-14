#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Two genuinely concurrent public-inference executors; not loss/reassignment proof."""

import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / "agent-training-smoke.py"))
CUSTODY = runpy.run_path(str(HERE / "content-custody-smoke.py"))
read, write, require = TRAIN["read"], TRAIN["write"], TRAIN["require"]
file_hash, identity, alive = TRAIN["file_hash"], TRAIN["identity"], TRAIN["alive"]
SCOPE = ("two distinct node-local fixed-model workers concurrently execute disjoint signed public rows over protected paths; "
         "not automatic reassignment, private offload, distributed training, model-layer sharding or answer quality")
NODES = ("relay3", "relay4", "relay5")


def private(path, name):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.name == name and not path.is_symlink()
            and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.getuid() != 0, "wrong private compute fixture root")
    return path


def dataset(revision, source):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "invalid source revision")
    first = "Every parallel path uses exactly one distinct relay between the same client and exit."
    second = "The normal client dataplane never connects directly to an exit."
    text = source.replace("\n", " ")
    require(first in text and second.lower() in text.lower(), "public source text changed")
    return {"version": 1, "visibility": "public", "license": "GPL-3.0-only", "source_revision": revision,
            "train": [], "heldout": [{"question": "Is direct client-to-exit access normal?", "context": second, "answer": "No."}],
            "inference": [{"question": "How many relays does one path use?", "context": first},
                          {"question": "May a normal client directly contact an exit dataplane?", "context": second}]}


def prepare(path):
    root = private(path, "agent-jobs-user")
    require(not list(root.iterdir()), "provision root already populated")
    subprocess.run([sys.executable, "-B", str(HERE / "ml/provision.py"), "--execute", "--yes",
                    "--disposable-guest", "--root", str(root / "provision"), "--budget-bytes", str(3 * 1024 ** 3)],
                   check=True, timeout=1850)


def source(path, revision):
    root = private(path, "compute-source")
    require(not list(root.iterdir()), "source root already populated")
    write(root / "dataset.json", dataset(revision, (HERE / "agent-jobs-README.md").read_text()))
    with (root / "passphrase").open("xb") as stream:
        stream.write(base64.b64encode(os.urandom(48)) + b"\n")
    (root / "passphrase").chmod(0o600)


def publication(path):
    root = private(path, "compute-source")
    return {"dataset": read(root / "dataset.json"), "dataset_file": file_hash(root / "dataset.json", 1048576),
            "dataset_json": (root / "dataset.json").read_text(),
            "manifest": file_hash(root / "manifest.pb", 65536),
            "manifest_hex": (root / "manifest.pb").read_bytes().hex(), "explicit_public_source": True}


def derive(original, rows):
    require(rows and rows == sorted(set(rows)) and all(0 <= x < len(original["inference"]) for x in rows), "invalid rows")
    value = copy.deepcopy(original)
    value["inference"] = [original["inference"][x] for x in rows]
    # Struct field order is the canonical Rust dataset serialization order.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def guest_work(work):
    TRAIN["guest_guard"](root=True)
    require(work.parent == Path("/opt") and work.name.startswith("va.") and not work.is_symlink(), "wrong owned topology root")


def broker_pid(node):
    raw = subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
                                   f"volparossa-alpha-compute@{node}.service"], text=True).strip()
    require(raw.isdecimal() and int(raw) > 0, "actual broker not running")
    return int(raw)


def worker_snapshot(work, node, broker):
    require(identity(broker["pid"]) == broker, "broker changed during observation")
    proc = Path(f"/proc/{broker['pid']}")
    require(Path(os.readlink(proc / "exe")).name == "volparossa", "unexpected broker executable")
    service_pid = int(subprocess.check_output(["systemctl", "show", "--property=MainPID", "--value",
                                               f"volparossa-alpha-agent@{node}.service"], text=True))
    namespace = os.readlink(proc / "ns/net")
    require(namespace == os.readlink(f"/proc/{service_pid}/ns/net"), "broker outside its actual node namespace")
    private_root = work / f"state-{node}/compute"
    family = TRAIN["descendants"](broker["pid"])
    for member in family:
        worker = Path(f"/proc/{member['pid']}")
        try:
            args = (worker / "cmdline").read_bytes().split(b"\0")
            if not args or args[0] != b"/runtime/bin/python3":
                continue
            root = worker / "root"
            mounts = {}
            for line in (worker / "mountinfo").read_text().splitlines():
                fields = line.split()
                if fields[4] in ("/runtime", "/model", "/dataset.json", "/output"):
                    mounts[fields[4]] = fields[5].split(",")
            require(all("ro" in mounts.get(p, []) for p in ("/runtime", "/model", "/dataset.json"))
                    and "rw" in mounts.get("/output", []), "actual worker mounts not isolated")
            datasets = list((private_root / "work").glob("compute-job-*/dataset.json"))
            require(len(datasets) == 1, "expected one actual node-owned job input")
            actual = {"model/model.safetensors": work / "agent-jobs-user/provision/model/model.safetensors",
                      "runtime/pyvenv.cfg": private_root / "runtime/pyvenv.cfg", "dataset.json": datasets[0]}
            inodes = {}
            for mounted, original in actual.items():
                left, right = (root / mounted).stat(), original.stat()
                require((left.st_dev, left.st_ino) == (right.st_dev, right.st_ino), "worker input is not exact node-local file")
                inodes[mounted] = [right.st_dev, right.st_ino]
            namespaces = {kind: os.readlink(worker / "ns" / kind) for kind in ("net", "pid", "ipc", "mnt")}
            guest = {kind: os.readlink(Path("/proc/self/ns") / kind) for kind in namespaces}
            require(all(namespaces[k] != guest[k] for k in namespaces)
                    and namespaces["net"] != namespace, "worker shares node or guest network namespace")
            devices = [line.split(":", 1)[0].strip() for line in (worker / "net/dev").read_text().splitlines()[2:]]
            require(devices == ["lo"] and len((worker / "net/route").read_text().splitlines()) == 1, "worker has external network")
            status = dict(line.split(":", 1) for line in (worker / "status").read_text().splitlines() if ":" in line)
            require(int(status["CapEff"], 16) == 0 and not (root / "home").exists() and not (root / "root").exists(), "worker exposes host authority")
            for other in ("client", *NODES):
                if other != node:
                    hidden = proc / "root" / str(work / f"state-{other}").lstrip("/")
                    visible, original = hidden.stat(), (work / f"state-{other}").stat()
                    require(stat.S_IMODE(visible.st_mode) == 0
                            and (visible.st_dev, visible.st_ino) != (original.st_dev, original.st_ino),
                            "broker mount exposes other node state")
            require(proc.stat().st_uid == private_root.stat().st_uid != 0,
                    "broker is not the unprivileged node owner")
            lock_path = private_root / "runtime/.volparossa-compute.lock"
            lock = lock_path.lstat()
            require(stat.S_ISREG(lock.st_mode) and lock.st_nlink == 1, "runtime lock is aliased")
            with lock_path.open("rb") as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise ValueError("observed worker does not hold its runtime lease")
            return {"node": node, "broker": broker, "service": identity(service_pid), "worker": member,
                    "owned_processes": family, "node_namespace": namespace, "worker_namespaces": namespaces,
                    "guest_namespaces": guest, "network_devices": devices, "ipv4_routes": [], "mounts": mounts,
                    "input_inodes": inodes, "runtime_lock_inode": [lock.st_dev, lock.st_ino], "runtime_lock_held": True,
                    "dataset_json": datasets[0].read_text(), "dataset_file": file_hash(datasets[0], 1048576),
                    "effective_capabilities": 0, "host_home_visible": False, "other_node_state_hidden": True}
        except FileNotFoundError:
            continue
    return None


def check_overlap(observation):
    workers = observation["workers"]
    require(len(workers) == 2 and len({w["node"] for w in workers}) == 2
            and len({w["node_namespace"] for w in workers}) == 2
            and len({w["broker"]["pid"] for w in workers}) == 2
            and len({w["worker"]["pid"] for w in workers}) == 2
            and len({tuple(w["runtime_lock_inode"]) for w in workers}) == 2,
            "not two independent simultaneous executors")
    require(observation["both_alive_before_and_after"] is True
            and observation["last_monotonic_ns"] > observation["first_monotonic_ns"], "worker lifetimes never overlapped")
    for worker in workers:
        require(worker["node"] in NODES and worker["runtime_lock_held"] is True
                and worker["network_devices"] == ["lo"] and worker["ipv4_routes"] == []
                and worker["effective_capabilities"] == 0 and worker["host_home_visible"] is False
                and worker["other_node_state_hidden"] is True, "worker isolation missing")
        require(all(worker["worker_namespaces"][k] != worker["guest_namespaces"][k] for k in ("net", "pid", "ipc", "mnt"))
                and worker["worker_namespaces"]["net"] != worker["node_namespace"], "worker namespace reused")
        require(all("ro" in worker["mounts"][p] for p in ("/runtime", "/model", "/dataset.json")), "writable compute input")
    require(workers[0]["input_inodes"]["model/model.safetensors"] == workers[1]["input_inodes"]["model/model.safetensors"], "base model was downloaded per worker")
    for name in ("runtime/pyvenv.cfg", "dataset.json"):
        require(workers[0]["input_inodes"][name] != workers[1]["input_inodes"][name], "independent worker input aliased")


def observe(work):
    guest_work(work)
    layout = read(work / "agent-jobs-layout.json")
    brokers = {node: identity(broker_pid(node)) for node in layout["provider_nodes"]}
    for _ in range(1200):
        first = time.monotonic_ns()
        values = [worker_snapshot(work, node, broker) for node, broker in brokers.items()]
        if all(values):
            before = all(alive(x["worker"]) and alive(x["broker"]) for x in values)
            last = time.monotonic_ns()
            after = all(alive(x["worker"]) and alive(x["broker"]) for x in values)
            if before and after:
                result = {"workers": values, "both_alive_before_and_after": True,
                          "first_monotonic_ns": first, "last_monotonic_ns": last}
                check_overlap(result)
                write(work / "agent-jobs-observation.json", result)
                return
        time.sleep(0.05)
    raise ValueError("two actual isolated Python worker lifetimes did not overlap")


def cleanup(work):
    guest_work(work)
    observation = work / "agent-jobs-observation.json"
    if observation.is_file():
        require(not any(alive(p) for w in read(observation)["workers"] for p in w["owned_processes"]), "owned compute process alive")
    targets = [work / "agent-jobs-user", work / "state-client/compute-source"]
    targets.extend(work / f"state-{node}/compute" for node in NODES)
    for target in targets:
        if target.exists():
            info = target.lstat()
            require(stat.S_ISDIR(info.st_mode) and not target.is_symlink() and info.st_uid != 0
                    and stat.S_IMODE(info.st_mode) == 0o700, "wrong cleanup root")
            shutil.rmtree(target)
    return {"observed_compute_processes_ended": True, "model_runtime_removed": True,
            "private_job_roots_removed": all(not path.exists() for path in targets), "publisher_key_removed": True}


def check_evidence(evidence, revision):
    require(evidence["success"] is True and evidence["source_revision"] == revision, "wrong source-bound job proof")
    require(evidence["provision"]["success"] is True and evidence["provision"]["installed_wheels"] == 38
            and evidence["provision"]["download_bytes"] == 523040250
            and evidence["provision"]["training_performed"] is False, "unverified or repeated provision scope")
    check_overlap(evidence["observation"])
    original, publication = evidence["source"], evidence["publish"]
    require(original["explicit_public_source"] is True and json.loads(original["dataset_json"]) == original["dataset"]
            and original["dataset"]["source_revision"] == revision and len(original["dataset"]["inference"]) == 2
            and original["dataset"]["visibility"] == "public" and original["dataset"]["license"] == "GPL-3.0-only",
            "original explicit public source missing")
    require(hashlib.sha256(original["dataset_json"].encode()).hexdigest() == original["dataset_file"]["sha256"]
            and hashlib.sha256(bytes.fromhex(original["manifest_hex"])).hexdigest() == original["manifest"]["sha256"]
            and publication["manifest_id"] == original["manifest"]["sha256"]
            and publication["bytes"] == original["dataset_file"]["bytes"]
            and publication["operation"] == "offline_content_publish"
            and publication["network_publication"] is False, "original publication bytes differ")
    layout, peers, result = evidence["layout"], evidence["peers"], evidence["result"]
    require(set(layout["provider_nodes"]) == {w["node"] for w in evidence["observation"]["workers"]}
            and all(CUSTODY["peer_key"](peers[node]) == key for node, key in layout["provider_keys"].items())
            and layout["control_relay_peer_id"] not in {peers[node] for node in layout["provider_nodes"]}, "provider identity/lineage differs")
    require(result["operation"] == "compute_distribute" and result["complete"] is True and result["provider_count"] == 2
            and result["dataset_manifest_id"] == publication["manifest_id"] and len(result["jobs"]) == 2,
            "actual distributed batch incomplete")
    require(all(result[x] is False for x in ("private_data_supported", "model_layer_sharding", "result_truthfulness_guaranteed")), "unsupported compute claim")
    rows, response_bytes = [], {}
    for index, status in enumerate(evidence["statuses"]):
        binding = status["binding"]
        part = next(x for x in result["jobs"] if x["handle"]["binding"]["job_id"] == binding["job_id"])
        handle = part["handle"]
        node = layout["provider_nodes"][index]
        caps = handle["capabilities"]
        require(caps["model"]["model_id"] == "HuggingFaceTB/SmolLM2-135M-Instruct"
                and caps["model"]["model_revision"] == TRAIN["MODEL_REVISION"]
                and caps["model"]["base_weights"] == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}
                and caps["model"]["adapter_files"] is None and caps["public_inference_only"] is True
                and caps["runtime_slots"] == 1 and caps["max_threads"] == 2
                and caps["model_fingerprint"] == binding["model_fingerprint"], "job not bound to the selected fixed-model profile")
        require(handle["provider_key"] == layout["provider_keys"][node]
                and handle["binding"] == binding and part["state"] == status["state"] == "complete"
                and binding["row_indices"] == [index] and binding["dataset_manifest_id"] == publication["manifest_id"]
                and binding["expires_unix_seconds"] <= publication["expires_unix_seconds"], "wrong original job binding")
        derived = derive(original["dataset"], binding["row_indices"])
        observation = next(w for w in evidence["observation"]["workers"] if w["node"] == node)
        require(observation["dataset_json"] == derived and binding["dataset_sha256"] == hashlib.sha256(derived.encode()).hexdigest(),
                "executor received different or overlapping public rows")
        report_json = status["report_json"]
        require(status["report_sha256"] == part["report_sha256"] == hashlib.sha256(report_json.encode()).hexdigest(), "returned worker report changed")
        report = json.loads(report_json)
        require(report["status"] == "ok" and report["mode"] == "infer" and report["device"] == "cpu"
                and report["threads"] == 2 and report["updates_completed"] == 0
                and report["dataset"]["sha256"] == binding["dataset_sha256"]
                and report["dataset"]["source_revision"] == revision and len(report["outputs"]) == 1,
                "no real source-bound inference result")
        require(report["model"]["files"]["model.safetensors"] == {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}
                and report["model"]["revision"] == TRAIN["MODEL_REVISION"], "wrong fixed model")
        supervisor = report["supervisor"]
        require(supervisor["child_reaped"] is True and supervisor["network_access"] is False
                and supervisor["gpu_access"] is False and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"], "worker accounting/cleanup missing")
        output = result["outputs"][index]
        require(output["sample_index"] == index and output["job_id"] == binding["job_id"]
                and output["provider_key"] == handle["provider_key"] and output["text"] == report["outputs"][0]["text"], "original result order was not retained")
        rows.extend(binding["row_indices"])
        response_bytes[node] = len(report_json.encode())
    require(sorted(rows) == [0, 1] and len(set(rows)) == 2, "rows not executed exactly once by distinct peers")
    phase = evidence["path"]
    # Reuse exact graph/role/multipath validation, not its content-operation semantics.
    CUSTODY["validate_path"](phase, peers, layout, "inspect")
    for node in layout["provider_nodes"]:
        application = phase["privacy"]["exit"]["provider_application"][node]
        require(application["request_packets"] > 0
                and application["response_payload_bytes"] >= response_bytes[node], "selected provider did not carry job/result bytes")
    require(all(evidence["cleanup"].values()), "compute private cleanup incomplete")


def build_evidence(work, revision):
    evidence = {name: read(work / f"agent-jobs-{name}.json") for name in ("source", "publish", "layout", "result", "observation", "provision")}
    evidence.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
                    cleanup=read(work / "agent-jobs-private-cleanup.json"),
                    statuses=[read(work / f"agent-jobs-status-{n}.json") for n in (0, 1)],
                    path={"selected_route": read(work / "content-custody-fetch-live-selection.json"),
                          "privacy": {role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
                          "control_privacy": read(work / "content-provider-custody-fetch-control.json"),
                          "gates": read(work / "content-custody-fetch-gates.json")})
    check_evidence(evidence, revision)
    write(work / "agent-jobs-evidence.json", evidence)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    evidence = read(work / "agent-jobs-evidence.json", 1048576) if (work / "agent-jobs-evidence.json").is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(work / "agent-jobs-smoke.json", {
        "report_kind": "volparossa-public-cooperative-jobs", "source_revision": revision, "scope": SCOPE,
        "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and evidence is not None,
        "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker, "runner_exit_status": status,
        "automatic_reassignment_claimed": False, "full_b03_claimed": False, "full_alpha_claimed": False,
        "evidence": evidence, "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host})


def check_report(report, revision):
    require(report["report_kind"] == "volparossa-public-cooperative-jobs" and report["source_revision"] == revision
            and report["success"] is True and report["scope"] == SCOPE and report["runner_exit_status"] == 0, "incomplete job report")
    require(report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"], "guest cleanup differs")
    require(all(report[k] is False for k in ("automatic_reassignment_claimed", "full_b03_claimed", "full_alpha_claimed")), "unsupported broader proof")
    check_evidence(report["evidence"], revision)


def self_test():
    value = dataset("a" * 40, (HERE.parent.parent / "README.md").read_text())
    a, b = (derive(value, [n]) for n in (0, 1))
    require(a != b and json.loads(a)["inference"] == value["inference"][:1]
            and json.loads(b)["inference"] == value["inference"][1:], "disjoint source derivation failed")
    for rows in ([], [0, 0], [1, 0], [2]):
        try:
            derive(value, rows)
        except ValueError:
            continue
        raise AssertionError("invalid source rows accepted")
    for proof in ({"workers": []}, {"workers": [{"node": "relay4"}] * 2}):
        try:
            check_overlap(proof)
        except (ValueError, KeyError):
            continue
        raise AssertionError("absent or same-worker proof accepted")
    # Exercise a complete synthetic contract, then reject altered source, identity,
    # overlap and results. This fixture never counts as actual network/model evidence.
    base = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["fixture"]()
    encoded = json.dumps(value)
    digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
    model = {"model_id": "HuggingFaceTB/SmolLM2-135M-Instruct", "model_revision": TRAIN["MODEL_REVISION"],
             "base_weights": {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}, "adapter_files": None}
    profiles = dict(model=model, model_fingerprint="f" * 64, public_inference_only=True, runtime_slots=1, max_threads=2)
    manifest_id = digest("synthetic-manifest")
    fixture = {"success": True, "source_revision": "a" * 40, "layout": base["layout"], "peers": base["expected_peers"],
               "provision": dict(success=True, installed_wheels=38, download_bytes=523040250, training_performed=False),
               "source": {"dataset": value, "dataset_json": encoded, "dataset_file": {"bytes": len(encoded), "sha256": digest(encoded)},
                          "manifest": {"sha256": manifest_id}, "manifest_hex": b"synthetic-manifest".hex(), "explicit_public_source": True},
               "publish": {"operation": "offline_content_publish", "network_publication": False,
                           "manifest_id": manifest_id, "bytes": len(encoded), "expires_unix_seconds": 3000},
               "result": dict(operation="compute_distribute", complete=True, provider_count=2, dataset_manifest_id=manifest_id,
                              private_data_supported=False, model_layer_sharding=False, result_truthfulness_guaranteed=False,
                              jobs=[], outputs=[]), "statuses": [], "cleanup": {"done": True},
               "path": base["phases"]["inspect"], "observation": {"workers": [], "both_alive_before_and_after": True,
                                                                   "first_monotonic_ns": 1000, "last_monotonic_ns": 2000}}
    for n, node in enumerate(base["layout"]["provider_nodes"]):
        derived = derive(value, [n])
        binding = dict(job_id=str(n) * 32, row_indices=[n], dataset_manifest_id=manifest_id,
                       dataset_sha256=digest(derived), model_fingerprint="f" * 64, expires_unix_seconds=2000)
        report = dict(status="ok", mode="infer", device="cpu", threads=2, updates_completed=0,
                      dataset=dict(sha256=digest(derived), source_revision="a" * 40),
                      outputs=[dict(text="synthetic public output")],
                      model=dict(revision=TRAIN["MODEL_REVISION"], files={"model.safetensors": model["base_weights"]}),
                      supervisor=dict(child_reaped=True, network_access=False, gpu_access=False,
                                      max_observed_rss_bytes=100, rss_limit_bytes=1000))
        report_json = json.dumps(report)
        handle = dict(provider_key=base["layout"]["provider_keys"][node], binding=binding, capabilities=profiles)
        fixture["result"]["jobs"].append(dict(handle=handle, state="complete", report_sha256=digest(report_json)))
        fixture["result"]["outputs"].append(dict(sample_index=n, provider_key=handle["provider_key"],
                                                 job_id=binding["job_id"], text=report["outputs"][0]["text"]))
        fixture["statuses"].append(dict(binding=binding, state="complete", report_json=report_json, report_sha256=digest(report_json)))
        fixture["observation"]["workers"].append(dict(node=node, broker=dict(pid=100+n), worker=dict(pid=200+n),
            node_namespace=f"net:[{n+1}]", worker_namespaces={k: f"{k}:[{n+20}]" for k in ("net", "pid", "ipc", "mnt")},
            guest_namespaces={k: f"{k}:[30]" for k in ("net", "pid", "ipc", "mnt")}, runtime_lock_inode=[1, n+10],
            runtime_lock_held=True, dataset_json=derived, network_devices=["lo"], ipv4_routes=[],
            mounts={p: ["ro"] for p in ("/runtime", "/model", "/dataset.json")},
            effective_capabilities=0, host_home_visible=False, other_node_state_hidden=True,
            input_inodes={"model/model.safetensors": [1, 100], "runtime/pyvenv.cfg": [1, n+200], "dataset.json": [1, n+300]}))
    check_evidence(fixture, "a" * 40)
    for kind in ("same_lock", "no_overlap", "altered_dataset", "reordered_result"):
        bad = copy.deepcopy(fixture)
        if kind == "same_lock":
            bad["observation"]["workers"][1]["runtime_lock_inode"] = bad["observation"]["workers"][0]["runtime_lock_inode"]
        elif kind == "no_overlap":
            bad["observation"]["both_alive_before_and_after"] = False
        elif kind == "altered_dataset":
            bad["observation"]["workers"][0]["dataset_json"] += " "
        else:
            bad["result"]["outputs"].reverse()
        try:
            check_evidence(bad, "a" * 40)
        except ValueError:
            continue
        raise AssertionError(f"invalid synthetic contract accepted: {kind}")
    print("agent-jobs source/subset/complete-contract/overlap/result negative self-tests PASS; no model or network executed")


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        self_test()
    elif len(args) == 2 and args[0] == "prepare":
        prepare(args[1])
    elif len(args) == 3 and args[0] == "source":
        source(args[1], args[2])
    elif len(args) == 2 and args[0] == "publication":
        print(json.dumps(publication(args[1])))
    elif len(args) == 2 and args[0] == "observe":
        observe(Path(args[1]))
    elif len(args) == 2 and args[0] == "cleanup":
        print(json.dumps(cleanup(Path(args[1]))))
    elif len(args) == 3 and args[0] == "evidence":
        build_evidence(Path(args[1]), args[2])
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif len(args) == 3 and args[0] == "report":
        check_report(read(Path(args[1]), 1048576), args[2])
        print("actual two-node concurrent signed public job report PASS")
    else:
        raise ValueError("unsupported fixture operation")


if __name__ == "__main__":
    os.umask(0o077)
    main()
