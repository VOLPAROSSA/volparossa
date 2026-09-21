#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One real followed owner discovers a third executor after both originals leave."""
import copy
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
FOLLOW = runpy.run_path(str(HERE / "agent-jobs-follow-smoke.py"))
JOBS, CUSTODY = FOLLOW["JOBS"], FOLLOW["CUSTODY"]
SHARED = CUSTODY["SHARED"]
read, write, require = FOLLOW["read"], FOLLOW["write"], FOLLOW["require"]
alive, identity, hashes = FOLLOW["alive"], FOLLOW["identity"], FOLLOW["hash_bytes"]
workflow, initial_handles = FOLLOW["workflow"], FOLLOW["initial_handles"]
FIRST, RETRY = FOLLOW["FIRST"], FOLLOW["RETRY"]
PREFIX = "agent-jobs-peer-recovery"
KIND = "volparossa-public-new-peer-recovery"
SCOPE = ("one followed public workflow discovers two executors, retains a completed original row, "
         "and discovers a real third same-model executor after an observed worker loss and removal "
         "of both original brokers; fixture-controlled owner pause during broker cutover; "
         "not private computation, exactly-once execution, answer quality or full B03")


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def signal_owner(owner, action):
    original = owner["identity"]
    fd = os.pidfd_open(original["pid"])
    try:
        require(identity(original["pid"]) == original, "owner PID reused")
        signal.pidfd_send_signal(fd, action)
    finally:
        os.close(fd)


def stopped(owner):
    require(alive(owner["identity"]), "original owner vanished")
    return Path(f"/proc/{owner['identity']['pid']}/stat").read_text().rsplit(")", 1)[1].split()[0] == "T"


def pause_after_loss(work, launcher):
    JOBS["guest_work"](work)
    deadline = time.monotonic() + 180
    while not (workflow(work) / "workflow.json").is_file():
        require(time.monotonic() < deadline, "initial executor enrollment timeout")
        time.sleep(0.05)
    enrollment = read(workflow(work) / "workflow.json")
    layout = read(work / "agent-jobs-layout.json")
    require(set(enrollment["provider_keys"]) == set(layout["provider_keys"].values())
            and enrollment["replace_peers"] is True, "wrong discovered initial peers/permission")
    # Independently reconcile actual discovery order with the actual node keys;
    # fixture setup sorts the real keys, never assumes R4 sorts before R5.
    require(layout["provider_nodes"] == [next(node for node, key in layout["provider_keys"].items() if key == found)
                                         for found in enrollment["provider_keys"]], "discovery/node row order changed")
    JOBS["observe"](work)
    owner = FOLLOW["owner_process"](work, launcher)
    require(owner is not None and alive(owner["identity"]), "original workflow owner missing")
    args = Path(f"/proc/{owner['identity']['pid']}/cmdline").read_bytes().split(b"\0")
    require(b"--discover-peers" in args and b"--replace-peers" in args and b"--provider-key" not in args,
            "owner did not authorize automatic executor replacement")
    owner.update(discover_peers=True, replace_peers=True)
    write(record(work, "owner"), owner)
    inject = JOBS["inject_loss"]
    previous = inject.__globals__["initial_handles"]
    inject.__globals__["initial_handles"] = initial_handles
    try:
        inject(work)
    finally:
        inject.__globals__["initial_handles"] = previous
    loss = read(work / "agent-jobs-loss-control.json")
    deadline = time.monotonic() + 630
    result = workflow(work) / FIRST / "result.json"
    receipts = [workflow(work) / FIRST / f"receipt-{entry['value']['binding']['job_id']}.json"
                for entry in loss["original_handles"]]
    while True:
        try:
            ready = result.is_file() and all(path.is_file() for path in receipts)
            if ready:
                read(result)
                for path in receipts:
                    read(path)
                break
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        require(time.monotonic() < deadline and alive(owner["identity"]), "original terminal receipt timeout")
        time.sleep(0.02)
    signal_owner(owner, signal.SIGSTOP)
    # Record immediately, so outer cleanup can release the exact stopped owner
    # even if any subsequent assertion or broker startup fails.
    write(record(work, "pause"), {"owner": owner, "signal": "SIGSTOP", "pidfd_bound": True,
          "sent_boottime_ns": JOBS["boot_ns"]()})
    for _ in range(100):
        if stopped(owner):
            break
        time.sleep(0.01)
    require(stopped(owner) and not (workflow(work) / RETRY).exists(), "owner cutover did not precede retry")
    statuses = [read(path) for path in receipts]
    require(statuses[0]["status"]["state"] == "failed" and statuses[1]["status"]["state"] == "complete"
            and all(not alive(loss[name]["worker"]) for name in ("victim", "survivor")),
            "actual terminal failure/success not retained")
    write(record(work, "originals"), {"receipts": [FOLLOW["retained_file"](path, workflow(work).stat().st_uid)
          for path in receipts], "handles": initial_handles(work), "owner_stopped": True,
          "observed_boottime_ns": JOBS["boot_ns"](), "third_broker_previously_absent":
          not (work / "state-relay3/compute/broker.sock").exists()})


def cutover(work):
    JOBS["guest_work"](work)
    owner, loss = read(record(work, "owner")), read(work / "agent-jobs-loss-control.json")
    require(stopped(owner) and all(not alive(loss[name]["broker"]) and not alive(loss[name]["worker"])
            for name in ("victim", "survivor")), "original brokers not gone during paused cutover")
    broker = identity(JOBS["broker_pid"]("relay3"))
    require(alive(broker) and read(work / "agent-jobs-relay3-attach.json")["serving"] is True,
            "real third broker not attached")
    write(record(work, "cutover"), {"old_brokers_ended": True, "owner": owner,
          "broker": broker, "node": "relay3", "observed_boottime_ns": JOBS["boot_ns"]()})


def continue_owner(work, cleanup=False):
    JOBS["guest_work"](work)
    path = record(work, "pause")
    if cleanup and not path.is_file():
        return
    owner = read(path)["owner"]
    if cleanup and not alive(owner["identity"]):
        return
    if not cleanup:
        require(stopped(owner) and read(record(work, "cutover"))["old_brokers_ended"], "cutover incomplete")
    signal_owner(owner, signal.SIGCONT)
    if not cleanup:
        write(record(work, "continued"), {"owner": owner, "signal": "SIGCONT", "pidfd_bound": True,
              "sent_boottime_ns": JOBS["boot_ns"]()})


def observe_replacement(work):
    JOBS["guest_work"](work)
    owner, cut = read(record(work, "owner")), read(record(work, "cutover"))
    key = read(work / "agent-jobs-relay3-public.json")["identity_public_key_hex"]
    loss = read(work / "agent-jobs-loss-control.json")
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        require(alive(owner["identity"]), "original owner ended before new peer recovery")
        path = workflow(work) / RETRY / "job-0.json"
        if path.is_file():
            handle = read(path)
            require(handle["provider_key"] == key and handle["binding"]["row_indices"] == [0], "retry was not on new third peer")
            worker = JOBS["worker_snapshot"](work, "relay3", cut["broker"], handle["binding"]["dataset_sha256"])
            if worker and alive(worker["worker"]):
                require(all(not alive(loss[name]["worker"]) and not alive(loss[name]["broker"])
                            for name in ("victim", "survivor")), "old broker/worker reappeared")
                observed = {"worker": worker, "handle": handle, "same_owner_alive": alive(owner["identity"]),
                            "owner": owner, "first_boottime_ns": JOBS["boot_ns"](),
                            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
                            "handle_saved_unix_seconds": path.stat().st_mtime_ns // 1000000000}
                write(work / "agent-jobs-replacement-observation.json", observed)
                return
        time.sleep(0.025)
    raise ValueError("new third worker never observed")


def retained_tree(root):
    files = {}
    uid = root.stat().st_uid
    for count, path in enumerate(root.rglob("*")):
        name, info = path.relative_to(root).as_posix(), path.lstat()
        require(count < 64 and not path.is_symlink() and info.st_uid == uid, "retained tree bound/ownership")
        if stat.S_ISDIR(info.st_mode):
            require(name in {"package-0000", FIRST[:-1], RETRY[:-1]} and stat.S_IMODE(info.st_mode) == 0o700,
                    "unexpected attempt/directory")
        else:
            require(name in {"workflow.json", ".workflow.lock", "package-0000/dataset.json", "package-0000/manifest.bin"}
                    or re.fullmatch(r"package-0000/attempt-000[01]/(?:job-[01]|original-0|observation-0|retry-0|result|executor-admission|receipt-[0-9a-f]{32})\.json", name),
                    "unexpected retained file")
            files[name] = FOLLOW["retained_file"](path, uid)
    require(sum(item["bytes"] for item in files.values()) <= 4 * 1048576, "retained bytes limit")
    return files


def capture(work):
    JOBS["guest_work"](work)
    require(not alive(read(record(work, "owner"))["identity"]), "owner not reaped")
    raw = (work / f"{PREFIX}-output.jsonl").read_bytes()
    events, result = FOLLOW["parse_output"](raw)
    write(record(work, "retained"), {"files": retained_tree(workflow(work)), "stdout": {**hashes(raw), "hex": raw.hex()},
          "events": events, "result": result, "handles": initial_handles(work), "owner_reaped": True})


def validate_path(phase, peers, layout, required_nodes):
    route, privacy, control = phase["selected_route"], phase["privacy"], phase["control_privacy"]
    require(route["transport"] == "mptcp" and route["route_context_id"] == layout["route_context_id"]
            and len(route["paths"]) == len(route["benchmark_slots"]) == 2
            and len({path["relay_peer_id"] for path in route["paths"]}) == 2
            and all(path["exit_peer_id"] == peers["exit"] and path["route_context_id"] == route["route_context_id"]
                    for path in route["paths"]), "original two-path protected route changed")
    slots = route["benchmark_slots"]
    require([slot["relay_peer_id"] for slot in slots] == [path["relay_peer_id"] for path in route["paths"]]
            and all(slot["relay_node"] in CUSTODY["ROLES"][1:4] and peers[slot["relay_node"]] == slot["relay_peer_id"]
                    for slot in slots), "physical relay lineage missing")
    require(set(privacy) == set(CUSTODY["ROLES"]), "five role captures required")
    for role, item in privacy.items():
        SHARED["validate_drained"](item, allow_empty=role in CUSTODY["ROLES"][1:4]
                                   and role not in [slot["relay_node"] for slot in slots])
        require(item["capture_role"] == role and item["content_provider_mode"] is True
                and item["unexpected_outer_packets"] == item["unexpected_provider_application_packets"]
                    == item["expected_link_down_notifications"] == 0
                and set(item["provider_application"]) == set(JOBS["NODES"]), "unexpected provider traffic")
        if role != "exit":
            require(all(number == 0 for counters in item["provider_application"].values() for number in counters.values()),
                    "provider request bypassed protected exit")
    require(privacy["client"]["direct_client_exit_packets"] == privacy["client"]["internet_destination_outer_packets"]
            == privacy["exit"]["direct_client_exit_packets"] == privacy["exit"]["client_public_packets"]
            == privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[node]["internet_destination_outer_packets"] == 0 for node in CUSTODY["ROLES"][1:4]),
            "privacy boundary violated")
    for slot in slots:
        item = privacy[slot["relay_node"]]
        require(item["client_leg_wireguard_data_datagrams"] > 0 and item["exit_leg_wireguard_data_datagrams"] > 0,
                "selected two-leg WireGuard paths inactive")
    for node in required_nodes:
        item = privacy["exit"]["provider_application"][node]
        require(item["request_packets"] > 0 and item["response_payload_bytes"] > 0, "actual peer exchange absent")
    control_node = next(node for node, peer in peers.items() if peer == layout["control_relay_peer_id"])
    require(control_node in {"relay0", "relay1", "relay2"}, "provider became own broker")
    expected = {f"ac{i}": [SHARED["PUBLIC_IPS"][control_node], SHARED["PUBLIC_IPS"][node]] for i, node in enumerate(JOBS["NODES"])}
    SHARED["validate_drained"](control)
    require(control["capture_role"] == "content-control" and control["content_provider_mode"] is True
            and control["content_control_pairs"] == expected and set(control["interfaces"]) == set(expected)
            and set(control["content_control_packets"]) == set(expected)
            and control["unexpected_provider_control_packets"] == control["unexpected_provider_application_packets"] == 0
            and all(number == 0 for item in control["provider_application"].values() for number in item.values()),
            "three discovery-only links leaked application data")


def check_evidence(value, revision):
    require(value["source_revision"] == revision and value["success"] is True, "wrong recovery build")
    JOBS["check_overlap"](value["observation"])
    source, published, loss, layout, retained = (value[name] for name in ("source", "publish", "loss", "layout", "retained"))
    files = retained["files"]
    get = lambda name: FOLLOW["decode"](files, name)
    enrollment = get("workflow.json")
    original = [entry["value"] for entry in loss["original_handles"]]
    require(retained["handles"] == loss["original_handles"] == value["originals"]["handles"]
            and retained["owner_reaped"] is True and value["originals"]["third_broker_previously_absent"] is True
            and set(layout["provider_nodes"]) == {"relay4", "relay5"}
            and enrollment["provider_keys"] == [handle["provider_key"] for handle in original]
            and enrollment["replace_peers"] is True, "initial peers/permission changed")
    require(value["provision"]["success"] is True and value["provision"]["training_performed"] is False
            and source["explicit_public_source"] is True and source["dataset"]["source_revision"] == revision
            and source["dataset"]["visibility"] == "public" and source["dataset"]["license"] == "GPL-3.0-only"
            and hashes(source["dataset_json"].encode()) == source["dataset_file"], "source/provision changed")
    manifest = JOBS["source_manifest_id"](source, published)
    require(loss["signal"] == "SIGKILL" and loss["signal_number"] == 9 and loss["pidfd_bound"] is True
            and all(loss[k] is True for k in ("signal_sent", "worker_exit_observed", "both_workers_alive_before_signal",
                "surviving_worker_alive_after_signal", "both_brokers_alive_after_signal")), "real worker loss absent")
    statuses = []
    for index, handle in enumerate(original):
        node = layout["provider_nodes"][index]
        observed = next(item for item in value["observation"]["workers"] if item["node"] == node)
        require(CUSTODY["peer_key"](value["peers"][node]) == layout["provider_keys"][node]
                and observed == loss[("victim", "survivor")[index]]
                and observed["dataset_json"] == JOBS["derive"](source["dataset"], [index]), "original worker/node/source lineage changed")
        JOBS["check_loss_handle"](handle, source["dataset"], published, manifest, node, layout)
        name = FIRST + f"receipt-{handle['binding']['job_id']}.json"
        receipt = get(name)
        require(get(FIRST + f"job-{index}.json") == handle and files[name] == value["originals"]["receipts"][index]
                and receipt["handle"] == handle and receipt["status"]["binding"] == handle["binding"], "original receipt altered")
        statuses.append(receipt["status"])
    require(statuses[0]["state"] == "failed" and statuses[0]["error"] == "worker_failed" and statuses[1]["state"] == "complete",
            "missing terminal failed/kept parts")
    first, retry = get(FIRST + "result.json"), get(RETRY + "retry-0.json")
    require(first["complete"] is False and first["outputs"][0] is None, "failed first round overstated")
    JOBS["check_loss_completed"](statuses[1], original[1], revision, first["outputs"][1])
    admission, handle = get(RETRY + "executor-admission.json"), retry["handle"]
    key = value["new_public"]["identity_public_key_hex"]
    require(key == CUSTODY["peer_key"](value["peers"]["relay3"]) and key not in enrollment["provider_keys"]
            and admission["version"] == 1 and admission["provider_keys"] == [key]
            and handle["provider_key"] == key and handle["binding"]["row_indices"] == [0]
            and retry["original_handle"] == original[0] and retry["original_state"] == "stopped"
            and retry["retried"] is True and retry["prior_terminal_receipt_received"] is True
            and handle["binding"]["job_id"] not in [h["binding"]["job_id"] for h in original]
            and handle["binding"]["model_fingerprint"] == enrollment["model_fingerprint"] == original[0]["binding"]["model_fingerprint"],
            "new peer/source/model/retry authority missing")
    auth = admission["authorization"]
    require(auth == dict(workflow_sha256=files["workflow.json"]["sha256"],
            publisher_key=published["publisher_key_hex"], dataset_manifest_id=manifest, dataset_sha256=source["dataset_file"]["sha256"],
            model_fingerprint=enrollment["model_fingerprint"], task=None, document=False, derived=False,
            enrolled_at=enrollment["verified_at_unix_seconds"], source_expires=published["expires_unix_seconds"])
            and auth["enrolled_at"] <= admission["observed_at"] < auth["source_expires"]
            and files[RETRY + "executor-admission.json"]["modified_unix_ns"] <= files[RETRY + "job-0.json"]["modified_unix_ns"],
            "immutable original authorization/admission-before-submit absent")
    extra_layout = dict(layout, provider_keys=dict(layout["provider_keys"], relay3=key))
    JOBS["check_loss_handle"](handle, source["dataset"], published, manifest, "relay3", extra_layout)
    result = get(RETRY + "result.json")
    require(result["complete"] is True and result["requested_rows"] == [0] and result["jobs"] == [retry]
            and get(RETRY + "job-0.json") == handle and get(RETRY + "original-0.json") == original[0], "new attempt changed work")
    JOBS["check_loss_completed"](retry["status"], handle, revision, result["outputs"][0])
    require(get(RETRY + f"receipt-{handle['binding']['job_id']}.json")["status"] == retry["status"], "new terminal receipt missing")
    required = {".workflow.lock", "workflow.json", "package-0000/dataset.json", "package-0000/manifest.bin",
                FIRST + "job-0.json", FIRST + "job-1.json", FIRST + "result.json",
                *(FIRST + f"receipt-{h['binding']['job_id']}.json" for h in original),
                *(RETRY + name for name in ("original-0.json", "observation-0.json", "job-0.json", "retry-0.json", "result.json", "executor-admission.json")),
                RETRY + f"receipt-{original[0]['binding']['job_id']}.json", RETRY + f"receipt-{handle['binding']['job_id']}.json"}
    require(set(files) == required and get(RETRY + f"receipt-{original[0]['binding']['job_id']}.json")["status"] == statuses[0]
            and get(RETRY + "observation-0.json") == dict(handle=original[0], state="stopped", status=statuses[0]),
            "extra worker/attempt or lost original terminal authorization")
    owner, pause, cut, continued = (value[name] for name in ("owner", "pause", "cutover", "continued"))
    require(owner["discover_peers"] is True and owner["replace_peers"] is True and owner["manual_resume"] is False
            and pause["owner"] == cut["owner"] == continued["owner"] == owner
            and pause["signal"] == "SIGSTOP" and continued["signal"] == "SIGCONT"
            and pause["pidfd_bound"] is True and continued["pidfd_bound"] is True and cut["old_brokers_ended"] is True
            and 0 < loss["exit_boottime_ns"] < pause["sent_boottime_ns"] < cut["observed_boottime_ns"] < continued["sent_boottime_ns"],
            "same-owner deterministic broker cutover unproven")
    replacement, worker = value["replacement"], value["replacement"]["worker"]
    require(replacement["same_owner_alive"] is True and replacement["owner"] == owner and replacement["handle"] == handle
            and worker["node"] == "relay3" and worker["broker"] == cut["broker"]
            and worker["worker"] not in [loss[name]["worker"] for name in ("victim", "survivor")]
            and worker["dataset_json"] == JOBS["derive"](source["dataset"], [0])
            and continued["sent_boottime_ns"] < replacement["first_boottime_ns"]
            and 0 < handle["binding"]["expires_unix_seconds"] - replacement["handle_saved_unix_seconds"] <= 600,
            "actual new independent worker/unchanged lease bound missing")
    require(worker["network_devices"] == ["lo"] and worker["ipv4_routes"] == [] and worker["runtime_lock_held"] is True
            and worker["effective_capabilities"] == 0 and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][name] for name in ("/runtime", "/model", "/dataset.json"))
            and all(worker["worker_namespaces"][name] != worker["guest_namespaces"][name] for name in ("net", "pid", "ipc", "mnt"))
            and worker["worker_namespaces"]["net"] != worker["node_namespace"]
            and worker["node_namespace"] not in [loss[name]["node_namespace"] for name in ("victim", "survivor")]
            and all(worker["runtime_lock_inode"] != loss[name]["runtime_lock_inode"] for name in ("victim", "survivor"))
            and worker["dataset_file"]["sha256"] == handle["binding"]["dataset_sha256"], "new worker sandbox/independent runtime missing")
    tick_ns = 10**9 // replacement["clock_ticks_per_second"]
    require(worker["worker"]["start_ticks"] * tick_ns + tick_ns >= continued["sent_boottime_ns"], "replacement preceded cutover")
    raw = bytes.fromhex(retained["stdout"]["hex"])
    require(hashes(raw) == {k: retained["stdout"][k] for k in ("bytes", "sha256")}, "stdout changed")
    events, final = FOLLOW["parse_output"](raw)
    require(events == retained["events"] and final == retained["result"] and final["completed_packages"] == 1
            and final["packages"][0]["attempts"] == 2 and final["packages"][0]["pending_handles"] == [], "owner did not complete exact attempts")
    outputs = final["packages"][0]["outputs"]
    require(outputs == [dict(result["outputs"][0], report_sha256=retry["status"]["report_sha256"]),
                        dict(first["outputs"][1], report_sha256=statuses[1]["report_sha256"])], "completed row was rerun/replaced")
    for name in files:
        FOLLOW["decode"](files, name, True)
    validate_path(value["paths"]["initial"], value["peers"], layout, layout["provider_nodes"])
    validate_path(value["paths"]["replacement"], value["peers"], layout, ["relay3"])
    require(value["paths"]["replacement"]["privacy"]["exit"]["provider_application"]["relay3"]["response_payload_bytes"]
                >= len(retry["status"]["report_json"].encode())
            and value["paths"]["initial"]["privacy"]["exit"]["provider_application"][layout["provider_nodes"][1]]["response_payload_bytes"]
                >= len(statuses[1]["report_json"].encode()), "captures did not carry actual original/replacement reports")
    require(all(value["cleanup"].values()), "owned compute cleanup incomplete")


def evidence(work, revision):
    value = {name: read(work / f"agent-jobs-{name}.json") for name in ("source", "publish", "layout", "observation", "provision")}
    value.update({name: read(record(work, name), 12 * 1048576) for name in ("owner", "pause", "originals", "cutover", "continued", "retained")})
    value.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"),
                 new_public=read(work / "agent-jobs-relay3-public.json"), loss=read(work / "agent-jobs-loss-control.json"),
                 replacement=read(work / "agent-jobs-replacement-observation.json"), cleanup=read(work / "agent-jobs-private-cleanup.json"))
    value["paths"] = {phase: {"selected_route": read(work / f"{PREFIX}-{phase}-live-selection.json"),
         "privacy": {role: read(work / f"content-custody-peer-{phase}-privacy-{role}.json") for role in CUSTODY["ROLES"]},
         "control_privacy": read(work / f"content-provider-adaptive-peer-{phase}-control.json")}
         for phase in ("initial", "replacement")}
    check_evidence(value, revision)
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    path = record(work, "evidence")
    proof = read(path, 16 * 1048576) if path.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    write(record(work, "smoke"), dict(report_kind=KIND, scope=SCOPE, source_revision=revision,
          success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and proof is not None,
          runner_exit_status=status, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
          fixture_controlled_owner_pause=True, full_b03_claimed=False, full_alpha_claimed=False,
          exactly_once_execution_claimed=False, original_lease_extension_claimed=False,
          evidence=proof, cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host))


def report(value, revision):
    require(value["report_kind"] == KIND and value["scope"] == SCOPE and value["source_revision"] == revision
            and value["success"] is True and value["runner_exit_status"] == 0 and value["observed_blocker"] is None
            and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"]
            and value["fixture_controlled_owner_pause"] is True
            and all(value[key] is False for key in ("full_b03_claimed", "full_alpha_claimed", "exactly_once_execution_claimed", "original_lease_extension_claimed")),
            "new-peer recovery or host preservation incomplete/overstated")
    check_evidence(value["evidence"], revision)


def contract_fixture():
    """Synthetic parser contract only; never interpreted as executed evidence."""
    value = FOLLOW["contract_fixture"]()
    files = value["retained"]["files"]
    def put(name, item):
        raw = json.dumps(item, separators=(",", ":")).encode()
        old = files.get(name, {"inode": [1, 99], "modified_unix_ns": 2100 * 10**9})
        files[name] = {**old, **hashes(raw), "hex": raw.hex()}
    get = lambda name: FOLLOW["decode"](files, name)
    key = "1" * 64
    # Encode the standard identity-multihash Ed25519 protobuf for the synthetic key.
    number = int.from_bytes(bytes.fromhex("002408011220" + key), "big")
    alphabet, encoded = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", ""
    while number:
        number, digit = divmod(number, 58)
        encoded = alphabet[digit] + encoded
    value["peers"]["relay3"] = "1" + encoded
    value["new_public"] = {"identity_public_key_hex": key}
    old = get("workflow.json")
    enrollment = {"version": old["version"], "verified_at_unix_seconds": old["verified_at_unix_seconds"],
                  "provider_keys": old["provider_keys"], "model_fingerprint": "f" * 64,
                  "replace_peers": True, "packages": old["packages"]}
    put("workflow.json", enrollment)
    retry = get(RETRY + "retry-0.json")
    retry["handle"]["provider_key"] = key
    handle = retry["handle"]
    put(RETRY + "retry-0.json", retry)
    put(RETRY + "job-0.json", handle)
    path = RETRY + f"receipt-{handle['binding']['job_id']}.json"
    receipt = get(path)
    receipt["handle"] = handle
    put(path, receipt)
    result = get(RETRY + "result.json")
    result["jobs"] = [retry]
    result["outputs"][0]["provider_key"] = key
    put(RETRY + "result.json", result)
    manifest = enrollment["packages"][0]["manifest_id"]
    auth = dict(workflow_sha256=hashes(json.dumps(enrollment, separators=(",", ":")).encode())["sha256"],
                publisher_key=value["publish"]["publisher_key_hex"], dataset_manifest_id=manifest,
                dataset_sha256=value["source"]["dataset_file"]["sha256"], model_fingerprint="f" * 64,
                task=None, document=False, derived=False, enrolled_at=1000, source_expires=3000)
    put(RETRY + "executor-admission.json", dict(version=1, authorization=auth, observed_at=2100, provider_keys=[key]))
    value["originals"] = dict(handles=value["loss"]["original_handles"], receipts=value["replacement"]["original_receipts"],
                              third_broker_previously_absent=True, owner_stopped=True)
    owner = {k: v for k, v in value["owner"].items() if k not in {"alive_after_loss", "observed_boottime_ns"}}
    owner.update(discover_peers=True, replace_peers=True)
    value["owner"] = owner
    value["pause"] = dict(owner=copy.deepcopy(owner), signal="SIGSTOP", pidfd_bound=True, sent_boottime_ns=3 * 10**9)
    value["cutover"] = dict(owner=copy.deepcopy(owner), old_brokers_ended=True, node="relay3",
                             broker={"pid": 3333, "start_ticks": 333}, observed_boottime_ns=4 * 10**9)
    value["continued"] = dict(owner=copy.deepcopy(owner), signal="SIGCONT", pidfd_bound=True, sent_boottime_ns=5 * 10**9)
    replacement = value["replacement"]
    replacement.update(owner=copy.deepcopy(owner), handle=handle)
    replacement["worker"].update(node="relay3", broker=value["cutover"]["broker"], node_namespace="net:[303]", runtime_lock_inode=[2, 303])
    final = value["result"]
    final["packages"][0]["outputs"][0]["provider_key"] = key
    retained = value["retained"]
    raw = (json.dumps(retained["events"][0]) + "\n" + json.dumps(final) + "\n").encode()
    retained.update(handles=retained["original_handles_after"], stdout={**hashes(raw), "hex": raw.hex()}, result=final)
    value["paths"] = {name: copy.deepcopy(value["path"]) for name in ("initial", "replacement")}
    for phase in value["paths"].values():
        control = phase["control_privacy"]
        control["content_control_pairs"] = {f"ac{i}": [SHARED["PUBLIC_IPS"]["relay2"], SHARED["PUBLIC_IPS"][node]]
                                              for i, node in enumerate(JOBS["NODES"])}
        control["interfaces"] = ["ac0", "ac1", "ac2"]
        control["observed_frames"] = 300
        control["interface_statistics"] = {f"ac{i}": copy.deepcopy(control["interface_statistics"]["cp0"]) for i in range(3)}
        control["content_control_packets"] = {f"ac{i}": dict(inbound=50, outbound=50) for i in range(3)}
    value["paths"]["replacement"]["privacy"]["exit"]["provider_application"]["relay3"] = dict(
        request_packets=20, response_packets=20, response_payload_bytes=20000)
    return value


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        FOLLOW["self_test"]()
        # Pure contract rejection: this scenario must not accept the old survivor
        # fixture as evidence of a previously absent third executor.
        old = FOLLOW["contract_fixture"]()
        try:
            check_evidence(old, "a" * 40)
        except (KeyError, ValueError):
            pass
        else:
            raise AssertionError("survivor-only recovery accepted as new peer")
        value = contract_fixture()
        check_evidence(value, "a" * 40)
        changes = {
            "old_broker_still_present": lambda x: x["cutover"].update(old_brokers_ended=False),
            "not_new_peer": lambda x: x["originals"].update(third_broker_previously_absent=False),
            "different_owner": lambda x: x["continued"]["owner"]["identity"].update(pid=999),
            "survivor_used": lambda x: x["replacement"]["worker"].update(node="relay5"),
            "no_actual_worker_loss": lambda x: x["loss"].update(worker_exit_observed=False),
            "receipt_changed": lambda x: x["originals"]["receipts"][1].update(sha256="0" * 64),
            "missing_admission": lambda x: x["retained"]["files"].pop(RETRY + "executor-admission.json"),
            "direct_exit": lambda x: x["paths"]["replacement"]["privacy"]["client"].update(direct_client_exit_packets=1),
            "cleanup_incomplete": lambda x: x["cleanup"].update(done=False),
        }
        for name, change in changes.items():
            altered = copy.deepcopy(value)
            change(altered)
            try:
                check_evidence(altered, "a" * 40)
            except (KeyError, ValueError):
                continue
            raise AssertionError(f"invalid new-peer evidence accepted: {name}")
        print("new-peer positive contract and 10 negative gates PASS; synthetic only, no guest, model, signal or network executed")
    elif args[0] == "pause-after-loss" and len(args) == 3:
        pause_after_loss(Path(args[1]), int(args[2]))
    elif args[0] == "cutover" and len(args) == 2:
        cutover(Path(args[1]))
    elif args[0] in {"continue-owner", "cleanup-owner"} and len(args) == 2:
        continue_owner(Path(args[1]), args[0] == "cleanup-owner")
    elif args[0] == "observe-replacement" and len(args) == 2:
        observe_replacement(Path(args[1]))
    elif args[0] == "capture" and len(args) == 2:
        capture(Path(args[1]))
    elif args[0] == "evidence" and len(args) == 3:
        evidence(Path(args[1]), args[2])
    elif args[0] == "finalize" and len(args) == 8:
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif args[0] == "report" and len(args) == 3:
        report(read(Path(args[1]), 16 * 1048576), args[2])
    else:
        raise ValueError("invalid new-peer recovery collector command")


if __name__ == "__main__":
    main()
