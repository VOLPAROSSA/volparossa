#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Additive guest-only C→A rollback and no-predecessor withdrawal proof.

Requires the preceding genuine autonomous aggregate and approved local successor.
No invented approval, model execution on the host, or claim of aggregate→aggregate recovery.
"""
import copy
import json
import os
from pathlib import Path
import runpy
import signal
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
AUTO = runpy.run_path(str(HERE / "agent-autonomous-aggregation-smoke.py"))
A, R, S, JOBS, TRAIN = (AUTO[key] for key in ("A", "R", "S", "JOBS", "TRAIN"))
read, write, require, digest = (AUTO[key] for key in ("read", "write", "require", "digest"))
PREFIX = "agent-aggregate-recovery"
ROUND, CYCLE, MAX_PROOF = (AUTO[key] for key in ("ROUND", "CYCLE", "MAX_PROOF"))
LOCAL_FILE = f"{CYCLE}/training/adapter/adapter_model.safetensors"
AGGREGATE_FILE = f"{ROUND}/candidate/import/adapter/adapter_model.safetensors"
SCOPE = "real-approved-local-C-to-original-aggregate-A-then-no-approved-predecessor-blocked"


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def identities(files):
    return {name: {key: item[key] for key in ("bytes", "sha256")} for name, item in files.items()}


def current(work):
    loop = AUTO["root"](work)
    serving = A["private"](work, "relay4") / "serving"
    return dict(files=identities(A["snapshot"](loop)), state=read(loop / "state.json", MAX_PROOF),
        serving_hex=(serving / "current.json").read_bytes().hex(),
        withdrawal=read(serving / "withdrawal.json") if (serving / "withdrawal.json").exists() else None,
        observed_unix_seconds=int(time.time()))


def prepare(work):
    first = read(AUTO["record"](work, "first"), MAX_PROOF)
    resumed = read(AUTO["record"](work, "resumed"), MAX_PROOF)
    AUTO["unchanged_completed"](first, resumed)
    raw = R["raw_files"](first["files"])
    evaluation, training, validation = (json.loads(raw[f"{CYCLE}/{name}"])
        for name in ("evaluation.json", "training-report.json", "validation.json"))
    require(AUTO["local_approval"](training, validation, evaluation) is True
        and first["state"]["latest"] == 1 and first["state"]["promoted"] == 1,
        "recovery requires an actually approved local successor, not a forced promotion")
    require(evaluation["aggregate_predecessor"]["aggregate_sequence"] == 1
        and evaluation["aggregate_predecessor"]["local_predecessor"] is None
        and first["state"]["aggregate_updates"]["rounds"][0]["baseline_origin"] == dict(kind="pinned_base"),
        "recovery fixture does not have exact C→A→base lineage")
    snapshot = current(work)
    require(snapshot["files"] == resumed["snapshot"] and snapshot["state"] == resumed["state"]
        and snapshot["serving_hex"] == resumed["serving_hex"], "original autonomous state changed before injection")
    # Preserve the previous component's originals before the first byte mutation.
    snapshots = {name: digest(AUTO["record"](work, name).read_bytes()) for name in
        ("first", "resumed", "handle", "status", "receiver-files", "receiver-inference-files", "receiver-inference")}
    write(record(work, "before"), dict(snapshot, original_artifacts=snapshots,
        original_aggregate=evaluation["aggregate_predecessor"], source_revision=training["dataset"]["source_revision"]))


def inject(work, label):
    require(label in ("local", "aggregate"), "unknown extraction fault")
    before = current(work)
    if label == "aggregate":
        restored = read(record(work, "restarted"), MAX_PROOF)
        require(before["files"] == restored["files"] and before["state"] == restored["state"],
            "state changed between restored job and aggregate fault")
    path = AUTO["root"](work) / (LOCAL_FILE if label == "local" else AGGREGATE_FILE)
    expected = before["files"][path.relative_to(AUTO["root"](work)).as_posix()]
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == AUTO["root"](work).stat().st_uid != 0
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 2 * 1024 * 1024,
            "fault target not the exact bounded owner extraction")
        original = os.read(descriptor, info.st_size + 1)
        require(digest(original) == expected, "extraction changed before fault")
        os.lseek(descriptor, info.st_size - 1, os.SEEK_SET)
        require(os.write(descriptor, bytes([original[-1] ^ 1])) == 1, "fault byte not written")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    after = current(work)
    changed = [name for name in before["files"] if before["files"][name] != after["files"][name]]
    require(changed == [path.relative_to(AUTO["root"](work)).as_posix()]
        and before["state"] == after["state"] and before["serving_hex"] == after["serving_hex"],
        "fault modified anything except one extracted weight byte")
    write(record(work, f"{label}-fault"), dict(before=expected, after=after["files"][changed[0]],
        changed_paths=changed, injected_unix_seconds=int(time.time()), publisher_malice_claimed=False))


def observe_loop(work, label, pid):
    require(label in ("local", "resume"), "wrong resume phase")
    owner = TRAIN["identity"](pid)
    write(record(work, f"{label}-owner"), owner)
    deadline = time.monotonic() + 120
    expected = read(record(work, "before"), MAX_PROOF)["original_aggregate"]
    errors = work / f"{AUTO['PREFIX']}-recovery-{label}.err"
    observed = {}
    while time.monotonic() < deadline and TRAIN["alive"](owner):
        for process in TRAIN["descendants"](pid):
            observed[(process["pid"], process["start_ticks"])] = process
            try:
                require(Path(f"/proc/{process['pid']}/cmdline").read_bytes().split(b"\0")[0]
                    != b"/runtime/bin/python3", "recovery started new model work")
            except FileNotFoundError:
                continue
        state = read(AUTO["root"](work) / "state.json", MAX_PROOF)
        serving = read(A["private"](work, "relay4") / "serving/current.json")
        stderr = errors.read_bytes()
        require(len(stderr) <= 262144, "recovery loop diagnostic bound")
        if (state["latest"] is None and state["aggregate_updates"]["active"] == 1
                and state["cycles"][0].get("retirement") is not None
                and serving["provenance"].get("origin") == expected
                and b"loop_event=approved_serving_snapshot_published" in stderr):
            write(record(work, f"{label}-monitor"), dict(owner=owner, owned_processes=list(observed.values()),
                observed_no_model_worker=True, original_expiry=expected["expires_unix_seconds"]))
            # This event follows Activity initialization and exact serving reconciliation.
            require(TRAIN["alive"](owner), "coordinator exited before owner cancellation")
            os.kill(pid, signal.SIGINT)
            return
        time.sleep(0.02)
    require(False, "original aggregate was not restored and served by actual coordinator")


def capture(work, label, status=0):
    require(label in ("local", "resume", "blocked"), "unknown recovery capture")
    raw = (work / f"{AUTO['PREFIX']}-recovery-{label}.jsonl").read_bytes()
    errors = (work / f"{AUTO['PREFIX']}-recovery-{label}.err").read_bytes()
    require(len(raw) <= 262144 and len(errors) <= 262144, "recovery output bound")
    value = dict(current(work), exit_status=status, stdout=raw.decode(), stderr=errors.decode())
    if label == "blocked":
        require(status == 1 and b"aggregate_retirement_no_verified_predecessor" in errors and not raw,
            "aggregate without approved predecessor did not fail closed")
    else:
        summaries = [json.loads(line) for line in raw.splitlines()]
        require(status == 0 and len(summaries) == 1 and summaries[0]["operation"] == "compute_train_loop"
            and summaries[0]["attempts_this_invocation"] == 0 and summaries[0]["owner_cancelled"] is True,
            "recovery re-executed model work or failed before clean cancellation")
        value["summary"] = summaries[0]
    write(record(work, {"local": "restored", "resume": "restarted", "blocked": "blocked"}[label]), value)


def ready(work, label):
    require(label in ("restored", "blocked"), "unknown broker phase")
    before = read(record(work, "before"), MAX_PROOF)
    adapter = before["original_aggregate"]["adapter_files"]
    caps = read(record(work, f"{label}-capabilities"))
    if label == "restored" and caps["model"]["adapter_files"] != adapter:
        old = json.loads(bytes.fromhex(before["serving_hex"]))["adapter_files"]
        S["capability_ready"](caps, old)
        print("false")
        return
    accepting = S["capability_ready"](caps, adapter)
    print("true" if accepting is (label == "restored") else "false")


def observe_job(work):
    broker = TRAIN["identity"](JOBS["broker_pid"]("relay4"))
    expected = read(record(work, "before"), MAX_PROOF)["original_aggregate"]["adapter_files"]
    dataset = read(work / "agent-jobs-source.json")["dataset"]
    derived = JOBS["derive"](dataset, [0]).encode()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        found = JOBS["worker_snapshot"](work, "relay4", broker, expected_dataset_sha256=digest(derived)["sha256"])
        if found:
            proc = Path(f"/proc/{found['worker']['pid']}")
            require(any(parts[4] == "/adapter" and "ro" in parts[5].split(",")
                for line in (proc / "mountinfo").read_text().splitlines() if len(parts := line.split()) > 5),
                "restored adapter mount not read-only")
            found["adapter_files"] = A["adapter_files"](proc / "root/adapter")
            require(found["adapter_files"] == expected, "protected job did not mount exact original aggregate")
            write(record(work, "job-observation"), found)
            return
        time.sleep(0.02)
    require(False, "restored aggregate inference worker not observed")


def network(work):
    prefix = f"{PREFIX}-path"
    value = dict(layout=read(work / f"{prefix}-layout.json"), selected_route=read(work / f"{prefix}-selection.json"),
        route=read(work / f"{prefix}-live-selection.json"), disconnected=True,
        captures={role: read(work / f"{prefix}-{role}.json") for role in A["REP"]["ROLES"]})
    R["check_network_path"](value, "reserve-fetch", read(work / "a01-expected-peers.json"))
    require(len(json.dumps(value, indent=2)) < A["MAX_NETWORK_REPORT"], "recovery packet report bound")
    write(record(work, "network"), value)


def capture_job(work):
    write(record(work, "handle"), read(A["private"](work, "client") / "aggregate-recovery-job.json"))
    write(record(work, "model-after"), A["file_hash"](A["model"](work, "relay4") / "model.safetensors", 300 * 1024 * 1024))


def cleanup_workers(work):
    processes = [read(path) for path in work.glob(f"{PREFIX}-*-owner.json")]
    for path in work.glob(f"{PREFIX}-*-monitor.json"):
        processes.extend(read(path)["owned_processes"])
    if record(work, "job-observation").exists():
        processes.extend(read(record(work, "job-observation"))["owned_processes"])
    require(not any(TRAIN["alive"](process) for process in processes), "owned recovery process still running")
    if not record(work, "process-cleanup").exists():
        write(record(work, "process-cleanup"), dict(owned_processes=processes,
            all_recorded_processes_ended=True, checked_before_private_store_removal=True))


def normalize_state(value):
    value = copy.deepcopy(value)
    # Discovery scheduling can progress while owner cancellation drains; no model or lease fields may change.
    value["aggregate_updates"].pop("next_poll", None)
    value["aggregate_updates"].pop("verified_cohort_polls", None)
    return value


def snapshot_digest(snapshot):
    raw = json.dumps({name: dict(sha256=item["sha256"], bytes=item["bytes"])
        for name, item in sorted(snapshot.items())}, separators=(",", ":")).encode()
    return digest(raw)["sha256"]


def check_transition(before, fault, restored, restarted):
    aggregate = before["original_aggregate"]
    require(fault["changed_paths"] == [LOCAL_FILE] and fault["publisher_malice_claimed"] is False
        and fault["before"] == before["files"][LOCAL_FILE]
        and fault["after"]["bytes"] == fault["before"]["bytes"] and fault["after"] != fault["before"],
        "local fault was not one bounded extracted-weight change")
    expected_files = copy.deepcopy(before["files"])
    expected_files[LOCAL_FILE] = fault["after"]
    for value in (restored, restarted):
        require({key: item for key, item in value["files"].items() if key != "state.json"}
            == {key: item for key, item in expected_files.items() if key != "state.json"},
            "recovery changed originals or created new model work")
        state = value["state"]
        require(state["latest"] is None and state["aggregate_updates"]["active"] == 1,
            "recovery did not select exact approved aggregate")
        retirement = state["cycles"][0]["retirement"]
        require(retirement["version"] == 1 and retirement["sequence"] == 1
            and retirement["scope"] == "local-successor-extraction-integrity-not-model-or-publisher-verdict"
            and retirement["original_snapshot_sha256"] == snapshot_digest(before["state"]["cycles"][0]["snapshot"])
            and retirement["restored_origin"] == aggregate
            and retirement["restored_expires"] == aggregate["expires_unix_seconds"] > value["observed_unix_seconds"]
            and retirement["observed_at"] >= fault["injected_unix_seconds"], "retirement changed original authority")
        expected_adapter = {name: before["files"][f"{CYCLE}/training/adapter/{name}"] for name in A["FILES"]}
        expected_adapter["adapter_model.safetensors"] = fault["after"]
        require(retirement["observed_adapter_files"] == expected_adapter, "retirement did not preserve observed damage")
        expected_state = copy.deepcopy(before["state"])
        expected_state["latest"] = None
        expected_state["aggregate_updates"]["active"] = 1
        expected_state["cycles"][0]["retirement"] = retirement
        require(normalize_state(state) == normalize_state(expected_state), "recovery changed counts/approval/publication/enrollment")
        serving = json.loads(bytes.fromhex(value["serving_hex"]))
        require(serving["provenance"]["kind"] == "approved_aggregate" and serving["provenance"]["origin"] == aggregate
            and serving["adapter_files"] == aggregate["adapter_files"]
            and serving["expires_unix_seconds"] == aggregate["expires_unix_seconds"], "serving changed aggregate weights or expiry")
        require(value["exit_status"] == 0 and value["summary"]["attempts_this_invocation"] == 0
            and value["summary"]["completed_cycles"] == 1 and value["summary"]["owner_cancelled"] is True,
            "recovery did not exit cleanly without new training")
    require(normalize_state(restored["state"]) == normalize_state(restarted["state"])
        and restored["serving_hex"] == restarted["serving_hex"] and restored["withdrawal"] == restarted["withdrawal"],
        "second restart renewed or changed recovery")


def check(value, original):
    before, restored, restarted, blocked = (value[key] for key in ("before", "restored", "restarted", "blocked"))
    require(value["scope"] == SCOPE and value["source_revision"] == original["source_revision"]
        and value["aggregate_to_aggregate_success_claimed"] is False
        and before["state"] == original["resumed"]["state"] and before["files"] == original["resumed"]["snapshot"]
        and before["serving_hex"] == original["resumed"]["serving_hex"], "recovery substituted pre-fault autonomous originals")
    require(before["state"]["latest"] == 1 and before["state"]["promoted"] == 1,
        "recovery lacks genuine approved local successor")
    require(before["state"]["aggregate_updates"]["rounds"][0]["baseline_origin"] == dict(kind="pinned_base")
        and before["original_aggregate"]["aggregate_sequence"] == 1
        and before["original_aggregate"]["local_predecessor"] is None,
        "recovery scope changed from exact C→A→base lineage")
    check_transition(before, value["local-fault"], restored, restarted)
    fault = value["aggregate-fault"]
    require(fault["changed_paths"] == [AGGREGATE_FILE] and fault["publisher_malice_claimed"] is False
        and fault["before"] == restarted["files"][AGGREGATE_FILE]
        and fault["after"]["bytes"] == fault["before"]["bytes"] and fault["after"] != fault["before"],
        "aggregate fault changed non-extraction evidence")
    expected = copy.deepcopy(restarted["files"]); expected[AGGREGATE_FILE] = fault["after"]
    require(blocked["files"] == expected and blocked["state"] == restarted["state"]
        and blocked["serving_hex"] == restarted["serving_hex"] and blocked["exit_status"] == 1
        and "aggregate_retirement_no_verified_predecessor" in blocked["stderr"] and blocked["stdout"] == "",
        "no-predecessor case modified state, selected base or failed for another reason")
    serving = json.loads(bytes.fromhex(blocked["serving_hex"]))
    require(blocked["withdrawal"] == dict(version=1, owner=serving["owner"],
        selection_id=digest(bytes.fromhex(blocked["serving_hex"]))["sha256"]), "current selection was not actually withdrawn")
    adapter = before["original_aggregate"]["adapter_files"]
    require(S["capability_ready"](value["restored-capabilities"], adapter) is True
        and S["capability_ready"](value["blocked-capabilities"], adapter) is False, "broker did not activate then stop admission")
    handle, status = value["handle"], value["status"]
    derived = JOBS["derive"](original["job-source"]["dataset"], [0]).encode()
    report_ = json.loads(status["report_json"])
    require(status["state"] == "complete" and status["binding"] == handle["binding"]
        and status["report_sha256"] == digest(status["report_json"].encode())["sha256"]
        and handle["provider_key"] == original["layout"]["keys"]["relay4"]
        and handle["binding"]["model_fingerprint"] == value["restored-capabilities"]["model_fingerprint"]
        and handle["binding"]["dataset_sha256"] == digest(derived)["sha256"]
        and handle["binding"]["expires_unix_seconds"] <= serving["expires_unix_seconds"], "protected restored inference receipt changed")
    A["check_supervisor"](report_, "infer", derived)
    observation = value["job-observation"]
    require(report_["input_adapter"]["files"] == adapter and report_["outputs"] and report_["updates_completed"] == 0
        and observation["adapter_files"] == adapter and observation["dataset_json"].encode() == derived
        and observation["network_devices"] == ["lo"] and observation["ipv4_routes"] == []
        and observation["effective_capabilities"] == 0, "actual protected worker did not use original A")
    R["check_network_path"](value["network"], "reserve-fetch", original["peers"])
    require(value["model-after"] == original["sources"]["model_before"]
        and value["process-cleanup"]["all_recorded_processes_ended"] is True,
        "recovery changed the base model or left owned processes")


def evidence(work, revision):
    before = read(record(work, "before"), MAX_PROOF)
    for name, identity in before["original_artifacts"].items():
        require(digest(AUTO["record"](work, name).read_bytes()) == identity, "original autonomous artifact rewritten")
    keys = ("before", "local-fault", "restored", "restarted", "aggregate-fault", "blocked",
        "restored-capabilities", "blocked-capabilities", "handle", "status", "job-observation", "model-after", "process-cleanup")
    value = {name: read(record(work, name), MAX_PROOF) for name in keys}
    value.update(source_revision=revision, scope=SCOPE, aggregate_to_aggregate_success_claimed=False,
        network=read(record(work, "network"), A["MAX_NETWORK_REPORT"]))
    require(len(json.dumps(value)) < 4 * 1024 * 1024, "recovery component proof bound")
    write(record(work, "evidence"), value)


def self_test():
    original = {"a": dict(bytes=3, sha256="a" * 64), "b": dict(bytes=4, sha256="b" * 64)}
    expected = b'{"a":{"sha256":"' + b'a' * 64 + b'","bytes":3},"b":{"sha256":"' + b'b' * 64 + b'","bytes":4}}'
    require(snapshot_digest(original) == digest(expected)["sha256"], "Rust snapshot field ordering changed")
    first = dict(latest=None, promoted=1, aggregate_updates=dict(active=1, next_poll=10, verified_cohort_polls=2))
    other = copy.deepcopy(first); other["aggregate_updates"]["next_poll"] += 1
    require(normalize_state(first) == normalize_state(other), "scheduling normalization changed")
    other["promoted"] = 2
    require(normalize_state(first) != normalize_state(other), "normalization hid promotion changes")
    # Synthetic state exercises only the checker, never claims a real approval/model run.
    adapter = {name: digest(name.encode()) for name in A["FILES"]}
    aggregate = dict(kind="aggregate_update", aggregate_sequence=1, local_predecessor=None,
        adapter_files=adapter, expires_unix_seconds=100)
    files = {f"{CYCLE}/training/adapter/{name}": item for name, item in adapter.items()}
    files.update({"state.json": digest(b"old state"), f"{CYCLE}/adapter.bundle": digest(b"unchanged original bundle")})
    state = dict(latest=1, promoted=1, completed=1, aggregate_updates=dict(active=None, next_poll=1,
        verified_cohort_polls=1), cycles=[dict(sequence=1, phase="complete", snapshot=copy.deepcopy(files))])
    before = dict(files=files, state=state, original_aggregate=aggregate)
    fault = dict(changed_paths=[LOCAL_FILE], publisher_malice_claimed=False,
        before=files[LOCAL_FILE], after=dict(files[LOCAL_FILE], sha256="f" * 64), injected_unix_seconds=10)
    observed = copy.deepcopy(adapter); observed["adapter_model.safetensors"] = fault["after"]
    retirement = dict(version=1, sequence=1, scope="local-successor-extraction-integrity-not-model-or-publisher-verdict",
        original_snapshot_sha256=snapshot_digest(state["cycles"][0]["snapshot"]), observed_adapter_files=observed,
        restored_origin=aggregate, restored_expires=100, observed_at=11)
    recovered_state = copy.deepcopy(state)
    recovered_state["latest"] = None; recovered_state["aggregate_updates"]["active"] = 1
    recovered_state["cycles"][0]["retirement"] = retirement
    recovered_files = copy.deepcopy(files); recovered_files[LOCAL_FILE] = fault["after"]
    recovered_files["state.json"] = digest(b"retired state")
    serving = dict(adapter_files=adapter, expires_unix_seconds=100,
        provenance=dict(kind="approved_aggregate", origin=aggregate))
    restored = dict(files=recovered_files, state=recovered_state, serving_hex=json.dumps(serving).encode().hex(),
        observed_unix_seconds=12, exit_status=0, withdrawal=None,
        summary=dict(attempts_this_invocation=0, completed_cycles=1, owner_cancelled=True))
    restarted = copy.deepcopy(restored); restarted["observed_unix_seconds"] = 13
    check_transition(before, fault, restored, restarted)
    for mutate in (
        lambda value: value["state"].update(promoted=0),
        lambda value: value["state"]["aggregate_updates"].update(active=None),
        lambda value: value["state"]["cycles"][0]["retirement"].update(restored_expires=101),
        lambda value: value["files"][f"{CYCLE}/adapter.bundle"].update(sha256="e" * 64),
        lambda value: value["summary"].update(attempts_this_invocation=1),
    ):
        invalid = copy.deepcopy(restarted); mutate(invalid)
        try:
            check_transition(before, fault, restored, invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("changed original authority, bundle, selection or repeated work accepted")
    print("aggregate recovery inert transition/identity checks PASS; no model/network executed")


def main(args):
    command, *args = args
    if command == "self-test": self_test(); return
    work = Path(args[0]); JOBS["guest_work"](work)
    if command == "prepare": prepare(work)
    elif command == "inject": inject(work, args[1])
    elif command == "observe-loop": observe_loop(work, args[1], int(args[2]))
    elif command == "capture": capture(work, args[1], int(args[2]))
    elif command == "ready": ready(work, args[1])
    elif command == "observe-job": observe_job(work)
    elif command == "capture-job": capture_job(work)
    elif command == "network": network(work)
    elif command == "cleanup-workers": cleanup_workers(work)
    elif command == "evidence": evidence(work, args[1])
    else: raise ValueError("unknown aggregate recovery command")


if __name__ == "__main__":
    main(sys.argv[1:])
