#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Additional actual peer-update adoption proof; pure tests are not ML/network evidence."""

import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
LOOP = runpy.run_path(str(HERE / "agent-train-loop-smoke.py"))
ART, TRAIN, REP = (LOOP[key] for key in ("ART", "TRAIN", "REP"))
read, write, require, file_hash = (ART[key] for key in ("read", "write", "require", "file_hash"))
FILES = LOOP["FILES"]
MAX_EXPORT = 32 * 1024 ** 2
ROUND = "peer-update-0000000000000001"
CYCLE = "cycle-0000000000000001"
STAGES = ("peer-baseline", "peer-candidate", "training", "validation-baseline", "validation-candidate")
SCOPE = ("A distinct R3 consumer/contributor discovers an explicitly trusted R4 adapter without a seed or copied adapter, "
         "compares pinned-base and received weights on the same explicitly selected public validation set, "
         "adopts only the measured improvement and performs eight real updates from those received weights. "
         "Both local successor gates precede any own publication. Original R5 content service is stopped. "
         "Shared explicitly provisioned base/runtime, not base distribution, joint optimization, an independent "
         "benchmark, poisoning resistance, general quality improvement, full B05 or full alpha.")


def digest(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def configuration(path):
    """Read only the fixed fixture's consent/bind fields, never export raw configuration."""
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.name == "config-relay3.yaml" and stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 16384,
            "unexpected learner configuration")
    text = path.read_text(encoding="ascii")
    expected = {
        "roles": {"client": "true", "relay": "true", "exit": "false"},
        "sharing": {"enabled": "true", "interface": "r3x"},
        "download_sharing": {"enabled": "true", "interface": "r3x"},
        "content_contribution": {"enabled": "true", "bind_address": '"48.164.4.1:18080"',
            "advertised_hostname": "provider-c.volparossa.test",
            "cache": json.dumps(str(path.parent / "state-relay3/custody-cache"))},
    }
    for section, fields in expected.items():
        blocks = re.findall(r"(?m)^" + section + r":\n((?:[ \t].*\n)+)", text)
        require(len(blocks) == 1, "missing or duplicate learner consent section")
        for field, value in fields.items():
            actual = re.findall(r"(?m)^  " + field + r": (.*)$", blocks[0])
            require(actual == [value], "learner consent or fixed endpoint changed")
    return dict(learner="relay3", client_enabled=True, relay_enabled=True, exit_enabled=False,
                contribution_enabled=True, sharing_enabled=True, download_sharing_enabled=True,
                bind_address="48.164.4.1:18080", advertised_hostname="provider-c.volparossa.test",
                contribution_cache="state-relay3/custody-cache")


def check_participation(value):
    require(value["configuration"] == dict(learner="relay3", client_enabled=True, relay_enabled=True,
                exit_enabled=False, contribution_enabled=True, sharing_enabled=True, download_sharing_enabled=True,
                bind_address="48.164.4.1:18080", advertised_hostname="provider-c.volparossa.test",
                contribution_cache="state-relay3/custody-cache"), "actual learner contribution configuration missing")
    require(value["network"] == dict(learner="relay3", identity_readable=True,
                other_node_stores_inaccessible=True, publisher_private_root_inaccessible=True,
                links=["lr0:r0l", "lr1:r1l", "lr2:r2l"], segments=[110, 112, 114],
                exit_link_serving_only=True), "actual learner isolation or owned link scope changed")
    require(value["service_before"]["serving"] is True and value["service_before"]["replication_enabled"] is True
            and value["service_stop"]["serving"] is False, "learner serving lifecycle missing")
    require(value["network_cleanup"] == dict(learner="relay3", agent_stopped=True, owned_link_pairs_absent=3,
                serving_filter_removed=True, prior_topology_restored=True), "learner temporary topology remains")


def setup(path, publisher):
    root = ART["private_root"](path)
    state = read(root / "loop/state.json", 4 * 1024 ** 2)
    latest = state["latest"]
    require(latest in (1, 2) and TRAIN["HASH"].fullmatch(publisher), "no approved provider update")
    cycle = root / "loop" / f"cycle-{latest:016x}"
    selected = read(cycle / "selection.json")
    require(read(cycle / "evaluation.json")["approved"] is True, "provider update was rejected")
    source = dict(publisher_key=selected["publisher_key"], name=selected["dataset_name"],
                  min_revision=read(cycle / "source-provenance.json")["source_receipt"]["revision"],
                  manifest_id=file_hash(cycle / "dataset.manifest", 65536)["sha256"])
    validation = read(root / "loop-validation-source.json")
    channels = dict(version=1, channels=[dict(publisher_key=publisher, name="disposable-loop-update", min_revision=latest)])
    write(root / "peer-plan.json", dict(version=1, sources=[source]))
    write(root / "peer-channels.json", channels)
    write(root / "peer-validation-source.json", validation)
    with (root / "peer-passphrase").open("xb") as stream:
        stream.write(os.urandom(32).hex().encode() + b"\n")
    (root / "peer-passphrase").chmod(0o600)
    require(not (root / "peer-learning").exists(), "consumer loop already exists")
    original = {name: (cycle / name).read_bytes().hex()
                for name in ("publication.pb", "adapter.bundle", "dataset.json", "dataset.manifest")}
    return dict(version=1, source=source, validation=validation, channels=channels,
                provider_sequence=latest, provider_files=original,
                provider_adapter_files={name: file_hash(cycle / "training/adapter" / name, 2 * 1024 ** 2) for name in FILES},
                provider_parameters=read(cycle / "training-report.json")["adapter_after"],
                provider_lineage=read(root / f"loop-{latest}-isolation.json")["node_lineage"],
                seed_configured=False, adapter_copied=False)


def stage_paths(root):
    peer = root / "peer-learning" / ROUND
    cycle = root / "peer-learning" / CYCLE
    imported = peer / "import/adapter"
    return ((peer / "comparison/dataset.json", peer / "comparison/baseline", None),
            (peer / "comparison/dataset.json", peer / "comparison/candidate", imported),
            (cycle / "dataset.json", cycle / "training", imported),
            (cycle / "validation/dataset.json", cycle / "validation/baseline", imported),
            (cycle / "validation/dataset.json", cycle / "validation/candidate", cycle / "training/adapter"))


def observe(pid, path, namespace, service):
    TRAIN["guest_guard"](root=True)
    root, namespace = Path(path), Path(namespace)
    owner = TRAIN["identity"](pid)
    for label, (dataset, output, adapter) in zip(STAGES, stage_paths(root)):
        deadline = time.monotonic() + 90
        while not output.is_dir():
            require(TRAIN["alive"](owner) and time.monotonic() < deadline, "expected real peer-learning stage was not admitted")
            time.sleep(0.05)
        raw = root / f"peer-{label}-isolation.raw.json"
        ART["observe"](pid, raw, root / "provision", dataset, root / "private-canary",
                       "training", "relay3", namespace, service)
        evidence = read(raw)
        worker = Path(f"/proc/{evidence['worker']['pid']}")
        actual, expected = (worker / "root/output").stat(), output.stat()
        require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), "observer found another worker stage")
        mounts = [line.split()[5].split(",") for line in (worker / "mountinfo").read_text().splitlines()
                  if line.split()[4] == "/adapter"]
        exact = {}
        if adapter is None:
            require(mounts == [] and not (worker / "root/adapter").exists(), "cold baseline already has an adapter")
        else:
            require(len(mounts) == 1 and "ro" in mounts[0], "received adapter mount is not readonly")
            for name in FILES:
                actual, expected = (worker / "root/adapter" / name).stat(), (adapter / name).stat()
                exact[name] = (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
            require(all(exact.values()), "worker used copied or different weights")
        observation = dict(raw=evidence, stage=label, output_exact_inode=True,
                           adapter_absent=adapter is None, adapter_readonly=adapter is not None, adapter_exact_inodes=exact)
        target = root / f"peer-{label}-isolation.json"
        write(target, observation)
        info = raw.stat()
        os.chown(target, info.st_uid, info.st_gid)
        deadline = time.monotonic() + 605
        while TRAIN["alive"](evidence["worker"]):
            require(time.monotonic() < deadline, "actual model stage exceeded original deadline")
            time.sleep(0.05)


def collect_tree(root):
    owner = root.lstat()
    require(stat.S_ISDIR(owner.st_mode) and stat.S_IMODE(owner.st_mode) == 0o700, "unsafe peer loop root")
    result, total = {}, 0
    for count, path in enumerate(root.rglob("*")):
        require(count < 160, "unbounded peer-learning tree")
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        require(info.st_uid == owner.st_uid and not path.is_symlink(), "wrong retained owner or symlink")
        require(relative in ("state.json", "enrollment.json", ".coordinator.lock", "validation-input", ROUND, CYCLE)
                or relative.startswith(("validation-input/", ROUND + "/", CYCLE + "/")), "unapproved retained path")
        if stat.S_ISDIR(info.st_mode):
            require(stat.S_IMODE(info.st_mode) == 0o700, "nonprivate retained directory")
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= 4 * 1024 ** 2, "unbounded or aliased retained file")
        raw = path.read_bytes()
        require(len(raw) == info.st_size and (raw or relative == ".coordinator.lock"), "empty or changed retained output")
        total += len(raw)
        require(total * 2 < MAX_EXPORT, "peer evidence export too large")
        result[relative] = dict(**digest(raw), hex=raw.hex())
    return result


def collect(path):
    root = ART["private_root"](path)
    observations = {label: read(root / f"peer-{label}-isolation.json") for label in STAGES}
    require(all(not TRAIN["alive"](member) for value in observations.values()
                for member in value["raw"]["owned_processes"]), "actual peer-learning processes remain")
    return dict(files=collect_tree(root / "peer-learning"), observations=observations,
                base_after=file_hash(root / "provision/model/model.safetensors", 269060552))


def metric(value):
    require(set(value) == {"loss", "target_tokens"} and type(value["loss"]) in (int, float)
            and math.isfinite(value["loss"]) and value["loss"] >= 0
            and type(value["target_tokens"]) is int and 0 < value["target_tokens"] <= 2048,
            "invalid actual validation metric")
    return value


def compared(baseline, candidate):
    metric(baseline); metric(candidate)
    require(baseline["target_tokens"] == candidate["target_tokens"], "comparison changed target tokens")
    return candidate["loss"] < baseline["loss"] - 1e-6


def check_observations(values, selected):
    require(set(values) == set(STAGES), "five actual worker observations missing")
    workers, lineage = set(), None
    for label in STAGES:
        value, cold = values[label], label == "peer-baseline"
        raw = value["raw"]
        TRAIN["check_isolation"](raw)
        require(value["stage"] == label and value["output_exact_inode"] is True
                and value["adapter_absent"] is cold and value["adapter_readonly"] is (not cold)
                and value["adapter_exact_inodes"] == ({} if cold else dict.fromkeys(FILES, True)),
                "actual expected input/output mounts missing")
        current = raw["node_lineage"]
        require(current["node"] == "relay3" and current["network_namespace"] != selected["provider_lineage"]["network_namespace"]
                and current["cli_namespace"] == current["service_namespace"] == current["network_namespace"]
                and (lineage is None or current == lineage), "peer learning not on the distinct R3 contributor")
        lineage = current
        workers.add((raw["worker"]["pid"], raw["worker"]["start_ticks"]))
    require(len(workers) == 5, "model worker identity reused between stages")


def check(value, revision):
    require(value["source_revision"] == revision, "wrong peer-learning source snapshot")
    check_participation(value)
    selected, retained, peers = value["selected"], value["retained"], value["peers"]
    require(selected["seed_configured"] is False and selected["adapter_copied"] is False, "fixture injected a seed")
    provider = value["provider_loop"]
    require(selected["provider_sequence"] == provider["state"]["latest"] and selected["provider_sequence"] in (1, 2),
            "peer candidate is not the actually approved provider successor")
    provider_cycle = provider["cycles"][selected["provider_sequence"] - 1]
    require(provider_cycle["evaluation"]["approved"] is True
            and selected["provider_files"]["publication.pb"] == provider_cycle["publication_hex"]
            and digest(bytes.fromhex(selected["provider_files"]["adapter.bundle"])) == provider_cycle["bundle"]
            and digest(bytes.fromhex(selected["provider_files"]["dataset.json"])) == provider_cycle["dataset"]
            and digest(bytes.fromhex(selected["provider_files"]["dataset.manifest"])) == provider_cycle["manifest"]
            and selected["provider_adapter_files"] == provider_cycle["adapter_files"]
            and selected["provider_parameters"] == provider_cycle["training"]["adapter_after"]
            and selected["provider_lineage"] == provider_cycle["isolation"]["node_lineage"],
            "peer candidate does not bind the separately checked R4 training evidence")
    require(selected["channels"]["channels"][0]["publisher_key"] == value["provider_owner_key"]["identity_public_key_hex"]
            != selected["source"]["publisher_key"]
            and value["owner_key"]["identity_public_key_hex"] != value["provider_owner_key"]["identity_public_key_hex"],
            "publisher or independently enrolled dataset authority changed")
    files = retained["files"]
    raw = {}
    for name, item in files.items():
        content = bytes.fromhex(item["hex"])
        require(digest(content) == {key: item[key] for key in ("sha256", "bytes")}, "retained bytes/hash mismatch")
        raw[name] = content
    def load(name):
        return json.loads(raw[name])
    def identity(name):
        return digest(raw[name])
    state, enrollment = load("state.json"), load("enrollment.json")
    require(state["seed"] is None and enrollment["seed"] is None
            and enrollment["peer_updates"] == selected["channels"] and enrollment["sources"] == [selected["source"]]
            and enrollment["validation_source"] == selected["validation"] and enrollment["repeat_sources"] is False,
            "owner selection or independent source authority changed")
    registry = state["peer_updates"]
    require(registry["pending"] is None and len(registry["completed"]) == 1 and registry["garbage"] == [],
            "peer comparison did not finish exactly once")
    round_record = registry["completed"][0]
    require(round_record["sequence"] == 1 and round_record["phase"] == "approved"
            and round_record["baseline"]["origin"] == {"kind": "pinned_base"}
            and round_record["baseline"]["adapter_root"] is None and round_record["source"] == selected["source"],
            "received model was not adopted over the pinned base")
    require(round_record["snapshot"] == {name[len(ROUND) + 1:]: identity(name) for name in files if name.startswith(ROUND + "/")},
            "durable peer round does not retain actual originals and decisions")
    imported = ROUND + "/import/"
    for name, original in (("adapter.manifest", "publication.pb"), ("adapter.bundle", "adapter.bundle"),
                           ("dataset.json", "dataset.json"), ("dataset.manifest", "dataset.manifest")):
        require(raw[imported + name].hex() == selected["provider_files"][original], "import replaced original provider bytes")
    adapter_files = {name: identity(imported + "adapter/" + name) for name in FILES}
    require(adapter_files == selected["provider_adapter_files"], "imported adapter differs from actual approved provider weights")
    proof = load(imported + "provenance.json")
    require(proof["model_activated"] is False and proof["private_data_supported"] is False
            and proof["adapter"]["manifest_id"] == round_record["manifest_id"] == identity(imported + "adapter.manifest")["sha256"]
            and proof["dataset"]["manifest_id"] == round_record["dataset_manifest_id"] == selected["source"]["manifest_id"]
            and proof["dataset"]["publisher_key"] == selected["source"]["publisher_key"], "original import authority changed")
    total = 0
    for kind in ("adapter", "dataset"):
        receipt, body = proof[kind + "_receipt"], proof[kind]
        require(receipt["manifest_id"] == body["manifest_id"] and receipt["sha256"] == body["sha256"]
                and receipt["bytes"] == receipt["peer_bytes"] == body["bytes"]
                and receipt["chunks"] == (body["bytes"] + 262143) // 262144
                and receipt["providers_used"] == 1 and receipt["provider_peer_ids"] == [peers["relay4"]]
                and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0,
                "new Client adapter/dataset did not arrive over the protected provider path")
        total += body["bytes"]
    validation = load("validation-input/provenance.json")
    initial = value["initial_fetch"]
    LOOP["check_provider_receipt"](initial, validation["manifest_id"], validation["dataset"], peers["relay4"], validation["dataset"]["bytes"])
    require(validation["selection"] == selected["validation"] and validation["source_receipt"]["peer_bytes"] == 0,
            "validation was not the exact protected cache input")
    total += validation["dataset"]["bytes"]
    comparison_root = ROUND + "/comparison/"
    decision = load(comparison_root + "decision.json")
    reports = {}
    previous_end = None
    for stage in ("baseline", "candidate"):
        envelope = load(comparison_root + stage + "-report.json")
        report = envelope["report"]
        require({key: entry for key, entry in report.items() if key != "supervisor"}
                == load(comparison_root + stage + "/report.json"), "comparison worker report differs")
        LOOP["check_validation_outputs"](report["outputs"])
        supervisor = report["supervisor"]
        require(report["mode"] == "infer" and report["status"] == "ok" and report["updates_completed"] == 0
                and report["dataset"]["sha256"] == validation["dataset"]["sha256"] and report["artifacts"] == []
                and report["model"]["id"] == "HuggingFaceTB/SmolLM2-135M-Instruct"
                and report["model"]["revision"] == TRAIN["MODEL_REVISION"]
                and report["model"]["files"]["model.safetensors"] == {"bytes":269060552, "sha256":TRAIN["WEIGHT_HASH"]}
                and supervisor["child_reaped"] is True and supervisor["spare_capacity"] is True
                and supervisor["network_access"] is False and supervisor["gpu_access"] is False
                and supervisor["sandbox"] == "bubblewrap-private-user-net-pid-ipc-mount"
                and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"], "not actual isolated comparison inference")
        require(0 < supervisor["deadline_seconds"] <= 600 and envelope["version"] == 1
                and envelope["started_at"] <= envelope["completed_at"] <= envelope["deadline"]
                and envelope["deadline"] == envelope["started_at"] + supervisor["deadline_seconds"]
                and envelope["completed_at"] < proof["expires_unix_seconds"]
                and envelope["deadline"] <= min(proof["expires_unix_seconds"], validation["expires_unix_seconds"])
                and (previous_end is None or previous_end <= envelope["started_at"]), "comparison renewed or overlapped a lease")
        previous_end = envelope["completed_at"]
        if stage == "baseline":
            require("input_adapter" not in report, "baseline was not cold pinned base")
        else:
            require(report["input_adapter"]["files"] == adapter_files
                    and report["input_adapter"]["applied_parameters"] == selected["provider_parameters"]
                    and report["input_adapter"]["applied"] is True, "received weights were not actually applied")
        reports[stage] = report
    require(decision["version"] == 1 and decision["policy"] == "local-peer-update-validation-loss-v1"
            and decision["approved"] is True and decision["baseline_origin"] == {"kind": "pinned_base"}
            and decision["import_proof"] == proof and decision["candidate_files"] == adapter_files
            and decision["validation_manifest_id"] == validation["manifest_id"]
            and decision["baseline"] == reports["baseline"]["baseline_evaluation"]
            and decision["candidate"] == reports["candidate"]["baseline_evaluation"]
            and compared(decision["baseline"], decision["candidate"]), "peer adoption ignored actual local comparison")
    require(decision["files"] == {name: identity(comparison_root + name) for name in decision["files"]}
            and set(decision["files"]) == {"selection.json", "dataset.json", "dataset.manifest", "provenance.json",
                "baseline-report.json", "candidate-report.json", "baseline/report.json", "candidate/report.json"}, "comparison raw snapshot differs")
    trained = load(CYCLE + "/training-report.json")
    TRAIN["check_worker"](trained, revision)
    require(trained["input_adapter"] == reports["candidate"]["input_adapter"]
            and trained["adapter_before"] == selected["provider_parameters"]
            and trained["adapter_after"] != trained["adapter_before"], "R3 did not actually train from adopted peer weights")
    selection = load(CYCLE + "/selection.json")
    origin = selection["peer_predecessor"]
    require(origin["kind"] == "peer_update" and origin["import_sequence"] == 1
            and origin["adapter_manifest_id"] == round_record["manifest_id"]
            and origin["dataset_manifest_id"] == selected["source"]["manifest_id"]
            and origin["comparison_sha256"] == identity(comparison_root + "decision.json")["sha256"]
            and origin["adapter_files"] == adapter_files and origin["local_predecessor"] is None,
            "actual training lost adopted peer lineage")
    content_files = {name: identity(CYCLE + "/" + name) for name in LOOP["CONTENT_FILES"]}
    cycle = dict(sequence=1, training=trained, content_files=content_files,
                 manifest=identity(CYCLE + "/dataset.manifest"), dataset=identity(CYCLE + "/dataset.json"),
                 result=load(CYCLE + "/result.json"), adapter_files={name: identity(CYCLE + "/training/adapter/" + name) for name in FILES},
                 validation=dict(files={name: files[CYCLE + "/" + name] for name in LOOP["VALIDATION_FILES"]}))
    second = LOOP["check_validation"](cycle)
    evaluation = load(CYCLE + "/evaluation.json")
    approved = compared(trained["baseline_evaluation"], trained["reloaded_evaluation"]) and second["approved"]
    require(evaluation["approved"] is approved and evaluation["validation"] == second
            and evaluation["policy"] == LOOP["POLICY"] and evaluation["baseline_kind"] == "approved_peer_update"
            and evaluation["peer_predecessor"] == origin and evaluation["files"] == content_files
            and evaluation["baseline"] == trained["baseline_evaluation"]
            and evaluation["reloaded"] == trained["reloaded_evaluation"], "local successor bypassed either quality gate")
    require(len(state["cycles"]) == 1 and state["completed"] == 1 and state["next_sequence"] == 2
            and state["latest"] == (1 if approved else None) and registry["active"] == (None if approved else 1)
            and state["cycles"][0]["phase"] == ("complete" if approved else "rejected"), "local/peer adoption state is inconsistent")
    expected_snapshot = dict(content_files, **{name: identity(CYCLE + "/" + name) for name in (*LOOP["VALIDATION_FILES"], "evaluation.json")})
    require(state["cycles"][0]["snapshot"] == expected_snapshot, "durable successor snapshot differs")
    if approved:
        contribution = load(CYCLE + "/contribution.json")
        require(contribution["network_publication"] is True and contribution["serving"] is True
                and contribution["publisher_key_hex"] == value["owner_key"]["identity_public_key_hex"]
                and contribution["manifest_id"] == identity(CYCLE + "/publication.pb")["sha256"]
                and contribution["bytes"] == identity(CYCLE + "/adapter.bundle")["bytes"], "approved R3 successor was not actually contributed")
    else:
        require(all(CYCLE + "/" + name not in files for name in ("publication.pb", "publication.json", "contribution.json"))
                and state["cycles"][0]["publication"] is None, "rejected R3 successor was published")
    require(value["summary"]["attempts_this_invocation"] == value["summary"]["completed_cycles"] == 1
            and value["summary"]["pending_publications"] == 0 and value["summary"]["owner_cancelled"] is False
            and value["summary"]["publication_drain"] == "complete"
            and value["summary"]["publication_drain_seconds"] == 600,
            "R3 did not finish one real automatic cycle and its bounded publication drain")
    require(retained["base_after"] == {"bytes":269060552, "sha256":TRAIN["WEIGHT_HASH"]}, "base model changed")
    check_observations(retained["observations"], selected)
    require(value["source_stop"]["serving"] is False, "original R5 source still serving")
    REP["validate_phase"](value["phase"], "peer-learning", peers, total)


def evidence(work, revision):
    work = Path(work)
    value = dict(source_revision=revision, peers=read(work / "a01-expected-peers.json"),
        selected=read(work / "agent-peer-learning-selected.json", MAX_EXPORT),
        retained=read(work / "agent-peer-learning-files.json", MAX_EXPORT),
        provider_loop=read(work / "agent-train-loop-loop.json", 4 * 1024 ** 2),
        provider_owner_key=read(work / "agent-train-loop-owner-key.json"),
        initial_fetch=read(work / "agent-peer-learning-initial-fetch.json"),
        owner_key=read(work / "agent-peer-learning-owner-key.json"),
        configuration=read(work / "agent-peer-learning-configuration.json"),
        network=read(work / "agent-peer-learning-network.json"),
        service_before=read(work / "agent-peer-learning-service-before.json"),
        service_stop=read(work / "agent-peer-learning-service-stop.json"),
        network_cleanup=read(work / "agent-peer-learning-network-cleanup.json"),
        summary=read(work / "agent-peer-learning-summary.json"), source_stop=read(work / "agent-train-loop-source-stop.json"),
        phase=dict(route=read(work / "agent-peer-learning-transfer-live-selection.json"),
            layout=read(work / "agent-peer-learning-transfer-layout.json"),
            captures={role: read(work / f"agent-peer-learning-transfer-{role}.json") for role in REP["ROLES"]}))
    check(value, revision)
    write(work / "agent-peer-learning-evidence.json", value)


def cleanup(path):
    root = Path(path)
    require(root.is_absolute() and root.name == "agent-artifact-user", "wrong owned peer cleanup root")
    observed = []
    if root.exists():
        ART["private_root"](root)
        for label in STAGES:
            file = root / f"peer-{label}-isolation.raw.json"
            if file.exists():
                observed.extend(read(file)["owned_processes"])
        require(not any(TRAIN["alive"](member) for member in observed), "owned peer-learning worker remains")
    return dict(observed_owned_processes_ended=True, observed_process_records=len(observed),
                parent_private_root_cleanup_required=True)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    work = Path(work)
    path = work / "agent-peer-learning-evidence.json"
    evidence_value = read(path, MAX_EXPORT) if path.exists() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").exists() else {}
    own = read(work / "agent-peer-learning-cleanup.json") if (work / "agent-peer-learning-cleanup.json").exists() else {}
    parent = read(work / "agent-train-loop-cleanup.json") if (work / "agent-train-loop-cleanup.json").exists() else {}
    write(work / "agent-peer-learning-smoke.json", dict(report_kind="volparossa-public-peer-learning", source_revision=revision,
        success=status == 0 and complete and remaining == 0 and evidence_value is not None,
        evidence=evidence_value, scope=SCOPE, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining, peer=own, parent=parent), host_state=host,
        base_distribution_claimed=False, independent_quality_claimed=False, full_b05_claimed=False, full_alpha_claimed=False))


def report(value, revision):
    require(value["report_kind"] == "volparossa-public-peer-learning" and value["source_revision"] == revision
            and value["scope"] == SCOPE and value["success"] is True, "peer-learning not actually covered")
    require(value["cleanup"]["complete"] is True and value["cleanup"]["remaining_owned_objects"] == 0
            and value["cleanup"]["peer"]["observed_owned_processes_ended"] is True
            and value["cleanup"]["parent"]["user_root_removed"] is True
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "peer-learning cleanup incomplete")
    require(all(value[key] is False for key in ("base_distribution_claimed", "independent_quality_claimed", "full_b05_claimed", "full_alpha_claimed")), "unsupported proof claim")
    check(value["evidence"], revision)


def self_test():
    require(compared({"loss":1.0,"target_tokens":12}, {"loss":0.5,"target_tokens":12}), "actual improvement rejected")
    require(not compared({"loss":1.0,"target_tokens":12}, {"loss":1.0,"target_tokens":12}), "equal loss promoted")
    for bad in ({"loss":float("nan"),"target_tokens":12}, {"loss":0.5,"target_tokens":11}, {"loss":-1,"target_tokens":12}):
        try:
            compared({"loss":1.0,"target_tokens":12}, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid comparison accepted")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        config = root / "config-relay3.yaml"
        fixture = ('roles:\n  client: true\n  relay: true\n  exit: false\n'
                   'sharing:\n  enabled: true\n  interface: r3x\n'
                   'download_sharing:\n  enabled: true\n  interface: r3x\n'
                   'content_contribution:\n  enabled: true\n  bind_address: "48.164.4.1:18080"\n'
                   '  advertised_hostname: provider-c.volparossa.test\n'
                   f'  cache: {json.dumps(str(root / "state-relay3/custody-cache"))}\n')
        config.write_text(fixture)
        config.chmod(0o600)
        require(configuration(config)["contribution_enabled"] is True, "explicit combined-role fixture rejected")
        for before, after in (("client: true", "client: false"), ("relay: true", "relay: false"),
                              ("exit: false", "exit: true"), ("enabled: true", "enabled: false"),
                              ("48.164.4.1:18080", "43.159.1.1:18080")):
            config.write_text(fixture.replace(before, after))
            try:
                configuration(config)
            except ValueError:
                pass
            else:
                raise AssertionError("wrong learner consent or bind accepted")
        config.unlink()
        write(root / "state.json", {"version":2})
        (root / ".coordinator.lock").touch(mode=0o600)
        tree = collect_tree(root)
        require(tree[".coordinator.lock"]["bytes"] == 0 and tree["state.json"]["sha256"] == digest((root / "state.json").read_bytes())["sha256"], "actual fixture tree mismatch")
        (root / "enrollment.json").symlink_to(root / "state.json")
        try:
            collect_tree(root)
        except ValueError:
            pass
        else:
            raise AssertionError("symlink accepted")
    print("peer-learning metric and retained-file pure checks PASS; no model or network proof")


def main(args):
    command = args[0]
    if command == "self-test": self_test()
    elif command == "setup": print(json.dumps(setup(args[1], args[2])))
    elif command == "configuration": print(json.dumps(configuration(args[1])))
    elif command == "observe": observe(int(args[1]), args[2], args[3], int(args[4]))
    elif command == "collect": print(json.dumps(collect(args[1])))
    elif command == "cleanup": print(json.dumps(cleanup(args[1])))
    elif command == "evidence": evidence(args[1], args[2])
    elif command == "finalize": finalize(args[1], args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif command == "report": report(read(Path(args[1]), MAX_EXPORT), args[2])
    else: raise ValueError("unknown fixed peer-learning command")


if __name__ == "__main__":
    main(sys.argv[1:])
