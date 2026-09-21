#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable signed invalid-artifact recovery; self-test never runs a model."""

import copy
import json
import math
from pathlib import Path
import re
import runpy
import struct
import sys

PEER = runpy.run_path(str(Path(__file__).resolve().with_name("agent-peer-learning-smoke.py")))
ART, TRAIN, REP, LOOP = (PEER[name] for name in ("ART", "TRAIN", "REP", "LOOP"))
read, write, require, digest = (PEER[name] for name in ("read", "write", "require", "digest"))
FILES, ROUND, CYCLE, MAX_EXPORT = (PEER[name] for name in ("FILES", "ROUND", "CYCLE", "MAX_EXPORT"))
STAGES = ("peer-baseline", "training", "validation-baseline", "validation-candidate")
CODE = "NONFINITE_ADAPTER_WEIGHTS"
NAME = "disposable-quarantine-update"
QUARANTINE_FILES = (
    "comparison/selection.json", "comparison/dataset.json", "comparison/dataset.manifest",
    "comparison/provenance.json", "comparison/baseline-report.json", "comparison/baseline/report.json",
    "import/adapter.bundle", "import/adapter.manifest", "import/dataset.json", "import/dataset.manifest",
    "import/provenance.json",
)
SCOPE = ("R4 signs a separate revision containing one deliberately nonfinite adapter value. A distinct R3 "
         "consumer/contributor fetches it over protected content, runs an actual pinned-base comparison, "
         "and records only the exact candidate as locally quarantined after a correlated isolated-worker "
         "contract rejection. The same owner train-loop then performs eight real updates from the intact "
         "pinned base and evaluates its own successor. Four successful model stages are observed; the bad "
         "candidate is rejected before model inference. Not a publisher/network ban, general poisoning "
         "defence, later-valid-revision proof, independent quality claim, full B05, full B07 or full alpha.")


def canonical_bundle(files, manifest):
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
    require(set(files) == set(FILES) and TRAIN["HASH"].fullmatch(manifest), "bad fixed bundle inputs")
    index = (integer(1, 1) + blob(2, b"HuggingFaceTB/SmolLM2-135M-Instruct")
             + blob(3, TRAIN["MODEL_REVISION"].encode()) + blob(4, bytes.fromhex(TRAIN["WEIGHT_HASH"]))
             + integer(5, 4) + integer(6, 8) + blob(7, b"q_proj") + blob(7, b"v_proj")
             + blob(8, bytes.fromhex(manifest)))
    payload = b""
    for name in FILES:
        raw = files[name]
        require(0 < len(raw) <= (2 * 1024 ** 2 if name.endswith("safetensors") else 16384), "bad fixed file size")
        entry = (blob(1, name.encode()) + integer(2, len(payload)) + integer(3, len(raw))
                 + blob(4, bytes.fromhex(digest(raw)["sha256"])))
        index += blob(9, entry)
        payload += raw
    require(len(index) <= 4096, "unbounded fixed index")
    return len(index).to_bytes(4, "big") + index + payload


def corrupt_one_value(raw):
    require(8 < len(raw) <= 2 * 1024 ** 2, "invalid fixture weights size")
    size = int.from_bytes(raw[:8], "little")
    require(0 < size <= 65536 and 8 + size < len(raw), "invalid fixture tensor header")
    header = json.loads(raw[8:8 + size])
    tensors = [value for name, value in header.items() if name != "__metadata__"]
    require(tensors and all(value["dtype"] == "F32" for value in tensors), "fixture expects actual FP32 adapter")
    first = min(value["data_offsets"][0] for value in tensors)
    require(first == 0 and all(type(v) is int for value in tensors for v in value["data_offsets"]), "bad fixture offsets")
    offset = 8 + size
    require(len(raw) >= offset + 4 and math.isfinite(struct.unpack("<f", raw[offset:offset + 4])[0]), "first value is not finite")
    changed = raw[:offset] + struct.pack("<f", float("nan")) + raw[offset + 4:]
    require(changed != raw and math.isnan(struct.unpack("<f", changed[offset:offset + 4])[0]), "fault not installed")
    return changed, offset


def setup(path, publisher):
    TRAIN["guest_guard"]()
    selected = PEER["setup"](path, publisher)
    root = ART["private_root"](path)
    cycle = root / "loop" / f"cycle-{selected['provider_sequence']:016x}"
    originals = {name: (cycle / "training/adapter" / name).read_bytes() for name in FILES}
    manifest = selected["source"]["manifest_id"]
    require(canonical_bundle(originals, manifest).hex() == selected["provider_files"]["adapter.bundle"],
            "original adapter bundle does not match actually trained files")
    changed = dict(originals)
    changed["adapter_model.safetensors"], offset = corrupt_one_value(originals["adapter_model.safetensors"])
    bundle = canonical_bundle(changed, manifest)
    with (root / "quarantine.bundle.bin").open("xb") as stream:
        stream.write(bundle)
    (root / "quarantine.bundle.bin").chmod(0o600)
    selected["channels"] = dict(version=1, channels=[dict(publisher_key=publisher, name=NAME, min_revision=1)])
    # setup created this one fixture-owned file immediately above; preserve its mode.
    with (root / "peer-channels.json").open("w") as stream:
        json.dump(selected["channels"], stream, allow_nan=False)
        stream.write("\n")
    selected["fault"] = dict(code=CODE, offset=offset, original_files={name:digest(raw) for name, raw in originals.items()},
                             candidate_files={name:digest(raw) for name, raw in changed.items()}, bundle=digest(bundle))
    return selected


def observe(pid, path, namespace, service):
    root = Path(path) / "peer-learning"
    peer, cycle = root / ROUND, root / CYCLE
    paths = ((peer / "comparison/dataset.json", peer / "comparison/baseline", None),
             (cycle / "dataset.json", cycle / "training", None),
             (cycle / "validation/dataset.json", cycle / "validation/baseline", None),
             (cycle / "validation/dataset.json", cycle / "validation/candidate", cycle / "training/adapter"))
    PEER["observe"](pid, path, namespace, service, stages=STAGES, paths=paths)


def check_quarantine(record, selection, proof, candidate_files, validation, baseline, identities):
    require(set(record) == {"version", "policy", "scope", "stage", "request_id", "code", "started_at", "completed_at",
                           "deadline", "source_expires", "baseline_origin", "import_proof", "candidate_files",
                           "validation_manifest_id", "files"}, "unexpected quarantine vocabulary")
    require(record["version"] == 1 and record["policy"] == "local-peer-update-runtime-contract-v1"
            and record["scope"] == "local-artifact-only-not-publisher-or-network-ban"
            and record["stage"] == "candidate" and record["code"] == CODE
            and re.fullmatch(r"[0-9a-f]{32}", record["request_id"])
            and record["request_id"] != baseline["report"]["id"], "not exact correlated local candidate rejection")
    require(record["baseline_origin"] == {"kind":"pinned_base"} == selection["baseline_origin"]
            and record["import_proof"] == proof == selection["import_proof"]
            and record["candidate_files"] == candidate_files == selection["candidate_files"]
            and record["validation_manifest_id"] == validation["manifest_id"] == selection["validation_source"]["manifest_id"]
            and record["files"] == identities and set(identities) == set(QUARANTINE_FILES), "quarantine original evidence changed")
    require(0 < baseline["completed_at"] <= record["started_at"] <= record["completed_at"] <= record["deadline"]
            and record["completed_at"] < record["source_expires"] == selection["expires"]
            and 0 < selection["max_seconds"] <= 600
            and record["deadline"] == record["started_at"] + min(selection["max_seconds"], selection["expires"] - record["started_at"])
            and record["source_expires"] <= min(proof["expires_unix_seconds"], validation["expires_unix_seconds"]),
            "quarantine changed original execution or source deadline")


def check_inference(envelope, report_file, validation, model, cold, adapter_files=None):
    report = envelope["report"]
    require({key:value for key,value in report.items() if key != "supervisor"} == report_file, "raw inference report differs")
    LOOP["check_validation_outputs"](report["outputs"])
    PEER["metric"](report["baseline_evaluation"])
    require(report["version"] == 1 and report["kind"] == "result" and report["status"] == "ok"
            and report["mode"] == "infer" and report["device"] == "cpu" and report["threads"] == 2
            and report["model"] == model and report["updates_completed"] == 0 and report["artifacts"] == []
            and report["dataset"]["sha256"] == validation["dataset"]["sha256"]
            and report["dataset"]["bytes"] == validation["dataset"]["bytes"], "actual selected model inference missing")
    supervisor = report["supervisor"]
    require(supervisor["child_reaped"] is True and supervisor["spare_capacity"] is True
            and supervisor["network_access"] is False and supervisor["gpu_access"] is False
            and supervisor["sandbox"] == "bubblewrap-private-user-net-pid-ipc-mount"
            and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"]
            and 0 < supervisor["deadline_seconds"] <= 600, "model worker bypassed original isolation/bounds")
    if cold:
        require("input_adapter" not in report, "quarantined adapter became a baseline")
    else:
        require(report["input_adapter"]["applied"] is True and report["input_adapter"]["files"] == adapter_files,
                "validation did not load newly trained clean successor")
    return report


def check(value, revision):
    require(value["source_revision"] == revision, "wrong quarantine source snapshot")
    PEER["check_participation"](value)
    selected, retained, peers = (value[name] for name in ("selected", "retained", "peers"))
    provider = value["provider_loop"]
    require(selected["seed_configured"] is False and selected["adapter_copied"] is False
            and selected["provider_sequence"] == provider["state"]["latest"] in (1, 2), "fixture preloaded learner or lacks real trained origin")
    original = provider["cycles"][selected["provider_sequence"] - 1]
    require(original["evaluation"]["approved"] is True and selected["provider_adapter_files"] == original["adapter_files"]
            and selected["fault"]["original_files"] == original["adapter_files"]
            and selected["provider_lineage"] == original["isolation"]["node_lineage"]
            and digest(bytes.fromhex(selected["provider_files"]["adapter.bundle"])) == original["bundle"], "fault source is not real R4 training")
    publisher = value["provider_owner_key"]["identity_public_key_hex"]
    require(selected["channels"] == dict(version=1, channels=[dict(publisher_key=publisher, name=NAME, min_revision=1)])
            and value["owner_key"]["identity_public_key_hex"] != publisher != selected["source"]["publisher_key"], "publisher or enrolled owner changed")
    files, raw = retained["files"], {}
    for name, info in files.items():
        raw[name] = bytes.fromhex(info["hex"])
        require(digest(raw[name]) == {key:info[key] for key in ("bytes", "sha256")}, "retained bytes/hash mismatch")
    def load(name): return json.loads(raw[name])
    def identity(name): return digest(raw[name])
    state, enrollment = load("state.json"), load("enrollment.json")
    require(state["seed"] is None and enrollment["seed"] is None
            and enrollment["sources"] == [selected["source"]] and enrollment["peer_updates"] == selected["channels"]
            and enrollment["validation_source"] == selected["validation"] and enrollment["repeat_sources"] is False,
            "same owner loop changed source authority")
    registry = state["peer_updates"]
    require(registry["pending"] is None and registry["active"] is None and registry["garbage"] == []
            and len(registry["completed"]) == 1, "candidate quarantine changed active peer selection")
    record = registry["completed"][0]
    require(record["sequence"] == 1 and record["phase"] == "quarantined"
            and record["baseline"]["origin"] == {"kind":"pinned_base"} and record["baseline"]["adapter_root"] is None
            and record["source"] == selected["source"] and record["snapshot"] == {
                name[len(ROUND) + 1:]:identity(name) for name in files if name.startswith(ROUND + "/")}, "durable quarantine not exact original round")
    imported, comparison = ROUND + "/import/", ROUND + "/comparison/"
    candidate = {name:raw[imported + "adapter/" + name] for name in FILES}
    candidate_files = {name:digest(data) for name,data in candidate.items()}
    require(candidate_files == selected["fault"]["candidate_files"] and selected["fault"]["code"] == CODE
            and canonical_bundle(candidate, selected["source"]["manifest_id"]) == raw[imported + "adapter.bundle"]
            and identity(imported + "adapter.bundle") == selected["fault"]["bundle"], "protected candidate differs from explicit canonical fault")
    # Recover the finite original from the intact original bundle's payload, not a model backend.
    original_bundle = bytes.fromhex(selected["provider_files"]["adapter.bundle"])
    original_weights_size = selected["provider_adapter_files"]["adapter_model.safetensors"]["bytes"]
    original_weights = original_bundle[-original_weights_size:]
    changed, offset = corrupt_one_value(original_weights)
    require(candidate["adapter_model.safetensors"] == changed and offset == selected["fault"]["offset"]
            and digest(original_weights) == selected["provider_adapter_files"]["adapter_model.safetensors"]
            and all(candidate_files[name] == selected["provider_adapter_files"][name] for name in FILES if not name.endswith("safetensors")),
            "fault modifies more than the explicitly selected NaN value")
    for name in ("dataset.json", "dataset.manifest"):
        require(raw[imported + name].hex() == selected["provider_files"][name], "original training data changed")
    proof = load(imported + "provenance.json")
    publication = value["fault_publication"]
    require(proof["model_activated"] is False and proof["private_data_supported"] is False
            and proof["adapter"]["manifest_id"] == record["manifest_id"] == identity(imported + "adapter.manifest")["sha256"]
            == publication["manifest_id"] and publication["publisher_key_hex"] == publisher
            and publication["network_publication"] is True and publication["serving"] is True
            and proof["adapter"]["publisher_key"] == publisher and proof["adapter"]["name"] == NAME
            and proof["dataset"]["manifest_id"] == record["dataset_manifest_id"] == selected["source"]["manifest_id"],
            "fault was not signed and imported as an exact separate local candidate")
    total = 0
    for kind in ("adapter", "dataset"):
        body, receipt = proof[kind], proof[kind + "_receipt"]
        require(receipt["manifest_id"] == body["manifest_id"] and receipt["sha256"] == body["sha256"]
                and receipt["bytes"] == receipt["peer_bytes"] == body["bytes"]
                and receipt["chunks"] == (body["bytes"] + 262143) // 262144
                and receipt["providers_used"] == 1 and receipt["provider_peer_ids"] == [peers["relay4"]]
                and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0,
                "candidate or dataset did not arrive over the protected provider path")
        total += body["bytes"]
    validation = load("validation-input/provenance.json")
    LOOP["check_provider_receipt"](value["initial_fetch"], validation["manifest_id"], validation["dataset"], peers["relay4"], validation["dataset"]["bytes"])
    require(validation["selection"] == selected["validation"] and validation["source_receipt"]["peer_bytes"] == 0,
            "validation was not protected content input")
    total += validation["dataset"]["bytes"]
    trained = load(CYCLE + "/training-report.json")
    TRAIN["check_worker"](trained, revision)
    baseline = load(comparison + "baseline-report.json")
    check_inference(baseline, load(comparison + "baseline/report.json"), validation, trained["model"], True)
    require(baseline["started_at"] <= baseline["completed_at"] <= baseline["deadline"]
            and baseline["deadline"] == baseline["started_at"] + baseline["report"]["supervisor"]["deadline_seconds"], "baseline renewed lease")
    quarantine = load(comparison + "quarantine.json")
    check_quarantine(quarantine, load(comparison + "selection.json"), proof, candidate_files, validation, baseline,
                     {name:identity(ROUND + "/" + name) for name in QUARANTINE_FILES})
    require(all(comparison + name not in files for name in ("candidate-report.json", "candidate/report.json", "decision.json")),
            "invalid candidate recorded as completed inference or ordinary quality decision")
    selection = load(CYCLE + "/selection.json")
    require("input_adapter" not in trained and selection.get("peer_predecessor") is None
            and selection.get("predecessor") is None and selection["adapter_root"] is None,
            "same-loop useful training used quarantined weights")
    validation_reports = {}
    for stage in ("baseline", "candidate"):
        envelope = load(CYCLE + "/" + stage + "-report.json")
        validation_reports[stage] = check_inference(envelope, load(CYCLE + "/validation/" + stage + "/report.json"),
            validation, trained["model"], stage == "baseline",
            {name:identity(CYCLE + "/training/adapter/" + name) for name in FILES})
        require(envelope["started_at_unix_seconds"] <= envelope["verified_at_unix_seconds"] <= envelope["deadline_unix_seconds"]
                and envelope["deadline_unix_seconds"] == envelope["started_at_unix_seconds"] + envelope["report"]["supervisor"]["deadline_seconds"]
                and envelope["deadline_unix_seconds"] <= validation["expires_unix_seconds"], "successor validation renewed lease")
    second = load(CYCLE + "/validation.json")
    second_files = {name for name in LOOP["VALIDATION_FILES"] if name != "validation.json"}
    second_files.update(("training-report.json", "result.json", "selection.json", *("training/adapter/" + name for name in FILES)))
    require(second["version"] == 1 and second["policy"] == "second-source-heldout-loss-v1"
            and second["source_manifest_id"] == validation["manifest_id"]
            and second["source_expires_unix_seconds"] == validation["expires_unix_seconds"]
            and second["baseline_input_adapter"] is None and second["candidate_input_adapter"] == validation_reports["candidate"]["input_adapter"]
            and second["baseline"] == validation_reports["baseline"]["baseline_evaluation"]
            and second["candidate"] == validation_reports["candidate"]["baseline_evaluation"]
            and second["approved"] is PEER["compared"](second["baseline"], second["candidate"])
            and second["files"] == {name:identity(CYCLE + "/" + name) for name in second_files}, "second source gate differs from real outputs")
    evaluation = load(CYCLE + "/evaluation.json")
    approved = PEER["compared"](trained["baseline_evaluation"], trained["reloaded_evaluation"]) and second["approved"]
    require(evaluation["approved"] is approved and evaluation["baseline_kind"] == "pinned_base" and evaluation["policy"] == LOOP["POLICY"]
            and evaluation.get("peer_predecessor") is None and evaluation["validation"] == second
            and evaluation["baseline"] == trained["baseline_evaluation"] and evaluation["reloaded"] == trained["reloaded_evaluation"]
            and evaluation["files"] == {name:identity(CYCLE + "/" + name) for name in LOOP["CONTENT_FILES"]}
            and state["completed"] == 1 and state["next_sequence"] == 2 and len(state["cycles"]) == 1
            and state["latest"] == (1 if approved else None)
            and state["cycles"][0]["phase"] == ("complete" if approved else "rejected"), "training failed to continue or bypassed quality gates")
    snapshot_names = set(LOOP["CONTENT_FILES"]) | set(LOOP["VALIDATION_FILES"]) | {"evaluation.json"}
    require(state["cycles"][0]["snapshot"] == {name:identity(CYCLE + "/" + name) for name in snapshot_names},
            "durable useful successor lost exact source and evaluation identities")
    if approved:
        contribution = load(CYCLE + "/contribution.json")
        require(contribution["network_publication"] is True and contribution["serving"] is True
                and contribution["publisher_key_hex"] == value["owner_key"]["identity_public_key_hex"]
                and contribution["manifest_id"] == identity(CYCLE + "/publication.pb")["sha256"], "clean approved successor not contributed")
    else:
        require(all(CYCLE + "/" + name not in files for name in ("publication.pb", "publication.json", "contribution.json")),
                "rejected successor was published")
    require(value["summary"]["attempts_this_invocation"] == value["summary"]["completed_cycles"] == 1
            and value["summary"]["pending_publications"] == 0 and value["summary"]["owner_cancelled"] is False
            and value["summary"]["publication_drain"] == "complete", "same train-loop did not recover and finish")
    require(retained["base_after"] == {"bytes":269060552, "sha256":TRAIN["WEIGHT_HASH"]}, "original pinned base changed")
    PEER["check_observations"](retained["observations"], selected, stages=STAGES, cold_stages=STAGES[:3])
    require(value["source_stop"]["serving"] is False, "original R5 source still serving")
    REP["validate_phase"](value["phase"], "peer-learning", peers, total)


def evidence(work, revision):
    work = Path(work)
    value = PEER["evidence_value"](work, revision)
    value["fault_publication"] = read(work / "agent-artifact-quarantine-publish.json")
    check(value, revision)
    write(work / "agent-artifact-quarantine-evidence.json", value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    work = Path(work)
    def optional(name, default):
        path = work / name
        return read(path, MAX_EXPORT) if path.exists() else default
    evidence_value = optional("agent-artifact-quarantine-evidence.json", None)
    write(work / "agent-artifact-quarantine-smoke.json", dict(report_kind="volparossa-public-artifact-quarantine",
        source_revision=revision, success=status == 0 and complete and remaining == 0 and evidence_value is not None,
        evidence=evidence_value, scope=SCOPE, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining, peer=optional("agent-peer-learning-cleanup.json", {}),
                     parent=optional("agent-train-loop-cleanup.json", {})), host_state=optional("a15-evidence.json", {}),
        global_publisher_ban_claimed=False, later_valid_revision_claimed=False, independent_quality_claimed=False,
        full_b05_claimed=False, full_b07_claimed=False, full_alpha_claimed=False))


def report(value, revision):
    require(value["report_kind"] == "volparossa-public-artifact-quarantine" and value["source_revision"] == revision
            and value["scope"] == SCOPE and value["success"] is True, "artifact quarantine not actually covered")
    require(value["cleanup"]["complete"] is True and value["cleanup"]["remaining_owned_objects"] == 0
            and value["cleanup"]["peer"]["observed_owned_processes_ended"] is True
            and value["cleanup"]["parent"]["user_root_removed"] is True and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "quarantine topology/host cleanup incomplete")
    require(all(value[key] is False for key in ("global_publisher_ban_claimed", "later_valid_revision_claimed",
        "independent_quality_claimed", "full_b05_claimed", "full_b07_claimed", "full_alpha_claimed")), "unsupported quarantine scope claim")
    check(value["evidence"], revision)


def self_test():
    header = json.dumps({"fixture":dict(dtype="F32", shape=[2], data_offsets=[0, 8])}).encode()
    original = len(header).to_bytes(8, "little") + header + struct.pack("<ff", 1.0, 2.0)
    changed, offset = corrupt_one_value(original)
    require(changed[:offset] == original[:offset] and changed[offset + 4:] == original[offset + 4:], "fault changed surrounding data")
    data = {"README.md":b"fixture", "adapter_config.json":b"{}", "adapter_model.safetensors":original}
    bundle = canonical_bundle(data, "11" * 32)
    mutated = canonical_bundle(dict(data, **{"adapter_model.safetensors":changed}), "11" * 32)
    require(bundle != mutated and digest(bundle) != digest(mutated) and len(bundle) == len(mutated), "bundle failed to bind changed weights")
    proof, candidate, validation = dict(expires_unix_seconds=200), {"weights":digest(changed)}, dict(manifest_id="22" * 32, expires_unix_seconds=200)
    identities = dict.fromkeys(QUARANTINE_FILES, digest(b"fixture"))
    baseline = dict(completed_at=100, report=dict(id="00" * 16))
    selection = dict(baseline_origin={"kind":"pinned_base"}, import_proof=proof, candidate_files=candidate,
                     validation_source=dict(manifest_id=validation["manifest_id"]), expires=200, max_seconds=60)
    record = dict(version=1, policy="local-peer-update-runtime-contract-v1", scope="local-artifact-only-not-publisher-or-network-ban",
                  stage="candidate", request_id="01" * 16, code=CODE, started_at=101, completed_at=102, deadline=161,
                  source_expires=200, baseline_origin=selection["baseline_origin"], import_proof=proof,
                  candidate_files=candidate, validation_manifest_id=validation["manifest_id"], files=identities)
    check_quarantine(record, selection, proof, candidate, validation, baseline, identities)
    for key, replacement in (("code", "TIMEOUT"), ("code", "OUT_OF_MEMORY"), ("stage", "baseline"),
                             ("scope", "publisher-ban"), ("request_id", "00" * 16), ("request_id", "invalid"),
                             ("deadline", 201), ("source_expires", 201), ("files", {}), ("candidate_files", {})):
        bad = copy.deepcopy(record)
        bad[key] = replacement
        try:
            check_quarantine(bad, selection, proof, candidate, validation, baseline, identities)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid quarantine proof accepted: " + key)
    print("artifact-quarantine canonical fault + correlated evidence positive/10-negative pure checks PASS; no ML/network proof")


def main(args):
    command = args[0]
    if command == "self-test": self_test()
    elif command == "setup": print(json.dumps(setup(args[1], args[2])))
    elif command == "configuration": print(json.dumps(PEER["configuration"](args[1])))
    elif command == "observe": observe(int(args[1]), args[2], args[3], int(args[4]))
    elif command == "collect": print(json.dumps(PEER["collect"](args[1], stages=STAGES)))
    elif command == "cleanup": print(json.dumps(PEER["cleanup"](args[1])))
    elif command == "evidence": evidence(args[1], args[2])
    elif command == "finalize": finalize(args[1], args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif command == "report": report(read(Path(args[1]), MAX_EXPORT), args[2])
    else: raise ValueError("unknown fixed quarantine command")


if __name__ == "__main__":
    main(sys.argv[1:])
