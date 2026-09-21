#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual public model assessments/cross-reviews; never proof of moral/legal accuracy."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
TRAIN, CUSTODY = JOBS["TRAIN"], JOBS["CUSTODY"]
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
NAME = "agent-policy-assessment"
SUBJECT = "Neighbors voluntarily lend spare computing capacity to help each other, while respecting consent and each device owner's needs.\n"
STAGES = ("assessment-0", "assessment-1", "review-0", "review-1")
CONTRACTS = ("principle_assessment_v1", "principle_review_v1")
CONTENT_TYPE = "application/vnd.volparossa.agent-principle.v4+json"
DECODER = {"implementation": "lm-format-enforcer", "version": "0.11.3", "adapter_version": 1,
           "schema_version": 3, "dependencies": {"interegular": "0.3.3", "pydantic": "1.10.24"}}
SCOPE = ("one exact synthetic public native object fetched through its protected content path, two actual "
         "360M peer assessments and opposite-peer cross-reviews under the seven virtues/vices, bound "
         "to signed dataset-v4 contracts and original provider-signed JSON-boundary/EOS receipts, "
         "using the explicitly provisioned pinned decoder without fixed verdicts, publish and fetch their exact native bundle into "
         "a new cache and directory on the same client, then unchanged completed offline replay and full owned cleanup; "
         "not classifier quality, legal correctness, independent semantic judgment, network-policy activation or full B06")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def provision_pins():
    pin_root = HERE / "ml" if (HERE / "ml").is_dir() else HERE.parent.parent / "workers/volparossa-ml"
    pins = read(pin_root / "model-pins.json")
    pins.update(read(pin_root / "model-pins-360m.json"))
    extra = read(pin_root / "graph-decoder-pins.json")
    require(extra["format_version"] == 1 and extra["decoder"] == DECODER and len(extra["wheels"]) == 3,
            "unexpected explicitly selected decoder pins")
    pins["wheels"] += extra["wheels"]
    pins["task_graph_decoder"] = extra["decoder"]
    lock = (pin_root / "requirements.lock").read_bytes()
    lock += (b"" if lock.endswith(b"\n") else b"\n") + (pin_root / "graph-decoder-requirements.lock").read_bytes()
    return pins, lock


def check_provision(value):
    pins, lock = provision_pins()
    model = TRAIN["inference_profile"]("smollm2-360m-v1")["model"]
    weights = next(item for item in pins["files"] if item["path"] == "model.safetensors")
    require(pins["model_id"] == model["model_id"] and pins["revision"] == model["model_revision"]
            and {key: weights[key] for key in ("bytes", "sha256")} == model["base_weights"],
            "selected provision/model profile mismatch")
    require(value["success"] is True and value["installed_wheels"] == len(pins["wheels"]) == 41
            and value["model_profile"] == "smollm2-360m-v1" and value["model_id"] == pins["model_id"]
            and value["revision"] == pins["revision"] and value["task_graph_decoder"] == DECODER
            and value["download_bytes"] == sum(item["bytes"] for item in pins["files"] + pins["wheels"])
            and value["model_pins_sha256"] == sha((json.dumps(pins, indent=2) + "\n").encode())
            and value["requirements_sha256"] == sha(lock) and value["budget_bytes"] == 3 * 1024**3
            and value["runtime_autofetch_enabled"] is False and value["training_performed"] is False,
            "unverified 360M/41-wheel structured-inference provision")


def stage_contract(stage):
    require(stage in STAGES, "unknown policy stage")
    return CONTRACTS[0 if stage.startswith("assessment-") else 1]


def check_dataset(dataset, stage, context, manifest):
    require(set(dataset) == {"version", "visibility", "license", "source_manifest_hex", "inference", "output_contract"}
            and dataset["version"] == 4 and dataset["visibility"] == "public" and dataset["license"] == "CC0-1.0"
            and dataset["output_contract"] == stage_contract(stage)
            and dataset["source_manifest_hex"] == manifest.hex() and len(dataset["inference"]) == 1,
            "not the original explicit public singleton dataset-v4 contract")
    row = dataset["inference"][0]
    require(set(row) == {"question", "context", "start", "end"} and row["question"].strip()
            and row["context"] == context.decode() and row["start"] == 0 and row["end"] == len(context),
            "dataset did not retain its complete signed original context")


def check_output(output, stage, assessment):
    generation = output["generation"]
    require(set(generation) == {"version", "stop_reason", "max_new_tokens", "model_profile", "output_contract"}
            and generation["version"] == 3 and generation["max_new_tokens"] == 512
            and generation["model_profile"] == "smollm2-360m-v1"
            and generation["output_contract"] == stage_contract(stage)
            and generation["stop_reason"] in ("json_boundary", "eos")
            and type(output["generated_tokens"]) is int and 0 < output["generated_tokens"] <= 512
            and output["text_truncated"] is False, "incomplete/mismatched structured model generation")
    raw = output["text"].encode()
    payload = strict_json(raw)
    fields = {"version", "outcome", "reasoning", "counterargument", "uncertainty"}
    if stage.startswith("review-"):
        fields.add("verdict")
    require(0 < len(raw) <= 1024 and set(payload) == fields and payload["version"] == 1
            and sha(raw) == assessment["output_sha256"]
            and payload == assessment.get("assessment", assessment.get("review")),
            "full model JSON was malformed, repaired, replaced or bound to a different contract")


def record(work, suffix):
    return work / f"{NAME}-{suffix}.json"


def root_path(work):
    return work / "state-client/compute-source/policy-assessment"


def prepare(work):
    require(TRAIN["socket"].gethostname() == "volparossa-alpha"
            and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
            and os.geteuid() != 0, "not the unprivileged disposable guest")
    source = work / "state-client/compute-source"
    require(work.parent == Path("/opt") and work.name.startswith("va.")
            and not work.is_symlink() and HERE == work / "bin"
            and source.stat().st_uid == os.geteuid(), "wrong disposable policy fixture")
    for path in (Path(__file__),):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222,
                "fixture is not root-installed readonly")
    path = source / "policy-input.txt"
    with path.open("xb") as stream:
        stream.write(SUBJECT.encode())
    path.chmod(0o600)
    print(json.dumps({"subject": SUBJECT, "sha256": sha(SUBJECT.encode()), "license": "CC0-1.0",
                      "synthetic_public_fixture": True, "expected_moral_verdict_supplied": False}))


def snapshot(root):
    owner = root.lstat()
    require(stat.S_ISDIR(owner.st_mode) and not root.is_symlink() and owner.st_uid != 0
            and stat.S_IMODE(owner.st_mode) == 0o700, "wrong retained workflow root")
    files, total, entries = {}, 0, 0
    for directory, children, names in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(children):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
                    and info.st_uid == owner.st_uid and stat.S_IMODE(info.st_mode) == 0o700,
                    "unsafe workflow directory")
            # Publication chunks are not task decisions or receipts; never export identities/runtime.
            if relative.endswith("/publication-cache"):
                continue
            require(re.fullmatch(r"(?:assessment|review)-[01](?:/(?:work|poll-[0-9]{2}))?", relative),
                    "unexpected policy workflow directory")
            kept.append(name)
        children[:] = kept
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            require(name in {"subject.txt", "subject.manifest", "subject-download.json", "enrollment.json",
                             "result.json", "context.txt", "context.manifest", "dataset.json", "dataset.manifest",
                             "job-0.json", "provider-transcript.json", ".task.lock"}
                    or re.fullmatch(r"receipt-[0-9a-f]{32}\.json", name), "unexpected exported policy file")
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == owner.st_uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1048576,
                    "unsafe retained public proof file")
            raw = path.read_bytes()
            total += len(raw)
            entries += 1
            require(len(raw) == info.st_size and total <= 8 * 1048576 and entries <= 128,
                    "unbounded/changed retained history")
            files[relative] = {"bytes": len(raw), "sha256": sha(raw), "raw_hex": raw.hex(),
                               "inode": [info.st_dev, info.st_ino]}
    return files


def observe(work, pid):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](pid)
    layout = read(work / "agent-jobs-layout.json")
    brokers = {node: JOBS["identity"](JOBS["broker_pid"](node)) for node in layout["provider_nodes"]}
    observed = {}
    deadline = time.monotonic() + 3300
    while JOBS["alive"](owner) and time.monotonic() < deadline:
        for stage in STAGES:
            path = root_path(work) / stage / "work/job-0.json"
            if stage in observed or not path.is_file():
                continue
            handle = read(path)
            nodes = [n for n, key in layout["provider_keys"].items() if key == handle["provider_key"]]
            require(len(nodes) == 1, "job not assigned to one of the selected peers")
            node = nodes[0]
            value = JOBS["worker_snapshot"](work, node, brokers[node], handle["binding"]["dataset_sha256"])
            if value is not None:
                require(JOBS["alive"](value["worker"]), "worker disappeared during observation")
                observed[stage] = {"handle": handle, "observation": value}
                # Preserve useful original observations even when a later model answer is invalid.
                write(record(work, "observed-" + stage), observed[stage])
        time.sleep(0.025)
    write(record(work, "observation"), {"stages": observed})
    require(set(observed) == set(STAGES), "four actual assessment/review workers were not observed")


def collect(work):
    JOBS["guest_work"](work)
    write(record(work, "files"), snapshot(root_path(work)))


def stopped(work):
    JOBS["guest_work"](work)
    stages = read(record(work, "observation"))["stages"]
    require(set(stages) == set(STAGES), "missing observed executions")
    require(all(not JOBS["alive"](p) for stage in stages.values()
                for p in stage["observation"]["owned_processes"]), "observed worker lifetime still alive")
    write(record(work, "stopped"), {"observed_processes_ended": True})


def replay(work):
    JOBS["guest_work"](work)
    before = read(record(work, "files"), 32 * 1048576)
    require(snapshot(root_path(work)) == before, "completed replay changed retained history or added jobs")
    require(read(record(work, "result")) == read(record(work, "resume")), "offline result differs")
    write(record(work, "replay"), {"original_files_unchanged": True, "new_jobs": 0,
                                  "identical_result": True, "brokers_stopped": True})


def decode_file(files, name, json_value=True):
    item = files[name]
    raw = bytes.fromhex(item["raw_hex"])
    require(sha(raw) == item["sha256"] and len(raw) == item["bytes"], "retained bytes differ")
    return json.loads(raw) if json_value else raw


def receipt_name(files, stage, handle):
    suffix = "/receipt-" + handle["binding"]["job_id"] + ".json"
    names = [stage + "/" + directory + suffix
             for directory in ["work"] + [f"poll-{index:02}" for index in range(32)]]
    found = [name for name in names if name in files]
    require(found, "original terminal receipt missing")
    return found[-1]


def verify_signature(body, signature, publisher, domain):
    # Public-only Ed25519 verification; no private identity or model is loaded.
    require(len(signature) == 64 and len(publisher) == 32, "invalid signature dimensions")
    with tempfile.TemporaryDirectory(prefix="volparossa-public-signature-") as name:
        root = Path(name)
        (root / "key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + publisher)
        (root / "message").write_bytes(domain + body)
        (root / "signature").write_bytes(signature)
        verified = JOBS["subprocess"].run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
            "-inkey", str(root / "key.der"), "-rawin", "-in", str(root / "message"),
            "-sigfile", str(root / "signature")], capture_output=True, timeout=5, check=False)
        require(verified.returncode == 0, "original public Ed25519 signature failed")


def check_transcript(retained, handle, status, requester, selected_at):
    require(set(retained) == {"version", "requester_key", "transcript_hex"}
            and retained["version"] == 1 and retained["requester_key"] == requester,
            "portable requester differs")
    raw = bytes.fromhex(retained["transcript_hex"])
    fields = CUSTODY["fields"]
    proof = fields(raw, 96 * 1024)
    require(set(proof) == {1, 2, 3, 4} and proof[1] == 1, "wrong portable transcript framing")
    bodies = []
    for kind, encoded, key in zip((1, 2, 3), (proof[2], proof[3], proof[4]),
                                  (handle["provider_key"], requester, handle["provider_key"])):
        envelope = fields(encoded, 96 * 1024)
        require(set(envelope) == {1, 2}, "wrong signed envelope")
        body = fields(envelope[1], 96 * 1024)
        expected = set(range(1, 8)) if kind == 1 else set(range(1, 9)) | {10}
        if kind == 3:
            expected.add(9)
        require(set(body) == expected and body[1] == 1 and body[6] == kind
                and body[2] == bytes.fromhex(key) and len(body[5]) == 32
                and 0 < body[4] - body[3] <= 30
                and body[7] == hashlib.sha256(body.get(8, b"")).digest(), "signed body bindings differ")
        verify_signature(envelope[1], envelope[2], bytes.fromhex(key), b"VOLPAROSSA/compute-control/v1\0")
        bodies.append(body)
    challenge, request, reply = bodies
    require(challenge[5] == request[5] == reply[5] and challenge[4] == request[4] == reply[4]
            and challenge[3] <= request[3] <= reply[3] < reply[4]
            and request[10] == reply[10] == hashlib.sha256(proof[2]).digest()
            and reply[9] == hashlib.sha256(proof[3]).digest()
            and len(request[8]) <= 16 * 1024 and len(reply[8]) <= 64 * 1024
            and selected_at <= reply[3] < handle["binding"]["expires_unix_seconds"],
            "historical signed exchange chronology/hash/lease differs")
    request_value, response_value = json.loads(request[8]), json.loads(reply[8])
    require(set(request_value) == {"version", "request_id", "requester_key", "operation"}
            and request_value["version"] == 1 and request_value["requester_key"] == requester
            and re.fullmatch(r"[0-9a-f]{32}", request_value["request_id"])
            and request_value["operation"] == {"operation": "poll", "value": handle["binding"]}
            and response_value == {"version": 1, "request_id": request_value["request_id"],
                                   "outcome": {"outcome": "job", "value": status}},
            "original provider signed another request or result")


def bundle_projection(files, requester):
    value = {"version": 1, "requester_key": requester}
    for field, name in (("enrollment", "enrollment.json"), ("subject", "subject.txt"),
                        ("subject_manifest", "subject.manifest"), ("source_receipt", "subject-download.json"),
                        ("result", "result.json")):
        value[field] = decode_file(files, name, False).hex()
    value["stages"] = []
    for stage in STAGES:
        handle = decode_file(files, stage + "/work/job-0.json")
        names = {"context": stage + "/context.txt", "context_manifest": stage + "/context.manifest",
                 "dataset": stage + "/dataset.json", "dataset_manifest": stage + "/dataset.manifest",
                 "handle": stage + "/work/job-0.json", "receipt": receipt_name(files, stage, handle),
                 "provider_transcript": stage + "/provider-transcript.json"}
        value["stages"].append({key: decode_file(files, name, False).hex() for key, name in names.items()})
    return value


def bundle_before(work):
    JOBS["guest_work"](work)
    source = root_path(work).parent
    require(all(not os.path.lexists(source / name) for name in ("policy-bundle-fetch", "policy-bundle-cache")),
            "bundle consumer directory/cache were not fresh")
    require(snapshot(root_path(work)) == read(record(work, "files"), 32 * 1048576),
            "pack changed original workflow")
    write(record(work, "bundle-before"), {"same_client": True, "new_output_absent": True,
          "new_cache_absent": True, "original_files_unchanged": True})


def public_file(path, owner):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 2 * 1048576,
            "unsafe retained public bundle file")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "bundle file changed during observation")
    return raw


def transfer(work):
    JOBS["guest_work"](work)
    source = root_path(work).parent
    owner = source.stat().st_uid
    pack, fetched = source / "policy-bundle-publication", source / "policy-bundle-fetch"
    require(set(path.name for path in fetched.iterdir()) == {
        ".task.lock", "assessment.bundle", "assessment.manifest", "download.json", "result.json"},
        "fetch created extra work or retained a temporary projection")
    raw = public_file(pack / "assessment.bundle", owner)
    manifest = public_file(pack / "assessment.manifest", owner)
    require(raw == public_file(fetched / "assessment.bundle", owner)
            and manifest == public_file(fetched / "assessment.manifest", owner),
            "native bundle roundtrip changed original bytes")
    require(snapshot(root_path(work)) == read(record(work, "files"), 32 * 1048576),
            "bundle roundtrip changed original tasks/receipts")
    require(json.loads(public_file(fetched / "result.json", owner)) == read(record(work, "result")),
            "fetched signed evidence reconstructed a different decision")
    write(record(work, "transfer"), {"before": read(record(work, "bundle-before")),
        "bundle_hex": raw.hex(), "manifest_hex": manifest.hex(),
        "pack": read(record(work, "pack")), "fetch": read(record(work, "fetch")),
        "download": json.loads(public_file(fetched / "download.json", owner)),
        "fetched_names": sorted(path.name for path in fetched.iterdir()),
        "exact_bundle_and_manifest": True, "identical_result": True, "original_files_unchanged": True,
        "new_jobs": 0, "other_node_execution_claimed": False})


def check_transfer(value, files, requester, layout, peers, result, publisher):
    raw = bytes.fromhex(value["bundle_hex"])
    require(0 < len(raw) <= 2 * 1048576 and json.loads(raw) == bundle_projection(files, requester),
            "portable bundle is not the exact fixed original-file projection")
    pack, fetched, receipt = value["pack"], value["fetch"], value["download"]
    enrolled = decode_file(files, "enrollment.json")
    check_bundle_manifest(bytes.fromhex(value["manifest_hex"]), raw, publisher, enrolled)
    require(pack == {"operation": "compute_policy_pack", "complete": True,
        "name": "assessment-" + sha(raw)[:32], "manifest_id": sha(bytes.fromhex(value["manifest_hex"])),
        "publisher_key": publisher, "expires": enrolled["expires"], "network_policy_activation": False,
        "provider_signed_claims_verified": True, "independent_execution_proven": False}, "package authority changed")
    require(fetched == {"operation": "compute_policy_fetch", "complete": True, "decision": result["decision"],
        "provider_signed_claims_verified": True, "independent_execution_proven": False,
        "network_policy_activation": False}, "fetch did not verify/reconstruct original claims")
    require(receipt["operation"] == "named_content_download" and receipt["publisher_key"] == publisher
            and receipt["name"] == pack["name"] and receipt["manifest_id"] == pack["manifest_id"]
            and receipt["sha256"] == sha(raw) and receipt["bytes"] == len(raw)
            and receipt["peer_bytes"] == len(raw) and receipt["providers_used"] == 1
            and receipt["provider_peer_ids"] == [peers[layout["provider_nodes"][0]]]
            and receipt["control_relay_peer_id"] == layout["control_relay_peer_id"]
            and receipt["origin_body_bytes"] == 0 and receipt["origin_range_requests"] == 0,
            "fresh-cache bundle bytes did not arrive through the selected protected peer")
    require(value["before"] == {"same_client": True, "new_output_absent": True, "new_cache_absent": True,
                                "original_files_unchanged": True}
            and value["fetched_names"] == sorted([".task.lock", "assessment.bundle", "assessment.manifest",
                                                  "download.json", "result.json"])
            and all(value[key] is True for key in ("exact_bundle_and_manifest", "identical_result", "original_files_unchanged"))
            and value["new_jobs"] == 0 and value["other_node_execution_claimed"] is False,
            "roundtrip isolation/history scope differs")


def protobuf_value(number, value):
    # Only an encoder for exact expected native metadata; reuse the existing strict parser.
    def integer(value):
        encoded = bytearray()
        while value >= 128:
            encoded.append((value & 127) | 128)
            value >>= 7
        return bytes(encoded) + bytes([value])
    if isinstance(value, bytes):
        return integer(number * 8 + 2) + integer(len(value)) + value
    return integer(number * 8) + integer(value)


def check_bundle_manifest(encoded, raw, publisher, enrolled):
    fields, field = CUSTODY["fields"], protobuf_value
    envelope = fields(encoded, 64 * 1024)
    require(set(envelope) == {1, 2}, "invalid bundle signed manifest envelope")
    body = fields(envelope[1], 64 * 1024)
    payload = field(1, ("assessment-" + sha(raw)[:32]).encode()) + field(2, 1)
    payload += field(3, b"application/vnd.volparossa.principle-assessment+json") + field(4, len(raw))
    for offset in range(0, len(raw), 256 * 1024):
        chunk = raw[offset:offset + 256 * 1024]
        payload += field(5, field(1, hashlib.sha256(chunk).digest()) + field(2, len(chunk)))
    payload += field(6, hashlib.sha256(raw).digest())
    require(set(body) == set(range(1, 9)) and body[1] == 1 and body[2] == bytes.fromhex(publisher)
            and enrolled["selected_at"] <= body[3] < body[4] == enrolled["expires"]
            and len(body[5]) == 32 and body[6] == 1
            and body[7] == hashlib.sha256(payload).digest() and body[8] == payload,
            "bundle publisher, original expiry or exact ordered chunks changed")
    verify_signature(envelope[1], envelope[2], body[2], b"VOLPAROSSA/native-content-manifest/v1\0")


def check_stage_manifest(encoded, raw, enrolled, name, content_type):
    fields = CUSTODY["fields"]
    envelope = fields(encoded, 64 * 1024)
    require(set(envelope) == {1, 2}, "invalid signed policy manifest envelope")
    body = fields(envelope[1], 64 * 1024)
    payload = fields(body[8], 64 * 1024)
    chunk = fields(payload[5], 64)
    require(set(body) == set(range(1, 9)) and body[1] == 1
            and body[2] == bytes.fromhex(enrolled["publisher_key"]) and body[6] == 1
            and body[3] == enrolled["selected_at"] and body[4] == enrolled["expires"]
            and 0 < body[3] < body[4] and len(body[5]) == 32
            and body[7] == hashlib.sha256(body[8]).digest(), "signed stage authority/expiry changed")
    require(set(payload) == set(range(1, 7)) and payload[1] == name.encode() and payload[2] == 1
            and payload[3] == content_type.encode() and payload[4] == len(raw)
            and payload[6] == hashlib.sha256(raw).digest()
            and chunk == {1: hashlib.sha256(raw).digest(), 2: len(raw)},
            "signed stage MIME or original bytes differ")
    verify_signature(envelope[1], envelope[2], body[2], b"VOLPAROSSA/native-content-manifest/v1\0")


def check_result(value):
    require(value["operation"] == "compute_peer_policy_assessment" and value["complete"] is True
            and value["network_policy_activation"] is False
            and value["receipt_scope"] == "original_provider_signed_poll_claims_not_independent_execution_proof",
            "model reasoning incomplete or overclaims activation")
    decision = value["decision"]
    require(decision["outcome"] in ("allow", "deny", "undetermined")
            and decision["decision_scope"] == "principle_framework_concept_only"
            and decision["legal_status"] == "not_determined"
            and all(decision[name] is False for name in ("enforcement_authority", "network_policy_changed",
                    "independent_evidence_proven", "semantic_reasoning_correctness_proven")), "unsupported judgment authority")
    require(len(decision["assessments"]) == len(decision["reviews"]) == 2 and len(value["stages"]) == 4,
            "missing actual assessments or cross-reviews")
    records = decision["assessments"] + decision["reviews"]
    require(all(item["scope"] == decision["scope"] for item in records), "decision source bindings differ")
    keys = [item["evidence"]["provider_key"] for item in records]
    require(keys[0] != keys[1] and keys[:2] == keys[2:], "distinct assessors/opposite reviews missing")
    for item in records:
        payload = item.get("assessment", item.get("review"))
        require(payload["version"] == 1 and 1 <= len(payload["reasoning"]) <= 3,
                "model did not produce complete structured reasoning")
        require(all(reason["quote"] and reason["quote"] in SUBJECT and reason["reason"].strip()
                    for reason in payload["reasoning"]), "reasoning is not bound to a literal subject quote")
    return records


def assessment_hash(value):
    # Exact Rust struct field order, not sorted generic JSON. Bind the reviewed
    # original receipt/raw-output digest as well as the interpreted payload.
    ordered = lambda item, keys: {key: item[key] for key in keys}
    payload = ordered(value["assessment"], ("version", "outcome", "reasoning", "counterargument", "uncertainty"))
    payload["reasoning"] = [ordered(item, ("principle", "quote", "reason")) for item in payload["reasoning"]]
    payload["uncertainty"] = ordered(payload["uncertainty"], ("material", "reason"))
    record_value = {
        "scope": ordered(value["scope"], ("source_publisher_key", "source_manifest_id", "source_sha256",
                                          "source_bytes", "framework_version", "framework_sha256")),
        "evidence": ordered(value["evidence"], ("provider_key", "job_id", "report_sha256", "model_fingerprint",
                                                "package_manifest_id")),
        "output_sha256": value["output_sha256"], "assessment": payload,
    }
    return sha(json.dumps(record_value, ensure_ascii=False, separators=(",", ":")).encode())


def check_evidence(value, revision):
    require(value["source_revision"] == revision and value["scope"] == SCOPE, "wrong source/scope")
    check_provision(value["provision"])
    result = value["result"]
    records = check_result(result)
    files = value["files"]
    enrolled = decode_file(files, "enrollment.json")
    require(enrolled["version"] == 2, "new fixture did not explicitly enroll structured public inference")
    requester = value["requester"]["identity_public_key_hex"]
    require(requester == CUSTODY["peer_key"](value["peers"]["client"])
            and requester != value["publication"]["publisher_key_hex"] and enrolled["portable_receipts"] is True,
            "portable requester was not independently bound to the client agent identity")
    require(decode_file(files, "subject.txt", False) == SUBJECT.encode(), "wrong original subject")
    require(decode_file(files, "result.json") == result, "CLI result differs from retained result")
    subject_manifest = decode_file(files, "subject.manifest", False)
    scope = result["decision"]["scope"]
    require(scope["source_sha256"] == sha(SUBJECT.encode()) and scope["source_bytes"] == len(SUBJECT.encode())
            and scope["source_manifest_id"] == sha(subject_manifest)
            and scope["source_publisher_key"] == value["publication"]["publisher_key_hex"],
            "native subject/version differs")
    native = decode_file(files, "subject-download.json")
    require(native["operation"] == "named_content_download" and native["publisher_key"] == scope["source_publisher_key"]
            and native["manifest_id"] == scope["source_manifest_id"] and native["name"] == "disposable-policy-subject"
            and native["sha256"] == scope["source_sha256"] and native["bytes"] == scope["source_bytes"]
            and native["peer_bytes"] == scope["source_bytes"] and native["providers_used"] == 1
            and native["origin_body_bytes"] == 0 and native["origin_range_requests"] == 0
            and native["provider_peer_ids"] == [value["peers"][value["layout"]["provider_nodes"][0]]]
            and native["control_relay_peer_id"] == value["layout"]["control_relay_peer_id"],
            "exact native subject did not arrive from the selected protected peer on a cache miss")
    for index in range(2):
        require(records[2 + index]["reviewed_assessment_sha256"] == assessment_hash(records[1 - index]),
                "cross-review targets a different original assessment")
    observed = value["observation"]["stages"]
    require(set(observed) == set(STAGES), "missing live worker proof")
    response_bytes = {node: 0 for node in value["layout"]["provider_nodes"]}
    for stage, assessment in zip(STAGES, records):
        handle = decode_file(files, stage + "/work/job-0.json")
        bind = handle["binding"]
        dataset_raw = decode_file(files, stage + "/dataset.json", False)
        context = decode_file(files, stage + "/context.txt", False)
        context_manifest = decode_file(files, stage + "/context.manifest", False)
        dataset_manifest = decode_file(files, stage + "/dataset.manifest", False)
        dataset = strict_json(dataset_raw)
        check_dataset(dataset, stage, context, context_manifest)
        check_stage_manifest(context_manifest, context, enrolled, "policy-" + stage + "-context", "text/plain")
        check_stage_manifest(dataset_manifest, dataset_raw, enrolled, "policy-" + stage + "-dataset", CONTENT_TYPE)
        require(sha(dataset_manifest) == bind["dataset_manifest_id"] and bind["row_indices"] == [0]
                and handle["capabilities"].get("principle_inference_v4") is True,
                "actual job does not bind the signed v4 contract or explicit peer capability")
        receipt = decode_file(files, receipt_name(files, stage, handle))
        require(receipt["handle"] == handle and receipt["status"]["binding"] == bind
                and receipt["status"]["state"] == "complete", "original actual receipt differs")
        check_transcript(decode_file(files, stage + "/provider-transcript.json"), handle,
                         receipt["status"], requester, enrolled["selected_at"])
        report_json = receipt["status"]["report_json"]
        report = json.loads(report_json)
        require(sha(report_json.encode()) == receipt["status"]["report_sha256"]
                == assessment["evidence"]["report_sha256"], "raw report binding differs")
        require(assessment["evidence"]["provider_key"] == handle["provider_key"]
                and assessment["evidence"]["job_id"] == bind["job_id"]
                and assessment["evidence"]["model_fingerprint"] == bind["model_fingerprint"]
                and assessment["evidence"]["package_manifest_id"] == bind["dataset_manifest_id"], "assessment provenance differs")
        model = TRAIN["inference_profile"]("smollm2-360m-v1")
        require(handle["capabilities"]["model"] == model["model"]
                and report["status"] == "ok" and report["mode"] == "infer" and report["device"] == "cpu"
                and report["updates_completed"] == 0 and len(report["outputs"]) == 1, "not actual pinned public inference")
        output = report["outputs"][0]
        check_output(output, stage, assessment)
        observation = observed[stage]["observation"]
        require(observed[stage]["handle"] == handle
                and sha(observation["dataset_json"].encode()) == bind["dataset_sha256"]
                and strict_json(observation["dataset_json"]) == dataset
                and report["dataset"]["sha256"] == bind["dataset_sha256"]
                and report["dataset"]["version"] == 4
                and report["dataset"]["output_contract"] == stage_contract(stage)
                and report["dataset"]["source_manifest_sha256"] == sha(context_manifest)
                and observation["network_devices"] == ["lo"] and observation["runtime_lock_held"] is True,
                "worker mount/input/isolation does not bind the actual task")
        require(report["supervisor"]["child_reaped"] is True
                and report["supervisor"]["network_access"] is False, "worker cleanup/network differs")
        response_bytes[observation["node"]] += len(report_json.encode())
    check_transfer(value["transfer"], files, requester, value["layout"], value["peers"], result,
                   value["publication"]["publisher_key_hex"])
    response_bytes[value["layout"]["provider_nodes"][0]] += value["transfer"]["download"]["peer_bytes"]
    CUSTODY["validate_path"](value["path"], value["peers"], value["layout"], "inspect")
    for node, minimum in response_bytes.items():
        require(value["path"]["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"] >= minimum,
                "protected selected provider did not carry the result bytes")
    require(value["replay"] == {"original_files_unchanged": True, "new_jobs": 0, "identical_result": True,
                                "brokers_stopped": True} and value["stopped"]["observed_processes_ended"] is True
            and all(value["cleanup"].values()), "offline replay/private cleanup incomplete")


def evidence(work, revision):
    JOBS["guest_work"](work)
    value = dict(source_revision=revision, scope=SCOPE, result=read(record(work, "result")),
        provision=read(work / "agent-jobs-provision.json"),
        files=read(record(work, "files"), 32 * 1048576), observation=read(record(work, "observation")),
        publication=read(record(work, "publication")), replay=read(record(work, "replay")),
        requester=read(record(work, "requester")), transfer=read(record(work, "transfer"), 8 * 1048576),
        stopped=read(record(work, "stopped")), layout=read(work / "agent-jobs-layout.json"),
        peers=read(work / "a01-expected-peers.json"), cleanup=read(work / "agent-jobs-private-cleanup.json"),
        path=dict(selected_route=read(work / "content-custody-fetch-live-selection.json"),
            privacy={role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in CUSTODY["ROLES"]},
            control_privacy=read(work / "content-provider-custody-fetch-control.json"),
            gates=read(work / "content-custody-fetch-gates.json")))
    check_evidence(value, revision)
    write(record(work, "evidence"), value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    path = record(work, "evidence")
    proof = read(path, 64 * 1048576) if path.is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    value = dict(report_kind=NAME, source_revision=revision, scope=SCOPE,
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and proof is not None,
        runner_exit_status=status, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        full_b06_claimed=False, network_policy_activation_claimed=False, evidence=proof,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host)
    write(record(work, "smoke"), value)


def check_report(value, revision):
    require(value["report_kind"] == NAME and value["source_revision"] == revision and value["scope"] == SCOPE
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["full_b06_claimed"] is False and value["network_policy_activation_claimed"] is False,
            "incomplete or overstated policy proof")
    require(value["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "host/guest cleanup changed")
    check_evidence(value["evidence"], revision)


def self_test():
    from copy import deepcopy
    from unittest.mock import patch

    checked_rejections = 0
    def rejects(function, *args):
        nonlocal checked_rejections
        try:
            function(*args)
        except (KeyError, ValueError):
            checked_rejections += 1
        else:
            raise ValueError("structured inference mutation accepted")

    # Synthetic checker controls only; never supplied to real model inference.
    payload = {"version": 1, "outcome": "undetermined", "reasoning": [
        {"principle": "Humilitas", "quote": "Neighbors", "reason": "Synthetic checker input."}],
        "counterargument": "Synthetic counterargument.", "uncertainty": {"material": True, "reason": "Synthetic uncertainty."}}
    for stage in ("assessment-0", "review-0"):
        expected = deepcopy(payload)
        if stage.startswith("review-"):
            expected["verdict"] = "undetermined"
        text = json.dumps(expected, separators=(",", ":"))
        assertion = {"review" if stage.startswith("review-") else "assessment": expected, "output_sha256": sha(text.encode())}
        output = {"text": text, "text_truncated": False, "generated_tokens": 120,
            "generation": {"version": 3, "stop_reason": "json_boundary", "max_new_tokens": 512,
                           "model_profile": "smollm2-360m-v1", "output_contract": stage_contract(stage)}}
        check_output(output, stage, assertion)
        check_output({**output, "generation": {**output["generation"], "stop_reason": "eos"}}, stage, assertion)
        for stop_reason in ("json_boundary", "eos"):
            check_output({**output, "generated_tokens": 512,
                          "generation": {**output["generation"], "stop_reason": stop_reason}}, stage, assertion)
        # Historical v2/256 and mixed version/budget pairs cannot prove this new execution.
        for version, budget in ((2, 256), (2, 512), (3, 256)):
            rejects(check_output, {**output, "generation": {**output["generation"],
                    "version": version, "max_new_tokens": budget}}, stage, assertion)
        for key, value in (("version", 1), ("stop_reason", "token_limit"), ("stop_reason", "graph_boundary"),
                           ("max_new_tokens", 384), ("model_profile", "smollm2-135m-v1"),
                           ("output_contract", CONTRACTS[1 if stage.startswith("assessment-") else 0])):
            bad = deepcopy(output)
            bad["generation"][key] = value
            if value == "token_limit":
                bad["generated_tokens"] = 512
            rejects(check_output, bad, stage, assertion)
        for key, value in (("text_truncated", True), ("generated_tokens", 0), ("generated_tokens", 513),
                           ("generated_tokens", True), ("text", text + " extra"), ("text", text[:-1])):
            rejects(check_output, {**output, key: value}, stage, assertion)
        duplicate = text[:-1] + ',"version":1}'
        rejects(check_output, {**output, "text": duplicate}, stage,
                {**assertion, "output_sha256": sha(duplicate.encode())})
        dataset = {"version": 4, "visibility": "public", "license": "CC0-1.0", "source_manifest_hex": b"manifest".hex(),
            "inference": [{"question": "Synthetic question", "context": SUBJECT, "start": 0, "end": len(SUBJECT.encode())}],
            "output_contract": stage_contract(stage)}
        check_dataset(dataset, stage, SUBJECT.encode(), b"manifest")
        for key, value in (("version", 2), ("visibility", "private"), ("source_manifest_hex", "00"),
                           ("output_contract", "arbitrary"), ("inference", []), ("license", "unknown")):
            rejects(check_dataset, {**dataset, key: value}, stage, SUBJECT.encode(), b"manifest")
        bad = deepcopy(dataset)
        bad["inference"][0]["end"] -= 1
        rejects(check_dataset, bad, stage, SUBJECT.encode(), b"manifest")

    pins, lock = provision_pins()
    provision = {"success": True, "installed_wheels": len(pins["wheels"]), "model_profile": "smollm2-360m-v1",
        "model_id": pins["model_id"], "revision": pins["revision"], "task_graph_decoder": DECODER,
        "download_bytes": sum(item["bytes"] for item in pins["files"] + pins["wheels"]),
        "model_pins_sha256": sha((json.dumps(pins, indent=2) + "\n").encode()), "requirements_sha256": sha(lock),
        "budget_bytes": 3 * 1024**3, "runtime_autofetch_enabled": False, "training_performed": False}
    check_provision(provision)
    for key, value in (("installed_wheels", 38), ("task_graph_decoder", None), ("model_pins_sha256", "00" * 32),
                       ("requirements_sha256", "00" * 32), ("model_profile", "smollm2-135m-v1")):
        rejects(check_provision, {**provision, key: value})

    for value in ({}, {"operation": "compute_peer_policy_assessment", "complete": False,
                      "network_policy_activation": False},
                  {"operation": "compute_peer_policy_assessment", "complete": True,
                   "network_policy_activation": True}):
        try:
            check_result(value)
        except (KeyError, ValueError):
            pass
        else:
            raise ValueError("missing/incomplete/activating result accepted")
    require(0 < len(SUBJECT.encode()) <= 512, "synthetic subject exceeds actual product scope")
    # Synthetic protocol bindings only. Real signatures are checked by OpenSSL in
    # evidence/report, and the Rust transcript tests exercise actual signing keys.
    field = protobuf_value
    provider, requester = "11" * 32, "22" * 32
    handle = {"provider_key": provider, "binding": {"job_id": "33" * 16, "expires_unix_seconds": 100}}
    status = {"binding": handle["binding"], "state": "complete", "report_json": "{}"}
    request = {"version": 1, "request_id": "44" * 16, "requester_key": requester,
               "operation": {"operation": "poll", "value": handle["binding"]}}
    response = {"version": 1, "request_id": request["request_id"],
                "outcome": {"outcome": "job", "value": status}}
    def envelope(kind, key, payload, challenge=None, original_request=None):
        body = field(1, 1) + field(2, bytes.fromhex(key)) + field(3, 10 + kind) + field(4, 30)
        body += field(5, b"n" * 32) + field(6, kind) + field(7, hashlib.sha256(payload).digest())
        if payload:
            body += field(8, payload)
        if original_request:
            body += field(9, hashlib.sha256(original_request).digest())
        if challenge:
            body += field(10, hashlib.sha256(challenge).digest())
        return field(1, body) + field(2, b"s" * 64)
    challenge = envelope(1, provider, b"")
    original_request = envelope(2, requester, json.dumps(request).encode(), challenge)
    reply = envelope(3, provider, json.dumps(response).encode(), challenge, original_request)
    transcript = field(1, 1) + field(2, challenge) + field(3, original_request) + field(4, reply)
    retained = {"version": 1, "requester_key": requester, "transcript_hex": transcript.hex()}
    with patch.dict(globals(), {"verify_signature": lambda *_: None}):
        enrolled = {"publisher_key": provider, "selected_at": 10, "expires": 100}
        raw = b'{"version":4}'
        object_name = "policy-assessment-0-dataset"
        package = field(1, object_name.encode()) + field(2, 1) + field(3, CONTENT_TYPE.encode()) + field(4, len(raw))
        package += field(5, field(1, hashlib.sha256(raw).digest()) + field(2, len(raw)))
        package += field(6, hashlib.sha256(raw).digest())
        body = field(1, 1) + field(2, bytes.fromhex(provider)) + field(3, 10) + field(4, 100)
        body += field(5, b"n" * 32) + field(6, 1) + field(7, hashlib.sha256(package).digest()) + field(8, package)
        signed = field(1, body) + field(2, b"s" * 64)
        check_stage_manifest(signed, raw, enrolled, object_name, CONTENT_TYPE)
        rejects(check_stage_manifest, signed, raw, enrolled, object_name,
                "application/vnd.volparossa.agent-document.v2+json")
        rejects(check_stage_manifest, signed, raw, enrolled, "policy-review-0-dataset", CONTENT_TYPE)
        rejects(check_stage_manifest, signed, raw + b" ", enrolled, object_name, CONTENT_TYPE)
        rejects(check_stage_manifest, signed, raw, {**enrolled, "expires": 101}, object_name, CONTENT_TYPE)
        rejects(check_stage_manifest, signed, raw, {**enrolled, "publisher_key": requester}, object_name, CONTENT_TYPE)
        check_transcript(retained, handle, status, requester, 10)
        failures = [lambda: check_transcript(retained, handle, status, provider, 10),
                    lambda: check_transcript(retained, handle, {**status, "state": "failed"}, requester, 10),
                    lambda: check_transcript(retained, handle, status, requester, 14),
                    lambda: check_transcript({**retained, "transcript_hex": (transcript + field(4, reply)).hex()},
                                             handle, status, requester, 10)]
        for failure in failures:
            try:
                failure()
            except (KeyError, ValueError):
                pass
            else:
                raise ValueError("synthetic transcript binding mutation accepted")
    files = {}
    def add(name, raw):
        files[name] = {"bytes": len(raw), "sha256": sha(raw), "raw_hex": raw.hex()}
    for name in ("enrollment.json", "subject.txt", "subject.manifest", "subject-download.json", "result.json"):
        add(name, name.encode())
    for stage in STAGES:
        for name in ("context.txt", "context.manifest", "dataset.json", "dataset.manifest", "provider-transcript.json"):
            add(stage + "/" + name, name.encode())
        add(stage + "/work/job-0.json", json.dumps(handle).encode())
        add(stage + "/work/receipt-" + handle["binding"]["job_id"] + ".json", b"running")
        add(stage + "/poll-00/receipt-" + handle["binding"]["job_id"] + ".json", b"complete")
    projected = bundle_projection(files, requester)
    require(set(projected) == {"version", "requester_key", "enrollment", "subject", "subject_manifest",
                              "source_receipt", "result", "stages"}
            and all(set(stage) == {"context", "context_manifest", "dataset", "dataset_manifest",
                                  "handle", "receipt", "provider_transcript"}
                    and bytes.fromhex(stage["receipt"]) == b"complete" for stage in projected["stages"]),
            "portable projection dropped proof fields or selected a superseded receipt")
    print(f"PASS: structured contract/provision positives + {checked_rejections} rejections; "
          "3 incomplete/authority rejections, synthetic transcript positive + 4 binding rejections, "
          "fixed bundle projection/terminal receipt selection; no model or real-signature execution")


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        self_test()
    elif len(args) == 2 and args[0] in ("prepare", "collect", "stopped", "replay", "bundle_before", "transfer"):
        globals()[args[0]](Path(args[1]))
    elif len(args) == 3 and args[0] == "observe":
        observe(Path(args[1]), int(args[2]))
    elif len(args) == 3 and args[0] == "evidence":
        evidence(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "report":
        check_report(read(Path(args[1]), 64 * 1048576), args[2])
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    else:
        raise SystemExit("invalid policy fixture arguments")


if __name__ == "__main__":
    main()
