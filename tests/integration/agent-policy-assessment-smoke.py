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
MAX_OUTPUT_BYTES = 2048
CONTENT_TYPE = "application/vnd.volparossa.agent-principle.v4+json"
DECODER = {"implementation": "lm-format-enforcer", "version": "0.11.3", "adapter_version": 1,
           "schema_version": 3, "dependencies": {"interegular": "0.3.3", "pydantic": "1.10.24"}}
SCOPE = ("one exact synthetic public native object fetched through its protected content path, two actual "
         "360M peer assessments and opposite-peer cross-reviews under the seven virtues/vices, bound "
         "to signed dataset-v4 contracts and original provider-signed JSON-boundary/EOS receipts, "
         "using the explicitly provisioned pinned decoder without fixed verdicts, publish and fetch their exact native bundle into "
         "a new cache and directory on the same client, unchanged completed offline replay, three separately invoked "
         "existing development authorities replaying and endorsing that actual outcome without local application, "
         "protected signed-decision custody delivery to a second node, its own signed named publication, "
         "an explicitly enrolled automatic Client follower started with an empty cache before that publication, "
         "actual peer retrieval and exact-object quorum activation with cached-access and Client-restart checks, "
         "the second node's independent import, exact cached-object export and restart "
         "checks, and full owned cleanup; "
         "not classifier quality, legal correctness, independent semantic judgment, global-policy activation or full B06")


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
    require(0 < len(raw) <= MAX_OUTPUT_BYTES and set(payload) == fields and payload["version"] == 1
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


def object_fields(raw, maximum, repeated=()):
    """Strict original protobuf fields, with only declared repeatable message tags."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum, "object proof bound")
    values, offset, previous, canonical = {}, 0, 0, b""
    while offset < len(raw):
        tag, offset = CUSTODY["varint"](raw, offset)
        number, wire = tag >> 3, tag & 7
        require(number > previous or number == previous and number in repeated, "object proof field order")
        require(number > 0 and wire in (0, 2), "object proof wire type")
        previous = number
        value, offset = CUSTODY["varint"](raw, offset)
        if wire == 2:
            require(value > 0 and offset + value <= len(raw), "object proof truncated field")
            value, offset = raw[offset:offset + value], offset + value
        else:
            require(value > 0, "noncanonical default object scalar")
        canonical += protobuf_value(number, value)
        if number in repeated:
            values.setdefault(number, []).append(value)
        else:
            values[number] = value
    require(canonical == raw, "noncanonical object proof encoding")
    return values


def object_envelope(raw, public_keys, expected_signers, policy_epoch=False):
    envelope = object_fields(raw, 64 * 1024 if policy_epoch else 8192, (3,))
    require(set(envelope) == ({1, 2, 3} if expected_signers else {1, 2})
            and envelope[2] == hashlib.sha256(envelope[1]).digest(), "original signed body hash differs")
    signatures = envelope.get(3, [])
    require(len(signatures) == expected_signers, "wrong distinct authority signature count")
    previous = b""
    observed = set()
    for original in signatures:
        signature = object_fields(original, 256)
        require(set(signature) == {1, 2} and signature[1] > previous and signature[1] in public_keys,
                "unknown, repeated or unordered authority")
        previous = signature[1]
        observed.add(previous)
        if policy_epoch:
            domain = b"volparossa/whitelist-manifest/signature/v1\0"
            message = envelope[2] + envelope[1]
        else:
            domain = b"VOLPAROSSA/native-object-decision/signature/v1\0"
            message = signature[1] + envelope[2] + envelope[1]
        verify_signature(message, signature[2], public_keys[signature[1]], domain)
    return envelope, observed


def check_object_probe(probe, phase, result):
    require(probe["phase"] == phase and type(probe["exit_code"]) is int
            and probe["observed_at_ms"] > 0 and probe["agent"]["pid"] > 0,
            "missing actual cache probe observation")
    allowed = phase == "before" or result["decision"]["outcome"] == "allow"
    raw = bytes.fromhex(probe["stdout_hex"])
    error = bytes.fromhex(probe["stderr_hex"])
    if allowed:
        receipt = strict_json(raw)
        scope = result["decision"]["scope"]
        require(probe["exit_code"] == 0 and probe["output_bytes"] == len(SUBJECT.encode())
                and probe["output_sha256"] == sha(SUBJECT.encode())
                and receipt["operation"] == "named_content_download" and receipt["cache_only"] is True
                and receipt["manifest_id"] == scope["source_manifest_id"]
                and receipt["publisher_key"] == scope["source_publisher_key"]
                and receipt["sha256"] == scope["source_sha256"] and receipt["bytes"] == scope["source_bytes"]
                and receipt["peer_bytes"] == receipt["providers_used"] == receipt["origin_body_bytes"] == 0,
                "Allow did not retain actual exact cached-object access")
    else:
        require(probe["exit_code"] == 1 and raw == b"" and probe["output_bytes"] is None
                and probe["output_sha256"] is None
                and error.strip() == b"Error: agent rejected request: CONTENT_POLICY (Policy)",
                "Deny/Undetermined was not an actual typed policy refusal without output")


def object_probe(work, phase, status):
    JOBS["guest_work"](work)
    require(phase in ("before", "applied", "restarted"), "unknown object probe")
    source = root_path(work).parent
    output = source / f"policy-object-{phase}.txt"
    raw = public_file(output, source.stat().st_uid) if output.exists() else None
    pid = int(JOBS["subprocess"].check_output(["systemctl", "show", "--property=MainPID", "--value",
                                              "volparossa-alpha-agent@client.service"], text=True))
    observed = dict(phase=phase, exit_code=status, observed_at_ms=time.time_ns() // 1000000,
        stdout_hex=record(work, "object-" + phase).read_bytes().hex(),
        stderr_hex=(work / f"{NAME}-object-{phase}.err").read_bytes().hex(),
        output_bytes=len(raw) if raw is not None else None, output_sha256=sha(raw) if raw is not None else None,
        agent=JOBS["identity"](pid), namespace=os.readlink(f"/proc/{pid}/ns/net"))
    write(record(work, "object-probe-" + phase), observed)
    check_object_probe(observed, phase, read(record(work, "result")))


def object_collect(work, phase):
    JOBS["guest_work"](work)
    require(phase in ("before", "after"), "unknown object collection phase")
    source = root_path(work).parent
    owner = source.stat().st_uid
    bundle = public_file(source / "policy-bundle-fetch/assessment.bundle", owner)
    retained = {}
    for directory, extra in [("policy-object-proposal", "proposal.bin"),
                            *[(f"policy-object-endorsement-{i}", "endorsement.bin") for i in range(3)],
                            ("policy-object-combined", "decision.bin")]:
        base = source / directory
        expected = {".task.lock", "assessment.bundle", "selection.json", "proposal.bin", extra}
        require(set(item.name for item in base.iterdir()) == expected, "unexpected policy output/private file")
        for name in sorted(expected - {".task.lock"}):
            raw = public_file(base / name, owner)
            item = {"bytes": len(raw), "sha256": sha(raw)}
            if name == "assessment.bundle":
                require(raw == bundle, "authority silently replaced original assessment bundle")
            else:
                item["raw_hex"] = raw.hex()
            retained[directory + "/" + name] = item
    require(snapshot(root_path(work)) == read(record(work, "files"), 32 * 1048576),
            "object authority flow altered original model work")
    journal = public_file(work / "state-client/object-policy/journal.json", owner)
    value = {"files": retained, "journal_hex": journal.hex(),
             "follow": read(record(work, "follow-proof"), 8 * 1048576),
             "epoch_manifest_hex": public_file(work / "development-policy.manifest", owner).hex(),
             "trust": strict_json(public_file(work / "policy-maintainers.json", owner)),
             "authorities": [read(record(work, f"object-authority-{i}")) for i in range(3)],
             "reports": {name: read(record(work, "object-" + name)) for name in
                         ("proposal", "endorsement-0", "endorsement-1", "endorsement-2", "combined")}}
    write(record(work, "object-originals-" + phase), value)
    if phase == "after":
        require(value == read(record(work, "object-originals-before"), 8 * 1048576),
                "restart changed original decision, authority or durable journal")
        probes = {name: read(record(work, "object-probe-" + name)) for name in ("before", "applied", "restarted")}
        require(not JOBS["alive"](probes["applied"]["agent"]) and JOBS["alive"](probes["restarted"]["agent"]),
                "restart did not end the original agent lifetime")
        proof = {"originals": value, "probes": probes, "originals_unchanged_after_restart": True,
                 "old_agent_ended": True, "new_agent_alive": True}
        check_object_activation(proof, read(record(work, "result")),
                                read(record(work, "transfer"), 8 * 1048576),
                                read(record(work, "files"), 32 * 1048576))
        write(record(work, "object-activation"), proof)


def check_fixture_epoch_header(epoch_body, epoch_signers, public):
    # Manifest schema/version are 1; minimum_protocol_version is the separate policy protocol 2.
    require(set(epoch_body) == set(range(1, 10)) and epoch_body[1] == epoch_body[2] == 1
            and epoch_body[3] == 2 and epoch_body[7] == 3 and epoch_signers == set(public),
            "different fixture authority epoch")


def check_object_activation(proof, result, transfer_value, original_files):
    original = proof["originals"]
    trust = original["trust"]
    require(trust["schema_version"] == 1 and len(trust["maintainers"]) == 3
            and all(item["environment"] == "development" for item in trust["maintainers"]),
            "authority is not the original three development maintainers")
    public = {hashlib.sha256(b"volparossa/whitelist-maintainer/id/v1\0" + bytes.fromhex(item["public_key_hex"])).digest():
              bytes.fromhex(item["public_key_hex"]) for item in trust["maintainers"]}
    require(len(public) == 3, "duplicate configured authority")
    epoch, epoch_signers = object_envelope(bytes.fromhex(original["epoch_manifest_hex"]), public, 3, True)
    epoch_body = object_fields(epoch[1], 64 * 1024, (8, 9))
    check_fixture_epoch_header(epoch_body, epoch_signers, public)
    epoch_members = [object_fields(item, 256) for item in epoch_body[8]]
    require(len(epoch_members) == 3 and {member[1] for member in epoch_members} == set(public)
            and all(set(member) == {1, 2, 3} and member[2] == public[member[1]] and member[3] == 2
                    for member in epoch_members), "original policy assigned a different development trust set")
    files = original["files"]
    raw_bundle = bytes.fromhex(transfer_value["bundle_hex"])
    enrolled = decode_file(original_files, "enrollment.json")
    scope = result["decision"]["scope"]
    proposal, _ = object_envelope(decode_file(files, "policy-object-proposal/proposal.bin", False), public, 0)
    body = object_fields(proposal[1], 1024)
    outcome = {"allow": 1, "deny": 2, "undetermined": 3}[result["decision"]["outcome"]]
    require(set(body) == set(range(1, 15)) and body[1] == body[2] == body[5] == 1
            and body[3] == epoch[2] and body[4] == epoch_body[2]
            and body[6] == bytes.fromhex(scope["source_publisher_key"])
            and body[7] == bytes.fromhex(scope["source_manifest_id"])
            and body[8] == bytes.fromhex(scope["source_sha256"])
            and body[9] == bytes.fromhex(scope["framework_sha256"])
            and body[10] == hashlib.sha256(raw_bundle).digest() and body[11] == outcome
            and len(body[14]) == 32 and body[14] != bytes(32)
            and max(enrolled["selected_at"] * 1000, epoch_body[5]) <= body[12] < body[13]
            and body[13] == min(enrolled["expires"] * 1000, epoch_body[6], body[12] + 7 * 24 * 3600 * 1000),
            "proposal changed the actual model verdict, original source/evidence or expiry")
    expected_selection = {"version": 1, "requester_key": json.loads(raw_bundle)["requester_key"],
        "source_publisher_key": scope["source_publisher_key"],
        "source_manifest_id": scope["source_manifest_id"], "providers": enrolled["providers"],
        "model_profile": "smollm2-360m-v1"}
    signed_by = set()
    for index, authority in enumerate(original["authorities"]):
        require(authority == {"index": index, "public_key_hex": trust["maintainers"][index]["public_key_hex"],
                             "development_only": True, "identities_created": 1}, "authority was replaced")
        endorsement, signers = object_envelope(decode_file(files,
            f"policy-object-endorsement-{index}/endorsement.bin", False), public, 1)
        expected_key = hashlib.sha256(b"volparossa/whitelist-maintainer/id/v1\0" + bytes.fromhex(authority["public_key_hex"])).digest()
        require(endorsement[1] == proposal[1] and signers == {expected_key} and not signed_by.intersection(signers),
                "authority did not sign the same original body separately")
        signed_by.update(signers)
    decision_raw = decode_file(files, "policy-object-combined/decision.bin", False)
    decision, signers = object_envelope(decision_raw, public, 3)
    require(decision[1] == proposal[1] and signers == signed_by == set(public), "quorum changed the original body")
    for directory in ("policy-object-proposal", "policy-object-combined",
                      *(f"policy-object-endorsement-{i}" for i in range(3))):
        require(files[directory + "/assessment.bundle"] == {"bytes": len(raw_bundle), "sha256": sha(raw_bundle)}
                and decode_file(files, directory + "/selection.json") == expected_selection
                and decode_file(files, directory + "/proposal.bin", False)
                    == decode_file(files, "policy-object-proposal/proposal.bin", False), "independent selection/evidence changed")
    for name, report_value in original["reports"].items():
        require(report_value["complete"] is True and report_value["outcome"] == result["decision"]["outcome"]
                and report_value["provider_signed_claims_replayed"] == 4
                and report_value["threshold_verified"] == (name == "combined")
                and report_value["network_policy_activation"] is False
                and report_value["local_object_policy_applied"] is False
                and report_value["semantic_correctness_proven"] is False
                and report_value["issued_at_ms"] == body[12] and report_value["expires_at_ms"] == body[13],
                "CLI overclaimed global/model authority or changed actual outcome")
    receipt = original["follow"]["state"]["applied"]["apply_receipt"]
    require(original["follow"]["state"]["applied"]["epoch_manifest_hex"] == original["epoch_manifest_hex"],
            "follower accepted a different original authority epoch")
    require(receipt == {"version": 1, "manifest_id": list(body[7]), "decision_hash": list(decision[2]),
        "decision_revision": 1, "policy_hash": list(epoch[2]), "outcome": outcome}, "applied a different object decision")
    require(strict_json(bytes.fromhex(original["journal_hex"])) == {"version": 1, "entries": [
        {"envelope_hex": decision_raw.hex(), "epoch_manifest_hex": original["epoch_manifest_hex"]}]},
        "durable restart authority did not retain exact original signatures")
    probes = proof["probes"]
    for phase in ("before", "applied", "restarted"):
        check_object_probe(probes[phase], phase, result)
        require(probes[phase]["observed_at_ms"] < body[13], "access proof ran after original authority expiry")
    require(probes["before"]["agent"] == probes["applied"]["agent"] != probes["restarted"]["agent"]
            and len({item["namespace"] for item in probes.values()}) == 1
            and body[12] <= probes["applied"]["observed_at_ms"] <= probes["restarted"]["observed_at_ms"]
            and proof["originals_unchanged_after_restart"] is True
            and proof["old_agent_ended"] is True and proof["new_agent_alive"] is True,
            "restart did not preserve original exact-object access decision")


def object_peer_context(work):
    node = read(work / "agent-jobs-layout.json")["provider_nodes"][0]
    require(node in ("relay3", "relay4", "relay5"), "wrong independent object-policy receiver")
    root = work / f"state-{node}/policy-object-receiver"
    owner = root_path(work).parent.stat().st_uid
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and stat.S_IMODE(info.st_mode) == 0o700,
            "unsafe object receiver directory")
    pid = int(JOBS["subprocess"].check_output(["systemctl", "show", "--property=MainPID", "--value",
        f"volparossa-alpha-agent@{node}.service"], text=True))
    return node, root, owner, JOBS["identity"](pid), os.readlink(f"/proc/{pid}/ns/net")


def object_peer_pins(work):
    JOBS["guest_work"](work)
    source = root_path(work).parent
    raw = public_file(source / "policy-object-combined/decision.bin", source.stat().st_uid)
    trust = read(work / "policy-maintainers.json")
    public = {hashlib.sha256(b"volparossa/whitelist-maintainer/id/v1\0" + bytes.fromhex(item["public_key_hex"])).digest():
              bytes.fromhex(item["public_key_hex"]) for item in trust["maintainers"]}
    envelope, _ = object_envelope(raw, public, 3)
    body = object_fields(envelope[1], 1024)
    scope = read(record(work, "result"))["decision"]["scope"]
    require(body[6].hex() == scope["source_publisher_key"] and body[7].hex() == scope["source_manifest_id"]
            and body[8].hex() == scope["source_sha256"] and body[9].hex() == scope["framework_sha256"]
            and body[11] == {"allow": 1, "deny": 2, "undetermined": 3}[read(record(work, "result"))["decision"]["outcome"]],
            "remote pins not derived from original quorum decision")
    write(record(work, "remote-object-pins"), dict(subject_publisher_key=body[6].hex(),
        subject_manifest_id=body[7].hex(), subject_sha256=body[8].hex(),
        decision_hash=envelope[2].hex(), evidence_sha256=body[10].hex()))


def object_peer_before(work):
    JOBS["guest_work"](work)
    node, root, owner, agent, namespace = object_peer_context(work)
    source = root_path(work).parent
    raw = public_file(source / "policy-object-publication/decision.bin", owner)
    manifest = public_file(root / "decision.manifest", owner)
    subject = public_file(root / "subject.manifest", owner)
    require(set(path.name for path in root.iterdir()) == {"subject.manifest", "decision.manifest"}
            and manifest == public_file(source / "policy-object-publication/publication.manifest", owner)
            and subject == public_file(source / "policy-subject.pb", owner), "receiver seeded data instead of public metadata")
    custody = root.parent / "custody-cache"
    require(not os.path.lexists(custody / sha(raw)), "decision payload was not cold before custody deposit")
    require(public_file(custody / sha(SUBJECT.encode()), owner) == SUBJECT.encode(),
            "receiver does not hold the original deposited subject")
    journal = public_file(root.parent / "object-policy/journal.json", owner)
    require(strict_json(journal) == {"version": 1, "entries": []}, "receiver already had an object-policy decision")
    write(record(work, "remote-object-cold"), dict(node=node, agent=agent, namespace=namespace,
        observed_at_ms=time.time_ns() // 1000000, decision_chunk_absent=True, local_decision_absent=True,
        metadata_only=True, subject_manifest_hex=subject.hex(), manifest_hex=manifest.hex(),
        journal_hex=journal.hex(), custody_directory=[custody.stat().st_dev, custody.stat().st_ino]))


def object_peer_received(work):
    JOBS["guest_work"](work)
    node, root, owner, agent, namespace = object_peer_context(work)
    source = root_path(work).parent
    raw = public_file(root / "decision.bin", owner)
    require(raw == public_file(source / "policy-object-combined/decision.bin", owner)
            == public_file(source / "policy-object-publication/decision.bin", owner),
            "remote custody transport replaced original quorum bytes")
    require(snapshot(root_path(work)) == read(record(work, "files"), 32 * 1048576),
            "policy distribution changed original model work")
    write(record(work, "remote-object-received"), dict(node=node, agent=agent, namespace=namespace,
        observed_at_ms=time.time_ns() // 1000000, decision_hex=raw.hex(),
        before=read(record(work, "remote-object-cold")), pins=read(record(work, "remote-object-pins")),
        publication=read(record(work, "remote-object-publication")),
        deposit=read(record(work, "remote-object-deposit")),
        export=read(record(work, "remote-object-export")), assemble=read(record(work, "remote-object-assemble")),
        original_model_files_unchanged=True, new_jobs=0))


def follow_paths(work):
    source = root_path(work).parent
    node = read(work / "agent-jobs-layout.json")["provider_nodes"][0]
    return source / "policy-object-follow", source / "policy-object-follow-cache", \
        work / f"state-{node}/policy-object-receiver/follow-publication"


def follow_snapshot(work):
    directory, _, _ = follow_paths(work)
    owner = root_path(work).parent.stat().st_uid
    files = {name: public_file(directory / name, owner).hex()
             for name in ("enrollment.json", "state.json", "status.json")}
    state, status = (strict_json(bytes.fromhex(files[name])) for name in ("state.json", "status.json"))
    if status["state_sha256"] != sha(bytes.fromhex(files["state.json"])):
        return None  # Two separately atomic checkpoints may straddle this read.
    return dict(files=files, state=state, status=status,
                enrollment=strict_json(bytes.fromhex(files["enrollment.json"])))


def check_follow_cold(value):
    state = value["state"]
    require(state["version"] == 1 and state["completed_polls"] >= 1
            and state["confirmed_applications"] == 0 and state["latest"] is None and state["applied"] is None
            and state["last_poll"]["outcome"] == "fetch_failed"
            and 0 < state["last_poll"]["completed_at_ms"] <= value["observed_at_ms"]
            and value["provider_publication_absent"] is True and value["cache_payload_absent"] is True
            and strict_json(bytes.fromhex(value["journal_hex"])) == {"version": 1, "entries": []},
            "follower was not observed unavailable and unapplied before named publication")


def follow_observe(work, pid, applied):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](pid)
    directory, cache, publication = follow_paths(work)
    node_owner = root_path(work).parent.stat().st_uid
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        require(JOBS["alive"](owner), "original policy follower exited before its required phase")
        try:
            value = follow_snapshot(work)
        except FileNotFoundError:
            value = None
        if value is None:
            time.sleep(.1)
            continue
        state = value["state"]
        ready = (state["applied"] is not None if applied else
                 state["completed_polls"] >= 1 and state["last_poll"]["outcome"] == "fetch_failed")
        if not ready:
            time.sleep(.1)
            continue
        processes = TRAIN["descendants"](pid)
        children = []
        for member in processes:
            proc = Path(f"/proc/{member['pid']}")
            try:
                if Path(os.readlink(proc / "exe")).name != "volparossa":
                    continue
                argv = (proc / "cmdline").read_bytes().split(b"\0")
                require(b"policy-follow" in argv and str(directory).encode() in argv
                        and proc.stat().st_uid == node_owner, "unexpected follower executable/owner/enrollment")
                children.append(member)
            except FileNotFoundError:
                continue
        require(len(children) == 1, "missing exact live unprivileged policy-follow child")
        agent_pid = int(JOBS["subprocess"].check_output(["systemctl", "show", "--property=MainPID", "--value",
            "volparossa-alpha-agent@client.service"], text=True))
        namespace = os.readlink(f"/proc/{children[0]['pid']}/ns/net")
        require(namespace == os.readlink(f"/proc/{agent_pid}/ns/net"), "follower bypassed the Client namespace")
        value.update(owner=owner, child=children[0], owned_processes=processes, namespace=namespace,
                     agent=JOBS["identity"](agent_pid), observed_at_ms=time.time_ns() // 1000000)
        if not applied:
            value.update(provider_publication_absent=not os.path.lexists(publication),
                cache_payload_absent=not cache.exists() or not any(re.fullmatch(r"[0-9a-f]{64}", item.name)
                                                                  for item in cache.iterdir()),
                journal_hex=public_file(work / "state-client/object-policy/journal.json", node_owner).hex())
            check_follow_cold(value)
        else:
            before = read(record(work, "follow-before"))
            require(value["owner"] == before["owner"] and value["child"] == before["child"]
                    and state["confirmed_applications"] == 1, "follower was replaced or applied multiple decisions")
        write(record(work, "follow-observed-applied" if applied else "follow-before"), value)
        return
    raise ValueError("actual policy follower did not reach the required bounded phase")


def object_follow_before(work, pid):
    follow_observe(work, pid, False)


def object_follow_applied(work, pid):
    follow_observe(work, pid, True)


def object_follow_collect(work, pid, status):
    JOBS["guest_work"](work)
    before = read(record(work, "follow-before"))
    observed = read(record(work, "follow-observed-applied"))
    require(before["owner"]["pid"] == pid and status == 0
            and all(not JOBS["alive"](item) for item in [before["owner"], before["child"], *observed["owned_processes"]]),
            "original follower was not successfully stopped and fully reaped")
    final = follow_snapshot(work)
    require(final is not None and final["state"]["applied"] == observed["state"]["applied"]
            and final["files"]["enrollment.json"] == before["files"]["enrollment.json"],
            "stopping changed the original applied policy or enrollment")
    _, _, publication = follow_paths(work)
    owner = root_path(work).parent.stat().st_uid
    proof = dict(**final, before=before, observed=observed,
        publication_files={name: public_file(publication / name, owner).hex()
                           for name in ("selection.json", "decision.bin", "publication.manifest", "publication.json")},
        publication=read(record(work, "follow-publication")), contribution=read(record(work, "follow-contribution")),
        summary=read(record(work, "follow-summary")), exit_status=status, owner_ended=True, child_ended=True)
    raw = public_file(root_path(work).parent / "policy-object-combined/decision.bin", owner)
    check_object_follow(proof, raw, read(record(work, "result")), read(work / "agent-jobs-layout.json"),
                        read(work / "a01-expected-peers.json"))
    write(record(work, "follow-proof"), proof)


def check_object_follow(value, raw, result, layout, peers):
    before, observed, state = value["before"], value["observed"], value["state"]
    check_follow_cold(before)
    envelope = object_fields(raw, 8192, (3,))
    body = object_fields(envelope[1], 1024)
    applied = state["applied"]
    require(state["version"] == 1 and state["confirmed_applications"] == 1 and state["completed_polls"] > before["state"]["completed_polls"]
            and applied["phase"] == "applied" and applied["decision_hex"] == raw.hex()
            and applied == observed["state"]["applied"] and state["latest"] == applied
            and before["owner"] == observed["owner"] and before["child"] == observed["child"]
            and before["agent"] == observed["agent"] and before["namespace"] == observed["namespace"]
            and value["exit_status"] == 0 and value["owner_ended"] is True and value["child_ended"] is True,
            "follower did not retain one original automatic application and complete cleanup")
    for snapshot in (before, observed, value):
        require(strict_json(bytes.fromhex(snapshot["files"]["state.json"])) == snapshot["state"]
                and strict_json(bytes.fromhex(snapshot["files"]["status.json"])) == snapshot["status"]
                and snapshot["status"]["state_sha256"] == sha(bytes.fromhex(snapshot["files"]["state.json"]))
                and snapshot["files"]["enrollment.json"] == before["files"]["enrollment.json"]
                and strict_json(bytes.fromhex(snapshot["files"]["enrollment.json"])) == snapshot["enrollment"],
                "follower observations do not bind original stable checkpoints")
        require(snapshot["status"]["version"] == 1 and snapshot["status"]["scope"] == "selected_channel_exact_object"
                and snapshot["status"]["completed_polls"] == snapshot["state"]["completed_polls"]
                and snapshot["status"]["confirmed_applications"] == snapshot["state"]["confirmed_applications"]
                and snapshot["status"]["last_poll"] == snapshot["state"]["last_poll"]
                and snapshot["status"]["applied"] == (snapshot["state"]["applied"] is not None),
                "follower status invented a completed poll or application")
    native_raw = bytes.fromhex(applied["manifest_hex"])
    native = object_fields(native_raw, 64 * 1024)
    native_body = object_fields(native[1], 64 * 1024)
    payload = object_fields(native_body[8], 64 * 1024)
    node = layout["provider_nodes"][0]
    publisher = layout["provider_keys"][node]
    require(native_body[1] == native_body[6] == 1 and native_body[2].hex() == publisher
            and native_body[7] == hashlib.sha256(native_body[8]).digest()
            and before["observed_at_ms"] // 1000 <= native_body[3] < native_body[4] == body[13] // 1000
            and body[12] <= before["observed_at_ms"] <= applied["observed_at_ms"] <= observed["observed_at_ms"] < body[13]
            and payload == {1: b"disposable-follow-policy", 2: 1,
                3: b"application/vnd.volparossa.object-policy.v1", 4: len(raw),
                5: protobuf_value(1, hashlib.sha256(raw).digest()) + protobuf_value(2, len(raw)),
                6: hashlib.sha256(raw).digest()}, "peer wrapper changed content, publisher or original expiry")
    verify_signature(native[1], native[2], native_body[2], b"VOLPAROSSA/native-content-manifest/v1\0")
    publication, contribution = value["publication"], value["contribution"]
    work = Path(publication["manifest"]).parents[3]
    scope = result["decision"]["scope"]
    require(value["enrollment"] == dict(version=1, scope="selected_channel_exact_object",
        policy_config=str(work / "config-client.yaml"),
        feed=dict(publisher_key=publisher, name="disposable-follow-policy", min_revision=1),
        subject=dict(publisher_key=scope["source_publisher_key"], manifest_id=scope["source_manifest_id"],
                     object_sha256=scope["source_sha256"]), framework_sha256=scope["framework_sha256"],
        cache=str(work / "state-client/compute-source/policy-object-follow-cache"), poll_seconds=1,
        limits=dict(quota_bytes=16777216, max_entries=64, min_free_bytes=268435456)),
        "follower did not enroll the exact independent subject, framework, channel and local policy")
    require(applied["apply_receipt"] == dict(version=1, manifest_id=list(body[7]), decision_hash=list(envelope[2]),
            decision_revision=body[5], policy_hash=list(body[3]), outcome=body[11]),
            "automatic acknowledgement did not apply the original exact-object quorum")
    require(value["publication_files"]["decision.bin"] == raw.hex()
            and value["publication_files"]["publication.manifest"] == applied["manifest_hex"]
            and strict_json(bytes.fromhex(value["publication_files"]["publication.json"])) ==
                dict(manifest_id=sha(native_raw), manifest_sha256=sha(native_raw), created=native_body[3], expires=native_body[4])
            and publication["operation"] == "compute_policy_publish" and publication["network_publication"] is False
            and publication["local_object_policy_applied"] is False and publication["decision_sha256"] == sha(raw)
            and publication["decision_hash"] == envelope[2].hex() and publication["publisher_key"] == publisher
            and publication["manifest_id"] == sha(native_raw) and publication["expires_at_ms"] == body[13]
            and contribution["operation"] == "content_contribute" and contribution["serving"] is True
            and contribution["network_publication"] is True and contribution["original_signature_reused"] is True
            and contribution["private_keys_transferred"] is False and contribution["manifest_id"] == sha(native_raw)
            and contribution["publisher_key_hex"] == publisher and contribution["name"] == "disposable-follow-policy"
            and contribution["revision"] == 1 and contribution["bytes"] == len(raw)
            and contribution["expires_unix_seconds"] == native_body[4], "missing actual independent named publication")
    download = applied["download_receipt"]
    require(download["operation"] == "named_content_download" and download["cache_only"] is False
            and download["publisher_key"] == publisher and download["name"] == "disposable-follow-policy"
            and download["revision"] == 1 and download["manifest_id"] == sha(native_raw)
            and download["sha256"] == sha(raw) and download["bytes"] == download["peer_bytes"] == len(raw)
            and download["providers_used"] == 1 and download["provider_peer_ids"] == [peers[node]]
            and download["control_relay_peer_id"] == layout["control_relay_peer_id"]
            and download["origin_body_bytes"] == download["origin_range_requests"] == 0,
            "automatic intake did not actually receive the exact decision from the protected peer")
    summary = value["summary"]
    require(summary["operation"] == "compute_policy_follow" and summary["stopped"] is True
            and summary["model_execution"] is False and summary["network_policy_activation"] is False
            and summary["status"] == value["status"], "follower terminal summary does not bind the original stopped state")


def check_object_peer_probe(probe, phase, outcome, subject, manifest_id):
    require(probe["phase"] == phase and type(probe["exit_code"]) is int and probe["agent"]["pid"] > 0,
            "missing actual receiver export probe")
    allowed = phase == "before" or outcome == "allow"
    raw, error = bytes.fromhex(probe["stdout_hex"]), bytes.fromhex(probe["stderr_hex"])
    if allowed:
        receipt, assembled = strict_json(raw), probe["assemble"]
        require(probe["exit_code"] == 0 and probe["cache_exists"] is True
                and probe["output_bytes"] == len(subject) and probe["output_sha256"] == sha(subject)
                and receipt["operation"] == "content_export" and receipt["manifest_id"] == manifest_id
                and receipt["complete"] is True and receipt["network_transfer"] is False
                and receipt["public_content"] is True and receipt["content_bytes"] == len(subject)
                and receipt["ownership_changed"] is False and receipt["private_keys_transferred"] is False
                and assembled["operation"] == "offline_content_assemble" and assembled["network_retrieval"] is False
                and assembled["bytes"] == len(subject), "receiver did not export/assemble the exact cached object")
    else:
        require(probe["exit_code"] == 1 and raw == b"" and probe["cache_exists"] is False
                and probe["output_bytes"] is None and probe["output_sha256"] is None and probe["assemble"] is None
                and error.splitlines() and error.splitlines()[-1].strip() == b"agent rejected request: CONTENT_POLICY (Policy)",
                "receiver did not refuse before creating the output cache")


def object_peer_probe(work, phase, status):
    JOBS["guest_work"](work)
    require(phase in ("before", "applied", "restarted"), "unknown receiver probe")
    node, root, owner, agent, namespace = object_peer_context(work)
    output = root / f"output-{phase}.txt"
    raw = public_file(output, owner) if output.exists() else None
    value = dict(node=node, phase=phase, exit_code=status, agent=agent, namespace=namespace,
        observed_at_ms=time.time_ns() // 1000000,
        stdout_hex=record(work, "remote-object-" + phase).read_bytes().hex(),
        stderr_hex=(work / f"{NAME}-remote-object-{phase}.err").read_bytes().hex(),
        cache_exists=os.path.lexists(root / f"cache-{phase}"),
        output_bytes=len(raw) if raw is not None else None, output_sha256=sha(raw) if raw is not None else None,
        assemble=read(record(work, f"remote-object-{phase}-assemble")) if status == 0 else None)
    result = read(record(work, "result"))["decision"]
    write(record(work, "remote-object-probe-" + phase), value)
    check_object_peer_probe(value, phase, result["outcome"], SUBJECT.encode(), result["scope"]["source_manifest_id"])


def object_peer_collect(work, phase):
    JOBS["guest_work"](work)
    require(phase in ("before", "after"), "unknown receiver collection phase")
    node, root, owner, agent, namespace = object_peer_context(work)
    imported = root / "import"
    require(set(path.name for path in imported.iterdir()) == {".task.lock", "selection.json", "decision.bin", "apply-receipt.json"},
            "unexpected import files or model work")
    originals = dict(files={name: public_file(imported / name, owner).hex()
                           for name in ("selection.json", "decision.bin", "apply-receipt.json")},
        journal_hex=public_file(root.parent / "object-policy/journal.json", owner).hex(),
        custody_directory=[(root.parent / "custody-cache").stat().st_dev, (root.parent / "custody-cache").stat().st_ino],
        import_report=read(record(work, "remote-object-import")))
    write(record(work, "remote-object-originals-" + phase), originals)
    if phase == "after":
        require(originals == read(record(work, "remote-object-originals-before")), "receiver restart rewrote original authority")
        probes = {name: read(record(work, "remote-object-probe-" + name)) for name in ("before", "applied", "restarted")}
        require(not JOBS["alive"](probes["applied"]["agent"]) and JOBS["alive"](agent)
                and agent == probes["restarted"]["agent"], "receiver agent did not actually restart")
        require(snapshot(root_path(work)) == read(record(work, "files"), 32 * 1048576), "remote import added/changed original jobs")
        proof = dict(originals=originals, probes=probes, received=read(record(work, "remote-object-received")),
            original_model_files_unchanged=True, new_jobs=0, original_decision_unchanged_after_restart=True,
            old_agent_ended=True, new_agent_alive=True, node=node, namespace=namespace)
        check_object_peer(proof, read(record(work, "object-activation")), read(record(work, "result")),
            read(work / "agent-jobs-layout.json"), read(work / "a01-expected-peers.json"))
        write(record(work, "remote-object-proof"), proof)


def check_object_peer(value, local, result, layout, peers):
    received, before, originals = value["received"], value["received"]["before"], value["originals"]
    raw = decode_file(local["originals"]["files"], "policy-object-combined/decision.bin", False)
    envelope = object_fields(raw, 8192, (3,))
    body = object_fields(envelope[1], 1024)
    node = layout["provider_nodes"][0]
    require(node != "client" and value["node"] == received["node"] == before["node"] == node
            and received["decision_hex"] == originals["files"]["decision.bin"] == raw.hex()
            and before["decision_chunk_absent"] is True and before["local_decision_absent"] is True
            and before["metadata_only"] is True and sha(bytes.fromhex(before["subject_manifest_hex"])) == body[7].hex()
            and originals["custody_directory"] == before["custody_directory"]
            and strict_json(bytes.fromhex(before["journal_hex"])) == {"version": 1, "entries": []},
            "second node or exact cold original decision changed")
    pins = dict(subject_publisher_key=body[6].hex(), subject_manifest_id=body[7].hex(), subject_sha256=body[8].hex(),
                decision_hash=envelope[2].hex(), evidence_sha256=body[10].hex())
    require(received["pins"] == pins, "remote verification selection changed")
    wrapper = bytes.fromhex(before["manifest_hex"])
    native = object_fields(wrapper, 64 * 1024)
    native_body = object_fields(native[1], 64 * 1024)
    payload = object_fields(native_body[8], 64 * 1024)
    publication = received["publication"]
    require(set(native) == {1, 2} and set(native_body) == set(range(1, 9))
            and native_body[1] == native_body[6] == 1 and native_body[2].hex() == publication["publisher_key"]
            and body[12] // 1000 <= native_body[3] < native_body[4] == body[13] // 1000
            and native_body[7] == hashlib.sha256(native_body[8]).digest() and len(native_body[5]) == 32
            and payload == {1: publication["name"].encode(), 2: 1,
                3: b"application/vnd.volparossa.object-policy.v1", 4: len(raw),
                5: protobuf_value(1, hashlib.sha256(raw).digest()) + protobuf_value(2, len(raw)),
                6: hashlib.sha256(raw).digest()}, "wrapper changed bytes, MIME or original authority lease")
    require(native_body[2].hex() not in {item["public_key_hex"] for item in local["originals"]["trust"]["maintainers"]},
            "fixture accidentally used a policy authority as its content publisher")
    verify_signature(native[1], native[2], native_body[2], b"VOLPAROSSA/native-content-manifest/v1\0")
    require(publication["manifest_id"] == sha(wrapper) and publication["network_publication"] is False
            and publication["content_type"] == "application/vnd.volparossa.object-policy.v1"
            and publication["publication_expires_unix_seconds"] == native_body[4], "publication receipt differs")
    for report, operation, applied in ((publication, "compute_policy_publish", False),
                                      (originals["import_report"], "compute_policy_import", True)):
        expected = dict(operation=operation, complete=True, decision_sha256=sha(raw), decision_hash=envelope[2].hex(),
            evidence_sha256=body[10].hex(), subject=dict(publisher_key=body[6].hex(), manifest_id=body[7].hex(), object_sha256=body[8].hex()),
            policy_hash=body[3].hex(), policy_version=body[4], decision_revision=body[5], issued_at_ms=body[12], expires_at_ms=body[13],
            outcome=result["decision"]["outcome"], threshold_verified=True, network_policy_activation=False,
            local_object_policy_applied=applied, wrapper_publisher_is_policy_authority=False,
            provider_signed_claims_replayed=0, model_execution=False, semantic_correctness_proven=False)
        require(all(report.get(key) == item for key, item in expected.items()), "publication/import changed authority or claims")
    imported_selection = strict_json(bytes.fromhex(originals["files"]["selection.json"]))
    require(imported_selection == dict(version=1, policy_config=str(Path(publication["manifest"]).parents[3] / f"config-{node}.yaml"),
            decision_sha256=sha(raw), **pins), "import did not use receiver's own configuration/exact pins")
    require(originals["journal_hex"] == local["originals"]["journal_hex"]
            and strict_json(bytes.fromhex(originals["files"]["apply-receipt.json"]))
                == local["originals"]["follow"]["state"]["applied"]["apply_receipt"],
            "second node replaced original quorum/epoch/expiry")
    deposit = received["deposit"]
    require(deposit["operation"] == "content_custody_deposit" and deposit["complete"] is True
            and deposit["manifest_id"] == sha(wrapper) and deposit["publisher_key_hex"] == publication["publisher_key"]
            and deposit["object_bytes"] == len(raw) and deposit["original_expiry_unix_seconds"] == native_body[4]
            and deposit["requested_providers"] == deposit["confirmed_complete_providers"] == 1 and deposit["failed_providers"] == 0
            and deposit["direct_provider_dial"] is False and deposit["private_keys_transferred"] is False
            and len(deposit["observations"]) == 1, "original quorum wrapper was not actually deposited at one peer")
    observation = deposit["observations"][0]
    provider = layout["provider_keys"][node]
    require(provider == CUSTODY["peer_key"](peers[node]) and observation["provider_key_hex"] == provider
            and observation["agent_handoff_complete"] is True and observation["state"] == "complete" and observation["error"] is None,
            "wrong or incomplete remote custody owner")
    custody = object_fields(bytes.fromhex(observation["signed_receipt_hex"]), 2048)
    custody_body = object_fields(custody[1], 2048)
    claim = object_fields(custody_body[8], 1024)
    require(set(custody) == {1, 2} and custody_body[1] == 1 and custody_body[2].hex() == provider
            and custody_body[6] == 3 and custody_body[7] == hashlib.sha256(custody_body[8]).digest()
            and 0 < custody_body[4] - custody_body[3] <= 900 and custody_body[4] <= native_body[4]
            and claim.get(5, 1) == 1 and claim.get(6) == 2 and claim[3].hex() == provider
            and claim[4] == native_body[2] and claim[7] == hashlib.sha256(wrapper).digest()
            and claim[8] == hashlib.sha256(raw).digest() and claim[9] == len(raw) and claim[10] == 1 and claim[11] == native_body[4],
            "signed receiver receipt changed object/provider/original expiry")
    verify_signature(custody[1], custody[2], custody_body[2], b"VOLPAROSSA/public-custody/v1\0")
    exported, assembled = received["export"], received["assemble"]
    require(exported["operation"] == "content_export" and exported["manifest_id"] == sha(wrapper)
            and exported["content_bytes"] == assembled["bytes"] == len(raw) and exported["complete"] is True
            and exported["network_transfer"] is False and exported["public_content"] is True
            and assembled["operation"] == "offline_content_assemble" and assembled["network_retrieval"] is False,
            "receiver did not get original decision from its own actual custody export")
    probes = value["probes"]
    for phase in ("before", "applied", "restarted"):
        check_object_peer_probe(probes[phase], phase, result["decision"]["outcome"], SUBJECT.encode(), body[7].hex())
        require(probes[phase]["node"] == node and probes[phase]["namespace"] == value["namespace"]
                and body[12] <= probes[phase]["observed_at_ms"] < body[13], "receiver proof ran outside original authority")
    require(before["agent"] == received["agent"] == probes["before"]["agent"] == probes["applied"]["agent"]
            != probes["restarted"]["agent"] and before["namespace"] == received["namespace"] == value["namespace"]
            and before["observed_at_ms"] <= received["observed_at_ms"] <= probes["before"]["observed_at_ms"]
            and probes["before"]["observed_at_ms"] <= probes["applied"]["observed_at_ms"] <= probes["restarted"]["observed_at_ms"]
            and value["old_agent_ended"] is True and value["new_agent_alive"] is True
            and value["original_decision_unchanged_after_restart"] is True
            and value["original_model_files_unchanged"] is received["original_model_files_unchanged"] is True
            and value["new_jobs"] == received["new_jobs"] == 0, "second-node restart changed evidence or reran models")


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
    check_object_activation(value["object_activation"], result, value["transfer"], files)
    follow = value["object_activation"]["originals"]["follow"]
    check_object_follow(follow, decode_file(value["object_activation"]["originals"]["files"],
                        "policy-object-combined/decision.bin", False), result, value["layout"], value["peers"])
    check_object_peer(value["object_peer"], value["object_activation"], result, value["layout"], value["peers"])
    response_bytes[value["layout"]["provider_nodes"][0]] += value["transfer"]["download"]["peer_bytes"]
    response_bytes[value["layout"]["provider_nodes"][0]] += follow["state"]["applied"]["download_receipt"]["peer_bytes"]
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
        object_activation=read(record(work, "object-activation"), 8 * 1048576),
        object_peer=read(record(work, "remote-object-proof"), 8 * 1048576),
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
        local_object_policy_applied=proof is not None,
        automatic_named_policy_follow_applied=proof is not None,
        second_node_object_policy_applied=proof is not None,
        object_outcome=proof["result"]["decision"]["outcome"] if proof is not None else None,
        object_access_branch=("allow_exact_cached_access" if proof["result"]["decision"]["outcome"] == "allow"
                              else "withhold_exact_cached_object") if proof is not None else None,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining), host_state=host)
    write(record(work, "smoke"), value)


def check_report(value, revision):
    require(value["report_kind"] == NAME and value["source_revision"] == revision and value["scope"] == SCOPE
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["full_b06_claimed"] is False and value["network_policy_activation_claimed"] is False
            and value["local_object_policy_applied"] is True
            and value["automatic_named_policy_follow_applied"] is True
            and value["second_node_object_policy_applied"] is True
            and value["object_outcome"] == value["evidence"]["result"]["decision"]["outcome"]
            and value["object_access_branch"] == ("allow_exact_cached_access" if value["object_outcome"] == "allow"
                                                 else "withhold_exact_cached_object"),
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

    # Inert numeric/byte controls only; no synthetic outcome is submitted to agents.
    field = protobuf_value
    repeated = field(1, b"a") + field(3, b"b") + field(3, b"c")
    require(object_fields(repeated, 128, (3,)) == {1: b"a", 3: [b"b", b"c"]}, "repeated proof parser differs")
    rejects(object_fields, repeated, 128)
    rejects(object_fields, field(3, b"a") + field(1, b"b"), 128, (3,))
    rejects(object_fields, b"\x08\x81\x00", 128)
    key = bytes.fromhex("11" * 32)
    signer_id = hashlib.sha256(b"volparossa/whitelist-maintainer/id/v1\0" + key).digest()
    unsigned = field(1, b"body") + field(2, hashlib.sha256(b"body").digest())
    signature = field(1, signer_id) + field(2, b"s" * 64)
    with patch.dict(globals(), {"verify_signature": lambda *_: None}):
        object_envelope(unsigned, {signer_id: key}, 0)
        object_envelope(unsigned + field(3, signature), {signer_id: key}, 1)
        rejects(object_envelope, unsigned + field(3, signature), {signer_id: key}, 3)
        rejects(object_envelope, unsigned + field(3, signature) * 2, {signer_id: key}, 2)
        rejects(object_envelope, unsigned + field(3, signature), {}, 1)
        rejects(object_envelope, field(1, b"changed") + field(2, hashlib.sha256(b"body").digest()), {}, 0)
    # Header-only regression for the actual protocol-2 development epoch; not a signature proof.
    epoch_header = {number: 1 for number in range(1, 10)}
    epoch_header.update({3: 2, 7: 3})
    epoch_signers = {b"a", b"b", b"c"}
    check_fixture_epoch_header(epoch_header, epoch_signers, epoch_signers)
    rejects(check_fixture_epoch_header, {**epoch_header, 3: 1}, epoch_signers, epoch_signers)
    rejects(check_fixture_epoch_header, {**epoch_header, 7: 2}, epoch_signers, epoch_signers)
    rejects(check_fixture_epoch_header, epoch_header, {b"a", b"b"}, epoch_signers)

    # Counter/presence proofs only: no synthetic decision is ever sent to an agent.
    cold = dict(state=dict(version=1, completed_polls=1, confirmed_applications=0,
        last_poll=dict(completed_at_ms=10, outcome="fetch_failed"), latest=None, applied=None),
        observed_at_ms=11, provider_publication_absent=True, cache_payload_absent=True,
        journal_hex=b'{"version":1,"entries":[]}'.hex())
    check_follow_cold(cold)
    for changed in (
        {**cold, "state": {**cold["state"], "completed_polls": 0}},
        {**cold, "state": {**cold["state"], "confirmed_applications": 1}},
        {**cold, "provider_publication_absent": False},
        {**cold, "cache_payload_absent": False},
        {**cold, "journal_hex": b'{"version":1,"entries":[{}]}'.hex()},
    ):
        rejects(check_follow_cold, changed)

    scope = {"source_manifest_id": "21" * 32, "source_publisher_key": "22" * 32,
             "source_sha256": sha(SUBJECT.encode()), "source_bytes": len(SUBJECT.encode())}
    cached = {"operation": "named_content_download", "cache_only": True, "manifest_id": scope["source_manifest_id"],
              "publisher_key": scope["source_publisher_key"], "sha256": scope["source_sha256"],
              "bytes": scope["source_bytes"], "peer_bytes": 0, "providers_used": 0, "origin_body_bytes": 0}
    good = {"phase": "applied", "exit_code": 0, "observed_at_ms": 10, "agent": {"pid": 123},
            "stdout_hex": json.dumps(cached).encode().hex(), "stderr_hex": "",
            "output_bytes": len(SUBJECT.encode()), "output_sha256": sha(SUBJECT.encode())}
    blocked = {**good, "exit_code": 1, "stdout_hex": "", "output_bytes": None, "output_sha256": None,
               "stderr_hex": b"Error: agent rejected request: CONTENT_POLICY (Policy)\n".hex()}
    for outcome in ("allow", "deny", "undetermined"):
        result = {"decision": {"outcome": outcome, "scope": scope}}
        expected, incorrect = (good, blocked) if outcome == "allow" else (blocked, good)
        check_object_probe(expected, "applied", result)
        rejects(check_object_probe, incorrect, "applied", result)
        check_object_probe({**good, "phase": "before"}, "before", result)
    rejects(check_object_probe, {**blocked, "stderr_hex": b"Error: CONTENT_UNAVAILABLE".hex()}, "applied",
            {"decision": {"outcome": "deny", "scope": scope}})

    remote_receipt = dict(operation="content_export", manifest_id=scope["source_manifest_id"], complete=True,
        network_transfer=False, public_content=True, content_bytes=len(SUBJECT.encode()), ownership_changed=False,
        private_keys_transferred=False)
    remote_good = dict(phase="applied", exit_code=0, agent={"pid": 2}, cache_exists=True,
        stdout_hex=json.dumps(remote_receipt).encode().hex(), stderr_hex="", output_bytes=len(SUBJECT.encode()),
        output_sha256=sha(SUBJECT.encode()), assemble=dict(operation="offline_content_assemble",
        network_retrieval=False, bytes=len(SUBJECT.encode())))
    remote_blocked = dict(remote_good, exit_code=1, cache_exists=False, stdout_hex="",
        stderr_hex=b"Error: content handoff failed\n\nCaused by:\n    agent rejected request: CONTENT_POLICY (Policy)\n".hex(),
        output_bytes=None, output_sha256=None, assemble=None)
    for outcome in ("allow", "deny", "undetermined"):
        check_object_peer_probe(remote_good if outcome == "allow" else remote_blocked, "applied", outcome,
                                SUBJECT.encode(), scope["source_manifest_id"])
    for bad, outcome in ((dict(remote_good, output_sha256="00" * 32), "allow"),
                         (dict(remote_blocked, cache_exists=True), "deny"),
                         (dict(remote_blocked, stderr_hex=b"Error: CONTENT_UNAVAILABLE".hex()), "undetermined"),
                         (remote_good, "deny")):
        rejects(check_object_peer_probe, bad, "applied", outcome, SUBJECT.encode(), scope["source_manifest_id"])

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
        full = deepcopy(expected)
        full["reasoning"] = [{"principle": principle, "quote": SUBJECT.strip(), "reason": "r" * 192}
                             for principle in ("Mansuetudo", "Liberalitas", "Temperantia")]
        full["counterargument"] = "c" * 192
        full["uncertainty"] = {"material": True, "reason": "u" * 192}
        full_text = json.dumps(full, separators=(",", ":"))
        require(1024 < len(full_text.encode()) <= MAX_OUTPUT_BYTES, "expanded output fixture missed raw boundary")
        for raw_text in (full_text, full_text + " " * (MAX_OUTPUT_BYTES - len(full_text.encode()))):
            full_assertion = {"review" if stage.startswith("review-") else "assessment": full,
                              "output_sha256": sha(raw_text.encode())}
            check_output({**output, "text": raw_text}, stage, full_assertion)
        too_long = full_text + " " * (MAX_OUTPUT_BYTES + 1 - len(full_text.encode()))
        rejects(check_output, {**output, "text": too_long}, stage,
                {**full_assertion, "output_sha256": sha(too_long.encode())})
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
    elif len(args) == 2 and args[0] in ("prepare", "collect", "stopped", "replay", "bundle_before", "transfer",
                                       "object_peer_pins", "object_peer_before", "object_peer_received"):
        globals()[args[0]](Path(args[1]))
    elif len(args) == 3 and args[0] == "observe":
        observe(Path(args[1]), int(args[2]))
    elif len(args) == 4 and args[0] == "object_probe":
        object_probe(Path(args[1]), args[2], int(args[3]))
    elif len(args) == 3 and args[0] == "object_collect":
        object_collect(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] in ("object_follow_before", "object_follow_applied"):
        globals()[args[0]](Path(args[1]), int(args[2]))
    elif len(args) == 4 and args[0] == "object_follow_collect":
        object_follow_collect(Path(args[1]), int(args[2]), int(args[3]))
    elif len(args) == 4 and args[0] == "object_peer_probe":
        object_peer_probe(Path(args[1]), args[2], int(args[3]))
    elif len(args) == 3 and args[0] == "object_peer_collect":
        object_peer_collect(Path(args[1]), args[2])
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
