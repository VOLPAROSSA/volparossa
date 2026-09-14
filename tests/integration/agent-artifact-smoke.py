#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual distinct-node training, protected artifact transfer and received-weight reuse."""

import base64
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys


HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / "agent-training-smoke.py"))
CUSTODY = runpy.run_path(str(HERE / "content-custody-smoke.py"))
read, require = TRAIN["read"], TRAIN["require"]
file_hash, write = TRAIN["file_hash"], TRAIN["write"]
SCOPE = ("one producer node trains and publishes; a distinct Client retrieves the signed adapter/dataset over protected MPTCP and explicitly reuses received weights; "
         "one common explicitly provisioned readonly base/runtime, not distributed optimization, base-model distribution or model quality")
CYCLE_SCOPE = ("the complete distinct-node adapter transfer followed by one explicitly selected public training cycle on the receiving Client after provider stop; "
               "verified cached dataset and readonly received adapter, eight real warmstart updates and a new local bundle; "
               "not automatic training/publication, globally latest data, distributed optimization or model quality")
DATASET_TYPE = "application/vnd.volparossa.agent-dataset.v1+json"
ADAPTER_TYPE = "application/vnd.volparossa.adapter.v1"
SOURCE_NAMES = ("train", "dataset.json", "dataset-cache", "adapter-cache", "bundle.bin", "identity.key",
                "passphrase", "dataset.pb", "adapter.pb")


def private_root(path, missing=False):
    root = Path(path)
    require(root.is_absolute() and root.name == "agent-artifact-user", "wrong private artifact fixture root")
    if missing and not root.exists():
        return root
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
            "artifact fixture root is not current-user private")
    return root


def dataset(revision, source_text):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "invalid revision")
    context = "Every parallel path uses exactly one distinct relay between the same client and exit."
    context2 = "The normal client dataplane never connects directly to an exit."
    require(context in source_text.replace("\n", " ")
            and context2.lower() in source_text.replace("\n", " ").lower(), "fixture public source changed")
    return {"version": 1, "visibility": "public", "license": "GPL-3.0-only", "source_revision": revision,
            "train": [{"question": "How many relays does one parallel path use?", "answer": "Exactly one distinct relay.", "context": context},
                      {"question": "May the normal client dataplane connect directly to an exit?", "answer": "No.", "context": context2}],
            "heldout": [{"question": "Is a direct client-to-exit dataplane connection normal?", "answer": "No.", "context": context2}],
            "inference": [{"question": "How many relays are in each parallel path?", "context": context}]}


def prepare(path, revision):
    root = private_root(path)
    require(not list(root.iterdir()), "artifact user directory not empty")
    write(root / "dataset.json", dataset(revision, (HERE / "agent-artifact-README.md").read_text()))
    (root / "passphrase").write_bytes(base64.b64encode(os.urandom(48)) + b"\n")
    (root / "private-canary").write_bytes(b"Public isolation canary, not a private key.\n")
    for name in ("passphrase", "private-canary"):
        (root / name).chmod(0o600)
    subprocess.run([sys.executable, "-B", str(HERE / "ml/provision.py"), "--execute", "--yes",
                    "--disposable-guest", "--root", str(root / "provision"), "--budget-bytes", str(3 * 1024 ** 3)],
                   check=True, timeout=1850)


def originals(path):
    root = private_root(path)
    return {"dataset": file_hash(root / "dataset.json", 1048576),
            "adapter_bundle": file_hash(root / "bundle.bin", 4 * 1024 ** 2),
            "dataset_manifest_id": file_hash(root / "dataset.pb", 65536)["sha256"],
            "adapter_manifest_id": file_hash(root / "adapter.pb", 65536)["sha256"],
            "adapter_files": {name: file_hash(root / "train/adapter" / name, 2 * 1024 ** 2)
                              for name in ("README.md", "adapter_config.json", "adapter_model.safetensors")}}


def received(path, name="received"):
    root = private_root(path)
    require(name in ("received", "reopened"), "unsupported receiver path")
    target = root / name
    require(set(x.name for x in target.iterdir()) == {"adapter", "dataset.json", "provenance.json"}, "unexpected received files")
    return {"dataset": file_hash(target / "dataset.json", 1048576),
            "adapter_files": {item: file_hash(target / "adapter" / item, 2 * 1024 ** 2)
                              for item in ("README.md", "adapter_config.json", "adapter_model.safetensors")},
            "private_directory": stat.S_IMODE(target.stat().st_mode) == 0o700,
            "provenance": read(target / "provenance.json"), "source_files_absent": all(not (root / x).exists() for x in SOURCE_NAMES)}


def drop_source(path):
    root = private_root(path)
    for name in SOURCE_NAMES:
        target = root / name
        require(target.exists() and not target.is_symlink(), "expected original training/publication input missing")
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    return {"trainer_inputs_removed": True, "trainer_adapter_removed": True,
            "publisher_cache_removed": True, "publisher_key_removed": True,
            "base_model_retained_explicitly": True, "publisher_node_offline_claimed": False}


def cleanup(path):
    root = private_root(path, missing=True)
    ended = True
    if root.exists():
        for label in ("training", "inference", "cycle"):
            evidence = root / f"{label}-isolation.json"
            if evidence.is_file():
                ended &= not any(TRAIN["alive"](member) for member in read(evidence)["owned_processes"])
        require(ended, "observed compute process still alive")
        shutil.rmtree(root)
    return {"user_root_removed": not root.exists(), "model_runtime_removed": True,
            "originals_and_received_outputs_removed": True, "observed_compute_lifetimes_ended": ended}


def observe(pid, output, provision, source, canary, label, node, namespace, service_pid):
    require(label in ("training", "inference", "cycle"), "invalid observation label")
    require(node in ("client", "relay3", "relay4", "relay5"), "invalid logical compute node")
    cli_namespace = os.readlink(f"/proc/{pid}/ns/net")
    service_namespace = os.readlink(f"/proc/{service_pid}/ns/net")
    expected = namespace.stat()
    actual = Path(f"/proc/{pid}/ns/net").stat()
    require((expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)
            and cli_namespace == service_namespace, "compute CLI is not in the claimed node namespace")
    service = TRAIN["identity"](service_pid)
    executable = Path(os.readlink(f"/proc/{service_pid}/exe")).name
    require(executable == "volparossa-agent", "wrong actual node service")
    lineage = {"node": node, "cli_namespace": cli_namespace, "service_namespace": service_namespace,
               "network_namespace": cli_namespace, "service": service, "service_executable": executable}
    temporary = output.with_name(output.name + ".pending")
    TRAIN["observe"](pid, temporary, provision, source, canary)
    evidence = read(temporary)
    require(TRAIN["identity"](service_pid) == service, "node service changed during observation")
    evidence["node_lineage"] = lineage
    if label in ("inference", "cycle"):
        worker = Path(f"/proc/{evidence['worker']['pid']}")
        require(TRAIN["identity"](evidence["worker"]["pid"]) == evidence["worker"], "worker identity changed")
        options = [line.split()[5].split(",") for line in (worker / "mountinfo").read_text().splitlines()
                   if line.split()[4] == "/adapter"]
        require(len(options) == 1 and "ro" in options[0], "actual received adapter mount is not readonly")
        checks = {}
        adapter = source.parent / "adapter" if label == "inference" else source.parent.parent / "received/adapter"
        for name in ("README.md", "adapter_config.json", "adapter_model.safetensors"):
            mounted, actual = (worker / "root/adapter" / name).stat(), (adapter / name).stat()
            checks[name] = (mounted.st_dev, mounted.st_ino) == (actual.st_dev, actual.st_ino)
        require(all(checks.values()), "worker used an adapter other than the received files")
        evidence["received_adapter_readonly"] = True
        evidence["received_adapter_exact_inodes"] = checks
    write(output, evidence)
    owner = temporary.stat()
    os.chown(output, owner.st_uid, owner.st_gid)
    temporary.unlink()


def check_training(work, revision):
    training = read(work / "agent-artifact-training.json")
    TRAIN["check_worker"](training, revision)
    TRAIN["check_isolation"](read(work / "agent-artifact-training-isolation.json"))
    require(training["dataset"]["sha256"] == file_hash(work / "agent-artifact-original-dataset.json", 1048576)["sha256"],
            "actual training dataset bytes differ")


def check_lineage(train_owner, infer_owner, producer, restart):
    require(train_owner["node"] == producer and infer_owner["node"] == "client"
            and train_owner["network_namespace"] != infer_owner["network_namespace"]
            and train_owner["service"]["pid"] == restart["pid_before"]
            and train_owner["service"]["pid"] != infer_owner["service"]["pid"],
            "training and inference did not belong to distinct live fixture nodes")
    for owner in (train_owner, infer_owner):
        require(owner["cli_namespace"] == owner["service_namespace"] == owner["network_namespace"]
                and owner["service_executable"] == "volparossa-agent",
                "compute CLI did not execute inside its claimed real service namespace")


def check_control_binding(layout, peers, fetch, binding):
    probe = binding["producer_layout"]
    owner = layout["control_relay_peer_id"]
    nodes = layout["provider_nodes"]
    require(all(probe[key] == layout[key] for key in ("provider_nodes", "producer_node", "consumer_node", "provider_keys"))
            and probe["control_relay_peer_id"] == binding["probe_status"]["control_relay_peer_id"]
            and owner == binding["fetch_status"]["control_relay_peer_id"]
            and owner in {peers[node] for node in ("relay0", "relay1", "relay2")}
            and owner not in {peers[node] for node in nodes}
            and all(re.fullmatch(r"[0-9a-f]{32}", item["route_context_id"]) for item in (probe, layout))
            and probe["route_context_id"] != layout["route_context_id"],
            "fresh control selection changed producer identity or reused the disconnected probe")
    require(all(fetch[kind + "_receipt"]["control_relay_peer_id"] == owner for kind in ("adapter", "dataset")),
            "artifact objects were fetched through a different control owner")
    addresses = CUSTODY["SHARED"]["PUBLIC_IPS"]
    control = next(node for node in ("relay0", "relay1", "relay2") if peers[node] == owner)
    routes = binding["routes"]
    require(set(routes) == set(nodes), "actual control route coverage incomplete")
    for index, node in enumerate(nodes):
        for direction, device, gateway, source, destination in (
                ("out", f"cp{index}", f"10.241.{80+index}.2", addresses[control], addresses[node]),
                ("back", f"pc{index}", f"10.241.{80+index}.1", addresses[node], addresses[control])):
            rows = routes[node][direction]
            require(isinstance(rows, list) and len(rows) == 1
                    and all(rows[0].get(key) == value for key, value in
                            dict(dev=device, gateway=gateway, prefsrc=source, dst=destination).items()),
                    "actual fresh-owner route differs from its exact filtered control link")


def check_evidence(evidence, revision):
    require(evidence["success"] is True and evidence["source_revision"] == revision, "incomplete adapter reuse")
    TRAIN["check_worker"](evidence["training"], revision)
    for label in ("training", "inference"):
        TRAIN["check_isolation"](evidence[label + "_isolation"])
    originals = evidence["originals"]
    training, infer = evidence["training"], evidence["inference"]
    require(originals["dataset"]["sha256"] == training["dataset"]["sha256"], "training source was not published")
    require(evidence["pack"]["dataset_manifest_id"] == originals["dataset_manifest_id"]
            and evidence["pack"]["sha256"] == originals["adapter_bundle"]["sha256"]
            and evidence["pack"]["content_type"] == ADAPTER_TYPE, "packed artifact lacks exact dataset binding")
    publisher = evidence["dataset_publish"]["publisher_key_hex"]
    require(evidence["adapter_publish"]["publisher_key_hex"] == publisher, "publisher changed")
    layout, peers = evidence["layout"], evidence["peers"]
    nodes = layout["provider_nodes"]
    require(len(nodes) == len(set(nodes)) == 2 and set(layout["provider_keys"]) == set(nodes), "producer/control fixture identity set differs")
    require(len(set(layout["provider_keys"].values())) == 2
            and layout["control_relay_peer_id"] not in {peers[n] for n in nodes}
            and all(CUSTODY["peer_key"](peers[n]) == layout["provider_keys"][n] for n in nodes), "provider identity binding differs")
    check_control_binding(layout, peers, evidence["fetch"], evidence["control_binding"])
    producer = layout["producer_node"]
    require(producer in nodes and layout["consumer_node"] == "client" and producer != "client",
            "producer and consumer are not different logical nodes")
    restart = evidence["providers"][producer]["restart"]
    require(restart["same_cache"] is True and restart["pid_before"] != restart["pid_after"]
            and restart["pid_before"] > 0 and restart["pid_after"] > 0
            and restart["restored_publications"] == 2, "actual producer service restart/reopen missing")
    require(all(evidence["providers"][node]["stop"]["serving"] is False for node in nodes), "provider stop missing")
    unused = next(node for node in nodes if node != producer)
    require(evidence["providers"][unused]["empty"]["publications"] == 0
            and evidence["providers"][unused]["empty"]["replica_publications"] == 0, "unused provider is not empty")
    for count, (kind, source_key) in enumerate((("dataset", "dataset"), ("adapter", "adapter_bundle")), 1):
        publication = evidence[kind + "_publish"]
        require(publication["operation"] == "content_publish" and publication["network_publication"] is True
                and publication["serving"] is True and publication["publications"] == count
                and publication["bytes"] == originals[source_key]["bytes"]
                and publication["manifest_id"] == originals[kind + "_manifest_id"]
                and publication["private_keys_transferred"] is False and publication["origin_authenticated"] is False,
                "producer's own public contribution was not committed")
    train_owner, infer_owner = (evidence[label + "_isolation"]["node_lineage"] for label in ("training", "inference"))
    check_lineage(train_owner, infer_owner, producer, restart)
    require(all(evidence["source_removed"][x] is True for x in ("trainer_inputs_removed", "trainer_adapter_removed", "publisher_cache_removed", "publisher_key_removed")), "original trainer source survived")
    require(evidence["source_removed"]["base_model_retained_explicitly"] is True
            and evidence["source_removed"]["publisher_node_offline_claimed"] is False, "source removal scope overstated")
    require(evidence["content_isolation"] == dict(client_identity_positive_control=True,
                client_cannot_read_trainer=True, client_cannot_read_provider_stores=True,
                user_cannot_read_agent_cache=True, fresh_agent_cache=True), "local content shortcut not excluded")
    for label in ("fetch", "cache_only"):
        fetch = evidence[label]
        require(fetch["publisher"] == publisher and fetch["adapter_manifest_id"] == originals["adapter_manifest_id"]
                and fetch["dataset_manifest_id"] == originals["dataset_manifest_id"]
                and fetch["model_activated"] is False and fetch["remote_execution"] is False
                and fetch["cache_only"] is (label == "cache_only"), "received identities/activation differ")
        for kind in ("adapter", "dataset"):
            receipt = fetch[kind + "_receipt"]
            require(receipt["manifest_id"] == originals[kind + "_manifest_id"]
                    and receipt["publisher_key"] == publisher and receipt["origin_authenticated"] is False
                    and receipt["publication_expires_unix_seconds"] == evidence[kind + "_publish"]["expires_unix_seconds"]
                    and receipt["sha256"] == originals["adapter_bundle" if kind == "adapter" else kind]["sha256"]
                    and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0,
                    "named publisher-authenticated retrieval missing")
            if label == "fetch":
                require(receipt["peer_bytes"] == originals["adapter_bundle" if kind == "adapter" else kind]["bytes"]
                        and receipt["providers_used"] == 1 and receipt["provider_peer_ids"] == [peers[producer]],
                        "received object did not traverse protected provider streams")
            else:
                require(receipt["peer_bytes"] == 0 and receipt["providers_used"] == 0, "cache-only replay contacted a provider")
    for label in ("received", "reopened"):
        item = evidence[label]
        require(item["dataset"] == originals["dataset"] and item["adapter_files"] == originals["adapter_files"]
                and item["private_directory"] is True and item["source_files_absent"] is True, "received bytes came from wrong source")
    require(infer["status"] == "ok" and infer["mode"] == "infer" and infer["updates_completed"] == 0
            and infer["input_adapter"]["applied"] is True
            and infer["input_adapter"]["files"] == originals["adapter_files"]
            and infer["input_adapter"]["applied_parameters"] == training["adapter_after"]
            and infer["input_adapter"]["base_parameters_before_apply"] == infer["input_adapter"]["base_parameters_after_apply"] == training["base_after"],
            "received adapter was not actually applied to the unchanged base")
    require(infer["device"] == "cpu" and infer["threads"] == 2
            and infer["backend_versions"] == training["backend_versions"]
            and infer["model"] == training["model"] and infer["dataset"] == training["dataset"],
            "received inference used a different backend, base or public dataset")
    supervisor = infer["supervisor"]
    require(supervisor["sandbox"] == "bubblewrap-private-user-net-pid-ipc-mount"
            and supervisor["network_access"] is False and supervisor["gpu_access"] is False
            and supervisor["child_reaped"] is True
            and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"], "inference supervisor incomplete")
    require(math.isclose(infer["baseline_evaluation"]["loss"], training["reloaded_evaluation"]["loss"], rel_tol=1e-5, abs_tol=1e-6)
            and infer["outputs"] == training["outputs"] and len(infer["outputs"]) > 0,
            "actual reloaded adapter evaluation/inference differs")
    require(evidence["inference_isolation"]["received_adapter_readonly"] is True
            and all(evidence["inference_isolation"]["received_adapter_exact_inodes"].values()), "wrong actual inference mount")
    minimum = originals["adapter_bundle"]["bytes"] + originals["dataset"]["bytes"]
    for phase in ("fetch",):
        CUSTODY["validate_path"](evidence["phases"][phase], peers, layout, phase, payload_minimum=minimum)
    require(evidence["phases"]["fetch"]["gates"]["exit_mptcp_tls_completed"] >= 2,
            "both signed objects lack completed protected retrieval streams")
    require(all(evidence["cleanup"].values()), "private compute cleanup incomplete")


def build_evidence(work, revision):
    names = ("training", "training-isolation", "inference", "inference-isolation", "originals", "pack", "layout",
             "dataset-publish", "adapter-publish", "source-removed", "fetch",
             "received", "cache-only", "reopened", "private-cleanup", "provision", "content-isolation")
    evidence = {name.replace("-", "_"): read(work / f"agent-artifact-{name}.json") for name in names}
    evidence["cleanup"] = evidence.pop("private_cleanup")
    evidence.update(success=True, source_revision=revision, peers=read(work / "a01-expected-peers.json"))
    evidence["control_binding"] = {
        "producer_layout": read(work / "agent-artifact-producer-layout.json"),
        "probe_status": read(work / "agent-artifact-client-status.json"),
        "fetch_status": read(work / "agent-artifact-client-fetch-status.json"),
        "routes": {node: {direction: read(work / f"content-provider-control-{node}-{direction}.json")
                          for direction in ("out", "back")}
                   for node in evidence["layout"]["provider_nodes"]}}
    producer = evidence["layout"]["producer_node"]
    evidence["providers"] = {node: {
        "restart": read(work / f"agent-artifact-{node}-restart.json") if node == producer else None,
        "empty": read(work / f"content-custody-{node}-artifact-still-empty.json") if node != producer else None,
        "stop": read(work / f"agent-artifact-{node}-stop.json")}
        for node in evidence["layout"]["provider_nodes"]}
    evidence["phases"] = {name: {
        "selected_route": read(work / f"content-custody-{name}-live-selection.json"),
        "privacy": {role: read(work / f"content-custody-{name}-privacy-{role}.json") for role in CUSTODY["ROLES"]},
        "control_privacy": read(work / f"content-provider-custody-{name}-control.json"),
        "gates": read(work / f"content-custody-{name}-gates.json")}
        for name in ("fetch",)}
    check_evidence(evidence, revision)
    write(work / "agent-artifact-evidence.json", evidence)


def finalize(work, revision, status, complete, remaining, phase, blocker, cycle=False):
    name = "agent-train-cycle" if cycle else "agent-artifact"
    evidence = read(work / f"{name}-evidence.json") if (work / f"{name}-evidence.json").is_file() else None
    host = read(work / "a15-evidence.json") if (work / "a15-evidence.json").is_file() else {}
    report = {"report_kind": "volparossa-public-" + name, "source_revision": revision,
              "success": status == 0 and complete and remaining == 0 and host.get("unchanged") is True and evidence is not None,
              "phase": phase, "observed_blocker": None if blocker == "NONE" else blocker,
              "scope": CYCLE_SCOPE if cycle else SCOPE, "distributed_training_claimed": False, "base_model_distributed_claimed": False,
              "full_alpha_claimed": False, "evidence": evidence,
              "cleanup": {"complete": complete, "remaining_owned_objects": remaining}, "host_state": host}
    write(work / f"{name}-smoke.json", report)


def check_report(report, revision):
    cycle = report["report_kind"] == "volparossa-public-agent-train-cycle"
    require(report["report_kind"] == ("volparossa-public-agent-train-cycle" if cycle else "volparossa-public-agent-artifact")
            and report["source_revision"] == revision and report["success"] is True
            and report["scope"] == (CYCLE_SCOPE if cycle else SCOPE), "incomplete artifact report")
    require(report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"], "guest cleanup differs")
    require(all(report[k] is False for k in ("distributed_training_claimed", "base_model_distributed_claimed", "full_alpha_claimed")), "unsupported scope")
    check_evidence(report["evidence"], revision)
    if cycle:
        check_cycle(report["evidence"], revision)


def cycle_files(path):
    root = private_root(path)
    cycle = root / "cycle"
    training = read(cycle / "training-report.json")
    worker = read(cycle / "training/report.json")
    require(worker == {k: v for k, v in training.items() if k != "supervisor"}, "saved worker report differs")
    files = {name: file_hash(cycle / "training/adapter" / name, 2 * 1024 ** 2)
             for name in ("README.md", "adapter_config.json", "adapter_model.safetensors")}
    # Reconstruct the fixed canonical protobuf index from actual saved bytes. This
    # checks the produced local bundle without interpreting tensors or peer code.
    def varint(value):
        encoded = bytearray()
        while value > 127:
            encoded.append((value & 127) | 128)
            value >>= 7
        return bytes(encoded) + bytes([value])

    def integer(tag, value):
        return varint(tag << 3) + varint(value) if value else b""

    def blob(tag, value):
        return varint((tag << 3) | 2) + varint(len(value)) + value

    manifest = file_hash(cycle / "dataset.manifest", 65536)
    index = (integer(1, 1) + blob(2, training["model"]["id"].encode())
             + blob(3, training["model"]["revision"].encode()) + blob(4, bytes.fromhex(TRAIN["WEIGHT_HASH"]))
             + integer(5, 4) + integer(6, 8) + blob(7, b"q_proj") + blob(7, b"v_proj")
             + blob(8, bytes.fromhex(manifest["sha256"])))
    payload = b""
    for name, info in files.items():
        entry = (blob(1, name.encode()) + integer(2, len(payload)) + integer(3, info["bytes"])
                 + blob(4, bytes.fromhex(info["sha256"])))
        index += blob(9, entry)
        payload += (cycle / "training/adapter" / name).read_bytes()
    expected_bundle = len(index).to_bytes(4, "big") + index + payload
    bundle = file_hash(cycle / "adapter.bundle", 4 * 1024 ** 2)
    require(bundle == {"bytes": len(expected_bundle), "sha256": hashlib.sha256(expected_bundle).hexdigest()},
            "new adapter bundle is not the canonical actual files and exact dataset identity")
    return {"selection": read(cycle / "selection.json"), "provenance": read(cycle / "source-provenance.json"),
            "result": read(cycle / "result.json"), "dataset": file_hash(cycle / "dataset.json", 1048576),
            "manifest": manifest, "training_report": file_hash(cycle / "training-report.json", 65536),
            "bundle": bundle, "adapter_files": files, "canonical_bundle_matches_actual_files": True,
            "received_after": received(path), "private_directory": stat.S_IMODE(cycle.stat().st_mode) == 0o700,
            "original_sources_absent": all(not (root / name).exists() for name in SOURCE_NAMES)}


def check_cycle(evidence, revision):
    cycle = evidence["cycle"]
    result, files, trained, isolation = (cycle[name] for name in ("result", "files", "training", "isolation"))
    original, first = evidence["originals"], evidence["training"]
    TRAIN["check_worker"](trained, revision)
    TRAIN["check_isolation"](isolation)
    require(result == files["result"] and result["operation"] == "compute_train_cycle" and result["complete"] is True
            and result["updates_completed"] == 8 and result["input_adapter_applied"] is True, "cycle not completed")
    require(all(result[key] is False for key in ("network_published", "private_data_supported", "model_quality_proven",
                "autonomous_training", "model_activated_for_peer_jobs")), "unsupported training-cycle claim")
    selection, provenance, receipt = files["selection"], files["provenance"], result["source_receipt"]
    publisher, expiry = evidence["dataset_publish"]["publisher_key_hex"], evidence["dataset_publish"]["expires_unix_seconds"]
    require(selection["publisher_key"] == provenance["publisher_key"] == receipt["publisher_key"] == publisher
            and selection["dataset_name"] == provenance["dataset_name"] == receipt["name"] == "disposable-agent-dataset"
            and selection["minimum_revision"] == receipt["revision"] == 1
            and selection["expected_dataset_manifest_id"] == provenance["dataset_manifest_id"]
            == result["dataset_manifest_id"] == result["bundle"]["dataset_manifest_id"]
            == receipt["manifest_id"] == files["manifest"]["sha256"] == original["dataset_manifest_id"],
            "cycle selected a different signed source")
    require(provenance["signed_manifest_sha256"] == original["dataset_manifest_id"]
            and provenance["expires_unix_seconds"] == result["source_expires_unix_seconds"]
            == receipt["publication_expires_unix_seconds"] == result["bundle"]["dataset_expires"] == expiry
            and 0 < provenance["verified_at_unix_seconds"] < expiry, "cycle extended or lost original expiry")
    require(selection["prefer_cached"] is True and selection["cache_only"] is False and selection["reuse_cache"] is True
            and selection["cache_miss_selects_different_source"] is False and selection["automatic_source_discovery"] is False
            and selection["globally_latest_version_claimed"] is False, "wrong explicit cached-source policy")
    require(receipt == provenance["source_receipt"] and receipt["peer_bytes"] == receipt["providers_used"]
            == receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0
            and receipt["provider_peer_ids"] == [] and receipt["origin_authenticated"] is False
            and receipt["globally_latest"] is False, "cycle bypassed provider-stop cache proof")
    require(files["dataset"] == original["dataset"] and trained["dataset"] == first["dataset"]
            and result["dataset_sha256"] == provenance["dataset_sha256"] == receipt["sha256"] == original["dataset"]["sha256"]
            and receipt["bytes"] == provenance["dataset_bytes"] == original["dataset"]["bytes"], "cycle trained different bytes")
    require(trained["input_adapter"]["applied"] is True and trained["input_adapter"]["files"] == original["adapter_files"]
            and trained["input_adapter"]["applied_parameters"] == trained["adapter_before"] == first["adapter_after"]
            and result["input_adapter"] == trained["input_adapter"]
            and trained["base_before"] == first["base_after"], "cycle did not warmstart received weights on unchanged base")
    require(files["received_after"] == evidence["received"] and files["original_sources_absent"] is True
            and files["private_directory"] is True and files["canonical_bundle_matches_actual_files"] is True,
            "cycle changed inputs, used original source or lacks actual canonical output")
    require(result["training_report_sha256"] == files["training_report"]["sha256"]
            and result["bundle"]["sha256"] == files["bundle"]["sha256"]
            and result["bundle"]["bytes"] == files["bundle"]["bytes"]
            and files["bundle"]["sha256"] != original["adapter_bundle"]["sha256"]
            and result["bundle"]["content_type"] == ADAPTER_TYPE
            and result["bundle"]["network_published"] is False, "wrong new local artifact")
    actual = {item["relative_path"].removeprefix("adapter/"): {k: item[k] for k in ("bytes", "sha256")}
              for item in trained["artifacts"]}
    require(actual == files["adapter_files"] and actual["adapter_model.safetensors"]["sha256"]
            != original["adapter_files"]["adapter_model.safetensors"]["sha256"], "actual saved weights unchanged")
    require(isolation["node_lineage"] == evidence["inference_isolation"]["node_lineage"]
            and isolation["received_adapter_readonly"] is True
            and set(isolation["received_adapter_exact_inodes"]) == set(original["adapter_files"])
            and all(isolation["received_adapter_exact_inodes"].values()), "cycle ran outside receiver or used different writable adapter")


def build_cycle_evidence(work, revision):
    evidence = read(work / "agent-artifact-evidence.json")
    evidence["cycle"] = {name: read(work / f"agent-artifact-cycle-{name}.json")
                         for name in ("result", "files", "training", "isolation")}
    check_cycle(evidence, revision)
    write(work / "agent-train-cycle-evidence.json", evidence)


def cycle_self_test():
    # Synthetic checker inputs only. No backend, model or networking is executed.
    revision, digest = "a" * 40, "b" * 64
    identity = {"bytes": 10, "sha256": digest}
    old_files = {name: identity.copy() for name in ("README.md", "adapter_config.json", "adapter_model.safetensors")}
    new_files = copy.deepcopy(old_files)
    new_files["adapter_model.safetensors"]["sha256"] = "c" * 64
    base, previous, updated = ({"sha256": char * 64, "parameters": count}
                              for char, count in (("d", 134515008), ("e", 230400), ("f", 230400)))
    data = dict(source_revision=revision, visibility="public", license="GPL-3.0-only", training_examples=2, heldout_examples=1)
    trained = dict(status="ok", mode="train", device="cpu", threads=2, updates_completed=8, training_losses=[1.0] * 8,
        backend_versions=dict(torch="2.14.0+cpu", transformers="5.16.1", peft="0.20.0"),
        model=dict(id="HuggingFaceTB/SmolLM2-135M-Instruct", revision=TRAIN["MODEL_REVISION"],
                   files={"model.safetensors": {"bytes": 269060552, "sha256": TRAIN["WEIGHT_HASH"]}}), dataset=data,
        base_before=base, base_after=base, reloaded_base=base, adapter_before=previous, adapter_after=updated,
        reloaded_adapter=updated, base_weights_unchanged=True, adapter_weights_changed=True, checkpoint_reloaded=True,
        better_answers_claimed=False, distributed_training_claimed=False, network_policy_changed=False,
        artifacts=[dict(relative_path="adapter/" + name, **info) for name, info in new_files.items()],
        input_adapter=dict(applied=True, files=old_files, applied_parameters=previous),
        supervisor=dict(sandbox="bubblewrap-private-user-net-pid-ipc-mount", network_access=False,
                        gpu_access=False, child_reaped=True, max_observed_rss_bytes=1, rss_limit_bytes=2))
    for name in ("baseline_evaluation", "adapted_evaluation", "reloaded_evaluation"):
        trained[name] = dict(loss=1.0, target_tokens=1)
    receipt = dict(publisher_key=digest, name="disposable-agent-dataset", revision=1, manifest_id=digest,
        publication_expires_unix_seconds=100, peer_bytes=0, providers_used=0, origin_body_bytes=0,
        origin_range_requests=0, provider_peer_ids=[], origin_authenticated=False, globally_latest=False, **identity)
    selection = dict(publisher_key=digest, dataset_name=receipt["name"], minimum_revision=1,
        expected_dataset_manifest_id=digest, prefer_cached=True, cache_only=False, reuse_cache=True,
        cache_miss_selects_different_source=False, automatic_source_discovery=False, globally_latest_version_claimed=False)
    provenance = dict(publisher_key=digest, dataset_name=receipt["name"], dataset_manifest_id=digest,
        signed_manifest_sha256=digest, expires_unix_seconds=100, verified_at_unix_seconds=50,
        source_receipt=receipt, dataset_sha256=digest, dataset_bytes=10)
    bundle = dict(dataset_manifest_id=digest, dataset_expires=100, sha256="1" * 64, bytes=40,
                  content_type=ADAPTER_TYPE, network_published=False)
    result = dict(operation="compute_train_cycle", complete=True, updates_completed=8, input_adapter_applied=True,
        network_published=False, private_data_supported=False, model_quality_proven=False, autonomous_training=False,
        model_activated_for_peer_jobs=False, source_receipt=receipt, dataset_manifest_id=digest,
        source_expires_unix_seconds=100, dataset_sha256=digest, input_adapter=trained["input_adapter"],
        training_report_sha256=digest, bundle=bundle)
    files = dict(result=result, selection=selection, provenance=provenance, manifest=identity, dataset=identity,
        received_after={"fixture": True}, original_sources_absent=True, private_directory=True,
        canonical_bundle_matches_actual_files=True, training_report=identity,
        bundle={key: bundle[key] for key in ("sha256", "bytes")}, adapter_files=new_files)
    isolation = dict(observed=True, network_devices=["lo"], ipv4_routes=[], effective_capabilities=0,
        namespaces=dict.fromkeys(("net", "pid", "ipc", "mnt"), "isolated"),
        guest_namespaces=dict.fromkeys(("net", "pid", "ipc", "mnt"), "guest"),
        host_home_visible=False, outside_canary_visible=False, exact_input_inodes=dict.fromkeys("abc", True),
        mounts=dict.fromkeys(("/runtime", "/model", "/dataset.json"), ["ro"]),
        node_lineage={"node": "client"}, received_adapter_readonly=True,
        received_adapter_exact_inodes=dict.fromkeys(old_files, True))
    evidence = dict(cycle=dict(result=result, files=files, training=trained, isolation=isolation),
        originals=dict(dataset=identity, dataset_manifest_id=digest, adapter_files=old_files, adapter_bundle=identity),
        training=dict(dataset=data, adapter_after=previous, base_after=base),
        dataset_publish=dict(publisher_key_hex=digest, expires_unix_seconds=100),
        received=files["received_after"], inference_isolation=dict(node_lineage=isolation["node_lineage"]))
    check_cycle(evidence, revision)
    for path, value in (("result.dataset_manifest_id", "0" * 64), ("result.source_expires_unix_seconds", 101),
                        ("result.source_receipt.peer_bytes", 10), ("training.adapter_before", {"sha256": "0" * 64, "parameters": 230400}),
                        ("training.updates_completed", 0), ("files.canonical_bundle_matches_actual_files", False),
                        ("isolation.received_adapter_readonly", False), ("result.network_published", True)):
        bad = copy.deepcopy(evidence)
        target = bad["cycle"]
        fields = path.split(".")
        for field in fields[:-1]:
            target = target[field]
        target[fields[-1]] = value
        try:
            check_cycle(bad, revision)
        except ValueError:
            continue
        raise AssertionError("invalid synthetic cycle accepted: " + path)
    print("agent-train-cycle checker positive + eight rejection cases PASS; synthetic only")


def control_binding_self_test():
    fixture = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["fixture"]()
    peers, addresses = fixture["expected_peers"], CUSTODY["SHARED"]["PUBLIC_IPS"]
    for control in ("relay0", "relay1"):
        layout = dict(fixture["layout"], producer_node="relay4", consumer_node="client",
                      route_context_id="b" * 32, control_relay_peer_id=peers[control])
        probe = dict(layout, route_context_id="a" * 32, control_relay_peer_id=peers["relay0"])
        fetch = {kind + "_receipt": {"control_relay_peer_id": peers[control]} for kind in ("adapter", "dataset")}
        routes = {}
        for index, node in enumerate(layout["provider_nodes"]):
            routes[node] = {
                "out": [dict(dev=f"cp{index}", gateway=f"10.241.{80+index}.2",
                             prefsrc=addresses[control], dst=addresses[node])],
                "back": [dict(dev=f"pc{index}", gateway=f"10.241.{80+index}.1",
                              prefsrc=addresses[node], dst=addresses[control])]}
        binding = dict(producer_layout=probe, probe_status={"control_relay_peer_id": peers["relay0"]},
                       fetch_status={"control_relay_peer_id": peers[control]}, routes=routes)
        check_control_binding(layout, peers, fetch, binding)
    # Changed-owner positive above binds new status, actual object receipts and both
    # kernel route directions; changing a label alone cannot turn the old proof green.
    mutations = [
        lambda b, f: b["fetch_status"].update(control_relay_peer_id=peers["relay0"]),
        lambda b, f: b["probe_status"].update(control_relay_peer_id=peers["relay1"]),
        lambda b, f: b["producer_layout"].update(producer_node="relay5"),
        lambda b, f: b["producer_layout"].update(route_context_id="b" * 32),
        lambda b, f: f["adapter_receipt"].update(control_relay_peer_id=peers["relay0"]),
        lambda b, f: b["routes"]["relay4"]["out"][0].update(prefsrc=addresses["relay0"]),
        lambda b, f: b["routes"]["relay4"]["back"][0].update(dst=addresses["relay0"]),
        lambda b, f: b["routes"]["relay4"]["out"][0].update(dev="underlay"),
        lambda b, f: b["routes"]["relay4"]["out"][0].update(gateway="10.241.80.1"),
        lambda b, f: b["routes"].pop("relay5"),
    ]
    for mutate in mutations:
        bad_binding, bad_fetch = copy.deepcopy(binding), copy.deepcopy(fetch)
        mutate(bad_binding, bad_fetch)
        try:
            check_control_binding(layout, peers, bad_fetch, bad_binding)
        except ValueError:
            continue
        raise AssertionError("stale or relabeled artifact control owner accepted")
    print("agent-artifact owner binding: unchanged/changed positives + ten rejections PASS; synthetic only")


def main():
    args = sys.argv[1:]
    if args == ["cycle-self-test"]:
        cycle_self_test()
        return
    if args == ["self-test"]:
        control_binding_self_test()
        source = (HERE.parent.parent / "README.md").read_text()
        value = dataset("a" * 40, source)
        require(value["heldout"][0]["question"] != value["train"][0]["question"], "heldout overlap")
        require(SOURCE_NAMES.count("train") == 1 and "provision" not in SOURCE_NAMES, "source removal scope")
        fixture = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["fixture"]()
        phase = fixture["phases"]["fetch"]
        actual = sum(x["response_payload_bytes"] for x in phase["privacy"]["exit"]["provider_application"].values())
        CUSTODY["validate_path"](phase, fixture["expected_peers"], fixture["layout"], "fetch", payload_minimum=actual)
        for minimum in (0, actual + 1):
            try:
                CUSTODY["validate_path"](phase, fixture["expected_peers"], fixture["layout"], "fetch", payload_minimum=minimum)
            except ValueError:
                continue
            raise AssertionError("missing exact object-byte bound accepted")
        producer = dict(node="relay4", network_namespace="net:[101]", cli_namespace="net:[101]",
                        service_namespace="net:[101]", service={"pid": 201, "start_ticks": 301},
                        service_executable="volparossa-agent")
        receiver = dict(node="client", network_namespace="net:[102]", cli_namespace="net:[102]",
                        service_namespace="net:[102]", service={"pid": 202, "start_ticks": 302},
                        service_executable="volparossa-agent")
        check_lineage(producer, receiver, "relay4", {"pid_before": 201})
        for field, value in (("node", "relay4"), ("network_namespace", "net:[101]"), ("service_namespace", "net:[103]")):
            bad = dict(receiver, **{field: value})
            try:
                check_lineage(producer, bad, "relay4", {"pid_before": 201})
            except ValueError:
                continue
            raise AssertionError("same-node or wrongly bound inference accepted")
        print("agent-artifact source/cleanup/path-bound/distinct-lineage self-test PASS; synthetic only, not network/training evidence")
        return
    if len(args) == 3 and args[0] == "prepare":
        prepare(args[1], args[2])
    elif len(args) == 3 and args[0] == "training":
        check_training(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "evidence":
        build_evidence(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "cycle-evidence":
        build_cycle_evidence(Path(args[1]), args[2])
    elif len(args) == 2 and args[0] == "cycle-files":
        print(json.dumps(cycle_files(args[1])))
    elif len(args) == 2 and args[0] in ("originals", "drop-source", "cleanup"):
        print(json.dumps({"originals": originals, "drop-source": drop_source, "cleanup": cleanup}[args[0]](args[1])))
    elif len(args) in (2, 3) and args[0] == "received":
        print(json.dumps(received(args[1], args[2] if len(args) == 3 else "received")))
    elif len(args) == 10 and args[0] == "observe":
        observe(int(args[1]), *(Path(x) for x in args[2:6]), args[6], args[7], Path(args[8]), int(args[9]))
    elif len(args) == 8 and args[0] in ("finalize", "cycle-finalize"):
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7], args[0] == "cycle-finalize")
    elif len(args) == 3 and args[0] == "report":
        check_report(read(Path(args[1]), 1048576), args[2])
        print("actual distinct-node public adapter transfer/reuse report PASS")
    else:
        raise ValueError("unsupported fixture operation")


if __name__ == "__main__":
    os.umask(0o077)
    main()
