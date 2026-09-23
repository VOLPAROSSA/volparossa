#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Original automatic-custody observations; never a future availability promise."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).parent
C = runpy.run_path(str(HERE / "content-custody-smoke.py"))
require, fields, read = C["require"], C["fields"], C["read"]
NODES = ("relay3", "relay4", "relay5")
FILES = {"enrollment.json", "original.manifest", "state.json", "status.json", ".retain.lock"}
DOMAIN = b"VOLPAROSSA/public-custody/v1\0"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_signature(body, signature, key, domain):
    require(len(signature) == 64 and len(key) == 32, "invalid public signature dimensions")
    with tempfile.TemporaryDirectory(prefix="volparossa-retain-signature-") as temporary:
        root = Path(temporary)
        (root / "key").write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
        (root / "message").write_bytes(domain + body)
        (root / "signature").write_bytes(signature)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
            "-inkey", str(root / "key"), "-rawin", "-in", str(root / "message"),
            "-sigfile", str(root / "signature")], capture_output=True, timeout=5, check=False)
        require(result.returncode == 0, "original Ed25519 signature failed")


def envelope(raw, key, kind, at):
    encoded = fields(raw, 65536)
    require(set(encoded) == {1, 2}, "signed envelope fields differ")
    body = fields(encoded[1], 65536)
    require(set(body) == set(range(1, 9)) and body[1] == 1 and body[2] == bytes.fromhex(key)
            and body[6] == kind and len(body[5]) == 32 and body[7] == hashlib.sha256(body[8]).digest()
            and body[3] <= at < body[4] and 0 < body[4] - body[3] <= 900,
            "custody envelope identity, time, nonce or payload differs")
    verify_signature(encoded[1], encoded[2], body[2], DOMAIN)
    return body, fields(body[8], 65536)


def exchange(record, provider, publisher, original, expiry):
    signed = record["original"]
    require(signed["handoff_complete"] is True and signed["verified_at"] <= record["checked_at"],
            "missing successful original handoff")
    at = signed["verified_at"]
    challenge, authorization, receipt = (bytes.fromhex(signed[f"{name}_hex"])
                                       for name in ("challenge", "authorization", "receipt"))
    cb, cp = envelope(challenge, provider, 1, at)
    ab, ap = envelope(authorization, publisher, 2, at)
    rb, rp = envelope(receipt, provider, 3, at)
    operation = {"deposit": 1, "inspect": 2}[record["operation"]]
    require(set(cp) == {1} and len(cp[1]) == 32
            and set(ap) == ({1, 2, 4} if operation == 1 else {1, 2, 3, 4})
            and ap[1].hex() == sha(challenge)
            and ap[2] == bytes.fromhex(provider) and ap.get(3, 1) == operation and ap[4] == original
            and ab[4] <= min(cb[4], expiry) and rb[4] <= ab[4],
            "original challenge/authorization/manifest binding differs")
    request, challenge_id = C["receipt"](receipt.hex(), provider, publisher, sha(original),
                                         expiry, operation, 2)
    require(request == sha(authorization) and challenge_id == sha(challenge),
            "original receipt is not for its own authorization/challenge")
    return request, challenge_id


def snapshot(path):
    root = C["private_root"](path)
    directory = root / "retain-owner"
    info = directory.lstat()
    require(directory.is_dir() and not directory.is_symlink() and info.st_uid == os.geteuid()
            and info.st_mode & 0o777 == 0o700, "wrong owner directory")
    raw = {}
    for name in FILES - {".retain.lock"}:
        target = directory / name
        require(C["private_file"](target).st_size <= 262144, "fixture owner record exceeds bound")
        raw[name] = target.read_bytes()
    state, status = json.loads(raw["state.json"]), json.loads(raw["status.json"])
    require(status["state_sha256"] == sha(raw["state.json"]), "owner checkpoint is changing")
    return dict(captured_unix_ms=time.time_ns() // 1000000,
                raw={name: dict(hex=value.hex(), sha256=sha(value)) for name, value in raw.items()},
                state=state, status=status, enrollment=json.loads(raw["enrollment.json"]))


def validate_snapshot(value, publication, keys, maintained=True):
    raw = {name: bytes.fromhex(entry["hex"]) for name, entry in value["raw"].items()}
    require(set(raw) == FILES - {".retain.lock"}
            and all(sha(raw[name]) == value["raw"][name]["sha256"] for name in raw),
            "original checkpoint bytes/hash missing")
    state, status, enrollment = (json.loads(raw[name]) for name in
                                  ("state.json", "status.json", "enrollment.json"))
    require(state == value["state"] and status == value["status"] and enrollment == value["enrollment"]
            and status["state_sha256"] == sha(raw["state.json"])
            and state["enrollment_sha256"] == sha(raw["enrollment.json"]), "checkpoint binding changed")
    original = raw["original.manifest"]
    manifest = fields(original, 65536)
    body = fields(manifest[1], 65536)
    require(set(manifest) == {1, 2} and set(body) == set(range(1, 9))
            and body[1] == body[6] == 1 and body[2].hex() == publication["publisher_key_hex"]
            and body[4] == publication["expires_unix_seconds"]
            and body[7] == hashlib.sha256(body[8]).digest(), "original manifest header differs")
    verify_signature(manifest[1], manifest[2], bytes.fromhex(publication["publisher_key_hex"]),
                     b"VOLPAROSSA/native-content-manifest/v1\0")
    require(sha(original) == status["manifest_id"] == publication["manifest_id"]
            and status["original_expiry_unix_seconds"] == publication["expires_unix_seconds"]
            and state["deadline"] == min(state["started_at"] + enrollment["max_seconds"],
                                           publication["expires_unix_seconds"])
            and enrollment["copies"] == 2 and enrollment["max_upload_bytes"] == C["BYTES"] * 4
            and enrollment["discovery_batch"] == 16 and "provider_keys" not in enrollment
            and state["uploads_reserved_bytes"] <= enrollment["max_upload_bytes"]
            and state["confirmed_holders"] == status["confirmed_holders"]
            and all(status[field] is False for field in
                    ("future_availability_guaranteed", "maintenance_while_owner_offline")),
            "original enrollment, manifest, expiry or upload ceiling changed")
    holders = set(state["confirmed_holders"])
    require(holders <= set(keys.values()) and len(holders) == len(state["confirmed_holders"]),
            "unknown or duplicate holder")
    if maintained:
        require(len(holders) == 2 and state["completed_polls"] > 0 and state["pending"] is None
                and state["last_outcome"] == "maintained"
                and state["started_at"] <= state["last_observed"] < state["deadline"],
                "snapshot is not an original completed current poll")
    bindings = []
    for key in holders:
        record = state["observations"][key]
        require(record["outcome"] == "complete" and record["sequence"] <= state["attempt_sequence"]
                and state["started_at"] <= record["checked_at"] <= state["last_observed"],
                "holder lacks its successful observation")
        bindings.append(exchange(record, key, publication["publisher_key_hex"], original,
                                 publication["expires_unix_seconds"]))
    require(len(bindings) == len(set(bindings)), "a signed observation was reused for another holder")
    return holders


def observe(path, label, initial_path=None):
    root = C["private_root"](path)
    initial = read(Path(initial_path)) if initial_path else None
    until = time.monotonic() + 700
    while time.monotonic() < until:
        try:
            value = snapshot(root)
            state = value["state"]
            complete = state["last_outcome"] == "maintained" and state["pending"] is None \
                and len(set(state["confirmed_holders"])) == 2 and state["completed_polls"] > 0
            if initial:
                lost = initial["state"]["confirmed_holders"][0]
                complete = complete and state["completed_polls"] > initial["state"]["completed_polls"] \
                    and lost not in state["confirmed_holders"] \
                    and set(state["confirmed_holders"]) != set(initial["state"]["confirmed_holders"])
            if complete:
                value["phase"] = label
                return value
            require(state["last_outcome"] not in ("stopped", "expired", "deadline_reached"),
                    "owner ended before the requested observed redundancy")
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        except ValueError as error:
            if str(error) != "owner checkpoint is changing":
                raise
        time.sleep(0.25)
    raise ValueError("automatic custody observation deadline reached")


def process(pid, executable):
    pid = int(pid)
    root = Path(f"/proc/{pid}")
    until = time.monotonic() + 5
    while (root / "exe").resolve() != Path(executable).resolve() and time.monotonic() < until:
        time.sleep(0.05)
    require((root / "exe").resolve() == Path(executable).resolve(), "owner executable is not the exact CLI")
    argv = (root / "cmdline").read_bytes().decode().rstrip("\0").split("\0")
    require("retain" in argv and "content" in argv and "--execute" in argv
            and "--provider-key" not in argv, "not an automatic real retain process")
    status = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines())
    require(all(int(n) > 0 for n in status["Uid"].split())
            and all(int(status[name], 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            and int(status["NoNewPrivs"]) == 1, "owner was privileged")
    start = int((root / "stat").read_text().split(") ", 1)[1].split()[19])
    return dict(pid=pid, start_ticks=start, started_unix_ms=time.time_ns() // 1000000,
                original_argv=argv, executable_verified=True, provider_keys_supplied=False,
                uid=[int(n) for n in status["Uid"].split()], capabilities_zero=True, no_new_privileges=True)


def cleanup(path):
    root = C["private_root"](path, missing=True)
    directory = root / "retain-owner"
    if directory.exists() or directory.is_symlink():
        require(directory.is_dir() and not directory.is_symlink(), "unsafe owner cleanup root")
        children = list(directory.iterdir())
        require(all(child.name in FILES for child in children), "unexpected owner cleanup content")
        for child in children:
            C["private_file"](child)
        for child in children:
            child.unlink()
        directory.rmdir()
    initial = root / "initial-observation.json"
    if initial.exists() or initial.is_symlink():
        C["private_file"](initial)
        initial.unlink()
    return C["cleanup"](path)


def validate_path(phase, peers, layout, active, name):
    selected, captures = phase["selected_route"], phase["privacy"]
    paths, slots = selected["paths"], selected["benchmark_slots"]
    require(selected["transport"] == "mptcp" and selected["route_context_id"] == layout["route_context_id"]
            and len(paths) == len(slots) == 2
            and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == layout["route_context_id"] for p in paths)
            and all(slot["relay_node"] in C["ROLES"][1:4]
                    and peers[slot["relay_node"]] == slot["relay_peer_id"] == path["relay_peer_id"]
                    for slot, path in zip(slots, paths)), "carrying route geometry changed")
    require(set(captures) == set(C["ROLES"]), "missing five-role captures")
    for role, capture in captures.items():
        C["SHARED"]["validate_drained"](capture, allow_empty=role in C["ROLES"][1:4])
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == capture["unexpected_provider_application_packets"] == 0
                and set(capture["provider_application"]) == set(NODES), "unexpected outer/application traffic")
        if role != "exit":
            require(all(n == 0 for counters in capture["provider_application"].values() for n in counters.values())
                    and capture["internet_destination_outer_packets"] == 0, "application bypassed protected route")
        if role in ("client", "exit"):
            require(capture["direct_client_exit_packets"] == 0, "direct Client to Exit traffic")
    require(captures["exit"]["client_public_packets"] == 0
            and captures["exit"]["outbound_client_discovery_attempt_packets"] == 0, "Exit learned Client address")
    for slot in slots:
        capture = captures[slot["relay_node"]]
        require(capture["client_leg_wireguard_data_datagrams"] > 0
                and capture["exit_leg_wireguard_data_datagrams"] > 0, "unused selected WG leg")
    for node in active:
        counters = captures["exit"]["provider_application"][node]
        require(counters["request_packets"] > 0 and counters["response_packets"] > 0
                and counters["response_payload_bytes"] > 0, "actual custody/fetch exchange absent")
    if name == "fetch":
        require(sum(captures["exit"]["provider_application"][n]["response_payload_bytes"] for n in active)
                >= C["UNIQUE_BYTES"], "fresh fetch lacks payload bytes")
    control = next(n for n in C["ROLES"][1:4] if peers[n] == layout["control_relay_peer_id"])
    capture = phase["control_privacy"]
    pairs = {f"ac{i}": [C["SHARED"]["PUBLIC_IPS"][control], C["SHARED"]["PUBLIC_IPS"][node]]
             for i, node in enumerate(NODES)}
    require(capture["capture_role"] == "content-control" and capture["content_control_pairs"] == pairs
            and set(capture["interfaces"]) == set(pairs)
            and set(capture["content_control_packets"]) == set(pairs)
            and capture["unexpected_provider_control_packets"] == capture["unexpected_provider_application_packets"] == 0
            and all(v == 0 for row in capture["provider_application"].values() for v in row.values()),
            "three dedicated control links carried unexpected traffic")
    C["SHARED"]["validate_drained"](capture, allow_empty=True)
    if name == "initial":
        require(all(row["inbound"] > 0 and row["outbound"] > 0
                    for row in capture["content_control_packets"].values()),
                "initial discovery did not contact all three independent provider candidates")
    require(phase["gates"]["exit_mptcp_tls_completed"] >= (4 if name == "initial" else 1),
            "actual protected MPTCP/TLS completions missing")


def validate_evidence(evidence):
    publish, layout, peers = (evidence[key] for key in ("publish", "layout", "expected_peers"))
    keys = layout["provider_keys"]
    require(layout["provider_nodes"] == list(NODES) and set(keys) == set(NODES)
            and len(set(keys.values())) == 3
            and all(C["peer_key"](peers[node]) == key for node, key in keys.items())
            and layout["control_relay_peer_id"] in {peers[n] for n in C["ROLES"][1:4]}
            and not {peers[n] for n in NODES}.intersection({peers[n] for n in C["ROLES"]}),
            "providers are not three independent route-distinct nodes")
    require(publish["bytes"] == C["BYTES"] and publish["chunks"] == 9
            and publish["network_publication"] is False and publish["manifest_id"] == layout["manifest_id"],
            "wrong original publication")
    first = validate_snapshot(evidence["initial"], publish, keys)
    replacement = validate_snapshot(evidence["replacement"], publish, keys)
    stopped = evidence["stopped"]
    validate_snapshot(evidence["final_state"], publish, keys, maintained=False)
    require(stopped["last_outcome"] == "stopped" and stopped["operation"] == "content_retain"
            and stopped["maintenance_while_owner_offline"] is False
            and evidence["final_state"]["state"]["last_outcome"] == "stopped",
            "owner did not terminate honestly")
    lost = evidence["initial"]["state"]["confirmed_holders"][0]
    require(lost not in replacement and len(first & replacement) == 1
            and first | replacement == set(keys.values())
            and evidence["replacement"]["state"]["observations"][lost]["outcome"] == "unavailable"
            and evidence["replacement"]["state"]["completed_polls"] > evidence["initial"]["state"]["completed_polls"]
            and evidence["withdrawal"]["provider_key"] == lost
            and evidence["withdrawal"]["receipt"]["serving"] is False,
            "lost holder was not replaced by the third actual provider")
    after = evidence["replacement"]["state"]
    require(all(after["observations"][key]["checked_at"] >= evidence["withdrawal"]["withdrawn_unix_seconds"]
                for key in replacement | {lost})
            and after["uploads_reserved_bytes"] >= evidence["initial"]["state"]["uploads_reserved_bytes"] + C["BYTES"],
            "replacement reused stale availability or did not reserve the new deposit")
    for key in first & replacement:
        require(after["observations"][key]["original"]["challenge_hex"]
                != evidence["initial"]["state"]["observations"][key]["original"]["challenge_hex"],
                "surviving holder was not freshly challenged after loss")
    previous = evidence["initial"]["state"]
    for value in (evidence["initial"], evidence["replacement"], evidence["final_state"]):
        require(value["raw"]["original.manifest"] == evidence["initial"]["raw"]["original.manifest"]
                and value["raw"]["enrollment.json"] == evidence["initial"]["raw"]["enrollment.json"]
                and value["state"]["started_at"] == previous["started_at"]
                and value["state"]["deadline"] == previous["deadline"]
                and all(value["state"][field] >= previous[field] for field in
                        ("attempt_sequence", "completed_polls", "uploads_reserved_bytes", "last_observed")),
                "replacement/final checkpoint renewed enrollment, window or cumulative budget")
        previous = value["state"]
    process = evidence["process"]
    require(process["pid"] > 1 and process["start_ticks"] > 0 and process["exit_status"] == 0
            and process["term_sent"] is True and process["reaped"] is True
            and process["ended_unix_ms"] >= process["started_unix_ms"] > 0
            and process["ended_unix_ms"] <= evidence["fetch_started_unix_ms"]
            and process["executable_verified"] is True and process["provider_keys_supplied"] is False
            and process["forced_kill"] is False,
            "publisher owner process was not stopped/reaped before fresh retrieval")
    for node, provider in evidence["providers"].items():
        require(provider["empty"]["publications"] == 0 and provider["empty"]["serving"] is True
                and provider["stop"]["serving"] is False, "provider did not start empty and stop")
    fetch, output = evidence["fetch"], evidence["output"]
    remaining_peers = {peers[n] for n in NODES if keys[n] in replacement}
    require(fetch["operation"] == "named_content_download" and fetch["name"] == "disposable-public-custody"
            and fetch["manifest_id"] == publish["manifest_id"]
            and fetch["publication_expires_unix_seconds"] == publish["expires_unix_seconds"]
            and fetch["publisher_key"] == publish["publisher_key_hex"] and fetch["revision"] == 1
            and fetch["bytes"] == output["bytes"] == C["BYTES"]
            and C["UNIQUE_BYTES"] <= fetch["peer_bytes"] <= C["BYTES"]
            and fetch["sha256"] == output["sha256"] == C["SHA"]
            and 0 < fetch["providers_used"] == len(set(fetch["provider_peer_ids"])) <= 2
            and set(fetch["provider_peer_ids"]) <= remaining_peers
            and fetch["origin_authenticated"] is False and fetch["local_delivery"] is True
            and fetch["control_relay_peer_id"] == layout["control_relay_peer_id"]
            and evidence["source_removed"]["source_cache_removed"] is True
            and evidence["source_removed"]["source_input_removed"] is True,
            "fresh consumer did not reconstruct the exact original from remaining holders")
    require(all(evidence["isolation"][key] is True for key in ("agent_mount_positive_control",
            "agent_cannot_read_user_state", "client_cannot_read_provider_stores", "fresh_consumer_cache",
            "user_cannot_read_agent_cache"))
            and evidence["private_cleanup"]["user_directory_removed"] is True, "isolation/cleanup incomplete")
    for name, holder_keys in (("initial", first), ("replacement", replacement),
                              ("fetch", {keys[n] for n in NODES if peers[n] in fetch["provider_peer_ids"]})):
        validate_path(evidence["phases"][name], peers, layout,
                      [n for n in NODES if keys[n] in holder_keys], name)
    control = next(n for n in C["ROLES"][1:4] if peers[n] == layout["control_relay_peer_id"])
    addresses = C["SHARED"]["PUBLIC_IPS"]
    require(set(evidence["control_routes"]) == set(NODES), "three actual control route pairs missing")
    for index, node in enumerate(NODES):
        for direction, device, gateway, source, destination in (
                ("out", f"ac{index}", f"10.241.{83+index}.2", addresses[control], addresses[node]),
                ("back", f"ap{index}", f"10.241.{83+index}.1", addresses[node], addresses[control])):
            rows = evidence["control_routes"][node][direction]
            require(isinstance(rows, list) and len(rows) == 1
                    and all(rows[0].get(key) == value for key, value in
                            dict(dev=device, gateway=gateway, prefsrc=source, dst=destination).items()),
                    "actual control route differs from its dedicated disposable link")
    entries = evidence["early_control_filter"]["nftables"]
    rules = [entry["rule"] for entry in entries if "rule" in entry]
    require(len(rules) == 4, "early control filter changed")
    for chain, field in (("input", "iifname"), ("output", "oifname")):
        for port in ("sport", "dport"):
            require(any(rule["chain"] == chain and rule["table"] == "vpa_content_adaptive_client_control"
                and rule["family"] == "inet" and rule["expr"] == [
                    dict(match=dict(op="==", left=dict(meta=dict(key=field)),
                                    right=dict(set=["cr3", "cr4", "cr5"]))),
                    dict(match=dict(op="==", left=dict(payload=dict(protocol="udp", field=port)), right=41000)),
                    dict(counter=dict(packets=0, bytes=0)), {"drop": None}] for rule in rules),
                "early filter does not exclude only provider control contacts")


def build_evidence(work):
    names = ("publish", "layout", "initial", "replacement", "stopped", "withdrawal", "process",
             "fetch", "output", "source-removed", "isolation", "private-cleanup", "final-state")
    evidence = {name.replace("-", "_"): read(work / f"content-custody-{name}.json") for name in names}
    evidence.update(success=True, automatic_provider_selection=True,
                    expected_peers=read(work / "a01-expected-peers.json"),
                    fetch_started_unix_ms=read(work / "content-custody-fetch-start.json")["unix_ms"])
    evidence["providers"] = {node: {label: read(work / f"content-custody-{node}-{label}.json")
                                    for label in ("empty", "stop")} for node in NODES}
    evidence["phases"] = {name: dict(selected_route=read(work / f"content-custody-{name}-live-selection.json"),
        privacy={role: read(work / f"content-custody-{name}-privacy-{role}.json") for role in C["ROLES"]},
        control_privacy=read(work / f"content-provider-adaptive-custody-{name}-control.json"),
        gates=read(work / f"content-custody-{name}-gates.json")) for name in ("initial", "replacement", "fetch")}
    evidence["control_routes"] = {node: {direction: json.loads(
        (work / f"content-provider-adaptive-control-{node}-{direction}.json").read_bytes())
        for direction in ("out", "back")} for node in NODES}
    evidence["early_control_filter"] = read(work / "content-provider-adaptive-control-filter.json")
    validate_evidence(evidence)
    return evidence


def main(arguments):
    command = arguments[0]
    if command == "observe" and len(arguments) in (3, 4):
        result = observe(*arguments[1:])
    elif command == "snapshot" and len(arguments) == 2:
        result = snapshot(arguments[1])
    elif command == "process" and len(arguments) == 3:
        result = process(*arguments[1:])
    elif command == "cleanup" and len(arguments) == 2:
        result = cleanup(arguments[1])
    elif command == "evidence" and len(arguments) == 3:
        result = build_evidence(Path(arguments[1]))
        Path(arguments[2]).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    else:
        raise ValueError("unknown automatic custody evidence command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError) as error:
        print(f"automatic custody evidence rejected: {error}", file=sys.stderr)
        sys.exit(1)
