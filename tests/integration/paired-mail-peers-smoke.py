#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify an offline Mail handoff between two Core Clients and two independent custodians."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "content-mailbox-smoke.py"))
PEER = runpy.run_path(str(HERE / "paired-mail-peer-capture.py"))
ROLES = ("sender", "recipient")
CUSTODIANS = ("relay3", "relay5")
FLOW_MINIMUM = {"enroll": 2, "send": 2, "receive": 7}
ISOLATION = ("client_role_verified", "own_agent_key_readable", "other_agent_key_hidden",
    "provider_caches_hidden", "offline_socket_unavailable")
PREFIX = "paired-mail-peers"
REPORT_NAME = PREFIX + "-smoke.json"
NAMES = {REPORT_NAME, "paired-mail-supply.json", PREFIX + "-lifecycle.json", "a01-expected-peers.json",
    *(f"{PREFIX}-{role}-{operation}.json" for role in ROLES for operation in ("init", "pair")),
    *(name for phase in FLOW_MINIMUM for name in (f"{PREFIX}-{phase}.json", f"{PREFIX}-{phase}-live-selection.json",
        f"{PREFIX}-{phase}-route-diagnostic.json", f"{PREFIX}-{phase}-preselection.json", f"{PREFIX}-{phase}-gates.json",
        f"content-provider-mail-peers-{phase}-control.json", *(f"{PREFIX}-{phase}-{role}.json" for role in PEER["INTERFACES"])))}
read, require = BASE["read"], BASE["require"]
SHA = re.compile(r"[0-9a-f]{64}")
DOMAIN = b"VOLPAROSSA/native-mailbox/v1\0"


def keys(value, names):
    require(type(value) is dict and set(value) == set(names), "unexpected Mail evidence fields")


def positive(value):
    return type(value) is int and 0 < value < 2**64


def signed_receipts(verify_signature, values, providers, operation, message=None, size=0):
    grant = BASE["receipts"](values, providers, operation, message, size)
    for encoded in values:
        envelope = BASE["fields"](bytes.fromhex(encoded))
        body = BASE["fields"](envelope[1])
        verify_signature(envelope[1], envelope[2], body[2], DOMAIN)
    return grant


def validate_apps(actors, app, providers):
    keys(actors, ROLES)
    for role, other in (("sender", "recipient"), ("recipient", "sender")):
        keys(actors[role], ("init", "pair"))
        initial, pair, peer = actors[role]["init"], actors[role]["pair"], actors[other]["init"]
        keys(initial, ("core_key", "signal_bundle_sha256"))
        require(all(isinstance(s, str) and SHA.fullmatch(s) for s in initial.values())
            and all(initial[k] != peer[k] for k in initial) and initial["core_key"] not in providers
            and pair == {"peer_key": peer["core_key"], "paired_bundle_sha256": peer["signal_bundle_sha256"]},
            "Mail participants did not pair each other's independent identities")
    keys(app, FLOW_MINIMUM)
    enroll, sent, received = (app[n] for n in FLOW_MINIMUM)
    keys(enroll, ("owner_key", "invitation_sha256", "storage_receipts"))
    require(enroll["owner_key"] == actors["recipient"]["init"]["core_key"]
        and SHA.fullmatch(enroll["invitation_sha256"]), "wrong Mail enrollment owner")
    keys(sent, ("message_id", "message_sha256", "packet_sha256", "packet_bytes", "message_bytes",
        "ciphertext_bytes", "confirmed_providers", "resumed_without_inputs", "sender_profile_removed", "deposit_receipts"))
    keys(received, ("confirmed_providers", "exact_raw_bytes", "fetched_messages", "message_bytes", "message_id",
        "message_sha256", "messages_after_ack", "owner_emails", "packet_bytes", "packet_sha256", "preimport_acks", "acknowledgement_receipts"))
    fixture = runpy.run_path(str(HERE / "paired-mail-guest.py"))
    require(all(received[k] == sent[k] for k in ("message_id", "packet_sha256", "packet_bytes", "message_sha256", "message_bytes"))
        and SHA.fullmatch(sent["message_id"]) and SHA.fullmatch(sent["packet_sha256"]) and sent["message_sha256"] == fixture["DIGEST"]
        and all(positive(sent[k]) for k in ("packet_bytes", "message_bytes", "ciphertext_bytes"))
        and sent["message_bytes"] == len(fixture["MIME"]) and sent["message_bytes"] < sent["packet_bytes"]
        and sent["packet_bytes"] + 16 <= sent["ciphertext_bytes"] <= sent["packet_bytes"] + 1024
        and all(type(received[k]) is int for k in ("packet_bytes", "message_bytes", "preimport_acks", "messages_after_ack", "fetched_messages", "owner_emails"))
        and sent["confirmed_providers"] == received["confirmed_providers"] == 2
        and sent["sender_profile_removed"] is True and sent["resumed_without_inputs"] is True
        and received["exact_raw_bytes"] is True and received["fetched_messages"] == received["owner_emails"] == 1
        and received["preimport_acks"] == received["messages_after_ack"] == 0, "Mail send/import/cleanup incomplete")
    verify_signature = runpy.run_path(str(HERE / "content-retain-smoke.py"))["verify_signature"]
    grant = signed_receipts(verify_signature, enroll["storage_receipts"], providers, 1)
    require(grant.hex() == enroll["invitation_sha256"], "signed grant differs from the enrolled invitation file")
    require(grant == signed_receipts(verify_signature, sent["deposit_receipts"], providers, 2, sent["message_id"], sent["ciphertext_bytes"]),
        "Mail deposit used a different grant")
    acks = received["acknowledgement_receipts"]
    require(type(acks) is list and len(acks) == 2 and {a["provider_key"] for a in acks} == providers, "wrong ACK providers")
    for ack in acks:
        keys(ack, ("version", "provider_key", "message_id", "receipt", "observed_unix_seconds", "original_expires_unix_seconds"))
        require(type(ack["version"]) is int and ack["version"] == 1 and ack["message_id"] == sent["message_id"]
            and isinstance(ack["receipt"], str) and 0 < len(ack["receipt"]) <= 131072, "wrong ACK identity")
        envelope = BASE["fields"](bytes.fromhex(ack["receipt"]))
        body = BASE["fields"](envelope[1])
        payload = BASE["fields"](body[8])
        require(body[2].hex() == ack["provider_key"] and ack["original_expires_unix_seconds"] == payload[6]
            and positive(ack["observed_unix_seconds"]) and body[3] <= ack["observed_unix_seconds"] < body[4],
            "ACK metadata differs from signed provider receipt")
    require(grant == signed_receipts(verify_signature, [a["receipt"] for a in acks], providers, 5, sent["message_id"]),
        "Mail acknowledgement used a different grant")


def validate_supply(supply):
    pins = read(HERE / "paired-mail-pins.json")
    native = "node_modules/@signalapp/libsignal-client/prebuilds/linux-x64/@signalapp+libsignal-client.node"
    keys(supply, ("mail_revision", "runtime_bytes", "files", "native_binaries", *pins["actions"]))
    require(supply["mail_revision"] == pins["mail_revision"] and all(supply[k] == v for k, v in pins["actions"].items())
        and positive(supply["files"]) and supply["files"] > 100 and positive(supply["runtime_bytes"])
        and supply["native_binaries"] == {"bin/stalwart": pins["actions"]["stalwart_sha256"],
            native: pins["actions"]["libsignal_sha256"], "bin/node": "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"},
        "Mail runtime differs from its pinned original Actions closure")


def validate(report, revision):
    keys(report, ("schema_version", "report_kind", "source_revision", "runner_exit_status", "observed_blocker", "success",
        "cleanup", "host_state", "actors", "app", "supply", "lifecycle", "expected_peers", "network"))
    require(type(report["schema_version"]) is int and report["schema_version"] == 1 and report["report_kind"] == "volparossa-paired-mail-peers"
        and re.fullmatch("[0-9a-f]{40}", revision) and report["source_revision"] == revision and report["success"] is True
        and type(report["runner_exit_status"]) is int and report["runner_exit_status"] == 0 and report["observed_blocker"] is None,
        "paired Mail guest outcome incomplete")
    keys(report["cleanup"], ("complete", "remaining_owned_objects"))
    keys(report["host_state"], ("before_sha256", "after_sha256", "unchanged"))
    require(report["cleanup"]["complete"] is True and type(report["cleanup"]["remaining_owned_objects"]) is int
        and report["cleanup"]["remaining_owned_objects"] == 0 and report["host_state"]["unchanged"] is True
        and SHA.fullmatch(report["host_state"]["before_sha256"]) and report["host_state"]["after_sha256"] == report["host_state"]["before_sha256"],
        "paired Mail host cleanup incomplete")
    validate_supply(report["supply"])
    lifecycle, peers = report["lifecycle"], report["expected_peers"]
    keys(lifecycle, ("participants", "provider_keys", "reopened_provider", "cache_inode_before", "cache_inode_after", "listener_absent_between",
        "sender_private_removed", "recipient_private_removed"))
    require(lifecycle["provider_keys"] == {n: BASE["peer_key"](peers[n]) for n in CUSTODIANS}
        and lifecycle["reopened_provider"] == "relay5" and positive(lifecycle["cache_inode_before"])
        and lifecycle["cache_inode_before"] == lifecycle["cache_inode_after"]
        and all(lifecycle[key] is True for key in ("listener_absent_between", "sender_private_removed","recipient_private_removed")),
        "custodian identity, reopening, cache or owner cleanup incomplete")
    participants = lifecycle["participants"]
    keys(participants, ("client", "relay4"))
    for initial in participants.values():
        keys(initial, ("pid", "socket", "netns", "uid"))
        require(all(positive(value) for value in initial.values()), "initial Mail Client observation missing")
    require(all(participants["client"][k] != participants["relay4"][k] for k in ("pid", "socket", "netns", "uid")),
        "simultaneous Mail Client endpoints are not independent")
    validate_apps(report["actors"], report["app"], set(lifecycle["provider_keys"].values()))
    phases = report["network"]
    keys(phases, FLOW_MINIMUM)
    for phase, minimum in FLOW_MINIMUM.items():
        data = phases[phase]
        keys(data, ("selected_route", "gates", "captures", "control"))
        gate = data["gates"]
        keys(gate, ("event_baseline_unix_ms", "exit_mptcp_tls_completed", "exact_provider_lookups", "control_relay_peer_id",
            "active_node", "inactive_node", "inactive_pid", "active_pid", "active_netns", "active_socket", "application_uid", *ISOLATION))
        active = PEER["ACTIVE"][phase]
        require(gate["active_node"] == active and gate["inactive_node"] == ("relay4" if active == "client" else "client")
            and type(gate["inactive_pid"]) is int and gate["inactive_pid"] == 0 and all(positive(gate[k]) for k in (
                "active_pid", "active_netns", "active_socket", "application_uid", "event_baseline_unix_ms",
                "exit_mptcp_tls_completed", "exact_provider_lookups"))
            and gate["active_netns"] == participants[active]["netns"] and gate["application_uid"] == participants[active]["uid"]
            and min(gate["exit_mptcp_tls_completed"], gate["exact_provider_lookups"]) >= minimum
            and all(gate[k] is True for k in ISOLATION), "independent Client or protected Mail exchange missing")
        brokers = [n for n in PEER["RELAYS"] if peers[n] == gate["control_relay_peer_id"]]
        require(len(brokers) == 1, "Mail control relay outside fixture")
        BASE["SHARED"]["validate_control"](data["control"], brokers[0], CUSTODIANS, False)
        PEER["validate"](data["captures"], data["selected_route"], peers, report["app"]["send"]["packet_bytes"], phase=phase)
    enroll, receive = phases["enroll"]["gates"], phases["receive"]["gates"]
    require(enroll["active_pid"] == participants["relay4"]["pid"] and enroll["active_socket"] == participants["relay4"]["socket"]
        and enroll["active_pid"] != receive["active_pid"]
        and len({data["selected_route"]["route_context_id"] for data in phases.values()}) == 3,
        "Mail phases did not use independently offline Clients and a fresh recipient route")


def originals(root):
    def get(name):
        return read(root / (name + ".json"))
    return dict(actors={r: {n: get(f"{PREFIX}-{r}-{n}") for n in ("init", "pair")} for r in ROLES},
        app={p: get(f"{PREFIX}-{p}") for p in FLOW_MINIMUM}, supply=get("paired-mail-supply"),
        lifecycle=get(PREFIX + "-lifecycle"), expected_peers=get("a01-expected-peers"),
        network={p: dict(selected_route=get(f"{PREFIX}-{p}-live-selection"), gates=get(f"{PREFIX}-{p}-gates"),
            control=get(f"content-provider-mail-peers-{p}-control"), captures={r: get(f"{PREFIX}-{p}-{r}") for r in PEER["INTERFACES"]})
            for p in FLOW_MINIMUM})


def closed_blocker(code):
    if code == "NONE":
        return None
    # The shell reports fixed failure labels. Unknown product log text must not leave the guest.
    if re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code):
        token = re.compile(r"\bfail " + re.escape(code) + r"(?![A-Z0-9_])")
        for script in ("paired-mail-peers-smoke.sh", "content-mailbox-smoke.sh", "kvm-alpha-topology.sh"):
            if token.search((HERE / script).read_text()):
                return code
    return "UNCLASSIFIED_GUEST_FAILURE"


def assemble(root, revision, status, blocker, cleanup, remaining, before, after):
    require(bool(re.fullmatch("[0-9a-f]{40}", revision)) and status.isascii() and status.isdigit() and int(status) <= 255
        and cleanup in ("true", "false") and remaining.isascii() and remaining.isdigit(), "invalid guest finalization")
    report = dict(schema_version=1, report_kind="volparossa-paired-mail-peers", source_revision=revision, runner_exit_status=int(status),
        observed_blocker=closed_blocker(blocker), success=False,
        cleanup=dict(complete=cleanup == "true", remaining_owned_objects=int(remaining)),
        host_state=dict(before_sha256=before, after_sha256=after, unchanged=bool(SHA.fullmatch(before) and before == after)))
    if status == "0":
        report.update(originals(root), success=True)
        validate(report, revision)
    return report


def main(args):
    if args == ["export-names"]:
        print("\n".join(sorted(NAMES)))
    elif len(args) == 3 and args[0] == "selection-events" and args[2] in FLOW_MINIMUM:
        root = Path(args[1])
        prefix = f"{PREFIX}-{args[2]}"
        diagnostics = runpy.run_path(str(HERE / "private-storage-maintenance-smoke.py"))
        observation = diagnostics["closed_preselection_events"](
            root / f"{prefix}-events.private", root / f"{prefix}-start.private", root / f"{prefix}-end.private")
        diagnostics["validate_preselection_diagnostic"](observation)
        print(json.dumps(observation, sort_keys=True))
    elif len(args) == 9 and args[0] == "assemble":
        print(json.dumps(assemble(Path(args[1]), *args[2:]), sort_keys=True, separators=(",", ":")))
    elif len(args) == 3 and args[0] == "report":
        path = Path(args[1])
        report = read(path)
        validate(report, args[2])
        require(all(report[k] == v for k, v in originals(path.parent).items()), "Mail report differs from raw originals")
        for moment in ("before", "after"):
            host = path.parent / f"host-state-{moment}.json"
            require(not host.is_symlink() and host.stat().st_size <= 1048576
                and hashlib.sha256(host.read_bytes()).hexdigest() == report["host_state"][moment + "_sha256"],
                "paired Mail host-state digest differs")
    else:
        raise ValueError("unsupported paired Mail evidence command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        sys.exit("PAIRED_MAIL_PEERS_EVIDENCE_INCOMPLETE")
