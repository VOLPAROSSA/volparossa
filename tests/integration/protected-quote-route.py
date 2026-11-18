#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed negative quote-route evidence; never hardware or private-task acceptance."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

HERE = Path(__file__).resolve().parent
COMMON = runpy.run_path(str(HERE / "content-provider-https-smoke.py"))
peer_key = runpy.run_path(str(HERE / "content-custody-smoke.py"))["peer_key"]
require = COMMON["require"]
ROLES = ("client", "relay0", "relay1", "relay2", "exit")
PROVIDERS = ("relay4", "relay5", "relay3")
EXPORT_NAMES = ("protected-quote-route.json", "protected-quote-vm-cleanup.json")
PINS = {
    "vcek.der": ("vcek_milan.der", "3bbfb6ee259f75a95d13168cfdf2e034181bb93c7c016825731cbe8ea16c95e1"),
    "vendor.crl": ("ark_milan_20260922.crl", "dd68e9e3feb97dd0e95135feeae47d9cc193c73239a6281ec9884c00d5e6a525"),
}
REFUSAL = dict(version=2, provider_claim="fixed_quote_device_unavailable",
    provider_assertion_verified_by="local_agent", quote_exchange=False,
    bound_reference_evidence=False, complete_appraisal=False,
    worker_admission=False, private_input_released=False)
SCOPE = dict(authenticated_provider_refusal=True, hardware_attestation=False,
    private_task_execution=False, private_input_released=False, full_appraisal=False,
    portable_provider_signature=False, two_subflow_payload_proven=False,
    full_alpha_acceptance=False, synthetic_firmware=False)
INPUTS = dict(version=1, public_test_expectations=True, collateral_authenticated=False,
    positive_hardware_acceptance=False, **{name.replace(".", "_") + "_sha256": pin[1]
        for name, pin in PINS.items()})


def integer(value, minimum=0, maximum=2**53 - 1):
    return type(value) is int and minimum <= value <= maximum


def shape(value, keys):
    require(type(value) is dict and set(value) == set(keys), "closed evidence shape required")


def same(left, right):
    # Python considers True == 1; evidence schemas must not.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def bytes_at(path, limit=262144):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "regular evidence file required")
        value = source.read(limit + 1)
    require(len(value) <= limit, "evidence size exceeded")
    return value


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=object_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read(path):
    value = decode(bytes_at(path))
    require(type(value) is dict, "object evidence required")
    return value


def write(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= 262144, "closed report size exceeded")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)


def prepare(work, source):
    root = work / "protected-quote-inputs"
    root.mkdir(mode=0o700)
    fixtures = source / "crates/volparossa-content/tests/fixtures/snp"
    for name, (original, digest) in PINS.items():
        raw = bytes_at(fixtures / original, 65536)
        require(hashlib.sha256(raw).hexdigest() == digest, "public collateral pin mismatch")
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
    floor = dict(bootloader=1, tee=2, snp=3, microcode=4)
    write(root / "policy.json", dict(version=1, public_policy_id="11" * 32,
        expected_measurement="22" * 48, minimum_guest_svn=0,
        minimum_tcb={name: floor for name in ("current", "reported", "committed", "launch")},
        smt="require_disabled"))
    # These are historical public fixtures, not fresh trusted collateral or a
    # measurement of this test machine. A positive quote cannot pass this smoke.
    write(work / "protected-quote-inputs.json", INPUTS)


def capture_projection(raw, control=False):
    keys = ("capture_role", "content_provider_mode", "truncated", "observed_frames",
        "packet_socket_drops", "interfaces", "interface_statistics", "provider_application",
        "unexpected_provider_application_packets")
    keys += (("content_control_pairs", "content_control_packets", "unexpected_provider_control_packets")
        if control else ("unexpected_outer_packets", "expected_link_down_notifications",
            "direct_client_exit_packets", "internet_destination_outer_packets", "client_public_packets",
            "outbound_client_discovery_attempt_packets", "client_leg_wireguard_data_datagrams",
            "exit_leg_wireguard_data_datagrams"))
    value = {key: raw[key] for key in keys}
    for key in keys:
        if key not in {"capture_role", "content_provider_mode", "truncated", "interfaces",
                       "interface_statistics", "provider_application", "content_control_pairs",
                       "content_control_packets"}:
            require(integer(value[key]), "invalid capture counter")
    require(type(value["interfaces"]) is list and 0 < len(value["interfaces"]) <= 16
        and all(type(name) is str and re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", name)
            for name in value["interfaces"]), "invalid capture interfaces")
    shape(value["interface_statistics"], value["interfaces"])
    value["interface_statistics"] = {name: {key: row[key] for key in (
        "observed_frames", "packet_socket_packets", "packet_socket_drops", "intake_stopped")}
        for name, row in value["interface_statistics"].items()}
    for row in value["interface_statistics"].values():
        require(all(integer(row[key]) for key in ("observed_frames", "packet_socket_packets",
            "packet_socket_drops")) and type(row["intake_stopped"]) is bool, "invalid interface counters")
    shape(value["provider_application"], PROVIDERS)
    value["provider_application"] = {name: {key: row[key] for key in (
        "request_packets", "response_packets", "response_payload_bytes")}
        for name, row in value["provider_application"].items()}
    require(all(integer(count) for row in value["provider_application"].values()
        for count in row.values()), "invalid provider counters")
    if control:
        shape(value["content_control_packets"], ("cp0", "cp1"))
        for row in value["content_control_packets"].values():
            shape(row, ("inbound", "outbound"))
            require(all(integer(count) for count in row.values()), "invalid control counters")
    return value


def route_projection(raw):
    require(type(raw["paths"]) is list and len(raw["paths"]) == 2
        and type(raw["benchmark_slots"]) is list and len(raw["benchmark_slots"]) == 2,
        "exactly two selected paths required")
    return dict(transport=raw["transport"], route_context_id=raw["route_context_id"],
        paths=[{key: row[key] for key in ("route_context_id", "path_id", "relay_peer_id", "exit_peer_id")}
            for row in raw["paths"]], benchmark_slots=[{key: row[key] for key in ("relay_node", "relay_peer_id")}
            for row in raw["benchmark_slots"]])


def validate_evidence(value, revision):
    shape(value, ("source_revision", "layout", "gates", "inputs", "cases", "operations", "expected_peers",
        "selected_route", "live_route", "privacy", "control_privacy", "control_before", "control_after", "scope"))
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision,
        "exact source binding required")
    require(same(value["scope"], SCOPE) and same(value["inputs"], INPUTS), "scope or public inputs changed")
    layout, gates, peers = value["layout"], value["gates"], value["expected_peers"]
    shape(layout, ("provider_nodes", "quote_provider", "control_relay_peer_id", "provider_key",
        "requester_key", "wrong_requester_key"))
    nodes = layout["provider_nodes"]
    require(type(nodes) is list and len(nodes) == len(set(nodes)) == 2
        and all(node in PROVIDERS for node in nodes) and layout["quote_provider"] == nodes[0],
        "independent provider selection required")
    shape(peers, (*ROLES, *PROVIDERS))
    require(all(type(peer) is str and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{10,128}", peer)
        for peer in peers.values()) and len(set(peers.values())) == len(peers), "distinct public node identities required")
    keys = [layout[key] for key in ("provider_key", "requester_key", "wrong_requester_key")]
    require(all(type(key) is str and re.fullmatch(r"[0-9a-f]{64}", key) and key != "0" * 64
        for key in keys) and len(set(keys)) == 3, "distinct public signing keys required")
    require(keys == [peer_key(peers[node]) for node in (nodes[0], "client", nodes[1])],
        "signing keys do not bind the selected provider and requester identities")
    controls = [node for node, peer in peers.items() if peer == layout["control_relay_peer_id"]]
    require(len(controls) == 1 and controls[0].startswith("relay") and controls[0] not in nodes,
        "independent discovery relay required")
    require(value["control_before"] == value["control_after"] == layout["control_relay_peer_id"],
        "control relay changed")
    shape(gates, ("wrong", "device_unavailable", "repeat", "grant", "device", "detach_wrong",
        "detach_valid", "provider_stopped", "client_disconnected"))
    shape(value["cases"], ("wrong", "device-unavailable", "repeat"))
    for case, delta in (("wrong", 1), ("device-unavailable", 0), ("repeat", 1)):
        gate = gates[case.replace("-", "_")]
        shape(gate, ("exit_status", "stdout_empty", "signed_exchange_failures_before", "signed_exchange_failures_after"))
        before, after = gate["signed_exchange_failures_before"], gate["signed_exchange_failures_after"]
        require(integer(before) and integer(after) and after - before == delta
            and type(gate["exit_status"]) is int and gate["exit_status"] == 1
            and gate["stdout_empty"] is (case != "device-unavailable"), "wrong failure stage or command status")
        case_value = value["cases"][case]
        shape(case_value, ("exit_status", "stdout"))
        require(type(case_value["exit_status"]) is int and case_value["exit_status"] == 1
            and (same(case_value["stdout"], REFUSAL) if delta == 0 else case_value["stdout"] is None),
            "only the authenticated device refusal may return a closed result")
    shape(gates["grant"], ("max_seconds", "max_attempts", "wrong_key_distinct", "requester_key_bound"))
    require(integer(gates["grant"]["max_seconds"], 1, 600)
        and type(gates["grant"]["max_attempts"]) is int and gates["grant"]["max_attempts"] == 1
        and gates["grant"]["wrong_key_distinct"] is True and gates["grant"]["requester_key_bound"] is True,
        "finite exact requester authority required")
    require(same(gates["device"], dict(provider_mount_checked=True, fixed_device_absent=True))
        and all(gates[key] is True for key in ("detach_wrong", "detach_valid", "provider_stopped", "client_disconnected")),
        "real device boundary or final cleanup incomplete")
    shape(value["operations"], ("attach-wrong", "attach-valid", "detach-wrong", "detach-valid", "stop"))
    for name, receipt in value["operations"].items():
        require(same(receipt, dict(serving=name != "stop", publications=0)), "quote-only service operation incomplete")
    route = route_projection(value["selected_route"])
    require(same(route, route_projection(value["live_route"])) and route["transport"] == "mptcp"
        and re.fullmatch(r"[0-9a-f]{32}", route["route_context_id"]), "selected route changed")
    paths, slots = route["paths"], route["benchmark_slots"]
    require(len({row["path_id"] for row in paths}) == 2 and all(integer(row["path_id"], 1) for row in paths)
        and len({row["relay_peer_id"] for row in paths}) == 2
        and all(row["exit_peer_id"] == peers["exit"] and row["route_context_id"] == route["route_context_id"] for row in paths)
        and all(slot["relay_node"] in ROLES[1:4] and peers[slot["relay_node"]] == slot["relay_peer_id"] == path["relay_peer_id"]
            for slot, path in zip(slots, paths)), "same exit and two distinct selected relay bindings required")
    shape(value["privacy"], ROLES)
    privacy = value["privacy"]
    for role in ROLES:
        capture = capture_projection(privacy[role])
        require(same(capture, privacy[role]) and capture["capture_role"] == role
            and capture["content_provider_mode"] is True
            and all(capture[key] == 0 for key in ("unexpected_outer_packets", "expected_link_down_notifications",
                "unexpected_provider_application_packets", "direct_client_exit_packets")), "physical privacy violation")
        COMMON["validate_drained"](capture, allow_empty=role in ROLES[1:4])
        if role != "exit":
            require(capture["internet_destination_outer_packets"] == 0 and all(count == 0
                for row in capture["provider_application"].values() for count in row.values()), "unprotected provider traffic")
    require(privacy["exit"]["client_public_packets"] == privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0,
        "exit learned direct client address or discovery")
    active = privacy["exit"]["provider_application"][nodes[0]]
    require(all(active[key] > 0 for key in ("request_packets", "response_packets", "response_payload_bytes"))
        and active["response_payload_bytes"] <= 65536 and all(count == 0
            for node, row in privacy["exit"]["provider_application"].items() if node != nodes[0] for count in row.values()),
        "bounded real quote provider exchange required")
    require(any(privacy[slot["relay_node"]]["client_leg_wireguard_data_datagrams"] > 0
        and privacy[slot["relay_node"]]["exit_leg_wireguard_data_datagrams"] > 0 for slot in slots),
        "no selected relay carried traffic")
    control = capture_projection(value["control_privacy"], control=True)
    require(same(control, value["control_privacy"]), "control receipt is not closed")
    COMMON["validate_control"](control, controls[0], nodes, missing=True)


def build_evidence(work, revision):
    def item(name):
        return read(work / ("protected-quote-" + name + ".json"))
    cases = {}
    for name in ("wrong", "device-unavailable", "repeat"):
        status = bytes_at(work / ("protected-quote-" + name + ".status"), 8)
        require(status in (b"1", b"1\n"), "quote CLI must exit one, not timeout or signal")
        raw = bytes_at(work / ("protected-quote-" + name + ".json"), 4096)
        require(raw == b"" if name != "device-unavailable" else bool(raw), "unexpected CLI output")
        cases[name] = dict(exit_status=1, stdout=decode(raw) if raw else None)
    peers = read(work / "a01-expected-peers.json")
    value = dict(source_revision=revision, layout=item("layout"), gates=item("gates"), inputs=item("inputs"), cases=cases,
        expected_peers={name: peers[name] for name in (*ROLES, *PROVIDERS)},
        operations={name: {key: item(name)[key] for key in ("serving", "publications")}
            for name in ("attach-wrong", "attach-valid", "detach-wrong", "detach-valid", "stop")},
        selected_route=route_projection(item("selected-route")), live_route=route_projection(item("live-selection")),
        control_before=item("status-before")["control_relay_peer_id"], control_after=item("status-after")["control_relay_peer_id"],
        privacy={role: capture_projection(item("privacy-" + role)) for role in ROLES},
        control_privacy=capture_projection(item("control-privacy"), control=True), scope=SCOPE)
    validate_evidence(value, revision)
    return value


def validate_report(value, revision):
    shape(value, ("schema_version", "report_kind", "source_revision", "success", "phase", "observed_blocker",
        "runner_exit_status", "cleanup", "host_state", "evidence"))
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["report_kind"] == "volparossa-protected-quote-refusal-route" and value["source_revision"] == revision
        and value["success"] is True and type(value["runner_exit_status"]) is int and value["runner_exit_status"] == 0
        and value["phase"] == "protected-quote-complete" and value["observed_blocker"] is None
        and same(value["cleanup"], dict(complete=True, remaining_owned_objects=0))
        and same(value["host_state"], dict(unchanged=True)), "route trial or cleanup incomplete")
    validate_evidence(value["evidence"], revision)


def finalize(work, output, revision, status, complete, remaining, phase, blocker):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and re.fullmatch(r"[a-z0-9-]{1,96}", phase)
        and re.fullmatch(r"[A-Z0-9_]{1,96}", blocker), "invalid final metadata")
    require(complete in ("true", "false") and re.fullmatch(r"[0-9]{1,6}", remaining)
        and re.fullmatch(r"[0-9]{1,3}", status) and int(status) <= 255, "invalid cleanup status")
    evidence, unchanged = None, False
    try:
        evidence = read(work / "protected-quote-route-evidence.json")
        validate_evidence(evidence, revision)
        unchanged = read(work / "a15-evidence.json")["unchanged"] is True
    except (KeyError, TypeError, ValueError, OSError):
        evidence = None
    value = dict(schema_version=1, report_kind="volparossa-protected-quote-refusal-route", source_revision=revision,
        success=False, phase=phase, observed_blocker=None if blocker == "NONE" else blocker,
        runner_exit_status=int(status), cleanup=dict(complete=complete == "true", remaining_owned_objects=int(remaining)),
        host_state=dict(unchanged=unchanged), evidence=evidence)
    value["success"] = (status == "0" and complete == "true" and remaining == "0" and unchanged
        and evidence is not None and phase == "protected-quote-complete" and blocker == "NONE")
    write(output / EXPORT_NAMES[0], value)
    validate_report(value, revision)


def validate_vm_cleanup(value, revision):
    shape(value, ("schema_version", "source_revision", "qemu_started", "qemu_joined", "private_guest_state_removed"))
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
        and re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision
        and all(value[key] is True for key in ("qemu_started", "qemu_joined", "private_guest_state_removed")),
        "original source-bound outer VM cleanup required")


def main(args):
    if args == ["export-names"]:
        print("\n".join(EXPORT_NAMES)); return
    if len(args) == 3 and args[0] == "prepare":
        prepare(Path(args[1]), Path(args[2]))
    elif len(args) == 3 and args[0] == "evidence":
        work = Path(args[1])
        write(work / "protected-quote-route-evidence.json", build_evidence(work, args[2]))
    elif len(args) == 9 and args[0] == "finalize":
        finalize(Path(args[1]), Path(args[2]), *args[3:])
    elif len(args) == 3 and args[0] == "report":
        validate_report(read(Path(args[1])), args[2])
    elif len(args) == 3 and args[0] == "vm-report":
        validate_vm_cleanup(read(Path(args[1])), args[2])
    else:
        raise ValueError("unknown quote-route command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError):
        print("Protected quote route evidence incomplete; no private diagnostics exported", file=sys.stderr)
        sys.exit(1)
