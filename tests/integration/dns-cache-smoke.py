#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Normal protected DNS requests and exact source-scoped C05 evidence, not DNSSEC forgery."""
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
import time

def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

WIRE = module("dns-cache-fixture.py", "dns_fixture")
CAPTURE = module("dns-cache-capture.py", "dns_capture")
PHASES = CAPTURE.PHASES
METRICS = tuple("volparossa_dns_" + suffix for suffix in (
    "upstream_validated_total", "peer_validated_total", "local_validated_total",
    "trusted_fallback_total", "cache_miss_replies_total"))
PUBLIC = CAPTURE.PUBLIC


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, maximum=4 * 1024 * 1024):
    require(not path.is_symlink(), "symlink evidence")
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    require(len(data) <= maximum, "evidence size")
    return json.loads(data)


def write(path, value):
    with path.open("x", encoding="ascii") as target:
        json.dump(value, target, sort_keys=True, separators=(",", ":"))
        target.write("\n")


def metrics():
    WIRE.require_isolated()
    connection = http.client.HTTPConnection("127.0.0.1", 9767, timeout=2)
    try:
        connection.request("GET", "/metrics")
        response = connection.getresponse()
        data = response.read(16385)
        require(response.status == 200 and len(data) <= 16384, "bounded local metrics unavailable")
    finally:
        connection.close()
    result = {}
    for line in data.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in METRICS:
            require(fields[0] not in result and re.fullmatch(r"[0-9]+", fields[1]), "invalid fixed metric")
            result[fields[0]] = int(fields[1])
    require(set(result) == set(METRICS), "missing fixed DNS metrics")
    return result


def query(name, family):
    WIRE.require_isolated()
    require(name in (WIRE.CANDIDATE, "destination.volparossa.test") and family in ("A", "AAAA"), "fixed DNS question")
    kind = 1 if family == "A" else 28
    transaction = int.from_bytes(os.urandom(2), "big")
    question = WIRE.name_wire(name) + struct.pack("!HH", kind, 1)
    request = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + question
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as application:
        application.settimeout(30)
        application.sendto(request, ("9.9.9.9", 53))
        response, source = application.recvfrom(4097)
    require(source == ("9.9.9.9", 53) and 12 <= len(response) <= 4096, "DNS transparent source/size")
    header = struct.unpack_from("!6H", response)
    require(header[0] == transaction and header[1] & 0x8000 and not header[1] & 0x7A0F
            and header[2] == 1 and 1 <= header[3] <= 16 and header[4:] == (0, 0), "DNS response header")
    actual_name, position = WIRE.read_name(response, 12)
    require(actual_name == name and response[position:position + 4] == struct.pack("!HH", kind, 1), "DNS question changed")
    position += 4
    addresses, ttls = [], []
    for _ in range(header[3]):
        owner, position = WIRE.read_name(response, position)
        require(position + 10 <= len(response), "short DNS answer")
        actual_type, dns_class, ttl, length = struct.unpack_from("!HHIH", response, position)
        position += 10
        require(owner == name and actual_type == kind and dns_class == 1 and 0 < ttl <= 30
                and length == (4 if kind == 1 else 16) and position + length <= len(response), "DNS answer binding")
        addresses.append(str(ipaddress.ip_address(response[position:position + length])))
        ttls.append(ttl)
        position += length
    require(position == len(response), "DNS trailing bytes")
    return {"name": name, "family": family, "addresses": sorted(set(addresses)), "ttls": ttls,
            "application_protocol": "UDP", "resolver": {"ip": "9.9.9.9", "port": 53},
            "response_source": {"ip": source[0], "port": source[1]},
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "completed_at_unix_ms": int(time.time() * 1000),
            "request_bytes": len(request), "response_bytes": len(response),
            "response_sha256": hashlib.sha256(response).hexdigest(), "ad_used_as_proof": False}


def selection(text, peers, wanted):
    require(len(text) <= 65536 and wanted in ("exit", "exit2"), "selection bound")
    rows = [line for line in text.splitlines() if line]
    if not rows:
        return 1, None
    require(len(rows) == 1, "DNS route must have exactly one relay")
    match = re.fullmatch(r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) state=([1-4]) rtt_us=([0-9]+) bytes=([0-9]+)(?: acked_transport_bytes=0)?", rows[0])
    require(match is not None, "DNS selected route shape")
    context, path, relay, exit_peer, state, rtt, count = match.groups()
    exits = {peers[node]: node for node in ("exit", "exit2")}
    relays = {peers[node]: node for node in ("relay0", "relay1", "relay2")}
    require(context != "0" * 32 and exit_peer in exits and relay in relays, "unknown selected endpoint")
    result = {"route_context_id": context, "path_id": int(path), "relay_peer_id": relay,
              "relay_node": relays[relay], "exit_peer_id": exit_peer, "exit_node": exits[exit_peer],
              "transport": "protected-dns", "state": int(state), "rtt_us": int(rtt), "reported_bytes": int(count)}
    require(result["state"] == 1 and result["rtt_us"] == result["reported_bytes"] == 0,
            "DNS prewarm must report reachability without invented traffic or RTT")
    # Both Exits have actual adjacent links to every admitted data relay in this scenario.
    return (0 if result["exit_node"] == wanted else 2), result


def delta(before, after, metric):
    require(set(before) == set(after) == set(METRICS) and all(type(value) is int and value >= 0
            for value in (*before.values(), *after.values())), "DNS aggregate shape")
    require(all(after[key] >= before[key] for key in METRICS), "DNS aggregate reset")
    return after["volparossa_dns_" + metric + "_total"] - before["volparossa_dns_" + metric + "_total"]


def complete_capture(record, role, layout):
    require(record["complete"] is True and record["truncated"] is False and record["node"] == role
            and record["phase"] == layout["phase"] and record["packet_socket_drops"] == 0
            and record["forbidden_packets"] == record["direct_client_exit_packets"] == record["unexpected_dns_packets"] == 0,
            "DNS capture incomplete or boundary violation")
    rows = record["interface_statistics"]
    require(set(rows) == set(record["interfaces"]) == CAPTURE.PHYSICAL_INTERFACES[role] and 0 < len(rows) <= 16
            and all(row["intake_stopped"] is True and row["drained"] is True
                    and row["packet_socket_drops"] == 0 and row["forbidden_packets"] == 0
                    and row["packet_socket_packets"] == row["observed_frames"] for row in rows.values())
            and sum(row["observed_frames"] for row in rows.values()) == record["observed_frames"], "DNS exact capture accounting")


def validate_phase(phase, evidence, expected, peers):
    wanted = "exit" if phase.startswith("warm-") else "exit2"
    route, app, layout, captures = (evidence[key] for key in ("selection", "application", "layout", "captures"))
    require(route["exit_node"] == wanted and route["exit_peer_id"] == peers[wanted]
            and route["relay_peer_id"] == peers[route["relay_node"]] and route["transport"] == "protected-dns",
            "ordinary DNS route changed endpoint")
    require(re.fullmatch(r"[0-9a-f]{32}", route["route_context_id"]) and route["route_context_id"] != "0" * 32
            and 1 <= route["path_id"] <= 8 and route["state"] == 1
            and route["rtt_us"] == route["reported_bytes"] == 0, "DNS route identity/readiness")
    CAPTURE.validate_layout(layout)
    require(layout == {"phase": phase, "exit_node": wanted, "relays": {route["relay_node"]: PUBLIC[route["relay_node"]]}},
            "capture route correlation")
    family = "AAAA" if phase.endswith("aaaa") else "A"
    name = "destination.volparossa.test" if phase == "unsigned-b" else WIRE.CANDIDATE
    addresses = ["47.163.4.2"] if phase == "unsigned-b" else expected[family]
    require(app["name"] == name and app["family"] == family and app["addresses"] == addresses
            and app["resolver"] == app["response_source"] == {"ip": "9.9.9.9", "port": 53}
            and app["ad_used_as_proof"] is False and app["ttls"] and all(0 < ttl <= 30 for ttl in app["ttls"]),
            "ordinary DNS answer differs from actual root-validated source")
    before, after = evidence["metrics_before"][wanted], evidence["metrics_after"][wanted]
    mode = "upstream_validated" if phase.startswith("warm-") else "peer_validated" if phase.startswith("peer-") \
        else "trusted_fallback" if phase == "unsigned-b" else "local_validated"
    for other in ("upstream_validated", "peer_validated", "local_validated", "trusted_fallback"):
        require(delta(before, after, other) == (1 if mode == other else 0), "DNS source counter not exact")
    require(set(captures) == {"client", "exit", "exit2", "destination", route["relay_node"]}, "missing DNS role capture")
    for role, record in captures.items():
        complete_capture(record, role, layout)
    relay = captures[route["relay_node"]]
    require(captures["client"]["client_leg_wireguard_data_datagrams"] > 0
            and relay["client_leg_wireguard_data_datagrams"] > 0 and relay["exit_leg_wireguard_data_datagrams"] > 0
            and captures[wanted]["exit_leg_wireguard_data_datagrams"] > 0, "both genuine WireGuard legs did not carry DNS")
    if phase.startswith("warm-"):
        require(captures["exit"]["upstream_request_payload_bytes"] > 0
                and captures["destination"]["upstream_response_payload_bytes"] > 0, "ExitA did not collect real chain")
    else:
        require(all(record["upstream_request_packets"] == record["upstream_response_packets"] == 0
                    for record in captures.values()), "peer/local/fallback phase triggered recursive DNS")
    if phase.startswith("peer-") or phase == "unsigned-b":
        require(captures["exit"]["cross_exit_control_packets"] > 0
                and captures["exit2"]["cross_exit_control_packets"] > 0, "no actual authenticated peer transport")
    if phase == "unsigned-b":
        require(delta(evidence["metrics_before"]["exit"], evidence["metrics_after"]["exit"], "cache_miss_replies") >= 1
                and delta(evidence["metrics_before"]["exit"], evidence["metrics_after"]["exit"], "upstream_validated") == 0,
                "cache-only miss reply/fallback boundary unproven")


def build_evidence(work):
    expected = read(work / "dns-cache-expected.json")
    preflight = read(work / "dns-cache-core-proof.json")
    peers = read(work / "a01-expected-peers.json")
    result = {"success": True, "expected": expected, "preflight": preflight, "expected_peers": peers, "phases": {}}
    config = read(work / "dns-cache-config.json")
    result["configuration"] = config
    for phase in PHASES:
        prefix = "dns-cache-" + phase
        value = {key: read(work / (prefix + "-" + key.replace("_", "-") + ".json"))
                 for key in ("selection", "application", "layout", "metrics_before", "metrics_after")}
        value["captures"] = {role: read(work / (prefix + "-capture-" + role + ".json"))
                             for role in ("client", "exit", "exit2", "destination", value["selection"]["relay_node"])}
        result["phases"][phase] = value
    stopped = read(work / "dns-cache-peer-stopped.json")
    result["peer_stopped"] = stopped
    result["upstream"] = {phase: read(work / ("dns-cache-" + phase + "-upstream.json")) for phase in PHASES}
    validate_evidence(result)
    return result


def validate_evidence(evidence):
    require(evidence["success"] is True and set(evidence["phases"]) == set(PHASES), "incomplete DNS network phases")
    expected, preflight = evidence["expected"], evidence["preflight"]
    require(preflight["success"] is True and preflight["scope"] == "builtin-anchor-collector-and-local-cache-only"
            and preflight["candidate_name"] == WIRE.CANDIDATE and preflight["source_url"] == WIRE.SOURCE_URL
            and preflight["normal_client_route_proven"] is False and preflight["peer_cache_proven"] is False
            and len(preflight["core"]) == 2 and set(expected) == {"A", "AAAA"}
            and {answer["family"]: sorted(answer["addresses"]) for answer in preflight["core"]} == expected
            and all(answer["source"] == "UpstreamValidated" and answer["builtin_anchors"] is True
                    and answer["local_reuse"] is True and answer["ttl_seconds"] > 0
                    and re.fullmatch(r"[0-9a-f]{64}", answer["proof_sha256"]) for answer in preflight["core"]),
            "real unchanged-anchor fixture preflight missing")
    require(evidence["configuration"] == {"exit_upstream": "47.163.4.2:53", "exit2_upstream": None,
                       "positive_name_in_hosts": False, "other_nodes_cache_disabled": True,
                       "production_root_anchors_unchanged": True}, "DNS fixture configuration authority")
    require(evidence["peer_stopped"] == {"node": "exit", "agent_active": False, "main_pid": 0},
            "cache peer not genuinely stopped")
    require(set(evidence["upstream"]) == set(PHASES), "missing bounded upstream observations")
    for phase, value in evidence["phases"].items():
        validate_phase(phase, value, expected, evidence["expected_peers"])
        if phase != "unsigned-b":
            family = value["application"]["family"]
            expiry = next(row["expires_at_ms"] for row in preflight["core"] if row["family"] == family)
            require(0 < value["application"]["completed_at_unix_ms"] < expiry, "original public proof expired")
        replay = evidence["upstream"][phase]
        require(replay["listener_closed"] is True and replay["bounded_stop"] is True and replay["rejected"] == 0
                and replay["cryptographically_verified"] is False, "upstream cleanup/malformed requests")
        require((2 <= replay["connections"] <= 128) if phase.startswith("warm-") else replay["connections"] == 0,
                "recursive traffic outside upstream-warm phase")


def validate_report(report, revision):
    require(report["source_revision"] == revision and re.fullmatch(r"[0-9a-f]{40}", revision)
            and report["schema_version"] == 1 and report["report_kind"] == "volparossa-dns-cache"
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["full_c05_claimed"] is False
            and report["full_alpha_acceptance_claimed"] is False
            and report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["success"] is True and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"], "DNS report/cleanup/source failure")
    validate_evidence(report["dns"])


if __name__ == "__main__":
    try:
        mode, *args = sys.argv[1:]
        if mode == "metrics":
            print(json.dumps(metrics(), sort_keys=True))
        elif mode == "query":
            print(json.dumps(query(args[0], args[1]), sort_keys=True))
        elif mode == "select":
            with Path(args[0]).open(encoding="ascii") as paths:
                status, value = selection(paths.read(65537), read(Path(args[1])), args[2])
            if value is not None:
                write(Path(args[3]), value)
            raise SystemExit(status)
        elif mode == "evidence":
            write(Path(args[1]), build_evidence(Path(args[0])))
        elif mode == "report":
            validate_report(read(Path(args[0])), args[1])
        else:
            raise ValueError("unknown DNS fixture mode")
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        raise SystemExit("DNS evidence rejected: " + str(error)) from None
