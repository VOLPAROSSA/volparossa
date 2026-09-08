#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded real HTTP/3 MPQUIC 2-to-3 proof; no throughput-improvement claim."""

import hashlib
import json
from pathlib import Path
import re
import runpy
import sys
import time

COMMON = runpy.run_path(str(Path(__file__).with_name("content-network-smoke.py")))
read, require = COMMON["read"], COMMON["require"]
ROLES = ("client", "relay0", "relay1", "relay2", "exit")
BODY_BYTES = 32 * 1024 * 1024
MIN_DELTA = 65536
PREFIX = "mpquic-growth"


def text(path):
    require(not path.is_symlink(), "symlink evidence rejected")
    with path.open(encoding="ascii") as source:
        value = source.read(65537)
    require(len(value) <= 65536, "text evidence exceeds bound")
    return value


def paths(value):
    pattern = re.compile(r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) "
                         r"state=([0-6]) rtt_us=([0-9]+) bytes=([0-9]+) acked_transport_bytes=([0-9]+)")
    rows = []
    for line in value.splitlines():
        match = pattern.fullmatch(line)
        require(match is not None, "malformed native path row")
        context, path, relay, exit_peer, state, rtt, user_count, transport_count = match.groups()
        require(all(int(value) <= 2**64 - 1 for value in (rtt, user_count, transport_count)),
                "native path counters exceed their u64 representation")
        rows.append(dict(route_context_id=context, path_id=int(path), relay_peer_id=relay,
                         exit_peer_id=exit_peer, state=int(state), smoothed_rtt_us=int(rtt),
                         user_bytes=int(user_count), acked_transport_bytes=int(transport_count)))
    require(2 <= len(rows) <= 3 and len({row["path_id"] for row in rows}) == len(rows)
            and len({row["relay_peer_id"] for row in rows}) == len(rows)
            and len({row["route_context_id"] for row in rows}) == 1
            and rows[0]["route_context_id"] != "0" * 32,
            "native path snapshot is not one bounded original context")
    return dict(route_context_id=rows[0]["route_context_id"], paths=sorted(rows, key=lambda row: row["path_id"]),
                observed_monotonic_ns=time.monotonic_ns())


def initial(snapshot, peers):
    rows = snapshot["paths"]
    require(len(rows) == 3 and sorted(row["state"] for row in rows) == [3, 3, 4]
            and {row["relay_peer_id"] for row in rows} == {peers[f"relay{i}"] for i in range(3)}
            and {row["exit_peer_id"] for row in rows} == {peers["exit"]}
            and all(row["acked_transport_bytes"] == row["smoothed_rtt_us"] == 0
                    for row in rows if row["state"] == 4),
            "need two actual native paths and one reserved backup on exactly R0/R1/R2")


def bound(snapshot, selection):
    expected = {row["path_id"]: row for row in selection["paths"]}
    require(snapshot["route_context_id"] == selection["route_context_id"], "route context changed")
    for row in snapshot["paths"]:
        original = expected.get(row["path_id"])
        require(original is not None and all(row[key] == original[key] for key in
                ("route_context_id", "relay_peer_id", "exit_peer_id")), "native identity rebound")


def progress(before, after, count):
    active = {row["path_id"]: row for row in before["paths"] if row["state"] == 3}
    current = {row["path_id"]: row for row in after["paths"]}
    require(len(active) == count and after["observed_monotonic_ns"] > before["observed_monotonic_ns"],
            "wrong active baseline or non-forward observation time")
    require(all(path in current and current[path]["state"] == 3
                and current[path]["acked_transport_bytes"] - row["acked_transport_bytes"] >= MIN_DELTA
                for path, row in active.items()), "every active native path needs fresh substantial ACKed transport progress")


def payload_hash(run_id, direction):
    require(re.fullmatch(r"[0-9a-f]{32}", run_id) is not None, "invalid run identity")
    seed = b"volparossa-http3:mpquic-growth:" + direction.encode() + b":" + bytes.fromhex(run_id)
    block = seed * (65536 // len(seed))
    digest, remaining = hashlib.sha256(), BODY_BYTES
    while remaining >= len(block):
        digest.update(block)
        remaining -= len(block)
    digest.update((seed * (remaining // len(seed) + 1))[:remaining])
    return digest.hexdigest()


def drained(capture, allow_empty=False):
    statistics = capture["interface_statistics"]
    require(capture["truncated"] is False and capture["packet_socket_drops"] == 0
            and capture["observed_frames"] >= (0 if allow_empty else 1)
            and set(statistics) == set(capture["interfaces"])
            and sum(row["observed_frames"] for row in statistics.values()) == capture["observed_frames"]
            and all(row["intake_stopped"] is True and row["packet_socket_drops"] == 0
                    and row["packet_socket_packets"] == row["observed_frames"] for row in statistics.values()),
            "physical capture was not complete and exactly drained")


def privacy(captures, all_three, warm_role):
    require(set(captures) == set(ROLES), "five-role capture coverage missing")
    for role, capture in captures.items():
        silent_backup = not all_three and role == warm_role
        drained(capture, allow_empty=silent_backup)
        if silent_backup and capture["observed_frames"] == 0:
            require(all(value == 0 for key, value in capture.items()
                        if key.endswith(("_packets", "_datagrams"))),
                    "silent reserved backup has nonzero packet counters")
        require(capture["capture_role"] == role and capture["unexpected_outer_packets"] == 0
                and capture["expected_link_down_notifications"] == 0,
                "unexpected traffic or unrelated link disruption")
        if role.startswith("relay"):
            index = role[-1]
            require({f"r{index}c", f"r{index}x", "underlay"} == set(capture["interfaces"])
                    and capture["internet_destination_outer_packets"] == 0,
                    "relay physical coverage/privacy incomplete")
            if all_three or role != warm_role:
                require(capture["client_leg_wireguard_data_datagrams"] > 16
                        and capture["exit_leg_wireguard_data_datagrams"] > 16,
                        "all six selected WireGuard legs need fresh expanded-window data")
    client, exit_capture = captures["client"], captures["exit"]
    require({"cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cb1", "cb2", "underlay"}
            == set(client["interfaces"])
            and {"xr0", "xr1", "xr2", "xr3", "xr4", "xr5", "xd", "underlay"}
            == set(exit_capture["interfaces"])
            and client["direct_client_exit_packets"] == client["internet_destination_outer_packets"] == 0
            and exit_capture["direct_client_exit_packets"] == exit_capture["client_public_packets"] == 0
            and exit_capture["outbound_client_discovery_attempt_packets"] == 0,
            "Client/Exit physical isolation failed")


def qdisc(value, injected):
    require(isinstance(value, list) and len(value) == 1, "unexpected qdisc tree")
    row = value[0]
    if not injected:
        require(row["kind"] == "noqueue" and row["handle"] == "0:", "owned link was not unshaped")
        return
    options = row["options"]
    # iproute2 q_netem.c emits loss as a fraction, not percentage points.
    require(row["kind"] == "netem" and row["handle"] == "7a01:"
            and abs(options["loss-random"]["loss"] - 0.15) < 0.000001
            and options["loss-random"].get("correlation", 0) == 0
            and not any(key in options for key in ("delay", "rate", "duplicate", "reorder", "corrupt", "slot")),
            "loss injection differs from fixed independent15percent profile")


def validate(evidence):
    require(evidence["success"] is True, "growth flow failed")
    selection, peers = evidence["selection"], evidence["expected_peers"]
    initial(selection, peers)
    snapshots = [evidence[key] for key in ("before_loss", "expanded", "expanded_progress", "after_restore")]
    for snapshot in snapshots:
        bound(snapshot, selection)
    require([selection["observed_monotonic_ns"], *[row["observed_monotonic_ns"] for row in snapshots]]
            == sorted({selection["observed_monotonic_ns"], *[row["observed_monotonic_ns"] for row in snapshots]}),
            "native lifecycle snapshots are not strictly ordered")
    progress(selection, evidence["before_loss"], 2)
    initial(evidence["before_loss"], peers)
    require(len(evidence["expanded"]["paths"]) == 3
            and all(row["state"] == 3 for row in evidence["expanded"]["paths"]),
            "nominal backup does not prove actual2-to3 activation")
    progress(evidence["expanded"], evidence["expanded_progress"], 3)
    warm_peer = next(row["relay_peer_id"] for row in selection["paths"] if row["state"] == 4)
    warm_role = next(role for role in ROLES[1:4] if peers[role] == warm_peer)
    for phase in ("initial", "expanded"):
        privacy(evidence["privacy"][phase], phase == "expanded", warm_role)
    injection = evidence["injection"]
    target = next((row for row in selection["paths"] if row["path_id"] == injection["path_id"]), None)
    require(target is not None and target["state"] == 3
            and peers[injection["relay_node"]] == target["relay_peer_id"]
            and injection["interface"] == f"r{injection['relay_node'][-1]}x"
            and injection["loss_percent"] == 15, "loss was not scoped to one original active relay leg")
    qdisc(injection["before"], False)
    qdisc(injection["during"], True)
    qdisc(injection["after"], False)
    require(injection["during"][0]["drops"] > 0, "configured loss without actual dropped packets is insufficient")
    client, server = evidence["client"], evidence["server"]
    for receipt in (client, server):
        require(receipt["case"] == PREFIX and receipt["protocol"] == receipt["http_version"] == "HTTP/3"
                and receipt["negotiated_alpn"] == "h3" and receipt["hostname"] == "destination.volparossa.test"
                and receipt["request_bytes"] == receipt["response_bytes"] == BODY_BYTES
                and receipt["request_sha256"] == payload_hash(evidence["run_id"], "request")
                and receipt["response_sha256"] == payload_hash(evidence["run_id"], "response"),
                "complete real HTTP3 request/response hashes do not match this run")
    require(server["source"]["ip"] == "47.163.4.1" and 0 < server["source"]["port"] <= 65535
            and server["listen"] == dict(ip="47.163.4.2", port=443)
            and server["peer_completion_observed"] is True and server["release_observed"] is False
            and client["application"] == dict(ip="43.159.1.1", port=52008)
            and client["destination"] == dict(ip="47.163.4.2", port=443)
            and client["transfer_elapsed_ns"] > 0 and client["response_duration_ns"] > 0
            and type(client["endpoint_drain_completed"]) is bool and client["endpoint_drain_budget_ms"] == 5000,
            "HTTP3 source, ordinary application or exact authenticated completion missing")
    require(evidence["cleanup"] == dict(client_exit_status=0, server_exit_status=0,
            route_disconnected=True, active_contexts=0, paths_empty=True, loss_removed=True),
            "application/route/qdisc cleanup incomplete")


def build_evidence(work):
    work = Path(work)
    final = text(work / f"{PREFIX}-final-status.txt").splitlines()
    require("connected: false" in final and "active contexts: 0" in final
            and text(work / f"{PREFIX}-final-paths.txt") == "", "raw final route not retired")
    result = {key: read(work / f"{PREFIX}-{suffix}.json") for key, suffix in (
        ("selection", "selection"), ("before_loss", "before-loss"), ("expanded", "expanded"),
        ("expanded_progress", "expanded-progress"), ("after_restore", "after-restore"),
        ("client", "client"), ("server", "server"), ("cleanup", "cleanup"), ("injection", "injection"))}
    for key, suffix in (("selection", "selection"), ("before_loss", "before-loss"),
                        ("expanded", "expanded"), ("expanded_progress", "expanded-progress"),
                        ("after_restore", "after-restore")):
        native = paths(text(work / f"{PREFIX}-{suffix}.txt"))
        require(all(native[field] == result[key][field] for field in ("route_context_id", "paths")),
                "projected native receipt differs from actual CLI path text")
    result.update(success=True, run_id=read(work / f"{PREFIX}-run.json")["run_id"],
                  expected_peers=read(work / "a01-expected-peers.json"),
                  privacy={phase: {role: read(work / f"{PREFIX}-{phase}-privacy-{role}.json")
                                   for role in ROLES} for phase in ("initial", "expanded")})
    for stage in ("before", "during", "after"):
        result["injection"][stage] = json.loads(text(work / f"{PREFIX}-qdisc-{stage}.json"))
    validate(result)
    return result


def validate_report(path, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None and not path.is_symlink(),
            "invalid exact source revision/report path")
    with path.open(encoding="ascii") as source:
        raw = source.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "report exceeds bound")
    report = json.loads(raw)
    require(report["schema_version"] == 1 and report["report_kind"] == "volparossa-mpquic-growth-runtime"
            and report["source_revision"] == revision and report["success"] is True
            and report["phase"] == "mpquic-growth-complete" and report["observed_blocker"] in (None, "NONE")
            and report["cleanup"] == dict(complete=True, remaining_owned_objects=0),
            "wrong source, incomplete phase or unsuccessful owned-object cleanup")
    require(report["host_state"]["success"] is True and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"],
            "parent host-state evidence does not prove no changes")
    for stage in ("before", "after"):
        host_path = path.parent / f"host-state-{stage}.json"
        require(not host_path.is_symlink(), "symlink host snapshot rejected")
        with host_path.open("rb") as source:
            payload = source.read(8 * 1024 * 1024 + 1)
        require(len(payload) <= 8 * 1024 * 1024
                and hashlib.sha256(payload).hexdigest() == report["host_state"][f"{stage}_sha256"],
                "raw exported host-state hash differs from the source-bound report")
    rebuilt = build_evidence(path.parent)
    require(report["transfer"] == rebuilt and report["run_id"] == rebuilt["run_id"]
            and read(path.parent / f"{PREFIX}-evidence.json") == rebuilt,
            "source-bound report differs from its exact raw lifecycle/capture reconstruction")


def main():
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "report":
        validate_report(Path(args[1]), args[2])
        return
    if len(args) == 3 and args[0] == "evidence":
        result = build_evidence(Path(args[1]))
    elif len(args) == 4 and args[0] in ("select", "sample"):
        result = paths(text(Path(args[1])))
        if args[0] == "select":
            initial(result, read(Path(args[2])))
        else:
            bound(result, read(Path(args[2])))
    elif len(args) == 4 and args[0] == "progress":
        require(args[3] in ("2", "3"), "invalid progress count")
        progress(read(Path(args[1])), read(Path(args[2])), int(args[3]))
        return
    elif len(args) == 3 and args[0] == "qdisc":
        require(args[2] in ("plain", "loss"), "invalid qdisc phase")
        qdisc(json.loads(text(Path(args[1]))), args[2] == "loss")
        return
    else:
        raise ValueError("usage: evidence WORK OUT | report REPORT SHA | select PATHS PEERS OUT | sample PATHS SELECTION OUT | progress BEFORE AFTER 2|3 | qdisc FILE plain|loss")
    Path(args[-1]).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"MPQUIC growth proof unavailable: {error}", file=sys.stderr)
        sys.exit(1)
