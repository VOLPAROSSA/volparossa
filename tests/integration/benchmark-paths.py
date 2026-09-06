#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded benchmark selection metadata; never a payload/subflow proof."""
import json
import re
import sys
from pathlib import Path


def selected_paths(text, relay0, relay1, relay2, exit_peer, transport, any_pair=False):
    if len(text) > 65536 or transport not in {"mptcp", "multipath-quic", "single-path-udp"}:
        return 3, None
    pattern = re.compile(
        r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) "
        r"state=([0-9]+) rtt_us=([0-9]+) bytes=([0-9]+)"
    )
    paths = []
    for line in text.splitlines():
        if not line:
            continue
        match = pattern.fullmatch(line)
        if match is None:
            return 3, None
        context, path, relay, exit_id, state, rtt, count = match.groups()
        paths.append(dict(route_context_id=context, path_id=int(path), relay_peer_id=relay,
                          exit_peer_id=exit_id, state=int(state), smoothed_rtt_us=int(rtt),
                          reported_bytes=int(count)))
        if len(paths) > 8:
            return 3, None
    if not paths:
        return 1, None
    required_count = 1 if transport == "single-path-udp" else 2
    if (len(paths) != required_count or len({p["route_context_id"] for p in paths}) != 1
            or paths[0]["route_context_id"] == "0" * 32
            or len({p["path_id"] for p in paths}) != required_count
            or len({p["relay_peer_id"] for p in paths}) != required_count
            or not {p["relay_peer_id"] for p in paths} <= {relay0, relay1, relay2}
            or {p["exit_peer_id"] for p in paths} != {exit_peer}):
        return 3, None
    if any(p["state"] not in {1, 2, 3, 4} for p in paths):
        return 3, None
    paths.sort(key=lambda p: p["path_id"])
    indexes = {relay0: 0, relay1: 1, relay2: 2}
    if len(indexes) != 3:
        return 3, None
    slots = [dict(slot=slot, relay_index=indexes[path["relay_peer_id"]],
                  relay_node=f"relay{indexes[path['relay_peer_id']]}",
                  relay_peer_id=path["relay_peer_id"], path_id=path["path_id"])
             for slot, path in enumerate(paths, 1)]
    result = dict(schema_version=1, transport=transport,
                  source="agent committed route selection; not per-path payload proof",
                  route_context_id=paths[0]["route_context_id"],
                  exact_selected_relays=[p["relay_peer_id"] for p in paths],
                  exact_selected_exit=exit_peer, paths=paths, benchmark_slots=slots,
                  counter_labels=("relay1/relay2 denote ordered benchmark slots, not node names"
                                  if any_pair else "relay1/relay2 denote physical topology nodes"))
    return (0 if any_pair or {p["relay_peer_id"] for p in paths} <= {relay1, relay2} else 2), result


def privacy_evidence(captures, selections):
    roles = {"client", "exit", "relay0", "relay1", "relay2"}
    selected_nodes = sorted({slot["relay_node"] for selected in selections
                             for slot in selected["benchmark_slots"]})
    geometry = all(
        selected.get("transport") == "mptcp"
        and len(selected.get("paths", [])) == 2
        and len(selected.get("benchmark_slots", [])) == 2
        and len({slot["relay_node"] for slot in selected["benchmark_slots"]}) == 2
        and all(slot["relay_node"] == f"relay{slot['relay_index']}"
                and slot["relay_index"] in {0, 1, 2}
                and slot["relay_peer_id"] == path["relay_peer_id"]
                and slot["path_id"] == path["path_id"]
                for slot, path in zip(selected["benchmark_slots"], selected["paths"]))
        for selected in selections
    )
    complete = set(captures) == roles and all(
        capture.get("capture_role") == role and capture.get("truncated") is False
        and capture.get("packet_socket_drops") == 0
        and capture.get("observed_frames", 0) > 0
        for role, capture in captures.items()
    )
    relay_private = all(
        captures[role].get("internet_destination_outer_packets") == 0
        and captures[role].get("unexpected_outer_packets") == 0
        and {f"r{role[-1]}c", f"r{role[-1]}x"} <= set(captures[role].get("interfaces", []))
        for role in roles - {"client", "exit"}
    )
    used_paths = all(
        captures[role].get("client_leg_wireguard_data_datagrams", 0) > 0
        and captures[role].get("exit_leg_wireguard_data_datagrams", 0) > 0
        and captures["client"].get(f"{role}_wireguard_data_datagrams", 0) > 0
        and captures["exit"].get(f"{role}_wireguard_data_datagrams", 0) > 0
        for role in selected_nodes
    )
    no_direct = (captures["client"].get("direct_client_exit_packets") == 0
                 and captures["exit"].get("direct_client_exit_packets") == 0
                 and captures["exit"].get("client_public_packets") == 0
                 and captures["exit"].get("outbound_client_discovery_attempt_packets") == 0)
    return dict(schema_version=1, success=(len(selections) == 4 and geometry and complete
                                          and relay_private and used_paths and no_direct),
                scope="A02-A04 MPTCP window; all three physical Relay pairs, Client and Exit",
                selected_relay_nodes=selected_nodes, selected_routes=selections,
                captures=captures, payload_capture_retained=False)


def write_privacy(work):
    def read(name):
        with (work / name).open(encoding="ascii") as stream:
            text = stream.read(1048577)
        if len(text) > 1048576:
            raise ValueError("bounded benchmark evidence exceeded")
        return json.loads(text)

    captures = {role: read(f"mptcp-privacy-{role}.json")
                for role in ("client", "exit", "relay0", "relay1", "relay2")}
    selections = [read(f"{case}-selected-paths.json")
                  for case in ("a02", "a03-single", "a03-aggregate", "a04")]
    evidence = privacy_evidence(captures, selections)
    (work / "mptcp-privacy-evidence.json").write_text(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    return 0 if evidence["success"] else 1


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--privacy":
        return write_privacy(Path(sys.argv[2]))
    source, output, r0, r1, r2, exit_peer, transport, *options = sys.argv[1:]
    if options not in ([], ["--any-pair"]):
        return 3
    with open(source, encoding="ascii") as stream:
        text = stream.read(65537)
    status, result = selected_paths(text, r0, r1, r2, exit_peer, transport, bool(options))
    if result is not None:
        Path(output).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
                                encoding="ascii")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
