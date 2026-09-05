#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded benchmark selection metadata; never a payload/subflow proof."""
import json
import re
import sys
from pathlib import Path


def selected_paths(text, relay0, relay1, relay2, exit_peer, transport):
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
    result = dict(schema_version=1, transport=transport,
                  source="agent committed route selection; not per-path payload proof",
                  route_context_id=paths[0]["route_context_id"],
                  exact_selected_relays=[p["relay_peer_id"] for p in paths],
                  exact_selected_exit=exit_peer, paths=paths)
    return (0 if {p["relay_peer_id"] for p in paths} <= {relay1, relay2} else 2), result


def main():
    source, output, r0, r1, r2, exit_peer, transport = sys.argv[1:]
    with open(source, encoding="ascii") as stream:
        text = stream.read(65537)
    status, result = selected_paths(text, r0, r1, r2, exit_peer, transport)
    if result is not None:
        Path(output).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
                                encoding="ascii")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
