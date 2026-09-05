#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("benchmark_paths", HERE / "benchmark-paths.py")
paths_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paths_module)


def row(relay, path=1, context="11" * 16, state=1):
    return f"context={context} path={path} relay={relay} exit=X state={state} rtt_us=0 bytes=0\n"


class SelectionTests(unittest.TestCase):
    def parse(self, text, transport="mptcp"):
        return paths_module.selected_paths(text, "R0", "R1", "R2", "X", transport)

    def test_mptcp_committed_is_not_fake_active_or_bytes(self):
        status, result = self.parse(row("R1") + row("R2", 2))
        self.assertEqual(status, 0)
        self.assertEqual(result["transport"], "mptcp")
        self.assertTrue(all(p["state"] == 1 and p["reported_bytes"] == 0 for p in result["paths"]))

    def test_real_other_relay_draw_is_distinct_from_invalid_proof(self):
        status, result = self.parse(row("R0") + row("R2", 2), "multipath-quic")
        self.assertEqual(status, 2)
        self.assertEqual(result["exact_selected_relays"], ["R0", "R2"])
        for text in (row("R1") + row("R1", 2), row("R1") + row("R2", 1),
                     row("R1") + row("R2", 2, "22" * 16),
                     row("R1") + row("R3", 2), row("R1", state=6) + row("R2", 2),
                     row("R1").replace("exit=X", "exit=OTHER") + row("R2", 2),
                     row("R1") + row("R2", 2) + row("R0", 3), "not a path", "x" * 65537):
            self.assertEqual(self.parse(text)[0], 3)
        self.assertEqual(self.parse("")[0], 1)

    def test_single_udp_retains_actual_one_of_two_measured_relays(self):
        for relay in ("R1", "R2"):
            status, result = self.parse(row(relay, state=3), "single-path-udp")
            self.assertEqual(status, 0)
            self.assertEqual(result["exact_selected_relays"], [relay])
        self.assertEqual(self.parse(row("R0"), "single-path-udp")[0], 2)
        self.assertEqual(self.parse(row("R1") + row("R2", 2), "single-path-udp")[0], 3)

    def test_shell_redraw_is_bounded_and_precedes_application(self):
        with tempfile.TemporaryDirectory(prefix="benchmark-contract-", dir=HERE) as directory:
            script = r'''
set -eu
. "$1/benchmark-selection.sh"
WORK=$2; binary_directory=/unused; source_directory=/unused
draws=0; disconnected=0
timeout() { return 0; }
date() { printf '0\n'; }
sleep() { :; }
benchmark_disconnect_route() { disconnected=$((disconnected + 1)); }
benchmark_capture_paths() {
    draws=$((draws + 1))
    printf '{"draw":%s}\n' "$draws" >"$WORK/$1-selection.json"
    if [ "$draws" -lt "$ACCEPT_DRAW" ]; then return 2; fi
    return 0
}
benchmark_select_route test mptcp
printf '{"draws":%s,"disconnected":%s}\n' "$draws" "$disconnected"
'''
            outcome = subprocess.run(["sh", "-c", script, "test", str(HERE), directory],
                                     env={"PATH": "/usr/bin:/bin", "ACCEPT_DRAW": "2"},
                                     check=True, text=True, capture_output=True)
            self.assertEqual(json.loads(outcome.stdout), {"draws": 2, "disconnected": 1})
            evidence = Path(directory, "benchmark-selection-draws.jsonl").read_text().splitlines()
            self.assertEqual(len(evidence), 2)
            exhausted = subprocess.run(["sh", "-c", script, "test", str(HERE), directory],
                                      env={"PATH": "/usr/bin:/bin", "ACCEPT_DRAW": "99"},
                                      text=True, capture_output=True)
            self.assertEqual(exhausted.returncode, 1)
            self.assertEqual(len(Path(directory, "benchmark-selection-draws.jsonl").read_text().splitlines()), 34)


if __name__ == "__main__":
    unittest.main()
