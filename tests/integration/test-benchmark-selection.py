#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import copy
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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

    def test_mixed_slot1_is_actual_lan_and_wan_only_pair_is_not_accepted(self):
        for wan in (0, 2):
            status, selected = paths_module.selected_paths(
                row(f"R{wan}") + row("R1", 2), "R0", "R1", "R2", "X",
                "multipath-quic", lan_pair=True)
            self.assertEqual(status, 0)
            self.assertEqual([slot["relay_index"] for slot in selected["benchmark_slots"]], [1, wan])
            self.assertEqual([slot["path_id"] for slot in selected["benchmark_slots"]], [2, 1])
        self.assertEqual(paths_module.selected_paths(row("R0") + row("R2", 2),
            "R0", "R1", "R2", "X", "multipath-quic", lan_pair=True)[0], 2)

    def test_native_snapshot_never_rebinds_context_path_exit_or_surviving_slot(self):
        text = row("R0", state=3) + row("R1", 2, state=3)
        selected = paths_module.selected_paths(text, "R0", "R1", "R2", "X",
            "multipath-quic", lan_pair=True)[1]
        before = paths_module.native_paths(text, selected, "both")
        self.assertEqual(before["benchmark_slots"][0]["relay_node"], "relay1")
        after = paths_module.native_paths(row("R0", state=3), selected, "relay2")
        self.assertEqual(after["benchmark_slots"], before["benchmark_slots"])
        self.assertEqual(after["paths"][0]["relay"], "relay2")
        self.assertEqual(after["paths"][0]["relay_node"], "relay0")
        for bad in (text.replace("exit=X", "exit=Y"), text.replace("R0", "R2"),
                    text.replace("path=1", "path=3"),
                    text.replace("11" * 16, "22" * 16), text + row("R0", 3),
                    row("R1", 2, state=3), ""):
            with self.assertRaises(ValueError):
                paths_module.native_paths(bad, selected, "relay2")
        with self.assertRaises(ValueError):
            paths_module.native_paths(row("R0", state=3), selected, "both")

    def test_any_valid_pair_maps_exact_nodes_without_changing_context(self):
        for first, second in ((0, 1), (0, 2), (1, 2), (2, 0)):
            status, result = paths_module.selected_paths(
                row(f"R{first}") + row(f"R{second}", 2), "R0", "R1", "R2", "X", "mptcp", True)
            self.assertEqual(status, 0)
            self.assertEqual(result["route_context_id"], "11" * 16)
            self.assertEqual([slot["relay_index"] for slot in result["benchmark_slots"]], [first, second])
            with tempfile.TemporaryDirectory(prefix="benchmark-map-") as directory:
                selection = Path(directory) / "selected.json"
                selection.write_text(json.dumps(result))
                script = r'''
set -eu
. "$1/benchmark-selection.sh"
R0=fixed0; R1=fixed1; R2=fixed2
benchmark_bind_slots "$2"
native_bind_slots "$2"
[ "$NATIVE_NS1" = "$BENCH_NS1" ] && [ "$NATIVE_NS2" = "$BENCH_NS2" ]
[ "$NATIVE_NODE1" = "$BENCH_NODE1" ] && [ "$NATIVE_NODE2" = "$BENCH_NODE2" ]
[ "$NATIVE_CLIENT_IF1" = "$BENCH_CLIENT_IF1" ] && [ "$NATIVE_CLIENT_IF2" = "$BENCH_CLIENT_IF2" ]
[ "$NATIVE_CONTEXT" = 11111111111111111111111111111111 ]
printf '%s\n' "$R0 $R1 $R2" "$BENCH_NS1 $BENCH_NODE1 $BENCH_CLIENT_IF1 $BENCH_RELAY_IF1 $BENCH_EXIT_IF1" "$BENCH_NS2 $BENCH_NODE2 $BENCH_CLIENT_IF2 $BENCH_RELAY_IF2 $BENCH_EXIT_IF2"
'''
                outcome = subprocess.run(["sh", "-c", script, "test", str(HERE), str(selection)],
                                         capture_output=True, text=True, check=True)
                self.assertEqual(outcome.stdout.splitlines(), ["fixed0 fixed1 fixed2",
                    f"fixed{first} relay{first} cr{first} r{first}c xr{first}",
                    f"fixed{second} relay{second} cr{second} r{second}c xr{second}"])

    def test_all_used_relays_require_both_legs_and_complete_privacy(self):
        captures = {}
        for role in ("client", "exit", "relay0", "relay1", "relay2"):
            captures[role] = dict(capture_role=role, truncated=False, packet_socket_drops=0,
                observed_frames=10, internet_destination_outer_packets=0, unexpected_outer_packets=0,
                client_leg_wireguard_data_datagrams=2, exit_leg_wireguard_data_datagrams=2,
                relay0_wireguard_data_datagrams=2, relay1_wireguard_data_datagrams=2,
                relay2_wireguard_data_datagrams=2, direct_client_exit_packets=0,
                client_public_packets=0, outbound_client_discovery_attempt_packets=0,
                interfaces=[f"r{role[-1]}c", f"r{role[-1]}x"])
        selected = paths_module.selected_paths(row("R0") + row("R2", 2), "R0", "R1", "R2", "X", "mptcp", True)[1]
        evidence = paths_module.privacy_evidence(captures, [selected] * 4)
        self.assertTrue(evidence["success"])
        self.assertEqual(evidence["selected_relay_nodes"], ["relay0", "relay2"])
        for role, field, value in (("relay0", "exit_leg_wireguard_data_datagrams", 0),
                                   ("relay0", "client_leg_wireguard_data_datagrams", 0),
                                   ("relay0", "internet_destination_outer_packets", 1),
                                   ("relay0", "unexpected_outer_packets", 1),
                                   ("client", "relay0_wireguard_data_datagrams", 0),
                                   ("exit", "relay0_wireguard_data_datagrams", 0),
                                   ("exit", "client_public_packets", 1)):
            bad = copy.deepcopy(captures)
            bad[role][field] = value
            self.assertFalse(paths_module.privacy_evidence(bad, [selected] * 4)["success"], (role, field))
        for role in captures:
            for field, value in (("packet_socket_drops", 1), ("packet_socket_drops", None),
                                  ("truncated", True)):
                bad = copy.deepcopy(captures)
                bad[role][field] = value
                self.assertFalse(paths_module.privacy_evidence(bad, [selected] * 4)["success"])
            bad = copy.deepcopy(captures)
            del bad[role]["packet_socket_drops"]
            self.assertFalse(paths_module.privacy_evidence(bad, [selected] * 4)["success"])

    def test_generated_observer_counts_actual_r0_interfaces_in_correct_slot(self):
        source = (HERE / "kvm-alpha-topology.sh").read_text()
        observer = source.split('cat >"$WORK/bin/a02-observer.py" <<\'PYTHON\'\n', 1)[1].split("\nPYTHON\n", 1)[0]
        public = {0: "42.158.0.1", 1: "44.160.1.1", 2: "45.161.2.1"}

        class Capture:
            def __init__(self, frame):
                self.frames = [frame]

            def bind(self, _address):
                pass

            def setblocking(self, _enabled):
                pass

            def recv(self, _maximum):
                if not self.frames:
                    raise BlockingIOError
                return self.frames.pop()

            def close(self):
                pass

        def frame(source, destination):
            ipv4 = bytearray(20)
            ipv4[0] = 0x45
            ipv4[9] = socket.IPPROTO_UDP
            ipv4[12:16] = socket.inet_aton(source)
            ipv4[16:20] = socket.inet_aton(destination)
            return (b"\0" * 12 + b"\x08\x00" + ipv4
                    + struct.pack("!HHHH", 20000, 30000, 44, 0)
                    + struct.pack("<I", 4) + b"\0" * 32)

        for indexes in ((0, 1), (0, 2), (2, 0)):
            for role in ("client", "exit"):
                captures = [Capture(frame("43.159.1.1", public[index]) if role == "client"
                                    else frame(public[index], "46.162.3.1")) for index in indexes]
                namespace = {}

                def ready(*_args):
                    namespace["running"] = False
                    return captures, [], []

                with tempfile.TemporaryDirectory(prefix="benchmark-observer-") as directory:
                    output = Path(directory) / "capture.json"
                    args = ["observer", role, str(output), str(Path(directory) / "ready"), "-",
                            "--benchmark-relays", *(str(index) for index in indexes),
                            *(f"{'cr' if role == 'client' else 'xr'}{index}" for index in indexes)]
                    with (patch("sys.argv", args), patch("socket.socket", side_effect=captures),
                          patch("signal.signal"), patch("select.select", side_effect=ready),
                          patch("time.monotonic", return_value=1)):
                        exec(compile(observer, "a02-observer.py", "exec"), namespace)
                    record = json.loads(output.read_text())
                self.assertEqual(record["benchmark_relay_nodes"], [f"relay{i}" for i in indexes])
                self.assertEqual(record["relay1_wireguard_data_datagrams"], 1)
                self.assertEqual(record["relay2_wireguard_data_datagrams"], 1)
                self.assertFalse(record["truncated"])

    def test_generated_native_observer_uses_actual_r0_slot_and_direction(self):
        # Use the existing mixed-observer packet harness, but feed real public R0/R2 tuples.
        module_spec = importlib.util.spec_from_file_location("mixed_test", HERE / "test-mixed-link-smoke.py")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        public = {0: "42.158.0.1", 2: "45.161.2.1"}
        for indexes in ((0, 2), (2, 0)):
            for role in ("client", "exit"):
                peer = "43.159.1.1" if role == "client" else "46.162.3.1"
                frames = [[module.wireguard_frame(peer, public[index]),
                           module.wireguard_frame(public[index], peer)] for index in indexes]
                interfaces = ["--benchmark-relays", *(str(index) for index in indexes),
                              *(f"{'cr' if role == 'client' else 'xr'}{index}" for index in indexes)]
                record = module.capture("a06-observer.py", role, interfaces, frames, False)
                self.assertEqual(record["benchmark_relay_nodes"], [f"relay{i}" for i in indexes])
                for slot in (1, 2):
                    self.assertEqual(record[f"relay{slot}_wireguard_data_datagrams"], 2)
                    if role == "client":
                        self.assertEqual(record[f"relay{slot}_received_wireguard_data_bytes"], 104)
                self.assertEqual(record["packet_socket_drops"], 0)
                self.assertFalse(record["truncated"])

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


class A07FreshRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (HERE / "kvm-alpha-topology.sh").read_text()
        cls.prepare = "a07_prepare_fresh_native_route() {" + cls.source.split(
            "a07_prepare_fresh_native_route() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        block = cls.source.split('if [ "$A07_STATUS" -eq 0 ]; then\n    jq -S -c -n', 1)[1]
        block = block.split('>"$WORK/a07-evidence.json"', 1)[0]
        cls.predicate = block[block.index("'($application[0])") + 1:block.rindex("'")]

    def fixtures(self):
        selected = paths_module.selected_paths(row("R0", context="22" * 16, state=3)
            + row("R2", 2, "22" * 16, 3), "R0", "R1", "R2", "X",
            "multipath-quic", any_pair=True)[1]
        text = row("R0", context="22" * 16, state=3) + row("R2", 2, "22" * 16, 3)
        before = paths_module.native_paths(text, selected, "both")
        after = paths_module.native_paths(row("R2", 2, "22" * 16, 3), selected, "relay2")
        a06 = paths_module.selected_paths(row("R1", state=3) + row("R2", 2, state=3),
            "R0", "R1", "R2", "X", "multipath-quic", any_pair=True)[1]
        windows = {label: {key: item[key] for key in ("route_context_id", "benchmark_slots")}
                   for label, item in (("a06", a06), ("a07", before))}
        application = dict(protocol="HTTP/3", http_version="HTTP/3", negotiated_alpn="h3",
            application=dict(ip="43.159.1.1", port=52007), destination=dict(ip="47.163.4.2", port=443),
            request_bytes=4194304, response_bytes=33554432, request_sha256="a" * 64,
            response_sha256="b" * 64)
        destination = dict(protocol="HTTP/3", http_version="HTTP/3", negotiated_alpn="h3",
            peer_completion_observed=True, release_observed=True, source=dict(ip="47.163.4.1"),
            request_sha256="a" * 64, response_sha256="b" * 64)
        capture = dict(benchmark_relay_nodes=["relay0", "relay2"], marker_observed=True,
            direct_client_exit_packets=0, truncated=False, packet_socket_drops=0,
            destination_request_datagrams=2, destination_response_datagrams=2,
            before_marker={f"relay{slot}_wireguard_data_{field}": value
                           for slot in (1, 2) for field, value in (("bytes", 1048577), ("datagrams", 2))},
            after_marker=dict(relay2_wireguard_data_bytes=1048577, relay2_wireguard_data_datagrams=2))
        removal = dict(process_active_at_removal=True, removed_relay="relay0",
            removed_links=dict(relay_client_operstate="DOWN", relay_exit_operstate="DOWN"))
        return dict(application=application, destination=destination,
            client_capture=copy.deepcopy(capture), exit_capture=copy.deepcopy(capture),
            preconnect=copy.deepcopy(before), native_before=before, native_after=after,
            native_windows=windows, removal=removal)

    def evaluate(self, data):
        args = ["jq", "-c", "-n"]
        for key, value in data.items():
            args.extend(["--argjson", key, json.dumps([value])])
        return json.loads(subprocess.run([*args, self.predicate], check=True,
                                        text=True, capture_output=True).stdout)

    def test_fresh_preconnect_precedes_application_and_fails_closed_in_order(self):
        invocation = self.source.index("\na07_prepare_fresh_native_route || fail ")
        observer = self.source.index("\nstart_http3_observers a07 ")
        application = self.source.index('"$WORK/bin/examples/http3-acceptance-fixture" client a07 ')
        self.assertLess(invocation, observer)
        self.assertLess(observer, application)
        script = self.prepare + r'''
WORK=$1; fail_step=$2
step() { printf '%s\n' "$1" >>"$WORK/order"; [ "$fail_step" != "$1" ]; }
benchmark_disconnect_route() { step disconnect; }
benchmark_select_route() { [ "$1:$2" = a07-fresh:multipath-quic ] && step select; }
native_bind_slots() { [ "$1" = "$WORK/a07-fresh-selection.json" ] && step bind; }
wait_active_native_mpquic_paths() { [ "$1" = a07-native-preconnect ] && step active; }
a07_prepare_fresh_native_route || exit 1
'''
        data = self.fixtures()
        for failed, expected in (("", ["disconnect", "select", "bind", "active"]),
                                 ("disconnect", ["disconnect"]),
                                 ("select", ["disconnect", "select"]),
                                 ("bind", ["disconnect", "select", "bind"]),
                                 ("active", ["disconnect", "select", "bind", "active"]),
                                 ("same-context", ["disconnect", "select", "bind", "active"])):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory(prefix="a07-prepare-") as tmp:
                work = Path(tmp)
                old = copy.deepcopy(data["native_windows"]["a06"])
                if failed == "same-context":
                    old["route_context_id"] = data["preconnect"]["route_context_id"]
                (work / "a06-native-paths.json").write_text(json.dumps(old))
                (work / "a07-native-preconnect.json").write_text(json.dumps(data["preconnect"]))
                outcome = subprocess.run(["sh", "-c", script, "test", tmp, failed],
                                         text=True, capture_output=True)
                self.assertEqual(outcome.returncode, 1 if failed else 0, outcome.stderr)
                self.assertEqual((work / "order").read_text().splitlines(), expected)
                if not failed:
                    self.assertEqual(json.loads((work / "native-route-windows.json").read_text()),
                                     data["native_windows"])

    def test_actual_a07_predicate_binds_one_flow_to_fresh_context_and_exact_paths(self):
        data = self.fixtures()
        result = self.evaluate(data)
        self.assertTrue(result["success"])
        self.assertEqual(result["native_route_windows"], data["native_windows"])
        self.assertNotEqual(data["native_windows"]["a06"]["benchmark_slots"],
                            data["native_windows"]["a07"]["benchmark_slots"])
        for stage in ("preconnect", "native_before", "native_after"):
            for field, value in (("route_context_id", "33" * 16), ("benchmark_slots", [])):
                bad = copy.deepcopy(data)
                bad[stage][field] = value
                self.assertFalse(self.evaluate(bad)["success"], (stage, field))
        bad = copy.deepcopy(data)
        bad["native_after"]["paths"][0]["path_id"] = 7
        self.assertFalse(self.evaluate(bad)["success"])
        for field in ("peer_completion_observed", "release_observed"):
            bad = copy.deepcopy(data)
            bad["destination"][field] = False
            self.assertFalse(self.evaluate(bad)["success"])

    def test_existing_byte_and_privacy_gates_remain_strict(self):
        data = self.fixtures()
        for role in ("client_capture", "exit_capture"):
            for stage, slots in (("before_marker", (1, 2)), ("after_marker", (2,))):
                for slot in slots:
                    bad = copy.deepcopy(data)
                    bad[role][stage][f"relay{slot}_wireguard_data_bytes"] = 1048576
                    self.assertFalse(self.evaluate(bad)["success"], (role, stage, slot))
            bad = copy.deepcopy(data)
            bad[role]["truncated"] = True
            self.assertFalse(self.evaluate(bad)["success"])
        bad = copy.deepcopy(data)
        bad["client_capture"]["direct_client_exit_packets"] = 1
        self.assertFalse(self.evaluate(bad)["success"])
        for acceptance in ("A11", "A12", "A13"):
            section = self.source.split(f"{acceptance}_STATUS=1\njq", 1)[1].split(
                f'>"$WORK/{acceptance.lower()}-evidence.json"', 1)[0]
            self.assertIn('--slurpfile native_windows "$WORK/native-route-windows.json"', section)
            self.assertIn("native_route_windows:$native_windows[0]", section)
            self.assertIn(".packet_socket_drops == 0", section)


if __name__ == "__main__":
    unittest.main()
