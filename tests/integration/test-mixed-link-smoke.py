#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure generated-observer and mixed-report checks; no network sockets or mutations."""

import copy
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent
SOURCE = (HERE / "kvm-alpha-topology.sh").read_text(encoding="utf-8")


def observer_source(name):
    return SOURCE.split(f'cat >"$WORK/bin/{name}" <<\'PYTHON\'\n', 1)[1].split(
        "\nPYTHON\n", 1
    )[0]


def wireguard_frame(source, destination):
    payload = struct.pack("<I", 4) + bytes(100)
    udp = struct.pack("!HHHH", 51820, 51821, len(payload) + 8, 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
        socket.inet_aton(source), socket.inet_aton(destination),
    )
    return bytes(12) + struct.pack("!H", 0x0800) + ipv4 + udp


class Capture:
    def __init__(self, frames):
        self.frames = iter(frames)

    def bind(self, _address):
        pass

    def setblocking(self, _enabled):
        pass

    def setsockopt(self, *_args):
        pass

    def getsockopt(self, *_args):
        return struct.pack("II", 0, 0)

    def recv(self, _maximum):
        try:
            return next(self.frames)
        except StopIteration as error:
            raise BlockingIOError from error

    def close(self):
        pass


def capture(name, role, interfaces, frames, local):
    with tempfile.TemporaryDirectory(prefix="volparossa-mixed-observer-") as directory:
        output = Path(directory) / "capture.json"
        args = [name, role, str(output), str(Path(directory) / "ready")]
        if name == "a06-observer.py":
            args.append("-")
        if local:
            args.append("--direct-lan-relay1")
        args.extend(interfaces)
        sockets = [Capture(packets) for packets in frames]
        with (
            patch("sys.argv", args),
            patch("socket.socket", side_effect=sockets),
            patch("select.select", return_value=(sockets, [], [])),
            patch("signal.signal"),
            patch("time.monotonic", side_effect=[0, 1, 2000]),
        ):
            exec(compile(observer_source(name), name, "exec"), {})
        return json.loads(output.read_text(encoding="ascii"))


class MixedLinkTests(unittest.TestCase):
    def test_bandwidth_comparison_keeps_real_path_payload_and_gain_gates(self):
        def records():
            result = {}
            privacy = []
            for index, case in enumerate(("single", "aggregate")):
                prefix = "mixed-link-" + case
                context = str(index + 1) * 32
                native = {"route_context_id": context, "paths": [
                    {"relay_peer_id": relay, "exit_peer_id": "exit", "state": 3, "path_id": path + 1}
                    for path, relay in enumerate(("lan", "wan"))]}
                app = {"case": "mixed-" + case, "protocol": "HTTP/3", "http_version": "HTTP/3",
                    "negotiated_alpn": "h3", "application": {"ip": "43.159.1.1", "port": 52016 + index},
                    "destination": {"ip": "47.163.4.2", "port": 443}, "request_bytes": 4194304,
                    "response_bytes": 33554432, "request_sha256": "a" * 64,
                    "response_sha256": str(index + 1) * 64,
                    "response_duration_ns": 40_000_000_000 if case == "single" else 25_000_000_000}
                destination = dict(app, source={"ip": "47.163.4.1"}, release_observed=True,
                                   peer_completion_observed=True)
                result[prefix + "-client.json"] = app
                result[prefix + "-destination.json"] = destination
                for stage in ("before", "request-active", "after"):
                    result[prefix + "-" + stage + ".json"] = copy.deepcopy(native)
                for role in ("client", "exit"):
                    result[prefix + "-" + role + "-capture.json"] = {
                        "truncated": False, "packet_socket_drops": 0, "observed_frames": 100,
                        "marker_observed": True, "after_marker": {
                            "relay1_wireguard_data_bytes": 0 if case == "single" else 16_777_216,
                            "relay2_wireguard_data_bytes": 34_000_000 if case == "single" else 17_777_216,
                            "relay1_received_wireguard_data_bytes": 0 if case == "single" else 16_777_216,
                            "relay2_received_wireguard_data_bytes": 34_000_000 if case == "single" else 17_777_216}}
                result[prefix + "-response-qdisc-bytes.json"] = {
                    "relay1": 0 if case == "single" else 16_777_216,
                    "relay2": 34_000_000 if case == "single" else 17_777_216}
                for interface in ("r1c", "r1x"):
                    result[prefix + "-" + interface + "-release.json"] = [{
                        "ifname": interface, "ifindex": 3 if interface == "r1c" else 4,
                        "flags": [] if case == "single" and interface == "r1c" else ["UP"]}]
                for role in ("client", "relay1", "relay2", "exit"):
                    down = case == "single" and role == "relay1"
                    privacy.append({"benchmark": "mixed-" + case, "capture_role": role,
                        "truncated": False, "packet_socket_drops": 0, "observed_frames": 100,
                        "unexpected_outer_packets": 0, "direct_client_exit_packets": 0,
                        "internet_destination_outer_packets": 4 if role == "exit" else 0,
                        "client_public_packets": 0,
                        "expected_link_down_notifications": int(down),
                        "expected_link_down_interfaces": {"r1c": 1} if down else {}})
            result["mixed-link-bandwidth-privacy.json"] = privacy
            for interface in ("r1c", "r2c"):
                result["mixed-link-shape-" + interface + ".json"] = [
                    {"kind": "tbf", "root": True, "options": {"rate": 1_000_000}}]
            return result

        def evaluate(data):
            with tempfile.TemporaryDirectory(prefix="volparossa-mixed-bandwidth-") as temporary:
                work = Path(temporary)
                for name, record in data.items():
                    (work / name).write_text(json.dumps(record), encoding="ascii")
                run = subprocess.run(["sh", "-c", '. "$1"; WORK=$2; R1_PEER=lan; R2_PEER=wan; '
                    'EXIT_PEER=exit; mixed_link_bandwidth_validate', "mixed-bandwidth-test",
                    str(HERE / "mixed-link-smoke.sh"), temporary], capture_output=True, text=True)
                return run.returncode, run.stderr

        valid = records()
        self.assertEqual(evaluate(valid), (0, ""))
        for mutation in (
            lambda d: d["mixed-link-aggregate-client.json"].update(response_duration_ns=32_000_000_000),
            lambda d: d["mixed-link-aggregate-after.json"]["paths"].pop(),
            lambda d: d["mixed-link-aggregate-request-active.json"]["paths"][0].update(state=1),
            lambda d: d["mixed-link-aggregate-before.json"].update(route_context_id="1" * 32),
            lambda d: d["mixed-link-single-r1c-release.json"][0].update(flags=["UP"]),
            lambda d: d["mixed-link-single-r1x-release.json"][0].update(flags=[]),
            lambda d: d["mixed-link-aggregate-r1c-release.json"][0].update(ifindex=9),
            lambda d: d["mixed-link-single-client-capture.json"]["after_marker"].update(relay1_received_wireguard_data_bytes=1),
            lambda d: d["mixed-link-aggregate-exit-capture.json"]["after_marker"].update(relay1_wireguard_data_bytes=0),
            lambda d: d["mixed-link-aggregate-client-capture.json"].update(packet_socket_drops=1),
            lambda d: d["mixed-link-aggregate-destination.json"].update(response_sha256="bad"),
            lambda d: d["mixed-link-single-destination.json"]["source"].update(ip="43.159.1.1"),
            lambda d: d["mixed-link-bandwidth-privacy.json"][0].update(unexpected_outer_packets=1),
            lambda d: d["mixed-link-bandwidth-privacy.json"][1].update(expected_link_down_interfaces={"r1x": 1}),
            lambda d: d["mixed-link-bandwidth-privacy.json"].pop(),
            lambda d: d["mixed-link-shape-r1c.json"][0]["options"].update(rate=8_000_000),
            lambda d: d["mixed-link-single-after.json"]["paths"][1].update(path_id=3),
        ):
            data = records()
            mutation(data)
            self.assertNotEqual(evaluate(data)[0], 0)

    def test_directional_received_payload_does_not_count_outbound_path_probes(self):
        for relay, pair, interface in (("relay1", ("10.241.11.1", "10.241.11.2"), "cr1"),
                                       ("relay2", ("43.159.1.1", "45.161.2.1"), "cr2")):
            outgoing = capture("a06-observer.py", "client", [interface], [[wireguard_frame(*pair)]], True)
            incoming = capture("a06-observer.py", "client", [interface], [[wireguard_frame(*reversed(pair))]], True)
            self.assertGreater(outgoing[relay + "_wireguard_data_bytes"], 0)
            self.assertEqual(outgoing[relay + "_received_wireguard_data_bytes"], 0)
            self.assertGreater(incoming[relay + "_received_wireguard_data_bytes"], 0)

    def test_http3_observer_requires_the_explicit_exact_lan_pairs(self):
        for role, interface, endpoints in [
            ("client", "cr1", ("10.241.11.1", "10.241.11.2")),
            ("exit", "xr1", ("10.241.21.1", "10.241.21.2")),
        ]:
            frame = wireguard_frame(*endpoints)
            local = capture("a06-observer.py", role, [interface], [[frame]], True)
            public = capture("a06-observer.py", role, [interface], [[frame]], False)
            self.assertEqual(local["relay1_wireguard_data_datagrams"], 1)
            self.assertGreater(local["relay1_wireguard_data_bytes"], 0)
            self.assertEqual(public["relay1_wireguard_data_datagrams"], 0)

    def test_public_observer_tuple_is_unchanged(self):
        frame = wireguard_frame("43.159.1.1", "44.160.1.1")
        public = capture("a06-observer.py", "client", ["cr1"], [[frame]], False)
        local = capture("a06-observer.py", "client", ["cr1"], [[frame]], True)
        self.assertEqual(public["relay1_wireguard_data_datagrams"], 1)
        self.assertEqual(local["relay1_wireguard_data_datagrams"], 0)

    def test_lan_relay_privacy_counts_both_legs_and_still_rejects_destination(self):
        result = capture(
            "privacy-observer.py", "relay1", ["r1c", "r1x"],
            [[wireguard_frame("10.241.11.1", "10.241.11.2")],
             [wireguard_frame("10.241.21.1", "10.241.21.2"),
              wireguard_frame("10.241.21.1", "47.163.4.2")]], True,
        )
        self.assertEqual(result["client_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(result["exit_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(result["internet_destination_outer_packets"], 1)
        self.assertEqual(result["unexpected_outer_packets"], 1)

    def test_private_client_identity_at_exit_is_a_leak(self):
        result = capture(
            "privacy-observer.py", "exit", ["xr1"],
            [[wireguard_frame("10.241.11.1", "10.241.21.2")]], True,
        )
        self.assertEqual(result["client_public_packets"], 1)
        self.assertEqual(result["direct_client_exit_packets"], 1)

    def test_mixed_report_rejects_wrong_exit_missing_payload_or_privacy_leak(self):
        counters = {
            "truncated": False, "observed_frames": 4,
            "expected_link_down_notifications": 0, "unexpected_outer_packets": 0,
            "direct_client_exit_packets": 0, "internet_destination_outer_packets": 0,
            "client_public_packets": 0, "client_leg_wireguard_data_datagrams": 2,
            "exit_leg_wireguard_data_datagrams": 2,
        }
        transfer = {"success": True, "native_mpquic": {"paths": [
            {"relay_peer_id": relay, "exit_peer_id": "exit", "state": 3,
             "native_acked_bytes": 0} for relay in ("lan", "wan")
        ]}, "path_evidence": {role: {"relay1_wireguard_data_bytes": 2097152,
                                    "relay2_wireguard_data_bytes": 2097152}
                              for role in ("client_capture", "exit_capture")}}
        for defect in (None, "exit", "encrypted_payload", "leg", "privacy", "truncation"):
            with tempfile.TemporaryDirectory(prefix="volparossa-mixed-report-") as directory:
                work = Path(directory)
                evidence = copy.deepcopy(transfer)
                captures = {role: dict(counters) for role in ("client", "relay1", "relay2", "exit")}
                if defect == "exit":
                    evidence["native_mpquic"]["paths"][0]["exit_peer_id"] = "another-exit"
                elif defect == "encrypted_payload":
                    evidence["path_evidence"]["client_capture"]["relay1_wireguard_data_bytes"] = 0
                elif defect == "leg":
                    captures["relay1"]["exit_leg_wireguard_data_datagrams"] = 0
                elif defect == "privacy":
                    captures["relay2"]["unexpected_outer_packets"] = 1
                elif defect == "truncation":
                    captures["client"]["truncated"] = True
                (work / "a06-evidence.json").write_text(json.dumps(evidence), encoding="ascii")
                for role, counters_for_role in captures.items():
                    (work / f"privacy-{role}.json").write_text(json.dumps(counters_for_role), encoding="ascii")
                result = subprocess.run(
                    ["sh", "-c", '. "$1"; WORK=$2; R1_PEER=lan; R2_PEER=wan; EXIT_PEER=exit; '
                     'mixed_link_snapshot_local_relay() { :; }; mixed_link_validate_evidence',
                     "mixed-link-test", str(HERE / "mixed-link-smoke.sh"), directory],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, defect is None, (defect, result.stderr))


if __name__ == "__main__":
    unittest.main()
