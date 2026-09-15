#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure phase/tuple/interface counter tests; no packet sockets or network execution."""

import copy
from pathlib import Path
import runpy
import socket
import struct
import unittest

HERE = Path(__file__).resolve().parent
REP = runpy.run_path(str(HERE / "content-replication-smoke.py"))
CAP = REP["CAPTURE"]
BASE = runpy.run_path(str(HERE / "test-content-replication-smoke.py"))
FRAME = runpy.run_path(str(HERE / "test-content-replication-capture.py"))
WG = struct.pack("<I", 4) + bytes(44)


def layout():
    return dict(phase="peer-learning", client=dict(node="relay3", ip=CAP["LEARNER_IP"]),
        provider=dict(node="relay4", ip=CAP["PUBLIC"]["relay4"]), exit=dict(node="exit", ip=CAP["PUBLIC"]["exit"]),
        relays={node: CAP["PUBLIC"][node] for node in ("relay0", "relay2")})


def packet(current, node, iface, source, destination, protocol=socket.IPPROTO_UDP, sport=22000, dport=23000, payload=WG):
    return CAP["classify"](current, node, protocol, source, sport, destination, dport, payload, iface)


def phase(control="relay1"):
    old = BASE["fixture"](control)
    current = copy.deepcopy(old["phases"]["reserve-fetch"])
    current["layout"].update(phase="peer-learning", client=dict(node="relay3", ip=CAP["LEARNER_IP"]))
    for role, capture in current["captures"].items():
        node = "relay3" if role == "receiver" else capture["node"]
        interfaces = REP["physical_interfaces"](current["layout"], node)
        capture.update(phase="peer-learning", node=node, capture_role=node, interfaces=sorted(interfaces),
            interface_statistics={name: dict(receive_buffer_bytes=8388608,
                observed_frames=500 if name == "underlay" else 0,
                packet_socket_packets=500 if name == "underlay" else 0,
                packet_socket_drops=0, intake_stopped=True, drained=True) for name in interfaces})
        capture.update(dict.fromkeys(CAP["LEARNER_PROVIDER_COUNTERS"], 0))
    old["expected_peers"]["relay3"] = "peer-relay3"
    return current, old["expected_peers"]


class LearnerCapture(unittest.TestCase):
    def test_exact_selected_wireguard_legs_never_direct_or_wrong_interface(self):
        current = CAP["validate_layout"](layout())
        learner, exit_ip = current["client"]["ip"], current["exit"]["ip"]
        for node, address in current["relays"].items():
            index = node[-1]
            for source, destination in ((learner, address), (address, learner)):
                for role, interface in (("relay3", "lr" + index), (node, "r" + index + "l")):
                    classified = packet(current, role, interface, source, destination)
                    self.assertEqual(classified["client_leg_wireguard_data_datagrams"], 1)
                    self.assertEqual(classified[f"{node}_client_leg_wireguard_data_datagrams"], 1)
                    self.assertEqual(packet(current, role, "r3x", source, destination), {"forbidden_packets": 1})
            for source, destination in ((address, exit_ip), (exit_ip, address)):
                for role, interface in ((node, "r" + index + "x"), ("exit", "xr" + index)):
                    self.assertEqual(packet(current, role, interface, source, destination)["exit_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(packet(current, "relay3", "lr1", learner, CAP["PUBLIC"]["relay1"]), {"forbidden_packets": 1})
        self.assertEqual(packet(current, "relay3", "lr0", learner, current["provider"]["ip"]),
                         {"forbidden_packets": 1, "direct_provider_packets": 1})
        for protocol, sport, dport in ((socket.IPPROTO_UDP, 22000, 23000), (socket.IPPROTO_UDP, 41000, 41000),
                                       (socket.IPPROTO_TCP, 22000, 443), (socket.IPPROTO_TCP, 22000, 18080)):
            self.assertEqual(packet(current, "relay3", "r3x", learner, exit_ip, protocol, sport, dport),
                             {"forbidden_packets": 1, "direct_client_exit_packets": 1})

    def test_own_serving_and_protected_fetch_are_separate_exact_endpoints(self):
        current = layout()
        learner, exit_ip, provider = (current[key]["ip"] for key in ("client", "exit", "provider"))
        for node, interface in (("relay3", "r3x"), ("exit", "xr3")):
            self.assertEqual(packet(current, node, interface, exit_ip, learner, socket.IPPROTO_TCP, 30000, 18080),
                             {"learner_provider_request_packets": 1})
            self.assertEqual(packet(current, node, interface, learner, exit_ip, socket.IPPROTO_TCP, 18080, 30000),
                             {"learner_provider_response_packets": 1, "learner_provider_response_payload_bytes": len(WG)})
            self.assertEqual(packet(current, node, "xr4", learner, exit_ip, socket.IPPROTO_TCP, 18080, 30000),
                             {"forbidden_packets": 1, "direct_client_exit_packets": 1})
        for node, interface in (("exit", "xr4"), ("relay4", "r4x")):
            self.assertEqual(packet(current, node, interface, exit_ip, provider, socket.IPPROTO_TCP, 30000, 18080),
                             {"provider_request_packets": 1})
            self.assertEqual(packet(current, node, interface, provider, exit_ip, socket.IPPROTO_TCP, 18080, 30000),
                             {"provider_response_packets": 1, "provider_response_payload_bytes": len(WG)})
            self.assertEqual(packet(current, node, "xr3", provider, exit_ip, socket.IPPROTO_TCP, 18080, 30000),
                             {"forbidden_packets": 1})
        # Changing a peer-learning endpoint is not a reusable direct-exit exception.
        invalid = layout()
        invalid["client"] = dict(node="client", ip=CAP["PUBLIC"]["client"])
        with self.assertRaises(ValueError):
            CAP["validate_layout"](invalid)

    def test_late_control_and_mdns_require_exact_local_links(self):
        current = layout()
        for index, segment in enumerate((110, 112, 114)):
            for node, interface in (("relay3", f"lr{index}"), (f"relay{index}", f"r{index}l")):
                if node not in ("relay3", *current["relays"]):
                    continue
                left, right = f"10.241.{segment}.1", f"10.241.{segment}.2"
                self.assertEqual(packet(current, node, interface, left, right, dport=41000), {"control_packets": 1})
                self.assertEqual(packet(current, node, "wrong0", left, right, dport=41000), {"forbidden_packets": 1})
                self.assertEqual(packet(current, node, interface, left, "224.0.0.251", dport=5353),
                                 {"mdns_packets": 1, "control_packets": 1})
                frame = FRAME["membership_frame"](left)
                parsed = CAP["decode_frame"](frame)
                self.assertEqual(CAP["classify"](current, node, *parsed[1:], interface, frame=frame),
                                 {"control_packets": 1, "mdns_membership_packets": 1})
                self.assertEqual(CAP["classify"](current, node, *parsed[1:], "wrong0", frame=frame), {"forbidden_packets": 1})

    def test_five_role_coverage_and_late_link_removal_preserve_old_client_proof(self):
        for control in ("relay0", "relay1", "relay2"):
            current, peers = phase(control)
            REP["validate_phase"](current, "peer-learning", peers, 1024)
            for role, field, wrong in (("receiver", "client_leg_wireguard_data_datagrams", 0),
                    ("relay-a", "client_leg_wireguard_data_datagrams", 0),
                    ("provider", "learner_provider_response_payload_bytes", 1),
                    ("provider", "provider_response_payload_bytes", 0),
                    ("exit", "packet_socket_drops", 1)):
                bad = copy.deepcopy(current)
                if role == "receiver":
                    relay = sorted(current["layout"]["relays"])[0]
                    field = f"{relay}_client_leg_wireguard_data_datagrams"
                bad["captures"][role][field] = wrong
                with self.assertRaises(ValueError):
                    REP["validate_phase"](bad, "peer-learning", peers, 1024)
            missing = copy.deepcopy(current)
            missing["captures"]["receiver"]["interfaces"].remove("lr1")
            with self.assertRaises(ValueError):
                REP["validate_phase"](missing, "peer-learning", peers, 1024)
        old = BASE["fixture"]()
        REP["validate_evidence"](old)
        restored = old["phases"]["reserve-fetch"]
        relay = restored["captures"]["relay-a"]["node"]
        self.assertNotIn("r" + relay[-1] + "l", REP["physical_interfaces"](restored["layout"], relay))
        restored["captures"]["relay-a"]["interfaces"].append("r" + relay[-1] + "l")
        with self.assertRaises(ValueError):
            REP["validate_phase"](restored, "reserve-fetch", old["expected_peers"])


if __name__ == "__main__":
    unittest.main()
