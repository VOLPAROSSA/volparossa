#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed physical Mail classifier, route binding and independent receiver contracts."""
import copy
from pathlib import Path
import runpy
import socket
import unittest
from unittest.mock import patch

M = runpy.run_path(str(Path(__file__).with_name("paired-mail-peer-capture.py")))
CUSTODIANS, RELAYS, IPS = M["CUSTODIANS"], M["RELAYS"], M["PUBLIC"]
WG = b"\x04\x00\x00\x00" + bytes(60)


def packet(role, iface, src, dst, *, protocol=socket.IPPROTO_UDP, sport=10301, dport=10302, payload=WG):
    return M["classify"](M["layout"]("receive"), role, protocol, IPS.get(src, src), sport,
        IPS.get(dst, dst), dport, payload, iface)


def fixture(phase):
    peers = {n: n + "-key" for n in (*RELAYS, "client", "relay4", "exit", *CUSTODIANS)}
    context = "a" * 32
    route = dict(transport="mptcp", route_context_id=context,
        paths=[dict(route_context_id=context, relay_peer_id=peers[n], exit_peer_id=peers["exit"]) for n in RELAYS[:2]],
        benchmark_slots=[dict(relay_node=n, relay_peer_id=peers[n]) for n in RELAYS[:2]])
    records = {}
    for role, interfaces in M["INTERFACES"].items():
        live = role in (M["ACTIVE"][phase], "exit")
        observed = 100 if live else 0
        rows = {name: dict(intake_stopped=True, drained=True, forbidden_packets=0, packet_socket_drops=0,
            packet_socket_packets=observed if i == 0 else 0, observed_frames=observed if i == 0 else 0,
            receive_buffer_bytes=4194304) for i, name in enumerate(interfaces)}
        record = dict(schema_version=1, phase=M["layout"](phase)["phase"], capture_role=role, node=role,
            complete=True, truncated=False, interfaces=list(interfaces), interface_statistics=rows,
            observed_frames=observed, malformed_packets=0, forbidden_packets=0, direct_provider_packets=0,
            direct_client_exit_packets=0, packet_socket_drops=0)
        leg = "exit_leg" if role == "exit" else "client_leg"
        record.update({f"{n}_{leg}_wireguard_data_datagrams": 17 if live and i < 2 else 0 for i, n in enumerate(RELAYS)})
        for node in CUSTODIANS:
            record.update({f"{node}_{key}": (17 if key != "response_payload_bytes" else 500) if role == "exit" else 0
                for key in M["PROVIDER_FIELDS"]})
        records[role] = record
    return records, route, peers


class PeerCapture(unittest.TestCase):
    def test_physical_mail_and_wireguard_pairs_bind_exact_endpoints_and_interfaces(self):
        for role, prefix, leg in (("client", "cr", "client_leg"), ("relay4", "ar", "client_leg"), ("exit", "xr", "exit_leg")):
            for i, relay in enumerate(RELAYS):
                self.assertEqual(packet(role, prefix + str(i), role, relay)[f"{relay}_{leg}_wireguard_data_datagrams"], 1)
                self.assertEqual(packet(role, prefix + str((i + 1) % 3), role, relay), {"forbidden_packets": 1})
        for node in CUSTODIANS:
            for src, dst, sport, dport, key in (("exit", node, 1010, 18080, "request_packets"),
                    (node, "exit", 18080, 1010, "response_packets")):
                kwargs = dict(protocol=socket.IPPROTO_TCP, sport=sport, dport=dport, payload=b"private")
                updates = packet("exit", "xr" + node[-1], src, dst, **kwargs)
                self.assertEqual(updates[f"{node}_{key}"], 1)
                self.assertNotIn("private", repr(updates))
                self.assertEqual(packet("exit", "xr4", src, dst, **kwargs), {"forbidden_packets": 1})
            for client in ("client", "relay4"):
                self.assertEqual(packet(client, "underlay", client, node, protocol=socket.IPPROTO_TCP, dport=18080),
                    {"forbidden_packets": 1, "direct_provider_packets": 1})
                self.assertEqual(packet(client, "underlay", client, "exit"), {"forbidden_packets": 1, "direct_client_exit_packets": 1})

    def test_ipv6_and_control_stay_independent_of_data(self):
        self.assertEqual(packet("relay4", "ar0", "relay4", "relay0", sport=41000), {"control_packets": 1})
        self.assertEqual(packet("relay4", "ar1", "relay4", "relay0", sport=41000, payload=b"discovery"), {"forbidden_packets": 1})
        self.assertEqual(packet("relay4", "underlay", "relay4", "relay5", sport=41000, dport=41000),
            {"control_packets": 1, "underlay_control_attempt_packets": 1})
        self.assertEqual(packet("relay4", "r4b1", "fe80::1", "ff02::fb", dport=5353), {"mdns_packets": 1, "control_packets": 1})
        self.assertEqual(packet("relay4", "ar0", "2001:db8::1", "2001:db8::2"), {"forbidden_packets": 1})

    def test_three_phases_keep_both_independent_clients_and_custodians_bound(self):
        for phase, active in M["ACTIVE"].items():
            args = fixture(phase)
            M["validate"](*args, 500, phase=phase)
            inactive = "client" if active == "relay4" else "relay4"
            mutations = [
                lambda c,r: c.pop(inactive),
                lambda c,r: c[active].update(phase="other"),
                lambda c,r: c[active]["interface_statistics"]["underlay"].update(drained=False),
                lambda c,r: c[active].update(relay0_client_leg_wireguard_data_datagrams=0),
                lambda c,r: c[inactive].update(relay1_client_leg_wireguard_data_datagrams=17),
                lambda c,r: c["exit"].update(relay2_exit_leg_wireguard_data_datagrams=1),
                lambda c,r: c["exit"].update(relay3_request_packets=0),
                lambda c,r: c["exit"].update(relay5_response_packets=0),
                lambda c,r: c[inactive].update(relay3_request_packets=1),
                lambda c,r: r["paths"][0].update(exit_peer_id="other"),
            ]
            if phase == "receive":
                mutations.append(lambda c,r: c["exit"].update(relay3_response_payload_bytes=499, relay5_response_payload_bytes=499))
            if phase == "send":
                mutations.append(lambda c,r: c["exit"].update(relay3_request_packets=16))
            for mutate in mutations:
                changed = copy.deepcopy(args); mutate(*changed[:2])
                with self.assertRaises((KeyError, ValueError)): M["validate"](*changed, 500, phase=phase)

    def test_capture_entrypoint_owns_its_physical_interfaces(self):
        with patch.object(M["ENGINE"], "capture") as run:
            M["main"](["capture", "send", "client", "/out", "/ready"])
            run.assert_called_once_with(M["layout"]("send"), "/out", "/ready", "client", list(M["INTERFACES"]["client"]))
            for args in (["capture", "send", "relay0", "/out", "/ready"],
                    ["capture", "receive", "relay4", "/out", "/ready", "lo"], ["capture", "redirect", "exit", "/out", "/ready"]):
                with self.assertRaises(ValueError): M["main"](args)


if __name__ == "__main__":
    unittest.main()
