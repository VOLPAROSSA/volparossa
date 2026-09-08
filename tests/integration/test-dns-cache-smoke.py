#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Small adversarial report/packet-contract tests; synthetic data is not C05 acceptance."""
import copy
import importlib.util
from pathlib import Path
import socket
import struct
import unittest

SPEC = importlib.util.spec_from_file_location("dns_network", Path(__file__).with_name("dns-cache-smoke.py"))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
CAPTURE = CHECK.CAPTURE


def fixture():
    expected = {"A": ["192.0.43.8"], "AAAA": ["2001:500:88:200::8"]}
    peers = {node: "peer-" + node for node in ("client", "exit", "exit2", "relay0", "relay1", "relay2")}
    preflight = dict(success=True, scope="builtin-anchor-collector-and-local-cache-only",
        candidate_name="iana.org", source_url=CHECK.WIRE.SOURCE_URL,
        normal_client_route_proven=False, peer_cache_proven=False, recording_sha256="f" * 64,
        core=[dict(family=family, addresses=addresses, source="UpstreamValidated", builtin_anchors=True,
                   local_reuse=True, ttl_seconds=969, expires_at_ms=2_000_000, proof_sha256="a" * 64)
              for family, addresses in expected.items()])
    evidence = dict(success=True, expected=expected, expected_peers=peers, preflight=preflight,
        configuration=dict(exit_upstream="47.163.4.2:53", exit2_upstream=None, positive_name_in_hosts=False,
                           other_nodes_cache_disabled=True, production_root_anchors_unchanged=True),
        peer_stopped=dict(node="exit", agent_active=False, main_pid=0), upstream={}, phases={})
    for index, phase in enumerate(CHECK.PHASES, 1):
        node = "exit" if phase.startswith("warm-") else "exit2"
        relay = "relay1" if node == "exit" else "relay0"
        family = "AAAA" if phase.endswith("aaaa") else "A"
        mode = "upstream_validated" if phase.startswith("warm-") else "peer_validated" if phase.startswith("peer-") \
            else "trusted_fallback" if phase == "unsigned-b" else "local_validated"
        route = dict(exit_node=node, exit_peer_id=peers[node], relay_node=relay, relay_peer_id=peers[relay],
                     route_context_id=f"{index:032x}", path_id=1, state=1, transport="protected-dns",
                     rtt_us=0, reported_bytes=0)
        layout = dict(phase=phase, exit_node=node, relays={relay: CHECK.PUBLIC[relay]})
        before = {name: dict.fromkeys(CHECK.METRICS, 0) for name in ("exit", "exit2")}
        after = copy.deepcopy(before)
        after[node][f"volparossa_dns_{mode}_total"] = 1
        if phase == "unsigned-b":
            after["exit"]["volparossa_dns_cache_miss_replies_total"] = 1
        if phase.startswith("local-"):
            before["exit"] = after["exit"] = None
        app = dict(name="destination.volparossa.test" if phase == "unsigned-b" else "iana.org", family=family,
                   addresses=["47.163.4.2"] if phase == "unsigned-b" else expected[family], ttls=[30],
                   resolver=dict(ip="9.9.9.9", port=53), response_source=dict(ip="9.9.9.9", port=53),
                   ad_used_as_proof=False, completed_at_unix_ms=1_000_000 + index)
        captures = {}
        for role in ("client", relay, "exit", "exit2", "destination"):
            interfaces = sorted(CAPTURE.PHYSICAL_INTERFACES[role])
            record = dict.fromkeys(CAPTURE.ENGINE.COUNTERS, 0)
            record.update(complete=True, truncated=False, node=role, phase=phase,
                packet_socket_drops=0, observed_frames=10 * len(interfaces), interfaces=interfaces,
                interface_statistics={iface: dict(intake_stopped=True, drained=True, packet_socket_drops=0,
                                                  forbidden_packets=0, packet_socket_packets=10, observed_frames=10)
                                      for iface in interfaces})
            if role in ("client", relay): record["client_leg_wireguard_data_datagrams"] = 5
            if role in (node, relay): record["exit_leg_wireguard_data_datagrams"] = 5
            if phase.startswith("warm-") and role in ("exit", "destination"):
                record.update(upstream_request_packets=10, upstream_response_packets=10,
                              upstream_request_payload_bytes=600, upstream_response_payload_bytes=8000)
            if (phase.startswith("peer-") or phase == "unsigned-b") and role in ("exit", "exit2"):
                record["cross_exit_control_packets"] = 10
            captures[role] = record
        evidence["phases"][phase] = dict(selection=route, application=app, layout=layout, captures=captures,
                                          metrics_before=before, metrics_after=after)
        evidence["upstream"][phase] = dict(listener_closed=True, bounded_stop=True, rejected=0,
                                            cryptographically_verified=False, connections=6 if phase.startswith("warm-") else 0)
    return evidence


class DnsNetworkEvidenceTests(unittest.TestCase):
    def test_seven_phase_contract_and_exact_exit_selection(self):
        CHECK.validate_evidence(fixture())
        peers = fixture()["expected_peers"]
        row = f"context={'a' * 32} path=1 relay=peer-relay0 exit=peer-exit2 state=1 rtt_us=0 bytes=0\n"
        self.assertEqual(CHECK.selection(row, peers, "exit2")[0], 0)
        self.assertEqual(CHECK.selection(row, peers, "exit")[0], 2)
        self.assertEqual(CHECK.selection("", peers, "exit")[0], 1)
        for relay in ("relay0", "relay1", "relay2"):
            self.assertEqual(CHECK.selection(row.replace("peer-relay0", "peer-" + relay), peers, "exit2")[0], 0)
            CAPTURE.validate_layout(dict(phase="peer-b-a", exit_node="exit2", relays={relay: CHECK.PUBLIC[relay]}))
        with self.assertRaises(ValueError):
            CHECK.selection(row.replace("peer-relay0", "peer-relay3"), peers, "exit2")
        for invented in (row.replace("state=1", "state=3"), row.replace("rtt_us=0", "rtt_us=42"),
                         row.replace("bytes=0", "bytes=1")):
            with self.assertRaises(ValueError):
                CHECK.selection(invented, peers, "exit2")

    def test_rejects_fake_trust_wrong_source_expired_recording_and_peer_recursion(self):
        def upstream_on_peer(value):
            value["phases"]["peer-b-a"]["metrics_after"]["exit2"]["volparossa_dns_peer_validated_total"] = 0
            value["phases"]["peer-b-a"]["metrics_after"]["exit2"]["volparossa_dns_upstream_validated_total"] = 1
        mutations = (
            lambda v: v["phases"]["warm-a-a"]["selection"].update(transport="single-path-udp"),
            lambda v: v["phases"]["warm-a-a"]["selection"].update(reported_bytes=42),
            lambda v: v["preflight"]["core"][0].update(builtin_anchors=False),
            lambda v: v["preflight"]["core"][0].update(source="TrustedFallback"),
            lambda v: v["preflight"]["core"][0].update(expires_at_ms=1),
            lambda v: v["configuration"].update(exit2_upstream="47.163.4.2:53"),
            lambda v: v["phases"]["peer-b-a"]["application"].update(ad_used_as_proof=True),
            upstream_on_peer,
            lambda v: v["phases"]["unsigned-b"]["metrics_after"]["exit"].update(volparossa_dns_cache_miss_replies_total=0),
            lambda v: v["upstream"]["unsigned-b"].update(connections=1),
            lambda v: v["peer_stopped"].update(main_pid=123),
        )
        for change in mutations:
            value = fixture(); change(value)
            with self.assertRaises(ValueError): CHECK.validate_evidence(value)

    def test_rejects_capture_loss_missing_physical_interface_and_false_report_cleanup(self):
        for change in (
            lambda c: c.update(packet_socket_drops=1),
            lambda c: c["interface_statistics"]["xc0"].update(drained=False),
            lambda c: c["interface_statistics"].pop("xr5"),
            lambda c: c.update(unexpected_dns_packets=1),
        ):
            value = fixture(); change(value["phases"]["peer-b-a"]["captures"]["exit"])
            with self.assertRaises(ValueError): CHECK.validate_evidence(value)
        report = dict(schema_version=1, report_kind="volparossa-dns-cache", source_revision="a" * 40,
                      success=True, runner_exit_status=0, full_alpha_acceptance_claimed=False, full_c05_claimed=False,
                      cleanup=dict(complete=True, remaining_owned_objects=0),
                      host_state=dict(success=True, unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64), dns=fixture())
        CHECK.validate_report(report, "a" * 40)
        report["cleanup"]["remaining_owned_objects"] = 1
        with self.assertRaises(ValueError): CHECK.validate_report(report, "a" * 40)

    def test_exact_selected_wg_paths_and_control_are_not_dns_egress(self):
        current = fixture()["phases"]["peer-b-a"]["layout"]
        def classify(role, src, dst, protocol=socket.IPPROTO_UDP, sport=20001, dport=20002,
                     payload=struct.pack("<I", 4) + bytes(44), iface="x2r0"):
            return CAPTURE.classify(current, role, protocol, src, sport, dst, dport, payload, iface)
        self.assertEqual(classify("relay0", CHECK.PUBLIC["relay0"], CHECK.PUBLIC["exit2"])["exit_leg_wireguard_data_datagrams"], 1)
        self.assertEqual(classify("relay0", CHECK.PUBLIC["relay0"], CHECK.PUBLIC["exit"]), {"forbidden_packets": 1})
        self.assertEqual(classify("client", CHECK.PUBLIC["client"], CHECK.PUBLIC["exit2"])["direct_client_exit_packets"], 1)
        self.assertEqual(classify("exit2", CHECK.PUBLIC["exit"], CHECK.PUBLIC["exit2"], dport=41000, iface="xc1")
                         ["cross_exit_control_packets"], 1)
        self.assertEqual(classify("exit2", CHECK.PUBLIC["exit2"], "52.168.8.2", protocol=socket.IPPROTO_TCP,
                                 dport=53)["unexpected_dns_packets"], 1)
        self.assertEqual(classify("exit", "47.163.4.1", "47.163.4.2", protocol=socket.IPPROTO_TCP,
                                 dport=53, payload=b"wire", iface="xd")["upstream_request_payload_bytes"], 4)
        self.assertEqual(classify("exit2", "10.241.26.1", "51.167.7.1", dport=41000)["control_packets"], 1)
        self.assertEqual(classify("exit2", "10.241.99.1", "51.167.7.1", dport=41000), {"forbidden_packets": 1})
        for index, segment in ((1, 97), (2, 98)):
            relay, iface = f"relay{index}", f"x2r{index}"
            current = dict(phase="peer-b-a", exit_node="exit2", relays={relay: CHECK.PUBLIC[relay]})
            self.assertIn(iface, CAPTURE.PHYSICAL_INTERFACES["exit2"])
            self.assertIn(f"r{index}x2", CAPTURE.PHYSICAL_INTERFACES[relay])
            self.assertEqual(classify("exit2", CHECK.PUBLIC[relay], CHECK.PUBLIC["exit2"], iface=iface)
                             ["exit_leg_wireguard_data_datagrams"], 1)
            self.assertEqual(classify("exit2", CHECK.PUBLIC["relay0"], CHECK.PUBLIC["exit2"], iface=iface),
                             {"forbidden_packets": 1})
            self.assertEqual(classify("exit2", f"10.241.{segment}.1", CHECK.PUBLIC["exit2"],
                                     dport=41000, iface=iface)["control_packets"], 1)
            self.assertEqual(classify("exit2", f"10.241.{segment}.1", CHECK.PUBLIC["exit2"],
                                     dport=41000, iface="x2r0"), {"forbidden_packets": 1})
            self.assertEqual(classify("exit2", f"10.241.{segment}.2", "224.0.0.251", dport=5353,
                                     iface=iface)["mdns_packets"], 1)
            self.assertEqual(classify("exit2", f"10.241.{segment}.2", CHECK.PUBLIC["exit2"], dport=53,
                                     iface=iface)["unexpected_dns_packets"], 1)


if __name__ == "__main__":
    unittest.main()
