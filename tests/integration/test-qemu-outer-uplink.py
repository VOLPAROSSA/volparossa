#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure runner-uplink decision tests; no network, QEMU or host-state changes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("qemu_uplink", HERE / "qemu-outer-uplink.py")
UPLINK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = UPLINK
SPEC.loader.exec_module(UPLINK)
REVISION = "a" * 40


def parsed(value):
    return UPLINK.Probe(0, json.dumps(value).encode())


def addresses():
    return parsed([dict(addr_info=[dict(family="inet6", local="fe80::1234", scope="link")])])


def present():
    return parsed([dict(dst=UPLINK.ROOT_IPV6, dev="eth0", prefsrc="2606:4700::1234", gateway="fe80::1")])


def absent():
    return UPLINK.Probe(2, b"", b"RTNETLINK answers: Network is unreachable\n")


class UplinkDecision(unittest.TestCase):
    def test_explicit_absence_changes_only_fixture_outer_ipv6(self):
        report = UPLINK.make_report(addresses(), absent(), "dns-cache", REVISION)
        self.assertTrue(report["preflight_complete"])
        self.assertIs(report["outer_ipv6"], False)
        self.assertEqual(report["qemu_option"], "ipv6=off")
        self.assertEqual(report["observations"]["route"]["status"], "kernel_enetunreach")
        self.assertFalse(report["product_ipv6_changed"])
        self.assertFalse(report["overlay_ipv6_changed"])
        self.assertFalse(report["host_network_modified"])
        self.assertFalse(report["network_traffic_sent"])
        self.assertFalse(report["external_reachability_proven"])

    def test_present_route_is_not_connectivity_proof_or_false_absence(self):
        report = UPLINK.make_report(addresses(), present(), "reciprocity-private-dns", REVISION)
        self.assertTrue(report["preflight_complete"])
        self.assertTrue(report["outer_ipv6"])
        self.assertEqual(report["qemu_option"], "ipv6=on")
        self.assertFalse(report["observations"]["addresses"]["has_global_address"])
        self.assertTrue(report["observations"]["route"]["has_global_source"])
        self.assertFalse(report["external_reachability_proven"])
        encoded = json.dumps(report)
        for private in ("2606:4700::1234", "fe80::1234", "fe80::1", "eth0", UPLINK.ROOT_IPV6):
            self.assertNotIn(private, encoded)
        self.assertLess(len(encoded), 4096)

    def test_unknown_never_disables_ipv6_or_allows_launch(self):
        unknown = (UPLINK.Probe(failure="timeout"), UPLINK.Probe(failure="tool_unavailable"),
            UPLINK.Probe(2, b"", b"RTNETLINK answers: Operation not permitted\n"),
            UPLINK.Probe(2, b"", b"Usage: unknown argument\n"), UPLINK.Probe(0, b"not-json"),
            parsed([]), parsed([{}]), parsed([dict(dst=UPLINK.ROOT_IPV6, dev="eth0", type="blackhole")]),
            parsed([dict(dst="2606:4700::1111", dev="eth0")]),
            UPLINK.Probe(0, b"[" + b" " * UPLINK.MAX_BYTES + b"]"))
        for route in unknown:
            with self.subTest(route=route.failure or route.code):
                report = UPLINK.make_report(addresses(), route, "dns-cache", REVISION)
                self.assertFalse(report["preflight_complete"])
                self.assertIsNone(report["outer_ipv6"])
                self.assertIsNone(report["qemu_option"])
        for address_result in (UPLINK.Probe(failure="tool_unavailable"), parsed([{}]),
                               parsed([dict(addr_info=[dict(family="inet6", local="invalid")])])):
            report = UPLINK.make_report(address_result, absent(), "dns-cache", REVISION)
            self.assertFalse(report["preflight_complete"])
            self.assertIsNone(report["outer_ipv6"])

    def test_only_exact_read_commands_and_fixed_scope_can_run(self):
        self.assertEqual(UPLINK.ADDRESS_COMMAND, ("ip", "-j", "-6", "address", "show"))
        self.assertEqual(UPLINK.ROUTE_COMMAND, ("ip", "-j", "-6", "route", "get", UPLINK.ROOT_IPV6))
        for scenario in ("alpha", "reciprocity", "unsupported"):
            with self.assertRaises(ValueError):
                UPLINK.make_report(addresses(), absent(), scenario, REVISION)
        with mock.patch.object(UPLINK.subprocess, "Popen", side_effect=FileNotFoundError):
            result = UPLINK.read_command(UPLINK.ROUTE_COMMAND)
            self.assertEqual(result.failure, "tool_unavailable")
        with mock.patch.object(sys, "argv", ["probe", "dns-cache", REVISION]), \
                mock.patch.object(UPLINK.os, "geteuid", return_value=1000), \
                mock.patch.object(UPLINK, "read_command", side_effect=[addresses(), absent()]) as read, \
                mock.patch("builtins.print") as output, self.assertRaises(SystemExit) as stopped:
            UPLINK.main()
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(read.call_args_list, [mock.call(UPLINK.ADDRESS_COMMAND), mock.call(UPLINK.ROUTE_COMMAND)])
        self.assertFalse(json.loads(output.call_args.args[0])["outer_ipv6"])

    def test_host_wrapper_wires_only_the_two_scenarios_and_retains_decision(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        section = source.split("qemu_usernet=user,id=net0,hostfwd=tcp:127.0.0.1:22223-:22\n", 1)[1]
        case, launch = section.split("qemu-system-x86_64 \\\n", 1)
        self.assertIn("case $scenario in dns-cache|reciprocity-private-dns)", case)
        self.assertIn('python3 -B "$HERE/qemu-outer-uplink.py" "$scenario" "$expected_commit"', case)
        self.assertIn('[ "$uplink_preflight_status" -eq 0 ]', case)
        self.assertIn('case $qemu_outer_ipv6 in ipv6=on|ipv6=off)', case)
        self.assertIn('qemu_usernet=$qemu_usernet,$qemu_outer_ipv6', case)
        self.assertIn('-netdev "$qemu_usernet"', launch)
        self.assertIn('"$output_directory/qemu-outer-uplink.json"', case)
        cleanup = source.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
        self.assertIn('"$output_directory/qemu-outer-uplink.json"', cleanup)
        self.assertNotIn("sysctl", case)
        self.assertNotIn("sudo", case)
        for scenario in ("dns-cache", "reciprocity-private-dns"):
            preview = subprocess.check_output(["sh", str(HERE / "run-alpha-topology-vm.sh"),
                                               "--preview", "--scenario", scenario], text=True)
            self.assertIn("Private-DNS outer uplink:", preview)
        for scenario in ("alpha", "reciprocity"):
            preview = subprocess.check_output(["sh", str(HERE / "run-alpha-topology-vm.sh"),
                                               "--preview", "--scenario", scenario], text=True)
            self.assertNotIn("Private-DNS outer uplink:", preview)


if __name__ == "__main__":
    unittest.main()
