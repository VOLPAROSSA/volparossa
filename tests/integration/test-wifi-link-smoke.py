#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure parser/report and nonmutating preview contracts, not live Wi-Fi evidence."""

import copy
import importlib.util
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("wifi_link", HERE / "wifi-link-smoke.py")
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class WifiLinkEvidence(unittest.TestCase):
    def test_non_mesh_config_preserves_success_after_the_wifi_condition(self):
        for node in ("client", "relay0", "bootstrap1", "relay1", "relay2", "exit"):
            with self.subTest(node=node):
                result = subprocess.run([
                    "sh", "-eu", "-c",
                    '. "$1"\nnode=$2\nwifi_link=yes\n'
                    'WIFI_LINK_CLIENT_PARENT=wlan0\nWIFI_LINK_RELAY_PARENT=wlan1\n'
                    '[ "$wifi_link" != yes ] || wifi_link_config\n'
                    'printf "configuration-continued\\n"',
                    "wifi-config-test", str(HERE / "wifi-link-smoke.sh"), node,
                ], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("configuration-continued", result.stdout)
                self.assertEqual("wifi_mesh:" in result.stdout, node in ("client", "relay0"))

    def test_kernel_snapshot_and_exact_mdns_record(self):
        name = "vw" + "a" * 13
        links = [{"ifname": name, "ifindex": 7, "address": "02:00:00:00:00:01",
                  "ifalias": "volparossa-mesh:" + "a" * 32}]
        info = f"Interface {name}\n\tifindex 7\n\twiphy 1\n\ttype mesh point\n\tchannel 1 (2412 MHz), width: 20 MHz\n"
        stations = (f"Station 02:00:00:00:00:02 (on {name})\n\tmesh plink:\tESTAB\n"
                    "\trx bytes:\t100\n\trx packets:\t2\n\ttx bytes:\t120\n\ttx packets:\t3\n")
        parsed = FIXTURE.parse_snapshot(links, info, stations)
        self.assertEqual((parsed["wiphy"], parsed["rx_bytes"], parsed["tx_packets"]), (1, 100, 3))
        with self.assertRaises(ValueError):
            FIXTURE.parse_snapshot(links, info, stations.replace("ESTAB", "OPN_SNT"))
        peer = "12D3KooW" + "A" * 44
        dns = b"\0\0\x84\0" + b"\0" * 8 + b"dnsaddr=/ip4/10.241.10.2/udp/41000/quic-v1/p2p/" + peer.encode()
        ip = bytearray(20)
        ip[0], ip[9] = 0x45, 17
        ip[12:16], ip[16:20] = socket.inet_aton("10.241.10.2"), socket.inet_aton("224.0.0.251")
        frame = b"\0" * 12 + b"\x08\x00" + ip + struct.pack("!HHHH", 5353, 5353, len(dns) + 8, 0) + dns
        self.assertTrue(FIXTURE.mdns_packet(frame, name, peer))
        self.assertFalse(FIXTURE.mdns_packet(frame, "cr2", peer))
        self.assertFalse(FIXTURE.mdns_packet(frame, name, peer + "B"))
        self.assertFalse(FIXTURE.mdns_packet(frame[:30], name, peer))

    def test_report_requires_mesh_payload_growth_and_lifetime(self):
        with tempfile.TemporaryDirectory(prefix="volparossa-wifi-link-test-") as temporary:
            directory = Path(temporary)
            FIXTURE.write(directory, "local-link-smoke.json", {"success": True, "source_revision": "1" * 40,
                          "flows": [{"client_node": "client", "relay_node": "relay2"},
                                    {"client_node": "relay0", "relay_node": "client"}]})
            FIXTURE.write(directory, "wifi-link-association.json", {"success": True})
            FIXTURE.write(directory, "wifi-link-shutdown.json",
                          {"remaining_mesh_interfaces": 0, "agents_stopped_before_helpers": True})
            FIXTURE.write(directory, "wifi-link-radio-cleanup.json",
                          {"hwsim_module_unloaded": True, "remaining_radios": 0})
            for ordinal, node in enumerate(("client", "relay0")):
                name = "vw" + str(ordinal + 1) * 13
                item = {"interface": name, "ifindex": 7, "wiphy": ordinal,
                        "runtime_alias": str(ordinal), "local_mac": str(ordinal), "peer_mac": str(1 - ordinal)}
                for stage in ("associated", "payload-before", "payload-after", "disconnected"):
                    counter = 10 if stage in ("associated", "payload-before") else 100
                    FIXTURE.write(directory, f"wifi-link-mesh-{node}-{stage}.json",
                                  {**item, **dict.fromkeys(("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"), counter)})
                FIXTURE.write(directory, f"local-link-capture-{node}.json", {"wireguard_interfaces": {
                    name: {"10.241.10.1>10.241.10.2": 20, "10.241.10.2>10.241.10.1": 20}}})
            self.assertTrue(FIXTURE.build_report(directory)["success"])
            self.assertEqual([flow["client_relay_underlay"] for flow in FIXTURE.build_report(directory)["flows"]],
                             ["ethernet_veth", "simulated_80211s_mesh"])
            path = "wifi-link-mesh-client-payload-after.json"
            original = FIXTURE.load(directory, path)
            broken = copy.deepcopy(original)
            broken["rx_bytes"] = 10
            FIXTURE.write(directory, path, broken)
            with self.assertRaises(ValueError):
                FIXTURE.build_report(directory)
            FIXTURE.write(directory, path, original)
            FIXTURE.write(directory, "local-link-capture-client.json", {"wireguard_interfaces": {"cr2": {}}})
            with self.assertRaises(ValueError):
                FIXTURE.build_report(directory)

    def test_early_failure_report_without_local_link_artifact(self):
        with tempfile.TemporaryDirectory(prefix="volparossa-wifi-link-failure-") as temporary:
            directory = Path(temporary)
            FIXTURE.write(directory, "wifi-link-runner.json", {"success": False, "source_revision": "2" * 40,
                          "observed_blocker": "WIFI_LINK_HWSIM_UNAVAILABLE", "cleanup": {"complete": True}})
            FIXTURE.report(directory, "1")
            failed = FIXTURE.load(directory, "wifi-link-smoke.json")
            self.assertFalse(failed["success"])
            self.assertEqual(failed["observed_blocker"], "WIFI_LINK_HWSIM_UNAVAILABLE")
            self.assertEqual(failed["source_revision"], "2" * 40)

    def test_preview_and_startup_order_are_nonmutating(self):
        for script in ("kvm-alpha-topology.sh", "run-alpha-topology-vm.sh"):
            output = subprocess.run(["sh", str(HERE / script), "--preview", "--scenario", "wifi-link"],
                                    capture_output=True, text=True, check=True).stdout
            self.assertIn("agent-created", output)
            self.assertIn("Ethernet", output)
            subprocess.run(["sh", "-n", str(HERE / script)], check=True)
        source = (HERE / "kvm-alpha-topology.sh").read_text()
        self.assertLess(source.index("then wifi_link_observe_start;"), source.index('launch_agent client "$CLIENT"'))
        self.assertIn('if [ "$wifi_link" != yes ]; then\n    launch_agent bootstrap1 "$B1"\n'
                      '    launch_agent bootstrap2 "$B2"\nfi\nlaunch_agent relay0 "$R0"', source)
        self.assertIn('launch_agent relay0 "$R0"\nif [ "$wifi_link" = yes ]; then\n'
                      '    wifi_link_wait_mdns\n    launch_agent bootstrap1 "$B1"', source)
        self.assertIn("case $node in client|relay0) bootstrap_one=none", source)
        self.assertLess(source.index("wifi_link_agents_stopped ||"),
                        source.index('for cleanup_unit in $HELPER_UNITS; do retire_unit'))


if __name__ == "__main__":
    unittest.main()
