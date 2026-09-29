#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert report/parser/containment tests, never substitute for the live KVM proof."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("reciprocal_private_dns", HERE / "reciprocity-private-dns.py")
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def valid_report():
    nodes = FIXTURE.NODES
    agents = {node: dict(pid=100 + i, parent_pid=1, uid=1000, netns_inode=1000 + i, start_ticks=100)
              for i, node in enumerate(nodes)}
    contexts = {node: str(i + 1) * 32 for i, node in enumerate(nodes)}
    counters = {metric: 0 for metric in FIXTURE.DNS.METRICS}
    phases = {}
    for phase, source in (("warm", "upstream_validated"), ("local", "local_validated")):
        captures = {}
        for node in nodes:
            interfaces = [*FIXTURE.CAPTURE.NODES[node]["interfaces"], "dnsup0"]
            counts = dict.fromkeys(("packet_socket_drops", "forbidden_packets", "plaintext_dns_packets",
                "plaintext_echo_packets", "direct_client_exit_packets", "malformed_packets",
                "recursive_request_packets", "recursive_response_packets", "recursive_response_payload_bytes"), 0)
            if phase == "warm" and node == "exit":
                counts.update(recursive_request_packets=3, recursive_response_packets=3, recursive_response_payload_bytes=300)
            captures[node] = dict(node=node, phase=phase, complete=True, truncated=False, interfaces=interfaces,
                interface_statistics={interface: dict(intake_stopped=True, drained=True, packet_socket_drops=0,
                    packet_socket_packets=5, observed_frames=5) for interface in interfaces}, **counts)
        before = {node: counters.copy() for node in nodes}
        after = copy.deepcopy(before)
        after["exit"]["volparossa_dns_" + source + "_total"] += 1
        phases[phase] = dict(phase=phase, selected=dict(exit_node="exit", relay_node="relay0", exit_peer_id="exit-peer"),
            application=dict(name="iana.org", family="A", addresses=["192.0.43.8"], ad_used_as_proof=False),
            metrics_before=before, metrics_after=after, captures=captures, exit_agent=agents["exit"],
            route_retired=True, native_workers_reaped=True, workers=[])
        if phase == "warm":
            phases[phase]["workers"] = [dict(pid=200, start_ticks=101, parent_pid=agents["exit"]["pid"], uid=1000,
                netns_inode=agents["exit"]["netns_inode"], inherited_private_pipes=True,
                effective_capabilities=0, no_new_privileges=True)]
    return dict(version=1, report_kind="volparossa-reciprocity-private-dns", source_revision="a" * 40,
        scope=FIXTURE.SCOPE, success=True,
        evidence=dict(success=True, same_agents=True, same_udp_contexts=True, agents_before=copy.deepcopy(agents),
            agents_after=copy.deepcopy(agents), udp_contexts_before=contexts.copy(), udp_contexts_after=contexts.copy(),
            started_ns=20, completed_ns=30, **phases),
        reciprocity=dict(success=True, source_revision="a" * 40,
            flows=[dict(client_node=node, route_context_id=contexts[node], application=dict(first_echo_ns=10, last_echo_ns=40)) for node in nodes],
            nodes=[dict(node=node, roles=dict(client=True, relay=True, exit=True), agent_pid_before=agents[node]["pid"],
                        agent_pid_after=agents[node]["pid"]) for node in nodes]),
        cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True),
        uplinks_cleanup=dict(complete=True, owned_slirp_processes_reaped=True, restored_nodes=list(nodes)))


class ReciprocalPrivateDnsTests(unittest.TestCase):
    def test_live_selection_requires_a_distinct_real_route_not_a_forced_exit(self):
        peers = {node: node + "-peer" for node in FIXTURE.NODES}
        original = "1" * 32
        native = f"context={original} path=1 relay=relay2-peer exit=exit-peer state=4 rtt_us=10 bytes=100\n"
        dns = "context=" + "2" * 32 + " path=1 relay=relay0-peer exit=exit-peer state=1 rtt_us=0 bytes=0\n"
        selected = FIXTURE.selection(native + dns, peers, original)
        self.assertEqual(selected["exit_node"], "exit")
        for wrong in (native, native + dns + dns, native + dns.replace("exit=exit-peer", "exit=client-peer"),
                      native + dns.replace("relay=relay0-peer", "relay=exit-peer"), native + dns.replace("bytes=0", "bytes=1")):
            with self.assertRaises(ValueError):
                FIXTURE.selection(wrong, peers, original)

    def test_plain_dns_only_allowed_on_actual_selected_exit_tap(self):
        capture = FIXTURE.CAPTURE
        layout = dict(phase="warm", exit_node="exit", relays={"relay0": capture.NODES["relay0"]["public"]}, run_id="a" * 32)
        capture.validate_layout(layout)
        def packet(node, iface, src="10.242.93.100", dst="198.41.0.4", sport=43000, dport=53):
            return capture.classify(layout, node, socket.IPPROTO_UDP, src, sport, dst, dport, b"synthetic", iface, frame=b"synthetic")
        self.assertEqual(packet("exit", "dnsup0")["recursive_request_packets"], 1)
        for node, interface in (("client", "dnsup0"), ("relay0", "dnsup0"), ("exit", "xd")):
            self.assertEqual(packet(node, interface)["plaintext_dns_packets"], 1)
        self.assertEqual(packet("exit", "dnsup0", dst="10.242.93.3")["plaintext_dns_packets"], 1)
        self.assertEqual(packet("client", "underlay", src="43.159.1.1", dst="46.162.3.1", sport=43000, dport=44443)["direct_client_exit_packets"], 1)

    def test_wait_only_for_exact_original_route_before_new_dns_publication(self):
        peers = {node: node + "-peer" for node in FIXTURE.NODES}
        original = "1" * 32
        native = f"context={original} path=1 relay=relay2-peer exit=exit-peer state=4 rtt_us=10 bytes=100\n"
        dns = "context=" + "2" * 32 + " path=1 relay=relay0-peer exit=exit-peer state=1 rtt_us=0 bytes=0\n"
        paths = mock.Mock(side_effect=[native, native + dns])
        with mock.patch.object(FIXTURE.time, "sleep"):
            self.assertEqual(FIXTURE.wait_selection(paths, peers, original)["exit_node"], "exit")
        self.assertEqual(paths.call_count, 2)
        for text in ("", native + "malformed\n", native + dns + dns):
            with self.assertRaises(ValueError):
                FIXTURE.wait_selection(lambda: text, peers, original)

    def test_report_keeps_native_privacy_cleanup_and_simultaneous_role_requirements(self):
        valid = valid_report()
        FIXTURE.check_report(valid, "a" * 40)
        mutations = (
            (("cleanup", "complete"), False), (("uplinks_cleanup", "restored_nodes"), ["exit"]),
            (("evidence", "agents_after", "exit", "pid"), 500),
            (("evidence", "udp_contexts_after", "client"), "f" * 32),
            (("evidence", "warm", "workers"), []),
            (("evidence", "warm", "native_workers_reaped"), False),
            (("evidence", "warm", "workers", 0, "uid"), 0),
            (("evidence", "warm", "workers", 0, "inherited_private_pipes"), False),
            (("evidence", "warm", "captures", "exit", "recursive_request_packets"), 0),
            (("evidence", "local", "captures", "exit", "recursive_request_packets"), 1),
            (("evidence", "warm", "captures", "client", "packet_socket_drops"), 1),
            (("evidence", "warm", "captures", "relay0", "plaintext_dns_packets"), 1),
            (("evidence", "warm", "captures", "exit", "interface_statistics", "dnsup0", "drained"), False),
            (("evidence", "local", "selected", "exit_peer_id"), "different-peer"),
            (("evidence", "local", "metrics_after", "exit", "volparossa_dns_local_validated_total"), 0),
            (("evidence", "completed_ns"), 50),
        )
        for path, replacement in mutations:
            changed = copy.deepcopy(valid)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                FIXTURE.check_report(changed, "a" * 40)

    def test_uplink_only_adds_drop_containment_and_owned_exit_readiness_fds(self):
        source = (HERE / "reciprocity-private-dns-uplink.py").read_text()
        rules = FIXTURE.UPLINK.FILTER
        self.assertNotIn(" accept\n", rules)
        self.assertNotIn("skuid", rules)
        self.assertIn('iifname "dnsup0" ct state != established drop', rules)
        self.assertIn('oifname "dnsup0" th dport != 53 drop', rules)
        self.assertIn('iifname "dnsup0" th sport != 53 drop', rules)
        self.assertIn("--disable-dns", source)
        self.assertIn("--disable-host-loopback", source)
        self.assertIn("--ready-fd=", source)
        self.assertIn("--exit-fd=", source)
        self.assertNotIn("--api-socket", source)
        self.assertIn('default_routes(namespace) == state["original"]', source)

    def test_slirp_mount_isolation_precedes_unchanged_sandbox_and_owned_fds(self):
        argv = FIXTURE.UPLINK.slirp_command("owned-fixture-client", 17, 19)
        self.assertEqual(argv[:6], ["unshare", "--mount", "--propagation", "private", "--", "slirp4netns"])
        self.assertEqual(argv[6:], [
            "--netns-type=path", "--disable-host-loopback", "--disable-dns",
            "--enable-sandbox", "--enable-seccomp", "--cidr=10.242.93.0/24", "--mtu=1500",
            "--ready-fd=17", "--exit-fd=19", "/run/netns/owned-fixture-client", "dnsup0",
        ])
        # unshare must exec the owned slirp child, not fork a new untracked supervisor
        # or move its Internet-side sockets into the fixture's isolated namespace.
        self.assertNotIn("--fork", argv)
        self.assertNotIn("--net", argv)

    @unittest.skipUnless(os.environ.get("VOLPAROSSA_MOUNT_REGRESSION") == "1",
                         "opt-in anonymous user/mount namespace reproduction; no networking")
    def test_shared_tmp_pivot_fails_without_recursive_child_isolation(self):
        self.assertIn(platform.machine(), ("x86_64", "amd64"))
        before = Path("/proc/self/mountinfo").read_bytes()
        snippet = r'''
import ctypes, errno, json, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                      ctypes.c_ulong, ctypes.c_void_p]
libc.unshare.argtypes = [ctypes.c_int]
def mount(source, target, kind, flags):
    if libc.mount(source, target, kind, flags, None) != 0:
        raise OSError(ctypes.get_errno(), "anonymous mount failed")
def isolate():
    if libc.unshare(0x00020000) != 0:
        raise OSError(ctypes.get_errno(), "anonymous mount namespace failed")
# The OUTER unshare already detached every inherited mount from host propagation.
# Only now synthesize a shared /tmp inside this throwaway user/mount namespace.
mount(b"tmpfs", b"/tmp", b"tmpfs", 2 | 4 | 8)
mount(None, b"/tmp", None, 1 << 20)
if sys.argv[1] == "fixed":
    isolate()
    mount(None, b"/", None, (1 << 18) | 16384)
# Relevant upstream v1.2.3 sandbox.c sequence, with no TAP or network calls.
isolate()
mount(None, b"/", None, 1 << 18)
mount(b"tmpfs", b"/tmp", b"tmpfs", 2 | 4 | 8)
os.mkdir("/tmp/old")
os.chdir("/tmp")
result = libc.syscall(155, ctypes.c_char_p(b"."), ctypes.c_char_p(b"old"))
error = ctypes.get_errno() if result else 0
print(json.dumps({"pivot_succeeded": result == 0, "errno": error}))
'''
        for variant in ("original", "fixed"):
            result = subprocess.run([
                "unshare", "--user", "--map-root-user", "--mount", "--propagation", "private", "--",
                "python3", "-B", "-c", snippet, variant,
            ], text=True, capture_output=True, timeout=10, check=True)
            self.assertEqual(result.stderr, "")
            self.assertEqual(json.loads(result.stdout), {
                "pivot_succeeded": variant == "fixed", "errno": 0 if variant == "fixed" else 22,
            })
        self.assertEqual(Path("/proc/self/mountinfo").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
