#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure bounded validator/preview tests; these do not claim a live uplink transition."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("uplink", HERE / "uplink-link-smoke.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
RUN = "1" * 32


def records():
    peers = {node: "peer-" + node for node in module.NODES}
    result = {"a01-expected-peers.json": peers,
        "uplink-withdraw-events.txt": "1001\tlevel=2\tevent=INDEPENDENT_EGRESS_WITHDRAWN\n",
        "uplink-rejection-events.txt": "", "uplink-loss-baseline-ms.txt": "1000\n",
        "uplink-fresh-loss-paths.txt": "No paths\n",
        "uplink-fresh-loss-attempt.json": {"node": "relay0", "transport": "single-path-udp",
            "started_ms": 1001, "finished_ms": 1002, "exit_code": 1}}
    for phase_index, phase in enumerate(module.PHASES):
        flows = module.configure(phase)
        prefix = f"uplink-{phase}/"
        result[f"uplink-peers-{phase}.txt"] = "peer-relay2\troles=" + ("0b011" if phase == "lost" else "0b111") + "\treachability=1\n"
        result[f"uplink-egress-{phase}-addresses.json"] = [{"ifname": "r2d", "ifindex": 15,
            "flags": [] if phase == "lost" else ["UP", "LOWER_UP"], "addr_info": [{"local": "10.241.35.1"}]}]
        result[f"uplink-egress-{phase}-routes.json"] = [] if phase == "lost" else [
            {"dst": "default", "dev": "r2d", "gateway": "10.241.35.2"}]
        result[f"uplink-client-{phase}-addresses.json"] = [
            {"ifname": "cr0", "addr_info": [{"local": "10.241.10.1"}]},
            {"ifname": "cr2", "addr_info": [{"local": "10.241.12.1"}]}]
        result[f"uplink-client-{phase}-routes.json"] = []
        echoes = {}
        for index, node in enumerate(module.NODES):
            result[f"local-link-node-{node}-{phase}.json"] = {"agent_pid": index + 100,
                "roles": {"client": True, "relay": True, "exit": node != "client"}}
            result[prefix + f"local-link-capture-{node}.json"] = {
                "wireguard_edges": {edge: 4 for pair in module.EDGES.values() for edge in pair},
                "destination_requests": {name: 4 for name in flows},
                "destination_responses": {name: 4 for name in flows}, "truncated": False,
                "packet_socket_drops": 0, "direct_client_exit_packets": 0, "plaintext_leaks": 0}
        for index, (name, flow) in enumerate(flows.items()):
            payload = module.fixture.payload_for(module.phase_id(RUN, phase), name)
            digest = hashlib.sha256(payload).hexdigest()
            result[prefix + f"app/{name}.json"] = {"success": True, "datagrams": 3,
                "destination": list(module.fixture.DESTINATION), "sent_sha256": digest,
                "response_sha256": digest, "sent_bytes": len(payload), "response_bytes": len(payload),
                "first_echo_ns": 100, "last_echo_ns": 3_000_000_100}
            if phase == "initial" and name == "relay0":
                result[prefix + f"app/{name}.json"].update(
                    same_application_socket=True, loss_attempts=3, loss_replies=0,
                    loss_barrier_ns=4_000_000_000, loss_complete_ns=10_000_000_000,
                    loss_markers=[{"sha256": hashlib.sha256(module.fixture.payload_for(module.phase_id(RUN, phase), marker)).hexdigest(),
                        "attempted_ns": 4_000_000_000 + index} for index, marker in enumerate(module.LOSS_MARKERS)])
            echoes[name] = {"sha256": digest, "bytes": len(payload), "datagrams": 3, "source_ips": [flow["uplink"]]}
            context = f"{phase_index * 2 + index + 1:032x}"
            result[prefix + f"paths-{name}.txt"] = f"context={context} path=1 relay=peer-{next(iter(flow['relays']))} exit=peer-{flow['exit']} state=3 rtt_us=1 bytes=0\n"
        if phase == "initial":
            for marker in module.LOSS_MARKERS:
                echoes[marker] = {"datagrams": 0}
        result[prefix + "app/server.json"] = {"destination": list(module.fixture.DESTINATION), "flows": echoes}
    return result


def evaluate(data):
    with tempfile.TemporaryDirectory(prefix="volparossa-uplink-proof-") as temporary:
        directory = Path(temporary)
        for name, value in data.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="ascii")
        return module.build_evidence(directory, RUN)


class UplinkEvidence(unittest.TestCase):
    def test_new_loss_markers_keep_the_same_plaintext_and_direct_exit_guards(self):
        module.configure_capture("initial")
        original = module.local.FLOWS["relay0"]
        payloads = {module.fixture.payload_for(module.phase_id(RUN, "initial"), name)
                    for name in ("relay0", *module.LOSS_MARKERS)}
        self.assertEqual(len(payloads), 4)
        for marker in module.LOSS_MARKERS:
            self.assertEqual(module.local.FLOWS[marker], original)
        module.configure_capture("lost")
        self.assertEqual(set(module.local.FLOWS), {"client", "relay2"})

    def test_real_phase_shape_and_optional_server_rejection(self):
        data = records()
        result = evaluate(data)
        self.assertEqual(len(result["flows"]), 6)
        self.assertTrue(result["success"])
        self.assertFalse(result["transition"]["incoming_grant_rejection_observed"])
        data["uplink-rejection-events.txt"] = "random text about rejection\n"
        self.assertFalse(evaluate(data)["transition"]["incoming_grant_rejection_observed"])
        data["uplink-rejection-events.txt"] = "1002\tlevel=2\tevent=NATIVE_PROBE_PERMIT_EXIT_REJECTED\tsession=\tpath=-\n"
        self.assertTrue(evaluate(data)["transition"]["incoming_grant_rejection_observed"])
        data["uplink-rejection-events.txt"] = data["uplink-rejection-events.txt"].replace("1002", "999")
        self.assertFalse(evaluate(data)["transition"]["incoming_grant_rejection_observed"])

    def test_rejects_false_transition_or_missing_actual_admission(self):
        mutations = [
            lambda d: d["uplink-egress-lost-addresses.json"][0].update(flags=["UP"]),
            lambda d: d["uplink-egress-lost-routes.json"].append({"dst": "default", "dev": "underlay"}),
            lambda d: d["uplink-egress-restored-addresses.json"][0].update(ifindex=99),
            lambda d: d["uplink-egress-restored-routes.json"][0].update(dev="underlay"),
            lambda d: d["uplink-initial/app/relay0.json"].update(loss_replies=1),
            lambda d: d["uplink-initial/app/relay0.json"].update(same_application_socket=False),
            lambda d: d["uplink-initial/app/relay0.json"]["loss_markers"][0].update(sha256="bad"),
            lambda d: d["uplink-initial/app/relay0.json"]["loss_markers"][0].update(attempted_ns=0),
            lambda d: d["uplink-initial/app/server.json"]["flows"][module.LOSS_MARKERS[0]].update(datagrams=1),
            lambda d: d["local-link-node-relay2-lost.json"].update(agent_pid=9),
            lambda d: d["local-link-node-relay2-lost.json"]["roles"].update(exit=False),
            lambda d: d["uplink-client-lost-routes.json"].append({"dst": "default", "dev": "cr0"}),
            lambda d: d.update({"uplink-peers-lost.txt": "peer-relay2 roles=0b111\n"}),
            lambda d: d.update({"uplink-withdraw-events.txt": ""}),
            lambda d: d["uplink-fresh-loss-attempt.json"].update(exit_code=127),
            lambda d: d["uplink-fresh-loss-attempt.json"].update(finished_ms=100_000),
            lambda d: d.update({"uplink-fresh-loss-paths.txt": d["uplink-initial/paths-relay0.txt"]}),
            lambda d: d.update({"uplink-restored/paths-relay0.txt": d["uplink-initial/paths-relay0.txt"]}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                data = records()
                mutate(data)
                with self.assertRaises(ValueError):
                    evaluate(data)

    def test_rejects_missing_packet_and_payload_evidence(self):
        for phase in module.PHASES:
            for field in ("truncated", "packet_socket_drops", "direct_client_exit_packets", "plaintext_leaks"):
                data = records()
                data[f"uplink-{phase}/local-link-capture-client.json"][field] = 1
                with self.subTest(phase=phase, field=field), self.assertRaises(ValueError):
                    evaluate(data)
            for mutate in (
                lambda d: d[f"uplink-{phase}/local-link-capture-client.json"].update(wireguard_edges={}),
                lambda d: d[f"uplink-{phase}/app/client.json"].update(response_sha256="bad"),
                lambda d: d[f"uplink-{phase}/app/server.json"]["flows"]["client"].update(source_ips=["10.241.10.1"]),
                lambda d: d[f"uplink-{phase}/app/client.json"].update(first_echo_ns=3_000_000_000),
            ):
                data = records()
                mutate(data)
                with self.assertRaises(ValueError):
                    evaluate(data)

    def test_nonmutating_scenario_preview_and_barriers(self):
        for script in ("kvm-alpha-topology.sh", "run-alpha-topology-vm.sh"):
            result = subprocess.run(["sh", str(HERE / script), "--preview", "--scenario", "uplink-link"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("uplink-link", result.stdout.lower())
        script = (HERE / "uplink-link-smoke.sh").read_text()
        self.assertLess(script.index("ip -n \"$R2\" link set dev r2d down"), script.index("printf 'loss\\n'"))
        self.assertIn("INDEPENDENT_EGRESS_WITHDRAWN", script)
        self.assertIn("independent_egress_interface: r2d", (HERE / "kvm-alpha-topology.sh").read_text())
        self.assertNotIn("--force-relay", script)


if __name__ == "__main__":
    unittest.main()
