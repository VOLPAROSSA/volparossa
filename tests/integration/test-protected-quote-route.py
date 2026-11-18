#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic closed-report regressions; these are not an actual route trial."""

import copy
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / "protected-quote-route.py"))
SHA = "a" * 40


def fixture():
    def inline_peer(key):
        raw = bytes.fromhex("002408011220" + key)
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        number, encoded = int.from_bytes(raw, "big"), ""
        while number:
            number, remainder = divmod(number, 58)
            encoded = alphabet[remainder] + encoded
        return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded
    keys = {name: f"{index+64:02x}" * 32 for index, name in enumerate((*M["ROLES"], *M["PROVIDERS"]))}
    keys.update(relay4="11" * 32, client="22" * 32, relay5="33" * 32)
    peers = {name: inline_peer(key) for name, key in keys.items()}
    nodes = ["relay4", "relay5"]
    paths = [dict(route_context_id="a" * 32, path_id=i+1, relay_peer_id=peers[f"relay{i}"], exit_peer_id=peers["exit"])
        for i in range(2)]
    route = dict(transport="mptcp", route_context_id="a" * 32, paths=paths,
        benchmark_slots=[dict(relay_node=f"relay{i}", relay_peer_id=peers[f"relay{i}"]) for i in range(2)])
    def application(active=False):
        return {node: dict(request_packets=4 if active and node == nodes[0] else 0,
            response_packets=6 if active and node == nodes[0] else 0,
            response_payload_bytes=3000 if active and node == nodes[0] else 0) for node in M["PROVIDERS"]}
    def statistics(count):
        return dict(observed_frames=count, packet_socket_packets=count, packet_socket_drops=0, intake_stopped=True)
    privacy = {role: dict(capture_role=role, content_provider_mode=True, truncated=False, observed_frames=20,
        packet_socket_drops=0, interfaces=["eth0"], interface_statistics=dict(eth0=statistics(20)),
        provider_application=application(role == "exit"), unexpected_provider_application_packets=0,
        unexpected_outer_packets=0, expected_link_down_notifications=0, direct_client_exit_packets=0,
        internet_destination_outer_packets=0, client_public_packets=0, outbound_client_discovery_attempt_packets=0,
        client_leg_wireguard_data_datagrams=4, exit_leg_wireguard_data_datagrams=4) for role in M["ROLES"]}
    ips = M["COMMON"]["PUBLIC_IPS"]
    control = dict(capture_role="content-control", content_provider_mode=True, truncated=False,
        observed_frames=4, packet_socket_drops=0, interfaces=["cp0", "cp1"],
        interface_statistics=dict(cp0=statistics(4), cp1=statistics(0)), provider_application=application(),
        unexpected_provider_application_packets=0, unexpected_provider_control_packets=0,
        content_control_pairs={f"cp{i}": [ips["relay2"], ips[node]] for i, node in enumerate(nodes)},
        content_control_packets=dict(cp0=dict(inbound=2, outbound=2), cp1=dict(inbound=0, outbound=0)))
    gates = {name: dict(exit_status=1, stdout_empty=name != "device_unavailable",
        signed_exchange_failures_before=0, signed_exchange_failures_after=0 if name == "device_unavailable" else 1)
        for name in ("wrong", "device_unavailable", "repeat")}
    gates.update(grant=dict(max_seconds=600, max_attempts=1, wrong_key_distinct=True, requester_key_bound=True),
        device=dict(provider_mount_checked=True, fixed_device_absent=True), detach_wrong=True, detach_valid=True,
        provider_stopped=True, client_disconnected=True)
    return dict(source_revision=SHA, layout=dict(provider_nodes=nodes, quote_provider=nodes[0],
        control_relay_peer_id=peers["relay2"], provider_key="11" * 32, requester_key="22" * 32, wrong_requester_key="33" * 32),
        gates=gates, inputs=copy.deepcopy(M["INPUTS"]), cases={name: dict(exit_status=1,
            stdout=copy.deepcopy(M["REFUSAL"]) if name == "device-unavailable" else None)
            for name in ("wrong", "device-unavailable", "repeat")},
        operations={name: dict(serving=name != "stop", publications=0)
            for name in ("attach-wrong", "attach-valid", "detach-wrong", "detach-valid", "stop")},
        expected_peers=peers, selected_route=copy.deepcopy(route), live_route=copy.deepcopy(route),
        privacy=privacy, control_privacy=control, control_before=peers["relay2"], control_after=peers["relay2"],
        scope=copy.deepcopy(M["SCOPE"]))


def raw_files(work, value):
    def save(name, item):
        (work / name).write_text(json.dumps(item) + "\n")
    for key, name in (("layout", "layout"), ("gates", "gates"), ("inputs", "inputs"),
                     ("selected_route", "selected-route"), ("live_route", "live-selection"), ("control_privacy", "control-privacy")):
        save("protected-quote-" + name + ".json", value[key])
    for key, name in (("control_before", "status-before"), ("control_after", "status-after")):
        save("protected-quote-" + name + ".json", dict(control_relay_peer_id=value[key]))
    for name, receipt in value["operations"].items():
        save("protected-quote-" + name + ".json", receipt)
    for role, receipt in value["privacy"].items():
        save("protected-quote-privacy-" + role + ".json", receipt)
    for name, result in value["cases"].items():
        (work / ("protected-quote-" + name + ".status")).write_text(str(result["exit_status"]) + "\n")
        (work / ("protected-quote-" + name + ".json")).write_text(
            json.dumps(result["stdout"]) + "\n" if result["stdout"] is not None else "")
    save("a01-expected-peers.json", value["expected_peers"])


class NegativeQuoteRoute(unittest.TestCase):
    def test_closed_three_case_fixture_does_not_claim_hardware_or_two_subflows(self):
        value = fixture()
        M["validate_evidence"](value, SHA)
        self.assertFalse(value["scope"]["hardware_attestation"])
        self.assertFalse(value["scope"]["private_task_execution"])
        self.assertFalse(value["scope"]["two_subflow_payload_proven"])

    def test_refusal_requires_exact_typed_eight_fields(self):
        for key, original in M["REFUSAL"].items():
            with self.subTest(key=key):
                value = fixture()
                value["cases"]["device-unavailable"]["stdout"][key] = True if type(original) is not bool else 0
                with self.assertRaises(ValueError):
                    M["validate_evidence"](value, SHA)
        value = fixture()
        value["cases"]["device-unavailable"]["stdout"]["raw_report"] = "private"
        with self.assertRaises(ValueError):
            M["validate_evidence"](value, SHA)

    def test_timeout_signal_success_or_bool_is_not_expected_cli_failure(self):
        for case in ("wrong", "device-unavailable", "repeat"):
            for status in (0, True, 124, 137, -9):
                with self.subTest(case=case, status=status):
                    value = fixture()
                    value["cases"][case]["exit_status"] = status
                    with self.assertRaises(ValueError):
                        M["validate_evidence"](value, SHA)

    def test_non_signed_exchange_failure_does_not_prove_expected_rejection(self):
        for case in ("wrong", "repeat"):
            for count in (0, 2, True, -1):
                with self.subTest(case=case, count=count):
                    value = fixture()
                    value["gates"][case]["signed_exchange_failures_after"] = count
                    with self.assertRaises(ValueError):
                        M["validate_evidence"](value, SHA)

    def test_original_finite_grant_device_probe_and_cleanup_are_required(self):
        mutations = (("grant", "max_attempts", 2), ("grant", "max_seconds", 601),
            ("grant", "max_attempts", True), ("grant", "requester_key_bound", False),
            ("device", "fixed_device_absent", False), ("device", "provider_mount_checked", False))
        for parent, key, replacement in mutations:
            value = fixture()
            value["gates"][parent][key] = replacement
            with self.subTest(parent=parent, key=key), self.assertRaises(ValueError):
                M["validate_evidence"](value, SHA)
        for name in ("detach_wrong", "detach_valid", "provider_stopped", "client_disconnected"):
            value = fixture()
            value["gates"][name] = False
            with self.subTest(name=name), self.assertRaises(ValueError):
                M["validate_evidence"](value, SHA)

    def test_route_identity_and_selection_cannot_change(self):
        for key, replacement in (("transport", "tcp"), ("route_context_id", "b" * 32)):
            value = fixture()
            value["live_route"][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                M["validate_evidence"](value, SHA)
        value = fixture()
        value["layout"]["quote_provider"] = "relay0"
        with self.assertRaises(ValueError):
            M["validate_evidence"](value, SHA)

    def test_valid_but_unrelated_public_key_does_not_match_selected_peer(self):
        for name in ("provider_key", "requester_key", "wrong_requester_key"):
            value = fixture()
            value["layout"][name] = "bb" * 32
            with self.subTest(name=name), self.assertRaises(ValueError):
                M["validate_evidence"](value, SHA)

    def test_incomplete_capture_or_direct_provider_traffic_is_rejected(self):
        for role in M["ROLES"]:
            for key, replacement in (("truncated", True), ("packet_socket_drops", 1), ("direct_client_exit_packets", 1)):
                value = fixture()
                value["privacy"][role][key] = replacement
                with self.subTest(role=role, key=key), self.assertRaises(ValueError):
                    M["validate_evidence"](value, SHA)
        value = fixture()
        value["privacy"]["relay0"]["provider_application"]["relay4"]["request_packets"] = 1
        with self.assertRaises(ValueError):
            M["validate_evidence"](value, SHA)

    def test_no_required_bulk_payload_threshold_for_short_refusal(self):
        value = fixture()
        value["privacy"]["relay1"]["client_leg_wireguard_data_datagrams"] = 0
        value["privacy"]["relay1"]["exit_leg_wireguard_data_datagrams"] = 0
        M["validate_evidence"](value, SHA)
        value["privacy"]["relay0"]["client_leg_wireguard_data_datagrams"] = 0
        with self.assertRaises(ValueError):
            M["validate_evidence"](value, SHA)

    def test_original_files_reconstruct_and_do_not_export_unselected_fields(self):
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            raw_files(work, value)
            path = work / "protected-quote-privacy-client.json"
            raw = json.loads(path.read_text())
            raw["raw_packet_dump"] = "must not be published"
            path.write_text(json.dumps(raw))
            self.assertEqual(M["build_evidence"](work, SHA), value)
            (work / "protected-quote-wrong.json").write_text(" \n")
            with self.assertRaises(ValueError):
                M["build_evidence"](work, SHA)

    def test_reader_rejects_duplicate_keys_symlinks_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            path = work / "input"
            path.write_text('{"x":1,"x":2}')
            with self.assertRaises(ValueError):
                M["read"](path)
            link = work / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                M["read"](link)
            fifo = work / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                M["read"](fifo)
            path.write_bytes(b"x" * 4097)
            with self.assertRaises(ValueError):
                M["bytes_at"](path, 4096)

    def test_public_preparation_uses_exact_fixtures_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            M["prepare"](work, HERE.parent.parent)
            self.assertEqual(M["read"](work / "protected-quote-inputs.json"), M["INPUTS"])
            policy = M["read"](work / "protected-quote-inputs/policy.json")
            self.assertEqual(policy["expected_measurement"], "22" * 48)
            self.assertNotIn("production_root_authorized", policy)
            with self.assertRaises(FileExistsError):
                M["prepare"](work, HERE.parent.parent)

    def test_finalize_retains_failure_without_inventing_missing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, output = root / "work", root / "output"
            work.mkdir(); output.mkdir()
            with self.assertRaises(ValueError):
                M["finalize"](work, output, SHA, "1", "true", "0", "protected-quote-exchange", "QUOTE_FAILED")
            value = M["read"](output / M["EXPORT_NAMES"][0])
            self.assertFalse(value["success"])
            self.assertIsNone(value["evidence"])
            self.assertFalse(value["host_state"]["unchanged"])

    def test_complete_guest_evidence_still_needs_separate_original_vm_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, output = root / "work", root / "output"
            work.mkdir(); output.mkdir()
            M["write"](work / "protected-quote-route-evidence.json", fixture())
            M["write"](work / "a15-evidence.json", dict(unchanged=True))
            M["finalize"](work, output, SHA, "0", "true", "0", "protected-quote-complete", "NONE")
            self.assertEqual(set(path.name for path in output.iterdir()), {"protected-quote-route.json"})
            value = dict(schema_version=1, source_revision=SHA, qemu_started=True, qemu_joined=True,
                private_guest_state_removed=True)
            M["validate_vm_cleanup"](value, SHA)
            for key in ("qemu_joined", "private_guest_state_removed", "qemu_started"):
                broken = dict(value, **{key: False})
                with self.subTest(key=key), self.assertRaises(ValueError):
                    M["validate_vm_cleanup"](broken, SHA)
            with self.assertRaises(ValueError):
                M["validate_vm_cleanup"](value, "b" * 40)


if __name__ == "__main__":
    unittest.main()
