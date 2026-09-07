#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic checker/classifier tests, not claims of an actual network transfer."""

import ast
import copy
from pathlib import Path
import runpy
import socket
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-provider-smoke.py"))


def fixture(control_node="relay2"):
    peers = {name: f"peer-{name}" for name in (*CHECK["ROLES"], "relay3", "relay4", "relay5")}
    provider_nodes = [node for node in CHECK["CANDIDATES"] if node != control_node][:2]
    paths = [dict(route_context_id="a" * 32, path_id=index + 1,
                  relay_peer_id=peers[f"relay{index}"], exit_peer_id=peers["exit"])
             for index in range(2)]
    privacy = {}
    for role in CHECK["ROLES"]:
        application = {node: dict(request_packets=0, response_packets=0, response_payload_bytes=0)
                       for node in CHECK["CANDIDATES"]}
        if role == "exit":
            for node in provider_nodes:
                application[node] = dict(request_packets=30, response_packets=900,
                                         response_payload_bytes=1100000)
        privacy[role] = dict(
            capture_role=role, content_provider_mode=True, truncated=False, observed_frames=2000,
            interfaces=["physical"], interface_statistics={"physical": dict(
                observed_frames=2000, packet_socket_packets=2000, packet_socket_drops=0,
                intake_stopped=True)}, packet_socket_drops=0, unexpected_outer_packets=0,
            expected_link_down_notifications=0, unexpected_provider_application_packets=0,
            direct_client_exit_packets=0, internet_destination_outer_packets=0,
            client_public_packets=0, outbound_client_discovery_attempt_packets=0,
            client_leg_wireguard_data_datagrams=900, exit_leg_wireguard_data_datagrams=900,
            provider_application=application)
    control_capture = dict(
        capture_role="content-control", content_provider_mode=True, truncated=False,
        observed_frames=40, packet_socket_drops=0, interfaces=["cp0", "cp1"],
        content_control_pairs={f"cp{i}": [CHECK["PUBLIC_IPS"][control_node], CHECK["PUBLIC_IPS"][node]]
                               for i, node in enumerate(provider_nodes)},
        content_control_packets={name: dict(inbound=10, outbound=10) for name in ("cp0", "cp1")},
        unexpected_provider_control_packets=0, unexpected_provider_application_packets=0,
        provider_application=copy.deepcopy(privacy["client"]["provider_application"]),
        interface_statistics={name: dict(intake_stopped=True, observed_frames=20,
                                         packet_socket_packets=20, packet_socket_drops=0)
                              for name in ("cp0", "cp1")})
    control_routes = {node: dict(
        out=[dict(dst=CHECK["PUBLIC_IPS"][node], prefsrc=CHECK["PUBLIC_IPS"][control_node],
                  dev=f"cp{i}", gateway=f"10.241.{80+i}.2")],
        back=[dict(dst=CHECK["PUBLIC_IPS"][control_node], prefsrc=CHECK["PUBLIC_IPS"][node],
                   dev=f"pc{i}", gateway=f"10.241.{80+i}.1")])
        for i, node in enumerate(provider_nodes)}
    evidence = dict(success=True,
        control_underlay=dict(capture=control_capture, routes=control_routes),
        layout=dict(provider_nodes=provider_nodes, control_relay_peer_id=peers[control_node]),
        status_before=dict(control_relay_peer_id=peers[control_node]),
        status_after=dict(control_relay_peer_id=peers[control_node]), publication=dict(
        bytes=CHECK["BYTES"], object_sha256=CHECK["SHA"], chunks=9, manifest_id="d" * 64,
        replica_a_chunks=5, replica_b_chunks=4, publisher_removed=True,
        publisher_private_key_persisted=False, publisher_hex="1" * 64),
        output=dict(bytes=CHECK["BYTES"], sha256=CHECK["SHA"], client_cache_initially_absent=True,
                    client_mount_cannot_read_replica_stores=True, publisher_process_exited_before_fetch=True,
                    event_baseline_unix_ms=1000, generic_dht_queries=1,
                    authenticated_upstream_offers=2, client_forwarded_discovery=1),
        fetch=dict(bytes=CHECK["BYTES"], chunks=9, providers_used=2, serving=False,
                   provider_peer_ids=[peers[node] for node in provider_nodes],
                   control_relay_peer_id=peers[control_node]), expected_peers=peers,
        providers={node: dict(serve=dict(serving=True, publications=1),
                             stop=dict(serving=False, publications=0)) for node in provider_nodes},
        selected_route=dict(transport="mptcp", route_context_id="a" * 32, paths=paths,
                            benchmark_slots=[dict(relay_node=f"relay{i}", relay_peer_id=peers[f"relay{i}"])
                                             for i in range(2)]), privacy=privacy)
    evidence["https"] = runpy.run_path(str(HERE / "test-content-provider-https-smoke.py"))["fixture"](
        control_node, evidence["publication"])
    return evidence


class ContentProviderContract(unittest.TestCase):
    def test_current_control_relay_is_excluded_without_changing_roles(self):
        for control in ("relay0", "relay1", "relay2", "relay3", "relay4", "relay5"):
            evidence = fixture(control)
            CHECK["validate_transfer"](evidence)
            self.assertNotIn(control, evidence["layout"]["provider_nodes"])
        self.assertEqual(fixture("relay4")["layout"]["provider_nodes"], ["relay5", "relay3"])

    def test_exact_scoped_report(self):
        report = dict(report_kind="volparossa-native-content-providers", source_revision="a" * 40,
                      explicit_origin_authenticated_https=True,
                      success=True, runner_exit_status=0, cleanup=dict(complete=True, remaining_owned_objects=0),
                      host_state=dict(unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64),
                      transfer=fixture(), **{name: False for name in CHECK["SCOPE"]})
        CHECK["validate_report"](report, "a" * 40)
        for mutate in (
            lambda item: item.update(source_revision="c" * 40),
            lambda item: item.update(full_c02_claimed=True),
            lambda item: item.update(explicit_origin_authenticated_https=False),
            lambda item: item["cleanup"].update(remaining_owned_objects=1),
            lambda item: item["host_state"].update(after_sha256="c" * 64),
        ):
            wrong = copy.deepcopy(report)
            mutate(wrong)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](wrong, "a" * 40)

    def test_substituted_discovery_providers_or_incomplete_physical_proof_fail(self):
        for mutate in (
            lambda item: item["fetch"].update(providers_used=1),
            lambda item: item["fetch"].update(provider_peer_ids=["peer-relay4", "peer-relay4"]),
            lambda item: item["status_after"].update(control_relay_peer_id="peer-relay1"),
            lambda item: item["fetch"].update(control_relay_peer_id="peer-relay1"),
            lambda item: item["layout"].update(control_relay_peer_id="peer-relay4"),
            lambda item: item["layout"].update(provider_nodes=["relay4", "relay4"]),
            lambda item: item["control_underlay"]["capture"].update(unexpected_provider_control_packets=1),
            lambda item: item["control_underlay"]["capture"]["content_control_packets"]["cp1"].update(inbound=0),
            lambda item: item["control_underlay"]["capture"]["interface_statistics"]["cp0"].update(intake_stopped=False),
            lambda item: item["control_underlay"]["routes"]["relay4"]["out"][0].update(dev="underlay"),
            lambda item: item["output"].update(generic_dht_queries=0),
            lambda item: item["output"].update(client_forwarded_discovery=0),
            lambda item: item["output"].update(client_mount_cannot_read_replica_stores=False),
            lambda item: item["output"].update(sha256="c" * 64),
            lambda item: item["privacy"]["client"].update(unexpected_provider_application_packets=1),
            lambda item: item["privacy"]["relay0"].update(exit_leg_wireguard_data_datagrams=0),
            lambda item: item["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=0),
            lambda item: item["privacy"]["exit"]["provider_application"]["relay3"].update(request_packets=1),
            lambda item: item["privacy"]["exit"]["interface_statistics"]["physical"].update(packet_socket_packets=2001),
            lambda item: item["privacy"]["client"].update(truncated=True),
            lambda item: item["providers"]["relay4"]["stop"].update(serving=True),
        ):
            wrong = fixture()
            mutate(wrong)
            with self.assertRaises(ValueError):
                CHECK["validate_transfer"](wrong)

    def test_actual_embedded_classifier_requires_exit_source_and_separates_control(self):
        text = (HERE / "kvm-alpha-topology.sh").read_text(encoding="utf-8")
        embedded = text.split('cat >"$WORK/bin/privacy-observer.py" <<\'PYTHON\'\n', 1)[1].split("\nPYTHON\n", 1)[0]
        tree = ast.parse(embedded)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "record_provider_application")
        environment = dict(socket=socket, content_provider_mode=True,
                           provider_addresses={"49.165.5.1": "relay4", "50.166.6.1": "relay5",
                                               "48.164.4.1": "relay3"},
                           provider_application={name: dict(request_packets=0, response_packets=0,
                                                           response_payload_bytes=0)
                                                 for name in CHECK["CANDIDATES"]},
                           unexpected_provider_application_packets=0)
        exec(compile(ast.Module(body=[function], type_ignores=[]), "actual-provider-classifier", "exec"), environment)
        record = environment["record_provider_application"]
        record("exit", socket.IPPROTO_TCP, "46.162.3.1", 32000, "49.165.5.1", 18080, 100)
        record("exit", socket.IPPROTO_TCP, "49.165.5.1", 18080, "46.162.3.1", 32000, 1400)
        self.assertEqual(environment["provider_application"]["relay4"],
                         dict(request_packets=1, response_packets=1, response_payload_bytes=1400))
        record("exit", socket.IPPROTO_TCP, "48.164.4.1", 18080, "46.162.3.1", 32000, 700)
        self.assertEqual(environment["provider_application"]["relay3"],
                         dict(request_packets=0, response_packets=1, response_payload_bytes=700))
        record("client", socket.IPPROTO_TCP, "43.159.1.1", 32000, "49.165.5.1", 18080, 100)
        record("relay0", socket.IPPROTO_TCP, "42.158.0.1", 32000, "50.166.6.1", 18080, 100)
        record("exit", socket.IPPROTO_TCP, "49.165.5.1", 18080, "43.159.1.1", 32000, 100)
        self.assertEqual(environment["unexpected_provider_application_packets"], 3)
        record("client", socket.IPPROTO_UDP, "43.159.1.1", 41000, "49.165.5.1", 41000, 100)
        self.assertEqual(environment["unexpected_provider_application_packets"], 3)
        environment["content_provider_mode"] = False
        record("client", socket.IPPROTO_TCP, "43.159.1.1", 32000, "49.165.5.1", 18080, 100)
        self.assertEqual(environment["unexpected_provider_application_packets"], 3)

    def test_actual_control_classifier_rejects_app_traffic_and_wrong_endpoints(self):
        text = (HERE / "kvm-alpha-topology.sh").read_text(encoding="utf-8")
        embedded = text.split('cat >"$WORK/bin/privacy-observer.py" <<\'PYTHON\'\n', 1)[1].split("\nPYTHON\n", 1)[0]
        function = next(node for node in ast.parse(embedded).body if isinstance(node, ast.FunctionDef)
                        and node.name == "record_provider_control")
        environment = dict(socket=socket, content_control_pairs={"cp0": ["42.158.0.1", "49.165.5.1"]},
                           content_control_packets={"cp0": dict(inbound=0, outbound=0)},
                           unexpected_provider_control_packets=0)
        exec(compile(ast.Module(body=[function], type_ignores=[]), "actual-control-classifier", "exec"), environment)
        record = environment["record_provider_control"]
        record("cp0", socket.IPPROTO_UDP, "42.158.0.1", 41000, "49.165.5.1", 41000)
        record("cp0", socket.IPPROTO_UDP, "49.165.5.1", 41000, "42.158.0.1", 41000)
        self.assertEqual(environment["content_control_packets"]["cp0"], dict(inbound=1, outbound=1))
        for args in (
            ("cp0", socket.IPPROTO_TCP, "42.158.0.1", 32000, "49.165.5.1", 18080),
            ("cp0", socket.IPPROTO_UDP, "42.158.0.1", 32000, "49.165.5.1", 51820),
            ("cp0", socket.IPPROTO_UDP, "43.159.1.1", 41000, "49.165.5.1", 41000),
            ("cp1", socket.IPPROTO_UDP, "42.158.0.1", 41000, "49.165.5.1", 41000),
        ):
            record(*args)
        self.assertEqual(environment["unexpected_provider_control_packets"], 4)


if __name__ == "__main__":
    unittest.main()
