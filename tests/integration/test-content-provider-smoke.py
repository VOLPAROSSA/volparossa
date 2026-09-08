#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic checker/classifier tests, not claims of an actual network transfer."""

import ast
import copy
import json
from pathlib import Path
import runpy
import socket
import struct
import tempfile
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
    privacy["exit"]["provider_payload_timing"] = dict(
        enabled=True, clock="linux-so-timestampns-new", errors=0,
        milestones_bytes=[65536, 983040],
        providers={node: [100 + 50 * provider_nodes.index(node), 300 + 50 * provider_nodes.index(node)]
                   if node in provider_nodes else [0, 0] for node in CHECK["CANDIDATES"]})
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
    evidence = dict(success=True, provider_payload_overlap_ns=150,
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
    evidence["ordinary_publication"] = user_fixture(evidence)
    evidence["named_publication"] = named_fixture(evidence)
    return evidence


def named_fixture(base):
    return dict(success=True, selected_route=copy.deepcopy(base["selected_route"]),
                privacy=copy.deepcopy(base["privacy"]),
                control_privacy=copy.deepcopy(base["control_underlay"]["capture"]),
                cleanup=dict(user_output_removed=True, user_directory_removed=True),
                serves={node: dict(serving=True, publications=1, replication_enabled=False)
                        for node in base["layout"]["provider_nodes"]},
                fetch=dict(operation="named_content_download", publisher_key=base["publication"]["publisher_hex"],
                    name="disposable-native-network-publication", revision=1, manifest_id="d" * 64,
                    sha256=CHECK["SHA"], bytes=CHECK["BYTES"], chunks=9, providers_used=2,
                    provider_peer_ids=base["fetch"]["provider_peer_ids"], peer_bytes=CHECK["BYTES"],
                    control_relay_peer_id=base["layout"]["control_relay_peer_id"],
                    origin_authenticated=False, globally_latest=False, local_delivery=True,
                    output_mode="0600", ownership_changed=False, local_output="/user/named.bin", cache="/agent/named"),
                output=dict(sha256=CHECK["SHA"], bytes=CHECK["BYTES"], path="/user/named.bin", agent_cache="/agent/named",
                    user_uid=1001, agent_uid=1002, control_gid=1003, agent_gid=1002,
                    output_mode="0600", cache_mode="0700", fresh_cache=True, client_manifest_removed=True,
                    no_manifest_argument=True, agent_mount_positive_control=True, agent_cannot_read_user_output=True,
                    client_cannot_read_provider_caches=True, no_clobber_verified=True))


def user_fixture(base):
    node = base["layout"]["provider_nodes"][0]
    privacy = copy.deepcopy(base["privacy"])
    for name, counters in privacy["exit"]["provider_application"].items():
        counters.update(request_packets=50 if name == node else 0,
                        response_packets=1800 if name == node else 0,
                        response_payload_bytes=CHECK["BYTES"] + 10000 if name == node else 0)
    imported = dict(operation="content_import", manifest_id="e" * 64, complete=True,
                    content_bytes=CHECK["BYTES"], chunks=9, public_content=True,
                    cache="/user/source", agent_cache=f"/agent/{node}/import",
                    ownership_changed=False, network_transfer=False,
                    recipient_decryption_performed=False, private_keys_transferred=False,
                    ciphertext_format_verified=False, origin_authenticated=False)
    exported = dict(imported, operation="content_export", cache="/user/received",
                    agent_cache="/agent/client/download")
    return dict(success=True, expected_peers=copy.deepcopy(base["expected_peers"]),
                layout=copy.deepcopy(base["layout"]), selected_route=copy.deepcopy(base["selected_route"]),
                privacy=privacy,
                output=dict(provider_node=node, bytes=CHECK["BYTES"], sha256=CHECK["SHA"],
                    route_context_id="a" * 32, user_uid=1001, agent_uid=1002, control_gid=1003, agent_gid=1002,
                    cache_modes="0700", output_mode="0600", fresh_destination_cache=True,
                    agent_cannot_read_user_state=True, user_cannot_read_agent_caches=True,
                    client_mount_cannot_read_provider_cache=True, encrypted_identity_unchanged=True,
                    publisher_process_exited_before_fetch=True, explicit_public_fixture=True,
                    https_origin_authenticated=False, mailbox_claimed=False),
                publish=dict(operation="offline_content_publish", network_publication=False,
                    publisher_key_hex="2" * 64, bytes=CHECK["BYTES"], chunks=9, cache="/user/source"),
                **{"import": imported, "export": exported},
                serve=dict(serving=True, publications=2),
                fetch=dict(bytes=CHECK["BYTES"], chunks=9, peer_bytes=CHECK["BYTES"], providers_used=1,
                    provider_peer_ids=[base["expected_peers"][node]], origin_authenticated=False,
                    origin_body_bytes=0, control_relay_peer_id=base["layout"]["control_relay_peer_id"]),
                assemble=dict(operation="offline_content_assemble", network_retrieval=False,
                    bytes=CHECK["BYTES"], chunks=9, publisher_key_hex="2" * 64, output="/user/output.bin"),
                private_cleanup=dict(encrypted_identity_removed=True, passphrase_removed=True,
                    input_and_output_removed=True, private_directory_removed=True))


class ContentProviderContract(unittest.TestCase):
    def test_parallel_proof_requires_overlapping_kernel_bulk_not_handshake_or_drain_times(self):
        evidence = fixture()
        nodes = evidence["layout"]["provider_nodes"]
        capture = evidence["privacy"]["exit"]
        self.assertEqual(CHECK["provider_payload_overlap"](capture, nodes), 150)
        for mutate in (
            lambda value: value.update(enabled=False),
            lambda value: value.update(clock="userspace-recv-time"),
            lambda value: value.update(errors=1),
            lambda value: value.update(milestones_bytes=[1, 100]),
            lambda value: value["providers"].update({nodes[1]: [0, 0]}),
            lambda value: value["providers"].update({nodes[1]: [300, 400]}),
            lambda value: value["providers"].update({nodes[1]: [400, 500]}),
            lambda value: value["providers"].update({nodes[1]: [300, 200]}),
        ):
            bad = copy.deepcopy(capture)
            mutate(bad["provider_payload_timing"])
            with self.assertRaises(ValueError):
                CHECK["provider_payload_overlap"](bad, nodes)
        evidence["provider_payload_overlap_ns"] = 151
        with self.assertRaises(ValueError):
            CHECK["validate_transfer"](evidence)

    def test_actual_kernel_timestamp_decoder_and_bounded_bulk_milestones(self):
        text = (HERE / "kvm-alpha-topology.sh").read_text(encoding="utf-8")
        embedded = text.split('cat >"$WORK/bin/privacy-observer.py" <<\'PYTHON\'\n', 1)[1].split("\nPYTHON\n", 1)[0]
        names = {"decode_packet_timestamp", "record_provider_payload_timing", "record_provider_application"}
        functions = [node for node in ast.parse(embedded).body
                     if isinstance(node, ast.FunctionDef) and node.name in names]
        environment = dict(socket=socket, struct=struct, SO_TIMESTAMPNS_NEW=64,
            provider_timing_enabled=True, content_provider_mode=True, frame_timestamp_ns=0,
            provider_addresses={"49.165.5.1": "relay4"}, unexpected_provider_application_packets=0,
            provider_application={"relay4": dict(request_packets=0, response_packets=0, response_payload_bytes=0)},
            provider_payload_timing=dict(milestones_bytes=[65536, 983040], errors=0, providers={"relay4": [0, 0]}),
            provider_last_timestamp={"relay4": 0})
        exec(compile(ast.Module(body=functions, type_ignores=[]), "actual-packet-timing", "exec"), environment)
        decode = environment["decode_packet_timestamp"]
        ancillary = (socket.SOL_SOCKET, 64, struct.pack("=qq", 2200000000, 123))
        timestamp = decode([ancillary], 0)
        self.assertEqual(timestamp, 2200000000000000123)
        for records, flags in (
            ([], 0), ([ancillary, ancillary], 0), ([ancillary], socket.MSG_CTRUNC),
            ([ancillary], socket.MSG_TRUNC), ([(socket.SOL_SOCKET, 64, bytes(8))], 0),
            ([(socket.SOL_SOCKET, 64, bytes(24))], 0),
            ([(socket.SOL_SOCKET, 64, struct.pack("=qq", 1, 1000000000))], 0),
        ):
            self.assertEqual(decode(records, flags), 0)
        environment["frame_timestamp_ns"] = timestamp
        record = environment["record_provider_application"]
        # ACKs and a small TLS handshake cannot establish a useful-data timing window.
        for size in (0, 2000, 0):
            record("exit", socket.IPPROTO_TCP, "49.165.5.1", 18080, "46.162.3.1", 32000, size)
        timing = environment["provider_payload_timing"]
        self.assertEqual(timing["providers"]["relay4"], [0, 0])
        bulk = environment["record_provider_payload_timing"]
        bulk("relay4", 65536, timestamp + 1)
        bulk("relay4", 983040, timestamp + 2)
        self.assertEqual(timing["providers"]["relay4"], [timestamp + 1, timestamp + 2])
        bulk("relay4", 1000000, 0)
        bulk("relay4", 1000000, timestamp)
        self.assertEqual(timing["errors"], 2)

    def test_name_lookup_requires_exact_object_no_manifest_and_both_real_providers(self):
        base = fixture()
        for mutate in (
            lambda item: item["fetch"].update(name="different-name"),
            lambda item: item["fetch"].update(manifest_id="e" * 64),
            lambda item: item["fetch"].update(globally_latest=True),
            lambda item: item["fetch"].update(providers_used=1),
            lambda item: item["output"].update(client_manifest_removed=False),
            lambda item: item["output"].update(user_uid=item["output"]["agent_uid"]),
            lambda item: item["cleanup"].update(user_output_removed=False),
            lambda item: item["privacy"]["exit"].update(outbound_client_discovery_attempt_packets=1),
        ):
            named = copy.deepcopy(base["named_publication"])
            mutate(named)
            with self.assertRaises(ValueError):
                CHECK["validate_named_publication"](named, base["publication"], base["expected_peers"],
                                                     base["layout"], base["selected_route"]["route_context_id"])

    def test_user_publication_builder_reads_the_exact_cli_and_capture_files(self):
        ordinary = fixture()["ordinary_publication"]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name, suffix in (("output", "object"), ("publish", "publish"), ("import", "import"),
                                 ("serve", "serve"), ("fetch", "fetch"), ("export", "export"),
                                 ("assemble", "assemble"), ("private_cleanup", "cleanup"),
                                 ("selected_route", "selection")):
                (work / f"content-provider-user-{suffix}.json").write_text(json.dumps(ordinary[name]))
            for role, capture in ordinary["privacy"].items():
                (work / f"content-provider-user-privacy-{role}.json").write_text(json.dumps(capture))
            (work / "content-provider-layout.json").write_text(json.dumps(ordinary["layout"]))
            (work / "a01-expected-peers.json").write_text(json.dumps(ordinary["expected_peers"]))
            self.assertEqual(CHECK["build_user_publication"](work), ordinary)

    def test_normal_user_publication_requires_real_peer_bytes_account_boundaries_and_cleanup(self):
        ordinary = fixture()["ordinary_publication"]
        CHECK["validate_user_publication"](ordinary)
        for mutate in (
            lambda value: value["fetch"].update(peer_bytes=0),
            lambda value: value["fetch"].update(provider_peer_ids=["peer-client"]),
            lambda value: value["export"].update(manifest_id="f" * 64),
            lambda value: value["output"].update(user_uid=1002),
            lambda value: value["output"].update(client_mount_cannot_read_provider_cache=False),
            lambda value: value["private_cleanup"].update(passphrase_removed=False),
            lambda value: value["privacy"]["relay0"].update(exit_leg_wireguard_data_datagrams=0),
            lambda value: value["privacy"]["exit"]["provider_application"]["relay4"].update(response_payload_bytes=0),
        ):
            bad = copy.deepcopy(ordinary)
            mutate(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_user_publication"](bad)

    def test_actual_kernel_route_array_files_are_read_and_bound(self):
        evidence = fixture()
        names = {
            "layout": "layout", "publication": "publication", "status_before": "status-before",
            "status_after": "status-after", "output": "object", "fetch": "fetch",
            "https": "https-evidence", "selected_route": "live-selection",
            "ordinary_publication": "user-publication",
        }
        files = {f"content-provider-{suffix}.json": evidence[key] for key, suffix in names.items()}
        files["a01-expected-peers.json"] = evidence["expected_peers"]
        named = evidence["named_publication"]
        for key, suffix in (("fetch", "fetch"), ("output", "output"), ("cleanup", "cleanup"),
                            ("selected_route", "selection"), ("control_privacy", "control")):
            files[f"content-provider-named-{suffix}.json"] = named[key]
        for role, capture in named["privacy"].items():
            files[f"content-provider-named-privacy-{role}.json"] = capture
        for node, receipt in named["serves"].items():
            files[f"content-provider-named-{node}-serve.json"] = receipt
        files["content-provider-control-privacy.json"] = evidence["control_underlay"]["capture"]
        for node, routes in evidence["control_underlay"]["routes"].items():
            for direction, rows in routes.items():
                files[f"content-provider-control-{node}-{direction}.json"] = rows
        for role, capture in evidence["privacy"].items():
            files[f"content-provider-privacy-{role}.json"] = capture
        for node, states in evidence["providers"].items():
            for operation, state in states.items():
                files[f"content-provider-{node}-{operation}.json"] = state
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name, value in files.items():
                (work / name).write_text(json.dumps(value), encoding="ascii")
            self.assertEqual(CHECK["build_evidence"](work), evidence)
            # Keep every existing exact source/destination/gateway/device check after decoding.
            wrong = copy.deepcopy(files["content-provider-control-relay4-out.json"])
            wrong[0]["dev"] = "underlay"
            (work / "content-provider-control-relay4-out.json").write_text(
                json.dumps(wrong), encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["build_evidence"](work)

    def test_route_reader_rejects_wrong_shape_size_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            route = Path(directory) / "route.json"
            for value in ({}, [], [{}, {}], ["not a route"]):
                with self.subTest(value=value):
                    route.write_text(json.dumps(value), encoding="ascii")
                    with self.assertRaises(ValueError):
                        CHECK["read_route"](route)
            route.write_text(" " * 65537, encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["read_route"](route)
            alias = Path(directory) / "alias.json"
            alias.symlink_to(route)
            with self.assertRaises(ValueError):
                CHECK["read_route"](alias)

    def test_current_control_relay_is_excluded_without_changing_roles(self):
        for control in ("relay0", "relay1", "relay2", "relay3", "relay4", "relay5"):
            evidence = fixture(control)
            CHECK["validate_transfer"](evidence)
            self.assertNotIn(control, evidence["layout"]["provider_nodes"])
        self.assertEqual(fixture("relay4")["layout"]["provider_nodes"], ["relay5", "relay3"])

    def test_exact_scoped_report(self):
        report = dict(report_kind="volparossa-native-content-providers", source_revision="a" * 40,
                      explicit_origin_authenticated_https=True, normal_user_publication=True, native_name_retrieval=True,
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
        environment = dict(socket=socket, content_provider_mode=True, provider_timing_enabled=False,
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
