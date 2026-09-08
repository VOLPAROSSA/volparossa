#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure evidence-gate regressions; these synthetic captures are not network proof."""

import copy
import json
from pathlib import Path
import runpy
import tempfile
import unittest

CHECK = runpy.run_path(str(Path(__file__).with_name("content-provider-adaptive-smoke.py")))


def filter_fixture():
    table = "vpa_content_adaptive_client_control"
    entries = [dict(metainfo={}), dict(table=dict(family="inet", name=table))]
    for chain, key in (("input", "iifname"), ("output", "oifname")):
        entries.append(dict(chain=dict(family="inet", table=table, name=chain, type="filter",
                                       hook=chain, prio=-25, policy="accept")))
        for field in ("sport", "dport"):
            entries.append(dict(rule=dict(family="inet", table=table, chain=chain, expr=[
                dict(match=dict(op="==", left=dict(meta=dict(key=key)),
                                right=dict(set=["cr3", "cr4", "cr5"]))),
                dict(match=dict(op="==", left=dict(payload=dict(protocol="udp", field=field)), right=41000)),
                dict(counter=dict(packets=0, bytes=0)), {"drop": None}])))
    return dict(nftables=entries)


def fixture(control_node="relay2"):
    nodes, roles = CHECK["NODES"], CHECK["ROLES"]
    peers = {node: f"peer-{node}" for node in (*roles, *nodes)}
    control, addresses = peers[control_node], CHECK["BASE"]["PUBLIC_IPS"]
    privacy = {}
    for role in roles:
        application = {node: dict(request_packets=0, response_packets=0, response_payload_bytes=0)
                       for node in nodes}
        if role == "exit":
            application = {node: dict(request_packets=100, response_packets=1000,
                                     response_payload_bytes=CHECK["SHARD_BYTES"] + 10000) for node in nodes}
        privacy[role] = dict(capture_role=role, content_provider_mode=True, truncated=False,
            observed_frames=2000, packet_socket_drops=0, interfaces=["physical"],
            interface_statistics={"physical": dict(intake_stopped=True, observed_frames=2000,
                packet_socket_packets=2000, packet_socket_drops=0)}, unexpected_outer_packets=0,
            expected_link_down_notifications=0, unexpected_provider_application_packets=0,
            direct_client_exit_packets=0, internet_destination_outer_packets=0,
            client_public_packets=0, outbound_client_discovery_attempt_packets=0,
            client_leg_wireguard_data_datagrams=900, exit_leg_wireguard_data_datagrams=900,
            provider_application=application)
    privacy["exit"]["provider_payload_timing"] = dict(enabled=True, clock="linux-so-timestampns-new",
        errors=0, milestones_bytes=[65536, 983040],
        providers={node: [100 + index * 20, 300 + index * 20] for index, node in enumerate(nodes)})
    selected = dict(transport="mptcp", route_context_id="b" * 32,
        paths=[dict(route_context_id="b" * 32, path_id=i + 1, relay_peer_id=peers[f"relay{i}"],
                    exit_peer_id=peers["exit"]) for i in range(2)],
        benchmark_slots=[dict(relay_node=f"relay{i}", relay_peer_id=peers[f"relay{i}"])
                         for i in range(2)])
    capture = dict(capture_role="content-control", content_provider_mode=True, truncated=False,
        observed_frames=60, packet_socket_drops=0, interfaces=[f"ac{i}" for i in range(3)],
        content_control_pairs={f"ac{i}": [addresses[control_node], addresses[node]] for i, node in enumerate(nodes)},
        content_control_packets={f"ac{i}": dict(inbound=10, outbound=10) for i in range(3)},
        unexpected_provider_control_packets=0, unexpected_provider_application_packets=0,
        provider_application=copy.deepcopy(privacy["client"]["provider_application"]),
        interface_statistics={f"ac{i}": dict(intake_stopped=True, observed_frames=20,
            packet_socket_packets=20, packet_socket_drops=0) for i in range(3)})
    routes = {node: dict(out=[dict(dst=addresses[node], prefsrc=addresses[control_node],
                                  dev=f"ac{i}", gateway=f"10.241.{83+i}.2")],
                         back=[dict(dst=addresses[control_node], prefsrc=addresses[node],
                                    dev=f"ap{i}", gateway=f"10.241.{83+i}.1")]) for i, node in enumerate(nodes)}
    publication = dict(report_kind="volparossa-content-adaptive-provider-seed", bytes=CHECK["BYTES"],
        chunks=15, object_sha256=CHECK["SHA"], publisher_hex="2" * 64, manifest_id="e" * 64,
        publisher_removed=True, publisher_private_key_persisted=False, recipient_encrypted=False,
        created_unix_seconds=1000, expires_unix_seconds=4600)
    for label in "abc":
        publication[f"replica_{label}_chunks"] = 5
        publication[f"replica_{label}_bytes"] = CHECK["SHARD_BYTES"]
    return dict(success=True, publication=publication, expected_peers=peers,
        previous_context="a" * 32, selected_before=copy.deepcopy(selected), selected_route=selected,
        layout=dict(provider_nodes=list(nodes), control_relay_peer_id=control),
        status_before=dict(control_relay_peer_id=control), status_after=dict(control_relay_peer_id=control),
        fetch=dict(operation="native_content", bytes=CHECK["BYTES"], chunks=15, providers_used=3,
            provider_peer_ids=[peers[node] for node in nodes], control_relay_peer_id=control,
            peer_bytes=CHECK["BYTES"], origin_body_bytes=0, origin_range_requests=0, origin_authenticated=False),
        output=dict(bytes=CHECK["BYTES"], sha256=CHECK["SHA"], client_cache_initially_absent=True,
            client_mount_positive_control=True, client_mount_cannot_read_replica_stores=True,
            publisher_process_exited_before_fetch=True, event_baseline_unix_ms=1000,
            generic_dht_queries=1, authenticated_upstream_offers=3, client_forwarded_discovery=1),
        providers={node: dict(before=dict(serving=False, publications=0),
            serve=dict(serving=True, publications=1, replication_enabled=False),
            stop=dict(serving=False, publications=0)) for node in nodes},
        privacy=privacy, control_underlay=dict(capture=capture, routes=routes), control_filter=filter_fixture(),
        provider_payload_overlap_ns=160, cleanup=dict(previous_route_disconnected=True,
            route_disconnected=True, active_contexts=0, paths_empty=True,
            client_output_removed=True, client_manifest_removed=True))


def raw_files(evidence):
    prefix = CHECK["PREFIX"]
    files = {f"{prefix}-{suffix}.json": evidence[key] for key, suffix in (
        ("publication", "publication"), ("layout", "layout"), ("status_before", "status-before"),
        ("status_after", "status-after"), ("fetch", "fetch"), ("output", "object"),
        ("selected_before", "selection"), ("selected_route", "live-selection"), ("cleanup", "cleanup"),
        ("control_filter", "control-filter"))}
    files["a01-expected-peers.json"] = evidence["expected_peers"]
    files["content-provider-selection.json"] = dict(route_context_id=evidence["previous_context"])
    for label in ("content-provider", prefix):
        files[f"{label}-final-status.txt"] = "connected: false\nactive contexts: 0\n"
        files[f"{label}-final-paths.txt"] = ""
    for node, receipts in evidence["providers"].items():
        for operation, receipt in receipts.items():
            files[f"{prefix}-{node}-{operation}.json"] = receipt
    for role, capture in evidence["privacy"].items():
        files[f"{prefix}-privacy-{role}.json"] = capture
    files[f"{prefix}-control-privacy.json"] = evidence["control_underlay"]["capture"]
    for node, routes in evidence["control_underlay"]["routes"].items():
        for direction, route in routes.items():
            files[f"{prefix}-control-{node}-{direction}.json"] = route
    return files


class AdaptiveEvidence(unittest.TestCase):
    def test_three_kernel_payload_windows_and_raw_rebuild(self):
        for node in ("relay0", "relay1", "relay2"):
            CHECK["validate"](fixture(node))
        evidence = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for filename, value in raw_files(evidence).items():
                (work / filename).write_text(value if isinstance(value, str) else json.dumps(value), encoding="ascii")
            self.assertEqual(CHECK["build_evidence"](work), evidence)
            (work / "content-provider-adaptive-final-paths.txt").write_text("context=still-active\n", encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["build_evidence"](work)

    def test_two_provider_success_or_nonoverlap_cannot_substitute(self):
        for mutation in (
                lambda e: e["fetch"].update(providers_used=2),
                lambda e: e["fetch"]["provider_peer_ids"].pop(),
                lambda e: e["privacy"]["exit"]["provider_payload_timing"]["providers"].update(relay5=[301, 500]),
                lambda e: e["privacy"]["exit"]["provider_payload_timing"].update(errors=1),
                lambda e: e["privacy"]["exit"]["provider_payload_timing"].update(clock="userspace-recv"),
                lambda e: e["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=65536)):
            evidence = fixture()
            mutation(evidence)
            with self.assertRaises(ValueError):
                CHECK["validate"](evidence)

    def test_cold_cache_discovery_source_accounting_and_cleanup_are_mandatory(self):
        for mutation in (
                lambda e: e["output"].update(client_mount_positive_control=False),
                lambda e: e["output"].update(client_cache_initially_absent=False),
                lambda e: e["output"].update(authenticated_upstream_offers=2),
                lambda e: e["output"].update(sha256="0" * 64),
                lambda e: e["fetch"].update(peer_bytes=1),
                lambda e: e["fetch"].update(origin_body_bytes=1),
                lambda e: e.update(previous_context=e["selected_route"]["route_context_id"]),
                lambda e: e["cleanup"].update(client_output_removed=False),
                lambda e: e["providers"]["relay5"]["stop"].update(serving=True)):
            evidence = fixture()
            mutation(evidence)
            with self.assertRaises(ValueError):
                CHECK["validate"](evidence)

    def test_three_links_privacy_drain_and_filter_are_exact(self):
        for mutation in (
                lambda e: e["control_underlay"]["capture"]["content_control_packets"]["ac2"].update(outbound=0),
                lambda e: e["control_underlay"]["routes"]["relay5"]["back"][0].update(dev="pc2"),
                lambda e: e["privacy"]["relay0"].update(exit_leg_wireguard_data_datagrams=0),
                lambda e: e["privacy"]["client"].update(direct_client_exit_packets=1),
                lambda e: e["privacy"]["exit"]["interface_statistics"]["physical"].update(packet_socket_packets=2001),
                lambda e: e["control_filter"]["nftables"].pop()):
            evidence = fixture()
            mutation(evidence)
            with self.assertRaises(ValueError):
                CHECK["validate"](evidence)


if __name__ == "__main__":
    unittest.main()
