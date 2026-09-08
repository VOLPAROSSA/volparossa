#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic HTTPS-provider gate tests; not evidence of an actual network transfer."""

import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-provider-https-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-network-smoke.py"))


def fixture(control_node="relay2", native_publication=None):
    """Independent factory: native-provider tests may import it without circular runpy imports."""
    base = BASE["fixture"]()
    original = copy.deepcopy(native_publication) if native_publication is not None else base["publication"]
    if native_publication is None:
        original.update(object_sha256=CHECK["SHA"], manifest_id="d" * 64)
    publication = {key: original[key] for key in
                   ("bytes", "chunks", "object_sha256", "publisher_hex", "manifest_id")}
    publication.update(existing_publication_reused=True, publisher_private_key_persisted=False,
                       metadata_bytes=1024)
    peers = {node: f"peer-{node}" for node in (*CHECK["ROLES"], "relay3", "relay4", "relay5")}
    provider_nodes = [node for node in CHECK["CANDIDATES"] if node != control_node][:2]
    control_peer = peers[control_node]
    paths = [dict(route_context_id="a" * 32, path_id=i+1,
                  relay_peer_id=peers[f"relay{i}"], exit_peer_id=peers["exit"])
             for i in range(2)]
    route = dict(transport="mptcp", route_context_id="a" * 32, paths=paths,
                 benchmark_slots=[dict(relay_node=f"relay{i}", relay_peer_id=peers[f"relay{i}"])
                                  for i in range(2)])
    pairs = {f"cp{i}": [CHECK["PUBLIC_IPS"][control_node], CHECK["PUBLIC_IPS"][node]]
             for i, node in enumerate(provider_nodes)}
    cases = {}
    for index, name in enumerate(("complete", "missing")):
        active = provider_nodes[:1] if index else provider_nodes
        privacy = copy.deepcopy(base["phases"][index]["privacy"])
        for role, capture in privacy.items():
            capture.update(content_provider_mode=True, unexpected_provider_application_packets=0,
                           interfaces=["physical"], interface_statistics={"physical": dict(
                               observed_frames=100, packet_socket_packets=100,
                               packet_socket_drops=0, intake_stopped=True)})
            capture["provider_application"] = {
                node: dict(request_packets=20 if role == "exit" and node in active else 0,
                           response_packets=100 if role == "exit" and node in active else 0,
                           response_payload_bytes=1100000 if role == "exit" and node in active else 0)
                for node in CHECK["CANDIDATES"]}
        control = dict(
            capture_role="content-control", content_provider_mode=True, truncated=False,
            observed_frames=200, packet_socket_drops=0, interfaces=["cp0", "cp1"],
            interface_statistics={name: dict(observed_frames=100, packet_socket_packets=100,
                packet_socket_drops=0, intake_stopped=True) for name in pairs},
            content_control_pairs=copy.deepcopy(pairs),
            content_control_packets={name: dict(inbound=50, outbound=50) for name in pairs},
            unexpected_provider_control_packets=0, unexpected_provider_application_packets=0,
            provider_application={node: dict(request_packets=0, response_packets=0,
                response_payload_bytes=0) for node in CHECK["CANDIDATES"]})
        cases[name] = dict(
            fetch=dict(bytes=CHECK["BYTES"], chunks=9, operation="https_content_download",
                local_delivery=True, output_mode="0600", ownership_changed=False,
                origin_authority_persisted=False, sha256=CHECK["SHA"],
                local_output=f"/user/{name}.bin", cache=f"/agent/{name}-cache",
                providers_used=len(active), provider_peer_ids=[peers[node] for node in active],
                control_relay_peer_id=control_peer, origin_authenticated=True,
                peer_bytes=1048699 if index else CHECK["BYTES"],
                origin_body_bytes=1048576 if index else 0, origin_range_requests=4 if index else 0),
            status=dict(serving=False, control_relay_peer_id=control_peer),
            output=dict(bytes=CHECK["BYTES"], sha256=CHECK["SHA"], path=f"/user/{name}.bin",
                agent_cache=f"/agent/{name}-cache", user_uid=1001, agent_uid=1002,
                control_gid=1003, agent_gid=1002, output_mode="0600", directory_mode="0700",
                agent_cache_mode="0700", local_output_initially_absent=True,
                no_clobber_verified=True, no_clobber_rejected_before_network=True,
                agent_mount_positive_control=True, agent_cannot_read_user_output_directory=True,
                client_cache_initially_absent=True, client_mount_cannot_read_origin=True),
            selected_route=copy.deepcopy(route), privacy=privacy, control=control)
    origin = dict(pid=300, connections=[
        dict(kind="metadata", payload_bytes=1024, tls13=True, alpn_http11=True,
             source="47.163.4.1:32100", status=200, range_start=None, range_end=None, range_total=None)
        for _ in range(2)] + [dict(kind="body_range", payload_bytes=CHECK["RANGE_BYTES"],
             tls13=True, alpn_http11=True, source="47.163.4.1:32100", status=206,
             range_start=start, range_end=end, range_total=CHECK["BYTES"])
        for start, end in CHECK["RANGES"]])
    return dict(success=True, publication=publication, native_publication=original,
        layout=dict(provider_nodes=provider_nodes, control_relay_peer_id=control_peer),
        expected_peers=peers, origin=origin, cases=cases,
        user_cleanup=dict(user_outputs_removed=True, explicit_fixture_ca_removed=True, user_directory_removed=True),
        missing_provider_stop=dict(serving=False, publications=0),
        withdrawal=dict(provider_node=provider_nodes[1], provider_peer_id=peers[provider_nodes[1]]))


def changed(evidence, path, value):
    result = copy.deepcopy(evidence)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return result


class ProviderHttpsEvidence(unittest.TestCase):
    def test_https_local_delivery_requires_actual_owner_and_no_clobber_not_native_export(self):
        evidence = fixture()
        for field, wrong in (
            ("user_uid", 1002), ("control_gid", 1002), ("output_mode", "0644"),
            ("agent_cannot_read_user_output_directory", False), ("agent_mount_positive_control", False),
            ("no_clobber_verified", False), ("no_clobber_rejected_before_network", False),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(evidence, ("cases", "complete", "output", field), wrong))
        for field, wrong in (
            ("operation", "content_export"), ("local_delivery", False),
            ("origin_authority_persisted", True), ("ownership_changed", True),
            ("local_output", "/agent/complete-cache"), ("cache", "/user/complete.bin"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(evidence, ("cases", "missing", "fetch", field), wrong))
        with self.assertRaises(ValueError):
            CHECK["validate_evidence"](changed(evidence, ("user_cleanup", "user_outputs_removed"), False))

    def test_user_output_cleanup_is_exact_and_idempotent(self):
        script = str(HERE.joinpath("content-provider-https-smoke.sh").resolve())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "client-fixtures/https-output"
            output.mkdir(parents=True, mode=0o700)
            for name in ("origin.pem", "complete-object.bin", "missing-object.bin"):
                path = output / name
                path.write_bytes(b"known public cleanup fixture")
                path.chmod(0o400 if name == "origin.pem" else 0o600)
            unrelated = root / "unrelated.txt"
            unrelated.write_text("preserve", encoding="ascii")
            environment = dict(os.environ, WORK=str(root), WORKER_UID=str(os.getuid()), WORKER_GID=str(os.getgid()))
            for _ in range(2):
                subprocess.run(["sh", "-eu", "-c", '. "$1"; content_provider_https_cleanup', "sh", script],
                               env=environment, check=True, capture_output=True, timeout=5)
            self.assertFalse(output.exists())
            self.assertEqual(unrelated.read_text(encoding="ascii"), "preserve")
            self.assertEqual(json.loads(root.joinpath("content-provider-https-user-cleanup.json").read_text()),
                             fixture()["user_cleanup"])

    def test_exact_shared_publication_origin_authority_ranges_and_peer_receipts(self):
        for control in CHECK["PUBLIC_IPS"]:
            CHECK["validate_evidence"](fixture(control))
        value = fixture()
        for path, wrong in (
            (("publication", "manifest_id"), "e" * 64),
            (("publication", "publisher_hex"), "e" * 64),
            (("publication", "existing_publication_reused"), False),
            (("native_publication", "publisher_private_key_persisted"), True),
            (("withdrawal", "provider_node"), "relay4"),
            (("missing_provider_stop", "serving"), True),
            (("origin", "connections", 0, "tls13"), False),
            (("origin", "connections", 1, "source"), "43.159.1.1:32100"),
            (("origin", "connections", 1, "source"), "46.162.3.1:32100"),
            (("origin", "connections", 2, "status"), 200),
            (("origin", "connections", 3, "range_start"), 0),
            (("origin", "connections", 4, "range_end"), 1572864),
            (("origin", "connections", 5, "range_total"), CHECK["BYTES"] - 1),
            (("cases", "complete", "fetch", "origin_authenticated"), False),
            (("cases", "complete", "fetch", "origin_body_bytes"), CHECK["BYTES"]),
            (("cases", "complete", "fetch", "provider_peer_ids"), ["peer-relay4", "peer-relay4"]),
            (("cases", "missing", "fetch", "peer_bytes"), CHECK["BYTES"]),
            (("cases", "missing", "fetch", "origin_body_bytes"), 0),
            (("cases", "missing", "fetch", "origin_range_requests"), 3),
            (("cases", "missing", "fetch", "provider_peer_ids"), ["peer-relay5"]),
            (("cases", "missing", "fetch", "control_relay_peer_id"), "peer-relay1"),
            (("cases", "complete", "output", "client_mount_cannot_read_origin"), False),
            (("cases", "missing", "output", "client_cache_initially_absent"), False),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(value, path, wrong))

    def test_physical_privacy_and_control_capture_cleanup_are_not_optional(self):
        value = fixture()
        # Stopping the second provider does not promise further control packets on its link.
        missing = value["cases"]["missing"]["control"]
        missing["content_control_packets"]["cp1"] = dict(inbound=0, outbound=0)
        missing["interface_statistics"]["cp1"].update(observed_frames=0, packet_socket_packets=0)
        missing["observed_frames"] = 100
        CHECK["validate_evidence"](value)
        for path, wrong in (
            (("cases", "complete", "privacy", "client", "direct_client_exit_packets"), 1),
            (("cases", "complete", "privacy", "exit", "client_public_packets"), 1),
            (("cases", "complete", "privacy", "client", "truncated"), True),
            (("cases", "complete", "privacy", "relay0", "exit_leg_wireguard_data_datagrams"), 0),
            (("cases", "complete", "privacy", "client", "interface_statistics", "physical", "intake_stopped"), False),
            (("cases", "complete", "privacy", "client", "interface_statistics", "physical", "packet_socket_drops"), 1),
            (("cases", "complete", "privacy", "client", "interface_statistics", "physical", "packet_socket_packets"), 101),
            (("cases", "complete", "privacy", "exit", "provider_application", "relay5", "response_payload_bytes"), 1),
            (("cases", "missing", "privacy", "exit", "provider_application", "relay5", "request_packets"), 1),
            (("cases", "complete", "control", "content_control_pairs", "cp1"), ["42.158.0.1", "50.166.6.1"]),
            (("cases", "complete", "control", "content_control_packets", "cp1", "inbound"), 0),
            (("cases", "missing", "control", "content_control_packets", "cp0", "outbound"), 0),
            (("cases", "complete", "control", "unexpected_provider_control_packets"), 1),
            (("cases", "complete", "control", "unexpected_provider_application_packets"), 1),
            (("cases", "complete", "control", "interface_statistics", "cp0", "intake_stopped"), False),
            (("cases", "complete", "control", "interface_statistics", "cp0", "packet_socket_packets"), 101),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(value, path, wrong))


if __name__ == "__main__":
    unittest.main()
