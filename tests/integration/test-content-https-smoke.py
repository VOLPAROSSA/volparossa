#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic gate negatives only; never substitutes for a live HTTPS network run."""

import copy
from pathlib import Path
import runpy
import unittest

CHECK = runpy.run_path(str(Path(__file__).with_name("content-https-smoke.py")))
BASE = runpy.run_path(str(Path(__file__).with_name("test-content-network-smoke.py")))


def fixture():
    value = BASE["fixture"]()
    publication = value["publication"]
    publication.update(object_sha256=CHECK["SHA"], metadata_bytes=1024)
    value.pop("reconstructed_object")
    value["origin"] = dict(pid=300, connections=[
        dict(kind=kind, payload_bytes=size, tls13=True, alpn_http11=True, source="47.163.4.1:12345")
        for kind, size in [("metadata", 1024), ("metadata", 1024), ("body", CHECK["BYTES"])]] )
    route = copy.deepcopy(value["phases"][0]["selected_route"])
    for index, phase in enumerate(value["phases"]):
        phase.pop("provider")
        phase["selected_route"] = copy.deepcopy(route)
        phase["consumer"] = dict(pid=200 + index, variant=("complete", "missing")[index],
            bytes=CHECK["BYTES"], object_sha256=CHECK["SHA"], peer_chunks=(9, 5)[index],
            peer_bytes=(CHECK["BYTES"], 1048699)[index], origin_body_bytes=(0, CHECK["BYTES"])[index],
            fallback_used=bool(index), origin_authenticated_before_peers=True,
            tls_interception_ca_installed=False, origin_authority_persisted=False,
            browser_integration_claimed=False)
        phase["peers"] = dict(pid=100 + index, sessions=[
            dict(replica="replica-" + replica, chunks=chunks, bytes=size, missing=missing,
                 source="47.163.4.1:23456") for replica, chunks, size, missing in
            [("a", 5, 1048699, 4), ("b", 4, 1048576, 0)][:2-index]])
        phase["protected_gates"] = dict(peer_pid=100 + index, event_baseline_unix_ms=1000,
            ingress_completed=3, exit_mptcp_tls_open_completed=3, object_sha256=CHECK["SHA"],
            bytes=CHECK["BYTES"], client_cache_initially_absent=True,
            client_cannot_read_origin_or_replica_files=True)
        for capture in phase["privacy"].values():
            capture["interfaces"] = ["fixture0"]
            capture["interface_statistics"] = dict(fixture0=dict(intake_stopped=True,
                packet_socket_drops=0, packet_socket_packets=100, observed_frames=100))
    return value


class HttpsEvidence(unittest.TestCase):
    def test_complete_and_fallback_then_reject_false_proof(self):
        CHECK["validate_transfer"](fixture())
        changes = [
            (("origin", "connections", 0, "tls13"), False),
            (("origin", "connections", 1, "source"), "46.162.0.1:12345"),
            (("origin", "connections", 2, "payload_bytes"), 0),
            (("phases", 0, "consumer", "origin_authenticated_before_peers"), False),
            (("phases", 0, "consumer", "origin_body_bytes"), CHECK["BYTES"]),
            (("phases", 1, "consumer", "origin_body_bytes"), 0),
            (("phases", 1, "consumer", "fallback_used"), False),
            (("phases", 0, "consumer", "tls_interception_ca_installed"), True),
            (("phases", 0, "consumer", "origin_authority_persisted"), True),
            (("phases", 1, "protected_gates", "client_cache_initially_absent"), False),
            (("phases", 0, "protected_gates", "client_cannot_read_origin_or_replica_files"), False),
            (("phases", 0, "protected_gates", "ingress_completed"), 2),
            (("phases", 0, "protected_gates", "exit_mptcp_tls_open_completed"), 2),
            (("phases", 0, "protected_gates", "object_sha256"), "0" * 64),
            (("phases", 0, "peers", "sessions", 1, "bytes"), 0),
            (("phases", 0, "privacy", "client", "direct_client_exit_packets"), 1),
            (("phases", 0, "privacy", "relay0", "internet_destination_outer_packets"), 1),
            (("phases", 0, "privacy", "relay0", "exit_leg_wireguard_data_datagrams"), 0),
            (("phases", 0, "privacy", "exit", "client_public_packets"), 1),
            (("phases", 0, "privacy", "client", "interface_statistics", "fixture0", "packet_socket_drops"), 1),
            (("phases", 0, "privacy", "client", "interface_statistics", "fixture0", "intake_stopped"), False),
        ]
        for path, wrong in changes:
            with self.subTest(path=path):
                altered = fixture()
                target = altered
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = wrong
                with self.assertRaises(ValueError):
                    CHECK["validate_transfer"](altered)

    def test_report_is_exact_build_and_scoped(self):
        report = dict(report_kind="volparossa-https-content-network", source_revision="a" * 40,
            success=True, runner_exit_status=0, transfer=fixture(),
            cleanup=dict(complete=True, remaining_owned_objects=0),
            host_state=dict(unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64),
            **dict.fromkeys(CHECK["SCOPE"], False))
        CHECK["validate_report"](report, "a" * 40)
        with self.assertRaises(ValueError):
            CHECK["validate_report"](report, "c" * 40)
        for flag in CHECK["SCOPE"]:
            altered = copy.deepcopy(report)
            altered[flag] = True
            with self.assertRaises(ValueError):
                CHECK["validate_report"](altered, "a" * 40)


if __name__ == "__main__":
    unittest.main()
