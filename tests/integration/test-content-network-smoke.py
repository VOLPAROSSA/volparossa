#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure evidence-checker tests; these synthetic records do not prove a network transfer."""

import copy
from pathlib import Path
import runpy
import unittest

CHECK = runpy.run_path(str(Path(__file__).with_name("content-network-smoke.py")))


def fixture():
    publication = dict(publisher_removed=True, publisher_private_key_persisted=False,
                       publisher_hex="1" * 64, object_sha256="2" * 64,
                       bytes=2097275, chunks=9, replica_a_chunks=5, replica_b_chunks=4)
    phases = []
    for index, replica in enumerate("ab"):
        pid = 100 + index
        count, size = ((5, 1048699), (4, 1048576))[index]
        paths = [dict(route_context_id=str(index + 1) * 32, path_id=slot + 1,
                      relay_peer_id=f"peer{slot}", exit_peer_id="exit-peer") for slot in range(2)]
        slots = [dict(relay_peer_id=f"peer{slot}", relay_node=f"relay{slot}") for slot in range(2)]
        privacy = {role: dict(capture_role=role, truncated=False, packet_socket_drops=0,
                             observed_frames=100, expected_link_down_notifications=0,
                             unexpected_outer_packets=0, direct_client_exit_packets=0,
                             internet_destination_outer_packets=0, client_public_packets=0,
                             outbound_client_discovery_attempt_packets=0,
                             client_leg_wireguard_data_datagrams=100,
                             exit_leg_wireguard_data_datagrams=100)
                   for role in CHECK["ROLES"]}
        captures = {role: dict(capture_role=role, truncated=False, observed_frames=100,
                              benchmark_relay_nodes=["relay0", "relay1"],
                              relay1_wireguard_data_datagrams=100, relay2_wireguard_data_datagrams=100,
                              direct_client_exit_packets=0, destination_request_segments=50,
                              destination_response_segments=100) for role in ("client", "exit")}
        phases.append({
            "provider": dict(replica=replica, pid=pid, listen=CHECK["DESTINATION"],
                             source=dict(ip="47.163.4.1", port=32100 + index),
                             chunks_sent=count, bytes_sent=size, missing=(4, 0)[index]),
            "consumer": dict(pid=200 + index, chunks_received=count, bytes_received=size,
                             missing=(4, 0)[index], cached_chunks=(5, 9)[index], complete=bool(index),
                             output_bytes=(0, 2097275)[index],
                             object_sha256=(None, publication["object_sha256"])[index]),
            "selected_route": dict(transport="mptcp", route_context_id=str(index + 1) * 32,
                                   paths=paths, benchmark_slots=slots),
            "protected_gates": dict(serving_pid=pid, publisher_process_exited_before_fetch=True,
                                    event_baseline_unix_ms=1000, ingress_completed=True,
                                    exit_mptcp_tls_open_completed=True),
            "privacy": privacy,
            "application_captures": captures,
        })
    return dict(
        success=True, publication=publication, phases=phases,
        reconstructed_object=dict(bytes=2097275, sha256=publication["object_sha256"],
                                  client_cache_initially_absent=True,
                                  client_cannot_read_replica_stores=True,
                                  publisher_process_exited_before_fetch=True))


class EvidenceContract(unittest.TestCase):
    def test_scoped_good_report(self):
        report = dict(report_kind="volparossa-native-content-network", source_revision="a" * 40,
                      success=True, runner_exit_status=0, transfer=fixture(),
                      cleanup=dict(complete=True, remaining_owned_objects=0),
                      host_state=dict(unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64),
                      full_alpha_acceptance_claimed=False, distinct_provider_nodes_claimed=False,
                      provider_discovery_claimed=False, https_authentication_claimed=False)
        CHECK["validate_report"](report, "a" * 40)
        for mutation in (
            lambda value: value.update(source_revision="c" * 40),
            lambda value: value.update(https_authentication_claimed=True),
            lambda value: value.update(distinct_provider_nodes_claimed=True),
            lambda value: value["cleanup"].update(remaining_owned_objects=1),
            lambda value: value["host_state"].update(after_sha256="c" * 64),
        ):
            wrong = copy.deepcopy(report)
            mutation(wrong)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](wrong, "a" * 40)

    def test_substituted_or_incomplete_proofs_fail(self):
        for label, mutation in (
            ("publisher online", lambda value: value["publication"].update(publisher_removed=False)),
            ("local shortcut", lambda value: value["reconstructed_object"].update(client_cannot_read_replica_stores=False)),
            ("wrong object", lambda value: value["reconstructed_object"].update(sha256="f" * 64)),
            ("missing replica", lambda value: value["phases"].pop()),
            ("first already complete", lambda value: value["phases"][0]["consumer"].update(complete=True)),
            ("second downloaded all", lambda value: value["phases"][1]["consumer"].update(chunks_received=9)),
            ("direct source", lambda value: value["phases"][0]["provider"]["source"].update(ip="43.159.1.1")),
            ("wrong destination", lambda value: value["phases"][0]["provider"].update(listen=dict(ip="47.163.4.2", port=80))),
            ("substituted provider process", lambda value: value["phases"][0]["provider"].update(pid=999)),
            ("ordinary TCP", lambda value: value["phases"][0]["selected_route"].update(transport="tcp")),
            ("no TLS proof", lambda value: value["phases"][0]["protected_gates"].update(exit_mptcp_tls_open_completed=False)),
            ("missing leg", lambda value: value["phases"][1]["privacy"]["relay0"].update(exit_leg_wireguard_data_datagrams=0)),
            ("capture loss", lambda value: value["phases"][1]["privacy"]["relay1"].update(packet_socket_drops=1)),
            ("capture truncated", lambda value: value["phases"][1]["privacy"]["client"].update(truncated=True)),
            ("direct Client Exit", lambda value: value["phases"][1]["privacy"]["client"].update(direct_client_exit_packets=1)),
            ("Relay destination leak", lambda value: value["phases"][1]["privacy"]["relay0"].update(internet_destination_outer_packets=1)),
            ("Exit sees Client", lambda value: value["phases"][1]["privacy"]["exit"].update(client_public_packets=1)),
            ("missing destination bytes", lambda value: value["phases"][1]["application_captures"]["exit"].update(destination_response_segments=0)),
        ):
            with self.subTest(label=label):
                wrong = fixture()
                mutation(wrong)
                with self.assertRaises(ValueError):
                    CHECK["validate_transfer"](wrong)


if __name__ == "__main__":
    unittest.main()
