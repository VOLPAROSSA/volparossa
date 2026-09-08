#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Small adversarial checks of the C03 evidence contract, not a network substitute."""

import copy
from pathlib import Path
import runpy
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "content-replication-smoke.py"))
CAPTURE = CHECK["CAPTURE"]


def fixture(control_node="relay1"):
    peers = {node: "peer-" + node for node in ("client", "relay0", "relay1", "relay2", "relay4", "relay5", "exit")}
    relays = sorted(CHECK["RELAY_NODES"] - {control_node})
    def fetch(size, chunks, provider):
        return dict(bytes=size, peer_bytes=size, chunks=chunks, providers_used=1,
                    provider_peer_ids=[peers[provider]], control_relay_peer_id=peers[control_node],
                    origin_authenticated=False, origin_body_bytes=0, origin_range_requests=0)
    publication, output = {}, {name: True for name in CHECK["ISOLATION"]}
    for label, field, size, chunks, digest in (("p", "foreground", CHECK["P_BYTES"], 3, CHECK["P_SHA"]),
                                              ("q", "reserve", CHECK["Q_BYTES"], 2, CHECK["Q_SHA"])):
        publication[field] = dict(label=label, bytes=size, chunks=chunks, seeded_cache_bytes=size,
            seeded_cache_entries=chunks, object_sha256=digest, publisher_hex="b" * 64,
            manifest_id=("d" if label == "p" else "e") * 64,
            publisher_removed=True, publisher_private_key_persisted=False)
        output[field] = dict(bytes=size, sha256=digest)
    publication.update(publisher_removed=True, publisher_private_key_persisted=False, replicator_seeded=False)
    before = dict(serving=True, replication_enabled=True, replica_chunks=0, replica_bytes=0,
                  replica_publications=0, publications=1, control_relay_peer_id=peers[control_node])
    after = dict(before, replica_chunks=2, replica_bytes=CHECK["Q_BYTES"], replica_publications=1, publications=2)
    evidence = dict(success=True, publication=publication, output=output, expected_peers=peers,
        warm_fetch=fetch(CHECK["P_BYTES"], 3, "relay5"),
        foreground_fetch=fetch(CHECK["P_BYTES"], 3, "relay5"),
        final_fetch=fetch(CHECK["Q_BYTES"], 2, "relay4"), before=before, after=after,
        origin_stop=dict(serving=False, publications=0), replica_stop=dict(serving=False, publications=0),
        replica_pause=dict(serving=False, publications=0, replication_enabled=False),
        replica_resume=dict(after),
        origin_offline=dict(unit="volparossa-alpha-agent@relay5.service", active_state="inactive",
                            main_pid=0, listener_absent=True),
        events=dict(replica_chunks_available=1, exit_mptcp_flows_completed=4,
                    replicator_forwarded_discovery=2, consumer_forwarded_discovery=1), phases={})
    for phase, client, provider, context in (("uptake", "relay4", "relay5", "a" * 32),
                                            ("reserve-fetch", "client", "relay4", "b" * 32)):
        layout = dict(phase=phase, client=dict(node=client, ip=CAPTURE["PUBLIC"][client]),
                      provider=dict(node=provider, ip=CAPTURE["PUBLIC"][provider]),
                      relays={node: CAPTURE["PUBLIC"][node] for node in relays},
                      exit=dict(node="exit", ip=CAPTURE["PUBLIC"]["exit"]))
        route = dict(transport="mptcp", route_context_id=context,
                     paths=[dict(route_context_id=context, relay_peer_id=peers[node], exit_peer_id=peers["exit"])
                            for node in relays],
                     benchmark_slots=[dict(relay_node=node, relay_peer_id=peers[node])
                                      for node in relays])
        captures = {}
        for role in CHECK["ROLES"]:
            node = (client if role == "receiver" else provider if role == "provider" else
                    relays[0] if role == "relay-a" else relays[1] if role == "relay-b" else role)
            capture = dict.fromkeys(CAPTURE["COUNTERS"], 0)
            capture.update(schema_version=1, capture_role=node, node=node, phase=phase, complete=True,
                truncated=False, observed_frames=500, packet_socket_drops=0,
                interfaces=sorted(CHECK["PHYSICAL_INTERFACES"][node]),
                interface_statistics={interface: dict(receive_buffer_bytes=8388608,
                    observed_frames=(500 if interface == "underlay" else 0),
                    packet_socket_packets=(500 if interface == "underlay" else 0), packet_socket_drops=0,
                    intake_stopped=True, drained=True) for interface in CHECK["PHYSICAL_INTERFACES"][node]})
            for relay in relays:
                for leg in ("client_leg", "exit_leg"):
                    capture[f"{relay}_{leg}_wireguard_data_datagrams"] = 50
            if role in ("relay-a", "relay-b"):
                capture.update(client_leg_wireguard_data_datagrams=50, exit_leg_wireguard_data_datagrams=50)
            if role in ("exit", "provider"):
                capture.update(provider_request_packets=50, provider_response_packets=500,
                               provider_response_payload_bytes=CHECK["P_BYTES"] + CHECK["Q_BYTES"])
            captures[role] = capture
        evidence["phases"][phase] = dict(layout=layout, route=route, captures=captures)
    return evidence


class ReplicationEvidence(unittest.TestCase):
    def test_fixture_keeps_control_candidate_separate_from_two_data_relays(self):
        script = '''set -eu
            . "$1"
            R0_PEER=peer-r0; R1_PEER=peer-r1; R2_PEER=peer-r2
            node=$2; client_role=false; relay_role=true; relay_capacity=32
            bootstrap_one=none; bootstrap_two=none; bootstrap_three=none
            content_replication_configure_node
            printf '%s\\n' "$client_role" "$relay_role" "$relay_capacity" \\
                "$bootstrap_one" "$bootstrap_two" "$bootstrap_three"
        '''
        for node in ("client", "relay4", "relay1"):
            result = subprocess.run(["sh", "-c", script, "config-test",
                                     str(HERE / "content-replication-smoke.sh"), node],
                                    check=True, capture_output=True, text=True, timeout=5)
            fields = result.stdout.splitlines()
            self.assertEqual(fields[1:3], ["true", "32"])
            if node in ("client", "relay4"):
                self.assertEqual({peer.rsplit("/", 1)[-1] for peer in fields[3:]},
                                 {"peer-r0", "peer-r1", "peer-r2"})
            if node == "relay4":
                self.assertEqual(fields[0], "true")

    def test_distinct_foreground_then_new_replica_then_independent_consumer(self):
        for control_node in sorted(CHECK["RELAY_NODES"]):
            CHECK["validate_evidence"](fixture(control_node))
        for mutate in (
            lambda value: value["publication"].update(replicator_seeded=True),
            lambda value: value["publication"]["reserve"].update(manifest_id="d" * 64),
            lambda value: value["publication"]["reserve"].update(publisher_private_key_persisted=True),
            lambda value: value["output"].update(reserve_manifest_not_supplied_to_replicator=False),
            lambda value: value["output"].update(consumer_cannot_read_either_cache=False),
            lambda value: value["output"]["reserve"].update(sha256="0" * 64),
            lambda value: value["before"].update(replica_chunks=2),
            lambda value: value["after"].update(replica_publications=0),
            lambda value: value["final_fetch"].update(provider_peer_ids=["peer-relay5"]),
            lambda value: value["final_fetch"].update(control_relay_peer_id="peer-relay4"),
            lambda value: value["final_fetch"].update(control_relay_peer_id="peer-relay0"),
            lambda value: value["foreground_fetch"].update(peer_bytes=0),
            lambda value: value["origin_stop"].update(serving=True),
            lambda value: value["replica_pause"].update(serving=True),
            lambda value: value["replica_pause"].update(replication_enabled=True),
            lambda value: value["replica_resume"].update(replica_publications=0),
            lambda value: value["replica_resume"].update(replica_chunks=0),
            lambda value: value["replica_resume"].update(replica_bytes=0),
            lambda value: value["output"].update(replica_listener_absent_before_reopen=False),
            lambda value: value["output"].update(replica_reopened_after_original_shutdown=False),
            lambda value: value["origin_offline"].update(main_pid=55),
            lambda value: value["events"].update(replica_chunks_available=0),
            lambda value: value["events"].update(exit_mptcp_flows_completed=0),
            lambda value: value["phases"]["uptake"]["route"].update(transport="tcp"),
            lambda value: value["phases"]["reserve-fetch"]["layout"]["provider"].update(node="relay5"),
            lambda value: value["phases"]["uptake"]["captures"]["relay-b"].update(exit_leg_wireguard_data_datagrams=0),
            lambda value: value["phases"]["uptake"]["captures"]["relay-a"].update(node="relay1", capture_role="relay1"),
            lambda value: value["phases"]["reserve-fetch"]["captures"]["receiver"].update(forbidden_packets=1),
            lambda value: value["phases"]["reserve-fetch"]["captures"]["provider"].update(provider_response_payload_bytes=0),
            lambda value: value["phases"]["uptake"]["captures"]["exit"]["interface_statistics"]["underlay"].update(drained=False),
            lambda value: value["phases"]["uptake"]["captures"]["exit"]["interface_statistics"]["underlay"].update(packet_socket_packets=501),
            lambda value: (value["phases"]["uptake"]["captures"]["receiver"]["interfaces"].remove("r4x"),
                           value["phases"]["uptake"]["captures"]["receiver"]["interface_statistics"].pop("r4x")),
        ):
            bad = fixture()
            mutate(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](bad)

    def test_exact_source_complete_cleanup_and_no_broader_claims(self):
        report = dict(report_kind="volparossa-content-replication", source_revision="a" * 40,
                      success=True, runner_exit_status=0, transfer=fixture(),
                      cleanup=dict(complete=True, remaining_owned_objects=0),
                      host_state=dict(unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64),
                      **{flag: False for flag in CHECK["SCOPE"]})
        CHECK["validate_report"](report, "a" * 40)
        for mutate in (
            lambda value: value.update(source_revision="c" * 40),
            lambda value: value.update(full_c03_claimed=True),
            lambda value: value["cleanup"].update(remaining_owned_objects=1),
            lambda value: value["host_state"].update(after_sha256="c" * 64),
        ):
            bad = copy.deepcopy(report)
            mutate(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](bad, "a" * 40)


if __name__ == "__main__":
    unittest.main()
