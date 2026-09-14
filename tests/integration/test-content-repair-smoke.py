#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic repair evidence gates only; these fixtures do not establish a live VM result."""

import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "content-repair-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-replication-smoke.py"))
CAPTURE = CHECK["SHARED"]["CAPTURE"]
CHUNK = CHECK["CHUNK"]
REVISION = "12" * 20


def fixture():
    existing = BASE["fixture"]()
    peers = existing["expected_peers"]
    uptake = copy.deepcopy(existing["phases"]["uptake"])
    uptake["layout"].update(phase="repair-uptake", relays={node: CAPTURE["PUBLIC"][node]
                                                          for node in sorted(CHECK["RELAYS"])})
    selected = {slot["relay_node"] for slot in uptake["route"]["benchmark_slots"]}
    captures = {}
    for role in CHECK["UPTAKE_ROLES"]:
        node = "relay4" if role == "receiver" else "relay5" if role == "provider" else role
        interfaces = sorted(CHECK["SHARED"]["PHYSICAL_INTERFACES"][node])
        capture = dict.fromkeys(CAPTURE["COUNTERS"], 0)
        capture.update(schema_version=1, capture_role=node, node=node, phase="repair-uptake",
            complete=True, truncated=False, observed_frames=500, packet_socket_drops=0,
            interfaces=interfaces, interface_statistics={name: dict(receive_buffer_bytes=8388608,
                observed_frames=500 if name == "underlay" else 0,
                packet_socket_packets=500 if name == "underlay" else 0,
                packet_socket_drops=0, intake_stopped=True, drained=True) for name in interfaces})
        for relay in CHECK["RELAYS"]:
            capture[f"{relay}_client_leg_wireguard_data_datagrams"] = (
                50 if relay in selected and role in ("receiver", relay) else 0)
            capture[f"{relay}_exit_leg_wireguard_data_datagrams"] = (
                50 if relay in selected and role in ("exit", relay) else 0)
        if role in selected:
            capture.update(client_leg_wireguard_data_datagrams=50, exit_leg_wireguard_data_datagrams=50)
        if role in ("exit", "provider"):
            capture.update(provider_request_packets=50, provider_response_packets=500,
                           provider_response_payload_bytes=2 * CHUNK + 4096)
        captures[role] = capture
    uptake["captures"] = captures
    final = copy.deepcopy(existing["phases"]["reserve-fetch"])
    for role in ("exit", "provider"):
        final["captures"][role]["provider_response_payload_bytes"] = 3 * CHUNK + 4096

    def cache(inode, hashes, journal):
        return dict(device=1, inode=inode, uid=987, gid=987, mode=0o700,
            journal_sha256=journal * 64, journal_bytes=1024, index_sha256="f" * 64,
            chunks=sorted(hashes), bytes=len(hashes) * CHUNK,
            chunk_hashes_verified=True, cache_owner_locked=True)

    stopped, restarted = {}, {}
    for index, node in enumerate(("relay4", "relay5")):
        stopped[node] = dict(unit=f"volparossa-alpha-agent@{node}.service", pid_before=100 + index,
            main_pid=0, active_state="inactive", unit_collected=True, listener_absent=True,
            cache_identity=f"1:{41 + index}")
        restarted[node] = dict(unit=stopped[node]["unit"], pid_before=100 + index, pid_after=200 + index,
            active_state="active", executable_verified=True, original_cache_identity_preserved=True,
            cache_identity=stopped[node]["cache_identity"], network_namespace_identity=f"3:{81 + index}")
    return dict(success=True, expected_peers=peers,
        publication=dict(report_kind="volparossa-public-repair-seed", bytes=3 * CHUNK, chunks=3,
            object_sha256=CHECK["SHA"], holder_chunks=3, receiver_chunks=1, receiver_bytes=CHUNK,
            missing_chunks=2, missing_bytes=2 * CHUNK, publisher_removed=True,
            publisher_private_key_persisted=False, initial_placement_over_network=False,
            publisher_hex="b" * 64, manifest_id="c" * 64, created_unix_seconds=1000,
            expires_unix_seconds=8200),
        before={node: dict(serving=True, replication_enabled=True, publications=0,
            replica_publications=0, replica_chunks=0, replica_bytes=0) for node in ("relay4", "relay5")},
        caches=dict(seeded_holder=cache(42, CHECK["CHUNK_HASHES"], "d"),
                    seeded_receiver=cache(41, CHECK["CHUNK_HASHES"][:1], "d"),
                    repaired_receiver=cache(41, CHECK["CHUNK_HASHES"], "e")),
        receiver_status=dict(serving=True, replication_enabled=True, publications=1,
                             replica_publications=1, replica_chunks=3, replica_bytes=3 * CHUNK),
        uptake=uptake, final=final,
        fetch=dict(operation="named_content_download", publisher_key="b" * 64,
            name="disposable-public-repair", revision=1, manifest_id="c" * 64,
            publication_expires_unix_seconds=8200, bytes=3 * CHUNK, peer_bytes=3 * CHUNK,
            sha256=CHECK["SHA"], chunks=3, providers_used=1, provider_peer_ids=[peers["relay4"]],
            control_relay_peer_id=peers["relay1"], origin_authenticated=False,
            origin_body_bytes=0, origin_range_requests=0, globally_latest=False),
        output=dict(bytes=3 * CHUNK, sha256=CHECK["SHA"], mode="0600"),
        stopped=stopped, restarted=restarted,
        holder_offline=dict(stopped["relay5"], pid_before=restarted["relay5"]["pid_after"]),
        isolation=dict(consumer_uid=987, consumer_gid=987, capabilities_dropped=True,
            client_mount_positive_control=True, receiver_mount_positive_control=True,
            client_cannot_read_holder_cache=True, client_cannot_read_receiver_cache=True,
            receiver_cannot_read_holder_cache=True, publisher_seed_inaccessible=True,
            fresh_consumer_cache=True, fetch_input_is_publisher_and_name_only=True),
        startup=dict(event_baseline_unix_ms=5000, captures_ready_before_restart=True,
            initial_active_contexts=0, foreground_fetch_issued=False, manual_connect_issued=False,
            initial_placement_over_network=False, publisher_source_and_key_removed_by_fixture=True),
        receiver_initially_disconnected=True, events=dict(repair_complete=1, exit_mptcp_completed=2))


def report():
    return dict(source_revision=REVISION, report_kind="volparossa-content-repair", schema_version=1,
        success=True, runner_exit_status=0, phase="content-repair-complete", observed_blocker=None,
        cleanup=dict(complete=True, remaining_owned_objects=0),
        host_state=dict(unchanged=True, before_sha256="f" * 64, after_sha256="f" * 64),
        initial_placement_over_network=False, independent_publisher_node_offline_claimed=False,
        future_availability_guaranteed=False, full_alpha_acceptance_claimed=False, repair=fixture())


class RepairEvidence(unittest.TestCase):
    def test_exact_repair_requires_autonomous_startup_same_cache_and_complete_capture(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        mutations = (
            (("publication", "object_sha256"), "0" * 64),
            (("fetch", "publication_expires_unix_seconds"), 8201),
            (("fetch", "sha256"), "0" * 64),
            (("events", "repair_complete"), 0),
            (("events", "exit_mptcp_completed"), 0),
            (("startup", "manual_connect_issued"), True),
            (("startup", "foreground_fetch_issued"), True),
            (("startup", "initial_active_contexts"), 1),
            (("startup", "captures_ready_before_restart"), False),
            (("restarted", "relay4", "pid_after"), 100),
            (("caches", "repaired_receiver", "inode"), 44),
            (("caches", "repaired_receiver", "journal_sha256"), "d" * 64),
            (("uptake", "captures", "relay1", "client_leg_wireguard_data_datagrams"), 1),
            (("uptake", "captures", "receiver", "relay1_client_leg_wireguard_data_datagrams"), 1),
            (("uptake", "captures", "exit", "relay1_exit_leg_wireguard_data_datagrams"), 1),
            (("uptake", "captures", "provider", "provider_response_payload_bytes"), CHUNK),
            (("uptake", "captures", "relay0", "packet_socket_drops"), 1),
            (("final", "captures", "provider", "provider_response_payload_bytes"), 0),
            (("final", "captures", "receiver", "direct_provider_packets"), 1),
            (("fetch", "provider_peer_ids"), ["peer-relay5"]),
            (("publication", "publisher_removed"), False),
            (("publication", "publisher_private_key_persisted"), True),
            (("holder_offline", "listener_absent"), False),
            (("isolation", "publisher_seed_inaccessible"), False),
        )
        for path, replacement in mutations:
            invalid = copy.deepcopy(valid)
            cursor = invalid
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](invalid)
        for phase, role in (("uptake", "relay1"), ("final", "provider")):
            invalid = copy.deepcopy(valid)
            del invalid[phase]["captures"][role]
            with self.subTest(missing=(phase, role)), self.assertRaises(ValueError):
                CHECK["validate_evidence"](invalid)

    def test_report_entrypoint_binds_revision_host_cleanup_and_truthful_scope(self):
        valid = report()
        CHECK["validate_report"](valid, REVISION)
        for key, replacement in (("source_revision", "34" * 20), ("runner_exit_status", 1),
                ("full_alpha_acceptance_claimed", True), ("initial_placement_over_network", True),
                ("cleanup", dict(complete=False, remaining_owned_objects=1)),
                ("host_state", dict(unchanged=True, before_sha256="f" * 64, after_sha256="e" * 64))):
            invalid = copy.deepcopy(valid)
            invalid[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                CHECK["validate_report"](invalid, REVISION)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(json.dumps(valid), encoding="ascii")
            result = subprocess.run([sys.executable, "-B", str(HERE / "content-repair-smoke.py"),
                                     "report", str(path), REVISION], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["success"])

    def test_local_cache_and_output_snapshots_require_actual_private_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "state-relay4" / "repair-cache"
            cache.mkdir(mode=0o700, parents=True)
            # These metadata bytes test the Python snapshot's ownership/shape gate only;
            # actual journal cryptography and decoding belong to the production Rust proof.
            files = {".volparossa-owner-v1": bytes(60), ".volparossa-index-v1": b"fixture index",
                     ".volparossa-replicas-v1": b"fixture journal",
                     CHECK["CHUNK_HASHES"][0]: bytes([17]) * CHUNK}
            for name, value in files.items():
                path = cache / name
                path.write_bytes(value)
                path.chmod(0o600)
            snapshot = CHECK["cache_snapshot"](cache)
            self.assertEqual(snapshot["bytes"], CHUNK)
            self.assertEqual(snapshot["chunks"], [CHECK["CHUNK_HASHES"][0]])
            chunk = cache / CHECK["CHUNK_HASHES"][0]
            chunk.write_bytes(bytes([18]) * CHUNK)
            with self.assertRaises(ValueError):
                CHECK["cache_snapshot"](cache)
            output = root / "state-client" / "content" / "repair-output.bin"
            output.parent.mkdir(parents=True)
            output.write_bytes(CHECK["PAYLOAD"])
            output.chmod(0o600)
            self.assertEqual(CHECK["output_snapshot"](output)["sha256"], CHECK["SHA"])
            output.chmod(0o644)
            with self.assertRaises(ValueError):
                CHECK["output_snapshot"](output)
            output.unlink()
            output.symlink_to(chunk)
            with self.assertRaises(OSError):
                CHECK["output_snapshot"](output)


if __name__ == "__main__":
    unittest.main()
