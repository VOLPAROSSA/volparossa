#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic repair evidence gates only; these fixtures do not establish a live VM result."""

import copy
import hashlib
import json
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "content-repair-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-replication-smoke.py"))
SITE_TEST = runpy.run_path(str(HERE / "test-content-provider-site-smoke.py"))
CAPTURE = CHECK["SHARED"]["CAPTURE"]
CHUNK = CHECK["CHUNK"]
REVISION = "12" * 20


def site_fixture(existing, publisher_pid):
    source = SITE_TEST["fixture"]()
    expected, viewer = source["input"], source["application"]
    peers = existing["expected_peers"]
    key, size = expected["publisher_key"], expected["bundle_bytes"]
    manifest = viewer["ready"]["manifest_id"]
    publish = dict(source["publish"], operation="content_publish", network_publication=True, serving=True,
                   name=expected["name"], content_type=expected["content_type"], revision=1, manifest_id=manifest)
    uptake, view = (copy.deepcopy(existing["phases"][kind]) for kind in ("uptake", "reserve-fetch"))
    for phase in (uptake, view):
        for role in ("exit", "provider"):
            phase["captures"][role]["provider_response_payload_bytes"] = size + 4096
    acquire = dict(existing["foreground_fetch"], operation="named_content_download", bytes=size, chunks=9,
                   peer_bytes=size, name=expected["name"], publisher_key=key, manifest_id=manifest, revision=1,
                   publication_expires_unix_seconds=publish["expires_unix_seconds"],
                   sha256=expected["bundle_sha256"], cache_only=False)
    viewer["agent_cache"] = "/state-client/offline-publisher-site-cache"
    for label in ("ready", "final"):
        viewer[label].update(provider_peer_ids=[peers["relay4"]], providers_used=1,
                             control_relay_peer_id=existing["final_fetch"]["control_relay_peer_id"])
    boundary = dict(publisher_node="relay5", holder_node="relay4", reader_node="client", publisher_pid=publisher_pid,
                    publisher_absent_from_unix_seconds=1788850000, publisher_absent_through_unix_seconds=1788850004,
                    pid_listener_and_unit_absent_before_and_after=True, fresh_client_cache=True,
                    agent_cache=viewer["agent_cache"], user_uid=985, user_gid=985, control_gid=1003)
    return dict(input=expected, publish=publish, source_removed=source["publisher_cleanup"], acquire=acquire,
                holder=dict(serving=True, replication_enabled=True, publications=2, replica_publications=2,
                            replica_chunks=12, replica_bytes=3 * CHUNK + size),
                acquisition_removed=dict(temporary_output_removed=True, temporary_cache_removed=True,
                                         sha256=expected["bundle_sha256"], bytes=size),
                viewer=viewer, boundary=boundary, cleanup=source["cleanup"], uptake=uptake, view=view)


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
        capture.update(repair_mdns_leaves={}, repair_mdns_leave_packets=0)
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
    uptake["layout"]["restart_memberships"] = {node: dict(pid_before=entry["pid_before"],
        network_namespace_identity=entry["network_namespace_identity"], observed_ns=100, stop_started_ns=200,
        stop_completed_ns=300, group="224.0.0.251", robustness=2,
        interfaces={"underlay": dict(source=CAPTURE["PUBLIC"][node], interval_ms=1000)})
        for node, entry in restarted.items()}
    for node, entry in uptake["layout"]["restart_memberships"].items():
        stopped[node]["restart_membership"] = copy.deepcopy(entry)
    return dict(success=True, expected_peers=peers, offline_site=site_fixture(existing, restarted["relay5"]["pid_after"]),
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
    return dict(source_revision=REVISION, report_kind="volparossa-content-repair", schema_version=2, publisher_offline_site_verified=True,
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
            (("uptake", "layout", "restart_memberships", "relay4", "pid_before"), 201),
            (("uptake", "layout", "restart_memberships", "relay4", "observed_ns"), 400),
            (("uptake", "layout", "restart_memberships", "relay5", "interfaces", "underlay", "source"), "49.165.5.1"),
            (("uptake", "captures", "provider", "repair_mdns_leave_packets"), 3),
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

    def test_membership_snapshot_uses_kernel_groups_and_matching_live_interface_index(self):
        helper = runpy.run_path(str(HERE / "content-repair-memberships.py"))
        word = int.from_bytes(socket.inet_aton("224.0.0.251"), sys.byteorder)
        table = (f"Idx Device : Count Querier Group Users Timer Reporter\n3 ar0 : 1 V3\n"
                 f"    {word:08X} 1 0:00000000 0\n4 ar1 : 1 V3\n    {word:08X} 0 0:00000000 0\n")
        self.assertEqual(helper["joined_interfaces"](table), {"ar0": 3})
        with self.assertRaises(ValueError):
            helper["joined_interfaces"](table.replace("4 ar1 : 1 V3", "invalid interface"))
        function = helper["snapshot"]
        link = dict(ifindex=3, ifname="ar0", addr_info=[dict(family="inet", local="10.241.90.1")])
        def kernel_value(path, **_kwargs):
            return {"igmp": table, "igmp_qrv": "2", "igmpv3_unsolicited_report_interval": "1000"}[path.name]

        with mock.patch.dict(function.__globals__, namespace_identity=lambda _pid: "3:81"), \
                mock.patch.object(Path, "read_text", side_effect=kernel_value, autospec=True), \
                mock.patch.object(subprocess, "run") as run:
            def snapshot():
                run.return_value.stdout = json.dumps([link]).encode("ascii")
                return function("relay4", 100, "3:81")["interfaces"]

            self.assertEqual(snapshot(), {"ar0": dict(source="10.241.90.1", interval_ms=1000)})
            link["ifindex"] = 4
            self.assertEqual(snapshot(), {})
            link["ifindex"] = 3
            link["addr_info"][0]["local"] = "10.241.90.2"
            with self.assertRaises(ValueError):
                snapshot()
            with self.assertRaises(ValueError):
                function("relay4", 100, "3:82")

    def test_live_leave_counts_retain_exact_validated_header_link_and_interval(self):
        evidence = fixture()
        layout = evidence["uptake"]["layout"]
        capture = evidence["uptake"]["captures"]["receiver"]
        sample = dict(header=dict(interface="underlay", source="relay4.public",
            destination="igmpv3.multicast", ip_version=4, protocol=2,
            igmp=dict(parse="complete", type=34, bytes=16, checksum_valid=True, ttl=1, router_alert_only=True,
                record_count=1, records=[dict(type=3, auxiliary_words=0, source_count=0, group="mdns.multicast")])),
            first_ns=200, last_ns=300, packets=1)
        capture.update(repair_mdns_leave_packets=1, repair_mdns_leaves={"underlay/relay4.public": sample},
                       mdns_membership_packets=2, control_packets=3)
        CHECK["validate_repair_leaves"](capture, layout, "relay4")
        for key, replacement in (("last_ns", 3_000_000_000), ("first_ns", 199), ("packets", 3),
                                 ("header", dict(sample["header"], interface="ar0"))):
            invalid = copy.deepcopy(capture)
            invalid["repair_mdns_leaves"]["underlay/relay4.public"][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                CHECK["validate_repair_leaves"](invalid, layout, "relay4")

    def test_site_requires_same_manifest_independent_retention_physical_path_and_ordinary_http(self):
        valid = fixture()
        CHECK["validate_evidence"](valid)
        mutations = (
            (("source_removed", "manifest_removed"), False),
            (("publish", "network_publication"), False),
            (("publish", "content_type"), "application/octet-stream"),
            (("boundary", "publisher_pid"), 123),
            (("boundary", "pid_listener_and_unit_absent_before_and_after"), False),
            (("boundary", "fresh_client_cache"), False),
            (("boundary", "publisher_absent_through_unix_seconds"), valid["offline_site"]["publish"]["expires_unix_seconds"]),
            (("acquire", "manifest_id"), "f" * 64),
            (("acquire", "origin_body_bytes"), 12),
            (("acquire", "provider_peer_ids"), ["peer-relay4"]),
            (("holder", "replica_chunks"), 8),
            (("acquisition_removed", "temporary_cache_removed"), False),
            (("uptake", "captures", "provider", "provider_response_payload_bytes"), CHUNK),
            (("view", "captures", "receiver", "direct_provider_packets"), 1),
            (("viewer", "ready", "provider_peer_ids"), ["peer-relay5"]),
            (("viewer", "final", "manifest_id"), "f" * 64),
            (("viewer", "ready", "publication_expires_unix_seconds"), 100),
            (("viewer", "ready", "peer_bytes"), 0),
            (("viewer", "assets", "/main.js", "sha256"), "f" * 64),
            (("viewer", "listener_closed"), False),
        )
        for path, value in mutations:
            invalid = copy.deepcopy(valid["offline_site"])
            target = invalid
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_offline_site"](invalid, valid["expected_peers"], valid["holder_offline"])
        del valid["offline_site"]
        with self.assertRaises(ValueError):
            CHECK["validate_evidence"](valid)

    def test_generated_restore_requires_owner_activation_and_exact_immutable_deployment(self):
        valid = report()
        site = valid["repair"]["offline_site"]
        expected, publish = site["input"], site["publish"]
        candidate_id, digest = publish["manifest_id"], expected["bundle_sha256"]
        expiry = publish["expires_unix_seconds"]
        expected["restored_release"] = dict(revision=3, manifest_id=candidate_id)
        publish.update(operation="content_contribute", revision=3, original_signature_reused=True,
                       origin_authenticated=False, ownership_changed=False, private_keys_transferred=False)
        site["acquire"]["revision"] = 3
        for key in ("ready", "final"):
            site["viewer"][key]["revision"] = 3
        site["viewer"]["release_selection"] = ["--min-revision", "3", "--expected-manifest-id", candidate_id]
        first_id, previous_id = "1" * 64, "2" * 64
        site["owner_restore"] = dict(source=dict(revision=1, manifest_id=first_id, bundle_sha256=digest,
            expires_unix_seconds=expiry), current=dict(revision=2, manifest_id=previous_id, bundle_sha256="a" * 64,
            expires_unix_seconds=expiry), candidate=dict(revision=3, manifest_id=candidate_id, bundle_sha256=digest,
            expires_unix_seconds=expiry), owner_state_removed=True, restored_bytes_verified=True,
            restore=dict(schema_version=1, operation="local_site_restore", base="reviewed_initial_current",
                state="activated", publisher_key=expected["publisher_key"], name=expected["name"],
                source_manifest_id=first_id, source_revision=1, previous_manifest_id=previous_id, previous_revision=2,
                manifest_id=candidate_id, revision=3, bundle_sha256=digest, bundle_bytes=expected["bundle_bytes"],
                expires_unix_seconds=expiry, predecessor_observed_in_this_operation=True,
                network_publication=False, globally_latest=False))
        CHECK["validate_report"](valid, REVISION, "restored")
        for value, variant in ((report(), "restored"), (valid, "studio")):
            with self.assertRaises(ValueError):
                CHECK["validate_report"](value, REVISION, variant)
        for path, replacement in (
            (("owner_restore", "restore", "state"), "already_current"),
            (("owner_restore", "restore", "previous_manifest_id"), first_id),
            (("owner_restore", "current", "bundle_sha256"), digest),
            (("owner_restore", "owner_state_removed"), False),
            (("owner_restore", "candidate", "expires_unix_seconds"), expiry + 1),
            (("publish", "original_signature_reused"), False),
            (("input", "restored_release", "revision"), 1),
            (("acquire", "manifest_id"), first_id),
            (("acquire", "revision"), 1),
            (("viewer", "ready", "revision"), 1),
            (("viewer", "release_selection"), ["--min-revision", "3"])):
            changed = copy.deepcopy(site)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_offline_site"](changed, valid["repair"]["expected_peers"], valid["repair"]["holder_offline"])

    def test_report_entrypoint_binds_revision_host_cleanup_and_truthful_scope(self):
        valid = report()
        CHECK["validate_report"](valid, REVISION)
        for key, replacement in (("source_revision", "34" * 20), ("runner_exit_status", 1),
                ("schema_version", 1), ("publisher_offline_site_verified", False),
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

    def test_holder_removes_only_exact_verified_acquisition_scratch(self):
        payload = b"a" * CHUNK + b"tail"
        expected = dict(BUNDLE_SHA256=hashlib.sha256(payload).hexdigest(), BUNDLE_BYTES=len(payload))
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(CHECK["SITE"], expected):
            state = Path(temporary) / "state-relay4"
            cache, output = state / "site-acquisition-cache", state / "site-acquired.vps"
            state.mkdir(mode=0o700)
            cache.mkdir(mode=0o700)
            write = CHECK["SITE"]["write_new"]
            write(output, payload)
            for value in (payload[:CHUNK], payload[CHUNK:]):
                write(cache / hashlib.sha256(value).hexdigest(), value)
            for name in (".volparossa-index-v1", ".volparossa-owner-v1"):
                write(cache / name, b"fixture metadata")
            unknown = cache / "unrelated"
            write(unknown, b"keep me")
            with self.assertRaises(ValueError):
                CHECK["remove_site_acquisition"](state)
            self.assertTrue(unknown.exists() and output.exists())
            unknown.unlink()
            self.assertEqual(CHECK["remove_site_acquisition"](state),
                             dict(temporary_cache_removed=True, temporary_output_removed=True,
                                  sha256=expected["BUNDLE_SHA256"], bytes=len(payload)))
            self.assertFalse(cache.exists() or output.exists())

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
