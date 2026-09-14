#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Small adversarial checks of the C03 evidence contract, not a network substitute."""

import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
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
                                              ("q", "reserve", CHECK["Q_BYTES"], 3, CHECK["Q_SHA"])):
        publication[field] = dict(label=label, bytes=size, chunks=chunks, seeded_cache_bytes=size,
            seeded_cache_entries=chunks, object_sha256=digest, publisher_hex="b" * 64,
            manifest_id=("d" if label == "p" else "e") * 64,
            publisher_removed=True, publisher_private_key_persisted=False)
        output[field] = dict(bytes=size, sha256=digest)
    publication.update(publisher_removed=True, publisher_private_key_persisted=False, replicator_seeded=False)
    before = dict(serving=True, replication_enabled=True, replica_chunks=0, replica_bytes=0,
                  replica_publications=0, publications=1, control_relay_peer_id=peers[control_node])
    after = dict(before, replica_chunks=3, replica_bytes=CHECK["Q_BYTES"], replica_publications=1, publications=2)
    evidence = dict(success=True, publication=publication, output=output, expected_peers=peers,
        warm_fetch=fetch(CHECK["P_BYTES"], 3, "relay5"),
        foreground_fetch=fetch(CHECK["P_BYTES"], 3, "relay5"),
        final_fetch=fetch(CHECK["Q_BYTES"], 3, "relay4"), before=before, after=after,
        origin_stop=dict(serving=False, publications=0), replica_stop=dict(serving=False, publications=0),
        replica_pause=dict(serving=False, publications=0, replication_enabled=False),
        replica_resume=dict(after),
        origin_offline=dict(unit="volparossa-alpha-agent@relay5.service", active_state="inactive",
                            main_pid=0, listener_absent=True),
        events=dict(replica_chunks_available=1, exit_mptcp_flows_completed=4,
                    replicator_forwarded_discovery=2, consumer_forwarded_discovery=1), phases={})
    evidence["owner_isolation"] = dict(uid=1000, gid=1000, relay4=41, relay0=42, parent=40)
    evidence["owner_cleanup"] = dict(complete=True, remaining_processes=0)
    for label, namespace, process in (("source", 41, 101), ("sink", 42, 102)):
        evidence["owner_" + label] = dict(mode="owner-" + label, complete=True, socket_closed=True,
            socket_priority=0, packets=2000, bytes=2400000,
            identity=dict(uid=1000, gid=1000, pid=process, netns=namespace,
                          cap_eff=0, cap_bnd=0, no_new_privs=True))
    evidence["owner_source"].update(owner_start_ns=1_000_000_000, owner_end_ns=4_000_000_000,
        chunks={"0": dict(at_ns=900_000_000, bytes=262144),
                "1": dict(at_ns=1_300_000_000, bytes=262144),
                "2": dict(at_ns=4_800_000_000, bytes=123)})
    evidence["owner_sink"].update(drained=True, first_packet_ns=1_001_000_000, last_packet_ns=3_990_000_000)
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
                capture["provider_payload_timeline"] = [dict(at_ns=800_000_000, flow=0, bytes=262900),
                    dict(at_ns=1_250_000_000, flow=0, bytes=262900),
                    dict(at_ns=4_500_000_000, flow=0, bytes=700)] if phase == "uptake" else []
            if phase == "uptake" and role == "receiver":
                capture.update(owner_fixture_packets=2000, owner_fixture_payload_bytes=2400000)
            captures[role] = capture
        evidence["phases"][phase] = dict(layout=layout, route=route, captures=captures)
    cache = dict(device=1, inode=42, uid=987, gid=987, mode=0o700,
                 journal_sha256="f" * 64, journal_bytes=1024)
    automatic = dict(config=dict(content_contribution=dict(enabled=True,
        bind_address="49.165.5.1:18080", advertised_hostname="provider-a.volparossa.test",
        cache="/fixture/state-relay4/content/automatic-replicas", quota_bytes=67108864,
        max_entries=256, min_free_bytes=268435456, max_bytes=1048576, max_chunks=4),
        relay_enabled=True, sharing_enabled=True, download_sharing_enabled=True, cache_initially_absent=True),
        before=dict(before, publications=0), after=dict(after, publications=1, replica_bytes=CHECK["P_BYTES"]),
        restored=dict(after, publications=1, replica_bytes=CHECK["P_BYTES"]),
        foreground_fetch=fetch(CHECK["P_BYTES"], 3, "relay5"),
        final_fetch=fetch(CHECK["P_BYTES"], 3, "relay4"),
        origin_stop=dict(serving=False, publications=0), stop=dict(serving=False, publications=0),
        origin_offline=dict(evidence["origin_offline"]), contribution_events=1,
        cache_empty=dict(cache, journal_sha256=None, journal_bytes=0),
        cache_before=dict(cache), cache_after=dict(cache), phases=copy.deepcopy(evidence["phases"]),
        output=dict(foreground=dict(bytes=CHECK["P_BYTES"], sha256=CHECK["P_SHA"]),
                    final=dict(bytes=CHECK["P_BYTES"], sha256=CHECK["P_SHA"]),
                    download_cache_initially_absent=True, consumer_cache_initially_absent=True,
                    replicator_cannot_read_original_cache=True, consumer_cannot_read_either_cache=True,
                    manual_serve_used_on_replicator=False, replicator_restarted_after_original_shutdown=True))
    for name, old, new in (("startup", 100, 101), ("restart", 101, 102)):
        automatic[name] = dict(unit="volparossa-alpha-agent@relay4.service", active_state="active",
                               pid_before=old, pid_after=new, network_namespace_identity="4:500",
                               executable_verified=True)
    for name, context in (("uptake", "c" * 32), ("reserve-fetch", "d" * 32)):
        automatic["phases"][name]["route"]["route_context_id"] = context
        for path in automatic["phases"][name]["route"]["paths"]:
            path["route_context_id"] = context
    evidence["automatic_contribution"] = automatic
    evidence["public_publication"] = publication_fixture(evidence)
    return evidence


def publication_fixture(evidence):
    helper = CHECK["publication_module"]()
    auto = evidence["automatic_contribution"]
    site = helper["SITE"]
    source = {f"{index + 1:064x}": 262144 if index < 8 else helper["BYTES"] - 8 * 262144 for index in range(9)}
    initial = dict(auto["cache_after"], staging_absent=True,
                   chunks={f"{10 + index:064x}": size for index, size in enumerate((262144, 262144, 321))})
    before = dict(initial, chunks=dict(initial["chunks"], **source), journal_sha256="e" * 64, journal_bytes=2048)
    status = dict(serving=True, replication_enabled=True, publications=2,
                  replica_publications=2, replica_chunks=12, replica_bytes=helper["BYTES"] + CHECK["P_BYTES"])
    publish = dict(operation="content_publish", network_publication=True, serving=True, publications=2,
        bytes=helper["BYTES"], chunks=9, manifest_id="6" * 64, publisher_key_hex="7" * 64,
        cache="/user/site-publisher/source-cache", expires_unix_seconds=5000,
        private_keys_transferred=False, ownership_changed=False, origin_authenticated=False)
    phase = copy.deepcopy(auto["phases"]["reserve-fetch"])
    phase["route"]["route_context_id"] = "f" * 32
    for path in phase["route"]["paths"]:
        path["route_context_id"] = "f" * 32
    for role in ("exit", "provider"):
        phase["captures"][role]["provider_response_payload_bytes"] = helper["BYTES"] + 4096
    final = dict(auto["final_fetch"], operation="named_content_download", publisher_key=publish["publisher_key_hex"],
        name=site["NAME"], revision=1, manifest_id=publish["manifest_id"],
        publication_expires_unix_seconds=5000, bytes=helper["BYTES"], peer_bytes=helper["BYTES"], chunks=9,
        sha256=helper["SHA"], cache_only=False, globally_latest=False)
    boundary = dict(user_uid=985, user_gid=985, control_gid=1001, client_namespace=True,
                    outside_parent_namespace=True, all_capabilities_dropped=True, no_new_privileges=True)
    return dict(input=dict(name=site["NAME"], content_type=site["CONTENT_TYPE"], assets=site["inventory"](),
        bytes=helper["BYTES"], sha256=helper["SHA"], manifest_id=publish["manifest_id"],
        source_chunks=source, source_cache=publish["cache"]), publish=publish,
        pack=dict(operation="site_pack", assets=4, bytes=helper["BYTES"], content_type=site["CONTENT_TYPE"], network_published=False),
        cache_initial=initial, cache_before=before, cache_after=copy.deepcopy(before),
        before=copy.deepcopy(auto["restored"]), after=status, restored=copy.deepcopy(status),
        startup=dict(auto["restart"], pid_before=102, pid_after=103),
        restart=dict(auto["restart"], pid_before=103, pid_after=104),
        phase=phase, application=dict(final=final, consumer=boundary, cli=dict(boundary), bytes=helper["BYTES"],
            sha256=helper["SHA"], output_mode="0600", no_manifest_argument=True, browser_engine_executed=False),
        isolation=dict(user_uid=985, user_gid=985, agent_uid=987, agent_gid=987, control_gid=1001,
            fresh_client_cache=True, agent_mount_positive_control=True, client_cannot_read_provider_cache=True,
            agent_cannot_read_user_source=True, user_cannot_read_agent_cache=True,
            publisher_process_exited_before_fetch=True, publisher_node_offline_claimed=False),
        publisher_cleanup=dict(publisher_files_removed=True, source_cache_removed=True, manifest_removed=True),
        cleanup=dict(user_directory_removed=True), stop=dict(serving=False, publications=0))


class ReplicationEvidence(unittest.TestCase):
    def test_explicit_publication_requires_real_complete_admission_restart_and_independent_name_fetch(self):
        value = fixture()
        CHECK["validate_evidence"](value)
        for path, wrong in (
            (("publish", "network_publication"), False), (("publish", "serving"), False),
            (("publish", "manifest_id"), "0" * 64), (("publish", "private_keys_transferred"), True),
            (("cache_before", "chunks", "0000000000000000000000000000000000000000000000000000000000000001"), 1),
            (("cache_after", "journal_sha256"), "a" * 64), (("cache_after", "inode"), 99),
            (("cache_before", "staging_absent"), False), (("restored", "replica_chunks"), 7),
            (("restart", "pid_after"), 103), (("publisher_cleanup", "source_cache_removed"), False),
            (("application", "final", "publication_expires_unix_seconds"), 5001),
            (("application", "final", "peer_bytes"), 0), (("application", "final", "origin_body_bytes"), 1),
            (("application", "final", "provider_peer_ids"), ["peer-relay5"]),
            (("application", "cli", "all_capabilities_dropped"), False),
            (("isolation", "client_cannot_read_provider_cache"), False),
            (("phase", "captures", "provider", "provider_response_payload_bytes"), 0),
            (("cleanup", "user_directory_removed"), False),
        ):
            bad = copy.deepcopy(value)
            cursor = bad["public_publication"]
            for key in path[:-1]: cursor = cursor[key]
            cursor[path[-1]] = wrong
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](bad)
        incomplete = copy.deepcopy(value)
        del incomplete["public_publication"]
        with self.assertRaises(KeyError): CHECK["validate_evidence"](incomplete)
        script = (HERE / "content-replication-smoke.sh").read_text()
        self.assertLess(script.index("    content_replication_automatic_run\n"), script.index("    content_contribution_publish_run\n"))
        subscript = (HERE / "content-contribution-publish-smoke.sh").read_text()
        self.assertIn("content publish --contribute", subscript)
        self.assertNotIn("content import", subscript)
        self.assertNotIn("content serve", subscript)
        # Real initial owner-probe staging has only these two scripts, not the later
        # publication/site helpers. Importing it must not perform publication setup.
        with tempfile.TemporaryDirectory(prefix="volparossa-owner-staging-") as directory:
            staged = Path(directory)
            for name in ("content-replication-smoke.py", "content-replication-capture.py"):
                (staged / name).write_bytes((HERE / name).read_bytes())
            module = runpy.run_path(str(staged / "content-replication-smoke.py"))
            self.assertTrue(callable(module["owner_process"]))

    def test_automatic_restart_is_available_without_the_skipped_a01_block(self):
        # Dependency regression only: reach the fixed systemd restart request and deliberately
        # fail it. No host service is touched and no successful restart evidence is fabricated.
        script = '''set -eu
            . "$1"
            AGENT_UNITS=" volparossa-alpha-agent@relay4.service"
            systemctl() {
                if [ "$*" = 'show --property=MainPID --value volparossa-alpha-agent@relay4.service' ]; then
                    printf '123\\n'
                elif [ "$*" = 'restart volparossa-alpha-agent@relay4.service' ]; then
                    printf 'fixed owned restart reached\\n' >&2
                    return 1
                else return 95; fi
            }
            content_replication_automatic_restart startup
        '''
        result = subprocess.run(["sh", "-c", script, "automatic-restart-contract",
                                 str(HERE / "content-replication-smoke.sh")],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "fixed owned restart reached\n")
        self.assertEqual(result.stdout, "")

    def test_automatic_contribution_requires_empty_start_real_restart_journal_and_independent_p(self):
        CHECK["validate_evidence"](fixture())
        for mutate in (
            lambda value: value["config"].update(download_sharing_enabled=False),
            lambda value: value["config"]["content_contribution"].update(max_chunks=5),
            lambda value: value["before"].update(publications=1),
            lambda value: value["after"].update(replica_bytes=0),
            lambda value: value["restored"].update(replica_publications=0),
            lambda value: value["restart"].update(pid_after=101),
            lambda value: value["cache_after"].update(inode=43),
            lambda value: value["cache_after"].update(journal_sha256="0" * 64),
            lambda value: value["origin_offline"].update(main_pid=500),
            lambda value: value["output"].update(manual_serve_used_on_replicator=True),
            lambda value: value["output"]["final"].update(sha256=CHECK["Q_SHA"]),
            lambda value: value["final_fetch"].update(provider_peer_ids=["peer-relay5"]),
            lambda value: value.update(contribution_events=0),
            lambda value: value["phases"]["reserve-fetch"]["captures"]["provider"].update(forbidden_packets=1),
        ):
            evidence = fixture()
            mutate(evidence["automatic_contribution"])
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](evidence)

    def test_automatic_config_preserves_explicit_roles_and_both_real_sharing_budgets(self):
        original = ("roles:\n  client: true\n  relay: true\n  exit: false\n"
                    "sharing:\n  enabled: true\n  interface: ar0\n"
                    "download_sharing:\n  enabled: true\n  interface: ar2\n")
        with tempfile.TemporaryDirectory(prefix="volparossa-automatic-config-") as directory:
            path = Path(directory) / "config-relay4.yaml"
            path.write_text(original)
            path.chmod(0o600)
            result = CHECK["configure_automatic"](path)
            self.assertTrue(path.read_text().startswith(original))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result["content_contribution"]["max_chunks"], 4)
            with self.assertRaises(ValueError):
                CHECK["configure_automatic"](path)
            for absent in ("client", "relay", "download_sharing"):
                text = original.replace(f"  {absent}: true", f"  {absent}: false") if absent != "download_sharing" else \
                    original.replace("download_sharing:\n  enabled: true", "download_sharing:\n  enabled: false")
                path.write_text(text)
                with self.assertRaises(ValueError):
                    CHECK["configure_automatic"](path)
                self.assertEqual(path.read_text(), text)

    def test_real_owner_evidence_requires_same_flow_pause_resume_not_a_new_job_or_no_load(self):
        CHECK["validate_contention"](fixture())
        for mutate in (
            lambda value: value["owner_sink"].update(bytes=0),
            lambda value: value["owner_source"].update(owner_end_ns=2_000_000_000),
            lambda value: value["owner_source"]["chunks"]["2"].update(at_ns=2_000_000_000),
            lambda value: value["owner_source"]["chunks"]["2"].update(at_ns=20_000_000_000),
            lambda value: value["owner_source"]["identity"].update(cap_eff=1),
            lambda value: value["owner_source"]["identity"].update(netns=40),
            lambda value: value["owner_cleanup"].update(remaining_processes=1),
            lambda value: value["phases"]["uptake"]["captures"]["receiver"].update(owner_fixture_payload_bytes=0),
            lambda value: value["phases"]["uptake"]["captures"]["provider"]["provider_payload_timeline"][2].update(flow=1),
            lambda value: value["phases"]["uptake"]["captures"]["exit"]["provider_payload_timeline"][1].update(bytes=524288),
            lambda value: value["phases"]["uptake"]["captures"]["provider"]["provider_payload_timeline"][1].update(at_ns=3_500_000_000),
        ):
            evidence = fixture()
            mutate(evidence)
            with self.assertRaises(ValueError):
                CHECK["validate_contention"](evidence)

    def test_finalizers_stream_large_evidence_and_preserve_failed_raw_inputs(self):
        # Exercise the real shell finalizers and their real validators with synthetic data.
        # This is an argv/copy regression only, never evidence of an actual network transfer.
        parent = (HERE / "kvm-alpha-topology.sh").read_text()
        helper = parent[parent.index("optional_json_evidence() {"):]
        helper = helper[:helper.index("\n}\n") + 3]
        script = helper + '\n. "$1"\n"$2" 0\n'
        providers = runpy.run_path(str(HERE / "test-content-provider-smoke.py"))
        for scenario, factory in (("replication", fixture), ("provider", providers["fixture"])):
            for mode in ("large", "missing", "serialization-error"):
                with self.subTest(scenario=scenario, mode=mode), tempfile.TemporaryDirectory(
                        prefix="volparossa-report-argv-") as directory:
                    work = Path(directory) / "work"
                    output = Path(directory) / "output"
                    work.mkdir()
                    output.mkdir()
                    evidence = factory()
                    evidence["synthetic_report_padding"] = "x" * (160 * 1024)
                    encoded = json.dumps(evidence)
                    self.assertGreater(len(encoded), 131072)
                    prefix = "content-" + scenario
                    if mode != "missing":
                        (work / f"{prefix}-evidence.json").write_text(encoded)
                    (work / "a15-evidence.json").write_text(json.dumps(dict(
                        unchanged=True, before_sha256="b" * 64, after_sha256="b" * 64)))
                    (work / f"{prefix}-raw.err").write_text("synthetic raw observation\n")
                    env = dict(os.environ, WORK=str(work), output_directory=str(output),
                               source_directory=str(HERE.parent.parent), expected_commit="a" * 40,
                               OUTPUT_UID=str(os.getuid()), OUTPUT_GID=str(os.getgid()),
                               PHASE="synthetic-complete", OBSERVED_BLOCKER="NONE", RUN_ID="synthetic",
                               CLEANUP_COMPLETE=("invalid-json" if mode == "serialization-error" else "true"),
                               REMAINING_OWNED_OBJECTS="0", PYTHONDONTWRITEBYTECODE="1")
                    result = subprocess.run(["sh", "-c", script, "report-test",
                                             str(HERE / f"{prefix}-smoke.sh"),
                                             f"content_{scenario}_finalize_report"],
                                            env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, mode == "large", result.stderr)
                    self.assertEqual((output / f"{prefix}-raw.err").read_text(),
                                     "synthetic raw observation\n")
                    if mode == "serialization-error":
                        self.assertEqual(json.loads((output / f"{prefix}-evidence.json").read_text()),
                                         evidence)
                    else:
                        report = json.loads((output / f"{prefix}-smoke.json").read_text())
                        self.assertEqual(report["success"], mode == "large")
                        self.assertEqual(report["transfer"], evidence if mode == "large" else None)

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
