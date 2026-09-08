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
from unittest import mock

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
                agent_cache=f"/agent/{name}-cache", user_uid=985, agent_uid=1002,
                control_gid=1003, agent_gid=1002, output_mode="0600", directory_mode="0700",
                agent_cache_mode="0700", local_output_initially_absent=True,
                no_clobber_verified=True, no_clobber_rejected_before_network=True,
                agent_mount_positive_control=True, agent_cannot_read_user_output_directory=True,
                client_cache_initially_absent=True, client_mount_cannot_read_origin=True),
            selected_route=copy.deepcopy(route), privacy=privacy, control=control)
        fetch = cases[name]["fetch"]
        boundary = dict(user_uid=985, user_gid=985, control_gid=1003,
                        client_namespace=True, outside_parent_namespace=True,
                        all_capabilities_dropped=True, no_new_privileges=True)
        application = dict(consumer=copy.deepcopy(boundary), cli=copy.deepcopy(boundary),
                           elapsed_ns=3_000_000_000, requested_source_strategy="peers-first")
        if not index:
            for key in ("local_delivery", "output_mode", "ownership_changed", "local_output", "cache"):
                del fetch[key]
            fetch.update(operation="browser_content_download", private_spool_removed=True,
                         authentication_scope="cooperative-origin", https_origin_privileges=False,
                         single_use=True)
            ready = {key: value for key, value in fetch.items() if key != "private_spool_removed"}
            ready.update(operation="browser_download_ready", expires_unix_seconds=1788848552)
            application.update(ready=ready, ready_elapsed_ns=2_000_000_000,
                browser_engine_executed=False, private_spool=dict(directory_mode="0700",
                    file_mode="0600", observed_complete=True, removed=True),
                http=dict(status=200, bytes=CHECK["BYTES"], sha256=CHECK["SHA"], attachment=True,
                    octet_stream=True, no_store=True, nosniff=True, loopback_only=True,
                    single_use_listener_closed=True, completed_before_expiry=True, elapsed_ns=100_000_000))
        application["final"] = copy.deepcopy(fetch)
        cases[name]["application"] = application
    origin = dict(pid=300, request_limit=28, stop_requested=True,
        listener_closed=True, inflight_drained=True, connections=[
        dict(kind="metadata", payload_bytes=1024, tls13=True, alpn_http11=True,
             source="47.163.4.1:32100", status=200, range_start=None, range_end=None, range_total=None)
        for _ in range(2)] + [dict(kind="body_range", payload_bytes=CHECK["RANGE_BYTES"],
             tls13=True, alpn_http11=True, source="47.163.4.1:32100", status=206,
             range_start=start, range_end=end, range_total=CHECK["BYTES"])
        for start, end in CHECK["RANGES"]])
    origin["connections"].extend([
        dict(kind=kind, payload_bytes=length, tls13=True, alpn_http11=True,
             source="47.163.4.1:32100", status=200, range_start=None, range_end=None, range_total=None)
        for kind, length in (("metadata", 1024), ("body", CHECK["BYTES"]))])
    baseline_privacy = copy.deepcopy(cases["complete"]["privacy"])
    for capture in baseline_privacy.values():
        for counters in capture["provider_application"].values():
            counters.update(request_packets=0, response_packets=0, response_payload_bytes=0)
    baseline = dict(privacy=baseline_privacy, selected_route=copy.deepcopy(route),
        ingress=dict(client_before=2, client_after=4, exit_before=10, exit_after=12),
        application=dict(consumer=copy.deepcopy(boundary), cli=copy.deepcopy(boundary),
            elapsed_ns=2_600_000_000, reported_client_namespace=True,
            final=dict(report_kind="volparossa-https-origin-baseline", pid=400,
                effective_uid=985, network_namespace="net:[12345]", bytes=CHECK["BYTES"],
                chunks=9, object_sha256=CHECK["SHA"], origin_body_bytes=CHECK["BYTES"],
                peer_bytes=0, metadata_requests=1, body_requests=1,
                metadata_elapsed_ns=400_000_000, body_elapsed_ns=2_000_000_000,
                reconstruct_elapsed_ns=20_000_000, total_elapsed_ns=2_420_000_000,
                origin_authenticated=True, origin_authority_persisted=False,
                reference_cache_initially_empty=True, private_spool_removed=True, output_mode="0600",
                application_socket="ordinary_tcp_transparent_ingress")))
    strategies = {}
    for mode, elapsed in (("origin-only", 2_000_000_000), ("auto", 3_000_000_000)):
        phase = copy.deepcopy(cases["missing"])
        phase["privacy"] = copy.deepcopy(baseline_privacy)
        phase["fetch"].update(peer_bytes=0, origin_body_bytes=CHECK["BYTES"],
            origin_range_requests=1, providers_used=0, provider_peer_ids=[],
            local_output=f"/user/{mode}.bin", cache=f"/agent/{mode}-cache")
        phase["output"].update(path=f"/user/{mode}.bin", agent_cache=f"/agent/{mode}-cache")
        phase["application"].update(final=copy.deepcopy(phase["fetch"]),
            requested_source_strategy=mode, elapsed_ns=elapsed)
        # Origin-only need not contact a cache peer; an empty fully drained control
        # socket is still coverage, never invented useful traffic.
        phase["control"]["observed_frames"] = 0
        for counters in phase["control"]["content_control_packets"].values():
            counters.update(inbound=0, outbound=0)
        for statistics in phase["control"]["interface_statistics"].values():
            statistics.update(observed_frames=0, packet_socket_packets=0)
        strategies[mode] = phase
        origin["connections"].extend([
            copy.deepcopy(origin["connections"][0]),
            dict(kind="body_range", payload_bytes=CHECK["BYTES"], tls13=True,
                alpn_http11=True, source="47.163.4.1:32100", status=206,
                range_start=0, range_end=CHECK["BYTES"] - 1, range_total=CHECK["BYTES"])])
    return dict(success=True, publication=publication, native_publication=original,
        layout=dict(provider_nodes=provider_nodes, control_relay_peer_id=control_peer),
        expected_peers=peers, origin=origin, cases=cases,
        origin_baseline=baseline, comparison=CHECK["measured_comparison"](cases, baseline),
        source_strategy_cases=strategies, source_strategy_comparison=CHECK["strategy_comparison"](strategies),
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
    def test_peer_phases_pin_source_strategy_and_do_not_relabel_origin_reference(self):
        value = fixture()
        for name in ("complete", "missing", "baseline", "origin-only", "auto"):
            with self.subTest(case=name):
                command = CHECK["consumer_command"](name, "/fixture/binary", "/agent/socket",
                    "/agent/cache", Path("/user"), Path("/user/output"))
                if name == "baseline":
                    self.assertEqual(command[1], "origin-baseline")
                    self.assertNotIn("--source-strategy", command)
                else:
                    self.assertEqual(command.count("--source-strategy"), 1)
                    self.assertEqual(command[command.index("--source-strategy") + 1],
                                     name if name in ("origin-only", "auto") else "peers-first")
                if name in ("complete", "missing"):
                    for mode in ("auto", "origin-only", "unverified"):
                        with self.assertRaises(ValueError):
                            CHECK["validate_evidence"](changed(value,
                                ("cases", name, "application", "requested_source_strategy"), mode))
        relabelled = copy.deepcopy(value)
        relabelled["origin_baseline"]["application"]["requested_source_strategy"] = "origin-only"
        with self.assertRaises(ValueError):
            CHECK["validate_evidence"](relabelled)

    def test_cold_product_comparison_accepts_either_auto_source_without_forcing_gain(self):
        value = fixture()
        self.assertLess(value["source_strategy_comparison"]["origin_to_auto_command_ratio"], 1)
        CHECK["validate_evidence"](value)
        for path, wrong in (
            (("origin", "stop_requested"), False), (("origin", "inflight_drained"), False),
            (("origin", "listener_closed"), False), (("origin", "request_limit"), 100),
            (("source_strategy_cases", "auto", "application", "requested_source_strategy"), "peers-first"),
            (("source_strategy_cases", "auto", "fetch", "peer_bytes"), 262144),
            (("source_strategy_cases", "auto", "output", "client_cache_initially_absent"), False),
            (("source_strategy_cases", "auto", "output", "path"), "/user/origin-only.bin"),
            (("source_strategy_cases", "origin-only", "privacy", "exit", "provider_application",
              "relay4", "response_payload_bytes"), 1),
            (("source_strategy_comparison", "origin_to_auto_command_ratio"), 2),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(value, path, wrong))
        extra = copy.deepcopy(value)
        extra["origin"]["connections"].append(copy.deepcopy(extra["origin"]["connections"][-1]))
        with self.assertRaises(ValueError):
            CHECK["validate_evidence"](extra)
        # Auto may instead use the remaining real 5-chunk provider and exact four
        # missing origin ranges. Preserve its own cold destination and requested mode.
        alternate = copy.deepcopy(value)
        phase = alternate["source_strategy_cases"]["auto"]
        missing = alternate["cases"]["missing"]
        for key in ("peer_bytes", "origin_body_bytes", "origin_range_requests",
                    "providers_used", "provider_peer_ids"):
            phase["fetch"][key] = copy.deepcopy(missing["fetch"][key])
        phase["application"]["final"] = copy.deepcopy(phase["fetch"])
        phase["privacy"] = copy.deepcopy(missing["privacy"])
        phase["privacy"]["exit"]["provider_application"]["relay4"]["response_payload_bytes"] = 1050000
        alternate["origin"]["connections"][11:] = copy.deepcopy(alternate["origin"]["connections"][2:6])
        alternate["source_strategy_comparison"] = CHECK["strategy_comparison"](alternate["source_strategy_cases"])
        CHECK["validate_evidence"](alternate)
        duplicate = copy.deepcopy(alternate)
        duplicate["origin"]["connections"][12] = copy.deepcopy(duplicate["origin"]["connections"][11])
        with self.assertRaises(ValueError):
            CHECK["validate_evidence"](duplicate)

    def test_origin_reference_requires_fresh_protected_flow_full_body_and_honest_timing(self):
        value = fixture()
        # A slower end-to-end browser result must still pass: no fabricated benefit gate.
        self.assertLess(value["comparison"]["origin_to_browser_command_ratio"], 1)
        # Late ACK/FIN on an old provider socket is not reference-body traffic.
        value["origin_baseline"]["privacy"]["exit"]["provider_application"]["relay4"].update(
            request_packets=1, response_packets=1)
        CHECK["validate_evidence"](value)
        for path, wrong in (
            (("application", "consumer", "client_namespace"), False),
            (("application", "reported_client_namespace"), False),
            (("application", "final", "effective_uid"), 0),
            (("application", "final", "origin_authenticated"), False),
            (("application", "final", "origin_body_bytes"), 0),
            (("application", "final", "peer_bytes"), CHECK["BYTES"]),
            (("application", "final", "reference_cache_initially_empty"), False),
            (("application", "final", "private_spool_removed"), False),
            (("application", "final", "metadata_elapsed_ns"), 0),
            (("application", "final", "total_elapsed_ns"), 1),
            (("application", "final", "application_socket"), "direct_exit"),
            (("ingress", "client_after"), 3), (("ingress", "exit_after"), 11),
            (("selected_route", "route_context_id"), "b" * 32),
            (("privacy", "exit", "provider_application", "relay4", "response_payload_bytes"), 1),
            (("privacy", "exit", "provider_application", "relay4", "request_payload_bytes"), 1),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(value, ("origin_baseline", *path), wrong))
        for path, wrong in (
            (("comparison", "origin_to_browser_command_ratio"), 9),
            (("origin", "connections", 6, "kind"), "body_range"),
            (("origin", "connections", 7, "payload_bytes"), 0),
            (("origin", "connections", 7, "source"), "43.159.1.1:32100"),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(value, path, wrong))

    def test_browser_delivery_requires_actual_client_get_receipt_deadline_and_private_spool(self):
        value = fixture()
        CHECK["validate_evidence"](value)
        for path, wrong in (
            (("cli", "user_uid"), 0), (("consumer", "client_namespace"), False),
            (("cli", "all_capabilities_dropped"), False),
            (("consumer", "outside_parent_namespace"), False),
            (("consumer", "no_new_privileges"), False),
            (("http", "bytes"), 0), (("http", "sha256"), "0" * 64),
            (("http", "loopback_only"), False), (("http", "single_use_listener_closed"), False),
            (("http", "completed_before_expiry"), False), (("http", "attachment"), False),
            (("private_spool", "file_mode"), "0644"), (("private_spool", "removed"), False),
            (("browser_engine_executed",), True), (("elapsed_ns",), 0),
            (("ready_elapsed_ns",), 3_000_000_000), (("http", "elapsed_ns"), 3_000_000_000),
            (("ready", "peer_bytes"), 0), (("ready", "https_origin_privileges"), True),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK["validate_evidence"](changed(value, ("cases", "complete", "application", *path), wrong))
        relabelled = copy.deepcopy(value)
        relabelled["cases"]["complete"]["fetch"]["operation"] = "https_content_download"
        relabelled["cases"]["complete"]["application"]["final"]["operation"] = "https_content_download"
        with self.assertRaises(ValueError):
            CHECK["validate_evidence"](relabelled)

    def test_browser_driver_rejects_nonlocal_or_expired_url_before_any_socket(self):
        with mock.patch("http.client.HTTPConnection", side_effect=AssertionError("socket attempted")):
            for url, expiry in (
                ("http://example.com/" + "a" * 64, 9999999999),
                ("http://127.0.0.1:1234/" + "a" * 64, 1),
                ("http://127.0.0.1:1234/" + "a" * 64 + "?url=anything", 9999999999),
            ):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    CHECK["browser_http_get"](dict(download_url=url, expires_unix_seconds=expiry),
                                              Path("/unused-test-output"), 0)

    def test_baseline_capture_prefix_is_registered_only_for_provider_scenario(self):
        source = HERE.joinpath("kvm-alpha-topology.sh").read_text(encoding="utf-8")
        # Execute only the existing prefix guard, never any observer or namespace operation.
        registration = source.split("start_privacy_observers() {\n", 1)[1].split("    set --\n", 1)[0]
        script = "registered() {\n" + registration + '}\nscenario=$1\nregistered "$2"\n'
        for scenario in ("content-provider", "content-https", "content-message", "dns-cache"):
            for suffix in ("complete", "missing", "baseline", "origin-only", "auto", "unregistered"):
                with self.subTest(scenario=scenario, suffix=suffix):
                    prefix = f"content-provider-https-{suffix}-privacy"
                    result = subprocess.run(["sh", "-eu", "-c", script, "sh", scenario, prefix],
                                            capture_output=True, timeout=2, check=False)
                    self.assertEqual(result.returncode == 0,
                                     scenario == "content-provider" and suffix != "unregistered")

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
            for name in ("origin.pem", "complete-object.bin", "missing-object.bin", "origin-baseline.json",
                         "origin-only-object.bin", "auto-object.bin"):
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
