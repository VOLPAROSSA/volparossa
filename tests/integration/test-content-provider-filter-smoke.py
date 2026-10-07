#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert acceptance/cleanup/wiring tests; no claim of actual protected peer execution."""

import copy
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-provider-filter-smoke.py"))
SITE = runpy.run_path(str(HERE / "test-content-provider-site-smoke.py"))


def fixture(control_node="relay2"):
    site = SITE["fixture"](control_node)
    expected = dict(name=CHECK["NAME"], content_type="text/plain", bytes=len(CHECK["TEXT"]),
                    sha256=CHECK["SHA"], rules=2, publisher_key="6" * 64, manifest_id="5" * 64)
    expiry = site["publish"]["expires_unix_seconds"]
    report = dict(version=1, operation="content_filter_snapshot", visibility="public",
        grammar="ubo-domain-block-v1", rules=2, bytes=expected["bytes"], sha256=expected["sha256"],
        publisher_key=expected["publisher_key"], name=CHECK["NAME"], manifest_id=expected["manifest_id"],
        revision=1, verified_at_unix_seconds=1788850000, expires_unix_seconds=expiry,
        globally_latest=False, delivery_receipt_file="delivery-receipt.json",
        delivery_receipt_is_signed_attestation=False, browser_configuration_changed=False,
        subscription_installed=False, output="/fixture/filter-viewer/cold")
    receipt = dict(operation="named_content_download", bytes=expected["bytes"], chunks=1,
        publisher_key=expected["publisher_key"], name=CHECK["NAME"], revision=1,
        manifest_id=expected["manifest_id"], publication_expires_unix_seconds=expiry,
        sha256=expected["sha256"], local_delivery=True, output_mode="0600", ownership_changed=False,
        origin_authenticated=False, globally_latest=False, peer_bytes=expected["bytes"],
        providers_used=1, provider_peer_ids=site["application"]["ready"]["provider_peer_ids"][:1],
        origin_body_bytes=0, origin_range_requests=0,
        control_relay_peer_id=site["layout"]["control_relay_peer_id"], cache_only=False)
    application = dict(report=report, receipt=receipt, manifest_sha256=expected["manifest_id"],
        output_sha256=expected["sha256"], output_bytes=expected["bytes"], output_modes="0700/0600",
        consumer=site["application"]["consumer"], cli_boundary_inherited=True, elapsed_ns=1000000,
        observed_unix_seconds=1788850001, agent_cache="/state-client/filter-cache", reuse_cache=False,
        before=None, after=None, private_staging_removed=True, browser_engine_executed=False)
    warm = copy.deepcopy(application)
    warm.update(reuse_cache=True, before=site["cache_only"]["application"]["before"],
                after=site["cache_only"]["application"]["after"])
    warm["report"]["output"] = "/fixture/filter-viewer/warm"
    warm["receipt"].update(peer_bytes=0, providers_used=0, provider_peer_ids=[], control_relay_peer_id="")
    isolation = {key: value for key, value in site["isolation"].items()
                 if key not in ("publisher_process_exited_before_fetch", "publisher_node_offline_claimed")}
    isolation.update(agent_cache="/state-client/filter-cache", publisher_sources_removed_before_fetch=True,
                     selection_pinned_before_fetch=True)
    return dict(success=True, input=expected,
        publish=dict(operation="offline_content_publish", network_publication=False,
                     publisher_key_hex=expected["publisher_key"], bytes=expected["bytes"], chunks=1,
                     expires_unix_seconds=expiry),
        isolation=isolation, expected_peers=site["expected_peers"], layout=site["layout"],
        selected_route=site["selected_route"],
        imports={node: dict(value, manifest_id=expected["manifest_id"], content_bytes=expected["bytes"],
                           agent_cache=value["agent_cache"].replace("site-cache", "filter-cache"))
                 for node, value in site["imports"].items()},
        serves={node: dict(value, publications=3) for node, value in site["serves"].items()},
        cold=dict(application=application, privacy=site["privacy"], control_privacy=site["control_privacy"]),
        warm=dict(application=warm, privacy=site["cache_only"]["privacy"],
                  control_privacy=site["cache_only"]["control_privacy"]),
        publisher_cleanup=dict(directory_removed=True, files_removed=True),
        cleanup=dict(directory_removed=True, files_removed=True))


def raw_files(evidence):
    files = {f"content-provider-filter-{suffix}.json": evidence[key] for key, suffix in (
        ("input", "input"), ("publish", "publish"), ("isolation", "isolation"),
        ("publisher_cleanup", "publisher-cleanup"), ("cleanup", "cleanup"), ("selected_route", "selection"))}
    files["content-provider-layout.json"] = evidence["layout"]
    files["a01-expected-peers.json"] = evidence["expected_peers"]
    for key, operation in (("imports", "import"), ("serves", "serve")):
        for node, receipt in evidence[key].items():
            files[f"content-provider-filter-{node}-{operation}.json"] = receipt
    for phase in ("cold", "warm"):
        files[f"content-provider-filter-{phase}-consumer.json"] = evidence[phase]["application"]
        files[f"content-provider-filter-{phase}-control.json"] = evidence[phase]["control_privacy"]
        for role, capture in evidence[phase]["privacy"].items():
            files[f"content-provider-filter-{phase}-privacy-{role}.json"] = capture
    return files


class FilterProof(unittest.TestCase):
    def test_exact_cold_and_warm_profile_allows_one_real_source_not_forced_replica_work(self):
        for control in ("relay2", "relay4"):
            CHECK["validate"](fixture(control))
        evidence = fixture()
        for role in ("relay0", "relay1"):
            evidence["cold"]["privacy"][role].update(client_leg_wireguard_data_datagrams=1,
                                                       exit_leg_wireguard_data_datagrams=1)
        # Tiny data must not be inflated merely to recreate the separate bulk proof.
        CHECK["validate"](evidence)

    def test_identity_expiry_peer_accounting_and_cache_boundaries_fail_closed(self):
        changes = [
            (("cold", "application", "report", "manifest_id"), "f" * 64),
            (("warm", "application", "manifest_sha256"), "f" * 64),
            (("warm", "application", "report", "expires_unix_seconds"), 1788851200),
            (("warm", "application", "receipt", "publication_expires_unix_seconds"), 1788851200),
            (("warm", "application", "output_sha256"), "f" * 64),
            (("cold", "application", "receipt", "peer_bytes"), 0),
            (("cold", "application", "receipt", "provider_peer_ids"), []),
            (("cold", "application", "receipt", "provider_peer_ids"), ["peer-client"]),
            (("cold", "application", "receipt", "providers_used"), 2),
            (("warm", "application", "receipt", "peer_bytes"), 1),
            (("warm", "application", "receipt", "cache_only"), True),
            (("warm", "application", "receipt", "control_relay_peer_id"), "peer-relay2"),
            (("warm", "application", "receipt", "origin_body_bytes"), 1),
            (("warm", "application", "report", "subscription_installed"), True),
            (("isolation", "cache_identity_after"), "1:43"),
            (("isolation", "selection_pinned_before_fetch"), False),
            (("isolation", "client_cannot_read_provider_caches"), False),
            (("publisher_cleanup", "files_removed"), False),
            (("cleanup", "directory_removed"), False),
            (("cold", "application", "consumer", "all_capabilities_dropped"), False),
        ]
        self.reject_mutations(changes)

    def test_complete_capture_route_and_no_discovery_evidence_required(self):
        changes = [
            (("selected_route", "route_context_id"), "b" * 32),
            (("cold", "privacy", "client", "direct_client_exit_packets"), 1),
            (("cold", "privacy", "exit", "packet_socket_drops"), 1),
            (("cold", "privacy", "exit", "provider_application", "relay4", "response_payload_bytes"), 0),
            (("warm", "privacy", "exit", "provider_application", "relay4", "request_packets"), 1),
            (("warm", "privacy", "client", "client_leg_wireguard_data_datagrams"), 1),
            (("warm", "privacy", "exit", "truncated"), True),
            (("warm", "control_privacy", "unexpected_provider_application_packets"), 1),
            (("warm", "application", "after", "paths"), "unexpected path\n"),
            (("warm", "application", "after", "logs"), "1788850000200 Info event=LOST_BASELINE\n"),
            (("warm", "application", "after", "logs"), "1788850000000 Info event=OLD\n1788850000200 Info event=CONTENT_DISCOVERY_STARTED\n"),
        ]
        self.reject_mutations(changes)
        evidence = fixture()
        evidence["warm"]["privacy"].pop("relay2")
        with self.assertRaises(ValueError):
            CHECK["validate"](evidence)

    def reject_mutations(self, changes):
        for path, value in changes:
            with self.subTest(path=path):
                evidence = fixture()
                target = evidence
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                with self.assertRaises((ValueError, KeyError)):
                    CHECK["validate"](evidence)

    def test_fixture_cleanup_refuses_unknown_files_without_partial_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "filter-publisher"
            root.mkdir(mode=0o700)
            CHECK["initialize"](root)
            CHECK["write_new"](root / "unknown", b"keep")
            with self.assertRaises(ValueError):
                CHECK["cleanup"](root, True)
            self.assertEqual((root / "filters.txt").read_bytes(), CHECK["TEXT"])
            (root / "unknown").unlink()
            self.assertEqual(CHECK["cleanup"](root, True), dict(directory_removed=True, files_removed=True))
            self.assertEqual(CHECK["cleanup"](root, True), dict(directory_removed=True, files_removed=True))

    def test_user_cleanup_removes_only_exact_snapshot_files_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "filter-viewer"
            root.mkdir(mode=0o700)
            for phase in ("cold", "warm"):
                directory = root / phase
                directory.mkdir(mode=0o700)
                for name in CHECK["FILES"]:
                    CHECK["write_new"](directory / name, b"disposable")
            target = root / "warm" / "manifest.pb"
            target.unlink()
            target.symlink_to(root / "cold" / "manifest.pb")
            with self.assertRaises(ValueError):
                CHECK["cleanup"](root, False)
            self.assertTrue((root / "cold" / "manifest.pb").exists())
            target.unlink()
            CHECK["write_new"](target, b"disposable")
            self.assertTrue(all(CHECK["cleanup"](root, False).values()))

    def test_exact_capture_allowlist_cleanup_and_phase_order_are_wired(self):
        source = (HERE / "kvm-alpha-topology.sh").read_text()
        registration = source.split("start_privacy_observers() {\n", 1)[1].split("    set --\n", 1)[0]
        script = "registered() {\n" + registration + '}\nscenario=$1\nregistered "$2"\n'
        for scenario in ("content-provider", "content", "content-https"):
            for prefix in ("content-provider-filter-cold-privacy", "content-provider-filter-warm-privacy",
                           "content-provider-filter-unregistered"):
                result = subprocess.run(["sh", "-eu", "-c", script, "sh", scenario, prefix],
                                        capture_output=True, timeout=2, check=False)
                self.assertEqual(result.returncode == 0,
                    scenario == "content-provider" and prefix != "content-provider-filter-unregistered")
        self.assertIn('content_provider_filter_cleanup || original_status=1', source)
        self.assertIn('. "$source_directory/tests/integration/content-provider-filter-smoke.sh"', source)
        site = (HERE / "content-provider-site-smoke.sh").read_text().split("content_provider_site_run() {", 1)[1]
        self.assertLess(site.index("content_provider_filter_cold_run"), site.index("content_provider_site_cache_only_run"))
        self.assertLess(site.index("content_provider_site_cache_only_run"), site.index("content_provider_filter_warm_run"))
        self.assertLess(site.index(".publications == 2"), site.index("content_provider_filter_cold_run"))
        runtime = (HERE / "content-provider-smoke.sh").read_text()
        self.assertIn("$evidence.filter_snapshot.success == true", runtime)
        workflow = (HERE.parents[1] / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("python3 -B tests/integration/test-content-provider-filter-smoke.py", workflow)


if __name__ == "__main__":
    unittest.main()
