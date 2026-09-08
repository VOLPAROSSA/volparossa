#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic site-evidence gates and exact fixture cleanup; not a network acceptance run."""

import copy
import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "content-provider-site-smoke.py"))
BASE = runpy.run_path(str(HERE / "test-content-provider-https-smoke.py"))


def fixture(control_node="relay2"):
    base = BASE["fixture"](control_node)
    phase = base["cases"]["complete"]
    peers, layout = base["expected_peers"], base["layout"]
    expected = dict(name=CHECK["NAME"], content_type=CHECK["CONTENT_TYPE"], assets=CHECK["inventory"](),
                    publisher_key="4" * 64, bundle_bytes=CHECK["BUNDLE_BYTES"], bundle_sha256=CHECK["BUNDLE_SHA256"])
    boundary = dict(user_uid=985, user_gid=985, control_gid=1003,
                    client_namespace=True, outside_parent_namespace=True,
                    all_capabilities_dropped=True, no_new_privileges=True)
    ready = dict(operation="native_site_ready", publisher_key=expected["publisher_key"], name=CHECK["NAME"],
                 revision=1, assets=4, bytes=expected["bundle_bytes"], peer_bytes=expected["bundle_bytes"],
                 chunks=9, sha256=expected["bundle_sha256"], manifest_id="3"*64, providers_used=2,
                 provider_peer_ids=[peers[n] for n in layout["provider_nodes"]],
                 control_relay_peer_id=layout["control_relay_peer_id"], native_publisher_authenticated=True,
                 static_only=True, local_delivery=True, origin_authenticated=False,
                 https_origin_authenticated=False, globally_latest=False, automatic_browser_open=False,
                 ownership_changed=False, expires_unix_seconds=1788851000)
    final = dict(ready, operation="native_site_closed", reason="terminated", private_spool_removed=True)
    results = {path: dict(value, status=200, content_length=str(value["bytes"]),
                         content_range=None, security_headers_verified=True)
               for path, value in expected["assets"].items()}
    media = CHECK["assets"]()["/media.bin"][1]
    application = dict(consumer=boundary, cli=copy.deepcopy(boundary), ready=ready, final=final,
        assets=results, head=dict(status=200, bytes=0, content_length=str(len(media)), security_headers_verified=True),
        byte_range=dict(status=206, bytes=4096, sha256=hashlib.sha256(media[101:4197]).hexdigest(),
                        content_range=f"bytes 101-4196/{len(media)}", content_length="4096", security_headers_verified=True),
        rejected=dict(host=400, traversal=404), elapsed_ns=2_000_000_000, no_manifest_argument=True,
        browser_engine_executed=False, sigterm_cleanup=True, listener_closed=True,
        private_spool_removed=True, spool_modes="0700/0600")
    imports = {node: dict(operation="content_import", complete=True, content_bytes=expected["bundle_bytes"],
                         public_content=True, ownership_changed=False, network_transfer=False,
                         origin_authenticated=False, manifest_id="3"*64, agent_cache=f"/state-{node}/site-cache")
               for node in layout["provider_nodes"]}
    return dict(success=True, input=expected, application=application, expected_peers=peers, layout=layout,
        pack=dict(operation="site_pack", assets=4, bytes=expected["bundle_bytes"],
                  content_type=CHECK["CONTENT_TYPE"], network_published=False),
        publish=dict(operation="offline_content_publish", network_publication=False, bytes=expected["bundle_bytes"],
                     chunks=9, publisher_key_hex=expected["publisher_key"], expires_unix_seconds=1788851100),
        imports=imports, serves={node: dict(serving=True, publications=2, replication_enabled=False)
                                 for node in layout["provider_nodes"]},
        selected_route=phase["selected_route"], privacy=phase["privacy"], control_privacy=phase["control"],
        isolation=dict(route_context_id="a"*32, user_uid=985, user_gid=985, agent_uid=987,
                       agent_gid=987, control_gid=1003, cache_modes="0700", fresh_client_cache=True,
                       agent_mount_positive_control=True, client_cannot_read_provider_caches=True,
                       agent_cannot_read_user_directory=True, user_cannot_read_agent_caches=True,
                       publisher_process_exited_before_fetch=True, publisher_node_offline_claimed=False),
        publisher_cleanup=dict(publisher_files_removed=True, source_cache_removed=True, manifest_removed=True),
        cleanup=dict(user_directory_removed=True))


class SiteProof(unittest.TestCase):
    def test_full_scoped_site_evidence_and_missing_functional_boundaries(self):
        evidence = fixture()
        CHECK["validate_evidence"](evidence)
        changes = [
            (("application", "ready", "publisher_key"), "f"*64),
            (("application", "ready", "peer_bytes"), 0),
            (("application", "ready", "providers_used"), 1),
            (("application", "ready", "https_origin_authenticated"), True),
            (("application", "ready", "sha256"), "f"*64),
            (("application", "assets", "/main.js", "sha256"), "f"*64),
            (("application", "byte_range", "status"), 200),
            (("application", "head", "bytes"), 1),
            (("application", "sigterm_cleanup"), False),
            (("application", "browser_engine_executed"), True),
            (("application", "cli", "client_namespace"), False),
            (("publisher_cleanup", "manifest_removed"), False),
            (("publisher_cleanup", "source_cache_removed"), False),
            (("isolation", "client_cannot_read_provider_caches"), False),
            (("selected_route", "route_context_id"), "b"*32),
            (("privacy", "client", "direct_client_exit_packets"), 1),
            (("privacy", "relay0", "client_leg_wireguard_data_datagrams"), 0),
            (("privacy", "exit", "packet_socket_drops"), 1),
            (("control_privacy", "unexpected_provider_application_packets"), 1),
        ]
        for path, value in changes:
            with self.subTest(path=path):
                changed = copy.deepcopy(evidence)
                target = changed
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    CHECK["validate_evidence"](changed)

    def test_exact_fixture_cleanup_refuses_unknown_entries_then_removes_all_publisher_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "site-publisher"
            root.mkdir(mode=0o700)
            expected = CHECK["initialize"](root)
            self.assertEqual(expected["assets"], CHECK["inventory"]())
            for name in ("identity.key", "manifest.bin", "bundle.bin"):
                CHECK["write_new"](root / name, b"explicit disposable test bytes")
            cache = root / "source-cache"
            cache.mkdir(mode=0o700)
            for name in ("a"*64, ".volparossa-owner-v1", ".volparossa-index-v1"):
                CHECK["write_new"](cache / name, b"test cache metadata")
            CHECK["write_new"](root / "unknown", b"do not remove")
            with self.assertRaises(ValueError):
                CHECK["remove_publisher"](root)
            self.assertTrue((root / "identity.key").is_file())
            (root / "unknown").unlink()
            self.assertTrue(all(CHECK["remove_publisher"](root).values()))
            self.assertFalse(root.exists())
            self.assertTrue(all(CHECK["remove_publisher"](root).values()))


if __name__ == "__main__":
    unittest.main()
