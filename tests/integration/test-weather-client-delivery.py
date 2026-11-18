#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert receipt/cleanup tests. No origin requests, decoder, core or browser."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
A = runpy.run_path(str(HERE / "weather-client-delivery.py"))
SHA = "a" * 64
FILTER = runpy.run_path(str(HERE / "test-content-provider-filter-smoke.py"))


def publication():
    return dict(publisher_key=SHA, name=A["NAME"], revision=1, manifest_id="b" * 64,
        sha256="c" * 64, bytes=6000, expires_unix_seconds=1900000000)


def selected():
    return dict(schema=1, publication=publication(), query=dict(latitude=52.52, longitude=13.41,
        run="2026-10-10T12:00:00.000Z", model="ifs", steps=[3, 9, 24], communityArea=True, includeWind=True))


def receipt(cache=Path("/fixture/state-client/weather-cache"), output=Path("/fixture/forecast.json")):
    p = publication()
    return dict(operation="named_content_download", **{k: v for k, v in p.items() if k != "expires_unix_seconds"},
        publication_expires_unix_seconds=p["expires_unix_seconds"], cache=str(cache), local_output=str(output),
        local_delivery=True, output_mode="0600", peer_bytes=p["bytes"], providers_used=1, provider_peer_ids=["peer-a"],
        origin_body_bytes=0, origin_range_requests=0, chunks=1, ownership_changed=False, origin_authenticated=False,
        globally_latest=False, cache_only=False, control_relay_peer_id="control")


def acquisition():
    return dict(schema=1, success=True, origin_https=True, acquisition_outside_overlay=True,
        upstream_signature_attested=False, synthetic_weather=False, forecast_sha256=publication()["sha256"],
        forecast_bytes=publication()["bytes"], decoder_sha256=A["B"]["DECODER_SHA"],
        fields=[dict(lead_hours=step, parameter=parameter, index_sha256=SHA, field_sha256=SHA)
            for step in (3, 9, 24) for parameter in ("2t", "10u", "10v")])


def report():
    return dict(schema=1, passed=True, phase="complete", source=dict(bundle_manifest_sha256=SHA,
        driver_sha256=SHA, preparer_sha256=SHA, built_tree_sha256=SHA, node_sha256=A["B"]["NODE_SHA"],
        bridge_modules={name: SHA for name in ("scripts/serve-provider.mjs", "src/provider-http.mjs",
            "src/provider-core.mjs", "src/core-cache.mjs")}),
        expected=dict(expected_sha256=SHA, cold_receipt_sha256=SHA, core_sha256=SHA, display_sha256=SHA,
            forecast_sha256=publication()["sha256"], manifest_id=publication()["manifest_id"]),
        scope=dict(actual_drizzli_ui=True, actual_http_bridge=True, real_core_adapter=True,
            synthetic_weather=False, standalone_origin_proven=False, standalone_overlay_proven=False,
            browser_triggered_cold_fetch=False),
        checks=dict(api_response_sha256=SHA, initial_dom_display_sha256=SHA, refresh_dom_display_sha256=SHA,
            initial_dom_matches_cold_publication=True, refresh_dom_matches_cold_publication=True,
            browser_api_requests=2, provider_requests_checked=1, exact_native_times_and_values=True,
            explicit_missing_capabilities=True, no_external_resources=True, source_attribution=True),
        cleanup=dict(browser_exited=True, bridge_exited=True, private_state_removed=True,
            normal_browser_stop=True, normal_bridge_stop=True),
        outer_cleanup=dict(namespace_wrapper_exited=True, private_state_removed=True, client_namespace_unchanged=True))


def save(path, value, mode=0o600):
    A["write_new"](path, json.dumps(value).encode(), mode)


def joined_fixture(work):
    """Synthetic closed records exercise the join, not real network transport."""
    f = FILTER["fixture"]()
    p = publication()
    r = receipt(work / "state-client/weather-cache", work / "client-fixtures/weather-viewer/forecast.json")
    r.update(provider_peer_ids=f["cold"]["application"]["receipt"]["provider_peer_ids"],
        control_relay_peer_id=f["layout"]["control_relay_peer_id"])
    files = {
        "input": selected(), "acquisition": acquisition(), "publisher-cleanup": dict(directory_removed=True, files_removed=True),
        "input-cleanup": dict(directory_removed=True, files_removed=True), "selection": f["selected_route"],
        "control": f["cold"]["control_privacy"], "prepared": dict(prepared=True, expected_sha256=SHA, display_sha256=SHA),
        "cold-consumer": dict(schema=1, receipt=r, publication=p, cold_cache_requested=True, core_sha256=SHA,
            cold_receipt_sha256=SHA, observed_unix_seconds=p["expires_unix_seconds"]-60,
            boundary=dict(user_uid=985, primary_control_gid=os.getgid(), supplementary_groups_empty=True,
                all_capabilities_dropped=True, no_new_privileges=True, client_namespace=True, acquisition_parent_namespace=False)),
        "publish": dict(operation="offline_content_publish", network_publication=False,
            publisher_key_hex=p["publisher_key"], content_type="application/json", chunks=1,
            **{k: p[k] for k in ("name", "revision", "bytes", "manifest_id", "expires_unix_seconds")})}
    cache = dict(device=1, inode=10, mode="0700", user_uid=1234, group_gid=os.getgid()+1)
    files.update({"cache-" + name: cache for name in ("before", "after")})
    for role, captured in f["cold"]["privacy"].items(): files["privacy-" + role] = captured
    for node in f["layout"]["provider_nodes"]:
        files[node + "-import"] = dict(f["imports"][node], manifest_id=p["manifest_id"], content_bytes=p["bytes"],
            agent_cache=str(work / f"state-{node}/weather-cache"))
        files[node + "-serve"] = dict(f["serves"][node], publications=4)
    B = A["B"]
    items = {name: dict(bytes=1, mode=B["mode"](name), sha256=SHA) for name in B["FIXED"] | {B["STATIC"]+"index.html"}}
    for name, digest in (("runtime/node", B["NODE_SHA"]), ("decoder/grib_ls", B["DECODER_SHA"]),
            (B["WEATHER"]+"third_party/eccodes-sources.json", B["PIN_SHA"]),
            (B["WEATHER"]+"scripts/build_eccodes.py", B["BUILD_SHA"])): items[name]["sha256"] = digest
    manifest = B["encode"](dict(version=1, kind=B["KIND"], files=items))
    manifest_sha = hashlib.sha256(manifest).hexdigest()
    A["write_new"](work / "weather-client-delivery-manifest.json", manifest, 0o400)
    for name in ("before", "after"):
        files["tree-"+name] = dict(version=1, action="verify-tree", manifest_sha256=manifest_sha, files=len(items), runtime_executed=False)
    browser = report(); browser["source"]["bundle_manifest_sha256"] = manifest_sha
    browser["source"]["built_tree_sha256"] = hashlib.sha256(json.dumps({"index.html": SHA}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    files["original-report"] = browser
    save(work / "a01-expected-peers.json", f["expected_peers"])
    save(work / "content-provider-layout.json", f["layout"])
    socket = work / "runtime-client/control/agent.sock"; socket.parent.mkdir(parents=True)
    A["write_new"](socket, b"inert stat-only fixture")
    for suffix, value in files.items(): save(work / f"weather-client-delivery-{suffix}.json", value)
    with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda *args: cache):
        save(work / "weather-client-delivery-cold-evidence.json", A["cold_evidence"](work, manifest_sha, SHA))
    return manifest_sha, cache


class Receipts(unittest.TestCase):
    def test_join_requires_same_publication_dom_hash_and_closed_real_evidence(self):
        mutations = [None,
            ("original-report", ("checks", "refresh_dom_display_sha256"), "f"*64),
            ("original-report", ("scope", "synthetic_weather"), True),
            ("original-report", ("expected", "cold_receipt_sha256"), "f"*64),
            ("original-report", ("expected", "expected_sha256"), "f"*64),
            ("original-report", ("source", "node_sha256"), "f"*64),
            ("original-report", ("cleanup", "normal_bridge_stop"), False),
            ("acquisition", ("synthetic_weather",), True),
            ("cold-consumer", ("boundary", "all_capabilities_dropped"), False),
            ("cold-consumer", ("receipt", "origin_body_bytes"), 1),
            ("publisher-cleanup", ("files_removed",), False),
            ("cold-evidence", ("forecast_sha256",), "f"*64),
            ("cold-evidence", ("scope", "end_to_end_proven"), True),
            ("tree-after", ("manifest_sha256",), "f"*64),
            ("privacy-client", ("direct_client_exit_packets",), 1),
            ("privacy-exit", ("packet_socket_drops",), 1),
            ("control", ("unexpected_provider_application_packets",), 1)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, cache = joined_fixture(work)
                if mutation:
                    suffix, keys, value = mutation
                    path = work / f"weather-client-delivery-{suffix}.json"
                    data = json.loads(path.read_bytes()); target = data
                    for key in keys[:-1]: target = target[key]
                    target[keys[-1]] = value
                    path.unlink(); save(path, data)
                with patch.dict(A["evidence"].__globals__, cache_state=lambda *args: cache):
                    if mutation:
                        with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)
                    else:
                        proof = A["evidence"](work, digest, SHA)
                        self.assertTrue(proof["success"])
                        self.assertEqual(proof["protected_cold"]["peer_bytes"], publication()["bytes"])
                        self.assertFalse(proof["scope"]["browser_triggered_cold_fetch"])
                        self.assertFalse(proof["scope"]["browser_cache_only_proven"])
                        self.assertFalse(proof["scope"]["two_subflow_bulk_aggregation"])
                        A["validate_export"](proof)

    def test_cold_evidence_survives_missing_or_failed_ui_without_claiming_end_to_end(self):
        for browser_outcome in ("missing", "failed"):
            with self.subTest(browser=browser_outcome), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, cache = joined_fixture(work)
                for suffix in ("original-report", "tree-after", "cache-after", "prepared", "input-cleanup"):
                    (work / f"weather-client-delivery-{suffix}.json").unlink()
                if browser_outcome == "failed":
                    failed = report(); failed.update(passed=False, phase="inputs", checks={}, cleanup={})
                    failed["scope"].update(actual_drizzli_ui=False, actual_http_bridge=False, real_core_adapter=False)
                    save(work / "weather-client-delivery-original-report.json", failed)
                # The browser has not removed its private working inputs yet.
                (work / "client-fixtures/weather-viewer").mkdir(parents=True)
                original = (work / "weather-client-delivery-cold-evidence.json").read_bytes()
                with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda *args: cache):
                    proof = A["cold_evidence"](work, digest, SHA)
                    self.assertEqual(json.loads(original), proof)
                    with self.assertRaises((OSError, ValueError)):
                        A["evidence"](work, digest, SHA)
                self.assertTrue(proof["scope"]["protected_cold_transfer"])
                self.assertEqual(proof["forecast_sha256"], publication()["sha256"])
                for key in ("actual_drizzli_ui", "actual_http_bridge", "actual_ui_refresh", "end_to_end_proven"):
                    self.assertIs(proof["scope"][key], False)
                output = work / "output"; output.mkdir()
                A["copy_artifacts"](work, output, os.getuid(), os.getgid())
                self.assertEqual((output / "weather-client-delivery-cold-evidence.json").read_bytes(), original)
                self.assertFalse((output / "weather-client-delivery-evidence.json").exists())

    def test_cold_evidence_requires_full_acquisition_publication_transport_and_privacy_join(self):
        mutations = [
            ("acquisition", ("forecast_sha256",), "f"*64),
            ("acquisition", ("forecast_bytes",), 1),
            ("acquisition", ("synthetic_weather",), True),
            ("acquisition", ("fields",), []),
            ("cold-consumer", ("core_sha256",), "f"*64),
            ("cold-consumer", ("boundary", "all_capabilities_dropped"), False),
            ("cold-consumer", ("receipt", "peer_bytes"), 0),
            ("cold-consumer", ("receipt", "origin_body_bytes"), 1),
            ("cold-consumer", ("receipt", "local_output"), "/private/unrelated"),
            ("publish", ("manifest_id",), "f"*64),
            ("publisher-cleanup", ("files_removed",), False),
            ("tree-before", ("manifest_sha256",), "f"*64),
            ("cache-before", ("user_uid",), 985),
            ("privacy-client", ("direct_client_exit_packets",), 1),
            ("privacy-exit", ("packet_socket_drops",), 1),
            ("control", ("unexpected_provider_application_packets",), 1)]
        for suffix, keys, value in mutations:
            with self.subTest(file=suffix, field=keys), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, cache = joined_fixture(work)
                (work / "weather-client-delivery-original-report.json").unlink()
                path = work / f"weather-client-delivery-{suffix}.json"
                data = json.loads(path.read_bytes()); target = data
                for key in keys[:-1]: target = target[key]
                target[keys[-1]] = value
                path.unlink(); save(path, data)
                with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda *args: cache):
                    with self.assertRaises(ValueError): A["cold_evidence"](work, digest, SHA)

    def test_cold_evidence_rejects_publisher_residue_and_closed_export_violations(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); digest, cache = joined_fixture(work)
            publisher = work / "client-fixtures/weather-publisher"; publisher.parent.mkdir()
            for symlink in (False, True):
                if symlink: publisher.symlink_to(work / "absent")
                else: publisher.mkdir()
                with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda *args: cache):
                    with self.assertRaises(ValueError): A["cold_evidence"](work, digest, SHA)
                if symlink: publisher.unlink()
                else: publisher.rmdir()
            path = work / "weather-client-delivery-cold-evidence.json"; original = path.read_bytes()
            for keys, value in [(('path',), '/private/forecast'), (('forecast_sha256',), 'coordinates'),
                    (('forecast_bytes',), True), (('scope', 'end_to_end_proven'), True),
                    (('scope', 'actual_drizzli_ui'), True), (('protected_cold', 'privacy_captures_validated'), False),
                    (('protected_cold', 'peer_bytes'), 1), (('protected_cold', 'providers_used'), True)]:
                bad = json.loads(original); target = bad
                for key in keys[:-1]: target = target[key]
                target[keys[-1]] = value
                with self.subTest(field=keys), self.assertRaises(ValueError): A["validate_cold_export"](bad)
            bad = json.loads(original); bad["private"] = "DO NOT EXPORT"
            path.unlink(); save(path, bad)
            output = work / "output"; output.mkdir()
            with self.assertRaises(ValueError): A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual(list(output.iterdir()), [])

    def test_early_cold_export_survives_later_invalid_ui_evidence_without_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); joined_fixture(work)
            output = work / "output"; output.mkdir()
            proof = work / "weather-client-delivery-cold-evidence.json"
            wanted = proof.read_bytes()
            result = A["copy_artifacts"](work, output, os.getuid(), os.getgid(), only_cold=True)
            self.assertEqual(result, dict(files=1, raw_logs_exported=False))
            target = output / proof.name; inode = target.stat().st_ino
            # Even a malformed later UI/final receipt cannot erase the already
            # exported cold proof or turn the final join into a success.
            bad = work / "weather-client-delivery-evidence.json"
            save(bad, dict(success=False, failure="inert_late_ui_failure"))
            with self.assertRaises(ValueError): A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual(list(output.iterdir()), [target])
            self.assertEqual(target.read_bytes(), wanted)
            self.assertEqual(target.stat().st_ino, inode)
            self.assertEqual(A["copy_artifacts"](work, output, os.getuid(), os.getgid(), only_cold=True), result)
            modified = json.loads(wanted); modified["core_sha256"] = "f"*64
            proof.unlink(); save(proof, modified)
            with self.assertRaises(ValueError):
                A["copy_artifacts"](work, output, os.getuid(), os.getgid(), only_cold=True)
            self.assertEqual(target.read_bytes(), wanted)
            proof.unlink()
            with self.assertRaises(ValueError):
                A["copy_artifacts"](work, output, os.getuid(), os.getgid(), only_cold=True)

    def test_selection_has_no_authority_or_query_fallback(self):
        A["validate_selection"](selected())
        for key, value in (("latitude", 52), ("communityArea", False), ("includeWind", False),
                           ("steps", [3, 6, 9]), ("model", "aifs"), ("run", "2026-10-10T01:00:00.000Z")):
            bad = selected(); bad["query"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): A["validate_selection"](bad)
        for key, value in (("revision", True), ("bytes", 0), ("bytes", 131073), ("publisher_key", "wrong")):
            bad = selected(); bad["publication"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): A["validate_selection"](bad)

    def test_cold_receipt_requires_real_peer_bytes_zero_origin_and_exact_object(self):
        cache, output = Path("/fixture/state-client/weather-cache"), Path("/fixture/forecast.json")
        A["validate_cold_receipt"](receipt(), publication(), cache, output)
        changes = dict(peer_bytes=0, origin_body_bytes=1, origin_range_requests=1, cache_only=True,
            providers_used=True, provider_peer_ids=["peer-a", "peer-a"], chunks=True, local_delivery=False,
            publication_expires_unix_seconds=1, manifest_id=SHA, sha256=SHA, cache="/other", local_output="/other")
        for key, value in changes.items():
            bad = receipt(); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                A["validate_cold_receipt"](bad, publication(), cache, output)

    def test_acquisition_requires_all_nine_actual_fields_and_decoder_pin(self):
        A["validate_acquisition"](acquisition())
        changes = dict(synthetic_weather=True, upstream_signature_attested=True, acquisition_outside_overlay=False,
            decoder_sha256=SHA, forecast_bytes=True, forecast_sha256="private", fields=[])
        for key, value in changes.items():
            bad = acquisition(); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): A["validate_acquisition"](bad)
        bad = acquisition(); bad["fields"][-1] = bad["fields"][0]
        with self.assertRaises(ValueError): A["validate_acquisition"](bad)

    def test_closed_browser_report_rejects_private_or_unbounded_fields(self):
        A["closed_report"](report())
        variants = []
        bad = report(); bad["log"] = "PRIVATE"; variants.append(bad)
        bad = report(); bad["checks"]["url"] = "PRIVATE"; variants.append(bad)
        bad = report(); bad["checks"]["browser_api_requests"] = 500; variants.append(bad)
        bad = report(); bad["checks"]["refresh_dom_display_sha256"] = "PRIVATE"; variants.append(bad)
        bad = report(); bad["source"]["bridge_modules"]["raw.js"] = SHA; variants.append(bad)
        bad = report(); bad["scope"]["actual_drizzli_ui"] = 1; variants.append(bad)
        for bad in variants:
            with self.assertRaises(ValueError): A["closed_report"](bad)

    def test_export_is_byte_exact_and_prevalidates_all_candidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); work = root / "work"; output = root / "output"
            work.mkdir(); output.mkdir()
            raw = json.dumps(acquisition(), indent=2).encode() + b"\n"
            source = work / "weather-client-delivery-acquisition.json"
            A["write_new"](source, raw)
            late = work / "weather-client-delivery-input-cleanup.json"
            save(late, dict(directory_removed=True, private="DO NOT EXPORT"))
            with self.assertRaises(ValueError): A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual(list(output.iterdir()), [])
            late.unlink()
            result = A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual(result, dict(files=1, raw_logs_exported=False))
            self.assertEqual((output / source.name).read_bytes(), raw)
            before = (output / source.name).stat().st_ino
            self.assertEqual(A["copy_artifacts"](work, output, os.getuid(), os.getgid()), result)
            self.assertEqual((output / source.name).stat().st_ino, before)
            source.unlink(); save(source, dict(schema=1, success=False))
            with self.assertRaises(ValueError): A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual((output / source.name).read_bytes(), raw)

    def test_duplicate_keys_rejected_before_raw_retention_or_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "output"; output.mkdir()
            raw = b'{"schema":"PRIVATE",' + json.dumps(acquisition()).encode()[1:]
            A["write_new"](root / "weather-client-delivery-acquisition.json", raw)
            with self.assertRaises(ValueError): A["copy_artifacts"](root, output, os.getuid(), os.getgid())
            self.assertEqual(list(output.iterdir()), [])
            path = root / "client-fixtures/weather-viewer/browser-output"; path.mkdir(parents=True)
            save(path / "report.json", report())
            duplicate = b'{"schema":"PRIVATE",' + json.dumps(report()).encode()[1:]
            with patch.dict(A["retain"].__globals__, worker_report=lambda p: duplicate):
                with self.assertRaises(ValueError): A["retain"](root)
            self.assertFalse((root / "weather-client-delivery-original-report.json").exists())

    def test_cleanup_refuses_unknown_input_before_removing_known_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "weather-publisher"; root.mkdir(mode=0o700)
            A["write_new"](root / "passphrase", b"fixture")
            A["write_new"](root / "foreign", b"preserve")
            with self.assertRaises(ValueError): A["cleanup"](root, True)
            self.assertEqual((root / "passphrase").read_bytes(), b"fixture")
            (root / "foreign").unlink()
            save(root / "publish-receipt.json", {"schema": 1}, 0o400)
            self.assertEqual(A["cleanup"](root, True), dict(directory_removed=True, files_removed=True))
            self.assertFalse(root.exists())


class ProcessBounds(unittest.TestCase):
    def test_output_limit_timeout_environment_and_handler_restore(self):
        previous = signal.getsignal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = A["run"]([sys.executable, "-c", "import os;print(sorted(os.environ))"], root, 1024, 3)
            self.assertNotIn(b"TOKEN", raw)
            for code, maximum, timeout in (("print('x'*200)", 32, 3), ("import time;time.sleep(60)", 32, .05)):
                with self.assertRaises(ValueError): A["run"]([sys.executable, "-c", code], root, maximum, timeout)
            self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
            self.assertEqual(Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip(), "")

    def test_successful_parent_exit_reaps_detached_grandchild(self):
        code = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
            "start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print(p.pid)")
        with tempfile.TemporaryDirectory() as temporary:
            raw = A["run"]([sys.executable, "-c", code], Path(temporary), 64, 3)
            pid = int(raw)
            with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
            self.assertEqual(Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip(), "")


if __name__ == "__main__": unittest.main()
