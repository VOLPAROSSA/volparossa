#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert joined-proof/ordering tests; never starts Browser, broker or namespaces."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "browser-filter-delivery.py"))
FILTER_TEST = runpy.run_path(str(HERE / "test-content-provider-filter-smoke.py"))


def fixture():
    selected = FILTER_TEST["fixture"]()["input"]
    expected = {key: selected[key] for key in ("publisher_key", "name", "manifest_id")}
    expected["authority_expires_unix_seconds"] = 2_000_000_000
    manifest = {"files": {"scripts/smoke_filter_delivery.py": {"sha256": "a" * 64},
        "integration/filters/Gecko.sys.mjs": {"sha256": "b" * 64},
        "tests/fixtures/filter_delivery.sys.mjs": {"sha256": "c" * 64}}}
    stage = dict(version="140.16.0", source_stamp="d" * 40, runtime_sha256={"firefox-esr": "e" * 64},
                 extensions={"packages": [dict(id="test-original", sha256="f" * 64)]})
    logs = {name: dict(bytes=0, sha256=hashlib.sha256(b"").hexdigest()) for name in ("browser", "broker")}
    report = dict(schema=1, passed=True, scope=CHECK["SCOPE"], operation="complete", failure=None,
        expected=expected, broker_sha256="7" * 64, host_read_only=True, interfaces=["lo"], browser_exit_status=0,
        broker_cleanup=dict(started=True, reaped=True, graceful=True), broker_socket_removed=True,
        temporary_profiles_removed=True, receipts={operation: CHECK["operation_receipt"](operation, expected)
                                                   for operation in CHECK["OPERATIONS"]},
        probes={case: {kind: 0 if case == "enrolled" and kind != "neutral" else 1 for kind in ("ads", "tracker", "neutral")}
                for case in CHECK["CASES"]},
        driver_sha256="a" * 64,
        module_sha256={"integration/filters/Gecko.sys.mjs": "b" * 64, "tests/fixtures/filter_delivery.sys.mjs": "c" * 64},
        runtime_version=stage["version"], runtime_source_stamp=stage["source_stamp"], runtime_sha256=stage["runtime_sha256"],
        extension_packages=stage["extensions"]["packages"], logs=logs)
    outer = dict(schema=1, temporary_profiles_removed=True, broker_copy_removed=True, logs=logs)
    return report, outer, expected, manifest, stage, "7" * 64


class JoinedFilterProof(unittest.TestCase):
    def setUp(self):
        guard = patch.object(os, "execv", side_effect=AssertionError("execution forbidden"))
        guard.start(); self.addCleanup(guard.stop)

    def test_exact_real_broker_asset_engine_sequence_is_required(self):
        CHECK["validate_browser"](*fixture())

    def test_join_rejects_wrong_bytes_manifest_mutation_missing_reload_or_missing_cleanup(self):
        changes = [(("passed",), False), (("browser_exit_status",), 1), (("schema",), True),
            (("broker_sha256",), "0" * 64), (("driver_sha256",), "0" * 64),
            (("module_sha256", "integration/filters/Gecko.sys.mjs"), "0" * 64),
            (("receipts", "fetch", "delivery", "manifest_id"), "f" * 64),
            (("receipts", "fetch", "delivery", "bytes"), 62),
            (("receipts", "enroll", "asset", "completed"), 0),
            (("receipts", "enroll", "asset", "accepted"), 2),
            (("receipts", "enroll", "result", "receipt", "reloadEvents"), 1),
            (("receipts", "suspend", "broker_revoked"), False),
            (("receipts", "retry", "result", "attempted"), True),
            (("probes", "enrolled", "ads"), 1), (("probes", "enrolled", "tracker"), 1),
            (("probes", "baseline", "ads"), 0), (("probes", "suspended", "neutral"), 0),
            (("broker_cleanup", "graceful"), False), (("temporary_profiles_removed",), False)]
        for path, value in changes:
            args = list(fixture()); args[0] = copy.deepcopy(args[0]); target = args[0]
            for part in path[:-1]: target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): CHECK["validate_browser"](*args)

    def test_extra_private_fields_and_scope_overclaims_are_refused(self):
        for change in (lambda report: report.update(raw_output="PRIVATE"),
                       lambda report: report["logs"]["browser"].update(raw="PRIVATE"),
                       lambda report: report["scope"].update(cold_cache_proven=True)):
            args = list(fixture()); args[0] = copy.deepcopy(args[0]); change(args[0])
            with self.assertRaises(ValueError) as error: CHECK["validate_browser"](*args)
            self.assertNotIn("PRIVATE", str(error.exception))

    def test_outer_cleanup_must_match_inner_actual_logs_and_remove_broker_copy(self):
        args = list(fixture()); args[1] = copy.deepcopy(args[1]); args[1]["broker_copy_removed"] = False
        with self.assertRaises(ValueError): CHECK["validate_browser"](*args)
        args = list(fixture()); args[1] = copy.deepcopy(args[1]); args[1]["logs"]["broker"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError): CHECK["validate_browser"](*args)

    def test_original_cold_packet_route_and_actual_peer_bytes_remain_mandatory(self):
        original = FILTER_TEST["fixture"]()
        CHECK["validate_cold"](original)
        mutations = [("peer_bytes", 0), ("providers_used", 0), ("provider_peer_ids", [])]
        for key, value in mutations:
            changed = copy.deepcopy(original); changed["cold"]["application"]["receipt"][key] = value
            with self.assertRaises(ValueError): CHECK["validate_cold"](changed)
        changed = copy.deepcopy(original); changed["cold"]["privacy"]["client"]["direct_client_exit_packets"] = 1
        with self.assertRaises(ValueError): CHECK["validate_cold"](changed)
        changed = copy.deepcopy(original); changed["selected_route"]["paths"][1]["relay_peer_id"] = changed["selected_route"]["paths"][0]["relay_peer_id"]
        with self.assertRaises(ValueError): CHECK["validate_cold"](changed)

    def test_owner_authority_is_four_fields_same_publication_and_at_most_ten_minutes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "browser-filter-delivery"; root.mkdir(mode=0o700)
            (root / "home").mkdir(mode=0o700)
            CHECK["write_new"](root / "selection.json", json.dumps(FILTER_TEST["fixture"]()["input"]).encode())
            with patch("time.time", return_value=1000): result = CHECK["prepare"](root, 1500)
            self.assertEqual(result["expected"]["authority_expires_unix_seconds"], 1500)
            self.assertEqual(set(result["expected"]), {"publisher_key", "name", "manifest_id", "authority_expires_unix_seconds"})
            self.assertEqual(CHECK["read"](root / "expected.json"), result["expected"])
            self.assertTrue(all(CHECK["cleanup"](root).values())); self.assertFalse(root.exists())

    def test_cleanup_refuses_unknown_entries_before_removing_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "browser-filter-delivery"; root.mkdir(mode=0o700)
            CHECK["write_new"](root / "selection.json", b"keep")
            CHECK["write_new"](root / "unknown", b"keep too")
            with self.assertRaises(ValueError): CHECK["cleanup"](root)
            self.assertEqual((root / "selection.json").read_bytes(), b"keep")

    def test_launcher_observes_primary_control_gid_empty_groups_no_caps_and_exact_netns(self):
        fields = dict(Uid="985 985 985 985", Gid="984 984 984 984", Groups="", NoNewPrivs="1",
                      CapInh="0", CapPrm="0", CapEff="0", CapBnd="0", CapAmb="0")
        for key, bad in ((None, None), ("Gid", "985 985 985 985"), ("Groups", "984"), ("CapEff", "1"), ("NoNewPrivs", "0")):
            candidate = dict(fields)
            if key: candidate[key] = bad
            with patch.object(Path, "read_text", return_value="\n".join(k+":"+v for k,v in candidate.items())), \
                    patch.object(os, "readlink", return_value="net:[20]"):
                if key:
                    with self.assertRaises(ValueError): CHECK["process_boundary"]("net:[10]", "net:[20]", 985, 984)
                else:
                    self.assertTrue(CHECK["process_boundary"]("net:[10]", "net:[20]", 985, 984)["all_capabilities_dropped"])

    def test_failed_original_receipt_retained_byte_exact_and_absence_not_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); output = work / "client-fixtures/browser-filter-source/build/filter-delivery"
            output.mkdir(parents=True)
            raw = b'{"schema":1,"passed":false,"failure":"fixture_failed"}'
            (output / "report.json").write_bytes(raw)
            (output / "report.json").chmod(0o600)
            first = CHECK["retain"](work)
            self.assertFalse(first["successful_native_execution_claimed"])
            self.assertEqual((work / "browser-filter-delivery-original-report.json").read_bytes(), raw)
            self.assertEqual(CHECK["retain"](work), first)
            (output / "report.json").write_bytes(b'{"schema":1,"passed":true}')
            with self.assertRaises(ValueError): CHECK["retain"](work)

    def test_closed_file_reader_refuses_duplicate_json_keys_symlinks_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"; path.write_text('{"a":1,"a":2}')
            path.chmod(0o600)
            with self.assertRaises(ValueError): CHECK["read"](path)
            link = path.parent / "link"; link.symlink_to(path)
            with self.assertRaises(ValueError): CHECK["raw_file"](link)
            path.write_bytes(b"a" * 65537)
            with self.assertRaises(ValueError): CHECK["raw_file"](path)

    def test_early_diagnostic_retained_without_driver_report_exported_and_cleaned(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve(); root = work / "client-fixtures/browser-filter-delivery"
            root.mkdir(parents=True, mode=0o700)
            raw = b'{"schema":1,"success":false,"phase":"topology_namespace","cleanup_failed":false}'
            CHECK["write_new"](root / "diagnostic.json", raw)
            result = CHECK["retain"](work)
            self.assertEqual(result["originals_sha256"], {"diagnostic": hashlib.sha256(raw).hexdigest()})
            self.assertFalse(result["successful_native_execution_claimed"])
            self.assertEqual(CHECK["retain"](work), result)
            output = work / "output"; output.mkdir()
            exported = CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertIn("original-report", exported["missing"])
            self.assertEqual((output / "browser-filter-delivery-original-diagnostic.json").read_bytes(), raw)
            CHECK["cleanup"](root)
            self.assertFalse(root.exists())

    def test_diagnostic_schema_is_closed_and_never_a_success_receipt(self):
        good = dict(schema=1, success=False, phase="binary", cleanup_failed=True)
        for phase in CHECK["DIAGNOSTIC_PHASES"]:
            CHECK["validate_diagnostic"](dict(good, phase=phase))
        for change in (dict(schema=True), dict(success=True), dict(cleanup_failed=1), dict(phase="PRIVATE"),
                       dict(phase=["binary"]), dict(error="PRIVATE")):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "browser-filter-delivery"; root.mkdir(mode=0o700)
                CHECK["write_new"](root / "selection.json", b"keep")
                CHECK["write_new"](root / "diagnostic.json", json.dumps(dict(good, **change)).encode())
                with self.assertRaises(ValueError): CHECK["cleanup"](root)
                self.assertTrue((root / "selection.json").exists())

    def test_artifact_export_preserves_bytes_hash_and_omits_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, output = Path(temporary) / "work", Path(temporary) / "output"
            work.mkdir(); output.mkdir()
            report = fixture()[0]
            report["extension_packages"][0]["id"] = "uBlock0@raymondhill.net"
            raw = json.dumps(report, indent=2).encode()  # Deliberately no trailing newline.
            name = "browser-filter-delivery-original-report.json"
            CHECK["write_new"](work / name, raw)
            CHECK["write_new"](work / "browser-filter-delivery.err", b"PRIVATE")
            CHECK["write_new"](work / "browser-filter-inputs.tar", b"PRIVATE")
            result = CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual((output / name).read_bytes(), raw)
            self.assertEqual(result["originals"][name], dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            self.assertFalse(result["successful_native_execution_claimed"])
            self.assertIn("evidence", result["missing"])
            self.assertEqual({path.name for path in output.iterdir()}, {name, "browser-filter-delivery-artifacts.json"})
            self.assertEqual(CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid()), result)

    def test_empty_failure_receipts_are_missing_not_success_and_original_false_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, output = Path(temporary) / "work", Path(temporary) / "output"
            work.mkdir(); output.mkdir()
            CHECK["write_new"](work / "browser-filter-delivery-evidence.json", b"")
            raw = b'{"schema":1,"passed":false,"failure":"fixture_failed"}'
            CHECK["write_new"](work / "browser-filter-delivery-original-report.json", raw)
            result = CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertIn("evidence", result["missing"])
            self.assertFalse(result["successful_native_execution_claimed"])
            self.assertEqual((output / "browser-filter-delivery-original-report.json").read_bytes(), raw)

    def test_browser_subphase_diagnostic_retained_and_exported_byte_exact_on_failure(self):
        for phase in CHECK["BROWSER_PHASES"]:
            for kind in CHECK["BROWSER_ERROR_KINDS"]:
                value = dict(schema=1, passed=False, failure="fixture_failed", operation="browser_start",
                    browser_diagnostic=dict(schema=1, phase=phase, error_kind=kind, cleanup_failed=False))
                CHECK["validate_report_diagnostic"](value)
                CHECK["export_value"](value)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            original = work / "client-fixtures/browser-filter-source/build/filter-delivery"
            original.mkdir(parents=True)
            # browser_start includes baseline checks: preserve the actual subphase.
            value = dict(schema=1, passed=False, failure="fixture_failed", operation="browser_start",
                browser_diagnostic=dict(schema=1, phase="baseline_probe", error_kind="check_failed", cleanup_failed=True))
            raw = json.dumps(value, indent=2).encode()
            CHECK["write_new"](original / "report.json", raw)
            retained = CHECK["retain"](work)
            self.assertEqual(retained["originals_sha256"], {"report": hashlib.sha256(raw).hexdigest()})
            self.assertFalse(retained["successful_native_execution_claimed"])
            output = work / "export"; output.mkdir()
            exported = CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual((output / "browser-filter-delivery-original-report.json").read_bytes(), raw)
            self.assertFalse(exported["successful_native_execution_claimed"])

    def test_browser_subphase_schema_rejects_raw_fields_wrong_types_and_unknown_enums_before_export(self):
        diagnostic = dict(schema=1, phase="greeting", error_kind="timeout", cleanup_failed=False)
        changes = [dict(schema=True), dict(schema=2), dict(phase="PRIVATE_SENTINEL"), dict(phase=["greeting"]),
            dict(error_kind="none"), dict(error_kind=["timeout"]), dict(cleanup_failed=1), dict(raw="PRIVATE_SENTINEL")]
        bad_values = [None, {}, {key: value for key, value in diagnostic.items() if key != "phase"},
                      *(dict(diagnostic, **change) for change in changes)]
        for bad in bad_values:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve(); output = work / "export"; output.mkdir()
                value = dict(schema=1, passed=False, failure="fixture_failed", browser_diagnostic=bad)
                CHECK["write_new"](work / "browser-filter-delivery-original-report.json", json.dumps(value).encode())
                with self.assertRaises(ValueError) as error:
                    CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
                self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))
                self.assertEqual(list(output.iterdir()), [])
                original = work / "client-fixtures/browser-filter-source/build/filter-delivery"
                original.mkdir(parents=True)
                CHECK["write_new"](original / "report.json", json.dumps(value).encode())
                with self.assertRaises(ValueError): CHECK["retain"](work)

    def test_closed_protocol_diagnostics_are_retained_and_exported_byte_exact(self):
        values = [dict(kind=kind, webdriver_code=None, source_frames=[]) for kind in CHECK["PROTOCOL_ERROR_KINDS"]
                  if kind != "webdriver_error"]
        values += [dict(kind="webdriver_error", webdriver_code=code,
                       source_frames=[dict(module=module, line=maximum)])
                   for code in CHECK["WEBDRIVER_CODES"] for module, maximum in CHECK["RUNTIME_SOURCE_LINES"].items()]
        for protocol in values:
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve()
                original = work / "client-fixtures/browser-filter-source/build/filter-delivery"
                original.mkdir(parents=True)
                diagnostic = dict(schema=1, phase="session", error_kind="command_error", cleanup_failed=False,
                                  protocol_error=protocol)
                value = dict(schema=1, passed=False, failure="fixture_failed", browser_diagnostic=diagnostic)
                raw = json.dumps(value, indent=2).encode()
                CHECK["write_new"](original / "report.json", raw)
                retained = CHECK["retain"](work)
                self.assertEqual(retained["originals_sha256"], {"report": hashlib.sha256(raw).hexdigest()})
                self.assertFalse(retained["successful_native_execution_claimed"])
                output = work / "export"; output.mkdir()
                exported = CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
                self.assertEqual((output / "browser-filter-delivery-original-report.json").read_bytes(), raw)
                self.assertFalse(exported["successful_native_execution_claimed"])

    def test_protocol_diagnostic_rejects_private_fields_wrong_shapes_bounds_and_categories(self):
        valid = dict(kind="webdriver_error", webdriver_code="session_not_created",
                     source_frames=[dict(module="marionette/driver.sys.mjs", line=717)])
        changed = [dict(kind="PRIVATE"), dict(kind=["webdriver_error"]), dict(webdriver_code="PRIVATE"),
            dict(webdriver_code=None), dict(webdriver_code=["unknown_error"]), dict(source_frames=None),
            dict(source_frames={}), dict(source_frames=[None]), dict(source_frames=[{}]),
            dict(source_frames=[dict(module="PRIVATE", line=1)]),
            dict(source_frames=[dict(module="marionette/driver.sys.mjs", line=True)]),
            dict(source_frames=[dict(module="marionette/driver.sys.mjs", line=0)]),
            dict(source_frames=[dict(module="marionette/driver.sys.mjs", line=3887)]),
            dict(source_frames=[dict(module="marionette/driver.sys.mjs", line="717")]),
            dict(source_frames=[dict(module="marionette/driver.sys.mjs", line=717, column=1)]),
            dict(source_frames=[dict(module="marionette/driver.sys.mjs", line=717)] * 2),
            dict(source_frames=[dict(module="marionette/driver.sys.mjs", line=i) for i in range(1, 10)]),
            dict(message="PRIVATE"), dict(stacktrace="PRIVATE"), dict(response="PRIVATE"), dict(data="PRIVATE")]
        bad_values = [None, {}, *(dict(valid, **change) for change in changed)]
        for kind in CHECK["PROTOCOL_ERROR_KINDS"] - {"webdriver_error"}:
            bad_values += [dict(kind=kind, webdriver_code="unknown_error", source_frames=[]),
                           dict(kind=kind, webdriver_code=None, source_frames=valid["source_frames"])]
        for protocol in bad_values:
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve(); output = work / "export"; output.mkdir()
                value = dict(schema=1, passed=False, failure="fixture_failed", browser_diagnostic=dict(
                    schema=1, phase="session", error_kind="command_error", cleanup_failed=False, protocol_error=protocol))
                raw = json.dumps(value).encode()
                CHECK["write_new"](work / "browser-filter-delivery-original-report.json", raw)
                with self.assertRaises(ValueError) as error:
                    CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
                self.assertNotIn("PRIVATE", str(error.exception)); self.assertEqual(list(output.iterdir()), [])
                original = work / "client-fixtures/browser-filter-source/build/filter-delivery"
                original.mkdir(parents=True); CHECK["write_new"](original / "report.json", raw)
                with self.assertRaises(ValueError): CHECK["retain"](work)

    def test_protocol_diagnostic_is_never_accepted_on_success(self):
        value = dict(passed=True, browser_diagnostic=dict(schema=1, phase="session", error_kind="command_error",
            cleanup_failed=False, protocol_error=dict(kind="eof", webdriver_code=None, source_frames=[])))
        with self.assertRaises(ValueError): CHECK["validate_report_diagnostic"](value)

    def test_browser_subphase_is_never_allowed_on_success_and_old_reports_remain_compatible(self):
        args = list(fixture())
        CHECK["validate_report_diagnostic"](args[0])
        CHECK["validate_browser"](*args)
        CHECK["validate_report_diagnostic"](dict(schema=1, passed=False, failure="fixture_failed"))
        args[0]["browser_diagnostic"] = dict(schema=1, phase="cleanup", error_kind="io_error", cleanup_failed=True)
        with self.assertRaises(ValueError): CHECK["validate_browser"](*args)
        with self.assertRaises(ValueError): CHECK["validate_report_diagnostic"](args[0])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve(); output = work / "export"; output.mkdir()
            CHECK["write_new"](work / "browser-filter-delivery-original-report.json", json.dumps(args[0]).encode())
            with self.assertRaises(ValueError): CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual(list(output.iterdir()), [])

    def test_artifact_export_refuses_private_nested_value_before_any_copy(self):
        for mutation in (lambda value: value.update(raw="PRIVATE"),
                         lambda value: value.update(failure="PRIVATE /home/user"),
                         lambda value: value.update(failure="192.168.1.23"),
                         lambda value: value.update(logs={"browser": {"raw": "PRIVATE"}})):
            with tempfile.TemporaryDirectory() as temporary:
                work, output = Path(temporary) / "work", Path(temporary) / "output"
                work.mkdir(); output.mkdir()
                value = dict(schema=1, passed=False, failure="fixture_failed"); mutation(value)
                CHECK["write_new"](work / "browser-filter-delivery-original-report.json", json.dumps(value).encode())
                with self.assertRaises(ValueError): CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
                self.assertEqual(list(output.iterdir()), [])

    def test_artifact_export_refuses_destination_overwrite_and_source_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, output = Path(temporary) / "work", Path(temporary) / "output"
            work.mkdir(); output.mkdir()
            name = "browser-filter-delivery-input-cleanup.json"
            CHECK["write_new"](work / name, b'{"directory_removed":true,"files_removed":true}')
            CHECK["write_new"](output / name, b"keep-original")
            with self.assertRaises(ValueError): CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual((output / name).read_bytes(), b"keep-original")
            (work / name).unlink(); (work / name).symlink_to(output / name)
            with self.assertRaises(ValueError): CHECK["copy_artifacts"](work, output, os.getuid(), os.getgid())

    def test_opt_in_call_is_additive_after_original_cold_before_original_warm_baseline(self):
        shell = (HERE / "content-provider-filter-smoke.sh").read_text()
        cold = shell.index("    content_provider_filter_consume cold\n")
        hook = shell.index('if [ -n "${browser_filter_bundle:-}" ]; then', cold)
        baseline = shell.index("    filter_cache_before=", cold)
        self.assertLess(cold, hook); self.assertLess(hook, baseline)
        self.assertIn("browser_filter_delivery_run", shell[hook:baseline])
        source = (HERE / "browser-filter-delivery.sh").read_text()
        self.assertIn('--regid="$site_control_gid" --clear-groups', source)
        self.assertIn('ip netns exec "$CLIENT" setpriv', source)
        self.assertIn('"$WORK/bin/browser-filter-bundle.py" verify-tree', source)
        self.assertIn('env HOME="$browser_filter_input/home"', source)
        self.assertLess(source.index(' retain "$WORK"'), source.index('"$browser_filter_status" -eq 0'))
        self.assertNotIn('chmod "$filter_cache"', source)
        self.assertNotIn('chown "$filter_cache"', source)
        self.assertIn('browser_filter_delivery_copy_artifacts()', source)
        self.assertIn('copy-artifacts "$WORK"', source)
        self.assertNotIn('cp -r', source)


if __name__ == "__main__": unittest.main()
