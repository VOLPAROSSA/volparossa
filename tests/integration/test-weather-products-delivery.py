#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic adversarial evidence tests, not an origin/overlay/UI proof."""
import copy
from contextlib import nullcontext
import datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
A = runpy.run_path(str(HERE / "weather-products-delivery.py"))
OLD = runpy.run_path(str(HERE / "test-weather-client-delivery.py"))
SHA = "a" * 64
CLOCK = A["stamp"]("2026-10-11T14:00:00.000Z")


def iso(milliseconds):
    return (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(milliseconds=milliseconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def forecast(key, model_run=None, acquired_at=None, version=2):
    p = A["PRODUCTS"][key]
    model_run = model_run or selected()["products"][key]["query"]["run"]
    def field(parameter):
        return dict(parameter=parameter, decoder_sha256=A["B"]["decoder_sha"](version), index_sha256=SHA, field_sha256=SHA)
    samples = []
    for step in p["steps"]:
        samples.append(dict(lead_hours=step, valid_at=iso(A["stamp"](model_run) + step * 3600000),
            **(dict(evidence=field("2t"), wind_10m=dict(evidence=dict(eastward=field("10u"), northward=field("10v"))),
                precipitation=dict(evidence=field("tp"))) if key == "weather" else
                dict(evidence=dict(pm2_5=field("PMTF"), pm10=field("PMTC"))))))
    return dict(schema=p["schema"], kind="forecast", source=dict(provider=p["provider"], acquisition="origin-https",
        model=p["model"], model_run_at=model_run, acquired_at=acquired_at or iso(CLOCK)),
        area=dict(latitude=52.52, longitude=13.41, sharing="public-community"), samples=samples)


def prepare_fixture(viewer, version=2):
    selection, forecasts = selected(), {}
    for key, p in A["PRODUCTS"].items():
        forecasts[key] = forecast(key, version=version)
        raw = A["B"]["encode"](forecasts[key]); A["write_new"](viewer / p["filename"], raw)
        selection["products"][key]["publication"].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    save(viewer / "selection.json", selection, 0o400)
    return selection, forecasts


def selected():
    result = dict(schema=2, products={})
    for key, p in A["PRODUCTS"].items():
        value = OLD["publication"]()
        value.update(name=p["name"], manifest_id=("b" if key == "weather" else "d")*64,
            sha256=("c" if key == "weather" else "e")*64, bytes=6000 if key == "weather" else 4000)
        result["products"][key] = dict(publication=value,
            query=A["fixed_query"](key, "2026-10-10T12:00:00.000Z" if key == "weather" else "2026-10-10T00:00:00.000Z"))
    return result


def acquisition(version=2):
    selection = selected()
    return dict(schema=6 if version == 6 else 4 if version in (4, 5) else 2,
        success=True, origin_https=True, acquisition_outside_overlay=True,
        upstream_signature_attested=False, synthetic_weather=False, synthetic_air_quality=False,
        independent_product_runs=True, decoder_sha256=A["B"]["decoder_sha"](version), products={
            key: dict(forecast_sha256=selection["products"][key]["publication"]["sha256"],
                forecast_bytes=selection["products"][key]["publication"]["bytes"],
                fields=[dict(lead_hours=step, parameter=parameter, index_sha256=SHA, field_sha256=SHA)
                    for step in p["steps"] for parameter in p["parameters"]]) for key, p in A["PRODUCTS"].items()})


def diagnostic(stage="weather-run"):
    return A["AcquisitionFailure"](stage, ValueError("private coordinates, path, URL and raw stderr")).diagnostic


def source_response(key="weather", observed=CLOCK):
    return dict(schema=1, kind="weather-source-rate-limit", product=key, status=429,
        observed_at_ms=observed, retry_after_state="valid-seconds", retry_not_before_ms=observed+60000)


def failure_fixture(work, raw=None):
    save(A["artifact"](work, "tree-before"), dict(version=1, action="verify-tree", manifest_sha256=SHA,
        files=193, runtime_executed=False))
    save(A["artifact"](work, "input-cleanup"), dict(directory_removed=True, files_removed=True))
    A["write_new"](A["artifact"](work, "acquisition"), raw if raw is not None else A["B"]["encode"](diagnostic()))
    marker = A["retain_acquisition_failure"](work, 1)
    save(A["artifact"](work, "acquisition-failure"), marker)
    return marker


def report(version=2):
    legacy = OLD["report"](); expected = legacy["expected"]
    result = dict(schema=version, passed=True, phase="complete", source=legacy["source"],
        expected={key: expected[key] for key in ("expected_sha256", "core_sha256", "display_sha256")},
        products={}, scope=dict(legacy["scope"], synthetic_air_quality=False, separate_native_runs=True),
        checks=dict(no_external_resources=True, provider_requests_checked=2, browser_api_requests=4,
            initial_dom_display_sha256=SHA, refresh_dom_display_sha256=SHA),
        cleanup=legacy["cleanup"], outer_cleanup=legacy["outer_cleanup"])
    result["source"]["bridge_modules"] = {name: SHA for name in A["BRIDGE_MODULES"]}
    if version in (4, 5):
        result["source"]["synthetic_ui_proof"] = dict(sha256=SHA, driver_sha256=SHA,
            core_executed=False, overlay_proven=False)
    if version == 5:
        result["source"]["synthetic_ui_proof"].update(sha256="1"*64, driver_sha256="2"*64)
        result["source"]["synthetic_table_proof"] = dict(sha256="3"*64, driver_sha256="4"*64,
            verifier_sha256="5"*64, core_executed=False, overlay_proven=False)
    for key in A["PRODUCTS"]:
        publication = selected()["products"][key]["publication"]
        result["products"][key] = dict(expected=dict(cold_receipt_sha256=SHA, display_sha256=SHA,
            forecast_sha256=publication["sha256"], manifest_id=publication["manifest_id"]), checks=copy.deepcopy(legacy["checks"]))
    if version in (3, 5):
        result["scope"]["actual_overmorrow_ui"] = result["scope"].pop("actual_drizzli_ui")
    return result


def save(path, value, mode=0o600):
    A["write_new"](path, json.dumps(value).encode(), mode)


def joined_fixture(work, version=2):
    f = OLD["FILTER"]["fixture"]()
    selection = selected()
    common = {"input": selection, "acquisition": acquisition(version),
        "publisher-cleanup": dict(directory_removed=True, files_removed=True),
        "input-cleanup": dict(directory_removed=True, files_removed=True),
        "prepared": dict(prepared=True, expected_sha256=SHA, display_sha256=SHA)}
    caches = {key: dict(device=1, inode=10+i, mode="0700", user_uid=1234, group_gid=os.getgid()+1)
        for i, key in enumerate(A["PRODUCTS"])}
    for key, p in A["PRODUCTS"].items():
        publication = selection["products"][key]["publication"]
        receipt = OLD["receipt"](work / "state-client" / p["cache"], work / "client-fixtures/weather-viewer" / p["filename"])
        receipt.update({k: v for k, v in publication.items() if k != "expires_unix_seconds"})
        receipt.update(peer_bytes=publication["bytes"], provider_peer_ids=f["cold"]["application"]["receipt"]["provider_peer_ids"],
            control_relay_peer_id=f["layout"]["control_relay_peer_id"])
        files = {
            "selection": f["selected_route"], "control": f["cold"]["control_privacy"],
            "cold-consumer": dict(schema=2, product=key, receipt=receipt, publication=publication,
                cold_cache_requested=True, core_sha256=SHA, cold_receipt_sha256=SHA,
                observed_unix_seconds=publication["expires_unix_seconds"]-60,
                boundary=dict(user_uid=985, primary_control_gid=os.getgid(), supplementary_groups_empty=True,
                    all_capabilities_dropped=True, no_new_privileges=True, client_namespace=True, acquisition_parent_namespace=False)),
            "publish": dict(operation="offline_content_publish", network_publication=False,
                publisher_key_hex=publication["publisher_key"], content_type="application/json", chunks=1,
                **{k: publication[k] for k in ("name", "revision", "bytes", "manifest_id", "expires_unix_seconds")}),
            "cache-before": caches[key], "cache-after": caches[key],
        }
        files.update({"privacy-" + role: captured for role, captured in f["cold"]["privacy"].items()})
        for node in f["layout"]["provider_nodes"]:
            files[node + "-import"] = dict(f["imports"][node], manifest_id=publication["manifest_id"],
                content_bytes=publication["bytes"], agent_cache=str(work / f"state-{node}" / p["cache"]))
            files[node + "-serve"] = dict(f["serves"][node], publications=4 if key == "weather" else 5)
        for suffix, value in files.items(): save(A["artifact"](work, suffix, key), value)
    B = A["B"]
    profile = A["ui_profile"](version)
    fixed = {2: B["FIXED_V2"], 3: B["FIXED_V3"], 4: B["FIXED_V4"], 5: B["FIXED_V5"]}[version]
    static_files = B["STATIC_REQUIRED_V3"] if version in (3, 5) else {"index.html"}
    items = {name: dict(bytes=1, mode=B["mode"](name), sha256=SHA)
        for name in fixed | {profile["static"] + name for name in static_files}}
    for name, digest in (("runtime/node", B["NODE_SHA"]), ("decoder/grib_ls", B["decoder_sha"](version)),
            (B["WEATHER"]+"third_party/eccodes-sources.json", B["pin_sha"](version)),
            (B["WEATHER"]+B["build_source"](version), B["build_sha"](version))):
        items[name]["sha256"] = digest
    if version == 5:
        prefix = B["WEATHER"] + "integrations/overmorrow/"
        for name, value in (("hosted-browser-proof.json", "1"), ("smoke_browser.py", "2"),
                ("hosted-table-proof.json", "3"), ("smoke_table_browser.py", "4"),
                ("hosted-proof/historical-smoke_core_browser_v3.py", "5")):
            items[prefix + name]["sha256"] = value*64
    manifest = B["encode"](dict(version=version, kind=B["KIND"], files=items)); digest = hashlib.sha256(manifest).hexdigest()
    A["write_new"](A["artifact"](work, "manifest"), manifest, 0o400)
    for phase in ("before", "after"):
        common["tree-"+phase] = dict(version=1, action="verify-tree", manifest_sha256=digest, files=len(items), runtime_executed=False)
        common["cache-"+phase] = dict(schema=2, products=caches)
    browser = report(version); browser["source"]["bundle_manifest_sha256"] = digest
    browser["source"]["built_tree_sha256"] = hashlib.sha256(json.dumps(
        {name: SHA for name in static_files}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    common["original-report"] = browser
    save(work / "a01-expected-peers.json", f["expected_peers"]); save(work / "content-provider-layout.json", f["layout"])
    socket = work / "runtime-client/control/agent.sock"; socket.parent.mkdir(parents=True)
    A["write_new"](socket, b"inert stat-only fixture")
    for suffix, value in common.items(): save(A["artifact"](work, suffix), value)
    with fixture_admission(work, version), patch.dict(A["cold_evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
        save(A["artifact"](work, "cold-evidence"), A["cold_evidence"](work, digest, SHA))
    return digest, caches


def fixture_admission(work, version):
    if version not in (4, 5): return nullcontext()
    # This suite tests joining evidence, not actual public artifact admission.
    # Bundle tests separately reject unreviewed inventory and modified receipts.
    files = json.loads(A["artifact"](work, "manifest").read_text())["files"]
    admitted = {name: {key: value[key] for key in ("bytes", "sha256")} for name, value in files.items()}
    accessor = "public_admission" if version == 4 else "public_overmorrow_admission"
    return patch.dict(A["B"]["manifest"].__globals__, {accessor: lambda: dict(files=admitted)})


class Products(unittest.TestCase):
    def setUp(self):
        clock = patch.dict(A["prepare"].__globals__, observed_ms=lambda: CLOCK,
            source_observer=lambda: "file:///root-owned/bin/weather-source-observer.mjs")
        clock.start(); self.addCleanup(clock.stop)

    def test_profiles_and_browser_exports_never_accept_other_consumers(self):
        for version, consumer in ((2, "drizzli"), (3, "overmorrow"), (4, "drizzli"), (5, "overmorrow")):
            good = report(version)
            A["closed_report"](good)
            self.assertEqual(A["ui_profile"](version)["ui"], "actual_"+consumer+"_ui")
            for other in (1, 6, "3", "4", "5", True, *({2, 3, 4, 5} - {version})):
                bad = copy.deepcopy(good); bad["schema"] = other
                with self.subTest(version=version, other=other), self.assertRaises(ValueError): A["closed_report"](bad)
            bad = copy.deepcopy(good); bad["scope"]["arbitrary_ui"] = True
            with self.assertRaises(ValueError): A["closed_report"](bad)
        for version in (1, 6, "3", "4", "5", True, None):
            with self.assertRaises(ValueError): A["ui_profile"](version)

    def test_acquisition_receipt_requires_exact_decoder_and_manifest_profile(self):
        for version in (2, 3, 4, 5):
            good = acquisition(version)
            A["validate_acquisition"](good)
            A["validate_acquisition"](good, version)
            other = 2 if version in (4, 5) else 4
            with self.subTest(version=version), self.assertRaises(ValueError):
                A["validate_acquisition"](good, other)
            bad = copy.deepcopy(good); bad["decoder_sha256"] = A["B"]["decoder_sha"](other)
            with self.assertRaises(ValueError): A["validate_acquisition"](bad)
        for schema in (1, 3, 5, True, "4", None):
            bad = acquisition(4); bad["schema"] = schema
            with self.subTest(schema=schema), self.assertRaises(ValueError): A["validate_acquisition"](bad)

    def test_android_acquisition_is_separate_from_old_schema_and_browser_authority(self):
        good = acquisition(6)
        A["validate_acquisition"](good, 6)
        A["validate_acquisition"](good)
        for version in (1, 2, 3, 4, 5, True, "6"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                A["validate_acquisition"](good, version)
        for version in (2, 3, 4, 5):
            with self.subTest(old=version), self.assertRaises(ValueError):
                A["validate_acquisition"](acquisition(version), 6)
        with self.assertRaises(ValueError): A["ui_profile"](6)
        for version in (2, 3, 4, 5):
            bad = report(version); bad["schema"] = 6
            with self.assertRaises(ValueError): A["closed_report"](bad)
        for flag in ("synthetic_weather", "synthetic_air_quality", "upstream_signature_attested"):
            bad = copy.deepcopy(good); bad[flag] = True
            with self.assertRaises(ValueError): A["validate_acquisition"](bad, 6)

    def test_v4_full_join_binds_new_decoder_original_ui_proof_and_actual_products(self):
        for mutation in (None, "acquisition-schema", "acquisition-decoder", "cold-schema",
                "cold-decoder", "browser-schema", "proof-hash", "proof-driver", "proof-core",
                "weather-value", "air-quality-refresh"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, caches = joined_fixture(work, 4)
                if mutation:
                    suffix = "acquisition" if mutation.startswith("acquisition-") else \
                        "cold-evidence" if mutation.startswith("cold-") else "original-report"
                    path = A["artifact"](work, suffix); value = A["read"](path)
                    if mutation.endswith("schema"): value["schema"] = 2
                    elif mutation.endswith("decoder"): value["decoder_sha256"] = A["B"]["DECODER_SHA"]
                    elif mutation == "proof-hash": value["source"]["synthetic_ui_proof"]["sha256"] = "f"*64
                    elif mutation == "proof-driver": value["source"]["synthetic_ui_proof"]["driver_sha256"] = "f"*64
                    elif mutation == "proof-core": value["source"]["synthetic_ui_proof"]["core_executed"] = True
                    elif mutation == "weather-value": value["products"]["weather"]["checks"]["exact_native_times_and_values"] = False
                    else: value["products"]["air_quality"]["checks"]["refresh_dom_display_sha256"] = "f"*64
                    path.unlink(); save(path, value)
                with fixture_admission(work, 4), patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                    if mutation:
                        with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)
                    else:
                        proof = A["evidence"](work, digest, SHA); A["validate_evidence_export"](proof)
                        self.assertEqual(proof["schema"], 4)
                        self.assertEqual(proof["decoder_sha256"], A["B"]["decoder_sha"](4))
                        self.assertTrue(proof["scope"]["actual_drizzli_ui"])
                        self.assertFalse(proof["scope"]["browser_triggered_cold_fetch"])
                        bad = copy.deepcopy(proof); bad["schema"] = 2
                        with self.assertRaises(ValueError): A["validate_evidence_export"](bad)

    def test_android_schema_cannot_relabel_historical_cold_evidence(self):
        for version in (2, 3, 4, 5):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                joined_fixture(work, version)
                good = A["read"](A["artifact"](work, "cold-evidence"))
                A["validate_cold_export"](good)
                A["validate_export"]("cold-evidence", good)
                for schema in (6, "6", True):
                    bad = copy.deepcopy(good); bad["schema"] = schema
                    with self.assertRaises(ValueError): A["validate_cold_export"](bad)
                    with self.assertRaises(ValueError): A["validate_export"]("cold-evidence", bad)
        # Reject the unsupported consumer before reading any synthetic receipts.
        with self.assertRaises(ValueError):
            A["cold_summary"](selected(), acquisition(6), {}, SHA, SHA, 6)

    def test_v5_full_join_binds_both_original_proofs_without_upgrading_synthetic_scope(self):
        mutations = [(None, (), None),
            ("acquisition", ("schema",), 2), ("cold-evidence", ("schema",), 5),
            ("acquisition", ("decoder_sha256",), A["B"]["DECODER_SHA"]),
            ("cold-evidence", ("decoder_sha256",), A["B"]["DECODER_SHA"]),
            ("original-report", ("schema",), 3),
            ("original-report", ("products", "weather", "checks", "exact_native_times_and_values"), False),
            ("original-report", ("products", "air_quality", "checks", "refresh_dom_display_sha256"), "f"*64),
            ("original-report", ("products", "air_quality", "expected", "cold_receipt_sha256"), "f"*64),
            ("original-report", ("source", "synthetic_ui_proof", "sha256"), "3"*64),
            ("original-report", ("source", "synthetic_table_proof", "sha256"), "1"*64)]
        for proof in ("synthetic_ui_proof", "synthetic_table_proof"):
            fields = ("sha256", "driver_sha256", "verifier_sha256") if proof == "synthetic_table_proof" else ("sha256", "driver_sha256")
            mutations.extend(("original-report", ("source", proof, field), "f"*64) for field in fields)
            mutations.extend(("original-report", ("source", proof, field), True)
                for field in ("core_executed", "overlay_proven"))
            mutations.append(("original-report", ("source", proof, "unexpected"), "not admitted"))
        for suffix, fields, replacement in mutations:
            with self.subTest(suffix=suffix, fields=fields, replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, caches = joined_fixture(work, 5)
                if suffix:
                    path = A["artifact"](work, suffix); value = A["read"](path); target = value
                    for field in fields[:-1]: target = target[field]
                    target[fields[-1]] = replacement
                    path.unlink(); save(path, value)
                with fixture_admission(work, 5), patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                    if suffix:
                        with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)
                    else:
                        cold = A["read"](A["artifact"](work, "cold-evidence"))
                        self.assertEqual(cold["schema"], 4)
                        self.assertFalse(cold["scope"]["end_to_end_proven"])
                        proof = A["evidence"](work, digest, SHA); A["validate_evidence_export"](proof)
                        self.assertEqual(proof["schema"], 5)
                        self.assertEqual(proof["decoder_sha256"], A["B"]["decoder_sha"](5))
                        self.assertTrue(proof["scope"]["actual_overmorrow_ui"])
                        self.assertNotIn("actual_drizzli_ui", proof["scope"])
                        self.assertFalse(proof["scope"]["browser_triggered_cold_fetch"])
                        for wrong in (2, 3, 4, "5", True):
                            bad = copy.deepcopy(proof); bad["schema"] = wrong
                            with self.assertRaises(ValueError): A["validate_evidence_export"](bad)

    def test_v5_acquisition_keeps_public_decoder_schema_four_and_independent_deadline(self):
        self.check_acquisition(5)

    def test_v6_acquisition_runs_only_sources_with_its_own_schema_and_shared_deadline(self):
        self.check_acquisition(6)

    def check_acquisition(self, version):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
            source = base / "inputs"; source.mkdir(mode=0o700)
            A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
            calls = []
            def execute(command, cwd, maximum, timeout):
                calls.append((command, timeout))
                if command[-1] == "-V": return b"ecCodes Version 2.44.0\n"
                key = "weather" if command[4].endswith("/forecast.mjs") else "air_quality"
                self.assertEqual(command[command.index("--decoder-sha256")+1], A["B"]["decoder_sha"](version))
                return json.dumps(forecast(key, command[command.index("--run")+1], version=version)).encode()
            with patch.dict(A["acquisition"].__globals__, run=execute, boundary=lambda *args: None), \
                    patch.dict(A["B"], verify_tree=lambda *args: None, manifest=lambda *args: {"version": version}), \
                    patch.object(A["time"], "time", return_value=CLOCK/1000), \
                    patch.object(A["time"], "monotonic", side_effect=[100, 120, 480]):
                value = A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
            A["validate_acquisition"](value, version)
            self.assertEqual(value["schema"], 6 if version == 6 else 4)
            self.assertEqual([timeout for _, timeout in calls], [10, 360, 340])
            self.assertNotEqual(value["products"]["weather"]["forecast_sha256"], value["products"]["air_quality"]["forecast_sha256"])

    def test_v5_preparer_requires_explicit_profile_and_exact_new_expected_schema(self):
        for expected_version in (2, 3, 4, 5, True, "5"):
            with self.subTest(expected_version=expected_version), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary); viewer = base / "weather-viewer"; viewer.mkdir(mode=0o700)
                selection, forecasts = prepare_fixture(viewer, 5)
                def execute(command, cwd, maximum, timeout):
                    self.assertTrue(command[2].endswith("integrations/overmorrow/prepare_core_browser.mjs"))
                    self.assertEqual(command[-2:], ["--bundle-version", "5"])
                    expected = dict(schema=expected_version, core_sha256=SHA, display_sha256=SHA,
                        products={key: dict(publication=value["publication"], forecast=forecasts[key])
                            for key, value in selection["products"].items()})
                    raw = A["B"]["encode"](expected); A["write_new"](viewer / "expected.json", raw, 0o400)
                    return json.dumps(dict(prepared=True, expected_sha256=hashlib.sha256(raw).hexdigest(), display_sha256=SHA)).encode()
                with patch.dict(A["prepare"].__globals__, run=execute), patch.dict(A["B"], fingerprint=lambda *args: {"sha256": SHA}):
                    args = (base / "source", viewer, base / "binary", base / "agent.sock",
                        base / "state-client/weather-cache", base / "state-client/air-quality-cache", 5)
                    if type(expected_version) is int and expected_version == 5:
                        self.assertTrue(A["prepare"](*args)["prepared"])
                    else:
                        with self.assertRaises(ValueError): A["prepare"](*args)

    def test_v4_acquisition_uses_new_decoder_and_keeps_two_product_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
            source = base / "inputs"; source.mkdir(mode=0o700)
            A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
            calls = []
            def execute(command, cwd, maximum, timeout):
                calls.append((command, timeout))
                if command[-1] == "-V": return b"ecCodes Version 2.44.0\n"
                key = "weather" if command[4].endswith("/forecast.mjs") else "air_quality"
                self.assertEqual(command[command.index("--decoder-sha256")+1], A["B"]["decoder_sha"](4))
                return json.dumps(forecast(key, command[command.index("--run")+1], version=4)).encode()
            with patch.dict(A["acquisition"].__globals__, run=execute, boundary=lambda *args: None), \
                    patch.dict(A["B"], verify_tree=lambda *args: None, manifest=lambda *args: {"version": 4}), \
                    patch.object(A["time"], "time", return_value=CLOCK/1000), \
                    patch.object(A["time"], "monotonic", side_effect=[100, 120, 480]):
                value = A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
            A["validate_acquisition"](value, 4)
            self.assertEqual(value["schema"], 4)
            self.assertEqual([timeout for _, timeout in calls], [10, 360, 340])

    def test_v4_preparer_passes_explicit_profile_and_rejects_legacy_result(self):
        for expected_version in (2, 3, 4, True, "4"):
            with self.subTest(expected_version=expected_version), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary); viewer = base / "weather-viewer"; viewer.mkdir(mode=0o700)
                selection, forecasts = prepare_fixture(viewer)
                def execute(command, cwd, maximum, timeout):
                    self.assertTrue(command[2].endswith("integrations/drizzli/prepare-core-browser.mjs"))
                    self.assertEqual(command[-2:], ["--bundle-version", "4"])
                    expected = dict(schema=expected_version, core_sha256=SHA, display_sha256=SHA,
                        products={key: dict(publication=value["publication"], forecast=forecasts[key])
                            for key, value in selection["products"].items()})
                    raw = A["B"]["encode"](expected); A["write_new"](viewer / "expected.json", raw, 0o400)
                    return json.dumps(dict(prepared=True, expected_sha256=hashlib.sha256(raw).hexdigest(), display_sha256=SHA)).encode()
                with patch.dict(A["prepare"].__globals__, run=execute), patch.dict(A["B"], fingerprint=lambda *args: {"sha256": SHA}):
                    args = (base / "source", viewer, base / "binary", base / "agent.sock",
                        base / "state-client/weather-cache", base / "state-client/air-quality-cache", 4)
                    if type(expected_version) is int and expected_version == 4:
                        self.assertTrue(A["prepare"](*args)["prepared"])
                    else:
                        with self.assertRaises(ValueError): A["prepare"](*args)

    def test_overmorrow_full_join_is_bound_to_profile_three_and_cold_products(self):
        mutations = [None, ("schema",), ("scope", "actual_overmorrow_ui"),
            ("source", "driver_sha256"), ("source", "preparer_sha256"), ("source", "built_tree_sha256"),
            ("products", "weather", "checks", "exact_native_times_and_values"),
            ("products", "air_quality", "checks", "refresh_dom_display_sha256"),
            ("products", "air_quality", "expected", "cold_receipt_sha256")]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, caches = joined_fixture(work, 3)
                if mutation:
                    path = A["artifact"](work, "original-report"); value = A["read"](path); target = value
                    for key in mutation[:-1]: target = target[key]
                    target[mutation[-1]] = (2 if mutation == ("schema",) else
                        False if type(target[mutation[-1]]) is bool else "f"*64)
                    if mutation == ("schema",):
                        value["scope"]["actual_drizzli_ui"] = value["scope"].pop("actual_overmorrow_ui")
                    path.unlink(); save(path, value)
                with patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                    if mutation:
                        with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)
                    else:
                        proof = A["evidence"](work, digest, SHA); A["validate_evidence_export"](proof)
                        self.assertEqual(proof["schema"], 3)
                        self.assertTrue(proof["scope"]["actual_overmorrow_ui"])
                        self.assertNotIn("actual_drizzli_ui", proof["scope"])
                        self.assertFalse(proof["scope"]["browser_triggered_cold_fetch"])
                        bad = copy.deepcopy(proof); bad["schema"] = 2
                        with self.assertRaises(ValueError): A["validate_evidence_export"](bad)

    def test_acquisition_diagnoses_every_stage_without_error_details(self):
        for failed_stage in A["ACQUISITION_STAGES"]:
            with self.subTest(stage=failed_stage), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
                source = base / "inputs"; source.mkdir(mode=0o700)
                A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
                def gate(stage):
                    if failed_stage == stage: raise ValueError("SECRET URL coordinates and path")
                def execute(command, cwd, maximum, timeout):
                    if command[-1] == "-V":
                        gate("decoder"); return b"ecCodes Version 2.44.0\n"
                    key = "weather" if command[4].endswith("/forecast.mjs") else "air_quality"
                    gate(A["PRODUCTS"][key]["suffix"] + "-run")
                    if failed_stage == A["PRODUCTS"][key]["suffix"] + "-validation": return b'{"SECRET":'
                    return json.dumps(forecast(key, command[command.index("--run")+1])).encode()
                with patch.dict(A["acquisition"].__globals__, run=execute,
                        private=lambda *args, **kwargs: gate("preconditions"),
                        boundary=lambda *args: gate("boundary"),
                        validate_acquisition=lambda *args: gate("final-validation")), \
                        patch.dict(A["B"], verify_tree=lambda *args: gate("tree"), manifest=lambda *args: {"version": 2}), \
                        patch.object(A["time"], "time", return_value=CLOCK // 1000):
                    with self.assertRaises(A["AcquisitionFailure"]) as raised:
                        A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
                value = raised.exception.diagnostic
                A["validate_acquisition_diagnostic"](value)
                self.assertEqual(value["stage"], failed_stage)
                self.assertNotIn("SECRET", json.dumps(value))
                self.assertNotIn(str(base), json.dumps(value))

    def test_acquisition_failure_classification_does_not_leak_subprocess_arguments(self):
        cases = [(FileNotFoundError("SECRET path"), "missing-input"),
            (PermissionError("SECRET path"), "permission-denied"), (OSError("SECRET"), "io-failed"),
            (subprocess.TimeoutExpired(["SECRET", "URL"], 1, output=b"SECRET"), "timeout"),
            (subprocess.CalledProcessError(7, ["SECRET"], stderr=b"SECRET"), "process-failed"),
            (ValueError("SECRET"), "check-or-execution-failed")]
        for error, expected in cases:
            with self.subTest(expected=expected):
                value = A["AcquisitionFailure"]("air-quality-run", error).diagnostic
                A["validate_acquisition_diagnostic"](value)
                self.assertEqual(value["failure"], expected); self.assertNotIn("SECRET", json.dumps(value))
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, str(HERE / "weather-products-delivery.py"), "acquire",
                temporary, SHA, str(Path(temporary) / "missing-private-path"), "net:[1]", "net:[2]", "1000"],
                capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            value = json.loads(result.stdout); A["validate_acquisition_diagnostic"](value)
            self.assertEqual(value["stage"], "preconditions"); self.assertEqual(result.stderr, b"")
            self.assertNotIn(temporary.encode(), result.stdout)

    def test_source_response_schema_preserves_bounded_advice_without_retry_authority(self):
        for key in A["PRODUCTS"]:
            good = source_response(key)
            A["validate_source_response"](good, key, (CLOCK, CLOCK))
            for state in ("missing", "malformed", "out-of-range"):
                A["validate_source_response"](dict(good, retry_after_state=state, retry_not_before_ms=None), key)
            for until in (0, -1000, -A["MAX_SOURCE_EPOCH_MS"], CLOCK+A["MAX_RETRY_ADVICE_MS"]):
                A["validate_source_response"](dict(good, retry_after_state="valid-date", retry_not_before_ms=until), key)
            for delay in (0, A["MAX_RETRY_ADVICE_MS"]):
                A["validate_source_response"](dict(good, retry_not_before_ms=CLOCK+delay), key)
            bad_values = [dict(good, schema=True), dict(good, status=True), dict(good, status=503),
                dict(good, product="wrong"), dict(good, raw_headers="SECRET"), dict(good, url="SECRET"),
                dict(good, observed_at_ms=True), dict(good, observed_at_ms=-1),
                dict(good, observed_at_ms=A["MAX_SOURCE_EPOCH_MS"]+1), dict(good, retry_after_state=[]),
                dict(good, retry_after_state="retry"), dict(good, retry_after_state="missing"),
                dict(good, retry_not_before_ms=None), dict(good, retry_not_before_ms=True),
                dict(good, retry_not_before_ms=CLOCK-1000), dict(good, retry_not_before_ms=CLOCK+1),
                dict(good, retry_not_before_ms=CLOCK+A["MAX_RETRY_ADVICE_MS"]+1000),
                dict(good, retry_after_state="valid-date", retry_not_before_ms=-1001),
                dict(good, retry_after_state="valid-date", retry_not_before_ms=-A["MAX_SOURCE_EPOCH_MS"]-1000)]
            for bad in bad_values:
                with self.subTest(bad=bad), self.assertRaises(ValueError): A["validate_source_response"](bad, key)
            for window in ((CLOCK+1, CLOCK+2), (CLOCK-2, CLOCK-1), (CLOCK+1, CLOCK), (True, CLOCK)):
                with self.subTest(window=window), self.assertRaises(ValueError):
                    A["validate_source_response"](good, key, window)

    def test_source_sidecar_requires_private_bounded_unique_current_product_record(self):
        cases = ("valid", "missing", "mode", "link", "hardlink", "directory", "oversize", "empty",
            "duplicate", "wrong-product", "old", "future", "raw-field", "owner", "clock-backward")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); path = root / A["SOURCE_SIDECARS"]["weather"]
                value = source_response()
                if case == "wrong-product": value["product"] = "air_quality"
                elif case == "old": value["observed_at_ms"] -= 1
                elif case == "future": value["observed_at_ms"] += 1
                elif case == "raw-field": value["url"] = "SECRET"
                if case == "link": path.symlink_to(root / "absent")
                elif case == "directory": path.mkdir(mode=0o700)
                elif case != "missing":
                    raw = b"x" * 1025 if case == "oversize" else b"" if case == "empty" else \
                        b'{"schema":1,"schema":1}' if case == "duplicate" else A["B"]["encode"](value)
                    A["write_new"](path, raw, 0o644 if case == "mode" else 0o600)
                    if case == "hardlink": os.link(path, root / "second-link")
                with patch.object(A["os"], "getuid", return_value=os.getuid()+1) if case == "owner" else \
                        patch.dict(A["source_response"].__globals__, observed_ms=lambda: CLOCK):
                    state, result = A["source_response"](root, "weather", CLOCK,
                        CLOCK-1 if case == "clock-backward" else CLOCK)
                self.assertEqual(state, "valid" if case == "valid" else "missing" if case == "missing" else "invalid")
                self.assertEqual(result, value if case == "valid" else None)
                self.assertEqual(A["source_response"](root, "weather", None, None), ("missing", None))

    def test_observer_requires_fixed_root_owned_readonly_single_link_core_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / "weather-source-observer.mjs"
            target.touch()
            for mode, owner, links, valid in ((0o100555, 0, 1, True), (0o100755, 0, 1, False),
                    (0o100555, 1000, 1, False), (0o100555, 0, 2, False), (0o040555, 0, 1, False)):
                info = SimpleNamespace(st_mode=mode, st_uid=owner, st_nlink=links)
                with patch.dict(A["source_observer"].__globals__, HERE=root), \
                        patch.object(Path, "lstat", return_value=info), \
                        patch.dict(A["B"]["B"], canonical=lambda path: self.assertEqual(path, target)), \
                        patch.dict(A["source_observer"].__globals__, raw_file=lambda path, maximum, mode:
                            self.assertEqual((path, maximum, mode), (target, 64*1024, 0o555))):
                    if valid: self.assertEqual(A["source_observer"](), target.as_uri())
                    else:
                        with self.assertRaises(ValueError): A["source_observer"]()

    def test_failure_diagnostics_keep_historical_v2_distinct_from_new_source_metadata(self):
        old = diagnostic(); old["schema"] = 2
        del old["source_response_state"]; del old["source_response"]
        A["validate_acquisition_diagnostic"](old)
        value = dict(diagnostic(), source_response_state="valid", source_response=source_response())
        A["validate_acquisition_diagnostic"](value)
        for bad in (dict(old, source_response=None), dict(old, schema=3), dict(value, schema=2),
                dict(value, source_response_state="missing"), dict(value, source_response_state=[]),
                dict(value, stage="decoder", product=None), dict(value, product="air_quality")):
            with self.subTest(bad=bad), self.assertRaises(ValueError): A["validate_acquisition_diagnostic"](bad)
        for inner in (old, value):
            with tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); failure_fixture(work, A["B"]["encode"](inner))
                output = work / "output"; output.mkdir()
                status = A["copy_failure_artifacts"](work, output, os.getuid(), os.getgid())
                self.assertTrue(status["success"])
                retained = A["read"](A["artifact"](output, "acquisition-failure"))
                self.assertEqual(retained["schema"], 2); self.assertEqual(retained["diagnostic"], inner)
                self.assertFalse(any(path.name in A["SOURCE_SIDECARS"].values() for path in output.iterdir()))

    def test_acquisition_failure_binds_only_actual_failing_subprocess_observation(self):
        for failed_key, sidecar_key, observed, expected in (("weather", "weather", CLOCK, "valid"),
                ("air_quality", "air_quality", CLOCK, "valid"), ("air_quality", "weather", CLOCK, "missing"),
                ("weather", "weather", CLOCK-1, "invalid"), ("weather", "weather", CLOCK+1, "invalid")):
            with self.subTest(failed_key=failed_key, sidecar_key=sidecar_key, observed=observed), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
                source = base / "inputs"; source.mkdir(mode=0o700)
                A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
                def execute(command, cwd, maximum, timeout):
                    if command[-1] == "-V": return b"ecCodes Version 2.44.0\n"
                    key = command[3].split("?product=")[1]
                    if key == failed_key:
                        save(root / A["SOURCE_SIDECARS"][sidecar_key], source_response(sidecar_key, observed))
                        raise ValueError("PRIVATE source response and URL")
                    return json.dumps(forecast(key, command[command.index("--run")+1])).encode()
                with patch.dict(A["acquisition"].__globals__, run=execute, boundary=lambda *args: None), \
                        patch.dict(A["B"], verify_tree=lambda *args: None, manifest=lambda *args: {"version": 3}), \
                        patch.object(A["time"], "time", return_value=CLOCK//1000):
                    with self.assertRaises(A["AcquisitionFailure"]) as raised:
                        A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
                value = raised.exception.diagnostic; A["validate_acquisition_diagnostic"](value)
                self.assertEqual(value["source_response_state"], expected)
                self.assertEqual(value["product"], failed_key); self.assertNotIn("PRIVATE", json.dumps(value))
                self.assertEqual(value["source_response"], source_response(sidecar_key, observed) if expected == "valid" else None)

    def test_preexisting_product_sidecar_prevents_child_and_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
            source = base / "inputs"; source.mkdir(mode=0o700)
            A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
            calls = []
            def execute(command, *args):
                calls.append(command)
                save(root / A["SOURCE_SIDECARS"]["weather"], source_response())
                return b"ecCodes Version 2.44.0\n"
            with patch.dict(A["acquisition"].__globals__, run=execute, boundary=lambda *args: None), \
                    patch.dict(A["B"], verify_tree=lambda *args: None, manifest=lambda *args: {"version": 3}):
                with self.assertRaises(A["AcquisitionFailure"]) as raised:
                    A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
            self.assertEqual(len(calls), 1)
            self.assertEqual(raised.exception.diagnostic["source_response_state"], "missing")
            self.assertEqual(raised.exception.diagnostic["stage"], "weather-run")

    def test_retained_acquisition_failures_are_closed_and_not_success_claims(self):
        cases = [(None, "missing"), (b"", "missing"), (b'{"secret":', "invalid"),
            (A["B"]["encode"](acquisition()), "invalid"),
            (A["B"]["encode"](dict(diagnostic(), stderr="SECRET")), "invalid"),
            (A["B"]["encode"](dict(diagnostic(), product="air_quality")), "invalid"),
            (A["B"]["encode"](diagnostic()), "valid")]
        for raw, state in cases:
            with self.subTest(state=state, raw=raw), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                if raw is not None: A["write_new"](A["artifact"](work, "acquisition"), raw)
                value = A["retain_acquisition_failure"](work, 124)
                A["validate_acquisition_failure"](value)
                self.assertEqual(value["diagnostic_state"], state)
                self.assertEqual(value["command_exit_status"], 124)
                self.assertNotIn("SECRET", json.dumps(value))
                with self.assertRaises(ValueError): A["validate_acquisition"](value)
                for status in (0, True, -1, 256):
                    with self.assertRaises(ValueError): A["retain_acquisition_failure"](work, status)
        mutations = [dict(diagnostic(), success=True), dict(diagnostic(), coordinates=[52.52, 13.41]),
            dict(diagnostic(), stage="private URL"), dict(diagnostic(), failure="raw stderr")]
        for value in mutations:
            with self.assertRaises(ValueError): A["validate_acquisition_diagnostic"](value)

    def test_dedicated_failure_export_retains_valid_siblings_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); failure_fixture(work)
            output = work / "output"; output.mkdir()
            A["write_new"](work / "raw-private.log", b"SECRET")
            for _ in range(2):
                result = A["copy_failure_artifacts"](work, output, os.getuid(), os.getgid())
                A["validate_failure_export_status"](result); self.assertTrue(result["success"])
                self.assertEqual(result["exported"], list(A["FAILURE_EXPORTS"]))
            self.assertEqual({path.name for path in output.iterdir()},
                {A["artifact"](output, suffix).name for suffix in (*A["FAILURE_EXPORTS"], "export-status")})
            self.assertFalse(A["artifact"](output, "acquisition").exists())

    def test_failure_export_retains_safe_siblings_but_exits_nonzero_for_rejected_evidence(self):
        for bad in ("acquisition", "tree-before", "input-cleanup"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); failure_fixture(work, b"" if bad == "acquisition" else None)
                if bad != "acquisition":
                    source = A["artifact"](work, bad); source.unlink(); save(source, dict(raw="SECRET"))
                output = work / "output"; output.mkdir()
                result = subprocess.run([sys.executable, str(HERE / "weather-products-delivery.py"),
                    "copy-failure-artifacts", str(work), str(output), str(os.getuid()), str(os.getgid())],
                    capture_output=True, check=False)
                self.assertEqual(result.returncode, 1); self.assertEqual(result.stderr, b"")
                status = A["read"](A["artifact"](output, "export-status"))
                A["validate_failure_export_status"](status)
                self.assertFalse(status["success"]); self.assertEqual(status["rejected"], [bad])
                self.assertEqual(json.loads(result.stdout), status)
                for suffix in status["exported"]: self.assertTrue(A["artifact"](output, suffix).exists())
                for path in output.iterdir(): self.assertNotIn(b"SECRET", path.read_bytes())
                self.assertFalse(A["artifact"](output, bad).exists())

    def test_failure_export_rejects_unsafe_or_forged_marker_before_writing(self):
        for bad in ("missing", "symlink", "mode", "success", "raw-field", "status", "duplicate"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); value = failure_fixture(work); marker = A["artifact"](work, "acquisition-failure")
                marker.unlink()
                if bad == "symlink": marker.symlink_to(A["artifact"](work, "acquisition"))
                elif bad != "missing":
                    if bad == "success": value["success"] = True
                    elif bad == "raw-field": value["raw"] = "SECRET"
                    elif bad == "status": value["command_exit_status"] = 0
                    if bad == "duplicate": A["write_new"](marker, b'{"schema":2,"schema":2}')
                    else: save(marker, value, 0o644 if bad == "mode" else 0o600)
                output = work / "output"; output.mkdir()
                with self.assertRaises((ValueError, OSError)): A["copy_failure_artifacts"](work, output, os.getuid(), os.getgid())
                self.assertEqual(list(output.iterdir()), [])

    def test_acquisition_commands_include_precipitation_and_independent_noaa_cycle_with_one_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
            source = base / "inputs"; source.mkdir(mode=0o700)
            A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
            calls = []
            def execute(command, cwd, maximum, timeout):
                calls.append((command, timeout))
                if command[-1] == "-V": return b"ecCodes Version 2.44.0\n"
                key = "weather" if command[4].endswith("/forecast.mjs") else "air_quality"
                return json.dumps(forecast(key, command[command.index("--run")+1])).encode()
            clock = datetime.datetime(2026, 10, 11, 14, tzinfo=datetime.timezone.utc).timestamp()
            with patch.dict(A["acquisition"].__globals__, run=execute, boundary=lambda *args: None), \
                    patch.dict(A["B"], verify_tree=lambda *args: None, manifest=lambda *args: {"version": 2}), \
                    patch.object(A["time"], "time", return_value=clock), \
                    patch.object(A["time"], "monotonic", side_effect=[100, 120, 480]):
                result = A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
            A["validate_acquisition"](result)
            weather, aq = calls[1][0], calls[2][0]
            for key, command in (("weather", weather), ("air_quality", aq)):
                self.assertEqual(command[1:4], ["--max-old-space-size=256", "--import",
                    "file:///root-owned/bin/weather-source-observer.mjs?product=" + key])
                self.assertEqual(command[4], str(source / A["B"]["WEATHER"] / "scripts" / A["PRODUCTS"][key]["script"]))
            self.assertIn("--include-precipitation", weather); self.assertNotIn("--include-precipitation", aq)
            self.assertEqual(weather[weather.index("--run")+1], "2026-10-11T00:00:00.000Z")
            self.assertEqual(aq[aq.index("--run")+1], "2026-10-11T00:00:00.000Z")
            # Same cycle time is permissible when independently selected;
            # unlike their native samples, the times need not differ by force.
            self.assertEqual(weather[weather.index("--steps")+1], "3,9,24,48")
            self.assertEqual(aq[aq.index("--steps")+1], "3,6,12,24,48")
            self.assertEqual([call[1] for call in calls], [10, 360, 340])
            self.assertTrue((root / "forecast.json").exists()); self.assertTrue((root / "air-quality.json").exists())

    def test_acquisition_preserves_future_native_coverage_across_midnight_and_noon(self):
        cases = [
            ("2026-10-10T23:59:59.999Z", "2026-10-10T00:00:00.000Z", "2026-10-10T00:00:00.000Z"),
            ("2026-10-11T00:00:00.000Z", "2026-10-10T12:00:00.000Z", "2026-10-10T00:00:00.000Z"),
            ("2026-10-11T11:59:59.999Z", "2026-10-10T12:00:00.000Z", "2026-10-10T00:00:00.000Z"),
            ("2026-10-11T12:00:00.000Z", "2026-10-11T00:00:00.000Z", "2026-10-11T00:00:00.000Z"),
        ]
        for when, weather_run, aq_run in cases:
            with self.subTest(when=when), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary); root = base / "weather-publisher"; root.mkdir(mode=0o700)
                source = base / "inputs"; source.mkdir(mode=0o700)
                A["initialize"](root); A["write_new"](source / "INPUTS.json", b"fixture", 0o400)
                started, received = A["stamp"](when), []
                def execute(command, cwd, maximum, timeout):
                    if command[-1] == "-V": return b"ecCodes Version 2.44.0\n"
                    key = "weather" if command[4].endswith("/forecast.mjs") else "air_quality"
                    value = forecast(key, command[command.index("--run")+1], iso(started + 2000))
                    received.append(value); return json.dumps(value).encode()
                with patch.dict(A["acquisition"].__globals__, run=execute, boundary=lambda *args: None,
                        observed_ms=lambda: started + 2000), \
                        patch.dict(A["B"], verify_tree=lambda *args: None, manifest=lambda *args: {"version": 2}), \
                        patch.object(A["time"], "time", return_value=started / 1000), \
                        patch.object(A["time"], "monotonic", side_effect=[100, 120, 480]):
                    A["acquisition"](source, SHA, root, "net:[1]", "net:[2]", 1000)
                self.assertEqual([v["source"]["model_run_at"] for v in received], [weather_run, aq_run])
                for value in received:
                    self.assertGreater(A["stamp"](value["samples"][-1]["valid_at"]), started + 2000)
                    self.assertLess(A["stamp"](value["samples"][0]["valid_at"]), started + 2000)

    def test_utc_timestamps_require_real_dates_and_preserve_exact_milliseconds(self):
        self.assertEqual(A["stamp"]("2026-10-11T14:00:00.001Z"), CLOCK + 1)
        for value in (None, True, "2026-02-30T00:00:00.000Z", "2026-10-11T24:00:00.000Z",
                "2026-10-11T14:00:00Z", "2026-10-11T14:00:00.000+00:00", "2026-10-11T14:00:00.0000Z"):
            with self.subTest(value=value), self.assertRaises(ValueError): A["stamp"](value)
        for key, value in (("weather", "2026-02-30T00:00:00.000Z"), ("weather", "2026-10-11T06:00:00.000Z"),
                ("air_quality", "2026-10-11T12:00:00.000Z")):
            bad = selected(); bad["products"][key]["query"]["run"] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): A["validate_selection"](bad)

    def test_forecast_times_bind_acquisition_window_native_leads_and_future_coverage(self):
        for key in A["PRODUCTS"]:
            good = forecast(key); model_run = good["source"]["model_run_at"]
            A["forecast_times"](good, key, model_run, CLOCK, (CLOCK, CLOCK))
            mutations = [(("kind",), "observation"), (("source", "model_run_at"), iso(CLOCK)),
                (("source", "acquired_at"), iso(A["stamp"](model_run)-1)),
                (("source", "acquired_at"), iso(CLOCK+1)),
                (("samples", 0, "valid_at"), iso(A["stamp"](good["samples"][0]["valid_at"])+1)),
                (("samples", 0, "lead_hours"), True),
                (("samples", -1, "valid_at"), iso(CLOCK+1))]
            for keys, changed in mutations:
                value = copy.deepcopy(good); target = value
                for part in keys[:-1]: target = target[part]
                target[keys[-1]] = changed
                with self.subTest(key=key, mutation=keys), self.assertRaises(ValueError):
                    A["forecast_times"](value, key, model_run, CLOCK)
            backdated = copy.deepcopy(good); backdated["source"]["acquired_at"] = iso(CLOCK-1)
            with self.assertRaises(ValueError): A["forecast_times"](backdated, key, model_run, CLOCK, (CLOCK, CLOCK))
            with self.assertRaises(ValueError): A["forecast_times"](good, key, model_run, CLOCK, (CLOCK+1, CLOCK))
            last = A["stamp"](good["samples"][-1]["valid_at"])
            A["forecast_times"](good, key, model_run, last-1)
            for observed in (last, last+1):
                with self.subTest(key=key, observed=observed), self.assertRaises(ValueError):
                    A["forecast_times"](good, key, model_run, observed)
            query = A["fixed_query"](key, model_run)
            with self.assertRaises(ValueError): A["future_query"](key, query, A["stamp"](model_run)-1)

    def test_preparer_uses_both_receipts_and_separate_caches(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); viewer = base / "weather-viewer"; viewer.mkdir(mode=0o700)
            selection, forecasts = prepare_fixture(viewer)
            def execute(command, cwd, maximum, timeout):
                self.assertEqual(command[command.index("--air-quality")+1], str(viewer / "air-quality.json"))
                self.assertEqual(command[command.index("--air-quality-receipt")+1], str(viewer / "air-quality-cold-receipt.json"))
                config = A["read"](viewer / "config.json")
                self.assertNotEqual(config["core"]["cache"], config["airQuality"]["core"]["cache"])
                self.assertEqual(config["core"]["scratchParent"], config["airQuality"]["core"]["scratchParent"])
                self.assertTrue(config["core"]["query"]["includePrecipitation"])
                expected = dict(schema=2, core_sha256=SHA, display_sha256=SHA,
                    products={key: dict(publication=value["publication"], forecast=forecasts[key])
                        for key, value in selection["products"].items()})
                raw = A["B"]["encode"](expected); A["write_new"](viewer / "expected.json", raw, 0o400)
                return json.dumps(dict(prepared=True, expected_sha256=hashlib.sha256(raw).hexdigest(), display_sha256=SHA)).encode()
            with patch.dict(A["prepare"].__globals__, run=execute), patch.dict(A["B"], fingerprint=lambda *args: {"sha256": SHA}):
                result = A["prepare"](base / "source", viewer, base / "binary", base / "agent.sock",
                    base / "state-client/weather-cache", base / "state-client/air-quality-cache")
            self.assertTrue(result["prepared"])

    def test_preparer_rejects_unbound_cold_bytes_expected_forecast_and_exhausted_future(self):
        for key in A["PRODUCTS"]:
            for fault in ("length", "hash", "expected", "future"):
                with self.subTest(key=key, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    base = Path(temporary); viewer = base / "weather-viewer"; viewer.mkdir(mode=0o700)
                    selection, forecasts = prepare_fixture(viewer)
                    if fault in ("length", "hash"):
                        path = viewer / A["PRODUCTS"][key]["filename"]
                        raw = A["B"]["encode"](forecasts[key])
                        altered = raw + b" " if fault == "length" else raw.replace(b"2026-10-10", b"2026-10-09", 1)
                        self.assertNotEqual(raw, altered)
                        if fault == "hash": self.assertEqual(len(raw), len(altered))
                        path.unlink(); A["write_new"](path, altered)
                    if fault == "expected": forecasts[key]["source"]["acquired_at"] = iso(CLOCK-1)
                    observed = A["stamp"](forecasts[key]["samples"][-1]["valid_at"]) if fault == "future" else CLOCK
                    def execute(command, cwd, maximum, timeout):
                        expected = dict(schema=2, core_sha256=SHA, display_sha256=SHA,
                            products={name: dict(publication=value["publication"], forecast=forecasts[name])
                                for name, value in selection["products"].items()})
                        raw = A["B"]["encode"](expected); A["write_new"](viewer / "expected.json", raw, 0o400)
                        return json.dumps(dict(prepared=True, expected_sha256=hashlib.sha256(raw).hexdigest(), display_sha256=SHA)).encode()
                    with patch.dict(A["prepare"].__globals__, run=execute, observed_ms=lambda: observed), \
                            patch.dict(A["B"], fingerprint=lambda *args: {"sha256": SHA}), self.assertRaises(ValueError):
                        A["prepare"](base / "source", viewer, base / "binary", base / "agent.sock",
                            base / "state-client/weather-cache", base / "state-client/air-quality-cache")

    def test_overmorrow_preparer_selects_only_its_source_and_schema(self):
        for expected_version in (2, 3, "3", True):
            with self.subTest(expected_version=expected_version), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary); viewer = base / "weather-viewer"; viewer.mkdir(mode=0o700)
                selection, forecasts = prepare_fixture(viewer)
                def execute(command, cwd, maximum, timeout):
                    self.assertEqual(command[2], str(base / "source" / A["B"]["WEATHER"] /
                        "integrations/overmorrow/prepare_core_browser.mjs"))
                    self.assertNotIn("drizzli", command[2])
                    expected = dict(schema=expected_version, core_sha256=SHA, display_sha256=SHA,
                        products={key: dict(publication=value["publication"], forecast=forecasts[key])
                            for key, value in selection["products"].items()})
                    raw = A["B"]["encode"](expected); A["write_new"](viewer / "expected.json", raw, 0o400)
                    return json.dumps(dict(prepared=True, expected_sha256=hashlib.sha256(raw).hexdigest(), display_sha256=SHA)).encode()
                with patch.dict(A["prepare"].__globals__, run=execute), patch.dict(A["B"], fingerprint=lambda *args: {"sha256": SHA}):
                    args = (base / "source", viewer, base / "binary", base / "agent.sock",
                        base / "state-client/weather-cache", base / "state-client/air-quality-cache", 3)
                    if type(expected_version) is int and expected_version == 3:
                        self.assertTrue(A["prepare"](*args)["prepared"])
                    else:
                        with self.assertRaises(ValueError): A["prepare"](*args)

    def test_partial_browser_report_is_retainable_but_never_success(self):
        failed = report(); failed.update(passed=False, phase="provider", checks={}, cleanup={})
        failed["scope"].update(actual_drizzli_ui=False, real_core_adapter=False, separate_native_runs=False)
        for value in failed["products"].values(): value["checks"] = {}
        A["closed_report"](failed)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); digest, caches = joined_fixture(work)
            path = A["artifact"](work, "original-report"); path.unlink(); save(path, failed)
            with patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)

    def test_exact_selection_keeps_separate_native_runs_and_no_cross_product_alias(self):
        value = selected(); A["validate_selection"](value)
        self.assertNotEqual(value["products"]["weather"]["query"]["run"], value["products"]["air_quality"]["query"]["run"])
        mutations = [("air_quality", "query", "steps", [3, 9, 24]), ("weather", "query", "includePrecipitation", False),
            ("air_quality", "publication", "name", A["PRODUCTS"]["weather"]["name"]),
            ("air_quality", "publication", "manifest_id", value["products"]["weather"]["publication"]["manifest_id"])]
        for key, group, field, changed in mutations:
            bad = copy.deepcopy(value); bad["products"][key][group][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError): A["validate_selection"](bad)

    def test_acquisition_requires_sixteen_weather_and_ten_native_particulate_fields(self):
        good = acquisition(); A["validate_acquisition"](good)
        self.assertEqual([len(good["products"][key]["fields"]) for key in A["PRODUCTS"]], [16, 10])
        for key in A["PRODUCTS"]:
            for field in ("missing", "duplicate", "wrong_parameter", "wrong_step"):
                value = copy.deepcopy(good); fields = value["products"][key]["fields"]
                if field == "missing": fields.pop()
                elif field == "duplicate": fields[0] = fields[1]
                elif field == "wrong_parameter": fields[0]["parameter"] = "private-source-url"
                else: fields[0]["lead_hours"] = 1
                with self.subTest(key=key, field=field), self.assertRaises(ValueError): A["validate_acquisition"](value)

    def test_full_join_rejects_product_specific_origin_privacy_and_ui_failures(self):
        mutations = [None,
            ("cold-consumer", "air_quality", ("receipt", "origin_body_bytes"), 1),
            ("cold-consumer", "air_quality", ("publication", "sha256"), "f"*64),
            ("cold-consumer", "weather", ("boundary", "no_new_privileges"), False),
            ("cold-consumer", "air_quality", ("observed_unix_seconds",), 1900000000),
            ("privacy-client", "air_quality", ("direct_client_exit_packets",), 1),
            ("privacy-exit", "air_quality", ("packet_socket_drops",), 1),
            ("control", "air_quality", ("unexpected_provider_application_packets",), 1),
            ("original-report", None, ("products", "air_quality", "checks", "browser_api_requests"), 1),
            ("original-report", None, ("products", "weather", "checks", "refresh_dom_display_sha256"), "f"*64),
            ("original-report", None, ("products", "air_quality", "expected", "cold_receipt_sha256"), "f"*64),
            ("original-report", None, ("source", "bridge_modules", "src/air-quality-provider.mjs"), "f"*64),
            ("original-report", None, ("scope", "synthetic_air_quality"), True),
            ("original-report", None, ("scope", "separate_native_runs"), False),
            ("original-report", None, ("checks", "browser_api_requests"), 6),
            ("original-report", None, ("checks", "refresh_dom_display_sha256"), "f"*64),
            ("cold-evidence", None, ("products", "air_quality", "forecast_sha256"), "f"*64),
            ("acquisition", None, ("products", "air_quality", "forecast_sha256"), "f"*64),
            ("publisher-cleanup", None, ("files_removed",), False),
            ("cache-after", "air_quality", ("inode",), 123)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, caches = joined_fixture(work)
                if mutation:
                    suffix, key, keys, changed = mutation; path = A["artifact"](work, suffix, key)
                    value = json.loads(path.read_bytes()); target = value
                    for field in keys[:-1]: target = target[field]
                    target[keys[-1]] = changed; path.unlink(); save(path, value)
                with patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                    if mutation:
                        with self.assertRaises(ValueError): A["evidence"](work, digest, SHA)
                    else:
                        proof = A["evidence"](work, digest, SHA); A["validate_evidence_export"](proof)
                        self.assertTrue(proof["scope"]["end_to_end_proven"])
                        self.assertFalse(proof["scope"]["browser_triggered_cold_fetch"])
                        self.assertEqual(proof["products"]["weather"]["acquired_fields"], 16)
                        self.assertEqual(proof["products"]["air_quality"]["acquired_fields"], 10)

    def test_weather_only_capture_or_receipt_never_proves_air_quality(self):
        for suffix in ("cold-consumer", "selection", "privacy-client", "privacy-exit", "control", "cache-before"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); digest, caches = joined_fixture(work)
                A["artifact"](work, suffix, "air_quality").unlink()
                with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                    with self.assertRaises((OSError, ValueError)): A["cold_evidence"](work, digest, SHA)

    def test_final_future_check_works_after_viewer_cleanup_but_export_has_no_wall_clock_dependency(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); digest, caches = joined_fixture(work)
            self.assertFalse((work / "client-fixtures/weather-viewer").exists())
            last = min(A["stamp"](v["query"]["run"]) + 48 * 3600000 for v in selected()["products"].values())
            with patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key], observed_ms=lambda: last-1):
                proof = A["evidence"](work, digest, SHA)
            for observed in (last, last+1, 0):
                with patch.dict(A["evidence"].__globals__, cache_state=lambda key, *args: caches[key], observed_ms=lambda: observed):
                    with self.subTest(observed=observed), self.assertRaises(ValueError): A["evidence"](work, digest, SHA)
            def unexpected_clock(): raise AssertionError("historical export must not read wall clock")
            with patch.dict(A["evidence"].__globals__, observed_ms=unexpected_clock), \
                    patch.object(A["time"], "time", side_effect=unexpected_clock), \
                    patch.object(A["time"], "time_ns", side_effect=unexpected_clock):
                A["validate_evidence_export"](proof)
                A["validate_acquisition"](acquisition())
                A["validate_cold_export"](A["read"](A["artifact"](work, "cold-evidence")))

    def test_cold_evidence_survives_missing_ui_without_claiming_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); digest, caches = joined_fixture(work)
            for suffix in ("original-report", "prepared", "tree-after", "input-cleanup"):
                A["artifact"](work, suffix).unlink()
            with patch.dict(A["cold_evidence"].__globals__, cache_state=lambda key, *args: caches[key]):
                result = A["cold_evidence"](work, digest, SHA)
                self.assertFalse(result["scope"]["end_to_end_proven"])
                with self.assertRaises((ValueError, OSError)): A["evidence"](work, digest, SHA)
            output = work / "output"; output.mkdir()
            A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertTrue(A["artifact"](output, "cold-evidence").exists())
            self.assertFalse(A["artifact"](output, "evidence").exists())

    def test_closed_exports_reject_location_and_raw_receipts_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); joined_fixture(work); output = work / "output"; output.mkdir()
            path = A["artifact"](work, "acquisition"); value = json.loads(path.read_bytes())
            value["coordinates"] = [52.52, 13.41]; path.unlink(); save(path, value)
            with self.assertRaises(ValueError): A["copy_artifacts"](work, output, os.getuid(), os.getgid())
            self.assertEqual(list(output.iterdir()), [])
        value = report(); value["products"]["air_quality"]["receipt"] = {"private": "raw"}
        with self.assertRaises(ValueError): A["closed_report"](value)

    def test_cleanup_validates_all_targets_before_deleting_two_product_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "weather-publisher"; root.mkdir(mode=0o700)
            for name in ("forecast.json", "air-quality.json", "identity.key"):
                A["write_new"](root / name, b"fixture")
            A["write_new"](root / "unrelated", b"keep")
            with self.assertRaises(ValueError): A["cleanup"](root, True)
            self.assertTrue((root / "forecast.json").exists()); self.assertTrue((root / "air-quality.json").exists())
            (root / "unrelated").unlink()
            self.assertEqual(A["cleanup"](root, True), dict(directory_removed=True, files_removed=True))
            self.assertFalse(root.exists())

    def test_cleanup_removes_only_exact_private_bounded_source_sidecars(self):
        for bad in (None, "empty", "unexpected", "directory", "mode", "oversize", "symlink", "hardlink"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "weather-publisher"; root.mkdir(mode=0o700)
                A["write_new"](root / "forecast.json", b"retained-until-all-paths-checked")
                weather = root / A["SOURCE_SIDECARS"]["weather"]
                aq = root / A["SOURCE_SIDECARS"]["air_quality"]
                # An interrupted/malformed diagnostic is removable, never exported raw.
                A["write_new"](aq, b'{"incomplete":')
                if bad == "directory": weather.mkdir(mode=0o700)
                elif bad == "symlink": weather.symlink_to(aq)
                else:
                    A["write_new"](weather, b"x" * (1025 if bad == "oversize" else 0 if bad == "empty" else 100),
                        0o644 if bad == "mode" else 0o600)
                if bad == "unexpected": A["write_new"](root / "other-origin-http.json", b"keep")
                if bad == "hardlink": os.link(weather, root / "linked-diagnostic")
                if bad not in (None, "empty"):
                    with self.assertRaises((ValueError, OSError)): A["cleanup"](root, True)
                    self.assertTrue((root / "forecast.json").exists()); self.assertTrue(aq.exists())
                else:
                    self.assertEqual(A["cleanup"](root, True), dict(directory_removed=True, files_removed=True))
                    self.assertFalse(root.exists())

    def test_cleanup_accepts_larger_two_product_expected_but_not_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "weather-viewer"; root.mkdir(mode=0o700)
            A["write_new"](root / "expected.json", b"x" * (300*1024), 0o400)
            (root / "air-quality.json").symlink_to(root / "expected.json")
            with self.assertRaises(ValueError): A["cleanup"](root, False)
            self.assertTrue((root / "expected.json").exists())
            (root / "air-quality.json").unlink(); A["cleanup"](root, False)

    def test_cache_metadata_is_distinct_private_and_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary); state = work / "state-client"; state.mkdir()
            values = {}
            for key, p in A["PRODUCTS"].items():
                path = state / p["cache"]; path.mkdir(mode=0o700)
                values[key] = A["cache_state"](key, path, os.getuid(), os.getgid())
            self.assertNotEqual(values["weather"]["inode"], values["air_quality"]["inode"])
            A["validate_cache_export"](dict(schema=2, products=values))
            with self.assertRaises(ValueError): A["cache_state"]("air_quality", state / "weather-cache", os.getuid(), os.getgid())


if __name__ == "__main__": unittest.main()
