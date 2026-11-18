#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Join two real source products to independent cold transfers and native UI.

Version one is deliberately untouched. Closed version-two (Drizz.li) and
version-three (Overmorrow) UI profiles share two-product acquisition and transfer,
not each other's UI evidence. Coordinates and raw receipts stay inside the guest.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time

HERE = Path(__file__).parent
V1 = runpy.run_path(str(HERE / "weather-client-delivery.py"))
B, HTTPS = V1["B"], V1["HTTPS"]
require, hex64, same = V1["require"], V1["hex64"], V1["same"]
raw_file, read, write_new, private = (V1[k] for k in ("raw_file", "read", "write_new", "private"))
run, boundary = V1["run"], V1["boundary"]
MAX_FORECAST, MAX_REPORT = V1["MAX_FORECAST"], V1["MAX_REPORT"]
MAX_EXPECTED = 384 * 1024
PREFIX = "weather-products-delivery"
PRODUCTS = {
    "weather": dict(suffix="weather", name="disposable-public-community-weather", filename="forecast.json",
        manifest="manifest.bin", published="publish-receipt.json", cache="weather-cache", source_cache="source-cache",
        receipt="cold-receipt.json", script="forecast.mjs", schema="volparossa.forecast.v1", provider="ecmwf",
        model="ifs", steps=[3, 9, 24, 48], parameters=["2t", "10u", "10v", "tp"]),
    "air_quality": dict(suffix="air-quality", name="disposable-public-community-air-quality", filename="air-quality.json",
        manifest="air-quality-manifest.bin", published="air-quality-publish-receipt.json", cache="air-quality-cache",
        source_cache="air-quality-source-cache", receipt="air-quality-cold-receipt.json", script="air-quality.mjs",
        schema="volparossa.air-quality.forecast.v1", provider="noaa", model="gefs-aerosols",
        steps=[3, 6, 12, 24, 48], parameters=["PMTF", "PMTC"]),
}
BRIDGE_MODULES = {"scripts/serve-provider.mjs", "src/provider-http.mjs", "src/provider-core.mjs", "src/core-cache.mjs",
    "src/air-quality.mjs", "src/air-quality-provider.mjs", "src/air-quality-core.mjs"}
EXPORTS = ("cold-evidence", "evidence", "acquisition", "original-report", "tree-before", "tree-after",
    "cache-before", "cache-after", "input-cleanup")
ACQUISITION_STAGES = {"preconditions": None, "boundary": None, "tree": None, "decoder": None,
    "weather-run": "weather", "weather-validation": "weather", "air-quality-run": "air_quality",
    "air-quality-validation": "air_quality", "final-validation": None}
FAILURE_CLASSES = {"missing-input", "permission-denied", "io-failed", "timeout", "process-failed",
    "check-or-execution-failed"}
FAILURE_EXPORTS = ("acquisition-failure", "tree-before", "input-cleanup")
SAFE_ERRORS = (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError)
SOURCE_SIDECARS = {"weather": "weather-origin-http.json", "air_quality": "air-quality-origin-http.json"}
MAX_SOURCE_RESPONSE = 1024
MAX_SOURCE_EPOCH_MS = 8640000000000000  # JavaScript Date range, within safe integers.
MAX_RETRY_ADVICE_MS = 7 * 24 * 3600000
SOURCE_RESPONSE_STATES = {"valid-seconds", "valid-date", "missing", "malformed", "out-of-range"}


def source_observer():
    # This explicit fixture helper belongs to the verified core, not the frozen
    # Weather bundle. The root orchestrator stages it read-only before dropping UID.
    path = HERE / "weather-source-observer.mjs"
    B["B"]["canonical"](path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o555)
    raw_file(path, 64 * 1024, 0o555)
    return path.as_uri()


def validate_source_response(value, key, window=None):
    require(type(value) is dict and set(value) == {"schema", "kind", "product", "status",
        "observed_at_ms", "retry_after_state", "retry_not_before_ms"})
    same(value["schema"], 1); same(value["kind"], "weather-source-rate-limit")
    same(value["product"], key); product(key); same(value["status"], 429)
    observed, until, state = value["observed_at_ms"], value["retry_not_before_ms"], value["retry_after_state"]
    require(type(observed) is int and 0 <= observed <= MAX_SOURCE_EPOCH_MS
        and type(state) is str and state in SOURCE_RESPONSE_STATES)
    if window is not None:
        start, end = window
        require(type(start) is int and type(end) is int and 0 <= start <= observed <= end <= MAX_SOURCE_EPOCH_MS)
    if state in ("valid-seconds", "valid-date"):
        require(type(until) is int and abs(until) <= MAX_SOURCE_EPOCH_MS
            and until - observed <= MAX_RETRY_ADVICE_MS)
        require(until >= observed and (until - observed) % 1000 == 0
            if state == "valid-seconds" else until % 1000 == 0)
    else:
        same(until, None)


def source_response(root, key, started_at, finished_at):
    # No file from an earlier product/run can explain this failure. These files
    # are never exported directly, and their advice never triggers a retry.
    if key is None or started_at is None:
        return "missing", None
    path = root / SOURCE_SIDECARS[key]
    try:
        if not path.exists() and not path.is_symlink(): return "missing", None
        private(path, directory=False)
        value = json.loads(raw_file(path, MAX_SOURCE_RESPONSE, 0o600), object_pairs_hook=B["B"]["unique_pairs"])
        end = observed_ms() if finished_at is None else finished_at
        validate_source_response(value, key, (started_at, end))
        return "valid", value
    except SAFE_ERRORS:
        return "invalid", None


def ui_profile(version):
    # A version selects a fixed consumer, never a caller-supplied executable.
    require(type(version) is int and version in (2, 3, 4, 5))
    if version in (2, 4):
        return dict(ui="actual_drizzli_ui", static=B["STATIC"],
            preparer="integrations/drizzli/prepare-core-browser.mjs",
            driver="integrations/drizzli/smoke_core_browser.py")
    return dict(ui="actual_overmorrow_ui", static=B["WEATHER"] + "build/overmorrow-web/",
        preparer="integrations/overmorrow/prepare_core_browser.mjs",
        driver="integrations/overmorrow/smoke_core_browser.py")


def acquisition_schema(version):
    # Android reuses source acquisition, not a browser profile or its proof.
    require(type(version) is int and version in (2, 3, 4, 5, 6))
    return 6 if version == 6 else 4 if version in (4, 5) else 2


class AcquisitionFailure(ValueError):
    """Carry only a closed classification, never a subprocess error or argv."""
    def __init__(self, stage, error, source_response_state="missing", source_response=None):
        failure = ("missing-input" if isinstance(error, FileNotFoundError) else
            "permission-denied" if isinstance(error, PermissionError) else
            "io-failed" if isinstance(error, OSError) else
            "timeout" if isinstance(error, subprocess.TimeoutExpired) else
            "process-failed" if isinstance(error, subprocess.CalledProcessError) else
            "check-or-execution-failed")
        self.diagnostic = dict(schema=3, kind="weather-products-acquisition-diagnostic", success=False,
            stage=stage, product=ACQUISITION_STAGES[stage], failure=failure,
            source_response_state=source_response_state, source_response=source_response)
        super().__init__("weather_products_acquisition_failed")


def validate_acquisition_diagnostic(value):
    require(type(value) is dict and type(value.get("schema")) is int and value["schema"] in (2, 3))
    fields = {"schema", "kind", "success", "stage", "product", "failure"}
    # Historical v2 proves only the stage; do not invent HTTP metadata for it.
    require(set(value) == fields | ({"source_response_state", "source_response"} if value["schema"] == 3 else set()))
    same(value["kind"], "weather-products-acquisition-diagnostic"); same(value["success"], False)
    require(type(value["stage"]) is str and value["stage"] in ACQUISITION_STAGES
        and type(value["failure"]) is str and value["failure"] in FAILURE_CLASSES)
    same(value["product"], ACQUISITION_STAGES[value["stage"]])
    if value["schema"] == 3:
        state = value["source_response_state"]
        require(type(state) is str and state in {"missing", "valid", "invalid"})
        if value["product"] is None: same(state, "missing")
        if state == "valid": validate_source_response(value["source_response"], value["product"])
        else: same(value["source_response"], None)


def validate_acquisition_failure(value):
    require(type(value) is dict and set(value) == {"schema", "kind", "success", "command_exit_status", "diagnostic_state", "diagnostic"})
    same(value["schema"], 2); same(value["kind"], "weather-products-acquisition-failure"); same(value["success"], False)
    require(type(value["command_exit_status"]) is int and 1 <= value["command_exit_status"] <= 255
        and type(value["diagnostic_state"]) is str and value["diagnostic_state"] in {"valid", "missing", "invalid"})
    if value["diagnostic_state"] == "valid": validate_acquisition_diagnostic(value["diagnostic"])
    else: same(value["diagnostic"], None)


def retain_acquisition_failure(work, status):
    # The root shell invokes this only after acquire exits nonzero. A killed
    # worker may leave empty stdout; never turn that into guessed source failure.
    require(type(status) is int and 1 <= status <= 255)
    source = artifact(work, "acquisition")
    state, diagnostic = "missing", None
    try:
        if source.exists() or source.is_symlink():
            info = private(source, directory=False)
            raw = raw_file(source, MAX_REPORT, 0o600) if info.st_size else b""
            if raw:
                candidate = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
                validate_acquisition_diagnostic(candidate)
                state, diagnostic = "valid", candidate
    except SAFE_ERRORS:
        state = "invalid"
    result = dict(schema=2, kind="weather-products-acquisition-failure", success=False,
        command_exit_status=status, diagnostic_state=state, diagnostic=diagnostic)
    validate_acquisition_failure(result)
    return result


def product(key):
    require(type(key) is str and key in PRODUCTS)
    return PRODUCTS[key]


def artifact(work, suffix, key=None):
    return work / f"{PREFIX}-{product(key)['suffix'] + '-' if key else ''}{suffix}.json"


def initialize(root):
    result = V1["initialize"](root)
    result["schema"] = 2
    return result


def fixed_query(key, model_run):
    p = product(key)
    result = dict(latitude=52.52, longitude=13.41, run=model_run, model=p["model"],
        steps=p["steps"], communityArea=True)
    if key == "weather": result.update(includeWind=True, includePrecipitation=True)
    return result


def stamp(value):
    require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value))
    moment = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (moment - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(milliseconds=1)


def observed_ms():
    return time.time_ns() // 1000000


def future_query(key, query, observed_at):
    same(query, fixed_query(key, query["run"]))
    run_at = stamp(query["run"])
    require(type(observed_at) is int and run_at <= observed_at < run_at + 48 * 3600000)


def forecast_times(value, key, model_run, observed_at, acquisition_window=None):
    require(value["kind"] == "forecast" and value["source"]["model_run_at"] == model_run)
    run_at, acquired_at = stamp(model_run), stamp(value["source"]["acquired_at"])
    require(type(observed_at) is int and run_at <= acquired_at <= observed_at)
    samples = value["samples"]
    same([sample["lead_hours"] for sample in samples], product(key)["steps"])
    for sample in samples:
        require(type(sample["lead_hours"]) is int
            and stamp(sample["valid_at"]) == run_at + sample["lead_hours"] * 3600000)
    # Past native samples remain forecasts, never observations. The final lead
    # must still be in the future at this actual acquisition/preparation check.
    require(stamp(samples[-1]["valid_at"]) > observed_at)
    if acquisition_window is not None:
        started_at, finished_at = acquisition_window
        require(started_at <= acquired_at <= finished_at == observed_at)


def acquisition(source, manifest_sha, root, parent, client, group):
    stage = "preconditions"
    active_product, started_at, finished_at = None, None, None
    try:
        private(root)
        require(root.name == "weather-publisher" and set(p.name for p in root.iterdir()) == {"passphrase", "scratch"})
        stage = "boundary"
        boundary(parent, client, group, True)
        stage = "tree"
        B["verify_tree"](source, manifest_sha)
        version = B["manifest"](raw_file(source / "INPUTS.json", B["MAX_MANIFEST"], 0o400), manifest_sha)["version"]
        schema = acquisition_schema(version)
        decoder = B["decoder_sha"](version)
        observer = source_observer()
        deadline = time.monotonic() + 720
        stage = "decoder"
        require(run([str(source / "decoder/grib_ls"), "-V"], root, 4096, 10).strip() == b"ecCodes Version 2.44.0")
        now = int(time.time())
        # Select independently completed cycles. NOAA's 00UTC cycle with an explicit
        # twelve-hour availability margin is not rewritten to match IFS. Native
        # samples are not interpolated; lead 48 preserves future coverage across
        # midnight/noon boundaries without pretending the earlier leads are current.
        cycles = dict(weather=now // 43200 * 43200 - 43200, air_quality=(now - 43200) // 86400 * 86400)
        products = {}
        for key, p in PRODUCTS.items():
            stage = p["suffix"] + "-run"
            active_product, started_at, finished_at = key, None, None
            sidecar = root / SOURCE_SIDECARS[key]
            require(not sidecar.exists() and not sidecar.is_symlink())
            model_run = datetime.datetime.fromtimestamp(cycles[key], datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            command = [str(source / "runtime/node"), "--max-old-space-size=256", "--import", observer + "?product=" + key,
                str(source / B["WEATHER"] / "scripts" / p["script"]), "origin", "--latitude", "52.52", "--longitude", "13.41",
                "--run", model_run, "--steps", ",".join(map(str, p["steps"])), "--community-area",
                "--execute", "--accept-data-license", "--decoder", str(source / "decoder/grib_ls"),
                "--decoder-sha256", decoder, "--scratch-parent", str(root / "scratch")]
            if key == "weather": command += ["--model", "ifs", "--include-wind", "--include-precipitation"]
            remaining = deadline - time.monotonic(); require(remaining > 0)
            started_at = observed_ms()
            raw = run(command, root, MAX_FORECAST, min(360, remaining))
            finished_at = observed_ms()
            stage = p["suffix"] + "-validation"
            value = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
            require(value["schema"] == p["schema"] and value["source"]["provider"] == p["provider"]
                and value["source"]["acquisition"] == "origin-https" and value["source"]["model"] == p["model"]
                and value["source"]["model_run_at"] == model_run)
            same(value["area"], dict(latitude=52.52, longitude=13.41, sharing="public-community"))
            forecast_times(value, key, model_run, finished_at, (started_at, finished_at))
            require(not list((root / "scratch").iterdir()))
            fields = []
            for sample in value["samples"]:
                evidence = (sample["evidence"], *sample["wind_10m"]["evidence"].values(), sample["precipitation"]["evidence"]) \
                    if key == "weather" else tuple(sample["evidence"].values())
                for field in evidence:
                    require(field["decoder_sha256"] == decoder and field["parameter"] in p["parameters"]
                        and hex64(field["index_sha256"]) and hex64(field["field_sha256"]))
                    fields.append(dict(lead_hours=sample["lead_hours"], parameter=field["parameter"],
                        index_sha256=field["index_sha256"], field_sha256=field["field_sha256"]))
            products[key] = dict(forecast_sha256=hashlib.sha256(raw).hexdigest(), forecast_bytes=len(raw), fields=fields)
            write_new(root / p["filename"], raw)
        stage = "final-validation"
        active_product, started_at, finished_at = None, None, None
        result = dict(schema=schema, success=True, origin_https=True, acquisition_outside_overlay=True,
            upstream_signature_attested=False, synthetic_weather=False, synthetic_air_quality=False,
            independent_product_runs=True, decoder_sha256=decoder, products=products)
        validate_acquisition(result, version)
        return result
    except SAFE_ERRORS as error:
        state, response = source_response(root, active_product, started_at, finished_at)
        raise AcquisitionFailure(stage, error, state, response) from None


def validate_publication(value, key):
    p = product(key)
    require(type(value) is dict and set(value) == {"publisher_key", "name", "revision", "manifest_id", "sha256", "bytes", "expires_unix_seconds"})
    same(value["name"], p["name"]); same(value["revision"], 1)
    require(all(hex64(value[k]) for k in ("publisher_key", "manifest_id", "sha256"))
        and type(value["bytes"]) is int and 0 < value["bytes"] <= MAX_FORECAST
        and type(value["expires_unix_seconds"]) is int and value["expires_unix_seconds"] > 0)


def validate_selection(value):
    require(type(value) is dict and set(value) == {"schema", "products"})
    same(value["schema"], 2); require(type(value["products"]) is dict and set(value["products"]) == set(PRODUCTS))
    for key, selected in value["products"].items():
        require(type(selected) is dict and set(selected) == {"publication", "query"})
        validate_publication(selected["publication"], key)
        query = selected["query"]
        same(query, fixed_query(key, query["run"]))
        require(type(query["run"]) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T(?:00|12):00:00\.000Z" if key == "weather"
            else r"\d{4}-\d{2}-\d{2}T00:00:00\.000Z", query["run"]))
        stamp(query["run"])
    require(value["products"]["weather"]["publication"]["manifest_id"] != value["products"]["air_quality"]["publication"]["manifest_id"])
    return value


def select(root, viewer):
    private(root); private(viewer)
    require(root.name == "weather-publisher" and viewer.name == "weather-viewer" and not list(viewer.iterdir()))
    selected = dict(schema=2, products={})
    for key, p in PRODUCTS.items():
        published = read(root / p["published"])
        raw = raw_file(root / p["filename"], MAX_FORECAST, 0o600)
        forecast = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
        manifest_id = hashlib.sha256(raw_file(root / p["manifest"])).hexdigest()
        require(published["operation"] == "offline_content_publish" and published["network_publication"] is False
            and published["bytes"] == len(raw) and published["chunks"] == 1 and hex64(published["publisher_key_hex"])
            and published["name"] == p["name"] and published["revision"] == 1 and published["content_type"] == "application/json"
            and published["manifest_id"] == manifest_id and forecast["schema"] == p["schema"])
        same(forecast["area"], dict(latitude=52.52, longitude=13.41, sharing="public-community"))
        selected["products"][key] = dict(publication=dict(publisher_key=published["publisher_key_hex"], name=p["name"],
            revision=1, manifest_id=manifest_id, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
            expires_unix_seconds=published["expires_unix_seconds"]), query=fixed_query(key, forecast["source"]["model_run_at"]))
    validate_selection(selected)
    write_new(viewer / "selection.json", B["encode"](selected), 0o400)
    return selected


def cold(key, binary, control, cache, viewer, parent, client, group):
    p = product(key); private(viewer)
    require(viewer.name == "weather-viewer" and cache.name == p["cache"])
    allowed = {"selection.json"} | ({PRODUCTS["weather"]["filename"], PRODUCTS["weather"]["receipt"]} if key == "air_quality" else set())
    require(set(path.name for path in viewer.iterdir()) == allowed)
    process_boundary = boundary(parent, client, group)
    publication = validate_selection(read(viewer / "selection.json", mode=0o400))["products"][key]["publication"]
    output = viewer / p["filename"]
    binary_before = B["fingerprint"](binary, 256*1024**2)
    raw = run([str(binary), "--control-socket", str(control), "content", "fetch-name", "--publisher-key",
        publication["publisher_key"], "--name", p["name"], "--min-revision", "1", "--cache", str(cache),
        "--local-output", str(output), "--quota-bytes", str(MAX_FORECAST), "--max-entries", "16", "--min-free-bytes", "67108864"],
        viewer, MAX_REPORT, 180)
    receipt = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
    V1["validate_cold_receipt"](receipt, publication, cache, output)
    content = raw_file(output, MAX_FORECAST, 0o600)
    require(len(content) == publication["bytes"] and hashlib.sha256(content).hexdigest() == publication["sha256"]
        and time.time() < publication["expires_unix_seconds"])
    write_new(viewer / p["receipt"], raw)
    same(B["fingerprint"](binary, 256*1024**2), binary_before)
    return dict(schema=2, product=key, boundary=process_boundary, publication=publication, receipt=receipt,
        cold_receipt_sha256=hashlib.sha256(raw).hexdigest(), core_sha256=binary_before["sha256"],
        cold_cache_requested=True, observed_unix_seconds=int(time.time()))


def prepare(source, viewer, binary, control, weather_cache, air_quality_cache, version=2):
    profile = ui_profile(version)
    private(viewer)
    selected = validate_selection(read(viewer / "selection.json", mode=0o400))
    core_sha = B["fingerprint"](binary, 256*1024**2)["sha256"]
    def core_config(key, cache):
        publication = selected["products"][key]["publication"]
        require(cache.name == product(key)["cache"])
        return dict(mode="core-cache", executable=str(binary), controlSocket=str(control), cache=str(cache),
            scratchParent=str(viewer / "browser-output/scratch"), publisherKey=publication["publisher_key"],
            name=publication["name"], minRevision=1, query=selected["products"][key]["query"], reuseCache=True)
    config = dict(core=core_config("weather", weather_cache), variables=V1["VARIABLES"],
        airQuality=dict(core=core_config("air_quality", air_quality_cache), variables=["pm2_5", "pm10"]))
    write_new(viewer / "config.json", B["encode"](config))
    command = [str(source / "runtime/node"), "--max-old-space-size=256",
        str(source / B["WEATHER"] / profile["preparer"]),
        "--forecast", str(viewer / "forecast.json"), "--receipt", str(viewer / "cold-receipt.json"),
        "--air-quality", str(viewer / "air-quality.json"), "--air-quality-receipt", str(viewer / "air-quality-cold-receipt.json"),
        "--config", str(viewer / "config.json"), "--core-sha256", core_sha, "--output", str(viewer / "expected.json")]
    if version in (4, 5):
        command += ["--bundle-version", str(version)]
    raw = run(command, viewer, 4096, 30)
    result = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
    same(set(result), {"prepared", "expected_sha256", "display_sha256"})
    require(result["prepared"] is True and hex64(result["expected_sha256"]) and hex64(result["display_sha256"]))
    expected_raw = raw_file(viewer / "expected.json", MAX_EXPECTED, 0o400)
    expected = json.loads(expected_raw, object_pairs_hook=B["B"]["unique_pairs"])
    require(set(expected) == {"schema", "core_sha256", "products", "display_sha256"}
        and type(expected["schema"]) is int and expected["schema"] == version
        and expected["core_sha256"] == core_sha and set(expected["products"]) == set(PRODUCTS)
        and hashlib.sha256(expected_raw).hexdigest() == result["expected_sha256"]
        and expected["display_sha256"] == result["display_sha256"])
    for key, p in PRODUCTS.items():
        publication = selected["products"][key]["publication"]
        same(expected["products"][key]["publication"], publication)
        cold_raw = raw_file(viewer / p["filename"], MAX_FORECAST, 0o600)
        require(len(cold_raw) == publication["bytes"] and hashlib.sha256(cold_raw).hexdigest() == publication["sha256"])
        forecast = json.loads(cold_raw, object_pairs_hook=B["B"]["unique_pairs"])
        same(expected["products"][key]["forecast"], forecast)
        forecast_times(forecast, key, selected["products"][key]["query"]["run"], observed_ms())
    return result


def cache_state(key, path, uid, gid):
    require(path.name == product(key)["cache"] and path.parent.name == "state-client" and path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == uid and info.st_gid == gid)
    return dict(device=info.st_dev, inode=info.st_ino, mode="0700", user_uid=uid, group_gid=gid)


def cache_summary(work, phase):
    require(phase in ("before", "after"))
    result = dict(schema=2, products={key: read(artifact(work, "cache-" + phase, key)) for key in PRODUCTS})
    validate_cache_export(result)
    return result


def cleanup(root, publisher):
    require(root.name == ("weather-publisher" if publisher else "weather-viewer") and not root.is_symlink())
    if not root.exists(): return dict(directory_removed=True, files_removed=True)
    private(root)
    allowed = {"passphrase", "identity.key", "scratch"} if publisher else {"selection.json", "config.json", "expected.json", "browser-output"}
    allowed |= {p[field] for p in PRODUCTS.values() for field in
        (("filename", "manifest", "published", "source_cache") if publisher else ("filename", "receipt"))}
    if publisher: allowed |= set(SOURCE_SIDECARS.values())
    files, directories, total = [], [], 0
    for path in root.iterdir():
        require(path.name in allowed)
        sidecar_info = private(path, directory=False) if path.name in SOURCE_SIDECARS.values() else None
        if path.is_dir():
            private(path); directories.append(path)
            children = list(path.iterdir()); require(len(children) <= 20)
            for child in children:
                require(child.name == "report.json" if path.name == "browser-output" else
                    path.name in {p["source_cache"] for p in PRODUCTS.values()} and
                    (re.fullmatch(r"[a-f0-9]{64}", child.name) or child.name in (".volparossa-owner-v1", ".volparossa-index-v1")))
                total += len(raw_file(child, MAX_FORECAST)); files.append(child)
        else:
            if path.name in SOURCE_SIDECARS.values():
                # Exclusive create followed by interruption can leave zero bytes.
                total += len(raw_file(path, MAX_SOURCE_RESPONSE, 0o600)) if sidecar_info.st_size else 0
            else:
                total += len(raw_file(path, MAX_EXPECTED))
            files.append(path)
    require(total <= 4*1024*1024)
    for path in files: path.unlink()
    for path in directories: path.rmdir()
    root.rmdir()
    return dict(directory_removed=True, files_removed=True)


def acquisition_profile(value, version=None):
    # Receipts retain schema 2 for the old Drizz.li/Overmorrow inputs. The new
    # decoder has a distinct receipt contract, bound to the verified manifest.
    require(type(value) is dict and type(value.get("schema")) is int and value["schema"] in (2, 4, 6))
    if version is not None:
        same(value["schema"], acquisition_schema(version))
    return value["schema"]


def validate_acquisition(value, version=None):
    schema = acquisition_profile(value, version)
    same({k: v for k, v in value.items() if k != "products"}, dict(schema=schema, success=True, origin_https=True,
        acquisition_outside_overlay=True, upstream_signature_attested=False, synthetic_weather=False,
        synthetic_air_quality=False, independent_product_runs=True, decoder_sha256=B["decoder_sha"](schema)))
    require(type(value["products"]) is dict and set(value["products"]) == set(PRODUCTS))
    for key, item in value["products"].items():
        p = product(key)
        require(type(item) is dict and set(item) == {"forecast_sha256", "forecast_bytes", "fields"}
            and hex64(item["forecast_sha256"]) and type(item["forecast_bytes"]) is int and 0 < item["forecast_bytes"] <= MAX_FORECAST
            and type(item["fields"]) is list and len(item["fields"]) == len(p["steps"]) * len(p["parameters"]))
        coverage = []
        for field in item["fields"]:
            require(set(field) == {"lead_hours", "parameter", "index_sha256", "field_sha256"}
                and type(field["lead_hours"]) is int and field["lead_hours"] in p["steps"]
                and field["parameter"] in p["parameters"] and hex64(field["index_sha256"]) and hex64(field["field_sha256"]))
            coverage.append((field["lead_hours"], field["parameter"]))
        require(set(coverage) == {(step, parameter) for step in p["steps"] for parameter in p["parameters"]})


def closed_report(report):
    require(type(report) is dict and set(report) <= {"schema", "passed", "phase", "source", "expected", "products",
        "scope", "checks", "cleanup", "outer_cleanup", "failure"})
    profile = ui_profile(report["schema"]); require(type(report["passed"]) is bool)
    require(report["phase"] in {"inputs", "sandbox", "bridge_start", "provider", "browser_start", "hydration", "refresh", "shutdown", "complete"})
    if "failure" in report: require(report["failure"] in ("interrupted", "check_or_runtime_failed"))
    source = report["source"]
    extra_source = ({"synthetic_ui_proof", "synthetic_table_proof"} if report["schema"] == 5
        else {"synthetic_ui_proof"} if report["schema"] == 4 else set())
    require(set(source) == {"bundle_manifest_sha256", "driver_sha256", "preparer_sha256", "built_tree_sha256", "node_sha256", "bridge_modules"} | extra_source
        and all(hex64(v) for k, v in source.items() if k not in {"bridge_modules"} | extra_source)
        and set(source["bridge_modules"]) == BRIDGE_MODULES and all(hex64(v) for v in source["bridge_modules"].values()))
    if extra_source:
        proof = source["synthetic_ui_proof"]
        require(type(proof) is dict and set(proof) == {"sha256", "driver_sha256", "core_executed", "overlay_proven"}
            and hex64(proof["sha256"]) and hex64(proof["driver_sha256"])
            and proof["core_executed"] is False and proof["overlay_proven"] is False)
    if report["schema"] == 5:
        proof = source["synthetic_table_proof"]
        require(type(proof) is dict and set(proof) == {"sha256", "driver_sha256", "verifier_sha256", "core_executed", "overlay_proven"}
            and all(hex64(proof[key]) for key in ("sha256", "driver_sha256", "verifier_sha256"))
            and proof["core_executed"] is False and proof["overlay_proven"] is False)
    require(set(report["expected"]) == {"expected_sha256", "core_sha256", "display_sha256"}
        and all(hex64(v) or k == "expected_sha256" and v is None for k, v in report["expected"].items()))
    require(set(report["products"]) == set(PRODUCTS))
    for item in report["products"].values():
        require(set(item) == {"expected", "checks"} and set(item["expected"]) ==
            {"cold_receipt_sha256", "display_sha256", "forecast_sha256", "manifest_id"}
            and all(hex64(v) for v in item["expected"].values()))
        allowed = {"api_response_sha256", "initial_dom_display_sha256", "refresh_dom_display_sha256",
            "initial_dom_matches_cold_publication", "refresh_dom_matches_cold_publication", "browser_api_requests",
            "provider_requests_checked", "exact_native_times_and_values", "explicit_missing_capabilities", "no_external_resources", "source_attribution"}
        require(set(item["checks"]) <= allowed)
        for key, v in item["checks"].items():
            require(hex64(v) if key.endswith("sha256") else type(v) is int and 0 <= v <= 2
                if key in {"browser_api_requests", "provider_requests_checked"} else type(v) is bool)
    require(set(report["scope"]) == {profile["ui"], "actual_http_bridge", "real_core_adapter", "synthetic_weather",
        "synthetic_air_quality", "separate_native_runs", "standalone_origin_proven", "standalone_overlay_proven", "browser_triggered_cold_fetch"}
        and all(type(v) is bool for v in report["scope"].values()))
    require(set(report["checks"]) <= {"no_external_resources", "provider_requests_checked", "browser_api_requests",
        "initial_dom_display_sha256", "refresh_dom_display_sha256"})
    for key, v in report["checks"].items():
        require(hex64(v) if key.endswith("sha256") else type(v) is int and 0 <= v <= 4
            if key in {"provider_requests_checked", "browser_api_requests"} else type(v) is bool)
    for name, allowed in (("cleanup", {"browser_exited", "bridge_exited", "private_state_removed", "normal_browser_stop", "normal_bridge_stop"}),
            ("outer_cleanup", {"namespace_wrapper_exited", "private_state_removed", "client_namespace_unchanged"})):
        if name in report: require(set(report[name]) <= allowed and all(type(v) is bool for v in report[name].values()))
    return report


def retain(work):
    path = work / "client-fixtures/weather-viewer/browser-output/report.json"
    if not path.exists(): return dict(retained=False)
    raw = V1["worker_report"](path)
    closed_report(json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"]))
    write_new(artifact(work, "original-report"), raw)
    return dict(retained=True, sha256=hashlib.sha256(raw).hexdigest())


def validate_publications(work, publication, nodes, key):
    p = product(key); published = read(artifact(work, "publish", key))
    require(published["operation"] == "offline_content_publish" and published["network_publication"] is False
        and published["publisher_key_hex"] == publication["publisher_key"] and published["content_type"] == "application/json"
        and published["chunks"] == 1 and all(published[k] == publication[k] for k in
            ("name", "revision", "bytes", "manifest_id", "expires_unix_seconds")))
    for node in nodes:
        imported = read(artifact(work, node + "-import", key)); served = read(artifact(work, node + "-serve", key))
        require(imported["operation"] == "content_import" and imported["complete"] is True
            and imported["manifest_id"] == publication["manifest_id"] and imported["content_bytes"] == publication["bytes"]
            and imported["agent_cache"] == str(work / f"state-{node}" / p["cache"]) and imported["public_content"] is True
            and all(imported[k] is False for k in ("ownership_changed", "network_transfer", "origin_authenticated"))
            and served["serving"] is True and type(served["publications"]) is int
            and served["publications"] == (4 if key == "weather" else 5) and served["replication_enabled"] is False)


def validate_cold_phase(work, manifest_sha, binary_sha):
    require(hex64(binary_sha))
    manifest = B["manifest"](raw_file(artifact(work, "manifest"), B["MAX_MANIFEST"], 0o400), manifest_sha)
    ui_profile(manifest["version"])
    selected = validate_selection(read(artifact(work, "input")))
    acquired = read(artifact(work, "acquisition")); validate_acquisition(acquired, manifest["version"])
    peers, layout = read(work / "a01-expected-peers.json"), read(work / "content-provider-layout.json")
    control_gid = (work / "runtime-client/control/agent.sock").stat().st_gid
    colds, caches = {}, {}
    for key, p in PRODUCTS.items():
        publication = selected["products"][key]["publication"]; acquisition_item = acquired["products"][key]
        require(acquisition_item["forecast_sha256"] == publication["sha256"] and acquisition_item["forecast_bytes"] == publication["bytes"])
        cold_result = read(artifact(work, "cold-consumer", key)); colds[key] = cold_result
        same(cold_result["publication"], publication); same(cold_result["schema"], 2); same(cold_result["product"], key)
        V1["validate_cold_receipt"](cold_result["receipt"], publication, work / "state-client" / p["cache"],
            work / "client-fixtures/weather-viewer" / p["filename"])
        same(cold_result["cold_cache_requested"], True)
        require(cold_result["core_sha256"] == binary_sha and hex64(cold_result["cold_receipt_sha256"])
            and type(cold_result["observed_unix_seconds"]) is int and 0 < cold_result["observed_unix_seconds"] < publication["expires_unix_seconds"])
        same(cold_result["boundary"], dict(user_uid=985, primary_control_gid=control_gid, supplementary_groups_empty=True,
            all_capabilities_dropped=True, no_new_privileges=True, client_namespace=True, acquisition_parent_namespace=False))
        validate_publications(work, publication, layout["provider_nodes"], key)
        V1["validate_packets"](cold_result, peers, layout, read(artifact(work, "selection", key)),
            {role: read(artifact(work, "privacy-" + role, key)) for role in HTTPS["ROLES"]}, read(artifact(work, "control", key)))
        before = read(artifact(work, "cache-before", key)); caches[key] = before
        same(before, cache_state(key, work / "state-client" / p["cache"], before["user_uid"], before["group_gid"]))
        require(before["user_uid"] != 985 and control_gid != before["group_gid"])
    same(read(artifact(work, "publisher-cleanup")), dict(directory_removed=True, files_removed=True))
    publisher = work / "client-fixtures/weather-publisher"
    require(not publisher.exists() and not publisher.is_symlink())
    same(read(artifact(work, "tree-before")), dict(version=1, action="verify-tree", manifest_sha256=manifest_sha,
        files=len(manifest["files"]), runtime_executed=False))
    return selected, acquired, colds, manifest, caches


def cold_summary(selected, acquired, colds, manifest_sha, binary_sha, version=2):
    ui_profile(version)
    validate_acquisition(acquired, version)
    products = {}
    for key in PRODUCTS:
        publication = selected["products"][key]["publication"]; cold = colds[key]
        products[key] = dict(forecast_sha256=publication["sha256"], forecast_bytes=publication["bytes"],
            manifest_id=publication["manifest_id"], cold_receipt_sha256=cold["cold_receipt_sha256"],
            acquired_fields=len(acquired["products"][key]["fields"]), protected_cold=dict(peer_bytes=cold["receipt"]["peer_bytes"],
                providers_used=cold["receipt"]["providers_used"], origin_body_bytes=0, origin_range_requests=0, privacy_captures_validated=True))
    result = dict(schema=4 if version in (4, 5) else 2, success=True, kind="volparossa-weather-products-protected-cold", bundle_manifest_sha256=manifest_sha,
        core_sha256=binary_sha, decoder_sha256=B["decoder_sha"](version), products=products,
        scope=dict(actual_acquisition=True, acquisition_outside_overlay=True, same_publications_joined=True,
            independent_product_captures=True, protected_cold_transfer=True, actual_drizzli_ui=False, actual_http_bridge=False,
            actual_ui_refresh=False, end_to_end_proven=False, browser_triggered_cold_fetch=False,
            two_subflow_bulk_aggregation=False, upstream_signature_attested=False, production_service_complete=False),
        cleanup=dict(publisher_sources_removed_before_fetch=True))
    validate_cold_export(result)
    return result


def validate_cold_export(value):
    require(set(value) == {"schema", "success", "kind", "bundle_manifest_sha256", "core_sha256", "decoder_sha256", "products", "scope", "cleanup"})
    # Android acquisition is not evidence of the historical prewarmed cold run.
    require(type(value["schema"]) is int and value["schema"] in (2, 4))
    schema = value["schema"]
    same(value["success"], True); same(value["kind"], "volparossa-weather-products-protected-cold")
    require(all(hex64(value[k]) for k in ("bundle_manifest_sha256", "core_sha256", "decoder_sha256"))
        and value["decoder_sha256"] == B["decoder_sha"](schema) and set(value["products"]) == set(PRODUCTS))
    for key, item in value["products"].items():
        require(set(item) == {"forecast_sha256", "forecast_bytes", "manifest_id", "cold_receipt_sha256", "acquired_fields", "protected_cold"}
            and all(hex64(item[k]) for k in ("forecast_sha256", "manifest_id", "cold_receipt_sha256"))
            and type(item["forecast_bytes"]) is int and 0 < item["forecast_bytes"] <= MAX_FORECAST)
        p = product(key)
        same(item["acquired_fields"], len(p["steps"]) * len(p["parameters"]))
        transfer = item["protected_cold"]
        require(type(transfer["providers_used"]) is int and transfer["providers_used"] in (1, 2))
        same(transfer, dict(peer_bytes=item["forecast_bytes"], providers_used=transfer["providers_used"],
            origin_body_bytes=0, origin_range_requests=0, privacy_captures_validated=True))
    same(value["scope"], dict(actual_acquisition=True, acquisition_outside_overlay=True, same_publications_joined=True,
        independent_product_captures=True, protected_cold_transfer=True, actual_drizzli_ui=False, actual_http_bridge=False,
        actual_ui_refresh=False, end_to_end_proven=False, browser_triggered_cold_fetch=False,
        two_subflow_bulk_aggregation=False, upstream_signature_attested=False, production_service_complete=False))
    same(value["cleanup"], dict(publisher_sources_removed_before_fetch=True))


def cold_evidence(work, manifest_sha, binary_sha):
    selected, acquired, colds, manifest, _before = validate_cold_phase(work, manifest_sha, binary_sha)
    return cold_summary(selected, acquired, colds, manifest_sha, binary_sha, manifest["version"])


def evidence(work, manifest_sha, binary_sha):
    selected, acquired, colds, manifest, before = validate_cold_phase(work, manifest_sha, binary_sha)
    version = manifest["version"]
    profile = ui_profile(version)
    retained = read(artifact(work, "cold-evidence")); validate_cold_export(retained)
    same(retained, cold_summary(selected, acquired, colds, manifest_sha, binary_sha, version))
    same(read(artifact(work, "input-cleanup")), dict(directory_removed=True, files_removed=True))
    require(all(not path.exists() and not path.is_symlink() for path in
        (work / "client-fixtures/weather-publisher", work / "client-fixtures/weather-viewer")))
    for key, p in PRODUCTS.items():
        after = read(artifact(work, "cache-after", key)); same(before[key], after)
        same(after, cache_state(key, work / "state-client" / p["cache"], after["user_uid"], after["group_gid"]))
    for phase in ("before", "after"):
        same(read(artifact(work, "tree-" + phase)), dict(version=1, action="verify-tree", manifest_sha256=manifest_sha,
            files=len(manifest["files"]), runtime_executed=False))
    report = closed_report(read(artifact(work, "original-report"), 16384))
    same(report["schema"], version)
    same(read(artifact(work, "prepared")), dict(prepared=True,
        expected_sha256=report["expected"]["expected_sha256"], display_sha256=report["expected"]["display_sha256"]))
    require(report["passed"] is True and report["phase"] == "complete" and "failure" not in report)
    same(report["scope"], dict({profile["ui"]: True}, actual_http_bridge=True, real_core_adapter=True,
        synthetic_weather=False, synthetic_air_quality=False, separate_native_runs=True,
        standalone_origin_proven=False, standalone_overlay_proven=False, browser_triggered_cold_fetch=False))
    require(report["source"]["bundle_manifest_sha256"] == manifest_sha and report["expected"]["core_sha256"] == binary_sha)
    for field, relative in (("driver_sha256", profile["driver"]), ("preparer_sha256", profile["preparer"])):
        require(report["source"][field] == manifest["files"][B["WEATHER"] + relative]["sha256"])
    if version == 4:
        proof = report["source"]["synthetic_ui_proof"]
        same(proof["sha256"], manifest["files"][B["WEATHER"] + "integrations/drizzli/hosted-browser-proof.json"]["sha256"])
        same(proof["driver_sha256"], manifest["files"][B["WEATHER"] + "integrations/drizzli/smoke_browser.py"]["sha256"])
    if version == 5:
        for key, retained_name, driver in (("synthetic_ui_proof", "hosted-browser-proof.json", "smoke_browser.py"),
                                     ("synthetic_table_proof", "hosted-table-proof.json", "smoke_table_browser.py")):
            proof = report["source"][key]
            prefix = B["WEATHER"] + "integrations/overmorrow/"
            same(proof["sha256"], manifest["files"][prefix + retained_name]["sha256"])
            same(proof["driver_sha256"], manifest["files"][prefix + driver]["sha256"])
        same(report["source"]["synthetic_table_proof"]["verifier_sha256"],
             manifest["files"][prefix + "hosted-proof/historical-smoke_core_browser_v3.py"]["sha256"])
    for relative, digest in report["source"]["bridge_modules"].items(): require(digest == manifest["files"][B["WEATHER"] + relative]["sha256"])
    require(report["source"]["node_sha256"] == B["NODE_SHA"])
    static = {name[len(profile["static"]):]: item["sha256"] for name, item in manifest["files"].items()
        if name.startswith(profile["static"])}
    require(report["source"]["built_tree_sha256"] == hashlib.sha256(json.dumps(static, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    for key in PRODUCTS:
        item = report["products"][key]; publication = selected["products"][key]["publication"]
        require(item["expected"]["cold_receipt_sha256"] == colds[key]["cold_receipt_sha256"]
            and item["expected"]["forecast_sha256"] == publication["sha256"]
            and item["expected"]["manifest_id"] == publication["manifest_id"])
        same(item["checks"], dict(api_response_sha256=item["checks"]["api_response_sha256"],
            initial_dom_display_sha256=item["expected"]["display_sha256"], refresh_dom_display_sha256=item["expected"]["display_sha256"],
            initial_dom_matches_cold_publication=True, refresh_dom_matches_cold_publication=True, browser_api_requests=2,
            provider_requests_checked=1, exact_native_times_and_values=True, explicit_missing_capabilities=True,
            no_external_resources=True, source_attribution=True))
    same(report["checks"], dict(no_external_resources=True, provider_requests_checked=2, browser_api_requests=4,
        initial_dom_display_sha256=report["expected"]["display_sha256"], refresh_dom_display_sha256=report["expected"]["display_sha256"]))
    same(report["cleanup"], dict(browser_exited=True, bridge_exited=True, private_state_removed=True, normal_browser_stop=True, normal_bridge_stop=True))
    same(report["outer_cleanup"], dict(namespace_wrapper_exited=True, private_state_removed=True, client_namespace_unchanged=True))
    # Raw viewer inputs have already been removed. Acquisition and preparation
    # bound their native times to these queries and the browser's exact hashes.
    # Check future coverage when creating the joined proof, never when merely
    # validating/exporting this historical evidence later.
    observed_at = observed_ms()
    for key in PRODUCTS: future_query(key, selected["products"][key]["query"], observed_at)
    result = dict(schema=version, success=True, kind="volparossa-weather-products-delivery", bundle_manifest_sha256=manifest_sha,
        core_sha256=binary_sha, decoder_sha256=B["decoder_sha"](version), products=retained["products"],
        browser_report_sha256=hashlib.sha256(raw_file(artifact(work, "original-report"))).hexdigest(),
        display_sha256=report["expected"]["display_sha256"],
        scope=dict({profile["ui"]: True}, actual_acquisition=True, same_publications_joined=True, independent_product_captures=True,
            actual_http_bridge=True, actual_ui_refresh=True, end_to_end_proven=True,
            browser_triggered_cold_fetch=False, browser_cache_only_proven=False, two_subflow_bulk_aggregation=False,
            upstream_signature_attested=False, production_service_complete=False),
        cleanup=dict(publisher_sources_removed_before_fetch=True, browser_private_state_removed=True,
            viewer_removed=True, agent_cache_identity_preserved=True, agent_cache_private=True))
    validate_evidence_export(result)
    return result


def validate_evidence_export(value):
    require(set(value) == {"schema", "success", "kind", "bundle_manifest_sha256", "core_sha256", "decoder_sha256", "products",
        "browser_report_sha256", "display_sha256", "scope", "cleanup"})
    same(value["kind"], "volparossa-weather-products-delivery")
    profile = ui_profile(value["schema"])
    require(hex64(value["browser_report_sha256"]) and hex64(value["display_sha256"]))
    cold = {k: v for k, v in value.items() if k not in {"browser_report_sha256", "display_sha256", "scope", "cleanup"}}
    cold.update(schema=4 if value["schema"] in (4, 5) else 2, kind="volparossa-weather-products-protected-cold", scope=dict(actual_acquisition=True,
        acquisition_outside_overlay=True, same_publications_joined=True, independent_product_captures=True,
        protected_cold_transfer=True, actual_drizzli_ui=False, actual_http_bridge=False, actual_ui_refresh=False,
        end_to_end_proven=False, browser_triggered_cold_fetch=False, two_subflow_bulk_aggregation=False,
        upstream_signature_attested=False, production_service_complete=False), cleanup=dict(publisher_sources_removed_before_fetch=True))
    validate_cold_export(cold)
    same(value["scope"], dict({profile["ui"]: True}, actual_acquisition=True, same_publications_joined=True, independent_product_captures=True,
        actual_http_bridge=True, actual_ui_refresh=True, end_to_end_proven=True,
        browser_triggered_cold_fetch=False, browser_cache_only_proven=False, two_subflow_bulk_aggregation=False,
        upstream_signature_attested=False, production_service_complete=False))
    same(value["cleanup"], dict(publisher_sources_removed_before_fetch=True, browser_private_state_removed=True,
        viewer_removed=True, agent_cache_identity_preserved=True, agent_cache_private=True))


def validate_cache_export(value):
    require(set(value) == {"schema", "products"}); same(value["schema"], 2)
    require(set(value["products"]) == set(PRODUCTS))
    for item in value["products"].values():
        require(set(item) == {"device", "inode", "mode", "user_uid", "group_gid"})
        same(item["mode"], "0700")
        require(all(type(v) is int and 0 <= v < 2**64 for k, v in item.items() if k != "mode"))


def validate_export(suffix, value):
    if suffix == "original-report": closed_report(value)
    elif suffix == "cold-evidence": validate_cold_export(value)
    elif suffix == "evidence": validate_evidence_export(value)
    elif suffix == "acquisition": validate_acquisition(value)
    elif suffix in {"cache-before", "cache-after"}: validate_cache_export(value)
    elif suffix == "input-cleanup": same(value, dict(directory_removed=True, files_removed=True))
    elif suffix in {"tree-before", "tree-after"}:
        require(set(value) == {"version", "action", "manifest_sha256", "files", "runtime_executed"})
        same(value["version"], 1); same(value["action"], "verify-tree"); same(value["runtime_executed"], False)
        require(hex64(value["manifest_sha256"]) and type(value["files"]) is int and 0 < value["files"] <= 2048)
    else: raise ValueError("weather_products_export_rejected")


def copy_artifacts(work, output, uid, gid, only_cold=False):
    if only_cold: require(artifact(work, "cold-evidence").exists())
    pending, count = [], 0
    for suffix in (("cold-evidence",) if only_cold else EXPORTS):
        source = artifact(work, suffix)
        if not source.exists(): continue
        raw = raw_file(source, MAX_REPORT); value = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
        validate_export(suffix, value)
        target = output / source.name
        if target.exists() or target.is_symlink():
            require(target.resolve(strict=True) == target)
            with os.fdopen(os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as existing:
                info = os.fstat(existing.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid and info.st_gid == gid
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw))
                require(existing.read(MAX_REPORT+1) == raw and B["identity"](os.fstat(existing.fileno())) == B["identity"](info))
        else:
            B["new_path"](target); pending.append((target, raw))
        count += 1
    for target, raw in pending:
        write_new(target, raw); os.chown(target, uid, gid)
    return dict(files=count, raw_logs_exported=False)


def validate_failure_export_status(value):
    require(type(value) is dict and set(value) == {"schema", "kind", "complete", "success", "exported", "rejected"})
    same(value["schema"], 2); same(value["kind"], "weather-products-failure-export"); same(value["complete"], True)
    for field, allowed in (("exported", set(FAILURE_EXPORTS)), ("rejected", set(FAILURE_EXPORTS) | {"acquisition"})):
        items = value[field]
        require(type(items) is list and len(items) <= len(allowed)
            and all(type(item) is str and item in allowed for item in items) and len(items) == len(set(items)))
    require("acquisition-failure" in value["exported"] and not set(value["exported"]) & set(value["rejected"]))
    same(value["success"], not value["rejected"])


def copy_failure_file(target, raw, uid, gid):
    if target.exists() or target.is_symlink():
        require(target.resolve(strict=True) == target)
        with os.fdopen(os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as existing:
            info = os.fstat(existing.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid and info.st_gid == gid
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw))
            require(existing.read(MAX_REPORT+1) == raw and B["identity"](os.fstat(existing.fileno())) == B["identity"](info))
    else:
        write_new(target, raw); os.chown(target, uid, gid)


def copy_failure_artifacts(work, output, uid, gid):
    # This action is explicitly selected only after acquisition failed. Its
    # trusted-shell marker is mandatory; malformed success output is never an
    # alternative success export. Keep copy_artifacts fully atomic as before.
    marker = artifact(work, "acquisition-failure")
    private(marker, directory=False)
    raw = raw_file(marker, MAX_REPORT, 0o600)
    failure = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
    validate_acquisition_failure(failure)
    copy_failure_file(artifact(output, "acquisition-failure"), raw, uid, gid)
    exported, rejected = ["acquisition-failure"], []
    if failure["diagnostic_state"] != "valid": rejected.append("acquisition")
    for suffix in FAILURE_EXPORTS[1:]:
        source = artifact(work, suffix)
        if not source.exists() and not source.is_symlink(): continue
        try:
            raw = raw_file(source, MAX_REPORT, 0o600)
            value = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
            validate_export(suffix, value)
            copy_failure_file(artifact(output, suffix), raw, uid, gid)
            exported.append(suffix)
        except SAFE_ERRORS:
            rejected.append(suffix)
    result = dict(schema=2, kind="weather-products-failure-export", complete=True,
        success=not rejected, exported=exported, rejected=rejected)
    validate_failure_export_status(result)
    # Written last, allowing the emergency collector to distinguish a complete
    # partial-safe export (exit 1) from a crash/timeout while copying files.
    copy_failure_file(artifact(output, "export-status"), B["encode"](result), uid, gid)
    return result


def main():
    action, *args = sys.argv[1:]
    if action == "init" and len(args) == 1: result = initialize(Path(args[0]))
    elif action == "acquire" and len(args) == 6: result = acquisition(Path(args[0]), args[1], Path(args[2]), args[3], args[4], int(args[5]))
    elif action == "retain-acquisition-failure" and len(args) == 2: result = retain_acquisition_failure(Path(args[0]), int(args[1]))
    elif action == "select" and len(args) == 2: result = select(*map(Path, args))
    elif action == "cold" and len(args) == 8: result = cold(args[0], *map(Path, args[1:5]), args[5], args[6], int(args[7]))
    elif action == "prepare" and len(args) == 6: result = prepare(*map(Path, args))
    elif action == "prepare" and len(args) == 7: result = prepare(*map(Path, args[:6]), int(args[6]))
    elif action in {"publisher-cleanup", "user-cleanup"} and len(args) == 1: result = cleanup(Path(args[0]), action == "publisher-cleanup")
    elif action == "cache-state" and len(args) == 4: result = cache_state(args[0], Path(args[1]), int(args[2]), int(args[3]))
    elif action == "cache-summary" and len(args) == 2: result = cache_summary(Path(args[0]), args[1])
    elif action == "retain" and len(args) == 1: result = retain(Path(args[0]))
    elif action == "cold-evidence" and len(args) == 3: result = cold_evidence(Path(args[0]), args[1], args[2])
    elif action == "evidence" and len(args) == 3: result = evidence(Path(args[0]), args[1], args[2])
    elif action in {"copy-cold-evidence", "copy-artifacts"} and len(args) == 4:
        result = copy_artifacts(Path(args[0]), Path(args[1]), int(args[2]), int(args[3]), only_cold=action == "copy-cold-evidence")
    elif action == "copy-failure-artifacts" and len(args) == 4:
        result = copy_failure_artifacts(Path(args[0]), Path(args[1]), int(args[2]), int(args[3]))
    else: raise ValueError("weather_products_delivery_rejected")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if action == "copy-failure-artifacts" and not result["success"]: raise SystemExit(1)


if __name__ == "__main__":
    try: main()
    except AcquisitionFailure as error:
        print(json.dumps(error.diagnostic, sort_keys=True, separators=(",", ":")))
        raise SystemExit(1)
    except SAFE_ERRORS:
        print('{"success":false,"failure":"weather_products_delivery_rejected"}')
        raise SystemExit(1)
