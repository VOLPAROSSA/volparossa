#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed joins for the Android profile, not standalone network acceptance.

Original CLI stdout is inspected only inside the disposable guest. HTTP bodies
are hashed in the owner tunnel, never copied into public evidence. Matching these
records still requires the separate source, process, capture and cleanup gates.
"""
import datetime
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

PROFILE = "android-protected-core-v6"
PRODUCTS = ("weather", "air_quality")
ROUTES = dict(zip(("/api/volparossa/forecast", "/api/volparossa/air-quality"), PRODUCTS))
NAMES = dict(zip(PRODUCTS, ("disposable-public-community-weather", "disposable-public-community-air-quality")))
CACHES = dict(zip(PRODUCTS, ("weather-cache", "air-quality-cache")))
MAX_BODY = 256 * 1024
MAX_RECEIPT = 16384
HEX = re.compile(r"[a-f0-9]{64}")
PEER = re.compile(r"[1-9A-HJ-NP-Za-km-z]{1,128}")
PUBLICATION_KEYS = {"publisher_key", "name", "revision", "manifest_id", "sha256", "expires_unix_seconds"}
RECEIPT_KEYS = {"operation", "bytes", "chunks", "publisher_key", "name", "revision", "manifest_id",
    "publication_expires_unix_seconds", "sha256", "local_delivery", "output_mode", "ownership_changed",
    "origin_authenticated", "globally_latest", "peer_bytes", "providers_used", "origin_body_bytes",
    "origin_range_requests", "provider_peer_ids", "control_relay_peer_id", "cache_only", "cache", "local_output"}
TRANSFER_KEYS = {"product", "ordinal", "stdout_sha256", "observation_sha256", "started_at_ms", "completed_at_ms",
    "reuse_cache", "forecast_sha256", "forecast_bytes", "peer_bytes", "providers_used", "origin_body_bytes", "origin_range_requests"}
PREFIX = "weather-android-delivery"
GUEST_FAILURE_CODES = dict(zip(("boundary", "source", "prepared", "selection", "configuration",
    "api-lifecycle", "api-private-cleanup", "receipt-custody", "receipt-shape", "receipt-timing",
    "receipt-publication", "receipt-counters", "acquisition", "topology-inputs", "cache-custody",
    "publication-files", "packet-control-route", "publisher-cleanup", "source-snapshot", "export-shape"), range(20, 40)))


class GuestVerificationFailure(ValueError):
    """A fixed rejected check group, not the private exception or root cause."""
    def __init__(self, stage):
        if stage not in GUEST_FAILURE_CODES: raise ValueError("weather_android_unknown_check_group")
        self.stage = stage
        super().__init__("weather_android_evidence_rejected")


@contextmanager
def guest_group(stage):
    if stage not in GUEST_FAILURE_CODES: raise ValueError("weather_android_unknown_check_group")
    try:
        yield
    except (GuestVerificationFailure, TimeoutError, InterruptedError):
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise GuestVerificationFailure(stage) from None


def require(value):
    if not value:
        raise ValueError("weather_android_evidence_rejected")


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def integer(value, low=0, high=2**53 - 1):
    require(type(value) is int and low <= value <= high)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def hashes(value, keys):
    require(all(type(value[key]) is str and HEX.fullmatch(value[key]) for key in keys))


def same(value, expected):
    # Do not accept bools in place of numbers in otherwise equal JSON objects.
    require(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        == json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False))


def decode(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_constant):
        raise ValueError("weather_android_nonfinite_json")
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique, parse_constant=invalid)


def publication(value, key, *, size=False):
    require(key in PRODUCTS)
    exact(value, PUBLICATION_KEYS | ({"bytes"} if size else set()))
    hashes(value, ("publisher_key", "manifest_id", "sha256"))
    same(value["name"], NAMES[key]); same(value["revision"], 1)
    integer(value["expires_unix_seconds"], 1, 253402300799)
    if size: integer(value["bytes"], 1, MAX_BODY)


def response_observation(route, ordinal, raw):
    """Observe original fixed-length HTTP bytes before forwarding them unchanged."""
    require(route in ROUTES)
    integer(ordinal, 1, 3)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BODY + 8192)
    header, separator, body = raw.partition(b"\r\n\r\n")
    require(separator and len(header) <= 8192)
    lines = header.decode("ascii", errors="strict").split("\r\n")
    same(lines[0], "HTTP/1.1 200 OK")
    fields = {}
    for line in lines[1:]:
        require(":" in line and not line.startswith((" ", "\t")))
        name, value = line.split(":", 1)
        require(re.fullmatch(r"[A-Za-z0-9-]+", name) and name.lower() not in fields
            and all(32 <= ord(char) < 127 or char == "\t" for char in value))
        fields[name.lower()] = value.strip()
    require(re.fullmatch(r"[1-9][0-9]{0,5}", fields.get("content-length", ""))
        and int(fields["content-length"]) == len(body) <= MAX_BODY
        and re.fullmatch(r"application/json(?:;\s*charset=utf-8)?", fields.get("content-type", ""), re.I)
        and not set(fields) & {"transfer-encoding", "content-encoding", "set-cookie"})
    value = decode(body, MAX_BODY)
    require(type(value) is dict and type(value.get("delivery")) is dict)
    delivery = value["delivery"]
    exact(delivery, PUBLICATION_KEYS - {"expires_unix_seconds"} | {"mode", "publication_expires_at", "freshness",
        "upstream_origin_attested", "manifest_media_type_checked"})
    same(delivery["mode"], "core-cache")
    same(delivery["upstream_origin_attested"], False); same(delivery["manifest_media_type_checked"], False)
    expiry = delivery["publication_expires_at"]
    require(type(expiry) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z", expiry))
    seconds = int(datetime.datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S.000Z")
        .replace(tzinfo=datetime.timezone.utc).timestamp())
    binding = {key: delivery[key] for key in PUBLICATION_KEYS - {"expires_unix_seconds"}}
    binding["expires_unix_seconds"] = seconds
    publication(binding, ROUTES[route])
    result = dict(schema=6, kind="weather-android-http-observation", product=ROUTES[route], ordinal=ordinal,
        body_bytes=len(body), body_sha256=digest(body), publication=binding, joined_core_acceptance=False)
    validate_response(result)
    return result


def validate_response(value):
    exact(value, ("schema", "kind", "product", "ordinal", "body_bytes", "body_sha256", "publication", "joined_core_acceptance"))
    same(value["schema"], 6); same(value["kind"], "weather-android-http-observation")
    publication(value["publication"], value["product"])
    integer(value["ordinal"], 1, 3); integer(value["body_bytes"], 1, MAX_BODY)
    hashes(value, ("body_sha256",)); same(value["joined_core_acceptance"], False)


def receipt_observation(raw, observation_raw, key, ordinal, selected, work, window):
    """Validate original private bytes; callers must also prove file/worker custody."""
    with guest_group("receipt-shape"):
        publication(selected, key, size=True)
        integer(ordinal, 1, 3)
        receipt = decode(raw, MAX_RECEIPT); exact(receipt, RECEIPT_KEYS)
        observation = decode(observation_raw, 2048)
        exact(observation, ("schema", "kind", "profile", "product", "ordinal", "started_at_ms", "completed_at_ms",
            "reuse_cache", "stdout_bytes", "stdout_sha256"))
        same(observation["schema"], 1); same(observation["kind"], "weather-android-core-receipt-observation")
        same(observation["profile"], PROFILE); same(observation["product"], key); same(observation["ordinal"], ordinal)
        same(observation["reuse_cache"], ordinal > 1)
        same(observation["stdout_bytes"], len(raw)); same(observation["stdout_sha256"], digest(raw))
    with guest_group("receipt-timing"):
        require(type(window) in (tuple, list) and len(window) == 2)
        start, end = window
        integer(start, 1); integer(end, start)
        integer(observation["started_at_ms"], start, end)
        integer(observation["completed_at_ms"], observation["started_at_ms"], min(end, observation["started_at_ms"] + 185000))
        require(observation["completed_at_ms"] < selected["expires_unix_seconds"] * 1000)
    with guest_group("receipt-publication"):
        for field in ("publisher_key", "name", "revision", "manifest_id", "sha256", "bytes"):
            same(receipt[field], selected[field])
        same(receipt["publication_expires_unix_seconds"], selected["expires_unix_seconds"])
        same(receipt["operation"], "named_content_download"); same(receipt["chunks"], 1)
        same(receipt["local_delivery"], True); same(receipt["output_mode"], "0600")
        for field in ("ownership_changed", "origin_authenticated", "globally_latest", "cache_only"):
            same(receipt[field], False)
        same(receipt["origin_body_bytes"], 0); same(receipt["origin_range_requests"], 0)
        work = Path(work)
        require(work.is_absolute() and str(work) == str(Path(str(work))) and ".." not in work.parts)
        same(receipt["cache"], str(work / "weather-android-cache" / CACHES[key]))
        output = receipt["local_output"]
        require(type(output) is str and re.fullmatch(re.escape(str(work / "client-fixtures/weather-viewer/scratch"))
            + r"/forecast-[A-Za-z0-9]{6}/forecast\.json", output))
    with guest_group("receipt-counters"):
        peers = receipt["provider_peer_ids"]
        require(type(peers) is list and all(type(peer) is str and PEER.fullmatch(peer) for peer in peers))
        integer(receipt["providers_used"], 0, 2)
        same(len(peers), receipt["providers_used"]); require(len(set(peers)) == len(peers))
        relay = receipt["control_relay_peer_id"]
        require(type(relay) is str and (relay == "" or PEER.fullmatch(relay)) and relay not in peers)
        if ordinal == 1:
            same(receipt["peer_bytes"], selected["bytes"])
            require(receipt["providers_used"] in (1, 2) and relay != "")
        else:
            same(receipt["peer_bytes"], 0); same(receipt["providers_used"], 0); same(peers, [])
    return dict(product=key, ordinal=ordinal, stdout_sha256=digest(raw), observation_sha256=digest(observation_raw),
        started_at_ms=observation["started_at_ms"], completed_at_ms=observation["completed_at_ms"],
        reuse_cache=ordinal > 1, forecast_sha256=selected["sha256"], forecast_bytes=selected["bytes"],
        peer_bytes=receipt["peer_bytes"], providers_used=receipt["providers_used"], origin_body_bytes=0, origin_range_requests=0)


def join_observations(report, transfers, responses, publications):
    """Match six real operations to UI observations; no standalone acceptance flag."""
    require(type(report) is dict and type(transfers) is dict and type(responses) is list
        and len(responses) == 6 and set(transfers) == set(publications) == set(PRODUCTS))
    same(report["schema"], 2); same(report["kind"], "overmorrow-installed-android-protected-core-trial")
    same(report["profile"], "protected-core"); same(report["joined_core_acceptance"], False)
    same(report["passed"], True); same(report["phase"], "complete")
    same(report["package"], "org.volparossa.weather.trial")
    same(report["scope"], dict(installed_android_app=True, mounted_widget_tables=True, real_adb_interaction=True,
        pixel_visibility_proven=False, synthetic_weather=False, synthetic_air_quality=False, core_executed=False,
        overlay_proven=False, physical_device=False, production_authority=False, expiry_proven=False))
    same(report["checks"], dict(initial_exact_native_rows=True, actual_tap_refresh=True, third_refresh_exact_native_rows=True,
        real_android_background_resume=True, original_products_fresh_after_resume=True, no_extra_product_requests=True))
    same(report["cleanup"], dict(app_stopped=True, forward_removed=True, vm_closed=True))
    observations = report["observations"]
    same(observations["requests"], dict(weather=3, air_quality=3))
    indexed = {}
    for response in responses:
        validate_response(response)
        key, ordinal = response["product"], response["ordinal"]
        require((key, ordinal) not in indexed)
        indexed[key, ordinal] = response
    result = {}
    for key in PRODUCTS:
        selected = publications[key]; publication(selected, key, size=True)
        rows = transfers[key]; require(type(rows) is list and len(rows) == 3)
        completed = 0
        for ordinal, (phase, row) in enumerate(zip(("initial", "refresh", "before_background"), rows), 1):
            exact(row, TRANSFER_KEYS)
            same(row["product"], key); same(row["ordinal"], ordinal)
            same(row["forecast_sha256"], selected["sha256"]); same(row["forecast_bytes"], selected["bytes"])
            hashes(row, ("stdout_sha256", "observation_sha256"))
            integer(row["started_at_ms"], completed); integer(row["completed_at_ms"], row["started_at_ms"])
            completed = row["completed_at_ms"]
            same(row["reuse_cache"], ordinal > 1)
            same(row["peer_bytes"], selected["bytes"] if ordinal == 1 else 0)
            integer(row["providers_used"], 1 if ordinal == 1 else 0, 2 if ordinal == 1 else 0)
            same(row["origin_body_bytes"], 0); same(row["origin_range_requests"], 0)
            response = indexed[key, ordinal]
            same(response["publication"], {field: selected[field] for field in PUBLICATION_KEYS})
            fetched = observations[phase]
            exact(fetched, (*PRODUCTS, "response_sha256")); exact(fetched["response_sha256"], PRODUCTS)
            same(fetched["response_sha256"][key], response["body_sha256"])
            table = fetched[key]; exact(table, ("rows", "table_sha256", "product_sha256"))
            same(table["rows"], 4 if key == "weather" else 5); hashes(table, ("table_sha256", "product_sha256"))
            # Production sends JSON.stringify(result), and the pinned observer
            # hashes JSON.stringify(the parsed original object), byte-equivalent.
            same(table["product_sha256"], response["body_sha256"])
        exact(observations["after_resume"], PRODUCTS)
        same(observations["after_resume"][key], observations["before_background"][key])
        binding = observations["bindings"][key]
        exact(binding, ("forecast_sha256", "immutable_product_sha256")); hashes(binding, binding)
        same(binding["forecast_sha256"], selected["sha256"])
        result[key] = dict(forecast_sha256=selected["sha256"], manifest_id=selected["manifest_id"],
            cold_receipt_sha256=rows[0]["stdout_sha256"], original_receipts=[row["stdout_sha256"] for row in rows],
            response_sha256=[indexed[key, i]["body_sha256"] for i in (1, 2, 3)],
            cold_peer_bytes=selected["bytes"], warm_peer_bytes=0, requests=3, native_rows=4 if key == "weather" else 5)
    return dict(schema=6, kind="weather-android-observation-join", profile=PROFILE, products=result,
        matched_original_receipts_and_http_and_ui=True, joined_core_acceptance=False, expiry_proven=False)


def private_bytes(path, limit, uid, mode=0o600):
    """Read one stable private regular inode; never follow links or read FIFOs."""
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= limit)
        def identity(info):
            return tuple(getattr(info, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))
        require(identity(before) == identity(path.lstat()))
        chunks, total = [], 0
        while total <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - total))
            if not chunk: break
            chunks.append(chunk); total += len(chunk)
        require(total == before.st_size and identity(os.fstat(descriptor)) == identity(before)
            and identity(path.lstat()) == identity(before) and path.resolve(strict=True) == path)
        return b"".join(chunks)
    finally: os.close(descriptor)


def proof_receipts(directory, selected, work, window, uid=985):
    directory = Path(directory)
    require(directory.resolve(strict=True) == directory)
    before = directory.lstat()
    require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700 and before.st_uid == uid)
    expected = {f"{key}-{ordinal}.{suffix}.json" for key in PRODUCTS for ordinal in (1, 2, 3)
        for suffix in ("receipt", "observation")}
    same({path.name for path in directory.iterdir()} == expected, True)
    transfers, raw_receipts, seen = {}, {}, set()
    for key in PRODUCTS:
        transfers[key], raw_receipts[key] = [], []
        for ordinal in (1, 2, 3):
            raw = private_bytes(directory / f"{key}-{ordinal}.receipt.json", MAX_RECEIPT, uid)
            metadata = private_bytes(directory / f"{key}-{ordinal}.observation.json", 2048, uid)
            item = receipt_observation(raw, metadata, key, ordinal, selected[key], work, window)
            require(item["stdout_sha256"] not in seen); seen.add(item["stdout_sha256"])
            transfers[key].append(item); raw_receipts[key].append(decode(raw, MAX_RECEIPT))
    after = directory.lstat()
    require(tuple(getattr(before, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_mtime_ns", "st_ctime_ns"))
        == tuple(getattr(after, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_mtime_ns", "st_ctime_ns"))
        and {path.name for path in directory.iterdir()} == expected and directory.resolve(strict=True) == directory)
    return transfers, raw_receipts


def guest(work, manifest_sha, core_sha, prepared_sha):
    """Run only after the owned API/sink and capture processes are joined."""
    with guest_group("boundary"):
        require(os.geteuid() == 0)
        api = runpy.run_path(str(Path(__file__).with_name("weather-android-api.py")))
        D, P, B = api["D"], api["P"], api["B"]
        layout = D["paths"](work)
        group = layout["control"].stat().st_gid
        agent_uid, agent_gid = D["accounts"](group)
        D["validate_work"](work, agent_gid)
        for value in (manifest_sha, core_sha, prepared_sha): require(type(value) is str and HEX.fullmatch(value))
    def root_document(name, limit=65536, mode=0o600):
        return decode(private_bytes(work / name, limit, 0, mode), limit)
    with guest_group("source"):
        manifest_raw = private_bytes(work / "weather-products-delivery-manifest.json", B["MAX_MANIFEST"], 0, 0o400)
        manifest = B["manifest"](manifest_raw, manifest_sha); same(manifest["version"], 6)
        B["verify_android_worker_tree"](layout["source"], manifest_sha)
        same(B["fingerprint"](layout["binary"], 256 * 1024**2, normalized=0o555)["sha256"], core_sha)
    with guest_group("prepared"):
        prepared_raw = private_bytes(work / f"{PREFIX}-prepared.json", 8192, 0)
        same(digest(prepared_raw), prepared_sha)
        require(private_bytes(layout["viewer"] / "prepared.json", 8192, 985, 0o400) == prepared_raw)
        prepared = decode(prepared_raw, 8192); D["validate_prepared"](prepared)
        same(prepared["manifest_sha256"], manifest_sha); same(prepared["core_sha256"], core_sha)
    with guest_group("selection"):
        selected_raw = private_bytes(layout["viewer"] / "selection.json", 16384, 985, 0o400)
        same(digest(selected_raw), prepared["selection_sha256"])
        selected = P["validate_selection"](decode(selected_raw, 16384))
        same(root_document("weather-products-delivery-input.json"), selected)
    with guest_group("configuration"):
        config_raw = private_bytes(layout["config"], 16384, 985)
        same(digest(config_raw), prepared["config_sha256"])
        require(config_raw == B["encode"](D["configuration"](layout, selected)))
    with guest_group("api-lifecycle"):
        lifecycle_raw = private_bytes(work / f"{PREFIX}-api.jsonl", 16384, 0)
        lines = lifecycle_raw.splitlines(); require(len(lines) == 2)
        ready, final = [decode(line, 8192) for line in lines]
        for record in (ready, final):
            api["validate_record"](record)
            same(record["manifest_sha256"], manifest_sha); same(record["prepared_sha256"], prepared_sha)
        same(ready["kind"], "weather-android-api-ready"); same(final["kind"], "weather-android-api-final")
        same(ready["core_sha256"], core_sha); same(ready["config_sha256"], prepared["config_sha256"])
        same(final["success"], True); same(final["retained_files"], 12)
    with guest_group("api-private-cleanup"):
        D["absent"](layout["socket"])
        for name in ("scratch", "socket"):
            D["owned"](layout["viewer"] / name, stat.S_ISDIR, 0o700, 985)
            same(list((layout["viewer"] / name).iterdir()), [])
    with guest_group("receipt-custody"):
        publications = {key: selected["products"][key]["publication"] for key in PRODUCTS}
        transfers, receipts = proof_receipts(layout["proof"], publications, work,
            (ready["ready_at_ms"], min(ready["expires_at"] * 1000 - 1, int(time.time() * 1000))))
    with guest_group("acquisition"):
        acquisition_raw = private_bytes(work / "weather-products-delivery-acquisition.json", 65536, 0)
        acquisition = decode(acquisition_raw, 65536); P["validate_acquisition"](acquisition, 6)
    with guest_group("topology-inputs"):
        peers = root_document("a01-expected-peers.json"); provider_layout = root_document("content-provider-layout.json")
        captures = {role: root_document(f"{PREFIX}-privacy-{role}.json") for role in P["HTTPS"]["ROLES"]}
        control = root_document(f"{PREFIX}-control.json"); route = root_document(f"{PREFIX}-selection.json")
    with guest_group("cache-custody"):
        D["owned"](layout["cache_parent"], stat.S_ISDIR, 0o710, agent_uid, group)
    for key in PRODUCTS:
        with guest_group("publication-files"):
            publication(publications[key], key, size=True)
            item = acquisition["products"][key]
            same(item["forecast_sha256"], publications[key]["sha256"]); same(item["forecast_bytes"], publications[key]["bytes"])
            P["validate_publications"](work, publications[key], provider_layout["provider_nodes"], key)
        with guest_group("packet-control-route"):
            # Both products share this capture window. Never relabel it as two
            # independent captures; original per-product CLI counters remain required.
            P["V1"]["validate_packets"](dict(receipt=receipts[key][0]), peers, provider_layout, route, captures, control)
        with guest_group("cache-custody"):
            D["owned"](layout["cache_parent"] / CACHES[key], stat.S_ISDIR, 0o700, agent_uid, agent_gid)
    with guest_group("publisher-cleanup"):
        same(root_document("weather-products-delivery-publisher-cleanup.json"), dict(directory_removed=True, files_removed=True))
        D["absent"](work / "client-fixtures/weather-publisher")
    with guest_group("source-snapshot"):
        same(root_document("weather-products-delivery-tree-before.json"), dict(version=1, action="verify-tree",
            manifest_sha256=manifest_sha, files=len(manifest["files"]), runtime_executed=False))
    with guest_group("export-shape"):
        result = dict(schema=6, kind="weather-android-guest-evidence", profile=PROFILE,
            manifest_sha256=manifest_sha, core_sha256=core_sha, prepared_sha256=prepared_sha,
            acquisition_sha256=digest(acquisition_raw), api_lifecycle_sha256=digest(lifecycle_raw),
            publications=publications, transfers=transfers, capture_scope="common-product-window",
            captures_validated=True, source_acquisition_validated=True, cold_caches_absent_before_api_requests=True,
            publisher_originals_removed=True, helper_requests=0, api_and_sink_joined=True, scratch_outputs_removed=True,
            private_receipts_exported=False, private_viewer_retained_until_vm_destruction=True,
            native_android_proven=False, joined_core_acceptance=False, expiry_proven=False)
        validate_guest_export(result)
    return result


def validate_guest_export(value):
    fields = {"schema", "kind", "profile", "manifest_sha256", "core_sha256", "prepared_sha256", "acquisition_sha256",
        "api_lifecycle_sha256", "publications", "transfers", "capture_scope", "captures_validated",
        "source_acquisition_validated", "cold_caches_absent_before_api_requests", "publisher_originals_removed",
        "helper_requests", "api_and_sink_joined", "scratch_outputs_removed", "private_receipts_exported",
        "private_viewer_retained_until_vm_destruction", "native_android_proven", "joined_core_acceptance", "expiry_proven"}
    exact(value, fields); same(value["schema"], 6); same(value["kind"], "weather-android-guest-evidence")
    same(value["profile"], PROFILE); same(value["capture_scope"], "common-product-window"); same(value["helper_requests"], 0)
    hashes(value, ("manifest_sha256", "core_sha256", "prepared_sha256", "acquisition_sha256", "api_lifecycle_sha256"))
    for name in ("captures_validated", "source_acquisition_validated", "cold_caches_absent_before_api_requests",
            "publisher_originals_removed", "api_and_sink_joined", "scratch_outputs_removed", "private_viewer_retained_until_vm_destruction"):
        same(value[name], True)
    for name in ("private_receipts_exported", "native_android_proven", "joined_core_acceptance", "expiry_proven"):
        same(value[name], False)
    exact(value["publications"], PRODUCTS); exact(value["transfers"], PRODUCTS)
    seen = set()
    for key in PRODUCTS:
        selected = value["publications"][key]; publication(selected, key, size=True)
        rows = value["transfers"][key]; require(type(rows) is list and len(rows) == 3)
        completed = 0
        for ordinal, row in enumerate(rows, 1):
            exact(row, TRANSFER_KEYS); same(row["product"], key); same(row["ordinal"], ordinal)
            hashes(row, ("stdout_sha256", "observation_sha256", "forecast_sha256"))
            require(row["stdout_sha256"] not in seen); seen.add(row["stdout_sha256"])
            same(row["forecast_sha256"], selected["sha256"]); same(row["forecast_bytes"], selected["bytes"])
            integer(row["started_at_ms"], max(1, completed))
            integer(row["completed_at_ms"], row["started_at_ms"], min(row["started_at_ms"] + 185000,
                selected["expires_unix_seconds"] * 1000 - 1)); completed = row["completed_at_ms"]
            same(row["reuse_cache"], ordinal > 1); same(row["origin_body_bytes"], 0); same(row["origin_range_requests"], 0)
            same(row["peer_bytes"], selected["bytes"] if ordinal == 1 else 0)
            integer(row["providers_used"], 1 if ordinal == 1 else 0, 2 if ordinal == 1 else 0)


def copy_artifacts(work, output, uid, gid):
    require(os.geteuid() == 0 and output.resolve(strict=True) == output and output.is_dir())
    integer(uid, 1, 2**32 - 1); integer(gid, 1, 2**32 - 1)
    source = work / f"{PREFIX}-evidence.json"
    if not source.exists() and not source.is_symlink():
        return dict(files=0, raw_logs_exported=False, acceptance_evidence_missing=True)
    raw = private_bytes(source, 65536, 0)
    validate_guest_export(decode(raw, 65536))
    P = runpy.run_path(str(Path(__file__).with_name("weather-products-delivery.py")))
    P["copy_failure_file"](output / source.name, raw, uid, gid)
    return dict(files=1, raw_logs_exported=False, acceptance_evidence_missing=False)


def main():
    action, *args = sys.argv[1:]
    if action == "guest" and len(args) == 4:
        result = guest(Path(args[0]), *args[1:])
    elif action == "copy-artifacts" and len(args) == 4:
        result = copy_artifacts(Path(args[0]), Path(args[1]), int(args[2]), int(args[3]))
    else: raise ValueError("weather_android_evidence_command")
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


def command_status(command):
    """Exit statuses are closed observations, never private exception text."""
    try:
        command()
        return 0
    except GuestVerificationFailure as error:
        status = GUEST_FAILURE_CODES[error.stage]
    except TimeoutError:
        status = 124
    except InterruptedError:
        status = 125
    except KeyboardInterrupt:
        status = 130
    except Exception:
        status = 1
    print("weather_android_evidence_failed", file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(command_status(main))
