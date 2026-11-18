#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Joined real Weather acquisition, protected cold receipt and native UI evidence.

Only the explicit disposable topology hook executes these operations. Publication
uses the normal CLI; the browser cannot publish, acquire origin data or see agent
caches. Export only closed summaries, never forecasts, locations, paths or logs.
"""
import datetime
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).parent
B = runpy.run_path(str(HERE / "weather-client-bundle.py"))
HTTPS = runpy.run_path(str(HERE / "content-provider-https-smoke.py"))
NAME = "disposable-public-community-weather"
MAX_FORECAST = 131072
MAX_REPORT = 65536
VARIABLES = ["temperature_2m", "wind_speed_10m", "wind_direction_10m", "precipitation", "air_quality"]
EXPORTS = ("cold-evidence", "evidence", "acquisition", "original-report", "tree-before", "tree-after", "cache-before", "cache-after", "input-cleanup")
require, hex64 = B["require"], B["hex64"]


def same(value, expected):
    require(type(value) is type(expected))
    if type(expected) is dict:
        require(set(value) == set(expected))
        for key in expected: same(value[key], expected[key])
    elif type(expected) is list:
        require(len(value) == len(expected))
        for actual, wanted in zip(value, expected): same(actual, wanted)
    else: require(value == expected)


def raw_file(path, maximum=MAX_REPORT, mode=None):
    stream, info = B["open_checked"](path, maximum, normalized=mode)
    with stream:
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and B["identity"](os.fstat(stream.fileno())) == B["identity"](info))
    return raw


def read(path, maximum=MAX_REPORT, mode=None):
    return json.loads(raw_file(path, maximum, mode), object_pairs_hook=B["B"]["unique_pairs"])


def write_new(path, raw, mode=0o600):
    B["new_path"](path)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as output:
        output.write(raw)


def private(root, directory=True):
    B["B"]["canonical"](root)
    info = root.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
    if not directory: require(info.st_nlink == 1)
    return info


def boundary(parent, client, group, acquisition=False):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    require(os.getuid() == 985 and os.getgid() == group and not os.getgroups()
        and all(int(v) == 985 for v in status["Uid"].split())
        and all(int(v) == group for v in status["Gid"].split())
        and all(int(status[k], 16) == 0 for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        and int(status["NoNewPrivs"]) == 1 and re.fullmatch(r"net:\[\d+\]", parent)
        and re.fullmatch(r"net:\[\d+\]", client) and parent != client
        and os.readlink("/proc/self/ns/net") == (parent if acquisition else client))
    return dict(user_uid=985, primary_control_gid=group, supplementary_groups_empty=True,
        all_capabilities_dropped=True, no_new_privileges=True, client_namespace=not acquisition,
        acquisition_parent_namespace=acquisition)


def run(command, cwd, maximum, timeout):
    """Bound output/time and reap even detached decoder descendants after exit.

    This single-threaded fixture owns all children. A Linux subreaper prevents a
    decoder orphan escaping when its Node parent exits before normal cleanup.
    No process-name matching or unrelated process-group signalling is used.
    """
    children_path = Path(f"/proc/self/task/{os.getpid()}/children")
    require(not children_path.read_text().strip())
    libc = ctypes.CDLL(None, use_errno=True)
    previous_reaper = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(previous_reaper), 0, 0, 0) == 0)
    require(libc.prctl(36, 1, 0, 0, 0) == 0)
    environment = dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8", PYTHONDONTWRITEBYTECODE="1")
    process = None
    data = bytearray(); deadline = time.monotonic() + timeout
    previous = {}
    def interrupted(_signum, _frame): raise ValueError("weather_client_interrupted")
    try:
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, env=environment, start_new_session=True)
        for signum in (signal.SIGINT, signal.SIGTERM): previous[signum] = signal.signal(signum, interrupted)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                require(time.monotonic() < deadline and selector.select(max(0, deadline-time.monotonic())))
                part = os.read(process.stdout.fileno(), min(65536, maximum + 1 - len(data)))
                if not part: break
                data.extend(part); require(len(data) <= maximum)
        require(process.wait(timeout=max(0.1, deadline-time.monotonic())) == 0 and data)
        return bytes(data)
    finally:
        if process is not None and process.poll() is None:
            try: os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=5)
        if process is not None: process.stdout.close()
        cleanup_deadline = time.monotonic() + 5
        while True:
            children = children_path.read_text().split()
            if not children: break
            require(len(children) <= 64 and time.monotonic() < cleanup_deadline)
            for child in children:
                pid = int(child)
                # A live direct child cannot have its PID reused until we reap
                # it. There is no other thread or wait() consumer in this helper.
                if os.waitpid(pid, os.WNOHANG)[0] == 0:
                    try: os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError: pass
            time.sleep(0.01)
        require(libc.prctl(36, previous_reaper.value, 0, 0, 0) == 0)
        for signum, handler in previous.items(): signal.signal(signum, handler)


def initialize(root):
    private(root); require(root.name == "weather-publisher" and not list(root.iterdir()))
    write_new(root / "passphrase", os.urandom(48).hex().encode() + b"\n")
    (root / "scratch").mkdir(mode=0o700)
    return dict(schema=1, initialized=True)


def acquisition(source, manifest_sha, root, parent, client, group):
    private(root); require(root.name == "weather-publisher" and set(p.name for p in root.iterdir()) == {"passphrase", "scratch"})
    boundary(parent, client, group, True)
    B["verify_tree"](source, manifest_sha)
    version = run([str(source / "decoder/grib_ls"), "-V"], root, 4096, 10)
    require(version.strip() == b"ecCodes Version 2.44.0")
    # A prior complete 12UTC cycle, never an implicit alternate service/model retry.
    hour = int(time.time()) // 43200 * 43200 - 43200
    model_run = datetime.datetime.fromtimestamp(hour, datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    command = [str(source / "runtime/node"), "--max-old-space-size=256",
        str(source / B["WEATHER"] / "scripts/forecast.mjs"), "origin", "--latitude", "52.52", "--longitude", "13.41",
        "--run", model_run, "--model", "ifs", "--steps", "3,9,24", "--community-area", "--include-wind",
        "--execute", "--accept-data-license", "--decoder", str(source / "decoder/grib_ls"),
        "--decoder-sha256", B["DECODER_SHA"], "--scratch-parent", str(root / "scratch")]
    raw = run(command, root, MAX_FORECAST, 360)
    value = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
    require(value["schema"] == "volparossa.forecast.v1" and value["source"]["provider"] == "ecmwf"
        and value["source"]["acquisition"] == "origin-https" and value["source"]["model"] == "ifs"
        and value["source"]["model_run_at"] == model_run and value["area"]["sharing"] == "public-community"
        and [sample["lead_hours"] for sample in value["samples"]] == [3, 9, 24]
        and not list((root / "scratch").iterdir()))
    fields = []
    for sample in value["samples"]:
        for field in (sample["evidence"], *sample["wind_10m"]["evidence"].values()):
            require(field["decoder_sha256"] == B["DECODER_SHA"] and field["parameter"] in ("2t", "10u", "10v")
                and hex64(field["index_sha256"]) and hex64(field["field_sha256"]))
            fields.append(dict(lead_hours=sample["lead_hours"], parameter=field["parameter"],
                index_sha256=field["index_sha256"], field_sha256=field["field_sha256"]))
    write_new(root / "forecast.json", raw)
    return dict(schema=1, success=True, origin_https=True, acquisition_outside_overlay=True,
        upstream_signature_attested=False, synthetic_weather=False, forecast_sha256=hashlib.sha256(raw).hexdigest(),
        forecast_bytes=len(raw), decoder_sha256=B["DECODER_SHA"], fields=fields)


def select(root, publish_path, viewer):
    private(root); private(viewer)
    require(root.name == "weather-publisher" and viewer.name == "weather-viewer" and not list(viewer.iterdir()))
    publication = read(publish_path); raw = raw_file(root / "forecast.json", MAX_FORECAST, 0o600)
    forecast = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
    require(publication["operation"] == "offline_content_publish" and publication["network_publication"] is False
        and publication["bytes"] == len(raw) and publication["chunks"] == 1 and hex64(publication["publisher_key_hex"])
        and publication["name"] == NAME and publication["revision"] == 1 and publication["content_type"] == "application/json"
        and publication["manifest_id"] == hashlib.sha256(raw_file(root / "manifest.bin")).hexdigest())
    selected = dict(schema=1, publication=dict(publisher_key=publication["publisher_key_hex"], name=NAME, revision=1,
        manifest_id=hashlib.sha256(raw_file(root / "manifest.bin")).hexdigest(), sha256=hashlib.sha256(raw).hexdigest(),
        bytes=len(raw), expires_unix_seconds=publication["expires_unix_seconds"]),
        query=dict(latitude=forecast["area"]["latitude"], longitude=forecast["area"]["longitude"],
            run=forecast["source"]["model_run_at"], model="ifs", steps=[3, 9, 24], communityArea=True, includeWind=True))
    validate_selection(selected)
    write_new(viewer / "selection.json", B["encode"](selected), 0o400)
    return selected


def validate_selection(value):
    require(type(value) is dict and set(value) == {"schema", "publication", "query"})
    same(value["schema"], 1)
    publication = value["publication"]
    require(type(publication) is dict and set(publication) == {"publisher_key", "name", "revision", "manifest_id", "sha256", "bytes", "expires_unix_seconds"})
    same(publication["name"], NAME); same(publication["revision"], 1)
    require(all(hex64(publication[key]) for key in ("publisher_key", "manifest_id", "sha256"))
        and type(publication["bytes"]) is int and 0 < publication["bytes"] <= MAX_FORECAST
        and type(publication["expires_unix_seconds"]) is int and publication["expires_unix_seconds"] > 0)
    query = value["query"]
    same({k: v for k, v in query.items() if k != "run"}, dict(latitude=52.52, longitude=13.41,
        model="ifs", steps=[3, 9, 24], communityArea=True, includeWind=True))
    require(type(query["run"]) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T(?:00|12):00:00\.000Z", query["run"]))
    return value


def validate_cold_receipt(receipt, publication, cache, output):
    require(all(type(receipt[k]) is int and receipt[k] >= 0 for k in ("revision", "bytes", "publication_expires_unix_seconds",
        "peer_bytes", "providers_used", "origin_body_bytes", "origin_range_requests", "chunks"))
        and type(receipt["provider_peer_ids"]) is list and all(type(peer) is str for peer in receipt["provider_peer_ids"]))
    require(receipt["operation"] == "named_content_download" and all(receipt[key] == publication[key]
        for key in ("publisher_key", "name", "revision", "manifest_id", "sha256", "bytes")))
    require(receipt["publication_expires_unix_seconds"] == publication["expires_unix_seconds"]
        and receipt["cache"] == str(cache) and receipt["local_output"] == str(output)
        and receipt["local_delivery"] is True and receipt["output_mode"] == "0600"
        and receipt["peer_bytes"] == publication["bytes"] and receipt["providers_used"] in (1, 2)
        and len(receipt["provider_peer_ids"]) == len(set(receipt["provider_peer_ids"])) == receipt["providers_used"]
        and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0
        and receipt["chunks"] == 1 and all(receipt[k] is False for k in
            ("ownership_changed", "origin_authenticated", "globally_latest", "cache_only")))


def cold(binary, control, cache, viewer, parent, client, group):
    private(viewer); require(viewer.name == "weather-viewer" and set(p.name for p in viewer.iterdir()) == {"selection.json"})
    process_boundary = boundary(parent, client, group)
    selected = validate_selection(read(viewer / "selection.json", mode=0o400)); publication = selected["publication"]
    output = viewer / "forecast.json"
    binary_before = B["fingerprint"](binary, 256*1024**2)
    raw = run([str(binary), "--control-socket", str(control), "content", "fetch-name", "--publisher-key",
        publication["publisher_key"], "--name", NAME, "--min-revision", "1", "--cache", str(cache),
        "--local-output", str(output), "--quota-bytes", str(MAX_FORECAST), "--max-entries", "16",
        "--min-free-bytes", "67108864"], viewer, MAX_REPORT, 180)
    receipt = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
    validate_cold_receipt(receipt, publication, cache, output)
    content = raw_file(output, MAX_FORECAST, 0o600)
    require(len(content) == publication["bytes"] and hashlib.sha256(content).hexdigest() == publication["sha256"]
        and time.time() < publication["expires_unix_seconds"])
    write_new(viewer / "cold-receipt.json", raw)
    same(B["fingerprint"](binary, 256*1024**2), binary_before)
    return dict(schema=1, boundary=process_boundary, publication=publication, receipt=receipt,
        cold_receipt_sha256=hashlib.sha256(raw).hexdigest(), core_sha256=binary_before["sha256"],
        cold_cache_requested=True, observed_unix_seconds=int(time.time()))


def prepare(source, viewer, binary, control, cache):
    private(viewer)
    selected = validate_selection(read(viewer / "selection.json", mode=0o400)); publication = selected["publication"]
    core_sha = B["fingerprint"](binary, 256*1024**2)["sha256"]
    config = dict(core=dict(mode="core-cache", executable=str(binary), controlSocket=str(control), cache=str(cache),
        scratchParent=str(viewer / "browser-output/scratch"), publisherKey=publication["publisher_key"], name=NAME,
        minRevision=1, query=selected["query"], reuseCache=True), variables=VARIABLES)
    write_new(viewer / "config.json", B["encode"](config))
    result = run([str(source / "runtime/node"), "--max-old-space-size=256",
        str(source / B["WEATHER"] / "integrations/drizzli/prepare-core-browser.mjs"),
        "--forecast", str(viewer / "forecast.json"), "--receipt", str(viewer / "cold-receipt.json"),
        "--config", str(viewer / "config.json"), "--core-sha256", core_sha, "--output", str(viewer / "expected.json")],
        viewer, 4096, 30)
    result = json.loads(result, object_pairs_hook=B["B"]["unique_pairs"])
    require(result["prepared"] is True and hex64(result["expected_sha256"]) and hex64(result["display_sha256"]))
    expected = read(viewer / "expected.json", 192*1024, 0o400)
    same(expected["publication"], publication)
    require(expected["core_sha256"] == core_sha and hashlib.sha256(raw_file(viewer / "expected.json", 192*1024)).hexdigest() == result["expected_sha256"])
    return result


def cache_state(path, uid, gid):
    require(path.name == "weather-cache" and path.parent.name == "state-client" and path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == uid and info.st_gid == gid)
    return dict(device=info.st_dev, inode=info.st_ino, mode="0700", user_uid=uid, group_gid=gid)


def cleanup(root, publisher):
    require(root.name == ("weather-publisher" if publisher else "weather-viewer") and not root.is_symlink())
    if not root.exists(): return dict(directory_removed=True, files_removed=True)
    private(root)
    allowed = {"passphrase", "identity.key", "forecast.json", "manifest.bin", "publish-receipt.json", "source-cache", "scratch"} if publisher else {
        "selection.json", "forecast.json", "cold-receipt.json", "config.json", "expected.json", "browser-output"}
    files, directories, total = [], [], 0
    for path in root.iterdir():
        require(path.name in allowed)
        if path.is_dir():
            private(path); directories.append(path)
            children = list(path.iterdir()); require(len(children) <= 20)
            for child in children:
                require(child.name == "report.json" if path.name == "browser-output" else
                    path.name == "source-cache" and (re.fullmatch(r"[a-f0-9]{64}", child.name)
                    or child.name in (".volparossa-owner-v1", ".volparossa-index-v1")))
                total += len(raw_file(child, MAX_FORECAST)); files.append(child)
        else:
            total += len(raw_file(path, 192*1024)); files.append(path)
    require(total <= 2*1024*1024)
    for path in files: path.unlink()
    for path in directories: path.rmdir()
    root.rmdir()
    return dict(directory_removed=True, files_removed=True)


def validate_packets(cold, peers, layout, route, captures, control):
    receipt = cold["receipt"]; actual = set(receipt["provider_peer_ids"])
    nodes = layout["provider_nodes"]
    require(len(nodes) == len(set(nodes)) == 2 and set(nodes) <= set(HTTPS["CANDIDATES"])
        and actual <= {peers[node] for node in nodes} and receipt["control_relay_peer_id"] == layout["control_relay_peer_id"])
    require(set(captures) == set(HTTPS["ROLES"]))
    for role, capture in captures.items():
        HTTPS["validate_drained"](capture, allow_empty=True)
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
            and all(capture[key] == 0 for key in ("unexpected_outer_packets", "expected_link_down_notifications",
                "unexpected_provider_application_packets", "direct_client_exit_packets"))
            and set(capture["provider_application"]) == set(HTTPS["CANDIDATES"]))
        require(capture["client_public_packets"] == capture["outbound_client_discovery_attempt_packets"] == 0
            if role == "exit" else capture["internet_destination_outer_packets"] == 0)
        for node, counters in capture["provider_application"].items():
            if role == "exit" and node in nodes:
                if peers[node] in actual:
                    require(counters["request_packets"] > 0 and counters["response_packets"] > 0
                        and counters["response_payload_bytes"] >= receipt["bytes"])
            else: require(all(value == 0 for value in counters.values()))
    control_node = next(node for node in HTTPS["PUBLIC_IPS"] if peers[node] == layout["control_relay_peer_id"])
    HTTPS["validate_control"](control, control_node, nodes, False, require_contacts=True)
    paths, slots = route["paths"], route["benchmark_slots"]
    require(route["transport"] == "mptcp" and len(paths) == len(slots) == 2
        and re.fullmatch(r"[a-f0-9]{32}", route["route_context_id"])
        and len({path["relay_peer_id"] for path in paths}) == 2 and {path["exit_peer_id"] for path in paths} == {peers["exit"]}
        and all(path["route_context_id"] == route["route_context_id"] for path in paths)
        and [slot["relay_peer_id"] for slot in slots] == [path["relay_peer_id"] for path in paths]
        and all(slot["relay_node"] in HTTPS["ROLES"][1:4] and peers[slot["relay_node"]] == slot["relay_peer_id"] for slot in slots)
        and {peers[node] for node in nodes}.isdisjoint({peers["client"], peers["exit"], layout["control_relay_peer_id"]}
            | {path["relay_peer_id"] for path in paths})
        and any(captures[slot["relay_node"]]["client_leg_wireguard_data_datagrams"] > 0
            and captures[slot["relay_node"]]["exit_leg_wireguard_data_datagrams"] > 0 for slot in slots))


def closed_report(report):
    require(type(report) is dict and set(report) <= {"schema", "passed", "phase", "source", "expected", "scope", "checks", "cleanup", "outer_cleanup", "failure"})
    same(report["schema"], 1); require(type(report["passed"]) is bool)
    require(report["phase"] in {"inputs", "sandbox", "bridge_start", "provider", "browser_start", "hydration", "refresh", "shutdown", "complete"})
    if "failure" in report: require(report["failure"] in ("interrupted", "check_or_runtime_failed"))
    source = report["source"]
    require(set(source) == {"bundle_manifest_sha256", "driver_sha256", "preparer_sha256", "built_tree_sha256", "node_sha256", "bridge_modules"})
    require(all(hex64(v) for k, v in source.items() if k != "bridge_modules"))
    require(set(source["bridge_modules"]) == {"scripts/serve-provider.mjs", "src/provider-http.mjs", "src/provider-core.mjs", "src/core-cache.mjs"}
        and all(hex64(v) for v in source["bridge_modules"].values()))
    expected = report["expected"]
    require(set(expected) == {"expected_sha256", "cold_receipt_sha256", "core_sha256", "display_sha256", "forecast_sha256", "manifest_id"}
        and all(hex64(v) or (k == "expected_sha256" and v is None) for k, v in expected.items()))
    require(set(report["scope"]) == {"actual_drizzli_ui", "actual_http_bridge", "real_core_adapter", "synthetic_weather",
        "standalone_origin_proven", "standalone_overlay_proven", "browser_triggered_cold_fetch"}
        and all(type(v) is bool for v in report["scope"].values()))
    require(set(report["checks"]) <= {"api_response_sha256", "initial_dom_matches_cold_publication", "refresh_dom_matches_cold_publication",
        "browser_api_requests", "provider_requests_checked", "exact_native_times_and_values", "explicit_missing_capabilities", "no_external_resources", "source_attribution",
        "initial_dom_display_sha256", "refresh_dom_display_sha256"})
    for key, value in report["checks"].items():
        require(hex64(value) if key.endswith("sha256") else type(value) is int and 0 <= value <= 3
            if key.endswith("requests") or key == "provider_requests_checked" else type(value) is bool)
    for name, allowed in (("cleanup", {"browser_exited", "bridge_exited", "private_state_removed", "normal_browser_stop", "normal_bridge_stop"}),
            ("outer_cleanup", {"namespace_wrapper_exited", "private_state_removed", "client_namespace_unchanged"})):
        if name in report:
            require(set(report[name]) <= allowed and all(type(value) is bool for value in report[name].values()))
    return report


def retain(work):
    path = work / "client-fixtures/weather-viewer/browser-output/report.json"
    if not path.exists(): return dict(retained=False)
    raw = worker_report(path); closed_report(json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"]))
    write_new(work / "weather-client-delivery-original-report.json", raw)
    return dict(retained=True, sha256=hashlib.sha256(raw).hexdigest())


def worker_report(path):
    # Only this exact private worker output crosses into root-owned evidence.
    require(path.parts[-4:] == ("client-fixtures", "weather-viewer", "browser-output", "report.json"))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 985 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 16384)
        raw = stream.read(16385)
        require(len(raw) == info.st_size and B["identity"](os.fstat(stream.fileno())) == B["identity"](info))
    return raw


def validate_acquisition(value):
    same({k: v for k, v in value.items() if k not in ("forecast_sha256", "forecast_bytes", "fields")},
        dict(schema=1, success=True, origin_https=True, acquisition_outside_overlay=True,
            upstream_signature_attested=False, synthetic_weather=False, decoder_sha256=B["DECODER_SHA"]))
    require(hex64(value["forecast_sha256"]) and type(value["forecast_bytes"]) is int and 0 < value["forecast_bytes"] <= MAX_FORECAST
        and type(value["fields"]) is list and len(value["fields"]) == 9)
    coverage = []
    for field in value["fields"]:
        require(set(field) == {"lead_hours", "parameter", "index_sha256", "field_sha256"}
            and type(field["lead_hours"]) is int and field["lead_hours"] in (3, 9, 24)
            and field["parameter"] in ("2t", "10u", "10v") and hex64(field["index_sha256"]) and hex64(field["field_sha256"]))
        coverage.append((field["lead_hours"], field["parameter"]))
    require(set(coverage) == {(step, parameter) for step in (3, 9, 24) for parameter in ("2t", "10u", "10v")})


def validate_publications(work, publication, nodes):
    published = read(work / "weather-client-delivery-publish.json")
    require(published["operation"] == "offline_content_publish" and published["network_publication"] is False
        and published["publisher_key_hex"] == publication["publisher_key"] and published["content_type"] == "application/json"
        and published["chunks"] == 1 and all(published[k] == publication[k] for k in
            ("name", "revision", "bytes", "manifest_id", "expires_unix_seconds")))
    for node in nodes:
        imported = read(work / f"weather-client-delivery-{node}-import.json")
        served = read(work / f"weather-client-delivery-{node}-serve.json")
        require(imported["operation"] == "content_import" and imported["complete"] is True
            and imported["manifest_id"] == publication["manifest_id"] and imported["content_bytes"] == publication["bytes"]
            and imported["agent_cache"] == str(work / f"state-{node}/weather-cache") and imported["public_content"] is True
            and all(imported[k] is False for k in ("ownership_changed", "network_transfer", "origin_authenticated"))
            and served["serving"] is True and type(served["publications"]) is int and served["publications"] == 4
            and served["replication_enabled"] is False)


def validate_cold_phase(work, manifest_sha, binary_sha):
    """Full cold-phase join, independent of whether a browser ever starts.

    The final join calls the same validator again; retaining this earlier proof
    must not turn a later browser failure into successful end-to-end evidence.
    """
    require(hex64(binary_sha))
    selected = validate_selection(read(work / "weather-client-delivery-input.json")); publication = selected["publication"]
    acquisition = read(work / "weather-client-delivery-acquisition.json")
    validate_acquisition(acquisition)
    require(acquisition["forecast_sha256"] == publication["sha256"]
        and acquisition["forecast_bytes"] == publication["bytes"])
    cold = read(work / "weather-client-delivery-cold-consumer.json")
    same(cold["publication"], publication)
    validate_cold_receipt(cold["receipt"], publication, work / "state-client/weather-cache", work / "client-fixtures/weather-viewer/forecast.json")
    same(cold["cold_cache_requested"], True); require(cold["core_sha256"] == binary_sha)
    same(cold["schema"], 1)
    require(hex64(cold["cold_receipt_sha256"]) and type(cold["observed_unix_seconds"]) is int
        and 0 < cold["observed_unix_seconds"] < publication["expires_unix_seconds"])
    control_gid = (work / "runtime-client/control/agent.sock").stat().st_gid
    same(cold["boundary"], dict(user_uid=985, primary_control_gid=control_gid, supplementary_groups_empty=True,
        all_capabilities_dropped=True, no_new_privileges=True, client_namespace=True, acquisition_parent_namespace=False))
    peers, layout = read(work / "a01-expected-peers.json"), read(work / "content-provider-layout.json")
    validate_publications(work, publication, layout["provider_nodes"])
    validate_packets(cold, peers, layout, read(work / "weather-client-delivery-selection.json"),
        {role: read(work / f"weather-client-delivery-privacy-{role}.json") for role in HTTPS["ROLES"]},
        read(work / "weather-client-delivery-control.json"))
    same(read(work / "weather-client-delivery-publisher-cleanup.json"), dict(directory_removed=True, files_removed=True))
    publisher = work / "client-fixtures/weather-publisher"
    require(not publisher.exists() and not publisher.is_symlink())
    before = read(work / "weather-client-delivery-cache-before.json")
    same(before, cache_state(work / "state-client/weather-cache", before["user_uid"], before["group_gid"]))
    require(before["user_uid"] != 985 and cold["boundary"]["primary_control_gid"] != before["group_gid"])
    # Retained by root before UID985 receives the input tree. This binds the
    # acquisition source/runtime pins without requiring a later UI report.
    manifest = B["manifest"](raw_file(work / "weather-client-delivery-manifest.json", B["MAX_MANIFEST"], 0o400), manifest_sha)
    same(read(work / "weather-client-delivery-tree-before.json"), dict(version=1, action="verify-tree",
        manifest_sha256=manifest_sha, files=len(manifest["files"]), runtime_executed=False))
    return publication, acquisition, cold, manifest, before


def cold_summary(publication, acquisition, cold, manifest_sha, binary_sha):
    result = dict(schema=1, success=True, kind="volparossa-weather-protected-cold",
        bundle_manifest_sha256=manifest_sha, core_sha256=binary_sha,
        forecast_sha256=publication["sha256"], forecast_bytes=publication["bytes"],
        manifest_id=publication["manifest_id"], cold_receipt_sha256=cold["cold_receipt_sha256"],
        decoder_sha256=acquisition["decoder_sha256"], acquired_fields=len(acquisition["fields"]),
        protected_cold=dict(peer_bytes=cold["receipt"]["peer_bytes"], providers_used=cold["receipt"]["providers_used"],
            origin_body_bytes=0, origin_range_requests=0, privacy_captures_validated=True),
        scope=dict(actual_acquisition=True, acquisition_outside_overlay=True, same_publication_joined=True,
            protected_cold_transfer=True, actual_drizzli_ui=False, actual_http_bridge=False, actual_ui_refresh=False,
            end_to_end_proven=False, browser_triggered_cold_fetch=False, two_subflow_bulk_aggregation=False,
            upstream_signature_attested=False, production_service_complete=False),
        cleanup=dict(publisher_sources_removed_before_fetch=True))
    validate_cold_export(result)
    return result


def validate_cold_export(value):
    """Exact closed schema: no paths, names, coordinates, peers or raw receipts."""
    require(type(value) is dict and set(value) == {"schema", "success", "kind", "bundle_manifest_sha256",
        "core_sha256", "forecast_sha256", "forecast_bytes", "manifest_id", "cold_receipt_sha256",
        "decoder_sha256", "acquired_fields", "protected_cold", "scope", "cleanup"})
    same(value["schema"], 1); same(value["success"], True)
    same(value["kind"], "volparossa-weather-protected-cold")
    require(all(hex64(value[key]) for key in ("bundle_manifest_sha256", "core_sha256", "forecast_sha256",
        "manifest_id", "cold_receipt_sha256", "decoder_sha256")) and value["decoder_sha256"] == B["DECODER_SHA"]
        and type(value["forecast_bytes"]) is int and 0 < value["forecast_bytes"] <= MAX_FORECAST)
    same(value["acquired_fields"], 9)
    transfer = value["protected_cold"]
    require(type(transfer) is dict and type(transfer.get("providers_used")) is int and transfer["providers_used"] in (1, 2))
    same(transfer, dict(peer_bytes=value["forecast_bytes"], providers_used=transfer["providers_used"],
        origin_body_bytes=0, origin_range_requests=0, privacy_captures_validated=True))
    same(value["scope"], dict(actual_acquisition=True, acquisition_outside_overlay=True, same_publication_joined=True,
        protected_cold_transfer=True, actual_drizzli_ui=False, actual_http_bridge=False, actual_ui_refresh=False,
        end_to_end_proven=False, browser_triggered_cold_fetch=False, two_subflow_bulk_aggregation=False,
        upstream_signature_attested=False, production_service_complete=False))
    same(value["cleanup"], dict(publisher_sources_removed_before_fetch=True))


def cold_evidence(work, manifest_sha, binary_sha):
    publication, acquisition, cold, _manifest, _before = validate_cold_phase(work, manifest_sha, binary_sha)
    return cold_summary(publication, acquisition, cold, manifest_sha, binary_sha)


def evidence(work, manifest_sha, binary_sha):
    publication, acquisition, cold, manifest, before = validate_cold_phase(work, manifest_sha, binary_sha)
    retained_cold = read(work / "weather-client-delivery-cold-evidence.json")
    validate_cold_export(retained_cold)
    same(retained_cold, cold_summary(publication, acquisition, cold, manifest_sha, binary_sha))
    same(read(work / "weather-client-delivery-input-cleanup.json"), dict(directory_removed=True, files_removed=True))
    require(all(not path.exists() and not path.is_symlink() for path in
        (work / "client-fixtures/weather-publisher", work / "client-fixtures/weather-viewer")))
    after = read(work / "weather-client-delivery-cache-after.json")
    same(before, after); same(after, cache_state(work / "state-client/weather-cache", after["user_uid"], after["group_gid"]))
    require(after["user_uid"] != 985 and cold["boundary"]["primary_control_gid"] != after["group_gid"])
    # A root-owned manifest was retained before the verified tree was handed to
    # UID985. Worker verify-tree receipts check that tree before and after use;
    # root never weakens owner checks or grants access to private agent caches.
    checked = dict(manifest_sha256=manifest_sha, files=len(manifest["files"]), runtime_executed=False)
    for phase in ("before", "after"):
        same(read(work / f"weather-client-delivery-tree-{phase}.json"), dict(version=1, action="verify-tree", **checked))
    report = closed_report(read(work / "weather-client-delivery-original-report.json", 16384))
    same(read(work / "weather-client-delivery-prepared.json"), dict(prepared=True,
        expected_sha256=report["expected"]["expected_sha256"], display_sha256=report["expected"]["display_sha256"]))
    require(report["passed"] is True and report["phase"] == "complete" and "failure" not in report)
    same(report["scope"], dict(actual_drizzli_ui=True, actual_http_bridge=True, real_core_adapter=True,
        synthetic_weather=False, standalone_origin_proven=False, standalone_overlay_proven=False, browser_triggered_cold_fetch=False))
    require(report["source"]["bundle_manifest_sha256"] == manifest_sha and report["expected"]["core_sha256"] == binary_sha
        and report["expected"]["cold_receipt_sha256"] == cold["cold_receipt_sha256"]
        and report["expected"]["forecast_sha256"] == acquisition["forecast_sha256"] == publication["sha256"]
        and acquisition["forecast_bytes"] == publication["bytes"] and report["expected"]["manifest_id"] == publication["manifest_id"])
    for field, relative in (("driver_sha256", "integrations/drizzli/smoke_core_browser.py"),
            ("preparer_sha256", "integrations/drizzli/prepare-core-browser.mjs")):
        require(report["source"][field] == manifest["files"][B["WEATHER"] + relative]["sha256"])
    for relative, digest in report["source"]["bridge_modules"].items(): require(digest == manifest["files"][B["WEATHER"] + relative]["sha256"])
    require(report["source"]["node_sha256"] == B["NODE_SHA"])
    static = {name[len(B["STATIC"]):]: item["sha256"] for name, item in manifest["files"].items() if name.startswith(B["STATIC"])}
    require(report["source"]["built_tree_sha256"] == hashlib.sha256(json.dumps(static, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    same(report["checks"], dict(api_response_sha256=report["checks"]["api_response_sha256"],
        initial_dom_display_sha256=report["expected"]["display_sha256"], refresh_dom_display_sha256=report["expected"]["display_sha256"],
        initial_dom_matches_cold_publication=True, refresh_dom_matches_cold_publication=True, browser_api_requests=2,
        provider_requests_checked=1, exact_native_times_and_values=True, explicit_missing_capabilities=True,
        no_external_resources=True, source_attribution=True))
    same(report["cleanup"], dict(browser_exited=True, bridge_exited=True, private_state_removed=True, normal_browser_stop=True, normal_bridge_stop=True))
    same(report["outer_cleanup"], dict(namespace_wrapper_exited=True, private_state_removed=True, client_namespace_unchanged=True))
    return dict(schema=1, success=True, kind="volparossa-weather-client-delivery", bundle_manifest_sha256=manifest_sha,
        core_sha256=binary_sha, publication=publication, acquisition=acquisition,
        protected_cold=dict(peer_bytes=cold["receipt"]["peer_bytes"], providers_used=cold["receipt"]["providers_used"],
            origin_body_bytes=0, origin_range_requests=0, privacy_captures_validated=True, cold_receipt_sha256=cold["cold_receipt_sha256"]),
        browser_report_sha256=hashlib.sha256(raw_file(work / "weather-client-delivery-original-report.json")).hexdigest(),
        scope=dict(actual_acquisition=True, same_publication_joined=True, actual_ui_refresh=True,
            browser_triggered_cold_fetch=False, browser_cache_only_proven=False, two_subflow_bulk_aggregation=False,
            upstream_signature_attested=False, production_service_complete=False),
        cleanup=dict(publisher_sources_removed_before_fetch=True, browser_private_state_removed=True,
            viewer_removed=True, agent_cache_identity_preserved=True, agent_cache_private=True))


def copy_artifacts(work, output, uid, gid, only_cold=False):
    # Closed identifiers only; original page/forecast/receipt/paths never cross this boundary.
    # The earlier cold-only export is independent of later UI receipt failures.
    # Full export still prevalidates every candidate and never replaces a file.
    if only_cold: require((work / "weather-client-delivery-cold-evidence.json").exists())
    pending = []; count = 0
    for suffix in (("cold-evidence",) if only_cold else EXPORTS):
        source = work / f"weather-client-delivery-{suffix}.json"
        if not source.exists(): continue
        raw = raw_file(source, MAX_REPORT); value = json.loads(raw, object_pairs_hook=B["B"]["unique_pairs"])
        if suffix == "original-report": closed_report(value)
        elif suffix == "cold-evidence": validate_cold_export(value)
        else: validate_export(value)
        target = output / source.name
        if target.exists() or target.is_symlink():
            require(target.resolve(strict=True) == target)
            with os.fdopen(os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as existing:
                info = os.fstat(existing.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid and info.st_gid == gid
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw))
                require(existing.read(MAX_REPORT+1) == raw and B["identity"](os.fstat(existing.fileno())) == B["identity"](info))
        else:
            B["new_path"](target)
            pending.append((target, raw))
        count += 1
    # Reject every candidate before creating the first exported artifact.
    for target, raw in pending:
        write_new(target, raw); os.chown(target, uid, gid)
    return dict(files=count, raw_logs_exported=False)


EXPORT_FIELDS = {"schema", "version", "success", "kind", "bundle_manifest_sha256", "core_sha256", "publication", "publisher_key",
    "name", "revision", "manifest_id", "sha256", "bytes", "expires_unix_seconds", "acquisition", "origin_https",
    "acquisition_outside_overlay", "upstream_signature_attested", "synthetic_weather", "forecast_sha256", "forecast_bytes",
    "decoder_sha256", "fields", "lead_hours", "parameter", "index_sha256", "field_sha256", "protected_cold", "peer_bytes",
    "providers_used", "origin_body_bytes", "origin_range_requests", "privacy_captures_validated", "cold_receipt_sha256",
    "browser_report_sha256", "scope", "actual_acquisition", "same_publication_joined", "actual_ui_refresh",
    "browser_triggered_cold_fetch", "browser_cache_only_proven", "two_subflow_bulk_aggregation", "production_service_complete",
    "cleanup", "publisher_sources_removed_before_fetch", "browser_private_state_removed", "viewer_removed",
    "agent_cache_identity_preserved", "agent_cache_private", "device", "inode", "mode", "user_uid", "group_gid",
    "directory_removed", "files_removed", "action", "manifest_sha256", "files", "runtime_executed"}


def validate_export(value, depth=0):
    require(depth <= 8)
    if type(value) is dict:
        require(set(value) <= EXPORT_FIELDS)
        for child in value.values(): validate_export(child, depth+1)
    elif type(value) is list:
        require(len(value) <= 16)
        for child in value: validate_export(child, depth+1)
    elif type(value) is str:
        require(hex64(value) or value in {NAME, "volparossa-weather-client-delivery", "verify-tree", "0700", "2t", "10u", "10v"})
    else: require(type(value) is bool or type(value) is int and 0 <= value < 2**64)


def main():
    action, *args = sys.argv[1:]
    if action == "init" and len(args) == 1: result = initialize(Path(args[0]))
    elif action == "acquire" and len(args) == 6: result = acquisition(Path(args[0]), args[1], Path(args[2]), args[3], args[4], int(args[5]))
    elif action == "select" and len(args) == 3: result = select(*map(Path, args))
    elif action == "cold" and len(args) == 7: result = cold(*map(Path, args[:4]), args[4], args[5], int(args[6]))
    elif action == "prepare" and len(args) == 5: result = prepare(*map(Path, args))
    elif action in ("publisher-cleanup", "user-cleanup") and len(args) == 1: result = cleanup(Path(args[0]), action == "publisher-cleanup")
    elif action == "cache-state" and len(args) == 3: result = cache_state(Path(args[0]), int(args[1]), int(args[2]))
    elif action == "retain" and len(args) == 1: result = retain(Path(args[0]))
    elif action == "cold-evidence" and len(args) == 3: result = cold_evidence(Path(args[0]), args[1], args[2])
    elif action == "evidence" and len(args) == 3: result = evidence(Path(args[0]), args[1], args[2])
    elif action == "copy-cold-evidence" and len(args) == 4: result = copy_artifacts(Path(args[0]), Path(args[1]), int(args[2]), int(args[3]), only_cold=True)
    elif action == "copy-artifacts" and len(args) == 4: result = copy_artifacts(Path(args[0]), Path(args[1]), int(args[2]), int(args[3]))
    else: raise ValueError("weather_client_delivery_rejected")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError):
        print('{"success":false,"failure":"weather_client_delivery_rejected"}')
        raise SystemExit(1)
