#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed joined-proof checker/launcher, only for the disposable provider fixture.

No cache seeding, agent mutation, replacement broker reply or model execution.
The enclosing topology retains ownership of source/runtime/output cleanup.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

HERE = Path(__file__).parent
FILTER = runpy.run_path(str(HERE / "content-provider-filter-smoke.py"))
BUNDLE = runpy.run_path(str(HERE / "browser-filter-bundle.py"))
TEXT, SHA, NAME = FILTER["TEXT"], FILTER["SHA"], FILTER["NAME"]
OPERATIONS = ("open", "fetch", "enroll", "suspend", "optOut", "retry", "close")
CASES = ("baseline", "enrolled", "suspended", "opted_out", "retry")
SCOPE = dict(real_core_broker=True, real_gecko_unix_ipc=True, positive_verified_publication=True,
    original_signed_ubo=True, actual_background_asset_request=True, actual_engine_probes=True,
    existing_agent_required=True, browser_sessions=1, protected_peer_fetch_proven=False,
    cold_cache_proven=False, native_admission_registered=False, production_default_enrollment=False,
    startup_resume_stale_filter_barrier=False, real_os_expiry=False)
MAX_REPORT = 65536
DIAGNOSTIC_PHASES = {
    "arguments", "stage", "packages", "sources", "expected", "binary", "control",
    "topology_guest", "topology_init", "topology_root", "topology_unit", "topology_namespace", "topology_peer",
    "output_path", "output_prepare", "binary_copy", "wrapper_inputs", "home", "wrapper",
    "cleanup_profile", "cleanup_binary", "cleanup_receipt",
}
DIAGNOSTIC_KEYS = {"schema", "success", "phase", "cleanup_failed"}
BROWSER_DIAGNOSTIC_KEYS = {"schema", "phase", "error_kind", "cleanup_failed"}
BROWSER_PHASES = {
    "log_open", "spawn", "log_drain", "connect", "greeting", "session", "context", "runtime_check",
    "preference_check", "addon_check", "fixture_server", "baseline_selection", "baseline_probe", "exercise",
    "selection", "probe", "final_addon_check", "final_preference_check", "quit", "join", "cleanup",
}
BROWSER_ERROR_KINDS = {"check_failed", "timeout", "io_error", "command_error", "interrupted", "other"}
PROTOCOL_ERROR_KINDS = {"webdriver_error", "unexpected_envelope", "framing_error", "eof", "timeout", "transport_error"}
WEBDRIVER_CODES = {"session_not_created", "invalid_argument", "unknown_command", "unknown_error",
    "unsupported_operation", "invalid_session_id", "no_such_window", "timeout", "script_timeout", "other"}
# Must match the Browser driver's closed source map for pinned ESR 140.16.0.
RUNTIME_SOURCE_LINES = {
    "marionette/driver.sys.mjs": 3886, "marionette/server.sys.mjs": 460,
    "shared/WindowManager.sys.mjs": 595, "shared/NavigationManager.sys.mjs": 860,
    "shared/webdriver/Capabilities.sys.mjs": 1075, "shared/webdriver/Errors.sys.mjs": 978,
    "shared/webdriver/Session.sys.mjs": 489, "webdriver-bidi/NewSessionHandler.sys.mjs": 55,
}
REPORT_KEYS = {"schema", "passed", "scope", "operation", "receipts", "probes", "module_sha256", "driver_sha256",
    "broker_sha256", "expected", "runtime_version", "runtime_source_stamp", "runtime_sha256", "extension_packages",
    "failure", "host_read_only", "interfaces", "browser_exit_status", "broker_cleanup", "broker_socket_removed",
    "temporary_profiles_removed", "logs", "failure_phase", "browser_diagnostic"}
EXPORT_KEYS = {
    "original-report": REPORT_KEYS,
    "original-outer-cleanup": {"schema", "temporary_profiles_removed", "broker_copy_removed", "logs"},
    "original-diagnostic": DIAGNOSTIC_KEYS,
    "evidence": {"version", "kind", "success", "bundle_manifest_sha256", "core_broker_sha256", "originals_sha256",
                 "publication", "protected_cold", "browser", "scope", "cleanup"},
    "prepared": {"version", "expected", "created_unix_seconds", "maximum_authority_seconds"},
    "cache-before": {"device", "inode", "mode", "user_uid", "group_gid"},
    "cache-after": {"device", "inode", "mode", "user_uid", "group_gid"},
    "launch": {"version", "boundary"},
    "tree-before": {"version", "action", "transferred", "runtime_executed", "manifest_sha256", "files", "private_output_inspected"},
    "tree-after": {"version", "action", "transferred", "runtime_executed", "manifest_sha256", "files", "private_output_inspected"},
    "input-cleanup": {"directory_removed", "files_removed"},
    "retained": {"version", "originals_sha256", "successful_native_execution_claimed"},
}
EXPORT_FIELDS = set().union(*EXPORT_KEYS.values(), SCOPE, OPERATIONS, CASES, {
    "schema", "status", "choice", "state", "closed", "failed", "result", "attempted", "receipt", "selected", "imported",
    "preserved", "freshReload", "reloadEvents", "delivery", "asset", "broker_revoked", "bytes", "sha256", "rules",
    "manifest_id", "publisher_key", "name", "authority_expires_unix_seconds", "accepted", "completed", "denied",
    "ok", "phase", "error_kind", "ads", "tracker", "neutral", "started", "reaped", "graceful", "broker", "id", "size",
    "unpacked_bytes", "zip_entries", "report", "outer-cleanup", "diagnostic", "content_type", "peer_bytes", "providers_used",
    "privacy_captures_validated", "exit_status", "same_publication_joined", "broker_reuse_requested", "broker_cache_only_proven",
    "new_broker_peer_transfer_proven", "two_subflow_bulk_aggregation", "browser_profile_removed", "broker_reaped",
    "fixture_authority_removed", "separate_owner_input_removed", "agent_cache_identity_preserved", "agent_cache_private",
    "staged_inputs_removed_by_enclosing_topology", "primary_control_gid", "supplementary_groups_empty", "client_namespace",
    "outside_parent_namespace", "all_capabilities_dropped", "no_new_privileges",
    "protocol_error", "webdriver_code", "source_frames", "module", "line",
    *("integration/filters/" + name + ".sys.mjs" for name in BUNDLE["MODULES"]),
    "tests/fixtures/filter_delivery.sys.mjs", "firefox-esr", "libxul.so", "omni.ja", "browser/omni.ja"})
EXPORT_WORDS = {"complete", "prepare", "browser_start", "browser_quit", "broker_start", "command", "bootstrap", *OPERATIONS,
    "eligible", "opted-out", "fresh", "pending", "active", "suspended", "lo", "0700", "verify-tree", NAME,
    "text/plain", "volparossa-browser-filter-delivery", "uBlock0@raymondhill.net", "jid1-BoFifL9Vbdl2zQ@jetpack",
    "ATBC@EasonWong", "gdpr@cavi.au.dk", "fixture_command", "fixture_failed", "fixture_cleanup", "fixture_clock",
    "fixture_other", "invalid_request", "duplicate_request", "handshake_required", "busy", "unavailable", "revoked",
    "clock_error", "expired", "invalid_snapshot", "invalid_response", "not_configured", "owner_config", "owner_context",
    "owner_clock", "owner_busy", "owner_closed", "owner_failed", "owner_cleanup", "asset_config", "asset_package",
    "asset_context", "asset_authority", "asset_expired", "asset_clock", "asset_busy", "asset_closed", "asset_failed", "asset_cleanup",
    *DIAGNOSTIC_PHASES, *BROWSER_PHASES, *BROWSER_ERROR_KINDS,
    *PROTOCOL_ERROR_KINDS, *WEBDRIVER_CODES, *RUNTIME_SOURCE_LINES}


def require(condition):
    if not condition: raise ValueError("browser_filter_delivery_rejected")


def same(value, expected):
    require(type(value) is type(expected))
    if type(expected) is dict:
        require(set(value) == set(expected))
        for key in expected: same(value[key], expected[key])
    elif type(expected) is list:
        require(len(value) == len(expected))
        for item, other in zip(value, expected): same(item, other)
    else: require(value == expected)


def hex64(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def raw_file(path, limit=MAX_REPORT):
    require(path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022
            and 0 <= info.st_size <= limit)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size))
        raw = stream.read(limit + 1)
    require(len(raw) == info.st_size)
    return raw


def read(path):
    return json.loads(raw_file(path), object_pairs_hook=BUNDLE["unique_pairs"])


def write_new(path, raw):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400), "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def validate_diagnostic(value):
    require(type(value) is dict and set(value) == DIAGNOSTIC_KEYS
            and type(value["schema"]) is int and value["schema"] == 1
            and value["success"] is False and type(value["cleanup_failed"]) is bool
            and type(value["phase"]) is str and value["phase"] in DIAGNOSTIC_PHASES)


def validate_protocol_error(value):
    require(type(value) is dict and set(value) == {"kind", "webdriver_code", "source_frames"}
            and type(value["kind"]) is str and value["kind"] in PROTOCOL_ERROR_KINDS
            and type(value["source_frames"]) is list and len(value["source_frames"]) <= 8)
    if value["kind"] != "webdriver_error":
        require(value["webdriver_code"] is None and value["source_frames"] == [])
        return
    require(type(value["webdriver_code"]) is str and value["webdriver_code"] in WEBDRIVER_CODES)
    seen = set()
    for frame in value["source_frames"]:
        require(type(frame) is dict and set(frame) == {"module", "line"}
                and type(frame["module"]) is str and frame["module"] in RUNTIME_SOURCE_LINES
                and type(frame["line"]) is int and 1 <= frame["line"] <= RUNTIME_SOURCE_LINES[frame["module"]])
        pair = (frame["module"], frame["line"])
        require(pair not in seen); seen.add(pair)


def validate_report_diagnostic(report):
    # Older reports have no browser subphase. A new diagnostic is failure-only,
    # and must never turn baseline checks into a claim that Firefox did not start.
    if "browser_diagnostic" not in report:
        return
    value = report["browser_diagnostic"]
    require(report.get("passed") is False and type(value) is dict
            and set(value) in (BROWSER_DIAGNOSTIC_KEYS, BROWSER_DIAGNOSTIC_KEYS | {"protocol_error"})
            and type(value["schema"]) is int and value["schema"] == 1
            and type(value["phase"]) is str and value["phase"] in BROWSER_PHASES
            and type(value["error_kind"]) is str and value["error_kind"] in BROWSER_ERROR_KINDS
            and type(value["cleanup_failed"]) is bool)
    if "protocol_error" in value: validate_protocol_error(value["protocol_error"])


def private_root(root):
    require(root.name == "browser-filter-delivery" and root.resolve(strict=True) == root)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.getuid() and info.st_gid == os.getgid())


def selection(value):
    require(type(value) is dict and set(value) == {"name", "content_type", "bytes", "sha256", "rules", "publisher_key", "manifest_id"})
    same({key: value[key] for key in ("name", "content_type", "bytes", "sha256", "rules")},
         dict(name=NAME, content_type="text/plain", bytes=len(TEXT), sha256=SHA, rules=2))
    require(all(hex64(value[key]) and value[key] != "0" * 64 for key in ("publisher_key", "manifest_id")))
    return value


def prepare(root, publication_expiry):
    private_root(root)
    require({path.name for path in root.iterdir()} == {"selection.json", "home"})
    require(not list((root / "home").iterdir()))
    chosen = selection(read(root / "selection.json"))
    now = int(time.time())
    require(type(publication_expiry) is int and now < publication_expiry <= 2**53 - 1)
    expected = dict(publisher_key=chosen["publisher_key"], name=chosen["name"], manifest_id=chosen["manifest_id"],
                    authority_expires_unix_seconds=min(publication_expiry, now + 600))
    write_new(root / "expected.json", json.dumps(expected, sort_keys=True, separators=(",", ":")).encode())
    return dict(version=1, expected=expected, created_unix_seconds=now, maximum_authority_seconds=600)


def cleanup(root):
    require(root.name == "browser-filter-delivery" and not root.is_symlink())
    if not root.exists(): return dict(directory_removed=True, files_removed=True)
    private_root(root)
    require({path.name for path in root.iterdir()} <= {"selection.json", "expected.json", "diagnostic.json", "home"})
    files = []
    for path in root.iterdir():
        info = path.lstat()
        require(info.st_uid == os.getuid() and info.st_gid == os.getgid())
        if path.name == "home":
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and not list(path.iterdir()))
        else:
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o400
                    and info.st_nlink == 1 and info.st_size <= 1024)
            if path.name == "diagnostic.json": validate_diagnostic(read(path))
            files.append(path)
    for path in files: path.unlink()
    if (root / "home").exists(): (root / "home").rmdir()
    root.rmdir()
    return dict(directory_removed=True, files_removed=True)


def process_boundary(parent, client, uid, control):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    require(uid == 985 and os.readlink("/proc/self/ns/net") == client != parent
            and all(int(value) == uid for value in status["Uid"].split())
            and all(int(value) == control for value in status["Gid"].split())
            and status["Groups"].strip() == ""
            and all(int(status[key], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            and int(status["NoNewPrivs"]) == 1)
    return dict(user_uid=uid, primary_control_gid=control, supplementary_groups_empty=True,
                client_namespace=True, outside_parent_namespace=True, all_capabilities_dropped=True, no_new_privileges=True)


def launch(arguments):
    directory, input_directory, binary, binary_sha, control_socket, cache, parent, client, uid, group = arguments
    source, root = Path(directory), Path(input_directory)
    private_root(root)
    require(source == root.parent / "browser-filter-source" and source.resolve(strict=True) == source
            and Path.home() == root / "home" and hex64(binary_sha))
    boundary = process_boundary(parent, client, int(uid), int(group))
    print(json.dumps(dict(version=1, boundary=boundary), sort_keys=True), flush=True)
    # Replace this inspected process; no changed credential or hidden wrapper
    # exists between the observation and the reviewed Browser driver.
    os.execv(sys.executable, [sys.executable, "-B", str(source / "scripts/smoke_filter_delivery.py"),
        "--execute", "--stage", str(source / "build/firefox-filter-runtime"),
        "--output", str(source / "build/filter-delivery"), "--broker", binary, "--broker-sha256", binary_sha,
        "--control-socket", control_socket, "--agent-cache", cache, "--expected", str(root / "expected.json"),
        "--diagnostic-output", str(root / "diagnostic.json")])


def cache_state(path, uid, gid):
    require(path.name == "filter-cache" and path.parent.name == "state-client" and path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == uid and info.st_gid == gid)
    return dict(device=info.st_dev, inode=info.st_ino, mode="0700", user_uid=uid, group_gid=gid)


def operation_receipt(operation, expected):
    choice = "opted-out" if operation in ("optOut", "retry", "close") else "eligible"
    state = "fresh" if operation in ("open", "fetch") else "active" if operation == "enroll" else "suspended"
    result = None
    if operation in ("enroll", "suspend", "optOut", "retry"):
        result = dict(schema=1, choice=choice, state=state, attempted=operation != "retry", receipt=None)
        if operation != "retry":
            result["receipt"] = dict(selected=operation == "enroll", imported=operation == "enroll",
                                     preserved=True, freshReload=True, reloadEvents=2)
    return dict(schema=1, ok=True, phase=operation, status=dict(schema=1, choice=choice, state=state,
        closed=operation == "close", failed=False), result=result,
        delivery=None if operation == "open" else dict(bytes=len(TEXT), sha256=SHA, rules=2, manifest_id=expected["manifest_id"]),
        asset=None if operation in ("open", "fetch") else dict(closed=True, accepted=1, completed=1, denied=0),
        broker_revoked=operation in ("suspend", "optOut", "retry", "close"))


def validate_browser(report, outer, expected, manifest, stage, binary_sha):
    fixed = dict(schema=1, passed=True, scope=SCOPE, operation="complete", failure=None,
        expected=expected, broker_sha256=binary_sha, host_read_only=True, interfaces=["lo"], browser_exit_status=0,
        broker_cleanup=dict(started=True, reaped=True, graceful=True), broker_socket_removed=True,
        temporary_profiles_removed=True,
        receipts={operation: operation_receipt(operation, expected) for operation in OPERATIONS},
        probes={case: {kind: 0 if case == "enrolled" and kind != "neutral" else 1 for kind in ("ads", "tracker", "neutral")}
                for case in CASES})
    files = manifest["files"]
    fixed.update(driver_sha256=files["scripts/smoke_filter_delivery.py"]["sha256"],
        module_sha256={name: record["sha256"] for name, record in files.items()
                       if name.startswith("integration/filters/") or name == "tests/fixtures/filter_delivery.sys.mjs"},
        runtime_version=stage["version"], runtime_source_stamp=stage["source_stamp"],
        runtime_sha256=stage["runtime_sha256"], extension_packages=stage["extensions"]["packages"])
    require(type(report) is dict and set(report) == set(fixed) | {"logs"})
    for key, value in fixed.items(): same(report[key], value)
    logs = report["logs"]
    require(type(logs) is dict and set(logs) == {"browser", "broker"})
    for value in logs.values():
        require(type(value) is dict and set(value) == {"bytes", "sha256"} and type(value["bytes"]) is int
                and 0 <= value["bytes"] <= 4 * 1024 * 1024 and hex64(value["sha256"]))
    same(outer, dict(schema=1, temporary_profiles_removed=True, broker_copy_removed=True, logs=logs))


def validate_cold(evidence):
    selection(evidence["input"])
    FILTER["validate_application"](evidence, evidence["cold"]["application"], False)
    FILTER["validate_packets"](evidence, evidence["cold"], False)
    route, peers, layout = evidence["selected_route"], evidence["expected_peers"], evidence["layout"]
    paths, slots = route["paths"], route["benchmark_slots"]
    require(route["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and re.fullmatch(r"[0-9a-f]{32}", route["route_context_id"])
            and len({path["relay_peer_id"] for path in paths}) == 2
            and {path["exit_peer_id"] for path in paths} == {peers["exit"]}
            and all(path["route_context_id"] == route["route_context_id"] for path in paths)
            and [slot["relay_peer_id"] for slot in slots] == [path["relay_peer_id"] for path in paths]
            and all(slot["relay_node"] in FILTER["ROLES"][1:4] and peers[slot["relay_node"]] == slot["relay_peer_id"] for slot in slots)
            and {peers[node] for node in layout["provider_nodes"]}.isdisjoint(
                {peers["client"], peers["exit"], layout["control_relay_peer_id"]} | {path["relay_peer_id"] for path in paths})
            and any(evidence["cold"]["privacy"][slot["relay_node"]]["client_leg_wireguard_data_datagrams"] > 0
                    and evidence["cold"]["privacy"][slot["relay_node"]]["exit_leg_wireguard_data_datagrams"] > 0 for slot in slots))
    same(evidence["publisher_cleanup"], dict(directory_removed=True, files_removed=True))


def retain(work):
    """Preserve original closed receipts on failure too; absence is not success."""
    output = work / "client-fixtures/browser-filter-source/build/filter-delivery"
    retained = {}
    for name, keys in (("report", REPORT_KEYS), ("outer-cleanup", {"schema", "temporary_profiles_removed", "broker_copy_removed", "logs"}),
                       ("diagnostic", DIAGNOSTIC_KEYS)):
        path = (work / "client-fixtures/browser-filter-delivery" if name == "diagnostic" else output) / (name + ".json")
        if not path.exists() and not path.is_symlink(): continue
        raw = raw_file(path)
        value = json.loads(raw, object_pairs_hook=BUNDLE["unique_pairs"])
        require(type(value) is dict and set(value) <= keys and type(value.get("schema")) is int and value["schema"] == 1)
        if name == "report": validate_report_diagnostic(value)
        if name == "diagnostic": validate_diagnostic(value)
        target = work / ("browser-filter-delivery-original-" + name + ".json")
        if target.exists(): require(raw_file(target) == raw)
        else: write_new(target, raw)
        retained[name] = hashlib.sha256(raw).hexdigest()
    return dict(version=1, originals_sha256=retained, successful_native_execution_claimed=False)


def export_value(value, depth=0, field=None):
    """Only the fixture's closed fields/scalars, never raw errors, paths or logs."""
    require(depth <= 12)
    if type(value) is dict:
        require(len(value) <= 64 and set(value) <= EXPORT_FIELDS)
        for key, child in value.items(): export_value(child, depth + 1, key)
    elif type(value) is list:
        require(len(value) <= 16)
        for child in value: export_value(child, depth + 1, field)
    elif type(value) is str:
        require(value in EXPORT_WORDS or hex64(value) or re.fullmatch(r"[0-9a-f]{40}", value)
                or (field in {"version", "runtime_version"}
                    and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}", value)))
    else:
        require(value is None or type(value) is bool or (type(value) is int and 0 <= value < 2**64))


def copy_artifacts(work, output, uid, gid):
    require(work.resolve(strict=True) == work and output.resolve(strict=True) == output and work != output)
    require(output.is_dir() and not output.lstat().st_mode & 0o002 and uid >= 0 and gid >= 0)
    pending, missing = {}, []
    # Validate the complete available set before copying anything. Empty files
    # can result from a command which failed before emitting JSON; never turn
    # that absence into a successful-native-execution claim.
    for suffix, keys in EXPORT_KEYS.items():
        name = "browser-filter-delivery-" + suffix + ".json"
        source = work / name
        if not source.exists() and not source.is_symlink(): missing.append(suffix); continue
        raw = raw_file(source)
        if not raw: missing.append(suffix); continue
        value = json.loads(raw, object_pairs_hook=BUNDLE["unique_pairs"])
        require(type(value) is dict and set(value) <= keys)
        if suffix == "original-report":
            require({"schema", "passed", "failure"} <= set(value)
                    and type(value["schema"]) is int and value["schema"] == 1 and type(value["passed"]) is bool)
            validate_report_diagnostic(value)
        else: require(set(value) == keys)
        if suffix == "original-diagnostic": validate_diagnostic(value)
        export_value(value)
        pending[name] = raw
    result = dict(version=1, originals={name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                 for name, raw in pending.items()}, missing=missing, successful_native_execution_claimed=False)
    pending["browser-filter-delivery-artifacts.json"] = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    for name, raw in pending.items():
        destination = output / name
        if destination.exists() or destination.is_symlink(): require(raw_file(destination) == raw)
        else: write_new(destination, raw)
        os.chmod(destination, 0o600, follow_symlinks=False)
        os.chown(destination, uid, gid, follow_symlinks=False)
    return result


def evidence(work, manifest_sha, binary_sha, uid, original_gid, control_gid):
    diagnostic = work / "browser-filter-delivery-original-diagnostic.json"
    require(not diagnostic.exists() and not diagnostic.is_symlink())
    source = work / "client-fixtures/browser-filter-source"
    output = source / "build/filter-delivery"
    manifest_raw = raw_file(source / "INPUTS.json")
    manifest = BUNDLE["manifest"](manifest_raw, manifest_sha)
    stage_path = source / "build/firefox-filter-runtime/volparossa-staging.json"
    require(hashlib.sha256(raw_file(stage_path)).hexdigest() == manifest["files"]["build/firefox-filter-runtime/volparossa-staging.json"]["sha256"])
    stage = read(stage_path)
    prepared = read(work / "browser-filter-delivery-prepared.json")
    require(type(prepared) is dict and set(prepared) == {"version", "expected", "created_unix_seconds", "maximum_authority_seconds"})
    require(type(prepared["created_unix_seconds"]) is int and prepared["created_unix_seconds"] > 0)
    same(prepared["version"], 1); same(prepared["maximum_authority_seconds"], 600)
    selected = selection(read(work / "content-provider-filter-input.json"))
    publish = read(work / "content-provider-filter-publish.json")
    expected = dict(publisher_key=selected["publisher_key"], name=NAME, manifest_id=selected["manifest_id"],
        authority_expires_unix_seconds=min(publish["expires_unix_seconds"], prepared["created_unix_seconds"] + 600))
    require(expected["authority_expires_unix_seconds"] > prepared["created_unix_seconds"])
    same(prepared["expected"], expected)
    report, outer = read(output / "report.json"), read(output / "outer-cleanup.json")
    validate_browser(report, outer, expected, manifest, stage, binary_sha)
    same(read(work / "browser-filter-delivery-launch.json"), dict(version=1, boundary=dict(user_uid=uid,
        primary_control_gid=control_gid, supplementary_groups_empty=True, client_namespace=True,
        outside_parent_namespace=True, all_capabilities_dropped=True, no_new_privileges=True)))
    for phase in ("before", "after"):
        same(read(work / f"browser-filter-delivery-tree-{phase}.json"), dict(version=1, action="verify-tree",
            transferred=True, runtime_executed=False, manifest_sha256=manifest_sha,
            files=len(manifest["files"]), private_output_inspected=False))
    before, after = (read(work / f"browser-filter-delivery-cache-{phase}.json") for phase in ("before", "after"))
    same(before, after)
    same(before, cache_state(work / "state-client/filter-cache", before["user_uid"], before["group_gid"]))
    require(uid == 985 and uid != before["user_uid"] and control_gid != before["group_gid"])
    same(read(work / "browser-filter-delivery-input-cleanup.json"), dict(directory_removed=True, files_removed=True))
    require(not (work / "client-fixtures/browser-filter-delivery").exists())
    for name in ("profile", "config", "cache", "runtime", "tmp", "appdata", "broker-binary"):
        require(not (output / name).exists() and not (output / name).is_symlink())
    for name, value in report["logs"].items():
        raw = raw_file(output / (name + ".log"), 4 * 1024 * 1024)
        same(value, dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    cold = dict(input=selected, publish=publish, layout=read(work / "content-provider-layout.json"),
        expected_peers=read(work / "a01-expected-peers.json"),
        publisher_cleanup=read(work / "content-provider-filter-publisher-cleanup.json"),
        selected_route=read(work / "content-provider-filter-selection.json"),
        isolation=dict(agent_cache=str(work / "state-client/filter-cache"), user_uid=uid, user_gid=original_gid, control_gid=control_gid),
        cold=dict(application=read(work / "content-provider-filter-cold-consumer.json"),
            control_privacy=read(work / "content-provider-filter-cold-control.json"),
            privacy={role: read(work / f"content-provider-filter-cold-privacy-{role}.json") for role in FILTER["ROLES"]}))
    validate_cold(cold)
    originals = {}
    for name in ("report", "outer-cleanup"):
        raw = raw_file(output / (name + ".json"))
        require(raw_file(work / ("browser-filter-delivery-original-" + name + ".json")) == raw)
        originals[name] = hashlib.sha256(raw).hexdigest()
    return dict(version=1, kind="volparossa-browser-filter-delivery", success=True,
        bundle_manifest_sha256=manifest_sha, core_broker_sha256=binary_sha, originals_sha256=originals,
        publication=selected, protected_cold=dict(peer_bytes=cold["cold"]["application"]["receipt"]["peer_bytes"],
            providers_used=cold["cold"]["application"]["receipt"]["providers_used"], privacy_captures_validated=True),
        browser=dict(receipts=report["receipts"], probes=report["probes"], exit_status=0),
        scope=dict(same_publication_joined=True, broker_reuse_requested=True, broker_cache_only_proven=False,
            new_broker_peer_transfer_proven=False, native_admission_registered=False, production_default_enrollment=False,
            startup_resume_stale_filter_barrier=False, two_subflow_bulk_aggregation=False),
        cleanup=dict(browser_profile_removed=True, broker_reaped=True, broker_socket_removed=True,
            fixture_authority_removed=True, separate_owner_input_removed=True, agent_cache_identity_preserved=True,
            agent_cache_private=True, staged_inputs_removed_by_enclosing_topology=False))


def main():
    action, *args = sys.argv[1:]
    if action == "prepare" and len(args) == 2: result = prepare(Path(args[0]), int(args[1]))
    elif action == "cleanup" and len(args) == 1: result = cleanup(Path(args[0]))
    elif action == "cache-state" and len(args) == 3: result = cache_state(Path(args[0]), int(args[1]), int(args[2]))
    elif action == "launch" and len(args) == 10: return launch(args)
    elif action == "retain" and len(args) == 1: result = retain(Path(args[0]))
    elif action == "copy-artifacts" and len(args) == 4:
        result = copy_artifacts(Path(args[0]), Path(args[1]), int(args[2]), int(args[3]))
    elif action == "evidence" and len(args) == 6:
        result = evidence(Path(args[0]), args[1], args[2], *map(int, args[3:]))
    else: raise ValueError("browser_filter_delivery_rejected")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try: main()
    except (Exception, KeyboardInterrupt):
        print("browser_filter_delivery_rejected", file=sys.stderr); raise SystemExit(1) from None
