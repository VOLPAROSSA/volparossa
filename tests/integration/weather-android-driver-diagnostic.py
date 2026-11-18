#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Optional closed observations from files already retrieved by the VM owner.

This does not run the guest, retrieve anything, inspect logs, or authorize any
success/cleanup claim. A terminal topology blocker can have been overwritten by
cleanup; it is an observation, not necessarily the first cause of driver exit.
"""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import stat

HERE = Path(__file__).resolve().parent
E = runpy.run_path(str(HERE / "weather-android-evidence.py"))
require, exact, same = E["require"], E["exact"], E["same"]
NAME = "weather-android-driver-diagnostic.json"
MAX_BYTES = 8192
LEGACY_WEATHER_COMMIT = "f6ee829961da387d9c0cd71b7163b47baab434fa"
FIRST_DRIVER_WEATHER_COMMIT = "0a31bf180f1a42b96b0ceaec3715f56496a559a5"
WEATHER_COMMIT = "3b90442a9d5be4db73ccf83cba2028364980c3ca"
ROOTS = {"normal": "", "published": "published", **{f"work_{n}": f"work-{n}" for n in range(1, 5)}}
ERRORS = (OSError, ValueError, KeyError, TypeError, RecursionError)
STATES = frozenset(("available", "absent", "rejected"))
DRIVER_PHASES = frozenset("verify-source packages weather-client-inputs build egress-netns-test private-unbound-preflight package-lifecycle topology archive driver-finished".split())
TOPOLOGY_PHASES = frozenset("identity-setup host-state-before network-topology configuration helper-launch helper-verification mpquic-launch agent-launch agent-readiness discovery a01-bootstrap1-loss a01-bootstrap2-loss a01-complete content-provider-inventory content-provider-selection content-provider-control-underlay content-provider-publication content-provider-fetch content-provider-stop content-provider-complete weather-client-delivery-profile weather-client-delivery-prepare weather-products-delivery-prepare weather-products-delivery-acquire weather-products-delivery-publish weather-android-delivery-prepare weather-android-delivery-api weather-android-delivery-installed-app weather-android-delivery-verify weather-android-delivery-complete a15-complete".split())

# Only reviewed literals are categorized. No prefix/regex turns an arbitrary
# child string into exported text, including apparently well-formed error IDs.
BLOCKER_GROUPS = {
    "not-reached": "NOT_REACHED",
    "agent-startup": "AGENT_OR_DESTINATION_NOT_READY IDENTITY_INVALID",
    "agent-unit-collision": "AGENT_UNIT_COLLISION",
    "cache-preparation": "WEATHER_CLIENT_AGENT_CACHE_PREPARE_FAILED",
    "cache-parent-changed": "WEATHER_ANDROID_CACHE_PARENT_CHANGED",
    "cleanup": "A14_REMAINING_INVENTORY_UNAVAILABLE A14_FORCED_CRASH_CLEANUP_INCOMPLETE A15_HOST_STATE_CHANGED A15_HOST_STATE_AFTER_UNAVAILABLE",
    "provider-discovery": "CONTENT_PROVIDER_INVENTORY_UNAVAILABLE CONTENT_PROVIDER_CONTROL_STATUS_UNAVAILABLE CONTENT_PROVIDER_CONTROL_RELAY_UNAVAILABLE CONTENT_PROVIDER_INDEPENDENT_NODES_UNAVAILABLE",
    "provider-route": "CONTENT_PROVIDER_MPTCP_SELECTION_UNAVAILABLE CONTENT_PROVIDER_SELECTION_INVALID CONTENT_PROVIDER_CONTROL_NODE_INVALID CONTENT_PROVIDER_NODE_INVALID CONTENT_PROVIDER_CONTROL_FILTER_FAILED",
    "weather-acquisition": "WEATHER_CLIENT_ACQUISITION_FAILED WEATHER_PRODUCTS_ACQUISITION_FAILED",
    "weather-budget": "WEATHER_PRODUCTS_DEADLINE WEATHER_ANDROID_TRIAL_BUDGET_INSUFFICIENT WEATHER_ANDROID_API_READY_TIMEOUT WEATHER_ANDROID_API_JOIN_TIMEOUT",
    "android-preparation": "WEATHER_ANDROID_BOUNDARY_INVALID WEATHER_ANDROID_ORIGINALS_REMAIN WEATHER_ANDROID_PREPARE_FAILED WEATHER_ANDROID_PREPARED_RETENTION_FAILED WEATHER_ANDROID_CONTROLLER_EXISTS WEATHER_ANDROID_CONTROLLER_DIRECTORY_UNSAFE WEATHER_ANDROID_CONTROLLER_STAGE_FAILED WEATHER_ANDROID_READY_REJECTED",
    "android-api": "WEATHER_ANDROID_API_START_FAILED WEATHER_ANDROID_API_EXITED WEATHER_ANDROID_API_FAILED WEATHER_ANDROID_API_JOIN_UNCONFIRMED",
}
BLOCKERS = {literal: category for category, literals in BLOCKER_GROUPS.items() for literal in literals.split()}
for _node in "client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 relay5 exit exit2".split():
    for _check in "SERVICE_UNAVAILABLE SOCKET_UNAVAILABLE MAINPID_INVALID GETUNITBYPID_MISMATCH NETWORK_NAMESPACE_MISMATCH NOTIFY_CONTRACT FDSTORE_MAX_CONTRACT FDSTORE_PRESERVE_CONTRACT CGROUP_CONTRACT SOCKET_METADATA".split():
        BLOCKERS[f"HELPER_{_check}_{_node}"] = "helper"
BLOCKER_VALUES = frozenset(BLOCKER_GROUPS) | {"helper", "unknown", "none"}
# Schema one retains its original finite projection. These existing guest
# postflight guards are visible only in the new, late-driver schema two.
POSTFLIGHT_BLOCKER_GROUPS = {
    "android-path-capture": "WEATHER_ANDROID_PATHS_UNAVAILABLE",
    "android-observer-close": "WEATHER_ANDROID_CAPTURE_INCOMPLETE",
    "weather-source-changed": "WEATHER_PRODUCTS_SOURCE_CHANGED",
    "android-guest-evidence": "WEATHER_ANDROID_EVIDENCE_INVALID",
    "android-controller-cleanup": "WEATHER_ANDROID_CONTROLLER_CLEANUP_FAILED",
}
LATE_BLOCKERS = dict(BLOCKERS, **{literal: category
    for category, literals in POSTFLIGHT_BLOCKER_GROUPS.items() for literal in literals.split()})
LATE_BLOCKER_VALUES = BLOCKER_VALUES | frozenset(POSTFLIGHT_BLOCKER_GROUPS)
# The verifier emits only these finite statuses; the shell maps them to these
# exact blockers. Historical schema one/two never acquire this extra meaning.
GUEST_BLOCKERS = {"WEATHER_ANDROID_EVIDENCE_" + stage.upper().replace("-", "_") + "_INVALID":
    "android-evidence-" + stage for stage in E["GUEST_FAILURE_CODES"]}
GUEST_BLOCKERS.update(WEATHER_ANDROID_EVIDENCE_TIMEOUT="android-evidence-timeout",
    WEATHER_ANDROID_EVIDENCE_INTERRUPTED="android-evidence-interrupted",
    WEATHER_ANDROID_EVIDENCE_SIGNAL="android-evidence-signal")
GUEST_BLOCKER_VALUES = frozenset(GUEST_BLOCKERS.values())
GUEST_PHASE = "weather-android-delivery-verify"
REPORT_FLAGS = frozenset("general_nat_reachability_claimed full_c02_claimed explicit_origin_authenticated_https normal_user_publication native_name_retrieval native_static_site public_filter_snapshot adaptive_provider_workers pressure late_provider_recovery requester_cancellation browser_integration_claimed arbitrary_https_integration_claimed speed_improvement_claimed full_alpha_acceptance_claimed".split())
REPORT_KEYS = REPORT_FLAGS | {"schema_version", "report_kind", "source_revision", "run_id", "phase", "success", "transfer", "runner_exit_status", "observed_blocker", "cleanup", "host_state", "scope"}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def identity(value):
    exact(value, ("core_commit", "weather_commit", "run_id", "run_attempt"))
    require(type(value["core_commit"]) is str and re.fullmatch("[a-f0-9]{40}", value["core_commit"])
        and value["weather_commit"] in (LEGACY_WEATHER_COMMIT, FIRST_DRIVER_WEATHER_COMMIT, WEATHER_COMMIT))
    for key in ("run_id", "run_attempt"):
        require(type(value[key]) is str and re.fullmatch("[1-9][0-9]{0,19}", value[key]))


def finite(value, choices, *, nullable=False):
    if nullable and value is None: return None
    require(type(value) is str and len(value) <= 256)
    return value if value in choices else "unknown"


def observation(state, facts=None):
    require(state in STATES and (facts is None) == (state != "available"))
    return dict(state=state, facts=facts)


def root_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700)
    return path


def private_read(root, relative, limit):
    path = root / relative
    parent = path.parent
    while parent != root:
        root_directory(parent)
        parent = parent.parent
    return E["private_bytes"](path, limit, os.getuid())


def read_source(root, relative, limit, projector):
    try:
        raw = private_read(root, relative, limit)
        return observation("available", projector(raw))
    except FileNotFoundError:
        # A dangling symlink is rejected, not silently treated as absent.
        path = root / relative
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
            return observation("rejected")
        return observation("absent")
    except ERRORS:
        return observation("rejected")


def early_owner_gate(value, expected):
    """Accept only the current, closed early-driver failure shape; not success."""
    exact(value, ("schema", "kind", "identity", "phase", "statuses", "owner_cleanup", "owner_stop",
        "tunnel_diagnostic", "native_diagnostic", "weather_records", "diagnostic_only", "success",
        "joined_core_acceptance", "vm_cleanup_pending", "expiry_proven", "physical_device", "production_authority"))
    same(value["schema"], 8); same(value["kind"], "weather-android-owner-failure")
    same(value["identity"], expected); same(value["phase"], "read-ready")
    for key in ("diagnostic_only", "vm_cleanup_pending"): same(value[key], True)
    for key in ("success", "joined_core_acceptance", "expiry_proven", "physical_device", "production_authority"):
        same(value[key], False)
    stop = value["owner_stop"]
    exact(stop, ("reason", "stage", "budgets", "children", "output_overflow"))
    same(stop["reason"], "driver-exited"); same(stop["stage"], "read-ready")
    same(stop["budgets"], []); same(stop["output_overflow"], False)
    exact(stop["children"], ("driver", "tunnel", "native"))
    child = stop["children"]["driver"]
    exact(child, ("state", "status", "stdout_open", "stderr_open"))
    same(child["state"], "exited"); E["integer"](child["status"], -255, 255)
    require(child["status"] != 0 and all(type(child[k]) is bool for k in ("stdout_open", "stderr_open")))
    for name in ("native", "tunnel"):
        same(stop["children"][name], dict(state="not-started", status=None, stdout_open=False, stderr_open=False))
    same(value["statuses"], dict(driver=child["status"], native=None, tunnel=None))
    exact(value["owner_cleanup"], ("children_joined", "output_drained", "forced_kill", "socket_removed", "host_netns_unchanged"))
    require(all(type(v) is bool for v in value["owner_cleanup"].values()))
    require(value["owner_cleanup"]["children_joined"] and value["owner_cleanup"]["output_drained"])
    same(value["tunnel_diagnostic"], None)
    same(value["native_diagnostic"], dict(state="absent", record=None))
    exact(value["weather_records"], ("result", "failure", "emulator_cleanup"))
    for record in value["weather_records"].values():
        exact(record, ("state", "facts"))
        require(record["state"] in ("absent", "rejected") and record["facts"] is None)
    return dict(reason="driver-exited", stage="read-ready", driver_status=child["status"])


def late_owner_gate(value, expected):
    """The exact observed post-native failure, not guest API/evidence success.

    The owner accepted the native result, tunnel record and finalize request,
    then rejected the guest driver's exit status. None of those facts proves
    successful guest API finalization or establishes the guest failure cause.
    """
    require(type(value) is dict)
    exact(value["statuses"], ("driver", "native", "tunnel"))
    status = value["statuses"]["driver"]
    E["integer"](status, -255, 255); require(status != 0)
    children = {name: dict(state="exited", status=code, stdout_open=False, stderr_open=False)
        for name, code in (("driver", status), ("native", 0), ("tunnel", 0))}
    same(value, dict(schema=8, kind="weather-android-owner-failure", identity=expected, phase="driver-join",
        statuses=dict(driver=status, native=0, tunnel=0),
        owner_stop=dict(reason="guard-rejected", stage="driver-join", budgets=[], children=children, output_overflow=False),
        owner_cleanup=dict(children_joined=True, output_drained=True, forced_kill=False,
            socket_removed=True, host_netns_unchanged=True),
        tunnel_diagnostic=None, native_diagnostic=dict(state="absent", record=None),
        weather_records=dict(result=dict(state="available", facts=dict(schema=1,
            kind="hosted-android-protected-core-installed-trial", phase="complete", success=True,
            process_drain_confirmed=True, policy_cleanup_complete=True, host_netns_unchanged=True,
            synthetic=False, expiry_proven=False, core_delivery=False, joined_core_acceptance=False,
            mobile_core=False, production_authority=False)), failure=dict(state="absent", facts=None),
            emulator_cleanup=dict(state="available", facts=dict(schema=1, direct_children_reaped=True,
                private_avd_removed=True, private_android_home_removed=True, trial_returned=True,
                enclosing_namespace_cleanup_required=True))),
        diagnostic_only=True, success=False, joined_core_acceptance=False, vm_cleanup_pending=True,
        expiry_proven=False, physical_device=False, production_authority=False))
    return dict(reason="guard-rejected", stage="driver-join", driver_status=status)


def owner_gate(value, expected):
    identity(expected)
    require(type(value) is dict)
    if value.get("phase") == "driver-join": return late_owner_gate(value, expected)
    return early_owner_gate(value, expected)


def diagnostic_schema(stop):
    exact(stop, ("reason", "stage", "driver_status"))
    E["integer"](stop["driver_status"], -255, 255); require(stop["driver_status"] != 0)
    if stop["stage"] == "read-ready":
        same(stop["reason"], "driver-exited")
        return 1
    same(stop["stage"], "driver-join"); same(stop["reason"], "guard-rejected")
    return 2


def provider(raw, expected, schema=1):
    E["integer"](schema, 1, 3)
    value = E["decode"](raw, 1048576)
    exact(value, REPORT_KEYS)
    same(value["schema_version"], 4)
    same(value["report_kind"], "volparossa-native-content-providers")
    same(value["source_revision"], expected["core_commit"]); same(value["success"], False)
    require(type(value["run_id"]) is str and re.fullmatch("[a-f0-9]{32}", value["run_id"]))
    require(all(type(value[key]) is bool for key in REPORT_FLAGS))
    E["integer"](value["runner_exit_status"], 0, 255)
    require(value["transfer"] is None or type(value["transfer"]) is dict)
    require(value["host_state"] is None or type(value["host_state"]) is dict)
    require(type(value["scope"]) is str and len(value["scope"]) <= 2048)
    exact(value["cleanup"], ("complete", "remaining_owned_objects"))
    require(type(value["cleanup"]["complete"]) is bool)
    E["integer"](value["cleanup"]["remaining_owned_objects"], -1, 65536)
    phase = finite(value["phase"], TOPOLOGY_PHASES)
    blocker = value["observed_blocker"]
    require(blocker is None or type(blocker) is str and len(blocker) <= 256)
    blockers = BLOCKERS if schema == 1 else LATE_BLOCKERS if schema == 2 else dict(LATE_BLOCKERS, **GUEST_BLOCKERS)
    if schema == 3 and blocker in GUEST_BLOCKERS:
        same(phase, GUEST_PHASE); require(value["runner_exit_status"] != 0)
    facts = dict(phase=phase, blocker="none" if blocker is None else blockers.get(blocker, "unknown"),
        runner_exit_status=value["runner_exit_status"])
    # Compare original selected facts and private run binding before projecting.
    # Different unreviewed strings must not look equal merely because both map
    # to 'unknown'. No run identifier or unreviewed text enters the receipt.
    binding = (value["run_id"], value["phase"], blocker, value["runner_exit_status"])
    return dict(facts=facts, binding=binding)


def vm(raw, expected):
    value = E["decode"](raw, 65536)
    keys = {"schema_version", "report_kind", "source_revision", "scenario", "success", "guest_exit_status",
        "observed_blocker", "driver_phase", "topology_phase", "cleanup", "host_state", "diagnostics"}
    require(type(value) is dict and set(value) in (keys, keys | {"helper_processes"}))
    same(value["schema_version"], 1); same(value["report_kind"], "volparossa-incomplete-vm-diagnostics")
    same(value["source_revision"], expected["core_commit"]); same(value["scenario"], "content-provider")
    same(value["success"], False); E["integer"](value["guest_exit_status"], 0, 255)
    same(value["cleanup"], dict(complete=False, verified=False))
    same(value["host_state"], dict(unchanged=None, verified=False))
    require(type(value["diagnostics"]) is dict and value["diagnostics"].get("partial") is True
        and type(value["diagnostics"].get("available")) is bool)
    if "helper_processes" in value: require(type(value["helper_processes"]) is list)
    blocker = "GUEST_EXECUTION_TIMEOUT" if value["guest_exit_status"] in (124, 137) else "GUEST_OUTPUT_UNAVAILABLE"
    same(value["observed_blocker"], blocker)
    return dict(driver_phase=finite(value["driver_phase"], DRIVER_PHASES, nullable=True),
        topology_phase=finite(value["topology_phase"], TOPOLOGY_PHASES, nullable=True),
        blocker="guest-timeout" if blocker == "GUEST_EXECUTION_TIMEOUT" else "guest-output-unavailable",
        guest_exit_status=value["guest_exit_status"])


def phase(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65)
    return dict(phase=finite(raw.decode("ascii").strip(), TOPOLOGY_PHASES))


def receipt(root, expected, stop):
    schema = diagnostic_schema(stop)
    sources, originals = {}, []
    for label, relative in ROOTS.items():
        report = read_source(root, str(Path(relative) / "content-provider-smoke.json"), 1048576,
            lambda raw: provider(raw, expected, 3 if schema == 2 else schema))
        if report["state"] == "available":
            originals.append(report["facts"]["binding"])
            report["facts"] = report["facts"]["facts"]
        sources[label] = dict(report=report, phase=read_source(root, str(Path(relative) / "current-phase"), 65, phase))
    conflict = any(row["report"]["state"] == "rejected" for row in sources.values()) or len(set(originals)) > 1
    if conflict:
        for row in sources.values():
            if row["report"]["state"] != "absent": row["report"] = observation("rejected")
    if schema == 2 and any(row["report"]["state"] == "available"
            and row["report"]["facts"]["blocker"] in GUEST_BLOCKER_VALUES for row in sources.values()):
        schema = 3
    result = dict(schema=schema, kind="weather-android-driver-diagnostic", identity=expected, owner_stop=stop,
        sources=sources, provider_consistency="rejected" if conflict else "absent" if not originals else "single" if len(originals) == 1 else "consistent",
        vm=read_source(root, "vm-incomplete.json", 65536, lambda raw: vm(raw, expected)),
        diagnostic_only=True, success=False, joined_core_acceptance=False, cause_established=False,
        cleanup_verified=False, physical_device=False, production_authority=False)
    validate_receipt(result)
    return result


def validate_observation(value, validator):
    exact(value, ("state", "facts"))
    require(type(value["state"]) is str and value["state"] in STATES)
    if value["state"] == "available": validator(value["facts"])
    else: same(value["facts"], None)


def validate_receipt(value):
    exact(value, ("schema", "kind", "identity", "owner_stop", "sources", "provider_consistency", "vm",
        "diagnostic_only", "success", "joined_core_acceptance", "cause_established", "cleanup_verified", "physical_device", "production_authority"))
    E["integer"](value["schema"], 1, 3)
    same(2 if value["schema"] == 3 else value["schema"], diagnostic_schema(value["owner_stop"]))
    same(value["kind"], "weather-android-driver-diagnostic"); identity(value["identity"])
    if value["schema"] in (2, 3): same(value["identity"]["weather_commit"], WEATHER_COMMIT)
    same(value["diagnostic_only"], True)
    for key in ("success", "joined_core_acceptance", "cause_established", "cleanup_verified", "physical_device", "production_authority"):
        same(value[key], False)
    def phase_value(item):
        require(item is None or type(item) is str and item in TOPOLOGY_PHASES | {"unknown"})
    def check_phase(facts):
        exact(facts, ("phase",)); phase_value(facts["phase"]); require(facts["phase"] is not None)
    def check_report(facts):
        exact(facts, ("phase", "blocker", "runner_exit_status")); check_phase(dict(phase=facts["phase"]))
        blockers = BLOCKER_VALUES if value["schema"] == 1 else LATE_BLOCKER_VALUES
        if value["schema"] == 3: blockers |= GUEST_BLOCKER_VALUES
        require(type(facts["blocker"]) is str and facts["blocker"] in blockers)
        E["integer"](facts["runner_exit_status"], 0, 255)
        if facts["blocker"] in GUEST_BLOCKER_VALUES:
            same(facts["phase"], GUEST_PHASE); require(facts["runner_exit_status"] != 0)
    exact(value["sources"], ROOTS)
    states, reports = [], []
    for row in value["sources"].values():
        exact(row, ("report", "phase")); validate_observation(row["report"], check_report)
        validate_observation(row["phase"], check_phase); states.append(row["report"]["state"])
        if row["report"]["state"] == "available": reports.append(row["report"]["facts"])
    expected = "rejected" if "rejected" in states else "absent" if not reports else "single" if len(reports) == 1 else "consistent"
    same(value["provider_consistency"], expected)
    require(not ("rejected" in states and reports) and all(row == reports[0] for row in reports))
    if value["schema"] == 3:
        require(any(row["blocker"] in GUEST_BLOCKER_VALUES for row in reports))
    def check_vm(facts):
        exact(facts, ("driver_phase", "topology_phase", "blocker", "guest_exit_status"))
        require(facts["driver_phase"] is None or type(facts["driver_phase"]) is str and facts["driver_phase"] in DRIVER_PHASES | {"unknown"})
        phase_value(facts["topology_phase"]); E["integer"](facts["guest_exit_status"], 0, 255)
        same(facts["blocker"], "guest-timeout" if facts["guest_exit_status"] in (124, 137) else "guest-output-unavailable")
    validate_observation(value["vm"], check_vm)
    require(len(encoded(value)) <= MAX_BYTES)
    return value


def export(root, expected):
    identity(expected)
    # Historical schema-one diagnostics remain readable; only the current
    # exactly pinned source may produce a new workflow diagnostic export.
    same(expected["weather_commit"], WEATHER_COMMIT)
    root = root_directory(root)
    try:
        stop = owner_gate(E["decode"](private_read(root, "weather-android-owner-failure.json", 65536), 65536), expected)
    except ERRORS:
        return False  # Neither admitted failure shape; no new authority or record.
    result = receipt(root, expected, stop)
    with os.fdopen(os.open(root / NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(encoded(result)); stream.flush()
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("export",))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--core-commit", required=True)
    parser.add_argument("--weather-commit", required=True)
    args = parser.parse_args(argv)
    expected = dict(core_commit=args.core_commit, weather_commit=args.weather_commit,
        run_id=os.environ.get("GITHUB_RUN_ID"), run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"))
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("GITHUB_REPOSITORY") == "VOLPAROSSA/volparossa"
        and os.environ.get("GITHUB_WORKFLOW") == "Weather Android protected core delivery"
        and os.environ.get("GITHUB_SHA") == args.core_commit
        and os.environ.get("VOLPAROSSA_WEATHER_SOURCE_SHA") == args.weather_commit)
    export(args.output, expected)


if __name__ == "__main__":
    try:
        main()
    except ERRORS:
        raise SystemExit("weather_android_driver_diagnostic_unavailable") from None
