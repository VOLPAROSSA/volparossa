#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed optional observations from the pinned Weather inner trial.

No Weather code is executed here. The owner supplies original, fresh, bounded
private files only after joining its children. Missing/rejected observations
remain diagnostic and cannot authorize delivery, cleanup or acceptance.
"""
import json
import re

NAME = "weather-android-inner-diagnostic.json"
MAX_BYTES = 8192
LEGACY_WEATHER_COMMIT = "f6ee829961da387d9c0cd71b7163b47baab434fa"
FIRST_DRIVER_WEATHER_COMMIT = "0a31bf180f1a42b96b0ceaec3715f56496a559a5"
WEATHER_COMMIT = "3b90442a9d5be4db73ccf83cba2028364980c3ca"
LEGACY_INPUTS = {
    "emulator": "build/overmorrow-hosted-android-live-proof/emulator-diagnostic.json",
    "guest_network": "build/overmorrow-hosted-android-live-proof/guest-network-diagnostic.json",
}
INPUTS = dict(LEGACY_INPUTS, driver="build/overmorrow-hosted-android-live-proof/driver/first-failure.json")
INPUT_LIMITS = {"emulator": 1024, "guest_network": 2048, "driver": 2048}


def words(value):
    return frozenset(value.split())


# Literal domains reviewed in f6 scripts/prepare_hosted_android_ci.py. Never
# derive accepted strings from the child, exception text, paths or logs.
PHASES = words("avd_create avd_configure service_start boot guest_identity guest_network apk_install package_identity port_reverse app_driver unknown")
COMMANDS = words("avdmanager adb adb_server fixture emulator app_driver none unknown")
CHECKS = words("EMULATOR_DEADLINE EMULATOR_COMMAND_DEADLINE EMULATOR_COMMAND_OUTPUT EMULATOR_BOOT_FAILED ANDROID_API ANDROID_ABI GUEST_ROUTE_OUTPUT_BOUND GUEST_NETWORK_STILL_ACTIVE GUEST_PACKAGE_UID unknown")
FAILURE_KINDS = words("interrupted command_exit deadline output_bound not_found permission_denied os_error check_failed unknown")
SDK_ERRORS = words("java_version java_home java_classpath java_initialization launcher_helper sdk_root sdk_package sdk_image sdk_avd sdk_license unknown ambiguous")
JAVA_ERRORS = words("version classpath initialization linkage invalid_operation state null_reference security memory io network service_configuration internal unknown ambiguous")
FATAL_TEMPLATES = words("java_home_invalid java_not_found jdk_too_old tools_directory_unset working_directory_invalid package_argument_missing package_unrecognized package_has_no_images avd_name_invalid avd_already_exists tag_abi_conflict abi_syntax_invalid tag_invalid abi_ambiguous abi_invalid device_not_found skin_not_found emulator_package_missing hardware_properties_unreadable avd_create_exception parser_global_flag parser_action_flag parser_expected_verb parser_argument parser_missing_argument parser_argument_is_flag parser_invalid_usage parser_missing_verb parser_missing_object parser_required_parameters unknown ambiguous")
NETWORK_FAILURES = words("interrupted non_ascii command_exit command_timeout command_io parse_bound command_output_bound command_deadline routes_rejected unknown link_bound link_unknown link_active link_changed qdisc_bound qdisc_unknown qdisc_unsafe qdisc_changed link_json_syntax link_json_depth link_json_duplicate observer_rejected observer_bound observer_deadline observer_query link_join")
QUERIES = words("link_before loopback_before dummy_before qdisc_before ipv4 ipv6 qdisc_after link_after loopback_after dummy_after")
LINK_QUERIES = words("link_before loopback_before dummy_before link_after loopback_after dummy_after")
GUARDS = words("build_type debuggable shell_uid shell_context selinux observer_uid observer_context")
PARSE_REASONS = NETWORK_FAILURES | words("none expected_value extra_data expected_key expected_comma expected_colon unterminated_string invalid_escape invalid_control json_syntax")
METADATA_REASONS = words("document_type row_count row_type unknown_fields required_missing index_type index_range index_duplicate name_type name_shape name_duplicate flags_type flags_count flag_type flag_shape flags_duplicate operstate_type operstate_value link_type_type qdisc_type linkinfo_type linkinfo_unknown_fields linkinfo_kind_type sink_qdisc sink_linkmode sink_promiscuity sink_allmulti sink_flags loopback_required")
METADATA_FIELDS = words("document row ifindex ifname flags operstate link_type qdisc linkinfo linkmode promiscuity allmulti")
UNKNOWN_CLASSES = words("linked_device linked_index linked_namespace master xdp virtual_functions alternate_names statistics event slave_kind slave_data other_unknown")
REJECTION_COUNTS = words("default_route gateway device_count device_value non_loopback")
ROUTE_COUNTS = words("unreachable blackhole prohibit throw unicast_or_unspecified other")
DEVICE_COUNTS = words("lo ethernet wifi other missing_or_invalid")
DRIVER_PHASES = words("installed-app read-only-observer initial-native-products actual-refresh background-resume-fresh")
DRIVER_STARTUP_PHASES = words("installed-app read-only-observer")
DRIVER_SUBPHASES = words("unobserved logcat_read vm_address forward_create forward_port websocket_create websocket_connect get_vm isolate_identity get_isolate native_snapshot isolate_wait package_check force_stop app_start pidof pid_validation control_request control_status control_body control_decode control_schema product_counts product_count_wait product_snapshot product_metadata product_tables products_unobserved swipe swipe_settle refresh_snapshot refresh_target refresh_unobserved refresh_wait post_tap_snapshot tap missing_values expiry_snapshot expiry_labels expiry_wait before_background background_home background_snapshot background_wait background_pause resume_start resume_snapshot resume_wait expired_labels expired_tables final_requests clock_window clock_guest_read clock_guest_decode clock_validity clock_wait lifecycle_baseline lifecycle_read lifecycle_validate")
DRIVER_CODES = words("unknown validation_failed response_type_invalid adb_exit adb_signal adb_output_bound adb_spawn_failed adb_failed websocket_deadline websocket_failed vm_request_rejected vm_request_deadline vm_connection_closed vm_response_invalid vm_response_type vm_response_bound vm_response_json observation_deadline trial_deadline interrupted clock_expired clock_host_before_acquisition")


def require(condition):
    if not condition:
        raise ValueError("weather_android_inner_diagnostic_rejected")


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def integer(value, low=0, high=65536):
    require(type(value) is int and low <= value <= high)


def enum(value, choices, *, nullable=False):
    require(nullable and value is None or type(value) is str and value in choices)


def boolean(value):
    require(type(value) is bool)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def identity(value, schema):
    exact(value, ("core_commit", "weather_commit", "run_id", "run_attempt"))
    require(type(value["core_commit"]) is str and re.fullmatch("[0-9a-f]{40}", value["core_commit"])
        and value["weather_commit"] in ((LEGACY_WEATHER_COMMIT,) if schema == 1
            else (FIRST_DRIVER_WEATHER_COMMIT, WEATHER_COMMIT)))
    for key in ("run_id", "run_attempt"):
        require(type(value[key]) is str and re.fullmatch("[1-9][0-9]{0,19}", value[key]))


def emulator(value):
    exact(value, ("schema", "kind", "phase", "command_category", "failure_kind", "check_code", "exit_status",
        "output_bytes", "output_complete", "output_truncated", "sdk_error", "java_error_family",
        "filesystem_markers", "fatal_template", "milestones", "raw_text_exported", "cause_established"))
    integer(value["schema"], 3, 3)
    require(value["kind"] == "hosted-android-emulator-diagnostic")
    for key, choices in (("phase", PHASES), ("command_category", COMMANDS), ("failure_kind", FAILURE_KINDS),
            ("check_code", CHECKS), ("sdk_error", SDK_ERRORS), ("java_error_family", JAVA_ERRORS),
            ("fatal_template", FATAL_TEMPLATES)):
        enum(value[key], choices)
    if value["exit_status"] is not None: integer(value["exit_status"], -255, 255)
    integer(value["output_bytes"])
    for key in ("output_complete", "output_truncated"): boolean(value[key])
    require(not (value["output_complete"] and value["output_truncated"]))
    for key, names in (("filesystem_markers", ("read_only", "missing", "access_denied")),
            ("milestones", ("cli_usage", "local_repository", "single_abi_selected", "hardware_question"))):
        exact(value[key], names)
        for item in value[key].values(): boolean(item)
    require(value["raw_text_exported"] is False and value["cause_established"] is False)


def counts(value, keys, high=65536):
    exact(value, keys)
    for item in value.values(): integer(item, high=high)


def family(value):
    exact(value, ("outcome", "error", "routes", "rejected_routes", "rejection_counts", "route_type_counts", "device_category_counts"))
    enum(value["outcome"], words("unobserved unknown admitted rejected"))
    enum(value["error"], NETWORK_FAILURES | {"none"})
    counted = ("routes", "rejected_routes", "rejection_counts", "route_type_counts", "device_category_counts")
    if value["outcome"] in ("unknown", "unobserved"):
        require(all(value[key] is None for key in counted))
        if value["outcome"] == "unobserved": require(value["error"] == "none")
        return
    require(value["error"] == "none")
    integer(value["routes"]); integer(value["rejected_routes"], high=value["routes"])
    require((value["outcome"] == "rejected") == (value["rejected_routes"] > 0))
    for key, keys in (("rejection_counts", REJECTION_COUNTS), ("route_type_counts", ROUTE_COUNTS),
            ("device_category_counts", DEVICE_COUNTS)):
        counts(value[key], keys, value["routes"])
    require(sum(value["route_type_counts"].values()) == value["routes"]
        and sum(value["device_category_counts"].values()) == value["routes"])


def guest_network(value):
    exact(value, ("schema", "kind", "stage", "failure", "polls", "families", "snapshot", "typed", "last_query",
        "rejection_counts_overlap", "device_category_basis", "gate_passed", "cause_established", "raw_text_exported",
        "observer", "link_decode", "observer_authority", "query_streams", "link_decode_query", "link_join",
        "link_metadata", "link_relation"))
    integer(value["schema"], 9, 9)
    require(value["kind"] == "hosted-android-guest-network-diagnostic"
        and value["snapshot"] == "last_poll" and value["rejection_counts_overlap"] is True
        and value["device_category_basis"] == "fixed_name_convention_only"
        and value["observer_authority"] == "disposable-userdebug-existing-permissive-su")
    require(all(value[key] is False for key in ("gate_passed", "cause_established", "raw_text_exported")))
    enum(value["stage"], words("wifi_disable data_disable routes observer_before observer_after"))
    enum(value["failure"], NETWORK_FAILURES); integer(value["polls"])
    exact(value["families"], ("ipv4", "ipv6"))
    for item in value["families"].values(): family(item)
    typed = value["typed"]; exact(typed, ("status", "ipv4", "ipv6"))
    enum(typed["status"], words("unobserved unknown verified"))
    for key in ("ipv4", "ipv6"):
        if typed["status"] == "verified": counts(typed[key], ("loopback", "dummy", "rejected"))
        else: require(typed[key] is None)
    query = value["last_query"]; exact(query, ("name", "outcome"))
    enum(query["name"], QUERIES, nullable=True)
    enum(query["outcome"], words("unobserved started returned command_failed"))
    require((query["outcome"] == "unobserved") == (query["name"] is None))
    observer = value["observer"]; exact(observer, ("before", "after", "guard", "outcome"))
    for key in ("before", "after"): enum(observer[key], words("unobserved checking verified"))
    enum(observer["guard"], GUARDS, nullable=True)
    enum(observer["outcome"], words("unobserved started returned failed verified"))
    decoded = value["link_decode"]; exact(decoded, ("status", "bytes", "shape", "reason", "position"))
    enum(decoded["status"], words("unobserved started failed verified"))
    enum(decoded["shape"], words("unobserved empty array_prefix object_prefix other"))
    enum(decoded["reason"], PARSE_REASONS)
    if decoded["bytes"] is not None: integer(decoded["bytes"], high=65537)
    if decoded["position"] is not None: integer(decoded["position"])
    if decoded["status"] == "unobserved":
        require(decoded == dict(status="unobserved", bytes=None, shape="unobserved", reason="none", position=None))
    else: require(decoded["bytes"] is not None and decoded["shape"] != "unobserved")
    enum(value["link_decode_query"], LINK_QUERIES, nullable=True)
    require((decoded["status"] == "unobserved") == (value["link_decode_query"] is None))
    if value["link_decode_query"] is not None: require(value["link_decode_query"] == query["name"])
    streams = value["query_streams"]
    exact(streams, ("status", "stdout_bytes", "stderr_bytes", "stdout_eof", "stderr_eof", "exit_status"))
    enum(streams["status"], words("unobserved complete failed"))
    for key in ("stdout_bytes", "stderr_bytes"):
        if streams[key] is not None: integer(streams[key], high=65537)
    for key in ("stdout_eof", "stderr_eof"): boolean(streams[key])
    if streams["exit_status"] is not None: integer(streams["exit_status"], -128, 255)
    if streams["status"] == "unobserved":
        require(streams == dict(status="unobserved", stdout_bytes=None, stderr_bytes=None,
            stdout_eof=False, stderr_eof=False, exit_status=None))
    else:
        require(streams["stdout_bytes"] is not None and streams["stderr_bytes"] is not None)
        if streams["status"] == "complete":
            require(streams["stdout_eof"] and streams["stderr_eof"] and streams["exit_status"] == 0)
    joined = value["link_join"]; exact(joined, ("status", "side"))
    enum(joined["status"], words("unobserved started failed verified"))
    enum(joined["side"], words("before after"), nullable=True)
    require((joined["status"] == "unobserved") == (joined["side"] is None))
    if joined["side"] is not None: require(query["name"] == "dummy_" + joined["side"])
    metadata = value["link_metadata"]
    exact(metadata, ("status", "context", "reason", "field", "unknown_key_classes"))
    enum(metadata["status"], words("unobserved rejected"))
    if metadata["status"] == "unobserved":
        require(metadata == dict(status="unobserved", context=None, reason=None, field=None, unknown_key_classes=[]))
    else:
        enum(metadata["context"], words("rows join")); enum(metadata["reason"], METADATA_REASONS)
        enum(metadata["field"], METADATA_FIELDS)
        classes = metadata["unknown_key_classes"]
        require(type(classes) is list and len(classes) <= len(UNKNOWN_CLASSES))
        for item in classes: enum(item, UNKNOWN_CLASSES)
        require(classes == sorted(set(classes)))
    relation = value["link_relation"]
    require(type(relation) is dict)
    if relation.get("status") == "unobserved": exact(relation, ("status",))
    else:
        exact(relation, ("status", "context", "reason", "value_kind", "admin_down", "operstate_down", "sink"))
        require(relation["status"] == "rejected")
        enum(relation["context"], words("link loopback dummy"))
        enum(relation["reason"], words("non_null sink not_down"))
        enum(relation["value_kind"], words("null string boolean integer number array object"))
        enum(relation["sink"], words("loopback dummy other"))
        boolean(relation["admin_down"]); boolean(relation["operstate_down"])


def driver(value):
    exact(value, ("schema", "kind", "profile", "phase", "failure", "observer", "before_cleanup",
        "diagnostic_only", "cause_established", "joined_core_acceptance", "raw_output_retained"))
    integer(value["schema"], 1, 1)
    require(value["kind"] == "overmorrow-native-first-failure" and value["profile"] == "protected-core"
        and value["failure"] == "NATIVE_TRIAL_PHASE_FAILED")
    enum(value["phase"], DRIVER_PHASES)
    require(value["before_cleanup"] is True and value["diagnostic_only"] is True
        and all(value[key] is False for key in ("cause_established", "joined_core_acceptance", "raw_output_retained")))
    observer = value["observer"]
    if observer is None: return
    exact(observer, ("source_schema", "subphase", "code", "adb_exit_status", "adb_signal"))
    expected = 1 if value["phase"] in DRIVER_STARTUP_PHASES else 5
    integer(observer["source_schema"], expected, expected)
    enum(observer["subphase"], DRIVER_SUBPHASES); enum(observer["code"], DRIVER_CODES)
    if observer["adb_exit_status"] is not None: integer(observer["adb_exit_status"], 0, 255)
    enum(observer["adb_signal"], words("SIGKILL SIGTERM"), nullable=True)


def project_record(name, value):
    require(type(name) is str and name in INPUTS)
    # Check the producer's original finite bound too, even when called with an
    # already decoded object. Return a detached, validated closed projection.
    require(len(encoded(value)) <= INPUT_LIMITS[name])
    {"emulator": emulator, "guest_network": guest_network, "driver": driver}[name](value)
    return json.loads(encoded(value))


def receipt(expected_identity, records):
    identity(expected_identity, 2)
    require(expected_identity["weather_commit"] == WEATHER_COMMIT)
    value = dict(schema=2, kind="weather-android-inner-diagnostic", identity=expected_identity,
        records=records, diagnostic_only=True, cause_established=False, joined_core_acceptance=False,
        physical_device=False, production_authority=False)
    return validate_receipt(value)


def validate_receipt(value):
    exact(value, ("schema", "kind", "identity", "records", "diagnostic_only", "cause_established",
        "joined_core_acceptance", "physical_device", "production_authority"))
    integer(value["schema"], 1, 2)
    require(value["kind"] == "weather-android-inner-diagnostic" and value["diagnostic_only"] is True
        and all(value[key] is False for key in ("cause_established", "joined_core_acceptance", "physical_device", "production_authority")))
    identity(value["identity"], value["schema"])
    exact(value["records"], LEGACY_INPUTS if value["schema"] == 1 else INPUTS)
    for name, row in value["records"].items():
        exact(row, ("state", "facts")); enum(row["state"], words("available absent rejected"))
        if row["state"] == "available": project_record(name, row["facts"])
        else: require(row["facts"] is None)
    require(len(encoded(value)) <= MAX_BYTES)
    return json.loads(encoded(value))
