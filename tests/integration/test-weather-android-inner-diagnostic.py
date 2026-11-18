#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert tests: no SDK, native process, Weather import or fixture privilege."""
import copy
import json
from pathlib import Path
import runpy
import unittest

M = runpy.run_path(str(Path(__file__).with_name("weather-android-inner-diagnostic.py")))
IDENTITY = dict(core_commit="a" * 40, weather_commit=M["WEATHER_COMMIT"], run_id="123", run_attempt="1")


def emulator_fixture():
    return dict(schema=3, kind="hosted-android-emulator-diagnostic", phase="guest_network", command_category="none",
        failure_kind="unknown", check_code="unknown", exit_status=None, output_bytes=0,
        output_complete=False, output_truncated=False, sdk_error="unknown", java_error_family="unknown",
        filesystem_markers=dict(read_only=False, missing=False, access_denied=False), fatal_template="unknown",
        milestones=dict(cli_usage=False, local_repository=False, single_abi_selected=False, hardware_question=False),
        raw_text_exported=False, cause_established=False)


def network_fixture():
    unobserved = dict(outcome="unobserved", error="none", routes=None, rejected_routes=None,
        rejection_counts=None, route_type_counts=None, device_category_counts=None)
    return dict(schema=9, kind="hosted-android-guest-network-diagnostic", stage="routes", failure="link_unknown",
        polls=1, families=dict(ipv4=copy.deepcopy(unobserved), ipv6=copy.deepcopy(unobserved)), snapshot="last_poll",
        typed=dict(status="unknown", ipv4=None, ipv6=None), last_query=dict(name="link_before", outcome="returned"),
        rejection_counts_overlap=True, device_category_basis="fixed_name_convention_only", gate_passed=False,
        cause_established=False, raw_text_exported=False,
        observer=dict(before="verified", after="unobserved", guard=None, outcome="verified"),
        link_decode=dict(status="failed", bytes=100, shape="array_prefix", reason="link_unknown", position=None),
        observer_authority="disposable-userdebug-existing-permissive-su",
        query_streams=dict(status="complete", stdout_bytes=100, stderr_bytes=0, stdout_eof=True, stderr_eof=True, exit_status=0),
        link_decode_query="link_before", link_join=dict(status="unobserved", side=None),
        link_metadata=dict(status="unobserved", context=None, reason=None, field=None, unknown_key_classes=[]),
        link_relation=dict(status="unobserved"))


def driver_fixture():
    return dict(schema=1, kind="overmorrow-native-first-failure", profile="protected-core", phase="actual-refresh",
        failure="NATIVE_TRIAL_PHASE_FAILED", observer=dict(source_schema=5, subphase="product_count_wait",
            code="observation_deadline", adb_exit_status=None, adb_signal=None), before_cleanup=True,
        diagnostic_only=True, cause_established=False, joined_core_acceptance=False, raw_output_retained=False)


def records_fixture():
    return {name: dict(state="available", facts=factory())
        for name, factory in (("emulator", emulator_fixture), ("guest_network", network_fixture), ("driver", driver_fixture))}


class Projection(unittest.TestCase):
    def rejected(self, name, value):
        with self.assertRaises((ValueError, TypeError)) as context:
            M["project_record"](name, value)
        self.assertNotIn("PRIVATE_CANARY", str(context.exception))

    def test_exact_producer_shapes_and_detached_output(self):
        for name, factory in (("emulator", emulator_fixture), ("guest_network", network_fixture), ("driver", driver_fixture)):
            original = factory()
            result = M["project_record"](name, original)
            self.assertEqual(result, original)
            self.assertIsNot(result, original)
            self.assertLessEqual(len(M["encoded"](result)), M["INPUT_LIMITS"][name])
        value = M["receipt"](IDENTITY, records_fixture())
        self.assertEqual(value["schema"], 2)
        self.assertEqual(M["validate_receipt"](value), value)
        self.assertLess(len(M["encoded"](value)), M["MAX_BYTES"])
        self.assertTrue(value["diagnostic_only"])
        self.assertFalse(value["joined_core_acceptance"])
        self.assertFalse(value["cause_established"])

    def test_emulator_literal_domains(self):
        for field, domain in (("phase", "PHASES"), ("command_category", "COMMANDS"),
                ("failure_kind", "FAILURE_KINDS"), ("check_code", "CHECKS"), ("sdk_error", "SDK_ERRORS"),
                ("java_error_family", "JAVA_ERRORS"), ("fatal_template", "FATAL_TEMPLATES")):
            for item in M[domain]:
                value = emulator_fixture(); value[field] = item
                self.assertEqual(M["project_record"]("emulator", value)[field], item)
            for item in ("PRIVATE_CANARY", "", None, True, [], {}):
                value = emulator_fixture(); value[field] = item
                self.rejected("emulator", value)

    def test_emulator_bounds_and_booleans(self):
        for field, invalid in (("schema", (True, 2, 4)), ("exit_status", (True, -256, 256, 1.5)),
                ("output_bytes", (True, -1, 65537)), ("output_complete", (1, "true", None)),
                ("output_truncated", (0, "false", None)), ("raw_text_exported", (True, 0)),
                ("cause_established", (True, 0))):
            for item in invalid:
                value = emulator_fixture(); value[field] = item
                self.rejected("emulator", value)
        value = emulator_fixture(); value.update(output_complete=True, output_truncated=True)
        self.rejected("emulator", value)

    def test_unknown_fields_rejected_at_every_nested_object(self):
        def objects(value):
            if type(value) is dict:
                yield value
                for item in value.values(): yield from objects(item)
        for name, factory in (("emulator", emulator_fixture), ("guest_network", network_fixture), ("driver", driver_fixture)):
            value = factory()
            for row in list(objects(value)):
                row["PRIVATE_CANARY"] = "private path / account / exception"
                self.rejected(name, value)
                del row["PRIVATE_CANARY"]
            value["padding"] = "PRIVATE_CANARY" * 10000
            self.rejected(name, value)

    def test_historical_network_shapes_and_raw_text_not_admitted(self):
        for version in (True, 1, 3, 5, 6, 7, 8, 10):
            value = network_fixture(); value["schema"] = version
            self.rejected("guest_network", value)
        for field in ("gate_passed", "cause_established", "raw_text_exported"):
            for invalid in (True, 0):
                value = network_fixture(); value[field] = invalid
                self.rejected("guest_network", value)
        for field in ("kind", "snapshot", "device_category_basis", "observer_authority", "stage", "failure"):
            value = network_fixture(); value[field] = "PRIVATE_CANARY"
            self.rejected("guest_network", value)

    def test_network_failure_and_decoder_reason_domains(self):
        for reason in M["NETWORK_FAILURES"]:
            value = network_fixture(); value["failure"] = reason
            self.assertEqual(M["project_record"]("guest_network", value)["failure"], reason)
        for reason in M["PARSE_REASONS"]:
            value = network_fixture(); value["link_decode"]["reason"] = reason
            self.assertEqual(M["project_record"]("guest_network", value)["link_decode"]["reason"], reason)
        for section, field in (("observer", "guard"), ("observer", "before"), ("last_query", "name"),
                ("last_query", "outcome"), ("link_decode", "reason"), ("link_decode", "shape"),
                ("query_streams", "status"), ("link_join", "side")):
            value = network_fixture(); value[section][field] = "PRIVATE_CANARY"
            self.rejected("guest_network", value)

    def test_network_unobserved_and_current_query_binding(self):
        value = network_fixture()
        value.update(stage="wifi_disable", polls=0, failure="command_exit", link_decode_query=None)
        value["last_query"] = dict(name=None, outcome="unobserved")
        value["observer"] = dict(before="unobserved", after="unobserved", guard=None, outcome="unobserved")
        value["link_decode"] = dict(status="unobserved", bytes=None, shape="unobserved", reason="none", position=None)
        value["query_streams"] = dict(status="unobserved", stdout_bytes=None, stderr_bytes=None,
            stdout_eof=False, stderr_eof=False, exit_status=None)
        self.assertEqual(M["project_record"]("guest_network", value), value)
        value["link_decode_query"] = "link_before"
        self.rejected("guest_network", value)
        value = network_fixture(); value["link_decode_query"] = "link_after"
        self.rejected("guest_network", value)
        value = network_fixture(); value["link_join"] = dict(status="failed", side="before")
        self.rejected("guest_network", value)
        value.update(link_decode_query="dummy_before", last_query=dict(name="dummy_before", outcome="returned"))
        self.assertEqual(M["project_record"]("guest_network", value), value)

    def test_network_numeric_counts_and_stream_completion(self):
        for field in ("polls",):
            for bad in (True, -1, 65537):
                value = network_fixture(); value[field] = bad
                self.rejected("guest_network", value)
        for section, field, bad in (("link_decode", "bytes", True), ("link_decode", "bytes", 65538),
                ("link_decode", "position", 65537), ("query_streams", "stdout_bytes", 65538),
                ("query_streams", "stderr_bytes", -1), ("query_streams", "stdout_eof", 1),
                ("query_streams", "exit_status", True), ("query_streams", "exit_status", -129),
                ("query_streams", "exit_status", 256), ("query_streams", "exit_status", 1),
                ("query_streams", "stdout_eof", False)):
            value = network_fixture(); value[section][field] = bad
            self.rejected("guest_network", value)

    def test_network_families_counted_original_and_unknown(self):
        value = network_fixture()
        row = dict(outcome="rejected", error="none", routes=1, rejected_routes=1,
            rejection_counts={key: int(key == "non_loopback") for key in M["REJECTION_COUNTS"]},
            route_type_counts={key: int(key == "unicast_or_unspecified") for key in M["ROUTE_COUNTS"]},
            device_category_counts={key: int(key == "ethernet") for key in M["DEVICE_COUNTS"]})
        # Retain only one counted family within f6's unchanged 2KiB limit.
        value["families"]["ipv4"] = row
        self.assertEqual(M["project_record"]("guest_network", value), value)
        row["routes"] = True; self.rejected("guest_network", value)
        row["routes"] = 0; self.rejected("guest_network", value)
        row["routes"] = 1; row["device_category_counts"]["ethernet"] = 0
        self.rejected("guest_network", value)
        value = network_fixture(); value["families"]["ipv4"].update(outcome="unknown", error="link_unknown")
        self.assertEqual(M["project_record"]("guest_network", value), value)

    def test_closed_metadata_and_relation_reasons(self):
        for reason in M["METADATA_REASONS"]:
            value = network_fixture()
            value["link_metadata"] = dict(status="rejected", context="rows", reason=reason,
                field="row", unknown_key_classes=["other_unknown"])
            self.assertEqual(M["project_record"]("guest_network", value), value)
        for reason in ("non_null", "sink", "not_down"):
            value = network_fixture()
            value["link_relation"] = dict(status="rejected", context="link", reason=reason,
                value_kind="null", admin_down=True, operstate_down=False, sink="other")
            self.assertEqual(M["project_record"]("guest_network", value), value)
        for field in ("context", "reason", "value_kind", "sink", "admin_down", "operstate_down"):
            altered = copy.deepcopy(value); altered["link_relation"][field] = "PRIVATE_CANARY"
            self.rejected("guest_network", altered)
        value = network_fixture()
        value["link_metadata"] = dict(status="rejected", context="join", reason="unknown_fields", field="row",
            unknown_key_classes=["PRIVATE_CANARY"])
        self.rejected("guest_network", value)

    def test_receipt_absent_rejected_and_identity_cannot_grant_acceptance(self):
        for state in ("absent", "rejected"):
            records = {key: dict(state=state, facts=None) for key in M["INPUTS"]}
            value = M["receipt"](IDENTITY, records)
            self.assertEqual(value["records"], records)
            for field in ("joined_core_acceptance", "cause_established", "production_authority", "physical_device"):
                changed = copy.deepcopy(value); changed[field] = True
                with self.assertRaises(ValueError): M["validate_receipt"](changed)
            changed = copy.deepcopy(value); changed["records"]["emulator"]["facts"] = emulator_fixture()
            with self.assertRaises(ValueError): M["validate_receipt"](changed)
        for field, invalid in (("core_commit", "A" * 40), ("weather_commit", "b" * 40),
                ("run_id", "0"), ("run_attempt", 1)):
            selected = dict(IDENTITY); selected[field] = invalid
            with self.assertRaises(ValueError): M["receipt"](selected, records_fixture())

    def test_driver_closed_domains_startup_binding_and_unknown_observer(self):
        for phase in M["DRIVER_PHASES"]:
            value = driver_fixture(); value["phase"] = phase
            value["observer"]["source_schema"] = 1 if phase in M["DRIVER_STARTUP_PHASES"] else 5
            self.assertEqual(M["project_record"]("driver", value), value)
            value["observer"]["source_schema"] = 5 if phase in M["DRIVER_STARTUP_PHASES"] else 1
            self.rejected("driver", value)
        for field, domain in (("subphase", "DRIVER_SUBPHASES"), ("code", "DRIVER_CODES")):
            for item in M[domain]:
                value = driver_fixture(); value["observer"][field] = item
                self.assertEqual(M["project_record"]("driver", value), value)
        for status in (None, 0, 1, 255):
            for observed_signal in (None, "SIGKILL", "SIGTERM"):
                value = driver_fixture(); value["observer"].update(adb_exit_status=status, adb_signal=observed_signal)
                self.assertEqual(M["project_record"]("driver", value), value)
        value = driver_fixture(); value["observer"] = None
        self.assertEqual(M["project_record"]("driver", value), value)

    def test_driver_cannot_export_raw_data_or_claim_authority(self):
        for field, bad in (("schema", True), ("schema", 2), ("phase", "PRIVATE_CANARY"),
                ("phase", "background-resume-expiry"), ("profile", "synthetic"), ("failure", "PRIVATE_CANARY"),
                ("before_cleanup", False), ("before_cleanup", 1), ("diagnostic_only", 1),
                ("cause_established", True), ("joined_core_acceptance", True), ("raw_output_retained", True)):
            value = driver_fixture(); value[field] = bad; self.rejected("driver", value)
        for field, bad in (("source_schema", True), ("subphase", "PRIVATE_CANARY"), ("code", "PRIVATE_CANARY"),
                ("adb_exit_status", True), ("adb_exit_status", -1), ("adb_exit_status", 256),
                ("adb_exit_status", 0.5), ("adb_signal", True), ("adb_signal", "PRIVATE_CANARY")):
            value = driver_fixture(); value["observer"][field] = bad; self.rejected("driver", value)
        value = driver_fixture(); value["observer"] = {}
        self.rejected("driver", value)

    def test_historical_schema_one_keeps_exact_fields_and_weather_binding(self):
        original = M["receipt"](IDENTITY, records_fixture())
        original["schema"] = 1; del original["records"]["driver"]
        original["identity"]["weather_commit"] = M["LEGACY_WEATHER_COMMIT"]
        raw = M["encoded"](original)
        self.assertEqual(M["encoded"](M["validate_receipt"](original)), raw)
        extended = copy.deepcopy(original); extended["records"]["driver"] = dict(state="absent", facts=None)
        with self.assertRaises(ValueError): M["validate_receipt"](extended)
        downgraded = copy.deepcopy(original); downgraded["schema"] = 2
        with self.assertRaises(ValueError): M["validate_receipt"](downgraded)
        for schema in (True, 0, 3):
            changed = copy.deepcopy(original); changed["schema"] = schema
            with self.assertRaises(ValueError): M["validate_receipt"](changed)
        for commit in (M["FIRST_DRIVER_WEATHER_COMMIT"], M["WEATHER_COMMIT"]):
            changed = copy.deepcopy(original); changed["identity"]["weather_commit"] = commit
            with self.assertRaises(ValueError): M["validate_receipt"](changed)
        # A future producer pin cannot broaden historical schema-one identity.
        globals_ = M["identity"].__globals__; before = globals_["WEATHER_COMMIT"]
        try:
            globals_["WEATHER_COMMIT"] = "b" * 40
            self.assertEqual(M["validate_receipt"](original), original)
            changed = copy.deepcopy(original); changed["identity"]["weather_commit"] = "b" * 40
            with self.assertRaises(ValueError): M["validate_receipt"](changed)
        finally: globals_["WEATHER_COMMIT"] = before

    def test_historical_schema_two_readable_but_not_current_export(self):
        original = M["receipt"](IDENTITY, records_fixture())
        original["identity"]["weather_commit"] = M["FIRST_DRIVER_WEATHER_COMMIT"]
        raw = M["encoded"](original)
        self.assertEqual(M["encoded"](M["validate_receipt"](json.loads(raw))), raw)
        for commit in (M["LEGACY_WEATHER_COMMIT"], M["FIRST_DRIVER_WEATHER_COMMIT"], "b" * 40):
            expected = dict(IDENTITY, weather_commit=commit)
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                M["receipt"](expected, records_fixture())
        for commit in (M["LEGACY_WEATHER_COMMIT"], "b" * 40):
            changed = copy.deepcopy(original); changed["identity"]["weather_commit"] = commit
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                M["validate_receipt"](changed)
        downgraded = copy.deepcopy(original); downgraded["schema"] = 1
        del downgraded["records"]["driver"]
        with self.assertRaises(ValueError): M["validate_receipt"](downgraded)

    def test_static_paths_and_original_limits(self):
        self.assertEqual(M["NAME"], "weather-android-inner-diagnostic.json")
        self.assertEqual(M["INPUT_LIMITS"], dict(emulator=1024, guest_network=2048, driver=2048))
        self.assertEqual(M["MAX_BYTES"], 8192)
        for name, relative in M["LEGACY_INPUTS"].items():
            self.assertEqual(Path(relative).parent.as_posix(), "build/overmorrow-hosted-android-live-proof")
            self.assertEqual(Path(relative).name, "emulator-diagnostic.json" if name == "emulator" else "guest-network-diagnostic.json")
        self.assertEqual(M["INPUTS"]["driver"], "build/overmorrow-hosted-android-live-proof/driver/first-failure.json")
        for name in ("other", "../private.log", True, None):
            with self.assertRaises(ValueError): M["project_record"](name, emulator_fixture())


if __name__ == "__main__":
    unittest.main()
