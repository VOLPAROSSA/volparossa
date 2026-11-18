#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert owner tests: private records and owned Python children, never an APK.

Synthetic fixtures test rejection and lifecycle semantics only. They are not
distributed-delivery evidence and cannot enter the guarded hosted workflow.
"""
import copy
import ctypes
import json
import os
from pathlib import Path
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
O = runpy.run_path(str(HERE / "weather-android-owner.py"))
G = O["run"].__globals__
F = runpy.run_path(str(HERE / "test-weather-android-evidence.py"))
E = O["E"]
K = O["K"]
D = O["D"]
KF = runpy.run_path(str(HERE / "test-weather-android-kvm.py"))
DF = runpy.run_path(str(HERE / "test-weather-android-inner-diagnostic.py"))
CORE_COMMIT = "a" * 40
WEATHER_COMMIT = "3b90442a9d5be4db73ccf83cba2028364980c3ca"
IDENTITY = dict(core_commit=CORE_COMMIT, weather_commit=WEATHER_COMMIT, run_id="123", run_attempt="1")
ENV = dict(GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
NATIVE_RESULT = dict(schema=1, kind="hosted-android-protected-core-installed-trial", phase="complete", success=True,
    process_drain_confirmed=True, policy_cleanup_complete=True, host_netns_unchanged=True, synthetic=False,
    expiry_proven=False, core_delivery=False, joined_core_acceptance=False, mobile_core=False, production_authority=False)
NATIVE_DIAGNOSTIC = dict(schema=6, kind="weather-android-native-diagnostic", outcome="failed", category="value",
    code="CORE_SOCKET_ONLY", joined_core_acceptance=False)
TUNNEL_DIAGNOSTIC = dict(schema=1, kind="weather-android-tunnel-diagnostic", success=False,
    joined_core_acceptance=False,
    primary=dict(phase="exchange-join", reason="child-failed", product="weather", ordinal=1,
        completed=0, requests=dict(weather=1, air_quality=0), ssh_status=1, http_status=None),
    cleanup=dict(exchange_child_joined=True, socket_removed=True))
INERT_ROLES = r'''
import json, os, signal, socket, sys, time
from pathlib import Path
role, root, mode = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
data = json.loads((root / 'inert-roles.json').read_bytes())
if role == 'driver':
    if mode == 'driver-exit': sys.exit(3)
    (root / 'driver-ready').touch()
    while not (root / 'finalized').exists():
        if mode == 'driver-exit-native' and (root / 'native-started').exists(): sys.exit(7)
        time.sleep(.01)
elif role == 'read-ready':
    if not (root / 'driver-ready').exists(): sys.exit(1)
    if mode == 'cancel-ready': os.kill(os.getppid(), signal.SIGTERM); sys.exit(1)
    # Match the real fixed controller: retries consume the original budget;
    # they neither return stale remaining time nor extend the deadline.
    data['ready']['remaining_seconds'] = data['ready']['deadline_unix_seconds'] - int(time.time())
    print(json.dumps(data['ready']), flush=True)
elif role == 'finalize':
    if mode == 'finalize-fail': sys.exit(2)
    (root / 'finalized').touch()
    print(json.dumps(data['finalize']), flush=True)
elif role == 'tunnel':
    path = Path(data['socket'])
    stream = socket.socket(socket.AF_UNIX); stream.bind(str(path)); path.chmod(0o600); stream.listen()
    def finish(*_):
        if mode != 'socket-left': path.unlink()
        stream.close()
        if mode == 'tunnel-extra-output': print('unrequested output', flush=True)
        print(json.dumps(data['tunnel']), flush=True); sys.exit(0)
    signal.signal(signal.SIGTERM, finish)
    if mode == 'tunnel-exit': finish()
    while True:
        if mode == 'tunnel-exit-native' and (root / 'native-started').exists(): finish()
        if mode == 'tunnel-exit-first-driver-failure' and (root / 'first-driver-failure-written').exists():
            path.unlink(); stream.close(); sys.exit(1)
        if mode.startswith('tunnel-diagnostic') and (root / 'native-started').exists():
            path.unlink(); stream.close()
            print('PRIVATE tunnel stdout https://example.invalid/private-key', flush=True)
            print('PRIVATE tunnel stderr credential', file=sys.stderr, flush=True)
            print('VOLPAROSSA_WEATHER_ANDROID_TUNNEL_DIAGNOSTIC ' + json.dumps(data['tunnel_diagnostic']), flush=True)
            if mode == 'tunnel-diagnostic-trailing': print('PRIVATE trailing output', flush=True)
            sys.exit(1)
        time.sleep(.01)
elif role == 'native':
    # This role never connects to the socket or creates an Android process.
    # Only coordinator ownership, ordering and failure propagation are tested.
    (root / 'native-started').touch()
    if mode == 'tunnel-exit-first-driver-failure':
        path = Path(data['inner_paths']['driver']); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Original finite first failure is written before simulated APK cleanup
        # breaks the exchange. The owner interrupts us before any final report.
        with path.open('x') as out: out.write(json.dumps(data['inner_records']['driver']))
        path.chmod(0o600); (root / 'first-driver-failure-written').touch()
        time.sleep(30)
    if mode in ('driver-exit-native', 'tunnel-exit-native') or mode.startswith('tunnel-diagnostic'): time.sleep(30)
    if mode == 'native-fail': sys.exit(2)
    if mode.startswith('native-diagnostic'):
        if 'inner' in mode:
            for name, value in data['inner_records'].items():
                path = Path(data['inner_paths'][name]); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_text(json.dumps(value)); path.chmod(0o600)
        print('PRIVATE stdout https://example.invalid/private-token', flush=True)
        print('PRIVATE stderr private-key-fragment', file=sys.stderr, flush=True)
        if 'kvm' in mode:
            print('VOLPAROSSA_ANDROID_KVM_OBSERVATION ' + json.dumps(data['kvm']), flush=True)
        print('VOLPAROSSA_ANDROID_NATIVE_DIAGNOSTIC ' + json.dumps(data['diagnostic']), flush=True)
        if mode == 'native-diagnostic-trailing': print('PRIVATE trailing data', flush=True)
        sys.exit(1)
    if mode == 'native-deadline': time.sleep(30)
    if mode == 'cancel-native': os.kill(os.getppid(), signal.SIGTERM); time.sleep(30)
    path = Path(data['native_result']); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(data['native'])); path.chmod(0o600)
else:
    raise ValueError('unknown inert role')
'''


def save(path, value, mode=0o600):
    raw = value if type(value) is bytes else (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(raw); path.chmod(mode)
    return E["digest"](raw)


def mutate(path, update):
    value = json.loads(path.read_bytes()); update(value); save(path, value)


def tunnel_record(responses):
    return dict(schema=6, kind="weather-android-api-tunnel", completed=6,
        requests=dict.fromkeys(O["T"]["ROUTES"], 3), original_response_bytes=True,
        joined_core_acceptance=False, cleanup_confirmed=True, responses=responses)


def preparation_record():
    return dict(schema=6, kind="weather-android-owner-preflight", identity=IDENTITY,
        prepared_sha256=E["digest"](b"inert original preparation\n"),
        result_sha256=E["digest"](b"inert original preparation result\n"),
        apk=dict(bytes=1024, sha256="e" * 64), original_preparation_verified=True,
        runtime_executed=False, publication_started=False)


class RecordFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-own-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.run = self.root / "weather-client-kvm.Abc123"
        self.weather = self.root / "weather"
        self.output = self.root / "output"
        for path in (self.run, self.weather, self.output): path.mkdir(mode=0o700)
        self.private = self.run / "android-owner"; self.private.mkdir(mode=0o700)
        self.live = self.weather / "build/hosted-android-live-ci"
        self.proof = self.weather / "build/overmorrow-hosted-android-live-proof"
        self.prepared = self.weather / "build/hosted-android-ci"
        self.config = dict(schema=6, core_commit=CORE_COMMIT, weather_commit=WEATHER_COMMIT,
            weather_root=str(self.weather), run_directory=str(self.run), output_directory=str(self.output),
            source_sha256="7" * 64, mpquic_sha256="8" * 64, package_sha256="none",
            weather_archive_sha256="9" * 64, weather_manifest_sha256="1" * 64)
        self.environment = patch.dict(os.environ, ENV); self.environment.start(); self.addCleanup(self.environment.stop)
        self.seams = patch.dict(G, CORE=self.root, hosted=lambda *_: None)
        self.seams.start(); self.addCleanup(self.seams.stop)
        self.guest = F["guest_summary"]()
        self.report, _, responses, _ = F["fixture"]()
        self.ready = dict(schema=6, kind="weather-android-guest-ready", manifest_sha256="1" * 64,
            core_sha256="2" * 64, prepared_sha256="3" * 64,
            # The real API owner budget is intentionally shorter than the
            # independently created 900-second publication lifetimes.
            deadline_unix_seconds=F["END"] // 1000 + 40, remaining_seconds=800,
            api_socket_ready=True, cold_caches_absent=True, helper_requests=0, joined_delivery_proven=False)
        save(self.private / "ready.json", self.ready)
        save(self.private / "preparation.json", preparation_record())
        save(self.private / "result.json", dict(schema=6, kind="weather-android-owner-run", identity=IDENTITY,
            success=True, phase="complete", statuses=dict(driver=0, tunnel=0, native=0),
            cleanup=dict(children_joined=True, forced_kill=False, output_drained=True,
                socket_removed=True, host_netns_unchanged=True), helper_requests=0,
            joined_core_acceptance=False, vm_cleanup_pending=True))
        save(self.private / "finalize.json", dict(schema=6, kind="weather-android-finalize-requested",
            prepared_sha256="3" * 64, finalize_requested=True, joined_delivery_proven=False))
        save(self.private / "tunnel.json", tunnel_record(responses))
        save(self.output / "weather-android-delivery-evidence.json", self.guest)
        save(self.prepared / "prepared.json", b"inert original preparation\n")
        save(self.prepared / "result.json", b"inert original preparation result\n")
        preparation = preparation_record()
        save(self.live / "admission.json", dict(schema=1, kind="hosted-android-protected-core-admission",
            identity=IDENTITY, prepared_sha256=preparation["prepared_sha256"],
            result_sha256=preparation["result_sha256"], apk=preparation["apk"],
            core_executed=False, joined_core_acceptance=False))
        save(self.live / "result.json", NATIVE_RESULT)
        report_sha = save(self.proof / "report.json", self.report)
        boundary_sha = save(self.proof / "emulator-boundary.json", dict(inert=True))
        cleanup_sha = save(self.proof / "emulator-cleanup.json", dict(schema=1, direct_children_reaped=True,
            private_avd_removed=True, private_android_home_removed=True, trial_returned=True,
            enclosing_namespace_cleanup_required=True))
        save(self.live / "installed.json", dict(schema=1, kind="hosted-android-protected-core-installed",
            identity=IDENTITY, apk=preparation["apk"], installed_report_sha256=report_sha,
            boundary_sha256=boundary_sha, emulator_cleanup_sha256=cleanup_sha, actual_installed_app=True,
            synthetic=False, expiry_proven=False, core_delivery=False, joined_core_acceptance=False,
            production_authority=False))
        self.vm = self.output / "weather-android-vm-cleanup.json"
        save(self.vm, dict(schema=6, kind="weather-android-vm-cleanup", core_commit=CORE_COMMIT,
            weather_commit=WEATHER_COMMIT, manifest_sha256="1" * 64, driver_finished=True,
            qemu_started=True, qemu_joined=True, private_guest_state_removed=True, owner_exit_status=0,
            joined_core_acceptance=False))
        self.kvm = self.root / "kvm-cleanup.json"
        save(self.kvm, dict(schema=6, kind="weather-android-kvm-cleanup", identity=IDENTITY,
            baseline_sha256="f" * 64, restored_sha256="f" * 64, baseline_bytes=150, restored_bytes=150,
            original_kvm_acl_restored=True))

    def join(self):
        return O["join"](self.config)

    def accept(self):
        return O["accept"](self.output, CORE_COMMIT, WEATHER_COMMIT, "1" * 64, self.kvm)


class JoinTests(RecordFixture):
    def test_original_six_operations_join_without_promoting_unfinished_vm_cleanup(self):
        result = self.join()
        self.assertFalse(result["joined_core_acceptance"])
        self.assertTrue(result["vm_cleanup_pending"])
        self.assertTrue(result["original_cli_http_ui_joined"])
        self.assertLess(self.ready["deadline_unix_seconds"], self.guest["publications"]["weather"]["expires_unix_seconds"])
        for key in E["PRODUCTS"]:
            self.assertEqual(result["observations"]["products"][key]["requests"], 3)
        for private in (str(self.root), "local_output", "provider_peer_ids", "weather_root"):
            self.assertNotIn(private, json.dumps(result))

    def test_original_records_cannot_be_reencoded_changed_or_replaced(self):
        paths = (self.prepared / "prepared.json", self.prepared / "result.json", self.proof / "report.json",
            self.proof / "emulator-boundary.json", self.proof / "emulator-cleanup.json")
        for path in paths:
            original = path.read_bytes()
            with self.subTest(path=path.name):
                save(path, original + b"\n")
                with self.assertRaises(ValueError): self.join()
                save(path, original)

    def test_rejects_cross_run_native_installation_and_changed_apk(self):
        for basename, updater in (("admission.json", lambda value: value["identity"].update(run_attempt="2")),
                ("installed.json", lambda value: value["apk"].update(sha256="0" * 64)),
                ("result.json", lambda value: value.update(policy_cleanup_complete=False))):
            path = self.live / basename; original = path.read_bytes()
            with self.subTest(basename=basename), self.assertRaises(ValueError):
                mutate(path, updater); self.join()
            save(path, original)

    def test_rejects_wrong_guest_source_binding_or_capture_and_unknown_export_fields(self):
        path = self.output / "weather-android-delivery-evidence.json"; original = path.read_bytes()
        for field, replacement in dict(manifest_sha256="f" * 64, core_sha256="e" * 64,
                prepared_sha256="d" * 64, captures_validated=False, helper_requests=1, private_path="not-exportable").items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                mutate(path, lambda value: value.update({field: replacement})); self.join()
            save(path, original)

    def test_deadline_must_fit_both_publications_and_cover_every_original_receipt(self):
        path = self.private / "ready.json"; original = path.read_bytes()
        for deadline in (self.guest["publications"]["weather"]["expires_unix_seconds"] + 1,
                self.guest["transfers"]["air_quality"][2]["completed_at_ms"] // 1000):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                mutate(path, lambda value: value.update(deadline_unix_seconds=deadline)); self.join()
            save(path, original)

    def test_no_extra_get_changed_http_body_or_unfinished_tunnel_can_join(self):
        path = self.private / "tunnel.json"; original = path.read_bytes()
        changes = (lambda value: value["requests"].update({next(iter(O["T"]["ROUTES"])): 4}),
            lambda value: value["responses"][0].update(body_sha256="0" * 64),
            lambda value: value["responses"].append(value["responses"][0]),
            lambda value: value.update(cleanup_confirmed=False))
        for index, update in enumerate(changes):
            with self.subTest(index=index), self.assertRaises(ValueError): mutate(path, update); self.join()
            save(path, original)

    def test_owner_failed_cleanup_or_unrequested_finalize_is_not_accepted(self):
        for basename, update in (("result.json", lambda value: value["cleanup"].update(forced_kill=True)),
                ("result.json", lambda value: value["statuses"].update(driver=1)),
                ("finalize.json", lambda value: value.update(prepared_sha256="4" * 64))):
            path = self.private / basename; original = path.read_bytes()
            with self.subTest(basename=basename), self.assertRaises(ValueError): mutate(path, update); self.join()
            save(path, original)

    def test_join_is_exclusive_and_never_replaces_prior_evidence(self):
        self.join(); path = self.output / "weather-android-owner-join.json"; original = path.read_bytes()
        with self.assertRaises(FileExistsError): self.join()
        self.assertEqual(path.read_bytes(), original)


class AcceptanceTests(RecordFixture):
    def setUp(self):
        super().setUp(); self.join()

    def test_only_final_gate_promotes_after_exact_vm_and_kvm_cleanup(self):
        result = self.accept()
        self.assertTrue(result["passed"] and result["joined_core_acceptance"])
        self.assertFalse(result["vm_cleanup_pending"] or result["expiry_proven"]
            or result["physical_device"] or result["production_authority"])
        self.assertEqual(result["guest_evidence_sha256"], E["digest"](
            (self.output / "weather-android-delivery-evidence.json").read_bytes()))
        self.assertFalse(result["observations"]["joined_core_acceptance"])

    def test_failure_diagnostic_is_never_join_or_acceptance_authority(self):
        path = self.output / O["FAILURE_NAME"]
        for schema in (6, 7, 8):
            save(path, dict(schema=schema, kind="weather-android-owner-failure", joined_core_acceptance=False))
            with self.assertRaises(ValueError): self.join()
            with self.assertRaises(ValueError): self.accept()
        self.assertFalse((self.output / "weather-android-hosted-acceptance.json").exists())
        path.unlink(); path.symlink_to(self.output / "does-not-exist")
        with self.assertRaises(ValueError): self.join()
        with self.assertRaises(ValueError): self.accept()

    def test_inner_diagnostic_cannot_replace_original_owner_or_delivery_proof(self):
        records = dict.fromkeys(D["INPUTS"], dict(state="absent", facts=None))
        save(self.output / D["NAME"], D["receipt"](IDENTITY, records))
        (self.private / "result.json").unlink()
        (self.output / "weather-android-owner-join.json").unlink()
        with self.assertRaises((OSError, ValueError)): self.join()
        with self.assertRaises((OSError, ValueError)): self.accept()
        self.assertFalse((self.output / "weather-android-hosted-acceptance.json").exists())

    def test_every_vm_cleanup_fact_and_original_owner_exit_is_required(self):
        original = self.vm.read_bytes()
        fields = dict(driver_finished=False, qemu_started=False, qemu_joined=False,
            private_guest_state_removed=False, owner_exit_status=1, joined_core_acceptance=True,
            manifest_sha256="0" * 64, core_commit="0" * 40, weather_commit="1" * 40, unexpected=True)
        for field, replacement in fields.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                mutate(self.vm, lambda value: value.update({field: replacement})); self.accept()
            save(self.vm, original)

    def test_acl_restoration_requires_same_run_exact_bytes_and_digest(self):
        original = self.kvm.read_bytes()
        updates = (lambda value: value["identity"].update(run_id="124"),
            lambda value: value.update(restored_sha256="1" * 64),
            lambda value: value.update(restored_bytes=149),
            lambda value: value.update(original_kvm_acl_restored=False),
            lambda value: value.update(baseline_bytes=True, restored_bytes=True),
            lambda value: value.update(unknown="private"))
        for index, update in enumerate(updates):
            with self.subTest(index=index), self.assertRaises(ValueError): mutate(self.kvm, update); self.accept()
            save(self.kvm, original)

    def test_cannot_change_guest_closed_record_after_the_original_join(self):
        path = self.output / "weather-android-delivery-evidence.json"
        mutate(path, lambda value: value.update(acquisition_sha256="0" * 64))
        with self.assertRaises(ValueError): self.accept()

    def test_cannot_promote_changed_or_overclaimed_observation_projection(self):
        path = self.output / "weather-android-owner-join.json"; original = path.read_bytes()
        updates = (lambda value: value["identity"].update(run_attempt="2"),
            lambda value: value.update(joined_core_acceptance=True),
            lambda value: value["observations"].update(expiry_proven=True),
            lambda value: value["observations"]["products"]["weather"].update(original_receipts=["0" * 64] * 3),
            lambda value: value["observations"]["products"]["weather"].update(requests=True),
            lambda value: value["observations"]["products"]["weather"].update(warm_peer_bytes=1))
        for index, update in enumerate(updates):
            with self.subTest(index=index), self.assertRaises(ValueError): mutate(path, update); self.accept()
            save(path, original)

    def test_acceptance_requires_private_owned_files_and_is_exclusive(self):
        self.vm.chmod(0o644)
        with self.assertRaises(ValueError): self.accept()
        self.vm.chmod(0o600)
        self.accept(); path = self.output / "weather-android-hosted-acceptance.json"; raw = path.read_bytes()
        with self.assertRaises(FileExistsError): self.accept()
        self.assertEqual(path.read_bytes(), raw)


class FailureRecordTests(RecordFixture):
    def inner_export(self, preexisting=None, cleanup=None):
        O["export_inner_diagnostic"](self.config, IDENTITY,
            dict.fromkeys(D["INPUTS"], False) if preexisting is None else preexisting,
            dict(children_joined=True, output_drained=True) if cleanup is None else cleanup)
        path = self.output / D["NAME"]
        raw = path.read_bytes(); path.unlink()
        self.assertLessEqual(len(raw), D["MAX_BYTES"])
        self.assertNotIn(b"PRIVATE", raw)
        self.assertNotIn(str(self.root).encode(), raw)
        return D["validate_receipt"](json.loads(raw))

    def test_inner_originals_are_closed_optional_records_not_acceptance(self):
        originals = dict(emulator=DF["emulator_fixture"](), guest_network=DF["network_fixture"](), driver=DF["driver_fixture"]())
        for name, value in originals.items(): save(self.weather / D["INPUTS"][name], value)
        result = self.inner_export()
        self.assertEqual(result["identity"], IDENTITY)
        self.assertEqual(result["records"], {name: dict(state="available", facts=value)
            for name, value in originals.items()})
        self.assertTrue(result["diagnostic_only"])
        self.assertFalse(any(result[key] for key in ("cause_established", "joined_core_acceptance",
            "physical_device", "production_authority")))
        for row in self.inner_export(dict.fromkeys(D["INPUTS"], True))["records"].values():
            self.assertEqual(row, dict(state="rejected", facts=None))

    def test_inner_missing_and_unsafe_files_are_absent_or_rejected_without_raw_text(self):
        self.assertEqual(self.inner_export()["records"], dict.fromkeys(D["INPUTS"], dict(state="absent", facts=None)))
        path = self.weather / D["INPUTS"]["emulator"]
        target = self.root / "private-diagnostic.json"; save(target, DF["emulator_fixture"]())
        raw = json.dumps(DF["emulator_fixture"]()).encode()
        cases = (
            lambda: path.symlink_to(target),
            lambda: os.link(target, path),
            lambda: os.mkfifo(path, 0o600),
            lambda: save(path, DF["emulator_fixture"](), 0o644),
            lambda: save(path, b"PRIVATE" + b"x" * D["INPUT_LIMITS"]["emulator"]),
            lambda: save(path, b'{"PRIVATE":'),
            lambda: save(path, raw[:-1] + b',"schema":3}'),
            lambda: save(path, dict(DF["emulator_fixture"](), private="PRIVATE")),
        )
        for index, create in enumerate(cases):
            with self.subTest(index=index):
                create()
                try:
                    self.assertEqual(self.inner_export()["records"]["emulator"], dict(state="rejected", facts=None))
                finally: path.unlink()

    def test_inner_symlink_ancestor_and_existing_output_are_not_followed_or_replaced(self):
        target = self.root / "private-proof"; target.mkdir(mode=0o700)
        save(target / "emulator-diagnostic.json", DF["emulator_fixture"]())
        linked_weather = self.root / "linked-weather"; linked_weather.mkdir(mode=0o700)
        (linked_weather / "build").mkdir(mode=0o700)
        (linked_weather / "build/overmorrow-hosted-android-live-proof").symlink_to(target, target_is_directory=True)
        config = dict(self.config, weather_root=str(linked_weather))
        cleanup = dict(children_joined=True, output_drained=True)
        O["export_inner_diagnostic"](config, IDENTITY, dict.fromkeys(D["INPUTS"], False), cleanup)
        path = self.output / D["NAME"]; before = path.read_bytes()
        self.assertEqual(json.loads(before)["records"]["emulator"], dict(state="rejected", facts=None))
        with self.assertRaises(FileExistsError):
            O["export_inner_diagnostic"](config, IDENTITY, dict.fromkeys(D["INPUTS"], False), cleanup)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_driver_record_is_not_read_until_children_and_pipes_are_closed(self):
        path = self.weather / D["INPUTS"]["driver"]; original = DF["driver_fixture"]()
        save(path, original)
        for cleanup in ({}, dict(children_joined=False, output_drained=True),
                dict(children_joined=True, output_drained=False), dict(children_joined=1, output_drained=True),
                dict(children_joined=True, output_drained=1)):
            with self.subTest(cleanup=cleanup), patch.dict(G, document=lambda *_: self.fail("read before joined/drained")):
                result = self.inner_export(cleanup=cleanup)
            self.assertEqual(result["records"]["driver"], dict(state="rejected", facts=None))
        result = self.inner_export()
        self.assertEqual(result["records"]["driver"], dict(state="available", facts=original))
        self.assertEqual(result["schema"], 2)
        self.assertEqual(self.inner_export(dict.fromkeys(D["INPUTS"], True))["records"]["driver"],
            dict(state="rejected", facts=None))

    def test_driver_private_inode_validation_is_not_weakened_for_optional_failure(self):
        path = self.weather / D["INPUTS"]["driver"]; path.parent.mkdir(mode=0o700)
        target = self.root / "original-driver.json"; save(target, DF["driver_fixture"]())
        raw = target.read_bytes().rstrip()
        for index, create in enumerate((lambda: path.symlink_to(target), lambda: os.link(target, path),
                lambda: os.mkfifo(path, 0o600), lambda: save(path, DF["driver_fixture"](), 0o644),
                lambda: save(path, b"PRIVATE" * D["INPUT_LIMITS"]["driver"]),
                lambda: save(path, raw[:-1] + b',"schema":1}'),
                lambda: save(path, dict(DF["driver_fixture"](), private="PRIVATE")))):
            with self.subTest(index=index):
                create()
                try: self.assertEqual(self.inner_export()["records"]["driver"], dict(state="rejected", facts=None))
                finally: path.unlink()

    def native_job(self, raw=None, *, status=1, opened=(), limit=2 * 1024**2):
        if raw is None:
            raw = O["N"]["PREFIX"].encode() + json.dumps(NATIVE_DIAGNOSTIC).encode() + b"\n"
        return dict(process=SimpleNamespace(returncode=status), open=set(opened), limit=limit,
            data=dict(stdout=bytearray(raw), stderr=bytearray(b"PRIVATE stderr not exported")))

    def test_only_closed_last_native_marker_is_exported_not_original_streams(self):
        job = self.native_job(); job["data"]["stdout"][:0] = b"PRIVATE raw stdout\n"
        result = O["native_diagnostic"](job)
        self.assertEqual(result, dict(state="available", record=NATIVE_DIAGNOSTIC))
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(O["native_diagnostic"](None), dict(state="absent", record=None))
        self.assertEqual(O["native_diagnostic"](self.native_job(b"private unmarked output")),
            dict(state="absent", record=None))

    def test_malformed_extra_field_oversized_duplicate_and_nonfinal_marker_rejected(self):
        prefix = O["N"]["PREFIX"].encode(); good = json.dumps(NATIVE_DIAGNOSTIC).encode()
        values = (prefix + good, prefix + good + b"\nPRIVATE trailing\n", prefix + b"{}\n",
            prefix + good + b"\n" + prefix + good + b"\n", prefix + b"x" * 4096 + b"\n",
            prefix + json.dumps(dict(NATIVE_DIAGNOSTIC, private="PRIVATE")).encode() + b"\n",
            prefix + json.dumps(dict(NATIVE_DIAGNOSTIC, code="PRIVATE_KEY")).encode() + b"\n",
            prefix + json.dumps(dict(NATIVE_DIAGNOSTIC, category="private-category")).encode() + b"\n",
            prefix + good[:-1] + b',"schema":6}\n', prefix + b"\xff\n",
            prefix + json.dumps(dict(NATIVE_DIAGNOSTIC, joined_core_acceptance=True)).encode() + b"\n")
        for index, raw in enumerate(values):
            with self.subTest(index=index):
                self.assertEqual(O["native_diagnostic"](self.native_job(raw)), dict(state="rejected", record=None))
        for job in (self.native_job(status=None), self.native_job(opened=("stdout",)), self.native_job(limit=32)):
            self.assertEqual(O["native_diagnostic"](job), dict(state="rejected", record=None))

    def tunnel_marker(self, value=None):
        return O["T"]["PREFIX"].encode() + json.dumps(TUNNEL_DIAGNOSTIC if value is None else value).encode() + b"\n"

    def test_only_unique_closed_last_tunnel_marker_is_exported_without_private_streams(self):
        raw = b"PRIVATE stdout\n" + self.tunnel_marker()
        for status in (1, -signal.SIGTERM):
            with self.subTest(status=status):
                result = O["tunnel_diagnostic"](self.native_job(raw, status=status))
                self.assertEqual(result, TUNNEL_DIAGNOSTIC)
                self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertIsNone(O["tunnel_diagnostic"](None))
        self.assertIsNone(O["tunnel_diagnostic"](self.native_job(b"PRIVATE unmarked stdout")))
        stderr_only = self.native_job(b"PRIVATE unmarked stdout")
        stderr_only["data"]["stderr"] = bytearray(self.tunnel_marker())
        self.assertIsNone(O["tunnel_diagnostic"](stderr_only))
        for job in (self.native_job(raw, status=None), self.native_job(raw, status=0),
                self.native_job(raw, status=True), self.native_job(raw, status=256),
                self.native_job(raw, opened=("stdout",)), self.native_job(raw, opened=("stderr",)),
                self.native_job(raw, limit=32)):
            self.assertIsNone(O["tunnel_diagnostic"](job))

    def test_tunnel_marker_duplicate_nonfinal_unknown_and_private_fields_yield_no_facts(self):
        marker = self.tunnel_marker(); prefix = O["T"]["PREFIX"].encode()
        cases = [marker[:-1], marker + b"PRIVATE trailing\n", marker + marker,
            marker + b"PRIVATE between\n" + marker, prefix + b"{}\n", prefix + b"\xff\n",
            marker[:-2] + b',"schema":1}\n', self.tunnel_marker(dict(TUNNEL_DIAGNOSTIC, PRIVATE="secret")),
            self.tunnel_marker(dict(TUNNEL_DIAGNOSTIC, schema=2)),
            self.tunnel_marker(dict(TUNNEL_DIAGNOSTIC, joined_core_acceptance=True)),
            self.tunnel_marker(dict(TUNNEL_DIAGNOSTIC, success=True))]
        for field, replacement in (("phase", "PRIVATE stage"), ("reason", "PRIVATE error"),
                ("product", "https://private.invalid/secret"), ("ordinal", 4), ("ssh_status", "PRIVATE"),
                ("http_status", "PRIVATE"), ("requests", dict(weather=1, air_quality=0, PRIVATE=1))):
            value = copy.deepcopy(TUNNEL_DIAGNOSTIC); value["primary"][field] = replacement
            cases.append(self.tunnel_marker(value))
        for raw in cases:
            with self.subTest(length=len(raw)):
                self.assertIsNone(O["tunnel_diagnostic"](self.native_job(raw)))
        with patch.dict(O["T"], validate_diagnostic=lambda *_: (_ for _ in ()).throw(ValueError("PRIVATE parse"))):
            self.assertIsNone(O["tunnel_diagnostic"](self.native_job(marker)))

    def test_nullable_tunnel_observations_never_invent_primary_or_cleanup_facts(self):
        unknown = copy.deepcopy(TUNNEL_DIAGNOSTIC)
        unknown["primary"] = dict(phase=None, reason=None, product=None, ordinal=None, completed=0,
            requests=dict(weather=0, air_quality=0), ssh_status=None, http_status=None)
        unknown["cleanup"] = dict(exchange_child_joined=None, socket_removed=None)
        self.assertEqual(O["tunnel_diagnostic"](self.native_job(self.tunnel_marker(unknown))), unknown)

    def test_tunnel_marker_bound_includes_prefix_and_final_newline(self):
        marker = self.tunnel_marker()
        padding = O["T"]["MAX_DIAGNOSTIC_BYTES"] - len(marker)
        bounded = marker[:-1] + b" " * padding + b"\n"
        self.assertEqual(len(bounded), O["T"]["MAX_DIAGNOSTIC_BYTES"])
        self.assertEqual(O["tunnel_diagnostic"](self.native_job(bounded)), TUNNEL_DIAGNOSTIC)
        self.assertIsNone(O["tunnel_diagnostic"](self.native_job(bounded[:-1] + b" \n")))

    def test_tunnel_export_requires_confirmed_group_join_and_drain(self):
        result = json.loads((self.private / "result.json").read_bytes()); result["success"] = False
        job = self.native_job(self.tunnel_marker()); job["name"] = "tunnel"
        for field in ("children_joined", "output_drained"):
            failed = copy.deepcopy(result); failed["cleanup"][field] = False
            with patch.dict(G, tunnel_diagnostic=lambda *_: self.fail("unconfirmed child diagnostic decoded")):
                O["export_failure"](self.config, failed, SimpleNamespace(jobs=[job]),
                    dict.fromkeys(O["NATIVE_RECORDS"], False), None)
            path = self.output / O["FAILURE_NAME"]
            failure = json.loads(path.read_bytes()); path.unlink()
            self.assertEqual(failure["schema"], 8)
            self.assertIsNone(failure["tunnel_diagnostic"])
            self.assertFalse(failure["success"] or failure["joined_core_acceptance"])

    def test_separate_kvm_marker_binds_identity_and_exact_original_guard(self):
        before = KF["private_fixture"]()
        value = K["native_record"](IDENTITY, before, before, "available", before)
        prefix = K["PREFIX"].encode()
        line = prefix + json.dumps(value).encode() + b"\n"
        diagnostic = O["N"]["PREFIX"].encode() + json.dumps(dict(NATIVE_DIAGNOSTIC, code="KVM_REQUIRED_NO_TCG")).encode() + b"\n"
        job = self.native_job(b"PRIVATE raw\n" + line + diagnostic)
        observed = O["native_kvm"](job, IDENTITY)
        self.assertEqual(observed, dict(state="available", record=value))
        self.assertNotIn("PRIVATE", json.dumps(observed))
        self.assertEqual(O["native_kvm"](None, IDENTITY), dict(state="absent", record=None))
        self.assertEqual(O["native_kvm"](self.native_job(), IDENTITY), dict(state="absent", record=None))
        success = dict(value, at_kvm_guard_failure=None)
        self.assertEqual(O["native_kvm"](self.native_job(prefix + json.dumps(success).encode() + b"\n", status=0), IDENTITY),
            dict(state="available", record=success))
        failures = (line + diagnostic + b"trailing\n", line + line + diagnostic, line + diagnostic[:-1],
            line + b"\n" + diagnostic, line + self.native_job()["data"]["stdout"],
            prefix + b"x" * 8192 + b"\n" + diagnostic,
            prefix + json.dumps(dict(value, extra="PRIVATE")).encode() + b"\n" + diagnostic,
            prefix + json.dumps(dict(value, identity=dict(IDENTITY, run_attempt="2"))).encode() + b"\n" + diagnostic,
            prefix + json.dumps(dict(value, joined_core_acceptance=True)).encode() + b"\n" + diagnostic,
            prefix + b"\xff\n" + diagnostic)
        for raw in failures:
            self.assertEqual(O["native_kvm"](self.native_job(raw), IDENTITY), dict(state="rejected", record=None))
        for job in (self.native_job(line + diagnostic, status=None), self.native_job(line + diagnostic, opened=("stdout",)),
                self.native_job(line + diagnostic, limit=32), self.native_job(line, status=0)):
            self.assertEqual(O["native_kvm"](job, IDENTITY), dict(state="rejected", record=None))

    def test_original_result_and_emulator_cleanup_are_separate_diagnostic_facts(self):
        records = O["native_originals"](self.weather, dict.fromkeys(O["NATIVE_RECORDS"], False))
        self.assertEqual(records["result"], dict(state="available", facts=NATIVE_RESULT))
        self.assertEqual(records["failure"], dict(state="absent", facts=None))
        self.assertEqual(records["emulator_cleanup"]["state"], "available")
        self.assertEqual(records["emulator_cleanup"]["facts"], json.loads((self.proof / "emulator-cleanup.json").read_bytes()))
        for record in O["native_originals"](self.weather, dict.fromkeys(O["NATIVE_RECORDS"], True)).values():
            self.assertEqual(record, dict(state="rejected", facts=None))

    def test_private_original_failure_text_is_only_finite_code_and_category(self):
        original = dict(schema=1, phase="baseline", category="ValueError", code="CORE_SOCKET_ONLY")
        self.assertEqual(O["native_facts"]("failure", original),
            dict(phase="baseline", category="value", code="CORE_SOCKET_ONLY"))
        projected = O["native_facts"]("failure", dict(original, category="PRIVATE_EXCEPTION", code="PRIVATE /path?token"))
        self.assertEqual(projected, dict(phase="baseline", category="unknown", code="UNKNOWN"))
        for replacement in (dict(original, private="PRIVATE"), dict(original, phase="PRIVATE"),
                dict(original, schema=True), dict(original, code=["PRIVATE"])):
            with self.assertRaises(ValueError): O["native_facts"]("failure", replacement)

    def test_original_unsafe_missing_symlink_oversize_and_extra_fields_are_explicit(self):
        path = self.live / "result.json"; original = path.read_bytes()
        preexisting = dict.fromkeys(O["NATIVE_RECORDS"], False)
        def state(): return O["native_originals"](self.weather, preexisting)["result"]
        path.unlink(); self.assertEqual(state(), dict(state="absent", facts=None))
        target = self.root / "private-original.json"; save(target, original); path.symlink_to(target)
        self.assertEqual(state(), dict(state="rejected", facts=None)); path.unlink()
        for raw, mode in ((b"x" * 16385, 0o600), (original, 0o644),
                (dict(NATIVE_RESULT, private="PRIVATE"), 0o600), (dict(NATIVE_RESULT, success=1), 0o600),
                (dict(NATIVE_RESULT, production_authority=True), 0o600)):
            save(path, raw, mode)
            self.assertEqual(state(), dict(state="rejected", facts=None))


class ContractTests(RecordFixture):
    def test_children_receive_only_fixed_tool_paths_and_same_run_public_identity(self):
        inherited = dict.fromkeys(O["ENV_KEYS"], "inert")
        inherited.update(HTTP_PROXY="secret proxy", NODE_OPTIONS="unrequested module", GH_TOKEN="secret token")
        with patch.dict(os.environ, inherited, clear=True): value = O["environment"]()
        self.assertEqual(set(value), set(O["ENV_KEYS"]) | {"PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE",
            "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT"})
        self.assertEqual(value["PATH"], "/usr/bin:/bin")
        self.assertEqual((O["NATIVE_SECONDS"], O["TUNNEL_SECONDS"]), (420, 480))

    def test_git_head_is_compared_as_original_bytes_and_dirty_tree_check_is_required(self):
        head = subprocess.CompletedProcess([], 0, stdout=(CORE_COMMIT + "\n").encode())
        clean = subprocess.CompletedProcess([], 0, stdout=b"")
        with patch.dict(G, environment=lambda: {}), patch("subprocess.run", side_effect=[head, clean]) as process:
            O["git_check"](self.root, CORE_COMMIT)
        self.assertEqual(process.call_count, 2)
        self.assertEqual(process.call_args_list[0].args[0][-2:], ["rev-parse", "HEAD"])
        self.assertEqual(process.call_args_list[1].args[0][-4:], ["diff", "--quiet", "HEAD", "--"])
        with patch.dict(G, environment=lambda: {}), patch("subprocess.run", return_value=clean), self.assertRaises(ValueError):
            O["git_check"](self.root, CORE_COMMIT)

    def test_preflight_reuses_pinned_original_preparation_without_invoking_runtime(self):
        calls = []
        helper = object()
        runtime = {"H": SimpleNamespace(policy_helper=lambda: helper),
            "prepared_core_inputs": lambda selected: calls.append(selected) or dict(apk=preparation_record()["apk"])}
        with patch.dict(G, git_check=lambda *args: calls.append(args)), \
                patch.object(O["runpy"], "run_path", return_value=runtime) as load:
            result = O["prepared"](self.weather, CORE_COMMIT, WEATHER_COMMIT)
        self.assertEqual(result, preparation_record())
        self.assertEqual(calls, [(self.root, CORE_COMMIT), (self.weather, WEATHER_COMMIT), helper])
        self.assertEqual(load.call_args.args, (str(self.weather / "scripts/prepare_hosted_android_ci.py"),))
        with self.assertRaises(ValueError): O["prepared"](self.weather, CORE_COMMIT, "f" * 40)

    def test_preflight_kvm_unavailable_exports_only_diagnostic_and_stops_before_guest(self):
        before = dict(KF["private_fixture"](), open_result="eacces", real_write=False)
        with patch.dict(G, prepared=lambda *_: preparation_record()), patch.dict(K, snapshot=lambda: before):
            with self.assertRaisesRegex(ValueError, "kvm-unavailable"):
                O["preflight"](self.weather, CORE_COMMIT, WEATHER_COMMIT, self.output)
        path = self.output / K["NAME"]
        receipt = K["validate_receipt"](json.loads(path.read_bytes()))
        self.assertEqual(receipt["phase"], "preflight")
        self.assertEqual(receipt["owner_before_publication"]["open_result"], "eacces")
        self.assertFalse(receipt["joined_core_acceptance"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_preflight_persists_private_pre_qemu_baseline_only_at_fixed_run_path(self):
        path = self.run / "kvm-before-vm.json"
        with patch.dict(G, prepared=lambda *_: preparation_record()), \
                patch.dict(K, snapshot=KF["private_fixture"], group_acl=KF["acl_fixture"]):
            self.assertEqual(O["preflight"](self.weather, CORE_COMMIT, WEATHER_COMMIT, self.output, path), preparation_record())
            with self.assertRaises(FileExistsError): O["preflight"](self.weather, CORE_COMMIT, WEATHER_COMMIT, self.output, path)
            for bad in (self.run / "other.json", self.output / "kvm-before-vm.json", self.root / "kvm-before-vm.json"):
                with self.assertRaises(ValueError): O["preflight"](self.weather, CORE_COMMIT, WEATHER_COMMIT, self.output, bad)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        initial = K["continuity_baseline"](json.loads(path.read_bytes()), IDENTITY)
        self.assertEqual(initial["snapshot"], KF["private_fixture"]())
        self.assertEqual(initial["acl"], KF["acl_fixture"]())
        self.assertEqual(O["kvm_continuity"](self.run, IDENTITY), ("available", initial))
        self.assertFalse((self.output / "kvm-before-vm.json").exists())

    def test_private_pre_qemu_baseline_rejects_cross_run_symlink_mode_and_oversize(self):
        path = self.run / "kvm-before-vm.json"
        self.assertEqual(O["kvm_continuity"](self.run, IDENTITY), ("absent", None))
        initial = K["continuity_baseline_record"](IDENTITY, KF["private_fixture"](), KF["acl_fixture"]())
        for value, mode in ((dict(initial, identity=dict(IDENTITY, run_attempt="2")), 0o600),
                (dict(initial, extra="PRIVATE"), 0o600), (b"x" * 16385, 0o600), (initial, 0o644)):
            save(path, value, mode)
            self.assertEqual(O["kvm_continuity"](self.run, IDENTITY), ("rejected", None))
        path.unlink(); target = self.root / "private.json"; save(target, initial); path.symlink_to(target)
        self.assertEqual(O["kvm_continuity"](self.run, IDENTITY), ("rejected", None))

    def test_preflight_group_acl_failure_is_visible_and_never_creates_baseline(self):
        acl = KF["acl_fixture"](); acl["mask_write"] = False
        path = self.run / "kvm-before-vm.json"
        with patch.dict(G, prepared=lambda *_: preparation_record()), \
                patch.dict(K, snapshot=KF["private_fixture"], group_acl=lambda: acl):
            with self.assertRaisesRegex(ValueError, "kvm-group-unavailable"):
                O["preflight"](self.weather, CORE_COMMIT, WEATHER_COMMIT, self.output, path)
        self.assertFalse(path.exists())
        receipt = K["validate_receipt"](json.loads((self.output / K["NAME"]).read_bytes()))
        self.assertEqual((receipt["schema"], receipt["phase"]), (2, "preflight"))
        self.assertFalse(receipt["acl_before_publication"]["mask_write"])

    def test_kvm_receipt_alone_never_supplies_acceptance_records(self):
        receipt = K["receipt"](IDENTITY, "owner", KF["private_fixture"]())
        save(self.output / K["NAME"], receipt)
        (self.private / "result.json").unlink()
        with self.assertRaises(FileNotFoundError): self.join()

    def test_hosted_guard_rejects_local_root_wrong_workflow_and_cross_run_identity(self):
        good = dict(GITHUB_ACTIONS="true", RUNNER_OS="Linux", RUNNER_ENVIRONMENT="github-hosted",
            GITHUB_REPOSITORY="VOLPAROSSA/volparossa", GITHUB_WORKFLOW="Weather Android protected core delivery",
            GITHUB_WORKSPACE=str(self.root), GITHUB_SHA=CORE_COMMIT, VOLPAROSSA_WEATHER_SOURCE_SHA=WEATHER_COMMIT,
            **ENV)
        with patch.dict(os.environ, good, clear=True), patch("os.getuid", return_value=1000), \
                patch("os.geteuid", return_value=1000), patch.object(Path, "read_text", return_value="NoNewPrivs:\t0\n"):
            O["hosted"](CORE_COMMIT, WEATHER_COMMIT)
            for key, value in dict(GITHUB_ACTIONS="false", GITHUB_REPOSITORY="VOLPAROSSA/volparossa-weather",
                    GITHUB_WORKFLOW="unrelated workflow", GITHUB_SHA="b" * 40, GITHUB_RUN_ATTEMPT="0",
                    VOLPAROSSA_WEATHER_SOURCE_SHA="c" * 40).items():
                with self.subTest(key=key), patch.dict(os.environ, {key: value}), self.assertRaises(ValueError):
                    O["hosted"](CORE_COMMIT, WEATHER_COMMIT)
            with patch("os.geteuid", return_value=0), self.assertRaises(ValueError): O["hosted"](CORE_COMMIT, WEATHER_COMMIT)
            with patch.object(Path, "read_text", return_value="NoNewPrivs:\t1\n"), self.assertRaises(ValueError):
                O["hosted"](CORE_COMMIT, WEATHER_COMMIT)

    def test_fixed_ssh_commands_have_no_caller_selected_program_or_destination(self):
        for name in ("guest-key", "known-hosts"): save(self.run / name, b"inert\n")
        driver = O["command"](self.config, "driver")
        remote = driver.index("vpci@127.0.0.1")
        self.assertEqual(driver[remote + 1:], ["/home/vpci/guest-driver.sh", CORE_COMMIT, "7" * 64,
            "8" * 64, "none", "content-provider", "weather-client", "9" * 64, "1" * 64])
        for action in ("read-ready", "finalize"):
            controller = O["command"](self.config, "controller", action)
            self.assertEqual(controller[:remote + 1], driver[:remote + 1])
            self.assertEqual(controller[remote + 1:], ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", O["CONTROL"], action])
        with self.assertRaises(ValueError): O["command"](self.config, "controller", "/bin/sh")
        self.assertEqual(O["command"](self.config, "native"), ["/usr/bin/python3", "-B",
            str(HERE / "weather-android-native.py"), "--weather-root", str(self.weather),
            "--core-commit", CORE_COMMIT, "--weather-commit", WEATHER_COMMIT,
            "--upstream-socket", str(self.run / "android-api/core-api.sock")])

    def test_configuration_has_exact_paths_pins_and_no_program_injection(self):
        for name in ("guest-key", "known-hosts"): save(self.run / name, b"inert\n")
        path = self.run / "android-owner-input.json"; save(path, self.config)
        self.assertEqual(O["config"](path), self.config)
        for field, replacement in dict(command="/bin/sh", package_sha256="0" * 64,
                source_sha256="not-a-digest", schema=True, output_directory=str(self.run)).items():
            value = dict(self.config); value[field] = replacement; save(path, value)
            with self.subTest(field=field), self.assertRaises(ValueError): O["config"](path)
        save(path, self.config)
        linked = self.run / "configuration-link.json"; linked.symlink_to(path)
        with self.assertRaises(ValueError): O["config"](linked)

    def test_ready_budget_is_not_extended_and_historical_observation_is_not_new_authority(self):
        now = 1792000000
        ready = dict(self.ready, deadline_unix_seconds=now + 700, remaining_seconds=700)
        with patch.object(O["time"], "time", return_value=now): O["ready_record"](ready, self.config)
        for deadline, remaining in ((now - 1, 700), (now + 841, 841), (now + 700, 840), (now + 599, 599)):
            with self.subTest(deadline=deadline), patch.object(O["time"], "time", return_value=now), self.assertRaises(ValueError):
                O["ready_record"](dict(ready, deadline_unix_seconds=deadline, remaining_seconds=remaining), self.config)
        with patch.object(O["time"], "time", return_value=now + 900):
            O["ready_record"](ready, self.config, historical=True)


class StopObservationTests(unittest.TestCase):
    def pool(self):
        return SimpleNamespace(overflow=False, jobs=[dict(name=name, process=SimpleNamespace(returncode=status),
            open=set(streams)) for name, status, streams in (("driver", None, ("stdout", "stderr")),
                ("tunnel", 1, ("stderr",)), ("native", -signal.SIGTERM, ()))])

    def test_native_budget_sources_are_distinct_and_ties_are_not_recomputed(self):
        names = ("owner-reserve", "publication-reserve-monotonic", "native", "publication-reserve-wall")
        for reached in ((name,) for name in names):
            with self.subTest(reached=reached), patch.object(O["time"], "monotonic", return_value=100), \
                    patch.object(O["time"], "time", return_value=200):
                mono = tuple((name, 100 if name in reached else 101) for name in names[:3])
                wall = ((names[3], 200 if names[3] in reached else 201),)
                with self.assertRaises(O["Deadline"]) as caught: O["check_deadlines"](mono, wall)
                self.assertEqual(caught.exception.budgets, reached)
            # Cleanup may occur much later; the original branch facts stay frozen.
            with patch.object(O["time"], "monotonic", side_effect=AssertionError("no later clock read")), \
                    patch.object(O["time"], "time", side_effect=AssertionError("no later clock read")):
                stop = O["owner_stop"](caught.exception, "native-wait", self.pool())
            self.assertEqual(stop["budgets"], list(reached))
        with patch.object(O["time"], "monotonic", return_value=100), patch.object(O["time"], "time", return_value=200):
            with self.assertRaises(O["Deadline"]) as caught:
                O["check_deadlines"](tuple((name, 100) for name in names[:3]), ((names[3], 200),))
        self.assertEqual(caught.exception.budgets, names)

    def test_wait_keeps_the_original_minimum_and_wall_deadline(self):
        pool = SimpleNamespace(done=lambda _: False)
        with patch.object(O["time"], "monotonic", return_value=100), patch.object(O["time"], "time", return_value=200):
            with self.assertRaises(O["Deadline"]) as caught:
                O["Children"].wait(pool, None, 100, deadline_scopes=(("owner", 101), ("read-ready", 100)))
            self.assertEqual(caught.exception.budgets, ("read-ready",))
            with self.assertRaises(O["Deadline"]) as caught:
                O["Children"].wait(pool, None, 101, wall_deadline=200,
                    deadline_scopes=(("owner", 102), ("finalize", 101)), wall_scope="publication-wall")
            self.assertEqual(caught.exception.budgets, ("publication-wall",))
            with self.assertRaises(ValueError):
                O["Children"].wait(pool, None, 99, deadline_scopes=(("owner", 101),))
            # A non-expired check neither sleeps nor renews any authorization.
            self.assertIsNone(O["check_deadlines"]((("owner", 101),), (("publication-wall", 201),)))

    def test_snapshot_is_copied_without_polling_and_preserves_negative_exit_status(self):
        pool = self.pool()
        stop = O["owner_stop"](O["Failure"]("tunnel-exited"), "native-wait", pool)
        self.assertEqual(stop["children"]["driver"]["state"], "running")
        self.assertEqual(stop["children"]["tunnel"], dict(state="exited", status=1, stdout_open=False, stderr_open=True))
        self.assertEqual(stop["children"]["native"]["status"], -signal.SIGTERM)
        pool.jobs[0]["process"].returncode = 255
        pool.jobs[0]["open"].clear(); pool.overflow = True
        self.assertEqual(stop["children"]["driver"], dict(state="running", status=None, stdout_open=True, stderr_open=True))
        self.assertFalse(stop["output_overflow"])

    def test_only_fixed_reasons_are_exported_without_exception_text(self):
        cases = ((O["Failure"]("PRIVATE path/key/url"), "guard-rejected"),
            (O["Failure"](["PRIVATE"]), "guard-rejected"), (OSError("PRIVATE"), "io-error"),
            (subprocess.SubprocessError("PRIVATE"), "subprocess-error"), (ValueError("PRIVATE"), "guard-rejected"),
            (O["Failure"]("output-limit"), "output-limit"))
        for error, reason in cases:
            stop = O["owner_stop"](error, "native-start", self.pool())
            self.assertEqual(stop["reason"], reason)
            self.assertNotIn("PRIVATE", json.dumps(stop))
            self.assertEqual(stop["budgets"], [])
        self.assertIsNone(O["validate_owner_stop"](None))

    def test_closed_snapshot_rejects_unknown_fields_and_false_deadline_claims(self):
        original = O["owner_stop"](O["Failure"]("interrupted"), "native-wait", self.pool())
        changes = (lambda value: value.update(private="PRIVATE"), lambda value: value.update(stage="PRIVATE"),
            lambda value: value.update(reason="PRIVATE"), lambda value: value.update(reason="deadline"),
            lambda value: value.update(budgets=["native"]), lambda value: value.update(output_overflow=1),
            lambda value: value["children"]["driver"].update(pid=1234),
            lambda value: value["children"]["native"].update(status=True),
            lambda value: value["children"]["native"].update(status=-256))
        for change in changes:
            value = copy.deepcopy(original); change(value)
            with self.assertRaises(ValueError): O["validate_owner_stop"](value)


class ChildTests(unittest.TestCase):
    def setUp(self):
        self.seams = patch.dict(G, TERM_SECONDS=0.15, KILL_SECONDS=1)
        self.seams.start(); self.addCleanup(self.seams.stop)

    def child(self, source, limit=65536):
        pool = O["Children"]()
        job = pool.start([sys.executable, "-B", "-u", "-c", source], "inert", {}, HERE, limit)
        return pool, job

    def assert_drained(self):
        self.assertEqual(Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip(), "")

    def test_original_output_drained_before_success_and_subreaper_restored(self):
        libc = ctypes.CDLL(None); original = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(original), 0, 0, 0), 0)
        pool, job = self.child("import sys; sys.stdout.write('original'); sys.stderr.write('diagnostic')")
        try:
            self.assertEqual(pool.wait(job, time.monotonic() + 2), 0)
            self.assertEqual(bytes(job["data"]["stdout"]), b"original")
            self.assertEqual(bytes(job["data"]["stderr"]), b"diagnostic")
        finally: cleanup = pool.close()
        self.assertEqual(cleanup, dict(children_joined=True, forced_kill=False, output_drained=True))
        after = ctypes.c_int(); self.assertEqual(libc.prctl(37, ctypes.byref(after), 0, 0, 0), 0)
        self.assertEqual(original.value, after.value); self.assert_drained()

    def test_buffered_overflow_after_exit_is_not_success(self):
        pool, job = self.child("import os; os.write(1,b'x'*4096)", limit=32)
        try:
            with self.assertRaises(O["Failure"]): pool.wait(job, time.monotonic() + 2)
        finally: cleanup = pool.close()
        self.assertTrue(cleanup["children_joined"]); self.assertFalse(cleanup["output_drained"])
        self.assertEqual(len(job["data"]["stdout"]), 33); self.assert_drained()

    def test_deadline_joins_only_the_owned_process_group(self):
        pool, job = self.child("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready'); time.sleep(30)")
        try:
            until = time.monotonic() + 2
            while not job["data"]["stdout"] and time.monotonic() < until: pool.pump()
            self.assertTrue(job["data"]["stdout"])
            with self.assertRaises(O["Failure"]): pool.wait(job, time.monotonic() - 1)
        finally: cleanup = pool.close()
        self.assertTrue(cleanup["children_joined"] and cleanup["forced_kill"])
        self.assertEqual(job["process"].returncode, -signal.SIGKILL); self.assert_drained()

    def test_exited_leader_does_not_hide_stdout_holding_detached_descendant(self):
        source = ("import os,signal,time\nif os.fork()==0:\n os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "print('orphan'); time.sleep(30)\nelse:\n os._exit(0)\n")
        pool, job = self.child(source)
        try:
            with self.assertRaises(O["Failure"]): pool.wait(job, time.monotonic() + 0.3)
        finally: cleanup = pool.close()
        self.assertTrue(cleanup["children_joined"] and cleanup["forced_kill"])
        self.assertEqual(job["process"].returncode, 0); self.assert_drained()

    def test_spawn_failure_keeps_cleanup_owner_and_restores_subreaper(self):
        pool = O["Children"]()
        try:
            with patch("subprocess.Popen", side_effect=OSError("private error")), self.assertRaises(OSError):
                pool.start(["inert"], "inert", {}, HERE)
        finally: cleanup = pool.close()
        self.assertEqual(cleanup, dict(children_joined=True, forced_kill=False, output_drained=True)); self.assert_drained()

    def test_pipe_overflow_during_shutdown_cannot_become_clean_success(self):
        source = ("import os,signal,time\ndef stop(*_):\n os.write(2,b'x'*4096); raise SystemExit(0)\n"
            "signal.signal(signal.SIGTERM,stop); print('ready')\nwhile True: time.sleep(.01)\n")
        pool, job = self.child(source, limit=32)
        try:
            until = time.monotonic() + 2
            while not job["data"]["stdout"] and time.monotonic() < until: pool.pump()
            self.assertTrue(job["data"]["stdout"])
        finally: cleanup = pool.close()
        self.assertTrue(cleanup["children_joined"]); self.assertFalse(cleanup["output_drained"]); self.assert_drained()

    def test_blocked_cancellation_is_rejected_before_any_spawn(self):
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
        try:
            with self.assertRaises(ValueError): O["Children"]()
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, prior)
        self.assert_drained()


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-owner-run-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.run = self.root / "weather-client-kvm.Abc123"; self.run.mkdir(mode=0o700)
        self.weather = self.root / "weather"; self.weather.mkdir(mode=0o700)
        self.output = self.root / "output"; self.output.mkdir(mode=0o700)
        self.value = dict(core_commit=CORE_COMMIT, weather_commit=WEATHER_COMMIT,
            weather_root=str(self.weather), run_directory=str(self.run), output_directory=str(self.output),
            weather_manifest_sha256="1" * 64)
        ready = dict(schema=6, kind="weather-android-guest-ready", manifest_sha256="1" * 64, core_sha256="2" * 64,
            prepared_sha256="3" * 64, deadline_unix_seconds=int(time.time()) + 800, remaining_seconds=800,
            api_socket_ready=True, cold_caches_absent=True, helper_requests=0, joined_delivery_proven=False)
        save(self.root / "inert-roles.json", dict(ready=ready, diagnostic=NATIVE_DIAGNOSTIC,
            tunnel_diagnostic=TUNNEL_DIAGNOSTIC,
            finalize=dict(schema=6, kind="weather-android-finalize-requested", prepared_sha256="3" * 64,
                finalize_requested=True, joined_delivery_proven=False), tunnel=tunnel_record(F["fixture"]()[2]),
            socket=str(self.run / "android-api/core-api.sock"),
            native_result=str(self.weather / "build/hosted-android-live-ci/result.json"), native=NATIVE_RESULT))
        self.environment = patch.dict(os.environ, ENV); self.environment.start(); self.addCleanup(self.environment.stop)
        self.seams = patch.dict(G, CORE=self.root, prepared=lambda *_: preparation_record(), environment=lambda: {},
            TERM_SECONDS=1, KILL_SECONDS=1, DRIVER_SECONDS=75)
        self.seams.start(); self.addCleanup(self.seams.stop)
        self.kvm_seam = patch.dict(K, snapshot=lambda: KF["private_fixture"](), group_acl=KF["acl_fixture"])
        self.kvm_seam.start(); self.addCleanup(self.kvm_seam.stop)
        save(self.run / "kvm-before-vm.json", K["continuity_baseline_record"](
            IDENTITY, KF["private_fixture"](), KF["acl_fixture"]()))

    def run_owner(self, mode):
        def command(_value, name, action=None):
            return [sys.executable, "-B", "-u", "-c", INERT_ROLES, action or name, str(self.root), mode]
        with patch.dict(G, command=command): result = O["run"](self.value)
        self.assertEqual(Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip(), "")
        self.assertFalse(result["joined_core_acceptance"])
        self.assertTrue(result["vm_cleanup_pending"])
        self.assertEqual(result["helper_requests"], 0)
        self.assertNotIn(str(self.root), json.dumps(result))
        return result

    def test_ordered_inert_lifecycle_finalizes_after_native_and_tunnel_join(self):
        result = self.run_owner("normal")
        self.assertTrue(result["success"])
        self.assertEqual(result["statuses"], dict(driver=0, tunnel=0, native=0))
        self.assertEqual(result["cleanup"], dict(children_joined=True, forced_kill=False, output_drained=True,
            socket_removed=True, host_netns_unchanged=True))
        self.assertTrue((self.root / "finalized").exists())
        self.assertFalse((self.run / "android-api/core-api.sock").exists())
        self.assertFalse((self.output / O["FAILURE_NAME"]).exists())
        self.assertFalse((self.output / D["NAME"]).exists())

    def test_kvm_access_loss_stops_before_driver_or_publication_with_versioned_failure(self):
        before = dict(KF["private_fixture"](), open_result="eperm")
        with patch.dict(K, snapshot=lambda: before): result = self.run_owner("normal")
        self.assertEqual(result["phase"], "driver")
        self.assertFalse(result["success"])
        self.assertEqual(result["statuses"], dict(driver=None, tunnel=None, native=None))
        self.assertFalse((self.root / "driver-ready").exists())
        receipt = K["validate_receipt"](json.loads((self.output / K["NAME"]).read_bytes()))
        self.assertEqual(receipt["schema"], 2)
        self.assertEqual(receipt["before_qemu"]["open_result"], "opened")
        self.assertEqual(receipt["owner_before_publication"]["open_result"], "eperm")
        self.assertEqual(receipt["native"], dict(state="absent", record=None))
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertNotIn("kvm", failure)
        self.assertEqual(failure["schema"], 8)
        self.assertEqual(failure["owner_stop"]["reason"], "guard-rejected")
        self.assertEqual(failure["owner_stop"]["stage"], "driver")
        self.assertTrue(all(child["state"] == "not-started" for child in failure["owner_stop"]["children"].values()))

    def test_group_grant_loss_is_explicit_and_stops_before_driver(self):
        acl = KF["acl_fixture"](); acl["named_group_write"] = False
        with patch.dict(K, group_acl=lambda: acl): result = self.run_owner("normal")
        self.assertFalse(result["success"])
        self.assertEqual(result["statuses"], dict(driver=None, tunnel=None, native=None))
        receipt = K["validate_receipt"](json.loads((self.output / K["NAME"]).read_bytes()))
        self.assertTrue(receipt["acl_before_qemu"]["named_group_write"])
        self.assertFalse(receipt["acl_before_publication"]["named_group_write"])
        self.assertFalse((self.root / "driver-ready").exists())

    def test_missing_pre_qemu_baseline_is_not_replaced_with_self_comparison(self):
        (self.run / "kvm-before-vm.json").unlink()
        result = self.run_owner("normal")
        self.assertFalse(result["success"])
        receipt = K["validate_receipt"](json.loads((self.output / K["NAME"]).read_bytes()))
        self.assertEqual(receipt["baseline_state"], "absent")
        self.assertIsNone(receipt["before_qemu"])
        self.assertTrue(all(receipt["owner_before_publication"][key] is None for key in K["COMPARISONS"]))
        self.assertFalse((self.root / "driver-ready").exists())

    def test_changed_identity_is_compared_against_pre_qemu_and_blocks_publication(self):
        changed = KF["private_fixture"](); changed["credentials"][3:] = [45678] * 3
        with patch.dict(K, snapshot=lambda: changed): result = self.run_owner("normal")
        self.assertFalse(result["success"])
        receipt = K["validate_receipt"](json.loads((self.output / K["NAME"]).read_bytes()))
        self.assertFalse(receipt["owner_before_publication"]["same_identity"])
        self.assertFalse((self.root / "driver-ready").exists())
        self.assertNotIn("45678", json.dumps(receipt))

    def test_native_failure_never_requests_finalize(self):
        result = self.run_owner("native-fail")
        self.assertFalse(result["success"]); self.assertEqual(result["phase"], "native")
        self.assertEqual(result["statuses"]["native"], 2)
        self.assertFalse((self.root / "finalized").exists())
        self.assertTrue(result["cleanup"]["children_joined"])
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertEqual(failure["native_diagnostic"], dict(state="absent", record=None))
        self.assertEqual(failure["statuses"]["native"], 2)
        self.assertEqual(failure["owner_cleanup"], result["cleanup"])
        stop = failure["owner_stop"]
        self.assertEqual((stop["reason"], stop["stage"], stop["budgets"]), ("native-exited", "native-result", []))
        self.assertEqual(stop["children"]["native"], dict(state="exited", status=2, stdout_open=False, stderr_open=False))
        self.assertEqual(stop["children"]["driver"]["state"], "running")

    def test_early_native_guard_code_is_visible_after_owned_cleanup_without_live_files(self):
        result = self.run_owner("native-diagnostic-early")
        self.assertFalse(result["success"])
        path = self.output / O["FAILURE_NAME"]; raw = path.read_bytes(); failure = json.loads(raw)
        self.assertEqual(set(failure), {"schema", "kind", "identity", "phase", "statuses", "owner_cleanup", "owner_stop",
            "native_diagnostic", "tunnel_diagnostic", "weather_records", "diagnostic_only", "success", "joined_core_acceptance",
            "vm_cleanup_pending", "expiry_proven", "physical_device", "production_authority"})
        self.assertEqual(failure["identity"], IDENTITY)
        self.assertEqual(failure["native_diagnostic"], dict(state="available", record=NATIVE_DIAGNOSTIC))
        self.assertEqual(failure["weather_records"], dict.fromkeys(O["NATIVE_RECORDS"], dict(state="absent", facts=None)))
        self.assertTrue(failure["owner_cleanup"]["children_joined"] and failure["owner_cleanup"]["socket_removed"])
        self.assertEqual(failure["statuses"], dict(driver=-signal.SIGTERM, tunnel=0, native=1))
        self.assertTrue(failure["diagnostic_only"] and failure["vm_cleanup_pending"])
        self.assertFalse(any(failure[key] for key in ("success", "joined_core_acceptance", "expiry_proven",
            "physical_device", "production_authority")))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertNotIn(b"PRIVATE", raw); self.assertNotIn(str(self.root).encode(), raw)
        self.assertFalse((self.root / "finalized").exists())
        with self.assertRaises(ValueError): O["join"](self.value)
        with self.assertRaises(FileExistsError): O["write"](path, {})
        self.assertEqual(path.read_bytes(), raw)
        inner = D["validate_receipt"](json.loads((self.output / D["NAME"]).read_bytes()))
        self.assertEqual(inner["records"], dict.fromkeys(D["INPUTS"], dict(state="absent", facts=None)))

    def test_inner_failure_receipt_is_written_after_children_join_and_preserves_original_run_schema_six(self):
        originals = dict(emulator=DF["emulator_fixture"](), guest_network=DF["network_fixture"](), driver=DF["driver_fixture"]())
        mutate(self.root / "inert-roles.json", lambda value: value.update(inner_records=originals,
            inner_paths={name: str(self.weather / relative) for name, relative in D["INPUTS"].items()}))
        original_export = O["export_inner_diagnostic"]
        def export(value, expected_identity, preexisting, cleanup):
            self.assertEqual(Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip(), "")
            self.assertTrue(cleanup["children_joined"] and cleanup["output_drained"])
            self.assertTrue((self.output / O["FAILURE_NAME"]).is_file())
            self.assertTrue((self.output / K["NAME"]).is_file())
            return original_export(value, expected_identity, preexisting, cleanup)
        with patch.dict(G, export_inner_diagnostic=export): result = self.run_owner("native-diagnostic-inner")
        self.assertFalse(result["success"])
        receipt = D["validate_receipt"](json.loads((self.output / D["NAME"]).read_bytes()))
        self.assertEqual(receipt["records"], {name: dict(state="available", facts=value)
            for name, value in originals.items()})
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertEqual(failure["schema"], 8)
        self.assertEqual(result["schema"], 6)
        self.assertNotIn("inner", failure)
        self.assertNotIn("PRIVATE", json.dumps(receipt))
        self.assertFalse((self.root / "finalized").exists())
        with self.assertRaises(ValueError): O["join"](self.value)

    def test_first_driver_failure_survives_exchange_exit_and_early_native_cleanup(self):
        original = DF["driver_fixture"]()
        mutate(self.root / "inert-roles.json", lambda value: value.update(inner_records=dict(driver=original),
            inner_paths={name: str(self.weather / relative) for name, relative in D["INPUTS"].items()}))
        result = self.run_owner("tunnel-exit-first-driver-failure")
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"] and result["cleanup"]["output_drained"])
        receipt = D["validate_receipt"](json.loads((self.output / D["NAME"]).read_bytes()))
        self.assertEqual(receipt["schema"], 2)
        self.assertEqual(receipt["records"]["driver"], dict(state="available", facts=original))
        self.assertEqual(receipt["records"]["emulator"], dict(state="absent", facts=None))
        self.assertEqual(receipt["records"]["guest_network"], dict(state="absent", facts=None))
        self.assertFalse(receipt["cause_established"] or receipt["joined_core_acceptance"])
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertEqual((failure["schema"], failure["owner_stop"]["reason"]), (8, "tunnel-exited"))
        self.assertEqual(failure["owner_stop"]["children"]["native"]["state"], "running")
        self.assertEqual(failure["statuses"]["native"], -signal.SIGTERM)
        self.assertFalse((self.weather / "build/overmorrow-hosted-android-live-proof/driver/report.json").exists())
        self.assertFalse((self.root / "finalized").exists())
        self.assertFalse((self.output / "weather-android-owner-join.json").exists())
        with self.assertRaises(ValueError): O["join"](self.value)

    def test_preexisting_inner_file_cannot_be_reported_as_this_native_attempt(self):
        save(self.weather / D["INPUTS"]["emulator"], DF["emulator_fixture"]())
        result = self.run_owner("native-fail")
        self.assertFalse(result["success"])
        receipt = json.loads((self.output / D["NAME"]).read_bytes())
        self.assertEqual(receipt["records"]["emulator"], dict(state="rejected", facts=None))
        self.assertEqual(receipt["records"]["guest_network"], dict(state="absent", facts=None))

    def test_optional_inner_export_error_preserves_original_failure_and_cleanup(self):
        with patch.dict(G, export_inner_diagnostic=lambda *_: (_ for _ in ()).throw(OSError("PRIVATE"))):
            result = self.run_owner("native-fail")
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"] and result["cleanup"]["socket_removed"])
        self.assertTrue((self.output / O["FAILURE_NAME"]).is_file())
        self.assertTrue((self.output / K["NAME"]).is_file())
        self.assertFalse((self.output / D["NAME"]).exists())

    def test_kvm_guard_diagnostic_has_separate_closed_receipt_and_no_acceptance(self):
        before = KF["private_fixture"]()
        lost = dict(before, real_read=False, real_write=False, open_result="eacces")
        observation = K["native_record"](IDENTITY, before, before, "available", lost)
        mutate(self.root / "inert-roles.json", lambda value: value.update(
            diagnostic=dict(NATIVE_DIAGNOSTIC, code="KVM_REQUIRED_NO_TCG"), kvm=observation))
        result = self.run_owner("native-diagnostic-kvm")
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"])
        path = self.output / K["NAME"]; raw = path.read_bytes()
        receipt = K["validate_receipt"](json.loads(raw))
        self.assertEqual(receipt["native"], dict(state="available", record=observation))
        self.assertEqual(receipt["native"]["record"]["at_kvm_guard_failure"]["open_result"], "eacces")
        self.assertTrue(all(receipt["native"]["record"]["at_kvm_guard_failure"][key] for key in K["COMPARISONS"]))
        self.assertFalse(any(receipt[key] for key in ("joined_core_acceptance", "physical_device", "production_authority")))
        for secret in (b"PRIVATE", b"12345", b"23456", b"34567", str(self.root).encode()):
            self.assertNotIn(secret, raw)
        self.assertFalse((self.root / "finalized").exists())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertNotIn("kvm", failure)
        self.assertEqual(failure["native_diagnostic"]["record"]["code"], "KVM_REQUIRED_NO_TCG")

    def test_rejected_kvm_marker_never_prevents_owned_cleanup_or_exports_raw_data(self):
        before = KF["private_fixture"]()
        observation = K["native_record"](IDENTITY, before, before, "available", before)
        observation["private"] = "PRIVATE_CANARY"
        mutate(self.root / "inert-roles.json", lambda value: value.update(
            diagnostic=dict(NATIVE_DIAGNOSTIC, code="KVM_REQUIRED_NO_TCG"), kvm=observation))
        result = self.run_owner("native-diagnostic-kvm-invalid")
        receipt = json.loads((self.output / K["NAME"]).read_bytes())
        self.assertEqual(receipt["native"], dict(state="rejected", record=None))
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"])
        self.assertNotIn("PRIVATE", json.dumps(receipt))

    def test_malformed_native_diagnostic_cannot_skip_cleanup_or_request_finalize(self):
        mutate(self.root / "inert-roles.json", lambda value: value["diagnostic"].update(private="PRIVATE"))
        result = self.run_owner("native-diagnostic-invalid")
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"] and result["cleanup"]["socket_removed"])
        self.assertEqual(failure["native_diagnostic"], dict(state="rejected", record=None))
        self.assertNotIn("PRIVATE", json.dumps(failure))
        self.assertFalse((self.root / "finalized").exists())

    def test_native_deadline_is_abort_and_still_joins_all_children(self):
        with patch.dict(G, NATIVE_SECONDS=0.2): result = self.run_owner("native-deadline")
        self.assertFalse(result["success"]); self.assertEqual(result["phase"], "native")
        self.assertTrue(result["cleanup"]["children_joined"])
        self.assertFalse((self.root / "finalized").exists())
        self.assertIsNone(result["statuses"]["native"])
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        stop = failure["owner_stop"]
        self.assertEqual((stop["reason"], stop["stage"], stop["budgets"]), ("deadline", "native-wait", ["native"]))
        self.assertEqual(stop["children"]["native"]["state"], "running")
        self.assertIsNone(stop["children"]["native"]["status"])
        self.assertEqual(failure["statuses"]["native"], -signal.SIGTERM)

    def test_driver_exit_cannot_be_mistaken_for_ready(self):
        result = self.run_owner("driver-exit")
        self.assertFalse(result["success"]); self.assertEqual(result["phase"], "read-ready")
        self.assertIsNone(result["statuses"]["native"])
        self.assertFalse((self.root / "finalized").exists())

    def test_driver_exit_during_native_is_frozen_before_cleanup_changes_other_statuses(self):
        result = self.run_owner("driver-exit-native")
        self.assertFalse(result["success"])
        self.assertEqual(result["phase"], "native")
        self.assertIsNone(result["statuses"]["native"])
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        stop = failure["owner_stop"]
        self.assertEqual((stop["reason"], stop["stage"], stop["budgets"]), ("driver-exited", "native-wait", []))
        self.assertEqual(stop["children"]["driver"]["status"], 7)
        self.assertEqual(stop["children"]["native"]["state"], "running")
        self.assertEqual(failure["statuses"]["native"], -signal.SIGTERM)
        self.assertTrue(result["cleanup"]["children_joined"])
        self.assertFalse((self.root / "finalized").exists())

    def test_early_clean_tunnel_exit_still_aborts_and_is_not_inferred_from_cleanup(self):
        result = self.run_owner("tunnel-exit-native")
        self.assertFalse(result["success"])
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        stop = failure["owner_stop"]
        self.assertEqual((stop["reason"], stop["stage"]), ("tunnel-exited", "native-wait"))
        self.assertEqual(stop["children"]["tunnel"]["status"], 0)
        self.assertEqual(stop["children"]["native"]["state"], "running")
        self.assertTrue(result["cleanup"]["children_joined"])
        self.assertIsNone(failure["tunnel_diagnostic"])
        self.assertFalse((self.root / "finalized").exists())

    def test_tunnel_failure_facts_follow_cleanup_without_overwriting_original_owner_stop(self):
        closed = []
        original_close, original_decode = O["Children"].close, O["tunnel_diagnostic"]
        def close(pool):
            result = original_close(pool); closed.append(result); return result
        def decode(job):
            self.assertEqual(len(closed), 1)
            self.assertTrue(closed[0]["children_joined"] and closed[0]["output_drained"])
            self.assertFalse(job["open"])
            return original_decode(job)
        with patch.object(O["Children"], "close", close), patch.dict(G, tunnel_diagnostic=decode):
            result = self.run_owner("tunnel-diagnostic-early")
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertEqual((result["schema"], failure["schema"]), (6, 8))
        self.assertEqual(failure["tunnel_diagnostic"], TUNNEL_DIAGNOSTIC)
        stop = failure["owner_stop"]
        self.assertEqual((stop["reason"], stop["stage"], stop["budgets"]), ("tunnel-exited", "native-wait", []))
        self.assertEqual(stop["children"]["tunnel"]["status"], 1)
        self.assertEqual(stop["children"]["native"]["state"], "running")
        self.assertIsNone(stop["children"]["native"]["status"])
        self.assertEqual(failure["statuses"]["native"], -signal.SIGTERM)
        self.assertEqual(failure["owner_cleanup"], result["cleanup"])
        self.assertFalse(any(failure[key] for key in ("success", "joined_core_acceptance", "expiry_proven",
            "physical_device", "production_authority")))
        self.assertNotIn("PRIVATE", json.dumps(failure)); self.assertNotIn(str(self.root), json.dumps(failure))
        self.assertFalse((self.root / "finalized").exists())
        with self.assertRaises(ValueError): O["join"](self.value)

    def test_nonfinal_tunnel_marker_keeps_stop_and_cleanup_but_no_diagnostic_facts(self):
        result = self.run_owner("tunnel-diagnostic-trailing")
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"] and result["cleanup"]["output_drained"])
        self.assertEqual(failure["owner_stop"]["reason"], "tunnel-exited")
        self.assertIsNone(failure["tunnel_diagnostic"])
        self.assertNotIn("PRIVATE", json.dumps(failure))
        self.assertFalse((self.root / "finalized").exists())

    def test_tunnel_validator_failure_preserves_original_stop_result_and_cleanup(self):
        with patch.dict(O["T"], validate_diagnostic=lambda *_: (_ for _ in ()).throw(ValueError("PRIVATE parse"))):
            result = self.run_owner("tunnel-diagnostic-early")
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"] and result["cleanup"]["socket_removed"])
        self.assertIsNone(failure["tunnel_diagnostic"])
        self.assertEqual(failure["owner_stop"]["reason"], "tunnel-exited")
        self.assertTrue((self.output / K["NAME"]).is_file() and (self.output / D["NAME"]).is_file())
        self.assertNotIn("PRIVATE", json.dumps(failure))

    def test_pipe_io_error_is_distinct_and_never_exports_private_error_text(self):
        original = O["Children"].pump
        def pump(pool, timeout=0.05, *, cleanup=False):
            if not cleanup and any(job["name"] == "native" for job in pool.jobs):
                raise OSError("PRIVATE https://secret.invalid/key")
            return original(pool, timeout, cleanup=cleanup)
        with patch.object(O["Children"], "pump", pump): result = self.run_owner("native-deadline")
        self.assertFalse(result["success"])
        raw = (self.output / O["FAILURE_NAME"]).read_bytes(); failure = json.loads(raw)
        self.assertEqual(failure["owner_stop"]["reason"], "io-error")
        self.assertEqual(failure["owner_stop"]["stage"], "native-wait")
        self.assertTrue(result["cleanup"]["children_joined"])
        self.assertNotIn(b"PRIVATE", raw); self.assertNotIn(b"secret.invalid", raw)

    def test_optional_stop_capture_failure_keeps_original_failure_and_cleanup(self):
        with patch.dict(G, owner_stop=lambda *_: (_ for _ in ()).throw(ValueError("PRIVATE capture error"))):
            result = self.run_owner("native-fail")
        self.assertFalse(result["success"])
        self.assertEqual(result["schema"], 6)
        self.assertEqual(result["statuses"]["native"], 2)
        self.assertTrue(result["cleanup"]["children_joined"] and result["cleanup"]["socket_removed"])
        raw = (self.output / O["FAILURE_NAME"]).read_bytes(); failure = json.loads(raw)
        self.assertIsNone(failure["owner_stop"])
        self.assertEqual(failure["statuses"]["native"], 2)
        self.assertTrue((self.output / K["NAME"]).is_file())
        self.assertTrue((self.output / D["NAME"]).is_file())
        self.assertNotIn(b"PRIVATE", raw)

    def test_finalization_failure_keeps_guest_cleanup_pending(self):
        result = self.run_owner("finalize-fail")
        self.assertFalse(result["success"]); self.assertEqual(result["phase"], "finalize")
        self.assertFalse((self.root / "finalized").exists())

    def test_tunnel_extra_stdout_is_rejected_before_finalize(self):
        result = self.run_owner("tunnel-extra-output")
        self.assertFalse(result["success"]); self.assertEqual(result["phase"], "tunnel-join")
        self.assertFalse((self.root / "finalized").exists())

    def test_tunnel_leftover_socket_is_not_silently_removed_or_promoted(self):
        result = self.run_owner("socket-left")
        self.assertFalse(result["success"] or result["cleanup"]["socket_removed"])
        self.assertTrue((self.run / "android-api/core-api.sock").exists())
        self.assertFalse((self.root / "finalized").exists())

    def test_cancel_after_tunnel_and_native_spawn_joins_without_finalize(self):
        def interrupt(*_): raise O["Failure"]("interrupted")
        prior = signal.signal(signal.SIGTERM, interrupt)
        try: result = self.run_owner("cancel-native")
        finally: signal.signal(signal.SIGTERM, prior)
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["children_joined"] and result["cleanup"]["socket_removed"])
        self.assertFalse((self.root / "finalized").exists())
        failure = json.loads((self.output / O["FAILURE_NAME"]).read_bytes())
        self.assertEqual(failure["phase"], "native")
        self.assertEqual(failure["statuses"]["native"], -signal.SIGTERM)
        self.assertEqual(failure["owner_stop"]["reason"], "interrupted")
        self.assertEqual(failure["owner_stop"]["stage"], "native-wait")
        self.assertEqual(failure["owner_stop"]["budgets"], [])
        self.assertIsNone(failure["owner_stop"]["children"]["native"]["status"])
        self.assertEqual(failure["native_diagnostic"], dict(state="absent", record=None))
        self.assertTrue(failure["owner_cleanup"]["children_joined"] and failure["diagnostic_only"])
        self.assertFalse(any(failure[key] for key in ("success", "joined_core_acceptance", "expiry_proven",
            "physical_device", "production_authority")))
        inner = D["validate_receipt"](json.loads((self.output / D["NAME"]).read_bytes()))
        self.assertFalse(inner["joined_core_acceptance"] or inner["cause_established"])


if __name__ == "__main__": unittest.main()
