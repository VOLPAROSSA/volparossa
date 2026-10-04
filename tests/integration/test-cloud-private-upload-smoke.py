#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure closed/parser contracts. These fixtures are NOT actual UI/peer evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "cloud-private-upload-smoke.py"))
OLD = runpy.run_path(str(HERE / "test-cloud-private-file-smoke.py"))


def ui(mode):
    return dict(version=1, kind="cloud-owner-upload-original-ui", mode=mode, success=True, stage="cleanup",
        original_files_ui=True, synthetic_backend=False, original_file_input_used=mode == "upload",
        upload_201_observed=mode == "upload", uploaded_file_listed=True, reload_reauthenticated=mode == "upload",
        file_downloads_verified=0 if mode == "upload" else 2, wrong_token_denied=True, logout_relocks=True,
        token_absent_from_url_and_web_storage=True, browser_stopped_and_joined=True, private_profile_removed=True,
        browser_version="140.16.0", bytes=262145,
        sha256="9012cf78cb493db125d4a0f4f761ae8cb021c5ed16b5085bf32cd4252be575f6",
        peer_storage_proven=False, service_restart_owned_by_parent=True,
        source_shutdown_owned_by_parent=True, owner_secrets_exported=False,
        upload_receipt=dict(puts=1, completed=1, created=1, last_status=201, statuses=[201]) if mode == "upload" else None)


def ui_failure():
    return dict(ui("upload"), success=False, stage="upload_commit", upload_201_observed=False,
        uploaded_file_listed=False, failure_kind="condition_timeout",
        upload_receipt=None, upload_observation=dict(puts=1, completed=0, created=0, last_status=0, statuses=[]))


def fixture(size=270445):
    value = OLD["fixture"]()
    value.update(dict.fromkeys(CHECK["FALSE_CLAIMS"], False))
    pins = CHECK["PINS"]
    value["provision"].update(pins=copy.deepcopy(pins), pins_sha256=hashlib.sha256(CHECK["PINS_PATH"].read_bytes()).hexdigest())
    value["provision"]["sdk"]["pins_sha256"] = CHECK["HASHES"]["third_party/opencloud-web-sdk.json"]
    value["provision"]["ui"].update(pins_sha256=CHECK["HASHES"]["third_party/opencloud-web-ui.json"],
        patch_sha256=CHECK["HASHES"]["patches/opencloud-web-owner-recovery.patch"])
    value["prepare"].update(cloud_revision=CHECK["REVISION"], source_sha256=CHECK["HASHES"],
        grant_payload_bytes=[1048576] * 3, grant_max_leases=[8] * 3)
    geometry = CHECK["CLOUD"]["configure"](value["prepare"])
    width = min(CHECK["UPLOAD_CHUNK"], size // 3)
    lengths = [min(width, size - offset) for offset in range(0, size, width)]
    charges, leases, survivors = [0] * 3, [0] * 3, [0] * 3
    for index, length in enumerate(lengths):
        for copy_index in range(2):
            provider = (index + copy_index) % 3
            charges[provider] += length; leases[provider] += 1
        survivors[index % 3 or 1] += length
    added = [dict(reserved_bytes=0, committed_bytes=n, leases=c) for n, c in zip(charges, leases)]
    combined = [dict(reserved_bytes=0, committed_bytes=n + other["committed_bytes"], leases=c + other["leases"])
        for n, c, other in zip(geometry["PROVIDER_BYTES"], geometry["PROVIDER_LEASES"], added)]
    baseline = value["upload"]
    value["upload"] = dict(baseline=baseline, ui=ui("upload"), upload_ciphertext_bytes=size,
        upload_provider_usage=copy.deepcopy(added), service_stopped_and_joined=True,
        both_local_ciphertexts_removed=True, original_source_stopped=True,
        private_staging_removed=True, committed_fragment_copies=8 + 2 * len(lengths))
    value["restore"] = dict(ui=ui("download"), upload_ciphertext_bytes=size, upload_provider_usage=copy.deepcopy(added),
        baseline_restores=2, upload_downloads=2, new_service_and_browser=True, all_reads_nonconsuming=True,
        both_local_ciphertexts_absent=True, original_source_stopped=True, service_stopped_and_joined=True,
        private_staging_removed=True, retained_identities_unchanged=True)
    value["finish"] = dict(baseline=value["finish"], all_fragment_copies_deleted=True,
        deleted_fragment_copies=8 + 2 * len(lengths), delete_retry_idempotent=True, final_payload_charge=0)
    value["uploaded_usage"] = copy.deepcopy(combined)
    value["restored_usage"] = copy.deepcopy(combined)
    restore = value["network"]["restore"]
    restore["gates"]["exit_mptcp_tls_completed"] = 4 * (4 + len(lengths))
    restore["privacy"]["exit"]["provider_application"]["relay5"]["response_payload_bytes"] = (
        2 * (2 * CHECK["CHUNK"] + geometry["LENGTHS"][-1] + survivors[1]))
    restore["privacy"]["exit"]["provider_application"]["relay3"]["response_payload_bytes"] = (
        2 * (CHECK["CHUNK"] + survivors[2]))
    return value


def status(phase, size=270445):
    keys, chunk = [n * 64 for n in "abc"], min(CHECK["UPLOAD_CHUNK"], size // 3)
    totals, charges, fragments = dict(reserved=0, committed=0, uncertain=0), [0, 0, 0], []
    for index, offset in enumerate(range(0, size, chunk)):
        length = min(chunk, size - offset)
        copies, confirmed = [], 0
        for copy_index in range(2):
            provider = (index + copy_index) % 3
            charge = "deleted" if phase == "deleted" else "uncertain" if phase == "restore" and provider == copy_index == 0 else "committed"
            copies.append(dict(provider_key=keys[provider], charge=charge,
                last_confirmed_stored_bytes=0 if charge == "deleted" else length,
                last_confirmed_state="Deleted" if charge == "deleted" else "Committed",
                last_confirmed_expiry=0 if charge == "deleted" else int(time.time()) + 3600))
            if charge != "deleted":
                totals[charge] += length; charges[provider] += length
                confirmed += int(charge == "committed")
        fragments.append(dict(index=index, offset=index * chunk, ciphertext_bytes=length,
            copies=copies, confirmed_unexpired_copies=confirmed))
    value = dict(operation="private_storage_fragments_status", logical_ciphertext_bytes=size, fragment_count=len(fragments),
        copies_per_fragment=2, distinct_provider_identities=3, owner_signature_verified=True,
        read_consumes_archive=False, expired_copies_remain_charged=True, fragments=fragments,
        physical_payload_charge_upper_bound=sum(charges),
        fragments_with_confirmed_unexpired_copy=sum(row["confirmed_unexpired_copies"] > 0 for row in fragments),
        fully_redundant_from_retained_receipts=phase == "committed",
        providers=[dict(provider_key=k, physical_payload_charge_upper_bound=n) for k, n in zip(keys, charges)],
        **{k + "_payload_bytes": n for k, n in totals.items()},
        **dict.fromkeys(("metadata_overhead_measured", "current_remote_availability_proven",
            "independent_failure_domains_proven", "network_contribution_credit", "automatic_repair",
            "automatic_handoff", "erasure_coding"), False))
    return value, keys, size


class UploadContracts(unittest.TestCase):
    def test_geometry_uses_core_upper_bound_with_division_remainder_not_three_fixed_chunks(self):
        # Independent literal expectations for the three-provider production
        # split, not a generated report pretending to be a live core result.
        expected = {262145: (87381, 87381, 87381, 2),
            270444: (90148, 90148, 90148), 270445: (90148, 90148, 90148, 1),
            270446: (90148, 90148, 90148, 2),
            393215: (131071, 131071, 131071, 2), 393216: (131072, 131072, 131072)}
        for size, lengths in expected.items():
            geometry = CHECK["upload_geometry"](size)
            self.assertEqual(geometry["lengths"], lengths)
            self.assertEqual(geometry["width"], lengths[0])
            self.assertEqual(sum(lengths), size)
            self.assertEqual(sum(row["committed_bytes"] for row in geometry["provider_usage"]), 2 * size)
            self.assertEqual(sum(row["leases"] for row in geometry["provider_usage"]), 2 * len(lengths))
            self.assertEqual(sum(geometry["survivor_bytes"]), size)
            self.assertEqual(geometry["survivor_bytes"][0], 0)
        four = CHECK["upload_geometry"](270445)
        self.assertEqual(four["provider_usage"], [dict(reserved_bytes=0, committed_bytes=n, leases=c)
            for n, c in ((180297, 3), (180297, 3), (180296, 2))])
        self.assertEqual(four["survivor_bytes"], [0, 180297, 90148])
        for size in (None, True, 270444.0, "270444", 0, 262144, 393217):
            with self.assertRaises(ValueError): CHECK["upload_geometry"](size)
        core = (HERE.parents[1] / "crates/volparossa/src/storage/fragments_state.rs").read_text()
        self.assertIn(".min(plan.ciphertext_bytes / grants.len() as u64)", core)
        self.assertIn("plan.ciphertext_bytes.div_ceil(fragment_bytes)", core)

    def test_three_and_four_fragment_evidence_requires_every_copy_flow_and_survivor_byte(self):
        for size in (270444, 270445, 270446, 393216):
            value = fixture(size)
            CHECK["validate_evidence"](value)
            for alter in (
                lambda v: v["upload"].update(committed_fragment_copies=v["upload"]["committed_fragment_copies"] - 2),
                lambda v: v["finish"].update(deleted_fragment_copies=v["finish"]["deleted_fragment_copies"] - 2),
                lambda v: v["network"]["restore"]["gates"].update(
                    exit_mptcp_tls_completed=v["network"]["restore"]["gates"]["exit_mptcp_tls_completed"] - 1),
                lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=0),
                lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay3"].update(response_payload_bytes=0),
                lambda v: v["restored_usage"][0].update(leases=0),
            ):
                changed = copy.deepcopy(value); alter(changed)
                with self.assertRaises(ValueError): CHECK["validate_evidence"](changed)

    def test_fourth_fragment_cannot_disappear_or_lose_uncertain_charge_after_provider_a_stops(self):
        value, keys, size = status("restore", 270445)
        self.assertEqual(value["fragment_count"], 4)
        self.assertEqual(value["fragments"][3]["copies"][0]["charge"], "uncertain")
        self.assertEqual(value["fragments"][2]["copies"][1]["charge"], "committed")
        self.assertEqual(value["uncertain_payload_bytes"], 90149)
        for alter in (
            lambda v: v["fragments"].pop(),
            lambda v: v.update(fragment_count=3),
            lambda v: v["fragments"][3].update(ciphertext_bytes=2),
            lambda v: v["fragments"][3].update(offset=3 * CHECK["UPLOAD_CHUNK"]),
            lambda v: v["fragments"][3]["copies"][0].update(charge="committed"),
            lambda v: v["fragments"][3]["copies"][0].update(charge="deleted"),
            lambda v: v["fragments"][3]["copies"][1].update(provider_key=keys[2]),
        ):
            changed = copy.deepcopy(value); alter(changed)
            with self.assertRaises(ValueError): CHECK["validate_upload_status"](changed, keys, size, "status", "restore")

    def test_identity_covers_every_copy_including_fourth_fragment(self):
        with tempfile.TemporaryDirectory(prefix="cloud-upload-identity-") as temporary:
            root = Path(temporary); journal = root / "journal"; journal.mkdir(mode=0o700)
            manifest = journal / "fragments.json"; manifest.write_bytes(b'{"inert_test_manifest":true}')
            manifest.chmod(0o600)
            for index in range(4):
                for copy_index in range(2):
                    path = journal / f"fragment-{index:04}/copy-{copy_index}/archive.json"
                    path.parent.mkdir(parents=True, mode=0o700)
                    value = dict(provider_key="synthetic", owner_key="synthetic", grant_hex="synthetic",
                        archive_id=f"synthetic-{index}-{copy_index}", ciphertext_bytes=1 if index == 3 else 90148,
                        sha256="synthetic", lease="synthetic-lease")
                    path.write_text(json.dumps(value)); path.chmod(0o600)
            before = CHECK["upload_identity"](root, 270445)
            last = journal / "fragment-0003/copy-1/archive.json"
            value = json.loads(last.read_text()); value["lease"] = "changed-lease"
            last.write_text(json.dumps(value))
            self.assertNotEqual(CHECK["upload_identity"](root, 270445), before)
            last.unlink()
            with self.assertRaises(FileNotFoundError): CHECK["upload_identity"](root, 270445)

    def test_upload_failure_categories_never_export_private_cli_or_exception_text(self):
        select = CHECK["closed_upload_failure"]
        for message, expected in CHECK["UPLOAD_FAILURE_CODES"].items():
            self.assertEqual(select(ValueError(message)), expected)
        self.assertEqual(select(subprocess.TimeoutExpired(["PRIVATE_PATH"], 900,
            output=b"PRIVATE_STDOUT", stderr=b"PRIVATE_STDERR")), "cli_timeout")
        for error in (ValueError("PRIVATE_URL_TOKEN_PAYLOAD"), KeyError("PRIVATE_RECEIPT"),
            OSError("PRIVATE_PATH"), json.JSONDecodeError("PRIVATE_ERROR", "PRIVATE_JSON", 0)):
            self.assertEqual(select(error), "unclassified")

    def test_complete_parser_fixture_and_source_bound_report(self):
        value = fixture()
        CHECK["validate_evidence"](value)
        report = dict(schema_version=1, report_kind="volparossa-cloud-private-upload", source_revision="b" * 40,
            success=True, runner_exit_status=0, phase="cloud-private-upload-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), cloud=value)
        CHECK["validate_report"](report, "b" * 40)
        report["phase"] = "cloud-private-file-complete"
        with self.assertRaises(ValueError): CHECK["validate_report"](report, "b" * 40)

    def test_missing_ui_source_shutdown_restoration_charge_or_provenance_rejects(self):
        for alter in (
            lambda v: v["upload"]["ui"].update(original_file_input_used=False),
            lambda v: v["upload"]["ui"].update(upload_201_observed=False),
            lambda v: v["restore"]["ui"].update(file_downloads_verified=1),
            lambda v: v["restore"].update(new_service_and_browser=False),
            lambda v: v["restore"].update(both_local_ciphertexts_absent=False),
            lambda v: v["restored_usage"][0].update(committed_bytes=0),
            lambda v: v["finish"].update(all_fragment_copies_deleted=False),
            lambda v: v["finish"].update(deleted_fragment_copies=14),
            lambda v: v["provision"]["ui"].update(patch_sha256="f" * 64),
            lambda v: v["provision"]["browser"].update(browser_execution_proven=True),
            lambda v: v["network"]["restore"]["gates"].update(exit_mptcp_tls_completed=24),
            lambda v: v["withdrawal"].update(first_provider_stopped_before_restore=False),
            lambda v: v["private_cleanup"].update(recovery_keys_removed=False),
        ):
            value = fixture(); alter(value)
            with self.assertRaises((ValueError, KeyError)): CHECK["validate_evidence"](value)

    def test_canonical_three_or_four_fragment_status_keeps_all_uncertain_charges(self):
        for size in (270444, 270445, 270446, 393216):
            for phase in ("committed", "restore", "deleted"):
                value, keys, size = status(phase, size)
                usage = CHECK["validate_upload_status"](value, keys, size, "status", phase)
                self.assertEqual(sum(row["committed_bytes"] for row in usage), 0 if phase == "deleted" else 2 * size)
                value["providers"][0]["physical_payload_charge_upper_bound"] += 1
                with self.assertRaises(ValueError): CHECK["validate_upload_status"](value, keys, size, "status", phase)
        value, keys, size = status("restore")
        value["fragments"][0]["copies"][0]["charge"] = "deleted"
        with self.assertRaises(ValueError): CHECK["validate_upload_status"](value, keys, size, "status", "restore")

    def test_pinned_inventory_has_actual_upload_dependencies_and_no_runtime_claim(self):
        module = runpy.run_path(str(HERE / "cloud-private-upload-provision.py"))
        state = module["configured"]()
        pins = state["load_pins"]()
        self.assertEqual(pins["revision"], "ffdcfaa15cdd2a029dae545904b0a58603da4e17")
        self.assertEqual(len(pins["files"]), 27)
        self.assertTrue({"src/owner-uploads.mjs", "scripts/upload_lock.py", "scripts/smoke_owner_upload_ui.py"} <= pins["files"].keys())
        self.assertEqual(pins["runtime"]["version"], "24.19.0")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pins.json"
            for revision in (None, "0" * 40, "working-tree"):
                invalid = dict(pins, revision=revision); path.write_text(json.dumps(invalid))
                with mock.patch.dict(module["configured"].__globals__, PIN_PATH=path):
                    with self.assertRaises(ValueError): module["configured"]()

    def test_exact_ui_fields_and_hash_are_closed(self):
        for mode in ("upload", "download"):
            CHECK["ui_record"](ui(mode), mode)
            for field, changed in (("bytes", 1), ("sha256", "f" * 64), ("success", False),
                ("peer_storage_proven", True), ("unknown", "private text")):
                value = ui(mode); value[field] = changed
                with self.assertRaises(ValueError): CHECK["ui_record"](value, mode)

    def test_failure_selection_keeps_only_closed_codes_counters_and_booleans(self):
        parse = CHECK["closed_ui_failure"]
        fields = {"failure_kind", "upload_observation", *CHECK["UI_FAILURE_FLAGS"]}
        for kind in CHECK["UI_FAILURE_KINDS"]:
            for observation in (None, dict(puts=1, completed=0, created=0, last_status=0, statuses=[]),
                dict(puts=4, completed=4, created=1, last_status=201, statuses=[0, 401, 503, 201])):
                value = dict(ui_failure(), failure_kind=kind, upload_observation=observation,
                    raw_error="PRIVATE_URL_TOKEN_PAYLOAD")
                result = parse(value, "upload")
                self.assertEqual(set(result), fields)
                self.assertEqual(result["failure_kind"], kind)
                self.assertEqual(result["upload_observation"], observation)
                self.assertNotIn("PRIVATE", json.dumps(result))
                if observation is not None:
                    self.assertIsNot(result["upload_observation"], observation)
                    self.assertIsNot(result["upload_observation"]["statuses"], observation["statuses"])
        value = ui_failure()
        for key in CHECK["UI_FAILURE_FLAGS"]:
            value[key] = False
        self.assertEqual({key: parse(value, "upload")[key] for key in CHECK["UI_FAILURE_FLAGS"]},
            dict.fromkeys(CHECK["UI_FAILURE_FLAGS"], False))
        self.assertIsNone(parse(ui("upload"), "upload"))
        with self.assertRaises(ValueError): CHECK["ui_record"](ui_failure(), "upload")

    def test_invalid_failure_metadata_is_unknown_not_a_raw_error_or_success(self):
        parse = CHECK["closed_ui_failure"]
        for value in (None, [], "PRIVATE_RAW_ERROR", 1):
            self.assertIsNone(parse(value, "upload"))
        mutations = [
            lambda v: v.update(version=True), lambda v: v.update(kind="PRIVATE_RAW_ERROR"),
            lambda v: v.update(mode="download"), lambda v: v.update(success=True),
            lambda v: v.update(stage=[]), lambda v: v.update(stage="PRIVATE_STAGE"),
            lambda v: v.update(failure_kind="PRIVATE_ERROR"), lambda v: v.pop("failure_kind"),
            lambda v: v.update(upload_observation=[]), lambda v: v.pop("upload_observation"),
            lambda v: v["upload_observation"].update(raw="PRIVATE_URL"),
            lambda v: v["upload_observation"].update(puts=-1),
            lambda v: v["upload_observation"].update(puts=65536),
            lambda v: v["upload_observation"].update(puts=5),
            lambda v: v["upload_observation"].update(completed=2),
            lambda v: v["upload_observation"].update(created=1),
            lambda v: v["upload_observation"].update(statuses=[201]),
            lambda v: v["upload_observation"].update(statuses="PRIVATE"),
        ]
        for key in CHECK["UI_FAILURE_FLAGS"]:
            mutations.append(lambda v, key=key: v.update({key: 1}))
        for key in ("puts", "completed", "created", "last_status"):
            for invalid in (True, "1", 1.0):
                mutations.append(lambda v, key=key, invalid=invalid: v["upload_observation"].update({key: invalid}))
        for invalid in (-1, 1, 99, 600):
            mutations.append(lambda v, invalid=invalid: v["upload_observation"].update(last_status=invalid))
        for mutate in mutations:
            value = ui_failure(); mutate(value)
            self.assertIsNone(parse(value, "upload"))

    def test_native_retry_receipt_does_not_replace_object_charge_or_original_success_gates(self):
        def receipt(statuses):
            return dict(puts=len(statuses), completed=len(statuses), created=statuses.count(201),
                last_status=statuses[-1] if statuses else 0, statuses=statuses)
        for statuses in ([201], [503, 201], [0, 401, 503, 201]):
            value = fixture()
            value["upload"]["ui"]["upload_receipt"] = receipt(statuses)
            CHECK["validate_evidence"](value)
            value["uploaded_usage"][0]["leases"] += 1
            with self.assertRaises(ValueError): CHECK["validate_evidence"](value)
        for statuses in ([], [503], [0], [200, 201], [204, 201], [299, 201], [201, 503],
            [201, 201], [0, 503, 503, 503, 201], [True, 201], ["503", 201], [99, 201], [600, 201]):
            value = ui("upload"); value["upload_receipt"] = receipt(statuses)
            with self.subTest(statuses=statuses), self.assertRaises(ValueError): CHECK["ui_record"](value, "upload")
        for change in (dict(puts=2), dict(completed=2), dict(created=0), dict(last_status=503),
            dict(puts=True), dict(statuses=[201, 503]), dict(raw="PRIVATE")):
            value = ui("upload"); value["upload_receipt"].update(change)
            with self.assertRaises(ValueError): CHECK["ui_record"](value, "upload")
        value = ui("download"); value["upload_receipt"] = receipt([201])
        with self.assertRaises(ValueError): CHECK["ui_record"](value, "download")

    def test_parent_keeps_failed_ui_receipt_without_masking_original_failure(self):
        serve = CHECK["serve_ui"]
        closed = json.dumps(dict(version=1, kind="volparossa-cloud-private-read", state="closed")).encode()
        ready = dict(version=1, kind="volparossa-cloud-private-read", state="listening", readOnly=False,
            loopbackOnly=True, originalServerFallback=False, openCloudAccountService=False,
            origin="http://127.0.0.1:1234")
        for report in (ui_failure(), dict(ui_failure(), failure_kind="PRIVATE_RAW_ERROR")):
            service = mock.Mock(returncode=0)
            service.stdout = io.BytesIO(json.dumps(ready).encode())
            service.poll.return_value = 0
            service.communicate.return_value = (closed, b"")
            process = mock.Mock(returncode=1)
            process.poll.return_value = 1
            process.communicate.return_value = (json.dumps(report).encode(), b"PRIVATE_STDERR")
            with mock.patch.dict(serve.__globals__, tools=lambda: (Path("/synthetic-source"), Path("/synthetic-node")),
                read=lambda _path: dict(bearerToken="PRIVATE_TOKEN"), UI_FAILURE={"stale": True}), \
                mock.patch.object(serve.__globals__["subprocess"], "Popen", side_effect=[service, process]), \
                mock.patch.object(serve.__globals__["select"], "select", return_value=([service.stdout], [], [])):
                with self.assertRaisesRegex(ValueError, "original UI failed"):
                    serve(Path("/synthetic-owner"), "upload")
                self.assertEqual(serve.__globals__["UI_STAGE"], "upload_commit")
                self.assertEqual(serve.__globals__["UI_PARENT_STAGE"], "ui_execution")
                self.assertEqual(serve.__globals__["UI_FAILURE"], CHECK["closed_ui_failure"](report, "upload"))
                self.assertNotIn("PRIVATE", json.dumps(serve.__globals__["UI_FAILURE"]))

    def test_parent_phase_distinguishes_ui_contract_service_close_and_staging(self):
        serve = CHECK["serve_ui"]
        closed = json.dumps(dict(version=1, kind="volparossa-cloud-private-read", state="closed")).encode()
        ready = dict(version=1, kind="volparossa-cloud-private-read", state="listening", readOnly=False,
            loopbackOnly=True, originalServerFallback=False, openCloudAccountService=False,
            origin="http://127.0.0.1:1234")
        for phase in ("complete", "ui_contract", "service_shutdown", "staging_cleanup"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); (root / "w").mkdir()
                if phase == "staging_cleanup": (root / "w" / "private-staging").touch()
                report = ui("upload")
                if phase == "ui_contract": report["private_raw"] = "PRIVATE_RAW"
                service = mock.Mock(returncode=1 if phase == "service_shutdown" else 0)
                service.stdout = io.BytesIO(json.dumps(ready).encode())
                service.poll.return_value = service.returncode
                service.communicate.return_value = (closed, b"PRIVATE_STDERR" if phase == "service_shutdown" else b"")
                process = mock.Mock(returncode=0)
                process.poll.return_value = 0
                process.communicate.return_value = (json.dumps(report).encode(), b"")
                with mock.patch.dict(serve.__globals__, tools=lambda: (Path("/synthetic-source"), Path("/synthetic-node")),
                    read=lambda _path: dict(bearerToken="PRIVATE_TOKEN")), \
                    mock.patch.object(serve.__globals__["subprocess"], "Popen", side_effect=[service, process]), \
                    mock.patch.object(serve.__globals__["select"], "select", return_value=([service.stdout], [], [])):
                    if phase == "complete": self.assertEqual(serve(root, "upload"), report)
                    else:
                        with self.assertRaises(ValueError): serve(root, "upload")
                    self.assertEqual(CHECK["closed_ui_parent_stage"](), phase)
                    self.assertIsNone(serve.__globals__["UI_FAILURE"])

    def test_parent_phase_is_closed_and_never_exports_raw_failure_details(self):
        select = CHECK["closed_ui_parent_stage"]
        phases = {"not_started", "service_start", "service_readiness", "ui_execution", "ui_contract",
            "service_shutdown", "staging_cleanup", "complete", "unreported"}
        self.assertEqual(CHECK["UI_PARENT_STAGES"], phases)
        for value in [*phases, None, [], {}, True, "PRIVATE_TOKEN_PATH_ERROR"]:
            with mock.patch.dict(select.__globals__, UI_PARENT_STAGE=value):
                self.assertEqual(select(), value if type(value) is str and value in phases else "unreported")


if __name__ == "__main__": unittest.main()
