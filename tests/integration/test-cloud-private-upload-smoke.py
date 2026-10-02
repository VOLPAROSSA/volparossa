#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure closed/parser contracts. These fixtures are NOT actual UI/peer evidence."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
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
        source_shutdown_owned_by_parent=True, owner_secrets_exported=False)


def fixture():
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
    size, chunk = 270445, CHECK["UPLOAD_CHUNK"]
    added = [dict(reserved_bytes=0, committed_bytes=n, leases=2) for n in (size - chunk, 2 * chunk, size - chunk)]
    combined = [dict(reserved_bytes=0, committed_bytes=n + other["committed_bytes"], leases=c + 2)
        for n, c, other in zip(geometry["PROVIDER_BYTES"], geometry["PROVIDER_LEASES"], added)]
    baseline = value["upload"]
    value["upload"] = dict(baseline=baseline, ui=ui("upload"), upload_ciphertext_bytes=size,
        upload_provider_usage=copy.deepcopy(added), service_stopped_and_joined=True,
        both_local_ciphertexts_removed=True, original_source_stopped=True,
        private_staging_removed=True, committed_fragment_copies=14)
    value["restore"] = dict(ui=ui("download"), upload_ciphertext_bytes=size, upload_provider_usage=copy.deepcopy(added),
        baseline_restores=2, upload_downloads=2, new_service_and_browser=True, all_reads_nonconsuming=True,
        both_local_ciphertexts_absent=True, original_source_stopped=True, service_stopped_and_joined=True,
        private_staging_removed=True, retained_identities_unchanged=True)
    value["finish"] = dict(baseline=value["finish"], all_fourteen_copies_deleted=True,
        delete_retry_idempotent=True, final_payload_charge=0)
    value["uploaded_usage"] = copy.deepcopy(combined)
    value["restored_usage"] = copy.deepcopy(combined)
    return value


def status(phase):
    keys, size, chunk = [n * 64 for n in "abc"], 270445, CHECK["UPLOAD_CHUNK"]
    totals, charges, fragments = dict(reserved=0, committed=0, uncertain=0), [0, 0, 0], []
    for index, length in enumerate((chunk, chunk, size - 2 * chunk)):
        copies, confirmed = [], 0
        for copy_index in range(2):
            provider = (index + copy_index) % 3
            charge = "deleted" if phase == "deleted" else "uncertain" if phase == "restore" and index == provider == 0 else "committed"
            copies.append(dict(provider_key=keys[provider], charge=charge,
                last_confirmed_stored_bytes=0 if charge == "deleted" else length,
                last_confirmed_state="Deleted" if charge == "deleted" else "Committed",
                last_confirmed_expiry=0 if charge == "deleted" else int(time.time()) + 3600))
            if charge != "deleted":
                totals[charge] += length; charges[provider] += length
                confirmed += int(charge == "committed")
        fragments.append(dict(index=index, offset=index * chunk, ciphertext_bytes=length,
            copies=copies, confirmed_unexpired_copies=confirmed))
    value = dict(operation="private_storage_fragments_status", logical_ciphertext_bytes=size, fragment_count=3,
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
            lambda v: v["finish"].update(all_fourteen_copies_deleted=False),
            lambda v: v["provision"]["ui"].update(patch_sha256="f" * 64),
            lambda v: v["provision"]["browser"].update(browser_execution_proven=True),
            lambda v: v["network"]["restore"]["gates"].update(exit_mptcp_tls_completed=24),
            lambda v: v["withdrawal"].update(first_provider_stopped_before_restore=False),
            lambda v: v["private_cleanup"].update(recovery_keys_removed=False),
        ):
            value = fixture(); alter(value)
            with self.assertRaises((ValueError, KeyError)): CHECK["validate_evidence"](value)

    def test_three_fragment_signed_status_keeps_all_uncertain_charges(self):
        for phase in ("committed", "restore", "deleted"):
            value, keys, size = status(phase)
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
        self.assertEqual(pins["revision"], "3e3d6587012ed46d200218e4447506300f8a4f18")
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


if __name__ == "__main__": unittest.main()
