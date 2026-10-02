#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed evidence/parser tests only; no application execution or peer proof."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import unittest
from unittest import mock

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "cloud-private-file-smoke.py"))
OLD = runpy.run_path(str(HERE / "test-private-storage-fragments-smoke.py"))


def fixture():
    value = OLD["fixture"]()
    size = 3 * CHECK["CHUNK"] + 12345
    prepare = dict(cloud_revision=CHECK["REVISION"], source_sha256=CHECK["SOURCE_HASHES"],
        plaintext_sha256=CHECK["CONTENT_SHA"], plaintext_bytes=len(CHECK["CONTENT"]),
        ciphertext_bytes=size, cipher_sha256="a" * 64, archive_encryption_proven=True,
        authenticated_dav_ranges=4, source_stopped_and_joined=True, source_credentials_removed=True,
        private_import_staging_removed=True, owner_distinct_from_all_providers=True, owner_secrets_exported=False)
    geometry = CHECK["configure"](prepare)
    prepare.update(grant_payload_bytes=list(geometry["PROVIDER_BYTES"]), grant_max_leases=list(geometry["PROVIDER_LEASES"]))
    value.update(prepare=prepare, archive_encryption_proven=True, web_sdk_read_proven=True, original_files_ui_read_proven=True,
        **dict.fromkeys(CHECK["FALSE_CLAIMS"], False))
    value["upload"] = CHECK["upload_report"](size)
    value["restore"] = CHECK["restore_report"](size, CHECK["sdk_report"]("e" * 64))
    value["finish"] = dict(actual_core_cli=True, reopened_copies_confirmed=True, all_eight_copies_deleted=True,
        delete_retry_idempotent=True, final_payload_charge=0)
    retained = [dict(reserved_bytes=0, committed_bytes=n, leases=c)
        for n, c in zip(geometry["PROVIDER_BYTES"], geometry["PROVIDER_LEASES"])]
    value["uploaded_usage"] = copy.deepcopy(retained)
    value["restored_usage"] = copy.deepcopy(retained)
    value["private_cleanup"] = dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        recovery_keys_removed=True, private_plaintext_removed=True, ciphertext_removed=True,
        fragment_journal_removed=True, user_directory_removed=True)
    pins = HERE / "cloud-private-file-pins.json"
    value["provision"] = dict(version=1, kind="cloud-private-file-runtime-provision", success=True,
        pins=json.loads(pins.read_text()), pins_sha256=hashlib.sha256(pins.read_bytes()).hexdigest(),
        tools={name: dict(package=name, package_version="fixture", bytes=1, sha256="a" * 64)
            for name in ("gpg", "gpg-agent", "gpgconf", "tar")}, guest_only=True,
        source_files_verified=True, runtime_files_verified=True, original_licenses_retained=True,
        private_file_created=False, peer_storage_proven=False, opencloud_server_started=False,
        sdk=dict(pins_sha256=CHECK["SOURCE_HASHES"]["third_party/opencloud-web-sdk.json"],
            archive_sha256=CHECK["SDK_SHA"], receipt_sha256="e" * 64, files_verified=True, files=109,
            source_build_claimed=False, sdk_reads_proven=False),
        ui=dict(source_revision="11e699ac82fda4dd113ac3ceb2ecb2dd74574045",
            source_tree="4f13ceee9b21450659266df69a4fac57f25c3bc9",
            pins_sha256=CHECK["SOURCE_HASHES"]["third_party/opencloud-web-ui.json"],
            patch_sha256=CHECK["SOURCE_HASHES"]["patches/opencloud-web-owner-recovery.patch"],
            build_report_sha256="d" * 64, source_built=True, files_verified=True, ui_execution_proven=False),
        browser=dict(version="140.16.0", source_stamp="d864999404b3032f682d74ccc60d1ce38c9ce609",
            archive_sha256="e32aeabcab2e74fe112332fad10f7d9630e14cd6f4564a596a71073018d24508",
            files_verified=True, browser_execution_proven=False))
    value["network"]["restore"]["gates"]["exit_mptcp_tls_completed"] = 48
    for phase in value["network"].values():
        for node in ("relay5", "relay3"):
            phase["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"] = 6 * size
    return value


class CloudEvidence(unittest.TestCase):
    def test_closed_fixture_validates_but_does_not_execute_or_prove_the_scenario(self):
        value = fixture()
        CHECK["validate_evidence"](value)
        report = dict(schema_version=3, report_kind="volparossa-cloud-private-file", source_revision="b" * 40,
            success=True, runner_exit_status=0, phase="cloud-private-file-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), cloud=value)
        CHECK["validate_report"](report, "b" * 40)
        for field, altered in (("source_revision", "c" * 40), ("runner_exit_status", 1),
                               ("phase", "private-storage-fragments-complete")):
            candidate = copy.deepcopy(report)
            candidate[field] = altered
            with self.assertRaises(ValueError):
                CHECK["validate_report"](candidate, "b" * 40)

    def test_missing_real_operations_scope_inflation_or_shortcuts_rejected(self):
        for mutate in (
            lambda v: v.update(archive_encryption_proven=False),
            lambda v: v.update(serverless_opencloud_proven=True),
            lambda v: v.update(web_client_proven=True),
            lambda v: v.update(web_sdk_read_proven=False),
            lambda v: v.update(original_files_ui_read_proven=False),
            lambda v: v.update(public_cache_used=True),
            lambda v: v["prepare"].update(cloud_revision="a" * 40),
            lambda v: v["prepare"].update(authenticated_dav_ranges=0),
            lambda v: v["prepare"].update(source_stopped_and_joined=False),
            lambda v: v["prepare"].update(source_credentials_removed=False),
            lambda v: v["prepare"].update(private_import_staging_removed=False),
            lambda v: v["prepare"].update(ciphertext_bytes=1000),
            lambda v: v["upload"].update(source_ciphertext_removed=False),
            lambda v: v["upload"].update(actual_cloud_cli=False),
            lambda v: v["restore"].update(actual_gpg_decryptions=0),
            lambda v: v["restore"].update(private_source_metadata_verified=False),
            lambda v: v["restore"].update(reads_nonconsuming=False),
            lambda v: v["restore"]["sdk"].update(actual_cloud_cli_service=False),
            lambda v: v["restore"]["sdk"].update(actual_published_sdk=False),
            lambda v: v["restore"]["sdk"].update(catalog_verified_full_restore=False),
            lambda v: v["restore"]["sdk"].update(read_service_stopped_and_joined=False),
            lambda v: v["restore"]["sdk"].update(temporary_plaintext_removed=False),
            lambda v: v["restore"]["sdk"].update(original_source_fallback=True),
            lambda v: v["restore"]["sdk"].update(local_ciphertext_fallback=True),
            lambda v: v["restore"]["sdk"].update(sdk_receipt_sha256="b" * 64),
            lambda v: v["restore"]["sdk"].update(range_get_sha256="b" * 64),
            lambda v: v["restore"]["sdk"]["ui"].update(synthetic_backend=True),
            lambda v: v["restore"]["sdk"]["ui"].update(file_downloads_verified=1),
            lambda v: v["restore"]["sdk"]["ui"].update(private_profile_removed=False),
            lambda v: v["withdrawal"].update(first_provider_stopped_before_restore=False),
            lambda v: v["private_cleanup"].update(recovery_keys_removed=False),
            lambda v: v["deleted_usage"][0].update(committed_bytes=1),
            lambda v: v["restored_usage"][0].update(committed_bytes=0),
            lambda v: v["provision"].update(pins_sha256="f" * 64),
            lambda v: v["provision"]["pins"].update(revision="f" * 40),
            lambda v: v["provision"]["tools"].pop("gpg"),
            lambda v: v["provision"]["sdk"].update(archive_sha256="f" * 64),
            lambda v: v["provision"]["sdk"].update(source_build_claimed=True),
            lambda v: v["provision"]["ui"].update(source_built=False),
            lambda v: v["provision"]["browser"].update(files_verified=False),
            lambda v: v["network"]["restore"]["gates"].update(exit_mptcp_tls_completed=32),
            lambda v: v["network"]["restore"]["gates"].update(exit_mptcp_tls_completed=16),
            lambda v: v["network"]["restore"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay4"].update(response_payload_bytes=1),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=1),
        ):
            value = fixture()
            mutate(value)
            with self.assertRaises((ValueError, KeyError)):
                CHECK["validate_evidence"](value)

    def test_cloud_invocation_uses_actual_pinned_app_and_no_injected_storage_factory(self):
        globals_ = CHECK["cloud"].__globals__
        with mock.patch.dict(globals_, tools=lambda: (Path("/opt/volparossa-cloud"), Path("/opt/volparossa-node/bin/node"))):
            with mock.patch.dict(globals_, process_json=lambda command, **kwargs: (command, kwargs)):
                command, _ = CHECK["cloud"](Path("/owner/i"), "restore", "--output", "/owner/i/restored")
                self.assertEqual(command, [Path("/opt/volparossa-node/bin/node"),
                    Path("/opt/volparossa-cloud/scripts/cloud-file.mjs"), "restore", "--bundle", Path("/owner/i/bundle"),
                    "--config", Path("/owner/i/storage.json"), "--output", "/owner/i/restored"])
                command, _ = CHECK["cloud"](Path("/owner/i"), "import")
                self.assertEqual(command[-2:], ["--source-config", Path("/owner/i/source.private.json")])
                self.assertNotIn("--config", command)

    def test_sdk_driver_uses_actual_catalog_and_service_clis_and_published_sdk(self):
        text = (HERE / "cloud-private-file-sdk.mjs").read_text()
        for required in ("runCLI('cloud-catalog.mjs'", "launch('cloud-serve.mjs'",
                "package/dist/web-client/webdav.js", "client.listFiles(space)", "client.getFileContents(space",
                "Range: 'bytes=3-14'", "error.statusCode === 401", "error.statusCode === 412",
                "lines[1].state === 'closed'", "readdir(`${root}/w`)", "maxConcurrent: 2"):
            self.assertIn(required, text)
        for forbidden in ('storageFactory', 'openCatalog:', 'startServer:', 'restore-local'):
            self.assertNotIn(forbidden, text)
        self.assertIn('response_payload_bytes"] >= 6 *', (HERE / "cloud-private-file-smoke.py").read_text())

    def test_dav_shutdown_and_local_cipher_removal_are_required_before_restore(self):
        text = (HERE / "cloud-private-file-smoke.py").read_text()
        self.assertIn('server.shutdown()', text)
        self.assertIn('thread.join(timeout=10)', text)
        self.assertIn('server.socket.fileno() == -1', text)
        self.assertIn('counts == dict(head=1, ranges=4, bytes=len(CONTENT), rejected=0)', text)
        self.assertIn('(root / "bundle/file.pgp").unlink()', text)
        self.assertIn('not (root / "bundle/file.pgp").exists()', text)
        self.assertNotIn('storageFactory', text)
        self.assertNotIn('"restore-local"', text)

    def test_only_closed_reports_are_exported(self):
        names = CHECK["EXPORT_NAMES"]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("cloud-private-file-route-diagnostic.json", names)
        self.assertIn("cloud-private-file-provision.json", names)
        for name in ("image-snapshot-smoke.json", "private-storage-fragments-smoke.json",
                     "file.pgp", "recovery.key", "storage.json", "source.private.json", "fixture.json"):
            self.assertNotIn(name, names)


if __name__ == "__main__":
    unittest.main()
