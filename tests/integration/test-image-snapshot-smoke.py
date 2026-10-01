#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Evidence mutation checks and optional real local GPG; never live peer proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "image-snapshot-smoke.py"))
OLD = runpy.run_path(str(HERE / "test-private-storage-fragments-smoke.py"))


def fixture():
    value = OLD["fixture"]()
    size = 3 * CHECK["CHUNK"] + 12345
    prepare = dict(image_revision=CHECK["REVISION"], source_sha256=CHECK["SOURCE_HASHES"],
        plaintext_sha256=CHECK["SOURCE_DIGESTS"], plaintext_bytes=CHECK["SOURCE_BYTES"],
        ciphertext_bytes=size, cipher_sha256="a" * 64, archive_encryption_proven=True,
        original_plaintext_preserved=True, owner_distinct_from_all_providers=True, owner_secrets_exported=False)
    geometry = CHECK["configure"](prepare)
    prepare.update(grant_payload_bytes=list(geometry["PROVIDER_BYTES"]), grant_max_leases=list(geometry["PROVIDER_LEASES"]))
    value.update(prepare=prepare, archive_encryption_proven=True, **dict.fromkeys(CHECK["FALSE_CLAIMS"], False))
    value["upload"] = dict(actual_image_cli=True, committed_fragment_copies=8,
        logical_ciphertext_bytes=size, physical_payload_charge=2 * size, committed_retry_same_identities=True,
        renewal_confirmed=True, source_ciphertext_removed=True, original_plaintext_preserved=True,
        temporary_transfer_files_removed=True)
    value["restore"] = dict(actual_image_cli=True, restores=2, actual_gpg_decryptions=2,
        plaintext_sha256=[CHECK["SOURCE_DIGESTS"], CHECK["SOURCE_DIGESTS"]], source_ciphertext_absent=True,
        original_plaintext_preserved=True, openpgp_integrity_verified=True, manifest_verified=True,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
        retained_identity_unchanged=True, physical_payload_charge=2 * size)
    value["finish"] = dict(actual_image_cli=True, reopened_copies_confirmed=True, all_eight_copies_deleted=True,
        delete_retry_idempotent=True, original_plaintext_preserved=True, final_payload_charge=0)
    retained = [dict(reserved_bytes=0, committed_bytes=n, leases=c)
                for n, c in zip(geometry["PROVIDER_BYTES"], geometry["PROVIDER_LEASES"])]
    value["uploaded_usage"] = copy.deepcopy(retained)
    value["restored_usage"] = copy.deepcopy(retained)
    value["private_cleanup"] = dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        recovery_keys_removed=True, private_plaintext_removed=True, ciphertext_removed=True,
        fragment_journal_removed=True, user_directory_removed=True)
    pins = HERE / "image-snapshot-pins.json"
    value["provision"] = dict(version=1, kind="image-snapshot-runtime-provision", success=True,
        pins=json.loads(pins.read_text()), pins_sha256=hashlib.sha256(pins.read_bytes()).hexdigest(),
        tools={name: dict(package=name, package_version="fixture", bytes=1, sha256="a" * 64)
               for name in ("gpg", "gpg-agent", "gpgconf", "tar")}, guest_only=True,
        source_files_verified=True, runtime_files_verified=True, original_licenses_retained=True,
        snapshot_created=False, peer_storage_proven=False, immich_server_started=False)
    for phase in value["network"].values():
        for node in ("relay5", "relay3"):
            phase["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"] = 2 * size
    return value


class ImageEvidence(unittest.TestCase):
    def test_exact_image_candidate_and_fragment_network_evidence(self):
        value = fixture()
        CHECK["validate_evidence"](value)
        report = dict(schema_version=1, report_kind="volparossa-image-snapshot", source_revision="b" * 40,
            success=True, runner_exit_status=0, phase="image-snapshot-complete", observed_blocker=None,
            cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), image=value)
        CHECK["validate_report"](report, "b" * 40)
        with self.assertRaises(ValueError):
            CHECK["validate_report"](report, "c" * 40)

    def test_encryption_only_cache_stub_or_false_scope_is_rejected(self):
        for mutate in (
            lambda v: v.update(archive_encryption_proven=False),
            lambda v: v.update(serverless_immich_proven=True),
            lambda v: v.update(public_cache_used=True),
            lambda v: v.update(owner_secrets_exported=True),
            lambda v: v["prepare"].update(image_revision="a" * 40),
            lambda v: v["prepare"].update(ciphertext_bytes=1024),
            lambda v: v["prepare"].update(plaintext_bytes=0),
            lambda v: v["prepare"].update(owner_distinct_from_all_providers=False),
            lambda v: v["upload"].update(actual_image_cli=False),
            lambda v: v["upload"].update(source_ciphertext_removed=False),
            lambda v: v["restore"].update(actual_gpg_decryptions=0),
            lambda v: v["restore"].update(plaintext_sha256=[]),
            lambda v: v["restore"].update(original_plaintext_preserved=False),
            lambda v: v["restore"].update(reads_nonconsuming=False),
            lambda v: v["withdrawal"].update(first_provider_stopped_before_restore=False),
            lambda v: v["private_cleanup"].update(recovery_keys_removed=False),
            lambda v: v["deleted_usage"][0].update(committed_bytes=1),
            lambda v: v["restored_usage"][0].update(committed_bytes=0),
            lambda v: v["provision"].update(runtime_files_verified=False),
            lambda v: v["provision"].update(pins_sha256="f" * 64),
            lambda v: v["provision"]["pins"].update(revision="f" * 40),
            lambda v: v["provision"]["tools"].pop("gpg"),
            lambda v: v["network"]["restore"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay4"].update(response_payload_bytes=1),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay5"].update(response_payload_bytes=1),
        ):
            value = fixture()
            mutate(value)
            with self.assertRaises((ValueError, KeyError)):
                CHECK["validate_evidence"](value)

    def test_exports_do_not_substitute_old_non_encryption_report(self):
        names = CHECK["EXPORT_NAMES"]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("image-snapshot-smoke.json", names)
        self.assertIn("image-snapshot-provision.json", names)
        self.assertNotIn("private-storage-fragments-smoke.json", names)
        self.assertNotIn("private-storage-fragments-evidence.json", names)
        self.assertTrue(all("/" not in name and name.endswith(".json") for name in names))
        self.assertFalse(any("recovery.key" in name or "snapshot.pgp" in name for name in names))

    def test_private_cleanup_rejects_symlink_and_removes_owned_state(self):
        with tempfile.TemporaryDirectory(prefix="vp-img-") as temporary:
            root = Path(temporary) / "i"
            root.mkdir(mode=0o700)
            (root / "nested").mkdir(mode=0o700)
            CHECK["create"](root / "nested/recovery.key", b"synthetic")
            (root / "escape").symlink_to(Path(temporary))
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(root))
            self.assertTrue((root / "nested/recovery.key").exists())
            (root / "escape").unlink()
            result = CHECK["cleanup"](str(root))
            self.assertTrue(result["recovery_keys_removed"])
            self.assertFalse(root.exists())
            self.assertEqual(CHECK["cleanup"](str(root)), result)

    def test_arbitrary_cleanup_root_is_rejected(self):
        for root in ("/", "/tmp", "relative/i", "/i"):
            with self.assertRaises(ValueError):
                CHECK["cleanup"](root)

    def test_real_plaintext_verifier_rejects_changed_asset(self):
        with tempfile.TemporaryDirectory(prefix="vp-img-") as temporary:
            root = Path(temporary)
            for name, data in CHECK["SOURCE_FILES"].items():
                (root / name).parent.mkdir(mode=0o700, exist_ok=True)
                CHECK["create"](root / name, data)
            CHECK["verify_plain"](root)
            (root / "upload/synthetic.bin").unlink()
            CHECK["create"](root / "upload/synthetic.bin", b"wrong")
            with self.assertRaises(ValueError):
                CHECK["verify_plain"](root)

    @unittest.skipUnless(os.environ.get("IMAGE_SNAPSHOT_LOCAL_SOURCE"), "optional actual pinned local GPG probe")
    def test_actual_pinned_image_gpg_create_and_two_independent_plaintext_restores(self):
        source = Path(os.environ["IMAGE_SNAPSHOT_LOCAL_SOURCE"])
        for name, digest in CHECK["SOURCE_HASHES"].items():
            self.assertEqual(hashlib.sha256((source / name).read_bytes()).hexdigest(), digest)
        with tempfile.TemporaryDirectory(prefix="vp-img-") as temporary:
            root = Path(temporary) / "i"
            root.mkdir(mode=0o700)
            original = root / "source"
            original.mkdir(mode=0o700)
            for name, data in CHECK["SOURCE_FILES"].items():
                (original / name).parent.mkdir(mode=0o700, exist_ok=True)
                CHECK["create"](original / name, data)
            # Only the test resolves the already-present checkout; production
            # tools() accepts only the exact root-owned guest provision.
            with mock.patch.dict(CHECK["snapshot"].__globals__, tools=lambda: (source, Path("/unused"))):
                receipt = CHECK["snapshot"]("create", "--source", original,
                    "--output", root / "bundle", "--quiesced-copy")
                self.assertEqual(receipt["encryption"], "OpenPGP-AES256")
                self.assertGreater(receipt["cipher_bytes"], 3 * CHECK["CHUNK"])
                self.assertLessEqual(receipt["cipher_bytes"], 4 * CHECK["CHUNK"])
                for index in (1, 2):
                    result = CHECK["snapshot"]("restore", "--bundle", root / "bundle",
                        "--output", root / f"plain-{index}", "--expected-sha256", receipt["cipher_sha256"])
                    self.assertTrue(result["openpgp_integrity_verified"])
                    self.assertTrue(result["manifest_verified"])
                    CHECK["verify_plain"](root / f"plain-{index}")
                    CHECK["verify_plain"](original)
            self.assertFalse(any(path.name.startswith(("g-", "r-")) for path in root.iterdir()))
            self.assertTrue(CHECK["cleanup"](str(root))["user_directory_removed"])


if __name__ == "__main__":
    unittest.main()
