#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic receipt/rendezvous contracts; not native execution or live storage proof."""
import copy
import json
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "signal-backup-fragments-smoke.py"))
NATIVE = runpy.run_path(str(HERE / "test-signal-backup-smoke.py"))
FRAGMENTS = runpy.run_path(str(HERE / "test-private-storage-fragments-smoke.py"))
REVISION = "a" * 40


def fixture():
    old, fragments = NATIVE["fixture"](), FRAGMENTS["fixture"]()
    size = FRAGMENTS["CHECK"]["BYTES"]
    lengths, counts, charges = CHECK["configure_geometry"](size)
    value = {name: fragments[name] for name in
        ("expected_peers", "layout", "isolation", "uploaded_usage", "restored_usage", "deleted_usage", "network")}
    value.update(success=True, **dict.fromkeys(CHECK["FALSE_SCOPE"], False))
    for name in ("native", "guard", "private_cleanup"):
        value[name] = old[name]
    value["native"]["chat_revision"] = REVISION
    value["prepare"] = dict(providers=3, grant_max_leases_each=4, grant_payload_bytes_each=CHECK["CAPACITY"],
        owner_distinct_from_all_providers=True, owner_secrets_exported=False)
    value["uploaded"] = dict(logical_ciphertext_bytes=size, fragment_lengths=list(lengths), fragment_count=4,
        copies_per_fragment=2, committed_fragment_copies=8, provider_leases=counts, provider_payload_bytes=charges,
        physical_payload_charge=2 * size, owner_signature_verified=True, source_removed_before_restore=True,
        native_export_rendezvous_observed=True)
    value["restore"] = dict(second_core_restore=True, native_import_already_completed=True,
        fragment_provider_indexes=[1, 1, 2, 1], whole_archive_sha256_verified=True, reads_nonconsuming=True,
        retained_identity_unchanged=True, ciphertext_removed=True)
    value["finish"] = dict(logical_ciphertext_bytes=size, all_eight_fragment_copies_deleted=True, final_payload_charge=0)
    value["withdrawal"] = dict(first_provider_stopped_before_confirmation=True,
        native_ready_provider_matches_first=True, first_store_retained=True, other_two_providers_serving=True,
        same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True)
    return value


class SignalFragmentEvidence(unittest.TestCase):
    def test_native_fragment_receipts_and_all_three_network_phases_required(self):
        good = fixture()
        CHECK["validate_evidence"](good, REVISION)
        for mutate in (
            lambda v: v["native"].update(chat_revision="b" * 40),
            lambda v: v["native"].update(native_encrypted_export_import=False),
            lambda v: v["native"]["native_test"].update(passes=0, tests=0),
            lambda v: v["native"]["native_test"].update(pending=1),
            lambda v: v["native"].update(private_logs_exported=True),
            lambda v: v["uploaded"].update(fragment_count=1),
            lambda v: v["uploaded"].update(copies_per_fragment=1),
            lambda v: v["uploaded"].update(physical_payload_charge=1),
            lambda v: v["uploaded"].update(source_removed_before_restore=False),
            lambda v: v["uploaded"]["provider_payload_bytes"].__setitem__(0, 1),
            lambda v: v["withdrawal"].update(first_provider_stopped_before_confirmation=False),
            lambda v: v["withdrawal"].update(native_ready_provider_matches_first=False),
            lambda v: v["restore"].update(fragment_provider_indexes=[1, 1, 1, 1]),
            lambda v: v["restore"].update(retained_identity_unchanged=False),
            lambda v: v["restored_usage"][0].update(committed_bytes=0),
            lambda v: v["deleted_usage"][2].update(leases=1),
            lambda v: v["network"].pop("upload"),
            lambda v: v["network"]["restore"]["gates"].update(exit_mptcp_tls_completed=15),
            lambda v: v["network"]["restore"]["privacy"]["exit"]["provider_application"]["relay4"].update(response_payload_bytes=1),
            lambda v: v["network"]["restore"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda v: v["guard"].update(blocked_packets=0),
            lambda v: v["private_cleanup"].update(recovery_keys_removed=False),
        ):
            bad = copy.deepcopy(good); mutate(bad)
            with self.assertRaises(ValueError):
                CHECK["validate_evidence"](bad, REVISION)

    def test_real_native_size_geometry_is_fragmented_not_whole_archive_duplication(self):
        chunk, lengths, counts, charges = CHECK["geometry"](198352)
        self.assertEqual(lengths, (66117, 66117, 66117, 1))
        self.assertEqual(counts, [3, 3, 2])
        self.assertEqual(sum(charges), 396704)
        self.assertTrue(all(0 < n < 198352 for n in charges))
        for size in (0, True, 3, 198351, 5 * 262144):
            with self.assertRaises(ValueError): CHECK["geometry"](size)

    def test_rendezvous_matches_exact_provider_and_never_exports_private_markers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "backup").mkdir(mode=0o700)
            keys = [str(i) * 64 for i in (1, 2, 3)]
            CHECK["create"](root / "config.json", json.dumps(dict(providers=[dict(key=k) for k in keys])).encode())
            CHECK["create"](root / "backup/recovery.json", json.dumps(dict(version=2,
                storage=dict(kind="fragments", providerKeys=keys), ciphertextBytes=198352,
                ciphertextSha256="a" * 64)).encode())
            ready = root / "backup/withdrawal-ready.json"
            CHECK["create"](ready, json.dumps(dict(version=1, ready=True, provider_key=keys[1])).encode())
            with self.assertRaises(ValueError): CHECK["confirm_withdrawal"](root)
            ready.unlink()
            CHECK["create"](ready, json.dumps(dict(version=1, ready=True, provider_key=keys[0])).encode())
            self.assertEqual(CHECK["confirm_withdrawal"](root), dict(confirmation_written=True))
            self.assertEqual(json.loads((root / "backup/withdrawal-confirmed.json").read_text()),
                dict(version=1, provider_stopped=True, provider_key=keys[0]))
            with self.assertRaises(FileExistsError): CHECK["confirm_withdrawal"](root)
        self.assertTrue(all("recovery" not in name and "withdrawal-ready" not in name
                            and "config" not in name and not name.endswith(".log") for name in CHECK["EXPORT_NAMES"]))

    def test_shell_stops_provider_before_confirm_and_waits_for_native_before_second_restore(self):
        source = (HERE / "signal-backup-fragments-smoke.sh").read_text()
        self.assertLess(source.index("signal_backup_fragments_private uploaded"),
                        source.index("private_storage_fragments_usage uploaded_usage"))
        self.assertLess(source.index("private_storage_fragments_reopen relay5 relay3"),
                        source.index("signal_backup_fragments_private confirm-withdrawal"))
        self.assertLess(source.index(".serving == false"), source.index("confirm-withdrawal"))
        self.assertLess(source.index('wait "$DOWNLOAD_CLIENT_PID"'), source.index("signal_backup_fragments_private restore"))
        self.assertIn('signal_wait" -lt 2400', source)
        self.assertNotIn("--copies", source)


if __name__ == "__main__":
    unittest.main()
