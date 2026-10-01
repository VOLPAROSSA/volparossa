#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure maintenance receipt/cleanup contracts, not a running-core or peer proof."""
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
OLD = runpy.run_path(str(HERE / 'test-private-storage-fragments-smoke.py'))


def fixture():
    value = OLD['fixture']()
    for name in CHECK['F']['SCOPE_FALSE']:
        value.pop(name, None)
    value.update(dict.fromkeys(CHECK['SCOPE_FALSE'], False))
    size, a, fg = CHECK['BYTES'], CHECK['A_BYTES'], len(CHECK['FG'])
    value['prepare'].update(grant_payload_bytes=[size] * 3, grant_max_leases=[4] * 3,
        independent_foreground_bytes=fg)
    value['upload'].update(core_renewal_confirmed=True, renewal_fragment_index=0,
        owner_eof_during_admitted_turn=True, subsequent_core_turn_proves_lane_released=True,
        independent_foreground_progress_confirmed=True, foreground_turn_revoked=True,
        cursor_before_restart=2, cursor_after_restart=3, cancelled_turns_reconciled=True,
        enrollment_owner_private=True)
    value['restore'] = dict(restores=2, source_absent=True, owner_worker_starts=3,
        scan_cursor_before=3, scan_cursor_after=6, fresh_verified_replacements=3,
        retained_copy_records=11, pending_retirements=3, physical_payload_charge=CHECK['MAX_CHARGE'],
        uncertain_payload_charge=a, survivor_provider_indexes=[1, 2], uniform_target_copies=2,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
        original_identities_retained=True, staging_removed=True)
    value['finish'] = dict(owner_worker_starts=1, pending_retirements=0, duplicate_replacements=0,
        acknowledged_source_retirement=True, all_eleven_copies_deleted=True, foreground_copy_deleted=True,
        delete_retry_idempotent=True, original_identities_retained=True, final_payload_charge=0, staging_removed=True)
    value['uploaded_usage'][1]['committed_bytes'] += fg
    value['uploaded_usage'][1]['leases'] += 1
    value['restored_usage'] = [dict(reserved_bytes=0, committed_bytes=b, leases=n)
        for b, n in zip((a, size + fg, size), (3, 5, 4))]
    value['private_cleanup'].update(enrollment_checkpoint_removed=True, foreground_journal_removed=True)
    return value


def report(value):
    return dict(source_revision='1' * 40, schema_version=1,
        report_kind='volparossa-private-storage-maintenance', success=True, runner_exit_status=0,
        phase='private-storage-maintenance-complete', observed_blocker=None,
        cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), maintenance=value)


class MaintenanceEvidence(unittest.TestCase):
    def test_retirement_readback_is_not_a_new_replacement(self):
        before = dict(placement_authorizations=3, retained_copy_records=11)
        for fresh in (0, 1):
            CHECK['validate_retirement_progress'](before, dict(before),
                dict(freshly_verified_replacements=fresh))
        for value, fresh in ((dict(before, placement_authorizations=4), 0),
                             (dict(before, retained_copy_records=12), 1),
                             (before, 2), (before, True)):
            with self.assertRaises(ValueError):
                CHECK['validate_retirement_progress'](before, value,
                    dict(freshly_verified_replacements=fresh))

    def test_closed_source_bound_bundle_reuses_actual_network_proof_contracts(self):
        value = fixture()
        CHECK['validate_evidence'](value)
        CHECK['validate_report'](report(value), '1' * 40)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            OLD['write_evidence'](root, value)
            self.assertEqual(CHECK['evidence'](root), value)
            self.assertEqual(set(CHECK['EXPORT_NAMES']) - {
                'private-storage-maintenance-smoke.json', 'private-storage-maintenance-evidence.json'},
                {p.name for p in root.iterdir()})
            (root / 'private-storage-fragments-restored_usage.json').write_text('{}')
            with self.assertRaises(ValueError):
                CHECK['evidence'](root)

    def test_missing_core_authority_cursor_and_stop_proofs_never_pass(self):
        for mutate in (
            lambda v: v['upload'].update(core_renewal_confirmed=False),
            lambda v: v['upload'].update(owner_eof_during_admitted_turn=False),
            lambda v: v['upload'].update(subsequent_core_turn_proves_lane_released=False),
            lambda v: v['upload'].update(independent_foreground_progress_confirmed=False),
            lambda v: v['upload'].update(foreground_turn_revoked=False),
            lambda v: v['upload'].update(cancelled_turns_reconciled=False),
            lambda v: v['upload'].update(cursor_after_restart=1),
            lambda v: v['restore'].update(scan_cursor_after=3),
            lambda v: v['restore'].update(fresh_verified_replacements=2),
            lambda v: v.update(automatic_grant_refresh=True),
        ):
            invalid = fixture()
            mutate(invalid)
            with self.assertRaises(ValueError):
                CHECK['validate_evidence'](invalid)
        with self.assertRaises((ValueError, KeyError)):
            CHECK['validate_evidence'](OLD['fixture']())

    def test_uncertain_charges_replacements_cleanup_and_privacy_are_required(self):
        for mutate in (
            lambda v: v['restore'].update(uncertain_payload_charge=0),
            lambda v: v['restore'].update(physical_payload_charge=2 * CHECK['BYTES']),
            lambda v: v['restored_usage'][0].update(committed_bytes=0),
            lambda v: v['restored_usage'][1].update(leases=4),
            lambda v: v['finish'].update(acknowledged_source_retirement=False),
            lambda v: v['finish'].update(duplicate_replacements=1),
            lambda v: v['deleted_usage'][1].update(committed_bytes=64),
            lambda v: v['private_cleanup'].update(enrollment_checkpoint_removed=False),
            lambda v: v['network']['upload']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['network']['restore']['privacy']['exit']['provider_application']['relay4'].update(response_payload_bytes=1),
        ):
            invalid = fixture()
            mutate(invalid)
            with self.assertRaises(ValueError):
                CHECK['validate_evidence'](invalid)
        for mutate in (lambda v: v['host_state'].update(unchanged=False),
                       lambda v: v['cleanup'].update(remaining_owned_objects=1),
                       lambda v: v.update(source_revision='2' * 40)):
            invalid = report(fixture())
            mutate(invalid)
            with self.assertRaises(ValueError):
                CHECK['validate_report'](invalid, '1' * 40)

    def test_stale_redundancy_receipts_do_not_end_partial_repair(self):
        keys = ['1' * 64, '2' * 64, '3' * 64]
        value = dict(fully_redundant_from_retained_receipts=True)
        for count in range(3):
            value.update(placement_authorizations=count, pending_retirements=count, retained_copy_records=8 + count)
            self.assertFalse(CHECK['repaired'](value, keys))
        # A third Copying intent, not yet a verified replacement, still stays pending.
        value.update(placement_authorizations=3, pending_retirements=2, retained_copy_records=11)
        self.assertFalse(CHECK['repaired'](value, keys))

    def test_cleanup_removes_only_exact_private_owner_tree_and_crash_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private-storage-user'
            root.mkdir(mode=0o700)
            def add(relative):
                path = root / relative
                for parent in reversed(path.parents):
                    if root == parent or root in parent.parents:
                        parent.mkdir(mode=0o700, exist_ok=True)
                CHECK['create'](path, b'synthetic private fixture')
            for name in ('identity.key', 'passphrase', 'foreground-grant.bin',
                         'fragment-set/fragments.json', 'fragment-set/placement-authorizations.json',
                         'maintenance/enrollment.json', 'maintenance/checkpoint.json', 'foreground/archive.json',
                         'maintenance-fixed-a/enrollment.json', 'maintenance-fixed-a/checkpoint.json',
                         'fragment-set/fragment-0000/copy-2/archive.json',
                         'fragment-set/fragment-0000/.handoff-journal-X1/copy/archive.json',
                         'fragment-set/fragment-0000/.handoff-transfer-X2/survivor-1',
                         'fragment-set/.fragment-transfer-X3/.tmpA1'):
                add(name)
            sentinel = Path(temporary) / 'not-ours'
            sentinel.write_text('retain')
            (root / 'unexpected-link').symlink_to(sentinel)
            with self.assertRaises(ValueError):
                CHECK['cleanup'](root)
            self.assertEqual(sentinel.read_text(), 'retain')
            self.assertTrue((root / 'identity.key').exists())
            (root / 'unexpected-link').unlink()
            self.assertTrue(all(CHECK['cleanup'](root).values()))
            self.assertFalse(root.exists())
            self.assertTrue(all(CHECK['cleanup'](root).values()))
            self.assertEqual(sentinel.read_text(), 'retain')


if __name__ == '__main__':
    unittest.main()
