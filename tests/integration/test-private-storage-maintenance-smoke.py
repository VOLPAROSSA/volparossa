#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure maintenance receipt/cleanup contracts, not a running-core or peer proof."""
from pathlib import Path
import copy
import json
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

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
    for phase in value['network'].values():
        selected = phase['selected_route']
        selected['exact_selected_exit'] = selected['paths'][0]['exit_peer_id']
        selected['exact_selected_relays'] = [p['relay_peer_id'] for p in selected['paths']]
        for path, slot in zip(selected['paths'], selected['benchmark_slots']):
            path['state'] = 1
            slot['path_id'] = path['path_id']
        gates = phase['gates']
        gates.update(exit_log_sampling_version=2, exit_log_samples=2,
            exit_log_observed_records=gates['exit_log_records'], exit_log_overlap_verified=True,
            exit_log_sampler_joined=True, exit_route_scope=CHECK['SAMPLER']['route_scope'](selected),
            observed_route_context_ids=[selected['route_context_id']],
            exit_flow_contexts=[dict(route_context_id=selected['route_context_id'],
                completed=gates['exit_mptcp_tls_completed'], failed=gates['exit_mptcp_tls_failed'])])
    value['layout']['route_scope'] = copy.deepcopy(value['network']['upload']['gates']['exit_route_scope'])
    return value


def report(value):
    return dict(source_revision='1' * 40, schema_version=1,
        report_kind='volparossa-private-storage-maintenance', success=True, runner_exit_status=0,
        phase='private-storage-maintenance-complete', observed_blocker=None,
        cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), maintenance=value)


class MaintenanceEvidence(unittest.TestCase):
    def test_retirement_projects_only_existing_bounded_checkpoint_fields(self):
        namespace = CHECK['retirement_turn'].__globals__
        with patch.dict(namespace, RETIREMENT_TURNS=[]):
            invalid = dict(turns=True, detail=dict(maintenance_stage='SECRET_PRIVATE',
                repair_stage={'SECRET_KEY': 'SECRET_VALUE'}, attempted_handoffs=True,
                freshly_verified_replacements=2, pending_retirements=-1,
                physical_payload_charge_upper_bound=CHECK['MAX_CHARGE'] + 1,
                refresh=dict(fragment_index=len(CHECK['LENGTHS']), renewal='SECRET',
                    operation_complete=1), extra='SECRET_STDERR'))
            CHECK['retirement_turn'](invalid, 1)
            CHECK['retirement_turn'](dict(turns=8, detail=dict(maintenance_stage='observed',
                refresh=dict(fragment_index=3, renewal=False, operation_complete=True))), 2)
            CHECK['retirement_turn'](None, 3)
            CHECK['retirement_turn'](dict(detail='SECRET'), 4)
            for turn in (5, True, -1, 1):
                CHECK['retirement_turn'](invalid, turn)
            result = CHECK['failure_receipt'](ValueError('source retirement unconfirmed'))
            self.assertEqual(len(result['retirement_turns']), 4)
            first, observed = result['retirement_turns'][:2]
            self.assertEqual(first['turn'], 1)
            self.assertTrue(all(value is None for key, value in first.items() if key not in ('turn', 'refresh')))
            self.assertTrue(all(value is None for value in first['refresh'].values()))
            self.assertEqual(observed['maintenance_stage'], 'observed')
            self.assertIsNone(observed['repair_stage'])
            self.assertIsNone(observed['attempted_handoffs'])
            self.assertEqual(observed['refresh'], dict(fragment_index=3, renewal=False, operation_complete=True))
            self.assertNotIn('SECRET', json.dumps(result))

    def test_four_pending_retirement_turns_fail_with_each_existing_repair_receipt(self):
        namespace = CHECK['finish'].__globals__
        before = dict(placement_authorizations=3, retained_copy_records=11, pending_retirements=3)
        turns = [dict(turns=7 + index, stage='turn_completed', detail=dict(
            maintenance_stage='maintained', repair_stage='pass_limit' if index == 0 else 'pending_handoff',
            attempted_handoffs=1, freshly_verified_replacements=1 if index == 0 else 0,
            pending_retirements=2, physical_payload_charge_upper_bound=CHECK['MAX_CHARGE'],
            refresh=dict(fragment_index=(6 + index) % 4, renewal=True, operation_complete=index == 0)))
            for index in range(4)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'fragment-set').mkdir(mode=0o700)
            CHECK['create'](root / 'fragment-set/placement-authorizations.json', b'synthetic signed placements')
            owner, status, invoke = Mock(side_effect=turns), Mock(side_effect=[before] +
                [dict(before, pending_retirements=2)] * 4), Mock()
            with patch.dict(namespace, run_turn=owner, status=status, invoke=invoke,
                    RETIREMENT_TURNS=[], SAMPLER_DIAGNOSTIC={}):
                with self.assertRaisesRegex(ValueError, 'source retirement unconfirmed') as failure:
                    CHECK['finish'](root, '/synthetic/cli', '/synthetic/socket', ['a', 'b', 'c'])
                result = CHECK['failure_receipt'](failure.exception)
                self.assertEqual(result['code'], 'retirement_pending_or_charge')
                self.assertEqual(owner.call_count, 4)
                self.assertEqual(status.call_count, 5)
                invoke.assert_not_called()  # No deletion before confirmed retirement.
                self.assertEqual([v['cursor'] for v in result['retirement_turns']], [7, 8, 9, 10])
                self.assertEqual([v['repair_stage'] for v in result['retirement_turns']],
                    ['pass_limit', 'pending_handoff', 'pending_handoff', 'pending_handoff'])
                self.assertEqual([v['freshly_verified_replacements'] for v in result['retirement_turns']], [1, 0, 0, 0])
                self.assertEqual(result['retirement']['pending_retirements'], 2)

    def test_failure_diagnostics_are_closed_and_bound_private_checkpoint_fields(self):
        namespace = CHECK['failure_receipt'].__globals__
        with patch.dict(namespace, TURN_DIAGNOSTIC={}, RETIREMENT_DIAGNOSTIC=None, SAMPLER_DIAGNOSTIC={}):
            CHECK['turn_checkpoint'](dict(turns=True, stage='SECRET_PATH',
                detail=dict(maintenance_stage='SECRET_PAYLOAD', extra='SECRET_KEY')))
            CHECK['retirement_counts'](dict(pending_retirements=10**9,
                placement_authorizations=True, retained_copy_records='SECRET'), 99)
            result = CHECK['failure_receipt'](ValueError('SECRET_STDERR'))
            self.assertEqual(result['code'], 'unclassified')
            self.assertEqual(result['turn'], dict(cursor_after=None, checkpoint_stage=None, maintenance_stage=None))
            self.assertTrue(all(v is None for v in result['retirement'].values()))
            self.assertNotIn('SECRET', json.dumps(result))
            for message, code in (
                ('cursor did not resume exactly one turn', 'cursor_mismatch'),
                ('maintenance did not complete a core turn', 'turn_stage'),
                ('source retirement unconfirmed', 'retirement_pending_or_charge'),
                ('signed replacement identities changed', 'retirement_identity'),
            ):
                self.assertEqual(CHECK['failure_receipt'](ValueError(message))['code'], code)
            self.assertEqual(CHECK['failure_receipt'](subprocess.TimeoutExpired('SECRET', 650))['code'], 'cli_timeout')

    def test_failed_turn_preserves_fixed_checkpoint_stage_and_cursor(self):
        namespace = CHECK['run_turn'].__globals__
        process = Mock(returncode=0)
        process.communicate.return_value = (b'', b'')
        process.poll.return_value = 0
        checkpoints = [dict(turns=6), dict(turns=7, stage='retry_pending', detail='SECRET_PRIVATE_ERROR')]
        with patch.dict(namespace, checkpoint=Mock(side_effect=checkpoints), unlock=lambda root: []), \
                patch.object(CHECK['subprocess'], 'Popen', return_value=process):
            with self.assertRaisesRegex(ValueError, 'maintenance did not complete') as failure:
                CHECK['run_turn'](Path('/synthetic'), '/synthetic/cli', '/synthetic/socket', 'key')
            result = CHECK['failure_receipt'](failure.exception)
            self.assertEqual(result['code'], 'turn_stage')
            self.assertEqual(result['turn']['checkpoint_stage'], 'retry_pending')
            self.assertEqual((result['turn']['cursor_before'], result['turn']['cursor_after']), (6, 7))
            self.assertNotIn('SECRET', json.dumps(result))

    def test_owner_timeout_is_not_replaced_by_cleanup_io_failure(self):
        namespace = CHECK['run_turn'].__globals__
        original = subprocess.TimeoutExpired('SECRET_COMMAND', 650)
        process = Mock(returncode=None)
        process.communicate.side_effect = original
        process.poll.return_value = None
        process.send_signal.side_effect = OSError('SECRET_CLEANUP_PATH')
        with patch.dict(namespace, checkpoint=lambda *args: dict(turns=6), unlock=lambda root: []), \
                patch.object(CHECK['subprocess'], 'Popen', return_value=process):
            with self.assertRaises(subprocess.TimeoutExpired) as failure:
                CHECK['run_turn'](Path('/synthetic'), '/synthetic/cli', '/synthetic/socket', 'key')
            self.assertIs(failure.exception, original)
            result = CHECK['failure_receipt'](failure.exception)
            self.assertEqual(result['code'], 'cli_timeout')
            self.assertEqual(result['turn']['cleanup_error'], 'local_io')
            self.assertEqual(result['turn']['substage'], 'join_owner')
            self.assertNotIn('SECRET', json.dumps(result))

    def test_new_context_requires_same_paths_and_new_actual_flow_evidence(self):
        value = fixture()
        phase = value['network']['finish']
        newer = 'b' * 32
        phase['selected_route']['route_context_id'] = newer
        for path in phase['selected_route']['paths']:
            path['route_context_id'] = newer
        with self.assertRaises(ValueError):
            CHECK['validate_evidence'](value)
        phase['gates']['observed_route_context_ids'] = [newer]
        phase['gates']['exit_flow_contexts'][0]['route_context_id'] = newer
        CHECK['validate_evidence'](value)
        # Normal fragment validation remains initial-context strict.
        with self.assertRaises(ValueError):
            CHECK['F']['validate_network'](phase, value['expected_peers'], value['layout'], 'finish')
        phase['selected_route']['paths'][0]['relay_peer_id'] = 'other'
        with self.assertRaises(ValueError):
            CHECK['validate_evidence'](value)

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
                         'flow-upload.json', 'flow-restore.json', 'flow-finish.json',
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
