#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert receipt/authority and owned-child tests; no GPG, core, VM or network."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
G = M['main'].__globals__
PROVISION = 'a' * 64


def base(phase):
    return dict(version=1, kind='storage-consumer-maintenance', phase=phase, passed=True,
        provision_sha256=PROVISION, scope=dict(M['SCOPE']))


def prepared():
    return dict(base('prepare'), **{name: dict(cipher_bytes=800001 + i * 2,
        cipher_sha256=str(i + 1) * 64, application_encryption='OpenPGP-AES256')
        for i, name in enumerate(('image', 'cloud'))})


def report(phase):
    value, original = base(phase), prepared()
    for name in ('image', 'cloud'):
        size = original[name]['cipher_bytes']
        committed = 0 if phase == 'finish' else 2 * size
        uncertain = M['geometry'](size)[2] if phase == 'exercise' else 0
        app = dict(logical_ciphertext_bytes=size, committed_payload_bytes=committed,
            uncertain_payload_bytes=uncertain, physical_payload_charge_upper_bound=committed + uncertain,
            fragment_count=4, copies_per_fragment=2, retained_copy_records=8 if phase == 'publish' else 11,
            pending_retirements=0 if phase == 'publish' else 3)
        if phase == 'publish':
            app.update(cipher_sha256=original[name]['cipher_sha256'], enrollment_created=True,
                maintenance_started=False, original_journals_bound=True)
        elif phase == 'exercise':
            app.update({key: True for key in M['LIFECYCLE']})
            app.update(cursor_before=3, cursor_after=4, exact_join_before_spawn_measured=False,
                completed_turn_observed=False, confirmed_copy_retentions_advanced=1,
                cipher_cache_removed_before_read=True, plaintext_sha256=M['fixture_hash'](name),
                plaintext_bytes=M['PLAIN_BYTES'], original_enrollment_and_journals_retained=True,
                owner_joined=True)
            app.update(dict(application_decryption_verified=True, quiesced_sql_dump_restored=True)
                if name == 'image' else dict(authenticated_get_body_verified=True, wrong_token_status=401))
        else:
            app.update(all_retained_copies_delete_acknowledged=True, owner_joined=True,
                provider_usage_independently_checked=False, private_fixture_removed=False)
        value[name] = app
    return value


def write(path, data=b'{}'):
    path.write_bytes(data)
    path.chmod(0o600)


def diagnostic_failure(profile_version=2):
    value = dict(version=3, kind='storage-consumer-maintenance', phase='publish', passed=False,
        provision_sha256=PROVISION, stage='cloud_publish', code='publish_operation', cleanup_confirmed=False,
        publish_observation=dict(version=2, app='cloud', operation='deposit', status='incomplete',
            code='retained_operation_incomplete', local_process_joined=True,
            core_report_present=True, core_operation_complete=False,
            deposit_diagnostics_state='observed', deposit_diagnostics=dict(version=1, omitted_failures=0,
                failures=[dict(fragment_index=2, copy_index=1, operation='reserve', stage='agent_terminal',
                    category='io', agent_code=None)])))
    if profile_version in (3, 4, 5, 6, 7, 8, 9, 10):
        value['version'] = profile_version + 1
        observed = value['publish_observation']
        observed['version'] = profile_version
        observed['deposit_diagnostics']['version'] = profile_version - 1
        observed['deposit_diagnostics']['failures'][0].update(stage='agent_ready', category='agent_rejected',
            agent_code='CONTENT_UNAVAILABLE', agent_detail=dict(stage='route_connect', deadline_scope='none'))
        if profile_version >= 4:
            observed['deposit_diagnostics']['failures'][0]['agent_detail'].update(
                stage='tls_handshake', tls_failure='authentication')
        if profile_version == 5:
            observed['deposit_diagnostics']['failures'][0].update(stage='wire_receipt', category='io',
                operation='finalize', agent_code=None, agent_detail=None,
                agent_outcome=dict(status='observed', detail=dict(phase='remote_receipt_read',
                    category='timeout', deadline_scope='remote_wire')))
        if profile_version == 6:
            observed['deposit_diagnostics']['failures'][0].update(agent_outcome=None,
                agent_detail=dict(stage='stream_open', deadline_scope='none', tls_failure=None,
                    stream_failure='flow_acquire'))
        if profile_version == 7:
            observed['deposit_diagnostics']['failures'][0].update(agent_outcome=None,
                agent_detail=dict(stage='challenge', deadline_scope='operation', tls_failure=None,
                    stream_failure=None, challenge=dict(phase='challenge_read_verify',
                        before_challenge='90_to_120s', in_challenge='1_to_5s')))
        if profile_version == 8:
            observed['deposit_diagnostics']['failures'][0].update(operation='append', stage='wire_receipt',
                category='timeout', agent_code=None, agent_detail=None,
                agent_outcome=dict(status='observed', detail=dict(phase='remote_receipt_read',
                    category='timeout', deadline_scope='operation'), append_timing=dict(
                        before_payload='90_to_120s', in_payload_write_flush='under_1s', in_receipt_read='5_to_15s')))
        if profile_version == 9:
            boundary = dict(stage='helper_acquire', reason='helper_io')
            observed['deposit_diagnostics']['failures'][0].update(agent_outcome=None,
                agent_detail=dict(stage='stream_open', deadline_scope='none', tls_failure=None,
                    stream_failure='flow_acquire', challenge=None,
                    flow_acquire=dict(rounds=1, first=dict(boundary), last=dict(boundary))))
        if profile_version == 10:
            observed['deposit_diagnostics']['failures'][0].update(stage='agent_terminal', category='io',
                agent_code=None, agent_detail=None, agent_outcome=dict(status='observed',
                    detail=dict(phase='transport_tls_close', category='unavailable', deadline_scope='none'),
                    append_timing=None, tls_close_failure='read_io'))
    return value


class ConsumerReceipts(unittest.TestCase):
    def test_profile10_closed_close_reasons_and_nullable_outcomes(self):
        for reason in (None, 'shutdown_io', 'read_io', 'trailing_data', 'internal_deadline'):
            value = diagnostic_failure(10)
            value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_outcome']['tls_close_failure'] = reason
            self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=10), value)
            with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)
        for status in ('missing', 'pending', 'expired', 'query_failed', 'query_timeout'):
            value = diagnostic_failure(10)
            outcome = value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_outcome']
            outcome.update(status=status, detail=None, tls_close_failure=None)
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=10)
            outcome['tls_close_failure'] = 'read_io'
            with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=10)

    def test_profile10_refuses_malformed_close_scope_and_preserves_historical_details(self):
        for mutation in (lambda v: v.pop('tls_close_failure'), lambda v: v.pop('append_timing'),
                lambda v: v.update(tls_close_failure='PRIVATE'), lambda v: v.update(raw='PRIVATE'),
                lambda v: v['detail'].update(phase='provider_tls_close'),
                lambda v: v['detail'].update(category='io'), lambda v: v['detail'].update(deadline_scope='operation'),
                lambda v: v.update(append_timing={})):
            value = diagnostic_failure(10)
            mutation(value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_outcome'])
            with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=10)
        for profile in (8, 9):
            value = diagnostic_failure(profile)
            value['version'] = 11
            observed = value['publish_observation']; observed['version'] = 10
            observed['deposit_diagnostics']['version'] = 9
            outcome = observed['deposit_diagnostics']['failures'][0]['agent_outcome']
            if outcome is not None: outcome['tls_close_failure'] = None
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=10)

    def test_profile9_closed_flow_matrix_all_rounds_and_scope(self):
        helper = {'helper_kernel', 'helper_capacity', 'helper_unavailable', 'helper_not_found',
            'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
            'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed'}
        expected = {'source_port': {'entropy'},
            'retirement_drain': {'unconfirmed', 'io'} | (helper - {'helper_not_found'}),
            'material': {'metadata', 'topology'},
            'slot_reservation': {'unconfirmed', 'local_capacity', 'local_unavailable'},
            'helper_acquire': helper, 'descriptor_clone': {'io'},
            'descriptor_adoption': {'metadata', 'io'}, 'flow_metadata': {'metadata'}}
        self.assertEqual(sum(map(len, expected.values())), 35)
        reasons = set().union(*expected.values(), {'unobserved', 'PRIVATE'})
        for stage in (*expected, 'unobserved', 'PRIVATE'):
            for reason in reasons:
                for rounds in (1, 2, 8):
                    value = diagnostic_failure(9)
                    flow = value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_detail']['flow_acquire']
                    flow.update(rounds=rounds, first=dict(stage=stage, reason=reason), last=dict(stage=stage, reason=reason))
                    if reason in expected.get(stage, ()):
                        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=9), value)
                    else:
                        with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)
        value = diagnostic_failure(9)
        flow = value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_detail']['flow_acquire']
        flow['last'] = dict(stage='source_port', reason='entropy')
        with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)
        for rounds in range(2, 9):
            flow['rounds'] = rounds
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)

    def test_profile9_flow_rejects_malformed_scope_and_preserves_append_shape(self):
        mutations = [lambda f: f['agent_detail'].pop('flow_acquire'),
            lambda f: f['agent_detail']['flow_acquire'].update(raw='/private/canary'),
            *(lambda f, x=x: f['agent_detail']['flow_acquire'].update(rounds=x)
                for x in (0, 9, True, None, 1.0, '1')),
            *(lambda f, k=k: f['agent_detail']['flow_acquire'].pop(k) for k in ('rounds', 'first', 'last')),
            *(lambda f, k=k: f['agent_detail']['flow_acquire'].update({k: None}) for k in ('first', 'last')),
            lambda f: f['agent_detail']['flow_acquire']['first'].update(path='/private/canary'),
            *(lambda f, k=k, x=x: f['agent_detail']['flow_acquire']['first'].update({k: x})
                for k in ('stage', 'reason') for x in (None, True, 1, [], {}, 'PRIVATE')),
            *(lambda f, x=x: f['agent_detail'].update(stage=x) for x in ('tls_handshake', 'challenge', 'route_connect')),
            *(lambda f, x=x: f['agent_detail'].update(deadline_scope=x) for x in ('operation', 'exchange')),
            *(lambda f, x=x: f['agent_detail'].update(stream_failure=x) for x in (None, 'policy', 'route_material')),
            lambda f: f['agent_detail'].update(tls_failure='io'),
            lambda f: f['agent_detail'].update(challenge=dict(phase='challenge_read_verify', before_challenge='under_1s', in_challenge='under_1s')),
            *(lambda f, x=x: f.update(agent_code=x) for x in ('CONTENT_INVALID', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown')),
            lambda f: f.update(stage='wire_receipt'), lambda f: f.update(category='io', agent_code=None)]
        for mutate in mutations:
            value = diagnostic_failure(9); mutate(value['publish_observation']['deposit_diagnostics']['failures'][0])
            with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)
        value = diagnostic_failure(9)
        value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_detail']['flow_acquire'] = None
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)
        for version in range(1, 8):
            value['publish_observation']['deposit_diagnostics']['version'] = version
            with self.assertRaises(ValueError): M['validate_deposit_diagnostics'](value['publish_observation']['deposit_diagnostics'], version)
        appended = diagnostic_failure(8)['publish_observation']['deposit_diagnostics']
        appended['version'] = 8
        M['validate_deposit_diagnostics'](appended, 8)
        appended['failures'][0]['agent_outcome'].pop('append_timing')
        with self.assertRaises(ValueError): M['validate_deposit_diagnostics'](appended, 8)

    def test_profile9_failed_child_is_exact_and_never_historical_acceptance(self):
        value = diagnostic_failure(9)
        self.assertEqual(value['version'], 10)
        for old in range(1, 9):
            with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=old)
        for phase in ('prepare', 'publish', 'exercise', 'finish'):
            success = prepared() if phase == 'prepare' else report(phase)
            M['validate_node_report'](success, phase, PROVISION, prepared(), profile_version=9)
            self.assertEqual(success['version'], 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            calls = []
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-RAW-STDERR'
            with patch.dict(G, run_child=child, PROFILE_VERSION=9):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '9'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_profile9_lifecycle11_requires_matching_observation_and_keeps_cleanup_false(self):
        value = diagnostic_failure(9)
        value.update(version=11, publish_cleanup=dict(app='cloud', state='complete'))
        for state in ('complete', 'failed'):
            value['publish_cleanup']['state'] = state
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)
        for mutate in (lambda v: v.update(version=10), lambda v: v.update(cleanup_confirmed=True),
                lambda v: v['publish_observation'].update(version=8), lambda v: v['publish_cleanup'].update(app='image')):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_node_report'](invalid, 'publish', PROVISION, profile_version=9)
        for old in range(1, 9):
            with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=old)
        value.pop('publish_observation')
        value.update(stage='cloud_catalog_create', code='catalog_materialization_failed')
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=9)

    def test_profile8_publish_lifecycle_is_closed_and_keeps_historical_versions_strict(self):
        original = dict(version=10, kind='storage-consumer-maintenance', phase='publish', passed=False,
            provision_sha256=PROVISION, stage='cloud_catalog_create', code='catalog_materialization_failed',
            cleanup_confirmed=False, publish_cleanup=dict(app='cloud', state='failed'))
        for code in M['CATALOG_FAILURE_CODES']:
            for state in ('complete', 'failed'):
                value = copy.deepcopy(original)
                value.update(code=code)
                value['publish_cleanup']['state'] = state
                self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=8), value)
        for app in ('image', 'cloud'):
            for stage in ('publish', 'enroll', 'policy_read', 'core_close'):
                value = copy.deepcopy(original)
                value.update(stage=f'{app}_{stage}', code='core_close_failed' if stage == 'core_close'
                             else 'application_failed')
                value['publish_cleanup']['app'] = app
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=8)
        cases = [lambda v: v.update(version=9), lambda v: v.update(version=True),
            lambda v: v.update(phase='exercise'), lambda v: v.update(passed=True),
            lambda v: v.update(cleanup_confirmed=True), lambda v: v.update(stage='cloud_catalog'),
            lambda v: v.update(stage='cloud_policy_read'), lambda v: v.update(code='PRIVATE'),
            lambda v: v.update(raw_error='PRIVATE'), lambda v: v['publish_cleanup'].update(state=True),
            lambda v: v['publish_cleanup'].update(state='PRIVATE'),
            lambda v: v['publish_cleanup'].update(app='image'),
            lambda v: v['publish_cleanup'].update(remote_cleanup_confirmed=True),
            lambda v: v.update(stage='cloud_core_close'),
            lambda v: v.update(code='core_close_failed')]
        for mutate in cases:
            value = copy.deepcopy(original)
            mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                M['validate_node_report'](value, value['phase'], PROVISION, profile_version=8)
        for profile in range(1, 8):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                M['validate_node_report'](original, 'publish', PROVISION, profile_version=profile)
        for version in range(1, 10):
            value = copy.deepcopy(original)
            value['version'] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION)
        value = copy.deepcopy(original)
        del value['publish_cleanup']
        with self.assertRaises(ValueError):
            M['validate_node_report'](value, 'publish', PROVISION)

    def test_profile8_primary_deposit_and_close_failure_both_survive_node_export(self):
        value = diagnostic_failure(8)
        old = copy.deepcopy(value)
        value.update(version=10, publish_cleanup=dict(app='cloud', state='failed'))
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=8)
        M['validate_node_report'](old, 'publish', PROVISION, profile_version=8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            with patch.dict(G, PROFILE_VERSION=8, run_child=lambda *_: (1, raw, b'PRIVATE-DO-NOT-EXPORT')):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            retained = caught.exception.report
            self.assertEqual(retained['node'], value)
            self.assertEqual(retained['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertFalse(retained['cleanup_confirmed'])
            self.assertFalse(retained['node']['cleanup_confirmed'])
            self.assertNotIn('PRIVATE', json.dumps(retained))
        for mutate in (lambda v: v['publish_cleanup'].update(app='image'),
                       lambda v: v['publish_observation'].update(version=7),
                       lambda v: v.update(stage='cloud_core_close')):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['validate_node_report'](invalid, 'publish', PROVISION, profile_version=8)

    def test_profile_eight_original_failed_child_and_only_closed_timing_survive(self):
        value = diagnostic_failure(8)
        self.assertEqual(value['version'], 9)
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=8), value)
        for old in range(1, 8):
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=old)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            calls = []
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-STDERR-CANARY'
            with patch.dict(G, run_child=child, PROFILE_VERSION=8):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '8'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_append_timing_uses_only_original_outcome_phase_and_exact_nullable_buckets(self):
        buckets = ('under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
            '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s')
        for phase in ('remote_payload_write', 'remote_receipt_read'):
            for before in buckets:
                for payload in buckets:
                    for receipt in ((None,) if phase == 'remote_payload_write' else buckets):
                        value = diagnostic_failure(8)
                        outcome = value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_outcome']
                        outcome['detail']['phase'] = phase
                        outcome['append_timing'] = dict(before_payload=before, in_payload_write_flush=payload,
                            in_receipt_read=receipt)
                        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=8), value)
        for status in ('observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout'):
            value = diagnostic_failure(8)
            outcome = value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_outcome']
            outcome['status'] = status
            if status != 'observed':
                outcome['detail'] = None
                with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=8)
            outcome['append_timing'] = None
            self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=8), value)

    def test_append_timing_rejects_scope_malformed_private_and_unsolicited_old_fields(self):
        mutations = [
            lambda f: f.update(operation='finalize'),
            lambda f: f['agent_outcome']['detail'].update(phase='remote_receipt_verify'),
            lambda f: f['agent_outcome']['detail'].update(phase='remote_payload_write'),
            lambda f: f['agent_outcome'].pop('append_timing'),
            lambda f: f['agent_outcome']['append_timing'].update(phase='remote_receipt_read'),
            lambda f: f['agent_outcome']['append_timing'].update(raw='/private/canary'),
        ]
        for field in ('before_payload', 'in_payload_write_flush', 'in_receipt_read'):
            mutations.append(lambda f, k=field: f['agent_outcome']['append_timing'].pop(k))
            for invalid in (None, True, 1, {}, [], 'unobserved', '/private/canary'):
                mutations.append(lambda f, k=field, v=invalid: f['agent_outcome']['append_timing'].update({k: v}))
        for mutate in mutations:
            value = diagnostic_failure(8)
            mutate(value['publish_observation']['deposit_diagnostics']['failures'][0])
            with self.assertRaises(ValueError): M['validate_node_report'](value, 'publish', PROVISION, profile_version=8)
        for version in (4, 5, 6):
            value = diagnostic_failure(8)['publish_observation']['deposit_diagnostics']
            value['version'] = version
            for timing in (None, value['failures'][0]['agent_outcome']['append_timing']):
                value['failures'][0]['agent_outcome']['append_timing'] = timing
                with self.assertRaises(ValueError): M['validate_deposit_diagnostics'](value, version)

    def test_profile_seven_retains_original_failed_child_and_does_not_upgrade_history(self):
        value = diagnostic_failure(7)
        self.assertEqual(value['version'], 8)
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=7), value)
        for old in range(1, 7):
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=old)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            calls = []
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-RAW-STDERR'
            with patch.dict(G, run_child=child, PROFILE_VERSION=7):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '7'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_challenge_progress_is_finite_scoped_and_not_part_of_old_diagnostics(self):
        original = diagnostic_failure(7)['publish_observation']['deposit_diagnostics']
        buckets = ('under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
            '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s')
        for phase in ('selector_write_flush', 'grant_write_flush', 'challenge_read_verify'):
            for before in buckets:
                for within in buckets:
                    for deadline in ('none', 'operation', 'exchange'):
                        value = copy.deepcopy(original)
                        value['failures'][0]['agent_detail'].update(deadline_scope=deadline,
                            challenge=dict(phase=phase, before_challenge=before, in_challenge=within))
                        M['validate_deposit_diagnostics'](value, 6)
        nullable = copy.deepcopy(original); nullable['failures'][0]['agent_detail']['challenge'] = None
        M['validate_deposit_diagnostics'](nullable, 6)
        for old in range(1, 6):
            value = copy.deepcopy(nullable); value['version'] = old
            with self.assertRaises(ValueError): M['validate_deposit_diagnostics'](value, old)
        mutations = [
            lambda f: f['agent_detail'].pop('challenge'),
            lambda f: f['agent_detail']['challenge'].update(raw='PRIVATE'),
            *(lambda f, k=k: f['agent_detail']['challenge'].pop(k)
                for k in ('phase', 'before_challenge', 'in_challenge')),
            *(lambda f, k=k, v=v: f['agent_detail']['challenge'].update({k: v})
                for k in ('phase', 'before_challenge', 'in_challenge') for v in (None, 0, True, {}, [], 'PRIVATE', 'unobserved')),
            *(lambda f, v=v: f['agent_detail'].update(stage=v)
                for v in ('stream_open', 'tls_handshake', 'route_connect')),
            lambda f: f['agent_detail'].update(tls_failure='io'),
            lambda f: f['agent_detail'].update(stream_failure='flow_acquire'),
            *(lambda f, v=v: f.update(agent_code=v) for v in ('CONTENT_INVALID', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown')),
            lambda f: f.update(stage='wire_receipt'), lambda f: f.update(category='io', agent_code=None),
        ]
        for mutate in mutations:
            value = copy.deepcopy(original); mutate(value['failures'][0])
            with self.assertRaises(ValueError): M['validate_deposit_diagnostics'](value, 6)

    def test_profile_six_keeps_exact_failed_child_and_rejects_older_profile_binding(self):
        value = diagnostic_failure(6)
        self.assertEqual(value['version'], 7)
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=6), value)
        for old in (1, 2, 3, 4, 5):
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=old)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            calls = []
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-RAW-STDERR'
            with patch.dict(G, run_child=child, PROFILE_VERSION=6):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '6'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_profile_six_stream_matrix_is_closed_and_old_details_are_not_widened(self):
        original = diagnostic_failure(6)
        def failure(value):
            return value['publish_observation']['deposit_diagnostics']['failures'][0]
        for name in (None, 'policy', 'route_state', 'route_material', 'flow_acquire',
                'transport_certificate', 'transport_tls', 'initial_paths', 'open_tcp_write',
                'subflow_readiness', 'stream_attachment'):
            value = copy.deepcopy(original); failure(value)['agent_detail']['stream_failure'] = name
            self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=6), value)
        mutations = [
            *(lambda f, k=k: f['agent_detail'].pop(k) for k in ('stage', 'deadline_scope', 'tls_failure', 'stream_failure')),
            *(lambda f, v=v: f['agent_detail'].update(stream_failure=v) for v in ('PRIVATE', 'unknown', '', 1, False, {}, [])),
            *(lambda f, v=v: f['agent_detail'].update(deadline_scope=v) for v in ('operation', 'exchange')),
            *(lambda f, v=v: f['agent_detail'].update(stage=v) for v in ('route_connect', 'provider_lookup', 'tls_handshake', 'challenge')),
            *(lambda f, v=v: f.update(agent_code=v) for v in ('CONTENT_INVALID', 'CONTENT_POLICY', 'CONTENT_BUSY', 'unknown')),
            lambda f: f.update(stage='wire_receipt'), lambda f: f.update(category='io', agent_code=None),
            lambda f: f['agent_detail'].update(tls_failure='io'), lambda f: f['agent_detail'].update(raw='PRIVATE'),
            lambda f: f.pop('agent_outcome'), lambda f: f.update(agent_outcome=dict(status='missing', detail=None)),
        ]
        for mutate in mutations:
            value = copy.deepcopy(original); mutate(failure(value))
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=6)
        for version in (2, 3, 4):
            value = copy.deepcopy(original['publish_observation']['deposit_diagnostics'])
            value['version'] = version
            value['failures'][0]['agent_detail']['stream_failure'] = None
            if version < 4: value['failures'][0].pop('agent_outcome')
            with self.assertRaises(ValueError): M['validate_deposit_diagnostics'](value, version)

    def test_profile_five_keeps_exact_failed_child_receipt_and_does_not_upgrade_older_profiles(self):
        value = diagnostic_failure(5)
        self.assertEqual(value['version'], 6)
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=5), value)
        for old in (1, 2, 3, 4):
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=old)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            calls = []
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-RAW-STDERR'
            with patch.dict(G, run_child=child, PROFILE_VERSION=5):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '5'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_profile_five_outcome_matrix_requires_real_timeout_and_post_ready_scope(self):
        phases = M['OUTCOME_PHASES']
        for index, phase in enumerate(phases):
            for category in ('io', 'auth', 'invalid', 'busy', 'store', 'expired', 'entropy', 'timeout', 'policy', 'unavailable', 'cancelled'):
                for scope in ('none', 'operation', 'exchange', 'bridge', 'remote_wire'):
                    value = diagnostic_failure(5)
                    outcome = value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_outcome']
                    outcome['detail'] = dict(phase=phase, category=category, deadline_scope=scope)
                    allowed = ((category == 'timeout') == (scope != 'none')) and (
                        scope != 'bridge' or 1 <= index <= 14) and (scope != 'remote_wire' or 6 <= index <= 12)
                    if allowed:
                        M['validate_node_report'](value, 'publish', PROVISION, profile_version=5)
                    else:
                        with self.assertRaises(ValueError):
                            M['validate_node_report'](value, 'publish', PROVISION, profile_version=5)

    def test_profile_five_required_nullable_outcome_and_closed_status_fields(self):
        for status in ('observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout'):
            for detail in (None, dict(phase='remote_receipt_read', category='io', deadline_scope='none')):
                value = diagnostic_failure(5)
                failure = value['publish_observation']['deposit_diagnostics']['failures'][0]
                failure['agent_outcome'] = dict(status=status, detail=detail)
                if (status == 'observed') == (detail is not None):
                    M['validate_node_report'](value, 'publish', PROVISION, profile_version=5)
                else:
                    with self.assertRaises(ValueError):
                        M['validate_node_report'](value, 'publish', PROVISION, profile_version=5)
        mutations = [lambda f: f.pop('agent_outcome'), lambda f: f['agent_outcome'].pop('detail'),
            lambda f: f['agent_outcome'].update(original_request_id='PRIVATE'),
            lambda f: f['agent_outcome']['detail'].update(raw_error='PRIVATE'),
            lambda f: f['agent_outcome']['detail'].update(phase='unobserved')]
        mutations += [lambda f, stage=stage: f.update(stage=stage)
            for stage in ('agent_ready', 'authorization', 'signed_request', 'accounting', 'unknown')]
        for mutate in mutations:
            value = diagnostic_failure(5)
            mutate(value['publish_observation']['deposit_diagnostics']['failures'][0])
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=5)
        value = diagnostic_failure(5)
        value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_outcome'] = None
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=5)

    def test_profile_four_retains_original_child_tls_failure_and_rejects_downgrades(self):
        value = diagnostic_failure(4)
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=4), value)
        for old in (1, 2, 3):
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=old)
        for old in (1, 2):
            diagnostic = copy.deepcopy(value['publish_observation']['deposit_diagnostics'])
            diagnostic['version'] = old
            with self.assertRaises(ValueError):
                M['validate_deposit_diagnostics'](diagnostic, old)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            calls = []
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-RAW-STDERR'
            with patch.dict(G, run_child=child, PROFILE_VERSION=4):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '4'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_profile_four_enforces_tls_matrix_and_required_nullable_field(self):
        for tls in ('offer', 'configuration', 'handshake_deadline', 'authentication', 'tls_other', 'io'):
            for stage in ('tls_handshake', 'stream_open', 'challenge', 'unobserved'):
                for scope in ('none', 'operation', 'exchange'):
                    for code in ('CONTENT_UNAVAILABLE', 'CONTENT_INVALID', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown'):
                        value = diagnostic_failure(4)
                        failure = value['publish_observation']['deposit_diagnostics']['failures'][0]
                        failure.update(agent_code=code, agent_detail=dict(stage=stage, deadline_scope=scope, tls_failure=tls))
                        if stage == 'tls_handshake' and scope == 'none' and code == 'CONTENT_UNAVAILABLE':
                            M['validate_node_report'](value, 'publish', PROVISION, profile_version=4)
                        else:
                            with self.assertRaises(ValueError):
                                M['validate_node_report'](value, 'publish', PROVISION, profile_version=4)
        for absent in (None, dict(stage='tls_handshake', deadline_scope='none', tls_failure=None)):
            value = diagnostic_failure(4)
            value['publish_observation']['deposit_diagnostics']['failures'][0]['agent_detail'] = absent
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=4)

    def test_profile_four_rejects_nonclosed_reserved_tls_and_keeps_missing_invalid_failures(self):
        mutations = [lambda f: f['agent_detail'].pop('tls_failure'), lambda f: f['agent_detail'].update(raw='PRIVATE'),
            lambda f: f.update(stage='agent_terminal'), lambda f: f.update(category='io', agent_code=None)]
        mutations += [lambda f, v=v: f['agent_detail'].update(tls_failure=v)
            for v in ('unobserved', 'PRIVATE', 0, 1, False, [], {})]
        for mutate in mutations:
            value = diagnostic_failure(4)
            mutate(value['publish_observation']['deposit_diagnostics']['failures'][0])
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=4)
        for state in ('missing', 'invalid'):
            value = diagnostic_failure(4)
            value['publish_observation'].update(status='complete', core_operation_complete=True,
                deposit_diagnostics_state=state, deposit_diagnostics=None)
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=4)

    def test_profile_three_binds_detail_version_exact_child_call_and_original_bytes(self):
        value = diagnostic_failure(3)
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=3), value)
        for profile, other in ((1, value), (2, value), (3, diagnostic_failure())):
            with self.assertRaises(ValueError):
                M['validate_node_report'](other, 'publish', PROVISION, profile_version=profile)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            calls = []
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-RAW-STDERR'
            with patch.dict(G, run_child=child, PROFILE_VERSION=3):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '3'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_profile_three_enforces_exact_detail_deadline_matrix(self):
        stages = ('unobserved', 'route_connect', 'control_selection', 'provider_lookup',
            'provider_cardinality', 'offer_validity', 'stream_open', 'tls_handshake', 'challenge')
        for stage in stages:
            for scope in ('none', 'operation', 'exchange'):
                value = diagnostic_failure(3)
                failure = value['publish_observation']['deposit_diagnostics']['failures'][0]
                failure['agent_detail'] = dict(stage=stage, deadline_scope=scope)
                allowed = (stage != 'unobserved' or scope == 'operation') and (
                    scope != 'exchange' or stage in ('stream_open', 'tls_handshake', 'challenge'))
                if allowed:
                    M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)
                else:
                    with self.assertRaises(ValueError):
                        M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)
        for code in ('CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY'):
            value = diagnostic_failure(3)
            failure = value['publish_observation']['deposit_diagnostics']['failures'][0]
            failure['agent_code'] = code
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)
            failure['agent_detail']['deadline_scope'] = 'operation'
            if code == 'CONTENT_UNAVAILABLE':
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)
            else:
                with self.assertRaises(ValueError):
                    M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)

    def test_profile_three_rejects_nonclosed_detail_and_preserves_null_and_missing_states(self):
        mutations = [lambda f: f.pop('agent_detail'), lambda f: f.update(agent_detail='/PRIVATE'),
            lambda f: f.update(agent_detail=[]), lambda f: f['agent_detail'].update(raw='PRIVATE'),
            lambda f: f['agent_detail'].update(stage='PRIVATE'),
            lambda f: f['agent_detail'].update(deadline_scope='PRIVATE'),
            lambda f: f['agent_detail'].pop('stage'), lambda f: f.update(stage='agent_terminal'),
            lambda f: f.update(category='io', agent_code=None), lambda f: f.update(agent_code='unknown')]
        for mutate in mutations:
            value = diagnostic_failure(3)
            mutate(value['publish_observation']['deposit_diagnostics']['failures'][0])
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)
        value = diagnostic_failure(3)
        diagnostic = value['publish_observation']['deposit_diagnostics']
        diagnostic['failures'][0].update(category='io', agent_code=None, agent_detail=None)
        diagnostic['failures'] = [dict(diagnostic['failures'][0], fragment_index=i // 2, copy_index=i % 2) for i in range(8)]
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)
        for state in ('missing', 'invalid'):
            value = diagnostic_failure(3)
            value['publish_observation'].update(status='complete', core_operation_complete=True,
                deposit_diagnostics_state=state, deposit_diagnostics=None)
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)
        for mutate in (lambda v: v.update(version=3), lambda v: v['publish_observation'].update(version=2),
                lambda v: v['publish_observation']['deposit_diagnostics'].update(version=1)):
            value = diagnostic_failure(3); mutate(value)
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=3)

    def test_current_deposit_failure_survives_exact_child_call_and_retained_bytes(self):
        value = diagnostic_failure()
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION, profile_version=2), value)
        with self.assertRaises(ValueError):
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=1)
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            def child(command, _):
                calls.append(command)
                return 1, raw, b'PRIVATE-NOT-EXPORTED'
            with patch.dict(G, run_child=child, PROFILE_VERSION=2):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(calls[0][-2:], ['--profile-version', '2'])
            self.assertEqual(caught.exception.report['node'], value)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))

    def test_current_diagnostic_rejects_unbounded_unknown_private_or_duplicate_records(self):
        mutations = [lambda d: d.update(version=True), lambda d: d.update(omitted_failures=1),
            lambda d: d.update(failures=d['failures'] * 9), lambda d: d.update(failures=d['failures'] * 2),
            lambda d: d.update(raw='PRIVATE'), lambda d: d['failures'][0].update(raw='PRIVATE'),
            lambda d: d['failures'][0].update(fragment_index=4), lambda d: d['failures'][0].update(copy_index=2),
            lambda d: d['failures'][0].update(fragment_index=True), lambda d: d['failures'][0].update(operation='PRIVATE'),
            lambda d: d['failures'][0].update(stage='PRIVATE'), lambda d: d['failures'][0].update(category='PRIVATE'),
            lambda d: d['failures'][0].update(agent_code='CONTENT_POLICY'),
            lambda d: d['failures'][0].update(category='agent_rejected'),
            lambda d: d['failures'][0].update(category='agent_rejected', agent_code='PRIVATE')]
        for mutate in mutations:
            value = diagnostic_failure()
            mutate(value['publish_observation']['deposit_diagnostics'])
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=2)
        value = diagnostic_failure()
        d = value['publish_observation']['deposit_diagnostics']
        d['failures'] = [dict(d['failures'][0], fragment_index=i // 2, copy_index=i % 2) for i in range(8)]
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=2)
        d['failures'][0].update(category='agent_rejected', agent_code='unknown')
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=2)

    def test_diagnostic_failure_versions_and_missing_invalid_states_do_not_downgrade(self):
        for state in ('missing', 'invalid'):
            value = diagnostic_failure()
            value['publish_observation'].update(status='complete', code='ok', core_operation_complete=True,
                deposit_diagnostics_state=state, deposit_diagnostics=None)
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=2)
            value['publish_observation']['deposit_diagnostics'] = {'private': 'NO'}
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=2)
        for mutate in (lambda v: v.update(version=2), lambda v: v.update(version=True),
                lambda v: v['publish_observation'].update(version=1),
                lambda v: v['publish_observation'].update(deposit_diagnostics_state='not_applicable'),
                lambda v: v['publish_observation'].update(core_operation_complete=True),
                lambda v: v['publish_observation'].update(core_operation_complete=1)):
            value = diagnostic_failure()
            mutate(value)
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, profile_version=2)
        value = diagnostic_failure()
        value['version'] = 2
        observed = value['publish_observation']
        observed['version'] = 1
        del observed['deposit_diagnostics_state'], observed['deposit_diagnostics']
        M['validate_node_report'](value, 'publish', PROVISION, profile_version=1)
        with self.assertRaises(ValueError):
            M['validate_node_report'](value, 'publish', PROVISION, profile_version=2)

    def test_exact_phase_geometry_and_original_ciphertext_accounting(self):
        M['validate_node_report'](prepared(), 'prepare', PROVISION)
        for phase in ('publish', 'exercise', 'finish'):
            with self.subTest(phase=phase):
                value = report(phase)
                self.assertEqual(M['validate_node_report'](value, phase, PROVISION, prepared()), value)
        self.assertEqual(M['FLOW_MINIMUM'], dict(publish=56, exercise=16, finish=22))
        for size in (16, 17, 800001, M['MAX_CIPHER']):
            fragment, lengths, charge_a = M['geometry'](size)
            self.assertEqual(sum(lengths), size)
            self.assertEqual(max(lengths), fragment)
            self.assertEqual(charge_a, lengths[0] + lengths[2] + lengths[3])
        for bad in (True, 0, 15, M['MAX_CIPHER'] + 1):
            with self.assertRaises(ValueError):
                M['geometry'](bad)

    def test_closed_reports_reject_extra_fields_wrong_source_and_claim_scope(self):
        cases = [lambda v: v.update(raw_path='/private'),
            lambda v: v.update(version=True), lambda v: v.update(provision_sha256='b' * 64),
            lambda v: v['scope'].update(immich_running_proven=True),
            lambda v: v['image'].update(owner_key='secret'),
            lambda v: v['image'].update(cipher_sha256='0' * 64),
            lambda v: v['cloud'].update(maintenance_started=True)]
        for mutate in cases:
            value = report('publish')
            mutate(value)
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'publish', PROVISION, prepared())

    def test_exercise_requires_real_full_read_auth_charge_and_measured_lifecycle(self):
        for name, field, changed in [('image', 'plaintext_sha256', '0' * 64),
            ('image', 'application_decryption_verified', False), ('cloud', 'wrong_token_status', 200),
            ('cloud', 'authenticated_get_body_verified', False), ('image', 'cursor_after', 3),
            ('cloud', 'confirmed_copy_retentions_advanced', 0), ('image', 'uncertain_payload_bytes', 0),
            ('cloud', 'exact_join_before_spawn_measured', True), ('image', 'completed_turn_observed', True),
            ('cloud', 'owner_joined', False), ('cloud', 'plaintext_bytes', True)]:
            with self.subTest(field=field):
                value = report('exercise')
                value[name][field] = changed
                with self.assertRaises(ValueError):
                    M['validate_node_report'](value, 'exercise', PROVISION, prepared())

    def test_delete_zero_charge_is_not_private_or_remote_cleanup_proof(self):
        value = report('finish')
        for field, changed in [('physical_payload_charge_upper_bound', 1), ('retained_copy_records', 8),
            ('all_retained_copies_delete_acknowledged', False), ('provider_usage_independently_checked', True),
            ('private_fixture_removed', True)]:
            current = copy.deepcopy(value)
            current['image'][field] = changed
            with self.assertRaises(ValueError):
                M['validate_node_report'](current, 'finish', PROVISION, prepared())

    def test_original_closed_node_failure_survives_without_private_stderr(self):
        value = dict(version=1, kind='storage-consumer-maintenance', phase='exercise', passed=False,
            provision_sha256=PROVISION, stage='image_decrypt', code='image_decrypt', cleanup_confirmed=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-exercise.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            with patch.dict(G, run_child=lambda *_: (1, raw, b'PRIVATE-DO-NOT-EXPORT')):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'exercise', PROVISION, time.monotonic() + 1)
            retained = caught.exception.report
            self.assertFalse(retained['passed'])
            self.assertEqual(retained['node'], value)
            self.assertEqual(retained['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(retained))
            value['unexpected'] = 'secret'
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'exercise', PROVISION, prepared())

    def test_generic_failure_is_closed_and_does_not_repeat_arguments(self):
        value = M['failure_report'](['exercise', '/private/key'])
        self.assertEqual(set(value), {'version', 'kind', 'phase', 'passed', 'code', 'cleanup_confirmed'})
        self.assertEqual(value['phase'], 'exercise')
        self.assertNotIn('/private', json.dumps(value))
        self.assertEqual(M['failure_report'](['/private/key'])['phase'], 'invalid')

    def test_closed_publish_observation_preserves_operation_without_exporting_raw_result(self):
        value = dict(version=2, kind='storage-consumer-maintenance', phase='publish', passed=False,
            provision_sha256=PROVISION, stage='cloud_publish', code='publish_operation', cleanup_confirmed=False,
            publish_observation=dict(version=1, app='cloud', operation='deposit', status='incomplete',
                code='retained_operation_incomplete', local_process_joined=True,
                core_report_present=True, core_operation_complete=False))
        self.assertEqual(M['validate_node_report'](value, 'publish', PROVISION), value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = (json.dumps(value) + '\n').encode()
            write(root / 'storage-consumer-publish.json', raw)
            write(root / 'storage-consumer-prepare.json', json.dumps(prepared()).encode())
            with patch.dict(G, run_child=lambda *_: (1, raw, b'PRIVATE-DO-NOT-EXPORT')):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'publish', PROVISION, time.monotonic() + 1)
            self.assertEqual(caught.exception.report['node'], value)
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))
        cases = [lambda v: v.update(version=1), lambda v: v.update(stage='image_publish'),
            lambda v: v.update(phase='exercise'), lambda v: v.update(code='application_failed'),
            lambda v: v['publish_observation'].update(app='private-path'),
            lambda v: v['publish_observation'].update(operation='restore'),
            lambda v: v['publish_observation'].update(status='PRIVATE'),
            lambda v: v['publish_observation'].update(code='PRIVATE'),
            lambda v: v['publish_observation'].update(local_process_joined=1),
            lambda v: v['publish_observation'].update(core_report_present=1),
            lambda v: v['publish_observation'].update(core_operation_complete=1),
            lambda v: v['publish_observation'].update(core_report_present=False),
            lambda v: v['publish_observation'].update(status='complete'),
            lambda v: v['publish_observation'].update(raw_storage={'path': 'PRIVATE'}),
            lambda v: v['publish_observation'].update(version=True)]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(value)
                mutate(changed)
                with self.assertRaises(ValueError):
                    M['validate_node_report'](changed, changed['phase'], PROVISION)
        changed = copy.deepcopy(value)
        changed['code'] = 'phase_deadline'
        changed['publish_observation'].update(status='cancelled', code='cancelled',
            core_report_present=False, core_operation_complete=None)
        M['validate_node_report'](changed, 'publish', PROVISION)


class ConsumerBoundaries(unittest.TestCase):
    def test_private_reader_enforces_real_size_mode_links_and_no_follow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, path = Path(temporary), Path(temporary) / 'owned'
            write(path, b'abcd')
            self.assertEqual(M['file_bytes'](path, 4), b'abcd')
            with self.assertRaises(ValueError):
                M['file_bytes'](path, 3)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                M['file_bytes'](path, 4)
            path.chmod(0o600)
            (root / 'link').symlink_to(path)
            with self.assertRaises(OSError):
                M['file_bytes'](root / 'link', 4)
            os.link(path, root / 'hardlink')
            with self.assertRaises(ValueError):
                M['file_bytes'](path, 4)

    def test_owned_child_drains_full_buffer_and_eof_after_normal_exit(self):
        status, output, errors = M['run_child']([sys.executable, '-I', '-B', '-c',
            'import os; os.write(1,b"a"*12000); os.write(2,b"b"*6000)'], time.monotonic() + 5)
        self.assertEqual((status, len(output), len(errors)), (0, 12000, 6000))

    def test_owned_child_failure_is_retained_not_relabelled_success(self):
        status, output, errors = M['run_child']([sys.executable, '-I', '-B', '-c',
            'import os; os.write(1,b"{}"); os.write(2,b"inert failure"); raise SystemExit(1)'], time.monotonic() + 5)
        self.assertEqual((status, output, errors), (1, b'{}', b'inert failure'))

    def test_selector_constructor_failure_still_terminates_and_joins_owned_child(self):
        children, spawn = [], subprocess.Popen

        def started(*args, **kwargs):
            child = spawn(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(subprocess, 'Popen', side_effect=started), \
                patch.object(G['selectors'], 'DefaultSelector', side_effect=OSError('inert EMFILE')):
            with self.assertRaisesRegex(OSError, 'EMFILE'):
                M['run_child']([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)'], time.monotonic() + 5)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)
        with self.assertRaises(ProcessLookupError):
            os.killpg(children[0].pid, 0)

    def test_owned_child_oversize_and_deadline_abort_are_failures(self):
        for code, deadline, limit, reason in [
            ('import os,time; os.write(1,b"x"*4096); time.sleep(10)', 5, 128, 'output_bound'),
            ('import time; time.sleep(10)', .15, 128, 'deadline')]:
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, reason):
                M['run_child']([sys.executable, '-I', '-B', '-c', code], started + deadline, limit=limit)
            self.assertLess(time.monotonic() - started, 3)

    def test_no_fixture_cleanup_while_real_owned_child_names_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'm'
            root.mkdir(mode=0o700)
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)', str(root)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                with self.assertRaisesRegex(ValueError, 'fixture_process_active'):
                    M['no_fixture_processes'](root)
                self.assertTrue(root.is_dir())
            finally:
                child.terminate()
                child.wait(timeout=5)
            M['no_fixture_processes'](root)

    def test_cleanup_removes_only_exact_private_tree_and_stays_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'm'
            root.mkdir(mode=0o700)
            (root / 'image').mkdir(mode=0o700)
            (root / 'image/bundle').mkdir(mode=0o700)
            (root / 'cloud').mkdir(mode=0o700)
            write(root / 'image/bundle/recovery.key')
            write(root / 'consumer-binding.json')
            result = M['cleanup'](root)
            self.assertEqual(result['removed_files'], 2)
            self.assertEqual(result['removed_directories'], 4)
            self.assertFalse(result['remote_cleanup_confirmed'])
            self.assertFalse(result['provider_usage_proven'])
            self.assertEqual(M['cleanup'](root)['removed_files'], 0)

    def test_cleanup_rejects_unknown_top_level_or_symlink_before_removing_any_file(self):
        for bad in ('unknown', 'symlink'):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'm'
                root.mkdir(mode=0o700)
                write(root / 'consumer-binding.json')
                if bad == 'unknown':
                    write(root / 'unadmitted.txt')
                else:
                    (root / 'image').mkdir(mode=0o700)
                    (root / 'image/link').symlink_to(root / 'consumer-binding.json')
                with self.assertRaises(ValueError):
                    M['cleanup_tree'](root)
                self.assertTrue((root / 'consumer-binding.json').exists())

    def test_guard_denies_host_before_provisioning_or_spawn(self):
        with patch.object(G['socket'], 'gethostname', return_value='developer-host'), \
                patch.dict(G, tools=lambda: self.fail('tools should not run')):
            with self.assertRaisesRegex(ValueError, 'guest_only'):
                M['main'](['prepare', '/private'])


class ConsumerOrchestration(unittest.TestCase):
    def test_actual_staged_import_and_pin_closure_without_download_or_execution(self):
        # The guest stages individual files, not this whole checkout. Exercise
        # the actual runpy/load_pins closure in that same sparse arrangement.
        names = ('storage-consumer-maintenance-smoke.py', 'storage-consumer-maintenance-provision.py',
            'storage-consumer-maintenance-pins.json', 'storage-consumer-maintenance-pins-v2.json',
            'storage-consumer-maintenance-pins-v3.json', 'storage-consumer-maintenance-pins-v4.json',
            'storage-consumer-maintenance-pins-v5.json', 'storage-consumer-maintenance-pins-v6.json',
            'storage-consumer-maintenance-pins-v7.json', 'storage-consumer-maintenance-pins-v8.json',
            'storage-consumer-maintenance-pins-v9.json', 'image-snapshot-provision.py',
            'agent-private-task-code.py', 'agent-private-task-code-pins.json',
            'private-storage-fragments-smoke.py', 'private-storage-replicas-smoke.py',
            'private-storage-peer-smoke.py', 'content-provider-https-smoke.py',
            'content-network-smoke.py', 'private-storage-log-sampler.py', 'storage-provider-activity-sampler.py',
            'storage-fixture-correlation-sampler.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in names:
                (root / name).write_bytes((HERE / name).read_bytes())
            with patch.object(subprocess, 'Popen') as spawn, patch.object(os, 'execve') as execute, \
                    patch.object(urllib.request, 'urlopen') as download:
                loaded = runpy.run_path(str(root / names[0]))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](), M['PROVISIONER']['load_pins']())
                self.assertEqual(loaded['PROVISIONER']['load_pins'](2), M['PROVISIONER']['load_pins'](2))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](3), M['PROVISIONER']['load_pins'](3))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](4), M['PROVISIONER']['load_pins'](4))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](5), M['PROVISIONER']['load_pins'](5))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](6), M['PROVISIONER']['load_pins'](6))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](7), M['PROVISIONER']['load_pins'](7))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](8), M['PROVISIONER']['load_pins'](8))
                self.assertEqual(loaded['PROVISIONER']['load_pins'](9), M['PROVISIONER']['load_pins'](9))
                self.assertEqual(loaded['FLOW_MINIMUM'], M['FLOW_MINIMUM'])
                for absent in ('image-snapshot-provision.py', 'agent-private-task-code.py', 'agent-private-task-code-pins.json'):
                    (root / absent).unlink()
                    with self.assertRaises(FileNotFoundError):
                        check = runpy.run_path(str(root / names[0]))
                        check['PROVISIONER']['load_pins']()
                    (root / absent).write_bytes((HERE / absent).read_bytes())
                spawn.assert_not_called()
                execute.assert_not_called()
                download.assert_not_called()

    def test_profile_selection_is_explicit_and_reset_between_independent_cli_calls(self):
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            for profile in (2, 3, 4, 5, 6, 7, 8, 9, 10):
                M['main'](['flow-minimum', 'publish', '--profile-version', str(profile)])
                self.assertEqual(G['PROFILE_VERSION'], profile)
            M['main'](['flow-minimum', 'publish'])
            self.assertEqual(G['PROFILE_VERSION'], 1)
        with self.assertRaises(ValueError):
            M['main'](['flow-minimum', 'publish', '--profile-version', '11'])

    def test_preparation_creates_only_original_finite_authority_from_exact_cipher_size(self):
        self.assert_preparation(1)

    def test_preparation_enables_append_diagnostics_only_in_explicit_profile_eight(self):
        self.assert_preparation(8)
        self.assert_preparation(7)

    def test_preparation_enables_only_flow_opt_in_for_explicit_profile_nine(self):
        self.assert_preparation(9)

    def test_preparation_enables_only_close_opt_in_for_explicit_profile_ten(self):
        self.assert_preparation(10)

    def assert_preparation(self, profile):
        original, calls, owners = prepared(), [], iter(('4' * 64, '5' * 64))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def node(*_):
                for name in ('image', 'cloud'):
                    (root / name).mkdir(mode=0o700)
                return original, 'b' * 64

            def core(binary, control, arguments, deadline, raw=False):
                calls.append([str(v) for v in arguments])
                if arguments[0] == 'init':
                    return None
                if arguments[:2] == ['content', 'recipient-key']:
                    return dict(identity_public_key_hex=next(owners))
                self.assertEqual(arguments[:3], ['storage', 'peer', 'grant'])
                selected = dict(zip(arguments[3::2], arguments[4::2]))
                self.assertEqual(selected['--max-leases'], 4)
                self.assertEqual(selected['--max-retention-seconds'], 7200)
                self.assertEqual(selected['--lifetime-seconds'], 7200)
                write(Path(selected['--output']), b'inert signed grant fixture')
                return dict(operation='private_storage_peer_grant', grant_written=True,
                    max_payload_bytes=selected['--max-payload-bytes'], max_leases=4,
                    expires_unix_seconds=int(time.time()) + 7200, reserved_bytes=0, network_contribution_credit=False)

            with patch.dict(G, PROFILE_VERSION=profile, node_phase=node, core=core,
                    validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client'))):
                result = M['prepare'](root, '/fixed/core', '/fixed/client', ['a', 'b', 'c'],
                    [str(i) * 64 for i in (1, 2, 3)], PROVISION, time.monotonic() + 5)
            self.assertEqual(len(calls), 10)
            self.assertFalse(result['protected_flow_proven'])
            for name in ('image', 'cloud'):
                size = original[name]['cipher_bytes']
                config = M['private_json'](root / name / 'storage.json')
                if profile == 8:
                    self.assertIs(config.pop('appendDiagnosticsV7'), True)
                else:
                    self.assertNotIn('appendDiagnosticsV7', config)
                if profile == 9:
                    self.assertIs(config.pop('flowAcquireDiagnosticsV8'), True)
                else:
                    self.assertNotIn('flowAcquireDiagnosticsV8', config)
                if profile == 10:
                    self.assertIs(config.pop('tlsCloseDiagnosticsV9'), True)
                else:
                    self.assertNotIn('tlsCloseDiagnosticsV9', config)
                policy = M['private_json'](root / name / 'maintenance-policy.json')
                self.assertEqual(config['fragmentBytes'], (size + 3) // 4)
                self.assertEqual((config['lifetimeSeconds'], config['deadlineMs']), (1800, 1800000))
                self.assertEqual((policy['authorizationSeconds'], policy['lifetimeSeconds'], policy['renewBeforeSeconds']),
                    (6000, 3600, 7200))
                self.assertEqual(policy['maximumChargedBytes'], size * 3)
                self.assertEqual(policy['maximumTurnBytes'], 8388608)
                self.assertNotIn(policy['fromProviderKey'], [p['key'] for p in policy['providers']])
                self.assertFalse(result['authority'][name]['enrollment_created'])

    def test_phase_requires_initial_continuous_final_sampler_and_exports_exact_name(self):
        events, writes = [], []
        value = report('exercise')
        class Coverage:
            joined = True
            def report(self, *, joined):
                self.assert_joined = joined
                return dict(exit_log_sampling_version=2)
        coverage = Coverage()

        @contextmanager
        def capture(*args, **kwargs):
            self.assertEqual(args[3], 16)
            self.assertEqual(kwargs['scope']['exit_peer_id'], 'exit')
            events.append('initial')
            yield coverage
            events.append('final_join')

        def node(*_):
            events.append('node')
            return value, 'b' * 64

        root = Path('/opt/va.' + 'a' * 32 + '.abcdef/u/m')
        work = root.parents[1]
        scope = dict(exit_peer_id='exit', paths=[dict(path_id=1, relay_peer_id='a'), dict(path_id=2, relay_peer_id='b')])
        fake_sampler = dict(M['SAMPLER'], capture=capture,
            validate_summary=lambda *_: events.append('validate'))
        with patch.dict(os.environ, STORAGE_PROOF_BASELINE_MS='1', STORAGE_PROOF_ROUTE_SCOPE=json.dumps(scope)), \
                patch.dict(G, private_json=lambda *_: dict(coreBinary='/fixed/core', controlSocket='/fixed/client'),
                    validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client')), private_directory=lambda *_: None,
                    node_phase=node, SAMPLER=fake_sampler, write_json=lambda path, value: writes.append((path, value))):
            result = M['phase'](root, 'exercise', work / 'runtime-exit/control/agent.sock',
                work / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 1)
        self.assertEqual(events, ['initial', 'node', 'final_join', 'validate'])
        self.assertEqual(writes[0][0].name, 'flow-consumer-exercise.json')
        self.assertTrue(result['protected_flow_proven'])
        self.assertFalse(result['remote_cleanup_independently_proven'])

    def test_flow_minimum_cli_requires_no_guest_mutation(self):
        for phase, minimum in M['FLOW_MINIMUM'].items():
            run = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-maintenance-smoke.py'),
                'flow-minimum', phase], capture_output=True, timeout=5, check=True)
            self.assertEqual(run.stdout, f'{minimum}\n'.encode())
            self.assertEqual(run.stderr, b'')

    def phase_activity_failure(self, profile, network):
        events = []
        root = Path('/opt/va.' + 'a' * 32 + '.abcdef/u/m')
        work = root.parents[1]
        original_error = ValueError('original_node_failure')
        @contextmanager
        def activity(binary, selected_work, selected_root, phase):
            self.assertEqual(binary, Path('/fixed/core'))
            self.assertEqual((selected_work, selected_root, phase), (work, root, 'publish'))
            events.append('activity_start')
            try: yield
            finally: events.append('activity_join')
        @contextmanager
        def flow(*args, **kwargs):
            self.assertEqual(args[3], 56)
            events.append('flow_start')
            try: yield None
            finally: events.append('flow_join')
        def node(*_):
            events.append('node')
            raise original_error
        real_runpy = runpy.run_path
        def load(path):
            module = real_runpy(path)
            if str(path).endswith('storage-consumer-route-sampler.py'):
                module.update(capture=flow, validate_policy=lambda *_: None)
            return module
        with patch.dict(os.environ, STORAGE_PROOF_BASELINE_MS='1', STORAGE_PROOF_ROUTE_POLICY='{}',
                STORAGE_PROOF_ROUTE_SCOPE='{}', STORAGE_PROOF_UNDERLAY_SHA256='a' * 64), \
                patch.object(G['runpy'], 'run_path', load), \
                patch.dict(G, PROFILE_VERSION=profile, NETWORK_VERSION=network,
                    ACTIVITY=dict(M['ACTIVITY'], capture=activity),
                    SAMPLER=dict(M['SAMPLER'], capture=flow, validate_route_scope=lambda *_: None),
                    private_json=lambda *_: dict(coreBinary='/fixed/core', controlSocket='/fixed/client'),
                    validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client')),
                    private_directory=lambda *_: None, node_phase=node):
            with self.assertRaises(ValueError) as caught:
                M['phase'](root, 'publish', work / 'runtime-exit/control/agent.sock',
                    work / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 1)
            self.assertIs(caught.exception, original_error)
        return events

    def test_current_phase_joins_activity_after_flow_cleanup_without_replacing_owner_failure(self):
        for profile in (7, 8, 9):
            with self.subTest(profile=profile):
                self.assertEqual(self.phase_activity_failure(profile, 2),
                    ['activity_start', 'flow_start', 'node', 'flow_join', 'activity_join'])

    def test_activity_remains_absent_outside_explicit_profiles_and_network(self):
        for profile in range(10):
            for network in (1, 2):
                if profile in (7, 8, 9) and network == 2:
                    continue
                with self.subTest(profile=profile, network=network):
                    self.assertEqual(self.phase_activity_failure(profile, network),
                        ['flow_start', 'node', 'flow_join'])

    def test_network_two_actual_sampler_and_original_node_failure_keep_separate_boundaries(self):
        # Real new sampler; only its core RPC replies and the Node phase are
        # synthetic. No runtime, socket or provider is used by this component test.
        fixtures = runpy.run_path(str(HERE / 'test-storage-consumer-route-sampler.py'))
        root = Path('/opt/va.' + 'a' * 32 + '.abcdef/u/m')
        work, writes = root.parents[1], []
        context = 'a' * 32
        initial = fixtures['snapshot'](context, 0, fixtures['OLD']['event'](9))
        final = fixtures['snapshot'](context, 0, fixtures['OLD']['event'](9) + b''.join(
            fixtures['OLD']['event'](11 + i, context=context) for i in range(16)))
        env = dict(STORAGE_PROOF_BASELINE_MS='10', STORAGE_PROOF_ROUTE_POLICY=json.dumps(fixtures['POLICY']),
            STORAGE_PROOF_UNDERLAY_SHA256='d' * 64)
        from types import SimpleNamespace
        replies = [SimpleNamespace(stdout=raw) for raw in initial + final]
        with patch.dict(os.environ, env), patch.dict(G, NETWORK_VERSION=2,
                private_json=lambda *_: dict(coreBinary='/fixed/core', controlSocket='/fixed/client'),
                validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client')),
                private_directory=lambda *_: None, node_phase=lambda *_: (report('exercise'), 'b' * 64),
                write_json=lambda path, value: writes.append((path, value))), \
                patch.object(subprocess, 'run', side_effect=replies) as query:
            result = M['phase'](root, 'exercise', work / 'runtime-exit/control/agent.sock',
                work / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 1)
        self.assertEqual(query.call_count, 8)
        self.assertEqual((result['version'], result['network_version'], result['control_underlay_sha256']), (2, 2, 'd' * 64))
        self.assertEqual(writes[0][1]['exit_log_sampling_version'], 3)
        self.assertTrue(writes[0][1]['exit_log_sampler_joined'])
        original = M['NodePhaseFailure'](diagnostic_failure(3), 'b' * 64, PROVISION)
        for owner_failure in (False, True):
            writes.clear()
            error = subprocess.CalledProcessError(1, ['PRIVATE'])
            replies = [SimpleNamespace(stdout=raw) for raw in initial] + [error] if owner_failure else [error]
            def node(*_): raise original
            with patch.dict(os.environ, env), patch.dict(G, NETWORK_VERSION=2,
                    private_json=lambda *_: dict(coreBinary='/fixed/core', controlSocket='/fixed/client'),
                    validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client')),
                    private_directory=lambda *_: None, node_phase=node,
                    write_json=lambda *args: writes.append(args)), \
                    patch.object(subprocess, 'run', side_effect=replies):
                expected = M['NodePhaseFailure'] if owner_failure else M['NetworkPhaseFailure']
                with self.assertRaises(expected) as caught:
                    M['phase'](root, 'exercise', work / 'runtime-exit/control/agent.sock',
                        work / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 1)
            if owner_failure: self.assertIs(caught.exception, original)
            else:
                self.assertEqual(caught.exception.report['sampler']['operation'], 'paths_before')
                self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))
            self.assertEqual(writes, [])


if __name__ == '__main__':
    unittest.main()
