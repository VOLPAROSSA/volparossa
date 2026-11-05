#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure maintenance receipt/cleanup contracts, not a running-core or peer proof."""
from pathlib import Path
from contextlib import contextmanager
import copy
import json
import os
import re
import runpy
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
OLD = runpy.run_path(str(HERE / 'test-private-storage-fragments-smoke.py'))
CONSUMER_FIXTURE = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))


class ProviderEventDiagnostic(unittest.TestCase):
    CODE = 'CONTENT_DISCOVERY_RESPONSE_TARGETS_UNAVAILABLE'

    def test_every_allowlisted_event_exists_in_the_selected_product_source(self):
        source = '\n'.join((HERE.parents[1] / path).read_text() for path in (
            'crates/volparossa-agent/src/content.rs', 'crates/volparossa-agent/src/discovery/content.rs',
            'crates/volparossa-agent/src/discovery/content/exact.rs'))
        self.assertEqual(len(CHECK['PROVIDER_EVENT_CODES']), len(set(CHECK['PROVIDER_EVENT_CODES'])))
        for code in CHECK['PROVIDER_EVENT_CODES']:
            self.assertIn(f'"{code}"', source)

    @staticmethod
    def save(path, raw):
        path.write_text(raw); path.chmod(0o600)

    @classmethod
    def event(cls, stamp=101, code=None):
        return f'{stamp}\tlevel=1\tevent={code or cls.CODE}\tsession={"deadbeef" * 8}\tpath=7\n'

    def observed(self, root, raw=None, status='0\n'):
        self.save(root / 'logs-client-cleanup-status.private', status)
        self.save(root / 'logs-client.txt', self.event() if raw is None else raw)
        return CHECK['provider_events'](root, 'storage-consumer-publish', '100')

    def test_exact_roles_allowlist_and_no_raw_identifiers_or_unknown_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for node in CHECK['PROVIDER_EVENT_ROLES'].values():
                self.save(root / f'logs-{node}-cleanup-status.private', '0\n')
                self.save(root / f'logs-{node}.txt', self.event(99) + self.event()
                    + self.event(102, 'CONTENT_DISCOVERY_PRIVATE_SENTINEL') + self.event(103, 'UNRELATED'))
            value = CHECK['provider_events'](root, 'storage-consumer-publish', '100')
            CHECK['validate_provider_events'](value)
            self.assertEqual(set(value['roles']), set(CHECK['PROVIDER_EVENT_ROLES']))
            for row in value['roles'].values():
                self.assertEqual((row['records'], row['stale_records'], row['fresh_records']), (4, 1, 3))
                self.assertEqual(row['counts'][self.CODE], 1)
                self.assertEqual(row['unrecognized_event_records'], 1)
                self.assertTrue(row['window_covers_baseline'])
            encoded = json.dumps(value)
            for private in ('deadbeef', 'PRIVATE_SENTINEL', 'UNRELATED', str(root), 'session=', 'path='):
                self.assertNotIn(private, encoded)
            self.assertFalse(value['event_absence_proven'])
            self.assertFalse(value['causal_attribution'])

    def test_capture_status_is_required_and_failure_never_becomes_empty_ring(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.save(root / 'logs-client.txt', self.event())
            value = CHECK['provider_events'](root, 'private_unknown_phase', '100')
            self.assertEqual(value['phase'], 'unknown')
            self.assertEqual(value['roles']['client']['state'], 'unqueried')
            for code in (1, 77, 255):
                row = self.observed(root, raw='', status=f'{code}\n')['roles']['client']
                self.assertEqual(row['state'], 'query_failed')
                self.assertEqual(row['query_exit_status'], code)
                self.assertIsNone(row['records'])
                self.assertIsNone(row['counts'])
            row = self.observed(root, raw='')['roles']['client']
            self.assertEqual((row['state'], row['records']), ('observed', 0))
            self.assertFalse(row['window_covers_baseline'])
            self.assertEqual(sum(row['counts'].values()), 0)

    def test_invalid_capture_status_and_missing_log_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for raw in ('00\n', '-1\n', '256\n', '0\nPRIVATE', '0', 'true'):
                with self.subTest(raw=raw):
                    row = self.observed(root, status=raw)['roles']['client']
                    self.assertEqual(row['state'], 'capture_invalid')
                    self.assertIsNone(row['query_exit_status'])
            self.save(root / 'logs-client-cleanup-status.private', '0\n')
            (root / 'logs-client.txt').unlink()
            self.assertEqual(CHECK['provider_events'](root, 'unknown', '100')['roles']['client']['state'], 'absent')

    def test_baseline_is_bound_without_exporting_timestamp_or_unbound_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.observed(root)
            for baseline, state in (('0', 'absent'), ('', 'absent'), ('-1', 'invalid'),
                    ('0100', 'invalid'), ('1\nPRIVATE', 'invalid'), ('9' * 20, 'invalid')):
                value = CHECK['provider_events'](root, 'storage-consumer-publish', baseline)
                self.assertEqual(value['baseline_state'], state)
                self.assertEqual(value['roles']['client']['state'], 'baseline_unavailable')
                self.assertIsNone(value['roles']['client']['counts'])

    def test_ring_capacity_and_uncovered_window_remain_observations_not_absence_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self.observed(root, raw=self.event() * 400)
            row = value['roles']['client']
            self.assertEqual(row['counts'][self.CODE], 400)
            self.assertTrue(row['ring_at_capacity'])
            self.assertFalse(row['window_covers_baseline'])
            self.assertFalse(value['acceptance_evidence'])
            self.assertEqual(self.observed(root, raw=self.event() * 401)['roles']['client']['state'], 'invalid')

    def test_malformed_raw_paths_bounds_and_clock_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for raw in ('PRIVATE_PATH /secret/private\n', self.event().replace('path=7', 'path=/secret'),
                    self.event().replace('event=', 'event=private.example/'), '\N{SNOWMAN}', 'x' * 131073):
                with self.subTest(length=len(raw)):
                    value = self.observed(root, raw=raw)
                    self.assertEqual(value['roles']['client']['state'], 'invalid')
                    self.assertIsNone(value['roles']['client']['counts'])
                    self.assertNotIn('PRIVATE_PATH', json.dumps(value))
                    self.assertNotIn('/secret', json.dumps(value))
            for raw in (self.event(0), self.event(102) + self.event(101), self.event(10**19)):
                self.assertEqual(self.observed(root, raw=raw)['roles']['client']['state'], 'clock_invalid')

    def test_private_input_metadata_and_no_follow_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.observed(root)
            path = root / 'logs-client.txt'
            path.chmod(0o644)
            self.assertEqual(CHECK['provider_events'](root, 'unknown', '100')['roles']['client']['state'], 'invalid')
            path.chmod(0o600)
            other = root / 'other'; path.rename(other); path.symlink_to(other)
            self.assertEqual(CHECK['provider_events'](root, 'unknown', '100')['roles']['client']['state'], 'invalid')
            path.unlink(); os.link(other, path)
            self.assertEqual(CHECK['provider_events'](root, 'unknown', '100')['roles']['client']['state'], 'invalid')
            path.unlink(); os.mkfifo(path, 0o600)
            self.assertEqual(CHECK['provider_events'](root, 'unknown', '100')['roles']['client']['state'], 'invalid')

    def test_closed_validator_rejects_mutation_and_boolean_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = self.observed(Path(temporary))
            changes = ({'private_path': 'PRIVATE'}, {'version': True}, {'phase': 'PRIVATE'},
                {'scope': 'failure_cause'}, {'acceptance_evidence': True}, {'event_absence_proven': True},
                {'causal_attribution': True}, {'baseline_state': 'invalid'}, {'roles': {}})
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    CHECK['validate_provider_events']({**value, **change})
            for change in ({'records': True}, {'fresh_records': 401}, {'query_exit_status': True},
                    {'query_exit_status': 1}, {'state': 'query_failed'}, {'raw': 'PRIVATE'},
                    {'window_covers_baseline': True}, {'ring_at_capacity': True},
                    {'counts': {self.CODE: 1}}, {'unrecognized_event_records': 1}):
                invalid = copy.deepcopy(value); invalid['roles']['client'].update(change)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    CHECK['validate_provider_events'](invalid)

    def test_sidecar_failure_is_independent_of_existing_route_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.observed(root)
            expected = CHECK['route_diagnostic'](root)
            for error in (RuntimeError('PRIVATE_FAILURE'), KeyboardInterrupt()):
                with patch.dict(CHECK['export_provider_events'].__globals__,
                        provider_events=Mock(side_effect=error)), patch('builtins.print') as output:
                    CHECK['main'](['route-diagnostic', str(root), 'storage-consumer-publish', '100'])
                self.assertEqual(json.loads(output.call_args.args[0]), expected)
                self.assertFalse((root / CHECK['PROVIDER_EVENTS_NAME']).exists())
            with patch('os.replace', side_effect=OSError('PRIVATE_WRITE_FAILURE')), patch('builtins.print') as output:
                CHECK['main'](['route-diagnostic', str(root), 'storage-consumer-publish', '100'])
            self.assertEqual(json.loads(output.call_args.args[0]), expected)
            self.assertFalse((root / 'maintenance-provider-events.part').exists())

    def test_atomic_sidecar_and_export_validator_do_not_publish_private_or_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.observed(root)
            CHECK['export_provider_events'](root, 'storage-consumer-publish', '100')
            target = root / CHECK['PROVIDER_EVENTS_NAME']
            value = CHECK['provider_events_file'](target)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse((root / 'maintenance-provider-events.part').exists())
            for raw in ('{"version":1,"version":1}', json.dumps({**value, 'path': '/PRIVATE'}), 'x' * 65537):
                self.save(target, raw)
                with self.assertRaises(ValueError): CHECK['provider_events_file'](target)
                with patch('builtins.print') as output:
                    CHECK['main'](['export-names', str(root)])
                self.assertNotIn(CHECK['PROVIDER_EVENTS_NAME'], output.call_args.args[0].splitlines())

    @staticmethod
    def storage_codes():
        return [f'{CHECK["STORAGE_FAILURE_PREFIX"]}{operation}__{phase}__{category}'
            for operation in CHECK['STORAGE_FAILURE_OPERATIONS']
            for phase in CHECK['STORAGE_FAILURE_PHASES']
            for category in CHECK['STORAGE_FAILURE_CATEGORIES']
            if CHECK['storage_failure_code'](
                f'{CHECK["STORAGE_FAILURE_PREFIX"]}{operation}__{phase}__{category}')]

    def test_storage_events_require_closed_verified_operation_and_phase_labels(self):
        valid = ('UNKNOWN__GRANT__AUTH', 'UNKNOWN__REQUEST__TIMEOUT',
            'FINALIZE__BACKEND__INTEGRITY', 'FINALIZE__RECEIPT__IO',
            'APPEND__DISK_ADMISSION__BUSY', 'READ_RANGE__RESPONSE_PAYLOAD__IO')
        invalid = ('UNKNOWN__BACKEND__STORE', 'FINALIZE__REQUEST__AUTH',
            'UNKNOWN__RECEIPT__IO', 'FINALIZE__RESPONSE_PAYLOAD__IO',
            'DELETE__PRIVATE_PHASE__IO', 'FINALIZE__BACKEND__PRIVATE_CATEGORY',
            'PRIVATE_OPERATION__BACKEND__IO', 'FINALIZE_BACKEND_IO',
            'FINALIZE__BACKEND__IO__PRIVATE', 'finalize__BACKEND__IO')
        for suffix in valid:
            self.assertTrue(CHECK['storage_failure_code'](CHECK['STORAGE_FAILURE_PREFIX'] + suffix))
        for suffix in invalid:
            self.assertFalse(CHECK['storage_failure_code'](CHECK['STORAGE_FAILURE_PREFIX'] + suffix))
        for value in (None, True, 1, [], {}, 'x' * 97):
            self.assertFalse(CHECK['storage_failure_code'](value))

    def test_storage_allowlist_matches_the_producer_static_label_contract(self):
        source = (HERE.parents[1] /
            'crates/volparossa-content/src/private_storage/wire/diagnostic.rs').read_text()
        self.assertEqual(set(re.findall(r'phase_code!\(\s*"([A-Z_]+)"', source)),
            set(CHECK['STORAGE_FAILURE_OPERATIONS']))
        self.assertEqual(set(re.findall(r'category_code!\(\s*\$op,\s*"([A-Z_]+)"', source)),
            set(CHECK['STORAGE_FAILURE_PHASES']))
        category_macro = source[source.index('macro_rules! category_code'):source.index('macro_rules! phase_code')]
        self.assertEqual(set(re.findall(r'"__([A-Z_]+)"', category_macro)),
            set(CHECK['STORAGE_FAILURE_CATEGORIES']))
        self.assertIn('"' + CHECK['STORAGE_FAILURE_PREFIX'] + '"', source)
        self.assertNotIn('format!(', source)
        self.assertLessEqual(max(map(len, self.storage_codes())), 96)

    def test_sparse_storage_tuples_preserve_pairs_without_private_identifiers(self):
        first = CHECK['STORAGE_FAILURE_PREFIX'] + 'FINALIZE__BACKEND__INTEGRITY'
        second = CHECK['STORAGE_FAILURE_PREFIX'] + 'APPEND__RECEIPT__IO'
        unknown = CHECK['STORAGE_FAILURE_PREFIX'] + 'PRIVATE__BACKEND__IO'
        with tempfile.TemporaryDirectory() as temporary:
            value = self.observed(Path(temporary), raw=self.event(99, first)
                + self.event(101, first) + self.event(102, second) + self.event(103, first)
                + self.event(104, unknown) + self.event(105))
            row = value['roles']['client']
            self.assertEqual(value['version'], 2)
            self.assertEqual(row['storage_failures'], {first: 2, second: 1})
            self.assertEqual(row['omitted_storage_failure_records'], 0)
            self.assertEqual(row['counts'][self.CODE], 1)
            self.assertEqual(row['unrecognized_event_records'], 1)
            self.assertEqual((row['records'], row['stale_records'], row['fresh_records']), (6, 1, 5))
            self.assertNotIn(CHECK['STORAGE_FAILURE_PREFIX'] + 'FINALIZE__RECEIPT__IO',
                row['storage_failures'])
            for private in ('deadbeef', unknown, 'session=', 'path=', temporary):
                self.assertNotIn(private, json.dumps(value))
            self.assertFalse(value['acceptance_evidence'])
            self.assertFalse(value['causal_attribution'])
            self.assertFalse(value['event_absence_proven'])

    def test_storage_tuple_bound_counts_omissions_and_keeps_existing_keys(self):
        codes = self.storage_codes()[:33]
        self.assertEqual(len(set(codes)), 33)
        with tempfile.TemporaryDirectory() as temporary:
            value = self.observed(Path(temporary), raw=''.join(self.event(101, code) for code in codes)
                + self.event(102, codes[-1]) + self.event(103, codes[0]))
            row = value['roles']['client']
            self.assertEqual(set(row['storage_failures']), set(codes[:32]))
            self.assertEqual(row['storage_failures'][codes[0]], 2)
            self.assertEqual(row['omitted_storage_failure_records'], 2)
            self.assertEqual(row['fresh_records'], 35)
            self.assertEqual(row['unrecognized_event_records'], 0)

    def test_historical_v1_event_receipts_stay_exact_and_reject_new_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = self.observed(Path(temporary))
        value['version'] = 1
        for row in value['roles'].values():
            del row['storage_failures'], row['omitted_storage_failure_records']
        self.assertEqual(CHECK['validate_provider_events'](copy.deepcopy(value)), value)
        changed = copy.deepcopy(value)
        changed['roles']['client']['storage_failures'] = {}
        with self.assertRaises(ValueError): CHECK['validate_provider_events'](changed)
        changed = copy.deepcopy(value); changed['version'] = 2
        with self.assertRaises(ValueError): CHECK['validate_provider_events'](changed)

    def test_storage_validator_rejects_unknown_zero_boolean_and_invented_counts(self):
        code = CHECK['STORAGE_FAILURE_PREFIX'] + 'FINALIZE__RECEIPT__IO'
        with tempfile.TemporaryDirectory() as temporary:
            value = self.observed(Path(temporary), raw=self.event(101, code))
        changes = ({'storage_failures': None}, {'storage_failures': {code: True}},
            {'storage_failures': {code: 0}}, {'storage_failures': {code: -1}},
            {'storage_failures': {code: 2}}, {'storage_failures': {code: 1.0}},
            {'storage_failures': {'PRIVATE': 1}}, {'omitted_storage_failure_records': True},
            {'omitted_storage_failure_records': 1}, {'omitted_storage_failure_records': -1},
            {'omitted_storage_failure_records': 1.0},
            {'storage_failures': dict.fromkeys(self.storage_codes()[:33], 1)})
        for change in changes:
            invalid = copy.deepcopy(value); invalid['roles']['client'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                CHECK['validate_provider_events'](invalid)
        for name in ('storage_failures', 'omitted_storage_failure_records'):
            invalid = copy.deepcopy(value)
            invalid['roles']['provider_relay3'][name] = {} if name == 'storage_failures' else 0
            with self.assertRaises(ValueError): CHECK['validate_provider_events'](invalid)

    def test_maximum_storage_snapshot_stays_inside_existing_export_bound(self):
        codes = sorted(self.storage_codes(), key=len, reverse=True)[:32]
        raw = ''.join(self.event(101, codes[i % 32]) for i in range(400))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for node in CHECK['PROVIDER_EVENT_ROLES'].values():
                self.save(root / f'logs-{node}-cleanup-status.private', '0\n')
                self.save(root / f'logs-{node}.txt', raw)
            CHECK['export_provider_events'](root, 'storage-consumer-publish', '100')
            target = root / CHECK['PROVIDER_EVENTS_NAME']
            self.assertLessEqual(target.stat().st_size, 65536)
            value = CHECK['provider_events_file'](target)
            for row in value['roles'].values():
                self.assertEqual(len(row['storage_failures']), 32)
                self.assertEqual(sum(row['storage_failures'].values()), 400)
                self.assertTrue(row['ring_at_capacity'])
                self.assertFalse(row['window_covers_baseline'])

    @staticmethod
    def payload_io_codes():
        return [CHECK['APPEND_PAYLOAD_IO_PREFIX'] + boundary + '__' + kind
            for boundary in CHECK['APPEND_PAYLOAD_IO_BOUNDARIES'] for kind in CHECK['APPEND_PAYLOAD_IO_KINDS']]

    def test_v3_payload_io_mapping_matches_static_producer_and_rejects_unreviewed_labels(self):
        source = (HERE.parents[1] /
            'crates/volparossa-content/src/private_storage/wire/diagnostic.rs').read_text()
        macro = source[source.index('macro_rules! payload_io_code'):source.index('macro_rules! category_code')]
        self.assertEqual(set(re.findall(r'"__([A-Z_]+)"', macro)), set(CHECK['APPEND_PAYLOAD_IO_KINDS']))
        self.assertEqual(set(re.findall(r'payload_io_code!\("([A-Z_]+)"', source)),
            set(CHECK['APPEND_PAYLOAD_IO_BOUNDARIES']))
        self.assertIn('"' + CHECK['APPEND_PAYLOAD_IO_PREFIX'] + '"', macro)
        self.assertNotIn('format!(', source)
        self.assertEqual(len(self.payload_io_codes()), 14)
        for code in self.payload_io_codes():
            self.assertTrue(CHECK['append_payload_io_code'](code))
            self.assertLessEqual(len(code), 96)
        for code in (None, True, 1, [], {}, self.payload_io_codes()[0] + '__PRIVATE',
                self.payload_io_codes()[0].replace('APPEND', 'FINALIZE'),
                self.payload_io_codes()[0].replace('PAYLOAD_HEADER', 'REQUEST'),
                self.payload_io_codes()[0].replace('UNEXPECTED_EOF', 'PRIVATE'), 'x' * 97):
            self.assertFalse(CHECK['append_payload_io_code'](code))

    def test_v3_is_explicit_and_preserves_default_v2_shape_and_unknown_count(self):
        first, second = self.payload_io_codes()[0], self.payload_io_codes()[-1]
        legacy = CHECK['STORAGE_FAILURE_PREFIX'] + 'APPEND__PAYLOAD__IO'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = self.observed(root, self.event(99, first) + self.event(101, first)
                + self.event(102, second) + self.event(103, legacy) + self.event(104, first))
            current = CHECK['provider_events'](root, 'storage-consumer-publish', '100', version=3)
        self.assertEqual(previous['version'], 2)
        self.assertEqual(previous['roles']['client']['unrecognized_event_records'], 3)
        self.assertNotIn('append_payload_io_failures', previous['roles']['client'])
        self.assertEqual(current['roles']['client']['append_payload_io_failures'], {first: 2, second: 1})
        self.assertEqual(current['roles']['client']['storage_failures'], {legacy: 1})
        projection = copy.deepcopy(current); projection['version'] = 2
        for row in projection['roles'].values():
            payload = row.pop('append_payload_io_failures')
            if payload is not None: row['unrecognized_event_records'] += sum(payload.values())
        self.assertEqual(json.dumps(projection, sort_keys=True), json.dumps(previous, sort_keys=True))
        for private in ('deadbeef', 'session=', 'path=', temporary):
            self.assertNotIn(private, json.dumps(current))
        self.assertFalse(current['causal_attribution'])
        self.assertFalse(current['acceptance_evidence'])

    def test_v3_rejects_missing_unknown_boolean_and_impossible_payload_counts(self):
        code = self.payload_io_codes()[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.observed(root, self.event(101, code))
            value = CHECK['provider_events'](root, 'storage-consumer-publish', '100', version=3)
        for payload in (None, [], {code: True}, {code: 0}, {code: -1}, {code: 1.0},
                {code: 2}, {code: 401}, {'PRIVATE': 1}):
            changed = copy.deepcopy(value); changed['roles']['client']['append_payload_io_failures'] = payload
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                CHECK['validate_provider_events'](changed)
        changed = copy.deepcopy(value); del changed['roles']['client']['append_payload_io_failures']
        with self.assertRaises(ValueError): CHECK['validate_provider_events'](changed)
        changed = copy.deepcopy(value); changed['roles']['provider_relay3']['append_payload_io_failures'] = {}
        with self.assertRaises(ValueError): CHECK['validate_provider_events'](changed)
        for version in (1, 2):
            changed = copy.deepcopy(value); changed['version'] = version
            with self.assertRaises(ValueError): CHECK['validate_provider_events'](changed)

    def test_v3_current_export_is_separate_and_failure_cannot_replace_route_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.observed(root, self.event(101, self.payload_io_codes()[0]))
            expected = CHECK['route_diagnostic'](root)
            with patch('builtins.print') as output:
                CHECK['main'](['route-diagnostic-v3', str(root), 'storage-consumer-publish', '100'])
            self.assertEqual(json.loads(output.call_args.args[0]), expected)
            path = root / CHECK['PROVIDER_EVENTS_NAME']
            self.assertEqual(CHECK['provider_events_file'](path)['version'], 3)
            with patch('builtins.print') as output:
                CHECK['main'](['export-names', str(root)])
            self.assertIn(CHECK['PROVIDER_EVENTS_NAME'], output.call_args.args[0].splitlines())
            with patch.dict(CHECK['export_provider_events'].__globals__, provider_events=Mock(side_effect=ValueError('PRIVATE'))), \
                    patch('builtins.print') as output:
                CHECK['main'](['route-diagnostic-v3', str(root), 'storage-consumer-publish', '100'])
            self.assertEqual(json.loads(output.call_args.args[0]), expected)
            self.assertFalse(path.exists())

    def test_v3_maximum_old_and_new_tuples_fit_existing_export_limit(self):
        codes = sorted(self.storage_codes(), key=len, reverse=True)[:32] + self.payload_io_codes()
        raw = ''.join(self.event(101, codes[i % len(codes)]) for i in range(400))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for node in CHECK['PROVIDER_EVENT_ROLES'].values():
                self.save(root / f'logs-{node}-cleanup-status.private', '0\n')
                self.save(root / f'logs-{node}.txt', raw)
            CHECK['export_provider_events'](root, 'storage-consumer-publish', '100', version=3)
            target = root / CHECK['PROVIDER_EVENTS_NAME']
            self.assertLessEqual(target.stat().st_size, 65536)
            value = CHECK['provider_events_file'](target)
            for row in value['roles'].values():
                self.assertEqual(len(row['storage_failures']), 32)
                self.assertEqual(len(row['append_payload_io_failures']), 14)
                self.assertEqual(sum(row['storage_failures'].values()) + sum(row['append_payload_io_failures'].values()), 400)
                self.assertTrue(row['ring_at_capacity'])

    def test_provider_event_export_version_rejects_unknown_or_boolean_selection(self):
        for version in (True, 1, 4, '3', 3.0):
            with self.subTest(version=version), self.assertRaises(ValueError):
                CHECK['provider_events'](Path('/unused'), 'unknown', '100', version=version)


class SupervisorDiagnostic(unittest.TestCase):
    def test_closed_schema_rejects_unknown_fields_values_statuses_and_false_acceptance(self):
        value = CHECK['supervisor_record']('control_match', 'failed', '1', 'different')
        self.assertFalse(value['acceptance_evidence'])
        for changed in ({'stage': 'PRIVATE_PATH'}, {'outcome': 'success'}, {'exit_status': 256},
                {'exit_status': 0}, {'exit_status': True}, {'exit_status': 1.0},
                {'control_relay_relation': 'PRIVATE_PEER'}, {'acceptance_evidence': True},
                {'raw_command': 'PRIVATE_COMMAND'}, {'version': True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                CHECK['validate_supervisor']({**value, **changed})
        for status in ('-15', '01', '1\nPRIVATE', '1.0', 'true'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                CHECK['supervisor_record']('bind_slots', 'failed', status, 'unobserved')
        with self.assertRaises(ValueError):
            CHECK['supervisor_record']('bind_slots', 'complete', '0', 'unobserved')

    def test_private_receipt_reader_is_closed_bounded_and_no_follow(self):
        value = CHECK['supervisor_record']('control_query', 'pending', 'null', 'unobserved')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'supervisor.json'
            path.write_text(json.dumps(value)); path.chmod(0o600)
            self.assertEqual(CHECK['supervisor_file'](path), value)
            for raw in ('x' * 1025, '{"version":1,"version":1}',
                    json.dumps({**value, 'private_peer': 'DO_NOT_EXPORT'})):
                path.write_text(raw)
                with self.assertRaises(ValueError): CHECK['supervisor_file'](path)
            path.write_text(json.dumps(value)); path.chmod(0o644)
            with self.assertRaises(ValueError): CHECK['supervisor_file'](path)
            path.chmod(0o600)
            link = root / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): CHECK['supervisor_file'](link)
            fifo = root / 'fifo'; os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError): CHECK['supervisor_file'](fifo)


class InitialInventory(unittest.TestCase):
    def test_closed_original_helper_receipt_rejects_changed_status_scope_and_unbounded_input(self):
        helper = runpy.run_path(str(HERE / 'content-provider-readiness.py'))
        value = helper['new_record']()
        value.update(outcome='deadline')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'inventory.json'
            def save(record):
                path.write_text(json.dumps(record)); path.chmod(0o600)
            save(value)
            self.assertEqual(CHECK['inventory_file'](path, '1'), value)
            for status in ('0', '2', '124', '-15'):
                with self.assertRaises(ValueError): CHECK['inventory_file'](path, status)
            for record in ({**value, 'raw_peers': 'not-exportable'},
                    {**value, 'scope': 'route_readiness'}, {**value, 'deadline_seconds': 61},
                    {**value, 'last_valid_presence': {'relay3': True}}):
                save(record)
                with self.assertRaises(ValueError): CHECK['inventory_file'](path, '1')
            path.write_text('x' * 8193)
            with self.assertRaises(ValueError): CHECK['inventory_file'](path, '1')
            save(value)
            path.chmod(0o644)
            with self.assertRaises(ValueError): CHECK['inventory_file'](path, '1')


def identity_projection(indexes):
    return [dict(fragment=index, authorization_sha256=str(index + 1) * 64,
        copy_identity_sha256=str(index + 4) * 64) for index in indexes]


def baseline_fixture(retired=()):
    return dict(version=1, retired_original_a=list(retired), replacement_identities=identity_projection(retired),
        physical_payload_charge=2 * CHECK['BYTES'], pending_retirements=0, retained_copy_records=8 + len(retired))


def custody_fixture(retired=(), *, withdrawn=False):
    value, _, keys = OLD['cli_fixture']('committed')
    for index, fragment in enumerate(value['fragments']):
        if index in retired or withdrawn and index != 1:
            replacement = copy.deepcopy(fragment['copies'][0])
            replacement['provider_key'] = keys[2 if index in (0, 3) else 1]
            fragment['copies'].append(replacement)
        for item in fragment['copies']:
            if item['provider_key'] == keys[0]:
                if index in retired:
                    item.update(charge='deleted', last_confirmed_state='Deleted',
                        last_confirmed_expiry=0, last_confirmed_stored_bytes=0)
                elif withdrawn:
                    item['charge'] = 'uncertain'
    count = 3 if withdrawn else len(retired)
    if count:
        value.update(report_version=2, desired_copies_per_fragment=2, placement_authorizations=count,
            retained_copy_records=8 + count, pending_retirements=3 - len(retired) if withdrawn else 0,
            replacement_overhead_included=True)
    uncertain = sum(CHECK['LENGTHS'][i] for i in (0, 2, 3) if i not in retired) if withdrawn else 0
    value.update(uncertain_payload_bytes=uncertain, physical_payload_charge_upper_bound=2 * CHECK['BYTES'] + uncertain)
    usage = CHECK['custody_usage'](retired, withdrawn=withdrawn)
    value['providers'] = [dict(provider_key=key, physical_payload_charge_upper_bound=item['committed_bytes']
        - (len(CHECK['FG']) if index == 1 else 0)) for index, (key, item) in enumerate(zip(keys, usage))]
    return value, keys


def private_replacements(root, indexes, retired):
    """Synthetic text-only identity fixture, never signed/provider evidence."""
    entries = []
    for index in indexes:
        directory = root / f'fragment-set/fragment-{index:04}'
        (directory / 'copy-2').mkdir(parents=True, mode=0o700)
        journal = dict(provider_key=list(bytes.fromhex(str(3 if index in (0, 3) else 2) * 64)),
            owner_key=[4] * 32, grant_hex='12', archive_id=[index + 5] * 32,
            ciphertext_bytes=CHECK['LENGTHS'][index], sha256=[index] * 32)
        intent = {'from': 0 if index in (0, 3) else 1, 'to': 2, 'phase': 'copying', 'initial_journal': journal}
        entries.append(dict(fragment=index, handoff=intent))
        CHECK['create'](directory / 'replicas.json', json.dumps(dict(handoff=dict(intent,
            phase='complete' if index in retired else 'delete_pending'))).encode())
        CHECK['create'](directory / 'copy-2/archive.json', json.dumps(dict(journal, lease=[9] * 16)).encode())
    if entries:
        CHECK['create'](root / 'fragment-set/placement-authorizations.json',
            json.dumps(dict(authority=dict(placements=entries))).encode())


def fixture(*, historical=False, previous=False, retired=()):
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
        scan_cursor_before=6, scan_cursor_after=9, fresh_verified_replacements=3,
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
    value['lifecycle'] = dict(cursor_before=3, cursor_at_core_loss=4, cursor_after_reconnect=5,
        cursor_at_pause=5, cursor_after_resume=6, same_owner_survived_core_loss=True,
        charge_retained_during_core_loss=True, journal_identity_retained_during_core_loss=True,
        core_unavailable_observed=True, fresh_core_turn_completed=True, sigterm_exit_zero=True,
        paused_checkpoint_retained=True, new_owner_process_resumed=True, enrollment_unchanged=True,
        original_identities_retained=True, physical_payload_charge=2 * size,
        uncertainty_reconciled=True, owner_process_joined=True, guest_core_pid_changed=True,
        guest_core_namespace_preserved=True)
    if not historical:
        value['lifecycle']['pre_withdrawal'] = baseline_fixture(retired)
        remaining = sorted(set((0, 2, 3)) - set(retired))
        uncertain = sum(CHECK['LENGTHS'][i] for i in remaining)
        value['restore'].update(fresh_verified_replacements=len(remaining),
            pre_withdrawal_verified_replacements=len(retired), post_withdrawal_verified_fragment_indexes=remaining,
            replacement_identities=identity_projection((0, 2, 3)), pending_retirements=len(remaining),
            uncertain_payload_charge=uncertain, physical_payload_charge=2 * size + uncertain)
        value['uploaded_usage'] = CHECK['custody_usage'](retired, withdrawn=False)
        value['restored_usage'] = CHECK['custody_usage'](retired, withdrawn=True)
    value['network']['lifecycle'] = copy.deepcopy(value['network']['upload'])
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
    if not (historical or previous):
        CONSUMER_FIXTURE['attach_transition'](value, consumer=False)
    return value


def report(value):
    return dict(source_revision='1' * 40, schema_version=2,
        report_kind='volparossa-private-storage-maintenance', success=True, runner_exit_status=0,
        phase='private-storage-maintenance-complete', observed_blocker=None,
        cleanup=dict(complete=True, remaining_owned_objects=0), host_state=dict(unchanged=True), maintenance=value)


def original_custody(value, keys, retired, *, withdrawn):
    """Exact ea6efddb predicates/messages, retained only as a differential oracle."""
    require, lengths, size, foreground = CHECK['require'], CHECK['LENGTHS'], CHECK['BYTES'], CHECK['FG']
    replacements = 3 if withdrawn else len(retired)
    uncertain_bytes = sum(lengths[index] for index in (0, 2, 3) if index not in retired) if withdrawn else 0
    usage = CHECK['custody_usage'](retired, withdrawn=withdrawn)
    require(value['owner_signature_verified'] is True and value.get('report_version', 2 if not replacements else None) == 2
        and value['logical_ciphertext_bytes'] == size and value['fragment_count'] == 4
        and value['copies_per_fragment'] == value.get('desired_copies_per_fragment', 2 if not replacements else None) == 2
        and value.get('placement_authorizations', 0) == replacements and value.get('retained_copy_records', 8) == 8 + replacements
        and value.get('pending_retirements', 0) == (3 - len(retired) if withdrawn else 0)
        and value.get('replacement_overhead_included', not replacements) is True
        and value['uncertain_payload_bytes'] == uncertain_bytes and value['committed_payload_bytes'] == 2 * size
        and value['reserved_payload_bytes'] == 0 and value['physical_payload_charge_upper_bound'] == 2 * size + uncertain_bytes
        and value['fully_redundant_from_retained_receipts'] is True
        and value['fragments_with_confirmed_unexpired_copy'] == 4
        and value['providers'] == [dict(provider_key=key, physical_payload_charge_upper_bound=count)
            for key, count in zip(keys, (usage[0]['committed_bytes'], usage[1]['committed_bytes'] - len(foreground),
                usage[2]['committed_bytes']))], 'replacement custody or accounting incomplete')
    require(all(value[key] is False for key in ('read_consumes_archive', 'metadata_overhead_measured',
        'current_remote_availability_proven', 'independent_failure_domains_proven',
        'network_contribution_credit', 'erasure_coding')), 'replacement scope changed')
    require(len(value['fragments']) == 4, 'fragment reconstruction geometry changed')
    for index, fragment in enumerate(value['fragments']):
        require(fragment['index'] == index and fragment['offset'] == sum(lengths[:index])
            and fragment['ciphertext_bytes'] == lengths[index] and fragment['confirmed_unexpired_copies'] == 2,
            'fragment reconstruction geometry changed')
        providers = [(index + copy) % 3 for copy in range(2)]
        if index in retired or withdrawn and index != 1:
            providers.append(2 if index in (0, 3) else 1)
        require(len(fragment['copies']) == len(providers), 'effective replacement placement')
        for copy_value, provider in zip(fragment['copies'], providers):
            charge = ('deleted' if index in retired else 'uncertain' if withdrawn else 'committed') if provider == 0 else 'committed'
            require(copy_value['provider_key'] == keys[provider] and copy_value['charge'] == charge
                and copy_value['last_confirmed_state'] == ('Deleted' if charge == 'deleted' else 'Committed')
                and copy_value['last_confirmed_stored_bytes'] == (0 if charge == 'deleted' else lengths[index])
                and (copy_value['last_confirmed_expiry'] == 0 if charge == 'deleted'
                    else copy_value['last_confirmed_expiry'] > int(time.time())), 'effective replacement placement')


def fresh_turn_fixture():
    return dict(turns=6, stage='turn_completed', detail=dict(maintenance_stage='maintained',
        repair_stage='pending_handoff', attempted_handoffs=1, freshly_verified_replacements=0,
        pending_retirements=1, physical_payload_charge_upper_bound=CHECK['MAX_CHARGE'],
        fragment_outcomes=[dict(index=0, handoff_stage='replacement_retention_insufficient',
            resumed_signed_intent=True, replacement_verified_this_pass=False, operation_complete=False)],
        refresh=dict(fragment_index=1, renewal=True, operation_complete=True,
            copy_outcomes=['confirmed', 'existing_retention_sufficient'])))


class LifecycleReconciliationDiagnostic(unittest.TestCase):
    def test_original_custody_guard_pass_fail_messages_and_boolean_semantics_preserved(self):
        mutations = [lambda value: None]
        for key in ('owner_signature_verified', 'report_version', 'logical_ciphertext_bytes', 'fragment_count',
                'copies_per_fragment', 'desired_copies_per_fragment', 'placement_authorizations', 'retained_copy_records',
                'pending_retirements', 'replacement_overhead_included', 'uncertain_payload_bytes',
                'committed_payload_bytes', 'reserved_payload_bytes', 'physical_payload_charge_upper_bound',
                'fully_redundant_from_retained_receipts', 'fragments_with_confirmed_unexpired_copy',
                'read_consumes_archive', 'metadata_overhead_measured', 'current_remote_availability_proven',
                'independent_failure_domains_proven', 'network_contribution_credit', 'erasure_coding'):
            for replacement in (False, True, -1, 0, 1, 2, None, 'PRIVATE_CANARY'):
                mutations.append(lambda value, k=key, r=replacement: value.update({k: r}))
            mutations.append(lambda value, k=key: value.pop(k, None))
        for key in ('provider_key', 'physical_payload_charge_upper_bound'):
            mutations.append(lambda value, k=key: value['providers'][0].update({k: 'PRIVATE_CANARY'}))
        for key in ('index', 'offset', 'ciphertext_bytes', 'confirmed_unexpired_copies'):
            for replacement in (False, True, None, 1, 'PRIVATE_CANARY'):
                mutations.append(lambda value, k=key, r=replacement: value['fragments'][0].update({k: r}))
        for key in ('provider_key', 'charge', 'last_confirmed_state', 'last_confirmed_stored_bytes', 'last_confirmed_expiry'):
            for replacement in (False, True, None, 1, 'PRIVATE_CANARY'):
                mutations.append(lambda value, k=key, r=replacement: value['fragments'][0]['copies'][0].update({k: r}))
        mutations.extend((lambda value: value['fragments'].pop(),
            lambda value: value['fragments'][0]['copies'].pop(),
            lambda value: value.update(owner_signature_verified=False, fragments=None)))
        def outcome(function, value, keys, retired, withdrawn):
            try: function(value, keys, retired, withdrawn=withdrawn)
            except (ValueError, KeyError, TypeError) as error:
                return ('ValueError' if isinstance(error, ValueError) else type(error).__name__, str(error))
            return ('accepted',)
        for retired, withdrawn in (((), False), ((0,), False), ((0, 2), False), ((), True), ((0,), True)):
            for index, mutate in enumerate(mutations):
                value, keys = custody_fixture(retired, withdrawn=withdrawn)
                mutate(value)
                with self.subTest(retired=retired, withdrawn=withdrawn, mutation=index), patch.object(time, 'time', return_value=1000):
                    self.assertEqual(outcome(original_custody, value, keys, retired, withdrawn),
                        outcome(CHECK['validate_custody'], value, keys, retired, withdrawn))

    def test_actual_rejected_predicates_have_distinct_closed_reasons(self):
        cases = (
            (lambda v: v.update(pending_retirements=1, placement_authorizations=1, retained_copy_records=9), 'pending_handoff'),
            (lambda v: v.update(fully_redundant_from_retained_receipts=False), 'unconfirmed'),
            (lambda v: v['fragments'][0]['copies'][0].update(last_confirmed_expiry=1), 'expired'),
            (lambda v: v.update(committed_payload_bytes=0), 'accounting'),
            (lambda v: v['providers'][0].update(physical_payload_charge_upper_bound=0), 'accounting'),
            (lambda v: v['fragments'][0]['copies'][0].update(provider_key='PRIVATE_CANARY'), 'identity'),
            (lambda v: v['fragments'][0].update(offset=999), 'geometry'),
            (lambda v: v.update(erasure_coding=True), 'scope'),
            (lambda v: v.pop('owner_signature_verified'), 'malformed'))
        for mutate, expected in cases:
            with self.subTest(reason=expected), tempfile.TemporaryDirectory() as temporary:
                value, keys = custody_fixture(); mutate(value)
                with self.assertRaises(ValueError) as caught:
                    CHECK['pre_withdrawal'](Path(temporary), value, keys)
                self.assertEqual(str(caught.exception), 'pre-withdrawal custody not reconciled')
                self.assertEqual(CHECK['baseline_failure_reason'](caught.exception), expected)
        self.assertEqual(CHECK['baseline_failure_reason'](ValueError('PRIVATE_CANARY')), 'unknown')

    def test_maintained_pending_handoff_does_not_pass_baseline_or_replace_earlier_snapshot(self):
        namespace = CHECK['lifecycle'].__globals__
        early, keys = custody_fixture()
        current = copy.deepcopy(early)
        current.update(placement_authorizations=1, retained_copy_records=9, pending_retirements=1)
        current['fragments'][0]['copies'].append(dict(provider_key=keys[2], charge='unattempted', last_confirmed_expiry=0))
        gates = fixture()['network']['lifecycle']['gates']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'maintenance').mkdir()
            (root / 'maintenance/enrollment.json').write_text(json.dumps({'enrollment': {'expires': int(time.time()) + 6000}}))
            path = MagicMock(); path.parents = [None, None, path]; path.__truediv__.return_value = path
            path.exists.return_value = True
            path.lstat.return_value = Mock(st_mode=stat.S_IFREG | 0o640, st_nlink=1, st_uid=0, st_size=2)
            owner = Mock(); owner.process.poll.return_value = 0
            owner.reports.return_value = [dict(stage='turn_completed', turns=5)]
            @contextmanager
            def capture(*args, **kwargs): yield Mock(joined=True)
            def retained(*args):
                namespace['LIFECYCLE_DIAGNOSTIC']['retained_status'] = CHECK['retained_status_diagnostic'](early, 1000)
                return dict(version=1, pending=None)
            with patch.dict(namespace, LIFECYCLE_DIAGNOSTIC=None, SAMPLER_DIAGNOSTIC={},
                    Path=Mock(return_value=path), OwnerProcess=Mock(return_value=owner),
                    checkpoint=Mock(side_effect=[dict(stage='paused', turns=3), dict(stage='working', turns=4),
                        dict(stage='core_unavailable', turns=4), dict(stage='waiting_for_core', turns=4), dict(stage='paused', turns=5)]),
                    read=Mock(return_value=dict(baseline=gates['event_baseline_unix_ms'], scope=gates['exit_route_scope'])),
                    retained_current_during_core_loss=retained, retained_intent_continuity=Mock(),
                    wait_owner=lambda owner, predicate, seconds=180, **kwargs: predicate(),
                    status=Mock(return_value=early), run_turn=Mock(return_value=fresh_turn_fixture()),
                    invoke=Mock(return_value=current), unlock=lambda root: [], create=Mock()), \
                    patch.dict(CHECK['F'], check_identity=Mock()), patch.dict(CHECK['SAMPLER'], capture=capture):
                with self.assertRaisesRegex(ValueError, '^pre-withdrawal custody not reconciled$') as caught:
                    CHECK['lifecycle'](root, '/PRIVATE/cli', '/PRIVATE/socket', keys)
                result = CHECK['failure_receipt'](caught.exception)
                CHECK['validate_lifecycle_failure'](result)
                self.assertEqual(result['version'], 3)
                self.assertEqual(result['baseline_reason'], 'pending_handoff')
                self.assertEqual(result['retained_status_scope'], 'core_loss')
                self.assertEqual(result['retained_status']['copy_counts'], [2, 2, 2, 2])
                self.assertEqual(result['reconcile_status']['status']['copy_counts'], [3, 2, 2, 2])
                self.assertEqual(result['reconcile_status']['pending_retirements'], 1)
                self.assertEqual((result['cursor_last'], result['checkpoint_stage']), (5, 'paused'))
                self.assertEqual(result['fresh_turn_detail']['cursor'], 6)
                self.assertEqual(result['fresh_turn_detail']['repair_stage'], 'pending_handoff')
                self.assertEqual(result['fresh_turn_detail']['fragment_outcomes'][0]['handoff_stage'], 'replacement_retention_insufficient')
                self.assertEqual(result['fresh_turn_detail']['maintenance_stage'], 'maintained')
                namespace['run_turn'].assert_called_once(); namespace['invoke'].assert_called_once()
                owner.close.assert_called_once()
                self.assertFalse(result['success'])
                self.assertNotIn('PRIVATE', json.dumps(result))
                self.assertFalse(any(call.args[0] == root / 'lifecycle-result.json' for call in namespace['create'].call_args_list))

    def test_fresh_turn_unknown_fields_and_bounds_never_escape(self):
        value = fresh_turn_fixture(); value['detail']['private'] = 'PRIVATE_CANARY'
        projected = CHECK['fresh_turn_diagnostic'](value)
        CHECK['validate_fresh_turn_detail'](projected)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(projected))
        value.update(turns=True, stage='PRIVATE_CANARY')
        value['detail'].update(repair_stage='PRIVATE_CANARY', attempted_handoffs=2,
            fragment_outcomes=[{}, {}], refresh=dict(copy_outcomes=['PRIVATE_CANARY']))
        projected = CHECK['fresh_turn_diagnostic'](value)
        CHECK['validate_fresh_turn_detail'](projected)
        self.assertIsNone(projected['cursor']); self.assertIsNone(projected['repair_stage'])
        self.assertIsNone(projected['checkpoint_stage']); self.assertIsNone(projected['attempted_handoffs'])
        self.assertIsNone(projected['fragment_outcomes']); self.assertEqual(projected['refresh']['copy_outcomes'], [None])
        for field, wrong in (('cursor', True), ('repair_stage', 'PRIVATE_CANARY'), ('attempted_handoffs', 2), ('extra', 'PRIVATE_CANARY')):
            with self.assertRaises(ValueError): CHECK['validate_fresh_turn_detail'](dict(projected, **{field: wrong}))

    def test_later_status_unknown_and_oversize_values_remain_unknown(self):
        value, _ = custody_fixture()
        value.update(pending_retirements=True, retained_copy_records=4097, fragments_with_confirmed_unexpired_copy=-1,
            fully_redundant_from_retained_receipts='PRIVATE_CANARY')
        projected = CHECK['reconcile_status_diagnostic'](value, 1000)
        CHECK['validate_reconcile_status'](projected)
        self.assertTrue(all(projected[key] is None for key in projected if key != 'status'))
        for field in ('pending_retirements', 'retained_copy_records', 'fragments_with_confirmed_unexpired_copy'):
            with self.assertRaises(ValueError): CHECK['validate_reconcile_status'](dict(projected, **{field: True}))
        unknown = CHECK['reconcile_status_diagnostic'](None, 1000)
        self.assertIsNone(unknown['pending_retirements']); self.assertIsNone(unknown['retained_copy_records'])

    def test_diagnostic_projection_failure_cannot_replace_primary_failure(self):
        context = {}
        with patch.dict(CHECK['observe_lifecycle'].__globals__, LIFECYCLE_DIAGNOSTIC=context):
            CHECK['observe_lifecycle']('reconcile_status', Mock(side_effect=ValueError('PRIVATE_CANARY')), {})
        self.assertEqual(context, dict(reconcile_status=None))

    def test_historical_v1_v2_fields_and_encoding_are_unchanged(self):
        old = dict(version=1, success=False, kind='private-storage-maintenance-lifecycle-failure',
            stage='reconcile_progress', code='baseline_custody', cursor_before=3, cursor_last=5,
            checkpoint_stage='paused', owner_exit_status=0, owner_joined=True, cleanup_error=None, sampler=None)
        for version in (1, 2):
            value = dict(old, version=version)
            if version == 2: value['retained_status'] = CHECK['retained_status_diagnostic']({}, 1000)
            original = json.dumps(value, sort_keys=True)
            self.assertEqual(CHECK['validate_lifecycle_failure'](value), value)
            self.assertEqual(json.dumps(value, sort_keys=True), original)
            with self.assertRaises(ValueError): CHECK['validate_lifecycle_failure'](dict(value, reconcile_status=None))

    def test_current_receipt_is_closed_bounded_and_does_not_change_historical_shapes(self):
        status, _ = custody_fixture()
        value = dict(version=3, success=False, kind='private-storage-maintenance-lifecycle-failure',
            stage='reconcile_progress', code='baseline_custody', cursor_before=3, cursor_last=5,
            checkpoint_stage='paused', owner_exit_status=0, owner_joined=True, cleanup_error=None, sampler=None,
            retained_status=CHECK['retained_status_diagnostic'](status, 1000), retained_status_scope='core_loss',
            reconcile_status=CHECK['reconcile_status_diagnostic'](status, 1000),
            fresh_turn_detail=CHECK['fresh_turn_diagnostic'](fresh_turn_fixture()), baseline_reason='pending_handoff')
        CHECK['validate_lifecycle_failure'](value)
        self.assertLessEqual(len(json.dumps(value).encode()), 8192)
        for field in ('retained_status_scope', 'reconcile_status', 'fresh_turn_detail', 'baseline_reason'):
            invalid = copy.deepcopy(value); del invalid[field]
            with self.assertRaises(ValueError): CHECK['validate_lifecycle_failure'](invalid)
        for fields in (dict(retained_status_scope='reconcile_progress'), dict(baseline_reason='PRIVATE_CANARY'),
                dict(baseline_reason=True), dict(reconcile_status={}), dict(fresh_turn_detail={}),
                dict(version=2), dict(success=True), dict(private='PRIVATE_CANARY')):
            with self.assertRaises(ValueError): CHECK['validate_lifecycle_failure'](dict(value, **fields))
        # Optional observations remain explicitly unknown, never acceptance.
        unknown = dict(value, reconcile_status=None, fresh_turn_detail=None, baseline_reason=None)
        CHECK['validate_lifecycle_failure'](unknown)
        self.assertFalse(unknown['success'])


class MaintenanceEvidence(unittest.TestCase):
    def test_lifecycle_failure_retains_primary_stage_cursor_and_secondary_cleanup_error(self):
        namespace = CHECK['lifecycle'].__globals__
        retained, _, _ = OLD['cli_fixture']('committed')
        for cleanup_error in (None, subprocess.TimeoutExpired('PRIVATE_COMMAND', 10)):
            with self.subTest(cleanup_error=cleanup_error is not None), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'maintenance').mkdir()
                (root / 'maintenance/enrollment.json').write_text(json.dumps(
                    {'enrollment': {'expires': int(time.time()) + 6000}}))
                owner = Mock()
                owner.process.poll.return_value = 0 if cleanup_error is None else None
                owner.close.side_effect = cleanup_error
                calls = []

                def wait(_owner, predicate, seconds=180, *, budget=None):
                    calls.append(seconds)
                    self.assertIsNotNone(budget)
                    if len(calls) == 3:
                        raise ValueError('owner lifecycle deadline')
                    return predicate()

                with patch.dict(namespace, LIFECYCLE_DIAGNOSTIC=None, SAMPLER_DIAGNOSTIC={},
                        checkpoint=Mock(side_effect=[dict(stage='paused', turns=3),
                            dict(stage='working', turns=4), dict(stage='core_unavailable', turns=4)]),
                        OwnerProcess=Mock(return_value=owner), wait_owner=wait,
                        retained_current_during_core_loss=Mock(return_value=dict(version=1, pending=None)),
                        status=Mock(return_value=retained), create=Mock(), unlock=lambda root: []), \
                        patch.dict(CHECK['F'], check_identity=Mock()):
                    with self.assertRaisesRegex(ValueError, '^owner lifecycle deadline$') as caught:
                        CHECK['lifecycle'](root, '/PRIVATE/binary', '/PRIVATE/runtime-client/control/agent.sock', ['a', 'b', 'c'])
                    receipt = CHECK['failure_receipt'](caught.exception)
                    CHECK['validate_lifecycle_failure'](receipt)
                    self.assertEqual(receipt['stage'], 'await_coordinator')
                    self.assertEqual(receipt['code'], 'lifecycle_deadline')
                    self.assertEqual(receipt['cursor_before'], 3)
                    self.assertEqual(receipt['cursor_last'], 4)
                    self.assertEqual(receipt['checkpoint_stage'], 'core_unavailable')
                    self.assertEqual(receipt['owner_joined'], cleanup_error is None)
                    self.assertEqual(receipt['cleanup_error'], 'cli_timeout' if cleanup_error else None)
                    self.assertNotIn('PRIVATE', json.dumps(receipt))
                    owner.close.assert_called_once()
                    self.assertNotIn('--maximum-turns', namespace['OwnerProcess'].call_args.args[0])
                    self.assertEqual(calls, [180, 180, CHECK['LIFECYCLE_SECONDS']])

    def test_coordinator_wait_uses_one_lifecycle_budget_not_the_old_180s_window(self):
        namespace = CHECK['wait_owner'].__globals__
        clock = Mock()
        elapsed = [0.0]
        clock.monotonic.side_effect = lambda: elapsed[0]
        clock.time.side_effect = lambda: 1000 + elapsed[0]
        clock.sleep.side_effect = lambda _: elapsed.__setitem__(0, elapsed[0] + 30)
        owner = Mock()
        owner.process.poll.return_value = None
        with patch.dict(namespace, time=clock):
            budget = CHECK['LifecycleBudget'](7000)
            ready = lambda: elapsed[0] >= 30 + 60 + 600
            with self.assertRaisesRegex(ValueError, '^owner lifecycle deadline$'):
                CHECK['wait_owner'](owner, ready)  # The actual old default fails.
            self.assertEqual(elapsed[0], 180)
            self.assertTrue(CHECK['wait_owner'](owner, ready, CHECK['LIFECYCLE_SECONDS'], budget=budget))
            self.assertEqual(elapsed[0], 690)
            self.assertEqual(budget.remaining(CHECK['LIFECYCLE_SECONDS']), 1110)
            # Later waits share the initial deadline; no fresh 1800s allocation.
            with self.assertRaisesRegex(ValueError, '^owner lifecycle deadline$'):
                CHECK['wait_owner'](owner, lambda: False, CHECK['LIFECYCLE_SECONDS'], budget=budget)
            self.assertEqual(elapsed[0], CHECK['LIFECYCLE_SECONDS'])

    def test_lifecycle_wait_never_outlives_original_expiry_or_clock_rollback_cap(self):
        namespace = CHECK['wait_owner'].__globals__
        clock = Mock()
        monotonic, wall = [0.0], [1000.0]
        clock.monotonic.side_effect = lambda: monotonic[0]
        clock.time.side_effect = lambda: wall[0]
        def advance(_):
            monotonic[0] += 1
            wall[0] += 1
        clock.sleep.side_effect = advance
        owner = Mock()
        owner.process.poll.return_value = None
        with patch.dict(namespace, time=clock):
            budget = CHECK['LifecycleBudget'](1005)
            with self.assertRaisesRegex(ValueError, '^owner lifecycle deadline$'):
                CHECK['wait_owner'](owner, lambda: False, CHECK['LIFECYCLE_SECONDS'], budget=budget)
            self.assertEqual(monotonic[0], 5)
            self.assertEqual(budget.expires, 1005)
            monotonic[0], wall[0] = 0, 1000
            budget = CHECK['LifecycleBudget'](1010)
            wall[0] = 900  # Clock rollback does not grant another 110s.
            self.assertEqual(budget.remaining(1800), 10)
            wall[0] = 1011  # Forward clock movement stops further admission.
            with self.assertRaisesRegex(ValueError, '^owner lifecycle deadline$'):
                budget.remaining(1800)
            for expires in (True, None, 0, -1, '7000'):
                with self.subTest(expires=expires), self.assertRaises(ValueError):
                    CHECK['LifecycleBudget'](expires)

    def test_more_coordinator_turns_preserve_closed_cursor_and_lifecycle_requirements(self):
        value = fixture()['lifecycle']
        value.update(cursor_after_reconnect=34, cursor_at_pause=35, cursor_after_resume=36)
        CHECK['validate_lifecycle'](value)
        for changed in (dict(cursor_after_resume=CHECK['MAX_LIFECYCLE_CURSOR'] + 1),
                dict(cursor_after_resume=35), dict(enrollment_unchanged=False),
                dict(same_owner_survived_core_loss=False)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                CHECK['validate_lifecycle'](dict(value, **changed))

    def test_sampler_finalization_cannot_publish_success_after_original_expiry(self):
        namespace = CHECK['lifecycle'].__globals__
        retained, _, _ = OLD['cli_fixture']('committed')
        gates = fixture()['network']['lifecycle']['gates']
        for expired in (False, True):
            with self.subTest(expired=expired), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'maintenance').mkdir()
                (root / 'maintenance/enrollment.json').write_text(json.dumps({'enrollment': {'expires': 1010}}))
                elapsed = [0]
                clock = Mock()
                clock.monotonic.side_effect = lambda: elapsed[0]
                clock.time.side_effect = lambda: 1000 + elapsed[0]
                # Inert path/uid and CLI doubles; no root metadata or actual core.
                path = MagicMock()
                path.parents = [None, None, path]
                path.__truediv__.return_value = path
                path.exists.return_value = True
                path.lstat.return_value = Mock(st_mode=stat.S_IFREG | 0o640,
                    st_nlink=1, st_uid=0, st_size=2)
                owner = Mock()
                owner.process.poll.return_value = 0
                owner.reports.return_value = [dict(stage='turn_completed', turns=6)]
                coverage = Mock(joined=True)
                coverage.report.return_value = gates

                @contextmanager
                def capture(*args, **kwargs):
                    yield coverage
                    elapsed[0] = 11 if expired else 5

                created = Mock()
                with patch.dict(namespace, time=clock, Path=Mock(return_value=path),
                        checkpoint=Mock(side_effect=[dict(stage='paused', turns=3),
                            dict(stage='working', turns=4), dict(stage='core_unavailable', turns=4),
                            dict(stage='waiting_for_core', turns=5), dict(stage='paused', turns=6)]),
                        read=Mock(return_value=dict(baseline=gates['event_baseline_unix_ms'], scope=gates['exit_route_scope'])),
                        OwnerProcess=Mock(return_value=owner), unlock=lambda root: [], create=created,
                        retained_current_during_core_loss=Mock(return_value=dict(version=1, pending=None)),
                        retained_intent_continuity=Mock(),
                        wait_owner=lambda owner, predicate, seconds=180, **kwargs: predicate(),
                        status=Mock(return_value=retained), run_turn=Mock(return_value=dict(turns=7)),
                        invoke=Mock(return_value=dict(physical_payload_charge_upper_bound=2 * CHECK['BYTES'],
                            uncertain_payload_bytes=0)), pre_withdrawal=Mock(return_value=baseline_fixture())), \
                        patch.dict(CHECK['F'], check_identity=Mock()), \
                        patch.dict(CHECK['SAMPLER'], capture=capture):
                    if expired:
                        with self.assertRaisesRegex(ValueError, '^owner lifecycle deadline$'):
                            CHECK['lifecycle'](root, '/synthetic/cli', '/synthetic/socket', ['a', 'b', 'c'])
                    else:
                        self.assertTrue(CHECK['lifecycle'](root, '/synthetic/cli', '/synthetic/socket',
                            ['a', 'b', 'c'])['same_owner_survived_core_loss'])
                published = [call.args[0] for call in created.call_args_list]
                self.assertEqual(root / 'lifecycle-result.json' in published, not expired)
                owner.close.assert_called_once()

    def test_initial_renewal_accepts_current_receipt_without_weakening_fields(self):
        # Exercise the actual upload guard, not an independent schema replica.
        # CLI/provider calls are doubles; this is not live renewal evidence.
        class RenewalAccepted(Exception):
            pass

        namespace = CHECK['upload'].__globals__
        expected = dict(fragment_index=0, renewal=True, operation_complete=True,
            copy_outcomes=['confirmed', 'confirmed'])

        def probe(refresh, accepted):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'foreground.bin').write_bytes(CHECK['FG'])
                invoke = Mock(side_effect=[dict(committed=True, stored_bytes=len(CHECK['FG'])),
                    dict(stage='enrolled', turns=0)])
                status = Mock(side_effect=[{}, RenewalAccepted()])
                owner = Mock(return_value=dict(detail=dict(refresh=refresh)))
                with patch.dict(CHECK['F'], upload=Mock(return_value={})), \
                        patch.dict(namespace, invoke=invoke, status=status, run_turn=owner,
                            unlock=lambda root: [], STAGE='not_started'):
                    failure = RenewalAccepted if accepted else ValueError
                    with self.assertRaises(failure) as raised:
                        CHECK['upload'](root, '/synthetic/cli', '/synthetic/socket', ['a', 'b', 'c'])
                    if not accepted:
                        self.assertEqual(str(raised.exception), 'real rotating renewal not observed')
                    self.assertEqual(status.call_count, 2 if accepted else 1)
                    self.assertEqual(owner.call_count, 1)

        probe(expected, True)
        for key in expected:
            with self.subTest(missing=key):
                probe({name: value for name, value in expected.items() if name != key}, False)
        for key, values in (
                ('fragment_index', (1, -1, False, 0.0, '0', None)),
                ('renewal', (False, 1, 'true', None)),
                ('operation_complete', (False, 1, 'true', None)),
                ('copy_outcomes', (None, [], ['confirmed'], ['confirmed'] * 3,
                    ['confirmed', 'unconfirmed_retained'], ['confirmed', 'unknown'], 'confirmed'))):
            for value in values:
                with self.subTest(field=key, value=value):
                    probe(dict(expected, **{key: value}), False)
        probe(dict(expected, unexpected='not part of the closed receipt'), False)

    def test_preselection_projection_requires_fresh_closed_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            baseline, events, end = self.preselection_files(work)
            events.write_text(self.event(99, 'PRESELECTION_SAMPLE_NO_EXIT')
                + self.event(100, 'PRESELECTION_SAMPLE_NO_EXIT')
                + self.event(101, 'PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS')
                + self.event(111, 'PRESELECTION_SAMPLE_NO_EXIT'))
            result = CHECK['closed_preselection_events'](events, baseline, end)
            CHECK['validate_preselection_diagnostic'](result)
            self.assertEqual(result['state'], 'known')
            self.assertEqual(result['observed_reason'], 'PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS')
            self.assertEqual(result['records'], 4)
            self.assertEqual(result['fresh_records'], 1)
            self.assertEqual(result['stale_records'], 2)
            self.assertEqual(result['later_records'], 1)
            self.assertEqual(result['counts']['PRESELECTION_SAMPLE_NO_EXIT'], 0)
            self.assertTrue(result['window_covers_baseline'])
            self.assertIsNone(result['uncertainty'])
            for private in (str(work), '12345', 'session=', 'path=', 'baseline_unix_ms'):
                self.assertNotIn(private, json.dumps(result))

    @staticmethod
    def event(timestamp, code):
        return f'{timestamp}\tlevel=1\tevent={code}\tsession={"a" * 64}\tpath=12345\n'

    @staticmethod
    def preselection_files(work):
        baseline = work / 'selection-start.private'
        events = work / 'logs-client.txt'
        end = work / 'selection-end.private'
        baseline.write_text('100\n')
        events.write_text('')
        end.write_text('110\n')
        baseline.chmod(0o600)
        events.chmod(0o600)
        end.chmod(0o600)
        return baseline, events, end

    def test_preselection_missing_ambiguous_truncated_and_stale_are_not_known(self):
        cases = (
            ('no_signal', '', 'no_fresh_signal'),
            ('stale', self.event(99, 'PRESELECTION_SAMPLE_NO_EXIT'), 'no_fresh_signal'),
            ('later', self.event(111, 'PRESELECTION_SAMPLE_NO_EXIT'), 'no_fresh_signal'),
            ('ambiguous', self.event(101, 'PRESELECTION_SAMPLE_NO_EXIT')
                + self.event(102, 'PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS'), 'ambiguous'),
            ('full_ring', self.event(101, 'PRESELECTION_SAMPLE_NO_EXIT') * 400, 'ring_at_capacity'),
            ('unknown', self.event(101, 'PRESELECTION_SAMPLE_PRIVATE_TOKEN'), 'unrecognized'),
            ('regression', self.event(101, 'PRESELECTION_SAMPLE_NO_EXIT')
                + self.event(99, 'PRESELECTION_SAMPLE_NO_EXIT'), 'clock_regression'),
            ('future', self.event(18446744073709551615, 'PRESELECTION_SAMPLE_NO_EXIT'), 'clock_regression'),
            ('raw_private', 'PRIVATE token=secret 192.0.2.99\n', 'invalid'),
        )
        for label, raw, uncertainty in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                baseline, events, end = self.preselection_files(Path(temporary))
                events.write_text(raw)
                result = CHECK['closed_preselection_events'](events, baseline, end)
                CHECK['validate_preselection_diagnostic'](result)
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result['observed_reason'], 'unknown')
                self.assertEqual(result['uncertainty'], uncertainty)
                for private in ('PRIVATE', 'token', 'secret', '192.0.2.99'):
                    self.assertNotIn(private, json.dumps(result))
        with tempfile.TemporaryDirectory() as temporary:
            baseline, events, end = self.preselection_files(Path(temporary))
            events.unlink()
            self.assertEqual(CHECK['closed_preselection_events'](events, baseline, end)['uncertainty'], 'absent')
            end.unlink()
            self.assertEqual(CHECK['closed_preselection_events'](events, baseline, end)['uncertainty'], 'absent_window_end')
            baseline.unlink()
            self.assertEqual(CHECK['closed_preselection_events'](events, baseline, end)['uncertainty'], 'absent_baseline')

    def test_preselection_rejects_unsafe_baseline_and_logs(self):
        for kind in ('baseline_mode', 'baseline_invalid', 'baseline_zero', 'baseline_future',
                     'end_mode', 'end_before_start', 'end_future', 'log_mode', 'log_symlink',
                     'baseline_symlink', 'oversize', 'too_many_records'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                baseline, events, end = self.preselection_files(Path(temporary))
                events.write_text(self.event(101, 'PRESELECTION_SAMPLE_NO_EXIT'))
                if kind == 'baseline_mode':
                    baseline.chmod(0o644)
                elif kind == 'baseline_invalid':
                    baseline.write_text('PRIVATE_BASELINE\n')
                elif kind == 'baseline_zero':
                    baseline.write_text('0\n')
                elif kind == 'baseline_future':
                    baseline.write_text('18446744073709551615\n')
                elif kind == 'end_mode':
                    end.chmod(0o644)
                elif kind == 'end_before_start':
                    end.write_text('99\n')
                elif kind == 'end_future':
                    end.write_text('18446744073709551615\n')
                elif kind == 'log_mode':
                    events.chmod(0o644)
                elif kind.endswith('_symlink'):
                    target = baseline if kind.startswith('baseline') else events
                    replacement = target.with_suffix('.copy')
                    target.rename(replacement)
                    target.symlink_to(replacement)
                elif kind == 'oversize':
                    events.write_text('a' * 131073)
                else:
                    events.write_text(self.event(101, 'PRESELECTION_SAMPLE_NO_EXIT') * 401)
                result = CHECK['closed_preselection_events'](events, baseline, end)
                CHECK['validate_preselection_diagnostic'](result)
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(result['uncertainty'],
                    'invalid_baseline' if kind.startswith('baseline')
                    else 'invalid_window_end' if kind.startswith('end') else 'invalid')
                self.assertIsNone(result['counts'])

    @staticmethod
    def selection_route():
        return dict(schema_version=1, stage='budget', reason='DEADLINE_EXHAUSTED',
            last_connect_reason='PRESELECTION_UNAVAILABLE', connect_exit_status=1,
            attempts=12, retries=11, redraws=0, path_polls=0, path_status=None)

    def test_route_projection_binds_last_window_and_excludes_private_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            baseline, events, end = self.preselection_files(work)
            baseline.rename(work / 'private-storage-maintenance-selection-start.private')
            end.rename(work / 'private-storage-maintenance-selection-end.private')
            phase = work / 'private-storage-maintenance-selection-phase.private'
            phase.write_text('initial\n')
            phase.chmod(0o600)
            events.write_text(self.event(99, 'PRESELECTION_SAMPLE_NO_EXIT')
                + self.event(101, 'PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS')
                + self.event(111, 'PRESELECTION_SAMPLE_NO_EXIT'))
            raw = work / 'private-storage-maintenance-selection-route-diagnostic.json'
            raw.write_text(json.dumps(self.selection_route()))
            raw.chmod(0o600)
            value = CHECK['route_diagnostic'](work)
            CHECK['validate_route_diagnostic'](value)
            self.assertEqual(value['route_state'], 'observed')
            self.assertEqual(value['selection_phase'], 'initial')
            self.assertEqual(value['route'], self.selection_route())
            self.assertEqual(value['preselection']['observed_reason'], 'PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS')
            self.assertEqual(value['scope'], 'last_selection_window_not_failure_cause')
            self.assertFalse(value['acceptance_evidence'])
            for private in (str(work), 'session=', 'path=', '12345', 'a' * 64):
                self.assertNotIn(private, json.dumps(value))
            exported = work / 'public.json'
            exported.write_text(json.dumps(value))
            subprocess.run(['python3', '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                'route-diagnostic-check', str(exported)], check=True, capture_output=True, timeout=5)
            for phase_text, expected in (('reconnect\n', 'reconnect'), ('PRIVATE_PATH\n', 'unknown')):
                phase.write_text(phase_text)
                self.assertEqual(CHECK['route_diagnostic'](work)['selection_phase'], expected)
            phase.write_text('initial\n')
            phase.chmod(0o644)
            self.assertEqual(CHECK['route_diagnostic'](work)['selection_phase'], 'unknown')

    def test_route_projection_missing_or_invalid_is_unknown_not_raw_export(self):
        for kind in ('missing', 'empty', 'duplicate', 'private', 'oversize', 'mode', 'symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                raw = work / 'private-storage-maintenance-selection-route-diagnostic.json'
                if kind != 'missing':
                    raw.write_text(json.dumps(self.selection_route()))
                    raw.chmod(0o600)
                if kind == 'empty':
                    raw.write_text('')
                elif kind == 'duplicate':
                    raw.write_text('{"schema_version":1,' + raw.read_text()[1:])
                elif kind == 'private':
                    raw.write_text(json.dumps(dict(self.selection_route(), token='PRIVATE_CANARY')))
                elif kind == 'oversize':
                    raw.write_text('PRIVATE_CANARY' * 2048)
                elif kind == 'mode':
                    raw.chmod(0o644)
                elif kind == 'symlink':
                    raw.rename(work / 'target')
                    raw.symlink_to(work / 'target')
                elif kind == 'hardlink':
                    os.link(raw, work / 'other')
                elif kind == 'fifo':
                    raw.unlink()
                    os.mkfifo(raw, 0o600)
                # Real child bounds the FIFO/no-writer regression as well.
                result = subprocess.run(['python3', '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                    'route-diagnostic', str(work)], check=True, capture_output=True, text=True, timeout=5)
                value = json.loads(result.stdout)
                CHECK['validate_route_diagnostic'](value)
                self.assertEqual(value['route_state'], 'absent' if kind == 'missing' else 'invalid')
                self.assertEqual(value['selection_phase'], 'unknown')
                self.assertIsNone(value['route'])
                self.assertEqual(value['preselection']['state'], 'unknown')
                self.assertNotIn('PRIVATE_CANARY', result.stdout)
                self.assertNotIn(str(work), result.stdout)

    def test_route_diagnostic_validator_rejects_open_fields_and_fabricated_known(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = CHECK['route_diagnostic'](Path(temporary))
        value.update(route_state='observed', route=self.selection_route())
        mutations = (
            lambda v: v.update(version=True), lambda v: v.update(acceptance_evidence=True),
            lambda v: v.update(scope='failure_cause'), lambda v: v.update(token='PRIVATE'),
            lambda v: v.update(selection_phase='PRIVATE'),
            lambda v: v.update(route_state='absent'), lambda v: v.update(route=None),
            lambda v: v['route'].update(attempts=True), lambda v: v['route'].update(retries=0),
            lambda v: v['route'].update(attempts=361, retries=360),
            lambda v: v['route'].update(redraws=33), lambda v: v['route'].update(path_polls=101),
            lambda v: v['route'].update(stage='complete'),
            lambda v: v['route'].update(last_connect_reason='PRIVATE'),
            lambda v: v['route'].update(connect_exit_status=True),
            lambda v: v['preselection'].update(state='known', observed_reason='PRESELECTION_SAMPLE_NO_EXIT'),
            lambda v: v['preselection'].update(uncertainty='PRIVATE'),
            lambda v: v['preselection'].update(records=0),
            lambda v: v['preselection'].update(window_covers_baseline=True),
            lambda v: v['preselection'].update(session='PRIVATE'),
        )
        for mutate in mutations:
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                CHECK['validate_route_diagnostic'](invalid)

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
            self.assertEqual(observed['refresh'], dict(fragment_index=3, renewal=False,
                operation_complete=True, copy_outcomes=None))
            self.assertNotIn('SECRET', json.dumps(result))

    def test_lower_handoff_and_renewal_outcomes_are_closed_and_bounded(self):
        stage = CHECK['handoff_outcomes']
        renew = CHECK['renewal_outcomes']
        for name in ('complete', 'survivor_unavailable', 'replacement_upload_pending',
                'replacement_verification_pending', 'replacement_retention_insufficient',
                'source_delete_unconfirmed'):
            value = stage([dict(index=2, handoff_stage=name, resumed_signed_intent=True,
                replacement_verified_this_pass=False, operation_complete=False,
                provider_key='SECRET', error='SECRET')])
            self.assertEqual(value, [dict(index=2, handoff_stage=name, resumed_signed_intent=True,
                replacement_verified_this_pass=False, operation_complete=False)])
        invalid = stage([dict(index=True, handoff_stage={'SECRET': 'SECRET'},
            resumed_signed_intent=1, replacement_verified_this_pass='SECRET', operation_complete=0)])
        self.assertTrue(all(v is None for v in invalid[0].values()))
        self.assertIsNone(stage([{}, {}]))
        self.assertIsNone(stage('SECRET'))
        self.assertEqual(stage([]), [])
        names = ('retiring_not_renewed', 'explicitly_deleted', 'unavailable_or_grant_invalid',
            'unknown_reservation_use_deposit_retry', 'unconfirmed_retained',
            'renewal_outside_original_grant', 'existing_retention_sufficient', 'confirmed')
        for name in names:
            self.assertEqual(renew([name]), [name])
        self.assertEqual(renew(['SECRET', {'SECRET': 'SECRET'}, True]), [None] * 3)
        self.assertIsNone(renew(['confirmed'] * 4))
        self.assertIsNone(renew('SECRET'))

    def test_four_pending_retirement_turns_fail_with_each_existing_repair_receipt(self):
        namespace = CHECK['finish'].__globals__
        before = dict(placement_authorizations=3, retained_copy_records=11, pending_retirements=3)
        turns = [dict(turns=7 + index, stage='turn_completed', detail=dict(
            maintenance_stage='maintained', repair_stage='pass_limit' if index == 0 else 'pending_handoff',
            attempted_handoffs=1, freshly_verified_replacements=1 if index == 0 else 0,
            pending_retirements=2, physical_payload_charge_upper_bound=CHECK['MAX_CHARGE'],
            fragment_outcomes=[dict(index=1, resumed_signed_intent=True,
                handoff_stage='complete' if index == 0 else 'survivor_unavailable',
                operation_complete=index == 0, replacement_verified_this_pass=index == 0)],
            refresh=dict(fragment_index=(6 + index) % 4, renewal=True, operation_complete=index == 0,
                copy_outcomes=['confirmed'] if index == 0 else ['unconfirmed_retained'])))
            for index in range(4)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'fragment-set').mkdir(mode=0o700)
            CHECK['create'](root / 'fragment-set/placement-authorizations.json', b'synthetic signed placements')
            owner, status, invoke = Mock(side_effect=turns), Mock(side_effect=[before] +
                [dict(before, pending_retirements=2)] * 4), Mock()
            with patch.dict(namespace, run_turn=owner, status=status, invoke=invoke,
                    retained_intent_continuity=Mock(),
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
                self.assertEqual([v['fragment_outcomes'][0]['handoff_stage'] for v in result['retirement_turns']],
                    ['complete'] + ['survivor_unavailable'] * 3)
                self.assertEqual([v['refresh']['copy_outcomes'] for v in result['retirement_turns']],
                    [['confirmed']] + [['unconfirmed_retained']] * 3)
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
        with patch.dict(namespace, checkpoint=lambda *args, **kwargs: dict(turns=6), unlock=lambda root: []), \
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
        CHECK['validate_report'](report(fixture(historical=True)), '1' * 40, historical=True)
        with self.assertRaises(ValueError):
            CHECK['validate_report'](report(value), '1' * 40, historical=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            OLD['write_evidence'](root, value)
            (root / 'private-storage-fragments-layout.json').write_bytes(CONSUMER_FIXTURE['M']['encoded'](value['layout']))
            (root / CHECK['CONSUMERS']['TRANSITION_NAME']).write_bytes(CHECK['CONSUMERS']['canonical'](value['control_transition']))
            for name, phase in value['network'].items():
                (root / f'private-storage-fragments-{name}-layout.json').write_text(json.dumps(phase['layout']))
            (root / 'private-storage-maintenance-lifecycle.json').write_text(json.dumps(value['lifecycle']))
            for path in root.iterdir(): path.chmod(0o600)
            self.assertEqual(CHECK['evidence'](root), value)
            consumer_only = set(CHECK['CONSUMERS']['EXPORT_NAMES']) - set(CHECK['F']['EXPORT_NAMES'])
            self.assertEqual(set(CHECK['EXPORT_NAMES']) - consumer_only - {
                'private-storage-maintenance-smoke.json', 'private-storage-maintenance-evidence.json',
                'private-storage-maintenance-lifecycle-failure.json', 'private-storage-maintenance-route-diagnostic.json',
            'private-storage-maintenance-provider-events.json',
                'private-storage-provider-activity.json',
                'private-storage-maintenance-inventory.json', 'private-storage-maintenance-supervisor.json',
                'private-storage-fixture-correlation.json', 'private-storage-maintenance-helper-acquire.json',
                'storage-consumer-provider-usage.json', 'storage-consumer-failure-boundary.json'},
                {p.name for p in root.iterdir()} - {CHECK['CONSUMERS']['TRANSITION_NAME']})
            (root / 'private-storage-fragments-restored_usage.json').write_text('{}')
            with self.assertRaises(ValueError):
                CHECK['evidence'](root)

    def test_current_report_requires_both_proofs_from_the_same_topology(self):
        consumers = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))['fixture']()
        original = fixture()
        # Bind this synthetic consumer fixture to the original fixture's scope.
        for name in ('expected_peers', 'layout', 'isolation'):
            consumers[name] = copy.deepcopy(original[name])
        CONSUMER_FIXTURE['attach_transition'](consumers)
        combined = dict(report(original), schema_version=4, consumers=consumers)
        CHECK['validate_report'](combined, '1' * 40)
        with self.assertRaises(ValueError):
            CHECK['validate_report'](report(original), '1' * 40)
        for mutation in (lambda v: v.pop('consumers'), lambda v: v['consumers'].update(success=False),
                lambda v: v['maintenance'].update(success=False),
                lambda v: v['consumers']['deleted_usage'][0].update(leases=1),
                lambda v: v['consumers']['expected_peers'].update(client='differentPeer'),
                lambda v: v.update(schema_version=2)):
            invalid = copy.deepcopy(combined)
            mutation(invalid)
            with self.assertRaises((ValueError, KeyError)):
                CHECK['validate_report'](invalid, '1' * 40)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            path.write_text(json.dumps(report(original)))
            result = subprocess.run(['python3', '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                'report', str(path), '1' * 40], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0, 'historical v2 must not pass the current CLI gate')

    def test_current_consumer_v4_cli_requires_new_generation_but_preserves_historical_replay(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            for profile in (1, 3, 4, 5, 6, 7, 8, 9, 10):
                consumers = (CONSUMER_FIXTURE['fixture']() if profile == 1 else network['fixture'](profile))
                combined = dict(report(original), schema_version=9 if profile == 10 else 8 if profile == 9 else 7 if profile == 8 else 6 if profile == 7 else 5 if profile == 6 else 4, consumers=consumers)
                for command in ('report', 'report-consumer-v4', 'report-consumer-v5', 'report-consumer-v6', 'report-consumer-v7', 'report-consumer-v8', 'report-consumer-v9', 'report-consumer-v10'):
                    with self.subTest(profile=profile, command=command):
                        path.write_text(json.dumps(combined))
                        path.chmod(0o600)
                        result = subprocess.run(['python3', '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                            command, str(path), '1' * 40], capture_output=True, timeout=10)
                        self.assertEqual(result.returncode == 0, (command == 'report' and profile not in (6, 7, 8, 9, 10))
                            or (command == 'report-consumer-v4' and profile == 4)
                            or (command == 'report-consumer-v5' and profile == 5)
                            or (command == 'report-consumer-v6' and profile == 6)
                            or (command == 'report-consumer-v7' and profile == 7)
                            or (command == 'report-consumer-v8' and profile == 8)
                            or (command == 'report-consumer-v9' and profile == 9)
                            or (command == 'report-consumer-v10' and profile == 10),
                            result.stdout + result.stderr)

    def test_consumer_v9_flow_profile_preserves_network_custody_and_cleanup_gates(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = dict(report(fixture()), schema_version=8, consumers=network['fixture'](9))
        CHECK['validate_report'](original, '1' * 40, flow_profile=True)
        for options in ({}, dict(append_profile=True), dict(challenge_profile=True),
                dict(stream_profile=True), dict(flow_profile=True, append_profile=True),
                dict(flow_profile=True, challenge_profile=True), dict(flow_profile=True, stream_profile=True),
                dict(flow_profile=True, historical=True), dict(flow_profile=True, previous=True),
                dict(flow_profile=1), dict(flow_profile='true')):
            with self.subTest(options=options), self.assertRaises(ValueError):
                CHECK['validate_report'](original, '1' * 40, **options)
        mutations = (
            lambda v: v.update(schema_version=7), lambda v: v.update(schema_version=8.0),
            lambda v: v.update(source_revision='2' * 40), lambda v: v['cleanup'].update(complete=False),
            lambda v: v['consumers'].update(schema_version=9.0),
            lambda v: v['consumers']['provision'].update(version=8),
            lambda v: v['consumers']['provision'].update(pins=CHECK['CONSUMERS']['PROVISIONER']['load_pins'](8)),
            lambda v: v['consumers']['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['consumers']['deleted_usage'][0].update(leases=1),
        )
        for mutate in mutations:
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError):
                CHECK['validate_report'](value, '1' * 40, flow_profile=True)

    def test_consumer_v10_close_profile_preserves_network_custody_and_cleanup_gates(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = dict(report(fixture()), schema_version=9, consumers=network['fixture'](10))
        CHECK['validate_report'](original, '1' * 40, close_profile=True)
        options = [{}, dict(close_profile=1), dict(close_profile='true')]
        options.extend(dict(close_profile=True, **{k: True}) for k in (
            'flow_profile', 'append_profile', 'challenge_profile', 'stream_profile', 'historical', 'previous'))
        for option in options:
            with self.assertRaises(ValueError): CHECK['validate_report'](original, '1' * 40, **option)
        for mutate in (lambda v: v.update(schema_version=8), lambda v: v.update(schema_version=9.0),
                lambda v: v.update(source_revision='2' * 40), lambda v: v['cleanup'].update(complete=False),
                lambda v: v['consumers'].update(schema_version=10.0),
                lambda v: v['consumers']['provision'].update(version=9),
                lambda v: v['consumers']['provision'].update(pins=CHECK['CONSUMERS']['PROVISIONER']['load_pins'](9)),
                lambda v: v['consumers']['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['consumers']['deleted_usage'][0].update(leases=1)):
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError): CHECK['validate_report'](value, '1' * 40, close_profile=True)

    def test_consumer_v8_is_explicit_and_keeps_network_custody_and_cleanup_gates(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = dict(report(fixture()), schema_version=7, consumers=network['fixture'](8))
        CHECK['validate_report'](original, '1' * 40, append_profile=True)
        for options in ({}, dict(challenge_profile=True), dict(stream_profile=True),
                dict(append_profile=True, challenge_profile=True), dict(append_profile=True, stream_profile=True),
                dict(append_profile=True, historical=True), dict(append_profile=True, previous=True),
                dict(append_profile=1), dict(append_profile='true')):
            with self.subTest(options=options), self.assertRaises(ValueError):
                CHECK['validate_report'](original, '1' * 40, **options)
        mutations = (
            lambda v: v.update(schema_version=6), lambda v: v.update(schema_version=7.0),
            lambda v: v.update(source_revision='2' * 40), lambda v: v['cleanup'].update(complete=False),
            lambda v: v['consumers'].update(schema_version=8.0),
            lambda v: v['consumers']['provision'].update(version=7),
            lambda v: v['consumers']['provision'].update(pins=CHECK['CONSUMERS']['PROVISIONER']['load_pins'](7)),
            lambda v: v['consumers']['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['consumers']['deleted_usage'][0].update(leases=1),
        )
        for mutate in mutations:
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError):
                CHECK['validate_report'](value, '1' * 40, append_profile=True)

    def test_consumer_v7_needs_explicit_outer_generation_and_unchanged_acceptance(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = dict(report(fixture()), schema_version=6, consumers=network['fixture'](7))
        CHECK['validate_report'](original, '1' * 40, challenge_profile=True)
        for options in ({}, dict(stream_profile=True), dict(challenge_profile=True, stream_profile=True),
                dict(challenge_profile=True, historical=True), dict(challenge_profile=True, previous=True)):
            with self.assertRaises(ValueError): CHECK['validate_report'](original, '1' * 40, **options)
        mutations = (
            lambda v: v.update(schema_version=5), lambda v: v.update(schema_version=6.0),
            lambda v: v.update(source_revision='2' * 40), lambda v: v['cleanup'].update(complete=False),
            lambda v: v['consumers'].update(schema_version=7.0),
            lambda v: v['consumers']['provision'].update(pins=CHECK['CONSUMERS']['PROVISIONER']['load_pins'](6)),
            lambda v: v['consumers']['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['consumers']['deleted_usage'][0].update(leases=1),
        )
        for mutate in mutations:
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError):
                CHECK['validate_report'](value, '1' * 40, challenge_profile=True)

    def test_consumer_v6_requires_new_outer_schema_and_retains_cleanup_and_network_gates(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = dict(report(fixture()), schema_version=5, consumers=network['fixture'](6))
        CHECK['validate_report'](original, '1' * 40, stream_profile=True)
        with self.assertRaises(ValueError): CHECK['validate_report'](original, '1' * 40)
        for schema in (4, 5.0, True):
            invalid = copy.deepcopy(original); invalid['schema_version'] = schema
            with self.assertRaises(ValueError): CHECK['validate_report'](invalid, '1' * 40, stream_profile=True)
        invalid = copy.deepcopy(original); invalid['schema_version'] = 4
        with self.assertRaises(ValueError): CHECK['validate_report'](invalid, '1' * 40)
        mutations = (
            lambda v: v.update(source_revision='2' * 40), lambda v: v['cleanup'].update(complete=False),
            lambda v: v['consumers'].update(schema_version=6.0), lambda v: v['consumers']['provision'].update(version=True),
            lambda v: v['consumers']['provision'].update(pins=CHECK['CONSUMERS']['PROVISIONER']['load_pins'](5)),
            lambda v: v['consumers']['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['consumers']['deleted_usage'][0].update(leases=1),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            for mutate in mutations:
                value = copy.deepcopy(original); mutate(value)
                path.write_text(json.dumps(value)); path.chmod(0o600)
                result = subprocess.run(['python3', '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                    'report-consumer-v6', str(path), '1' * 40], capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_current_consumer_v5_cli_keeps_original_network_custody_and_cleanup_gates(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = dict(report(fixture()), schema_version=4, consumers=network['fixture'](5))
        mutations = (
            lambda v: v.update(source_revision='2' * 40), lambda v: v['cleanup'].update(complete=False),
            lambda v: v['consumers'].update(schema_version=5.0), lambda v: v['consumers']['provision'].update(version=True),
            lambda v: v['consumers']['provision'].update(pins=CHECK['CONSUMERS']['PROVISIONER']['load_pins'](4)),
            lambda v: v['consumers']['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['consumers']['deleted_usage'][0].update(leases=1),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    value = copy.deepcopy(original); mutate(value)
                    path.write_text(json.dumps(value)); path.chmod(0o600)
                    result = subprocess.run(['python3', '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                        'report-consumer-v5', str(path), '1' * 40], capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_current_consumer_v4_cli_keeps_source_types_cleanup_and_network_checks(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        original = dict(report(fixture()), schema_version=4, consumers=network['fixture'](4))
        mutations = (
            lambda v: v.update(source_revision='2' * 40),
            lambda v: v['cleanup'].update(complete=False),
            lambda v: v['consumers'].update(schema_version=4.0),
            lambda v: v['consumers'].update(schema_version=True),
            lambda v: v['consumers']['provision'].update(version=4.0),
            lambda v: v['consumers']['provision'].update(version=True),
            lambda v: v['consumers']['provision'].update(pins=CHECK['CONSUMERS']['PROVISIONER']['load_pins'](3)),
            lambda v: v['consumers']['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    value = copy.deepcopy(original)
                    mutate(value)
                    path.write_text(json.dumps(value))
                    path.chmod(0o600)
                    result = subprocess.run(['python3', '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                        'report-consumer-v4', str(path), '1' * 40], capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_original_schema_three_remains_explicit_without_reinterpreting_broker_evidence(self):
        original = fixture(previous=True)
        consumers = CONSUMER_FIXTURE['fixture'](previous=True)
        for name in ('expected_peers', 'layout', 'isolation'):
            consumers[name] = copy.deepcopy(original[name])
        retained = dict(report(original), schema_version=3, consumers=consumers)
        CHECK['validate_report'](retained, '1' * 40, previous=True)
        with self.assertRaises(ValueError): CHECK['validate_report'](retained, '1' * 40)
        with self.assertRaises(ValueError): CHECK['validate_report'](retained, '1' * 40, historical=True)
        retained['maintenance']['control_transition'] = fixture()['control_transition']
        with self.assertRaises(ValueError): CHECK['validate_report'](retained, '1' * 40, previous=True)

    def test_original_upload_control_capture_is_not_relabelled_by_later_transition(self):
        value = fixture()
        original_upload = copy.deepcopy(value['network']['upload'])
        CHECK['validate_evidence'](value)
        self.assertEqual(value['network']['upload'], original_upload)
        for name in ('upload', 'lifecycle', 'restore', 'finish'):
            invalid = copy.deepcopy(value)
            other = 'lifecycle' if name == 'upload' else 'upload'
            invalid['network'][name]['control_privacy'] = copy.deepcopy(value['network'][other]['control_privacy'])
            with self.subTest(phase=name), self.assertRaises(ValueError): CHECK['validate_evidence'](invalid)

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
                CHECK['validate_report'](invalid, '1' * 40, historical=True)

    def test_stale_redundancy_receipts_do_not_end_partial_repair(self):
        keys = ['1' * 64, '2' * 64, '3' * 64]
        value = dict(fully_redundant_from_retained_receipts=True)
        for count in range(3):
            value.update(placement_authorizations=count, pending_retirements=count, retained_copy_records=8 + count)
            self.assertFalse(CHECK['repaired'](value, keys, baseline_fixture()))
        # A third Copying intent, not yet a verified replacement, still stays pending.
        value.update(placement_authorizations=3, pending_retirements=2, retained_copy_records=11)
        self.assertFalse(CHECK['repaired'](value, keys, baseline_fixture()))

    def test_completed_early_handoffs_are_bound_to_actual_status_and_private_identities(self):
        for retired in ((), (0,), (2,), (3,), (0, 2), (0, 3), (2, 3)):
            with self.subTest(retired=retired), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value, keys = custody_fixture(retired)
                private_replacements(root, retired, retired)
                baseline = CHECK['pre_withdrawal'](root, value, keys)
                self.assertEqual(CHECK['validate_baseline'](baseline), list(retired))
                self.assertEqual(baseline['retained_copy_records'], 8 + len(retired))
                for private in (str(root), keys[0], 'grant_hex', 'archive_id', 'lease'):
                    self.assertNotIn(private, json.dumps(baseline))
                CHECK['validate_evidence'](fixture(retired=retired))
                after, _ = custody_fixture(retired, withdrawn=True)
                CHECK['validate_repaired'](after, keys, baseline)
                self.assertTrue(CHECK['repaired'](after, keys, baseline))
        # The actual d3 aggregate shift, not its own proof of authorization.
        self.assertEqual(CHECK['custody_usage']((0,), withdrawn=False), [
            dict(reserved_bytes=0, committed_bytes=262217, leases=2),
            dict(reserved_bytes=0, committed_bytes=524425, leases=4),
            dict(reserved_bytes=0, committed_bytes=786432, leases=3)])

    def test_early_custody_cannot_erase_live_source_or_invent_verified_replacement(self):
        mutations = (
            lambda v: v['fragments'][0]['copies'][0].update(charge='committed'),
            lambda v: v['fragments'][0]['copies'][0].update(last_confirmed_state='Committed'),
            lambda v: v['fragments'][0]['copies'][2].update(charge='reserved'),
            lambda v: v['fragments'][0]['copies'][2].update(last_confirmed_expiry=1),
            lambda v: v['fragments'][0]['copies'][2].update(provider_key='9' * 64),
            lambda v: v.update(uncertain_payload_bytes=1),
            lambda v: v.update(pending_retirements=1),
            lambda v: v.update(placement_authorizations=2),
            lambda v: v.update(retained_copy_records=8),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory() as temporary:
                value, keys = custody_fixture((0,))
                private_replacements(Path(temporary), (0,), (0,))
                mutate(value)
                with self.assertRaises(ValueError):
                    CHECK['pre_withdrawal'](Path(temporary), value, keys)
        for field, replacement in (('phase', 'delete_pending'), ('from', 1), ('to', 3)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value, keys = custody_fixture((0,))
                private_replacements(root, (0,), (0,))
                path = root / 'fragment-set/fragment-0000/replicas.json'
                child = json.loads(path.read_text())
                child['handoff'][field] = replacement
                path.write_text(json.dumps(child))
                with self.assertRaisesRegex(ValueError, 'pre-withdrawal replacement binding'):
                    CHECK['pre_withdrawal'](root, value, keys)
        value, keys = custody_fixture((0, 2, 3))
        with self.assertRaisesRegex(ValueError, 'exhausted withdrawal case'):
            CHECK['pre_withdrawal'](Path('/not-read'), value, keys)

    def test_current_exact_baseline_and_history_cannot_be_cross_labelled(self):
        for mutate in (
            lambda v: v['lifecycle'].pop('pre_withdrawal'),
            lambda v: v['lifecycle']['pre_withdrawal'].update(retired_original_a=[0, 0]),
            lambda v: v['lifecycle']['pre_withdrawal'].update(retired_original_a=[0, 2, 3]),
            lambda v: v['lifecycle']['pre_withdrawal'].update(pending_retirements=1),
            lambda v: v['lifecycle']['pre_withdrawal']['replacement_identities'][0].update(authorization_sha256='f' * 64),
            lambda v: v['restore'].update(pre_withdrawal_verified_replacements=0),
            lambda v: v['restore'].update(post_withdrawal_verified_fragment_indexes=[0, 2]),
            lambda v: v['restore'].update(fresh_verified_replacements=3),
            lambda v: v['restore'].update(pending_retirements=3),
            lambda v: v['restored_usage'][0].update(committed_bytes=0),
            lambda v: v['uploaded_usage'][2].update(leases=2),
        ):
            with self.subTest(mutation=mutate):
                value = fixture(retired=(0,))
                mutate(value)
                with self.assertRaises((ValueError, KeyError)):
                    CHECK['validate_evidence'](value)
        CHECK['validate_evidence'](fixture(historical=True), historical=True)
        with self.assertRaises(ValueError):
            CHECK['validate_evidence'](fixture(historical=True))

    def test_actual_restore_loop_preserves_early_identities_and_requires_complement_readbacks(self):
        for retired in ((), (0,), (0, 2)):
            with self.subTest(retired=retired), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                remaining = sorted(set((0, 2, 3)) - set(retired))
                initial, keys = custody_fixture(retired)
                final, _ = custody_fixture(retired, withdrawn=True)
                private_replacements(root, (0, 2, 3), retired)
                identities = CHECK['replacement_identities'](root, final, keys, retired, withdrawn=True)
                baseline = baseline_fixture(retired)
                baseline['replacement_identities'] = [v for v in identities if v['fragment'] in retired]
                CHECK['create'](root / 'lifecycle-result.json', json.dumps(dict(cursor_after_resume=9,
                    pre_withdrawal=baseline)).encode())
                # The first real post-withdrawal scan can touch only B/C. That
                # observed turn has no repair report and is not a new readback.
                states = [initial, initial]
                turns = [dict(turns=10, detail=dict(maintenance_stage='observed',
                    refresh=dict(fragment_index=1)))]
                for count, index in enumerate(remaining, 1):
                    states.extend([initial, final if count == len(remaining) else initial])
                    turns.append(dict(turns=10 + count, detail=dict(refresh=dict(fragment_index=(9 + count) % 4),
                        freshly_verified_replacements=1, fragment_outcomes=[dict(index=index,
                            replacement_verified_this_pass=True)])))
                def invoke(_binary, _client, arguments, **kwargs):
                    if kwargs.get('expected') == 1:
                        return {}
                    CHECK['create'](arguments[-1], CHECK['F']['FIXTURE'])
                    return dict(final, restored=True, whole_archive_sha256_verified=True,
                        fragment_outcomes=[dict(restored=True, provider_key=keys[1])] * 4)
                namespace = CHECK['restore'].__globals__
                with patch.dict(namespace, checkpoint=Mock(side_effect=[dict(turns=9), dict(turns=10 + len(remaining))]),
                        status=Mock(side_effect=states), run_turn=Mock(side_effect=turns), invoke=invoke,
                        retained_intent_continuity=Mock(),
                        staged_files_absent=Mock(), REPAIR_DIAGNOSTIC=None, REPAIR_TURNS=[]), \
                        patch.dict(CHECK['F'], check_identity=Mock()):
                    actual = CHECK['restore'](root, 'inert-cli', 'inert-socket', keys)
                    self.assertEqual(actual['fresh_verified_replacements'], len(remaining))
                    self.assertEqual(actual['owner_worker_starts'], 1 + len(remaining))
                    self.assertEqual(actual['pending_retirements'], len(remaining))
                    self.assertEqual(actual['post_withdrawal_verified_fragment_indexes'], remaining)
                    self.assertEqual(actual['replacement_identities'], identities)
                    self.assertEqual(actual['uncertain_payload_charge'], sum(CHECK['LENGTHS'][i] for i in remaining))

    def test_twelve_incomplete_turns_retain_primary_code_and_closed_actual_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            CHECK['create'](root / 'lifecycle-result.json', json.dumps(dict(cursor_after_resume=9,
                pre_withdrawal=baseline_fixture((0,)))).encode())
            initial, keys = custody_fixture((0,))
            turns = [dict(turns=10 + index, detail=dict(maintenance_stage='maintained', repair_stage='pending_handoff',
                refresh=dict(fragment_index=(9 + index) % 4), freshly_verified_replacements=0,
                fragment_outcomes=[dict(index=2, handoff_stage='survivor_unavailable',
                    replacement_verified_this_pass=False, private_key='SECRET')])) for index in range(12)]
            namespace = CHECK['restore'].__globals__
            with patch.dict(namespace, checkpoint=Mock(return_value=dict(turns=9)), status=Mock(return_value=initial),
                    run_turn=Mock(side_effect=turns), REPAIR_DIAGNOSTIC=None, REPAIR_TURNS=[],
                    LIFECYCLE_DIAGNOSTIC=None, SAMPLER_DIAGNOSTIC={}), patch.dict(CHECK['F'], check_identity=Mock()):
                with self.assertRaisesRegex(ValueError, '^bounded repair turns incomplete$') as error:
                    CHECK['restore'](root, 'inert-cli', 'inert-socket', keys)
                receipt = CHECK['failure_receipt'](error.exception)
                self.assertEqual(receipt['version'], 2)
                self.assertEqual(receipt['code'], 'repair_turns_exhausted')
                self.assertEqual(len(receipt['repair_turns']), 12)
                self.assertEqual(receipt['repair']['latest_status']['copy_counts'], [3, 2, 2, 2])
                self.assertEqual(receipt['repair_turns'][-1]['cursor'], 21)
                self.assertEqual(receipt['repair_turns'][-1]['fragment_outcomes'][0]['handoff_stage'], 'survivor_unavailable')
                self.assertNotIn('SECRET', json.dumps(receipt))
                self.assertLess(len(json.dumps(receipt)), 16384)

    def test_missing_maintained_outcomes_are_not_an_observed_turn(self):
        for detail in (dict(maintenance_stage='maintained'),
                dict(maintenance_stage='observed', freshly_verified_replacements=1),
                dict(maintenance_stage='observed', fragment_outcomes=None)):
            with self.subTest(detail=detail), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                CHECK['create'](root / 'lifecycle-result.json', json.dumps(dict(cursor_after_resume=9,
                    pre_withdrawal=baseline_fixture())).encode())
                value, keys = custody_fixture()
                with patch.dict(CHECK['restore'].__globals__, checkpoint=Mock(return_value=dict(turns=9)),
                        status=Mock(return_value=value), run_turn=Mock(return_value=dict(turns=10,
                            detail=dict(refresh=dict(fragment_index=1), **detail))),
                        REPAIR_DIAGNOSTIC=None, REPAIR_TURNS=[]):
                    with self.assertRaisesRegex(ValueError, 'new replacement readbacks incomplete'):
                        CHECK['restore'](root, 'inert-cli', 'inert-socket', keys)

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
                         'flow-consumer-publish.json', 'flow-consumer-exercise.json', 'flow-consumer-finish.json',
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
            add('flow-consumer-unknown.json')
            with self.assertRaises(ValueError):
                CHECK['cleanup'](root)
            self.assertTrue((root / 'identity.key').exists())
            (root / 'flow-consumer-unknown.json').unlink()
            self.assertTrue(all(CHECK['cleanup'](root).values()))
            self.assertFalse(root.exists())
            self.assertTrue(all(CHECK['cleanup'](root).values()))
            self.assertEqual(sentinel.read_text(), 'retain')


class UploadFailureProjection(unittest.TestCase):
    def setUp(self):
        self.namespace = CHECK['upload_invoke'].__globals__
        self.state = patch.dict(self.namespace, UPLOAD_DIAGNOSTIC=None, STAGE='upload',
            LIFECYCLE_DIAGNOSTIC=None, SAMPLER_DIAGNOSTIC={})
        self.state.start()
        self.addCleanup(self.state.stop)

    @staticmethod
    def report(version=2, failures=1):
        diagnostic = dict(version=version, omitted_failures=0, failures=[])
        for index in range(failures):
            failure = dict(fragment_index=index // 2, copy_index=index % 2,
                operation='reserve', stage='agent_ready', category='agent_rejected',
                agent_code='CONTENT_UNAVAILABLE')
            if version >= 2:
                failure['agent_detail'] = dict(stage='route_connect', deadline_scope='none')
            if version >= 3:
                failure['agent_detail']['tls_failure'] = None
            if version == 4:
                failure.update(stage='wire_receipt', category='io', operation='finalize', agent_code=None,
                    agent_detail=None, agent_outcome=dict(status='observed', detail=dict(
                        phase='remote_receipt_read', category='timeout', deadline_scope='remote_wire')))
            diagnostic['failures'].append(failure)
        return dict(operation='private_storage_fragments_deposit', operation_complete=False,
            fragment_count=4, copies_per_fragment=2, deposit_diagnostics=diagnostic,
            providers=[dict(provider_key='PRIVATE_KEY')], private_path='PRIVATE_PATH')

    def observe(self, report, operation='deposit'):
        raw = json.dumps(report).encode() if type(report) is dict else report
        return CHECK['upload_observation'](operation, 1, raw, b'PRIVATE_STDERR')

    def test_exact_call_labels_and_both_existing_diagnostic_versions(self):
        for version in (1, 2, 3, 4):
            for count in (0, 1, 8):
                source = self.report(version, count)
                for operation in CHECK['UPLOAD_OPERATIONS']:
                    with self.subTest(version=version, count=count, operation=operation):
                        value = self.observe(source, operation)
                        self.assertEqual(set(value), {'operation', 'exit_status', 'stdout_state',
                            'stderr_state', 'deposit_diagnostics_state', 'deposit_diagnostics'})
                        self.assertEqual(value['operation'], operation)
                        self.assertEqual(value['exit_status'], 1)
                        applicable = operation in ('deposit', 'redeposit')
                        self.assertEqual(value['deposit_diagnostics_state'],
                            'observed' if applicable else 'not_applicable')
                        self.assertEqual(value['deposit_diagnostics'],
                            source['deposit_diagnostics'] if applicable else None)
                        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_upload_outcome_projects_only_valid_closed_observation_without_success_or_custody_claim(self):
        source = self.report(4)
        value = self.observe(source)
        self.assertEqual(value['deposit_diagnostics_state'], 'observed')
        self.assertEqual(value['deposit_diagnostics'], source['deposit_diagnostics'])
        self.assertNotIn('success', value); self.assertNotIn('custody', json.dumps(value))
        for mutate in (lambda f: f.pop('agent_outcome'), lambda f: f['agent_outcome'].pop('detail'),
                lambda f: f['agent_outcome'].update(raw='PRIVATE'),
                lambda f: f['agent_outcome']['detail'].update(original_request_id='PRIVATE'),
                lambda f: f['agent_outcome']['detail'].update(category='cancelled'),
                lambda f: f.update(stage='signed_request')):
            bad = copy.deepcopy(source); mutate(bad['deposit_diagnostics']['failures'][0])
            result = self.observe(bad)
            self.assertEqual(result['deposit_diagnostics_state'], 'invalid')
            self.assertIsNone(result['deposit_diagnostics']); self.assertNotIn('PRIVATE', json.dumps(result))

    def test_invalid_missing_oversized_and_duplicate_reports_never_export_raw_data(self):
        mutations = [
            lambda v: v.update(operation='PRIVATE_OPERATION'),
            lambda v: v.update(operation_complete=True),
            lambda v: v.update(operation_complete=0),
            lambda v: v.update(fragment_count=True),
            lambda v: v.update(copies_per_fragment=3),
            lambda v: v.update(deposit_diagnostics=None),
            lambda v: v['deposit_diagnostics'].update(version=True),
            lambda v: v['deposit_diagnostics'].update(version=3),
            lambda v: v['deposit_diagnostics'].update(omitted_failures=1),
            lambda v: v['deposit_diagnostics'].update(raw='PRIVATE_PAYLOAD'),
            lambda v: v['deposit_diagnostics']['failures'].append(
                copy.deepcopy(v['deposit_diagnostics']['failures'][0])),
            lambda v: v['deposit_diagnostics']['failures'][0].update(fragment_index=4),
            lambda v: v['deposit_diagnostics']['failures'][0].update(copy_index=True),
            lambda v: v['deposit_diagnostics']['failures'][0].update(raw='PRIVATE_PAYLOAD'),
            lambda v: v['deposit_diagnostics']['failures'][0].update(operation='PRIVATE_PATH'),
            lambda v: v['deposit_diagnostics']['failures'][0].update(stage='PRIVATE_PATH'),
            lambda v: v['deposit_diagnostics']['failures'][0].update(category='PRIVATE_ERROR'),
            lambda v: v['deposit_diagnostics']['failures'][0].update(agent_code='PRIVATE_CODE'),
            lambda v: v['deposit_diagnostics']['failures'][0].pop('agent_detail'),
            lambda v: v['deposit_diagnostics']['failures'][0]['agent_detail'].update(raw='PRIVATE_KEY'),
        ]
        for change in mutations:
            report = self.report()
            change(report)
            value = self.observe(report)
            self.assertEqual(value['deposit_diagnostics_state'], 'invalid')
            self.assertIsNone(value['deposit_diagnostics'])
            self.assertNotIn('PRIVATE', json.dumps(value))
        for raw in (b'PRIVATE_INVALID_JSON', b'[]', b'{"operation":1,"operation":2}',
                    b' ' * 16385, b'\xff', b'[' * 1100):
            value = self.observe(raw)
            self.assertEqual(value['deposit_diagnostics_state'], 'invalid')
            self.assertIsNone(value['deposit_diagnostics'])
        value = self.observe(self.report(failures=9))
        self.assertEqual(value['deposit_diagnostics_state'], 'invalid')
        source = self.report()
        source.pop('deposit_diagnostics')
        self.assertEqual(self.observe(source)['deposit_diagnostics_state'], 'missing')
        raw = json.dumps(self.report()).encode()
        for size, expected in ((16384, 'observed'), (16385, 'invalid')):
            value = CHECK['upload_observation']('deposit', 1, raw, b'x' * size)
            self.assertEqual(value['deposit_diagnostics_state'], expected)
        padded = raw + b' ' * (16384 - len(raw))
        self.assertEqual(self.observe(padded)['deposit_diagnostics_state'], 'observed')
        self.assertEqual(self.observe(padded + b' ')['stdout_state'], 'oversize')

    def test_projection_uses_the_same_closed_agent_deadline_matrix(self):
        stages = ('unobserved', 'route_connect', 'control_selection', 'provider_lookup',
            'provider_cardinality', 'offer_validity', 'stream_open', 'tls_handshake', 'challenge')
        for stage in stages:
            for scope in ('none', 'operation', 'exchange'):
                for code in ('CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY'):
                    report = self.report()
                    failure = report['deposit_diagnostics']['failures'][0]
                    failure.update(agent_code=code, agent_detail=dict(stage=stage, deadline_scope=scope))
                    valid = (stage != 'unobserved' or scope == 'operation') \
                        and (scope != 'exchange' or stage in stages[-3:]) \
                        and (scope == 'none' or code == 'CONTENT_UNAVAILABLE')
                    self.assertEqual(self.observe(report)['deposit_diagnostics_state'],
                        'observed' if valid else 'invalid', (stage, scope, code))

    def test_nonzero_observer_keeps_original_error_and_does_not_change_success(self):
        invoke = CHECK['F']['invoke']
        process = Mock(returncode=7)
        process.communicate.return_value = (json.dumps(self.report()).encode(), b'PRIVATE_STDERR')
        process.poll.return_value = 7
        for problem in (ValueError('PRIVATE_ERROR'), TypeError('PRIVATE_ERROR'),
                        SystemExit('PRIVATE_ERROR'), KeyboardInterrupt()):
            observer = Mock(side_effect=problem)
            with patch.object(CHECK['subprocess'], 'Popen', return_value=process):
                with self.assertRaisesRegex(ValueError, '^private replica CLI operation failed$'):
                    invoke('private-cli', 'private-socket', [], deadline=900, failure_observer=observer)
            observer.assert_called_once_with(7, *process.communicate.return_value)
            process.communicate.assert_called_with(timeout=900)
        process.returncode = process.poll.return_value = 0
        process.communicate.return_value = (b'{"ok":true}', b'')
        observer = Mock(side_effect=AssertionError('must not run on success'))
        with patch.object(CHECK['subprocess'], 'Popen', return_value=process):
            self.assertEqual(invoke('private-cli', 'private-socket', [], failure_observer=observer), {'ok': True})
        observer.assert_not_called()
        process.terminate.assert_not_called()

    def test_failure_is_this_call_not_the_previous_deposit_or_secondary_sampler(self):
        process = Mock(returncode=7)
        process.communicate.return_value = (json.dumps(self.report()).encode(), b'PRIVATE_STDERR')
        process.poll.return_value = 7
        with patch.object(CHECK['subprocess'], 'Popen', return_value=process):
            with self.assertRaises(ValueError) as failure:
                CHECK['upload_invoke']('deposit', 'private-cli', 'private-socket', [], deadline=900)
        self.namespace['SAMPLER_DIAGNOSTIC'].update(phase='final_drain', operation='route_query',
            code='process', samples=1, completed=0, failed=0)
        value = CHECK['failure_receipt'](failure.exception)
        self.assertEqual((value['version'], value['code'], value['upload']['operation']), (3, 'cli_exit', 'deposit'))
        self.assertEqual(value['upload']['deposit_diagnostics_state'], 'observed')
        self.assertEqual(value['sampler']['phase'], 'final_drain')
        original = subprocess.TimeoutExpired('PRIVATE_COMMAND', 900)
        process.communicate.side_effect = original
        with patch.object(CHECK['subprocess'], 'Popen', return_value=process):
            with self.assertRaises(subprocess.TimeoutExpired) as failure:
                CHECK['upload_invoke']('progress', 'private-cli', 'private-socket', [], deadline=900)
        self.assertIs(failure.exception, original)
        value = CHECK['failure_receipt'](failure.exception)
        self.assertEqual(value['code'], 'cli_timeout')
        self.assertEqual(value['upload']['operation'], 'progress')
        self.assertIsNone(value['upload']['exit_status'])
        self.assertIsNone(value['upload']['deposit_diagnostics'])
        self.assertNotIn('PRIVATE', json.dumps(value))
        self.namespace['STAGE'] = 'restore'
        historical = CHECK['failure_receipt'](ValueError('private replica CLI operation failed'))
        self.assertEqual(historical['version'], 2)
        self.assertNotIn('upload', historical)

    def test_fragment_upload_labels_preserve_calls_deadlines_and_short_circuit(self):
        upload = CHECK['F']['upload']
        namespace = upload.__globals__
        expected = ['create', 'deposit', 'progress', 'redeposit', 'renew', 'status']
        for stop in [None, *expected]:
            seen = []
            def invoke(operation, binary, socket, arguments, **options):
                seen.append((operation, arguments[:3], options))
                if operation == stop:
                    raise ValueError('private replica CLI operation failed')
                return {}
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'input.bin').write_bytes(b'inert')
                with patch.dict(namespace, validate_cli=Mock(), existing=lambda root: [],
                        identity_digest=Mock(return_value=b''), create=Mock(), check_identity=Mock(),
                        staged_files_absent=Mock(), private_file=Mock()):
                    if stop is None:
                        upload(root, 'private-cli', 'private-socket', ['a', 'b', 'c'], invoke_operation=invoke)
                    else:
                        with self.assertRaisesRegex(ValueError, 'private replica CLI operation failed'):
                            upload(root, 'private-cli', 'private-socket', ['a', 'b', 'c'], invoke_operation=invoke)
            labels = expected if stop is None else expected[:expected.index(stop) + 1]
            self.assertEqual([item[0] for item in seen], labels)
            for operation, command, options in seen:
                self.assertEqual(command, ['storage', 'fragments', 'deposit' if operation == 'redeposit' else operation])
                self.assertEqual(options, {} if operation in ('create', 'status') else {'deadline': 900})

    def test_foreground_seed_is_separate_and_a_new_upload_clears_stale_observation(self):
        process = Mock(returncode=1)
        process.communicate.return_value = (json.dumps(self.report()).encode(), b'PRIVATE_STDERR')
        process.poll.return_value = 1
        self.namespace['UPLOAD_DIAGNOSTIC'] = self.observe(self.report())
        with patch.dict(CHECK['F'], upload=Mock(return_value={})), \
                patch.dict(self.namespace, peer_args=lambda *args: []), \
                patch.object(CHECK['subprocess'], 'Popen', return_value=process):
            with self.assertRaises(ValueError) as failure:
                CHECK['upload'](Path('/private'), 'private-cli', 'private-socket', ['a', 'b', 'c'])
            value = CHECK['failure_receipt'](failure.exception)
        self.assertEqual(value['upload']['operation'], 'foreground_seed')
        self.assertEqual(value['upload']['deposit_diagnostics_state'], 'not_applicable')
        self.assertIsNone(value['upload']['deposit_diagnostics'])
        with patch.dict(CHECK['F'], upload=Mock(side_effect=OSError('PRIVATE_PATH'))):
            with self.assertRaises(OSError) as failure:
                CHECK['upload'](Path('/private'), 'private-cli', 'private-socket', ['a', 'b', 'c'])
        self.assertNotIn('upload', CHECK['failure_receipt'](failure.exception))


if __name__ == '__main__':
    unittest.main()
