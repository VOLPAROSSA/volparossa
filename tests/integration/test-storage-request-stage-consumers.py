#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert schema-3 private IPC, target binding and RO-export tests; no core/SDK."""
import copy
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-fixture-correlation-sampler.py'))
G = M['RequestCapture'].observe.__globals__
U = runpy.run_path(str(HERE / 'storage-consumer-provider-usage.py'))
CONTROLS = tuple(Path('/fixed') / node for node in M['NODES'])
HASH = 'ab' * 32
FINGERPRINT = 'cd' * 32


def fixture(root, index=2):
    app = root / 'image'
    copy_dir = app / 'archive/fragment-0002/copy-0'
    copy_dir.mkdir(parents=True)
    for path in (root, app, app / 'archive', copy_dir.parent, copy_dir): path.chmod(0o700)
    keys = [list(bytes([value]) * 32) for value in (31, 32, 33)]
    journal = dict(archive_id=list(bytes([44]) * 32), provider_key=keys[index])
    config = dict(providers=[dict(key=bytes(key).hex()) for key in keys])
    manifest = dict(providers=[dict(key=key) for key in keys], fragments=[dict(copies=[dict(
        provider=index, archive_id=journal['archive_id'])]) for _ in range(4)])
    for path, value in ((copy_dir / 'archive.json', journal), (app / 'storage.json', config),
            (app / 'archive/fragments.json', dict(manifest=manifest))):
        path.write_text(json.dumps(value)); path.chmod(0o600)
    return dict(version=3, target=dict(archive_id=bytes(journal['archive_id']).hex(),
        provider_key=bytes(journal['provider_key']).hex(), operation='reserve'), provider_index=index)


def observation(role='client', stage='backend_entered', worker='entered', digest=HASH, late=False):
    return dict(request_digest=digest, operation='reserve',
        provider_stage='unobserved' if role == 'client' else stage,
        worker_state='unobserved' if role == 'client' else worker,
        worker_returned_after_terminal=False if role == 'client' else late,
        reserve_timing=dict(before_request_flush_elapsed='90_to_120s', before_request_flush_remaining='under_1s',
            receipt_wait_elapsed='under_1s', receipt_wait_remaining='under_1s') if role == 'client' else None)


def row(role='client', **options):
    return dict(role=role, fingerprint=FINGERPRINT, phase='closing' if role == 'client' else 'storage_operation',
        terminal='operation_error' if role == 'client' else 'cancelled', flow_acquire=None,
        request_observation=observation(role, **options))


def response(action, records=(), unavailable=False):
    return dict(version=3, kind='storage-fixture-correlation', state='unavailable' if unavailable else
        dict(arm='armed', clients='observed', providers='observed', disarm='disarmed')[action],
        incomplete=unavailable, records=list(records), diagnostic_only=True, acceptance_evidence=False,
        target_scoped=True, complete_phase_history=False)


def queries(events, *, index=2, provider=None, missing=False, duplicate=False, unavailable=None, foreign=False):
    def query(binary, control, action, epoch, fingerprints, stopped, version=1, target=None, deadline=None):
        M['request'](action, epoch, fingerprints, version, target)
        events.append((action, control))
        records = [row()] if action == 'clients' else []
        if action == 'providers' and not missing:
            actual = 1 if foreign else index
            if control == CONTROLS[actual + 1] or (duplicate and control == CONTROLS[(actual + 1) % 3 + 1]):
                records = [provider or row('provider')]
        value = response(action, records, unavailable=action == unavailable)
        if value['state'] == 'unavailable': value['records'] = []
        M['reply'](value, action, fingerprints, version)
        return value['state'], value, True
    return query


def receive(channel):
    raw = bytearray()
    while not raw.endswith(b'\n'):
        data = channel.recv(4096)
        if not data: raise AssertionError('unexpected_private_pipe_eof')
        raw.extend(data)
        if len(raw) > 4096: raise AssertionError('private_pipe_bound')
    return json.loads(raw)


class ExactRequest(unittest.TestCase):
    def test_existing_child_supervisor_passes_only_the_opted_private_fd_and_preserves_exit_and_pipes(self):
        app = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binding = fixture(root)
            code = '''
import json,os,socket,sys
s=socket.socket(fileno=int(os.environ['STORAGE_PROOF_REQUEST_STAGE_FD']))
f=s.makefile('rwb',buffering=0)
f.write((json.dumps(BINDING)+'\\n').encode())
assert json.loads(f.readline())['state']=='armed'
f.write(b'{"version":3,"outcome":"targeted_failure"}\\n')
assert json.loads(f.readline())['state']=='closed'
f.close();s.close()
print('{"original_failure":true}')
print('/private/canary',file=sys.stderr)
sys.exit(1)
'''.replace('BINDING', repr(binding))
            deadline = time.monotonic() + 5
            with patch.dict(G, controls_for=lambda _: CONTROLS, query=queries(events)):
                with M['capture_request'](Path('/core'), root, root, deadline) as observer:
                    result = app['run_child']([sys.executable, '-B', '-c', code], deadline, request_stage=observer)
                    self.assertEqual(observer.child.fileno(), -1)
            self.assertEqual(result, (1, b'{"original_failure":true}\n', b'/private/canary\n'))
            self.assertFalse(observer.thread.is_alive())
            public = (root / M['private_name']('publish')).read_text()
            self.assertNotIn('canary', public)
            self.assertEqual(json.loads(public)['state'], 'observed')

    def capture(self, *, index=2, outcome='targeted_failure', **options):
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binding = fixture(root, index)
            with patch.dict(G, controls_for=lambda _: CONTROLS, query=queries(events, index=index, **options)), \
                    patch.object(subprocess, 'Popen', side_effect=AssertionError('no_real_process')):
                with M['capture_request'](Path('/core'), root, root, time.monotonic() + 3) as observer:
                    self.assertIsNotNone(observer)
                    observer.child.settimeout(2)
                    observer.child.sendall(M['encoded'](binding))
                    armed = receive(observer.child)
                    events.append(('original_deposit', None))
                    observer.child.sendall(M['encoded'](dict(version=3, outcome=outcome)))
                    self.assertEqual(receive(observer.child), dict(version=3, state='closed'))
                self.assertFalse(observer.thread.is_alive())
                self.assertEqual(observer.parent.fileno(), -1)
                self.assertEqual(observer.child.fileno(), -1)
            value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
            raw = M['encoded'](value).decode()
            for private in (HASH, FINGERPRINT, binding['target']['archive_id'], binding['target']['provider_key']):
                self.assertNotIn(private, raw)
            self.assertNotIn('/fixed', raw)
            return value, events, armed

    def test_real_private_ipc_arms_before_original_deposit_and_disarms_before_joined_publication(self):
        value, events, armed = self.capture()
        self.assertEqual(armed, dict(version=3, state='armed'))
        self.assertEqual([kind for kind, _ in events], ['arm'] * 4 + ['original_deposit', 'clients']
            + ['providers'] * 3 + ['disarm'] * 4)
        self.assertEqual(value['state'], 'observed')
        self.assertEqual(value['record']['provider_role'], 'c')
        self.assertEqual(value['record']['worker_state'], 'entered')
        self.assertEqual(value['later_worker_completion'], 'unknown')
        self.assertFalse(value['acceptance_evidence'])
        self.assertFalse(value['causal_attribution'])
        self.assertFalse(value['remote_cleanup_proven'])

    def test_actual_private_journal_association_selects_provider_role_without_index_guess(self):
        for index, role in enumerate(M['ROLES']):
            value, _, _ = self.capture(index=index)
            self.assertEqual(value['record']['provider_role'], role)

    def test_matching_tls_fingerprint_with_different_request_digest_is_unavailable(self):
        value, _, _ = self.capture(provider=row('provider', digest='ef' * 32))
        self.assertEqual((value['state'], value['reason'], value['record']), ('unavailable', 'missing', None))

    def test_missing_ambiguous_foreign_and_expired_observations_never_identify_cause(self):
        for options, reason in ((dict(missing=True), 'missing'), (dict(duplicate=True), 'ambiguous'),
                (dict(foreign=True), 'query'), (dict(unavailable='clients'), 'query')):
            with self.subTest(options=options):
                value, _, _ = self.capture(**options)
                self.assertEqual((value['state'], value['reason'], value['record']), ('unavailable', reason, None))
                self.assertFalse(value['fragment_copy_binding'])

    def test_untargeted_failure_and_failed_arming_cannot_export_partial_matches(self):
        value, events, _ = self.capture(outcome='untargeted_failure')
        self.assertEqual(value['reason'], 'untargeted_failure')
        self.assertFalse(any(action == 'clients' for action, _ in events))
        value, _, armed = self.capture(unavailable='arm')
        self.assertEqual(armed['state'], 'unavailable')
        self.assertEqual(value['reason'], 'arm')
        self.assertTrue(value['disarmed'])

    def test_late_backend_return_and_receipt_flush_are_separate_observations(self):
        for stage, late in (('backend_entered', True), ('backend_returned', True), ('receipt_flush_returned', False)):
            value, _, _ = self.capture(provider=row('provider', stage=stage, worker='returned_ok', late=late))
            self.assertEqual(value['record']['provider_stage'], stage)
            self.assertEqual(value['record']['worker_state'], 'returned_ok')
            self.assertEqual(value['record']['worker_returned_after_terminal'], late)
            self.assertEqual(value['later_worker_completion'], 'unknown')

    def test_closed_unknown_or_oversized_ipc_is_unavailable_and_cannot_mask_original_error(self):
        for raw in (b'', b'{"raw_error":"/private/key-canary"}\n', b'x' * 4097):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); root.chmod(0o700)
                with self.assertRaisesRegex(RuntimeError, '^original_deposit_failure$'):
                    with M['capture_request']('/core', root, root, time.monotonic() + 1) as observer:
                        observer.child.settimeout(2)
                        if raw: observer.child.sendall(raw)
                        observer.child.shutdown(socket.SHUT_WR)
                        raise RuntimeError('original_deposit_failure')
                self.assertFalse(observer.thread.is_alive())
                value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
                self.assertEqual(value['state'], 'unavailable')
                self.assertNotIn('canary', M['encoded'](value).decode())

    def test_original_absolute_deadline_prevents_new_query_spawn(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('expired_query_spawn')):
            result = M['query']('/core', CONTROLS[0], 'arm', 'aa' * 16, [], threading.Event(), 3,
                dict(archive_id='bb' * 32, provider_key='cc' * 32, operation='reserve'), time.monotonic() - 1)
        self.assertEqual(result, ('timeout', None, True))

    def test_binding_rejects_wrong_copy_manifest_provider_raw_fields_and_links(self):
        for change in ('archive', 'provider', 'index', 'operation', 'extra', 'bool', 'symlink'):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = fixture(root)
                path = root / 'image/archive/fragment-0002/copy-0/archive.json'
                if change == 'archive': value['target']['archive_id'] = 'ee' * 32
                elif change == 'provider': value['target']['provider_key'] = 'ee' * 32
                elif change == 'index': value['provider_index'] = 0
                elif change == 'operation': value['target']['operation'] = 'delete'
                elif change == 'extra': value['raw_error'] = '/private/canary'
                elif change == 'bool': value['provider_index'] = True
                else:
                    target = path.with_name('retained.json'); path.rename(target); path.symlink_to(target)
                with self.assertRaises((ValueError, OSError)):
                    M['private_binding'](root, value)

    def test_public_projection_rejects_extra_fields_fake_acceptance_invalid_worker_or_timing(self):
        good, _, _ = self.capture()
        for pointer, key, invalid in ((None, 'request_digest', HASH), (None, 'acceptance_evidence', True),
                (None, 'fragment_index', True), ('record', 'provider_role', '/private/key'),
                ('record', 'worker_state', 'unobserved'), ('record', 'reserve_timing', dict(raw='canary'))):
            value = copy.deepcopy(good)
            (value if pointer is None else value[pointer])[key] = invalid
            with self.assertRaises((ValueError, TypeError)):
                M['validate'](value)


class ProviderUsage(unittest.TestCase):
    def test_unjoined_provider_is_not_opened_and_observed_usage_never_proves_owner_cleanup(self):
        calls = []
        def observe(path):
            calls.append(path)
            return dict(version=1, state='observed', reason=None, reserved_bytes=12, committed_bytes=34,
                leases=2, owner_cleanup_proven=False)
        with tempfile.TemporaryDirectory() as temporary:
            value = U['collect'](Path(temporary), '010', observe)
        self.assertEqual(len(calls), 1)
        self.assertIn('state-relay5', str(calls[0]))
        self.assertEqual([row['state'] for row in value['providers']], ['unavailable', 'observed', 'unavailable'])
        self.assertFalse(value['owner_reconciliation_proven'])
        self.assertFalse(value['remote_deletion_proven'])

    def test_ro_failure_unknown_fields_private_canary_and_invalid_counts_are_not_exported(self):
        for result in (dict(raw_error='/private/canary'), dict(version=1, state='observed', reason=None,
                reserved_bytes=True, committed_bytes=0, leases=0, owner_cleanup_proven=False)):
            with tempfile.TemporaryDirectory() as temporary:
                value = U['collect'](Path(temporary), '111', lambda _: result)
            self.assertTrue(all(row['state'] == 'unavailable' for row in value['providers']))
            self.assertNotIn('canary', U['encoded'](value).decode())
        value = U['report']([U['empty'](role) for role in U['ROLES']])
        value['raw_error'] = '/private/canary'
        with self.assertRaises(ValueError): U['validate'](value)
        with self.assertRaises(ValueError): U['decode'](b'{"version":1,"version":1}')

    def test_shell_success_keeps_original_finish_deletion_checks_before_snapshot(self):
        text = (HERE / 'storage-consumer-maintenance-smoke.sh').read_text()
        run = text.split('private_storage_consumer_run() {', 1)[1]
        self.assertLess(run.index('private_storage_consumer_phase finish'), run.index('consumer_deleted_usage'))
        self.assertLess(run.index('CONSUMER_PROVIDER_CLEANUP_INCOMPLETE'), run.index('private_storage_consumer_cleanup'))
        cleanup = text.split('private_storage_consumer_cleanup() {', 1)[1].split('\n}', 1)[0]
        self.assertLess(cleanup.index('private_storage_consumer_usage_snapshot'), cleanup.index('private_storage_consumer_private cleanup'))
        hook = text.split('private_storage_consumer_usage_snapshot() {', 1)[1].split('\n}', 1)[0]
        self.assertLess(hook.index('private_storage_consumer_private quiesced'), hook.index('systemctl stop'))
        self.assertLess(hook.index('done'), hook.index(' collect '))
        for forbidden in ('storage local status', 'storage peer delete', 'private_storage_replicas_usage'):
            self.assertNotIn(forbidden, hook)

    def test_failure_export_validates_usage_and_schema3_on_normal_emergency_and_final_paths(self):
        text = (HERE / 'run-alpha-topology-vm.sh').read_text()
        self.assertIn('"storage-consumer-provider-usage.json"', text)
        self.assertIn('if original_size > 4096 or original_size != len(data)', text)
        self.assertIn('storage-consumer-provider-usage.py validate-stdin', text)
        normal = (HERE / 'private-storage-maintenance-smoke.py').read_text()
        self.assertIn("usage['read'](Path(args[1]) / usage['NAME'])", normal)
        topology = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertIn('storage-provider-usage-snapshot.py storage-consumer-provider-usage.py', topology)


if __name__ == '__main__': unittest.main()
