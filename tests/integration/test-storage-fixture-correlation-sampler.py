#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert private-pipe/closed-projection tests, not actual peer evidence."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import runpy
import select
import signal
import stat
import subprocess
import sys
import tempfile
import tarfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-fixture-correlation-sampler.py'))
G = M['query'].__globals__
EPOCH = '0123456789abcdef' * 2
FINGERPRINT = '123456789abcdef0' * 4
CONTROLS = tuple(Path('/fixed') / node for node in M['NODES'])


def row(role='client', fingerprint=FINGERPRINT, phase=None, terminal='active'):
    return dict(role=role, fingerprint=fingerprint,
        phase=phase or ('client_challenge' if role == 'client' else 'storage_grant_read_verify'), terminal=terminal)


def reply(action='clients', records=None, incomplete=False, version=1):
    records = copy.deepcopy(records or [])
    if version == 2:
        for record in records: record.setdefault('flow_acquire', None)
    return dict(version=version, kind='storage-fixture-correlation',
        state=dict(arm='armed', clients='observed', providers='observed', disarm='disarmed')[action],
        records=records, incomplete=incomplete, diagnostic_only=True, acceptance_evidence=False)


def query_fixture(provider_records=None, client_records=None, incomplete=False):
    def query(binary, control, action, epoch, fingerprints, stopped, version=1):
        M['request'](action, epoch, fingerprints, version)
        records = []
        if action == 'clients': records = client_records if client_records is not None else [row()]
        elif action == 'providers':
            records = (provider_records or {}).get(str(control), [])
            records = [record for record in records if record['fingerprint'] in fingerprints]
        value = reply(action, records, incomplete and action == 'providers', version)
        M['reply'](value, action, fingerprints, version)
        return value['state'], value, True
    return query


class Contracts(unittest.TestCase):
    def test_fixed_control_sockets_use_existing_nonroot_worker_group(self):
        work = Path('/fixed/work')
        socket = dict(st_mode=stat.S_IFSOCK | 0o660, st_uid=1001, st_gid=2001)
        parent = dict(st_mode=stat.S_IFDIR | 0o750, st_uid=1001, st_gid=2001)
        def check(socket, parent, accessible=True, uid=1002, groups=(2001,)):
            with patch.object(Path, 'lstat', lambda path: SimpleNamespace(**(socket if path.name == 'agent.sock' else parent))), \
                    patch.object(G['os'], 'geteuid', return_value=uid), \
                    patch.object(G['os'], 'getegid', return_value=1002), \
                    patch.object(G['os'], 'getgroups', return_value=groups), \
                    patch.object(G['os'], 'access', return_value=accessible):
                return M['controls_for'](work)
        self.assertEqual(check(socket, parent), tuple(work / f'runtime-{node}/control/agent.sock' for node in M['NODES']))
        for changed in (dict(socket, st_uid=1002), dict(socket, st_uid=0),
                dict(socket, st_mode=stat.S_IFSOCK | 0o666), dict(socket, st_mode=stat.S_IFREG | 0o660)):
            with self.assertRaises(ValueError): check(changed, parent)
        for changed in (dict(parent, st_uid=1002), dict(parent, st_gid=3001), dict(parent, st_mode=stat.S_IFDIR | 0o770)):
            with self.assertRaises(ValueError): check(socket, changed)
        for kwargs in (dict(uid=0), dict(accessible=False), dict(groups=())):
            with self.assertRaises(ValueError): check(socket, parent, **kwargs)

    def test_exact_request_shapes_and_bounds(self):
        for action in ('arm', 'clients', 'disarm'):
            self.assertEqual(M['request'](action, EPOCH, [])['fingerprints'], [])
            with self.assertRaises(ValueError): M['request'](action, EPOCH, [FINGERPRINT])
        self.assertLessEqual(len(M['encoded'](M['request']('providers', EPOCH,
            [f'{index:064x}' for index in range(8)]))), 4096)
        for epoch, fingerprints in (('PRIVATE', [FINGERPRINT]), (EPOCH.upper(), [FINGERPRINT]),
                (EPOCH, []), (EPOCH, [FINGERPRINT] * 2), (EPOCH, [f'{i:064x}' for i in range(9)]),
                (EPOCH, [None]), (EPOCH, ['PRIVATE'])):
            with self.assertRaises(ValueError): M['request']('providers', epoch, fingerprints)

    def test_all_phase_terminal_domains_and_null_scope(self):
        for role, phases in (('client', M['CLIENT_PHASES']), ('provider', M['PROVIDER_PHASES'])):
            action = 'clients' if role == 'client' else 'providers'
            for phase in phases:
                for terminal in M['TERMINALS']:
                    value = reply(action, [row(role, phase=phase, terminal=terminal)])
                    if terminal.startswith('tls_') and phase != 'tls_handshake':
                        with self.assertRaises(ValueError): M['reply'](value, action, [FINGERPRINT])
                    else: self.assertEqual(M['reply'](value, action, [FINGERPRINT]), value)
        self.assertIsNone(M['reply'](reply(records=[row(fingerprint=None)]), 'clients', [])['records'][0]['fingerprint'])
        with self.assertRaises(ValueError): M['reply'](reply('providers', [row('provider', None)]), 'providers', [FINGERPRINT])

    def test_reply_rejects_private_fields_unsolicited_records_and_wrong_types(self):
        for key, value in (('version', True), ('version', 2), ('kind', 'PRIVATE'), ('state', 'armed'),
                ('incomplete', 1), ('diagnostic_only', False), ('acceptance_evidence', True), ('secret', 'PRIVATE')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                M['reply'](dict(reply(), **{key: value}), 'clients', [])
        for record in (dict(row(), secret='PRIVATE'), dict(row(), phase='PRIVATE'),
                dict(row(), terminal='PRIVATE'), row('provider'), row(fingerprint='PRIVATE')):
            with self.assertRaises(ValueError): M['reply'](reply(records=[record]), 'clients', [])
        with self.assertRaises(ValueError): M['reply'](reply('providers', [row('provider')]), 'providers', ['f' * 64])
        with self.assertRaises(ValueError): M['reply'](reply(records=[row()] * 65), 'clients', [])
        self.assertEqual(len(M['reply'](reply(records=[row()] * 64), 'clients', [])['records']), 64)
        for action in ('arm', 'disarm'):
            with self.assertRaises(ValueError): M['reply'](reply(action, [row()]), action, [])
            with self.assertRaises(ValueError): M['reply'](reply(action, incomplete=True), action, [])
        unavailable = dict(reply(), state='unavailable', incomplete=True)
        self.assertEqual(M['reply'](unavailable, 'clients', []), unavailable)
        with self.assertRaises(ValueError): M['reply'](dict(unavailable, incomplete=False), 'clients', [])

    def test_decoder_rejects_duplicates_nan_private_oversize(self):
        for raw in (b'{"version":1,"version":1}', b'{"records":NaN}', b'PRIVATE', b'x' * 32769):
            with self.assertRaises(ValueError): M['decode'](raw, M['MAX_REPLY'])

    def test_matching_missing_ambiguous_incomplete_and_unmatchable(self):
        cases = [('matched', {str(CONTROLS[1]): [row('provider')]}, False, row()),
            ('missing', {}, False, row()),
            ('ambiguous', {str(CONTROLS[1]): [row('provider')] * 2}, False, row()),
            ('ambiguous', {str(CONTROLS[1]): [row('provider')], str(CONTROLS[2]): [row('provider')]}, False, row()),
            ('matched_incomplete', {str(CONTROLS[1]): [row('provider')]}, True, row()),
            ('incomplete', {}, True, row()),
            ('ambiguous', {str(CONTROLS[1]): [row('provider')] * 2}, True, row()),
            ('unmatchable', {}, False, row(fingerprint=None))]
        for expected, providers, incomplete, client in cases:
            samples = M['Samples']('publish')
            with patch.dict(G, query=query_fixture(providers, [client], incomplete)):
                samples.round('/fixed/core', CONTROLS, EPOCH, threading.Event())
            value = samples.report()
            self.assertEqual(value['records'][0]['match_status'], expected)
            self.assertEqual(value['records'][0]['provider_role'],
                'a' if expected in ('matched', 'matched_incomplete') else None)
            data = M['encoded'](value)
            for private in (EPOCH, FINGERPRINT, '/fixed', 'fingerprint'):
                self.assertNotIn(private.encode(), data)
            self.assertFalse(value['acceptance_evidence'] or value['causal_attribution']
                or value['fragment_copy_binding'] or value['remote_cleanup_proven'])

    def test_expired_history_retains_known_pair_without_unique_or_absence_claim(self):
        samples = M['Samples']('publish')
        providers = {str(CONTROLS[2]): [row('provider', phase='storage_challenge_write_flush', terminal='operation_error')]}
        original = query_fixture(providers, [row(terminal='operation_error')], incomplete=True)
        def query(*args):
            state, value, joined = original(*args)
            if args[2] == 'clients': value['incomplete'] = True
            return state, value, joined
        with patch.dict(G, query=query):
            samples.round('/fixed/core', CONTROLS, EPOCH, threading.Event())
        value = samples.report()
        self.assertTrue(value['incomplete'])
        self.assertEqual(value['records'], [dict(client_phase='client_challenge', client_terminal='operation_error',
            match_status='matched_incomplete', provider_role='b', provider_phase='storage_challenge_write_flush',
            provider_terminal='operation_error')])
        self.assertEqual(M['validate'](value), value)
        with self.assertRaises(ValueError): M['validate'](dict(value, incomplete=False, armed=True, disarmed=True))
        result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'storage-fixture-correlation-sampler.py'),
            'validate-stdin'], input=M['encoded'](value), capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_batches_rotate_at_eight_and_total_rounds_are_bounded(self):
        clients = [row(fingerprint=f'{index:064x}') for index in range(64)]
        original = query_fixture(client_records=clients)
        batches = []
        def query(*args):
            if args[2] == 'providers': batches.append(tuple(args[4]))
            return original(*args)
        samples = M['Samples']('publish')
        with patch.dict(G, query=query, MAX_ROUNDS=8):
            for _ in range(9): samples.round('/fixed/core', CONTROLS, EPOCH, threading.Event())
        self.assertEqual(len(batches), 24)
        self.assertTrue(all(len(batch) == 8 for batch in batches))
        self.assertEqual(set(item for batch in batches for item in batch), {client['fingerprint'] for client in clients})
        self.assertTrue(samples.report()['incomplete'])

    def test_public_allowlist_has_no_metadata_and_maximum_is_bounded(self):
        samples = M['Samples']('publish')
        for phase in M['CLIENT_PHASES']:
            for terminal in ('active', 'complete', 'operation_error', 'cancelled'):
                for status in ('missing', 'ambiguous'):
                    samples.add(row(phase=phase, terminal=terminal), status)
        value = samples.report()
        self.assertEqual(len(value['records']), 32)
        self.assertLessEqual(len(M['encoded'](value)), 16384)
        for key, bad in (('version', True), ('secret', EPOCH), ('acceptance_evidence', True),
                ('causal_attribution', True), ('fragment_copy_binding', True), ('remote_cleanup_proven', True),
                ('sampler_joined', False), ('incomplete', False)):
            with self.assertRaises(ValueError): M['validate'](dict(value, **{key: bad}))
        bad = copy.deepcopy(value); bad['records'][0]['fingerprint'] = FINGERPRINT
        with self.assertRaises(ValueError): M['validate'](bad)
        with self.assertRaises(ValueError): M['validate'](dict(value, records=value['records'] * 2))

    def test_file_is_already_public_exclusive_phase_and_owner_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            value = M['Samples']('publish').report()
            M['publish'](root, 'publish', value)
            path = root / M['private_name']('publish')
            self.assertEqual(M['read_file'](path, 'publish', os.geteuid()), value)
            with self.assertRaises(FileExistsError): M['publish'](root, 'publish', value)
            with self.assertRaises(ValueError): M['read_file'](path, 'finish', os.geteuid())
            with self.assertRaises(ValueError): M['read_file'](path, 'publish', os.geteuid() + 1)
            link = root / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): M['read_file'](link, 'publish', os.geteuid())
            link.unlink(); os.link(path, link)
            with self.assertRaises(ValueError): M['read_file'](path, 'publish', os.geteuid())
            link.unlink(); path.chmod(0o644)
            with self.assertRaises(ValueError): M['read_file'](path, 'publish', os.geteuid())


class FixtureV2(unittest.TestCase):
    @staticmethod
    def summary():
        first = dict(stage='helper_acquire', reason='helper_kernel', helper_diagnostic='transport_unavailable')
        last = dict(stage='helper_acquire', reason='helper_cleanup_incomplete', helper_diagnostic='flow_identity_unavailable')
        return dict(rounds=2, first=first, last=last)

    def client(self):
        return dict(row(fingerprint=None, phase='flow_acquire', terminal='operation_error'), flow_acquire=self.summary())

    def test_closed_matrix_all_codes_and_unknown_are_not_raw_strings(self):
        self.assertEqual(len(M['ACQUIRE_PAIRS']), 35)
        for stage, reason in M['ACQUIRE_PAIRS']:
            failure = dict(stage=stage, reason=reason, helper_diagnostic=None)
            value = dict(rounds=1, first=failure, last=failure)
            M['acquire_summary'](value, 'flow_acquire', 'operation_error')
            for code in M['HELPER_DIAGNOSTICS']:
                failure['helper_diagnostic'] = code
                if stage == 'helper_acquire' and reason in M['HELPER_REASONS'][:6]:
                    M['acquire_summary'](value, 'flow_acquire', 'operation_error')
                else:
                    with self.assertRaises(ValueError): M['acquire_summary'](value, 'flow_acquire', 'operation_error')

    def test_strict_summary_fields_bounds_and_no_private_canary(self):
        invalid = []
        for rounds in (True, 0, 9, '2', None): invalid.append(dict(self.summary(), rounds=rounds))
        invalid.append(dict(self.summary(), rounds=1))
        invalid.append(dict(self.summary(), raw='PRIVATE_CANARY'))
        for key, value in (('stage', 'PRIVATE_CANARY'), ('reason', 'PRIVATE_CANARY'),
                ('helper_diagnostic', 'MPTCP_FLOW_IDENTITY_UNAVAILABLE'), ('helper_diagnostic', {}),
                ('helper_diagnostic', 0), ('request_id', 'PRIVATE_CANARY')):
            summary = self.summary(); summary['last'][key] = value; invalid.append(summary)
        for summary in invalid:
            with self.assertRaises(ValueError) as caught:
                M['acquire_summary'](summary, 'flow_acquire', 'operation_error')
            self.assertNotIn('PRIVATE_CANARY', str(caught.exception))
        for phase, terminal in (('tls_handshake', 'operation_error'), ('flow_acquire', 'cancelled'), ('flow_acquire', 'active')):
            with self.assertRaises(ValueError): M['acquire_summary'](self.summary(), phase, terminal)

    def test_versions_are_explicit_and_legacy_bytes_unchanged(self):
        legacy = reply(records=[row()])
        raw = M['encoded'](legacy)
        self.assertEqual(M['encoded'](M['reply'](legacy, 'clients', [])), raw)
        value = reply(records=[self.client()], version=2)
        self.assertEqual(M['reply'](value, 'clients', [], 2), value)
        for item, version in ((legacy, 2), (value, 1)):
            with self.assertRaises(ValueError): M['reply'](item, 'clients', [], version)
        value['records'][0].pop('flow_acquire')
        with self.assertRaises(ValueError): M['reply'](value, 'clients', [], 2)
        linked = reply(records=[dict(self.client(), fingerprint=FINGERPRINT)], version=2)
        with self.assertRaises(ValueError): M['reply'](linked, 'clients', [], 2)
        provider = reply('providers', [dict(row('provider'), flow_acquire=self.summary())], version=2)
        with self.assertRaises(ValueError): M['reply'](provider, 'providers', [FINGERPRINT], 2)

    def test_unmatchable_request_detail_never_queries_provider_or_exports_identity(self):
        calls = []
        original = query_fixture(client_records=[self.client()])
        def query(*args):
            calls.append(args[2]); return original(*args)
        samples = M['Samples']('publish', version=2)
        with patch.dict(G, query=query): samples.round('/fixed/core', CONTROLS, EPOCH, threading.Event())
        self.assertEqual(calls, ['clients'])
        report = samples.report()
        record = report['records'][0]
        self.assertEqual((record['match_status'], record['provider_role']), ('unmatchable', None))
        self.assertEqual(record['flow_acquire'], self.summary())
        for status in ('matched', 'matched_incomplete'):
            forged = copy.deepcopy(report)
            forged['records'][0].update(match_status=status, provider_role='a',
                provider_phase='storage_operation', provider_terminal='operation_error')
            with self.assertRaises(ValueError): M['validate'](forged)
        self.assertTrue(report['incomplete'])
        for value in (EPOCH, FINGERPRINT, 'fingerprint', 'request_id', 'MPTCP_FLOW_IDENTITY_UNAVAILABLE'):
            self.assertNotIn(value, M['encoded'](report).decode())
        for flag in ('acceptance_evidence', 'causal_attribution', 'fragment_copy_binding', 'remote_cleanup_proven'):
            self.assertFalse(report[flag])

    def test_v2_export_remains_bounded_deduplicated_and_accepts_historical_v1(self):
        samples = M['Samples']('publish', version=2)
        for first in M['HELPER_DIAGNOSTICS']:
            for last in M['HELPER_DIAGNOSTICS']:
                client = self.client()
                client['flow_acquire']['first']['helper_diagnostic'] = first
                client['flow_acquire']['last']['helper_diagnostic'] = last
                samples.add(client, 'unmatchable')
        report = samples.report()
        self.assertLessEqual(len(report['records']), 32)
        self.assertLessEqual(len(M['encoded'](report)), 16384)
        self.assertTrue(report['incomplete'])
        for report in (report, M['Samples']('publish').report()):
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'storage-fixture-correlation-sampler.py'),
                'validate-stdin'], input=M['encoded'](report), capture_output=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_v2_downgrade_does_not_replace_original_consumer_failure(self):
        primary = ValueError('PRIVATE_PRIMARY')
        def query(*args): return 'armed' if args[2] == 'arm' else 'disarmed', reply(args[2]), True
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            with patch.dict(G, controls_for=lambda _: CONTROLS, query=query), self.assertRaises(ValueError) as caught:
                with M['capture']('/fixed/core', Path('/fixed/work'), root, 'publish'): raise primary
            self.assertIs(caught.exception, primary)
            value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
            self.assertEqual(value['version'], 2)
            self.assertTrue(value['sampling_failed'] and value['incomplete'])
            self.assertFalse(value['armed'])
            self.assertNotIn('PRIVATE_PRIMARY', M['encoded'](value).decode())


class OwnedQueries(unittest.TestCase):
    def execute(self, code, stopped=None, *, ignore_term=False):
        popen, children = subprocess.Popen, []
        def spawn(argv, **kwargs):
            self.assertEqual(argv, ['/fixed/core', '--control-socket', '/fixed/control', 'content', 'fixture-correlation'])
            self.assertEqual(kwargs['env'], dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C'))
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertNotIn(EPOCH, repr((argv, kwargs)))
            self.assertNotIn(FINGERPRINT, repr((argv, kwargs)))
            if not ignore_term:
                child = popen([sys.executable, '-I', '-B', '-c', code], **kwargs)
                children.append(child)
                return child
            ready_read, ready_write = os.pipe()
            child = None
            try:
                # Test-only private pipe: do not start testing TERM/KILL until
                # the child has actually installed its ignored-TERM handler.
                prefix = ('import os,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                    f'os.write({ready_write},b"R"); os.close({ready_write}); ')
                child = popen([sys.executable, '-I', '-B', '-c', prefix + code],
                    pass_fds=(ready_write,), **kwargs)
                children.append(child)
                os.close(ready_write)
                ready_write = None
                readable, _, _ = select.select([ready_read], [], [], 5)
                self.assertEqual(os.read(ready_read, 1) if readable else None, b'R')
                return child
            except BaseException:
                if child is not None:
                    child.kill()
                    child.wait(timeout=1)
                    child.stdin.close()
                    child.stdout.close()
                raise
            finally:
                os.close(ready_read)
                if ready_write is not None: os.close(ready_write)
        with patch.object(G['subprocess'], 'Popen', spawn):
            result = M['query']('/fixed/core', '/fixed/control', 'clients', EPOCH, [], stopped or threading.Event())
        self.assertTrue(all(child.poll() is not None for child in children))
        return result

    def test_real_private_pipe_only_stdin_and_closed_reply(self):
        value = reply(records=[row()])
        code = 'import json,sys; v=json.load(sys.stdin); assert v=='+repr(M['request']('clients', EPOCH, []))+'; print('+repr(json.dumps(value))+')'
        self.assertEqual(self.execute(code), ('observed', value, True))
        for code in ('print("PRIVATE")', 'print("x" * 100000)', 'raise SystemExit(2)'):
            status, value, joined = self.execute(code)
            self.assertIn(status, ('rejected', 'failed'))
            self.assertIsNone(value); self.assertTrue(joined)

    def test_deadline_cancellation_and_stuck_output_are_joined(self):
        with patch.dict(G, QUERY_SECONDS=.1):
            status, value, joined = self.execute('import time; time.sleep(30)')
            self.assertEqual((status, value, joined), ('timeout', None, True))
        stopped = threading.Event(); stopped.set()
        self.assertEqual(self.execute('raise RuntimeError("must_not_spawn")', stopped), ('cancelled', None, True))
        stopped = threading.Event()
        timer = threading.Timer(.05, stopped.set)
        timer.start()
        try:
            self.assertEqual(self.execute('import time; time.sleep(30)', stopped), ('cancelled', None, True))
        finally: timer.join()

    def test_unexpected_arm_failure_does_not_claim_child_join_or_mask_primary(self):
        def query(*args):
            if args[2] == 'arm': raise PermissionError('PRIVATE')
            return query_fixture()(*args)
        primary = ValueError('owner_failure')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            with patch.dict(G, controls_for=lambda _: CONTROLS, query=query), self.assertRaises(ValueError) as caught:
                with M['capture']('/fixed/core', Path('/fixed/work'), root, 'publish'): raise primary
            self.assertIs(caught.exception, primary)
            value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
            self.assertFalse(value['children_joined'])
            self.assertTrue(value['sampling_failed'] and value['incomplete'])

    def test_failed_thread_start_still_launches_consumer_and_disarms(self):
        events = []
        original = query_fixture()
        def query(*args):
            events.append(args[2])
            return original(*args)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            with patch.dict(G, controls_for=lambda _: CONTROLS, query=query), \
                    patch.object(G['threading'].Thread, 'start', side_effect=RuntimeError('PRIVATE')):
                with M['capture']('/fixed/core', Path('/fixed/work'), root, 'publish'): events.append('consumer')
            self.assertEqual(events[:5], ['arm'] * 4 + ['consumer'])
            self.assertEqual(events[-4:], ['disarm'] * 4)
            self.assertTrue(M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())['sampling_failed'])

    def test_cleanup_permissionerror_still_attempts_kill_and_join(self):
        original, calls = os.killpg, []
        def kill(group, signum):
            calls.append(signum)
            if signum == signal.SIGTERM: raise PermissionError('PRIVATE')
            return original(group, signum)
        with patch.object(G['os'], 'killpg', kill), patch.dict(G, QUERY_SECONDS=.1):
            result = self.execute('import time; time.sleep(30)')
        self.assertFalse(result[2])
        self.assertEqual(result[:2], ('timeout', None))
        self.assertIn(signal.SIGKILL, calls)

    def test_success_reap_never_signals_reused_numeric_group(self):
        with patch.object(G['os'], 'killpg', side_effect=AssertionError('must_not_signal_after_reap')):
            result = self.execute('print('+repr(json.dumps(reply()))+')')
        self.assertEqual(result, ('observed', reply(), True))

    def test_timeout_term_then_kill_reaps_only_owned_live_child(self):
        original, calls = os.killpg, []
        def kill(group, signum):
            calls.append(signum)
            return original(group, signum)
        with patch.object(G['os'], 'killpg', kill), patch.dict(G, QUERY_SECONDS=.2):
            result = self.execute('import time; time.sleep(30)', ignore_term=True)
        self.assertEqual(result, ('timeout', None, True))
        self.assertEqual(calls, [signal.SIGTERM, signal.SIGKILL])

    def test_capture_arms_all_before_body_and_disarms_after_join_without_secrets_on_disk(self):
        events, reached = [], threading.Event()
        original = query_fixture({str(CONTROLS[1]): [row('provider')]})
        def query(*args):
            events.append((args[2], str(args[1])))
            if args[2] == 'clients': reached.set()
            return original(*args)
        primary = ValueError('original_consumer_failure')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            with patch.dict(G, controls_for=lambda _: CONTROLS, query=query), self.assertRaises(ValueError) as caught:
                with M['capture']('/fixed/core', Path('/fixed/work'), root, 'publish'):
                    self.assertEqual([action for action, _ in events[:4]], ['arm'] * 4)
                    self.assertTrue(reached.wait(1))
                    raise primary
            self.assertIs(caught.exception, primary)
            self.assertEqual([action for action, _ in events[-4:]], ['disarm'] * 4)
            value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
            self.assertTrue(value['armed'] and value['disarmed'] and value['children_joined'])
            self.assertEqual(len(list(root.iterdir())), 1)
            for private in (EPOCH, FINGERPRINT, 'fingerprint', 'epoch', 'original_consumer_failure'):
                self.assertNotIn(private, (root / M['private_name']('publish')).read_text())
            self.assertFalse(any(thread.name == 'storage-fixture-correlation-sampler' for thread in threading.enumerate()))

    def test_arm_query_disarm_and_publish_failures_do_not_change_consumer_result(self):
        for failed_action in ('arm', 'clients', 'disarm'):
            original = query_fixture()
            def query(*args):
                if args[2] == failed_action: return 'failed', None, True
                return original(*args)
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); root.chmod(0o700)
                with patch.dict(G, controls_for=lambda _: CONTROLS, query=query):
                    with M['capture']('/fixed/core', Path('/fixed/work'), root, 'publish'): pass
                value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
                self.assertTrue(value['sampling_failed'] and value['incomplete'])
        def failed(*_): raise PermissionError('PRIVATE')
        with patch.dict(G, controls_for=failed, publish=failed):
            with M['capture']('/fixed/core', Path('/fixed/work'), Path('/unused'), 'publish'): pass


class Wiring(unittest.TestCase):
    def test_normal_export_omits_oversized_optional_sidecar_without_failing(self):
        source = (HERE / 'run-alpha-topology-vm.sh').read_text()
        block = source.split('elif [ "$scenario" = private-storage-fragments ]', 1)[1]
        body = block.split('} | while IFS= read -r retained; do\n', 1)[1].split('\n    done >/home/vpci/fragment-export.list', 1)[0]
        self.assertIn('python3 -I -B tests/integration/storage-fixture-correlation-sampler.py validate-stdin', body)
        body = body.replace('retained_path=/home/vpci/alpha-output/$retained', 'retained_path=$1/$retained')
        script = 'set -eu\nfor retained in private-storage-fixture-correlation.json; do\n' + body + '\ndone\n'
        for raw, expected in ((M['encoded'](M['Samples']('publish').report()), M['NAME'].encode() + b'\n'),
                (b'PRIVATE' * 160000, b''), (b'{"epoch":"PRIVATE"}', b'')):
            with tempfile.TemporaryDirectory() as temp:
                (Path(temp) / M['NAME']).write_bytes(raw)
                result = subprocess.run(['sh', '-eu', '-c', script, 'inert', temp],
                    cwd=HERE.parents[1], capture_output=True, timeout=5)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))

    def test_original_phase_result_is_fixed_before_optional_final_queries(self):
        smoke = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
        scope = smoke['phase'].__globals__
        events, clock = [], [99.0]
        root = Path('/fixed/work/u/m'); work = root.parents[1]
        @contextmanager
        def correlation(*_):
            events.append('arm')
            try: yield
            finally:
                clock[0] = 1000.0  # Beyond the original deadline + 30, after its gate.
                events.append('bounded_diagnostic_shutdown')
        @contextmanager
        def flow(*_, **__):
            yield SimpleNamespace(joined=True, report=lambda **_: dict(exit_log_sampling_version=3))
        @contextmanager
        def activity(*_): yield
        original_loader = runpy.run_path
        def load(path):
            module = original_loader(path)
            if str(path).endswith('storage-consumer-route-sampler.py'):
                module.update(capture=flow, validate_policy=lambda *_: None, validate_summary=lambda *_: None)
            return module
        with patch.dict(os.environ, STORAGE_PROOF_BASELINE_MS='1', STORAGE_PROOF_ROUTE_POLICY='{}',
                STORAGE_PROOF_UNDERLAY_SHA256='a' * 64), \
                patch.object(scope['runpy'], 'run_path', load), \
                patch.object(scope['time'], 'monotonic', side_effect=lambda: clock[0]), \
                patch.dict(scope, PROFILE_VERSION=9, NETWORK_VERSION=2, FIXTURE_CORRELATION=True, CANCELLED=False,
                    CORRELATION=dict(smoke['CORRELATION'], capture=correlation),
                    ACTIVITY=dict(smoke['ACTIVITY'], capture=activity),
                    private_json=lambda *_: dict(coreBinary='/fixed/core', controlSocket='/fixed/client'),
                    validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client')),
                    private_directory=lambda *_: None, node_phase=lambda *_: ({'passed': True}, 'b' * 64),
                    write_json=lambda *_: events.append('after_original_deadline_check')):
            value = smoke['phase'](root, 'publish', work / 'runtime-exit/control/agent.sock',
                work / 'client-fixtures/private-storage-user', 'a' * 64, 100.0)
            self.assertTrue(value['passed'])
        self.assertEqual(events, ['arm', 'after_original_deadline_check', 'bounded_diagnostic_shutdown'])
        self.assertEqual(clock[0], 1000.0)

    def test_emergency_export_revalidates_exact_named_closed_sidecar(self):
        diagnostics = runpy.run_path(str(HERE / 'test-private-storage-fragments-wiring.py'))['diagnostics']()
        for raw, helper_present, expected in ((M['encoded'](M['Samples']('publish').report()), True, True),
                (M['encoded'](M['Samples']('publish').report()), False, False),
                (b'{"epoch":"PRIVATE"}', True, False), (b'PRIVATE' * 4096, True, False)):
            with tempfile.TemporaryDirectory() as temp:
                base = Path(temp); home = base / 'home'; published = home / 'alpha-output'
                published.mkdir(parents=True)
                (published / M['NAME']).write_bytes(raw)
                if helper_present:
                    helper = home / 'source/tests/integration/storage-fixture-correlation-sampler.py'
                    helper.parent.mkdir(parents=True)
                    helper.write_bytes((HERE / helper.name).read_bytes())
                archive = diagnostics['collect'](home, base / 'missing-opt', 'a' * 40,
                    'private-storage-maintenance', 124, cgroups=base / 'missing-cgroups', proc=base / 'missing-proc')
                with tarfile.open(archive) as bundle:
                    self.assertEqual('published/' + M['NAME'] in bundle.getnames(), expected)
                    for member in bundle.getmembers():
                        self.assertNotIn(b'PRIVATE', bundle.extractfile(member).read())

    def test_projection_on_original_consumer_failure_cannot_change_exit(self):
        script = '''
set -eu
. "$1"
WORK=$2
consumer_user=$WORK/owner
storage_user=$WORK/unused
WORKER_UID=$3
storage_fixture_correlation=yes
storage_consumer_phase_start() { :; }
storage_consumer_phase_finish() { printf '%s\\n' finished; }
fail() { printf '%s\\n' "$1" >&2; exit 17; }
application_status=$4
private_storage_consumer_private() { printf '%s\\n' original; return "$application_status"; }
private_storage_consumer_phase publish
'''
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); work.chmod(0o700)
            owner = work / 'owner'; owner.mkdir(mode=0o700)
            binary = work / 'bin'; binary.mkdir(mode=0o700)
            for name in ('storage-provider-activity-sampler.py', 'storage-fixture-correlation-sampler.py'):
                (binary / name).write_bytes((HERE / name).read_bytes())
            (binary / 'storage-consumer-maintenance-smoke.py').write_text('print(56)\n')
            path = owner / M['private_name']('publish')
            for valid in (True, False):
                path.write_bytes(M['encoded'](M['Samples']('publish').report()) if valid else b'PRIVATE')
                path.chmod(0o600)
                for original in ('0', '1'):
                    target = work / M['NAME']; target.unlink(missing_ok=True)
                    result = subprocess.run(['sh', '-eu', '-c', script, 'inert',
                        str(HERE / 'storage-consumer-maintenance-smoke.sh'), str(work), str(os.geteuid()), original],
                        capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0 if original == '0' else 17)
                    self.assertEqual(target.exists(), valid)
                    self.assertNotIn(b'PRIVATE', result.stdout + result.stderr)

    def test_real_phase_capture_is_only_opted_current_profile_and_closes_last(self):
        smoke = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
        scope = smoke['phase'].__globals__
        root = Path('/fixed/work/u/m'); work = root.parents[1]
        original_error = ValueError('original_node_failure')
        for profile in range(1, 10):
            for network in (1, 2):
                for enabled in (False, True):
                    events = []
                    @contextmanager
                    def correlation(*_):
                        events.append('arm')
                        try: yield
                        finally: events.append('disarm')
                    @contextmanager
                    def capture(*_, **__):
                        events.append('flow')
                        try: yield
                        finally: events.append('joined')
                    def node(*_): raise original_error
                    original_loader = runpy.run_path
                    def load(path):
                        module = original_loader(path)
                        if str(path).endswith('storage-consumer-route-sampler.py'):
                            module.update(capture=capture, validate_policy=lambda *_: None)
                        return module
                    with patch.dict(os.environ, STORAGE_PROOF_BASELINE_MS='1', STORAGE_PROOF_ROUTE_POLICY='{}',
                            STORAGE_PROOF_ROUTE_SCOPE='{}', STORAGE_PROOF_UNDERLAY_SHA256='a' * 64), \
                            patch.object(scope['runpy'], 'run_path', load), \
                            patch.dict(scope, PROFILE_VERSION=profile, NETWORK_VERSION=network, FIXTURE_CORRELATION=enabled,
                                CORRELATION=dict(smoke['CORRELATION'], capture=correlation),
                                ACTIVITY=dict(smoke['ACTIVITY'], capture=capture),
                                SAMPLER=dict(smoke['SAMPLER'], capture=capture, validate_route_scope=lambda *_: None),
                                private_json=lambda *_: dict(coreBinary='/fixed/core', controlSocket='/fixed/client'),
                                validate_locations=lambda *_: (Path('/fixed/core'), Path('/fixed/client')),
                                private_directory=lambda *_: None, node_phase=node):
                        with self.assertRaises(ValueError) as caught:
                            smoke['phase'](root, 'publish', work / 'runtime-exit/control/agent.sock',
                                work / 'client-fixtures/private-storage-user', 'a' * 64, time.monotonic() + 1)
                        self.assertIs(caught.exception, original_error)
                    expected = enabled and profile == 9 and network == 2
                    self.assertEqual('arm' in events, expected)
                    if expected: self.assertEqual((events[0], events[-1]), ('arm', 'disarm'))

    def test_flag_is_explicit_current_profile_only_without_privilege_or_budget_change(self):
        script = '''
. "$1"
WORK=/fixed
WORKER_UID=123
WORKER_GID=124
custody_control_gid=125
storage_consumer_profile_version=$2
storage_fixture_correlation=$3
timeout() { printf '%s\\n' "$@"; }
private_storage_consumer_private "$4" /fixed/owner
'''
        for profile in ('7', '8', '9'):
            for enabled in ('yes', 'no'):
                for phase in ('prepare', 'publish', 'exercise', 'finish', 'cleanup'):
                    result = subprocess.run(['sh', '-eu', '-c', script, 'inert',
                        str(HERE / 'storage-consumer-maintenance-smoke.sh'), profile, enabled, phase],
                        capture_output=True, text=True, timeout=5, check=True)
                    args = result.stdout.splitlines()
                    self.assertEqual(args[:4], ['--signal=TERM', '--kill-after=30s', '2400s', 'setpriv'])
                    self.assertIn('--reuid=123', args); self.assertIn('--groups=125', args)
                    self.assertEqual('--fixture-correlation' in args,
                        profile == '9' and enabled == 'yes' and phase in M['PHASES'])

    def test_maintenance_export_omits_absent_or_private_payload_and_keeps_valid_diagnostic(self):
        for raw, expected in ((None, False), (b'PRIVATE', False),
                (M['encoded'](dict(M['Samples']('publish').report(), fingerprint=FINGERPRINT)), False),
                (M['encoded'](M['Samples']('publish').report()), True)):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                if raw is not None:
                    (root / M['NAME']).write_bytes(raw)
                    (root / M['NAME']).chmod(0o600)
                result = subprocess.run([sys.executable, '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                    'export-names', temp], capture_output=True, timeout=5, check=True)
                self.assertEqual(M['NAME'].encode() in result.stdout.splitlines(), expected)
                self.assertNotIn(b'PRIVATE', result.stdout + result.stderr)
                self.assertNotIn(FINGERPRINT.encode(), result.stdout + result.stderr)

    def test_validator_cli_never_echoes_private_input(self):
        for raw, status in ((M['encoded'](M['Samples']('publish').report()), 0),
                (b'PRIVATE' * 4096, 1), (b'{"version":1,"epoch":"PRIVATE"}', 1)):
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'storage-fixture-correlation-sampler.py'),
                'validate-stdin'], input=raw, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, status)
            self.assertEqual(result.stdout + result.stderr, b'')


if __name__ == '__main__': unittest.main()
