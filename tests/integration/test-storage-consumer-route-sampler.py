#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert context/flow and actual sampler tests, never a protected-network proof."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py'))
OLD = runpy.run_path(str(HERE / 'test-private-storage-log-sampler.py'))
POLICY = dict(exit_peer_id='exit', relay_peers={f'relay{i}': f'r{i}' for i in range(3)})


def routes(context, broker=0, *, reverse=False):
    peers = [p for i, p in enumerate(POLICY['relay_peers'].values()) if i != broker]
    if reverse: peers.reverse()
    return [dict(path_id=i + 1, relay_peer_id=peer) for i, peer in enumerate(peers)]


def paths(context, broker=0, *, reverse=False):
    return ''.join(f'context={context} path={p["path_id"]} relay={p["relay_peer_id"]} '
        'exit=exit state=1 rtt_us=2 bytes=3 acked_transport_bytes=4\n'
        for p in routes(context, broker, reverse=reverse)).encode()


def status(broker):
    return json.dumps(dict(control_relay_peer_id=f'r{broker}', other_local_field='not retained')).encode()


def selected(context, broker=0, *, reverse=False):
    mapping = routes(context, broker, reverse=reverse)
    return dict(transport='mptcp', route_context_id=context, exact_selected_exit='exit',
        exact_selected_relays=[p['relay_peer_id'] for p in mapping],
        paths=[dict(**p, route_context_id=context, exit_peer_id='exit', state=1) for p in mapping],
        benchmark_slots=copy.deepcopy(mapping))


def snapshot(context, broker, logs):
    return [paths(context, broker), status(broker), paths(context, broker), logs]


class ContextSampler(unittest.TestCase):
    def test_broker_0_1_0_uses_new_exact_context_bindings_not_peer_union(self):
        coverage = M['Coverage'](10, POLICY)
        records = OLD['event'](9)
        coverage.add(records)
        for i, (context, broker) in enumerate((('a' * 32, 0), ('b' * 32, 1), ('c' * 32, 0))):
            coverage.route(paths(context, broker), status(broker), paths(context, broker))
            records += OLD['event'](11 + i, context=context)
            coverage.add(records)
        value = coverage.report(True)
        M['validate_summary'](value, 10, 3)
        M['validate_phase_route'](POLICY, selected('c' * 32), value)
        self.assertEqual([r['control_relay_peer_id'] for r in value['observed_context_routes']], ['r0', 'r1', 'r0'])
        self.assertEqual(value['exit_mptcp_tls_completed'], 3)
        self.assertNotIn('other_local_field', repr(value))
        with self.assertRaises(ValueError): M['OLD']['validate_summary'](value, 10, 3)

    def test_same_context_cannot_change_broker_or_permute_path_ids(self):
        a = 'a' * 32
        for before, control, after in (
                (paths(a, reverse=True), status(0), paths(a, reverse=True)),
                (paths(a, 1), status(1), paths(a, 1)),
                (paths(a), status(1), paths(a))):
            coverage = M['Coverage'](10, POLICY)
            coverage.route(paths(a), status(0), paths(a))
            with self.assertRaises(ValueError): coverage.route(before, control, after)
            self.assertEqual(len(coverage.route_bindings), 1)
            self.assertEqual(coverage.current_context, a)

    def test_new_context_may_change_exact_mapping_but_never_exit_provider_or_geometry(self):
        a, b = 'a' * 32, 'b' * 32
        coverage = M['Coverage'](10, POLICY)
        coverage.route(paths(a), status(0), paths(a))
        coverage.route(paths(b, reverse=True), status(0), paths(b, reverse=True))
        for bad in (b'', b'\n', paths(a).replace(b'exit=exit', b'exit=foreign'),
                paths(a).replace(b'relay=r1', b'relay=provider'), paths(a).replace(b'state=1', b'state=0'),
                paths(a).splitlines(keepends=True)[0], paths(a) * 2,
                paths(a).replace(b'path=2', b'path=1'), paths(a).replace(b'relay=r2', b'relay=r1'),
                paths(a) + b'SECRET', b'x' * 65537):
            with self.subTest(raw=bad[:40]), self.assertRaises(ValueError):
                M['Coverage'](10, POLICY).route(bad, status(0), bad)

    def test_bracket_change_retirement_unknown_broker_and_duplicate_json_fail_closed(self):
        a, b = 'a' * 32, 'b' * 32
        for first, control, last in (
                (paths(a), status(0), paths(b)), (paths(a), status(0), b''),
                (b'', status(0), paths(a)), (paths(a), b'{}', paths(a)),
                (paths(a), b'{"control_relay_peer_id":null}', paths(a)),
                (paths(a), b'{"control_relay_peer_id":"exit"}', paths(a)),
                (paths(a), b'{"control_relay_peer_id":"r0","control_relay_peer_id":"r1"}', paths(a)),
                (paths(a), b'[]', paths(a)), (paths(a), b'x' * 65537, paths(a))):
            coverage = M['Coverage'](10, POLICY)
            with self.assertRaises(ValueError): coverage.route(first, control, last)
            self.assertEqual(coverage.route_bindings, {})

    def test_every_counted_flow_needs_observed_context_and_final_context_needs_completed_flow(self):
        a, b = 'a' * 32, 'b' * 32
        coverage = M['Coverage'](10, POLICY)
        coverage.route(paths(a), status(0), paths(a))
        coverage.add(OLD['event'](9)); coverage.add(OLD['event'](9) + OLD['event'](11, context=b))
        with self.assertRaises(ValueError): M['validate_summary'](coverage.report(True), 10, 1)
        coverage.route(paths(b), status(0), paths(b))
        value = coverage.report(True)
        M['validate_summary'](value, 10, 1)
        with self.assertRaises(ValueError): M['validate_phase_route'](POLICY, selected(a), value)
        M['validate_phase_route'](POLICY, selected(b), value)
        for mutate in (
                lambda v: v['observed_context_routes'][0]['scope']['paths'][0].update(relay_peer_id='provider'),
                lambda v: v['observed_context_routes'].append(copy.deepcopy(v['observed_context_routes'][0])),
                lambda v: v.update(extra=True), lambda v: v.update(exit_log_sampler_joined=False),
                lambda v: v.update(exit_log_sampling_version=3.0),
                lambda v: v['exit_flow_contexts'][0].update(completed=2)):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_summary'](invalid, 10, 1)

    def test_original_eight_context_bound_and_policy_closed(self):
        coverage = M['Coverage'](10, POLICY)
        for i in range(8):
            context = f'{i + 1:032x}'
            coverage.route(paths(context), status(0), paths(context))
        with self.assertRaises(ValueError): coverage.route(paths('f' * 32), status(0), paths('f' * 32))
        for policy in ({}, dict(POLICY, extra=True), dict(exit_peer_id='exit', relay_peers={'relay0':'r0'}),
                dict(exit_peer_id='r0', relay_peers=POLICY['relay_peers']),
                dict(exit_peer_id='exit', relay_peers=dict(relay0='r0', relay1='r0', relay2='r2'))):
            with self.assertRaises(ValueError): M['Coverage'](10, policy)

    def test_actual_capture_uses_live_bracket_before_exit_logs_and_preserves_counters(self):
        a, c = 'a' * 32, 'c' * 32
        outputs = snapshot(a, 0, OLD['event'](9)) + snapshot(c, 0,
            OLD['event'](9) + OLD['event'](11, context=a) + OLD['event'](12, context=c))
        with patch.object(M['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=x) for x in outputs]) as query:
            with M['capture']('/synthetic/core', '/synthetic/exit', 10, 2,
                    client='/synthetic/client', policy=POLICY) as coverage:
                self.assertEqual(len(coverage.route_bindings), 1)
        self.assertEqual(query.call_count, 8)
        self.assertEqual([c.args[0][3:] for c in query.call_args_list],
            [['paths'], ['content', 'status'], ['paths'], ['logs', '--limit', '1000']] * 2)
        self.assertTrue(all(0 < c.kwargs['timeout'] <= 3 for c in query.call_args_list))
        M['validate_phase_route'](POLICY, selected(c), coverage.report(True))

    def test_busy_no_retry_and_process_output_never_exported(self):
        real_run = subprocess.run
        diagnostic = {}
        def rejected(command, **options):
            return real_run([sys.executable, '-B', '-c',
                "import sys; print('SECRET'); print('SECRET STDERR', file=sys.stderr); sys.exit(1)"], **options)
        with patch.object(M['subprocess'], 'run', side_effect=rejected) as query:
            with self.assertRaises(M['OLD']['SamplerFailure']) as failure:
                with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                    self.fail('failed observation admitted owner')
        self.assertEqual(query.call_count, 1)
        self.assertEqual((diagnostic['phase'], diagnostic['operation'], diagnostic['code']),
            ('initial', 'paths_before', 'process'))
        self.assertNotIn('SECRET', repr(diagnostic) + str(failure.exception))
        M['validate_diagnostic'](diagnostic)

    def test_query_after_sample_deadline_never_admits_owner(self):
        diagnostic = {}
        with patch.object(M['time'], 'monotonic', side_effect=[100, 100.1, 103.01]), \
                patch.object(M['subprocess'], 'run', return_value=SimpleNamespace(stdout=paths('a' * 32))) as query:
            with self.assertRaises(M['OLD']['SamplerFailure']):
                with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                    self.fail('late success admitted owner')
        self.assertEqual(query.call_count, 1)
        self.assertEqual(diagnostic['operation'], 'paths_before')
        self.assertEqual(diagnostic['code'], 'deadline')

    def test_every_rpc_failure_is_closed_and_never_retried(self):
        replies = snapshot('a' * 32, 0, OLD['event'](9))
        operations = ('paths_before', 'control_status', 'paths_after', 'exit_log_query')
        errors = (
            (lambda: subprocess.CalledProcessError(1, ['SECRET'], output=b'SECRET'), 'process'),
            (lambda: subprocess.TimeoutExpired(['SECRET'], 3, output=b'SECRET'), 'timeout'),
            (lambda: OSError('SECRET'), 'local_io'))
        for index, operation in enumerate(operations):
            for make_error, code in errors:
                diagnostic = {}
                outputs = [SimpleNamespace(stdout=x) for x in replies[:index]] + [make_error()]
                with self.subTest(operation=operation, code=code), \
                        patch.object(M['subprocess'], 'run', side_effect=outputs) as query:
                    with self.assertRaises(M['OLD']['SamplerFailure']) as failure:
                        with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                                client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                            self.fail('failed query admitted owner')
                self.assertEqual(query.call_count, index + 1)
                self.assertEqual((diagnostic['phase'], diagnostic['operation'], diagnostic['code']),
                    ('initial', operation, code))
                self.assertNotIn('SECRET', repr(diagnostic) + str(failure.exception))

    def test_actual_query_bounds_and_parsers_reject_without_starting_owner(self):
        a, b = 'a' * 32, 'b' * 32
        for index, raw, expected_operation, expected_queries in (
                (0, b'x' * 65537, 'paths_before', 1),
                (1, b'x' * 65537, 'control_status', 2),
                (2, b'x' * 65537, 'paths_after', 3),
                (3, b'x' * (262144 + 1), 'exit_log_query', 4),
                (0, b'PRIVATE MALFORMED', 'route_binding', 3),
                (1, b'{"control_relay_peer_id":"PRIVATE"}', 'route_binding', 3),
                (2, b'', 'route_binding', 3),
                (2, paths(b), 'route_binding', 3),
                (3, b'PRIVATE MALFORMED', 'coverage', 4)):
            replies = snapshot(a, 0, OLD['event'](9)); replies[index] = raw
            diagnostic = {}
            with self.subTest(index=index, operation=expected_operation), \
                    patch.object(M['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=x) for x in replies]) as query:
                with self.assertRaises(M['OLD']['SamplerFailure']) as failure:
                    with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                            client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                        self.fail('invalid observation admitted owner')
            self.assertEqual(query.call_count, expected_queries)
            self.assertEqual((diagnostic['operation'], diagnostic['code']), (expected_operation, 'invalid'))
            self.assertNotIn('PRIVATE', repr(diagnostic) + str(failure.exception))

    def test_parse_time_is_in_same_sample_budget(self):
        diagnostic = {}
        replies = snapshot('a' * 32, 0, OLD['event'](9))
        # Deadline construction + two clock reads per four queries, then the
        # post-parse guard. There is no separate fresh parsing allowance.
        with patch.object(M['time'], 'monotonic', side_effect=[100] * 9 + [103]), \
                patch.object(M['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=x) for x in replies]):
            with self.assertRaises(M['OLD']['SamplerFailure']):
                with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                    self.fail('late parse admitted owner')
        self.assertEqual((diagnostic['operation'], diagnostic['code']), ('coverage', 'deadline'))

    def test_background_rejection_is_not_retried_and_owned_thread_is_joined(self):
        stop, failed = threading.Event(), threading.Event()
        class ImmediateFirstTick:
            initial = True
            def set(self): stop.set()
            def wait(self, timeout):
                if self.initial:
                    self.initial = False
                    return False
                return stop.wait(timeout)
        replies = [SimpleNamespace(stdout=x) for x in snapshot('a' * 32, 0, OLD['event'](9))]
        calls = []
        def query(command, **options):
            calls.append(command)
            if len(calls) <= 4: return replies[len(calls) - 1]
            failed.set()
            raise subprocess.CalledProcessError(1, ['PRIVATE'])
        diagnostic = {}
        globals_ = M['capture'].__wrapped__.__globals__
        shim = SimpleNamespace(Event=ImmediateFirstTick, Thread=threading.Thread)
        with patch.dict(globals_, threading=shim), patch.object(M['subprocess'], 'run', side_effect=query):
            with self.assertRaises(M['OLD']['SamplerFailure']):
                with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                    self.assertTrue(failed.wait(1), 'owned sampler did not run')
        self.assertEqual(len(calls), 5)
        self.assertTrue(stop.is_set())
        self.assertFalse(any(t.name == 'consumer-exit-flow-sampler' for t in threading.enumerate()))
        self.assertEqual((diagnostic['phase'], diagnostic['operation'], diagnostic['code']),
            ('sampling', 'paths_before', 'process'))

    def test_no_log_transcript_can_admit_an_unobserved_context_at_final_join(self):
        a, b = 'a' * 32, 'b' * 32
        replies = snapshot(a, 0, OLD['event'](9)) + snapshot(a, 0,
            OLD['event'](9) + OLD['event'](11, context=a) + OLD['event'](12, context=b))
        diagnostic = {}
        with patch.object(M['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=x) for x in replies]) as query:
            with self.assertRaises(M['OLD']['SamplerFailure']):
                with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                    pass
        self.assertEqual(query.call_count, 8)
        self.assertEqual((diagnostic['phase'], diagnostic['operation'], diagnostic['code']),
            ('final_drain', 'coverage', 'invalid'))

    def test_diagnostic_is_closed_and_bounded(self):
        original = dict(version=1, kind='consumer-route-sampler-failure', phase='sampling',
            operation='route_binding', code='invalid', samples=2, completed=3, failed=0)
        M['validate_diagnostic'](original)
        for change in (dict(version=True), dict(kind='PRIVATE'), dict(phase='PRIVATE'),
                dict(operation='PRIVATE'), dict(code='PRIVATE'), dict(samples=513),
                dict(completed=512001), dict(failed=-1), dict(raw='PRIVATE')):
            with self.subTest(change=change), self.assertRaises(ValueError):
                M['validate_diagnostic']({**original, **change})

    def test_original_owner_failure_survives_final_rejection_and_sampler_joins(self):
        a = 'a' * 32
        replies = [SimpleNamespace(stdout=x) for x in snapshot(a, 0, OLD['event'](9))]
        replies.append(subprocess.CalledProcessError(1, ['SECRET']))
        primary, diagnostic = ValueError('original owner failure'), {}
        with patch.object(M['subprocess'], 'run', side_effect=replies) as query:
            with self.assertRaises(ValueError) as failure:
                with M['capture']('/synthetic/core', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', policy=POLICY, diagnostic=diagnostic):
                    raise primary
        self.assertIs(failure.exception, primary)
        self.assertEqual(query.call_count, 5)
        self.assertEqual(diagnostic['phase'], 'final_drain')


if __name__ == '__main__':
    unittest.main()
