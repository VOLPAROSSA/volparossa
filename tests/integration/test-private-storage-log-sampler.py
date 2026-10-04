#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure coverage/counter contracts, not real core or protected-flow evidence."""
from pathlib import Path
import copy
import runpy
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
S = runpy.run_path(str(HERE / 'private-storage-log-sampler.py'))


def event(timestamp, code='MPTCP_EXIT_FLOW_COMPLETED', context=''):
    return f'{timestamp}\tlevel=1\tevent={code}\tsession={context}\tpath=-\n'.encode()


SCOPE = dict(exit_peer_id='exit', paths=[dict(path_id=1, relay_peer_id='one'), dict(path_id=2, relay_peer_id='two')])


def paths(context):
    return ''.join(f'context={context} path={p["path_id"]} relay={p["relay_peer_id"]} exit=exit state=1 rtt_us=0 bytes=0\n'
        for p in SCOPE['paths']).encode()


def selected(context):
    return dict(transport='mptcp', route_context_id=context, exact_selected_exit='exit',
        exact_selected_relays=['one', 'two'],
        paths=[dict(**p, route_context_id=context, exit_peer_id='exit', state=1) for p in SCOPE['paths']],
        benchmark_slots=copy.deepcopy(SCOPE['paths']))


class CoveredExitLogs(unittest.TestCase):
    def test_sampler_finally_preserves_owner_error_and_separately_records_observation_failure(self):
        diagnostic = {}
        primary = ValueError('synthetic primary owner failure')
        replies = [SimpleNamespace(stdout=event(9)), subprocess.TimeoutExpired('SECRET_ARGS', 3)]
        with patch.object(S['subprocess'], 'run', side_effect=replies):
            with self.assertRaises(ValueError) as caught:
                with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1, diagnostic=diagnostic):
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(diagnostic, dict(phase='final_drain', operation='exit_log_query',
            code='timeout', samples=1, completed=0, failed=0))
        self.assertNotIn('SECRET', repr(diagnostic))

    def test_successful_owner_does_not_hide_sampler_failure(self):
        diagnostic = {}
        replies = [SimpleNamespace(stdout=event(9)), SimpleNamespace(stdout=b'SECRET_RAW_LOG')]
        with patch.object(S['subprocess'], 'run', side_effect=replies):
            with self.assertRaises(S['SamplerFailure']):
                with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1, diagnostic=diagnostic):
                    pass
        self.assertEqual(diagnostic['operation'], 'coverage')
        self.assertEqual(diagnostic['code'], 'invalid')
        self.assertNotIn('SECRET', repr(diagnostic))

    def test_fresh_context_requires_its_own_completed_flow_and_identical_observed_scope(self):
        a, b = 'a' * 32, 'b' * 32
        coverage = S['Coverage'](10, SCOPE)
        coverage.route(paths(a))
        first = event(9, 'STARTED') + event(11, context=a) + event(12, 'MPTCP_EXIT_FLOW_FAILED', a)
        coverage.add(first)
        coverage.route(paths(b))
        coverage.add(first + event(13, context=b))
        report = coverage.report(True)
        S['validate_summary'](report, 10, 2)
        S['validate_phase_route'](SCOPE, selected(b), report)
        self.assertEqual(report['exit_flow_contexts'], [dict(route_context_id=a, completed=1, failed=1),
            dict(route_context_id=b, completed=1, failed=0)])
        for mutate in (
            lambda v: v['exit_flow_contexts'][1].update(completed=0),
            lambda v: v['exit_flow_contexts'][1].update(route_context_id='c' * 32),
            lambda v: v.update(observed_route_context_ids=[a]),
            lambda v: v['exit_route_scope'].update(exit_peer_id='other'),
            lambda v: v['exit_route_scope']['paths'][0].update(relay_peer_id='other'),
        ):
            invalid = copy.deepcopy(report); mutate(invalid)
            with self.assertRaises(ValueError):
                S['validate_phase_route'](SCOPE, selected(b), invalid)
        # Even with the same total and both IDs observed, old completed counts
        # cannot substitute for a new-context failure with no completion.
        wrong = copy.deepcopy(report)
        wrong['exit_flow_contexts'][0].update(completed=2, failed=0)
        wrong['exit_flow_contexts'][1].update(completed=0, failed=1)
        S['validate_summary'](wrong, 10, 2)
        with self.assertRaises(ValueError):
            S['validate_phase_route'](SCOPE, selected(b), wrong)

    def test_contextual_sampler_rejects_missing_scope_and_foreign_paths(self):
        for raw in (paths('a' * 32).replace(b'exit=exit', b'exit=other'),
                    paths('a' * 32).replace(b'relay=one', b'relay=other'),
                    paths('a' * 32).replace(b'path=1', b'path=3')):
            with self.assertRaises(ValueError):
                S['Coverage'](10, SCOPE).route(raw)
        for row in (event(11), event(11, context='0' * 32), event(11, context='abc'),
                    event(11, 'MPTCP_EXIT_FLOW_SCOPE_MISMATCH'), event(11, 'MPTCP_EXIT_FLOW_OWNER_MISSING')):
            with self.assertRaises(ValueError):
                S['Coverage'](10, SCOPE).add(event(9, 'STARTED') + row)

    def test_contextual_capture_reads_only_live_paths_and_existing_exit_ring(self):
        a, b = 'a' * 32, 'b' * 32
        first = event(9, 'STARTED')
        replies = [paths(a), first, paths(b), first + event(11, context=a) + event(12, context=b)]
        with patch.object(S['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=row) for row in replies]) as command:
            with S['capture']('/synthetic/cli', '/synthetic/exit.sock', 10, 2,
                              client='/synthetic/client.sock', scope=SCOPE) as coverage:
                pass
        report = coverage.report(True)
        S['validate_phase_route'](SCOPE, selected(b), report)
        self.assertEqual(command.call_count, 4)
        self.assertEqual([call.args[0][2:] for call in command.call_args_list], [
            ['/synthetic/client.sock', 'paths'], ['/synthetic/exit.sock', 'logs', '--limit', '1000'],
            ['/synthetic/client.sock', 'paths'], ['/synthetic/exit.sock', 'logs', '--limit', '1000']])
        self.assertTrue(all(0 < call.kwargs['timeout'] <= 3 for call in command.call_args_list))

    def test_final_drain_does_not_use_old_context_minimum_for_new_context(self):
        a, b = 'a' * 32, 'b' * 32
        initial = event(9, 'STARTED') + event(11, context=a)
        replies = [paths(a), initial, paths(b), initial, paths(b), initial + event(12, context=b)]
        now = [0.0]
        with patch.object(S['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=row) for row in replies]) as command, \
                patch.object(S['time'], 'monotonic', side_effect=lambda: now[0]), \
                patch.object(S['time'], 'sleep', side_effect=lambda delay: now.__setitem__(0, now[0] + delay)):
            with S['capture']('/synthetic/cli', '/synthetic/exit.sock', 10, 1,
                              client='/synthetic/client.sock', scope=SCOPE) as coverage:
                pass
        self.assertEqual(command.call_count, 6)
        self.assertEqual(now[0], 0.2)
        S['validate_phase_route'](SCOPE, selected(b), coverage.report(True))

    def test_more_than_one_thousand_events_preserve_exact_counts_and_coverage(self):
        rows = [event(number) for number in range(1, 2402)]
        coverage = S['Coverage'](100)
        for start, end in ((0, 1000), (500, 1500), (1000, 2000), (1401, 2401)):
            coverage.add(b''.join(rows[start:end]))
        report = coverage.report(joined=True)
        S['validate_summary'](report, 100, 2301)
        self.assertEqual(report['exit_mptcp_tls_completed'], 2301)
        self.assertEqual(report['exit_log_observed_records'], 2401)
        self.assertEqual(report['exit_log_records'], 1000)
        self.assertEqual(report['exit_log_samples'], 4)
        self.assertLessEqual(report['exit_log_oldest_unix_ms'], 100)

    def test_overlapping_equal_timestamp_duplicates_are_counted_not_deduplicated(self):
        coverage = S['Coverage'](10)
        initial = event(9, 'STARTED') + event(11) * 3
        coverage.add(initial)
        coverage.add(initial)
        coverage.add(initial + event(11) * 2 + event(12))
        self.assertEqual(coverage.report(True)['exit_mptcp_tls_completed'], 6)
        # Evict the earlier partial timestamp group, retaining the complete tail
        # plus one additional event in that same millisecond.
        coverage.add(event(11) * 5 + event(12) * 2 + event(13, 'MPTCP_EXIT_FLOW_FAILED'))
        report = coverage.report(True)
        self.assertEqual(report['exit_mptcp_tls_completed'], 7)
        self.assertEqual(report['exit_mptcp_tls_failed'], 1)

    def test_missing_segment_or_changed_overlap_never_claims_full_coverage(self):
        rows = [event(number) for number in range(1, 2002)]
        for after in (b''.join(rows[1000:2000]), b''.join(rows[999:1999]),
                      b''.join(rows[500:999]) + event(1000, 'FORGED') + event(1001),
                      b''.join(rows[500:998]) + event(999) + event(999) + event(1001)):
            coverage = S['Coverage'](100)
            coverage.add(b''.join(rows[:1000]))
            with self.assertRaises(ValueError):
                coverage.add(after)
        with self.assertRaises(ValueError):
            S['Coverage'](100).add(b''.join(rows[100:1100]))
        with self.assertRaises(ValueError):
            S['Coverage'](100).add(event(100) * 1000)

    def test_parse_limits_clock_regression_and_closed_summary(self):
        for raw in (b'', b'private arbitrary content', event(2) + event(1), event(1) * 1001,
                    b'x' * 262145):
            with self.assertRaises(ValueError):
                S['records'](raw)
        coverage = S['Coverage'](10)
        coverage.add(event(9) + event(11))
        coverage.add(event(9) + event(11) + event(12))
        report = coverage.report(True)
        S['validate_summary'](report, 10, 2)
        for changes in (dict(exit_log_sampler_joined=False), dict(exit_log_overlap_verified=False),
                        dict(exit_log_samples=513), dict(exit_log_records=1001),
                        dict(exit_mptcp_tls_completed=1000), dict(secret='not permitted'),
                        dict(exit_log_window_covers_baseline=False), dict(exit_log_samples=True)):
            with self.assertRaises(ValueError):
                S['validate_summary'](dict(report, **changes), 10, 2)

    def test_sampler_is_owner_joined_and_exports_only_closed_existing_gate_files(self):
        maintenance = (HERE / 'private-storage-maintenance-smoke.py').read_text()
        self.assertIn("with SAMPLER['capture'](args[2], exit_socket, baseline, F['PHASES'][args[0]],", maintenance)
        self.assertIn('client=socket, scope=scope, diagnostic=SAMPLER_DIAGNOSTIC) as coverage:', maintenance)
        self.assertIn('summary = coverage.report(joined=coverage.joined)', maintenance)
        shell = (HERE / 'private-storage-fragments-smoke.sh').read_text()
        self.assertIn('STORAGE_PROOF_BASELINE_MS=${provider_baseline_ms:-0}', shell)
        self.assertIn('"$storage_user/flow-$storage_phase.json"', shell)
        self.assertIn('|| fail FRAGMENTS_EXIT_LOG_WINDOW_TRUNCATED', shell)
        checker = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
        self.assertFalse(any('flow-upload' in name or 'log-sampler' in name for name in checker['EXPORT_NAMES']))
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertIn('"$WORK/bin/private-storage-log-sampler.py"', guest)
        self.assertIn('|| { [ "$private_storage_maintenance" = yes ] && [ "$node" = exit ]; }', guest)
        self.assertIn('chgrp volparossa-users "$WORK/runtime-$node/control"', guest)
        self.assertIn('group:volparossa-users:--x,mask::r-x', guest)
        self.assertIn('install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 \\\n        "$WORK/runtime-$node/native" "$WORK/state-$node" "$WORK/credential-$node"', guest)
        self.assertIn('--reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid"', shell)

    def test_final_drain_waits_for_actual_completion_and_joins(self):
        replies = [event(9), event(9) + event(11), event(9) + event(11) + event(12)]
        now = [0.0]
        with patch.object(S['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=row) for row in replies]) as command, \
                patch.object(S['time'], 'monotonic', side_effect=lambda: now[0]), \
                patch.object(S['time'], 'sleep', side_effect=lambda delay: now.__setitem__(0, now[0] + delay)):
            with S['capture']('/synthetic/cli', '/synthetic/exit.sock', 10, 2) as coverage:
                pass
        self.assertEqual(command.call_count, 3)
        self.assertEqual(now[0], 0.2)
        self.assertTrue(coverage.joined)
        S['validate_summary'](coverage.report(True), 10, 2)
        self.assertTrue(all(call.kwargs['timeout'] <= 3 for call in command.call_args_list))

    def test_final_drain_missing_completion_fails_within_original_budget(self):
        now = [0.0]
        with patch.object(S['subprocess'], 'run', return_value=SimpleNamespace(stdout=event(9))) as command, \
                patch.object(S['time'], 'monotonic', side_effect=lambda: now[0]), \
                patch.object(S['time'], 'sleep', side_effect=lambda delay: now.__setitem__(0, now[0] + delay)):
            with self.assertRaises(ValueError):
                with S['capture']('/synthetic/cli', '/synthetic/exit.sock', 10, 1):
                    pass
        self.assertEqual(now[0], 5.0)
        self.assertLessEqual(command.call_count, 27)


if __name__ == '__main__':
    unittest.main()
