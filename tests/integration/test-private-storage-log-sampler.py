#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure coverage/counter contracts, not real core or protected-flow evidence."""
from pathlib import Path
import copy
import os
import runpy
import subprocess
import sys
import threading
import time
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
    def test_paths_process_failure_is_closed_and_never_retried(self):
        busy = b'Error: agent rejected request: CLIENT_ROUTE_BUSY (Unavailable)\n'
        unavailable = b'Error: agent rejected request: MPQUIC_PATH_STATUS_UNAVAILABLE (Unavailable)\n'
        cases = (
            (1, b'', busy, 'CLIENT_ROUTE_BUSY', 'bounded'),
            (1, b'', unavailable, 'MPQUIC_PATH_STATUS_UNAVAILABLE', 'bounded'),
            (2, b'', busy, 'UNRECOGNIZED', 'bounded'),
            (-9, b'', busy, 'UNRECOGNIZED', 'bounded'),
            (1, b'SECRET_STDOUT', busy, 'UNRECOGNIZED', 'bounded'),
            (1, b'', b'Error: agent rejected request: SECRET_CODE (Unavailable)\n', 'UNRECOGNIZED', 'bounded'),
            (1, b'', busy.replace(b'Unavailable', b'Policy'), 'UNRECOGNIZED', 'bounded'),
            (1, b'', b'SECRET_PREFIX\n' + busy, 'UNRECOGNIZED', 'bounded'),
            (1, b'', busy + b'SECRET_SUFFIX', 'UNRECOGNIZED', 'bounded'),
            (1, b'', busy + busy, 'UNRECOGNIZED', 'bounded'),
            (1, b'', b'\xffSECRET_PRIVATE', 'UNRECOGNIZED', 'bounded'),
            (1, b'', b'', 'UNRECOGNIZED', 'bounded'),
            (1, b'', busy + b'SECRET_PRIVATE' * 1000, 'UNRECOGNIZED', 'oversize'),
        )
        for status, stdout, stderr, reason, state in cases:
            diagnostic = {}

            def rejected(command, **options):
                # Exercise the actual pipe capture/parser, not a fabricated parsed code.
                if options['stderr'] != subprocess.DEVNULL:
                    os.write(options['stderr'], stderr)
                raise subprocess.CalledProcessError(status, ['SECRET_COMMAND'], output=stdout)

            with self.subTest(reason=reason, status=status, state=state), \
                    patch.object(S['subprocess'], 'run', side_effect=rejected) as command:
                with self.assertRaises(S['SamplerFailure']) as failure:
                    with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                            client='/synthetic/client', scope=SCOPE, diagnostic=diagnostic):
                        self.fail('failed Paths must not admit owner work')
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.kwargs['timeout'], 3)
                self.assertEqual(diagnostic, dict(phase='initial', operation='route_query', code='process',
                    samples=0, completed=0, failed=0,
                    paths_process=dict(exit_status=status, diagnostic=reason, stderr_state=state)))
                self.assertNotIn('SECRET', repr(diagnostic) + str(failure.exception))

    def test_paths_failure_capture_is_bounded_with_a_real_inert_subprocess(self):
        run = subprocess.run
        diagnostic = {}

        def rejected(command, **options):
            # No agent, socket, network or model: exercise child output/EOF and draining.
            return run([sys.executable, '-c',
                "import os,sys; os.write(2, b'SECRET_PRIVATE' * 20000); sys.exit(1)"], **options)

        with patch.object(S['subprocess'], 'run', side_effect=rejected) as command:
            with self.assertRaises(S['SamplerFailure']):
                with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', scope=SCOPE, diagnostic=diagnostic):
                    self.fail('oversize rejection remains failed')
        self.assertEqual(command.call_count, 1)
        self.assertEqual(diagnostic['paths_process'],
            dict(exit_status=1, diagnostic='UNRECOGNIZED', stderr_state='oversize'))
        self.assertNotIn('SECRET', repr(diagnostic))
        # A distinct, healthy observation still follows the unchanged real route parser.
        a = 'a' * 32
        replies = [paths(a), event(9), paths(a), event(9) + event(11, context=a)]
        restored = {}
        with patch.object(S['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=row) for row in replies]):
            with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                    client='/synthetic/client', scope=SCOPE, diagnostic=restored) as coverage:
                pass
        S['validate_phase_route'](SCOPE, selected(a), coverage.report(True))
        self.assertEqual(restored, {})

    def test_paths_process_status_bounds_and_capture_absence_are_not_guessed(self):
        diagnostic = S['paths_process_diagnostic']
        busy = b'Error: agent rejected request: CLIENT_ROUTE_BUSY (Unavailable)\n'
        for status in (None, True, -129, 256, '1'):
            self.assertEqual(diagnostic(status, b'', busy),
                dict(exit_status=None, diagnostic='UNRECOGNIZED', stderr_state='bounded'))
        for raw in (None, 'SECRET_STRING'):
            self.assertEqual(diagnostic(1, b'', raw),
                dict(exit_status=1, diagnostic='UNRECOGNIZED', stderr_state='unavailable'))

    def test_paths_stderr_live_retention_bound_and_success_are_unchanged(self):
        run = subprocess.run
        with S['paths_stderr']() as (descriptor, captured):
            run([sys.executable, '-c', "import os; os.write(2, b'x' * 262144)"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=descriptor, check=True, timeout=3)
        self.assertEqual(captured['data'], b'x' * (S['PATHS_STDERR_LIMIT'] + 1))
        a = 'a' * 32
        replies = iter([paths(a), event(9), paths(a), event(9) + event(11, context=a)])

        def success(command, **options):
            if command[-1] == 'paths':
                os.write(options['stderr'], b'Error: agent rejected request: CLIENT_ROUTE_BUSY (Unavailable)\n')
            return SimpleNamespace(stdout=next(replies))

        diagnostic = {}
        with patch.object(S['subprocess'], 'run', side_effect=success):
            with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                    client='/synthetic/client', scope=SCOPE, diagnostic=diagnostic) as coverage:
                pass
        self.assertEqual(diagnostic, {})
        S['validate_phase_route'](SCOPE, selected(a), coverage.report(True))

    def test_paths_error_cannot_replace_owner_failure_or_weaken_final_coverage(self):
        busy = b'Error: agent rejected request: CLIENT_ROUTE_BUSY (Unavailable)\n'
        for owner_fails in (False, True):
            primary = ValueError('owner operation failed')
            diagnostic, count = {}, [0]

            def invoke(command, **options):
                count[0] += 1
                if count[0] <= 2:
                    return SimpleNamespace(stdout=paths('a' * 32) if count[0] == 1 else event(9))
                os.write(options['stderr'], busy)
                raise subprocess.CalledProcessError(1, ['SECRET_ARGS'], output=b'')

            with self.subTest(owner_fails=owner_fails), patch.object(S['subprocess'], 'run', side_effect=invoke):
                with self.assertRaises(ValueError) as failure:
                    with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                            client='/synthetic/client', scope=SCOPE, diagnostic=diagnostic):
                        if owner_fails:
                            raise primary
            self.assertEqual(count[0], 3)
            if owner_fails:
                self.assertIs(failure.exception, primary)
            else:
                self.assertIsInstance(failure.exception, S['SamplerFailure'])
            self.assertEqual(diagnostic, dict(phase='final_drain', operation='route_query', code='process',
                samples=1, completed=0, failed=0, paths_process=dict(exit_status=1,
                    diagnostic='CLIENT_ROUTE_BUSY', stderr_state='bounded')))
            self.assertNotIn('SECRET', repr(diagnostic))

    def test_partial_busy_stderr_never_reclassifies_paths_timeout(self):
        diagnostic = {}

        def timeout(command, **options):
            os.write(options['stderr'], b'Error: agent rejected request: CLIENT_ROUTE_BUSY (Unavailable)\n')
            raise subprocess.TimeoutExpired(['SECRET_ARGS'], options['timeout'])

        with patch.object(S['subprocess'], 'run', side_effect=timeout) as command:
            with self.assertRaises(S['SamplerFailure']):
                with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', scope=SCOPE, diagnostic=diagnostic):
                    self.fail('timeout must not admit owner work')
        self.assertEqual(command.call_count, 1)
        self.assertEqual(diagnostic, dict(phase='initial', operation='route_query', code='timeout',
            samples=0, completed=0, failed=0))

    def test_real_paths_timeout_reaps_child_and_joins_stderr_reader(self):
        run, popen = subprocess.run, subprocess.Popen
        children, diagnostic = [], {}
        threads_before = set(threading.enumerate())

        def start(*args, **options):
            child = popen(*args, **options)
            children.append(child)
            return child

        def stalled(command, **options):
            self.assertEqual(options['timeout'], 3)
            return run([sys.executable, '-c',
                "import os,time; os.write(2, b'SECRET_PRIVATE' * 20000); time.sleep(30)"], **options)

        started = time.monotonic()
        with patch.object(S['subprocess'], 'run', side_effect=stalled) as command, \
                patch.object(S['subprocess'], 'Popen', side_effect=start):
            with self.assertRaises(S['SamplerFailure']) as failure:
                with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', scope=SCOPE, diagnostic=diagnostic):
                    self.fail('timed-out child must not admit owner work')
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(len(children), 1)
        self.assertLess(children[0].returncode, 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)
        self.assertFalse(any(thread not in threads_before and thread.is_alive()
            and thread.name == 'private-storage-paths-stderr' for thread in threading.enumerate()))
        self.assertEqual(diagnostic, dict(phase='initial', operation='route_query', code='timeout',
            samples=0, completed=0, failed=0))
        self.assertNotIn('SECRET', repr(diagnostic) + str(failure.exception))

    def test_first_route_mismatch_is_closed_and_preserves_acceptance_bounds(self):
        a, b = 'a' * 32, 'b' * 32
        original = paths(a)
        cases = (
            (None, 'reply_bound'), (b'x' * 65537, 'reply_bound'),
            (b'SECRET_PRIVATE_RAW', 'line_format'),
            (original.replace(b'state=1', b'state=5'), 'path_state'),
            (paths('0' * 32), 'zero_context'),
            (original.replace(b'exit=exit', b'exit=SECRET_EXIT'), 'exit_changed'),
            (original.splitlines(keepends=True)[0] + paths(b).splitlines(keepends=True)[1], 'context_count'),
            (original.splitlines(keepends=True)[0], 'path_count'),
            (original.replace(b'path=1', b'path=3'), 'path_ids_changed'),
            (original.replace(b'relay=one', b'relay=SECRET_RELAY'), 'relays_changed'),
            (original.replace(b'state=1', b'state=5').replace(b'exit=exit', b'exit=SECRET_EXIT'), 'path_state'),
        )
        for raw, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(S['RouteMismatch']) as failure:
                    S['selected_context'](raw, SCOPE)
                self.assertEqual(failure.exception.code, code)
                self.assertNotIn('SECRET', str(failure.exception))
        for state in (b'0', b'5', b'6', b'01', b'99'):
            with self.assertRaises(S['RouteMismatch']) as failure:
                S['selected_context'](original.replace(b'state=1', b'state=' + state), SCOPE)
            self.assertEqual(failure.exception.code, 'path_state')
        for state in (b'1', b'2', b'3', b'4'):
            self.assertEqual(S['selected_context'](original.replace(b'state=1', b'state=' + state), SCOPE), a)
        self.assertIsNone(S['selected_context'](b'\n', SCOPE))
        coverage = S['Coverage'](10, SCOPE)
        for index in range(1, 9):
            coverage.route(paths(f'{index:032x}'))
        with self.assertRaises(S['RouteMismatch']) as failure:
            coverage.route(paths('9' * 32))
        self.assertEqual(failure.exception.code, 'context_limit')

    def test_primary_owner_failure_keeps_separate_first_route_mismatch(self):
        diagnostic = {}
        primary = ValueError('synthetic primary owner failure')
        replies = [paths('a' * 32), event(9), paths('b' * 32).replace(b'relay=one', b'relay=SECRET_RELAY')]
        with patch.object(S['subprocess'], 'run', side_effect=[SimpleNamespace(stdout=row) for row in replies]):
            with self.assertRaises(ValueError) as failure:
                with S['capture']('/synthetic/cli', '/synthetic/exit', 10, 1,
                        client='/synthetic/client', scope=SCOPE, diagnostic=diagnostic):
                    raise primary
        self.assertIs(failure.exception, primary)
        self.assertEqual(diagnostic, dict(phase='final_drain', operation='route_scope',
            code='invalid', route_mismatch='relays_changed', samples=1, completed=0, failed=0))
        self.assertNotIn('SECRET', repr(diagnostic))

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
