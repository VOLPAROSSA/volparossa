#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert actor-observation parser, deadline, subprocess and selector wiring tests."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-route-readiness.py'))


def reply(outcome='eligible_advertisement_slate', timestamp=100000):
    return dict(schema_version=1, scope='advertisement_preselection', transport='mptcp',
        captured_at_unix_ms=timestamp, outcome=outcome,
        eligible_slate_observed=outcome == 'eligible_advertisement_slate',
        dataplane_verified=False, route_selected=False)


class Clock:
    def __init__(self):
        self.now = 100

    def read(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Readiness(unittest.TestCase):
    def test_closed_fresh_reply_only(self):
        for outcome in M['OUTCOMES']:
            value = reply(outcome)
            self.assertEqual(M['checked_reply'](json.dumps(value).encode(), 99999, 100001), value)
        for change in ({'captured_at_unix_ms': 99998}, {'captured_at_unix_ms': 100002},
            {'captured_at_unix_ms': True}, {'schema_version': True}, {'transport': 'udp'},
            {'outcome': 'private-sentinel'}, {'route_selected': True}, {'dataplane_verified': True},
            {'eligible_slate_observed': 1}, {'eligible_slate_observed': False},
            {'peer': 'private-sentinel'}, {'scope': 'ready'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                M['checked_reply'](json.dumps(reply() | change).encode(), 99999, 100001)
        for raw in (b'', b'x' * 2049, b'{"outcome":1,"outcome":2}', b'[]', b'null'):
            with self.assertRaises(ValueError):
                M['checked_reply'](raw, 99999, 100001)

    def test_incomplete_and_ineligible_observations_wait_then_eligible(self):
        clock, seen = Clock(), []
        outcomes = iter(('incomplete_snapshot', 'no_eligible_exit_pair',
                         'insufficient_diverse_relays', 'eligible_advertisement_slate'))

        def query(command, timeout):
            seen.append((command, timeout))
            return json.dumps(reply(next(outcomes), clock.now * 1000)).encode(), None

        value = M['observe_until']('/unused/cli', '/unused/socket', 110, query=query,
            wall=clock.read, monotonic=clock.read, sleep=clock.sleep)
        self.assertTrue(value['eligible_slate_observed'])
        self.assertEqual(value['polls'], 4)
        self.assertEqual(clock.now, 103)
        self.assertTrue(all(command == ['/unused/cli', '--control-socket', '/unused/socket',
            'route-readiness', '--transport', 'mptcp'] and timeout <= 5 for command, timeout in seen))
        self.assertFalse(value['route_selected'])
        self.assertFalse(value['dataplane_verified'])

    def test_absent_or_ineligible_capacity_never_passes_original_deadline(self):
        for outcome in ('incomplete_snapshot', 'no_eligible_exit_pair'):
            clock = Clock()

            def query(_command, seconds):
                self.assertLessEqual(seconds, 103 - clock.now)
                return json.dumps(reply(outcome, clock.now * 1000)).encode(), None

            value = M['observe_until']('/unused', '/unused', 103, query=query,
                wall=clock.read, monotonic=clock.read, sleep=clock.sleep)
            self.assertEqual(value['result'], 'deadline_exhausted')
            self.assertEqual(value['polls'], 3)
            self.assertEqual(clock.now, 103)
            self.assertFalse(value['eligible_slate_observed'])

    def test_rejected_query_unknown_and_late_reply_are_terminal_not_ready(self):
        for failure, raw in (('query_rejected', None), ('query_timeout', None),
                             ('reply_oversize', None), (None, b'private-sentinel')):
            clock = Clock()
            value = M['observe_until']('/unused', '/unused', 105,
                query=lambda _cmd, _seconds: (raw, failure),
                wall=clock.read, monotonic=clock.read, sleep=clock.sleep)
            self.assertEqual(value['polls'], 1)
            self.assertFalse(value['eligible_slate_observed'])
            self.assertNotIn('private-sentinel', json.dumps(value))
        clock = Clock()

        def late(_command, _seconds):
            clock.now = 105
            return json.dumps(reply(timestamp=105000)).encode(), None

        value = M['observe_until']('/unused', '/unused', 105, query=late,
            wall=clock.read, monotonic=clock.read, sleep=clock.sleep)
        self.assertFalse(value['eligible_slate_observed'])
        self.assertEqual(value['result'], 'deadline_exhausted')

    def test_monotonic_limit_cannot_be_extended_by_wall_clock_rollback(self):
        clock, wall = Clock(), Clock()

        def query(_command, _seconds):
            raw = json.dumps(reply('incomplete_snapshot', wall.now * 1000)).encode()
            return raw, None

        def sleep(seconds):
            clock.sleep(seconds)
            wall.now -= 1

        value = M['observe_until']('/unused', '/unused', 103, query=query,
            wall=wall.read, monotonic=clock.read, sleep=sleep)
        self.assertEqual(value['result'], 'deadline_exhausted')
        self.assertEqual(value['polls'], 3)

    def test_actual_child_output_overflow_timeout_and_failure_are_bounded_and_reaped(self):
        real_popen, children = subprocess.Popen, []

        def track(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(subprocess, 'Popen', track):
            for code, budget, expected in (
                ('import sys; sys.stderr.write("private-sentinel"); sys.exit(1)', 2, 'query_rejected'),
                ('import sys; sys.stdout.write("x"*10000)', 2, 'reply_oversize'),
                ('import time; time.sleep(10)', .05, 'query_timeout')):
                started = time.monotonic()
                raw, failure = M['bounded_query']([sys.executable, '-c', code], budget)
                self.assertIsNone(raw)
                self.assertEqual(failure, expected)
                self.assertIsNotNone(children[-1].returncode)
                self.assertTrue(children[-1].stdout.closed)
                self.assertLess(time.monotonic() - started, 3)

    def test_maintenance_barrier_is_after_deadline_before_connect_and_other_scenarios_unchanged(self):
        source = (HERE / 'benchmark-selection.sh').read_text()
        start = source.index('benchmark_select_route()')
        body = source[start:]
        self.assertLess(body.index('benchmark_deadline='), body.index('storage-route-readiness.py'))
        self.assertLess(body.index('storage-route-readiness.py'), body.index(' connect \\\n'))
        self.assertIn('"$benchmark_deadline")', body)
        self.assertIn('benchmark_attempt" -lt 360', body)
        self.assertIn('benchmark_draw" -lt 32', body)
        transient = source.split('a01_transient_connect_unavailable()', 1)[1].split('\n}', 1)[0]
        self.assertNotIn('NO_ELIGIBLE_PATHS', transient)
        self.assertNotIn('POLICY_UNAVAILABLE', transient)
        script = r'''
set -eu
source_directory=$1; WORK=$2; binary_directory=/unused
private_storage_maintenance=$3
. "$source_directory/tests/integration/benchmark-selection.sh"
python3() { printf 'observer-called\n' >>"$WORK/calls"; printf '%s\n' '{"eligible_slate_observed":false}'; return 1; }
timeout() { printf 'connect-called\n' >>"$WORK/calls"; return 1; }
benchmark_image_route_diagnostic() { :; }
if benchmark_select_route test mptcp; then exit 3; fi
'''
        for maintenance, expected in (('yes', 'observer-called\n'), ('no', 'connect-called\n')):
            with tempfile.TemporaryDirectory() as temporary:
                subprocess.run(['sh', '-c', script, 'test', str(HERE.parents[1]), temporary, maintenance],
                    check=True, capture_output=True, timeout=5)
                self.assertEqual((Path(temporary) / 'calls').read_text(), expected)


if __name__ == '__main__':
    unittest.main()
