#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure coverage/counter contracts, not real core or protected-flow evidence."""
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
S = runpy.run_path(str(HERE / 'private-storage-log-sampler.py'))


def event(timestamp, code='MPTCP_EXIT_FLOW_COMPLETED'):
    return f'{timestamp}\tlevel=1\tevent={code}\tsession=\tpath=-\n'.encode()


class CoveredExitLogs(unittest.TestCase):
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
        self.assertIn("with SAMPLER['capture'](args[2], exit_socket, baseline, F['PHASES'][args[0]]) as coverage:", maintenance)
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
