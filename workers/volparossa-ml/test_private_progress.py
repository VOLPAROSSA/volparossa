#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed lifecycle/real-pipe checks, never a successful-model inference claim."""
import io
import json
import select
import subprocess
import unittest
from unittest import mock

from test_worker_protocol import WORKER, embedded_command, request, control


class PrivateProgressTests(unittest.TestCase):
    def test_private_observations_neither_read_input_nor_change_owner_checkpoints(self):
        value = WORKER.validate_request(dict(request(), mode='private_infer'))
        session = WORKER.Session(value)
        with mock.patch.object(WORKER, 'WIRE_OUTPUT', io.StringIO()) as output, \
                mock.patch.object(session, 'check', side_effect=AssertionError('unexpected checkpoint')):
            for stage in WORKER.PRIVATE_STAGES:
                for state in ('begin', 'complete'):
                    session.private_progress(stage, state)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(records), 18)
        for record in records:
            self.assertEqual(set(record), {'version', 'id', 'kind', 'phase', 'step', 'elapsed_ms', 'private_execution'})
            self.assertEqual(set(record['private_execution']), {'stage', 'state'})
            self.assertLess(record['elapsed_ms'], 600000)
        self.assertNotIn('/dataset', output.getvalue())

    def test_public_legacy_output_unchanged_and_private_vocabulary_closed(self):
        session = WORKER.Session(WORKER.validate_request(request()))
        with mock.patch.object(WORKER, 'WIRE_OUTPUT', io.StringIO()) as output:
            session.private_progress('owner_gate', 'begin')
            self.assertEqual(output.getvalue(), '')
            session.request['mode'] = 'private_infer'
            for stage, state in [('PRIVATE_CANARY', 'begin'), ('model_load', 'PRIVATE_CANARY')]:
                with self.assertRaisesRegex(WORKER.JobError, 'INTERNAL_PRIVATE_PROGRESS'):
                    session.private_progress(stage, state)
            with mock.patch.object(session, 'elapsed', return_value=600000):
                session.private_progress('owner_gate', 'begin')
            self.assertEqual(output.getvalue(), '')

    def test_real_private_worker_reports_initial_owner_pause_before_touching_model(self):
        value = dict(request(), mode='private_conversation', steps=1, owner_control=True, max_seconds=5,
                     model_profile=WORKER.QWEN4B_MODEL_PROFILE, model_root='/missing-private-progress-model')
        process = subprocess.Popen(embedded_command(), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        try:
            process.stdin.write(json.dumps(value).encode() + b'\n' + control(1, 'pause'))
            def record():
                self.assertTrue(select.select([process.stdout], [], [], 3)[0], 'missing bounded progress')
                return json.loads(process.stdout.readline(16385))
            first, paused = record(), record()
            self.assertEqual(first['private_execution'], {'stage': 'owner_gate', 'state': 'begin'})
            self.assertEqual(paused['phase'], 'paused')
            self.assertFalse(select.select([process.stdout], [], [], .1)[0])
            process.stdin.write(control(2, 'resume'))
            records = []
            while True:
                current = record()
                records.append(current)
                if current['kind'] == 'result':
                    break
            self.assertEqual(process.wait(timeout=3), 1)
            self.assertEqual(records[-1]['code'], 'JOB_INPUT_NOT_FOUND')
            stages = [item['private_execution'] for item in records if 'private_execution' in item]
            self.assertEqual(stages, [{'stage': 'owner_gate', 'state': 'complete'},
                                      {'stage': 'verify_files', 'state': 'begin'}])
            self.assertEqual(process.stderr.read(), b'')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


if __name__ == '__main__':
    unittest.main()
