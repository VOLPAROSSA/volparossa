#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert scalar/hook/protocol tests. No tensor backend or model is loaded."""
import io
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from test_worker_protocol import WORKER, request, task_planner_doubles


def session(enabled=True):
    return SimpleNamespace(request=dict(request(), private_generation_diagnostics=enabled),
                           elapsed=mock.Mock(return_value=10), check=mock.Mock())


def cpu():
    return SimpleNamespace(get_num_threads=lambda: 2, get_num_interop_threads=lambda: 1,
        cpu=SimpleNamespace(get_capabilities=lambda: {'avx2': True, 'avx512_bf16': False,
                                                     'amx_bf16': None, 'amx_tile': True}),
        backends=SimpleNamespace(cpu=SimpleNamespace(get_cpu_capability=lambda: 'AVX2'),
                                 mkldnn=SimpleNamespace(is_available=lambda: True, enabled=True)))


class PrivateGenerationTests(unittest.TestCase):
    def test_request_flag_is_boolean_explicit_and_private_native_only(self):
        value = dict(request(), mode='private_conversation', model_profile=WORKER.QWEN4B_MODEL_PROFILE,
                     steps=1, owner_control=True, private_generation_diagnostics=True)
        self.assertTrue(WORKER.validate_request(value)['private_generation_diagnostics'])
        for change in ({'mode': 'public_code_proposal'}, {'mode': 'private_infer'},
                       {'model_profile': WORKER.DEFAULT_MODEL_PROFILE},
                       {'private_generation_diagnostics': 1}, {'private_generation_diagnostics': None}):
            with self.subTest(change=change), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(value, **change))
        self.assertNotIn('private_generation_diagnostics', WORKER.validate_request(request()))

    def test_disabled_observation_does_not_touch_model_backend_or_wire(self):
        with mock.patch.object(WORKER, 'WIRE_OUTPUT', io.StringIO()) as output:
            with WORKER.private_generation_observation(None, None, session(False), 3) as observed:
                self.assertIsNone(observed)
            self.assertEqual(output.getvalue(), '')

    def test_unknown_capabilities_remain_null_without_raw_hardware_or_init(self):
        backend = cpu()
        backend.cpu.get_capabilities = mock.Mock(side_effect=RuntimeError('PRIVATE_CANARY'))
        backend.backends.cpu.get_cpu_capability = lambda: 'PRIVATE_CANARY'
        backend.backends.mkldnn.enabled = 1
        backend.get_num_threads = lambda: 'PRIVATE_CANARY'
        with mock.patch.object(WORKER, 'WIRE_OUTPUT', io.StringIO()) as output:
            observed = WORKER.PrivateGenerationObservation(session(), backend, 12288)
        self.assertIsNone(observed.value['threads'])
        self.assertIsNone(observed.value['cpu']['avx512_bf16'])
        self.assertIsNone(observed.value['cpu']['mkldnn_enabled'])
        self.assertIsNone(observed.value['cpu']['isa'])
        self.assertNotIn('PRIVATE_CANARY', output.getvalue())

    def test_hooks_and_existing_checkpoint_preserve_generation_and_checks(self):
        for failure in (None, 'FORWARD_FAILED', 'JOB_CANCELLED', 'JOB_DEADLINE_EXCEEDED'):
            with self.subTest(failure=failure):
                model, tokenizer, torch, transformers = task_planner_doubles('Inert output.')
                owner = session()
                hooks = {}
                pre_handle, post_handle = mock.Mock(), mock.Mock()
                model.register_forward_pre_hook.side_effect = lambda fn: hooks.setdefault('pre', fn) and pre_handle
                model.register_forward_hook.side_effect = lambda fn: hooks.setdefault('post', fn) and post_handle
                native = mock.Mock()
                native.native.return_value.generation_options.return_value = {'do_sample': False, 'num_beams': 1}
                def generate(**kwargs):
                    self.assertEqual(set(kwargs), {'input_ids', 'attention_mask', 'max_new_tokens', 'use_cache',
                        'do_sample', 'num_beams', 'stopping_criteria', 'pad_token_id', 'eos_token_id'})
                    self.assertEqual((kwargs['max_new_tokens'], kwargs['do_sample'], kwargs['num_beams'],
                                      kwargs['use_cache']), (1024, False, 1, True))
                    self.assertIsNone(hooks['pre'](model, object()))
                    if failure == 'FORWARD_FAILED':
                        raise RuntimeError(failure)
                    self.assertIsNone(hooks['post'](model, object(), object()))
                    for count in range(1, 4):
                        if failure and count == 2:
                            owner.check.side_effect = WORKER.JobError(failure)
                        self.assertFalse(kwargs['stopping_criteria'][0](torch.tensor([[11, 12, 13] + [21] * count]), object()))
                    return torch.tensor([[11, 12, 13, 21, 22, 2]])
                model.generate.side_effect = generate
                with mock.patch.object(WORKER, 'conversation_module', return_value=native), \
                        mock.patch.object(WORKER, 'WIRE_OUTPUT', io.StringIO()) as output:
                    args = (model, [torch.tensor([[11, 12, 13]])], tokenizer, torch, owner, transformers,
                            WORKER.QWEN4B_MODEL_PROFILE)
                    if failure:
                        with self.assertRaisesRegex(Exception, failure):
                            WORKER.generate(*args, generation_policy='greedy_v1')
                        tokenizer.decode.assert_not_called()
                    else:
                        result = WORKER.generate(*args, generation_policy='greedy_v1')
                        self.assertEqual(result[0]['generated_tokens'], 3)
                        self.assertEqual(result[0]['generation']['stop_reason'], 'eos')
                        self.assertEqual(tokenizer.decode.call_args.args[0], [21, 22])
                        self.assertEqual(owner.check.call_count, 5)
                values = [json.loads(line)['private_generation'] for line in output.getvalue().splitlines()]
                self.assertEqual(values[-1]['complete'], failure is None)
                if failure == 'FORWARD_FAILED':
                    self.assertIsNone(values[-1]['first_forward_completed_ms'])
                    self.assertEqual(values[-1]['generated_tokens'], 0)
                pre_handle.remove.assert_called_once_with()
                post_handle.remove.assert_called_once_with()
                model.register_forward_hook.assert_called_once_with(hooks['post'])

    def test_progress_is_bounded_without_extra_owner_checks_and_stops_at_deadline(self):
        owner = session()
        with mock.patch.object(WORKER, 'WIRE_OUTPUT', io.StringIO()) as output:
            observed = WORKER.PrivateGenerationObservation(owner, cpu(), 12288)
            observed.forward_begin(None, None)
            observed.forward_complete(None, None, None)
            for token in range(1, 1025):
                owner.elapsed.return_value = min(599999, token * 580)
                observed.tokens(token)
            observed.complete()
            count = len(output.getvalue().splitlines())
            owner.elapsed.return_value = 600000
            observed.record()
            self.assertEqual(len(output.getvalue().splitlines()), count)
            records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertLessEqual(count, 64)
        self.assertLess(len(output.getvalue().encode()), 65536)
        self.assertEqual(records[-1]['private_generation']['generated_tokens'], 1024)
        self.assertTrue(records[-1]['private_generation']['complete'])
        self.assertTrue(all(set(row) == {'version', 'id', 'kind', 'phase', 'step', 'elapsed_ms',
                                        'private_generation'} for row in records))
        owner.check.assert_not_called()

    def test_rate_limit_uses_emitted_timestamp_not_earlier_callback_time(self):
        owner = session()
        owner.elapsed.side_effect = [10, 11, 12, 13, 14, 15, 16, 10015, 10016, 10017]
        with mock.patch.object(WORKER, 'WIRE_OUTPUT', io.StringIO()) as output:
            observed = WORKER.PrivateGenerationObservation(owner, cpu(), 100)
            observed.forward_begin(None, None)
            observed.forward_complete(None, None, None)
            observed.tokens(1)
            observed.tokens(2)  # Only 9999ms since the first emitted token record.
            observed.tokens(3)
            records = [json.loads(line)['private_generation'] for line in output.getvalue().splitlines()]
        self.assertEqual([value['elapsed_ms'] for value in records], [10, 12, 14, 16, 10017])
        self.assertEqual([value['generated_tokens'] for value in records], [0, 0, 0, 1, 3])


if __name__ == '__main__':
    unittest.main()
