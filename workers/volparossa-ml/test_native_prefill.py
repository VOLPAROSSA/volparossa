# SPDX-License-Identifier: GPL-3.0-only
"""Inert scheduling/control regressions, never native throughput or inference proof."""
import ctypes
import math
import os
from types import SimpleNamespace
import unittest
from unittest import mock

import llama_cpu as native
from test_worker_protocol import WORKER, controlled_pipe, control


def tokenizer():
    return SimpleNamespace(eos_token_id=151645, decode=lambda *args, **kwargs: "")


class PrefillPolicyTests(unittest.TestCase):
    def test_fast_observations_grow_gradually_back_to_original_128_bound(self):
        quantum = native.PrefillQuantum()
        sizes = []
        for _ in range(8):
            sizes.append(quantum.tokens)
            quantum.completed(quantum.tokens, 0.25, WORKER.require)
        self.assertEqual(sizes, [16, 32, 64, 128, 128, 128, 128, 128])

    def test_slowdown_shrinks_immediately_and_recovery_cannot_jump_unbounded(self):
        quantum = native.PrefillQuantum()
        quantum.completed(128, 8.0, WORKER.require)
        self.assertEqual(quantum.tokens, 32)
        quantum.completed(32, 8.0, WORKER.require)
        self.assertEqual(quantum.tokens, 8)
        quantum.completed(8, 0.001, WORKER.require)
        self.assertEqual(quantum.tokens, 16)

    def test_one_token_floor_and_zero_duration_do_not_expand_native_bounds(self):
        quantum = native.PrefillQuantum()
        quantum.completed(1, 20.0, WORKER.require)
        self.assertEqual(quantum.tokens, 1)
        quantum.completed(1, 0, WORKER.require)
        self.assertEqual(quantum.tokens, 2)
        quantum.completed(128, 0.0, WORKER.require)
        self.assertEqual(quantum.tokens, 128)

    def test_unknown_nonfinite_negative_or_boolean_samples_cannot_tune_work(self):
        for count, seconds in ((0, 1), (129, 1), (True, 1), (16, None),
                               (16, True), (16, -1), (16, math.nan), (16, math.inf),
                               (16, "0.1")):
            with self.subTest(count=count, seconds=seconds):
                quantum = native.PrefillQuantum()
                with self.assertRaisesRegex(WORKER.JobError, "NATIVE_DECODE_FAILED"):
                    quantum.completed(count, seconds, WORKER.require)
                self.assertEqual(quantum.tokens, 16)

    def test_measurement_is_turn_local_and_does_not_reuse_other_owner_cost(self):
        first, second = native.PrefillQuantum(), native.PrefillQuantum()
        first.completed(128, 0.25, WORKER.require)
        self.assertEqual(first.tokens, 128)
        self.assertEqual(second.tokens, 16)


class PrefillCoverageTests(unittest.TestCase):
    def generate(self, prompt, *, prefix=0, cost=lambda count: 0.25, samples=(151645,)):
        batches = []
        model = mock.Mock()
        def decode(tokens):
            batches.append(list(tokens))
            return cost(len(tokens))
        model.decode.side_effect = decode
        model.sample.side_effect = samples
        observed, decoded = mock.Mock(), []
        result = native.generate(model, prompt, tokenizer(), WORKER.model_profile(native.PROFILE),
                                 mock.Mock(), WORKER, observed, retained_tokens=prefix,
                                 decoded_tokens=decoded)
        return batches, decoded, result, model, observed

    def test_full_prompt_boundaries_are_neither_truncated_duplicated_nor_reordered(self):
        for length in (1, 15, 16, 17, 127, 128, 129, 4572, 5164, 12288):
            with self.subTest(length=length):
                prompt = list(range(length))
                batches, decoded, result, model, observed = self.generate(prompt)
                self.assertEqual(sum(batches, []), prompt)
                self.assertEqual(decoded, prompt)
                self.assertTrue(all(1 <= len(batch) <= 128 for batch in batches))
                model.sample.assert_called_once()
                observed.forward_begin.assert_called_once()
                observed.forward_complete.assert_called_once()
                self.assertEqual(result["generation"]["stop_reason"], "eos")

    def test_retained_prefix_is_only_skipped_when_already_decoded(self):
        prompt = list(range(5164))
        for prefix in (1, 127, 4096, len(prompt) - 1):
            with self.subTest(prefix=prefix):
                batches, decoded, _, _, _ = self.generate(prompt, prefix=prefix)
                self.assertEqual(sum(batches, []), prompt[prefix:])
                self.assertEqual(decoded, prompt)

    def test_generation_stays_one_token_and_final_sample_is_not_in_kv_claim(self):
        prompt = list(range(257))
        batches, decoded, result, model, _ = self.generate(prompt, samples=(71, 72, 151645))
        self.assertEqual(sum(batches[:-2], []), prompt)
        self.assertEqual(batches[-2:], [[71], [72]])
        self.assertEqual(decoded, prompt + [71, 72])
        self.assertEqual(result["generated_tokens"], 3)
        self.assertEqual(model.sample.call_count, 3)

    def test_fast_case_adds_only_two_prefill_calls_not_a_fixed_eightfold_count(self):
        prompt = list(range(5164))
        batches, _, _, _, _ = self.generate(prompt)
        original_calls = math.ceil(len(prompt) / 128)
        self.assertEqual(original_calls, 41)
        self.assertEqual(len(batches), original_calls + 2)
        self.assertEqual([len(batch) for batch in batches[:4]], [16, 32, 64, 128])
        # Call count is measurable here; this is NOT a native throughput ratio.

    def test_nonuniform_cost_adapts_without_inserting_extra_model_work(self):
        count = [0]
        def cost(size):
            count[0] += 1
            return 0.25 if count[0] < 5 else size * 0.25
        batches, decoded, _, _, _ = self.generate(list(range(512)), cost=cost)
        self.assertEqual([len(batch) for batch in batches[:6]], [16, 32, 64, 128, 128, 8])
        self.assertTrue(all(len(batch) <= 8 for batch in batches[5:]))
        self.assertEqual(sum(batches, []), decoded)
        self.assertEqual(decoded, list(range(512)))

    def test_failed_decode_never_samples_or_marks_prefill_complete(self):
        model, observed = mock.Mock(), mock.Mock()
        model.decode.side_effect = [0.25, WORKER.JobError("NATIVE_DECODE_FAILED")]
        with self.assertRaisesRegex(WORKER.JobError, "NATIVE_DECODE_FAILED"):
            native.generate(model, list(range(257)), tokenizer(), WORKER.model_profile(native.PROFILE),
                            mock.Mock(), WORKER, observed)
        self.assertEqual([len(call.args[0]) for call in model.decode.call_args_list], [16, 32])
        model.sample.assert_not_called()
        observed.forward_complete.assert_not_called()
        observed.complete.assert_not_called()


class NativeDecodeTimingTests(unittest.TestCase):
    def model(self, probe, decode):
        # Use the real scalar-call/checkpoint method, but never load a native
        # library or model. The injected ABI is only an ordering/cost fixture.
        model = object.__new__(native.NativeModel)
        model.handle, model.require, model.probe = ctypes.c_void_p(123), WORKER.require, probe
        model.lib = SimpleNamespace(vp_llama_decode_v1=decode, vp_llama_close_v1=mock.Mock())
        model.sample = mock.Mock(return_value=151645)
        return model

    def test_elapsed_stops_before_joined_pause_wait(self):
        clock = [100.0]
        probe = mock.Mock()
        def decode(*args):
            clock[0] += 0.5
            return 0
        def join():
            clock[0] += 20.0
        probe.joined.side_effect = join
        model = self.model(probe, decode)
        with mock.patch.object(native.time, "monotonic", side_effect=lambda: clock[0]):
            elapsed = model.decode([1] * 16)
        self.assertEqual(elapsed, 0.5)
        quantum = native.PrefillQuantum()
        quantum.completed(16, elapsed, WORKER.require)
        self.assertEqual(quantum.tokens, 32)
        probe.joined.assert_called_once()
        self.assertEqual(clock[0], 120.5)

    def test_failed_or_cancelled_decode_does_not_return_a_tuning_sample(self):
        for status, joined_error, expected in ((2, None, "NATIVE_DECODE_FAILED"),
                (1, WORKER.JobError("JOB_CANCELLED"), "JOB_CANCELLED")):
            with self.subTest(status=status):
                probe = mock.Mock()
                probe.joined.side_effect = joined_error
                model = self.model(probe, lambda *args: status)
                with self.assertRaisesRegex(WORKER.JobError, expected):
                    model.decode([1])
                probe.joined.assert_called_once()

    def run_controlled(self, *, duration, action="pause", deadline=False, pause_wait=0.0):
        clock, active, issued = [100.0], [False], [None]
        batches, acknowledgements = [], []
        with mock.patch.object(native.time, "monotonic", side_effect=lambda: clock[0]):
            with controlled_pipe() as (session, writer, wire):
                session.request["max_seconds"] = 600
                started = session.started
                os.write(writer, control(1, "resume"))
                session.check()
                probe = native.OwnerProbe(session, WORKER)
                original_emit = WORKER.emit
                def emit(record):
                    original_emit(record)
                    if record.get("phase") == "paused":
                        self.assertFalse(active[0], "ACK while native work is still executing")
                        acknowledgements.append(clock[0] - issued[0])
                        # The owner only resumes after receiving the real pause ACK.
                        clock[0] += pause_wait
                        os.write(writer, control(3, "resume"))
                def decode(_handle, values, count):
                    batches.append(list(values))
                    active[0] = True
                    try:
                        before = wire.getvalue()
                        if issued[0] is None:
                            issued[0] = clock[0]
                            os.write(writer, control(2, action))
                        aborted = probe.callback(None)
                        self.assertEqual(wire.getvalue(), before)
                        clock[0] += duration(count)
                        if deadline:
                            clock[0] = started + 600
                            aborted = probe.callback(None)
                        if action == "pause" and not acknowledgements and not deadline:
                            # Deterministic stand-in for the unchanged Rust owner
                            # guard. It proves scheduling, not actual CPU latency.
                            WORKER.require(clock[0] - issued[0] < 10, "compute_control_ack_deadline")
                        return 1 if aborted else 0
                    finally:
                        active[0] = False
                model = self.model(probe, decode)
                try:
                    with mock.patch.object(WORKER, "emit", side_effect=emit):
                        result = native.generate(model, list(range(257)), tokenizer(),
                            WORKER.model_profile(native.PROFILE), session, WORKER)
                    self.assertEqual(session.started, started)
                    self.assertEqual(session.request["max_seconds"], 600)
                    return batches, acknowledgements, result, session.owner_stats()
                finally:
                    model.close()
                    model.lib.vp_llama_close_v1.assert_called_once()
                    if action != "pause" or deadline:
                        self.assertEqual(acknowledgements, [])

    def test_real_pipe_pause_ack_is_joined_before_next_complete_prefill_quantum(self):
        batches, acknowledgements, result, _ = self.run_controlled(duration=lambda count: 1.0 + count * 0.09)
        self.assertEqual(sum(batches, []), list(range(257)))
        self.assertEqual(len(acknowledgements), 1)
        self.assertAlmostEqual(acknowledgements[0], 2.44)
        self.assertEqual(result["generated_tokens"], 1)
        # With the original128-token call this same synthetic cost is12.52s,
        # so the owner's original10s guard rejects before any pause ACK.

    def test_real_pipe_pause_wait_does_not_shrink_the_next_quantum(self):
        batches, _, _, owner = self.run_controlled(duration=lambda count: 1.0 + count * 0.09,
                                                   pause_wait=20.0)
        self.assertEqual([len(batch) for batch in batches[:2]], [16, 13])
        self.assertEqual(owner["pause_count"], 1)
        self.assertEqual(owner["resume_count"], 2)
        self.assertEqual(owner["paused_ms"], 20000)
        self.assertEqual(sum(batches, []), list(range(257)))

    def test_stalled_operation_still_fails_original_owner_guard(self):
        for count in (16, 1):
            quantum = native.PrefillQuantum()
            quantum.tokens = count
            with self.subTest(count=count), mock.patch.object(native, "PrefillQuantum", return_value=quantum), \
                    self.assertRaisesRegex(WORKER.JobError, "compute_control_ack_deadline"):
                self.run_controlled(duration=lambda count: 11.0)

    def test_cancel_is_not_relabelled_as_successful_pause_or_replayed(self):
        with self.assertRaisesRegex(WORKER.JobError, "JOB_CANCELLED"):
            self.run_controlled(duration=lambda count: 0.1, action="cancel")

    def test_original_absolute_turn_deadline_still_wins_during_decode(self):
        with self.assertRaisesRegex(WORKER.JobError, "JOB_DEADLINE_EXCEEDED"):
            self.run_controlled(duration=lambda count: 0.1, deadline=True)


if __name__ == "__main__":
    unittest.main()
