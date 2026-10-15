# SPDX-License-Identifier: GPL-3.0-only
"""Inert session protocol and exact-prefix tests; no model or native library."""
import copy
import json
import os
import queue
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import llama_cpu as native
import native_session as warm
from test_llama_cpu import job, manifest
from test_native_output_constraint import library
from test_worker_protocol import WORKER


def selected(turn=1):
    return WORKER.validate_request(dict(job(), model_root="/model", dataset_path=f"/session/turn-{turn}/input.json",
        output_root=f"/session/turn-{turn}/output", native_session={"version": 1, "turn": turn},
        id=f"{turn:032x}"))


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


class ContractTests(unittest.TestCase):
    def test_selection_is_closed_native_only_and_fixed_paths(self):
        self.assertEqual(selected()["native_session"], {"version": 1, "turn": 1})
        for value in (None, True, {}, {"version": True, "turn": 1}, {"version": 1, "turn": True},
                      {"version": 1, "turn": 0}, {"version": 1, "turn": 129},
                      {"version": 1, "turn": 1, "token": "private"}):
            with self.subTest(value=value), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(selected(), native_session=value))
        for key, value in (("model_root", "/elsewhere"), ("dataset_path", "/session/turn-2/input.json"),
                           ("output_root", "/session/turn-1/../output"), ("owner_control", False),
                           ("inference_backend", "other")):
            with self.subTest(key=key), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(selected(), **{key: value}))

    def test_legacy_absence_and_manifests_keep_their_own_shapes(self):
        self.assertNotIn("native_session", WORKER.validate_request(job()))
        for version in (1, 2, 3):
            value = manifest()
            value["version"] = version
            if version >= 2:
                value["output_constraints"] = [native.OUTPUT_CONSTRAINT]
            if version == 3:
                value["native_sessions"] = [native.NATIVE_SESSION]
            self.assertEqual(native.validate_manifest(value, WORKER.require), value)
            bad = copy.deepcopy(value)
            if version == 3:
                del bad["native_sessions"]
            else:
                bad["native_sessions"] = [native.NATIVE_SESSION]
            with self.assertRaises(WORKER.JobError):
                native.validate_manifest(bad, WORKER.require)
        for value in (None, [], ["other"], [native.NATIVE_SESSION, native.NATIVE_SESSION]):
            with self.subTest(value=value), self.assertRaises(WORKER.JobError):
                native.validate_manifest(dict(manifest(), version=3, output_constraints=[native.OUTPUT_CONSTRAINT],
                                              native_sessions=value), WORKER.require)

    def test_cpu_soft_delta_never_raises_fixed_hard_task_cap(self):
        with mock.patch.object(warm.resource, "getrusage", return_value=SimpleNamespace(ru_utime=17.2, ru_stime=2.1)), \
                mock.patch.object(warm.resource, "getrlimit", return_value=(1200, 4800)), \
                mock.patch.object(warm.resource, "setrlimit") as set_limit:
            warm.turn_cpu_limit(selected(), WORKER.require)
            set_limit.assert_called_once_with(warm.resource.RLIMIT_CPU, (1220, 4800))
        for consumed, hard in ((float("nan"), 4800), (-1, 4800), (4800, 4800), (0, 9999)):
            with self.subTest(consumed=consumed, hard=hard), \
                    mock.patch.object(warm.resource, "getrusage", return_value=SimpleNamespace(ru_utime=consumed, ru_stime=0)), \
                    mock.patch.object(warm.resource, "getrlimit", return_value=(1200, hard)), \
                    mock.patch.object(warm.resource, "setrlimit") as set_limit, self.assertRaises(WORKER.JobError):
                warm.turn_cpu_limit(selected(), WORKER.require)
            set_limit.assert_not_called()

    def test_backend_configuration_and_tokenizer_are_once_per_owned_runtime(self):
        backend = (mock.Mock(), mock.Mock(), mock.Mock(), {})
        tokenizer = object()
        backend[1].AutoTokenizer.from_pretrained.return_value = tokenizer
        with mock.patch.dict(warm.sys.modules, {"volparossa_llama_cpu": native}), \
                mock.patch.object(WORKER, "load_backend", return_value=backend) as load:
            runtime = warm.Runtime(WORKER)
            for _ in range(2):
                self.assertIs(runtime.backend(2, mock.Mock()), backend)
                self.assertIs(runtime.tokenizer(backend[1], Path("/model")), tokenizer)
            load.assert_called_once()
            backend[1].AutoTokenizer.from_pretrained.assert_called_once()
            with self.assertRaises(WORKER.JobError):
                runtime.backend(1, mock.Mock())
            runtime.close()
            self.assertIsNone(runtime.loaded_tokenizer)


class PrefixTests(unittest.TestCase):
    def setUp(self):
        self.manifest = dict(manifest(), version=3, output_constraints=[native.OUTPUT_CONSTRAINT],
                             native_sessions=[native.NATIVE_SESSION])
        self.constructor = mock.patch.object(native, "NativeModel")
        self.model_type = self.constructor.start()
        self.addCleanup(self.constructor.stop)

    def begin(self, state, prompt, **changes):
        request = dict(selected(), **changes)
        return state.begin(Path("/native-backend"), self.manifest, {"library": "fixed"}, request,
                           prompt, mock.Mock(), WORKER)

    def test_only_exact_decoded_prefix_survives_and_last_prompt_token_is_recomputed(self):
        state = native.RetainedModel()
        self.assertEqual(self.begin(state, [1, 2, 3])[1], 0)
        state.tokens = [1, 2, 3, 4]
        self.assertEqual(self.begin(state, [1, 2, 3])[1], 2)
        self.assertEqual(state.tokens, [])
        state.tokens = [1, 2, 3]
        self.assertEqual(self.begin(state, [1, 9, 3])[1], 1)
        state.tokens = [1, 2, 3]
        self.assertEqual(self.begin(state, [9, 2, 3])[1], 0)
        self.assertEqual(self.model_type.call_count, 1)
        self.assertEqual(self.model_type.call_args.args[1], 1280)
        self.assertTrue(self.model_type.call_args.kwargs["context_capacity"])

    def test_initial_capacity_covers_complete_prompt_and_unchanged_output_bound(self):
        for length, capacity in ((1, 1280), (256, 1280), (257, 1536), (4572, 5632), (12288, 13312)):
            with self.subTest(length=length):
                state = native.RetainedModel()
                self.assertEqual(self.begin(state, [1] * length)[1], 0)
                self.assertEqual(state.capacity, capacity)
                self.assertEqual(self.model_type.call_args.args[1], capacity)
                self.assertGreaterEqual(capacity, length + 1024)
                state.close()

    def test_invalid_full_prompt_is_rejected_before_model_allocation(self):
        for prompt in ([], [1] * 12289, [True], [151936], [-1], (1, 2)):
            with self.subTest(length=len(prompt)), self.assertRaisesRegex(WORKER.JobError, "NATIVE_PROMPT_BOUND"):
                self.begin(native.RetainedModel(), prompt)
        self.model_type.assert_not_called()

    def test_fit_keeps_prefix_and_growth_keeps_model_but_recomputes_entire_prompt(self):
        state = native.RetainedModel()
        model, _ = self.begin(state, [1] * 256)
        state.tokens = [1] * 256
        self.assertEqual(self.begin(state, [1] * 256)[1], 255)
        model.reserve_context.assert_not_called()
        state.tokens = [1] * 256
        def grow(capacity, _probe):
            self.assertEqual(capacity, 1536)
            self.assertEqual(state.tokens, [])
        model.reserve_context.side_effect = grow
        prompt = [1] * 257
        same, prefix = self.begin(state, prompt)
        self.assertIs(same, model)
        self.assertEqual(prefix, 0)
        self.assertEqual(self.model_type.call_count, 1)
        model.close.assert_not_called()
        model.sample.return_value = 151645
        native.generate(model, prompt, SimpleNamespace(eos_token_id=151645, decode=lambda *a, **k: ""),
                        WORKER.model_profile(native.PROFILE), mock.Mock(), WORKER, retained_tokens=prefix)
        self.assertEqual([token for call in model.decode.call_args_list for token in call.args[0]], prompt)
        self.assertEqual([len(call.args[0]) for call in model.decode.call_args_list], [128, 128, 1])
        state.tokens = prompt
        self.assertEqual(self.begin(state, [1, 1])[1], 1)
        self.assertEqual(state.capacity, 1536)  # No shrink/reallocation on a shorter turn.
        model.reserve_context.assert_called_once()

    def test_failed_or_cancelled_growth_clears_tokens_closes_and_cannot_retry(self):
        for code in ("NATIVE_CONTEXT_INITIALIZATION_FAILED", "JOB_CANCELLED"):
            with self.subTest(code=code):
                self.model_type.reset_mock(return_value=True)
                state = native.RetainedModel()
                model, _ = self.begin(state, [1] * 256)
                state.tokens = [1] * 256
                model.reserve_context.side_effect = WORKER.JobError(code)
                with self.assertRaisesRegex(WORKER.JobError, code):
                    self.begin(state, [1] * 257)
                self.assertEqual(state.tokens, [])
                self.assertIsNone(state.model)
                self.assertTrue(state.failed)
                model.close.assert_called_once()
                self.assertEqual(model.begin_turn.call_count, 1)
                with self.assertRaisesRegex(WORKER.JobError, "NATIVE_SESSION_PREFIX_RESET_FAILED"):
                    self.begin(state, [1] * 257)
                self.assertEqual(self.model_type.call_count, 1)

    def test_grown_context_begin_failure_also_closes_without_retry(self):
        state = native.RetainedModel()
        model, _ = self.begin(state, [1] * 256)
        state.tokens = [1] * 256
        model.begin_turn.side_effect = WORKER.JobError("NATIVE_SESSION_PREFIX_RESET_FAILED")
        with self.assertRaisesRegex(WORKER.JobError, "NATIVE_SESSION_PREFIX_RESET_FAILED"):
            self.begin(state, [1] * 257)
        model.reserve_context.assert_called_once()
        model.close.assert_called_once()
        self.assertEqual(state.tokens, [])
        self.assertTrue(state.failed)

    def test_no_cross_instance_identity_or_failed_handle_replacement(self):
        first, second = native.RetainedModel(), native.RetainedModel()
        self.begin(first, [1, 2])
        first.tokens = [1, 2]
        self.assertEqual(self.begin(second, [1, 2])[1], 0)
        self.assertEqual(self.model_type.call_count, 2)
        with self.assertRaises(WORKER.JobError):
            self.begin(first, [1, 2], threads=1)
        first.model.begin_turn.side_effect = WORKER.JobError("NATIVE_SESSION_PREFIX_RESET_FAILED")
        with self.assertRaises(WORKER.JobError):
            self.begin(first, [1, 2])
        self.assertEqual(self.model_type.call_count, 2)
        first.close()
        self.assertEqual(first.tokens, [])
        self.assertIsNone(first.binding)

    def test_generate_reuses_no_uncomputed_sample_and_keeps_full_prompt_bound(self):
        model = mock.Mock()
        model.sample.side_effect = [4, 151645]
        tokenizer = SimpleNamespace(eos_token_id=151645, decode=lambda *a, **k: "ok")
        tokens = []
        result = native.generate(model, [1, 2, 3], tokenizer, WORKER.model_profile(native.PROFILE),
                                 mock.Mock(), WORKER, retained_tokens=2, decoded_tokens=tokens)
        self.assertEqual(tokens, [1, 2, 3, 4])
        self.assertEqual(model.decode.call_args_list, [mock.call([3]), mock.call([4])])
        self.assertEqual(result["generated_tokens"], 2)
        for retain in (-1, 3, True):
            with self.subTest(retain=retain), self.assertRaises(WORKER.JobError):
                native.generate(model, [1, 2, 3], tokenizer, WORKER.model_profile(native.PROFILE),
                                mock.Mock(), WORKER, retained_tokens=retain)


class AbiTests(unittest.TestCase):
    def open(self, value, **kwargs):
        with mock.patch.object(native.ctypes, "CDLL", return_value=value):
            return native.NativeModel(Path("/inert"), kwargs.pop("capacity", 12288 + 1024),
                                      2, mock.Mock(), WORKER.require, **kwargs)

    def capacity_library(self, version=1):
        value = library()
        value.vp_llama_native_session_abi_v1 = mock.Mock(return_value=1)
        value.vp_llama_begin_turn_v1 = mock.Mock(return_value=0)
        if version is not None:
            value.vp_llama_context_capacity_abi_v1 = mock.Mock(return_value=version)
            value.vp_llama_reserve_context_v1 = mock.Mock(return_value=0)
        return value

    def test_capacity_extension_required_only_for_explicit_internal_selection(self):
        for version in (None, 0, 2, True):
            value = self.capacity_library(version)
            with self.subTest(version=version), self.assertRaisesRegex(WORKER.JobError, "NATIVE_SESSION_ABI_MISMATCH"):
                self.open(value, native_session=True, context_capacity=True)
            value.vp_llama_open_v1.assert_not_called()
            self.open(value, native_session=True).close()  # Old callers retain the original v1 ABI.
        value = library()
        self.open(value).close()  # Cold/legacy needs neither session nor capacity symbols.
        value.vp_llama_open_v1.reset_mock()
        with self.assertRaisesRegex(WORKER.JobError, "NATIVE_SESSION_ABI_MISMATCH"):
            self.open(value, context_capacity=True)
        value.vp_llama_open_v1.assert_not_called()

    def test_capacity_handover_uses_new_callback_and_no_model_reopen(self):
        value = self.capacity_library()
        model = self.open(value, native_session=True, context_capacity=True, capacity=1280)
        previous, current = model.probe, mock.Mock()
        def grow(handle, capacity, callback, opaque):
            self.assertIs(model.probe, previous)  # Old owner object stays alive until native returns.
            self.assertIs(handle, model.handle)
            self.assertEqual(capacity, 1536)
            self.assertIs(callback, current.callback)
            self.assertIsNone(opaque)
            return 0
        value.vp_llama_reserve_context_v1.side_effect = grow
        model.reserve_context(1536, current)
        self.assertIs(model.probe, current)
        self.assertEqual(model.capacity, 1536)
        current.joined.assert_called_once()
        value.vp_llama_open_v1.assert_called_once()
        value.vp_llama_close_v1.assert_not_called()
        for capacity in (True, 1536, 1280, 13313):
            with self.subTest(capacity=capacity), self.assertRaisesRegex(WORKER.JobError, "NATIVE_SESSION_PREFIX_BOUND"):
                model.reserve_context(capacity, current)
        value.vp_llama_reserve_context_v1.assert_called_once()
        model.close()
        value.vp_llama_close_v1.assert_called_once()

    def test_capacity_failure_or_pending_cancel_never_commits_capacity(self):
        for status, cancelled in ((3, False), (2, False), (0, True)):
            value = self.capacity_library()
            value.vp_llama_reserve_context_v1.return_value = status
            model = self.open(value, native_session=True, context_capacity=True, capacity=1280)
            current = mock.Mock()
            if cancelled:
                current.joined.side_effect = WORKER.JobError("JOB_CANCELLED")
            with self.subTest(status=status, cancelled=cancelled), self.assertRaises(WORKER.JobError):
                model.reserve_context(1536, current)
            self.assertIs(model.probe, current)
            self.assertEqual(model.capacity, 1280)
            model.close()
            value.vp_llama_close_v1.assert_called_once()

    def test_new_manifest_never_loads_old_or_mismatched_session_abi(self):
        for version in (None, 0, 2, True):
            value = library()
            if version is not None:
                value.vp_llama_native_session_abi_v1 = mock.Mock(return_value=version)
                value.vp_llama_begin_turn_v1 = mock.Mock(return_value=0)
            with self.subTest(version=version), self.assertRaisesRegex(WORKER.JobError, "NATIVE_SESSION_ABI_MISMATCH"):
                self.open(value, native_session=True)
            value.vp_llama_open_v1.assert_not_called()

    def test_selected_turn_resets_exact_prefix_and_does_not_call_legacy_setter(self):
        value = library()
        value.vp_llama_native_session_abi_v1 = mock.Mock(return_value=1)
        value.vp_llama_begin_turn_v1 = mock.Mock(return_value=0)
        model = self.open(value, native_session=True, output_constraints=[native.OUTPUT_CONSTRAINT])
        probe = mock.Mock()
        model.begin_turn(12, probe, native.OUTPUT_CONSTRAINT, ["vp_0", "vp_1"])
        self.assertEqual(value.vp_llama_begin_turn_v1.call_args.args[1:4], (12, 1, 2))
        self.assertIs(value.vp_llama_begin_turn_v1.call_args.args[4], probe.callback)
        self.assertIs(model.probe, probe)
        value.vp_llama_set_output_constraint_v1.assert_not_called()
        model.close()
        value.vp_llama_close_v1.assert_called_once()


class PipeTests(unittest.TestCase):
    def test_two_real_pipe_turns_drain_old_controls_before_next_request(self):
        read, write = os.pipe()
        output, errors = queue.Queue(), []
        runtime = mock.Mock()
        def execute(request, session, *, native_session):
            self.assertIs(native_session, runtime)
            session.check()
            return {"version": 1, "id": request["id"], "kind": "result", "status": "ok"}
        def consume():
            try:
                errors.append(warm.run(selected(), WORKER.InputFrames(read), WORKER))
            except BaseException as error:
                errors.append(error)
        with mock.patch.object(warm, "Runtime", return_value=runtime), \
                mock.patch.object(warm, "turn_cpu_limit"), \
                mock.patch.object(WORKER, "execute_job", side_effect=execute), \
                mock.patch.object(WORKER, "emit", side_effect=output.put):
            thread = threading.Thread(target=consume, daemon=True)
            thread.start()
            try:
                for turn in (1, 2):
                    request = selected(turn)
                    if turn == 2:
                        os.write(write, frame(request))
                    os.write(write, frame({"version": 1, "id": request["id"], "sequence": 1, "action": "resume"}))
                    self.assertEqual(output.get(timeout=2)["phase"], "resumed")
                    self.assertEqual(output.get(timeout=2)["kind"], "result")
                    # A real old control in flight at result time must not become
                    # an invalid next request or authorize more model operations.
                    os.write(write, frame({"version": 1, "id": request["id"], "sequence": 2, "action": "pause"})
                        + frame({"version": 1, "id": request["id"], "kind": "native_turn_finish"}))
                    self.assertEqual(output.get(timeout=2)["phase"], "paused")
                    self.assertEqual(output.get(timeout=2), {"version": 1, "id": request["id"], "kind": "native_turn_idle"})
                os.close(write)
                write = None
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [0])
                runtime.close.assert_called_once()
            finally:
                if write is not None:
                    os.close(write)
                thread.join(2)
                os.close(read)

    def test_deadline_cancel_and_partial_eof_never_become_idle_success(self):
        read, write = os.pipe()
        try:
            frames = WORKER.InputFrames(read)
            with self.assertRaisesRegex(WORKER.JobError, "DEADLINE"):
                warm.read_frame(frames, time.monotonic() - 1, WORKER, eof=True)
            with mock.patch.object(WORKER, "is_stopping", return_value=True), \
                    self.assertRaisesRegex(WORKER.JobError, "CANCELLED"):
                warm.read_frame(frames, time.monotonic() + 1, WORKER, eof=True)
            os.write(write, b'{"version":')
            os.close(write)
            write = None
            with self.assertRaisesRegex(WORKER.JobError, "OWNER_CONTROL_CLOSED"):
                warm.read_frame(frames, time.monotonic() + 1, WORKER, eof=True)
        finally:
            if write is not None:
                os.close(write)
            os.close(read)


if __name__ == "__main__":
    unittest.main()
