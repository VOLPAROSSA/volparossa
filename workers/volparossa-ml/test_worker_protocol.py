#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Standard-library framing/admission checks; never a successful-model execution claim."""

import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("worker.py")
SPEC = importlib.util.spec_from_file_location("volparossa_ml_worker", SOURCE)
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


def request():
    return {"version": 1, "id": "a" * 32, "mode": "train", "model_root": "/model",
            "dataset_path": "/dataset.json", "output_root": "/output"}


def control(sequence, action="resume", **changes):
    value = {"version": 1, "id": "a" * 32, "sequence": sequence, "action": action}
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


@contextlib.contextmanager
def controlled_pipe():
    reader, writer = os.pipe()
    try:
        value = WORKER.validate_request(dict(request(), owner_control=True))
        session = WORKER.Session(value, WORKER.InputFrames(reader))
        with mock.patch.object(WORKER, "WIRE_OUTPUT", io.StringIO()) as output:
            yield session, writer, output
    finally:
        os.close(reader)
        os.close(writer)


@contextlib.contextmanager
def controlled_process(seconds=10, initial=True):
    # Actual embedded worker and real pipes. Missing paths guarantee no model execution.
    with tempfile.TemporaryDirectory() as directory:
        value = dict(request(), owner_control=True, max_seconds=seconds,
                     model_root=str(Path(directory) / "missing-model"))
        process = subprocess.Popen([sys.executable, "-I", "-c", SOURCE.read_text(encoding="utf-8")],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
        try:
            raw = json.dumps(value).encode() + b"\n"
            process.stdin.write(raw + (control(1, "pause") if initial else b""))
            yield process
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def process_record(process, timeout=3):
    deadline, raw = time.monotonic() + timeout, bytearray()
    while len(raw) < WORKER.MAX_LINE:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            raise AssertionError("worker protocol record timed out")
        block = os.read(process.stdout.fileno(), 1)
        if not block:
            raise AssertionError("worker closed stdout before a complete record")
        raw.extend(block)
        if block == b"\n":
            return json.loads(raw)
    raise AssertionError("worker protocol record exceeded bound")


def dataset():
    return {"version": 1, "visibility": "public", "license": "GPL-3.0-only", "source_revision": "b" * 40,
            "train": [{"question": "Which platform?", "answer": "Debian 13 amd64.",
                       "context": "The project targets Debian 13 amd64."}],
            "heldout": [{"question": "What is the supported architecture?", "answer": "amd64.",
                         "context": "The project targets Debian 13 amd64."}],
            "inference": [{"question": "Which Debian release?", "context": "Debian 13 is supported."}]}


def adapter_config():
    return {"base_model_name_or_path": WORKER.MODEL_ID, "revision": WORKER.MODEL_REVISION,
            "peft_type": "LORA", "task_type": "CAUSAL_LM", "r": 4, "lora_alpha": 8,
            "lora_dropout": 0.0, "bias": "none", "inference_mode": True,
            "target_modules": ["q_proj", "v_proj"], **WORKER.ADAPTER_DEFAULTS}


def adapter_bytes(header_change=None, last_float=0.0):
    # Synthetic safetensors parser fixture, not trained weights or execution evidence.
    header, offset = {"__metadata__": {"format": "pt"}}, 0
    for name, shape in WORKER.adapter_shapes().items():
        length = shape[0] * shape[1] * 4
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + length]}
        offset += length
    if header_change:
        header_change(header)
    raw_header = json.dumps(header, separators=(",", ":")).encode("utf-8")
    raw_header += b" " * (-len(raw_header) % 8)
    return len(raw_header).to_bytes(8, "little") + raw_header + bytes(offset - 4) + struct.pack("<f", last_float)


class WorkerProtocolTests(unittest.TestCase):
    def test_encoding_requests_flat_tokens_and_preserves_prompt_mask_and_length_limit(self):
        class Tokenizer:
            def apply_chat_template(self, _messages, *, tokenize, add_generation_prompt, return_dict=True):
                assert tokenize
                tokens = [1, 2] if add_generation_prompt else [1, 2, 3]
                return {"input_ids": tokens} if return_dict else tokens

        # Contract-only fixture, without importing a tokenizer/model backend.
        backend = mock.Mock()
        backend.tensor.side_effect = lambda value, **_kwargs: value
        encoded = WORKER.encode_dataset(Tokenizer(), backend, dataset())
        self.assertEqual(encoded["train"][0]["input_ids"], [[1, 2, 3]])
        self.assertEqual(encoded["train"][0]["labels"], [[-100, -100, 3]])
        self.assertEqual(encoded["heldout"][0]["labels"], [[-100, -100, 3]])
        self.assertEqual(encoded["inference"], [[[1, 2]]])
        wrong = mock.Mock()
        wrong.apply_chat_template.return_value = {"input_ids": [1, 2]}
        with self.assertRaisesRegex(WORKER.JobError, "MODEL_TOKENIZER_RETURN_TYPE"):
            WORKER.encode_dataset(wrong, backend, dataset())
        wrong.apply_chat_template.return_value = [1] * (WORKER.MAX_CONTEXT + 1)
        with self.assertRaisesRegex(WORKER.JobError, "DOCUMENT_TOKEN_LIMIT_EXCEEDED"):
            WORKER.encode_dataset(wrong, backend, dataset())

    def test_request_schema_preserves_id_and_enforces_real_resource_caps(self):
        parsed = WORKER.validate_request(request())
        self.assertEqual(parsed["id"], "a" * 32)
        self.assertEqual((parsed["steps"], parsed["threads"], parsed["max_seconds"]), (8, 2, 600))
        for field, values in {"version": [True, 2], "id": ["A" * 32, "a" * 31],
                              "mode": ["shell", "classify"], "steps": [0, 65, True],
                              "threads": [0, 3], "max_seconds": [0, 601],
                              "model_root": ["relative", "/", "/bad\x00path"]}.items():
            for value in values:
                invalid = request()
                invalid[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(WORKER.JobError):
                    WORKER.validate_request(invalid)
        invalid = request()
        invalid["command"] = "unused"
        with self.assertRaises(WORKER.JobError):
            WORKER.validate_request(invalid)

    def test_optional_adapter_path_preserves_old_request_and_supports_both_modes(self):
        self.assertNotIn("adapter_root", WORKER.validate_request(request()))
        for mode in ("infer", "train"):
            source = dict(request(), adapter_root="/adapter", mode=mode)
            self.assertEqual(WORKER.validate_request(source)["adapter_root"], "/adapter")
        for value in (None, "", "relative", "/", "/a\x00b", 42):
            with self.assertRaisesRegex(WORKER.JobError, "INVALID_JOB_PATH"):
                WORKER.validate_request(dict(request(), adapter_root=value))

    def test_owner_control_is_explicit_boolean_and_legacy_frames_still_require_eof(self):
        self.assertNotIn("owner_control", WORKER.validate_request(request()))
        for enabled in (False, True):
            self.assertIs(WORKER.validate_request(dict(request(), owner_control=enabled))["owner_control"], enabled)
        for value in (None, 0, 1, "true", []):
            with self.assertRaisesRegex(WORKER.JobError, "INVALID_OWNER_CONTROL"):
                WORKER.validate_request(dict(request(), owner_control=value))
        process = self.run_embedded(json.dumps(dict(request(), owner_control=False)).encode() + b"\n{}\n")
        result = json.loads(process.stdout)
        self.assertEqual((process.returncode, result["code"]), (1, "INVALID_REQUEST_FRAME"))
        self.assertNotIn("owner_control", result)

    def test_real_pipe_controls_ack_every_action_and_stop_at_original_record_budget(self):
        with controlled_pipe() as (session, writer, output):
            for sequence in range(1, WORKER.MAX_CONTROLS + 1):
                os.write(writer, control(sequence))
                session.check()
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual([record["control_sequence"] for record in records], list(range(1, 129)))
            self.assertTrue(all(record["phase"] == "resumed" and record["step"] == 0 for record in records))
            self.assertEqual(session.owner_stats(), {"enabled": True, "records_received": 128,
                             "last_sequence": 128, "pause_count": 0, "resume_count": 128, "paused_ms": 0})
            os.write(writer, control(129))
            with self.assertRaisesRegex(WORKER.JobError, "INVALID_CONTROL_SEQUENCE"):
                session.check()

    def test_real_pipe_controls_reject_wrong_binding_replay_noncanonical_numbers_and_oversized_frames(self):
        cases = [(control(1, version=True), "INVALID_CONTROL_BINDING"),
                 (control(1, id="b" * 32), "INVALID_CONTROL_BINDING"),
                 (control(True), "INVALID_CONTROL_SEQUENCE"),
                 (control(1.0), "INVALID_CONTROL_SEQUENCE"),
                 (control(0), "INVALID_CONTROL_SEQUENCE"),
                 (control(2), "INVALID_CONTROL_SEQUENCE"),
                 (control(1, "shell"), "INVALID_CONTROL_ACTION"),
                 (control(1, extra=True), "INVALID_CONTROL_FIELDS"),
                 (b'{"version":1,"version":1}\n', "DUPLICATE_JSON_KEY"),
                 (b" " * WORKER.MAX_CONTROL_LINE + b"\n", "INVALID_CONTROL_FRAME")]
        for frame, code in cases:
            with self.subTest(code=code), controlled_pipe() as (session, writer, output):
                os.write(writer, frame)
                with self.assertRaisesRegex(WORKER.JobError, code):
                    session.check()
                self.assertEqual(output.getvalue(), "")
        with controlled_pipe() as (session, writer, _output):
            os.write(writer, control(1))
            session.check()
            os.write(writer, control(1))
            with self.assertRaisesRegex(WORKER.JobError, "INVALID_CONTROL_SEQUENCE"):
                session.check()

    def test_real_process_preserves_immediate_controls_and_pauses_before_model_work(self):
        with controlled_process() as process:
            first = process_record(process)
            self.assertEqual((first["phase"], first["control_sequence"], first["step"]), ("paused", 1, 0))
            self.assertFalse(select.select([process.stdout], [], [], 0.08)[0])
            self.assertIsNone(process.poll())
            process.stdin.write(control(2) + control(3, "pause"))
            self.assertEqual((process_record(process)["phase"], process_record(process)["phase"]),
                             ("resumed", "paused"))
            self.assertFalse(select.select([process.stdout], [], [], 0.08)[0])
            process.stdin.write(control(4, "cancel"))
            result = process_record(process)
            self.assertEqual((result["kind"], result["status"], result["code"]),
                             ("result", "error", "JOB_CANCELLED"))
            self.assertEqual(result["owner_control"] | {"paused_ms": 0},
                             {"enabled": True, "records_received": 4, "last_sequence": 4,
                              "pause_count": 2, "resume_count": 1, "paused_ms": 0})
            self.assertGreaterEqual(result["owner_control"]["paused_ms"], 100)
            self.assertEqual(process.wait(timeout=3), 1)
            self.assertEqual(process.stderr.read(), b"")

    def test_real_process_waits_for_initial_permission_and_resume_reaches_existing_input_checks(self):
        with controlled_process(initial=False) as process:
            self.assertFalse(select.select([process.stdout], [], [], 0.08)[0])
            process.stdin.write(control(1))
            self.assertEqual(process_record(process)["phase"], "resumed")
            self.assertEqual(process_record(process)["phase"], "preparing")
            result = process_record(process)
            self.assertEqual(result["code"], "JOB_INPUT_NOT_FOUND")
            self.assertEqual(result["owner_control"]["resume_count"], 1)
            self.assertEqual(result["owner_control"]["pause_count"], 0)
            self.assertEqual(process.wait(timeout=3), 1)

    def test_real_process_paused_eof_signal_and_original_deadline_remain_terminal(self):
        for reason in ("eof", "signal", "deadline"):
            with self.subTest(reason=reason), controlled_process(seconds=1) as process:
                self.assertEqual(process_record(process)["phase"], "paused")
                if reason == "eof":
                    process.stdin.close()
                elif reason == "signal":
                    process.terminate()
                result = process_record(process)
                expected = {"eof": "OWNER_CONTROL_CLOSED", "signal": "JOB_CANCELLED",
                            "deadline": "JOB_DEADLINE_EXCEEDED"}[reason]
                self.assertEqual((result["status"], result["code"]), ("error", expected))
                self.assertEqual(result["owner_control"]["last_sequence"], 1)
                if reason == "deadline":
                    self.assertGreaterEqual(result["elapsed_ms"], 1000)
                    self.assertGreaterEqual(result["owner_control"]["paused_ms"], 900)
                self.assertEqual(process.wait(timeout=3), 1)

    def test_adapter_configuration_is_admission_only_with_no_dynamic_operator(self):
        config = adapter_config()
        WORKER.validate_adapter_config(config)
        WORKER.validate_adapter_config(dict(config, target_modules=["v_proj", "q_proj"]))
        for name, value in (("base_model_name_or_path", "other/model"), ("revision", "main"),
                            ("r", 8), ("r", True), ("lora_alpha", 16), ("lora_dropout", 0.1),
                            ("target_modules", "all-linear"), ("target_modules", ["q_proj", "q_proj"]),
                            ("bias", "all"), ("auto_mapping", {"parent_library": "unsafe"}),
                            ("init_lora_weights", "pissa"), ("modules_to_save", ["lm_head"]),
                            ("use_dora", True), ("layer_replication", [[0, 30]]),
                            ("runtime_config", {}), ("unrecognized_extension", None)):
            with self.subTest(name=name), self.assertRaisesRegex(WORKER.JobError, "UNSUPPORTED_ADAPTER_CONFIG"):
                WORKER.validate_adapter_config(dict(config, **{name: value}))

    def test_safetensors_requires_all_exact_fp32_shapes_dense_offsets_and_finite_values(self):
        WORKER.validate_adapter_weights(adapter_bytes())
        self.assertEqual(len(WORKER.adapter_shapes()), 120)
        name = next(iter(WORKER.adapter_shapes()))
        mutations = [
            lambda h: h.pop(name),
            lambda h: h.update({"unexpected.weight": h[name]}),
            lambda h: h[name].update(dtype="F16"),
            lambda h: h[name].update(shape=[8, 576]),
            lambda h: h[name].update(data_offsets=[4, 9220]),
            lambda h: h.update({"__metadata__": {"custom_loader": "unsafe"}}),
        ]
        for mutation in mutations:
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_adapter_weights(adapter_bytes(mutation))
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaisesRegex(WORKER.JobError, "NONFINITE_ADAPTER_WEIGHTS"):
                WORKER.validate_adapter_weights(adapter_bytes(last_float=value))
        with self.assertRaises(WORKER.JobError):
            WORKER.validate_adapter_weights(adapter_bytes() + b"trailing")

    def test_actual_temporary_adapter_files_are_hash_bound_and_not_executable_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "adapter"
            root.mkdir(mode=0o700)
            output = Path(directory) / "output"
            output.mkdir(mode=0o700)
            contents = {"adapter_config.json": json.dumps(adapter_config()).encode(),
                        "adapter_model.safetensors": adapter_bytes(), "README.md": b"Synthetic parser fixture.\n"}
            for name, raw in contents.items():
                (root / name).write_bytes(raw)
                (root / name).chmod(0o600)
            actual_root, files, weights = WORKER.prepare_adapter(str(root), output)
            self.assertEqual(actual_root, root)
            self.assertEqual(weights, contents["adapter_model.safetensors"])
            self.assertEqual(set(files), set(WORKER.ADAPTER_FILES))
            for name, item in files.items():
                self.assertEqual(item, WORKER.file_hash(root / name))
            with self.assertRaisesRegex(WORKER.JobError, "ADAPTER_OUTPUT_PATH_OVERLAP"):
                WORKER.prepare_adapter(str(root), Path(directory))
            (root / "extra.py").write_bytes(b"never executed")
            with self.assertRaisesRegex(WORKER.JobError, "UNSUPPORTED_ADAPTER_FILES"):
                WORKER.prepare_adapter(str(root), output)
            (root / "extra.py").unlink()
            (root / "README.md").unlink()
            (root / "README.md").symlink_to(output)
            with self.assertRaises((OSError, WORKER.JobError)):
                WORKER.prepare_adapter(str(root), output)
            (root / "README.md").unlink()
            (root / "README.md").write_bytes(b"x" * 16385)
            with self.assertRaisesRegex(WORKER.JobError, "ARTIFACT_TOO_LARGE"):
                WORKER.prepare_adapter(str(root), output)

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        for raw in (b'{"version":1,"version":1}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}'):
            with self.assertRaises(WORKER.JobError):
                WORKER.parse_json(raw)

    def test_explicit_public_data_requires_disjoint_heldout_questions(self):
        original = dataset()
        self.assertEqual(WORKER.validate_dataset(original, "train"), original)
        for field, value in (("visibility", "private"), ("license", "unknown"), ("source_revision", "latest")):
            invalid = copy.deepcopy(original)
            invalid[field] = value
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(invalid, "train")
        invalid = copy.deepcopy(original)
        invalid["heldout"][0]["question"] = "  WHICH PLATFORM? "
        with self.assertRaisesRegex(WORKER.JobError, "TRAIN_HELDOUT_OVERLAP"):
            WORKER.validate_dataset(invalid, "train")
        for split in ("train", "heldout", "inference"):
            invalid = copy.deepcopy(original)
            invalid[split] *= 2
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(invalid, "train")

    def test_output_frame_cap_is_applied_before_any_write(self):
        previous = WORKER.WIRE_OUTPUT
        output = io.StringIO()
        WORKER.WIRE_OUTPUT = output
        try:
            with self.assertRaisesRegex(WORKER.JobError, "RESULT_TOO_LARGE"):
                WORKER.emit({"value": "x" * WORKER.MAX_LINE})
            self.assertEqual(output.getvalue(), "")
        finally:
            WORKER.WIRE_OUTPUT = previous

    def run_embedded(self, raw):
        # The actual deployment mode has no __file__ and a bounded stdin/stdout contract.
        return subprocess.run([sys.executable, "-I", "-c", SOURCE.read_text(encoding="utf-8")],
                              input=raw, capture_output=True, timeout=10, check=False)

    def test_real_embedded_process_rejects_extra_frames_and_preserves_valid_correlation(self):
        invalid = request()
        invalid["steps"] = 65
        process = self.run_embedded(json.dumps(invalid).encode("utf-8") + b"\n")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stderr, b"")
        result = json.loads(process.stdout)
        self.assertEqual((result["id"], result["kind"], result["status"], result["code"]),
                         ("a" * 32, "result", "error", "INVALID_JOB_BUDGET"))
        process = self.run_embedded(json.dumps(request()).encode("utf-8") + b"\n{}\n")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(process.stdout)["code"], "INVALID_REQUEST_FRAME")

    def test_all_original_model_files_are_bound_not_only_weights(self):
        self.assertEqual(set(WORKER.MODEL_FILES), set(WORKER.MODEL_HASHES))
        self.assertEqual(len(WORKER.MODEL_FILES), 8)
        self.assertEqual(WORKER.MODEL_FILES["model.safetensors"], 269060552)
        self.assertEqual(WORKER.MODEL_HASHES["model.safetensors"], WORKER.MODEL_WEIGHT_SHA)
        for digest in WORKER.MODEL_HASHES.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
