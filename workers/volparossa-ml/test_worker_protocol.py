#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Standard-library framing/admission checks; never a successful-model execution claim."""

import copy
import contextlib
import importlib.util
import io
import hashlib
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


def task_plan_input():
    return dict(version=1, visibility="public", license="CC0-1.0", question="What are the requirements and risks?",
                source_sha256="a" * 64, source_bytes=128)


def task_planner_doubles(text, generated=None, prompt=None):
    # Pure branch doubles only. Never import a real tokenizer, tensor library or model.
    class Vector:
        def __init__(self, values):
            self.values = values

        def tolist(self):
            return self.values

    class Tensor:
        def __init__(self, rows):
            self.rows = rows
            self.shape = (len(rows), len(rows[0]))

        def __getitem__(self, index):
            return Vector(self.rows[index[0]][index[1]])

    prompt = [11, 12, 13] if prompt is None else prompt
    generated = [21, 22, 2] if generated is None else generated
    tokenizer, torch, transformers, model = (mock.Mock() for _ in range(4))
    tokenizer.pad_token_id = tokenizer.eos_token_id = 2
    tokenizer.apply_chat_template.return_value = prompt
    texts = text if isinstance(text, (list, tuple)) else [text, text]
    tokenizer.decode.side_effect = lambda *_args, **_kwargs: texts[model.generate.call_count - 1]
    torch.tensor.side_effect = lambda rows, **_kwargs: Tensor(rows)
    torch.inference_mode.side_effect = contextlib.nullcontext
    transformers.StoppingCriteria = object
    transformers.StoppingCriteriaList.side_effect = lambda items: items
    transformers.AutoTokenizer.from_pretrained.return_value = tokenizer

    def generate(**kwargs):
        actual_prompt = kwargs["input_ids"].rows[0]
        for criterion in kwargs["stopping_criteria"]:
            criterion(Tensor([actual_prompt + generated]), None)
        return Tensor([actual_prompt + generated])

    model.generate.side_effect = generate
    return model, tokenizer, torch, transformers


def adapter_config():
    return {"base_model_name_or_path": WORKER.MODEL_ID, "revision": WORKER.MODEL_REVISION,
            "peft_type": "LORA", "task_type": "CAUSAL_LM", "r": 4, "lora_alpha": 8,
            "lora_dropout": 0.0, "bias": "none", "inference_mode": True,
            "target_modules": ["q_proj", "v_proj"], **WORKER.ADAPTER_DEFAULTS}


def derived_dataset(text="Generated café."):
    # Structural provenance fixture; no signed model-execution attestation is claimed.
    item = dict(text=text, provider_key="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                job_id="1" * 32, report_sha256="2" * 64, package_manifest_id="3" * 64,
                model_fingerprint="4" * 64, output_index=0, parent_index=0, source_start=0, source_end=20,
                piece_start=0, piece_end=len((text + "\n").encode()))
    return dict(version=3, visibility="public", license="CC0-1.0", source_manifest_hex="ab" * 64,
                level=1, claim_scope=WORKER.DERIVED_CLAIM_SCOPE,
                inference=[dict(question="What is the combined answer?", context=text + "\n", inputs=[item])])


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
    def test_task_planning_admission_is_explicit_public_goal_only_and_has_no_adapter(self):
        source = task_plan_input()
        self.assertEqual(WORKER.validate_request(dict(request(), mode="plan_tasks"))["mode"], "plan_tasks")
        with self.assertRaisesRegex(WORKER.JobError, "TASK_PLAN_ADAPTER_UNSUPPORTED"):
            WORKER.validate_request(dict(request(), mode="plan_tasks", adapter_root="/adapter"))
        for license_value in WORKER.PUBLIC_LICENSES:
            value = dict(source, license=license_value)
            self.assertEqual(WORKER.validate_dataset(value, "plan_tasks"), value)
        for changes in ({"version": True}, {"version": 2}, {"visibility": "private"}, {"license": "unknown"},
                        {"question": " "}, {"question": "a\0b"}, {"question": "\ud800"}, {"question": "é" * 257},
                        {"source_sha256": "0" * 64}, {"source_sha256": "A" * 64}, {"source_sha256": "a" * 63},
                        {"source_bytes": True}, {"source_bytes": 0}, {"source_bytes": 1048577}, {"document": "not admitted"},
                        {"tools": []}, {"train": []}):
            with self.subTest(changes=list(changes)), self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(dict(source, **changes), "plan_tasks")
        messages = WORKER.task_plan_messages(source)
        self.assertIn(source["question"], messages[1]["content"])
        self.assertNotIn(source["source_sha256"], json.dumps(messages))
        self.assertIn("have not seen", messages[0]["content"])

    def test_task_questions_require_whole_strict_json_and_preserve_original_strings(self):
        valid = dict(version=1, questions=[" Which requirements? ", "Which risks?"])
        self.assertEqual(WORKER.validate_task_questions(WORKER.parse_json(json.dumps(valid))), valid)
        # Same trim-only distinctness as the Rust consumer, not an extra Unicode casefold policy.
        WORKER.validate_task_questions(dict(version=1, questions=["Question?", "question?"]))
        for changes in ({"version": True}, {"version": 1.0}, {"version": 2}, {"tools": []},
                        {"questions": ["Only one?"]}, {"questions": [str(i) for i in range(5)]},
                        {"questions": ["Repeated?", " Repeated? "]}, {"questions": [" ", "Other?"]},
                        {"questions": ["é" * 257, "Other?"]}, {"questions": ["\ud800", "Other?"]},
                        {"questions": ["a\0b", "Other?"]}, {"questions": [1, "Other?"]}):
            with self.subTest(changes=list(changes)), self.assertRaises(WORKER.JobError):
                WORKER.validate_task_questions(dict(valid, **changes))
        for text in ('```json\n{"version":1,"questions":["A?","B?"]}\n```',
                     '{"version":1,"questions":["A?","B?"]} extra',
                     '{"version":1,"version":1,"questions":["A?","B?"]}',
                     '{"version":1,"questions":["A?","B?"],"questions":["C?","D?"]}',
                     '{"version":1,"questions":["A?","B?"]', 'null',
                     '{"version":NaN,"questions":["A?","B?"]}'):
            with self.subTest(text=text), self.assertRaises(WORKER.JobError):
                WORKER.validate_task_questions(WORKER.parse_json(text))

    def test_task_input_identity_binds_goal_hash_source_hash_size_and_exact_public_bytes(self):
        # Inert file/hash doubles exercise prepare_files' identity branch only.
        # No model contents are provisioned or claimed to match these placeholder files.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, output, source = root/"model", root/"output", root/"input.json"
            model.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            for name in WORKER.MODEL_FILES:
                (model/name).touch(mode=0o600)
            config = dict(architectures=["LlamaForCausalLM"], model_type="llama", hidden_size=576,
                num_hidden_layers=30, num_attention_heads=9, num_key_value_heads=3, intermediate_size=1536,
                vocab_size=49152, max_position_embeddings=8192, tie_word_embeddings=True)
            (model/"config.json").write_text(json.dumps(config))
            dataset = task_plan_input()
            raw = json.dumps(dataset, separators=(",", ":")).encode()
            source.write_bytes(raw)
            value = WORKER.validate_request(dict(request(), mode="plan_tasks", model_root=str(model),
                dataset_path=str(source), output_root=str(output)))

            def file_hash(path, **_kwargs):
                return dict(bytes=WORKER.MODEL_FILES[path.name], sha256=WORKER.MODEL_HASHES[path.name])

            with mock.patch.object(WORKER, "file_hash", side_effect=file_hash):
                prepared = WORKER.prepare_files(value)
                self.assertEqual(prepared[2], dataset)
                self.assertEqual(prepared[3], dict(version=1, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                    visibility="public", license=dataset["license"],
                    question_sha256=hashlib.sha256(dataset["question"].encode()).hexdigest(),
                    source_sha256=dataset["source_sha256"], source_bytes=dataset["source_bytes"]))
                source.write_bytes(b" " * WORKER.MAX_TASK_PLAN_BYTES + raw)
                with self.assertRaisesRegex(WORKER.JobError, "ARTIFACT_TOO_LARGE"):
                    WORKER.prepare_files(value)

    def test_task_planner_has_two_real_greedy_generations_with_one_shared_owner(self):
        expected = dict(version=1, questions=["Which requirements?", "Which risks?"])
        model, tokenizer, torch, transformers = task_planner_doubles(expected["questions"])
        tokenizer.apply_chat_template.side_effect = [[11, 12, 13], [31, 32, 33, 34]]
        session = mock.Mock()
        result, prompts, generated, stats = WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), session)
        self.assertEqual((result, prompts, generated), (expected, 4, 6))
        self.assertEqual(stats, [dict(prompt_tokens=count, generated_tokens=3, stop_reason="eos") for count in (3, 4)])
        self.assertEqual(model.generate.call_count, 2)
        for call in model.generate.call_args_list:
            arguments = call.kwargs
            self.assertEqual((arguments["max_new_tokens"], arguments["do_sample"], arguments["num_beams"],
                              arguments["num_return_sequences"]), (192, False, 1, 1))
        self.assertEqual(tokenizer.decode.call_args_list,
                         [mock.call([21, 22], skip_special_tokens=False, clean_up_tokenization_spaces=False)] * 2)
        self.assertEqual(session.check.call_count, 8)
        self.assertEqual((WORKER.MAX_CONTEXT, WORKER.MAX_NEW_TOKENS), (256, 64))
        self.assertEqual((WORKER.TASK_PLAN_PROMPT_TOKENS, WORKER.TASK_PLAN_CONTEXT_TOKENS), (512, 896))
        self.assertEqual(WORKER.TASK_PLAN_NEW_TOKENS, 384)
        self.assertEqual(tokenizer.apply_chat_template.call_args_list,
                         [mock.call(WORKER.task_plan_messages(task_plan_input(), previous),
                                    tokenize=True, add_generation_prompt=True, return_dict=False)
                          for previous in (None, expected["questions"][0])])

    def test_task_planner_stops_at_each_whole_question_without_changing_its_text(self):
        expected = dict(version=1, questions=[" Which requirements? ", "Which risks?"])
        model, tokenizer, torch, transformers = task_planner_doubles(expected["questions"], [21, 22])
        tokenizer.decode.side_effect = [" Which requirements", expected["questions"][0], expected["questions"][0],
                                       "Which risks", expected["questions"][1], expected["questions"][1]]
        session = mock.Mock()

        def generate(**kwargs):
            criterion, = kwargs["stopping_criteria"]
            self.assertFalse(criterion(torch.tensor([[11, 12, 13, 21]]), None))
            completed = torch.tensor([[11, 12, 13, 21, 22]])
            self.assertTrue(criterion(completed, None))
            return completed

        model.generate.side_effect = generate
        self.assertEqual(WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), session),
                         (expected, 3, 4, [dict(prompt_tokens=3, generated_tokens=2, stop_reason="question_boundary")] * 2))
        self.assertEqual(model.generate.call_count, 2)
        self.assertEqual(session.check.call_count, 10)
        self.assertEqual(tokenizer.decode.call_args_list,
                         [mock.call(tokens, skip_special_tokens=False, clean_up_tokenization_spaces=False)
                          for tokens in ([21], [21, 22], [21, 22])] * 2)

    def test_task_planner_online_stop_does_not_extract_questions_from_longer_output(self):
        for text in ("Incomplete question", "A question? trailing", "```\nA question?\n```", "", " ",
                     "a\0?", "\ud800?", "é" * 256 + "?"):
            model, tokenizer, torch, transformers = task_planner_doubles(text, [21, 22])

            def generate(**kwargs):
                criterion, = kwargs["stopping_criteria"]
                incomplete = torch.tensor([[11, 12, 13, 21, 22]])
                self.assertFalse(criterion(incomplete, None))
                return incomplete

            model.generate.side_effect = generate
            with self.subTest(text=text), self.assertRaisesRegex(WORKER.JobError, "TASK_PLAN_QUESTION_ONE_INCOMPLETE_GENERATION"):
                WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), mock.Mock())
            model.generate.assert_called_once()

    def test_task_planner_complete_marker_is_bound_to_exact_returned_tokens(self):
        valid = "What does the source require?"
        for returned in ([21, 23], [21, 22, 23], [21], [21, 22, 2]):
            model, tokenizer, torch, transformers = task_planner_doubles(valid)

            def generate(**kwargs):
                criterion, = kwargs["stopping_criteria"]
                self.assertTrue(criterion(torch.tensor([[11, 12, 13, 21, 22]]), None))
                return torch.tensor([[11, 12, 13] + returned])

            model.generate.side_effect = generate
            with self.subTest(returned=returned), self.assertRaisesRegex(WORKER.JobError, "TASK_PLAN_QUESTION_ONE_COMPLETION_TOKENS_CHANGED"):
                WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), mock.Mock())
        # Even valid final text without EOS needs its own in-generation marker.
        model, tokenizer, torch, transformers = task_planner_doubles(valid)
        model.generate.side_effect = None
        model.generate.return_value = torch.tensor([[11, 12, 13, 21, 22]])
        with self.assertRaisesRegex(WORKER.JobError, "TASK_PLAN_QUESTION_ONE_INCOMPLETE_GENERATION"):
            WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), mock.Mock())

    def test_task_planning_never_truncates_repairs_retries_or_falls_back(self):
        valid = "What does the source require?"
        for prompt, generated, text in (([1]*513, [21, 2], valid), ([1], [21]*191+[2], valid),
                                       ([1], [21]*192, valid), ([1], [2, 21, 2], valid),
                                       ([1], [21, 2], " "), ([1], [21, 2], "é"*257)):
            model, tokenizer, torch, transformers = task_planner_doubles(text, generated, prompt)
            with self.subTest(prompt=len(prompt), generated=len(generated)), self.assertRaises(WORKER.JobError):
                WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), mock.Mock())
            self.assertLessEqual(model.generate.call_count, 1)
        model, tokenizer, torch, transformers = task_planner_doubles(valid)
        session = mock.Mock()
        session.check.side_effect = [None, None, WORKER.JobError("JOB_CANCELLED")]
        with self.assertRaisesRegex(WORKER.JobError, "JOB_CANCELLED"):
            WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), session)
        model.generate.assert_called_once()  # Cancellation propagated from the generation-thread criterion.
        tokenizer.decode.assert_not_called()

    def test_task_planner_rejects_duplicate_model_questions_and_does_not_restart_budget(self):
        model, tokenizer, torch, transformers = task_planner_doubles(["Same question?", " Same question? "])
        with self.assertRaisesRegex(WORKER.JobError, "DUPLICATE_OR_EMPTY_TASK_PLAN_QUESTION"):
            WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), mock.Mock())
        self.assertEqual(model.generate.call_count, 2)
        for change, error in (("prompt", "TASK_PLAN_QUESTION_TWO_PROMPT_TOKEN_LIMIT_EXCEEDED"),
                              ("tokens", "TASK_PLAN_QUESTION_TWO_GENERATION_LIMIT_REACHED"),
                              ("owner", "JOB_DEADLINE_EXCEEDED")):
            model, tokenizer, torch, transformers = task_planner_doubles(["First question?", "Second question?"])
            session = mock.Mock()
            if change == "prompt":
                tokenizer.apply_chat_template.side_effect = [[11, 12, 13], [11] * 513]
            elif change == "tokens":
                original = model.generate.side_effect

                def generate(**kwargs):
                    if model.generate.call_count == 1:
                        return original(**kwargs)
                    return torch.tensor([kwargs["input_ids"].rows[0] + [21] * 191 + [2]])

                model.generate.side_effect = generate
            else:
                session.check.side_effect = [None] * 4 + [WORKER.JobError("JOB_DEADLINE_EXCEEDED")]
            with self.subTest(change=change), self.assertRaisesRegex(WORKER.JobError, error):
                WORKER.plan_tasks(model, tokenizer, torch, transformers, task_plan_input(), session)
            self.assertEqual(model.generate.call_count, 2 if change == "tokens" else 1)

    def test_task_question_failure_codes_match_supervisor_fixed_alphabet(self):
        # The Rust supervisor deliberately accepts only [A-Z_]{1,64}; digits
        # would hide either stage behind UNKNOWN_FIXED_FAILURE.
        for previous, stage in ((None, "ONE"), ("Earlier model question?", "TWO")):
            model, tokenizer, torch, transformers = task_planner_doubles(" ")
            with self.subTest(stage=stage), self.assertRaises(WORKER.JobError) as failure:
                WORKER.plan_task_question(model, tokenizer, torch, transformers,
                                          task_plan_input(), mock.Mock(), previous)
            code = str(failure.exception)
            self.assertEqual(code, "TASK_PLAN_QUESTION_" + stage + "_EMPTY_TEXT")
            self.assertRegex(code, r"\A[A-Z_]{1,64}\Z")

    def test_task_plan_branch_loads_weights_and_retains_only_valid_hashed_questions(self):
        expected = dict(version=1, questions=["Which requirements?", "Which risks?"])
        source = task_plan_input()
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                value = WORKER.validate_request(dict(request(), mode="plan_tasks", output_root=str(root)))
                model, tokenizer, torch, transformers = task_planner_doubles(expected["questions"] if valid else " ")
                digest = dict(sha256="b"*64, parameters=123)
                real_hash = WORKER.file_hash

                def file_hash(path, *args, **kwargs):
                    if path.name == "model.safetensors":
                        return dict(sha256=WORKER.MODEL_WEIGHT_SHA, bytes=WORKER.MODEL_WEIGHT_BYTES)
                    return real_hash(path, *args, **kwargs)

                with mock.patch.object(WORKER, "prepare_files", return_value=(root/"model", root, source, {"sha256":"a"*64}, {})), \
                     mock.patch.object(WORKER, "configure_offline"), \
                     mock.patch.object(WORKER, "load_backend", return_value=(torch, transformers, mock.Mock(), WORKER.BACKENDS)), \
                     mock.patch.object(WORKER, "load_model", return_value=model) as loader, \
                     mock.patch.object(WORKER, "parameter_hash", return_value=digest) as parameter_hash, \
                     mock.patch.object(WORKER, "file_hash", side_effect=file_hash), \
                     mock.patch.object(WORKER, "encode_dataset", side_effect=AssertionError("planner used ordinary inference rows")), \
                     mock.patch.object(WORKER, "new_lora", side_effect=AssertionError("planner created adapter")), \
                     mock.patch.object(WORKER, "WIRE_OUTPUT", io.StringIO()):
                    if not valid:
                        with self.assertRaises(WORKER.JobError):
                            WORKER.execute_job(value, WORKER.Session(value))
                        self.assertEqual(list(root.iterdir()), [])
                        continue
                    result = WORKER.execute_job(value, WORKER.Session(value))
                    loader.assert_called_once()
                    self.assertEqual(parameter_hash.call_count, 2)
                self.assertEqual(json.loads((root/"task-questions.json").read_text()), expected)
                self.assertEqual(result["artifacts"], [dict(relative_path="task-questions.json", **real_hash(root/"task-questions.json"))])
                self.assertEqual({p.name for p in root.iterdir()}, {"task-questions.json", "report.json"})
                self.assertEqual((root/"task-questions.json").stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads((root/"report.json").read_text()), result)
                self.assertEqual((result["mode"],result["updates_completed"]), ("plan_tasks",0))
                self.assertTrue(result["goal_only_planning"] and result["model_weights_loaded"] and result["base_weights_unchanged"])
                self.assertFalse(result["generation_limit_reached"] or result["model_answer_correctness_proven"])
                self.assertEqual(result["planner_stop_reason"], "two_questions")
                self.assertEqual(result["planner_strategy"], "model_questions_scaffold_v1")
                self.assertEqual(result["planner_structure_generated_by"], "local_schema")
                self.assertEqual(result["planner_question_stats"],
                                 [dict(prompt_tokens=3, generated_tokens=3, stop_reason="eos")] * 2)
                self.assertEqual(result["base_before"], result["base_after"])
                for field in ("outputs","baseline_evaluation","input_adapter","adapter_after"):
                    self.assertNotIn(field,result)

    def test_derived_v3_is_inference_only_and_preserves_exact_generated_pieces(self):
        value = derived_dataset("é")
        before = json.dumps(value).encode()
        self.assertEqual(WORKER.validate_dataset(value, "infer"), value)
        self.assertEqual(json.dumps(value).encode(), before)
        # The separator belongs to the virtual text BEFORE slicing. A newline-only
        # second piece is valid and never receives an invented extra separator.
        row = value["inference"][0]
        row["inputs"] = [dict(row["inputs"][0], piece_end=2), dict(row["inputs"][0], piece_start=2)]
        self.assertEqual(WORKER.validate_dataset(value, "infer"), value)
        for license_value in WORKER.PUBLIC_LICENSES:
            WORKER.validate_dataset(dict(value, license=license_value), "infer")
        with self.assertRaisesRegex(WORKER.JobError, "DERIVED_PROFILE_INFERENCE_ONLY"):
            WORKER.validate_dataset(value, "train")
        for changes in ({"visibility": "private"}, {"level": 0}, {"level": 17}, {"level": True},
                        {"claim_scope": "source_quotation"}, {"heldout": []}, {"source_revision": "a" * 40},
                        {"inference": []}, {"source_manifest_hex": "abc"}, {"source_manifest_hex": "AB"},
                        {"license": "unknown"}, {"source_manifest_hex": "ab" * 65537}):
            with self.subTest(changes=list(changes)), self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(dict(value, **changes), "infer")
        for changes in ({"piece_start": 1}, {"piece_end": 4}, {"piece_end": 0}, {"piece_end": True},
                        {"source_start": 20}, {"source_end": 1048577}, {"parent_index": 2 ** 32},
                        {"output_index": 65536}, {"provider_key": "0" * 64}, {"job_id": "A" * 32},
                        {"report_sha256": "0" * 64}, {"text": ""}, {"text": "x\0y"}, {"text": "é" * 513},
                        {"extra": 1}):
            bad = derived_dataset("é")
            bad["inference"][0]["inputs"][0].update(changes)
            with self.subTest(changes=list(changes)), self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(bad, "infer")
        for changes in ({"context": "é"}, {"context": "é\n\n"}, {"question": " "},
                        {"inputs": []}, {"inputs": [derived_dataset()["inference"][0]["inputs"][0]] * 65}):
            bad = derived_dataset("é")
            bad["inference"][0].update(changes)
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(bad, "infer")

    def test_synthesis_planning_and_encoding_use_the_same_fixed_prompt_and_bounds(self):
        class Tokenizer:
            def apply_chat_template(self, messages, *, tokenize, add_generation_prompt, return_dict):
                assert tokenize and add_generation_prompt and not return_dict
                assert messages[0] == WORKER.prompt_messages(dict(question="", context=""), synthesis=True)[0]
                return [1] * (8 + sum(len(row["content"].encode()) for row in messages) // 4)

        # Tokenizer/backend doubles prove exact branch/template/ranges, not real counts.
        source = derived_dataset("Public generated café. " * 35)
        row = source["inference"][0]
        planning = dict(version=1, visibility="public", license=source["license"], synthesis=True,
                        document=row["context"], question=row["question"])
        WORKER.validate_dataset(planning, "plan_document")
        tokenizer, session, backend = Tokenizer(), mock.Mock(), mock.Mock()
        backend.tensor.side_effect = lambda value, **_kwargs: value
        plan = WORKER.plan_document(tokenizer, planning, session)
        self.assertTrue(plan["synthesis"])
        self.assertGreater(len(plan["parts"]), 1)
        original, reconstructed = row["context"].encode(), bytearray()
        for part in plan["parts"]:
            single = copy.deepcopy(source)
            piece = original[part["start"]:part["end"]]
            single["inference"][0]["context"] = piece.decode()
            single["inference"][0]["inputs"][0].update(piece_start=part["start"], piece_end=part["end"])
            before = json.dumps(single).encode()
            samples = WORKER.encode_dataset(tokenizer, backend, WORKER.validate_dataset(single, "infer"))
            self.assertEqual(samples["train"], [])
            self.assertEqual(samples["heldout"], [])
            self.assertEqual(len(samples["inference"][0][0]), part["prompt_tokens"])
            self.assertLessEqual(part["prompt_tokens"], 192)
            self.assertEqual(before, json.dumps(single).encode())
            reconstructed.extend(piece)
        self.assertEqual(bytes(reconstructed), original)
        self.assertNotEqual(WORKER.prompt_messages(row), WORKER.prompt_messages(row, synthesis=True))
        for invalid in (1, "true", None, [], {}):
            with self.assertRaisesRegex(WORKER.JobError, "INVALID_DOCUMENT_SYNTHESIS_PROFILE"):
                WORKER.validate_dataset(dict(planning, synthesis=invalid), "plan_document")

    def test_document_and_v2_profiles_are_public_bounded_and_inference_only(self):
        document = dict(version=1, visibility="public", license="CC-BY-4.0", document="A public café.\n", question="What is stated?")
        self.assertEqual(WORKER.validate_dataset(document, "plan_document"), document)
        self.assertEqual(WORKER.validate_request(dict(request(), mode="plan_document"))["mode"], "plan_document")
        with self.assertRaisesRegex(WORKER.JobError, "DOCUMENT_PLAN_ADAPTER_UNSUPPORTED"):
            WORKER.validate_request(dict(request(), mode="plan_document", adapter_root="/adapter"))
        for changes in ({"document": ""}, {"document": "a\0b"}, {"document": "\ud800"}, {"document": "x" * (1048576 + 1)},
                        {"question": " "}, {"question": "é" * 257}, {"visibility": "private"}, {"license": "unknown"}, {"extra": True}):
            with self.subTest(changes=list(changes)), self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(dict(document, **changes), "plan_document")
        v2 = dict(version=2, visibility="public", license="CC0-1.0", source_manifest_hex="ab" * 64,
                  inference=[dict(question="What?", context="é", start=0, end=2),
                             dict(question="What?", context="文", start=3, end=6)])
        self.assertEqual(WORKER.validate_dataset(v2, "infer"), v2)
        for license_value in WORKER.PUBLIC_LICENSES:
            WORKER.validate_dataset(dict(v2, license=license_value), "infer")
        with self.assertRaisesRegex(WORKER.JobError, "DOCUMENT_PROFILE_INFERENCE_ONLY"):
            WORKER.validate_dataset(v2, "train")
        for field, value in (("start", True), ("start", 1), ("end", 5), ("end", 1048577), ("context", "")):
            wrong = copy.deepcopy(v2)
            wrong["inference"][1][field] = value
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(wrong, "infer")
        for changes in ({"source_manifest_hex": "abc"}, {"source_manifest_hex": "AB"}, {"source_manifest_hex": "ab" * 65537},
                        {"train": []}, {"source_revision": "a" * 40}, {"inference": []}):
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(dict(v2, **changes), "infer")

    def test_document_plan_preserves_exact_unicode_bytes_and_uses_full_inference_prompt(self):
        class Tokenizer:
            def apply_chat_template(self, messages, *, tokenize, add_generation_prompt, return_dict):
                assert tokenize and add_generation_prompt and not return_dict
                assert messages[0] == WORKER.prompt_messages(dict(context="", question=""))[0]
                return [1] * (8 + sum(len(row["content"].encode()) for row in messages) // 4)

        # This tokenizer double proves control flow/ranges only, never the pinned model's token counts.
        tokenizer, session = Tokenizer(), mock.Mock()
        source = dict(version=1, visibility="public", license="GPL-3.0-only", document=("Public café 文🙂.\n" * 200), question="What is stated?")
        plan = WORKER.plan_document(tokenizer, source, session)
        self.assertNotIn("synthesis", plan)
        explicit_legacy = WORKER.plan_document(tokenizer, dict(source, synthesis=False), session)
        self.assertEqual(explicit_legacy, plan)
        encoded = source["document"].encode()
        self.assertGreater(len(plan["parts"]), 1)
        self.assertEqual(plan["source_sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(plan["source_bytes"], len(encoded))
        self.assertEqual(plan["question_sha256"], hashlib.sha256(source["question"].encode()).hexdigest())
        self.assertEqual((plan["model_revision"], plan["tokenizer_sha256"], plan["prompt_limit"]),
                         (WORKER.MODEL_REVISION, WORKER.MODEL_HASHES["tokenizer.json"], 192))
        offset, assembled = 0, bytearray()
        for part in plan["parts"]:
            self.assertEqual(part["start"], offset)
            raw = encoded[part["start"]:part["end"]]
            self.assertLessEqual(len(raw), 4096)
            row = dict(question=source["question"], context=raw.decode("utf-8"))
            self.assertEqual(part["prompt_tokens"], len(WORKER.prompt_tokens(tokenizer, row)))
            self.assertLessEqual(part["prompt_tokens"], 192)
            assembled.extend(raw)
            offset = part["end"]
        self.assertEqual(bytes(assembled), encoded)
        with mock.patch.object(WORKER, "MAX_DOCUMENT_PARTS", 1), self.assertRaisesRegex(WORKER.JobError, "DOCUMENT_PART_LIMIT_EXCEEDED"):
            WORKER.plan_document(tokenizer, source, session)
        wrong = mock.Mock()
        wrong.apply_chat_template.return_value = [1] * 193
        with self.assertRaisesRegex(WORKER.JobError, "DOCUMENT_QUESTION_TOKEN_LIMIT_EXCEEDED"):
            WORKER.plan_document(wrong, source, session)
        wrong.apply_chat_template.side_effect = lambda messages, **_kwargs: [1] * (100 if messages[1]["content"].startswith("Documentation:\n\nQuestion:") else 193)
        with self.assertRaisesRegex(WORKER.JobError, "DOCUMENT_CHARACTER_DOES_NOT_FIT"):
            WORKER.plan_document(wrong, dict(source, document="é"), session)

    def test_v2_encoding_has_no_fabricated_training_or_heldout_rows(self):
        tokenizer, backend = mock.Mock(), mock.Mock()
        tokenizer.apply_chat_template.return_value = [1, 2, 3]
        backend.tensor.side_effect = lambda value, **_kwargs: value
        source = dict(version=2, visibility="public", license="CC0-1.0", source_manifest_hex="ab" * 64,
                      inference=[dict(question="What?", context="é", start=0, end=2)])
        before = json.dumps(source).encode()
        encoded = WORKER.encode_dataset(tokenizer, backend, WORKER.validate_dataset(source, "infer"))
        self.assertEqual(encoded, dict(train=[], heldout=[], inference=[[[1, 2, 3]]]))
        self.assertEqual(before, json.dumps(source).encode())
        tokenizer.apply_chat_template.assert_called_once_with(WORKER.prompt_messages(source["inference"][0]),
            tokenize=True, add_generation_prompt=True, return_dict=False)

    def test_plan_branch_writes_actual_bounded_artifact_without_calling_model_loader(self):
        # Controlled backend/tokenizer doubles test the branch and durable files, not real ML.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            value = WORKER.validate_request(dict(request(), mode="plan_document", output_root=str(root)))
            source = dict(version=1, visibility="public", license="CC0-1.0", document="Public text.\n", question="What?")
            tokenizer, transformers = mock.Mock(), mock.Mock()
            tokenizer.pad_token_id = tokenizer.eos_token_id = 2
            tokenizer.apply_chat_template.return_value = [1, 2, 3]
            transformers.AutoTokenizer.from_pretrained.return_value = tokenizer
            with mock.patch.object(WORKER, "prepare_files", return_value=(root / "model", root, source, {"sha256": "a" * 64}, {})), \
                 mock.patch.object(WORKER, "configure_offline"), \
                 mock.patch.object(WORKER, "load_backend", return_value=(mock.Mock(), transformers, mock.Mock(), WORKER.BACKENDS)), \
                 mock.patch.object(WORKER, "load_model", side_effect=AssertionError("planner loaded weights")), \
                 mock.patch.object(WORKER, "WIRE_OUTPUT", io.StringIO()):
                result = WORKER.execute_job(value, WORKER.Session(value))
            self.assertFalse(result["model_weights_loaded"])
            self.assertEqual((result["mode"], result["updates_completed"]), ("plan_document", 0))
            self.assertNotIn("outputs", result)
            self.assertNotIn("baseline_evaluation", result)
            self.assertEqual(result["artifacts"], [dict(relative_path="document-plan.json", **WORKER.file_hash(root / "document-plan.json"))])
            plan = json.loads((root / "document-plan.json").read_text())
            self.assertEqual(plan["parts"], [dict(start=0, end=13, prompt_tokens=3)])
            self.assertEqual(json.loads((root / "report.json").read_text()), result)
            self.assertEqual((root / "document-plan.json").stat().st_mode & 0o777, 0o600)

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
