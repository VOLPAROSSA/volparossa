#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit 1.7B admission/loading/report doubles; no model/backend execution."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_worker_protocol import WORKER, request, task_plan_input, task_planner_doubles
from test_grounded_synthesis import grounded, planning, ByteTokenizer
from test_principle_inference import dataset as principle_dataset
from test_provision import PROVISION


PROFILE = WORKER.REASONING_MODEL_PROFILE


class ReasoningProfileTests(unittest.TestCase):
    def test_explicit_profile_pins_original_weights_and_preserves_runtime(self):
        pins = PROVISION.load_pins(PROFILE)
        profile = WORKER.model_profile(PROFILE)
        self.assertEqual(pins["model_id"], profile["id"])
        self.assertEqual(pins["revision"], profile["revision"])
        self.assertEqual({x["path"]: x["bytes"] for x in pins["files"]}, profile["files"])
        self.assertEqual({x["path"]: x["sha256"] for x in pins["files"]}, profile["hashes"])
        baseline = PROVISION.load_pins()
        self.assertEqual(pins["wheels"], baseline["wheels"])
        self.assertEqual(pins["source_revisions"], baseline["source_revisions"])
        self.assertEqual(PROVISION.download_total(pins), 3676766484)
        self.assertEqual(sum(x["bytes"] for x in pins["files"]), 3424913067)
        self.assertEqual(PROVISION.download_total(PROVISION.load_pins(PROFILE, True)), 3677002264)
        self.assertIn("no LICENSE file", pins["license_provenance"])
        for item in pins["files"]:
            identity = PROVISION.PROFILES[PROVISION.DEFAULT_MODEL_PROFILE if item["path"] == "LICENSE" else PROFILE]
            self.assertEqual(item["url"], f"https://huggingface.co/{identity[0]}/resolve/{identity[1]}/{item['path']}")

    def test_preview_is_network_and_write_free_and_budget_is_not_implicitly_raised(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            with mock.patch.object(PROVISION.urllib.request, "build_opener", side_effect=AssertionError("network")), \
                 mock.patch.object(PROVISION.venv.EnvBuilder, "create", side_effect=AssertionError("install")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROVISION.main(["--model-profile", PROFILE, "--root", str(target)]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["model_profile"], PROFILE)
            self.assertEqual(report["download_bytes"], 3676766484)
            self.assertIsNone(report["budget_bytes"])
            self.assertFalse(target.exists())
            args = SimpleNamespace(budget_bytes=3 * 1024 ** 3)
            with mock.patch.object(PROVISION, "execution_root", return_value=(target, "kvm/qemu")):
                with self.assertRaisesRegex(PROVISION.ProvisionError, "budget cannot hold"):
                    PROVISION.execute(args, PROVISION.load_pins(PROFILE))
            self.assertFalse(target.exists())

    def test_new_profile_is_inference_only_with_existing_exact_budgets(self):
        for mode in ("infer", "private_infer", "plan_document", "plan_tasks"):
            self.assertEqual(WORKER.validate_request(dict(request(), mode=mode, model_profile=PROFILE))["model_profile"], PROFILE)
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(request(), mode=mode, model_profile=PROFILE, adapter_root="/adapter"))
        for mode in ("train", "aggregate_adapter"):
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(request(), mode=mode, model_profile=PROFILE, adapter_root="/adapter"))
        profile = WORKER.model_profile(PROFILE)
        self.assertEqual(tuple(profile[k] for k in ("prompt_tokens", "new_tokens", "wire_bytes", "max_rows")), (1024, 256, 4096, 1))
        self.assertEqual((WORKER.TASK_PLAN_PROMPT_TOKENS, WORKER.TASK_PLAN_NEW_TOKENS, WORKER.TASK_PLAN_CONTEXT_TOKENS), (512, 384, 896))

    def test_loading_is_explicit_cpu_bf16_without_autocast_or_fp32_retry(self):
        torch = SimpleNamespace(float32="torch.float32", bfloat16="torch.bfloat16", device=lambda x: x)
        for profile, dtype in ((WORKER.DEFAULT_MODEL_PROFILE, torch.float32),
                               (WORKER.LARGE_MODEL_PROFILE, torch.float32), (PROFILE, torch.bfloat16)):
            model, transformers = mock.Mock(), mock.Mock()
            parameter = mock.Mock(dtype=dtype, device=SimpleNamespace(type="cpu"))
            parameter.numel.return_value = 1
            model.parameters.return_value = [parameter]
            transformers.AutoModelForCausalLM.from_pretrained.return_value = model
            self.assertIs(WORKER.load_model(transformers, torch, Path("/model"), profile), model)
            transformers.AutoModelForCausalLM.from_pretrained.assert_called_once_with(
                "/model", local_files_only=True, trust_remote_code=False, use_safetensors=True,
                dtype=dtype, device_map=None, attn_implementation="eager")
            model.to.assert_called_once_with("cpu")
            self.assertFalse(model.config.use_cache)
            self.assertEqual(model.config._name_or_path, WORKER.model_profile(profile)["id"])
        transformers.AutoModelForCausalLM.from_pretrained.side_effect = RuntimeError("unsupported CPU kernel")
        transformers.AutoModelForCausalLM.from_pretrained.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "unsupported CPU kernel"):
            WORKER.load_model(transformers, torch, Path("/model"), PROFILE)
        self.assertEqual(transformers.AutoModelForCausalLM.from_pretrained.call_count, 1)

    def test_dtype_report_checks_all_actual_parameters_not_config_and_preserves_old_reports(self):
        torch = SimpleNamespace(bfloat16="torch.bfloat16")
        good = mock.Mock(dtype=torch.bfloat16, device=SimpleNamespace(type="cpu"))
        good.numel.return_value = 1
        model = mock.Mock()
        for parameters, code in (([], "EMPTY_PARAMETER_SET"),
                ([good, mock.Mock(dtype="torch.float32", device=SimpleNamespace(type="cpu"))], "MODEL_PARAMETER_DTYPE_MISMATCH"),
                ([good, mock.Mock(dtype=torch.bfloat16, device=SimpleNamespace(type="cuda"))], "CPU_BACKEND_REQUIRED")):
            model.parameters.return_value = parameters
            with self.subTest(code=code), self.assertRaisesRegex(WORKER.JobError, code):
                WORKER.model_dtype_report(PROFILE, model, torch)
        model.parameters.return_value = [good]
        self.assertEqual(WORKER.model_dtype_report(PROFILE, model, torch), {"model_parameter_dtype": "bfloat16"})
        self.assertEqual(WORKER.model_dtype_report(PROFILE), {"model_parameter_dtype": None})
        for legacy in (WORKER.DEFAULT_MODEL_PROFILE, WORKER.LARGE_MODEL_PROFILE):
            self.assertEqual(WORKER.model_dtype_report(legacy, model, torch), {})

    def test_bf16_hash_reinterprets_original_bytes_without_float_copy_or_numpy_bf16(self):
        class Tensor:
            device = SimpleNamespace(type="cpu")
            shape = (2,)
            dtype = "torch.bfloat16"

            def __init__(self):
                self.raw = bytearray(b"\x00\x00\x80\x3f")
                self.view_dtype = None

            def numel(self): return 2
            def detach(self): return self
            def contiguous(self): return self
            def view(self, dtype):
                self.view_dtype = dtype
                return SimpleNamespace(numpy=lambda: self.raw)
            def numpy(self): raise AssertionError("BF16 numpy is unsupported")

        tensor, session = Tensor(), mock.Mock()
        torch = SimpleNamespace(uint8="torch.uint8")
        model = SimpleNamespace(named_parameters=lambda: [("weight", tensor)])
        descriptor = json.dumps(["weight", tensor.dtype, [2]], separators=(",", ":")).encode()
        expected = hashlib.sha256(len(descriptor).to_bytes(4, "big") + descriptor + tensor.raw).hexdigest()
        self.assertEqual(WORKER.parameter_hash(model, False, session, torch), dict(sha256=expected, parameters=2))
        self.assertEqual(tensor.view_dtype, "torch.uint8")
        tensor.raw[0] = 1
        self.assertNotEqual(WORKER.parameter_hash(model, False, session, torch)["sha256"], expected)

    def test_grounded_and_principle_inputs_keep_all_existing_bounds_and_profile_binding(self):
        value = dict(grounded(), model_profile=PROFILE)
        self.assertIs(WORKER.validate_dataset(value, "infer", PROFILE), value)
        self.assertEqual(WORKER.validate_dataset(planning(value), "plan_document", PROFILE), planning(value))
        for wrong in (WORKER.DEFAULT_MODEL_PROFILE, WORKER.LARGE_MODEL_PROFILE):
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(value, "infer", wrong)
        tokenizer, backend = ByteTokenizer(), mock.Mock()
        backend.tensor.side_effect = lambda rows, **_kwargs: rows
        plan = WORKER.plan_document(tokenizer, planning(value), mock.Mock(), PROFILE)
        samples = WORKER.encode_dataset(tokenizer, backend, value, PROFILE)
        self.assertEqual(plan["parts"][0]["prompt_tokens"], len(samples["inference"][0][0]))
        self.assertEqual(plan["original_source_sha256"], hashlib.sha256(value["original_source"].encode()).hexdigest())
        for review in (False, True):
            source = principle_dataset(review)
            self.assertIs(WORKER.validate_dataset(source, "infer", PROFILE), source)
        with self.assertRaises(WORKER.JobError):
            WORKER.validate_dataset(dict(value, original_source="x" * 4097), "infer", PROFILE)

    def test_existing_execution_modes_report_actual_new_dtype_and_never_train(self):
        profile = WORKER.model_profile(PROFILE)
        files = {name: dict(bytes=size, sha256=profile["hashes"][name]) for name, size in profile["files"].items()}
        for mode in ("infer", "private_infer", "plan_document", "plan_tasks"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if mode == "plan_tasks":
                    source = dict(task_plan_input(), model_profile=PROFILE)
                elif mode == "plan_document":
                    source = dict(version=1, visibility="public", license="CC0-1.0", document="Public source.", question="What?", model_profile=PROFILE)
                elif mode == "private_infer":
                    source = dict(version=1, visibility="private_local", context="My private note.", question="What?")
                else:
                    source = dict(version=2, inference=[dict(question="What?", context="Public source.")])
                model, tokenizer, torch, transformers = task_planner_doubles(
                    ["Which source requirement?", "Which source limitation?"] if mode == "plan_tasks" else "A bounded answer.")
                value = WORKER.validate_request(dict(request(), mode=mode, model_profile=PROFILE, output_root=str(root)))
                real_hash = WORKER.file_hash
                def file_hash(path, *args, **kwargs):
                    return files[path.name] if path.name == "model.safetensors" else real_hash(path, *args, **kwargs)
                with mock.patch.object(WORKER, "prepare_files", return_value=(root / "model", root, source, {"sha256": "a" * 64}, files)), \
                     mock.patch.object(WORKER, "configure_offline"), \
                     mock.patch.object(WORKER, "load_backend", return_value=(torch, transformers, mock.Mock(), WORKER.BACKENDS)), \
                     mock.patch.object(WORKER, "load_model", return_value=model) as loader, \
                     mock.patch.object(WORKER, "parameter_hash", return_value=dict(sha256="b" * 64, parameters=1711378432)), \
                     mock.patch.object(WORKER, "file_hash", side_effect=file_hash), \
                     mock.patch.object(WORKER, "new_lora", side_effect=AssertionError("new profile trained")), \
                     mock.patch.object(WORKER, "WIRE_OUTPUT", io.StringIO()):
                    result = WORKER.execute_job(value, WORKER.Session(value))
                self.assertEqual(result["model_parameter_dtype"], None if mode == "plan_document" else "bfloat16")
                self.assertEqual(json.loads((root / "report.json").read_text())["model_parameter_dtype"], result["model_parameter_dtype"])
                self.assertEqual(result["updates_completed"], 0)
                if mode in ("infer", "plan_document"):
                    self.assertEqual(result["answer_prompt_revision"], WORKER.ANSWER_PROMPT_REVISION)
                else:
                    self.assertNotIn("answer_prompt_revision", result)
                self.assertEqual(result["model"]["files"], files)
                self.assertLessEqual((root / "report.json").stat().st_size, WORKER.MAX_LINE)
                if mode == "plan_document":
                    loader.assert_not_called()
                else:
                    loader.assert_called_once_with(transformers, torch, root / "model", PROFILE)


if __name__ == "__main__":
    unittest.main()
