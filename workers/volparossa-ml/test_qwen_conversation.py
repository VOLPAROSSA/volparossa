# SPDX-License-Identifier: GPL-3.0-only
"""Offline bridge tests, explicitly not model inference or coding-quality proof."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_conversation import CONVERSATION, WORKER, conversation, call
from test_worker_protocol import request, task_planner_doubles

SPEC = importlib.util.spec_from_file_location("volparossa_qwen_conversation", Path(__file__).with_name("qwen_conversation.py"))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
sys.modules[SPEC.name] = NATIVE
PROFILE = WORKER.QWEN_MODEL_PROFILE
ID = "abcd" * 8


def output(raw, reason="eos", truncated=False):
    return {"text": raw, "text_truncated": truncated, "generation": {"stop_reason": reason}}


class QwenConversationTests(unittest.TestCase):
    def test_worker_dispatch_reaches_native_template_and_real_generation_boundary(self):
        # Inert tensor/tokenizer/model doubles exercise dispatch, not inference quality.
        data = conversation()
        raw = json.dumps(data).encode()
        identity = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "visibility": "private_local"}
        profile = WORKER.model_profile(PROFILE)
        files = {name: {"bytes": size, "sha256": profile["hashes"][name]} for name, size in profile["files"].items()}
        native = '<tool_call>{"name":"vp_0","arguments":{"name":"demo.rs"}}</tool_call>'
        model, tokenizer, torch, transformers = task_planner_doubles(native, generated=[21, 151645])
        tokenizer.pad_token_id, tokenizer.eos_token_id = 151643, 151645
        model.config._attn_implementation = "sdpa"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = WORKER.validate_request(dict(request(), mode="private_conversation", steps=1,
                owner_control=True, model_profile=PROFILE, output_root=str(root)))
            with mock.patch.object(WORKER, "prepare_files", return_value=(root/"model", root, data, identity, files)), \
                 mock.patch.object(WORKER, "configure_offline"), \
                 mock.patch.object(WORKER, "load_backend", return_value=(torch, transformers, mock.Mock(), WORKER.BACKENDS)), \
                 mock.patch.object(WORKER, "load_model", return_value=model), \
                 mock.patch.object(WORKER, "file_hash", return_value=files["model.safetensors"]), \
                 mock.patch.object(WORKER, "encode_private", side_effect=AssertionError("Q&A branch")), \
                 mock.patch.object(WORKER, "encode_dataset", side_effect=AssertionError("public branch")), \
                 mock.patch.object(WORKER, "evaluate", side_effect=AssertionError("training")):
                session = mock.Mock(frames=None)
                session.elapsed.return_value = 0
                result = WORKER.execute_job(job, session)
            self.assertEqual(result["conversation"], dict(call(), call_id="vp-" + job["id"]))
            self.assertEqual(result["conversation_limits"], CONVERSATION.capabilities(PROFILE, profile))
            self.assertEqual(result["model_attention_backend"], "sdpa")
            self.assertEqual(result["model_parameter_dtype"], "bfloat16")
            self.assertEqual(result["dataset"], identity)
            self.assertEqual(result["artifacts"], [])
            self.assertEqual(result["updates_completed"], 0)
            self.assertLessEqual((root/"report.json").stat().st_size, WORKER.MAX_LINE)
            self.assertIn("tools", tokenizer.apply_chat_template.call_args.kwargs)
            self.assertFalse(tokenizer.apply_chat_template.call_args.kwargs["enable_thinking"])
            model.generate.assert_called_once()
            self.assertEqual(model.generate.call_args.kwargs["max_new_tokens"], 1024)
            self.assertEqual(model.generate.call_args.kwargs["eos_token_id"], 151645)
            generation = model.generate.call_args.kwargs
            self.assertEqual({key: generation[key] for key in
                ("do_sample", "temperature", "top_p", "top_k", "min_p")},
                {"do_sample": True, "temperature": 0.7, "top_p": 0.8, "top_k": 20, "min_p": 0.0})
            self.assertTrue(generation["use_cache"])
            self.assertEqual(len(generation["stopping_criteria"]), 1)
            tokenizer.decode.assert_called_once_with([21], skip_special_tokens=False)

    def test_exact_pins_preserve_runtime_and_private_only_admission(self):
        spec = importlib.util.spec_from_file_location("qwen_provision", Path(__file__).with_name("provision.py"))
        provision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(provision)
        pins = provision.load_pins(PROFILE)
        profile = WORKER.model_profile(PROFILE)
        self.assertEqual(len(pins["files"]), 9)
        self.assertEqual(pins["wheels"], provision.load_pins()["wheels"])
        self.assertEqual((pins["model_id"], pins["revision"]), (profile["id"], profile["revision"]))
        for artifact in pins["files"]:
            self.assertEqual((artifact["bytes"], artifact["sha256"]),
                             (profile["files"][artifact["path"]], profile["hashes"][artifact["path"]]))
        job = dict(request(), model_profile=PROFILE, mode="private_conversation", steps=1, owner_control=True)
        WORKER.validate_request(job)
        for mode in ("infer", "private_infer", "train", "plan_document", "plan_tasks", "aggregate_adapter"):
            with self.subTest(mode=mode), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(job, mode=mode))

    def test_real_template_arguments_preserve_roles_calls_namespace_and_custom_mapping(self):
        data = conversation()
        data["instructions"] = "i" * 20903
        data["tools"][0]["namespace"] = "files"
        data["tools"].append({"type": "custom", "name": "apply_patch", "namespace": "patch", "description": "Propose a patch."})
        history_call = dict(call(), namespace="files")
        data["history"].insert(0, {"type": "message", "role": "developer", "text": "Keep my ordered instruction."})
        data["history"].extend([history_call, {"type": "tool_result", "call_id": "c1", "output": "synthetic code"}])
        tokenizer = mock.Mock()
        tokenizer.apply_chat_template.return_value = [7] * 12288
        tokens = CONVERSATION.encode(tokenizer, data, WORKER.model_profile(PROFILE))
        self.assertEqual(len(tokens), 12288)
        args, kwargs = tokenizer.apply_chat_template.call_args
        self.assertFalse(kwargs["enable_thinking"])
        self.assertTrue(kwargs["tokenize"])
        self.assertNotIn("truncation", kwargs)
        self.assertIn(data["instructions"], args[0][0]["content"])
        self.assertEqual(args[0][1], {"role": "system", "content": "Developer instructions:\nKeep my ordered instruction."})
        self.assertEqual(args[0][3]["tool_calls"][0]["function"]["name"], "vp_0")
        self.assertEqual(args[0][3]["content"], "Tool call ID: c1")
        self.assertEqual(json.loads(args[0][4]["content"]), {"call_id": "c1", "name": "vp_0", "output": "synthetic code"})
        self.assertEqual(kwargs["tools"][1]["function"]["parameters"]["required"], ["input"])
        self.assertIn('"namespace":"patch"', kwargs["tools"][1]["function"]["description"])
        tokenizer.apply_chat_template.return_value.append(7)
        with self.assertRaisesRegex(ValueError, "TOKEN_LIMIT"):
            CONVERSATION.encode(tokenizer, data, WORKER.model_profile(PROFILE))
        with self.assertRaises(ValueError):
            CONVERSATION.validate(data)  # Old Smol caps and roles do not widen.

    def test_native_output_maps_only_offered_alias_and_complete_eos(self):
        data = conversation()
        data["tools"][0]["namespace"] = "files"
        raw = '<tool_call>{"name":"vp_0","arguments":{"name":"demo.rs"}}</tool_call>'
        result = NATIVE.decode(data, output(raw), ID)
        self.assertEqual(result, dict(call(), namespace="files", call_id="vp-" + ID))
        for text in (raw + raw, "first " + raw, raw + " last", raw[:-1], raw.replace("vp_0", "read_file"),
                     '<tool_call>{"name":"vp_0","arguments":{"x":1,"x":2}}</tool_call>',
                     '<think>reasoning</think>answer', '<tool_call>{"name":"vp_0","arguments":{},"extra":0}</tool_call>'):
            self.assertEqual(NATIVE.decode(data, output(text), ID)["reason"], "invalid_output")
        self.assertEqual(NATIVE.decode(data, output(raw, "token_limit"), ID)["reason"], "token_limit")
        self.assertEqual(NATIVE.decode(data, output(raw, truncated=True), ID)["reason"], "wire_truncated")
        self.assertEqual(NATIVE.decode(data, output("Plain final answer."), ID),
                         {"type": "assistant", "text": "Plain final answer."})
        data["history"].extend([result, {"type": "tool_result", "call_id": result["call_id"], "output": "ok"}])
        self.assertEqual(NATIVE.decode(data, output(raw), ID)["reason"], "invalid_output")

    def test_custom_mapping_is_explicit_and_never_execution(self):
        data = conversation()
        data["tools"] = [{"type": "custom", "name": "patch", "namespace": "local", "description": "Propose patch."}]
        raw = '<tool_call>{"name":"vp_0","arguments":{"input":"patch text"}}</tool_call>'
        self.assertEqual(NATIVE.decode(data, output(raw), ID), {"type": "custom_tool_call", "call_id": "vp-" + ID,
                         "name": "patch", "namespace": "local", "input": "patch text"})
        for arguments in ({"input": "patch", "extra": 1}, {}, {"input": 3}, {"input": "x" * 4097}):
            raw = '<tool_call>' + json.dumps({"name": "vp_0", "arguments": arguments}) + '</tool_call>'
            self.assertEqual(NATIVE.decode(data, output(raw), ID)["reason"], "invalid_output")

    def test_bf16_sdpa_no_fallback_and_caps_bind_actual_budget(self):
        profile = WORKER.model_profile(PROFILE)
        model, torch, transformers = mock.Mock(), mock.Mock(), mock.Mock()
        parameter = mock.Mock(dtype=torch.bfloat16)
        parameter.device.type = "cpu"
        parameter.numel.return_value = 1
        model.parameters.return_value = [parameter]
        model.config._attn_implementation = "sdpa"
        transformers.AutoModelForCausalLM.from_pretrained.return_value = model
        WORKER.load_model(transformers, torch, Path("/model"), PROFILE)
        self.assertEqual(transformers.AutoModelForCausalLM.from_pretrained.call_args.kwargs["dtype"], torch.bfloat16)
        self.assertEqual(transformers.AutoModelForCausalLM.from_pretrained.call_args.kwargs["attn_implementation"], "sdpa")
        self.assertEqual(WORKER.model_dtype_report(PROFILE, model, torch),
                         {"model_parameter_dtype": "bfloat16", "model_attention_backend": "sdpa"})
        model.config._attn_implementation = "eager"
        with self.assertRaisesRegex(WORKER.JobError, "ATTENTION_BACKEND"):
            WORKER.model_dtype_report(PROFILE, model, torch)
        model.config._attn_implementation = "sdpa"
        parameter.dtype = torch.float32
        with self.assertRaisesRegex(WORKER.JobError, "DTYPE"):
            WORKER.model_dtype_report(PROFILE, model, torch)
        limits = CONVERSATION.capabilities(PROFILE, profile)
        self.assertEqual((limits["max_prompt_tokens"], limits["max_new_tokens"], limits["model_context_tokens"]),
                         (12288, 1024, 32768))
        self.assertTrue(limits["native_tool_template"])
        self.assertFalse(limits["tool_execution"])


if __name__ == "__main__":
    unittest.main()
