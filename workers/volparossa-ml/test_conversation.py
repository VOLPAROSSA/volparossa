#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline protocol/template tests. Tokenizer/model doubles are not live inference proof."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_worker_protocol import WORKER, request, task_planner_doubles

SPEC = importlib.util.spec_from_file_location("volparossa_conversation", Path(__file__).with_name("conversation.py"))
CONVERSATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONVERSATION)
sys.modules["volparossa_conversation"] = CONVERSATION


def conversation():
    return {"version": 1, "visibility": "private_local", "instructions": "Review this synthetic code.",
            "tools": [{"type": "function", "name": "read_file", "description": "Read an approved file.",
                       "parameters": {"type": "object", "properties": {"name": {"type": "string"}}}}],
            "history": [{"type": "message", "role": "user", "text": "Read demo.rs."}]}


def call():
    return {"type": "function_call", "call_id": "c1", "name": "read_file", "namespace": None,
            "arguments": {"name": "demo.rs"}}


def output(value, reason="eos", truncated=False):
    return {"text": json.dumps(value), "text_truncated": truncated, "generation": {"stop_reason": reason}}


class ConversationTests(unittest.TestCase):
    def test_mode_is_private_owner_controlled_and_not_qa(self):
        job = dict(request(), mode="private_conversation", steps=1, owner_control=True)
        self.assertEqual(WORKER.validate_request(job), dict(job, threads=2, max_seconds=600))
        for change in ({"adapter_root": "/adapter"}, {"owner_control": False}, {"steps": 2}):
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(job, **change))
        data = conversation()
        self.assertIs(WORKER.validate_dataset(data, "private_conversation"), data)
        with self.assertRaises(WORKER.JobError):
            WORKER.validate_dataset(data, "private_infer")
        with mock.patch.dict(sys.modules, {"volparossa_conversation": None}):
            with self.assertRaisesRegex(WORKER.JobError, "MODULE_UNAVAILABLE"):
                WORKER.validate_dataset(data, "private_conversation")

    def test_ordered_conversation_and_definitions_enter_actual_template_boundary(self):
        data = conversation()
        data["history"].extend([call(), {"type": "tool_result", "call_id": "c1", "output": "fn main() {}"}])
        tokenizer = mock.Mock()
        tokenizer.apply_chat_template.return_value = [1, 5, 9]
        profile = WORKER.model_profile(WORKER.LARGE_MODEL_PROFILE)
        self.assertEqual(CONVERSATION.encode(tokenizer, data, profile), [1, 5, 9])
        args, kwargs = tokenizer.apply_chat_template.call_args
        self.assertEqual(kwargs, {"tokenize": True, "add_generation_prompt": True, "return_dict": False})
        messages = args[0]
        self.assertEqual([message["role"] for message in messages], ["system", "user", "assistant", "tool"])
        self.assertIn(data["instructions"], messages[0]["content"])
        self.assertIn(CONVERSATION.canonical(data["tools"]), messages[0]["content"])
        self.assertEqual(json.loads(messages[2]["content"]), call())
        self.assertEqual(json.loads(messages[3]["content"]), data["history"][2])

    def test_tokenization_never_truncates_or_raises_existing_model_limits(self):
        profile = WORKER.model_profile(WORKER.REASONING_MODEL_PROFILE)
        tokenizer = mock.Mock()
        for length, valid in ((1024, True), (1025, False), (0, False)):
            tokenizer.apply_chat_template.return_value = [1] * length
            if valid:
                self.assertEqual(len(CONVERSATION.encode(tokenizer, conversation(), profile)), length)
            else:
                with self.assertRaisesRegex(ValueError, "TOKEN_LIMIT"):
                    CONVERSATION.encode(tokenizer, conversation(), profile)
        limits = CONVERSATION.capabilities(WORKER.REASONING_MODEL_PROFILE, profile)
        self.assertEqual((limits["max_prompt_tokens"], limits["max_new_tokens"], limits["model_context_tokens"]),
                         (1024, 256, 8192))
        self.assertFalse(limits["tool_execution"])
        self.assertFalse(limits["native_tool_template"])

    def test_unknown_repeated_missing_and_wrong_kind_tool_results_rejected(self):
        data = conversation()
        data["history"].extend([call(), {"type": "tool_result", "call_id": "c1", "output": "ok"}])
        CONVERSATION.validate(data)
        invalids = []
        bad = copy.deepcopy(data); bad["history"][2]["call_id"] = "other"; invalids.append(bad)
        bad = copy.deepcopy(data); bad["history"].pop(); invalids.append(bad)
        bad = copy.deepcopy(data); bad["history"][1]["name"] = "shell"; invalids.append(bad)
        bad = copy.deepcopy(data); bad["history"].extend(data["history"][1:]); invalids.append(bad)
        bad = copy.deepcopy(data); bad["tools"].append(data["tools"][0]); invalids.append(bad)
        bad = copy.deepcopy(data); bad["visibility"] = "public"; invalids.append(bad)
        for bad in invalids:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                CONVERSATION.validate(bad)

    def test_only_complete_valid_actual_generation_becomes_proposal(self):
        data = conversation()
        self.assertEqual(CONVERSATION.decode(data, output(call())), call())
        for reason, truncated, expected in (("token_limit", False, "token_limit"), ("eos", True, "wire_truncated")):
            self.assertEqual(CONVERSATION.decode(data, output(call(), reason, truncated)),
                             {"type": "incomplete", "reason": expected})
        for raw in ('```json\n{}\n```', '{"type":"assistant","text":"a","text":"b"}',
                    '{"type":"function_call","call_id":"c1","name":"read_file","arguments":{"name":"a","name":"b"}}',
                    '{"type":"assistant","text":""}', json.dumps(dict(call(), name="shell"))):
            report = output(None); report["text"] = raw
            self.assertEqual(CONVERSATION.decode(data, report), {"type": "incomplete", "reason": "invalid_output"})
        data["history"].extend([call(), {"type": "tool_result", "call_id": "c1", "output": "ok"}])
        self.assertEqual(CONVERSATION.decode(data, output(call()))["reason"], "invalid_output")

    def test_custom_tools_preserve_namespace_and_plain_input_without_execution(self):
        data = conversation()
        data["tools"] = [{"type": "custom", "name": "patch", "namespace": "local", "description": "Propose a patch."}]
        proposal = {"type": "custom_tool_call", "call_id": "p1", "name": "patch", "namespace": "local", "input": "patch text"}
        self.assertEqual(CONVERSATION.decode(data, output(proposal)), proposal)
        self.assertEqual(CONVERSATION.decode(data, output(dict(proposal, namespace=None)))["reason"], "invalid_output")

    def test_worker_dispatch_uses_model_generation_not_public_qa_or_canned_proposals(self):
        # Backend doubles verify dispatch only; no weights/tokenizer are loaded in this test.
        data, profile_name = conversation(), WORKER.LARGE_MODEL_PROFILE
        raw = json.dumps(data).encode()
        identity = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "visibility": "private_local"}
        profile = WORKER.model_profile(profile_name)
        files = {name: {"bytes": size, "sha256": profile["hashes"][name]} for name, size in profile["files"].items()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, tokenizer, torch, transformers = task_planner_doubles(json.dumps(call()), generated=[21, 2])
            job = WORKER.validate_request(dict(request(), mode="private_conversation", steps=1, owner_control=True,
                                               model_profile=profile_name, output_root=str(root)))
            with mock.patch.object(WORKER, "prepare_files", return_value=(root/"model", root, data, identity, files)), \
                 mock.patch.object(WORKER, "configure_offline"), \
                 mock.patch.object(WORKER, "load_backend", return_value=(torch, transformers, mock.Mock(), WORKER.BACKENDS)), \
                 mock.patch.object(WORKER, "load_model", return_value=model), \
                 mock.patch.object(WORKER, "file_hash", return_value=files["model.safetensors"]), \
                 mock.patch.object(WORKER, "encode_private", side_effect=AssertionError("Q&A branch")), \
                 mock.patch.object(WORKER, "encode_dataset", side_effect=AssertionError("public branch")), \
                 mock.patch.object(WORKER, "evaluate", side_effect=AssertionError("training")), \
                 mock.patch.object(WORKER, "WIRE_OUTPUT", io.StringIO()):
                session = mock.Mock(frames=None)
                session.elapsed.return_value = 0
                result = WORKER.execute_job(job, session)
            self.assertEqual(result["mode"], "private_conversation")
            self.assertEqual(result["conversation"], call())
            self.assertEqual(result["conversation_limits"], CONVERSATION.capabilities(profile_name, profile))
            self.assertEqual(result["dataset"], identity)
            self.assertGreater(result["prompt_tokens"], 0)
            self.assertEqual(result["artifacts"], [])
            self.assertEqual(result["updates_completed"], 0)
            self.assertNotIn("generation_policy", result)
            model.generate.assert_called_once()
            self.assertEqual(model.generate.call_args.kwargs["max_new_tokens"], 256)
            self.assertFalse(model.generate.call_args.kwargs["do_sample"])
            self.assertNotIn("num_beams", model.generate.call_args.kwargs)
            self.assertLessEqual((root/"report.json").stat().st_size, WORKER.MAX_LINE)


if __name__ == "__main__":
    unittest.main()
