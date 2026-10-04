# SPDX-License-Identifier: GPL-3.0-only
"""Inert public-purpose/template/dispatch checks, not model or coding-quality proof."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_qwen_conversation import WORKER  # Registers only the fixed native template helper.
from test_worker_protocol import request, task_planner_doubles


def dataset(profile=WORKER.QWEN_MODEL_PROFILE):
    source = "// Public café fixture\nfn sum(a: i32, b: i32) -> i32 { a - b }\n"
    return dict(version=6, visibility="public", purpose="code_proposal", license="GPL-3.0-only",
                model_profile=profile, source_manifest_hex="ab" * 64,
                inference=[dict(question="Correct this function.", context=source,
                                start=0, end=len(source.encode()))],
                output_contract="single_file_replacement_v1")


class PublicCodeProposalTests(unittest.TestCase):
    def test_explicit_profile_purpose_no_adapter_training_or_private_context(self):
        for profile in WORKER.NATIVE_CONVERSATION_PROFILES:
            data = dataset(profile)
            job = dict(request(), mode="public_code_proposal", model_profile=profile,
                       steps=1, owner_control=True)
            WORKER.validate_request(job)
            self.assertIs(WORKER.validate_dataset(data, job["mode"], profile), data)
            for change in ({"steps": 2}, {"owner_control": False}, {"adapter_root": "/adapter"},
                           {"model_profile": WORKER.LARGE_MODEL_PROFILE}, {"mode": "infer"},
                           {"mode": "train"}, {"mode": "plan_document"}):
                with self.subTest(change=change), self.assertRaises(WORKER.JobError):
                    WORKER.validate_request(dict(job, **change))
            with self.assertRaises((WORKER.JobError, ValueError)):
                WORKER.validate_dataset(data, "private_conversation", profile)

    def test_exact_whole_public_source_shape_and_utf8_bounds(self):
        original = dataset()
        for key, value in (("version", True), ("visibility", "private_local"), ("purpose", "question"),
                           ("model_profile", WORKER.QWEN4B_MODEL_PROFILE), ("license", "unknown"),
                           ("source_manifest_hex", "AB"), ("output_contract", "execute_shell"),
                           ("inference", []), ("inference", original["inference"] * 2),
                           ("history", []), ("tools", []), ("train", []), ("path", "/private")):
            data = dict(original, **{key: value})
            with self.subTest(key=key), self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(data, "public_code_proposal", WORKER.QWEN_MODEL_PROFILE)
        for key, value in (("start", 1), ("start", False), ("end", 1), ("end", True),
                           ("question", " "), ("question", "x" * 513),
                           ("context", "x" * 4097), ("context", "bad\x00code")):
            data = copy.deepcopy(original)
            data["inference"][0][key] = value
            with self.subTest(key=key), self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(data, "public_code_proposal", WORKER.QWEN_MODEL_PROFILE)

    def test_source_identity_is_exact_bytes_not_independent_publisher_trust(self):
        data = dataset()
        identity = WORKER.code_proposal_identity(data)
        source = data["inference"][0]["context"].encode()
        self.assertEqual(identity["source_sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(identity["source_bytes"], len(source))
        self.assertEqual(identity["source_manifest_sha256"], hashlib.sha256(bytes.fromhex(data["source_manifest_hex"])).hexdigest())
        data["inference"][0]["context"] += " "
        self.assertNotEqual(WORKER.code_proposal_identity(data)["source_sha256"], identity["source_sha256"])

    def test_native_template_preserves_source_no_tools_and_never_truncates_input(self):
        data, tokenizer = dataset(), mock.Mock()
        for count, valid in ((1, True), (12288, True), (12289, False), (0, False)):
            tokenizer.apply_chat_template.return_value = [11] * count
            if valid:
                self.assertEqual(len(WORKER.code_proposal_tokens(tokenizer, data, WORKER.QWEN_MODEL_PROFILE)), count)
            else:
                with self.assertRaisesRegex(WORKER.JobError, "PUBLIC_CODE_TOKEN_LIMIT"):
                    WORKER.code_proposal_tokens(tokenizer, data, WORKER.QWEN_MODEL_PROFILE)
        args, kwargs = tokenizer.apply_chat_template.call_args
        self.assertEqual(kwargs, dict(tools=[], enable_thinking=False, tokenize=True,
                                      add_generation_prompt=True, return_dict=False))
        self.assertEqual([item["role"] for item in args[0]], ["system", "user"])
        self.assertTrue(args[0][1]["content"].endswith(data["inference"][0]["context"]))

    def test_real_dispatch_boundary_keeps_original_generation_for_both_profiles(self):
        for profile in WORKER.NATIVE_CONVERSATION_PROFILES:
            with self.subTest(profile=profile):
                result, model = self.execute_double(profile, "```rust\nunchanged raw model output\n```", [21, 2])
                self.assertTrue(result["proposal_complete"])
                self.assertEqual(result["outputs"][0]["text"], "```rust\nunchanged raw model output\n```")
                self.assertEqual(result["outputs"][0]["generation"]["stop_reason"], "eos")
                self.assertEqual(model.generate.call_args.kwargs["max_new_tokens"], 1024)
                self.assertEqual(model.generate.call_args.kwargs["num_beams"], 1)
                self.assertFalse(model.generate.call_args.kwargs["do_sample"])

    def test_incomplete_generation_is_retained_not_repaired_or_declared_complete(self):
        for text, tokens, reason, truncated in (("partial", [21] * 1024, "token_limit", False),
                                               ("x" * 5000, [21, 2], "eos", True),
                                               ("  \n", [21, 2], "eos", False)):
            with self.subTest(reason=reason, truncated=truncated):
                result, _ = self.execute_double(WORKER.QWEN_MODEL_PROFILE, text, tokens)
                self.assertFalse(result["proposal_complete"])
                self.assertEqual(result["outputs"][0]["generation"]["stop_reason"], reason)
                self.assertEqual(result["outputs"][0]["text_truncated"], truncated)
                if not truncated:
                    self.assertEqual(result["outputs"][0]["text"], text)

    def execute_double(self, profile_name, text, tokens):
        # Fake backend boundaries only: no tensor/model packages, weights, or inference.
        data, profile = dataset(profile_name), WORKER.model_profile(profile_name)
        raw = json.dumps(data).encode()
        identity = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), visibility="public",
                        license=data["license"], **WORKER.code_proposal_identity(data))
        files = {name: dict(bytes=size, sha256=profile["hashes"][name]) for name, size in profile["files"].items()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, tokenizer, torch, transformers = task_planner_doubles(
                text, generated=[151645 if token == 2 else token for token in tokens])
            tokenizer.pad_token_id, tokenizer.eos_token_id = 151643, 151645
            model.config._attn_implementation = "sdpa"
            job = WORKER.validate_request(dict(request(), mode="public_code_proposal", steps=1,
                owner_control=True, model_profile=profile_name, output_root=str(root)))
            with mock.patch.object(WORKER, "prepare_files", return_value=(root/"model", root, data, identity, files)), \
                 mock.patch.object(WORKER, "configure_offline"), \
                 mock.patch.object(WORKER, "load_backend", return_value=(torch, transformers, mock.Mock(), WORKER.BACKENDS)), \
                 mock.patch.object(WORKER, "load_model", return_value=model), \
                 mock.patch.object(WORKER, "file_hash", return_value=files.get("model.safetensors")), \
                 mock.patch.object(WORKER, "verify_sharded_weights", return_value=profile.get("weights")), \
                 mock.patch.object(WORKER, "execute_private_infer", side_effect=AssertionError("private conversation")), \
                 mock.patch.object(WORKER, "encode_dataset", side_effect=AssertionError("document QA")), \
                 mock.patch.object(WORKER, "evaluate", side_effect=AssertionError("training")), \
                 mock.patch.object(WORKER, "WIRE_OUTPUT", io.StringIO()):
                session = mock.Mock(frames=None)
                session.elapsed.return_value = 0
                result = WORKER.execute_job(job, session)
            self.assertEqual(result["mode"], "public_code_proposal")
            self.assertEqual(result["dataset"], identity)
            self.assertEqual(result["generation_policy"], "greedy_v1")
            self.assertEqual(result["artifacts"], [])
            self.assertEqual(result["updates_completed"], 0)
            self.assertTrue(result["public_data_only"])
            self.assertFalse(result["private_data_supported"])
            self.assertNotIn("conversation", result)
            self.assertNotIn("input_adapter", result)
            self.assertEqual(result["model_parameter_dtype"], "bfloat16")
            self.assertEqual(result["model_attention_backend"], "sdpa")
            self.assertEqual(result["model"].get("weights"), profile.get("weights"))
            model.generate.assert_called_once()
            self.assertLessEqual((root/"report.json").stat().st_size, WORKER.MAX_LINE)
            return result, model


if __name__ == "__main__":
    unittest.main()
