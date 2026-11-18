# SPDX-License-Identifier: GPL-3.0-only
"""Inert admission/provenance/ABI tests; no native build or model execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

import llama_cpu as native
from test_conversation import CONVERSATION, conversation
from test_llama_cpu import job, manifest
from test_worker_protocol import WORKER, request
from test_qwen_conversation import NATIVE


def selected(count=1):
    return dict(job(), output_constraint=native.OUTPUT_CONSTRAINT,
                output_constraint_tools=[f"vp_{index}" for index in range(count)])


def selected_data():
    return dict(conversation(), generation_policy="greedy_v1", output_constraint=native.OUTPUT_CONSTRAINT)


def build_manifest(version=2):
    result = dict(version=version, abi_version=1, kind=native.KIND,
                  source_commit=native.SOURCE, source_tree=native.SOURCE_TREE,
                  source_overlay=native.loader_provenance(), loader_compile_source_verified=True,
                  upstream_original_unchanged=True, cpu="avx2_fma_f16c", provisionable=True,
                  sanitizers=False, quantization=False)
    if version == 3:
        result["output_constraints"] = [native.OUTPUT_CONSTRAINT]
    return result


def bundle(root, version, build_version):
    value = manifest()
    value["version"] = version
    if version == 2:
        value["output_constraints"] = [native.OUTPUT_CONSTRAINT]
    for field, raw in (("library", b"inert-not-library"), ("gguf", b"inert-not-model")):
        (root / value[field]["path"]).write_bytes(raw)
        value[field].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    build = dict(build_manifest(build_version), library=value["library"])
    build_raw = json.dumps(build).encode()
    (root / "build.json").write_bytes(build_raw)
    value["build_manifest_sha256"] = hashlib.sha256(build_raw).hexdigest()
    value["verification"]["chat_template_sha256"] = hashlib.sha256(b"unchanged").hexdigest()
    raw = json.dumps(value).encode()
    (root / "backend.json").write_bytes(raw)
    return dict(job(), native_backend_root=str(root), native_backend_sha256=hashlib.sha256(raw).hexdigest())


def library(extension=True):
    def allocate(_path, _capacity, _threads, _callback, _opaque, output):
        output._obj.value = 123
        return 0
    value = SimpleNamespace(
        vp_llama_abi_v1=mock.Mock(return_value=1),
        vp_llama_source_v1=mock.Mock(return_value=native.SOURCE.encode()),
        vp_llama_open_stage_v1=mock.Mock(return_value=8),
        vp_llama_open_v1=mock.Mock(side_effect=allocate),
        vp_llama_decode_v1=mock.Mock(return_value=0),
        vp_llama_sample_v1=mock.Mock(return_value=0),
        vp_llama_close_v1=mock.Mock())
    if extension:
        value.vp_llama_output_constraint_abi_v1 = mock.Mock(return_value=1)
        value.vp_llama_set_output_constraint_v1 = mock.Mock(return_value=0)
    return value


class ConstraintAdmissionTests(unittest.TestCase):
    def test_legacy_requests_are_not_implicitly_constrained(self):
        for value in (request(), job()):
            result = WORKER.validate_request(value)
            self.assertEqual(result, dict(value, steps=value.get("steps", 8), threads=2, max_seconds=600))
            self.assertNotIn("output_constraint", result)
            self.assertNotIn("output_constraint_tools", result)

    def test_only_complete_core_alias_list_is_accepted(self):
        for count in (1, 32):
            value = selected(count)
            self.assertEqual(WORKER.validate_request(value)["output_constraint_tools"], value["output_constraint_tools"])
        for changes in ({"output_constraint": None}, {"output_constraint": True},
                        {"output_constraint": "user-grammar"}, {"output_constraint_tools": None},
                        {"output_constraint_tools": []}, {"output_constraint_tools": ["vp_1"]},
                        {"output_constraint_tools": ["vp_0", "vp_0"]},
                        {"output_constraint_tools": ["read_private_file"]},
                        {"output_constraint_tools": [True]},
                        {"output_constraint_tools": [f"vp_{n}" for n in range(33)]},
                        {"mode": "train"}, {"model_profile": WORKER.QWEN_MODEL_PROFILE}):
            with self.subTest(changes=changes), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(selected(), **changes))
        for field in ("output_constraint", "output_constraint_tools", "inference_backend"):
            value = selected()
            del value[field]
            with self.subTest(field=field), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(value)

    def test_aliases_bind_actual_ordered_dataset_before_loading(self):
        data = selected_data()
        for selected_job, changed in ((selected(2), data), (selected(), dict(data, tools=[]))):
            with mock.patch.object(WORKER, "conversation_module", return_value=CONVERSATION), \
                    mock.patch.object(native, "verified_bundle", side_effect=AssertionError("must not access bundle")), \
                    self.assertRaisesRegex((WORKER.JobError, ValueError), "OUTPUT_CONSTRAINT"):
                native.execute(selected_job, mock.Mock(), None, None, {}, None, None,
                               changed, {}, {}, WORKER, initial_source_weights=None)

    def test_serialized_input_selector_is_closed_and_preserves_bytes(self):
        data = selected_data()
        raw = CONVERSATION.canonical(data)
        self.assertIs(WORKER.validate_dataset(data, "private_conversation", native.PROFILE), data)
        self.assertEqual(CONVERSATION.canonical(data), raw)
        invalid = [dict(data, output_constraint=value) for value in
                   (None, True, 1, "", "private-grammar", [], {})]
        invalid.extend((dict(data, generation_policy=None), dict(data, tools=[]),
                        dict(data, output_constraint_tools=["vp_0"])))
        no_policy = dict(data)
        del no_policy["generation_policy"]
        invalid.append(no_policy)
        for changed in invalid:
            with self.subTest(data=changed), self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(changed, "private_conversation", native.PROFILE)
        for profile in (CONVERSATION.QWEN, WORKER.DEFAULT_MODEL_PROFILE):
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(data, "private_conversation", profile)

    def test_request_dataset_constraint_matches_in_both_directions_before_backend(self):
        legacy = dict(conversation(), generation_policy="greedy_v1")
        cases = ((selected(), legacy), (job(), selected_data()),
                 (dict(selected(), output_constraint="different"), selected_data()))
        for selected_job, data in cases:
            with self.subTest(request=selected_job), \
                    mock.patch.object(native, "verified_bundle", side_effect=AssertionError("no native load")), \
                    self.assertRaisesRegex(WORKER.JobError, "NATIVE_OUTPUT_CONSTRAINT_BINDING"):
                native.execute(selected_job, mock.Mock(), None, None, {}, None, None,
                               data, {}, {}, WORKER, initial_source_weights=None)
            with mock.patch.object(WORKER, "prepare_files", return_value=(None, None, data, {}, {})), \
                    mock.patch.object(WORKER, "load_backend", side_effect=AssertionError("no backend import")), \
                    self.assertRaisesRegex(WORKER.JobError, "NATIVE_OUTPUT_CONSTRAINT_BINDING"):
                WORKER.execute_job(selected_job, mock.Mock())
        torch_job = WORKER.validate_request(dict(request(), mode="private_conversation", steps=1,
                                                owner_control=True, model_profile=native.PROFILE))
        with mock.patch.object(WORKER, "prepare_files", return_value=(None, None, selected_data(), {}, {})), \
                mock.patch.object(WORKER, "load_backend", side_effect=AssertionError("no silent torch fallback")), \
                self.assertRaisesRegex(WORKER.JobError, "NATIVE_OUTPUT_CONSTRAINT_BINDING"):
            WORKER.execute_job(torch_job, mock.Mock())


class ConstraintProvenanceTests(unittest.TestCase):
    def test_old_and_new_closed_manifest_shapes_do_not_mix(self):
        legacy = manifest()
        old_bytes = json.dumps(legacy).encode()
        native.validate_manifest(legacy, WORKER.require)
        self.assertEqual(json.dumps(legacy).encode(), old_bytes)
        modern = dict(legacy, version=2, output_constraints=[native.OUTPUT_CONSTRAINT])
        native.validate_manifest(modern, WORKER.require)
        for value in (dict(legacy, output_constraints=[]), dict(legacy, output_constraints=[native.OUTPUT_CONSTRAINT]),
                      dict(legacy, version=2), dict(modern, version=True),
                      dict(modern, output_constraints=[]), dict(modern, output_constraints=None),
                      dict(modern, output_constraints=[native.OUTPUT_CONSTRAINT, native.OUTPUT_CONSTRAINT]),
                      dict(modern, output_constraints=["private-grammar"]), dict(modern, grammar="secret")):
            with self.subTest(value=value), self.assertRaises(WORKER.JobError):
                native.validate_manifest(value, WORKER.require)
        for version in (2, 3):
            native.validate_build_provenance(build_manifest(version), WORKER.require)
        for value in (dict(build_manifest(), output_constraints=[native.OUTPUT_CONSTRAINT]),
                      dict(build_manifest(3), output_constraints=[]), dict(build_manifest(3), version=4)):
            with self.assertRaises(WORKER.JobError):
                native.validate_build_provenance(value, WORKER.require)

    def test_verified_bundle_requires_matching_capabilities_and_request(self):
        for version, build_version in ((1, 2), (2, 3), (1, 3), (2, 2)):
            for constrained in (False, True):
                with self.subTest(version=version, build=build_version, constrained=constrained), \
                        tempfile.TemporaryDirectory() as directory:
                    value = bundle(Path(directory), version, build_version)
                    if constrained:
                        value.update(output_constraint=native.OUTPUT_CONSTRAINT, output_constraint_tools=["vp_0"])
                    with mock.patch.object(native.ctypes, "CDLL", side_effect=AssertionError("no library execution")):
                        arguments = (value, WORKER, SimpleNamespace(chat_template="unchanged"), mock.Mock())
                        if build_version != version + 1 or constrained and version == 1:
                            with self.assertRaises(WORKER.JobError):
                                native.verified_bundle(*arguments)
                        else:
                            _, _, identity = native.verified_bundle(*arguments)
                            self.assertNotIn("output_constraint", identity)
                            self.assertEqual(identity["manifest_sha256"], value["native_backend_sha256"])


class ConstraintAbiTests(unittest.TestCase):
    def open(self, value, **kwargs):
        with mock.patch.object(native.ctypes, "CDLL", return_value=value):
            return native.NativeModel(Path("/inert"), 512, 2, mock.Mock(), WORKER.require, **kwargs)

    def test_legacy_abi_without_extension_remains_usable(self):
        value = library(False)
        model = self.open(value)
        model.close()
        value.vp_llama_open_v1.assert_called_once()
        value.vp_llama_close_v1.assert_called_once()

    def test_capability_cannot_be_claimed_by_old_or_wrong_library(self):
        values = [library(False)]
        for version in (0, 2, True):
            value = library()
            value.vp_llama_output_constraint_abi_v1.return_value = version
            values.append(value)
        for value in values:
            with self.assertRaisesRegex(WORKER.JobError, "NATIVE_OUTPUT_CONSTRAINT_ABI_MISMATCH"):
                self.open(value, output_constraints=[native.OUTPUT_CONSTRAINT])
            value.vp_llama_open_v1.assert_not_called()

    def test_declared_capability_does_not_enable_constraint_without_request(self):
        value = library()
        model = self.open(value, output_constraints=[native.OUTPUT_CONSTRAINT])
        model.close()
        value.vp_llama_output_constraint_abi_v1.assert_called_once()
        value.vp_llama_set_output_constraint_v1.assert_not_called()

    def test_constraint_is_configured_once_with_mode_and_actual_count_before_decode(self):
        value = library()
        events = []
        value.vp_llama_set_output_constraint_v1.side_effect = lambda *_args: events.append("configure") or 0
        value.vp_llama_decode_v1.side_effect = lambda *_args: events.append("decode") or 0
        model = self.open(value, output_constraints=[native.OUTPUT_CONSTRAINT],
                          output_constraint=native.OUTPUT_CONSTRAINT, output_constraint_tools=["vp_0", "vp_1"])
        model.decode([7])
        self.assertEqual(events, ["configure", "decode"])
        self.assertEqual(value.vp_llama_set_output_constraint_v1.call_args.args[1:], (1, 2))
        value.vp_llama_set_output_constraint_v1.assert_called_once()
        model.close()

    def test_configure_failure_or_cancel_closes_handle_without_decode(self):
        for cancelled in (False, True):
            value, probe = library(), mock.Mock()
            value.vp_llama_set_output_constraint_v1.return_value = 3 if not cancelled else 0
            if cancelled:
                probe.joined.side_effect = [None, WORKER.JobError("JOB_CANCELLED")]
            with mock.patch.object(native.ctypes, "CDLL", return_value=value), \
                    self.assertRaisesRegex(WORKER.JobError, "JOB_CANCELLED" if cancelled else "CONFIGURATION_FAILED"):
                native.NativeModel(Path("/inert"), 512, 2, probe, WORKER.require,
                                   output_constraints=[native.OUTPUT_CONSTRAINT],
                                   output_constraint=native.OUTPUT_CONSTRAINT, output_constraint_tools=["vp_0"])
            value.vp_llama_close_v1.assert_called_once()
            value.vp_llama_decode_v1.assert_not_called()


class ConstraintResultTests(unittest.TestCase):
    def test_output_tag_only_echoes_successfully_requested_constraint(self):
        data = dict(conversation(), generation_policy="greedy_v1")
        profile = WORKER.model_profile(native.PROFILE)
        files = {name: {"bytes": profile["files"][name], "sha256": profile["hashes"][name]}
                 for name in profile["weights"]["files"]}
        output = {"sample_index": 0, "text": "Ordinary answer.", "generated_tokens": 3,
                  "text_truncated": False, "generation": {"stop_reason": "eos"}}
        bridge = SimpleNamespace(generation_policy=CONVERSATION.generation_policy,
                                 output_constraint=CONVERSATION.output_constraint,
                                 validate=CONVERSATION.validate, encode=lambda *_args: [1, 2],
                                 decode=lambda *_args: {"type": "assistant", "text": output["text"]},
                                 capabilities=lambda *_args: {"inert": True})
        baseline = None
        for declared, requested in ((False, False), (True, False), (True, True)):
            with self.subTest(declared=declared, requested=requested), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                raw = b"inert model file"
                (root / "model.gguf").write_bytes(raw)
                value = manifest()
                value["gguf"].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                if declared:
                    value.update(version=2, output_constraints=[native.OUTPUT_CONSTRAINT])
                model = mock.Mock()
                selected_job = WORKER.validate_request(selected() if requested else job())
                with mock.patch.object(WORKER, "conversation_module", return_value=bridge), \
                        mock.patch.object(native, "verified_bundle", return_value=(root, value, {})), \
                        mock.patch.object(native, "NativeModel", return_value=model) as opened, \
                        mock.patch.object(native, "generate", return_value=copy.deepcopy(output)), \
                        mock.patch.object(WORKER, "finish_result", side_effect=lambda result, *_args: result):
                    result = native.execute(selected_job, mock.Mock(), None, None, {}, None, root,
                                            selected_data() if requested else data,
                                            {"sha256": "d" * 64}, files, WORKER,
                                            initial_source_weights=profile["weights"])
                self.assertEqual(result["outputs"], [output])
                self.assertEqual(result["generation_policy"], "greedy_v1")
                self.assertEqual(result["conversation"], {"type": "assistant", "text": output["text"]})
                self.assertEqual("output_constraint" in result, requested)
                if requested:
                    self.assertEqual(result["output_constraint"], native.OUTPUT_CONSTRAINT)
                    self.assertEqual(opened.call_args.kwargs["output_constraint_tools"], ["vp_0"])
                elif declared:
                    self.assertEqual(opened.call_args.kwargs, {"output_constraints": [native.OUTPUT_CONSTRAINT]})
                else:
                    self.assertEqual(opened.call_args.kwargs, {})
                legacy_shape = dict(result)
                legacy_shape.pop("output_constraint", None)
                if baseline is None:
                    baseline = legacy_shape
                self.assertEqual(legacy_shape, baseline, "no other legacy result field changes")
                model.close.assert_called_once()

    def test_real_execute_chain_accepts_serialized_selection_and_unchanged_template(self):
        data, profile = selected_data(), WORKER.model_profile(native.PROFILE)
        raw = CONVERSATION.canonical(data).encode()
        files = {name: {"bytes": profile["files"][name], "sha256": profile["hashes"][name]}
                 for name in profile["weights"]["files"]}
        identity = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "visibility": "private_local"}
        tokenizer = mock.Mock(pad_token_id=151643, eos_token_id=151645)
        tokenizer.apply_chat_template.return_value = [1, 2]
        transformers = mock.Mock()
        transformers.AutoTokenizer.from_pretrained.return_value = tokenizer
        output = {"sample_index": 0, "text": '<tool_call>{"name":"vp_0","arguments":{"name":"demo.rs"}}</tool_call>',
                  "generated_tokens": 3, "text_truncated": False, "generation": {"stop_reason": "eos"}}
        with tempfile.TemporaryDirectory() as directory:
            root, model = Path(directory), mock.Mock()
            model_raw = b"inert model file"
            (root / "model.gguf").write_bytes(model_raw)
            value = dict(manifest(), version=2, output_constraints=[native.OUTPUT_CONSTRAINT])
            value["gguf"].update(bytes=len(model_raw), sha256=hashlib.sha256(model_raw).hexdigest())
            def prepared(_request, *, session, initial_source, source_cache):
                self.assertIsInstance(source_cache, WORKER.NativeSourceCache)
                initial_source["weights"] = profile["weights"]
                parsed = WORKER.validate_dataset(WORKER.parse_json(raw), "private_conversation", native.PROFILE)
                return root, root, parsed, identity, files
            with mock.patch.dict(sys.modules, {"volparossa_llama_cpu": native,
                                               "volparossa_qwen_conversation": NATIVE}), \
                    mock.patch.object(WORKER, "prepare_files", side_effect=prepared), \
                    mock.patch.object(WORKER, "configure_offline"), \
                    mock.patch.object(WORKER, "load_backend", return_value=(None, transformers, None, {})), \
                    mock.patch.object(native, "verified_bundle", return_value=(root, value, {})), \
                    mock.patch.object(native, "NativeModel", return_value=model) as opened, \
                    mock.patch.object(native, "generate", return_value=output), \
                    mock.patch.object(WORKER, "finish_result", side_effect=lambda result, *_args: result):
                result = WORKER.execute_job(WORKER.validate_request(selected()), mock.Mock())
            self.assertEqual(result["output_constraint"], native.OUTPUT_CONSTRAINT)
            self.assertEqual(result["conversation"]["type"], "function_call")
            self.assertEqual(result["conversation"]["arguments"], {"name": "demo.rs"})
            self.assertEqual(result["dataset"], identity)
            self.assertEqual(opened.call_args.kwargs["output_constraint_tools"], ["vp_0"])
            template = tokenizer.apply_chat_template.call_args
            legacy = dict(data)
            del legacy["output_constraint"]
            self.assertEqual(template.args[0], NATIVE.messages(legacy, native.PROFILE))
            self.assertEqual(template.kwargs["tools"], NATIVE.native_tools(legacy))
            model.close.assert_called_once()

    def test_selected_output_depth_counts_containers_not_envelope_or_strings(self):
        for depth in (1, 16, 17):
            args = {"name": "[[[{{{ literal text }}}]]]"}
            for index in range(depth - 1):
                args = {"child": args} if index % 2 == 0 else [args]
            if type(args) is not dict:
                # Preserve the required object root without increasing depth.
                args = {"child": args[0]}
            raw = '<tool_call>' + json.dumps({"name": "vp_0", "arguments": args}) + '</tool_call>'
            output = {"text": raw, "text_truncated": False, "generation": {"stop_reason": "eos"}}
            for constrained in (False, True):
                data = selected_data() if constrained else dict(conversation(), generation_policy="greedy_v1")
                result = CONVERSATION.decode(data, output, native.PROFILE, "a" * 32)
                self.assertEqual(result["type"], "incomplete" if constrained and depth > 16 else "function_call")
                if result["type"] == "incomplete":
                    self.assertEqual(result["reason"], "invalid_output")


if __name__ == "__main__":
    unittest.main()
