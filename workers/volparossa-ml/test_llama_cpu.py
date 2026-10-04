# SPDX-License-Identifier: GPL-3.0-only
"""Inert protocol/value-preservation tests: no model/backend download or inference."""
import copy
import io
import json
import hashlib
import os
from pathlib import Path
import signal
import struct
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import build_llama_cpu as builder
import convert_llama_cpu as conversion
import llama_cpu as native
from test_worker_protocol import WORKER, request, controlled_pipe, control


def job():
    return dict(request(), mode="private_conversation", model_profile=native.PROFILE,
                steps=1, owner_control=True, inference_backend=native.KIND,
                native_backend_root="/native-backend", native_backend_sha256="a" * 64)


def manifest():
    return {"version": 1, "kind": native.KIND, "abi_version": 1, "source_commit": native.SOURCE,
            "model_profile": native.PROFILE, "source_weights_sha256": native.WEIGHTS_SHA,
            "source_weights_bytes": native.WEIGHTS_BYTES,
            "library": {"path": native.LIBRARY, "sha256": "b" * 64, "bytes": 10},
            "gguf": {"path": "model.gguf", "sha256": "c" * 64, "bytes": 20},
            "verification": {"tensor_count": 398, "tensor_values_equal": True, "tokenizer_equal": True,
                             "chat_template_sha256": "d" * 64}, "build_manifest_sha256": "e" * 64}


class NativeCpuTests(unittest.TestCase):
    def test_converter_dependency_is_explicit_exact_and_baseline_lock_unchanged(self):
        provision = conversion.provision
        baseline = provision.load_pins(native.PROFILE)
        original = copy.deepcopy(baseline)
        pins = provision.load_pins(native.PROFILE, native_cpu_converter=True)
        self.assertEqual(len(baseline["wheels"]), 38)
        self.assertEqual(len(pins["wheels"]), 39)
        self.assertEqual(pins["wheels"][:-1], original["wheels"])
        self.assertEqual(pins["files"], original["files"])
        self.assertEqual(pins["weights"], original["weights"])
        self.assertEqual(provision.download_total(pins) - provision.download_total(baseline), 1387882)
        pin_bytes, lock = provision.retained_pin_files(pins)
        self.assertEqual(json.loads(pin_bytes)["native_cpu_converter"], provision.NATIVE_CONVERTER)
        self.assertEqual(lock, (provision.HERE / "requirements.lock").read_bytes()
                         + (provision.HERE / "native-converter-requirements.lock").read_bytes())
        self.assertEqual(provision.retained_pin_files(baseline)[1], (provision.HERE / "requirements.lock").read_bytes())
        self.assertEqual(provision.load_pins(native.PROFILE), original)
        for profile, graph in ((WORKER.QWEN_MODEL_PROFILE, False), (native.PROFILE, True)):
            with self.assertRaises(provision.ProvisionError):
                provision.load_pins(profile, graph, native_cpu_converter=True)

    def test_converter_pin_cannot_override_existing_distribution_or_license_bytes(self):
        provision = conversion.provision
        pins = provision.load_pins(native.PROFILE, native_cpu_converter=True)
        with self.assertRaisesRegex(provision.ProvisionError, "override"):
            provision.add_native_converter(pins)
        real_read = Path.read_bytes
        def changed(path):
            raw = real_read(path)
            return raw + b"changed" if path.name == "sentencepiece-LICENSE" else raw
        with mock.patch.object(Path, "read_bytes", changed), self.assertRaisesRegex(provision.ProvisionError, "notice bytes"):
            provision.native_converter_pins()

    def test_converter_cancellation_during_successful_wait_or_final_join_is_not_swallowed(self):
        before = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        def cancelled_success(*_args, **_kwargs):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return 0
        for checkpoint in ("wait", "poll"):
            with self.subTest(checkpoint=checkpoint):
                process = mock.Mock(pid=os.getpid())
                process.wait.return_value = process.poll.return_value = 0
                getattr(process, checkpoint).side_effect = cancelled_success
                with mock.patch.object(conversion.subprocess, "Popen", return_value=process), \
                        self.assertRaisesRegex(conversion.ConversionCancelled, "NATIVE_CONVERSION_CANCELLED"):
                    conversion.run_converter([sys.executable, "-c", "pass"], io.BytesIO(), dict(os.environ), 1)
                process.terminate.assert_not_called()
                process.kill.assert_not_called()
                self.assertEqual({signum: signal.getsignal(signum) for signum in before}, before)

    @staticmethod
    def child_source(ignore_term=False):
        return ("import json,os,signal,time;"
                + ("signal.signal(signal.SIGTERM,signal.SIG_IGN);" if ignore_term else "")
                + "print(json.dumps({'pid':os.getpid(),'parent':os.getppid(),'group':os.getpgrp()}),flush=True);time.sleep(60)")

    @staticmethod
    def wait_child(log):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            raw = log.read_text()
            if raw.endswith("\n"):
                return json.loads(raw.splitlines()[0])
            time.sleep(.02)
        raise AssertionError("harmless child did not report readiness")

    @staticmethod
    def finish_group(process):
        # Only the fresh group created by this test. Never the test runner's group.
        assert process.pid != os.getpgrp()
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                break
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                continue
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(.02)
        raise AssertionError("owned process group did not disappear")

    def test_converter_timeout_joins_sigterm_ignoring_child_without_killing_sibling(self):
        sibling = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"], start_new_session=True)
        try:
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "child.log"
                with target.open("xb") as log, mock.patch.object(os, "killpg", side_effect=AssertionError("parent group must not be signaled")):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        conversion.run_converter([sys.executable, "-u", "-c", self.child_source(True)], log, dict(os.environ), .5)
                child = self.wait_child(target)
                self.assertEqual(child["group"], os.getpgrp())
                self.assertFalse(Path(f"/proc/{child['pid']}").exists())
                self.assertIsNone(sibling.poll())
        finally:
            self.finish_group(sibling)

    def test_converter_cancellation_joins_child_and_restores_signal_handlers(self):
        harness = ("import convert_llama_cpu as c,os,sys;\ntry:\n"
                   " c.run_converter([sys.executable,'-u','-c',sys.argv[1]],sys.stdout,dict(os.environ),60)\n"
                   "except c.ConversionCancelled:\n sys.exit(77)\n")
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "child.log"
                with target.open("xb") as log:
                    process = subprocess.Popen([sys.executable, "-B", "-u", "-c", harness, self.child_source()],
                                               cwd=conversion.HERE, stdout=log, stderr=log, start_new_session=True)
                    try:
                        child = self.wait_child(target)
                        self.assertEqual(child["group"], process.pid)
                        process.send_signal(signum)
                        self.assertEqual(process.wait(timeout=5), 77)
                        self.assertFalse(Path(f"/proc/{child['pid']}").exists())
                    finally:
                        self.finish_group(process)
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        with tempfile.TemporaryFile() as log:
            conversion.run_converter([sys.executable, "-c", "pass"], log, dict(os.environ), 5)
        self.assertEqual(before, {sig: signal.getsignal(sig) for sig in before})

    def test_outer_subprocess_timeout_cannot_detach_converter_child_from_fixture_join(self):
        harness = ("import convert_llama_cpu as c,os,sys;"
                   "c.run_converter([sys.executable,'-u','-c',sys.argv[1]],sys.stdout,dict(os.environ),60)")
        real_popen, captured = subprocess.Popen, []
        def started(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            captured.append(process)
            return process
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "child.log"
            try:
                with target.open("xb") as log, mock.patch.object(subprocess, "Popen", side_effect=started):
                    # This is the actual subprocess.run timeout/SIGKILL behavior
                    # used by provision.run_checked, not a simulated cancellation.
                    with self.assertRaises(subprocess.TimeoutExpired):
                        subprocess.run([sys.executable, "-B", "-u", "-c", harness, self.child_source()],
                                       cwd=conversion.HERE, stdout=log, stderr=log,
                                       start_new_session=True, timeout=.5, check=True)
                child = self.wait_child(target)
                self.assertEqual(captured[0].returncode, -signal.SIGKILL)
                self.assertEqual(child["group"], captured[0].pid)
                self.assertEqual(os.getpgid(child["pid"]), captured[0].pid)
                self.finish_group(captured[0])
                self.assertFalse(Path(f"/proc/{child['pid']}").exists())
            finally:
                if captured:
                    self.finish_group(captured[0])

    def test_request_is_atomic_explicit_4b_private_only_and_legacy_unchanged(self):
        self.assertNotIn("inference_backend", WORKER.validate_request(request()))
        WORKER.validate_request(job())
        for key in ("inference_backend", "native_backend_root", "native_backend_sha256"):
            value = job(); del value[key]
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_request(value)
        for delta in ({"mode": "public_code_proposal"}, {"model_profile": WORKER.QWEN_MODEL_PROFILE},
                      {"mode": "train"}, {"native_backend_sha256": "not a digest"},
                      {"inference_backend": "peer-command"}, {"native_backend_root": "relative"}):
            with self.subTest(delta=delta), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(job(), **delta))

    def test_manifest_closed_shape_digest_scope_and_exact_proof_flags(self):
        native.validate_manifest(manifest(), WORKER.require)
        for field, replacement in (("abi_version", True), ("source_commit", "0" * 40),
                                   ("source_weights_sha256", "c" * 64), ("model_profile", WORKER.QWEN_MODEL_PROFILE)):
            value = manifest(); value[field] = replacement
            with self.assertRaises(WORKER.JobError): native.validate_manifest(value, WORKER.require)

    def test_owner_manifest_and_actual_artifact_hashes_checked_before_library_load(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = manifest()
            template = "original template"
            for field, data in (("library", b"inert-not-an-executable"), ("gguf", b"inert-not-a-model")):
                (root / value[field]["path"]).write_bytes(data)
                value[field].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            provenance = {"version": 1, "abi_version": 1, "kind": native.KIND, "source_commit": native.SOURCE,
                          "cpu": "avx2_fma_f16c", "library": value["library"], "provisionable": True,
                          "sanitizers": False, "quantization": False}
            build_raw = json.dumps(provenance).encode()
            (root / "build.json").write_bytes(build_raw)
            value["build_manifest_sha256"] = hashlib.sha256(build_raw).hexdigest()
            value["verification"]["chat_template_sha256"] = hashlib.sha256(template.encode()).hexdigest()
            raw = json.dumps(value).encode()
            (root / "backend.json").write_bytes(raw)
            selected = dict(job(), native_backend_root=str(root), native_backend_sha256=hashlib.sha256(raw).hexdigest())
            with mock.patch.object(native.ctypes, "CDLL", side_effect=AssertionError("validation must not execute library")):
                _, _, identity = native.verified_bundle(selected, WORKER, SimpleNamespace(chat_template=template))
                self.assertEqual(identity["gguf_sha256"], value["gguf"]["sha256"])
                with self.assertRaisesRegex(WORKER.JobError, "MANIFEST_DIGEST"):
                    native.verified_bundle(dict(selected, native_backend_sha256="0" * 64), WORKER,
                                           SimpleNamespace(chat_template=template))
                (root / native.LIBRARY).write_bytes(b"x" * value["library"]["bytes"])
                with self.assertRaisesRegex(WORKER.JobError, "ARTIFACT_DIGEST"):
                    native.verified_bundle(selected, WORKER, SimpleNamespace(chat_template=template))
        for field in ("tensor_values_equal", "tokenizer_equal"):
            value = manifest(); value["verification"][field] = 1
            with self.assertRaises(WORKER.JobError): native.validate_manifest(value, WORKER.require)
        for name in ("../library.so", "/library.so", "peer.so"):
            value = manifest(); value["library"]["path"] = name
            with self.assertRaises(WORKER.JobError): native.validate_manifest(value, WORKER.require)

    def test_pause_and_resume_are_not_acknowledged_until_native_has_joined(self):
        with controlled_pipe() as (session, writer, wire):
            os.write(writer, control(1)); session.check()
            probe = native.OwnerProbe(session, WORKER)
            before = wire.getvalue()
            os.write(writer, control(2, "pause") + control(3, "resume"))
            self.assertEqual(probe.callback(None), 0)
            self.assertEqual(wire.getvalue(), before)
            self.assertEqual(session.sequence, 1)
            self.assertEqual(len(probe.pending), 2)
            probe.joined()
            records = [json.loads(line) for line in wire.getvalue().splitlines()]
            self.assertEqual([row["phase"] for row in records], ["resumed", "paused", "resumed"])
            self.assertEqual(session.sequence, 3)
            self.assertEqual(probe.pending, [])

    def test_cancel_deadline_and_bad_frames_cross_abi_as_status_not_exception(self):
        for raw, reason in ((control(2, "cancel"), "JOB_CANCELLED"),
                            (control(3, "pause"), "INVALID_NATIVE_CONTROL"),
                            (control(2, id="b" * 32), "INVALID_NATIVE_CONTROL"),
                            (b'{"private-canary":true}\n', "INVALID_NATIVE_CONTROL")):
            with self.subTest(reason=reason), controlled_pipe() as (session, writer, wire):
                os.write(writer, control(1)); session.check()
                probe = native.OwnerProbe(session, WORKER)
                before = wire.getvalue()
                os.write(writer, raw)
                self.assertEqual(probe.callback(None), 1)
                self.assertEqual(wire.getvalue(), before)
                with self.assertRaisesRegex(WORKER.JobError, reason): probe.joined()
        with controlled_pipe() as (session, writer, _):
            os.write(writer, control(1)); session.check()
            probe = native.OwnerProbe(session, WORKER)
            with mock.patch.object(session, "budget", side_effect=WORKER.JobError("JOB_DEADLINE_EXCEEDED")):
                self.assertEqual(probe.callback(None), 1)
            with self.assertRaisesRegex(WORKER.JobError, "JOB_DEADLINE_EXCEEDED"): probe.joined()

    def test_partial_owner_frame_is_not_acknowledged_or_discarded(self):
        with controlled_pipe() as (session, writer, wire):
            os.write(writer, control(1)); session.check()
            probe = native.OwnerProbe(session, WORKER)
            raw = control(2, "resume")
            os.write(writer, raw[:20])
            self.assertEqual(probe.callback(None), 0)
            self.assertEqual(session.sequence, 1)
            os.write(writer, raw[20:])
            self.assertEqual(probe.callback(None), 0)
            probe.joined()
            self.assertEqual(session.sequence, 2)

    def test_full_4572_prompt_eos_raw_text_and_no_hidden_warmup(self):
        prompt = list(range(4572))
        model = mock.Mock()
        model.sample.side_effect = [77, 78, 151645]
        tokenizer = SimpleNamespace(eos_token_id=151645, decode=mock.Mock(return_value="<tool_call>raw</tool_call>"))
        session, observation = mock.Mock(), mock.Mock()
        profile = WORKER.model_profile(native.PROFILE)
        result = native.generate(model, prompt, tokenizer, profile, session, WORKER, observation)
        batches = [entry.args[0] for entry in model.decode.call_args_list]
        self.assertEqual(sum(batches[:36], []), prompt)
        self.assertEqual(batches[36:], [[77], [78]])
        self.assertTrue(all(1 <= len(batch) <= 128 for batch in batches))
        self.assertEqual(result["generation"]["stop_reason"], "eos")
        self.assertEqual(result["text"], "<tool_call>raw</tool_call>")
        tokenizer.decode.assert_called_once_with([77, 78], skip_special_tokens=False)
        observation.forward_complete.assert_called_once()
        observation.complete.assert_called_once()

    def test_no_invented_eos_or_silent_prompt_truncation(self):
        model = mock.Mock(); model.sample.return_value = 77
        tokenizer = SimpleNamespace(eos_token_id=151645, decode=mock.Mock(return_value="raw"))
        profile = WORKER.model_profile(native.PROFILE)
        result = native.generate(model, [1], tokenizer, profile, mock.Mock(), WORKER)
        self.assertEqual(result["generation"]["stop_reason"], "token_limit")
        self.assertEqual(result["generated_tokens"], 1024)
        self.assertEqual(model.sample.call_count, 1024)
        with self.assertRaisesRegex(WORKER.JobError, "NATIVE_PROMPT_BOUND"):
            native.generate(model, [1] * 12289, tokenizer, profile, mock.Mock(), WORKER)

    def test_failed_decode_does_not_sample_or_decode_text(self):
        model = mock.Mock(); model.decode.side_effect = WORKER.JobError("NATIVE_DECODE_FAILED")
        tokenizer = mock.Mock()
        with self.assertRaisesRegex(WORKER.JobError, "NATIVE_DECODE_FAILED"):
            native.generate(model, [1], tokenizer, WORKER.model_profile(native.PROFILE), mock.Mock(), WORKER)
        model.sample.assert_not_called(); tokenizer.decode.assert_not_called()

    def test_raw_output_wire_bound_stays_original(self):
        model = mock.Mock(); model.sample.return_value = 151645
        tokenizer = SimpleNamespace(eos_token_id=151645, decode=mock.Mock(return_value="漢" * 2000))
        result = native.generate(model, [1], tokenizer, WORKER.model_profile(native.PROFILE), mock.Mock(), WORKER)
        self.assertTrue(result["text_truncated"])
        self.assertLessEqual(len(json.dumps(result["text"], ensure_ascii=True).encode()), 4096)

    def test_c_abi_handle_closes_after_joined_python_error_and_only_once(self):
        library = mock.Mock()
        library.vp_llama_abi_v1.return_value = 1
        library.vp_llama_source_v1.return_value = native.SOURCE.encode()
        def allocate(_path, _capacity, _threads, _callback, _opaque, out):
            out._obj.value = 123
            return 0
        library.vp_llama_open_v1.side_effect = allocate
        owner = mock.Mock()
        owner.joined.side_effect = WORKER.JobError("JOB_CANCELLED")
        with mock.patch.object(native.ctypes, "CDLL", return_value=library), \
                self.assertRaisesRegex(WORKER.JobError, "JOB_CANCELLED"):
            native.NativeModel(Path("/native-backend"), 5600, 2, owner, WORKER.require)
        library.vp_llama_close_v1.assert_called_once()
        owner.joined.side_effect = None
        library.vp_llama_close_v1.reset_mock()
        with mock.patch.object(native.ctypes, "CDLL", return_value=library):
            model = native.NativeModel(Path("/native-backend"), 5600, 2, owner, WORKER.require)
            model.close(); model.close()
        library.vp_llama_close_v1.assert_called_once()

    def test_native_execute_rejects_implicit_sampling_before_any_library_or_model_load(self):
        bridge = mock.Mock()
        bridge.generation_policy.return_value = None
        with mock.patch.object(WORKER, "conversation_module", return_value=bridge), \
                mock.patch.object(native, "NativeModel", side_effect=AssertionError("must not load")), \
                self.assertRaisesRegex(WORKER.JobError, "NATIVE_GREEDY_POLICY_REQUIRED"):
            native.execute(job(), mock.Mock(), mock.Mock(), mock.Mock(), {}, None, None, {}, {}, {}, WORKER)

    def test_tensor_mapping_is_complete_for_exact_qwen_layers_not_arbitrary_names(self):
        self.assertEqual(conversion.tensor_name("model.layers.35.self_attn.q_norm.weight"), "blk.35.attn_q_norm.weight")
        self.assertEqual(conversion.tensor_name("model.embed_tokens.weight"), "token_embd.weight")
        for name in ("model.layers.36.mlp.up_proj.weight", "model.layers.0.injected.weight", "lm_head.weight"):
            with self.assertRaises(ValueError): conversion.tensor_name(name)

    def test_bf16_tensor_values_exact_and_norm_promotions_exact_including_signed_zero(self):
        raw = struct.pack("<4H", 0x3f80, 0x8000, 0xbf00, 0x4000)
        source = {"dtype": "BF16", "shape": [2, 2], "data_offsets": [0, 8]}
        target = SimpleNamespace(name="blk.0.attn_q.weight", shape=[2, 2], n_elements=4, tensor_type=30, data=bytearray(raw))
        conversion.compare_tensor(io.BytesIO(raw), 0, source, target, lambda: None)
        target.data[0] ^= 1
        with self.assertRaisesRegex(ValueError, "VALUE_CHANGED"):
            conversion.compare_tensor(io.BytesIO(raw), 0, source, target, lambda: None)
        source["shape"] = [4]
        target.shape, target.name, target.tensor_type = [4], "output_norm.weight", 0
        target.data = bytearray(struct.pack("<4I", *(value << 16 for value in struct.unpack("<4H", raw))))
        conversion.compare_tensor(io.BytesIO(raw), 0, source, target, lambda: None)
        # Positive zero may be numerically equal but must not replace negative zero.
        target.data[7] = 0
        with self.assertRaisesRegex(ValueError, "VALUE_CHANGED"):
            conversion.compare_tensor(io.BytesIO(raw), 0, source, target, lambda: None)

    def test_wrong_tensor_dtype_shape_and_f32_matrix_are_rejected(self):
        raw = b"\0" * 8
        source = {"dtype": "BF16", "shape": [2, 2], "data_offsets": [0, 8]}
        for dtype, shape in ((1, [2, 2]), (8, [2, 2]), (0, [2, 2]), (30, [4])):
            target = SimpleNamespace(name="blk.0.attn_q.weight", shape=shape, n_elements=4, tensor_type=dtype, data=bytearray(raw))
            with self.assertRaises(ValueError): conversion.compare_tensor(io.BytesIO(raw), 0, source, target, lambda: None)

    def test_shared_library_dependency_policy_has_no_side_loading(self):
        self.assertEqual(builder.dependencies("0 (NEEDED) Shared library: [libc.so.6]\n"), ["libc.so.6"])
        for value in ("0 (NEEDED) [libpeer.so]\n", "0 (NEEDED) [libc.so.6]\n0 (RUNPATH) [/peer]\n", ""):
            with self.assertRaises(ValueError): builder.dependencies(value)

    def test_converted_bundle_files_are_owner_private_and_not_shared_0444(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "licenses").mkdir()
            for path in (root / "backend.json", root / native.LIBRARY, root / "model.gguf", root / "licenses/MIT"):
                path.write_bytes(b"inert")
                path.chmod(0o444)
            conversion.private_bundle_modes(root)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            for path in root.rglob("*"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o400)

    def test_provision_native_selection_preserves_default_and_original_budget(self):
        provision = conversion.provision
        args = SimpleNamespace(model_profile=native.PROFILE, native_cpu_source=None, native_cpu_build=None)
        self.assertIsNone(provision.native_cpu_options(args))
        args.native_cpu_source = "/pinned/source"
        with self.assertRaises(provision.ProvisionError): provision.native_cpu_options(args)
        args.native_cpu_build = "/pinned/build"
        self.assertEqual(provision.native_cpu_options(args)["kind"], native.KIND)
        args.model_profile = WORKER.QWEN_MODEL_PROFILE
        with self.assertRaises(provision.ProvisionError): provision.native_cpu_options(args)
        args.model_profile = native.PROFILE
        args.budget_bytes = 8 * 1024 ** 3
        with mock.patch.object(provision, "run_checked", side_effect=AssertionError("budget refusal must precede execution")), \
                self.assertRaisesRegex(provision.ProvisionError, "same provisioning budget"):
            provision.provision_native_cpu(args, Path("/new"), "/runtime/python", {}, 1000, 2 * 1024 ** 3)

    def test_conversion_subwindow_caps_at_1800_without_rejecting_original_3600_deadline(self):
        provision = conversion.provision
        args = SimpleNamespace(model_profile=native.PROFILE, native_cpu_source="/pinned/source",
                               native_cpu_build="/pinned/build", budget_bytes=20 * 1024 ** 3)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def completed(command, environment, supplied_root, supplied_deadline):
                self.assertEqual(supplied_deadline, 4000)
                self.assertEqual(command[command.index("--timeout-seconds") + 1], "1800")
                self.assertEqual(command[command.index("--budget-bytes") + 1], str(10 * 1024 ** 3))
                target = root / "native-backend"
                target.mkdir(mode=0o700)
                (target / "backend.json").write_bytes(b"{}")
                (target / "backend.json").chmod(0o400)
            with mock.patch.object(provision.time, "monotonic", return_value=1000), \
                    mock.patch.object(provision, "run_checked", side_effect=completed) as invoked:
                result = provision.provision_native_cpu(args, root, "/runtime/python", {}, 4000, 10 * 1024 ** 3)
            self.assertEqual(result["backend_sha256"], hashlib.sha256(b"{}").hexdigest())
            invoked.assert_called_once()


if __name__ == "__main__":
    unittest.main()
