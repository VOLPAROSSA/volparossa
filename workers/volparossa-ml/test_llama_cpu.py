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
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import build_llama_cpu as builder
import convert_llama_cpu as conversion
import llama_cpu as native
from test_worker_protocol import WORKER, request, controlled_pipe, control, dataset
from test_qwen4b_weights import synthetic_shards
from test_conversation import conversation


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


def source_fixture(root):
    model, output = root / "source", root / "output"
    model.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    profile, _ = synthetic_shards(model)
    config = b"{}"
    (model / "config.json").write_bytes(config)
    profile.update(config={}, new_tokens=1, id="inert-source", revision="inert-revision")
    profile["files"]["config.json"] = len(config)
    profile["hashes"]["config.json"] = hashlib.sha256(config).hexdigest()
    data = root / "input.json"
    data.write_text(json.dumps(dict(conversation(), generation_policy="greedy_v1")))
    selected = WORKER.validate_request(dict(job(), model_root=str(model), output_root=str(output),
                                            dataset_path=str(data)))
    return selected, profile


class NativeSourceProvenanceTests(unittest.TestCase):
    def test_initial_measurement_is_retained_without_changing_prepared_tuple(self):
        with tempfile.TemporaryDirectory() as directory:
            selected, profile = source_fixture(Path(directory))
            measured, collector = [], {}
            original = WORKER.verify_sharded_weights

            def verify(*args, **kwargs):
                result = original(*args, **kwargs)
                measured.append(result)
                # Distinguish carrying the completed measurement from silently
                # copying the mutable expected profile after it was verified.
                profile["weights"]["sha256"] = "0" * 64
                return result

            with mock.patch.object(WORKER, "model_profile", return_value=profile), \
                    mock.patch.object(WORKER, "verify_sharded_weights", side_effect=verify):
                prepared = WORKER.prepare_files(selected, initial_source=collector)
                self.assertEqual(len(prepared), 5)
                self.assertEqual(len(measured), 1)
                self.assertEqual(collector, {"weights": measured[0]})
                self.assertIsNot(collector["weights"], measured[0])
                self.assertIsNot(collector["weights"]["files"], measured[0]["files"])
                self.assertNotEqual(collector["weights"], profile["weights"])
                self.assertEqual(collector["weights"]["sha256"], hashlib.sha256(
                    b"".join((prepared[0] / name).read_bytes() for name in profile["weight_shards"])).hexdigest())
                profile["weights"] = copy.deepcopy(measured[0])
                damaged = prepared[0] / profile["weight_shards"][-1]
                damaged.write_bytes(b"x" * damaged.stat().st_size)
                rejected = {}
                with self.assertRaisesRegex(WORKER.JobError, "MODEL_WEIGHTS_CHANGED_ON_DISK"):
                    WORKER.prepare_files(selected, initial_source=rejected)
                self.assertEqual(rejected, {}, "failed initial verification cannot create provenance")

    def test_collector_is_private_native_only_and_must_start_empty(self):
        for change, collector in (({}, []), ({}, {"weights": {}}),
                                  ({"inference_backend": None}, {}),
                                  ({"model_profile": WORKER.QWEN_MODEL_PROFILE}, {}),
                                  ({"mode": "private_infer"}, {})):
            with self.subTest(change=change, collector=collector), \
                    mock.patch.object(WORKER, "plain_path", side_effect=AssertionError("must fail before file access")), \
                    self.assertRaisesRegex(WORKER.JobError, "NATIVE_SOURCE_PROVENANCE"):
                WORKER.prepare_files(dict(job(), **change), initial_source=collector)

    def test_actual_worker_dispatch_forwards_the_measured_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            selected, profile = source_fixture(Path(directory))
            tokenizer = SimpleNamespace(pad_token_id=151643, eos_token_id=151645)
            transformers = SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=lambda *a, **k: tokenizer))
            backend = mock.Mock()
            backend.execute.return_value = "inert native dispatch"
            original = WORKER.verify_sharded_weights
            measured = []

            def verify(*args, **kwargs):
                value = original(*args, **kwargs)
                measured.append(value)
                return value

            with mock.patch.object(WORKER, "model_profile", return_value=profile), \
                    mock.patch.object(WORKER, "verify_sharded_weights", side_effect=verify), \
                    mock.patch.object(WORKER, "configure_offline"), \
                    mock.patch.object(WORKER, "load_backend", return_value=(mock.Mock(), transformers, mock.Mock(), {})), \
                    mock.patch.dict(WORKER.sys.modules, {"volparossa_llama_cpu": backend}):
                self.assertEqual(WORKER.execute_job(selected, mock.Mock()), "inert native dispatch")
            self.assertEqual(len(measured), 1)
            self.assertEqual(backend.execute.call_args.kwargs, {"initial_source_weights": measured[0]})


class HashOwnerControlTests(unittest.TestCase):
    def hash_with_control(self, action):
        """Real files and owner pipes; never a model or a resource-pressure trial."""
        block = 1024 * 1024
        raw = b"a" * block + b"b" * block + b"c" * 17
        paused, expired = threading.Event(), threading.Event()
        reads, results, errors = [], [], []
        reading = False
        with tempfile.TemporaryDirectory() as directory, controlled_pipe() as (session, writer, wire):
            path = Path(directory) / "inert-weights"
            path.write_bytes(raw)
            os.write(writer, control(1))
            session.check()
            session.request["max_seconds"] = 1
            original_start = session.started
            aggregate = hashlib.sha256(b"prefix")
            original_open, original_emit = WORKER.os.fdopen, WORKER.emit

            class ObservedReader:
                def __init__(self, descriptor, mode):
                    self.source = original_open(descriptor, mode)

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.source.__exit__(*args)

                def fileno(self):
                    return self.source.fileno()

                def read(self, size):
                    nonlocal reading
                    self_test.assertEqual(size, block)
                    reading = True
                    try:
                        data = self.source.read(size)
                    finally:
                        reading = False
                    reads.append(len(data))
                    if len(reads) == 1:
                        os.write(writer, control(2, "cancel" if action == "cancel" else "pause"))
                    return data

            self_test = self

            def emit(record):
                self.assertFalse(reading, "no ACK while a read is executing")
                original_emit(record)
                if record.get("phase") == "paused":
                    paused.set()

            def hash_file():
                try:
                    results.append(WORKER.file_hash(path, expected_size=len(raw), aggregate=aggregate,
                                                    session=session))
                except BaseException as error:
                    errors.append(error)

            with mock.patch.object(WORKER.os, "fdopen", ObservedReader), \
                    mock.patch.object(WORKER, "emit", emit), \
                    mock.patch.object(session, "elapsed", side_effect=lambda: 1001 if expired.is_set() else 0):
                thread = threading.Thread(target=hash_file)
                thread.start()
                try:
                    if action != "cancel":
                        self.assertTrue(paused.wait(3), "missing pause ACK between hash reads")
                        self.assertTrue(thread.is_alive())
                        self.assertEqual(reads, [block], "paused hashing must not read another chunk")
                        self.assertEqual(results, [])
                        if action == "resume":
                            os.write(writer, control(3, "resume"))
                        else:
                            expired.set()
                    thread.join(3)
                    self.assertFalse(thread.is_alive(), "hash worker did not finish bounded control")
                finally:
                    if thread.is_alive():
                        os.write(writer, control(session.sequence + 1, "cancel"))
                        thread.join(3)
            self.assertEqual(session.started, original_start, "pause must not reset the deadline")
            records = [json.loads(line) for line in wire.getvalue().splitlines()]
            if action == "resume":
                self.assertEqual(errors, [])
                self.assertEqual(results, [{"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}])
                self.assertEqual(aggregate.hexdigest(), hashlib.sha256(b"prefix" + raw).hexdigest())
                self.assertEqual(reads, [block, block, 17, 0])
                self.assertEqual([row["phase"] for row in records], ["resumed", "paused", "resumed"])
            else:
                self.assertEqual(results, [])
                self.assertEqual(reads, [block])
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], WORKER.JobError)
                self.assertEqual(str(errors[0]), "JOB_CANCELLED" if action == "cancel" else "JOB_DEADLINE_EXCEEDED")

    def test_hash_pause_resume_preserves_every_byte_and_aggregate(self):
        self.hash_with_control("resume")

    def test_hash_cancel_does_not_return_a_partial_digest(self):
        self.hash_with_control("cancel")

    def test_hash_pause_does_not_extend_original_deadline(self):
        self.hash_with_control("deadline")

    def test_prepare_and_shards_forward_session_and_still_reject_tampering(self):
        with tempfile.TemporaryDirectory() as directory, controlled_pipe() as (session, writer, _):
            root = Path(directory)
            model, output = root / "model", root / "output"
            model.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            profile, _ = synthetic_shards(model)
            config = b"{}"
            (model / "config.json").write_bytes(config)
            profile["config"] = {}
            profile["files"]["config.json"] = len(config)
            profile["hashes"]["config.json"] = hashlib.sha256(config).hexdigest()
            profile["max_rows"] = 4
            data = root / "input.json"
            data.write_text(json.dumps(dataset()))
            selected = dict(request(), mode="infer", model_root=str(model), output_root=str(output),
                            dataset_path=str(data))
            os.write(writer, control(1))
            hashed = []
            original = WORKER.file_hash

            def checked(path, *args, **kwargs):
                self.assertIs(kwargs.get("session"), session)
                hashed.append(path.name)
                return original(path, *args, **kwargs)

            with mock.patch.object(WORKER, "model_profile", return_value=profile), \
                    mock.patch.object(WORKER, "file_hash", side_effect=checked):
                prepared = WORKER.prepare_files(selected, session=session)
                self.assertEqual(set(hashed), set(profile["files"]))
                self.assertEqual(set(prepared[4]), set(profile["files"]))
                damaged = model / profile["weight_shards"][-1]
                damaged.write_bytes(b"x" * damaged.stat().st_size)
                with self.assertRaisesRegex(WORKER.JobError, "MODEL_WEIGHTS_CHANGED_ON_DISK"):
                    WORKER.prepare_files(selected, session=session)


class NativeCpuTests(unittest.TestCase):
    def test_effective_qwen3_rotary_dimension_matches_pinned_loader_without_weakening_required_fields(self):
        config = dict(max_position_embeddings=262144, hidden_size=2560, num_hidden_layers=36,
                      intermediate_size=9728, num_attention_heads=32, num_key_value_heads=8,
                      head_dim=128, rope_theta=5000000, rms_norm_eps=1e-6)
        values = dict(context_length=262144, embedding_length=2560, block_count=36,
                      feed_forward_length=9728)
        values.update({"attention.head_count": 32, "attention.head_count_kv": 8,
                       "attention.key_length": 128, "attention.value_length": 128,
                       "rope.freq_base": 5000000.0,
                       "attention.layer_norm_rms_epsilon": struct.unpack("<f", struct.pack("<f", 1e-6))[0]})
        def reader(fields):
            return SimpleNamespace(fields={"qwen3." + key: SimpleNamespace(contents=lambda value=value: value)
                                           for key, value in fields.items()})
        # The actual pinned converter omits the optional dimension. The loader
        # uses explicit key_length, not hidden_size / num_attention_heads (80).
        conversion.verify_model_parameters(reader(values), config)
        conversion.verify_model_parameters(reader(dict(values, **{"rope.dimension_count": 128})), config)
        for rotary in (0, 64, 80, 256, None, "128"):
            with self.subTest(rotary=rotary), self.assertRaisesRegex(ValueError, "NATIVE_GGUF_PARAMETER"):
                conversion.verify_model_parameters(reader(dict(values, **{"rope.dimension_count": rotary})), config)
        for key in values:
            missing = dict(values)
            del missing[key]
            with self.subTest(missing=key), self.assertRaisesRegex(ValueError, "NATIVE_GGUF_METADATA"):
                conversion.verify_model_parameters(reader(missing), config)
            changed = dict(values)
            changed[key] += 1
            with self.subTest(changed=key), self.assertRaisesRegex(ValueError, "NATIVE_GGUF_PARAMETER"):
                conversion.verify_model_parameters(reader(changed), config)

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
        with tempfile.TemporaryDirectory() as directory, controlled_pipe() as (session, writer, _):
            os.write(writer, control(1))
            root = Path(directory)
            value = manifest()
            template = "original template"
            for field, data in (("library", b"inert-not-an-executable"), ("gguf", b"inert-not-a-model")):
                (root / value[field]["path"]).write_bytes(data)
                value[field].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            provenance = {"version": 2, "abi_version": 1, "kind": native.KIND, "source_commit": native.SOURCE,
                          "source_tree": native.SOURCE_TREE, "source_overlay": native.loader_provenance(),
                          "loader_compile_source_verified": True, "upstream_original_unchanged": True,
                          "cpu": "avx2_fma_f16c", "library": value["library"], "provisionable": True,
                          "sanitizers": False, "quantization": False}
            build_raw = json.dumps(provenance).encode()
            (root / "build.json").write_bytes(build_raw)
            value["build_manifest_sha256"] = hashlib.sha256(build_raw).hexdigest()
            value["verification"]["chat_template_sha256"] = hashlib.sha256(template.encode()).hexdigest()
            raw = json.dumps(value).encode()
            (root / "backend.json").write_bytes(raw)
            selected = dict(job(), native_backend_root=str(root), native_backend_sha256=hashlib.sha256(raw).hexdigest())
            with mock.patch.object(native.ctypes, "CDLL", side_effect=AssertionError("validation must not execute library")), \
                    mock.patch.object(WORKER, "file_hash", wraps=WORKER.file_hash) as hashed:
                _, _, identity = native.verified_bundle(selected, WORKER, SimpleNamespace(chat_template=template), session)
                self.assertEqual(identity["gguf_sha256"], value["gguf"]["sha256"])
                self.assertEqual(identity["verification_scope"], {
                    "version": 1, "source_weights": "initial_complete_bytes_only",
                    "execution_weights": "gguf_complete_bytes_before_and_after"})
                self.assertEqual(len(hashed.call_args_list), 2)
                self.assertTrue(all(call.kwargs.get("session") is session for call in hashed.call_args_list))
                with self.assertRaisesRegex(WORKER.JobError, "MANIFEST_DIGEST"):
                    native.verified_bundle(dict(selected, native_backend_sha256="0" * 64), WORKER,
                                           SimpleNamespace(chat_template=template), session)
                (root / native.LIBRARY).write_bytes(b"x" * value["library"]["bytes"])
                with self.assertRaisesRegex(WORKER.JobError, "ARTIFACT_DIGEST"):
                    native.verified_bundle(selected, WORKER, SimpleNamespace(chat_template=template), session)
        for field in ("tensor_values_equal", "tokenizer_equal"):
            value = manifest(); value["verification"][field] = 1
            with self.assertRaises(WORKER.JobError): native.validate_manifest(value, WORKER.require)
        for name in ("../library.so", "/library.so", "peer.so"):
            value = manifest(); value["library"]["path"] = name
            with self.assertRaises(WORKER.JobError): native.validate_manifest(value, WORKER.require)

    def test_native_verify_after_checks_only_used_gguf_and_retains_initial_source(self):
        # Inert native doubles reach the actual post-execution hashing path;
        # these tests do not load a model or claim successful inference.
        with tempfile.TemporaryDirectory() as directory, controlled_pipe() as (session, writer, _):
            root = Path(directory)
            model_root = root / "weights"
            model_root.mkdir()
            profile, _ = synthetic_shards(model_root)
            profile["new_tokens"], profile["id"], profile["revision"] = 1, "test", "test"
            data = b"inert GGUF bytes"
            (root / "model.gguf").write_bytes(data)
            value = manifest()
            value["gguf"].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            bridge, model = mock.Mock(), mock.Mock()
            bridge.generation_policy.return_value = "greedy_v1"
            bridge.encode.return_value = [1]
            selected = WORKER.validate_request(job())
            os.write(writer, control(1))
            files = {}
            initial = WORKER.verify_sharded_weights(model_root, profile, files, session=session)
            original_hash = WORKER.file_hash
            hashed = []

            def checked(path, *args, **kwargs):
                model.close.assert_called_once()
                self.assertIs(kwargs.get("session"), session)
                hashed.append(path.name)
                return original_hash(path, *args, **kwargs)

            with mock.patch.object(WORKER, "model_profile", return_value=profile), \
                    mock.patch.object(WORKER, "conversation_module", return_value=bridge), \
                    mock.patch.object(WORKER, "file_hash", side_effect=checked), \
                    mock.patch.object(WORKER, "finish_result", side_effect=WORKER.JobError("POST_HASH_REACHED")), \
                    mock.patch.object(native, "verified_bundle", return_value=(root, value, {})) as bundle, \
                    mock.patch.object(native, "NativeModel", return_value=model), \
                    mock.patch.object(native, "generate", return_value={}):
                with self.assertRaisesRegex(WORKER.JobError, "POST_HASH_REACHED"):
                    native.execute(selected, session, mock.Mock(), mock.Mock(), {}, model_root, root,
                                   {}, {}, files, WORKER, initial_source_weights=initial)
                self.assertIs(bundle.call_args.args[-1], session)
                self.assertEqual(hashed, ["model.gguf"])
                result = WORKER.finish_result.call_args.args[0]
                self.assertEqual(result["model"]["weights"], initial)
                self.assertIsNot(result["model"]["weights"], initial)
                self.assertIsNot(result["model"]["weights"]["files"], initial["files"])
                # Changing now-unused source bytes does not change the measured
                # initial provenance or silently claim an end-of-run source check.
                for name in profile["weight_shards"]:
                    (model_root / name).write_bytes(b"x" * profile["files"][name])
                model.reset_mock()
                hashed.clear()
                with self.assertRaisesRegex(WORKER.JobError, "POST_HASH_REACHED"):
                    native.execute(selected, session, mock.Mock(), mock.Mock(), {}, model_root, root,
                                   {}, {}, files, WORKER, initial_source_weights=initial)
                self.assertEqual(hashed, ["model.gguf"])
                self.assertEqual(WORKER.finish_result.call_args.args[0]["model"]["weights"], initial)
                model.reset_mock()
                (root / "model.gguf").write_bytes(b"x" * len(data))
                with self.assertRaisesRegex(WORKER.JobError, "NATIVE_GGUF_CHANGED"):
                    native.execute(selected, session, mock.Mock(), mock.Mock(), {}, model_root, root,
                                   {}, {}, files, WORKER, initial_source_weights=initial)
                # The remaining post-GGUF check still services the same actual
                # owner pipe after the native handle closes; cancel cannot emit
                # a successful report or reuse the earlier source measurement
                # as a substitute for finishing execution-weight verification.
                model.reset_mock()
                (root / "model.gguf").write_bytes(data)
                completed_before_cancel = WORKER.finish_result.call_count
                model.close.side_effect = lambda: os.write(writer, control(2, "cancel"))
                with self.assertRaisesRegex(WORKER.JobError, "JOB_CANCELLED"):
                    native.execute(selected, session, mock.Mock(), mock.Mock(), {}, model_root, root,
                                   {}, {}, files, WORKER, initial_source_weights=initial)
                self.assertEqual(WORKER.finish_result.call_count, completed_before_cancel)

    def test_native_rejects_missing_or_changed_initial_provenance_before_loading(self):
        profile = WORKER.model_profile(native.PROFILE)
        files = {name: {"bytes": size, "sha256": profile["hashes"][name]}
                 for name, size in profile["files"].items()}
        wrong = copy.deepcopy(profile["weights"])
        wrong["sha256"] = "0" * 64
        for initial, selected_files in ((None, files), ({}, files), (wrong, files), (profile["weights"], {})):
            with self.subTest(initial=initial), \
                    mock.patch.object(native, "verified_bundle", side_effect=AssertionError("must not load")), \
                    mock.patch.object(WORKER, "conversation_module", return_value=SimpleNamespace(generation_policy=lambda *a: "greedy_v1")), \
                    self.assertRaisesRegex(WORKER.JobError, "NATIVE_SOURCE_PROVENANCE"):
                native.execute(job(), mock.Mock(), mock.Mock(), mock.Mock(), {}, None, None,
                               {}, {}, selected_files, WORKER, initial_source_weights=initial)

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
        library.vp_llama_open_stage_v1.return_value = 8
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

    def test_abi_requires_closed_open_stage_even_when_existing_abi_version_matches(self):
        codes = {1: "NATIVE_OPEN_INVALID_ARGUMENT", 2: "NATIVE_CPU_UNSUPPORTED",
                 3: "NATIVE_BACKEND_INITIALIZATION_FAILED", 4: "NATIVE_MODEL_INITIALIZATION_FAILED",
                 5: "NATIVE_VOCABULARY_MISMATCH", 6: "NATIVE_CONTEXT_INITIALIZATION_FAILED",
                 7: "NATIVE_SAMPLER_INITIALIZATION_FAILED", 8: "NATIVE_MODEL_LOAD_FAILED"}
        for stage, expected in [*codes.items(), (0, "NATIVE_OPEN_DIAGNOSTIC_INVALID"),
                                (9, "NATIVE_OPEN_DIAGNOSTIC_INVALID"),
                                (True, "NATIVE_OPEN_DIAGNOSTIC_INVALID")]:
            with self.subTest(stage=stage):
                library = mock.Mock()
                library.vp_llama_abi_v1.return_value = 1
                library.vp_llama_source_v1.return_value = native.SOURCE.encode()
                library.vp_llama_open_stage_v1.return_value = stage
                library.vp_llama_open_v1.return_value = 3
                with mock.patch.object(native.ctypes, "CDLL", return_value=library), \
                        self.assertRaisesRegex(WORKER.JobError, expected):
                    native.NativeModel(Path("/inert"), 16, 2, mock.Mock(), WORKER.require)
                library.vp_llama_decode_v1.assert_not_called()
                library.vp_llama_close_v1.assert_not_called()
        # An older ABI1 library cannot silently use the new patched provenance.
        library = SimpleNamespace(vp_llama_abi_v1=mock.Mock(return_value=1),
                                  vp_llama_source_v1=mock.Mock(return_value=native.SOURCE.encode()))
        with mock.patch.object(native.ctypes, "CDLL", return_value=library), \
                self.assertRaisesRegex(WORKER.JobError, "NATIVE_ABI_MISMATCH"):
            native.NativeModel(Path("/inert"), 16, 2, mock.Mock(), WORKER.require)

    def test_success_handle_with_wrong_open_stage_is_rejected_and_closed(self):
        library = mock.Mock()
        library.vp_llama_abi_v1.return_value = 1
        library.vp_llama_source_v1.return_value = native.SOURCE.encode()
        library.vp_llama_open_stage_v1.return_value = 4
        def allocate(_path, _capacity, _threads, _callback, _opaque, out):
            out._obj.value = 123
            return 0
        library.vp_llama_open_v1.side_effect = allocate
        with mock.patch.object(native.ctypes, "CDLL", return_value=library), \
                self.assertRaisesRegex(WORKER.JobError, "NATIVE_OPEN_DIAGNOSTIC_INVALID"):
            native.NativeModel(Path("/inert"), 16, 2, mock.Mock(), WORKER.require)
        library.vp_llama_close_v1.assert_called_once()

    def test_effective_loader_provenance_rejects_old_or_ambiguous_builds(self):
        value = dict(version=2, source_commit=native.SOURCE, source_tree=native.SOURCE_TREE,
                     source_overlay=native.loader_provenance(), loader_compile_source_verified=True,
                     upstream_original_unchanged=True)
        native.validate_build_provenance(value, WORKER.require)
        for key, bad in (("version", 1), ("source_tree", "0" * 40), ("source_commit", "0" * 40),
                         ("loader_compile_source_verified", 1), ("upstream_original_unchanged", False)):
            with self.subTest(key=key), self.assertRaisesRegex(WORKER.JobError, "NATIVE_BUILD_PATCH_BINDING"):
                native.validate_build_provenance(dict(value, **{key: bad}), WORKER.require)
        for key, bad in (("validation_execution_threads", True), ("complete_tensor_validation", 1),
                         ("owner_poll_between_tensors", 1), ("effective_sha256", native.LOADER_ORIGINAL_SHA),
                         ("original_sha256", "0" * 64), ("patch_sha256", "0" * 64),
                         ("compiled_source", "src/llama-model-loader.cpp")):
            changed = copy.deepcopy(value)
            changed["source_overlay"][key] = bad
            with self.subTest(key=key), self.assertRaisesRegex(WORKER.JobError, "NATIVE_BUILD_PATCH_BINDING"):
                native.validate_build_provenance(changed, WORKER.require)

    def test_compilation_must_use_exact_staged_loader_not_clean_upstream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build").mkdir()
            loader = root / "llama-model-loader.cpp"
            loader.write_bytes(b"inert-source")
            commands = root / "build/compile_commands.json"
            commands.write_text(json.dumps([{"file": str(loader)}]))
            with mock.patch.object(native, "LOADER_EFFECTIVE_SHA", hashlib.sha256(b"inert-source").hexdigest()):
                builder.verify_loader_compilation(root, loader)
                for rows in ([{"file": "/unmodified/llama-model-loader.cpp"}], [],
                             [{"file": str(loader)}, {"file": str(loader)}]):
                    commands.write_text(json.dumps(rows))
                    with self.assertRaises(ValueError):
                        builder.verify_loader_compilation(root, loader)
                commands.write_text(json.dumps([{"file": str(loader)}]))
                loader.write_bytes(b"changed-source")
                with self.assertRaisesRegex(ValueError, "NATIVE_COMPILED_LOADER"):
                    builder.verify_loader_compilation(root, loader)

    def test_patch_identity_and_fresh_staging_never_overwrite_existing_source(self):
        patch = builder.HERE / "native-cpu/bounded-tensor-validation.patch"
        self.assertEqual(builder.digest(patch)["sha256"], native.LOADER_PATCH_SHA)
        text = patch.read_text()
        self.assertEqual(text.count("+                validation_result.emplace_back(std::async(std::launch::deferred,"), 1)
        self.assertEqual(text.count("+                    validation_result.emplace_back(std::async(std::launch::deferred,"), 1)
        self.assertNotIn("-                    return std::make_pair", text)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(builder, "patched_loader", return_value=b"inert-source"):
                loader = builder.stage_loader(root / "original", root)
                self.assertEqual(loader.read_bytes(), b"inert-source")
                self.assertEqual(stat.S_IMODE(loader.stat().st_mode), 0o444)
                self.assertEqual(stat.S_IMODE(loader.parent.stat().st_mode), 0o700)
                with self.assertRaises(FileExistsError):
                    builder.stage_loader(root / "original", root)
                self.assertEqual(loader.read_bytes(), b"inert-source")

    def test_native_execute_rejects_implicit_sampling_before_any_library_or_model_load(self):
        bridge = mock.Mock()
        bridge.generation_policy.return_value = None
        with mock.patch.object(WORKER, "conversation_module", return_value=bridge), \
                mock.patch.object(native, "NativeModel", side_effect=AssertionError("must not load")), \
                self.assertRaisesRegex(WORKER.JobError, "NATIVE_GREEDY_POLICY_REQUIRED"):
            native.execute(job(), mock.Mock(), mock.Mock(), mock.Mock(), {}, None, None, {}, {}, {}, WORKER,
                           initial_source_weights=None)

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
