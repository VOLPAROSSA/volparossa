# SPDX-License-Identifier: GPL-3.0-only
"""Opt-in, core-owned BF16 CPU inference; no HTTP, downloads, tools or training.

ctypes sees only our scalar/opaque ABI. Upstream structs stay inside the compiled
adapter. Artifact hashes are checked against the owner's separately supplied
backend.json digest before loading any native code. Conversion metadata is not
peer executable authority. The supervisor still supplies read-only mounts and
hard limits, and confirms process cleanup independently.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import re
import stat
import threading

KIND = "llama_cpp_bf16_v1"
SOURCE = "7fe450e19305b828c199d602c23a8337aaa1f03b"
SOURCE_TREE = "fd570ef54b10ec5fecb739e7e04c8ce44a6f415a"
LOADER_ORIGINAL_SHA = "efdb5f273bd1ab77301f2cadea1a5a804bafb28040aca033e45605a97a450242"
LOADER_EFFECTIVE_SHA = "fcd26ea4ae21ea04954b275287c41a35e383015b736bbbe2e68f2ab5f6d095f9"
LOADER_PATCH_SHA = "388fff7d5d9ca812abfeb27fddd1629144b7de6284e4bf685fbc8c147891e8c1"
PROFILE = "qwen3-4b-instruct-2507-v1"
LIBRARY = "libvolparossa_llama_cpu.so"
WEIGHTS_SHA = "79f6bbc34572c0063d12022f0f93074d90bbcd5dfd82134423bf892f7f8df3cf"
WEIGHTS_BYTES = 8044982000
HEX = re.compile(r"[0-9a-f]{64}\Z")
ABORT = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p)


def loader_provenance():
    return dict(kind="serial_complete_tensor_validation_v1", original_path="src/llama-model-loader.cpp",
                original_sha256=LOADER_ORIGINAL_SHA, effective_sha256=LOADER_EFFECTIVE_SHA,
                patch_path="native-cpu/bounded-tensor-validation.patch", patch_sha256=LOADER_PATCH_SHA,
                compiled_source="loader-overlay/llama-model-loader.cpp", validation_execution_threads=1,
                complete_tensor_validation=True, owner_poll_between_tensors=True)


def validate_build_provenance(value, require):
    # Build manifest v2 distinguishes the effective loader from clean upstream.
    # ABI v1 is retained; old unpatched build manifests are not silently adopted.
    overlay = value.get("source_overlay") if type(value) is dict else None
    require(type(value) is dict and type(value.get("version")) is int and value["version"] == 2
            and value.get("source_commit") == SOURCE and value.get("source_tree") == SOURCE_TREE
            and type(overlay) is dict and overlay == loader_provenance()
            and type(overlay["validation_execution_threads"]) is int
            and overlay["complete_tensor_validation"] is True and overlay["owner_poll_between_tensors"] is True
            and value.get("loader_compile_source_verified") is True
            and value.get("upstream_original_unchanged") is True, "NATIVE_BUILD_PATCH_BINDING")


def validate_manifest(value, require):
    require(type(value) is dict and value.keys() == {"version", "kind", "abi_version", "source_commit",
            "model_profile", "source_weights_sha256", "source_weights_bytes", "library", "gguf",
            "verification", "build_manifest_sha256"}, "NATIVE_MANIFEST_FIELDS")
    require(type(value["version"]) is int and value["version"] == 1
            and type(value["abi_version"]) is int and value["abi_version"] == 1
            and value["kind"] == KIND and value["source_commit"] == SOURCE
            and value["model_profile"] == PROFILE and value["source_weights_sha256"] == WEIGHTS_SHA
            and type(value["source_weights_bytes"]) is int and value["source_weights_bytes"] == WEIGHTS_BYTES,
            "NATIVE_MANIFEST_BINDING")
    for field, name, maximum in (("library", LIBRARY, 128 * 1024 * 1024),
                                  ("gguf", "model.gguf", 9 * 1024 ** 3)):
        item = value[field]
        require(type(item) is dict and item.keys() == {"path", "sha256", "bytes"}
                and item["path"] == name and type(item["sha256"]) is str and HEX.fullmatch(item["sha256"])
                and type(item["bytes"]) is int and 0 < item["bytes"] <= maximum,
                "NATIVE_ARTIFACT_BINDING")
    checked = value["verification"]
    require(type(checked) is dict and checked.keys() == {"tensor_count", "tensor_values_equal", "tokenizer_equal",
                                                       "chat_template_sha256"}
            and type(checked["tensor_count"]) is int and checked["tensor_count"] == 398
            and checked["tensor_values_equal"] is True and checked["tokenizer_equal"] is True
            and type(checked["chat_template_sha256"]) is str and HEX.fullmatch(checked["chat_template_sha256"])
            and type(value["build_manifest_sha256"]) is str and HEX.fullmatch(value["build_manifest_sha256"]),
            "NATIVE_CONVERSION_BINDING")
    return value


def verified_bundle(request, worker, tokenizer, session):
    require = worker.require
    require(request.get("inference_backend") == KIND and request.get("model_profile") == PROFILE
            and request["mode"] == "private_conversation", "NATIVE_BACKEND_SCOPE")
    root, meta = worker.plain_path(request["native_backend_root"], True)
    require(not stat.S_IMODE(meta.st_mode) & 0o022, "NATIVE_BACKEND_WRITABLE")
    expected = request["native_backend_sha256"]
    require(type(expected) is str and HEX.fullmatch(expected), "NATIVE_MANIFEST_DIGEST")
    raw = worker.read_bounded(root / "backend.json", 16384)
    require(hashlib.sha256(raw).hexdigest() == expected, "NATIVE_MANIFEST_DIGEST")
    value = validate_manifest(worker.parse_json(raw), require)
    for field in ("library", "gguf"):
        item = value[field]
        require(worker.file_hash(root / item["path"], expected_size=item["bytes"], session=session)["sha256"] == item["sha256"],
                "NATIVE_ARTIFACT_DIGEST")
    build = worker.read_bounded(root / "build.json", 65536)
    require(hashlib.sha256(build).hexdigest() == value["build_manifest_sha256"], "NATIVE_BUILD_DIGEST")
    provenance = worker.parse_json(build)
    validate_build_provenance(provenance, require)
    require(type(provenance) is dict
            and provenance.get("kind") == KIND and provenance.get("source_commit") == SOURCE
            and provenance.get("abi_version") == 1 and provenance.get("cpu") == "avx2_fma_f16c"
            and provenance.get("provisionable") is True and provenance.get("sanitizers") is False
            and provenance.get("quantization") is False and provenance.get("library") == value["library"],
            "NATIVE_BUILD_BINDING")
    require(type(tokenizer.chat_template) is str and hashlib.sha256(tokenizer.chat_template.encode()).hexdigest()
            == value["verification"]["chat_template_sha256"], "NATIVE_TEMPLATE_BINDING")
    identity = dict(kind=KIND, abi_version=1, source_commit=SOURCE, manifest_sha256=expected,
                    library_sha256=value["library"]["sha256"], gguf_sha256=value["gguf"]["sha256"],
                    gguf_bytes=value["gguf"]["bytes"], source_weights_sha256=WEIGHTS_SHA)
    return root, value, identity


class OwnerProbe:
    """No exception/ACK crosses C. Pause waits for the current bounded decode.

    Frames retain their exact bytes/order until the native operation has joined.
    Then Session.check processes them and acknowledges stopped execution normally.
    Cancellation and deadline can abort native work; that handle is never resumed.
    """
    def __init__(self, session, worker):
        self.session, self.worker = session, worker
        self.pending = []
        self.error = None
        self.lock = threading.Lock()
        self.expected = session.sequence
        self.callback = ABORT(self.poll)

    def poll(self, _opaque=None):
        with self.lock:
            if self.error is not None:
                return 1
            try:
                self.session.budget()
                frames = self.session.frames
                while frames is not None:
                    raw = frames.control(0)
                    if raw is None:
                        break
                    value = self.worker.parse_json(raw)
                    self.worker.require(type(value) is dict and value.keys() == {"version", "id", "sequence", "action"}
                        and type(value["version"]) is int and value["version"] == 1
                        and value["id"] == self.session.request["id"]
                        and type(value["sequence"]) is int and value["sequence"] == self.expected + 1
                    and value["sequence"] <= self.worker.MAX_CONTROLS
                        and type(value["action"]) is str
                        and value["action"] in ("pause", "resume", "cancel"), "INVALID_NATIVE_CONTROL")
                    self.expected = value["sequence"]
                    self.worker.require(value["action"] != "cancel", "JOB_CANCELLED")
                    self.pending.append(raw)
                    self.session.budget()
            except BaseException as error:
                # BaseException too: ctypes must never swallow a Python exception
                # and accidentally return an unspecified value to native code.
                self.error = (error if isinstance(error, self.worker.JobError)
                              else self.worker.JobError("NATIVE_OWNER_CONTROL_FAILED"))
                return 1
            return 0

    def joined(self):
        if self.error is not None:
            raise self.error
        if self.pending:
            self.session.frames.pending[:0] = b"".join(self.pending)
            self.pending.clear()
        self.session.check()
        self.expected = self.session.sequence


class NativeModel:
    def __init__(self, root, capacity, threads, probe, require):
        self.handle = ctypes.c_void_p()
        self.require, self.probe = require, probe
        # The caller checked owner-authorized digest before this executable load.
        self.lib = ctypes.CDLL(str(root / LIBRARY), mode=0)
        signatures = {
            "vp_llama_abi_v1": (ctypes.c_uint32, []),
            "vp_llama_source_v1": (ctypes.c_char_p, []),
            "vp_llama_open_stage_v1": (ctypes.c_uint32, []),
            "vp_llama_open_v1": (ctypes.c_int32, [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
                ABORT, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]),
            "vp_llama_decode_v1": (ctypes.c_int32, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32), ctypes.c_uint32]),
            "vp_llama_sample_v1": (ctypes.c_int32, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32)]),
            "vp_llama_close_v1": (None, [ctypes.c_void_p]),
        }
        for name, (result, arguments) in signatures.items():
            try:
                function = getattr(self.lib, name)
            except AttributeError as error:
                require(False, "NATIVE_ABI_MISMATCH")
                raise error  # require always raises; no incomplete ABI can proceed.
            function.restype, function.argtypes = result, arguments
        require(self.lib.vp_llama_abi_v1() == 1 and self.lib.vp_llama_source_v1() == SOURCE.encode(),
                "NATIVE_ABI_MISMATCH")
        try:
            status = self.lib.vp_llama_open_v1(str(root / "model.gguf").encode(), capacity, threads,
                                             probe.callback, None, ctypes.byref(self.handle))
            probe.joined()
            stage = self.lib.vp_llama_open_stage_v1()
            codes = {1: "NATIVE_OPEN_INVALID_ARGUMENT", 2: "NATIVE_CPU_UNSUPPORTED",
                     3: "NATIVE_BACKEND_INITIALIZATION_FAILED", 4: "NATIVE_MODEL_INITIALIZATION_FAILED",
                     5: "NATIVE_VOCABULARY_MISMATCH", 6: "NATIVE_CONTEXT_INITIALIZATION_FAILED",
                     7: "NATIVE_SAMPLER_INITIALIZATION_FAILED", 8: "NATIVE_MODEL_LOAD_FAILED"}
            require(type(stage) is int and stage in codes, "NATIVE_OPEN_DIAGNOSTIC_INVALID")
            require(status == 0 and self.handle.value is not None, codes[stage])
            require(stage == 8, "NATIVE_OPEN_DIAGNOSTIC_INVALID")
        except BaseException:
            self.close()
            raise

    def decode(self, tokens):
        self.require(type(tokens) is list and 1 <= len(tokens) <= 128
                     and all(type(token) is int and 0 <= token < 151936 for token in tokens), "NATIVE_TOKEN_BOUND")
        values = (ctypes.c_int32 * len(tokens))(*tokens)
        status = self.lib.vp_llama_decode_v1(self.handle, values, len(tokens))
        self.probe.joined()
        self.require(status == 0, "NATIVE_DECODE_FAILED")

    def sample(self):
        token = ctypes.c_int32(-1)
        status = self.lib.vp_llama_sample_v1(self.handle, ctypes.byref(token))
        self.probe.joined()
        self.require(status == 0 and 0 <= token.value < 151936, "NATIVE_SAMPLE_FAILED")
        return token.value

    def close(self):
        if self.handle.value is not None:
            self.lib.vp_llama_close_v1(self.handle)
            self.handle = ctypes.c_void_p()


def generate(model, prompt, tokenizer, profile, session, worker, observation=None):
    worker.require(type(prompt) is list and 1 <= len(prompt) <= profile["prompt_tokens"]
                   and all(type(token) is int and 0 <= token < 151936 for token in prompt), "NATIVE_PROMPT_BOUND")
    if observation is not None:
        observation.forward_begin(None, None)
    # This is the complete original HF-rendered prompt in bounded prefill batches,
    # not truncation, sliding context, a second prompt or a hidden warmup.
    for start in range(0, len(prompt), 128):
        session.check()
        model.decode(prompt[start:start + 128])
    if observation is not None:
        observation.forward_complete(None, None, None)
    generated = []
    while len(generated) < profile["new_tokens"]:
        session.check()
        token = model.sample()
        generated.append(token)
        if observation is not None:
            observation.tokens(len(generated))
        if token == tokenizer.eos_token_id:
            break
        if len(generated) < profile["new_tokens"]:
            model.decode([token])
    metadata = worker.generation_metadata(generated, tokenizer.eos_token_id, PROFILE)
    visible = generated[:-1] if metadata["stop_reason"] == "eos" else generated
    raw = tokenizer.decode(visible, skip_special_tokens=False)
    text = raw[:profile["wire_bytes"]]
    while len(json.dumps(text, ensure_ascii=True).encode("ascii")) > profile["wire_bytes"]:
        text = text[:-1]
    if observation is not None:
        observation.complete()
    return {"sample_index": 0, "text": text, "generated_tokens": len(generated),
            "text_truncated": text != raw, "generation": metadata}


def execute(request, session, tokenizer, torch, versions, model_root, output_root,
            dataset, data_identity, model_files, worker):
    worker.require(worker.conversation_module().generation_policy(dataset, PROFILE) == "greedy_v1",
                   "NATIVE_GREEDY_POLICY_REQUIRED")
    profile = worker.model_profile(PROFILE)
    root, manifest, identity = verified_bundle(request, worker, tokenizer, session)
    session.private_progress("prompt_encode", "begin")
    prompt = worker.conversation_module().encode(tokenizer, dataset, profile)
    session.private_progress("prompt_encode", "complete")
    session.check()
    probe = OwnerProbe(session, worker)
    session.private_progress("model_load", "begin")
    model = NativeModel(root, len(prompt) + profile["new_tokens"], request["threads"], probe, worker.require)
    try:
        session.private_progress("model_load", "complete")
        session.progress("baseline")
        session.private_progress("generation", "begin")
        observation = (worker.PrivateGenerationObservation(session, torch, len(prompt))
                       if request.get("private_generation_diagnostics") is True else None)
        output = generate(model, prompt, tokenizer, profile, session, worker, observation)
        session.private_progress("generation", "complete")
    finally:
        model.close()
    session.private_progress("verify_after", "begin")
    weight_identity = worker.verify_sharded_weights(model_root, profile, session=session)
    worker.require(worker.file_hash(root / "model.gguf", expected_size=manifest["gguf"]["bytes"], session=session)["sha256"]
                   == manifest["gguf"]["sha256"], "NATIVE_GGUF_CHANGED")
    session.private_progress("verify_after", "complete")
    result = {"version": 1, "id": request["id"], "kind": "result", "status": "ok", "mode": request["mode"],
              "backend_versions": versions, "device": "cpu", "threads": request["threads"],
              "model": {"id": profile["id"], "revision": profile["revision"], "files": model_files,
                        "weights": weight_identity}, "dataset": data_identity, "outputs": [output],
              "updates_completed": 0, "artifacts": [], "model_weights_loaded": True,
              "private_data_supported": True, "distributed_execution_claimed": False,
              "private_training_claimed": False, "better_answers_claimed": False, "network_policy_changed": False,
              "conversation": worker.conversation_module().decode(dataset, output, PROFILE, request["id"]),
              "prompt_tokens": len(prompt), "conversation_limits": worker.conversation_module().capabilities(PROFILE, profile),
              "generation_policy": "greedy_v1", "model_parameter_dtype": "bf16_with_exact_f32_norms",
              "model_attention_backend": "llama_cpp_cpu", "inference_backend": identity}
    session.private_progress("result", "begin")
    result = worker.finish_result(result, output_root, session)
    session.private_progress("result", "complete")
    return result
