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
CPU_ORIGINAL_PATH = "ggml/src/ggml-cpu/arch/x86/quants.c"
CPU_ORIGINAL_SHA = "3c489fdc77e3ab484a5f188bff9c60c0e9483c951ed65c1a562a04c249d5628e"
CPU_EFFECTIVE_SHA = "b9a63f032ad048a688357194fa535d852959ffee0942c93d4b8fb9544febf6d2"
CPU_PATCH_SHA = "563a178667eeac17e7072c343d1d21a3f641d78c284acbeb2633db26e1c36369"
PROFILE = "qwen3-4b-instruct-2507-v1"
LIBRARY = "libvolparossa_llama_cpu.so"
WEIGHTS_SHA = "79f6bbc34572c0063d12022f0f93074d90bbcd5dfd82134423bf892f7f8df3cf"
WEIGHTS_BYTES = 8044982000
HEX = re.compile(r"[0-9a-f]{64}\Z")
ABORT = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p)
OUTPUT_CONSTRAINT = "qwen_tagged_tool_json_v1"
NATIVE_SESSION = "connection_bound_v1"


def validate_constraints(value, legacy_version, require, version_error="NATIVE_OUTPUT_CONSTRAINT_VERSION"):
    """Versioned capability, not a request to enable it or executable grammar."""
    version = value.get("version") if type(value) is dict else None
    require(type(version) is int and version in (legacy_version, legacy_version + 1, legacy_version + 2),
            version_error)
    if version == legacy_version + 2:
        require(value.get("native_sessions") == [NATIVE_SESSION], "NATIVE_SESSION_BINDING")
    else:
        require("native_sessions" not in value, "NATIVE_SESSION_BINDING")
    if version == legacy_version:
        require("output_constraints" not in value, "NATIVE_OUTPUT_CONSTRAINT_BINDING")
        return []
    require(value.get("output_constraints") == [OUTPUT_CONSTRAINT], "NATIVE_OUTPUT_CONSTRAINT_BINDING")
    return [OUTPUT_CONSTRAINT]


def verification_scope():
    return dict(version=1, source_weights="initial_complete_bytes_only",
                execution_weights="gguf_complete_bytes_before_and_after")


def loader_provenance():
    return dict(kind="serial_complete_tensor_validation_v1", original_path="src/llama-model-loader.cpp",
                original_sha256=LOADER_ORIGINAL_SHA, effective_sha256=LOADER_EFFECTIVE_SHA,
                patch_path="native-cpu/bounded-tensor-validation.patch", patch_sha256=LOADER_PATCH_SHA,
                compiled_source="loader-overlay/llama-model-loader.cpp", validation_execution_threads=1,
                complete_tensor_validation=True, owner_poll_between_tensors=True)


def validate_build_provenance(value, require):
    # Build v3 adds an explicit, optional generation extension to the same ABI.
    # Historical patched build v2 retains its exact absent-capability shape.
    overlay = value.get("source_overlay") if type(value) is dict else None
    validate_constraints(value, 2, require, "NATIVE_BUILD_PATCH_BINDING")
    require(type(value) is dict
            and value.get("source_commit") == SOURCE and value.get("source_tree") == SOURCE_TREE
            and type(overlay) is dict and overlay == loader_provenance()
            and type(overlay["validation_execution_threads"]) is int
            and overlay["complete_tensor_validation"] is True and overlay["owner_poll_between_tensors"] is True
            and value.get("loader_compile_source_verified") is True
            and value.get("upstream_original_unchanged") is True, "NATIVE_BUILD_PATCH_BINDING")
    validate_cpu_provenance(value, require)


def cpu_provenance():
    return dict(kind="q1_avx2_aligned_load_v1", original_path=CPU_ORIGINAL_PATH,
                original_sha256=CPU_ORIGINAL_SHA, effective_sha256=CPU_EFFECTIVE_SHA,
                patch_path="native-cpu/q1-aligned-load.patch", patch_sha256=CPU_PATCH_SHA,
                compiled_source="cpu-overlay/quants.c")


def validate_cpu_provenance(value, require):
    # An additive source correction, not a new model/generation capability.
    # Historical builds omit both fields and retain their unresolved Q1 finding.
    present = {key for key in ("cpu_source_overlay", "cpu_compile_source_verified") if key in value}
    if not present:
        return
    require(present == {"cpu_source_overlay", "cpu_compile_source_verified"}
            and type(value.get("version")) is int and value["version"] == 4
            and type(value.get("cpu_source_overlay")) is dict
            and value["cpu_source_overlay"] == cpu_provenance()
            and value.get("cpu_compile_source_verified") is True, "NATIVE_CPU_PATCH_BINDING")


def validate_manifest(value, require):
    constraints = validate_constraints(value, 1, require)
    fields = {"version", "kind", "abi_version", "source_commit",
            "model_profile", "source_weights_sha256", "source_weights_bytes", "library", "gguf",
            "verification", "build_manifest_sha256"}
    require(value.keys() == fields | ({"output_constraints"} if constraints else set())
            | ({"native_sessions"} if value["version"] == 3 else set()), "NATIVE_MANIFEST_FIELDS")
    require(type(value["abi_version"]) is int and value["abi_version"] == 1
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
    require(provenance["version"] == value["version"] + 1
            and provenance.get("output_constraints") == value.get("output_constraints")
            and provenance.get("native_sessions") == value.get("native_sessions"),
            "NATIVE_OUTPUT_CONSTRAINT_BINDING")
    if "native_session" in request:
        require(value.get("native_sessions") == [NATIVE_SESSION], "NATIVE_SESSION_UNSUPPORTED")
    if "output_constraint" in request:
        require(request["output_constraint"] == OUTPUT_CONSTRAINT
                and value.get("output_constraints") == [OUTPUT_CONSTRAINT],
                "NATIVE_OUTPUT_CONSTRAINT_UNSUPPORTED")
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
                    gguf_bytes=value["gguf"]["bytes"], source_weights_sha256=WEIGHTS_SHA,
                    verification_scope=verification_scope())
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
    def __init__(self, root, capacity, threads, probe, require, *, output_constraints=None,
                 output_constraint=None, output_constraint_tools=None, native_session=False,
                 context_capacity=False):
        self.handle = ctypes.c_void_p()
        self.require, self.probe = require, probe
        self.capacity, self.context_capacity = capacity, context_capacity
        require(type(context_capacity) is bool and (not context_capacity or native_session),
                "NATIVE_SESSION_ABI_MISMATCH")
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
        if output_constraints is not None:
            require(output_constraints == [OUTPUT_CONSTRAINT], "NATIVE_OUTPUT_CONSTRAINT_BINDING")
            for name, result, arguments in (
                    ("vp_llama_output_constraint_abi_v1", ctypes.c_uint32, []),
                    ("vp_llama_set_output_constraint_v1", ctypes.c_int32,
                     [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32])):
                require(hasattr(self.lib, name), "NATIVE_OUTPUT_CONSTRAINT_ABI_MISMATCH")
                function = getattr(self.lib, name)
                function.restype, function.argtypes = result, arguments
            extension = self.lib.vp_llama_output_constraint_abi_v1()
            require(type(extension) is int and extension == 1,
                    "NATIVE_OUTPUT_CONSTRAINT_ABI_MISMATCH")
        if output_constraint is not None or output_constraint_tools is not None:
            require(output_constraints == [OUTPUT_CONSTRAINT] and output_constraint == OUTPUT_CONSTRAINT
                    and type(output_constraint_tools) is list and 1 <= len(output_constraint_tools) <= 32
                    and output_constraint_tools == [f"vp_{index}" for index in range(len(output_constraint_tools))],
                    "NATIVE_OUTPUT_CONSTRAINT_BINDING")
        if native_session:
            for name, result, arguments in (
                    ("vp_llama_native_session_abi_v1", ctypes.c_uint32, []),
                    ("vp_llama_begin_turn_v1", ctypes.c_int32,
                     [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ABORT, ctypes.c_void_p])):
                require(hasattr(self.lib, name), "NATIVE_SESSION_ABI_MISMATCH")
                function = getattr(self.lib, name)
                function.restype, function.argtypes = result, arguments
            extension = self.lib.vp_llama_native_session_abi_v1()
            require(type(extension) is int and extension == 1, "NATIVE_SESSION_ABI_MISMATCH")
        if context_capacity:
            for name, result, arguments in (
                    ("vp_llama_context_capacity_abi_v1", ctypes.c_uint32, []),
                    ("vp_llama_reserve_context_v1", ctypes.c_int32,
                     [ctypes.c_void_p, ctypes.c_uint32, ABORT, ctypes.c_void_p])):
                require(hasattr(self.lib, name), "NATIVE_SESSION_ABI_MISMATCH")
                function = getattr(self.lib, name)
                function.restype, function.argtypes = result, arguments
            extension = self.lib.vp_llama_context_capacity_abi_v1()
            require(type(extension) is int and extension == 1, "NATIVE_SESSION_ABI_MISMATCH")
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
            if output_constraint is not None:
                status = self.lib.vp_llama_set_output_constraint_v1(self.handle, 1, len(output_constraint_tools))
                probe.joined()
                require(status == 0, "NATIVE_OUTPUT_CONSTRAINT_CONFIGURATION_FAILED")
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

    def begin_turn(self, retained_tokens, probe, constraint, aliases):
        self.require(type(retained_tokens) is int and 0 <= retained_tokens < 12288,
                     "NATIVE_SESSION_PREFIX_BOUND")
        self.require((constraint is None and aliases is None) or
                     (constraint == OUTPUT_CONSTRAINT and type(aliases) is list
                      and 1 <= len(aliases) <= 32
                      and aliases == [f"vp_{index}" for index in range(len(aliases))]),
                     "NATIVE_OUTPUT_CONSTRAINT_BINDING")
        # The old callback remains alive until the synchronous ABI handover has
        # returned. No native work or callback may outlive this one execution thread.
        previous = self.probe
        status = self.lib.vp_llama_begin_turn_v1(self.handle, retained_tokens,
                    0 if constraint is None else 1, 0 if aliases is None else len(aliases), probe.callback, None)
        self.probe = probe
        probe.joined()
        self.require(status == 0, "NATIVE_SESSION_PREFIX_RESET_FAILED")
        del previous

    def reserve_context(self, capacity, probe):
        self.require(self.context_capacity and type(capacity) is int
                     and self.capacity < capacity <= 12288 + 1024, "NATIVE_SESSION_PREFIX_BOUND")
        # Keep the old callback alive across the synchronous handover, exactly
        # as begin_turn does. The ABI installs this turn's owner/deadline first.
        previous = self.probe
        status = self.lib.vp_llama_reserve_context_v1(self.handle, capacity, probe.callback, None)
        self.probe = probe
        probe.joined()
        self.require(status == 0, "NATIVE_CONTEXT_INITIALIZATION_FAILED")
        self.capacity = capacity
        del previous

    def close(self):
        if self.handle.value is not None:
            self.lib.vp_llama_close_v1(self.handle)
            self.handle = ctypes.c_void_p()


def generate(model, prompt, tokenizer, profile, session, worker, observation=None, *, retained_tokens=0,
             decoded_tokens=None):
    worker.require(type(prompt) is list and 1 <= len(prompt) <= profile["prompt_tokens"]
                   and all(type(token) is int and 0 <= token < 151936 for token in prompt), "NATIVE_PROMPT_BOUND")
    if observation is not None:
        observation.forward_begin(None, None)
    # This is the complete original HF-rendered prompt in bounded prefill batches,
    # not truncation, sliding context, a second prompt or a hidden warmup.
    worker.require(type(retained_tokens) is int and 0 <= retained_tokens < len(prompt), "NATIVE_SESSION_PREFIX_BOUND")
    for start in range(retained_tokens, len(prompt), 128):
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
    if decoded_tokens is not None:
        # The final sampled token was not decoded (EOS or generation bound).
        # Prefix reuse can only name positions actually present in this handle.
        decoded_tokens[:] = prompt + generated[:-1]
    return {"sample_index": 0, "text": text, "generated_tokens": len(generated),
            "text_truncated": text != raw, "generation": metadata}


def execute(request, session, tokenizer, torch, versions, model_root, output_root,
            dataset, data_identity, model_files, worker, *, initial_source_weights, retained=None):
    worker.require(worker.conversation_module().generation_policy(dataset, PROFILE) == "greedy_v1",
                   "NATIVE_GREEDY_POLICY_REQUIRED")
    constraint = worker.conversation_constraint_binding(request, dataset, PROFILE)
    constraint_options = {}
    if constraint is not None:
        # The core supplies aliases, never arbitrary grammar. Validate against the
        # actual ordered input, not a separate count controlled by a peer.
        aliases = [f"vp_{index}" for index in range(len(dataset["tools"]))]
        constraint_options.update(output_constraint=constraint, output_constraint_tools=aliases)
    profile = worker.model_profile(PROFILE)
    worker.require(type(initial_source_weights) is dict and initial_source_weights == profile["weights"]
                   and all(model_files.get(name) == {"bytes": profile["files"][name],
                            "sha256": profile["hashes"][name]} for name in initial_source_weights["files"]),
                   "NATIVE_SOURCE_PROVENANCE")
    # Carry measured provenance, not a digest reconstructed from expected pins.
    # Only the GGUF below is used by NativeModel. The original source files are
    # not claimed to have been checked again at the end of this execution.
    weight_identity = dict(initial_source_weights, files=list(initial_source_weights["files"]))
    root, manifest, identity = verified_bundle(request, worker, tokenizer, session)
    if "output_constraints" in manifest:
        constraint_options["output_constraints"] = manifest["output_constraints"]
    session.private_progress("prompt_encode", "begin")
    prompt = worker.conversation_module().encode(tokenizer, dataset, profile)
    session.private_progress("prompt_encode", "complete")
    session.check()
    probe = OwnerProbe(session, worker)
    session.private_progress("model_load", "begin")
    worker.require((retained is not None) == ("native_session" in request), "NATIVE_SESSION_BINDING")
    prefix, decoded = 0, []
    if retained is None:
        model = NativeModel(root, len(prompt) + profile["new_tokens"], request["threads"], probe, worker.require,
                            **constraint_options)
    else:
        model, prefix = retained.begin(root, manifest, identity, request, prompt, probe, worker)
    try:
        session.private_progress("model_load", "complete")
        session.progress("baseline")
        session.private_progress("generation", "begin")
        observation = (worker.PrivateGenerationObservation(session, torch, len(prompt))
                       if request.get("private_generation_diagnostics") is True else None)
        output = generate(model, prompt, tokenizer, profile, session, worker, observation,
                          retained_tokens=prefix, decoded_tokens=decoded if retained is not None else None)
        session.private_progress("generation", "complete")
    finally:
        if retained is None:
            model.close()
    session.private_progress("verify_after", "begin")
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
    if "output_constraint" in request:
        result["output_constraint"] = request["output_constraint"]
    session.private_progress("result", "begin")
    result = worker.finish_result(result, output_root, session)
    session.private_progress("result", "complete")
    if retained is not None:
        retained.tokens = decoded
    return result


class RetainedModel:
    """One interpreter/connection's private RAM; never global or serializable."""
    def __init__(self):
        self.model, self.binding, self.tokens = None, None, []
        self.capacity, self.failed = 0, False

    def begin(self, root, manifest, identity, request, prompt, probe, worker):
        worker.require(not self.failed, "NATIVE_SESSION_PREFIX_RESET_FAILED")
        worker.require(manifest.get("native_sessions") == [NATIVE_SESSION], "NATIVE_SESSION_UNSUPPORTED")
        binding = (str(root), json.dumps(identity, sort_keys=True), request["threads"])
        worker.require(self.binding is None or self.binding == binding, "NATIVE_SESSION_MODEL_CHANGED")
        constraint, aliases = request.get("output_constraint"), request.get("output_constraint_tools")
        profile = worker.model_profile(PROFILE)
        worker.require(type(prompt) is list and 1 <= len(prompt) <= profile["prompt_tokens"]
                       and all(type(token) is int and 0 <= token < 151936 for token in prompt), "NATIVE_PROMPT_BOUND")
        # Match the pinned native context's 256-token padding, not its maximum
        # permitted context. The complete prompt and output allowance still fit.
        capacity = ((len(prompt) + profile["new_tokens"] + 255) // 256) * 256
        worker.require(capacity <= 12288 + 1024, "NATIVE_PROMPT_BOUND")
        prefix = 0
        previous = self.tokens
        # A failed or growing turn cannot retain authorization to old KV.
        self.tokens = []
        try:
            if self.model is None:
                self.model = NativeModel(root, capacity, request["threads"], probe, worker.require,
                    output_constraints=manifest["output_constraints"], native_session=True, context_capacity=True)
                self.binding, self.capacity = binding, capacity
            elif capacity > self.capacity:
                # Growth keeps the one model but destroys the old context first.
                # It costs prefix reuse for this turn, never any prompt tokens.
                self.model.reserve_context(capacity, probe)
                self.capacity = capacity
            else:
                for old, new in zip(previous, prompt[:-1]):
                    if old != new:
                        break
                    prefix += 1
            self.model.begin_turn(prefix, probe, constraint, aliases)
        except BaseException:
            self.failed = True
            self.close()
            raise
        return self.model, prefix

    def close(self):
        try:
            if self.model is not None:
                self.model.close()
        finally:
            self.model, self.binding, self.tokens = None, None, []
            self.capacity = 0
