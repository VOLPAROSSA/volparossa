#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline, disposable-guest BF16 conversion with full original-value comparison.

No model inference, network fetch, quantization, renamed weights digest or host
installation. The original pinned runtime, source checkout and source-built
adapter must already exist. A fresh owner-authorized artifact is produced only
after every original tensor and the tokenizer/template binding have been checked.
"""
import argparse
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import time

import build_llama_cpu as builder
import llama_cpu as native
import provision

HERE = Path(__file__).resolve().parent


class ConversionCancelled(Exception):
    """A fixed cancellation reason; no private subprocess command is exported."""


def run_converter(command, log, environment, timeout):
    """Join our direct child; never detach it from the owner's provision group.

    TERM/INT/HUP mark cancellation instead of interrupting Popen construction.
    Cleanup signals only this known child, never the shared parent group. If an
    outside timeout SIGKILLs this wrapper, the existing fixture's process-group
    join still includes the child. The pinned converter starts no subprocesses;
    native thread cleanup is part of joining its one Python process.
    """
    builder.require(timeout > 0, "NATIVE_CONVERSION_DEADLINE")
    deadline, process, cancelled = time.monotonic() + timeout, None, None
    previous = {}
    def stop(signum, _frame):
        nonlocal cancelled
        cancelled = signum
    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, stop)
        if cancelled is not None:
            raise ConversionCancelled("NATIVE_CONVERSION_CANCELLED")
        process = subprocess.Popen(["nice", "-n", "19", *command], stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, env=environment,
                                   start_new_session=False)
        builder.require(os.getpgid(process.pid) == os.getpgrp(), "NATIVE_CONVERTER_GROUP")
        while True:
            if cancelled is not None:
                raise ConversionCancelled("NATIVE_CONVERSION_CANCELLED")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("native converter", timeout)
            try:
                result = process.wait(timeout=min(.1, remaining))
                if cancelled is not None:
                    raise ConversionCancelled("NATIVE_CONVERSION_CANCELLED")
                builder.require(result == 0, "NATIVE_CONVERSION_PROCESS_FAILED")
                return
            except subprocess.TimeoutExpired:
                pass
    finally:
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        if cancelled is not None:
            raise ConversionCancelled("NATIVE_CONVERSION_CANCELLED")


def tensor_name(name):
    exact = {"model.embed_tokens.weight": "token_embd.weight", "model.norm.weight": "output_norm.weight"}
    if name in exact:
        return exact[name]
    match = re.fullmatch(r"model\.layers\.([0-9]+)\.(.+)\.weight", name)
    builder.require(match is not None and 0 <= int(match[1]) < 36, "NATIVE_TENSOR_NAME")
    suffixes = {"input_layernorm": "attn_norm", "post_attention_layernorm": "ffn_norm",
                "self_attn.q_proj": "attn_q", "self_attn.k_proj": "attn_k", "self_attn.v_proj": "attn_v",
                "self_attn.o_proj": "attn_output", "self_attn.q_norm": "attn_q_norm",
                "self_attn.k_norm": "attn_k_norm", "mlp.gate_proj": "ffn_gate",
                "mlp.up_proj": "ffn_up", "mlp.down_proj": "ffn_down"}
    builder.require(match[2] in suffixes, "NATIVE_TENSOR_NAME")
    return f"blk.{int(match[1])}.{suffixes[match[2]]}.weight"


def header(path):
    with path.open("rb") as stream:
        raw = stream.read(8)
        builder.require(len(raw) == 8, "NATIVE_SAFETENSORS_HEADER")
        length = struct.unpack("<Q", raw)[0]
        builder.require(2 <= length <= 1048576, "NATIVE_SAFETENSORS_HEADER")
        raw = stream.read(length)
        builder.require(len(raw) == length, "NATIVE_SAFETENSORS_HEADER")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            builder.require(key not in result, "NATIVE_DUPLICATE_TENSOR")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    builder.require(type(value) is dict and len(value) <= 399, "NATIVE_SAFETENSORS_HEADER")
    return 8 + length, {key: entry for key, entry in value.items() if key != "__metadata__"}


def compare_tensor(stream, offset, source, target, check):
    shape = source.get("shape")
    builder.require(source.keys() == {"dtype", "shape", "data_offsets"} and source["dtype"] == "BF16"
                    and type(shape) is list and 1 <= len(shape) <= 2
                    and all(type(size) is int and 0 < size <= 151936 for size in shape), "NATIVE_SOURCE_TENSOR")
    count = math.prod(shape)
    begin, end = source["data_offsets"]
    builder.require(type(begin) is int and type(end) is int and 0 <= begin < end
                    and end - begin == count * 2 and list(map(int, target.shape)) == list(reversed(shape))
                    and int(target.n_elements) == count, "NATIVE_TENSOR_SHAPE")
    # Pinned GGUF type IDs: F32=0, BF16=30. Exact promotions only, never F16/Q8/Q4.
    kind = int(target.tensor_type)
    expected = 0 if len(shape) == 1 or target.name.endswith("_norm.weight") else 30
    builder.require(kind == expected, "NATIVE_TENSOR_DTYPE")
    output = memoryview(target.data).cast("B")
    width = 4 if kind == 0 else 2
    builder.require(len(output) == count * width, "NATIVE_TENSOR_SIZE")
    stream.seek(offset + begin)
    for start in range(0, count, 65536):
        check()
        elements = min(65536, count - start)
        raw = stream.read(elements * 2)
        builder.require(len(raw) == elements * 2, "NATIVE_SOURCE_TENSOR_SHORT")
        if kind == 0:
            # BF16 bits shifted into F32, including signed zero. No approximate
            # float comparison, rounding tolerance or large tensor allocation.
            promoted = bytearray(elements * 4)
            for index in range(elements):
                promoted[index * 4 + 2:index * 4 + 4] = raw[index * 2:index * 2 + 2]
            raw = promoted
        builder.require(output[start * width:(start + elements) * width] == raw,
                        "NATIVE_TENSOR_VALUE_CHANGED")


def verify_conversion(reader, model, tokenizer, check):
    builder.require(sys.byteorder == "little", "NATIVE_ENDIAN_UNSUPPORTED")
    tensors = {entry.name: entry for entry in reader.tensors}
    builder.require(len(tensors) == len(reader.tensors) == 398, "NATIVE_TENSOR_COUNT")
    index = json.loads((model / "model.safetensors.index.json").read_bytes())["weight_map"]
    builder.require(len(index) == 398 and set(index.values()) == set(provision.QWEN4B_SHARDS), "NATIVE_WEIGHT_INDEX")
    checked = set()
    for name in provision.QWEN4B_SHARDS:
        offset, entries = header(model / name)
        builder.require(set(entries) == {key for key, shard in index.items() if shard == name}, "NATIVE_WEIGHT_INDEX")
        with (model / name).open("rb") as stream:
            for key, source in entries.items():
                target = tensor_name(key)
                builder.require(target in tensors and target not in checked, "NATIVE_TENSOR_SET")
                compare_tensor(stream, offset, source, tensors[target], check)
                checked.add(target)
    builder.require(checked == set(tensors), "NATIVE_TENSOR_SET")
    def field(name):
        builder.require(name in reader.fields, "NATIVE_GGUF_METADATA")
        return reader.fields[name].contents()
    builder.require(field("general.architecture") == "qwen3" and field("general.file_type") == 32,
                    "NATIVE_GGUF_ARCHITECTURE")
    config = json.loads((model / "config.json").read_bytes())
    parameters = {"context_length": config["max_position_embeddings"], "embedding_length": config["hidden_size"],
                  "block_count": config["num_hidden_layers"], "feed_forward_length": config["intermediate_size"],
                  "attention.head_count": config["num_attention_heads"], "attention.head_count_kv": config["num_key_value_heads"],
                  "attention.key_length": config["head_dim"], "attention.value_length": config["head_dim"],
                  "rope.dimension_count": config["head_dim"], "rope.freq_base": config["rope_theta"],
                  "attention.layer_norm_rms_epsilon": config["rms_norm_eps"]}
    for key, expected in parameters.items():
        if key in ("rope.freq_base", "attention.layer_norm_rms_epsilon"):
            expected = struct.unpack("<f", struct.pack("<f", expected))[0]
        builder.require(field("qwen3." + key) == expected, "NATIVE_GGUF_PARAMETER")
    vocab = tokenizer.get_vocab()
    tokens = field("tokenizer.ggml.tokens")
    reverse = {token_id: token for token, token_id in vocab.items()}
    builder.require(len(tokens) == 151936 and len(vocab) == len(set(vocab.values()))
                    and all(type(token_id) is int and 0 <= token_id < len(tokens)
                            and tokens[token_id] == token for token, token_id in vocab.items()),
                    "NATIVE_GGUF_TOKENIZER")
    builder.require(all(token == reverse.get(index, f"[PAD{index}]") for index, token in enumerate(tokens)),
                    "NATIVE_GGUF_TOKENIZER")
    tokenizer_source = json.loads((model / "tokenizer.json").read_bytes())
    merges = tokenizer_source["model"]["merges"]
    merges = [" ".join(pair) if type(pair) is list else pair for pair in merges]
    builder.require(field("tokenizer.ggml.merges") == merges, "NATIVE_GGUF_MERGES")
    builder.require(field("tokenizer.ggml.eos_token_id") == tokenizer.eos_token_id == 151645
                    and tokenizer.pad_token_id == 151643, "NATIVE_GGUF_SPECIAL_TOKENS")
    template = tokenizer.chat_template
    builder.require(type(template) is str and field("tokenizer.chat_template") == template, "NATIVE_GGUF_TEMPLATE")
    return {"tensor_count": 398, "tensor_values_equal": True, "tokenizer_equal": True,
            "chat_template_sha256": hashlib.sha256(template.encode()).hexdigest()}


def private_bundle_modes(root):
    root.chmod(0o700)
    for path in root.rglob("*"):
        builder.require(not path.is_symlink(), "NATIVE_BUNDLE_SYMLINK")
        if path.is_file():
            path.chmod(0o400)
        elif path.is_dir():
            path.chmod(0o700)
        else:
            raise ValueError("NATIVE_BUNDLE_FILE_TYPE")


def execute(args):
    # Reuse the existing explicit disposable VM/CI/CPython3.13/fresh-private-root
    # guard. This tool never relaxes provision's host-safety requirements.
    root, _ = provision.execution_root(args)
    builder.verify_source(args.source)
    builder.require(1 <= args.timeout_seconds <= 1800, "NATIVE_CONVERSION_DEADLINE")
    pins = provision.load_pins(provision.QWEN4B_MODEL_PROFILE, native_cpu_converter=True)
    started = time.monotonic()
    deadline = started + args.timeout_seconds
    def check():
        builder.require(time.monotonic() < deadline, "NATIVE_CONVERSION_DEADLINE")
    for name, expected in (("torch", "2.14.0+cpu"), ("transformers", "5.16.1"), ("peft", "0.20.0"),
                           ("sentencepiece", "0.2.1")):
        builder.require(importlib.metadata.version(name) == expected, "NATIVE_CONVERTER_RUNTIME_PIN")
    model = args.model
    builder.require(model.is_absolute() and model == model.resolve() and model.is_dir(), "NATIVE_MODEL_PATH")
    builder.require({path.name for path in model.iterdir()} == {item["path"] for item in pins["files"]}, "NATIVE_MODEL_FILES")
    for item in pins["files"]:
        check()
        builder.require(builder.digest(model / item["path"]) == {key: item[key] for key in ("sha256", "bytes")},
                        "NATIVE_ORIGINAL_MODEL_PIN")
    provision.verify_weight_set(pins, model, deadline)
    build_root = args.build
    build_raw = (build_root / "build.json").read_bytes()
    builder.require(len(build_raw) <= 65536, "NATIVE_BUILD_MANIFEST_BOUND")
    build = json.loads(build_raw)
    builder.require(build["version"] == 1 and build["source_commit"] == builder.SOURCE
                    and build["kind"] == native.KIND and build["abi_version"] == 1
                    and build["quantization"] is False and build["provisionable"] is True
                    and build["sanitizers"] is False and build["library"]["path"] == native.LIBRARY
                    and set(build["dynamic_dependencies"]) <= builder.ALLOWED_NEEDED,
                    "NATIVE_BUILD_MANIFEST")
    builder.require(build["wrapper_sources"] == {name: builder.digest(HERE / "native-cpu" / name)
                    for name in ("CMakeLists.txt", "adapter.h", "adapter.cpp")}, "NATIVE_WRAPPER_SOURCE_BINDING")
    library = build_root / native.LIBRARY
    builder.require(builder.digest(library) == {key: build["library"][key] for key in ("bytes", "sha256")},
                    "NATIVE_LIBRARY_PIN")
    required = native.WEIGHTS_BYTES + 128 * 1024 ** 2 + build["library"]["bytes"]
    builder.require(type(args.budget_bytes) is int and required <= args.budget_bytes
                    and shutil.disk_usage(root.parent).free >= args.budget_bytes, "NATIVE_CONVERSION_DISK_BUDGET")
    root.mkdir(mode=0o700)
    output = root / "model.gguf"
    env = dict(os.environ, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_DATASETS_OFFLINE="1",
               HF_HUB_DISABLE_TELEMETRY="1", OMP_NUM_THREADS="2", MKL_NUM_THREADS="2",
               TOKENIZERS_PARALLELISM="false")
    for key in list(env):
        if key.startswith("LD_") or key in ("PYTHONPATH", "PYTHONHOME"):
            env.pop(key)
    with (root / "conversion.log").open("xb") as log:
        run_converter([sys.executable, str(args.source / "convert_hf_to_gguf.py"), str(model),
                       "--outfile", str(output), "--outtype", "bf16"], log, env, deadline - time.monotonic())
    check()
    sys.path.insert(0, str(args.source / "gguf-py"))
    import gguf
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(model), local_files_only=True, trust_remote_code=False, use_fast=True)
    verified = verify_conversion(gguf.GGUFReader(str(output)), model, tokenizer, check)
    check()
    provision.verify_weight_set(pins, model, deadline)
    shutil.copyfile(library, root / native.LIBRARY)
    shutil.copyfile(build_root / "build.json", root / "build.json")
    shutil.copytree(build_root / "licenses", root / "licenses", symlinks=False)
    shutil.copyfile(model / "LICENSE", root / "licenses" / "Qwen-APACHE-2.0.txt")
    for notice in provision.native_converter_pins()["notices"]:
        shutil.copyfile(HERE / notice["path"], root / "licenses" / Path(notice["path"]).name)
    manifest = {"version": 1, "kind": native.KIND, "abi_version": 1, "source_commit": builder.SOURCE,
                "model_profile": native.PROFILE, "source_weights_sha256": native.WEIGHTS_SHA,
                "source_weights_bytes": native.WEIGHTS_BYTES,
                "library": {"path": native.LIBRARY, **builder.digest(root / native.LIBRARY)},
                "gguf": {"path": "model.gguf", **builder.digest(output)}, "verification": verified,
                "build_manifest_sha256": hashlib.sha256(build_raw).hexdigest()}
    native.validate_manifest(manifest, builder.require)
    retained = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    builder.require(retained + 65536 <= args.budget_bytes, "NATIVE_CONVERSION_DISK_BUDGET")
    check()
    builder.write_json(root / "backend.json", manifest)
    private_bundle_modes(root)
    return {"version": 1, "kind": native.KIND, "manifest": builder.digest(root / "backend.json"),
            "model_inference": False, "downloads": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--budget-bytes", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--disposable-guest", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"kind": native.KIND, "source_commit": builder.SOURCE, "model_profile": native.PROFILE,
                          "execute": False, "downloads": False, "model_inference": False}))
        return
    try:
        print(json.dumps(execute(args), sort_keys=True))
    except Exception:
        parser.exit(1, "NATIVE_CONVERSION_FAILED\n")


if __name__ == "__main__":
    main()
