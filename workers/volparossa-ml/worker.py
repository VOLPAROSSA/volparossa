#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One explicitly public document job in the supervisor's isolated CPU worker.

The supervisor owns path authorization, network isolation, process-group cancellation and
hard resource limits. This module never provisions a backend/model, accepts executable code,
loads pickle checkpoints, or turns model output into policy/tool authority. Its protocol and
validation import only the standard library; successful jobs require the real pinned backend.
It may be embedded and invoked as ``python -I -c CODE``; no __file__ dependency is allowed.
"""

import contextlib
import gc
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import time

VERSION = 1
MAX_REQUEST = 65536
MAX_DATASET = 1048576
MAX_LINE = 16384
MAX_CONTEXT = 256
MAX_NEW_TOKENS = 64
MODEL_ID = "HuggingFaceTB/SmolLM2-135M-Instruct"
MODEL_REVISION = "83212e1e2b3cfd6958f3707877bb878945dea8ee"
MODEL_WEIGHT_BYTES = 269060552
MODEL_WEIGHT_SHA = "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c"
BACKENDS = {"torch": "2.14.0+cpu", "transformers": "5.16.1", "peft": "0.20.0"}
MODEL_FILES = {
    "LICENSE": 10172,
    "README.md": 6141,
    "config.json": 861,
    "generation_config.json": 132,
    "model.safetensors": MODEL_WEIGHT_BYTES,
    "special_tokens_map.json": 655,
    "tokenizer.json": 2104556,
    "tokenizer_config.json": 3764,
}
MODEL_HASHES = {
    "LICENSE": "59899c6091b540582ed617e8eeaac4919dc985ccfc35459ee9752b699be5205b",
    "README.md": "ea87bdb4e8d2bda80d739923ae0efcc5ec64afa20d47c6b0f2488625ba3bac13",
    "config.json": "8eb740e8bbe4cff95ea7b4588d17a2432deb16e8075bc5828ff7ba9be94d982a",
    "generation_config.json": "87b916edaaab66b3899b9d0dd0752727dff6666686da0504d89ae0a6e055a013",
    "model.safetensors": MODEL_WEIGHT_SHA,
    "special_tokens_map.json": "2b7379f3ae813529281a5c602bc5a11c1d4e0a99107aaa597fe936c1e813ca52",
    "tokenizer.json": "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c",
    "tokenizer_config.json": "4ec77d44f62efeb38d7e044a1db318f6a939438425312dfa333b8382dbad98df",
}
ADAPTER_FILES = {"adapter_config.json": 16384, "adapter_model.safetensors": 2 * 1024 * 1024,
                 "README.md": 16384}
# Admission only: these inert defaults are never passed to a backend constructor.
# Pinned PEFT 0.20.0 emits them when saving the fixed LoRA configuration.
ADAPTER_DEFAULTS = {
    "auto_mapping": None, "peft_version": "0.20.0", "exclude_modules": None,
    "fan_in_fan_out": False, "use_rslora": False, "modules_to_save": None,
    "init_lora_weights": True, "layers_to_transform": None, "layers_pattern": None,
    "rank_pattern": {}, "alpha_pattern": {}, "megatron_config": None,
    "megatron_core": "megatron.core", "trainable_token_indices": None,
    "loftq_config": {}, "eva_config": None, "corda_config": None, "lora_ga_config": None,
    "use_dora": False, "velora_config": None, "alora_invocation_tokens": None,
    "use_qalora": False, "qalora_group_size": 16, "monteclora_config": None,
    "layer_replication": None, "lora_bias": False, "target_parameters": None,
    "use_bdlora": None, "arrow_config": None, "ensure_weight_tying": False,
}
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
PHASES = {"preparing", "baseline", "training", "checkpoint", "reload", "complete"}
STOP_REQUESTED = False
WIRE_OUTPUT = sys.stdout


class JobError(Exception):
    """Fixed, non-sensitive failure code; never propagate a dataset/backend exception."""


def require(condition, code):
    if not condition:
        raise JobError(code)


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def invalid_constant(_value):
    raise JobError("INVALID_JSON_NUMBER")


def parse_json(data):
    try:
        return json.loads(data, object_pairs_hook=no_duplicate_keys, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise JobError("INVALID_JSON") from error


def bounded_integer(value, low, high):
    return type(value) is int and low <= value <= high


def validate_request(value):
    required = {"version", "id", "mode", "model_root", "dataset_path", "output_root"}
    optional = {"steps", "threads", "max_seconds", "adapter_root"}
    require(type(value) is dict and required <= value.keys()
            and value.keys() <= required | optional, "INVALID_REQUEST_FIELDS")
    require(type(value["version"]) is int and value["version"] == VERSION, "UNSUPPORTED_VERSION")
    require(type(value["id"]) is str and HEX32.fullmatch(value["id"]), "INVALID_REQUEST_ID")
    require(value["mode"] in ("infer", "train"), "INVALID_JOB_MODE")
    for field in ("model_root", "dataset_path", "output_root", "adapter_root"):
        if field == "adapter_root" and field not in value:
            continue
        path = value[field]
        require(type(path) is str and 1 < len(path.encode("utf-8")) <= 4096
                and path.startswith("/") and "\x00" not in path, "INVALID_JOB_PATH")
    result = dict(value)
    for field, default, upper in (("steps", 8, 64), ("threads", 2, 2), ("max_seconds", 600, 600)):
        result.setdefault(field, default)
        require(bounded_integer(result[field], 1, upper), "INVALID_JOB_BUDGET")
    return result


def validate_sample(sample, answered):
    fields = {"question", "context", "answer"} if answered else {"question", "context"}
    require(type(sample) is dict and sample.keys() == fields, "INVALID_SAMPLE_FIELDS")
    for field in fields:
        text = sample[field]
        maximum = 4096 if field == "context" else 1024 if field == "answer" else 512
        require(type(text) is str and 0 < len(text.encode("utf-8")) <= maximum
                and "\x00" not in text, "INVALID_SAMPLE_TEXT")
    return sample


def validate_dataset(dataset, mode):
    fields = {"version", "visibility", "license", "source_revision", "train", "heldout", "inference"}
    require(type(dataset) is dict and dataset.keys() == fields, "INVALID_DATASET_FIELDS")
    require(type(dataset["version"]) is int and dataset["version"] == VERSION
            and dataset["visibility"] == "public" and dataset["license"] == "GPL-3.0-only",
            "DATASET_NOT_EXPLICIT_PUBLIC_REPO_DOCS")
    require(type(dataset["source_revision"]) is str and HEX40.fullmatch(dataset["source_revision"]),
            "INVALID_DATASET_REVISION")
    for field, minimum, maximum in (("train", 1 if mode == "train" else 0, 32),
                                    ("heldout", 1, 8), ("inference", 1, 4)):
        rows = dataset[field]
        require(type(rows) is list and minimum <= len(rows) <= maximum, "INVALID_DATASET_SIZE")
        seen = set()
        for row in rows:
            validate_sample(row, field != "inference")
            identity = (row["question"], row["context"])
            require(identity not in seen, "DUPLICATE_DATASET_SAMPLE")
            seen.add(identity)
    training_questions = {row["question"].strip().casefold() for row in dataset["train"]}
    require(not training_questions.intersection(row["question"].strip().casefold()
                                               for row in dataset["heldout"]), "TRAIN_HELDOUT_OVERLAP")
    return dataset


def plain_path(value, directory):
    path = Path(value)
    require(path.resolve(strict=True) == path, "JOB_PATH_NOT_CANONICAL")
    metadata = path.lstat()
    require((stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
            and not stat.S_ISLNK(metadata.st_mode), "INVALID_JOB_PATH_TYPE")
    return path, metadata


def file_hash(path, expected_size=None, maximum=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "INVALID_ARTIFACT_FILE")
        require(expected_size is None or metadata.st_size == expected_size, "ARTIFACT_SIZE_MISMATCH")
        require(maximum is None or metadata.st_size <= maximum, "ARTIFACT_TOO_LARGE")
        digest, length = hashlib.sha256(), 0
        while True:
            data = source.read(1024 * 1024)
            if not data:
                break
            length += len(data)
            require(length <= metadata.st_size, "ARTIFACT_CHANGED")
            digest.update(data)
        require(length == metadata.st_size, "ARTIFACT_CHANGED")
        return {"bytes": length, "sha256": digest.hexdigest()}


def read_bounded(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "INVALID_ARTIFACT_FILE")
        value = source.read(maximum + 1)
        require(len(value) <= maximum, "ARTIFACT_TOO_LARGE")
        return value


def prepare_files(request):
    model_root, model_metadata = plain_path(request["model_root"], True)
    dataset_path, _ = plain_path(request["dataset_path"], False)
    output_root, output_metadata = plain_path(request["output_root"], True)
    require(not stat.S_IMODE(model_metadata.st_mode) & 0o022, "MODEL_DIRECTORY_WRITABLE_BY_OTHERS")
    require(output_metadata.st_uid == os.geteuid()
            and stat.S_IMODE(output_metadata.st_mode) == 0o700 and not any(output_root.iterdir()),
            "OUTPUT_DIRECTORY_NOT_FRESH_PRIVATE")
    require(not model_root.is_relative_to(output_root) and not output_root.is_relative_to(model_root),
            "MODEL_OUTPUT_PATH_OVERLAP")
    require({path.name for path in model_root.iterdir()} == set(MODEL_FILES), "UNSUPPORTED_MODEL_FILES")
    files = {name: file_hash(model_root / name, expected_size=size) for name, size in MODEL_FILES.items()}
    require(all(files[name]["sha256"] == expected for name, expected in MODEL_HASHES.items()),
            "MODEL_FILES_NOT_PINNED")
    config = parse_json(read_bounded(model_root / "config.json", 8192))
    expected = {"architectures": ["LlamaForCausalLM"], "model_type": "llama", "hidden_size": 576,
                "num_hidden_layers": 30, "num_attention_heads": 9, "num_key_value_heads": 3,
                "intermediate_size": 1536, "vocab_size": 49152, "max_position_embeddings": 8192,
                "tie_word_embeddings": True}
    require(type(config) is dict and all(config.get(key) == value for key, value in expected.items())
            and "auto_map" not in config and "quantization_config" not in config,
            "UNSUPPORTED_MODEL_ARCHITECTURE")
    raw_dataset = read_bounded(dataset_path, MAX_DATASET)
    dataset = validate_dataset(parse_json(raw_dataset), request["mode"])
    return model_root, output_root, dataset, {
        "sha256": hashlib.sha256(raw_dataset).hexdigest(), "bytes": len(raw_dataset),
        "visibility": "public", "license": dataset["license"], "source_revision": dataset["source_revision"],
        "training_examples": len(dataset["train"]), "heldout_examples": len(dataset["heldout"]),
        "inference_examples": len(dataset["inference"]),
    }, files


def validate_adapter_config(config):
    fixed = {"base_model_name_or_path": MODEL_ID, "revision": MODEL_REVISION,
             "peft_type": "LORA", "task_type": "CAUSAL_LM", "r": 4, "lora_alpha": 8,
             "lora_dropout": 0.0, "bias": "none", "inference_mode": True}
    required = fixed.keys() | {"target_modules"}
    require(type(config) is dict and required <= config.keys()
            and config.keys() <= required | ADAPTER_DEFAULTS.keys(), "UNSUPPORTED_ADAPTER_CONFIG")
    for key, expected in (fixed | {k: v for k, v in ADAPTER_DEFAULTS.items() if k in config}).items():
        require(type(config[key]) is type(expected) and config[key] == expected,
                "UNSUPPORTED_ADAPTER_CONFIG")
    targets = config["target_modules"]
    require(type(targets) is list and len(targets) == 2 and all(type(x) is str for x in targets)
            and set(targets) == {"q_proj", "v_proj"}, "UNSUPPORTED_ADAPTER_CONFIG")


def adapter_shapes():
    return {f"base_model.model.model.layers.{layer}.self_attn.{module}.lora_{matrix}.weight": shape
            for layer in range(30)
            for module, width in (("q_proj", 576), ("v_proj", 192))
            for matrix, shape in (("A", [4, 576]), ("B", [width, 4]))}


def validate_adapter_weights(raw):
    """Bound the complete safetensors structure and FP32 values before backend loading."""
    require(8 < len(raw) <= ADAPTER_FILES["adapter_model.safetensors"], "INVALID_ADAPTER_WEIGHTS")
    header_length = int.from_bytes(raw[:8], "little")
    require(0 < header_length <= 65536 and 8 + header_length < len(raw), "INVALID_ADAPTER_HEADER")
    header = parse_json(raw[8:8 + header_length])
    require(type(header) is dict, "INVALID_ADAPTER_HEADER")
    metadata = header.pop("__metadata__", None)
    require(metadata is None or metadata == {"format": "pt"}, "INVALID_ADAPTER_METADATA")
    shapes = adapter_shapes()
    require(header.keys() == shapes.keys(), "UNSUPPORTED_ADAPTER_TENSOR_KEYS")
    segments = []
    for name, shape in shapes.items():
        tensor = header[name]
        require(type(tensor) is dict and tensor.keys() == {"dtype", "shape", "data_offsets"}
                and tensor["dtype"] == "F32" and tensor["shape"] == shape
                and all(type(x) is int for x in tensor["shape"]), "UNSUPPORTED_ADAPTER_TENSOR_FORMAT")
        offsets = tensor["data_offsets"]
        require(type(offsets) is list and len(offsets) == 2
                and all(type(x) is int for x in offsets)
                and 0 <= offsets[0] < offsets[1] <= len(raw) - 8 - header_length
                and offsets[1] - offsets[0] == math.prod(shape) * 4,
                "INVALID_ADAPTER_TENSOR_OFFSETS")
        segments.append(offsets)
    ordered = sorted(segments)
    require(ordered[0][0] == 0 and ordered[-1][1] == len(raw) - 8 - header_length == 230400 * 4
            and all(a[1] == b[0] for a, b in zip(ordered, ordered[1:])),
            "INVALID_ADAPTER_TENSOR_LAYOUT")
    payload = memoryview(raw)[8 + header_length:]
    require(all(math.isfinite(value[0]) for value in struct.iter_unpack("<f", payload)),
            "NONFINITE_ADAPTER_WEIGHTS")


def prepare_adapter(value, output_root, owned_checkpoint=False):
    root, metadata = plain_path(value, True)
    require(metadata.st_uid == os.geteuid() and not stat.S_IMODE(metadata.st_mode) & 0o022,
            "ADAPTER_DIRECTORY_WRITABLE_BY_OTHERS")
    if owned_checkpoint:
        require(root == output_root / "adapter", "INVALID_OWNED_CHECKPOINT_PATH")
    else:
        require(not root.is_relative_to(output_root) and not output_root.is_relative_to(root),
                "ADAPTER_OUTPUT_PATH_OVERLAP")
    require({p.name for p in root.iterdir()} == ADAPTER_FILES.keys(), "UNSUPPORTED_ADAPTER_FILES")
    files, payloads = {}, {}
    for name, maximum in ADAPTER_FILES.items():
        path = root / name
        files[name] = file_hash(path, maximum=maximum)
        require(files[name]["bytes"] > 0 and not path.stat().st_mode & 0o022, "INVALID_ADAPTER_FILE")
        payloads[name] = read_bounded(path, maximum)
        require(hashlib.sha256(payloads[name]).hexdigest() == files[name]["sha256"], "ADAPTER_FILE_CHANGED")
    validate_adapter_config(parse_json(payloads["adapter_config.json"]))
    try:
        require("\x00" not in payloads["README.md"].decode("utf-8"), "INVALID_ADAPTER_README")
    except UnicodeError as error:
        raise JobError("INVALID_ADAPTER_README") from error
    validate_adapter_weights(payloads["adapter_model.safetensors"])
    return root, files, payloads["adapter_model.safetensors"]


def new_lora(model, peft, trainable=True):
    return peft.get_peft_model(model, peft.LoraConfig(
        task_type="CAUSAL_LM", r=4, lora_alpha=8, lora_dropout=0.0,
        target_modules=["q_proj", "v_proj"], bias="none", inference_mode=not trainable))


def apply_adapter(model, prepared, peft, torch, session, trainable):
    from safetensors.torch import load
    from peft.utils.save_and_load import get_peft_model_state_dict, set_peft_model_state_dict

    _, files, raw = prepared
    # No peer-controlled config, module name, class, auto_mapping or Hub path reaches PEFT.
    weights = load(raw)
    expected = adapter_shapes()
    require(weights.keys() == expected.keys(), "UNSUPPORTED_ADAPTER_TENSOR_KEYS")
    for name, tensor in weights.items():
        session.check()
        require(tensor.dtype == torch.float32 and tensor.device.type == "cpu"
                and list(tensor.shape) == expected[name] and torch.isfinite(tensor).all().item(),
                "UNSUPPORTED_ADAPTER_TENSOR_FORMAT")
    model = new_lora(model, peft, trainable)
    before = parameter_hash(model, False, session)
    loaded = set_peft_model_state_dict(model, weights, adapter_name="default",
                                      ignore_mismatched_sizes=False, low_cpu_mem_usage=False)
    require(not loaded.unexpected_keys and not any(".lora_" in x for x in loaded.missing_keys),
            "ADAPTER_APPLICATION_INCOMPLETE")
    applied = get_peft_model_state_dict(model, adapter_name="default", save_embedding_layers=False)
    require(applied.keys() == weights.keys()
            and all(torch.equal(applied[name], value) for name, value in weights.items()),
            "APPLIED_ADAPTER_WEIGHTS_DIFFER")
    after = parameter_hash(model, False, session)
    require(before == after, "BASE_WEIGHTS_CHANGED_BY_ADAPTER")
    applied_parameters = parameter_hash(model, True, session)
    require(applied_parameters["parameters"] == 230400, "UNEXPECTED_TRAINABLE_PARAMETERS")
    return model, {"model_id": MODEL_ID, "model_revision": MODEL_REVISION, "files": files,
                   "applied_parameters": applied_parameters, "base_parameters_before_apply": before,
                   "base_parameters_after_apply": after, "applied": True}


class Session:
    def __init__(self, request):
        self.request = request
        self.started = time.monotonic()

    def elapsed(self):
        return int((time.monotonic() - self.started) * 1000)

    def check(self):
        require(not STOP_REQUESTED, "JOB_CANCELLED")
        require(self.elapsed() < self.request["max_seconds"] * 1000, "JOB_DEADLINE_EXCEEDED")

    def progress(self, phase, step=0):
        self.check()
        require(phase in PHASES, "INTERNAL_PHASE_ERROR")
        emit({"version": VERSION, "id": self.request["id"], "kind": "progress",
              "phase": phase, "step": step, "elapsed_ms": self.elapsed()})


def emit(record):
    raw = json.dumps(record, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    require(len(raw.encode("ascii")) + 1 <= MAX_LINE, "RESULT_TOO_LARGE")
    WIRE_OUTPUT.write(raw + "\n")
    WIRE_OUTPUT.flush()


def configure_offline():
    # Local-only flags are defense in depth; the supervisor must deny actual network access.
    for name, value in {
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1", "DO_NOT_TRACK": "1", "WANDB_DISABLED": "true",
        "TOKENIZERS_PARALLELISM": "false", "CUDA_VISIBLE_DEVICES": "", "HIP_VISIBLE_DEVICES": "",
        "PYTHONDONTWRITEBYTECODE": "1",
    }.items():
        os.environ[name] = value
    sys.dont_write_bytecode = True


def load_backend(threads):
    try:
        versions = {name: importlib.metadata.version(name) for name in BACKENDS}
    except importlib.metadata.PackageNotFoundError as error:
        raise JobError("BACKEND_NOT_INSTALLED") from error
    require(versions == BACKENDS, "BACKEND_VERSION_MISMATCH")
    import torch
    import peft
    import transformers
    require(torch.version.cuda is None and torch.version.hip is None, "CPU_BACKEND_REQUIRED")
    torch.set_num_threads(threads)
    torch.set_num_interop_threads(1)
    torch.manual_seed(7)
    transformers.logging.set_verbosity_error()
    return torch, transformers, peft, versions


def load_model(transformers, torch, model_root):
    model = transformers.AutoModelForCausalLM.from_pretrained(
        str(model_root), local_files_only=True, trust_remote_code=False, use_safetensors=True,
        dtype=torch.float32, device_map=None, attn_implementation="eager")
    model.to(torch.device("cpu"))
    model.config.use_cache = False
    # Generated public adapter metadata must name the original model, never a local path.
    model.config._name_or_path = MODEL_ID
    return model


def prompt_messages(row):
    return [{"role": "system", "content": "Answer the question using only the supplied public documentation. "
             "If it does not contain the answer, say you do not know."},
            {"role": "user", "content": "Documentation:\n" + row["context"] + "\nQuestion:\n" + row["question"]}]


def encode_dataset(tokenizer, torch, dataset):
    result = {"train": [], "heldout": [], "inference": []}
    for split in result:
        for row in dataset[split]:
            messages = prompt_messages(row)
            prompt = tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True)
            require(type(prompt) is list and 1 <= len(prompt) <= MAX_CONTEXT - MAX_NEW_TOKENS,
                    "DOCUMENT_TOKEN_LIMIT_EXCEEDED")
            if split == "inference":
                result[split].append(torch.tensor([prompt], dtype=torch.long, device="cpu"))
                continue
            complete = tokenizer.apply_chat_template(messages + [{"role": "assistant", "content": row["answer"]}],
                                                     tokenize=True, add_generation_prompt=False)
            require(complete[:len(prompt)] == prompt and len(prompt) < len(complete) <= MAX_CONTEXT,
                    "TRAINING_TOKEN_LIMIT_OR_TEMPLATE_INVALID")
            labels = [-100] * len(prompt) + complete[len(prompt):]
            result[split].append({
                "input_ids": torch.tensor([complete], dtype=torch.long, device="cpu"),
                "labels": torch.tensor([labels], dtype=torch.long, device="cpu"),
                "use_cache": False,
            })
    return result


def finite_loss(value):
    result = float(value.detach().item())
    require(math.isfinite(result) and result >= 0, "NONFINITE_MODEL_LOSS")
    return result


def evaluate(model, samples, torch, session):
    model.eval()
    total, tokens = 0.0, 0
    with torch.inference_mode():
        for sample in samples:
            session.check()
            count = int((sample["labels"][:, 1:] != -100).sum().item())
            require(count > 0, "EMPTY_EVALUATION_TARGET")
            loss = finite_loss(model(**sample).loss)
            total += loss * count
            tokens += count
    require(tokens > 0, "EMPTY_EVALUATION_SET")
    return {"loss": total / tokens, "target_tokens": tokens}


def generate(model, samples, tokenizer, torch, session):
    model.eval()
    results = []
    with torch.inference_mode():
        for index, input_ids in enumerate(samples):
            session.check()
            output = model.generate(input_ids=input_ids, attention_mask=torch.ones_like(input_ids),
                                    max_new_tokens=MAX_NEW_TOKENS, do_sample=False, use_cache=True,
                                    pad_token_id=tokenizer.pad_token_id, eos_token_id=tokenizer.eos_token_id)
            generated = output[0, input_ids.shape[1]:]
            require(generated.numel() <= MAX_NEW_TOKENS, "GENERATION_TOKEN_LIMIT_EXCEEDED")
            text = tokenizer.decode(generated, skip_special_tokens=True)
            # Bound the escaped wire representation too: four multilingual responses must
            # not overflow a frame merely because JSON represents one character as \uXXXX.
            public_text = text[:1024]
            while len(json.dumps(public_text, ensure_ascii=True).encode("ascii")) > 1024:
                public_text = public_text[:-1]
            results.append({"sample_index": index, "text": public_text,
                            "generated_tokens": int(generated.numel()), "text_truncated": public_text != text})
    return results


def parameter_hash(model, adapter, session):
    """Hash actual CPU tensors without copying an entire model into an extra buffer."""
    digest, parameters = hashlib.sha256(), 0
    for name, tensor in sorted(model.named_parameters()):
        is_adapter = ".lora_" in name
        if is_adapter != adapter:
            continue
        session.check()
        require(tensor.device.type == "cpu", "CPU_BACKEND_REQUIRED")
        descriptor = json.dumps([name, str(tensor.dtype), list(tensor.shape)], separators=(",", ":")).encode("ascii")
        digest.update(len(descriptor).to_bytes(4, "big"))
        digest.update(descriptor)
        view = memoryview(tensor.detach().contiguous().numpy()).cast("B")
        for offset in range(0, len(view), 1024 * 1024):
            digest.update(view[offset:offset + 1024 * 1024])
        parameters += tensor.numel()
    require(parameters > 0, "EMPTY_PARAMETER_SET")
    return {"sha256": digest.hexdigest(), "parameters": parameters}


def durable_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_checkpoint(model, output_root, session):
    session.progress("checkpoint")
    adapter_root = output_root / "adapter"
    adapter_root.mkdir(mode=0o700)
    model.peft_config["default"].base_model_name_or_path = MODEL_ID
    model.peft_config["default"].revision = MODEL_REVISION
    model.save_pretrained(str(adapter_root), safe_serialization=True, save_embedding_layers=False)
    expected = {"adapter_config.json", "adapter_model.safetensors", "README.md"}
    require({path.name for path in adapter_root.iterdir()} == expected, "UNEXPECTED_CHECKPOINT_FILES")
    artifacts = []
    for name in sorted(expected):
        path = adapter_root / name
        artifact = file_hash(path, maximum=4 * 1024 * 1024)
        require(stat.S_IMODE(path.lstat().st_mode) == 0o600, "CHECKPOINT_NOT_PRIVATE")
        durable_file(path)
        artifacts.append({"relative_path": "adapter/" + name, **artifact})
    durable_file(adapter_root)
    durable_file(output_root)
    return adapter_root, artifacts


def execute_job(request, session):
    session.progress("preparing")
    model_root, output_root, dataset, data_identity, model_files = prepare_files(request)
    prepared_adapter = (prepare_adapter(request["adapter_root"], output_root)
                        if "adapter_root" in request else None)
    configure_offline()
    torch, transformers, peft, versions = load_backend(request["threads"])
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        str(model_root), local_files_only=True, trust_remote_code=False, use_fast=True)
    require(tokenizer.pad_token_id == 2 and tokenizer.eos_token_id == 2, "MODEL_TOKENIZER_MISMATCH")
    samples = encode_dataset(tokenizer, torch, dataset)
    model = load_model(transformers, torch, model_root)
    input_adapter = None
    if prepared_adapter is not None:
        model, input_adapter = apply_adapter(model, prepared_adapter, peft, torch, session,
                                             trainable=request["mode"] == "train")
    session.progress("baseline")
    baseline = evaluate(model, samples["heldout"], torch, session)
    baseline_outputs = generate(model, samples["inference"], tokenizer, torch, session)
    result = {"version": VERSION, "id": request["id"], "kind": "result", "status": "ok", "mode": request["mode"],
              "backend_versions": versions, "device": "cpu", "threads": request["threads"],
              "model": {"id": MODEL_ID, "revision": MODEL_REVISION, "files": model_files},
              "dataset": data_identity, "baseline_evaluation": baseline, "outputs": baseline_outputs,
              "updates_completed": 0, "artifacts": [], "better_answers_claimed": False,
              "network_policy_changed": False, "distributed_training_claimed": False}
    if input_adapter is not None:
        result["input_adapter"] = input_adapter
    if request["mode"] == "train":
        if input_adapter is None:
            model = new_lora(model, peft)
        trainable = [tensor for name, tensor in model.named_parameters() if tensor.requires_grad]
        require(sum(tensor.numel() for tensor in trainable) == 230400
                and all((".lora_" in name) == tensor.requires_grad for name, tensor in model.named_parameters()),
                "UNEXPECTED_TRAINABLE_PARAMETERS")
        base_before = parameter_hash(model, False, session)
        adapter_before = parameter_hash(model, True, session)
        if input_adapter is not None:
            require(adapter_before == input_adapter["applied_parameters"], "WARMSTART_ADAPTER_CHANGED")
        optimizer = torch.optim.AdamW(trainable, lr=0.0005, weight_decay=0.0)
        losses = []
        for step in range(request["steps"]):
            session.progress("training", step)
            model.train()
            optimizer.zero_grad(set_to_none=True)
            loss = model(**samples["train"][step % len(samples["train"])]).loss
            losses.append(finite_loss(loss))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(trainable, 1.0, error_if_nonfinite=True)
            session.check()
            optimizer.step()
        adapted = evaluate(model, samples["heldout"], torch, session)
        base_after = parameter_hash(model, False, session)
        adapter_after = parameter_hash(model, True, session)
        require(base_before == base_after, "BASE_WEIGHTS_CHANGED")
        require(adapter_before["parameters"] == adapter_after["parameters"]
                and adapter_before["sha256"] != adapter_after["sha256"], "ADAPTER_WEIGHTS_UNCHANGED")
        adapter_root, artifacts = save_checkpoint(model, output_root, session)
        # Release original tensors and optimizer before loading a genuinely fresh base.
        del model, optimizer, trainable, loss
        gc.collect()
        session.progress("reload", request["steps"])
        fresh = load_model(transformers, torch, model_root)
        checkpoint = prepare_adapter(str(adapter_root), output_root, owned_checkpoint=True)
        reloaded, _ = apply_adapter(fresh, checkpoint, peft, torch, session, trainable=False)
        reload_base = parameter_hash(reloaded, False, session)
        reload_adapter = parameter_hash(reloaded, True, session)
        require(reload_base == base_before and reload_adapter == adapter_after, "CHECKPOINT_RELOAD_WEIGHTS_DIFFER")
        reloaded_evaluation = evaluate(reloaded, samples["heldout"], torch, session)
        require(math.isclose(adapted["loss"], reloaded_evaluation["loss"], rel_tol=1e-5, abs_tol=1e-6),
                "CHECKPOINT_RELOAD_EVALUATION_DIFFERS")
        result.update(updates_completed=request["steps"], training_losses=losses,
                      adapted_evaluation=adapted, reloaded_evaluation=reloaded_evaluation,
                      base_before=base_before, base_after=base_after, adapter_before=adapter_before,
                      adapter_after=adapter_after, reloaded_base=reload_base, reloaded_adapter=reload_adapter,
                      base_weights_unchanged=True, adapter_weights_changed=True, checkpoint_reloaded=True,
                      lora={"rank": 4, "alpha": 8, "target_modules": ["q_proj", "v_proj"]},
                      outputs=generate(reloaded, samples["inference"], tokenizer, torch, session), artifacts=artifacts)
    if prepared_adapter is not None:
        root, original_files, _ = prepared_adapter
        require(all(file_hash(root / name, maximum=ADAPTER_FILES[name]) == metadata
                    for name, metadata in original_files.items()), "INPUT_ADAPTER_CHANGED_ON_DISK")
        if request["mode"] == "infer":
            require(parameter_hash(model, True, session) == input_adapter["applied_parameters"]
                    and parameter_hash(model, False, session) == input_adapter["base_parameters_after_apply"],
                    "INPUT_ADAPTER_CHANGED_DURING_INFERENCE")
    # Check original on-disk weights again; the public artifact identity is independent of
    # in-memory frozen-parameter comparison and is required for compatible adapter reuse.
    require(file_hash(model_root / "model.safetensors", MODEL_WEIGHT_BYTES)["sha256"] == MODEL_WEIGHT_SHA,
            "MODEL_WEIGHTS_CHANGED_ON_DISK")
    result["elapsed_ms"] = session.elapsed()
    session.progress("complete", result["updates_completed"])
    serialized = json.dumps(result, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    require(len(serialized.encode("ascii")) + 1 <= MAX_LINE, "RESULT_TOO_LARGE")
    with (output_root / "report.json").open("x", encoding="ascii") as report:
        report.write(serialized + "\n")
        report.flush()
        os.fsync(report.fileno())
    durable_file(output_root)
    return result


def stop_requested(_signum, _frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)
    request_id, session = "0" * 32, None
    try:
        raw = sys.stdin.buffer.readline(MAX_REQUEST + 1)
        require(len(raw) <= MAX_REQUEST and raw.endswith(b"\n") and sys.stdin.buffer.read(1) == b"",
                "INVALID_REQUEST_FRAME")
        value = parse_json(raw)
        if type(value) is dict and type(value.get("id")) is str and HEX32.fullmatch(value["id"]):
            request_id = value["id"]
        request = validate_request(value)
        session = Session(request)
        # Third-party diagnostics may include local paths. Only our fixed, bounded protocol
        # uses the original stdout; no raw prompt, dataset or stack trace is logged.
        with open(os.devnull, "w", encoding="ascii") as quiet:
            with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
                result = execute_job(request, session)
        emit(result)
        return 0
    except JobError as error:
        code = str(error)
    except (FileNotFoundError, NotADirectoryError):
        code = "JOB_INPUT_NOT_FOUND"
    except PermissionError:
        code = "JOB_PATH_PERMISSION_DENIED"
    except MemoryError:
        code = "JOB_MEMORY_EXHAUSTED"
    except ImportError:
        code = "BACKEND_IMPORT_FAILED"
    except Exception:
        code = "BACKEND_EXECUTION_FAILED"
    emit({"version": VERSION, "id": request_id, "kind": "result", "status": "error", "code": code,
          "elapsed_ms": session.elapsed() if session else 0})
    return 1


if __name__ == "__main__":
    sys.exit(main())
