# SPDX-License-Identifier: GPL-3.0-only
"""Fixed CPU adapter algebra; imports no model/backend and grants no activation authority.

The caller verifies three signed public inputs and calls worker.prepare_adapter on
each before entry. The supervisor provides read-only input mounts, owner control
and hard resource limits. Numerical execution is confined to that worker.
"""

import hashlib
import math
import os
from pathlib import Path
import stat


ALGORITHM = "coordinate-median-effective-lora-rank4-v1"
FILES = {"adapter_config.json": 16384, "adapter_model.safetensors": 2 * 1024 * 1024,
         "README.md": 16384}


class AggregationError(Exception):
    """Fixed content-free rejection, not a backend or input diagnostic."""


def _require(condition, code):
    if not condition:
        raise AggregationError(code)


def shapes():
    return {f"base_model.model.model.layers.{layer}.self_attn.{module}.lora_{matrix}.weight": shape
            for layer in range(30)
            for module, width in (("q_proj", 576), ("v_proj", 192))
            for matrix, shape in (("A", (4, 576)), ("B", (width, 4)))}


def _run(check, operation):
    # A native call cannot acknowledge pause mid-operation. The outer supervisor
    # still owns the deadline/kill/reap boundary; ACK happens only at checkpoints.
    check()
    try:
        value = operation()
    except (RuntimeError, ValueError):
        raise AggregationError("AGGREGATION_BACKEND_FAILED") from None
    check()
    return value


def _read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and info.st_uid == os.geteuid() and not info.st_mode & 0o022
                 and 0 < info.st_size <= maximum, "AGGREGATION_INPUT_FILE")
        raw = source.read(maximum + 1)
    _require(0 < len(raw) <= maximum, "AGGREGATION_INPUT_FILE")
    return raw


def _snapshot(root):
    info = root.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and not info.st_mode & 0o022, "AGGREGATION_INPUT_DIRECTORY")
    _require({item.name for item in root.iterdir()} == FILES.keys(), "AGGREGATION_INPUT_FILES")
    payloads = {name: _read(root / name, limit) for name, limit in FILES.items()}
    return ({name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
             for name, raw in payloads.items()}, payloads)


def _finite(torch, value, check):
    _require(_run(check, lambda: torch.isfinite(value).all().item()), "AGGREGATION_NONFINITE")


def _validate_tensors(torch, tensors, check):
    expected = shapes()
    _require(type(tensors) is dict and tensors.keys() == expected.keys(), "AGGREGATION_TENSOR_KEYS")
    for name, shape in expected.items():
        value = tensors[name]
        _require(value.dtype == torch.float32 and value.device.type == "cpu"
                 and tuple(value.shape) == shape, "AGGREGATION_TENSOR_FORMAT")
        _finite(torch, value, check)


def _norm(torch, value, check):
    result = _run(check, lambda: torch.linalg.vector_norm(value).item())
    _require(type(result) is float and math.isfinite(result) and result >= 0,
             "AGGREGATION_METRIC_NONFINITE")
    return result


def _combine_module(torch, pairs, check):
    # Every input uses the same frozen base and alpha/r = 8/4 = 2. Combine
    # absolute effective deltas, not LoRA factors or warmstart-relative updates.
    deltas = []
    for a, b in pairs:
        a64 = _run(check, lambda: a.to(dtype=torch.float64))
        b64 = _run(check, lambda: b.to(dtype=torch.float64))
        delta = _run(check, lambda: 2.0 * (b64 @ a64))
        _finite(torch, delta, check)
        deltas.append(delta)
    median = _run(check, lambda: torch.median(torch.stack(deltas, dim=0), dim=0).values)
    _finite(torch, median, check)
    del deltas
    u, s, vh = _run(check, lambda: torch.linalg.svd(median, full_matrices=False))
    for tensor in (u, s, vh):
        _finite(torch, tensor, check)
    _require(_run(check, lambda: (s >= 0).all().item()), "AGGREGATION_SINGULAR_VALUES")
    scale = _run(check, lambda: torch.sqrt(s[:4] / 2.0))
    b64 = _run(check, lambda: u[:, :4] * scale.unsqueeze(0))
    a64 = _run(check, lambda: scale.unsqueeze(1) * vh[:4, :])
    projected = _run(check, lambda: 2.0 * (b64 @ a64))
    target_norm = _norm(torch, median, check)
    truncation_norm = _norm(torch, _run(check, lambda: median - projected), check)
    a = _run(check, lambda: a64.to(dtype=torch.float32).contiguous())
    b = _run(check, lambda: b64.to(dtype=torch.float32).contiguous())
    _finite(torch, a, check)
    _finite(torch, b, check)
    # Measure actual FP32 output reconstruction as well as mathematical rank
    # truncation; neither residual is a claim about model answer quality.
    stored = _run(check, lambda: 2.0 * (b.to(dtype=torch.float64) @ a.to(dtype=torch.float64)))
    stored_norm = _norm(torch, _run(check, lambda: median - stored), check)
    return a, b, (target_norm, truncation_norm, stored_norm)


def _readme(payloads):
    result = ("# Aggregated adapter candidate\n\n"
              f"Algorithm: {ALGORITHM}. Three inputs; no optimizer updates.\n"
              "No quality, Byzantine-resilience or Sybil-resistance claim.\n"
              "Original distinct input model cards and notices follow unchanged.\n").encode()
    seen = set()
    for index, files in enumerate(payloads):
        original = files["README.md"]
        if original not in seen:
            result += f"\n## Original input {index}\n\n".encode() + original
            seen.add(original)
    _require(len(result) <= FILES["README.md"], "AGGREGATION_README_TOO_LARGE")
    return result


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def _sync(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def aggregate(torch, load_file, save_file, inputs: list[Path], output: Path, check, progress) -> dict:
    """Write exactly three adapter files into a NEW directory; return algebra evidence.

    load_file/save_file are the pinned safetensors.torch callables. progress has
    Session.progress's (phase, step) signature. The caller must validate the saved
    adapter with prepare_adapter and independently evaluate before activation.
    """
    _require(type(inputs) is list and len(inputs) == 3 and all(isinstance(p, Path) for p in inputs),
             "AGGREGATION_INPUT_COUNT")
    _require(isinstance(output, Path) and output.is_absolute() and not os.path.lexists(output),
             "AGGREGATION_OUTPUT_NOT_FRESH")
    roots = [path.resolve(strict=True) for path in inputs]
    destination = output.parent.resolve(strict=True) / output.name
    _require(len(set(roots)) == 3 and all(not destination.is_relative_to(path)
             and not path.is_relative_to(destination) for path in roots), "AGGREGATION_PATH_OVERLAP")
    check()
    snapshots = [_snapshot(path) for path in inputs]
    identities = [item[0] for item in snapshots]
    payloads = [item[1] for item in snapshots]
    readme = _readme(payloads)
    weights = [_run(check, lambda path=path: load_file(str(path / "adapter_model.safetensors"), device="cpu"))
               for path in inputs]
    for tensors in weights:
        _validate_tensors(torch, tensors, check)
    result, norms = {}, (0.0, 0.0, 0.0)
    completed = 0
    progress("checkpoint", completed)
    with torch.inference_mode():
        for layer in range(30):
            for module in ("q_proj", "v_proj"):
                prefix = f"base_model.model.model.layers.{layer}.self_attn.{module}.lora_"
                name_a, name_b = prefix + "A.weight", prefix + "B.weight"
                a, b, measured = _combine_module(torch, [(w[name_a], w[name_b]) for w in weights], check)
                result[name_a], result[name_b] = a, b
                norms = tuple(math.hypot(total, value) for total, value in zip(norms, measured))
                _require(all(math.isfinite(value) for value in norms), "AGGREGATION_METRIC_NONFINITE")
                completed += 1
                progress("checkpoint", completed)
    _validate_tensors(torch, result, check)
    check()
    _require([_snapshot(path)[0] for path in inputs] == identities, "AGGREGATION_INPUT_CHANGED")
    output.mkdir(mode=0o700)
    _write(output / "adapter_config.json", payloads[0]["adapter_config.json"])
    _write(output / "README.md", readme)
    # Reserve the new destination exclusively. Pinned safetensors 0.8 replaces
    # it via a new 0600 NamedTempFile, rather than preserving this inode's mode.
    # Verify the replacement's privacy; partial output is never success.
    weight_path = output / "adapter_model.safetensors"
    descriptor = os.open(weight_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    _run(check, lambda: save_file(result, str(weight_path), metadata={"format": "pt"}))
    _require(stat.S_IMODE(weight_path.lstat().st_mode) == 0o600, "AGGREGATION_OUTPUT_PERMISSIONS")
    _sync(weight_path)
    _sync(output)
    _sync(output.parent)
    artifacts = _snapshot(output)[0]
    check()
    _require([_snapshot(path)[0] for path in inputs] == identities, "AGGREGATION_INPUT_CHANGED")
    return {"mode": "aggregate_adapter", "updates_completed": 0, "algorithm": ALGORITHM,
            "input_count": 3, "input_files": identities, "combined_modules": completed,
            "rank": 4, "alpha": 8, "calculation_dtype": "float64", "output_dtype": "float32",
            "metrics": {"target_frobenius_norm": norms[0], "rank4_residual_frobenius_norm": norms[1],
                        "stored_fp32_residual_frobenius_norm": norms[2]},
            "artifacts": [{"relative_path": "adapter/" + name, **artifacts[name]} for name in sorted(FILES)],
            "model_weights_loaded": False, "model_quality_proven": False,
            "byzantine_resilience_proven": False, "sybil_resistance_proven": False}
