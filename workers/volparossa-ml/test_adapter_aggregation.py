#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stdlib-only admission/control/operation doubles; NOT numerical or model proof."""

import ast
import contextlib
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("adapter_aggregation", ROOT / "adapter_aggregation.py")
AGG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AGG)


class Tensor:
    """Operation recorder: it does not calculate or pretend to calculate tensors."""

    def __init__(self, tag, events, shape=(), dtype="f32", finite=True):
        self.tag, self.events, self.shape, self.dtype, self.finite = tag, events, shape, dtype, finite
        self.device = SimpleNamespace(type="cpu")

    def child(self, operation, shape=(), dtype=None):
        self.events.append(operation)
        return Tensor(operation, self.events, shape, dtype or self.dtype, self.finite)

    def to(self, *, dtype):
        return self.child(("to", self.tag, dtype), self.shape, dtype)

    def contiguous(self):
        return self.child(("contiguous", self.tag), self.shape)

    def __matmul__(self, other):
        return self.child(("matmul", self.tag, other.tag))

    def __rmul__(self, value):
        return self.child(("scalar_mul", value, self.tag))

    def __mul__(self, other):
        return self.child(("multiply", self.tag, other.tag))

    def __truediv__(self, value):
        return self.child(("divide", self.tag, value))

    def __getitem__(self, value):
        return self.child(("slice", self.tag, value))

    def unsqueeze(self, dimension):
        return self.child(("unsqueeze", self.tag, dimension))

    def __sub__(self, other):
        return self.child(("subtract", self.tag, other.tag))

    def __ge__(self, value):
        return self.child(("ge", self.tag, value))

    def all(self):
        return self

    def item(self):
        return self.finite


class Backend:
    float32, float64 = "f32", "f64"

    def __init__(self):
        self.events = []
        self.linalg = SimpleNamespace(svd=self.svd, vector_norm=lambda tensor: SimpleNamespace(item=lambda: 1.0))

    def inference_mode(self):
        return contextlib.nullcontext()

    def isfinite(self, tensor):
        self.events.append(("isfinite", tensor.tag))
        return tensor

    def stack(self, tensors, *, dim):
        self.events.append(("stack", [tensor.tag for tensor in tensors], dim))
        return Tensor("stacked", self.events, dtype=self.float64)

    def median(self, tensor, *, dim):
        self.events.append(("median", tensor.tag, dim))
        return SimpleNamespace(values=Tensor("median", self.events, dtype=self.float64))

    def svd(self, tensor, *, full_matrices):
        self.events.append(("svd", tensor.tag, tensor.dtype, full_matrices))
        return tuple(Tensor(name, self.events, dtype=self.float64) for name in ("U", "S", "Vh"))

    def sqrt(self, tensor):
        return tensor.child(("sqrt", tensor.tag))


class AggregationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = []
        for index in range(3):
            directory = self.root / f"input-{index}"
            directory.mkdir(mode=0o700)
            for name, raw in {"adapter_config.json": b'{"inert_test_config":true}',
                              "adapter_model.safetensors": f"inert input {index}; not weights".encode(),
                              "README.md": f"Original notice {index}\n".encode()}.items():
                AGG._write(directory / name, raw)
            self.inputs.append(directory)
        self.output = self.root / "adapter"
        self.torch = Backend()
        self.check, self.progress = mock.Mock(), mock.Mock()

    def tensors(self):
        return {name: Tensor(name, self.torch.events, shape) for name, shape in AGG.shapes().items()}

    def load(self, filename, *, device):
        self.assertEqual(device, "cpu")
        self.assertIn(Path(filename).parent, self.inputs)
        return self.tensors()

    def save(self, tensors, filename, *, metadata):
        self.assertEqual(set(tensors), set(AGG.shapes()))
        self.assertEqual(metadata, {"format": "pt"})
        self.assertEqual(Path(filename).stat().st_mode & 0o777, 0o600)
        # An inert serialization sentinel, never passed to the real worker.
        Path(filename).write_bytes(b"inert output; NOT safetensors or numerical evidence")

    def fake_module(self, torch, pairs, check):
        check()
        a, b = pairs[0]
        return a, b, (3.0, 0.5, 0.6)

    def invoke(self):
        return AGG.aggregate(self.torch, self.load, self.save, self.inputs, self.output,
                             self.check, self.progress)

    def test_only_stdlib_imports_and_exact_current_worker_shapes(self):
        tree = ast.parse((ROOT / "adapter_aggregation.py").read_text())
        imports = {node.names[0].name if isinstance(node, ast.Import) else node.module
                   for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))}
        self.assertEqual(imports, {"hashlib", "math", "os", "pathlib", "stat"})
        worker = ast.parse((ROOT / "worker.py").read_text())
        function = next(node for node in worker.body if isinstance(node, ast.FunctionDef)
                        and node.name == "adapter_shapes")
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<inert-shapes>", "exec"), namespace)
        self.assertEqual(AGG.shapes(), {name: tuple(shape) for name, shape in namespace["adapter_shapes"]().items()})
        self.assertEqual(len(AGG.shapes()), 120)
        self.assertEqual(sum(math.prod(shape) for shape in AGG.shapes().values()), 230400)

    def test_exact_three_distinct_inputs_and_fresh_disjoint_output(self):
        for inputs in (self.inputs[:2], self.inputs + self.inputs[:1], tuple(self.inputs)):
            with self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_INPUT_COUNT$"):
                AGG.aggregate(None, None, None, inputs, self.output, self.check, self.progress)
        with self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_PATH_OVERLAP$"):
            AGG.aggregate(None, None, None, self.inputs[:2] + self.inputs[:1], self.output,
                          self.check, self.progress)
        with self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_PATH_OVERLAP$"):
            AGG.aggregate(None, None, None, self.inputs, self.inputs[0] / "nested", self.check, self.progress)
        self.output.mkdir()
        with self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_OUTPUT_NOT_FRESH$"):
            self.invoke()

    def test_tensor_names_shapes_cpu_fp32_and_finiteness_are_checked(self):
        for mutation, code in (
                (lambda values: values.pop(next(iter(values))), "TENSOR_KEYS"),
                (lambda values: setattr(next(iter(values.values())), "shape", (4, 577)), "TENSOR_FORMAT"),
                (lambda values: setattr(next(iter(values.values())), "dtype", "f64"), "TENSOR_FORMAT"),
                (lambda values: setattr(next(iter(values.values())).device, "type", "cuda"), "TENSOR_FORMAT"),
                (lambda values: setattr(next(iter(values.values())), "finite", False), "NONFINITE")):
            values = self.tensors()
            mutation(values)
            with self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_" + code + "$"):
                AGG._validate_tensors(self.torch, values, self.check)

    def test_operation_trace_is_delta_median_then_fp64_svd_with_scaling_two(self):
        pairs = [(Tensor(f"A{i}", self.torch.events), Tensor(f"B{i}", self.torch.events)) for i in range(3)]
        a, b, metrics = AGG._combine_module(self.torch, pairs, self.check)
        events = self.torch.events
        for index in range(3):
            multiplication = ("matmul", ("to", f"B{index}", "f64"), ("to", f"A{index}", "f64"))
            self.assertIn(("scalar_mul", 2.0, multiplication), events)
        stack = next(event for event in events if event[0] == "stack")
        self.assertEqual(len(stack[1]), 3)
        self.assertEqual(stack[2], 0)
        self.assertIn(("median", "stacked", 0), events)
        self.assertIn(("svd", "median", "f64", False), events)
        self.assertIn(("divide", ("slice", "S", slice(None, 4)), 2.0), events)
        self.assertEqual((a.dtype, b.dtype), ("f32", "f32"))
        self.assertEqual(metrics, (1.0, 1.0, 1.0))  # recorder constants, not numerical proof
        self.assertGreaterEqual(self.check.call_count, 50)

    def test_owner_cancellation_is_not_converted_into_backend_error(self):
        class OwnerCancelled(Exception):
            pass
        self.check.side_effect = OwnerCancelled("fixed owner stop")
        with self.assertRaises(OwnerCancelled):
            self.invoke()
        self.assertFalse(self.output.exists())
        operation = mock.Mock()
        with self.assertRaises(OwnerCancelled):
            AGG._run(self.check, operation)
        operation.assert_not_called()
        self.check.side_effect = [None, OwnerCancelled("cancel after native operation")]
        with self.assertRaises(OwnerCancelled):
            AGG._run(self.check, operation)
        operation.assert_called_once_with()
        with self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_BACKEND_FAILED$"):
            AGG._run(lambda: None, mock.Mock(side_effect=RuntimeError("private backend details")))

    def test_nonfinite_median_or_fp32_conversion_is_not_saved(self):
        pairs = [(Tensor(f"A{i}", self.torch.events), Tensor(f"B{i}", self.torch.events)) for i in range(3)]
        original = self.torch.isfinite
        for reject in (lambda tag: tag == "median",
                       lambda tag: isinstance(tag, tuple) and tag[0] == "contiguous"):
            def finite(tensor):
                if reject(tensor.tag):
                    return SimpleNamespace(all=lambda: SimpleNamespace(item=lambda: False))
                return original(tensor)
            with mock.patch.object(self.torch, "isfinite", side_effect=finite), \
                    self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_NONFINITE$"):
                AGG._combine_module(self.torch, pairs, self.check)
        self.assertFalse(self.output.exists())

    def test_complete_inert_flow_preserves_inputs_notices_and_zero_training(self):
        before = [AGG._snapshot(path)[0] for path in self.inputs]
        with mock.patch.object(AGG, "_combine_module", side_effect=self.fake_module) as combine:
            report = self.invoke()
        self.assertEqual(combine.call_count, 60)
        self.assertEqual(report["mode"], "aggregate_adapter")
        self.assertEqual(report["algorithm"], "coordinate-median-effective-lora-rank4-v1")
        self.assertEqual(report["updates_completed"], 0)
        self.assertEqual(report["combined_modules"], 60)
        self.assertEqual(report["input_files"], before)
        self.assertEqual([AGG._snapshot(path)[0] for path in self.inputs], before)
        self.assertEqual(self.progress.call_args_list,
                         [mock.call("checkpoint", count) for count in range(61)])
        self.assertEqual({path.name for path in self.output.iterdir()}, set(AGG.FILES))
        self.assertEqual((self.output / "adapter_config.json").read_bytes(),
                         (self.inputs[0] / "adapter_config.json").read_bytes())
        readme = (self.output / "README.md").read_bytes()
        for path in self.inputs:
            self.assertIn((path / "README.md").read_bytes(), readme)
        for artifact in report["artifacts"]:
            path = self.output / Path(artifact["relative_path"]).name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), artifact["sha256"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(all(math.isfinite(value) for value in report["metrics"].values()))
        self.assertLess(len(json.dumps(report)), 16384)
        self.assertFalse(report["model_weights_loaded"])
        self.assertFalse(report["model_quality_proven"])
        self.assertFalse(report["byzantine_resilience_proven"])
        self.assertFalse(report["sybil_resistance_proven"])

    def test_changed_input_and_excess_notice_bytes_fail_without_output(self):
        def modified(torch, pairs, check):
            (self.inputs[1] / "README.md").write_bytes(b"changed original")
            return self.fake_module(torch, pairs, check)
        with mock.patch.object(AGG, "_combine_module", side_effect=modified), \
                self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_INPUT_CHANGED$"):
            self.invoke()
        self.assertFalse(self.output.exists())
        payloads = [{"README.md": b"same original notice"}] * 3
        self.assertEqual(AGG._readme(payloads).count(b"same original notice"), 1)
        with self.assertRaisesRegex(AGG.AggregationError, "^AGGREGATION_README_TOO_LARGE$"):
            AGG._readme([{"README.md": bytes([letter]) * 16384} for letter in (65, 66, 67)])


if __name__ == "__main__":
    unittest.main()
