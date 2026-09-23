#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure dispatch doubles; no safetensors/torch/model code is imported or run."""

import contextlib
import hashlib
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

from test_worker_protocol import WORKER, request


class AggregateWorkerTests(unittest.TestCase):
    def test_cohort_dispatch_preserves_three_inputs_and_validates_saved_candidate_without_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cohort_root, output = root / "cohort", root / "output"
            cohort_root.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            cohort = []
            for index in range(3):
                adapter = cohort_root / str(index)
                adapter.mkdir(mode=0o700)
                for name in WORKER.ADAPTER_FILES:
                    # These are only file-hash sentinels, not model/config bytes.
                    (adapter / name).write_bytes(f"inert input {index}/{name}".encode())
                    (adapter / name).chmod(0o600)
                files = {name: WORKER.file_hash(adapter / name, maximum=bound)
                         for name, bound in WORKER.ADAPTER_FILES.items()}
                cohort.append((adapter, files, b"inert weights"))
            records = [item[1] for item in cohort]
            original_hash = WORKER.file_hash
            saved = {name: {"bytes": 17, "sha256": hashlib.sha256(name.encode()).hexdigest()}
                     for name in WORKER.ADAPTER_FILES}
            sentinel = object()
            torch = SimpleNamespace(optim=SimpleNamespace(AdamW=mock.Mock(side_effect=AssertionError("optimizer invoked"))))
            transformers = SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=
                mock.Mock(side_effect=AssertionError("tokenizer invoked"))))
            module = ModuleType("volparossa_adapter_aggregation")
            class AggregationError(Exception):
                pass
            module.AggregationError = AggregationError
            module.aggregate = mock.Mock(return_value={"mode": "aggregate_adapter", "updates_completed": 0,
                "input_files": records, "algorithm": "coordinate-median-effective-lora-rank4-v1",
                "combined_modules": 60})
            safe = ModuleType("safetensors")
            safe_torch = ModuleType("safetensors.torch")
            safe_torch.load_file, safe_torch.save_file = sentinel, sentinel
            safe.torch = safe_torch
            options = WORKER.validate_request(dict(request(), mode="aggregate_adapter", steps=1, owner_control=True,
                adapter_root=str(cohort_root), output_root=str(output)))
            session = mock.Mock()
            session.frames = None
            prepared_order = []
            def prepare(value, owner_output, owned_checkpoint=False):
                self.assertEqual(owner_output, output)
                path = Path(value)
                prepared_order.append((path, owned_checkpoint))
                if owned_checkpoint:
                    self.assertEqual(path, output / "adapter")
                    return path, saved, b"saved inert weights"
                return next(item for item in cohort if item[0] == path)
            with contextlib.ExitStack() as patches:
                patches.enter_context(mock.patch.dict(sys.modules, {
                    "volparossa_adapter_aggregation": module, "safetensors": safe, "safetensors.torch": safe_torch}))
                patches.enter_context(mock.patch.object(WORKER, "prepare_files", return_value=(
                    root / "model", output, {}, {"visibility": "public"}, {})))
                prepare_spy = patches.enter_context(mock.patch.object(WORKER, "prepare_adapter", side_effect=prepare))
                hashes = patches.enter_context(mock.patch.object(WORKER, "file_hash", wraps=original_hash))
                patches.enter_context(mock.patch.object(WORKER, "configure_offline"))
                backend = patches.enter_context(mock.patch.object(WORKER, "load_backend", return_value=(
                    torch, transformers, sentinel, {"inert": "test-only"})))
                load_model = patches.enter_context(mock.patch.object(WORKER, "load_model",
                    side_effect=AssertionError("base model invoked")))
                finish = patches.enter_context(mock.patch.object(WORKER, "finish_result",
                    side_effect=lambda result, _output, _session: result))
                result = WORKER.execute_job(options, session)
            self.assertEqual(prepared_order, [(path, False) for path, _, _ in cohort]
                             + [(output / "adapter", True)])
            self.assertEqual(prepare_spy.call_count, 4)
            backend.assert_called_once_with(2, session)
            module.aggregate.assert_called_once_with(torch, sentinel, sentinel, [item[0] for item in cohort],
                                                     output / "adapter", session.check, session.progress)
            self.assertEqual(hashes.call_count, 9)
            self.assertEqual({call.args[0] for call in hashes.call_args_list},
                             {path / name for path, _, _ in cohort for name in WORKER.ADAPTER_FILES})
            self.assertEqual(result["aggregation"]["input_files"], records)
            self.assertEqual(result["mode"], "aggregate_adapter")
            self.assertEqual(result["updates_completed"], 0)
            self.assertFalse(result["model_weights_loaded"])
            self.assertFalse(result["better_answers_claimed"])
            self.assertFalse(result["distributed_training_claimed"])
            self.assertNotIn("input_adapter", result)
            self.assertEqual(result["artifacts"], [{"relative_path": "adapter/" + name, **saved[name]}
                                                  for name in sorted(saved)])
            load_model.assert_not_called()
            transformers.AutoTokenizer.from_pretrained.assert_not_called()
            torch.optim.AdamW.assert_not_called()
            finish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
