#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Standard-library framing/admission checks; never a successful-model execution claim."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).with_name("worker.py")
SPEC = importlib.util.spec_from_file_location("volparossa_ml_worker", SOURCE)
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


def request():
    return {"version": 1, "id": "a" * 32, "mode": "train", "model_root": "/model",
            "dataset_path": "/dataset.json", "output_root": "/output"}


def dataset():
    return {"version": 1, "visibility": "public", "license": "GPL-3.0-only", "source_revision": "b" * 40,
            "train": [{"question": "Which platform?", "answer": "Debian 13 amd64.",
                       "context": "The project targets Debian 13 amd64."}],
            "heldout": [{"question": "What is the supported architecture?", "answer": "amd64.",
                         "context": "The project targets Debian 13 amd64."}],
            "inference": [{"question": "Which Debian release?", "context": "Debian 13 is supported."}]}


def adapter_config():
    return {"base_model_name_or_path": WORKER.MODEL_ID, "revision": WORKER.MODEL_REVISION,
            "peft_type": "LORA", "task_type": "CAUSAL_LM", "r": 4, "lora_alpha": 8,
            "lora_dropout": 0.0, "bias": "none", "inference_mode": True,
            "target_modules": ["q_proj", "v_proj"], **WORKER.ADAPTER_DEFAULTS}


def adapter_bytes(header_change=None, last_float=0.0):
    # Synthetic safetensors parser fixture, not trained weights or execution evidence.
    header, offset = {"__metadata__": {"format": "pt"}}, 0
    for name, shape in WORKER.adapter_shapes().items():
        length = shape[0] * shape[1] * 4
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + length]}
        offset += length
    if header_change:
        header_change(header)
    raw_header = json.dumps(header, separators=(",", ":")).encode("utf-8")
    raw_header += b" " * (-len(raw_header) % 8)
    return len(raw_header).to_bytes(8, "little") + raw_header + bytes(offset - 4) + struct.pack("<f", last_float)


class WorkerProtocolTests(unittest.TestCase):
    def test_request_schema_preserves_id_and_enforces_real_resource_caps(self):
        parsed = WORKER.validate_request(request())
        self.assertEqual(parsed["id"], "a" * 32)
        self.assertEqual((parsed["steps"], parsed["threads"], parsed["max_seconds"]), (8, 2, 600))
        for field, values in {"version": [True, 2], "id": ["A" * 32, "a" * 31],
                              "mode": ["shell", "classify"], "steps": [0, 65, True],
                              "threads": [0, 3], "max_seconds": [0, 601],
                              "model_root": ["relative", "/", "/bad\x00path"]}.items():
            for value in values:
                invalid = request()
                invalid[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(WORKER.JobError):
                    WORKER.validate_request(invalid)
        invalid = request()
        invalid["command"] = "unused"
        with self.assertRaises(WORKER.JobError):
            WORKER.validate_request(invalid)

    def test_optional_adapter_path_preserves_old_request_and_supports_both_modes(self):
        self.assertNotIn("adapter_root", WORKER.validate_request(request()))
        for mode in ("infer", "train"):
            source = dict(request(), adapter_root="/adapter", mode=mode)
            self.assertEqual(WORKER.validate_request(source)["adapter_root"], "/adapter")
        for value in (None, "", "relative", "/", "/a\x00b", 42):
            with self.assertRaisesRegex(WORKER.JobError, "INVALID_JOB_PATH"):
                WORKER.validate_request(dict(request(), adapter_root=value))

    def test_adapter_configuration_is_admission_only_with_no_dynamic_operator(self):
        config = adapter_config()
        WORKER.validate_adapter_config(config)
        WORKER.validate_adapter_config(dict(config, target_modules=["v_proj", "q_proj"]))
        for name, value in (("base_model_name_or_path", "other/model"), ("revision", "main"),
                            ("r", 8), ("r", True), ("lora_alpha", 16), ("lora_dropout", 0.1),
                            ("target_modules", "all-linear"), ("target_modules", ["q_proj", "q_proj"]),
                            ("bias", "all"), ("auto_mapping", {"parent_library": "unsafe"}),
                            ("init_lora_weights", "pissa"), ("modules_to_save", ["lm_head"]),
                            ("use_dora", True), ("layer_replication", [[0, 30]]),
                            ("runtime_config", {}), ("unrecognized_extension", None)):
            with self.subTest(name=name), self.assertRaisesRegex(WORKER.JobError, "UNSUPPORTED_ADAPTER_CONFIG"):
                WORKER.validate_adapter_config(dict(config, **{name: value}))

    def test_safetensors_requires_all_exact_fp32_shapes_dense_offsets_and_finite_values(self):
        WORKER.validate_adapter_weights(adapter_bytes())
        self.assertEqual(len(WORKER.adapter_shapes()), 120)
        name = next(iter(WORKER.adapter_shapes()))
        mutations = [
            lambda h: h.pop(name),
            lambda h: h.update({"unexpected.weight": h[name]}),
            lambda h: h[name].update(dtype="F16"),
            lambda h: h[name].update(shape=[8, 576]),
            lambda h: h[name].update(data_offsets=[4, 9220]),
            lambda h: h.update({"__metadata__": {"custom_loader": "unsafe"}}),
        ]
        for mutation in mutations:
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_adapter_weights(adapter_bytes(mutation))
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaisesRegex(WORKER.JobError, "NONFINITE_ADAPTER_WEIGHTS"):
                WORKER.validate_adapter_weights(adapter_bytes(last_float=value))
        with self.assertRaises(WORKER.JobError):
            WORKER.validate_adapter_weights(adapter_bytes() + b"trailing")

    def test_actual_temporary_adapter_files_are_hash_bound_and_not_executable_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "adapter"
            root.mkdir(mode=0o700)
            output = Path(directory) / "output"
            output.mkdir(mode=0o700)
            contents = {"adapter_config.json": json.dumps(adapter_config()).encode(),
                        "adapter_model.safetensors": adapter_bytes(), "README.md": b"Synthetic parser fixture.\n"}
            for name, raw in contents.items():
                (root / name).write_bytes(raw)
                (root / name).chmod(0o600)
            actual_root, files, weights = WORKER.prepare_adapter(str(root), output)
            self.assertEqual(actual_root, root)
            self.assertEqual(weights, contents["adapter_model.safetensors"])
            self.assertEqual(set(files), set(WORKER.ADAPTER_FILES))
            for name, item in files.items():
                self.assertEqual(item, WORKER.file_hash(root / name))
            with self.assertRaisesRegex(WORKER.JobError, "ADAPTER_OUTPUT_PATH_OVERLAP"):
                WORKER.prepare_adapter(str(root), Path(directory))
            (root / "extra.py").write_bytes(b"never executed")
            with self.assertRaisesRegex(WORKER.JobError, "UNSUPPORTED_ADAPTER_FILES"):
                WORKER.prepare_adapter(str(root), output)
            (root / "extra.py").unlink()
            (root / "README.md").unlink()
            (root / "README.md").symlink_to(output)
            with self.assertRaises((OSError, WORKER.JobError)):
                WORKER.prepare_adapter(str(root), output)
            (root / "README.md").unlink()
            (root / "README.md").write_bytes(b"x" * 16385)
            with self.assertRaisesRegex(WORKER.JobError, "ARTIFACT_TOO_LARGE"):
                WORKER.prepare_adapter(str(root), output)

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        for raw in (b'{"version":1,"version":1}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}'):
            with self.assertRaises(WORKER.JobError):
                WORKER.parse_json(raw)

    def test_explicit_public_data_requires_disjoint_heldout_questions(self):
        original = dataset()
        self.assertEqual(WORKER.validate_dataset(original, "train"), original)
        for field, value in (("visibility", "private"), ("license", "unknown"), ("source_revision", "latest")):
            invalid = copy.deepcopy(original)
            invalid[field] = value
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(invalid, "train")
        invalid = copy.deepcopy(original)
        invalid["heldout"][0]["question"] = "  WHICH PLATFORM? "
        with self.assertRaisesRegex(WORKER.JobError, "TRAIN_HELDOUT_OVERLAP"):
            WORKER.validate_dataset(invalid, "train")
        for split in ("train", "heldout", "inference"):
            invalid = copy.deepcopy(original)
            invalid[split] *= 2
            with self.assertRaises(WORKER.JobError):
                WORKER.validate_dataset(invalid, "train")

    def test_output_frame_cap_is_applied_before_any_write(self):
        previous = WORKER.WIRE_OUTPUT
        output = io.StringIO()
        WORKER.WIRE_OUTPUT = output
        try:
            with self.assertRaisesRegex(WORKER.JobError, "RESULT_TOO_LARGE"):
                WORKER.emit({"value": "x" * WORKER.MAX_LINE})
            self.assertEqual(output.getvalue(), "")
        finally:
            WORKER.WIRE_OUTPUT = previous

    def run_embedded(self, raw):
        # The actual deployment mode has no __file__ and a bounded stdin/stdout contract.
        return subprocess.run([sys.executable, "-I", "-c", SOURCE.read_text(encoding="utf-8")],
                              input=raw, capture_output=True, timeout=10, check=False)

    def test_real_embedded_process_rejects_extra_frames_and_preserves_valid_correlation(self):
        invalid = request()
        invalid["steps"] = 65
        process = self.run_embedded(json.dumps(invalid).encode("utf-8") + b"\n")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stderr, b"")
        result = json.loads(process.stdout)
        self.assertEqual((result["id"], result["kind"], result["status"], result["code"]),
                         ("a" * 32, "result", "error", "INVALID_JOB_BUDGET"))
        process = self.run_embedded(json.dumps(request()).encode("utf-8") + b"\n{}\n")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(process.stdout)["code"], "INVALID_REQUEST_FRAME")

    def test_all_original_model_files_are_bound_not_only_weights(self):
        self.assertEqual(set(WORKER.MODEL_FILES), set(WORKER.MODEL_HASHES))
        self.assertEqual(len(WORKER.MODEL_FILES), 8)
        self.assertEqual(WORKER.MODEL_FILES["model.safetensors"], 269060552)
        self.assertEqual(WORKER.MODEL_HASHES["model.safetensors"], WORKER.MODEL_WEIGHT_SHA)
        for digest in WORKER.MODEL_HASHES.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
