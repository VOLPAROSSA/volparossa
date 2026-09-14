#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Standard-library framing/admission checks; never a successful-model execution claim."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
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
