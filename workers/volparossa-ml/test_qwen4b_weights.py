# SPDX-License-Identifier: GPL-3.0-only
"""Pinned asset and bounded protocol tests; no model is installed or executed."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from test_conversation import CONVERSATION, WORKER, conversation
from test_worker_protocol import request

SPEC = importlib.util.spec_from_file_location("qwen4b_provision", Path(__file__).with_name("provision.py"))
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)
PROFILE = WORKER.QWEN4B_MODEL_PROFILE


def synthetic_shards(root):
    """Tiny original files test byte accounting; they are not model weights."""
    names = tuple(PROVISION.QWEN4B_SHARDS)
    blocks = (b"original first shard", b"second shard bytes", b"third")
    index = json.dumps({"metadata": {"total_size": 999999},
                        "weight_map": {f"tensor_{i}": names[i % 3] for i in range(398)}}).encode()
    contents = dict(zip(names, blocks))
    contents["model.safetensors.index.json"] = index
    for name, data in contents.items():
        (root / name).write_bytes(data)
    identity = {"layout": "safetensors_shards_concat_v1", "bytes": sum(map(len, blocks)),
                "sha256": hashlib.sha256(b"".join(blocks)).hexdigest(), "files": list(names)}
    profile = {"files": {name: len(data) for name, data in contents.items()},
               "hashes": {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
               "weight_shards": names, "weights": identity}
    pins = {"files": [{"path": name, "bytes": len(data), "sha256": profile["hashes"][name]}
                      for name, data in contents.items()], "weights": identity}
    return profile, pins


class Qwen4bWeightsTests(unittest.TestCase):
    def test_exact_original_assets_and_runtime_are_pinned(self):
        pins = PROVISION.load_pins(PROFILE)
        profile = WORKER.model_profile(PROFILE)
        self.assertEqual(pins["wheels"], PROVISION.load_pins()["wheels"])
        self.assertEqual(len(pins["files"]), 12)
        self.assertEqual(pins["weights"], profile["weights"])
        self.assertEqual(pins["weights"]["bytes"], 8044982000)
        self.assertNotEqual(pins["weights"]["sha256"], profile["hashes"]["model.safetensors.index.json"])
        self.assertEqual(set(profile["files"]), {item["path"] for item in pins["files"]})
        for item in pins["files"]:
            self.assertEqual((item["bytes"], item["sha256"]),
                             (profile["files"][item["path"]], profile["hashes"][item["path"]]))
        self.assertEqual(sum(profile["files"][name] for name in profile["weight_shards"]),
                         pins["weights"]["bytes"])
        self.assertNotIn("model.safetensors", profile["files"])

    def test_owner_selected_private_conversation_only_and_explicit_context(self):
        job = dict(request(), mode="private_conversation", model_profile=PROFILE,
                   steps=1, owner_control=True)
        WORKER.validate_request(job)
        for mode in ("infer", "private_infer", "train", "plan_document", "plan_tasks", "aggregate_adapter"):
            with self.subTest(mode=mode), self.assertRaises(WORKER.JobError):
                WORKER.validate_request(dict(job, mode=mode))
        profile = WORKER.model_profile(PROFILE)
        caps = CONVERSATION.capabilities(PROFILE, profile)
        old = CONVERSATION.capabilities(WORKER.QWEN_MODEL_PROFILE, WORKER.model_profile(WORKER.QWEN_MODEL_PROFILE))
        expected = dict(old, model_profile=PROFILE, model_context_tokens=262144,
                        conversation_template="qwen3-tools-instruct-2507-v1")
        self.assertEqual(caps, expected)
        data = dict(conversation(), generation_policy="greedy_v1", instructions="i" * 20903)
        self.assertIs(WORKER.validate_dataset(data, "private_conversation", PROFILE), data)

    def test_streamed_raw_concatenation_and_report_preserve_original_shard_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, pins = synthetic_shards(root)
            files = {}
            self.assertEqual(WORKER.verify_sharded_weights(root, profile, files), profile["weights"])
            self.assertEqual(set(files), set(profile["files"]))
            with mock.patch.object(PROVISION, "QWEN4B_WEIGHTS", profile["weights"]):
                PROVISION.verify_weight_set(pins, root, time.monotonic() + 30)
            bad = copy.deepcopy(profile)
            bad["weights"]["sha256"] = bad["hashes"]["model.safetensors.index.json"]
            with self.assertRaisesRegex(WORKER.JobError, "MODEL_WEIGHT_SET_NOT_PINNED"):
                WORKER.verify_sharded_weights(root, bad)
            bad = copy.deepcopy(profile)
            bad["weight_shards"] = tuple(reversed(bad["weight_shards"]))
            with self.assertRaisesRegex(WORKER.JobError, "MODEL_WEIGHT_SET_NOT_PINNED"):
                WORKER.verify_sharded_weights(root, bad)
            shard = root / profile["weight_shards"][0]
            shard.write_bytes(b"x" * shard.stat().st_size)
            with self.assertRaisesRegex(WORKER.JobError, "MODEL_WEIGHTS_CHANGED_ON_DISK"):
                WORKER.verify_sharded_weights(root, profile)
            with mock.patch.object(PROVISION, "QWEN4B_WEIGHTS", profile["weights"]), \
                 self.assertRaisesRegex(PROVISION.ProvisionError, "shard changed"):
                PROVISION.verify_weight_set(pins, root, time.monotonic() + 30)

    def test_missing_symlink_and_changed_index_fail_before_backend(self):
        for mutation in ("missing", "symlink", "index"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                profile, _ = synthetic_shards(root)
                shard = root / profile["weight_shards"][0]
                if mutation == "index":
                    index = root / "model.safetensors.index.json"
                    index.write_bytes(b"x" * index.stat().st_size)
                else:
                    shard.unlink()
                    if mutation == "symlink":
                        shard.symlink_to(root / profile["weight_shards"][1])
                with self.assertRaises((WORKER.JobError, OSError)):
                    WORKER.verify_sharded_weights(root, profile)


if __name__ == "__main__":
    unittest.main()
