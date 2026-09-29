#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert storage tests only: no model, custody handoff or policy correctness claim."""

import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

CHECK = runpy.run_path(str(Path(__file__).with_name("agent-policy-assessment-smoke.py")))


class FailureDiagnostics(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="volparossa-policy-diagnostics-")
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name)
        self.root = self.source / "policy-cycle"
        self.root.mkdir(mode=0o700)
        (self.root / "round").mkdir(mode=0o700)

    def put(self, name, value=None, raw=None):
        path = self.root / name
        data = raw if raw is not None else json.dumps(value, indent=2).encode() + b"\n"
        path.write_bytes(data)
        path.chmod(0o600)
        return data

    def receipt(self):
        return dict(operation="content_custody_deposit", manifest_id="a" * 64,
            publisher_key_hex="b" * 64, object_bytes=1024, original_expiry_unix_seconds=900,
            requested_providers=3, confirmed_complete_providers=0, failed_providers=3, complete=False,
            observations=[dict(provider_key_hex=str(index) * 64, agent_handoff_complete=False,
                state=None, signed_receipt_hex=None, original_expiry_unix_seconds=None,
                object_bytes=None, unique_chunks=None, error="agent rejected request: CONTENT_BUSY")
                for index in range(3)], private_keys_transferred=False, direct_provider_dial=False,
            origin_authenticated=False, future_availability_guaranteed=False)

    def test_all_original_incomplete_receipts_survive_without_result_or_private_payload(self):
        self.put("state.json", dict(version=1, phase="round", enrollment_sha256="c" * 64,
            started_at_ms=1000, deadline_ms=3001000, assessment_sha256="d" * 64,
            bundle_sha256="e" * 64, round_sha256=None))
        self.put("status.json", dict(operation="compute_policy_cycle", complete=False, phase="round",
            reason="round_incomplete_retained", started_at_ms=1000, deadline_ms=3001000,
            assessment=None, original_jobs_retained=True, remote_cancellation_confirmed=False,
            network_policy_activation=False, authority_private_keys_loaded=False,
            semantic_correctness_proven=False, cancellation_cleanup_grace_seconds=30))
        window = self.put("round/window.json", dict(started_at_ms=1000, deadline_ms=601000))
        self.put("round/status.json", dict(operation="compute_policy_round", phase="incomplete_retained",
            verified_endorsements=0, complete=False, model_execution=False, assessment_started=False,
            authority_private_keys_loaded=False, network_policy_activation=False))
        self.put("round/request.bin", raw=b"DO NOT EXPORT original source text")
        self.put("identity.key", raw=b"DO NOT EXPORT private identity")
        receipts = {f"round/request-deposit-{index:02}.json": self.put(
            f"round/request-deposit-{index:02}.json", self.receipt()) for index in range(64)}
        value = CHECK["round_failure_snapshot"](self.root, os.getuid())
        self.assertEqual(value["original_request_receipts"], 64)
        self.assertEqual(value["rejected"], {})
        self.assertEqual(value["missing"], [])
        self.assertEqual(set(value["files"]), {"state.json", "status.json", "round/window.json",
                                              "round/status.json", *receipts})
        self.assertEqual(CHECK["decode_file"](value["files"], "round/window.json", False), window)
        for name, raw in receipts.items():
            self.assertEqual(CHECK["decode_file"](value["files"], name, False), raw)
            self.assertEqual((self.root / name).read_bytes(), raw)
        self.assertNotIn("DO NOT EXPORT", json.dumps(value))
        self.assertFalse((self.root / "result.json").exists())

    def test_malformed_missing_aliased_and_oversized_records_are_not_accepted(self):
        self.put("round/request-deposit-00.json", raw=b'{"complete":false,"complete":true}')
        self.put("round/request-deposit-01.json", raw=b"[not JSON")
        (self.root / "round/request-deposit-02.json").symlink_to("request-deposit-00.json")
        self.put("round/request-deposit-03.json", raw=b" " * 65537)
        altered = self.receipt()
        altered["unexpected_source"] = "must not be exported"
        self.put("round/request-deposit-04.json", altered)
        value = CHECK["round_failure_snapshot"](self.root, os.getuid())
        self.assertEqual(value["files"], {})
        self.assertEqual(value["original_request_receipts"], 0)
        self.assertEqual(len(value["rejected"]), 5)
        self.assertIn("round/window.json", value["missing"])
        self.assertNotIn("must not be exported", json.dumps(value))
        (self.root / "round").rename(self.root / "other")
        (self.root / "round").symlink_to("other", target_is_directory=True)
        self.assertFalse(CHECK["round_failure_snapshot"](self.root, os.getuid())["files"])

    def test_failure_report_retains_exit_and_cannot_become_success(self):
        function = CHECK["round_failure_collect"]
        saved = []
        class Owner:
            st_uid = 12345
        class Source:
            def stat(self):
                return Owner()
        with patch.dict(function.__globals__, {
            "JOBS": {"guest_work": lambda _: None}, "source_path": lambda _: Source(),
            "round_failure_snapshot": lambda root, owner: dict(files={}, missing=["round/window.json"],
                rejected={}, original_bytes=0, original_request_receipts=0),
            "write": lambda path, value: saved.append(value),
            "cycle_root": lambda _: self.root,
        }):
            function(self.source, 1)
            with self.assertRaises(ValueError):
                function(self.source, 0)
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["cycle_exit_status"], 1)
        self.assertTrue(saved[0]["diagnostic_only"])
        self.assertFalse(saved[0]["success"])
        self.assertFalse(saved[0]["cycle_complete"])


if __name__ == "__main__":
    unittest.main()
