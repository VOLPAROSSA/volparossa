#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Regression checks for independent participants and original signed provider evidence."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
V = runpy.run_path(str(HERE / "paired-mail-peers-smoke.py"))
S = runpy.run_path(str(HERE / "paired-mail-sandbox.py"))
OLD = HERE.parents[1] / "docs/development/evidence/paired-mail-44553382181/paired-mail-smoke.json"


class IndependentMail(unittest.TestCase):
    def test_each_mount_contains_one_actor_and_its_own_control_socket(self):
        for actor, node in (("sender", "client"), ("recipient", "relay4")):
            root = Path("/private") / actor
            control = Path("/run") / node / "control/agent.sock"
            cli = Path("/staged") / actor / "volparossa"
            argv = list(map(str, S["mounts"](Path("/runtime"), root, cli, control)))
            mounts = {(argv[i+1], argv[i+2]): option for i, option in enumerate(argv) if option in ("--bind", "--ro-bind")}
            self.assertEqual({pair for pair, mode in mounts.items() if mode == "--bind"},
                {(str(root/"app"), "/trial/state"), (str(root/"store"), "/var/lib/volparossa-mail")})
            self.assertEqual({src for src, target in mounts if target.startswith("/trial/core/")}, {str(cli), str(control)})
            self.assertIn("--unshare-all", argv)
            self.assertIn("--clearenv", argv)

    def test_original_signatures_bound_to_operation_key_and_message(self):
        base = json.loads(OLD.read_bytes())["mailbox"]["mailbox"]
        verify = runpy.run_path(str(HERE/"content-retain-smoke.py"))["verify_signature"]
        providers = set(base["provider_keys"].values())
        signed = V["signed_receipts"]
        grant = signed(verify, base["enroll"]["storage_receipts"], providers, 1)
        send = base["send"]
        self.assertEqual(grant, signed(verify, send["storage_receipts"], providers, 2, send["message_id"], send["ciphertext_bytes"]))
        def corrupt(value):
            return value[:-2] + f"{int(value[-2:], 16) ^ 1:02x}"
        for receipts, keys, msg in (
            ([corrupt(send["storage_receipts"][0]), send["storage_receipts"][1]], providers, send["message_id"]),
            (send["storage_receipts"], providers, "0" * 64),
            (send["storage_receipts"], {"1" * 64, "2" * 64}, send["message_id"]),
            (base["enroll"]["storage_receipts"], providers, send["message_id"]),
        ):
            with self.assertRaises(ValueError):
                signed(verify, receipts, keys, 2, msg, send["ciphertext_bytes"])

    def test_failure_report_requires_no_private_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = V["assemble"](root, "0"*40, "1", "PAIRED_MAIL_PEER_ROUTE_UNAVAILABLE", "true", "0", "1"*64, "1"*64)
            self.assertFalse(report["success"])
            self.assertEqual(report["observed_blocker"], "PAIRED_MAIL_PEER_ROUTE_UNAVAILABLE")
            self.assertFalse({"actors", "app", "network"} & set(report))
            with self.assertRaises(ValueError):
                V["validate"](report, "0"*40)


if __name__ == "__main__":
    unittest.main()
