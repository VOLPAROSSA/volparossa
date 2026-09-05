#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure evidence-parser and guard regressions; never starts a VM, module or radio."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("mesh_report", HERE / "wifi-mesh-report.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class MeshEvidence(unittest.TestCase):
    def test_preview_and_incomplete_execution_are_nonmutating(self):
        result = subprocess.run(["sh", str(HERE / "wifi-mesh-smoke.sh"), "--preview"],
                                capture_output=True, text=True, check=True)
        self.assertIn("PREVIEW ONLY", result.stdout)
        self.assertEqual(subprocess.run(["sh", str(HERE / "wifi-mesh-smoke.sh"), "--execute"],
                                       capture_output=True).returncode, 64)
        outer = subprocess.run(["sh", str(HERE / "run-alpha-topology-vm.sh"), "--preview", "--scenario", "wifi-mesh"],
                               capture_output=True, text=True, check=True)
        self.assertIn("not physical Wi-Fi or full overlay proof", outer.stdout)
        for script in ("wifi-mesh-smoke.sh", "wifi-mesh-vm-guest.sh", "run-alpha-topology-vm.sh"):
            subprocess.run(["sh", "-n", str(HERE / script)], check=True)

    def test_requires_actual_payload_both_radio_counters_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="volparossa-mesh-report-") as temporary:
            output = Path(temporary)
            nodes = []
            for ordinal, role in enumerate(("a", "b")):
                node = {"role": role, "interface": "vw" + ("51" if role == "a" else "52") * 6 + "5",
                        "ifindex": 7, "wiphy": ordinal, "joined": True, "established": True,
                        "sent_bytes": 131072, "received_bytes": 131072,
                        "sent_sha256": REPORT.payload_hash(role == "b"),
                        "received_sha256": REPORT.payload_hash(role != "b"),
                        "rx_bytes_delta": 145000, "tx_bytes_delta": 145000,
                        "rx_packets_delta": 128, "tx_packets_delta": 128}
                nodes.append(node)

            def save(values):
                for node in values:
                    role = node["role"]
                    (output / f"mesh-{role}.log").write_text("MESH_RESULT " + json.dumps(node) + "\nMESH_REMOVED "
                        + json.dumps({"role": role, "idempotent": True}) + "\n")
                (output / "mesh-crash.log").write_text('MESH_CRASH_READY {"interface":"vw5353535353535","ifindex":9}\n')

            def report(**changes):
                args = dict(status=0, normal="yes", socket_loss="yes", unchanged="yes", remaining=0)
                args.update(changes)
                return REPORT.build(output, "1" * 40, **args)

            save(nodes)
            self.assertTrue(report()["success"])
            self.assertFalse(report()["full_agent_overlay_proven"])
            for key, value in (("socket_loss", "no"), ("unchanged", "no"), ("remaining", 1), ("status", 1)):
                self.assertFalse(report(**{key: value})["success"])
            for key, value in (("received_sha256", "0" * 64), ("rx_bytes_delta", 0),
                               ("tx_bytes_delta", 0), ("established", False), ("wiphy", 1)):
                changed = copy.deepcopy(nodes)
                changed[0][key] = value
                save(changed)
                self.assertFalse(report()["success"], key)


if __name__ == "__main__":
    unittest.main()
