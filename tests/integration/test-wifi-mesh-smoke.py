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
        self.assertIn("admission 0 then 2", result.stdout)
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

            def save(values, admission_changes=None, omit_admission=False, late_admission=False):
                for node in values:
                    role = node["role"]
                    admission = {"role": role, "ifindex": node["ifindex"], "zero_readback": True,
                                 "final_maximum_peers": 2, "established_preserved": True}
                    if role == "a" and admission_changes:
                        admission.update(admission_changes)
                    admission_line = "" if omit_admission else "MESH_ADMISSION " + json.dumps(admission) + "\n"
                    payload_line = "MESH_RESULT " + json.dumps(node) + "\n"
                    lines = payload_line + admission_line if late_admission else admission_line + payload_line
                    (output / f"mesh-{role}.log").write_text(lines + "MESH_REMOVED "
                        + json.dumps({"role": role, "idempotent": True}) + "\n")
                (output / "mesh-crash.log").write_text('MESH_CRASH_READY {"interface":"vw5353535353535","ifindex":9}\n')

            def report(**changes):
                args = dict(status=0, normal="yes", socket_loss="yes", unchanged="yes", remaining=0)
                args.update(changes)
                return REPORT.build(output, "1" * 40, **args)

            save(nodes)
            self.assertTrue(report()["success"])
            self.assertTrue(report()["admission_setter_readback_proven"])
            self.assertEqual(report()["nodes"][0]["admission"]["ifindex"], nodes[0]["ifindex"])
            self.assertFalse(report()["full_agent_overlay_proven"])
            for key, value in (("socket_loss", "no"), ("unchanged", "no"), ("remaining", 1), ("status", 1)):
                self.assertFalse(report(**{key: value})["success"])
            for key, value in (("received_sha256", "0" * 64), ("rx_bytes_delta", 0),
                               ("tx_bytes_delta", 0), ("established", False), ("wiphy", 1)):
                changed = copy.deepcopy(nodes)
                changed[0][key] = value
                save(changed)
                self.assertFalse(report()["success"], key)
            for key, value in (("role", "b"), ("ifindex", 8), ("zero_readback", False),
                               ("final_maximum_peers", 8), ("established_preserved", False)):
                save(nodes, admission_changes={key: value})
                self.assertFalse(report()["success"], key)
                self.assertFalse(report()["admission_setter_readback_proven"])
            for options in ({"omit_admission": True}, {"late_admission": True}):
                save(nodes, **options)
                self.assertFalse(report()["success"], options)


if __name__ == "__main__":
    unittest.main()
