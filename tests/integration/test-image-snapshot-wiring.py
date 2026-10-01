#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure Image snapshot staging and export contracts, not runtime storage evidence."""

import json
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCENARIO = "image-snapshot"


def diagnostics():
    source = (HERE / "run-alpha-topology-vm.sh").read_text()
    code = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON", 1)[0]
    module = {"__name__": "image_export_boundary_test"}
    exec(compile(code, "bounded_guest_diagnostics", "exec"), module)
    return module


class ImageSnapshotWiring(unittest.TestCase):
    def test_runner_preview_and_repeated_selection(self):
        for first, last in ((SCENARIO, "private-storage-fragments"), ("private-storage-fragments", SCENARIO)):
            with self.subTest(first=first, last=last):
                result = subprocess.run(["sh", str(HERE / "run-alpha-topology-vm.sh"), "--preview",
                    "--scenario", first, "--scenario", last], capture_output=True, text=True, timeout=10, check=True)
                self.assertIn(last, result.stdout.lower())
                self.assertNotIn(first, result.stdout.lower())
                self.assertIn("PREVIEW ONLY", result.stdout)

    def test_guest_driver_is_syntactically_valid_and_stages_only_in_guest(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        head, guest = source.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)
        guest = guest.split("\nGUEST_DRIVER_SCRIPT", 1)[0]
        subprocess.run(["sh", "-n"], input=guest, text=True, capture_output=True, timeout=10, check=True)
        self.assertNotIn("image-snapshot-provision.py provision --download", head)
        self.assertIn("sudo -n python3 -B tests/integration/image-snapshot-provision.py provision --download", guest)
        self.assertIn("--no-install-recommends gpg gpg-agent gpgconf tar", guest)
        for value in ("IMAGE_SOURCE=/opt/volparossa-image", "IMAGE_NODE=/opt/volparossa-node/bin/node",
                      "IMAGE_REVISION=e177afebabd99ac0773de2a73d60275346a5de52"):
            self.assertIn(value, guest)
        self.assertIn('sudo -n -- env "$@" ./tests/integration/kvm-alpha-topology.sh', guest)
        self.assertIn('"tests/integration/$scenario-smoke.py" export-names', guest)

    def test_exact_export_list_and_timeout_exclude_private_owner_data(self):
        checker = runpy.run_path(str(HERE / "image-snapshot-smoke.py"))
        module = diagnostics()
        names = set(checker["EXPORT_NAMES"])
        self.assertEqual(names, module["IMAGE_NAMES"])
        self.assertNotIn("private-storage-fragments-smoke.json", names)
        self.assertLess(len(names), 128)
        with tempfile.TemporaryDirectory(prefix="image-snapshot-export-") as temporary:
            base = Path(temporary)
            home = base / "home"
            published = home / "alpha-output"
            published.mkdir(parents=True)
            for name in names:
                self.assertNotIn("/", name)
                (published / name).write_text("{}\n")
            for name in ("image-snapshot-owner.key", "image-snapshot-cipher.bin", "image-snapshot-result.log",
                         "image-snapshot-raw-receipt.json", "private-storage-fragments-request.json",
                         "private-storage-fragments-journal.json", "content-private-owner.json"):
                (published / name).write_text("PRIVATE_DO_NOT_EXPORT\n")
            archive = module["collect"](home, base / "missing-opt", "a" * 40, SCENARIO, 124,
                                       cgroups=base / "missing-cgroups", proc=base / "missing-proc")
            with tarfile.open(archive, "r:gz") as bundle:
                self.assertEqual(set(bundle.getnames()), {"published/" + name for name in names} | {"vm-incomplete.json"})
                for member in bundle.getmembers():
                    with bundle.extractfile(member) as stream:
                        self.assertNotIn(b"PRIVATE_DO_NOT_EXPORT", stream.read())
                with bundle.extractfile("vm-incomplete.json") as stream:
                    report = json.load(stream)
            self.assertFalse(report["success"])
            self.assertFalse(report["cleanup"]["verified"])
            self.assertIsNone(report["host_state"]["unchanged"])

    def test_workflow_has_separate_gate_and_never_claims_full_alpha(self):
        workflow = (HERE.parents[1] / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("          - image-snapshot\n", workflow)
        start = workflow.index("      - name: Require encrypted Image snapshot")
        end = workflow.index("\n      - name:", start + 1)
        gate = workflow[start:end]
        self.assertIn("if: always() && env.VOLPAROSSA_ALPHA_SCENARIO == 'image-snapshot'", gate)
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', gate)
        self.assertIn('image-snapshot-smoke.py report "$report" "$GITHUB_SHA"', gate)
        self.assertIn("host-state-before.json", gate)
        self.assertIn("host-state-after.json", gate)
        for title in ("Validate normative acceptance report before upload", "Require successful A01-A15 evidence"):
            segment = workflow.split("      - name: " + title, 1)[1].split("\n        env:", 1)[0]
            self.assertIn("env.VOLPAROSSA_ALPHA_SCENARIO != 'image-snapshot'", segment)


if __name__ == "__main__":
    unittest.main()
