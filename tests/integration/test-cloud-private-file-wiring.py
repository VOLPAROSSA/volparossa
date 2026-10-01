#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure Cloud snapshot staging and export contracts, not runtime storage evidence."""

import json
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCENARIO = "cloud-private-file"


def diagnostics():
    source = (HERE / "run-alpha-topology-vm.sh").read_text()
    code = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON", 1)[0]
    module = {"__name__": "cloud_export_boundary_test"}
    exec(compile(code, "bounded_guest_diagnostics", "exec"), module)
    return module


class CloudSnapshotWiring(unittest.TestCase):
    def test_owner_parent_is_private_removable_and_gpg_socket_stays_short(self):
        source = (HERE / "cloud-private-file-smoke.sh").read_text()
        self.assertIn('storage_owner_parent=$WORK/u', source)
        self.assertIn('storage_owner_directory=$storage_owner_parent/i', source)
        self.assertIn('install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$storage_owner_parent"', source)
        self.assertIn('[ "${#longest_cloud_socket}" -lt 104 ]', source)
        self.assertLess(source.index('private_storage_fragments_run\n'),
                        source.index('rmdir "$storage_owner_parent"'))
        # Exact topology prefix, 32-character run ID, mktemp suffix and pinned
        # Cloud tempfile prefix/suffix. No longer client-fixtures component.
        work = '/opt/va.' + 'a' * 32 + '.abcdef'
        socket = work + '/u/i/w/catalog-read-abcdef/g-abcdefgh/S.gpg-agent'
        self.assertEqual(len(socket.encode()), 96)
        self.assertLess(len(socket.encode()), 104)
        self.assertIn('storage_restore_flows=48', source)
        self.assertIn('storage_phase_timeout_seconds=2400', source)
        fragments = (HERE / "private-storage-fragments-smoke.sh").read_text()
        self.assertIn('private_storage_fragments_phase_finish "${storage_restore_flows:-16}"', fragments)
        topology = (HERE / "kvm-alpha-topology.sh").read_text()
        self.assertIn('"$WORK/bin/cloud-private-file-sdk.mjs"', topology)
        self.assertIn('"$WORK/bin/cloud-private-file-ui.py"', topology)

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
        self.assertNotIn("cloud-private-file-provision.py provision --download", head)
        self.assertIn("sudo -n python3 -B tests/integration/cloud-private-file-provision.py provision --download", guest)
        self.assertIn("--no-install-recommends gpg gpg-agent gpgconf tar", guest)
        for value in ("CLOUD_SOURCE=/opt/volparossa-cloud", "CLOUD_NODE=/opt/volparossa-node/bin/node",
                      "CLOUD_REVISION=c81980dd71297b257f1df6aa382c28a18f9c2f57"):
            self.assertIn(value, guest)
        self.assertIn('sudo -n -- env "$@" ./tests/integration/kvm-alpha-topology.sh', guest)
        self.assertIn('"tests/integration/$scenario-smoke.py" export-names', guest)

    def test_exact_export_list_and_timeout_exclude_private_owner_data(self):
        checker = runpy.run_path(str(HERE / "cloud-private-file-smoke.py"))
        module = diagnostics()
        names = set(checker["EXPORT_NAMES"])
        self.assertEqual(names, module["CLOUD_NAMES"])
        self.assertIn("cloud-private-file-route-diagnostic.json", names)
        self.assertNotIn("private-storage-fragments-smoke.json", names)
        self.assertLess(len(names), 128)
        with tempfile.TemporaryDirectory(prefix="cloud-private-file-export-") as temporary:
            base = Path(temporary)
            home = base / "home"
            published = home / "alpha-output"
            published.mkdir(parents=True)
            for name in names:
                self.assertNotIn("/", name)
                (published / name).write_text("{}\n")
            for name in ("cloud-private-file-owner.key", "cloud-private-file-cipher.bin", "cloud-private-file-result.log",
                         "cloud-private-file-raw-receipt.json", "private-storage-fragments-request.json",
                         "private-storage-fragments-journal.json", "content-private-owner.json",
                         "private-storage-fragments-connect.err", "private-storage-fragments-connect.out",
                         "logs-client.txt", "cloud-private-file-route-diagnostic.part"):
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
        self.assertIn("          - cloud-private-file\n", workflow)
        start = workflow.index("      - name: Require encrypted Cloud private file")
        end = workflow.index("\n      - name:", start + 1)
        gate = workflow[start:end]
        self.assertIn("if: always() && env.VOLPAROSSA_ALPHA_SCENARIO == 'cloud-private-file'", gate)
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', gate)
        self.assertIn('cloud-private-file-smoke.py report "$report" "$GITHUB_SHA"', gate)
        self.assertIn("host-state-before.json", gate)
        self.assertIn("host-state-after.json", gate)
        for title in ("Validate normative acceptance report before upload", "Require successful A01-A15 evidence"):
            segment = workflow.split("      - name: " + title, 1)[1].split("\n        env:", 1)[0]
            self.assertIn("env.VOLPAROSSA_ALPHA_SCENARIO != 'cloud-private-file'", segment)


if __name__ == "__main__":
    unittest.main()
