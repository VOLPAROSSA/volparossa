#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded preview/export/staging contracts; no browser, build or peer execution."""
import json
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCENARIO = "cloud-private-upload"
CHECK = runpy.run_path(str(HERE / "cloud-private-upload-smoke.py"))
OLD = runpy.run_path(str(HERE / "test-cloud-private-file-wiring.py"))


class UploadWiring(unittest.TestCase):
    def test_independent_scenario_preview_and_last_selection_wins(self):
        for script in ("run-alpha-topology-vm.sh", "kvm-alpha-topology.sh"):
            for first, last in ((SCENARIO, "cloud-private-file"), ("cloud-private-file", SCENARIO)):
                result = subprocess.run(["sh", str(HERE / script), "--preview", "--scenario", first,
                    "--scenario", last], capture_output=True, text=True, timeout=10, check=True)
                self.assertIn("cloud private-file" if script == "kvm-alpha-topology.sh" and last == "cloud-private-file"
                    else last, result.stdout.lower())
                self.assertNotIn(first, result.stdout.lower())
        self.assertEqual(json.loads((HERE / "cloud-private-file-pins.json").read_text())["revision"],
            "63bba5d1163a69e1ee6b4218c9e7462d941f22f7")

    def test_longest_actual_object_and_catalog_gpg_paths_fit_only_short_guest_work(self):
        shell = (HERE / "cloud-private-upload-smoke.sh").read_text()
        topology = (HERE / "kvm-alpha-topology.sh").read_text()
        work = "/opt/vu.abcdef"
        suffix = "/u/i/o/object-" + "a" * 32 + "/g-abcdefgh/S.gpg-agent"
        self.assertLess(len((work + suffix).encode()), 104)
        self.assertGreaterEqual(len(("/opt/va." + "a" * 32 + ".abcdef" + suffix).encode()), 104)
        self.assertLess(len((work + "/u/i/w/catalog-read-abcdef/g-abcdefgh/S.gpg-agent").encode()), 104)
        self.assertIn("WORK=$(mktemp -d /opt/vu.XXXXXX)", topology)
        self.assertIn('WORK=$(mktemp -d "/opt/va.$RUN_ID.XXXXXX")', topology)
        self.assertIn("/o/object-0123456789abcdef0123456789abcdef/g-xxxxxxxx/S.gpg-agent", shell)
        self.assertIn('[ "${#longest_cloud_socket}" -lt 104 ]', shell)
        self.assertIn('rmdir "$storage_owner_parent"', shell)
        self.assertIn("storage_restore_flows=28", shell)
        self.assertIn("storage_phase_timeout_seconds=2400", shell)

    def test_exact_closed_exports_also_on_failed_short_work_root(self):
        module = OLD["diagnostics"]()
        names = set(CHECK["EXPORT_NAMES"])
        self.assertEqual(names, module["UPLOAD_NAMES"])
        self.assertEqual(len(names), 40)
        self.assertNotIn("cloud-private-file-smoke.json", names)
        with tempfile.TemporaryDirectory(prefix="cloud-upload-export-") as temporary:
            base = Path(temporary)
            (base / "home").mkdir()
            work = base / "opt/vu.abcdef"; work.mkdir(parents=True)
            for name in names: (work / name).write_text("{}\n")
            (work / "u/i").mkdir(parents=True)
            (work / "u/i/recovery.key").write_text("PRIVATE_SENTINEL")
            for name in ("runner.stdout", "cloud-private-upload-error.txt", "private-storage-fragments-connect.err"):
                (work / name).write_text("PRIVATE_SENTINEL")
            archive = module["collect"](base / "home", base / "opt", "a" * 40, SCENARIO, 124,
                cgroups=base / "missing-cgroup", proc=base / "missing-proc")
            with tarfile.open(archive, "r:gz") as bundle:
                self.assertEqual(set(bundle.getnames()), {"work-1/" + n for n in names} | {"vm-incomplete.json"})
                for member in bundle.getmembers():
                    with bundle.extractfile(member) as stream: self.assertNotIn(b"PRIVATE_SENTINEL", stream.read())
                report = json.load(bundle.extractfile("vm-incomplete.json"))
                self.assertFalse(report["success"])
                self.assertFalse(report["cleanup"]["verified"])
                self.assertIsNone(report["host_state"]["unchanged"])

    def test_guest_stage_env_and_workflow_shell_remain_executable(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        head, guest = source.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)
        guest = guest.split("\nGUEST_DRIVER_SCRIPT", 1)[0]
        subprocess.run(["sh", "-n"], input=guest, text=True, capture_output=True, timeout=10, check=True)
        self.assertNotIn("cloud-private-upload-provision.py provision --download", head)
        self.assertIn("sudo -n python3 -B tests/integration/cloud-private-upload-provision.py provision --download", guest)
        self.assertIn("CLOUD_REVISION=" + CHECK["REVISION"], guest)
        self.assertIn('"tests/integration/$scenario-smoke.py" export-names', guest)
        self.assertIn('[ "$scenario" != cloud-private-upload ] || driver_time_bound=3600s', source)
        topology = (HERE / "kvm-alpha-topology.sh").read_text()
        self.assertIn('cloud_private_upload_run\n    exit 0\nelif [ "$cloud_private_file" = yes ]', topology)
        for name in ("cloud-private-upload-smoke.py", "cloud-private-upload-pins.json",
                     "cloud-private-file-smoke.py", "cloud-private-file-pins.json", "image-snapshot-smoke.py"):
            self.assertIn(f'"$WORK/bin/{name}"', topology)
        workflow = (HERE.parents[1] / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("          - cloud-private-upload\n", workflow)
        start = workflow.index("      - name: Require original Cloud upload")
        end = workflow.index("\n      - name:", start + 1)
        gate = workflow[start:end]
        self.assertIn("env.VOLPAROSSA_ALPHA_SCENARIO == 'cloud-private-upload'", gate)
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', gate)
        self.assertIn('cloud-private-upload-smoke.py report "$report" "$GITHUB_SHA"', gate)
        # Read existing inline shell blocks, replacing only GitHub expressions.
        for block in re.findall(r"^        run: \|\n((?:          .*\n|\n)+)", workflow, re.M):
            body = "\n".join(line[10:] for line in block.splitlines())
            body = re.sub(r"\$\{\{.*?\}\}", "fixture", body)
            subprocess.run(["bash", "-n"], input=body, text=True, capture_output=True, timeout=10, check=True)

    def test_cleanup_is_bounded_owned_tree_and_rejects_links(self):
        with tempfile.TemporaryDirectory(prefix="cloud-upload-cleanup-") as temporary:
            root = Path(temporary) / "i"; root.mkdir(mode=0o700)
            nested = root / "o" / ("object-" + "a" * 32) / "journal/fragment-0002/copy-1"
            nested.mkdir(parents=True, mode=0o700)
            for parent in nested.parents:
                if parent == root.parent: break
                parent.chmod(0o700)
            target = nested / "archive.json"; target.write_bytes(b"private synthetic data"); target.chmod(0o600)
            link = root / "link"; link.symlink_to(target)
            with self.assertRaises(ValueError): CHECK["cleanup"](root)
            self.assertTrue(target.is_file())
            link.unlink()
            self.assertTrue(CHECK["cleanup"](root)["user_directory_removed"])
            self.assertFalse(root.exists())


if __name__ == "__main__": unittest.main()
