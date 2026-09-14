#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Execute the real embedded timeout collector against disposable local files, without a VM."""
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

RUNNER = Path(__file__).with_name("run-alpha-topology-vm.sh")
SOURCE = RUNNER.read_text()
COLLECTOR = SOURCE.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split(
    "\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
MODULE = {"__name__": "fixture_test"}
exec(compile(COLLECTOR, str(RUNNER) + ":diagnostics", "exec"), MODULE)


class VmFailureDiagnostics(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="volparossa-vm-diagnostics-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.guest = self.root / "guest"
        self.opt = self.root / "opt"
        self.guest.mkdir()
        self.opt.mkdir()
        self.work = self.opt / ("va." + "a" * 32 + ".ABCdef")
        self.work.mkdir()
        (self.guest / "alpha-output").mkdir()

    def snapshot(self):
        archive = MODULE["collect"](self.guest, self.opt, "b" * 40, "wifi-link", 124,
                                    self.root / "cgroups", self.root / "proc")
        with tarfile.open(archive) as bundle:
            contents = {member.name: bundle.extractfile(member).read()
                        for member in bundle.getmembers()}
        return contents, json.loads(contents["vm-incomplete.json"])

    def test_timeout_retains_present_evidence_without_promoting_it_to_success(self):
        (self.guest / "guest-phase.txt").write_text("topology\n")
        (self.guest / "alpha-output/current-phase").write_text("local-link-discovery\n")
        (self.guest / "alpha-output/runner.stderr").write_text("last bounded runner diagnostic\n")
        (self.work / "helper-client.log").write_text("last actual helper operation\n")
        (self.work / "wifi-link-smoke.json").write_text('{"success":true}\n')
        (self.work / "config.yaml").write_text("private configuration, never export\n")
        (self.work / "identity.key").write_text("private key, never export\n")
        unit = "volparossa-alpha-helper@client.service"
        group = self.root / "cgroups" / unit
        process = self.root / "proc/123"
        group.mkdir(parents=True)
        (process / "ns").mkdir(parents=True)
        (group / "cgroup.procs").write_text("123\n")
        (process / "cgroup").write_text(f"0::/system.slice/{unit}\n")
        (process / "stat").write_text("123 (volparossa-help) S 1\n")
        (process / "wchan").write_text("skb_wait_for_more_packets\n")
        (process / "ns/net").symlink_to("net:[12345]")
        files, summary = self.snapshot()
        self.assertEqual(summary["source_revision"], "b" * 40)
        self.assertEqual(summary["guest_exit_status"], 124)
        self.assertEqual(summary["observed_blocker"], "GUEST_EXECUTION_TIMEOUT")
        self.assertEqual(summary["driver_phase"], "topology")
        self.assertEqual(summary["topology_phase"], "local-link-discovery")
        self.assertFalse(summary["success"])
        self.assertEqual(summary["helper_processes"][0]["wchan"], "skb_wait_for_more_packets")
        self.assertEqual(summary["helper_processes"][0]["netns"], "net:[12345]")
        self.assertIsNone(summary["helper_processes"][0]["syscall"])
        self.assertEqual(summary["cleanup"], {"complete": False, "verified": False})
        self.assertIsNone(summary["host_state"]["unchanged"])
        self.assertIn("work-1/helper-client.log", files)
        self.assertIn("work-1/wifi-link-smoke.json", files)
        self.assertNotIn("wifi-link-smoke.json", files)
        self.assertFalse(any("config" in name or "identity" in name for name in files))
        self.assertEqual(sum(name.endswith("wifi-link-smoke.json") for name in files), 1)

    def test_bounds_symlinks_special_files_and_unavailable_phase(self):
        limit = MODULE["FILE_LIMIT"]
        (self.work / "helper-client.log").write_bytes(b"x" * (limit + 17))
        (self.work / "secret").write_text("not an allowlisted output")
        (self.work / "agent-client.log").symlink_to(self.work / "secret")
        os.mkfifo(self.guest / "alpha-output/runner.stdout")
        for index in range(80):
            (self.work / f"wifi-link-{index}.txt").write_text("bounded fixture data\n")
        files, summary = self.snapshot()
        self.assertEqual(len(files["work-1/helper-client.log.tail"]), limit)
        self.assertNotIn("work-1/agent-client.log", files)
        self.assertNotIn("published/runner.stdout", files)
        self.assertIsNone(summary["driver_phase"])
        self.assertIsNone(summary["topology_phase"])
        self.assertLessEqual(len(summary["diagnostics"]["files"]), MODULE["FILE_COUNT_LIMIT"])
        self.assertLessEqual(summary["diagnostics"]["captured_bytes"], MODULE["TOTAL_LIMIT"])

    def test_missing_archive_and_unreachable_guest_keep_failure_and_original_status(self):
        function = re.search(r"^retrieve_incomplete_output\(\) \{\n.*?^\}", SOURCE,
                             re.MULTILINE | re.DOTALL).group()
        recovery = SOURCE.split("retrieval_bound=600s\n", 1)[1].split(
            '\ntar -C "$output_directory" -xzf "$RUN_DIRECTORY/alpha-output.tar.gz"', 1)[0]
        script = "\n".join([
            "set -eu", "expected_commit=" + "b" * 40, "scenario=wifi-link", "GUEST_STATUS=124",
            'output_directory=$1', 'RUN_DIRECTORY=$1', 'CONSOLE=$1/console.log',
            'ssh_bounded() { test "$1" = 30s || exit 99; return 1; }',
            'scp_from_bounded() { test "$1" = 30s || exit 99; return 1; }',
            function, "retrieval_bound=600s", recovery,
        ])
        (self.root / "console.log").write_text("bounded console\n")
        outcome = subprocess.run(["sh", "-c", script, "test", str(self.root)],
                                 capture_output=True, timeout=3, check=False)
        self.assertEqual(outcome.returncode, 124, outcome.stderr)
        report = json.loads((self.root / "vm-incomplete.json").read_text())
        self.assertFalse(report["success"])
        self.assertFalse(report["diagnostics"]["available"])
        self.assertFalse(report["cleanup"]["verified"])
        self.assertIn('ssh_base() { ssh_bounded 2400s "$@"; }', SOURCE)

    def test_uplink_guest_requires_actual_egress_namespace_proof(self):
        driver = SOURCE.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
        syntax = subprocess.run(["sh", "-n"], input=driver, text=True, capture_output=True,
                                timeout=3, check=False)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        block = SOURCE.split('if [ "$scenario" = uplink-link ]; then\n    guest_phase egress-netns-test', 1)[1]
        block = block.split("\nfi", 1)[0]
        self.assertIn("VOLPAROSSA_REQUIRE_EGRESS_NETNS_PROOF=1", block)
        self.assertIn("egress::tests::egress_disposable_link_loss_return_and_capless_first_bind", block)
        self.assertIn("-- --exact --nocapture --test-threads=1", block)
        self.assertIn("exit 1", block)


if __name__ == "__main__":
    unittest.main()
