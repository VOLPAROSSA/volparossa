#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise inert outer registration and closed failure exports; never launch a VM."""
import json
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).parent
RUNNER = HERE / "run-alpha-topology-vm.sh"
SOURCE = RUNNER.read_text()
DRIVER = SOURCE.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
COLLECTOR = SOURCE.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
MODULE = {"__name__": "fixture_test"}
exec(compile(COLLECTOR, str(RUNNER) + ":diagnostics", "exec"), MODULE)
CODE = runpy.run_path(str(HERE / "agent-cooperative-code.py"))


def selected_topology_argv(scenario):
    """Run the actual selector with sudo intercepted, no VM or guest file writes."""
    marker = "topology_scenario=alpha\n"
    selector = marker + DRIVER.split(marker, 1)[1].split("\ntopology_status=$?\n", 1)[0]
    for name in ("runner.stdout", "runner.stderr"):
        original = "/home/vpci/alpha-output/" + name
        if selector.count(original) != 1:
            raise AssertionError("guest output redirection changed")
        selector = selector.replace(original, "/dev/null")
    script = "\n".join(("set -eu", 'scenario=$1', "expected_commit=" + "a" * 40,
                        "code_manifest_sha256=" + "b" * 64, "exec 3>&1",
                        "guest_phase() { :; }", "sudo() { printf '%s\\0' \"$@\" >&3; }", selector))
    result = subprocess.run(["sh", "-c", script, "test", scenario], capture_output=True, timeout=5, check=True)
    if not result.stdout.endswith(b"\0"):
        raise AssertionError("selected command never reached mocked sudo")
    return result.stdout[:-1].decode("utf-8").split("\0")


def common_topology_args(scenario):
    return ["--execute", "--yes", "--source", "/home/vpci/source", "--bin", "/home/vpci/target/debug",
            "--mpquic", "/home/vpci/volparossa-mpquic", "--scenario", scenario,
            "--output", "/home/vpci/alpha-output", "--expected-commit", "a" * 40]


class CooperativeCodeVm(unittest.TestCase):
    def test_guest_selector_preserves_exact_code_and_browser_commands(self):
        self.assertEqual(selected_topology_argv("agent-cooperative-code"),
            ["-n", "--", "./tests/integration/kvm-alpha-topology.sh",
             "--code-bundle", "/home/vpci/cooperative-code-inputs", "--code-manifest-sha256", "b" * 64,
             *common_topology_args("agent-cooperative-code")])
        self.assertEqual(selected_topology_argv("agent-cooperative-browser"),
            ["-n", "--", "env", "./tests/integration/kvm-alpha-topology.sh",
             *common_topology_args("agent-cooperative-browser")])

    def test_preview_and_invalid_inputs_are_inert(self):
        preview = subprocess.run(["sh", str(RUNNER), "--preview", "--scenario", "agent-cooperative-code"],
                                 capture_output=True, text=True, timeout=5)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("synthetic private planner only", preview.stdout)
        base = ["--execute", "--yes", "--image", "/absent-image", "--mpquic", "/absent-mpquic",
                "--output", "/absent-output", "--expected-commit", "a" * 40]
        code = [*base, "--scenario", "agent-cooperative-code"]
        bundle = ["--code-bundle", "/explicit-code", "--code-manifest-sha256", "b" * 64]
        for args in ([*code], [*code, "--code-bundle", "/explicit-code"],
                     [*code, "--code-manifest-sha256", "b" * 64],
                     [*code, "--code-bundle", "relative", "--code-manifest-sha256", "b" * 64],
                     [*code, "--code-bundle", "/explicit-code", "--code-manifest-sha256", "A" * 64],
                     [*code, *bundle, "--code-bundle", "/second"],
                     [*code, *bundle, "--code-manifest-sha256", "c" * 64],
                     [*base, "--scenario", "agent-jobs", *bundle],
                     ["--preview", "--scenario", "agent-cooperative-code", *bundle]):
            with self.subTest(args=args):
                result = subprocess.run(["sh", str(RUNNER), *args], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 64, result.stdout + result.stderr)

    def test_guest_installs_worker_and_isolation_prerequisites_without_browser(self):
        blocks = re.findall(r'^if \[ "\$scenario" = [^\n]+; then\n.*?^fi$', DRIVER, re.MULTILINE | re.DOTALL)
        matching = [block for block in blocks if "--no-install-recommends python3-venv bubblewrap" in block]
        self.assertEqual(len(matching), 1)
        self.assertIn('[ "$scenario" = agent-cooperative-code ]', matching[0])
        # Execute just the scenario selector with apt/sudo replaced by a function.
        script = 'set -eu\nscenario=agent-cooperative-code\nsudo() { printf "%s\\n" "$*"; }\n' + matching[0]
        result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("python3-venv bubblewrap"), 1)
        self.assertNotIn("firefox", result.stdout.lower())

    def test_bound_bundle_is_transferred_verified_unpacked_and_forwarded(self):
        self.assertIn('"$HERE/cooperative-code-bundle.py" capture "$code_bundle" "$CODE_ARCHIVE" "$code_manifest_sha256"', SOURCE)
        self.assertIn('scp_to "$CODE_ARCHIVE" /home/vpci/cooperative-code.tar', SOURCE)
        self.assertIn('"$scenario" "$CODE_ARCHIVE_SHA256" "$CODE_MANIFEST_SHA256"', SOURCE)
        self.assertIn('code_archive_sha256=${6:-none}', DRIVER)
        self.assertIn('code_manifest_sha256=${7:-none}', DRIVER)
        self.assertIn('"$code_archive_sha256" | sha256sum --check --strict -', DRIVER)
        self.assertIn('/home/vpci/cooperative-code.tar /home/vpci/cooperative-code-inputs "$code_manifest_sha256"', DRIVER)
        self.assertIn('--code-bundle /home/vpci/cooperative-code-inputs', DRIVER)
        self.assertIn('--code-manifest-sha256 "$code_manifest_sha256"', DRIVER)
        self.assertIn('agent-cooperative-code|agent-public-collection', DRIVER)
        self.assertIn('--scenario "$topology_scenario"', DRIVER)
        self.assertIn('"tests/integration/$scenario.py" export-names', DRIVER)
        self.assertIn('[ "$scenario" != agent-cooperative-code ] || driver_time_bound=4800s', SOURCE)

    def test_timeout_exports_only_code_structural_receipts(self):
        extras = {"host-state-before.json", "host-state-after.json", "guest-exit-status", "current-phase"}
        self.assertEqual(MODULE["COOPERATIVE_CODE_NAMES"], set(CODE["EXPORT_NAMES"]) | extras)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, opt = root / "home", root / "opt"
            home.mkdir()
            opt.mkdir()
            (home / "alpha-output").mkdir()
            work = opt / ("va." + "a" * 32 + ".ABCdef")
            work.mkdir()
            (home / "guest-phase.txt").write_text("topology\n")
            (work / "agent-cooperative-code-driver.json").write_text('{"passed":false}\n')
            (work / "agent-cooperative-code-diagnostic.json").write_text('{"observer_report":"unavailable"}\n')
            for name in ("runner.stderr", "agent-cooperative-code-driver.log", "agent-cooperative-code-service.err",
                         "agent-cooperative-code-observer-status.private", "content-secret.json", "input.json",
                         "agent-cooperative-browser-panel.json"):
                (work / name).write_text("PRIVATE MODEL OR INPUT\n")
            (home / "cargo-build.log").write_text("UNRELATED BUILD LOG\n")
            archive = MODULE["collect"](home, opt, "b" * 40, "agent-cooperative-code", 124,
                                         root / "cgroups", root / "proc")
            with tarfile.open(archive) as bundle:
                files = {member.name: bundle.extractfile(member).read() for member in bundle.getmembers()}
            self.assertIn("work-1/agent-cooperative-code-driver.json", files)
            self.assertIn("work-1/agent-cooperative-code-diagnostic.json", files)
            self.assertNotIn(b"PRIVATE MODEL OR INPUT", b"".join(files.values()))
            self.assertNotIn(b"UNRELATED BUILD LOG", b"".join(files.values()))
            summary = json.loads(files["vm-incomplete.json"])
            self.assertFalse(summary["success"])
            self.assertFalse(summary["cleanup"]["verified"])
            self.assertEqual(summary["scenario"], "agent-cooperative-code")


if __name__ == "__main__":
    unittest.main()
