#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert wiring/export checks: no VM, stress worker, privileged command or network."""
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOPOLOGY = (HERE / "kvm-alpha-topology.sh").read_text()
RUNNER = (HERE / "run-alpha-topology-vm.sh").read_text()
SUFFIXES = ("worker-budget", "continuation", "resource-ready", "evidence", "ready", "controller",
            "cleanup", "object", "fetch", "selection", "live-selection", "status-before", "status-after",
            "qdisc-before", "qdisc-limited", "qdisc-after", "qdisc-profile", "control-privacy")
ROLES = ("client", "relay0", "relay1", "relay2", "exit")
NAMES = {f"content-provider-pressure-{suffix}.json" for suffix in SUFFIXES}
NAMES |= {f"content-provider-pressure-privacy-{role}.json" for role in ROLES}
NAMES |= {f"content-provider-pressure-{node}-{operation}.json"
          for node in ("relay3", "relay4", "relay5") for operation in ("reset", "serve", "status", "stop")}


def shell(script, *args):
    return subprocess.run(["sh", "-eu", "-c", script, "sh", *args],
                          capture_output=True, timeout=3, check=False)


def collector():
    embedded = RUNNER.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
    api = {"__name__": "inert_pressure_collector"}
    exec(compile(embedded, "pressure-collector", "exec"), api)
    return api


class PressureWiring(unittest.TestCase):
    def test_presence_symlinks_source_and_staged_controller_closure(self):
        preflight = "for provider_fixture in " + TOPOLOGY.split("for provider_fixture in ", 1)[1].split("\n    done", 1)[0] + "\n    done\n"
        names = preflight.split("; do", 1)[0].removeprefix("for provider_fixture in ").replace("\\\n", " ").split()
        pressure = ("content-provider-pressure-smoke.sh", "content-provider-pressure-smoke.py", "content-provider-pressure.py")
        for name in pressure:
            self.assertIn(name, names)
            self.assertTrue((HERE / name).is_file())
        self.assertIn('. "$source_directory/tests/integration/content-provider-pressure-smoke.sh"', TOPOLOGY)
        stage = TOPOLOGY.split("for pressure_helper in ", 1)[1].split("\n    done", 1)[0]
        self.assertEqual(stage.split("; do", 1)[0].split(),
                         ["content-provider-pressure.py", "content-provider-resource-ready.py"])
        self.assertIn('install -o root -g root -m 0555', stage)
        self.assertIn('"$WORK/bin/$pressure_helper"', stage)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "tests/integration"
            target.mkdir(parents=True)
            for name in names:
                (target / name).write_text("fixture\n")
            command = 'source_directory=$1\n' + preflight
            self.assertEqual(shell(command, str(root)).returncode, 0)
            for name in pressure:
                path = target / name
                path.unlink()
                self.assertEqual(shell(command, str(root)).returncode, 69)
                path.symlink_to(target / "content-provider-smoke.py")
                self.assertEqual(shell(command, str(root)).returncode, 69)
                path.unlink()
                path.write_text("fixture\n")

    def test_early_cleanup_retains_failure_and_runs_remaining_hooks(self):
        cleanup = TOPOLOGY.split("cleanup() {\n", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(cleanup.index("content_provider_pressure_cleanup"), cleanup.index("retire_unit"))
        early = cleanup.split('    if [ "$scenario" = dns-cache ]', 1)[0]
        for failure in (0, 1):
            for scenario in ("content-provider", "content"):
                prefix = ('scenario=$1\nPHASE=pressure-failed\nOBSERVED_BLOCKER=pressure-blocker\nFINALIZED=no\n'
                    f'content_provider_pressure_cleanup() {{ printf "pressure\\n"; return {failure}; }}\n'
                    'content_provider_late_recovery_cleanup() { printf "late\\n"; }\n'
                    'content_provider_cancellation_resume() { printf "cancel\\n"; }\n')
                command = prefix + 'cleanup_prelude() {\n' + early + '\n}\ntrue\ncleanup_prelude\n'
                command += 'printf "%s:%s:%s\\n" "$original_status" "$failure_phase" "$failure_reason"\n'
                result = shell(command, scenario)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = f"pressure\nlate\ncancel\n{failure}" if scenario == "content-provider" else "0"
                self.assertEqual(result.stdout.decode(), expected + ":pressure-failed:pressure-blocker\n")
        # No phase was entered: an unavailable hook must not make cleanup fail.
        command = ('scenario=content-provider\nPHASE=preflight\nOBSERVED_BLOCKER=none\nFINALIZED=no\n'
                   'cleanup_prelude() {\n' + early + '\n}\ntrue\ncleanup_prelude\n')
        self.assertEqual(shell(command).returncode, 0)

    def test_pressure_phase_runs_once_after_https_before_shared_teardown(self):
        adaptive = (HERE / "content-provider-adaptive-smoke.sh").read_text()
        matches = list(re.finditer(r"^    content_provider_pressure_run$", adaptive, re.M))
        self.assertEqual(len(matches), 1)
        start = matches[0].start()
        self.assertLess(adaptive.index("\n    content_provider_adaptive_https_run\n"), start)
        self.assertLess(start, adaptive.index("\n    PHASE=content-provider-adaptive-cleanup\n"))
        pressure = (HERE / "content-provider-pressure-smoke.sh").read_text()
        self.assertIn('"$WORK/bin/content-provider-pressure.py" observe "$WORK"', pressure)
        self.assertIn('"$source_directory/tests/integration/content-provider-pressure-smoke.py"', pressure)
        for operation in ("mark", "finish", "pending"):
            self.assertIn(f"content_provider_worker_budget_capture {operation} pressure", pressure)

    def test_privacy_registration_is_exact_and_timing_matches_adaptive(self):
        registration = TOPOLOGY.split("start_privacy_observers() {\n", 1)[1].split("    set --\n", 1)[0]
        command = 'registered() {\n' + registration + '}\nscenario=$1\nregistered "$2"\n'
        for scenario in ("content-provider", "content", "content-https"):
            for prefix in ("content-provider-pressure-privacy", "content-provider-pressure-other", "../pressure-privacy"):
                self.assertEqual(shell(command, scenario, prefix).returncode == 0,
                                 scenario == "content-provider" and prefix == "content-provider-pressure-privacy")
        import os
        code = "provider_timing_enabled = " + TOPOLOGY.split("provider_timing_enabled = ", 1)[1].split("provider_payload_timing =", 1)[0]
        for role in ("exit", "client"):
            for enabled in (True, False):
                for name in ("adaptive", "adaptive-https", "pressure", "pressure-other"):
                    scope = dict(os=os, role=role, content_provider_mode=enabled,
                                 output_path=f"/fixture/content-provider-{name}-privacy-exit.json")
                    exec(compile(code, "inert-timing-selection", "exec"), scope)
                    self.assertEqual(scope["provider_timing_enabled"], enabled and role == "exit" and name != "pressure-other")
                    if name != "pressure-other":
                        self.assertEqual(scope["provider_payload_milestones"], [262144, 3932160])

    def test_workflows_run_pure_checks_and_current_not_historical_acceptance(self):
        for name in ("quality.yml", "alpha-topology.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text()
            for test in ("pressure", "pressure-smoke", "pressure-wiring", "worker-budget", "resource-ready"):
                self.assertIn(f"python3 -B tests/integration/test-content-provider-{test}.py", workflow)
            self.assertIn("sh -n tests/integration/content-provider-pressure-smoke.sh", workflow)
        workflow = (ROOT / ".github/workflows/alpha-topology.yml").read_text()
        step = workflow.split("- name: Require actual native provider discovery and protected fetch\n", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn('content-provider-smoke.py report "$report" "$GITHUB_SHA"', step)
        self.assertNotIn("historical-report", step)
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', step)

    def test_closed_emergency_names_and_unchanged_caps(self):
        api = collector()
        self.assertEqual(api["PRESSURE_PROVIDER_NAMES"], NAMES)
        self.assertEqual(api["PRESSURE_PRIORITY_NAMES"], {f"content-provider-pressure-{suffix}.json"
            for suffix in ("worker-budget", "continuation", "resource-ready", "evidence", "ready", "controller", "cleanup", "object", "fetch")})
        self.assertEqual((api["FILE_LIMIT"], api["TOTAL_LIMIT"], api["FILE_COUNT_LIMIT"]), (131072, 8388608, 64))
        for phase in ("adaptive", "adaptive-https"):
            for suffix in ("worker-budget", "continuation", "resource-ready"):
                self.assertIn(f"content-provider-{phase}-{suffix}.json", api["SAFE_NAMES"])

    def test_normal_and_emergency_pressure_export_allowlists_match(self):
        source = (HERE / "content-provider-smoke.sh").read_text()
        finalize = source.split("content_provider_finalize_report() {\n", 1)[1]
        selection = '        case $(basename -- "$provider_artifact") in' + finalize.split(
            '        case $(basename -- "$provider_artifact") in', 1)[1].split('        [ ! -f "$provider_artifact" ]', 1)[0]
        command = 'for provider_artifact do\n' + selection + '\nprintf "%s\\n" "$provider_artifact"\ndone\n'
        denied = {"content-provider-pressure-unknown.json", "content-provider-pressure-fetch.err",
                  "content-provider-pressure-controller.log", "content-provider-pressure-fetch.state",
                  "content-provider-pressure-privacy-relay3.json", "content-provider-pressure-relay2-serve.json",
                  "content-provider-pressure-privacy-bootstrap1.json"}
        result = shell(command, *sorted(NAMES | denied))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(result.stdout.decode().splitlines()), NAMES)

    def test_emergency_priority_keeps_terminal_and_outcomes_across_duplicate_roots(self):
        api = collector()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home, opt, proc, cgroups = (root / name for name in ("home", "opt", "proc", "cgroups"))
            for path in (home, opt, proc, cgroups): path.mkdir()
            work = opt / ("va." + "a" * 32 + ".ABC123")
            work.mkdir()
            published = home / "alpha-output"
            published.mkdir()
            for path in (published, work):
                (path / "content-provider-smoke.json").write_text('{"success":false}')
                (path / "current-phase").write_text("content-provider-pressure-fetch\n")
                for name in NAMES | api["LATE_PROVIDER_NAMES"]: (path / name).write_text('{"observed":true}')
                for index in range(60): (path / f"content-before-{index:02}.json").write_text("{}")
            archive = api["collect"](home, opt, "b" * 40, "content-provider", 124, cgroups, proc)
            with tarfile.open(archive, "r:gz") as bundle:
                files = set(bundle.getnames())
                summary = json.load(bundle.extractfile("vm-incomplete.json"))
            for label in ("published", "work-1"):
                for name in api["PRESSURE_PRIORITY_NAMES"] | {"content-provider-smoke.json", "current-phase"}:
                    self.assertIn(f"{label}/{name}", files)
            self.assertEqual(len(summary["diagnostics"]["files"]), 64)
            self.assertTrue(summary["diagnostics"]["partial"])
            self.assertFalse(summary["success"])

    def test_emergency_recovers_only_complete_exact_json_with_no_success_claim(self):
        api = collector()
        for scenario in ("content-provider", "content"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home, opt, proc, cgroups = (root / name for name in ("home", "opt", "proc", "cgroups"))
                for path in (home, opt, proc, cgroups): path.mkdir()
                work = opt / ("va." + "a" * 32 + ".ABC123")
                work.mkdir()
                published = home / "alpha-output"
                published.mkdir()
                (published / "content-provider-smoke.json").write_text('{"success":false}')
                (published / "current-phase").write_text("content-provider-pressure-fetch\n")
                for index in range(60): (work / f"content-before-{index:02}.json").write_text("{}")
                for name in NAMES | api["LATE_PROVIDER_NAMES"]: (work / name).write_text('{"observed":true}')
                oversized = "content-provider-pressure-evidence.json"
                (work / oversized).write_bytes(b" " * (api["FILE_LIMIT"] + 1))
                alias = "content-provider-pressure-cleanup.json"
                (work / alias).unlink()
                (work / alias).symlink_to(work / "content-before-00.json")
                malformed = "content-provider-pressure-controller.json"
                (work / malformed).write_text('{"interrupted":')
                for name in ("content-provider-pressure-fetch.state", "content-provider-pressure-unknown.json",
                             "content-provider-pressure-fetch.err", ".content-provider-pressure-relay3-final.json"):
                    (work / name).write_text("PRIVATE RAW INPUT")
                archive = api["collect"](home, opt, "b" * 40, scenario, 124, cgroups, proc)
                with tarfile.open(archive, "r:gz") as bundle:
                    files = {member.name: bundle.extractfile(member).read() for member in bundle.getmembers()}
                selected = {name.rsplit("/", 1)[-1] for name in files if "/content-provider-pressure-" in name}
                self.assertEqual(selected, NAMES - {oversized, alias, malformed} if scenario == "content-provider" else set())
                if scenario == "content-provider":
                    self.assertIn("published/content-provider-smoke.json", files)
                    self.assertIn("published/current-phase", files)
                self.assertFalse(any(b"PRIVATE" in value for value in files.values()))
                summary = json.loads(files["vm-incomplete.json"])
                self.assertIs(summary["success"], False)
                self.assertEqual(summary["cleanup"], {"complete": False, "verified": False})
                self.assertLessEqual(len(summary["diagnostics"]["files"]), 64)
                self.assertLessEqual(summary["diagnostics"]["captured_bytes"], 8388608)


if __name__ == "__main__":
    unittest.main()
