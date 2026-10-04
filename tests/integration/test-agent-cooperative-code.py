#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure synthetic input/evidence boundaries; no core, runtime, model or VM launch."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "agent-cooperative-code.py"))


def manifest():
    return dict(version=1, kind="opencode-cooperative-inputs", code_revision=CHECK["CODE_REVISION"],
        opencode_revision=CHECK["OPENCODE_REVISION"], opencode_binary_sha256="a" * 64, node_version="24.19.0",
        files={name: dict(bytes=1, sha256="a" * 64, mode=0o700 if name in ("runtime/opencode", "runtime/node") else 0o600)
               for name in CHECK["BUNDLE_FILES"]})


def driver():
    value = dict.fromkeys(CHECK["DRIVER_FIELDS"], False)
    value.update(version=1, kind="opencode-external-public-core-cooperation", passed=True, phase="complete", failure=None,
        source_commit=CHECK["OPENCODE_REVISION"], license="GPL-3.0-only", refused_actions=0,
        public_submissions=1, public_completed=1, elapsed_ms=100)
    for key in value:
        if key.endswith("sha256"):
            value[key] = "a" * 64
    for key in ("synthetic_private_planner", "externally_supplied_public_endpoint", "peer_worker_receipts_and_datapath_owned_by_parent",
                "source_binding_to_core_manifest_owned_by_parent", "vm_cleanup_owned_by_parent", "actual_native_turn_completed",
                "original_tool_result_roundtrip", "runtime_cleanup_confirmed", "public_owner_cleanup_confirmed",
                "planner_cleanup_confirmed", "project_removed"):
        value[key] = True
    value["original_public_result"] = dict(tool_call_id="external-public-cooperation-1", core_task_id="b" * 32,
        original_tool_result_sha256="c" * 64, original_core_result_sha256="d" * 64, output_sha256="e" * 64,
        output_bytes=42, source_manifest_id="f" * 64, provider_keys=["1" * 64, "2" * 64],
        selected_provider_keys=["1" * 64, "2" * 64], answer_complete=True, answer_status="complete",
        execution_complete=True, joining="hierarchical_peer_synthesis", package_count=2, total_parts=8,
        synthesis_levels=2, core_reported_remote_cleanup_confirmed=True, complete_with_two_execution_providers=True)
    return value


class CooperativeCode(unittest.TestCase):
    def test_code_uses_shared_closed_refinement_projection_without_content(self):
        value = dict(version=1, enabled=True, complete=False, reason="children_incomplete", split_levels=1,
            parents=[dict(complete=False, parent_job_id="PRIVATE_ID", children=[dict(complete=True,
                answer_complete=False, generation=dict(version=1, stop_reason="token_limit"), text="PRIVATE_OUTPUT")])],
            answers=[])
        projected = CHECK["BROWSER"]["closed_refinement"](value)
        self.assertEqual(projected["state"], "valid")
        self.assertFalse(projected["status"]["complete"])
        self.assertEqual(projected["status"]["child_generation_counts"]["token_limit"], 1)
        self.assertNotIn("PRIVATE", json.dumps(projected))

    def test_guest_registration_preview_and_invalid_inputs_never_reach_execution(self):
        script = HERE / "kvm-alpha-topology.sh"
        def invoke(*args, env=None):
            return subprocess.run(["sh", str(script), *args], capture_output=True, text=True, timeout=5, env=env)
        preview = invoke("--preview", "--scenario", "agent-cooperative-code")
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("cooperative Code proof plan", preview.stdout)
        self.assertIn("no private peer confidentiality", preview.stdout)
        base = ["--execute", "--yes", "--source", "/absent-source", "--bin", "/absent-bin",
                "--output", "/absent-output", "--mpquic", "/absent-mpquic", "--expected-commit", "a" * 40]
        code = [*base, "--scenario", "agent-cooperative-code"]
        bundle = ["--code-bundle", "/explicit-code", "--code-manifest-sha256", "a" * 64]
        invalid = [
            [*code], [*code, "--code-bundle", "/explicit-code"],
            [*code, "--code-manifest-sha256", "a" * 64],
            [*code, "--code-bundle", "relative", "--code-manifest-sha256", "a" * 64],
            [*code, "--code-bundle", "/a/../b", "--code-manifest-sha256", "a" * 64],
            [*code, "--code-bundle", "/explicit-code", "--code-manifest-sha256", "A" * 64],
            [*code, "--code-bundle", "/explicit-code", "--code-manifest-sha256", "a" * 63],
            [*code, *bundle, "--code-bundle", "/second"],
            [*code, *bundle, "--code-manifest-sha256", "b" * 64],
            [*base, "--scenario", "agent-cooperative-browser", *bundle],
            [*code, *bundle, "--scenario", "agent-jobs"],
            ["--preview", "--scenario", "agent-cooperative-code", *bundle],
        ]
        for args in invalid:
            with self.subTest(args=args):
                result = invoke(*args)
                self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        result = invoke(*code, env=dict(os.environ, COOPERATIVE_CODE_BUNDLE="/environment-only",
                                       COOPERATIVE_CODE_MANIFEST_SHA256="a" * 64))
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        selected = invoke("--preview", "--scenario", "agent-cooperative-code", "--scenario", "agent-cooperative-browser")
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertNotIn("cooperative Code proof plan", selected.stdout)
        self.assertIn("cooperative browser proof plan", selected.stdout)

    def test_guest_dispatch_dependencies_finalization_and_exact_unit_cleanup(self):
        topology = (HERE / "kvm-alpha-topology.sh").read_text()
        jobs = (HERE / "agent-jobs-smoke.sh").read_text()
        self.assertIn('agent-cooperative-code) scenario=agent-jobs; agent_cooperative_code=yes;', topology)
        self.assertIn('. "$source_directory/tests/integration/agent-cooperative-code.sh"', topology)
        for dependency in ("agent-cooperative-code.py", "agent-cooperative-code.sh", "agent-cooperative-browser.py",
                           "agent-private-conversation-pins.json", "agent-document-synthesis.py"):
            self.assertIn(dependency, topology)
        self.assertIn('COOPERATIVE_CODE_BUNDLE=$code_bundle', topology)
        self.assertIn('COOPERATIVE_CODE_MANIFEST_SHA256=$code_manifest_sha256', topology)
        self.assertIn('agent_cooperative_code_account_home_cleanup || return 1', jobs)
        self.assertIn('agent_jobs_setup\n    if [ "${agent_cooperative_code_proposal:-no}" = yes ]; then\n'
            '        agent_cooperative_code_proposal_run\n        return\n    fi\n'
            '    if [ "${agent_cooperative_code:-no}" = yes ]; then\n        agent_cooperative_code_run', jobs)
        self.assertIn('agent_cooperative_code_finalize_report "$jobs_status"\n        return', jobs)
        # Source only function definitions and replace all system access. This
        # exercises the exact production allowlist without touching a real unit.
        command = '''
set -eu
. "$1"
systemctl() {
    case "$*" in
        "show --property=LoadState --value "*) printf '%s\\n' not-found ;;
        "show --property=ActiveState --value "*) printf '%s\\n' inactive ;;
        "show --property=MainPID --value "*) printf '%s\\n' 0 ;;
        "reset-failed "*) return 0 ;;
        *) return 1 ;;
    esac
}
agent_jobs_cgroup_empty() { return 0; }
agent_jobs_stop_unit volparossa-alpha-public-code.service
agent_jobs_stop_unit volparossa-alpha-cooperative-code.service
if agent_jobs_stop_unit unrelated.service; then exit 1; fi
if agent_jobs_stop_unit volparossa-alpha-public-code-extra.service; then exit 1; fi
'''
        result = subprocess.run(["sh", "-c", command, "test", str(HERE / "agent-jobs-smoke.sh")],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bundle_is_closed_and_binds_exact_source_runtime_and_executable_modes(self):
        CHECK["bundle_manifest"](manifest())
        for change in (
            lambda v: v.update(code_revision="0" * 40),
            lambda v: v.update(opencode_revision="0" * 40),
            lambda v: v.update(node_version="latest"),
            lambda v: v.update(opencode_binary_sha256="b" * 64),
            lambda v: v["files"].update({"code/../../evil": dict(bytes=1, sha256="a" * 64, mode=0o600)}),
            lambda v: v["files"].pop("code/scripts/smoke_opencode_cooperation.cjs"),
            lambda v: v["files"]["runtime/node"].update(mode=0o777),
            lambda v: v["files"]["runtime/opencode"].update(bytes=161 * 1048576),
            lambda v: v["files"]["code/LICENSE"].update(mode=0o700),
        ):
            value = manifest()
            change(value)
            with self.assertRaises(ValueError):
                CHECK["bundle_manifest"](value)

    def test_unique_manifest_not_wire_id_joins_retained_task_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            first = state / ("task-" + "7" * 32)
            (first / "document").mkdir(parents=True)
            raw = b"synthetic signed-manifest bytes, not peer execution evidence"
            (first / "document/source.manifest").write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with mock.patch.dict(CHECK["BROWSER"], task_roots=lambda _: [first]):
                self.assertEqual(CHECK["unique_document"](state, digest), first / "document")
                with self.assertRaises(ValueError):
                    CHECK["unique_document"](state, "b" * 64)
            second = state / ("task-" + "9" * 32)
            (second / "document").mkdir(parents=True)
            (second / "document/source.manifest").write_bytes(raw)
            with mock.patch.dict(CHECK["BROWSER"], task_roots=lambda _: [first, second]):
                with self.assertRaises(ValueError):
                    CHECK["unique_document"](state, digest)

    def test_driver_exports_only_closed_fields_and_preserves_incomplete_failure(self):
        value = driver()
        CHECK["driver"](value, successful=True)
        value.update(passed=False, phase="observed-public-result", failure="public_answer_incomplete")
        value["original_public_result"].update(answer_complete=False, answer_status="incomplete", execution_complete=False,
            complete_with_two_execution_providers=False, provider_keys=[], joining="awaiting_fragments_before_peer_synthesis")
        CHECK["driver"](value)
        with self.assertRaises(ValueError):
            CHECK["driver"](value, successful=True)
        for change in (
            lambda v: v.update(private_peer_execution_proven=True),
            lambda v: v.update(synthetic_private_planner=False),
            lambda v: v.update(prompt="PRIVATE SOURCE"),
            lambda v: v.update(failure="PRIVATE EXCEPTION /secret"),
            lambda v: v["original_public_result"].update(output="PRIVATE ANSWER"),
            lambda v: v["original_public_result"].update(provider_keys=["1" * 64]),
            lambda v: v.update(public_owner_cleanup_confirmed=False),
        ):
            value = driver()
            change(value)
            with self.assertRaises(ValueError):
                CHECK["driver"](value, successful=True)

    def test_result_join_binds_original_source_answer_and_providers(self):
        shown = driver()["original_public_result"]
        snapshot = dict(context="exact public source")
        result = {name: shown[name] for name in ("source_manifest_id", "output_sha256", "package_count", "total_parts", "synthesis_levels")}
        result.update(provider_keys=shown["provider_keys"], source_sha256=hashlib.sha256(snapshot["context"].encode()).hexdigest(),
            context_bytes=len(snapshot["context"].encode()), answer_complete=True, execution_complete=True,
            exact_native_receipts_verified=True)
        CHECK["join_result"](shown, result, snapshot)
        for change in (dict(output_sha256="0" * 64), dict(source_sha256="0" * 64),
                       dict(provider_keys=["1" * 64]), dict(exact_native_receipts_verified=False)):
            with self.assertRaises(ValueError):
                CHECK["join_result"](shown, dict(result, **change), snapshot)

    def test_failure_export_does_not_include_private_logs_or_claim_browser_and_cancellation(self):
        names = CHECK["EXPORT_NAMES"]
        self.assertTrue(all(name.endswith(".json") for name in names))
        self.assertFalse(any(".private" in name or ".log" in name or ".err" in name or "panel" in name for name in names))
        self.assertIn("live_peer_cancellation_proven", CHECK["FALSE_SCOPE"])
        shell = (HERE / "agent-cooperative-code.sh").read_text()
        self.assertIn('capture "$WORK" "$code_driver_status" "$code_observer_status"', shell)
        self.assertLess(shell.index('capture "$WORK"'), shell.index('content_custody_phase_finish'))
        self.assertNotIn("firefox", shell.lower())
        self.assertNotIn('task-$', shell)

    def test_observer_status_retains_closed_failure_facts_not_exception_or_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "status.private"
            status = dict(version=1, phase="worker_scan", failure="observer_incomplete", observed_workers=1, task_count=1)
            output.write_text(json.dumps(status))
            output.chmod(0o600)
            self.assertEqual(CHECK["closed_observer"](output), dict(state="valid", status=status))
            for change in (dict(phase="PRIVATE QUESTION"), dict(failure="/private/path"),
                           dict(observed_workers=129), dict(task_count=True), dict(exception="PRIVATE ERROR")):
                output.write_text(json.dumps(dict(status, **change)))
                self.assertEqual(CHECK["closed_observer"](output), dict(state="invalid"))
            self.assertEqual(CHECK["closed_observer"](Path(temporary) / "absent"), dict(state="absent"))
        self.assertNotIn("agent-cooperative-code-observer-status.private", CHECK["EXPORT_NAMES"])


if __name__ == "__main__":
    unittest.main()
