#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert fixture/provenance/receipt tests. No model, VM or network is executed."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
C = runpy.run_path(str(HERE / "agent-cooperative-code-proposal.py"))


def driver():
    value = dict.fromkeys(C["FLAGS"], True)
    value.update(version=1, kind="public-code-single-file-trial-v1", phase="complete", failure=None,
        cleanup_failure=None, original_source_sha256=C["sha"](C["ORIGINAL"]), original_tests_sha256=C["TEST_SHA"],
        question_sha256=C["QUESTION_SHA"], license="GPL-3.0-only", owner_check_status="passed", elapsed_ms=100)
    for key in ("synthetic_model_answers", "synthetic_public_core", "local_planner_used", "private_peer_execution_proven",
            "full_coding_quality_proven"):
        value[key] = False
    result = dict.fromkeys(C["RESULT_HASHES"], "a" * 64)
    result.update(tool_call_id="owner-public-code-trial-1", core_task_id="b" * 32, model_profile=C["PROFILE"],
        source_sha256=C["sha"](C["ORIGINAL"]), source_bytes=len(C["ORIGINAL"]), peer_job_id="c" * 32,
        model_fingerprint=C["FINGERPRINT"], output_bytes=5, proposal_complete=True, stop_reason="eos",
        generated_tokens=4, core_reported_cleanup_confirmed=True)
    value["public_result"] = result
    return value


def manifest():
    result = dict(version=1, kind="public-code-proposal-inputs", code_revision=C["CODE_REVISION"], node_version="24.19.0",
        files={name: dict(bytes=1, sha256="a" * 64, mode=0o700 if name == "runtime/node" else 0o600)
            for name in C["BUNDLE_FILES"]})
    node = C["read"](HERE / "agent-private-conversation-pins.json")["runtime"]["files"]
    for name, origin in (("runtime/node", "bin/node"), ("runtime/node-LICENSE", "LICENSE")):
        result["files"][name].update(node[origin])
    return result


def phase_evidence():
    # Synthetic parser data only: these counters never stand in for real captures.
    custody = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["fixture"]()
    layout = custody["layout"]; layout["provider_nodes"] = ["relay4"]
    layout["provider_keys"] = {"relay4":layout["provider_keys"]["relay4"]}
    shown = driver(); shown["public_result"]["provider_key"] = layout["provider_keys"]["relay4"]
    path = custody["phases"]["fetch"]
    discovery_path = copy.deepcopy(path)
    discovery_path["gates"]["event_baseline_unix_ms"] = 500
    path["privacy"]["exit"]["provider_application"]["relay5"] = dict(request_packets=0, response_packets=0, response_payload_bytes=0)
    discovery = dict(version=1, purpose="original_control_frame_phase_observation", failure=None,
        discovery=dict(request_sha256="a"*64, response_sha256="b"*64, public_code_v6_only=True,
            minimum=1, maximum=1, selected_count=1, task_requests_before_release=0),
        discovery_response_released=False, selected_provider_key=layout["provider_keys"]["relay4"],
        operations=dict(capabilities=0, submit=0, poll=0, cancel=0), completed_exchanges=0,
        connections=1, active_connections=1, byte_preserving=True, responses_generated=False)
    control = copy.deepcopy(discovery)
    control.update(discovery_response_released=True, operations=dict(capabilities=1, submit=1, poll=2, cancel=0),
        completed_exchanges=5, connections=5, active_connections=0)
    return dict(source_revision="a"*40, public_service_stopped=True, peer_broker_stopped=True,
        private_state_removed=True, provision=dict(manifest=manifest()), driver=shown,
        result=dict(shown["public_result"], exact_receipt_join=True, original_input_observed=True,
            observed_task_processes_ended=True), layout=layout, peers=custody["expected_peers"],
        observation=dict(isolated_live_worker=True, observed_task_processes_ended=True,
            base_model_sha256=C["MODEL"]["base_weights"]["sha256"],
            dataset_sha256=shown["public_result"]["dataset_sha256"], node="relay4"),
        private_cleanup=dict(observed_compute_processes_ended=True, model_runtime_removed=True,
            private_job_roots_removed=True, publisher_key_removed=True),
        discovery=discovery, control=control, path=path, discovery_path=discovery_path,
        discovery_drain=dict(version=1, scope="owned_kernel_provider_tcp_before_capture_drain",
            inspected_nodes=["exit", "relay3", "relay4", "relay5"], tables=8, live_tcp_streams=0, time_wait_sockets=2))


class PublicCodeProposal(unittest.TestCase):
    def test_separate_original_discovery_and_exact_worker_execution(self):
        C["check_evidence"](phase_evidence(), "a"*40)
        mutations = (
            lambda v: v["discovery"]["operations"].update(submit=1),
            lambda v: v["control"].update(responses_generated=True),
            lambda v: v["control"].update(byte_preserving=False),
            lambda v: v["control"].update(selected_provider_key="f"*64),
            lambda v: v["control"]["discovery"].update(response_sha256="c"*64),
            lambda v: v["control"].update(active_connections=1),
            lambda v: v["control"].update(completed_exchanges=4),
            lambda v: v["control"].update(failure="invalid_frame"),
            lambda v: v["discovery_drain"].update(live_tcp_streams=1),
            lambda v: v["discovery_path"]["gates"].update(event_baseline_unix_ms=1000),
            lambda v: v["path"]["privacy"]["exit"]["provider_application"]["relay5"].update(request_packets=1),
            lambda v: v["path"]["control_privacy"]["content_control_pairs"]["cp1"].append("wrong-link"),
        )
        for mutate in mutations:
            value = phase_evidence(); mutate(value)
            with self.assertRaises(ValueError): C["check_evidence"](value, "a"*40)

    def test_capture_barrier_order_and_no_fixture_or_runtime_substitution(self):
        shell = (HERE / (C["NAME"] + ".sh")).read_text()
        ordered = ["content_custody_phase_start executor-discovery", '"$proposal_script" await-discovery',
            "content_custody_phase_finish 1", "content_custody_phase_start fetch", '"$proposal_script" release-discovery',
            '"$proposal_script" observe']
        offsets = [shell.index(value) for value in ordered]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('--control-socket "$code_control_socket"', shell)
        self.assertIn('--upstream "$WORK/runtime-client/control/agent.sock"', shell)
        self.assertIn('--max-seconds 600 --max-task-seconds 2400', shell)
        self.assertEqual(C["CODE_REVISION"], "f27576ebd7e7ded2f1319186f34df87f48e970d7")
        self.assertIn("content-custody-executor-discovery-privacy-exit.json", C["EXPORT_NAMES"])
        self.assertIn(C["NAME"] + "-control.json", C["EXPORT_NAMES"])

    def test_kernel_stream_barrier_does_not_confuse_listener_timewait_and_active_flow(self):
        header = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        def row(state, port="46A0"):
            return f"0: 00000000:{port} 00000000:0000 {state} 0 0 0 0 0 0\n"
        self.assertEqual(C["tcp_counts"](header + row("0A") + row("06")), (0, 1))
        for state in ("01", "02", "03", "04", "05", "08", "09", "0B", "0C"):
            self.assertEqual(C["tcp_counts"](header + row(state)), (1, 0))
        self.assertEqual(C["tcp_counts"](header + row("01", "1000")), (0, 0))
        for value in ("", header + row("0D"), header + "malformed", "x"*1048577):
            with self.assertRaises(ValueError): C["tcp_counts"](value)

    def test_exact_closed_export_set_includes_both_phase_captures(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        raw = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        module = {"__name__":"public_code_export_contract"}
        exec(compile(raw, "inert-collector", "exec"), module)
        self.assertEqual(module["COOPERATIVE_CODE_PROPOSAL_NAMES"], set(C["EXPORT_NAMES"]) |
            {"host-state-before.json", "host-state-after.json", "guest-exit-status", "current-phase"})

    def test_exact_node_only_manifest_and_purpose(self):
        C["bundle_manifest"](manifest())
        self.assertEqual(len(C["BUNDLE_FILES"]), 28)
        self.assertNotIn("runtime/opencode", C["BUNDLE_FILES"])
        for key, value in (("kind", "opencode-cooperative-inputs"), ("code_revision", "0" * 40), ("node_version", "24.0.0")):
            item = manifest(); item[key] = value
            with self.assertRaises(ValueError): C["bundle_manifest"](item)
        for name, key, value in (("runtime/node", "sha256", "b" * 64), ("runtime/node-LICENSE", "bytes", 1),
                ("code/scripts/smoke_public_code_proposal.cjs", "mode", 0o777)):
            item = manifest(); item["files"][name][key] = value
            with self.assertRaises(ValueError): C["bundle_manifest"](item)

    def test_driver_requires_original_tests_true_baseline_and_permissions(self):
        C["driver"](driver(), successful=True)
        for key in ("original_baseline_failed", "original_tests_unchanged", "owner_edit_approved", "owner_test_approved",
                "replacement_applied", "independent_test_passed", "owner_cleanup_confirmed", "project_removed"):
            value = driver(); value[key] = False
            with self.assertRaises(ValueError): C["driver"](value, successful=True)
        for key in ("original_source_sha256", "original_tests_sha256", "question_sha256"):
            value = driver(); value[key] = "f" * 64
            with self.assertRaises(ValueError): C["driver"](value)

    def test_driver_preserves_real_failure_without_promoting_token_limit(self):
        value = driver(); value.update(passed=False, phase="owner_check", failure="public_code_trial_failed", owner_check_status="unavailable")
        C["driver"](value)
        with self.assertRaises(ValueError): C["driver"](value, successful=True)
        value = driver(); value["public_result"]["stop_reason"] = "token_limit"
        C["driver"](value)
        with self.assertRaises(ValueError): C["driver"](value, successful=True)
        value = driver(); value["private_payload"] = "must not export"
        with self.assertRaises(ValueError): C["driver"](value)

    def test_raw_receipt_join_rejects_source_model_and_output_mutations(self):
        # Explicit synthetic parser data, not an executed coding result.
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp); (task / "execution").mkdir()
            write = lambda path, value: path.write_text(json.dumps(value, separators=(",", ":")))
            source_manifest = b"synthetic source manifest"
            (task / "source.manifest").write_bytes(source_manifest)
            (task / "dataset.manifest").write_bytes(b"synthetic dataset manifest")
            dataset = dict(version=6, visibility="public", purpose="code_proposal", license="GPL-3.0-only",
                model_profile=C["PROFILE"], source_manifest_hex=source_manifest.hex(),
                inference=[dict(question="synthetic parser question", context=C["ORIGINAL"].decode(), start=0, end=len(C["ORIGINAL"]))],
                output_contract="single_file_replacement_v1")
            write(task / "dataset.json", dataset)
            raw = (task / "dataset.json").read_bytes()
            result = driver()["public_result"]
            result.update(dataset_sha256=C["sha"](raw), dataset_manifest_id=C["digest"](task / "dataset.manifest"),
                source_manifest_id=C["sha"](source_manifest))
            handle = dict(binding=dict(job_id=result["peer_job_id"], row_indices=[0], task=None,
                    dataset_sha256=result["dataset_sha256"], dataset_manifest_id=result["dataset_manifest_id"],
                    model_fingerprint=C["FINGERPRINT"]), provider_key=result["provider_key"],
                capabilities=dict(code_proposal_v6=True, model=C["MODEL"]))
            write(task / "execution/job-0.json", handle)
            text = "synthetic candidate; not an executed model answer"
            report = dict(mode="public_code_proposal", purpose="code_proposal", output_contract="single_file_replacement_v1",
                proposal_complete=True, model_weights_loaded=True, supervisor=dict(child_reaped=True, network_access=False),
                private_data_supported=False, public_data_only=True, artifacts=[], updates_completed=0,
                model=dict(id=C["MODEL"]["model_id"], revision=C["MODEL"]["model_revision"], files={"model.safetensors":C["MODEL"]["base_weights"]}),
                dataset=dict(sha256=result["dataset_sha256"], source_manifest_sha256=result["source_manifest_id"], source_sha256=C["sha"](C["ORIGINAL"])),
                outputs=[dict(sample_index=0, text=text, text_truncated=False, generated_tokens=4,
                    generation=dict(version=1, stop_reason="eos", max_new_tokens=1024, model_profile=C["PROFILE"]))])
            result.update(output_sha256=C["sha"](text.encode()), output_bytes=len(text.encode()))
            layout = dict(provider_nodes=["relay4"], provider_keys={"relay4":result["provider_key"]})
            observed = dict(dataset_file=dict(sha256=result["dataset_sha256"]), dataset_json=raw.decode(), node="relay4")
            def check(value):
                raw_report = json.dumps(value, separators=(",", ":")); result["report_sha256"] = C["sha"](raw_report.encode())
                write(task / ("execution/receipt-" + result["peer_job_id"] + ".json"), dict(handle=handle,
                    status=dict(binding=handle["binding"], state="complete", cancellation_requested=False,
                        report_json=raw_report, report_sha256=result["report_sha256"])))
                return C["retained_result"](task, result, layout, observed)
            self.assertTrue(check(report)["exact_receipt_join"])
            for key, value in (("purpose", "document"), ("proposal_complete", False), ("private_data_supported", True)):
                changed = copy.deepcopy(report); changed[key] = value
                with self.assertRaises(ValueError): check(changed)
            for key, value in (("text", "rewritten candidate"), ("text_truncated", True)):
                changed = copy.deepcopy(report); changed["outputs"][0][key] = value
                with self.assertRaises(ValueError): check(changed)
            changed = copy.deepcopy(report); changed["outputs"][0]["generation"]["stop_reason"] = "token_limit"
            with self.assertRaises(ValueError): check(changed)
            observed["dataset_json"] += " "
            with self.assertRaises(ValueError): check(report)

    def test_preview_registration_and_bundle_arguments_fail_before_host_changes(self):
        for name in ("kvm-alpha-topology.sh", "run-alpha-topology-vm.sh"):
            result = subprocess.run(["sh", str(HERE / name), "--preview", "--scenario", C["NAME"]], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no local model", result.stdout)
            self.assertIn("PREVIEW ONLY", result.stdout)
        result = subprocess.run(["sh", str(HERE / "kvm-alpha-topology.sh"), "--execute", "--yes", "--scenario", C["NAME"],
            "--source", "/absent", "--bin", "/absent", "--mpquic", "/absent", "--output", "/absent", "--expected-commit", "a" * 40],
            capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 64)

    def test_owner_service_has_no_model_and_only_one_broker_is_started(self):
        shell = (HERE / (C["NAME"] + ".sh")).read_text()
        service = shell.split("compute public-serve", 1)[1].split("|| fail CODE_PROPOSAL_SERVICE_FAILED", 1)[0]
        self.assertIn("--code-proposal-v6 --model-profile qwen3-0.6b-v1 --discover-peers", service)
        for flag in ("--runtime-root", "--model-root", "--provider-key"):
            self.assertNotIn(flag, service)
        jobs = (HERE / "agent-jobs-smoke.sh").read_text()
        self.assertIn('[ "${agent_cooperative_code_proposal:-no}" != yes ] || [ "$jobs_node" = "$provider_node_a" ]', jobs)
        self.assertIn("--property=MemoryMax=7516192768 --property=MemorySwapMax=0", jobs)
        self.assertIn("prepare-code-proposal", jobs)
        self.assertIn('model-pins-qwen3-0.6b.json', (HERE / "kvm-alpha-topology.sh").read_text())


if __name__ == "__main__":
    unittest.main()
