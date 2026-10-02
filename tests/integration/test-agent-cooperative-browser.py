#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure synthetic proof-boundary controls; no browser, peer or model execution."""
import copy
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).parent
CHECK = runpy.run_path(str(HERE / "agent-cooperative-browser.py"))
BASE = runpy.run_path(str(HERE / "test-private-storage-replicas-smoke.py"))
REVISION = "a" * 40


def fixture():
    base = BASE["fixture"]()
    layout = base["layout"]
    keys = ["1" * 64, "2" * 64]
    layout["provider_keys"] = dict(zip(layout["provider_nodes"], keys))
    selected = CHECK["pins"]()
    value = dict(source_revision=REVISION, success=True, provision=selected,
        input=dict(context_bytes=3840, context_sha256="c" * 64, readme_sha256="d" * 64,
                   explicit_public_source=True, license="GPL-3.0-only"),
        result=dict(source_sha256="c" * 64, source_manifest_id="e" * 64, context_bytes=3840,
            total_parts=8, package_count=2, synthesis_levels=2, provider_keys=keys, jobs=8,
            output_sha256="f" * 64, execution_complete=True, answer_complete=True,
            semantic_completeness_proven=False, exact_native_receipts_verified=True),
        cleanup=dict(public_service_stopped=True, peer_brokers_stopped=True, browser_root_removed=True,
                     public_receipts_removed=True, socket_removed=True),
        private_cleanup=dict(observed_compute_processes_ended=True, model_runtime_removed=True,
                             private_job_roots_removed=True, publisher_key_removed=True),
        peers=base["expected_peers"], layout=layout, path=base["network"]["upload"],
        **dict.fromkeys(CHECK["FALSE_SCOPE"], False))
    workers = [dict(node=node, level=None, provider_key=key, dataset_sha256="a" * 64,
                    isolated_live_worker=True, base_model_sha256=CHECK["JOBS"]["TRAIN"]["WEIGHT_HASH"])
               for node, key in zip(layout["provider_nodes"], keys)]
    value["observation"] = dict(no_dispatch_before_consent=True, real_fragment_peers=sorted(layout["provider_nodes"]),
        observed_synthesis_levels=[0, 1], completed_workers=workers, cancelled_workers=workers[:1],
        cancel_target_had_live_peer_worker=True, observed_workers_ended=True)
    result = value["result"]
    displayed = {name: result[name] for name in ("source_manifest_id", "package_count", "total_parts",
                 "synthesis_levels", "output_sha256", "provider_keys", "execution_complete")}
    displayed["joining"] = "hierarchical_peer_synthesis"
    value["panel"] = dict(version=1, kind="real-gecko-cooperative-public-peers", passed=True,
        browser_source_sha256={name: record["sha256"] for name, record in selected["files"].items()},
        runtime_version=selected["runtime"]["version"], runtime_source_stamp=selected["runtime"]["source_stamp"],
        runtime_sha256=selected["runtime"]["files"], interfaces=["lo"], host_read_only=True, same_owner_socket_mode=0o600,
        core_revision=REVISION, temporary_browser_data_removed=True, observed=dict(prefill_no_dispatch=True,
            explicit_consent=True, text_only=True, scoped_cancel_confirmed=True, first_task_id=1,
            cancel_task_id=2, first_result=displayed))
    return value


def discovered_fixture():
    check = runpy.run_path(str(HERE / "agent-cooperative-browser.py"))
    check["select_trial"]("discovered-360m")
    value = fixture()
    fields, profile = check["trial_fields"](), check["selected_model"]()
    for item in (value, value["input"], value["result"]):
        item.update(fields)
    for item in (value["input"], value["result"]):
        item["context_bytes"] = 4096
    value["result"].update(total_parts=2, package_count=1, synthesis_levels=1, jobs=3,
        selected_provider_keys=list(reversed(value["result"]["provider_keys"])), model_fingerprint=profile["fingerprint"])
    value["observation"]["observed_synthesis_levels"] = [1]
    for row in value["observation"]["completed_workers"] + value["observation"]["cancelled_workers"]:
        row["base_model_sha256"] = profile["model"]["base_weights"]["sha256"]
    displayed = value["panel"]["observed"]["first_result"]
    for key in ("total_parts", "package_count", "synthesis_levels", "selected_provider_keys"):
        displayed[key] = value["result"][key]
    pin_root = HERE.parents[1] / "workers/volparossa-ml"
    pins = json.loads((pin_root / "model-pins.json").read_bytes())
    pins.update(json.loads((pin_root / "model-pins-360m.json").read_bytes()))
    value["model_provision"] = dict(success=True, installed_wheels=38, model_profile=profile["name"],
        model_id=profile["model"]["model_id"], revision=profile["model"]["model_revision"],
        download_bytes=sum(row["bytes"] for row in pins["files"] + pins["wheels"]),
        model_pins_sha256=check["sha"]((json.dumps(pins, indent=2) + "\n").encode()),
        requirements_sha256=check["sha"]((pin_root / "requirements.lock").read_bytes()),
        budget_bytes=3 * 1024**3, runtime_autofetch_enabled=False, training_performed=False)
    return check, value


class CooperativeBrowserProof(unittest.TestCase):
    def test_discovered_source_is_a_longer_literal_prefix_without_changing_legacy_input(self):
        check, _value = discovered_fixture()
        source = (HERE.parents[1] / "README.md").read_bytes()
        for current, limit in ((CHECK, 3840), (check, 4096)):
            selected = current["source_excerpt"](source)
            expected = source[:limit].decode("utf-8", errors="ignore")
            self.assertEqual(selected, expected)
            self.assertEqual(selected.encode(), source[:len(selected.encode())])
            self.assertEqual(current["QUESTION"], CHECK["DOCUMENT"]["QUESTION"])
            with self.assertRaises(ValueError):
                current["source_excerpt"](source[:limit - 1])
        self.assertTrue(check["source_excerpt"](source).startswith(CHECK["source_excerpt"](source)))
        # An incomplete final code point is excluded, not replaced or padded.
        multibyte = b"a" * 4095 + "\u20ac".encode() + b"tail"
        self.assertEqual(check["source_excerpt"](multibyte).encode(), multibyte[:4095])
        self.assertEqual(CHECK["source_excerpt"](multibyte).encode(), multibyte[:3840])

    def test_discovered_trial_has_separate_profile_shape_and_unchanged_required_proofs(self):
        check, value = discovered_fixture()
        check["check_evidence"](value, REVISION, value["provision"])
        with self.assertRaises(ValueError):
            CHECK["check_evidence"](value, REVISION, value["provision"])
        with self.assertRaises(ValueError):
            check["check_evidence"](fixture(), REVISION, value["provision"])
        # Removing provenance must not reinterpret a smaller trial as the historical proof.
        without_contract = copy.deepcopy(value)
        for row in (without_contract, without_contract["input"], without_contract["result"]):
            for key in check["trial_fields"]():
                row.pop(key)
        with self.assertRaises(ValueError):
            CHECK["check_evidence"](without_contract, REVISION, value["provision"])
        for mutation in (
            lambda v: v.update(trial_contract="fixed-135m"),
            lambda v: v["input"].update(scenario="agent-cooperative-browser"),
            lambda v: v["result"].update(answer_complete=False),
            lambda v: v["result"].update(execution_complete=False),
            lambda v: v["result"].update(source_sha256="0" * 64),
            lambda v: v["result"].update(provider_keys=["1" * 64]),
            lambda v: v["result"].update(selected_provider_keys=["1" * 64, "3" * 64]),
            lambda v: v["result"].update(model_fingerprint="0" * 64),
            lambda v: v["result"].update(synthesis_levels=0),
            lambda v: v["result"].update(total_parts=1),
            lambda v: v["panel"]["observed"].update(explicit_consent=False),
            lambda v: v["panel"]["observed"].update(scoped_cancel_confirmed=False),
            lambda v: v["model_provision"].update(download_bytes=523040250),
            lambda v: v["observation"]["completed_workers"][0].update(base_model_sha256=CHECK["JOBS"]["TRAIN"]["WEIGHT_HASH"]),
            lambda v: v["cleanup"].update(peer_brokers_stopped=False),
        ):
            bad = copy.deepcopy(value)
            mutation(bad)
            with self.assertRaises(ValueError):
                check["check_evidence"](bad, REVISION, value["provision"])

    def test_discovered_plan_preserves_exact_original_source_and_existing_profile_limits(self):
        check, _value = discovered_fixture()
        source = b"Explicit public source.\n" * 8
        model = check["selected_model"]()["model"]
        split = len(source) // 2
        plan = dict(version=1, source_bytes=len(source), source_sha256=check["sha"](source),
            question_sha256=check["sha"](check["QUESTION"].encode()), model_id=model["model_id"],
            model_revision=model["model_revision"], tokenizer_sha256=check["DOCUMENT"]["TOKENIZER"],
            prompt_limit=1024, parts=[dict(start=0, end=split, prompt_tokens=100),
                                     dict(start=split, end=len(source), prompt_tokens=100)])
        check["check_trial_plan"](plan, source)
        for mutation in (
            lambda v: v.update(prompt_limit=2048),
            lambda v: v.update(model_id="HuggingFaceTB/SmolLM2-135M-Instruct"),
            lambda v: v["parts"][1].update(start=split + 1),
            lambda v: v["parts"][1].update(end=len(source) - 1),
            lambda v: v["parts"][0].update(prompt_tokens=1025),
            lambda v: v.update(parts=[dict(start=0, end=len(source), prompt_tokens=100)]),
        ):
            bad = copy.deepcopy(plan)
            mutation(bad)
            with self.assertRaises(ValueError):
                check["check_trial_plan"](bad, source)
        # Real output is not involved: this is a rejection test for the selected EOS contract.
        output = dict(text="Fixture", text_truncated=False, generated_tokens=256,
            generation=dict(version=1, stop_reason="token_limit", max_new_tokens=256, model_profile="smollm2-360m-v1"))
        with self.assertRaises(ValueError):
            check["JOBS"]["TRAIN"]["check_generation"](output, require_eos=True, model_profile="smollm2-360m-v1")

    def test_discovered_selector_is_explicit_and_service_argv_has_no_fixed_peers(self):
        source = (HERE / "agent-cooperative-browser.sh").read_text()
        selected = source.split('    set -- --model-profile', 1)[1].split('    PHASE=agent-cooperative-browser-service', 1)[0]
        selector = 'set -- --model-profile' + selected
        for flag, expected in (("no", ["--model-profile", "smollm2-135m-v1", "--provider-key", "peer-a", "--provider-key", "peer-b"]),
                               ("yes", ["--model-profile", "smollm2-360m-v1", "--discover-peers"])):
            inert = 'jobs_key_a=peer-a\njobs_key_b=peer-b\nagent_cooperative_browser_discovered="$1"\n' + selector + '\nprintf "%s\\0" "$@"\n'
            result = subprocess.run(["sh", "-c", inert, "test", flag], capture_output=True, timeout=3, check=True)
            self.assertEqual(result.stdout.decode().split("\0")[:-1], expected)
        for selector in ([], ["--trial", "discovered-360m"]):
            result = subprocess.run(["python3", "-B", str(HERE / "agent-cooperative-browser.py"), *selector, "export-names"],
                                    capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual(result.stdout.splitlines(), list(CHECK["EXPORT_NAMES"]))
        rejected = subprocess.run(["python3", "-B", str(HERE / "agent-cooperative-browser.py"),
                                  "--trial", "arbitrary-model", "export-names"], capture_output=True, timeout=5)
        self.assertNotEqual(rejected.returncode, 0)

    def test_real_provision_and_broker_selectors_choose_one_unchanged_model_cohort(self):
        shell = (HERE / "agent-jobs-smoke.sh").read_text()
        prepare = shell.split('    set -- "$jobs_root"\n', 1)[1].split('    agent_jobs_private prepare', 1)[0]
        prepare = 'set -- "$jobs_root"\n' + prepare
        broker = shell.split('agent_jobs_broker() {', 1)[1].split('    set --\n', 1)[1]
        broker = 'set --\n' + broker.split('    if [ "${agent_policy_assessment:-no}" = yes ]; then', 1)[0]
        for flag in ("no", "yes"):
            initial = 'jobs_root=/fixture/jobs\nagent_cooperative_browser_discovered="$1"\n'
            expected = (["/fixture/jobs", "smollm2-360m-v1"] if flag == "yes" else ["/fixture/jobs"])
            for selector, wanted in ((prepare, expected),
                    (broker, ["--model-profile", "smollm2-360m-v1"] if flag == "yes" else [])):
                # Only execute actual argument-selection text, never install/systemd/model commands.
                command = initial + selector + '\nfor value do printf "%s\\0" "$value"; done\n'
                result = subprocess.run(["sh", "-c", command, "test", flag], env={"PATH": os.defpath},
                                        capture_output=True, timeout=3, check=True)
                got = result.stdout.decode().split("\0")[:-1] if result.stdout else []
                self.assertEqual(got, wanted)

    def test_observer_failure_is_retained_before_driver_interrupt_without_private_details(self):
        self.assertEqual(CHECK["observer_invariant_reason"](ValueError("actual worker mounts not isolated")),
                         "worker_mounts")
        self.assertIsNone(CHECK["observer_invariant_reason"](ValueError("PRIVATE_PROMPT /private/path")))
        self.assertIsNone(CHECK["observer_invariant_reason"](OSError("actual worker mounts not isolated")))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "agent-jobs-user/browser/build/cooperative-proof"
            output.mkdir(parents=True)
            (output / "pre-consent.json").write_text("{}")
            first = root / "synthetic-task"
            original = ValueError("PRIVATE_PROMPT /private/code.py key=do-not-export")
            def fail_scan(_work, _document, _layout, _brokers, observed):
                observed["PRIVATE_JOB_ID"] = {"private_path": "/private/code.py"}
                raise original
            jobs = dict(CHECK["JOBS"], guest_work=lambda _work: None,
                        identity=lambda pid: {"pid": pid}, broker_pid=lambda _node: 2,
                        alive=lambda _owner: True, worker_snapshot=lambda *_args: None)
            # Synthetic observer inputs only: no /proc, systemd, browser or worker is touched.
            with mock.patch.dict(CHECK["observe"].__globals__, {
                "JOBS": jobs, "read": lambda *_args: {"provider_nodes": ["peer-a"]},
                "marker": lambda *_args: None, "authorize": lambda *_args: None,
                "task_roots": mock.Mock(side_effect=[[], [first]]), "scan_workers": fail_scan,
            }):
                with self.assertRaises(ValueError) as raised:
                    CHECK["observe"](root, 1)
                self.assertIs(raised.exception, original)
            status_path = root / "agent-cooperative-browser-observer-status.private"
            expected = dict(version=1, phase="worker_scan", failure="invariant_or_unknown",
                            invariant_reason=None,
                            task_count=1, observed_workers=1, cancel_workers=0,
                            counts_saturated=False, driver_alive=True)
            self.assertEqual(CHECK["closed_observer"](status_path), dict(state="valid", status=expected))
            self.assertFalse((root / "agent-cooperative-browser-observation.json").exists())
            self.assertNotIn("PRIVATE", status_path.read_text())
            self.assertNotIn("/private", status_path.read_text())
            for mutation in (
                lambda value: value.update(phase="PRIVATE_PROMPT"),
                lambda value: value.update(failure="PRIVATE_PROMPT"),
                lambda value: value.update(invariant_reason="PRIVATE_PROMPT"),
                lambda value: value.update(private_path="/private/code.py"),
                lambda value: value.update(observed_workers=129),
                lambda value: value.update(task_count=True),
            ):
                invalid = dict(expected)
                mutation(invalid)
                status_path.write_text(json.dumps(invalid))
                self.assertEqual(CHECK["closed_observer"](status_path), dict(state="invalid"))
            # Failed diagnostic I/O must not replace the original observer failure.
            with mock.patch.dict(CHECK["observe"].__globals__, {
                "JOBS": jobs, "observe_inner": mock.Mock(side_effect=original),
                "write": mock.Mock(side_effect=OSError("PRIVATE_DIAGNOSTIC_PATH")),
            }):
                with self.assertRaises(ValueError) as raised:
                    CHECK["observe"](root, 1)
                self.assertIs(raised.exception, original)
        self.assertEqual(CHECK["closed_observer"](Path(temporary) / "absent"), dict(state="absent"))
        self.assertNotIn("agent-cooperative-browser-observer-status.private", CHECK["EXPORT_NAMES"])

    def test_rpc_stage_counts_are_allowlisted_bounded_and_keep_ring_coverage_explicit(self):
        source = (HERE.parents[1] / 'crates/volparossa-agent/src/content/compute_remote.rs').read_text()
        self.assertEqual(CHECK['RPC_EVENT_CODES'], set(re.findall(r'COMPUTE_RPC_[A-Z_]+_FAILED', source)))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'rpc-events.private'
            parse = lambda: CHECK['closed_rpc_events'](path, 100, 0)
            self.assertEqual(parse(), dict(state='absent'))
            def event(stamp, code):
                return f'{stamp}\tlevel=1\tevent={code}\tsession={"a" * 64}\tpath=2\n'
            text = event(99, 'COMPUTE_RPC_ROUTE_FLOW_FAILED') + event(101, 'COMPUTE_RPC_ROUTE_FLOW_FAILED')
            text += event(102, 'PRIVATE_UNKNOWN_CODE') + event(103, 'COMPUTE_RPC_ROUTE_SETUP_FAILED')
            path.write_text(text)
            path.chmod(0o600)
            value = parse()
            self.assertEqual(value['state'], 'valid')
            self.assertTrue(value['window_covers_baseline'])
            self.assertEqual(value['records'], 4)
            self.assertEqual(value['matching_failures'], 2)
            self.assertEqual(value['counts']['COMPUTE_RPC_ROUTE_FLOW_FAILED'], 1)
            self.assertEqual(value['counts']['COMPUTE_RPC_ROUTE_SETUP_FAILED'], 1)
            self.assertNotIn('PRIVATE', json.dumps(value))
            self.assertNotIn('a' * 64, json.dumps(value))
            path.write_text(event(101, 'COMPUTE_RPC_ROUTE_FLOW_FAILED'))
            self.assertFalse(parse()['window_covers_baseline'])
            self.assertEqual(CHECK['closed_rpc_events'](path, 100, 1), dict(state='query_failed'))
            for invalid in ('PRIVATE_DATA', event(101, 'COMPUTE_RPC_ROUTE_FLOW_FAILED') + event(100, 'COMPUTE_RPC_ROUTE_FLOW_FAILED'),
                            event(101, 'COMPUTE_RPC_ROUTE_FLOW_FAILED') * 1001, 'x' * 262145):
                path.write_text(invalid)
                self.assertEqual(parse(), dict(state='invalid'))
            path.write_text(text)
            path.chmod(0o644)
            self.assertEqual(parse(), dict(state='invalid'))
        shell = (HERE / 'agent-cooperative-browser.sh').read_text()
        self.assertLess(shell.index('logs --limit 1000'), shell.index('diagnostic "$WORK"'))
        self.assertNotIn('agent-cooperative-browser-rpc-events.private', CHECK['EXPORT_NAMES'])

    def test_coordinator_diagnostic_retains_only_closed_stage_and_cleanup_facts(self):
        value = dict(version=1, phase='tokenization', execution_ok=False,
            error_class='io_permission', rpc=None, local_cleanup_confirmed=False,
            receipts=dict(phase='complete', handles=0, receipts=0, terminal=0, error='none', confirmed=True),
            cleanup_confirmed=False)
        CHECK['check_execution_diagnostic'](value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'execution-diagnostic.json'
            self.assertEqual(CHECK['closed_execution'](path), dict(state='absent'))
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            self.assertEqual(CHECK['closed_execution'](path), dict(state='valid', status=value))
            for mutation in (
                lambda v: v.update(question='PRIVATE_PROMPT'),
                lambda v: v.update(phase='PRIVATE_PROMPT'),
                lambda v: v.update(error_class='PRIVATE_PROMPT'),
                lambda v: v.update(cleanup_confirmed=True),
                lambda v: v['receipts'].update(handles=16385),
                lambda v: v['receipts'].update(path='/private/secret'),
                lambda v: v.update(rpc=dict(category='exchange_unconfirmed', phase='poll', raw='PRIVATE_PROMPT')),
            ):
                bad = copy.deepcopy(value)
                mutation(bad)
                path.write_text(json.dumps(bad))
                captured = CHECK['closed_execution'](path)
                self.assertEqual(captured, dict(state='invalid'))
                self.assertNotIn('PRIVATE_PROMPT', json.dumps(captured))
        peer = dict(value, phase='peer_execution', error_class='peer_rpc',
                    rpc=dict(category='broker_rejected', phase='submit', code='busy'))
        CHECK['check_execution_diagnostic'](peer)
        recovered = dict(value, version=2, phase='complete', execution_ok=True, execution_complete=False,
            answer_complete=False, reconciliation=dict(attempted=1, terminal_persisted=0, deadline_reached=True,
                error='peer_rpc', rpc=dict(category='exchange_unconfirmed', phase='poll')))
        CHECK['check_execution_diagnostic'](recovered)
        # A returned Result::Ok is not complete inference and expiry is not cleanup.
        self.assertTrue(recovered['execution_ok'])
        self.assertFalse(recovered['execution_complete'])
        self.assertFalse(recovered['cleanup_confirmed'])
        for mutate in (
            lambda v: v['reconciliation'].update(raw='PRIVATE_PROMPT'),
            lambda v: v['reconciliation'].update(terminal_persisted=2),
            lambda v: v['reconciliation']['rpc'].update(path='/private/secret'),
            lambda v: v.update(answer_complete=True),
        ):
            bad = copy.deepcopy(recovered)
            mutate(bad)
            with self.assertRaises(ValueError):
                CHECK['check_execution_diagnostic'](bad)

    def test_answer_counts_distinguish_execution_from_generation_without_exporting_content(self):
        row = dict(text="PRIVATE_ANSWER", generated_tokens=64, text_truncated=False,
                   generation=dict(version=1, stop_reason="eos", max_new_tokens=64))
        rows = [row, dict(row, generation=dict(row["generation"], stop_reason="token_limit")),
                dict(row, text_truncated=True), dict(row, text=" "), dict(text="PRIVATE_LEGACY"),
                dict(row, generation=dict(row["generation"], stop_reason="json_boundary"))]
        result = CHECK["answer_status_counts"](rows)
        self.assertEqual(result["state"], "valid")
        self.assertEqual(result["observed"], 6)
        self.assertEqual(result["counts"], dict(eos=1, token_limit=1, wire_truncated=1, empty=1,
                                               legacy_unknown=1, json_boundary=1, invalid_or_unknown=0))
        rows += [dict(row, answer_status="token_limit"), dict(row, generation={"stop_reason": "PRIVATE_REASON"})]
        result = CHECK["answer_status_counts"](rows)
        self.assertEqual(result["state"], "incomplete")
        self.assertEqual(result["counts"]["invalid_or_unknown"], 2)
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(CHECK["answer_status_counts"](None), dict(state="absent"))
        self.assertEqual(CHECK["answer_status_counts"]({}), dict(state="invalid"))
        self.assertEqual(CHECK["answer_status_counts"]([row] * 16385), dict(state="invalid"))

    def test_retained_answer_diagnostic_is_additive_closed_and_explicit_about_missing_data(self):
        row = dict(text="PRIVATE_ANSWER", generated_tokens=64, text_truncated=False,
                   generation=dict(version=1, stop_reason="token_limit", max_new_tokens=64))
        value = dict(version=2, operation="compute_public_document", complete=False,
            execution_complete=True, answer_complete=False, interrupted=False,
            joining="hierarchical_peer_synthesis_incomplete", answers=[row],
            public_question="PRIVATE_QUESTION", provider_key="PRIVATE_ID", private_path="/PRIVATE_PATH",
            synthesis=dict(reason="worker_output_hit_token_limit", levels=[dict(level=1, answers=[row])]))
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary)
            project = lambda: CHECK["closed_answer_diagnostic"](task)
            self.assertEqual(project(), dict(state="absent"))
            document = task / "document"
            document.mkdir(mode=0o700)
            self.assertEqual(project(), dict(state="absent"))
            path = document / "result.json"
            def save(report):
                path.write_text(json.dumps(report))
                path.chmod(0o600)
            save(value)
            projected = project()
            self.assertEqual(projected["state"], "valid")
            status = projected["status"]
            self.assertTrue(status["execution_complete"])
            self.assertFalse(status["answer_complete"])
            self.assertEqual(status["synthesis"]["reason"], "worker_output_hit_token_limit")
            self.assertEqual(status["leaf_answers"]["counts"]["token_limit"], 1)
            self.assertEqual(status["synthesis"]["levels"][0]["answers"]["counts"]["token_limit"], 1)
            self.assertNotIn("PRIVATE", json.dumps(projected))
            # Existing consumers keep their exact execution status schema and meaning.
            original = dict(state="valid", status={"existing": "unchanged"})
            with mock.patch.dict(CHECK["coordinator_diagnostic"].__globals__, {
                    "task_roots": lambda _state: [task], "closed_execution": lambda _path: original}):
                entry = CHECK["coordinator_diagnostic"](task)["tasks"][0]
            self.assertEqual({key: entry[key] for key in original}, original)
            self.assertEqual(entry["answer_diagnostic"], projected)
            partial = copy.deepcopy(value)
            partial.pop("interrupted")
            partial["joining"] = "PRIVATE_JOINING"
            partial["synthesis"]["reason"] = "PRIVATE_REASON"
            partial["synthesis"]["levels"][0].pop("answers")
            save(partial)
            projected = project()
            self.assertEqual(projected["state"], "incomplete")
            self.assertIsNone(projected["status"]["interrupted"])
            self.assertIsNone(projected["status"]["joining"])
            self.assertIsNone(projected["status"]["synthesis"]["reason"])
            self.assertEqual(projected["status"]["synthesis"]["levels"][0]["answers"], dict(state="absent"))
            self.assertNotIn("PRIVATE", json.dumps(projected))
            for mutation in (lambda bad: bad.update(operation="PRIVATE_OPERATION"),
                             lambda bad: bad["synthesis"].update(levels=[dict(level=17)]),
                             lambda bad: bad["synthesis"].update(levels=[dict(level=1)] * 17)):
                bad = copy.deepcopy(value)
                mutation(bad)
                save(bad)
                self.assertEqual(project(), dict(state="invalid"))
            save(value)
            path.chmod(0o644)
            self.assertEqual(project(), dict(state="invalid"))
            path.unlink()
            outside = task / "outside.json"
            outside.write_text(json.dumps(value))
            outside.chmod(0o600)
            path.symlink_to(outside)
            self.assertEqual(project(), dict(state="invalid"))

    def test_guest_account_home_is_created_only_when_absent_and_removed_only_when_owned_and_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "account-home"
            marker = CHECK["prepare_account_home"](home, os.geteuid(), os.getegid())
            self.assertTrue(marker["created"])
            self.assertEqual(home.stat().st_mode & 0o777, 0o700)
            existing = CHECK["prepare_account_home"](home, os.geteuid(), os.getegid())
            self.assertFalse(existing["created"])
            CHECK["cleanup_account_home"](home, existing)
            self.assertTrue(home.is_dir())
            keep = home / "do-not-remove"
            keep.write_text("unrelated data")
            with self.assertRaises(OSError):
                CHECK["cleanup_account_home"](home, marker)
            self.assertEqual(keep.read_text(), "unrelated data")
            keep.unlink()
            CHECK["cleanup_account_home"](home, marker)
            CHECK["cleanup_account_home"](home, marker)
            self.assertFalse(home.exists())
            home.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                CHECK["prepare_account_home"](home, os.geteuid(), os.getegid())
            with self.assertRaises(ValueError):
                CHECK["cleanup_account_home"](home, marker)
            self.assertTrue(home.is_symlink())
        shell = (HERE / "agent-cooperative-browser.sh").read_text()
        self.assertLess(shell.index('account-home-prepare "$WORK"'), shell.index("--property=SetLoginEnvironment=yes"))
        cleanup = (HERE / "agent-jobs-smoke.sh").read_text().split("agent_jobs_cleanup() {", 1)[1]
        self.assertLess(cleanup.index("agent_jobs_stop"), cleanup.index("account-home-cleanup"))

    def test_failure_metadata_is_closed_and_account_transition_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "browser-status.json"
            self.assertEqual(CHECK["closed_status"](path), dict(state="absent"))
            value = dict(version=1, phase="wrapper-launch", failure="OS_ERROR")
            path.write_text(json.dumps(value))
            self.assertEqual(CHECK["closed_status"](path), dict(state="valid", status=value))
            for bad in (dict(value, context="PRIVATE"), dict(value, failure="PRIVATE"),
                        dict(value, phase="PRIVATE")):
                path.write_text(json.dumps(bad))
                self.assertEqual(CHECK["closed_status"](path), dict(state="invalid"))
        shell = (HERE / "agent-cooperative-browser.sh").read_text()
        self.assertIn("--property=SetLoginEnvironment=yes", shell)
        self.assertIn("--property=User=volparossa --property=Group=volparossa", shell)
        self.assertIn("--property=CapabilityBoundingSet= --property=AmbientCapabilities=", shell)
        self.assertIn('diagnostic "$WORK" "$cooperative_browser_status"', shell)
        jobs = (HERE / "agent-jobs-smoke.sh").read_text()
        stop = "agent_jobs_stop_unit() {" + jobs.split("agent_jobs_stop_unit() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        # Exercise the real allowlist without invoking host systemd or touching cgroups.
        doubles = '''
systemctl() {
    case "$*" in
        "show --property=LoadState --value "*) printf 'not-found\\n' ;;
        "show --property=ActiveState --value "*) printf 'inactive\\n' ;;
        "show --property=MainPID --value "*) printf '0\\n' ;;
        "reset-failed "*) return 0 ;;
        *) return 99 ;;
    esac
}
agent_jobs_cgroup_empty() { return 0; }
'''
        for unit, expected in (("volparossa-alpha-public-browser.service", 0),
                               ("volparossa-alpha-cooperative-browser.service", 0),
                               ("volparossa-agent.service", 1),
                               ("volparossa-alpha-public-browser-other.service", 1)):
            result = subprocess.run(["sh", "-c", doubles + stop + 'agent_jobs_stop_unit "$1"', "test", unit],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, expected)

    def test_receipts_consent_and_two_real_peer_levels_cannot_be_substituted(self):
        value = fixture()
        CHECK["check_evidence"](value, REVISION, value["provision"])
        for mutation in (
            lambda e: e["panel"]["observed"].update(explicit_consent=False),
            lambda e: e["panel"]["observed"].update(scoped_cancel_confirmed=False),
            lambda e: e["panel"]["observed"].update(cancel_task_id=1),
            lambda e: e["panel"]["observed"]["first_result"].update(output_sha256="0" * 64),
            lambda e: e["observation"].update(no_dispatch_before_consent=False),
            lambda e: e["observation"].update(cancelled_workers=[]),
            lambda e: e["observation"].update(observed_synthesis_levels=[0]),
            lambda e: e["observation"]["completed_workers"][0].update(base_model_sha256="0" * 64),
            lambda e: e["result"].update(exact_native_receipts_verified=False),
            lambda e: e["panel"].update(browser_source_sha256={}),
            lambda e: e["panel"].update(interfaces=["lo", "eth0"]),
            lambda e: e["path"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda e: e["path"]["gates"].update(exit_mptcp_tls_completed=0),
            lambda e: e["cleanup"].update(public_service_stopped=False),
            lambda e: e["private_cleanup"].update(publisher_key_removed=False),
            lambda e: e.update(answer_correctness_proven=True),
        ):
            bad = copy.deepcopy(value); mutation(bad)
            with self.assertRaises(ValueError):
                CHECK["check_evidence"](bad, REVISION, value["provision"])

    def test_exact_export_set_matches_closed_timeout_collector(self):
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        collector = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        module = {"__name__": "cooperative_collect_test"}
        exec(compile(collector, "guest_diagnostics", "exec"), module)
        names = set(CHECK["EXPORT_NAMES"])
        extras = {"host-state-before.json", "host-state-after.json", "guest-exit-status", "current-phase"}
        self.assertEqual(names | extras, module["COOPERATIVE_BROWSER_NAMES"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); home = root / "home"; out = home / "alpha-output"
            out.mkdir(parents=True)
            (home / "guest-phase.txt").write_text("topology\n")
            for name in names | extras:
                (out / name).write_text("{}\n")
            for name in ("runner.stdout", "agent-jobs-private.log", "agent-cooperative-browser-driver.log",
                         "agent-cooperative-browser-rpc-events.private",
                         "input.json", "identity.key", "passphrase"):
                (out / name).write_text("PRIVATE_DO_NOT_EXPORT\n")
            for scenario in ("agent-cooperative-browser", "agent-cooperative-browser-discovered"):
                archive = module["collect"](home, root / "absent", REVISION, scenario, 1,
                                            root / "cgroups", root / "proc")
                with tarfile.open(archive) as bundle:
                    self.assertEqual(set(bundle.getnames()), {f"published/{name}" for name in names | extras}
                                     | {"driver/guest-phase.txt", "vm-incomplete.json"})
                    for member in bundle.getmembers():
                        self.assertNotIn(b"PRIVATE_DO_NOT_EXPORT", bundle.extractfile(member).read())

    def test_preview_and_inner_driver_are_nonmutating_and_syntactically_valid(self):
        for name in ("run-alpha-topology-vm.sh", "kvm-alpha-topology.sh"):
            for scenario in ("agent-cooperative-browser", "agent-cooperative-browser-discovered"):
                result = subprocess.run(["sh", str(HERE / name), "--preview", "--scenario", scenario],
                                        capture_output=True, text=True, timeout=5, check=True)
                self.assertIn("PREVIEW ONLY", result.stdout)
                self.assertIn("cooperative", result.stdout.lower())
        source = (HERE / "run-alpha-topology-vm.sh").read_text()
        driver = source.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
        subprocess.run(["sh", "-n"], input=driver, text=True, check=True)
        gate = ('if [ "$scenario" = agent-cooperative-browser ] || [ "$scenario" = agent-cooperative-browser-discovered ]'
                ' || [ "$scenario" = agent-cooperative-code ]; then')
        self.assertIn(gate, driver)
        selected_export = driver.split(gate, 1)[1].split("\nelif ", 1)[0]
        self.assertIn('"tests/integration/$scenario.py" export-names', selected_export)
        self.assertIn('agent-cooperative-browser.py --trial discovered-360m', selected_export)
        self.assertIn("libgtk-3-0t64", driver)
        selector = runpy.run_path(str(HERE / "test-cooperative-code-vm-contract.py"))["selected_topology_argv"]
        for scenario in ("agent-cooperative-browser", "agent-cooperative-browser-discovered"):
            argv = selector(scenario)
            self.assertEqual(argv[argv.index("--scenario") + 1], scenario)
            self.assertNotIn("--code-bundle", argv)
        workflow = (HERE.parents[1] / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn('agent-cooperative-browser.py --trial discovered-360m report "$report" "$GITHUB_SHA"', workflow)


if __name__ == "__main__":
    unittest.main()
