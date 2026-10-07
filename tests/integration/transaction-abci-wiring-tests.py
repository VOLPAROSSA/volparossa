#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert scenario/receipt wiring regressions; no VM, build or network execution."""

import copy
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VM = HERE / "run-alpha-topology-vm.sh"
WORKFLOW = ROOT / ".github/workflows/alpha-topology.yml"
SPEC = importlib.util.spec_from_file_location("transaction_abci_evidence", HERE / "transaction-abci-evidence.py")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
FIXTURE = EVIDENCE.FIXTURE


def inert_receipts(*, countdown=False):
    """Artificial parser inputs only; never exported as runtime evidence."""
    def convergence(height):
        return {"height": height, "block_hash": "a" * 64, "header_app_hash": "b" * 64}
    build = {"schema": 1, "source_commit": "c" * 40, "comet_source": FIXTURE.COMET_COMMIT,
             "compiler": FIXTURE.GO_VERSION, "compiler_archive_sha256": FIXTURE.GO_SHA256,
             "compiler_license_sha256": FIXTURE.GO_LICENSE_SHA256,
             "source_built_engine": True, "compiler_auto_upgrade": False,
             "comet_sha256": "d" * 64, "adapter_sha256": "e" * 64,
             "go_mod_sha256": "f" * 64, "go_sum_sha256": "1" * 64}
    scope = FIXTURE.plan()["does_not_prove"]
    checks = {
        "setup": {"validators": 4, "independent_stores": 4, "private_sockets": 4, "genesis_sha256": "2" * 64},
        "startup": convergence(2),
        "signed_conflict": {**convergence(4), "result_codes": [7, 0], "conserved_units": 100},
        "commit": {**convergence(6), "debited_units": 70, "credited_units": 70, "conserved_units": 100},
        "partition_3_1": {"heights": [7], "majority_heights_before": [7, 7, 7],
                          "majority_heights_after": [10, 10, 10], "majority_progress_blocks_at_least": 3,
                          "samples": 30, "observation_seconds": 8.1, "drop_packets": [10, 20], "all_processes_alive": True},
        "rejoin_3_1": convergence(11),
        "partition_2_2": {"heights": [12, 12, 12, 12], "samples": 30, "observation_seconds": 8.1,
                          "drop_packets": [10, 20], "all_processes_alive": True},
        "rejoin_2_2": convergence(14),
        "crash_replay": {**convergence(21), "crashed_node": 3, "post_commit_restart": True,
                         "height_before_restart": 15, "retry_start_height": 18,
                         "retry_committed_heights": [19, 20], "retry_result_codes": [0, 0],
                         "original_receipt_sequences": [1, 2], "unchanged_balances": True,
                         "unchanged_receipts": True, "second_abci_execution_proven": True},
    }
    inner = {"schema": 1, "unit": "TEST", "comet_source": FIXTURE.COMET_COMMIT, "compiler": FIXTURE.GO_VERSION,
             "scope": scope, "phase": "crash_replay", "acceptance": True, "processes_reaped": True,
             "checkpoints": checks,
             "children_before_cleanup": [{"node": node, "kind": kind, "exit_status": None}
                                         for node in range(4) for kind in ("app", "comet")]}
    before = {key: "3" * 64 for key in EVIDENCE.PARENT_FIELDS}
    after, fields = before.copy(), {}
    for label in ("addresses", "routes6"):
        raw = b'[{"expires":900}]' if label == "routes6" else b'[{"addr_info":[{"valid_life_time":900}]}]'
        later = raw.replace(b"900", b"890") if countdown else raw
        left = FIXTURE.timed_parent_read(label, raw, 100_000_000_000, 100_010_000_000)
        right = FIXTURE.timed_parent_read(label, later, 110_000_000_000, 110_010_000_000)
        fields[label] = FIXTURE.parent_countdown_evidence(left, right)
        before[label], after[label] = left["raw_sha256"], right["raw_sha256"]
    outer = {"schema": 1, "source_commit": "c" * 40, "comet_source": FIXTURE.COMET_COMMIT,
             "acceptance": True, "parent_unchanged": not countdown, "owned_namespaces_removed": True,
             "private_keys_removed": True, "failure": None, "scope": scope,
             "parent_before": before, "parent_after": after, "parent_semantically_unchanged": True,
             "parent_observation": {"schema": 1, "policy": FIXTURE.COUNTDOWN_POLICY, "fields": fields}}
    return build, inner, outer


def workflow_step(name):
    text = WORKFLOW.read_text()
    marker = "      - name: " + name + "\n"
    body = text.split(marker, 1)[1]
    return body.split("\n      - name: ", 1)[0]


class TransactionWiring(unittest.TestCase):
    def validate(self, values, **overrides):
        options = {"revision": "c" * 40, "driver_exit": "0", "guest_exit": "0", "phase": "complete"}
        options.update(overrides)
        EVIDENCE.validate(*values, **options)

    def test_new_preview_is_inert_and_uses_unchanged_envelope(self):
        result = subprocess.run(["sh", str(VM), "--preview", "--scenario", "transaction-abci"],
                                capture_output=True, text=True, check=True)
        self.assertIn("PREVIEW ONLY", result.stdout)
        self.assertIn("4 vCPUs, 4096 MiB RAM", result.stdout)
        self.assertIn("16 GiB guest and 2400s driver budget", result.stdout)
        self.assertIn("not Byzantine equivocation, overlay transport, independent clients", result.stdout)
        rejected = subprocess.run(["sh", str(VM), "--execute", "--scenario", "transaction-abci"], capture_output=True)
        self.assertEqual(rejected.returncode, 64)

    def test_old_previews_keep_their_resource_and_scope_choices(self):
        for scenario, memory, expected in (("wifi-mesh", "4096", "not physical Wi-Fi"),
                                          ("agent-reasoning", "8192", "1.7B BF16"),
                                          ("alpha", "4096", "install, doctor, start, upgrade")):
            with self.subTest(scenario=scenario):
                result = subprocess.run(["sh", str(VM), "--preview", "--scenario", scenario],
                                        capture_output=True, text=True, check=True)
                self.assertIn(memory + " MiB RAM", result.stdout)
                self.assertIn(expected, result.stdout)

    def test_early_guest_entry_never_needs_native_overlay_or_kernel_reboot(self):
        text = VM.read_text()
        entry = text.index('if [ "$scenario" = transaction-abci ]; then\n    guest_phase')
        self.assertLess(entry, text.index('if [ "$scenario" = wifi-mesh ]; then\n    guest_phase'))
        self.assertIn('exec sh tests/integration/transaction-abci-vm-guest.sh "$expected_commit"', text[entry:entry + 400])
        self.assertIn('[ "$scenario" != transaction-abci ] &&', text)
        self.assertIn('case $scenario in wifi-mesh|wifi-link) set -- ;; esac', text)
        self.assertIn('driver_time_bound=2400s', text)
        self.assertNotRegex(text, r'\[ "\$scenario" != transaction-abci \] \|\| driver_time_bound=')
        self.assertIn('-machine q35,accel=kvm -cpu host -smp 4 -m "$guest_memory_mib"', text)

    def test_only_transaction_is_exempted_from_irrelevant_workflow_gates(self):
        text = WORKFLOW.read_text()
        self.assertIn("          - transaction-abci\n", text)
        self.assertIn("python3 -B tests/integration/transaction-abci-wiring-tests.py", text)
        for name in ("Build exact pinned mqvpn/xquic runtime", "Require successful A01-A15 evidence"):
            self.assertIn("env.VOLPAROSSA_ALPHA_SCENARIO != 'transaction-abci'", workflow_step(name))
        run = workflow_step("Run disposable production-helper topology")
        self.assertIn('test "$VOLPAROSSA_ALPHA_SCENARIO" != transaction-abci', run)
        self.assertIn('"${native_args[@]}"', run)
        gate = workflow_step("Require real isolated four-validator TEST evidence")
        self.assertIn("if: always() && env.VOLPAROSSA_ALPHA_SCENARIO == 'transaction-abci'", gate)
        self.assertIn('--driver-exit-code "$TOPOLOGY_EXIT_CODE"', gate)
        self.assertIn('--expected-commit "$GITHUB_SHA"', gate)
        self.assertNotIn("continue-on-error", gate)
        summary = workflow_step("Summarise exact reached point")
        self.assertIn("parent raw snapshots equal: \\(.parent_unchanged)", summary)
        self.assertIn("parent bounded observer accepted: \\(.parent_semantically_unchanged // false)", summary)

    def test_export_is_an_explicit_receipt_allowlist(self):
        step = workflow_step("Upload closed transaction TEST evidence")
        self.assertIn("env.VOLPAROSSA_ALPHA_OUTPUT != ''", step)
        self.assertNotIn("*", step)
        self.assertNotIn(".seed", step)
        self.assertNotIn("node0", step)
        self.assertNotIn("runner.stdout", step)
        for name in ("transaction-abci-build.json", "transaction-abci-inner.json", "transaction-abci-acceptance.json"):
            self.assertIn("}}/" + name, step)
            self.assertIn("}}/published/" + name, step)
        self.assertIn("!= 'transaction-abci'", workflow_step("Upload bounded topology diagnostics"))
        collector = VM.read_text().split('if scenario == "transaction-abci":', 1)[1].split('if scenario in ("agent-private-conversation"', 1)[0]
        self.assertIn('if label == "published":', collector)
        self.assertNotIn("glob", collector)
        self.assertIn("continue", collector)

    def test_early_failure_reporting_preserves_missing_runtime_evidence(self):
        summary = textwrap.dedent(workflow_step("Summarise exact reached point").split("run: |\n", 1)[1])
        gate = textwrap.dedent(workflow_step("Require real isolated four-validator TEST evidence").split("run: |\n", 1)[1])
        # Execute only reporting prefixes, never the runtime evidence commands.
        summary_stop = 'if test "$VOLPAROSSA_ALPHA_SCENARIO" = transaction-abci; then'
        gate_stop = 'python3 -B tests/integration/transaction-abci-evidence.py'
        self.assertEqual(summary.count(summary_stop), 1)
        self.assertEqual(gate.count(gate_stop), 1)
        summary = summary.split(summary_stop, 1)[0]
        gate = gate.split(gate_stop, 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "summary"
            env = {"PATH": os.defpath, "VOLPAROSSA_ALPHA_SCENARIO": "transaction-abci",
                   "GITHUB_STEP_SUMMARY": str(destination), "GITHUB_SHA": "a" * 40}
            result = subprocess.run(["bash", "-c", summary], env=env, capture_output=True,
                                    text=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Stopped before VM output initialization; no runtime evidence", destination.read_text())
            self.assertNotIn("unbound variable", result.stderr)
            for extra in ({}, {"VOLPAROSSA_ALPHA_OUTPUT": ""},
                          {"VOLPAROSSA_ALPHA_OUTPUT": str(Path(temporary) / "absent")},
                          {"TOPOLOGY_EXIT_CODE": "0"}):
                with self.subTest(extra=extra):
                    result = subprocess.run(["bash", "-c", gate], env={**env, **extra},
                                            capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("runtime evidence is absent", result.stderr)
                    self.assertNotIn("unbound variable", result.stderr)
            self.assertEqual(sorted(path.name for path in Path(temporary).iterdir()), ["summary"])

    def test_complete_parser_fixture_passes_but_every_exit_failure_is_preserved(self):
        self.validate(inert_receipts())
        for options in ({"driver_exit": "1"}, {"driver_exit": ""}, {"guest_exit": "143"},
                        {"phase": "source-build"}, {"revision": "e" * 40}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.validate(inert_receipts(), **options)

    def test_missing_phase_bad_source_and_unreaped_process_fail(self):
        for section, key, bad in ((0, "source_built_engine", False), (0, "compiler_auto_upgrade", True),
                                  (0, "compiler_archive_sha256", "f" * 64), (1, "acceptance", False),
                                  (1, "processes_reaped", False), (2, "parent_unchanged", False),
                                  (2, "parent_semantically_unchanged", False),
                                  (2, "owned_namespaces_removed", False), (2, "private_keys_removed", False),
                                  (2, "failure", "interrupted")):
            values = inert_receipts()
            values[section][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(values)
        for phase in FIXTURE.PHASES[:-1]:
            values = inert_receipts()
            del values[1]["checkpoints"][phase]
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                self.validate(values)

    def test_lifetime_diagnostics_cannot_override_raw_parent_mismatch(self):
        values = inert_receipts()
        values[2]["parent_lifetime_diagnostics"] = {
            label: {"parsed": True, "structure_equal": True, "lifetime_values_equal": False,
                    "lifetime_fields_only_changed": True, "lifetime_fields_before": 2, "lifetime_fields_after": 2}
            for label in ("addresses", "routes6")
        }
        self.validate(values)
        for label in ("addresses", "routes6"):
            changed = copy.deepcopy(values)
            changed[2]["parent_after"][label] = "f" * 64
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.validate(changed)
            changed[2]["parent_unchanged"] = False
            changed[2]["acceptance"] = False
            with self.assertRaises(ValueError):
                self.validate(changed)

    def test_countdown_acceptance_retains_raw_difference_and_all_cleanup_gates(self):
        values = inert_receipts(countdown=True)
        self.assertFalse(values[2]["parent_unchanged"])
        self.assertNotEqual(values[2]["parent_before"], values[2]["parent_after"])
        self.validate(values)
        for key in ("parent_semantically_unchanged", "owned_namespaces_removed", "private_keys_removed"):
            changed = copy.deepcopy(values)
            changed[2][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(changed)
        for options in ({"driver_exit": "1"}, {"guest_exit": "1"}, {"phase": "real-consensus-trial"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.validate(values, **options)
        for key, bad in (("parent_unchanged", True), ("parent_unchanged", 0), ("acceptance", False)):
            changed = copy.deepcopy(values)
            changed[2][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(changed)

    def test_countdown_receipt_is_closed_bound_and_not_a_diagnostics_override(self):
        for countdown in (False, True):
            original = inert_receipts(countdown=countdown)
            for bad in (None, {}, {"parsed": True, "structure_equal": True}):
                values = copy.deepcopy(original)
                values[2]["parent_observation"] = bad
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    self.validate(values)
            for key, bad in (("schema", True), ("policy", "mask-only"), ("unexpected", True)):
                values = copy.deepcopy(original)
                values[2]["parent_observation"][key] = bad
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.validate(values)
            for key, bad in (("status", "structure_equal"), ("status", "future_policy"),
                             ("before_sha256", "f" * 64), ("after_sha256", "f" * 64),
                             ("structure_after_sha256", "f" * 64), ("fields_before", True),
                             ("fields_after", 1025), ("checked_finite", 0), ("checked_forever", 1),
                             ("elapsed_min_ns", -1), ("elapsed_max_ns", 0),
                             ("before_read_ns", FIXTURE.PARENT_READ_NS + 1), ("unexpected", True),
                             ("changed_finite", 0 if countdown else 1)):
                values = copy.deepcopy(original)
                values[2]["parent_observation"]["fields"]["routes6"][key] = bad
                with self.subTest(countdown=countdown, key=key), self.assertRaises(ValueError):
                    self.validate(values)
            for key in EVIDENCE.PARENT_FIELDS - {"addresses", "routes6"}:
                values = copy.deepcopy(original)
                values[2]["parent_after"][key] = "f" * 64
                values[2]["parent_unchanged"] = False
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.validate(values)

    def test_no_consensus_claim_from_absent_counters_progress_or_coverage(self):
        for phase, field, bad in (("partition_3_1", "drop_packets", [0, 1]),
                                  ("partition_3_1", "majority_heights_after", [7, 7, 7]),
                                  ("partition_3_1", "all_processes_alive", False),
                                  ("partition_2_2", "observation_seconds", 7.9),
                                  ("partition_2_2", "samples", 0),
                                  ("signed_conflict", "result_codes", [0, 0]),
                                  ("signed_conflict", "result_codes", [0, 4]),
                                  ("commit", "conserved_units", 170)):
            values = inert_receipts()
            values[1]["checkpoints"][phase][field] = bad
            with self.subTest(phase=phase, field=field), self.assertRaises(ValueError):
                self.validate(values)

    def test_replay_requires_actual_new_block_execution_and_unchanged_receipts(self):
        for field, bad in (("retry_committed_heights", [18, 18]), ("retry_result_codes", [0, 7]),
                           ("unchanged_receipts", False), ("unchanged_balances", False),
                           ("second_abci_execution_proven", False), ("original_receipt_sequences", [2, 1])):
            values = inert_receipts()
            values[1]["checkpoints"]["crash_replay"][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(values)

    def test_changed_parent_state_dead_child_and_scope_expansion_fail(self):
        values = inert_receipts()
        values[2]["parent_after"]["firewall"] = "9" * 64
        with self.assertRaises(ValueError):
            self.validate(values)
        values = inert_receipts()
        values[1]["children_before_cleanup"][0]["exit_status"] = 1
        with self.assertRaises(ValueError):
            self.validate(values)
        values = inert_receipts()
        values[1]["scope"] = []
        with self.assertRaises(ValueError):
            self.validate(values)


if __name__ == "__main__":
    unittest.main()
