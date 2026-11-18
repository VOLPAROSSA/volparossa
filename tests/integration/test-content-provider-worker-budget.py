#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic closed-log and failure-retention checks; no daemon or VM starts."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HELPER = HERE / "content-provider-worker-budget.py"
CHECK = runpy.run_path(str(HELPER))


def budget(**changes):
    value = dict(schema_version=1, outcome="returned", initial_allowance=3,
                 min_allowance=1, max_allowance=3, min_memory_workers=3,
                 min_fd_workers=100, peak_shared_held=3, admitted_leases=3,
                 denied_leases=0, peak_leases=3, active_leases=0,
                 causes={key: False for key in CHECK["CAUSES"]})
    value.update(changes)
    return value


def event(value=None, **changes):
    envelope = dict(timestamp="not-for-export", level="DEBUG", target=CHECK["TARGET"],
                    fields=dict(code=CHECK["CODE"], budget=json.dumps(value or budget())))
    envelope.update(changes)
    return json.dumps(envelope).encode() + b"\n"


def continuation(**changes):
    value = dict(schema_version=1, outcome="returned", retired_candidates=2,
                 prepared_continuations=2, admitted_continuations=2, returned_useful_continuations=2,
                 returned_verified_chunks=6, returned_verified_bytes=1572864,
                 initial_active_workers=0, peak_active_workers=1, final_active_workers=0)
    value.update(changes)
    return value


def continuation_event(value=None):
    return event(target=CHECK["CONTINUATION_TARGET"], fields=dict(code=CHECK["CONTINUATION_CODE"],
                 continuation=json.dumps(value or continuation())))


class WorkerBudgetDiagnostics(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="provider-budget-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.log = self.work / "agent-client.log"
        self.log.touch(mode=0o600)

    def append(self, raw):
        with self.log.open("ab") as output:
            output.write(raw)

    def marker(self, phase):
        CHECK["mark"](self.work, phase)

    def finish(self, phase, pending=False):
        return CHECK["finish"](self.work, phase, pending=pending)

    def report(self, phase):
        return CHECK["paths"](self.work, phase)[1]

    def test_phase_boundaries_prevent_native_https_and_later_event_bleed(self):
        self.append(event(budget(initial_allowance=99)))
        self.marker("native")
        self.append(event())
        native = self.finish("native")
        self.assertEqual(native["status"], "observed")
        self.assertTrue(native["complete"])
        self.marker("https")
        self.append(event(budget(outcome="failed")))
        https = self.finish("https")
        self.append(event(budget(outcome="interrupted")))
        CHECK["finalize"](self.work)
        self.assertEqual(json.loads(self.report("native").read_bytes()), native)
        self.assertEqual(json.loads(self.report("https").read_bytes()), https)
        self.assertEqual([item["outcome"] for item in https["records"]], ["failed"])
        self.assertNotIn("success", native)

    def test_pressure_has_separate_paths_and_preserves_historical_names(self):
        expected = {"native": "content-provider-adaptive", "https": "content-provider-adaptive-https",
                    "pressure": "content-provider-pressure"}
        self.assertEqual(set(CHECK["PHASES"]), set(expected))
        for phase, prefix in expected.items():
            marker, output = CHECK["paths"](self.work, phase)
            self.assertEqual(marker.name, f".content-worker-budget-{phase}.part")
            self.assertEqual(output.name, f"{prefix}-worker-budget.json")
            self.assertEqual(CHECK["continuation_path"](self.work, phase).name, f"{prefix}-continuation.json")
        for phase in ("", "PRESSURE", "../pressure", "native-pressure"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                CHECK["paths"](self.work, phase)
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                CHECK["continuation_path"](self.work, phase)

    def test_three_phase_ranges_remain_independent_when_finalized_later(self):
        retained = {}
        for phase, allowance in (("native", 12), ("https", 8), ("pressure", 3)):
            self.marker(phase)
            sample = budget(initial_allowance=allowance, max_allowance=allowance)
            sample["causes"]["cpu_pressure"] = phase == "pressure"
            progress = continuation(returned_verified_chunks=allowance)
            self.append(event(sample) + continuation_event(progress))
            report = self.finish(phase)
            self.assertEqual(report["phase"], phase)
            self.assertEqual(report["records"], [sample])
            for path in (self.report(phase), CHECK["continuation_path"](self.work, phase)):
                retained[path] = path.read_bytes()
            parsed = json.loads(CHECK["continuation_path"](self.work, phase).read_bytes())
            self.assertEqual(parsed["records"], [progress])
            self.assertEqual(parsed["phase"], phase)
        self.append(event(budget(outcome="failed")) + continuation_event(continuation(outcome="failed")))
        CHECK["finalize"](self.work)
        for path, raw in retained.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_pressure_pending_then_cancelled_records_finalize_without_other_phases(self):
        self.marker("pressure")
        pending = self.finish("pressure", pending=True)
        target = CHECK["continuation_path"](self.work, "pressure")
        self.assertEqual((pending["phase_closed"], pending["complete"], pending["status"]),
                         (False, False, "incomplete"))
        self.assertFalse(json.loads(target.read_bytes())["complete"])
        interrupted = continuation(outcome="interrupted", returned_useful_continuations=0,
                                   returned_verified_chunks=0, returned_verified_bytes=0)
        self.append(event(budget(outcome="interrupted")) + continuation_event(interrupted))
        CHECK["finalize"](self.work)
        final = json.loads(self.report("pressure").read_bytes())
        self.assertEqual((final["phase_closed"], final["complete"], final["status"]),
                         (True, True, "observed"))
        self.assertEqual(final["records"][0]["outcome"], "interrupted")
        self.assertEqual(json.loads(target.read_bytes())["records"], [interrupted])
        for phase in ("native", "https"):
            self.assertFalse(self.report(phase).exists())
            self.assertFalse(CHECK["continuation_path"](self.work, phase).exists())

    def test_pressure_rejects_cross_phase_marker_and_keeps_other_closed_evidence(self):
        self.marker("native")
        self.append(event() + continuation_event())
        self.finish("native")
        retained = self.report("native").read_bytes()
        marker, _ = CHECK["paths"](self.work, "pressure")
        original, _ = CHECK["paths"](self.work, "native")
        marker.write_bytes(original.read_bytes())
        marker.chmod(0o600)
        self.append(event(budget(outcome="failed")))
        CHECK["finalize"](self.work)
        self.assertEqual(self.report("native").read_bytes(), retained)
        for path in (self.report("pressure"), CHECK["continuation_path"](self.work, "pressure")):
            parsed = json.loads(path.read_bytes())
            self.assertEqual((parsed["phase"], parsed["status"], parsed["complete"], parsed["records"]),
                             ("pressure", "invalid", False, []))

    def test_pressure_cli_lifecycle_is_closed_and_preserves_invalid_payload_isolation(self):
        for action in ("mark", "pending"):
            result = subprocess.run([sys.executable, "-B", str(HELPER), action, str(self.work), "pressure"],
                                    capture_output=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
        self.append(event(budget(peer_id="not-exportable")) + continuation_event())
        result = subprocess.run([sys.executable, "-B", str(HELPER), "finalize", str(self.work)],
                                capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
        invalid = json.loads(self.report("pressure").read_bytes())
        self.assertEqual((invalid["status"], invalid["records"]), ("invalid", []))
        continued = json.loads(CHECK["continuation_path"](self.work, "pressure").read_bytes())
        self.assertEqual((continued["status"], continued["records"]), ("observed", [continuation()]))
        self.assertNotIn("not-exportable", self.report("pressure").read_text())

    def test_unfinished_failed_command_is_finalized_after_summary_arrives(self):
        self.marker("native")
        pending = self.finish("native", pending=True)
        self.assertFalse(pending["phase_closed"])
        self.assertFalse(pending["complete"])
        self.append(event(budget(outcome="interrupted")))
        CHECK["finalize"](self.work)
        final = json.loads(self.report("native").read_bytes())
        self.assertEqual(final["records"][0]["outcome"], "interrupted")
        self.assertTrue(final["phase_closed"])
        self.assertTrue(final["complete"])
        self.assertFalse(self.report("https").exists(), "unstarted phase must not acquire evidence")

    def test_missing_observation_is_not_fabricated_zero_or_success(self):
        self.marker("native")
        missing = self.finish("native")
        self.assertEqual(missing["status"], "missing")
        self.assertFalse(missing["complete"])
        nulls = budget(**{key: None for key in CHECK["OBSERVATIONS"]})
        nulls["causes"]["resource_unavailable"] = True
        parsed, _ = CHECK["extract"](event(nulls))
        self.assertIsNone(parsed[0]["initial_allowance"])
        self.assertEqual(parsed[0]["denied_leases"], 0)
        self.assertTrue(parsed[0]["causes"]["resource_unavailable"])

    def test_only_closed_budget_survives_unrelated_log_envelopes(self):
        self.marker("native")
        self.append(event(target="unrelated", fields={"private_url": "https://private.invalid/secret"}))
        self.append(event())
        report = self.finish("native")
        self.assertEqual(report["records"], [budget()])
        raw = self.report("native").read_text()
        for private in ("timestamp", "not-for-export", "private_url", "private.invalid", "target", "device", "inode"):
            self.assertNotIn(private, raw)
        self.assertEqual(self.report("native").stat().st_mode & 0o777, 0o600)

    def test_unknown_keys_free_form_values_bool_counters_and_invalid_ranges_rejected(self):
        changes = ({"outcome": "secret URL"}, {"initial_allowance": -1}, {"peak_shared_held": True},
                   {"min_fd_workers": 2**32}, {"active_leases": 4}, {"min_allowance": 4},
                   {"max_allowance": None}, {"peer_id": "not-allowed"}, {"schema_version": True})
        for mutation in changes:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                CHECK["extract"](event(budget(**mutation)))
        for mutate in (lambda v: v["causes"].update(extra=False),
                       lambda v: v["causes"].update(cpu_unavailable="false")):
            value = budget(); mutate(value)
            with self.assertRaises(ValueError):
                CHECK["extract"](event(value))

    def test_envelope_and_nested_json_duplicates_nonfinite_and_extra_fields_rejected(self):
        raw = event()
        with self.assertRaises(ValueError):
            CHECK["extract"](raw.replace(b'"level": "DEBUG"', b'"level":"DEBUG","level":"DEBUG"'))
        fields = {"code": CHECK["CODE"], "budget": json.dumps(budget()).replace('"schema_version": 1',
                    '"schema_version":1,"schema_version":1')}
        with self.assertRaises(ValueError):
            CHECK["extract"](event(fields=fields))
        for fields in ({"code": CHECK["CODE"], "budget": json.dumps(budget()), "secret": "no"},
                       {"code": CHECK["CODE"], "budget": {"not": "a string"}},
                       {"code": CHECK["CODE"], "budget": "NaN"}):
            with self.assertRaises(ValueError):
                CHECK["extract"](event(fields=fields))

    def test_resource_bounds_reject_excess_input_line_budget_or_summaries(self):
        samples = (b"x" * (CHECK["MAX_INPUT"] + 1),
                   b"x" * (CHECK["MAX_LINE"] + 1) + b"\n",
                   b"\n" * (CHECK["MAX_LINES"] + 1),
                   event(fields={"code": CHECK["CODE"], "budget": " " * (CHECK["MAX_BUDGET"] + 1)}),
                   event() * (CHECK["MAX_RECORDS"] + 1))
        for raw in samples:
            with self.assertRaises(ValueError):
                CHECK["extract"](raw)

    def test_partial_trailing_record_is_incomplete_not_success(self):
        self.marker("native")
        self.append(event() + b'{"target":')
        report = self.finish("native", pending=True)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["complete"])
        self.assertEqual(report["records"], [budget()])

    def test_rotation_truncation_symlink_and_hardlink_refused(self):
        for action in ("rotation", "truncate", "symlink", "hardlink"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); log = work / "agent-client.log"
                log.write_bytes(event()); log.chmod(0o600)
                CHECK["mark"](work, "native")
                if action == "truncate":
                    log.write_bytes(b"")
                else:
                    log.rename(work / "old")
                    if action == "symlink": log.symlink_to(work / "old")
                    elif action == "hardlink": os.link(work / "old", log)
                    else: log.write_bytes(event()); log.chmod(0o600)
                report = CHECK["finish"](work, "native")
                self.assertEqual(report["status"], "invalid")
                self.assertEqual(report["records"], [])

    def test_malformed_logs_and_markers_export_only_closed_invalid_status(self):
        self.marker("native")
        self.append(b"secret malformed diagnostic\n")
        self.assertEqual(self.finish("native")["status"], "invalid")
        marker, _ = CHECK["paths"](self.work, "native")
        marker.write_text('{"private":"do not export"}')
        report = self.finish("native")
        self.assertEqual(report["records"], [])
        self.assertNotIn("private", self.report("native").read_text())
        marker.write_text("[" * 1500 + "0" + "]" * 1500)
        self.assertEqual(self.finish("native")["status"], "invalid")

    def test_actual_cli_marker_finish_and_failed_acceptance_retains_reports(self):
        self.work.chmod(0o755)  # Actual fixture root is searchable by service UIDs, never writable by them.
        for args in (("mark", "native"), ("pending", "native")):
            result = subprocess.run([sys.executable, "-B", str(HELPER), args[0], str(self.work), args[1]],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"")
        self.append(event())
        result = subprocess.run([sys.executable, "-B", str(HELPER), "finalize", str(self.work)],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        # An unrelated acceptance failure neither changes nor deletes this diagnostic.
        report = self.report("native").read_bytes()
        (self.work / "content-provider-smoke.json").write_text('{"success":false}')
        self.assertEqual(self.report("native").read_bytes(), report)

    def test_continuations_use_same_phase_boundary_but_separate_closed_report(self):
        self.append(continuation_event(continuation(retired_candidates=99)))
        self.marker("native")
        self.append(event() + continuation_event())
        legacy = self.finish("native")
        target = CHECK["continuation_path"](self.work, "native")
        retained = target.read_bytes()
        parsed = json.loads(retained)
        self.assertEqual(legacy["records"], [budget()])
        self.assertEqual(parsed, dict(schema_version=1, kind="content-provider-continuation-diagnostic",
            phase="native", phase_closed=True, complete=True, status="observed", records=[continuation()]))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.marker("https")
        self.append(continuation_event(continuation(outcome="failed")))
        self.finish("https")
        self.append(continuation_event(continuation(outcome="interrupted")))
        CHECK["finalize"](self.work)
        self.assertEqual(target.read_bytes(), retained)
        https = json.loads(CHECK["continuation_path"](self.work, "https").read_bytes())
        self.assertEqual([row["outcome"] for row in https["records"]], ["failed"])
        for secret in ("timestamp", "not-for-export", "target", "device", "inode", "success"):
            self.assertNotIn(secret, retained.decode())

    def test_continuation_pending_and_missing_are_not_success_or_zero_traffic(self):
        self.marker("native")
        self.finish("native", pending=True)
        target = CHECK["continuation_path"](self.work, "native")
        self.assertFalse(json.loads(target.read_bytes())["complete"])
        interrupted = continuation(outcome="interrupted", returned_useful_continuations=0,
                                   returned_verified_chunks=0, returned_verified_bytes=0)
        self.append(continuation_event(interrupted))
        CHECK["finalize"](self.work)
        self.assertEqual(json.loads(target.read_bytes())["records"], [interrupted])
        self.assertFalse(CHECK["continuation_path"](self.work, "https").exists())
        self.marker("https"); self.finish("https")
        missing = json.loads(CHECK["continuation_path"](self.work, "https").read_bytes())
        self.assertEqual((missing["status"], missing["complete"], missing["records"]), ("missing", False, []))

    def test_continuation_rejects_unknown_fields_types_ranges_and_envelope(self):
        mutations = ({"schema_version": True}, {"outcome": "complete"}, {"peer_id": "SECRET"},
            {"retired_candidates": -1}, {"prepared_continuations": 3}, {"admitted_continuations": 3},
            {"returned_useful_continuations": 3}, {"returned_verified_chunks": 2**32},
            {"returned_verified_bytes": 2**64}, {"returned_verified_bytes": True},
            {"initial_active_workers": 2}, {"final_active_workers": 2}, {"peak_active_workers": None})
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                CHECK["extract"](continuation_event(continuation(**mutation)), continuation=True)
        for fields in ({"code": CHECK["CONTINUATION_CODE"], "continuation": "NaN"},
                {"code": CHECK["CONTINUATION_CODE"], "continuation": '{}', "secret": 'PRIVATE'},
                {"code": CHECK["CONTINUATION_CODE"], "continuation": json.dumps(continuation()).replace(
                    '"schema_version": 1', '"schema_version":1,"schema_version":1')},
                {"code": CHECK["CONTINUATION_CODE"], "continuation": "x" * (CHECK["MAX_BUDGET"]+1)}):
            with self.assertRaises(ValueError):
                CHECK["extract"](event(target=CHECK["CONTINUATION_TARGET"], fields=fields), continuation=True)
        with self.assertRaises(ValueError):
            CHECK["extract"](continuation_event() * (CHECK["MAX_RECORDS"]+1), continuation=True)
        maximal = continuation(retired_candidates=2**32-1, returned_verified_chunks=2**32-1,
                               returned_verified_bytes=2**64-1)
        self.assertEqual(CHECK["extract"](continuation_event(maximal), continuation=True)[0], [maximal])

    def test_invalid_payload_does_not_erase_other_report_or_reopen_closed_phase(self):
        self.marker("native")
        self.append(event() + continuation_event(continuation(peer_id="PRIVATE")))
        legacy = self.finish("native")
        target = CHECK["continuation_path"](self.work, "native")
        retained = target.read_bytes()
        self.assertEqual(legacy["records"], [budget()])
        self.assertEqual(json.loads(retained)["status"], "invalid")
        self.append(continuation_event())
        CHECK["finalize"](self.work)
        self.assertEqual(target.read_bytes(), retained)
        self.marker("https")
        self.append(event(budget(peer_id="PRIVATE")) + continuation_event())
        self.assertEqual(self.finish("https")["status"], "invalid")
        self.assertEqual(json.loads(CHECK["continuation_path"](self.work, "https").read_bytes())["records"],
                         [continuation()])

    def test_glue_opt_in_cleanup_order_and_closed_emergency_allowlist(self):
        topology = (HERE / "kvm-alpha-topology.sh").read_text()
        optin = ('if [ "$scenario" = content-provider ] && [ "$node" = client ]; then\n'
                 '        # Disposable fixture opt-in: closed per-batch resources only, no object/route/peer identities.\n'
                 '        agent_rust_log=$agent_rust_log,volparossa_agent::content::worker_budget=debug,'
                 'volparossa_agent::content::parallel::continuation=debug')
        self.assertIn(optin, topology)
        retire = topology.index('for cleanup_unit in $AGENT_UNITS; do retire_unit "$cleanup_unit"')
        finalize = topology.index("        content_provider_worker_budget_finalize", retire)
        self.assertLess(retire, finalize)
        self.assertLess(finalize, topology.index("    copy_artifacts || original_status=1", finalize))
        shell = (HERE / "content-provider-adaptive-smoke.sh").read_text()
        for phase in ("native", "https"):
            self.assertIn(f"content_provider_worker_budget_capture mark {phase}", shell)
            self.assertIn(f"content_provider_worker_budget_capture pending {phase}", shell)
            self.assertIn(f"content_provider_worker_budget_capture finish {phase}", shell)
        self.assertIn('|| fail CONTENT_PROVIDER_ADAPTIVE_EVIDENCE_INVALID', shell)
        emergency = (HERE / "run-alpha-topology-vm.sh").read_text()
        for phase in ("native", "https"):
            self.assertIn('"' + self.report(phase).name + '"', emergency)
            self.assertIn('"' + CHECK["continuation_path"](self.work, phase).name + '"', emergency)
        for name in ("kvm-alpha-topology.sh", "run-alpha-topology-vm.sh", "content-provider-adaptive-smoke.sh"):
            subprocess.run(["/bin/sh", "-n", str(HERE / name)], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
