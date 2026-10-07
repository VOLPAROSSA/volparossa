#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure maintenance dispatch/export contracts; never execute a VM or network operation."""

import json
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SCENARIO = "private-storage-maintenance"


def diagnostics():
    driver = (HERE / "run-alpha-topology-vm.sh").read_text()
    code = driver.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split(
        "\nGUEST_DIAGNOSTICS_PYTHON", 1
    )[0]
    namespace = {"__name__": "maintenance_wiring_test"}
    exec(compile(code, "bounded_guest_diagnostics", "exec"), namespace)
    return namespace


class PrivateStorageMaintenanceWiring(unittest.TestCase):
    def test_preview_and_repeated_scenario_selection_are_isolated(self):
        for script in ("kvm-alpha-topology.sh", "run-alpha-topology-vm.sh"):
            for first, last in ((SCENARIO, "private-storage-replicas"),
                                ("private-storage-replicas", SCENARIO),
                                (SCENARIO, "private-storage-peer")):
                with self.subTest(script=script, first=first, last=last):
                    result = subprocess.run(
                        ["sh", str(HERE / script), "--preview", "--scenario", first,
                         "--scenario", last],
                        capture_output=True, text=True, timeout=10, check=True,
                    )
                    self.assertIn(last, result.stdout.lower())
                    self.assertNotIn(first, result.stdout.lower())
                    self.assertIn("PREVIEW ONLY", result.stdout)

    def test_guest_stages_dependencies_and_uses_separate_lifecycle(self):
        guest = (HERE / "kvm-alpha-topology.sh").read_text()
        self.assertIn("private_storage_maintenance=no", guest)
        self.assertIn("private-storage-maintenance) scenario=content-custody; private_storage_fragments=yes; private_storage_maintenance=yes;", guest)
        for dependency in ("private-storage-maintenance-smoke.py", "private-storage-maintenance-smoke.sh",
                           "storage-route-readiness.py",
                           "private-storage-fragments-smoke.py", "private-storage-replicas-smoke.py",
                           "private-storage-peer-smoke.py", "content-provider-https-smoke.py",
                           "content-network-smoke.py"):
            self.assertIn(dependency, guest)
        for operation in ("run", "finalize_report"):
            self.assertIn("private_storage_maintenance_" + operation, guest)
        self.assertIn("private_storage_fragments_cleanup", guest)
        self.assertLess(guest.index("    private_storage_maintenance_run\n"),
                        guest.index("    private_storage_fragments_run\n"))
        self.assertLess(guest.index("        private_storage_maintenance_finalize_report"),
                        guest.index("        private_storage_fragments_finalize_report"))
        for phase in ("upload", "restore", "finish"):
            self.assertIn(f"private-storage-fragments-{phase}-privacy", guest)
        workflow = (HERE.parents[1] / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("          - private-storage-maintenance\n", workflow)
        start = workflow.index("      - name: Require actual owner-private storage maintenance")
        end = workflow.index("\n      - name:", start + 1)
        gate = workflow[start:end]
        self.assertIn("if: always() && env.VOLPAROSSA_ALPHA_SCENARIO == 'private-storage-maintenance'", gate)
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', gate)
        self.assertIn('private-storage-maintenance-smoke.py report "$report" "$GITHUB_SHA"', gate)
        self.assertIn("host-state-before.json", gate)
        self.assertIn("host-state-after.json", gate)

    def test_owner_admission_and_enclosing_timeout_remain_scoped(self):
        guest = (HERE / "kvm-alpha-topology.sh").read_text()
        self.assertNotIn('        if [ "$private_storage_maintenance" = yes ] && [ "$node" = client ]; then', guest)
        # Execute the canonical emitter, rather than matching another duplicate
        # config block. The config-crate test additionally parses the full client
        # output using the same strict Rust parser as the real agent.
        result = subprocess.run(['sh', '-eu', '-c',
            '. "$1"; scenario=content-custody; node=client; private_storage_maintenance=yes; content_custody_config',
            'maintenance-config-test', str(HERE / 'content-custody-smoke.sh')],
            capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout, 'sharing:\n  enabled: true\n  interface: cr0\n'
            '  total_upload_mbps: 100\n  contribution_upload_ceiling_mbps: 10\n'
            'download_sharing:\n  enabled: true\n  interface: cr0\n'
            '  total_download_mbps: 100\n  contribution_download_ceiling_mbps: 10\n')
        driver = (HERE / "run-alpha-topology-vm.sh").read_text()
        self.assertIn('[ "$scenario" != private-storage-maintenance ] || driver_time_bound=3600s', driver)
        self.assertIn('driver_time_bound=2400s', driver)
        success_export = driver[driver.index('printf \'%s\\n\' "$topology_status"'):]
        self.assertIn('[ "$scenario" = private-storage-maintenance ]', success_export)
        self.assertIn('python3 -B "tests/integration/$scenario-smoke.py" export-names', success_export)

    def test_exact_export_allowlist_excludes_private_data_and_generic_globs(self):
        checker = runpy.run_path(str(HERE / "private-storage-maintenance-smoke.py"))
        module = diagnostics()
        names = set(checker["EXPORT_NAMES"])
        self.assertEqual(names, module["MAINTENANCE_NAMES"])
        self.assertIn("private-storage-maintenance-route-diagnostic.json", names)
        self.assertEqual(len(names), len(checker["EXPORT_NAMES"]))
        self.assertTrue(all(name.endswith(".json") and "/" not in name for name in names))
        self.assertLess(len(names), 128)
        with tempfile.TemporaryDirectory(prefix="volparossa-maintenance-export-") as temporary:
            base = Path(temporary)
            home = base / "home"
            published = home / "alpha-output"
            published.mkdir(parents=True)
            for name in names:
                (published / name).write_text("{}\n")
            forbidden = (
                "private-storage-maintenance-owner.json", "private-storage-maintenance-journal.json",
                "private-storage-maintenance-grant.json", "private-storage-maintenance-request.json",
                "private-storage-maintenance-result.log", "private-storage-maintenance-input.bin",
                "private-storage-maintenance.key", "content-provider-adaptive-private-storage-fragments-upload-control.log",
                "content-private-owner.json", "content-private-request.json",
                "private-storage-fragments-connect.err", "private-storage-fragments-connect.out",
                "private-storage-fragments-paths.txt", "logs-client.txt",
                "private-storage-maintenance-selection-start.private",
                "private-storage-maintenance-selection-end.private",
                "private-storage-maintenance-preselection.part",
            )
            for name in forbidden:
                (published / name).write_text("PRIVATE_SENTINEL_DO_NOT_EXPORT\n")
            archive = module["collect"](home, base / "missing-opt", "a" * 40, SCENARIO, 124,
                                        cgroups=base / "missing-cgroups", proc=base / "missing-proc")
            with tarfile.open(archive, "r:gz") as bundle:
                actual = set(bundle.getnames())
                self.assertEqual(actual, {f"published/{name}" for name in names} | {"vm-incomplete.json"})
                for member in bundle.getmembers():
                    with bundle.extractfile(member) as stream:
                        self.assertNotIn(b"PRIVATE_SENTINEL_DO_NOT_EXPORT", stream.read())
                with bundle.extractfile("vm-incomplete.json") as stream:
                    report = json.load(stream)
            self.assertFalse(report["success"])
            self.assertFalse(report["cleanup"]["verified"])
            self.assertIsNone(report["host_state"]["unchanged"])
            self.assertLessEqual(report["diagnostics"]["captured_bytes"], module["TOTAL_LIMIT"])

    def test_actual_finalizer_exports_fresh_projection_without_changing_failed_outcome(self):
        # Run only the sourced selector/finalizer with a failing Connect double.
        # No binary, network namespace, peer or service is started here.
        script = r'''
set -eu
source_directory=$1; WORK=$2; output_directory=$3
OUTPUT_UID=$(id -u); OUTPUT_GID=$(id -g)
binary_directory=/unused; private_storage_maintenance=yes
expected_commit=1111111111111111111111111111111111111111
RUN_ID=synthetic; PHASE=private-storage-fragments-prepare
OBSERVED_BLOCKER=FRAGMENTS_ROUTE_UNAVAILABLE; CLEANUP_COMPLETE=true; REMAINING_OWNED_OBJECTS=0
. "$source_directory/tests/integration/benchmark-selection.sh"
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
date() {
    if [ "$1" = '+%s%3N' ]; then
        if [ "$benchmark_connect_count" -eq 0 ]; then printf '1000\n'; else printf '1010\n'; fi
    else printf '1\n'; fi
}
timeout() { printf '%s\n' 'Error: agent rejected request: NO_ELIGIBLE_PATHS (Unavailable)' >&2; return 1; }
python3() {
    case "$*" in
        *storage-route-readiness.py*) printf '%s\n' '{"eligible_slate_observed":true,"dataplane_verified":false,"route_selected":false}'; return 0 ;;
    esac
    command python3 "$@"
}
benchmark_capture_paths() { exit 99; }
optional_json_evidence() { printf 'null\n'; }
selection_status=0
benchmark_select_route private-storage-fragments mptcp || selection_status=$?
final_status=0
private_storage_maintenance_finalize_report "$selection_status" || final_status=$?
printf 'closed_status=%s:%s\n' "$selection_status" "$final_status"
'''
        with tempfile.TemporaryDirectory(prefix="maintenance-finalize-", dir=HERE) as temporary:
            work = Path(temporary)
            output = work / 'published'
            output.mkdir()
            raw = work / 'logs-client.txt'
            raw.write_text('999\tlevel=1\tevent=PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS\tsession=\tpath=-\n'
                '1005\tlevel=1\tevent=PRESELECTION_SAMPLE_NO_EXIT\tsession=abcdef\tpath=12345\n'
                '1020\tlevel=1\tevent=PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS\tsession=\tpath=-\n')
            raw.chmod(0o600)
            result = subprocess.run(['sh', '-c', script, 'test', str(HERE.parents[1]), str(work), str(output)],
                capture_output=True, text=True, check=True, timeout=10)
            self.assertIn('closed_status=1:1', result.stdout)
            record = json.loads((output / 'private-storage-maintenance-route-diagnostic.json').read_text())
            self.assertEqual(record['connect_reason_counts'], {'NO_ELIGIBLE_PATHS': 1})
            projection = record['preselection_diagnostic']
            self.assertEqual(projection['state'], 'known')
            self.assertEqual(projection['observed_reason'], 'PRESELECTION_SAMPLE_NO_EXIT')
            self.assertEqual((projection['fresh_records'], projection['stale_records'], projection['later_records']),
                (1, 1, 1))
            self.assertNotIn('abcdef', json.dumps(record))
            self.assertNotIn('12345', json.dumps(record))
            self.assertEqual({path.name for path in output.iterdir()}, {
                'private-storage-maintenance-route-diagnostic.json', 'private-storage-maintenance-smoke.json'})
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertLess(guest.index('logs --limit 400 >"$WORK/logs-$cleanup_node.txt"'),
            guest.index('        private_storage_maintenance_finalize_report'))


if __name__ == "__main__":
    unittest.main()
