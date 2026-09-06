#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Load-only shell and synthetic report checks; no networking or product processes."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap

HERE = Path(__file__).resolve().parent
source = (HERE / "kvm-alpha-topology.sh").read_text(encoding="utf-8")
workflow = (HERE.parent.parent / ".github/workflows/alpha-topology.yml").read_text(encoding="utf-8")


def function(name):
    start = source.index(name + "() {\n")
    return source[start:source.index("\n}\n", start) + 3]


sequence = function("run_a14_crash_recovery")
assert source.count("\nrun_a14_crash_recovery() {\n") == 1
assert source.count("\n    run_a14_crash_recovery\n") == 1
assert source.endswith("\nrun_a14_crash_recovery\n")
assert source.index("start_mptcp_download() {") < source.index("\n    run_a14_crash_recovery\n")
assert source.index("\n    run_a14_crash_recovery\n") < source.index("\nPHASE=a02-capture\n")
assert '[ "$scenario" != mixed-link ] && [ "$scenario" != crash-recovery ]' in source
assert sequence.index("refresh_a14_live_custody") < sequence.index("record_a14_owned_inventory")
assert sequence.index("record_a14_owned_inventory") < sequence.index("force_crash_unit agent")
assert sequence.index("force_crash_unit helper") < sequence.index("verify_a14_helper_restart_recovery")
assert 'start_mptcp_download a14-custody a14-custody 0 -' in function("refresh_a14_live_custody")
definitions = "\n".join(function(name) for name in (
    "run_a14_crash_recovery", "refresh_a14_live_custody", "start_mptcp_download",
    "record_a14_owned_inventory", "verify_a14_helper_restart_recovery",
    "optional_json_evidence", "crash_recovery_finalize_report",
))
subprocess.run(["sh", "-eu", "-c", definitions], check=True, timeout=5)

step = workflow.split("      - name: Require scoped A14/A15 crash recovery evidence\n", 1)[1]
validator = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
assert "acceptance-report.json" not in validator

with tempfile.TemporaryDirectory(prefix="crash-report-test-", dir=HERE) as raw:
    directory = Path(raw)
    baseline = b'{"scope":"synthetic report test only"}\n'
    digest = hashlib.sha256(baseline).hexdigest()
    for name in ("host-state-before.json", "host-state-after.json"):
        (directory / name).write_bytes(baseline)
    cleanup = {name: 0 for name in (
        "remaining_owned_objects", "remaining_namespaces", "remaining_units", "remaining_runtime_sockets",
        "remaining_links", "remaining_routes", "remaining_mptcp_endpoints", "remaining_mpquic_paths",
        "remaining_nftables_rules", "remaining_worker_network_namespaces",
        "remaining_worker_namespace_references", "remaining_helper_fdstore_descriptors",
    )}
    cleanup["worker_custody_after"] = {"referenced_namespace_count": 0, "remaining_reference_count": 0}
    a14 = {
        "success": True, "live_application_flow": {
            "case": "a14-custody", "attempt": 0, "release_gate_closed": True,
            "listen": {"ip": "47.163.4.2", "port": 18080},
            "source": {"ip": "47.163.4.1", "port": 12345},
            "request_bytes": 32, "request_sha256": digest,
        },
        "owned_before": {"network_namespace_count": 12, "runtime_socket_count": 25,
                         "namespaces": [{"nftables_rules": 1}], "helper_worker_custody": {
            "worker_process_count": 5, "worker_network_namespace_count": 5,
            "durable_route_namespace_count": 4, "live_ingress_namespace_count": 1,
            "helper_fdstore_descriptors": 8,
            "helper_custody_coverage": [{"fdstore_descriptors": 8, "durable_route_namespace_count": 4}],
        }},
        "forced_crashes": [{"class": kind, "sigkill_delivered": True, "pid_absent_after": True}
                           for kind, count in (("agent", 11), ("helper", 11), ("native", 3))
                           for _ in range(count)],
        "helper_restart_recovery": {"all_helpers_restarted": True, "helpers": [
            {"old_pid": i + 1, "new_pid": i + 101, "restarted": True,
             "helper_socket_republished": True, "inherited_fdstore_descriptors_after": 0}
            for i in range(11)]},
        "cleanup": cleanup,
    }
    a15 = {"success": True, "unchanged": True, "before_sha256": digest, "after_sha256": digest}
    environment = dict(os.environ, WORK=raw, output_directory=raw,
                       expected_commit="a" * 40, STARTED_AT="test", FINISHED_AT="test",
                       PHASE="a15-complete", OBSERVED_BLOCKER="NONE", CLEANUP_COMPLETE="true",
                       REMAINING_OWNED_OBJECTS="0", OUTPUT_UID=str(os.getuid()), OUTPUT_GID=str(os.getgid()),
                       TOPOLOGY_EXIT_CODE="0", GITHUB_SHA="a" * 40, VOLPAROSSA_ALPHA_OUTPUT=raw)

    def report(evidence, status, remaining):
        (directory / "a14-evidence.json").write_text(json.dumps(evidence), encoding="ascii")
        (directory / "a15-evidence.json").write_text(json.dumps(a15), encoding="ascii")
        env = dict(environment, REMAINING_OWNED_OBJECTS=str(remaining),
                   CLEANUP_COMPLETE="true" if remaining == 0 else "false")
        subprocess.run(["sh", "-eu", "-c", definitions + f"\ncrash_recovery_finalize_report {status}"],
                       env=env, capture_output=True, text=True, check=True, timeout=5)
        result = json.loads((directory / "crash-recovery.json").read_text(encoding="ascii"))
        assert result["scope"] == ["A14", "A15"] and not result["full_alpha_acceptance_claimed"]
        assert not (directory / "acceptance-report.json").exists()
        return result

    def accepted():
        return subprocess.run(["bash", "-c", validator], env=environment, capture_output=True,
                              text=True, timeout=5).returncode == 0

    assert report(a14, 0, 0)["success"] and accepted()
    failed = copy.deepcopy(a14)
    failed["cleanup"]["remaining_worker_namespace_references"] = 1
    failed["success"] = False
    assert not report(failed, 1, 1)["success"] and not accepted()
    failed["success"] = True  # A forged summary cannot hide an actual remaining reference.
    report(failed, 0, 0)
    assert not accepted()
    failed = copy.deepcopy(a14)
    failed["helper_restart_recovery"]["helpers"][0]["new_pid"] = 1
    report(failed, 0, 0)
    assert not accepted()
    assert not report(None, 1, 0)["success"] and not accepted()
    report(a14, 0, 0)
    (directory / "host-state-after.json").write_bytes(b"changed\n")
    assert not accepted()

print("Crash-recovery definitions and scoped positive/failed-cleanup reports PASS (no live networking)")
