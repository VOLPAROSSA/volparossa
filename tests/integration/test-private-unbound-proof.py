#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline report-parser regression; never represents actual Unbound execution."""

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "private_unbound_proof", Path(__file__).with_name("private-unbound-proof.py"))
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)
REVISION = "a" * 40


def synthetic_report():
    report = {"schema": 2, "source_revision": REVISION, "success": True, "failure": None,
              "report_kind": "private-unbound-public-adapter",
              "native_package_version": "1.26.1-0+deb13u1",
              "worker_sha256": "b" * 64, "root_key_sha256": "c" * 64,
              "root_hints_sha256": "d" * 64,
              "normal_client_route_proven": False, "reciprocal_client_exit_proven": False,
              "shared_dns_proof_proven": False, "native_cache_linkage_proven": True,
              "guest_hosts_unchanged": True,
              "cases": {case: {"case": case, "case_passed": True, "probe_exit_code": 0,
                               "os_sentinel": True} for case in PROOF.CASES}}
    for case, secure in (("signed", True), ("unsigned", False)):
        report["cases"][case].update(verdict="positive", dnssec_secure=secure,
                                     ttl_seconds=30, address_count=1, shareable_proof=secure,
                                     source="independently_validated" if secure else "private_unbound",
                                     local_cache_reuse=secure, cache_ttl_not_extended=secure,
                                     proof_policy_bound=True)
    report["cases"]["bogus"]["verdict"] = "bogus"
    for case in ("timeout", "cancel"):
        report["cases"][case].update(native_worker_stopped=True, native_worker_reaped=True)
    report["cases"]["timeout"].update(verdict="unavailable", elapsed_ms=4500)
    report["cases"]["cancel"]["verdict"] = "cancelled"
    return report


class ReportContract(unittest.TestCase):
    def test_complete_scoped_schema(self):
        PROOF.validate(synthetic_report(), REVISION)

    def test_scope_and_actual_verdict_cannot_be_substituted(self):
        for field in ("normal_client_route_proven", "reciprocal_client_exit_proven",
                      "shared_dns_proof_proven"):
            changed = synthetic_report()
            changed[field] = True
            with self.assertRaises(RuntimeError):
                PROOF.validate(changed, REVISION)
        changed = synthetic_report()
        changed["cases"]["unsigned"]["dnssec_secure"] = True
        with self.assertRaises(RuntimeError):
            PROOF.validate(changed, REVISION)

    def test_cleanup_and_fallback_failure_are_required(self):
        original = synthetic_report()
        for case, field, value in (("timeout", "native_worker_reaped", False),
                                   ("cancel", "native_worker_stopped", False),
                                   ("bogus", "verdict", "positive"),
                                   ("signed", "os_sentinel", False),
                                   ("signed", "ttl_seconds", 0),
                                   ("signed", "shareable_proof", False),
                                   ("signed", "local_cache_reuse", False),
                                   ("signed", "cache_ttl_not_extended", False),
                                   ("signed", "proof_policy_bound", False)):
            changed = copy.deepcopy(original)
            changed["cases"][case][field] = value
            with self.assertRaises(RuntimeError):
                PROOF.validate(changed, REVISION)

    def test_fixed_error_is_retained_without_becoming_the_expected_verdict(self):
        changed = synthetic_report()
        changed["cases"]["bogus"].update(case_passed=False, verdict="unavailable",
                                        error="Unavailable", elapsed_ms=4501)
        with self.assertRaises(RuntimeError):
            PROOF.validate(changed, REVISION)
        self.assertEqual(changed["cases"]["bogus"]["error"], "Unavailable")
        self.assertEqual(changed["cases"]["bogus"]["elapsed_ms"], 4501)


if __name__ == "__main__":
    unittest.main()
