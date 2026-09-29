#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline report-parser regression; never represents actual Unbound execution."""

import copy
import importlib.util
import os
from pathlib import Path
import struct
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

    def test_extra_native_diagnostic_never_replaces_failed_primary_acceptance(self):
        changed = synthetic_report()
        changed["cases"]["signed"].update(case_passed=False, error="Unavailable", verdict="unavailable")
        changed["diagnostics"] = dict(acceptance_evidence=False,
            cases=dict(signed=dict(native_status="positive", native_secure_flag=True,
                                   primary_reply_elapsed_ms=7000, native_worker_reaped=True)))
        self.assertEqual(PROOF.diagnostic_cases(changed["cases"]), ["signed"])
        with self.assertRaises(RuntimeError):
            PROOF.validate(changed, REVISION)
        changed["cases"]["bogus"].update(case_passed=False, error="Unavailable")
        changed["cases"]["timeout"].update(case_passed=False, error="Unavailable")
        self.assertEqual(PROOF.diagnostic_cases(changed["cases"]), ["signed", "bogus"])
        changed["cases"]["signed"]["error"] = "InvalidProof"
        self.assertEqual(PROOF.diagnostic_cases(changed["cases"]), ["bogus"])

    def test_diagnostic_frame_is_exact_bound_and_exports_no_raw_packet(self):
        name, nonce = b"iana.org", os.urandom(16)
        header = bytearray(44)
        header[:8], header[16:32] = PROOF.NATIVE_MAGIC, nonce
        header[9] = 1
        header[10:12] = struct.pack("!H", 1)
        header[12:16] = struct.pack("!I", 60)
        header[36:40] = struct.pack("!I", 12)
        header[40:44] = struct.pack("!HH", 1, len(name))
        frame = header + name + b"\xc0\x00\x2b\x08" + b"\0" * 12
        summary = PROOF.native_reply_summary(frame, name, nonce)
        self.assertEqual(summary, dict(native_status="positive", native_secure_flag=True,
            address_count=1, ttl_seconds=60, raw_packet_bytes=12))
        for index, replacement in ((0, b"invalid!"), (8, b"\x05"), (9, b"\x02"),
                                   (10, struct.pack("!H", 17)), (12, b"\0" * 4),
                                   (16, os.urandom(16)), (32, struct.pack("!I", 1)),
                                   (36, struct.pack("!I", 4097)), (40, struct.pack("!H", 28)),
                                   (42, struct.pack("!H", len(name) + 1)), (44, b"x")):
            bad = frame.copy()
            bad[index:index + len(replacement)] = replacement
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                PROOF.native_reply_summary(bad, name, nonce)
        for bad in (frame[:-1], frame + b"x", b"", frame[:43]):
            with self.assertRaises(RuntimeError):
                PROOF.native_reply_summary(bad, name, nonce)
        for status in range(1, 5):
            negative = header.copy()
            negative[8], negative[9:16], negative[36:40] = status, b"\0" * 7, b"\0" * 4
            result = PROOF.native_reply_summary(negative + name, name, nonce)
            self.assertEqual(result["native_status"], ("unavailable", "nxdomain", "nodata", "bogus")[status - 1])
            negative[9] = 1
            with self.assertRaises(RuntimeError):
                PROOF.native_reply_summary(negative + name, name, nonce)


if __name__ == "__main__":
    unittest.main()
