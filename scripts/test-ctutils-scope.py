#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert security-boundary mutation tests; no Rust execution."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("scope", Path(__file__).with_name("check-ctutils-scope.py"))
SCOPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCOPE)


class ScopeTests(unittest.TestCase):
    def test_current_barriers_primitives_and_const_api_cannot_change(self):
        changes = (("src/choice.rs", b"core::hint::black_box(self.0)", b"self.0"),
                   ("src/choice.rs", b"self.to_u8().wrapping_neg()", b"self.0.wrapping_neg()"),
                   ("src/choice.rs", b"Self::from_u64_lt(x_hi, y_hi).to_u8()", b"Self::from_u64_lt(x_hi, y_hi).0"),
                   ("src/primitives.rs", b"black_box(bitborrow!", b"(bitborrow!"),
                   ("src/primitives.rs", b"pub const fn $sub", b"pub fn $sub"),
                   ("src/primitives.rs", b"value.leading_zeros()", b"0"))
        for path, old, new in changes:
            files = SCOPE.current_expected_files()
            self.assertIn(old, files[path])
            files[path] = files[path].replace(old, new)
            with self.subTest(path=path, old=old), self.assertRaisesRegex(ValueError, "approved"):
                SCOPE.verify_current(files)

    def test_current_licenses_or_extra_files_cannot_change(self):
        for path in ("LICENSE-MIT", "LICENSE-APACHE", "extra.rs"):
            files = SCOPE.current_expected_files()
            files[path] = b"changed"
            with self.subTest(path=path), self.assertRaises(ValueError):
                SCOPE.verify_current(files)

    def test_actual_vendor_has_only_approved_changes(self):
        SCOPE.main()
        self.assertEqual(len(SCOPE.CHOICE_METHODS) + len(SCOPE.OPTION_METHODS), 20)

    def reject_mutation(self, path, old, new):
        files = SCOPE.expected_files()
        self.assertIn(old, files[path])
        files[path] = files[path].replace(old, new)
        with self.assertRaisesRegex(ValueError, "approved"):
            SCOPE.verify(files)

    def test_removing_runtime_black_box_is_rejected(self):
        self.reject_mutation("src/choice.rs", b"core::hint::black_box(self.0)", b"self.0")

    def test_vulnerable_direct_mask_generation_is_rejected(self):
        self.reject_mutation("src/choice.rs", b"self.to_u8().wrapping_neg()", b"self.0.wrapping_neg()")

    def test_halves_barrier_removal_is_rejected(self):
        self.reject_mutation("src/choice.rs", b"Self::from_u64_lt(x_hi, y_hi).to_u8()", b"Self::from_u64_lt(x_hi, y_hi).0")

    def test_32bit_routing_changes_are_rejected(self):
        self.reject_mutation("src/choice.rs", b'Self::from_u128_lt_halves(x, y)', b'Self::from_u128_lsb(bitlt!(x, y, u128::BITS))')

    def test_extra_const_reduction_is_rejected(self):
        self.reject_mutation("src/choice.rs", b"pub const fn from_u64_lt(", b"pub fn from_u64_lt(")

    def test_removing_upstream_assertions_is_rejected(self):
        self.reject_mutation("src/choice.rs", b"assert!(lt.to_bool());", b"// removed")

    def test_license_changes_and_extra_files_are_rejected(self):
        for path in ("LICENSE-MIT", "LICENSE-APACHE", "extra.rs"):
            files = SCOPE.expected_files()
            files[path] = b"changed"
            with self.subTest(path=path), self.assertRaises(ValueError):
                SCOPE.verify(files)


if __name__ == "__main__":
    unittest.main()
