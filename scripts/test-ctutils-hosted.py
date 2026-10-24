#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert execution-location/authority contract checks; never invokes Rust."""
import importlib.util
from pathlib import Path
import unittest
import os
import tomllib
import tempfile
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("hosted", Path(__file__).with_name("run-ctutils-hosted.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class AdmissionTests(unittest.TestCase):
    def test_exact_hosted_assignment_is_accepted(self):
        M.admission(dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                         GITHUB_SHA="a" * 40, CTUTILS_CORE_REVISION="a" * 40), "a" * 40)

    def test_host_or_self_hosted_execution_is_rejected(self):
        for location in (None, "self-hosted", ""):
            with self.subTest(location=location), self.assertRaises(ValueError):
                M.admission(dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT=location,
                                 GITHUB_SHA="a" * 40, CTUTILS_CORE_REVISION="a" * 40), "a" * 40)

    def test_mismatched_or_mutable_revisions_are_rejected(self):
        for revision in ("main", "b" * 40, "A" * 40):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                M.admission(dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                                 GITHUB_SHA="a" * 40, CTUTILS_CORE_REVISION="a" * 40), revision)

    def test_admission_precedes_output_creation_and_any_compilation(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(M.subprocess, "check_output", return_value="a" * 40), \
             patch.object(M.subprocess, "run", side_effect=AssertionError("early execution")), \
             patch.object(Path, "mkdir", side_effect=AssertionError("early directory creation")):
            with self.assertRaises(ValueError):
                M.execute(Path("unused"))

    def test_captured_profile_matches_actual_core_and_consumer_fixture(self):
        for path in (M.ROOT / "Cargo.toml", M.ROOT / "third_party/rust/ctutils-regressions/Cargo.toml"):
            self.assertEqual(tomllib.loads(path.read_text())["profile"]["release"], M.RELEASE)

    def test_payload_selection_excludes_sources_binaries_caches_and_hidden_files(self):
        with tempfile.TemporaryDirectory(prefix="ctutils-payload-") as temporary:
            root = Path(temporary)
            allowed = {"receipt.json", "REVIEW_REQUIRED.md", "tests.log",
                       "codegen-1.85-amd64/proof.s", "codegen-1.85-i686/proof.ll"}
            forbidden = {"reference/ctutils-0.4.4/src/lib.rs", "reference/fixture/Cargo.lock",
                         "reference/build.log", "cargo-home/credentials.toml", "target/proof",
                         "proof.bin", "codegen-1.85-amd64/proof.o", "codegen-1.85-amd64/nested/proof.s",
                         ".hidden.log", "codegen-1.85-amd64/.hidden.ll"}
            for name in allowed | forbidden:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"inert fixture")
            selected = {str(p.relative_to(root)) for p in M.artifact_files(root)}
            self.assertEqual(selected, allowed)
            self.assertTrue(selected.isdisjoint(forbidden))

    def test_payload_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="ctutils-payload-link-") as temporary:
            root = Path(temporary)
            (root / "source.bin").write_bytes(b"not evidence")
            (root / "fake.log").symlink_to(root / "source.bin")
            with self.assertRaisesRegex(ValueError, "symlink"):
                M.artifact_files(root)

    def test_both_native_and_real_32bit_targets_and_secret_entrypoints_are_named(self):
        self.assertEqual(M.TARGETS, ("x86_64-unknown-linux-gnu", "i686-unknown-linux-musl"))
        self.assertEqual(len(M.SYMBOLS), 17)
        self.assertIn("ct_digest_output_eq", M.SYMBOLS)
        self.assertIn("ct_poly1305_verify", M.SYMBOLS)


if __name__ == "__main__":
    unittest.main()
