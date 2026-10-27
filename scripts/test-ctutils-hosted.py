#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert execution-location/authority contract checks; never invokes Rust."""
import importlib.util
import io
import hashlib
import json
import re
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
        for path in (M.ROOT / "Cargo.toml", M.ROOT / "third_party/rust/ctutils-current-regressions/Cargo.toml"):
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

    def test_private_cleanup_respects_group_safety_and_refuses_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir()
            (private / "retained.log").write_text("owned child may remain")
            self.assertFalse(M.remove_private(private, False))
            self.assertTrue((private / "retained.log").exists())
            link = root / "link"
            link.symlink_to(private)
            self.assertFalse(M.remove_private(link, True))
            self.assertTrue(private.exists())
            self.assertTrue(M.remove_private(private, True))
            self.assertFalse(private.exists())
            self.assertTrue(M.remove_private(private, True))

    def test_current_lock_rejects_wrong_or_duplicate_crypto_versions_and_registry_ctutils(self):
        def lock(ct="0.4.5", bigint="0.7.9", p384="0.14.0", source="", extra=""):
            return (f'[[package]]\nname="ctutils"\nversion="{ct}"\n{source}\n'
                    f'[[package]]\nname="crypto-bigint"\nversion="{bigint}"\n'
                    f'[[package]]\nname="p384"\nversion="{p384}"\n{extra}')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Cargo.lock"
            path.write_text(lock())
            self.assertEqual(len(M.fixture_lock(path)), 64)
            for text in (lock(ct="0.4.4"), lock(bigint="0.7.8"), lock(p384="0.13.1"),
                         lock(source='source="registry+https://example.invalid"'),
                         lock(extra='[[package]]\nname="p384"\nversion="0.13.1"\n')):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    M.fixture_lock(path)

    def test_in_process_provision_cleanup_failure_retains_scratch_and_never_reports_passed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "proof"
            musl = root / "ctutils-musl-i386"
            compiler = root / "volparossa-rust-1.99.1"
            staging = root / "rust199-components-inert"
            def prepare(prefix, *_):
                prefix.mkdir()
                (prefix / "retained").write_text("inert musl")
                return {"inert": True}
            def provision(mode):
                self.assertEqual(mode, "runner")
                compiler.mkdir()
                staging.mkdir()
                print("inert installer cleanup unconfirmed")
                raise M.GROUP['CleanupUnconfirmed']("inert retained installer")
            environment = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                GITHUB_SHA="a" * 40, CTUTILS_CORE_REVISION="a" * 40, RUNNER_TEMP=temporary)
            captured = io.StringIO()
            with patch.dict(os.environ, environment, clear=True), \
                 patch.object(M.sys, "stdout", captured), \
                 patch.object(M.subprocess, "check_output", return_value="a" * 40), \
                 patch.object(M, "fixture_lock", return_value="inert"), \
                 patch.object(M, "run_owned") as run, \
                 patch.object(M.shutil, "copytree"), \
                 patch.dict(M.MUSL, prepare=prepare), \
                 patch.dict(M.GROUP, provision=provision):
                with self.assertRaises(M.GROUP['CleanupUnconfirmed']):
                    M.execute(output)
            self.assertNotIn("install-1.99.1: passed", captured.getvalue())
            receipt = json.loads((output / "receipt.json").read_text())
            self.assertFalse(receipt['process_group_cleanup_confirmed'])
            self.assertFalse(receipt['private_graph_removed'])
            self.assertFalse(receipt['musl_input_removed'])
            self.assertFalse(receipt['functional_tests_passed'])
            self.assertEqual(receipt['failure']['type'], 'CleanupUnconfirmed')
            operation = receipt['commands'][-1]
            self.assertEqual(operation['operation'], "in-process provision('runner')")
            self.assertFalse(operation['passed'])
            self.assertEqual(set(receipt['retained_prefixes']),
                {str(output) + "-private", str(musl), str(compiler)})
            self.assertEqual(receipt['retained_compiler_staging_candidates'], [str(staging)])
            for path in (Path(str(output) + "-private"), musl, compiler, staging):
                self.assertTrue(path.is_dir())
            self.assertIn("inert installer cleanup unconfirmed", (output / "install-1.99.1.log").read_text())
            self.assertEqual(run.call_count, 2)  # Only inert source checks, never a provision child.
            self.assertFalse(any('provision-rust199.py' in str(call.args) for call in run.call_args_list))

    def test_public_release_vector_reconstructs_existing_core_fixture_bytes(self):
        fixtures = M.ROOT / "crates/volparossa-content/tests/fixtures/snp"
        certificate = (fixtures / "vcek_milan.der").read_bytes()
        report = bytes.fromhex((fixtures / "report_milan.hex").read_text())
        source = (M.ROOT / "third_party/rust/ctutils-current-regressions/src/public_vector.rs").read_text()
        def constant(name):
            match = re.search(r"pub const " + name + r": \[u8; [0-9]+\] = \[(.*?)\];", source, re.S)
            self.assertIsNotNone(match)
            return bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", match[1]))
        marker = bytes.fromhex("03620004")
        self.assertEqual(certificate.count(marker), 1)
        index = certificate.index(marker)
        self.assertEqual(constant("PUBLIC_KEY"), certificate[index + 3:index + 100])
        self.assertEqual(len(constant("PUBLIC_KEY")), 97)
        self.assertEqual(constant("PREHASH"), hashlib.sha384(report[:0x2a0]).digest())
        self.assertEqual(report[0x2a0 + 48:0x2a0 + 72], bytes(24))
        self.assertEqual(report[0x2a0 + 120:0x2a0 + 144], bytes(24))
        self.assertEqual(constant("SIGNATURE"),
            report[0x2a0:0x2a0 + 48][::-1] + report[0x2a0 + 72:0x2a0 + 120][::-1])
        for name in ("vcek_milan.der", "report_milan.hex"):
            self.assertIn(hashlib.sha256((fixtures / name).read_bytes()).hexdigest(), source)

    def test_both_native_and_real_32bit_targets_and_secret_entrypoints_are_named(self):
        self.assertEqual(M.TARGETS, ("x86_64-unknown-linux-gnu", "i686-unknown-linux-musl"))
        self.assertEqual(M.COMPILERS, ("1.99.1",))
        self.assertEqual(len(M.SYMBOLS), 28)
        self.assertIn("ct_digest_output_eq", M.SYMBOLS)
        self.assertIn("ct_poly1305_verify", M.SYMBOLS)


if __name__ == "__main__":
    unittest.main()
