#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert SEV provenance/adapter mutation tests; no cryptographic acceptance."""
import importlib.util
import copy
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("scope", Path(__file__).with_name("check-sev-p384-scope.py"))
SCOPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCOPE)


class ScopeTests(unittest.TestCase):
    def fixed_metadata(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        packages = [dict(name=name, version=version, source=registry) for name, version in {
            "crypto-bigint": "0.7.9", "p384": "0.14.0", "ecdsa": "0.17.0",
            "elliptic-curve": "0.14.3", "primeorder": "0.14.0"}.items()]
        packages.append(dict(name="sev", version="8.0.0", source=None,
            manifest_path=str(SCOPE.ROOT / SCOPE.VENDOR / "Cargo.toml")))
        ctutils = dict(name="ctutils", version="0.4.5", source=None,
            manifest_path=str(SCOPE.ROOT / "third_party/rust/vendor/ctutils-0.4.5/Cargo.toml"))
        return dict(packages=[*packages, ctutils]), dict(packages=[ctutils])

    def test_fixed_graph_requires_every_exact_package_and_path(self):
        root, fuzz = self.fixed_metadata()
        SCOPE.verify_metadata(root, fuzz)
        for index in range(len(root["packages"])):
            for field, replacement in (("version", "0.0.0"), ("source", "unreviewed")):
                changed = copy.deepcopy(root)
                changed["packages"][index][field] = replacement
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    SCOPE.verify_metadata(changed, fuzz)
            changed = copy.deepcopy(root)
            changed["packages"].append(changed["packages"][index])
            with self.subTest(duplicate=index), self.assertRaises(ValueError):
                SCOPE.verify_metadata(changed, fuzz)

    def test_vulnerable_crypto_and_fuzz_expansion_are_rejected(self):
        root, fuzz = self.fixed_metadata()
        changed = copy.deepcopy(root)
        changed["packages"][0]["version"] = "0.5.5"
        with self.assertRaises(ValueError):
            SCOPE.verify_metadata(changed, fuzz)
        for package in root["packages"][:-1]:
            changed = copy.deepcopy(fuzz)
            changed["packages"].append(package)
            with self.subTest(package=package["name"]), self.assertRaises(ValueError):
                SCOPE.verify_metadata(root, changed)

    def test_current_source_matches_three_file_adapter(self):
        SCOPE.verify_repository()
        original = SCOPE.original_files()
        expected = SCOPE.expected_files()
        self.assertEqual({name for name in original if original[name] != expected[name]}, {
            "Cargo.toml", "src/certs/snp/ecdsa/mod.rs", "src/firmware/guest/types/snp.rs"})

    def reject(self, path, old, new):
        files = SCOPE.expected_files()
        self.assertIn(old, files[path])
        files[path] = files[path].replace(old, new)
        with self.assertRaisesRegex(ValueError, "approved"):
            SCOPE.verify(files)

    def test_legacy_p384_and_unpinned_dependency_are_rejected(self):
        for replacement in (b'"0.13"', b'"0.14"', b'"=0.14.1"'):
            with self.subTest(replacement=replacement):
                self.reject("Cargo.toml", b'"=0.14.0"', replacement)

    def test_digest_algorithm_extent_and_double_hash_changes_are_rejected(self):
        path = "src/firmware/guest/types/snp.rs"
        for old, new in ((b"sha2::Sha384::digest", b"sha2::Sha256::digest"),
                         (b"[..0x2a0]", b"[..0x2b0]"),
                         (b"verify_prehash(&base_digest", b"verify_digest(&base_digest")):
            with self.subTest(old=old):
                self.reject(path, old, new)

    def test_scalar_width_and_byte_order_changes_are_rejected(self):
        path = "src/certs/snp/ecdsa/mod.rs"
        for old, new in ((b"[u8; 48]", b"[u8; 72]"),
                         (b"signature.r[47 - index]", b"signature.r[index]"),
                         (b"signature.s[47 - index]", b"signature.s[index]")):
            with self.subTest(old=old):
                self.reject(path, old, new)

    def test_rsa_verifier_and_builtin_anchor_changes_are_rejected(self):
        self.reject("src/certs/snp/cert_nossl.rs", b"sha2::Sha384", b"sha2::Sha256")
        files = SCOPE.expected_files()
        anchor = "src/certs/snp/builtin/milan/ark.pem"
        files[anchor] += b"changed"
        with self.assertRaises(ValueError):
            SCOPE.verify(files)

    def test_license_or_extra_source_changes_are_rejected(self):
        for path in ("LICENSE", "extra.rs"):
            files = SCOPE.expected_files()
            files[path] = b"changed"
            with self.subTest(path=path), self.assertRaises(ValueError):
                SCOPE.verify(files)

    def test_fixed_array_adapter_preserves_original_first_48_bytes(self):
        # Value equivalence only. The upstream/Core Rust tests must still execute.
        for value in (bytes(range(72)), bytes([0] * 72), bytes([255] * 72)):
            original = bytes(reversed(value[:48]))
            fixed_array = bytes(value[47 - index] for index in range(48))
            self.assertEqual(fixed_array, original)


if __name__ == "__main__":
    unittest.main()
