#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert source/metadata mutation tests; never invoke Cargo or native code."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("public_rsa_scope", Path(__file__).with_name("check-public-rsa-scope.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def metadata(root):
    packages = [dict(id=name, name=name, version=version, source=source)
        for name, version, source in (("rsa", "0.9.10", M.REGISTRY), ("sev", "8.0.0", None),
            ("volparossa-content", "0.1.0", None))]
    packages[-1]["manifest_path"] = str(root / M.CONTENT)
    packages[1]["manifest_path"] = str(root / M.SEV_SCOPE.VENDOR / "Cargo.toml")
    packages[1]["features"] = dict(snp=[], crypto_nossl=["dep:p384", "dep:rsa", "dep:sha2", "dep:x509-cert"])
    packages.extend(dict(id=name, name=name, version=version, source=M.REGISTRY)
        for name, version in M.CRYPTO.items() if name != "rsa")
    nodes = [dict(id=p["id"], dependencies=[], deps=[], features=[]) for p in packages]
    nodes[1]["features"] = ["crypto_nossl", "snp"]
    for parent, child in ((nodes[1], packages[0]), (nodes[2], packages[1])):
        parent["dependencies"] = [child["id"]]
        parent["deps"] = [dict(name=child["name"], pkg=child["id"], dep_kinds=[dict(kind=None, target=None)])]
    nodes[2]["dependencies"].append("rsa")
    nodes[2]["deps"].append(dict(name="rsa", pkg="rsa", dep_kinds=[dict(kind=None, target=None)]))
    for child in packages[3:]:
        nodes[1]["dependencies"].append(child["id"])
        nodes[1]["deps"].append(dict(name=child["name"].replace("-", "_"), pkg=child["id"],
            dep_kinds=[dict(kind=None, target=None)]))
    return (dict(workspace_root=str(root), workspace_members=["volparossa-content"],
        packages=packages, resolve=dict(nodes=nodes)), dict(workspace_root=str(root / "fuzz"), packages=[]))


class PublicRsaScope(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Use the current exact reviewed files, not a fake Rust implementation.
        for relative in (M.SNP, M.COLLATERAL, M.GUEST, M.SNP.parent.with_suffix(".rs"), M.CONTENT,
                Path("Cargo.toml"), Path("Cargo.lock"), Path("fuzz/Cargo.toml"),
                Path("fuzz/Cargo.lock"), Path("deny.toml")):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((M.ROOT / relative).read_bytes())
        self.meta, self.fuzz = metadata(self.root)
        # The same archived source and bounded adapter are authenticated by the
        # RSA guard before it can grant the pre-existing public-only exception.
        source = Path("third_party/rust/sources/sev-8.0.0-a966d06.tar.gz")
        destination = self.root / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((M.ROOT / source).read_bytes())
        for name, raw in M.SEV_SCOPE.expected_files().items():
            destination = self.root / M.SEV_SCOPE.VENDOR / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)

    def test_current_repository_scope_without_cargo(self):
        M.verify_repository(M.ROOT)
        M.verify_repository(self.root)
        M.verify_metadata(self.root, self.meta, self.fuzz)

    def test_root_config_changes_only_one_ignore_and_base_remains_strict(self):
        text = (self.root / "deny.toml").read_text()
        result = M.root_deny_config(text)
        self.assertNotIn(M.ADVISORY, M.tomllib.loads(text)["advisories"]["ignore"])
        before = M.tomllib.loads(text)
        before["advisories"]["ignore"].insert(0, M.ADVISORY)
        self.assertEqual(M.tomllib.loads(result), before)
        for invalid in (text.replace(M.MARKER, ""), text + "\n" + M.MARKER,
                text.replace(M.MARKER, M.MARKER + '\n  "' + M.ADVISORY + '",')):
            with self.subTest(invalid=invalid[:20]), self.assertRaises(ValueError):
                M.root_deny_config(invalid)

    def test_selected_identity_and_features_mutations(self):
        cases = []
        for index, field, value in ((0, "version", "0.9.9"), (0, "source", M.SOURCE),
                (1, "source", M.SOURCE.replace(M.REVISION, "0" * 40)),
                (1, "version", "8.0.1"), (1, "manifest_path", "/private/wrong/sev/Cargo.toml"),
                (2, "manifest_path", "/private/wrong/Cargo.toml")):
            changed = copy.deepcopy(self.meta)
            changed["packages"][index][field] = value
            cases.append(changed)
        for features in ([], ["snp"], ["crypto_nossl"], ["crypto_nossl", "snp", "snp"],
                *(["crypto_nossl", "snp", name] for name in ("default", "sev", "openssl", "hw_tests"))):
            changed = copy.deepcopy(self.meta)
            changed["resolve"]["nodes"][1]["features"] = features
            cases.append(changed)
        for value in cases:
            with self.subTest(value=value), self.assertRaises((ValueError, KeyError)):
                M.verify_metadata(self.root, value, self.fuzz)

    def test_crypto_feature_definition_and_required_edges(self):
        self.meta["packages"][1]["features"]["crypto_nossl"].remove("dep:rsa")
        with self.assertRaises(ValueError): M.verify_metadata(self.root, self.meta, self.fuzz)
        self.meta, self.fuzz = metadata(self.root)
        for name in ("p384", "sha2", "x509_cert"):
            value = copy.deepcopy(self.meta)
            node = value["resolve"]["nodes"][1]
            dep = next(d for d in node["deps"] if d["name"] == name)
            node["dependencies"].remove(dep["pkg"])
            node["deps"].remove(dep)
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.verify_metadata(self.root, value, self.fuzz)

    def test_reverse_edges_kind_alias_missing_extra_and_unresolved(self):
        for parent_index in (1, 2):
            for change in ("missing", "alias", "dev", "target", "extra", "unresolved", "hidden"):
                value = copy.deepcopy(self.meta)
                node = value["resolve"]["nodes"][parent_index]
                if change == "missing": node["deps"], node["dependencies"] = [], []
                elif change == "alias": node["deps"][0]["name"] = "renamed"
                elif change == "dev": node["deps"][0]["dep_kinds"][0]["kind"] = "dev"
                elif change == "target": node["deps"][0]["dep_kinds"][0]["target"] = "cfg(unix)"
                elif change == "extra": node["deps"].append(copy.deepcopy(node["deps"][0]))
                elif change == "unresolved": node["deps"][0]["pkg"] = "unresolved"
                else: node["dependencies"] = []
                with self.subTest(parent=parent_index, change=change), self.assertRaises((ValueError, KeyError)):
                    M.verify_metadata(self.root, value, self.fuzz)
        value = copy.deepcopy(self.meta)
        value["resolve"]["nodes"][2]["deps"].append(copy.deepcopy(value["resolve"]["nodes"][1]["deps"][0]))
        value["resolve"]["nodes"][2]["dependencies"].append("rsa")
        with self.assertRaises(ValueError): M.verify_metadata(self.root, value, self.fuzz)

    def test_duplicate_package_node_stale_workspace_and_fuzz_presence(self):
        for field in ("packages", "nodes"):
            value = copy.deepcopy(self.meta)
            target = value[field] if field == "packages" else value["resolve"][field]
            target.append(copy.deepcopy(target[0]))
            with self.assertRaises(ValueError): M.verify_metadata(self.root, value, self.fuzz)
        self.meta["workspace_root"] = "/private/stale"
        with self.assertRaises(ValueError): M.verify_metadata(self.root, self.meta, self.fuzz)
        self.meta, self.fuzz = metadata(self.root)
        for name in ("rsa", "sev"):
            self.fuzz["packages"] = [dict(name=name)]
            with self.assertRaises(ValueError): M.verify_metadata(self.root, self.meta, self.fuzz)

    def test_sev_manifest_requires_exact_version_alongside_git_revision(self):
        path = self.root / "Cargo.toml"
        original = path.read_text()
        selected = 'sev = { version = "=8.0.0", '
        self.assertIn(selected, original)
        for version in (None, "*", "8.0.0", "^8.0.0", "=8.0.1"):
            replacement = 'sev = { ' if version is None else f'sev = {{ version = "{version}", '
            path.write_text(original.replace(selected, replacement))
            try:
                with self.subTest(version=version), self.assertRaises(ValueError):
                    M.verify_repository(self.root)
            finally:
                path.write_text(original)

    def test_collateral_public_only_source_and_direct_edge_are_exact(self):
        for relative, old, new in ((M.COLLATERAL, "RsaPublicKey", "RsaPrivateKey"),
                (Path("Cargo.toml"), 'version = "=0.9.10"', 'version = "0.9.10"'),
                (M.CONTENT, 'rsa.workspace = true', 'rsa = "0.9.10"'),
                (M.CONTENT, 'rsa.workspace = true', '')):
            path = self.root / relative
            original = path.read_text()
            self.assertIn(old, original)
            path.write_text(original.replace(old, new))
            try:
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    M.verify_repository(self.root)
            finally:
                path.write_text(original)
        for change in ("missing", "alias", "dev", "target", "extra"):
            value = copy.deepcopy(self.meta)
            node = value["resolve"]["nodes"][2]
            direct = next(d for d in node["deps"] if d["name"] == "rsa")
            if change == "missing":
                node["deps"].remove(direct)
                node["dependencies"].remove("rsa")
            elif change == "alias": direct["name"] = "renamed"
            elif change == "dev": direct["dep_kinds"][0]["kind"] = "dev"
            elif change == "target": direct["dep_kinds"][0]["target"] = "cfg(unix)"
            else: node["deps"].append(copy.deepcopy(direct))
            with self.subTest(change=change), self.assertRaises(ValueError):
                M.verify_metadata(self.root, value, self.fuzz)

    def test_guest_firmware_only_source_is_exact_and_does_not_exempt_neighbors(self):
        path = self.root / M.GUEST
        original = path.read_text()
        call = '.get_report(Some(1), Some(data), Some(0))'
        self.assertIn('sev::firmware::guest::Firmware::open()', original)
        self.assertEqual(original.count(call), 1)
        variants = (
            original + '\nuse rsa::RsaPrivateKey;\n',
            original + '\nuse sev::certs::snp::Chain;\n',
            original.replace(call, '.get_ext_report(Some(1), Some(data), Some(0))'),
            original.replace(call, '.get_report(Some(1), Some(data), Some(1))'),
            original.replace('#[cfg(target_os = "linux")]', ''),
        )
        for changed in variants:
            path.write_text(changed)
            try:
                with self.subTest(change=changed[-80:]), self.assertRaises(ValueError):
                    M.verify_repository(self.root)
            finally:
                path.write_text(original)
        # The exact-file exception must not allow another SEV/RSA user beside it.
        neighbor = self.root / M.GUEST.with_suffix('') / 'wire.rs'
        neighbor.parent.mkdir(parents=True)
        for name in ('rsa', 'sev'):
            neighbor.write_text(f'use {name}::Unreviewed;\n')
            try:
                with self.subTest(neighbor=name), self.assertRaises(ValueError):
                    M.verify_repository(self.root)
            finally:
                neighbor.unlink()
        M.verify_repository(self.root)

    def test_lock_manifest_source_and_test_boundary_mutations(self):
        cases = [("Cargo.lock", M.RSA_CHECKSUM, "0" * 64),
            ("Cargo.lock", 'name = "sev"\nversion = "8.0.0"',
                'name = "sev"\nversion = "8.0.0"\nsource = "' + M.SOURCE + '"'),
            ("Cargo.toml", 'sev = { path = "third_party/rust/vendor/sev-8.0.0" }',
                'sev = { path = "third_party/rust/vendor/unreviewed-sev" }'),
            ("Cargo.toml", 'features = ["snp", "crypto_nossl"]', 'features = ["snp", "crypto_nossl", "sev"]'),
            (str(M.CONTENT), "sev.workspace = true", 'renamed = { workspace = true, package = "sev" }'),
            (str(M.SNP), "use sev::{", "use sev::{ /* changed */"),
            (str(M.SNP.parent.with_suffix(".rs")), "#[cfg(test)]\nmod tests;", "mod tests;")]
        for relative, old, new in cases:
            path = self.root / relative
            original = path.read_text()
            self.assertIn(old, original)
            path.write_text(original.replace(old, new))
            try:
                with self.subTest(relative=relative), self.assertRaises(ValueError): M.verify_repository(self.root)
            finally: path.write_text(original)
        for name in ("rsa", "sev"):
            path = self.root / "crates/extra.rs"
            path.write_text(f"use {name}::Private;\n")
            with self.assertRaises(ValueError): M.verify_repository(self.root)
            path.unlink()
            path = self.root / "fuzz/Cargo.lock"
            original = path.read_text()
            path.write_text(original + f'\n[[package]]\nname = "{name}"\nversion = "0.1.0"\n')
            with self.assertRaises(ValueError): M.verify_repository(self.root)
            path.write_text(original)

    def test_config_created_only_after_all_guards_and_never_overwritten(self):
        paths = [self.root / name for name in ("root.json", "fuzz.json", "root-deny.toml")]
        paths[0].write_text(json.dumps(self.meta))
        paths[1].write_text(json.dumps(self.fuzz))
        with patch.object(M, "ROOT", self.root), contextlib.redirect_stdout(io.StringIO()) as out:
            changed = copy.deepcopy(self.meta)
            changed["resolve"]["nodes"][1]["features"].append("openssl")
            paths[0].write_text(json.dumps(changed))
            with self.assertRaises(ValueError): M.main(list(map(str, paths)))
            self.assertFalse(paths[2].exists())
            paths[0].write_text(json.dumps(self.meta))
            M.main(list(map(str, paths)))
            self.assertIn("NOT patched", out.getvalue())
            self.assertTrue(paths[2].exists())
            original = paths[2].read_bytes()
            with self.assertRaises(FileExistsError): M.main(list(map(str, paths)))
            self.assertEqual(paths[2].read_bytes(), original)

    def test_shell_keeps_exception_out_of_fuzz_and_requires_guard_first(self):
        script = (M.ROOT / "scripts/check-rust-dependencies.sh").read_text()
        root_audit, fuzz_audit = script.split('"$audit_command" audit')[1:]
        self.assertIn("--ignore " + M.ADVISORY, root_audit)
        self.assertNotIn("--ignore " + M.ADVISORY, fuzz_audit)
        # Shell continuation lines preserve the actual CLI argv. Normalize only
        # whitespace so the scan wrapper cannot hide a missing/relocated guard.
        normalized = " ".join(script.replace("\\\n", " ").split())
        root_deny = 'cargo deny --locked --offline check --config "$root_deny_config"'
        self.assertLess(normalized.index("python3 -B scripts/check-public-rsa-scope.py"),
                        normalized.index(root_deny))
        # Pinned cargo-deny 0.18.6 declares config on Check, not the global CLI.
        self.assertIn(root_deny, normalized)


if __name__ == "__main__":
    unittest.main()
