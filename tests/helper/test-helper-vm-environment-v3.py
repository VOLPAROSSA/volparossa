#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real validators with inert JSON fixtures; never launches a VM/compiler."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('environment', HERE / 'validate-helper-vm-environment-v3.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
SPEC2 = importlib.util.spec_from_file_location('compiler_tests', M.ROOT / 'scripts/test-provision-rust189.py')
T = importlib.util.module_from_spec(SPEC2); SPEC2.loader.exec_module(T)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n'


class EnvironmentTests(unittest.TestCase):
    def fixture(self, kind, directory):
        name = 'helper-boundary-evidence-v1.pass.json' if kind == 'boundary' else 'helper-restart-exact-present-evidence-v1.pass.json'
        report = directory / 'report.json'
        report.write_text((HERE / 'fixtures' / name).read_text())
        commit = json.loads(report.read_text())['observed_source']['commit_sha']
        value = dict(schema_version=3, expected_commit=commit, image_release_build='20260826-2582',
                     image_sha512=M.IMAGE, proof_network=dict(external_https='denied', mode='qemu-user-restrict-on'),
                     report_kind=M.KINDS[kind][0], status='PASS', report_sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
                     guest=dict(architecture='amd64', cargo_commit='c24e10642', debian_version='13',
                                rustc_version='1.89.0', systemd_version=257, virtualization='kvm'),
                     toolchain=T.receipt())
        return value, report, commit

    def test_both_successor_profiles_cross_link_real_existing_report_validators(self):
        for kind in M.KINDS:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                value, report, commit = self.fixture(kind, Path(directory))
                environment = Path(directory) / 'env.json'; environment.write_text(canonical(value))
                M.main([kind, str(environment), str(report), commit, M.IMAGE])

    def test_unreviewed_compiler_authority_and_mismatched_evidence_are_rejected(self):
        for field in ('profile', 'archive', 'compiler', 'guest', 'schema', 'report', 'commit', 'extra'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                value, report, commit = self.fixture('boundary', Path(directory))
                if field == 'profile': value['toolchain']['profile'] = 'stable'
                elif field == 'archive': value['toolchain']['components'][0]['xz_sha256'] = '0' * 64
                elif field == 'compiler': value['toolchain']['observed_versions']['rustc'] = 'rustc 1.85.0\n'
                elif field == 'guest': value['guest']['rustc_version'] = '1.85.0'
                elif field == 'schema': value['schema_version'] = 1
                elif field == 'report': value['report_sha256'] = '0' * 64
                elif field == 'commit': value['expected_commit'] = 'f' * 40
                elif field == 'extra': value['expected_toolchain_hash'] = '0' * 64
                with self.assertRaises(ValueError): M.validate(value, report, 'boundary', commit, M.IMAGE)

    def test_historical_v2_receipt_and_schema_cannot_enter_current_profile(self):
        legacy_spec = importlib.util.spec_from_file_location('legacy_compiler_tests', M.ROOT / 'scripts/test-provision-rust199.py')
        legacy = importlib.util.module_from_spec(legacy_spec)
        legacy_spec.loader.exec_module(legacy)
        for field in ('receipt', 'schema', 'guest'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                value, report, commit = self.fixture('boundary', Path(directory))
                if field == 'receipt': value['toolchain'] = legacy.receipt()
                elif field == 'schema': value['schema_version'] = 2
                else: value['guest']['rustc_version'] = '1.99.1'
                with self.assertRaises(ValueError): M.validate(value, report, 'boundary', commit, M.IMAGE)

    def test_unknown_profile_and_unreviewed_image_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            value, report, commit = self.fixture('boundary', Path(directory))
            for kind, image in [('unknown', M.IMAGE), ('boundary', 'f' * 128)]:
                with self.assertRaises(ValueError): M.validate(value, report, kind, commit, image)

    def test_symlinks_hardlinks_and_duplicate_json_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.write_text('{}\n')
            link = root / 'link'; link.symlink_to(source)
            with self.assertRaises(ValueError): M.read_input(link)
            link.unlink(); link.hardlink_to(source)
            with self.assertRaises(ValueError): M.read_input(source)
            link.unlink(); source.write_text('{"x":1,"x":1}\n')
            with self.assertRaises(ValueError): M.read_input(source)


if __name__ == '__main__': unittest.main()
