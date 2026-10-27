#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert resolver mutation fixtures: never run Cargo, Rust, or provisioning."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('resolver', Path(__file__).with_name('run-f04-security-resolver.py'))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def lock(packages):
    # Test TOML input only; production lock output is exclusively Cargo-generated.
    lines = ['version = 4']
    for name, version, dependencies in packages:
        lines += ['[[package]]', f'name = "{name}"', f'version = "{version}"',
                  f'checksum = "{name}-{version}"', 'source = "registry+https://github.com/rust-lang/crates.io-index"',
                  'dependencies = ' + json.dumps(dependencies)]
    return ('\n'.join(lines) + '\n').encode()


class ResolverTests(unittest.TestCase):
    def test_host_denied_before_mutation(self):
        with mock.patch.dict(R.os.environ, {}, clear=True), mock.patch.object(R.os, 'geteuid', return_value=1000), mock.patch.object(R.Path, 'mkdir') as mkdir:
            with self.assertRaises(ValueError):
                R.admit()
            mkdir.assert_not_called()

    def test_allowed_crypto_delta_and_semantic_parent_edges(self):
        before = lock([('outside', '1.0.0', ['ctutils']), ('ctutils', '0.4.4', [])])
        after = lock([('outside', '1.0.0', ['ctutils']), ('ctutils', '0.4.5', [])])
        delta = R.graph_delta(before, after)
        self.assertEqual(delta['unknown_package_names'], [])
        self.assertEqual(delta['unknown_edges'], [])
        self.assertEqual(len(delta['removed_edges']), 1)
        self.assertEqual(delta['added'][0]['version'], '0.4.5')

    def test_unknown_package_checksum_and_edge_mutations_rejected(self):
        before = lock([('unrelated', '1.0.0', []), ('other', '1.0.0', [])])
        after = lock([('unrelated', '1.0.0', ['other']), ('other', '1.0.0', [])])
        self.assertTrue(R.graph_delta(before, after)['unknown_edges'])
        checksum = before.replace(b'unrelated-1.0.0', b'changed-checksum')
        self.assertEqual(R.graph_delta(before, checksum)['unknown_package_names'], ['unrelated'])
        self.assertEqual(R.graph_delta(before, before + b'\n[[package]]\nname="unknown"\nversion="1.0.0"\n')['unknown_package_names'], ['unknown'])

    def test_ambiguous_dependency_rejected(self):
        value = lock([('parent', '1', ['ctutils']), ('ctutils', '0.4.4', []), ('ctutils', '0.4.5', [])])
        with self.assertRaises(ValueError):
            R.lock_graph(value)

    def test_duplicate_child_version_qualification_is_not_unknown(self):
        before = lock([('outside', '1', ['digest']), ('digest', '0.10.7', [])])
        after = lock([('outside', '1', ['digest 0.10.7']), ('digest', '0.10.7', []), ('digest', '0.11.0', [])])
        delta = R.graph_delta(before, after)
        self.assertEqual(delta['unknown_package_names'], [])
        self.assertEqual(delta['unknown_edges'], [])
        self.assertEqual(delta['removed_edges'], [])
        self.assertEqual(delta['added_edges'], [])

    def test_precise_selection_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Cargo.lock'
            path.write_bytes(lock([('crypto-bigint', '0.7.10', [])]))
            self.assertEqual(R.checked_selection(path, 'crypto-bigint', {'0.7.8', '0.7.9', '0.7.10'}), 'crypto-bigint@0.7.10')
            with self.assertRaises(ValueError):
                R.checked_selection(path, 'crypto-bigint', {'0.7.9'})
            path.write_bytes(lock([('ctutils', '0.4.5', []), ('ctutils', '0.4.6', [])]))
            with self.assertRaises(ValueError):
                R.checked_selection(path, 'ctutils', {'0.4.5', '0.4.6'})

    def test_only_known_dual_ctutils_precursor_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Cargo.lock'
            direct = b'[[package]]\nname="ctutils"\nversion="0.4.5"\n'
            registry = lock([('ctutils', '0.4.6', [])])
            path.write_bytes(registry + direct)
            allowed = {'0.4.4', '0.4.5', '0.4.6'}
            self.assertEqual(R.checked_selection(path, 'ctutils', allowed), 'ctutils@0.4.6')
            path.write_bytes(registry.replace(b'0.4.6', b'0.4.7') + direct)
            with self.assertRaises(ValueError):
                R.checked_selection(path, 'ctutils', allowed)
            path.write_bytes(registry + direct.replace(b'0.4.5', b'0.4.4'))
            with self.assertRaises(ValueError):
                R.checked_selection(path, 'ctutils', allowed)
            path.write_bytes(registry.replace(R.REGISTRY.encode(), b'git+https://unreviewed') + direct)
            with self.assertRaises(ValueError):
                R.checked_selection(path, 'ctutils', allowed)

    def test_source_mutation_index_includes_ignored_and_mode_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'ignored.rs'
            path.write_text('original')
            before = R.source_index(root)
            path.write_text('changed')
            self.assertEqual(R.changed_paths(before, R.source_index(root)), ['ignored.rs'])
            path.write_text('original')
            path.chmod(0o700)
            self.assertEqual(R.changed_paths(before, R.source_index(root)), ['ignored.rs'])

    def test_timeout_cleanup_is_recorded_without_launching_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finish = mock.Mock()
            provision = types.SimpleNamespace(wait_for_leader=mock.Mock(side_effect=subprocess.TimeoutExpired('fake', 1)), finish_group=finish)
            runner = R.Runner(root, root, root, root, provision)
            child = types.SimpleNamespace(pid=42)
            with mock.patch.object(R.subprocess, 'Popen', return_value=child) as launch:
                with self.assertRaises(subprocess.TimeoutExpired):
                    runner.command('synthetic', ['--version'])
            finish.assert_called_once_with(child)
            self.assertTrue(runner.records[0]['cleanup_confirmed'])
            self.assertTrue(launch.call_args.kwargs['start_new_session'])
            self.assertEqual(launch.call_args.args[0][0], str(root / 'bin/cargo'))
            self.assertEqual(launch.call_args.kwargs['env']['RUSTC'], str(root / 'bin/rustc'))

    def test_unconfirmed_cleanup_remains_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provision = types.SimpleNamespace(wait_for_leader=mock.Mock(return_value=types.SimpleNamespace(si_code=R.os.CLD_EXITED, si_status=0)), finish_group=mock.Mock(side_effect=RuntimeError('cleanup unconfirmed')))
            runner = R.Runner(root, root, root, root, provision)
            with mock.patch.object(R.subprocess, 'Popen', return_value=types.SimpleNamespace(pid=42)):
                with self.assertRaises(RuntimeError):
                    runner.command('synthetic', ['--version'])
            self.assertFalse(runner.records[0]['cleanup_confirmed'])

    def test_fixture_requires_exact_current_source_pins(self):
        source = Path('/fixed')
        packages = [dict(name='ctutils', version='0.4.5', source=None, manifest_path=str(source / 'third_party/rust/vendor/ctutils-0.4.5/Cargo.toml')),
                    dict(name='volparossa-ctutils-regressions', version='0.0.0', source=None),
                    dict(name='crypto-bigint', version='0.7.9', source=R.REGISTRY),
                    dict(name='p384', version='0.14.0', source=R.REGISTRY)]
        R.metadata_checks(dict(packages=packages), source, True)
        packages[2]['version'] = '0.7.10'
        with self.assertRaises(ValueError):
            R.metadata_checks(dict(packages=packages), source, True)

    def authority_fixture(self, directory, payload_error=None, changed_observations=False):
        prefix = Path(directory)
        (prefix / 'bin').mkdir()
        for name in ('rustc', 'cargo', 'rustdoc', 'clippy-driver', 'rustfmt'):
            (prefix / 'bin' / name).write_bytes(('inert fixture ' + name).encode())
        observations = {'rustc': 'fixed reviewed identity', 'cargo': 'fixed reviewed cargo'}
        receipt = json.dumps(dict(observed_versions=observations)).encode()
        order = []
        def validate(value):
            self.assertEqual(value['observed_versions'], observations)
            order.append('receipt')
        def verify(path, metadata):
            self.assertEqual(order, ['receipt'])
            self.assertEqual(path, prefix)
            order.append('payload')
            if payload_error:
                raise payload_error
        def observe(path):
            self.assertEqual(order, ['receipt', 'payload'])
            order.append('observe')
            return dict(observations, rustc='substituted identity') if changed_observations else observations
        provision = types.SimpleNamespace(validate_receipt=validate, pins=lambda: {'components': ['fixed']}, verify_payload=verify, observe=mock.Mock(side_effect=observe))
        return prefix, receipt, provision, order

    def test_valid_receipt_substituted_payload_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, receipt, provision, order = self.authority_fixture(directory, ValueError('substituted payload'))
            record = {}
            with self.assertRaisesRegex(ValueError, 'substituted payload'):
                R.compiler_authority(provision, prefix, receipt, record)
            provision.observe.assert_not_called()
            self.assertFalse(record['accepted'])
            self.assertFalse(record['payload_verified'])
            self.assertEqual(order, ['receipt', 'payload'])

    def test_valid_receipt_changed_observations_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, receipt, provision, order = self.authority_fixture(directory, changed_observations=True)
            record = {}
            with self.assertRaisesRegex(ValueError, 'observations changed'):
                R.compiler_authority(provision, prefix, receipt, record)
            self.assertTrue(record['payload_verified'])
            self.assertFalse(record['observations_match'])
            self.assertFalse(record['accepted'])
            self.assertEqual(order, ['receipt', 'payload', 'observe'])

    def test_verified_authority_binds_actual_bytes_and_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix, receipt, provision, order = self.authority_fixture(directory)
            record = {}
            R.compiler_authority(provision, prefix, receipt, record)
            self.assertTrue(record['accepted'])
            self.assertTrue(record['observations_match'])
            self.assertEqual(record['receipt_sha256'], R.sha(receipt))
            self.assertEqual(record['executable_sha256']['cargo'], R.sha(b'inert fixture cargo'))
            self.assertEqual(len(record['observations_sha256']), 64)
            self.assertEqual(order, ['receipt', 'payload', 'observe'])


if __name__ == '__main__':
    unittest.main()
