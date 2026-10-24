#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert compiler authority, extraction and execution-location regression tests."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch, MagicMock

SPEC = importlib.util.spec_from_file_location('compiler', Path(__file__).with_name('provision-rust199.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def receipt():
    return dict(schema_version=1, profile=M.PROFILE, manifest_sha256=M.MANIFEST_SHA256,
                components=M.pins()['components'], observed_versions={
                    'rustc': 'rustc 1.99.1 (58cf8f9c3 2026-10-13)\nrelease: 1.99.1\n',
                    'cargo': 'cargo 1.99.1 (5f94df478 2026-08-27)\nrelease: 1.99.1\n',
                    'rustfmt': 'rustfmt 1.10.0 (fixture)\n',
                    'clippy-driver': 'clippy 0.1.99 (fixture)\n'})


class CompilerTests(unittest.TestCase):
    def test_six_reviewed_components_and_receipt(self):
        M.validate_receipt(receipt())
        self.assertEqual(len(M.pins()['components']), 6)
        self.assertEqual({c['target'] for c in M.pins()['components']},
                         {'x86_64-unknown-linux-gnu', 'i686-unknown-linux-musl'})

    def test_profile_archive_authority_and_observations_fail_closed(self):
        for mutation in ('profile', 'manifest', 'archive', 'missing', 'rustc', 'cargo', 'extra'):
            value = receipt()
            if mutation == 'profile': value['profile'] = 'stable'
            elif mutation == 'manifest': value['manifest_sha256'] = 'a' * 64
            elif mutation == 'archive': value['components'][0]['xz_sha256'] = 'b' * 64
            elif mutation == 'missing': value['components'].pop()
            elif mutation == 'extra': value['caller_expected_hash'] = 'c' * 64
            else: value['observed_versions'][mutation] = 'unreviewed compiler\n'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                M.validate_receipt(value)

    def test_manifest_cargo_version_is_not_assumed_to_be_executable_version(self):
        self.assertTrue(M.pins()['components'][1]['version'].startswith('0.100.0'))
        M.validate_receipt(receipt())

    def test_host_rejected_before_network_or_installation(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(M.urllib.request, 'urlopen', side_effect=AssertionError('network')), \
             patch.object(M.subprocess, 'run', side_effect=AssertionError('execution')), \
             patch.object(M.subprocess, 'check_output', return_value='none\n'):
            with self.assertRaises(ValueError): M.provision('runner')
            with self.assertRaises(ValueError): M.provision('guest')

    def test_archive_mismatch_rejected(self):
        component = M.pins()['components'][0]
        response = io.BytesIO(b'not the reviewed compiler')
        response.geturl = lambda: component['xz_url']
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(M.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'digest'):
                M.download(component, Path(directory) / 'archive')

    def test_unsafe_archive_paths_and_links_rejected(self):
        for name, link in [('../escape', None), ('/escape', None), ('root/link', '/escape')]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / 'input.tar'
                with tarfile.open(archive, 'w') as output:
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type = tarfile.SYMTYPE
                        member.linkname = link
                    output.addfile(member)
                with self.assertRaises((ValueError, tarfile.TarError)):
                    M.extract(archive, Path(directory) / 'out')

    def test_existing_prefix_is_not_replaced_or_deleted_on_bad_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / M.PREFIX_NAME
            prefix.mkdir(); (prefix / 'receipt.json').write_text('{}')
            with patch.object(M, 'location', return_value=prefix), \
                 patch.object(M, 'download', side_effect=AssertionError('network')):
                with self.assertRaises(ValueError): M.provision('runner')
            self.assertTrue(prefix.is_dir())

    def test_interrupted_installer_group_is_reaped_before_cleanup(self):
        child = MagicMock(pid=4242)
        child.wait.side_effect = [KeyboardInterrupt(), 0]
        with patch.object(M.subprocess, 'Popen', return_value=child), \
             patch.object(M.os, 'killpg') as kill:
            with self.assertRaises(KeyboardInterrupt):
                M.install_component(Path('/inert/source'), Path('/inert/prefix'))
        kill.assert_called_once_with(4242, M.signal.SIGTERM)
        self.assertEqual(child.wait.call_count, 2)

    def test_offline_guest_check_never_installs_missing_compiler(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(M, 'location', return_value=Path(directory) / 'absent'), \
             patch.object(M, 'download', side_effect=AssertionError('network')):
            with self.assertRaisesRegex(ValueError, 'not been provisioned'):
                M.provision('guest-check')


if __name__ == '__main__': unittest.main()
