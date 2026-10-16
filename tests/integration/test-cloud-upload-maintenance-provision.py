#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert source/provision contracts. No downloads, applications or guest execution."""
import copy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'cloud-upload-maintenance-provision.py'))


def tools():
    return {name: dict(package=name, package_version='1.0-1', bytes=1234, sha256='a' * 64)
        for name in ('gpg', 'gpg-agent', 'gpgconf', 'tar')}


def receipt(profile_version=1):
    """Synthetic schema fixture, never a live provisioning result."""
    return dict(version=profile_version, kind='cloud-upload-maintenance-runtime-provision', success=True,
        pins=M['load_pins'](profile_version), pins_sha256=M['digest'](M['pins_path'](profile_version)), previous_consumer_provision_sha256='b' * 64,
        tools=tools(), **dict.fromkeys(M['TRUE_FLAGS'], True), **dict.fromkeys(M['FALSE_FLAGS'], False))


class UploadProvision(unittest.TestCase):
    def test_stream_profile_has_separate_closed_pins_with_same_runtime_and_inventory(self):
        old, new = M['load_pins'](), M['load_pins'](2)
        self.assertEqual(new['version'], 2)
        self.assertEqual(new['runtime'], old['runtime'])
        self.assertEqual(M['STREAM_REVISIONS'], dict(image='949f208dbb48fcb734d4dfd33eb1933b69830a01',
            cloud='7d10c4943062c5a0ae46fc57e293dc3e33db3ed2'))
        for name in ('image', 'cloud'):
            self.assertEqual(new['sources'][name]['revision'], M['STREAM_REVISIONS'][name])
            self.assertEqual(set(new['sources'][name]['files']), set(old['sources'][name]['files']))
        M['validate_provision'](receipt(2))
        for version in (True, 0, 6, '2'):
            with self.subTest(version=version), self.assertRaises(ValueError): M['load_pins'](version)
        for version, other in ((1, 2), (2, 1)):
            value = receipt(version)
            for change in ({'version': other}, {'pins': M['load_pins'](other)},
                    {'pins_sha256': M['digest'](M['pins_path'](other))}):
                with self.subTest(version=version, change=change), self.assertRaises(ValueError):
                    M['validate_provision']({**value, **change})

    def test_source_generation_rejects_wrong_prior_before_runtime_access(self):
        previous = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))
        for profile, prior in ((1, 6), (1, 7), (2, 5), (2, 7), (3, 5), (3, 6),
                (1, 8), (2, 8), (3, 8), (4, 5), (4, 6), (4, 7)):
            raw = json.dumps(previous['fixture'](profile_version=prior)['provision']).encode()
            with patch.dict(M['verify_shared_runtime'].__globals__, public_file=lambda *_: raw,
                    verify_files=Mock(side_effect=AssertionError('unexpected runtime access'))), self.assertRaises(ValueError):
                M['verify_shared_runtime'](M['load_pins'](profile), profile)

    def test_challenge_profile_pins_same_runtime_exact_adapter_and_distinct_upload_inventory(self):
        old, stream, new = (M['load_pins'](version) for version in (1, 2, 3))
        prior = M['PREVIOUS']['PROVISIONER']['load_pins'](7)
        self.assertEqual(new['version'], 3)
        self.assertEqual(new['runtime'], old['runtime'])
        self.assertEqual(new['runtime'], stream['runtime'])
        self.assertEqual(new['runtime'], prior['runtime'])
        self.assertEqual(M['CHALLENGE_REVISIONS'], dict(image='43029ea8b780de2376a3b7325d24a8e1c657f08e',
            cloud='e0db1cacf7bec2df3925ee454ec6216587b8ddef'))
        self.assertEqual([len(new['sources'][name]['files']) for name in ('image', 'cloud')], [3, 21])
        for name in ('image', 'cloud'):
            source = new['sources'][name]
            self.assertEqual(source['revision'], M['CHALLENGE_REVISIONS'][name])
            self.assertEqual(source['revision'], prior['sources'][name]['revision'])
            self.assertEqual(set(source['files']), set(stream['sources'][name]['files']))
            for path in source['files'].keys() & prior['sources'][name]['files'].keys():
                self.assertEqual(source['files'][path], prior['sources'][name]['files'][path])
        M['validate_provision'](receipt(3))
        for version in (1, 2, 3):
            for other in (1, 2, 3):
                if version == other: continue
                for change in ({'version': other}, {'pins': M['load_pins'](other)},
                        {'pins_sha256': M['digest'](M['pins_path'](other))}):
                    with self.subTest(version=version, other=other), self.assertRaises(ValueError):
                        M['validate_provision']({**receipt(version), **change})

    def test_exact_new_sources_keep_old_pins_paths_and_runtime(self):
        pins = M['load_pins']()
        old = M['PREVIOUS']['PROVISIONER']['load_pins']()
        self.assertEqual(pins['sources']['cloud']['revision'], 'cea181f1f80d57c9d8047093ed543f40ec43138d')
        self.assertEqual(pins['sources']['image']['revision'], 'eb9758453d094df5ea3ba045e993bd3d2dd47881')
        self.assertEqual(old['sources']['cloud']['revision'], '9cb94fbb83e9f503ff5a66d43ed814f556d4a3af')
        self.assertEqual(old['sources']['image']['revision'], 'aade424c3e96d0934edbddf31d2434757aa08564')
        self.assertEqual(pins['runtime'], old['runtime'])
        self.assertEqual([len(pins['sources'][n]['files']) for n in ('image', 'cloud')], [3, 21])
        self.assertTrue({'scripts/upload_lock.py', 'scripts/cloud-catalog.mjs', 'src/storage-upload-maintenance.mjs'}
            <= set(pins['sources']['cloud']['files']))
        self.assertEqual(set(M['SOURCES'].values()), {Path('/opt/volparossa-image-upload'), Path('/opt/volparossa-cloud-upload')})
        self.assertTrue(set(M['SOURCES'].values()).isdisjoint(M['PREVIOUS']['PROVISIONER']['SOURCES'].values()))
        for original, vendored in M['VENDORED'].items():
            self.assertEqual(pins['sources']['image']['files'][original], pins['sources']['cloud']['files'][vendored])

    def test_append_profile_binds_shared8_and_all_24_upload_files_without_changing_runtime(self):
        current = M['load_pins'](4)
        prior = M['PREVIOUS']['PROVISIONER']['load_pins'](8)
        self.assertEqual(M['APPEND_REVISIONS'], dict(image='10c46b9d6424929748e324fdd188a2f5ca77851a',
            cloud='dda7a21818ece774445cf63d6e9a01fe0f2803b2'))
        self.assertEqual([len(current['sources'][name]['files']) for name in ('image', 'cloud')], [3, 21])
        self.assertEqual(current['runtime'], prior['runtime'])
        for profile in (1, 2, 3):
            old = M['load_pins'](profile)
            self.assertEqual(current['runtime'], old['runtime'])
            for name in ('image', 'cloud'):
                self.assertEqual(set(current['sources'][name]['files']), set(old['sources'][name]['files']))
        for name in ('image', 'cloud'):
            self.assertEqual(current['sources'][name]['revision'], prior['sources'][name]['revision'])
            for path in current['sources'][name]['files'].keys() & prior['sources'][name]['files'].keys():
                self.assertEqual(current['sources'][name]['files'][path], prior['sources'][name]['files'][path])
        for profile in (1, 2, 3, 4):
            M['validate_provision'](receipt(profile))
            for other in (1, 2, 3, 4):
                if profile == other: continue
                for change in ({'version': other}, {'pins': M['load_pins'](other)},
                        {'pins_sha256': M['digest'](M['pins_path'](other))}):
                    with self.subTest(profile=profile, other=other), self.assertRaises(ValueError):
                        M['validate_provision']({**receipt(profile), **change})

    def test_changed_revision_inventory_runtime_and_adapter_rejected(self):
        original = M['load_pins']()
        changes = []
        for name in ('cloud', 'image'):
            value = copy.deepcopy(original); value['sources'][name]['revision'] = '0' * 40; changes.append(value)
        value = copy.deepcopy(original); value['version'] = True; changes.append(value)
        value = copy.deepcopy(original); value['runtime']['version'] = '24.20.0'; changes.append(value)
        value = copy.deepcopy(original); del value['sources']['cloud']['files']['scripts/upload_lock.py']; changes.append(value)
        value = copy.deepcopy(original); value['sources']['cloud']['files']['../extra'] = dict(bytes=1, sha256='0' * 64); changes.append(value)
        value = copy.deepcopy(original)
        value['sources']['cloud']['files']['vendor/volparossa-image/core-storage.mjs']['sha256'] = '0' * 64
        changes.append(value)
        for value in changes:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'pins.json'; path.write_text(json.dumps(value))
                with patch.dict(M['load_pins'].__globals__, PINS=path), self.assertRaises(ValueError):
                    M['load_pins']()

    def test_flow_profile_binds_shared9_current_finite_sources_and_rejects_all_other_generations(self):
        current = M['load_pins'](5)
        prior = M['PREVIOUS']['PROVISIONER']['load_pins'](9)
        self.assertEqual(M['FLOW_REVISIONS'], dict(image='9694a2b9dcb40aceefd78dbc0ab34303071a0ffd',
            cloud='47b0f03b84913761570c3de7037ba5509b848c23'))
        self.assertEqual([len(current['sources'][name]['files']) for name in ('image', 'cloud')], [3, 21])
        self.assertEqual(current['runtime'], prior['runtime'])
        for name in ('image', 'cloud'):
            self.assertEqual(current['sources'][name]['revision'], prior['sources'][name]['revision'])
            for path in current['sources'][name]['files'].keys() & prior['sources'][name]['files'].keys():
                self.assertEqual(current['sources'][name]['files'][path], prior['sources'][name]['files'][path])
        previous = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))
        for profile in (1, 2, 3, 4, 5):
            M['validate_provision'](receipt(profile))
            self.assertEqual(M['load_pins'](profile)['runtime'], current['runtime'])
            for other in (1, 2, 3, 4, 5):
                if profile == other: continue
                for change in ({'version': other}, {'pins': M['load_pins'](other)},
                        {'pins_sha256': M['digest'](M['pins_path'](other))}):
                    with self.subTest(profile=profile, other=other), self.assertRaises(ValueError):
                        M['validate_provision']({**receipt(profile), **change})
            for shared in ((1, 2, 3, 4, 5, 6, 7, 8) if profile == 5 else (9,)):
                raw = json.dumps(previous['fixture'](profile_version=shared)['provision']).encode()
                with patch.dict(M['verify_shared_runtime'].__globals__, public_file=lambda *_: raw,
                        verify_files=Mock(side_effect=AssertionError('unexpected runtime access'))), self.assertRaises(ValueError):
                    M['verify_shared_runtime'](M['load_pins'](profile), profile)

    def test_closed_provision_does_not_claim_application_or_network_success(self):
        good = receipt()
        M['validate_provision'](good)
        for change in ({'version': True}, {'previous_consumer_provision_sha256': 'private-path'},
                {'peer_storage_proven': True}, {'storage_enrollment_created': True},
                {'sdk_or_browser_provisioned': True}, {'runtime_reused_without_modification': False},
                {'success': False}, {'raw_output': 'not-exportable'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                M['validate_provision']({**good, **change})

    def test_developer_host_guard_fails_before_subprocess_or_network(self):
        function = M['guard']
        with patch.object(function.__globals__['os'], 'geteuid', return_value=0), \
                patch.object(function.__globals__['socket'], 'gethostname', return_value='developer-host'), \
                patch.object(function.__globals__['subprocess'], 'check_output') as command:
            with self.assertRaises(ValueError): function()
            command.assert_not_called()

    def test_reused_receipt_requires_original_closed_success(self):
        original = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))['fixture']()['provision']
        for change in ({'success': False}, {'runtime_files_verified': False}, {'raw_output': 'not-exportable'}):
            raw = json.dumps({**original, **change}).encode()
            with patch.dict(M['verify_shared_runtime'].__globals__, public_file=lambda *_: raw), self.assertRaises(ValueError):
                M['verify_shared_runtime'](M['load_pins']())

    def test_public_receipt_rejects_symlink_fifo_and_group_or_other_writable_mode(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ordinary = root / 'ordinary'; ordinary.write_text('{}'); ordinary.chmod(0o666)
            link = root / 'link'; link.symlink_to(ordinary)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            for path in (ordinary, link, fifo):
                with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                    M['public_file'](path, 8192)

    def test_orchestration_only_fetches_new_sources_and_never_exposes_or_replaces_shared_runtime(self):
        # Fake I/O exercises orchestration only; no materialized-code/run claim.
        pins = M['load_pins']()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = {name: root / name for name in M['SOURCES']}
            output = root / 'receipt'
            fetched, exposed = [], []
            loader = M['BASE']['loader']()
            base = {**M['BASE'], 'loader': lambda: {**loader, 'fetch': lambda *args: fetched.append(args)},
                'tool_receipts': tools, 'expose': lambda path: exposed.append(path)}
            verify_runtime = Mock(return_value='b' * 64)
            before = M['PINS'].read_bytes()
            with patch.dict(M['provision'].__globals__, BASE=base, SOURCES=sources, RECEIPT=output,
                    guard=lambda: None, verify_shared_runtime=verify_runtime, verify_files=lambda *_: None,
                    verify_vendor=lambda *_: None):
                report = M['provision']()
            self.assertEqual(report, receipt())
            self.assertEqual(json.loads((output / 'provision.json').read_bytes()), report)
            self.assertEqual(verify_runtime.call_count, 2)
            self.assertEqual(len(fetched), 24)
            self.assertEqual(set(exposed), {*sources.values(), output})
            self.assertNotIn(M['RUNTIME'], exposed)
            for url, target, record in fetched:
                source_name = next(name for name, path in sources.items() if target.is_relative_to(path))
                relative = str(target.relative_to(sources[source_name]))
                self.assertEqual(url, f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-{source_name}/{M['REVISIONS'][source_name]}/{relative}")
                self.assertEqual(record, pins['sources'][source_name]['files'][relative])
            self.assertEqual(M['PINS'].read_bytes(), before)

    def test_explicit_download_flag_is_mandatory(self):
        result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-provision.py'),
            'provision'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--download', result.stderr)


if __name__ == '__main__':
    unittest.main()
