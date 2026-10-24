#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-trial authority/data/wiring regressions; never execute decoder or package tools."""
import copy
import json
import os
from pathlib import Path
import runpy
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

H = runpy.run_path(str(Path(__file__).with_name('weather-decoder-abi.py')))
G = H['execute'].__globals__


def payload(root):
    record, _ = H['source_trial_record']()
    record = copy.deepcopy(record)
    root.mkdir(mode=0o700)
    binary = bytearray(64); binary[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', binary, 16, 3, 62)
    files = {name: (bytes(binary) if name == H['DECODER'] else ('inert ' + name).encode())
             for name in record['files']}
    files['build-manifest.json'] = b'{"inert":true}\n'
    record['files'] = {name: dict(bytes=len(raw), sha256=H['digest'](raw),
        mode=0o500 if name in {H['DECODER'], 'eccodes-build/bin/grib_filter', 'eccodes-build/bin/codes_info'} else 0o400)
        for name, raw in files.items()}
    record['bytes'] = sum(map(len, files.values()))
    record['build_manifest'] = {k: record['files']['build-manifest.json'][k] for k in ('bytes', 'sha256')}
    for name, raw in files.items():
        path = root / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in path.parents:
            if parent.is_relative_to(root): parent.chmod(0o700)
        H['write_new'](path, raw, record['files'][name]['mode'])
    return record, files


class SourceTrial(unittest.TestCase):
    def test_fixed_record_binds_reviewed_pair_and_all14_files_without_final_admission(self):
        value, sha = H['source_trial_record']()
        self.assertEqual(sha, H['SOURCE_TRIAL_RECORD_SHA256'])
        self.assertEqual((len(value['files']), value['bytes']), (14, 93841627))
        self.assertEqual([x['id'] for x in value['evidence']['runs']], [40057456323, 40057858381])
        self.assertFalse(value['scope']['abi_proven']); self.assertFalse(value['scope']['production_decoder_authorized'])
        self.assertNotIn(H['RECEIPT'], value['files'])

    def test_missing_changed_candidate_wrong_profile_and_all7_old_artifact_ids_fail_closed(self):
        original, _ = H['source_trial_record']()
        mutations = [lambda x: x.update(schema=2), lambda x: x.update(profile='historical-v1'),
            lambda x: x.update(id='weather-decoder-source-20261024-v1'), lambda x: x.update(admitted=True),
            lambda x: x.update(weather_commit='a' * 40), lambda x: x.update(environment_lock_sha256='0' * 64),
            lambda x: x['source_files'].pop('scripts/prepare_hosted_decoder.py'),
            lambda x: x['source_archives'][0].update(sha256='0' * 64),
            lambda x: x['files'].pop('ecbuild-source/NOTICE'),
            lambda x: x['scope'].update(abi_trial_inputs_authorized=False)]
        for old in (11731895956, 11732430773, 11732188075, 11735448641, 11735263794, 11741150955, 11741385637):
            mutations.append(lambda x, old=old: x['evidence']['runs'][0].update(artifact_id=old))
        with tempfile.TemporaryDirectory() as directory, patch.object(H['subprocess'], 'Popen', side_effect=AssertionError('execute')):
            path = Path(directory) / 'trial'
            with patch.dict(G, SOURCE_TRIAL_RECORD=path):
                with self.assertRaises(FileNotFoundError): H['source_trial_record']()
                for mutate in mutations:
                    value = copy.deepcopy(original); mutate(value)
                    path.write_text(json.dumps(value)); path.chmod(0o600)
                    with self.assertRaisesRegex(ValueError, 'SOURCE_TRIAL_RECORD_CHANGED'): H['source_trial_record']()

    def test_entire_payload_stages_with_exact_modes_and_rejects_every_changed_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); record, files = payload(root / 'payload')
            with patch.dict(G, source_trial_record=lambda: (record, 'a' * 64)):
                H['stage_source_trial_inputs'](root / 'payload', root / 'staged')
                self.assertEqual(H['verify_source_trial_inputs'](root / 'staged')[2], files)
                for name in files:
                    path = root / 'payload' / name; path.chmod(0o600); path.write_bytes(b'corrupt')
                    with self.subTest(name=name), self.assertRaises(ValueError): H['verify_source_trial_inputs'](root / 'payload')
                    path.write_bytes(files[name]); path.chmod(record['files'][name]['mode'])

    def test_extra_missing_wrong_mode_and_linked_inputs_never_execute(self):
        for mutation in ('extra', 'empty-directory', 'missing', 'mode', 'symlink', 'hardlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); record, _ = payload(root / 'payload'); path = root / 'payload/probe.grib2'
                if mutation == 'extra': H['write_new'](root / 'payload/extra', b'extra')
                elif mutation == 'empty-directory': (root / 'payload/unexpected').mkdir()
                elif mutation == 'missing': path.unlink()
                elif mutation == 'mode': path.chmod(0o500)
                elif mutation == 'symlink': path.unlink(); path.symlink_to(root / 'payload/build-manifest.json')
                elif mutation == 'hardlink': os.link(path, root / 'outside')
                with patch.dict(G, source_trial_record=lambda: (record, 'a' * 64)), \
                     patch.object(H['subprocess'], 'Popen', side_effect=AssertionError('execute')):
                    with self.assertRaises((OSError, ValueError)): H['verify_source_trial_inputs'](root / 'payload')

    def test_fresh_build_manifest_must_match_raw_reviewed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); record, _ = payload(root / 'payload'); output = root / 'output'; output.mkdir()
            manifest = dict(files=record['files'], bytes=record['bytes'], environment_lock_sha256=H['SOURCE_ENVIRONMENT_SHA256'])
            raw = json.dumps(manifest).encode(); record['payload_manifest'] = dict(bytes=len(raw), sha256=H['digest'](raw))
            H['write_new'](output / 'payload-manifest.json', raw)
            with patch.dict(G, source_trial_record=lambda: (record, 'a' * 64)):
                H['verify_source_trial_build'](output, root / 'payload')
                (output / 'payload-manifest.json').write_bytes(raw + b' ')
                with self.assertRaisesRegex(ValueError, 'SOURCE_TRIAL_BUILD_MANIFEST'):
                    H['verify_source_trial_build'](output, root / 'payload')

    def simulated_execute(self, root, changed=False):
        record, files = payload(root / 'payload')
        class Commands:
            drained = True
            def run(self, argv, _deadline):
                if '-c' in argv: return 0, json.dumps(dict(uid=os.geteuid(), network_namespace='net:[0]', isolated=True)).encode()
                if '/usr/bin/readelf' in argv: return 0, b'inert ELF metadata'
                if '-V' in argv: return 0, b'ecCodes Version 2.44.0\n'
                first = '60,0,1' in argv
                if changed and not first:
                    path = root / 'payload/ecbuild-source/NOTICE'; path.chmod(0o600); path.write_bytes(b'changed unused notice')
                value = [dict(keys=dict(edition=2, packingType='grid_ccsds', bitsPerValue=16, numberOfPoints=496),
                    method='nearest', neighbours=[dict(latitude=60 if first else 0, longitude=0 if first else 30,
                    value=0 if first else 495, distance=0, distance_unit='km')])]
                return 0, json.dumps(value).encode()
        with patch.dict(G, source_trial_record=lambda: (record, 'a' * 64), Commands=Commands,
                        guest_boundary=lambda _: {'inert': True}):
            return H['execute'](root / 'payload', root / 'output', 'b' * 40, profile='source-v1')

    def test_shared_execute_has_no_historical_receipt_and_rechecks_unused_notice(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                value = self.simulated_execute(Path(directory), changed)
                self.assertEqual(value['success'], not changed)
                self.assertEqual(value['kind'], 'weather-decoder-source-trial-abi')
                self.assertEqual(len(value['inputs']), 14)
                self.assertNotIn('admission_sha256', value); self.assertNotIn('hosted_run', value)
                self.assertTrue(all(value['cleanup'].values()))

    def test_abi_tools_loader_and_libraries_use_locked_authority_without_compiler_execution(self):
        names = {'libc6', 'libstdc++6', 'libgcc-s1', 'libc-bin', 'bubblewrap', 'binutils', 'util-linux', 'python3'}
        environment = dict(environment_lock_sha256=H['SOURCE_ENVIRONMENT_SHA256'], inventory=[{'name': n} for n in names])
        binder = Mock(return_value={'bound': True}); development = Mock(return_value='d' * 64)
        helper = dict(check_environment=lambda: environment, verify_development_files=development, bind_tools=binder)
        with patch.dict(G, source_helper=lambda _: helper, source_builder=lambda _: {'tool_record': lambda p: {'path': p}}):
            result = H['source_trial_environment']()
        self.assertEqual(set(binder.call_args.args[0]), {'readelf', 'python', 'bwrap', 'prlimit', 'loader'})
        self.assertEqual(result['development_files_sha256'], 'd' * 64)
        development.assert_called_once_with(environment)
        binder.side_effect = ValueError('TOOL_PACKAGE_BYTES')
        with patch.dict(G, source_helper=lambda _: helper, source_builder=lambda _: {'tool_record': lambda p: {'path': p}}):
            with self.assertRaisesRegex(ValueError, 'TOOL_PACKAGE_BYTES'): H['source_trial_environment']()

    def test_second_guest_prepares_same_lock_no_build_and_checks_environment_after_failure(self):
        for change, abi_success in ((False, True), (True, True), (False, False)):
            with self.subTest(change=change, abi_success=abi_success), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); calls = []; snapshots = Mock(side_effect=[{'fixed': True}, {'fixed': not change}])
                def prepare(_commit, **kw):
                    self.assertEqual(kw, {'build_mode': True}); calls.append('prepare'); (root / 'env').mkdir()
                executor = Mock(return_value=dict(success=abi_success, cleanup=dict(process_drain_confirmed=True)))
                verifier = Mock(return_value=({'fixed-record': True}, 'a' * 64, {}))
                with patch.dict(G, inventory_boundary=lambda _: None, source_files=lambda _: {}, source_inventory=prepare,
                    source_trial_record=lambda: ({'fixed-record': True}, 'a' * 64), verify_source_trial_inputs=verifier,
                    source_trial_environment=snapshots, execute=executor, INVENTORY_ROOT=root / 'env',
                    source_helper=lambda _: {}, load_source_lock=lambda _: ({}, H['SOURCE_ENVIRONMENT_SHA256']),
                    source_cold_build=Mock(side_effect=AssertionError('no compilation B'))):
                    if change or not abi_success:
                        with self.assertRaises(ValueError): H['source_trial']('b' * 40)
                    else: self.assertTrue(H['source_trial']('b' * 40)['success'])
                self.assertEqual(calls, ['prepare']); self.assertEqual(snapshots.call_count, 2)
                self.assertEqual(executor.call_args.kwargs, {'profile': 'source-v1'})
                report = json.loads((root / 'env/source-trial-report.json').read_bytes())
                self.assertEqual(report['success'], not change and abi_success)
                self.assertFalse(report['compiled_in_abi_guest'])

    def test_changed_lock_fails_before_package_install_or_execution(self):
        installer = Mock(side_effect=AssertionError('install'))
        executor = Mock(side_effect=AssertionError('execute'))
        with patch.dict(G, inventory_boundary=lambda _: None, source_files=lambda _: {},
            verify_source_trial_inputs=lambda _: ({}, 'a' * 64, {}), source_helper=lambda _: {},
            load_source_lock=lambda _: ({}, '0' * 64), source_inventory=installer, execute=executor):
            with self.assertRaisesRegex(ValueError, 'SOURCE_TRIAL_ENVIRONMENT_LOCK'): H['source_trial']('b' * 40)
        installer.assert_not_called(); executor.assert_not_called()

    def test_public_projection_excludes_every_payload_member_and_accepts_only_closed_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.mkdir(mode=0o700)
            H['write_new'](source / 'source-trial-report.json', b'{"success":false}')
            H['write_new'](source / 'decoder.elf', b'\x7fELFprivate payload')
            H['write_new'](source / 'secret.key', b'PRIVATE RUNNER STATE')
            H['stage_source_trial_public'](source, root / 'public')
            self.assertEqual({p.name for p in (root / 'public').iterdir()}, {'source-trial-report.json', 'inventory-public-export.json'})
            H['write_new'](source / 'source-abi-version.log', b'\x7fELFnot-text')
            with self.assertRaisesRegex(ValueError, 'SOURCE_TRIAL_PUBLIC_BINARY'):
                H['stage_source_trial_public'](source, root / 'rejected')


if __name__ == '__main__': unittest.main()
