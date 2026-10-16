#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert closed-contract tests, not Cloud/core/network acceptance evidence."""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'cloud-upload-maintenance-smoke.py'))
G = M['main'].__globals__
PROVISION = 'a' * 64


def identity(index):
    return dict(fragment=index, authorization_sha256=str(index + 1) * 64, copy_identity_sha256=str(index + 2) * 64)


def report(phase, retired=()):
    size = 800001
    value = dict(version=1, kind='cloud-upload-maintenance', phase=phase, passed=True,
        provision_sha256=PROVISION, scope=dict(M['SCOPE']),
        plaintext_bytes=M['PLAIN_BYTES'], plaintext_sha256=M['fixture_hash']())
    if phase == 'prepare':
        return dict(value, catalog_files=0, catalog_encrypted=True)
    value.update(cipher_bytes=size, cipher_sha256='b' * 64, fragment_bytes=M['FRAGMENT'],
        authority=dict(expires_at=2000000000, maximum_charged_bytes=3 * M['MAX_CIPHER'],
            intent_sha256='c' * 64, enrollment_sha256='d' * 64, config_sha256='e' * 64, root_sha256='f' * 64))
    baseline = dict(version=1, retired_original_a=list(retired), replacement_identities=[identity(i) for i in retired],
        physical_payload_charge=2 * size, pending_retirements=0, retained_copy_records=8 + len(retired))
    committed = 0 if phase == 'finish' else 2 * size
    uncertain = sum(M['geometry'](size)[i] for i in (0, 2, 3) if i not in retired) if phase == 'exercise' else 0
    value['accounting'] = dict(logical_ciphertext_bytes=size, committed_payload_bytes=committed,
        uncertain_payload_bytes=uncertain, physical_payload_charge_upper_bound=committed + uncertain,
        fragment_count=4, copies_per_fragment=2, retained_copy_records=8 + len(retired) if phase == 'upload' else 11,
        pending_retirements=0 if phase == 'upload' else 3 - len(retired))
    if phase == 'upload':
        value.update(baseline=baseline, http_put_status=201, wrong_token_status=401, automatic_enrollment=True,
            ready_observed=True, owned_session_observed=True, ordering_source_enforced=True,
            io_ordering_measured=False, owner_joined=True)
    elif phase == 'exercise':
        read = dict(authenticated_get_body_verified=True, cipher_cache_absent_before_read=True,
            plaintext_bytes=M['PLAIN_BYTES'], plaintext_sha256=M['fixture_hash'](), wrong_token_status=401,
            owned_session_observed=True, owner_joined=True)
        value.update(baseline=baseline, repair_replacement_identities=[identity(i) for i in (0, 2, 3)],
            new_replacements_after_withdrawal=3 - len(retired), reads=[dict(read), dict(read)],
            service_restarted_between_reads=True, original_authority_and_journals_retained=True)
    else:
        value.update(all_retained_copies_delete_acknowledged=True, owner_joined=True, private_fixture_removed=False)
    return value


def write(path, value):
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)


class Contract(unittest.TestCase):
    def test_four_phases_with_zero_one_or_two_real_prewithdrawal_replacements(self):
        M['validate_node_report'](report('prepare'), 'prepare', PROVISION)
        for retired in ((), (0,), (2,), (3,), (0, 2), (0, 3), (2, 3)):
            upload = report('upload', retired)
            for phase in ('upload', 'exercise', 'finish'):
                value = report(phase, retired)
                self.assertEqual(M['validate_node_report'](value, phase, PROVISION, upload), value)
        self.assertEqual(M['FLOW_MINIMUM'], dict(upload=24, exercise=16, finish=11))

    def test_fixed_fragment_geometry_never_reuses_old_ceil_by_four(self):
        self.assertEqual(M['geometry'](800001), [262144, 262144, 262144, 13569])
        for invalid in (True, 3 * 262144, 1048577):
            with self.assertRaises(ValueError):
                M['geometry'](invalid)

    def test_finish_counts_only_requests_not_previously_acknowledged_deletes(self):
        for retired in ((), (0,), (0, 2)):
            uploaded = report('upload', retired)
            self.assertEqual(M['flow_minimum']('finish', uploaded), 11 - len(retired))
            self.assertEqual(M['flow_minimum']('upload', uploaded), 24)
            self.assertEqual(M['flow_minimum']('exercise', uploaded), 16)
        with self.assertRaises(ValueError):
            M['flow_minimum']('finish')
        with self.assertRaises(ValueError):
            M['flow_minimum']('finish', report('upload', (0, 2, 3)))

    def test_minimum_cli_upload_needs_no_future_receipt_finish_uses_original_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(M['OLD'], guard=lambda: None), patch.dict(G, owner_root=lambda *a: root):
                output = io.StringIO()
                with redirect_stdout(output):
                    M['main'](['flow-minimum', 'upload', str(root)])
                self.assertEqual(output.getvalue(), '24\n')
                with self.assertRaises(FileNotFoundError):
                    M['main'](['flow-minimum', 'finish', str(root)])
                for retired in ((), (0,), (0, 2)):
                    write(root / 'cloud-upload-upload.json', report('upload', retired))
                    output = io.StringIO()
                    with redirect_stdout(output):
                        M['main'](['flow-minimum', 'finish', str(root)])
                    self.assertEqual(output.getvalue(), str(11 - len(retired)) + '\n')

    def test_closed_scope_auth_actual_upload_and_unmeasured_ordering(self):
        cases = [lambda v: v.update(private_path='/key'), lambda v: v.update(version=True),
            lambda v: v.update(provision_sha256='0' * 64), lambda v: v.update(http_put_status=200),
            lambda v: v.update(wrong_token_status=200), lambda v: v.update(automatic_enrollment=False),
            lambda v: v.update(io_ordering_measured=True), lambda v: v.update(owner_joined=False),
            lambda v: v['scope'].update(protected_routes_independently_proven=True),
            lambda v: v['authority'].update(maximum_charged_bytes=1),
            lambda v: v['baseline'].update(retired_original_a=[0, 2, 3]),
            lambda v: v['baseline'].update(retired_original_a=[True]),
            lambda v: v['baseline'].update(retained_copy_records=9)]
        for mutate in cases:
            value = report('upload')
            mutate(value)
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'upload', PROVISION)

    def test_original_authority_identities_and_cold_restore_cannot_be_replaced(self):
        cases = [lambda v: v['authority'].update(expires_at=2000000001),
            lambda v: v.update(cipher_sha256='0' * 64),
            lambda v: v['repair_replacement_identities'][0].update(authorization_sha256='0' * 64),
            lambda v: v.update(new_replacements_after_withdrawal=3),
            lambda v: v['accounting'].update(uncertain_payload_bytes=0),
            lambda v: v['reads'][1].update(cipher_cache_absent_before_read=False),
            lambda v: v['reads'][1].update(plaintext_bytes=True),
            lambda v: v.update(service_restarted_between_reads=False),
            lambda v: v['accounting'].update(retained_copy_records=8)]
        for mutate in cases:
            value = report('exercise', (0,))
            mutate(value)
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'exercise', PROVISION, report('upload', (0,)))

    def test_all_eleven_deletes_zero_charge_is_not_remote_or_private_cleanup(self):
        for key, replacement in [('committed_payload_bytes', 1), ('retained_copy_records', 8), ('pending_retirements', 0)]:
            value = report('finish', (0, 2))
            value['accounting'][key] = replacement
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'finish', PROVISION, report('upload', (0, 2)))
        value = report('finish')
        value['private_fixture_removed'] = True
        with self.assertRaises(ValueError):
            M['validate_node_report'](value, 'finish', PROVISION, report('upload'))

    def test_prepare_rejects_implicit_seed_and_missing_encryption(self):
        for key, replacement in [('catalog_files', 1), ('catalog_files', False), ('catalog_encrypted', False)]:
            value = report('prepare')
            value[key] = replacement
            with self.assertRaises(ValueError):
                M['validate_node_report'](value, 'prepare', PROVISION)

    def test_failure_preserves_closed_original_not_private_stderr(self):
        failed = dict(version=1, kind='cloud-upload-maintenance', phase='upload', passed=False,
            provision_sha256=PROVISION, stage='upload_put', code='application_failed', cleanup_confirmed=False)
        raw = json.dumps(failed).encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write(root / 'cloud-upload-upload.json', raw)
            with patch.dict(G, run_child=lambda *a: (1, raw, b'PRIVATE_TOKEN')):
                with self.assertRaises(M['NodePhaseFailure']) as caught:
                    M['node_phase'](root, 'upload', PROVISION, time.monotonic() + 1)
            self.assertEqual(caught.exception.report['node'], failed)
            self.assertEqual(caught.exception.report['node_report_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))
        for field in ('stage', 'code'):
            wrong = dict(failed, **{field: '/private/token'})
            with self.assertRaises(ValueError):
                M['validate_node_report'](wrong, 'upload', PROVISION)

    def test_failure_vocabulary_matches_actual_driver_without_executing_it(self):
        source = (HERE / 'cloud-upload-maintenance.mjs').read_text()
        codes = re.search(r'const CODES = new Set\(\[(.*?)\]\);', source, re.S).group(1)
        self.assertEqual(set(re.findall(r"'([a-z_]+)'", codes)) | {'application_failed'}, M['FAILURE_CODES'])
        assignments = re.findall(r"ctx.stage = (.*?);", source)
        stages = {name for value in assignments for name in re.findall(r"'([a-z_]+)'", value)} | {'phase_start'}
        self.assertEqual(stages, M['FAILURE_STAGES'])


class Orchestration(unittest.TestCase):
    def test_dynamic_phase_uses_policy_sampler_exact_underlay_and_closed_failure(self):
        from contextlib import contextmanager
        current = runpy.run_path(str(HERE / 'test-cloud-upload-maintenance-evidence.py'))['fixture'](network_version=2)
        network = current['network']['upload']
        sampler = runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py'))
        calls, writes, fail = [], {}, [False]
        root = Path('/inert/work/u/a')
        client = root.parents[1] / 'runtime-client/control/agent.sock'
        @contextmanager
        def capture(binary, socket, baseline, minimum, **kwargs):
            calls.append((binary, socket, baseline, minimum, kwargs))
            if fail[0]:
                kwargs['diagnostic'].update(version=1, kind='consumer-route-sampler-failure', phase='initial',
                    operation='paths_before', code='process', samples=0, completed=0, failed=0)
                raise sampler['OLD']['SamplerFailure']('PRIVATE_DO_NOT_EXPORT')
            class Coverage:
                joined = True
                def report(self, *, joined):
                    return copy.deepcopy(network['gates'])
            yield Coverage()
        sampler['capture'] = capture
        digest = hashlib.sha256(b'{}').hexdigest()
        prepared = dict(phase='prepare', passed=True, provision_sha256=PROVISION,
            authority=dict(service_config_sha256=digest, storage_template_sha256=digest,
                policy_expires_at=2000000000))
        def read(path):
            return prepared if path.name == 'cloud-upload-prepared.json' else dict(coreBinary='/inert/core', controlSocket=str(client))
        env = dict(STORAGE_PROOF_BASELINE_MS=str(network['gates']['event_baseline_unix_ms']),
            STORAGE_PROOF_ROUTE_POLICY=json.dumps(network['layout']['route_policy']),
            STORAGE_PROOF_UNDERLAY_SHA256=network['layout']['control_underlay_sha256'])
        with patch.dict(os.environ, env, clear=True), \
                patch.dict(M['OLD'], validate_locations=lambda *args: (Path('/inert/core'), client)), \
                patch.dict(G, private_json=read, file_bytes=lambda *a: b'{}', private_directory=lambda *a: None,
                    node_phase=lambda *a: (report('upload'), 'b' * 64),
                    write_json=lambda path, value: writes.update({path.name: value})), \
                patch.object(M['runpy'], 'run_path', return_value=sampler):
            result = M['phase'](root, 'upload', root.parents[1] / 'runtime-exit/control/agent.sock',
                root.parents[1] / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 30,
                network_version=2)
            self.assertEqual((result['version'], result['network_version']), (2, 2))
            self.assertEqual(result['control_underlay_sha256'], env['STORAGE_PROOF_UNDERLAY_SHA256'])
            self.assertEqual(calls[0][3], 24)
            self.assertEqual(calls[0][4]['policy'], network['layout']['route_policy'])
            self.assertNotIn('scope', calls[0][4])
            self.assertEqual(writes['flow-cloud-upload-upload.json']['exit_log_sampling_version'], 3)
            fail[0] = True
            with self.assertRaises(M['NetworkPhaseFailure']) as caught:
                M['phase'](root, 'upload', root.parents[1] / 'runtime-exit/control/agent.sock',
                    root.parents[1] / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 30,
                    network_version=2)
            self.assertFalse(caught.exception.report['passed'])
            self.assertEqual(caught.exception.report['sampler']['operation'], 'paths_before')
            self.assertNotIn('PRIVATE', json.dumps(caught.exception.report))
            env['STORAGE_PROOF_UNDERLAY_SHA256'] = '/private/identity'
            with patch.dict(os.environ, env), self.assertRaisesRegex(ValueError, 'control_underlay_hash'):
                M['phase'](root, 'upload', root.parents[1] / 'runtime-exit/control/agent.sock',
                    root.parents[1] / 'client-fixtures/private-storage-user', PROVISION, time.monotonic() + 30,
                    network_version=2)

    def test_explicit_network_cli_keeps_historical_default_and_rejects_unknown_profile(self):
        root = Path('/inert/root')
        calls = []
        with patch.dict(M['OLD'], guard=lambda: None), patch.dict(G, owner_root=lambda *a, **k: root,
                tools=lambda: PROVISION, phase=lambda *a, **kw: calls.append(kw) or {'passed': False}):
            for suffix in ([], ['--network-version', '2']):
                with redirect_stdout(io.StringIO()):
                    M['main'](['upload', str(root), '/exit', '/flow', *suffix])
            self.assertEqual(calls, [dict(network_version=1), dict(network_version=2)])
            for version in ('1', '3', 'true', ''):
                with self.assertRaisesRegex(ValueError, 'network_version'):
                    M['main'](['upload', str(root), '/exit', '/flow', '--network-version', version])

    def test_source_profile_selector_is_explicit_reset_and_forwarded_to_node(self):
        root = Path('/inert/root')
        calls = []
        with patch.dict(M['OLD'], guard=lambda: None), patch.dict(G, owner_root=lambda *a, **k: root,
                tools=lambda: PROVISION, phase=lambda *a, **kw: calls.append((G['PROFILE_VERSION'], kw)) or {'passed': False}):
            for suffix in (['--profile-version', '2', '--network-version', '2'],
                    ['--profile-version', '3', '--network-version', '2'],
                    ['--profile-version', '4', '--network-version', '2'],
                    ['--profile-version', '5', '--network-version', '2'],
                    ['--profile-version', '6', '--network-version', '2'], []):
                with redirect_stdout(io.StringIO()):
                    M['main'](['upload', str(root), '/exit', '/flow', *suffix])
            self.assertEqual(calls, [(2, dict(network_version=2)), (3, dict(network_version=2)),
                (4, dict(network_version=2)), (5, dict(network_version=2)), (6, dict(network_version=2)), (1, dict(network_version=1))])
            for version in ('1', '7', 'true', ''):
                with self.assertRaisesRegex(ValueError, 'profile_version'):
                    M['main'](['upload', str(root), '/exit', '/flow', '--profile-version', version])
        node = report('prepare')
        raw = json.dumps(node).encode()
        calls = []
        for profile in (1, 2, 3, 4, 5, 6):
            with patch.dict(G, PROFILE_VERSION=profile, file_bytes=lambda *a: raw,
                    run_child=lambda args, deadline: calls.append(args) or (0, raw, b'')):
                M['node_phase'](root, 'prepare', PROVISION, 1)
        original = [M['NODE'], HERE / 'cloud-upload-maintenance.mjs', 'prepare', root]
        self.assertEqual(calls, [original, [*original, '--profile-version', '2'],
            [*original, '--profile-version', '3'], [*original, '--profile-version', '4'],
            [*original, '--profile-version', '5'], [*original, '--profile-version', '6']])

    def test_tools_rejects_valid_wrong_generation_before_source_access(self):
        fixture = runpy.run_path(str(HERE / 'test-cloud-upload-maintenance-provision.py'))['receipt']
        for wanted, actual in ((a, b) for a in (1, 2, 3, 4, 5, 6) for b in (1, 2, 3, 4, 5, 6) if a != b):
            with patch.dict(G, PROFILE_VERSION=wanted, file_bytes=lambda *a, **kw: json.dumps(fixture(actual)).encode()), \
                    patch.dict(M['OLD'], digest_public=lambda *a: self.fail('source must not be read')), \
                    self.assertRaisesRegex(ValueError, 'provision_profile'):
                M['tools']()

    def test_actual_prepare_code_creates_finite_policy_but_no_enrollment_or_deposit(self):
        for profile in (1, 2, 3, 4, 5, 6):
            with self.subTest(profile=profile):
                self.check_prepare_policy(profile)

    def check_prepare_policy(self, profile):
        calls, writes = [], {}
        deadline, clock = time.monotonic() + 10, 1900000000
        providers, provider_keys = ['socket-a', 'socket-b', 'socket-c'], ['1' * 64, '2' * 64, '3' * 64]
        def command(binary, socket, argv, original_deadline, raw=False):
            calls.append((socket, argv))
            self.assertEqual(original_deadline, deadline)
            if argv[0] == 'init':
                return None
            if argv[:2] == ['content', 'recipient-key']:
                return dict(identity_public_key_hex='4' * 64)
            self.assertEqual(argv[:3], ['storage', 'peer', 'grant'])
            return dict(operation='private_storage_peer_grant', grant_written=True,
                max_payload_bytes=1048576, max_leases=4, expires_unix_seconds=clock + 7200,
                reserved_bytes=0, network_contribution_credit=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(M['OLD'], validate_locations=lambda *a: (Path('/core'), Path('/client'))), \
                    patch.dict(M['BASE'], create=lambda *a: None), \
                    patch.dict(G, PROFILE_VERSION=profile, core=command, node_phase=lambda *a: (report('prepare'), 'e' * 64),
                        write_json=lambda path, value: writes.update({path.name: value}),
                        file_bytes=lambda path, size: json.dumps(writes.get(path.name, {})).encode()), \
                    patch.object(M['time'], 'time', return_value=clock):
                result = M['prepare'](root, '/core', '/client', providers, provider_keys, PROVISION, deadline)
        self.assertEqual(len(calls), 5)
        self.assertEqual([c[0] for c in calls[2:]], providers)
        for _, argv in calls[2:]:
            self.assertEqual(argv[argv.index('--max-payload-bytes') + 1], 1048576)
            self.assertEqual(argv[argv.index('--max-leases') + 1], 4)
        self.assertNotIn('stateDirectory', writes['storage-template.json'])
        if profile == 4:
            self.assertIs(writes['storage-template.json']['appendDiagnosticsV7'], True)
        else:
            self.assertNotIn('appendDiagnosticsV7', writes['storage-template.json'])
        if profile == 5:
            self.assertIs(writes['storage-template.json']['flowAcquireDiagnosticsV8'], True)
        else:
            self.assertNotIn('flowAcquireDiagnosticsV8', writes['storage-template.json'])
        if profile == 6:
            self.assertIs(writes['storage-template.json']['tlsCloseDiagnosticsV9'], True)
        else:
            self.assertNotIn('tlsCloseDiagnosticsV9', writes['storage-template.json'])
        policy = writes['service.json']['storageMaintenance']
        self.assertEqual(policy['version'], 2)
        self.assertEqual(policy['expiresAt'], clock + 6000)
        self.assertEqual(policy['maxSessions'], 1)
        self.assertEqual(policy['maxChargedBytes'], policy['perArchiveMaxChargedBytes'])
        self.assertEqual(policy['maxChargedBytes'], 3 * 1048576)
        self.assertEqual(policy['existing'], [])
        self.assertFalse(result['authority']['enrollment_created'])
        self.assertFalse(result['protected_flow_proven'])
        self.assertEqual(writes['cloud-upload-prepared.json'], result)

    def test_changed_config_fails_before_sampler_or_node(self):
        prepared = dict(provision_sha256=PROVISION, phase='prepare', passed=True,
            authority=dict(service_config_sha256='0' * 64))
        with patch.dict(G, private_json=lambda *a: prepared, file_bytes=lambda *a: b'changed',
                node_phase=lambda *a: self.fail('node must not run')):
            with self.assertRaisesRegex(ValueError, 'configuration_changed'):
                M['phase'](Path('/tmp/root/u/a'), 'upload', '/exit', '/flow', PROVISION, time.monotonic() + 1)

    def test_separate_root_refuses_old_consumer_or_broad_path(self):
        for bad in ('/', '/tmp/a', '/opt/va.' + 'a' * 32 + '.abcdef/u/m', '/opt/va.' + 'a' * 32 + '.abcdef/u'):
            with self.assertRaises(ValueError):
                M['owner_root'](bad, missing=True)

    def test_cleanup_validates_whole_tree_before_removing_anything(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'owned'
            root.mkdir(mode=0o700)
            (root / 'uploads').mkdir(mode=0o700)
            write(root / 'plaintext.bin', b'test')
            write(root / 'uploads/archive.json', b'{}')
            write(root / 'unexpected', b'leave')
            with self.assertRaises(ValueError):
                M['cleanup_tree'](root)
            self.assertTrue((root / 'plaintext.bin').exists())
            (root / 'unexpected').unlink()
            self.assertEqual(M['cleanup_tree'](root), (2, 2))
            self.assertFalse(root.exists())

    def test_reuses_original_owned_child_runner_and_its_cancellation_state(self):
        self.assertIs(M['run_child'], M['OLD']['run_child'])
        state = M['run_child'].__globals__
        with patch.dict(state, CANCELLED=True):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                M['run_child']([sys.executable, '-c', 'raise SystemExit(99)'], time.monotonic() + 2)
        code, output, errors = M['run_child']([sys.executable, '-I', '-B', '-c', 'print("inert")'], time.monotonic() + 2)
        self.assertEqual((code, output, errors), (0, b'inert\n', b''))


if __name__ == '__main__':
    unittest.main()
