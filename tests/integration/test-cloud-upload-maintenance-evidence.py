#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic closed evidence tests only; no app, GPG, core or network execution."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'cloud-upload-maintenance-evidence.py'))
APP = runpy.run_path(str(HERE / 'test-cloud-upload-maintenance-smoke.py'))
PREVIOUS = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))
MAINTENANCE = runpy.run_path(str(HERE / 'test-private-storage-maintenance-smoke.py'))
NETWORK = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))


def fixture(retired=(), *, changed=True, network_version=1, stream_profile=False, challenge_profile=False, append_profile=False, flow_profile=False, close_profile=False):
    previous = NETWORK['fixture'](10 if close_profile else 9 if flow_profile else 8 if append_profile else 7 if challenge_profile else 6 if stream_profile else 5) if network_version == 2 else PREVIOUS['fixture']()
    if network_version == 1:
        PREVIOUS['attach_transition'](previous, changed=changed)
    profile_version = 6 if close_profile else 5 if flow_profile else 4 if append_profile else 3 if challenge_profile else 2 if stream_profile else 1
    pins = M['PROVISIONER']['load_pins'](profile_version)
    provision = dict(version=profile_version, kind='cloud-upload-maintenance-runtime-provision', success=True,
        pins=pins, pins_sha256=hashlib.sha256(M['PROVISIONER']['pins_path'](profile_version).read_bytes()).hexdigest(),
        previous_consumer_provision_sha256=previous['provision_sha256'], tools=copy.deepcopy(previous['provision']['tools']),
        **dict.fromkeys(M['PROVISIONER']['TRUE_FLAGS'], True), **dict.fromkeys(M['PROVISIONER']['FALSE_FLAGS'], False))
    digest = hashlib.sha256(M['encoded'](provision)).hexdigest()
    value = dict(schema_version=8 if close_profile else 7 if flow_profile else 6 if append_profile else 5 if challenge_profile else 4 if stream_profile else 3 if network_version == 2 else 2,
        kind='cloud-upload-maintenance-evidence', success=True,
        scope=dict(M['SCOPE']), previous_consumers=previous, provision=provision, provision_sha256=digest)
    for phase in ('prepare', *M['PHASES']):
        node = APP['report'](phase, retired)
        node['provision_sha256'] = digest
        receipt = dict(version=1, kind='cloud-upload-maintenance-orchestration', phase=phase, passed=True,
            node=node, node_report_sha256=hashlib.sha256(json.dumps(node).encode()).hexdigest(),
            provision_sha256=digest, node_joined=True, protected_flow_proven=phase != 'prepare')
        if phase == 'prepare':
            receipt['authority'] = dict(fresh_owner_created=True, owner_distinct_from_providers=True,
                grant_payload_bytes=[1048576] * 3, grant_max_leases=[4] * 3, grant_retention_seconds=7200,
                grant_lifetime_seconds=7200, reserved_credit=0, enrollment_created=False, automatic_grant_refresh=False,
                policy_expires_at=2000000000, policy_lifetime_seconds=3600, policy_maximum_charge=3145728,
                policy_max_sessions=1, service_config_sha256='1' * 64, storage_template_sha256='2' * 64)
        else:
            receipt.update(minimum_protected_completions=M['APP']['flow_minimum'](phase, APP['report']('upload', retired)), sampler_joined=True,
                remote_cleanup_independently_proven=False)
            if network_version == 2:
                receipt.update(version=2, network_version=2,
                    control_underlay_sha256=previous['publish']['control_underlay_sha256'])
        value[phase] = receipt
    value.update({k: copy.deepcopy(previous[k]) for k in ('layout', 'isolation', 'expected_peers')})
    value['upload_isolation'] = copy.deepcopy(previous['consumer_isolation'])
    upload = value['upload']['node']
    value.update(initial_usage=copy.deepcopy(previous['deleted_usage']),
        uploaded_usage=M['custody_usage'](upload, withdrawn=False), restored_usage=M['custody_usage'](upload, withdrawn=True),
        deleted_usage=copy.deepcopy(previous['deleted_usage']),
        withdrawal=dict(first_provider_stopped_after_measured_upload_baseline=True,
            first_provider_stopped_before_new_repair_and_reads=True, first_store_retained=True,
            other_two_providers_serving=True, same_three_stores_reopened=True,
            all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True),
        private_cleanup=dict(previous['private_cleanup'], kind='cloud-upload-maintenance-cleanup'), network={})
    repair = sum(M['APP']['geometry'](upload['cipher_bytes'])[i] for i in (0, 2, 3) if i not in retired)
    for name in M['PHASES']:
        minimum = M['APP']['flow_minimum'](name, upload)
        network = copy.deepcopy(previous['network']['exercise' if name == 'exercise' else 'publish'])
        gates = network['gates']
        gates.update(exit_mptcp_tls_completed=minimum, exit_log_records=minimum + 1,
            exit_log_observed_records=minimum + 1)
        gates['exit_flow_contexts'][-1]['completed'] = minimum - (2 if network_version == 2 else 0)
        if name == 'exercise':
            for provider in M['NODES'][1:]:
                network['privacy']['exit']['provider_application'][provider]['response_payload_bytes'] = repair + upload['cipher_bytes']
        value['network'][name] = network
    return value


def write_evidence(root, value):
    PREVIOUS['write_evidence'](root, value['previous_consumers'])
    def write(name, data):
        compact = value['schema_version'] in (3, 4, 5, 6, 7, 8) and name in (
            'storage-consumer-evidence.json', 'private-storage-maintenance-smoke.json')
        (root / name).write_bytes(M['OLD']['canonical'](data) if compact else M['encoded'](data))
        (root / name).chmod(0o600)
    if value['schema_version'] in (3, 4, 5, 6, 7, 8):
        prior = value['previous_consumers']
        NETWORK['U']['save'](root, NETWORK['M']['U']['NAME'], M['OLD']['canonical'](prior['control_underlay']))
        for name, phase in prior['network'].items():
            (root / f'content-provider-adaptive-private-storage-fragments-consumer-{name}-control.json').unlink()
            for suffix, data in (('before', phase['control_before']), ('after', phase['control_after']),
                    *phase['control_privacy'].items()):
                NETWORK['U']['save'](root, f'storage-consumer-{name}-control-{suffix}.json', M['OLD']['canonical'](data))
    write('storage-consumer-evidence.json', value['previous_consumers'])
    original = MAINTENANCE['fixture']()
    for name in ('expected_peers', 'layout', 'isolation'):
        original[name] = copy.deepcopy(value[name])
    PREVIOUS['attach_transition'](original,
        changed=value['previous_consumers']['control_transition']['relation'] == 'different', consumer=False)
    write('private-storage-maintenance-smoke.json', dict(MAINTENANCE['report'](original),
        schema_version=9 if value['schema_version'] == 8 else 8 if value['schema_version'] == 7 else 7 if value['schema_version'] == 6 else 6 if value['schema_version'] == 5 else 5 if value['schema_version'] == 4 else 4,
        run_id='a' * 32, consumers=value['previous_consumers']))
    for name in ('provision', 'prepare', *M['PHASES'], 'withdrawal'):
        write(f'cloud-upload-{name}.json', value[name])
    write('cloud-upload-private-cleanup.json', value['private_cleanup'])
    write('cloud-upload-isolation.json', value['upload_isolation'])
    for name in ('uploaded', 'restored', 'deleted'):
        write(f'private-storage-fragments-cloud_upload_{name}_usage.json', value[name + '_usage'])
    for name, phase in value['network'].items():
        for field, suffix in (('layout', 'layout'), ('selected_route', 'live-selection'), ('gates', 'gates')):
            write(f'private-storage-fragments-cloud-upload-{name}-{suffix}.json', phase[field])
        if value['schema_version'] in (3, 4, 5, 6, 7, 8):
            for suffix, data in (('before', phase['control_before']), ('after', phase['control_after']),
                    *phase['control_privacy'].items()):
                write(f'cloud-upload-{name}-control-{suffix}.json', data)
        else:
            write(f'content-provider-adaptive-private-storage-fragments-cloud-upload-{name}-control.json', phase['control_privacy'])
        for role, capture in phase['privacy'].items():
            write(f'private-storage-fragments-cloud-upload-{name}-privacy-{role}.json', capture)


class Evidence(unittest.TestCase):
    def reject(self, mutate, pattern='.'):
        value = fixture((0,))
        mutate(value)
        with self.assertRaisesRegex(ValueError, pattern):
            M['validate_evidence'](value)

    def test_exact_raw_builder_cli_and_export_union(self):
        value = fixture((0, 2))
        self.assertEqual(M['validate_evidence'](value), value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            self.assertEqual(M['build_evidence'](root), value)
            exports = set(M['EXPORT_NAMES']) | (set(M['OLD']['EXPORT_NAMES']) - set(NETWORK['M']['EXPORT_NAMES']))
            self.assertEqual(exports - {'cloud-upload-evidence.json', 'cloud-upload-maintenance-smoke.json'}, {p.name for p in root.iterdir()})
            self.assertEqual(len(M['EXPORT_NAMES']), len(set(M['EXPORT_NAMES'])))
            output = root / 'cloud-upload-evidence.json'
            for args in (['evidence', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'), *args],
                    capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_bytes()), value)
            (root / 'private-storage-fragments-cloud-upload-exercise-layout.json').unlink()
            with self.assertRaises(FileNotFoundError):
                M['build_evidence'](root)

    def test_previous_proof_and_raw_records_remain_mandatory(self):
        self.reject(lambda v: v['previous_consumers']['finish'].update(passed=False))
        self.reject(lambda v: v['provision'].update(previous_consumer_provision_sha256='0' * 64))
        self.reject(lambda v: v['provision']['pins']['sources']['cloud'].update(revision='0' * 40))
        self.reject(lambda v: v['isolation'].update(agent_uid=123))
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            old = root / 'storage-consumer-finish.json'
            modified = json.loads(old.read_bytes())
            modified['node_report_sha256'] = '0' * 64
            old.write_bytes(M['encoded'](modified))
            with self.assertRaisesRegex(ValueError, 'previous_raw_binding'):
                M['build_evidence'](root)

    def test_all_cloud_phases_bind_current_broker_without_rewriting_original_upload(self):
        for changed in (False, True):
            value = fixture(changed=changed)
            original = copy.deepcopy(value['layout'])
            self.assertEqual(M['validate_evidence'](value), value)
            self.assertEqual(value['layout'], original)
            transition = value['previous_consumers']['control_transition']
            self.assertEqual(value['layout']['control_relay_peer_id'], transition['previous_control_relay_peer_id'])
            digest = hashlib.sha256(M['OLD']['canonical'](transition)).hexdigest()
            for phase in M['PHASES']:
                self.assertEqual(value['network'][phase]['layout']['control_transition_sha256'], digest)
                invalid = copy.deepcopy(value)
                invalid['network'][phase]['layout']['control_transition_sha256'] = '0' * 64
                with self.assertRaisesRegex(ValueError, 'upload_phase_transition'):
                    M['validate_evidence'](invalid)
                invalid = copy.deepcopy(value)
                del invalid['network'][phase]['layout']['control_transition_sha256']
                with self.assertRaises(ValueError): M['validate_evidence'](invalid)
                if changed:
                    invalid = copy.deepcopy(value)
                    node = next(node for node in M['ROLES'][1:4]
                        if value['expected_peers'][node] == original['control_relay_peer_id'])
                    pairs = invalid['network'][phase]['control_privacy']['content_control_pairs']
                    for pair in pairs.values(): pair[0] = M['NET']['PUBLIC_IPS'][node]
                    with self.assertRaisesRegex(ValueError, 'upload_control_boundary'):
                        M['validate_evidence'](invalid)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_evidence(root, value)
                self.assertEqual(M['build_evidence'](root), value)
                maintenance = json.loads((root / 'private-storage-maintenance-smoke.json').read_bytes())
                self.assertEqual(maintenance['schema_version'], 4)
                self.assertEqual(maintenance['maintenance']['layout'], original)
                self.assertNotIn('control_transition_sha256', maintenance['maintenance']['network']['upload']['layout'])
                self.assertEqual(maintenance['consumers']['control_transition'], transition)

    def test_old_profiles_or_replaced_transition_cannot_satisfy_current_acceptance(self):
        self.reject(lambda value: value.update(schema_version=1), 'upload_evidence_identity')
        self.reject(lambda value: value['previous_consumers'].update(schema_version=1))
        self.reject(lambda value: value['layout'].update(control_relay_peer_id=
            value['previous_consumers']['control_transition']['current_control_relay_peer_id']), 'upload_previous_fixture_binding')
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            path = root / M['OLD']['TRANSITION_NAME']
            replacement = fixture(changed=False)['previous_consumers']['control_transition']
            path.write_bytes(M['OLD']['canonical'](replacement))
            with self.assertRaises((ValueError, OSError)): M['build_evidence'](root)

    def test_absolute_shared_authority_and_source_only_ordering_claim(self):
        for mutate in (
            lambda v: v['prepare']['authority'].update(policy_expires_at=2000000001),
            lambda v: v['prepare']['authority'].update(policy_max_sessions=2),
            lambda v: v['prepare']['authority'].update(policy_maximum_charge=4000000),
            lambda v: v['prepare']['authority'].update(enrollment_created=True),
            lambda v: v['scope'].update(io_ordering_measured=True),
            lambda v: v['scope'].update(opencloud_account_server_proven=True),
            lambda v: v['upload'].update(provision_sha256='0' * 64),
            lambda v: v['upload']['node'].update(ready_observed=False)):
            self.reject(mutate)

    def test_exact_independent_baseline_and_conservative_stopped_a_charge(self):
        for retired in ((), (0,), (2,), (3,), (0, 2), (0, 3), (2, 3)):
            value = fixture(retired)
            M['validate_evidence'](value)
            self.assertEqual(value['uploaded_usage'][0]['leases'], 3 - len(retired))
            self.assertEqual(value['restored_usage'][0], value['uploaded_usage'][0])
            self.assertEqual([x['committed_bytes'] for x in value['restored_usage'][1:]], [800001] * 2)
            self.assertEqual([x['leases'] for x in value['restored_usage'][1:]], [4] * 2)
        for phase in ('initial', 'uploaded', 'restored', 'deleted'):
            for index in range(3):
                for field in ('reserved_bytes', 'committed_bytes', 'leases'):
                    self.reject(lambda v: v[phase + '_usage'][index].update(
                        {field: v[phase + '_usage'][index][field] + 1}))

    def test_new_network_scope_not_old_phase_or_tcp_or_unsampled_route(self):
        for phase in M['PHASES']:
            minimum = M['APP']['flow_minimum'](phase, APP['report']('upload', (0,)))
            self.reject(lambda v: v[phase].update(minimum_protected_completions=minimum - 1))
            self.reject(lambda v: v['network'][phase]['gates'].update(exit_mptcp_tls_completed=minimum - 1))
            self.reject(lambda v: v['network'][phase]['gates'].update(exit_log_sampler_joined=False))
            self.reject(lambda v: v['network'][phase]['selected_route'].update(transport='tcp'))
            self.reject(lambda v: v['network'][phase]['layout']['route_scope'].update(exit_peer_id='other'))

    def test_two_reads_plus_only_remaining_repair_bytes_and_honest_failed_flows(self):
        value = fixture((0, 2))
        network = value['network']['exercise']
        application = network['privacy']['exit']['provider_application']
        # Deliberately below the original full A-copy bytes: only fragment3
        # remains to repair after withdrawal. Exact two full reads remain due.
        repair = M['APP']['geometry'](800001)[3]
        self.assertEqual(application[M['NODES'][1]]['response_payload_bytes'], repair + 800001)
        gates = network['gates']
        gates.update(exit_mptcp_tls_failed=3, exit_log_observed_records=20)
        gates['exit_flow_contexts'][0]['failed'] = 3
        M['validate_evidence'](value)
        application[M['NODES'][2]]['response_payload_bytes'] -= 1
        with self.assertRaisesRegex(ValueError, 'survivor_payload'):
            M['validate_evidence'](value)
        self.reject(lambda v: v['network']['exercise']['privacy']['exit']['provider_application'][M['NODES'][0]].update(response_payload_bytes=1))
        self.reject(lambda v: v['network']['exercise']['privacy']['client'].update(direct_client_exit_packets=1))
        self.reject(lambda v: v['network']['upload']['control_privacy']['provider_application'][M['NODES'][0]].update(request_packets=1))

    def test_new_owner_mount_denial_and_actual_all_zero_delete_not_old_probe(self):
        for field in ('client_cannot_read_new_owner_root', 'agent_mount_positive_control', 'client_cannot_read_any_provider_store'):
            self.reject(lambda v: v['upload_isolation'].update({field: False}))
        self.reject(lambda v: v['withdrawal'].update(first_provider_stopped_after_measured_upload_baseline=False))
        self.reject(lambda v: v['private_cleanup'].update(remote_cleanup_confirmed=True))
        self.reject(lambda v: v['private_cleanup'].update(removed_files=512))
        self.reject(lambda v: v['finish']['node'].update(all_retained_copies_delete_acknowledged=False))

    def test_compact_terminal_report_requires_both_original_byte_bound_proofs(self):
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            upload = root / 'cloud-upload-evidence.json'
            upload.write_bytes(M['encoded'](value)); upload.chmod(0o600)
            output = root / 'cloud-upload-maintenance-smoke.json'
            result = M['final_report'](root, '1' * 40, 'a' * 32, 'private-storage-maintenance-complete', 0, True, 0, 'NONE')
            self.assertTrue(result['success'])
            self.assertLess(len(M['encoded'](result)), 4096)
            self.assertNotIn('previous_consumers', result)
            output.write_bytes(M['encoded'](result)); output.chmod(0o600)
            self.assertEqual(M['check_report'](output, '1' * 40), result)
            check = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                'check-report', str(output), '1' * 40], capture_output=True, timeout=15)
            self.assertEqual(check.returncode, 0, check.stderr)
            # Same semantic report with different bytes is not the original.
            upload.write_bytes(M['encoded'](value) + b'\n')
            with self.assertRaisesRegex(ValueError, 'original_report_hash'):
                M['check_report'](output, '1' * 40)
            upload.unlink()
            failed = M['final_report'](root, '1' * 40, 'a' * 32, 'cloud-upload-exercise', 1, False, 2, 'CLOUD_UPLOAD_APPLICATION_FAILED')
            self.assertFalse(failed['success'])
            self.assertEqual(failed['runner_exit_status'], 1)
            self.assertEqual(failed['observed_blocker'], 'CLOUD_UPLOAD_APPLICATION_FAILED')
            self.assertFalse(failed['cleanup']['complete'])
            self.assertIsNone(failed['upload_evidence_sha256'])


class CurrentEvidence(unittest.TestCase):
    def test_only_named_current_full_evidence_gets_bounded_growth_allowance(self):
        value = fixture(network_version=2)
        # Exercise the accepted identity-length bound, not an unvalidated blob.
        # Rebind every dependent commitment after replacing fixture identities.
        raw = M['serialize_evidence'](value)
        for index, peer in enumerate(value['expected_peers'].values()):
            raw = raw.replace(json.dumps(peer).encode(), json.dumps(f'p{index:02}' + 'a' * 125).encode())
        value = json.loads(raw)
        prior = value['previous_consumers']
        transition, underlay = prior['control_transition'], prior['control_underlay']
        transition.update(original_layout_sha256=hashlib.sha256(M['encoded'](prior['layout'])).hexdigest(),
            original_layout_canonical_sha256=hashlib.sha256(M['OLD']['canonical'](prior['layout'])).hexdigest())
        underlay.update(original_transition_sha256=hashlib.sha256(M['OLD']['canonical'](transition)).hexdigest(),
            original_peers_sha256=hashlib.sha256(M['OLD']['canonical'](prior['expected_peers'])).hexdigest())
        digest = hashlib.sha256(M['OLD']['canonical'](underlay)).hexdigest()
        for component in (value, prior):
            for name, phase in component['network'].items():
                phase['layout']['control_underlay_sha256'] = digest
                component[name]['control_underlay_sha256'] = digest
        M['validate_evidence'](value)
        raw = M['serialize_evidence'](value)
        self.assertGreater(len(raw), M['MAX_JSON'])
        self.assertLess(len(raw), M['CURRENT_MAX_JSON'])
        self.assertLess(len(raw), len(M['encoded'](value)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / M['EVIDENCE_NAME']
            for size in (len(raw), M['CURRENT_MAX_JSON']):
                expanded = raw + b' ' * (size - len(raw))
                path.write_bytes(expanded); path.chmod(0o600)
                self.assertEqual(M['read_upload_evidence'](path), (value, expanded))
                with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read'](path)
            path.write_bytes(raw + b' ' * (M['CURRENT_MAX_JSON'] + 1 - len(raw)))
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](path)
            wrong_name = root / 'other-evidence.json'
            wrong_name.write_bytes(raw + b' ' * (M['MAX_JSON'] + 1 - len(raw))); wrong_name.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](wrong_name)
            legacy = M['serialize_evidence'](fixture())
            path.write_bytes(legacy + b' ' * (M['MAX_JSON'] + 1 - len(legacy)))
            with self.assertRaisesRegex(ValueError, 'upload_evidence_bound'): M['read_upload_evidence'](path)
            invalid = dict(value, success=False)
            invalid_raw = M['serialize_evidence'](invalid)
            path.write_bytes(invalid_raw + b' ' * (M['MAX_JSON'] + 1 - len(invalid_raw)))
            with self.assertRaisesRegex(ValueError, 'upload_evidence_identity'): M['read_upload_evidence'](path)
        self.assertEqual(M['evidence_limit'](M['EVIDENCE_NAME'], True), M['MAX_JSON'])

    def test_current_builder_cli_preserves_exact_original_profile5_and_separate_pins(self):
        value = fixture((0, 2), network_version=2)
        original = copy.deepcopy(value['previous_consumers'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            self.assertEqual(M['build_evidence'](root, network_version=2), value)
            with self.assertRaises(ValueError): M['build_evidence'](root)
            output = root / 'cloud-upload-evidence.json'
            for args in (['evidence-v3', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_bytes()), value)
            self.assertEqual(value['previous_consumers'], original)
            self.assertNotEqual(value['provision']['pins']['sources'], original['provision']['pins']['sources'])
            self.assertEqual(value['provision']['pins']['runtime'], original['provision']['pins']['runtime'])
            names = set(M['EXPORT_NAMES']) | set(M['CURRENT_EXPORT_NAMES']) | set(M['OLD']['EXPORT_NAMES'])
            self.assertTrue({p.name for p in root.iterdir()} <= names)
            self.assertEqual(len(M['CURRENT_EXPORT_NAMES']), 16)
            self.assertTrue(all(f'cloud-upload-{phase}-control-{suffix}.json' in names
                for phase in M['PHASES'] for suffix in ('before', 'after', 'relay0', 'relay1', 'relay2')))
            (root / 'cloud-upload-exercise-control-relay2.json').unlink()
            with self.assertRaises(FileNotFoundError): M['build_evidence'](root, network_version=2)

    def test_current_profile_rejects_relabelled_historical_predecessor_and_missing_matrix(self):
        original = fixture(network_version=2)
        for mutate in (lambda v: v.update(schema_version=2),
                lambda v: v['previous_consumers'].update(schema_version=4),
                lambda v: v['previous_consumers'].pop('control_underlay'),
                lambda v: v['provision'].update(previous_consumer_provision_sha256='0' * 64),
                lambda v: v['network']['upload']['control_before']['nodes']['relay0']['links'].pop(),
                lambda v: v['network']['finish']['control_after']['nodes']['relay5']['routes'].pop(),
                lambda v: v['network']['exercise']['control_privacy'].pop('relay1'),
                lambda v: v['network']['upload']['layout'].update(control_underlay_sha256='0' * 64),
                lambda v: v['upload'].update(control_underlay_sha256='0' * 64)):
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises((ValueError, KeyError)): M['validate_evidence'](value)
        old = fixture(); old['schema_version'] = 3
        with self.assertRaisesRegex(ValueError, 'upload_previous_profile'): M['validate_evidence'](old)

    def test_current_network_preserves_cloud_specific_bounds_privacy_and_all_retained_deletes(self):
        original = fixture((0, 2), network_version=2)
        M['validate_evidence'](original)
        for mutate in (
                lambda v: v['network']['upload']['gates'].update(exit_mptcp_tls_completed=23),
                lambda v: v['network']['finish']['gates'].update(exit_mptcp_tls_completed=8),
                lambda v: v['network']['exercise']['gates']['observed_context_routes'].pop(),
                lambda v: v['network']['exercise']['privacy']['exit']['provider_application'][M['NODES'][2]].update(
                    response_payload_bytes=800001 + M['APP']['geometry'](800001)[3] - 1),
                lambda v: v['network']['exercise']['privacy']['exit']['provider_application'][M['NODES'][0]].update(
                    response_payload_bytes=1),
                lambda v: v['network']['upload']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['network']['upload']['control_privacy']['relay2']['provider_application'][M['NODES'][0]].update(
                    request_packets=1),
                lambda v: v['finish']['node']['accounting'].update(retained_copy_records=9),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1)):
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError): M['validate_evidence'](value)
        self.assertEqual(original['finish']['minimum_protected_completions'], 9)
        self.assertEqual(original['finish']['node']['accounting']['retained_copy_records'], 11)

    def test_current_terminal_gate_cannot_accept_historical_complete_proofs(self):
        for network_version in (1, 2):
            value = fixture(network_version=network_version)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_evidence(root, value)
                (root / 'cloud-upload-evidence.json').write_bytes(M['serialize_evidence'](value))
                (root / 'cloud-upload-evidence.json').chmod(0o600)
                result = M['final_report'](root, '1' * 40, 'a' * 32,
                    'private-storage-maintenance-complete', 0, True, 0, 'NONE', current=True)
                self.assertEqual(result['success'], network_version == 2)
                output = root / 'cloud-upload-maintenance-smoke.json'
                output.write_bytes(M['encoded'](result)); output.chmod(0o600)
                checked = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    'check-report-v3', str(output), '1' * 40], capture_output=True, timeout=30)
                self.assertEqual(checked.returncode == 0, network_version == 2, checked.stderr)


class StreamEvidence(unittest.TestCase):
    def test_explicit_builder_and_cli_bind_profile6_and_new_pins_without_replacing_original_bytes(self):
        value = fixture((0, 2), network_version=2, stream_profile=True)
        self.assertEqual(value['schema_version'], 4)
        self.assertEqual(value['previous_consumers']['schema_version'], 6)
        self.assertEqual(value['provision']['version'], 2)
        M['validate_evidence'](value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            original = {p.name: p.read_bytes() for p in root.iterdir()}
            self.assertEqual(M['build_evidence'](root, network_version=2, stream_profile=True), value)
            for options in ({}, dict(network_version=2), dict(stream_profile=True)):
                with self.assertRaises(ValueError): M['build_evidence'](root, **options)
            output = root / 'cloud-upload-evidence.json'
            for args in (['evidence-v4', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), M['serialize_evidence'](value))
            self.assertTrue(all((root / name).read_bytes() == raw for name, raw in original.items()))
            self.assertEqual(value['previous_consumers']['provision']['pins']['sources']['cloud']['revision'],
                value['provision']['pins']['sources']['cloud']['revision'])
            # Even when the source commit matches, the old 23-file provision
            # and separate 24-file upload inventory remain distinct receipts.
            self.assertNotEqual(value['previous_consumers']['provision_sha256'], value['provision_sha256'])
            prior = root / 'storage-consumer-finish.json'
            tampered = json.loads(prior.read_bytes()); tampered['node_report_sha256'] = '0' * 64
            prior.write_bytes(M['encoded'](tampered))
            with self.assertRaisesRegex(ValueError, 'previous_raw_binding'):
                M['build_evidence'](root, network_version=2, stream_profile=True)

    def test_generations_cannot_be_relabelled_or_cross_bound(self):
        stream = fixture(network_version=2, stream_profile=True)
        for mutate in (lambda v: v.update(schema_version=3),
                lambda v: v.update(previous_consumers=fixture(network_version=2)['previous_consumers']),
                lambda v: v.update(provision=fixture(network_version=2)['provision']),
                lambda v: v['provision']['pins']['sources']['image'].update(revision='0' * 40),
                lambda v: v['previous_consumers'].pop('control_underlay'),
                lambda v: v['network']['exercise']['control_privacy'].pop('relay1'),
                lambda v: v['network']['finish']['control_after']['nodes']['relay5']['routes'].pop(),
                lambda v: v['network']['upload']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1)):
            value = copy.deepcopy(stream); mutate(value)
            with self.assertRaises((ValueError, KeyError)): M['validate_evidence'](value)
        for old in (fixture(), fixture(network_version=2)):
            old['schema_version'] = 4
            with self.assertRaisesRegex(ValueError, 'upload_previous_profile'): M['validate_evidence'](old)

    def test_terminal2_and_v4_selectors_require_exact_new_originals_and_keep_failures_closed(self):
        for schema in (2, 3, 4):
            value = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_evidence(root, value)
                upload = root / M['EVIDENCE_NAME']
                upload.write_bytes(M['serialize_evidence'](value)); upload.chmod(0o600)
                output = root / 'cloud-upload-maintenance-smoke.json'
                argv = ['finalize-report-v4', str(root), '1' * 40, 'a' * 32,
                    'private-storage-maintenance-complete', '0', 'true', '0', 'NONE', str(output)]
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *argv], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                terminal = json.loads(output.read_bytes())
                self.assertEqual(terminal['schema_version'], 2)
                self.assertEqual(terminal['success'], schema == 4)
                self.assertLess(len(output.read_bytes()), 4096)
                self.assertEqual(terminal['upload_evidence_sha256'], hashlib.sha256(upload.read_bytes()).hexdigest())
                for selector in ('check-report', 'check-report-v3', 'check-report-v4'):
                    checked = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                        selector, str(output), '1' * 40], capture_output=True, timeout=30)
                    self.assertEqual(checked.returncode == 0, schema == 4 and selector == 'check-report-v4', checked.stderr)
                if schema != 4:
                    continue
                old_terminal = M['final_report'](root, '1' * 40, 'a' * 32,
                    'private-storage-maintenance-complete', 0, True, 0, 'NONE')
                self.assertEqual(old_terminal['schema_version'], 1)
                self.assertFalse(old_terminal['success'])
                upload.write_bytes(upload.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'original_report_hash'):
                    M['check_report'](output, '1' * 40, stream_profile=True)
                failed = M['final_report'](root, '1' * 40, 'a' * 32, 'cloud-upload-exercise',
                    1, False, 2, 'CLOUD_UPLOAD_APPLICATION_FAILED', stream_profile=True)
                self.assertEqual((failed['schema_version'], failed['success'], failed['runner_exit_status']), (2, False, 1))
                self.assertEqual(failed['observed_blocker'], 'CLOUD_UPLOAD_APPLICATION_FAILED')
                self.assertEqual(failed['cleanup'], dict(complete=False, remaining_owned_objects=2))

    def test_schema4_growth_allowance_is_exact_name_bounded_and_preserves_schema3_bytes(self):
        value = fixture(network_version=2, stream_profile=True)
        raw = M['serialize_evidence'](value)
        self.assertEqual(raw, M['OLD']['canonical'](value))
        for version in (2, 3, 4, 5, 6, 7, 8, 9, True, '4'):
            self.assertEqual(M['evidence_limit'](M['EVIDENCE_NAME'], version),
                M['CURRENT_MAX_JSON'] if type(version) is int and version in (3, 4, 5, 6, 7, 8) else M['MAX_JSON'])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / M['EVIDENCE_NAME']
            for size in (M['MAX_JSON'] + 1, M['CURRENT_MAX_JSON']):
                expanded = raw + b' ' * (size - len(raw))
                path.write_bytes(expanded); path.chmod(0o600)
                self.assertEqual(M['read_upload_evidence'](path), (value, expanded))
            path.write_bytes(raw + b' ' * (M['CURRENT_MAX_JSON'] + 1 - len(raw)))
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](path)
        historical = fixture(network_version=2)
        self.assertEqual(M['serialize_evidence'](historical), M['OLD']['canonical'](historical))
        historical = fixture()
        self.assertEqual(M['serialize_evidence'](historical), M['encoded'](historical))


class ChallengeEvidence(unittest.TestCase):
    def test_explicit_profile7_builder_reconstructs_originals_and_binds_distinct_profile3(self):
        value = fixture((0, 2), network_version=2, challenge_profile=True)
        self.assertEqual((value['schema_version'], value['previous_consumers']['schema_version'],
            value['provision']['version']), (5, 7, 3))
        M['validate_evidence'](value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); write_evidence(root, value)
            original = {p.name: p.read_bytes() for p in root.iterdir()}
            options = dict(network_version=2, challenge_profile=True)
            self.assertEqual(M['build_evidence'](root, **options), value)
            for wrong in ({}, dict(network_version=2), dict(network_version=2, stream_profile=True),
                    dict(challenge_profile=True), dict(network_version=2, challenge_profile=True, stream_profile=True),
                    dict(network_version=2, challenge_profile=1)):
                with self.subTest(options=wrong), self.assertRaises(ValueError): M['build_evidence'](root, **wrong)
            output = root / M['EVIDENCE_NAME']
            for args in (['evidence-v5', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), M['OLD']['canonical'](value))
            self.assertTrue(all((root / name).read_bytes() == raw for name, raw in original.items()))
            prior = value['previous_consumers']
            self.assertEqual(prior['provision']['pins']['sources']['cloud']['revision'],
                value['provision']['pins']['sources']['cloud']['revision'])
            self.assertNotEqual(prior['provision_sha256'], value['provision_sha256'])
            record = root / 'storage-consumer-finish.json'
            changed = json.loads(record.read_bytes()); changed['node_report_sha256'] = '0' * 64
            record.write_bytes(M['encoded'](changed))
            with self.assertRaisesRegex(ValueError, 'previous_raw_binding'): M['build_evidence'](root, **options)

    def test_challenge_generation_rejects_old_pins_evidence_and_weakened_original_requirements(self):
        original = fixture(network_version=2, challenge_profile=True)
        for schema in (2, 3, 4):
            historical = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4)
            relabelled = copy.deepcopy(historical); relabelled['schema_version'] = 5
            with self.assertRaisesRegex(ValueError, 'upload_previous_profile'): M['validate_evidence'](relabelled)
            for field in ('previous_consumers', 'provision'):
                value = copy.deepcopy(original); value[field] = historical[field]
                with self.assertRaises(ValueError): M['validate_evidence'](value)
        for change in (lambda v: v['provision']['pins']['sources']['image'].update(revision='0' * 40),
                lambda v: v['previous_consumers'].pop('control_underlay'),
                lambda v: v['network']['exercise']['control_privacy'].pop('relay1'),
                lambda v: v['network']['finish']['control_after']['nodes']['relay5']['routes'].pop(),
                lambda v: v['network']['upload']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1),
                lambda v: v['initial_usage'][0].update(reserved_bytes=1),
                lambda v: v['finish']['node'].update(all_retained_copies_delete_acknowledged=False)):
            value = copy.deepcopy(original); change(value)
            with self.assertRaises((ValueError, KeyError)): M['validate_evidence'](value)

    def test_terminal3_current_cli_keeps_all_old_generations_inspectable_but_not_current(self):
        for schema in (2, 3, 4, 5):
            value = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4,
                challenge_profile=schema == 5)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); write_evidence(root, value)
                upload = root / M['EVIDENCE_NAME']; upload.write_bytes(M['serialize_evidence'](value)); upload.chmod(0o600)
                output = root / 'cloud-upload-maintenance-smoke.json'
                argv = ['finalize-report-v5', str(root), '1' * 40, 'a' * 32,
                    'private-storage-maintenance-complete', '0', 'true', '0', 'NONE', str(output)]
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *argv], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                terminal = json.loads(output.read_bytes())
                self.assertEqual(terminal['schema_version'], 3)
                self.assertEqual(terminal['success'], schema == 5)
                self.assertLess(len(output.read_bytes()), 4096)
                self.assertEqual(terminal['upload_evidence_sha256'], hashlib.sha256(upload.read_bytes()).hexdigest())
                for selector in ('check-report', 'check-report-v3', 'check-report-v4', 'check-report-v5'):
                    checked = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                        selector, str(output), '1' * 40], capture_output=True, timeout=30)
                    self.assertEqual(checked.returncode == 0, schema == 5 and selector == 'check-report-v5', checked.stderr)
                if schema != 5: continue
                for old_options in ({}, dict(current=True), dict(stream_profile=True)):
                    old = M['final_report'](root, '1' * 40, 'a' * 32, 'private-storage-maintenance-complete',
                        0, True, 0, 'NONE', **old_options)
                    self.assertFalse(old['success'])
                    self.assertIn(old['schema_version'], (1, 2))
                upload.write_bytes(upload.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'original_report_hash'):
                    M['check_report'](output, '1' * 40, challenge_profile=True)
                upload.unlink()
                failed = M['final_report'](root, '1' * 40, 'a' * 32, 'cloud-upload-exercise', 1, False, 2,
                    'CLOUD_UPLOAD_APPLICATION_FAILED', challenge_profile=True)
                self.assertEqual((failed['schema_version'], failed['success'], failed['runner_exit_status']), (3, False, 1))
                self.assertEqual(failed['observed_blocker'], 'CLOUD_UPLOAD_APPLICATION_FAILED')
                self.assertEqual(failed['cleanup'], dict(complete=False, remaining_owned_objects=2))

    def test_schema5_bound_and_export_names_remain_closed_without_changing_historical_encoding(self):
        value = fixture(network_version=2, challenge_profile=True)
        raw = M['serialize_evidence'](value)
        self.assertEqual(raw, M['OLD']['canonical'](value))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / M['EVIDENCE_NAME']
            for size in (M['MAX_JSON'] + 1, M['CURRENT_MAX_JSON']):
                expanded = raw + b' ' * (size - len(raw)); path.write_bytes(expanded); path.chmod(0o600)
                self.assertEqual(M['read_upload_evidence'](path), (value, expanded))
            path.write_bytes(raw + b' ' * (M['CURRENT_MAX_JSON'] + 1 - len(raw)))
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](path)
            wrong = root / 'other.json'; wrong.write_bytes(raw + b' ' * (M['MAX_JSON'] + 1 - len(raw))); wrong.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](wrong)
            invalid = dict(value, kind='other')
            invalid_raw = M['serialize_evidence'](invalid)
            path.write_bytes(invalid_raw + b' ' * (M['MAX_JSON'] + 1 - len(invalid_raw)))
            with self.assertRaisesRegex(ValueError, 'upload_evidence_identity'): M['read_upload_evidence'](path)
        outputs = []
        for command in ('export-names-v3', 'export-names-v4', 'export-names-v5'):
            result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'), command],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr); outputs.append(result.stdout)
        self.assertTrue(all(output == outputs[0] for output in outputs))
        for schema in (2, 3, 4):
            old = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4)
            self.assertEqual(M['serialize_evidence'](old), M['encoded'](old) if schema == 2 else M['OLD']['canonical'](old))


class AppendEvidence(unittest.TestCase):
    def test_profile8_originals_reconstruct_only_explicit_profile4_evidence6(self):
        value = fixture((0, 2), network_version=2, append_profile=True)
        self.assertEqual((value['schema_version'], value['previous_consumers']['schema_version'],
            value['provision']['version']), (6, 8, 4))
        M['validate_evidence'](value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); write_evidence(root, value)
            original = {p.name: p.read_bytes() for p in root.iterdir()}
            options = dict(network_version=2, append_profile=True)
            self.assertEqual(M['build_evidence'](root, **options), value)
            for wrong in ({}, dict(network_version=2), dict(network_version=2, stream_profile=True),
                    dict(network_version=2, challenge_profile=True), dict(append_profile=True),
                    dict(network_version=2, append_profile=True, stream_profile=True),
                    dict(network_version=2, append_profile=True, challenge_profile=True),
                    dict(network_version=2, append_profile=1)):
                with self.subTest(options=wrong), self.assertRaises(ValueError): M['build_evidence'](root, **wrong)
            output = root / M['EVIDENCE_NAME']
            for args in (['evidence-v6', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), M['OLD']['canonical'](value))
            self.assertTrue(all((root / name).read_bytes() == raw for name, raw in original.items()))
            prior = value['previous_consumers']
            for name in ('cloud', 'image'):
                self.assertEqual(prior['provision']['pins']['sources'][name]['revision'],
                    value['provision']['pins']['sources'][name]['revision'])
            self.assertNotEqual(prior['provision_sha256'], value['provision_sha256'])
            record = root / 'storage-consumer-finish.json'
            changed = json.loads(record.read_bytes()); changed['node_report_sha256'] = '0' * 64
            record.write_bytes(M['encoded'](changed))
            with self.assertRaisesRegex(ValueError, 'previous_raw_binding'): M['build_evidence'](root, **options)

    def test_append_generation_rejects_cross_generation_and_weakened_originals(self):
        original = fixture(network_version=2, append_profile=True)
        for schema in (2, 3, 4, 5):
            historical = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4,
                challenge_profile=schema == 5)
            relabelled = copy.deepcopy(historical); relabelled['schema_version'] = 6
            with self.assertRaisesRegex(ValueError, 'upload_previous_profile'): M['validate_evidence'](relabelled)
            for field in ('previous_consumers', 'provision'):
                value = copy.deepcopy(original); value[field] = historical[field]
                with self.assertRaises(ValueError): M['validate_evidence'](value)
        for change in (lambda v: v['provision']['pins']['sources']['image'].update(revision='0' * 40),
                lambda v: v['previous_consumers'].pop('control_underlay'),
                lambda v: v['network']['exercise']['control_privacy'].pop('relay1'),
                lambda v: v['network']['finish']['control_after']['nodes']['relay5']['routes'].pop(),
                lambda v: v['network']['upload']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1),
                lambda v: v['initial_usage'][0].update(reserved_bytes=1),
                lambda v: v['prepare']['authority'].update(automatic_grant_refresh=True),
                lambda v: v['finish']['node'].update(all_retained_copies_delete_acknowledged=False)):
            value = copy.deepcopy(original); change(value)
            with self.assertRaises((ValueError, KeyError)): M['validate_evidence'](value)

    def test_terminal4_requires_all_new_generations_and_preserves_primary_failure(self):
        for schema in (2, 3, 4, 5, 6):
            value = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4,
                challenge_profile=schema == 5, append_profile=schema == 6)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); write_evidence(root, value)
                upload = root / M['EVIDENCE_NAME']; upload.write_bytes(M['serialize_evidence'](value)); upload.chmod(0o600)
                output = root / 'cloud-upload-maintenance-smoke.json'
                argv = ['finalize-report-v6', str(root), '1' * 40, 'a' * 32,
                    'private-storage-maintenance-complete', '0', 'true', '0', 'NONE', str(output)]
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *argv], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                terminal = json.loads(output.read_bytes())
                self.assertEqual(terminal['schema_version'], 4)
                self.assertEqual(terminal['success'], schema == 6)
                self.assertLess(len(output.read_bytes()), 4096)
                self.assertEqual(terminal['upload_evidence_sha256'], hashlib.sha256(upload.read_bytes()).hexdigest())
                for selector in ('check-report', 'check-report-v3', 'check-report-v4', 'check-report-v5', 'check-report-v6'):
                    checked = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                        selector, str(output), '1' * 40], capture_output=True, timeout=30)
                    self.assertEqual(checked.returncode == 0, schema == 6 and selector == 'check-report-v6', checked.stderr)
                if schema != 6: continue
                for old_options in ({}, dict(current=True), dict(stream_profile=True), dict(challenge_profile=True)):
                    old = M['final_report'](root, '1' * 40, 'a' * 32, 'private-storage-maintenance-complete',
                        0, True, 0, 'NONE', **old_options)
                    self.assertFalse(old['success'])
                    self.assertIn(old['schema_version'], (1, 2, 3))
                upload.write_bytes(upload.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'original_report_hash'):
                    M['check_report'](output, '1' * 40, append_profile=True)
                upload.unlink()
                failed = M['final_report'](root, '1' * 40, 'a' * 32, 'cloud-upload-exercise', 1, False, 2,
                    'CLOUD_UPLOAD_APPLICATION_FAILED', append_profile=True)
                self.assertEqual((failed['schema_version'], failed['success'], failed['runner_exit_status']), (4, False, 1))
                self.assertEqual(failed['observed_blocker'], 'CLOUD_UPLOAD_APPLICATION_FAILED')
                self.assertEqual(failed['cleanup'], dict(complete=False, remaining_owned_objects=2))

    def test_schema6_keeps_exact_named_bound_exports_and_historical_encoding(self):
        value = fixture(network_version=2, append_profile=True)
        raw = M['serialize_evidence'](value)
        self.assertEqual(raw, M['OLD']['canonical'](value))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / M['EVIDENCE_NAME']
            for size in (M['MAX_JSON'] + 1, M['CURRENT_MAX_JSON']):
                expanded = raw + b' ' * (size - len(raw)); path.write_bytes(expanded); path.chmod(0o600)
                self.assertEqual(M['read_upload_evidence'](path), (value, expanded))
            path.write_bytes(raw + b' ' * (M['CURRENT_MAX_JSON'] + 1 - len(raw)))
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](path)
            wrong = root / 'other.json'; wrong.write_bytes(raw + b' ' * (M['MAX_JSON'] + 1 - len(raw))); wrong.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](wrong)
            for invalid, error in ((dict(value, kind='other'), 'upload_evidence_identity'),
                    (dict(value, schema_version=9), 'upload_evidence_bound')):
                invalid_raw = M['OLD']['canonical'](invalid)
                path.write_bytes(invalid_raw + b' ' * (M['MAX_JSON'] + 1 - len(invalid_raw)))
                with self.assertRaisesRegex(ValueError, error): M['read_upload_evidence'](path)
        outputs = []
        for command in ('export-names-v3', 'export-names-v4', 'export-names-v5', 'export-names-v6'):
            result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'), command],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr); outputs.append(result.stdout)
        self.assertTrue(all(output == outputs[0] for output in outputs))
        for schema in (2, 3, 4, 5):
            old = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4, challenge_profile=schema == 5)
            self.assertEqual(M['serialize_evidence'](old), M['encoded'](old) if schema == 2 else M['OLD']['canonical'](old))


class FlowEvidence(unittest.TestCase):
    def test_historical_fixture_serializations_keep_original_representation(self):
        # Spell out the parent encoders independently of serialize_evidence.
        # Nested observed Node hashes deliberately retain original bytes, so
        # these synthetic fixtures are not cross-process canonical hash goldens.
        for schema in (2, 3, 4, 5, 6):
            value = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4,
                challenge_profile=schema == 5, append_profile=schema == 6)
            raw = M['serialize_evidence'](value)
            expected = ((json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
                if schema == 2 else json.dumps(value, sort_keys=True, separators=(',', ':'),
                    ensure_ascii=True, allow_nan=False).encode())
            self.assertEqual(raw, expected)
            self.assertEqual(M['validate_evidence'](value), value)

    def test_profile9_originals_reconstruct_only_explicit_profile5_evidence7(self):
        value = fixture((0, 2), network_version=2, flow_profile=True)
        self.assertEqual((value['schema_version'], value['previous_consumers']['schema_version'],
            value['provision']['version']), (7, 9, 5))
        M['validate_evidence'](value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); write_evidence(root, value)
            original = {p.name: p.read_bytes() for p in root.iterdir()}
            options = dict(network_version=2, flow_profile=True)
            self.assertEqual(M['build_evidence'](root, **options), value)
            for wrong in ({}, dict(network_version=2), dict(network_version=2, stream_profile=True),
                    dict(network_version=2, challenge_profile=True), dict(network_version=2, append_profile=True), dict(flow_profile=True),
                    dict(network_version=2, flow_profile=True, stream_profile=True),
                    dict(network_version=2, flow_profile=True, challenge_profile=True),
                    dict(network_version=2, flow_profile=True, append_profile=True),
                    dict(network_version=2, flow_profile=1)):
                with self.subTest(options=wrong), self.assertRaises(ValueError): M['build_evidence'](root, **wrong)
            output = root / M['EVIDENCE_NAME']
            for args in (['evidence-v7', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), M['OLD']['canonical'](value))
            self.assertTrue(all((root / name).read_bytes() == raw for name, raw in original.items()))
            prior = value['previous_consumers']
            for name in ('cloud', 'image'):
                self.assertEqual(prior['provision']['pins']['sources'][name]['revision'],
                    value['provision']['pins']['sources'][name]['revision'])
            self.assertNotEqual(prior['provision_sha256'], value['provision_sha256'])
            record = root / 'storage-consumer-finish.json'
            changed = json.loads(record.read_bytes()); changed['node_report_sha256'] = '0' * 64
            record.write_bytes(M['encoded'](changed))
            with self.assertRaisesRegex(ValueError, 'previous_raw_binding'): M['build_evidence'](root, **options)

    def test_flow_generation_rejects_cross_generation_and_weakened_originals(self):
        original = fixture(network_version=2, flow_profile=True)
        for schema in (2, 3, 4, 5, 6):
            historical = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4,
                challenge_profile=schema == 5, append_profile=schema == 6)
            relabelled = copy.deepcopy(historical); relabelled['schema_version'] = 7
            with self.assertRaisesRegex(ValueError, 'upload_previous_profile'): M['validate_evidence'](relabelled)
            for field in ('previous_consumers', 'provision'):
                value = copy.deepcopy(original); value[field] = historical[field]
                with self.assertRaises(ValueError): M['validate_evidence'](value)
        for change in (lambda v: v['provision']['pins']['sources']['image'].update(revision='0' * 40),
                lambda v: v['previous_consumers'].pop('control_underlay'),
                lambda v: v['network']['exercise']['control_privacy'].pop('relay1'),
                lambda v: v['network']['finish']['control_after']['nodes']['relay5']['routes'].pop(),
                lambda v: v['network']['upload']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1),
                lambda v: v['initial_usage'][0].update(reserved_bytes=1),
                lambda v: v['prepare']['authority'].update(automatic_grant_refresh=True),
                lambda v: v['finish']['node'].update(all_retained_copies_delete_acknowledged=False)):
            value = copy.deepcopy(original); change(value)
            with self.assertRaises((ValueError, KeyError)): M['validate_evidence'](value)

    def test_terminal5_requires_all_new_generations_and_preserves_primary_failure(self):
        for schema in (2, 3, 4, 5, 6, 7):
            value = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4,
                challenge_profile=schema == 5, append_profile=schema == 6, flow_profile=schema == 7)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); write_evidence(root, value)
                upload = root / M['EVIDENCE_NAME']; upload.write_bytes(M['serialize_evidence'](value)); upload.chmod(0o600)
                output = root / 'cloud-upload-maintenance-smoke.json'
                argv = ['finalize-report-v7', str(root), '1' * 40, 'a' * 32,
                    'private-storage-maintenance-complete', '0', 'true', '0', 'NONE', str(output)]
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *argv], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                terminal = json.loads(output.read_bytes())
                self.assertEqual(terminal['schema_version'], 5)
                self.assertEqual(terminal['success'], schema == 7)
                self.assertLess(len(output.read_bytes()), 4096)
                self.assertEqual(terminal['upload_evidence_sha256'], hashlib.sha256(upload.read_bytes()).hexdigest())
                for selector in ('check-report', 'check-report-v3', 'check-report-v4', 'check-report-v5', 'check-report-v6', 'check-report-v7'):
                    checked = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                        selector, str(output), '1' * 40], capture_output=True, timeout=30)
                    self.assertEqual(checked.returncode == 0, schema == 7 and selector == 'check-report-v7', checked.stderr)
                if schema != 7: continue
                for old_options in ({}, dict(current=True), dict(stream_profile=True), dict(challenge_profile=True), dict(append_profile=True)):
                    old = M['final_report'](root, '1' * 40, 'a' * 32, 'private-storage-maintenance-complete',
                        0, True, 0, 'NONE', **old_options)
                    self.assertFalse(old['success'])
                    self.assertIn(old['schema_version'], (1, 2, 3, 4))
                upload.write_bytes(upload.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'original_report_hash'):
                    M['check_report'](output, '1' * 40, flow_profile=True)
                upload.unlink()
                failed = M['final_report'](root, '1' * 40, 'a' * 32, 'cloud-upload-exercise', 1, False, 2,
                    'CLOUD_UPLOAD_APPLICATION_FAILED', flow_profile=True)
                self.assertEqual((failed['schema_version'], failed['success'], failed['runner_exit_status']), (5, False, 1))
                self.assertEqual(failed['observed_blocker'], 'CLOUD_UPLOAD_APPLICATION_FAILED')
                self.assertEqual(failed['cleanup'], dict(complete=False, remaining_owned_objects=2))

    def test_schema7_keeps_exact_named_bound_exports_and_historical_encoding(self):
        value = fixture(network_version=2, flow_profile=True)
        raw = M['serialize_evidence'](value)
        self.assertEqual(raw, M['OLD']['canonical'](value))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / M['EVIDENCE_NAME']
            for size in (M['MAX_JSON'] + 1, M['CURRENT_MAX_JSON']):
                expanded = raw + b' ' * (size - len(raw)); path.write_bytes(expanded); path.chmod(0o600)
                self.assertEqual(M['read_upload_evidence'](path), (value, expanded))
            path.write_bytes(raw + b' ' * (M['CURRENT_MAX_JSON'] + 1 - len(raw)))
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](path)
            wrong = root / 'other.json'; wrong.write_bytes(raw + b' ' * (M['MAX_JSON'] + 1 - len(raw))); wrong.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](wrong)
            for invalid, error in ((dict(value, kind='other'), 'upload_evidence_identity'),
                    (dict(value, schema_version=9), 'upload_evidence_bound')):
                invalid_raw = M['OLD']['canonical'](invalid)
                path.write_bytes(invalid_raw + b' ' * (M['MAX_JSON'] + 1 - len(invalid_raw)))
                with self.assertRaisesRegex(ValueError, error): M['read_upload_evidence'](path)
        outputs = []
        for command in ('export-names-v3', 'export-names-v4', 'export-names-v5', 'export-names-v6', 'export-names-v7'):
            result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'), command],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr); outputs.append(result.stdout)
        self.assertTrue(all(output == outputs[0] for output in outputs))
        for schema in (2, 3, 4, 5, 6):
            old = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4, challenge_profile=schema == 5, append_profile=schema == 6)
            self.assertEqual(M['serialize_evidence'](old), M['encoded'](old) if schema == 2 else M['OLD']['canonical'](old))


class CloseEvidence(unittest.TestCase):
    def test_profile10_originals_reconstruct_only_explicit_upload6_evidence8(self):
        value = fixture((0, 2), network_version=2, close_profile=True)
        self.assertEqual((value['schema_version'], value['previous_consumers']['schema_version'],
            value['provision']['version']), (8, 10, 6))
        M['validate_evidence'](value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); write_evidence(root, value)
            originals = {p.name: p.read_bytes() for p in root.iterdir()}
            options = dict(network_version=2, close_profile=True)
            self.assertEqual(M['build_evidence'](root, **options), value)
            for wrong in ({}, dict(network_version=2), dict(close_profile=True),
                    dict(network_version=2, close_profile=1),
                    *(dict(options, **{name: True}) for name in
                        ('stream_profile', 'challenge_profile', 'append_profile', 'flow_profile'))):
                with self.subTest(options=wrong), self.assertRaises(ValueError): M['build_evidence'](root, **wrong)
            output = root / M['EVIDENCE_NAME']
            for args in (['evidence-v8', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    *args], capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), M['OLD']['canonical'](value))
            self.assertTrue(all((root / name).read_bytes() == raw for name, raw in originals.items()))
            record = root / 'storage-consumer-finish.json'
            changed = json.loads(record.read_bytes()); changed['node_report_sha256'] = '0' * 64
            record.write_bytes(M['encoded'](changed))
            with self.assertRaisesRegex(ValueError, 'previous_raw_binding'): M['build_evidence'](root, **options)

    def test_close_profile_keeps_shared_pass_network_zero_usage_and_authority_prerequisites(self):
        original = fixture(network_version=2, close_profile=True)
        for schema in range(2, 8):
            historical = fixture(network_version=2 if schema >= 3 else 1, stream_profile=schema == 4,
                challenge_profile=schema == 5, append_profile=schema == 6, flow_profile=schema == 7)
            relabelled = copy.deepcopy(historical); relabelled['schema_version'] = 8
            with self.assertRaisesRegex(ValueError, 'upload_previous_profile'): M['validate_evidence'](relabelled)
            for field in ('previous_consumers', 'provision'):
                value = copy.deepcopy(original); value[field] = historical[field]
                with self.assertRaises(ValueError): M['validate_evidence'](value)
        for change in (lambda v: v['previous_consumers']['publish'].update(passed=False),
                lambda v: v['previous_consumers']['finish'].update(node_joined=False),
                lambda v: v['previous_consumers'].pop('control_underlay'),
                lambda v: v['network']['exercise']['control_privacy'].pop('relay1'),
                lambda v: v['network']['upload']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1),
                lambda v: v['initial_usage'][0].update(reserved_bytes=1),
                lambda v: v['prepare']['authority'].update(automatic_grant_refresh=True),
                lambda v: v['finish']['node'].update(all_retained_copies_delete_acknowledged=False),
                lambda v: v['private_cleanup'].update(remote_cleanup_confirmed=True)):
            value = copy.deepcopy(original); change(value)
            with self.assertRaises((ValueError, KeyError)): M['validate_evidence'](value)

    def test_terminal6_binds_original_siblings_and_preserves_failure(self):
        value = fixture(network_version=2, close_profile=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); write_evidence(root, value)
            upload = root / M['EVIDENCE_NAME']; upload.write_bytes(M['serialize_evidence'](value)); upload.chmod(0o600)
            output = root / 'cloud-upload-maintenance-smoke.json'
            args = ['finalize-report-v8', str(root), '1' * 40, 'a' * 32,
                'private-storage-maintenance-complete', '0', 'true', '0', 'NONE', str(output)]
            result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                *args], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            terminal = json.loads(output.read_bytes())
            self.assertEqual((terminal['schema_version'], terminal['success']), (6, True))
            self.assertLess(len(output.read_bytes()), 4096)
            for selector in ('check-report', 'check-report-v3', 'check-report-v4', 'check-report-v5',
                    'check-report-v6', 'check-report-v7', 'check-report-v8'):
                checked = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'),
                    selector, str(output), '1' * 40], capture_output=True, timeout=30)
                self.assertEqual(checked.returncode == 0, selector == 'check-report-v8', checked.stderr)
            upload.write_bytes(upload.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'original_report_hash'):
                M['check_report'](output, '1' * 40, close_profile=True)
            upload.unlink()
            failed = M['final_report'](root, '1' * 40, 'a' * 32, 'cloud-upload-exercise', 17, False, 2,
                'CLOUD_UPLOAD_APPLICATION_FAILED', close_profile=True)
            self.assertEqual((failed['schema_version'], failed['success'], failed['runner_exit_status']), (6, False, 17))
            self.assertEqual(failed['observed_blocker'], 'CLOUD_UPLOAD_APPLICATION_FAILED')
            self.assertEqual(failed['cleanup'], dict(complete=False, remaining_owned_objects=2))

    def test_schema8_exact_name_and_bound_and_unchanged_export_names(self):
        value = fixture(network_version=2, close_profile=True)
        raw = M['serialize_evidence'](value)
        self.assertEqual(raw, M['OLD']['canonical'](value))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / M['EVIDENCE_NAME']
            for size in (M['MAX_JSON'] + 1, M['CURRENT_MAX_JSON']):
                expanded = raw + b' ' * (size - len(raw)); path.write_bytes(expanded); path.chmod(0o600)
                self.assertEqual(M['read_upload_evidence'](path), (value, expanded))
            path.write_bytes(raw + b' ' * (M['CURRENT_MAX_JSON'] + 1 - len(raw)))
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](path)
            wrong = root / 'other.json'; wrong.write_bytes(raw + b' ' * (M['MAX_JSON'] + 1 - len(raw))); wrong.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'input_boundary'): M['read_upload_evidence'](wrong)
        outputs = []
        for command in ('export-names-v7', 'export-names-v8'):
            result = subprocess.run([sys.executable, '-B', str(HERE / 'cloud-upload-maintenance-evidence.py'), command],
                capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr); outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])


if __name__ == '__main__':
    unittest.main()
