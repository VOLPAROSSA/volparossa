#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert raw-evidence fixtures; no consumer, core, key, tool or network execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-maintenance-evidence.py'))
APP = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-smoke.py'))
OLD = runpy.run_path(str(HERE / 'test-private-storage-fragments-smoke.py'))


def filter_fixture(slot, interface, local, remote):
    table = f'vpa_content_control_adaptive_{slot}'
    rows = [dict(metainfo=dict(version='1.1.3', release_name='Test fixture', json_schema_version=1)),
        dict(table=dict(family='inet', name=table, handle=1))]
    def match(left, right):
        return dict(match=dict(op='==', left=left, right=right))
    for chain, key, source, destination in (
            ('input', 'iifname', remote, local), ('output', 'oifname', local, remote),
            ('forward', None, None, None)):
        rows.append(dict(chain=dict(family='inet', table=table, name=chain,
            type='filter', hook=chain, prio=-20, policy='accept')))
        rules = []
        if key:
            device = match(dict(meta=dict(key=key)), interface)
            for field in ('dport', 'sport'):
                rules.append([device, match(dict(payload=dict(protocol='ip', field='saddr')), source),
                    match(dict(payload=dict(protocol='ip', field='daddr')), destination),
                    match(dict(payload=dict(protocol='udp', field=field)), 41000), dict(accept=None)])
            rules.append([device, dict(drop=None)])
        else:
            rules = [[match(dict(meta=dict(key=key)), interface), dict(drop=None)]
                for key in ('iifname', 'oifname')]
        rows.extend(dict(rule=dict(family='inet', table=table, chain=chain, expr=rule)) for rule in rules)
    return dict(nftables=rows)


def snapshot_fixture(broker, *, routed=False):
    value = dict(nodes={node: dict(links=[], routes=[], tables={}) for node in M['CONTROL_NODES']}, route_checks=None)
    if broker is None: return value
    addresses = M['NET']['PUBLIC_IPS']
    for slot, provider in enumerate(M['CONTROL_PROVIDERS']):
        for node, other, device, index, peerindex, address, gateway in (
                (broker, provider, f'ac{slot}', 10 + slot, 20 + slot, 1, 2),
                (provider, broker, f'ap{slot}', 20 + slot, 10 + slot, 2, 1)):
            snapshot = value['nodes'][node]
            snapshot['links'].append(dict(ifindex=index, ifname=device, link_index=peerindex,
                flags=['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'], kind='veth'))
            snapshot['routes'].extend([
                dict(dst=f'10.241.{83 + slot}.0/30', dev=device, gateway=None,
                    prefsrc=f'10.241.{83 + slot}.{address}', scope='link', protocol='kernel'),
                dict(dst=addresses[other], dev=device, gateway=f'10.241.{83 + slot}.{gateway}',
                    prefsrc=addresses[node], scope=None, protocol='boot')])
            snapshot['tables'][f'vpa_content_control_adaptive_{slot}'] = filter_fixture(slot, device,
                addresses[node], addresses[other])
    if routed:
        value['route_checks'] = {node: dict(
            out=[dict(dst=addresses[node], dev=f'ac{slot}', gateway=f'10.241.{83 + slot}.2', prefsrc=addresses[broker])],
            back=[dict(dst=addresses[broker], dev=f'ap{slot}', gateway=f'10.241.{83 + slot}.1', prefsrc=addresses[node])])
            for slot, node in enumerate(M['CONTROL_PROVIDERS'])}
    return value


def attach_transition(value, *, changed=True, consumer=True):
    peers, layout = value['expected_peers'], value['layout']
    # Current a01-expected-peers.json retains all eleven initialized roles,
    # including contacts/secondary exit that are never custody brokers.
    for node in ('bootstrap1', 'bootstrap2', 'exit2'):
        peers.setdefault(node, f'fixture-{node}')
    previous = next(node for node in M['CONTROL_NODES'][:3] if peers[node] == layout['control_relay_peer_id'])
    current = next(node for node in M['CONTROL_NODES'][:3] if node != previous) if changed else previous
    transition = dict(schema_version=1, kind='storage-maintenance-control-transition',
        original_layout_sha256=hashlib.sha256(M['encoded'](layout)).hexdigest(),
        original_layout_canonical_sha256=hashlib.sha256(M['canonical'](layout)).hexdigest(),
        previous_control_relay_peer_id=peers[previous], current_control_relay_peer_id=peers[current],
        relation='different' if changed else 'same', before=snapshot_fixture(previous),
        detached=snapshot_fixture(None) if changed else None, after=snapshot_fixture(current, routed=True))
    value['control_transition'] = transition
    digest = hashlib.sha256(M['canonical'](transition)).hexdigest()
    for name, phase in value['network'].items():
        phase['layout'] = dict(route_scope=copy.deepcopy(phase['gates']['exit_route_scope']))
        if not consumer and name == 'upload': continue
        phase['layout']['control_transition_sha256'] = digest
        phase['control_privacy']['content_control_pairs'] = {f'ac{i}':
            [M['NET']['PUBLIC_IPS'][current], M['NET']['PUBLIC_IPS'][node]]
            for i, node in enumerate(M['CONTROL_PROVIDERS'])}
    return value


def fixture(*, previous=False, profile_version=1):
    """Complete *synthetic* input for parent aggregate tests, never live proof."""
    pins = M['PROVISIONER']['load_pins'](profile_version)
    provision = dict(version=profile_version, kind='storage-consumer-maintenance-runtime-provision', success=True,
        pins=pins, pins_sha256=hashlib.sha256(M['PROVISIONER']['pins_path'](profile_version).read_bytes()).hexdigest(),
        tools={name: dict(package=name, package_version='1.0-1', bytes=1234, sha256='a' * 64)
            for name in ('gpg', 'gpg-agent', 'gpgconf', 'tar')},
        guest_only=True, source_files_verified=True, runtime_files_verified=True, shared_adapter_verified=True,
        original_licenses_retained=True, storage_enrollment_created=False, peer_storage_proven=False,
        application_restore_proven=False, sdk_or_browser_provisioned=False, immich_or_opencloud_server_started=False)
    digest = hashlib.sha256(M['encoded'](provision)).hexdigest()
    prepared = APP['prepared']()
    prepared['provision_sha256'] = digest
    value = dict(schema_version=1 if previous else 2, kind='storage-consumer-maintenance-evidence', success=True,
        scope=dict(M['SCOPE']), provision=provision, provision_sha256=digest)
    for phase in ('prepare', *M['PHASES']):
        node = prepared if phase == 'prepare' else APP['report'](phase)
        node['provision_sha256'] = digest
        receipt = dict(version=1, kind='storage-consumer-maintenance-orchestration', phase=phase,
            passed=True, node=node, node_report_sha256=hashlib.sha256(json.dumps(node).encode()).hexdigest(),
            provision_sha256=digest, node_joined=True, protected_flow_proven=phase != 'prepare')
        if phase == 'prepare':
            receipt['authority'] = {app: dict(fresh_owner_created=True, owner_distinct_from_providers=True,
                grant_payload_bytes=[prepared[app]['cipher_bytes']] * 3, grant_max_leases=[4] * 3,
                grant_retention_seconds=7200, grant_lifetime_seconds=7200, reserved_credit=0,
                enrollment_created=False, policy_authorization_seconds=6000, policy_lifetime_seconds=3600,
                policy_maximum_charge=3 * prepared[app]['cipher_bytes'], automatic_grant_refresh=False) for app in M['APPS']}
        else:
            receipt.update(minimum_protected_completions=M['PHASES'][phase], sampler_joined=True,
                remote_cleanup_independently_proven=False)
        value[phase] = receipt
    old = OLD['fixture']()
    value.update({k: copy.deepcopy(old[k]) for k in ('layout', 'isolation', 'expected_peers')})
    value['consumer_isolation'] = dict(user_uid=value['isolation']['user_uid'], agent_uid=value['isolation']['agent_uid'],
        agent_mount_positive_control=True, client_cannot_read_new_owner_root=True, client_cannot_read_any_provider_store=True)
    total, amounts, repair = M['geometry'](prepared)
    def usage(amounts, counts):
        return [dict(reserved_bytes=0, committed_bytes=amount, leases=count) for amount, count in zip(amounts, counts)]
    value.update(initial_usage=usage([0] * 3, [0] * 3), uploaded_usage=usage(amounts, [6, 6, 4]),
        restored_usage=usage([amounts[0], total, total], [6, 8, 8]), deleted_usage=usage([0] * 3, [0] * 3),
        withdrawal=dict(first_provider_stopped_before_repair_and_read=True, first_store_retained=True,
            other_two_providers_serving=True, same_three_stores_reopened=True,
            all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True),
        private_cleanup=dict(version=1, kind='storage-consumer-maintenance-cleanup', passed=True,
            local_fixture_removed=True, no_owned_fixture_process_observed=True, removed_files=30, removed_directories=15,
            remote_cleanup_confirmed=False, provider_usage_proven=False), network={})
    for name, minimum in M['PHASES'].items():
        phase = copy.deepcopy(old['network']['upload'])
        selected = phase['selected_route']
        selected.update(exact_selected_exit=selected['paths'][0]['exit_peer_id'],
            exact_selected_relays=[p['relay_peer_id'] for p in selected['paths']])
        for path, slot in zip(selected['paths'], selected['benchmark_slots']):
            path['state'] = 1
            slot['path_id'] = path['path_id']
        scope = M['SAMPLER']['route_scope'](selected)
        phase['layout'] = dict(route_scope=copy.deepcopy(scope))
        gates = phase['gates']
        gates.update(exit_mptcp_tls_completed=minimum, exit_log_records=minimum + 1,
            exit_log_sampling_version=2, exit_log_samples=2, exit_log_observed_records=minimum + 1,
            exit_log_overlap_verified=True, exit_log_sampler_joined=True, exit_route_scope=scope,
            observed_route_context_ids=[selected['route_context_id']],
            exit_flow_contexts=[dict(route_context_id=selected['route_context_id'], completed=minimum, failed=0)])
        app = phase['privacy']['exit']['provider_application']
        if name == 'exercise':
            app[M['NODES'][0]] = dict(request_packets=1, response_packets=0, response_payload_bytes=0)
            for n in M['NODES'][1:]:
                app[n]['response_payload_bytes'] = repair + total  # Framing/extra renew traffic is permitted.
        value['network'][name] = phase
    value['layout']['route_scope'] = copy.deepcopy(value['network']['publish']['layout']['route_scope'])
    if not previous: attach_transition(value)
    return value


def write_evidence(root, value):
    def write(name, data):
        (root / name).write_bytes(M['encoded'](data))
        (root / name).chmod(0o600)
    for name in ('provision', 'prepare', *M['PHASES'], 'withdrawal'):
        write(f'storage-consumer-{name}.json', value[name])
    write('storage-consumer-private-cleanup.json', value['private_cleanup'])
    write('storage-consumer-isolation.json', value['consumer_isolation'])
    write('private-storage-fragments-deleted_usage.json', value['initial_usage'])
    for name in ('uploaded', 'restored', 'deleted'):
        write(f'private-storage-fragments-consumer_{name}_usage.json', value[name + '_usage'])
    for name in ('layout', 'isolation'):
        write(f'private-storage-fragments-{name}.json', value[name])
    write('a01-expected-peers.json', value['expected_peers'])
    if 'control_transition' in value:
        (root / M['TRANSITION_NAME']).write_bytes(M['canonical'](value['control_transition']))
        (root / M['TRANSITION_NAME']).chmod(0o600)
    for name, phase in value['network'].items():
        for field, suffix in (('layout', 'layout'), ('selected_route', 'live-selection'), ('gates', 'gates')):
            write(f'private-storage-fragments-consumer-{name}-{suffix}.json', phase[field])
        write(f'content-provider-adaptive-private-storage-fragments-consumer-{name}-control.json', phase['control_privacy'])
        for role, capture in phase['privacy'].items():
            write(f'private-storage-fragments-consumer-{name}-privacy-{role}.json', capture)


class ControlTransition(unittest.TestCase):
    def test_current_topology_has_exact_eleven_roles_and_bounded_unique_identities(self):
        value = fixture()
        peers, transition = value['expected_peers'], value['control_transition']
        self.assertEqual(set(peers), {'client', 'bootstrap1', 'bootstrap2', 'exit', 'exit2',
            'relay0', 'relay1', 'relay2', 'relay3', 'relay4', 'relay5'})
        M['validate_control_transition'](transition, peers, value['layout'])
        for mutate in (
                *(lambda p, node=node: p.pop(node) for node in peers),
                lambda p: p.update(extra='fixture-extra'),
                lambda p: p.update(bootstrap1=p['client']),
                lambda p: p.update(exit2=p['bootstrap2']),
                lambda p: p.update(bootstrap2=''),
                lambda p: p.update(exit2='x' * 129),
                lambda p: p.update(bootstrap1='not/a/peer'),
                lambda p: p.update(exit2=True)):
            invalid = copy.deepcopy(peers)
            mutate(invalid)
            with self.subTest(peers=invalid), self.assertRaises(ValueError):
                M['validate_control_transition'](transition, invalid, value['layout'])
        for node in ('bootstrap1', 'bootstrap2', 'exit2'):
            invalid = copy.deepcopy(transition)
            invalid['current_control_relay_peer_id'] = peers[node]
            with self.subTest(broker=node), self.assertRaisesRegex(ValueError, 'control_broker_identity'):
                M['validate_control_transition'](invalid, peers, value['layout'])

    def test_real_before_cli_accepts_original_role_geometry_not_kernel_execution(self):
        # Real Python CLI, synthetic kernel snapshots. The original hosted
        # receipt did not retain its intermediate snapshot, so this does not
        # establish which command within broker_validated failed in that run.
        for changed in (False, True):
            value = fixture()
            attach_transition(value, changed=changed)
            partial = copy.deepcopy(value['control_transition'])
            partial.update(detached=None, after=None)
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_evidence(root, value)
                path = root / M['TRANSITION_NAME']
                path.write_bytes(M['encoded'](partial))
                command = [sys.executable, '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                    'control-transition-check', str(root), str(path), 'before']
                result = subprocess.run(command, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                peers_path = root / 'a01-expected-peers.json'
                invalid = dict(value['expected_peers'], extra='fixture-extra')
                peers_path.write_bytes(M['encoded'](invalid))
                result = subprocess.run(command, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)

    def test_same_and_changed_only_pass_after_exact_detach_routes_and_filters(self):
        for changed in (False, True):
            value = fixture()
            attach_transition(value, changed=changed)
            transition = value['control_transition']
            M['validate_evidence'](value)
            for stage in ('before', 'detached', 'complete'):
                partial = copy.deepcopy(transition)
                if stage != 'complete': partial['after'] = None
                if stage == 'before': partial['detached'] = None
                effective = M['validate_control_transition'](partial, value['expected_peers'], value['layout'], stage=stage)
                self.assertEqual(effective['control_relay_peer_id'], transition['current_control_relay_peer_id'])
                if stage != 'complete':
                    with self.assertRaises(ValueError):
                        M['validate_control_transition'](partial, value['expected_peers'], value['layout'])

    def test_link_pair_teardown_and_actual_kernel_routes_are_not_self_reported_labels(self):
        value = fixture()
        current = next(n for n, peer in value['expected_peers'].items()
            if peer == value['control_transition']['current_control_relay_peer_id'])
        for mutate in (
                lambda t: t.update(relation='same'),
                lambda t: t.update(current_control_relay_peer_id=value['expected_peers']['relay3']),
                lambda t: t.update(previous_control_relay_peer_id=value['expected_peers'][current]),
                lambda t: t.update(original_layout_canonical_sha256='0' * 64),
                lambda t: t['detached']['nodes']['relay2']['links'].append(dict(ifname='ac0')),
                lambda t: t['detached']['nodes']['relay3']['routes'].append(dict(dev='ap0')),
                lambda t: t['detached']['nodes']['relay4']['tables'].update(unexpected={}),
                lambda t: t['after']['nodes'][current]['links'][0].update(link_index=999),
                lambda t: t['after']['nodes'][current]['links'][0].update(flags=['UP']),
                lambda t: t['after']['nodes'][current]['routes'][1].update(gateway='10.1.1.1'),
                lambda t: t['after']['nodes'][current]['routes'].append(dict(dev='ac0')),
                lambda t: t['after']['nodes']['relay3']['routes'][1].update(prefsrc='127.0.0.1'),
                lambda t: t['after']['route_checks']['relay4']['out'][0].update(dev='underlay'),
                lambda t: t['after']['route_checks']['relay5']['back'].clear(),
                lambda t: t['after']['nodes'].update(client=dict(links=[], routes=[], tables={})),
                lambda t: t.update(unverified_private_detail='DO_NOT_ACCEPT')):
            invalid = copy.deepcopy(value['control_transition'])
            mutate(invalid)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                M['validate_control_transition'](invalid, value['expected_peers'], value['layout'])

    def test_filter_exact_verdict_order_scope_and_udp_tuple_cannot_be_broadened(self):
        original = filter_fixture(0, 'ac0', '42.158.0.1', '48.164.4.1')
        M['control_filter'](original, 0, 'ac0', '42.158.0.1', '48.164.4.1')
        for mutate in (
                lambda rows: rows[1]['table'].update(name='other'),
                lambda rows: rows[2]['chain'].update(prio=-19),
                lambda rows: rows[2]['chain'].update(policy='drop'),
                lambda rows: rows[3]['rule']['expr'][0]['match'].update(right='underlay'),
                lambda rows: rows[3]['rule']['expr'][1]['match'].update(right='0.0.0.0/0'),
                lambda rows: rows[3]['rule']['expr'][3]['match'].update(right=443),
                lambda rows: rows[3]['rule']['expr'][3]['match']['left']['payload'].update(protocol='tcp'),
                lambda rows: rows[3]['rule']['expr'].pop(),
                lambda rows: rows[5]['rule']['expr'].__setitem__(-1, dict(accept=None)),
                lambda rows: rows.__setitem__(slice(3, 6), rows[5:6] + rows[3:5]),
                lambda rows: rows.pop(),
                lambda rows: rows.append(dict(rule=copy.deepcopy(rows[-1]['rule'])))):
            invalid = copy.deepcopy(original)
            mutate(invalid['nftables'])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                M['control_filter'](invalid, 0, 'ac0', '42.158.0.1', '48.164.4.1')

    def test_phase_hash_and_captured_actual_control_pairs_must_both_match(self):
        value = fixture()
        for phase in M['PHASES']:
            for change in ('hash', 'capture'):
                invalid = copy.deepcopy(value)
                if change == 'hash':
                    invalid['network'][phase]['layout']['control_transition_sha256'] = '0' * 64
                else:
                    previous = next(n for n, peer in value['expected_peers'].items()
                        if peer == value['layout']['control_relay_peer_id'])
                    invalid['network'][phase]['control_privacy']['content_control_pairs']['ac0'][0] = M['NET']['PUBLIC_IPS'][previous]
                with self.subTest(phase=phase, change=change), self.assertRaises(ValueError):
                    M['validate_evidence'](invalid)

    def test_raw_input_binding_and_real_cli_reject_symlinks_oversize_and_noncanonical_complete(self):
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            path = root / M['TRANSITION_NAME']
            command = [sys.executable, '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                'control-transition-check', str(root), str(path), 'complete']
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            canonical = path.read_bytes()
            for raw in (canonical + b'\n', b' ' * (M['MAX_TRANSITION'] + 1),
                    b'{"schema_version":1,"schema_version":1}'):
                path.write_bytes(raw)
                with self.assertRaises((ValueError, KeyError)):
                    M['read_control_transition'](root)
            path.write_bytes(canonical)
            path.chmod(0o644)
            with self.assertRaises(ValueError): M['read_control_transition'](root)
            path.chmod(0o600)
            layout = root / 'private-storage-fragments-layout.json'
            layout.write_bytes(layout.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'original_layout_bytes'):
                M['read_control_transition'](root)
            link = root / 'transition-link'; link.symlink_to(path)
            with self.assertRaises(OSError): M['read_control_transition'](root, path=link)
            fifo = root / 'transition-fifo'; os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError): M['read_control_transition'](root, path=fifo)

    def test_previous_schema_is_explicit_and_never_current_acceptance(self):
        previous = fixture(previous=True)
        self.assertEqual(len(previous['expected_peers']), 8)
        M['validate_evidence'](previous, previous=True)
        with self.assertRaises(ValueError): M['validate_evidence'](previous)
        with self.assertRaises(ValueError): M['validate_evidence'](fixture(), previous=True)
        previous['expected_peers'].update({node: f'fixture-{node}' for node in ('bootstrap1', 'bootstrap2', 'exit2')})
        with self.assertRaisesRegex(ValueError, 'consumer_closed_fields'):
            M['validate_evidence'](previous, previous=True)
        current = fixture()
        for node in ('bootstrap1', 'bootstrap2', 'exit2'):
            current['expected_peers'].pop(node)
        with self.assertRaisesRegex(ValueError, 'consumer_closed_fields'):
            M['validate_evidence'](current)


class ConsumerEvidence(unittest.TestCase):
    def test_profile_ten_binds_close_sources_and_preserves_privacy_custody_and_cleanup(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        value = network['fixture'](10)
        self.assertEqual(M['validate_evidence'](value), value)
        for prior in range(1, 10):
            for mutate in (lambda v, p=prior: v.update(schema_version=p),
                    lambda v, p=prior: v['provision'].update(version=p),
                    lambda v, p=prior: v['provision'].update(pins=M['PROVISIONER']['load_pins'](p))):
                invalid = copy.deepcopy(value); mutate(invalid)
                with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for mutate in (lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(leases=1),
                lambda v: v['private_cleanup'].update(no_owned_fixture_process_observed=False),
                lambda v: v['publish'].update(node_joined=False)):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for arguments in (dict(close_profile=True), dict(close_profile=1),
                *(dict(network_version=2, close_profile=True, **{other: True})
                    for other in ('tls_profile', 'outcome_profile', 'stream_profile', 'challenge_profile', 'append_profile', 'flow_profile'))):
            with self.assertRaises(ValueError): M['build_evidence']('/inert/not-read', **arguments)
        network['ConsumerNetwork']().assert_builder(10)

    def test_profile_nine_binds_exact_sources_and_retains_all_custody_privacy_and_cleanup_gates(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        value = network['fixture'](9)
        self.assertEqual(M['validate_evidence'](value), value)
        for prior in range(1, 9):
            for mutate in (lambda v, p=prior: v.update(schema_version=p),
                    lambda v, p=prior: v['provision'].update(version=p),
                    lambda v, p=prior: v['provision'].update(pins=M['PROVISIONER']['load_pins'](p))):
                invalid = copy.deepcopy(value); mutate(invalid)
                with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for mutate in (lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(leases=1),
                lambda v: v['private_cleanup'].update(no_owned_fixture_process_observed=False),
                lambda v: v['publish'].update(node_joined=False),
                lambda v: v['provision'].update(raw='/private/canary')):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for arguments in (dict(flow_profile=True), dict(flow_profile=1),
                *(dict(network_version=2, flow_profile=True, **{other: True})
                    for other in ('tls_profile', 'outcome_profile', 'stream_profile', 'challenge_profile', 'append_profile'))):
            with self.assertRaises(ValueError): M['build_evidence']('/inert/not-read', **arguments)
        network['ConsumerNetwork']().assert_builder(9)

    def test_profile_eight_binds_new_sources_without_weakening_network_custody_or_cleanup(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        value = network['fixture'](8)
        self.assertEqual(M['validate_evidence'](value), value)
        for prior in range(1, 8):
            for mutate in (lambda v, p=prior: v.update(schema_version=p),
                    lambda v, p=prior: v['provision'].update(version=p),
                    lambda v, p=prior: v['provision'].update(pins=M['PROVISIONER']['load_pins'](p))):
                invalid = copy.deepcopy(value); mutate(invalid)
                with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for mutate in (lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(leases=1),
                lambda v: v['private_cleanup'].update(no_owned_fixture_process_observed=False),
                lambda v: v['publish'].update(node_joined=False),
                lambda v: v['provision'].update(raw='/private/canary')):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for arguments in (dict(append_profile=True), dict(append_profile=1),
                *(dict(network_version=2, append_profile=True, **{other: True})
                    for other in ('tls_profile', 'outcome_profile', 'stream_profile', 'challenge_profile'))):
            with self.assertRaises(ValueError): M['build_evidence']('/inert/not-read', **arguments)
        network['ConsumerNetwork']().assert_builder(8)

    def test_profile_seven_binds_challenge_sources_and_preserves_custody_privacy_and_cleanup(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        value = network['fixture'](7)
        self.assertEqual(M['validate_evidence'](value), value)
        for mutate in (lambda v: v.update(schema_version=6), lambda v: v['provision'].update(version=6),
                lambda v: v['provision'].update(pins=M['PROVISIONER']['load_pins'](6)),
                lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(leases=1)):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for arguments in (dict(challenge_profile=True),
                dict(network_version=2, tls_profile=True, challenge_profile=True),
                dict(network_version=2, outcome_profile=True, challenge_profile=True),
                dict(network_version=2, stream_profile=True, challenge_profile=True)):
            with self.assertRaises(ValueError): M['build_evidence']('/inert/not-read', **arguments)
        network['ConsumerNetwork']().assert_builder(7)

    def test_profile_six_requires_stream_pins_without_relabeling_network_or_custody(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        value = network['fixture'](6)
        self.assertEqual(M['validate_evidence'](value), value)
        self.assertEqual(value['schema_version'], 6)
        for mutate in (lambda v: v.update(schema_version=5), lambda v: v['provision'].update(version=5),
                lambda v: v['provision'].update(pins=M['PROVISIONER']['load_pins'](5)),
                lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(leases=1)):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        for arguments in (dict(stream_profile=True),
                dict(network_version=2, tls_profile=True, stream_profile=True),
                dict(network_version=2, outcome_profile=True, stream_profile=True)):
            with self.assertRaises(ValueError): M['build_evidence']('/inert/not-read', **arguments)
        network['ConsumerNetwork']().assert_builder(6)

    def test_profile_five_requires_new_pins_and_full_dynamic_network_evidence(self):
        network = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
        value = network['fixture'](5)
        self.assertEqual(M['validate_evidence'](value), value)
        self.assertEqual(value['schema_version'], 5)
        for mutate in (lambda v: v.update(schema_version=4), lambda v: v['provision'].update(version=4),
                lambda v: v['provision'].update(pins=M['PROVISIONER']['load_pins'](4)),
                lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['deleted_usage'][0].update(leases=1)):
            invalid = copy.deepcopy(value); mutate(invalid)
            with self.assertRaises(ValueError): M['validate_evidence'](invalid)
        with self.assertRaises(ValueError):
            M['build_evidence']('/inert/not-read', outcome_profile=True)
        with self.assertRaises(ValueError):
            M['build_evidence']('/inert/not-read', network_version=2, tls_profile=True, outcome_profile=True)
        # Reuse the existing complete synthetic file-layout builder assertion;
        # it invokes evidence-v5, not a relabelled older proof or a live core.
        network['ConsumerNetwork']().assert_builder(5)

    def test_profile_three_provision_is_not_a_relabelled_profile_two_receipt(self):
        values = [fixture(profile_version=profile) for profile in (1, 2, 3)]
        for value in values:
            M['validate_evidence'](value)
        self.assertEqual(len({value['provision_sha256'] for value in values}), 3)
        for prior in values[:2]:
            mixed = copy.deepcopy(values[2])
            mixed['provision']['pins'] = prior['provision']['pins']
            with self.assertRaises(ValueError):
                M['validate_provision'](mixed['provision'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, values[2])
            self.assertEqual(M['build_evidence'](root), values[2])

    def test_new_profile_has_independent_source_binding_without_replacing_historical_provision(self):
        old, current = fixture(), fixture(profile_version=2)
        M['validate_evidence'](old)
        M['validate_evidence'](current)
        self.assertNotEqual(old['provision_sha256'], current['provision_sha256'])
        self.assertEqual(old['provision']['version'], 1)
        self.assertEqual(current['provision']['version'], 2)
        for version, pins in ((1, current['provision']['pins']), (2, old['provision']['pins'])):
            value = copy.deepcopy(current['provision'])
            value.update(version=version, pins=pins)
            with self.assertRaises(ValueError):
                M['validate_provision'](value)

    def reject(self, mutate, code=None):
        value = fixture()
        mutate(value)
        with self.assertRaisesRegex(ValueError, code or '.'):
            M['validate_evidence'](value)

    def test_complete_raw_rebuild_exact_exports_and_cli_without_runtime(self):
        value = fixture()
        self.assertEqual(M['validate_evidence'](value), value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, value)
            self.assertEqual(M['build_evidence'](root), value)
            self.assertEqual(set(M['LEGACY_EXPORT_NAMES']) - {'storage-consumer-evidence.json'}, {p.name for p in root.iterdir()})
            self.assertEqual(len(M['EXPORT_NAMES']), len(set(M['EXPORT_NAMES'])))
            output = root / 'storage-consumer-evidence.json'
            for args in (['evidence', str(root), str(output)], ['check', str(output)]):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-maintenance-evidence.py'), *args],
                    capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_bytes()), value)
            (root / 'private-storage-fragments-consumer-exercise-layout.json').unlink()
            with self.assertRaises(FileNotFoundError):
                M['build_evidence'](root)

    def test_pinned_sources_exact_provision_hash_and_scope(self):
        for mutate in (
            lambda v: v['provision']['pins']['sources']['image'].update(revision='0' * 40),
            lambda v: v['provision']['pins']['runtime'].update(sha256='0' * 64),
            lambda v: v['provision'].update(pins_sha256='0' * 64),
            lambda v: v['provision'].update(peer_storage_proven=True),
            lambda v: v['provision'].update(version=True),
            lambda v: v['provision']['tools']['gpg'].update(package='other'),
            lambda v: v.update(provision_sha256='0' * 64),
            lambda v: v['publish'].update(provision_sha256='0' * 64),
            lambda v: v['publish']['node'].update(provision_sha256='0' * 64),
            lambda v: v['scope'].update(host_cleanup_proven=True),
            lambda v: v['scope'].update(node_report_hash_independently_reconstructed=True)):
            with self.subTest(mutate=mutate):
                self.reject(mutate)

    def test_closed_original_application_failure_never_becomes_success(self):
        for phase in ('prepare', *M['PHASES']):
            self.reject(lambda v: v[phase].update(passed=False), 'consumer_orchestration')
            self.reject(lambda v: v[phase]['node'].update(passed=False), 'consumer_orchestration')
        self.reject(lambda v: v['exercise'].update(code='node_phase_failed', cleanup_confirmed=False), 'closed_fields')
        self.reject(lambda v: v['finish'].update(node_joined=False), 'consumer_orchestration')

    def test_authority_and_cipher_geometry_are_not_caller_selected(self):
        for mutate in (
            lambda v: v['prepare']['authority']['cloud'].update(automatic_grant_refresh=True),
            lambda v: v['prepare']['authority']['image'].update(reserved_credit=True),
            lambda v: v['prepare']['authority']['image'].update(grant_max_leases=[8] * 3),
            lambda v: v['prepare']['authority']['image'].update(policy_maximum_charge=10**7),
            lambda v: v['prepare']['node']['image'].update(cipher_bytes=15),
            lambda v: v['publish']['node']['image'].update(cipher_sha256='0' * 64),
            lambda v: v['exercise']['node']['cloud'].update(fragment_count=1),
            lambda v: v['exercise']['node']['image'].update(uncertain_payload_bytes=0)):
            with self.subTest(mutate=mutate):
                self.reject(mutate)

    def test_foreground_read_lifecycle_and_delete_checks_are_all_required(self):
        for name, field, changed in (
            ('image', 'application_decryption_verified', False), ('image', 'plaintext_sha256', '0' * 64),
            ('image', 'cipher_cache_removed_before_read', False), ('image', 'cursor_after', 3),
            ('image', 'observed_old_owner_absent_while_foreground_active', False),
            ('cloud', 'authenticated_get_body_verified', False), ('cloud', 'wrong_token_status', 200),
            ('cloud', 'confirmed_copy_retentions_advanced', 0), ('cloud', 'owner_joined', False),
            ('cloud', 'completed_turn_observed', True), ('image', 'exact_join_before_spawn_measured', True)):
            with self.subTest(field=field):
                self.reject(lambda v: v['exercise']['node'][name].update({field: changed}))
        self.reject(lambda v: v['finish']['node']['image'].update(all_retained_copies_delete_acknowledged=False))
        # Pending handoff intentions persist after acknowledged deletion; usage, not that count, proves zero charge.
        self.assertEqual(fixture()['finish']['node']['image']['pending_retirements'], 3)
        self.reject(lambda v: v['finish']['node']['image'].update(pending_retirements=0))

    def test_independent_store_usage_exact_per_provider_at_each_phase(self):
        for phase in ('initial', 'uploaded', 'restored', 'deleted'):
            for index in range(3):
                for key in ('reserved_bytes', 'committed_bytes', 'leases'):
                    with self.subTest(phase=phase, index=index, key=key):
                        self.reject(lambda v: v[phase + '_usage'][index].update(
                            {key: v[phase + '_usage'][index][key] + 1}), 'consumer_exact_provider_usage')
        self.reject(lambda v: v['deleted_usage'][0].update(leases=False), 'consumer_exact_provider_usage')

    def test_new_private_owner_probe_with_positive_control_and_cleanup(self):
        for field in ('agent_mount_positive_control', 'client_cannot_read_new_owner_root', 'client_cannot_read_any_provider_store'):
            self.reject(lambda v: v['consumer_isolation'].update({field: False}), 'consumer_new_owner_isolation')
        self.reject(lambda v: v['consumer_isolation'].update(user_uid=1001), 'consumer_new_owner_isolation')
        self.reject(lambda v: v['private_cleanup'].update(local_fixture_removed=False), 'consumer_private_cleanup')
        self.reject(lambda v: v['private_cleanup'].update(removed_files=512), 'consumer_private_cleanup')
        self.reject(lambda v: v['private_cleanup'].update(remote_cleanup_confirmed=True), 'consumer_private_cleanup')
        self.reject(lambda v: v['withdrawal'].update(all_three_store_inodes_preserved=False), 'consumer_store_withdrawal')

    def test_phase_specific_minima_and_continuous_actual_exit_scope(self):
        for name, minimum in M['PHASES'].items():
            self.reject(lambda v: v[name].update(minimum_protected_completions=minimum - 1), 'consumer_flow_scope')
            self.reject(lambda v: v['network'][name]['gates'].update(exit_mptcp_tls_completed=minimum - 1))
            self.reject(lambda v: v['network'][name]['gates'].update(exit_log_sampler_joined=False))
            self.reject(lambda v: v['network'][name]['layout']['route_scope'].update(exit_peer_id='other'))
            self.reject(lambda v: v['network'][name]['selected_route'].update(transport='tcp'))
        self.reject(lambda v: v['network']['publish']['gates'].update(exit_log_sampling_version=1))

    def test_failed_a_flows_are_retained_not_mislabelled_as_bypass(self):
        value = fixture()
        gates = value['network']['exercise']['gates']
        gates.update(exit_mptcp_tls_failed=3, exit_log_observed_records=20)
        gates['exit_flow_contexts'][0]['failed'] = 3
        M['validate_evidence'](value)
        self.assertEqual(gates['exit_mptcp_tls_failed'], 3)

    def test_context_rotation_does_not_rebind_to_old_global_context(self):
        value = fixture()
        phase = value['network']['exercise']
        new = 'b' * 32
        phase['selected_route']['route_context_id'] = new
        for path in phase['selected_route']['paths']:
            path['route_context_id'] = new
        phase['gates']['observed_route_context_ids'] = [new]
        phase['gates']['exit_flow_contexts'][0]['route_context_id'] = new
        M['validate_evidence'](value)
        phase['gates']['exit_flow_contexts'][0]['completed'] = 0
        with self.assertRaises(ValueError):
            M['validate_evidence'](value)

    def test_survivor_payload_bounds_follow_actual_four_fragment_repair_not_old_restore(self):
        value = fixture()
        total, _, repair = M['geometry'](value['prepare']['node'])
        app = value['network']['exercise']['privacy']['exit']['provider_application']
        # Either survivor can supply the application reads, after both verified repairs.
        for reader in ('relay5', 'relay3'):
            for node in ('relay5', 'relay3'):
                app[node]['response_payload_bytes'] = repair + (total if node == reader else 0)
            M['validate_evidence'](value)
        for node in ('relay5', 'relay3'):
            self.reject(lambda v: v['network']['exercise']['privacy']['exit']['provider_application'][node].update(
                response_payload_bytes=repair - 1), 'consumer_survivor_payload')
        app['relay5']['response_payload_bytes'] = repair
        app['relay3']['response_payload_bytes'] = repair + total - 1
        with self.assertRaisesRegex(ValueError, 'consumer_survivor_payload'):
            M['validate_evidence'](value)
        self.reject(lambda v: v['network']['exercise']['privacy']['exit']['provider_application']['relay4'].update(
            response_payload_bytes=1), 'consumer_withdrawn_provider_responded')

    def test_privacy_controls_actual_both_legs_and_capture_drain(self):
        for mutate in (
            lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['network']['publish']['privacy']['relay0'].update(internet_destination_outer_packets=1),
            lambda v: v['network']['publish']['privacy']['exit'].update(client_public_packets=1),
            lambda v: v['network']['publish']['privacy']['relay1'].update(exit_leg_wireguard_data_datagrams=16),
            lambda v: v['network']['publish']['privacy']['exit'].update(packet_socket_drops=1),
            lambda v: v['network']['publish']['privacy']['exit'].update(truncated=True),
            lambda v: v['network']['exercise']['control_privacy'].update(unexpected_provider_control_packets=1),
            lambda v: v['network']['exercise']['control_privacy']['provider_application']['relay3'].update(request_packets=1),
            lambda v: v['network']['finish']['privacy']['client']['provider_application']['relay4'].update(request_packets=1),
            lambda v: v['network']['finish']['privacy']['exit']['provider_application']['relay3'].update(request_packets=0)):
            with self.subTest(mutate=mutate):
                self.reject(mutate)

    def test_closed_envelopes_reject_extra_fields_and_false_success(self):
        for mutate in (lambda v: v.update(raw_log='secret'), lambda v: v.update(schema_version=True),
            lambda v: v.update(success=False), lambda v: v['prepare'].update(private_path='/private'),
            lambda v: v['network']['exercise'].update(restore=True),
            lambda v: v['prepare']['node']['image'].update(owner_key='secret')):
            self.reject(mutate)


class EvidenceFiles(unittest.TestCase):
    def test_noncanonical_provision_file_cannot_reuse_a_different_original_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_evidence(root, fixture())
            path = root / 'storage-consumer-provision.json'
            path.write_text(json.dumps(json.loads(path.read_bytes())))
            with self.assertRaisesRegex(ValueError, 'consumer_provision_encoding'):
                M['build_evidence'](root)

    def test_same_fd_file_type_size_links_mode_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'receipt.json'
            path.write_bytes(b'{}')
            path.chmod(0o600)
            self.assertEqual(M['read'](path), ({}, b'{}'))
            for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'', b' ' * (M['MAX_JSON'] + 1)):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    M['read'](path)
            path.write_bytes(b'{}')
            path.chmod(0o622)
            with self.assertRaises(ValueError):
                M['read'](path)
            path.chmod(0o600)
            os.link(path, root / 'hardlink')
            with self.assertRaises(ValueError):
                M['read'](path)
            (root / 'symlink').symlink_to(path)
            with self.assertRaises(OSError):
                M['read'](root / 'symlink')
            os.mkfifo(root / 'fifo', 0o600)
            with self.assertRaises(ValueError):
                M['read'](root / 'fifo')


if __name__ == '__main__':
    unittest.main()
