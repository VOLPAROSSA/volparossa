#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent closed evidence for the additional automatic-upload continuation.

Original maintenance/consumer acceptance remains mandatory and unchanged.
Synthetic application data and a real Cloud service are not a full account
server deployment, arbitrary service lifetime, or host-cleanup proof.
"""
import hashlib
import json
from pathlib import Path
import re
import runpy
import sys

HERE = Path(__file__).resolve().parent
APP = runpy.run_path(str(HERE / 'cloud-upload-maintenance-smoke.py'))
OLD = runpy.run_path(str(HERE / 'storage-consumer-maintenance-evidence.py'))
F, SAMPLER, PROVISIONER = APP['BASE'], APP['SAMPLER'], APP['PROVISIONER']
NET, ROLES, NODES = F['NET'], F['ROLES'], F['NODES']
require, keys, count, sha, encoded, read = (OLD[n] for n in ('require', 'keys', 'count', 'sha', 'encoded', 'read'))
PHASES, MAX_JSON = APP['FLOW_MINIMUM'], OLD['MAX_JSON']
CURRENT_MAX_JSON = 2 * MAX_JSON
EVIDENCE_NAME = 'cloud-upload-evidence.json'
SCOPE = dict(synthetic_inputs=True, automatic_grant_refresh=False, private_keys_exported=False,
    opencloud_account_server_proven=False, node_report_hash_independently_reconstructed=False,
    host_cleanup_proven=False, upload_enrollment_ordering_source_enforced=True, io_ordering_measured=False)
EXPORT_NAMES = (
    'cloud-upload-maintenance-smoke.json', 'private-storage-maintenance-smoke.json',
    'storage-consumer-evidence.json', 'private-storage-fragments-consumer_deleted_usage.json',
    'a01-expected-peers.json', 'private-storage-fragments-layout.json', 'private-storage-fragments-isolation.json',
    OLD['TRANSITION_NAME'],
    *(f'cloud-upload-{name}.json' for name in ('provision', 'prepare', *PHASES, 'withdrawal', 'private-cleanup', 'isolation', 'evidence')),
    *(f'private-storage-fragments-cloud_upload_{name}_usage.json' for name in ('uploaded', 'restored', 'deleted')),
    *(filename for phase in PHASES for filename in (
        f'private-storage-fragments-cloud-upload-{phase}-layout.json',
        f'private-storage-fragments-cloud-upload-{phase}-live-selection.json',
        f'private-storage-fragments-cloud-upload-{phase}-gates.json',
        f'content-provider-adaptive-private-storage-fragments-cloud-upload-{phase}-control.json',
        *(f'private-storage-fragments-cloud-upload-{phase}-privacy-{role}.json' for role in ROLES))))
CURRENT_EXPORT_NAMES = ('storage-consumer-control-underlay.json',
    *(f'cloud-upload-{phase}-control-{suffix}.json'
        for phase in PHASES for suffix in ('before', 'after', 'relay0', 'relay1', 'relay2')))


def serialize_evidence(value):
    # Current matrix snapshots repeat across phases. Compact encoding preserves
    # full originals without reformatting historical proof bytes. Schemas 3/4/5/6/7
    # have a separate 2MiB bound; emergency collection retains its 8MiB ceiling.
    return OLD['canonical'](value) if value['schema_version'] in (3, 4, 5, 6, 7) else encoded(value)


def evidence_limit(path, version):
    return CURRENT_MAX_JSON if Path(path).name == EVIDENCE_NAME and type(version) is int and version in (3, 4, 5, 6, 7) else MAX_JSON


def read_upload_evidence(path):
    path = Path(path)
    value, raw = read(path, maximum=CURRENT_MAX_JSON if path.name == EVIDENCE_NAME else MAX_JSON)
    require(type(value) is dict, 'upload_evidence_identity')
    require(len(raw) <= evidence_limit(path, value.get('schema_version')), 'upload_evidence_bound')
    validate_evidence(value)
    return value, raw


def validate_orchestration(value, phase, provision_sha, uploaded, prepared_authority, *, network_layout=None):
    dynamic = network_layout is not None and phase != 'prepare'
    extra = ('authority',) if phase == 'prepare' else (
        'minimum_protected_completions', 'sampler_joined', 'remote_cleanup_independently_proven')
    keys(value, ('version', 'kind', 'phase', 'passed', 'node', 'node_report_sha256',
        'provision_sha256', 'node_joined', 'protected_flow_proven', *extra,
        *(('network_version', 'control_underlay_sha256') if dynamic else ())))
    require(type(value['version']) is int and value['version'] == (2 if dynamic else 1)
        and value['kind'] == 'cloud-upload-maintenance-orchestration' and value['phase'] == phase
        and value['passed'] is True and value['node_joined'] is True
        and value['provision_sha256'] == provision_sha and sha(value['node_report_sha256'])
        and value['node'].get('passed') is True, 'upload_orchestration')
    APP['validate_node_report'](value['node'], phase, provision_sha, uploaded)
    if phase == 'prepare':
        require(value['protected_flow_proven'] is False, 'upload_prepare_not_flow_proof')
        authority = value['authority']
        hashes = ('service_config_sha256', 'storage_template_sha256')
        fixed = dict(fresh_owner_created=True, owner_distinct_from_providers=True,
            grant_payload_bytes=[APP['MAX_CIPHER']] * 3, grant_max_leases=[4] * 3,
            grant_retention_seconds=7200, grant_lifetime_seconds=7200, reserved_credit=0,
            enrollment_created=False, automatic_grant_refresh=False, policy_lifetime_seconds=3600,
            policy_maximum_charge=3 * APP['MAX_CIPHER'], policy_max_sessions=1)
        keys(authority, (*fixed, 'policy_expires_at', *hashes))
        require(encoded({k: authority[k] for k in fixed}) == encoded(fixed)
            and count(authority['policy_expires_at'], 1, 2**53 - 1) and all(sha(authority[k]) for k in hashes),
            'upload_finite_authority')
    else:
        if dynamic:
            require(type(value['network_version']) is int and value['network_version'] == 2
                and value['control_underlay_sha256'] == network_layout['control_underlay_sha256'],
                'upload_orchestration_network')
        require(value['protected_flow_proven'] is True and value['sampler_joined'] is True
            and type(value['minimum_protected_completions']) is int
            and value['minimum_protected_completions'] == APP['flow_minimum'](phase, uploaded)
            and value['remote_cleanup_independently_proven'] is False, 'upload_flow_scope')
        require(value['node']['authority']['expires_at'] == prepared_authority['policy_expires_at'], 'upload_absolute_expiry')


def custody_usage(uploaded, *, withdrawn):
    size = uploaded['cipher_bytes']
    lengths = APP['geometry'](size)
    retired = APP['baseline'](uploaded['baseline'], size)
    result = [dict(reserved_bytes=0, committed_bytes=0, leases=0) for _ in NODES]
    for index, size in enumerate(lengths):
        providers = [(index + copy) % 3 for copy in range(2)]
        if index in retired:
            providers.remove(0)
        if index in retired or withdrawn and index != 1:
            providers.append(2 if index in (0, 3) else 1)
        for provider in providers:
            result[provider]['committed_bytes'] += size
            result[provider]['leases'] += 1
    return result


def usage(actual, expected):
    require(type(actual) is list and len(actual) == 3, 'upload_usage_count')
    for record, original in zip(actual, expected):
        keys(record, ('reserved_bytes', 'committed_bytes', 'leases'))
        require(all(count(n) for n in record.values()) and record == original, 'upload_exact_store_usage')


def validate_network(phase, peers, layout, name, size, repair_bytes, minimum, transition_sha):
    """Unchanged privacy/route predicates, explicit new phases and byte bounds.

    Each still-live original A fragment needs its B/C survivor read and other
    B/C target readback. Two later cold HTTP GETs additionally read 2*T bytes.
    Pre-withdrawal replacements are not counted again as post-loss reads.
    """
    keys(phase, ('layout', 'selected_route', 'privacy', 'control_privacy', 'gates'))
    keys(phase['layout'], ('route_scope', 'control_transition_sha256'))
    require(phase['layout']['control_transition_sha256'] == transition_sha, 'upload_phase_transition')
    selected, privacy, gates = phase['selected_route'], phase['privacy'], phase['gates']
    SAMPLER['validate_summary'](gates, gates['event_baseline_unix_ms'], minimum)
    SAMPLER['validate_phase_route'](phase['layout']['route_scope'], selected, gates)
    paths, slots = selected['paths'], selected['benchmark_slots']
    require(layout['provider_nodes'] == list(NODES) and len({peers[n] for n in NODES}) == 3
        and layout['control_relay_peer_id'] in {peers[n] for n in ROLES[1:4]}, 'upload_provider_roles')
    require(selected['transport'] == 'mptcp' and len(paths) == len(slots) == 2
        and len({p['relay_peer_id'] for p in paths}) == 2 and {p['exit_peer_id'] for p in paths} == {peers['exit']}
        and all(p['route_context_id'] == selected['route_context_id'] for p in paths)
        and [p['relay_peer_id'] for p in paths] == [s['relay_peer_id'] for s in slots], 'upload_protected_mptcp')
    forbidden = {peers['client'], peers['exit'], layout['control_relay_peer_id']} | {p['relay_peer_id'] for p in paths}
    require(all(peers[n] not in forbidden for n in NODES), 'upload_provider_path_overlap')
    relays = [s['relay_node'] for s in slots]
    require(len(set(relays)) == 2 and all(r in ROLES[1:4] for r in relays)
        and all(peers[s['relay_node']] == s['relay_peer_id'] for s in slots), 'upload_physical_relays')
    keys(privacy, ROLES)
    for role, capture in privacy.items():
        require(capture['capture_role'] == role and capture['content_provider_mode'] is True
            and capture['unexpected_outer_packets'] == capture['unexpected_provider_application_packets'] == 0
            and capture['expected_link_down_notifications'] == 0, 'upload_unexpected_egress')
        OLD['provider_counters'](capture)
        NET['validate_drained'](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != 'exit':
            require(all(n == 0 for counters in capture['provider_application'].values() for n in counters.values()), 'upload_provider_bypass')
    require(privacy['client']['direct_client_exit_packets'] == privacy['client']['internet_destination_outer_packets'] == 0
        and privacy['exit']['direct_client_exit_packets'] == privacy['exit']['client_public_packets'] == 0
        and privacy['exit']['outbound_client_discovery_attempt_packets'] == 0
        and all(privacy[r]['internet_destination_outer_packets'] == 0 for r in ROLES[1:4]), 'upload_privacy')
    for relay in relays:
        require(privacy[relay]['client_leg_wireguard_data_datagrams'] > 16
            and privacy[relay]['exit_leg_wireguard_data_datagrams'] > 16, 'upload_two_leg_traffic')
    application = privacy['exit']['provider_application']
    for node in NODES[1:] if name == 'exercise' else NODES:
        require(application[node]['request_packets'] > 0 and application[node]['response_packets'] > 0, 'upload_provider_traffic')
    if name == 'exercise':
        require(application[NODES[0]]['response_payload_bytes'] == 0, 'upload_withdrawn_provider_responded')
        actual = [application[node]['response_payload_bytes'] for node in NODES[1:]]
        require(all(n >= repair_bytes for n in actual) and sum(actual) >= 2 * repair_bytes + 2 * size, 'upload_survivor_payload')
    control = phase['control_privacy']
    control_node = next(n for n in ROLES[1:4] if peers[n] == layout['control_relay_peer_id'])
    pairs = {f'ac{i}': [NET['PUBLIC_IPS'][control_node], NET['PUBLIC_IPS'][node]]
        for i, node in enumerate(('relay3', 'relay4', 'relay5'))}
    require(control['capture_role'] == 'content-control' and control['content_provider_mode'] is True
        and control['content_control_pairs'] == pairs and set(control['interfaces']) == set(pairs)
        and set(control['content_control_packets']) == set(pairs)
        and control['unexpected_provider_control_packets'] == control['unexpected_provider_application_packets'] == 0,
        'upload_control_boundary')
    OLD['provider_counters'](control)
    require(all(n == 0 for values in control['provider_application'].values() for n in values.values()), 'upload_control_payload')
    NET['validate_drained'](control, allow_empty=True)


def validate_evidence(value):
    keys(value, ('schema_version', 'kind', 'success', 'scope', 'previous_consumers', 'provision', 'provision_sha256',
        'prepare', *PHASES, 'withdrawal', 'private_cleanup', 'initial_usage', 'uploaded_usage', 'restored_usage',
        'deleted_usage', 'expected_peers', 'layout', 'isolation', 'upload_isolation', 'network'))
    require(type(value['schema_version']) is int and value['schema_version'] in (2, 3, 4, 5, 6, 7)
        and value['kind'] == 'cloud-upload-maintenance-evidence' and value['success'] is True, 'upload_evidence_identity')
    require(encoded(value['scope']) == encoded(SCOPE), 'upload_evidence_scope')
    OLD['validate_evidence'](value['previous_consumers'])
    dynamic = value['schema_version'] in (3, 4, 5, 6, 7)
    stream_profile = value['schema_version'] == 4
    challenge_profile = value['schema_version'] == 5
    append_profile = value['schema_version'] == 6
    flow_profile = value['schema_version'] == 7
    require(value['previous_consumers']['schema_version'] == (9 if flow_profile else 8 if append_profile else 7 if challenge_profile else 6 if stream_profile else 5 if dynamic else 2),
        'upload_previous_profile')
    PROVISIONER['validate_provision'](value['provision'])
    require(value['provision']['version'] == (5 if flow_profile else 4 if append_profile else 3 if challenge_profile else 2 if stream_profile else 1), 'upload_source_profile')
    provision_sha = hashlib.sha256(encoded(value['provision'])).hexdigest()
    require(value['provision_sha256'] == provision_sha
        and value['provision']['previous_consumer_provision_sha256'] == value['previous_consumers']['provision_sha256'], 'upload_provision_hash')
    for field in ('expected_peers', 'layout', 'isolation'):
        require(encoded(value[field]) == encoded(value['previous_consumers'][field]), 'upload_previous_fixture_binding')
    # Keep the original upload layout immutable. The additional Cloud phases
    # run after the real core restart and the mandatory, kernel-checked rebind.
    transition = value['previous_consumers']['control_transition']
    current_layout = OLD['validate_control_transition'](transition, value['expected_peers'], value['layout'])
    transition_sha = hashlib.sha256(OLD['canonical'](transition)).hexdigest()
    network, network_layout = None, None
    if dynamic:
        network = runpy.run_path(str(HERE / 'storage-consumer-network.py'))
        underlay = value['previous_consumers']['control_underlay']
        network_layout = network['layout'](underlay, value['expected_peers'])
    require(encoded(value['initial_usage']) == encoded(value['previous_consumers']['deleted_usage']), 'upload_previous_zero_binding')
    prepared_authority = value['prepare']['authority']
    uploaded = value['upload']['node']
    for phase in ('prepare', *PHASES):
        validate_orchestration(value[phase], phase, provision_sha, uploaded, prepared_authority,
            network_layout=network_layout)
    zero = [dict(reserved_bytes=0, committed_bytes=0, leases=0) for _ in NODES]
    usage(value['initial_usage'], zero)
    usage(value['uploaded_usage'], custody_usage(uploaded, withdrawn=False))
    usage(value['restored_usage'], custody_usage(uploaded, withdrawn=True))
    usage(value['deleted_usage'], zero)
    require(encoded(value['withdrawal']) == encoded(dict(first_provider_stopped_after_measured_upload_baseline=True,
        first_provider_stopped_before_new_repair_and_reads=True, first_store_retained=True,
        other_two_providers_serving=True, same_three_stores_reopened=True,
        all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True)), 'upload_store_withdrawal')
    cleanup = value['private_cleanup']
    keys(cleanup, ('version', 'kind', 'passed', 'local_fixture_removed', 'no_owned_fixture_process_observed',
        'removed_files', 'removed_directories', 'remote_cleanup_confirmed', 'provider_usage_proven'))
    require(type(cleanup['version']) is int and cleanup['version'] == 1 and cleanup['kind'] == 'cloud-upload-maintenance-cleanup'
        and cleanup['passed'] is True and cleanup['local_fixture_removed'] is True and cleanup['no_owned_fixture_process_observed'] is True
        and count(cleanup['removed_files'], 1, 512) and count(cleanup['removed_directories'], 1, 512)
        and cleanup['removed_files'] + cleanup['removed_directories'] <= 513
        and cleanup['remote_cleanup_confirmed'] is False and cleanup['provider_usage_proven'] is False, 'upload_private_cleanup')
    isolation = value['isolation']
    require(encoded(value['upload_isolation']) == encoded(dict(user_uid=isolation['user_uid'], agent_uid=isolation['agent_uid'],
        agent_mount_positive_control=True, client_cannot_read_new_owner_root=True,
        client_cannot_read_any_provider_store=True)), 'upload_new_owner_isolation')
    size = uploaded['cipher_bytes']
    lengths = APP['geometry'](size)
    repair_bytes = sum(lengths[i] for i in (0, 2, 3) if i not in uploaded['baseline']['retired_original_a'])
    keys(value['network'], PHASES)
    for name, phase in value['network'].items():
        minimum = APP['flow_minimum'](name, uploaded)
        if dynamic:
            network['validate_network'](phase, value['expected_peers'], current_layout, name,
                2 * size, repair_bytes, underlay, minimum=minimum)
        else:
            validate_network(phase, value['expected_peers'], current_layout, name, size, repair_bytes,
                minimum, transition_sha)
    return value


def build_evidence(work, *, network_version=1, stream_profile=False, challenge_profile=False, append_profile=False, flow_profile=False):
    require(type(network_version) is int and network_version in (1, 2), 'upload_network_version')
    require(type(stream_profile) is bool and (not stream_profile or network_version == 2), 'upload_stream_profile')
    require(type(challenge_profile) is bool and (not challenge_profile or network_version == 2 and not stream_profile),
        'upload_challenge_profile')
    require(type(append_profile) is bool and (not append_profile or network_version == 2 and not (stream_profile or challenge_profile)),
        'upload_append_profile')
    require(type(flow_profile) is bool and (not flow_profile or network_version == 2
        and not (stream_profile or challenge_profile or append_profile)), 'upload_flow_profile')
    work = Path(work)
    def get(name):
        return read(work / name)[0]
    provision, raw = read(work / 'cloud-upload-provision.json')
    require(raw == encoded(provision), 'upload_provision_encoding')
    previous = get('storage-consumer-evidence.json')
    require(type(previous) is dict and previous.get('schema_version') == (9 if flow_profile else 8 if append_profile else 7 if challenge_profile else 6 if stream_profile else 5 if network_version == 2 else 2),
        'upload_previous_profile')
    # Reconstruct the original mandatory component independently as well; a
    # standalone invented old report is not enough in the joined raw builder.
    previous_options = (dict(network_version=2, flow_profile=True) if flow_profile
        else dict(network_version=2, append_profile=True) if append_profile
        else dict(network_version=2, challenge_profile=True) if challenge_profile
        else dict(network_version=2, stream_profile=True) if stream_profile
        else dict(network_version=2, outcome_profile=True) if network_version == 2 else {})
    require(encoded(previous) == encoded(OLD['build_evidence'](work, **previous_options)), 'upload_previous_raw_binding')
    value = dict(schema_version=7 if flow_profile else 6 if append_profile else 5 if challenge_profile else 4 if stream_profile else 3 if network_version == 2 else 2,
        kind='cloud-upload-maintenance-evidence', success=True, scope=dict(SCOPE),
        previous_consumers=previous, provision=provision, provision_sha256=hashlib.sha256(raw).hexdigest(),
        **{name: get(f'cloud-upload-{name}.json') for name in ('prepare', *PHASES, 'withdrawal')},
        private_cleanup=get('cloud-upload-private-cleanup.json'),
        initial_usage=get('private-storage-fragments-consumer_deleted_usage.json'),
        **{name + '_usage': get(f'private-storage-fragments-cloud_upload_{name}_usage.json') for name in ('uploaded', 'restored', 'deleted')},
        expected_peers=get('a01-expected-peers.json'), layout=get('private-storage-fragments-layout.json'),
        isolation=get('private-storage-fragments-isolation.json'), upload_isolation=get('cloud-upload-isolation.json'))
    value['network'] = {name: dict(layout=get(f'private-storage-fragments-cloud-upload-{name}-layout.json'),
        selected_route=get(f'private-storage-fragments-cloud-upload-{name}-live-selection.json'),
        gates=get(f'private-storage-fragments-cloud-upload-{name}-gates.json'),
        privacy={role: get(f'private-storage-fragments-cloud-upload-{name}-privacy-{role}.json') for role in ROLES}) for name in PHASES}
    for name, phase in value['network'].items():
        if network_version == 2:
            phase.update(control_before=get(f'cloud-upload-{name}-control-before.json'),
                control_after=get(f'cloud-upload-{name}-control-after.json'),
                control_privacy={broker: get(f'cloud-upload-{name}-control-{broker}.json')
                    for broker in ('relay0', 'relay1', 'relay2')})
        else:
            phase['control_privacy'] = get(f'content-provider-adaptive-private-storage-fragments-cloud-upload-{name}-control.json')
    return validate_evidence(value)


def validate_report(value, revision, maintenance, maintenance_raw, upload, upload_raw, *, current=False,
        stream_profile=False, challenge_profile=False, append_profile=False, flow_profile=False):
    """Require original complete siblings; compact hashes never replace proofs."""
    require(all(type(flag) is bool for flag in (current, stream_profile, challenge_profile, append_profile, flow_profile))
        and sum((current, stream_profile, challenge_profile, append_profile, flow_profile)) <= 1, 'upload_report_profile')
    keys(value, ('schema_version', 'report_kind', 'source_revision', 'run_id', 'phase', 'runner_exit_status',
        'success', 'observed_blocker', 'cleanup', 'maintenance_report_sha256', 'upload_evidence_sha256', 'scope'))
    require(type(value['schema_version']) is int and value['schema_version'] == (5 if flow_profile else 4 if append_profile else 3 if challenge_profile else 2 if stream_profile else 1)
        and value['report_kind'] == 'volparossa-cloud-upload-maintenance'
        and type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision)
        and value['source_revision'] == revision and type(value['run_id']) is str
        and re.fullmatch('[0-9a-f]{32}', value['run_id']) and value['run_id'] == maintenance['run_id']
        and value['phase'] == maintenance['phase'] == 'private-storage-maintenance-complete'
        and type(value['runner_exit_status']) is int and value['runner_exit_status'] == 0
        and value['success'] is True and value['observed_blocker'] is None
        and encoded(value['cleanup']) == encoded(dict(complete=True, remaining_owned_objects=0))
        and encoded(value['scope']) == encoded(SCOPE), 'upload_source_bound_cleanup')
    require(value['maintenance_report_sha256'] == hashlib.sha256(maintenance_raw).hexdigest()
        and value['upload_evidence_sha256'] == hashlib.sha256(upload_raw).hexdigest(), 'upload_original_report_hash')
    runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))['validate_report'](
        maintenance, revision, stream_profile=stream_profile, challenge_profile=challenge_profile, append_profile=append_profile, flow_profile=flow_profile)
    validate_evidence(upload)
    require(upload['schema_version'] in ((7,) if flow_profile else (6,) if append_profile else (5,) if challenge_profile else (4,) if stream_profile else (3,) if current else (2, 3)),
        'upload_current_profile_required')
    require(encoded(upload['previous_consumers']) == encoded(maintenance['consumers']), 'upload_original_consumer_report')
    return value


def check_report(path, revision, *, current=False, stream_profile=False, challenge_profile=False, append_profile=False, flow_profile=False):
    value, _ = read(path)
    maintenance, maintenance_raw = read(path.parent / 'private-storage-maintenance-smoke.json')
    upload, upload_raw = read_upload_evidence(path.parent / EVIDENCE_NAME)
    return validate_report(value, revision, maintenance, maintenance_raw, upload, upload_raw,
        current=current, stream_profile=stream_profile, challenge_profile=challenge_profile, append_profile=append_profile, flow_profile=flow_profile)


def final_report(work, revision, run, phase, status, complete, remaining, blocker, *, current=False,
        stream_profile=False, challenge_profile=False, append_profile=False, flow_profile=False):
    require(all(type(flag) is bool for flag in (current, stream_profile, challenge_profile, append_profile, flow_profile))
        and sum((current, stream_profile, challenge_profile, append_profile, flow_profile)) <= 1, 'upload_report_profile')
    require(re.fullmatch('[0-9a-f]{40}', revision) and re.fullmatch('[0-9a-f]{32}', run)
        and re.fullmatch('[A-Za-z0-9_.:-]{1,128}', phase) and re.fullmatch('[A-Z0-9_]{1,128}', blocker)
        and type(status) is int and 0 <= status <= 255 and type(complete) is bool
        and count(remaining, 0, 100000), 'upload_final_arguments')
    result = dict(schema_version=5 if flow_profile else 4 if append_profile else 3 if challenge_profile else 2 if stream_profile else 1, report_kind='volparossa-cloud-upload-maintenance', source_revision=revision,
        run_id=run, phase=phase, runner_exit_status=status, success=False,
        observed_blocker=None if blocker == 'NONE' else blocker,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining),
        maintenance_report_sha256=None, upload_evidence_sha256=None, scope=dict(SCOPE))
    records = []
    for filename, field in (('private-storage-maintenance-smoke.json', 'maintenance_report_sha256'),
            ('cloud-upload-evidence.json', 'upload_evidence_sha256')):
        try:
            value, raw = read_upload_evidence(work / filename) if filename == EVIDENCE_NAME else read(work / filename)
            result[field] = hashlib.sha256(raw).hexdigest()
            records.extend((value, raw))
        except (OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError):
            records.extend((None, b''))
    candidate = dict(result, success=True)
    try:
        validate_report(candidate, revision, *records, current=current, stream_profile=stream_profile,
            challenge_profile=challenge_profile, append_profile=append_profile, flow_profile=flow_profile)
        result['success'] = True
    except (ValueError, KeyError, TypeError, OSError, RecursionError, StopIteration):
        pass  # Preserve the primary terminal outcome; missing proof stays false.
    return result


def main(arguments):
    if len(arguments) == 1 and arguments[0] == 'export-names':
        print('\n'.join(EXPORT_NAMES))
    elif len(arguments) == 1 and arguments[0] in ('export-names-v3', 'export-names-v4', 'export-names-v5', 'export-names-v6', 'export-names-v7'):
        print('\n'.join((*EXPORT_NAMES, *CURRENT_EXPORT_NAMES)))
    elif len(arguments) == 2 and arguments[0] == 'check':
        read_upload_evidence(Path(arguments[1]))
    elif len(arguments) == 3 and arguments[0] in ('evidence', 'evidence-v3', 'evidence-v4', 'evidence-v5', 'evidence-v6', 'evidence-v7'):
        value = build_evidence(Path(arguments[1]), network_version=1 if arguments[0] == 'evidence' else 2,
            stream_profile=arguments[0] == 'evidence-v4', challenge_profile=arguments[0] == 'evidence-v5',
            append_profile=arguments[0] == 'evidence-v6', flow_profile=arguments[0] == 'evidence-v7')
        raw = serialize_evidence(value)
        require(len(raw) <= evidence_limit(arguments[2], value['schema_version']), 'upload_evidence_bound')
        F['create'](Path(arguments[2]), raw)
    elif len(arguments) == 3 and arguments[0] in ('check-report', 'check-report-v3', 'check-report-v4', 'check-report-v5', 'check-report-v6', 'check-report-v7'):
        check_report(Path(arguments[1]), arguments[2], current=arguments[0] == 'check-report-v3',
            stream_profile=arguments[0] == 'check-report-v4', challenge_profile=arguments[0] == 'check-report-v5',
            append_profile=arguments[0] == 'check-report-v6', flow_profile=arguments[0] == 'check-report-v7')
    elif len(arguments) == 10 and arguments[0] in ('finalize-report', 'finalize-report-v3', 'finalize-report-v4', 'finalize-report-v5', 'finalize-report-v6', 'finalize-report-v7'):
        require(arguments[6] in ('true', 'false'), 'upload_cleanup_boolean')
        raw = encoded(final_report(Path(arguments[1]), arguments[2], arguments[3], arguments[4],
            int(arguments[5]), arguments[6] == 'true', int(arguments[7]), arguments[8],
            current=arguments[0] == 'finalize-report-v3', stream_profile=arguments[0] == 'finalize-report-v4',
            challenge_profile=arguments[0] == 'finalize-report-v5', append_profile=arguments[0] == 'finalize-report-v6', flow_profile=arguments[0] == 'finalize-report-v7'))
        require(len(raw) <= 4096, 'upload_terminal_bound')
        F['create'](Path(arguments[9]), raw)
    else:
        raise ValueError('upload_evidence_arguments')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, StopIteration, RecursionError):
        sys.exit('Cloud upload evidence rejected')
