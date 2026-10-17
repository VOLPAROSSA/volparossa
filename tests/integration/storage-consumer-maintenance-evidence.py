#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Join actual consumer receipts, store usage and independently drained captures.

This new profile does not reinterpret historical fragment/maintenance evidence.
Its application inputs are synthetic; it proves neither an Immich installation
nor an OpenCloud account server. The outer VM report owns host/guest cleanup.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

HERE = Path(__file__).resolve().parent
APP = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
F, SAMPLER, PROVISIONER = APP['BASE'], APP['SAMPLER'], APP['PROVISIONER']
NET, ROLES, NODES = F['NET'], F['ROLES'], F['NODES']
PHASES = dict(publish=56, exercise=16, finish=22)
APPS = ('image', 'cloud')
MAX_JSON = 1024 * 1024
TRANSITION_NAME = 'private-storage-maintenance-control-transition.json'
MAX_TRANSITION = 131072
CONTROL_NODES = tuple(f'relay{i}' for i in range(6))
CONTROL_PROVIDERS = ('relay3', 'relay4', 'relay5')
# The root topology's original a01 file includes both bootstrap contacts and
# the secondary exit. They are identities, not additional permitted brokers.
TOPOLOGY_ROLES = (*ROLES, *NODES, 'bootstrap1', 'bootstrap2', 'exit2')
SCOPE = dict(synthetic_inputs=True, automatic_grant_refresh=False, private_keys_exported=False,
    immich_running_proven=False, opencloud_account_server_proven=False,
    node_report_hash_independently_reconstructed=False, host_cleanup_proven=False)
EXPORT_NAMES = (
    'a01-expected-peers.json', 'private-storage-fragments-layout.json',
    TRANSITION_NAME,
    'private-storage-fragments-isolation.json', 'private-storage-fragments-deleted_usage.json',
    *(f'storage-consumer-{name}.json' for name in
        ('provision', 'prepare', *PHASES, 'withdrawal', 'private-cleanup', 'isolation', 'evidence')),
    *(f'private-storage-fragments-consumer_{name}_usage.json' for name in ('uploaded', 'restored', 'deleted')),
    *(filename for phase in PHASES for filename in (
        f'private-storage-fragments-consumer-{phase}-layout.json',
        f'private-storage-fragments-consumer-{phase}-live-selection.json',
        f'private-storage-fragments-consumer-{phase}-gates.json',
        f'content-provider-adaptive-private-storage-fragments-consumer-{phase}-control.json',
        *(f'private-storage-fragments-consumer-{phase}-privacy-{role}.json' for role in ROLES))))
LEGACY_EXPORT_NAMES = EXPORT_NAMES
EXPORT_NAMES += ('storage-consumer-control-underlay.json', *(f'storage-consumer-{phase}-control-{suffix}.json'
    for phase in PHASES for suffix in ('before', 'after', 'relay0', 'relay1', 'relay2')))


def require(condition, code):
    if not condition:
        raise ValueError(code)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'consumer_closed_fields')


def count(value, low=0, high=2**64 - 1):
    return type(value) is int and low <= value <= high


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def encoded(value):
    # This is the provisioner's exact original on-disk representation, not the
    # Node report representation (whose original hash is observed by wrapper).
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def canonical(value):
    # Same ASCII-only canonical representation as jq -cSj, without a newline.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode()


def optional_handle(value, required):
    require(type(value) is dict and set(required) <= set(value)
        and set(value) <= {*required, 'handle'}
        and ('handle' not in value or count(value['handle'], 1, 2**32 - 1)), 'control_nft_fields')


def control_filter(value, slot, interface, local, remote):
    """Validate actual kernel nft JSON, including rule order and every verdict."""
    keys(value, ('nftables',))
    rows = value['nftables']
    require(type(rows) is list and len(rows) == 13
        and all(type(row) is dict and len(row) == 1 for row in rows), 'control_nft_objects')
    meta, table_name = rows[0].get('metainfo'), f'vpa_content_control_adaptive_{slot}'
    keys(meta, ('version', 'release_name', 'json_schema_version'))
    require(type(meta['version']) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', meta['version'])
        and type(meta['release_name']) is str and re.fullmatch(r'[A-Za-z0-9 ._()#-]{1,80}', meta['release_name'])
        and type(meta['json_schema_version']) is int and meta['json_schema_version'] == 1, 'control_nft_metadata')
    table = rows[1].get('table')
    optional_handle(table, ('family', 'name'))
    require(table['family'] == 'inet' and table['name'] == table_name, 'control_nft_table')
    chains, rules = [], {}
    for row in rows[2:]:
        if 'chain' in row:
            chain = row['chain']
            optional_handle(chain, ('family', 'table', 'name', 'type', 'hook', 'prio', 'policy'))
            require(chain['family'] == 'inet' and chain['table'] == table_name
                and chain['name'] in ('input', 'output', 'forward') and chain['name'] not in chains
                and chain['type'] == 'filter' and chain['hook'] == chain['name']
                and type(chain['prio']) is int and chain['prio'] == -20
                and chain['policy'] == 'accept', 'control_nft_chain')
            chains.append(chain['name'])
        else:
            rule = row.get('rule')
            optional_handle(rule, ('family', 'table', 'chain', 'expr'))
            require(rule['family'] == 'inet' and rule['table'] == table_name
                and rule['chain'] in chains, 'control_nft_rule_scope')
            rules.setdefault(rule['chain'], []).append(rule['expr'])
    require(set(chains) == {'input', 'output', 'forward'}, 'control_nft_chains')
    def match(left, right):
        return dict(match=dict(op='==', left=left, right=right))
    def device(key):
        return match(dict(meta=dict(key=key)), interface)
    expected = {}
    for chain, key, source, destination in (
            ('input', 'iifname', remote, local), ('output', 'oifname', local, remote)):
        address = [device(key), match(dict(payload=dict(protocol='ip', field='saddr')), source),
            match(dict(payload=dict(protocol='ip', field='daddr')), destination)]
        expected[chain] = [address + [match(dict(payload=dict(protocol='udp', field=field)), 41000),
            dict(accept=None)] for field in ('dport', 'sport')]
        expected[chain].append([device(key), dict(drop=None)])
    expected['forward'] = [[device(key), dict(drop=None)] for key in ('iifname', 'oifname')]
    require(canonical(rules) == canonical(expected), 'control_nft_exact_rules')


def control_snapshot(value, broker, *, routed):
    keys(value, ('nodes', 'route_checks'))
    keys(value['nodes'], CONTROL_NODES)
    if broker is None:
        require(value['route_checks'] is None and all(node == dict(links=[], routes=[], tables={})
            for node in value['nodes'].values()), 'control_detached_not_empty')
        return
    addresses, links = NET['PUBLIC_IPS'], {}
    for node, snapshot in value['nodes'].items():
        keys(snapshot, ('links', 'routes', 'tables'))
        slots = range(3) if node == broker else (CONTROL_PROVIDERS.index(node),) if node in CONTROL_PROVIDERS else ()
        expected_interfaces = {('ac' if node == broker else 'ap') + str(slot) for slot in slots}
        require(type(snapshot['links']) is list and len(snapshot['links']) == len(expected_interfaces)
            and type(snapshot['routes']) is list and len(snapshot['routes']) == 2 * len(expected_interfaces),
            'control_link_route_count')
        keys(snapshot['tables'], (f'vpa_content_control_adaptive_{slot}' for slot in slots))
        by_name = {}
        for link in snapshot['links']:
            keys(link, ('ifindex', 'ifname', 'link_index', 'flags', 'kind'))
            require(link['ifname'] in expected_interfaces and link['ifname'] not in by_name
                and count(link['ifindex'], 1, 2**31 - 1) and count(link['link_index'], 1, 2**31 - 1)
                and link['kind'] == 'veth' and type(link['flags']) is list and len(link['flags']) == 4
                and set(link['flags']) == {'BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'}, 'control_link_identity')
            by_name[link['ifname']] = link
        require(len({link['ifindex'] for link in by_name.values()}) == len(by_name), 'control_duplicate_ifindex')
        links[node] = by_name
        expected_routes = []
        for slot in slots:
            interface = ('ac' if node == broker else 'ap') + str(slot)
            other = CONTROL_PROVIDERS[slot] if node == broker else broker
            local_address = f'10.241.{83 + slot}.{1 if node == broker else 2}'
            gateway = f'10.241.{83 + slot}.{2 if node == broker else 1}'
            expected_routes.extend([
                dict(dst=f'10.241.{83 + slot}.0/30', dev=interface, gateway=None,
                    prefsrc=local_address, scope='link', protocol='kernel'),
                dict(dst=addresses[other], dev=interface, gateway=gateway,
                    prefsrc=addresses[node], scope=None, protocol='boot')])
            control_filter(snapshot['tables'][f'vpa_content_control_adaptive_{slot}'], slot,
                interface, addresses[node], addresses[other])
        actual_routes = []
        for route in snapshot['routes']:
            keys(route, ('dst', 'dev', 'gateway', 'prefsrc', 'scope', 'protocol'))
            route = dict(route)
            if route['scope'] == 'global': route['scope'] = None
            if type(route['dst']) is str and route['dst'].endswith('/32'): route['dst'] = route['dst'][:-3]
            actual_routes.append(route)
        require(sorted(map(canonical, actual_routes)) == sorted(map(canonical, expected_routes)), 'control_exact_routes')
    for slot, node in enumerate(CONTROL_PROVIDERS):
        left, right = links[broker][f'ac{slot}'], links[node][f'ap{slot}']
        require(left['ifindex'] == right['link_index'] and left['link_index'] == right['ifindex'],
            'control_veth_pair')
    if not routed:
        require(value['route_checks'] is None, 'control_premature_routes')
        return
    keys(value['route_checks'], CONTROL_PROVIDERS)
    for slot, node in enumerate(CONTROL_PROVIDERS):
        keys(value['route_checks'][node], ('out', 'back'))
        for direction, device, gateway, source, destination in (
                ('out', f'ac{slot}', f'10.241.{83 + slot}.2', addresses[broker], addresses[node]),
                ('back', f'ap{slot}', f'10.241.{83 + slot}.1', addresses[node], addresses[broker])):
            require(value['route_checks'][node][direction] == [dict(dst=destination, dev=device,
                gateway=gateway, prefsrc=source)], 'control_kernel_route_get')


def validate_control_transition(value, peers, layout, *, stage='complete', layout_raw=None):
    keys(peers, TOPOLOGY_ROLES)
    require(all(type(peer) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', peer) for peer in peers.values())
        and len(set(peers.values())) == len(peers), 'control_peer_identity')
    keys(layout, ('provider_nodes', 'control_relay_peer_id', 'route_context_id', 'route_scope'))
    require(layout['provider_nodes'] == list(NODES), 'control_provider_identity')
    SAMPLER['context_id'](layout['route_context_id'])
    SAMPLER['validate_route_scope'](layout['route_scope'])
    keys(value, ('schema_version', 'kind', 'original_layout_sha256', 'original_layout_canonical_sha256',
        'previous_control_relay_peer_id', 'current_control_relay_peer_id', 'relation', 'before', 'detached', 'after'))
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'storage-maintenance-control-transition'
        and stage in ('before', 'detached', 'complete')
        and len(canonical(value)) <= MAX_TRANSITION, 'control_transition_identity')
    require(sha(value['original_layout_sha256']) and value['original_layout_canonical_sha256']
        == hashlib.sha256(canonical(layout)).hexdigest(), 'control_original_layout')
    if layout_raw is not None:
        require(value['original_layout_sha256'] == hashlib.sha256(layout_raw).hexdigest(), 'control_original_layout_bytes')
    previous, current = value['previous_control_relay_peer_id'], value['current_control_relay_peer_id']
    ordinary = {peers[node]: node for node in CONTROL_NODES[:3]}
    require(len(ordinary) == 3 and previous == layout['control_relay_peer_id']
        and previous in ordinary and current in ordinary
        and value['relation'] == ('same' if previous == current else 'different'), 'control_broker_identity')
    control_snapshot(value['before'], ordinary[previous], routed=False)
    if stage == 'before':
        require(value['detached'] is None and value['after'] is None, 'control_before_scope')
    else:
        if previous == current:
            require(value['detached'] is None, 'control_same_detached')
        else:
            control_snapshot(value['detached'], None, routed=False)
        if stage == 'detached':
            require(value['after'] is None, 'control_detached_scope')
        else:
            control_snapshot(value['after'], ordinary[current], routed=True)
            if previous == current:
                require(value['before']['nodes'] == value['after']['nodes'], 'control_same_changed')
    return {**layout, 'control_relay_peer_id': current}


def read_control_transition(work, *, path=None, stage='complete'):
    work = Path(work)
    value, raw = read(path or work / TRANSITION_NAME, maximum=MAX_TRANSITION, private=True)
    require(stage != 'complete' or raw == canonical(value), 'control_transition_encoding')
    layout, layout_raw = read(work / 'private-storage-fragments-layout.json')
    peers, _ = read(work / 'a01-expected-peers.json')
    validate_control_transition(value, peers, layout, stage=stage, layout_raw=layout_raw)
    return value


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'consumer_duplicate_json_key')
        value[key] = item
    return value


def read(path, *, maximum=MAX_JSON, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, os.geteuid())
            and not before.st_mode & 0o022 and (not private or stat.S_IMODE(before.st_mode) == 0o600)
            and 0 < before.st_size <= maximum, 'consumer_input_boundary')
        raw = stream.read(maximum + 1)
        after, named = os.fstat(stream.fileno()), Path(path).lstat()
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(named, k)
            for k in fields), 'consumer_input_changed')
    value = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: require(False, 'consumer_nonfinite_json'))
    return value, raw


def validate_provision(value):
    true = ('guest_only', 'source_files_verified', 'runtime_files_verified', 'shared_adapter_verified',
        'original_licenses_retained')
    false = ('storage_enrollment_created', 'peer_storage_proven', 'application_restore_proven',
        'sdk_or_browser_provisioned', 'immich_or_opencloud_server_started')
    keys(value, ('version', 'kind', 'success', 'pins', 'pins_sha256', 'tools', *true, *false))
    require(type(value['version']) is int and value['version'] in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        and value['kind'] == 'storage-consumer-maintenance-runtime-provision' and value['success'] is True
        and encoded(value['pins']) == encoded(PROVISIONER['load_pins'](value['version']))
        and value['pins_sha256'] == hashlib.sha256(PROVISIONER['pins_path'](value['version']).read_bytes()).hexdigest()
        and all(value[k] is True for k in true) and all(value[k] is False for k in false), 'consumer_provision')
    keys(value['tools'], ('gpg', 'gpg-agent', 'gpgconf', 'tar'))
    for name, tool in value['tools'].items():
        keys(tool, ('package', 'package_version', 'bytes', 'sha256'))
        require(tool['package'] == name and type(tool['package_version']) is str
            and re.fullmatch('[0-9A-Za-z.+:~_-]{1,100}', tool['package_version'])
            and count(tool['bytes'], 1, 16 * 1024**2) and sha(tool['sha256']), 'consumer_tool_provenance')


def validate_orchestration(value, phase, provision_sha, prepared, *, network_layout=None):
    dynamic = network_layout is not None and phase != 'prepare'
    extra = ('authority',) if phase == 'prepare' else (
        'minimum_protected_completions', 'sampler_joined', 'remote_cleanup_independently_proven')
    keys(value, ('version', 'kind', 'phase', 'passed', 'node', 'node_report_sha256',
        'provision_sha256', 'node_joined', 'protected_flow_proven', *extra,
        *(('network_version', 'control_underlay_sha256') if dynamic else ())))
    require(type(value['version']) is int and value['version'] == (2 if dynamic else 1)
        and value['kind'] == 'storage-consumer-maintenance-orchestration'
        and value['phase'] == phase and value['passed'] is True and value['node_joined'] is True
        and value['provision_sha256'] == provision_sha and sha(value['node_report_sha256'])
        and value['node'].get('passed') is True, 'consumer_orchestration')
    APP['validate_node_report'](value['node'], phase, provision_sha, prepared)
    if phase == 'prepare':
        require(value['protected_flow_proven'] is False, 'consumer_prepare_not_flow_proof')
        keys(value['authority'], APPS)
        for app in APPS:
            size = value['node'][app]['cipher_bytes']
            expected = dict(fresh_owner_created=True, owner_distinct_from_providers=True,
                grant_payload_bytes=[size] * 3, grant_max_leases=[4] * 3,
                grant_retention_seconds=7200, grant_lifetime_seconds=7200, reserved_credit=0,
                enrollment_created=False, policy_authorization_seconds=6000,
                policy_lifetime_seconds=3600, policy_maximum_charge=3 * size, automatic_grant_refresh=False)
            # JSON equality alone accepts bool as int; authority types are fixed.
            require(encoded(value['authority'][app]) == encoded(expected), 'consumer_authority')
    else:
        if dynamic:
            require(type(value['network_version']) is int and value['network_version'] == 2
                and value['control_underlay_sha256'] == network_layout['control_underlay_sha256'],
                'consumer_orchestration_network')
        require(value['protected_flow_proven'] is True and value['sampler_joined'] is True
            and type(value['minimum_protected_completions']) is int
            and value['minimum_protected_completions'] == PHASES[phase]
            and value['remote_cleanup_independently_proven'] is False, 'consumer_flow_scope')


def geometry(prepared):
    sizes, provider_bytes, repair_reads = [], [0, 0, 0], 0
    for app in APPS:
        size = prepared[app]['cipher_bytes']
        _, lengths, withdrawn = APP['geometry'](size)
        sizes.append(size)
        repair_reads += withdrawn
        for i, length in enumerate(lengths):
            for copy in range(2):
                provider_bytes[(i + copy) % 3] += length
    return sum(sizes), provider_bytes, repair_reads


def usage(value, sizes, leases):
    require(type(value) is list and len(value) == 3, 'consumer_usage_count')
    for item, size, number in zip(value, sizes, leases):
        keys(item, ('reserved_bytes', 'committed_bytes', 'leases'))
        require(all(count(n) for n in item.values()) and item == dict(reserved_bytes=0,
            committed_bytes=size, leases=number), 'consumer_exact_provider_usage')


def validate_network(phase, peers, layout, name, total, repair_reads, *, transition_sha=None):
    """Same protected-route/privacy conditions, with this profile's own phases.

    Repair of A's fragments 0/2/3 requires the sole original B/C survivor as
    source and the other survivor's verified readback. Thus each must return at
    least L0+L2+L3 per app, independent of later restore fallback selection.
    The two application reads additionally require the whole two ciphertexts.
    Packet payload includes framing: these are lower bounds, not GET attribution.
    """
    keys(phase, ('layout', 'selected_route', 'privacy', 'control_privacy', 'gates'))
    keys(phase['layout'], ('route_scope',) if transition_sha is None else ('route_scope', 'control_transition_sha256'))
    if transition_sha is not None:
        require(phase['layout']['control_transition_sha256'] == transition_sha, 'consumer_phase_transition')
    selected, privacy, gates = phase['selected_route'], phase['privacy'], phase['gates']
    SAMPLER['validate_summary'](gates, gates['event_baseline_unix_ms'], PHASES[name])
    SAMPLER['validate_phase_route'](phase['layout']['route_scope'], selected, gates)
    paths, slots = selected['paths'], selected['benchmark_slots']
    require(layout['provider_nodes'] == list(NODES) and len({peers[n] for n in NODES}) == 3
        and layout['control_relay_peer_id'] in {peers[n] for n in ROLES[1:4]}, 'consumer_provider_roles')
    require(selected['transport'] == 'mptcp' and len(paths) == len(slots) == 2
        and len({p['relay_peer_id'] for p in paths}) == 2
        and {p['exit_peer_id'] for p in paths} == {peers['exit']}
        and all(p['route_context_id'] == selected['route_context_id'] for p in paths)
        and [p['relay_peer_id'] for p in paths] == [s['relay_peer_id'] for s in slots], 'consumer_protected_mptcp')
    forbidden = {peers['client'], peers['exit'], layout['control_relay_peer_id']} | {p['relay_peer_id'] for p in paths}
    require(all(peers[n] not in forbidden for n in NODES), 'consumer_provider_path_overlap')
    relays = [s['relay_node'] for s in slots]
    require(len(set(relays)) == 2 and all(r in ROLES[1:4] for r in relays)
        and all(peers[s['relay_node']] == s['relay_peer_id'] for s in slots), 'consumer_physical_relays')
    keys(privacy, ROLES)
    for role, capture in privacy.items():
        require(capture['capture_role'] == role and capture['content_provider_mode'] is True
            and capture['unexpected_outer_packets'] == capture['unexpected_provider_application_packets'] == 0
            and capture['expected_link_down_notifications'] == 0, 'consumer_unexpected_egress')
        provider_counters(capture)
        NET['validate_drained'](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != 'exit':
            require(all(n == 0 for counters in capture['provider_application'].values() for n in counters.values()),
                'consumer_provider_bypass')
    require(privacy['client']['direct_client_exit_packets'] == privacy['client']['internet_destination_outer_packets'] == 0
        and privacy['exit']['direct_client_exit_packets'] == privacy['exit']['client_public_packets'] == 0
        and privacy['exit']['outbound_client_discovery_attempt_packets'] == 0
        and all(privacy[r]['internet_destination_outer_packets'] == 0 for r in ROLES[1:4]), 'consumer_privacy')
    for relay in relays:
        require(privacy[relay]['client_leg_wireguard_data_datagrams'] > 16
            and privacy[relay]['exit_leg_wireguard_data_datagrams'] > 16, 'consumer_two_leg_traffic')
    application = privacy['exit']['provider_application']
    for node in NODES[1:] if name == 'exercise' else NODES:
        require(application[node]['request_packets'] > 0 and application[node]['response_packets'] > 0,
            'consumer_active_provider_traffic')
    if name == 'exercise':
        require(application[NODES[0]]['response_payload_bytes'] == 0, 'consumer_withdrawn_provider_responded')
        actual = [application[node]['response_payload_bytes'] for node in NODES[1:]]
        require(all(n >= repair_reads for n in actual) and sum(actual) >= 2 * repair_reads + total,
            'consumer_survivor_payload')
    control = phase['control_privacy']
    control_node = next(n for n in ROLES[1:4] if peers[n] == layout['control_relay_peer_id'])
    pairs = {f'ac{i}': [NET['PUBLIC_IPS'][control_node], NET['PUBLIC_IPS'][node]]
        for i, node in enumerate(('relay3', 'relay4', 'relay5'))}
    require(control['capture_role'] == 'content-control' and control['content_provider_mode'] is True
        and control['content_control_pairs'] == pairs and set(control['interfaces']) == set(pairs)
        and set(control['content_control_packets']) == set(pairs)
        and control['unexpected_provider_control_packets'] == control['unexpected_provider_application_packets'] == 0,
        'consumer_control_boundary')
    provider_counters(control)
    require(all(n == 0 for values in control['provider_application'].values() for n in values.values()),
        'consumer_control_payload')
    NET['validate_drained'](control, allow_empty=True)


def provider_counters(capture):
    keys(capture['provider_application'], NODES)
    for counters in capture['provider_application'].values():
        keys(counters, ('request_packets', 'response_packets', 'response_payload_bytes'))
        require(all(count(n) for n in counters.values()), 'consumer_packet_counter')


def validate_evidence(value, *, previous=False):
    close_profile = not previous and type(value.get('schema_version')) is int and value['schema_version'] == 10
    flow_profile = not previous and type(value.get('schema_version')) is int and value['schema_version'] == 9
    append_profile = not previous and type(value.get('schema_version')) is int and value['schema_version'] == 8
    challenge_profile = not previous and type(value.get('schema_version')) is int and value['schema_version'] == 7
    stream_profile = not previous and type(value.get('schema_version')) is int and value['schema_version'] == 6
    outcome_profile = not previous and type(value.get('schema_version')) is int and value['schema_version'] == 5
    tls_profile = not previous and type(value.get('schema_version')) is int and value['schema_version'] == 4
    dynamic = close_profile or flow_profile or append_profile or challenge_profile or stream_profile or outcome_profile or tls_profile or (not previous and type(value.get('schema_version')) is int and value['schema_version'] == 3)
    keys(value, ('schema_version', 'kind', 'success', 'scope', 'provision', 'provision_sha256',
        'prepare', *PHASES, 'withdrawal', 'private_cleanup', 'initial_usage', 'uploaded_usage',
        'restored_usage', 'deleted_usage', 'expected_peers', 'layout', 'isolation', 'consumer_isolation', 'network',
        *(() if previous else ('control_transition',)), *(('control_underlay',) if dynamic else ())))
    require(type(value['schema_version']) is int and value['schema_version'] == (1 if previous else 10 if close_profile else 9 if flow_profile else 8 if append_profile else 7 if challenge_profile else 6 if stream_profile else 5 if outcome_profile else 4 if tls_profile else 3 if dynamic else 2)
        and value['kind'] == 'storage-consumer-maintenance-evidence' and value['success'] is True,
        'consumer_evidence_identity')
    require(encoded(value['scope']) == encoded(SCOPE), 'consumer_evidence_scope')
    validate_provision(value['provision'])
    require((value['provision']['version'] == 4) == tls_profile, 'consumer_tls_source_profile')
    require((value['provision']['version'] == 5) == outcome_profile, 'consumer_outcome_source_profile')
    require((value['provision']['version'] == 6) == stream_profile, 'consumer_stream_source_profile')
    require((value['provision']['version'] == 7) == challenge_profile, 'consumer_challenge_source_profile')
    require((value['provision']['version'] == 8) == append_profile, 'consumer_append_source_profile')
    require((value['provision']['version'] == 9) == flow_profile, 'consumer_flow_source_profile')
    require((value['provision']['version'] == 10) == close_profile, 'consumer_close_source_profile')
    provision_sha = hashlib.sha256(encoded(value['provision'])).hexdigest()
    require(value['provision_sha256'] == provision_sha, 'consumer_provision_hash')
    network, network_layout = None, None
    if dynamic:
        network = runpy.run_path(str(HERE / 'storage-consumer-network.py'))
        network['U']['validate'](value['control_underlay'], value['expected_peers'], value['layout'], value['control_transition'])
        network_layout = network['layout'](value['control_underlay'], value['expected_peers'])
        require(value['provision']['version'] == (10 if close_profile else 9 if flow_profile else 8 if append_profile else 7 if challenge_profile else 6 if stream_profile else 5 if outcome_profile else 4 if tls_profile else 3), 'consumer_network_source_profile')
    prepared = value['prepare']['node']
    for phase in ('prepare', *PHASES):
        validate_orchestration(value[phase], phase, provision_sha, prepared, network_layout=network_layout)
    total, initial_bytes, repair_reads = geometry(prepared)
    usage(value['initial_usage'], [0] * 3, [0] * 3)
    usage(value['uploaded_usage'], initial_bytes, [6, 6, 4])
    usage(value['restored_usage'], [initial_bytes[0], total, total], [6, 8, 8])
    usage(value['deleted_usage'], [0] * 3, [0] * 3)
    require(encoded(value['withdrawal']) == encoded(dict(first_provider_stopped_before_repair_and_read=True,
        first_store_retained=True, other_two_providers_serving=True, same_three_stores_reopened=True,
        all_usage_snapshots_with_services_stopped=True, all_three_store_inodes_preserved=True)),
        'consumer_store_withdrawal')
    cleanup = value['private_cleanup']
    keys(cleanup, ('version', 'kind', 'passed', 'local_fixture_removed', 'no_owned_fixture_process_observed',
        'removed_files', 'removed_directories', 'remote_cleanup_confirmed', 'provider_usage_proven'))
    require(type(cleanup['version']) is int and cleanup['version'] == 1
        and cleanup['kind'] == 'storage-consumer-maintenance-cleanup' and cleanup['passed'] is True
        and cleanup['local_fixture_removed'] is True and cleanup['no_owned_fixture_process_observed'] is True
        and count(cleanup['removed_files'], 1, 512) and count(cleanup['removed_directories'], 1, 512)
        # The walk permits 512 children; the receipt also counts the root.
        and cleanup['removed_files'] + cleanup['removed_directories'] <= 513
        and cleanup['remote_cleanup_confirmed'] is False and cleanup['provider_usage_proven'] is False,
        'consumer_private_cleanup')
    peers = value['expected_peers']
    # Preserve the explicitly requested historical schema-1 shape; current
    # schema 2 binds the complete original topology file without projection.
    keys(peers, (*ROLES, *NODES) if previous else TOPOLOGY_ROLES)
    require(all(type(p) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', p) for p in peers.values())
        and len(set(peers.values())) == len(peers), 'consumer_peer_identity')
    layout = value['layout']
    keys(layout, ('provider_nodes', 'control_relay_peer_id', 'route_context_id', 'route_scope'))
    SAMPLER['context_id'](layout['route_context_id'])
    SAMPLER['validate_route_scope'](layout['route_scope'])
    transition_sha = None
    if not previous:
        layout = validate_control_transition(value['control_transition'], peers, layout)
        transition_sha = hashlib.sha256(canonical(value['control_transition'])).hexdigest()
    isolation = value['isolation']
    ids = ('user_uid', 'agent_uid', 'control_gid', 'agent_gid')
    flags = ('agent_cannot_read_user_state', 'client_cannot_read_any_provider_store',
        'agent_mount_positive_control', 'all_provider_keys_match_independent_fixture_peers', 'three_provider_namespaces_distinct')
    keys(isolation, (*ids, *flags))
    require(all(count(isolation[k], 1, 2**32 - 1) for k in ids)
        and isolation['user_uid'] != isolation['agent_uid'] and isolation['control_gid'] != isolation['agent_gid']
        and all(isolation[k] is True for k in flags), 'consumer_shared_isolation')
    require(encoded(value['consumer_isolation']) == encoded(dict(user_uid=isolation['user_uid'],
        agent_uid=isolation['agent_uid'], agent_mount_positive_control=True,
        client_cannot_read_new_owner_root=True, client_cannot_read_any_provider_store=True)),
        'consumer_new_owner_isolation')
    keys(value['network'], PHASES)
    for name, phase in value['network'].items():
        if dynamic:
            network['validate_network'](phase, peers, value['layout'], name, total, repair_reads, value['control_underlay'])
        else:
            validate_network(phase, peers, layout, name, total, repair_reads, transition_sha=transition_sha)
    return value


def build_evidence(work, *, network_version=1, tls_profile=False, outcome_profile=False, stream_profile=False,
        challenge_profile=False, append_profile=False, flow_profile=False, close_profile=False):
    require(network_version in (1, 2), 'consumer_network_version')
    require(type(tls_profile) is bool and (not tls_profile or network_version == 2), 'consumer_tls_source_profile')
    require(type(outcome_profile) is bool and (not outcome_profile or (network_version == 2 and not tls_profile)),
        'consumer_outcome_source_profile')
    require(type(stream_profile) is bool and (not stream_profile or (
        network_version == 2 and not tls_profile and not outcome_profile)), 'consumer_stream_source_profile')
    require(type(challenge_profile) is bool and (not challenge_profile or (
        network_version == 2 and not tls_profile and not outcome_profile and not stream_profile)),
        'consumer_challenge_source_profile')
    require(type(append_profile) is bool and (not append_profile or (
        network_version == 2 and not tls_profile and not outcome_profile and not stream_profile and not challenge_profile)),
        'consumer_append_source_profile')
    require(type(flow_profile) is bool and (not flow_profile or (
        network_version == 2 and not tls_profile and not outcome_profile and not stream_profile
        and not challenge_profile and not append_profile)), 'consumer_flow_source_profile')
    require(type(close_profile) is bool and (not close_profile or (
        network_version == 2 and not tls_profile and not outcome_profile and not stream_profile
        and not challenge_profile and not append_profile and not flow_profile)), 'consumer_close_source_profile')
    work = Path(work)
    def get(name):
        return read(work / name)[0]
    provision, raw = read(work / 'storage-consumer-provision.json')
    require(raw == encoded(provision), 'consumer_provision_encoding')
    value = dict(schema_version=10 if close_profile else 9 if flow_profile else 8 if append_profile else 7 if challenge_profile else 6 if stream_profile else 5 if outcome_profile else 4 if tls_profile else 3 if network_version == 2 else 2,
        kind='storage-consumer-maintenance-evidence', success=True,
        scope=dict(SCOPE), provision=provision, provision_sha256=hashlib.sha256(raw).hexdigest(),
        **{name: get(f'storage-consumer-{name}.json') for name in ('prepare', *PHASES, 'withdrawal')},
        private_cleanup=get('storage-consumer-private-cleanup.json'),
        initial_usage=get('private-storage-fragments-deleted_usage.json'),
        **{name + '_usage': get(f'private-storage-fragments-consumer_{name}_usage.json')
            for name in ('uploaded', 'restored', 'deleted')},
        expected_peers=get('a01-expected-peers.json'), layout=get('private-storage-fragments-layout.json'),
        isolation=get('private-storage-fragments-isolation.json'),
        consumer_isolation=get('storage-consumer-isolation.json'), control_transition=read_control_transition(work))
    value['network'] = {name: dict(layout=get(f'private-storage-fragments-consumer-{name}-layout.json'),
        selected_route=get(f'private-storage-fragments-consumer-{name}-live-selection.json'),
        gates=get(f'private-storage-fragments-consumer-{name}-gates.json'),
        control_privacy=({} if network_version == 2 else
            get(f'content-provider-adaptive-private-storage-fragments-consumer-{name}-control.json')),
        privacy={role: get(f'private-storage-fragments-consumer-{name}-privacy-{role}.json') for role in ROLES})
        for name in PHASES}
    if network_version == 2:
        network = runpy.run_path(str(HERE / 'storage-consumer-network.py'))
        value['control_underlay'] = network['U']['read_check'](work, work / network['U']['NAME'], 'complete')
        for name, phase in value['network'].items():
            phase.update(control_privacy={broker: get(f'storage-consumer-{name}-control-{broker}.json')
                for broker in network['BROKERS']},
                control_before=get(f'storage-consumer-{name}-control-before.json'),
                control_after=get(f'storage-consumer-{name}-control-after.json'))
    return validate_evidence(value)


def main(arguments):
    if len(arguments) == 1 and arguments[0] == 'export-names':
        print('\n'.join(EXPORT_NAMES))
    elif len(arguments) == 2 and arguments[0] == 'check':
        validate_evidence(read(Path(arguments[1]))[0])
    elif len(arguments) == 3 and arguments[0] in ('evidence', 'evidence-v3', 'evidence-v4', 'evidence-v5', 'evidence-v6', 'evidence-v7', 'evidence-v8', 'evidence-v9', 'evidence-v10'):
        current = arguments[0] != 'evidence'
        value = build_evidence(Path(arguments[1]), network_version=2 if current else 1,
            tls_profile=arguments[0] == 'evidence-v4', outcome_profile=arguments[0] == 'evidence-v5',
            stream_profile=arguments[0] == 'evidence-v6', challenge_profile=arguments[0] == 'evidence-v7',
            append_profile=arguments[0] == 'evidence-v8', flow_profile=arguments[0] == 'evidence-v9',
            close_profile=arguments[0] == 'evidence-v10')
        # Keep the existing 1MiB bound; do not multiply indentation for repeated
        # actual kernel snapshots. Historical serialization stays unchanged.
        raw = canonical(value) if current else encoded(value)
        require(len(raw) <= MAX_JSON, 'consumer_evidence_bound')
        F['create'](Path(arguments[2]), raw)
    else:
        raise ValueError('consumer_evidence_arguments')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, StopIteration, RecursionError):
        sys.exit('storage consumer evidence rejected')
