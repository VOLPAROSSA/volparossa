#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit consumer network profile 2; no reinterpretation of base evidence."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys

HERE = Path(__file__).resolve().parent
U = runpy.run_path(str(HERE / 'storage-consumer-control-underlay.py'))
S = runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py'))
OLD = U['OLD']
require, keys, canonical = (OLD[k] for k in ('require', 'keys', 'canonical'))
BROKERS, PROVIDERS = U['BROKERS'], U['PROVIDERS']
PHASES = OLD['PHASES']
EXPORT_NAMES = (U['NAME'], *(f'storage-consumer-{phase}-control-{suffix}.json'
    for phase in PHASES for suffix in ('before', 'after', *BROKERS)))


def policy(peers):
    keys(peers, OLD['TOPOLOGY_ROLES'])
    value = dict(exit_peer_id=peers['exit'], relay_peers={n: peers[n] for n in BROKERS})
    S['validate_policy'](value)
    return value


def layout(underlay, peers):
    return dict(network_version=2, control_underlay_sha256=hashlib.sha256(canonical(underlay)).hexdigest(),
        route_policy=policy(peers))


def validate_readback(value, underlay):
    U['snapshot'](value)
    require(canonical(value) == canonical(underlay['after']), 'consumer_kernel_matrix_changed')


def worker_flow(work, path):
    """Only the fixed worker output, not a general alternate-owner JSON reader."""
    work, path = Path(work), Path(path)
    parent = work / 'client-fixtures/private-storage-user'
    require(path.parent == parent and path.name in {f'flow-consumer-{n}.json' for n in PHASES}
        and parent.resolve(strict=True) == parent, 'consumer_worker_flow_path')
    isolation = OLD['read'](work / 'private-storage-fragments-isolation.json', maximum=8192)[0]
    owner = isolation.get('user_uid')
    require(type(owner) is int and 0 < owner < 2**32 and owner != isolation.get('agent_uid')
        and os.geteuid() in (0, owner), 'consumer_worker_identity')
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(directory)
        require(stat.S_ISDIR(initial.st_mode) and stat.S_IMODE(initial.st_mode) == 0o700
            and initial.st_uid == owner, 'consumer_worker_directory')
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_uid == owner and before.st_nlink == 1 and 0 < before.st_size <= 16384,
                'consumer_worker_flow_boundary')
            raw = stream.read(16385)
            after, named = os.fstat(stream.fileno()), os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(named, k)
                for k in fields), 'consumer_worker_flow_changed')
        after, named = os.fstat(directory), parent.lstat()
        require(all(getattr(initial, k) == getattr(after, k) == getattr(named, k) for k in fields),
            'consumer_worker_directory_changed')
    finally:
        os.close(directory)
    return json.loads(raw, object_pairs_hook=OLD['unique'],
        parse_constant=lambda _: require(False, 'consumer_nonfinite_flow'))


def validate_network(phase, peers, original_layout, name, total, repair_reads, underlay):
    keys(phase, ('layout', 'selected_route', 'privacy', 'control_privacy', 'gates', 'control_before', 'control_after'))
    require(canonical(phase['layout']) == canonical(layout(underlay, peers)), 'consumer_matrix_binding')
    validate_readback(phase['control_before'], underlay)
    validate_readback(phase['control_after'], underlay)
    selected, privacy, gates = phase['selected_route'], phase['privacy'], phase['gates']
    S['validate_summary'](gates, gates['event_baseline_unix_ms'], PHASES[name])
    S['validate_phase_route'](policy(peers), selected, gates)
    require(original_layout['provider_nodes'] == list(OLD['NODES']), 'consumer_provider_roles')
    slots = selected['benchmark_slots']
    require(all(s['relay_node'] in BROKERS and peers[s['relay_node']] == s['relay_peer_id'] for s in slots),
        'consumer_physical_end_relays')
    # Every context retains its exact path->peer mapping; this set is ONLY the
    # set of physical interfaces that must have traffic, never route authority.
    used = {n for route in gates['observed_context_routes'] for p in route['scope']['paths']
        for n in BROKERS if peers[n] == p['relay_peer_id']}
    keys(privacy, OLD['ROLES'])
    for role, capture in privacy.items():
        require(capture['capture_role'] == role and capture['content_provider_mode'] is True
            and capture['unexpected_outer_packets'] == capture['unexpected_provider_application_packets'] == 0
            and capture['expected_link_down_notifications'] == 0, 'consumer_unexpected_egress')
        OLD['provider_counters'](capture)
        OLD['NET']['validate_drained'](capture, allow_empty=role in BROKERS and role not in used)
        if role != 'exit':
            require(all(n == 0 for counters in capture['provider_application'].values() for n in counters.values()),
                'consumer_provider_bypass')
        if role in BROKERS:
            number = BROKERS.index(role)
            require(capture['interfaces'] == [f'r{number}c', f'r{number}x', 'underlay'],
                'consumer_physical_capture_interfaces')
    require(privacy['client']['direct_client_exit_packets'] == privacy['client']['internet_destination_outer_packets'] == 0
        and privacy['exit']['direct_client_exit_packets'] == privacy['exit']['client_public_packets'] == 0
        and privacy['exit']['outbound_client_discovery_attempt_packets'] == 0
        and all(privacy[n]['internet_destination_outer_packets'] == 0 for n in BROKERS), 'consumer_privacy')
    for node in used:
        require(privacy[node]['client_leg_wireguard_data_datagrams'] > 16
            and privacy[node]['exit_leg_wireguard_data_datagrams'] > 16, 'consumer_two_leg_traffic')
    application = privacy['exit']['provider_application']
    for node in OLD['NODES'][1:] if name == 'exercise' else OLD['NODES']:
        require(application[node]['request_packets'] > 0 and application[node]['response_packets'] > 0,
            'consumer_active_provider_traffic')
    if name == 'exercise':
        require(application[OLD['NODES'][0]]['response_payload_bytes'] == 0, 'consumer_withdrawn_provider_responded')
        amounts = [application[node]['response_payload_bytes'] for node in OLD['NODES'][1:]]
        require(all(n >= repair_reads for n in amounts) and sum(amounts) >= 2 * repair_reads + total,
            'consumer_survivor_payload')
    keys(phase['control_privacy'], BROKERS)
    for broker, control in phase['control_privacy'].items():
        b = BROKERS.index(broker)
        pairs = {f'cc{b}{p}': [OLD['NET']['PUBLIC_IPS'][broker], OLD['NET']['PUBLIC_IPS'][node]]
            for p, node in enumerate(PROVIDERS)}
        require(control['capture_role'] == 'content-control' and control['content_provider_mode'] is True
            and control['consumer_control_role'] == broker and control['content_control_pairs'] == pairs
            and control['interfaces'] == list(pairs) and set(control['content_control_packets']) == set(pairs)
            and control['unexpected_provider_control_packets'] == control['unexpected_provider_application_packets'] == 0,
            'consumer_control_boundary')
        OLD['provider_counters'](control)
        require(all(n == 0 for values in control['provider_application'].values() for n in values.values()),
            'consumer_control_payload')
        for counters in control['content_control_packets'].values():
            keys(counters, ('inbound', 'outbound'))
            require(all(OLD['count'](n) for n in counters.values()), 'consumer_control_counters')
        OLD['NET']['validate_drained'](control, allow_empty=True)


def main(args):
    require(len(args) >= 2, 'consumer_network_arguments')
    command, work = args[0], Path(args[1])
    underlay = U['read_check'](work, work / U['NAME'], 'complete')
    peers = OLD['read'](work / 'a01-expected-peers.json')[0]
    expected = layout(underlay, peers)
    if command == 'layout' and len(args) == 2:
        print(json.dumps(expected, sort_keys=True))
    elif command == 'readback' and len(args) == 3:
        value, raw = OLD['read'](args[2], maximum=U['MAX_BYTES'], private=True)
        require(raw == canonical(value), 'consumer_readback_encoding')
        validate_readback(value, underlay)
    elif command == 'route-check' and len(args) == 4:
        selected = OLD['read'](args[2], maximum=65536)[0]
        gates = worker_flow(work, args[3])
        S['validate_phase_route'](expected['route_policy'], selected, gates)
    elif command == 'gates' and len(args) == 5:
        value = worker_flow(work, args[2])
        S['validate_summary'](value, int(args[3]), int(args[4]))
        require(value['exit_route_policy'] == expected['route_policy'], 'consumer_gates_policy')
        print(json.dumps(value, sort_keys=True))
    else:
        raise ValueError('consumer_network_arguments')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RecursionError):
        sys.exit('consumer network proof rejected')
