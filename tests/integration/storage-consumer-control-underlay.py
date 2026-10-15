#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed consumer-only physical control matrix; not route or application proof.

The historical upload/maintenance transition is immutable. Only after that
archive's phase has ended may the disposable supervisor replace its three owned
control links with nine UDP-only links. All production selection/authority is
unchanged. This helper is intentionally not a network operator.
"""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve().parent
OLD = runpy.run_path(str(HERE / 'storage-consumer-maintenance-evidence.py'))
require, keys, canonical, count = (OLD[n] for n in ('require', 'keys', 'canonical', 'count'))
BROKERS = ('relay0', 'relay1', 'relay2')
PROVIDERS = ('relay3', 'relay4', 'relay5')
NODES = (*BROKERS, *PROVIDERS)
MAX_BYTES = 131072
NAME = 'storage-consumer-control-underlay.json'


def pair(broker, provider):
    require(broker in BROKERS and provider in PROVIDERS, 'consumer_control_role')
    b, p = BROKERS.index(broker), PROVIDERS.index(provider)
    return dict(broker=broker, provider=provider, left=f'cc{b}{p}', right=f'pc{b}{p}',
        subnet=f'10.247.{1 + 3 * b + p}', table=f'vpa_content_control_consumer_{b}{p}')


PAIRS = tuple(pair(b, p) for b in BROKERS for p in PROVIDERS)


def filter_rules(value, name, interface, local, remote):
    """Reuse the exact historical eight-rule validator, not a wider nft grammar."""
    keys(value, ('nftables',))
    require(type(value['nftables']) is list, 'consumer_control_nft_rows')
    projected = copy.deepcopy(value)
    for row in projected['nftables']:
        require(type(row) is dict and len(row) == 1, 'consumer_control_nft_row')
        for kind, field in (('table', 'name'), ('chain', 'table'), ('rule', 'table')):
            if kind in row:
                require(type(row[kind]) is dict and row[kind].get(field) == name,
                    'consumer_control_nft_name')
                row[kind][field] = 'vpa_content_control_adaptive_0'
    OLD['control_filter'](projected, 0, interface, local, remote)


def snapshot(value, *, detached=False):
    keys(value, ('nodes', 'route_checks'))
    keys(value['nodes'], NODES)
    if detached:
        require(value['route_checks'] is None and all(v == dict(links=[], routes=[], tables={})
            for v in value['nodes'].values()), 'consumer_control_detached')
        return
    addresses, links = OLD['NET']['PUBLIC_IPS'], {}
    for node, raw in value['nodes'].items():
        keys(raw, ('links', 'routes', 'tables'))
        selected = [p for p in PAIRS if node in (p['broker'], p['provider'])]
        names = {p['left'] if node == p['broker'] else p['right'] for p in selected}
        require(type(raw['links']) is list and len(raw['links']) == 3
            and type(raw['routes']) is list and len(raw['routes']) == 6, 'consumer_control_counts')
        keys(raw['tables'], (p['table'] for p in selected))
        by_name = {}
        for link in raw['links']:
            keys(link, ('ifindex', 'ifname', 'link_index', 'flags', 'kind'))
            require(type(link['ifname']) is str and link['ifname'] in names
                and link['ifname'] not in by_name and count(link['ifindex'], 1, 2**31 - 1)
                and count(link['link_index'], 1, 2**31 - 1) and link['kind'] == 'veth'
                and type(link['flags']) is list and len(link['flags']) == 4
                and all(type(flag) is str for flag in link['flags'])
                and set(link['flags']) == {'BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'},
                'consumer_control_link')
            by_name[link['ifname']] = link
        require(len({v['ifindex'] for v in by_name.values()}) == 3, 'consumer_control_ifindex')
        links[node] = by_name
        expected_routes = []
        for p in selected:
            left = node == p['broker']
            device, other = (p['left'], p['provider']) if left else (p['right'], p['broker'])
            local, remote = (1, 2) if left else (2, 1)
            expected_routes.extend([
                dict(dst=p['subnet'] + '.0/30', dev=device, gateway=None,
                    prefsrc=p['subnet'] + f'.{local}', scope='link', protocol='kernel'),
                dict(dst=addresses[other], dev=device, gateway=p['subnet'] + f'.{remote}',
                    prefsrc=addresses[node], scope=None, protocol='boot')])
            filter_rules(raw['tables'][p['table']], p['table'], device, addresses[node], addresses[other])
        routes = []
        for route in raw['routes']:
            keys(route, ('dst', 'dev', 'gateway', 'prefsrc', 'scope', 'protocol'))
            route = dict(route)
            if route['scope'] == 'global': route['scope'] = None
            if type(route['dst']) is str and route['dst'].endswith('/32'): route['dst'] = route['dst'][:-3]
            routes.append(route)
        require(sorted(map(canonical, routes)) == sorted(map(canonical, expected_routes)),
            'consumer_control_routes')
    keys(value['route_checks'], BROKERS)
    for broker in BROKERS:
        keys(value['route_checks'][broker], PROVIDERS)
    for p in PAIRS:
        left, right = links[p['broker']][p['left']], links[p['provider']][p['right']]
        require(left['ifindex'] == right['link_index'] and left['link_index'] == right['ifindex'],
            'consumer_control_pair')
        check = value['route_checks'][p['broker']][p['provider']]
        keys(check, ('out', 'back'))
        for key, device, gateway, source, destination in (
                ('out', p['left'], p['subnet'] + '.2', addresses[p['broker']], addresses[p['provider']]),
                ('back', p['right'], p['subnet'] + '.1', addresses[p['provider']], addresses[p['broker']])):
            require(check[key] == [dict(dst=destination, dev=device, gateway=gateway, prefsrc=source)],
                'consumer_control_route_get')


def validate(value, peers, layout, transition, *, stage='complete'):
    require(stage in ('before', 'detached', 'complete'), 'consumer_control_stage')
    keys(value, ('schema_version', 'kind', 'original_transition_sha256', 'original_peers_sha256',
        'before', 'detached', 'after', 'application_acceptance'))
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == 'storage-consumer-control-underlay'
        and value['application_acceptance'] is False and len(canonical(value)) <= MAX_BYTES,
        'consumer_control_identity')
    current = OLD['validate_control_transition'](transition, peers, layout)
    require(value['original_transition_sha256'] == hashlib.sha256(canonical(transition)).hexdigest()
        and value['original_peers_sha256'] == hashlib.sha256(canonical(peers)).hexdigest(),
        'consumer_control_original_binding')
    broker = next(n for n in BROKERS if peers[n] == current['control_relay_peer_id'])
    OLD['control_snapshot'](value['before'], broker, routed=True)
    require(canonical(value['before']) == canonical(transition['after']), 'consumer_control_original_kernel')
    if stage == 'before':
        require(value['detached'] is None and value['after'] is None, 'consumer_control_early_fields')
    else:
        snapshot(value['detached'], detached=True)
        if stage == 'detached':
            require(value['after'] is None, 'consumer_control_early_matrix')
        else:
            snapshot(value['after'])
    return value


def read_check(work, path, stage):
    work, path = Path(work), Path(path)
    transition = OLD['read_control_transition'](work)
    peers, _ = OLD['read'](work / 'a01-expected-peers.json')
    layout, _ = OLD['read'](work / 'private-storage-fragments-layout.json')
    value, raw = OLD['read'](path, maximum=MAX_BYTES, private=True)
    require(stage != 'complete' or raw == canonical(value), 'consumer_control_encoding')
    return validate(value, peers, layout, transition, stage=stage)


def main(args):
    require(len(args) == 4 and args[0] == 'check', 'consumer_control_cli')
    read_check(args[1], args[2], args[3])


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError):
        sys.exit('consumer control underlay rejected')
