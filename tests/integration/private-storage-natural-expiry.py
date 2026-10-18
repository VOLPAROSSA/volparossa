#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Core-only ordinary expiry between eight and two copies, never in-flight expiry.

Two short fixture drivers retain the same private owner state; production CLI,
agent, helper and provider processes do not acquire alternative test lifetimes.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
SEQ = runpy.run_path(str(HERE / 'private-storage-deposit-sequence-smoke.py'))
S = runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py'))
OLD = S['OLD']
require, read = SEQ['require'], SEQ['read']
PREFIX = 'private-storage-natural-expiry'
CHECKPOINT = '.tmpExpiryCheckpoint'
LIFETIME = 600
WAIT = 601
BUDGET = 900
PHASES = ('prefix', 'suffix')
PROCESS_ROLES = tuple(f'{kind}@{node}' for node in ('client', 'exit', *S['BROKERS'])
    for kind in ('agent', 'helper')) + tuple(f'agent@{node}' for node in SEQ['NODES'])
EXPORT_NAMES = ('a01-expected-peers.json',
    *(f"{SEQ['PREFIX']}-{n}.json" for n in ('prepare', 'isolation', 'layout', 'deleted_usage', 'private_cleanup')),
    *(f'{PREFIX}-{n}.json' for n in ('smoke', 'evidence', 'prefix', 'suffix', 'abort', 'boundary',
        'initial', 'old', 'new', 'flows', 'prefix-clock', 'processes', 'matrix', 'cleanup')),
    *(name for phase in PHASES for name in (
        f'{PREFIX}-{phase}-live-selection.json',
        *(f'{PREFIX}-{phase}-privacy-{role}.json' for role in SEQ['FRAG']['ROLES']),
        *(f'{PREFIX}-{phase}-control-{broker}.json' for broker in S['BROKERS']),
        *(f'{PREFIX}-{phase}-matrix-{stage}.json' for stage in ('before', 'after')))))


def matrix_module():
    # Root-side readback/evidence runs from the source tree. The unprivileged
    # owner copy does not import or provision any application closure.
    return runpy.run_path(str(HERE / 'storage-consumer-control-underlay.py'))


def prefix_result():
    value = SEQ['sequence_result']()
    value.update(completed_deposits=8, attempted_deposits=8, owner_verified_committed_receipts=8)
    return value


def retained_digest(root):
    """Private byte binding, not an exported identifier or content fingerprint."""
    names = ['identity.key', 'passphrase', *(f'grant-{n}.bin' for n in range(3))]
    names += [f'set-{p}/replicas.json' for p in range(5)]
    names += [f'set-{p}/copy-{c}/archive.json' for p in range(5) for c in range(2)]
    digest = hashlib.sha256()
    for name in names:
        path = root / name
        require(0 < SEQ['private_file'](path).st_size <= 1048576, 'retained identity bound')
        raw = path.read_bytes()
        digest.update(name.encode() + b'\0' + len(raw).to_bytes(8, 'big') + raw)
    return digest.hexdigest()


def prefix(root, binary, client, keys):
    value = SEQ['sequence_result']()
    accepted = False
    failure = None
    try:
        SEQ['deposit_pairs'](root, binary, client, keys, value, set(), range(4))
        require(value == prefix_result(), 'eight-copy prefix incomplete')
        SEQ['create'](root / CHECKPOINT, (retained_digest(root) + '\n').encode())
        accepted = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        failure = 'prefix_or_checkpoint'
    finally:
        if not accepted:
            SEQ['delete_copies'](root, binary, client, keys, value)
    return dict(prefix_complete=accepted, sequence=value, fixture_failure=failure)


def retained_prefix(root, keys):
    path = root / CHECKPOINT
    require(SEQ['private_file'](path).st_size == 65, 'retained checkpoint bound')
    require(path.read_text() == retained_digest(root) + '\n', 'retained owner bytes changed')
    identities = set()
    for index in range(8):
        journal = SEQ['journal'](root, index)
        require(journal['lease'] is not None and journal['last_state'] == 3
            and journal['last_stored_bytes'] == SEQ['LENGTHS'][index], 'retained committed copy missing')
        identities.add((keys[SEQ['ORDER'][index]], journal['lease']))
    require(len(identities) == 8, 'retained leases not distinct')
    return identities


def suffix(root, binary, client, keys):
    value = prefix_result()
    retained = False
    failure = None
    try:
        identities = retained_prefix(root, keys)
        retained = True
        SEQ['deposit_pairs'](root, binary, client, keys, value, identities, range(4, 5))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        failure = 'retained_prefix' if not retained else 'suffix'
    finally:
        SEQ['delete_copies'](root, binary, client, keys, value)
    value['success'] = (value['completed_deposits'] == value['deleted_copies'] == 10
        and value['failure'] is None and value['remote_cleanup_complete'] and value['cli_children_joined'])
    return dict(retained_owner_bytes_verified=retained, sequence=value, fixture_failure=failure)


def abort(root, binary, client, keys, attempted):
    """Best-effort authorized deletion, never convert teardown into acceptance."""
    require(type(attempted) is int and attempted in (8, 10), 'invalid abort boundary')
    value = SEQ['sequence_result']()
    value['attempted_deposits'] = attempted
    SEQ['delete_copies'](root, binary, client, keys, value)
    return value


def policy(peers):
    value = dict(exit_peer_id=peers['exit'], relay_peers={n: peers[n] for n in S['BROKERS']})
    S['validate_policy'](value)
    return value


def query(binary, socket, arguments, deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'observation deadline')
    with tempfile.TemporaryFile() as output:
        reply = subprocess.run([binary, '--control-socket', socket, *arguments], stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.DEVNULL, timeout=remaining, check=True)
        require(reply.returncode == 0 and time.monotonic() < deadline, 'observation deadline')
        output.seek(0)
        value = output.read(OLD['MAX_BYTES'] + 1)
    require(len(value) <= OLD['MAX_BYTES'], 'observation reply bound')
    return value


def observe_route(binary, client, expected, *, expired=False, old=None):
    deadline = time.monotonic() + 3
    before = query(binary, client, ['paths'], deadline)
    status = query(binary, client, ['content', 'status'], deadline)
    after = query(binary, client, ['paths'], deadline)
    if not expired:
        observation = S['Coverage'](1, expected)
        observation.route(before, status, after)
        return observation.route_bindings[observation.current_context]
    # Paths may retain a stale snapshot after the actual route owner expires.
    # ContentReceipt uses an empty string (not null) for no usable broker:
    # agent/content.rs status() -> CLI main.rs direct JSON projection.
    # Only that sentinel plus empty OR exactly the original Paths can pass.
    value = json.loads(status, object_pairs_hook=S['unique'])
    require(type(value) is dict and 'control_relay_peer_id' in value
        and value['control_relay_peer_id'] == '', 'expired broker remains usable')
    require(old is not None, 'missing original route')
    S['validate_route'](old, expected)
    def paths(raw):
        if raw == b'':
            return 'empty'
        context, scope = S['path_observation'](raw, expected)
        require(context == old['route_context_id'] and scope == old['scope'], 'unexpected idle route')
        return 'stale_original'
    left, right = paths(before), paths(after)
    require(left == right, 'expiry snapshot changed while observing')
    return dict(control_relay_absent=True, paths_state=left)


def remaining(start, now=None):
    now = time.monotonic() if now is None else now
    require(type(start) in (int, float) and math.isfinite(start) and start > 0
        and type(now) in (int, float) and math.isfinite(now) and now >= start, 'invalid monotonic clock')
    return max(0, math.floor(start + BUDGET - now))


def natural_wait(start, binary, client, expected, old, *, clock=time.monotonic, sleep=time.sleep):
    require(remaining(start, clock()) > BUDGET - WAIT, 'prefix exceeded the natural expiry boundary')
    while (delay := start + WAIT - clock()) > 0:
        sleep(min(delay, 1))
    require(remaining(start, clock()) > 0, 'sequence budget exhausted')
    state = observe_route(binary, client, expected, expired=True, old=old)
    elapsed_ms = math.floor((clock() - start) * 1000)
    require(WAIT * 1000 <= elapsed_ms < BUDGET * 1000, 'expiry interval outside budget')
    return dict(version=1, default_lifetime_seconds=LIFETIME, wait_lower_bound_seconds=WAIT,
        selected_to_expired_observation_ms=elapsed_ms, **state, manual_route_change=False,
        in_flight_expiry_claim=False)


def validate_boundary(value):
    require(set(value) == {'version', 'default_lifetime_seconds', 'wait_lower_bound_seconds',
        'selected_to_expired_observation_ms', 'control_relay_absent', 'paths_state',
        'manual_route_change', 'in_flight_expiry_claim'}, 'boundary fields')
    require(type(value['version']) is int and value['version'] == 1
        and type(value['default_lifetime_seconds']) is int and value['default_lifetime_seconds'] == LIFETIME
        and type(value['wait_lower_bound_seconds']) is int and value['wait_lower_bound_seconds'] == WAIT
        and type(value['selected_to_expired_observation_ms']) is int
        and WAIT * 1000 <= value['selected_to_expired_observation_ms'] < BUDGET * 1000
        and value['control_relay_absent'] is True and value['paths_state'] in ('empty', 'stale_original')
        and value['manual_route_change'] is value['in_flight_expiry_claim'] is False, 'boundary invalid')


def collect(binary, socket, baseline, scope, output, ready, start):
    """One bounded, overlapping Exit ring reader, including every idle interval.

    The scope only enables existing context-aware collection. It is NOT used to
    label new flows with the old route: final validation joins each context to
    independent bracketed live observations before/after the boundary.
    """
    coverage = OLD['Coverage'](baseline, scope)
    stopping, requested, failure = False, False, None
    samples = []
    def stopped(_signum, _frame):
        nonlocal stopping
        stopping = True
    def request_sample(_signum, _frame):
        nonlocal requested
        requested = True
    previous = {signum: signal.signal(signum, stopped) for signum in (signal.SIGINT, signal.SIGTERM)}
    previous[signal.SIGUSR1] = signal.signal(signal.SIGUSR1, request_sample)
    def sample():
        raw = query(binary, socket, ['logs', '--limit', str(OLD['LIMIT'])], time.monotonic() + 3)
        coverage.add(raw)
        elapsed = math.floor((time.monotonic() - start) * 1000)
        require(0 <= elapsed < BUDGET * 1000, 'collector elapsed bound')
        samples.append(elapsed)
        publish()
    def publish():
        result = dict(version=1, failure=failure, stop_received=stopping,
            event_baseline_unix_ms=baseline, samples=coverage.samples, observed_records=coverage.observed,
            completed=coverage.completed, failed=coverage.failed,
            contexts=[dict(route_context_id=c, **v) for c, v in sorted(coverage.contexts.items())],
            overlap_verified=failure is None,
            first_elapsed_ms=samples[0] if samples else None,
            last_elapsed_ms=samples[-1] if samples else None,
            max_sample_gap_ms=max((b - a for a, b in zip(samples, samples[1:])), default=0))
        pending = Path(str(output) + '.tmp')
        pending.write_text(json.dumps(result, sort_keys=True) + '\n')
        os.replace(pending, output)
    try:
        sample()
        Path(ready).write_text('ready\n')
        while not stopping:
            require(remaining(start) > 0, 'sequence budget exhausted')
            deadline = min(time.monotonic() + 5, start + BUDGET)
            while not stopping and not requested and time.monotonic() < deadline:
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            requested = False
            sample()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        failure = ('query_timeout' if isinstance(error, subprocess.TimeoutExpired) else
            'query_failed' if isinstance(error, subprocess.SubprocessError) else
            'local_io' if isinstance(error, OSError) else 'coverage_or_budget')
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        publish()
    return 0 if stopping and failure is None else 1


def validate_flows(value, old, new, boundary, prefix_elapsed):
    validate_boundary(boundary)
    require(set(value) == {'version', 'failure', 'stop_received', 'event_baseline_unix_ms', 'samples',
        'observed_records', 'completed', 'failed', 'contexts', 'overlap_verified',
        'first_elapsed_ms', 'last_elapsed_ms', 'max_sample_gap_ms'},
        'flow fields')
    require(type(value['version']) is int and value['version'] == 1 and value['failure'] is None
        and value['stop_received'] is value['overlap_verified'] is True,
        'flow observation incomplete')
    require(all(type(value[k]) is int for k in ('event_baseline_unix_ms', 'samples', 'observed_records',
        'completed', 'failed')) and value['event_baseline_unix_ms'] > 0
        and 2 <= value['samples'] <= OLD['MAX_SAMPLES']
        and 40 <= value['observed_records'] <= value['samples'] * OLD['LIMIT']
        and value['failed'] == 0 and value['completed'] == 40, 'flow counts')
    require(type(prefix_elapsed) is int and all(type(value[k]) is int for k in
        ('first_elapsed_ms', 'last_elapsed_ms', 'max_sample_gap_ms'))
        and 0 <= value['first_elapsed_ms'] <= prefix_elapsed < WAIT * 1000
        and boundary['selected_to_expired_observation_ms'] <= value['last_elapsed_ms'] < BUDGET * 1000
        and 0 < value['max_sample_gap_ms'] <= 10000
        and value['samples'] >= 1 + math.ceil((value['last_elapsed_ms'] - value['first_elapsed_ms']) / 10000),
        'idle collection span or cadence unconfirmed')
    require(old['route_context_id'] != new['route_context_id'], 'context did not change')
    expected = sorted([dict(route_context_id=old['route_context_id'], completed=24, failed=0),
        dict(route_context_id=new['route_context_id'], completed=16, failed=0)], key=lambda r: r['route_context_id'])
    # No extra test operation creates a flow. Additional production retries are
    # retained by the observer but rejected here, not silently assigned a cause.
    require(value['contexts'] == expected, 'old/new operation attribution differs')


def process_snapshot(work):
    """Disposable supervisor only; raw process identifiers never get exported."""
    result = {}
    for role in PROCESS_ROLES:
        kind, node = role.split('@')
        reply = subprocess.run(['systemctl', 'show', '--property=MainPID', '--value',
            f'volparossa-alpha-{kind}@{node}.service'], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, check=True, timeout=3)
        require(re.fullmatch(rb'[1-9][0-9]{0,9}\n', reply.stdout) is not None, 'agent pid invalid')
        pid = int(reply.stdout)
        record = Path(f'/proc/{pid}/stat').read_text()
        start = int(record.rpartition(') ')[2].split()[19])
        namespace = Path(f'/proc/{pid}/ns/net').stat()
        store = None
        if node in SEQ['NODES']:
            metadata = (work / f'state-{node}/private-store').lstat()
            require(stat.S_ISDIR(metadata.st_mode), 'provider store is not a directory')
            store = [metadata.st_dev, metadata.st_ino]
        result[role] = dict(pid=pid, start=start, netns=[namespace.st_dev, namespace.st_ino], store=store)
    return result


def validate_processes(values):
    require(type(values) is list and len(values) == 3, 'three process observations required')
    first = values[0]
    require(set(first) == set(PROCESS_ROLES), 'process roles')
    for role, row in first.items():
        node = role.split('@')[1]
        require(set(row) == {'pid', 'start', 'netns', 'store'}
            and all(type(row[k]) is int and row[k] > 0 for k in ('pid', 'start')),
            'process identity fields')
        require(type(row['netns']) is list and len(row['netns']) == 2
            and all(type(n) is int and n >= 0 for n in row['netns']) and row['netns'][1] > 0,
            'namespace identity')
        if node not in SEQ['NODES']:
            require(row['store'] is None, 'unexpected client store')
        else:
            require(type(row['store']) is list and len(row['store']) == 2
                and all(type(n) is int and n >= 0 for n in row['store']) and row['store'][1] > 0,
                'store identity')
    require(len({tuple(first[f'agent@{node}']['netns']) for node in ('client', *SEQ['NODES'])}) == 4
        and all(value == first for value in values[1:]), 'process, namespace or provider store changed')
    return dict(observations=3, same_agent_processes=True, same_network_namespaces=True,
        same_route_helpers=True, same_provider_store_inodes=True, process_identifiers_exported=False)


def validate_matrix(value):
    U = matrix_module()
    require(set(value) == {'version', 'before', 'after', 'created_from_empty'}
        and type(value['version']) is int and value['version'] == 1
        and value['created_from_empty'] is True, 'matrix identity')
    U['snapshot'](value['before'], detached=True)
    U['snapshot'](value['after'])
    require(len(json.dumps(value).encode()) <= U['MAX_BYTES'], 'matrix size')


def validate_network(value, peers, route, matrix):
    U = matrix_module()
    shared, net = U['OLD'], U['OLD']['NET']
    require(set(value) == {'selected_route', 'privacy', 'control_privacy', 'matrix_before', 'matrix_after'},
        'network phase fields')
    for side in ('matrix_before', 'matrix_after'):
        U['snapshot'](value[side])
        require(value[side] == matrix['after'], 'control matrix changed during phase')
    expected = policy(peers)
    S['validate_route'](route, expected)
    selected = value['selected_route']
    require(OLD['route_scope'](selected) == route['scope']
        and selected['route_context_id'] == route['route_context_id'], 'phase current route differs')
    used = {node for node in S['BROKERS']
        if peers[node] in {p['relay_peer_id'] for p in route['scope']['paths']}}
    require(len(used) == 2 and all(slot['relay_node'] in used
        and peers[slot['relay_node']] == slot['relay_peer_id'] for slot in selected['benchmark_slots']),
        'physical phase route differs')
    privacy = value['privacy']
    require(set(privacy) == set(SEQ['FRAG']['ROLES']), 'privacy roles')
    for role, capture in privacy.items():
        require(capture['capture_role'] == role and capture['content_provider_mode'] is True
            and capture['unexpected_outer_packets'] == capture['unexpected_provider_application_packets'] == 0
            and capture['expected_link_down_notifications'] == 0, 'unexpected phase egress')
        shared['provider_counters'](capture)
        net['validate_drained'](capture, allow_empty=role in S['BROKERS'] and role not in used)
        if role != 'exit':
            require(all(n == 0 for row in capture['provider_application'].values() for n in row.values()),
                'provider application bypass')
        if role in S['BROKERS']:
            number = S['BROKERS'].index(role)
            require(capture['interfaces'] == [f'r{number}c', f'r{number}x', 'underlay'], 'relay capture interfaces')
    require(privacy['client']['direct_client_exit_packets'] == privacy['client']['internet_destination_outer_packets'] == 0
        and privacy['exit']['direct_client_exit_packets'] == privacy['exit']['client_public_packets'] == 0
        and privacy['exit']['outbound_client_discovery_attempt_packets'] == 0
        and all(privacy[n]['internet_destination_outer_packets'] == 0 for n in S['BROKERS']), 'phase privacy')
    for node in used:
        require(privacy[node]['client_leg_wireguard_data_datagrams'] > 16
            and privacy[node]['exit_leg_wireguard_data_datagrams'] > 16, 'phase two-path traffic')
    for node in SEQ['NODES']:
        counters = privacy['exit']['provider_application'][node]
        require(counters['request_packets'] > 0 and counters['response_packets'] > 0, 'phase provider traffic')
    require(set(value['control_privacy']) == set(S['BROKERS']), 'control capture roles')
    for b, broker in enumerate(S['BROKERS']):
        capture = value['control_privacy'][broker]
        pairs = {f'cc{b}{p}': [net['PUBLIC_IPS'][broker], net['PUBLIC_IPS'][node]]
            for p, node in enumerate(U['PROVIDERS'])}
        require(capture['capture_role'] == 'content-control' and capture['content_provider_mode'] is True
            and capture['consumer_control_role'] == broker and capture['content_control_pairs'] == pairs
            and capture['interfaces'] == list(pairs) and set(capture['content_control_packets']) == set(pairs)
            and capture['unexpected_provider_control_packets'] == capture['unexpected_provider_application_packets'] == 0,
            'control boundary')
        shared['provider_counters'](capture)
        require(all(n == 0 for row in capture['provider_application'].values() for n in row.values()),
            'control application payload')
        for row in capture['content_control_packets'].values():
            require(set(row) == {'inbound', 'outbound'} and all(shared['count'](n) for n in row.values()),
                'control counters')
        net['validate_drained'](capture, allow_empty=True)


def evidence(work):
    value = {name: read(work / f"{SEQ['PREFIX']}-{name}.json")
        for name in ('prepare', 'private_cleanup', 'isolation', 'layout')}
    value['deleted_usage'] = SEQ['FRAG']['read_usage'](work / f"{SEQ['PREFIX']}-deleted_usage.json")
    value.update({name: read(work / f'{PREFIX}-{name}.json') for name in ('prefix', 'suffix', 'boundary',
        'initial', 'old', 'new', 'flows', 'prefix-clock', 'processes', 'matrix', 'cleanup')})
    value['expected_peers'] = read(work / 'a01-expected-peers.json')
    value['network'] = {}
    for phase in PHASES:
        value['network'][phase] = dict(selected_route=read(work / f'{PREFIX}-{phase}-live-selection.json'),
            privacy={role: read(work / f'{PREFIX}-{phase}-privacy-{role}.json') for role in SEQ['FRAG']['ROLES']},
            control_privacy={node: read(work / f'{PREFIX}-{phase}-control-{node}.json') for node in S['BROKERS']},
            **{f'matrix_{side}': read(work / f'{PREFIX}-{phase}-matrix-{side}.json') for side in ('before', 'after')})
    value.update(success=True, scope=dict(core_only=True, ordinary_expiry_between_operations=True,
        in_flight_expiry_claim=False, full_consumer_acceptance=False, original_failure_reproduced=False))
    validate_evidence(value)
    return value


def validate_evidence(value):
    SEQ['validate_owner_evidence'](value)
    require(value['prefix'] == dict(prefix_complete=True, sequence=prefix_result(), fixture_failure=None),
        'prefix incomplete')
    require(set(value['suffix']) == {'retained_owner_bytes_verified', 'sequence', 'fixture_failure'}
        and value['suffix']['retained_owner_bytes_verified'] is True and value['suffix']['fixture_failure'] is None,
        'retained owner verification incomplete')
    SEQ['validate_result'](value['suffix']['sequence'])
    require(value['initial'] == value['old'], 'prefix route changed before idle boundary')
    require(set(value['prefix-clock']) == {'elapsed_ms'}, 'prefix clock fields')
    validate_boundary(value['boundary'])
    validate_flows(value['flows'], value['old'], value['new'], value['boundary'], value['prefix-clock']['elapsed_ms'])
    require(value['processes'] == dict(observations=3, same_agent_processes=True, same_network_namespaces=True,
        same_route_helpers=True, same_provider_store_inodes=True, process_identifiers_exported=False), 'process continuity absent')
    require(value['cleanup'] == dict(abort_attempted=False, remote_cleanup_confirmed=True,
        collector_joined=True, owner_cleanup_confirmed=True), 'cleanup incomplete')
    validate_matrix(value['matrix'])
    for phase, route in (('prefix', value['old']), ('suffix', value['new'])):
        validate_network(value['network'][phase], value['expected_peers'], route, value['matrix'])
    require(value['layout']['route_context_id'] == value['initial']['route_context_id']
        and value['layout']['route_scope'] == value['initial']['scope']
        and value['layout']['control_relay_peer_id'] == value['initial']['control_relay_peer_id'], 'initial layout changed')
    require(value['scope'] == dict(core_only=True, ordinary_expiry_between_operations=True,
        in_flight_expiry_claim=False, full_consumer_acceptance=False, original_failure_reproduced=False)
        and value['success'] is True, 'expiry scope changed')


def validate_report(value, revision):
    require(re.fullmatch('[0-9a-f]{40}', revision) and value['source_revision'] == revision
        and value['schema_version'] == 1 and value['report_kind'] == f'volparossa-{PREFIX}'
        and value['success'] is True and value['runner_exit_status'] == 0
        and value['phase'] == f'{PREFIX}-complete' and value['observed_blocker'] is None
        and value['cleanup']['complete'] is True and value['cleanup']['remaining_owned_objects'] == 0
        and value['host_state']['unchanged'] is True, 'expiry source/host cleanup incomplete')
    validate_evidence(value['storage'])


def main(args):
    command = args[0]
    if args == ['export-names']:
        print('\n'.join(EXPORT_NAMES)); return 0
    if command in ('prefix', 'suffix', 'abort'):
        require(len(args) == (8 if command == 'abort' else 7), 'owner arguments')
        root = SEQ['private_root'](args[1])
        selected = globals()[command]
        extra = [int(args[7])] if command == 'abort' else []
        value = selected(root, args[2], args[3], args[4:7], *extra)
        print(json.dumps(value, sort_keys=True))
        return 0 if (value.get('prefix_complete') is True or value.get('sequence', {}).get('success') is True
            or command == 'abort' and value['remote_cleanup_complete'] and value['cli_children_joined']) else 1
    if command == 'clock' and len(args) == 1:
        print(time.monotonic()); return 0
    if command == 'remaining' and len(args) == 2:
        print(remaining(float(args[1]))); return 0
    if command == 'elapsed' and len(args) == 2:
        value = dict(elapsed_ms=math.floor((time.monotonic() - float(args[1])) * 1000))
    elif command == 'process-snapshot' and len(args) == 2:
        value = process_snapshot(Path(args[1]))
    elif command == 'process-check' and len(args) == 4:
        value = validate_processes([read(Path(p)) for p in args[1:]])
    elif command == 'same-route' and len(args) == 3:
        require(read(Path(args[1])) == read(Path(args[2])), 'original route changed before idle wait')
        return 0
    elif command == 'matrix-check' and len(args) in (3, 4):
        matrix_module()['snapshot'](read(Path(args[2])), detached=args[1] == 'empty')
        require(args[1] in ('empty', 'installed'), 'matrix check stage')
        if len(args) == 4:
            require(read(Path(args[2])) == read(Path(args[3]))['after'], 'matrix changed')
        return 0
    elif command == 'prefix-flows' and len(args) == 3:
        flow, route = read(Path(args[1])), read(Path(args[2]))
        require(flow['failure'] is None and flow['completed'] == 24 and flow['failed'] == 0
            and flow['contexts'] == [dict(route_context_id=route['route_context_id'], completed=24, failed=0)],
            'prefix flow completion missing')
        return 0
    elif command == 'final-flows' and len(args) == 4:
        flow, old, new = (read(Path(p)) for p in args[1:])
        require(flow['failure'] is None and flow['completed'] == 40 and flow['failed'] == 0
            and flow['contexts'] == sorted([
                dict(route_context_id=old['route_context_id'], completed=24, failed=0),
                dict(route_context_id=new['route_context_id'], completed=16, failed=0)], key=lambda r: r['route_context_id']),
            'final context completions missing')
        return 0
    elif command == 'evidence' and len(args) == 2:
        value = evidence(Path(args[1]))
    elif command == 'report' and len(args) == 3:
        validate_report(read(Path(args[1])), args[2]); return 0
    elif command == 'observe' and len(args) == 4:
        value = observe_route(args[1], args[2], policy(read(Path(args[3]))))
    elif command == 'wait' and len(args) == 6:
        value = natural_wait(float(args[1]), args[2], args[3], policy(read(Path(args[4]))), read(Path(args[5])))
    elif command == 'collect' and len(args) == 8:
        return collect(args[1], args[2], int(args[3]), read(Path(args[4]))['scope'], args[5], args[6], float(args[7]))
    else:
        raise ValueError('expiry arguments')
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] != 'collect':
        def interrupted(_signum, _frame):
            raise ValueError('expiry fixture interrupted')
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupted)
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        sys.exit('natural expiry fixture failed; private diagnostics not exported')
