#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert contracts: fake CLI/files/clocks only; never native or network execution."""
import copy
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
C = runpy.run_path(str(HERE / 'private-storage-natural-expiry.py'))
T = runpy.run_path(str(HERE / 'test-private-storage-deposit-sequence.py'))
SEQ = C['SEQ']
KEYS = T['KEYS']
POLICY = dict(exit_peer_id='exit', relay_peers={f'relay{n}': f'relay{n}' for n in range(3)})
OLD = dict(route_context_id='1' * 32, control_relay_peer_id='relay2',
    scope=dict(exit_peer_id='exit', paths=[dict(path_id=1, relay_peer_id='relay0'),
        dict(path_id=2, relay_peer_id='relay1')]))
NEW = dict(route_context_id='2' * 32, control_relay_peer_id='relay0',
    scope=dict(exit_peer_id='exit', paths=[dict(path_id=1, relay_peer_id='relay1'),
        dict(path_id=2, relay_peer_id='relay2')]))


def paths(route):
    return ''.join(f"context={route['route_context_id']} path={p['path_id']} relay={p['relay_peer_id']} "
        'exit=exit state=1 rtt_us=1 bytes=1\n' for p in route['scope']['paths']).encode()


def boundary():
    return dict(version=1, default_lifetime_seconds=600, wait_lower_bound_seconds=601,
        selected_to_expired_observation_ms=601001, control_relay_absent=True, paths_state='empty',
        manual_route_change=False, in_flight_expiry_claim=False)


def fixture():
    N = runpy.run_path(str(HERE / 'test-storage-consumer-network.py'))
    source = N['fixture']()
    old = copy.deepcopy(source['network']['finish']['gates']['observed_context_routes'][-1])
    new = copy.deepcopy(old)
    new['route_context_id'] = 'd' * 32
    new['control_relay_peer_id'] = source['expected_peers']['relay1']
    new['scope']['paths'][0]['relay_peer_id'] = source['expected_peers']['relay0']
    value = T['evidence_fixture']()
    value.pop('sequence')
    value.update(scope=dict(core_only=True, ordinary_expiry_between_operations=True,
        in_flight_expiry_claim=False, full_consumer_acceptance=False, original_failure_reproduced=False),
        prefix=dict(prefix_complete=True, sequence=C['prefix_result'](), fixture_failure=None),
        suffix=dict(retained_owner_bytes_verified=True, sequence=T['completed'](), fixture_failure=None),
        boundary=boundary(), initial=copy.deepcopy(old), old=old, new=new,
        flows=dict(version=1, failure=None, stop_received=True, event_baseline_unix_ms=1,
            samples=130, observed_records=100, completed=40, failed=0, overlap_verified=True,
            first_elapsed_ms=1000, last_elapsed_ms=650000, max_sample_gap_ms=8000,
            contexts=[dict(route_context_id=old['route_context_id'], completed=24, failed=0),
                dict(route_context_id=new['route_context_id'], completed=16, failed=0)]),
        processes=dict(observations=3, same_agent_processes=True, same_network_namespaces=True,
            same_route_helpers=True, same_provider_store_inodes=True, process_identifiers_exported=False),
        cleanup=dict(abort_attempted=False, remote_cleanup_confirmed=True, collector_joined=True, owner_cleanup_confirmed=True),
        matrix=dict(version=1, created_from_empty=True, before=source['control_underlay']['detached'],
            after=source['control_underlay']['after']), expected_peers=source['expected_peers'])
    value['prefix-clock'] = dict(elapsed_ms=60000)
    value['layout'].update(route_context_id=old['route_context_id'], route_scope=old['scope'],
        control_relay_peer_id=old['control_relay_peer_id'])
    value['network'] = {}
    for phase, route in (('prefix', old), ('suffix', new)):
        base = copy.deepcopy(source['network']['finish'])
        selected = base['selected_route']
        selected['route_context_id'] = route['route_context_id']
        selected['exact_selected_relays'] = [p['relay_peer_id'] for p in route['scope']['paths']]
        for index, path in enumerate(route['scope']['paths']):
            node = next(n for n in C['S']['BROKERS'] if source['expected_peers'][n] == path['relay_peer_id'])
            selected['paths'][index].update(**path, route_context_id=route['route_context_id'])
            selected['benchmark_slots'][index].update(**path, relay_node=node)
        value['network'][phase] = dict(selected_route=selected, privacy=base['privacy'],
            control_privacy=base['control_privacy'], matrix_before=base['control_before'], matrix_after=base['control_after'])
    return value


def write_fixture(work):
    value = fixture()
    files = {f"{SEQ['PREFIX']}-{name}.json": value[name]
        for name in ('prepare', 'private_cleanup', 'isolation', 'layout', 'deleted_usage')}
    files.update({f"{C['PREFIX']}-{name}.json": value[name] for name in ('prefix', 'suffix', 'boundary',
        'initial', 'old', 'new', 'flows', 'prefix-clock', 'processes', 'matrix', 'cleanup')})
    files['a01-expected-peers.json'] = value['expected_peers']
    for phase, network in value['network'].items():
        prefix = f"{C['PREFIX']}-{phase}"
        files[f'{prefix}-live-selection.json'] = network['selected_route']
        for side in ('before', 'after'):
            files[f'{prefix}-matrix-{side}.json'] = network[f'matrix_{side}']
        for role, capture in network['privacy'].items():
            files[f'{prefix}-privacy-{role}.json'] = capture
        for broker, capture in network['control_privacy'].items():
            files[f'{prefix}-control-{broker}.json'] = capture
    for name, content in files.items():
        (work / name).write_text(json.dumps(content))
    return value


class NaturalExpiry(unittest.TestCase):
    def execute(self, operation, *, failure=None):
        with tempfile.TemporaryDirectory(prefix='vp-expiry-inert-') as directory:
            root = Path(directory) / 'private-storage-user'
            root.mkdir(mode=0o700)
            fake, calls = T['DepositSequence']().fake_cli(root, failure)
            with mock.patch.dict(SEQ['run'].__globals__, invoke=fake):
                SEQ['prepare'](root, 'inert-fixture-cli', 'client', ['A', 'B', 'C'], KEYS)
                result = operation(root)
            SEQ['cleanup'](str(root))
            self.assertFalse(root.exists())
            return result, calls

    def test_two_driver_phases_same_state_and_exact_production_order(self):
        def run(root):
            initial = C['prefix'](root, 'inert-fixture-cli', 'client', KEYS)
            self.assertEqual(initial, dict(prefix_complete=True, fixture_failure=None, sequence=C['prefix_result']()))
            final = C['suffix'](root, 'inert-fixture-cli', 'client', KEYS)
            SEQ['validate_result'](final['sequence'])
            self.assertTrue(final['retained_owner_bytes_verified'])
            return final
        value, calls = self.execute(run)
        operations = [a[3] if a[2].startswith('--') else a[2] for a in calls if a[:2] == ['storage', 'replicas']]
        self.assertEqual(operations, ['create'] * 5 + ['deposit'] * 5 + ['delete'] * 10)
        self.assertIsNone(value['fixture_failure'])

    def test_changed_private_state_rejected_but_known_prefix_cleanup_attempted(self):
        for relative in ('identity.key', 'grant-1.bin', 'set-2/replicas.json', 'set-0/copy-0/archive.json'):
            def run(root):
                self.assertTrue(C['prefix'](root, 'inert-fixture-cli', 'client', KEYS)['prefix_complete'])
                path = root / relative
                path.write_bytes(path.read_bytes() + b' ')
                result = C['suffix'](root, 'inert-fixture-cli', 'client', KEYS)
                self.assertFalse(result['retained_owner_bytes_verified'])
                self.assertEqual(result['fixture_failure'], 'retained_prefix')
                self.assertEqual(result['sequence']['deleted_copies'], 8)
                self.assertFalse(result['sequence']['success'])
            self.execute(run)

    def test_final_unknown_reservation_remains_explicit_with_closed_diagnostic(self):
        def run(root):
            self.assertTrue(C['prefix'](root, 'inert-fixture-cli', 'client', KEYS)['prefix_complete'])
            result = C['suffix'](root, 'inert-fixture-cli', 'client', KEYS)['sequence']
            self.assertTrue(result['unknown_reservation'])
            self.assertFalse(result['remote_cleanup_complete'])
            self.assertEqual(result['deleted_copies'], 9)
            self.assertEqual(result['failure']['diagnostics'], T['diagnostic'](1))
            self.assertNotIn('PRIVATE-STDERR', json.dumps(result))
        self.execute(run, failure=9)

    def test_wait_abort_deletes_eight_without_attempting_final_pair(self):
        def run(root):
            C['prefix'](root, 'inert-fixture-cli', 'client', KEYS)
            value = C['abort'](root, 'inert-fixture-cli', 'client', KEYS, 8)
            self.assertTrue(value['remote_cleanup_complete'])
            self.assertEqual(value['deleted_copies'], 8)
            self.assertFalse(value['success'])
        _, calls = self.execute(run)
        self.assertEqual(sum(a[:4] == ['storage', 'replicas', '--tls-close-diagnostics-v9', 'deposit'] for a in calls), 4)

    def test_failed_prefix_attempts_cleanup_and_never_issues_checkpoint(self):
        def run(root):
            value = C['prefix'](root, 'inert-fixture-cli', 'client', KEYS)
            self.assertFalse(value['prefix_complete'])
            self.assertFalse((root / C['CHECKPOINT']).exists())
            self.assertEqual(value['sequence']['deleted_copies'], 7)
            self.assertTrue(value['sequence']['unknown_reservation'])
        self.execute(run, failure=7)

    def test_observed_expiry_accepts_only_absent_broker_empty_or_exact_stale_paths(self):
        for raw in (b'', paths(OLD)):
            with mock.patch.dict(C['observe_route'].__globals__, query=mock.Mock(side_effect=[raw,
                    b'{"control_relay_peer_id":""}', raw])):
                observed = C['observe_route']('unused', 'unused', POLICY, expired=True, old=OLD)
            self.assertTrue(observed['control_relay_absent'])
        for rows in ([paths(OLD), b'{"control_relay_peer_id":"relay2"}', paths(OLD)],
                     [paths(NEW), b'{"control_relay_peer_id":""}', paths(NEW)],
                     [b'', b'{"control_relay_peer_id":""}', paths(OLD)],
                     [b'', b'{"control_relay_peer_id":null}', b''],
                     [b'', b'{}', b''], [b'', b'{"control_relay_peer_id":null,"control_relay_peer_id":null}', b'']):
            with mock.patch.dict(C['observe_route'].__globals__, query=mock.Mock(side_effect=rows)):
                with self.assertRaises(ValueError):
                    C['observe_route']('unused', 'unused', POLICY, expired=True, old=OLD)

    def test_monotonic_wait_and_single_budget_are_not_restarted_for_suffix(self):
        now, sleeps = [150.0], []
        def sleep(delay):
            sleeps.append(delay)
            now[0] += delay
        with mock.patch.dict(C['natural_wait'].__globals__, observe_route=mock.Mock(return_value=dict(
                control_relay_absent=True, paths_state='empty'))):
            value = C['natural_wait'](100.0, 'unused', 'unused', POLICY, OLD, clock=lambda: now[0], sleep=sleep)
        C['validate_boundary'](value)
        self.assertEqual(now[0], 701.0)
        self.assertEqual(C['remaining'](100.0, now[0]), 299)
        self.assertTrue(all(0 < delay <= 1 for delay in sleeps))
        self.assertEqual(C['remaining'](100.0, 1001.0), 0)
        for invalid in (float('nan'), float('inf'), -1, True):
            with self.assertRaises(ValueError):
                C['remaining'](invalid, 150.0)
        with self.assertRaises(ValueError):
            C['natural_wait'](100.0, 'unused', 'unused', POLICY, OLD, clock=lambda: 702.0, sleep=sleep)

    def test_context_counts_do_not_allow_union_or_hidden_retry_attribution(self):
        value = dict(version=1, failure=None, stop_received=True, event_baseline_unix_ms=1,
            samples=130, observed_records=100, completed=40, failed=0, overlap_verified=True,
            first_elapsed_ms=1000, last_elapsed_ms=650000, max_sample_gap_ms=8000,
            contexts=[dict(route_context_id=OLD['route_context_id'], completed=24, failed=0),
                dict(route_context_id=NEW['route_context_id'], completed=16, failed=0)])
        C['validate_flows'](value, OLD, NEW, boundary(), 60000)
        for key, bad in (('samples', 513), ('samples', 2), ('failed', 1), ('completed', 41),
                         ('first_elapsed_ms', 70000), ('last_elapsed_ms', 600000), ('max_sample_gap_ms', 10001)):
            changed = copy.deepcopy(value)
            changed[key] = bad
            with self.assertRaises(ValueError):
                C['validate_flows'](changed, OLD, NEW, boundary(), 60000)
        changed = copy.deepcopy(value)
        changed['contexts'][0]['completed'] = 23
        changed['contexts'][1]['completed'] = 17
        with self.assertRaises(ValueError):
            C['validate_flows'](changed, OLD, NEW, boundary(), 60000)
        with self.assertRaises(ValueError):
            C['validate_flows'](value, OLD, OLD, boundary(), 60000)

    def test_file_backed_evidence_and_independent_network_transition_gates(self):
        value = fixture()
        C['validate_evidence'](value)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            self.assertEqual(write_fixture(work), value)
            self.assertEqual(C['evidence'](work), value)
        changes = (
            lambda v: v['old']['scope']['paths'][0].update(relay_peer_id=v['expected_peers']['relay0']),
            lambda v: v['new'].update(route_context_id=v['old']['route_context_id']),
            lambda v: v['network']['suffix']['selected_route'].update(route_context_id=v['old']['route_context_id']),
            lambda v: v['network']['prefix']['privacy']['relay1'].update(client_leg_wireguard_data_datagrams=0),
            lambda v: v['network']['suffix']['privacy']['relay0'].update(exit_leg_wireguard_data_datagrams=0),
            lambda v: v['network']['suffix']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['network']['prefix']['control_privacy']['relay0'].update(unexpected_provider_application_packets=1),
            lambda v: v['network']['suffix']['matrix_after']['nodes']['relay0']['routes'].pop(),
            lambda v: v['matrix']['before']['nodes']['relay0']['links'].append(dict(ifname='ac0')),
            lambda v: v['cleanup'].update(collector_joined=False),
            lambda v: v['suffix'].update(retained_owner_bytes_verified=False),
            lambda v: v['deleted_usage'][0].update(leases=1),
            lambda v: v['processes'].update(same_agent_processes=False),
        )
        for index, change in enumerate(changes):
            changed = copy.deepcopy(value)
            change(changed)
            with self.subTest(index=index), self.assertRaises((KeyError, ValueError)):
                C['validate_evidence'](changed)

    def test_retained_process_store_and_namespace_identity_not_only_same_pid(self):
        first = {role: dict(pid=100 + i, start=200 + i, netns=[1, 300 + i],
            store=[2, 400 + i] if role.split('@')[1] in SEQ['NODES'] else None)
            for i, role in enumerate(C['PROCESS_ROLES'])}
        records = [copy.deepcopy(first) for _ in range(3)]
        self.assertTrue(C['validate_processes'](records)['same_agent_processes'])
        for field in ('pid', 'start', 'netns', 'store'):
            altered = copy.deepcopy(records)
            altered[2]['agent@relay4'][field] = [9, 999] if field in ('netns', 'store') else 999
            with self.assertRaises(ValueError):
                C['validate_processes'](altered)
        altered = copy.deepcopy(records)
        altered[1]['helper@client']['start'] += 1
        with self.assertRaises(ValueError):
            C['validate_processes'](altered)

    def test_collector_spans_real_fake_clock_idle_window_and_joins_on_stop(self):
        self.collector_case('stop')

    def test_collector_budget_timeout_and_overlap_failures_remain_closed(self):
        for failure in ('budget', 'timeout', 'overlap'):
            self.collector_case(failure)

    def collector_case(self, mode):
        now, handlers, queries = [101.0], {}, [0]
        def changed(signum, handler):
            previous = handlers.get(signum)
            handlers[signum] = handler
            return previous
        def sleep(duration):
            now[0] += duration
            if mode == 'stop' and now[0] >= 750 and handlers.get(signal.SIGTERM):
                handlers[signal.SIGTERM](signal.SIGTERM, None)
        def event(stamp, code, context=''):
            return f'{stamp}\tlevel=1\tevent={code}\tsession={context}\tpath=-\n'.encode()
        initial = event(10, 'READY')
        old = b''.join(event(30 + n, 'MPTCP_EXIT_FLOW_COMPLETED', OLD['route_context_id']) for n in range(24))
        new = b''.join(event(100 + n, 'MPTCP_EXIT_FLOW_COMPLETED', NEW['route_context_id']) for n in range(16))
        def query(*_args):
            queries[0] += 1
            if queries[0] > 1 and mode == 'timeout':
                raise subprocess.TimeoutExpired('PRIVATE-COMMAND', 3, output=b'PRIVATE-DATA')
            if queries[0] > 1 and mode == 'overlap':
                return event(11, 'CHANGED')
            return initial + (old if now[0] >= 106 else b'') + (new if now[0] >= 710 else b'')
        with tempfile.TemporaryDirectory() as temporary:
            output, ready = Path(temporary) / 'output', Path(temporary) / 'ready'
            with mock.patch.dict(C['collect'].__globals__, query=query,
                    signal=SimpleNamespace(SIGINT=signal.SIGINT, SIGTERM=signal.SIGTERM,
                        SIGUSR1=signal.SIGUSR1, signal=changed),
                    time=SimpleNamespace(monotonic=lambda: now[0], sleep=sleep)):
                status = C['collect']('unused', 'unused', 20, OLD['scope'], output, ready, 100.0)
            value = json.loads(output.read_text())
        self.assertNotIn('PRIVATE', json.dumps(value))
        if mode == 'stop':
            self.assertEqual(status, 0)
            C['validate_flows'](value, OLD, NEW, boundary(), 60000)
            self.assertGreaterEqual(value['samples'], 120)
            self.assertGreaterEqual(value['last_elapsed_ms'], 650000)
        else:
            self.assertEqual(status, 1)
            self.assertIsNotNone(value['failure'])
            self.assertFalse(value['overlap_verified'])
            with self.assertRaises(ValueError):
                C['validate_flows'](value, OLD, NEW, boundary(), 60000)

    def test_actual_terminal_tail_clears_not_reached_only_after_evidence(self):
        shell = (HERE / 'private-storage-natural-expiry.sh').read_text()
        beginning = shell.index('    private_storage_expiry_tool evidence "$WORK"')
        tail = shell[beginning:shell.index('\n}', beginning)]
        script = r'''
set -eu
WORK=$1; output_directory=$2; source_directory=$3; CASE=$4
expected_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN_ID=inert-expiry-finalizer
OUTPUT_UID=$(id -u); OUTPUT_GID=$(id -g)
CLEANUP_COMPLETE=true; REMAINING_OWNED_OBJECTS=0
PHASE=private-storage-natural-expiry-suffix
OBSERVED_BLOCKER=NOT_REACHED
. "$source_directory/tests/integration/private-storage-natural-expiry.sh"
optional_json_evidence() { if [ -f "$1" ]; then cat "$1"; else printf 'null\n'; fi; }
fail() { OBSERVED_BLOCKER=$1; exit 1; }
python3() {
    if [ "$CASE" = diagnostic-failed ] && [ "${3:-}" = initial-route-selection ]; then return 1; fi
    command python3 "$@"
}
trap 'status=$?; trap - EXIT; private_storage_expiry_finalize_report "$status"' EXIT
'''
        after = r'''
if [ "$CASE" = cleanup-failed ]; then
    OBSERVED_BLOCKER=A15_HOST_STATE_CHANGED
    CLEANUP_COMPLETE=false
    REMAINING_OWNED_OBJECTS=1
    exit 1
fi
'''
        for case in ('success', 'evidence-failed', 'cleanup-failed', 'old-marker', 'diagnostic-failed'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                work, output = Path(temporary) / 'work', Path(temporary) / 'output'
                work.mkdir(); output.mkdir()
                write_fixture(work)
                (work / 'a15-evidence.json').write_text('{"unchanged":true}')
                if case == 'evidence-failed':
                    (work / f"{SEQ['PREFIX']}-deleted_usage.json").write_text('[{}]')
                completion = tail if case != 'old-marker' else tail.replace('    OBSERVED_BLOCKER=NONE\n', '')
                result = subprocess.run(['sh', '-c', script + completion + after, 'inert-finalizer',
                    str(work), str(output), str(HERE.parents[1]), case], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0 if case in ('success', 'diagnostic-failed') else 1, result.stderr)
                report = json.loads((output / f"{C['PREFIX']}-smoke.json").read_text())
                self.assertTrue(set(p.name for p in output.iterdir()) <= set(C['EXPORT_NAMES']))
                if case in ('success', 'diagnostic-failed'):
                    if case == 'diagnostic-failed':
                        self.assertEqual(report['initial_route_selection'],
                            dict(schema_version=1, status='invalid', route=None))
                    C['validate_report'](report, 'a' * 40)
                else:
                    with self.assertRaises((ValueError, KeyError)):
                        C['validate_report'](report, 'a' * 40)

    def test_closed_vm_export_exact_parity_and_private_failure_files_excluded(self):
        diagnostic = T['WIRING']['diagnostics']()
        self.assertEqual(set(C['EXPORT_NAMES']), diagnostic['EXPIRY_NAMES'])
        self.assertEqual(len(C['EXPORT_NAMES']), 42)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, opt = root / 'guest', root / 'opt'
            home.mkdir(); opt.mkdir()
            work = opt / ('va.' + 'a' * 32 + '.ABCdef')
            work.mkdir()
            (home / 'alpha-output').mkdir()
            (home / 'guest-phase.txt').write_text('topology\n')
            for name in C['EXPORT_NAMES']:
                (work / name).write_text('{"inert_structural_fixture":true}\n')
            for name in ('expiry-process-initial.private', 'expiry-collector.private', 'agent-client.log',
                         'identity.key', '.tmpExpiryCheckpoint', 'private-storage-natural-expiry-unlisted.json'):
                (work / name).write_text('PRIVATE-MUST-NOT-EXPORT')
            archive = diagnostic['collect'](home, opt, 'b' * 40, C['PREFIX'], 124, root / 'cgroups', root / 'proc')
            with tarfile.open(archive) as bundle:
                files = {member.name: bundle.extractfile(member).read() for member in bundle.getmembers()}
            self.assertTrue(all('work-1/' + name in files for name in C['EXPORT_NAMES']))
            self.assertFalse(any(b'PRIVATE-MUST-NOT-EXPORT' in data for data in files.values()))
            self.assertFalse(json.loads(files['vm-incomplete.json'])['success'])

    def test_initial_selection_failure_survives_actual_prepare_and_report_finalization(self):
        # Real fixture shell control flow with fake CLI/status/clock inputs only.
        # This reproduces the original failure phase, not a real route or cleanup.
        script = r'''
set -eu
WORK=$1; output_directory=$2; source_directory=$3; mode=$4; kind=$5; capture=$6
binary_directory=/unused
WORKER_UID=$(id -u); WORKER_GID=$(id -g); AGENT_GID=999999
OUTPUT_UID=$WORKER_UID; OUTPUT_GID=$WORKER_GID
expected_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN_ID=inert-initial-selection
CLEANUP_COMPLETE=true; REMAINING_OWNED_OBJECTS=0
PHASE=initial; OBSERVED_BLOCKER=NOT_REACHED
private_storage_deposit_sequence=no; private_storage_natural_expiry=no
if [ "$capture" = yes ]; then
    if [ "$kind" = fresh ]; then private_storage_deposit_sequence=yes
    else private_storage_natural_expiry=yes; fi
fi
. "$source_directory/tests/integration/benchmark-selection.sh"
. "$source_directory/tests/integration/private-storage-deposit-sequence-smoke.sh"
. "$source_directory/tests/integration/private-storage-natural-expiry.sh"
getent() { printf 'volparossa-users:x:123456:\n'; }
date() { printf '0\n'; }
sleep() { :; }
timeout() {
    printf 'connect\n' >>"$WORK/calls.private"
    case $mode in
        terminal) printf 'Error: agent rejected request: NO_ELIGIBLE_PATHS (Unavailable)\n' >&2; return 1 ;;
        unknown) printf 'PRIVATE token=secret host=192.0.2.99\n' >&2; return 9 ;;
        deadline) return 124 ;;
    esac
    return 0
}
benchmark_capture_paths() { return 3; }
optional_json_evidence() { if [ -f "$1" ]; then cat "$1"; else printf 'null\n'; fi; }
fail() { OBSERVED_BLOCKER=$1; exit 1; }
finish() {
    status=$?
    trap - EXIT
    if [ "$kind" = fresh ]; then private_storage_sequence_finalize_report "$status"
    else private_storage_expiry_finalize_report "$status"; fi
}
trap finish EXIT
private_storage_sequence_prepare
exit 99
'''
        for kind in ('fresh', 'natural'):
            for mode, reason, code, path_status in (
                    ('terminal', 'CONNECT_REJECTED', 'NO_ELIGIBLE_PATHS', None),
                    ('unknown', 'CONNECT_REJECTED', 'UNRECOGNIZED', None),
                    ('deadline', 'CONNECT_TIMEOUT', 'UNRECOGNIZED', None),
                    ('paths', 'PATHS_INVALID_OR_QUERY_FAILED', 'CONNECTED', 3)):
                for capture in ('yes', 'no'):
                    with self.subTest(kind=kind, mode=mode, capture=capture), tempfile.TemporaryDirectory() as temporary:
                        work, output = Path(temporary) / 'work', Path(temporary) / 'output'
                        (work / 'client-fixtures').mkdir(parents=True); output.mkdir()
                        (work / 'a15-evidence.json').write_text('{"unchanged":true}')
                        result = subprocess.run(['sh', '-c', script, 'initial-selection', str(work),
                            str(output), str(HERE.parents[1]), mode, kind, capture],
                            capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 1, result.stderr)
                        prefix = SEQ['PREFIX'] if kind == 'fresh' else C['PREFIX']
                        encoded = (output / f'{prefix}-smoke.json').read_text()
                        report = json.loads(encoded)
                        self.assertFalse(report['success'])
                        self.assertEqual(report['runner_exit_status'], 1)
                        self.assertEqual(report['phase'], f"{SEQ['PREFIX']}-prepare")
                        self.assertEqual(report['observed_blocker'], 'SEQUENCE_ROUTE_UNAVAILABLE')
                        self.assertIsNone(report['storage'])
                        self.assertEqual(report['cleanup'], dict(complete=True, remaining_owned_objects=0))
                        projection = report['initial_route_selection']
                        SEQ['validate_initial_route_selection'](projection)
                        self.assertEqual(projection['status'], 'observed' if capture == 'yes' else 'missing')
                        if capture == 'yes':
                            route = projection['route']
                            self.assertEqual(route['reason'], reason)
                            self.assertEqual(route['last_connect_reason'], code)
                            self.assertEqual(route['path_status'], path_status)
                            self.assertEqual(route['attempts'], 1)
                        self.assertEqual((work / 'calls.private').read_text(), 'connect\n')
                        self.assertTrue(set(p.name for p in output.iterdir()) <= set(
                            SEQ['EXPORT_NAMES'] if kind == 'fresh' else C['EXPORT_NAMES']))
                        for forbidden in ('PRIVATE', 'secret', '192.0.2.99', str(work)):
                            self.assertNotIn(forbidden, encoded)

    def test_diagnostic_dispatch_remains_exact_source_and_branch_bound(self):
        import contextlib
        import io
        import textwrap
        workflow = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
        start = workflow.index('      - name: Bind natural-expiry sequence candidate')
        block = workflow[start:workflow.index('\n      - name:', start + 1)]
        self.assertIn('refs/heads/test/storage-natural-expiry-sequence|refs/heads/diagnostic/storage-route-selection-20261021', block)
        self.assertNotIn('refs/heads/diagnostic/*', block)
        code = textwrap.dedent(block.split("python3 -B - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
        diagnostic = {'.github/workflows/alpha-topology.yml',
            'tests/integration/benchmark-selection.sh', 'tests/integration/test-benchmark-selection.py',
            'tests/integration/private-storage-deposit-sequence-smoke.py',
            'tests/integration/private-storage-deposit-sequence-smoke.sh',
            'tests/integration/test-private-storage-deposit-sequence.py',
            'tests/integration/private-storage-natural-expiry.py',
            'tests/integration/private-storage-natural-expiry.sh',
            'tests/integration/test-private-storage-natural-expiry.py'}
        original = {'.github/workflows/alpha-topology.yml', 'tests/integration/kvm-alpha-topology.sh',
            'tests/integration/run-alpha-topology-vm.sh', 'tests/integration/private-storage-deposit-sequence-smoke.py',
            'tests/integration/private-storage-deposit-sequence-smoke.sh',
            'tests/integration/storage-consumer-control-underlay.sh', 'tests/integration/private-storage-natural-expiry.py',
            'tests/integration/private-storage-natural-expiry.sh', 'tests/integration/test-private-storage-natural-expiry.py'}
        for branch, allowed, base in (
                ('diagnostic/storage-route-selection-20261021', diagnostic, 'b2b9c6b3483ba13ad02ee1c1b3b23e1eaf0b8fc9'),
                ('test/storage-natural-expiry-sequence', original, 'd19f0246bf1ee8610e7cbc9bd52bdb973aedd289')):
            for added in (None, 'crates/volparossa-agent/src/route_setup.rs'):
                changed = sorted(allowed | ({added} if added else set()))
                with (self.subTest(branch=branch, added=added), mock.patch.dict(os.environ,
                        GITHUB_REF=f'refs/heads/{branch}'), mock.patch('subprocess.check_output',
                        return_value='\n'.join(changed)) as output, mock.patch('subprocess.run') as run,
                        contextlib.redirect_stdout(io.StringIO())):
                    if added:
                        with self.assertRaises(AssertionError):
                            exec(compile(code, 'inert-source-gate', 'exec'), {})
                    else:
                        exec(compile(code, 'inert-source-gate', 'exec'), {})
                    output.assert_called_once_with(['git', 'diff', '--name-only', base, 'HEAD'], text=True)
                    if branch.startswith('diagnostic/'):
                        run.assert_called_once_with(['git', 'merge-base', '--is-ancestor', base, 'HEAD'], check=True)
                    else:
                        run.assert_not_called()

    def test_optional_dispatch_and_previews_preserve_fresh_and_other_storage(self):
        source = (HERE / 'kvm-alpha-topology.sh').read_text()
        start = source.index('if [ "${private_storage_natural_expiry:-no}" = yes ]; then\n')
        block = source[start:source.index('if [ "$private_storage_fragments" = yes ]; then\n', start)]
        for expiry, sequence, expected in ((None, 'yes', 'fresh'), ('no', 'yes', 'fresh'),
                ('yes', 'yes', 'expiry'), (None, 'no', 'other')):
            prefix = 'set -eu\nprivate_storage_deposit_sequence=' + sequence + '\n'
            if expiry is not None:
                prefix += 'private_storage_natural_expiry=' + expiry + '\n'
            prefix += 'private_storage_expiry_run() { printf expiry; }\nprivate_storage_sequence_run() { printf fresh; }\n'
            result = subprocess.run(['sh', '-c', prefix + block + '\nprintf other\n'], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.decode(), expected)
        for name in ('kvm-alpha-topology.sh', 'run-alpha-topology-vm.sh'):
            result = subprocess.run(['sh', str(HERE / name), '--scenario', C['PREFIX']],
                capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(C['PREFIX'].encode(), result.stdout.lower())
        workflow = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
        self.assertIn('refs/heads/test/storage-natural-expiry-sequence', workflow)
        self.assertIn('d19f0246bf1ee8610e7cbc9bd52bdb973aedd289', workflow)
        self.assertIn("env.VOLPAROSSA_ALPHA_SCENARIO != 'private-storage-natural-expiry'", workflow)
        self.assertIn('private-storage-natural-expiry.py report', workflow)
        shell = (HERE / 'private-storage-natural-expiry.sh').read_text()
        wait = shell[shell.index('    PHASE=private-storage-natural-expiry-wait'):shell.index('    PHASE=private-storage-natural-expiry-suffix')]
        self.assertNotIn(' serve ', wait)
        for forbidden in ('benchmark_select_route', ' disconnect ', ' restart ', ' connect '):
            self.assertNotIn(forbidden, shell)

    def test_shell_failure_cleanup_is_bounded_ordered_and_idempotent(self):
        script = r'''
set -eu
WORK=$1; source_directory=$2; CASE=$3
mkdir -p "$WORK/client-fixtures/private-storage-user"
expiry_start=1; expiry_attempted=8
storage_key_a=A; storage_key_b=B; storage_key_c=C
binary_directory=/inert/unused
. "$source_directory/tests/integration/private-storage-natural-expiry.sh"
private_storage_expiry_private() {
    printf 'abort\n' >>"$WORK/order"
    [ "$CASE" != abort-failed ]
}
private_storage_expiry_join() {
    printf 'join\n' >>"$WORK/order"
    expiry_collector_joined=true
}
private_storage_sequence_cleanup() {
    printf 'remove\n' >>"$WORK/order"
}
status=0
private_storage_expiry_cleanup || status=$?
again=0
private_storage_expiry_cleanup || again=$?
test "$status" = "$again"
exit "$status"
'''
        for case in ('boundary-failed', 'abort-failed'):
            with tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                result = subprocess.run(['sh', '-c', script, 'inert-cleanup', str(work), str(HERE.parents[1]), case],
                    capture_output=True, timeout=3)
                self.assertEqual(result.returncode, int(case == 'abort-failed'), result.stderr)
                self.assertEqual((work / 'order').read_text(), 'abort\njoin\nremove\n')
                value = json.loads((work / f"{C['PREFIX']}-cleanup.json").read_text())
                self.assertTrue(value['abort_attempted'])
                self.assertEqual(value['remote_cleanup_confirmed'], case != 'abort-failed')
                self.assertTrue(value['collector_joined'] and value['owner_cleanup_confirmed'])


if __name__ == '__main__':
    unittest.main()
