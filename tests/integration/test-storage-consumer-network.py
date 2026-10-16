#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic proofs and owned ordinary children, never a kernel/network trial."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-network.py'))
F = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))
U = runpy.run_path(str(HERE / 'test-storage-consumer-control-underlay.py'))


def interfaces(capture, names):
    sample = copy.deepcopy(next(iter(capture['interface_statistics'].values())))
    capture['interfaces'] = names
    capture['interface_statistics'] = {}
    for i, name in enumerate(names):
        item = copy.deepcopy(sample)
        item.update(observed_frames=capture['observed_frames'] if i == 0 else 0,
            packet_socket_packets=capture['observed_frames'] if i == 0 else 0)
        capture['interface_statistics'][name] = item


def fixture(profile_version=3):
    value = F['fixture'](profile_version=profile_version)
    underlay = U['fixture']()[1]
    value.update(schema_version=profile_version, control_underlay=underlay)
    peers = value['expected_peers']
    for name, phase in value['network'].items():
        phase.update(layout=M['layout'](underlay, peers), control_before=copy.deepcopy(underlay['after']),
            control_after=copy.deepcopy(underlay['after']))
        bindings = []
        for char, broker in (('a', 'relay0'), ('b', 'relay1'), ('c', 'relay0')):
            relays = [n for n in M['BROKERS'] if n != broker]
            bindings.append(dict(route_context_id=char * 32, control_relay_peer_id=peers[broker],
                scope=dict(exit_peer_id=peers['exit'], paths=[dict(path_id=i + 1, relay_peer_id=peers[n])
                    for i, n in enumerate(relays)])))
        gates = phase['gates']
        gates.pop('exit_route_scope'); gates.pop('observed_route_context_ids')
        gates.update(exit_log_sampling_version=3, exit_route_policy=M['policy'](peers),
            observed_context_routes=bindings, exit_flow_contexts=[dict(route_context_id=char * 32,
                completed=n, failed=0) for char, n in (('a', 1), ('b', 1), ('c', M['PHASES'][name] - 2))])
        selected = phase['selected_route']
        selected.update(route_context_id='c' * 32, exact_selected_exit=peers['exit'],
            exact_selected_relays=[peers[n] for n in ('relay1', 'relay2')])
        for i, node in enumerate(('relay1', 'relay2')):
            selected['paths'][i].update(path_id=i + 1, route_context_id='c' * 32,
                exit_peer_id=peers['exit'], relay_peer_id=peers[node], state=1)
            selected['benchmark_slots'][i].update(path_id=i + 1, relay_node=node, relay_peer_id=peers[node])
        for i, node in enumerate(M['BROKERS']):
            capture = phase['privacy'][node]
            capture.update(client_leg_wireguard_data_datagrams=17, exit_leg_wireguard_data_datagrams=17)
            interfaces(capture, [f'r{i}c', f'r{i}x', 'underlay'])
        control = phase['control_privacy']
        phase['control_privacy'] = {}
        for i, broker in enumerate(M['BROKERS']):
            capture = copy.deepcopy(control)
            pairs = {f'cc{i}{p}': [M['OLD']['NET']['PUBLIC_IPS'][broker], M['OLD']['NET']['PUBLIC_IPS'][n]]
                for p, n in enumerate(M['PROVIDERS'])}
            capture.update(consumer_control_role=broker, content_control_pairs=pairs,
                content_control_packets={n: dict(inbound=0, outbound=0) for n in pairs})
            interfaces(capture, list(pairs))
            phase['control_privacy'][broker] = capture
        value[name].update(version=2, network_version=2,
            control_underlay_sha256=phase['layout']['control_underlay_sha256'])
    return value


class ConsumerNetwork(unittest.TestCase):
    def test_full_new_proof_and_old_profiles_are_distinct(self):
        value = fixture()
        M['OLD']['validate_evidence'](value)
        self.assertLess(len(M['canonical'](value)), 1024 * 1024)
        for version in (1, 2):
            invalid = copy.deepcopy(value); invalid['schema_version'] = version
            with self.assertRaises(ValueError): M['OLD']['validate_evidence'](invalid)
        for previous in (True, False):
            old = F['fixture'](previous=previous)
            M['OLD']['validate_evidence'](old, previous=previous)
            old['schema_version'] = 3
            with self.assertRaises((ValueError, KeyError)): M['OLD']['validate_evidence'](old)

    def test_tls_source_profile_has_its_own_schema_without_relaxing_network_or_app_gates(self):
        value = fixture(4)
        M['OLD']['validate_evidence'](value)
        for version in (1, 2, 3):
            changed = copy.deepcopy(value); changed['schema_version'] = version
            with self.assertRaises((ValueError, KeyError)): M['OLD']['validate_evidence'](changed)
        changed = fixture(); changed['schema_version'] = 4
        with self.assertRaises(ValueError): M['OLD']['validate_evidence'](changed)
        for mutate in (lambda v: v['publish'].update(node_joined=False),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1),
                lambda v: v['network']['publish']['privacy']['client'].update(direct_client_exit_packets=1),
                lambda v: v['network']['exercise']['gates']['observed_context_routes'].pop(),
                lambda v: v['network']['finish']['control_after']['nodes']['relay0']['links'].pop()):
            changed = copy.deepcopy(value); mutate(changed)
            with self.assertRaises(ValueError): M['OLD']['validate_evidence'](changed)

    def test_every_begin_end_kernel_readback_and_original_binding_is_required(self):
        original = fixture()
        for name in M['PHASES']:
            for moment in ('control_before', 'control_after'):
                for mutate in (lambda v: v['nodes']['relay0']['links'][0].update(ifindex=999),
                        lambda v: v['nodes']['relay3']['routes'].pop(),
                        lambda v: v['route_checks']['relay2'].pop('relay5')):
                    value = copy.deepcopy(original); mutate(value['network'][name][moment])
                    with self.assertRaises(ValueError): M['OLD']['validate_evidence'](value)
            for change in (dict(control_underlay_sha256='0' * 64), dict(network_version=2.0)):
                value = copy.deepcopy(original); value[name].update(change)
                with self.assertRaises(ValueError): M['OLD']['validate_evidence'](value)
        for key in ('original_transition_sha256', 'original_peers_sha256'):
            value = copy.deepcopy(original); value['control_underlay'][key] = '0' * 64
            with self.assertRaises(ValueError): M['OLD']['validate_evidence'](value)

    def test_exact_context_mapping_and_all_physical_captures_not_peer_union(self):
        original = fixture()
        for mutate in (
                lambda p: p['gates']['observed_context_routes'][0]['scope']['paths'][0].update(relay_peer_id='foreign'),
                lambda p: p['gates']['exit_flow_contexts'][0].update(route_context_id='e' * 32),
                lambda p: p['selected_route']['benchmark_slots'][0].update(relay_node='relay0'),
                lambda p: p['gates']['observed_context_routes'].pop(),
                lambda p: p['privacy']['relay0'].update(client_leg_wireguard_data_datagrams=0),
                lambda p: p['privacy']['relay0'].update(interfaces=['r1c', 'r1x', 'underlay']),
                lambda p: p['control_privacy'].pop('relay2'),
                lambda p: p['control_privacy']['relay0'].update(consumer_control_role='relay1'),
                lambda p: p['control_privacy']['relay1']['content_control_pairs']['cc10'].__setitem__(0, '192.0.2.1'),
                lambda p: p['control_privacy']['relay2'].update(packet_socket_drops=1),
                lambda p: p['control_privacy']['relay1'].update(unexpected_provider_control_packets=1),
                lambda p: p['control_privacy']['relay0']['provider_application']['relay4'].update(request_packets=1),
                lambda p: p['privacy']['client'].update(direct_client_exit_packets=1),
                lambda p: p['privacy']['exit']['provider_application']['relay4'].update(response_payload_bytes=1)):
            value = copy.deepcopy(original); mutate(value['network']['exercise'])
            with self.assertRaises((ValueError, KeyError)): M['OLD']['validate_evidence'](value)

    def test_original_app_authority_accounting_and_cleanup_checks_remain(self):
        original = fixture()
        for mutate in (lambda v: v['prepare']['authority']['image'].update(reserved_credit=1),
                lambda v: v['deleted_usage'][0].update(committed_bytes=1),
                lambda v: v['private_cleanup'].update(remote_cleanup_confirmed=True),
                lambda v: v['publish'].update(node_joined=False),
                lambda v: v['withdrawal'].update(first_store_retained=False)):
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError): M['OLD']['validate_evidence'](value)

    def test_actual_builder_cli_and_exact_export_names(self):
        self.assert_builder(3)

    def test_tls_builder_cli_requires_its_original_profile_and_keeps_all_network_checks(self):
        self.assert_builder(4)

    def assert_builder(self, profile_version):
        value = fixture(profile_version)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            # Historical helper serializes common receipts; new profile files
            # are independently written, not relabeled as old control captures.
            F['write_evidence'](work, value)
            U['save'](work, M['U']['NAME'], M['canonical'](value['control_underlay']))
            for name, phase in value['network'].items():
                (work / f'content-provider-adaptive-private-storage-fragments-consumer-{name}-control.json').unlink()
                for suffix, data in (('before', phase['control_before']), ('after', phase['control_after']),
                        *phase['control_privacy'].items()):
                    U['save'](work, f'storage-consumer-{name}-control-{suffix}.json', M['canonical'](data))
            owner = work / 'client-fixtures/private-storage-user'
            owner.mkdir(parents=True, mode=0o700)
            flow = U['save'](owner, 'flow-consumer-publish.json', M['canonical'](value['network']['publish']['gates']))
            # This unprivileged CLI fixture uses its actual local account. The
            # separate fd test below exercises root reading a different worker.
            value['isolation']['user_uid'] = os.geteuid()
            value['consumer_isolation']['user_uid'] = os.geteuid()
            U['save'](work, 'private-storage-fragments-isolation.json', M['canonical'](value['isolation']))
            U['save'](work, 'storage-consumer-isolation.json', M['canonical'](value['consumer_isolation']))
            result = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-maintenance-evidence.py'),
                f'evidence-v{profile_version}', str(work), str(work / 'joined.json')], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((work / 'joined.json').read_bytes()), value)
            for operation, more in (('layout', []), ('readback', [str(work / 'storage-consumer-publish-control-before.json')]),
                    ('route-check', [str(work / 'private-storage-fragments-consumer-publish-live-selection.json'),
                        str(flow)])):
                result = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-network.py'),
                    operation, str(work), *more], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(set(M['EXPORT_NAMES']) <= set(M['OLD']['EXPORT_NAMES']))

    def test_root_reads_only_exact_worker_owned_flow_with_real_bounded_fd(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            parent = work / 'client-fixtures/private-storage-user'
            parent.mkdir(parents=True, mode=0o700)
            flow = U['save'](parent, 'flow-consumer-publish.json', b'{"synthetic":true}')
            isolation = U['save'](work, 'private-storage-fragments-isolation.json', b'{"user_uid":4242,"agent_uid":4343}')
            root_inode = isolation.stat().st_ino
            wrong_owners = set()
            actual_fstat, actual_stat = os.fstat, os.stat
            def as_owner(info):
                return SimpleNamespace(**{name: getattr(info, name) for name in dir(info)
                    if name.startswith('st_') and name != 'st_uid'}, st_uid=(4343 if info.st_ino in wrong_owners
                        else 0 if info.st_ino == root_inode else 4242))
            def named(path, *args, **kwargs): return as_owner(actual_stat(path, *args, **kwargs))
            with patch.object(os, 'fstat', side_effect=lambda fd: as_owner(actual_fstat(fd))), \
                    patch.object(os, 'stat', side_effect=named), patch.object(os, 'geteuid', return_value=0):
                with self.assertRaises(ValueError): M['OLD']['read'](flow, maximum=16384, private=True)
                self.assertEqual(M['worker_flow'](work, flow), {'synthetic': True})
                for phase in ('upload', 'exercise', 'finish'):
                    cloud = U['save'](parent, f'flow-cloud-upload-{phase}.json', b'{"synthetic":true}')
                    self.assertEqual(M['worker_flow'](work, cloud), {'synthetic': True})
                for invalid in ('flow-cloud-upload-prepare.json', 'flow-cloud-upload-publish.json',
                        'flow-cloud-other-upload.json', 'flow-cloud-upload-finish.json.bak'):
                    with self.assertRaisesRegex(ValueError, 'consumer_worker_flow_path'):
                        M['worker_flow'](work, parent / invalid)
                for inode in (actual_stat(flow).st_ino, actual_stat(parent).st_ino):
                    wrong_owners.add(inode)
                    with self.assertRaises(ValueError): M['worker_flow'](work, flow)
                    wrong_owners.clear()
                for mode in (0o644, 0o660):
                    flow.chmod(mode)
                    with self.assertRaises(ValueError): M['worker_flow'](work, flow)
                flow.chmod(0o600)
                parent.chmod(0o755)
                with self.assertRaises(ValueError): M['worker_flow'](work, flow)
                parent.chmod(0o700)
                flow.write_bytes(b'x' * 16385)
                with self.assertRaises(ValueError): M['worker_flow'](work, flow)
                flow.write_bytes(b'{"synthetic":true}')
                with self.assertRaises(ValueError): M['worker_flow'](work, parent / 'flow-private.json')
                flow.unlink(); flow.symlink_to(isolation)
                with self.assertRaises(OSError): M['worker_flow'](work, flow)

    def test_actual_embedded_observer_profile_is_exact_and_historical_profiles_unchanged(self):
        source = (HERE / 'kvm-alpha-topology.sh').read_text()
        source = source.split('cat >"$WORK/bin/privacy-observer.py"', 1)[1]
        parser = source.split('role, output_path, ready_path, *interfaces = sys.argv[1:]', 1)[1].split('client_addresses =', 1)[0]
        parser = 'role, output_path, ready_path, *interfaces = sys.argv[1:]' + parser
        from types import SimpleNamespace
        def check(arguments):
            state = dict(sys=SimpleNamespace(argv=['observer', 'content-control', '/synthetic/out', '/synthetic/ready',
                '--content-providers', *arguments]), socket=socket)
            exec(compile(parser, 'embedded privacy observer argument parser', 'exec'), state)
            return state
        addresses = M['OLD']['NET']['PUBLIC_IPS']
        for b, broker in enumerate(M['BROKERS']):
            args = [f'--consumer-control={broker}', '--content-control=' + ','.join(
                [addresses[broker], *(addresses[n] for n in M['PROVIDERS'])]), *(f'cc{b}{p}' for p in range(3))]
            self.assertEqual(check(args)['consumer_control_role'], broker)
            for invalid in (args[1:], [*args[:2], 'cc10' if b != 1 else 'cc00', *args[3:]],
                    ['--consumer-control=relay3', *args[1:]], [args[0], args[1].replace(addresses[broker], '192.0.2.1'), *args[2:]],
                    args[:-1], [*args, 'extra'], [args[0], args[1], 'ac0', 'ac1', 'ac2']):
                with self.subTest(args=invalid), self.assertRaises(SystemExit): check(invalid)
        for names in (['cp0', 'cp1'], ['ac0', 'ac1', 'ac2'], ['lc0', 'lc1']):
            state = check(['--content-control=' + ','.join(f'192.0.2.{i + 1}' for i in range(len(names) + 1)), *names])
            self.assertIsNone(state['consumer_control_role'])
            self.assertEqual(list(state['content_control_pairs']), names)

    def test_new_sparse_closure_imports_without_runtime_download_or_network(self):
        old = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-smoke.py'))
        import ast
        parsed = ast.parse((HERE / 'test-storage-consumer-maintenance-smoke.py').read_text())
        function = next(node for node in ast.walk(parsed) if isinstance(node, ast.FunctionDef)
            and node.name == 'test_actual_staged_import_and_pin_closure_without_download_or_execution')
        names = ast.literal_eval(next(node.value for node in function.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'names' for target in node.targets)))
        additions = ('storage-consumer-network.py', 'storage-consumer-control-underlay.py',
            'storage-consumer-route-sampler.py', 'storage-consumer-maintenance-evidence.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (*names, *additions): (root / name).write_bytes((HERE / name).read_bytes())
            import urllib.request
            with patch.object(subprocess, 'Popen') as spawn, patch.object(os, 'execve') as execute, \
                    patch.object(urllib.request, 'urlopen') as download:
                loaded = runpy.run_path(str(root / additions[0]))
                self.assertEqual(loaded['OLD']['PROVISIONER']['load_pins'](3), old['M']['PROVISIONER']['load_pins'](3))
                loaded['validate_network'](fixture()['network']['publish'], fixture()['expected_peers'],
                    fixture()['layout'], 'publish', *M['OLD']['geometry'](fixture()['prepare']['node'])[::2], fixture()['control_underlay'])
                spawn.assert_not_called(); execute.assert_not_called(); download.assert_not_called()

    def test_actual_phase_helpers_check_readbacks_route_join_then_both_capture_drains(self):
        script = '''
. "$1"
WORK=$2; storage_user=$2; consumer_phase=publish
log() { printf '%s\\n' "$*" >>"$WORK/steps"; }
storage_consumer_readback() { log "readback-$1"; [ "$FAIL" != "readback-$1" ]; }
python3() { case $3 in
 layout) printf '%s\\n' '{"route_policy":{"synthetic":true},"control_underlay_sha256":"a"}';;
 route-check) log route-check; [ "$FAIL" != route-check ];;
 gates) log gates;; *) return 2;; esac; }
capture_product_logs() { log product-logs; }
client_log_baseline_ms() { log baseline; printf '1\\n'; }
start_privacy_observers() { log data-start; }
storage_consumer_start_captures() { log control-start; }
benchmark_capture_paths() { log end-selection; }
stop_privacy_observers() { log data-stop; [ "$FAIL" != data-stop ]; }
storage_consumer_stop_captures() { log control-stop; }
status=0
if storage_consumer_phase_start; then
 log owner
 storage_consumer_phase_finish 56 || status=$?
else status=$?; fi
printf '%s\\n' "$status"
'''
        for failure, expected in (
                ('none', ['readback-before', 'product-logs', 'baseline', 'data-start', 'control-start', 'owner',
                    'end-selection', 'route-check', 'readback-after', 'data-stop', 'control-stop', 'gates']),
                ('readback-before', ['readback-before']),
                ('route-check', ['readback-before', 'product-logs', 'baseline', 'data-start', 'control-start',
                    'owner', 'end-selection', 'route-check']),
                ('data-stop', ['readback-before', 'product-logs', 'baseline', 'data-start', 'control-start',
                    'owner', 'end-selection', 'route-check', 'readback-after', 'data-stop', 'control-stop'])):
            with tempfile.TemporaryDirectory() as temporary:
                result = subprocess.run(['sh', '-eu', '-c', script, 'inert', str(HERE / 'storage-consumer-network.sh'), temporary],
                    env=dict(os.environ, FAIL=failure), capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), b'0' if failure == 'none' else b'1')
                self.assertEqual((Path(temporary) / 'steps').read_text().splitlines(), expected)

    def test_real_capture_children_three_owned_pids_and_partial_failure_join(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / 'child.py'
            child.write_text('''import json, os, signal, sys, time
args=sys.argv[1:]
open(os.environ['TRACE'], 'a').write(json.dumps(args)+'\\n')
signal.signal(signal.SIGTERM, lambda *_: sys.exit(3 if os.environ.get('BAD_CHILD') == args[2] else 0))
open(args[7], 'w').write('ready')
while True: time.sleep(.01)
''')
            script = '''
. "$1"
WORK=$2; private_storage_maintenance=yes; PROVIDER_CONTROL_PID=
CONSUMER_CONTROL_0_PID=; CONSUMER_CONTROL_1_PID=; CONSUMER_CONTROL_2_PID=
content_provider_node() { provider_ns=$1; case $1 in
  relay0) provider_ip=42.158.0.1;; relay1) provider_ip=44.160.1.1;; relay2) provider_ip=45.161.2.1;;
  relay3) provider_ip=48.164.4.1;; relay4) provider_ip=49.165.5.1;; relay5) provider_ip=50.166.6.1;; esac; }
ip() { exec "$PYTHON" -B "$CHILD" "$@"; }
wait_observer() { for attempt in $(seq 1 200); do [ ! -f "$2" ] || break; sleep .01; done
  [ -f "$2" ] || return 1; case $2 in *relay1.ready) [ "$FAIL_SECOND" != yes ] || return 1;; esac; }
status=0; storage_consumer_start_captures publish || status=$?
pids="$CONSUMER_CONTROL_0_PID $CONSUMER_CONTROL_1_PID $CONSUMER_CONTROL_2_PID"
joined=0; storage_consumer_stop_captures || joined=$?
for pid in $pids; do if kill -0 "$pid" 2>/dev/null; then exit 91; fi; done
[ -z "$CONSUMER_CONTROL_0_PID$CONSUMER_CONTROL_1_PID$CONSUMER_CONTROL_2_PID" ] || exit 92
printf '%s:%s\\n' "$status" "$joined"
'''
            for fail, count, bad in (('no', 3, ''), ('yes', 2, ''), ('no', 3, 'relay1')):
                work = root / (fail + bad); work.mkdir()
                trace = work / 'trace'
                env = dict(os.environ, PYTHON=sys.executable, CHILD=str(child), TRACE=str(trace), FAIL_SECOND=fail, BAD_CHILD=bad)
                result = subprocess.run(['sh', '-eu', '-c', script, 'inert', str(HERE / 'storage-consumer-network.sh'), str(work)],
                    env=env, capture_output=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), f'{0 if fail == "no" else 1}:{1 if bad else 0}'.encode())
                calls = [json.loads(line) for line in trace.read_text().splitlines()]
                self.assertEqual(len(calls), count)
                for b, args in enumerate(calls):
                    self.assertEqual(args[:4], ['netns', 'exec', f'relay{b}', 'python3'])
                    self.assertIn(f'--consumer-control=relay{b}', args)
                    self.assertEqual(args[-3:], [f'cc{b}{p}' for p in range(3)])


if __name__ == '__main__':
    unittest.main()
