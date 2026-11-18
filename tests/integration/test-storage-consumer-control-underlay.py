#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic kernel readbacks and real shell/Python orchestration; no netns/netops."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-consumer-control-underlay.py'))
F = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))


def matrix():
    nodes = {f'relay{i}': dict(links=[], routes=[], tables={}) for i in range(6)}
    checks = {f'relay{i}': {} for i in range(3)}
    addresses = M['OLD']['NET']['PUBLIC_IPS']
    for b in range(3):
        for p in range(3):
            broker, provider = f'relay{b}', f'relay{p + 3}'
            table, segment = f'vpa_content_control_consumer_{b}{p}', 1 + 3 * b + p
            for node, other, dev, index, peer_index, local, remote in (
                    (broker, provider, f'cc{b}{p}', 100 + p, 200 + b, 1, 2),
                    (provider, broker, f'pc{b}{p}', 200 + b, 100 + p, 2, 1)):
                nodes[node]['links'].append(dict(ifindex=index, ifname=dev, link_index=peer_index,
                    flags=['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'], kind='veth'))
                nodes[node]['routes'].extend([
                    dict(dst=f'10.247.{segment}.0/30', dev=dev, gateway=None,
                        prefsrc=f'10.247.{segment}.{local}', scope='link', protocol='kernel'),
                    dict(dst=addresses[other], dev=dev, gateway=f'10.247.{segment}.{remote}',
                        prefsrc=addresses[node], scope='global', protocol='boot')])
                rules = F['filter_fixture'](0, dev, addresses[node], addresses[other])
                for row in rules['nftables']:
                    if 'table' in row: row['table']['name'] = table
                    for kind in ('chain', 'rule'):
                        if kind in row: row[kind]['table'] = table
                nodes[node]['tables'][table] = rules
            checks[broker][provider] = dict(
                out=[dict(dst=addresses[provider], dev=f'cc{b}{p}', gateway=f'10.247.{segment}.2', prefsrc=addresses[broker])],
                back=[dict(dst=addresses[broker], dev=f'pc{b}{p}', gateway=f'10.247.{segment}.1', prefsrc=addresses[provider])])
    return dict(nodes=nodes, route_checks=checks)


def fixture():
    original = F['fixture']()
    transition, peers = original['control_transition'], original['expected_peers']
    value = dict(schema_version=1, kind='storage-consumer-control-underlay',
        original_transition_sha256=hashlib.sha256(M['canonical'](transition)).hexdigest(),
        original_peers_sha256=hashlib.sha256(M['canonical'](peers)).hexdigest(),
        before=copy.deepcopy(transition['after']), detached=F['snapshot_fixture'](None),
        after=matrix(), application_acceptance=False)
    return original, value


def save(root, name, raw):
    path = root / name
    path.write_bytes(raw); path.chmod(0o600)
    return path


def save_original(root, original):
    for name, key, encode in (
            ('private-storage-maintenance-control-transition.json', 'control_transition', M['canonical']),
            ('private-storage-fragments-layout.json', 'layout', M['OLD']['encoded']),
            ('a01-expected-peers.json', 'expected_peers', M['OLD']['encoded'])):
        save(root, name, encode(original[key]))


class ConsumerUnderlay(unittest.TestCase):
    def validate(self, original, value, stage='complete'):
        return M['validate'](value, original['expected_peers'], original['layout'],
            original['control_transition'], stage=stage)

    def test_nine_pairs_allow_0_1_0_without_mutating_or_relabelling_original(self):
        original, value = fixture()
        historical, before = M['canonical'](original), M['canonical'](value)
        self.validate(original, value)
        for broker in ('relay0', 'relay1', 'relay0'):
            for provider in ('relay3', 'relay4', 'relay5'):
                check = value['after']['route_checks'][broker][provider]
                self.assertEqual(check['out'][0]['dst'], M['OLD']['NET']['PUBLIC_IPS'][provider])
                self.assertEqual(check['back'][0]['dst'], M['OLD']['NET']['PUBLIC_IPS'][broker])
        self.assertEqual(M['canonical'](original), historical)
        self.assertEqual(M['canonical'](value), before)
        self.assertLess(len(before), 131072)
        self.assertFalse(value['application_acceptance'])

    def test_old_single_broker_does_not_cover_reselection(self):
        original, value = fixture()
        value['after'] = original['control_transition']['after']
        with self.assertRaises(ValueError): self.validate(original, value)

    def test_every_pair_and_direction_is_mandatory_and_kernel_bound(self):
        original, value = fixture()
        for b in range(3):
            for p in range(3):
                for direction in ('out', 'back'):
                    bad = copy.deepcopy(value)
                    bad['after']['route_checks'][f'relay{b}'][f'relay{p + 3}'][direction][0]['dev'] = 'underlay'
                    with self.subTest(b=b, p=p, direction=direction), self.assertRaisesRegex(ValueError, 'route_get'):
                        self.validate(original, bad)

    def test_link_identity_route_destination_or_extra_owned_state_rejected(self):
        original, value = fixture()
        changes = (
            lambda v: v['after']['nodes']['relay0']['links'][0].update(link_index=999),
            lambda v: v['after']['nodes']['relay3']['links'][0].update(kind='dummy'),
            lambda v: v['after']['nodes']['relay0']['links'][0]['flags'].remove('UP'),
            lambda v: v['after']['nodes']['relay0']['links'][0].update(ifindex=True),
            lambda v: v['after']['nodes']['relay0']['links'].append(dict(v['after']['nodes']['relay0']['links'][0])),
            lambda v: v['after']['nodes']['relay0']['routes'][1].update(dst='47.163.4.2'),
            lambda v: v['after']['nodes']['relay0']['routes'][1].update(gateway='10.247.1.1'),
            lambda v: v['detached']['nodes']['relay0']['links'].append({'ifname': 'ac0'}),
            lambda v: next(n for n in v['before']['nodes'].values() if n['links'])['links'][0].update(ifindex=999),
            lambda v: v.update(original_transition_sha256='0' * 64),
            lambda v: v.update(original_peers_sha256='0' * 64),
            lambda v: v.update(application_acceptance=True),
            lambda v: v.update(unchecked='no'),
        )
        for index, change in enumerate(changes):
            bad = copy.deepcopy(value); change(bad)
            with self.subTest(index=index), self.assertRaises(ValueError): self.validate(original, bad)

    def test_no_tcp_other_port_forwarding_or_foreign_table(self):
        original, value = fixture()
        for mutation in ('tcp', 'port', 'forward', 'name', 'extra'):
            bad = copy.deepcopy(value)
            rows = bad['after']['nodes']['relay0']['tables']['vpa_content_control_consumer_00']['nftables']
            rules = [row['rule'] for row in rows if 'rule' in row]
            if mutation == 'tcp': rules[0]['expr'][3]['match']['left']['payload']['protocol'] = 'tcp'
            if mutation == 'port': rules[0]['expr'][3]['match']['right'] = 51820
            if mutation == 'forward': rules[-1]['expr'][-1] = dict(accept=None)
            if mutation == 'name': rows[1]['table']['name'] = 'foreign'
            if mutation == 'extra': rules[0]['expr'].append(dict(accept=None))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.validate(original, bad)

    def test_stage_order_and_actual_closed_cli(self):
        original, value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); save_original(root, original)
            for stage in ('before', 'detached', 'complete'):
                current = copy.deepcopy(value)
                if stage != 'complete': current['after'] = None
                if stage == 'before': current['detached'] = None
                path = save(root, 'candidate.json', M['canonical'](current))
                proc = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-control-underlay.py'),
                    'check', str(root), str(path), stage], capture_output=True, timeout=10)
                self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, b'', b''))
            for raw in (b'{}', b'x' * 131073, M['OLD']['encoded'](value)):
                path = save(root, 'candidate.json', raw)
                proc = subprocess.run([sys.executable, '-B', str(HERE / 'storage-consumer-control-underlay.py'),
                    'check', str(root), str(path), 'complete'], capture_output=True, timeout=10)
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(proc.stdout, b'')
                self.assertEqual(proc.stderr, b'consumer control underlay rejected\n')

    def shell_prepare(self, root, *, fail=''):
        original, value = fixture(); save_original(root, original)
        for name in ('before', 'detached', 'after'): save(root, f'fixture-{name}.json', M['canonical'](value[name]))
        (root / 'bin').symlink_to(HERE, target_is_directory=True)
        program = r'''
set -eu
WORK=$1; FAILURE=$2
R0=relay0; R1=relay1; R2=relay2; R3=relay3; R4=relay4; R5=relay5
private_storage_maintenance=yes; PROVIDER_CONTROL_PID=
provider_control_ns=$(jq -r '.nodes | to_entries[] | select(.key | test("^relay[012]$")) | select(.value.links | length > 0) | .key' "$WORK/fixture-before.json")
. "$WORK/bin/content-provider-smoke.sh"
. "$WORK/bin/storage-consumer-control-underlay.sh"
ip() {
    printf '%s\n' "ip $*" >>"$WORK/commands"
    if [ "${FAILURE:-}" = "$*" ]; then return 7; fi
    case "$*" in *'nft -f -') tee -a "$WORK/filters" >/dev/null ;; esac
}
storage_consumer_control_snapshot() {
    printf '%s\n' "snapshot $1" >>"$WORK/commands"
    cp "$WORK/fixture-$1.json" "$WORK/consumer-control-$1.private"
}
storage_consumer_control_prepare
'''
        return subprocess.run(['sh', '-c', program, 'fixture', str(root), fail], capture_output=True, timeout=15)

    def test_actual_shell_installs_both_filters_before_each_up_then_validates_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.shell_prepare(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            commands = (root / 'commands').read_text().splitlines()
            self.assertEqual(sum(' type veth ' in line for line in commands), 9)
            self.assertEqual(sum(' route add ' in line for line in commands), 18)
            self.assertEqual(sum(' link delete ' in line for line in commands), 3)
            for b in range(3):
                for p in range(3):
                    up = commands.index(f'ip -n relay{b} link set cc{b}{p} up')
                    right_up = commands.index(f'ip -n relay{p + 3} link set pc{b}{p} up')
                    create = commands.index(f'ip -n relay{b} link add cc{b}{p} type veth peer name pc{b}{p} netns relay{p + 3}')
                    self.assertEqual(sum('nft -f -' in x for x in commands[create:up]), 2)
                    self.assertLess(up, right_up)
            path = root / M['NAME']
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            M['read_check'](root, path, 'complete')
            self.assertFalse((root / 'consumer-control-candidate.private').exists())
            self.assertEqual((root / 'filters').read_text().count('udp dport 41000 accept'), 36)

    def test_filter_failure_never_raises_pair_or_publishes_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.shell_prepare(root, fail='netns exec relay3 nft -f -')
            self.assertNotEqual(result.returncode, 0)
            commands = (root / 'commands').read_text()
            self.assertNotIn('link set cc00 up', commands)
            self.assertFalse((root / M['NAME']).exists())

    def test_actual_snapshot_projects_all_nine_kernel_pairs_and_empty_detached(self):
        # Execute the actual jq/readback shell, replacing only ip/nft with inert
        # command responses. No privileged executable or kernel call is invoked.
        fake = r'''
import json, os, sys
from pathlib import Path
root = Path(os.environ['WORK'])
value = json.loads((root / 'matrix.json').read_text())
args = sys.argv[1:]
if os.environ.get('OVERSIZE') == 'yes':
    print(' ' * 65537 + '[]'); sys.exit(0)
if args[0] == '-n':
    node = args[1]
    if args[2:] == ['-j', '-d', 'link', 'show']:
        result = [{**{k:v for k,v in link.items() if k != 'kind'},
            'linkinfo': {'info_kind':link['kind']}, 'ignored_kernel_address':'not retained'}
            for link in value['nodes'][node]['links']]
    elif args[2:] == ['-j', '-d', '-4', 'route', 'show']:
        result = value['nodes'][node]['routes']
    elif args[2:5] == ['-j', 'route', 'get']:
        destination = args[5]
        rows = [r for r in value['nodes'][node]['routes'] if r['dst'] == destination]
        result = [{**{k:r[k] for k in ('dst','dev','gateway','prefsrc')}, 'cache':[]}
            for r in rows]
    else: raise SystemExit(2)
else:
    assert args[:2] == ['netns','exec']
    node = args[2]; tables = value['nodes'][node]['tables']
    if args[3:] == ['nft','-j','list','tables']:
        result = {'nftables': [{'table': {'family':'inet','name':name}} for name in tables]}
    elif args[3:7] == ['nft','-j','list','table']:
        assert args[7] == 'inet'; result = tables[args[8]]
    else: raise SystemExit(3)
print(json.dumps(result))
'''
        program = r'''
set -eu
WORK=$1; export WORK; OVERSIZE=$3; export OVERSIZE
R0=relay0; R1=relay1; R2=relay2; R3=relay3; R4=relay4; R5=relay5
. "$4/content-provider-smoke.sh"
. "$4/storage-consumer-control-underlay.sh"
ip() { python3 -B "$WORK/fake-ip.py" "$@"; }
umask 077
storage_consumer_control_snapshot "$2"
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); save(root, 'fake-ip.py', fake.encode())
            for stage, value in (('after', matrix()), ('detached', F['snapshot_fixture'](None))):
                save(root, 'matrix.json', M['canonical'](value))
                result = subprocess.run(['sh', '-c', program, 'fixture', str(root), stage, 'no', str(HERE)],
                    capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = json.loads((root / f'consumer-control-{stage}.private').read_text())
                self.assertEqual(actual, value)
                M['snapshot'](actual, detached=stage == 'detached')
            save(root, 'matrix.json', M['canonical'](matrix()))
            result = subprocess.run(['sh', '-c', program, 'fixture', str(root), 'after', 'yes', str(HERE)],
                capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
