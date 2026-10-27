#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual AWK terminal-peer derivation against production lease topology; inert."""
from pathlib import Path
import hashlib
import ipaddress
import re
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HOOK = HERE / 'lib/production-ipc-unit-hook.sh'
LEASE = ROOT / 'crates/volparossa-helper/src/lease_spec.rs'
WIREGUARD = ROOT / 'crates/volparossa-wireguard/src/lib.rs'
BASELINE = {
    'derive_client_peer_address': 'e22b4abd1f4c9f3aee4351e522cbfc939b313ba9f6a62bc6f2be84494e012e53',
    'derive_exit_peer_address': '001562021a8deb027f357cc791f007762bee22aa131ba22972f36acc5b334d6a',
    'derive_client_local_address': '18c4af8a1ed06fee5917969db3c4a7e3a8ca62321fb5a052b1bdc71ab6dc1b3a',
    'derive_exit_local_address': 'e2eff252f39748afc5c2d3806726856e32da114f7cc0afbca247c75774c22683',
    'derive_relay_pair_address': 'b28237d1c94ed1f9e754141e3cee5a78b24ad47a8953ab876a9e92b3b788da82',
    'worker_activated_wireguard_is_exact': '1c840cdc7f958d347b9242b6d49df81d04cce13faa5c15f0c95553bdf8e05db9',
    'functional_relay_fixture_is_exact': '0d86055d8dde8c5bd622e4f8f8499816639eb37ec752faf0506b1c9569bdef63',
    'functional_exit_relay_fixture_is_exact': 'f5ebe965798b3953f6fde9fdfdabe9a1df6d2ad253ac6ff97bf900fd6b8265af',
    'functional_peer_keeper_is_exact': '105dc58fc6307534dd7487de38afe016a199b098ece51fd3b351cc27043c0fd2',
}


def function(name):
    values = re.findall(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', HOOK.read_text(), re.M | re.S)
    if len(values) != 1:
        raise AssertionError((name, len(values)))
    return values[0]


class PeerTopology(unittest.TestCase):
    def topology(self):
        source = LEASE.read_text()
        cases = re.findall(r'EndpointRole::(Client|Exit|RelayClient|RelayExit) => \(([0-9]+), ([0-9]+)\),', source)
        self.assertEqual(len(cases), 4)
        roles = {name: (int(local), int(peer)) for name, local, peer in cases}
        self.assertEqual(roles, {'Client': (1, 4), 'Exit': (4, 1),
                                 'RelayClient': (2, 1), 'RelayExit': (3, 4)})
        self.assertIn('local[14..].copy_from_slice(&local_host.to_be_bytes());', source)
        self.assertIn('peer[14..].copy_from_slice(&peer_host.to_be_bytes());', source)
        overlay = WIREGUARD.read_text().split('pub fn overlay_prefix(', 1)[1].split('\n}', 1)[0]
        ula = re.findall(r'\n        (0x[0-9a-f]+),', overlay)
        self.assertEqual(len(ula), 3)
        # The remaining context words are harmless synthetic examples. Path1
        # is the existing fixed fixture; production derives it from path_id.
        prefix = ''.join(f'{int(word, 16):04x}' for word in ula) + '1234567800019abc'
        return roles, prefix

    def derive(self, role, data, interface='vpc1proof'):
        name = 'derive_' + role.lower() + '_peer_address'
        return subprocess.run(['sh', '-eu', '-c', function(name) + name + ' "$@"',
                               'fixture', interface], input=data, text=True,
                              capture_output=True, timeout=10)

    def test_terminal_peer_results_match_production_tuples_with_unrelated_rows(self):
        roles, prefix = self.topology()
        unrelated = 'fe80000000000000123456fffe789abc 02 40 20 80 vpc1proof\n'
        for role in ('Client', 'Exit'):
            local, peer = roles[role]
            data = f'{prefix}{local:04x} 02 80 00 80 vpc1proof\n' + unrelated
            result = self.derive(role, data)
            expected = ipaddress.IPv6Address(int(prefix + f'{peer:04x}', 16)).exploded + '\n'
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, ''))

    def test_wrong_role_malformed_duplicate_and_ambiguous_candidates_are_rejected(self):
        roles, prefix = self.topology()
        for role in ('Client', 'Exit'):
            local, _ = roles[role]
            good = f'{prefix}{local:04x} 02 80 00 80 vpc1proof\n'
            wrong_hosts = [host for host in (1, 2, 3, 4) if host != local]
            malformed = [f'{prefix}{host:04x} 02 80 00 80 vpc1proof\n' for host in wrong_hosts]
            malformed += ['', good.upper(), good.replace('fd76', 'fd77', 1),
                          good.replace('00019abc', '00029abc', 1),
                          good.replace(' 80 00 ', ' 70 00 ', 1),
                          good.replace(' 00 80 ', ' 20 80 ', 1),
                          good.replace('vpc1proof', 'other'),
                          good.replace(prefix, prefix[:-1]),
                          good + good,
                          good + good.replace('1234', '5678', 1)]
            for data in malformed:
                with self.subTest(role=role, data=data):
                    result = self.derive(role, data)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (1, '', ''))
            for interface in ('', 'unsafe/name', 'x' * 16):
                result = self.derive(role, good, interface)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, '', ''))

    def test_only_two_peer_suffixes_change_all_other_guards_and_fixtures_are_exact(self):
        for name, expected in BASELINE.items():
            source = function(name)
            if name == 'derive_client_peer_address':
                source = source.replace('peer = substr($1, 1, 28) "0004"',
                                        'peer = substr($1, 1, 28) "0002"', 1)
            if name == 'derive_exit_peer_address':
                source = source.replace('peer = substr($1, 1, 28) "0001"',
                                        'peer = substr($1, 1, 28) "0003"', 1)
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), expected, name)
        contract = (HERE / 'test-live-worker-identity-contract.sh').read_text()
        self.assertEqual(contract.count('python3 -B "$script_directory/test-helper-peer-topology.py"'), 1)


if __name__ == '__main__':
    unittest.main()
