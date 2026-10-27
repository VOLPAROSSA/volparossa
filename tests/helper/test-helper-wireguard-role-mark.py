#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert exact production role-mark observer contract; no kernel/namespace calls."""
from pathlib import Path
import hashlib
import re
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HOOK = HERE / 'lib/production-ipc-unit-hook.sh'
KERNEL = ROOT / 'crates/volparossa-helper/src/kernel.rs'
CORE = ROOT / 'crates/volparossa-core/src/lib.rs'
BASELINE = {
    'worker_wireguard_interface': '72822c5a852fa69a56257eb5bf918cbb0d9a9694bdcd0c5ac6b30c104f52f552',
    'worker_relay_pair_interfaces': 'a667d2dc6202b8873b18c4f12f78dd36ee3ffcba97515751f4f92a1cfeead6ed',
    'functional_relay_fixture_is_exact': '0d86055d8dde8c5bd622e4f8f8499816639eb37ec752faf0506b1c9569bdef63',
    'functional_exit_relay_fixture_is_exact': 'f5ebe965798b3953f6fde9fdfdabe9a1df6d2ad253ac6ff97bf900fd6b8265af',
    'functional_peer_keeper_is_exact': '105dc58fc6307534dd7487de38afe016a199b098ece51fd3b351cc27043c0fd2',
}


def function(name):
    values = re.findall(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', HOOK.read_text(), re.M | re.S)
    if len(values) != 1:
        raise AssertionError((name, len(values)))
    return values[0]


def shell(code, *args):
    return subprocess.run(['sh', '-eu', '-c', code, 'fixture', *args],
                          capture_output=True, text=True, timeout=10)


class WireguardRoleMark(unittest.TestCase):
    def marks(self):
        kernel = KERNEL.read_text()
        core = CORE.read_text()
        client = re.findall(r'pub\(crate\) const CLIENT_INGRESS_IPV4_MARK: u32 = (0x[0-9a-f_]+);', kernel)
        bit = re.findall(r'pub const CONTRIBUTION_MARK_BIT: u32 = (0x[0-9a-f_]+);', core)
        self.assertEqual(len(client), 1)
        self.assertEqual(len(bit), 1)
        client, bit = (int(value[0].replace('_', ''), 16) for value in (client, bit))
        self.assertIn('pub(crate) const CONTRIBUTION_WIREGUARD_MARK: u32 =\n'
                      '    CLIENT_INGRESS_IPV4_MARK | volparossa_core::CONTRIBUTION_MARK_BIT;', kernel)
        return {'client': f'{client:#x}', 'exit': f'{client | bit:#x}', 'relay': f'{client | bit:#x}'}

    def test_exact_guard_matches_source_derived_role_marks_and_rejects_other_values(self):
        marks = self.marks()
        code = function('worker_wireguard_mark_is_exact') + 'worker_wireguard_mark_is_exact "$@"'
        for role, expected in marks.items():
            with self.subTest(role=role, mark=expected):
                result = shell(code, role, expected)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
            wrong = marks['exit'] if role == 'client' else marks['client']
            for observed in ('off', '0', '0x0', wrong, '0x1', '0xffffffff', '',
                             expected.upper(), expected + '\n', expected + ' ', expected + ';'):
                with self.subTest(role=role, rejected=repr(observed)):
                    result = shell(code, role, observed)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (1, '', ''))
        for args in ((), ('client',), ('client', marks['client'], 'extra'),
                     ('unknown', marks['client']), ('Client', marks['client']), ('', marks['exit'])):
            result = shell(code, *args)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, '', ''))

    def test_production_encoder_and_prober_share_role_mark_authority(self):
        self.marks()
        source = KERNEL.read_text()
        role_map = source.split('fn wireguard_underlay_mark(', 1)[1].split('\nfn ', 1)[0]
        self.assertIn('Ok(WireguardRole::Client) => CLIENT_INGRESS_IPV4_MARK,', role_map)
        self.assertIn('Ok(WireguardRole::RelayClient | WireguardRole::RelayExit | WireguardRole::Exit) => {\n'
                      '            CONTRIBUTION_WIREGUARD_MARK\n        }', role_map)
        encoder = source.split('fn encode_activate_device_v3(', 1)[1].split('\nfn ', 1)[0]
        self.assertIn('WGDEVICE_A_FWMARK,\n        &wireguard_underlay_mark(resource).to_ne_bytes(),', encoder)
        prober = source.split('fn probe_wireguard_peer_v3(', 1)[1].split('\n    pub(crate) fn ', 1)[0]
        self.assertIn('|| state.firewall_mark != wireguard_underlay_mark(resource)', prober)

    def test_singleton_roles_are_closed_before_external_observation_and_callers_explicit(self):
        code = function('worker_wireguard_interface') + '\nworker_wireguard_interface "$@"'
        # Wrong roles/arity must fail before any fd, nsenter, ip or wg operation.
        for args in ((), ('7',), ('7', 'relay'), ('7', 'unknown'), ('7', ''), ('7', 'client', 'extra')):
            result = shell(code, *args)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, '', ''))
        source = HOOK.read_text()
        calls = re.findall(r'\$\(worker_wireguard_interface ([^)]*)\)', source)
        self.assertEqual(calls, ['7 client', '7 exit'])
        self.assertIn('worker_wireguard_mark_is_exact "$hook_wireguard_role" "$hook_firewall_mark" || return 1',
                      function('worker_wireguard_interface'))
        self.assertIn('worker_wireguard_mark_is_exact relay "$hook_pair_firewall_mark" || return 1',
                      function('worker_relay_pair_interfaces'))
        contract = (HERE / 'test-live-worker-identity-contract.sh').read_text()
        self.assertEqual(contract.count('python3 -B "$script_directory/test-helper-wireguard-role-mark.py"'), 1)

    def test_only_reviewed_mark_expectation_and_role_signature_change_other_observer_guards(self):
        for name, expected in BASELINE.items():
            source = function(name)
            if name == 'worker_wireguard_interface':
                source = source.replace('    [ "$#" -eq 2 ] || return 1\n',
                                        '    [ "$#" -eq 1 ] || return 1\n', 1)
                source = source.replace('    hook_wireguard_role=$2\n'
                                        '    case $hook_wireguard_role in client|exit) ;; *) return 1 ;; esac\n', '', 1)
                source = source.replace('    worker_wireguard_mark_is_exact "$hook_wireguard_role" "$hook_firewall_mark" || return 1\n',
                                        '    [ "$hook_firewall_mark" = off ] || return 1\n', 1)
            if name == 'worker_relay_pair_interfaces':
                source = source.replace('        worker_wireguard_mark_is_exact relay "$hook_pair_firewall_mark" || return 1\n',
                                        '        [ "$hook_pair_firewall_mark" = off ] || return 1\n', 1)
            # This also freezes all three separate synthetic-fixture off guards.
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), expected, name)


if __name__ == '__main__':
    unittest.main()
