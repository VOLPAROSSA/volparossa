#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the real state observer with inert public-output fixtures only."""
import base64
import hashlib
import os
from pathlib import Path
import re
import runpy
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
normalize_relay_traffic_diagnostic = runpy.run_path(str(HERE / 'test-helper-relay-traffic-diagnostic.py'))['normalize_relay_traffic_diagnostic']
ROOT = HERE.parents[1]
HOOK = HERE / 'lib/production-ipc-unit-hook.sh'
BACKEND = ROOT / 'crates/volparossa-helper/src/worker_v3/functional_backend.rs'
ORIGINAL_HOOK = '4836e21b400b27e6ffbb25434c24a1e9124ab15d4447d7cf45f72a6b6931d513'
ADDITION = ('# Real workers use the backend\'s fixed keepalive; external fixtures retain 25.\n'
            'functional_worker_peer_keepalive=1\n')
KEY = base64.b64encode(bytes([8]) * 32).decode()
PEER = 'fd76:6f6c:7061:1234:5678:1:9abc:4'
EXPANDED_PEER = 'fd76:6f6c:7061:1234:5678:0001:9abc:0004'
ROUTE = ('[{"dst":"' + PEER + '","dev":"vpc1proof","protocol":"static",'
         '"metric":1024,"flags":[],"pref":"medium"}]')


def function(name):
    matches = re.findall(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n',
                         HOOK.read_text(), re.M | re.S)
    if len(matches) != 1:
        raise AssertionError((name, len(matches)))
    return matches[0]


class WireguardState(unittest.TestCase):
    def production_keepalive(self):
        matches = re.findall(r'const FUNCTIONAL_ALPHA_KEEPALIVE_SECONDS: u32 = ([0-9]+);',
                             BACKEND.read_text())
        self.assertEqual(len(matches), 1)
        return matches[0]

    def observe(self, **changes):
        values = {
            'route': ROUTE, 'default': '[]', 'peers': KEY,
            'endpoints': KEY + '\t192.31.195.254:10000',
            'allowed': KEY + '\t' + PEER + '/128',
            'keepalive': KEY + '\t' + self.production_keepalive(),
            'handshake': KEY + '\t0', 'transfer': KEY + '\t0\t0',
        }
        values.update(changes)
        env = os.environ.copy()
        env.update({'FIX_' + key.upper(): value for key, value in values.items()})
        env['FIX_KEY'] = KEY
        env['FIX_PEER'] = EXPANDED_PEER
        constants = '\n'.join(line for line in HOOK.read_text().splitlines()
                              if re.fullmatch(r'functional_(worker_peer|peer)_keepalive=[0-9]+', line))
        code = constants + '\n' + ''.join(function(name) for name in (
            'number_is_safe', 'fd_number_is_safe', 'activated_route_destination',
            'wireguard_counter_line_is_exact', 'worker_activated_wireguard_is_exact'))
        # Replace only the fixed command seam. No namespace, kernel or real wg/ip calls.
        code = code.replace('/usr/bin/nsenter', 'fixture_nsenter')
        code += r'''
fixture_nsenter() {
    [ "$1" = --net=/proc/self/fd/7 ] && [ "$2" = -- ] || return 90
    shift 2
    case "$*" in
        "/usr/sbin/ip -6 -json route show table main exact $FIX_PEER/128") printf '%s\n' "$FIX_ROUTE" ;;
        '/usr/sbin/ip -6 -json route show table main default') printf '%s\n' "$FIX_DEFAULT" ;;
        '/usr/bin/wg show vpc1proof peers') printf '%s\n' "$FIX_PEERS" ;;
        '/usr/bin/wg show vpc1proof endpoints') printf '%s\n' "$FIX_ENDPOINTS" ;;
        '/usr/bin/wg show vpc1proof allowed-ips') printf '%s\n' "$FIX_ALLOWED" ;;
        '/usr/bin/wg show vpc1proof persistent-keepalive') printf '%s\n' "$FIX_KEEPALIVE" ;;
        '/usr/bin/wg show vpc1proof latest-handshakes') printf '%s\n' "$FIX_HANDSHAKE" ;;
        '/usr/bin/wg show vpc1proof transfer') printf '%s\n' "$FIX_TRANSFER" ;;
        *) return 91 ;;
    esac
}
functional_peer_endpoint=192.31.195.254:10000
functional_exit_peer_endpoint=192.31.195.254:10001
worker_activated_wireguard_is_exact 7 vpc1proof "$FIX_PEER" "$FIX_KEY" "$functional_peer_endpoint"
'''
        return subprocess.run(['sh', '-eu', '-c', code], env=env,
                              capture_output=True, text=True, timeout=10)

    def test_real_observer_accepts_source_derived_worker_keepalive(self):
        result = self.observe()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def test_old_fixture_keepalive_and_wrong_public_state_remain_fatal(self):
        mutations = (
            {'keepalive': KEY + '\t25'}, {'keepalive': KEY + '\t0'},
            {'keepalive': KEY + '\t01'}, {'keepalive': KEY + '\t2'},
            {'keepalive': KEY + '\t1\n' + KEY + '\t1'},
            {'route': '[]'}, {'route': ROUTE.replace('vpc1proof', 'other')},
            {'route': ROUTE.replace('static', 'kernel')},
            {'route': ROUTE.replace('1024', '1023')},
            {'route': ROUTE.replace('"flags":[]', '"flags":["onlink"]')},
            {'default': ROUTE}, {'peers': ''}, {'peers': KEY + '\n' + KEY},
            {'endpoints': KEY + '\t192.31.195.254:10001'},
            {'allowed': KEY + '\t' + PEER + '/64'},
            {'allowed': KEY + '\t' + PEER[:-1] + '2/128'},
            {'handshake': KEY + '\t-1'}, {'transfer': KEY + '\t0'},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result = self.observe(**mutation)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, '', ''))

    def test_worker_authority_and_all_other_hook_bytes_are_preserved(self):
        source = normalize_relay_traffic_diagnostic(HOOK.read_text())
        self.assertEqual(re.findall(r'^functional_worker_peer_keepalive=([0-9]+)$', source, re.M),
                         [self.production_keepalive()])
        self.assertIn('persistent_keepalive_seconds: FUNCTIONAL_ALPHA_KEEPALIVE_SECONDS,',
                      BACKEND.read_text())
        self.assertEqual(source.count(ADDITION), 1)
        self.assertEqual(source.count('"$functional_worker_peer_keepalive"'), 1)
        restored = source.replace(ADDITION, '').replace(
            '"$functional_worker_peer_keepalive"', '"$functional_peer_keepalive"')
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), ORIGINAL_HOOK)
        self.assertIn('functional_peer_keepalive=25\n', source)


if __name__ == '__main__':
    unittest.main()
