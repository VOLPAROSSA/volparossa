#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert exact GID/socket access in disposable fixture namespaces only."""
from pathlib import Path
import hashlib
import os
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HOOK = HERE / 'lib/production-ipc-unit-hook.sh'
GATE = HERE / 'require-live-worker-identity-proof.sh'
APPROVED_HELPERS = {'ping_fixture_namespace_is_exact': '95a3ef7b29dc03460209e1245bddea8eb9eb36e5638d07890abaa8b6840a5395', 'configure_private_ping_group_range': '6509aeeb18658996732d6450b4c891399471383c8b8eea71c6764b5da8a0a7f4', 'configure_functional_peer_ping_group_range': '56c3531d71bbe4f1500b42a7702ebb23ab0fde2b10b3d000bdcf76280b363161'}
PARENT_CALL = '    configure_private_ping_group_range \\\n        "$hook_functional_agent_gid" "$hook_private_namespace" || return 1\n'
PEER_CALL = '    configure_functional_peer_ping_group_range \\\n        "$hook_functional_agent_gid" "$functional_pair_client_keeper_pid" \\\n        "$functional_pair_client_keeper_starttime" \\\n        "$functional_pair_client_namespace_identity" || return 1\n'
HOOK_MODE = '    fixture-ping-range)\n        shift\n        configure_private_ping_group_range "$@" || fail \'private fixture ping range is invalid\'\n        ;;\n'
HOST_CAPTURE = '    # Retain the previous forwarding bytes and add exact read-only ping range\n    # bytes to the same before/after sysctls digest. Never configure host state.\n    vp_capture_run "$capture_directory/ping-group-range.raw" \\\n        cat /proc/sys/net/ipv4/ping_group_range || failed \'host ping range could not be read\'\n    [ "$(stat -Lc \'%s\' "$capture_directory/ping-group-range.raw")" -le 32 ] \\\n        || failed \'host ping range capture is oversized\'\n    printf \'%s=\' /proc/sys/net/ipv4/ping_group_range >>"$sysctls_capture" \\\n        || failed \'host ping range label could not be captured\'\n    cat "$capture_directory/ping-group-range.raw" >>"$sysctls_capture" \\\n        || failed \'host ping range bytes could not be captured\'\n'
BASELINE = {'hook': 'dae4d90a8acc2ff4a91791bb7a730da0f224c7f6e8f7d2c96491adbe17f4b12c', 'driver': '437d6e2f938b4a8e174a64547871a747492a3c5bada9ccef59e70d093bf4f569'}


def function(path, name):
    found = re.findall(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', path.read_text(), re.M | re.S)
    if len(found) != 1:
        raise AssertionError((path, name, len(found)))
    return found[0]


def normalize_ping_fixture_access(source):
    for name, expected in APPROVED_HELPERS.items():
        matches = re.findall(r'^' + name + r'\(\) \{\n.*?^\}\n', source, re.M | re.S)
        if matches:
            if len(matches) != 1 or hashlib.sha256(matches[0].encode()).hexdigest() != expected:
                raise AssertionError('unreviewed private ping setter change: ' + name)
            source = source.replace(matches[0] + '\n', '', 1)
    for addition in (PARENT_CALL, PEER_CALL, HOOK_MODE):
        source = source.replace(addition, '', 1)
    return source


def shell(code, *args):
    return subprocess.run(['sh', '-eu', '-c', code, 'fixture', *map(str, args)],
                          capture_output=True, text=True, timeout=10)


class PrivatePingAccess(unittest.TestCase):
    def code(self):
        names = ('number_is_safe', 'kernel_object_number_is_safe', 'kernel_object_identity_is_safe',
            'private_file_is_safe', 'capture_helper_process_contract', 'hook_entry_contract_is_exact',
            'process_contract_filter_count', 'ping_fixture_namespace_is_exact', 'configure_private_ping_group_range')
        code = ''.join(function(HOOK, name) for name in names)
        # Only inert files may receive writes: adapt root owner IDs to this test
        # account and the fixed proc/status and sysctl seams to private fixtures.
        code = code.replace('8180:0:0:600:1', f'8180:{os.getuid()}:{os.getgid()}:600:1')
        code = code.replace('hook_contract_status=/proc/$hook_contract_pid/status', 'hook_contract_status=$fixture_status')
        code = code.replace('/proc/sys/net/ipv4/ping_group_range', '"$fixture_range"')
        actual_write = 'printf \'%s\\t%s\\n\' "$1" "$1" >"$fixture_range" || return 1'
        self.assertEqual(code.count(actual_write), 1)
        code = code.replace(actual_write, 'fixture_write "$1" >"$fixture_range" || return 1', 1)
        self.assertNotIn('/proc/sys', code)
        return code + r'''
fixture_root=$1; mode=$2; input_gid=${3:-1250}; expected=${4:-5:101}
fixture_status=$fixture_root/status; fixture_range=$fixture_root/range
proof_directory=$fixture_root; host_network_identity_record=$fixture_root/host.identity
helper_bootstrap_capability_mask=00000000002015e0
uid_quad='0 0 0 0'; gid_quad='1250 1250 1250 1250'; groups=1250; nnp=1
case $mode in
    uid) uid_quad='0 1 0 0' ;; gid) gid_quad='1250 1251 1250 1250' ;;
    groups) groups='0 1250' ;; nnp) nnp=0 ;;
esac
printf 'Pid:\t%s\nUid:\t%s\nGid:\t%s\nGroups:\t%s\nNoNewPrivs:\t%s\nSeccomp:\t2\nSeccomp_filters:\t2\n' \
    "$$" "$uid_quad" "$gid_quad" "$groups" "$nnp" >"$fixture_status"
for name in CapInh CapPrm CapEff CapBnd CapAmb; do
    printf '%s:\t%s\n' "$name" "$helper_bootstrap_capability_mask" >>"$fixture_status"
done
printf 'one\ntwo\nthree\nfour\nfive\nprocess-status-v1=uid:0:0:0:0;gid:1250:1250:1250:1250;groups:1250;nnp:1;seccomp:2;caps:00000000002015e0;filters:2\n' >"$proof_directory/unit.identity"
printf '5:100\n' >"$host_network_identity_record"
if [ "$mode" = ambiguous-host ]; then printf '\n' >>"$host_network_identity_record"; fi
chmod 0600 "$proof_directory/unit.identity" "$host_network_identity_record"
case $mode in
    broad) printf '0\t4294967294\n' >"$fixture_range" ;;
    already) printf '1250\t1250\n' >"$fixture_range" ;;
    ambiguous) printf '1\t0\n1\t0\n' >"$fixture_range" ;;
    spaces) printf '1 0\n' >"$fixture_range" ;;
    *) printf '1\t0\n' >"$fixture_range" ;;
esac
stat() {
    for operand do :; done
    if [ "$operand" = /proc/self/ns/net ]; then
        case $mode in host) printf '5:100\n' ;; wrong-ns) printf '5:102\n' ;; *) printf '5:101\n' ;; esac
    else /usr/bin/stat "$@"; fi
}
fixture_write() {
    printf 'write\n' >>"$fixture_root/writes"
    case $mode in
        write-fail) return 1 ;;
        readback) printf '%s\t%s\n' "$1" 1251 ;;
        readback-ambiguous) printf '%s\t%s\n%s\t%s\n' "$1" "$1" "$1" "$1" ;;
        *) printf '%s\t%s\n' "$1" "$1" ;;
    esac
}
configure_private_ping_group_range "$input_gid" "$expected"
'''

    def test_exact_denied_to_single_group_and_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            result = shell(self.code(), directory, 'correct')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
            self.assertEqual((Path(directory)/'range').read_bytes(), b'1250\t1250\n')
            self.assertEqual((Path(directory)/'writes').read_text(), 'write\n')
            self.assertEqual((Path(directory)/'host.identity').read_bytes(), b'5:100\n')

    def test_prewrite_guards_reject_host_wrong_namespace_gid_credentials_or_initial_range(self):
        modes = ('host', 'wrong-ns', 'uid', 'gid', 'groups', 'nnp', 'ambiguous-host',
                 'broad', 'already', 'ambiguous', 'spaces')
        with tempfile.TemporaryDirectory() as directory:
            for index, mode in enumerate(modes):
                target = Path(directory)/str(index); target.mkdir()
                result = shell(self.code(), target, mode)
                self.assertNotEqual(result.returncode, 0, mode)
                self.assertFalse((target/'writes').exists(), mode)
            for index, gid in enumerate(('0', '01250', '1251', '4294967295', '1250;other')):
                target=Path(directory)/('gid'+str(index));target.mkdir()
                result=shell(self.code(),target,'correct',gid)
                self.assertNotEqual(result.returncode,0,gid)
                self.assertFalse((target/'writes').exists(),gid)
            for index, expected in enumerate(('5:100','5:102','05:101','5:0101','5:101\n5:101')):
                target=Path(directory)/('ns'+str(index));target.mkdir()
                result=shell(self.code(),target,'correct','1250',expected)
                self.assertNotEqual(result.returncode,0,expected)
                self.assertFalse((target/'writes').exists(),expected)

    def test_write_failure_or_wrong_readback_is_fatal_without_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            for index, mode in enumerate(('write-fail','readback','readback-ambiguous')):
                target=Path(directory)/str(index);target.mkdir()
                result=shell(self.code(),target,mode)
                self.assertNotEqual(result.returncode,0,mode)
                self.assertEqual((target/'writes').read_text(),'write\n')

    def test_keeper_setter_enters_only_exact_held_namespace_and_fixed_hook(self):
        code = function(HOOK,'configure_functional_peer_ping_group_range')
        code = code.replace('"/proc/$2/ns/net"','"$fixture_pin"').replace('/usr/bin/nsenter','fixture_nsenter')
        self.assertNotIn('exec 5<"/proc/',code)
        code += r'''
fixture_pin=$1/pin; mode=$2; trace=$1/trace
: >"$fixture_pin"
number_is_safe() { [ "$1" = 1250 ]; }
functional_peer_keeper_is_exact() { [ "$mode" != keeper-fail ] && [ "$*" = '4242 777 5:101' ]; }
stat() { if [ "$mode" = pin-fail ]; then printf '5:102\n'; else printf '5:101\n'; fi; }
fixture_nsenter() {
    [ "$*" = '--net=/proc/self/fd/5 -- /run/volparossa-helper-production-ipc-hook fixture-ping-range 1250 5:101' ] || return 99
    printf 'fixed setter\n' >>"$trace"
    [ "$mode" != setter-fail ]
}
configure_functional_peer_ping_group_range 1250 4242 777 5:101
'''
        with tempfile.TemporaryDirectory() as directory:
            for index,mode in enumerate(('correct','keeper-fail','pin-fail','setter-fail')):
                target=Path(directory)/str(index);target.mkdir();result=shell(code,target,mode)
                self.assertEqual(result.returncode==0,mode=='correct',mode)
                self.assertEqual((target/'trace').exists(),mode in ('correct','setter-fail'))

    def test_only_two_pinger_namespaces_are_configured_and_original_hook_is_exact(self):
        source=HOOK.read_text()
        self.assertEqual(hashlib.sha256(normalize_ping_fixture_access(source).encode()).hexdigest(),BASELINE['hook'])
        self.assertEqual(source.count(PARENT_CALL),1)
        self.assertEqual(source.count(PEER_CALL),1)
        self.assertEqual(source.count(HOOK_MODE),1)
        self.assertNotIn('configure_functional_peer_ping_group_range \\\n        "$hook_functional_agent_gid" "$functional_pair_exit_keeper_pid"',source)
        # The first Client/Exit ping share the parent; only the later Relay-pair
        # Client keeper runs another ping. No worker/Exit-keeper range is changed.
        self.assertEqual(len(re.findall(r'/usr/bin/ping -6 -n -I',source)),3)
        self.assertLess(source.index(PARENT_CALL),source.index('    advance_start_failure_stage functional-underlay-absent'))
        self.assertIn(PEER_CALL+'    /usr/bin/nsenter \\\n        --net="/proc/$functional_pair_client_keeper_pid/ns/net" -- \\\n        /usr/bin/ping',source)

    def test_host_range_bytes_join_unchanged_original_sysctls_fingerprint_read_only(self):
        source=GATE.read_text();self.assertEqual(source.count(HOST_CAPTURE),1)
        self.assertEqual(hashlib.sha256(source.replace(HOST_CAPTURE,'',1).encode()).hexdigest(),BASELINE['driver'])
        self.assertNotIn('>/proc/sys',HOST_CAPTURE)
        with tempfile.TemporaryDirectory() as directory:
            values=[]
            for index,observed in enumerate(('1\t0\n','1250\t1250\n')):
                target=Path(directory)/str(index);target.mkdir()
                code=HOST_CAPTURE+r'''
cat "$sysctls_capture"
'''
                fixture=r'''
capture_directory=$1; sysctls_capture=$1/sysctls
printf 'original forwarding bytes\n' >"$sysctls_capture"
failed() { exit 99; }
vp_capture_run() {
    [ "$2 $3" = 'cat /proc/sys/net/ipv4/ping_group_range' ] || exit 99
    printf '%s' "$fixture_value" >"$1"
}
fixture_value=$2
'''
                self.assertNotRegex(fixture+code,r'>\s*/proc/sys')
                result=shell(fixture+code,target,observed)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertTrue(result.stdout.startswith('original forwarding bytes\n/proc/sys/net/ipv4/ping_group_range='))
                values.append(result.stdout)
            self.assertNotEqual(values[0],values[1])


if __name__ == '__main__':
    unittest.main()
