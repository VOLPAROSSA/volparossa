#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert extracted-source preflight and safe-parser fixtures; no VM/native/Rust."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HOOK = HERE / 'lib/production-ipc-unit-hook.sh'
GATE = HERE / 'require-live-worker-identity-proof.sh'
RUNNER = HERE / 'run-helper-boundary-evidence-vm.sh'
CAPTURE = HERE / 'lib/live-worker-proof-capture.sh'
REASONS = ('preflight-contracts', 'preflight-socket-wait', 'preflight-directory-metadata',
           'preflight-socket-metadata', 'preflight-token-metadata', 'preflight-journal-metadata',
           'preflight-journal-lock-metadata', 'preflight-journal-next-present')
PREFIX = 'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1='
LAUNCH = 'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1='
FAILURE = 'live worker-identity proof failed: predicate rejected: production-launch-status'


def function(path, name):
    matches = re.findall(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', path.read_text(), re.M | re.S)
    if len(matches) != 1:
        raise AssertionError((str(path), name, len(matches)))
    return matches[0]


def shell(script, *args, env=None):
    return subprocess.run(['sh', '-eu', '-c', script, 'fixture', *map(str, args)],
                          env=env, text=True, capture_output=True, timeout=10)


class PreflightDiagnostic(unittest.TestCase):
    def test_named_bootstrap_capabilities_agree_across_all_production_layers(self):
        # Linux UAPI capability numbers, independently evaluated rather than
        # copying a previously recorded hexadecimal status string.
        bits = {'CAP_KILL': 5, 'CAP_SETGID': 6, 'CAP_SETUID': 7, 'CAP_SETPCAP': 8,
                'CAP_NET_BIND_SERVICE': 10, 'CAP_NET_ADMIN': 12, 'CAP_SYS_ADMIN': 21}
        expected = sum(1 << bit for bit in bits.values())
        root = HERE.parents[1]
        packaged = (root / 'packaging/systemd/volparossa-helper.service').read_text()
        for property_name in ('CapabilityBoundingSet', 'AmbientCapabilities'):
            values = re.findall(r'^' + property_name + r'=(.*)$', packaged, re.M)
            self.assertEqual(len(values), 1)
            names = values[0].split()
            self.assertEqual(len(names), len(bits))
            self.assertEqual(set(names), set(bits))
            self.assertEqual(sum(1 << bits[name] for name in names), expected)
        gate = GATE.read_text()
        configured = re.findall(r"^capabilities='([^']+)'$", gate, re.M)
        self.assertEqual(len(configured), 1)
        self.assertEqual(len(configured[0].split()), len(bits))
        self.assertEqual(set(configured[0].split()), set(bits))
        self.assertEqual(sum(1 << bits[name] for name in configured[0].split()), expected)
        # Worker, production and restart transient units all use this exact set.
        for property_name in ('CapabilityBoundingSet', 'AmbientCapabilities'):
            self.assertEqual(gate.count('--property="' + property_name + '=$capabilities"'), 3)
        rust = (root / 'crates/volparossa-helper/src/worker_sandbox.rs').read_text()
        constants = dict((name, int(value)) for name, value in re.findall(
            r'^const (CAP_[A-Z_]+): u32 = ([0-9]+);$', rust, re.M))
        self.assertEqual({name: constants[name] for name in bits}, bits)
        expression = re.search(r'const HELPER_BOOTSTRAP_CAPABILITY_BITS: u64 = (.*?);', rust, re.S)
        self.assertIsNotNone(expression)
        names = [name.removesuffix('_BIT') for name in expression[1].replace('|', ' ').split()]
        self.assertEqual(len(names), len(bits))
        self.assertEqual(set(names), set(bits))
        self.assertEqual(sum(1 << constants[name] for name in names), expected)
        for name in names:
            self.assertIn('const ' + name + '_BIT: u64 = 1_u64 << ' + name + ';', rust)
        rust_test = re.findall(r'assert_eq!\(HELPER_BOOTSTRAP_CAPABILITY_BITS, (0x[0-9a-f_]+)\);', rust)
        self.assertEqual(len(rust_test), 1)
        self.assertEqual(int(rust_test[0].replace('_', ''), 16), expected)
        hook_masks = re.findall(r'^helper_bootstrap_capability_mask=([0-9a-f]{16})$', HOOK.read_text(), re.M)
        self.assertEqual(len(hook_masks), 1)
        self.assertEqual(hook_masks[0], f'{expected:016x}')
        gate_masks = re.findall(r'expected_process_contract_prefix="[^"\n]*;caps:([0-9a-f]{16});filters:', gate)
        self.assertEqual(len(gate_masks), 1)
        self.assertEqual(gate_masks[0], f'{expected:016x}')

    def test_actual_process_parser_requires_every_exact_capability_set(self):
        parser = function(HOOK, 'capture_helper_process_contract')
        # Redirect only the proc-file operand to an inert fixture. Keep the real
        # shell guards and complete awk validator, with no process observation.
        operand = 'hook_contract_status=/proc/$hook_contract_pid/status'
        self.assertEqual(parser.count(operand), 1)
        parser = parser.replace(operand, 'hook_contract_status=$fixture_status')
        code = function(HOOK, 'number_is_safe') + parser
        fixture = '''
fixture_status=$1
helper_bootstrap_capability_mask=00000000002015e0
capture_helper_process_contract 4242 1250
'''
        status = ('Pid:\t4242\nUid:\t0\t0\t0\t0\nGid:\t1250\t1250\t1250\t1250\n'
                  'Groups:\t1250\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n')
        fields = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
        status += ''.join(name + ':\t00000000002015e0\n' for name in fields)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status'
            path.write_text(status)
            result = shell(code + fixture, path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'process-status-v1=uid:0:0:0:0;gid:1250:1250:1250:1250;'
                             'groups:1250;nnp:1;seccomp:2;caps:00000000002015e0;filters:2\n')
            for field in fields:
                line = field + ':\t00000000002015e0\n'
                for value in ('00000000002031e0', '00000000002011e0', '00000000002035e0'):
                    with self.subTest(field=field, value=value):
                        path.write_text(status.replace(line, field + ':\t' + value + '\n'))
                        result = shell(code + fixture, path)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, '')
                for changed in (status.replace(line, ''), status + line):
                    path.write_text(changed)
                    result = shell(code + fixture, path)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, '')

    def test_terminal_only_reason_selection_and_first_reason_preservation(self):
        code = function(HOOK, 'set_preflight_failure_stage') + function(HOOK, 'advance_start_failure_stage')
        for reason in REASONS:
            result = shell(code + '''
start_failure_stage=preflight-runtime
set_preflight_failure_stage "$1"
if set_preflight_failure_stage preflight-contracts; then exit 3; fi
if advance_start_failure_stage identity-socket; then exit 4; fi
printf '%s\n' "$start_failure_stage"
''', reason)
            self.assertEqual((result.returncode, result.stdout), (0, reason+'\n'))
        for stage, reason in [('identity-lock', REASONS[0]), ('preflight-runtime', 'preflight-private-value')]:
            result = shell(code + 'start_failure_stage=$1; ! set_preflight_failure_stage "$2"', stage, reason)
            self.assertEqual(result.returncode, 0)

    def test_each_metadata_operand_and_dangling_next_symlink_select_exact_reason(self):
        code = function(HOOK, 'set_preflight_failure_stage') + function(HOOK, 'validate_runtime_metadata')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'journal').touch()
            fixture = '''
runtime_directory=$1/runtime; helper_socket=$1/socket; cleanup_token=$1/token
journal=$1/journal; journal_lock=$1/lock; journal_next=$1/next
bad=$2
start_failure_stage=preflight-runtime
stat() {
    for operand do :; done
    key=${operand##*/}
    [ "$bad" != "$key" ] || { printf '%s\n' rejected; return; }
    case $key in
        runtime) printf '%s\n' directory:0:1250:750 ;;
        socket) printf '%s\n' socket:0:1250:660:1 ;;
        token) printf '%s\n' 'regular file:0:1250:640:1:32' ;;
        journal|lock) printf '%s\n' 8180:0:1250:600:1 ;;
        *) return 2 ;;
    esac
}
if validate_runtime_metadata 1250; then status=0; else status=$?; fi
printf '%s:%s\n' "$status" "$start_failure_stage"
'''
            for key, reason in [('runtime',REASONS[2]),('socket',REASONS[3]),('token',REASONS[4]),('journal',REASONS[5]),('lock',REASONS[6])]:
                with self.subTest(operand=key):
                    result=shell(code+fixture,root,key)
                    self.assertEqual((result.returncode,result.stdout),(0,'1:'+reason+'\n'))
            for kind in ('file','dangling-symlink'):
                path=root/'next'
                path.touch() if kind=='file' else path.symlink_to(root/'missing')
                result=shell(code+fixture,root,'none')
                self.assertEqual(result.stdout,'1:'+REASONS[7]+'\n')
                path.unlink()
            for journal in ('present','absent'):
                if journal=='absent': (root/'journal').unlink()
                result=shell(code+fixture,root,'none')
                self.assertEqual(result.stdout,'0:preflight-runtime\n')

    def test_actual_contract_and_socket_wait_failure_keep_fatal_exit(self):
        code = ''.join(function(HOOK,name) for name in ('fail','set_preflight_failure_stage','fail_preflight','unit_name_is_safe','number_is_safe'))
        # Only the first preflight portion is exercised. No identity capture,
        # process launch, network mutation, privilege or real waiting is allowed.
        start = function(HOOK,'start_hook').split('    validate_runtime_metadata "$agent_gid"',1)[0] + '    return 77\n}\n'
        fixture = '''
start_failure_stage=preflight-runtime
trap 'printf "stage=%s\\n" "$start_failure_stage"' EXIT
proof_directory=$1/proof; probe=$1/probe; helper_socket=$1/missing-socket
start_failure_record=$1/start.failure
restart_initial_handshake_failure_record=$1/handshake.failure
restart_initial_handshake_terminal_record=$1/handshake.terminal
restart_initial_release_authorized_record=$1/release
hook_entry_contract_is_exact() { [ "$contract_bad" = no ]; }
'''
        fixture += '''
contract_bad=$2
stat() {
    for operand do :; done
    case $operand in
        "$proof_directory") printf '%s\n' directory:0:0:2700 ;;
        "$probe") printf '%s\n' 'regular file:0:1250:550:1' ;;
        *) return 2 ;;
    esac
}
sleep() { :; }
start_hook volparossa-helper-live-proof-ABC123.service 1250 1250 1251 1252 1252
'''
        with tempfile.TemporaryDirectory() as directory:
            for bad, reason in [('yes',REASONS[0]),('no',REASONS[1])]:
                result=shell(code+start+fixture,directory,bad)
                self.assertEqual(result.returncode,1)
                self.assertEqual(result.stdout,'stage='+reason+'\n')
                self.assertNotIn(directory,result.stderr)

    def test_private_stage_publication_remains_first_only(self):
        code=''.join(function(HOOK,name) for name in ('start_failure_stage_is_safe','restart_start_failure_stage_is_safe','publish_start_failure'))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'first'
            result=shell(code+'''
start_failure_armed=yes; start_failure_published=no; start_failure_record=$1
write_private_file() { [ ! -e "$1" ] || return 1; printf '%s\n' "$2" >"$1"; }
start_failure_stage=preflight-token-metadata
publish_start_failure
start_failure_stage=preflight-contracts
! publish_start_failure
cat "$start_failure_record"
''',path)
            self.assertEqual((result.returncode,result.stdout),(0,PREFIX+REASONS[4]+'\n'))

    def gate(self, root):
        return ''.join(function(path,name) for path,name in (
            (CAPTURE,'vp_capture_file_is_safe'),(GATE,'production_start_failure_stage_is_safe'),
            (GATE,'production_functional_probe_failure_value_is_safe'),(GATE,'report_production_launch_diagnostic')))+'''
VP_CAPTURE_OWNER_UID=$(id -u); VP_CAPTURE_OWNER_GID=$(id -g)
temporary_stage=$1; proof_failure_reason=${2:-production-launch-status}
report_production_launch_diagnostic
'''

    def test_real_gate_and_outer_parser_accept_each_reason_and_old_coarse(self):
        outer=''.join(function(RUNNER,name) for name in ('require_no_private_key_marker','non_retained_production_launch_stage_is_safe','non_retained_functional_probe_failure_value_is_safe','report_non_retained_production_launch_diagnostic'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'production-output').mkdir()
            record=root/'production-output/start.failure';capture=root/'capture'
            for reason in ('preflight-runtime',*REASONS):
                record.write_text(PREFIX+reason+'\n');record.chmod(0o600)
                result=shell(self.gate(root),root)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stderr,LAUNCH+reason+'\n')
                capture.write_text(result.stderr+FAILURE+'\n');capture.chmod(0o600)
                parsed=shell(outer+'report_non_retained_production_launch_diagnostic "$1"',capture)
                self.assertEqual(parsed.returncode,0,parsed.stderr)
                self.assertEqual(parsed.stderr,'non-retained helper-boundary PR smoke production launch diagnostic: '+reason+'\n')

    def test_gate_rejects_malformed_missing_unsafe_tampered_and_wrong_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'production-output').mkdir();record=root/'production-output/start.failure'
            valid=PREFIX+REASONS[0]+'\n'
            for value in [PREFIX+'unknown\n',valid+valid,valid+'\n',valid.rstrip(),valid+'private-value\n',PREFIX+REASONS[0]+',/private/path\n']:
                record.write_text(value);record.chmod(0o600)
                self.assertNotEqual(shell(self.gate(root),root).returncode,0)
            record.write_text(valid);record.chmod(0o644)
            self.assertNotEqual(shell(self.gate(root),root).returncode,0)
            record.chmod(0o600)
            self.assertNotEqual(shell(self.gate(root),root,'other-stage').returncode,0)
            (root/'production-output/start.pass').touch()
            self.assertNotEqual(shell(self.gate(root),root).returncode,0)
            (root/'production-output/start.pass').unlink()
            record.unlink()
            self.assertNotEqual(shell(self.gate(root),root).returncode,0)
            target=root/'target';target.write_text(valid);target.chmod(0o600);record.symlink_to(target)
            self.assertNotEqual(shell(self.gate(root),root).returncode,0)
            record.unlink();record.hardlink_to(target)
            self.assertNotEqual(shell(self.gate(root),root).returncode,0)

    def test_outer_rejects_unknown_duplicate_mixed_private_key_and_wrong_failure(self):
        outer=''.join(function(RUNNER,name) for name in ('require_no_private_key_marker','non_retained_production_launch_stage_is_safe','non_retained_functional_probe_failure_value_is_safe','report_non_retained_production_launch_diagnostic'))
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture';line=LAUNCH+REASONS[0]+'\n';valid=line+FAILURE+'\n'
            for value in ['',LAUNCH+'unknown\n'+FAILURE+'\n',line+valid,line,valid+'extra\n',
                          '-----BEGIN PRIVATE KEY-----\n'+valid,PREFIX+REASONS[0]+'\n'+valid,
                          line+'live worker-identity proof failed: predicate rejected: other\n']:
                path.write_text(value);path.chmod(0o600)
                result=shell(outer+'report_non_retained_production_launch_diagnostic "$1"',path)
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn('PRIVATE KEY',result.stderr)
            path.write_text(valid);path.chmod(0o644)
            self.assertNotEqual(shell(outer+'report_non_retained_production_launch_diagnostic "$1"',path).returncode,0)
            path.unlink()
            self.assertNotEqual(shell(outer+'report_non_retained_production_launch_diagnostic "$1"',path).returncode,0)
            target=Path(directory)/'target';target.write_text(valid);target.chmod(0o600)
            path.symlink_to(target)
            self.assertNotEqual(shell(outer+'report_non_retained_production_launch_diagnostic "$1"',path).returncode,0)
            path.unlink();path.hardlink_to(target)
            self.assertNotEqual(shell(outer+'report_non_retained_production_launch_diagnostic "$1"',path).returncode,0)

    def test_restart_specific_parser_rejects_normal_start_details(self):
        code=function(CAPTURE,'vp_capture_file_is_safe')+function(GATE,'restart_successor_start_failure_category')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture'
            for reason in REASONS:
                path.write_text(PREFIX+reason+'\n');path.chmod(0o600)
                result=shell(code+'VP_CAPTURE_OWNER_UID=$(id -u); VP_CAPTURE_OWNER_GID=$(id -g); restart_successor_start_failure_category "$1"',path)
                self.assertNotEqual(result.returncode,0)


if __name__=='__main__': unittest.main()
