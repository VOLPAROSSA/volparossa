#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual-source, inert first Client relay-traffic failure/scalar contracts."""
from pathlib import Path
import hashlib
import os
import re
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
normalize_ping_fixture_access = runpy.run_path(str(HERE / 'test-helper-private-ping-access.py'))['normalize_ping_fixture_access']
HOOK = HERE / 'lib/production-ipc-unit-hook.sh'
GATE = HERE / 'require-live-worker-identity-proof.sh'
OUTER = HERE / 'run-helper-boundary-evidence-vm.sh'
CAPTURE = HERE / 'lib/live-worker-proof-capture.sh'
PREFIX = 'VOLPAROSSA_HELPER_RELAY_TRAFFIC_DIAGNOSTIC_V1='
STAGE = 'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-relay-traffic\n'
FAILURE = 'live worker-identity proof failed: predicate rejected: production-launch-status\n'
EXPECTED = {'ping': 'ping-exit-zero', 'worker-snapshot': 'canonical-u64-snapshot',
            'worker-growth': 'handshake-nonzero-rx-tx-increase',
            'relay-snapshot': 'canonical-u64-snapshot',
            'relay-growth': 'handshake-nonzero-rx-tx-increase', 'fixture': 'fixture-exact'}
UNAVAILABLE = 'unavailable,unavailable,unavailable'
ORIGINAL_HOOK = '78c67140e6c45522cc8d5fb3dd25155cf042dc7f0b9b97adf8834131c3d5ad52'
APPROVED_PING_WRAPPER = 'b1266328b69c77e12ec039ca78589e2abed4951a1a968a496567ca8b03385f1e'


def function(path, name):
    matches = re.findall(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', path.read_text(), re.M | re.S)
    if len(matches) != 1:
        raise AssertionError((path, name, len(matches)))
    return matches[0]


def traffic_block(source):
    start = source.index('    advance_start_failure_stage functional-relay-traffic || return 1\n')
    end = source.index('    advance_start_failure_stage functional-relay-cleanup || return 1\n', start)
    return source[start:end]


def normalize_relay_traffic_diagnostic(source):
    """Invert only this reviewed failure annotation; retain all original guards."""
    source = normalize_ping_fixture_access(source)
    if '    advance_start_failure_stage functional-relay-traffic || return 1\n' in source:
        block = traffic_block(source)
        def restore_ping(match):
            if hashlib.sha256(match[0].encode()).hexdigest() != APPROVED_PING_WRAPPER:
                raise AssertionError('unreviewed traffic ping wrapper change')
            return '    ' + match[1] + ' || return 1\n'
        restored = re.sub(r'    if (/usr/bin/ping -6 -n -I "\$functional_relay" \\\n'
                          r'        -c 1 -W 3 "\$hook_functional_client_address" >/dev/null 2>&1); then\n'
                          r'.*?^    fi\n', restore_ping, block, count=1, flags=re.M | re.S)
        restored = re.sub(r'\{ publish_relay_traffic_failure (?:ping|worker-snapshot|worker-growth|relay-snapshot|relay-growth|fixture) [^\n]*? \|\| :; return 1; \}',
                          'return 1', restored)
        for text, indentation in (
            ('[ "$hook_functional_wait_attempt" -lt 100 ]', 12),
            ('"$functional_relay" "$hook_functional_client_public_key")', 8),
            ('"$hook_functional_zero_snapshot" "$hook_functional_relay_snapshot"', 8),
            ('"$hook_functional_peer_address"', 8)):
            restored = restored.replace(text + ' \\\n' + ' ' * indentation + '|| return 1', text + ' || return 1')
        source = source.replace(block, restored, 1)
    for name in ('relay_traffic_diagnostic_value_is_safe', 'relay_traffic_snapshot_fields',
                 'publish_relay_traffic_failure'):
        source = re.sub(r'^' + name + r'\(\) \{\n.*?^\}\n\n', '', source, count=1, flags=re.M | re.S)
    return source


def shell(code, *args):
    return subprocess.run(['sh', '-eu', '-c', code, 'fixture', *map(str, args)],
                          text=True, capture_output=True, timeout=10)


def value(predicate='fixture', ping='0', before='0,10,20', worker='7,40,50', relay='8,60,70'):
    flag = lambda triple: ('unavailable' if triple == UNAVAILABLE else
                           'zero' if triple.split(',')[0] == '0' else 'nonzero')
    return (f'predicate={predicate};expected={EXPECTED[predicate]};ping={ping};'
            f'worker-baseline={before};worker-current={worker};relay-reference=0,0,0;'
            f'relay-current={relay};worker-handshake={flag(worker)};relay-handshake={flag(relay)}')


class RelayTrafficDiagnostic(unittest.TestCase):
    def publication_code(self):
        # Adapt only root owner IDs to the unprivileged inert test account;
        # actual mode/link/type/first-file/temporary-file guards remain intact.
        private = function(HOOK, 'private_file_is_safe').replace('8180:0:0:600:1',
                   f'8180:{os.getuid()}:{os.getgid()}:600:1')
        return private + ''.join(function(HOOK, name) for name in (
            'write_private_file', 'relay_traffic_diagnostic_value_is_safe',
            'relay_traffic_snapshot_fields', 'publish_relay_traffic_failure'))

    def test_real_failure_sites_report_exact_first_predicate_values_and_counts(self):
        code = self.publication_code() + function(HOOK, 'wireguard_snapshot_has_growth')
        block = traffic_block(HOOK.read_text()).replace('/usr/bin/ping', 'fixture_ping')
        code += 'fixture_traffic() {\n' + block + '}\n'
        fixture = r'''
proof_directory=$1; mode=$2; calls=$1/calls
start_failure_stage=functional-relay-traffic
hook_functional_baseline=$(printf '0\t10\t20')
hook_functional_wireguard=fixture; functional_relay_public_key=not-exported
functional_relay=fixture; hook_functional_client_public_key=not-exported
hook_functional_client_address=not-exported; functional_relay_ifindex=1
hook_functional_client_listen_port=1; hook_functional_peer_address=not-exported
advance_start_failure_stage() { start_failure_stage=$1; }
fixture_ping() { printf 'ping\n' >>"$calls"; [ "$mode" != ping ] || return 2; }
worker_wireguard_snapshot() {
    printf 'worker\n' >>"$calls"
    if [ "$mode" = worker-snapshot ]; then printf '7\t40\t50'; return 1; fi
    if [ "$mode" = worker-growth ]; then printf '0\t10\t20'; else printf '7\t40\t50'; fi
}
relay_wireguard_snapshot() {
    printf 'relay\n' >>"$calls"
    if [ "$mode" = relay-snapshot ]; then printf '8\t60\t70'; return 1; fi
    if [ "$mode" = relay-growth ]; then printf '0\t0\t0'; else printf '8\t60\t70'; fi
}
functional_relay_fixture_is_exact() { printf 'fixture\n' >>"$calls"; [ "$mode" != fixture ]; }
sleep() { [ "$1" = 0.05 ]; printf 'sleep\n' >>"$calls"; }
if fixture_traffic; then exit 99; fi
cat "$proof_directory/relay-traffic.failure"
'''
        with tempfile.TemporaryDirectory() as directory:
            for predicate in EXPECTED:
                root = Path(directory) / predicate; root.mkdir()
                result = shell(code + fixture, root, predicate)
                wc = '0,10,20' if predicate == 'worker-growth' else '7,40,50'
                rc = '0,0,0' if predicate == 'relay-growth' else '8,60,70'
                if predicate == 'worker-snapshot': wc = rc = UNAVAILABLE
                if predicate == 'worker-growth': rc = UNAVAILABLE
                if predicate == 'relay-snapshot': rc = UNAVAILABLE
                expected = value(predicate, '2' if predicate == 'ping' else '0', worker=wc, relay=rc)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, PREFIX + expected + '\n', ''))
                calls = (root / 'calls').read_text().splitlines()
                self.assertEqual(calls.count('ping'), 1)
                self.assertEqual(calls.count('worker'), 100 if predicate == 'worker-growth' else 1)
                self.assertEqual(calls.count('sleep'), 99 if predicate == 'worker-growth' else 0)
                self.assertEqual(calls.count('relay'), 0 if predicate.startswith('worker-') else 1)

    def test_invalid_snapshot_is_unavailable_not_zero_first_record_and_fatal_outcome_preserved(self):
        code = self.publication_code()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = r'''
proof_directory=$1; start_failure_stage=functional-relay-traffic
hook_functional_baseline=$(printf '0\t10\t20')
if publish_relay_traffic_failure ping 1 "$2" "$3"; then exit 99; fi
if publish_relay_traffic_failure fixture 0 '7\t8\t9' '1\t2\t3'; then exit 99; fi
cat "$proof_directory/relay-traffic.failure"
'''
            invalids = ('', '0\\t1\\t2', '01\t2\t3', '0\t18446744073709551616\t2',
                        '0\t1\t2\n0\t1\t2', '-----BEGIN PRIVATE KEY-----')
            for index, invalid in enumerate(invalids):
                target = root / str(index); target.mkdir()
                result = shell(code + fixture, target, invalid, invalid)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                    (0, PREFIX + value('ping', '1', worker=UNAVAILABLE, relay=UNAVAILABLE) + '\n', ''))
            wrong = root / 'wrong'; wrong.mkdir()
            result = shell(code + 'proof_directory=$1; start_failure_stage=functional-exit-relay-traffic; '
                           '! publish_relay_traffic_failure ping 1 0 0; test ! -e "$1/relay-traffic.failure"', wrong)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def test_success_commands_and_wait_guards_are_unchanged_and_publish_nothing(self):
        source = HOOK.read_text()
        restored = normalize_relay_traffic_diagnostic(source)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), ORIGINAL_HOOK)
        with self.assertRaises(AssertionError):
            normalize_relay_traffic_diagnostic(source.replace(
                '        hook_traffic_ping_status=0\n', '        hook_traffic_ping_status=0; extra-command\n', 1))
        # Actual and restored success blocks must execute the same fixed command
        # sequence. No diagnostic helper may run during success.
        traces = []
        for current in (source, restored):
            block = traffic_block(current).replace('/usr/bin/ping', 'fixture_ping')
            code = function(HOOK, 'wireguard_snapshot_has_growth')
            code += 'fixture_traffic() {\n' + block + '}\n' + r'''
hook_functional_baseline=$(printf '0\t10\t20')
hook_functional_wireguard=fixture; functional_relay_public_key=not-exported
functional_relay=fixture; hook_functional_client_public_key=not-exported
hook_functional_client_address=not-exported; functional_relay_ifindex=1
hook_functional_client_listen_port=1; hook_functional_peer_address=not-exported
exec 3>&2
advance_start_failure_stage() { printf 'stage\n' >&2; }
fixture_ping() { printf 'ping\n' >&3; }
worker_wireguard_snapshot() { printf 'worker\n' >&2; printf '7\t40\t50'; }
relay_wireguard_snapshot() { printf 'relay\n' >&2; printf '8\t60\t70'; }
functional_relay_fixture_is_exact() { printf 'fixture\n' >&2; }
publish_relay_traffic_failure() { exit 99; }
sleep() { exit 99; }
fixture_traffic
'''
            result = shell(code)
            self.assertEqual((result.returncode, result.stdout), (0, ''))
            traces.append(result.stderr)
        self.assertEqual(traces, ['stage\nping\nworker\nrelay\nfixture\n'] * 2)

    def test_closed_value_validators_agree_and_reject_noncanonical_unsafe_values(self):
        validators = [function(path, 'relay_traffic_diagnostic_value_is_safe') for path in (HOOK, GATE, OUTER)]
        self.assertEqual(validators, [validators[0]] * 3)
        valid = value()
        maxvalue = value(before='18446744073709551615,0,0', worker='18446744073709551615,18446744073709551615,18446744073709551615')
        for accepted in (valid, maxvalue):
            self.assertEqual(shell(validators[0] + 'relay_traffic_diagnostic_value_is_safe "$1"', accepted).returncode, 0)
        malformed = [valid + '\n' + valid, valid + '\n', valid.replace('fixture-exact', 'other'),
            valid.replace('predicate=fixture', 'predicate=other'), valid.replace('ping=0', 'ping=2'),
            valid.replace('7,40,50', '07,40,50'), valid.replace('7,40,50', '7,18446744073709551616,50'),
            valid.replace('7,40,50', '7,-1,50'), valid.replace('7,40,50', '7,unavailable,50'),
            valid.replace('worker-handshake=nonzero', 'worker-handshake=zero'),
            valid.replace('relay-reference=0,0,0', 'relay-reference=1,0,0'), valid + ';extra=1',
            '-----BEGIN PRIVATE KEY-----', 'x' * 1024]
        for bad in malformed:
            result = shell(validators[0] + 'relay_traffic_diagnostic_value_is_safe "$1"', bad)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout + result.stderr, '')

    def driver_code(self):
        return function(CAPTURE, 'vp_capture_file_is_safe') + ''.join(function(GATE, name) for name in (
            'relay_traffic_diagnostic_value_is_safe', 'report_relay_traffic_diagnostic')) + r'''
VP_CAPTURE_OWNER_UID=$(id -u); VP_CAPTURE_OWNER_GID=$(id -g)
temporary_stage=$1; proof_failure_reason=${2:-production-launch-status}
production_start_failure_stage=${3:-functional-relay-traffic}
report_relay_traffic_diagnostic
'''

    def outer_code(self):
        return ''.join(function(OUTER, name) for name in ('require_no_private_key_marker',
            'relay_traffic_diagnostic_value_is_safe', 'report_non_retained_relay_traffic_diagnostic'))

    def test_real_private_driver_and_outer_round_trip_all_six_predicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'production-output').mkdir()
            record = root / 'production-output/relay-traffic.failure'; capture = root / 'capture'
            for predicate in EXPECTED:
                current = value(predicate, '1' if predicate == 'ping' else '0')
                record.write_text(PREFIX + current + '\n'); record.chmod(0o600)
                result = shell(self.driver_code(), root)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', PREFIX + current + '\n'))
                capture.write_text(STAGE + result.stderr + FAILURE); capture.chmod(0o600)
                result = shell(self.outer_code() + 'report_non_retained_relay_traffic_diagnostic "$1"', capture)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                    (0, '', 'non-retained helper-boundary PR smoke relay traffic diagnostic: ' + current + '\n'))

    def test_actual_runtime_fence_path_retains_first_failure_and_delivers_scalars(self):
        driver_names = ('production_start_failure_stage_is_safe',
            'production_functional_probe_failure_value_is_safe', 'relay_traffic_diagnostic_value_is_safe',
            'report_relay_traffic_diagnostic', 'report_production_launch_diagnostic',
            'proof_failure_reason_is_safe', 'retire_failure_stage_is_safe',
            'production_retirement_diagnostic_stage_is_safe', 'report_production_retirement_diagnostic', 'failed')
        code = function(CAPTURE, 'vp_capture_file_is_safe')
        code += ''.join(function(GATE, name) for name in driver_names)
        code += r'''
VP_CAPTURE_OWNER_UID=$(id -u); VP_CAPTURE_OWNER_GID=$(id -g)
temporary_stage=$1; proof_failure_reason=production-launch-status; proof_ok=no
driver_phase=production-retirement
printf 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=production-retirement\n' >&2
report_production_retirement_diagnostic runtime-fence
[ "$proof_failure_reason" = production-launch-status ] && [ "$proof_ok" = no ]
failed 'production unit retirement fence did not settle'
'''
        outer_names = ('non_retained_restart_retirement_stage_is_safe',
            'non_retained_production_retirement_stage_is_safe', 'non_retained_proof_failure_reason_is_safe',
            'non_retained_production_launch_stage_is_safe', 'non_retained_functional_probe_failure_value_is_safe',
            'report_non_retained_production_retirement_diagnostic')
        outer = self.outer_code() + ''.join(function(OUTER, name) for name in outer_names)
        outer += 'report_non_retained_production_retirement_diagnostic "$1"'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'production-output'; output.mkdir()
            stage = output / 'start.failure'
            stage.write_text('VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-relay-traffic\n')
            stage.chmod(0o600)
            record = output / 'relay-traffic.failure'; capture = root / 'capture'
            diagnostic = PREFIX + value('ping', '2') + '\n'
            record.write_text(diagnostic); record.chmod(0o600)
            result = shell(code, root)
            self.assertEqual(result.returncode, 1)
            self.assertIn(diagnostic, result.stderr)
            self.assertIn('VOLPAROSSA_HELPER_LIVE_PRODUCTION_RETIREMENT_FIRST_FAILURE_V1=production-launch-status\n', result.stderr)
            capture.write_text(result.stderr); capture.chmod(0o600)
            parsed = shell(outer, capture)
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
            self.assertIn('production retirement stage: runtime-fence\n', parsed.stderr)
            self.assertIn('first proof failure: production-launch-status\n', parsed.stderr)
            self.assertIn('production launch diagnostic: functional-relay-traffic\n', parsed.stderr)
            self.assertIn('relay traffic diagnostic: ' + value('ping', '2') + '\n', parsed.stderr)
            direct = self.outer_code() + 'report_non_retained_relay_traffic_diagnostic "$1" retirement-runtime-fence'
            for malformed in (
                result.stderr.replace('FIRST_FAILURE_V1=production-launch-status', 'FIRST_FAILURE_V1=production-retirement'),
                result.stderr.replace('DIAGNOSTIC_V1=runtime-fence', 'DIAGNOSTIC_V1=stop-wait'),
                result.stderr.replace(STAGE, STAGE + STAGE.replace('functional-relay-traffic', 'preflight-runtime')),
                result.stderr.replace(diagnostic, diagnostic + diagnostic)):
                capture.write_text(malformed)
                rejected = shell(direct, capture)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout + rejected.stderr, '')
            # Invalid optional evidence disappears; neither original reason nor
            # actual fatal runtime-fence status can be replaced by the diagnostic.
            record.write_text(PREFIX + 'malformed\n')
            result = shell(code, root)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(PREFIX, result.stderr)
            self.assertIn('FIRST_FAILURE_V1=production-launch-status\n', result.stderr)
            capture.write_text(result.stderr)
            parsed = shell(outer, capture)
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
            self.assertNotIn('relay traffic diagnostic:', parsed.stderr)
            self.assertIn('first proof failure: production-launch-status\n', parsed.stderr)

    def test_private_driver_rejects_unsafe_files_malformed_oversize_duplicate_and_wrong_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'production-output').mkdir(); path = root / 'production-output/relay-traffic.failure'
            valid = PREFIX + value() + '\n'
            for raw in ('', valid + valid, valid + '\n', valid.rstrip(), valid + 'private', 'x' * 1025,
                        PREFIX + '-----BEGIN PRIVATE KEY-----\n'):
                path.write_text(raw); path.chmod(0o600)
                self.assertNotEqual(shell(self.driver_code(), root).returncode, 0)
            path.write_text(valid); path.chmod(0o644)
            self.assertNotEqual(shell(self.driver_code(), root).returncode, 0)
            path.chmod(0o600)
            for reason, stage in (('other', 'functional-relay-traffic'), ('production-launch-status', 'functional-exit-relay-traffic')):
                self.assertNotEqual(shell(self.driver_code(), root, reason, stage).returncode, 0)
            pending = path.with_name(path.name + '.next'); pending.touch()
            self.assertNotEqual(shell(self.driver_code(), root).returncode, 0); pending.unlink()
            path.unlink(); self.assertNotEqual(shell(self.driver_code(), root).returncode, 0)
            target = root / 'target'; target.write_text(valid); target.chmod(0o600)
            path.symlink_to(target); self.assertNotEqual(shell(self.driver_code(), root).returncode, 0)
            path.unlink(); path.hardlink_to(target); self.assertNotEqual(shell(self.driver_code(), root).returncode, 0)

    def test_outer_rejects_wrong_mixed_duplicate_privatekey_and_unsafe_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture'; line = PREFIX + value() + '\n'; valid = STAGE + line + FAILURE
            bad = [valid.replace('functional-relay-traffic', 'functional-exit-relay-traffic'),
                   STAGE + line + line + FAILURE, STAGE + PREFIX + 'bad\n' + FAILURE,
                   STAGE + PREFIX + 'x' * 1024 + '\n' + FAILURE, valid + '\n',
                   STAGE + line + '-----BEGIN PRIVATE KEY-----\n' + FAILURE,
                   valid.replace(STAGE, STAGE + STAGE.replace('functional-relay-traffic', 'preflight-runtime')),
                   STAGE + line + FAILURE.replace('production-launch-status', 'other') + FAILURE]
            code = self.outer_code() + 'report_non_retained_relay_traffic_diagnostic "$1"'
            for raw in bad:
                path.write_text(raw); path.chmod(0o600)
                result = shell(code, path)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout + result.stderr, '')
            path.write_text(valid); path.chmod(0o644)
            self.assertNotEqual(shell(code, path).returncode, 0)
            path.unlink(); self.assertNotEqual(shell(code, path).returncode, 0)
            target = Path(directory) / 'target'; target.write_text(valid); target.chmod(0o600)
            path.symlink_to(target); self.assertNotEqual(shell(code, path).returncode, 0)
            path.unlink(); path.hardlink_to(target); self.assertNotEqual(shell(code, path).returncode, 0)


if __name__ == '__main__':
    unittest.main()
