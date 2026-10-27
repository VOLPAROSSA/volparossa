#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert first-failure publication and strict-parser fixtures; no native/VM."""
from pathlib import Path
import hashlib
import importlib.util
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('preflight', HERE / 'test-helper-preflight-diagnostic.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
function, shell = preflight.function, preflight.shell
HOOK = preflight.HOOK
REASONS = ('functional-worker-child', 'functional-worker-custody', 'functional-worker-pidfd-identity', 'functional-worker-namespace-identity', 'functional-worker-fdstore', 'functional-worker-namespace-distinct', 'functional-worker-process-revalidate', 'functional-worker-namespace-revalidate', 'functional-worker-namespace-open', 'functional-worker-process-open', 'functional-worker-namespace-stat', 'functional-worker-namespace-pin', 'functional-worker-process-stat', 'functional-worker-process-pin', 'functional-worker-custody-repeat', 'functional-worker-custody-stability', 'functional-worker-process-status', 'functional-worker-helper-stability', 'functional-worker-wireguard-interface', 'functional-worker-wireguard-name', 'functional-worker-peer-address', 'functional-worker-local-address', 'functional-worker-wireguard-state', 'functional-worker-public-key-read', 'functional-worker-public-key-shape', 'functional-worker-public-key-unique', 'functional-worker-port-read', 'functional-worker-port-shape', 'functional-worker-port-distinct', 'functional-worker-counters', 'functional-worker-custody-parent-netns', 'functional-worker-custody-parent-netns-shape', 'functional-worker-custody-empty', 'functional-worker-custody-readlink', 'functional-worker-custody-pidfd', 'functional-worker-custody-pidfd-conflict', 'functional-worker-custody-process-target', 'functional-worker-custody-process', 'functional-worker-custody-process-conflict', 'functional-worker-custody-netns', 'functional-worker-custody-netns-conflict', 'functional-worker-custody-missing-pins', 'functional-worker-fdstore-count-before-read', 'functional-worker-fdstore-count-before', 'functional-worker-fdstore-object', 'functional-worker-fdstore-dump-read', 'functional-worker-fdstore-dump-size', 'functional-worker-fdstore-dump-exact', 'functional-worker-fdstore-name', 'functional-worker-fdstore-count-after-read', 'functional-worker-fdstore-count-after')
BASELINE = {'run_functional_client_lease_probe': '7f4ff87acd6c5f483dcade526d06c344e167d555e417d7e9bbe6136ba8dadc09', 'capture_parent_worker_custody': '13168e35d2ba2b2ef7a5097078ca340c53b43249abf0eb355d7ee0e42ff791a6', 'unit_fdstore_exact_active_custody': '510f49d7dca6695bc856d982062682d32275ce0516b587c324056a313642aebd', 'advance_start_failure_stage': 'd05ff03eba9a2511a2e7b826306484303570d1221c2126e2da4ea5ea5bca0915', 'advance_restart_start_failure_stage': '25b6810a51512b93b558f744261afbb1772bc3641c74c3f9a280363d407bc9e6'}
preflight.REASONS = REASONS


class WorkerObservationDiagnostic(unittest.TestCase):
    gate = preflight.PreflightDiagnostic.gate
    test_real_gate_and_outer_parser_accept_each_reason_and_old_coarse = preflight.PreflightDiagnostic.test_real_gate_and_outer_parser_accept_each_reason_and_old_coarse
    test_gate_rejects_malformed_missing_unsafe_tampered_and_wrong_stage = preflight.PreflightDiagnostic.test_gate_rejects_malformed_missing_unsafe_tampered_and_wrong_stage
    test_outer_rejects_unknown_duplicate_mixed_private_key_and_wrong_failure = preflight.PreflightDiagnostic.test_outer_rejects_unknown_duplicate_mixed_private_key_and_wrong_failure
    test_restart_specific_parser_rejects_normal_start_details = preflight.PreflightDiagnostic.test_restart_specific_parser_rejects_normal_start_details

    def code(self):
        return ''.join(function(HOOK, name) for name in (
            'start_failure_stage_is_safe', 'restart_start_failure_stage_is_safe',
            'publish_start_failure', 'worker_observation_failure',
            'advance_start_failure_stage'))

    def test_subshell_failure_survives_parent_fallback_and_exit_publication(self):
        # Execute the actual failure publisher under command substitution, then
        # its parent fallback and final coarse publication. No runtime identities
        # or stderr are copied into the private record.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'first'
            fixture = r''' 
start_failure_armed=yes; start_failure_published=no
start_failure_stage=functional-worker-observation; start_failure_record=$1
write_private_file() {
    [ ! -e "$1" ] && [ ! -L "$1" ] || return 1
    (set -C; printf '%s\n' "$2" >"$1")
}
if captured=$(worker_observation_failure "$2"); then exit 3; fi
[ -z "$captured" ]
if worker_observation_failure functional-worker-custody; then exit 4; fi
if publish_start_failure; then exit 5; fi
if advance_start_failure_stage functional-relay-fixture; then exit 6; fi
cat "$start_failure_record"
'''
            for reason in REASONS:
                with self.subTest(reason=reason):
                    if path.exists(): path.unlink()
                    result = shell(self.code() + fixture, path, reason)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, '')
                    self.assertEqual(result.stdout, preflight.PREFIX + reason + '\n')
                    self.assertLessEqual(len(result.stdout), 128)

    def test_wrong_stage_unknown_coarse_and_preflight_are_rejected(self):
        fixture = r'''
start_failure_stage=$1; start_failure_armed=yes; start_failure_published=no
write_private_file() { exit 99; }
if worker_observation_failure "$2"; then exit 3; fi
[ "$start_failure_stage" = "$1" ]
'''
        for stage, reason in (
            ('identity-process', REASONS[0]),
            ('functional-worker-child', REASONS[1]),
            ('functional-worker-observation', 'functional-worker-unknown'),
            ('functional-worker-observation', 'functional-worker-observation'),
            ('functional-worker-observation', 'preflight-token-metadata'),
            ('functional-worker-observation', REASONS[0] + ',/private/path')):
            result = shell(self.code() + fixture, stage, reason)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout + result.stderr, '')

    def test_guards_success_transitions_and_all_other_code_are_unchanged(self):
        source = HOOK.read_text()
        # Strip only the fixed diagnostic call preceding the ORIGINAL return1;
        # remove its braces and the explicit final-conjunction failure annotation.
        # Frozen hashes are the complete functions at source57b121a0.
        for name, expected in BASELINE.items():
            text = function(HOOK, name)
            # Only this reviewed observer correction changes successful code:
            # bind each existing call to its explicit Client/Exit role.
            text = text.replace('worker_wireguard_interface 7 client', 'worker_wireguard_interface 7')
            text = text.replace('worker_wireguard_interface 7 exit', 'worker_wireguard_interface 7')
            def restore_group(match):
                predicate = '\n'.join(line[4:] for line in match[1].splitlines())
                if match[2] == 'functional-worker-custody-missing-pins':
                    return predicate + '\n'
                return predicate + ' || return 1\n'
            text = re.sub(
                r'    if ! \{\n(.*?)\n    \}; then\n'
                r'        worker_observation_failure (functional-worker-[a-z-]+)\n'
                r'        return 1\n    fi\n', restore_group, text, flags=re.S)
            text = re.sub(r'\{ worker_observation_failure functional-worker-[a-z-]+; return 1; \}', 'return 1', text)
            text = re.sub(r'worker_observation_failure functional-worker-[a-z-]+; return 1', 'return 1', text)
            text = text.replace('        && [ "$hook_custody_namespace_count" -ge 1 ] \\\n        || return 1\n', '        && [ "$hook_custody_namespace_count" -ge 1 ]\n')
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), expected, name)
        actual = set(re.findall(r'worker_observation_failure (functional-worker-[a-z-]+)', source))
        self.assertEqual(actual, set(REASONS))
        for reason in REASONS:
            self.assertEqual(len(re.findall(r'worker_observation_failure ' + re.escape(reason) + r'(?:;|\n)', source)), 1)


if __name__ == '__main__':
    unittest.main()
