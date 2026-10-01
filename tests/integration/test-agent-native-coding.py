#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline contract tests, never evidence that a model performed the coding task."""
import copy
import hashlib
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / 'agent-native-coding.py'))


def synthetic_receipt():
    return dict(version=2, kind='native-codex-core-coding', success=True, phase='complete',
        model='qwen3-0.6b-v1', full_native_prompt_sha256=FIX['PROMPT_SHA'],
        before_sha256=hashlib.sha256(b'def add(a, b):\n    return a - b\n').hexdigest(),
        after_sha256=hashlib.sha256(b'def add(a, b):\n    return a + b\n').hexdigest(),
        native_turn_completed=True, read=True, edit=True, test=True, independent_test_passed=True,
        accepted_commands=3, declined_commands=0, unexpected_command=False,
        approval_denials=dict.fromkeys(FIX['APPROVAL_DENIALS'], 0),
        thread_unsubscribed=True, private_peer_execution_claimed=False,
        general_coding_quality_claimed=False, runtime_exit=0, forced_stop=False, diagnostic=None,
        responses=dict(submitted=4, completed=4, incomplete=0, cleanup_confirmed=4))


def synthetic_bundle():
    runtime = dict(binary_sha256='1' * 64, binary_bytes=1234, prompt_sha256=FIX['PROMPT_SHA'],
        prompt_bytes=20903, provenance=dict(source_revision=FIX['UPSTREAM'],
        source_tree='ea880e9a6ce9277531a9ab88be06f40a7ddf7b6f', report_sha256='2' * 64,
        lock_sha256='571137c35517878869d5dca7ca5df5fa0b3e596e0466ad7b8c100041c6ce75b8'))
    files = {f'code/{name}': dict(pin, mode=0o444) for name, pin in FIX['pins']()['files'].items()}
    files['runtime/runtime/codex-app-server'] = dict(bytes=1234, sha256='1' * 64, mode=0o555)
    files['runtime/prompt.md'] = dict(bytes=20903, sha256=FIX['PROMPT_SHA'], mode=0o444)
    return runtime, dict(version=1, kind='volparossa-native-coding-runtime-bundle', core_revision='a' * 40,
        code_revision=FIX['pins']()['revision'], code_tree=FIX['CODE_TREE'], codex_revision=FIX['UPSTREAM'],
        codex_tree=runtime['provenance']['source_tree'], toolchain_report_sha256=FIX['TOOLCHAIN_SHA'],
        binary_sha256='1' * 64, build_report_sha256='2' * 64, prompt_sha256=FIX['PROMPT_SHA'], source_build=True,
        existing_binary_reused=False, bit_reproducibility_proven=False, app_server_executed=False, files=files)


def synthetic_report():
    runtime, bundle = synthetic_bundle()
    memory = dict(memory_max_bytes=FIX['MEMORY_MAX'], swap_max_bytes=0, current_bytes=100,
                  peak_bytes=200, admission_headroom_bytes=FIX['MEMORY_MAX']-100, oom=0, oom_kill=0)
    return dict(report_kind='volparossa-agent-native-coding', proof_version=1, source_revision='a' * 40,
        scope=FIX['SCOPE'], success=True, phase='complete', code_provision=FIX['pins'](),
        node_provision=FIX['PRIVATE'].pins()['runtime'], provision=FIX['model_provenance'](),
        inputs_unchanged=True, service_clean_stop=True, raw_input_exported=False, raw_model_output_exported=False,
        general_coding_quality_proven=False, private_peer_execution_proven=False, hard_4gib_proven=False,
        codex_app_server_proven=True, code_edit_test_loop_proven=True, native=synthetic_receipt(), runtime=runtime,
        runtime_bundle=dict(sha256='3' * 64, **FIX['bundle_summary'](bundle, 'a' * 40, runtime, FIX['pins']())),
        memory_before=memory, memory_final=copy.deepcopy(memory),
        execution_timing=dict(version=1, scope='service_cgroup_during_native_harness',
            elapsed_ms=310000, cpu_usage_usec=601000000),
        native_cleanup=dict(process_joined=True, private_state_removed=True, host_network_unchanged=True),
        cleanup=dict(client_group_joined=True, provision_group_joined=True, service_stopped=True,
            service_cgroup_empty=True, observed_lifetimes_ended=True, guest_root_removed=True, code_output_removed=True),
        host_state_unchanged=True, host_state_hashes=dict(before='4' * 64, after='4' * 64),
        fixture_hashes={name: FIX['digest'](HERE / name) for name in FIX['FIXTURE_NAMES']})


class ContractTests(unittest.TestCase):
    def test_closed_service_cpu_observation_uses_counter_delta_and_monotonic_elapsed_time(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            counter = path / 'cpu.stat'
            counter.write_text('usage_usec 900\nuser_usec 700\nsystem_usec 200\n')
            with patch.object(FIX['PRIVATE'], 'CGROUP', path):
                before = FIX['service_cpu_usage']()
                counter.write_text('usage_usec 600000900\nuser_usec 500000700\nsystem_usec 100000200\n')
                with patch.object(FIX['time'], 'monotonic', return_value=410):
                    measured = FIX['execution_timing'](100, before)
                self.assertEqual(measured, dict(version=1, scope='service_cgroup_during_native_harness',
                    elapsed_ms=310000, cpu_usage_usec=600000000))
                for bad in ('usage_usec 1\nusage_usec 2\n', 'usage_usec PRIVATE_CANARY\n',
                            'usage_usec -1\n', 'x' * 4097, 'user_usec 1\n'):
                    counter.write_text(bad)
                    with self.assertRaises(ValueError):
                        FIX['service_cpu_usage']()

    def test_timing_is_bounded_content_free_and_does_not_assert_a_kill_cause(self):
        value = synthetic_report()['execution_timing']
        FIX['check_execution_timing'](value)
        for changes in ({'elapsed_ms': -1}, {'elapsed_ms': 3600001}, {'elapsed_ms': True},
                        {'cpu_usage_usec': -1}, {'cpu_usage_usec': 128 * 3600 * 1000000 + 1},
                        {'cpu_usage_usec': True}, {'version': True}, {'scope': 'PRIVATE_CANARY'},
                        {'kill_cause': 'cpu_limit'}, {'prompt': 'PRIVATE_CANARY'}):
            with self.assertRaises(ValueError):
                FIX['check_execution_timing'](dict(value, **changes))

    def test_runtime_bundle_binds_fresh_source_build_and_exact_cross_repo_sources(self):
        runtime, value = synthetic_bundle()
        summary = FIX['bundle_summary'](value, 'a' * 40, runtime, FIX['pins']())
        self.assertNotIn('files', summary)
        for field, bad in (('core_revision', 'b' * 40), ('code_revision', 'b' * 40),
                           ('codex_revision', 'b' * 40), ('binary_sha256', '9' * 64),
                           ('existing_binary_reused', True), ('source_build', False),
                           ('bit_reproducibility_proven', True), ('toolchain_report_sha256', '9' * 64)):
            with self.assertRaises(ValueError):
                FIX['bundle_summary'](dict(value, **{field: bad}), 'a' * 40, runtime, FIX['pins']())

    def test_bundle_rejects_changed_writable_or_missing_code_inputs(self):
        runtime, value = synthetic_bundle()
        for change in ('hash', 'mode', 'missing'):
            bad = copy.deepcopy(value)
            record = bad['files']['code/scripts/smoke_native_coding.py']
            if change == 'hash':
                record['sha256'] = '9' * 64
            elif change == 'mode':
                record['mode'] = 0o644
            else:
                del bad['files']['code/scripts/smoke_native_coding.py']
            with self.assertRaises(ValueError):
                FIX['bundle_summary'](bad, 'a' * 40, runtime, FIX['pins']())

    def test_component_report_requires_native_and_core_lifecycle_proof(self):
        value = synthetic_report()
        FIX['check_report'](value, 'a' * 40)
        for field in ('service_clean_stop', 'inputs_unchanged', 'host_state_unchanged', 'code_edit_test_loop_proven'):
            with self.assertRaises(ValueError):
                FIX['check_report'](dict(value, **{field: False}), 'a' * 40)
        for field in value['cleanup']:
            bad = copy.deepcopy(value)
            bad['cleanup'][field] = False
            with self.assertRaises(ValueError):
                FIX['check_report'](bad, 'a' * 40)
        bad = copy.deepcopy(value)
        bad['memory_final']['oom_kill'] = 1
        with self.assertRaises(ValueError):
            FIX['check_report'](bad, 'a' * 40)

    def test_closed_native_receipt_accepts_complete_structure_only(self):
        value = synthetic_receipt()
        self.assertEqual(FIX['native_receipt'](value), value)
        for field in ('read', 'edit', 'test', 'independent_test_passed', 'native_turn_completed', 'thread_unsubscribed'):
            changed = dict(value, **{field: False})
            with self.assertRaises(ValueError):
                FIX['native_receipt'](changed)

    def test_requires_four_real_completed_cleanup_confirmed_responses(self):
        for counters in (dict(submitted=3, completed=3, incomplete=0, cleanup_confirmed=3),
                         dict(submitted=4, completed=3, incomplete=1, cleanup_confirmed=4),
                         dict(submitted=4, completed=4, incomplete=0, cleanup_confirmed=3)):
            value = dict(synthetic_receipt(), responses=counters)
            with self.assertRaises(ValueError):
                FIX['native_receipt'](value)

    def test_denial_counts_are_closed_bounded_and_account_for_each_decline(self):
        value = synthetic_receipt()
        denials = dict(value['approval_denials'], command=1)
        value.update(approval_denials=denials, declined_commands=1)
        self.assertEqual(FIX['native_receipt'](value), value)
        for change in ({'version': 1}, {'version': True}, {'version': 3},
                       {'declined_commands': 0}, {'approval_denials': {}},
                       {'approval_denials': dict(denials, private_command='PRIVATE_CANARY')},
                       {'approval_denials': dict(denials, command=True)},
                       {'approval_denials': dict(denials, command=-1)},
                       {'approval_denials': dict(denials, command=17)},
                       {'approval_denials': dict(denials, command='PRIVATE_CANARY')}):
            with self.assertRaises(ValueError):
                FIX['native_receipt'](dict(value, **change))
        del value['approval_denials']
        with self.assertRaises(ValueError):
            FIX['native_receipt'](value)

    def test_declines_raw_text_and_unsupported_quality_claims(self):
        for changed in (dict(synthetic_receipt(), prompt='PRIVATE_CANARY'),
                        dict(synthetic_receipt(), general_coding_quality_claimed=True),
                        dict(synthetic_receipt(), private_peer_execution_claimed=True),
                        dict(synthetic_receipt(), diagnostic='PRIVATE_CANARY')):
            with self.assertRaises(ValueError):
                FIX['native_receipt'](changed)

    def test_modified_file_graceful_exit_and_no_forced_execution_are_required(self):
        value = synthetic_receipt()
        for changed in (dict(value, after_sha256=value['before_sha256']), dict(value, forced_stop=True),
                        dict(value, runtime_exit=1), dict(value, unexpected_command=True)):
            with self.assertRaises(ValueError):
                FIX['native_receipt'](changed)
        failed = dict(value, success=False, phase='native-turn', diagnostic='native_coding_incomplete',
                      after_sha256=None, read=False, edit=False, test=False, responses=None)
        self.assertFalse(FIX['native_receipt'](failed)['success'])

    def test_pins_are_exact_and_closed_exports_exclude_private_runtime(self):
        pins = FIX['pins']()
        self.assertEqual(pins['revision'], 'eb48696eb37afb9cda59bffc350845309b963dbb')
        self.assertEqual(set(pins['files']), FIX['SOURCE_NAMES'])
        self.assertEqual(FIX['EXPORT_NAMES'], {'agent-native-coding-smoke.json', 'host-state-before.json',
            'host-state-after.json', 'current-phase', 'guest-exit-status', 'runner.stdout', 'runner.stderr'})
        for name in ('client.log', 'service.log', 'report.json', 'arithmetic.py', 'private.sock', 'prompt.md'):
            self.assertNotIn(name, FIX['EXPORT_NAMES'])

    def test_existing_conversation_fixture_is_not_mutated(self):
        self.assertEqual(FIX['PRIVATE'].ROOT, Path('/home/vpci/native-coding'))
        self.assertEqual(FIX['PRIVATE'].UNIT, 'volparossa-native-coding.service')
        old = runpy.run_path(str(HERE / 'agent-private-conversation.py'))
        self.assertEqual(old['ROOT'], Path('/home/vpci/private-conversation'))
        self.assertEqual(old['UNIT'], 'volparossa-qwen-conversation.service')

    def test_guest_scoped_service_window_keeps_request_and_memory_limits(self):
        source = (HERE / 'agent-native-coding.py').read_text()
        self.assertIn('--property=RuntimeMaxSec=2700', source)
        self.assertIn("'--max-seconds', '600'", source)
        self.assertIn('--property=MemorySwapMax=0', source)
        self.assertIn('--property=PrivateNetwork=yes', source)
        self.assertIn('--property=KillMode=control-group', source)
        self.assertEqual(FIX['MEMORY_MAX'], 5 * 1024**3)
        self.assertIn("'--disposable-guest'", source)
        self.assertIn("require(not list((ROOT / 'work').iterdir())", source)

    def test_shell_preview_has_no_model_or_service_side_effect(self):
        result = subprocess.run(['sh', str(HERE / 'agent-native-coding.sh'), '--preview'],
                                capture_output=True, text=True, check=True)
        self.assertIn('PREVIEW ONLY: no files, model, installation or network changes.', result.stdout)
        self.assertIn('600s per-request', result.stdout)
        refused = subprocess.run(['sh', str(HERE / 'agent-native-coding.sh'), '--execute'],
                                 capture_output=True, text=True)
        self.assertEqual(refused.returncode, 64)


if __name__ == '__main__':
    unittest.main()
