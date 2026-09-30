#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline fixture-contract tests only. Synthetic receipts are not inference evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / 'agent-private-conversation.py'))
REVISION = 'a' * 40


def example_receipt():
    """Deliberately fabricated validator input, never exported as runtime proof."""
    provisioner = runpy.run_path(str(FIX['ML'] / 'provision.py'))
    model = provisioner['load_pins'](FIX['PROFILE'])
    model_bytes, requirements = provisioner['retained_pin_files'](model)
    isolation = dict(observed=True, cli=dict(pid=1234, start_ticks=1), worker=dict(pid=1235, start_ticks=2),
        network_devices=['lo'], ipv4_routes=[], effective_capabilities=0,
        namespaces={key: 'isolated' for key in ('net', 'pid', 'ipc', 'mnt')},
        guest_namespaces={key: 'guest' for key in ('net', 'pid', 'ipc', 'mnt')},
        host_home_visible=False, outside_canary_visible=False,
        exact_input_inodes={key: True for key in ('model', 'runtime', 'dataset')},
        mounts={key: ['ro'] for key in ('/runtime', '/model', '/dataset.json')})
    result = dict(report_kind='volparossa-agent-private-conversation', proof_version=1,
        source_revision=REVISION, scope=FIX['SCOPE'], success=True, phase='complete',
        raw_input_exported=False, raw_model_output_exported=False, codex_app_server_proven=False,
        code_edit_test_loop_proven=False, hard_4gib_proven=False, general_coding_quality_proven=False,
        code_provision=FIX['pins'](), inputs_unchanged=True, service_clean_stop=True, client_diagnostic=None,
        provision=dict(model_id=model['model_id'], revision=model['revision'], model_profile=FIX['PROFILE'],
            download_bytes=provisioner['download_total'](model), budget_bytes=5 * FIX['GIB'], installed_wheels=38,
            model_pins_sha256=hashlib.sha256(model_bytes).hexdigest(), requirements_sha256=hashlib.sha256(requirements).hexdigest()),
        client=dict(version=1, runtime_version='v24.19.0', network_isolated=True, genuine_conversation_client=True,
            model_turns=2, model_selected_tool=True, correlated_tool_result_consumed=True, literal_canary_present=True,
            source_was_synthetic=True, codex_app_server_proven=False, code_edit_test_loop_proven=False,
            general_coding_quality_proven=False),
        tool=dict(version=1, authorized_fixture_read=True, tool_calls_executed=1, command_execution=False,
            canary_absent_from_first_input=True, correlated_call_id='vp-' + 'a' * 32),
        cleanup=dict(client_group_joined=True, provision_group_joined=True, observer_group_joined=True,
            service_stopped=True, observed_lifetimes_ended=True, guest_root_removed=True),
        host_state_unchanged=True, host_state_hashes=dict(before='b' * 64, after='b' * 64),
        fixture_hashes={name: FIX['digest'](HERE / name) for name in ('agent-private-conversation.py',
            'agent-private-conversation.cjs', 'agent-private-conversation-pins.json', 'agent-private-conversation.sh')})
    for turn, kind in ((1, 'function_call'), (2, 'assistant')):
        result[f'turn_{turn}'] = dict(output_type=kind, incomplete_reason=None, turn_complete=True,
            prompt_tokens=100, generated_tokens=20, cleanup_confirmed=True)
        result[f'isolation_{turn}'] = copy.deepcopy(isolation)
        result[f'isolation_{turn}']['worker']['pid'] += turn
    for field in ('memory_before', 'memory_after_1', 'memory_after_2', 'memory_final'):
        result[field] = dict(memory_max_bytes=FIX['MEMORY_MAX'], swap_max_bytes=0,
            current_bytes=100, peak_bytes=200, admission_headroom_bytes=FIX['MEMORY_MAX']-100, oom=0, oom_kill=0)
    return result


class FixtureTests(unittest.TestCase):
    def test_service_diagnostic_preserves_fixed_stages_without_private_fields(self):
        event = dict(version=1, phase='refresh', detail=dict(code='compute_private_process_children',
            io_kind='permission_denied', exit_code=None, signal=None, stderr_class=None))
        records = [event]
        for change in ({'phase': 'PRIVATE_CANARY'}, {'request_id': 'PRIVATE_CANARY'},
                       {'detail': dict(event['detail'], code='PRIVATE_CANARY')},
                       {'detail': dict(event['detail'], io_kind='PRIVATE_CANARY')},
                       {'detail': dict(event['detail'], stderr_class='/private/PRIVATE_CANARY')},
                       {'detail': dict(event['detail'], signal=True)}):
            records.append(dict(event, **change))
        with tempfile.TemporaryDirectory(prefix='qwen-fixture-test-', dir=HERE) as directory:
            path = Path(directory) / 'private.log'
            path.write_text('private raw prompt PRIVATE_CANARY\n' + ''.join(
                'DEBUG private_execution_diagnostic ' + json.dumps(record) + '\n' for record in records))
            path.chmod(0o600)
            result = FIX['service_diagnostic'](path)
            self.assertEqual(result['events'], [event])
            self.assertTrue(result['unrecognized_record'])
            self.assertFalse(result['truncated'])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_service_diagnostic_is_bounded_and_requires_owner_only_regular_file(self):
        event = dict(version=1, phase='execution', detail=dict(code='startup_missing_result',
            io_kind='none', exit_code=-1, signal=5, stderr_class='other'))
        line = 'DEBUG private_execution_diagnostic ' + json.dumps(event) + '\n'
        with tempfile.TemporaryDirectory(prefix='qwen-fixture-test-', dir=HERE) as directory:
            path = Path(directory) / 'private.log'
            path.write_text(line * 17)
            path.chmod(0o600)
            result = FIX['service_diagnostic'](path)
            self.assertEqual(len(result['events']), 16)
            self.assertTrue(result['truncated'])
            path.write_text(line + 'PRIVATE_CANARY' * 8192)
            result = FIX['service_diagnostic'](path)
            self.assertEqual(result['events'], [event])
            self.assertTrue(result['truncated'])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                FIX['service_diagnostic'](path)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                FIX['service_diagnostic'](link)

    def test_service_diagnostic_vocabulary_matches_source_and_log_is_not_exported(self):
        source = (HERE.parents[1] / 'crates/volparossa/src/compute/supervise/diagnostic.rs').read_text()
        expected = {'unclassified', 'worker_other', 'startup_missing_result', 'result_observed', 'panic', 'join_cancelled'}
        for name in ('FIXED_CODES', 'WORKER_CODES'):
            array = source.split(f'const {name}: &[&str] = &[', 1)[1].split('];', 1)[0]
            expected.update(re.findall(r'"([A-Za-z_]+)"', array))
        self.assertEqual(FIX['SERVICE_CODES'], expected)
        self.assertNotIn('service.log', FIX['EXPORT_NAMES'])
        fixture = (HERE / 'agent-private-conversation.py').read_text()
        self.assertIn('--setenv=RUST_LOG=off,volparossa::compute::private_diagnostic=debug', fixture)
        self.assertIn('--setenv=NO_COLOR=1', fixture)
        self.assertIn('--property=StandardOutput=append:{diagnostic_log}', fixture)
        self.assertIn('--property=StandardError=append:{diagnostic_log}', fixture)

    def test_current_pins_and_offline_receipt_contract(self):
        self.assertEqual(FIX['pins']()['revision'], 'fd8513aff6e9322a488570618396ed8a81fcfb12')
        FIX['check_report'](example_receipt(), REVISION)

    def test_missing_real_turn_or_wrong_source_is_rejected(self):
        for key, change in (('source_revision', 'b' * 40), ('success', False), ('phase', 'turn-2-result')):
            value = example_receipt()
            value[key] = change
            with self.subTest(key=key), self.assertRaises(ValueError):
                FIX['check_report'](value, REVISION)
        for key in ('model_turns', 'literal_canary_present', 'correlated_tool_result_consumed'):
            value = example_receipt()
            value['client'][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                FIX['check_report'](value, REVISION)

    def test_cleanup_memory_and_false_scope_claims_rejected(self):
        mutations = [('cleanup', 'observer_group_joined', False), ('cleanup', 'provision_group_joined', False),
            ('memory_before', 'admission_headroom_bytes', 4 * FIX['GIB']),
            ('memory_after_1', 'memory_max_bytes', 4 * FIX['GIB']), ('memory_after_2', 'oom_kill', 1),
            ('client', 'codex_app_server_proven', True), ('tool', 'command_execution', True),
            ('tool', 'canary_absent_from_first_input', False), ('turn_2', 'turn_complete', False)]
        for section, key, change in mutations:
            value = example_receipt()
            value[section][key] = change
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                FIX['check_report'](value, REVISION)
        for key in ('hard_4gib_proven', 'general_coding_quality_proven', 'raw_model_output_exported'):
            value = example_receipt()
            value[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                FIX['check_report'](value, REVISION)

    def test_result_summary_strips_content_and_preserves_incomplete(self):
        value = dict(version=1, operation='compute_private_conversation', model_profile=FIX['PROFILE'],
            execution_complete=True, turn_complete=False, local_only=True, private_data_supported=True,
            tool_execution=False, model_answer_correctness_proven=False, distributed_execution_claimed=False,
            private_training_claimed=False, cleanup=dict(complete=True, retained_input=False, retained_report=False),
            prompt_tokens=100, generated_tokens=1024, output=dict(type='incomplete', reason='token_limit'))
        summary = FIX['result_summary'](value)
        self.assertEqual(summary['incomplete_reason'], 'token_limit')
        self.assertFalse(summary['turn_complete'])
        value['turn_complete'] = True
        with self.assertRaises(ValueError):
            FIX['result_summary'](value)
        value['turn_complete'] = True
        value['output'] = dict(type='assistant', text='synthetic private answer')
        self.assertNotIn('synthetic', str(FIX['result_summary'](value)))

    def test_archive_allows_only_hash_checked_runtime_entries(self):
        contents = {'bin/node': b'not an executable', 'LICENSE': b'synthetic license'}
        expected = {name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()) for name, data in contents.items()}
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            for name, data in contents.items():
                item = tarfile.TarInfo('node-v24.19.0-linux-x64/' + name)
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        raw.seek(0)
        with tempfile.TemporaryDirectory(prefix='qwen-fixture-test-', dir=HERE) as directory:
            with tarfile.open(fileobj=raw) as archive:
                FIX['extract_node'](archive, Path(directory), expected)
            self.assertEqual((Path(directory) / 'bin/node').read_bytes(), contents['bin/node'])

    def test_archive_rejects_traversal_symlink_and_wrong_hash(self):
        for name, kind, content in [('node-v24.19.0-linux-x64/../evil', tarfile.REGTYPE, b'x'),
            ('node-v24.19.0-linux-x64/bin/node', tarfile.SYMTYPE, b''),
            ('node-v24.19.0-linux-x64/bin/node', tarfile.REGTYPE, b'x')]:
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as archive:
                item = tarfile.TarInfo(name)
                item.size, item.type, item.linkname = len(content), kind, '/etc/passwd'
                archive.addfile(item, io.BytesIO(content))
            raw.seek(0)
            with tempfile.TemporaryDirectory(prefix='qwen-fixture-test-', dir=HERE) as directory:
                with tarfile.open(fileobj=raw) as archive, self.assertRaises(ValueError):
                    FIX['extract_node'](archive, Path(directory), {'bin/node': dict(bytes=1, sha256='0' * 64)})

    def test_preview_has_no_runtime_and_execute_requires_explicit_guest(self):
        script = HERE / 'agent-private-conversation.sh'
        result = subprocess.run(['sh', str(script), '--preview'], capture_output=True, text=True, timeout=5, check=True)
        self.assertIn('PREVIEW ONLY', result.stdout)
        self.assertIn('MemoryMax5GiB', result.stdout)
        result = subprocess.run(['sh', str(script), '--execute'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 64)

    def test_vm_dispatch_preserves_other_scenarios_and_resource_bounds(self):
        runner = HERE / 'run-alpha-topology-vm.sh'
        for selected, expected, rejected in (
            (['agent-private-conversation'], 'Private-conversation:', 'Private-code:'),
            (['agent-private-code', 'agent-private-conversation'], 'Private-conversation:', 'Private-code:'),
            (['agent-private-conversation', 'agent-private-code'], 'Private-code:', 'Private-conversation:')):
            arguments = ['sh', str(runner), '--preview']
            for scenario in selected:
                arguments.extend(['--scenario', scenario])
            result = subprocess.run(arguments, capture_output=True, text=True, timeout=5, check=True)
            self.assertIn(expected, result.stdout)
            self.assertNotIn(rejected, result.stdout)
            if selected[-1] == 'agent-private-conversation':
                self.assertIn('Guest resources: 4 vCPUs, 8192 MiB RAM;', result.stdout)
        source = runner.read_text()
        self.assertIn('[ "$scenario" != agent-private-conversation ] || driver_time_bound=3900s', source)
        guest = source.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split('\nGUEST_DRIVER_SCRIPT\n', 1)[0]
        self.assertLess(guest.index('if [ "$scenario" = agent-private-conversation ]; then'),
                        guest.index("printf '%s  volparossa-mpquic\\n'"))
        self.assertIn('exec sh tests/integration/agent-private-conversation.sh --execute --yes --expected-commit "$expected_commit"', guest)
        workflow = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
        self.assertIn('          - agent-private-conversation\n', workflow)
        self.assertIn("if: always() && env.VOLPAROSSA_ALPHA_SCENARIO == 'agent-private-conversation'", workflow)
        self.assertIn('agent-private-conversation.py report "$report" "$GITHUB_SHA"', workflow)
        self.assertIn('python3 -B tests/integration/test-agent-private-conversation.py', workflow)
        self.assertEqual(workflow.count("env.VOLPAROSSA_ALPHA_SCENARIO != 'agent-private-conversation'"), 4)
        self.assertIn('test "$VOLPAROSSA_ALPHA_SCENARIO" != agent-private-conversation &&', workflow)
        upload = workflow.split('      - name: Upload only closed private conversation evidence\n', 1)[1].split('\n      - name:', 1)[0]
        paths = [line.strip().split(' }}/', 1)[1] for line in upload.splitlines() if '${{ env.VOLPAROSSA_ALPHA_OUTPUT }}/' in line]
        expected = FIX['EXPORT_NAMES'] | {f'published/{name}' for name in FIX['EXPORT_NAMES']} | {
            'vm-console.log', 'vm-incomplete.json', 'vm-diagnostics.log', 'vm-diagnostics.stderr',
            'driver/guest-phase.txt', 'driver/cargo-build.log'}
        self.assertEqual(set(paths), expected)
        self.assertEqual(len(paths), len(expected))

    def test_failure_collector_exports_only_closed_conversation_artifacts(self):
        source = (HERE / 'run-alpha-topology-vm.sh').read_text()
        code = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split('\nGUEST_DIAGNOSTICS_PYTHON\n', 1)[0]
        namespace = {'__name__': 'offline_conversation_collector_test'}
        exec(compile(code, 'bounded_guest_diagnostics', 'exec'), namespace)
        with tempfile.TemporaryDirectory(prefix='qwen-fixture-test-', dir=HERE) as directory:
            root = Path(directory)
            home = root / 'home'
            published = home / 'alpha-output'
            published.mkdir(parents=True)
            for name in FIX['EXPORT_NAMES']:
                (published / name).write_text('{}\n')
            for name in ('input-1.json', 'result-2.json', 'fixture.js', 'client.log', 'content-private.json',
                         'agent-private-conversation-request.json', 'identity.key'):
                (published / name).write_text('PRIVATE_SENTINEL\n')
            private = home / 'private-conversation'
            private.mkdir()
            (private / 'result-1.json').write_text('PRIVATE_SENTINEL\n')
            archive = namespace['collect'](home, root / 'no-opt', REVISION, 'agent-private-conversation', 124,
                                           root / 'no-cgroups', root / 'no-proc')
            with tarfile.open(archive) as bundle:
                self.assertEqual(set(bundle.getnames()), {'vm-incomplete.json'} |
                                 {f'published/{name}' for name in FIX['EXPORT_NAMES']})
                for item in bundle.getmembers():
                    self.assertNotIn(b'PRIVATE_SENTINEL', bundle.extractfile(item).read())


if __name__ == '__main__':
    unittest.main()
