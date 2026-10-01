#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real native Codex/core read-edit-test trial, restricted to the disposable guest."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('native_coding_private_service', HERE / 'agent-private-conversation.py')
PRIVATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PRIVATE)
TRAIN = PRIVATE.TRAIN
read, write, require, digest = PRIVATE.read, PRIVATE.write, PRIVATE.require, PRIVATE.digest
ROOT = Path('/home/vpci/native-coding')
OUTPUT = Path('/home/vpci/alpha-output')
CODE = Path('/home/vpci/code')
RUNTIME = Path('/opt/volparossa-codex-runtime')
PINS = HERE / 'agent-native-coding-pins.json'
UNIT = 'volparossa-native-coding.service'
PRIVATE.ROOT, PRIVATE.UNIT = ROOT, UNIT
PRIVATE.CGROUP = Path('/sys/fs/cgroup/system.slice') / UNIT
GIB, MEMORY_MAX, PROFILE = PRIVATE.GIB, PRIVATE.MEMORY_MAX, PRIVATE.PROFILE
UPSTREAM = '67727e7cf114cf3e1b71db368d74b24e32f6cb12'
CODE_TREE = '60ddc9be734aa17bc95464cda8d81dc50e39cb6a'
TOOLCHAIN_SHA = 'f994b853cae209236bd522735903f66a4a01f5cc8c04632d36aa45449ca367ac'
PROMPT_SHA = 'ac8ae107a0d72fe3476b430afb161ea4e67da2e446d778aefc44828160559807'
APPROVAL_DENIALS = {'lineage', 'kind', 'item', 'cwd', 'command', 'network',
                   'permissions', 'network_policy', 'order', 'budget'}
SCOPE = ('actual pinned native Codex app-server, full upstream prompt and private Qwen3-0.6B '
         'performing an owner-authorized synthetic read/edit/test loop; not general coding '
         'quality, editor integration, private peer execution or a hard-4GiB proof')
SOURCE_NAMES = {'src/app-server.cjs', 'src/private-compute.cjs', 'src/private-conversation.cjs',
    'src/responses-provider.cjs', 'src/native-coding-fixture.cjs', 'scripts/smoke_native_coding.py',
    'scripts/smoke_native_coding.cjs', 'scripts/native_coding_fixture.py',
    'third_party/codex-runtime.json', 'LICENSE'}
FIXTURE_NAMES = ('agent-native-coding.py', 'agent-native-coding.sh', 'agent-native-coding-pins.json',
                 'agent-private-conversation.py', 'agent-training-smoke.py')
EXPORT_NAMES = {'agent-native-coding-smoke.json', 'host-state-before.json', 'host-state-after.json',
                'current-phase', 'guest-exit-status', 'runner.stdout', 'runner.stderr'}


def pins():
    value = read(PINS, 16384)
    require(set(value) == {'version', 'repository', 'revision', 'files'} and value['version'] == 1
            and value['repository'] == 'https://github.com/VOLPAROSSA/volparossa-code'
            and re.fullmatch('[0-9a-f]{40}', value['revision']) and set(value['files']) == SOURCE_NAMES,
            'native Code source pin')
    for item in value['files'].values():
        require(set(item) == {'bytes', 'sha256'} and type(item['bytes']) is int
                and 0 < item['bytes'] <= 262144 and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'source file pin')
    return value


def verify_code(value):
    require(CODE.resolve(strict=True) == CODE and CODE.is_dir(), 'Code root')
    for name, pin in value['files'].items():
        target = CODE / name
        info = target.lstat()
        require(target.resolve(strict=True) == target and stat.S_ISREG(info.st_mode)
                and not info.st_mode & 0o6022 and info.st_nlink == 1
                and info.st_size == pin['bytes'] and digest(target) == pin['sha256'], 'Code file identity')


def verify_runtime(value):
    """Execute no runtime: verify the source-built receipt and exact binary first."""
    verify_code(value)
    harness = runpy.run_path(str(CODE / 'scripts/smoke_native_coding.py'))
    binary = RUNTIME / 'runtime/codex-app-server'
    info = binary.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 1024**3, 'runtime binary bound')
    binary_hash = digest(binary)
    harness['verified_file'](str(binary), binary_hash, executable=True)
    provenance = harness['verified_build'](str(RUNTIME / 'BUILD_REPORT.json'), binary, binary_hash)
    prompt = harness['verified_file'](str(RUNTIME / 'prompt.md'), PROMPT_SHA)
    require(prompt.stat().st_size == 20903 and provenance['source_revision'] == UPSTREAM, 'native prompt')
    return dict(binary_sha256=binary_hash, binary_bytes=info.st_size,
                prompt_sha256=PROMPT_SHA, prompt_bytes=20903, provenance=provenance)


def bundle_summary(value, revision, runtime, source_pins):
    """Bind the explicit runner source-build receipt; never re-export its inventory."""
    keys = {'version', 'kind', 'core_revision', 'code_revision', 'code_tree', 'codex_revision',
        'codex_tree', 'toolchain_report_sha256', 'binary_sha256', 'build_report_sha256',
        'prompt_sha256', 'source_build', 'existing_binary_reused', 'bit_reproducibility_proven',
        'app_server_executed', 'files'}
    require(isinstance(value, dict) and set(value) == keys and value['version'] == 1
        and value['kind'] == 'volparossa-native-coding-runtime-bundle'
        and value['core_revision'] == revision and value['code_revision'] == source_pins['revision']
        and value['code_tree'] == CODE_TREE and value['codex_revision'] == UPSTREAM
        and value['codex_tree'] == runtime['provenance']['source_tree']
        and value['toolchain_report_sha256'] == TOOLCHAIN_SHA
        and value['binary_sha256'] == runtime['binary_sha256']
        and value['build_report_sha256'] == runtime['provenance']['report_sha256']
        and value['prompt_sha256'] == PROMPT_SHA and value['source_build'] is True
        and value['existing_binary_reused'] is False and value['bit_reproducibility_proven'] is False
        and value['app_server_executed'] is False, 'source-built bundle binding')
    files = value['files']
    require(isinstance(files, dict) and len(files) <= 10000, 'bundle inventory bound')
    expected = {f'code/{name}': pin for name, pin in source_pins['files'].items()}
    expected.update({'runtime/runtime/codex-app-server': dict(bytes=runtime['binary_bytes'], sha256=runtime['binary_sha256']),
                     'runtime/prompt.md': dict(bytes=20903, sha256=PROMPT_SHA)})
    for name, pin in expected.items():
        record = files.get(name)
        require(isinstance(record, dict) and set(record) == {'bytes', 'sha256', 'mode'}
            and {key: record[key] for key in ('bytes', 'sha256')} == pin
            and type(record['mode']) is int and 0 < record['mode'] <= 0o777
            and not record['mode'] & 0o222, 'bundle source inventory')
    return {key: value[key] for key in keys - {'files', 'version', 'kind'}}


def verify_bundle(revision, runtime, source_pins):
    target = RUNTIME / 'NATIVE_RUNTIME_BUNDLE.json'
    summary = bundle_summary(read(target, 4 * 1024**2), revision, runtime, source_pins)
    require(digest(RUNTIME / 'TOOLCHAIN_REPORT.json') == TOOLCHAIN_SHA, 'compiler receipt identity')
    built = read(RUNTIME / 'BUILD_REPORT.json', 65536)
    require(built['rust_version'] == '1.98.1' and built['toolchain_report_sha256'] == TOOLCHAIN_SHA
        and built['app_server_executed'] is False and built['global_installation'] is False,
        'reviewed source-build compiler')
    return dict(sha256=digest(target), **summary)


def model_provenance():
    provisioner = runpy.run_path(str(PRIVATE.ML / 'provision.py'))
    model = provisioner['load_pins'](PROFILE)
    model_bytes, requirements = provisioner['retained_pin_files'](model)
    return dict(model_id=model['model_id'], revision=model['revision'], model_profile=PROFILE,
        download_bytes=provisioner['download_total'](model), budget_bytes=5 * GIB, installed_wheels=38,
        model_pins_sha256=hashlib.sha256(model_bytes).hexdigest(),
        requirements_sha256=hashlib.sha256(requirements).hexdigest())


def check_native_diagnostics(value):
    for key in ('turns_started', 'turns_completed'):
        require(type(value[key]) is int and 0 <= value[key] <= 2, 'receipt-turn-count')
    require(value['turns_completed'] <= value['turns_started'], 'receipt-turn-order')
    counts = value['item_types']
    require(type(counts) is dict and set(counts) == {'commandExecution', 'agentMessage', 'userMessage', 'reasoning', 'other'}
            and all(type(n) is int and 0 <= n <= 64 for n in counts.values())
            and sum(counts.values()) <= 64, 'receipt-item-counts')
    diagnostic = value['response_diagnostics']
    if diagnostic is None:
        require(value['responses'] is None, 'receipt-diagnostics-missing')
        return
    require(type(diagnostic) is dict and set(diagnostic) == {'version', 'records', 'truncated'}
            and type(diagnostic['version']) is int and diagnostic['version'] == 1
            and type(diagnostic['truncated']) is bool and type(diagnostic['records']) is list
            and len(diagnostic['records']) <= 16, 'receipt-response-diagnostics')
    for row in diagnostic['records']:
        require(type(row) is dict and set(row) == {'output_kind', 'prompt_tokens', 'generated_tokens',
                'turn_complete', 'incomplete_reason', 'elapsed_ms'}
                and row['output_kind'] in ('assistant', 'function_call', 'custom_tool_call', 'incomplete')
                and type(row['turn_complete']) is bool
                and row['turn_complete'] == (row['output_kind'] != 'incomplete')
                and (row['incomplete_reason'] is None if row['turn_complete'] else
                     row['incomplete_reason'] in ('token_limit', 'wire_truncated', 'invalid_output')),
                'receipt-response-shape')
        for key, minimum, maximum in (('prompt_tokens', 1, 12288), ('generated_tokens', 1, 1024),
                                      ('elapsed_ms', 0, 3600000)):
            require(type(row[key]) is int and minimum <= row[key] <= maximum, 'receipt-response-bound')
    counters = value['responses']
    require(counters is not None and len(diagnostic['records']) == min(16, counters['cleanup_confirmed'])
            and diagnostic['truncated'] == (counters['cleanup_confirmed'] > 16), 'receipt-response-coverage')
    if not diagnostic['truncated']:
        require(sum(row['turn_complete'] for row in diagnostic['records']) == counters['completed']
                and sum(not row['turn_complete'] for row in diagnostic['records']) == counters['incomplete'],
                'receipt-response-correlation')


def native_receipt(value):
    """Closed projection only: no prompts, model text, commands or tool contents."""
    booleans = {'success', 'native_turn_completed', 'read', 'edit', 'test', 'independent_test_passed',
        'unexpected_command', 'thread_unsubscribed', 'private_peer_execution_claimed',
        'general_coding_quality_claimed', 'forced_stop'}
    require(isinstance(value, dict) and set(value) == booleans | {'version', 'kind', 'phase', 'model',
        'full_native_prompt_sha256', 'before_sha256', 'after_sha256', 'accepted_commands',
        'declined_commands', 'approval_denials', 'responses', 'runtime_exit', 'diagnostic',
        'turns_started', 'turns_completed', 'item_types', 'response_diagnostics'}, 'native receipt keys')
    require(type(value['version']) is int and value['version'] == 3 and value['kind'] == 'native-codex-core-coding'
        and value['model'] == PROFILE and value['phase'] in ('capabilities', 'launch', 'initialize',
        'thread-start', 'native-turn', 'independent-check', 'unsubscribe', 'complete')
        and value['diagnostic'] in (None, 'stderr_bound', 'turn_deadline', 'native_coding_incomplete',
        'provider_cleanup_unconfirmed') and all(type(value[key]) is bool for key in booleans), 'native receipt values')
    require(value['full_native_prompt_sha256'] == PROMPT_SHA
        and value['before_sha256'] == hashlib.sha256(b'def add(a, b):\n    return a - b\n').hexdigest()
        and (value['after_sha256'] is None or re.fullmatch('[0-9a-f]{64}', value['after_sha256']))
        and not value['private_peer_execution_claimed'] and not value['general_coding_quality_claimed'], 'native scope')
    for key in ('accepted_commands', 'declined_commands'):
        require(type(value[key]) is int and 0 <= value[key] <= 16, 'native command count')
    denials = value['approval_denials']
    require(isinstance(denials, dict) and set(denials) == APPROVAL_DENIALS
        and all(type(count) is int and 0 <= count <= 16 for count in denials.values())
        and sum(denials.values()) == value['declined_commands'], 'native approval denial counts')
    require(value['runtime_exit'] is None or type(value['runtime_exit']) is int
            and -255 <= value['runtime_exit'] <= 255, 'runtime exit')
    counters = value['responses']
    require(counters is None or isinstance(counters, dict)
        and set(counters) == {'submitted', 'completed', 'incomplete', 'cleanup_confirmed'}
        and all(type(count) is int and 0 <= count <= 32 for count in counters.values()), 'response counters')
    check_native_diagnostics(value)
    if value['success']:
        require(all(value[key] for key in ('native_turn_completed', 'read', 'edit', 'test',
            'independent_test_passed', 'thread_unsubscribed')) and value['phase'] == 'complete'
            and value['runtime_exit'] == 0 and not value['unexpected_command'] and not value['forced_stop']
            and value['diagnostic'] is None and value['after_sha256'] not in (None, value['before_sha256'])
            and counters is not None and counters['completed'] >= 4 and counters['incomplete'] == 0
            and counters['submitted'] == counters['completed'] == counters['cleanup_confirmed'], 'native loop unproven')
        require(1 <= value['turns_started'] == value['turns_completed'] <= 2
                and value['response_diagnostics']['truncated'] is False
                and value['item_types']['commandExecution'] >= 3, 'native task unproven')
    return value


def service_cpu_usage():
    """Only a fixed cgroup counter, never process arguments or workload content."""
    with (PRIVATE.CGROUP / 'cpu.stat').open('rb') as stream:
        raw = stream.read(4097)
    require(len(raw) <= 4096, 'CPU accounting size')
    values = [line.split()[1] for line in raw.splitlines()
              if len(line.split()) == 2 and line.split()[0] == b'usage_usec']
    require(len(values) == 1 and re.fullmatch(rb'[0-9]{1,18}', values[0]), 'CPU accounting counter')
    return int(values[0])


def check_execution_timing(value):
    require(isinstance(value, dict) and set(value) == {'version', 'scope', 'elapsed_ms', 'cpu_usage_usec'}
        and type(value['version']) is int and value['version'] == 1
        and value['scope'] == 'service_cgroup_during_native_harness'
        and type(value['elapsed_ms']) is int and 0 <= value['elapsed_ms'] <= 3600000
        and type(value['cpu_usage_usec']) is int and 0 <= value['cpu_usage_usec'] <= 128 * 3600 * 1000000,
        'execution timing')
    return value


def execution_timing(started, cpu_before):
    # This includes the service and all its worker descendants across the native
    # harness, not the separate Codex process and not a per-inference diagnosis.
    return check_execution_timing(dict(version=1, scope='service_cgroup_during_native_harness',
        elapsed_ms=int((time.monotonic() - started) * 1000),
        cpu_usage_usec=service_cpu_usage() - cpu_before))


def check_report(value, revision):
    require(value['report_kind'] == 'volparossa-agent-native-coding' and value['proof_version'] == 1
        and re.fullmatch('[0-9a-f]{40}', revision) and value['source_revision'] == revision
        and value['scope'] == SCOPE and value['success'] is True and value['phase'] == 'complete', 'proof incomplete')
    require(value['code_provision'] == pins() and value['node_provision'] == PRIVATE.pins()['runtime']
        and value['provision'] == model_provenance() and value['inputs_unchanged'] is True
        and value['service_clean_stop'] is True and not value.get('diagnostic_invalid'), 'provision or lifecycle')
    require(all(value[key] is False for key in ('raw_input_exported', 'raw_model_output_exported',
        'general_coding_quality_proven', 'private_peer_execution_proven', 'hard_4gib_proven')), 'unsupported claim')
    require(value['codex_app_server_proven'] is True and value['code_edit_test_loop_proven'] is True
        and native_receipt(value['native'])['success'] is True, 'native proof missing')
    runtime = value['runtime']
    require(set(runtime) == {'binary_sha256', 'binary_bytes', 'prompt_sha256', 'prompt_bytes', 'provenance'}
        and re.fullmatch('[0-9a-f]{64}', runtime['binary_sha256']) and type(runtime['binary_bytes']) is int
        and 0 < runtime['binary_bytes'] <= 1024**3 and runtime['prompt_sha256'] == PROMPT_SHA
        and runtime['prompt_bytes'] == 20903, 'runtime identity')
    provenance = runtime['provenance']
    require(provenance['source_revision'] == UPSTREAM
        and provenance['source_tree'] == 'ea880e9a6ce9277531a9ab88be06f40a7ddf7b6f'
        and provenance['lock_sha256'] == '571137c35517878869d5dca7ca5df5fa0b3e596e0466ad7b8c100041c6ce75b8'
        and re.fullmatch('[0-9a-f]{64}', provenance['report_sha256']), 'runtime source identity')
    bundle = value['runtime_bundle']
    require(set(bundle) == {'sha256', 'core_revision', 'code_revision', 'code_tree', 'codex_revision',
        'codex_tree', 'toolchain_report_sha256', 'binary_sha256', 'build_report_sha256', 'prompt_sha256',
        'source_build', 'existing_binary_reused', 'bit_reproducibility_proven', 'app_server_executed'}
        and re.fullmatch('[0-9a-f]{64}', bundle['sha256']) and bundle['core_revision'] == revision
        and bundle['code_revision'] == pins()['revision'] and bundle['code_tree'] == CODE_TREE
        and bundle['codex_revision'] == UPSTREAM and bundle['codex_tree'] == provenance['source_tree']
        and bundle['toolchain_report_sha256'] == TOOLCHAIN_SHA
        and bundle['binary_sha256'] == runtime['binary_sha256']
        and bundle['build_report_sha256'] == provenance['report_sha256'] and bundle['prompt_sha256'] == PROMPT_SHA
        and bundle['source_build'] is True and bundle['existing_binary_reused'] is False
        and bundle['bit_reproducibility_proven'] is False and bundle['app_server_executed'] is False,
        'runtime bundle identity')
    for name in ('memory_before', 'memory_final'):
        memory = value[name]
        require(memory['memory_max_bytes'] == MEMORY_MAX and memory['swap_max_bytes'] == 0
            and memory['oom'] == memory['oom_kill'] == 0
            and 0 <= memory['current_bytes'] <= memory['peak_bytes'] <= MEMORY_MAX
            and memory['admission_headroom_bytes'] == MEMORY_MAX - memory['current_bytes'], 'service memory')
    require(value['memory_before']['admission_headroom_bytes'] >= 9 * GIB // 2, 'admission headroom')
    check_execution_timing(value['execution_timing'])
    require(value['native_cleanup'] == dict(process_joined=True, private_state_removed=True, host_network_unchanged=True)
        and value['cleanup'] == dict(client_group_joined=True, provision_group_joined=True, service_stopped=True,
            service_cgroup_empty=True, observed_lifetimes_ended=True, guest_root_removed=True, code_output_removed=True)
        and value['host_state_unchanged'] is True
        and value['host_state_hashes']['before'] == value['host_state_hashes']['after'], 'cleanup proof')
    require(value['fixture_hashes'] == {name: digest(HERE / name) for name in FIXTURE_NAMES}, 'fixture provenance')


def check_bundle(path, revision):
    value = read(path)
    check_report(value, revision)
    for when in ('before', 'after'):
        require(digest(path.parent / f'host-state-{when}.json') == value['host_state_hashes'][when], 'host snapshot identity')
    for entry in path.parent.iterdir():
        info = entry.lstat()
        require(entry.name in EXPORT_NAMES | {'vm-console.log'} and stat.S_ISREG(info.st_mode)
            and info.st_size <= (16 * 1024**2 if entry.name == 'vm-console.log' else 262144), 'unexpected export')


def service_cgroup_empty():
    path = PRIVATE.CGROUP
    return not path.exists() or all(not file.read_text().strip() for file in path.rglob('cgroup.procs'))


def execute(output, revision):
    PRIVATE.guard()
    require(output == OUTPUT and re.fullmatch('[0-9a-f]{40}', revision), 'exact invocation')
    require(not ROOT.exists() and not ROOT.is_symlink() and PRIVATE.properties()['LoadState'] == 'not-found', 'existing fixture')
    available = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    require(int(available['MemAvailable'].split()[0]) * 1024 >= 6 * GIB, 'guest memory preflight')
    value = pins()
    native_output = CODE / 'build/native-coding-01'
    require(not native_output.exists() and not native_output.is_symlink(), 'existing native output')
    before = TRAIN['snapshot']()
    write(output / 'host-state-before.json', before)
    result = dict(report_kind='volparossa-agent-native-coding', proof_version=1, source_revision=revision,
        scope=SCOPE, success=False, phase='guard', code_provision=value, node_provision=PRIVATE.pins()['runtime'],
        raw_input_exported=False, raw_model_output_exported=False, codex_app_server_proven=False,
        code_edit_test_loop_proven=False, general_coding_quality_proven=False,
        private_peer_execution_proven=False, hard_4gib_proven=False)
    ROOT.mkdir(mode=0o700)
    (ROOT / 'work').mkdir(mode=0o700)
    process, provision_process, service_created, members = None, None, False, {}
    native_started, cpu_before = None, None
    try:
        result['phase'] = 'runtime-verification'
        result['runtime'] = verify_runtime(value)
        result['runtime_bundle'] = verify_bundle(revision, result['runtime'], value)
        require(shutil.disk_usage(ROOT).free >= 6 * GIB, 'disk preflight')
        require((CODE / 'build').is_dir() and (CODE / 'build').resolve(strict=True) == CODE / 'build', 'Code build root')
        result['phase'] = 'node-provision'
        node = result['node_provision']
        PRIVATE.fetch(node['url'], ROOT / 'node.tar.xz', node)
        with tarfile.open(ROOT / 'node.tar.xz', 'r:xz') as archive:
            PRIVATE.extract_node(archive, ROOT / 'runtime', node['files'])
        result['phase'] = 'model-provision'
        with (ROOT / 'provision.log').open('xb') as log:
            provision_process = subprocess.Popen([sys.executable, '-B', str(PRIVATE.ML / 'provision.py'),
                '--execute', '--yes', '--disposable-guest', '--model-profile', PROFILE,
                '--root', str(ROOT / 'ml'), '--budget-bytes', str(5 * GIB)],
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            require(provision_process.wait(timeout=1850) == 0, 'model provision failed')
        provision = read(ROOT / 'ml/provision-report.json')
        expected = model_provenance()
        require(provision['success'] is True and provision['training_performed'] is False
            and provision['runtime_autofetch_enabled'] is False
            and {key: provision[key] for key in expected} == expected, 'model provision identity')
        result['provision'] = expected
        result['phase'] = 'service-start'
        log = ROOT / 'service.log'
        log.touch(mode=0o600, exist_ok=False)
        command = [str(PRIVATE.CLI), 'compute', 'private-serve', '--socket', str(ROOT / 'private.sock'),
            '--work-parent', str(ROOT / 'work'), '--runtime-root', str(ROOT / 'ml/venv'),
            '--model-root', str(ROOT / 'ml/model'), '--model-profile', PROFILE,
            '--threads', '2', '--max-seconds', '600', '--execute']
        service_created = True
        subprocess.run(['sudo', '-n', 'systemd-run', '--quiet', f'--unit={UNIT}',
            '--property=Type=exec', '--property=RemainAfterExit=yes', '--property=User=vpci', '--property=Group=vpci',
            '--property=WorkingDirectory=/home/vpci/source', f'--property=MemoryMax={MEMORY_MAX}',
            '--property=MemorySwapMax=0', '--property=TasksMax=128', '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=2700', '--property=TimeoutStopSec=10',
            '--property=NoNewPrivileges=yes', '--property=PrivateNetwork=yes',
            '--setenv=RUST_LOG=off,volparossa::compute::private_diagnostic=debug', '--setenv=NO_COLOR=1',
            f'--property=StandardOutput=append:{log}', f'--property=StandardError=append:{log}', *command],
            capture_output=True, check=True, timeout=15)
        for _ in range(100):
            if (ROOT / 'private.sock').exists():
                break
            time.sleep(0.1)
        info = PRIVATE.properties()
        pid = int(info['MainPID'])
        require(pid > 0 and info['ActiveState'] == 'active'
            and info['ControlGroup'] == '/system.slice/' + UNIT, 'service launch')
        member = TRAIN['identity'](pid)
        members[(pid, member['start_ticks'])] = member
        result['memory_before'] = PRIVATE.memory()
        require(result['memory_before']['admission_headroom_bytes'] >= 9 * GIB // 2, 'service headroom')
        result['phase'] = 'native-coding'
        launch = [sys.executable, '-B', str(CODE / 'scripts/smoke_native_coding.py'),
            '--app-server', str(RUNTIME / 'runtime/codex-app-server'),
            '--app-server-sha256', result['runtime']['binary_sha256'],
            '--build-report', str(RUNTIME / 'BUILD_REPORT.json'),
            '--node', str(ROOT / 'runtime/bin/node'), '--node-sha256', node['files']['bin/node']['sha256'],
            '--upstream-prompt', str(RUNTIME / 'prompt.md'), '--socket', str(ROOT / 'private.sock'),
            '--output', str(native_output), '--execute', '--yes']
        with (ROOT / 'client.log').open('xb') as diagnostics:
            cpu_before = service_cpu_usage()
            native_started = time.monotonic()
            process = subprocess.Popen(launch, stdout=diagnostics, stderr=diagnostics, start_new_session=True)
            deadline = time.monotonic() + 2530
            while process.poll() is None:
                require(time.monotonic() < deadline, 'native harness deadline')
                for member in TRAIN['descendants'](pid):
                    members[(member['pid'], member['start_ticks'])] = member
                require(len(members) <= 1024, 'observed lifetime bound')
                time.sleep(0.25)
        result['execution_timing'] = execution_timing(native_started, cpu_before)
        report = read(native_output / 'report.json', 65536)
        if 'observed' in report:
            result['native'] = native_receipt(report['observed'])
        result['native_cleanup'] = report.get('cleanup')
        require(process.returncode == 0 and report['success'] is True and result['native']['success'] is True
            and report['runtime_provenance'] == result['runtime']['provenance']
            and result['native_cleanup'] == dict(process_joined=True, private_state_removed=True, host_network_unchanged=True),
            'native coding incomplete')
        require(not list((ROOT / 'work').iterdir()), 'private work remains')
        verify_code(value)
        require(verify_runtime(value) == result['runtime'], 'runtime changed')
        require(verify_bundle(revision, result['runtime'], value) == result['runtime_bundle'], 'bundle changed')
        result['inputs_unchanged'] = True
        result['memory_final'] = PRIVATE.memory()
        result['phase'] = 'service-stop'
        PRIVATE.unit('kill', '--kill-whom=main', '--signal=SIGINT')
        for _ in range(100):
            info = PRIVATE.properties()
            if info.get('MainPID') == '0':
                break
            time.sleep(0.1)
        require(info['ActiveState'] == 'active' and info['SubState'] == 'exited' and info['Result'] == 'success'
            and info['ExecMainStatus'] == '0' and not (ROOT / 'private.sock').exists(), 'service clean stop')
        result['service_clean_stop'] = True
        result['codex_app_server_proven'] = result['code_edit_test_loop_proven'] = True
        result['phase'] = 'complete'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result['failure_code'] = 'phase_failed'
    finally:
        try:
            result['client_launcher'] = PRIVATE.closed_log(ROOT / 'client.log')
            if PRIVATE.CGROUP.exists():
                result['memory_final'] = PRIVATE.memory()
                if native_started is not None and 'execution_timing' not in result:
                    result['execution_timing'] = execution_timing(native_started, cpu_before)
        except (OSError, ValueError, KeyError, TypeError):
            result['diagnostic_invalid'] = True
        client_joined = PRIVATE.stop_client(process)
        provision_joined = PRIVATE.stop_client(provision_process)
        service_stopped = not service_created
        if service_created:
            PRIVATE.unit('stop', check=False)
            info = PRIVATE.properties()
            service_stopped = info['LoadState'] == 'not-found' or info.get('ActiveState') in ('inactive', 'failed')
            PRIVATE.unit('reset-failed', check=False)
        empty = service_cgroup_empty()
        try:
            result['service_diagnostic'] = PRIVATE.service_diagnostic(ROOT / 'service.log')
        except (OSError, ValueError, KeyError, TypeError):
            result['diagnostic_invalid'] = True
        alive = any(TRAIN['alive'](member) for member in members.values())
        removed = client_joined and provision_joined and service_stopped and empty and not alive
        if removed:
            for owned in (ROOT, native_output):
                if owned.exists():
                    require(owned.lstat().st_uid == os.getuid() and stat.S_ISDIR(owned.lstat().st_mode), 'cleanup owner')
                    shutil.rmtree(owned)
        result['cleanup'] = dict(client_group_joined=client_joined, provision_group_joined=provision_joined,
            service_stopped=service_stopped, service_cgroup_empty=empty, observed_lifetimes_ended=not alive,
            guest_root_removed=not ROOT.exists(), code_output_removed=not native_output.exists())
        after = TRAIN['snapshot']()
        write(output / 'host-state-after.json', after)
        result['host_state_unchanged'] = before == after
        result['host_state_hashes'] = {when: digest(output / f'host-state-{when}.json') for when in ('before', 'after')}
        result['fixture_hashes'] = {name: digest(HERE / name) for name in FIXTURE_NAMES}
        result['success'] = result['phase'] == 'complete' and removed and before == after
        if result['success']:
            try:
                check_report(result, revision)
            except (OSError, ValueError, KeyError, TypeError):
                result['success'], result['failure_code'] = False, 'proof_validation_failed'
        write(output / 'agent-native-coding-smoke.json', result)
    return 0 if result['success'] else 1


def main():
    if len(sys.argv) == 5 and sys.argv[1] == 'execute' and sys.argv[4] == '--yes':
        return execute(Path(sys.argv[2]), sys.argv[3])
    if len(sys.argv) == 4 and sys.argv[1] == 'report':
        check_bundle(Path(sys.argv[2]), sys.argv[3])
        print('NATIVE_CODE_COMPONENT_PROOF_OK')
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == 'export-names':
        print('\n'.join(sorted(EXPORT_NAMES)))
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == 'failure':
        output, revision, phase = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
        require(output == OUTPUT and re.fullmatch('[0-9a-f]{40}', revision)
            and phase in ('guest-packages', 'cli-build', 'native-coding'), 'failure invocation')
        write(output / 'agent-native-coding-smoke.json', dict(report_kind='volparossa-agent-native-coding',
            proof_version=1, source_revision=revision, scope=SCOPE, success=False, phase=phase,
            failure_code='guest_phase_incomplete', codex_app_server_proven=False, code_edit_test_loop_proven=False))
        return 1
    return 64


if __name__ == '__main__':
    def interrupted(_signal, _frame):
        raise InterruptedError('fixture_interrupted')
    for kind in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(kind, interrupted)
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('native_coding_fixture_failed', file=sys.stderr)
        raise SystemExit(1)
