#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit disposable Qwen tool/result proof; no host inference or invented outputs."""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / 'agent-training-smoke.py'))
read, write, require = TRAIN['read'], TRAIN['write'], TRAIN['require']
ROOT = Path('/home/vpci/private-conversation')
OUTPUT = Path('/home/vpci/alpha-output')
ML = HERE.parent.parent / 'workers/volparossa-ml'
CLI = Path('/home/vpci/target/debug/volparossa')
PINS = HERE / 'agent-private-conversation-pins.json'
UNIT = 'volparossa-qwen-conversation.service'
CGROUP = Path('/sys/fs/cgroup/system.slice') / UNIT
PROFILE = 'qwen3-0.6b-v1'
GIB = 1024**3
MEMORY_MAX = 5 * GIB
# Canonical JSON of the exact published first conversation in the adjacent CJS.
# It contains neither the generated file nor its canary; changing any input
# disables this narrowly authorized diagnostic until the source pin is reviewed.
SYNTHETIC_FIRST_INPUT_SHA256 = 'de16db2f5b500fd6612c751c516546e337e98a6fbf40595f2b7e4b5b8a8de8d5'
SCOPE = ('two actual Qwen3-0.6B private conversation turns through the pinned Code Node client: '
         'a model-selected read_file proposal, one authorized synthetic fixture read, and a correlated '
         'tool-result continuation containing its canary; not Codex app-server, editing/tests, '
         'general coding quality, long-context capacity or a hard-4GiB execution proof')
MODEL = json.loads((ML / 'model-pins-qwen3-0.6b.json').read_text())
PHASES = {'guard', 'provision-client', 'provision-model', 'service-start', 'client-start',
          'turn-1-observe', 'turn-1-result', 'turn-2-observe', 'turn-2-result', 'client-result',
          'service-stop', 'complete'}
CLIENT_PHASES = {'guard', 'connect', 'turn-1-submit', 'turn-1-result', 'tool-check',
                 'turn-2-submit', 'turn-2-result', 'answer-check'}
CLIENT_CODES = {'busy', 'invalid_request', 'handshake_required', 'cancelled', 'execution_failed',
                'execution_budget_exceeded',
                'cleanup_unconfirmed', 'socket_ownership', 'socket_changed', 'socket_unavailable',
                'incompatible_capabilities', 'invalid_response', 'invalid_conversation', 'request_bound',
                'response_bound', 'socket_error', 'disconnected', 'frame_timeout', 'handshake_timeout',
                'not_connected', 'probe_failed'}
SERVICE_PHASES = {'execution', 'capture', 'refresh', 'lifetime', 'reap', 'storage', 'task'}
SERVICE_CODES = {
    'unclassified', 'worker_other', 'startup_missing_result', 'result_observed', 'panic', 'join_cancelled',
    'compute_deadline', 'compute_owner_busy', 'compute_memory_budget', 'compute_storage_budget',
    'compute_process_bound', 'compute_thread_bound', 'compute_process_observation', 'compute_observation_size',
    'compute_private_process_observation', 'compute_private_process_missing', 'compute_private_process_bound',
    'compute_private_process_stat', 'compute_private_process_stat_open', 'compute_private_process_stat_read',
    'compute_private_process_stat_bound', 'compute_private_process_children', 'compute_private_process_cleanup_deadline',
    'compute_private_storage_cleanup_failed', 'compute_reap_deadline', 'compute_reap',
    'compute_request_write_deadline', 'compute_request_write', 'compute_control_write_deadline', 'compute_control_write',
    'compute_control_ack_deadline', 'compute_private_progress',
    'compute_memory_pressure', 'compute_device_reserve', 'compute_owner_pressure', 'compute_pressure_observation',
    'compute_worker_json', 'compute_worker_correlation', 'compute_worker_phase', 'compute_worker_status',
    'compute_worker_kind', 'compute_worker_line_size', 'compute_worker_unterminated_line', 'compute_stdout_size',
    'compute_stderr_size', 'compute_stderr_read', 'compute_wait', 'compute_worker_exit',
    'conversation_request_id', 'conversation_native_marker', 'conversation_native_call',
    'conversation_native_preface', 'conversation_native_json', 'conversation_unknown_tool',
    'conversation_custom_input', 'conversation_arguments', 'conversation_call_id',
    'conversation_empty_answer', 'conversation_native_output_other',
    'JOB_INPUT_NOT_FOUND', 'JOB_PATH_PERMISSION_DENIED', 'JOB_MEMORY_EXHAUSTED', 'BACKEND_IMPORT_FAILED',
    'BACKEND_EXECUTION_FAILED', 'BACKEND_NOT_INSTALLED', 'BACKEND_VERSION_MISMATCH', 'CPU_BACKEND_REQUIRED',
    'MODEL_PARAMETER_DTYPE_MISMATCH', 'MODEL_WEIGHTS_CHANGED_ON_DISK', 'CONVERSATION_TOKENIZER_SHAPE',
    'CONVERSATION_TOKEN_LIMIT', 'RESULT_TOO_LARGE', 'JOB_CANCELLED', 'JOB_DEADLINE_EXCEEDED',
}
SERVICE_IO_KINDS = {'none', 'not_found', 'permission_denied', 'unexpected_eof', 'broken_pipe',
                    'interrupted', 'invalid_data', 'other'}
SERVICE_STDERR_CLASSES = {None, 'none', 'bubblewrap', 'user_namespace', 'proc_mount', 'exec_denied',
                          'python_startup', 'other'}
EXPORT_NAMES = {'agent-private-conversation-smoke.json', 'host-state-before.json', 'host-state-after.json',
                'current-phase', 'guest-exit-status', 'runner.stdout', 'runner.stderr'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pins():
    value = read(PINS, 8192)
    require(value['version'] == 1 and value['repository'] == 'https://github.com/VOLPAROSSA/volparossa-code'
            and value['revision'] == 'fd8513aff6e9322a488570618396ed8a81fcfb12'
            and set(value['files']) == {'src/private-compute.cjs', 'src/private-conversation.cjs', 'LICENSE'}, 'client pin')
    runtime = value['runtime']
    require(runtime['version'] == '24.19.0' and runtime['bytes'] == 31633904
            and runtime['url'] == 'https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.xz'
            and runtime['sha256'] == '14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647'
            and set(runtime['files']) == {'bin/node', 'LICENSE'}, 'runtime pin')
    for item in [*value['files'].values(), *runtime['files'].values()]:
        require(set(item) == {'bytes', 'sha256'} and type(item['bytes']) is int
                and 0 < item['bytes'] <= 160 * 1024**2 and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'file pin')
    return value


def fetch(url, target, pin):
    """Original public assets only, bounded and hash checked before any execution."""
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    deadline = time.monotonic() + 180
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=30) as response, target.open('xb') as output:
        require(response.url == url, 'unapproved redirect')
        count, hashed = 0, hashlib.sha256()
        while block := response.read(min(65536, pin['bytes'] + 1 - count)):
            count += len(block)
            require(count <= pin['bytes'] and time.monotonic() < deadline, 'download bound')
            hashed.update(block)
            output.write(block)
        require(count == pin['bytes'] and hashed.hexdigest() == pin['sha256'], 'download identity')
    target.chmod(0o600)


def extract_node(archive, destination, expected):
    """Same two-entry allowlist as private-code; archive names are never extract targets."""
    seen, selected, expanded = set(), set(), 0
    for member in archive:
        name = member.name.rstrip('/') if member.isdir() else member.name
        path = PurePosixPath(name)
        require(name and not path.is_absolute() and '..' not in path.parts and str(path) == name
                and path.parts[0] == 'node-v24.19.0-linux-x64' and '\\' not in name
                and not any(ord(c) < 32 for c in name) and name not in seen, 'archive path')
        seen.add(name)
        expanded += member.size
        require(len(seen) <= 20000 and member.size >= 0 and expanded <= 512 * 1024**2, 'archive bound')
        relative = str(path.relative_to('node-v24.19.0-linux-x64'))
        if relative not in expected:
            continue
        pin = expected[relative]
        require(member.isfile() and not member.mode & 0o6000 and member.size == pin['bytes'], 'archive entry')
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with archive.extractfile(member) as source, target.open('xb') as output:
            shutil.copyfileobj(source, output, 65536)
        require(target.stat().st_size == pin['bytes'] and digest(target) == pin['sha256'], 'runtime entry hash')
        target.chmod(0o700 if relative == 'bin/node' else 0o600)
        selected.add(relative)
    require(selected == set(expected), 'runtime missing')


def verify_client(value):
    for base, records in ((ROOT, value['files']), (ROOT / 'runtime', value['runtime']['files'])):
        for name, pin in records.items():
            target = base / name
            info = target.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                    and info.st_size == pin['bytes'] and digest(target) == pin['sha256'], 'client changed')


def unit(*arguments, check=True):
    return subprocess.run(['sudo', '-n', 'systemctl', *arguments, UNIT],
                          capture_output=True, text=True, timeout=15, check=check)


def properties():
    value = unit('show', '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,MemoryMax,MemorySwapMax,Result,ExecMainStatus', check=False)
    require(value.returncode in (0, 1) and len(value.stdout) <= 8192, 'unit property bound')
    result = dict(line.split('=', 1) for line in value.stdout.splitlines() if '=' in line)
    require(result.get('LoadState') in ('loaded', 'not-found'), 'unit lookup failed')
    return result


def memory():
    maximum = int((CGROUP / 'memory.max').read_text())
    swap = int((CGROUP / 'memory.swap.max').read_text())
    current = int((CGROUP / 'memory.current').read_text())
    peak = int((CGROUP / 'memory.peak').read_text())
    events = dict(line.split() for line in (CGROUP / 'memory.events').read_text().splitlines())
    require(maximum == MEMORY_MAX and swap == 0 and 0 <= current <= maximum and 0 <= peak <= maximum,
            'memory boundary')
    return dict(memory_max_bytes=maximum, swap_max_bytes=swap, current_bytes=current, peak_bytes=peak,
                admission_headroom_bytes=maximum-current, oom=int(events['oom']), oom_kill=int(events['oom_kill']))


def guard():
    TRAIN['guest_guard']()
    require(os.getuid() == os.geteuid() and os.getuid() != 0
            and Path.cwd() == Path('/home/vpci/source'), 'guest owner')


def observe(pid, turn):
    TRAIN['guest_guard'](root=True)
    require(turn in (1, 2) and ROOT.is_dir(), 'observer target')
    original = read(ROOT / f'input-{turn}.json', 65536)
    work = ROOT / 'work'
    deadline = time.monotonic() + 10
    candidate = None
    while time.monotonic() < deadline:
        directories = list(work.iterdir())
        require(len(directories) <= 1, 'observer work bound')
        if directories:
            directory = directories[0]
            require(directory.name.startswith('private-task-') and directory.is_dir() and not directory.is_symlink(),
                    'observer snapshot directory')
            candidate = directory / 'input.json'
            if candidate.exists():
                break
        time.sleep(0.05)
    require(candidate is not None and candidate.is_file(), 'snapshot not observed')
    info = candidate.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT.stat().st_uid != 0
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
            and stat.S_IMODE(candidate.parent.stat().st_mode) == 0o700
            and read(candidate, 65536) == original, 'snapshot binding')
    TRAIN['observe'](pid, ROOT / f'isolation-{turn}.json', ROOT / 'ml', candidate, ROOT / 'fixture.js')


def wait_file(name, process, seconds):
    deadline = time.monotonic() + seconds
    target = ROOT / name
    while not target.exists():
        require(process.poll() is None and time.monotonic() < deadline, 'client deadline or exit')
        time.sleep(0.05)
    return target


def result_summary(value):
    require(value['version'] == 1 and value['operation'] == 'compute_private_conversation'
            and value['model_profile'] == PROFILE and value['execution_complete'] is True
            and value['local_only'] is True and value['private_data_supported'] is True
            and value['tool_execution'] is False and value['model_answer_correctness_proven'] is False
            and value['distributed_execution_claimed'] is False and value['private_training_claimed'] is False
            and value['cleanup'] == dict(complete=True, retained_input=False, retained_report=False), 'result scope')
    kind = value['output']['type']
    require(kind in ('assistant', 'function_call', 'custom_tool_call', 'incomplete'), 'result kind')
    reason = value['output'].get('reason')
    require(reason is None or reason in ('token_limit', 'wire_truncated', 'invalid_output'), 'result reason')
    require(type(value['turn_complete']) is bool and value['turn_complete'] == (kind != 'incomplete')
            and ((kind == 'incomplete') == (reason is not None)), 'incomplete turn promoted')
    prompt, generated = value['prompt_tokens'], value['generated_tokens']
    require(type(prompt) is int and 1 <= prompt <= 12288 and type(generated) is int and 1 <= generated <= 1024,
            'result tokens')
    return dict(output_type=kind, incomplete_reason=reason, turn_complete=value['turn_complete'],
                prompt_tokens=prompt, generated_tokens=generated, cleanup_confirmed=True)


def synthetic_first_answer(input_value, response, turn, *, enabled=False):
    """Opt-in fixture evidence only; never general worker or private-user logging.

    The returned text is untrusted actual model output, not a selected answer or
    inferred tool call. Turn two can contain file contents and is never exported.
    """
    if enabled is not True or turn != 1:
        return None
    raw_input = json.dumps(input_value, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, separators=(',', ':')).encode('utf-8')
    require(len(raw_input) <= 4096 and hashlib.sha256(raw_input).hexdigest() ==
            SYNTHETIC_FIRST_INPUT_SHA256, 'synthetic first input identity')
    summary = result_summary(response)
    if summary['output_type'] != 'assistant':
        return None
    output = response['output']
    require(set(output) == {'type', 'text'} and type(output['text']) is str,
            'synthetic assistant shape')
    size = len(output['text'].encode('utf-8'))
    require(0 < size <= 4096 and '\0' not in output['text'], 'synthetic assistant bound')
    return dict(version=1, synthetic_only=True, turn=1,
        input_sha256=SYNTHETIC_FIRST_INPUT_SHA256,
        input_scope='published-first-input-before-any-tool-result',
        raw_model_output_exported=True, output_type='assistant',
        text=output['text'], utf8_bytes=size)


def stop_client(process, privileged=False):
    """Join only a new-session process group created by this fixture, including its children."""
    if process is None:
        return True
    group = process.pid
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            if privileged:
                subprocess.run(['sudo', '-n', '/bin/kill', f'-{sig.name[3:]}', '--', f'-{group}'],
                               capture_output=True, timeout=5, check=False)
            else:
                os.killpg(group, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is None:
        return False
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return True
    return False


def diagnostic():
    target = ROOT / 'failure.json'
    if not target.exists():
        return None
    value = read(target, 1024)
    require(set(value) == {'version', 'phase', 'code'} and value['version'] == 1
            and value['phase'] in CLIENT_PHASES and value['code'] in CLIENT_CODES, 'diagnostic vocabulary')
    return value


def closed_log(path):
    if not path.exists():
        return None
    with path.open('rb') as stream:
        raw = stream.read(16385)
    return dict(bounded=len(raw) <= 16384, **{name: signature in raw for name, signature in (
        ('bwrap_message', b'bwrap:'), ('permission_denied', b'Permission denied'),
        ('operation_denied', b'Operation not permitted'), ('missing_file', b'No such file or directory'),
        ('missing_library', b'error while loading shared libraries'))})


def generation_state(value):
    """Scalar, opt-in observations; capabilities are not proof of accelerated kernels."""
    require(type(value) is dict and set(value) == {'prompt_tokens', 'threads', 'interop_threads', 'cpu',
        'first_forward_started_ms', 'first_forward_completed_ms', 'first_token_ms',
        'generated_tokens', 'complete', 'elapsed_ms'}, 'generation fields')
    for key, low, high in [('prompt_tokens', 1, 12288), ('generated_tokens', 0, 1024), ('elapsed_ms', 0, 599999)]:
        require(type(value[key]) is int and low <= value[key] <= high, 'generation bound')
    for key in ('threads', 'interop_threads'):
        require(value[key] is None or (type(value[key]) is int and 1 <= value[key] <= 2), 'generation threads')
    cpu = value['cpu']
    require(type(cpu) is dict and set(cpu) == {'isa', 'avx2', 'avx512_bf16', 'amx_bf16', 'amx_tile',
        'mkldnn_available', 'mkldnn_enabled'} and cpu['isa'] in {None, 'DEFAULT', 'NO AVX', 'AVX2', 'AVX512'},
        'generation cpu')
    for key in set(cpu) - {'isa'}:
        require(cpu[key] is None or type(cpu[key]) is bool, 'generation cpu flag')
    start, end, first = [value[key] for key in ('first_forward_started_ms', 'first_forward_completed_ms', 'first_token_ms')]
    for timestamp in (start, end, first):
        require(timestamp is None or (type(timestamp) is int and 0 <= timestamp <= value['elapsed_ms']),
                'generation timestamp')
    require((end is None or (start is not None and start <= end))
            and (first is None or (end is not None and end <= first))
            and ((first is not None) == (value['generated_tokens'] > 0))
            and type(value['complete']) is bool and (not value['complete'] or value['generated_tokens'] > 0),
            'generation ordering')
    return value


def execution_state(value):
    """A bounded observation at failure, never a successful operation or cleanup claim."""
    require(type(value) is dict and set(value) - {'generation'} == {'version', 'last_phase', 'substage', 'capacity',
                'controls', 'peak_rss_bytes'} and type(value['version']) is int and value['version'] == 1,
            'execution state fields')
    require(value['last_phase'] in {None, 'preparing', 'baseline', 'training', 'checkpoint', 'reload',
                'complete', 'paused', 'resumed'}, 'execution phase')
    stage = value['substage']
    require(stage is None or (type(stage) is dict and set(stage) == {'stage', 'state', 'elapsed_ms'}
        and stage['stage'] in {'owner_gate', 'verify_files', 'backend_import', 'tokenizer_load', 'prompt_encode',
                              'model_load', 'generation', 'verify_after', 'result'}
        and stage['state'] in {'begin', 'complete'} and type(stage['elapsed_ms']) is int
        and 0 <= stage['elapsed_ms'] < 600000), 'execution substage')
    capacity = value['capacity']
    require(type(capacity) is dict and set(capacity) == {'decision', 'constraint', 'cpu_some_avg10',
        'io_some_avg10', 'memory_bytes'} and capacity['decision'] in {'run', 'pause', 'cancel'}
        and capacity['constraint'] in {'memory', 'device', 'cpu', 'io', 'quiet_hold', 'none'}, 'execution capacity')
    for key in ('cpu_some_avg10', 'io_some_avg10'):
        number = capacity[key]
        require(number is None or (type(number) in (int, float) and math.isfinite(number)
                                    and 0 <= number <= 100), 'execution pressure')
    number = capacity['memory_bytes']
    require(number is None or (type(number) is int and 0 <= number <= 2**64-1), 'execution memory')
    controls = value['controls']
    if controls is not None:
        require(type(controls) is dict and set(controls) == {'issued', 'acknowledged', 'last_issued', 'last_acknowledged'}
            and type(controls['issued']) is int and type(controls['acknowledged']) is int
            and 0 <= controls['acknowledged'] <= controls['issued'] <= 128, 'execution controls')
        for count, action in (('issued', 'last_issued'), ('acknowledged', 'last_acknowledged')):
            require((controls[count] == 0 and controls[action] is None)
                    or (controls[count] > 0 and controls[action] in {'pause', 'resume'}), 'execution control action')
    require(type(value['peak_rss_bytes']) is int and 0 <= value['peak_rss_bytes'] <= 10 * GIB, 'execution peak rss')
    if 'generation' in value:
        generation_state(value['generation'])
        require(stage is not None and stage['stage'] in {'generation', 'verify_after', 'result'}, 'generation scope')
    return value


def service_diagnostic(path):
    """Local observations only; fixed vocabulary, no raw log, prompt, path or request ID."""
    if not path.exists():
        return None
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'private service log owner')
        raw = stream.read(65537)
    truncated = len(raw) > 65536
    lines = raw[:65536].splitlines()
    if truncated:
        lines = lines[:-1]  # Never accept a partial final record.
    events, states, state_seen, unknown = [], [], False, False
    marker = b'private_execution_diagnostic '
    state_marker = b'private_execution_state '
    for line in lines:
        if state_marker in line:
            state_seen = True
            try:
                value = execution_state(json.loads(line.split(state_marker, 1)[1]))
                if len(states) < 16:
                    states.append(value)
                else:
                    truncated = True
            except (ValueError, KeyError, TypeError):
                unknown = True
            continue
        if marker not in line:
            continue
        try:
            event = json.loads(line.split(marker, 1)[1])
            require(isinstance(event, dict) and set(event) == {'version', 'phase', 'detail'}
                    and type(event['version']) is int and event['version'] == 1
                    and event['phase'] in SERVICE_PHASES, 'service diagnostic phase')
            detail = event['detail']
            require(isinstance(detail, dict) and set(detail) == {'code', 'io_kind', 'exit_code', 'signal', 'stderr_class'}
                    and detail['code'] in SERVICE_CODES and detail['io_kind'] in SERVICE_IO_KINDS
                    and detail['stderr_class'] in SERVICE_STDERR_CLASSES, 'service diagnostic vocabulary')
            for key, low, high in (('exit_code', -1, 255), ('signal', 0, 64)):
                require(detail[key] is None or (type(detail[key]) is int and low <= detail[key] <= high),
                        'service diagnostic exit bound')
            if len(events) < 16:
                events.append(event)
            else:
                truncated = True
        except (ValueError, KeyError, TypeError):
            unknown = True
    result = dict(version=1, events=events, truncated=truncated, unrecognized_record=unknown)
    if state_seen:
        result['states'] = states
    return result


def check_report(value, revision):
    require(value['report_kind'] == 'volparossa-agent-private-conversation' and value['proof_version'] == 1
            and value['source_revision'] == revision and re.fullmatch('[0-9a-f]{40}', revision)
            and value['scope'] == SCOPE and value['success'] is True and value['phase'] == 'complete', 'proof incomplete')
    require(all(value[key] is False for key in ('raw_input_exported', 'raw_model_output_exported',
            'codex_app_server_proven', 'code_edit_test_loop_proven', 'hard_4gib_proven',
            'general_coding_quality_proven')), 'unsupported proof claim')
    require(value['code_provision'] == pins() and value['inputs_unchanged'] is True
            and value['service_clean_stop'] is True and value['client_diagnostic'] is None
            and not value.get('diagnostic_invalid'), 'source or lifecycle incomplete')
    provisioner = runpy.run_path(str(ML / 'provision.py'))
    model = provisioner['load_pins'](PROFILE)
    model_bytes, requirement_bytes = provisioner['retained_pin_files'](model)
    require(value['provision'] == dict(model_id=MODEL['model_id'], revision=MODEL['revision'], model_profile=PROFILE,
        download_bytes=provisioner['download_total'](model), budget_bytes=5 * GIB, installed_wheels=38,
        model_pins_sha256=hashlib.sha256(model_bytes).hexdigest(), requirements_sha256=hashlib.sha256(requirement_bytes).hexdigest()),
        'model/runtime provenance')
    for turn, expected in ((1, 'function_call'), (2, 'assistant')):
        summary = value[f'turn_{turn}']
        require(set(summary) == {'output_type', 'incomplete_reason', 'turn_complete', 'prompt_tokens',
                                 'generated_tokens', 'cleanup_confirmed'}
                and summary['output_type'] == expected and summary['incomplete_reason'] is None
                and summary['turn_complete'] is True and summary['cleanup_confirmed'] is True
                and type(summary['prompt_tokens']) is int and 1 <= summary['prompt_tokens'] <= 12288
                and type(summary['generated_tokens']) is int and 1 <= summary['generated_tokens'] <= 1024, 'model turn incomplete')
        TRAIN['check_isolation'](value[f'isolation_{turn}'])
    require(value['isolation_1']['cli'] == value['isolation_2']['cli']
            and value['isolation_1']['worker'] != value['isolation_2']['worker'], 'distinct worker turns missing')
    require(value['client'] == dict(version=1, runtime_version='v24.19.0', network_isolated=True,
        genuine_conversation_client=True, model_turns=2, model_selected_tool=True,
        correlated_tool_result_consumed=True, literal_canary_present=True, source_was_synthetic=True,
        codex_app_server_proven=False, code_edit_test_loop_proven=False, general_coding_quality_proven=False), 'client proof')
    tool = value['tool']
    require(set(tool) == {'version', 'authorized_fixture_read', 'tool_calls_executed', 'command_execution',
            'canary_absent_from_first_input', 'correlated_call_id'} and tool['version'] == 1
            and tool['authorized_fixture_read'] is True and tool['tool_calls_executed'] == 1
            and tool['command_execution'] is False and tool['canary_absent_from_first_input'] is True
            and re.fullmatch('vp-[0-9a-f]{32}', tool['correlated_call_id']), 'tool permission or correlation')
    for field in ('memory_before', 'memory_after_1', 'memory_after_2', 'memory_final'):
        resource = value[field]
        require(resource['memory_max_bytes'] == MEMORY_MAX and resource['swap_max_bytes'] == 0
                and resource['oom'] == resource['oom_kill'] == 0
                and 0 <= resource['current_bytes'] <= resource['peak_bytes'] <= MEMORY_MAX
                and resource['admission_headroom_bytes'] == MEMORY_MAX - resource['current_bytes'], 'resource bound')
    require(value['memory_before']['admission_headroom_bytes'] >= 9 * GIB // 2, 'initial admission headroom')
    require(value['cleanup'] == dict(client_group_joined=True, provision_group_joined=True,
        observer_group_joined=True, service_stopped=True, observed_lifetimes_ended=True, guest_root_removed=True)
        and value['host_state_unchanged'] is True
        and value['host_state_hashes']['before'] == value['host_state_hashes']['after'], 'cleanup or host state')
    for name, expected in value['fixture_hashes'].items():
        require(name in ('agent-private-conversation.py', 'agent-private-conversation.cjs',
                        'agent-private-conversation-pins.json', 'agent-private-conversation.sh')
                and digest(HERE / name) == expected, 'fixture source differs')
    require(len(value['fixture_hashes']) == 4, 'fixture provenance incomplete')


def check_bundle(path, revision):
    value = read(path)
    check_report(value, revision)
    for when in ('before', 'after'):
        require(digest(path.parent / f'host-state-{when}.json') == value['host_state_hashes'][when], 'host snapshot differs')
    # The VM wrapper additionally publishes its own fixed console log, never the private task root.
    allowed = EXPORT_NAMES | {'vm-console.log'}
    for entry in path.parent.iterdir():
        info = entry.lstat()
        require(entry.name in allowed and stat.S_ISREG(info.st_mode)
                and info.st_size <= (16 * 1024**2 if entry.name == 'vm-console.log' else 262144), 'unexpected proof artifact')


def early_failure(output, revision, phase):
    require(output == OUTPUT and re.fullmatch('[0-9a-f]{40}', revision)
            and phase in ('guest-packages', 'cli-build', 'private-conversation'), 'failure invocation')
    write(output / 'agent-private-conversation-smoke.json', dict(report_kind='volparossa-agent-private-conversation',
        proof_version=1, source_revision=revision, scope=SCOPE, success=False, phase=phase,
        failure_code='guest_phase_incomplete', codex_app_server_proven=False, code_edit_test_loop_proven=False))


def execute(output, revision, *, export_synthetic_first_answer=False):
    guard()
    require(output == OUTPUT and re.fullmatch('[0-9a-f]{40}', revision), 'exact invocation')
    require(not ROOT.exists() and not ROOT.is_symlink() and properties()['LoadState'] == 'not-found', 'existing fixture')
    available = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    require(int(available['MemAvailable'].split()[0]) * 1024 >= 6 * GIB, 'guest memory preflight')
    value = pins()
    before = TRAIN['snapshot']()
    write(output / 'host-state-before.json', before)
    result = dict(report_kind='volparossa-agent-private-conversation', proof_version=1,
                  source_revision=revision, scope=SCOPE, success=False, phase='guard',
                  code_provision=value, raw_input_exported=False, raw_model_output_exported=False,
                  synthetic_first_answer_export_enabled=export_synthetic_first_answer,
                  codex_app_server_proven=False, code_edit_test_loop_proven=False,
                  hard_4gib_proven=False, general_coding_quality_proven=False)
    ROOT.mkdir(mode=0o700)
    (ROOT / 'work').mkdir(mode=0o700)
    process, observer, provision_process, service_created, members = None, None, None, False, []
    try:
        result['phase'] = 'provision-client'
        require(shutil.disk_usage(ROOT).free >= 6 * GIB, 'disk preflight')
        for name, pin in value['files'].items():
            fetch(f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-code/{value['revision']}/{name}", ROOT / name, pin)
        fetch(value['runtime']['url'], ROOT / 'node.tar.xz', value['runtime'])
        with tarfile.open(ROOT / 'node.tar.xz', 'r:xz') as archive:
            extract_node(archive, ROOT / 'runtime', value['runtime']['files'])
        verify_client(value)
        result['phase'] = 'provision-model'
        with (ROOT / 'provision.log').open('xb') as log:
            provision_process = subprocess.Popen([sys.executable, '-B', str(ML / 'provision.py'), '--execute', '--yes', '--disposable-guest',
                '--model-profile', PROFILE, '--root', str(ROOT / 'ml'), '--budget-bytes', str(5 * GIB)],
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            require(provision_process.wait(timeout=1850) == 0, 'model provision failed')
        provision = read(ROOT / 'ml/provision-report.json')
        require(provision['success'] is True and provision['model_profile'] == PROFILE
                and provision['model_id'] == MODEL['model_id'] and provision['revision'] == MODEL['revision']
                and provision['installed_wheels'] == 38 and provision['training_performed'] is False
                and provision['runtime_autofetch_enabled'] is False, 'model provisioning')
        result['provision'] = {key: provision[key] for key in ('model_id', 'revision', 'model_profile',
            'download_bytes', 'budget_bytes', 'installed_wheels', 'model_pins_sha256', 'requirements_sha256')}
        canary = 'CANARY' + str(int.from_bytes(os.urandom(4)) % 100000000).zfill(8)
        with (ROOT / 'fixture.js').open('x') as source:
            source.write(f'function testIdentifier() {{ return "{canary}"; }}\n')
        (ROOT / 'fixture.js').chmod(0o600)
        original_hash = digest(ROOT / 'fixture.js')
        result['phase'] = 'service-start'
        # Only this opt-in target reaches the private log; no diagnostic journal or raw-log artifact.
        diagnostic_log = ROOT / 'service.log'
        with os.fdopen(os.open(diagnostic_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb'):
            pass
        command = [str(CLI), 'compute', 'private-serve', '--socket', str(ROOT / 'private.sock'),
            '--work-parent', str(ROOT / 'work'), '--runtime-root', str(ROOT / 'ml/venv'),
            '--model-root', str(ROOT / 'ml/model'), '--model-profile', PROFILE,
            '--threads', '2', '--max-seconds', '600', '--execute']
        # This exact name was absent at preflight; retain the exited unit until its status is read.
        service_created = True
        subprocess.run(['sudo', '-n', 'systemd-run', '--quiet', f'--unit={UNIT}',
            '--property=Type=exec', '--property=RemainAfterExit=yes',
            '--property=User=vpci', '--property=Group=vpci', '--property=WorkingDirectory=/home/vpci/source',
            f'--property=MemoryMax={MEMORY_MAX}', '--property=MemorySwapMax=0', '--property=TasksMax=128',
            '--property=KillMode=control-group', '--property=RuntimeMaxSec=1400', '--property=TimeoutStopSec=10',
            '--setenv=RUST_LOG=off,volparossa::compute::private_diagnostic=debug',
            '--setenv=NO_COLOR=1',
            f'--property=StandardOutput=append:{diagnostic_log}', f'--property=StandardError=append:{diagnostic_log}',
            '--property=NoNewPrivileges=yes', '--property=PrivateNetwork=yes', *command], check=True,
            capture_output=True, timeout=15)
        for _ in range(100):
            if (ROOT / 'private.sock').exists():
                break
            time.sleep(0.1)
        info = properties()
        pid = int(info['MainPID'])
        require(pid > 0 and info['ActiveState'] == 'active' and info['ControlGroup'] == '/system.slice/' + UNIT,
                'service launch')
        members.append(TRAIN['identity'](pid))
        socket_info = (ROOT / 'private.sock').lstat()
        require(stat.S_ISSOCK(socket_info.st_mode) and socket_info.st_uid == os.getuid()
                and stat.S_IMODE(socket_info.st_mode) == 0o600, 'private socket')
        result['memory_before'] = memory()
        require(result['memory_before']['admission_headroom_bytes'] >= 9 * GIB // 2, 'service headroom')
        result['phase'] = 'client-start'
        launch = ['/usr/bin/bwrap', '--unshare-net', '--die-with-parent', '--ro-bind', '/', '/',
            '--bind', str(ROOT), str(ROOT), '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--chdir', str(ROOT),
            '--', str(ROOT / 'runtime/bin/node'), '--max-old-space-size=64', str(HERE / 'agent-private-conversation.cjs'),
            str(ROOT), str(ROOT / 'private.sock'), os.readlink('/proc/self/ns/net')]
        with (ROOT / 'client.log').open('xb') as log:
            process = subprocess.Popen(launch, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            for turn in (1, 2):
                result['phase'] = f'turn-{turn}-observe'
                wait_file(f'submitted-{turn}.json', process, 30)
                with (ROOT / 'observer.log').open('ab') as diagnostics:
                    observer = subprocess.Popen(['sudo', '-n', sys.executable, '-B', str(Path(__file__).resolve()),
                        'observe', str(pid), str(turn)], stdout=diagnostics, stderr=diagnostics, start_new_session=True)
                    require(observer.wait(timeout=75) == 0, 'worker observer')
                isolation = read(ROOT / f'isolation-{turn}.json')
                TRAIN['check_isolation'](isolation)
                members.extend(isolation['owned_processes'])
                result[f'isolation_{turn}'] = isolation
                result['phase'] = f'turn-{turn}-result'
                wait_file(f'settled-{turn}.json', process, 620)
                response = read(ROOT / f'result-{turn}.json', 65536)
                result[f'turn_{turn}'] = result_summary(response)
                require(not list((ROOT / 'work').iterdir()) and
                    not any(TRAIN['alive'](member) for member in isolation['owned_processes'] if member != isolation['cli']),
                    'actual result cleanup')
                if export_synthetic_first_answer and turn == 1:
                    answer = synthetic_first_answer(read(ROOT / 'input-1.json', 4096), response, turn,
                                                    enabled=export_synthetic_first_answer)
                    if answer is not None:
                        result['synthetic_first_answer'] = answer
                        result['raw_model_output_exported'] = True
                result[f'memory_after_{turn}'] = memory()
                write(ROOT / f'continue-{turn}.json', dict(cleanup_observed=True))
            require(process.wait(timeout=20) == 0, 'client proof failed')
        result['phase'] = 'client-result'
        require((ROOT / 'client.log').stat().st_size == 0, 'client diagnostics')
        result['client'] = read(ROOT / 'client.json', 4096)
        result['tool'] = read(ROOT / 'tool.json', 4096)
        require(digest(ROOT / 'fixture.js') == original_hash, 'fixture changed')
        verify_client(value)
        result['inputs_unchanged'] = True
        result['memory_final'] = memory()
        result['phase'] = 'service-stop'
        unit('kill', '--kill-whom=main', '--signal=SIGINT')
        for _ in range(100):
            info = properties()
            if info.get('MainPID') == '0':
                break
            time.sleep(0.1)
        require(info['ActiveState'] == 'active' and info['SubState'] == 'exited' and info['Result'] == 'success'
                and info['ExecMainStatus'] == '0' and not (ROOT / 'private.sock').exists(), 'service clean stop')
        result['service_clean_stop'] = True
        result['phase'] = 'complete'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result['failure_code'] = 'phase_failed'
    finally:
        # Error/status metadata stays closed. The sole text exception above is
        # explicitly opted-in and bound to the published synthetic first input.
        try:
            result['client_diagnostic'] = diagnostic()
            result['client_launcher'] = closed_log(ROOT / 'client.log')
            result['observer_launcher'] = closed_log(ROOT / 'observer.log')
            if CGROUP.exists():
                result['memory_final'] = memory()
        except (OSError, ValueError, KeyError, TypeError):
            result['diagnostic_invalid'] = True
        observer_joined = stop_client(observer, privileged=True)
        provision_joined = stop_client(provision_process)
        client_joined = stop_client(process)
        service_stopped = not service_created
        if service_created:
            status = properties()
            result['service_terminal'] = {key: status.get(key) for key in
                ('LoadState', 'ActiveState', 'SubState', 'Result', 'ExecMainStatus')}
            unit('stop', check=False)
            status = properties()
            service_stopped = status['LoadState'] == 'not-found' or status.get('ActiveState') in ('inactive', 'failed')
            unit('reset-failed', check=False)
        try:
            result['service_diagnostic'] = service_diagnostic(ROOT / 'service.log')
        except (OSError, ValueError, KeyError, TypeError):
            result['diagnostic_invalid'] = True
        alive = any(TRAIN['alive'](member) for member in members)
        removed = client_joined and provision_joined and observer_joined and service_stopped and not alive
        if removed:
            require(ROOT.lstat().st_uid == os.getuid() and stat.S_ISDIR(ROOT.lstat().st_mode), 'cleanup owner')
            shutil.rmtree(ROOT)
        result['cleanup'] = dict(client_group_joined=client_joined, service_stopped=service_stopped,
            provision_group_joined=provision_joined, observer_group_joined=observer_joined,
            observed_lifetimes_ended=not alive, guest_root_removed=not ROOT.exists())
        after = TRAIN['snapshot']()
        write(output / 'host-state-after.json', after)
        result['host_state_unchanged'] = before == after
        result['host_state_hashes'] = {when: digest(output / f'host-state-{when}.json') for when in ('before', 'after')}
        result['success'] = result['phase'] == 'complete' and removed and before == after
        result['fixture_hashes'] = {name: digest(HERE / name) for name in (
            'agent-private-conversation.py', 'agent-private-conversation.cjs', 'agent-private-conversation-pins.json',
            'agent-private-conversation.sh')}
        if result['success']:
            try:
                check_report(result, revision)
            except (OSError, ValueError, KeyError, TypeError):
                result['success'] = False
                result['failure_code'] = 'proof_validation_failed'
        write(output / 'agent-private-conversation-smoke.json', result)
    return 0 if result['success'] else 1


def main():
    if len(sys.argv) == 5 and sys.argv[1] == 'execute' and sys.argv[4] == '--yes':
        return execute(Path(sys.argv[2]), sys.argv[3])
    if (len(sys.argv) == 6 and sys.argv[1] == 'execute' and sys.argv[4:] ==
            ['--yes', '--export-synthetic-first-answer']):
        return execute(Path(sys.argv[2]), sys.argv[3], export_synthetic_first_answer=True)
    if len(sys.argv) == 4 and sys.argv[1] == 'observe':
        observe(int(sys.argv[2]), int(sys.argv[3]))
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == 'report':
        check_bundle(Path(sys.argv[2]), sys.argv[3])
        print('PRIVATE_CONVERSATION_COMPONENT_PROOF_OK')
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == 'failure':
        early_failure(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
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
        print('private_conversation_fixture_failed', file=sys.stderr)
        raise SystemExit(1)
