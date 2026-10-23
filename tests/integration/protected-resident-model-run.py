#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only controller for the PUBLIC, immutable, two-turn model fixture.

The build VM may fetch pinned public model/compiler inputs. The resulting
runtime guest has no NIC, SSH, writable root, shared host directory or debug
shell. Neither VM is confidential computing: private input admission remains
false. All subprocesses have deadlines; VM export requires stopped processes
AND empty control groups, not a successful parent process alone.
"""
import argparse
import contextvars
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import tarfile
import time
import types
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
GIB = 1024 ** 3
MAX_SECONDS = 14400
LOCK_SHA = 'ab3fe950b2e39e7f556843cb76a5421ae039a6b10464a7a5109150dae5dc1af8'
CODE = 'fd4ff9688c58d6228e07f2116a7e8dcdb12a89ef'
HELPER_SHA = '32a79a1801de0979fdca0064c5bbd2c09b71069a0141be7d68aaec01006bbcbf'
RUNTIME_BYTES = 32 * GIB
QEMU_BYTES = 13 * GIB
DISK_MEMORY_STAGES = ('inspect_roots', 'inspect_details', 'root_export', 'raw_resize',
                      'runtime_uuid', 'build_overlay', 'seed')
INPUT = '/home/vpci/resident-inputs'
OUTPUT = '/home/vpci/resident-output'
LOCK = INPUT + '/core/tests/integration/protected-resident-model-debian-lock-v1.json'
INSTALL = INPUT + '/core/tests/integration/protected-resident-model-install.py'
BUILD = INPUT + '/core/tests/integration/protected-resident-model-build.py'
READY = b'VP_PROTECTED_MODEL_READY_V1 '
BOOT = b'VP_PROTECTED_MODEL_BOOT_V1 '
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'PYTHONDONTWRITEBYTECODE': '1', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
CANCELLED = False
CLEANUP_ACTIVE = contextvars.ContextVar('resident_model_cleanup_active', default=False)
TOOL_PROCESSES = contextvars.ContextVar('resident_model_tool_processes', default=None)
REQUESTER_STAGE_PREFIX = b'VP_PUBLIC_REQUESTER_STAGE_V1 '
REQUESTER_STAGES = ('configuration', 'socket', 'certificate', 'connect', 'tls',
    'tls_profile', 'challenge', 'grant', 'accepted', 'turn_1_submit', 'turn_1_admitted',
    'turn_1_result', 'turn_2_submit', 'turn_2_admitted', 'turn_2_result', 'close', 'closed', 'cleanup')
REQUESTER_FAILURE_PREFIX = b'VP_PUBLIC_REQUESTER_FAILURE_V1 '
REQUESTER_SOCKET_PREFIX = b'VP_PUBLIC_REQUESTER_SOCKET_FAILURE_V1 '
REQUESTER_SOCKET_MAX_BODY = 512
REQUESTER_SOCKET_CONDITIONS = ('parent_validation', 'socket_metadata', 'not_socket', 'owner_mismatch')
REQUESTER_SOCKET_IO_KINDS = ('none', 'not_found', 'permission_denied', 'interrupted',
                           'invalid_input', 'invalid_data', 'other')
REQUESTER_CONNECT_PREFIX = b'VP_PUBLIC_REQUESTER_CONNECT_FAILURE_V1 '
REQUESTER_CONNECT_MAX_BODY = 512
REQUESTER_CONNECT_CONDITIONS = ('connect_deadline', 'connect_io', 'peer_credential_io', 'peer_uid_mismatch')
REQUESTER_CONNECT_IO_KINDS = ('none', 'not_found', 'permission_denied', 'connection_refused',
    'connection_reset', 'connection_aborted', 'not_connected', 'addr_in_use', 'addr_not_available',
    'timed_out', 'interrupted', 'would_block', 'invalid_input', 'invalid_data', 'other')
REQUESTER_RESULT_CATEGORIES = ('read_deadline', 'read_bound', 'read_frame', 'read_eof', 'read_io',
    'read_other', 'reply_order', 'failure_frame', 'guest_failure', 'result_json', 'result_completion',
    'result_profile', 'result_output', 'result_answer', 'result_tokens', 'result_cleanup')
# Exact Rust vocabulary; parity is checked inertly against the serializer source.
REQUESTER_NATIVE_CODES = frozenset((
    'compute_private_budget',
    'compute_model_memory_headroom',
    'compute_runtime_busy',
    'compute_lock_invalid',
    'compute_output_create',
    'compute_sandbox_spawn',
    'compute_sandbox_prerequisite',
    'compute_runtime_missing',
    'compute_native_backend_authorization',
    'compute_native_backend_manifest_hash',
    'compute_native_backend_manifest_schema',
    'compute_native_backend_identity',
    'compute_native_backend_artifacts',
    'compute_native_backend_conversion',
    'compute_native_backend_file',
    'compute_native_backend_scope',
    'compute_native_backend_policy',
    'compute_native_backend_output_constraint',
    'compute_private_result_scope',
    'compute_private_result_input',
    'compute_private_result_model',
    'compute_private_result_model_weights',
    'compute_private_result_outputs',
    'compute_private_result_output',
    'compute_native_backend_result_binding',
    'compute_native_backend_result_precision',
    'compute_native_backend_output_constraint_binding',
    'conversation_generation_policy_binding',
    'conversation_output_constraint_binding',
    'conversation_report_binding',
    'compute_deadline',
    'compute_owner_busy',
    'compute_memory_budget',
    'compute_storage_budget',
    'compute_process_bound',
    'compute_thread_bound',
    'compute_process_observation',
    'compute_observation_size',
    'compute_private_process_observation',
    'compute_private_process_missing',
    'compute_private_process_bound',
    'compute_private_process_stat',
    'compute_private_process_stat_open',
    'compute_private_process_stat_read',
    'compute_private_process_stat_bound',
    'compute_private_process_children',
    'compute_private_process_cleanup_deadline',
    'compute_private_storage_cleanup_failed',
    'compute_reap_deadline',
    'compute_reap',
    'compute_request_write_deadline',
    'compute_request_write',
    'compute_control_write_deadline',
    'compute_control_write',
    'compute_control_ack_deadline',
    'compute_private_progress',
    'compute_memory_pressure',
    'compute_device_reserve',
    'compute_owner_pressure',
    'compute_pressure_observation',
    'compute_worker_json',
    'compute_worker_correlation',
    'compute_worker_phase',
    'compute_worker_status',
    'compute_worker_kind',
    'compute_worker_line_size',
    'compute_worker_unterminated_line',
    'compute_stdout_size',
    'compute_stderr_size',
    'compute_stderr_read',
    'compute_wait',
    'compute_worker_exit',
    'conversation_request_id',
    'conversation_native_marker',
    'conversation_native_call',
    'conversation_native_preface',
    'conversation_native_json',
    'conversation_native_json_syntax',
    'conversation_native_json_data',
    'conversation_native_json_eof',
    'conversation_native_json_io',
    'conversation_unknown_tool',
    'conversation_custom_input',
    'conversation_arguments',
    'conversation_call_id',
    'conversation_empty_answer',
    'conversation_native_output_other',
    'JOB_INPUT_NOT_FOUND',
    'JOB_PATH_PERMISSION_DENIED',
    'JOB_MEMORY_EXHAUSTED',
    'BACKEND_IMPORT_FAILED',
    'BACKEND_EXECUTION_FAILED',
    'BACKEND_NOT_INSTALLED',
    'BACKEND_VERSION_MISMATCH',
    'CPU_BACKEND_REQUIRED',
    'MODEL_PARAMETER_DTYPE_MISMATCH',
    'MODEL_WEIGHTS_CHANGED_ON_DISK',
    'CONVERSATION_TOKENIZER_SHAPE',
    'CONVERSATION_TOKEN_LIMIT',
    'RESULT_TOO_LARGE',
    'JOB_CANCELLED',
    'JOB_DEADLINE_EXCEEDED',
    'NATIVE_ABI_MISMATCH',
    'NATIVE_BUILD_PATCH_BINDING',
    'NATIVE_OPEN_DIAGNOSTIC_INVALID',
    'NATIVE_OPEN_INVALID_ARGUMENT',
    'NATIVE_CPU_UNSUPPORTED',
    'NATIVE_BACKEND_INITIALIZATION_FAILED',
    'NATIVE_MODEL_INITIALIZATION_FAILED',
    'NATIVE_VOCABULARY_MISMATCH',
    'NATIVE_CONTEXT_INITIALIZATION_FAILED',
    'NATIVE_SAMPLER_INITIALIZATION_FAILED',
    'NATIVE_MODEL_LOAD_FAILED',
    'NATIVE_OWNER_CONTROL_FAILED',
    'INVALID_NATIVE_CONTROL',
    'compute_native_session_child_exited',
    'compute_native_session_cpu_backwards',
    'compute_native_session_cpu_bound',
    'compute_native_session_cpu_budget',
    'compute_native_session_cpu_clock',
    'compute_native_session_cpu_identity',
    'compute_native_session_cpu_stat',
    'compute_native_session_receiver',
    'compute_native_session_report',
    'compute_native_session_request_bound',
    'compute_native_session_root',
    'compute_native_session_stderr',
    'compute_native_session_stderr_closed',
    'compute_native_session_stdout_closed',
    'compute_native_session_turn_root',
    'compute_native_session_unrequested_idle',
    'compute_native_session_unsupported',
    'compute_native_session_worker',
    'compute_worker_invalid_json',
    'compute_output_after_result',
    'compute_result_missing',
    'NATIVE_DECODE_FAILED',
    'NATIVE_SAMPLE_FAILED',
    'NATIVE_SESSION_PREFIX_RESET_FAILED',
    'NATIVE_SESSION_CPU_OBSERVATION',
    'NATIVE_SESSION_CPU_BOUND',
    'NATIVE_SESSION_DEADLINE',
    'NATIVE_SESSION_MODEL_CHANGED',
    'NATIVE_SESSION_PREFIX_BOUND',
    'INVALID_NATIVE_SESSION_FINISH',
    'INVALID_NATIVE_SESSION_SEQUENCE',
    'unclassified', 'worker_other', 'startup_missing_result'))
REQUESTER_IO_KINDS = ('none', 'not_found', 'permission_denied', 'unexpected_eof', 'broken_pipe',
    'interrupted', 'invalid_data', 'other')
REQUESTER_STDERR_CLASSES = ('none', 'bubblewrap', 'user_namespace', 'proc_mount', 'exec_denied',
    'python_startup', 'other')
REQUESTER_BUBBLEWRAP_STAGES = ('bubblewrap_namespace_setup', 'bubblewrap_root_setup',
    'bubblewrap_source_setup', 'bubblewrap_destination_setup', 'bubblewrap_bind_mount')
FAILURE_CODES = frozenset(('controller_deadline', 'controller_cancelled', 'command_timeout',
    'command_output_bound', 'command_failed', 'host_memory_headroom', 'host_memory_snapshot', 'qemu_limits',
    'qemu_exited_before_scope', 'scope_start_timeout', 'guest_unit_failed', 'guest_unit_cgroup',
    'base_os', 'base_root_size', 'root_geometry', 'root_export_source', 'root_export_compare',
    'runtime_uuid', 'build_vm_died', 'build_boot_timeout',
    'guest_source_bundle', 'guest_package_bundle', 'installer_receipt', 'runtime_still_mounted',
    'runtime_kernel_binding', 'verity_root_hash', 'channel_path_length', 'model_vm_died',
    'console_bound', 'model_ready_timeout', 'model_guest_exit_timeout', 'sealed_inputs_changed',
    'negative_guest_exit_timeout', 'host_network_observation_changed', 'host_observation_capture_failed', 'source_changed',
    'space_download', 'space_root_extract', 'space_build', 'space_asset_export', 'space_workload_stage'))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def module(name):
    path = HERE / (name + '.py')
    result = types.ModuleType(name.replace('-', '_'))
    result.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), result.__dict__)
    return result


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def write_new(path, raw, mode=0o600):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), 'wb') as out:
        out.write(raw)
        os.fchmod(out.fileno(), mode)


def remaining(deadline, cap=MAX_SECONDS):
    require(not CANCELLED or CLEANUP_ACTIVE.get(), 'controller_cancelled')
    value = deadline - time.monotonic()
    require(0 < value <= MAX_SECONDS and 0 < cap <= MAX_SECONDS, 'controller_deadline')
    return min(value, cap)


def file_hash(path, deadline, maximum=48 * GIB, algorithm='sha256'):
    remaining(deadline)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum, 'controller_file')
        digest = hashlib.new(algorithm)
        while block := stream.read(1024 ** 2):
            remaining(deadline)
            digest.update(block)
        after = os.fstat(stream.fileno())
        require((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'controller_file_changed')
    return {'bytes': before.st_size, algorithm: digest.hexdigest()}


class CleanupUnconfirmed(RuntimeError):
    pass


def joined(process):
    # Keep the direct child unreaped until the final process-group signal.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise CleanupUnconfirmed('group_signal') from error
    try:
        process.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CleanupUnconfirmed('child_join') from error
    stop = time.monotonic() + 3
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        if time.monotonic() >= stop:
            raise CleanupUnconfirmed('group_remaining')
        time.sleep(.02)


def requester_protocol_stage(raw):
    """Only an ordered prefix of fixed attempt markers can enter evidence."""
    absent = dict(state='unavailable', attempt_stage=None)
    if type(raw) is not bytes or len(raw) > 65536:
        return absent
    seen = []
    for line in raw.splitlines(keepends=True):
        if not line.startswith(REQUESTER_STAGE_PREFIX.rstrip()):
            continue  # Never copy generic errors or arbitrary stderr to evidence.
        if not line.endswith(b'\n'):
            return dict(state='truncated', attempt_stage=None)
        if len(seen) >= len(REQUESTER_STAGES):
            return dict(state='malformed', attempt_stage=None)
        expected = REQUESTER_STAGE_PREFIX + REQUESTER_STAGES[len(seen)].encode() + b'\n'
        if line != expected:
            return dict(state='malformed', attempt_stage=None)
        seen.append(REQUESTER_STAGES[len(seen)])
    if not seen:
        return absent
    return dict(state='complete' if len(seen) == len(REQUESTER_STAGES) else 'prefix',
                attempt_stage=seen[-1])


def requester_failure_detail(value):
    if type(value) is not dict or set(value) != {'code', 'io_kind', 'exit_code', 'signal', 'stderr_class'}:
        return False
    if type(value['code']) is not str or value['code'] not in REQUESTER_NATIVE_CODES:
        return False
    if type(value['io_kind']) is not str or value['io_kind'] not in REQUESTER_IO_KINDS:
        return False
    if value['code'] == 'compute_native_session_stdout_closed':
        # All-null is the unchanged older encoding. Present status was observed
        # before native-session stdin close/cleanup; stderr is the existing
        # bounded drain classification, not proof of the original failure cause.
        # This extension requires the matching updated Rust fixture validator.
        if all(value[key] is None for key in ('exit_code', 'signal', 'stderr_class')):
            return True
        if type(value['stderr_class']) is not str or value['stderr_class'] not in (*REQUESTER_STDERR_CLASSES, *REQUESTER_BUBBLEWRAP_STAGES):
            return False
        if value['exit_code'] is None and value['signal'] is None:
            return True
    elif value['code'] != 'startup_missing_result':
        return all(value[key] is None for key in ('exit_code', 'signal', 'stderr_class'))
    exit_code, sig = value['exit_code'], value['signal']
    return (type(exit_code) is int and type(sig) is int and
            ((0 <= exit_code <= 255 and sig == 0) or (exit_code == -1 and 1 <= sig <= 64)) and
            type(value['stderr_class']) is str and value['stderr_class'] in
            ((*REQUESTER_STDERR_CLASSES, *REQUESTER_BUBBLEWRAP_STAGES)
             if value['code'] == 'compute_native_session_stdout_closed' else REQUESTER_STDERR_CLASSES))


def requester_result_failure(raw, protocol):
    absent = dict(state='unavailable', observation=None)
    if type(raw) is not bytes or len(raw) > 65536:
        return absent
    markers = [line for line in raw.splitlines(keepends=True)
               if line.startswith(REQUESTER_FAILURE_PREFIX.rstrip())]
    if not markers:
        return absent
    if len(markers) != 1:
        return dict(state='malformed', observation=None)
    line = markers[0]
    if not line.endswith(b'\n'):
        return dict(state='truncated', observation=None)
    if len(line) > 2048:
        return dict(state='malformed', observation=None)
    try:
        payload = line[len(REQUESTER_FAILURE_PREFIX):-1]
        value = json.loads(payload)
        require(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() == payload,
                'diagnostic_encoding')
        require(type(value) is dict and set(value) == {'version', 'turn', 'category', 'guest'}, 'diagnostic_schema')
        require(type(value['version']) is int and value['version'] == 1 and
                type(value['turn']) is int and value['turn'] in (1, 2) and
                type(value['category']) is str and value['category'] in REQUESTER_RESULT_CATEGORIES,
                'diagnostic_schema')
        require(protocol == dict(state='prefix', attempt_stage='turn_%d_result' % value['turn']),
                'diagnostic_order')
        # The single terminal marker must follow its stage, with no later stage.
        stage_line = REQUESTER_STAGE_PREFIX + ('turn_%d_result' % value['turn']).encode() + b'\n'
        require(raw.find(stage_line) < raw.find(line) and
                not any(item.startswith((REQUESTER_SOCKET_PREFIX.rstrip(), REQUESTER_CONNECT_PREFIX.rstrip()))
                        for item in raw.splitlines(keepends=True)), 'diagnostic_order')
        guest = value['guest']
        if value['category'] == 'guest_failure':
            require(type(guest) is dict and set(guest) == {'version', 'scope', 'detail', 'cleanup'} and
                    type(guest['version']) is int and guest['version'] == 1 and
                    guest['scope'] == 'public_fixture_native_session' and
                    requester_failure_detail(guest['detail']), 'diagnostic_guest')
            cleanup = guest['cleanup']
            require(type(cleanup) is dict and set(cleanup) == {'version', 'child_reaped', 'private_state_removed'} and
                    type(cleanup['version']) is int and cleanup['version'] == 1 and
                    cleanup['child_reaped'] is True and cleanup['private_state_removed'] is True,
                    'diagnostic_cleanup')
            require(len(json.dumps(guest, sort_keys=True, separators=(',', ':')).encode()) <= 1024,
                    'diagnostic_bound')
        else:
            require(guest is None, 'diagnostic_guest')
        return dict(state='observed', observation=value)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return dict(state='malformed', observation=None)


def requester_socket_failure(raw, protocol):
    """Closed failure projection; never a socket/native/cleanup success receipt."""
    absent = dict(state='unavailable', observation=None)
    if type(raw) is not bytes or len(raw) > 65536:
        return absent
    lines = raw.splitlines(keepends=True)
    markers = [line for line in lines if line.startswith(REQUESTER_SOCKET_PREFIX.rstrip())]
    if not markers:
        return absent
    if len(markers) != 1:
        return dict(state='malformed', observation=None)
    line = markers[0]
    if not line.startswith(REQUESTER_SOCKET_PREFIX):
        return dict(state='malformed', observation=None)
    if not line.endswith(b'\n'):
        return dict(state='truncated', observation=None)
    if len(line) > len(REQUESTER_SOCKET_PREFIX) + REQUESTER_SOCKET_MAX_BODY + 1:
        return dict(state='malformed', observation=None)
    try:
        payload = line[len(REQUESTER_SOCKET_PREFIX):-1]
        value = json.loads(payload)
        require(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() == payload,
                'diagnostic_encoding')
        require(type(value) is dict and set(value) == {'version', 'condition', 'io_kind'}, 'diagnostic_schema')
        require(type(value['version']) is int and value['version'] == 1 and
                type(value['condition']) is str and value['condition'] in REQUESTER_SOCKET_CONDITIONS and
                type(value['io_kind']) is str and value['io_kind'] in REQUESTER_SOCKET_IO_KINDS,
                'diagnostic_schema')
        require((value['condition'] != 'socket_metadata' or value['io_kind'] != 'none') and
                (value['condition'] not in ('not_socket', 'owner_mismatch') or value['io_kind'] == 'none'),
                'diagnostic_io_kind')
        require(protocol == dict(state='prefix', attempt_stage='socket'), 'diagnostic_order')
        stage_line = REQUESTER_STAGE_PREFIX + b'socket\n'
        require(raw.find(stage_line) < raw.find(line) and
                not any(item.startswith((REQUESTER_FAILURE_PREFIX.rstrip(), REQUESTER_CONNECT_PREFIX.rstrip()))
                        for item in lines),
                'diagnostic_order')
        return dict(state='observed', observation=value)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return dict(state='malformed', observation=None)


def requester_connect_failure(raw, protocol):
    """Closed post-preflight failure; no socket, TLS, native or cleanup acceptance."""
    absent = dict(state='unavailable', observation=None)
    if type(raw) is not bytes or len(raw) > 65536:
        return absent
    lines = raw.splitlines(keepends=True)
    markers = [line for line in lines if line.startswith(REQUESTER_CONNECT_PREFIX.rstrip())]
    if not markers:
        return absent
    if len(markers) != 1:
        return dict(state='malformed', observation=None)
    line = markers[0]
    if not line.startswith(REQUESTER_CONNECT_PREFIX):
        return dict(state='malformed', observation=None)
    if not line.endswith(b'\n'):
        return dict(state='truncated', observation=None)
    if len(line) > len(REQUESTER_CONNECT_PREFIX) + REQUESTER_CONNECT_MAX_BODY + 1:
        return dict(state='malformed', observation=None)
    try:
        payload = line[len(REQUESTER_CONNECT_PREFIX):-1]
        value = json.loads(payload)
        require(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() == payload,
                'diagnostic_encoding')
        require(type(value) is dict and set(value) == {'version', 'condition', 'io_kind'}, 'diagnostic_schema')
        require(type(value['version']) is int and value['version'] == 1 and
                type(value['condition']) is str and value['condition'] in REQUESTER_CONNECT_CONDITIONS and
                type(value['io_kind']) is str and value['io_kind'] in REQUESTER_CONNECT_IO_KINDS,
                'diagnostic_schema')
        require((value['condition'] in ('connect_deadline', 'peer_uid_mismatch')) == (value['io_kind'] == 'none'),
                'diagnostic_io_kind')
        require(protocol == dict(state='prefix', attempt_stage='connect'), 'diagnostic_order')
        stage_line = REQUESTER_STAGE_PREFIX + b'connect\n'
        require(raw.find(stage_line) < raw.find(line) and
                not any(item.startswith((REQUESTER_SOCKET_PREFIX.rstrip(), REQUESTER_FAILURE_PREFIX.rstrip()))
                        for item in lines), 'diagnostic_order')
        return dict(state='observed', observation=value)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return dict(state='malformed', observation=None)


def requester_diagnostic(raw=b'', returncode=None, failure=None):
    termination = dict(kind='unavailable', exit_code=None, signal=None)
    if failure in ('command_timeout', 'controller_cancelled', 'command_output_bound'):
        termination['kind'] = {'command_timeout': 'timeout', 'controller_cancelled': 'cancelled',
                               'command_output_bound': 'output_bound'}[failure]
    elif failure is None and type(returncode) is int:
        if 0 <= returncode <= 255:
            termination.update(kind='exit', exit_code=returncode)
        elif 0 < -returncode < signal.NSIG:
            termination.update(kind='signal', signal=-returncode)
    protocol = requester_protocol_stage(raw)
    # Version four adds connect_failure independently of preflight-only socket_failure.
    # Existing result/socket V1 markers and requester acceptance receipts keep their schemas.
    return dict(version=4, diagnostic_only=True, acceptance_evidence=False,
                stage_semantics='entered_only', termination=termination, protocol=protocol,
                result_failure=requester_result_failure(raw, protocol),
                socket_failure=requester_socket_failure(raw, protocol),
                connect_failure=requester_connect_failure(raw, protocol))


def run(argv, deadline, *, cap=300, maximum=16 * 1024 ** 2, env=None, check=True,
        requester_observation=None):
    if requester_observation is not None:
        requester_observation.update(requester_diagnostic())
    end = time.monotonic() + remaining(deadline, cap)
    process = subprocess.Popen([str(v) for v in argv], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or ENV,
        close_fds=True, start_new_session=True)
    stdout, stderr = bytearray(), bytearray()
    failure = None
    pending = TOOL_PROCESSES.get()
    try:
        if pending is not None:
            pending[id(process)] = process
        with selectors.DefaultSelector() as events:
            for pipe in (process.stdout, process.stderr):
                os.set_blocking(pipe.fileno(), False)
                events.register(pipe, selectors.EVENT_READ)
            while events.get_map():
                require(not CANCELLED or CLEANUP_ACTIVE.get(), 'controller_cancelled')
                require(time.monotonic() < end, 'command_timeout')
                for key, _ in events.select(.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        events.unregister(key.fileobj)
                        continue
                    (stdout if key.fileobj is process.stdout else stderr).extend(block)
                    require(len(stdout) + len(stderr) <= maximum, 'command_output_bound')
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                require(not CANCELLED or CLEANUP_ACTIVE.get(), 'controller_cancelled')
                require(time.monotonic() < end, 'command_timeout')
                time.sleep(.02)
    except BaseException as error:
        failure = str(error) if type(error) is ValueError else 'unavailable'
        raise
    finally:
        try:
            joined(process)
            if pending is not None:
                pending.pop(id(process), None)
        finally:
            try:
                process.stdout.close()
                process.stderr.close()
            finally:
                if requester_observation is not None:
                    try:
                        requester_observation.update(requester_diagnostic(bytes(stderr), process.returncode, failure))
                    except Exception:
                        pass  # Optional diagnostics cannot replace failure or cleanup.
    require(not check or process.returncode == 0, 'command_failed')
    return bytes(stdout), bytes(stderr), process.returncode


def source_binding(expected, deadline):
    require(re.fullmatch('[0-9a-f]{40}', expected or ''), 'source_sha')
    git = lambda *args: run(['git', '-C', ROOT, *args], deadline)[0].decode().strip()
    require(git('rev-parse', 'HEAD') == expected and not git('diff', '--name-only', 'HEAD'), 'source_changed')
    return {'commit': expected, 'tree': git('rev-parse', 'HEAD^{tree}')}


def hosted(args, deadline):
    require(args.execute and args.yes and os.getuid() > 0, 'explicit_hosted_execution')
    for key, expected in {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                          'RUNNER_OS': 'Linux', 'GITHUB_REPOSITORY': 'VOLPAROSSA/volparossa',
                          'GITHUB_SHA': args.expected_source, 'GITHUB_WORKFLOW_SHA': args.expected_source}.items():
        require(os.environ.get(key) == expected, 'hosted_source_scope')
    require(os.environ.get('GITHUB_REF') in ('refs/heads/feature/protected-resident-model',
            'refs/heads/integration/resident-model-main-20261022'), 'hosted_source_scope')
    require(os.uname().machine == 'x86_64', 'host_architecture')
    source = source_binding(args.expected_source, deadline)
    base = module('protected-resident-image')
    launch = base.verify_kvm_launch()
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    require(args.work.is_absolute() and args.work.parent.resolve(strict=True) == parent
            and re.fullmatch(r'vp-resident-model-[0-9]+', args.work.name)
            and not args.work.exists() and not args.work.is_symlink(), 'hosted_work_path')
    args.work.mkdir(mode=0o700)
    runtime = Path('/run/user') / str(os.getuid())
    meta = runtime.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
            and stat.S_IMODE(meta.st_mode) == 0o700 and stat.S_ISSOCK((runtime / 'bus').lstat().st_mode),
            'user_manager')
    return base, source, launch, dict(ENV, XDG_RUNTIME_DIR=str(runtime),
                                    DBUS_SESSION_BUS_ADDRESS='unix:path=' + str(runtime / 'bus'))


def scope_path(raw, unit):
    require(type(raw) is str and raw.startswith('/user.slice/') and raw.endswith('/' + unit)
            and all(p not in ('', '.', '..') for p in raw[1:].split('/')), 'owned_cgroup')
    return Path('/sys/fs/cgroup' + raw)


def memory_values(raw):
    """Only four bounded /proc counters, never the raw input, enter evidence."""
    require(type(raw) is bytes and len(raw) <= 65536 and raw.isascii(), 'host_memory_snapshot')
    fields = (b'MemTotal', b'MemAvailable', b'Dirty', b'Writeback')
    values = {}
    for line in raw.splitlines():
        if line.startswith(b'WritebackTmp:'):
            continue  # A separate standard counter, not Writeback.
        if not line.startswith(fields):
            continue
        match = re.fullmatch(rb'(MemTotal|MemAvailable|Dirty|Writeback):[ \t]+([0-9]{1,16})[ \t]+kB', line)
        require(match is not None and match[1] not in values, 'host_memory_snapshot')
        values[match[1]] = int(match[2]) * 1024
    require(values.keys() == set(fields), 'host_memory_snapshot')
    total = values[b'MemTotal']
    require(0 < total < 2 ** 63 and all(0 <= values[key] <= total for key in fields[1:]),
            'host_memory_snapshot')
    return tuple(values[key] for key in fields)


def memory_snapshot(snapshot, deadline):
    """One observation; unavailable is not itself an admission decision."""
    require(snapshot in [dict(label=label, phase='before_scope_start')
                         for label in ('build', 'model', 'corrupt')]
            or snapshot == dict(label='baseline', phase='before_disks')
            or snapshot in [dict(label=label, phase='after_disk_operation')
                            for label in DISK_MEMORY_STAGES], 'host_memory_snapshot')
    snapshot.update(version=1, state='unavailable', mem_total_bytes=None, mem_available_bytes=None,
                    dirty_bytes=None, writeback_bytes=None, required_available_bytes=14 * GIB,
                    guest_memory_bytes=12 * GIB, qemu_memory_max_bytes=QEMU_BYTES,
                    qemu_swap_max_bytes=0, admitted=None)
    remaining(deadline)
    try:
        with Path('/proc/meminfo').open('rb') as source:
            total, available, dirty, writeback = memory_values(source.read(65537))
    except (OSError, ValueError):
        remaining(deadline)
        return
    remaining(deadline)
    snapshot.update(state='observed', mem_total_bytes=total, mem_available_bytes=available,
                    dirty_bytes=dirty, writeback_bytes=writeback)


def disk_memory_observation(observations, label, deadline):
    """One closed observation after each joined preparation operation, never admission."""
    require(type(observations) is list and len(observations) < len(DISK_MEMORY_STAGES)
            and label == DISK_MEMORY_STAGES[len(observations)], 'host_memory_snapshot')
    snapshot = dict(phase='after_disk_operation', label=label)
    observations.append(snapshot)
    memory_snapshot(snapshot, deadline)


def build_boot_diagnostic():
    return dict(version=1, diagnostic_only=True, acceptance_evidence=False,
        ssh=dict(attempts=0, first=None, last=None, incomplete=False),
        console=dict(state='unavailable', linux_banner_seen=None, kernel_panic_seen=None,
            initramfs_prompt_seen=None, cloud_init_seen=None, login_prompt_seen=None,
            ssh_service_seen=None))


def build_ssh_class(result):
    """Only existing SSH stderr/status, not stdout, keys, paths or remote output.

    Literal diagnostics: OpenSSH V_9_6_P1 sshconnect.c/sshconnect2.c/kex.c.
    Host-key rejection deliberately combines unknown/changed/revoked trust.
    """
    if (type(result) is not tuple or len(result) != 3 or type(result[0]) is not bytes or type(result[1]) is not bytes
            or len(result[1]) > 65536 or type(result[2]) is not int or not -255 <= result[2] <= 255):
        return 'unavailable'
    if result[2] == 0:
        return 'ready'
    if result[2] != 255:
        return 'other'
    lines = result[1].splitlines()
    if any(len(line) > 4096 or b'\x00' in line for line in lines):
        return 'unavailable'
    classes = set()
    for line in lines:
        if line == b'ssh: connect to host 127.0.0.1 port 22223: Connection refused':
            classes.add('refused')
        elif line in (b'Connection closed by 127.0.0.1 port 22223',
                      b'kex_exchange_identification: Connection closed by remote host'):
            classes.add('closed')
        elif line in (b'ssh: connect to host 127.0.0.1 port 22223: Connection timed out',
                      b'Connection timed out during banner exchange',
                      b'Connection to 127.0.0.1 port 22223 timed out'):
            classes.add('connect_timeout')
        elif line == b'Host key verification failed.':
            classes.add('host_key_rejected')
        elif re.fullmatch(rb'vpci@127\.0\.0\.1: Permission denied \([a-z0-9@.,_-]{1,256}\)\.', line):
            classes.add('auth_failed')
    return next(iter(classes)) if len(classes) == 1 else 'ambiguous' if classes else 'other'


def observe_build_ssh(diagnostic, result):
    # Optional projection must neither retry nor replace the original command
    # result. Saturation affects diagnostics only, never the readiness loop.
    row = diagnostic['ssh']
    try:
        label = build_ssh_class(result)
        if row['attempts'] == 1024:
            row['incomplete'] = True
            return
        row['attempts'] += 1
        if row['first'] is None:
            row['first'] = label
        row['last'] = label
        row['incomplete'] |= label == 'unavailable'
    except Exception:
        row['incomplete'] = True


def build_console_projection(work, payload_identity, deadline):
    """Read only this stopped build's console; text markers are not boot proof."""
    remaining(deadline)
    require(work.name == 'payload' and work.is_absolute() and work.resolve(strict=True) == work
            and directory_identity(work) == payload_identity, 'console_owner')
    identity = lambda meta: (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
    directory_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory = os.fstat(directory_fd)
        require((directory.st_dev, directory.st_ino) == payload_identity
                and directory.st_uid == os.getuid() and stat.S_IMODE(directory.st_mode) == 0o700,
                'console_owner')
        before = os.stat('build-console.log', dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= 4 * 1024 ** 2,
                'console_owner')
        with os.fdopen(os.open('build-console.log', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=directory_fd), 'rb') as stream:
            require(identity(os.fstat(stream.fileno())) == identity(before), 'console_changed')
            raw = stream.read(4 * 1024 ** 2 + 1)
            require(len(raw) == before.st_size and identity(os.fstat(stream.fileno())) == identity(before)
                    and identity(os.stat('build-console.log', dir_fd=directory_fd, follow_symlinks=False))
                    == identity(before), 'console_changed')
    finally:
        os.close(directory_fd)
    remaining(deadline)
    require(directory_identity(work) == payload_identity and b'\x00' not in raw, 'console_changed')
    raw.decode('utf-8')  # Malformed binary data is unavailable, never exported.
    raw = re.sub(rb'\x1b\[[0-9;]{0,32}m', b'', raw)  # Only terminal colour sequences.
    lines = raw.splitlines()
    require(all(len(line) <= 8192 for line in lines), 'console_bound')
    prefix = rb'(?:\[[ 0-9.]{1,24}\] )?'
    patterns = dict(linux_banner_seen=prefix + rb'Linux version .+',
        kernel_panic_seen=prefix + rb'Kernel panic - not syncing:.*',
        initramfs_prompt_seen=rb'\(initramfs\) ?',
        cloud_init_seen=prefix + rb'(?:cloud-init\[[0-9]{1,10}\]: )?Cloud-init v\. .+',
        login_prompt_seen=rb'volparossa-alpha login: ?',
        ssh_service_seen=rb'(?:\[  OK  \] )?Started ssh\.service - OpenBSD Secure Shell server\.')
    return dict(state='observed', **{name: any(re.fullmatch(pattern, line) for line in lines)
                                   for name, pattern in patterns.items()})


def memory_admission(observations, label, deadline):
    labels = ('build', 'model', 'corrupt')
    require(type(observations) is list and len(observations) < len(labels)
            and label == labels[len(observations)], 'host_memory_snapshot')
    snapshot = dict(phase='before_scope_start', label=label)
    observations.append(snapshot)
    memory_snapshot(snapshot, deadline)
    require(snapshot['state'] == 'observed', 'host_memory_snapshot')
    available = snapshot['mem_available_bytes']
    admitted = available >= 14 * GIB
    # Publish before the original admission require, including its false case.
    snapshot['admitted'] = admitted
    require(admitted, 'host_memory_headroom')
    return available


class Scope:
    """An inherited-credential scope, never a detached user-manager service."""
    def __init__(self, argv, work, deadline, env, seconds, label):
        self.label = label
        self.unit = 'vp-resident-' + label + '-' + uuid.uuid4().hex + '.scope'
        self.env, self.deadline, self.group = env, deadline, None
        self.process, self.log = None, None
        self.started, self.cleanup_confirmed = False, False
        self.logpath = work / (self.unit + '.log')
        self.argv = ['systemd-run', '--user', '--scope', '--quiet', '--expand-environment=no',
                     '--unit=' + self.unit, '--property=MemoryMax=' + str(QEMU_BYTES),
                     '--property=MemorySwapMax=0', '--property=RuntimeMaxSec=' + str(seconds),
                     '--property=TimeoutStopSec=15', *map(str, argv)]

    def state(self, deadline=None):
        raw = run(['systemctl', '--user', 'show', self.unit,
                   '--property=ActiveState,ControlGroup,Result'], deadline or self.deadline,
                  cap=15, env=self.env, check=False)[0].decode()
        return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)

    def start(self, memory_observations):
        self.available = memory_admission(memory_observations, self.label, self.deadline)
        self.log = self.logpath.open('xb')
        self.process = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL, stdout=self.log,
            stderr=subprocess.STDOUT, env=self.env, close_fds=True, start_new_session=True)
        self.started = True
        end = time.monotonic() + remaining(self.deadline, 30)
        while time.monotonic() < end:
            current = self.state()
            if current.get('ControlGroup'):
                self.group = scope_path(current['ControlGroup'], self.unit)
                require(int((self.group / 'memory.max').read_text()) == QEMU_BYTES
                        and (self.group / 'memory.swap.max').read_text().strip() == '0', 'qemu_limits')
                require(str(self.process.pid) in (self.group / 'cgroup.procs').read_text().split(), 'scope_process')
                return
            require(os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None,
                    'qemu_exited_before_scope')
            time.sleep(.1)
        raise ValueError('scope_start_timeout')

    def alive(self):
        remaining(self.deadline)
        require(self.logpath.stat().st_size <= 4 * 1024 ** 2, 'qemu_log_bound')
        return os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None

    def stop(self):
        if self.process is None:
            if self.started and not self.cleanup_confirmed:
                raise CleanupUnconfirmed('scope_cleanup_unconfirmed')
            return {'qemu_process_joined': True, 'scope_empty': True}
        token = CLEANUP_ACTIVE.set(True)
        try:
            return self._stop()
        finally:
            CLEANUP_ACTIVE.reset(token)

    def _stop(self):
        # Cleanup has its own finite grace, even when the original work expired.
        grace = time.monotonic() + 45
        manager_error = None
        try:
            state = self.state(grace)
            if state.get('ControlGroup'):
                observed = scope_path(state['ControlGroup'], self.unit)
                require(self.group is None or self.group == observed, 'scope_changed')
                self.group = observed
            run(['systemctl', '--user', 'stop', self.unit], grace, cap=25, env=self.env, check=False)
        except (OSError, ValueError, subprocess.SubprocessError, CleanupUnconfirmed) as error:
            manager_error = error
        finally:
            # The bus is not the only teardown path. Always join the child and
            # its retained process group even when the manager is unavailable.
            try:
                joined(self.process)
                self.process = None
            finally:
                self.log.close()
        try:
            if self.group is not None and self.group.exists():
                require('populated 0' in (self.group / 'cgroup.events').read_text().splitlines(), 'scope_not_empty')
            require(self.state(grace).get('ActiveState') in ('inactive', 'failed'), 'scope_still_active')
            if manager_error is not None:
                raise CleanupUnconfirmed('scope_manager_cleanup_unconfirmed') from manager_error
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise CleanupUnconfirmed('scope_cleanup_unconfirmed') from error
        self.cleanup_confirmed = True
        return {'qemu_process_joined': True, 'scope_empty': True}


def fish_script(operations):
    rows = ['set-pgroup false', 'set-network false', 'run']
    require(len(operations) <= 200000, 'fish_operations')
    for operation in operations:
        require(type(operation) in (list, tuple) and operation
                and re.fullmatch('[a-z][a-z0-9-]+', operation[0]), 'fish_operation')
        values = list(map(str, operation))
        require(all(v.isascii() and not any(c in v for c in '\r\n\x00') and len(v) <= 4096 for v in values),
                'fish_argument')
        rows.append(values[0] + ''.join(' ' + json.dumps(value) for value in values[1:]))
    raw = ('\n'.join(rows) + '\n').encode()
    require(len(raw) <= 64 * 1024 ** 2, 'fish_script_bound')
    return raw


class ImageTools:
    def __init__(self, work, kernel, deadline):
        self.work, self.deadline = work, deadline
        require(work.name == 'payload' and kernel.resolve(strict=True).parent == work.parent.parent
                and not kernel.is_symlink(), 'appliance_kernel_path')
        record = file_hash(kernel, deadline, 64 * 1024 ** 2)
        data = kernel.read_bytes()[:66200]
        require(data[514:518] == b'HdrS', 'appliance_kernel_header')
        offset = int.from_bytes(data[526:528], 'little') + 0x200
        release = re.split(b'[\x00 \t\n]', data[offset:offset + 132], maxsplit=1)[0].decode()
        require(release == os.uname().release and re.fullmatch('[A-Za-z0-9._+-]+', release), 'appliance_kernel_release')
        modules = Path('/lib/modules') / release
        require(modules.is_dir() and (modules / 'modules.dep').is_file(), 'appliance_modules')
        self.kernel, self.kernel_record = kernel, record
        self.env = dict(ENV, LIBGUESTFS_BACKEND='direct', LIBGUESTFS_BACKEND_SETTINGS='force_kvm',
                        LIBGUESTFS_MEMSIZE='2048', SUPERMIN_KERNEL=str(kernel), SUPERMIN_MODULES=str(modules),
                        SUPERMIN_KERNEL_VERSION=release, LIBGUESTFS_CACHEDIR=str(work), LIBGUESTFS_TMPDIR=str(work))

    def fish(self, image, operations, *, readonly=True, image_format='raw', timeout=600, operation=None):
        require(image_format in ('raw', 'qcow2') and type(readonly) is bool, 'fish_format')
        require(image.resolve(strict=True).is_relative_to(self.work), 'fish_image_path')
        require(file_hash(self.kernel, self.deadline, 64 * 1024 ** 2) == self.kernel_record, 'appliance_changed')
        script = self.work / ('fish-' + uuid.uuid4().hex + '.txt')
        write_new(script, fish_script(operations))
        maximum = 64 * 1024 ** 2 if operation == 'model_export_metadata' else 4 * 1024 ** 2
        try:
            output, _, _ = run(['guestfish', '--ro' if readonly else '--rw', '--format=' + image_format,
                '-a', image, '-f', script], self.deadline, cap=timeout, maximum=maximum, env=self.env)
            value = output.decode('utf-8', errors='strict')
        except BaseException:
            # Preserve the original failure, especially an unjoined tool group.
            # The per-execution child ledger also retains that cleanup failure.
            try:
                script.unlink()
            except OSError:
                pass
            raise
        else:
            script.unlink()
            return value


def root_geometry(device, details):
    """Bind the inspected filesystem to one complete byte range, never a guessed sector offset."""
    require(type(device) is str, 'root_geometry')
    match = re.fullmatch(r'(/dev/sd[a-z])([1-9][0-9]{0,2})', device)
    require(match is not None and type(details) is str and len(details) <= 16384, 'root_geometry')
    rows = details.splitlines()
    require(len(rows) >= 12 and rows[:4] == [device, 'debian', '13', 'ext4'], 'base_os')
    require(all(re.fullmatch('[1-9][0-9]{0,11}', value) for value in rows[4:6]), 'root_geometry')
    size, disk_size = map(int, rows[4:6])
    require(0 < size <= 16 * GIB and size % 4096 == 0, 'base_root_size')
    require(size <= disk_size <= RUNTIME_BYTES and disk_size % 512 == 0, 'root_geometry')
    # Exact libguestfs v1.52 generator/fish.ml + partition struct rendering;
    # daemon/parted.ml returns byte offsets, not sector numbers.
    pattern = (r'\[([0-9]{1,2})\] = \{\n  part_num: ([1-9][0-9]{0,2})\n'
               r'  part_start: ([0-9]{1,12})\n  part_end: ([0-9]{1,12})\n'
               r'  part_size: ([0-9]{1,12})\n\}\n')
    table = '\n'.join(rows[6:]) + '\n'
    entries = list(re.finditer(pattern, table))
    require(0 < len(entries) <= 64 and ''.join(row[0] for row in entries) == table, 'root_geometry')
    partitions, intervals = {}, []
    for index, row in enumerate(entries):
        ordinal, number, start, end, length = map(int, row.groups())
        require(ordinal == index and number not in partitions and 0 < start <= end < disk_size
                and length == end - start + 1 and start % 512 == length % 512 == 0,
                'root_geometry')
        require(all(end < old_start or start > old_end for old_start, old_end in intervals), 'root_geometry')
        partitions[number] = (start, length)
        intervals.append((start, end))
    require(int(match[2]) in partitions, 'root_geometry')
    offset, length = partitions[int(match[2])]
    require(length == size, 'root_geometry')
    return {'offset': offset, 'size': size, 'disk_size': disk_size}


def export_identity(path, maximum):
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid() and meta.st_nlink == 1
            and not meta.st_mode & 0o022 and 0 < meta.st_size <= maximum, 'root_export_source')
    return meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns


def export_root(work, geometry, pin, deadline):
    """Sparse, byte-equivalent export without another appliance/FileOut stream.

    This removes work, not proof of sufficient subsequent VM memory headroom.
    The same existing export budget covers validation, conversion and comparison.
    """
    end = time.monotonic() + remaining(deadline, 600)
    require(type(geometry) is dict and geometry.keys() == {'offset', 'size', 'disk_size'}
            and all(type(value) is int for value in geometry.values()), 'root_geometry')
    offset, size, disk_size = (geometry[name] for name in ('offset', 'size', 'disk_size'))
    require(0 < size <= 16 * GIB and size % 4096 == 0 and offset > 0 and offset % 512 == 0
            and offset + size <= disk_size <= RUNTIME_BYTES and disk_size % 512 == 0, 'root_geometry')
    directory_identity(work)
    require(work.name == 'payload' and work.is_absolute() and work.resolve(strict=True) == work,
            'root_export_source')
    image, target = work / 'base.qcow2', work / 'runtime-root.raw'
    before = export_identity(image, 4 * GIB)
    require(type(pin) is dict and type(pin.get('sha512')) is str
            and re.fullmatch('[0-9a-f]{128}', pin['sha512']),
            'root_export_source')
    require(file_hash(image, end, 4 * GIB, 'sha512')['sha512'] == pin['sha512'], 'root_export_source')
    with os.fdopen(os.open(image, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        header = source.read(104)
    # QEMU v8.2.2 docs/interop/qcow2.txt: refuse external backing/data sources
    # before any QEMU open. All interpretation remains in the existing QEMU.
    version = int.from_bytes(header[4:8], 'big')
    require(len(header) == 104 and header[:4] == b'QFI\xfb' and version in (2, 3)
            and int.from_bytes(header[8:20], 'big') == 0
            and int.from_bytes(header[24:32], 'big') == disk_size
            and int.from_bytes(header[32:36], 'big') == 0
            and (version == 2 or not int.from_bytes(header[72:80], 'big') & 4), 'root_export_source')
    require(export_identity(image, 4 * GIB) == before, 'root_export_source')
    # JSON filenames are parsed by QEMU's block layer, not a shell or keyval
    # parser; a comma/colon in the owned filename cannot inject another node.
    graph = 'json:' + encoded(dict(driver='raw', offset=offset, size=size,
        file=dict(driver='qcow2', file=dict(driver='file', filename=str(image))))).decode().strip()
    remaining(end)
    with target.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.truncate(size)
    created = export_identity(target, size)
    run(['qemu-img', 'convert', '-q', '-n', '-O', 'raw', '-S', '4096', '-m', '1',
         '-t', 'writeback', graph, target], end, cap=600, maximum=4096)
    written = export_identity(target, size)
    require(written[:3] == created[:3] and written[2] == size
            and export_identity(image, 4 * GIB) == before, 'root_export_source')
    remaining(end)
    # -s would also compare allocation, which intentionally differs for holes.
    # Equal sizes are checked separately; compare still checks every data byte.
    _, _, code = run(['qemu-img', 'compare', '-q', '-F', 'raw', graph, target],
                     end, cap=600, maximum=4096, check=False)
    require(code == 0, 'root_export_compare')
    require(export_identity(target, size) == written and export_identity(image, 4 * GIB) == before,
            'root_export_source')
    remaining(end)


def reserve_space(work, upcoming, label):
    statv = os.statvfs(work)
    free = statv.f_bavail * statv.f_frsize
    require(type(upcoming) is int and upcoming >= 0 and free >= upcoming + GIB, 'space_' + label)
    return {'phase': label, 'free_bytes': free, 'upcoming_bytes': upcoming}


def qemu_build(work):
    # Match the accepted legacy-BIOS build fixture; display stays headless.
    # The immutable runtime guest still uses its separate direct-kernel profile.
    # Do not mix implicit if=virtio devices with the explicit runtime disk:
    # QEMU creates the implicit devices later, regardless of argv placement.
    # Only the build overlay contains a bootable disk, not the exported ext4
    # filesystem or cloud-init seed. Bind firmware boot to that overlay alone.
    return ['qemu-system-x86_64', '-name', 'volparossa-resident-build', '-no-user-config', '-nodefaults',
        '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '2', '-m', '12288',
        '-device', 'VGA,id=video0,bus=pcie.0,addr=0x1',
        '-drive', 'if=none,id=build,format=qcow2,file=' + str(work / 'build.qcow2'),
        '-device', 'virtio-blk-pci,drive=build,bootindex=1',
        '-drive', 'if=none,id=seed,format=raw,readonly=on,file=' + str(work / 'seed.img'),
        '-device', 'virtio-blk-pci,drive=seed',
        '-drive', 'if=none,id=runtime,format=raw,file=' + str(work / 'runtime-root.raw'),
        '-device', 'virtio-blk-pci,drive=runtime,serial=vp-resident-runtime',
        '-boot', 'strict=on',
        '-device', 'virtio-rng-pci', '-device', 'virtio-net-pci,netdev=buildnet',
        '-netdev', 'user,id=buildnet,hostfwd=tcp:127.0.0.1:22223-:22',
        '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(work / 'build-console.log'),
        '-no-reboot', '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def qemu_model(work, closure, channel):
    initrd = module('protected-resident-model-initrd')
    return ['qemu-system-x86_64', '-name', 'volparossa-resident-public-model', '-no-user-config', '-nodefaults',
        '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '2', '-m', '12288',
        '-kernel', str(closure['kernel']), '-initrd', str(work / 'model-initrd.img'), '-append', initrd.CMDLINE,
        '-drive', 'if=virtio,format=raw,readonly=on,file=' + str(work / 'runtime-root.raw'),
        '-drive', 'if=virtio,format=raw,readonly=on,file=' + str(work / 'verity.raw'),
        '-device', 'virtio-serial-pci', '-chardev', 'socket,id=resident,path=' + str(channel) + ',server=on,wait=off',
        '-device', 'virtserialport,chardev=resident,name=org.volparossa.resident',
        '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(work / 'model-console.log'),
        '-no-reboot', '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def package_unit_projection(raw, unit):
    require(type(raw) is bytes and len(raw) <= 2048, 'package_unit_diagnostic')
    fields = {}
    for row in raw.decode('ascii').splitlines():
        key, separator, value = row.partition('=')
        require(separator and key not in fields, 'package_unit_diagnostic')
        fields[key] = value
    require(fields.keys() == {'Result', 'ExecMainCode', 'ExecMainStatus', 'ActiveState', 'SubState', 'ControlGroup'}
            and fields['ControlGroup'] in ('', '/system.slice/' + unit), 'package_unit_diagnostic')
    require(fields['Result'] in ('success', 'exit-code', 'signal', 'core-dump', 'watchdog', 'timeout',
                'oom-kill', 'resources', 'protocol', 'start-limit-hit', 'exec-condition')
            and fields['ActiveState'] in ('activating', 'active', 'inactive', 'deactivating', 'failed', 'reloading')
            and fields['SubState'] in ('dead', 'condition', 'start-pre', 'start', 'start-post', 'running',
                'exited', 'reload', 'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-sigterm',
                'final-sigkill', 'failed', 'auto-restart', 'auto-restart-queued'), 'package_unit_diagnostic')
    require(re.fullmatch('[0-3]', fields['ExecMainCode'])
            and re.fullmatch('0|[1-9][0-9]{0,2}', fields['ExecMainStatus'])
            and int(fields['ExecMainStatus']) <= 255, 'package_unit_diagnostic')
    return dict(result=fields['Result'], exec_main_code=int(fields['ExecMainCode']),
                exec_main_status=int(fields['ExecMainStatus']), active_state=fields['ActiveState'],
                sub_state=fields['SubState'])


def package_installer_projection(raw, mode):
    require(mode in ('build', 'runtime') and type(raw) is bytes and len(raw) <= 16384,
            'package_installer_diagnostic')
    value = module('protected-resident-model-workload').parse(raw)
    flags = ('archives_verified', 'status_verified', 'triggers_clear', 'audit_clear', 'policy_restored',
             'runtime_unmounted', 'namespace_joined', 'direct_child_groups_joined')
    forbidden = ('complete_guest_cleanup', 'model_execution', 'worker_execution', 'private_inputs',
                 'hardware_attestation')
    plan_failures = ('plan_command_exit', 'plan_command_deadline', 'plan_command_output', 'plan_bytes',
                     'plan_schema', 'plan_outside_lock', 'plan_duplicate', 'plan_missing',
                     'plan_removal', 'plan_before', 'plan_encoding')
    install_failures = ('install_command_exit', 'install_command_deadline', 'install_command_output',
                        'install_command_cleanup')
    preparation_phases = ('runtime_device', 'runtime_fsck', 'runtime_resize', 'runtime_mount',
                          'runtime_bootstrap', 'archive_mount')
    preparation_failures = ('preparation_command_exit', 'preparation_command_deadline',
        'preparation_command_output', 'preparation_command_cleanup', 'preparation_deadline',
        'preparation_missing', 'preparation_permission', 'preparation_io')
    preparation_guards = {
        'runtime_device': ('runtime_alias', 'runtime_path', 'runtime_device', 'runtime_serial',
            'runtime_root_device', 'runtime_already_mounted', 'runtime_changed', 'runtime_size',
            'runtime_ext4', 'mountinfo_bound', 'kernel_file_bound'),
        'runtime_bootstrap': ('runtime_debian', 'runtime_mountpoint', 'input_file', 'input_changed'),
    }
    guard_failures = tuple(code for codes in preparation_guards.values() for code in codes)
    require(type(value) is dict and value.keys() == {'version', 'kind', 'mode', 'state', 'phase', 'failure',
                'package_lock_sha256', 'packages_verified', 'archive_bytes', 'descendants_joined',
                'controller_cgroup_cleanup_required', *flags, *forbidden}, 'package_installer_diagnostic')
    require(type(value['version']) is int and value['version'] == 1
            and value['kind'] == 'protected-resident-offline-package-install' and value['mode'] == mode
            and value['package_lock_sha256'] == LOCK_SHA and value['state'] in ('failed', 'configured')
            and value['phase'] in ('guard', 'archives', 'namespace', 'status_before', *preparation_phases,
                'package_cache', 'package_plan', 'package_install', 'package_verify', 'unmount', 'complete')
            and value['failure'] in (None, 'installation_failed', 'cleanup_unconfirmed',
                                    *plan_failures, *install_failures, *preparation_failures, *guard_failures)
            and all(type(value[key]) is bool for key in flags)
            and all(value[key] is False for key in forbidden)
            and value['controller_cgroup_cleanup_required'] is True and value['descendants_joined'] is None,
            'package_installer_diagnostic')
    count = 199 if mode == 'build' else 65
    require(type(value['packages_verified']) is int and 0 <= value['packages_verified'] <= count
            and type(value['archive_bytes']) is int and 0 <= value['archive_bytes'] <= 512 * 1024 ** 2,
            'package_installer_diagnostic')
    if value['state'] == 'configured':
        require(value['phase'] == 'complete' and value['failure'] is None
                and value['packages_verified'] == count and all(value[key] for key in flags),
                'package_installer_diagnostic')
    else:
        require(value['failure'] is not None, 'package_installer_diagnostic')
    if value['failure'] in plan_failures:
        require(value['state'] == 'failed' and value['phase'] == 'package_plan',
                'package_installer_diagnostic')
    if value['failure'] in install_failures:
        require(value['state'] == 'failed' and value['phase'] == 'package_install',
                'package_installer_diagnostic')
    if value['phase'] in preparation_phases:
        require(value['state'] == 'failed' and (mode == 'runtime' or value['phase'] == 'archive_mount')
                and value['packages_verified'] == 0
                and not any(value[key] for key in ('status_verified', 'triggers_clear', 'audit_clear')),
                'package_installer_diagnostic')
    if value['failure'] in preparation_failures or value['failure'] in guard_failures:
        require(value['phase'] in preparation_phases and (value['failure'] in preparation_failures
                or value['failure'] in preparation_guards.get(value['phase'], ())),
                'package_installer_diagnostic')
    return {key: value[key] for key in ('state', 'phase', 'failure', 'packages_verified', *flags)}


# Executed only in the existing guest, after its failed unit has stopped and its
# cgroup is empty. No journal or arbitrary path is read; errors emit no details.
PACKAGE_RECEIPT_READ = '''import os, stat, sys
fds = []
def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
try:
    mode = sys.argv[1]
    assert mode in ('build', 'runtime')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds.append(directory)
    chain = []
    for name in ('var', 'lib', 'volparossa-resident'):
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        fds.append(child)
        meta = os.fstat(child)
        assert stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022
        chain.append((directory, name, child, identity(meta)))
        directory = child
    name = 'install-' + mode + '.json'
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    fds.append(fd)
    before = os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
    assert stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 16384
    raw = os.read(fd, 16385)
    assert len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before)
    assert identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(before)
    for parent, name, child, before in chain:
        assert identity(os.fstat(child)) == before
        assert identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before
    sys.stdout.buffer.write(raw)
except Exception:
    raise SystemExit(1)
finally:
    for fd in reversed(fds):
        os.close(fd)
'''


def observe_package_failure(guest, unit, raw, grace, diagnostics):
    mode = {'vp-resident-install-build.service': 'build',
            'vp-resident-install-runtime.service': 'runtime'}.get(unit)
    if mode is None or diagnostics:
        return
    record = dict(version=1, mode=mode, unit_last_observed=None, installer=None,
                  diagnostic_only=True, acceptance_evidence=False)
    diagnostics.append(record)
    try:
        record['unit_last_observed'] = package_unit_projection(raw, unit)
    except Exception:
        pass
    try:
        remaining(grace, 5)
        reply = guest.ssh(['sudo', '-n', 'python3', '-c', PACKAGE_RECEIPT_READ, mode],
                          cap=5, deadline=grace, maximum=20480, check=False)
        if reply[2] == 0:
            record['installer'] = package_installer_projection(reply[0], mode)
    except Exception:
        pass  # Missing, malformed, cancelled or stalled evidence is unknown.


def builder_failure_projection(raw, source):
    require(type(raw) is bytes and len(raw) <= 16384
            and type(source) is dict and source.keys() == {'commit', 'tree'}
            and all(type(value) is str and re.fullmatch('[0-9a-f]{40}', value)
                    for value in source.values()), 'builder_diagnostic')
    value = module('protected-resident-model-workload').parse(raw)
    forbidden = ('assets_exported', 'model_execution', 'worker_execution', 'private_inputs',
                 'hardware_attestation', 'production_approval', 'complete_guest_cleanup', 'scratch_removed')
    base = {'version', 'kind', 'state', 'phase', 'source_commit', 'code_helper_commit',
            'code_helper_sha256', 'package_lock_sha256', 'controller_cgroup_cleanup_required',
            'direct_child_groups_joined', 'descendants_joined', *forbidden}
    require(type(value) is dict and base <= value.keys()
            and type(value['version']) is int and value['version'] == 1
            and value['kind'] == 'protected-resident-public-model-build' and value['state'] == 'failed'
            and value['phase'] in ('source', 'packages', 'build', 'provision', 'export')
            and value['source_commit'] == source['commit'] and value['code_helper_commit'] == CODE
            and value['code_helper_sha256'] == HELPER_SHA and value['package_lock_sha256'] == LOCK_SHA
            and all(value[key] is False for key in forbidden)
            and value['controller_cgroup_cleanup_required'] is True and value['descendants_joined'] is None
            and type(value['direct_child_groups_joined']) is bool, 'builder_diagnostic')
    required, optional = set(), set()
    phase = value['phase']
    if phase == 'source':
        optional.add('source_tree')  # An interrupt can precede the next phase assignment.
    else:
        required.add('source_tree')
    if 'source_tree' in value or phase != 'source':
        require(value.get('source_tree') == source['tree'], 'builder_diagnostic')
    if phase == 'packages':
        optional.add('installed_build_packages')
    elif phase in ('build', 'provision', 'export'):
        required.add('installed_build_packages')
    if phase == 'provision':
        optional.update(('provision', 'native_build_manifest_sha256'))
    elif phase == 'export':
        required.update(('provision', 'native_build_manifest_sha256'))
        optional.update(('export', 'export_diagnostic'))
    require(base | required <= value.keys() <= base | required | optional, 'builder_diagnostic')
    if 'installed_build_packages' in value:
        require(type(value['installed_build_packages']) is int and value['installed_build_packages'] == 199,
                'builder_diagnostic')
    if 'provision' in value:
        provision = value['provision']
        require(type(provision) is dict and provision.keys() == {'model_id', 'revision', 'model_profile',
            'download_bytes', 'budget_bytes', 'installed_wheels', 'model_pins_sha256', 'requirements_sha256'},
            'builder_diagnostic')
        require(type(provision['model_id']) is str and re.fullmatch('[A-Za-z0-9_./-]{1,128}', provision['model_id'])
                and type(provision['revision']) is str and re.fullmatch('[0-9a-f]{40}', provision['revision'])
                and type(provision['model_profile']) is str
                and re.fullmatch('[a-z0-9-]{1,128}', provision['model_profile']), 'builder_diagnostic')
        for key in ('model_pins_sha256', 'requirements_sha256'):
            require(type(provision[key]) is str and re.fullmatch('[0-9a-f]{64}', provision[key]), 'builder_diagnostic')
        for key, maximum in (('download_bytes', 20 * GIB), ('budget_bytes', 20 * GIB), ('installed_wheels', 65536)):
            require(type(provision[key]) is int and 0 < provision[key] <= maximum, 'builder_diagnostic')
    if 'native_build_manifest_sha256' in value:
        require('provision' in value and type(value['native_build_manifest_sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', value['native_build_manifest_sha256']), 'builder_diagnostic')
    if 'export' in value:
        exported = value['export']
        require(type(exported) is dict and exported.keys() == {'inventory_sha256', 'workload_sha256',
                'native_backend_sha256', 'asset_files', 'asset_bytes'}, 'builder_diagnostic')
        for key in ('inventory_sha256', 'workload_sha256', 'native_backend_sha256'):
            require(type(exported[key]) is str and re.fullmatch('[0-9a-f]{64}', exported[key]), 'builder_diagnostic')
        for key, maximum in (('asset_files', 65536), ('asset_bytes', 32 * GIB)):
            require(type(exported[key]) is int and 0 < exported[key] <= maximum, 'builder_diagnostic')
    diagnostic = value.get('export_diagnostic')
    if 'export_diagnostic' in value:
        contract = module('protected-resident-model-build')  # Source-owned stdlib schema, no guest assets.
        require(type(diagnostic) is dict and diagnostic.keys() == {'operation', 'reason'}
                and type(diagnostic['operation']) is str and diagnostic['operation'] in contract.EXPORT_ERRORS,
                'builder_diagnostic')
        operation, reason = diagnostic['operation'], diagnostic['reason']
        require(reason is None or (type(reason) is str
                and reason in contract.EXPORT_ERRORS[operation] | contract.EXPORT_CATEGORIES), 'builder_diagnostic')
        if reason is not None:
            require((reason == 'cleanup_unconfirmed') == (not value['direct_child_groups_joined']),
                    'builder_diagnostic')
        if operation in ('source_recheck', 'final_deadline'):
            require('export' in value, 'builder_diagnostic')
        elif operation != 'write_inventory':
            require('export' not in value, 'builder_diagnostic')
        # An interrupt can occur after export returned but before the next label.
        if 'export' in value and operation == 'write_inventory':
            require(reason in (None, 'interrupted'), 'builder_diagnostic')
    # Later-stage nested metadata is validated but never exported as a diagnostic.
    return dict(state=value['state'], phase=phase, source_tree_bound='source_tree' in value,
        installed_build_packages=value.get('installed_build_packages'),
        export_returned='export' in value, export_diagnostic=diagnostic,
        direct_child_groups_joined=value['direct_child_groups_joined'],
        controller_cgroup_cleanup_required=True, descendants_joined=None,
        **{key: False for key in forbidden})


# Exact vpci-owned output only, after the original builder unit/cgroup are joined.
# The caller supplies observed numeric owner IDs, never a path or command.
BUILDER_RECEIPT_READ = '''import os, stat, sys
fds = []
def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
try:
    assert len(sys.argv) == 3
    uid, gid = (int(value) for value in sys.argv[1:])
    assert all(0 < value < 2**31 and str(value) == raw for value, raw in zip((uid, gid), sys.argv[1:]))
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds.append(directory)
    root_meta = identity(os.fstat(directory))
    assert stat.S_ISDIR(root_meta[2]) and root_meta[3] == 0 and not root_meta[2] & 0o022
    chain = []
    for name, owner in (('home', 0), ('vpci', uid), ('resident-output', uid)):
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        fds.append(child)
        meta = os.fstat(child)
        assert stat.S_ISDIR(meta.st_mode) and meta.st_uid == owner and not meta.st_mode & 0o022
        if name in ('vpci', 'resident-output'):
            assert meta.st_gid == gid
        if name == 'resident-output':
            assert stat.S_IMODE(meta.st_mode) == 0o700
        chain.append((directory, name, child, identity(meta)))
        directory = child
    name = 'build-result.json'
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    fds.append(fd)
    before = os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_gid == gid and before.st_nlink == 1
    assert stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 16384
    raw = os.read(fd, 16385)
    assert len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before)
    assert identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(before)
    for parent, name, child, before in chain:
        assert identity(os.fstat(child)) == before
        assert identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before
    assert identity(os.fstat(fds[0])) == root_meta
    sys.stdout.buffer.write(raw)
except Exception:
    raise SystemExit(1)
finally:
    for fd in reversed(fds):
        os.close(fd)
'''


def observe_builder_failure(guest, unit, raw, grace, diagnostics, binding):
    if unit != 'vp-resident-builder.service' or diagnostics:
        return
    record = dict(version=1, unit_last_observed=None, builder=None,
                  diagnostic_only=True, acceptance_evidence=False)
    diagnostics.append(record)
    try:
        record['unit_last_observed'] = package_unit_projection(raw, unit)
    except Exception:
        pass
    try:
        require(type(binding) is dict and binding.keys() == {'source', 'uid', 'gid'}
                and all(type(binding[key]) is int and 0 < binding[key] < 2 ** 31
                        for key in ('uid', 'gid'))
                and type(binding['source']) is dict and binding['source'].keys() == {'commit', 'tree'}
                and all(type(value) is str and re.fullmatch('[0-9a-f]{40}', value)
                        for value in binding['source'].values()), 'builder_diagnostic')
        remaining(grace, 5)
        reply = guest.ssh(['sudo', '-n', 'python3', '-c', BUILDER_RECEIPT_READ,
                          str(binding['uid']), str(binding['gid'])],
                         cap=5, deadline=grace, maximum=20480, check=False)
        if reply[2] == 0:
            record['builder'] = builder_failure_projection(reply[0], binding['source'])
    except Exception:
        pass  # Guard failures before receipt creation remain unknown, never "source".


class Guest:
    def __init__(self, work, deadline):
        self.work, self.deadline = work, deadline
        self.options = ['-F', '/dev/null', '-i', str(work / 'ssh-key'), '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5', '-o', 'ClearAllForwardings=yes', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', '-o', 'ForwardAgent=no', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'PasswordAuthentication=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
            '-o', 'RequestTTY=no', '-o', 'StrictHostKeyChecking=yes', '-o', 'Tunnel=no',
            '-o', 'UserKnownHostsFile=' + str(work / 'known-hosts')]

    def ssh(self, argv, *, cap=120, check=True, deadline=None, maximum=16 * 1024 ** 2):
        return run(['ssh', *self.options, '-p', '22223', 'vpci@127.0.0.1', shlex.join(map(str, argv))],
                   deadline or self.deadline, cap=cap, check=check, maximum=maximum)

    def upload(self, source, target):
        run(['scp', *self.options, '-P', '22223', source, 'vpci@127.0.0.1:' + target],
            self.deadline, cap=600)

    def unit(self, name, argv, guest_deadline, *, user='root', diagnostics=None, builder_binding=None):
        require(name in ('vp-resident-install-build', 'vp-resident-install-runtime', 'vp-resident-builder'),
                'guest_unit_name')
        unit = name + '.service'
        cap = int(remaining(self.deadline, 7200))
        unit_end = time.monotonic() + remaining(self.deadline, cap)
        failed, raw = False, None
        try:
            # RemainAfterExit preserves the original status. Do not combine it
            # with --wait: active(exited) is intentionally not an inactive unit.
            self.ssh(['sudo', '-n', 'systemd-run', '--unit=' + unit,
                '--quiet', '--expand-environment=no', '--property=Type=exec', '--property=RemainAfterExit=yes',
                '--property=KillMode=control-group', '--property=RuntimeMaxSec=' + str(cap),
                '--property=TimeoutStopSec=15', '--property=MemoryMax=10G', '--property=MemorySwapMax=0',
                '--property=StandardOutput=null', '--property=StandardError=journal',
                '--property=User=' + user, *argv, '--deadline-monotonic-ns', str(guest_deadline)], cap=30)
            while True:
                remaining(unit_end, cap)
                raw = self.ssh(['sudo', '-n', 'systemctl', 'show', unit,
                    '--property=Result,ExecMainStatus,ExecMainCode,ActiveState,SubState,ControlGroup'])[0]
                state = raw.decode()
                fields = dict(row.split('=', 1) for row in state.splitlines() if '=' in row)
                require(fields.get('ControlGroup') in ('', '/system.slice/' + unit), 'guest_unit_cgroup')
                require(fields.get('Result') == 'success' and fields.get('ActiveState') in ('activating', 'active'),
                        'guest_unit_failed')
                if fields.get('SubState') == 'exited':
                    require(fields.get('ExecMainCode') == '1' and fields.get('ExecMainStatus') == '0',
                            'guest_unit_failed')
                    break
                time.sleep(1)
        except BaseException:
            failed = True
            raise
        finally:
            grace = time.monotonic() + 40
            stopped = self.ssh(['sudo', '-n', 'systemctl', 'stop', unit], cap=25, deadline=grace, check=False)
            # A stopped unit's exact cgroup either disappeared or is unpopulated.
            proof = ('import pathlib; p=pathlib.Path("/sys/fs/cgroup/system.slice/' + unit + '"); '
                     'assert not p.exists() or "populated 0" in (p/"cgroup.events").read_text().splitlines()')
            self.ssh(['sudo', '-n', 'python3', '-c', proof], cap=10, deadline=grace)
            if failed and diagnostics is not None and stopped[2] == 0:
                try:
                    if unit == 'vp-resident-builder.service':
                        observe_builder_failure(self, unit, raw, grace, diagnostics, builder_binding)
                    else:
                        observe_package_failure(self, unit, raw, grace, diagnostics)
                except Exception:
                    pass  # Optional projection never replaces failure or cleanup.
        return True


def seed(work, deadline):
    for name in ('ssh-key', 'host-key'):
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'volparossa-public-fixture', '-f', work / name], deadline)
    public = (work / 'ssh-key.pub').read_text().strip()
    host = (work / 'host-key.pub').read_text().strip()
    write_new(work / 'known-hosts', ('[127.0.0.1]:22223 ' + host + '\n').encode())
    data = '#cloud-config\nusers:\n  - name: vpci\n    groups: [sudo]\n    sudo: "ALL=(ALL) NOPASSWD:ALL"\n'
    data += '    shell: /bin/bash\n    lock_passwd: true\n    ssh_authorized_keys:\n      - ' + public + '\n'
    data += 'ssh_pwauth: false\ndisable_root: true\nssh_deletekeys: true\nssh_keys:\n  ed25519_private: |\n'
    data += ''.join('    ' + line + '\n' for line in (work / 'host-key').read_text().splitlines())
    data += '  ed25519_public: ' + host + '\ngrowpart:\n  mode: auto\n  devices: [/]\nresize_rootfs: true\n'
    write_new(work / 'user-data', data.encode())
    write_new(work / 'meta-data', ('instance-id: vp-resident-' + uuid.uuid4().hex + '\nlocal-hostname: volparossa-alpha\n').encode())
    run(['cloud-localds', work / 'seed.img', work / 'user-data', work / 'meta-data'], deadline)


def source_bundle(work, expected, requester, deadline):
    raw = run(['git', '-C', ROOT, 'archive', '--format=tar', '--prefix=core/', expected],
              deadline, maximum=512 * 1024 ** 2)[0]
    write_new(work / 'inputs.tar', raw)
    url = 'https://raw.githubusercontent.com/VOLPAROSSA/volparossa-code/' + CODE + '/scripts/opencode_native_cpu.py'
    with urllib.request.urlopen(url, timeout=30) as response:
        helper = response.read(1024 ** 2 + 1)
    require(len(helper) <= 1024 ** 2 and hashlib.sha256(helper).hexdigest() == HELPER_SHA, 'helper_digest')
    policy = json.loads(run([requester, 'compute', 'resident-public-trial', '--socket', work / 'unused.sock',
        '--certificate', work / 'server.der', '--requester-key', work / 'requester.seed',
        '--workload-sha256', '0' * 64], deadline)[0])
    fixture = {key: policy[key] for key in ('requester_key', 'public_input_sha256')}
    additions = {'core.commit': run(['git', '-C', ROOT, 'cat-file', 'commit', expected], deadline)[0],
                 'code/scripts/opencode_native_cpu.py': helper, 'fixture/requester.json': encoded(fixture),
                 'fixture/server.der': (work / 'server.der').read_bytes(),
                 'fixture/server-key.der': (work / 'server-key.der').read_bytes()}
    with tarfile.open(work / 'inputs.tar', 'a') as archive:
        for name, data in additions.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o600
            archive.addfile(info, io.BytesIO(data))
    return file_hash(work / 'inputs.tar', deadline, 512 * 1024 ** 2)


def public_keys(work, deadline):
    write_new(work / 'requester.seed', os.urandom(32))
    run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-days', '2', '-subj', '/CN=resident.test', '-addext', 'subjectAltName=DNS:resident.test',
        '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
        '-addext', 'extendedKeyUsage=serverAuth', '-keyout', work / 'server.pem', '-out', work / 'certificate.pem'], deadline)
    run(['openssl', 'x509', '-in', work / 'certificate.pem', '-outform', 'DER', '-out', work / 'server.der'], deadline)
    run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', work / 'server.pem', '-outform', 'DER',
         '-out', work / 'server-key.der'], deadline)


def boot_record(raw, outcome):
    require(len(raw) <= 4 * 1024 ** 2, 'console_bound')
    matches = [line[len(BOOT):] for line in raw.splitlines() if line.startswith(BOOT)]
    require(len(matches) == 1, 'one_model_boot_receipt')
    value = module('protected-resident-model-workload').parse(matches[0])
    flags = ('verity_verified', 'root_readonly', 'write_denied', 'entrypoint_invoked', 'process_exit_zero')
    forbidden = ('hardware_attestation', 'private_inputs', 'model_execution', 'worker_execution',
                 'guest_key_origin_proven', 'worker_cleanup_confirmed')
    require(type(value) is dict and value.keys() == {'version', 'outcome', 'stage', *flags, *forbidden}
            and type(value['version']) is int and value['version'] == 1 and value['outcome'] == outcome,
            'model_boot_outcome')
    require(outcome in ('guest_process_returned', 'integrity_failure'), 'model_boot_outcome')
    good = outcome == 'guest_process_returned'
    require(value['stage'] == ('complete' if good else 'verity_read')
            and all(value[key] is good for key in flags), 'model_boot_proof')
    for key in forbidden:
        require(value.get(key) is False, 'model_boot_scope')
    return value


def ready_record(raw):
    require(type(raw) is bytes and len(raw) <= 4 * 1024 ** 2, 'console_bound')
    rows = [line[len(READY):] for line in raw.splitlines() if line.startswith(READY)]
    if not rows:
        return False
    require(len(rows) == 1, 'one_model_ready_receipt')
    expected = {'version': 1, 'scope': 'public_fixture', 'privileges_dropped': True,
        'hardware_attestation': False, 'private_inputs': False, 'model_execution': False,
        'worker_execution': False}
    require(encoded(module('protected-resident-model-workload').parse(rows[0])) == encoded(expected),
            'model_ready_receipt')
    return True


def requester_record(raw, workload):
    require(type(raw) is bytes and len(raw) <= 65536 and re.fullmatch('[0-9a-f]{64}', workload),
            'requester_receipt_bound')
    value = module('protected-resident-model-workload').parse(raw)
    require(type(value) is dict and value.keys() == {'version', 'kind', 'public_fixture_only',
        'workload_sha256', 'tls_spki_sha256', 'turns', 'final_cleanup', 'private_inputs',
        'hardware_attestation', 'guest_key_origin_proven', 'production_approval'}
        and type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'public_resident_requester' and value['public_fixture_only'] is True
        and value['workload_sha256'] == workload and type(value['tls_spki_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}', value['tls_spki_sha256']), 'requester_receipt_scope')
    require(all(value[key] is False for key in ('private_inputs', 'hardware_attestation',
                'guest_key_origin_proven', 'production_approval')), 'requester_receipt_scope')
    require(type(value['turns']) is list and len(value['turns']) == 2, 'requester_turns')
    for index, (turn, answer) in enumerate(zip(value['turns'], ('READY', '4')), 1):
        require(type(turn) is dict and turn.keys() == {'sequence', 'answer', 'prompt_tokens',
                'generated_tokens', 'per_turn_cleanup'} and type(turn['sequence']) is int
                and turn['sequence'] == index and type(turn['answer']) is str and turn['answer'].strip() == answer,
                'requester_turn')
        require(type(turn['prompt_tokens']) is int and 1 <= turn['prompt_tokens'] <= 12288
                and type(turn['generated_tokens']) is int and 1 <= turn['generated_tokens'] <= 1024,
                'requester_tokens')
        require(encoded(turn['per_turn_cleanup']) == encoded({'version': 2, 'request_files_removed': True,
                'session_closed': False, 'session_private_state_retained': True}), 'requester_turn_cleanup')
    require(encoded(value['final_cleanup']) == encoded({'version': 1, 'child_reaped': True, 'private_state_removed': True}),
            'requester_final_cleanup')
    return value


def directory_identity(path):
    meta = path.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
            and stat.S_IMODE(meta.st_mode) == 0o700, 'scratch_directory')
    return meta.st_dev, meta.st_ino


def remove_model_channel(work, scope):
    """QEMU may already have removed its listener, but must first be joined."""
    require(scope.label == 'model' and scope.started and scope.cleanup_confirmed
            and scope.process is None, 'model_channel_cleanup_scope')
    channel = work / 'channel.sock'
    try:
        meta = channel.lstat()
    except FileNotFoundError:
        return
    require(stat.S_ISSOCK(meta.st_mode) and meta.st_uid == os.getuid(), 'model_channel_cleanup_path')
    try:
        channel.unlink()
    except FileNotFoundError:
        pass  # The joined QEMU may already have removed this fixed owned path.


def remove_payload(work, parent_identity, payload_identity):
    """Remove only this invocation's payload; never its public evidence sibling."""
    require(work.name == 'payload' and shutil.rmtree.avoids_symlink_attacks, 'scratch_directory')
    require(directory_identity(work.parent) == parent_identity
            and directory_identity(work) == payload_identity, 'scratch_directory')
    parent_fd = os.open(work.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent = os.fstat(parent_fd)
        require((parent.st_dev, parent.st_ino) == parent_identity, 'scratch_directory')
        payload_fd = os.open('payload', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            child = os.fstat(payload_fd)
            require((child.st_dev, child.st_ino) == payload_identity, 'scratch_directory')
            # Bind recursive removal to the already verified directory, not a
            # name that can be replaced between validation and rmtree's open.
            # POSIX refuses removing '.', so remove only that final empty name
            # through the retained parent descriptor after checking it again.
            def root_only(function, path, error):
                if function is not os.rmdir or path != '.' or error[1].errno != errno.EINVAL:
                    raise error[1]
            shutil.rmtree('.', dir_fd=payload_fd, onerror=root_only)
            require(not os.listdir(payload_fd), 'scratch_directory')
            current = os.stat('payload', dir_fd=parent_fd, follow_symlinks=False)
            require(stat.S_ISDIR(current.st_mode)
                    and (current.st_dev, current.st_ino) == payload_identity, 'scratch_directory')
            os.rmdir('payload', dir_fd=parent_fd)
        finally:
            os.close(payload_fd)
        try:
            os.stat('payload', dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError('scratch_directory')
    finally:
        os.close(parent_fd)


def execute(args):
    pending = {}
    token = TOOL_PROCESSES.set(pending)
    try:
        return execute_owned(args, pending)
    finally:
        TOOL_PROCESSES.reset(token)


def execute_owned(args, pending):
    os.umask(0o077)
    deadline = time.monotonic() + MAX_SECONDS
    base, source, launch, env = hosted(args, deadline)
    work = args.work / 'payload'
    evidence = args.work / 'evidence'
    evidence.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    parent_identity, payload_identity = directory_identity(args.work), directory_identity(work)
    report = dict(version=1, kind='protected-resident-public-model-trial', source=source,
                  state='failed', phase='prepare', process_launch=launch, model_execution=False,
                  private_inputs=False, hardware_attestation=False, confidential_execution=False,
                  production_approval=False, vm_cleanup_confirmed=False, scratch_removed=False,
                  tool_cleanup_confirmed=False, scratch_cleanup_failure=None,
                  host_observed_routes_dns_unchanged=False,
                  host_configuration_checkpoint=dict(version=1, mode='supported_ipv6_reference_metadata_v1',
                      eligible=False, classification='UNAVAILABLE', raw_equal=None),
                  host_configuration_checkpoint_accepted=False,
                  memory_admissions=[], disk_memory_observations=[],
                  build_boot_diagnostic=build_boot_diagnostic(), guest_package_diagnostics=[],
                  guest_builder_diagnostics=[])
    current = build_scope = None
    scopes = []
    workload_complete = False
    try:
        images = ImageTools(work, args.appliance_kernel, deadline)
        require(args.requester.resolve(strict=True).is_relative_to(ROOT / 'target'), 'requester_source_path')
        report['requester_binary'] = file_hash(args.requester, deadline, 256 * 1024 ** 2)
        host_observer = module('protected-resident-model-host-observation')
        host_before = host_observer.capture()
        report['host_before'] = host_observer.hashes(host_before)
        report['host_observation'] = dict(schema=1, before=host_before, after=None, comparison=None)
        require(host_observer.complete(host_before), 'host_observation_capture_failed')
        public_keys(work, deadline)
        bundle = source_bundle(work, args.expected_source, args.requester, deadline)
        lock_path = HERE / 'protected-resident-model-debian-lock-v1.json'
        require(hashlib.sha256(lock_path.read_bytes()).hexdigest() == LOCK_SHA, 'debian_lock')
        lock = json.loads(lock_path.read_bytes())
        pins = json.loads((HERE / 'protected-resident-image-pins-v1.json').read_bytes())
        image_pin = json.loads((ROOT / pins['debian_image_manifest']).read_bytes())
        report['phase'] = 'download'
        reserve_space(work, 6 * GIB, 'download')
        base.fetch(image_pin, work / 'base.qcow2', 'sha512', 4 * GIB, deadline)
        packages = work / 'packages'
        packages.mkdir(mode=0o700)
        for name, pin in lock['packages'].items():
            require(re.fullmatch('[a-z0-9][a-z0-9+.-]*', name), 'package_name')
            base.fetch(pin, packages / (name + '.deb'), 'sha256', pin['bytes'], deadline)
        with tarfile.open(work / 'packages.tar', 'x') as archive:
            for path in sorted(packages.iterdir()):
                archive.add(path, arcname=path.name, recursive=False)
        report['memory_before_disks'] = dict(label='baseline', phase='before_disks')
        memory_snapshot(report['memory_before_disks'], deadline)
        report['phase'] = 'prepare_disks'
        device = base.root_device(images.fish(work / 'base.qcow2', [['inspect-os']], image_format='qcow2'))
        disk_memory_observation(report['disk_memory_observations'], 'inspect_roots', deadline)
        disk = re.fullmatch(r'(/dev/sd[a-z])([1-9][0-9]{0,2})', device)
        require(disk is not None, 'root_geometry')
        details = images.fish(work / 'base.qcow2', [['inspect-os'], ['inspect-get-distro', device],
            ['inspect-get-major-version', device], ['vfs-type', device], ['blockdev-getsize64', device],
            ['blockdev-getsize64', disk[1]], ['part-list', disk[1]]], image_format='qcow2')
        geometry = root_geometry(device, details)
        size = geometry['size']
        disk_memory_observation(report['disk_memory_observations'], 'inspect_details', deadline)
        reserve_space(work, size + 2 * GIB, 'root_extract')
        export_root(work, geometry, image_pin, deadline)
        disk_memory_observation(report['disk_memory_observations'], 'root_export', deadline)
        run(['qemu-img', 'resize', '-f', 'raw', work / 'runtime-root.raw', str(RUNTIME_BYTES)], deadline)
        disk_memory_observation(report['disk_memory_observations'], 'raw_resize', deadline)
        runtime_uuid = str(uuid.uuid4())
        # Change identity before attaching both disks. Filesystem growth belongs
        # to the existing offline runtime installer's e2fsck -> resize2fs -> mount
        # sequence, not a duplicate appliance pass here. Raw capacity stays 32 GiB.
        observed = images.fish(work / 'runtime-root.raw', [['set-uuid', '/dev/sda', runtime_uuid],
            ['vfs-uuid', '/dev/sda']], readonly=False)
        require(observed.strip() == runtime_uuid, 'runtime_uuid')
        disk_memory_observation(report['disk_memory_observations'], 'runtime_uuid', deadline)
        run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', work / 'base.qcow2',
             work / 'build.qcow2', '40G'], deadline)
        disk_memory_observation(report['disk_memory_observations'], 'build_overlay', deadline)
        seed(work, deadline)
        disk_memory_observation(report['disk_memory_observations'], 'seed', deadline)
        # This reservation is conservative physical headroom for model/compiler
        # growth, not a fabricated measurement of maximum simultaneous usage.
        report['build_space'] = reserve_space(work, 40 * GIB, 'build')
        with socket.socket() as test:
            test.bind(('127.0.0.1', 22223))
        current = build_scope = Scope(qemu_build(work), work, deadline, env, min(7500, int(remaining(deadline))), 'build')
        scopes.append(current)
        current.start(report['memory_admissions'])
        guest = Guest(work, deadline)
        report['phase'] = 'guest_boot'
        end = time.monotonic() + remaining(deadline, 300)
        while time.monotonic() < end:
            reply = guest.ssh(['true'], cap=10, check=False)
            try:
                observe_build_ssh(report['build_boot_diagnostic'], reply)
            except Exception:
                report['build_boot_diagnostic']['ssh']['incomplete'] = True
            if reply[2] == 0:
                break
            require(current.alive(), 'build_vm_died')
            time.sleep(.5)
        else:
            raise ValueError('build_boot_timeout')
        guest.ssh(['sudo', '-n', 'cloud-init', 'status', '--wait'], cap=120)
        guest_deadline = int(guest.ssh(['python3', '-c', 'import time; print(time.monotonic_ns())'])[0])
        guest_deadline += int(remaining(deadline, 7200) * 10 ** 9)
        guest_uid = int(guest.ssh(['id', '-u', 'vpci'])[0])
        guest_gid = int(guest.ssh(['id', '-g', 'vpci'])[0])
        guest.upload(work / 'inputs.tar', '/home/vpci/resident-inputs.tar')
        guest.upload(work / 'packages.tar', '/home/vpci/resident-packages.tar')
        require(guest.ssh(['sha256sum', '/home/vpci/resident-inputs.tar'])[0].decode().split()[0] == bundle['sha256'],
                'guest_source_bundle')
        package_tar = file_hash(work / 'packages.tar', deadline, GIB)
        require(guest.ssh(['sha256sum', '/home/vpci/resident-packages.tar'])[0].decode().split()[0] == package_tar['sha256'],
                'guest_package_bundle')
        guest.ssh(['sh', '-c', 'umask 077; mkdir -m 0700 ' + INPUT + ' /home/vpci/resident-packages; '
                   'tar --no-same-owner --no-same-permissions -xf /home/vpci/resident-inputs.tar -C ' + INPUT + '; '
                   'tar --no-same-owner --no-same-permissions -xf /home/vpci/resident-packages.tar -C /home/vpci/resident-packages'])
        guest.ssh(['sudo', '-n', 'install', '-d', '-m', '0700', '/var/lib/volparossa-resident'])
        report['phase'] = 'guest_packages'
        for mode in ('build', 'runtime'):
            guest.unit('vp-resident-install-' + mode, ['python3', '-B', INSTALL, '--execute', '--yes',
                '--disposable-guest', '--mode', mode, '--package-lock', LOCK, '--package-lock-sha256', LOCK_SHA,
                '--packages', '/home/vpci/resident-packages', '--result', '/var/lib/volparossa-resident/install-' + mode + '.json'],
                guest_deadline, diagnostics=report['guest_package_diagnostics'])
            raw = guest.ssh(['sudo', '-n', 'cat', '/var/lib/volparossa-resident/install-' + mode + '.json'])[0]
            installed = json.loads(raw)
            require(installed.get('kind') == 'protected-resident-offline-package-install'
                    and installed.get('mode') == mode and installed.get('state') == 'configured'
                    and installed.get('package_lock_sha256') == LOCK_SHA
                    and installed.get('packages_verified') == (199 if mode == 'build' else 65)
                    and all(installed.get(key) is True for key in ('archives_verified', 'status_verified',
                        'triggers_clear', 'audit_clear', 'policy_restored', 'runtime_unmounted', 'namespace_joined',
                        'direct_child_groups_joined')), 'installer_receipt')
            write_new(evidence / ('install-' + mode + '.json'), raw)
        report['phase'] = 'guest_model_build'
        guest.unit('vp-resident-builder', ['python3', '-B', BUILD, '--execute', '--yes', '--disposable-guest',
            '--input', INPUT, '--output', OUTPUT, '--expected-source', args.expected_source,
            '--package-lock', LOCK, '--package-lock-sha256', LOCK_SHA], guest_deadline, user='vpci',
            diagnostics=report['guest_builder_diagnostics'],
            builder_binding=dict(source=source, uid=guest_uid, gid=guest_gid))
        # A successful process is insufficient: verify detached units and disk use.
        device = guest.ssh(['readlink', '-f', '/dev/disk/by-id/virtio-vp-resident-runtime'])[0].decode().strip()
        require(re.fullmatch('/dev/vd[a-z]', device), 'runtime_device')
        require(guest.ssh(['findmnt', '-rn', '-S', device], check=False)[2] == 1, 'runtime_still_mounted')
        guest.ssh(['sync'])
        cleanup = current.stop()
        current = None
        cleanup.update(version=1, kind='protected-resident-model-build-cleanup', source_commit=args.expected_source,
                       source_tree=source['tree'], guest_uid=guest_uid, guest_gid=guest_gid,
                       guest_build_units_empty=True, guest_root_units_empty=True, runtime_unmounted=True,
                       build_image=file_hash(work / 'build.qcow2', deadline),
                       runtime_image=file_hash(work / 'runtime-root.raw', deadline))
        write_new(evidence / 'build-cleanup.json', encoded(cleanup))
        report['phase'] = 'immutable_export'
        assembler = module('protected-resident-model-assemble')
        reserve_space(work, 21 * GIB, 'asset_export')
        exported = assembler.export_assets(work / 'build.qcow2', work / 'export', cleanup,
                                          args.expected_source, source['tree'], images.fish, deadline)
        write_new(evidence / 'model-build.json', encoded(exported['build_result']))
        # Only this known joined build overlay is released. Base/source/evidence
        # remain; runtime and exported assets have independent validated bindings.
        (work / 'build.qcow2').unlink()
        report['phase'] = 'runtime_assembly'
        reserve_space(work, 21 * GIB, 'workload_stage')
        closure = assembler.assemble_runtime(work / 'runtime-root.raw', exported, work / 'assembled',
                                             cleanup, images.fish, deadline)
        require(closure['kernel_release'] == pins['kernel_release'], 'runtime_kernel_binding')
        write_new(evidence / 'workload.json', encoded(closure['staging_receipt']))
        report['phase'] = 'seal'
        options = ['--no-superblock', '--format=1', '--hash=sha256', '--data-block-size=4096',
                   '--hash-block-size=4096', '--data-blocks=' + str(RUNTIME_BYTES // 4096), '--salt=' + '0' * 64]
        run(['veritysetup', *options, '--root-hash-file=' + str(work / 'root.hash'), 'format',
             work / 'runtime-root.raw', work / 'verity.raw'], deadline, cap=900)
        root_hash = (work / 'root.hash').read_text().strip()
        require(re.fullmatch('[0-9a-f]{64}', root_hash), 'verity_root_hash')
        run(['veritysetup', *options, 'verify', work / 'runtime-root.raw', work / 'verity.raw', root_hash], deadline, cap=900)
        initrd = module('protected-resident-model-initrd')
        initrd_result = initrd.build(closure['root_tree'], closure['original_initrd'], pins['kernel_release'],
                                    root_hash, RUNTIME_BYTES // 4096, work / 'model-initrd.img')
        write_new(evidence / 'initrd.json', encoded(initrd_result))
        sealed = {name: file_hash(work / name, deadline) for name in ('runtime-root.raw', 'verity.raw', 'model-initrd.img')}
        write_new(evidence / 'sealed-inputs.json', encoded(sealed))
        channel = work / 'channel.sock'
        require(len(os.fsencode(channel)) < 104, 'channel_path_length')
        report['phase'] = 'model_boot'
        current = Scope(qemu_model(work, closure, channel), work, deadline, env, 2700, 'model')
        scopes.append(current)
        current.start(report['memory_admissions'])
        end = time.monotonic() + remaining(deadline, 300)
        console = work / 'model-console.log'
        while time.monotonic() < end:
            require(current.alive(), 'model_vm_died')
            if console.exists():
                raw = console.read_bytes()
                require(len(raw) <= 4 * 1024 ** 2, 'console_bound')
                if ready_record(raw):
                    break
            time.sleep(.2)
        else:
            raise ValueError('model_ready_timeout')
        report['phase'] = 'two_public_turns'
        report['requester_diagnostic'] = requester_diagnostic()
        raw, _, _ = run([args.requester, 'compute', 'resident-public-trial', '--socket', channel,
            '--certificate', work / 'server.der', '--requester-key', work / 'requester.seed',
            '--workload-sha256', closure['staging_receipt']['workload_sha256'], '--execute',
            '--diagnostic-stages'], deadline, cap=2420, requester_observation=report['requester_diagnostic'])
        report['model_result'] = requester_record(raw, closure['staging_receipt']['workload_sha256'])
        write_new(evidence / 'requester.json', encoded(report['model_result']))
        end = time.monotonic() + remaining(deadline, 60)
        while current.alive() and time.monotonic() < end:
            time.sleep(.1)
        require(not current.alive(), 'model_guest_exit_timeout')
        write_new(evidence / 'model-boot.json', encoded(boot_record(console.read_bytes(), 'guest_process_returned')))
        current.stop()
        current = None
        require(all(file_hash(work / name, deadline) == record for name, record in sealed.items()), 'sealed_inputs_changed')
        # Corrupt in place only AFTER the successful VM is joined and all sealed
        # hashes checked. The image is disposable, not a published good artifact.
        report['phase'] = 'corruption_negative'
        with (work / 'runtime-root.raw').open('r+b') as image:
            image.seek(1024)
            old = image.read(1)
            image.seek(1024)
            image.write(bytes([old[0] ^ 1]))
            image.flush()
            os.fsync(image.fileno())
        console.unlink()
        remove_model_channel(work, scopes[-1])
        current = Scope(qemu_model(work, closure, channel), work, deadline, env, 360, 'corrupt')
        scopes.append(current)
        current.start(report['memory_admissions'])
        end = time.monotonic() + remaining(deadline, 300)
        while current.alive() and time.monotonic() < end:
            time.sleep(.1)
        require(not current.alive(), 'negative_guest_exit_timeout')
        write_new(evidence / 'corrupt-boot.json', encoded(boot_record(console.read_bytes(), 'integrity_failure')))
        current.stop()
        current = None
        require(source_binding(args.expected_source, deadline) == source, 'source_changed')
        host_after = host_observer.capture()
        after = host_observer.hashes(host_after)
        report['host_after'] = after
        report['host_observation']['after'] = host_after
        report['host_observation']['comparison'] = host_observer.compare(host_before, host_after)
        report['host_observed_routes_dns_unchanged'] = after == report['host_before']
        report['host_configuration_checkpoint'] = host_observer.configuration_checkpoint(host_before, host_after)
        require(report['host_configuration_checkpoint']['eligible'], 'host_network_observation_changed')
        workload_complete = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, CleanupUnconfirmed) as error:
        code = str(error) if type(error) is ValueError else ''
        report['failure'] = code if code in FAILURE_CODES else 'controller_stage_failed'
    finally:
        for scope in scopes:
            if scope.cleanup_confirmed:
                continue
            try:
                scope.stop()
            except (OSError, ValueError, subprocess.SubprocessError, CleanupUnconfirmed):
                pass  # Retain the primary failure and the scope's unconfirmed state.
        scopes_safe = all(scope.process is None and
                          (scope.cleanup_confirmed or (not scope.started and scope.group is None))
                          for scope in scopes)
        report['vm_cleanup_confirmed'] = scopes_safe
        if build_scope is not None and build_scope.cleanup_confirmed:
            try:
                report['build_boot_diagnostic']['console'] = build_console_projection(work, payload_identity, deadline)
            except Exception:
                pass  # Optional evidence cannot replace primary failure or skip cleanup.
        report['tool_cleanup_confirmed'] = not pending
        if scopes_safe and not pending:
            try:
                remove_payload(work, parent_identity, payload_identity)
                report['scratch_removed'] = True
            except (OSError, ValueError):
                report['scratch_cleanup_failure'] = 'scratch_removal_failed'
        else:
            report['scratch_cleanup_failure'] = 'process_cleanup_unconfirmed'
        if not report['scratch_removed']:
            report['state'] = 'failed'
            report.setdefault('failure', report['scratch_cleanup_failure'])
        # No workload/host observation is an aggregate success until all owned
        # processes and scratch are gone and late cancellation/expiry is checked.
        if (workload_complete and 'failure' not in report and scopes_safe and not pending
                and report['scratch_removed'] and report['host_configuration_checkpoint']['eligible'] is True):
            try:
                remaining(deadline)
                report.update(state='passed', phase='complete', model_execution=True,
                              host_configuration_checkpoint_accepted=True,
                              runtime_image_deliberately_corrupted=True)
            except ValueError as error:
                report.setdefault('failure', str(error) if str(error) in FAILURE_CODES else 'controller_stage_failed')
        write_new(evidence / 'result.json', encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--yes', action='store_true', required=True)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--appliance-kernel', type=Path, required=True)
    parser.add_argument('--requester', type=Path, required=True)
    args = parser.parse_args()
    def cancel(_number, _frame):
        global CANCELLED
        CANCELLED = True
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, cancel)
    try:
        result = execute(args)
    except (OSError, ValueError, KeyError, TypeError, CleanupUnconfirmed, subprocess.SubprocessError):
        result = {'version': 1, 'kind': 'protected-resident-public-model-trial', 'state': 'rejected'}
    print(encoded(result).decode(), end='')
    return 0 if result['state'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
