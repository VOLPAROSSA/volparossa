#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only immutable Debian boot prerequisite; never protected-task acceptance.

All image inspection/mutation happens inside libguestfs, not host loop mounts.
The input image and three additional packages are authenticated before extraction.
The resulting descriptor records a public build: it is NOT independent owner
approval, a hardware appraisal, or authorization to release private inputs.
"""
import argparse
import contextvars
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PINS = HERE / 'protected-resident-image-pins-v1.json'
BOOTSTRAP = ROOT / 'packaging/protected-resident/init'
ENTRYPOINT = ROOT / 'packaging/protected-resident/entrypoint'
ENTRYPOINT_GUEST = '/usr/lib/volparossa/protected-resident-entrypoint'
RUNTIME = '/opt/volparossa/runtime'
WORKER_UID = 985
SALT = '0' * 64
BLOCK_SIZE = 4096
MAX_IMAGE = 4 * 1024 ** 3
MAX_ROOT = 16 * 1024 ** 3
MAX_TREE = 4 * 1024 ** 3
MAX_LOG = 1024 ** 2
MAX_APPLIANCE_KERNEL = 64 * 1024 ** 2
BOOT_SECONDS = 180
BUILD_SECONDS = 1200
CMDLINE = 'console=ttyS0 panic=-1 oops=panic quiet rdinit=/init vp.profile=public-boot-v1'
PREFIX = b'VP_PROTECTED_BOOT_V1 '
WRITE_PROBE = b'VOLPAROSSA public verity write probe\n'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
       'LIBGUESTFS_BACKEND': 'direct', 'LIBGUESTFS_BACKEND_SETTINGS': 'force_kvm',
       'LIBGUESTFS_MEMSIZE': '2048', 'PYTHONDONTWRITEBYTECODE': '1'}
DEADLINE = contextvars.ContextVar('protected_public_boot_deadline', default=None)
SCRATCH = contextvars.ContextVar('protected_public_boot_scratch', default=None)
APPLIANCE = contextvars.ContextVar('protected_public_boot_appliance', default=None)
HYPERVISOR = contextvars.ContextVar('protected_public_boot_hypervisor', default=None)
QMP_CAPTURE = contextvars.ContextVar('protected_public_boot_qmp_capture', default=None)
CANCELLED = contextvars.ContextVar('protected_public_boot_cancelled', default=False)
GUESTFISH_OPERATIONS = frozenset(('inspect_roots', 'inspect_details', 'extract_boot_files',
    'readlink_bin', 'readlink_sbin', 'readlink_lib', 'readlink_lib64', 'stage_root'))
MAX_KERNEL_CANDIDATES = 32
MAX_PREFLIGHT_ENTRIES = 128
STDERR_CLASSES = frozenset(('kernel_not_found', 'kvm_unavailable', 'appliance_launch_failed',
    'appliance_launch_timeout', 'appliance_connection_closed', 'unclassified', 'ambiguous'))
# Exact C-locale lines from the public upstream sources; no arbitrary suffixes.
# https://github.com/libguestfs/supermin/blob/v5.2.2/src/format_ext2_kernel.ml#L57-L65
# https://github.com/libguestfs/libguestfs/blob/v1.52.0/lib/launch-direct.c#L483-L498
# https://github.com/libguestfs/libguestfs/blob/v1.52.0/lib/errors.c#L451-L491
STDERR_PATTERNS = {
    b'supermin: failed to find a suitable kernel (host_cpu=x86_64).': 'kernel_not_found',
    b'supermin: failed to find a suitable kernel (host_cpu=amd64).': 'kernel_not_found',
    b'libguestfs: error: force_kvm supplied but kvm not available.': 'kvm_unavailable',
    b'libguestfs: error: guestfs_launch failed.': 'appliance_launch_failed',
    b'libguestfs: error: appliance launch timed out.': 'appliance_launch_timeout',
    b'libguestfs: error: appliance closed the connection unexpectedly.': 'appliance_connection_closed',
}
# Noninteractive argv commands use this fixed fish error-callback prefix.
# https://github.com/libguestfs/libguestfs/blob/v1.52.0/fish/fish.c#L1225-L1235
STDERR_PATTERNS.update({b'*stdin*:0: ' + line: label for line, label in list(STDERR_PATTERNS.items())
                        if line.startswith(b'libguestfs: error: ')})
QMP_OPERATION = 'qmp_kvm_preflight'
QMP_COMMANDS = (b'{"execute":"qmp_capabilities","id":"capabilities"}\n'
                b'{"execute":"query-kvm","id":"kvm"}\n'
                b'{"execute":"quit","id":"quit"}\n')
MAX_QMP = 32768
LIBGUESTFS_QMP_ARGV = ('-display', 'none', '-machine', 'q35,accel=kvm:tcg', '-qmp', 'stdio')
# QEMU 8.2.2 accel/kvm/kvm-all.c (open failure), system/vl.c
# (accelerator initialization), util/error-report.c (fixed program/location).
# Only enumerated C-locale errno strings; neither syscall nor causal attribution.
QEMU_ERRNO_LABELS = {
    b'Permission denied': 'kvm_permission_denied',
    b'Operation not permitted': 'kvm_permission_denied',
    b'No such file or directory': 'kvm_device_missing',
    b'No such device': 'kvm_device_unavailable',
    b'Device or resource busy': 'kvm_resource_busy',
    b'Operation not supported': 'kvm_unsupported',
    b'Function not implemented': 'kvm_unsupported',
    b'Invalid argument': 'kvm_invalid_argument',
    b'Cannot allocate memory': 'kvm_memory_unavailable',
}
QEMU_STDERR_PATTERNS = {
    b'Could not access KVM kernel module: ' + text: label
    for text, label in QEMU_ERRNO_LABELS.items()
}
QEMU_STDERR_PATTERNS.update({
    b'qemu-system-x86_64: failed to initialize kvm: ' + text: label
    for text, label in QEMU_ERRNO_LABELS.items()
})
QEMU_STDERR_CLASSES = frozenset(QEMU_ERRNO_LABELS.values()) | {'unclassified', 'ambiguous'}
CONTEXT_KEYS = ('credentials', 'capabilities', 'seccomp', 'lsm', 'device_metadata', 'device_acl')
CONTEXT_EQUALITY = frozenset(('equal', 'different', 'unavailable'))
KVM_OBSERVATIONS = frozenset(('api_12', 'api_mismatch', 'not_character_device',
                             'missing', 'denied', 'io_error', 'unavailable'))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def checkpoint():
    require(not CANCELLED.get(), 'cancelled')
    if DEADLINE.get() is not None:
        require(time.monotonic() < DEADLINE.get(), 'build_deadline')


def exact_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_json_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('json_constant')))


def digest(path, algorithm='sha256', maximum=MAX_ROOT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                'input_file_shape')
        value, length = hashlib.new(algorithm), 0
        while block := source.read(1024 ** 2):
            checkpoint()
            length += len(block)
            require(length <= maximum, 'input_file_bound')
            value.update(block)
        after = os.fstat(source.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        require(identity(before) == identity(after) and length == before.st_size,
                'input_file_changed')
    return {'bytes': length, algorithm: value.hexdigest()}


def load_pins():
    pins = exact_json(PINS.read_bytes())
    image = exact_json((ROOT / pins['debian_image_manifest']).read_bytes())
    require(pins['version'] == 1 and pins['kind'] == 'protected-resident-public-boot-inputs'
            and pins['public_test_inputs_only'] is True
            and pins['independent_production_approval'] is False, 'pins_scope')
    require(image['sha512'] == pins['debian_image_sha512']
            and image['release_build'] == '20260826-2582'
            and image['architecture'] == 'amd64', 'image_pin_binding')
    require(pins['kernel_release'] == '6.12.105+deb13-cloud-amd64'
            and pins['kernel_package_version'] == '6.12.105-1', 'kernel_pin')
    require(set(pins['packages']) == {'cryptsetup-bin', 'libcryptsetup12', 'busybox-static'},
            'package_pins')
    require(pins['verity'] == dict(format=1, hash='sha256', data_block_size=4096,
                                  hash_block_size=4096, salt=SALT, superblock=False),
            'verity_parameters')
    return pins


def source_binding(expected):
    require(type(expected) is str and re.fullmatch('[0-9a-f]{40}', expected), 'source_revision')
    actual = command(['git', '-C', ROOT, 'rev-parse', 'HEAD']).decode().strip()
    require(actual == expected, 'source_revision')
    require(not command(['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=all']),
            'source_dirty')
    return {'revision': actual,
            'tree': command(['git', '-C', ROOT, 'rev-parse', 'HEAD^{tree}']).decode().strip()}


def hosted_output(path):
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Linux' and os.geteuid() != 0, 'hosted_only')
    parent = Path(os.environ.get('RUNNER_TEMP', '')).resolve(strict=True)
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent
            and path.is_relative_to(parent) and path != parent
            and not path.exists() and not path.is_symlink(), 'new_private_output')
    path.mkdir(mode=0o700)
    return path


class CleanupUnconfirmed(RuntimeError):
    pass


class CommandFailed(ValueError):
    def __init__(self, returncode, operation=None, stderr_class=None):
        super().__init__('command_failed')
        self.returncode = returncode
        self.operation = operation
        self.stderr_class = stderr_class


def command_failure(error):
    if (isinstance(error, CommandFailed) and type(error.operation) is str
            and error.operation in GUESTFISH_OPERATIONS | {QMP_OPERATION}
            and type(error.returncode) is int
            and -64 <= error.returncode <= 255 and error.returncode != 0):
        label = error.stderr_class
        classes = QEMU_STDERR_CLASSES if error.operation == QMP_OPERATION else STDERR_CLASSES
        return {'operation': error.operation, 'returncode': error.returncode,
                'stderr_class': label if type(label) is str and label in classes else None}
    return None


class GuestfishStderr:
    """Match bounded stderr lines, retaining neither raw output nor dynamic fields."""
    patterns = STDERR_PATTERNS
    def __init__(self):
        self.pending = bytearray()
        self.dropping = False
        self.matches = set()

    def feed(self, block):
        for index, part in enumerate(block.split(b'\n')):
            if index:
                self.line()
            if not self.dropping:
                if len(self.pending) + len(part) > 4096:
                    self.pending.clear()
                    self.dropping = True
                else:
                    self.pending.extend(part)

    def line(self):
        if not self.dropping:
            label = self.patterns.get(bytes(self.pending).removesuffix(b'\r'))
            if label is not None:
                self.matches.add(label)
        self.pending.clear()
        self.dropping = False

    def finish(self):
        self.line()
        if len(self.matches) > 1:
            return 'ambiguous'
        return next(iter(self.matches), 'unclassified')


class QemuStderr(GuestfishStderr):
    # Unknown QEMU text is discarded, never used as parser input or exported.
    patterns = QEMU_STDERR_PATTERNS


class QemuFailureBoundary(GuestfishStderr):
    """Independent exact line facts; init failure alone does not identify a syscall."""
    patterns = {
        prefix + text: (boundary, {b'Permission denied': 'eacces',
                                  b'Operation not permitted': 'eperm'}.get(text, 'other'))
        for boundary, prefix in (
            ('open', b'Could not access KVM kernel module: '),
            ('init', b'qemu-system-x86_64: failed to initialize kvm: '))
        for text in QEMU_ERRNO_LABELS
    }

    def result(self):
        self.line()
        result = {}
        for boundary in ('open', 'init'):
            values = {value for stage, value in self.matches if stage == boundary}
            result[boundary] = ('ambiguous' if len(values) > 1
                                else next(iter(values), 'unobserved'))
        return result


def context_read(path, maximum):
    """Fixed proc inputs only; zero-size proc metadata is not a content bound."""
    require(path in ('/proc/self/status', '/proc/self/attr/current'), 'qmp_context')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'qmp_context')
        raw = source.read(maximum + 1)
    require(0 < len(raw) <= maximum, 'qmp_context')
    return raw


def context_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def status_context(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 32768, 'qmp_context')
    names = ('Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb',
             'NoNewPrivs', 'Seccomp', 'Seccomp_filters')
    fields = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(b':')
        if key in tuple(name.encode() for name in names):
            require(separator and key.decode() not in fields, 'qmp_context')
            fields[key.decode()] = value.strip().decode('ascii')
    require(set(fields) == set(names), 'qmp_context')
    for name, minimum, maximum in (('Uid', 4, 4), ('Gid', 4, 4), ('Groups', 0, 256)):
        values = fields[name].split()
        require(minimum <= len(values) <= maximum
                and all(re.fullmatch(r'[0-9]{1,10}', value) and int(value) < 2 ** 32
                        for value in values), 'qmp_context')
        fields[name] = [int(value) for value in values]
    for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        require(re.fullmatch('[0-9a-f]{16}', fields[name]), 'qmp_context')
    require(fields['NoNewPrivs'] in ('0', '1') and fields['Seccomp'] in ('0', '1', '2')
            and re.fullmatch('[0-9]{1,10}', fields['Seccomp_filters'])
            and int(fields['Seccomp_filters']) < 2 ** 32, 'qmp_context')
    return {
        'credentials': context_hash({key: fields[key] for key in ('Uid', 'Gid', 'Groups')}),
        'capabilities': context_hash({key: fields[key] for key in names if key.startswith('Cap')}),
        'seccomp': context_hash({key: fields[key] for key in ('NoNewPrivs', 'Seccomp', 'Seccomp_filters')}),
    }


def context_snapshot():
    """Private digests only, never public process metadata or device authority."""
    result = dict.fromkeys(CONTEXT_KEYS)
    try:
        result.update(status_context(context_read('/proc/self/status', 32768)))
    except (OSError, ValueError, UnicodeError):
        pass
    try:
        raw = context_read('/proc/self/attr/current', 4096)
        result['lsm'] = hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError):
        pass
    try:
        before = os.lstat('/dev/kvm')
        require(stat.S_ISCHR(before.st_mode), 'qmp_context')
        identity = lambda value: (value.st_dev, value.st_ino, value.st_rdev,
                                  value.st_mode, value.st_uid, value.st_gid, value.st_ctime_ns)
        acl = None
        try:
            raw = os.getxattr('/dev/kvm', 'system.posix_acl_access', follow_symlinks=False)
            require(len(raw) <= 4096, 'qmp_context')
            acl = context_hash({'present': raw.hex()})
        except OSError as error:
            if error.errno == errno.ENODATA:
                acl = context_hash({'absent': True})
        require(identity(before) == identity(os.lstat('/dev/kvm')), 'qmp_context')
        result.update(device_metadata=context_hash(identity(before)), device_acl=acl)
    except (OSError, ValueError):
        pass
    return result


def valid_context_baseline(value):
    return (type(value) is dict and set(value) == set(CONTEXT_KEYS)
            and all(item is None or (type(item) is str and re.fullmatch('[0-9a-f]{64}', item))
                    for item in value.values()))


def pre_exec_unavailable():
    return dict(version=1, scope='wrapper_pre_exec', kvm='unavailable',
                equality=dict.fromkeys(CONTEXT_KEYS, 'unavailable'))


def pre_exec_observation(baseline, deadline):
    result = pre_exec_unavailable()
    # This is optional observation, never a new admission decision or deadline.
    if not valid_context_baseline(baseline) or (deadline is not None and
            (type(deadline) not in (int, float) or not 0 < deadline < 2 ** 53
             or not time.monotonic() < deadline)):
        return result
    try:
        current = context_snapshot()
        if valid_context_baseline(current):
            result['equality'] = {key: ('unavailable' if baseline[key] is None or current[key] is None
                                      else 'equal' if baseline[key] == current[key] else 'different')
                                  for key in CONTEXT_KEYS}
        observed = kvm_observation()
        if type(observed) is str and observed in KVM_OBSERVATIONS:
            result['kvm'] = observed
    except (OSError, ValueError):
        pass
    return result


def validate_pre_exec(value):
    require(type(value) is dict and set(value) == {'version', 'scope', 'kvm', 'equality'}
            and type(value['version']) is int and value['version'] == 1
            and value['scope'] == 'wrapper_pre_exec'
            and type(value['kvm']) is str and value['kvm'] in KVM_OBSERVATIONS
            and type(value['equality']) is dict and set(value['equality']) == set(CONTEXT_KEYS)
            and all(type(item) is str and item in CONTEXT_EQUALITY
                    for item in value['equality'].values()), 'qmp_context')
    return value


def probe_pre_exec(config):
    try:
        scratch = Path(config['scratch'])
        capture_directory(scratch)
        baseline = exact_json(capture_read(scratch / 'qmp-context-parent', 2048))
        return pre_exec_observation(baseline, config.get('deadline'))
    except (OSError, ValueError, RecursionError):
        return pre_exec_unavailable()


def bind_hypervisor(tools):
    binary = shutil.which('qemu-system-x86_64', path=ENV['PATH'])
    require(binary is not None, 'host_tool_missing')
    path = Path(binary).resolve(strict=True)
    identity = host_identity(path, maximum=128 * 1024 ** 2)
    expected = tools['observed_tools']['qemu-system-x86_64']['binary_sha256']
    require(digest(path, maximum=128 * 1024 ** 2)['sha256'] == expected
            and host_identity(path, maximum=128 * 1024 ** 2) == identity, 'hypervisor_binding')
    HYPERVISOR.set({'path': path, 'identity': identity, 'sha256': expected})
    return expected


def bound_hypervisor():
    value = HYPERVISOR.get()
    require(value is not None, 'hypervisor_binding')
    path = value['path']
    require(host_identity(path, maximum=128 * 1024 ** 2) == value['identity']
            and digest(path, maximum=128 * 1024 ** 2)['sha256'] == value['sha256']
            and host_identity(path, maximum=128 * 1024 ** 2) == value['identity'],
            'hypervisor_binding')
    return str(path)


def qmp_result(raw):
    """Consume one fixed QMP exchange; no greeting strings or timestamps escape.

    QEMU v8.2.2 qapi/{control,machine,run-state}.json: no OOB negotiation;
    ordered replies, plus at most the shutdown event caused by our own quit.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_QMP and raw.endswith(b'\n'), 'qmp_protocol')
    lines = raw.splitlines()
    require(len(lines) in (4, 5), 'qmp_protocol')
    try:
        values = [exact_json(line) for line in lines]
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('qmp_protocol') from None
    greeting = values[0]
    require(type(greeting) is dict and set(greeting) == {'QMP'}, 'qmp_protocol')
    greeting = greeting['QMP']
    require(type(greeting) is dict and set(greeting) == {'version', 'capabilities'}
            and greeting['capabilities'] in ([], ['oob']), 'qmp_protocol')
    version = greeting['version']
    require(type(version) is dict and set(version) == {'qemu', 'package'}
            and type(version['package']) is str and len(version['package']) <= 256
            and all(32 <= ord(char) <= 126 for char in version['package']), 'qmp_protocol')
    require(type(version['qemu']) is dict and set(version['qemu']) == {'major', 'minor', 'micro'}
            and all(type(number) is int and 0 <= number <= 65535
                    for number in version['qemu'].values()), 'qmp_protocol')
    replies, shutdown = [], False
    for value in values[1:]:
        require(type(value) is dict, 'qmp_protocol')
        if 'event' in value:
            require(not shutdown and len(replies) >= 2
                    and set(value) == {'event', 'data', 'timestamp'}
                    and value['event'] == 'SHUTDOWN'
                    and type(value['data']) is dict
                    and set(value['data']) == {'guest', 'reason'}
                    and value['data']['guest'] is False
                    and value['data']['reason'] == 'host-qmp-quit', 'qmp_protocol')
            stamp = value['timestamp']
            require(type(stamp) is dict and set(stamp) == {'seconds', 'microseconds'}
                    and type(stamp['seconds']) is int and 0 <= stamp['seconds'] < 2 ** 53
                    and type(stamp['microseconds']) is int and 0 <= stamp['microseconds'] < 1000000,
                    'qmp_protocol')
            shutdown = True
        else:
            require(set(value) == {'return', 'id'}, 'qmp_protocol')
            replies.append(value)
    # QAPI explicitly permits EOF before the quit reply. Require the exact
    # shutdown event instead in that case; command() also requires exit zero.
    require(len(replies) in (2, 3)
            and [value['id'] for value in replies] == ['capabilities', 'kvm', 'quit'][:len(replies)]
            and replies[0]['return'] == {}
            and (replies[2]['return'] == {} if len(replies) == 3 else shutdown), 'qmp_protocol')
    result = replies[1]['return']
    require(type(result) is dict and set(result) == {'present', 'enabled'}
            and all(type(value) is bool for value in result.values()), 'qmp_protocol')
    return dict(result)


def qmp_observation():
    return dict(version=1, profile='paused_kvm_no_disks_network_v1', state='pending',
                binary_sha256=None, present=None, enabled=None, failure=None, command=None,
                diagnostic_only=True, appliance_boot_verified=False, hardware_attestation=False)


def qmp_preflight(tools, observed):
    """Hosted execute owns this receipt before any fallible step; never a boot proof."""
    try:
        checkpoint()
        observed['binary_sha256'] = bind_hypervisor(tools)
        argv = [bound_hypervisor(), '-no-user-config', '-nodefaults', '-S',
                '-display', 'none', '-nic', 'none', '-serial', 'none', '-monitor', 'none',
                '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', '128', '-smp', '1', '-qmp', 'stdio']
        # A tiny anonymous regular file avoids a new pipe-writer thread/child,
        # blocking writes, persistent QMP inputs, or a command supplied by a peer.
        with tempfile.TemporaryFile(mode='w+b', dir=SCRATCH.get()) as source:
            source.write(QMP_COMMANDS)
            source.flush()
            source.seek(0)
            raw = command(argv, timeout=15, maximum=MAX_QMP, operation=QMP_OPERATION, qmp_input=source)
        observed.update(qmp_result(raw))
        require(observed['present'] and observed['enabled'], 'qmp_kvm_unavailable')
        observed['state'] = 'passed'
    except BaseException as error:
        observed.update(state='failed', failure=failure_reason(error), command=command_failure(error))
        raise


def capture_directory(path, mode=0o700):
    info = path.lstat()
    require(path.is_absolute() and path.resolve(strict=True) == path
            and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == mode, 'qmp_capture_binding')


def capture_read(path, maximum, *, modes=(0o600,), links=(1,)):
    """Read only a bounded, same-owner regular inode; never export its text."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) in modes and before.st_nlink in links
                and 0 <= before.st_size <= maximum, 'qmp_capture_binding')
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(after)
                and identity(after) == identity(path.lstat()), 'qmp_capture_binding')
    return raw


def retain_probe_stderr(scratch, destination, observation=None):
    """Keep the existing libguestfs cmderr inode, not a second stderr stream.

    v1.52.0 command.c:767-817 creates fd2; tmpdirs.c:169-237 fixes its shape.
    No stdin read, argv rewrite, extra process, or interpretation of probe order.
    """
    capture_directory(scratch)
    capture_directory(destination)
    require(destination.parent == scratch, 'qmp_capture_binding')
    source = Path(os.readlink('/proc/self/fd/2'))
    require(source.parent.parent == scratch
            and re.fullmatch(r'libguestfs[A-Za-z0-9]{6}', source.parent.name)
            and re.fullmatch(r'cmderr[1-9][0-9]{0,9}\.txt', source.name), 'qmp_capture_binding')
    capture_directory(source.parent)
    opened, named = os.fstat(2), source.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink)
    require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid()
            and stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_nlink == 1
            and identity(opened) == identity(named), 'qmp_capture_binding')
    for slot in ('probe-1', 'probe-2'):
        retained = destination / slot
        try:
            os.link(source, retained, follow_symlinks=False)
        except FileExistsError:
            continue
        after = os.fstat(2)
        require(after.st_nlink == 2 and identity(after) == identity(source.lstat())
                and identity(after) == identity(retained.lstat())
                and (after.st_dev, after.st_ino) == (opened.st_dev, opened.st_ino),
                'qmp_capture_binding')
        descriptor = os.open(destination / (slot + '.verified'),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as marker:
            if observation is not None:
                value = validate_pre_exec(observation())
                raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
                require(len(raw) <= 2048, 'qmp_context')
                marker.write(raw)
        return
    raise ValueError('qmp_capture_bound')


def hypervisor_exec(config, arguments):
    """Fixed generated trampoline: validate the real ELF, then replace ourselves."""
    require(capture_interpreter() == config['interpreter']
            and str(Path(sys.executable).resolve(strict=True)) == config['interpreter']['path'],
            'qmp_capture_binding')
    binary = Path(config['binary'])
    require(host_identity(binary, maximum=128 * 1024 ** 2) == config['identity']
            and digest(binary, maximum=128 * 1024 ** 2)['sha256'] == config['sha256']
            and host_identity(binary, maximum=128 * 1024 ** 2) == config['identity'],
            'hypervisor_binding')
    if tuple(arguments) == LIBGUESTFS_QMP_ARGV:
        try:
            retain_probe_stderr(Path(config['scratch']), Path(config['capture']),
                lambda: probe_pre_exec(config))
        except (OSError, ValueError):
            # Capture is optional. A fixed marker makes a gap explicit, without
            # replacing the original command's argv, streams, environment or exit.
            try:
                capture_directory(Path(config['capture']))
                descriptor = os.open(Path(config['capture']) / 'incomplete',
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                os.close(descriptor)
            except (OSError, ValueError):
                pass
    # CPython ignores these signals at startup; unlike caught handlers, an
    # ignored disposition survives exec. libguestfs run_child sets them to DFL.
    for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), signal.SIG_DFL)
    os.execv(str(binary), [str(binary), *arguments])


def capture_interpreter():
    path = Path('/usr/bin/python3').resolve(strict=True)
    identity = host_identity(path, maximum=128 * 1024 ** 2)
    hashed = digest(path, maximum=128 * 1024 ** 2)['sha256']
    require(host_identity(path, maximum=128 * 1024 ** 2) == identity, 'qmp_capture_binding')
    return dict(path=str(path), identity=identity, sha256=hashed)


def prepare_qmp_capture():
    observed = dict(version=1, diagnostic_only=True, state='unavailable',
        trampoline_sha256=None, interpreter_sha256=None, binary_sha256=None,
        probe_stderr=[], query_correlated=False,
        query_kvm=dict(state='unavailable', present=None, enabled=None), appliance_boot_verified=False)
    result = {'receipt': observed}
    try:
        checkpoint()
        binary = bound_hypervisor()
        scratch = SCRATCH.get()
        capture_directory(scratch)
        directory = scratch / 'qmp-observation'
        directory.mkdir(mode=0o700)
        # Kept outside the generated script: neither baseline digests nor a
        # digest of their configuration is part of any exported receipt/hash.
        baseline = context_snapshot()
        require(valid_context_baseline(baseline), 'qmp_context')
        raw_baseline = json.dumps(baseline, sort_keys=True, separators=(',', ':')).encode()
        require(len(raw_baseline) <= 2048, 'qmp_context')
        descriptor = os.open(scratch / 'qmp-context-parent',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as target:
            target.write(raw_baseline)
        config = dict(binary=binary, identity=HYPERVISOR.get()['identity'],
                      sha256=HYPERVISOR.get()['sha256'], scratch=str(scratch), capture=str(directory),
                      interpreter=capture_interpreter(), deadline=DEADLINE.get())
        builder = Path(__file__).resolve(strict=True)
        source_hash = digest(builder, maximum=262144)['sha256']
        # No imports from the checkout and no bytecode writes: compile only the
        # bounded exact builder bytes in memory, under isolated system Python.
        script = ('#!/usr/bin/python3 -I\nimport hashlib, os, stat, sys\nsys.dont_write_bytecode = True\n'
            'try:\n'
            f'    fd = os.open({str(builder)!r}, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)\n'
            '    with os.fdopen(fd, "rb") as source:\n'
            '        info = os.fstat(source.fileno())\n'
            '        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 262144:\n'
            '            raise ValueError()\n'
            '        raw = source.read(262145)\n'
            f'    if len(raw) > 262144 or hashlib.sha256(raw).hexdigest() != {source_hash!r}:\n'
            '        raise ValueError()\n'
            f'    namespace = {{"__name__": "protected_hypervisor", "__file__": {str(builder)!r}}}\n'
            f'    exec(compile(raw, {str(builder)!r}, "exec"), namespace)\n'
            f'    namespace["hypervisor_exec"]({config!r}, sys.argv[1:])\n'
            'except BaseException:\n    os._exit(126)\n').encode()
        wrapper = scratch / 'qmp-exec'
        with wrapper.open('xb') as target:
            target.write(script)
        wrapper.chmod(0o500)
        info = wrapper.lstat()
        result.update(wrapper=wrapper, directory=directory, scratch=scratch,
                      size=info.st_size, mtime=int(info.st_mtime), interpreter=config['interpreter'])
        observed.update(state='unobserved', trampoline_sha256=hashlib.sha256(script).hexdigest(),
                        interpreter_sha256=config['interpreter']['sha256'], binary_sha256=config['sha256'])
    except Exception:
        # This optional observation must not stop the original operation.
        pass
    return result


def guestfish_hypervisor():
    binary = bound_hypervisor()
    value = QMP_CAPTURE.get()
    if value is not None and 'wrapper' in value:
        try:
            capture_directory(value['scratch'])
            script = capture_read(value['wrapper'], 262144, modes=(0o500,))
            require(hashlib.sha256(script).hexdigest() == value['receipt']['trampoline_sha256'],
                    'qmp_capture_binding')
            require(capture_interpreter() == value['interpreter'], 'qmp_capture_binding')
            return str(value['wrapper'])
        except (OSError, ValueError):
            value['receipt']['state'] = 'incomplete'
    return binary


def project_qmp_capture(value, *, joined):
    """Two original probe observations, deliberately NOT correlated to a query."""
    if value is None or 'wrapper' not in value:
        return
    observed = value['receipt']
    observed.update(state='incomplete', probe_stderr=[],
                    query_kvm=dict(state='unavailable', present=None, enabled=None))
    if not joined:
        return
    try:
        checkpoint()
        capture_directory(value['scratch'])
        capture_directory(value['directory'])
        wrapper = capture_read(value['wrapper'], 262144, modes=(0o500,))
        info = value['wrapper'].lstat()
        require(hashlib.sha256(wrapper).hexdigest() == observed['trampoline_sha256']
                and info.st_size == value['size'] and int(info.st_mtime) == value['mtime'],
                'qmp_capture_binding')
        names = set()
        with os.scandir(value['directory']) as entries:
            for entry in entries:
                require(len(names) < 5, 'qmp_capture_bound')
                names.add(entry.name)
        require(names <= {'probe-1', 'probe-2', 'probe-1.verified', 'probe-2.verified', 'incomplete'},
                'qmp_capture_binding')
        records = []
        for slot in (1, 2):
            if 'probe-' + str(slot) in names:
                marker = capture_read(value['directory'] / ('probe-' + str(slot) + '.verified'), 2048)
                context = validate_pre_exec(exact_json(marker)) if marker else pre_exec_unavailable()
                raw = capture_read(value['directory'] / ('probe-' + str(slot)), MAX_QMP, links=(1, 2))
                classifier = QemuStderr()
                classifier.feed(raw)
                boundary = QemuFailureBoundary()
                boundary.feed(raw)
                records.append(dict(slot=slot, stderr_class=classifier.finish(),
                                    failure_boundary=boundary.result(), pre_exec=context))
        observed['probe_stderr'] = records
        # Upstream qemu.c:233-240 derives exactly this cache key from the
        # hypervisor executable's stat, not the underlying ELF or a glob match.
        cache = value['scratch'] / ('.guestfs-' + str(os.geteuid()))
        capture_directory(cache, mode=0o755)
        name = 'qemu-' + str(value['size']) + '-' + str(value['mtime']) + '.query-kvm'
        raw = capture_read(cache / name, 4096, modes=(0o600, 0o644))
        result = exact_json(raw)
        require(type(result) is dict and set(result) == {'return'}
                and type(result['return']) is dict and set(result['return']) == {'present', 'enabled'}
                and all(type(item) is bool for item in result['return'].values()), 'qmp_capture_binding')
        observed['query_kvm'] = dict(state='observed', **result['return'])
        if len(records) == 2 and 'incomplete' not in names:
            observed['state'] = 'observed'
    except Exception:
        # No arbitrary error text, and no diagnostic failure replacing the
        # original guestfish result or its mandatory cleanup/quarantine.
        pass


def readable_regular(path):
    """Observe access only, without reading/exporting file contents or metadata."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            return 'readable' if stat.S_ISREG(os.fstat(descriptor).st_mode) else 'other'
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return 'missing'
    except PermissionError:
        return 'denied'
    except OSError:
        return 'other'


def kvm_observation():
    # A system query only: no KVM_CREATE_VM, permission change or TCG fallback.
    # https://docs.kernel.org/virt/kvm/api.html#kvm-get-api-version
    try:
        descriptor = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
                return 'not_character_device'
            return 'api_12' if fcntl.ioctl(descriptor, 0xAE00, 0) == 12 else 'api_mismatch'
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return 'missing'
    except PermissionError:
        return 'denied'
    except OSError:
        return 'io_error'


def appliance_preflight():
    """Bounded host observations, NOT supermin selection or boot acceptance."""
    counts = lambda: dict(readable=0, missing=0, denied=0, other=0)
    result = dict(version=1, diagnostic_only=True, selected_kernel=False,
                  kernel_selection='unobserved', candidates=0, incomplete=False,
                  kernel=counts(), modules_index=counts(), kvm=None)
    checkpoint()
    result['kvm'] = kvm_observation()
    examined = 0
    # Supermin searches both trees. This is only a bounded candidate census;
    # it deliberately does not duplicate its version/content selection logic.
    for directory in (Path('/lib/modules'), Path('/boot')):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    checkpoint()
                    if examined == MAX_PREFLIGHT_ENTRIES or result['candidates'] == MAX_KERNEL_CANDIDATES:
                        result['incomplete'] = True
                        return result
                    examined += 1
                    name = entry.name
                    if directory == Path('/boot'):
                        if not re.fullmatch(r'vmlinu[xz]-[A-Za-z0-9_+.-]{1,128}', name):
                            continue
                        version, kernel = name[8:], directory / name
                        if version in ('.', '..'):
                            continue
                    else:
                        if not re.fullmatch(r'[A-Za-z0-9_+.-]{1,128}', name) or name in ('.', '..'):
                            continue
                        version, kernel = name, directory / name / 'vmlinuz'
                    result['candidates'] += 1
                    result['kernel'][readable_regular(kernel)] += 1
                    result['modules_index'][readable_regular(Path('/lib/modules') / version / 'modules.dep')] += 1
        except OSError:
            result['incomplete'] = True
    return result


def host_identity(path, *, directory=False, maximum=MAX_APPLIANCE_KERNEL):
    """Bind a fixed host input; never grant access or follow its final symlink."""
    require(path.is_absolute() and path.resolve(strict=True) == path, 'appliance_host_path')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'appliance_host_parent')
    info = path.lstat()
    shape = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    require(shape and info.st_uid == 0 and not info.st_mode & 0o022, 'appliance_host_metadata')
    require(directory or 0 < info.st_size <= maximum, 'appliance_kernel_bound')
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def appliance_inputs(release):
    require(type(release) is str and re.fullmatch(r'[0-9][A-Za-z0-9._+-]{0,127}', release),
            'appliance_kernel_release')
    kernel = Path('/boot') / ('vmlinuz-' + release)
    base = Path('/lib/modules').resolve(strict=True)
    require(base in (Path('/lib/modules'), Path('/usr/lib/modules')), 'appliance_host_path')
    modules = base / release
    return kernel, modules


def appliance_stage_path():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('RUNNER_OS') == 'Linux' and os.geteuid() != 0, 'hosted_only')
    run = os.environ.get('GITHUB_RUN_ID', '')
    require(re.fullmatch('[0-9]{1,20}', run) is not None, 'appliance_stage_path')
    temporary = os.environ.get('RUNNER_TEMP', '')
    require(bool(temporary) and Path(temporary).is_absolute(), 'appliance_stage_path')
    parent = Path(temporary).resolve(strict=True)
    return parent / ('protected-resident-appliance-' + run)


def kvm_group_ids():
    """Validate ordinary group DAC, not a uaccess-managed named-user grant."""
    checkpoint()
    uid, effective, saved = os.getresuid()
    require(0 < uid < 2 ** 32 - 1 and uid == effective == saved, 'kvm_launch_identity')
    try:
        group = grp.getgrnam('kvm')
    except (KeyError, OSError):
        raise ValueError('kvm_launch_group') from None
    gid = group.gr_gid
    require(group.gr_name == 'kvm' and type(gid) is int and 0 < gid < 2 ** 32 - 1,
            'kvm_launch_group')
    before = os.lstat('/dev/kvm')
    require(stat.S_ISCHR(before.st_mode) and before.st_uid == 0 and before.st_gid == gid
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o660,
            'kvm_launch_device')
    identity = lambda value: (value.st_dev, value.st_ino, value.st_rdev, value.st_mode,
                              value.st_uid, value.st_gid, value.st_nlink, value.st_ctime_ns)
    try:
        raw = os.getxattr('/dev/kvm', 'system.posix_acl_access', follow_symlinks=False)
    except OSError as error:
        # Only ENODATA means a basic ACL: group-object bits then are the mode
        # group bits, with no extended mask. Unsupported/unreadable is not proof.
        if error.errno != errno.ENODATA:
            raise ValueError('kvm_launch_acl') from None
    else:
        require(28 <= len(raw) <= 4096 and (len(raw) - 4) % 8 == 0
                and struct.unpack_from('<I', raw)[0] == 2, 'kvm_launch_acl')
        entries = {}
        for tag, permission, identifier in struct.iter_unpack('<HHI', raw[4:]):
            require(tag in (1, 2, 4, 8, 16, 32) and permission <= 7
                    and ((identifier == 0xffffffff) if tag in (1, 4, 16, 32)
                         else identifier < 0xffffffff)
                    and (tag, identifier) not in entries, 'kvm_launch_acl')
            entries[tag, identifier] = permission
        base = {tag: entries.get((tag, 0xffffffff)) for tag in (1, 4, 16, 32)}
        require(base == {1: 6, 4: 6, 16: 6, 32: 0}, 'kvm_launch_acl')
        # A named entry for this UID takes precedence over group matching.
        require(entries.get((2, uid), 6) & base[16] == 6, 'kvm_launch_acl')
    require(identity(before) == identity(os.lstat('/dev/kvm')), 'kvm_launch_device')
    checkpoint()
    return uid, gid


def kvm_launch_ids(args):
    """Private shell capture only; same prepared source and absolute budget."""
    require(args.yes, 'explicit_hosted_execution')
    stage = appliance_stage_path()
    private_stage_file(stage, directory=True)
    prepared = read_stage(stage / 'prepared.json')
    require(type(prepared) is dict and prepared.get('source') == args.expected_source,
            'appliance_stage_binding')
    started = prepared.get('started_monotonic_ns')
    require(type(started) is int and 0 < started <= time.monotonic_ns(), 'build_deadline')
    token = DEADLINE.set(started / 1e9 + BUILD_SECONDS)
    try:
        checkpoint()
        return kvm_group_ids()
    finally:
        DEADLINE.reset(token)


def verify_kvm_launch():
    expected = []
    for name in ('VP_PUBLIC_BOOT_UID', 'VP_PUBLIC_BOOT_KVM_GID'):
        value = os.environ.get(name, '')
        require(re.fullmatch('[1-9][0-9]{0,9}', value) is not None
                and int(value) < 2 ** 32 - 1, 'kvm_launch_identity')
        expected.append(int(value))
    require(os.getresuid() == (expected[0],) * 3
            and os.getresgid() == (expected[1],) * 3, 'kvm_launch_identity')
    require(os.getgroups() == [], 'kvm_launch_privileges')
    # Validate the result of the fixed system setpriv launcher, never perform
    # privilege changes inside this builder or rely on a requested flag alone.
    wanted = {name: b'0000000000000000' for name in
              (b'CapInh', b'CapPrm', b'CapEff', b'CapBnd', b'CapAmb')}
    wanted[b'NoNewPrivs'] = b'1'
    fields = {}
    for line in context_read('/proc/self/status', 32768).splitlines():
        name, separator, value = line.partition(b':')
        if name in wanted:
            require(separator and name not in fields, 'kvm_launch_privileges')
            fields[name] = value.strip()
    require(fields == wanted, 'kvm_launch_privileges')
    require(kvm_group_ids() == tuple(expected), 'kvm_launch_identity')
    return dict(version=1, scope='execute_process', same_unprivileged_uid=True,
                primary_kvm_group_verified=True, device_group_access_verified=True,
                supplementary_groups_cleared=True, capabilities_cleared=True, no_new_privileges=True)


def private_stage_file(path, *, directory=False):
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) in ((0o700,) if directory else (0o600, 0o400))
            and (directory or info.st_nlink == 1), 'appliance_stage_metadata')
    return info


def read_stage(path):
    checkpoint()
    before = private_stage_file(path)
    require(stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 16384, 'appliance_stage_bound')
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                             info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        require(identity(os.fstat(source.fileno())) == identity(before), 'appliance_stage_binding')
        raw = source.read(16385)
        require(identity(os.fstat(source.fileno())) == identity(before), 'appliance_stage_binding')
    require(identity(path.lstat()) == identity(before), 'appliance_stage_binding')
    require(len(raw) == before.st_size and len(raw) <= 16384, 'appliance_stage_bound')
    checkpoint()
    return exact_json(raw)


def prepare_appliance(args):
    """Prepare only private metadata; the workflow owns the bounded root read."""
    require(args.yes, 'explicit_hosted_execution')
    stage = appliance_stage_path()
    started = time.monotonic_ns()
    token = DEADLINE.set(started / 1e9 + BUILD_SECONDS)
    try:
        source_binding(args.expected_source)
        release = os.uname().release
        kernel, modules = appliance_inputs(release)
        source = host_identity(kernel)
        require(source[6] >= 10000, 'appliance_kernel_bound')
        module_identity = host_identity(modules, directory=True)
        index_identity = host_identity(modules / 'modules.dep', maximum=16 * 1024 ** 2)
        index = digest(modules / 'modules.dep', maximum=16 * 1024 ** 2)
        stage.mkdir(mode=0o700)
        record(stage / 'prepared.json', dict(version=1, source=args.expected_source, release=release,
            started_monotonic_ns=started, source_identity=source, modules_identity=module_identity,
            index_identity=index_identity, modules_index=index))
        (stage / 'prepared.json').chmod(0o600)
        return release
    finally:
        DEADLINE.reset(token)


def validate_appliance(stage, expected, *, ready):
    private_stage_file(stage, directory=True)
    prepared = read_stage(stage / 'prepared.json')
    require(type(prepared) is dict and set(prepared) == {'version', 'source', 'release',
            'started_monotonic_ns', 'source_identity', 'modules_identity', 'index_identity', 'modules_index'}
            and type(prepared['version']) is int and prepared['version'] == 1
            and prepared['source'] == expected, 'appliance_stage_binding')
    for name in ('source_identity', 'modules_identity', 'index_identity'):
        value = prepared[name]
        require(type(value) is list and len(value) == 9
                and all(type(part) is int and part >= 0 for part in value), 'appliance_stage_binding')
    started = prepared['started_monotonic_ns']
    require(type(started) is int and 0 < started <= time.monotonic_ns()
            and time.monotonic_ns() - started < BUILD_SECONDS * 10 ** 9, 'build_deadline')
    deadline = started / 1e9 + BUILD_SECONDS
    token = DEADLINE.set(min(DEADLINE.get() or deadline, deadline))
    try:
        kernel, modules = appliance_inputs(prepared['release'])
        index = digest(modules / 'modules.dep', maximum=16 * 1024 ** 2)
        require(host_identity(kernel) == prepared['source_identity']
                and host_identity(modules, directory=True) == prepared['modules_identity']
                and host_identity(modules / 'modules.dep', maximum=16 * 1024 ** 2) == prepared['index_identity']
                and index == prepared['modules_index'], 'appliance_source_changed')
        copied = stage / 'kernel'
        mode = private_stage_file(copied).st_mode
        require(stat.S_IMODE(mode) == (0o400 if ready else 0o600), 'appliance_stage_metadata')
        value = digest(copied, maximum=MAX_APPLIANCE_KERNEL)
        require(value['bytes'] == prepared['source_identity'][6], 'appliance_kernel_bound')
        # Validate the x86 bzImage release rather than trusting a renamed copy.
        # Same bounded HdrS/version fields used by supermin v5.2.2.
        descriptor = os.open(copied, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb') as source:
            header = source.read(66200)
        require(header[514:518] == b'HdrS' and int.from_bytes(header[518:520], 'little') >= 0x1ff,
                'appliance_kernel_release')
        offset = int.from_bytes(header[526:528], 'little') + 0x200
        version = re.split(b'[\x00 \t\n]', header[offset:offset + 132], maxsplit=1)
        require(len(version) == 2 and version[0] == prepared['release'].encode('ascii'),
                'appliance_kernel_release')
        require(host_identity(kernel) == prepared['source_identity'], 'appliance_source_changed')
        receipt = dict(version=1, selection='explicit_host_kernel', kernel_release=prepared['release'],
            kernel=value, modules_index=index, source_identity_unchanged=True,
            host_permissions_changed=False, pre_pinned_host_kernel=False, appliance_boot_verified=False)
        if ready:
            require(read_stage(stage / 'ready.json') == receipt, 'appliance_stage_binding')
        checkpoint()
        return prepared, receipt
    finally:
        DEADLINE.reset(token)


def finish_appliance(args):
    require(args.yes, 'explicit_hosted_execution')
    stage = appliance_stage_path()
    prepared, receipt = validate_appliance(stage, args.expected_source, ready=False)
    token = DEADLINE.set(prepared['started_monotonic_ns'] / 1e9 + BUILD_SECONDS)
    try:
        source_binding(args.expected_source)
        (stage / 'kernel').chmod(0o400)
        record(stage / 'ready.json', receipt)
        (stage / 'ready.json').chmod(0o600)
    finally:
        DEADLINE.reset(token)


def adopt_appliance(output, expected):
    stage = appliance_stage_path()
    prepared, receipt = validate_appliance(stage, expected, ready=True)
    deadline = prepared['started_monotonic_ns'] / 1e9 + BUILD_SECONDS
    token = DEADLINE.set(min(DEADLINE.get() or deadline, deadline))
    try:
        checkpoint()
        require({path.name for path in stage.iterdir()} == {'kernel', 'prepared.json', 'ready.json'},
                'appliance_stage_binding')
        target = output / 'appliance'
        stage.rename(target)
        checkpoint()
        return dict(stage=target, source=expected, deadline=deadline, receipt=receipt)
    finally:
        DEADLINE.reset(token)


def appliance_environment():
    value = APPLIANCE.get()
    require(value is not None, 'appliance_stage_binding')
    prepared, _receipt = validate_appliance(value['stage'], value['source'], ready=True)
    _kernel, modules = appliance_inputs(prepared['release'])
    return dict(SUPERMIN_KERNEL=str(value['stage'] / 'kernel'), SUPERMIN_MODULES=str(modules),
                SUPERMIN_KERNEL_VERSION=prepared['release'])


def cleanup_appliance(args):
    """Only the fixed, unadopted stage; no recursive or privileged deletion."""
    require(args.yes, 'explicit_hosted_execution')
    stage = appliance_stage_path()
    if not stage.exists() and not stage.is_symlink():
        return
    private_stage_file(stage, directory=True)
    files = list(stage.iterdir())
    require({path.name for path in files} <= {'kernel', 'prepared.json', 'ready.json'},
            'appliance_stage_binding')
    for path in files:
        private_stage_file(path)
    for path in files:
        path.unlink()
    stage.rmdir()


def group_absent(group, seconds=2):
    deadline = time.monotonic() + seconds
    while True:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(.02)


def command(argv, *, timeout=120, maximum=MAX_LOG, stdout_path=None, operation=None,
            qmp_input=None):
    """Bound public tool output; retain the child until the last group signal."""
    require(0 < timeout <= BUILD_SECONDS, 'command_deadline')
    require(operation is None or operation in GUESTFISH_OPERATIONS | {QMP_OPERATION},
            'command_operation')
    qmp = operation == QMP_OPERATION
    require((qmp_input is not None) == qmp, 'qmp_input')
    if qmp:
        info = os.fstat(qmp_input.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.geteuid() and info.st_nlink == 0
                and info.st_size == len(QMP_COMMANDS) and qmp_input.tell() == 0
                and qmp_input.read(len(QMP_COMMANDS) + 1) == QMP_COMMANDS
                and stdout_path is None and maximum == MAX_QMP, 'qmp_input')
        qmp_input.seek(0)
        require(str(argv[0]) == bound_hypervisor(), 'hypervisor_binding')
    checkpoint()
    if DEADLINE.get() is not None:
        timeout = min(timeout, DEADLINE.get() - time.monotonic())
        require(timeout > 0, 'build_deadline')
    output = bytearray()
    stderr = QemuStderr() if qmp else GuestfishStderr() if operation is not None else None
    deadline = time.monotonic() + timeout
    target = None
    environment = dict(ENV)
    if str(argv[0]) == 'guestfish':
        # Bind at handle creation too: -a processing precedes explicit set-hv.
        # https://libguestfs.org/guestfish.1.html#set-hv
        environment['LIBGUESTFS_HV'] = guestfish_hypervisor()
        if QMP_CAPTURE.get() is not None and 'wrapper' in QMP_CAPTURE.get():
            require(len(argv) >= 13 and argv[11] == 'set-hv'
                    and argv[12] == environment['LIBGUESTFS_HV'], 'hypervisor_binding')
        environment.update(appliance_environment())
    if SCRATCH.get() is not None:
        environment.update(LIBGUESTFS_CACHEDIR=str(SCRATCH.get()),
                           LIBGUESTFS_TMPDIR=str(SCRATCH.get()), TMPDIR=str(SCRATCH.get()))
    process = subprocess.Popen([str(item) for item in argv],
        stdin=qmp_input if qmp else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, close_fds=True,
        start_new_session=True)
    try:
        if stdout_path is not None:
            target = open(stdout_path, 'xb')
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            total = 0
            while selector.get_map():
                checkpoint()
                require(time.monotonic() < deadline, 'command_timeout')
                for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(block)
                    require(total <= maximum, 'command_output_bound')
                    if stderr is not None and key.fileobj is process.stderr:
                        stderr.feed(block)
                    if target is not None and key.fileobj is process.stdout:
                        target.write(block)
                    elif not qmp or key.fileobj is process.stdout:
                        output.extend(block)
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                checkpoint()
                require(time.monotonic() < deadline, 'command_timeout')
                time.sleep(.01)
    finally:
        # No poll()/wait() before this last signal: even an exited leader remains
        # unreaped, so its PID/process-group identity cannot have been recycled.
        signal_failed = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            signal_failed = True
        try:
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError) as error:
                raise CleanupUnconfirmed('child_join_unconfirmed') from error
            if not group_absent(process.pid):
                raise CleanupUnconfirmed('process_group_remaining')
            if signal_failed:
                raise CleanupUnconfirmed('process_group_signal_failed')
        finally:
            process.stdout.close()
            process.stderr.close()
            if target is not None:
                target.close()
    if process.returncode != 0:
        raise CommandFailed(process.returncode, operation, stderr.finish() if stderr is not None else None)
    if qmp or str(argv[0]) == 'guestfish':
        bound_hypervisor()
    return bytes(output)


class PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        original = urllib.parse.urlsplit(request.full_url)
        parsed = urllib.parse.urlsplit(newurl)
        permitted_host = parsed.hostname in ('cloud.debian.org', 'deb.debian.org') or (
            original.hostname == 'cloud.debian.org' and parsed.hostname == 'saimei.ftp.acc.umu.se')
        require(parsed.scheme == 'https' and permitted_host and parsed.username is None
                and parsed.password is None and parsed.port in (None, 443)
                and parsed.path == original.path and parsed.query == original.query
                and not parsed.fragment, 'download_redirect')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def fetch(item, target, algorithm, maximum, deadline):
    require(item['url'].startswith(('https://cloud.debian.org/', 'https://deb.debian.org/')),
            'download_origin')
    opener = urllib.request.build_opener(PinnedRedirect())
    checkpoint()
    require(time.monotonic() < deadline, 'build_deadline')
    with opener.open(item['url'], timeout=min(30, deadline - time.monotonic())) as response, \
            open(target, 'xb') as output:
        require(response.status == 200, 'download_status')
        length, value = 0, hashlib.new(algorithm)
        while block := response.read(1024 ** 2):
            checkpoint()
            require(time.monotonic() < deadline, 'build_deadline')
            length += len(block)
            require(length <= maximum, 'download_bound')
            output.write(block)
            value.update(block)
    require(0 < length <= maximum and value.hexdigest() == item[algorithm]
            and ('bytes' not in item or length == item['bytes']), 'download_digest')


def guestfish(image, operations, *, readonly=True, image_format='raw', timeout=300, operation=None):
    argv = ['guestfish', '--ro' if readonly else '--rw', '--format=' + image_format,
            '-a', image, 'set-pgroup', 'false', ':', 'set-network', 'false',
            ':', 'set-hv', guestfish_hypervisor(), ':', 'run']
    for subcommand in operations:
        argv.extend([':', *subcommand])
    return command(argv, timeout=timeout, operation=operation).decode('utf-8', errors='strict')


def root_device(output):
    lines = output.splitlines()
    require(len(lines) == 1 and re.fullmatch(r'/dev/sd[a-z][1-9][0-9]*', lines[0]),
            'one_inspected_root')
    return lines[0]


def kernel_config(raw):
    settings = dict(line.split('=', 1) for line in raw.splitlines()
                    if line.startswith('CONFIG_') and '=' in line)
    for name in ('BLK_DEV_INITRD', 'DEVTMPFS', 'EXT4_FS', 'BLK_DEV_DM', 'DM_VERITY',
                 'VIRTIO_PCI', 'VIRTIO_BLK', 'SERIAL_8250', 'SERIAL_8250_CONSOLE'):
        require(settings.get('CONFIG_' + name) in ('y', 'm'), 'kernel_feature_' + name)
    return settings


def safe_tree(archive, destination):
    """Extract authenticated public files; never follow archive symlink parents."""
    destination.mkdir(mode=0o700, exist_ok=True)
    total, count = 0, 0
    with tarfile.open(archive, mode='r:') as source:
        for member in source:
            checkpoint()
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts, 'archive_path')
            parts = tuple(part for part in path.parts if part != '.')
            if not parts:
                continue
            count += 1
            total += member.size
            require(count <= 100000 and total <= MAX_TREE, 'archive_bound')
            target = destination.joinpath(*parts)
            for parent in target.parents:
                if parent == destination:
                    break
                require(not parent.is_symlink(), 'archive_parent_symlink')
            require(not target.is_symlink(), 'archive_overwrite_symlink')
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(mode=0o755, exist_ok=True)
            elif member.issym():
                require(not target.exists(), 'archive_duplicate')
                target.symlink_to(member.linkname)
            elif member.isfile():
                require(not target.exists(), 'archive_duplicate')
                with source.extractfile(member) as incoming, open(target, 'xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 ** 2)
                target.chmod(member.mode & 0o777)
            elif member.islnk():
                link = PurePosixPath(member.linkname)
                require(not link.is_absolute() and '..' not in link.parts, 'archive_hardlink')
                original = destination.joinpath(*link.parts)
                require(original.resolve().is_relative_to(destination.resolve())
                        and original.is_file() and not original.is_symlink(), 'archive_hardlink')
                require(not target.exists(), 'archive_duplicate')
                shutil.copyfile(original, target)
                target.chmod(member.mode & 0o777)
            else:
                raise ValueError('archive_special_file')


def extract_boot(image, output, pins):
    require(digest(image, 'sha512', MAX_IMAGE)['sha512'] == pins['debian_image_sha512'],
            'image_digest')
    device = root_device(guestfish(image, [['inspect-os']], image_format='qcow2',
                                  operation='inspect_roots'))
    details = guestfish(image, [['inspect-os'], ['inspect-get-distro', device],
                              ['inspect-get-major-version', device],
                              ['vfs-type', device], ['blockdev-getsize64', device]],
                       image_format='qcow2', operation='inspect_details').splitlines()
    require(len(details) == 5 and root_device(details[0]) == device, 'inspection_root_binding')
    require(details[1:4] == ['debian', '13', 'ext4'], 'image_os')
    size = int(details[4])
    require(0 < size <= MAX_ROOT and size % BLOCK_SIZE == 0, 'root_size')
    release = pins['kernel_release']
    guestfish(image, [['mount-ro', device, '/'],
        ['download', '/boot/vmlinuz-' + release, output / 'vmlinuz'],
        ['download', '/boot/config-' + release, output / 'kernel.config'],
        ['download', '/boot/initrd.img-' + release, output / 'original-initrd.img'],
        ['download-offset', device, output / 'root.raw', '0', str(size)],
        ['tar-out', '/usr', output / 'usr.tar']], image_format='qcow2', timeout=600,
        operation='extract_boot_files')
    kernel_config((output / 'kernel.config').read_text())
    tree = output / 'root-tree'
    tree.mkdir(mode=0o700)
    safe_tree(output / 'usr.tar', tree / 'usr')
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        target = guestfish(image, [['mount-ro', device, '/'], ['readlink', '/' + name]],
                           image_format='qcow2', operation='readlink_' + name).strip()
        require(target == 'usr/' + name, 'usr_merge_binding')
        (tree / name).symlink_to(target)
    require((tree / 'usr/lib/modules' / release).is_dir(), 'kernel_modules')
    return tree, size


def stage_root(output, packages, pins):
    operations = [['mount', '/dev/sda', '/']]
    for name in ('busybox-static', 'libcryptsetup12', 'cryptsetup-bin'):
        item, package = pins['packages'][name], packages[name]
        require(digest(package, maximum=1024 ** 2) ==
                {'bytes': item['bytes'], 'sha256': item['sha256']}, 'package_digest')
        metadata = command(['dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}\n',
                            package]).decode().splitlines()
        require(metadata == [name, item['version'], 'amd64'], 'package_metadata')
        archive = output / (name + '.tar')
        command(['dpkg-deb', '--fsys-tarfile', package], stdout_path=archive,
                maximum=16 * 1024 ** 2)
        safe_tree(archive, output / 'root-tree')
        operations.append(['tar-in', archive, '/'])
    probe = output / 'write-probe'
    probe.write_bytes(WRITE_PROBE)
    operations.extend([
        ['mkdir-p', '/usr/lib/volparossa'], ['upload', ENTRYPOINT, ENTRYPOINT_GUEST],
        ['chmod', '0755', '/usr/lib/volparossa'], ['chown', '0', '0', '/usr/lib/volparossa'],
        ['chmod', '0555', ENTRYPOINT_GUEST], ['chown', '0', '0', ENTRYPOINT_GUEST],
        ['upload', probe, '/usr/lib/volparossa/verity-write-probe'],
        ['chmod', '0644', '/usr/lib/volparossa/verity-write-probe'],
        ['chown', '0', '0', '/usr/lib/volparossa/verity-write-probe'],
        ['mkdir-p', RUNTIME], ['chmod', '0700', RUNTIME],
        ['chown', str(WORKER_UID), str(WORKER_UID), RUNTIME],
        ['touch', RUNTIME + '/.volparossa-compute.lock'],
        ['chmod', '0600', RUNTIME + '/.volparossa-compute.lock'],
        ['chown', str(WORKER_UID), str(WORKER_UID), RUNTIME + '/.volparossa-compute.lock'],
        ['sync'], ['umount-all']])
    guestfish(output / 'root.raw', operations, readonly=False, operation='stage_root')


def verity_options(blocks):
    require(type(blocks) is int and 0 < blocks <= MAX_ROOT // BLOCK_SIZE, 'data_blocks')
    return ['--no-superblock', '--format=1', '--hash=sha256', '--data-block-size=4096',
            '--hash-block-size=4096', '--data-blocks=' + str(blocks), '--salt=' + SALT]


def seal_root(output, size):
    blocks = size // BLOCK_SIZE
    command(['veritysetup', *verity_options(blocks), '--root-hash-file=' + str(output / 'root.hash'),
             'format', output / 'root.raw', output / 'verity.raw'], timeout=300)
    root_hash = (output / 'root.hash').read_text().strip()
    require(re.fullmatch('[0-9a-f]{64}', root_hash), 'verity_root_hash')
    command(['veritysetup', *verity_options(blocks), 'verify', output / 'root.raw',
             output / 'verity.raw', root_hash], timeout=300)
    return root_hash, blocks


def boot_command(output, *, corrupted=False):
    output = Path(output)
    for path in (output / 'vmlinuz', output / 'initrd.img', output / 'root.raw', output / 'verity.raw'):
        require(',' not in str(path) and '\n' not in str(path), 'qemu_path')
    data = output / ('corrupted-root.raw' if corrupted else 'root.raw')
    return ['qemu-system-x86_64', '-name', 'volparossa-protected-public-boot',
            '-no-user-config', '-nodefaults', '-machine', 'q35,accel=kvm', '-cpu', 'host',
            '-smp', '2', '-m', '1024', '-kernel', str(output / 'vmlinuz'),
            '-initrd', str(output / 'initrd.img'), '-append', CMDLINE,
            '-drive', 'if=virtio,format=raw,readonly=on,file=' + str(data),
            '-drive', 'if=virtio,format=raw,readonly=on,file=' + str(output / 'verity.raw'),
            '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-no-reboot', '-sandbox',
            'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def boot_receipt(raw, expected=None):
    require(type(raw) is bytes and len(raw) <= MAX_LOG, 'boot_output_bound')
    rows = [line[len(PREFIX):] for line in raw.splitlines() if line.startswith(PREFIX)]
    require(len(rows) == 1 and len(rows[0]) <= 4096, 'one_boot_receipt')
    value = exact_json(rows[0])
    flags = ('verity_verified', 'root_readonly', 'write_denied', 'entrypoint_invoked')
    denied = ('hardware_attestation', 'private_inputs', 'model_execution', 'worker_execution')
    require(type(value) is dict and set(value) == {'version', 'outcome', 'stage', *flags, *denied}
            and type(value['version']) is int and value['version'] == 1, 'boot_receipt_shape')
    require(all(type(value[key]) is bool for key in (*flags, *denied))
            and not any(value[key] for key in denied), 'boot_scope')
    require(value['outcome'] in ('boot_verified', 'integrity_failure', 'boot_rejected'), 'boot_outcome')
    if expected is not None:
        require(expected in ('boot_verified', 'integrity_failure') and value['outcome'] == expected,
                'boot_outcome')
    if value['outcome'] == 'boot_verified':
        require(value['stage'] == 'complete' and all(value[key] for key in flags), 'boot_proof')
    elif value['outcome'] == 'integrity_failure':
        require(value['stage'] == 'verity_read' and not any(value[key] for key in flags),
                'integrity_proof')
    else:
        require(value['stage'] in ('bootstrap', 'cmdline', 'devices', 'modules', 'verity_open',
                'verity_read', 'root_mount', 'write_probe', 'entrypoint', 'complete')
                and not any(value[key] for key in flags), 'boot_rejection')
    return value


def record(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    require(len(raw) <= 1024 ** 2, 'evidence_bound')
    with open(path, 'xb') as output:
        output.write(raw)


def initrd_receipt(raw, output, pins, root_hash, blocks):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_LOG, 'initrd_receipt_bound')
    value = exact_json(raw)
    keys = {'version', 'kernel_version', 'root_hash', 'data_blocks', 'salt', 'cmdline',
            'original_initrd_sha256', 'hardware_attestation', 'private_inputs',
            'model_execution', 'worker_execution', 'closure', 'initrd_sha256', 'initrd_bytes'}
    require(type(value) is dict and set(value) == keys and type(value['version']) is int
            and value['version'] == 1 and value['kernel_version'] == pins['kernel_release']
            and value['root_hash'] == root_hash and type(value['data_blocks']) is int
            and value['data_blocks'] == blocks and value['salt'] == SALT
            and value['cmdline'] == CMDLINE, 'initrd_receipt_binding')
    require(all(value[key] is False for key in ('hardware_attestation', 'private_inputs',
                'model_execution', 'worker_execution')), 'initrd_receipt_scope')
    closure = value['closure']
    require(type(closure) is dict and 1 <= len(closure) <= 2048
            and all(type(name) is str and re.fullmatch(r'/[A-Za-z0-9_+./-]{1,256}', name)
                    and '..' not in name.split('/') and name.startswith(('/usr/', '/lib/', '/lib64/'))
                    or name == '/init' for name in closure), 'initrd_receipt_closure')
    require(all(type(item) is str and re.fullmatch('[0-9a-f]{64}', item)
                for item in closure.values()), 'initrd_receipt_closure')
    require(value['original_initrd_sha256'] == digest(output / 'original-initrd.img')['sha256']
            and type(value['initrd_bytes']) is int
            and {'bytes': value['initrd_bytes'], 'sha256': value['initrd_sha256']}
                == digest(output / 'initrd.img', maximum=256 * 1024 ** 2), 'initrd_receipt_file')
    return value


def boot_pair(output, evidence):
    good = boot_receipt(command(boot_command(output), timeout=BOOT_SECONDS))
    record(evidence / 'good-boot.json', good)
    require(good['outcome'] == 'boot_verified', 'positive_boot_failed')
    # One authenticated data byte is changed AFTER sealing. The initrd must
    # report both a mapped-read failure and verity status C, not just a timeout.
    corrupt = output / 'corrupted-root.raw'
    command(['cp', '--reflink=auto', '--sparse=always', '--', output / 'root.raw', corrupt], timeout=120)
    with open(corrupt, 'r+b') as changed:
        changed.seek(1024)
        original = changed.read(1)
        require(len(original) == 1, 'corruption_offset')
        changed.seek(1024)
        changed.write(bytes([original[0] ^ 1]))
    bad = boot_receipt(command(boot_command(output, corrupted=True), timeout=BOOT_SECONDS))
    record(evidence / 'corrupt-boot.json', bad)
    require(bad['outcome'] == 'integrity_failure', 'negative_boot_failed')
    return {'good': good, 'corrupt': bad}


def tool_inventory():
    tools = {}
    for name in ('guestfish', 'veritysetup', 'qemu-system-x86_64', 'dpkg-deb', 'readelf'):
        binary = shutil.which(name, path=ENV['PATH'])
        require(binary is not None, 'host_tool_missing')
        resolved = Path(binary).resolve(strict=True)
        tools[name] = {'binary_sha256': digest(resolved, maximum=128 * 1024 ** 2)['sha256'],
                       'version_sha256': hashlib.sha256(command([binary, '--version'])).hexdigest()}
    return {'observed_tools': tools, 'pre_pinned_host_tool_closure': False}


def failure_reason(error):
    allowed = {'cancelled', 'build_deadline', 'command_timeout', 'command_output_bound',
        'command_failed', 'child_join_unconfirmed', 'process_group_remaining', 'process_group_signal_failed',
        'source_revision', 'source_dirty', 'source_changed', 'host_tool_missing',
        'download_origin', 'download_redirect', 'download_status', 'download_bound',
        'download_digest', 'image_digest', 'one_inspected_root', 'inspection_root_binding', 'image_os', 'root_size',
        'kernel_modules', 'usr_merge_binding', 'archive_path', 'archive_bound',
        'archive_parent_symlink', 'archive_overwrite_symlink', 'archive_duplicate',
        'archive_hardlink', 'archive_special_file', 'package_digest', 'package_metadata',
        'verity_root_hash', 'positive_boot_failed', 'negative_boot_failed',
        'one_boot_receipt', 'boot_receipt_shape', 'boot_scope', 'boot_outcome',
        'boot_proof', 'integrity_proof', 'boot_rejection', 'boot_inputs_changed',
        'initrd_receipt_binding', 'initrd_receipt_scope', 'initrd_receipt_closure',
        'initrd_receipt_file', 'initrd_receipt_bound', 'appliance_host_path', 'appliance_host_parent',
        'appliance_host_metadata', 'appliance_kernel_bound', 'appliance_kernel_release',
        'appliance_stage_path', 'appliance_stage_metadata', 'appliance_stage_bound',
        'appliance_stage_binding', 'appliance_source_changed', 'hypervisor_binding',
        'qmp_input', 'qmp_protocol', 'qmp_kvm_unavailable', 'kvm_launch_identity',
        'kvm_launch_group', 'kvm_launch_device', 'kvm_launch_acl', 'kvm_launch_privileges'}
    if isinstance(error, (ValueError, CleanupUnconfirmed)) and error.args:
        reason = error.args[0]
        if type(reason) is str and reason in allowed:
            return reason
    if isinstance(error, OSError):
        return 'io_error'
    return 'unclassified'


def execute(args):
    require(args.yes, 'explicit_hosted_execution')
    launch = verify_kvm_launch()
    pins = load_pins()
    work = hosted_output(args.work)
    evidence, output = work / 'evidence', work / 'payload'
    evidence.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    deadline, cleanup_safe, completed = time.monotonic() + BUILD_SECONDS, True, False
    stage, failure, cleanup_error, primary = 'source', None, None, None
    preflight, appliance, qmp, capture = None, None, None, None
    budget_token = DEADLINE.set(deadline)
    appliance_token = APPLIANCE.set(None)
    hypervisor_token = HYPERVISOR.set(None)
    capture_token = QMP_CAPTURE.set(None)
    scratch = output / 'temporary'
    scratch.mkdir(mode=0o700)
    scratch_token = SCRATCH.set(scratch)
    cancel_token = CANCELLED.set(False)
    previous_signals = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    for number in previous_signals:
        # Defer cancellation to a bounded checkpoint instead of raising in the
        # narrow Popen construction/registration window. Owned children are then
        # killed and joined by command() before outer scratch removal.
        signal.signal(number, lambda _number, _frame: CANCELLED.set(True))
    try:
        stage = 'appliance_stage'
        appliance = adopt_appliance(output, args.expected_source)
        deadline = appliance['deadline']
        DEADLINE.set(deadline)
        APPLIANCE.set(appliance)
        stage = 'source'
        source = source_binding(args.expected_source)
        stage = 'host_tools'
        tools = tool_inventory()
        stage = 'appliance_preflight'
        preflight = appliance_preflight()
        stage = 'qmp_kvm_preflight'
        qmp = qmp_observation()
        qmp_preflight(tools, qmp)
        capture = prepare_qmp_capture()
        QMP_CAPTURE.set(capture)
        stage = 'input_download'
        image_pin = exact_json((ROOT / pins['debian_image_manifest']).read_bytes())
        image = output / 'debian.qcow2'
        fetch(image_pin, image, 'sha512', MAX_IMAGE, deadline)
        packages = {}
        for name, item in pins['packages'].items():
            packages[name] = output / (name + '.deb')
            fetch(item, packages[name], 'sha256', item['bytes'], deadline)
        stage = 'image_extract'
        tree, size = extract_boot(image, output, pins)
        stage = 'root_stage'
        stage_root(output, packages, pins)
        stage = 'root_seal'
        root_hash, blocks = seal_root(output, size)
        stage = 'initrd_build'
        initrd = command([sys.executable, HERE / 'protected-resident-initrd.py', tree,
            output / 'original-initrd.img', pins['kernel_release'], root_hash, str(blocks),
            output / 'initrd.img'], timeout=300)
        record(evidence / 'initrd.json', initrd_receipt(initrd, output, pins, root_hash, blocks))
        project_qmp_capture(capture, joined=True)
        descriptor = dict(version=1, kind='protected-resident-public-boot-build',
            source=source, kernel_release=pins['kernel_release'], verity=pins['verity'],
            root_hash=root_hash, data_blocks=blocks, cmdline=CMDLINE, host_tools=tools,
            appliance_kernel=appliance['receipt'], qmp_kvm_preflight=qmp, process_launch=launch,
            original_qmp_observation=capture['receipt'],
            inputs={'image_sha512': pins['debian_image_sha512'], 'packages': pins['packages'],
                    'pins': digest(PINS), 'bootstrap': digest(BOOTSTRAP), 'entrypoint': digest(ENTRYPOINT)},
            files={name: digest(output / name) for name in ('vmlinuz', 'initrd.img', 'root.raw', 'verity.raw')},
            public_test_inputs_only=True, independent_production_approval=False,
            model_execution=False, worker_admission=False, private_input_release=False,
            hardware_attestation=False, confidential_execution=False)
        record(evidence / 'build.json', descriptor)
        require(time.monotonic() < deadline, 'build_deadline')
        stage = 'boot_pair'
        boot_pair(output, evidence)
        stage = 'post_boot_binding'
        require(all(digest(output / name) == expected for name, expected in descriptor['files'].items()),
                'boot_inputs_changed')
        require(source_binding(args.expected_source) == source, 'source_changed')
        appliance_environment()
        completed = True
        stage = 'complete'
    except BaseException as error:
        primary = error
        failure = {'stage': stage, 'reason': failure_reason(error), 'command': command_failure(error)}
        if isinstance(error, CleanupUnconfirmed):
            cleanup_safe = False
        raise
    finally:
        project_qmp_capture(capture, joined=cleanup_safe)
        DEADLINE.reset(budget_token)
        APPLIANCE.reset(appliance_token)
        HYPERVISOR.reset(hypervisor_token)
        QMP_CAPTURE.reset(capture_token)
        SCRATCH.reset(scratch_token)
        try:
            if cleanup_safe:
                try:
                    shutil.rmtree(output)
                except OSError:
                    cleanup_error = 'scratch_removal_failed'
            try:
                record(evidence / 'cleanup.json', dict(version=1, kind='protected-resident-public-boot-cleanup',
                    child_leaders_reaped=cleanup_safe, original_process_groups_absent=cleanup_safe,
                    owned_scratch_removed=cleanup_safe and not output.exists(),
                    boot_pair_verified=completed, failure=failure, cleanup_error=cleanup_error,
                    appliance_preflight=preflight,
                    process_launch=launch,
                    qmp_kvm_preflight=qmp,
                    original_qmp_observation=capture['receipt'] if capture is not None else None,
                    appliance_kernel=appliance['receipt'] if appliance is not None else None,
                    hardware_attestation=False, private_inputs=False))
            except (OSError, ValueError):
                if primary is None:
                    raise
            if cleanup_error is not None and primary is None:
                raise CleanupUnconfirmed('scratch_removal_failed')
        finally:
            CANCELLED.reset(cancel_token)
            for number, handler in previous_signals.items():
                signal.signal(number, handler)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('execute', 'prepare-appliance', 'finish-appliance',
                                         'cleanup-appliance', 'kvm-launch-ids'))
    parser.add_argument('--work')
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--yes', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'execute':
            require(args.work is not None, 'new_private_output')
            execute(args)
        elif args.action == 'prepare-appliance':
            print(prepare_appliance(args))
        elif args.action == 'finish-appliance':
            finish_appliance(args)
        elif args.action == 'kvm-launch-ids':
            print(*kvm_launch_ids(args))
        else:
            cleanup_appliance(args)
    except (OSError, ValueError, subprocess.SubprocessError, CleanupUnconfirmed) as error:
        # Preparation may fail before execute creates its evidence directory.
        # Both labels are closed; never print paths, argv or raw error text.
        print('protected_resident_image_failed action=' + args.action
              + ' reason=' + failure_reason(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
