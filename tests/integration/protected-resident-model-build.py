#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build PUBLIC resident assets in an explicitly disposable Debian guest only.

The controller installs the authenticated locked packages BEFORE this command,
supplies the exact Git archive/commit and public fixture declarations, and owns
the finite guest systemd cgroup. In particular the native compiler starts a
separate session: joining our direct process groups is NOT whole-cgroup cleanup.
No inference, owner approval, hardware appraisal or private input is performed.
Incomplete output is retained for controller-owned cleanup after the VM joins.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import types

CODE_COMMIT = 'fd4ff9688c58d6228e07f2116a7e8dcdb12a89ef'
HELPER_SHA256 = '32a79a1801de0979fdca0064c5bbd2c09b71069a0141be7d68aaec01006bbcbf'
LLAMA_SOURCE = '7fe450e19305b828c199d602c23a8337aaa1f03b'
LLAMA_ORIGIN = 'https://github.com/ggml-org/llama.cpp.git'
MODEL = 'qwen3-4b-instruct-2507-v1'
PROVISION_BYTES = 20 * 1024 ** 3
MAX_SECONDS = 7200
MAX_LOG = 16 * 1024 ** 2
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]*\Z')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'PYTHONDONTWRITEBYTECODE': '1', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
       'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_INCREMENTAL': '0'}
# Diagnostic schema only. These exact source-owned labels never authorize work.
EXPORT_ERRORS = {
    'declaration': frozenset(('build_deadline', 'module_path', 'input_file', 'input_changed',
        'duplicate_json_key', 'nonfinite_json', 'public_requester_declaration')),
    'relocate': frozenset(),
    'core_copy': frozenset(('build_deadline', 'core_binary_metadata', 'core_binary_elf',
        'core_binary_changed', 'core_binary_copy', 'asset_file', 'asset_changed')),
    'fixture_copy': frozenset(('build_deadline', 'input_file', 'input_changed', 'public_tls_fixture')),
    'inventory': frozenset(('build_deadline', 'stage_deadline', 'inventory_entries',
        'asset_directory_metadata', 'asset_file', 'asset_changed', 'export_bytes',
        'inventory_digest', 'core_source', 'inventory_bound', 'inventory_scope', 'inventory_entry',
        'asset_scope', 'lease_is_generated', 'symlink_scope', 'file_inventory', 'executable_scope',
        'inventory_parent_file', 'inventory_total', 'core_executable', 'symlink_loop',
        'symlink_external', 'symlink_escape', 'symlink_target', 'symlink_missing')),
    'metadata': frozenset(('stage_deadline', 'asset_path', 'asset_file_metadata', 'asset_file_bound',
        'asset_digest', 'duplicate_json_key', 'nonfinite_json', 'model_inventory', 'model_pin',
        'native_inventory', 'native_session_required', 'native_build_digest', 'native_build_binding',
        'native_dependency_binding', 'native_wrapper_binding', 'native_artifact_binding',
        'runtime_python', 'runtime_config', 'elf_bound', 'elf_identity', 'public_policy_binding',
        'fixture_tls_bound', 'symlink_loop', 'symlink_external', 'symlink_escape', 'symlink_target',
        'symlink_missing', 'NATIVE_OUTPUT_CONSTRAINT_VERSION', 'NATIVE_OUTPUT_CONSTRAINT_BINDING',
        'NATIVE_SESSION_BINDING', 'NATIVE_BUILD_PATCH_BINDING', 'NATIVE_CPU_PATCH_BINDING',
        'NATIVE_ARTIFACT_BINDING', 'NATIVE_CONVERSION_BINDING', 'NATIVE_MANIFEST_BINDING',
        'NATIVE_MANIFEST_FIELDS')),
    'write_inventory': frozenset(),
    'source_recheck': frozenset(('build_deadline', 'input_file', 'input_changed', 'source_commit',
        'source_path', 'source_commit_tree', 'source_entries', 'source_owner', 'source_bytes',
        'source_tree', 'helper_path', 'helper_source', 'source_changed')),
    'final_deadline': frozenset(('build_deadline',)),
}
EXPORT_CATEGORIES = frozenset(('missing_file', 'existing_path', 'permission_denied', 'interrupted',
    'timeout', 'io_error', 'missing_field', 'invalid_type', 'invalid_value', 'subprocess_failed',
    'cleanup_unconfirmed'))


def export_failure(error, operation):
    # Never stringify exceptions: only exact closed labels or their class escape.
    if (type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str
            and type(operation) is str and operation in EXPORT_ERRORS
            and error.args[0] in EXPORT_ERRORS[operation]):
        return error.args[0]
    for kind, label in ((CleanupUnconfirmed, 'cleanup_unconfirmed'),
            (FileNotFoundError, 'missing_file'), (FileExistsError, 'existing_path'),
            (PermissionError, 'permission_denied'), (InterruptedError, 'interrupted'),
            (TimeoutError, 'timeout'), (OSError, 'io_error'), (KeyError, 'missing_field'),
            (TypeError, 'invalid_type'), (subprocess.SubprocessError, 'subprocess_failed')):
        if isinstance(error, kind):
            return label
    return 'invalid_value'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def remaining(deadline, cap=MAX_SECONDS):
    require(type(deadline) is int and 0 < deadline < 2 ** 63, 'build_deadline')
    value = (deadline - time.monotonic_ns()) / 1_000_000_000
    require(0 < value <= MAX_SECONDS and 0 < cap <= MAX_SECONDS, 'build_deadline')
    return min(value, cap)


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate_json_key')
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: require(False, 'nonfinite_json'))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def read_file(path, maximum, deadline):
    remaining(deadline)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum, 'input_file')
        raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno())),
                'input_changed')
    remaining(deadline)
    return raw


def file_record(path, deadline):
    remaining(deadline)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & 0o022 and before.st_size <= 9 * 1024 ** 3, 'asset_file')
        digest = hashlib.sha256()
        while block := stream.read(1024 ** 2):
            remaining(deadline)
            digest.update(block)
        require(identity(before) == identity(os.fstat(stream.fileno())), 'asset_changed')
    return dict(kind='file', bytes=before.st_size, sha256=digest.hexdigest(),
                executable=bool(before.st_mode & 0o111))


def git_object(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()


def source_tree(root, deadline):
    """Reconstruct the exact Git tree of a complete extracted archive, no .git."""
    count, total = 0, 0

    def visit(directory):
        nonlocal count, total
        items = []
        with os.scandir(directory) as entries:
            for entry in entries:
                remaining(deadline)
                count += 1
                require(count <= 65536 and entry.name != '.git', 'source_entries')
                meta = entry.stat(follow_symlinks=False)
                require(meta.st_uid == os.getuid()
                        and (stat.S_ISLNK(meta.st_mode) or not meta.st_mode & 0o022), 'source_owner')
                name = os.fsencode(entry.name)
                if stat.S_ISDIR(meta.st_mode):
                    mode, digest, order = b'40000', visit(Path(entry.path)), name + b'/'
                elif stat.S_ISLNK(meta.st_mode):
                    # Git archives may contain source links; they are hashed,
                    # never traversed. Input module paths separately forbid them.
                    mode, digest, order = b'120000', git_object('blob', os.fsencode(os.readlink(entry.path))), name
                else:
                    raw = read_file(entry.path, 64 * 1024 ** 2, deadline)
                    total += len(raw)
                    require(total <= 512 * 1024 ** 2, 'source_bytes')
                    mode = b'100755' if meta.st_mode & 0o111 else b'100644'
                    digest, order = git_object('blob', raw), name
                items.append((order, mode + b' ' + name + b'\0' + digest))
        return git_object('tree', b''.join(item for _, item in sorted(items)))

    return visit(root).hex()


def source_binding(inputs, expected, deadline):
    require(type(expected) is str and COMMIT.fullmatch(expected), 'source_commit')
    core = inputs / 'core'
    require(core.resolve(strict=True) == core and core.is_dir(), 'source_path')
    raw = read_file(inputs / 'core.commit', 65536, deadline)
    require(git_object('commit', raw).hex() == expected, 'source_commit')
    first = raw.split(b'\n', 1)[0]
    require(re.fullmatch(rb'tree [0-9a-f]{40}', first), 'source_commit_tree')
    tree = source_tree(core, deadline)
    require(tree == first[5:].decode(), 'source_tree')
    helper = inputs / 'code/scripts/opencode_native_cpu.py'
    require(helper.resolve(strict=True) == helper, 'helper_path')
    require(hashlib.sha256(read_file(helper, 1024 ** 2, deadline)).hexdigest() == HELPER_SHA256,
            'helper_source')
    return core, helper, tree


def load_module(path, name):
    # Only used after complete source/helper binding. No source __pycache__.
    require(path.resolve(strict=True) == path, 'module_path')
    value = types.ModuleType(name)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


class CleanupUnconfirmed(RuntimeError):
    pass


def group_absent(pid):
    end = time.monotonic() + 2
    while True:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        if time.monotonic() >= end:
            return False
        time.sleep(.02)


def command(argv, deadline, *, cap=300, cwd=None, extra_env=None, maximum=MAX_LOG):
    """Bound output; retain unreaped leader until final group signal.

    A separate-session compiler is ultimately owned by the controller's guest
    cgroup. This function claims only its direct leader/group, not that cgroup.
    """
    end = time.monotonic() + remaining(deadline, cap)
    process = subprocess.Popen([str(item) for item in argv], cwd=cwd,
        env=dict(ENV, **(extra_env or {})), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    output, count = bytearray(), 0
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                remaining(deadline)
                require(time.monotonic() < end, 'command_timeout')
                for key, _ in selector.select(.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(block)
                    require(count <= maximum, 'command_output_bound')
                    if key.fileobj is process.stdout:
                        output.extend(block)
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                remaining(deadline)
                require(time.monotonic() < end, 'command_timeout')
                time.sleep(.01)
    finally:
        failed = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            failed = True
        try:
            try:
                process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError) as error:
                raise CleanupUnconfirmed('leader_join') from error
            try:
                absent = group_absent(process.pid)
            except OSError as error:
                raise CleanupUnconfirmed('group_observation_interrupted') from error
            if failed or not absent:
                raise CleanupUnconfirmed('group_join')
        finally:
            process.stdout.close()
            process.stderr.close()
    require(process.returncode == 0, 'command_failed')
    return bytes(output)


def guest_guard(args):
    remaining(args.deadline_monotonic_ns)
    require(args.execute and args.yes and args.disposable_guest, 'execution_consent')
    require(os.getuid() == os.geteuid() > 0 and pwd.getpwuid(os.getuid()).pw_name == 'vpci'
            and socket.gethostname() == 'volparossa-alpha'
            and platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 13), 'disposable_guest')
    require(command(['/usr/bin/systemd-detect-virt', '--vm'], args.deadline_monotonic_ns,
                    cap=10, maximum=1024).strip() == b'kvm', 'disposable_guest')
    release = Path('/etc/os-release').resolve(strict=True)
    require(release in (Path('/etc/os-release'), Path('/usr/lib/os-release')), 'guest_release_path')
    require('VERSION_ID="13"' in read_file(release, 16384, args.deadline_monotonic_ns).decode(),
            'guest_debian')


def package_lock(path, digest, deadline):
    raw = read_file(path, 4 * 1024 ** 2, deadline)
    require(type(digest) is str and SHA.fullmatch(digest)
            and hashlib.sha256(raw).hexdigest() == digest, 'package_lock_digest')
    value = parse(raw)
    require(type(value) is dict and type(value.get('version')) is int and value['version'] == 1
            and value.get('kind') == 'protected-resident-debian-package-lock'
            and value.get('architecture') == 'amd64', 'package_lock')
    profiles, packages = value.get('profiles'), value.get('packages')
    require(type(profiles) is dict and set(profiles) == {'build', 'runtime'}
            and type(packages) is dict and 0 < len(packages) <= 512, 'package_lock')
    for profile in profiles.values():
        require(type(profile) is dict and set(profile) == {'roots', 'packages'}, 'package_profile')
        for key in ('roots', 'packages'):
            names = profile[key]
            require(type(names) is list and names and len(names) <= 512
                    and all(type(name) is str and PACKAGE.fullmatch(name) for name in names)
                    and len(names) == len(set(names)) and set(names) <= packages.keys(), 'package_names')
        require(set(profile['roots']) <= set(profile['packages']), 'package_roots')
    require(set(profiles['runtime']['packages']) <= set(profiles['build']['packages']), 'package_closure')
    for name, item in packages.items():
        require(type(name) is str and PACKAGE.fullmatch(name) and type(item) is dict
                and set(item) == {'version', 'architecture', 'filename', 'url', 'bytes', 'sha256',
                                  'index', 'depends', 'pre_depends'}
                and type(item['version']) is str and re.fullmatch(r'[A-Za-z0-9.+:~\-]{1,128}', item['version'])
                and item['architecture'] in ('amd64', 'all') and type(item['bytes']) is int
                and 0 < item['bytes'] <= 1024 ** 3 and type(item['sha256']) is str
                and SHA.fullmatch(item['sha256']), 'package_record')
    return value


def verify_packages(lock, deadline):
    names = sorted(lock['profiles']['build']['packages'])
    raw = command(['/usr/bin/dpkg-query', '--show',
        '--showformat=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n', *names],
        deadline, cap=30, maximum=1024 ** 2)
    observed = {}
    for line in raw.decode('ascii').splitlines():
        fields = line.split('\t')
        require(len(fields) == 4 and fields[0] not in observed, 'installed_package_shape')
        observed[fields[0]] = fields[1:]
    expected = {name: [lock['packages'][name]['version'], lock['packages'][name]['architecture'], 'installed']
                for name in names}
    require(observed == expected, 'installed_package_binding')
    return len(names)


def build_assets(core, output, deadline):
    target, native = output / 'target', output / 'native'
    native.mkdir(mode=0o700)
    for name in ('home', 'cargo-home'):
        (output / name).mkdir(mode=0o700)
    command(['/usr/bin/cargo', 'build', '--locked', '-p', 'volparossa', '--bin', 'volparossa'],
            deadline, cap=1200, cwd=core, extra_env={'CARGO_TARGET_DIR': str(target),
                'CARGO_HOME': str(output / 'cargo-home'), 'HOME': str(output / 'home')})
    source = native / 'llama-source'
    source.mkdir(mode=0o700)
    git = ['/usr/bin/git', '-c', 'credential.helper=', '-c', 'protocol.file.allow=never',
           '-c', 'protocol.ext.allow=never']
    native_deadline = min(deadline, time.monotonic_ns() + 1800 * 1_000_000_000)
    for operation in (['init', '--quiet'], ['remote', 'add', 'origin', LLAMA_ORIGIN],
                      ['fetch', '--depth=1', '--no-tags', 'origin', LLAMA_SOURCE],
                      ['checkout', '--detach', '--quiet', 'FETCH_HEAD']):
        command([*git, *operation], native_deadline, cwd=source)
    command(['/usr/bin/python3.13', '-B', core / 'workers/volparossa-ml/build_llama_cpu.py',
             '--source', source, '--output', native / 'llama-build', '--execute'],
            native_deadline, cap=1800)
    return target / 'debug/volparossa', native


def provision(core, native, deadline):
    seconds = int(remaining(deadline, 1800))
    require(seconds >= 1, 'build_deadline')
    command(['/usr/bin/python3.13', '-B', core / 'workers/volparossa-ml/provision.py',
        '--execute', '--yes', '--disposable-guest', '--root', native / 'ml',
        '--budget-bytes', str(PROVISION_BYTES), '--timeout-seconds', str(seconds),
        '--model-profile', MODEL, '--native-cpu-source', native / 'llama-source',
        '--native-cpu-build', native / 'llama-build'], deadline, cap=seconds)
    report = parse(read_file(native / 'ml/provision-report.json', 65536, deadline))
    contract = load_module(core / 'workers/volparossa-ml/provision.py', 'resident_provision')
    pins = contract.load_pins(model_profile=MODEL, native_cpu_converter=True)
    pin_bytes, requirements = contract.retained_pin_files(pins)
    expected = dict(model_id=pins['model_id'], revision=pins['revision'], model_profile=MODEL,
        download_bytes=contract.download_total(pins), budget_bytes=PROVISION_BYTES,
        installed_wheels=len(pins['wheels']), model_pins_sha256=hashlib.sha256(pin_bytes).hexdigest(),
        requirements_sha256=hashlib.sha256(requirements).hexdigest())
    require(report.get('success') is True and report.get('training_performed') is False
            and report.get('runtime_autofetch_enabled') is False
            and {key: report.get(key) for key in expected} == expected, 'provision_binding')
    require(read_file(native / 'ml/model-pins.json', 1024 ** 2, deadline) == pin_bytes
            and read_file(native / 'ml/requirements.lock', 1024 ** 2, deadline) == requirements,
            'retained_provision_pins')
    return report, expected


def asset_inventory(root, source, stager, deadline):
    entries, total = {}, 0
    for name in sorted(stager.scan(root, deadline / 1_000_000_000)):
        path = root / name
        if path.is_symlink():
            item = dict(kind='symlink', target=os.readlink(path))
        else:
            item = file_record(path, deadline)
            total += item['bytes']
            require(total <= stager.MAX_TOTAL, 'export_bytes')
        entries[name] = item
    return dict(version=1, kind='protected-resident-public-workload', public_fixture_only=True,
                core_source_commit=source, entries=entries)


def write_new(path, raw, mode=0o600):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), 'wb') as stream:
        stream.write(raw)


def copy_core_binary(source, target, deadline):
    """Cargo hardlinks target/debug to deps; export an independent bound ELF.

    Only this source accepts multiple links. The resulting asset still passes
    the unchanged single-link guard and is never executed by this exporter.
    """
    remaining(deadline)
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as original:
        before = os.fstat(original.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink >= 1 and not before.st_mode & 0o022 and before.st_mode & 0o111
                and 64 <= before.st_size <= 256 * 1024 ** 2, 'core_binary_metadata')
        header = original.read(64)
        require(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01'
                and int.from_bytes(header[16:18], 'little') in (2, 3)
                and int.from_bytes(header[18:20], 'little') == 62, 'core_binary_elf')
        original.seek(0)
        digest, count = hashlib.sha256(), 0
        with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o700), 'wb') as copied:
            while block := original.read(1024 ** 2):
                remaining(deadline)
                count += len(block)
                require(count <= before.st_size, 'core_binary_changed')
                digest.update(block)
                copied.write(block)
        require(count == before.st_size and identity(before) == identity(os.fstat(original.fileno())),
                'core_binary_changed')
    require(file_record(target, deadline) == dict(kind='file', bytes=count,
                sha256=digest.hexdigest(), executable=True), 'core_binary_copy')


def export_assets(core, binary, native, fixture, output, source, deadline, progress=None):
    if progress is not None:
        progress['operation'] = 'declaration'
    stager = load_module(core / 'tests/integration/protected-resident-model-workload.py', 'resident_stager')
    declaration = parse(read_file(fixture / 'requester.json', 4096, deadline))
    require(type(declaration) is dict and set(declaration) == {'requester_key', 'public_input_sha256'}
            and type(declaration['requester_key']) is str and SHA.fullmatch(declaration['requester_key'])
            and type(declaration['public_input_sha256']) is list and len(declaration['public_input_sha256']) == 2
            and all(type(item) is str and SHA.fullmatch(item) for item in declaration['public_input_sha256']),
            'public_requester_declaration')
    if progress is not None:
        progress['operation'] = 'relocate'
    assets = output / 'assets'
    assets.mkdir(mode=0o700)
    # Rename same-filesystem owned assets rather than duplicating ~20 GiB.
    (native / 'ml/venv').rename(assets / 'runtime')
    (native / 'ml/model').rename(assets / 'model')
    backend = assets / 'native-backend'
    backend.mkdir(mode=0o700)
    for name in sorted(stager.NATIVE | {'licenses'}):
        (native / 'ml/native-backend' / name).rename(backend / name)
    if progress is not None:
        progress['operation'] = 'core_copy'
    copy_core_binary(binary, assets / 'volparossa', deadline)
    if progress is not None:
        progress['operation'] = 'fixture_copy'
    for name in ('server.der', 'server-key.der'):
        raw = read_file(fixture / name, 8192, deadline)
        require(raw, 'public_tls_fixture')
        write_new(assets / name, raw)
    if progress is not None:
        progress['operation'] = 'inventory'
    value = asset_inventory(assets, source, stager, deadline)
    workload = stager.workload_sha256(value)
    policy = dict(version=1, visibility='public_fixture', workload_sha256=workload, **declaration)
    write_new(assets / 'public-policy.json', encoded(policy))
    value['entries']['public-policy.json'] = file_record(assets / 'public-policy.json', deadline)
    raw = encoded(value)
    digest = hashlib.sha256(raw).hexdigest()
    checked = stager.inventory(raw, digest, source)
    if progress is not None:
        progress['operation'] = 'metadata'
    fd = os.open(assets, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        backend_digest = stager.verified_metadata(fd, checked, deadline / 1_000_000_000)
    finally:
        os.close(fd)
    if progress is not None:
        progress['operation'] = 'write_inventory'
    write_new(output / 'inventory.json', raw)
    return dict(inventory_sha256=digest, workload_sha256=workload, native_backend_sha256=backend_digest,
                asset_files=len(value['entries']), asset_bytes=sum(item.get('bytes', 0)
                                                                 for item in value['entries'].values()))


def execute(args):
    guest_guard(args)
    deadline = args.deadline_monotonic_ns
    require(type(args.expected_source) is str and COMMIT.fullmatch(args.expected_source)
            and type(args.package_lock_sha256) is str and SHA.fullmatch(args.package_lock_sha256),
            'input_binding_shape')
    inputs, output = args.input, args.output
    require(inputs.is_absolute() and inputs.resolve(strict=True) == inputs and inputs.is_dir(), 'input_path')
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
            and output.parent.stat().st_uid == os.getuid() and not output.is_relative_to(inputs)
            and not inputs.is_relative_to(output) and not output.exists() and not output.is_symlink(), 'output_path')
    previous_umask = os.umask(0o077)
    previous_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    created = None
    report = dict(version=1, kind='protected-resident-public-model-build', state='failed', phase='source',
        source_commit=args.expected_source, code_helper_commit=CODE_COMMIT, code_helper_sha256=HELPER_SHA256,
        package_lock_sha256=args.package_lock_sha256, assets_exported=False, model_execution=False,
        worker_execution=False, private_inputs=False, hardware_attestation=False, production_approval=False,
        controller_cgroup_cleanup_required=True, direct_child_groups_joined=True, descendants_joined=None,
        complete_guest_cleanup=False, scratch_removed=False)
    try:
        output.mkdir(mode=0o700)
        meta = output.lstat()
        created = (meta.st_dev, meta.st_ino)
        core, helper_path, tree = source_binding(inputs, args.expected_source, deadline)
        report['source_tree'] = tree
        report['phase'] = 'packages'
        lock = package_lock(args.package_lock, args.package_lock_sha256, deadline)
        report['installed_build_packages'] = verify_packages(lock, deadline)
        helper = load_module(helper_path, 'resident_native_validator')
        require(helper.SOURCE == LLAMA_SOURCE and helper.ORIGIN == LLAMA_ORIGIN and helper.MODEL == MODEL,
                'native_helper_contract')
        report['phase'] = 'build'
        binary, native = build_assets(core, output, deadline)
        remaining(deadline)
        built = helper.validate_build(core, native)
        report['phase'] = 'provision'
        provisioned, report['provision'] = provision(core, native, deadline)
        backend = helper.validate_provision(core, native, provisioned, built)
        helper.require_output_constraint(built, backend)
        report['native_build_manifest_sha256'] = built['build_manifest_sha256']
        report['phase'] = 'export'
        report['export_diagnostic'] = dict(operation='declaration', reason=None)
        report['export'] = export_assets(core, binary, native, inputs / 'fixture', output,
                                         args.expected_source, deadline, report['export_diagnostic'])
        report['export_diagnostic']['operation'] = 'source_recheck'
        require(source_binding(inputs, args.expected_source, deadline)[2] == tree, 'source_changed')
        report['export_diagnostic']['operation'] = 'final_deadline'
        remaining(deadline)
        report.pop('export_diagnostic')  # Preserve the exact successful assembly receipt schema.
        report.update(state='assets_built', phase='complete', assets_exported=True)
    except CleanupUnconfirmed as error:
        report['direct_child_groups_joined'] = False
        if 'export_diagnostic' in report:
            report['export_diagnostic']['reason'] = export_failure(error, report['export_diagnostic']['operation'])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        if 'export_diagnostic' in report:
            report['export_diagnostic']['reason'] = export_failure(error, report['export_diagnostic']['operation'])
        # Closed labels only. No argv, source text, paths or exception export.
    finally:
        try:
            meta = output.lstat() if created is not None else None
            if (meta is not None and stat.S_ISDIR(meta.st_mode)
                    and (meta.st_dev, meta.st_ino) == created):
                write_new(output / 'build-result.json', encoded(report))
        finally:
            sys.dont_write_bytecode = previous_bytecode
            os.umask(previous_umask)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--yes', action='store_true', required=True)
    parser.add_argument('--disposable-guest', action='store_true', required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--package-lock', type=Path, required=True)
    parser.add_argument('--package-lock-sha256', required=True)
    parser.add_argument('--deadline-monotonic-ns', type=int, required=True)
    args = parser.parse_args(argv)
    previous = {}

    def cancel(_signum, _frame):
        raise InterruptedError('cancelled')

    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, cancel)
        value = execute(args)
        print(encoded(value).decode(), end='')
        return 0 if value['state'] == 'assets_built' else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('{"version":1,"kind":"protected-resident-public-model-build","state":"rejected"}')
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    raise SystemExit(main())
