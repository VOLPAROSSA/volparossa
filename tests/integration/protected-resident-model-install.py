#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline package configuration in an explicitly disposable Debian build guest.

The controller authenticates this source and owns a finite systemd cgroup and
the VM. This program never installs on the development/runner host. Package
scripts run only in the guest, in a private mount/network/PID namespace. A
successful receipt is package configuration, not model execution or complete
guest cleanup. The controller must join the whole unit and VM before export.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

LOCK_SHA256 = 'ab3fe950b2e39e7f556843cb76a5421ae039a6b10464a7a5109150dae5dc1af8'
COUNTS = {'build': 199, 'runtime': 65}
RUNTIME_DISK = Path('/dev/disk/by-id/virtio-vp-resident-runtime')
RUNTIME_SERIAL = 'vp-resident-runtime'
DISK_BYTES = 32 * 1024 ** 3
MAX_SECONDS = 7200
MAX_OUTPUT = 8 * 1024 ** 2
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]*\Z')
VERSION = re.compile(r'[A-Za-z0-9.+:~\-]{1,128}\Z')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
       'PYTHONDONTWRITEBYTECODE': '1', 'DEBIAN_FRONTEND': 'noninteractive',
       'SYSTEMD_OFFLINE': '1'}
POLICY = b'#!/bin/sh\nexit 101\n'
STATUS_FORMAT = '${Package}\t${Version}\t${Architecture}\t${Status}\t${Triggers-Pending}\t${Triggers-Awaited}\n'
PREPARATION_PHASES = ('runtime_device', 'runtime_fsck', 'runtime_resize', 'runtime_mount',
                      'runtime_bootstrap', 'archive_mount')
PREPARATION_GUARDS = {
    'runtime_device': ('runtime_alias', 'runtime_path', 'runtime_device', 'runtime_serial',
        'runtime_root_device', 'runtime_already_mounted', 'runtime_changed', 'runtime_size',
        'runtime_ext4', 'mountinfo_bound', 'kernel_file_bound'),
    'runtime_bootstrap': ('runtime_debian', 'runtime_mountpoint', 'input_file', 'input_changed'),
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def remaining(deadline, cap=MAX_SECONDS):
    require(type(deadline) is int and 0 < deadline < 2 ** 63, 'deadline')
    value = (deadline - time.monotonic_ns()) / 1e9
    require(0 < value <= MAX_SECONDS and 0 < cap <= MAX_SECONDS, 'deadline')
    return min(value, cap)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'json_duplicate')
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: require(False, 'json_constant'))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def read_file(path, maximum, deadline):
    remaining(deadline)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum, 'input_file')
        raw = source.read(maximum + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(source.fileno())),
                'input_changed')
    remaining(deadline)
    return raw


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, mode)
    with os.fdopen(fd, 'wb') as target:
        target.write(raw)
        os.fchmod(target.fileno(), mode)


def bounded_kernel_file(path, maximum):
    with path.open('rb') as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, 'kernel_file_bound')
    return raw


class CleanupUnconfirmed(Exception):
    pass


class Runner:
    def __init__(self, deadline):
        self.deadline = deadline
        self.joined = True

    def run(self, argv, *, cap=600, allowed=(0,), maximum=MAX_OUTPUT, env=None):
        end = time.monotonic() + remaining(self.deadline, cap)
        output, error, natural = bytearray(), None, False
        process = subprocess.Popen([str(item) for item in argv], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(ENV, **(env or {})),
            start_new_session=True, close_fds=True)
        try:
            os.set_blocking(process.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    require(time.monotonic() < end, 'command_deadline')
                    event = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    natural = event is not None
                    for _key, _mask in selector.select(min(0.1, max(0, end - time.monotonic()))):
                        block = os.read(process.stdout.fileno(), 65536)
                        if block:
                            output.extend(block)
                            require(len(output) <= maximum, 'command_output')
                        else:
                            selector.unregister(process.stdout)
                    if natural and not selector.get_map():
                        break
        except BaseException as caught:
            error = caught
        finally:
            # Never signal a recycled PGID: hold the leader unreaped until the
            # final group signal. The controller still owns separate sessions.
            try:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                end_join = time.monotonic() + 2
                while True:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    require(time.monotonic() < end_join, 'group_join')
                    time.sleep(0.02)
            except BaseException:
                self.joined = False
                try:
                    process.wait(timeout=5)
                except BaseException:
                    pass
            finally:
                process.stdout.close()
        if error is not None:
            raise error
        if not self.joined:
            raise CleanupUnconfirmed()
        require(natural and process.returncode in allowed, 'command_failed')
        return bytes(output)


def guest_guard(args, runner):
    remaining(args.deadline_monotonic_ns)
    require(args.execute and args.yes and args.disposable_guest, 'consent')
    require(os.getresuid() == (0, 0, 0) and platform.system() == 'Linux'
            and platform.machine() == 'x86_64' and socket.gethostname() == 'volparossa-alpha',
            'disposable_guest')
    release = Path('/etc/os-release').resolve(strict=True)
    require(release in (Path('/etc/os-release'), Path('/usr/lib/os-release'))
            and 'VERSION_ID="13"' in read_file(release, 16384, runner.deadline).decode(), 'guest_debian')
    require(runner.run(['/usr/bin/systemd-detect-virt', '--vm'], cap=10, maximum=1024).strip() == b'kvm',
            'guest_kvm')


def load_lock(path, expected, mode, deadline):
    require(expected == LOCK_SHA256, 'lock_selection')
    raw = read_file(path, 4 * 1024 ** 2, deadline)
    require(hashlib.sha256(raw).hexdigest() == expected, 'lock_hash')
    lock = parse(raw)
    require(type(lock) is dict and type(lock.get('version')) is int and lock['version'] == 1
            and lock.get('kind') == 'protected-resident-debian-package-lock'
            and lock.get('architecture') == 'amd64', 'lock_schema')
    names = lock['profiles'][mode]['packages']
    require(type(names) is list and len(names) == COUNTS[mode] and len(set(names)) == len(names), 'lock_count')
    selected = {}
    for name in names:
        require(type(name) is str and PACKAGE.fullmatch(name), 'package_name')
        item = lock['packages'][name]
        require(type(item) is dict and VERSION.fullmatch(item['version'])
                and item['architecture'] in ('amd64', 'all') and type(item['bytes']) is int
                and 0 < item['bytes'] <= 1024 ** 3
                and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'package_schema')
        basename = Path(item['filename']).name
        require(re.fullmatch(r'[A-Za-z0-9.+_~\-]+\.deb', basename), 'package_filename')
        selected[name] = dict(item, basename=basename)
    require(len({item['basename'] for item in selected.values()}) == len(selected), 'package_filename_duplicate')
    return selected


def copy_package(source_path, target_path, item, deadline):
    remaining(deadline)
    with os.fdopen(os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022
                and before.st_size == item['bytes'], 'package_file')
        fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        digest, count = hashlib.sha256(), 0
        with os.fdopen(fd, 'wb') as sink:
            while block := source.read(1024 ** 2):
                remaining(deadline)
                count += len(block)
                require(count <= item['bytes'], 'package_bytes')
                digest.update(block)
                sink.write(block)
        require(count == item['bytes'] and digest.hexdigest() == item['sha256']
                and identity(before) == identity(os.fstat(source.fileno())), 'package_hash')
    return count


def verify_package_metadata(paths, selected, runner):
    # Metadata is checked only AFTER every payload hash passed, before APT.
    for name, item in sorted(selected.items()):
        raw = runner.run(['/usr/bin/dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}\n',
                          paths[name]], cap=15, maximum=4096)
        require(raw.decode().splitlines() == [name, item['version'], item['architecture']], 'package_metadata')


def stage_packages(directory, target, selected, runner):
    require(directory.is_absolute() and directory.resolve(strict=True) == directory and directory.is_dir(),
            'packages_directory')
    target.mkdir(mode=0o700)
    total, paths = 0, {}
    for name, item in sorted(selected.items()):
        paths[name] = target / item['basename']
        total += copy_package(directory / (name + '.deb'), paths[name], item, runner.deadline)
        require(total <= 512 * 1024 ** 2, 'packages_bytes')
    verify_package_metadata(paths, selected, runner)
    return total


def apt_archive_name(name, item):
    require(type(name) is str and PACKAGE.fullmatch(name) and type(item['version']) is str
            and VERSION.fullmatch(item['version']) and item['architecture'] in ('amd64', 'all'),
            'package_cache_name')
    # APT 3.0.3 pkgAcqArchive uses QuoteString(..., "_:"). The lock's
    # restricted alphabet permits only ':' to need quoting (lowercase %3a).
    return name + '_' + item['version'].replace(':', '%3a') + '_' + item['architecture'] + '.deb'


def cache_packages(directory, selected, runner):
    target = directory / 'archives'
    for path in (directory, directory / 'debs', target, target / 'partial'):
        meta = path.lstat()
        require(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o700, 'package_cache_directory')
    require({path.name for path in target.iterdir()} == {'partial'}
            and not any((target / 'partial').iterdir()), 'package_cache_not_empty')
    paths = {name: target / apt_archive_name(name, item) for name, item in selected.items()}
    require(len(set(paths.values())) == len(paths), 'package_cache_duplicate')
    total = 0
    # With --no-download APT retains local items but then shuts down their
    # acquisition queue before file-method completion. Cache hits resolve an
    # absolute archive path beforehand; absent hits leave relative basenames.
    # Source: Debian/apt 45bebdfb891535d15e66e860aab1ee7c7b2ecaab,
    # apt-private/private-install.cc, apt-pkg/{acquire,acquire-item}.cc.
    # Do not trust a cache hit's size-only check: authenticate fresh regular
    # copies ourselves. No downloads, links or changes to package selection.
    for name, item in sorted(selected.items()):
        total += copy_package(directory / 'debs' / item['basename'], paths[name], item, runner.deadline)
        require(total <= 512 * 1024 ** 2, 'packages_bytes')
    verify_package_metadata(paths, selected, runner)
    return total


def namespace_guard():
    require(os.getpid() == 1 and os.getresuid() == (0, 0, 0), 'namespace_pid')
    # /sys can belong to the original mount's network namespace. /proc/net
    # and SIOCGIFFLAGS observe THIS process's namespace without changing it.
    raw = bounded_kernel_file(Path('/proc/net/dev'), 16384)
    require(len(raw) <= 16384 and len(raw.splitlines()) == 3
            and raw.splitlines()[2].split(b':', 1)[0].strip() == b'lo', 'namespace_network')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        data = fcntl.ioctl(probe.fileno(), 0x8913, b'lo' + bytes(30))  # SIOCGIFFLAGS
    require(not struct.unpack_from('H', data, 16)[0] & 1, 'namespace_loopback')


def runtime_device(runner):
    remaining(runner.deadline)
    require(RUNTIME_DISK.is_symlink(), 'runtime_alias')
    path = RUNTIME_DISK.resolve(strict=True)
    require(re.fullmatch(r'/dev/vd[a-z]+', str(path)), 'runtime_path')
    meta = path.lstat()
    require(stat.S_ISBLK(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1, 'runtime_device')
    serial = Path('/sys/class/block') / path.name / 'serial'
    with serial.open('rb') as source:
        # virtio_blk serial_show returns strlen(buf), without a newline:
        # https://github.com/gregkh/linux/blob/v6.12.105/drivers/block/virtio_blk.c#L835-L852
        require(source.read(128) == RUNTIME_SERIAL.encode(), 'runtime_serial')
    root = Path('/sys/dev/block') / f'{os.major(Path("/").stat().st_dev)}:{os.minor(Path("/").stat().st_dev)}'
    root = root.resolve(strict=True)
    require(path.name not in (root.name, root.parent.name), 'runtime_root_device')
    raw = bounded_kernel_file(Path('/proc/self/mountinfo'), MAX_OUTPUT)
    require(len(raw) <= MAX_OUTPUT, 'mountinfo_bound')
    number = f'{os.major(meta.st_rdev)}:{os.minor(meta.st_rdev)}'.encode()
    require(all(len(row.split()) > 3 and row.split()[2] != number for row in raw.splitlines()),
            'runtime_already_mounted')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(identity(meta) == identity(os.fstat(fd)), 'runtime_changed')
        size = struct.unpack('Q', fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]  # BLKGETSIZE64
        require(size == DISK_BYTES, 'runtime_size')
    finally:
        os.close(fd)
    require(identity(meta) == identity(path.lstat()), 'runtime_changed')
    require(runner.run(['/usr/sbin/blkid', '-p', '-s', 'TYPE', '-o', 'value', path],
                       cap=15, maximum=1024).strip() == b'ext4', 'runtime_ext4')
    return path


class Policy:
    def __init__(self, root, deadline):
        self.path = root / 'usr/sbin/policy-rc.d'
        self.deadline = deadline
        self.original = None
        self.installed = None

    def install(self):
        parent = self.path.parent
        require(parent.resolve(strict=True) == parent and parent.stat().st_uid == 0
                and not parent.stat().st_mode & 0o022, 'policy_parent')
        try:
            meta = self.path.lstat()
        except FileNotFoundError:
            meta = None
        if meta is not None:
            require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0, 'policy_file')
            self.original = (read_file(self.path, 65536, self.deadline), stat.S_IMODE(meta.st_mode), meta.st_gid)
        temporary = parent / ('.vp-policy-' + str(os.getpid()))
        write_new(temporary, POLICY, 0o755)
        if meta is not None:
            require(identity(meta) == identity(self.path.lstat()), 'policy_changed')
        else:
            require(not self.path.exists() and not self.path.is_symlink(), 'policy_changed')
        os.replace(temporary, self.path)
        self.installed = identity(self.path.lstat())

    def restore(self):
        if self.installed is None:
            return True
        require(identity(self.path.lstat()) == self.installed, 'policy_replaced')
        if self.original is None:
            self.path.unlink()
        else:
            raw, mode, group = self.original
            temporary = self.path.parent / ('.vp-policy-restore-' + str(os.getpid()))
            write_new(temporary, raw, mode)
            os.chown(temporary, 0, group)
            os.replace(temporary, self.path)
        return True


def status(raw):
    require(len(raw) <= MAX_OUTPUT, 'status_bytes')
    result = {}
    for row in raw.decode('utf-8').splitlines():
        fields = row.split('\t')
        require(len(fields) == 6 and PACKAGE.fullmatch(fields[0]) and fields[0] not in result
                and VERSION.fullmatch(fields[1]) and fields[2] in ('amd64', 'all'), 'status_schema')
        require(fields[3] in ('install ok installed', 'hold ok installed', 'deinstall ok config-files')
                and not fields[4] and not fields[5], 'status_incomplete')
        result[fields[0]] = fields[1:4]
    require(result, 'status_empty')
    return result


def final_status(before, after, selected):
    require(set(after) == set(before) | set(selected), 'package_set_changed')
    for name, value in after.items():
        if name in selected:
            require(value == [selected[name]['version'], selected[name]['architecture'], 'install ok installed'],
                    'installed_version')
        else:
            require(before[name] == value, 'outside_lock_changed')


def validate_plan(raw, selected, before):
    require(len(raw) <= MAX_OUTPUT, 'plan_bytes')
    seen = set()
    for line in raw.decode('utf-8').splitlines():
        require(not line.startswith(('Remv ', 'Purg ')), 'plan_removal')
        if line.startswith(('Inst ', 'Conf ')):
            match = re.match(r'^(Inst|Conf) ([a-z0-9][a-z0-9+.-]*)(?::amd64)?(?: \[[^\]\n]+\])? \(([^ ]+) ', line)
            require(match is not None, 'plan_schema')
            action, name, version = match.groups()
            require(name in selected and selected[name]['version'] == version, 'plan_outside_lock')
            if action == 'Inst':
                require(name not in seen, 'plan_duplicate')
                seen.add(name)
    # --reinstall consumes every selected, authenticated archive, not merely
    # an installed package with an equal version and unknown modified payload.
    require(seen == selected.keys(), 'plan_missing')
    require(all(name not in before or VERSION.fullmatch(before[name][0]) for name in selected), 'plan_before')


def apt_configuration(directory, visible):
    for name in ('empty', 'lists', 'lists/partial', 'archives', 'archives/partial', 'log'):
        (directory / name).mkdir(mode=0o700)
    raw = f'''Dir::Etc::main "/dev/null";
Dir::Etc::parts "{visible}/empty";
Dir::Etc::sourcelist "/dev/null";
Dir::Etc::sourceparts "{visible}/empty";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "{visible}/empty";
Dir::State::status "/var/lib/dpkg/status";
Dir::State::lists "{visible}/lists";
Dir::Cache::archives "{visible}/archives";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Log "{visible}/log";
Dir::Bin::dpkg "/usr/bin/dpkg";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Sandbox::User "root";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::Download "false";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::Retries "0";
DPkg::Options {{ "--force-confdef"; "--force-confold"; }};
'''.encode()
    write_new(directory / 'apt.conf', raw, 0o400)


def plan_failure(error, *, command):
    """Project only our own exact codes; never export exception text or output."""
    if not command and type(error) is UnicodeDecodeError:
        return 'plan_encoding'
    if type(error) is not ValueError or len(error.args) != 1 or type(error.args[0]) is not str:
        return 'installation_failed'
    code = error.args[0]
    if command:
        return {'command_failed': 'plan_command_exit', 'command_deadline': 'plan_command_deadline',
                'command_output': 'plan_command_output'}.get(code, 'installation_failed')
    return code if code in ('plan_bytes', 'plan_schema', 'plan_outside_lock', 'plan_duplicate',
                           'plan_missing', 'plan_removal', 'plan_before') else 'installation_failed'


def install_failure(error):
    if type(error) is CleanupUnconfirmed:
        return 'install_command_cleanup'
    if type(error) is not ValueError or len(error.args) != 1 or type(error.args[0]) is not str:
        return 'installation_failed'
    return {'command_failed': 'install_command_exit', 'command_deadline': 'install_command_deadline',
            'command_output': 'install_command_output'}.get(error.args[0], 'installation_failed')


def preparation_failure(error, phase):
    """Closed diagnostics from existing operations; no extra device probes or logs."""
    if phase not in PREPARATION_PHASES:
        return 'installation_failed'
    if type(error) is CleanupUnconfirmed:
        return 'preparation_command_cleanup'
    if type(error) is FileNotFoundError:
        return 'preparation_missing'
    if type(error) is PermissionError:
        return 'preparation_permission'
    if isinstance(error, OSError):
        return 'preparation_io'
    if type(error) is not ValueError or len(error.args) != 1 or type(error.args[0]) is not str:
        return 'installation_failed'
    code = error.args[0]
    if code in PREPARATION_GUARDS.get(phase, ()):
        return code
    return {'command_failed': 'preparation_command_exit', 'command_deadline': 'preparation_command_deadline',
            'command_output': 'preparation_command_output', 'deadline': 'preparation_deadline'}.get(
                code, 'installation_failed')


def install(root, directory, visible, selected, runner, report):
    prefix = ['/usr/sbin/chroot', root]
    env = {'APT_CONFIG': str(visible / 'apt.conf')}
    query = ['/usr/bin/dpkg-query', '--show', '--showformat=' + STATUS_FORMAT]
    report['phase'] = 'status_before'
    before = status(runner.run([*prefix, *query], maximum=MAX_OUTPUT))
    require(runner.run([*prefix, '/usr/bin/dpkg', '--audit'], maximum=MAX_OUTPUT).strip() == b'', 'dpkg_audit')
    apt_configuration(directory, visible)
    report['phase'] = 'package_cache'
    cache_packages(directory, selected, runner)
    policy = Policy(root, runner.deadline)
    try:
        policy.install()
        report['policy_restored'] = False
        packages = [str(visible / 'debs' / item['basename']) for _, item in sorted(selected.items())]
        apt = ['/usr/bin/apt-get', '--no-download', '--no-remove', '--no-install-recommends',
               '--reinstall', '--yes']
        report['phase'] = 'package_plan'
        try:
            plan = runner.run([*prefix, *apt, '--simulate', 'install', *packages], env=env)
        except ValueError as error:
            report['failure'] = plan_failure(error, command=True)
            raise
        try:
            validate_plan(plan, selected, before)
        except ValueError as error:
            report['failure'] = plan_failure(error, command=False)
            raise
        report['phase'] = 'package_install'
        try:
            runner.run([*prefix, *apt, 'install', *packages], env=env, cap=1200)
        except (ValueError, CleanupUnconfirmed) as error:
            report['failure'] = install_failure(error)
            raise
        report['phase'] = 'package_verify'
        runner.run([*prefix, '/usr/bin/dpkg', '--configure', '--pending'], cap=600)
        after = status(runner.run([*prefix, *query], maximum=MAX_OUTPUT))
        final_status(before, after, selected)
        require(runner.run([*prefix, '/usr/bin/dpkg', '--audit'], maximum=MAX_OUTPUT).strip() == b'', 'dpkg_audit')
        report.update(packages_verified=len(selected), status_verified=True, triggers_clear=True, audit_clear=True)
    finally:
        try:
            report['policy_restored'] = policy.restore()
        except (OSError, ValueError):
            report['policy_restored'] = False


def receipt(mode):
    return dict(version=1, kind='protected-resident-offline-package-install', mode=mode, state='failed',
        phase='guard', failure='installation_failed', package_lock_sha256=LOCK_SHA256,
        packages_verified=0, archives_verified=False, archive_bytes=0, status_verified=False,
        triggers_clear=False, audit_clear=False, policy_restored=True, runtime_unmounted=mode == 'build',
        namespace_joined=False, direct_child_groups_joined=True, descendants_joined=None,
        controller_cgroup_cleanup_required=True, complete_guest_cleanup=False,
        model_execution=False, worker_execution=False, private_inputs=False, hardware_attestation=False)


def worker(config, stage):
    mode, deadline = config['mode'], config['deadline']
    runner, report = Runner(deadline), receipt(mode)
    mounts = []
    try:
        namespace_guard()
        class Consent:
            execute = yes = disposable_guest = True
            deadline_monotonic_ns = deadline
        guest_guard(Consent(), runner)
        selected = load_lock(stage / 'lock.json', LOCK_SHA256, mode, deadline)
        root = Path('/')
        directory, visible = stage / 'apt', stage / 'apt'
        directory.mkdir(mode=0o700)
        if mode == 'build':
            # Do not expose the buildguest's live service-manager sockets to
            # package scripts. These mounts exist only in our private namespace.
            for target in (Path('/run/systemd'), Path('/run/dbus')):
                if target.exists():
                    require(target.is_dir() and not target.is_symlink(), 'service_mountpoint')
                    runner.run(['/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=0755,nosuid,nodev,noexec',
                                'tmpfs', target], cap=30)
                    mounts.append(target)
        if mode == 'runtime':
            report['phase'] = 'runtime_device'
            device = runtime_device(runner)
            report['phase'] = 'runtime_fsck'
            runner.run(['/usr/sbin/e2fsck', '-f', '-p', device], allowed=(0, 1), cap=600)
            report['phase'] = 'runtime_resize'
            runner.run(['/usr/sbin/resize2fs', device], cap=600)
            report['phase'] = 'runtime_mount'
            root = stage / 'root'
            root.mkdir(mode=0o700)
            runner.run(['/usr/bin/mount', '-t', 'ext4', '-o', 'rw,nosuid,nodev', device, root], cap=30)
            mounts.append(root)
            report['phase'] = 'runtime_bootstrap'
            require('VERSION_ID="13"' in read_file(root / 'usr/lib/os-release', 16384,
                                                  runner.deadline).decode(), 'runtime_debian')
            for name in ('run', 'proc', 'dev'):
                target = root / name
                require(target.is_dir() and not target.is_symlink(), 'runtime_mountpoint')
            runner.run(['/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=0755,nosuid,nodev', 'tmpfs', root / 'run'], cap=30)
            mounts.append(root / 'run')
            runner.run(['/usr/bin/mount', '-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc', root / 'proc'], cap=30)
            mounts.append(root / 'proc')
            runner.run(['/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=0755,nosuid', 'tmpfs', root / 'dev'], cap=30)
            mounts.append(root / 'dev')
            for name in ('null', 'zero', 'random', 'urandom'):
                target = root / 'dev' / name
                target.touch(mode=0o600)
                runner.run(['/usr/bin/mount', '--bind', '/dev/' + name, target], cap=30)
                mounts.append(target)
            visible = Path('/run/vp-resident-install')
            directory = root / visible.relative_to('/')
            directory.mkdir(mode=0o700)
        report['phase'] = 'archive_mount'
        (directory / 'debs').mkdir(mode=0o700)
        runner.run(['/usr/bin/mount', '--bind', stage / 'debs', directory / 'debs'], cap=30)
        mounts.append(directory / 'debs')
        runner.run(['/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev,noexec', directory / 'debs'], cap=30)
        install(root, directory, visible, selected, runner, report)
        report['phase'] = 'unmount'
        runner.run(['/usr/bin/sync'], cap=60)
        report['state'] = 'configured'
        report['failure'] = None
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, CleanupUnconfirmed) as error:
        if report['phase'] in PREPARATION_PHASES:
            report['failure'] = preparation_failure(error, report['phase'])
        # Never export exception text, argv, package output or guest paths.
    finally:
        unmounted = True
        clean = Runner(time.monotonic_ns() + 30 * 1_000_000_000)
        for target in reversed(mounts):
            try:
                # Cleanup has a separate bounded join allowance, not new work.
                clean.run(['/usr/bin/umount', target], cap=20)
                runner.joined = runner.joined and clean.joined
            except BaseException:
                unmounted = False
        runner.joined = runner.joined and clean.joined
        report['runtime_unmounted'] = unmounted
        report['direct_child_groups_joined'] = runner.joined
        if not (unmounted and report['policy_restored'] and runner.joined):
            report['state'] = 'failed'
            report['failure'] = report['failure'] or 'cleanup_unconfirmed'
        if report['state'] == 'configured':
            report['phase'] = 'complete'
        write_new(stage / 'worker-result.json', encoded(report))
    return report


def execute(args):
    runner, report = Runner(args.deadline_monotonic_ns), receipt(args.mode)
    guest_guard(args, runner)
    require(args.result.is_absolute() and args.result.parent.resolve(strict=True) == args.result.parent,
            'result_path')
    parent = args.result.parent.stat()
    require(parent.st_uid == 0 and not parent.st_mode & 0o022
            and not args.result.exists() and not args.result.is_symlink(), 'result_owner')
    stage = Path(tempfile.mkdtemp(prefix='vp-resident-install-', dir='/run'))
    try:
        report['phase'] = 'archives'
        selected = load_lock(args.package_lock, args.package_lock_sha256, args.mode, runner.deadline)
        raw = read_file(args.package_lock, 4 * 1024 ** 2, runner.deadline)
        require(hashlib.sha256(raw).hexdigest() == LOCK_SHA256, 'lock_changed')
        write_new(stage / 'lock.json', raw, 0o400)
        report['archive_bytes'] = stage_packages(args.packages, stage / 'debs', selected, runner)
        report['archives_verified'] = True
        source = read_file(Path(__file__).resolve(), 128 * 1024, runner.deadline)
        write_new(stage / 'installer.py', source, 0o400)
        config = {'mode': args.mode, 'deadline': runner.deadline}
        write_new(stage / 'config.json', encoded(config), 0o400)
        report['phase'] = 'namespace'
        try:
            runner.run(['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=SIGKILL',
                '--mount-proc', '--propagation', 'private', '/usr/bin/python3.13', '-B', stage / 'installer.py',
                '--namespace-child', stage], cap=MAX_SECONDS, allowed=(0, 1), maximum=16384)
            report['namespace_joined'] = True
        finally:
            child_path = stage / 'worker-result.json'
            if child_path.exists():
                child = parse(read_file(child_path, 16384,
                    time.monotonic_ns() + 5 * 1_000_000_000))
                require(type(child) is dict and child.keys() == report.keys()
                        and child['mode'] == args.mode and child['package_lock_sha256'] == LOCK_SHA256,
                        'worker_receipt')
                child.update(archives_verified=report['archives_verified'], archive_bytes=report['archive_bytes'],
                             namespace_joined=report['namespace_joined'])
                report = child
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, CleanupUnconfirmed):
        report['state'] = 'failed'
    finally:
        report['direct_child_groups_joined'] = report['direct_child_groups_joined'] and runner.joined
        if not report['namespace_joined'] or not runner.joined:
            report['state'] = 'failed'
            report['failure'] = report['failure'] or 'cleanup_unconfirmed'
        # Controller removes the exact staging directory only after its entire
        # cgroup/VM joined; never infer descendant absence from our direct wait.
        write_new(args.result, encoded(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=tuple(COUNTS))
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--disposable-guest', action='store_true')
    parser.add_argument('--package-lock', type=Path)
    parser.add_argument('--package-lock-sha256')
    parser.add_argument('--packages', type=Path)
    parser.add_argument('--deadline-monotonic-ns', type=int)
    parser.add_argument('--result', type=Path)
    parser.add_argument('--namespace-child', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    previous = {}
    previous_umask = None

    def cancel(_number, _frame):
        raise InterruptedError('cancelled')

    try:
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[number] = signal.signal(number, cancel)
        previous_umask = os.umask(0o077)
        if args.namespace_child is not None:
            stage = args.namespace_child
            require(stage.parent == Path('/run') and re.fullmatch(r'vp-resident-install-[a-z0-9_]+', stage.name),
                    'namespace_stage')
            meta = stage.lstat()
            require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0
                    and stat.S_IMODE(meta.st_mode) == 0o700, 'namespace_stage')
            config = parse(read_file(stage / 'config.json', 4096,
                                     time.monotonic_ns() + 5 * 1_000_000_000))
            require(type(config) is dict and set(config) == {'mode', 'deadline'} and config['mode'] in COUNTS,
                    'namespace_config')
            result = worker(config, stage)
        else:
            require(args.mode in COUNTS and all(value is not None for value in
                (args.package_lock, args.package_lock_sha256, args.packages, args.deadline_monotonic_ns, args.result)),
                'arguments')
            result = execute(args)
        print(encoded(result).decode(), end='')
        return 0 if result['state'] == 'configured' else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, CleanupUnconfirmed):
        print('{"version":1,"kind":"protected-resident-offline-package-install","state":"rejected"}')
        return 1
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)
        for number, previous_handler in previous.items():
            signal.signal(number, previous_handler)


if __name__ == '__main__':
    raise SystemExit(main())
