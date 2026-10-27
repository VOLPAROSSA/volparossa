#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Install one reviewed compiler profile only on disposable hosted runners/KVM guests."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import signal
import stat
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

PINS = Path(__file__).with_name('rust189-components.json')
PINS_SHA256 = 'a2c340e8965a3cc6324ef7972d7a02b67aed336cf394ef8fa259985f447b3f13'
MANIFEST_SHA256 = 'fbd1662e100e7b305908ece23b441cb7534eadfa6336c5f173ff08d1cec174a1'
PROFILE = 'rust-1.89.0-20250807'
PREFIX_NAME = 'volparossa-rust-1.89.0'
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXTRACTED = 2 * 1024 * 1024 * 1024
POLICY = runpy.run_path(str(Path(__file__).with_name('cargo-source-policy.py')))


def pins():
    raw = PINS.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS_SHA256:
        raise ValueError('reviewed compiler component metadata changed')
    return json.loads(raw)


def location(mode, env):
    if platform.machine() != 'x86_64' or os.geteuid() == 0:
        raise ValueError('compiler provisioning requires an unprivileged amd64 account')
    if mode == 'runner':
        if env.get('GITHUB_ACTIONS') != 'true' or env.get('RUNNER_ENVIRONMENT') != 'github-hosted':
            raise ValueError('compiler provisioning requires a disposable GitHub-hosted runner')
        root = Path(env.get('RUNNER_TEMP', ''))
        if not root.is_absolute() or not root.is_dir() or root.is_symlink():
            raise ValueError('fixed runner temporary root is unavailable')
    elif mode in ('guest', 'alpha-guest'):
        # No environment variable alone admits the development host as a guest.
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                       if '=' in line)
        if release.get('ID', '').strip('"') != 'debian' or release.get('VERSION_ID', '').strip('"') != '13':
            raise ValueError('compiler provisioning requires Debian 13')
        if Path('/proc/1/comm').read_text().strip() != 'systemd' or subprocess.check_output(
                ['systemd-detect-virt'], text=True).strip() != 'kvm':
            raise ValueError('compiler provisioning requires a disposable systemd KVM guest')
        account_home = Path('/home/vpci' if mode == 'alpha-guest' else '/home/volparossa')
        root = account_home / '.local'
        if Path.home() != account_home:
            raise ValueError('compiler provisioning requires the fixed guest account')
        root.mkdir(mode=0o700, exist_ok=True)
        if root.is_symlink() or root.stat().st_uid != os.geteuid():
            raise ValueError('guest toolchain parent is not owned by the guest account')
    else:
        raise ValueError('unknown compiler provisioning location')
    return root / PREFIX_NAME


def validate_outputs(outputs):
    if set(outputs) != {'rustc', 'cargo', 'rustfmt', 'clippy-driver'}:
        raise ValueError('compiler observations are incomplete')
    rustc = outputs['rustc']
    if not rustc.startswith('rustc 1.89.0 (29483883e 2025-08-04)\n') or '\nrelease: 1.89.0\n' not in rustc:
        raise ValueError('observed rustc identity does not match reviewed release')
    cargo = outputs['cargo']
    # The distribution manifest's Cargo package version is 0.90.0. Do not
    # invent its executable display version: bind the actual output to its commit.
    if not re.match(r'cargo [0-9]+\.[0-9]+\.[0-9]+ \(c24e10642 2025-06-23\)\n', cargo):
        raise ValueError('observed Cargo identity does not match reviewed component')
    if not outputs['rustfmt'].startswith('rustfmt 1.8.0'):
        raise ValueError('observed rustfmt identity does not match reviewed component')
    if not outputs['clippy-driver'].startswith('clippy 0.1.89'):
        raise ValueError('observed Clippy identity does not match reviewed component')


def validate_receipt(receipt):
    if set(receipt) != {'schema_version', 'profile', 'manifest_sha256', 'components', 'observed_versions'}:
        raise ValueError('compiler receipt fields are not exact')
    metadata = pins()
    if receipt['schema_version'] != 1 or receipt['profile'] != PROFILE or receipt['manifest_sha256'] != MANIFEST_SHA256:
        raise ValueError('compiler receipt profile is not the reviewed profile')
    if receipt['components'] != metadata['components']:
        raise ValueError('compiler receipt does not bind the reviewed component archives')
    validate_outputs(receipt['observed_versions'])


def observe(prefix, cargo_env=None):
    cargo_env = POLICY['validate_active'](POLICY['ROOT'], os.environ if cargo_env is None else cargo_env)
    print('CARGO_PUBLIC_SOURCE_POLICY_V1=pass', file=sys.stderr)
    outputs = {}
    for name in ('rustc', 'cargo', 'rustfmt', 'clippy-driver'):
        executable = prefix / 'bin' / name
        if not executable.is_file():
            raise ValueError('installed compiler component is missing: ' + name)
        outputs[name] = subprocess.check_output([str(executable), '--version'] + (['--verbose'] if name in ('rustc', 'cargo') else []),
                                                text=True, timeout=30, env=cargo_env)
    validate_outputs(outputs)
    return outputs


def download(component, destination):
    url = component['xz_url']
    if not url.startswith('https://static.rust-lang.org/dist/2025-08-07/'):
        raise ValueError('unreviewed compiler origin')
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(url, timeout=60) as response, destination.open('xb') as output:
        if response.geturl() != url:
            raise ValueError('compiler archive redirect is not allowed')
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ARCHIVE:
                raise ValueError('compiler archive exceeds its bound')
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != component['xz_sha256']:
        raise ValueError('compiler archive digest differs from reviewed authority')


def extract(archive_path, destination):
    with tarfile.open(archive_path) as archive:
        members = archive.getmembers()
        if len(members) > 100_000 or sum(m.size for m in members) > MAX_EXTRACTED:
            raise ValueError('compiler archive expansion exceeds its bound')
        roots = set()
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts:
                raise ValueError('compiler archive path is unsafe')
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError('compiler archive contains a special file')
            roots.add(path.parts[0])
        if len(roots) != 1:
            raise ValueError('compiler archive does not have one root')
        archive.extractall(destination, filter='data')
        return destination / roots.pop()


def regular_file(path, bound):
    """Open a private, single-link regular file without following a final link."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(descriptor, 'rb')
    info = os.fstat(stream.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.geteuid() or info.st_mode & 0o7022 or not 0 <= info.st_size <= bound):
        stream.close()
        raise ValueError('unsafe compiler file: ' + str(path))
    return stream


def digest_stream(stream):
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def payload_expectations(prefix, metadata):
    """Derive authority anew from the pinned archives, never from an installed receipt.

    All six reviewed distribution archives use installer-v3 file directives and
    contain no links. Reject any other layout rather than approximate cp semantics.
    Default install.sh directories preserve the manifest's relative paths.
    """
    expected = {}
    components = []
    def add(name, digest, executable):
        value = (digest, executable)
        if name in expected and expected[name] != value:
            raise ValueError('conflicting compiler payload: ' + name)
        expected[name] = value
    def data(name, value, executable=False):
        add(name, hashlib.sha256(value).hexdigest(), executable)
    for index, component in enumerate(metadata['components']):
        relative = f'.component-archives/{index}.tar.xz'
        with regular_file(prefix / relative, MAX_ARCHIVE) as stream:
            if digest_stream(stream) != component['xz_sha256']:
                raise ValueError('retained compiler archive digest differs from reviewed authority')
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r|xz') as archive:
                entries, hashes, contents = {}, {}, {}
                roots = set()
                expanded = 0
                for member in archive:
                    expanded += member.size
                    if len(entries) >= 100_000 or expanded > MAX_EXTRACTED:
                        raise ValueError('compiler archive expansion exceeds its bound')
                    path = Path(member.name)
                    if (path.is_absolute() or '..' in path.parts or not path.parts or
                            str(path) != member.name or not (member.isfile() or member.isdir()) or
                            member.name in entries):
                        raise ValueError('unsupported compiler archive path, link or special file')
                    roots.add(path.parts[0]); entries[member.name] = member
                    if member.isfile():
                        payload = archive.extractfile(member)
                        if path.name in ('components', 'manifest.in', 'install.sh', 'rust-installer-version'):
                            if member.size > 1024 * 1024:
                                raise ValueError('oversized compiler manifest')
                            contents[member.name] = payload.read()
                            hashes[member.name] = hashlib.sha256(contents[member.name]).hexdigest()
                        else:
                            hashes[member.name] = digest_stream(payload)
                if len(roots) != 1:
                    raise ValueError('compiler archive does not have one root')
                root = roots.pop()
                def read(name):
                    member = entries.get(root + '/' + name)
                    if member is None or not member.isfile() or member.size > 1024 * 1024:
                        raise ValueError('missing or oversized compiler manifest: ' + name)
                    return contents[member.name]
                if read('rust-installer-version') != b'3\n':
                    raise ValueError('unsupported compiler installer version')
                names = read('components').decode().splitlines()
                if not names or any(not re.fullmatch(r'[A-Za-z0-9_-]+', n) or n in components for n in names):
                    raise ValueError('invalid or repeated compiler component')
                components.extend(names)
                for name in names:
                    directives = read(name + '/manifest.in').decode().splitlines()
                    installed = []
                    for directive in directives:
                        command, separator, destination = directive.partition(':')
                        path = Path(destination)
                        if (command != 'file' or not separator or not destination or path.is_absolute() or
                                '..' in path.parts or str(path) != destination or
                                path.parts[0] not in ('bin', 'lib', 'libexec', 'etc', 'share')):
                            raise ValueError('unsupported compiler installation directive')
                        member = entries.get(root + '/' + name + '/' + destination)
                        if member is None or not member.isfile():
                            raise ValueError('compiler manifest payload is missing')
                        add(destination, hashes[member.name],
                            path.parts[0] == 'bin' or bool(member.mode & 0o111))
                        installed.append('file:' + str(prefix / destination) + '\n')
                    data('lib/rustlib/manifest-' + name, ''.join(installed).encode())
                # Each installer overwrites the uninstaller; the final one is authoritative.
                expected['lib/rustlib/uninstall.sh'] = (hashlib.sha256(read('install.sh')).hexdigest(),
                                                        bool(entries[root + '/install.sh'].mode & 0o111))
        add(relative, component['xz_sha256'], False)
    data('lib/rustlib/components', ''.join(n + '\n' for n in components).encode())
    data('lib/rustlib/rust-installer-version', b'3\n')
    return expected


def verify_payload(prefix, metadata):
    """Reject missing, changed, linked or extra payload before running any tool."""
    archive_directory = prefix / '.component-archives'
    if archive_directory.is_symlink() or not archive_directory.is_dir():
        raise ValueError('authenticated compiler archives are unavailable')
    expected = payload_expectations(prefix, metadata)
    # Only these two non-authoritative data files are variable. Neither can add
    # compiler/runtime payload. All other installed files have archive authority.
    variable = {'receipt.json': 32768, 'lib/rustlib/install.log': 1024 * 1024}
    allowed_directories = {'.component-archives'}
    for name in expected.keys() | variable.keys():
        allowed_directories.update(str(p) for p in Path(name).parents if str(p) != '.')
    seen = set()
    for root, directories, files in os.walk(prefix, followlinks=False):
        for name in directories:
            path = Path(root) / name
            relative = str(path.relative_to(prefix))
            info = path.lstat()
            if (relative not in allowed_directories or not stat.S_ISDIR(info.st_mode) or
                    info.st_uid != os.geteuid() or info.st_mode & 0o7022):
                raise ValueError('unsafe or extra compiler directory: ' + relative)
        for name in files:
            path = Path(root) / name
            relative = str(path.relative_to(prefix))
            if relative not in expected and relative not in variable:
                raise ValueError('extra compiler payload: ' + relative)
            with regular_file(path, variable.get(relative, MAX_EXTRACTED)) as stream:
                executable = bool(os.fstat(stream.fileno()).st_mode & 0o111)
                if relative in expected:
                    if (digest_stream(stream), executable) != expected[relative]:
                        raise ValueError('compiler payload differs from authenticated archive: ' + relative)
                elif executable:
                    raise ValueError('compiler data file is executable: ' + relative)
            seen.add(relative)
    if not expected.keys() <= seen:
        raise ValueError('authenticated compiler payload is incomplete')


class CleanupUnconfirmed(RuntimeError):
    """An owned installer might still run; preserve prefix and staging for recovery."""


def group_running(group):
    # Keep the unreaped leader as a PID/PGID identity anchor. Zombies cannot write
    # files; a group probe alone cannot distinguish them from live descendants.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if int(fields[2]) == group and fields[0] not in ('Z', 'X'):
            return True
    return False


def wait_for_leader(child, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is not None:
            return result
        time.sleep(0.05)
    raise subprocess.TimeoutExpired(child.args, timeout)


def finish_group(child, grace=5):
    """Do not reap the leader or delete scratch until the entire group is inert."""
    try:
        for number in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(child.pid, number)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + grace
            while group_running(child.pid):
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
            else:
                if number == signal.SIGKILL:
                    child.wait(timeout=grace)  # Reap only after descendants cannot run.
                    return
            # Always send final KILL while the leader identity is held. A /proc
            # snapshot during TERM grace could miss a newly forked descendant.
        raise CleanupUnconfirmed('installer group did not stop; retaining prefix and staging')
    except BaseException as error:
        if isinstance(error, CleanupUnconfirmed):
            raise
        raise CleanupUnconfirmed('installer cleanup unconfirmed; retaining prefix and staging') from error


def install_component(source, prefix):
    child = subprocess.Popen(['sh', str(source / 'install.sh'), '--prefix=' + str(prefix),
                              '--disable-ldconfig'], start_new_session=True)
    try:
        result = wait_for_leader(child, 300)
    except BaseException:
        finish_group(child)
        raise
    finish_group(child)
    if result.si_code != os.CLD_EXITED or result.si_status != 0:
        raise subprocess.CalledProcessError(result.si_status, child.args)


def provision(mode, cargo_env=None):
    prefix = location('guest' if mode == 'guest-check' else mode, os.environ)  # Before network, extraction or execution.
    if cargo_env is None:
        if mode == 'guest-check':
            cargo_env = POLICY['validate_active'](POLICY['ROOT'], os.environ)
        else:
            cargo_env = POLICY['activate'](mode)
    else:
        cargo_env = POLICY['validate_active'](POLICY['ROOT'], cargo_env)
    POLICY['write_scope'](cargo_env, prefix.parent/'cargo-source-policy.json')
    metadata = pins()
    if prefix.exists() or prefix.is_symlink():
        if (prefix.is_symlink() or not prefix.is_dir() or prefix.stat().st_uid != os.geteuid() or
                prefix.stat().st_mode & 0o7022):
            raise ValueError('compiler prefix is unsafe')
        marker = prefix / 'receipt.json'
        if marker.is_symlink() or not marker.is_file() or marker.stat().st_nlink != 1 or not 1 <= marker.stat().st_size <= 32768:
            raise ValueError('compiler receipt is outside its fixed file bound')
        receipt = json.loads(marker.read_text())
        validate_receipt(receipt)
        verify_payload(prefix, metadata)
        if observe(prefix, cargo_env) != receipt['observed_versions']:
            raise ValueError('compiler observations changed')
    else:
        if mode == 'guest-check':
            raise ValueError('the reviewed guest compiler has not been provisioned')
        # Retain archive authority for every subsequent offline check/reuse.
        staging = None
        previous_umask = os.umask(0o022)
        try:
            prefix.mkdir(mode=0o700)
            archives = prefix / '.component-archives'
            archives.mkdir(mode=0o700)
            staging = Path(tempfile.mkdtemp(prefix='rust189-components-', dir=prefix.parent))
            for index, component in enumerate(metadata['components']):
                archive = archives / f'{index}.tar.xz'
                download(component, archive)
                archive.chmod(0o600)
                source = extract(archive, staging / str(index))
                install_component(source, prefix)
            verify_payload(prefix, metadata)  # Fresh payload too, before any observation.
            receipt = dict(schema_version=1, profile=PROFILE, manifest_sha256=MANIFEST_SHA256,
                           components=metadata['components'], observed_versions=observe(prefix, cargo_env))
            validate_receipt(receipt)
            (prefix / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
        except CleanupUnconfirmed:
            # Do not unlink anything a surviving installer could still be using.
            print('compiler cleanup unconfirmed; retained ' + str(prefix) + ' and ' + str(staging), file=sys.stderr)
            raise
        except BaseException:
            shutil.rmtree(prefix)
            if staging is not None:
                shutil.rmtree(staging)
            raise
        else:
            shutil.rmtree(staging)
        finally:
            os.umask(previous_umask)
    if mode == 'runner':
        # GitHub applies these to subsequent steps. Callers in this step use the
        # printed fixed prefix directly; no rustup installation or moving channel.
        with open(os.environ['GITHUB_PATH'], 'a') as output:
            output.write(str(prefix / 'bin') + '\n')
        with open(os.environ['GITHUB_ENV'], 'a') as output:
            output.write('CARGO_HOME=' + cargo_env['CARGO_HOME'] + '\n')
            for name, value in POLICY['GIT_ENV'].items():
                output.write(name + '=' + value + '\n')
    print(prefix)
    return prefix


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('runner', 'guest', 'guest-check', 'alpha-guest'):
        raise SystemExit('usage: provision-rust189.py runner|guest|guest-check|alpha-guest')
    def interrupted(_number, _frame):
        raise KeyboardInterrupt('compiler provisioning interrupted')
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    provision(sys.argv[1])
