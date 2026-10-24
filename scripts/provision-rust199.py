#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Install one reviewed compiler profile only on disposable hosted runners/KVM guests."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

PINS = Path(__file__).with_name('rust199-components.json')
PINS_SHA256 = '5cf2439e109e9fa92a25037130a20f903282e703ddb0ce192d7c06a8ec2737ba'
MANIFEST_SHA256 = 'fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463'
PROFILE = 'rust-1.99.1-20261015'
PREFIX_NAME = 'volparossa-rust-1.99.1'
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXTRACTED = 2 * 1024 * 1024 * 1024


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
    if not rustc.startswith('rustc 1.99.1 (58cf8f9c3 2026-10-13)\n') or '\nrelease: 1.99.1\n' not in rustc:
        raise ValueError('observed rustc identity does not match reviewed release')
    cargo = outputs['cargo']
    # The distribution manifest's Cargo package version is 0.100.0. Do not
    # invent its executable display version: bind the actual output to its commit.
    if not re.match(r'cargo [0-9]+\.[0-9]+\.[0-9]+ \(5f94df478 2026-08-27\)\n', cargo):
        raise ValueError('observed Cargo identity does not match reviewed component')
    if not outputs['rustfmt'].startswith('rustfmt 1.10.0'):
        raise ValueError('observed rustfmt identity does not match reviewed component')
    if not outputs['clippy-driver'].startswith('clippy 0.1.99'):
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


def observe(prefix):
    outputs = {}
    for name in ('rustc', 'cargo', 'rustfmt', 'clippy-driver'):
        executable = prefix / 'bin' / name
        if not executable.is_file():
            raise ValueError('installed compiler component is missing: ' + name)
        outputs[name] = subprocess.check_output([str(executable), '--version'] + (['--verbose'] if name in ('rustc', 'cargo') else []),
                                                text=True, timeout=30)
    validate_outputs(outputs)
    return outputs


def download(component, destination):
    url = component['xz_url']
    if not url.startswith('https://static.rust-lang.org/dist/2026-10-15/'):
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


def install_component(source, prefix):
    child = subprocess.Popen(['sh', str(source / 'install.sh'), '--prefix=' + str(prefix),
                              '--disable-ldconfig'], start_new_session=True)
    try:
        status = child.wait(timeout=300)
        if status != 0:
            raise subprocess.CalledProcessError(status, child.args)
    except BaseException:
        # Reap the whole owned installer group before prefix/staging cleanup.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        raise


def provision(mode):
    prefix = location('guest' if mode == 'guest-check' else mode, os.environ)  # Before network, extraction or execution.
    metadata = pins()
    if prefix.exists() or prefix.is_symlink():
        if prefix.is_symlink() or not prefix.is_dir() or prefix.stat().st_uid != os.geteuid():
            raise ValueError('compiler prefix is unsafe')
        marker = prefix / 'receipt.json'
        if marker.is_symlink() or not marker.is_file() or marker.stat().st_nlink != 1 or not 1 <= marker.stat().st_size <= 32768:
            raise ValueError('compiler receipt is outside its fixed file bound')
        receipt = json.loads(marker.read_text())
        validate_receipt(receipt)
        if observe(prefix) != receipt['observed_versions']:
            raise ValueError('compiler observations changed')
    else:
        if mode == 'guest-check':
            raise ValueError('the reviewed guest compiler has not been provisioned')
        # A failed partial install is removed; a pre-existing prefix is never deleted.
        try:
            prefix.mkdir(mode=0o700)
            with tempfile.TemporaryDirectory(prefix='rust199-components-', dir=prefix.parent) as temporary:
                staging = Path(temporary)
                for index, component in enumerate(metadata['components']):
                    archive = staging / f'{index}.tar.xz'
                    download(component, archive)
                    source = extract(archive, staging / str(index))
                    install_component(source, prefix)
                receipt = dict(schema_version=1, profile=PROFILE, manifest_sha256=MANIFEST_SHA256,
                               components=metadata['components'], observed_versions=observe(prefix))
                validate_receipt(receipt)
                (prefix / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
        except BaseException:
            shutil.rmtree(prefix)
            raise
    if mode == 'runner':
        # GitHub applies these to subsequent steps. Callers in this step use the
        # printed fixed prefix directly; no rustup installation or moving channel.
        with open(os.environ['GITHUB_PATH'], 'a') as output:
            output.write(str(prefix / 'bin') + '\n')
    print(prefix)
    return prefix


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('runner', 'guest', 'guest-check', 'alpha-guest'):
        raise SystemExit('usage: provision-rust199.py runner|guest|guest-check|alpha-guest')
    def interrupted(_number, _frame):
        raise KeyboardInterrupt('compiler provisioning interrupted')
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    provision(sys.argv[1])
