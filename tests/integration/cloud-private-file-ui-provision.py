#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Guest-only source-built Web8 assets and existing exact Firefox staging.

Called by the guarded Cloud provisioner, never on import. Dependency fetching
and offline building run under the disposable vpci UID with empty private homes.
Only verified public output is copied into the root-owned application tree.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
UPSTREAM = '11e699ac82fda4dd113ac3ceb2ecb2dd74574045'
UPSTREAM_TREE = '4f13ceee9b21450659266df69a4fac57f25c3bc9'
BROWSER_STAGE = Path('/home/vpci/browser-network-runtime')


def require(value):
    if not value:
        raise ValueError('Cloud UI provisioning boundary or provenance failed')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, maximum):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and path.resolve() == path and 0 <= info.st_size <= maximum)
    return info


def relative(name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_./ -]+', name)
            and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')))
    return name


def verify_ui(source, dist):
    """Verify actual builder output; tests may supply synthetic bytes, never a build claim."""
    pins_path = source / 'third_party/opencloud-web-ui.json'
    pins = json.loads(pins_path.read_text())
    require(pins['repository'] == 'https://github.com/opencloud-eu/web.git'
            and pins['revision'] == UPSTREAM and pins['tree'] == UPSTREAM_TREE)
    report_path = dist / 'BUILD_REPORT.json'
    regular(report_path, 2 * 1024 ** 2)
    report = json.loads(report_path.read_text())
    require(report['version'] == 1 and report['kind'] == 'opencloud-web-owner-recovery-build'
            and report['source_revision'] == UPSTREAM and report['source_tree'] == UPSTREAM_TREE
            and report['pins_sha256'] == digest(pins_path)
            and report['patch_sha256'] == digest(source / relative(pins['patch']))
            and report['lock_sha256'] == pins['lock_sha256']
            and report['node'] == '24.19.0' and report['pnpm'] == '11.27.0'
            and all(report[key] is False for key in ('lifecycle_scripts', 'build_network', 'global_installation')))
    records = report['files']
    require(isinstance(records, dict) and 1 <= len(records) <= 10000
            and {'index.html', 'UPSTREAM_LICENSE'} <= records.keys())
    total = 0
    for name, record in records.items():
        path = dist / relative(name)
        info = regular(path, 32 * 1024 ** 2)
        require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int
                and record['bytes'] == info.st_size and record['sha256'] == digest(path))
        total += info.st_size
        require(total <= 120 * 1024 ** 2)
    require(digest(dist / 'UPSTREAM_LICENSE') == pins['license_sha256'])
    actual = set()
    for directory, directories, files in os.walk(dist, followlinks=False):
        for name in directories:
            require(not (Path(directory) / name).is_symlink())
        actual.update(str((Path(directory) / name).relative_to(dist)) for name in files)
    require(actual == set(records) | {'BUILD_REPORT.json'})
    return dict(source_revision=UPSTREAM, source_tree=UPSTREAM_TREE,
                pins_sha256=digest(pins_path), patch_sha256=report['patch_sha256'],
                build_report_sha256=digest(report_path), source_built=True,
                files_verified=True, ui_execution_proven=False)


def owner_run(command, owner, home, cwd, timeout=1200):
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LC_ALL': 'C',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                   'GIT_TERMINAL_PROMPT': '0'}
    process = subprocess.Popen(['setpriv', f'--reuid={owner.pw_uid}', f'--regid={owner.pw_gid}',
        '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all', '--bounding-set=-all',
        '--no-new-privs', '--', *map(str, command)], cwd=cwd, env=environment, start_new_session=True)
    try:
        require(process.wait(timeout=timeout) == 0)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)


def owned_directory(path, owner):
    path.mkdir(mode=0o700)
    os.chown(path, owner.pw_uid, owner.pw_gid)


def copy_public_tree(source, target):
    """Copy a verified public tree without importing symlinks or owner-write access."""
    require(not target.exists() and not target.is_symlink())
    target.mkdir(mode=0o755, parents=True)
    count, total = 0, 0
    for directory, directories, files in os.walk(source, followlinks=False):
        destination = target / Path(directory).relative_to(source)
        for name in directories:
            child = Path(directory) / name
            require(not child.is_symlink() and child.resolve() == child)
            (destination / name).mkdir(mode=0o755)
        for name in files:
            child = Path(directory) / name
            info = regular(child, 512 * 1024 ** 2)
            count += 1
            total += info.st_size
            require(count <= 10000 and total <= 1024 ** 3)
            shutil.copyfile(child, destination / name)
            (destination / name).chmod(0o555 if info.st_mode & 0o111 else 0o444)


def provision_ui(source, runtime):
    # The outer guard checks Debian13/KVM/root/hostname and fresh exact /opt paths.
    require(os.geteuid() == 0 and source == Path('/opt/volparossa-cloud')
            and runtime == Path('/opt/volparossa-node'))
    owner = pwd.getpwnam('vpci')
    require(owner.pw_uid > 0 and owner.pw_gid > 0 and shutil.disk_usage('/opt').free >= 8 * 1024 ** 3)
    pins = json.loads((source / 'third_party/opencloud-web-ui.json').read_text())
    require(pins['revision'] == UPSTREAM and pins['tree'] == UPSTREAM_TREE
            and pins['repository'] == 'https://github.com/opencloud-eu/web.git')
    # Workspace-local builder expects ROOT/build/<source>. A new private public-code
    # scratch meets that contract without making the final root-owned SOURCE writable.
    with tempfile.TemporaryDirectory(prefix='cloud-web-build.', dir='/opt') as temporary:
        work = Path(temporary)
        os.chown(work, owner.pw_uid, owner.pw_gid)
        for name in ('scripts', 'third_party', 'patches', 'build', 'home'):
            owned_directory(work / name, owner)
        for name in ('scripts/build_web_ui.py', 'third_party/opencloud-web-ui.json', pins['patch']):
            shutil.copyfile(source / name, work / name)
            (work / name).chmod(0o444)
        upstream = work / 'build/opencloud-web-11e699'
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'credential.helper=']
        owner_run([*git, 'init', str(upstream)], owner, work / 'home', work, 30)
        owner_run([*git, '-C', upstream, 'fetch', '--no-tags', '--depth=1',
                   pins['repository'], UPSTREAM], owner, work / 'home', work, 240)
        owner_run([*git, '-C', upstream, 'checkout', '--detach', UPSTREAM], owner, work / 'home', work, 60)
        owner_run([*git, '-C', upstream, 'apply', '--check', work / pins['patch']], owner, work / 'home', work, 30)
        owner_run([*git, '-C', upstream, 'apply', work / pins['patch']], owner, work / 'home', work, 30)
        owner_run(['/usr/bin/python3', '-B', work / 'scripts/build_web_ui.py', '--source', upstream,
                   '--node', runtime / 'bin/node', '--download', '--build', '--yes'],
                  owner, work / 'home', work)
        dist = upstream / 'dist'
        ui = verify_ui(source, dist)
        copy_public_tree(dist, source / 'build/web-ui')
        require(verify_ui(source, source / 'build/web-ui') == ui)
        license_file = work / 'build/pnpm-11.27.0/package/LICENSE'
        regular(license_file, 65536)
        shutil.copyfile(license_file, source / 'build/PNPM_LICENSE')
    return ui


def provision_browser(source):
    require(os.geteuid() == 0 and source == Path('/opt/volparossa-cloud')
            and not BROWSER_STAGE.exists() and not BROWSER_STAGE.is_symlink())
    owner = pwd.getpwnam('vpci')
    with tempfile.TemporaryDirectory(prefix='cloud-browser-stage.', dir='/opt') as temporary:
        home = Path(temporary)
        os.chown(home, owner.pw_uid, owner.pw_gid)
        owner_run(['/usr/bin/python3', '-B', HERE / 'browser-network-provision.py',
                   'provision', BROWSER_STAGE], owner, home, home, 300)
    pins_path = HERE / 'browser-network-pins.json'
    pins = json.loads(pins_path.read_text())
    require(json.loads((BROWSER_STAGE / 'provision.json').read_text()) == pins)
    runtime = pins['runtime']
    require(runtime == json.loads((HERE / 'agent-private-task-browser-pins.json').read_text())['runtime']
            and runtime['version'] == '140.16.0')
    original = BROWSER_STAGE / 'build/firefox-esr'
    for name, expected in runtime['files'].items():
        regular(original / relative(name), 512 * 1024 ** 2)
        require(digest(original / name) == expected)
    destination = source / 'build/firefox-esr'
    copy_public_tree(original, destination)
    for name, expected in runtime['files'].items():
        require(digest(destination / name) == expected)
    copyright_file = BROWSER_STAGE / 'package/usr/share/doc/firefox-esr/copyright'
    regular(copyright_file, 4 * 1024 ** 2)
    shutil.copyfile(copyright_file, source / 'build/FIREFOX_COPYRIGHT')
    shutil.copyfile(BROWSER_STAGE / 'provision.json', source / 'build/FIREFOX_PROVISION.json')
    return dict(version=runtime['version'], source_stamp=runtime['source_stamp'],
                archive_sha256=runtime['sha256'], files_verified=True, browser_execution_proven=False)
