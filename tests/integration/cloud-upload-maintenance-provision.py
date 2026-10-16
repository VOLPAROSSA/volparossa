#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Separate exact-source Cloud upload continuation, only in the disposable guest.

The existing consumer source trees, pins and Node runtime are never replaced.
No owner data, authority, storage request, SDK or browser is created here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import shutil
import socket
import stat
import subprocess

HERE = Path(__file__).resolve().parent
PINS = HERE / 'cloud-upload-maintenance-pins.json'
PINS_V2 = HERE / 'cloud-upload-maintenance-pins-v2.json'
PINS_V3 = HERE / 'cloud-upload-maintenance-pins-v3.json'
PINS_V4 = HERE / 'cloud-upload-maintenance-pins-v4.json'
PINS_V5 = HERE / 'cloud-upload-maintenance-pins-v5.json'
BASE = runpy.run_path(str(HERE / 'image-snapshot-provision.py'))
PREVIOUS = runpy.run_path(str(HERE / 'storage-consumer-maintenance-evidence.py'))
require, digest, verify_files = (BASE[name] for name in ('require', 'digest', 'verify_files'))
SOURCES = {name: Path('/opt') / ('volparossa-' + name + '-upload') for name in ('image', 'cloud')}
RUNTIME = Path('/opt/volparossa-node')
PREVIOUS_RECEIPT = Path('/opt/volparossa-storage-consumers/provision.json')
RECEIPT = Path('/opt/volparossa-cloud-upload-proof')
REVISIONS = dict(image='eb9758453d094df5ea3ba045e993bd3d2dd47881',
    cloud='cea181f1f80d57c9d8047093ed543f40ec43138d')
STREAM_REVISIONS = dict(image='949f208dbb48fcb734d4dfd33eb1933b69830a01',
    cloud='7d10c4943062c5a0ae46fc57e293dc3e33db3ed2')
CHALLENGE_REVISIONS = dict(image='43029ea8b780de2376a3b7325d24a8e1c657f08e',
    cloud='e0db1cacf7bec2df3925ee454ec6216587b8ddef')
APPEND_REVISIONS = dict(image='10c46b9d6424929748e324fdd188a2f5ca77851a',
    cloud='dda7a21818ece774445cf63d6e9a01fe0f2803b2')
FLOW_REVISIONS = dict(image='9694a2b9dcb40aceefd78dbc0ab34303071a0ffd',
    cloud='47b0f03b84913761570c3de7037ba5509b848c23')
FILES = {
    'image': frozenset(('scripts/immich_snapshot.py', 'src/core-storage.mjs', 'LICENSE')),
    'cloud': frozenset(('scripts/cloud-catalog.mjs', 'scripts/cloud-serve.mjs',
        'scripts/private_file.py', 'scripts/private_catalog.py', 'scripts/upload_lock.py',
        'scripts/recovery-web-assets.mjs', 'src/private-file.mjs', 'src/private-catalog.mjs',
        'src/opencloud-dav.mjs', 'src/private-dav-server.mjs', 'src/private-resource-id.mjs',
        'src/recovery-web-metadata.mjs', 'src/owner-uploads.mjs', 'src/storage-maintenance.mjs',
        'src/storage-upload-maintenance.mjs', 'vendor/volparossa-image/immich_snapshot.py',
        'vendor/volparossa-image/core-storage.mjs', 'vendor/volparossa-image/LICENSE',
        'third_party/volparossa-image-source.json', 'THIRD_PARTY_LICENSES.md', 'LICENSE')),
}
VENDORED = {name: 'vendor/volparossa-image/' + Path(name).name
    for name in FILES['image']}
TRUE_FLAGS = ('guest_only', 'source_files_verified', 'runtime_files_verified',
    'runtime_reused_without_modification', 'shared_adapter_verified', 'original_licenses_retained')
FALSE_FLAGS = ('storage_enrollment_created', 'peer_storage_proven', 'application_restore_proven',
    'sdk_or_browser_provisioned', 'opencloud_account_server_started')


def pins_path(profile_version=1):
    require(type(profile_version) is int and profile_version in (1, 2, 3, 4, 5))
    return {1: PINS, 2: PINS_V2, 3: PINS_V3, 4: PINS_V4, 5: PINS_V5}[profile_version]


def source_revisions(profile_version=1):
    pins_path(profile_version)
    return {1: REVISIONS, 2: STREAM_REVISIONS, 3: CHALLENGE_REVISIONS,
        4: APPEND_REVISIONS, 5: FLOW_REVISIONS}[profile_version]


def load_pins(profile_version=1):
    pins = json.loads(pins_path(profile_version).read_text())
    revisions = source_revisions(profile_version)
    require(set(pins) == {'version', 'sources', 'runtime'} and type(pins['version']) is int
        and pins['version'] == profile_version and set(pins['sources']) == set(SOURCES)
        and pins['runtime'] == BASE['loader']()['load_pins']()['runtime'])
    for name, source in pins['sources'].items():
        require(set(source) == {'repository', 'revision', 'files'}
            and source['repository'] == 'https://github.com/VOLPAROSSA/volparossa-' + name
            and source['revision'] == revisions[name] and set(source['files']) == FILES[name])
        for record in source['files'].values():
            require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int
                and 0 < record['bytes'] <= 131072
                and type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}', record['sha256']))
    for original, vendored in VENDORED.items():
        require(pins['sources']['image']['files'][original] == pins['sources']['cloud']['files'][vendored])
    return pins


def public_file(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            and not before.st_mode & 0o6022 and 0 < before.st_size <= maximum)
        data = stream.read(maximum + 1)
        after, named = os.fstat(stream.fileno()), path.lstat()
        require(len(data) == before.st_size and all(getattr(before, key) == getattr(other, key)
            for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            for other in (after, named)))
    return data


def verify_shared_runtime(pins, profile_version=1):
    # Only the old successful provision receipt, not a prior application pass,
    # authorizes reuse. The continuation must separately require zero usage.
    raw = public_file(PREVIOUS_RECEIPT, 65536)
    previous = json.loads(raw)
    PREVIOUS['validate_provision'](previous)
    pins_path(profile_version)
    require(previous['version'] in {1: (1, 2, 3, 4, 5), 2: (6,), 3: (7,), 4: (8,), 5: (9,)}[profile_version])
    require(previous['pins']['runtime'] == pins['runtime'])
    for name, record in pins['runtime']['files'].items():
        path = RUNTIME / name
        require(path.resolve(strict=True) == path)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == (0o555 if name == 'bin/node' else 0o444))
    verify_files(RUNTIME, pins['runtime']['files'])
    return hashlib.sha256(raw).hexdigest()


def guard():
    require(os.geteuid() == 0 and socket.gethostname() == 'volparossa-alpha' and platform.machine() == 'x86_64')
    require(subprocess.check_output(['systemd-detect-virt'], text=True, timeout=5).strip() == 'kvm')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'debian' and release.get('VERSION_ID', '').strip('"') == '13')
    for root in (*SOURCES.values(), RECEIPT):
        require(root.resolve() == root and not root.exists() and not root.is_symlink())
    require(shutil.disk_usage('/opt').free >= 512 * 1024**2)


def verify_vendor(pins, profile_version=1):
    vendor = json.loads((SOURCES['cloud'] / 'third_party/volparossa-image-source.json').read_text())
    require(vendor['version'] == 1 and vendor['revision'] == source_revisions(profile_version)['image']
        and vendor['repository'] == pins['sources']['image']['repository']
        and vendor['license'] == 'GPL-3.0-only' and vendor['local_modifications'] is False
        and set(vendor['files']) == set(VENDORED))
    for original, local in VENDORED.items():
        require(vendor['files'][original] == dict(local=local, **pins['sources']['image']['files'][original])
            and digest(SOURCES['image'] / original) == digest(SOURCES['cloud'] / local))


def validate_provision(value):
    require(type(value) is dict and set(value) == {'version', 'kind', 'success', 'pins', 'pins_sha256',
        'previous_consumer_provision_sha256', 'tools', *TRUE_FLAGS, *FALSE_FLAGS})
    require(type(value['version']) is int and value['version'] in (1, 2, 3, 4, 5)
        and value['kind'] == 'cloud-upload-maintenance-runtime-provision' and value['success'] is True
        and value['pins'] == load_pins(value['version']) and value['pins_sha256'] == digest(pins_path(value['version']))
        and type(value['previous_consumer_provision_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}', value['previous_consumer_provision_sha256'])
        and all(value[name] is True for name in TRUE_FLAGS) and all(value[name] is False for name in FALSE_FLAGS))
    require(type(value['tools']) is dict and set(value['tools']) == {'gpg', 'gpg-agent', 'gpgconf', 'tar'})
    for name, tool in value['tools'].items():
        require(type(tool) is dict and set(tool) == {'package', 'package_version', 'bytes', 'sha256'}
            and tool['package'] == name and type(tool['package_version']) is str
            and re.fullmatch('[0-9A-Za-z.+:~_-]{1,100}', tool['package_version'])
            and type(tool['bytes']) is int and 0 < tool['bytes'] <= 16 * 1024**2
            and type(tool['sha256']) is str and re.fullmatch('[0-9a-f]{64}', tool['sha256']))


def provision(profile_version=1):
    pins = load_pins(profile_version)
    guard()
    previous_sha = verify_shared_runtime(pins, profile_version)
    os.umask(0o077)
    stage, tools = BASE['loader'](), BASE['tool_receipts']()
    for root in (*SOURCES.values(), RECEIPT):
        root.mkdir(mode=0o700)
    for name, source in pins['sources'].items():
        for relative, record in source['files'].items():
            stage['fetch'](f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-{name}/{source['revision']}/{relative}",
                SOURCES[name] / relative, record)
        verify_files(SOURCES[name], source['files'])
    verify_vendor(pins, profile_version)
    require(verify_shared_runtime(pins, profile_version) == previous_sha)
    report = dict(version=profile_version, kind='cloud-upload-maintenance-runtime-provision', success=True,
        pins=pins, pins_sha256=digest(pins_path(profile_version)), previous_consumer_provision_sha256=previous_sha, tools=tools,
        **dict.fromkeys(TRUE_FLAGS, True), **dict.fromkeys(FALSE_FLAGS, False))
    validate_provision(report)
    with (RECEIPT / 'provision.json').open('x') as stream:
        stream.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    for root in (*SOURCES.values(), RECEIPT):
        BASE['expose'](root)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('provision',))
    parser.add_argument('--download', action='store_true', required=True)
    parser.add_argument('--profile-version', type=int, choices=(1, 2, 3, 4, 5), default=1)
    args = parser.parse_args()
    print(json.dumps(dict(plan='guest-only-pinned-cloud-upload-continuation', revisions=source_revisions(args.profile_version),
        reuse_existing_node=True, storage_enrollment_created=False)), flush=True)
    provision(args.profile_version)
    print('Pinned upload sources verified; no enrollment, HTTP upload or protected storage operation tested')


if __name__ == '__main__':
    main()
