#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage exact Image/Cloud maintenance consumers only in the disposable guest.

This is a new proof profile. Historical Image/Cloud pins and receipts stay intact.
No SDK, npm package, browser, user data or storage enrollment is provisioned here.
"""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
PINS = HERE / 'storage-consumer-maintenance-pins.json'
PINS_V2 = HERE / 'storage-consumer-maintenance-pins-v2.json'
PINS_V3 = HERE / 'storage-consumer-maintenance-pins-v3.json'
PINS_V4 = HERE / 'storage-consumer-maintenance-pins-v4.json'
PINS_V5 = HERE / 'storage-consumer-maintenance-pins-v5.json'
PINS_V6 = HERE / 'storage-consumer-maintenance-pins-v6.json'
PINS_V7 = HERE / 'storage-consumer-maintenance-pins-v7.json'
PINS_V8 = HERE / 'storage-consumer-maintenance-pins-v8.json'
PINS_V9 = HERE / 'storage-consumer-maintenance-pins-v9.json'
PINS_V10 = HERE / 'storage-consumer-maintenance-pins-v10.json'
BASE = runpy.run_path(str(HERE / 'image-snapshot-provision.py'))
require, digest, verify_files = (BASE[key] for key in ('require', 'digest', 'verify_files'))
SOURCES = {name: Path('/opt') / ('volparossa-' + name) for name in ('image', 'cloud')}
RUNTIME = Path('/opt/volparossa-node')
RECEIPT = Path('/opt/volparossa-storage-consumers')
REVISIONS = dict(image='aade424c3e96d0934edbddf31d2434757aa08564',
    cloud='9cb94fbb83e9f503ff5a66d43ed814f556d4a3af')
DIAGNOSTIC_REVISIONS = dict(image='fa0438747b79bf29e49a2fe65116cb166ebe10df',
    cloud='f51b49b84af404cc8dd6e377e0545e2ca1ea4569')
DETAIL_REVISIONS = dict(image='87a8016652db629a0afefb41d88b3056539bee17',
    cloud='54a00b58a6c24432e7427d72ff714c786dbeb0cc')
TLS_REVISIONS = dict(image='3b5830476dabd548debfdfade4fdf72acb4fa992',
    cloud='ea24b6cd53a14b204a7b8fbfda5c76ec9ca297e7')
OUTCOME_REVISIONS = dict(image='ec6b9dca5789a60447c643652c93643b9a6c4af6',
    cloud='4409c08680eebb3d679a036546691cb541675f97')
STREAM_REVISIONS = dict(image='949f208dbb48fcb734d4dfd33eb1933b69830a01',
    cloud='7d10c4943062c5a0ae46fc57e293dc3e33db3ed2')
CHALLENGE_REVISIONS = dict(image='43029ea8b780de2376a3b7325d24a8e1c657f08e',
    cloud='e0db1cacf7bec2df3925ee454ec6216587b8ddef')
APPEND_REVISIONS = dict(image='10c46b9d6424929748e324fdd188a2f5ca77851a',
    cloud='dda7a21818ece774445cf63d6e9a01fe0f2803b2')
FLOW_REVISIONS = dict(image='9694a2b9dcb40aceefd78dbc0ab34303071a0ffd',
    cloud='47b0f03b84913761570c3de7037ba5509b848c23')
TLS_CLOSE_REVISIONS = dict(image='1e812ec6424a539a336d230b99ae1c11a494ca29',
    cloud='35598609d3fedb5d1241a479c1930c8a6b831661')
FILES = {
    'image': frozenset(('scripts/immich_snapshot.py', 'scripts/snapshot-storage.mjs',
        'src/core-storage.mjs', 'LICENSE')),
    'cloud': frozenset(('scripts/cloud-serve.mjs', 'scripts/private_file.py',
        'scripts/private_catalog.py', 'scripts/recovery-web-assets.mjs', 'src/private-file.mjs',
        'src/private-catalog.mjs', 'src/opencloud-dav.mjs', 'src/private-dav-server.mjs',
        'src/private-resource-id.mjs', 'src/recovery-web-metadata.mjs', 'src/owner-uploads.mjs',
        'src/storage-maintenance.mjs', 'vendor/volparossa-image/immich_snapshot.py',
        'vendor/volparossa-image/core-storage.mjs', 'vendor/volparossa-image/LICENSE',
        'third_party/volparossa-image-source.json', 'THIRD_PARTY_LICENSES.md', 'LICENSE')),
}
DIAGNOSTIC_FILES = dict(FILES, cloud=FILES['cloud'] | {'src/storage-upload-maintenance.mjs'})
VENDORED = {'scripts/immich_snapshot.py': 'vendor/volparossa-image/immich_snapshot.py',
    'src/core-storage.mjs': 'vendor/volparossa-image/core-storage.mjs',
    'LICENSE': 'vendor/volparossa-image/LICENSE'}


def pins_path(profile_version=1):
    require(type(profile_version) is int and profile_version in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
    return {1: PINS, 2: PINS_V2, 3: PINS_V3, 4: PINS_V4, 5: PINS_V5, 6: PINS_V6, 7: PINS_V7, 8: PINS_V8, 9: PINS_V9, 10: PINS_V10}[profile_version]


def source_revisions(profile_version=1):
    pins_path(profile_version)  # Reject bools and unknown profile selectors first.
    return {1: REVISIONS, 2: DIAGNOSTIC_REVISIONS, 3: DETAIL_REVISIONS, 4: TLS_REVISIONS,
        5: OUTCOME_REVISIONS, 6: STREAM_REVISIONS, 7: CHALLENGE_REVISIONS, 8: APPEND_REVISIONS, 9: FLOW_REVISIONS, 10: TLS_CLOSE_REVISIONS}[profile_version]


def load_pins(profile_version=1):
    path = pins_path(profile_version)
    revisions = source_revisions(profile_version)
    files = FILES if profile_version == 1 else DIAGNOSTIC_FILES
    require(all(re.fullmatch('[a-f0-9]{40}', revision) for revision in revisions.values()))
    pins = json.loads(path.read_text())
    require(set(pins) == {'version', 'sources', 'runtime'} and type(pins['version']) is int
        and pins['version'] == profile_version and set(pins['sources']) == set(SOURCES)
        and pins['runtime'] == BASE['loader']()['load_pins']()['runtime'])
    for name, source in pins['sources'].items():
        require(set(source) == {'repository', 'revision', 'files'}
            and source['repository'] == 'https://github.com/VOLPAROSSA/volparossa-' + name
            and source['revision'] == revisions[name] and set(source['files']) == files[name])
        for record in source['files'].values():
            require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int
                and 0 < record['bytes'] <= 131072
                and re.fullmatch(r'[0-9a-f]{64}', record['sha256']))
    for original, vendored in VENDORED.items():
        require(pins['sources']['image']['files'][original]
            == pins['sources']['cloud']['files'][vendored])
    return pins


def guard():
    # The existing guard requires root, the exact Debian13 KVM guest identity,
    # fresh Image/Node destinations and free space before any network/mutation.
    BASE['guard']()
    for root in (SOURCES['cloud'], RECEIPT):
        require(root.resolve() == root and not root.exists() and not root.is_symlink())


def verify_vendor(pins, profile_version=1):
    source = SOURCES['cloud'] / 'third_party/volparossa-image-source.json'
    vendor = json.loads(source.read_text())
    revisions = source_revisions(profile_version)
    require(vendor['version'] == 1 and vendor['revision'] == revisions['image']
        and vendor['repository'] == pins['sources']['image']['repository']
        and vendor['license'] == 'GPL-3.0-only' and vendor['local_modifications'] is False
        and set(vendor['files']) == set(VENDORED))
    for original, local in VENDORED.items():
        expected = pins['sources']['image']['files'][original]
        require(vendor['files'][original] == dict(local=local, **expected)
            and digest(SOURCES['image'] / original) == digest(SOURCES['cloud'] / local))


def provision(profile_version=1):
    pins = load_pins(profile_version)
    guard()
    os.umask(0o077)
    runtime_stage = BASE['loader']()
    tools = BASE['tool_receipts']()
    for root in (*SOURCES.values(), RUNTIME, RECEIPT):
        root.mkdir(mode=0o700)
    for name, source in pins['sources'].items():
        for path, record in source['files'].items():
            runtime_stage['fetch'](
                f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-{name}/{source['revision']}/{path}",
                SOURCES[name] / path, record)
        verify_files(SOURCES[name], source['files'])
    verify_vendor(pins, profile_version)
    with tempfile.TemporaryDirectory(prefix='storage-consumer-node.', dir='/opt') as temporary:
        archive = Path(temporary) / 'node.tar.xz'
        runtime_stage['fetch'](pins['runtime']['url'], archive, pins['runtime'])
        with tarfile.open(archive, 'r:xz') as bundle:
            runtime_stage['extract_runtime'](bundle, RUNTIME, pins['runtime']['files'])
    verify_files(RUNTIME, pins['runtime']['files'])
    require(subprocess.check_output([str(RUNTIME / 'bin/node'), '--version'], text=True,
        timeout=10, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}).strip() == 'v24.19.0')
    report = dict(version=profile_version, kind='storage-consumer-maintenance-runtime-provision', success=True,
        pins=pins, pins_sha256=digest(pins_path(profile_version)), tools=tools, guest_only=True,
        source_files_verified=True, runtime_files_verified=True, shared_adapter_verified=True,
        original_licenses_retained=True, storage_enrollment_created=False,
        peer_storage_proven=False, application_restore_proven=False,
        sdk_or_browser_provisioned=False, immich_or_opencloud_server_started=False)
    with (RECEIPT / 'provision.json').open('x') as stream:
        stream.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    for root in (*SOURCES.values(), RUNTIME, RECEIPT):
        BASE['expose'](root)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('provision',))
    parser.add_argument('--download', action='store_true', required=True,
        help='explicit guest-only pinned Image/Cloud sources and Node runtime download')
    parser.add_argument('--profile-version', type=int, choices=(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), default=1)
    args = parser.parse_args()
    revisions = source_revisions(args.profile_version)
    print(json.dumps(dict(plan='guest-only-pinned-storage-consumers', revisions=revisions,
        sdk_or_browser_provisioned=False, storage_enrollment_created=False)), flush=True)
    provision(args.profile_version)
    print('Pinned consumers verified; application restoration and peer maintenance are not yet tested')


if __name__ == '__main__':
    main()
