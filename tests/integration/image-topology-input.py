#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify the private Immich ciphertext handoff and project only its public receipt."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

HERE = Path(__file__).resolve().parent
OWNER_PINS = HERE / 'image-snapshot-owner-pins.json'
FIELDS = {'version', 'kind', 'cipher_file', 'cipher_sha256', 'cipher_bytes', 'encryption', 'source_consistency'}
MAX_CIPHER = 1024 * 1024  # Four independently charged fragments of at most one wire chunk each.


def check(value):
    if not value:
        raise ValueError('Image peer handoff invalid')


def directory(path, names):
    info = path.lstat()
    check(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode)
          and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
          and set(p.name for p in path.iterdir()) == set(names))


def private_bytes(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        before = os.fstat(source.fileno())
        check(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
              and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= limit)
        value = source.read(limit + 1)
        after = path.lstat()
        check(len(value) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns)
              == (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns))
        return value


def sha(value):
    return hashlib.sha256(value).hexdigest()


def owner_receipt(path):
    record = json.loads(private_bytes(path / 'receipt.json', 4096))
    check(isinstance(record, dict) and set(record) == FIELDS and type(record['version']) is int
          and record['version'] == 1 and record['kind'] == 'volparossa-immich-snapshot'
          and record['cipher_file'] == 'snapshot.pgp' and record['encryption'] == 'OpenPGP-AES256'
          and record['source_consistency'] == 'operator-asserted-quiesced-copy'
          and type(record['cipher_bytes']) is int and 16 <= record['cipher_bytes'] <= MAX_CIPHER
          and isinstance(record['cipher_sha256'], str) and re.fullmatch('[0-9a-f]{64}', record['cipher_sha256']))
    return record


def verify(path):
    directory(path, ('snapshot.pgp', 'receipt.json'))
    record = owner_receipt(path)
    cipher = private_bytes(path / 'snapshot.pgp', MAX_CIPHER)
    check(len(cipher) == record['cipher_bytes'] and sha(cipher) == record['cipher_sha256'])
    return record


def check_source(checkout):
    pins = json.loads(OWNER_PINS.read_bytes())
    for name, expected in pins['files'].items():
        path = checkout / name
        check(path.resolve() == path and path.is_file() and path.stat().st_size == expected['bytes']
              and sha(path.read_bytes()) == expected['sha256'])


def host_receipt(source, restored, topology, core, image, run, attempt):
    check(all(re.fullmatch('[0-9a-f]{40}', v) for v in (core, image))
          and all(re.fullmatch('[1-9][0-9]{0,20}', v) for v in (run, attempt)))
    directory(source, ('receipt.json',))
    record = owner_receipt(source)
    directory(restored, ('snapshot.pgp',))
    result = private_bytes(restored / 'snapshot.pgp', MAX_CIPHER)
    check(len(result) == record['cipher_bytes'] and sha(result) == record['cipher_sha256'])
    smoke = json.loads((topology / 'image-snapshot-smoke.json').read_bytes())
    runpy.run_path(str(HERE / 'image-snapshot-smoke.py'))['validate_report'](smoke, core, joined=True)
    for phase in ('before', 'after'):
        check(sha((topology / f'host-state-{phase}.json').read_bytes()) == smoke['host_state'][phase + '_sha256'])
    checked = smoke['image']['prepare']
    check(checked['ciphertext_bytes'] == len(result) and checked['cipher_sha256'] == record['cipher_sha256'])
    cleanup = json.loads((topology / 'image-vm-cleanup.json').read_bytes())
    check(cleanup == dict(schema_version=1, source_revision=core, qemu_started=True, qemu_joined=True,
                          private_guest_state_removed=True))
    return dict(version=1, kind='image-immich-peer-transport', core_revision=core, image_revision=image,
                run_id=run, run_attempt=attempt, cipher_bytes=len(result), cipher_sha256=sha(result),
                source_ciphertext_removed=True, withdrawn_provider_unavailable=True, peer_restores=2,
                all_eight_copies_deleted=True, providers_final_usage_zero=True, kvm_joined=True,
                guest_private_state_removed=True)


def main(args):
    if len(args) == 2 and args[0] == 'verify':
        print(verify(Path(args[1]))['cipher_sha256'])
    elif len(args) == 2 and args[0] == 'check-source':
        check_source(Path(args[1]))
    elif len(args) == 8 and args[0] == 'host-receipt':
        print(json.dumps(host_receipt(*map(Path, args[1:4]), *args[4:]), sort_keys=True))
    else:
        raise ValueError('invalid command')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, TypeError, ValueError, KeyError):
        sys.exit('Image private handoff verification failed')
