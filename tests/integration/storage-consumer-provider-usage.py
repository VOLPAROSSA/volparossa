#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed RO logical usage after provider joins; never owner reconciliation."""
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

HERE = Path(__file__).resolve().parent
NAME = 'storage-consumer-provider-usage.json'
MAX_BYTES = 4096
ROLES = ('a', 'b', 'c')
NODES = ('relay4', 'relay5', 'relay3')
REASONS = ('provider_not_joined', 'invalid_input', 'owner', 'sidecar', 'busy', 'database', 'schema', 'counts', 'query', 'changed')


def require(value):
    if not value: raise ValueError('provider_usage_invalid')


def empty(role):
    return dict(provider_role=role, provider_joined=False, state='unavailable', reason='provider_not_joined',
        reserved_bytes=None, committed_bytes=None, leases=None, owner_cleanup_proven=False)


def report(providers):
    return validate(dict(version=1, kind='storage-consumer-provider-usage', phase='before_private_journal_removal',
        providers=providers, diagnostic_only=True, acceptance_evidence=False,
        owner_reconciliation_proven=False, remote_deletion_proven=False))


def validate(value):
    require(type(value) is dict and set(value) == {'version', 'kind', 'phase', 'providers', 'diagnostic_only',
        'acceptance_evidence', 'owner_reconciliation_proven', 'remote_deletion_proven'}
        and type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'storage-consumer-provider-usage' and value['phase'] == 'before_private_journal_removal'
        and value['diagnostic_only'] is True and value['acceptance_evidence'] is False
        and value['owner_reconciliation_proven'] is False and value['remote_deletion_proven'] is False
        and type(value['providers']) is list and len(value['providers']) == 3)
    for role, row in zip(ROLES, value['providers']):
        require(type(row) is dict and set(row) == set(empty(role)) and row['provider_role'] == role
            and type(row['provider_joined']) is bool and row['owner_cleanup_proven'] is False)
        if row['state'] == 'observed':
            require(row['provider_joined'] and row['reason'] is None
                and all(type(row[key]) is int and 0 <= row[key] <= 1024 ** 4 for key in ('reserved_bytes', 'committed_bytes'))
                and row['reserved_bytes'] + row['committed_bytes'] <= 1024 ** 4
                and type(row['leases']) is int and 0 <= row['leases'] <= 256)
        else:
            require(row['state'] == 'unavailable' and row['reason'] in REASONS
                and all(row[key] is None for key in ('reserved_bytes', 'committed_bytes', 'leases'))
                and (row['provider_joined'] or row['reason'] == 'provider_not_joined'))
    require(len(encoded(value)) <= MAX_BYTES)
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def collect(work, mask, observe=None):
    require(work.is_absolute() and work.resolve() == work and re.fullmatch('[01]{3}', mask))
    if observe is None:
        observe = runpy.run_path(str(HERE / 'storage-provider-usage-snapshot.py'))['observe']
    rows = []
    for role, node, joined in zip(ROLES, NODES, mask):
        row = empty(role)
        if joined == '1':
            row['provider_joined'] = True
            try:
                result = observe(work / ('state-' + node) / 'private-store')
                require(type(result) is dict and set(result) == {'version', 'state', 'reason',
                    'reserved_bytes', 'committed_bytes', 'leases', 'owner_cleanup_proven'}
                    and type(result['version']) is int and result['version'] == 1)
                row.update({key: result[key] for key in ('state', 'reason', 'reserved_bytes',
                    'committed_bytes', 'leases', 'owner_cleanup_proven')})
                report([row if candidate == role else empty(candidate) for candidate in ROLES])
            except Exception:
                row = dict(empty(role), provider_joined=True, reason='query')
        rows.append(row)
    return report(rows)


def group_empty(raw, unit):
    require(re.fullmatch(r'volparossa-alpha-agent@relay[345]\.service', unit) is not None
        and raw.startswith('/system.slice/') and raw.endswith('/' + unit)
        and all(part not in ('', '.', '..') for part in raw[1:].split('/')))
    path = Path('/sys/fs/cgroup' + raw)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return True
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not path.is_symlink())
    return (path / 'cgroup.procs').read_bytes() == b'' and b'populated 0' in (path / 'cgroup.events').read_bytes().splitlines()


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value
    return validate(json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False)))


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
            and before.st_mode & 0o022 == 0 and 0 < before.st_size <= MAX_BYTES)
        raw = stream.read(MAX_BYTES + 1)
        after, named = os.fstat(stream.fileno()), path.lstat()
        require(all(getattr(before, key) == getattr(after, key) == getattr(named, key)
            for key in ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')))
    return decode(raw)


def main(args):
    if args == ['validate-stdin']:
        decode(sys.stdin.buffer.read(MAX_BYTES + 1))
    elif len(args) == 3 and args[0] == 'collect':
        sys.stdout.buffer.write(encoded(collect(Path(args[1]), args[2])))
    elif len(args) == 3 and args[0] == 'group-empty':
        require(group_empty(args[1], args[2]))
    else:
        require(False)


if __name__ == '__main__':
    try: main(sys.argv[1:])
    except (ValueError, TypeError, KeyError, OSError, RecursionError, UnicodeError):
        raise SystemExit(1) from None
