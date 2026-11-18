#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Closed, bounded projection of a fixture-owned helper log; not acceptance evidence."""
from collections import deque
import io
import json
import os
from pathlib import Path
import stat
import sys

NAME = 'private-storage-maintenance-helper-acquire.json'
MARKER = 'WORKER_TRANSPORT_ACQUIRE_FAILED'
MAX_INPUT = 4 * 1024 * 1024
MAX_LINE = 16384
MAX_LINES = 32768
MAX_RECORDS = 64
MAX_BYTES = 16384
OPERATIONS = ('socket_create', 'ipv6_only_set', 'bind', 'connect', 'poll',
    'connect_socket_error', 'socket_domain', 'socket_type', 'socket_protocol',
    'local_address', 'listener_state', 'socket_error', 'ipv6_only_get',
    'descriptor_flags', 'status_flags', 'peer_address', 'mptcp_info', 'connect_readiness')
CLASSES = ('io', 'timed_out', 'ambiguous_readiness')
FALSE_FLAGS = ('acceptance_evidence', 'causal_attribution', 'fragment_copy_binding',
               'remote_cleanup_proven', 'event_absence_proven')


def require(condition):
    if not condition:
        raise ValueError('invalid helper acquire diagnostic')


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES)
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite diagnostic')))


def record(operation, kind, errno):
    require(type(operation) is int and 1 <= operation <= len(OPERATIONS))
    require(type(kind) is int and 1 <= kind <= len(CLASSES))
    require(errno is None or type(errno) is int and 1 <= errno <= 4095)
    require((operation == 18) == (kind == 3))
    require(kind != 3 or errno is None)
    return dict(operation=OPERATIONS[operation - 1], failure_class=CLASSES[kind - 1], errno=errno)


def empty(state='observed'):
    return dict(version=1, kind='private-storage-maintenance-helper-acquire',
        scope='client_mptcp_failure_log_projection_without_request_binding',
        diagnostic_only=True, **{name: False for name in FALSE_FLAGS},
        source_state=state, input_truncated=False, records_truncated=False,
        malformed_records=0, projection_complete=state == 'observed', records=[])


def validate(value):
    require(type(value) is dict and set(value) == set(empty()))
    require(type(value['version']) is int and value['version'] == 1)
    require(value['kind'] == empty()['kind'] and value['scope'] == empty()['scope'])
    require(value['diagnostic_only'] is True and all(value[key] is False for key in FALSE_FLAGS))
    require(value['source_state'] in ('observed', 'absent', 'invalid', 'unreadable', 'changed'))
    require(all(type(value[key]) is bool for key in
        ('input_truncated', 'records_truncated', 'projection_complete')))
    require(type(value['malformed_records']) is int and 0 <= value['malformed_records'] <= MAX_LINES)
    require(type(value['records']) is list and len(value['records']) <= MAX_RECORDS)
    for row in value['records']:
        require(type(row) is dict and set(row) == {'operation', 'failure_class', 'errno'})
        require(type(row['operation']) is str and row['operation'] in OPERATIONS)
        require(type(row['failure_class']) is str and row['failure_class'] in CLASSES)
        require(row == record(OPERATIONS.index(row['operation']) + 1,
                              CLASSES.index(row['failure_class']) + 1, row['errno']))
    if value['source_state'] != 'observed':
        require(not value['records'] and not value['input_truncated']
            and not value['records_truncated'] and value['malformed_records'] == 0)
    require(value['projection_complete'] == (value['source_state'] == 'observed'
        and not value['input_truncated'] and not value['records_truncated']
        and value['malformed_records'] == 0))
    return value


def encoded(value):
    raw = (json.dumps(validate(value), sort_keys=True, allow_nan=False) + '\n').encode('ascii')
    require(len(raw) <= MAX_BYTES)
    return raw


def project(path):
    """Read only a stable private regular file, retaining at most its bounded tail."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600):
                return validate(empty('invalid'))
            offset = max(0, before.st_size - MAX_INPUT)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                stream.seek(offset)
                raw = stream.read(MAX_INPUT)
                after = os.fstat(fd)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                     item.st_mtime_ns, item.st_ctime_ns)
            if identity(before) != identity(after) or len(raw) != before.st_size - offset:
                return validate(empty('changed'))
            try:
                current = os.stat(path, follow_symlinks=False)
            except OSError:
                return validate(empty('changed'))
            if identity(before) != identity(current):
                return validate(empty('changed'))
        finally:
            os.close(fd)
    except FileNotFoundError:
        return validate(empty('absent'))
    except OSError:
        return validate(empty('unreadable'))
    value = empty()
    value['input_truncated'] = offset != 0
    if offset:
        raw = raw.partition(b'\n')[2]  # Never parse an uncertain first partial line.
    rows = deque(maxlen=MAX_RECORDS)
    source = io.BytesIO(raw)
    for _ in range(MAX_LINES):
        line = source.readline(MAX_LINE + 1)
        if not line:
            break
        if len(line) > MAX_LINE or not line.endswith(b'\n'):
            value['input_truncated'] = True
            while line and not line.endswith(b'\n'):
                line = source.readline(MAX_LINE + 1)
            continue
        try:
            item = json.loads(line, object_pairs_hook=unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite diagnostic')))
            fields = item.get('fields') if type(item) is dict else None
            if type(fields) is not dict or fields.get('diagnostic_code') != MARKER:
                continue
            require(set(fields) in ({'diagnostic_code', 'operation', 'class'},
                                   {'diagnostic_code', 'operation', 'class', 'errno'}))
            row = record(fields['operation'], fields['class'], fields.get('errno'))
        except (ValueError, TypeError, UnicodeError, RecursionError):
            value['malformed_records'] += 1
            continue
        if len(rows) == MAX_RECORDS:
            value['records_truncated'] = True
        rows.append(row)
    if source.read(1):
        value['input_truncated'] = True
    value['records'] = list(rows)
    value['projection_complete'] = not (value['input_truncated']
        or value['records_truncated'] or value['malformed_records'])
    return validate(value)


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_BYTES)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return validate(decode(stream.read(MAX_BYTES + 1)))
    finally:
        os.close(fd)


def publish(work):
    """Optional fixture finalization: never replace its primary result with a log error."""
    part, owned = work / 'maintenance-helper-acquire.part', False
    try:
        data = encoded(project(work / 'helper-client.log'))
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        owned = True
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
        os.replace(part, work / NAME)
        return True
    except BaseException:
        if owned:
            try:
                part.unlink(missing_ok=True)
            except OSError:
                pass
        return False


if __name__ == '__main__':
    if sys.argv[1:] != ['validate-stdin']:
        raise SystemExit('expected validate-stdin')
    try:
        validate(decode(sys.stdin.buffer.read(MAX_BYTES + 1)))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise SystemExit('invalid helper acquire diagnostic') from None
