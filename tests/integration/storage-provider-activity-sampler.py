#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Optional, bounded local provider observations; never storage acceptance.

Sample while the consumer runs, before a stalled connection can disappear at
cleanup. Only aggregate finite phases/counts survive; no identities or raw logs.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

NAME = 'private-storage-provider-activity.json'
MAX_BYTES = 8192
MAX_REPLY = 4096
MAX_ROUNDS = 512
INTERVAL = 5
QUERY_SECONDS = 2
ROLES = ('a', 'b', 'c')
NODES = ('relay4', 'relay5', 'relay3')
PHASES = ('publish', 'exercise', 'finish')
STAGES = ('tls_handshake', 'registry_snapshot', 'selector_read', 'storage_grant_read_verify',
    'storage_challenge_write_flush', 'storage_request_read_verify', 'storage_operation', 'other_protocol', 'closing')
BUCKETS = ('under_1s', '1_to_5s', '5_to_15s', '15_to_30s', '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s')
STATES = ('observed', 'unavailable', 'rejected', 'failed', 'timeout', 'cancelled')


def require(value):
    if not value:
        raise ValueError('provider_activity_invalid')


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def count(value, low=0, high=MAX_ROUNDS):
    require(type(value) is int and low <= value <= high)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decode(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def snapshot(value):
    exact(value, ('version', 'kind', 'state', 'active_sessions', 'groups',
        'diagnostic_only', 'acceptance_evidence', 'causal_attribution'))
    count(value['version'], 1, 1)
    require(value['kind'] == 'content-provider-activity' and value['state'] in ('observed', 'unavailable')
        and value['diagnostic_only'] is True and value['acceptance_evidence'] is False
        and value['causal_attribution'] is False and type(value['groups']) is list)
    if value['state'] == 'unavailable':
        require(value['active_sessions'] is None and value['groups'] == [])
        return value
    count(value['active_sessions'], 0, 4)
    require(len(value['groups']) <= 4)
    previous, total = (-1, -1), 0
    for row in value['groups']:
        exact(row, ('stage', 'elapsed_bucket', 'count'))
        require(row['stage'] in STAGES and row['elapsed_bucket'] in BUCKETS)
        count(row['count'], 1, 4)
        key = STAGES.index(row['stage']), BUCKETS.index(row['elapsed_bucket'])
        require(key > previous)
        previous, total = key, total + row['count']
    require(total == value['active_sessions'])
    return value


def wait_rank(value):
    return max((BUCKETS.index(row['elapsed_bucket']) for row in value['groups']), default=-1)


def validate(value):
    exact(value, ('version', 'kind', 'phase', 'rounds', 'sampler_joined', 'children_joined',
        'sampling_failed', 'roles', 'diagnostic_only', 'acceptance_evidence', 'causal_attribution'))
    count(value['version'], 1, 1)
    require(value['kind'] == 'private-storage-provider-activity' and value['phase'] in PHASES
        and value['diagnostic_only'] is True and value['acceptance_evidence'] is False
        and value['causal_attribution'] is False and value['sampler_joined'] is True
        and type(value['children_joined']) is bool and type(value['sampling_failed']) is bool)
    count(value['rounds'])
    exact(value['roles'], ROLES)
    for row in value['roles'].values():
        exact(row, ('queries', 'counts', 'last_state', 'last', 'longest_wait'))
        count(row['queries'], 0, value['rounds'])
        exact(row['counts'], STATES)
        for n in row['counts'].values(): count(n)
        require(sum(row['counts'].values()) == row['queries'])
        require(row['last_state'] in (*STATES, 'unqueried')
            and (row['last_state'] == 'unqueried') == (row['queries'] == 0))
        if row['last_state'] in ('observed', 'unavailable'):
            snapshot(row['last'])
            require(row['last']['state'] == row['last_state'])
        else:
            require(row['last'] is None)
        if row['last_state'] != 'unqueried': require(row['counts'][row['last_state']] > 0)
        if row['longest_wait'] is not None:
            snapshot(row['longest_wait'])
            require(row['longest_wait']['state'] == 'observed' and row['longest_wait']['active_sessions'] > 0
                and row['counts']['observed'] > 0)
        if row['last_state'] == 'observed' and row['last']['active_sessions'] > 0:
            require(row['longest_wait'] is not None and wait_rank(row['longest_wait']) >= wait_rank(row['last']))
    require(len(encoded(value)) <= MAX_BYTES)
    return value


def query(binary, control, stopped):
    """One finite CLI child, private bounded pipe, cancellation and actual reap."""
    process, selector, joined = None, None, True
    result, output = ('failed', None), bytearray()
    try:
        process = subprocess.Popen([str(binary), '--control-socket', str(control), 'content', 'provider-activity'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
        selector = selectors.DefaultSelector()
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + QUERY_SECONDS
        while selector.get_map() or process.poll() is None:
            if stopped.is_set():
                result = ('cancelled', None)
                break
            if time.monotonic() >= deadline:
                result = ('timeout', None)
                break
            for event, _ in selector.select(.05):
                data = os.read(event.fd, min(4096, MAX_REPLY + 1 - len(output)))
                if data: output.extend(data)
                else: selector.unregister(event.fileobj)
            if len(output) > MAX_REPLY:
                result = ('rejected', None)
                break
        else:
            if process.returncode == 0:
                try:
                    value = snapshot(decode(bytes(output), MAX_REPLY))
                    result = (value['state'], value)
                except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
                    result = ('rejected', None)
    except (OSError, ValueError, subprocess.SubprocessError):
        result = ('failed', None)
    finally:
        if selector is not None:
            try: selector.close()
            except OSError: joined = False
        if process is not None:
            # The fixed CLI does not spawn descendants. Still stop its owned
            # group, including a process that inherited a pipe, on every path.
            try: os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            except OSError: joined = False
            try: process.wait(timeout=.2)
            except subprocess.TimeoutExpired: pass
            except (OSError, subprocess.SubprocessError): joined = False
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            except OSError: joined = False
            try: process.wait(timeout=1)
            except (OSError, subprocess.SubprocessError): joined = False
            try: os.killpg(process.pid, 0)
            except ProcessLookupError: pass
            except OSError: joined = False
            else: joined = False
            try: process.stdout.close()
            except OSError: joined = False
    return (*result, joined)


class Samples:
    def __init__(self, phase):
        require(phase in PHASES)
        self.phase, self.rounds, self.joined, self.failed = phase, 0, True, False
        self.roles = {role: dict(queries=0, counts=dict.fromkeys(STATES, 0), last_state='unqueried',
            last=None, longest_wait=None) for role in ROLES}

    def add(self, role, state, value, joined):
        require(role in ROLES and state in STATES and type(joined) is bool)
        if value is not None:
            snapshot(value)
            require(value['state'] == state)
            value = json.loads(encoded(value))
        else: require(state not in ('observed', 'unavailable'))
        row = self.roles[role]
        row['queries'] += 1
        row['counts'][state] += 1
        row.update(last_state=state, last=value)
        if state == 'observed' and value['active_sessions'] and (
                row['longest_wait'] is None or wait_rank(value) >= wait_rank(row['longest_wait'])):
            row['longest_wait'] = value
        self.joined &= joined
        self.failed |= not joined

    def report(self):
        return validate(dict(version=1, kind='private-storage-provider-activity', phase=self.phase,
            rounds=self.rounds, sampler_joined=True, children_joined=self.joined,
            sampling_failed=self.failed, roles=self.roles,
            diagnostic_only=True, acceptance_evidence=False, causal_attribution=False))


def private_name(phase):
    require(phase in PHASES)
    return f'private-storage-provider-activity-{phase}.json'


def publish(root, phase, value):
    info = root.lstat()
    require(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    data = encoded(validate(value))
    require(value['phase'] == phase)
    descriptor = os.open(root / private_name(phase), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream: stream.write(data)


@contextmanager
def capture(binary, work, root, phase):
    """Independent optional diagnostic; never replace the application's outcome."""
    samples, stopped = Samples(phase), threading.Event()

    def observe():
        try:
            for _ in range(MAX_ROUNDS):
                if stopped.is_set(): break
                started = time.monotonic()
                samples.rounds += 1
                for role, node in zip(ROLES, NODES):
                    if stopped.is_set(): break
                    samples.add(role, *query(binary, work / f'runtime-{node}/control/agent.sock', stopped))
                if stopped.wait(max(0, INTERVAL - (time.monotonic() - started))): break
        except Exception:
            samples.failed = True
            samples.joined = False  # An interrupted query is not confirmed reaped.

    thread = threading.Thread(target=observe, name='storage-provider-activity-sampler')
    started = False
    try:
        try:
            thread.start()
            started = True
        except RuntimeError:
            samples.failed = True
        yield
    finally:
        stopped.set()
        if started: thread.join()  # One bounded query; checks stop before the next.
        try: publish(root, phase, samples.report())
        except Exception: pass  # Optional diagnostics never replace the primary result.


def read_file(path, phase, owner):
    require(type(owner) is int and owner >= 0 and phase in PHASES)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(path.resolve() == path and stat.S_ISREG(before.st_mode) and before.st_uid == owner
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= MAX_BYTES)
        raw = stream.read(MAX_BYTES + 1)
        after, named = os.fstat(stream.fileno()), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(named, k) for k in fields))
    value = validate(decode(raw, MAX_BYTES))
    require(value['phase'] == phase)
    return value


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 4 and sys.argv[3].isdigit())
        sys.stdout.buffer.write(encoded(read_file(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]))))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise SystemExit(1) from None
