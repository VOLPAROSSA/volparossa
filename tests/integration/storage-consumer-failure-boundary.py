#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Optional disposable-fixture failure snapshot; never acceptance or causality.

The seven sequential ring reads and frozen file reads are NOT atomic. Existing
v3 projections deliberately retain their original scope text. This enclosing
receipt identifies their earlier capture point without changing those contracts.
"""
import json
import os
from pathlib import Path
import runpy
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

NAME = 'storage-consumer-failure-boundary.json'
MAX_BYTES = 131072
QUERY_BYTES = 131072
QUERY_SECONDS = 2
QUERY_BUDGET = 16
NODES = ('client', 'relay0', 'relay1', 'relay2', 'relay3', 'relay4', 'relay5')
PHASES = ('publish', 'exercise', 'finish')
INPUTS = {
    'selection_phase': ('private-storage-maintenance-selection-phase.private', 32),
    'selection_start': ('private-storage-maintenance-selection-start.private', 32),
    'selection_end': ('private-storage-maintenance-selection-end.private', 32),
    'selection_route': ('private-storage-maintenance-selection-route-diagnostic.json', 2048),
    'helper': ('helper-client.log', 4 * 1024 * 1024),
}
INPUT_STATES = ('frozen', 'absent', 'invalid', 'unreadable', 'changed', 'input_bound')
QUERY_STATES = ('observed', 'socket_absent', 'invalid_socket', 'query_failed',
    'query_timeout', 'output_bound', 'budget_exhausted', 'spawn_failed')
FALSE = ('acceptance_evidence', 'causal_attribution', 'event_absence_proven',
    'request_binding', 'atomic_snapshot', 'remote_cleanup_proven',
    'scratch_cleanup_proven', 'query_cleanup_proven')


class CaptureInterrupted(BaseException):
    pass


def require(value):
    if not value:
        raise ValueError('invalid consumer failure boundary')


def modules():
    here = Path(__file__).resolve().parent
    return (runpy.run_path(str(here / 'private-storage-maintenance-smoke.py')),
            runpy.run_path(str(here / 'storage-acquire-diagnostic.py')))


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: require(False))


def validate(value, maintenance=None, helper=None):
    require(type(value) is dict and set(value) == {'version', 'kind', 'phase', 'capture_point',
        'diagnostic_only', *FALSE, 'query_seconds', 'query_budget_seconds', 'query_byte_limit',
        'queries', 'inputs', 'provider_events', 'route', 'helper_acquire'})
    require(type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'storage-consumer-failure-boundary'
        and value['phase'] in PHASES
        and value['capture_point'] == 'after_application_observer_return_before_failure_cleanup'
        and value['diagnostic_only'] is True and all(value[key] is False for key in FALSE))
    for key, expected in (('query_seconds', QUERY_SECONDS), ('query_budget_seconds', QUERY_BUDGET),
                          ('query_byte_limit', QUERY_BYTES)):
        require(type(value[key]) is int and value[key] == expected)
    require(type(value['queries']) is dict and set(value['queries']) == set(NODES))
    for row in value['queries'].values():
        require(type(row) is dict and set(row) == {'state'} and row['state'] in QUERY_STATES)
    require(type(value['inputs']) is dict and set(value['inputs']) == set(INPUTS)
        and all(type(item) is str and item in INPUT_STATES for item in value['inputs'].values()))
    if maintenance is None or helper is None:
        maintenance, helper = modules()
    maintenance['validate_provider_events'](value['provider_events'])
    require(value['provider_events']['version'] == 3
        and value['provider_events']['phase'] == 'storage-consumer-' + value['phase'])
    maintenance['validate_route_diagnostic'](value['route'])
    helper['validate'](value['helper_acquire'])
    for role, node in maintenance['PROVIDER_EVENT_ROLES'].items():
        row = value['provider_events']['roles'][role]
        state = value['queries'][node]['state']
        require((row['query_exit_status'] == 0) == (state == 'observed'))
        require(state == 'observed' or row['state'] == 'query_failed')
    require(value['inputs']['helper'] == 'frozen'
        or value['helper_acquire']['source_state'] != 'observed')
    return value


def encoded(value, maintenance=None, helper=None):
    raw = (json.dumps(validate(value, maintenance, helper), sort_keys=True,
        separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    require(len(raw) <= MAX_BYTES)
    return raw


def freeze(source, target, maximum):
    """One bounded private read; reject symlinks, mutation and unsafe modes."""
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600):
                return 'invalid'
            if before.st_size > maximum:
                return 'input_bound'
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(maximum + 1)
            after = os.fstat(fd)
            current = os.stat(source, follow_symlinks=False)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
            if identity(before) != identity(after) or identity(before) != identity(current):
                return 'changed'
            if len(raw) != before.st_size:
                return 'changed'
        finally:
            os.close(fd)
        with target.open('xb') as output:
            os.chmod(target, 0o600)
            output.write(raw)
        return 'frozen'
    except FileNotFoundError:
        return 'absent'
    except OSError:
        return 'unreadable'


def query(binary, socket, deadline):
    """One bounded CLI read; finally attempts kill and a bounded owned-child join."""
    if time.monotonic() >= deadline:
        return 'budget_exhausted', b''
    try:
        if not stat.S_ISSOCK(socket.lstat().st_mode):
            return 'invalid_socket', b''
    except FileNotFoundError:
        return 'socket_absent', b''
    except OSError:
        return 'invalid_socket', b''
    process = None
    try:
        process = subprocess.Popen([str(binary), '--control-socket', str(socket), 'logs', '--limit', '400'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            # Stay inside the enclosing timeout group, including on hard termination.
            start_new_session=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        end = min(deadline, time.monotonic() + QUERY_SECONDS)
        raw = bytearray()
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout, selectors.EVENT_READ)
            while True:
                left = end - time.monotonic()
                if left <= 0 or not poll.select(left):
                    return 'query_timeout', b''
                chunk = os.read(process.stdout.fileno(), min(16384, QUERY_BYTES + 1 - len(raw)))
                if not chunk:
                    left = end - time.monotonic()
                    if left <= 0:
                        return 'query_timeout', b''
                    try:
                        status = process.wait(timeout=left)
                    except subprocess.TimeoutExpired:
                        return 'query_timeout', b''
                    return ('observed', bytes(raw)) if status == 0 else ('query_failed', b'')
                raw.extend(chunk)
                if len(raw) > QUERY_BYTES:
                    return 'output_bound', b''
    except OSError:
        return 'spawn_failed', b''
    finally:
        if process is not None:
            # Kill/join this owned CLI only. The outer timeout also owns its
            # group; hard termination remains inside the disposable VM boundary.
            try:
                process.kill()
                process.wait(timeout=0.5)
            finally:
                process.stdout.close()


def private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)


def capture(work, binary, phase, baseline):
    """Best effort only. Temp raw state never aliases later cleanup inputs."""
    try:
        require(phase in PHASES)
        target = work / NAME
        if target.exists() or target.is_symlink():
            return False
        maintenance, helper = modules()
        with tempfile.TemporaryDirectory(prefix='.consumer-failure-boundary-', dir=work) as name:
            frozen = Path(name)
            inputs = {key: freeze(work / filename, frozen / filename, limit)
                for key, (filename, limit) in INPUTS.items()}
            deadline = time.monotonic() + QUERY_BUDGET
            queries = {}
            for node in NODES:
                state, raw = query(binary, work / ('runtime-' + node) / 'control/agent.sock', deadline)
                queries[node] = {'state': state}
                private(frozen / ('logs-' + node + '-cleanup-status.private'),
                    b'0\n' if state == 'observed' else b'1\n')
                if state == 'observed':
                    private(frozen / ('logs-' + node + '.txt'), raw)
            # Project the frozen files, not the live helper/selection inputs.
            acquire = helper['project'](frozen / 'helper-client.log')
            if inputs['helper'] != 'frozen':
                acquire = helper['empty']('absent' if inputs['helper'] == 'absent' else 'invalid')
            value = dict(version=1, kind='storage-consumer-failure-boundary', phase=phase,
                capture_point='after_application_observer_return_before_failure_cleanup',
                diagnostic_only=True, **{key: False for key in FALSE},
                query_seconds=QUERY_SECONDS, query_budget_seconds=QUERY_BUDGET,
                query_byte_limit=QUERY_BYTES, queries=queries, inputs=inputs,
                provider_events=maintenance['provider_events'](frozen, 'storage-consumer-' + phase,
                    baseline, version=3), route=maintenance['route_diagnostic'](frozen),
                helper_acquire=acquire)
            private(frozen / 'receipt.json', encoded(value, maintenance, helper))
            # Atomic no-clobber publication. The temp link is removed on exit.
            os.link(frozen / 'receipt.json', target, follow_symlinks=False)
        return True
    except BaseException:
        # Includes interrupted optional capture; caller's primary failure wins.
        return False


def main(args):
    if args == ['validate-stdin']:
        validate(decode(sys.stdin.buffer.read(MAX_BYTES + 1)))
    elif len(args) == 5 and args[0] == 'capture':
        def interrupted(_signal, _frame):
            raise CaptureInterrupted()
        signal.signal(signal.SIGTERM, interrupted)
        capture(Path(args[1]), Path(args[2]), args[3], args[4])
    else:
        raise ValueError('invalid failure boundary arguments')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
        raise SystemExit('invalid consumer failure boundary') from None
