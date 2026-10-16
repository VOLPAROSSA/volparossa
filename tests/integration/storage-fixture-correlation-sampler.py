#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable, opt-in connection correlation; never application acceptance.

Epochs and TLS fingerprints exist only in this process and private child pipes.
The retained file is already a closed public projection, not a private reply.
Matched connections do not identify a fragment/copy or establish causality.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

NAME = 'private-storage-fixture-correlation.json'
MAX_BYTES = 16384
MAX_REQUEST = 4096
MAX_REPLY = 32768
MAX_RECORDS = 64
MAX_PUBLIC_RECORDS = 32
MAX_ROUNDS = 512
MAX_SECONDS = 2400
INTERVAL = 5
QUERY_SECONDS = 2
PHASES = ('publish', 'exercise', 'finish')
NODES = ('client', 'relay4', 'relay5', 'relay3')
ROLES = ('a', 'b', 'c')
CLIENT_PHASES = ('flow_acquire', 'tls_handshake', 'client_challenge', 'client_exchange', 'closing')
PROVIDER_PHASES = ('tls_handshake', 'registry_snapshot', 'selector_read', 'storage_grant_read_verify',
    'storage_challenge_write_flush', 'storage_request_read_verify', 'storage_operation', 'other_protocol', 'closing')
TERMINALS = ('active', 'complete', 'tls_timeout', 'tls_error', 'operation_error', 'cancelled')
MATCHES = ('matched', 'matched_incomplete', 'missing', 'ambiguous', 'incomplete', 'unmatchable')


def require(value):
    if not value: raise ValueError('fixture_correlation_invalid')


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def hexadecimal(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def request(action, epoch, fingerprints):
    require(action in ('arm', 'clients', 'providers', 'disarm') and hexadecimal(epoch, 32)
        and type(fingerprints) is list)
    require(all(hexadecimal(item, 64) for item in fingerprints) and len(set(fingerprints)) == len(fingerprints))
    require(1 <= len(fingerprints) <= 8 if action == 'providers' else fingerprints == [])
    value = dict(version=1, action=action, epoch=epoch, fingerprints=fingerprints)
    require(len(encoded(value)) <= MAX_REQUEST)
    return value


def phase_terminal(phase, terminal, role):
    require(phase in (CLIENT_PHASES if role == 'client' else PROVIDER_PHASES) and terminal in TERMINALS)
    require(terminal not in ('tls_timeout', 'tls_error') or phase == 'tls_handshake')


def reply(value, action, fingerprints):
    exact(value, ('version', 'kind', 'state', 'incomplete', 'records', 'diagnostic_only', 'acceptance_evidence'))
    require(type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'storage-fixture-correlation' and type(value['incomplete']) is bool
        and value['diagnostic_only'] is True and value['acceptance_evidence'] is False
        and type(value['records']) is list and len(value['records']) <= MAX_RECORDS)
    expected = dict(arm='armed', clients='observed', providers='observed', disarm='disarmed')[action]
    require(value['state'] in (expected, 'unavailable'))
    if value['state'] != 'observed':
        require(value['records'] == [] and value['incomplete'] is (value['state'] == 'unavailable'))
    role = 'client' if action == 'clients' else 'provider'
    for row in value['records']:
        exact(row, ('role', 'fingerprint', 'phase', 'terminal'))
        require(row['role'] == role)
        fingerprint = row['fingerprint']
        require(fingerprint is None and role == 'client' or hexadecimal(fingerprint, 64))
        require(role != 'provider' or fingerprint in fingerprints)
        phase_terminal(row['phase'], row['terminal'], role)
    return value


def query(binary, control, action, epoch, fingerprints, stopped):
    """Bounded private stdin/stdout; argv/env/stderr never carry reply content."""
    process = selector = None
    state, value, joined = 'failed', None, True
    outgoing = bytearray(encoded(request(action, epoch, fingerprints)))
    incoming = bytearray()
    try:
        if stopped.is_set(): return 'cancelled', None, True
        deadline = time.monotonic() + QUERY_SECONDS
        process = subprocess.Popen([str(binary), '--control-socket', str(control), 'content', 'fixture-correlation'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, close_fds=True)
        selector = selectors.DefaultSelector()
        for stream in (process.stdin, process.stdout): os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        offset, eof = 0, False
        while not (eof and process.poll() is not None):
            if stopped.is_set(): state = 'cancelled'; break
            if time.monotonic() >= deadline: state = 'timeout'; break
            for key, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                if key.fileobj is process.stdin:
                    offset += os.write(process.stdin.fileno(), outgoing[offset:])
                    if offset == len(outgoing):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                else:
                    chunk = os.read(process.stdout.fileno(), MAX_REPLY + 1 - len(incoming))
                    if not chunk:
                        eof = True
                        selector.unregister(process.stdout)
                    else:
                        incoming.extend(chunk)
                        if len(incoming) > MAX_REPLY: raise ValueError('fixture_correlation_invalid')
        else:
            if process.returncode == 0:
                value = reply(decode(bytes(incoming), MAX_REPLY), action, fingerprints)
                state = value['state']
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        state, value = 'rejected', None
    except (OSError, subprocess.SubprocessError):
        state, value = 'failed', None
    finally:
        outgoing.clear()
        incoming.clear()
        if selector is not None:
            try: selector.close()
            except OSError: joined = False
        if process is not None:
            # The fixed content fixture-correlation CLI performs only stdin,
            # one local-control exchange and stdout; it starts no subprocesses.
            # poll()/wait() may reap it. Never signal its numeric group after
            # that point: the PID/PGID could already belong to another process.
            for signum, seconds in ((signal.SIGTERM, .2), (signal.SIGKILL, 1)):
                if process.returncode is not None: break
                try: os.killpg(process.pid, signum)
                except ProcessLookupError: pass
                except OSError: joined = False
                try: process.wait(timeout=seconds)
                except subprocess.TimeoutExpired: pass  # Escalate only while still unreaped.
                except (OSError, subprocess.SubprocessError): joined = False
            joined &= process.returncode is not None
            for stream in (process.stdin, process.stdout):
                try: stream.close()
                except OSError: joined = False
    return state, value, joined


def validate(value):
    exact(value, ('version', 'kind', 'phase', 'armed', 'disarmed', 'sampler_joined', 'children_joined',
        'sampling_failed', 'incomplete', 'records', 'diagnostic_only', 'acceptance_evidence',
        'causal_attribution', 'fragment_copy_binding', 'remote_cleanup_proven'))
    require(type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'private-storage-fixture-correlation' and value['phase'] in PHASES
        and value['diagnostic_only'] is True and value['acceptance_evidence'] is False
        and value['causal_attribution'] is False and value['fragment_copy_binding'] is False
        and value['remote_cleanup_proven'] is False and value['sampler_joined'] is True)
    for key in ('armed', 'disarmed', 'children_joined', 'sampling_failed', 'incomplete'):
        require(type(value[key]) is bool)
    require(value['incomplete'] or (value['armed'] and value['disarmed'] and value['children_joined']
        and not value['sampling_failed']))
    require(type(value['records']) is list and len(value['records']) <= MAX_PUBLIC_RECORDS)
    previous = b''
    for row in value['records']:
        exact(row, ('client_phase', 'client_terminal', 'match_status', 'provider_role', 'provider_phase', 'provider_terminal'))
        phase_terminal(row['client_phase'], row['client_terminal'], 'client')
        require(row['match_status'] in MATCHES)
        if row['match_status'] in ('matched', 'matched_incomplete'):
            require(row['provider_role'] in ROLES)
            phase_terminal(row['provider_phase'], row['provider_terminal'], 'provider')
        else:
            require(row['provider_role'] is None and row['provider_phase'] is None and row['provider_terminal'] is None)
        require(row['match_status'] not in ('matched_incomplete', 'incomplete', 'unmatchable') or value['incomplete'])
        current = encoded(row)
        require(previous < current)
        previous = current
    require(len(encoded(value)) <= MAX_BYTES)
    return value


class Samples:
    def __init__(self, phase):
        require(phase in PHASES)
        self.phase, self.rows, self.cursor, self.rounds = phase, {}, 0, 0
        self.armed = self.disarmed = False
        self.joined = True
        self.failed = self.incomplete = False

    def checked(self, binary, control, action, epoch, fingerprints, stopped):
        state, value, joined = query(binary, control, action, epoch, fingerprints, stopped)
        self.joined &= joined
        expected = dict(arm='armed', clients='observed', providers='observed', disarm='disarmed')[action]
        if state != expected or not joined:
            self.failed = self.incomplete = True
            return None
        self.incomplete |= value['incomplete']
        return value

    def add(self, client, status, matched=None):
        row = dict(client_phase=client['phase'], client_terminal=client['terminal'], match_status=status,
            provider_role=matched[0] if matched else None, provider_phase=matched[1]['phase'] if matched else None,
            provider_terminal=matched[1]['terminal'] if matched else None)
        key = encoded(row)
        if key in self.rows or len(self.rows) < MAX_PUBLIC_RECORDS: self.rows[key] = row
        else:
            self.incomplete = True
            # Preserve bounded terminal observations in preference to earlier
            # active/active snapshots. Omission is always explicit, never hidden.
            if row['client_terminal'] != 'active' or row['provider_terminal'] not in (None, 'active'):
                replace = next((item for item, old in self.rows.items()
                    if old['client_terminal'] == 'active' and old['provider_terminal'] in (None, 'active')), None)
                if replace is not None:
                    del self.rows[replace]
                    self.rows[key] = row
        self.incomplete |= status in ('matched_incomplete', 'incomplete', 'unmatchable')

    def round(self, binary, controls, epoch, stopped):
        if self.rounds >= MAX_ROUNDS:
            self.incomplete = True
            return
        self.rounds += 1
        clients = self.checked(binary, controls[0], 'clients', epoch, [], stopped)
        if clients is None: return
        records = clients['records']
        fingerprints = list(dict.fromkeys(row['fingerprint'] for row in records if row['fingerprint'] is not None))
        # Rotate bounded batches; never query more than eight fingerprints per provider.
        batch = (fingerprints[self.cursor:] + fingerprints[:self.cursor])[:8]
        self.cursor = (self.cursor + len(batch)) % max(1, len(fingerprints))
        if len(batch) < len(fingerprints): self.incomplete = True
        providers = []
        if batch:
            for role, control in zip(ROLES, controls[1:]):
                if stopped.is_set(): providers.append((role, None)); continue
                providers.append((role, self.checked(binary, control, 'providers', epoch, batch, stopped)))
        complete = not clients['incomplete'] and all(value is not None and not value['incomplete'] for _, value in providers)
        for client in records:
            fingerprint = client['fingerprint']
            if fingerprint is None: self.add(client, 'unmatchable'); continue
            if fingerprint not in batch: continue
            matches = [(role, row) for role, value in providers if value is not None
                for row in value['records'] if row['fingerprint'] == fingerprint]
            if len(matches) > 1: self.add(client, 'ambiguous')
            elif len(matches) == 1:
                # A retained positive observation survives incomplete/expired
                # history, without claiming uniqueness among unobserved records.
                self.add(client, 'matched' if complete else 'matched_incomplete', matches[0])
            else: self.add(client, 'missing' if complete else 'incomplete')

    def report(self):
        incomplete = self.incomplete or self.failed or not (self.armed and self.disarmed and self.joined)
        return validate(dict(version=1, kind='private-storage-fixture-correlation', phase=self.phase,
            armed=self.armed, disarmed=self.disarmed, sampler_joined=True, children_joined=self.joined,
            sampling_failed=self.failed, incomplete=incomplete, records=[self.rows[key] for key in sorted(self.rows)],
            diagnostic_only=True, acceptance_evidence=False, causal_attribution=False,
            fragment_copy_binding=False, remote_cleanup_proven=False))


def private_name(phase):
    require(phase in PHASES)
    return f'private-storage-fixture-correlation-{phase}.json'


def publish(root, phase, value):
    info = root.lstat()
    require(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    data = encoded(validate(value))
    require(value['phase'] == phase)
    descriptor = os.open(root / private_name(phase), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream: stream.write(data)


def controls_for(work):
    require(os.geteuid() != 0 and work.is_absolute() and work.resolve() == work)
    paths = tuple(work / f'runtime-{node}/control/agent.sock' for node in NODES)
    groups = {os.getegid(), *os.getgroups()}
    for path in paths:
        info, parent = path.lstat(), path.parent.lstat()
        require(path.resolve() == path and stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o660
            and 0 < info.st_uid != os.geteuid() and info.st_gid in groups and os.access(path, os.W_OK)
            and stat.S_ISDIR(parent.st_mode) and parent.st_mode & 0o022 == 0
            and parent.st_uid == info.st_uid and parent.st_gid == info.st_gid)
    return paths


@contextmanager
def capture(binary, work, root, phase):
    """All observer failures are optional; always yield the original consumer."""
    samples, stopped = Samples(phase), threading.Event()
    epoch, controls, attempted, thread = None, (), [], None
    deadline = time.monotonic() + MAX_SECONDS

    def observe():
        try:
            for _ in range(MAX_ROUNDS):
                if stopped.is_set(): break
                if time.monotonic() >= deadline:
                    samples.incomplete = True
                    break
                started = time.monotonic()
                samples.round(binary, controls, epoch, stopped)
                if stopped.wait(max(0, INTERVAL - (time.monotonic() - started))): break
            else: samples.incomplete = True
        except Exception:
            samples.failed = samples.incomplete = True
            samples.joined = False

    try:
        try:
            controls = controls_for(work)
            epoch = os.urandom(16).hex()
            results = []
            for control in controls:
                attempted.append(control)
                results.append(samples.checked(binary, control, 'arm', epoch, [], stopped) is not None)
            samples.armed = all(results)
            if samples.armed:
                thread = threading.Thread(target=observe, name='storage-fixture-correlation-sampler')
                thread.start()
        except Exception:
            samples.failed = samples.incomplete = True
            samples.joined = False  # An unexpected query failure is not a proven child join.
        yield
    finally:
        stopped.set()
        if thread is not None and thread.ident is not None: thread.join()
        try:
            # Final query is not a new consumer request; retain terminal records
            # before disarming. It has the same bounded private query budget.
            finishing = threading.Event()
            if samples.armed and time.monotonic() < deadline:
                samples.round(binary, controls, epoch, finishing)
        except Exception:
            samples.failed = samples.incomplete = True
            samples.joined = False
        disarmed = []
        for control in attempted:
            try:
                disarmed.append(samples.checked(binary, control, 'disarm', epoch, [], threading.Event()) is not None)
            except Exception:
                samples.failed = samples.incomplete = True
                samples.joined = False
                disarmed.append(False)
        samples.disarmed = len(disarmed) == 4 and all(disarmed)
        epoch = None  # No durable secret or Python zeroization claim.
        try: publish(root, phase, samples.report())
        except Exception: pass


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
        require(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(named, key) for key in fields))
    value = validate(decode(raw, MAX_BYTES))
    require(value['phase'] == phase)
    return value


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['validate-stdin']:
            validate(decode(sys.stdin.buffer.read(MAX_BYTES + 1), MAX_BYTES))
            raise SystemExit(0)
        require(len(sys.argv) == 4 and sys.argv[3].isdigit())
        sys.stdout.buffer.write(encoded(read_file(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]))))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise SystemExit(1) from None
