#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable, opt-in fixture observations; never application acceptance.

Epochs and TLS fingerprints exist only in this process and private child pipes.
The retained file is already a closed public projection, not a private reply.
Schemas one/two do not identify a fragment/copy. Schema three adds a separate
exact private target and request-digest match, without establishing causality.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
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
HELPER_DIAGNOSTICS = ('unknown', 'backend_result_ambiguous', 'stale_backend_result',
    'flow_identity_unavailable', 'transport_unavailable', 'cleanup_incomplete', 'replay_commit_inconsistent',
    'expired_context_cleanup_incomplete', 'expired_extension_cleanup_incomplete',
    'mptcp_connect_poll_timed_out')
HELPER_REASONS = ('helper_kernel', 'helper_capacity', 'helper_unavailable', 'helper_not_found',
    'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
    'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed')
ACQUIRE_PAIRS = frozenset([('source_port', 'entropy'), ('descriptor_clone', 'io'),
    ('flow_metadata', 'metadata')] + [('retirement_drain', value) for value in
    ('unconfirmed', 'io') + tuple(value for value in HELPER_REASONS if value != 'helper_not_found')]
    + [('material', value) for value in ('metadata', 'topology')]
    + [('slot_reservation', value) for value in ('unconfirmed', 'local_capacity', 'local_unavailable')]
    + [('helper_acquire', value) for value in HELPER_REASONS]
    + [('descriptor_adoption', value) for value in ('metadata', 'io')])


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


def request(action, epoch, fingerprints, version=1, target=None):
    require(type(version) is int and version in (1, 2, 3))
    require(action in ('arm', 'clients', 'providers', 'disarm') and hexadecimal(epoch, 32)
        and type(fingerprints) is list)
    require(all(hexadecimal(item, 64) for item in fingerprints) and len(set(fingerprints)) == len(fingerprints))
    require(1 <= len(fingerprints) <= 8 if action == 'providers' else fingerprints == [])
    value = dict(version=version, action=action, epoch=epoch, fingerprints=fingerprints)
    if version == 3 and action in ('arm', 'clients'):
        exact(target, ('archive_id', 'provider_key', 'operation'))
        require(hexadecimal(target['archive_id'], 64) and hexadecimal(target['provider_key'], 64)
            and target['operation'] == 'reserve')
        value['target'] = target
    else:
        require(target is None)
    require(len(encoded(value)) <= MAX_REQUEST)
    return value


def phase_terminal(phase, terminal, role):
    require(phase in (CLIENT_PHASES if role == 'client' else PROVIDER_PHASES) and terminal in TERMINALS)
    require(terminal not in ('tls_timeout', 'tls_error') or phase == 'tls_handshake')


def acquire_summary(value, phase, terminal):
    if value is None: return
    require(phase == 'flow_acquire' and terminal == 'operation_error')
    exact(value, ('rounds', 'first', 'last'))
    require(type(value['rounds']) is int and 1 <= value['rounds'] <= 8)
    require(value['rounds'] != 1 or value['first'] == value['last'])
    for failure in (value['first'], value['last']):
        exact(failure, ('stage', 'reason', 'helper_diagnostic'))
        require(type(failure['stage']) is str and type(failure['reason']) is str
            and (failure['stage'], failure['reason']) in ACQUIRE_PAIRS)
        code = failure['helper_diagnostic']
        require(code is None or (type(code) is str and code in HELPER_DIAGNOSTICS
            and failure['stage'] == 'helper_acquire' and failure['reason'] in HELPER_REASONS[:6]))
        require(code != 'mptcp_connect_poll_timed_out' or failure['reason'] == 'helper_kernel')


def reply(value, action, fingerprints, version=1):
    exact(value, ('version', 'kind', 'state', 'incomplete', 'records', 'diagnostic_only', 'acceptance_evidence')
        + (('target_scoped', 'complete_phase_history') if version == 3 else ()))
    require(type(version) is int and version in (1, 2, 3)
        and type(value['version']) is int and value['version'] == version
        and value['kind'] == 'storage-fixture-correlation' and type(value['incomplete']) is bool
        and value['diagnostic_only'] is True and value['acceptance_evidence'] is False
        and type(value['records']) is list and len(value['records']) <= MAX_RECORDS)
    expected = dict(arm='armed', clients='observed', providers='observed', disarm='disarmed')[action]
    require(value['state'] in (expected, 'unavailable'))
    if value['state'] != 'observed':
        require(value['records'] == [] and value['incomplete'] is (value['state'] == 'unavailable'))
    role = 'client' if action == 'clients' else 'provider'
    if version == 3:
        require(value['target_scoped'] is True and value['complete_phase_history'] is False)
        require(value['state'] != 'observed' or (not value['incomplete']
            and (action != 'clients' or len(value['records']) == 1)))
    for row in value['records']:
        exact(row, ('role', 'fingerprint', 'phase', 'terminal') + (('flow_acquire',) if version >= 2 else ())
            + (('request_observation',) if version == 3 else ()))
        require(row['role'] == role)
        fingerprint = row['fingerprint']
        require(fingerprint is None and role == 'client' or hexadecimal(fingerprint, 64))
        require(role != 'provider' or fingerprint in fingerprints)
        phase_terminal(row['phase'], row['terminal'], role)
        if version >= 2:
            require(role == 'client' or row['flow_acquire'] is None)
            require(row['flow_acquire'] is None or fingerprint is None)
            acquire_summary(row['flow_acquire'], row['phase'], row['terminal'])
        if version == 3:
            detail = row['request_observation']
            request_observation(detail, role)
            require(role != 'client' or fingerprint is not None)
            if detail is not None:
                require(not detail['worker_returned_after_terminal'] or row['terminal'] in ('operation_error', 'cancelled'))
                if role == 'provider':
                    require(detail['worker_state'] == 'unobserved'
                        or PROVIDER_STAGES.index(detail['provider_stage']) >= 2 or row['terminal'] != 'active')
                    require(detail['worker_state'] not in ('returned_ok', 'returned_error')
                        or PROVIDER_STAGES.index(detail['provider_stage']) >= 3 or detail['worker_returned_after_terminal'])
    if version == 3:
        require(len({row['fingerprint'] for row in value['records']}) == len(value['records']))
    return value


def query(binary, control, action, epoch, fingerprints, stopped, version=1, target=None, deadline=None):
    """Bounded private stdin/stdout; argv/env/stderr never carry reply content."""
    process = selector = None
    state, value, joined = 'failed', None, True
    outgoing = bytearray(encoded(request(action, epoch, fingerprints, version, target)))
    incoming = bytearray()
    try:
        if stopped.is_set(): return 'cancelled', None, True
        deadline = min(deadline if deadline is not None else float('inf'), time.monotonic() + QUERY_SECONDS)
        if time.monotonic() >= deadline: return 'timeout', None, True
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
                value = reply(decode(bytes(incoming), MAX_REPLY), action, fingerprints, version)
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
    if type(value) is dict and type(value.get('version')) is int and value['version'] == 3:
        return validate_request_report(value)
    exact(value, ('version', 'kind', 'phase', 'armed', 'disarmed', 'sampler_joined', 'children_joined',
        'sampling_failed', 'incomplete', 'records', 'diagnostic_only', 'acceptance_evidence',
        'causal_attribution', 'fragment_copy_binding', 'remote_cleanup_proven'))
    require(type(value['version']) is int and value['version'] in (1, 2)
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
        exact(row, ('client_phase', 'client_terminal', 'match_status', 'provider_role', 'provider_phase', 'provider_terminal')
            + (('flow_acquire',) if value['version'] == 2 else ()))
        if value['version'] == 2:
            acquire_summary(row['flow_acquire'], row['client_phase'], row['client_terminal'])
            require(row['flow_acquire'] is None or row['match_status'] == 'unmatchable')
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
    def __init__(self, phase, version=1):
        require(phase in PHASES)
        require(type(version) is int and version in (1, 2))
        self.version = version
        self.phase, self.rows, self.cursor, self.rounds = phase, {}, 0, 0
        self.armed = self.disarmed = False
        self.joined = True
        self.failed = self.incomplete = False

    def checked(self, binary, control, action, epoch, fingerprints, stopped):
        state, value, joined = query(binary, control, action, epoch, fingerprints, stopped, self.version)
        self.joined &= joined
        expected = dict(arm='armed', clients='observed', providers='observed', disarm='disarmed')[action]
        if state != expected or not joined or value['version'] != self.version:
            self.failed = self.incomplete = True
            return None
        self.incomplete |= value['incomplete']
        return value

    def add(self, client, status, matched=None):
        row = dict(client_phase=client['phase'], client_terminal=client['terminal'], match_status=status,
            provider_role=matched[0] if matched else None, provider_phase=matched[1]['phase'] if matched else None,
            provider_terminal=matched[1]['terminal'] if matched else None)
        if self.version == 2:
            row['flow_acquire'] = client['flow_acquire']
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
        if sum(len(item) for item in self.rows) > MAX_BYTES - 1024:
            self.rows.pop(key, None)
            self.incomplete = True

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
        return validate(dict(version=self.version, kind='private-storage-fixture-correlation', phase=self.phase,
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
    samples, stopped = Samples(phase, version=2), threading.Event()
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


# Schema three is one exact request, not another phase-wide connection epoch.
BUCKETS = ('under_1s', '1_to_5s', '5_to_15s', '15_to_30s', '30_to_60s',
    '60_to_90s', '90_to_120s', 'at_least_120s')
REQUEST_OPERATIONS = ('unobserved', 'reserve', 'append', 'progress', 'finalize', 'read_range', 'renew', 'delete')
PROVIDER_STAGES = ('unobserved', 'request_verified', 'backend_entered', 'backend_returned',
    'receipt_write_entered', 'receipt_flush_returned')
WORKERS = ('unobserved', 'entered', 'returned_ok', 'returned_error')
UNAVAILABLE_REASONS = ('not_started', 'binding', 'arm', 'query', 'missing', 'ambiguous',
    'untargeted_failure', 'ipc', 'deadline', 'cleanup')


def reserve_timing(value):
    if value is None: return
    exact(value, ('before_request_flush_elapsed', 'before_request_flush_remaining',
        'receipt_wait_elapsed', 'receipt_wait_remaining'))
    require(value['before_request_flush_elapsed'] in BUCKETS and value['before_request_flush_remaining'] in BUCKETS)
    require((value['receipt_wait_elapsed'] is None) == (value['receipt_wait_remaining'] is None))
    require(value['receipt_wait_elapsed'] is None or (value['receipt_wait_elapsed'] in BUCKETS
        and value['receipt_wait_remaining'] in BUCKETS))


def request_observation(value, role):
    if value is None:
        require(role == 'provider')
        return
    exact(value, ('request_digest', 'operation', 'provider_stage', 'worker_state',
        'worker_returned_after_terminal', 'reserve_timing'))
    require(value['request_digest'] is None or hexadecimal(value['request_digest'], 64))
    require(value['operation'] in REQUEST_OPERATIONS and value['provider_stage'] in PROVIDER_STAGES
        and value['worker_state'] in WORKERS and type(value['worker_returned_after_terminal']) is bool)
    stage, worker = value['provider_stage'], value['worker_state']
    require(not value['worker_returned_after_terminal'] or worker in ('returned_ok', 'returned_error'))
    require(value['request_digest'] is None or value['operation'] != 'unobserved')
    if role == 'client':
        require(value['operation'] == 'reserve' and stage == 'unobserved' and worker == 'unobserved'
            and value['worker_returned_after_terminal'] is False)
        reserve_timing(value['reserve_timing'])
        require(value['reserve_timing'] is None or value['reserve_timing']['receipt_wait_elapsed'] is None
            or value['request_digest'] is not None)
    else:
        require(value['reserve_timing'] is None)
        require((stage == 'unobserved' and value['operation'] == 'unobserved'
            and value['request_digest'] is None and worker == 'unobserved')
            or (stage != 'unobserved' and value['operation'] != 'unobserved' and value['request_digest'] is not None))
        require(PROVIDER_STAGES.index(stage) < 2 or worker != 'unobserved')
        require(PROVIDER_STAGES.index(stage) < 3 or worker in ('returned_ok', 'returned_error'))
        require(PROVIDER_STAGES.index(stage) < 4 or worker == 'returned_ok')


def request_report(reason='not_started', *, outcome='unavailable', record=None, joined=True, disarmed=False):
    return dict(version=3, kind='private-storage-fixture-correlation', phase='publish', app='image',
        fragment_index=2, copy_index=0, operation='reserve',
        state='observed' if record is not None and reason is None else 'unavailable', reason=reason,
        consumer_outcome=outcome, record=record, sampler_joined=True, children_joined=joined, disarmed=disarmed,
        fragment_copy_binding=record is not None and reason is None, diagnostic_only=True,
        acceptance_evidence=False, causal_attribution=False, remote_cleanup_proven=False,
        observation_scope='single_snapshot_before_disarm', later_worker_completion='unknown')


def validate_request_report(value):
    expected = request_report()
    exact(value, expected)
    for key in ('version', 'kind', 'phase', 'app', 'fragment_index', 'copy_index', 'operation',
            'sampler_joined', 'diagnostic_only', 'acceptance_evidence', 'causal_attribution',
            'remote_cleanup_proven', 'observation_scope', 'later_worker_completion'):
        require(type(value[key]) is type(expected[key]) and value[key] == expected[key])
    require(value['consumer_outcome'] in ('unavailable', 'complete', 'targeted_failure', 'untargeted_failure'))
    require(all(type(value[key]) is bool for key in ('children_joined', 'disarmed', 'fragment_copy_binding')))
    if value['state'] == 'unavailable':
        require(value['reason'] in UNAVAILABLE_REASONS and value['record'] is None
            and value['fragment_copy_binding'] is False)
    else:
        require(value['state'] == 'observed' and value['reason'] is None and value['children_joined']
            and value['disarmed'] and value['fragment_copy_binding']
            and value['consumer_outcome'] in ('complete', 'targeted_failure'))
        row = value['record']
        exact(row, ('client_phase', 'client_terminal', 'provider_role', 'provider_phase', 'provider_terminal',
            'provider_stage', 'worker_state', 'worker_returned_after_terminal', 'reserve_timing'))
        phase_terminal(row['client_phase'], row['client_terminal'], 'client')
        phase_terminal(row['provider_phase'], row['provider_terminal'], 'provider')
        require(row['provider_role'] in ROLES)
        request_observation(dict(request_digest='0' * 64, operation='reserve',
            provider_stage=row['provider_stage'], worker_state=row['worker_state'],
            worker_returned_after_terminal=row['worker_returned_after_terminal'], reserve_timing=None), 'provider')
        require(row['provider_stage'] != 'unobserved')
        require(not row['worker_returned_after_terminal'] or row['provider_terminal'] in ('operation_error', 'cancelled'))
        require(row['worker_state'] not in ('returned_ok', 'returned_error')
            or PROVIDER_STAGES.index(row['provider_stage']) >= 3 or row['worker_returned_after_terminal'])
        reserve_timing(row['reserve_timing'])
    require(len(encoded(value)) <= MAX_BYTES)
    return value


def private_binding(root, incoming):
    """Recheck the exact journal against its signed-manifest/config association."""
    exact(incoming, ('version', 'target', 'provider_index'))
    require(type(incoming['version']) is int and incoming['version'] == 3
        and type(incoming['provider_index']) is int and 0 <= incoming['provider_index'] < 3)
    def read(parts):
        parent = root
        for part in parts[:-1]:
            parent /= part
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700 and parent.resolve() == parent)
        path = parent / parts[-1]
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 65536)
            raw = stream.read(65537)
            after, named = os.fstat(stream.fileno()), path.lstat()
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            require(len(raw) == before.st_size
                and all(getattr(before, key) == getattr(after, key) == getattr(named, key) for key in fields))
        return decode(raw, 65536)
    def key(value):
        require(type(value) is list and len(value) == 32
            and all(type(byte) is int and 0 <= byte <= 255 for byte in value))
        return bytes(value).hex()
    journal = read(('image', 'archive', 'fragment-0002', 'copy-0', 'archive.json'))
    manifest = read(('image', 'archive', 'fragments.json'))['manifest']
    config = read(('image', 'storage.json'))
    require(len(config['providers']) == len(manifest['providers']) == 3 and len(manifest['fragments']) == 4)
    selected = manifest['fragments'][2]['copies'][0]
    index = incoming['provider_index']
    require(type(selected['provider']) is int and selected['provider'] == index
        and key(selected['archive_id']) == key(journal['archive_id'])
        and key(manifest['providers'][index]['key']) == key(journal['provider_key'])
        and config['providers'][index]['key'] == key(journal['provider_key'])
        and len({provider['key'] for provider in config['providers']}) == 3)
    target = dict(archive_id=key(journal['archive_id']), provider_key=key(journal['provider_key']), operation='reserve')
    require(incoming['target'] == target)
    return target, index


def ipc_read(channel, stopped, deadline):
    raw = bytearray()
    with selectors.DefaultSelector() as events:
        events.register(channel, selectors.EVENT_READ)
        while not stopped.is_set() and time.monotonic() < deadline:
            if not events.select(min(.05, max(0, deadline - time.monotonic()))): continue
            block = channel.recv(MAX_REQUEST + 1 - len(raw))
            require(bool(block))
            raw.extend(block)
            require(len(raw) <= MAX_REQUEST)
            if b'\n' in raw:
                require(raw.endswith(b'\n') and raw.count(b'\n') == 1)
                return decode(bytes(raw), MAX_REQUEST)
    raise ValueError('fixture_correlation_invalid')


def ipc_write(channel, value, stopped, deadline):
    raw = memoryview(encoded(value))
    with selectors.DefaultSelector() as events:
        events.register(channel, selectors.EVENT_WRITE)
        while raw and not stopped.is_set() and time.monotonic() < deadline:
            if not events.select(min(.05, max(0, deadline - time.monotonic()))): continue
            count = channel.send(raw)
            require(count > 0)
            raw = raw[count:]
    require(not raw)


class RequestCapture:
    def __init__(self, binary, work, root, deadline):
        self.binary, self.work, self.root, self.deadline = binary, work, root, deadline
        self.parent, self.child = socket.socketpair()
        self.parent.setblocking(False)
        self.stopped = threading.Event()
        self.value = request_report()
        self.thread = threading.Thread(target=self.observe, name='storage-exact-request-observer')

    def checked(self, control, action, epoch, target=None, fingerprints=None):
        try:
            state, value, joined = query(self.binary, control, action, epoch, fingerprints or [],
                threading.Event(), 3, target, self.deadline)
        except Exception:
            self.value['children_joined'] = False
            raise
        self.value['children_joined'] &= joined
        require(joined and state == dict(arm='armed', clients='observed', providers='observed', disarm='disarmed')[action]
            and value is not None and not value['incomplete'])
        return value

    def snapshot(self, controls, epoch, target, index):
        client = self.checked(controls[0], 'clients', epoch, target)['records']
        require(len(client) == 1)
        client = client[0]
        detail = client['request_observation']
        require(detail['operation'] == 'reserve' and detail['request_digest'] is not None)
        matches = []
        for role, control in zip(ROLES, controls[1:]):
            value = self.checked(control, 'providers', epoch, fingerprints=[client['fingerprint']])
            for provider in value['records']:
                observation = provider['request_observation']
                if observation is not None and observation['request_digest'] == detail['request_digest']:
                    require(observation['operation'] == 'reserve')
                    matches.append((role, provider))
        if len(matches) != 1:
            self.value['reason'] = 'ambiguous' if len(matches) > 1 else 'missing'
            return
        role, provider = matches[0]
        require(role == ROLES[index])
        observation = provider['request_observation']
        row = dict(client_phase=client['phase'], client_terminal=client['terminal'], provider_role=role,
            provider_phase=provider['phase'], provider_terminal=provider['terminal'],
            provider_stage=observation['provider_stage'], worker_state=observation['worker_state'],
            worker_returned_after_terminal=observation['worker_returned_after_terminal'], reserve_timing=detail['reserve_timing'])
        self.value.update(reason=None, record=row)

    def observe(self):
        attempted, epoch = [], None
        try:
            self.value['reason'] = 'binding'
            incoming = ipc_read(self.parent, self.stopped, self.deadline)
            target, index = private_binding(self.root, incoming)
            controls, epoch = controls_for(self.work), os.urandom(16).hex()
            self.value['reason'] = 'arm'
            armed = True
            for control in controls:
                attempted.append(control)
                try: self.checked(control, 'arm', epoch, target)
                except Exception: armed = False
            ipc_write(self.parent, dict(version=3, state='armed' if armed else 'unavailable'), self.stopped, self.deadline)
            self.value['reason'] = 'ipc' if armed else 'arm'
            final = ipc_read(self.parent, self.stopped, self.deadline)
            exact(final, ('version', 'outcome'))
            require(type(final['version']) is int and final['version'] == 3
                and final['outcome'] in ('complete', 'targeted_failure', 'untargeted_failure'))
            self.value['consumer_outcome'] = final['outcome']
            if final['outcome'] == 'untargeted_failure': self.value['reason'] = 'untargeted_failure'
            elif armed:
                self.value['reason'] = 'query'
                self.snapshot(controls, epoch, target, index)
        except Exception:
            if time.monotonic() >= self.deadline: self.value['reason'] = 'deadline'
        finally:
            disarmed = []
            for control in attempted:
                try:
                    self.checked(control, 'disarm', epoch)
                    disarmed.append(True)
                except Exception: disarmed.append(False)
            self.value['disarmed'] = len(disarmed) == 4 and all(disarmed)
            if self.value['record'] is not None and not (self.value['children_joined'] and self.value['disarmed']):
                self.value.update(reason='cleanup', record=None)
            self.value['state'] = 'observed' if self.value['record'] is not None else 'unavailable'
            self.value['fragment_copy_binding'] = self.value['state'] == 'observed'
            try:
                ipc_write(self.parent, dict(version=3, state='closed'), self.stopped, self.deadline)
            except Exception: pass
            self.parent.close()


@contextmanager
def capture_request(binary, work, root, deadline):
    observer = None
    try:
        try:
            observer = RequestCapture(binary, work, root, deadline)
            observer.thread.start()
        except Exception:
            if observer is not None:
                observer.parent.close(); observer.child.close()
            observer = None
        yield observer
    finally:
        if observer is not None:
            observer.stopped.set()
            observer.child.close()
            if observer.thread.ident is not None: observer.thread.join()
            observer.parent.close()
        try: publish(root, 'publish', observer.value if observer else request_report('ipc'))
        except Exception: pass


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['validate-stdin']:
            validate(decode(sys.stdin.buffer.read(MAX_BYTES + 1), MAX_BYTES))
            raise SystemExit(0)
        require(len(sys.argv) == 4 and sys.argv[3].isdigit())
        sys.stdout.buffer.write(encoded(read_file(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]))))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise SystemExit(1) from None
