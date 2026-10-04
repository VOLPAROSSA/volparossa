#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded, continuously covered Exit flow counts; never retain raw logs on disk.

Reuses the joined-thread sampler pattern from agent-public-collection-smoke.py,
but unlike its diagnostic lower bounds, missing/changed overlap is fatal here.
"""
from contextlib import contextmanager
import json
import re
import subprocess
import threading
import time

LIMIT = 1000
MAX_SAMPLES = 512
MAX_BYTES = 262144
MAX_CONTEXTS = 8


class SamplerFailure(ValueError):
    """Only a fixed observation stage/code; never raw CLI errors or route data."""


def context_id(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value) and value != '0' * 32)
    return value


def route_scope(selected):
    """Identity projection only; the committed path snapshot is not flow proof."""
    context = context_id(selected['route_context_id'])
    paths, slots = selected['paths'], selected['benchmark_slots']
    require(selected['transport'] == 'mptcp' and len(paths) == len(slots) == 2)
    require(len({p['path_id'] for p in paths}) == len({p['relay_peer_id'] for p in paths}) == 2)
    require(selected['exact_selected_relays'] == [p['relay_peer_id'] for p in paths])
    projected = []
    for path, slot in zip(paths, slots):
        require(path['route_context_id'] == context and path['exit_peer_id'] == selected['exact_selected_exit']
            and type(path['path_id']) is int and 1 <= path['path_id'] <= 8 and path['state'] in (1, 2, 3, 4)
            and slot['path_id'] == path['path_id'] and slot['relay_peer_id'] == path['relay_peer_id'])
        projected.append(dict(path_id=path['path_id'], relay_peer_id=path['relay_peer_id']))
    value = dict(exit_peer_id=selected['exact_selected_exit'], paths=projected)
    validate_route_scope(value)
    return value


def validate_route_scope(scope):
    require(isinstance(scope, dict) and set(scope) == {'exit_peer_id', 'paths'}
        and isinstance(scope['paths'], list) and len(scope['paths']) == 2)
    require(all(isinstance(p, dict) and set(p) == {'path_id', 'relay_peer_id'}
        and type(p['path_id']) is int and 1 <= p['path_id'] <= 8 for p in scope['paths']))
    require(len({p['path_id'] for p in scope['paths']}) == len({p['relay_peer_id'] for p in scope['paths']}) == 2)
    require(all(isinstance(peer, str) and re.fullmatch('[A-Za-z0-9_-]{1,128}', peer)
        for peer in [scope['exit_peer_id'], *(p['relay_peer_id'] for p in scope['paths'])]))


def selected_context(raw, scope):
    require(isinstance(raw, bytes) and len(raw) <= 65536)
    if not raw.strip():
        return None  # A retirement gap authorizes/counts no context.
    paths, contexts = [], set()
    for line in raw.splitlines():
        match = re.fullmatch(rb'context=([0-9a-f]{32}) path=([1-8]) relay=([A-Za-z0-9_-]{1,128}) '
            rb'exit=([A-Za-z0-9_-]{1,128}) state=([1-4]) rtt_us=[0-9]+ bytes=[0-9]+(?: acked_transport_bytes=[0-9]+)?', line)
        require(match is not None)
        contexts.add(context_id(match[1].decode()))
        require(match[4].decode() == scope['exit_peer_id'])
        paths.append(dict(path_id=int(match[2]), relay_peer_id=match[3].decode()))
    require(len(contexts) == 1 and sorted(paths, key=lambda p: p['path_id']) == scope['paths'])
    return contexts.pop()


def require(condition):
    if not condition:
        raise ValueError('private storage flow coverage invalid')


def records(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BYTES)
    result = []
    for line in raw.splitlines():
        match = re.fullmatch(rb'([0-9]{1,20})\tlevel=([0-9]+)\tevent=([A-Z0-9_]+)\tsession=([0-9a-f]*)\tpath=(?:-|[0-9]+)', line)
        require(match is not None)
        timestamp = int(match[1])
        require(0 < timestamp < 2**64 and (not result or timestamp >= result[-1][0]))
        result.append((timestamp, line, match[3], match[4]))
    require(0 < len(result) <= LIMIT)
    return result


class Coverage:
    def __init__(self, baseline, scope=None):
        require(type(baseline) is int and baseline > 0)
        self.baseline = baseline
        self.previous = None
        self.samples = self.observed = self.completed = self.failed = 0
        if scope is not None:
            validate_route_scope(scope)
        self.scope, self.contexts, self.observed_contexts = scope, {}, set()
        self.current_context = None

    def route(self, raw):
        require(self.scope is not None)
        context = selected_context(raw, self.scope)
        self.current_context = context
        if context is not None:
            self.observed_contexts.add(context)
            require(len(self.observed_contexts) <= MAX_CONTEXTS)

    def add(self, raw):
        current = records(raw)
        require(self.samples < MAX_SAMPLES)
        # A saturated window of indistinguishable same-millisecond records has
        # no observable overlap boundary. Refuse rather than guess multiplicity.
        require(len(current) < LIMIT or current[0][0] < current[-1][0])
        if self.previous is None:
            require(current[0][0] <= self.baseline)
            self.oldest = current[0][0]
            added = current
        elif current == self.previous:
            added = []
        elif current[:len(self.previous)] == self.previous:
            added = current[len(self.previous):]  # No eviction, including equal timestamps.
        else:
            # The first current timestamp may be a partially evicted group.
            # Require an older group before the previous tail, then compare every
            # complete overlapping record in order, including duplicate codes in
            # one millisecond. A gap or a changed event cannot inflate totals.
            first, tail = current[0][0], self.previous[-1][0]
            require(self.previous[0][0] <= first < tail <= current[-1][0])
            known = [item for item in self.previous if item[0] > first]
            overlap = [item for item in current if first < item[0] <= tail]
            require(overlap[:len(known)] == known)
            appended_tail = overlap[len(known):]
            require(all(item[0] == tail for item in appended_tail))
            added = appended_tail + [item for item in current if item[0] > tail]
        self.samples += 1
        self.observed += len(added)
        require(self.observed <= MAX_SAMPLES * LIMIT)
        for stamp, _, code, context in added:
            if self.scope is not None and stamp > self.baseline:
                require(code not in (b'MPTCP_EXIT_FLOW_OWNER_MISSING', b'MPTCP_EXIT_FLOW_SCOPE_MISMATCH'))
            if stamp <= self.baseline or code not in (b'MPTCP_EXIT_FLOW_COMPLETED', b'MPTCP_EXIT_FLOW_FAILED'):
                continue
            succeeded = code == b'MPTCP_EXIT_FLOW_COMPLETED'
            self.completed += int(succeeded)
            self.failed += int(not succeeded)
            if self.scope is not None:
                identifier = context_id(context.decode())
                counts = self.contexts.setdefault(identifier, dict(completed=0, failed=0))
                counts['completed' if succeeded else 'failed'] += 1
                require(len(self.contexts) <= MAX_CONTEXTS)
        self.previous = current

    def report(self, joined):
        require(self.previous is not None and type(joined) is bool)
        result = dict(event_baseline_unix_ms=self.baseline, exit_log_limit=LIMIT,
            exit_log_records=len(self.previous), exit_log_oldest_unix_ms=self.oldest,
            exit_log_newest_unix_ms=self.previous[-1][0], exit_log_window_covers_baseline=True,
            exit_mptcp_tls_completed=self.completed, exit_mptcp_tls_failed=self.failed,
            exit_log_sampling_version=1, exit_log_samples=self.samples,
            exit_log_observed_records=self.observed, exit_log_overlap_verified=True,
            exit_log_sampler_joined=joined)
        if self.scope is not None:
            result.update(exit_log_sampling_version=2, exit_route_scope=self.scope,
                observed_route_context_ids=sorted(self.observed_contexts),
                exit_flow_contexts=[dict(route_context_id=context, **counts) for context, counts in sorted(self.contexts.items())])
        return result


def validate_summary(value, baseline, minimum=0):
    require(type(baseline) is int and baseline > 0 and type(minimum) is int and minimum >= 0)
    require(isinstance(value, dict))
    expected = {'event_baseline_unix_ms', 'exit_log_limit', 'exit_log_records',
        'exit_log_oldest_unix_ms', 'exit_log_newest_unix_ms', 'exit_log_window_covers_baseline',
        'exit_mptcp_tls_completed', 'exit_mptcp_tls_failed', 'exit_log_sampling_version',
        'exit_log_samples', 'exit_log_observed_records', 'exit_log_overlap_verified', 'exit_log_sampler_joined'}
    contextual = value.get('exit_log_sampling_version') == 2
    extra = {'exit_route_scope', 'observed_route_context_ids', 'exit_flow_contexts'} if contextual else set()
    require(isinstance(value, dict) and set(value) == expected | extra)
    boolean = {'exit_log_window_covers_baseline', 'exit_log_overlap_verified', 'exit_log_sampler_joined'}
    require(all(value[key] is True for key in boolean))
    require(all(type(value[key]) is int and value[key] >= 0 for key in expected - boolean))
    require(value['event_baseline_unix_ms'] == baseline and value['exit_log_limit'] == LIMIT
        and value['exit_log_sampling_version'] in (1, 2) and 2 <= value['exit_log_samples'] <= MAX_SAMPLES
        and 0 < value['exit_log_records'] <= LIMIT
        and value['exit_log_records'] <= value['exit_log_observed_records'] <= MAX_SAMPLES * LIMIT
        and 0 < value['exit_log_oldest_unix_ms'] <= baseline < value['exit_log_newest_unix_ms']
        and minimum <= value['exit_mptcp_tls_completed']
        and value['exit_mptcp_tls_completed'] + value['exit_mptcp_tls_failed'] <= value['exit_log_observed_records'])
    if contextual:
        validate_route_scope(value['exit_route_scope'])
        observed, flows = value['observed_route_context_ids'], value['exit_flow_contexts']
        require(isinstance(observed, list) and 1 <= len(observed) <= MAX_CONTEXTS
            and observed == sorted(set(observed)) and all(context_id(c) for c in observed))
        require(isinstance(flows, list) and 1 <= len(flows) <= MAX_CONTEXTS)
        for flow in flows:
            require(isinstance(flow, dict) and set(flow) == {'route_context_id', 'completed', 'failed'}
                and context_id(flow['route_context_id']) in observed
                and type(flow['completed']) is type(flow['failed']) is int
                and flow['completed'] >= 0 and flow['failed'] >= 0 and flow['completed'] + flow['failed'] > 0)
        ids = [flow['route_context_id'] for flow in flows]
        require(ids == sorted(set(ids)) and sum(f['completed'] for f in flows) == value['exit_mptcp_tls_completed']
            and sum(f['failed'] for f in flows) == value['exit_mptcp_tls_failed'])


def validate_phase_route(initial_scope, selected, gates):
    validate_summary(gates, gates['event_baseline_unix_ms'])
    require(gates['exit_log_sampling_version'] == 2 and route_scope(selected) == initial_scope == gates['exit_route_scope'])
    # Matching identities alone are not success: the final committed context
    # must have actual post-baseline Exit flow completion, never only old counts.
    require(any(flow['route_context_id'] == selected['route_context_id'] and flow['completed'] > 0
        for flow in gates['exit_flow_contexts']))


@contextmanager
def capture(binary, socket, baseline, minimum, *, client=None, scope=None, diagnostic=None):
    """The owner joins every sampler/CLI child before returning its phase result."""
    require((client is None) == (scope is None))
    coverage = Coverage(baseline, scope)
    require(type(minimum) is int and minimum >= 0)
    stopped = threading.Event()
    failures = []

    def failed(phase, operation, code):
        if diagnostic is not None and not diagnostic:
            diagnostic.update(phase=phase, operation=operation, code=code,
                samples=coverage.samples, completed=coverage.completed, failed=coverage.failed)
        return SamplerFailure('private storage sampler failed')

    def sample(timeout=3, phase='initial'):
        operation = 'route_query' if client is not None else 'exit_log_query'
        try:
            deadline = time.monotonic() + timeout
            if client is not None:
                snapshot = subprocess.run([str(binary), '--control-socket', str(client), 'paths'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    check=True, timeout=timeout)
                operation = 'route_scope'
                coverage.route(snapshot.stdout)
            operation = 'exit_log_query'
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            reply = subprocess.run([str(binary), '--control-socket', str(socket), 'logs', '--limit', str(LIMIT)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                check=True, timeout=remaining)
            operation = 'coverage'
            coverage.add(reply.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            code = ('timeout' if isinstance(error, subprocess.TimeoutExpired) else
                    'process' if isinstance(error, subprocess.SubprocessError) else
                    'local_io' if isinstance(error, OSError) else 'invalid')
            raise failed(phase, operation, code) from None

    sample()  # Establish coverage before starting any owner operation.

    def observe():
        while not stopped.wait(5):
            try:
                sample(phase='sampling')
            except SamplerFailure as error:
                failures.append(error)  # Only the fixed closed failure, never raw output.
                return

    thread = threading.Thread(target=observe, name='private-storage-exit-flow-sampler')
    thread.start()
    owner_failed = False
    try:
        yield coverage
    except BaseException:
        owner_failed = True
        raise
    finally:
        stopped.set()
        thread.join()  # An in-flight CLI invocation has the explicit three-second bound.
        # A successful owner reply can precede the final asynchronous Exit
        # FLOW_COMPLETED. Preserve the original five-second final-drain budget;
        # no new owner operation or weaker flow minimum is introduced. A 200ms
        # poll keeps a 2400s phase plus final drain inside the 512-sample bound.
        try:
            if failures:
                raise failures[0]
            deadline = time.monotonic() + 5
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise failed('final_drain', 'completion', 'deadline')
                sample(timeout=min(3, remaining), phase='final_drain')
                current_completed = coverage.scope is None or coverage.contexts.get(
                    coverage.current_context, {}).get('completed', 0) > 0
                if coverage.completed >= minimum and current_completed:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise failed('final_drain', 'completion', 'deadline')
                time.sleep(min(0.2, remaining))
            coverage.joined = True
        except SamplerFailure:
            if not owner_failed:
                raise


if __name__ == '__main__':
    from pathlib import Path
    import sys
    try:
        if len(sys.argv) == 5 and sys.argv[1] == 'route-check':
            inputs = []
            for name in sys.argv[2:]:
                path = Path(name)
                require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536)
                inputs.append(json.loads(path.read_bytes()))
            scope, selected, gates = inputs
            validate_phase_route(scope['route_scope'], selected, gates)
            sys.exit(0)
        require(len(sys.argv) == 5 and sys.argv[1] == 'check')
        path = Path(sys.argv[2])
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8192)
        value = json.loads(path.read_bytes())
        validate_summary(value, int(sys.argv[3]), int(sys.argv[4]))
        print(json.dumps(value, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError):
        print('private storage flow coverage invalid', file=sys.stderr)
        sys.exit(1)
