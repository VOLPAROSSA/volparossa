#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Consumer-only context observations, paired with actual Exit flow completions.

Unlike the historical fixed-layout sampler, a NEW context may use a different
pair of the original three physical relays. It never changes an observed
context's exact path-ID mapping. A bracketed live Paths/status/Paths observation,
not a log line or union of peer names, admits each mapping. Periodic observation
does not prove unseen contexts: every counted flow must join an observed one.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import re
import runpy
import subprocess
import threading
import time

OLD = runpy.run_path(str(Path(__file__).with_name('private-storage-log-sampler.py')))
require = OLD['require']
BROKERS = ('relay0', 'relay1', 'relay2')
MAX_REPLY = 65536
PHASES = ('initial', 'sampling', 'final_drain')
OPERATIONS = ('paths_before', 'control_status', 'paths_after', 'route_binding',
    'exit_log_query', 'coverage', 'completion')
CODES = ('timeout', 'process', 'local_io', 'invalid', 'deadline')


class SampleDeadline(ValueError):
    """The same single sample budget, including parsing, was exhausted."""


def before_deadline(deadline):
    if time.monotonic() >= deadline:
        raise SampleDeadline('consumer sample deadline')


def validate_policy(value):
    require(type(value) is dict and set(value) == {'exit_peer_id', 'relay_peers'}
        and type(value['relay_peers']) is dict and set(value['relay_peers']) == set(BROKERS))
    peers = [value['exit_peer_id'], *value['relay_peers'].values()]
    require(all(type(p) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', p) for p in peers)
        and len(set(peers)) == 4)


def path_observation(raw, policy):
    validate_policy(policy)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_REPLY)
    paths = []
    for line in raw.splitlines():
        match = re.fullmatch(rb'context=([0-9a-f]{32}) path=([1-8]) relay=([A-Za-z0-9_-]{1,128}) '
            rb'exit=([A-Za-z0-9_-]{1,128}) state=([0-9]+) rtt_us=[0-9]+ bytes=[0-9]+(?: acked_transport_bytes=[0-9]+)?', line)
        require(match is not None)
        paths.append(dict(path_id=int(match[2]), relay_peer_id=match[3].decode()))
    # The historical exact parser still checks nonzero/single context, two
    # unique path IDs/relays, allowed states and the exact unchanged Exit.
    scope = dict(exit_peer_id=policy['exit_peer_id'], paths=sorted(paths, key=lambda p: p['path_id']))
    OLD['validate_route_scope'](scope)
    require(all(p['relay_peer_id'] in policy['relay_peers'].values() for p in paths))
    context = OLD['selected_context'](raw, scope)
    require(context is not None)  # Retirement/busy is a failed observation, not a retry.
    return context, scope


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def control_observation(raw, policy):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_REPLY)
    value = json.loads(raw, object_pairs_hook=unique)
    # ContentReceipt has other unrelated local-service fields. Only this actual
    # route-controller field is retained; no payload, endpoint or log is copied.
    require(type(value) is dict and type(value.get('control_relay_peer_id')) is str)
    peer = value['control_relay_peer_id']
    require(peer in policy['relay_peers'].values())
    return peer


def validate_route(value, policy):
    require(type(value) is dict and set(value) == {'route_context_id', 'control_relay_peer_id', 'scope'})
    OLD['context_id'](value['route_context_id'])
    OLD['validate_route_scope'](value['scope'])
    require(value['scope']['exit_peer_id'] == policy['exit_peer_id']
        and value['control_relay_peer_id'] in policy['relay_peers'].values()
        and all(p['relay_peer_id'] in policy['relay_peers'].values() for p in value['scope']['paths'])
        and value['control_relay_peer_id'] not in {p['relay_peer_id'] for p in value['scope']['paths']})


class Coverage(OLD['Coverage']):
    def __init__(self, baseline, policy):
        validate_policy(policy)
        self.policy = json.loads(json.dumps(policy))
        self.route_bindings = {}
        # Parent uses this solely to enable its unchanged bounded context-aware
        # Exit log accounting. It is replaced by the first actual observation
        # before any owner operation is allowed and is never exported as proof.
        super().__init__(baseline, dict(exit_peer_id=policy['exit_peer_id'], paths=[
            dict(path_id=i + 1, relay_peer_id=policy['relay_peers'][role])
            for i, role in enumerate(BROKERS[:2])]))

    def route(self, before, status, after):
        left, right = path_observation(before, self.policy), path_observation(after, self.policy)
        require(left == right)
        context, scope = left
        broker = control_observation(status, self.policy)
        binding = dict(route_context_id=context, control_relay_peer_id=broker, scope=scope)
        validate_route(binding, self.policy)
        if context in self.route_bindings:
            require(self.route_bindings[context] == binding)
        else:
            require(len(self.route_bindings) < OLD['MAX_CONTEXTS'])
            self.route_bindings[context] = binding
        self.current_context = context
        self.observed_contexts.add(context)
        self.scope = scope

    def report(self, joined):
        value = super().report(joined)
        value.pop('exit_route_scope')
        value.pop('observed_route_context_ids')
        value.update(exit_log_sampling_version=3, exit_route_policy=self.policy,
            observed_context_routes=[self.route_bindings[c] for c in sorted(self.route_bindings)])
        return value


def validate_summary(value, baseline, minimum=0):
    require(type(value) is dict and type(value.get('exit_log_sampling_version')) is int
        and value['exit_log_sampling_version'] == 3)
    policy, routes = value.get('exit_route_policy'), value.get('observed_context_routes')
    validate_policy(policy)
    require(type(routes) is list and 1 <= len(routes) <= OLD['MAX_CONTEXTS'])
    for route in routes:
        validate_route(route, policy)
    ids = [r['route_context_id'] for r in routes]
    require(ids == sorted(set(ids)))
    # Reuse every historical overlap/count/limit/flow-context requirement.
    # The new exact route records above replace only its single static scope.
    old = dict(value)
    old.pop('exit_route_policy'); old.pop('observed_context_routes')
    old.update(exit_log_sampling_version=2, exit_route_scope=routes[0]['scope'], observed_route_context_ids=ids)
    OLD['validate_summary'](old, baseline, minimum)


def validate_phase_route(policy, selected, gates):
    validate_summary(gates, gates['event_baseline_unix_ms'])
    require(gates['exit_route_policy'] == policy)
    scope = OLD['route_scope'](selected)
    context = selected['route_context_id']
    require(any(r['route_context_id'] == context and r['scope'] == scope
        for r in gates['observed_context_routes']))
    require(any(f['route_context_id'] == context and f['completed'] > 0 for f in gates['exit_flow_contexts']))


def validate_diagnostic(value):
    require(type(value) is dict and set(value) == {'version', 'kind', 'phase', 'operation', 'code',
        'samples', 'completed', 'failed'} and type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'consumer-route-sampler-failure' and value['phase'] in PHASES
        and value['operation'] in OPERATIONS and value['code'] in CODES)
    require(all(type(value[k]) is int and 0 <= value[k] <= OLD['MAX_SAMPLES'] * OLD['LIMIT']
        for k in ('samples', 'completed', 'failed')) and value['samples'] <= OLD['MAX_SAMPLES'])


@contextmanager
def capture(binary, socket, baseline, minimum, *, client, policy, diagnostic=None):
    """Same 3s sample, 5s cadence/drain, limits and owned joins; no RPC retry."""
    coverage = Coverage(baseline, policy)
    require(type(minimum) is int and minimum >= 0)
    stopped, failures = threading.Event(), []

    def failed(phase, operation, code):
        value = dict(version=1, kind='consumer-route-sampler-failure', phase=phase,
            operation=operation, code=code, samples=coverage.samples,
            completed=coverage.completed, failed=coverage.failed)
        validate_diagnostic(value)
        if diagnostic is not None and not diagnostic:
            diagnostic.update(value)
        return OLD['SamplerFailure']('consumer route sampler failed')

    def sample(timeout=3, phase='initial'):
        operation = 'paths_before'
        deadline = time.monotonic() + timeout
        def query(endpoint, args, maximum):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SampleDeadline('consumer sample deadline')
            reply = subprocess.run([str(binary), '--control-socket', str(endpoint), *args],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                check=True, timeout=remaining)
            before_deadline(deadline)
            require(type(reply.stdout) is bytes and len(reply.stdout) <= maximum)
            return reply.stdout
        try:
            before = query(client, ['paths'], MAX_REPLY)
            operation = 'control_status'
            status = query(client, ['content', 'status'], MAX_REPLY)
            operation = 'paths_after'
            after = query(client, ['paths'], MAX_REPLY)
            operation = 'route_binding'
            coverage.route(before, status, after)
            operation = 'exit_log_query'
            raw = query(socket, ['logs', '--limit', str(OLD['LIMIT'])], OLD['MAX_BYTES'])
            operation = 'coverage'
            coverage.add(raw)
            before_deadline(deadline)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError) as error:
            code = ('deadline' if isinstance(error, SampleDeadline) else
                'timeout' if isinstance(error, subprocess.TimeoutExpired) else
                'process' if isinstance(error, subprocess.SubprocessError) else
                'local_io' if isinstance(error, OSError) else 'invalid')
            raise failed(phase, operation, code) from None

    sample()
    def observe():
        while not stopped.wait(5):
            try: sample(phase='sampling')
            except OLD['SamplerFailure'] as error:
                failures.append(error)
                return
    thread = threading.Thread(target=observe, name='consumer-exit-flow-sampler')
    thread.start()
    owner_failed = False
    try:
        yield coverage
    except BaseException:
        owner_failed = True
        raise
    finally:
        stopped.set()
        thread.join()
        try:
            if failures: raise failures[0]
            deadline = time.monotonic() + 5
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise failed('final_drain', 'completion', 'deadline')
                sample(timeout=min(3, remaining), phase='final_drain')
                if coverage.completed >= minimum and coverage.contexts.get(coverage.current_context, {}).get('completed', 0) > 0:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise failed('final_drain', 'completion', 'deadline')
                time.sleep(min(0.2, remaining))
            try:
                validate_summary(coverage.report(True), baseline, minimum)
            except (ValueError, TypeError, KeyError):
                raise failed('final_drain', 'coverage', 'invalid') from None
            coverage.joined = True
        except (OLD['SamplerFailure'], ValueError):
            if not owner_failed: raise
