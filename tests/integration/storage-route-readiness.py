#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only actor observation before maintenance Connect, inside its existing deadline.

A sampled advertisement slate is not a selected, probed or established route. This
helper never invokes Connect, reads the advertisement database or chooses a peer.
"""
import json
import selectors
import subprocess
import sys
import time

MAX_REPLY = 2048
QUERY_SECONDS = 5
OUTCOMES = frozenset(('eligible_advertisement_slate', 'incomplete_snapshot',
    'no_eligible_exit_pair', 'insufficient_diverse_relays', 'observation_unavailable'))
FIELDS = frozenset(('schema_version', 'scope', 'transport', 'captured_at_unix_ms',
    'outcome', 'eligible_slate_observed', 'dataplane_verified', 'route_selected'))


def require(condition):
    if not condition:
        raise ValueError('invalid closed advertisement observation')


def unique_fields(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def checked_reply(raw, started_ms, completed_ms):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_REPLY)
    value = json.loads(raw, object_pairs_hook=unique_fields)
    require(isinstance(value, dict) and set(value) == FIELDS)
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['scope'] == 'advertisement_preselection' and value['transport'] == 'mptcp')
    require(type(value['captured_at_unix_ms']) is int
        and 0 < started_ms <= value['captured_at_unix_ms'] <= completed_ms)
    require(isinstance(value['outcome'], str) and value['outcome'] in OUTCOMES)
    require(type(value['eligible_slate_observed']) is bool
        and value['eligible_slate_observed'] == (value['outcome'] == 'eligible_advertisement_slate')
        and value['dataplane_verified'] is False and value['route_selected'] is False)
    return value


def bounded_query(command, seconds):
    """Bound bytes and wall time; kill/reap only this exact CLI child on failure.

    The CLI does not spawn descendants. No stderr or raw reply is exported or
    retained on disk. Nonzero results, including policy refusals, are terminal.
    """
    deadline = time.monotonic() + seconds
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                raw = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None, 'query_timeout'
                    events = selector.select(remaining)
                    if not events:
                        return None, 'query_timeout'
                    chunk = child.stdout.read1(min(4096, MAX_REPLY + 1 - len(raw)))
                    if not chunk:
                        try:
                            status = child.wait(timeout=max(0, deadline - time.monotonic()))
                        except subprocess.TimeoutExpired:
                            return None, 'query_timeout'
                        return (bytes(raw), None) if status == 0 else (None, 'query_rejected')
                    raw.extend(chunk)
                    if len(raw) > MAX_REPLY:
                        return None, 'reply_oversize'
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()


def observe_until(binary, socket, deadline_epoch, *, query=bounded_query,
                  wall=time.time, monotonic=time.monotonic, sleep=time.sleep):
    remaining = deadline_epoch - wall()
    # Never create another 600-second window: consume the selector's existing one.
    require(type(deadline_epoch) is int and 0 < remaining <= 600)
    deadline = monotonic() + remaining
    summary = dict(schema_version=1, scope='advertisement_preselection', polls=0,
        last_outcome=None, eligible_slate_observed=False, dataplane_verified=False,
        route_selected=False, result='deadline_exhausted')
    command = [binary, '--control-socket', socket, 'route-readiness', '--transport', 'mptcp']
    while True:
        remaining = min(deadline - monotonic(), deadline_epoch - wall())
        if remaining <= 0:
            break
        started_ms = int(wall() * 1000)
        summary['polls'] += 1
        raw, failure = query(command, min(QUERY_SECONDS, remaining))
        if failure is not None:
            require(failure in ('query_timeout', 'query_rejected', 'reply_oversize'))
            summary['result'] = failure
            break
        try:
            value = checked_reply(raw, started_ms, int(wall() * 1000))
        except (ValueError, TypeError, UnicodeError):
            summary['result'] = 'invalid_observation'
            break
        summary['last_outcome'] = value['outcome']
        if monotonic() >= deadline or wall() >= deadline_epoch:
            break
        if value['eligible_slate_observed']:
            summary['eligible_slate_observed'] = True
            summary['result'] = 'eligible_slate_observed'
            break
        sleep(max(0, min(1, deadline - monotonic(), deadline_epoch - wall())))
    return summary


def main():
    try:
        require(len(sys.argv) == 4)
        value = observe_until(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    except (OSError, ValueError, TypeError):
        # No private paths, raw exceptions or subprocess output in diagnostic JSON.
        value = dict(schema_version=1, scope='advertisement_preselection', polls=0,
            last_outcome=None, eligible_slate_observed=False, dataplane_verified=False,
            route_selected=False, result='observation_failed')
    print(json.dumps(value, separators=(',', ':')))
    return 0 if value['eligible_slate_observed'] else 1


if __name__ == '__main__':
    sys.exit(main())
