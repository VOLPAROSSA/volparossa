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


def require(condition):
    if not condition:
        raise ValueError('private storage flow coverage invalid')


def records(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BYTES)
    result = []
    for line in raw.splitlines():
        match = re.fullmatch(rb'([0-9]{1,20})\tlevel=([0-9]+)\tevent=([A-Z0-9_]+)\tsession=[0-9a-f]*\tpath=(?:-|[0-9]+)', line)
        require(match is not None)
        timestamp = int(match[1])
        require(0 < timestamp < 2**64 and (not result or timestamp >= result[-1][0]))
        result.append((timestamp, line, match[3]))
    require(0 < len(result) <= LIMIT)
    return result


class Coverage:
    def __init__(self, baseline):
        require(type(baseline) is int and baseline > 0)
        self.baseline = baseline
        self.previous = None
        self.samples = self.observed = self.completed = self.failed = 0

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
        self.completed += sum(t > self.baseline and code == b'MPTCP_EXIT_FLOW_COMPLETED' for t, _, code in added)
        self.failed += sum(t > self.baseline and code == b'MPTCP_EXIT_FLOW_FAILED' for t, _, code in added)
        self.previous = current

    def report(self, joined):
        require(self.previous is not None and type(joined) is bool)
        return dict(event_baseline_unix_ms=self.baseline, exit_log_limit=LIMIT,
            exit_log_records=len(self.previous), exit_log_oldest_unix_ms=self.oldest,
            exit_log_newest_unix_ms=self.previous[-1][0], exit_log_window_covers_baseline=True,
            exit_mptcp_tls_completed=self.completed, exit_mptcp_tls_failed=self.failed,
            exit_log_sampling_version=1, exit_log_samples=self.samples,
            exit_log_observed_records=self.observed, exit_log_overlap_verified=True,
            exit_log_sampler_joined=joined)


def validate_summary(value, baseline, minimum=0):
    require(type(baseline) is int and baseline > 0 and type(minimum) is int and minimum >= 0)
    expected = {'event_baseline_unix_ms', 'exit_log_limit', 'exit_log_records',
        'exit_log_oldest_unix_ms', 'exit_log_newest_unix_ms', 'exit_log_window_covers_baseline',
        'exit_mptcp_tls_completed', 'exit_mptcp_tls_failed', 'exit_log_sampling_version',
        'exit_log_samples', 'exit_log_observed_records', 'exit_log_overlap_verified', 'exit_log_sampler_joined'}
    require(isinstance(value, dict) and set(value) == expected)
    boolean = {'exit_log_window_covers_baseline', 'exit_log_overlap_verified', 'exit_log_sampler_joined'}
    require(all(value[key] is True for key in boolean))
    require(all(type(value[key]) is int and value[key] >= 0 for key in expected - boolean))
    require(value['event_baseline_unix_ms'] == baseline and value['exit_log_limit'] == LIMIT
        and value['exit_log_sampling_version'] == 1 and 2 <= value['exit_log_samples'] <= MAX_SAMPLES
        and 0 < value['exit_log_records'] <= LIMIT
        and value['exit_log_records'] <= value['exit_log_observed_records'] <= MAX_SAMPLES * LIMIT
        and 0 < value['exit_log_oldest_unix_ms'] <= baseline < value['exit_log_newest_unix_ms']
        and minimum <= value['exit_mptcp_tls_completed']
        and value['exit_mptcp_tls_completed'] + value['exit_mptcp_tls_failed'] <= value['exit_log_observed_records'])


@contextmanager
def capture(binary, socket, baseline, minimum):
    """The owner joins every sampler/CLI child before returning its phase result."""
    coverage = Coverage(baseline)
    require(type(minimum) is int and minimum >= 0)
    stopped = threading.Event()
    failures = []

    def sample(timeout=3):
        reply = subprocess.run([str(binary), '--control-socket', str(socket), 'logs', '--limit', str(LIMIT)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True, timeout=timeout)
        coverage.add(reply.stdout)

    sample()  # Establish coverage before starting any owner operation.

    def observe():
        while not stopped.wait(5):
            try:
                sample()
            except (OSError, ValueError, subprocess.SubprocessError):
                failures.append(True)  # No exception text or raw output is retained.
                return

    thread = threading.Thread(target=observe, name='private-storage-exit-flow-sampler')
    thread.start()
    try:
        yield coverage
    finally:
        stopped.set()
        thread.join()  # An in-flight CLI invocation has the explicit three-second bound.
        require(not failures)
        # A successful owner reply can precede the final asynchronous Exit
        # FLOW_COMPLETED. Preserve the original five-second final-drain budget;
        # no new owner operation or weaker flow minimum is introduced. A 200ms
        # poll keeps a 2400s phase plus final drain inside the 512-sample bound.
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            sample(timeout=min(3, remaining))
            if coverage.completed >= minimum:
                break
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            time.sleep(min(0.2, remaining))
        coverage.joined = True


if __name__ == '__main__':
    from pathlib import Path
    import sys
    try:
        require(len(sys.argv) == 5 and sys.argv[1] == 'check')
        path = Path(sys.argv[2])
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8192)
        value = json.loads(path.read_bytes())
        validate_summary(value, int(sys.argv[3]), int(sys.argv[4]))
        print(json.dumps(value, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError):
        print('private storage flow coverage invalid', file=sys.stderr)
        sys.exit(1)
