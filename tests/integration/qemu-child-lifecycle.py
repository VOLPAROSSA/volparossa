#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded Linux-only shutdown of the VM runner's one original QEMU child.

The shell retains wait/reap ownership. This helper only confirms exit through a
pidfd; it never sends a signal through a numerical PID or manages other children.
The private birth token is recorded immediately after launch, never exported.
"""
import math
import os
from pathlib import Path
import select
import signal
import sys
import time

GRACE_SECONDS = 30
TERM_SECONDS = 5
KILL_SECONDS = 5
BIRTH_SECONDS = 2


def positive(value):
    if not value.isascii() or not value.isdecimal() or not 0 < int(value) < 2 ** 63:
        raise ValueError('identity')
    return int(value)


def identity(pid):
    # procfs is local kernel state, not a caller-chosen path. Bound its read and
    # parse after the final ')' because process comm may itself contain spaces.
    with (Path('/proc') / str(pid) / 'stat').open('rb') as source:
        if os.fstat(source.fileno()).st_uid != os.geteuid():
            raise ValueError('owner')
        raw = source.read(4097)
    if len(raw) > 4096:
        raise ValueError('identity')
    prefix, separator, tail = raw.rpartition(b') ')
    fields = tail.split()
    if not separator or not prefix.startswith(str(pid).encode() + b' (') or len(fields) < 20:
        raise ValueError('identity')
    return int(fields[1]), int(fields[19])


def preflight():
    # Probe the actual kernel API before starting QEMU. Signal 0 observes only
    # our own helper; there is deliberately no kill(2) fallback.
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise ValueError('pidfd')
    descriptor = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(descriptor, 0)
    finally:
        os.close(descriptor)


def qemu_command(pid):
    # The source-owned launch has this exact fixed name/flags sequence. Also
    # accept its reviewed loader/wrapper prefix, not an arbitrary sibling that
    # reused the PID before the first birth read. Private argv never leaves here.
    with (Path('/proc') / str(pid) / 'cmdline').open('rb') as source:
        raw = source.read(32769)
    if not raw.endswith(b'\0') or len(raw) > 32768:
        raise ValueError('command')
    args = raw[:-1].split(b'\0')
    marker = [b'-name', b'volparossa-alpha-topology', b'-no-user-config', b'-nodefaults']
    if not any(value.rsplit(b'/', 1)[-1] == b'qemu-system-x86_64' for value in args[:8]) \
            or not any(args[index:index + len(marker)] == marker for index in range(len(args))):
        raise ValueError('command')


def birth(pid, parent):
    observed_parent, started = identity(pid)
    if observed_parent != parent or started <= 0:
        raise ValueError('parent')
    expected, deadline = (parent, started), time.monotonic() + BIRTH_SECONDS
    while True:
        if identity(pid) != expected:
            raise ValueError('changed_identity')
        try:
            qemu_command(pid)
            ready = True
        except ValueError:
            ready = False
        if identity(pid) != expected:
            raise ValueError('changed_identity')
        # A forked shell may not have exec'd the fixed command yet. Wait only
        # for that original identity, never adopt a later PID/start-time pair.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('command')
        if ready:
            return started
        time.sleep(min(.01, remaining))


def exited(descriptor, seconds):
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP)
    deadline = time.monotonic() + seconds
    while True:
        remaining = max(0, deadline - time.monotonic())
        events = poller.poll(math.ceil(remaining * 1000))
        for actual, mask in events:
            if actual != descriptor or mask & (select.POLLERR | select.POLLNVAL):
                raise ValueError('pidfd')
            if mask & (select.POLLIN | select.POLLHUP):
                return True
        if time.monotonic() >= deadline:
            return False


def stop(pid, parent, started, *, graceful):
    expected = parent, started
    try:
        if identity(pid) != expected:
            raise ValueError('changed_identity')
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return True
    except FileNotFoundError:
        return True
    try:
        # Bind the opened descriptor and the earlier private birth token. Even
        # if the original child exits here, no recycled/foreign PID is signalled.
        try:
            if identity(pid) != expected:
                raise ValueError('changed_identity')
        except (ProcessLookupError, FileNotFoundError):
            return exited(descriptor, KILL_SECONDS)
        if exited(descriptor, GRACE_SECONDS if graceful else 0):
            return True
        for selected, seconds in ((signal.SIGTERM, TERM_SECONDS), (signal.SIGKILL, KILL_SECONDS)):
            try:
                signal.pidfd_send_signal(descriptor, selected)
            except ProcessLookupError:
                pass  # Confirm termination through the same pidfd below.
            if exited(descriptor, seconds):
                return True
        return False
    finally:
        os.close(descriptor)


def main(args):
    if args == ['preflight']:
        preflight()
        return 0
    if len(args) == 3 and args[0] == 'birth':
        print(birth(positive(args[1]), positive(args[2])))
        return 0
    if len(args) == 5 and args[0] == 'stop' and args[4] in ('normal', 'abort'):
        return 0 if stop(*(positive(value) for value in args[1:4]), graceful=args[4] == 'normal') else 1
    raise ValueError('arguments')


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (AttributeError, OSError, OverflowError, TypeError, ValueError, KeyboardInterrupt):
        print('QEMU child lifecycle could not be confirmed', file=sys.stderr)
        raise SystemExit(1)
