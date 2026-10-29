#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only parent-host equality receipt for the explicit hosted GPSD trial."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def output(argv):
    deadline = time.monotonic() + 10
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    captured = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in (child.stdout, child.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('host observer deadline')
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.fileobj is child.stderr or len(captured) + len(chunk) > 4 * 1024 * 1024:
                        raise ValueError('host observer exceeded bounds or reported an error')
                    captured.extend(chunk)
        if child.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise ValueError('host observer failed')
        return bytes(captured)
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=1)
        child.stdout.close()
        child.stderr.close()


def read_bounded(path, maximum):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('host observation file bound')
    return raw


def firewall_configuration(raw):
    value = json.loads(raw)
    def configuration(item):
        if isinstance(item, list):
            return [configuration(child) for child in item]
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if key == 'counter' and isinstance(child, dict):
                    # nftables packet/byte counts are live observations, not rules.
                    child = {name: number for name, number in child.items()
                             if name not in {'packets', 'bytes'}}
                result[key] = configuration(child)
            return result
        return item
    return sha(json.dumps(configuration(value), sort_keys=True, separators=(',', ':')).encode())


def observe(destination):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() == 0):
        raise ValueError('explicit nonroot disposable hosted observer required')
    ip = '/usr/sbin/ip' if Path('/usr/sbin/ip').is_file() else '/usr/bin/ip'
    nft = '/usr/sbin/nft' if Path('/usr/sbin/nft').is_file() else '/usr/bin/nft'
    sysctls = {}
    dynamic = {}
    # The network sysctl tree is read only, including interface-specific settings.
    for path in sorted(Path('/proc/sys/net').rglob('*')):
        if path.is_file():
            try:
                raw = read_bounded(path, 65536)
            except PermissionError:
                continue
            if len(raw) > 65536 or len(sysctls) >= 8192:
                raise ValueError('network sysctl observation bound')
            # Kernel documentation defines this as the current number of flows.
            # Retain it as a diagnostic rather than configuration equivalence.
            target = dynamic if str(path) == '/proc/sys/net/netfilter/nf_conntrack_count' else sysctls
            target[str(path)] = sha(raw)
    firewall = output(['/usr/bin/sudo', '-n', '--', nft, '-j', 'list', 'ruleset'])
    descriptor = os.open(destination.with_suffix('.nft.json'),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(firewall)
    return dict(schema_version=2,
                parent_net_namespace=os.readlink('/proc/self/ns/net'),
                parent_ipc_namespace=os.readlink('/proc/self/ns/ipc'),
                parent_pid_namespace=os.readlink('/proc/self/ns/pid'),
                routes_v4_sha256=sha(output([ip, '-j', '-4', 'route', 'show', 'table', 'all'])),
                routes_v6_sha256=sha(output([ip, '-j', '-6', 'route', 'show', 'table', 'all'])),
                rules_v4_sha256=sha(output([ip, '-j', '-4', 'rule', 'show'])),
                rules_v6_sha256=sha(output([ip, '-j', '-6', 'rule', 'show'])),
                dns_sha256=sha(read_bounded(Path('/etc/resolv.conf'), 65536)),
                dns_link=os.readlink('/etc/resolv.conf') if Path('/etc/resolv.conf').is_symlink() else None,
                firewall_raw_sha256=sha(firewall),
                firewall_configuration_sha256=firewall_configuration(firewall),
                dynamic_counts=dynamic, network_sysctls=sysctls)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    state = observe(args.destination)
    raw = (json.dumps(state, sort_keys=True, indent=2) + '\n').encode()
    descriptor = os.open(args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
    if args.compare:
        before = json.loads(read_bounded(args.compare, 4 * 1024 * 1024))
        def configuration(value):
            return {key: item for key, item in value.items()
                    if key not in {'dynamic_counts', 'firewall_raw_sha256'}}
        equal = configuration(before) == configuration(state)
        comparison = dict(schema_version=1, raw_equal=before == state,
                          configuration_equal=equal,
                          excluded_dynamic_fields=['dynamic_counts.nf_conntrack_count',
                                                   'firewall.nftables.counter.packets',
                                                   'firewall.nftables.counter.bytes'])
        destination = args.destination.parent / 'host-equality.json'
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(comparison, stream, sort_keys=True)
            stream.write('\n')
        if not equal:
            raise ValueError('parent-host equality failed; both original observations retained')
        print('Parent namespace, routes, DNS, firewall configuration and observed network settings unchanged')
