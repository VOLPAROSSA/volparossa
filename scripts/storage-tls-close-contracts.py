#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted, isolated TLS-close regressions; not consumer or full datapath acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
TESTS = tuple('content::tls::tests::kernel_close::' + name for name in (
    'signed_reserve_survives_tcp_provider_and_proxy_drop_before_outer_finish',
    'signed_reserve_rejects_abrupt_outer_drop_after_inner_finish'))
RUNNER = 'scripts/run-isolated-test.sh'
WORKFLOW = '.github/workflows/quality.yml'
MAX_OUTPUT = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, maximum):
    require(not path.is_symlink() and path.is_file(), 'regular input required')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, 'input bound exceeded')
    return raw


def command(argv, seconds=15):
    """Capture a bounded combined stream; terminate the owned group on failure."""
    child = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True, env={**os.environ, 'LC_ALL': 'C'})
    result = bytearray()
    deadline = time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(child.stdout.fileno(), False)
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'command deadline exceeded')
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        require(len(result) + len(chunk) <= MAX_OUTPUT, 'command output bound exceeded')
                        result.extend(chunk)
        # Hold the leader's PID until final group termination, even when a
        # descendant retains the pipe after the leader exits.
        while time.monotonic() < deadline:
            result_status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result_status is not None:
                status = result_status.si_status if result_status.si_code == os.CLD_EXITED else 128 + result_status.si_status
                return status, bytes(result)
            time.sleep(0.05)
        raise ValueError('command deadline exceeded')
    finally:
        # The exact namespace wrapper has its own shorter graceful timeout.
        # Kill any remaining descendants before reaping the identity anchor.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        child.stdout.close()


def checked(argv, seconds=15):
    status, raw = command(argv, seconds)
    require(status == 0, 'command failed')
    return raw


def guard(environment, uid):
    require(uid != 0 and all(environment.get(key) == value for key, value in {
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
        'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64',
        'GITHUB_REPOSITORY': 'VOLPAROSSA/volparossa',
        'VOLPAROSSA_TEST_ALLOW_SUDO_NETNS': '1',
    }.items()), 'explicit nonroot hosted namespace authorization required')
    for key in ('GITHUB_SHA', 'GITHUB_WORKFLOW_SHA'):
        require(re.fullmatch('[0-9a-f]{40}', environment.get(key, '')), 'exact source/workflow required')
    require(environment.get('GITHUB_WORKFLOW_REF', '').startswith(
        'VOLPAROSSA/volparossa/' + WORKFLOW + '@'), 'Quality workflow required')
    require(Path(environment.get('RUNNER_TEMP', '')).is_absolute(), 'absolute runner temporary root required')
    require('VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS' not in environment, 'nested test invocation rejected')


def source_receipt(environment):
    def git(*args):
        return checked(['git', *args]).decode().strip()
    source = git('rev-parse', 'HEAD')
    require(source == environment['GITHUB_SHA'], 'checkout/source mismatch')
    require(not git('status', '--porcelain', '--untracked-files=no'), 'tracked source changed')
    pins = git('ls-files', 'tests/integration/*maintenance-pins*.json').splitlines()
    require(1 <= len(pins) <= 64, 'maintenance pin inventory missing or unbounded')
    paths = [WORKFLOW, RUNNER, 'scripts/storage-tls-close-contracts.py',
             'scripts/test-storage-tls-close-contracts.py', 'rust-toolchain.toml',
             'Cargo.toml', 'Cargo.lock', *pins]
    blobs = {}
    for name in paths:
        blob = git('rev-parse', 'HEAD:' + name)
        require(re.fullmatch('[0-9a-f]{40}', blob), 'committed blob missing')
        require(git('hash-object', '--', name) == blob, 'source blob mismatch')
        blobs[name] = blob
    return dict(source_commit=source, source_tree=git('rev-parse', 'HEAD^{tree}'),
                workflow_commit=environment['GITHUB_WORKFLOW_SHA'],
                workflow_ref=environment['GITHUB_WORKFLOW_REF'], source_blobs=blobs)


def build_binary(raw, target):
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    require(rows and all(type(row) is dict for row in rows), 'invalid build records')
    completions = [row.get('success') for row in rows if row.get('reason') == 'build-finished']
    require(len(completions) == 1 and completions[0] is True,
            'successful completed build required')
    binaries = [row.get('executable') for row in rows
                if row.get('reason') == 'compiler-artifact'
                and row.get('target', {}).get('name') == 'volparossa_agent'
                and row.get('target', {}).get('kind') == ['lib']
                and row.get('profile', {}).get('test') is True and row.get('executable')]
    require(len(binaries) == 1 and type(binaries[0]) is str, 'one agent test binary required')
    binary = Path(binaries[0])
    require(binary.is_absolute() and not binary.is_symlink() and binary.is_file(), 'regular test binary required')
    require(binary.resolve().is_relative_to(target.resolve()) and os.access(binary, os.X_OK),
            'test binary outside target or not executable')
    require(0 < binary.stat().st_size <= 2 * 1024 * 1024 * 1024, 'test binary size bound')
    return binary


def validate_inventory(raw, name):
    require(raw.decode().splitlines() == [name + ': test', '', '1 test, 0 benchmarks'],
            'exact ignored-test inventory mismatch')


def validate_result(raw, name, status):
    text = raw.decode()
    summaries = [line for line in text.splitlines() if line.startswith('test result:')]
    require(status == 0 and len(summaries) == 1 and re.fullmatch(
        r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s',
        summaries[0]), 'exact test did not pass')
    require(re.findall(r'^test (.+) \.\.\. ok$', text, re.M) == [name], 'test identity mismatch')


CTIME = (r'(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) '
         r'( [1-9]|[12][0-9]|3[01]) ([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] [0-9]{4}')


def normalize_firewall(raw):
    """Original closed normalization: timestamps and chain counters only."""
    normalized = []
    for line in raw.decode().split('\n'):
        quoted = escaped = False
        for character in line:
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == '"':
                quoted = not quoted
        require(not quoted and not escaped, 'multiline firewall rule rejected')
        if re.fullmatch(r'# Generated by ip(6)?tables-save v[0-9][0-9A-Za-z.+:~_-]*( \(nf_tables\))? on ' + CTIME, line):
            line = re.sub(r' on .*$', ' on [timestamp]', line)
        elif re.fullmatch(r'# Completed on ' + CTIME, line):
            line = '# Completed on [timestamp]'
        elif re.fullmatch(r':[-A-Za-z0-9_.+]+ (ACCEPT|DROP|-) \[[0-9]+:[0-9]+\]', line):
            line = re.sub(r' \[[0-9]+:[0-9]+\]$', ' [counters]', line)
        normalized.append(line)
    return '\n'.join(normalized).encode()


def normalizer_controls():
    checked_count = 0
    for program in ('iptables-save', 'ip6tables-save'):
        for backend in ('', ' (nf_tables)'):
            before = (f'# Generated by {program} v1.8.10{backend} on Thu Oct 15 10:10:10 2026\n'
                      '*filter\n:INPUT ACCEPT [1:2]\n:custom-chain - [3:4]\n'
                      '-A INPUT -m comment --comment "semantic [1:2]" -j custom-chain\n'
                      'COMMIT\n# Completed on Thu Oct 15 10:10:10 2026\n')
            original = normalize_firewall(before.encode())
            after = before.replace('10:10:10', '11:11:11').replace('ACCEPT [1:2]', 'ACCEPT [99:100]').replace('- [3:4]', '- [101:102]')
            require(original == normalize_firewall(after.encode()), 'dynamic normalization failed')
            checked_count += 1
            for old, new in (('ACCEPT', 'DROP'), ('custom-chain', 'other-chain'),
                             ('semantic [1:2]', 'semantic [9:10]'), ('*filter', '*nat'),
                             ('v1.8.10', 'v1.8.11'), ('COMMIT\n', ''),
                             ('v1.8.10' + backend, 'v1.8.10 (legacy)'),
                             ('10:10:10', 'unrecognized-timestamp')):
                require(original != normalize_firewall(before.replace(old, new).encode()), 'semantic change hidden')
                checked_count += 1
            for embedded in ('# Completed on Thu Oct 15 10:10:10 2026', ':INPUT ACCEPT [1:2]',
                             f'# Generated by {program} v1.8.10{backend} on Thu Oct 15 10:10:10 2026'):
                try:
                    normalize_firewall(before.replace('semantic [1:2]', 'first\n' + embedded + '\nlast').encode())
                except ValueError:
                    checked_count += 1
                else:
                    raise ValueError('multiline normalization accepted')
    require(checked_count == 48, 'normalizer control inventory changed')
    return checked_count


def observe():
    with Path('/etc/resolv.conf').open('rb') as stream:
        dns = stream.read(65537)
    require(len(dns) <= 65536, 'DNS observation bound')
    return dict(parent_namespace=os.readlink('/proc/self/ns/net'),
                routes_v4=digest(checked(['ip', '-4', '-j', 'route', 'show', 'table', 'all'])),
                routes_v6=digest(checked(['ip', '-6', '-j', 'route', 'show', 'table', 'all'])),
                dns=digest(dns),
                firewall_v4=digest(normalize_firewall(checked(['sudo', '-n', 'iptables-save']))),
                firewall_v6=digest(normalize_firewall(checked(['sudo', '-n', 'ip6tables-save']))))


def execute(binary, destination, receipt, verify_source):
    before = observe()
    (destination / 'host-before.json').write_text(json.dumps(before, sort_keys=True) + '\n')
    errors, results = [], []
    try:
        for index, name in enumerate(TESTS):
            try:
                inventory = checked([str(binary), '--ignored', '--exact', name, '--list'])
                (destination / f'kernel-{index}-inventory.log').write_bytes(inventory)
                validate_inventory(inventory, name)
                status, raw = command([str(ROOT / RUNNER), '--command', str(binary), name,
                    'VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS', 'loopback',
                    '--ignored', '--exact', name, '--nocapture'], 180)
                (destination / f'kernel-{index}-test.log').write_bytes(raw)
                validate_result(raw, name, status)
                results.append(name)
            except (OSError, ValueError, subprocess.SubprocessError):
                errors.append(f'kernel-{index}-failed')
    except BaseException:
        errors.append('execution-interrupted')
        raise
    finally:
        try:
            after = observe()
            (destination / 'host-after.json').write_text(json.dumps(after, sort_keys=True) + '\n')
            unchanged = before == after
            if not unchanged:
                errors.append('host-configuration-changed')
        except (OSError, ValueError, subprocess.SubprocessError):
            unchanged = False
            errors.append('host-after-unavailable')
        try:
            source_unchanged = verify_source() is True
        except (OSError, ValueError, subprocess.SubprocessError):
            source_unchanged = False
        if not source_unchanged:
            errors.append('source-changed-or-unreadable')
        receipt.update(passed=not errors and results == list(TESTS), executed_tests=results,
                       errors=errors, host_unchanged=unchanged, source_unchanged=source_unchanged,
                       full_relay_datapath_proven=False, multiple_live_subflows_proven=False,
                       live_consumer_acceptance=False, original_timeout_cause_proven=False)
        (destination / 'result.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    require(receipt['passed'], 'isolated TLS contracts or host comparison failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    guard(os.environ, os.geteuid())
    def interrupted(_number, _frame):
        raise KeyboardInterrupt('hosted proof interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == temporary,
            'new direct runner-temporary output required')
    os.umask(0o077)
    args.output.mkdir(mode=0o700, exist_ok=False)
    source = source_receipt(os.environ)
    receipt = dict(version=1, scope='two-exact-isolated-TLS-close-regressions',
                   normalizer_controls=normalizer_controls(), **source)
    raw = read(args.build_receipt, 64 * 1024 * 1024)
    target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
    binary = build_binary(raw, target)
    with binary.open('rb') as stream:
        binary_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    receipt.update(build_receipt_sha256=digest(raw), binary_sha256=binary_sha,
                   expected_tests=list(TESTS))
    (args.output / 'source.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    execute(binary, args.output, receipt, lambda: source_receipt(os.environ) == source)
    print('Two isolated TLS-close regressions passed; parent host observations unchanged.')


if __name__ == '__main__':
    main()
