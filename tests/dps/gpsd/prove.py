#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real public gpsfake -> gpsd -> gpspipe -> Core proof inside disposable namespaces."""
import argparse
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

from build import (PYTHON_CARRIER, SANITIZERS, TARGETS, build_environment, build_options,
                   compile_observation, effective_profile, tree_hash)
from common import (ROOT, CommandFailure, clean_environment, command, digest, hosted, pins,
                    private_directory, source_binding, strict_json, terminate, write_json)
from fixture import fresh_fixture

PARENT_NET = 'VOLPAROSSA_DPS_GPSD_PARENT_NETNS'
GPSFAKE_WATCH = '?WATCH={"enable":true,"json":true,"nmea":false,"raw":0}'
SCENARIOS = [('normal', 'positive'), ('sanitized', 'positive'),
             ('normal', 'unknown_datum'), ('normal', 'missing_height')]
LIMITATIONS = {'CallerSuppliedEvidence', 'PhysicalIntegrityUnverified',
               'PhysicalIndependenceUnverified', 'UncertaintyConfidenceUnknown',
               'NoSensorFusion', 'NoSensorOrClockVerification', 'PairwiseConsistencyOnly'}


def gpsfake_argv(normal, port, fixture_path):
    if port not in (29471, 29472):
        raise ValueError('fixed actual/diagnostic fixture port required')
    # Official pipe mode sends its own WATCH and waits 1.4 seconds before feed.
    # Unbuffered Python preserves that public mirror while the product has its own pipe.
    return ['/usr/bin/python3', '-B', '-u', str(normal / 'gpsfake'), '-q', '-1', '-p',
            '-r', GPSFAKE_WATCH, '-c', '0.04', '-P', str(port), str(fixture_path)]


def loopback_only(devices, ipv4, ipv6):
    interfaces = [line.split(':', 1)[0].strip() for line in devices.splitlines()[2:]]
    if interfaces != ['lo']:
        raise ValueError('fixture namespace must contain only loopback')
    for line in ipv4.splitlines()[1:]:
        fields = line.split()
        if (len(fields) < 11 or fields[0] != 'lo' or
                (fields[1] == '00000000' and fields[7] == '00000000')):
            raise ValueError('unexpected IPv4 interface/default route')
    for line in ipv6.splitlines():
        fields = line.split()
        if len(fields) != 10 or fields[9] != 'lo':
            raise ValueError('unexpected IPv6 route/interface')
        # Linux installs an unreachable (::/0, RTF_REJECT) sentinel on lo.
        # It provides no egress and is not a usable configured default route.
        if fields[0] == '0' * 32 and fields[1] == '00' and not int(fields[8], 16) & 0x200:
            raise ValueError('usable IPv6 default route is forbidden')


def isolation(parent_ipc, parent_pid):
    hosted()
    if os.getpid() != 1:
        raise ValueError('proof controller must own namespace PID1 and orphan reaping')
    for name, parent in [('net', os.environ.get(PARENT_NET, '')),
                         ('ipc', parent_ipc), ('pid', parent_pid)]:
        current = os.readlink('/proc/self/ns/' + name)
        if not parent.startswith(name + ':[') or not parent.endswith(']') or current == parent:
            raise ValueError('independent net/IPC/PID namespaces required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    if (os.geteuid() == 0 or status['NoNewPrivs'].strip() != '1' or
            any(int(status[key].strip(), 16) for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) or
            status['Groups'].strip()):
        raise ValueError('nonroot, empty groups, zero capabilities and NNP required')
    loopback_only(Path('/proc/net/dev').read_text(), Path('/proc/net/route').read_text(),
                  Path('/proc/net/ipv6_route').read_text())
    return {'net_namespace_distinct': True, 'ipc_namespace_distinct': True,
            'pid_namespace_distinct': True, 'nonroot': True,
            'controller_is_pid1': True, 'loopback_only': True, 'no_usable_default_route': True,
            'empty_groups': True, 'all_capabilities_zero': True, 'no_new_privileges': True}


def descendants(pid, proc_root=Path('/proc')):
    pending = [pid]
    result = set()
    while pending:
        parent = pending.pop()
        try:
            tasks = []
            with os.scandir(proc_root / str(parent) / 'task') as entries:
                for entry in entries:
                    if (len(tasks) >= 64 or not entry.name.isascii() or not entry.name.isdecimal() or
                            len(entry.name) > 10):
                        raise ValueError('fixture task inventory exceeds its bound')
                    tasks.append(Path(entry.path))
        except (FileNotFoundError, ProcessLookupError):
            continue
        # Linux children is per task/TID. Tokio may spawn gpspipe on a worker,
        # so inspecting only task/<main-pid>/children misses a genuine child.
        for task in tasks:
            try:
                with (task / 'children').open('rb') as stream:
                    raw = stream.read(257)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if len(raw) > 256:
                raise ValueError('fixture child inventory exceeds its bound')
            for token in raw.split():
                if not token.isdigit() or len(token) > 10 or int(token) == 0:
                    raise ValueError('invalid fixture child PID')
                child = int(token)
                if child not in result:
                    if len(result) >= 16:
                        raise ValueError('fixture descendant count exceeds its bound')
                    result.add(child)
                    pending.append(child)
    return result


def reap_orphans(deadline):
    """Only namespace PID1 calls this, after all direct jobs have been joined."""
    while time.monotonic() < deadline:
        remaining = descendants(os.getpid())
        if not remaining:
            return True
        for pid in remaining:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        time.sleep(0.02)
    return not descendants(os.getpid())


def closed_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(0.1)
        return stream.connect_ex(('127.0.0.1', port)) != 0


def quality(value):
    integer_fields = ('schema_version', 'declared_independence_groups', 'eligible_claims')
    if (any(type(value.get(key)) is not int for key in integer_fields) or
            value.get('schema_version') != 1 or value.get('quality') != 'SingleClaim' or
            value.get('candidate_present') is not True or
            value.get('declared_independence_groups') != 1 or value.get('eligible_claims') != 1):
        raise ValueError('Core did not return one unverified claim')
    provenance = value.get('provenance', {})
    expected = {'input': 'gpsd_tpv', 'profile': 'operator_asserted_wgs84_receiver_ellipsoidal',
                'complete_distinct_epochs': 3, 'physical_datum_verified': False,
                'uncertainty_confidence': 'unknown', 'navigation_authentication': 'unknown'}
    if set(provenance) != set(expected) or any(
            type(provenance.get(key)) is not type(item) or provenance.get(key) != item
            for key, item in expected.items()):
        raise ValueError('GPSD provenance assertion differs')
    # A quality-only response cannot smuggle raw input into extra output fields.
    if set(value) != {'schema_version', 'quality', 'candidate_present',
                      'declared_independence_groups', 'eligible_claims', 'limitations', 'provenance'}:
        raise ValueError('unexpected public quality response field')
    if (not isinstance(value['limitations'], list) or len(value['limitations']) != 7 or
            set(value['limitations']) != LIMITATIONS):
        raise ValueError('all shared DPS limitation flags required')
    return value


def executable(pid):
    try:
        return os.readlink('/proc/' + str(pid) + '/exe')
    except FileNotFoundError:
        return None


def public_tpv_summary(raw):
    """Diagnostic shape only, never the product parser or acceptance decision."""
    if len(raw) > 327680:
        raise ValueError('public TPV diagnostic byte bound')
    classes = {}
    rows = []
    errors = 0
    lines = raw.splitlines()
    if len(lines) > 32 or any(len(line) > 10240 for line in lines):
        raise ValueError('public TPV diagnostic frame bound')
    for line in lines:
        try:
            value = strict_json(line)
        except (ValueError, UnicodeError):
            errors += 1
            continue
        if not isinstance(value, dict) or not isinstance(value.get('class'), str):
            errors += 1
            continue
        category = value['class'] if value['class'] in {'TPV', 'VERSION', 'WATCH', 'DEVICES', 'DEVICE', 'SKY', 'ERROR'} else 'other'
        classes[category] = classes.get(category, 0) + 1
        if category != 'TPV':
            continue
        fields = {name: name in value for name in ('time', 'device', 'lat', 'lon', 'altHAE', 'datum')}
        finite = all(type(value.get(name)) in (int, float) and math.isfinite(value[name])
                     for name in ('lat', 'lon', 'altHAE'))
        mode3 = type(value.get('mode')) is int and value['mode'] == 3
        datum = value.get('datum')
        timestamp = value.get('time')
        age = None
        if isinstance(timestamp, str) and len(timestamp) <= 64:
            try:
                epoch = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if epoch.tzinfo is not None:
                    age = round((datetime.now(timezone.utc) - epoch).total_seconds() * 1000)
            except ValueError:
                pass
        device_shape = isinstance(value.get('device'), str) and 0 < len(value['device'].encode()) <= 256
        rows.append({'fields_present': fields, 'mode_is_3': mode3,
                     'datum_is_wgs84': datum == 'WGS84', 'geometry_fields_finite': finite,
                     'device_binding_nonempty': device_shape,
                     'receiver_time': timestamp if isinstance(timestamp, str) and len(timestamp) <= 64 else None,
                     'age_ms_when_summarized': age,
                     'shape_complete': all(fields.values()) and mode3 and datum == 'WGS84' and finite
                                       and device_shape and age is not None})
    return {'classes': classes, 'tpv_rows': rows, 'non_json_or_invalid_rows': errors,
            'shape_complete_distinct_times': len({row['receiver_time'] for row in rows if row['shape_complete']}),
            'raw_bytes': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest(),
            'product_acceptance': False, 'shape_summary_only': True}


def terminate_diagnostic(child, deadline):
    """One cleanup owner; never start a wait extending beyond its absolute end."""
    for sig, delay in ((signal.SIGTERM, 0.5), (signal.SIGKILL, 1.0)):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            continue
        try:
            child.wait(timeout=min(delay, remaining))
        except subprocess.TimeoutExpired:
            continue
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return True
    return child.poll() is not None


def diagnose_public_tpv(kind, receipt, evidence, deadline):
    """One fresh real gpsfake/gpspipe replay after the primary failed case was joined.

    No Core retry, no shared product pipe, no new acceptance result, same global deadline.
    """
    end = min(deadline, time.monotonic() + 12)
    directory = private_directory(Path(receipt['prefix']) / ('diagnostic-' + kind), create=True)
    temporary = directory / 'tmp'
    temporary.mkdir(mode=0o700)
    home = directory / 'home'
    home.mkdir(mode=0o700)
    label = kind + '-diagnostic'
    fixture_path = directory / 'PUBLIC-SYNTHETIC.nmea'
    fixture_path.write_bytes(fresh_fixture('positive'))
    os.chmod(fixture_path, 0o600)
    (evidence / (label + '-PUBLIC-SYNTHETIC.nmea')).write_bytes(fixture_path.read_bytes())
    row = receipt['binaries'][kind]
    normal = Path(receipt['binaries']['normal']['variant_directory'])
    env = dict(clean_environment(), PYTHONPATH=str(normal), GPSD_HOME=row['variant_directory'],
               TMPDIR=str(temporary), HOME=str(home),
               ASAN_OPTIONS='abort_on_error=1:detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    result = {'schema_version': 1, 'status': 'failed', 'phase': 'launch',
              'public_synthetic_only': True, 'primary_failure_preserved': True,
              'product_retried': False, 'product_acceptance': False,
              'separate_fresh_replay': True, 'fixture_sha256': digest(fixture_path),
              'gpsd_sha256': row['gpsd']['sha256'], 'gpspipe_sha256': row['gpspipe']['sha256'],
              'actual_daemon_observed': False, 'actual_diagnostic_gpspipe_observed': False}
    child = None
    log = None
    joined = False
    drain = lambda: None
    port = 29472
    try:
        if not closed_port(port) or time.monotonic() >= end - 10:
            raise ValueError('diagnostic port or original budget unavailable')
        log = (evidence / (label + '-PUBLIC-SYNTHETIC-gpsfake.log')).open('xb')
        child = subprocess.Popen(gpsfake_argv(normal, port, fixture_path),
                                 cwd=normal, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        os.set_blocking(child.stdout.fileno(), False)
        written = 0
        def drain():
            nonlocal written
            while True:
                try:
                    chunk = os.read(child.stdout.fileno(), 65536)
                except BlockingIOError:
                    return
                if not chunk:
                    return
                written += len(chunk)
                if written > 1024 * 1024:
                    raise ValueError('diagnostic GPSD output bound')
                log.write(chunk)
                log.flush()
        result['phase'] = 'readiness'
        while closed_port(port):
            drain()
            if child.poll() is not None or time.monotonic() >= end - 10:
                raise TimeoutError('diagnostic readiness budget')
            time.sleep(0.02)
        def observe(pipe):
            drain()
            result['actual_daemon_observed'] |= any(executable(pid) == row['gpsd']['path']
                                                     for pid in descendants(child.pid))
            result['actual_diagnostic_gpspipe_observed'] |= executable(pipe.pid) == row['gpspipe']['path']
        result['phase'] = 'capture'
        raw = command([row['gpspipe']['path'], '-w', '-B', '-n', '32', '-x', '3',
                       '127.0.0.1:' + str(port)], cwd=directory, env=env,
                      deadline=min(end - 6, time.monotonic() + 4),
                      log_path=evidence / (label + '-PUBLIC-SYNTHETIC-TPV.log'),
                      limit=327680, observer=observe)
        result['summary'] = public_tpv_summary(raw)
        if not result['actual_daemon_observed'] or not result['actual_diagnostic_gpspipe_observed']:
            raise ValueError('real diagnostic source-bound processes not observed')
        result['phase'] = 'complete'
        result['status'] = 'observed'
    except Exception as error:
        result['failure_class'] = type(error).__name__
    finally:
        try:
            if child is not None:
                joined = terminate_diagnostic(child, end)
                if joined and log is not None:
                    drain()
        except Exception as error:
            result['status'] = 'failed'
            result['cleanup_failure_class'] = type(error).__name__
        finally:
            if child is not None and child.stdout is not None and not child.stdout.closed:
                child.stdout.close()
            if log is not None:
                log.close()
        reaped = reap_orphans(min(end, time.monotonic() + 2))
        listener_closed = closed_port(port)
        if joined and reaped and listener_closed:
            shutil.rmtree(directory)
        result['cleanup'] = {'gpsfake_reaped': joined,
                             'namespace_children_reaped': reaped, 'listener_closed': listener_closed,
                             'private_state_removed': not directory.exists()}
        if not all(result['cleanup'].values()):
            result['status'] = 'failed'
        if time.monotonic() >= end:
            result['status'] = 'failed'
            result['diagnostic_budget_expired'] = True
        write_json(evidence / (label + '-observations.json'), result)
    return result


def write_case_receipt(path, value):
    """Preserve a pending primary failure; receipt failure is fatal on success."""
    primary_active = sys.exc_info()[0] is not None
    try:
        write_json(path, value)
    except Exception:
        if not primary_active:
            raise


def failure_diagnostic(kind, scenario, receipt, evidence, deadline):
    """Admit a separate replay only after retained evidence confirms owned cleanup."""
    skipped = {'status': 'skipped', 'product_retried': False, 'product_acceptance': False}
    path = evidence / (kind + '-' + scenario + '-cleanup.json')
    fields = {'gpsfake_direct_child_reaped', 'observed_native_children_gone',
              'namespace_children_reaped', 'listener_closed', 'private_state_removed'}
    try:
        digest(path, 4096)
        cleanup = strict_json(path.read_bytes())
    except (OSError, ValueError):
        return dict(skipped, reason='original_cleanup_unconfirmed')
    if (not isinstance(cleanup, dict) or set(cleanup) != fields or
            not all(cleanup[key] is True for key in fields)):
        return dict(skipped, reason='original_cleanup_unconfirmed')
    if scenario != 'positive':
        return dict(skipped, reason='diagnostic_not_requested_for_negative_case')
    if time.monotonic() + 14 >= deadline:
        return dict(skipped, reason='original_budget_unavailable')
    return diagnose_public_tpv(kind, receipt, evidence, deadline)


def run_case(kind, scenario, core, receipt, evidence, deadline):
    label = kind + '-' + scenario
    directory = private_directory(Path(receipt['prefix']) / label, create=True)
    tmp = directory / 'tmp'
    tmp.mkdir(mode=0o700)
    home = directory / 'home'
    home.mkdir(mode=0o700)
    fixture_path = directory / 'public-synthetic.nmea'
    fixture_path.write_bytes(fresh_fixture(scenario))
    os.chmod(fixture_path, 0o600)
    # Public fixture is explicitly retained as such; private runtime paths are not.
    (evidence / (label + '-PUBLIC-SYNTHETIC.nmea')).write_bytes(fixture_path.read_bytes())
    row = receipt['binaries'][kind]
    normal = Path(receipt['binaries']['normal']['variant_directory'])
    variant = Path(row['variant_directory'])
    env = clean_environment()
    env.update({'PATH': str(variant / 'clients') + ':/usr/bin:/bin',
                'PYTHONPATH': str(normal), 'GPSD_HOME': str(variant),
                'TMPDIR': str(tmp), 'HOME': str(home),
                'ASAN_OPTIONS': 'abort_on_error=1:detect_leaks=1',
                'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'})
    port = 29471
    if not closed_port(port):
        raise ValueError('fixture loopback port already occupied')
    log_path = evidence / (label + '-PUBLIC-SYNTHETIC-gpsfake.log')
    native_pids = set()
    observed_pipe = set()
    daemon_seen = False
    core_started = False
    core_exit_observed = False
    child = None
    result = None
    cleanup = None
    try:
        with log_path.open('xb') as log:
            os.chmod(log_path, 0o600)
            child = subprocess.Popen(gpsfake_argv(normal, port, fixture_path),
                                     cwd=normal, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            os.set_blocking(child.stdout.fileno(), False)
            written = 0
            def drain():
                nonlocal written
                while True:
                    try:
                        chunk = os.read(child.stdout.fileno(), 65536)
                    except BlockingIOError:
                        return
                    if not chunk:
                        return
                    written += len(chunk)
                    if written > 1024 * 1024:
                        raise ValueError('gpsfake output bound')
                    log.write(chunk)
                    log.flush()
            ready = min(deadline - 3, time.monotonic() + 5)
            while closed_port(port):
                drain()
                if child.poll() is not None or time.monotonic() >= ready:
                    raise ValueError('real gpsfake/gpsd did not become ready')
                time.sleep(0.02)
            def observe(core_child):
                nonlocal daemon_seen, core_started
                core_started = True
                drain()
                for pid in descendants(child.pid):
                    native_pids.add(pid)
                    if executable(pid) == row['gpsd']['path']:
                        daemon_seen = True
                for pid in descendants(core_child.pid):
                    if executable(pid) == row['gpspipe']['path']:
                        try:
                            with Path('/proc', str(pid), 'cmdline').open('rb') as stream:
                                argv = stream.read(1025)
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        if len(argv) > 1024:
                            raise ValueError('Core child argument bytes exceed their bound')
                        expected = [b'gpspipe', b'-w', b'-B', b'-n', b'32', b'-x', b'8',
                                    ('127.0.0.1:' + str(port)).encode(), b'']
                        if argv.split(b'\0') != expected:
                            raise ValueError('Core did not invoke the fixed production gpspipe arguments')
                        observed_pipe.add(pid)
            argv = [str(core), 'dps', 'observe-gpsd', '--endpoint', '127.0.0.1:' + str(port),
                    '--profile', 'wgs84-receiver-ellipsoidal', '--comparison-radius-metres', '10']
            failed = False
            try:
                raw = command(argv, cwd=directory, env=env,
                              deadline=min(deadline - 2, time.monotonic() + 12),
                              log_path=evidence / (label + '-core.log'), limit=65536, observer=observe)
                core_exit_observed = True
            except CommandFailure:
                core_exit_observed = True
                if scenario == 'positive':
                    raise
                failed = True
            if scenario == 'positive':
                result = quality(strict_json(raw))
            elif not failed:
                raise ValueError('invalid GPSD input unexpectedly succeeded')
            else:
                failure = (evidence / (label + '-core.log')).read_bytes()
                allowed = {'unknown_datum': [b'DPS GPSD geometry rejected'],
                           'missing_height': [b'DPS GPSD complete epochs unavailable']}
                if not any(message in failure for message in allowed[scenario]):
                    raise ValueError('negative case failed for an unrelated reason')
            if not daemon_seen or not observed_pipe:
                raise ValueError('real source-bound gpsd/gpspipe execution was not observed')
            if any(Path('/proc', str(pid)).exists() for pid in observed_pipe):
                raise ValueError('Core gpspipe child outlived the completed CLI')
            native_pids.update(descendants(child.pid))
            terminate(child)
            drain()
            child.stdout.close()
    finally:
        if child is not None:
            native_pids.update(descendants(child.pid))
            terminate(child)
            if child.stdout is not None and not child.stdout.closed:
                child.stdout.close()
        # Namespace PID1 must not retain an orphan/zombie from the fixture.
        until = min(deadline, time.monotonic() + 2)
        while any(Path('/proc', str(pid)).exists() for pid in native_pids) and time.monotonic() < until:
            for pid in native_pids:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
            time.sleep(0.02)
        children_gone = not any(Path('/proc', str(pid)).exists() for pid in native_pids)
        listener_closed = closed_port(port)
        shutil.rmtree(directory)
        cleanup = {'gpsfake_direct_child_reaped': child is not None and child.returncode is not None,
                   'observed_native_children_gone': children_gone,
                   'namespace_children_reaped': reap_orphans(min(deadline, time.monotonic() + 2)),
                   'listener_closed': listener_closed, 'private_state_removed': not directory.exists()}
        write_case_receipt(evidence / (label + '-cleanup.json'), cleanup)
        write_case_receipt(evidence / (label + '-observations.json'), {
            'schema_version': 1, 'kind': kind, 'scenario': scenario,
            'actual_core_process_observed': core_started, 'core_exit_observed': core_exit_observed,
            'actual_daemon_observed': daemon_seen, 'actual_production_gpspipe_observed': bool(observed_pipe),
            'observed_gpspipe_children': len(observed_pipe),
            'gpspipe_children_gone': not any(Path('/proc', str(pid)).exists() for pid in observed_pipe),
            'cleanup': cleanup})
    if not all(cleanup.values()):
        raise ValueError('fixture cleanup was incomplete')
    original_log = log_path.read_bytes()
    if (len(original_log) > 1024 * 1024 or b'Sanitizer' in original_log or
            b'runtime error:' in original_log):
        raise ValueError('native sanitizer diagnostic/output bound; original log retained')
    return {'kind': kind, 'scenario': scenario, 'passed': True,
            'actual_daemon_observed': daemon_seen, 'actual_production_gpspipe_observed': bool(observed_pipe),
            'gpspipe_child_gone': True, 'quality': result, 'cleanup': cleanup}


def prove(args):
    boundary = isolation(args.parent_ipc, args.parent_pid)
    evidence = private_directory(args.evidence_dir)
    if args.build_receipt != evidence / 'build-receipt.json':
        raise ValueError('fixed build receipt path required')
    digest(args.build_receipt, 128 * 1024)
    receipt = strict_json(args.build_receipt.read_bytes())
    if (receipt['status'] != 'compiled_only' or receipt['phase'] != 'complete' or
            receipt['source_version'] != pins()['version'] or
            receipt['sanitizer_flags'] != SANITIZERS or
            receipt['build_targets'] != TARGETS or
            receipt['support_packages'] != pins()['support_packages']):
        raise ValueError('complete pinned native build required')
    source = source_binding(receipt['source']['commit'])
    if source != receipt['source']:
        raise ValueError('native build source binding differs')
    prefix = private_directory(receipt['prefix'])
    if prefix != Path(os.environ['RUNNER_TEMP']) / ('dps-gpsd-' + source['commit'][:12]):
        raise ValueError('native build prefix differs')
    if (receipt['build_options'] != build_options(prefix) or
            receipt['python_carrier']['path'] != str(prefix / 'python') or
            digest(prefix / 'python') != hashlib.sha256(PYTHON_CARRIER.encode()).hexdigest()):
        raise ValueError('fixed Python carrier/build options differ')
    if tree_hash(prefix / 'support') != receipt['support_tree_sha256']:
        raise ValueError('private support package payload changed')
    for kind in ('normal', 'sanitized'):
        compile_log = evidence / ('build-' + kind + '.log')
        digest(compile_log, 32 * 1024 * 1024)
        if compile_observation(compile_log.read_bytes(), kind) != receipt['compile_observations'][kind]:
            raise ValueError('actual code-generation/static linkage proof differs')
        source_directory = Path(receipt['binaries'][kind]['source_directory'])
        expected_source = prefix / ('gpsd-3.25' if kind == 'normal' else 'sanitized')
        if (source_directory != expected_source or
                receipt['binaries'][kind]['variant_directory'] != str(expected_source / 'gpsd-3.25')):
            raise ValueError('fixed native source/variant layout differs')
        if effective_profile(source_directory) != receipt['effective_profiles'][kind]:
            raise ValueError('effective native feature profile changed')
        for name in ('gpsd', 'gpspipe'):
            row = receipt['binaries'][kind][name]
            path = Path(row['path'])
            if prefix not in path.parents or path.resolve() != path or digest(path) != row['sha256']:
                raise ValueError('native binary binding differs')
    core = args.core_bin
    if core != ROOT / 'target/debug/volparossa' or not core.is_file() or core.is_symlink():
        raise ValueError('fixed source-built Core CLI required')
    core_sha = digest(core)
    deadline = time.monotonic() + 550
    report = {'schema_version': 1, 'status': 'failed', 'phase': 'upstream-check',
              'source': source, 'core_binary_sha256': core_sha,
              'build_receipt_sha256': digest(args.build_receipt), 'isolation': boundary,
              'upstream_check_passed': False, 'cases': [],
              'physical_sensor': False, 'measured_accuracy': False, 'certified_accuracy': False,
              'navigation_authentication_verified': False, 'independent_position': False,
              'debian13_runtime': False, 'private_location_history': False,
              'fixture': 'explicitly_public_synthetic_NMEA_not_a_sensor_recording'}
    def interrupted(_signal, _frame):
        raise InterruptedError('public GPSD proof interrupted')
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        env = build_environment()
        env['PYTHONPATH'] = str(prefix / 'support/usr/lib/python3/dist-packages')
        env['TMPDIR'] = str(prefix)
        normal_source = Path(receipt['binaries']['normal']['source_directory'])
        report['phase'] = 'native-version-observation'
        for kind in ('normal', 'sanitized'):
            for name in ('gpsd', 'gpspipe'):
                raw = command([receipt['binaries'][kind][name]['path'], '-V'],
                              cwd=normal_source, env=env, deadline=min(deadline, time.monotonic() + 5),
                              log_path=evidence / (kind + '-' + name + '-version.log'), limit=65536)
                if b'3.25' not in raw:
                    raise ValueError('native release version differs')
        report['phase'] = 'upstream-check'
        command([str(prefix / 'python'), receipt['scons'], *build_options(prefix), 'python=yes', 'check'],
                cwd=normal_source, env=env, deadline=min(deadline - 100, time.monotonic() + 360),
                log_path=evidence / 'upstream-check-original.log')
        if not reap_orphans(min(deadline, time.monotonic() + 2)):
            raise ValueError('upstream test descendants were not reaped')
        report['upstream_check_passed'] = True
        report['upstream_children_reaped'] = True
        for kind, scenario in SCENARIOS:
            report['phase'] = kind + '-' + scenario
            try:
                report['cases'].append(run_case(kind, scenario, core, receipt, evidence, deadline))
            except CommandFailure:
                report['failed_case_observations'] = kind + '-' + scenario + '-observations.json'
                try:
                    report['public_tpv_diagnostic'] = failure_diagnostic(kind, scenario, receipt, evidence, deadline)
                except Exception:
                    report['public_tpv_diagnostic'] = {'status': 'failed', 'product_retried': False,
                                                       'product_acceptance': False}
                raise
        if digest(core) != core_sha:
            raise ValueError('Core binary changed during proof')
        report['phase'] = 'complete'
        report['status'] = 'passed'
    finally:
        try:
            write_case_receipt(evidence / 'gpsd-proof.json', report)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-bin', required=True, type=Path)
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--build-receipt', required=True, type=Path)
    parser.add_argument('--parent-ipc', required=True)
    parser.add_argument('--parent-pid', required=True)
    prove(parser.parse_args())
