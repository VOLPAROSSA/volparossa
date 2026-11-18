#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert finite-contract and owned-child tests, not peer-delivery evidence."""
import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
M = runpy.run_path(str(HERE / 'storage-provider-activity-sampler.py'))
G = M['query'].__globals__


def snapshot(stage='storage_grant_read_verify', bucket='90_to_120s', active=1):
    return dict(version=1, kind='content-provider-activity', state='observed', active_sessions=active,
        groups=[dict(stage=stage, elapsed_bucket=bucket, count=active)] if active else [],
        diagnostic_only=True, acceptance_evidence=False, causal_attribution=False)


class Contracts(unittest.TestCase):
    def test_all_closed_phases_and_buckets(self):
        for stage in M['STAGES']:
            for bucket in M['BUCKETS']:
                value = snapshot(stage, bucket, 4)
                self.assertEqual(M['snapshot'](value), value)
        unavailable = dict(snapshot(), state='unavailable', active_sessions=None, groups=[])
        self.assertEqual(M['snapshot'](unavailable), unavailable)

    def test_rejects_unknown_fields_authority_counts_and_noncanonical_groups(self):
        for key, value in (('version', True), ('version', 2), ('state', 'PRIVATE'),
                ('active_sessions', True), ('active_sessions', 5), ('active_sessions', 0),
                ('diagnostic_only', False), ('acceptance_evidence', True), ('causal_attribution', True),
                ('secret', 'PRIVATE'), ('groups', {})):
            changed = dict(snapshot(), **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): M['snapshot'](changed)
        for key, value in (('stage', 'PRIVATE'), ('elapsed_bucket', 'PRIVATE'), ('count', True),
                ('count', 0), ('count', 5), ('secret', 'PRIVATE')):
            changed = snapshot(); changed['groups'][0][key] = value
            with self.assertRaises(ValueError): M['snapshot'](changed)
        for groups in ([dict(snapshot()['groups'][0])] * 2,
                [dict(stage='closing', elapsed_bucket='under_1s', count=1),
                 dict(stage='tls_handshake', elapsed_bucket='under_1s', count=1)]):
            with self.assertRaises(ValueError): M['snapshot'](dict(snapshot(), active_sessions=2, groups=groups))
        with self.assertRaises(ValueError):
            M['snapshot'](dict(snapshot(), state='unavailable', active_sessions=None))

    def test_closed_decoder_rejects_duplicates_nonfinite_and_oversize(self):
        for raw in (b'{"version":1,"version":1}', b'{"a":NaN}', b'PRIVATE' * 1024):
            with self.assertRaises(ValueError): M['snapshot'](M['decode'](raw, M['MAX_REPLY']))

    def test_longest_wait_survives_empty_and_failed_snapshots(self):
        samples = M['Samples']('publish')
        original = snapshot()
        for state, value in (('observed', original), ('observed', snapshot(active=0)), ('timeout', None)):
            samples.rounds += 1
            samples.add('a', state, value, True)
        original['groups'][0]['stage'] = 'PRIVATE'
        value = samples.report()
        self.assertEqual(value['roles']['a']['longest_wait'], snapshot())
        self.assertIsNone(value['roles']['a']['last'])
        self.assertEqual(value['roles']['a']['counts']['observed'], 2)
        self.assertFalse(value['acceptance_evidence'] or value['causal_attribution'])
        self.assertNotIn('PRIVATE', M['encoded'](value).decode())
        for key, bad in (('rounds', 513), ('children_joined', 1), ('sampler_joined', False), ('secret', 'PRIVATE')):
            changed = dict(value, **{key: bad})
            with self.assertRaises(ValueError): M['validate'](changed)
        changed = copy.deepcopy(value); changed['roles']['a']['counts']['observed'] += 1
        with self.assertRaises(ValueError): M['validate'](changed)

    def test_maximum_report_is_bounded(self):
        samples = M['Samples']('finish'); samples.rounds = 1
        value = snapshot(active=4)
        value['groups'] = [dict(stage=stage, elapsed_bucket='at_least_120s', count=1) for stage in M['STAGES'][:4]]
        for role in M['ROLES']: samples.add(role, 'observed', value, True)
        self.assertLess(len(M['encoded'](samples.report())), M['MAX_BYTES'])

    def test_private_report_exclusive_phase_binding_and_inode_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            value = M['Samples']('publish').report()
            M['publish'](root, 'publish', value)
            path = root / M['private_name']('publish')
            self.assertEqual(M['read_file'](path, 'publish', os.geteuid()), value)
            with self.assertRaises(FileExistsError): M['publish'](root, 'publish', value)
            with self.assertRaises(ValueError): M['read_file'](path, 'finish', os.geteuid())
            with self.assertRaises(ValueError): M['read_file'](path, 'publish', os.geteuid() + 1)
            link = root / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): M['read_file'](link, 'publish', os.geteuid())
            link.unlink(); os.link(path, link)
            with self.assertRaises(ValueError): M['read_file'](path, 'publish', os.geteuid())
            link.unlink(); path.chmod(0o644)
            with self.assertRaises(ValueError): M['read_file'](path, 'publish', os.geteuid())


class OwnedQueries(unittest.TestCase):
    def run_query(self, code, stopped=None, expected_joined=True):
        popen, children = subprocess.Popen, []
        def spawn(argv, **kwargs):
            self.assertEqual(argv, ['/fixed/core', '--control-socket', '/fixed/control', 'content', 'provider-activity'])
            child = popen([sys.executable, '-I', '-B', '-c', code], **kwargs)
            children.append(child)
            return child
        with patch.object(G['subprocess'], 'Popen', spawn):
            result = M['query']('/fixed/core', '/fixed/control', stopped or threading.Event())
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertIs(result[2], expected_joined)
        return result

    def test_actual_child_returns_only_valid_snapshot(self):
        value = snapshot()
        result = self.run_query('print(' + repr(json.dumps(value)) + ')')
        self.assertEqual(result, ('observed', value, True))
        for code in ('print("PRIVATE")', 'print("X" * 100000)'):
            self.assertEqual(self.run_query(code), ('rejected', None, True))
        self.assertEqual(self.run_query('raise SystemExit(2)'), ('failed', None, True))

    def test_deadline_and_cancellation_join_owned_process(self):
        with patch.dict(G, QUERY_SECONDS=.1):
            self.assertEqual(self.run_query('import time; time.sleep(30)'), ('timeout', None, True))
        stopped = threading.Event(); stopped.set()
        self.assertEqual(self.run_query('import time; time.sleep(30)', stopped), ('cancelled', None, True))

    def test_capture_samples_while_owner_waits_and_keeps_original_failure(self):
        reached, observed = threading.Event(), []
        def query(binary, control, stopped):
            observed.append(str(control)); reached.set()
            return 'observed', snapshot(), True
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            with patch.dict(G, query=query), self.assertRaisesRegex(RuntimeError, 'original_owner_failure'):
                with M['capture']('/fixed/core', Path('/fixed/work'), root, 'publish'):
                    self.assertTrue(reached.wait(1))
                    raise RuntimeError('original_owner_failure')
            value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
            self.assertTrue(value['sampler_joined'] and value['children_joined'])
            self.assertIsNotNone(value['roles']['a']['longest_wait'])
            self.assertTrue(all(path in [f'/fixed/work/runtime-{n}/control/agent.sock' for n in M['NODES']] for path in observed))
            self.assertFalse(any(t.name == 'storage-provider-activity-sampler' for t in threading.enumerate()))

    def test_round_limit_and_projection_failure_do_not_change_success(self):
        reached = threading.Event()
        calls = []
        def query(*_):
            calls.append(1)
            if len(calls) == 6: reached.set()
            return 'failed', None, True
        with patch.dict(G, MAX_ROUNDS=2, INTERVAL=0, query=query, publish=lambda *_: (_ for _ in ()).throw(ValueError('private'))):
            with M['capture']('/fixed/core', Path('/fixed/work'), Path('/unused'), 'finish'):
                self.assertTrue(reached.wait(1))
        self.assertEqual(len(calls), 6)

    def test_cleanup_error_is_not_confirmed_join_and_remaining_cleanup_is_attempted(self):
        original = os.killpg
        calls = []
        def kill(group, signum):
            calls.append(signum)
            if signum == G['signal'].SIGTERM: raise PermissionError('PRIVATE')
            return original(group, signum)
        with patch.object(G['os'], 'killpg', kill):
            result = self.run_query('print(' + repr(json.dumps(snapshot())) + ')', expected_joined=False)
        self.assertIn(G['signal'].SIGKILL, calls)
        samples = M['Samples']('publish'); samples.rounds = 1
        samples.add('a', *result)
        self.assertFalse(samples.report()['children_joined'])
        self.assertTrue(samples.report()['sampling_failed'])

    def test_unexpected_query_error_preserves_owner_error_and_never_claims_join(self):
        reached = threading.Event()
        def failed(*_):
            reached.set()
            raise PermissionError('PRIVATE')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            with patch.dict(G, query=failed), self.assertRaisesRegex(RuntimeError, 'owner_failure'):
                with M['capture']('/fixed/core', Path('/fixed/work'), root, 'publish'):
                    self.assertTrue(reached.wait(1))
                    raise RuntimeError('owner_failure')
            value = M['read_file'](root / M['private_name']('publish'), 'publish', os.geteuid())
            self.assertTrue(value['sampling_failed'])
            self.assertFalse(value['children_joined'])
            self.assertNotIn('PRIVATE', M['encoded'](value).decode())


class Wiring(unittest.TestCase):
    def export_names(self, work):
        result = subprocess.run([sys.executable, '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
            'export-names', str(work)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        self.assertNotIn(b'PRIVATE_EXPORT_CANARY', result.stdout)
        return set(result.stdout.decode('ascii').splitlines())

    def expected_exports(self, activity, usage=False):
        maintenance = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
        names = set(maintenance['EXPORT_NAMES']) - {maintenance['PROVIDER_EVENTS_NAME'],
            'private-storage-fixture-correlation.json', 'private-storage-maintenance-helper-acquire.json'}
        if not usage: names.remove('storage-consumer-provider-usage.json')
        return names if activity else names - {M['NAME']}

    def test_actual_exporter_includes_valid_optional_activity_in_each_phase(self):
        for phase, usage_present in ((phase, present) for phase in M['PHASES'] for present in (False, True)):
            with self.subTest(phase=phase, usage_present=usage_present), tempfile.TemporaryDirectory() as temp:
                work = Path(temp)
                samples = M['Samples'](phase); samples.rounds = 1
                samples.add('a', 'observed', snapshot(), True)
                M['publish'](work, phase, samples.report())
                work.joinpath(M['private_name'](phase)).rename(work / M['NAME'])
                if usage_present:
                    usage = runpy.run_path(str(HERE / 'storage-consumer-provider-usage.py'))
                    value = usage['report']([usage['empty'](role) for role in usage['ROLES']])
                    path = work / usage['NAME']
                    path.write_bytes(usage['encoded'](value)); path.chmod(0o600)
                self.assertEqual(self.export_names(work), self.expected_exports(True, usage_present))

    def test_actual_exporter_rejects_malformed_and_authority_changed_activity(self):
        invalid = M['Samples']('publish').report()
        invalid['acceptance_evidence'] = True
        for raw in (b'PRIVATE_EXPORT_CANARY', M['encoded'](invalid)):
            with self.subTest(raw=raw[:32]), tempfile.TemporaryDirectory() as temp:
                work = Path(temp)
                M['publish'](work, 'publish', M['Samples']('publish').report())
                path = work / M['NAME']
                work.joinpath(M['private_name']('publish')).rename(path)
                path.write_bytes(raw)
                self.assertEqual(self.export_names(work), self.expected_exports(False))

    def test_actual_exporter_omits_absent_optional_activity_without_losing_other_names(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(self.export_names(Path(temp)), self.expected_exports(False))

    def test_phase_projects_before_failure_and_never_overrides_application_result(self):
        script = '''
set -eu
. "$1"
WORK=$2
consumer_user=$WORK/owner
storage_user=$WORK/unused
WORKER_UID=$3
application_status=$4
storage_consumer_phase_start() { :; }
storage_consumer_phase_finish() { printf '%s\\n' finished; }
private_storage_consumer_private() { printf '%s\\n' original; return "$application_status"; }
fail() { printf '%s\\n' "$1" >&2; exit 17; }
private_storage_consumer_phase publish
'''
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); work.chmod(0o700)
            owner = work / 'owner'; owner.mkdir(mode=0o700)
            binary = work / 'bin'; binary.mkdir(mode=0o700)
            (binary / 'storage-provider-activity-sampler.py').write_bytes((HERE / 'storage-provider-activity-sampler.py').read_bytes())
            # Only the existing flow-minimum query uses this tiny inert CLI.
            (binary / 'storage-consumer-maintenance-smoke.py').write_text('print(56)\n')
            M['publish'](owner, 'publish', M['Samples']('publish').report())
            for primary in ('0', '1'):
                for valid in (True, False):
                    source = owner / M['private_name']('publish')
                    source.write_bytes(M['encoded'](M['Samples']('publish').report()) if valid else b'PRIVATE')
                    target = work / M['NAME']
                    target.unlink(missing_ok=True)
                    result = subprocess.run(['sh', '-c', script, 'inert',
                        str(HERE / 'storage-consumer-maintenance-smoke.sh'), str(work), str(os.geteuid()), primary],
                        capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0 if primary == '0' else 17)
                    self.assertEqual(result.stdout, b'finished\n' if primary == '0' else b'')
                    self.assertEqual(result.stderr, b'' if primary == '0' else b'CONSUMER_APPLICATION_FAILED\n')
                    self.assertEqual(target.exists(), valid)
                    if valid: M['read_file'](target, 'publish', os.geteuid())
                    self.assertNotIn(b'PRIVATE', result.stdout + result.stderr)
                    self.assertFalse((work / 'provider-activity.part').exists())

    def test_optional_names_and_guest_helper_are_staged(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertGreaterEqual(guest.count('storage-provider-activity-sampler.py'), 2)
        self.assertIn('"private-storage-provider-activity.json"', (HERE / 'run-alpha-topology-vm.sh').read_text())
        exporter = (HERE / 'run-alpha-topology-vm.sh').read_text()
        priority = exporter.split('MAINTENANCE_PRIORITY_NAMES = ', 1)[1].split('SIGNAL_FRAGMENT_NAMES', 1)[0]
        self.assertIn('"private-storage-provider-activity.json"', priority)
        self.assertIn('test-storage-provider-activity-sampler.py',
            (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text())
        maintenance = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
        self.assertIn(M['NAME'], maintenance['EXPORT_NAMES'])


if __name__ == '__main__':
    unittest.main()
