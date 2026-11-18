#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert synthetic checks only: no real query, socket, VM or network operation."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('failure_boundary', HERE / 'storage-consumer-failure-boundary.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
MAINT, HELPER = M.modules()
CANARY = 'PRIVATE_ADDRESS_HOST_URL_ID_CANARY'


def private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def event(code='CONTENT_PROVIDER_REGISTRY_TIMEOUT', stamp=200):
    return f'{stamp}\tlevel=3\tevent={code}\tsession={"a" * 64}\tpath=17\n'.encode()


class Capture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(M, 'modules', return_value=(MAINT, HELPER)).start()
        self.query = mock.patch.object(M, 'query', return_value=('socket_absent', b'')).start()

    def capture(self, phase='publish'):
        return M.capture(self.work, Path('/nonexecuted/volparossa'), phase, '100')

    def receipt(self):
        raw = (self.work / M.NAME).read_bytes()
        return M.validate(M.decode(raw), MAINT, HELPER)

    def test_each_role_once_phase_bound_missing_explicit_and_no_cleanup_claims(self):
        self.assertTrue(self.capture())
        self.assertEqual(self.query.call_count, 7)
        self.assertEqual([str(call.args[1]).split('runtime-')[1].split('/')[0]
            for call in self.query.call_args_list], list(M.NODES))
        self.assertEqual(len({call.args[2] for call in self.query.call_args_list}), 1)
        report = self.receipt()
        self.assertEqual(report['phase'], 'publish')
        self.assertTrue(all(row['state'] == 'socket_absent' for row in report['queries'].values()))
        self.assertTrue(all(row['state'] == 'query_failed' and row['counts'] is None
            for row in report['provider_events']['roles'].values()))
        self.assertTrue(all(report[key] is False for key in M.FALSE))
        self.assertEqual(report['helper_acquire']['source_state'], 'absent')
        self.assertEqual(list(self.work.iterdir()), [self.work / M.NAME])
        self.assertEqual(stat.S_IMODE((self.work / M.NAME).stat().st_mode), 0o600)

    def test_saturation_staleness_closed_v3_projection_and_private_identifiers_removed(self):
        self.query.return_value = ('observed', event(stamp=100) + event() * 399)
        fields = dict(diagnostic_code=HELPER['MARKER'], operation=4, **{'class': 1}, errno=111)
        private(self.work / 'helper-client.log', (json.dumps(dict(timestamp=CANARY,
            fields=fields, target=CANARY)) + '\n').encode())
        self.assertTrue(self.capture('exercise'))
        report = self.receipt()
        row = report['provider_events']['roles']['client']
        self.assertTrue(row['ring_at_capacity'])
        self.assertTrue(row['window_covers_baseline'])
        self.assertEqual(row['records'], 400)
        self.assertEqual(row['counts']['CONTENT_PROVIDER_REGISTRY_TIMEOUT'], 399)
        self.assertEqual(report['provider_events']['version'], 3)
        self.assertEqual(row['append_payload_io_failures'], {})
        self.assertEqual(report['helper_acquire']['records'][0]['errno'], 111)
        raw = (self.work / M.NAME).read_bytes()
        for private_value in (CANARY.encode(), ('a' * 64).encode(), b'session=', b'path=17'):
            self.assertNotIn(private_value, raw)
        self.assertLessEqual(len(raw), M.MAX_BYTES)
        self.assertFalse(any(path.name.startswith('.consumer-failure') for path in self.work.iterdir()))

    def test_earlier_receipt_survives_later_live_log_changes_and_second_phase(self):
        self.query.return_value = ('observed', event())
        self.assertTrue(self.capture())
        raw = (self.work / M.NAME).read_bytes()
        private(self.work / 'logs-client.txt', CANARY.encode())
        self.assertFalse(self.capture('finish'))
        self.assertEqual((self.work / M.NAME).read_bytes(), raw)
        self.assertEqual(self.query.call_count, 7)

    def test_projected_inputs_are_frozen_before_query_mutates_live_files(self):
        path = self.work / 'private-storage-maintenance-selection-phase.private'
        private(path, b'initial\n')
        def query(*_):
            private(path, b'reconnect\n')
            return 'observed', event()
        self.query.side_effect = query
        self.assertTrue(self.capture())
        self.assertEqual(self.receipt()['route']['selection_phase'], 'initial')

    def test_invalid_phase_does_not_query_or_publish(self):
        self.assertFalse(self.capture(CANARY))
        self.query.assert_not_called()
        self.assertEqual(list(self.work.iterdir()), [])

    def test_projection_publication_query_and_cancellation_failures_remove_scratch(self):
        for stage in ('query', 'project', 'publish', 'cancel'):
            with self.subTest(stage=stage):
                if stage in ('query', 'cancel'):
                    patch = mock.patch.object(M, 'query', side_effect=
                        M.CaptureInterrupted() if stage == 'cancel' else OSError())
                elif stage == 'project':
                    patch = mock.patch.object(M, 'encoded', side_effect=ValueError())
                else:
                    patch = mock.patch.object(M.os, 'link', side_effect=OSError())
                with patch:
                    self.assertFalse(self.capture())
                self.assertEqual(list(self.work.iterdir()), [])

    def test_symlink_and_racing_destination_never_clobbered(self):
        target = self.work / M.NAME
        target.symlink_to(self.work / 'missing')
        self.assertFalse(self.capture())
        self.query.assert_not_called()
        target.unlink()
        real_link = os.link
        def race(source, destination, **kwargs):
            private(destination, b'first-writer')
            return real_link(source, destination, **kwargs)
        with mock.patch.object(M.os, 'link', side_effect=race):
            self.assertFalse(self.capture())
        self.assertEqual(target.read_bytes(), b'first-writer')
        self.assertEqual(list(self.work.iterdir()), [target])

    def test_closed_schema_claims_phase_bounds_nested_unknown_and_duplicate_rejected(self):
        self.assertTrue(self.capture())
        report = self.receipt()
        cases = [dict(report, extra=CANARY), dict(report, version=True),
            dict(report, query_seconds=True), dict(report, phase=CANARY)]
        cases += [dict(report, **{flag: True}) for flag in M.FALSE]
        for field in ('queries', 'inputs', 'provider_events', 'route', 'helper_acquire'):
            value = copy.deepcopy(report)
            value[field]['extra'] = CANARY
            cases.append(value)
        value = copy.deepcopy(report)
        value['provider_events']['phase'] = 'storage-consumer-finish'
        cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                M.validate(value, MAINT, HELPER)
        with mock.patch.object(M, 'MAX_BYTES', 1), self.assertRaises(ValueError):
            M.encoded(report, MAINT, HELPER)
        for raw in (b'{"version":1,"version":1}', b'NaN', b'x' * (M.MAX_BYTES + 1)):
            with self.assertRaises(ValueError): M.decode(raw)


class FrozenInputs(unittest.TestCase):
    def test_freeze_bounded_private_regular_read_and_no_follow(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, target = root / 'source', root / 'target'
            private(source, b'abc')
            self.assertEqual(M.freeze(source, target, 3), 'frozen')
            self.assertEqual(target.read_bytes(), b'abc')
            target.unlink()
            self.assertEqual(M.freeze(source, target, 2), 'input_bound')
            self.assertFalse(target.exists())
            source.chmod(0o644)
            self.assertEqual(M.freeze(source, target, 3), 'invalid')
            source.unlink()
            self.assertEqual(M.freeze(source, target, 3), 'absent')
            source.symlink_to(root / 'missing')
            self.assertEqual(M.freeze(source, target, 3), 'unreadable')

    def test_changed_file_is_explicit_and_not_projected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            private(root / 'source', b'x')
            info = (root / 'source').stat()
            modified = mock.Mock(st_dev=info.st_dev, st_ino=info.st_ino, st_size=1,
                st_mtime_ns=info.st_mtime_ns + 1, st_ctime_ns=info.st_ctime_ns)
            with mock.patch.object(M.os, 'stat', return_value=modified):
                self.assertEqual(M.freeze(root / 'source', root / 'target', 3), 'changed')
            self.assertFalse((root / 'target').exists())


class Query(unittest.TestCase):
    def test_missing_invalid_socket_and_expired_budget_never_spawn(self):
        with mock.patch.object(M.subprocess, 'Popen') as spawn:
            for error, expected in ((FileNotFoundError(), 'socket_absent'), (OSError(), 'invalid_socket')):
                with mock.patch.object(Path, 'lstat', side_effect=error):
                    self.assertEqual(M.query('unused', Path('/unused'), float('inf'))[0], expected)
            with mock.patch.object(Path, 'lstat', return_value=mock.Mock(st_mode=stat.S_IFREG)):
                self.assertEqual(M.query('unused', Path('/unused'), float('inf'))[0], 'invalid_socket')
            self.assertEqual(M.query('unused', Path('/unused'), -1)[0], 'budget_exhausted')
            spawn.assert_not_called()

    def fake(self, chunks, ready=True, status=0, interrupted=False):
        process = mock.Mock()
        process.wait.return_value = status
        poll = mock.MagicMock()
        poll.__enter__.return_value = poll
        poll.select.return_value = [(None, None)] if ready else []
        patches = [mock.patch.object(Path, 'lstat', return_value=mock.Mock(st_mode=stat.S_IFSOCK)),
            mock.patch.object(M.subprocess, 'Popen', return_value=process),
            mock.patch.object(M.selectors, 'DefaultSelector', return_value=poll),
            mock.patch.object(M.os, 'read', side_effect=M.CaptureInterrupted() if interrupted else chunks)]
        for patch in patches: patch.start()
        try:
            if interrupted:
                with self.assertRaises(M.CaptureInterrupted): M.query('unused', Path('/unused'), float('inf'))
                result = None
            else:
                result = M.query('unused', Path('/unused'), float('inf'))
            process.kill.assert_called_once()
            process.wait.assert_any_call(timeout=0.5)
            process.stdout.close.assert_called_once()
            self.assertFalse(M.subprocess.Popen.call_args.kwargs['start_new_session'])
            self.assertEqual(M.subprocess.Popen.call_args.args[0][-3:], ['logs', '--limit', '400'])
            return result
        finally:
            for patch in reversed(patches): patch.stop()

    def test_success_failure_timeout_byte_limit_and_cancellation_kill_and_join(self):
        self.assertEqual(self.fake([b'abc', b'']), ('observed', b'abc'))
        self.assertEqual(self.fake([b''], status=1), ('query_failed', b''))
        self.assertEqual(self.fake([], ready=False), ('query_timeout', b''))
        self.assertEqual(self.fake([b'x' * (M.QUERY_BYTES + 1)]), ('output_bound', b''))
        self.fake([], interrupted=True)

    def test_sigterm_handler_enters_capture_finally_path(self):
        with mock.patch.object(M.signal, 'signal') as register, mock.patch.object(M, 'capture') as capture:
            M.main(['capture', '/unused', '/unused/binary', 'publish', '0'])
            capture.assert_called_once()
            self.assertEqual(register.call_args.args[0], M.signal.SIGTERM)
            with self.assertRaises(M.CaptureInterrupted): register.call_args.args[1](15, None)


class Integration(unittest.TestCase):
    def test_actual_shell_hook_preserves_failure_and_exit_cleanup_when_capture_fails(self):
        source = (HERE / 'storage-consumer-maintenance-smoke.sh').read_text()
        function = re.search(r'^private_storage_consumer_phase\(\) \{\n.*?^\}', source, re.M | re.S).group()
        # Execute only fixture shell control flow; every external command is an inert function.
        script = '\n'.join(['set -eu', 'WORK=$1', 'consumer_user=$1', 'WORKER_UID=1',
            'binary_directory=$1', 'storage_user=$1', "trap 'printf cleanup >>\"$WORK/result\"' EXIT",
            'python3() { if [ "$3" = flow-minimum ]; then printf 1; else return 1; fi; }',
            'timeout() { printf capture >>"$WORK/result"; return "$TEST_CAPTURE_STATUS"; }',
            'storage_consumer_phase_start() { return 0; }',
            'private_storage_consumer_private() { return 17; }',
            'storage_consumer_phase_finish() { printf unexpected >>"$WORK/result"; }',
            'fail() { printf "%s" "$1" >>"$WORK/result"; exit 23; }', function,
            'private_storage_consumer_phase publish'])
        with tempfile.TemporaryDirectory() as name:
            for capture_status in (1, 124, 137):
                with self.subTest(capture_status=capture_status):
                    result = subprocess.run(['/bin/sh', '-c',
                        'TEST_CAPTURE_STATUS=' + str(capture_status) + '\n' + script,
                        'inert', name], capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 23, result.stderr)
                    path = Path(name) / 'result'
                    self.assertEqual(path.read_text(), 'captureCONSUMER_APPLICATION_FAILEDcleanup')
                    path.unlink()
            result = subprocess.run(['/bin/sh', '-c', script.replace('return 17;', 'return 0;'),
                'inert', name], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(name) / 'result').read_text(), 'unexpectedcleanup')

    def test_exact_export_allowlist_staging_and_both_export_validator_paths(self):
        runner = (HERE / 'run-alpha-topology-vm.sh').read_text()
        collector = runner.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split(
            '\nGUEST_DIAGNOSTICS_PYTHON\n', 1)[0]
        module = {'__name__': 'inert_collector'}
        exec(compile(collector, 'inert-collector', 'exec'), module)
        self.assertIn(M.NAME, module['MAINTENANCE_NAMES'])
        self.assertIn(M.NAME, MAINT['EXPORT_NAMES'])
        self.assertIn('storage-consumer-failure-boundary.py',
            (HERE / 'kvm-alpha-topology.sh').read_text().split('for maintenance_script in ', 1)[1].split('; do', 1)[0])
        self.assertIn('if original_size > 131072 or original_size != len(data):', collector)
        self.assertIn('if [ "$retained" = storage-consumer-failure-boundary.json ]; then', runner)
        # Exercise the actual early collector branch, with validator subprocess mocked.
        collect = module['collect']
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            guest, opt = root / 'guest', root / 'opt'
            guest.mkdir(); opt.mkdir()
            (guest / 'alpha-output').mkdir()
            path = guest / 'alpha-output' / M.NAME
            private(path, b'{"private":"' + CANARY.encode() + b'"}')
            with mock.patch.object(module['subprocess'], 'run', side_effect=subprocess.CalledProcessError(1, 'inert')) as validate:
                archive = collect(guest, opt, 'b' * 40, 'private-storage-maintenance', 1,
                    root / 'cgroups', root / 'proc')
                self.assertTrue(validate.called)
                self.assertEqual(validate.call_args.args[0][-1], 'validate-stdin')
                import tarfile
                with tarfile.open(archive) as bundle:
                    self.assertFalse(any(item.name.endswith(M.NAME) for item in bundle.getmembers()))
            # A successful validator retains only the already bounded receipt;
            # an oversized input never reaches that validator or the archive.
            with mock.patch.object(module['subprocess'], 'run') as validate:
                archive = collect(guest, opt, 'b' * 40, 'private-storage-maintenance', 1,
                    root / 'cgroups', root / 'proc')
                self.assertTrue(validate.called)
                with tarfile.open(archive) as bundle:
                    self.assertTrue(any(item.name.endswith(M.NAME) for item in bundle.getmembers()))
            private(path, b'x' * (M.MAX_BYTES + 1))
            with mock.patch.object(module['subprocess'], 'run') as validate:
                archive = collect(guest, opt, 'b' * 40, 'private-storage-maintenance', 1,
                    root / 'cgroups', root / 'proc')
                validate.assert_not_called()
                with tarfile.open(archive) as bundle:
                    self.assertFalse(any(item.name.endswith(M.NAME) for item in bundle.getmembers()))


if __name__ == '__main__':
    unittest.main()
