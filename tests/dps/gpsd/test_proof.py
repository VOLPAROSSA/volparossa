#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only Python contracts; no GPSD binary, physical sensor or network needed."""
from datetime import datetime, timezone
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from build import (PYTHON_CARRIER, SANITIZERS, TARGETS, build_argv, build_environment,
                   compile_observation, download, effective_profile, unpack)
from common import CommandFailure, command, pins, strict_json
from fixture import fixture, sentence
from prove import (LIMITATIONS, failure_diagnostic, isolation, loopback_only,
                   public_tpv_summary, quality, terminate_diagnostic, write_case_receipt)


def valid_quality():
    return {'schema_version': 1, 'quality': 'SingleClaim', 'candidate_present': True,
            'declared_independence_groups': 1, 'eligible_claims': 1,
            'limitations': sorted(LIMITATIONS),
            'provenance': {'input': 'gpsd_tpv',
                           'profile': 'operator_asserted_wgs84_receiver_ellipsoidal',
                           'complete_distinct_epochs': 3, 'physical_datum_verified': False,
                           'uncertainty_confidence': 'unknown', 'navigation_authentication': 'unknown'}}


class Contracts(unittest.TestCase):
    def test_source_and_support_closure_fixed(self):
        value = pins()
        self.assertEqual(value['version'], '3.25-5+deb13u2')
        self.assertEqual(len(value['sources']), 4)
        self.assertEqual(len(value['series']), 11)
        self.assertEqual({p['package']: p['version'] for p in value['support_packages']},
                         {'scons': '4.5.2+dfsg-1', 'python3-setuptools': '68.1.2-2ubuntu1.2',
                          'python3-pkg-resources': '68.1.2-2ubuntu1.2'})

    def test_private_carrier_is_fixed_python_and_compiler_is_explicit(self):
        ast.parse(PYTHON_CARRIER)
        self.assertTrue(PYTHON_CARRIER.startswith('#!/usr/bin/python3\n'))
        self.assertIn("site.addsitedir(support)", PYTHON_CARRIER)
        self.assertEqual(build_environment()['CC'], '/usr/bin/clang')
        self.assertNotIn('LD_LIBRARY_PATH', build_environment())

    def test_native_sanitizer_findings_fail_without_runtime_environment_options(self):
        flags = shlex.split(SANITIZERS)
        self.assertIn('-fsanitize=address,undefined', flags)
        self.assertIn('-fno-sanitize-recover=all', flags)
        self.assertFalse(any(flag.startswith('-fsanitize-recover') for flag in flags))

    def test_actual_scons_argv_omits_presence_profiles_and_requires_client_nmea_targets(self):
        for kind in ('normal', 'sanitized'):
            argv = build_argv(Path('/private'), Path('/private/support/usr/bin/scons'), kind)
            self.assertFalse(any(arg.split('=', 1)[0] in {'timeservice', 'minimal'} for arg in argv))
            for option in ['gpsd=yes', 'gpsdclients=yes', 'ashtech=yes', 'socket_export=yes',
                           'shared=no', 'magic_hat=no', 'shm_export=no']:
                self.assertIn(option, argv)
            self.assertIn('gpsd-3.25/gpsd/gpsd', argv)
            self.assertIn('gpsd-3.25/clients/gpspipe', argv)
            self.assertEqual(argv[-len(TARGETS[kind]):], TARGETS[kind])
        self.assertIn('gpsd-3.25/gpsfake', build_argv(Path('/private'), Path('/scons'), 'normal'))

    def test_compile_observation_requires_real_client_codegen_and_fatal_flags_on_every_unit(self):
        files = ['gpsd-3.25/gpsd/gpsd.c', 'gpsd-3.25/clients/gpspipe.c',
                 'gpsd-3.25/drivers/driver_nmea0183.c']
        lines = ['/usr/bin/clang -o output.o -c ' + SANITIZERS + ' ' + name for name in files]
        for output in ['gpsd-3.25/gpsd/gpsd', 'gpsd-3.25/clients/gpspipe']:
            lines.append('/usr/bin/clang -o ' + output +
                         ' -fsanitize=address,undefined object.o gpsd-3.25/libgps_static.a -lm')
        raw = ('\n'.join(lines) + '\n').encode()
        self.assertEqual(compile_observation(raw, 'sanitized')['compiled_units'], 3)
        with self.assertRaises(ValueError):
            compile_observation(raw.replace(b'-fno-sanitize-recover=all', b'', 1), 'sanitized')
        with self.assertRaises(ValueError):
            compile_observation(raw.replace(b'gpsd-3.25/clients/gpspipe.c', b'gpsd-3.25/other.c'), 'sanitized')
        with self.assertRaises(ValueError):
            compile_observation(raw.replace(b'libgps_static.a', b'libgps.so'), 'sanitized')

    def test_effective_generated_profile_rejects_time_service_or_missing_nmea(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / 'gpsd-3.25/include/gpsd_config.h'
            header.parent.mkdir(parents=True)
            expected = '\n'.join('#define ' + key + '_ENABLE 1' for key in
                                 ['GPSD', 'GPSDCLIENTS', 'ASHTECH', 'SOCKET_EXPORT']) + '\n'
            header.write_text(expected)
            self.assertIn('ASHTECH', effective_profile(root)['required_features_enabled'])
            header.write_text(expected + '#define TIMESERVICE_ENABLE 1\n')
            with self.assertRaises(ValueError):
                effective_profile(root)
            header.write_text(expected.replace('#define ASHTECH_ENABLE 1\n', ''))
            with self.assertRaises(ValueError):
                effective_profile(root)

    def test_public_tpv_diagnostic_never_merges_frames_or_claims_product_acceptance(self):
        partial = [{'class': 'TPV', 'mode': 3, 'lat': 0.0, 'lon': 0.0},
                   {'class': 'TPV', 'altHAE': 10.0, 'datum': 'WGS84'},
                   {'class': 'TPV', 'time': '2026-10-28T12:00:00Z', 'device': '/dev/pts/PUBLIC'}]
        raw = b'\n'.join(json.dumps(item).encode() for item in partial)
        summary = public_tpv_summary(raw)
        self.assertEqual(summary['shape_complete_distinct_times'], 0)
        self.assertFalse(summary['product_acceptance'])
        self.assertTrue(summary['shape_summary_only'])
        complete = {'class': 'TPV', 'mode': 3, 'lat': 0.0, 'lon': 0.0, 'altHAE': 10.0,
                    'datum': 'WGS84', 'device': '/dev/pts/PUBLIC', 'time': '2026-10-28T12:00:00Z'}
        raw = (json.dumps(complete) + '\n' + json.dumps(complete)).encode()
        self.assertEqual(public_tpv_summary(raw)['shape_complete_distinct_times'], 1)

    def test_public_tpv_diagnostic_bounds_and_invalid_rows_remain_explicit(self):
        for raw in [b'{}\n' * 33, b'x' * 10241, b'x' * 327681]:
            with self.assertRaises(ValueError):
                public_tpv_summary(raw)
        raw = b'{"class":"TPV","class":"VERSION"}\n{"class":"TPV","lat":NaN}\n'
        summary = public_tpv_summary(raw)
        self.assertEqual(summary['non_json_or_invalid_rows'], 2)
        self.assertEqual(summary['shape_complete_distinct_times'], 0)
        self.assertFalse(summary['product_acceptance'])

    def test_separate_diagnostic_requires_all_five_retained_cleanup_booleans(self):
        cleanup = dict(gpsfake_direct_child_reaped=True, observed_native_children_gone=True,
                       namespace_children_reaped=True, listener_closed=True, private_state_removed=True)
        with tempfile.TemporaryDirectory() as directory, patch('prove.diagnose_public_tpv') as diagnostic:
            evidence = Path(directory)
            path = evidence / 'normal-positive-cleanup.json'
            deadline = time.monotonic() + 60
            self.assertEqual(failure_diagnostic('normal', 'positive', {}, evidence, deadline)['reason'],
                             'original_cleanup_unconfirmed')
            for key in cleanup:
                for refused in (False, 1, None):
                    with self.subTest(key=key, value=refused):
                        path.write_text(json.dumps(dict(cleanup, **{key: refused})))
                        self.assertEqual(failure_diagnostic('normal', 'positive', {}, evidence, deadline)['status'],
                                         'skipped')
            diagnostic.assert_not_called()
            path.write_text(json.dumps(cleanup))
            diagnostic.return_value = {'status': 'observed', 'product_acceptance': False}
            self.assertEqual(failure_diagnostic('normal', 'positive', {}, evidence, deadline)['status'], 'observed')
            diagnostic.assert_called_once_with('normal', {}, evidence, deadline)
            diagnostic.reset_mock()
            self.assertEqual(failure_diagnostic('normal', 'positive', {}, evidence, time.monotonic())['reason'],
                             'original_budget_unavailable')
            diagnostic.assert_not_called()

    def test_case_receipt_storage_failure_preserves_primary_but_fails_on_success(self):
        primary = CommandFailure('primary Core command failure')
        with patch('prove.write_json', side_effect=OSError('fixture receipt storage unavailable')):
            try:
                try:
                    raise primary
                finally:
                    write_case_receipt(Path('/unused'), {'observed': True})
            except CommandFailure as observed:
                self.assertIs(observed, primary)
            else:
                self.fail('pending primary failure was swallowed')
            with self.assertRaises(OSError):
                write_case_receipt(Path('/unused'), {'observed': True})

    def test_diagnostic_cleanup_has_one_owner_and_never_waits_past_end(self):
        class Child:
            pid = 4242
            def __init__(self):
                self.waits = []
            def wait(self, timeout):
                self.waits.append(timeout)
                raise subprocess.TimeoutExpired('synthetic-child', timeout)
            def poll(self):
                return None
        with patch('prove.os.killpg') as kill, patch('prove.time.monotonic', side_effect=[9.75, 10.0]):
            child = Child()
            self.assertFalse(terminate_diagnostic(child, 10.0))
            self.assertEqual(child.waits, [0.25])
            self.assertEqual(kill.call_count, 2)
        with patch('prove.os.killpg') as kill, patch('prove.time.monotonic', return_value=10.0):
            child = Child()
            self.assertFalse(terminate_diagnostic(child, 10.0))
            self.assertEqual(child.waits, [])
            self.assertEqual(kill.call_count, 2)

    def test_private_carrier_executes_exact_upstream_compile_without_executing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            carrier = root / 'python'
            carrier.write_text(PYTHON_CARRIER)
            carrier.chmod(0o700)
            support = root / 'support/usr/lib/python3/dist-packages'
            support.mkdir(parents=True)
            (support / 'private_carrier_probe.py').write_text('TOKEN = "private-support"\n')
            source = root / 'tmp.py'
            source.write_text('from pathlib import Path\nPath("executed").write_text("must not run")\n')
            env = {'PATH': '/usr/bin:/bin', 'PYTHONNOUSERSITE': '1'}
            command([str(carrier), '-tt', '-m', 'py_compile', 'tmp.py'], cwd=root,
                    env=env, deadline=time.monotonic() + 5, log_path=root / 'compile-ok.log', limit=65536)
            self.assertFalse((root / 'executed').exists())
            self.assertTrue(list((root / '__pycache__').glob('tmp.*.pyc')))
            source.write_text('def invalid(:\n')
            with self.assertRaises(CommandFailure):
                command([str(carrier), '-tt', '-m', 'py_compile', 'tmp.py'], cwd=root,
                        env=env, deadline=time.monotonic() + 5, log_path=root / 'compile-error.log', limit=65536)
            self.assertIn(b'SyntaxError', (root / 'compile-error.log').read_bytes())
            for index, arguments in enumerate([['-m', 'py_compile', 'tmp.py'],
                    ['-tt', '-m', 'json.tool', 'tmp.py'], ['-tt', '-m', 'py_compile', 'other.py']]):
                with self.subTest(arguments=arguments), self.assertRaises(CommandFailure):
                    command([str(carrier), *arguments], cwd=root, env=env,
                            deadline=time.monotonic() + 5, log_path=root / ('denied-' + str(index) + '.log'), limit=65536)
            check = root / 'check.py'
            check.write_text('import private_carrier_probe\nprint(private_carrier_probe.TOKEN)\n')
            raw = command([str(carrier), str(check)], cwd=root, env=env,
                          deadline=time.monotonic() + 5, log_path=root / 'private-support.log', limit=65536)
            self.assertEqual(raw, b'private-support\n')

    def test_public_fixture_direct_hae_not_msl(self):
        raw = fixture(datetime(2026, 10, 28, 12, 0, 4, tzinfo=timezone.utc))
        self.assertNotIn(b'GGA', raw)
        self.assertEqual(raw.count(b'$PASHR,POS,0,08,'), 3)
        self.assertEqual(raw.count(b'$GPDTM,W84,'), 3)
        self.assertIn(b',120001.00,', raw)
        self.assertIn(b',120002.00,', raw)
        self.assertIn(b',120003.00,', raw)
        self.assertLess(len(raw), 4096)

    def test_fixture_checksums_and_no_future_epoch(self):
        raw = fixture(datetime(2026, 10, 28, 12, 0, 4, tzinfo=timezone.utc))
        for line in raw.splitlines()[1:]:
            body = line[1:].split(b'*')[0]
            expected = 0
            for byte in body:
                expected ^= byte
            self.assertEqual(int(line.split(b'*')[1], 16), expected)
            self.assertNotIn(b'120004', line)

    def test_midnight_fixture_carries_per_epoch_dates(self):
        raw = fixture(datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc))
        self.assertIn(b'311225', raw)
        self.assertIn(b'010126', raw)

    def test_unknown_datum_and_absent_height_have_separate_fixtures(self):
        now = datetime(2026, 10, 28, 12, 0, 4, tzinfo=timezone.utc)
        self.assertEqual(fixture(now, 'unknown_datum').count(b'$GPDTM,W72,'), 3)
        self.assertEqual(fixture(now, 'missing_height').count(b',E,,,0.0,'), 3)

    def test_fixture_denies_injection_and_unrecognized_scenario(self):
        for body in ['GPDTM,W84\n$PASHR', '$GPDTM', 'a' * 241]:
            with self.assertRaises(ValueError):
                sentence(body)
        with self.assertRaises(ValueError):
            fixture(datetime.now(timezone.utc), 'arbitrary')
        with self.assertRaises(ValueError):
            fixture(datetime(2026, 10, 28))

    def test_json_duplicate_and_nonfinite_rejected(self):
        for raw in ['{"status":true,"status":false}', '{"radius":NaN}',
                    '{"radius":Infinity}', '{"radius":1e999}']:
            with self.assertRaises(ValueError):
                strict_json(raw)

    def test_quality_remains_claim_with_all_limitations(self):
        self.assertEqual(quality(valid_quality())['eligible_claims'], 1)
        for key, value in [('physical_datum_verified', True),
                           ('navigation_authentication', 'verified'),
                           ('uncertainty_confidence', '95%')]:
            candidate = valid_quality()
            candidate['provenance'][key] = value
            with self.assertRaises(ValueError):
                quality(candidate)

    def test_quality_rejects_location_history_and_missing_limitations(self):
        value = valid_quality()
        value['latitude'] = 0
        with self.assertRaises(ValueError):
            quality(value)
        value = valid_quality()
        value['limitations'][0] = value['limitations'][1]
        with self.assertRaises(ValueError):
            quality(value)

    def test_current_namespace_is_not_isolation(self):
        with patch('prove.hosted'), patch.dict(os.environ, {
                'VOLPAROSSA_DPS_GPSD_PARENT_NETNS': os.readlink('/proc/self/ns/net')}):
            with self.assertRaises(ValueError):
                isolation(os.readlink('/proc/self/ns/ipc'), os.readlink('/proc/self/ns/pid'))

    def test_private_loopback_rejects_external_device_and_ipv4_default(self):
        devices = 'header\nheader\n lo: 0\n'
        loopback_only(devices, 'header\n', '')
        with self.assertRaises(ValueError):
            loopback_only(devices + ' eth0: 0\n', 'header\n', '')
        with self.assertRaises(ValueError):
            loopback_only(devices, 'header\nlo 00000000 00000000 0001 0 0 0 00000000 0 0 0\n', '')

    def test_ipv6_unreachable_sentinel_is_not_egress_default(self):
        row = '0' * 32 + ' 00 ' + '0' * 32 + ' 00 ' + '0' * 32 + ' ffffffff 00000000 00000000 00200200 lo\n'
        loopback_only('header\nheader\n lo: 0\n', 'header\n', row)
        with self.assertRaises(ValueError):
            loopback_only('header\nheader\n lo: 0\n', 'header\n', row.replace('00200200', '00000001'))

    def archive_case(self, name, kind=tarfile.REGTYPE, size=1):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'input.tar'
            with tarfile.open(archive, 'w') as output:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = size if kind == tarfile.REGTYPE else 0
                member.linkname = '/tmp/outside'
                output.addfile(member, io.BytesIO(b'x' * member.size))
            destination = root / 'out'
            destination.mkdir()
            unpack(archive, destination, 'expected')
            return (destination / 'expected/file').read_bytes()

    def test_source_archive_valid_regular_file(self):
        self.assertEqual(self.archive_case('expected/file'), b'x')

    def test_source_archive_denies_traversal_absolute_and_other_root(self):
        for name in ['expected/../../outside', '/tmp/outside', 'other/file']:
            with self.assertRaises(ValueError):
                self.archive_case(name)

    def test_source_archive_denies_links_and_special_files(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE]:
            with self.assertRaises(ValueError):
                self.archive_case('expected/file', kind)

    def test_download_digest_and_size_fail_closed(self):
        class Response(io.BytesIO):
            def geturl(self):
                return 'https://example.invalid/source'
        with tempfile.TemporaryDirectory() as directory:
            item = {'url': 'https://example.invalid/source', 'size': 2,
                    'sha256': hashlib.sha256(b'xx').hexdigest()}
            with patch('urllib.request.urlopen', return_value=Response(b'no')):
                with self.assertRaises(ValueError):
                    download(item, Path(directory), time.monotonic() + 2)

    def test_download_rejects_redirect(self):
        class Response(io.BytesIO):
            def geturl(self):
                return 'https://other.invalid/source'
        with tempfile.TemporaryDirectory() as directory:
            with patch('urllib.request.urlopen', return_value=Response(b'x')):
                with self.assertRaises(ValueError):
                    download({'url': 'https://example.invalid/source', 'size': 1,
                              'sha256': hashlib.sha256(b'x').hexdigest()},
                             Path(directory), time.monotonic() + 2)

    def test_command_nonzero_distinct_from_bound_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(CommandFailure):
                command([sys.executable, '-c', 'raise SystemExit(7)'], cwd=root,
                        env={'PATH': '/usr/bin:/bin'}, deadline=time.monotonic() + 3,
                        log_path=root / 'nonzero.log')
            with self.assertRaises(ValueError) as failure:
                command([sys.executable, '-c', 'print("x" * 10000)'], cwd=root,
                        env={'PATH': '/usr/bin:/bin'}, deadline=time.monotonic() + 3,
                        log_path=root / 'bounded.log', limit=1024)
            self.assertNotIsInstance(failure.exception, CommandFailure)
            self.assertLessEqual((root / 'bounded.log').stat().st_size, 1024)

    def test_command_deadline_reaps_direct_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pids = []
            with self.assertRaises(TimeoutError):
                command([sys.executable, '-c', 'import time; time.sleep(60)'], cwd=root,
                        env={'PATH': '/usr/bin:/bin'}, deadline=time.monotonic() + 0.2,
                        log_path=root / 'timeout.log', observer=lambda child: pids.append(child.pid))
            self.assertTrue(pids)
            self.assertFalse(Path('/proc', str(pids[0])).exists())

    def test_observer_failure_is_not_an_expected_negative_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            pids = []
            def reject(child):
                pids.append(child.pid)
                raise ValueError('observer rejected child binding')
            with self.assertRaises(ValueError) as failure:
                command([sys.executable, '-c', 'import time; time.sleep(60)'], cwd=directory,
                        env={'PATH': '/usr/bin:/bin'}, deadline=time.monotonic() + 3,
                        log_path=Path(directory) / 'observer.log', observer=reject)
            self.assertNotIsInstance(failure.exception, CommandFailure)
            self.assertFalse(Path('/proc', str(pids[0])).exists())


if __name__ == '__main__':
    unittest.main()
