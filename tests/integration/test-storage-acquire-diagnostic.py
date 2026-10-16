#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert closed helper-log projection checks; no kernel/network/request proof."""
from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'storage-acquire-diagnostic.py'
SPEC = importlib.util.spec_from_file_location('storage_acquire_diagnostic', SCRIPT)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
CANARY = 'PRIVATE_URL_PATH_ID_ADDRESS_CANARY'


def line(operation=4, kind=1, errno=111, **extra):
    fields = dict(diagnostic_code=M.MARKER, operation=operation, **{'class': kind}, errno=errno)
    fields.update(extra)
    return (json.dumps(dict(timestamp=CANARY, target=CANARY, fields=fields)) + '\n').encode()


def private(path, data=b''):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def report(rows=None):
    return dict(M.empty(), records=rows or [])


class SchemaContracts(unittest.TestCase):
    def test_all_operation_class_errno_combinations_match_closed_protocol_matrix(self):
        expected = ('socket_create', 'ipv6_only_set', 'bind', 'connect', 'poll',
            'connect_socket_error', 'socket_domain', 'socket_type', 'socket_protocol',
            'local_address', 'listener_state', 'socket_error', 'ipv6_only_get',
            'descriptor_flags', 'status_flags', 'peer_address', 'mptcp_info', 'connect_readiness')
        self.assertEqual(M.OPERATIONS, expected)
        self.assertEqual(M.CLASSES, ('io', 'timed_out', 'ambiguous_readiness'))
        for operation in range(1, 19):
            for kind in range(1, 4):
                for errno in (None, 1, 110, 4095):
                    valid = (operation == 18) == (kind == 3) and (kind != 3 or errno is None)
                    with self.subTest(operation=operation, kind=kind, errno=errno):
                        if valid:
                            value = M.record(operation, kind, errno)
                            self.assertEqual(value, dict(operation=expected[operation - 1],
                                failure_class=M.CLASSES[kind - 1], errno=errno))
                            self.assertEqual(M.validate(report([value]))['records'], [value])
                        else:
                            with self.assertRaises(ValueError): M.record(operation, kind, errno)

    def test_numeric_fields_reject_bool_float_zero_negative_oversize_and_text(self):
        for value in (True, False, 1.0, 0, -1, 19, CANARY, [], None):
            with self.subTest(operation=value), self.assertRaises(ValueError):
                M.record(value, 1, None)
        for value in (True, False, 1.0, 0, -1, 4, CANARY, [], None):
            with self.subTest(kind=value), self.assertRaises(ValueError):
                M.record(1, value, None)
        for value in (True, False, 1.0, 0, -1, 4096, CANARY, []):
            with self.subTest(errno=value), self.assertRaises(ValueError):
                M.record(1, 1, value)

    def test_empty_states_are_valid_without_event_absence_or_acceptance_claims(self):
        for state in ('observed', 'absent', 'invalid', 'unreadable', 'changed'):
            value = M.empty(state)
            self.assertEqual(M.validate(value), value)
            self.assertEqual(value['projection_complete'], state == 'observed')
            self.assertTrue(value['diagnostic_only'])
            self.assertTrue(all(value[key] is False for key in M.FALSE_FLAGS))
            self.assertEqual(value['records'], [])

    def test_unknown_fields_types_and_claims_are_rejected(self):
        replacements = {'version': True, 'kind': CANARY, 'scope': CANARY,
            'diagnostic_only': 1, 'source_state': CANARY, 'input_truncated': 0,
            'records_truncated': None, 'malformed_records': True,
            'projection_complete': 1, 'records': {}, CANARY: CANARY}
        replacements.update({key: True for key in M.FALSE_FLAGS})
        for key, value in replacements.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.validate(dict(report(), **{key: value}))
        for key in report():
            changed = report(); del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError): M.validate(changed)

    def test_record_shape_and_cross_field_completeness_are_strict(self):
        row = M.record(4, 1, 111)
        for changed in (dict(row, raw_error=CANARY), dict(row, operation=CANARY),
                        dict(row, failure_class=CANARY), dict(row, errno=False), []):
            with self.subTest(row=changed), self.assertRaises(ValueError): M.validate(report([changed]))
        for key, value in (('input_truncated', True), ('records_truncated', True), ('malformed_records', 1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.validate(dict(report(), **{key: value}))
            M.validate(dict(report(), projection_complete=False, **{key: value}))
        for state in ('absent', 'invalid', 'unreadable', 'changed'):
            for key, value in (('records', [row]), ('input_truncated', True),
                               ('records_truncated', True), ('malformed_records', 1)):
                with self.subTest(state=state, key=key), self.assertRaises(ValueError):
                    M.validate(dict(M.empty(state), **{key: value}))

    def test_json_duplicate_nonfinite_wrong_encoding_and_byte_bounds_fail_closed(self):
        for raw in (b'{"version":1,"version":1}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'\xff', b'x' * (M.MAX_BYTES + 1), CANARY, bytearray(b'{}')):
            with self.subTest(raw=repr(raw)[:60]), self.assertRaises((ValueError, UnicodeError)):
                M.decode(raw)
        with self.assertRaises(ValueError): M.validate(M.decode(b'[]'))

    def test_maximal_public_record_is_bounded_and_contains_no_raw_metadata(self):
        value = report([M.record(6, 2, 4095)] * M.MAX_RECORDS)
        raw = M.encoded(value)
        self.assertLessEqual(len(raw), M.MAX_BYTES)
        self.assertEqual(M.validate(M.decode(raw)), value)
        self.assertNotIn(CANARY.encode(), raw)
        for rows in ([M.record(4, 1, None)] * 65,):
            with self.assertRaises(ValueError): M.encoded(report(rows))
        for count in (-1, M.MAX_LINES + 1):
            with self.assertRaises(ValueError):
                M.validate(dict(report(), projection_complete=False, malformed_records=count))


class LogProjection(unittest.TestCase):
    def project(self, raw, **limits):
        with tempfile.TemporaryDirectory() as directory:
            path = private(Path(directory) / 'helper.log', raw)
            with mock.patch.multiple(M, **limits) if limits else nullcontext():
                return M.project(path)

    def test_real_json_envelope_is_projected_without_timestamp_target_or_private_fields(self):
        value = self.project(line())
        self.assertEqual(value['records'], [M.record(4, 1, 111)])
        self.assertTrue(value['projection_complete'])
        raw = M.encoded(value)
        self.assertNotIn(CANARY.encode(), raw)
        self.assertNotIn(b'timestamp', raw)
        self.assertNotIn(b'target', raw)

    def test_absent_and_explicit_null_errno_are_equivalent(self):
        event = json.loads(line(errno=None)); del event['fields']['errno']
        value = self.project(line(errno=None) + (json.dumps(event) + '\n').encode())
        self.assertEqual(value['records'], [M.record(4, 1, None)] * 2)
        self.assertTrue(value['projection_complete'])

    def test_unrelated_valid_events_never_become_acquire_records(self):
        raw = b'{}\n[]\n' + json.dumps(dict(fields={'diagnostic_code': CANARY})).encode() + b'\n'
        value = self.project(raw)
        self.assertEqual(value, M.empty())
        self.assertFalse(value['event_absence_proven'])

    def test_malformed_duplicate_nonfinite_and_private_marker_fields_are_counted_not_exported(self):
        raw = b'not-json\n\xff\n{"a":1,"a":2}\n{"fields":NaN}\n' + line(private=CANARY)
        value = self.project(raw + line())
        self.assertEqual(value['malformed_records'], 5)
        self.assertFalse(value['projection_complete'])
        self.assertEqual(value['records'], [M.record(4, 1, 111)])
        self.assertNotIn(CANARY.encode(), M.encoded(value))

    def test_invalid_typed_marker_rows_are_malformed_not_partially_salvaged(self):
        raw = b''.join((line(True), line(kind=0), line(errno=0), line(18, 1),
                        line(18, 3, 1), line(1, 3, None), line(extra=CANARY)))
        value = self.project(raw)
        self.assertEqual(value['malformed_records'], 7)
        self.assertEqual(value['records'], [])
        self.assertFalse(value['projection_complete'])

    def test_deep_json_is_bounded_and_cannot_prevent_following_valid_record(self):
        # Older JSON decoders raise RecursionError; iterative decoders still
        # reject the deeply nested operation because it is not an exact int.
        raw = (b'{"fields":{"diagnostic_code":"' + M.MARKER.encode() + b'","operation":'
               + b'[' * 2000 + b'0' + b']' * 2000 + b',"class":1}}\n')
        value = self.project(raw + line())
        self.assertEqual(value['malformed_records'], 1)
        self.assertEqual(value['records'], [M.record(4, 1, 111)])

    def test_unterminated_last_record_is_truncated_not_accepted(self):
        value = self.project(line() + line(errno=12).rstrip(b'\n'))
        self.assertEqual(value['records'], [M.record(4, 1, 111)])
        self.assertTrue(value['input_truncated'])
        self.assertFalse(value['projection_complete'])

    def test_oversized_line_is_discarded_whole_and_next_record_survives(self):
        raw = b'P' * (M.MAX_LINE + 1) + line() + line(errno=12)
        value = self.project(raw)
        self.assertTrue(value['input_truncated'])
        self.assertEqual(value['records'], [M.record(4, 1, 12)])

    def test_input_tail_discards_partial_first_line_and_retains_full_last_record(self):
        tail = line(errno=12)
        value = self.project(b'P' * 400 + b'\n' + tail, MAX_INPUT=len(tail) + 5)
        self.assertTrue(value['input_truncated'])
        self.assertEqual(value['records'], [M.record(4, 1, 12)])
        self.assertFalse(value['projection_complete'])

    def test_line_count_bound_sets_incomplete_without_parsing_unbounded_tail(self):
        value = self.project(b'{}\n' * 3 + line(), MAX_LINES=3)
        self.assertTrue(value['input_truncated'])
        self.assertEqual(value['records'], [])
        self.assertFalse(value['projection_complete'])

    def test_ring_retains_latest_64_without_inferring_operation_or_request_identity(self):
        value = self.project(b''.join(line(errno=n) for n in range(1, 67)))
        self.assertEqual([row['errno'] for row in value['records']], list(range(3, 67)))
        self.assertTrue(value['records_truncated'])
        self.assertFalse(value['projection_complete'])
        self.assertTrue(all(value[key] is False for key in M.FALSE_FLAGS))


class PrivateFileContracts(unittest.TestCase):
    def test_absent_private_empty_file_and_regular_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'helper.log'
            self.assertEqual(M.project(path), M.empty('absent'))
            private(path)
            self.assertEqual(M.project(path), M.empty())
            private(path, line())
            self.assertEqual(M.project(path)['records'], [M.record(4, 1, 111)])

    def test_wrong_modes_or_owner_are_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = private(Path(directory) / 'helper.log', line())
            for mode in (0o644, 0o400, 0o660, 0o600 | stat.S_ISUID):
                path.chmod(mode)
                self.assertEqual(M.project(path), M.empty('invalid'))
            path.chmod(0o600)
            with mock.patch.object(M.os, 'geteuid', return_value=os.geteuid() + 1):
                self.assertEqual(M.project(path), M.empty('invalid'))

    def test_symlink_directory_and_fifo_are_not_followed_or_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = private(root / 'target', line())
            link = root / 'link'; link.symlink_to(target)
            fifo = root / 'fifo'; os.mkfifo(fifo, 0o600)
            self.assertEqual(M.project(link), M.empty('unreadable'))
            self.assertEqual(M.project(root), M.empty('invalid'))
            self.assertEqual(M.project(fifo), M.empty('invalid'))
            self.assertEqual(target.read_bytes(), line())

    def test_open_error_is_closed_unreadable(self):
        with mock.patch.object(M.os, 'open', side_effect=PermissionError(CANARY)):
            value = M.project(Path('/not-read'))
        self.assertEqual(value, M.empty('unreadable'))
        self.assertNotIn(CANARY.encode(), M.encoded(value))

    def test_rejected_file_and_fdopen_failure_close_original_descriptor(self):
        for reader in (M.project, M.read):
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as directory:
                opened = []
                original_open = M.os.open
                def remember(*args, **kwargs):
                    fd = original_open(*args, **kwargs); opened.append(fd); return fd
                with mock.patch.object(M.os, 'open', side_effect=remember):
                    if reader is M.project:
                        self.assertEqual(reader(Path(directory)), M.empty('invalid'))
                    else:
                        with self.assertRaises(ValueError): reader(Path(directory))
                with self.assertRaises(OSError): os.fstat(opened[0])
                path = private(Path(directory) / 'input', M.encoded(M.empty()))
                with mock.patch.object(M.os, 'open', side_effect=remember), \
                        mock.patch.object(M.os, 'fdopen', side_effect=OSError(CANARY)):
                    if reader is M.project:
                        self.assertEqual(reader(path), M.empty('unreadable'))
                    else:
                        with self.assertRaises(OSError): reader(path)
                with self.assertRaises(OSError): os.fstat(opened[-1])

    def test_changed_fd_metadata_discards_all_projected_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = private(Path(directory) / 'helper.log', line())
            fstat = M.os.fstat
            calls = 0
            def changed(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    with path.open('ab') as output: output.write(b'{}\n')
                return fstat(fd)
            with mock.patch.object(M.os, 'fstat', side_effect=changed):
                self.assertEqual(M.project(path), M.empty('changed'))

    def test_replaced_or_removed_path_is_changed_even_when_old_fd_stays_stable(self):
        for replace in (False, True):
            with self.subTest(replace=replace), tempfile.TemporaryDirectory() as directory:
                path = private(Path(directory) / 'helper.log', line())
                inspect = M.os.stat
                def changed(target, **kwargs):
                    path.unlink()
                    if replace: private(path, b'{}\n')
                    return inspect(target, **kwargs)
                with mock.patch.object(M.os, 'stat', side_effect=changed):
                    self.assertEqual(M.project(path), M.empty('changed'))


class PublicationContracts(unittest.TestCase):
    def test_atomic_publication_is_closed_0600_and_has_no_private_sidefiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private(root / 'helper-client.log', line())
            self.assertTrue(M.publish(root))
            target = root / M.NAME
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(set(p.name for p in root.iterdir()), {'helper-client.log', M.NAME})
            value = M.read(target)
            self.assertEqual(value['records'], [M.record(4, 1, 111)])
            self.assertNotIn(CANARY, target.read_text())

    def test_absent_log_publishes_missing_not_absence_or_cleanup_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(M.publish(root))
            self.assertEqual(M.read(root / M.NAME), M.empty('absent'))

    def test_existing_part_is_not_overwritten_or_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            part = private(root / 'maintenance-helper-acquire.part', CANARY.encode())
            self.assertFalse(M.publish(root))
            self.assertEqual(part.read_bytes(), CANARY.encode())
            self.assertFalse((root / M.NAME).exists())

    def test_publication_failure_cleans_only_owned_part_and_never_raises(self):
        for error in (PermissionError(CANARY), KeyboardInterrupt(CANARY)):
            with self.subTest(error=type(error)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                old = private(root / M.NAME, b'old public receipt')
                with mock.patch.object(M.os, 'replace', side_effect=error):
                    self.assertFalse(M.publish(root))
                self.assertEqual(old.read_bytes(), b'old public receipt')
                self.assertFalse((root / 'maintenance-helper-acquire.part').exists())

    def test_public_reader_rejects_symlink_oversize_and_invalid_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = private(root / 'report', M.encoded(M.empty()))
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaises(OSError): M.read(link)
            for raw in (b'', b'x' * (M.MAX_BYTES + 1), b'{"secret":"PRIVATE"}'):
                private(target, raw)
                with self.assertRaises(ValueError): M.read(target)

    def test_cli_strict_input_and_fixed_errors_never_echo_private_values(self):
        for raw, status in ((M.encoded(M.empty()), 0), (M.encoded(M.empty('absent')), 0),
                            (CANARY.encode(), 1), (b'x' * (M.MAX_BYTES + 1), 1),
                            (b'{"version":1,"version":1}', 1), (b'{"x":NaN}', 1)):
            result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), 'validate-stdin'],
                input=raw, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, status)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'' if status == 0 else b'invalid helper acquire diagnostic\n')
        result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), CANARY],
            input=b'', capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout + result.stderr, b'expected validate-stdin\n')

    def test_harness_export_allows_only_valid_closed_sidecar(self):
        for raw, accepted in ((None, False), (CANARY.encode(), False),
                               (M.encoded(M.empty()), True), (M.encoded(M.empty('changed')), True)):
            with tempfile.TemporaryDirectory() as directory:
                if raw is not None: private(Path(directory) / M.NAME, raw)
                result = subprocess.run([sys.executable, '-B',
                    str(HERE / 'private-storage-maintenance-smoke.py'), 'export-names', directory],
                    capture_output=True, timeout=5, check=True)
                self.assertEqual(M.NAME.encode() in result.stdout.splitlines(), accepted)
                self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)

    def test_harness_optional_projection_cannot_replace_original_phase_exception(self):
        module = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
        function = module['export_helper_acquire']
        for failure in (OSError(CANARY), KeyboardInterrupt(CANARY)):
            original = ValueError('original phase error')
            with mock.patch.object(function.__globals__['runpy'], 'run_path', side_effect=failure):
                with self.assertRaises(ValueError) as caught:
                    try:
                        raise original
                    finally:
                        function(Path('/not-read'))
            self.assertIs(caught.exception, original)


if __name__ == '__main__':
    unittest.main()
