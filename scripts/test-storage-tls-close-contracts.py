#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert controls: no commands, network namespaces or host observations execute."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location('tls_contracts', Path(__file__).with_name('storage-tls-close-contracts.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def environment():
    return dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
                RUNNER_OS='Linux', RUNNER_ARCH='X64', GITHUB_REPOSITORY='VOLPAROSSA/volparossa',
                VOLPAROSSA_TEST_ALLOW_SUDO_NETNS='1', GITHUB_SHA='a' * 40,
                GITHUB_WORKFLOW_SHA='b' * 40, RUNNER_TEMP='/inert/temp',
                GITHUB_WORKFLOW_REF='VOLPAROSSA/volparossa/.github/workflows/quality.yml@refs/pull/1/merge')


def inventory(name):
    return (name + ': test\n\n1 test, 0 benchmarks\n').encode()


def success(name):
    return (f'running 1 test\ntest {name} ... ok\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.05s\n').encode()


class Contracts(unittest.TestCase):
    def setUp(self):
        forbidden = patch.object(M.subprocess, 'Popen', side_effect=AssertionError('inert test executed a command'))
        forbidden.start()
        self.addCleanup(forbidden.stop)

    def test_deadline_kills_group_before_reaping_even_if_leader_already_exited(self):
        child = MagicMock(pid=4242)
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {'inert-pipe': object()}
        ordering = []
        child.wait.side_effect = lambda **_: ordering.append('reap')
        with patch.object(M.subprocess, 'Popen', return_value=child), \
             patch.object(M.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(M.os, 'set_blocking'), \
             patch.object(M.time, 'monotonic', side_effect=[0, 20]), \
             patch.object(M.os, 'killpg', side_effect=lambda *_: ordering.append('kill')) as kill:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                M.command(['inert'])
        kill.assert_called_once_with(4242, M.signal.SIGKILL)
        self.assertEqual(ordering, ['kill', 'reap'])
        child.poll.assert_not_called()

    def test_guard_rejects_host_root_wrong_repository_and_missing_explicit_authority(self):
        env = environment()
        M.guard(env, 1001)
        for key in env:
            changed = dict(env); changed.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.guard(changed, 1001)
        with self.assertRaises(ValueError):
            M.guard(env, 0)
        for key, value in (('GITHUB_SHA', 'a' * 39), ('RUNNER_TEMP', 'relative'),
                           ('GITHUB_WORKFLOW_REF', 'another/workflow@main'),
                           ('VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS', 'net:[1]')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.guard({**env, key: value}, 1001)

    def test_source_receipt_binds_checked_out_blobs_and_records_workflow_separately(self):
        def git(argv, **_):
            args = argv[1:]
            if args == ['rev-parse', 'HEAD']:
                return b'a' * 40 + b'\n'
            if args[:1] == ['status']:
                return b''
            if args[:1] == ['ls-files']:
                return b'tests/integration/storage-consumer-maintenance-pins.json\n'
            return b'c' * 40 + b'\n'
        with patch.object(M, 'checked', side_effect=git):
            receipt = M.source_receipt(environment())
        self.assertEqual(receipt['source_commit'], 'a' * 40)
        self.assertEqual(receipt['workflow_commit'], 'b' * 40)
        self.assertIn(M.RUNNER, receipt['source_blobs'])
        self.assertIn('tests/integration/storage-consumer-maintenance-pins.json', receipt['source_blobs'])
        for mutation in ('head', 'dirty', 'blob', 'pins'):
            def changed(argv, **kwargs):
                if mutation == 'head' and argv[1:] == ['rev-parse', 'HEAD']:
                    return b'd' * 40
                if mutation == 'dirty' and argv[1] == 'status':
                    return b' M Cargo.lock\n'
                if mutation == 'blob' and argv[1] == 'hash-object':
                    return b'd' * 40
                if mutation == 'pins' and argv[1] == 'ls-files':
                    return b''
                return git(argv, **kwargs)
            with self.subTest(mutation=mutation), patch.object(M, 'checked', side_effect=changed), self.assertRaises(ValueError):
                M.source_receipt(environment())

    def test_build_receipt_requires_exact_successful_regular_agent_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'target'; target.mkdir()
            binary = target / 'agent'; binary.write_bytes(b'inert'); binary.chmod(0o700)
            rows = [dict(reason='compiler-artifact', target=dict(name='volparossa_agent', kind=['lib']),
                         profile=dict(test=True), executable=str(binary)),
                    dict(reason='build-finished', success=True)]
            def encode(value):
                return b'\n'.join(json.dumps(row).encode() for row in value)
            self.assertEqual(M.build_binary(encode(rows), target), binary)
            for mutation in ('duplicate', 'incomplete', 'failed', 'wrong-target', 'not-test', 'outside', 'nonboolean'):
                changed = copy.deepcopy(rows)
                if mutation == 'duplicate': changed.insert(0, changed[0])
                elif mutation == 'incomplete': changed.pop()
                elif mutation == 'failed': changed[-1]['success'] = False
                elif mutation == 'wrong-target': changed[0]['target']['name'] = 'another'
                elif mutation == 'not-test': changed[0]['profile']['test'] = False
                elif mutation == 'outside':
                    outside = root / 'other'; outside.write_bytes(b'inert'); outside.chmod(0o700)
                    changed[0]['executable'] = str(outside)
                else: changed[-1]['success'] = 1
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    M.build_binary(encode(changed), target)
            link = target / 'link'; link.symlink_to(binary); rows[0]['executable'] = str(link)
            with self.assertRaises(ValueError): M.build_binary(encode(rows), target)
            with self.assertRaises(ValueError): M.build_binary(b'{truncated', target)

    def test_exact_inventory_rejects_zero_duplicate_and_substituted_cases(self):
        name = M.TESTS[0]
        M.validate_inventory(inventory(name), name)
        for raw in (b'0 tests, 0 benchmarks\n', inventory(name) * 2, inventory(M.TESTS[1])):
            with self.assertRaises(ValueError): M.validate_inventory(raw, name)

    def test_results_reject_false_success_skips_failure_and_wrong_identity(self):
        name = M.TESTS[0]; raw = success(name)
        M.validate_result(raw, name, 0)
        for bad, status in ((raw, 1), (raw * 2, 0), (success(M.TESTS[1]), 0),
                            (raw.replace(b'1 passed', b'0 passed'), 0),
                            (raw.replace(b'0 ignored', b'1 ignored'), 0),
                            (raw.replace(b'0 failed', b'1 failed'), 0)):
            with self.assertRaises(ValueError): M.validate_result(bad, name, status)

    def test_original_48_normalizer_controls_and_quoted_counter_preservation(self):
        self.assertEqual(M.normalizer_controls(), 48)
        raw = b'-A INPUT -m comment --comment "[1:2]" -j ACCEPT\n'
        self.assertEqual(M.normalize_firewall(raw), raw)
        self.assertNotEqual(M.normalize_firewall(raw), M.normalize_firewall(raw.replace(b'1:2', b'9:9')))
        for raw in (b'"unterminated\n', b'escaped\\\n'):
            with self.assertRaises(ValueError): M.normalize_firewall(raw)

    def test_after_snapshot_runs_and_failure_receipt_survives_both_test_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            with patch.object(M, 'observe', return_value={'parent_namespace': 'same'}) as observe, \
                 patch.object(M, 'checked', side_effect=lambda argv: inventory(argv[-2])), \
                 patch.object(M, 'command', return_value=(1, b'failed')):
                with self.assertRaises(ValueError): M.execute(Path('/inert/binary'), destination, {}, lambda: True)
            self.assertEqual(observe.call_count, 2)
            receipt = json.loads((destination / 'result.json').read_text())
            self.assertFalse(receipt['passed'])
            self.assertTrue(receipt['host_unchanged'])
            self.assertEqual(receipt['errors'], ['kernel-0-failed', 'kernel-1-failed'])
            self.assertTrue((destination / 'host-after.json').is_file())

    def test_host_change_or_unavailable_after_snapshot_cannot_pass(self):
        for after in ({'parent_namespace': 'changed'}, ValueError('observation failed')):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary)
                with patch.object(M, 'observe', side_effect=[{'parent_namespace': 'before'}, after]), \
                     patch.object(M, 'checked', side_effect=lambda argv: inventory(argv[-2])), \
                     patch.object(M, 'command', side_effect=lambda argv, _: (0, success(argv[-2]))):
                    with self.assertRaises(ValueError): M.execute(Path('/inert/binary'), destination, {}, lambda: True)
                receipt = json.loads((destination / 'result.json').read_text())
                self.assertFalse(receipt['passed'])
                self.assertFalse(receipt['host_unchanged'])
                self.assertEqual(receipt['executed_tests'], list(M.TESTS))

    def test_success_remains_bounded_kernel_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            with patch.object(M, 'observe', return_value={'parent_namespace': 'same'}), \
                 patch.object(M, 'checked', side_effect=lambda argv: inventory(argv[-2])), \
                 patch.object(M, 'command', side_effect=lambda argv, _: (0, success(argv[-2]))):
                M.execute(Path('/inert/binary'), destination, {}, lambda: True)
            receipt = json.loads((destination / 'result.json').read_text())
            self.assertTrue(receipt['passed'])
            self.assertFalse(receipt['live_consumer_acceptance'])
            self.assertFalse(receipt['full_relay_datapath_proven'])

    def test_changed_source_rejects_otherwise_successful_kernel_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            with patch.object(M, 'observe', return_value={'parent_namespace': 'same'}), \
                 patch.object(M, 'checked', side_effect=lambda argv: inventory(argv[-2])), \
                 patch.object(M, 'command', side_effect=lambda argv, _: (0, success(argv[-2]))):
                with self.assertRaises(ValueError):
                    M.execute(Path('/inert/binary'), destination, {}, lambda: False)
            receipt = json.loads((destination / 'result.json').read_text())
            self.assertFalse(receipt['passed'])
            self.assertFalse(receipt['source_unchanged'])
            self.assertEqual(receipt['errors'], ['source-changed-or-unreadable'])


if __name__ == '__main__':
    unittest.main()
