#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert guard/source-binding tests; no Rust, C, package or sanitizer execution."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('dps', Path(__file__).with_name('check-dps-current-source.py'))
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
REV = 'a' * 40
ENV = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux',
    RUNNER_ARCH='X64', GITHUB_REPOSITORY='VOLPAROSSA/volparossa', GITHUB_EVENT_NAME='workflow_dispatch',
    GITHUB_REF='refs/heads/fix/f04-maintained-zbus-rust199', DPS_MODE='current-compiler', CORE_REVISION=REV, GITHUB_SHA=REV, GITHUB_WORKFLOW_SHA=REV)


class CurrentDps(unittest.TestCase):
    def fake_git(self, changed=None, dirty=False, baseline_changed=None):
        def git(*args):
            if args == ('rev-parse', 'HEAD'): return REV
            if args[0] == 'status': return ' M fixture' if dirty else ''
            if args[0] in ('merge-base', 'check-ref-format'): return ''
            if args == ('rev-parse', 'HEAD^{tree}'): return 'b' * 40
            assert args[0] == 'rev-parse'
            ref, name = args[1].split(':', 1)
            if ref == M.SHARED_BASE and name == baseline_changed:
                return 'f' * 40
            if ref == 'HEAD' and name == changed:
                return 'c' * 40
            # The one reviewed safe test assertion intentionally differs at C11.
            if name == M.SHARED[-1] and ref in ('HEAD', M.SHARED_BASE):
                return 'e' * 40
            return 'd' * 40
        return git

    def test_current_full_tree_and_new_graph_bind_fixed_native_and_shared_baselines(self):
        record = M.source_receipt(ENV, self.fake_git(changed='Cargo.lock'))
        self.assertEqual(len(M.DPS), 13); self.assertEqual(len(M.SHARED), 4)
        self.assertEqual(len(record['source_blobs']), 25)
        self.assertEqual(record['source_commit'], REV)
        self.assertEqual(record['source_blobs']['Cargo.lock'], 'c' * 40)
        self.assertFalse(record['actual_android_acceptance'])
        self.assertEqual(record['base_commit'], '89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1')
        self.assertEqual(record['shared_base'], 'c11d97f4265834218500ba7ec7e2aff1e66c55db')
        self.assertIn('scripts/provision-rust189.py', record['source_blobs'])
        self.assertIn('scripts/rust189-components.json', record['source_blobs'])
        self.assertEqual(record['source_blobs'][M.SHARED[-1]], 'e' * 40)

    def test_every_changed_native_or_shared_fixture_is_rejected(self):
        for name in (*M.DPS, *M.SHARED):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'changed'):
                M.source_receipt(ENV, self.fake_git(changed=name))
        with self.assertRaisesRegex(ValueError, 'not clean'):
            M.source_receipt(ENV, self.fake_git(dirty=True))

    def test_host_wrong_repo_event_mode_and_revision_are_rejected(self):
        for key in ENV:
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.admission(dict(ENV, **{key: 'wrong'}), REV)
        for revision in ('main', 'A' * 40, 'b' * 40):
            with self.assertRaises(ValueError): M.admission(ENV, revision)

    def test_native_and_production_shared_must_match_both_fixed_baselines(self):
        for name in (*M.DPS, *M.SHARED[:-1]):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'baselines changed'):
                M.source_receipt(ENV, self.fake_git(baseline_changed=name))

    def test_root_and_non_branch_refs_are_rejected(self):
        with patch.object(M.os, 'geteuid', return_value=0), self.assertRaisesRegex(ValueError, 'unprivileged'):
            M.admission(ENV, REV)
        for ref in ('', 'refs/tags/v1', 'refs/pull/349/merge'):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                M.admission(dict(ENV, GITHUB_REF=ref), REV)
        # Real git is the final syntactic authority, not a caller's expected hash.
        rejecting = Mock(side_effect=[REV, ValueError('invalid git ref')])
        with self.assertRaisesRegex(ValueError, 'invalid git ref'):
            M.source_receipt(dict(ENV, GITHUB_REF='refs/heads/bad..ref'), rejecting)

    def test_guard_stops_before_source_traversal(self):
        git = Mock(return_value=REV)
        with self.assertRaises(ValueError): M.source_receipt({}, git)
        self.assertEqual(git.call_count, 1)


if __name__ == '__main__': unittest.main()
