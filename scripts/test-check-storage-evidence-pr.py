#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline Git tree, original ZIP and required-check regressions for the Storage evidence route."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('storage_evidence', HERE / 'check-storage-evidence-pr.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
RUN = '12345678901'
REVISION = '12345678' * 5


def git(*args, data=None):
    return subprocess.check_output(['git', *args], input=data, stderr=subprocess.DEVNULL).decode().strip()


class EvidenceChanges(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.enterContext(contextlib.chdir(self.temp.name))
        git('init', '-q', '-b', 'main')
        git('config', 'user.email', 'test@example.invalid')
        git('config', 'user.name', 'Test')
        self.status = Path(check.STATUS)
        self.status.parent.mkdir()
        self.status.write_text('Initial status\n')
        git('add', '.')
        git('commit', '-qm', 'base')
        self.base = git('rev-parse', 'HEAD')
        self.bundle = self.status.parent / 'development/evidence' / ('storage-maintenance-' + RUN)
        self.bundle.mkdir(parents=True)
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            for name in sorted(check.NAMES):
                item = {'report_kind': 'volparossa-private-storage-maintenance', 'source_revision': REVISION, 'success': False} if name.endswith('smoke.json') else {'sample': True}
                original = json.dumps(item).encode() + b'\n'
                (self.bundle / name).write_bytes(original)
                archive.writestr(name, original)
        self.archive = out.getvalue()
        self.artifact = dict(id=12, name='alpha-production-helper-topology-' + RUN, expired=False,
                             size_in_bytes=len(self.archive), digest='sha256:' + hashlib.sha256(self.archive).hexdigest())
        self.status.write_text('Initial status\nOriginal https://github.com/' + check.REPO + '/actions/runs/' + RUN
                               + ' at ' + REVISION[:8] + ' ZIP ' + self.artifact['digest'][7:] + '\n')

    def merge(self):
        git('add', '-A')
        git('commit', '-qm', 'evidence')
        head = git('rev-parse', 'HEAD')
        merge = git('commit-tree', 'HEAD^{tree}', '-p', self.base, '-p', head, '-m', 'merge')
        git('checkout', '-q', '--detach', merge)
        pr = {'base': {'repo': {'full_name': check.REPO}, 'ref': 'main', 'sha': self.base},
              'head': {'sha': head}, 'commits': 1, 'changed_files': 10}
        return {'repository': {'full_name': check.REPO}, 'pull_request': pr}, merge

    def classify(self, event, merge):
        run = dict(id=int(RUN), repository={'full_name': check.REPO}, head_repository={'full_name': check.REPO},
                   path='.github/workflows/alpha-topology.yml', event='workflow_dispatch', status='completed',
                   conclusion='failure', head_sha=REVISION)
        replies = [json.dumps(run).encode(), json.dumps({'total_count': 1, 'artifacts':[self.artifact]}).encode(), self.archive]
        with mock.patch.object(check, 'api', side_effect=replies):
            return check.classify(event, merge)

    def test_exact_authored_and_integrated_trees_match_all_original_receipts(self):
        self.assertEqual(self.classify(*self.merge()), 'verified')

    def test_changed_original_is_rejected_even_if_json_is_valid(self):
        (self.bundle / 'storage-consumer-publish.json').write_text('{"success":true}')
        with self.assertRaises(check.InvalidReceipt):
            self.classify(*self.merge())

    def test_documentation_used_by_the_package_takes_full_path(self):
        Path('README.md').write_text('packaged README')
        with self.assertRaises(check.FullSuite):
            self.classify(*self.merge())

    def test_symlinks_or_executable_evidence_cannot_use_the_short_path(self):
        (self.bundle / 'storage-consumer-publish.json').chmod(0o755)
        with self.assertRaises(check.FullSuite):
            self.classify(*self.merge())

    def test_unrelated_status_rewrite_runs_full_suite(self):
        self.status.write_text('Unrelated document rewrite\n')
        with self.assertRaises(check.FullSuite):
            self.classify(*self.merge())

    def test_wrong_merge_or_changed_prior_commit_never_qualifies(self):
        event, merge = self.merge()
        with self.assertRaises(check.FullSuite):
            self.classify(event, self.base)
        event['pull_request']['commits'] = 2
        with self.assertRaises(check.FullSuite):
            self.classify(event, merge)

    def test_authored_code_change_hidden_by_the_synthetic_merge_cannot_qualify(self):
        Path('build.rs').write_text('fn main() {}')
        event, original_merge = self.merge()
        head = event['pull_request']['head']['sha']
        git('rm', '-q', 'build.rs')
        tree = git('write-tree')
        merge = git('commit-tree', tree, '-p', self.base, '-p', head, '-m', 'synthetic resolution')
        git('checkout', '-q', '--detach', merge)
        self.assertNotEqual(original_merge, merge)
        with self.assertRaises(check.FullSuite):
            self.classify(event, merge)

    def test_required_check_cannot_be_green_on_a_skipped_or_invalid_route(self):
        workflow = (HERE.parent / '.github/workflows/quality.yml').read_text()
        gate = workflow.split('      - name: Require a complete workspace suite or a verified PR-only check', 1)[1]
        shell = gate.split('        run: |', 1)[1]
        for event, classifier, route, build, passed in (
            ('pull_request', 'success', 'verified', 'skipped', True),
            ('pull_request', 'success', 'status', 'skipped', True),
            ('pull_request', 'failure', 'status', 'skipped', False),
            ('push', 'success', 'status', 'skipped', False),
            ('pull_request', 'success', 'status-invalid', 'skipped', False),
            ('pull_request', 'success', 'status-invalid', 'success', False),
            ('push', 'skipped', '', 'success', True),
            ('pull_request', 'failure', '', 'success', True),
            ('pull_request', 'success', 'full', 'skipped', False),
            ('pull_request', 'success', 'invalid', 'success', False),
            ('pull_request', 'cancelled', 'verified', 'skipped', False),
            ('pull_request', 'failure', 'verified', 'success', True),
            ('push', 'success', 'verified', 'skipped', False),
        ):
            with self.subTest(event=event, route=route, build=build):
                environment = dict(EVENT=event, CLASSIFIER=classifier, ROUTE=route, BUILD=build)
                result = subprocess.run(['/bin/bash', '-c', shell], env=environment, check=False)
                self.assertEqual(result.returncode == 0, passed)

    def test_unavailable_archive_falls_back_to_complete_suite(self):
        self.artifact['expired'] = True
        with self.assertRaises(check.FullSuite):
            self.classify(*self.merge())

    def test_digest_mismatch_cannot_verify_retrieved_archive(self):
        self.archive += b'altered download'
        with self.assertRaises(check.FullSuite):
            self.classify(*self.merge())


if __name__ == '__main__':
    unittest.main()
