#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert original upstream authority/count checks; never builds or runs D-Bus."""
from pathlib import Path
import json
import os
import runpy
import tempfile
import unittest
from unittest.mock import Mock, patch

H=runpy.run_path(str(Path(__file__).with_name('run-zbus-upstream.py')))
REV='a'*40
ENV=dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',GITHUB_REPOSITORY='VOLPAROSSA/volparossa',
    RUNNER_OS='Linux',RUNNER_ARCH='X64',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_SHA=REV,GITHUB_WORKFLOW_SHA=REV,ZBUS_CORE_REVISION=REV)


class Upstream(unittest.TestCase):
    def test_source_policy_failure_precedes_archive_or_cargo_and_cleans_private_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            env=dict(ENV,RUNNER_TEMP=temporary)
            with patch.dict(os.environ,env,clear=True), \
                 patch.object(H['NATIVE']['subprocess'],'check_output',return_value=REV), \
                 patch.dict(H['POLICY'],activate=Mock(side_effect=ValueError('fixed policy rejection'))), \
                 patch.object(H['urllib'].request,'urlopen',side_effect=AssertionError('network')):
                with self.assertRaises(ValueError):H['execute']()
            self.assertFalse((Path(temporary)/'zbus-upstream-private').exists())
            receipt=json.loads((Path(temporary)/'zbus-upstream-proof/zbus-upstream-source.log').read_text())
            self.assertFalse(receipt['success'])
    def test_explicit_independent_features_and_actual_named_test_inventory(self):
        self.assertEqual(H['FEATURES'],'tokio,proxy,p2p')
        self.assertEqual(len(H['TESTS']),13)
        text='\n'.join(name+': test' for name in H['TESTS'])
        self.assertEqual(len(H['selected_inventory'](text)),13)
        for invalid in ('',text.split('\n',1)[1],text+'\n'+H['TESTS'][0]+': test'):
            with self.assertRaises(ValueError):H['selected_inventory'](invalid)

    def test_every_host_revision_repo_or_event_mismatch_is_rejected(self):
        H['admission'](ENV,REV)
        for key in ENV:
            with self.subTest(key=key),self.assertRaises(ValueError):H['admission'](dict(ENV,**{key:'wrong'}),REV)

    def test_wrong_root_lock_or_corrupt_original_archive_fail(self):
        for lock in ({'package':[]},{'package':[dict(name='zbus',version='5',checksum=H['SHA'])]}):
            with self.assertRaises(ValueError):H['original_files'](b'corrupt',lock)
        with self.assertRaises(ValueError):H['original_files'](b'corrupt',{'package':[dict(name='zbus',version='6.1.0',checksum=H['SHA'])]})


if __name__=='__main__':unittest.main()
