#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Git-only regression checks in synthetic empty repositories, with no network access."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

M = runpy.run_path(str(Path(__file__).with_name('public-git-recovery.py')))


class GitRecovery(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / 'origin'
        self.source.mkdir()
        self.bundle = M['create_bundle'](self.source)
        self.repo = self.source / 'publisher.git'

    def restore(self, digest=None):
        M['restore'](self.root, self.bundle, digest or M['digest'](self.bundle), M['COMMITS'])

    def test_original(self):
        self.restore()
        self.assertEqual(M['git'](self.root / 'recovered.git', 'rev-parse', M['REF']).decode().strip(), M['COMMITS'][1])

    def test_changed_bytes_never_reach_git(self):
        expected = M['digest'](self.bundle)
        with self.bundle.open('ab') as bundle:
            bundle.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.restore(expected)
        self.assertFalse((self.root / 'recovered.git').exists())

    def test_additional_ref_rejected(self):
        M['git'](self.repo, 'update-ref', 'refs/heads/extra', M['COMMITS'][0])
        M['git'](self.repo, 'bundle', 'create', self.bundle, '--branches')
        with self.assertRaisesRegex(ValueError, 'references'):
            self.restore()
        self.assertEqual(M['git'](self.root / 'recovered.git', 'for-each-ref'), b'')

    def test_missing_prerequisite_rejected(self):
        M['git'](self.repo, 'bundle', 'create', self.bundle, M['REF'], '^' + M['COMMITS'][0])
        with self.assertRaises(subprocess.CalledProcessError):
            self.restore()
        self.assertEqual(M['git'](self.root / 'recovered.git', 'for-each-ref'), b'')


if __name__ == '__main__':
    unittest.main()
