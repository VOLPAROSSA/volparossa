#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check the guest's exact public SQLite enrollment before any peer deposit."""
import hashlib
import io
from pathlib import Path
import runpy
import unittest

HERE = Path(__file__).parent
M = runpy.run_path(str(HERE / 'degoog-peer-recovery.py'))


class PublicIndex(unittest.TestCase):
    def test_publisher_cannot_attest_its_own_custody(self):
        holder = 'a0' * 32
        for invalid in (holder, holder.upper()):
            with self.subTest(key=invalid), self.assertRaisesRegex(ValueError, 'distinct enrolled keys'):
                M['PEER']['require_independent_publisher'](invalid, holder)
        M['PEER']['require_independent_publisher']('b0' * 32, holder)

    def test_original_and_changed_archive(self):
        raw = (HERE / 'fixtures' / 'degoog-public-index.zip').read_bytes()
        index = M['read_index'](io.BytesIO(raw))
        self.assertEqual(hashlib.sha256(index).hexdigest(), M['INDEX_SHA'])
        for other in (raw[:-1], raw + b'x', raw[1:] + raw[:1]):
            with self.subTest(size=len(other)), self.assertRaisesRegex(ValueError, 'archive'):
                M['read_index'](io.BytesIO(other))


if __name__ == '__main__':
    unittest.main()
