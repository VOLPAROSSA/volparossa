# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic corruption checks; no download or consensus execution."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import verify


class Sources(unittest.TestCase):
    def copied(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / 'upstream'
        shutil.copytree(Path(__file__).resolve().parent, root,
                        ignore=shutil.ignore_patterns('__pycache__'))
        return root

    def test_actual_verbatim_inputs_and_import_closure(self):
        self.assertEqual(verify.verify(Path(__file__).resolve().parent),
            dict(version=1, verified_files=13, verified_bytes=93414,
                 network_access=False, consensus_execution=False))

    def test_modified_schema_and_license_are_refused(self):
        for name in ('proto/tendermint/abci/types.proto', 'licenses/CometBFT-NOTICE'):
            with self.subTest(name=name):
                root = self.copied()
                path = root / name
                raw = path.read_bytes()
                path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                with self.assertRaises(ValueError):
                    verify.verify(root)

    def test_missing_and_extra_files_are_refused(self):
        root = self.copied()
        (root / 'vendor/unexpected.proto').write_bytes(b'not upstream')
        with self.assertRaises(ValueError):
            verify.verify(root)
        root = self.copied()
        (root / 'vendor/google/protobuf/duration.proto').unlink()
        with self.assertRaises(ValueError):
            verify.verify(root)

    def test_symlink_and_traversal_are_refused(self):
        root = self.copied()
        original = root / 'licenses/CometBFT-NOTICE'
        private = root.parent / 'private'
        original.rename(private)
        original.symlink_to(private)
        with self.assertRaises(ValueError):
            verify.verify(root)
        root = self.copied()
        manifest = root / 'sources.json'
        value = json.loads(manifest.read_bytes())
        value['files'][0]['path'] = '../private'
        manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            verify.verify(root)

    def test_duplicate_manifest_fields_are_refused(self):
        root = self.copied()
        manifest = root / 'sources.json'
        raw = manifest.read_text()
        manifest.write_text(raw.replace('"version": 1', '"version": 0, "version": 1', 1))
        with self.assertRaises(ValueError):
            verify.verify(root)


if __name__ == '__main__':
    unittest.main()
