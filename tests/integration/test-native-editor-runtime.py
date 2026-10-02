#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Small bundle contracts, not a model/editor execution claim."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('editor_bundle', HERE / 'native-editor-runtime.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
REVISION = 'a' * 40


class BundleTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix='volparossa-editor-bundle-test-')
        self.addCleanup(root.cleanup)
        self.path = Path(root.name) / 'input.tar.gz'
        self.data = {'code/LICENSE': b'license', 'editor/codium': b'not executable synthetic editor',
                     'runtime/runtime/codex-app-server': b'synthetic runtime',
                     'runtime/BUILD_REPORT.json': b'{}', 'runtime/prompt.md': b'full synthetic prompt',
                     'runtime/notices/LICENSE': b'unchanged notices'}
        self.files = {name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                     mode=0o555 if name in ('editor/codium', 'runtime/runtime/codex-app-server') else 0o444)
                      for name, data in self.data.items()}
        pin = copy.deepcopy(B.pins())
        pin['code_files'] = {'LICENSE': self.files['code/LICENSE']}
        editor = {'codium': self.files['editor/codium']}
        pin['editor'].update(inventory_sha256=B.inventory_digest(editor), files=1,
                             bytes=len(self.data['editor/codium']))
        pin['native'].update(notices_inventory_sha256=B.inventory_digest({'LICENSE': self.files['runtime/notices/LICENSE']}))
        for name, field in (('runtime/codex-app-server', 'binary_sha256'),
                            ('BUILD_REPORT.json', 'build_report_sha256'), ('prompt.md', 'prompt_sha256')):
            pin['native'][field] = self.files['runtime/' + name]['sha256']
        mock = patch.object(B, 'pins', return_value=pin)
        mock.start()
        self.addCleanup(mock.stop)
        self.receipt = copy.deepcopy(dict(B.authority(REVISION), files=self.files))

    def archive(self, *, extra=None, changed=None, mode=None):
        data = dict(self.data, **(changed or {}))
        data[B.MANIFEST] = json.dumps(self.receipt).encode()
        with tarfile.open(self.path, 'w:gz') as stream:
            for name, value in data.items():
                member = tarfile.TarInfo(name)
                member.size = len(value)
                member.mode = self.files[name]['mode'] if name in self.files else 0o444
                if name == mode:
                    member.mode = 0o4755
                stream.addfile(member, io.BytesIO(value))
            if extra is not None:
                stream.addfile(extra, io.BytesIO(b'x' * extra.size))

    def test_all_inventory_bytes_and_scope_are_checked(self):
        self.archive()
        self.assertEqual(B.verify(self.path, REVISION), self.receipt)
        with self.assertRaisesRegex(ValueError, 'authority'):
            B.verify(self.path, 'b' * 40)

    def test_editor_native_code_and_notices_tampering_reject(self):
        for name in self.data:
            self.archive(changed={name: b'tampered'})
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'content'):
                B.verify(self.path, REVISION)

    def test_links_duplicate_traversal_and_setuid_reject(self):
        for name, kind in [('editor/../escape', tarfile.REGTYPE), ('editor/link', tarfile.SYMTYPE),
                           ('code/LICENSE', tarfile.REGTYPE)]:
            extra = tarfile.TarInfo(name)
            extra.type = kind
            self.archive(extra=extra)
            with self.assertRaises(ValueError):
                B.verify(self.path, REVISION)
        self.archive(mode='editor/codium')
        with self.assertRaisesRegex(ValueError, 'member'):
            B.verify(self.path, REVISION)

    def test_inventory_rebinding_and_false_provenance_reject(self):
        self.receipt['editor']['source_build_proven'] = True
        self.archive()
        with self.assertRaisesRegex(ValueError, 'authority'):
            B.verify(self.path, REVISION)

    def test_vm_preview_and_closed_private_export_branch(self):
        runner = HERE / 'run-alpha-topology-vm.sh'
        text = runner.read_text()
        result = subprocess.run(['sh', str(runner), '--preview', '--scenario', 'agent-native-editor'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('8192 MiB', result.stdout)
        self.assertIn('real headless editor command', result.stdout)
        self.assertIn('native-editor-runtime.py stage --yes', text)
        self.assertIn('("agent-private-conversation", "agent-native-coding", "agent-native-editor")', text)
        self.assertNotIn('--no-sandbox', text)


if __name__ == '__main__':
    unittest.main()
