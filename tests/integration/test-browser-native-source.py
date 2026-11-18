#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert Git repositories exercise the verifier without a Gecko compile or network request."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('browser_native_source', Path(__file__).with_name('browser-native-source.py'))
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def put_json(path, value):
    put(path, json.dumps(value).encode())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def commit(root):
    def git(*args):
        return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                                        '-c', 'core.hooksPath=/dev/null', *args], cwd=root).strip().decode()
    git('init', '-q')
    git('add', '.')
    git('commit', '-qm', 'Inert source verification fixture')
    return git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')


class NativeSourceTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.browser = root / 'browser'
        build = self.build = self.browser / 'build/new'
        source = self.source = build / 'source'
        self.base = 'browser/fixture.txt'
        put(source / self.base, b'original')
        firefox, tree = commit(source)
        put(self.browser / '.gitignore', b'/build/\n')
        integration = {}
        for name in SOURCE.ASSETS:
            data = name.encode()
            put(self.browser / 'integration' / name, data)
            integration[name] = digest(data)
        pins = dict(source=dict(revision=firefox, tree=tree), reused_rust=dict(report_sha256=SOURCE.RUST_REPORT),
                    toolchains=[dict(name='compiler', bytes=8, sha256=digest(b'compiler'))])
        put_json(self.browser / 'patches/firefox-native-build.json', pins)
        put_json(self.browser / 'patches/firefox-source.json',
                 dict(upstream_revision=firefox, upstream_sha256={self.base: digest(b'original')}))
        put_json(self.browser / 'patches/firefox-network-ech.json', dict(upstream_revision=firefox, upstream_sha256={}))
        put(self.browser / 'scripts/native_build.py', b'''from pathlib import Path
def overlay_files(pristine):
    prefix = 'browser/components/genai/'
    files = {prefix + p.name:p.read_bytes() for p in (Path(__file__).resolve().parents[1] / 'integration').iterdir()}
    files['browser/fixture.txt'] = (pristine / 'browser/fixture.txt').read_bytes() + b' transformed'
    return files
''')
        browser_revision, _tree = commit(self.browser)
        put_json(root / 'core-pins.json', dict(revision=browser_revision, files={
            str(p.relative_to(self.browser)):dict(bytes=p.stat().st_size, sha256=digest(p.read_bytes()))
            for folder in ('patches', 'scripts') for p in (self.browser / folder).iterdir()}))
        settings = patch.multiple(SOURCE, CORE_PINS=root / 'core-pins.json', BROWSER=browser_revision,
                                  FIREFOX=firefox, TREE=tree, CONTROLLER_SHA=integration[SOURCE.CONTROLLER])
        settings.start()
        self.addCleanup(settings.stop)
        files = {self.base:b'original transformed'}
        for name in integration:
            files[SOURCE.SOURCE_PREFIX + name] = name.encode()
        for path, content in files.items():
            put(source / path, content)
        self.overlay = dict(revision=firefox, native_patch_sha256=SOURCE.PATCH, integration=integration,
                            files={path:digest(data) for path,data in files.items()})
        put_json(build / 'overlay.json', self.overlay)
        runtime = build / 'obj/dist/bin'
        (runtime / 'browser/modules').mkdir(parents=True)
        for name in SOURCE.MODULES:
            (runtime / 'browser/modules' / name).symlink_to(source / SOURCE.SOURCE_PREFIX / name)
        outputs = {}
        # A minimal header for verifier tests; these files are never executed.
        for name in sorted(SOURCE.OUTPUTS | {'obj/dist/bin/plugin-container'}):
            data = b'\x7fELF\x02\x01' + bytes(10) + b'\x03\0\x3e\0' + name.encode()
            put(build / name, data)
            if name in SOURCE.OUTPUTS:
                outputs[name] = digest(data)
        put(build / 'downloads/compiler.tar.zst', b'compiler')
        self.report = dict(version=1, jobs=2, source=pins['source'], native_build_requested=True,
                           native_build_proven=True, native_ech_wire_proven=False, build_network_disabled=True,
                           system_installation=False, output=str(build), overlay=self.overlay, outputs=outputs)
        put_json(build / 'build-result.json', self.report)

    def verify(self):
        return SOURCE.validate_build(self.browser, self.build)

    def test_fresh_receipt_and_current_binary_hashes(self):
        record = self.verify()
        self.assertEqual(record['outputs'], self.report['outputs'])
        self.assertEqual(record['receipt_sha256'], digest((self.build / 'build-result.json').read_bytes()))
        self.assertEqual(record['controller_sha256'], digest(SOURCE.CONTROLLER.encode()))
        self.assertEqual(SOURCE.validate_record(record), record)
        for invalid in (dict(record, more='private path'), dict(record, kind='historical'),
                        dict(record, rust_report_sha256='0'*64), dict(record, plugin_container_sha256='/path'),
                        dict(record, outputs={}), dict(record, controller_sha256='0'*64)):
            with self.subTest(invalid=list(invalid)), self.assertRaises(ValueError):
                SOURCE.validate_record(invalid)

    def test_consistent_forged_overlay_cannot_replace_reviewed_transformation(self):
        put(self.source / self.base, b'forged')
        self.overlay['files'][self.base] = digest(b'forged')
        put_json(self.build / 'overlay.json', self.overlay)
        put_json(self.build / 'build-result.json', self.report)
        with self.assertRaisesRegex(ValueError, 'transformations'):
            self.verify()

    def test_extra_firefox_source_not_covered_by_overlay(self):
        put(self.source / 'extra', b'additional input')
        with self.assertRaisesRegex(ValueError, 'modified Firefox'):
            self.verify()

    def test_untracked_browser_input_and_dirty_compute_module(self):
        extra = self.browser / 'unreviewed'
        put(extra, b'extra')
        with self.assertRaisesRegex(ValueError, 'Browser checkout'):
            self.verify()
        extra.unlink()
        put(self.browser / 'integration/VolparossaCompute.sys.mjs', b'changed')
        with self.assertRaisesRegex(ValueError, 'Browser checkout'):
            self.verify()

    def test_wrong_installed_module_target_is_rejected_even_with_same_contents(self):
        stage = self.build / 'obj/dist/bin/browser/modules' / SOURCE.CONTROLLER
        stage.unlink()
        put(self.build / 'unrelated', SOURCE.CONTROLLER.encode())
        stage.symlink_to(self.build / 'unrelated')
        with self.assertRaisesRegex(ValueError, 'installed Browser module'):
            self.verify()

    def test_rehashed_non_native_binary_is_rejected(self):
        name = 'obj/dist/bin/firefox'
        put(self.build / name, b'not an executable')
        self.report['outputs'][name] = digest(b'not an executable')
        put_json(self.build / 'build-result.json', self.report)
        with self.assertRaisesRegex(ValueError, 'ELF'):
            self.verify()

    def test_incomplete_output_inventory_and_changed_toolchain(self):
        del self.report['outputs']['obj/dist/bin/xpcshell']
        put_json(self.build / 'build-result.json', self.report)
        with self.assertRaisesRegex(ValueError, 'output inventory'):
            self.verify()
        put(self.build / 'downloads/compiler.tar.zst', b'bad tool')
        with self.assertRaisesRegex(ValueError, 'compiler archive'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
