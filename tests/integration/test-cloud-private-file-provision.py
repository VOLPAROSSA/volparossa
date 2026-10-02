#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure provision boundary checks, never download, install or run an Cloud snapshot."""

import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cloud_provision", HERE / "cloud-private-file-provision.py")
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)
UI_SPEC = importlib.util.spec_from_file_location("cloud_ui_provision", HERE / "cloud-private-file-ui-provision.py")
UI = importlib.util.module_from_spec(UI_SPEC)
UI_SPEC.loader.exec_module(UI)


class CloudProvision(unittest.TestCase):
    def test_exact_cloud_and_node_pins_retain_licenses(self):
        pins = PROVISION.load_pins()
        self.assertEqual(pins["revision"], "63bba5d1163a69e1ee6b4218c9e7462d941f22f7")
        self.assertEqual(set(pins["files"]), {
            "scripts/cloud-file.mjs", "scripts/private_file.py", "src/private-file.mjs", "src/opencloud-dav.mjs",
            "vendor/volparossa-image/immich_snapshot.py", "vendor/volparossa-image/core-storage.mjs",
            "vendor/volparossa-image/LICENSE", "third_party/volparossa-image-source.json", "LICENSE",
            "scripts/cloud-catalog.mjs", "scripts/cloud-serve.mjs", "scripts/private_catalog.py",
            "scripts/stage_web_sdk.py", "src/private-catalog.mjs", "src/private-dav-server.mjs",
            "third_party/opencloud-web-sdk.json", "THIRD_PARTY_LICENSES.md", "src/private-resource-id.mjs",
            "src/recovery-web-metadata.mjs", "scripts/recovery-web-assets.mjs", "scripts/build_web_ui.py",
            "scripts/smoke_web_ui.py", "third_party/opencloud-web-ui.json",
            "patches/opencloud-web-owner-recovery.patch"})
        self.assertEqual(set(pins["runtime"]["files"]), {"bin/node", "LICENSE"})
        self.assertEqual(pins["runtime"]["version"], "24.19.0")
        self.assertEqual(pins["files"]["vendor/volparossa-image/LICENSE"], pins["files"]["LICENSE"])

    def test_published_sdk_is_staged_and_verified_before_public_exposure(self):
        source = (HERE / "cloud-private-file-provision.py").read_text()
        self.assertLess(source.index('SOURCE / "scripts/stage_web_sdk.py"'), source.index('expose(SOURCE)'))
        self.assertLess(source.index('sdk = verify_sdk(SOURCE)'), source.index('expose(SOURCE)'))
        self.assertIn('"--download", "--yes"', source)
        self.assertIn('receipt["archive_sha256"] == SDK_SHA', source)
        self.assertIn('len(receipt["files"]) == 109', source)
        self.assertIn('"package/LICENSE" in receipt["files"]', source)
        self.assertIn('sdk_reads_proven=False', source)

    def test_ui_and_browser_are_guest_only_verified_before_exposure(self):
        source = (HERE / "cloud-private-file-provision.py").read_text()
        helper = (HERE / "cloud-private-file-ui-provision.py").read_text()
        self.assertLess(source.index('guard()\n'), source.index('SOURCE.mkdir('))
        self.assertLess(source.index('expose(RUNTIME)'), source.index('ui_stage["provision_ui"]'))
        self.assertLess(source.index('ui_stage["provision_browser"]'), source.index('expose(SOURCE)'))
        self.assertIn("'--no-new-privs'", helper)
        self.assertIn("'--bounding-set=-all'", helper)
        self.assertIn("'GIT_CONFIG_GLOBAL': '/dev/null'", helper)
        self.assertIn("'core.hooksPath=/dev/null'", helper)
        self.assertIn("'credential.helper='", helper)
        self.assertIn("'--depth=1'", helper)
        self.assertIn("'browser-network-provision.py'", helper)
        self.assertIn("'build/firefox-esr'", helper)
        self.assertIn("'build/web-ui'", helper)
        self.assertIn("'build/FIREFOX_COPYRIGHT'", helper)
        self.assertIn("'build/PNPM_LICENSE'", helper)
        self.assertIn("ui_execution_proven=False", helper)
        self.assertIn("browser_execution_proven=False", helper)

    def synthetic_ui(self, root):
        """Parser fixture only; no source build, browser or peer proof."""
        source, dist = root / "source", root / "dist"
        (source / 'third_party').mkdir(parents=True)
        (source / 'patches').mkdir()
        dist.mkdir()
        (source / 'patches/owner.patch').write_bytes(b'synthetic patch')
        (dist / 'index.html').write_bytes(b'synthetic index')
        (dist / 'UPSTREAM_LICENSE').write_bytes(b'synthetic license')
        pins = dict(repository='https://github.com/opencloud-eu/web.git', revision=UI.UPSTREAM,
                    tree=UI.UPSTREAM_TREE, patch='patches/owner.patch', lock_sha256='1' * 64,
                    license_sha256=UI.digest(dist / 'UPSTREAM_LICENSE'))
        (source / 'third_party/opencloud-web-ui.json').write_text(json.dumps(pins))
        report = dict(version=1, kind='opencloud-web-owner-recovery-build', source_revision=UI.UPSTREAM,
            source_tree=UI.UPSTREAM_TREE, pins_sha256=UI.digest(source / 'third_party/opencloud-web-ui.json'),
            patch_sha256=UI.digest(source / 'patches/owner.patch'), lock_sha256=pins['lock_sha256'],
            node='24.19.0', pnpm='11.27.0', lifecycle_scripts=False, build_network=False,
            global_installation=False, files={name: dict(bytes=(dist / name).stat().st_size,
            sha256=UI.digest(dist / name)) for name in ('index.html', 'UPSTREAM_LICENSE')})
        (dist / 'BUILD_REPORT.json').write_text(json.dumps(report))
        return source, dist, report

    def test_ui_receipt_requires_exact_bytes_and_closed_execution_scope(self):
        with tempfile.TemporaryDirectory(prefix='cloud-ui-contract-') as temporary:
            source, dist, _ = self.synthetic_ui(Path(temporary))
            receipt = UI.verify_ui(source, dist)
            self.assertEqual(set(receipt), {'source_revision', 'source_tree', 'pins_sha256',
                'patch_sha256', 'build_report_sha256', 'source_built', 'files_verified', 'ui_execution_proven'})
            self.assertFalse(receipt['ui_execution_proven'])
            self.assertEqual(receipt['build_report_sha256'], UI.digest(dist / 'BUILD_REPORT.json'))
            (dist / 'index.html').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                UI.verify_ui(source, dist)

    def test_ui_receipt_rejects_unreported_assets_and_links(self):
        with tempfile.TemporaryDirectory(prefix='cloud-ui-contract-') as temporary:
            source, dist, _ = self.synthetic_ui(Path(temporary))
            extra = dist / 'unreported'
            extra.write_bytes(b'x')
            with self.assertRaises(ValueError):
                UI.verify_ui(source, dist)
            extra.unlink()
            original = dist / 'index.html'
            target = Path(temporary) / 'outside'
            original.rename(target)
            original.symlink_to(target)
            with self.assertRaises(ValueError):
                UI.verify_ui(source, dist)

    def test_ui_receipt_rejects_build_network_or_lifecycle_claims(self):
        with tempfile.TemporaryDirectory(prefix='cloud-ui-contract-') as temporary:
            source, dist, report = self.synthetic_ui(Path(temporary))
            for key in ('build_network', 'lifecycle_scripts', 'global_installation'):
                report[key] = True
                (dist / 'BUILD_REPORT.json').write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    UI.verify_ui(source, dist)
                report[key] = False

    def test_public_copy_preserves_executable_only_readonly_and_rejects_links(self):
        with tempfile.TemporaryDirectory(prefix='cloud-ui-contract-') as temporary:
            source, destination = Path(temporary) / 'source', Path(temporary) / 'final'
            source.mkdir()
            (source / 'firefox-esr').write_bytes(b'synthetic nonexecutable test bytes')
            (source / 'firefox-esr').chmod(0o700)
            (source / 'LICENSE').write_bytes(b'synthetic license')
            (source / 'LICENSE').chmod(0o600)
            UI.copy_public_tree(source, destination)
            self.assertEqual((destination / 'firefox-esr').stat().st_mode & 0o777, 0o555)
            self.assertEqual((destination / 'LICENSE').stat().st_mode & 0o777, 0o444)
            (source / 'linked').symlink_to(source / 'LICENSE')
            with self.assertRaises(ValueError):
                UI.copy_public_tree(source, Path(temporary) / 'rejected')

    def test_owner_command_has_private_home_and_no_inherited_credentials(self):
        owner = mock.Mock(pw_uid=1001, pw_gid=1001)
        child = mock.Mock(pid=12345)
        child.wait.return_value, child.poll.return_value = 0, 0
        with mock.patch.object(UI.subprocess, 'Popen', return_value=child) as start:
            UI.owner_run(['/usr/bin/true'], owner, Path('/opt/temporary-home'), Path('/opt/temporary-cwd'))
        args, kwargs = start.call_args
        self.assertEqual(args[0][-1], '/usr/bin/true')
        self.assertIn('--no-new-privs', args[0])
        self.assertEqual(kwargs['env']['HOME'], '/opt/temporary-home')
        self.assertEqual(set(kwargs['env']), {'PATH', 'HOME', 'LC_ALL', 'GIT_CONFIG_NOSYSTEM',
            'GIT_CONFIG_GLOBAL', 'GIT_TERMINAL_PROMPT'})

    def test_guest_guard_refuses_before_subprocess_or_mutation(self):
        with mock.patch.object(PROVISION.os, "geteuid", return_value=0), \
                mock.patch.object(PROVISION.socket, "gethostname", return_value="developer-host"), \
                mock.patch.object(PROVISION.subprocess, "check_output") as execute:
            with self.assertRaises(ValueError):
                PROVISION.guard()
            execute.assert_not_called()

    def test_download_requires_explicit_flag(self):
        result = subprocess.run([sys.executable, "-B", str(HERE / "cloud-private-file-provision.py"), "provision"],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--download", result.stderr)
        self.assertNotIn("verified", result.stdout)

    def test_exact_file_verification_rejects_mutation_and_links(self):
        with tempfile.TemporaryDirectory(prefix="image-source-check-") as temporary:
            root = Path(temporary)
            source = root / "source.mjs"
            data = b"fixture source, not a runtime proof\n"
            source.write_bytes(data)
            records = {source.name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())}
            PROVISION.verify_files(root, records)
            source.write_bytes(data[:-1] + b"x")
            with self.assertRaises(ValueError):
                PROVISION.verify_files(root, records)
            original = root / "other"
            source.rename(original)
            source.symlink_to(original)
            with self.assertRaises(ValueError):
                PROVISION.verify_files(root, records)

    def test_reused_node_extractor_never_extracts_other_paths(self):
        stage = PROVISION.loader()
        members = {"bin/node": b"test-node", "LICENSE": b"test-license"}
        expected = {name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    for name, data in members.items()}
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode="w") as archive:
            for name, data in {**members, "bin/npm": b"not selected"}.items():
                member = tarfile.TarInfo(stage["NODE"] + "/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        packed.seek(0)
        with tempfile.TemporaryDirectory(prefix="image-runtime-check-") as temporary:
            with tarfile.open(fileobj=packed) as archive:
                stage["extract_runtime"](archive, Path(temporary), expected)
            actual = {str(path.relative_to(temporary)) for path in Path(temporary).rglob("*") if path.is_file()}
            self.assertEqual(actual, set(expected))
            self.assertEqual(os.stat(Path(temporary) / "bin/node").st_mode & 0o777, 0o700)

    def test_reused_node_extractor_rejects_link_target(self):
        stage = PROVISION.loader()
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode="w") as archive:
            member = tarfile.TarInfo(stage["NODE"] + "/bin/node")
            member.type = tarfile.SYMTYPE
            member.linkname = "/bin/sh"
            archive.addfile(member)
        packed.seek(0)
        with tempfile.TemporaryDirectory(prefix="image-runtime-check-") as temporary:
            with tarfile.open(fileobj=packed) as archive, self.assertRaises(ValueError):
                stage["extract_runtime"](archive, Path(temporary), {"bin/node": dict(bytes=0, sha256="0" * 64)})


if __name__ == "__main__":
    unittest.main()
