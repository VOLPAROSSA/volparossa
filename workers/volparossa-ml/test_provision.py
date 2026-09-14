#!/usr/bin/env python3
"""Stdlib-only provisioning checks. No packages, model weights or network used."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import zipfile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("provision", HERE / "provision.py")
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)


class Response(io.BytesIO):
    url = "https://files.pythonhosted.org/packages/fixture.whl"

    def __init__(self, body):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))}


class ProvisionTests(unittest.TestCase):
    def test_preview_is_network_and_write_free_with_complete_fixed_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "must-not-be-created"
            with mock.patch.object(PROVISION.urllib.request, "build_opener",
                                   side_effect=AssertionError("preview attempted network")), \
                    mock.patch.object(PROVISION.venv.EnvBuilder, "create",
                                      side_effect=AssertionError("preview attempted install")), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROVISION.main(["--root", str(destination)]), 0)
            plan = json.loads(output.getvalue())
            self.assertEqual(plan["mode"], "preview")
            self.assertEqual(plan["wheel_count"], 38)
            self.assertEqual(plan["download_bytes"], 523040250)
            self.assertFalse(destination.exists())
            pins = PROVISION.load_pins()
            self.assertEqual({x["path"] for x in pins["files"]}, {
                "LICENSE", "README.md", "config.json", "generation_config.json",
                "model.safetensors", "special_tokens_map.json", "tokenizer.json",
                "tokenizer_config.json",
            })
            versions = {x["name"]: x["version"] for x in pins["wheels"]}
            self.assertEqual(versions["mpmath"], "1.3.0")  # SymPy requires <1.4.
            self.assertEqual(versions["torch"], "2.14.0+cpu")
            self.assertIn("pip", versions)

    @mock.patch.object(PROVISION.sys, "version_info", (3, 13, 0))
    @mock.patch.object(PROVISION.platform, "system", return_value="Linux")
    @mock.patch.object(PROVISION.platform, "machine", return_value="x86_64")
    def test_execute_refuses_host_existing_root_and_missing_confirmation(self, _machine, _system):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "new-runtime"
            args = argparse.Namespace(yes=True, disposable_guest=True, root=str(root),
                                      budget_bytes=2_000_000_000)
            bare_host = mock.Mock(returncode=1, stdout="none\n")
            with mock.patch.dict(PROVISION.os.environ, {}, clear=True), \
                    mock.patch.object(PROVISION.subprocess, "run", return_value=bare_host):
                with self.assertRaisesRegex(PROVISION.ProvisionError, "disposable KVM"):
                    PROVISION.execution_root(args)
            self.assertFalse(root.exists())
            args.yes = False
            with self.assertRaisesRegex(PROVISION.ProvisionError, "--yes"):
                PROVISION.execution_root(args)
            args.yes = True
            root.mkdir()
            with self.assertRaisesRegex(PROVISION.ProvisionError, "already exist"):
                PROVISION.execution_root(args)
            root.rmdir()
            alias = Path(directory) / "alias"
            alias.symlink_to(Path(directory), target_is_directory=True)
            args.root = str(alias / "other")
            with self.assertRaisesRegex(PROVISION.ProvisionError, "symlink"):
                PROVISION.execution_root(args)

    def test_unsupported_interpreter_is_refused_before_guest_or_file_operations(self):
        args = argparse.Namespace(yes=True, disposable_guest=True, root=None, budget_bytes=None)
        with mock.patch.object(PROVISION.sys, "version_info", (3, 12, 0)), \
                mock.patch.object(PROVISION.subprocess, "run", side_effect=AssertionError("guest check must not run")):
            with self.assertRaisesRegex(PROVISION.ProvisionError, "CPython 3.13"):
                PROVISION.execution_root(args)

    def test_download_checks_hash_size_redirect_and_preserves_existing_file(self):
        body = b"small non-model fixture"
        item = {"url": Response.url, "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "fixture.whl"
            opener = mock.Mock()
            opener.open.side_effect = lambda *a, **kw: Response(body)
            PROVISION.download(item, target, opener, time.monotonic() + 10)
            self.assertEqual(target.read_bytes(), body)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                PROVISION.download(item, target, opener, time.monotonic() + 10)
            self.assertEqual(target.read_bytes(), body)
            target.unlink()
            with self.assertRaisesRegex(PROVISION.ProvisionError, "SHA256"):
                PROVISION.download(dict(item, sha256="0" * 64), target, opener,
                                   time.monotonic() + 10)
            self.assertFalse(target.exists())
            with self.assertRaisesRegex(PROVISION.ProvisionError, "size header"):
                PROVISION.download(dict(item, bytes=len(body) - 1), target, opener,
                                   time.monotonic() + 10)
            self.assertFalse(target.exists())
            for url in ("http://files.pythonhosted.org/a", "https://untrusted.example/a",
                        "https://files.pythonhosted.org@untrusted.example/a"):
                with self.assertRaises(PROVISION.ProvisionError):
                    PROVISION.official_url(url)

    def test_wheel_budget_inspection_refuses_path_escape_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "fixture.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("package/fixture.py", b"fixture")
            self.assertEqual(PROVISION.wheel_expanded_bytes(wheel), 7)
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("../escape", b"bad")
            with self.assertRaisesRegex(PROVISION.ProvisionError, "unsafe"):
                PROVISION.wheel_expanded_bytes(wheel)
            with zipfile.ZipFile(wheel, "w") as archive:
                entry = zipfile.ZipInfo("package/link")
                entry.external_attr = 0o120777 << 16
                archive.writestr(entry, b"/outside")
            with self.assertRaisesRegex(PROVISION.ProvisionError, "symlink"):
                PROVISION.wheel_expanded_bytes(wheel)


if __name__ == "__main__":
    unittest.main()
