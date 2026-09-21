#!/usr/bin/env python3
"""Stdlib-only provisioning checks. No packages, model weights or network used."""

import argparse
import ast
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
    def test_opt_in_360m_preview_preserves_runtime_and_separate_license_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "must-not-be-created"
            with mock.patch.object(PROVISION.urllib.request, "build_opener", side_effect=AssertionError("preview used network")), \
                 mock.patch.object(PROVISION.venv.EnvBuilder, "create", side_effect=AssertionError("preview installed")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(PROVISION.main(["--model-profile", PROVISION.LARGE_MODEL_PROFILE, "--root", str(destination)]), 0)
            plan = json.loads(output.getvalue())
            self.assertEqual((plan["model_profile"], plan["download_bytes"], plan["wheel_count"]),
                             (PROVISION.LARGE_MODEL_PROFILE, 977655758, 38))
            self.assertFalse(destination.exists())
        base = PROVISION.load_pins()
        selected = PROVISION.load_pins(PROVISION.LARGE_MODEL_PROFILE)
        self.assertEqual(base["wheels"], selected["wheels"])
        self.assertEqual(base["source_revisions"], selected["source_revisions"])
        self.assertEqual(selected["revision"], "a10cc1512eabd3dde888204e902eca88bddb4951")
        self.assertIn("no LICENSE file", selected["license_provenance"])
        source = importlib.util.spec_from_file_location("profile_worker", HERE / "worker.py")
        worker = importlib.util.module_from_spec(source)
        source.loader.exec_module(worker)
        profile = worker.model_profile(worker.LARGE_MODEL_PROFILE)
        self.assertEqual({item["path"]: item["bytes"] for item in selected["files"]}, profile["files"])
        self.assertEqual({item["path"]: item["sha256"] for item in selected["files"]}, profile["hashes"])
        for item in selected["files"]:
            identity = PROVISION.PROFILES[PROVISION.DEFAULT_MODEL_PROFILE if item["path"] == "LICENSE" else PROVISION.LARGE_MODEL_PROFILE]
            self.assertEqual(item["url"], f"https://huggingface.co/{identity[0]}/resolve/{identity[1]}/{item['path']}")
        with self.assertRaises(PROVISION.ProvisionError):
            PROVISION.load_pins("unrecognized-model")

    def test_graph_reads_own_metadata_not_vendored_distribution_metadata(self):
        # Execute the actual stdlib-only selector from the guest program without
        # importing/installing pip, packaging or the model runtime on this host.
        graph = ast.parse(PROVISION.CHECK_WHEEL_GRAPH)
        selector = next(node for node in graph.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "wheel_metadata_member")
        namespace = {}
        exec(compile(ast.Module(body=[selector], type_ignores=[]),
                     "guest-wheel-metadata-selector", "exec"), namespace)
        select = namespace["wheel_metadata_member"]
        own = "fixture-1.0.dist-info/METADATA"
        nested = "fixture/_vendor/other-2.0.dist-info/METADATA"
        for members, expected in [
            ([own], own), ([nested, own], own),
            ([nested], None), ([], None),
            ([own, "unrelated-1.0.dist-info/METADATA"], None),
        ]:
            with self.subTest(members=members), io.BytesIO() as buffer:
                with zipfile.ZipFile(buffer, "w") as archive:
                    for member in members:
                        archive.writestr(member, b"Metadata-Version: 2.1\n")
                buffer.seek(0)
                with zipfile.ZipFile(buffer) as archive:
                    if expected is None:
                        with self.assertRaisesRegex(AssertionError, "top-level METADATA"):
                            select(archive)
                    else:
                        self.assertEqual(select(archive), expected)

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
