#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert public staging fixtures: never execute assets, load a model or boot."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("resident_workload", HERE / "protected-resident-model-workload.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
NATIVE = M.module("llama_cpu")
PROVISION = M.module("provision")
REAL_PINS = PROVISION.load_pins(model_profile=NATIVE.PROFILE, native_cpu_converter=True)
SOURCE = "339294e0f31c7ebccf7bbffcd18819fefe84dfcc"


def record(raw, executable=False):
    return dict(kind="file", bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), executable=executable)


def public_elf():
    raw = bytearray(64)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", raw, 16, 3, 62)
    return bytes(raw)  # Structural test bytes, never a usable/loaded ELF.


class Fixture:
    def __init__(self, directory):
        self.base = Path(directory)
        self.assets = self.base / "assets"
        self.assets.mkdir(mode=0o700)
        self.output, self.inventory_path = self.base / "workload.tar", self.base / "inventory.json"
        self.value = dict(version=1, kind="protected-resident-public-workload", public_fixture_only=True,
                          core_source_commit=SOURCE, entries={})
        self.pins = {"files": []}
        # Small PUBLIC test bytes deliberately replace only the provision pin
        # loader inside this fixture. Actual stage_workload has no such switch.
        for item in REAL_PINS["files"]:
            raw = ("public fixture: " + item["path"]).encode()
            self.put("model/" + item["path"], raw)
            self.pins["files"].append(dict(path=item["path"], bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        self.put("volparossa", public_elf(), True)
        self.put("server.der", b"public fixture certificate")
        self.put("server-key.der", b"public fixture key, not private material")
        self.put("runtime/pyvenv.cfg", b"home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.13.5\n")
        self.put("runtime/lib/python3.13/site-packages/public.py", b"raise AssertionError('never execute assets')\n")
        self.link("runtime/bin/python3", "/usr/bin/python3.13")
        self.link("runtime/bin/python", "python3")
        self.link("runtime/lib64", "lib")
        library, gguf = public_elf(), b"PUBLIC GGUF fixture"
        self.put("native-backend/libvolparossa_llama_cpu.so", library)
        self.put("native-backend/model.gguf", gguf)
        self.put("native-backend/licenses/Qwen-APACHE-2.0.txt", b"PUBLIC license fixture")
        build = dict(version=4, kind=NATIVE.KIND, abi_version=1, source_commit=NATIVE.SOURCE,
                     source_tree=NATIVE.SOURCE_TREE, source_overlay=NATIVE.loader_provenance(),
                     cpu_source_overlay=NATIVE.cpu_provenance(), cpu_compile_source_verified=True,
                     loader_compile_source_verified=True, upstream_original_unchanged=True,
                     output_constraints=[NATIVE.OUTPUT_CONSTRAINT], native_sessions=[NATIVE.NATIVE_SESSION],
                     cpu="avx2_fma_f16c", provisionable=True, sanitizers=False, quantization=False,
                     models_loaded=False, downloads=False, install=False, jobs=2,
                     dynamic_dependencies=["libc.so.6", "libm.so.6"],
                     library=dict(path=NATIVE.LIBRARY, bytes=len(library), sha256=hashlib.sha256(library).hexdigest()),
                     wrapper_sources={name: {key: val for key, val in record((M.WORKERS / "native-cpu" / name).read_bytes()).items()
                                            if key in ("bytes", "sha256")} for name in M.WRAPPERS})
        build_raw = M.encoded(build)
        self.put("native-backend/build.json", build_raw)
        backend = dict(version=3, kind=NATIVE.KIND, abi_version=1, source_commit=NATIVE.SOURCE,
                       model_profile=NATIVE.PROFILE, source_weights_sha256=NATIVE.WEIGHTS_SHA,
                       source_weights_bytes=NATIVE.WEIGHTS_BYTES, library=build["library"],
                       gguf=dict(path="model.gguf", bytes=len(gguf), sha256=hashlib.sha256(gguf).hexdigest()),
                       verification=dict(tensor_count=398, tensor_values_equal=True, tokenizer_equal=True,
                                         chat_template_sha256="1" * 64),
                       build_manifest_sha256=hashlib.sha256(build_raw).hexdigest(),
                       output_constraints=[NATIVE.OUTPUT_CONSTRAINT], native_sessions=[NATIVE.NATIVE_SESSION])
        self.put("native-backend/backend.json", M.encoded(backend))
        self.policy()

    def put(self, name, raw, executable=False):
        path = self.assets / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in path.parents:
            if parent == self.base:
                break
            parent.chmod(0o700)
        path.write_bytes(raw)
        path.chmod(0o700 if executable else 0o600)
        self.value["entries"][name] = record(raw, executable)

    def link(self, name, target):
        path = self.assets / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in path.parents:
            if parent == self.base:
                break
            parent.chmod(0o700)
        path.symlink_to(target)
        self.value["entries"][name] = dict(kind="symlink", target=target)

    def policy(self):
        self.put("public-policy.json", M.encoded(dict(version=1, visibility="public_fixture", requester_key="2" * 64,
                 workload_sha256=M.workload_sha256(self.value), public_input_sha256=["3" * 64, "4" * 64])))

    def inventory(self):
        raw = M.encoded(self.value)
        self.inventory_path.write_bytes(raw)
        self.inventory_path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def stage(self, **kwargs):
        digest = self.inventory()
        fake = types.SimpleNamespace(load_pins=lambda **_kwargs: self.pins)
        with mock.patch.object(M, "module", side_effect=lambda name: NATIVE if name == "llama_cpu" else fake):
            return M.stage_workload(self.assets, self.inventory_path, digest, self.output, SOURCE,
                                    kwargs.pop("deadline", time.monotonic() + 30), **kwargs)


class InventoryContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(self.temp.name)

    def check(self, value):
        raw = M.encoded(value)
        return M.inventory(raw, hashlib.sha256(raw).hexdigest(), SOURCE)

    def test_original_pins_and_current_native_versions_are_used(self):
        self.assertEqual(len(REAL_PINS["files"]), 12)
        self.assertEqual(REAL_PINS["weights"]["bytes"], 8044982000)
        self.assertEqual(REAL_PINS["revision"], "cdbee75f17c01a7cc42f958dc650907174af0554")
        self.assertEqual(NATIVE.SOURCE, "7fe450e19305b828c199d602c23a8337aaa1f03b")
        self.assertEqual(len(M.WRAPPERS), 8)

    def test_external_inventory_and_core_source_binding_required(self):
        raw = M.encoded(self.fixture.value)
        for digest, source in (("0" * 64, SOURCE), (hashlib.sha256(raw).hexdigest(), "0" * 40)):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                M.inventory(raw, digest, source)

    def test_version_bool_unknown_fields_nonpublic_rejected(self):
        for key, value in (("version", True), ("public_fixture_only", False), ("unknown", 1)):
            changed = copy.deepcopy(self.fixture.value)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(changed)

    def test_json_duplicate_keys_nan_and_unknown_entry_keys_rejected(self):
        for raw in (b'{"version":1,"version":1}', b'{"value":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.parse(raw)
        self.fixture.value["entries"]["volparossa"]["extra"] = "private canary"
        with self.assertRaises(ValueError):
            self.check(self.fixture.value)

    def test_paths_scope_and_parent_file_collisions_rejected(self):
        for name in ("../outside", "/volparossa", "runtime/../escape", "etc/anything", "runtime//x", "runtime/bin"):
            value = copy.deepcopy(self.fixture.value)
            value["entries"][name] = record(b"x")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(value)

    def test_shared_path_classifier_changes_only_literal_parentheses_on_bounded_adversarial_cases(self):
        import re
        original_pattern = re.compile(r"[A-Za-z0-9_+.,@= -]+(?:/[A-Za-z0-9_+.,@= -]+)*\Z")
        def original(name):
            return (type(name) is str and 0 < len(name) <= 240 and original_pattern.fullmatch(name)
                and all(part not in ('.', '..') for part in name.split('/')))
        class StringSubclass(str):
            pass
        cases = [None, True, 1, 1.0, b'runtime/a', [], {}, Path('runtime/a'), StringSubclass('runtime/a'),
            '', '.', '..', '...', ' ', 'runtime/a', 'runtime/./a', 'runtime/../a',
            '/runtime/a', 'runtime//a', 'runtime/a/', 'runtime/a\\b',
            'runtime/é', 'runtime/雪', 'runtime/\u202e', 'runtime/a\n', 'runtime/a\0',
            *('a' * count for count in (1, 239, 240, 241, 1024)),
            *('runtime/' + 'a' * count for count in (231, 232, 233)),
            *('a/' * count + 'b' for count in (1, 118, 119, 120))]
        cases.extend(chr(first) + chr(second) for first in range(128) for second in range(128))
        cases.extend(prefix + chr(code) + suffix for code in range(256)
            for prefix, suffix in (('', ''), ('runtime/', ''), ('runtime/a', 'b'),
                ('runtime/', '/b'), ('runtime/a/', '/b')))
        for name in cases:
            # Replacing only parentheses with an already-accepted literal proves
            # the exact character-set extension; all other original rules remain.
            expected = bool(original(name.replace('(', 'a').replace(')', 'a'))
                            if type(name) is str else original(name))
            self.assertEqual(M.path_ok(name), expected)
            self.assertEqual(M.path_rejection(name) is None, expected)
            if original(name):
                self.assertTrue(M.path_ok(name))
            elif expected:
                self.assertTrue('(' in name or ')' in name)

    def test_shared_path_classifier_reports_only_the_first_closed_rule(self):
        cases = ((None, 'inventory_path_type'), ('', 'inventory_path_empty'),
            ('a' * 241, 'inventory_path_length'),
            ('runtime/PRIVATE:CANARY', 'inventory_path_character_or_separator'),
            ('runtime//x', 'inventory_path_character_or_separator'),
            ('runtime/../x', 'inventory_path_dot_component'),
            ('./runtime/x', 'inventory_path_dot_component'))
        for name, expected in cases:
            self.assertEqual(M.path_rejection(name), expected)
            self.assertNotIn('PRIVATE', expected)
        for name in ('runtime/a', 'native-backend/license.txt', 'runtime/a_+.,@= -b', 'a' * 240):
            self.assertIsNone(M.path_rejection(name))

    def test_inventory_counts_sizes_and_lease_collision_bounded(self):
        for attribute, limit in (("MAX_ENTRIES", 2), ("MAX_TOTAL", 1), ("MAX_FILE", 1), ("MAX_INVENTORY", 1)):
            with self.subTest(attribute=attribute), mock.patch.object(M, attribute, limit), self.assertRaises(ValueError):
                self.check(self.fixture.value)
        self.fixture.value["entries"]["runtime/.volparossa-compute.lock"] = record(b"")
        with self.assertRaises(ValueError):
            self.check(self.fixture.value)

    def test_only_fixed_python_external_symlink_and_contained_venv_links(self):
        self.check(self.fixture.value)
        self.assertEqual(M.resolve_link("runtime/bin/python", self.fixture.value["entries"]), "/usr/bin/python3.13")
        for target in ("/bin/sh", "/usr/bin/python3", "../../../outside", "python", "missing"):
            value = copy.deepcopy(self.fixture.value)
            value["entries"]["runtime/bin/python3"]["target"] = target
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.check(value)

    def test_non_runtime_symlink_and_nonruntime_executable_rejected(self):
        for item in (dict(kind="symlink", target="/usr/bin/python3.13"), record(b"x", True)):
            self.fixture.value["entries"]["server.der"] = item
            with self.assertRaises(ValueError):
                self.check(self.fixture.value)

    def test_workload_excludes_policy_and_keys_but_binds_runtime_and_core(self):
        value = copy.deepcopy(self.fixture.value)
        before = M.workload_sha256(value)
        for name in ("public-policy.json", "server.der", "server-key.der"):
            value["entries"][name] = record(b"different public fixture")
        self.assertEqual(M.workload_sha256(value), before)
        value["entries"]["volparossa"] = record(b"other executable", True)
        self.assertNotEqual(M.workload_sha256(value), before)


class Staging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(self.temp.name)

    def test_complete_staging_is_deterministic_closed_and_never_execution_proof(self):
        result = self.fixture.stage()
        raw = self.fixture.output.read_bytes()
        self.fixture.output.unlink()
        again = self.fixture.stage()
        self.assertEqual(result, again)
        self.assertEqual(raw, self.fixture.output.read_bytes())
        for key in ("model_execution", "worker_execution", "hardware_attestation", "private_inputs",
                    "production_approval", "guest_key_origin_proven"):
            self.assertIs(result[key], False)
        self.assertNotIn("public fixture key", json.dumps(result))

    def test_pinned_public_parenthesized_filename_and_contained_link_survive_staging(self):
        # Real member name from pinned setuptools 84; contents are inert public
        # test bytes, not an installed/imported package or model-execution proof.
        name = "runtime/lib/python3.13/site-packages/setuptools/script (dev).tmpl"
        payload = b"public inert setuptools pathname fixture\n"
        target = "../lib/python3.13/site-packages/setuptools/script (dev).tmpl"
        self.fixture.put(name, payload)
        self.fixture.link("runtime/bin/(template)", target)
        self.fixture.policy()
        raw = M.encoded(self.fixture.value)
        checked = M.inventory(raw, hashlib.sha256(raw).hexdigest(), SOURCE)
        self.assertEqual(checked["entries"][name], record(payload))
        result = self.fixture.stage()
        self.assertTrue(result["staged"])
        self.assertFalse(result["model_execution"])
        with tarfile.open(self.fixture.output) as archive:
            member = archive.getmember("opt/volparossa/" + name)
            self.assertTrue(member.isfile())
            self.assertEqual((member.uid, member.gid, member.mode, member.size),
                             (985, 985, 0o600, len(payload)))
            self.assertEqual(archive.extractfile(member).read(), payload)
            link = archive.getmember("opt/volparossa/runtime/bin/(template)")
            self.assertTrue(link.issym())
            self.assertEqual(link.linkname, target)

    def test_parentheses_do_not_admit_traversal_shell_syntax_controls_or_long_paths(self):
        for name in ("/runtime/(dev)", "runtime/(dev)/../outside", "runtime/(dev)//x",
                     "runtime/(dev)/x/", "runtime/$(command)", "runtime/(dev);command",
                     "runtime/(dev)`command`", "runtime/(dev):command", "runtime/(dev)\\x",
                     "runtime/(dev)\n", "runtime/(dev)\t", "runtime/(dev)\0", "runtime/(dév)",
                     "runtime/(雪)", "runtime/(\u202e)", "runtime/(" + "a" * 231 + ")"):
            changed = copy.deepcopy(self.fixture.value)
            changed["entries"][name] = record(b"public fixture")
            raw = M.encoded(changed)
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.inventory(raw, hashlib.sha256(raw).hexdigest(), SOURCE)
        self.assertTrue(M.path_ok("runtime/(" + "a" * 230 + ")"))  # 240 chars.
        for target in ("../../../outside (dev)", "/outside (dev)", "$(command)", "(missing)"):
            changed = copy.deepcopy(self.fixture.value)
            changed["entries"]["runtime/bin/(template)"] = dict(kind="symlink", target=target)
            raw = M.encoded(changed)
            with self.subTest(target=target), self.assertRaises(ValueError):
                M.inventory(raw, hashlib.sha256(raw).hexdigest(), SOURCE)

    def test_parenthesized_file_cannot_bypass_no_follow_digest_or_size_checks(self):
        name = "runtime/lib/python3.13/site-packages/setuptools/script (dev).tmpl"
        self.fixture.put(name, b"public original bytes")
        self.fixture.policy()
        path = self.fixture.assets / name
        path.write_bytes(b"public modified bytes")
        with self.assertRaisesRegex(ValueError, "asset_digest"):
            self.fixture.stage()
        self.assertFalse(self.fixture.output.exists())
        self.fixture.put(name, b"public original bytes")
        path.write_bytes(b"longer public original bytes")
        with self.assertRaisesRegex(ValueError, "asset_file_bound"):
            self.fixture.stage()
        self.assertFalse(self.fixture.output.exists())
        self.fixture.put(name, b"public original bytes")
        moved = self.fixture.base / "owner-setuptools"
        path.parent.rename(moved)
        path.parent.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "asset_inventory_exact"):
            self.fixture.stage()
        self.assertFalse(self.fixture.output.exists())

    def test_guest_metadata_fixed_paths_lease_and_no_volatile_work_contents(self):
        self.fixture.stage()
        with tarfile.open(self.fixture.output) as archive:
            self.assertEqual(archive.getmember("usr/bin/volparossa").mode, 0o555)
            self.assertEqual(archive.getmember("usr/bin/volparossa").uid, 0)
            for name in ("runtime", "model", "native-backend"):
                entry = archive.getmember("opt/volparossa/" + name)
                self.assertEqual((entry.uid, entry.gid, entry.mode), (985, 985, 0o700))
            lease = archive.getmember("opt/volparossa/runtime/.volparossa-compute.lock")
            self.assertEqual((lease.uid, lease.mode, lease.size), (985, 0o600, 0))
            self.assertFalse(any(name.startswith("run/") for name in archive.getnames()))
            key = archive.getmember("etc/volparossa-resident/server-key.der")
            self.assertEqual((key.uid, key.mode), (985, 0o600))

    def test_fixed_launch_argv_hash_and_virtio_prerequisites(self):
        result = self.fixture.stage()
        with tarfile.open(self.fixture.output) as archive:
            raw = archive.extractfile(M.LAUNCH_PATH).read()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result["launch_sha256"])
        launch = json.loads(raw)
        self.assertEqual(launch["argv"][:3], ["/usr/bin/volparossa", "compute", "resident-guest"])
        index = launch["argv"].index("--native-backend-sha256")
        self.assertEqual(launch["argv"][index + 1], result["native_backend_sha256"])
        self.assertEqual(launch["argv"][-1], "--execute")
        self.assertEqual(launch["profile"]["required_kernel_module"], "virtio_console")
        self.assertEqual(launch["profile"]["maximum_requests"], 2)
        self.assertEqual(launch["profile"]["maximum_task_seconds"], 2400)
        self.assertEqual(launch["profile"]["threads"], 2)
        self.assertNotIn("sh", launch["argv"])

    def test_existing_output_never_replaced(self):
        self.fixture.output.write_bytes(b"owner file")
        with self.assertRaises(FileExistsError):
            self.fixture.stage()
        self.assertEqual(self.fixture.output.read_bytes(), b"owner file")

    def test_replaced_output_is_preserved_on_original_staging_failure(self):
        target = self.fixture.base / "owner-target"
        target.write_bytes(b"owner replacement")
        failure = ValueError("original staging failure")
        for replacement in ("file", "symlink", "directory", "missing"):
            def replace_and_fail(_reader, _size):
                self.fixture.output.unlink()
                if replacement == "file":
                    self.fixture.output.write_bytes(b"owner replacement")
                elif replacement == "symlink":
                    self.fixture.output.symlink_to(target)
                elif replacement == "directory":
                    self.fixture.output.mkdir()
                raise failure

            with self.subTest(replacement=replacement), mock.patch.object(M.CheckedReader, "read", replace_and_fail):
                with self.assertRaises(ValueError) as raised:
                    self.fixture.stage()
                self.assertIs(raised.exception, failure)
                if replacement in ("file", "symlink"):
                    self.assertEqual(self.fixture.output.read_bytes(), b"owner replacement")
                    self.assertEqual(self.fixture.output.is_symlink(), replacement == "symlink")
                    self.fixture.output.unlink()
                elif replacement == "directory":
                    self.assertTrue(self.fixture.output.is_dir())
                    self.fixture.output.rmdir()
                else:
                    self.assertFalse(self.fixture.output.exists())
                self.assertEqual(target.read_bytes(), b"owner replacement")

    def test_extra_and_missing_source_assets_rejected(self):
        extra = self.fixture.assets / "extra"
        extra.write_bytes(b"private-canary")
        with self.assertRaises(ValueError):
            self.fixture.stage()
        extra.unlink()
        (self.fixture.assets / "volparossa").unlink()
        with self.assertRaises(ValueError):
            self.fixture.stage()
        self.assertFalse(self.fixture.output.exists())

    def test_wrong_file_digest_removes_only_owned_partial_output(self):
        source = self.fixture.assets / "volparossa"
        source.write_bytes(b"different bytes")
        with self.assertRaises(ValueError):
            self.fixture.stage()
        self.assertFalse(self.fixture.output.exists())
        self.assertEqual(source.read_bytes(), b"different bytes")

    def test_hardlinks_symlinks_and_writable_assets_denied(self):
        source = self.fixture.assets / "volparossa"
        os.link(source, self.fixture.base / "hardlink")
        with self.assertRaises(ValueError):
            self.fixture.stage()
        (self.fixture.base / "hardlink").unlink()
        source.chmod(0o777)
        with self.assertRaises(ValueError):
            self.fixture.stage()
        source.unlink()
        source.symlink_to(self.fixture.base / "hardlink")
        with self.assertRaises((ValueError, OSError)):
            self.fixture.stage()

    def test_inventory_fifo_symlink_and_oversized_file_never_followed(self):
        path = self.fixture.base / "fifo"
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            M.read_inventory(path, time.monotonic() + 1)
        link = self.fixture.base / "link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            M.read_inventory(link, time.monotonic() + 1)
        self.fixture.inventory()
        with mock.patch.object(M, "MAX_INVENTORY", 2), self.assertRaises(ValueError):
            M.read_inventory(self.fixture.inventory_path, time.monotonic() + 1)

    def test_deadline_expired_nonfinite_and_cancel_never_publish(self):
        for deadline in (0, float("inf"), float("nan"), True):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                self.fixture.stage(deadline=deadline)
        with mock.patch.object(M.CheckedReader, "read", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.fixture.stage()
        self.assertFalse(self.fixture.output.exists())

    def test_source_changed_during_stream_is_rejected(self):
        original = M.CheckedReader.read
        changed = False

        def read(reader, count):
            nonlocal changed
            raw = original(reader, count)
            if not changed:
                changed = True
                os.utime(reader.stream.fileno(), ns=(1, 1))
            return raw

        with mock.patch.object(M.CheckedReader, "read", read), self.assertRaises(ValueError):
            self.fixture.stage()
        self.assertFalse(self.fixture.output.exists())

    def test_output_inside_assets_and_symlink_parent_rejected(self):
        self.fixture.output = self.fixture.assets / "output.tar"
        with self.assertRaises(ValueError):
            self.fixture.stage()
        link = self.fixture.base / "alias"
        link.symlink_to(self.fixture.base, target_is_directory=True)
        self.fixture.output = link / "output.tar"
        with self.assertRaises(ValueError):
            self.fixture.stage()

    def test_unchanged_real_model_pin_loader_rejects_tiny_fixture(self):
        digest = self.fixture.inventory()
        with self.assertRaisesRegex(ValueError, "model_pin"):
            M.stage_workload(self.fixture.assets, self.fixture.inventory_path, digest, self.fixture.output,
                             SOURCE, time.monotonic() + 30)

    def test_native_version_wrapper_digest_and_cpu_patch_not_downgraded(self):
        for field, replacement in (("version", 3), ("cpu_compile_source_verified", False), ("wrapper_sources", {})):
            with self.subTest(field=field):
                original = (self.fixture.assets / "native-backend/build.json").read_bytes()
                build = json.loads(original)
                build[field] = replacement
                raw = M.encoded(build)
                self.fixture.put("native-backend/build.json", raw)
                backend = json.loads((self.fixture.assets / "native-backend/backend.json").read_bytes())
                backend["build_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
                self.fixture.put("native-backend/backend.json", M.encoded(backend))
                self.fixture.policy()
                with self.assertRaises(ValueError):
                    self.fixture.stage()
                self.fixture.put("native-backend/build.json", original)

    def test_policy_workload_binding_and_private_scope_fail_closed(self):
        for field, replacement in (("workload_sha256", "0" * 64), ("visibility", "private"),
                                   ("version", True), ("public_input_sha256", ["3" * 64])):
            self.fixture.policy()
            value = json.loads((self.fixture.assets / "public-policy.json").read_bytes())
            value[field] = replacement
            self.fixture.put("public-policy.json", M.encoded(value))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.fixture.stage()

    def test_runtime_system_packages_or_wrong_python_denied(self):
        for cfg in (b"home = /usr/bin\ninclude-system-site-packages = true\nversion = 3.13.5\n",
                    b"home = /private-host-path\ninclude-system-site-packages = false\nversion = 3.13.5\n"):
            self.fixture.put("runtime/pyvenv.cfg", cfg)
            self.fixture.policy()
            with self.assertRaises(ValueError):
                self.fixture.stage()

    def test_core_script_or_wrong_elf_machine_cannot_replace_bound_binary(self):
        wrong_machine = bytearray(public_elf())
        struct.pack_into("<H", wrong_machine, 18, 183)
        for raw in (b"#!/bin/sh\n", bytes(wrong_machine)):
            self.fixture.put("volparossa", raw, True)
            self.fixture.policy()
            with self.assertRaisesRegex(ValueError, "elf_"):
                self.fixture.stage()

    def test_policy_and_tls_bounds_match_actual_guest_adapter(self):
        self.fixture.put("server.der", b"x" * 8193)
        with self.assertRaisesRegex(ValueError, "fixture_tls_bound"):
            self.fixture.stage()
        self.fixture.put("server.der", b"public fixture")
        policy = (self.fixture.assets / "public-policy.json").read_bytes() + b" " * 4096
        self.fixture.put("public-policy.json", policy)
        with self.assertRaisesRegex(ValueError, "asset_file_bound"):
            self.fixture.stage()

    def test_cli_failure_emits_no_path_key_exception_or_payload(self):
        canary = "PRIVATE_CANARY_NO_EXPORT"
        result = subprocess.run([sys.executable, "-B", str(HERE / "protected-resident-model-workload.py"),
            "--assets", str(self.fixture.base / canary), "--inventory", str(self.fixture.inventory_path),
            "--inventory-sha256", "0" * 64, "--expected-source", SOURCE, "--output", str(self.fixture.output),
            "--deadline-monotonic", str(time.monotonic() + 5)], capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(canary.encode(), result.stdout)
        self.assertEqual(json.loads(result.stdout), dict(version=1, kind="protected-resident-public-workload-staging", staged=False))


if __name__ == "__main__":
    unittest.main()
