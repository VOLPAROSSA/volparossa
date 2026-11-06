#!/usr/bin/env python3
"""Inert archive/ELF/path/closed-shell contracts; never boot or load a module."""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("resident_initrd", HERE / "protected-resident-initrd.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
INIT = (HERE.parents[1] / "packaging/protected-resident/init").read_text()
ENTRY = (HERE.parents[1] / "packaging/protected-resident/entrypoint").read_text()


def elf(needed=None, interpreter=None):
    data = bytearray(1024)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<Q", data, 32, 64)
    count = 1 + (needed is not None) + (interpreter is not None)
    struct.pack_into("<HH", data, 54, 56, count)
    headers = [(1, 0, 0, 0x400000, 0, len(data), len(data), 4096)]
    if needed is not None:
        table = b"\0" + needed.encode() + b"\0"
        data[512:512 + len(table)] = table
        for index, pair in enumerate(((1, 1), (5, 0x400200), (10, len(table)), (0, 0))):
            struct.pack_into("<qQ", data, 320 + index * 16, *pair)
        headers.append((2, 0, 320, 0, 0, 64, 64, 8))
    if interpreter is not None:
        value = interpreter.encode() + b"\0"
        data[768:768 + len(value)] = value
        headers.append((3, 0, 768, 0, 0, len(value), len(value), 1))
    for index, header in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, *header)
    return bytes(data)


def unpack(data):
    raw, offset, entries = gzip.decompress(data), 0, {}
    while True:
        assert raw[offset:offset + 6] == b"070701"
        fields = [int(raw[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        offset += 110
        name = raw[offset:offset + fields[11] - 1].decode()
        offset = (offset + fields[11] + 3) & ~3
        body = raw[offset:offset + fields[6]]
        offset = (offset + fields[6] + 3) & ~3
        if name == "TRAILER!!!":
            break
        assert name not in entries
        entries[name] = (fields, body)
    return entries


class Paths(unittest.TestCase):
    def test_absolute_image_symlinks_never_read_the_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usr/lib").mkdir(parents=True)
            (root / "usr/lib/public").write_bytes(b"image")
            (root / "lib").symlink_to("/usr/lib")
            self.assertEqual(M.read_source(root, "/lib/public"), b"image")

    def test_relative_image_symlinks_remain_inside_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usr/bin").mkdir(parents=True)
            (root / "usr/bin/public").write_bytes(b"image")
            (root / "usr/link").symlink_to("bin/public")
            self.assertEqual(M.read_source(root, "/usr/link"), b"image")

    def test_symlink_escape_loop_and_missing_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "escape").symlink_to("../outside")
            (root / "loop").symlink_to("loop")
            for path in ("/escape", "/loop", "/../outside"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    M.rooted(root, path)
            with self.assertRaises(FileNotFoundError):
                M.rooted(root, "/no-fallback")

    def test_special_files_and_oversized_sources_are_not_archived(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "fifo")
            with self.assertRaises(ValueError):
                M.read_source(root, "/fifo")
            (root / "large").write_bytes(b"123")
            with mock.patch.object(M, "MAX_FILE", 2), self.assertRaises(ValueError):
                M.read_source(root, "/large")


class ElfClosure(unittest.TestCase):
    def test_static_and_dynamic_elf_dependencies_are_parsed_without_execution(self):
        self.assertEqual(M.elf_dependencies(elf()), (None, []))
        loader = "/lib64/ld-linux-x86-64.so.2"
        self.assertEqual(M.elf_dependencies(elf("libc.so.6", loader)), (loader, ["libc.so.6"]))

    def test_bad_elf_machine_lengths_and_interpreter_are_rejected(self):
        bad_machine = bytearray(elf())
        struct.pack_into("<H", bad_machine, 18, 183)
        bad_headers = bytearray(elf())
        struct.pack_into("<H", bad_headers, 56, 129)
        for value in (b"#!/bin/sh\n", elf()[:200], bytes(bad_machine), bytes(bad_headers),
                      elf(interpreter="/tmp/foreign-loader")):
            with self.subTest(value=value[:8]), self.assertRaises(ValueError):
                M.elf_dependencies(value)

    def test_library_search_override_and_slash_names_are_rejected(self):
        for tag in (15, 29):
            value = bytearray(elf("libc.so.6"))
            struct.pack_into("<qQ", value, 320, tag, 1)
            with self.assertRaises(ValueError):
                M.elf_dependencies(value)
        with self.assertRaises(ValueError):
            M.elf_dependencies(elf("../../host-library"))

    def test_dependency_closure_is_recursive_bounded_and_source_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usr/bin").mkdir(parents=True)
            (root / "lib/x86_64-linux-gnu").mkdir(parents=True)
            (root / "usr/bin/public").write_bytes(elf("libpublic.so"))
            (root / "lib/x86_64-linux-gnu/libpublic.so").write_bytes(elf())
            closure = M.Closure(root)
            closure.executable("/usr/bin/public")
            self.assertEqual(set(closure.files), {"/usr/bin/public", "/lib/x86_64-linux-gnu/libpublic.so"})
            with mock.patch.object(M, "MAX_FILES", 2), self.assertRaises(ValueError):
                closure.add("/extra", b"x", 0o644)

    def test_missing_library_cannot_fall_back_to_host_libc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "public").write_bytes(elf("libc.so.6"))
            with self.assertRaises(ValueError):
                M.Closure(root).executable("/public")


class Archive(unittest.TestCase):
    def fixture(self, root):
        for name in M.BINARIES:
            path = root / name.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(elf())
        modules = root / "lib/modules/6.12.public"
        modules.mkdir(parents=True)
        (modules / "modules.dep").write_text("")
        (modules / "modules.builtin").write_text("".join("kernel/" + name + ".ko\n" for name in M.MODULES))
        for name in ("dep.bin", "alias", "alias.bin", "builtin.bin", "builtin.modinfo",
                     "softdep", "symbols", "symbols.bin"):
            (modules / ("modules." + name)).write_bytes(b"public-index")

    def test_synthetic_closure_build_is_deterministic_and_binds_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "root"
            root.mkdir()
            self.fixture(root)
            original = parent / "original"
            original.write_bytes(b"public original-initrd fixture, not executed")
            one, two = parent / "one.gz", parent / "two.gz"
            first = M.build(root, original, "6.12.public", "a" * 64, 7, one)
            second = M.build(root, original, "6.12.public", "a" * 64, 7, two)
            self.assertEqual(first, second)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            entries = unpack(one.read_bytes())
            self.assertIn(b"ROOT_HASH='" + b"a" * 64 + b"'", entries["init"][1])
            self.assertIn(b"DATA_BLOCKS='7'", entries["init"][1])
            self.assertNotIn(b"@ROOT_HASH@", entries["init"][1])
            self.assertEqual(entries["bin/sh"][1], b"/usr/bin/busybox")
            self.assertEqual(entries["dev/console"][0][9:11], [5, 1])
            self.assertTrue(all(fields[2:4] == [0, 0] for fields, _ in entries.values()))
            for key in ("hardware_attestation", "private_inputs", "model_execution", "worker_execution"):
                self.assertIs(first[key], False)
            self.assertEqual(one.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                M.build(root, original, "6.12.public", "a" * 64, 7, one)

    def test_bad_binding_values_reject_before_building(self):
        for version, digest, blocks in (("x;exec", "a" * 64, 1), ("x", "A" * 64, 1),
                                        ("x", "a" * 64, 0), ("x", "a" * 64, True),
                                        ("x", "a" * 64, M.MAX_DATA_BLOCKS + 1)):
            with self.subTest(version=version, blocks=blocks), self.assertRaises(ValueError):
                M.build(Path("missing"), Path("missing"), version, digest, blocks, Path("unused"))

    def test_archive_rejects_a_file_parent_collision(self):
        with self.assertRaises(ValueError):
            M.archive({"/usr": (b"file", 0o644), "/usr/bin/child": (b"x", 0o644)})

    def test_module_dependency_closure_excludes_unrequested_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            modules = root / "lib/modules/6.12.public"
            (modules / "modules.builtin").write_text("".join(
                "kernel/" + name + ".ko\n" for name in M.MODULES if name != "dm_verity"))
            (modules / "modules.dep").write_text(
                "kernel/dm-verity.ko: kernel/dm-bufio.ko\n"
                "kernel/dm-bufio.ko:\n"
                "kernel/unrelated.ko:\n")
            (modules / "kernel").mkdir()
            for name in ("dm-verity", "dm-bufio", "unrelated"):
                (modules / ("kernel/" + name + ".ko")).write_bytes(b"public module")
            closure = M.Closure(root)
            closure.modules("6.12.public")
            self.assertIn("/lib/modules/6.12.public/kernel/dm-bufio.ko", closure.files)
            self.assertNotIn("/lib/modules/6.12.public/kernel/unrelated.ko", closure.files)

    def test_missing_required_module_has_no_generic_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "lib/modules/6.12.public/modules.builtin").write_text("")
            with self.assertRaises(ValueError):
                M.Closure(root).modules("6.12.public")


class BootContracts(unittest.TestCase):
    def shell(self, body):
        receipt = INIT.split("receipt() {\n", 1)[1].split("\n}\n", 1)[0]
        receipt = "receipt() {\n" + receipt.replace(">/dev/console", "") + "\n}\n"
        return subprocess.run(["/bin/sh", "-c", "set -eu\n" + receipt + body],
                              text=True, capture_output=True, timeout=5, check=False)

    def test_verity_open_uses_exact_pinned_cli_arguments_without_fallback(self):
        # Pinned 2.7.5 has no batch-mode option; unknown options fail before open:
        # https://github.com/mbroz/cryptsetup/blob/v2.7.5/src/veritysetup_arg_list.h
        # https://github.com/mbroz/cryptsetup/blob/v2.7.5/src/veritysetup.c#L525-L558
        block = INIT.split("stage=verity_open\n", 1)[1].split(
            "/usr/sbin/dmsetup mknodes vp-root\n", 1)[0]
        self.assertTrue(block.startswith("/usr/sbin/veritysetup open "))
        self.assertTrue(block.endswith('"$ROOT_HASH" >/dev/null 2>&1\n'))
        self.assertEqual(block.count("/usr/sbin/veritysetup"), 1)
        # Only substitute the executable with a shell function: no device opens,
        # real verity binary, bootstrap mounts or privileged operations execute.
        captured = block.replace("/usr/sbin/veritysetup", "capture_veritysetup", 1)
        bindings = "\n".join(line for line in INIT.splitlines()
                             if line.startswith(("ROOT_HASH=", "DATA_BLOCKS=", "SALT=")))
        root_hash = "0123456789abcdef" * 4
        for blocks in (1, 753408, M.MAX_DATA_BLOCKS):
            for status in (0, 7):
                with self.subTest(blocks=blocks, status=status):
                    values = bindings.replace("@ROOT_HASH@", root_hash).replace(
                        "@DATA_BLOCKS@", str(blocks))
                    body = ("set -efu\nexec 3>&1\n" + values + "\n"
                            "capture_veritysetup() { printf '%s\\n' \"$@\" >&3; "
                            f"return {status}; }}\n" + captured + "printf 'returned\\n'\n")
                    result = subprocess.run(["/bin/sh", "-c", body], stdin=subprocess.DEVNULL,
                        text=True, capture_output=True, timeout=5, check=False,
                        env={"PATH": "/nonexistent", "LC_ALL": "C"})
                    expected = ["open", "--no-superblock", "--format=1", "--hash=sha256",
                        "--data-block-size=4096", "--hash-block-size=4096",
                        "--data-blocks=" + str(blocks), "--salt=" + "0" * 64,
                        "/dev/vda", "vp-root", "/dev/vdb", root_hash]
                    self.assertEqual(result.stdout.splitlines(),
                                     expected + (["returned"] if status == 0 else []))
                    self.assertEqual(result.returncode, status)
                    self.assertEqual(result.stderr, "")

    def test_success_receipt_is_closed_and_never_private_authority(self):
        result = self.shell("stage=complete\nreceipt boot_verified\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix, raw = result.stdout.split(" ", 1)
        self.assertEqual(prefix, "VP_PROTECTED_BOOT_V1")
        value = json.loads(raw)
        self.assertEqual(set(value), {"version", "outcome", "stage", "verity_verified",
                                     "root_readonly", "write_denied", "entrypoint_invoked",
                                     "hardware_attestation", "private_inputs", "model_execution",
                                     "worker_execution"})
        self.assertEqual(value, dict(version=1, outcome="boot_verified", stage="complete",
                                    verity_verified=True, root_readonly=True, write_denied=True,
                                    entrypoint_invoked=True, hardware_attestation=False,
                                    private_inputs=False, model_execution=False, worker_execution=False))
        self.assertLess(len(result.stdout.encode()), 1024)

    def test_integrity_failure_requires_both_read_failure_and_kernel_c_status(self):
        block = INIT.split("stage=verity_read\n", 1)[1].split("stage=root_mount\n", 1)[0]
        block = block.replace("/usr/bin/busybox dd if=/dev/mapper/vp-root of=/dev/null bs=4096 count=\"$DATA_BLOCKS\" 2>/run/read-error", "fixture_read")
        block = block.replace("/usr/sbin/dmsetup status vp-root", "fixture_status")
        for read_status, status, expected in ((1, "0 56 verity C", True),
                                               (1, "0 56 verity V", False),
                                               (1, "0 55 verity C", False),
                                               (1, "0 56 other C", False),
                                               (0, "0 56 verity C", False)):
            body = ("DATA_BLOCKS=7\nstage=verity_read\n"
                    f"fixture_read() {{ return {read_status}; }}\n"
                    f"fixture_status() {{ printf '%s\\n' '{status}'; }}\n" + block)
            result = self.shell(body)
            with self.subTest(read_status=read_status, status=status):
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual("integrity_failure" in result.stdout, expected)
                if expected:
                    value = json.loads(result.stdout.split(" ", 1)[1])
                    self.assertTrue(all(value[key] is False for key in value if key.endswith(
                        ("verified", "readonly", "denied", "invoked", "attestation", "inputs", "execution"))))

    def test_original_init_is_not_executed_and_no_rescue_or_cmdline_hash_override_exists(self):
        self.assertIn("[ \"$$\" -eq 1 ] || exit 1", INIT)
        self.assertIn(M.CMDLINE, INIT)
        self.assertIn('[ "$(/usr/bin/busybox cat /proc/cmdline)" = "$EXPECTED_CMDLINE" ]', INIT)
        self.assertNotRegex(INIT, r"(?:switch_root|/sbin/init|systemctl|cloud-init|sshd|eval |exec sh)")
        self.assertNotIn("ignore-corruption", INIT)
        self.assertNotIn("check-at-most-once", INIT)
        self.assertLess(INIT.index("stage=verity_read"), INIT.index("stage=root_mount"))
        self.assertLess(INIT.index("stage=write_probe"), INIT.index("stage=entrypoint"))

    def test_write_probe_checks_real_known_path_and_erofs_not_only_command_failure(self):
        block = INIT.split("stage=write_probe\n", 1)[1].split("stage=entrypoint\n", 1)[0]
        self.assertIn("0:0:755", block)
        self.assertIn("0:0:644", block)
        self.assertIn("[ ! -L /newroot/usr/lib/volparossa/verity-write-probe ]", block)
        self.assertIn("printf 'must not be written", block)
        self.assertIn("grep -F 'Read-only file system' /run/write-error", block)
        self.assertIn("mount -t ext4 -o ro,noload", INIT)

    def test_fixed_entrypoint_preserves_runtime_permissions_and_starts_no_worker(self):
        self.assertIn("985:985:700", ENTRY)
        self.assertIn("985:985:600", ENTRY)
        self.assertNotRegex(ENTRY, r"(?:chmod |chown |exec |python|worker\.py|systemctl)")
        self.assertIn("[ \"$#\" -eq 0 ]", ENTRY)
        self.assertIn("VP_PROTECTED_ENTRYPOINT_V1", ENTRY)

    def test_shell_syntax_and_template_substitution_have_no_unknown_inputs(self):
        for source in (INIT, ENTRY):
            result = subprocess.run(["/bin/sh", "-n"], input=source, text=True,
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(re.findall(r"@([A-Z_]+)@", INIT)),
                         {"ROOT_HASH", "DATA_BLOCKS", "KERNEL_VERSION"})


if __name__ == "__main__":
    unittest.main()
