#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert synthetic ELF/sysfs/argv tests; no VM, device, privilege or model work."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(path, name):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), value.__dict__)
    return value


M = load(HERE / "protected-resident-model-initrd.py", "model_initrd")
OLD = load(HERE / "test-protected-resident-initrd.py", "old_initrd_tests")
W = load(HERE / "protected-resident-model-workload.py", "model_workload")
E = types.ModuleType("model_entry")
exec(compile(M.entrypoint(), M.ENTRY, "exec"), E.__dict__)
INIT = (M.SOURCE / "init").read_text()


def launch():
    return W.launch_contract("a" * 64)


def fixture(root):
    OLD.Archive().fixture(root)
    modules = root / "lib/modules/6.12.public"
    with (modules / "modules.builtin").open("a") as stream:
        stream.write("kernel/virtio_console.ko\n")
    for name in E.PROFILE["required_guest_executables"] + ["/usr/bin/setpriv", "/usr/bin/volparossa"]:
        path = root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(OLD.elf())
    # Synthetic source OS metadata, independent of the developer's umask.
    for parent, directories, _files in os.walk(root):
        for name in directories:
            (Path(parent) / name).chmod(0o755)
    M.stage_boot_files(root)
    path = root / "usr/lib/volparossa/protected-resident-model-launch.json"
    path.write_text(json.dumps(launch()))


class ImageClosure(unittest.TestCase):
    def test_separate_profile_archive_is_deterministic_and_has_no_model_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            fixture(root)
            original = Path(directory) / "original"
            original.write_bytes(b"original public initrd, never executed")
            one, two = Path(directory) / "one", Path(directory) / "two"
            result = M.build(root, original, "6.12.public", "a" * 64, 8, one)
            self.assertEqual(result, M.build(root, original, "6.12.public", "a" * 64, 8, two))
            self.assertEqual(one.read_bytes(), two.read_bytes())
            entries = OLD.unpack(one.read_bytes())
            self.assertIn(b"virtio_console", entries["init"][1])
            self.assertIn(M.CMDLINE.encode(), entries["init"][1])
            self.assertNotIn(b"@ROOT_HASH@", entries["init"][1])
            self.assertNotIn("usr/bin/volparossa", entries)  # Sealed OS, not initrd copies.
            self.assertEqual(result["entrypoint_sha256"], hashlib.sha256(M.entrypoint()).hexdigest())
            for key in ("hardware_attestation", "private_inputs", "model_execution", "worker_execution",
                        "production_approval", "guest_key_origin_proven"):
                self.assertIs(result[key], False)
            with self.assertRaises(FileExistsError):
                M.build(root, original, "6.12.public", "a" * 64, 8, one)

    def test_new_32gib_bound_does_not_change_old_16gib_bound(self):
        self.assertEqual(M.MAX_DATA_BLOCKS * 4096, 32 * 1024 ** 3)
        self.assertEqual(M.BASE.MAX_DATA_BLOCKS * 4096, 16 * 1024 ** 3)
        for blocks in (0, True, M.MAX_DATA_BLOCKS + 1):
            with self.subTest(blocks=blocks), self.assertRaisesRegex(ValueError, "initrd_data_blocks"):
                M.build(Path("missing"), Path("missing"), "6.12.public", "a" * 64, blocks, Path("unused"))
        with mock.patch.object(M, "validate_root", side_effect=RuntimeError("reached")):
            with self.assertRaisesRegex(RuntimeError, "reached"):
                M.build(Path("missing"), Path("missing"), "6.12.public", "a" * 64, M.MAX_DATA_BLOCKS, Path("unused"))

    def test_old_module_default_is_exact_and_virtio_console_is_mandatory_only_new(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            OLD.Archive().fixture(root)
            default, explicit = M.BASE.Closure(root), M.BASE.Closure(root)
            default.modules("6.12.public")
            explicit.modules("6.12.public", M.BASE.MODULES)
            self.assertEqual(default.files, explicit.files)
            with self.assertRaisesRegex(ValueError, "initrd_module_missing"):
                M.BASE.Closure(root).modules("6.12.public", M.MODULES)

    def test_stage_installs_only_fixed_files_and_real_mountpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            M.stage_boot_files(root)
            self.assertEqual((root / M.ENTRY.lstrip("/")).read_bytes(), M.entrypoint())
            self.assertEqual((root / M.ENTRY.lstrip("/")).stat().st_mode & 0o777, 0o555)
            self.assertEqual((root / "usr/lib/volparossa/verity-write-probe").read_bytes(), M.CANARY)
            for name in ("proc", "sys", "dev", "run"):
                self.assertEqual((root / name).stat().st_mode & 0o777, 0o755)
            with self.assertRaises(FileExistsError):
                M.stage_boot_files(root)

    def test_stage_refuses_symlink_and_writable_directory(self):
        for kind in ("symlink", "writable"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if kind == "symlink":
                    (root / "usr").symlink_to("/canary-outside")
                else:
                    (root / "usr").mkdir(mode=0o777)
                    (root / "usr").chmod(0o777)
                with self.assertRaises(ValueError):
                    M.stage_boot_files(root)

    def test_private_builder_umask_does_not_break_guest_mountpoint_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0o077)
            try:
                root = Path(directory)
                M.stage_boot_files(root)
                for name in ("usr", "usr/lib", "usr/lib/volparossa", "proc", "sys", "dev", "run"):
                    self.assertEqual((root / name).stat().st_mode & 0o777, 0o755)
            finally:
                os.umask(previous)

    def test_missing_os_tool_or_changed_entrypoint_is_not_accepted_as_closure(self):
        for kind in ("tool", "entry", "launch"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture(root)
                if kind == "tool":
                    (root / "usr/bin/setpriv").unlink()
                elif kind == "entry":
                    path = root / M.ENTRY.lstrip("/")
                    path.chmod(0o755)
                    path.write_bytes(b"private canary, not executable")
                else:
                    (root / "usr/lib/volparossa/protected-resident-model-launch.json").write_text("{}")
                with self.assertRaises((ValueError, FileNotFoundError)):
                    M.validate_root(root)


class Launch(unittest.TestCase):
    def test_launch_matches_existing_stager_exactly(self):
        self.assertEqual(E.decode_launch(json.dumps(launch()).encode()), E.argv_for("a" * 64))
        self.assertEqual(E.argv_for("a" * 64)[12], "a" * 64)

    def test_unknown_duplicate_nonfinite_and_wrong_types_reject(self):
        raw = json.dumps(launch())
        cases = [raw[:-1] + ',"other":"private canary"}', raw[:-1] + ',"argv":[]}',
                 raw.replace('"maximum_requests": 2', '"maximum_requests": NaN'), "[]"]
        for value in cases:
            with self.subTest(value=value[:10]), self.assertRaises(ValueError):
                E.decode_launch(value.encode())

    def test_profile_downgrade_bool_integer_and_arbitrary_argv_reject(self):
        for change in ("profile", "bool", "argv", "hash", "extra"):
            value = copy.deepcopy(launch())
            if change == "profile":
                value["profile"]["maximum_requests"] = 3
            elif change == "bool":
                value["profile"]["hardware_attestation"] = 0
            elif change == "argv":
                value["argv"][0] = "/bin/sh"
            elif change == "hash":
                value["native_backend_sha256"] = "$(private canary)"
            else:
                value["argv"].append("--help")
            with self.subTest(change=change), self.assertRaises(ValueError):
                E.decode_launch(json.dumps(value).encode())

    def test_launch_size_and_private_symlink_mode_bound(self):
        with self.assertRaises(ValueError):
            E.decode_launch(b" " * 16385)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            path.write_bytes(b"public fixture")
            path.chmod(0o600)
            owner = os.getuid()
            self.assertEqual(E.read_regular(path, 20, owner, 0o600), b"public fixture")
            for maximum, mode in ((2, 0o600), (20, 0o644)):
                with self.assertRaises(ValueError):
                    E.read_regular(path, maximum, owner, mode)
            alias = path.with_name("alias")
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                E.read_regular(alias, 20, owner, 0o600)

    def test_root_phase_execs_only_fixed_privilege_drop_with_clean_env(self):
        with mock.patch.object(E, "read_regular", return_value=json.dumps(launch()).encode()), \
             mock.patch.object(E.os, "getuid", return_value=0), mock.patch.object(E.os, "geteuid", return_value=0), \
             mock.patch.object(E.sys, "argv", [E.SELF]), mock.patch.object(E, "bind_port") as port, \
             mock.patch.object(E.os, "execve", side_effect=RuntimeError("exec boundary")) as execute:
            with self.assertRaisesRegex(RuntimeError, "exec boundary"):
                E.main()
            port.assert_called_once_with()
            binary, argv, env = execute.call_args.args
            self.assertEqual(binary, "/usr/bin/setpriv")
            self.assertEqual(argv, [binary, "--reuid=985", "--regid=985", "--clear-groups", "--inh-caps=-all",
                                   "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
                                   "/usr/bin/python3.13", "-I", E.SELF, "--unprivileged"])
            self.assertEqual(env, E.ENV)

    def test_unprivileged_phase_hashes_backend_before_exact_core_exec(self):
        manifest = b"public native manifest"
        value = W.launch_contract(hashlib.sha256(manifest).hexdigest())
        with mock.patch.object(E, "read_regular", side_effect=[json.dumps(value).encode(), manifest]), \
             mock.patch.object(E.sys, "argv", [E.SELF, "--unprivileged"]), \
             mock.patch.object(E, "unprivileged") as guard, \
             mock.patch.object(E, "announce_ready") as ready, \
             mock.patch.object(E.os, "execve", side_effect=RuntimeError("exec boundary")) as execute:
            with self.assertRaisesRegex(RuntimeError, "exec boundary"):
                E.main()
            guard.assert_called_once_with()
            ready.assert_called_once_with()
            self.assertEqual(execute.call_args.args, ("/usr/bin/volparossa", value["argv"], E.ENV))

    def test_ready_uses_only_inherited_console_then_closes_console_authority(self):
        console = types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(5, 1))
        null = types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3))
        with mock.patch.object(E.os, "fstat", side_effect=[console, null]), \
             mock.patch.object(E.os, "open", return_value=7) as opened, \
             mock.patch.object(E.os, "write", return_value=len(E.READY)) as write, \
             mock.patch.object(E.os, "dup2") as duplicate, mock.patch.object(E.os, "close") as close:
            E.announce_ready()
            opened.assert_called_once_with("/dev/null", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            write.assert_called_once_with(1, E.READY)
            self.assertEqual(duplicate.call_args_list, [mock.call(7, 0), mock.call(7, 1), mock.call(7, 2)])
            close.assert_called_once_with(7)
        value = json.loads(E.READY.split(b" ", 1)[1])
        self.assertIs(value["privileges_dropped"], True)
        for key in ("hardware_attestation", "private_inputs", "model_execution", "worker_execution"):
            self.assertIs(value[key], False)

    def test_failed_manifest_guard_cannot_emit_ready_or_exec(self):
        with mock.patch.object(E, "read_regular", side_effect=[json.dumps(launch()).encode(), b"wrong"]), \
             mock.patch.object(E.sys, "argv", [E.SELF, "--unprivileged"]), mock.patch.object(E, "unprivileged"), \
             mock.patch.object(E, "announce_ready") as ready, mock.patch.object(E.os, "execve") as execute:
            with self.assertRaises(ValueError):
                E.main()
            ready.assert_not_called()
            execute.assert_not_called()

    def test_unprivileged_guard_rejects_ids_groups_caps_and_nnp(self):
        status = "".join(key + ":\t0000000000000000\n" for key in
                         ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")) + "NoNewPrivs:\t1\n"
        with mock.patch.object(E.os, "getuid", return_value=985) as uid, \
             mock.patch.object(E.os, "geteuid", return_value=985), \
             mock.patch.object(E.os, "getgid", return_value=985), \
             mock.patch.object(E.os, "getegid", return_value=985), \
             mock.patch.object(E.os, "getgroups", return_value=[]) as groups, \
             mock.patch.object(E, "attribute", return_value=status) as attribute:
            E.unprivileged()
            uid.return_value = 0
            with self.assertRaises(ValueError):
                E.unprivileged()
            uid.return_value = 985
            groups.return_value = [985]
            with self.assertRaises(ValueError):
                E.unprivileged()
            groups.return_value = []
            for invalid in (status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
                            status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                            status + "CapEff:\t0000000000000000\n", ""):
                attribute.return_value = invalid
                with self.assertRaises(ValueError):
                    E.unprivileged()


class Port(unittest.TestCase):
    def fixture(self, parent, count=1):
        sys_root, dev_root = parent / "sys", parent / "dev"
        (sys_root / "class/virtio-ports").mkdir(parents=True)
        dev_root.mkdir()
        for index in range(count):
            name = "vport0p" + str(index)
            target = sys_root / "devices/virtio0" / name
            target.mkdir(parents=True)
            (target / "name").write_text(E.PORT_NAME + "\n")
            (target / "dev").write_text("240:" + str(index) + "\n")
            (sys_root / "class/virtio-ports" / name).symlink_to(target)
            (dev_root / name).write_bytes(b"never opened as device")
        return sys_root, dev_root

    def metadata(self, path):
        if path.name.startswith("vport") and path.parent.name == "dev":
            return types.SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_uid=0, st_gid=0,
                                         st_rdev=os.makedev(240, int(path.name.rsplit("p", 1)[1])))
        return self.real_lstat(path)

    def setUp(self):
        self.real_lstat = Path.lstat

    def test_selects_only_exact_named_sysfs_device_without_glob_or_open(self):
        with tempfile.TemporaryDirectory() as directory:
            sys_root, dev_root = self.fixture(Path(directory))
            with mock.patch.object(Path, "lstat", new=lambda path: self.metadata(path)):
                self.assertEqual(E.select_port(sys_root, dev_root), dev_root / "vport0p0")

    def test_duplicate_missing_and_nonchar_ports_reject(self):
        for count in (0, 2):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                sys_root, dev_root = self.fixture(Path(directory), count)
                with mock.patch.object(Path, "lstat", new=lambda path: self.metadata(path)), self.assertRaises(ValueError):
                    E.select_port(sys_root, dev_root)
        with tempfile.TemporaryDirectory() as directory:
            sys_root, dev_root = self.fixture(Path(directory))
            with self.assertRaises(ValueError):
                E.select_port(sys_root, dev_root)

    def test_wrong_name_device_numbers_and_attribute_length_reject(self):
        for name, value in (("name", "private canary\n"), ("dev", "240:3\n"),
                            ("dev", "../../private"), ("name", "x" * 129)):
            with self.subTest(name=name, value=value[:12]), tempfile.TemporaryDirectory() as directory:
                sys_root, dev_root = self.fixture(Path(directory))
                (sys_root / "devices/virtio0/vport0p0" / name).write_text(value)
                with mock.patch.object(Path, "lstat", new=lambda path: self.metadata(path)), self.assertRaises(ValueError):
                    E.select_port(sys_root, dev_root)

    def test_sysfs_escape_and_entry_count_bound_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            sys_root, dev_root = self.fixture(parent)
            link = sys_root / "class/virtio-ports/vport0p0"
            link.unlink()
            link.symlink_to(parent)
            with self.assertRaises(ValueError):
                E.select_port(sys_root, dev_root)
        with tempfile.TemporaryDirectory() as directory:
            sys_root, dev_root = self.fixture(Path(directory), 17)
            with mock.patch.object(Path, "lstat", new=lambda path: self.metadata(path)), self.assertRaises(ValueError):
                E.select_port(sys_root, dev_root)

    def test_alias_is_root_traversable_and_worker_owns_only_selected_device(self):
        node = Path("/dev/vport0p0")
        with mock.patch.object(E, "select_port", return_value=node), \
             mock.patch.object(Path, "mkdir") as mkdir, mock.patch.object(Path, "chmod") as directory_mode, \
             mock.patch.object(Path, "symlink_to") as link, \
             mock.patch.object(E.os, "chown") as owner, mock.patch.object(E.os, "chmod") as mode:
            E.bind_port()
            mkdir.assert_called_once_with(mode=0o755)
            directory_mode.assert_called_once_with(0o755)
            link.assert_called_once_with(node)
            owner.assert_called_once_with(node, 985, 985, follow_symlinks=False)
            mode.assert_called_once_with(node, 0o600, follow_symlinks=False)


class ShellContracts(unittest.TestCase):
    def shell(self, body):
        receipt = "receipt() {\n" + INIT.split("receipt() {\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        receipt = receipt.replace(">/dev/console", "")
        return subprocess.run(["/bin/sh", "-c", "set -efu\n" + receipt + body],
                              capture_output=True, text=True, timeout=5, check=False)

    def test_receipt_never_infers_model_or_worker_cleanup_from_process_zero(self):
        result = self.shell("stage=complete; verified=true; invoked=true; zero=true; receipt guest_process_returned\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout.split(" ", 1)[1])
        self.assertTrue(value["process_exit_zero"])
        for key in ("worker_cleanup_confirmed", "hardware_attestation", "private_inputs", "model_execution",
                    "worker_execution", "guest_key_origin_proven"):
            self.assertIs(value[key], False)
        result = self.shell("stage=verity_read; verified=false; invoked=false; zero=false; receipt integrity_failure\n")
        self.assertIn('"outcome":"integrity_failure"', result.stdout)

    def test_actual_verity_argv_has_no_unsupported_flag_or_alternate_device(self):
        block = INIT.split("stage=verity_open\n", 1)[1].split("/usr/sbin/dmsetup mknodes vp-root\n", 1)[0]
        block = block.replace("/usr/sbin/veritysetup", "capture").replace(">/dev/null 2>&1", "")
        script = "set -efu\ncapture() { printf '%s\\n' \"$@\"; }\nDATA_BLOCKS=8388608\nSALT=" + "0" * 64
        script += "\nROOT_HASH=" + "a" * 64 + "\n" + block
        result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["open", "--no-superblock", "--format=1", "--hash=sha256",
            "--data-block-size=4096", "--hash-block-size=4096", "--data-blocks=8388608", "--salt=" + "0" * 64,
            "/dev/vda", "vp-root", "/dev/vdb", "a" * 64])

    def test_full_root_is_verified_before_only_narrow_volatile_bind_and_launch(self):
        self.assertLess(INIT.index("stage=verity_read"), INIT.index("stage=root_mount"))
        self.assertLess(INIT.index("stage=write_probe"), INIT.index("stage=mounts"))
        self.assertLess(INIT.index("stage=lease"), INIT.index("stage=entrypoint"))
        self.assertIn("mount --bind /run/volparossa-resident/lease \"$lease\"", INIT)
        self.assertIn("remount,bind,rw,nosuid,nodev,noexec \"$lease\"", INIT)
        self.assertNotIn("--bind /run /newroot/opt", INIT)
        self.assertIn("[ \"$(/usr/bin/busybox ls /sys/class/net)\" = lo ]", INIT)
        self.assertIn("chroot /newroot /usr/bin/python3.13 -I", INIT)
        self.assertNotIn("eval ", INIT)
        # bwrap v0.11.0 writes user maps via its original proc_fd before --proc:
        # https://github.com/containers/bubblewrap/blob/v0.11.0/bubblewrap.c
        self.assertIn("mount -t proc -o rw,nosuid,nodev,noexec proc /newroot/proc", INIT)
        self.assertIn("mount -t ext4 -o ro,noload", INIT)

    def test_shell_parses_without_executing_mounts_or_guest(self):
        result = subprocess.run(["/bin/sh", "-n", str(M.SOURCE / "init")], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)

    def test_real_cgroup_mount_is_readonly_and_its_submount_reaches_worker(self):
        calls = [line for line in INIT.splitlines() if line.startswith("/usr/bin/busybox mount ")
                 and "cgroup" in line]
        script = "set -efu\ncapture() { printf '%s\\n' \"$*\"; }\n" + "\n".join(
            line.replace("/usr/bin/busybox mount", "capture") for line in calls)
        result = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "-t cgroup2 -o ro,nosuid,nodev,noexec cgroup2 /sys/fs/cgroup",
            "--bind /sys/fs/cgroup /newroot/sys/fs/cgroup",
            "-o remount,bind,ro,nosuid,nodev,noexec /newroot/sys/fs/cgroup"])
        self.assertIn("grep -w memory /sys/fs/cgroup/cgroup.controllers", INIT)
        self.assertNotIn("memory.max", INIT)  # No pretend controller or silently new resource limit.
        self.assertLess(INIT.index("stage=cgroup"), INIT.index("stage=entrypoint"))

    def test_actual_launch_branch_preserves_process_failure_without_fake_cleanup(self):
        block = INIT.split("invoked=true\n", 1)[1]
        block = block.replace("/usr/bin/busybox chroot", "capture")
        block = block.replace(">/dev/console", ">/dev/null")
        for code in (0, 1, 137):
            script = ("capture() { [ \"$*\" = '/newroot /usr/bin/python3.13 -I "
                      "/usr/lib/volparossa/protected-resident-model-entrypoint' ] || exit 99; return "
                      + str(code) + "; }\nstage=entrypoint; verified=true; invoked=true; zero=false\n" + block)
            result = self.shell(script)
            self.assertEqual(result.returncode, 0 if code == 0 else 1, result.stderr)
            value = json.loads(result.stdout.split(" ", 1)[1])
            self.assertEqual(value["outcome"], "guest_process_returned" if code == 0 else "guest_process_failed")
            self.assertIs(value["process_exit_zero"], code == 0)
            self.assertIs(value["worker_cleanup_confirmed"], False)
            self.assertIs(value["model_execution"], False)


if __name__ == "__main__":
    unittest.main()
