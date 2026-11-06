#!/usr/bin/env python3
"""Build a controlled public boot initrd from an already authenticated Debian tree.

No extracted executable is run. The caller owns image/package authentication;
this manifest records inputs, not attestation or private-input authorization.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct


CMDLINE = "console=ttyS0 panic=-1 oops=panic quiet rdinit=/init vp.profile=public-boot-v1"
SALT = "0" * 64
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILES = 2048
MAX_DATA_BLOCKS = 4 * 1024 * 1024
BINARIES = ("/usr/bin/busybox", "/usr/sbin/modprobe", "/usr/sbin/veritysetup",
            "/usr/sbin/dmsetup", "/usr/sbin/blockdev")
MODULES = ("virtio_pci", "virtio_blk", "dm_mod", "dm_verity", "ext4", "sha256_generic")
LIB_DIRS = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64")
HERE = Path(__file__).resolve().parents[2]


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def virtual_parts(name: str) -> list[str]:
    require(name.startswith("/") and "\x00" not in name, "initrd_path")
    result: list[str] = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            require(bool(result), "initrd_path_escape")
            result.pop()
        else:
            result.append(part)
    return result


def rooted(root: Path, name: str) -> Path:
    """Resolve image-absolute symlinks inside the image, never against the host."""
    pending = virtual_parts(name)
    done: list[str] = []
    links = 0
    while pending:
        part = pending.pop(0)
        candidate = root.joinpath(*done, part)
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            links += 1
            require(links <= 32, "initrd_symlink_loop")
            target = os.readlink(candidate)
            prefix = "" if target.startswith("/") else "/" + "/".join(done) + "/"
            pending = virtual_parts(prefix + target) + pending
            done = []
        else:
            if pending:
                require(stat.S_ISDIR(metadata.st_mode), "initrd_parent")
            done.append(part)
    return root.joinpath(*done)


def read_source(root: Path, name: str) -> bytes:
    path = rooted(root, name)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, "initrd_file")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    require(len(data) == info.st_size <= MAX_FILE, "initrd_file_changed")
    return data


def elf_dependencies(data: bytes) -> tuple[str | None, list[str]]:
    """Bounded ELF64 little-endian amd64 PT_INTERP/DT_NEEDED reader, no ldd."""
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "initrd_elf")
    require(struct.unpack_from("<H", data, 18)[0] == 62, "initrd_elf_machine")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56 and 1 <= count <= 128 and offset + count * size <= len(data),
            "initrd_elf_headers")
    loads, dynamic, interpreter = [], None, None
    for number in range(count):
        kind, _, start, address, _, length, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + number * size)
        require(start + length <= len(data), "initrd_elf_segment")
        if kind == 1:
            loads.append((address, start, length))
        elif kind == 2:
            require(dynamic is None and length <= 1024 * 1024 and length % 16 == 0,
                    "initrd_elf_dynamic")
            dynamic = data[start:start + length]
        elif kind == 3:
            require(interpreter is None and 2 <= length <= 256, "initrd_elf_interpreter")
            raw = data[start:start + length]
            require(raw[-1:] == b"\0" and b"\0" not in raw[:-1], "initrd_elf_interpreter")
            interpreter = raw[:-1].decode("ascii")
            require(interpreter == "/lib64/ld-linux-x86-64.so.2", "initrd_elf_interpreter")
    if dynamic is None:
        return interpreter, []
    entries = []
    for index in range(0, len(dynamic), 16):
        tag, value = struct.unpack_from("<qQ", dynamic, index)
        if tag == 0:
            break
        require(tag not in (15, 29), "initrd_elf_search_path")
        entries.append((tag, value))
    else:
        raise ValueError("initrd_elf_dynamic_end")
    needed = [value for tag, value in entries if tag == 1]
    if not needed:
        return interpreter, []
    strings = [value for tag, value in entries if tag == 5]
    lengths = [value for tag, value in entries if tag == 10]
    require(len(strings) == len(lengths) == 1 and 1 <= lengths[0] <= 1024 * 1024,
            "initrd_elf_strings")
    tables = [start + strings[0] - address for address, start, length in loads
              if address <= strings[0] and strings[0] + lengths[0] <= address + length]
    require(len(tables) == 1, "initrd_elf_strings")
    table = data[tables[0]:tables[0] + lengths[0]]
    names = []
    for index in needed:
        require(index < len(table), "initrd_elf_needed")
        end = table.find(b"\0", index)
        require(end != -1 and end - index <= 128, "initrd_elf_needed")
        name = table[index:end].decode("ascii")
        require(re.fullmatch(r"[A-Za-z0-9_.+-]+", name) is not None, "initrd_elf_needed")
        names.append(name)
    require(len(names) <= 64, "initrd_elf_needed")
    return interpreter, names


class Closure:
    def __init__(self, root: Path):
        require(root.is_dir() and not root.is_symlink(), "initrd_root")
        self.root = root
        self.files: dict[str, tuple[bytes, int]] = {}
        self.total = 0

    def add(self, name: str, data: bytes, mode: int) -> None:
        require(name == "/" + "/".join(virtual_parts(name)), "initrd_archive_path")
        previous = self.files.get(name)
        if previous is not None:
            require(previous == (data, mode), "initrd_duplicate")
            return
        require(len(self.files) < MAX_FILES and self.total + len(data) <= MAX_TOTAL,
                "initrd_closure_bound")
        self.files[name] = data, mode
        self.total += len(data)

    def executable(self, name: str) -> None:
        if name in self.files:
            return
        data = read_source(self.root, name)
        interpreter, dependencies = elf_dependencies(data)
        self.add(name, data, 0o755)
        if interpreter is not None:
            self.executable(interpreter)
        for library in dependencies:
            for directory in LIB_DIRS:
                candidate = directory + "/" + library
                try:
                    rooted(self.root, candidate)
                except FileNotFoundError:
                    continue
                self.executable(candidate)
                break
            else:
                raise ValueError("initrd_library_missing")

    def modules(self, version: str, required: tuple[str, ...] = MODULES) -> None:
        base = "/lib/modules/" + version
        dependencies = read_source(self.root, base + "/modules.dep").decode("ascii")
        builtin = read_source(self.root, base + "/modules.builtin").decode("ascii")
        mapping = {}

        def module_path(path: str) -> str:
            require(re.fullmatch(r"[A-Za-z0-9_+./-]+\.ko(?:\.(?:xz|zst|gz))?", path)
                    is not None and not path.startswith("/") and ".." not in path.split("/"),
                    "initrd_module_path")
            return path

        for line in dependencies.splitlines():
            name, separator, values = line.partition(":")
            require(separator == ":" and name not in mapping, "initrd_module_dependencies")
            mapping[module_path(name)] = [module_path(item) for item in values.split()]
        builtins = {module_path(item) for item in builtin.splitlines()}
        selected = set()

        def collect(name: str) -> None:
            if name in selected:
                return
            require(name in mapping and len(selected) < 128, "initrd_module_missing")
            selected.add(name)
            for child in mapping[name]:
                collect(child)

        for module in required:
            candidates = [name for name in mapping.keys() | builtins
                          if PurePosixPath(name).name.split(".ko", 1)[0].replace("-", "_") == module]
            require(len(candidates) == 1, "initrd_module_missing")
            if candidates[0] not in builtins:
                collect(candidates[0])
        for name in sorted(selected):
            self.add(base + "/" + name, read_source(self.root, base + "/" + name), 0o644)
        # libkmod uses the original indexes, but only the fixed module closure exists.
        for name in ("modules.dep", "modules.dep.bin", "modules.alias", "modules.alias.bin",
                     "modules.builtin", "modules.builtin.bin", "modules.builtin.modinfo",
                     "modules.softdep", "modules.symbols", "modules.symbols.bin"):
            self.add(base + "/" + name, read_source(self.root, base + "/" + name), 0o644)


def archive(files: dict[str, tuple[bytes, int]]) -> bytes:
    """Deterministic newc archive; no host device-node or ownership mutations."""
    entries: dict[str, tuple[bytes, int, int, int]] = {}
    for path in ("/dev", "/proc", "/sys", "/run", "/newroot"):
        entries[path] = b"", stat.S_IFDIR | 0o755, 0, 0
    for path, (data, mode) in files.items():
        require(path not in entries, "initrd_archive_duplicate")
        entries[path] = data, stat.S_IFREG | mode, 0, 0
        for parent in PurePosixPath(path).parents:
            if str(parent) != "/":
                previous = entries.setdefault(str(parent), (b"", stat.S_IFDIR | 0o755, 0, 0))
                require(stat.S_ISDIR(previous[1]), "initrd_archive_parent")
    entries["/bin/sh"] = b"/usr/bin/busybox", stat.S_IFLNK | 0o777, 0, 0
    entries.setdefault("/bin", (b"", stat.S_IFDIR | 0o755, 0, 0))
    entries["/dev/console"] = b"", stat.S_IFCHR | 0o600, 5, 1
    entries["/dev/null"] = b"", stat.S_IFCHR | 0o666, 1, 3
    output = io.BytesIO()
    for inode, (name, (data, mode, major, minor)) in enumerate(sorted(entries.items()), 1):
        append_cpio(output, inode, name.lstrip("/"), data, mode, major, minor)
    append_cpio(output, len(entries) + 1, "TRAILER!!!", b"", 0, 0, 0)
    return gzip.compress(output.getvalue(), compresslevel=9, mtime=0)


def append_cpio(output: io.BytesIO, inode: int, name: str, data: bytes,
                mode: int, major: int, minor: int) -> None:
    encoded = name.encode("utf-8") + b"\0"
    values = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0)
    output.write(b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in values))
    output.write(encoded)
    output.write(b"\0" * (-output.tell() % 4))
    output.write(data)
    output.write(b"\0" * (-output.tell() % 4))


def build(root: Path, original_initrd: Path, version: str, root_hash: str,
          data_blocks: int, output: Path) -> dict:
    require(re.fullmatch(r"[A-Za-z0-9.+_-]{1,96}", version) is not None, "initrd_kernel_version")
    require(re.fullmatch(r"[0-9a-f]{64}", root_hash) is not None, "initrd_root_hash")
    require(type(data_blocks) is int and 1 <= data_blocks <= MAX_DATA_BLOCKS, "initrd_data_blocks")
    require(original_initrd.is_file() and not original_initrd.is_symlink()
            and 1 <= original_initrd.stat().st_size <= MAX_TOTAL, "initrd_original")
    original_digest = hashlib.sha256()
    original_bytes = 0
    with original_initrd.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            original_bytes += len(chunk)
            require(original_bytes <= MAX_TOTAL, "initrd_original_bound")
            original_digest.update(chunk)
    require(original_bytes == original_initrd.stat().st_size, "initrd_original_changed")
    closure = Closure(root)
    for binary in BINARIES:
        closure.executable(binary)
    closure.modules(version)
    template = (HERE / "packaging/protected-resident/init").read_text()
    for key, value in {"ROOT_HASH": root_hash, "DATA_BLOCKS": str(data_blocks),
                       "KERNEL_VERSION": version}.items():
        require(template.count("@" + key + "@") == 1, "initrd_template")
        template = template.replace("@" + key + "@", value)
    require("@" not in template, "initrd_template")
    closure.add("/init", template.encode(), 0o755)
    record = {"version": 1, "kernel_version": version, "root_hash": root_hash,
              "data_blocks": data_blocks, "salt": SALT, "cmdline": CMDLINE,
              "original_initrd_sha256": original_digest.hexdigest(),
              "hardware_attestation": False, "private_inputs": False,
              "model_execution": False, "worker_execution": False,
              "closure": {name: hashlib.sha256(data).hexdigest()
                          for name, (data, _) in sorted(closure.files.items())}}
    closure.add("/boot-inputs.json", (json.dumps(record, sort_keys=True) + "\n").encode(), 0o400)
    data = archive(closure.files)
    require(len(data) <= MAX_TOTAL, "initrd_output_bound")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return dict(record, initrd_sha256=hashlib.sha256(data).hexdigest(), initrd_bytes=len(data))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root_tree", type=Path)
    parser.add_argument("original_initrd", type=Path)
    parser.add_argument("kernel_version")
    parser.add_argument("root_hash")
    parser.add_argument("data_blocks", type=int)
    parser.add_argument("output_initrd", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.root_tree, args.original_initrd, args.kernel_version,
                           args.root_hash, args.data_blocks, args.output_initrd), sort_keys=True))


if __name__ == "__main__":
    main()
