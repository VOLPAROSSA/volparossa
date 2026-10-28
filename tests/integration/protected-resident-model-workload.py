#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stage already-built PUBLIC fixture assets; never download, execute or seal.

The caller supplies an independently selected inventory digest and source SHA.
They bind this public fixture, not production approval, a successful source
build, installed-wheel provenance, OS dependency closure or hardware appraisal.
The existing provisioner/converter must have validated the supplied runtime.
This helper additionally verifies complete model bytes and native manifests.
The resulting tar is consumed by a separate model-image builder, not the old
immutable-boot fixture. No model/worker execution is claimed by staging.
"""
import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import time
import types

ROOT = Path(__file__).resolve().parents[2]
WORKERS = ROOT / "workers/volparossa-ml"
MAX_INVENTORY = 16 * 1024 ** 2
MAX_ENTRIES = 65536
MAX_TOTAL = 32 * 1024 ** 3  # New staging artifact only; old boot limits unchanged.
MAX_FILE = 9 * 1024 ** 3
MAX_DOCUMENT = 65536
UID = GID = 985
SHA = re.compile(r"[0-9a-f]{64}\Z")
SOURCE = re.compile(r"[0-9a-f]{40}\Z")
# Literal parentheses occur in pinned public wheel members. Paths remain data:
# no-follow filesystem operands, JSON-quoted guestfish operands and tar names.
PATH = re.compile(r"[A-Za-z0-9_+.,@= ()-]+(?:/[A-Za-z0-9_+.,@= ()-]+)*\Z")
WRAPPERS = ("CMakeLists.txt", "adapter.h", "adapter.cpp", "bounded-tensor-validation.patch",
            "output-constraint.h", "output-constraint.cpp", "session-state.h", "q1-aligned-load.patch")
FLAT = {"volparossa", "public-policy.json", "server.der", "server-key.der"}
NATIVE = {"backend.json", "build.json", "model.gguf", "libvolparossa_llama_cpu.so"}
LAUNCH_PATH = "usr/lib/volparossa/protected-resident-model-launch.json"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def budget(deadline):
    require(type(deadline) in (int, float) and math.isfinite(deadline)
            and time.monotonic() < deadline, "stage_deadline")


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: require(False, "nonfinite_json"))


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def module(name):
    # Only repository-owned stdlib-only validation modules; no asset imports,
    # native library loading, package execution or source-tree __pycache__.
    path = WORKERS / (name + ".py")
    value = types.ModuleType("resident_" + name)
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), value.__dict__)
    return value


def path_rejection(name):
    """Return a closed rule only, never the pathname or a pathname fingerprint."""
    if type(name) is not str:
        return "inventory_path_type"
    if not name:
        return "inventory_path_empty"
    if len(name) > 240:
        return "inventory_path_length"
    if not PATH.fullmatch(name):
        return "inventory_path_character_or_separator"
    if any(part in (".", "..") for part in name.split("/")):
        return "inventory_path_dot_component"
    return None


def path_ok(name):
    return path_rejection(name) is None


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def regular(meta):
    require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
            and not meta.st_mode & 0o022, "asset_file_metadata")


def open_entry(root_fd, name):
    require(path_ok(name), "asset_path")
    parent = os.dup(root_fd)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def read_entry(root_fd, name, item, maximum, deadline):
    budget(deadline)
    fd = open_entry(root_fd, name)
    try:
        before = os.fstat(fd)
        regular(before)
        require(before.st_size == item["bytes"] <= maximum, "asset_file_bound")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(maximum + 1)
        budget(deadline)
        require(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
                and identity(before) == identity(os.fstat(fd)), "asset_digest")
        return raw
    finally:
        os.close(fd)


def read_inventory(path, deadline):
    budget(deadline)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        regular(before)
        require(before.st_size <= MAX_INVENTORY, "inventory_bound")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_INVENTORY + 1)
        budget(deadline)
        require(identity(before) == identity(os.fstat(fd)), "inventory_changed")
        return raw
    finally:
        os.close(fd)


def inventory(raw, expected_digest, expected_source):
    require(type(expected_digest) is str and SHA.fullmatch(expected_digest)
            and hashlib.sha256(raw).hexdigest() == expected_digest, "inventory_digest")
    require(type(expected_source) is str and SOURCE.fullmatch(expected_source), "core_source")
    require(len(raw) <= MAX_INVENTORY, "inventory_bound")
    value = parse(raw)
    require(type(value) is dict and value.keys() == {"version", "kind", "public_fixture_only",
            "core_source_commit", "entries"} and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "protected-resident-public-workload" and value["public_fixture_only"] is True
            and value["core_source_commit"] == expected_source, "inventory_scope")
    entries = value["entries"]
    require(type(entries) is dict and 0 < len(entries) <= MAX_ENTRIES, "inventory_entries")
    total = 0
    for name, item in entries.items():
        require(path_ok(name) and type(item) is dict, "inventory_entry")
        require(name in FLAT or name.startswith(("runtime/", "model/", "native-backend/")), "asset_scope")
        require(name != "runtime/.volparossa-compute.lock", "lease_is_generated")
        if item.get("kind") == "symlink":
            require(item.keys() == {"kind", "target"} and name.startswith("runtime/")
                    and type(item["target"]) is str and 0 < len(item["target"]) <= 240, "symlink_scope")
        else:
            require(item.keys() == {"kind", "bytes", "sha256", "executable"} and item["kind"] == "file"
                    and type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_FILE
                    and type(item["sha256"]) is str and SHA.fullmatch(item["sha256"])
                    and type(item["executable"]) is bool, "file_inventory")
            require(not item["executable"] or name == "volparossa" or name.startswith("runtime/"),
                    "executable_scope")
            total += item["bytes"]
        require(not any(parent.as_posix() in entries for parent in PurePosixPath(name).parents
                        if parent.as_posix() != "."), "inventory_parent_file")
    require(total <= MAX_TOTAL and FLAT <= entries.keys(), "inventory_total")
    require(entries["volparossa"].get("executable") is True, "core_executable")
    for name, item in entries.items():
        if item["kind"] == "symlink":
            resolve_link(name, entries)
    return value


def resolve_link(name, entries):
    seen = set()
    while entries[name]["kind"] == "symlink":
        require(name not in seen and len(seen) < 16, "symlink_loop")
        seen.add(name)
        target = entries[name]["target"]
        if target.startswith("/"):
            require(target == "/usr/bin/python3.13" and name.startswith("runtime/bin/python"),
                    "symlink_external")
            return target
        parts = name.split("/")[:-1]
        for part in target.split("/"):
            if part == "..":
                require(len(parts) > 1, "symlink_escape")
                parts.pop()
            elif part != ".":
                require(part and path_ok(part), "symlink_target")
                parts.append(part)
        name = "/".join(parts)
        # A venv lib64 -> lib is the single supported directory alias.
        if name == "runtime/lib" and any(key.startswith(name + "/") for key in entries):
            return name
        require(name.startswith("runtime/") and name in entries, "symlink_missing")
    return name


def scan(root, deadline):
    result, pending, count = set(), [root], 0
    while pending:
        with os.scandir(pending.pop()) as children:
            for entry in children:
                budget(deadline)
                count += 1
                require(count <= 2 * MAX_ENTRIES, "inventory_entries")
                meta = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(meta.st_mode):
                    require(not meta.st_mode & 0o022, "asset_directory_metadata")
                    pending.append(Path(entry.path))
                else:
                    result.add(Path(entry.path).relative_to(root).as_posix())
                    require(len(result) <= MAX_ENTRIES, "inventory_entries")
    return result


def workload_descriptor(value):
    """Public content identity, deliberately excluding policy/TLS key material.

    A caller can compute this before creating the policy; no hash cycle and no
    automatic authority from a self-created descriptor.
    """
    profile = (ROOT / "packaging/protected-resident-model/profile-v1.json").read_bytes()
    return dict(version=1, kind="protected-resident-public-workload-identity",
                core_source_commit=value["core_source_commit"], profile_sha256=hashlib.sha256(profile).hexdigest(),
                entries={name: item for name, item in value["entries"].items()
                         if name not in ("public-policy.json", "server.der", "server-key.der")})


def workload_sha256(value):
    return hashlib.sha256(encoded(workload_descriptor(value))).hexdigest()


def elf_header(root_fd, name, item, maximum, deadline):
    # Only structural identity, not ABI/loadability or complete dependency proof.
    budget(deadline)
    fd = open_entry(root_fd, name)
    try:
        before = os.fstat(fd)
        regular(before)
        require(64 <= before.st_size == item["bytes"] <= maximum, "elf_bound")
        raw = os.read(fd, 64)
        require(len(raw) == 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
                and struct.unpack_from("<H", raw, 16)[0] in (2, 3)
                and struct.unpack_from("<H", raw, 18)[0] == 62
                and identity(before) == identity(os.fstat(fd)), "elf_identity")
    finally:
        os.close(fd)


def verified_metadata(root_fd, value, deadline):
    entries = value["entries"]
    native, provision = module("llama_cpu"), module("provision")
    pins = provision.load_pins(model_profile=native.PROFILE, native_cpu_converter=True)
    model = {"model/" + item["path"]: item for item in pins["files"]}
    require({name for name in entries if name.startswith("model/")} == model.keys(), "model_inventory")
    for name, item in model.items():
        require(entries[name] == dict(kind="file", bytes=item["bytes"], sha256=item["sha256"], executable=False),
                "model_pin")
    names = {name.removeprefix("native-backend/") for name in entries if name.startswith("native-backend/")}
    require(NATIVE <= names and all(name in NATIVE or name.startswith("licenses/") for name in names)
            and any(name.startswith("licenses/") for name in names), "native_inventory")
    backend_raw = read_entry(root_fd, "native-backend/backend.json", entries["native-backend/backend.json"],
                             16384, deadline)
    backend = parse(backend_raw)
    native.validate_manifest(backend, require)
    require(backend["version"] == 3, "native_session_required")
    build_raw = read_entry(root_fd, "native-backend/build.json", entries["native-backend/build.json"],
                           MAX_DOCUMENT, deadline)
    require(hashlib.sha256(build_raw).hexdigest() == backend["build_manifest_sha256"], "native_build_digest")
    build = parse(build_raw)
    native.validate_build_provenance(build, require)
    require(build.get("version") == 4 and build.get("kind") == native.KIND and build.get("abi_version") == 1
            and build.get("cpu") == "avx2_fma_f16c" and build.get("provisionable") is True
            and build.get("sanitizers") is False and build.get("quantization") is False
            and build.get("models_loaded") is False and build.get("downloads") is False
            and build.get("install") is False and type(build.get("jobs")) is int and build["jobs"] == 2
            and build.get("cpu_compile_source_verified") is True and build.get("library") == backend["library"],
            "native_build_binding")
    needed = build.get("dynamic_dependencies")
    require(type(needed) is list and needed and all(type(item) is str for item in needed)
            and len(set(needed)) == len(needed) and set(needed) <= {
                "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "ld-linux-x86-64.so.2"},
            "native_dependency_binding")
    expected = {}
    for name in WRAPPERS:
        raw = (WORKERS / "native-cpu" / name).read_bytes()
        expected[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    require(build.get("wrapper_sources") == expected, "native_wrapper_binding")
    for key in ("library", "gguf"):
        item = backend[key]
        require(entries["native-backend/" + item["path"]] == dict(kind="file", bytes=item["bytes"],
                sha256=item["sha256"], executable=False), "native_artifact_binding")
    require("runtime/pyvenv.cfg" in entries and "runtime/bin/python3" in entries
            and resolve_link("runtime/bin/python3", entries) == "/usr/bin/python3.13", "runtime_python")
    cfg = read_entry(root_fd, "runtime/pyvenv.cfg", entries["runtime/pyvenv.cfg"], 4096, deadline).decode()
    values = dict(line.split(" = ", 1) for line in cfg.splitlines() if " = " in line)
    require(values.get("home") == "/usr/bin" and values.get("include-system-site-packages") == "false"
            and values.get("version", "").startswith("3.13."), "runtime_config")
    elf_header(root_fd, "volparossa", entries["volparossa"], 256 * 1024 ** 2, deadline)
    elf_header(root_fd, "native-backend/" + native.LIBRARY, entries["native-backend/" + native.LIBRARY],
               128 * 1024 ** 2, deadline)
    policy = parse(read_entry(root_fd, "public-policy.json", entries["public-policy.json"], 4096, deadline))
    require(type(policy) is dict and policy.keys() == {"version", "visibility", "requester_key",
            "workload_sha256", "public_input_sha256"} and type(policy["version"]) is int and policy["version"] == 1
            and policy["visibility"] == "public_fixture" and type(policy["requester_key"]) is str
            and SHA.fullmatch(policy["requester_key"]) and policy["workload_sha256"] == workload_sha256(value)
            and type(policy["public_input_sha256"]) is list and len(policy["public_input_sha256"]) == 2
            and all(type(item) is str and SHA.fullmatch(item) for item in policy["public_input_sha256"]),
            "public_policy_binding")
    for name in ("server.der", "server-key.der"):
        require(0 < entries[name].get("bytes", 0) <= 8192 and entries[name]["kind"] == "file", "fixture_tls_bound")
    return hashlib.sha256(backend_raw).hexdigest()


def launch_contract(native_digest):
    require(type(native_digest) is str and SHA.fullmatch(native_digest), "native_manifest_digest")
    profile = parse((ROOT / "packaging/protected-resident-model/profile-v1.json").read_bytes())
    return dict(profile=profile, native_backend_sha256=native_digest, argv=[
        "/usr/bin/volparossa", "compute", "resident-guest",
        "--runtime-root", "/opt/volparossa/runtime", "--model-root", "/opt/volparossa/model",
        "--work-parent", "/run/volparossa-resident/work", "--native-backend-root", "/opt/volparossa/native-backend",
        "--native-backend-sha256", native_digest, "--public-policy", "/etc/volparossa-resident/public-policy.json",
        "--certificate", "/etc/volparossa-resident/server.der", "--private-key",
        "/etc/volparossa-resident/server-key.der", "--execute"])


def guest_path(name):
    if name == "volparossa":
        return "usr/bin/volparossa"
    if name in FLAT:
        return "etc/volparossa-resident/" + name
    return "opt/volparossa/" + name


def info(name, mode, owner, *, size=0, kind=tarfile.REGTYPE, link=""):
    value = tarfile.TarInfo(name)
    value.mode, value.uid, value.gid, value.size = mode, owner, owner, size
    value.type, value.linkname, value.mtime = kind, link, 0
    return value


class CheckedReader:
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline
        self.digest = hashlib.sha256()

    def read(self, size):
        budget(self.deadline)
        raw = self.stream.read(size)
        self.digest.update(raw)
        return raw


def stage_workload(asset_root, inventory_path, expected_inventory_sha256, output_tar, expected_source, deadline):
    """Create one exclusive tar from complete, caller-bound existing assets.

    Never chown/mount/execute the host assets. Archive ownership is guest-only.
    A failure removes only the newly-created output; existing outputs are refused.
    """
    budget(deadline)
    root, output = Path(asset_root), Path(output_tar)
    require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(), "asset_root")
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
            and not output.is_relative_to(root), "output_path")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = None
    try:
        raw = read_inventory(inventory_path, deadline)
        value = inventory(raw, expected_inventory_sha256, expected_source)
        entries = value["entries"]
        require(scan(root, deadline) == entries.keys(), "asset_inventory_exact")
        native_digest = verified_metadata(root_fd, value, deadline)
        launch = encoded(launch_contract(native_digest))
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created_meta = os.fstat(fd)
        created = (created_meta.st_dev, created_meta.st_ino)
        with os.fdopen(fd, "wb") as sink, tarfile.open(fileobj=sink, mode="w", format=tarfile.PAX_FORMAT) as archive:
            paths = [guest_path(name) for name in entries] + [LAUNCH_PATH,
                    "opt/volparossa/runtime/.volparossa-compute.lock"]
            dirs = {parent.as_posix() for name in paths for parent in PurePosixPath(name).parents
                    if parent.as_posix() != "."}
            for name in sorted(dirs, key=lambda path: (path.count("/"), path)):
                owned = name.startswith("opt/volparossa/") or name == "etc/volparossa-resident"
                archive.addfile(info(name, 0o700 if owned else 0o755, UID if owned else 0, kind=tarfile.DIRTYPE))
            for name, item in sorted(entries.items()):
                budget(deadline)
                destination = guest_path(name)
                if item["kind"] == "symlink":
                    require(os.readlink(root / name) == item["target"], "symlink_changed")
                    archive.addfile(info(destination, 0o777, UID, kind=tarfile.SYMTYPE, link=item["target"]))
                    continue
                fd = open_entry(root_fd, name)
                with os.fdopen(fd, "rb") as source:
                    before = os.fstat(source.fileno())
                    regular(before)
                    require(before.st_size == item["bytes"], "asset_file_bound")
                    reader = CheckedReader(source, deadline)
                    mode = 0o555 if name == "volparossa" else 0o700 if item["executable"] else 0o600
                    archive.addfile(info(destination, mode, 0 if name == "volparossa" else UID,
                                         size=item["bytes"]), reader)
                    require(reader.digest.hexdigest() == item["sha256"]
                            and identity(before) == identity(os.fstat(source.fileno())), "asset_digest")
            archive.addfile(info("opt/volparossa/runtime/.volparossa-compute.lock", 0o600, UID))
            archive.addfile(info(LAUNCH_PATH, 0o444, 0, size=len(launch)), io.BytesIO(launch))
        budget(deadline)
        return dict(version=1, kind="protected-resident-public-workload-staging", staged=True,
                    core_source_commit=expected_source, inventory_sha256=expected_inventory_sha256,
                    workload_sha256=workload_sha256(value),
                    native_backend_sha256=native_digest, files=len(entries),
                    asset_bytes=sum(item.get("bytes", 0) for item in entries.values()),
                    launch_sha256=hashlib.sha256(launch).hexdigest(), public_fixture_only=True,
                    model_execution=False, worker_execution=False, hardware_attestation=False,
                    private_inputs=False, production_approval=False, guest_key_origin_proven=False)
    except BaseException:
        if created is not None:
            try:
                current = output.lstat()
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == created:
                    output.unlink()
            except OSError:
                # Missing/replaced/uninspectable output is not ours to remove;
                # cleanup must not replace the original staging exception.
                pass
        raise
    finally:
        os.close(root_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    # The caller's original absolute monotonic deadline, never a fresh budget.
    parser.add_argument("--deadline-monotonic", type=float, required=True)
    args = parser.parse_args()
    try:
        receipt = stage_workload(args.assets, args.inventory, args.inventory_sha256, args.output,
                                 args.expected_source, args.deadline_monotonic)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        print('{"version":1,"kind":"protected-resident-public-workload-staging","staged":false}')
        return 1
    print(encoded(receipt).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
