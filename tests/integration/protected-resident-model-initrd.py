#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Separate PUBLIC model initrd, consuming a complete caller-staged sealed OS.

No download, compiler, image mount, device access or guest execution here.
stage_boot_files() adds fixed launch code to an owned root before sealing;
build() verifies that code and emits only the minimal initrd closure. These
structural checks do not prove OS dynamic-library/Python/runtime loadability.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / "packaging/protected-resident-model"
BASE = types.ModuleType("model_boot_base")
BASE.__file__ = str(HERE / "protected-resident-initrd.py")
exec(compile(Path(BASE.__file__).read_bytes(), BASE.__file__, "exec"), BASE.__dict__)
require = BASE.require
CMDLINE = "console=ttyS0 panic=-1 oops=panic quiet rdinit=/init vp.profile=public-resident-model-v1"
MAX_DATA_BLOCKS = 8 * 1024 * 1024  # 32 GiB; old public-boot-v1 remains 16 GiB.
MODULES = BASE.MODULES + ("virtio_console",)
ENTRY = "/usr/lib/volparossa/protected-resident-model-entrypoint"
CANARY = b"VOLPAROSSA public verity write probe\n"


def entrypoint():
    template = (SOURCE / "entrypoint").read_text()
    profile = json.loads((SOURCE / "profile-v1.json").read_bytes())
    require(template.count("@PROFILE_JSON@") == 1, "model_entry_template")
    template = template.replace("@PROFILE_JSON@", json.dumps(profile, sort_keys=True))
    require("@" not in template, "model_entry_template")
    compile(template, ENTRY, "exec")
    return template.encode()


def directory(root, relative):
    path = root
    for name in relative.split("/"):
        path = path / name
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o755)
            path.chmod(0o755)
        meta = path.lstat()
        require(stat.S_ISDIR(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o755, "model_boot_directory")
    return path


def stage_boot_files(root):
    """Write only to a caller-owned build tree; the image builder sets root UID.

    guestfish/image assembly must preserve root:root ownership for these files
    and directories. This function neither chowns the host nor verifies an OS.
    """
    require(root.is_dir() and not root.is_symlink(), "model_boot_root")
    directory(root, "usr/lib/volparossa")
    for name in ("proc", "sys", "dev", "run"):
        directory(root, name)
    for path, data, mode in ((ENTRY, entrypoint(), 0o555),
                             ("/usr/lib/volparossa/verity-write-probe", CANARY, 0o644)):
        target = root / path.lstrip("/")
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)


def validate_root(root):
    for path, mode in ((ENTRY, 0o555), ("/usr/lib/volparossa/verity-write-probe", 0o644)):
        meta = (root / path.lstrip("/")).lstat()
        require(stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == mode,
                "model_boot_metadata")
    require(BASE.read_source(root, ENTRY) == entrypoint(), "model_entry_identity")
    require(BASE.read_source(root, "/usr/lib/volparossa/verity-write-probe") == CANARY, "model_write_probe")
    # OS builder responsibility: complete Python stdlib and dynamic libraries,
    # unprivileged-userns-enabled kernel, and provenance for all staged assets.
    profile = json.loads((SOURCE / "profile-v1.json").read_bytes())
    for path in profile["required_guest_executables"] + ["/usr/bin/setpriv", "/usr/bin/volparossa"]:
        data = BASE.read_source(root, path)
        BASE.elf_dependencies(data)
    launch_raw = BASE.read_source(root, "/usr/lib/volparossa/protected-resident-model-launch.json")
    scope = {"__name__": "model_entry_validate"}
    exec(compile(entrypoint(), ENTRY, "exec"), scope)
    scope["decode_launch"](launch_raw)
    for name in ("proc", "sys", "dev", "run"):
        meta = (root / name).lstat()
        require(stat.S_ISDIR(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o755, "model_mountpoint")


def build(root, original_initrd, version, root_hash, data_blocks, output):
    require(type(version) is str and re.fullmatch(r"[A-Za-z0-9.+_-]{1,96}", version), "initrd_kernel_version")
    require(type(root_hash) is str and re.fullmatch(r"[0-9a-f]{64}", root_hash), "initrd_root_hash")
    require(type(data_blocks) is int and 1 <= data_blocks <= MAX_DATA_BLOCKS, "initrd_data_blocks")
    validate_root(root)
    meta = original_initrd.lstat()
    require(stat.S_ISREG(meta.st_mode) and 1 <= meta.st_size <= BASE.MAX_TOTAL, "initrd_original")
    digest, count = hashlib.sha256(), 0
    with original_initrd.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            require(count <= BASE.MAX_TOTAL, "initrd_original_bound")
            digest.update(chunk)
    require(count == meta.st_size == original_initrd.stat().st_size, "initrd_original_changed")
    closure = BASE.Closure(root)
    for binary in BASE.BINARIES:
        closure.executable(binary)
    closure.modules(version, MODULES)
    template = (SOURCE / "init").read_text()
    for key, value in {"ROOT_HASH": root_hash, "DATA_BLOCKS": str(data_blocks), "KERNEL_VERSION": version}.items():
        require(template.count("@" + key + "@") == 1, "initrd_template")
        template = template.replace("@" + key + "@", value)
    require("@" not in template, "initrd_template")
    closure.add("/init", template.encode(), 0o755)
    record = dict(version=1, kind="protected-resident-public-model-initrd", kernel_version=version,
                  root_hash=root_hash, data_blocks=data_blocks, salt=BASE.SALT, cmdline=CMDLINE,
                  original_initrd_sha256=digest.hexdigest(),
                  entrypoint_sha256=hashlib.sha256(entrypoint()).hexdigest(),
                  hardware_attestation=False, private_inputs=False, model_execution=False,
                  worker_execution=False, production_approval=False, guest_key_origin_proven=False,
                  closure={name: hashlib.sha256(data).hexdigest()
                           for name, (data, _) in sorted(closure.files.items())})
    closure.add("/boot-inputs.json", (json.dumps(record, sort_keys=True) + "\n").encode(), 0o400)
    data = BASE.archive(closure.files)
    require(len(data) <= BASE.MAX_TOTAL, "initrd_output_bound")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return dict(record, initrd_sha256=hashlib.sha256(data).hexdigest(), initrd_bytes=len(data))


def main():
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
