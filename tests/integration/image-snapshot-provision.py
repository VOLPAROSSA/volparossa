#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit exact-source Image/Node staging, exclusively in the disposable guest.

No application data, model, Immich server or storage request is created here.
Reuse the bounded verified Node archive reader; retain original source licenses.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
PINS = HERE / "image-snapshot-pins.json"
SOURCE = Path("/opt/volparossa-image")
RUNTIME = Path("/opt/volparossa-node")
REVISION = "e177afebabd99ac0773de2a73d60275346a5de52"
FILES = frozenset(("scripts/immich_snapshot.py", "scripts/snapshot-storage.mjs",
                   "src/core-storage.mjs", "LICENSE"))
TOOLS = {"gpg": "gpg", "gpg-agent": "gpg-agent", "gpgconf": "gpgconf", "tar": "tar"}


def require(condition):
    if not condition:
        raise ValueError("Image provision boundary or provenance failed")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def loader():
    return runpy.run_path(str(HERE / "agent-private-task-code.py"))


def load_pins():
    pins = json.loads(PINS.read_text())
    require(set(pins) == {"version", "repository", "revision", "files", "runtime"}
            and pins["version"] == 1 and pins["revision"] == REVISION
            and pins["repository"] == "https://github.com/VOLPAROSSA/volparossa-image"
            and set(pins["files"]) == FILES
            and pins["runtime"] == loader()["load_pins"]()["runtime"])
    for record in pins["files"].values():
        require(set(record) == {"bytes", "sha256"} and type(record["bytes"]) is int
                and 0 < record["bytes"] <= 131072
                and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]))
    return pins


def guard():
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha"
            and platform.machine() == "x86_64")
    require(subprocess.check_output(["systemd-detect-virt"], text=True, timeout=5).strip() == "kvm")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                   if "=" in line)
    require(release.get("ID", "").strip('"') == "debian"
            and release.get("VERSION_ID", "").strip('"') == "13")
    for root in (SOURCE, RUNTIME):
        require(root.resolve() == root and not root.exists() and not root.is_symlink())
    require(shutil.disk_usage(SOURCE.parent).free >= 512 * 1024**2)


def tool_receipts():
    tools = {}
    for name, package in TOOLS.items():
        path = Path("/usr/bin") / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o6022 and info.st_mode & 0o111
                and info.st_size <= 16 * 1024**2)
        version = subprocess.check_output(
            ["dpkg-query", "--show", "--showformat=${Version}", package], text=True, timeout=5)
        require(re.fullmatch(r"[0-9A-Za-z.+:~_-]{1,100}", version))
        tools[name] = dict(package=package, package_version=version,
                           bytes=info.st_size, sha256=digest(path))
    return tools


def verify_files(root, records):
    for name, record in records.items():
        path = root / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
                and info.st_size == record["bytes"] and digest(path) == record["sha256"])


def expose(root):
    # Only public exact-source code/runtime, never keys, requests or application input.
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            info = path.lstat()
            require(info.st_uid == 0 and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)))
            path.chmod(0o555 if path == RUNTIME / "bin/node" or stat.S_ISDIR(info.st_mode) else 0o444)
    root.chmod(0o555)


def provision():
    pins = load_pins()
    guard()
    os.umask(0o077)
    runtime_stage = loader()
    tools = tool_receipts()
    SOURCE.mkdir(mode=0o700)
    RUNTIME.mkdir(mode=0o700)
    for name, record in pins["files"].items():
        runtime_stage["fetch"](f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-image/{REVISION}/{name}",
                               SOURCE / name, record)
    # Download archive is private, short-lived, and never extracted by archive paths.
    with tempfile.TemporaryDirectory(prefix="image-node-stage.", dir="/opt") as temporary:
        archive = Path(temporary) / "node.tar.xz"
        runtime_stage["fetch"](pins["runtime"]["url"], archive, pins["runtime"])
        with tarfile.open(archive, "r:xz") as bundle:
            runtime_stage["extract_runtime"](bundle, RUNTIME, pins["runtime"]["files"])
    verify_files(SOURCE, pins["files"])
    verify_files(RUNTIME, pins["runtime"]["files"])
    require(subprocess.check_output([str(RUNTIME / "bin/node"), "--version"],
            text=True, timeout=10, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).strip() == "v24.19.0")
    report = dict(version=1, kind="image-snapshot-runtime-provision", success=True,
                  pins=pins, pins_sha256=digest(PINS), tools=tools,
                  guest_only=True, source_files_verified=True, runtime_files_verified=True,
                  original_licenses_retained=True, snapshot_created=False,
                  peer_storage_proven=False, immich_server_started=False)
    with (SOURCE / "provision.json").open("x") as output:
        output.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    expose(SOURCE)
    expose(RUNTIME)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("provision",))
    parser.add_argument("--download", action="store_true", required=True,
                        help="explicit guest-only pinned Image source and Node runtime download")
    parser.parse_args()
    print(json.dumps(dict(plan="guest-only-pinned-image-runtime", image_revision=REVISION,
                          snapshot_created=False, peer_storage_proven=False)), flush=True)
    provision()
    print("Pinned Image source and Node runtime verified; no snapshot or network storage tested")


if __name__ == "__main__":
    main()
