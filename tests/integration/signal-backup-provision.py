#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit pinned Signal build provisioning, only in the disposable KVM guest.

No Electron application, Signal account or backup runs here. Package lifecycle
scripts remain disabled; the separately audited native archives are materialized
offline by the pinned chat tooling. The actual backup test is a separate step.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import urllib.request

ROOT = Path("/home/vpci/signal-backup-runtime")
CHAT_REPOSITORY = "https://github.com/VOLPAROSSA/volparossa-chat"
CHAT_REVISION = "c897667d76bea8140f0bc5f373404e43cbd54552"
SIGNAL_REVISION = "ef3872cb0249ec939d8aff857568a0e87a6b5075"
LOCK_SHA256 = "bc06486a375791ed118b10f10c33428b0fefa37ce22e6c2cf56c2bf37dd11040"
CANDIDATE = "build/signal-backup-candidate"
NODE = "build/node-v24.19.0-linux-x64-with-npm/bin/node"
FILES = {
    "LICENSE": (35149, "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"),
    "upstream-lock.json": (2100, "1993b0dafb24a107d3702de4d5d144d765aba65123e9f680900fbf6f9200c385"),
    "scripts/stage_signal_source.py": (8116, "557954d2a9b7e6b6b24f2b51ccec15cda829c22a9e70fd22420a7c0d36168f11"),
    "scripts/stage_node.py": (8939, "83131d1745d072d73bd8fc4443a44b1405569716c3a26a1cd1cfefe5e470e812"),
    "scripts/stage_pnpm.py": (5154, "a694c1c9203ea43870e994da74066bd59bbfce77e79e43dad04e579ba0c027b2"),
    "scripts/stage_signal_dependencies.py": (17304, "ae3b7d99568010ef6caf69f0569947bedb0550993d8b3982115cc519e1131bb2"),
    "scripts/stage_signal_native.py": (11796, "00999a8c288516f3c7cb7e509915e238dcf4dcbc38897b9a75f651ad039ccc32"),
    "scripts/install_signal_native.py": (11235, "44a3396a1e486e5d6c2510fde84a85d549239c8c46a151fc8225ffebe65e8d1f"),
    "scripts/build_signal_candidate.py": (9706, "f2fae84721aae441d50086b57e4daa0c4b984b31c9aee9e0d55eb14ebc2113d2"),
    "scripts/apply_signal_overlay.py": (5582, "b24d5a9848d225e0b0273363a098780a4d5501f93fa968c686dd0a8885268cb5"),
    "patches/signal-backup-test.txt": (1766, "d7836788f7c3812984da43fec4395d8dbb8a5d0579ad20d556b4f9b149d0ec03"),
    "overlay/ts/services/backups/volparossa/archive.node.ts": (8082, "a9b5a191727cb007f91ef0be21a7ad4aecd086f06de8f18f9fb2d7757319e1cf"),
    "overlay/ts/services/backups/volparossa/connector.preload.ts": (8718, "ec14d7019b9b7e24f8a10dfd20d4e75c58359af065946afc9263605e8d60f0cd"),
    "overlay/ts/services/backups/volparossa/replicas.node.ts": (5584, "3ec62020058841d6b2c099b921eb55d7e8f5aa4d1cb8a2822e0f73d82022a4bd"),
}
STEPS = (
    ("source", "stage_signal_source.py", ("--download",), 180),
    ("node", "stage_node.py", ("--with-npm",), 300),
    ("pnpm", "stage_pnpm.py", ("--download",), 180),
    ("overlay", "apply_signal_overlay.py", (), 180),
    ("dependencies", "stage_signal_dependencies.py", ("--download",), 1920),
    ("electron-archive", "stage_signal_native.py", ("--download", "--artifact", "electron"), 660),
    ("ringrtc-archive", "stage_signal_native.py", ("--download", "--artifact", "ringrtc"), 660),
    ("electron-materialize", "install_signal_native.py", ("--artifact", "electron"), 180),
    ("ringrtc-materialize", "install_signal_native.py", ("--artifact", "ringrtc"), 180),
    ("compile", "build_signal_candidate.py", ("--build",), 2640),
)


def require(condition, message="Signal provision boundary or provenance failed"):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check_pins():
    require(re.fullmatch(r"[0-9a-f]{40}", CHAT_REVISION or "")
            and CHAT_REVISION != "0" * 40, "reviewed chat revision is required")
    require(len(FILES) == 14 and sum(size for size, _ in FILES.values()) <= 1024 * 1024)
    for name, (size, sha) in FILES.items():
        path = Path(name)
        require(not path.is_absolute() and str(path) == name and ".." not in path.parts
                and 0 < size <= 131072 and re.fullmatch(r"[0-9a-f]{64}", sha))


def guard(root):
    require(root == ROOT and root.resolve() == root and not root.exists() and not root.is_symlink())
    require(os.getuid() != 0 and os.getuid() == pwd.getpwnam("vpci").pw_uid
            and socket.gethostname() == "volparossa-alpha" and platform.machine() == "x86_64")
    require(subprocess.check_output(["systemd-detect-virt"], text=True, timeout=5).strip() == "kvm")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "debian" and release.get("VERSION_ID", "").strip('"') == "13")
    require(shutil.disk_usage(root.parent).free >= 12 * 1024**3, "insufficient disposable guest staging space")


def fetch(url, path, size, sha):
    """Fetch one exact small source file, not an arbitrary archive or installer."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "volparossa-signal-guest-provision/1"})
    with urllib.request.urlopen(request, timeout=60) as response, path.open("xb") as output:
        require(response.geturl() == url, "unexpected pinned source redirect")
        hashed, total = hashlib.sha256(), 0
        while chunk := response.read(min(65536, size - total + 1)):
            total += len(chunk)
            require(total <= size, "pinned source size exceeded")
            hashed.update(chunk)
            output.write(chunk)
    require(total == size and hashed.hexdigest() == sha, "pinned source hash differs")
    path.chmod(0o600)


def write_report(root, report):
    target = root / "provision.json"
    temporary = root / "provision.json.tmp"
    with temporary.open("x") as output:
        output.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(target)


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024**2)
    return json.loads(path.read_bytes())


def compile_receipt(root):
    receipts = list((root / "build/signal-candidate-build").glob("attempt-*.json"))
    require(len(receipts) == 1, "one fresh compilation receipt required")
    report = read_json(receipts[0])
    require(report["source"] == SIGNAL_REVISION and report["lock_sha256"] == LOCK_SHA256
            and report["preparatory_compilation_succeeded"] is True
            and report["native_app_started"] is False and report["signal_backup_runtime_proven"] is False
            and [step["name"] for step in report["steps"]] == ["types", "windows-ucv", "mock-server", "app-assets"])
    for step in report["steps"]:
        require(step["succeeded"] is True and step["original_source_and_lock_unchanged"] is True
                and step["process_group_joined"] is True and step["result"] == "COMPILED")
        for name, sha in step["output_sha256"].items():
            path = root / CANDIDATE / name
            require(path.resolve().is_relative_to(root / CANDIDATE) and digest(path) == sha)
    return digest(receipts[0])


def expose_tree(root):
    """Expose only verified public runtime/source, never fixture state or logs.

    The application receives a read-only view in its own sandbox. pnpm may
    hardlink public package files into its private cache; those bytes remain
    identical and the cache's enclosing directories remain owner-only.
    """
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root)
    entries = [root]
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            info = path.lstat()
            require(info.st_uid == os.getuid(), "foreign runtime ownership")
            if stat.S_ISLNK(info.st_mode):
                require(path.resolve(strict=True).is_relative_to(root), "runtime symlink escapes shared tree")
            else:
                require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "unsupported runtime object")
                require(not info.st_mode & 0o7000, "privileged runtime permissions refused")
                entries.append(path)
    # Validate the entire tree before changing any of its ordinary permissions.
    for path in entries:
        mode = path.lstat().st_mode
        path.chmod(0o555 if stat.S_ISDIR(mode) or mode & 0o111 else 0o444)


def load_supervisor(root):
    scripts = root / "scripts"
    sys.path.insert(0, str(scripts))
    spec = importlib.util.spec_from_file_location("signal_provision_supervisor", scripts / "stage_signal_dependencies.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def provision(root):
    check_pins()
    guard(root)
    os.umask(0o077)
    root.mkdir(mode=0o700)
    logs = root / "provision-logs"
    logs.mkdir(mode=0o700)
    report = dict(version=1, kind="signal-backup-runtime-provision", chat_repository=CHAT_REPOSITORY,
        chat_revision=CHAT_REVISION, signal_revision=SIGNAL_REVISION, lock_sha256=LOCK_SHA256,
        candidate=CANDIDATE, node=NODE, node_version="24.19.0", electron_version="44.1.0",
        files={name: dict(bytes=size, sha256=sha) for name, (size, sha) in FILES.items()},
        phase="source-files", steps=[], success=False, source_files_verified=False,
        native_app_started=False, signal_backup_runtime_proven=False,
        preload_cache_generated=False, package_lifecycle_scripts_enabled=False,
        pinned_source_configuration_hook_enabled=True, native_artifacts_materialized=False,
        preparatory_compilation_succeeded=False, third_party_notices_retained=True)
    write_report(root, report)
    for name, (size, sha) in FILES.items():
        fetch(f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-chat/{CHAT_REVISION}/{name}",
              root / name, size, sha)
    report["source_files_verified"] = True
    supervisor = load_supervisor(root)
    environment = {key: os.environ[key] for key in ("HOME", "USER", "LOGNAME") if key in os.environ}
    environment.update(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8")
    for phase, script, arguments, timeout in STEPS:
        report["phase"] = phase
        write_report(root, report)
        command = [sys.executable, "-B", str(root / "scripts" / script), *arguments]
        result = supervisor.run_bounded(command, root, environment, logs / (phase + ".log"), [root], timeout=timeout)
        report["steps"].append(dict(name=phase, **result))
        write_report(root, report)
        require(result["result"] == "INSTALLED" and result["process_group_joined"] is True,
                "pinned Signal provisioning step failed")
    report["phase"] = "runtime-validation"
    write_report(root, report)
    report["compile_receipt_sha256"] = compile_receipt(root)
    candidate = root / CANDIDATE
    require(digest(candidate / "pnpm-lock.yaml") == LOCK_SHA256)
    report["runtime_sha256"] = {name: digest(candidate / name) for name in (
        "node_modules/electron/dist/electron", "node_modules/@signalapp/ringrtc/build/linux/libringrtc-x64.node",
        "node_modules/@signalapp/libsignal-client/prebuilds/linux-x64/@signalapp+libsignal-client.node",
        "node_modules/@signalapp/sqlcipher/prebuilds/linux-x64/@signalapp+sqlcipher.node",
        "bundles/main.js", "bundles/preload/main.js", "bundles/workers/sql.js")}
    report["node_sha256"] = digest(root / NODE)
    require((candidate / "node_modules/electron/path.txt").read_bytes() == b"electron"
            and not (candidate / "preload.bundle.cache").exists())
    expose_tree(candidate)
    expose_tree((root / NODE).parent.parent)
    (root / "build").chmod(0o755)
    root.chmod(0o755)
    report.update(phase="complete", success=True, native_artifacts_materialized=True,
                  preparatory_compilation_succeeded=True)
    write_report(root, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("provision",))
    parser.add_argument("root", type=Path)
    parser.add_argument("--download", action="store_true", required=True,
                        help="explicit guest-only source/dependency/native downloads and offline compilation")
    args = parser.parse_args()
    print(json.dumps(dict(plan="pinned-signal-runtime-only", root=str(args.root),
                         steps=[step[0] for step in STEPS], native_app_started=False)), flush=True)
    provision(args.root)
    print("SIGNAL_BACKUP_PROVISIONED_RUNTIME_NOT_TESTED", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("SIGNAL_BACKUP_PROVISION_FAILED", file=sys.stderr)
        raise SystemExit(1) from None
