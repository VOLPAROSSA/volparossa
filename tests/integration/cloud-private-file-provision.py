#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit exact-source Cloud/Node staging, exclusively in the disposable guest.

No application data, model, OpenCloud server or storage request is created here.
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
PINS = HERE / "cloud-private-file-pins.json"
SOURCE = Path("/opt/volparossa-cloud")
RUNTIME = Path("/opt/volparossa-node")
REVISION = "c81980dd71297b257f1df6aa382c28a18f9c2f57"
FILES = frozenset(("scripts/cloud-file.mjs", "scripts/private_file.py", "src/private-file.mjs",
    "src/opencloud-dav.mjs", "vendor/volparossa-image/immich_snapshot.py",
    "vendor/volparossa-image/core-storage.mjs", "vendor/volparossa-image/LICENSE",
    "third_party/volparossa-image-source.json", "LICENSE", "scripts/cloud-catalog.mjs",
    "scripts/cloud-serve.mjs", "scripts/private_catalog.py", "scripts/stage_web_sdk.py",
    "src/private-catalog.mjs", "src/private-dav-server.mjs", "third_party/opencloud-web-sdk.json",
    "THIRD_PARTY_LICENSES.md", "src/private-resource-id.mjs", "src/recovery-web-metadata.mjs",
    "scripts/recovery-web-assets.mjs", "scripts/build_web_ui.py", "scripts/smoke_web_ui.py",
    "third_party/opencloud-web-ui.json", "patches/opencloud-web-owner-recovery.patch"))
SDK_SHA = "8954d9ad90e44a6f62d0e32d3280ca92fd7b0ce30042fe07cdde5c653e0739b3"
TOOLS = {"gpg": "gpg", "gpg-agent": "gpg-agent", "gpgconf": "gpgconf", "tar": "tar"}


def require(condition):
    if not condition:
        raise ValueError("Cloud provision boundary or provenance failed")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def loader():
    return runpy.run_path(str(HERE / "agent-private-task-code.py"))


def load_pins():
    pins = json.loads(PINS.read_text())
    require(set(pins) == {"version", "repository", "revision", "files", "runtime"}
            and pins["version"] == 1 and pins["revision"] == REVISION
            and pins["repository"] == "https://github.com/VOLPAROSSA/volparossa-cloud"
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
    require(shutil.disk_usage(SOURCE.parent).free >= 10 * 1024**3)


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
            browser_executable = path.is_relative_to(SOURCE / "build/firefox-esr") and info.st_mode & 0o111
            path.chmod(0o555 if path == RUNTIME / "bin/node" or browser_executable
                       or stat.S_ISDIR(info.st_mode) else 0o444)
    root.chmod(0o555)


def verify_sdk(source):
    """Verify every published SDK file; this is provenance, not a SDK read proof."""
    sdk = source / "build/web-sdk"
    receipt_path = sdk / "receipt.json"
    require(receipt_path.is_file() and not receipt_path.is_symlink()
            and receipt_path.stat().st_size <= 65536)
    receipt = json.loads(receipt_path.read_text())
    pins_sha = digest(source / "third_party/opencloud-web-sdk.json")
    require(receipt["version"] == 1 and receipt["kind"] == "opencloud-web-sdk-trial"
            and receipt["pins_sha256"] == pins_sha and receipt["archive_sha256"] == SDK_SHA
            and all(receipt[k] is False for k in ("package_scripts_run", "source_build_claimed", "global_installation"))
            and len(receipt["files"]) == 109
            and sum(r["bytes"] for r in receipt["files"].values()) == 1109076)
    for name in receipt["files"]:
        require(name.startswith("package/") and "\\" not in name
                and all(p not in ("", ".", "..") for p in name.split("/")))
    require({str(p.relative_to(sdk)) for p in sdk.rglob("*") if p.is_file()}
            == set(receipt["files"]) | {"receipt.json"})
    verify_files(sdk, receipt["files"])
    require("package/LICENSE" in receipt["files"] and "package/dist/web-client/webdav.js" in receipt["files"])
    return dict(pins_sha256=pins_sha, archive_sha256=SDK_SHA, receipt_sha256=digest(receipt_path),
                files_verified=True, files=109, source_build_claimed=False, sdk_reads_proven=False)


def provision():
    pins = load_pins()
    guard()
    os.umask(0o077)
    runtime_stage = loader()
    tools = tool_receipts()
    SOURCE.mkdir(mode=0o700)
    RUNTIME.mkdir(mode=0o700)
    for name, record in pins["files"].items():
        runtime_stage["fetch"](f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-cloud/{REVISION}/{name}",
                               SOURCE / name, record)
    # Download archive is private, short-lived, and never extracted by archive paths.
    with tempfile.TemporaryDirectory(prefix="cloud-node-stage.", dir="/opt") as temporary:
        archive = Path(temporary) / "node.tar.xz"
        runtime_stage["fetch"](pins["runtime"]["url"], archive, pins["runtime"])
        with tarfile.open(archive, "r:xz") as bundle:
            runtime_stage["extract_runtime"](bundle, RUNTIME, pins["runtime"]["files"])
    verify_files(SOURCE, pins["files"])
    verify_files(RUNTIME, pins["runtime"]["files"])
    # The source-built UI runs as vpci, not root; only its verified public Node
    # binary is exposed before the guarded builder creates the final assets.
    expose(RUNTIME)
    subprocess.run(["python3", "-B", str(SOURCE / "scripts/stage_web_sdk.py"), "--download", "--yes",
                    "--output", str(SOURCE / "build/web-sdk")], check=True, timeout=180,
                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    sdk = verify_sdk(SOURCE)
    require(subprocess.check_output([str(RUNTIME / "bin/node"), "--version"],
            text=True, timeout=10, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).strip() == "v24.19.0")
    ui_stage = runpy.run_path(str(HERE / "cloud-private-file-ui-provision.py"))
    ui = ui_stage["provision_ui"](SOURCE, RUNTIME)
    browser = ui_stage["provision_browser"](SOURCE)
    report = dict(version=1, kind="cloud-private-file-runtime-provision", success=True,
                  pins=pins, pins_sha256=digest(PINS), tools=tools, sdk=sdk, ui=ui, browser=browser,
                  guest_only=True, source_files_verified=True, runtime_files_verified=True,
                  original_licenses_retained=True, private_file_created=False,
                  peer_storage_proven=False, opencloud_server_started=False)
    with (SOURCE / "provision.json").open("x") as output:
        output.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    expose(SOURCE)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("provision",))
    parser.add_argument("--download", action="store_true", required=True,
                        help="explicit guest-only Cloud/Node, frozen Web8 UI build and pinned Firefox downloads")
    parser.parse_args()
    print(json.dumps(dict(plan="guest-only-pinned-cloud-runtime", cloud_revision=REVISION,
                          source_built_web_ui=True, browser_version="140.16.0",
                          ui_execution_proven=False, browser_execution_proven=False,
                          private_file_created=False, peer_storage_proven=False)), flush=True)
    provision()
    print("Pinned Cloud/Node, source-built Web8 and Firefox verified; no UI execution or peer storage tested")


if __name__ == "__main__":
    main()
