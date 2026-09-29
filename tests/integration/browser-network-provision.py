#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pinned Firefox/module staging, exclusively inside the explicit disposable KVM guest."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request

HERE = Path(__file__).resolve().parent
PINS = HERE / "browser-network-pins.json"
ROOT = Path("/home/vpci/browser-network-runtime")
FILES = ("scripts/smoke_network_core.py", "scripts/smoke_network.py", "scripts/smoke_browser_startup.py",
         "scripts/smoke_compute_model.py", "scripts/smoke_privacy.py", "scripts/stage_firefox.py",
         "integration/VolparossaNetwork.sys.mjs", "defaults/privacy.json")


def require(condition):
    if not condition:
        raise ValueError("browser runtime provenance or guest boundary failed")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def pins():
    value = json.loads(PINS.read_text())
    # A candidate without the root-reviewed browser commit is deliberately non-runnable.
    require(value["version"] == 1 and re.fullmatch(r"[0-9a-f]{40}", value["revision"] or "")
        and value["revision"] != "0" * 40 and set(value["files"]) == set(FILES)
        and value["repository"] == "https://github.com/VOLPAROSSA/volparossa-browser")
    for record in value["files"].values():
        require(set(record) == {"bytes", "sha256"} and type(record["bytes"]) is int
            and 0 < record["bytes"] <= 262144 and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]))
    runtime = value["runtime"]
    original = json.loads((HERE / "agent-private-task-browser-pins.json").read_text())["runtime"]
    require(runtime == original)
    return value


def fetch(url, path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    hashed, total = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=30) as source, path.open("xb") as output:
        while chunk := source.read(65536):
            total += len(chunk)
            require(total <= record["bytes"])
            hashed.update(chunk)
            output.write(chunk)
    require(total == record["bytes"] and hashed.hexdigest() == record["sha256"])


def provision(root):
    require(root == ROOT and not root.exists() and not root.is_symlink()
        and os.getuid() != 0 and subprocess.check_output(["hostname"], text=True).strip() == "volparossa-alpha"
        and subprocess.check_output(["systemd-detect-virt"], text=True).strip() == "kvm")
    value = pins()
    root.mkdir(mode=0o755)
    require(shutil.disk_usage(root).free >= 1024**3)
    for name, record in value["files"].items():
        fetch(f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-browser/{value['revision']}/{name}", root / name, record)
    package = root / "firefox-esr.deb"
    fetch(value["runtime"]["url"], package, value["runtime"])
    subprocess.run(["dpkg-deb", "--extract", str(package), str(root / "package")], check=True, timeout=60)
    subprocess.run([sys.executable, "-B", str(root / "scripts/stage_firefox.py"), "--firefox",
        str(root / "package/usr/lib/firefox-esr/firefox-esr"), "--output", str(root / "build/firefox-esr"),
        "--without-extensions", "--expected-version", value["runtime"]["version"],
        "--expected-source-stamp", value["runtime"]["source_stamp"]], check=True, timeout=90)
    for name, expected in value["runtime"]["files"].items():
        require(digest(root / "build/firefox-esr" / name) == expected)
    (root / "provision.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="ascii")
    # Same source/runtime are shared read-only with the capless synthetic application UID.
    for directory, _, files in os.walk(root):
        Path(directory).chmod(0o555)
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)


def main():
    require(len(sys.argv) == 3 and sys.argv[1] == "provision")
    provision(Path(sys.argv[2]))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("BROWSER_NETWORK_PROVISION_FAILED", file=sys.stderr)
        raise SystemExit(1)
