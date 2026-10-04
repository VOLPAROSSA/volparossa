#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Plan, or explicitly prepare, pinned workspace-only Debian QEMU tools.

No apt installation, maintainer scripts, VM launch, device or host-network changes.
Existing host shared libraries and ISO tools are recorded, not installed/replaced.
The caller still owns VM resource, network, filesystem and teardown confinement.
"""

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PINS = Path(__file__).with_name("browser-native-tools-pins.json")
LOADER = Path("/lib64/ld-linux-x86-64.so.2")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=60, **kwargs)


def fetch(url, maximum, expected, *, exact=True):
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.geturl().startswith("https://deb.debian.org/debian/"):
            raise ValueError("Unexpected download origin")
        data = response.read(maximum + 1)
    if len(data) > maximum or (exact and len(data) != maximum):
        raise ValueError("Unexpected download length")
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Pinned download digest mismatch")
    return data


def authenticated_metadata(pins, output):
    meta = pins["metadata"]
    keyring = Path(pins["keyring"])
    if digest(keyring) != pins["keyring_sha256"]:
        raise ValueError("Archive keyring changed; review required")
    release = fetch(pins["origin"] + meta["inrelease_path"], 4 * 1024 * 1024,
                    meta["inrelease_sha256"], exact=False)
    signature = run(["gpgv", "--keyring", str(keyring)], input=release)
    entry = f'{meta["index_sha256"]} {meta["index_size"]} {meta["index_path"]}'
    if entry not in {" ".join(line.split()) for line in release.decode().splitlines()}:
        raise ValueError("Package index is not covered by pinned signed release")
    index_url = (pins["origin"] + "dists/trixie/main/binary-amd64/by-hash/SHA256/"
                 + meta["index_sha256"])
    packed = fetch(index_url, meta["index_size"], meta["index_sha256"])
    decoder = lzma.LZMADecompressor()
    index = decoder.decompress(packed, max_length=80 * 1024 * 1024)
    if not decoder.eof:
        raise ValueError("Package index exceeds limit")
    entries = {}
    names = {p["name"] for p in pins["packages"]}
    for stanza in index.decode().split("\n\n"):
        values = dict(line.split(": ", 1) for line in stanza.splitlines()
                      if ": " in line and not line.startswith(" "))
        if values.get("Package") in names:
            entries[values["Package"]] = values
    fields = {"name": "Package", "version": "Version", "arch": "Architecture",
              "path": "Filename", "size": "Size", "sha256": "SHA256"}
    for package in pins["packages"]:
        if any(str(package[key]) != entries.get(package["name"], {}).get(field)
               for key, field in fields.items()):
            raise ValueError("Package pin differs from authenticated index")
    (output / "InRelease").write_bytes(release)
    (output / "Packages.xz").write_bytes(packed)
    (output / "signature-verification.txt").write_bytes(signature.stderr)


def wrapper(path, command, environment):
    lines = ["#!/bin/sh", "set -eu", "unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH"]
    for key, value in environment.items():
        lines.append(f"export {key}={shlex.quote(str(value))}")
    lines.append("exec " + shlex.join([str(part) for part in command]) + ' "$@"')
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o700)


def prepare(pins, output):
    common = Path(run(["git", "-C", str(ROOT), "rev-parse", "--path-format=absolute",
                       "--git-common-dir"], text=True).stdout.strip()).resolve()
    output = output.absolute()
    if output.exists() or output.is_symlink() or output.resolve() != output:
        raise ValueError("Output must be a new canonical directory")
    if not output.is_relative_to(common.parent) or output.parent == common.parent:
        raise ValueError("Output must be nested inside this repository workspace")
    if not output.parent.is_dir():
        raise ValueError("Output parent must already exist")
    for name in ("gpgv", "dpkg-deb", "genisoimage", "qemu-img", "file", "wget"):
        if name != "qemu-img" and not shutil.which(name):
            raise ValueError(f"Missing existing host tool: {name}")
    output.mkdir(mode=0o700)
    archives, sysroot, binaries = (output / name for name in ("archives", "root", "bin"))
    for directory in (archives, sysroot, binaries):
        directory.mkdir(mode=0o700)
    authenticated_metadata(pins, output)
    for package in pins["packages"]:
        print(f'Fetching pinned {package["name"]} {package["version"]}', flush=True)
        data = fetch(pins["origin"] + package["path"], package["size"], package["sha256"])
        archive = archives / Path(package["path"]).name
        archive.write_bytes(data)
        run(["dpkg-deb", "--extract", str(archive), str(sysroot)])
    relocated = {}
    for path in sorted(sysroot.rglob("*")):
        if path.is_symlink():
            target = os.readlink(path)
            if target.startswith("/"):
                replacement = os.path.relpath(sysroot / target.lstrip("/"), path.parent)
                path.unlink()
                path.symlink_to(replacement)
                relocated[str(path.relative_to(sysroot))] = {"old": target, "new": replacement}
            if not path.resolve().is_relative_to(sysroot):
                raise ValueError("Package symlink escapes workspace sysroot")
    lib = sysroot / "usr/lib/x86_64-linux-gnu"
    environment = {"PATH": f"{binaries}:/usr/bin:/bin", "LANG": "C",
                   "QEMU_MODULE_DIR": lib / "qemu"}
    host_libraries = {}
    for name in ("qemu-system-x86_64", "qemu-img"):
        executable = sysroot / "usr/bin" / name
        command = [LOADER, "--library-path", lib, executable]
        listing = run([str(LOADER), "--library-path", str(lib), "--list", str(executable)],
                      text=True).stdout
        if "not found" in listing:
            raise ValueError("Unresolved native library")
        (output / f"{name}-libraries.txt").write_text(listing)
        for raw_path in re.findall(r"(?:=> )?(/[^\s()]+)", listing):
            dependency = Path(raw_path).resolve()
            if dependency.is_file() and not dependency.is_relative_to(sysroot):
                host_libraries[str(dependency)] = digest(dependency)
        if name == "qemu-system-x86_64":
            command += ["-L", sysroot / "usr/share/qemu", "-bios",
                        sysroot / "usr/share/seabios/bios-256k.bin"]
        wrapper(binaries / name, command, environment)
    wrapper(binaries / "cloud-localds", [sysroot / "usr/bin/cloud-localds"], environment)
    versions = {name: run([str(binaries / name), "--version"], text=True).stdout.strip()
                for name in ("qemu-system-x86_64", "qemu-img")}
    if "kvm" not in run([str(binaries / "qemu-system-x86_64"), "-accel", "help"],
                        text=True).stdout.split():
        raise ValueError("QEMU build lacks KVM")
    files = {str(p.relative_to(output)): digest(p) for tree in (sysroot, binaries)
             for p in sorted(tree.rglob("*")) if p.is_file() and not p.is_symlink()}
    host_tools = {str(Path(shutil.which(name)).resolve()): digest(Path(shutil.which(name)))
                  for name in ("genisoimage", "file", "wget", "dpkg-deb", "gpgv")}
    receipt = {"schema": 1, "pins_sha256": digest(PINS), "output": str(output),
               "package_download_bytes": pins["package_download_bytes"],
               "versions": versions, "files": files, "relocated_symlinks": relocated,
               "host_libraries": host_libraries, "host_tools": host_tools,
               "host_installation": False, "vm_launched": False,
               "host_network_changed": False}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"prepared": str(output), "prepend_path": str(binaries)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="Explicitly download and extract pins")
    parser.add_argument("--verify", action="store_true", help="Read-only verification of prepared tools")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    pins = json.loads(PINS.read_text())
    if pins["schema"] != 1 or pins["package_download_bytes"] != sum(p["size"] for p in pins["packages"]):
        raise ValueError("Invalid pin manifest")
    if args.verify:
        if args.prepare or args.output is None:
            parser.error("--verify requires --output and excludes --prepare")
        root = args.output.absolute()
        if root != root.resolve() or not root.is_dir():
            raise ValueError("Noncanonical tool root")
        receipt = json.loads((root / "receipt.json").read_text())
        if receipt["pins_sha256"] != digest(PINS) or receipt["output"] != str(root):
            raise ValueError("Tool receipt identity differs")
        for collection in ("files", "host_libraries", "host_tools"):
            for name, sha in receipt[collection].items():
                path = root / name if collection == "files" else Path(name)
                if digest(path) != sha:
                    raise ValueError("Tool or dependency changed")
        for name, link in receipt["relocated_symlinks"].items():
            path = root / "root" / name
            if not path.is_symlink() or os.readlink(path) != link["new"] or not path.resolve().is_relative_to(root / "root"):
                raise ValueError("Relocated tool link changed")
        print(json.dumps({"verified": True, "tool_root": str(root)}))
        return
    if not args.prepare:
        print(json.dumps({"action": "plan_only", "packages": len(pins["packages"]),
                          "package_bytes": pins["package_download_bytes"],
                          "metadata_bytes": pins["metadata"]["index_size"],
                          "host_installation": False}, indent=2))
        return
    if args.output is None:
        parser.error("--prepare requires --output")
    prepare(pins, args.output)


if __name__ == "__main__":
    main()
