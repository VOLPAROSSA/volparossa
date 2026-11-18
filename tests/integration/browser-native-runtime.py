#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Export the reviewed local native build for a disposable guest; never publish binaries.

The original Firefox build stays untouched. The export resolves only its own
source/obj links, carries an exact file inventory and separately names the one
new product-JavaScript resource. No download or build is performed here.
"""
import argparse
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import shutil
import socket
import stat
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
PINS = HERE / "browser-native-pins.json"
BASE_RECEIPT_SHA = "4be952653fe30d9516dde25c4ccd1cf870a6ab87514f8ba6a0961a7f4d62485d"
FIREFOX_REVISION = "47c5f402c8d3a5369f1fb1b6cd61b0bb92725af1"
CONTROLLER = "VolparossaBrowserNetwork.sys.mjs"
BEFORE_CONTROLLER = "d2b0a5507b7fcc2b212d68ab344f4c7ae9364bd1fe146bf2963c91d4263d57cf"
AFTER_CONTROLLER = "fcc7eb622a1ff54e13e7ed40d5625e44f155c03b71fc0af9867bca6334379228"
PLUGIN_SHA = "8e3d79d8bea685047c94b72bdbc8ee2dbecd9781905483a6cc6237530e477eec"
GUEST_ROOT = Path("/home/vpci/browser-network-runtime")
MAX_BYTES = 1024 ** 3


def require(value):
    if not value:
        raise ValueError("native browser runtime provenance failed")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def canonical(raw):
    path = Path(raw).absolute()
    require(path == path.resolve() and path != Path("/"))
    return path


def file_record(path):
    require(path.is_file() and not path.is_symlink() and not path.stat().st_mode & 0o6000)
    return dict(bytes=path.stat().st_size, sha256=digest(path), executable=bool(path.stat().st_mode & 0o111))


def inventory(root):
    result = {}
    for directory, folders, files in os.walk(root):
        parent = Path(directory)
        # The separate private proof directory is not a runtime input. Do not
        # traverse/hash grants, browser profiles or status writes in that tree.
        if parent == root / "build":
            folders[:] = [name for name in folders if name != "proofs"]
        require(all(not (parent / name).is_symlink() for name in folders))
        for name in files:
            path = parent / name
            relative = str(path.relative_to(root))
            if relative != "native-bundle.json":
                result[relative] = file_record(path)
    require(0 < len(result) <= 20000 and sum(item["bytes"] for item in result.values()) <= MAX_BYTES)
    return result


def checked_pins():
    pins = json.loads(PINS.read_text())
    require(pins["version"] == 1 and len(pins["revision"] or "") == 40
            and set(pins["revision"]) <= set("0123456789abcdef")
            and pins["repository"] == "https://github.com/VOLPAROSSA/volparossa-browser")
    return pins


def copy_regular(source, destination):
    require(source.is_file() and not source.is_symlink())
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("xb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
    destination.chmod(0o555 if source.stat().st_mode & 0o111 else 0o444)


def source_checks():
    return runpy.run_path(str(HERE / "browser-native-source.py"))


def export(browser_checkout, native_build, output, *, source_built=False):
    browser, build, output = map(canonical, (browser_checkout, native_build, output))
    core = HERE.parents[1]
    require(output.is_relative_to(core / "build") and output != core / "build"
            and not output.exists() and build.is_relative_to(browser / "build"))
    pins = checked_pins()
    # Local identity check only: no fetch, credentials, hooks or remote mutation.
    revision = subprocess.check_output(["git", "-C", str(browser), "rev-parse", "HEAD"], text=True).strip()
    require(revision == pins["revision"])
    for name, item in pins["files"].items():
        require(file_record(browser / name)["sha256"] == item["sha256"]
                and (browser / name).stat().st_size == item["bytes"])
    sys.path.insert(0, str(browser / "scripts"))
    native = importlib.import_module("smoke_network_native")
    require(Path(native.__file__).resolve() == browser / "scripts/smoke_network_native.py")
    with (build / "build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if source_built:
            build_record = source_checks()["validate_build"](browser, build)
            require(build_record["controller_sha256"] == AFTER_CONTROLLER)
            receipt = build_record["receipt_sha256"]
            overlay = None
        else:
            metadata = native.validate_native_runtime(build, javascript_overlay=True)
            require(metadata["build_receipt_sha256"] == BASE_RECEIPT_SHA
                    and metadata["source_stamp"] == FIREFOX_REVISION
                    and metadata["javascript_overlay"]["original_sha256"] == BEFORE_CONTROLLER
                    and metadata["javascript_overlay"]["runtime_sha256"] == AFTER_CONTROLLER)
            receipt = BASE_RECEIPT_SHA
            overlay = metadata["javascript_overlay"]
        require(shutil.disk_usage(build).free >= 4 * MAX_BYTES)
        output.mkdir(parents=True, mode=0o700)
        source_runtime = build / "obj/dist/bin"
        for path in sorted(source_runtime.rglob("*")):
            require(not (path.is_symlink() and path.is_dir()))
            if path.is_dir():
                continue
            source = path.resolve(strict=True)
            require(source.is_relative_to(build / "source") or source.is_relative_to(build / "obj"))
            copy_regular(source, output / "build/firefox-native" / path.relative_to(source_runtime))
        # This is explicitly revised product JS, not evidence that the original
        # native compilation already included the corrected DOM-owner lookup.
        controller = output / "build/firefox-native/browser/modules" / CONTROLLER
        if source_built:
            require(digest(controller) == AFTER_CONTROLLER)
        else:
            require(digest(controller) == BEFORE_CONTROLLER)
            controller.chmod(0o600)
            with controller.open("wb") as destination:
                destination.write((browser / "integration" / CONTROLLER).read_bytes())
            controller.chmod(0o444)
        for name, item in pins["files"].items():
            copy_regular(browser / name, output / name)
        for name in ("build-result.json", "overlay.json"):
            copy_regular(build / name, output / "provenance" / name)
        # Retain the exact changed native sources, patch, licenses and reference
        # to the complete upstream source; this is a private local trial bundle.
        baseline = json.loads((build / "overlay.json").read_text())
        for name, sha in baseline["files"].items():
            require(digest(build / "source" / name) == sha)
            copy_regular(build / "source" / name, output / "provenance/source-overlay" / name)
        copy_regular(build / "source/LICENSE", output / "provenance/FIREFOX-LICENSE")
        copy_regular(HERE / "browser-native-core.py", output / "scripts/browser_native_core.py")
        module = "browser_native_shared.py" if source_built else "browser_native_runtime.py"
        copy_regular(Path(__file__).resolve(), output / "scripts" / module)
        if source_built:
            for name in ("browser-native-source.py", "browser-native-pins.json"):
                copy_regular(HERE / name, output / "scripts" / name)
            copy_regular(HERE / "browser-native-source-runtime.py", output / "scripts/browser_native_runtime.py")
        record = dict(version=2 if source_built else 1,
            kind="source-built-native-firefox-core-trial" if source_built else "local-native-firefox-core-trial",
            local_disposable_only=True, redistribution_reviewed=False, browser_revision=revision, browser_pins=pins,
            original_build_receipt_sha256=receipt, firefox_revision=FIREFOX_REVISION,
            javascript_overlay=overlay, native_rebuild=source_built, files=inventory(output))
        if source_built:
            record["source_build"] = build_record
        with (output / "native-bundle.json").open("x") as result:
            json.dump(record, result, indent=2, sort_keys=True)
            result.write("\n")
        validate(output)
        if source_built:
            require(source_checks()["validate_build"](browser, build) == build_record)
        else:
            native.validate_native_runtime(build, javascript_overlay=True)
    return dict(path=str(output), inventory_sha256=digest(output / "native-bundle.json"),
                files=len(record["files"]), bytes=sum(item["bytes"] for item in record["files"].values()))


def validate(root):
    root = canonical(root)
    manifest = root / "native-bundle.json"
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 8 * 1024 ** 2)
    value = json.loads(manifest.read_text())
    require(isinstance(value, dict) and value.get("kind") in (
        "local-native-firefox-core-trial", "source-built-native-firefox-core-trial"))
    require(value["local_disposable_only"] is True and value["firefox_revision"] == FIREFOX_REVISION)
    receipt = root / "provenance/build-result.json"
    baseline = json.loads(receipt.read_text())
    overlay = root / "provenance/overlay.json"
    require(json.loads(overlay.read_text()) == baseline["overlay"])
    if value["kind"] == "source-built-native-firefox-core-trial":
        record = value["source_build"]
        source_checks()["validate_record"](record)
        require(value["version"] == 2 and value["native_rebuild"] is True and value["javascript_overlay"] is None
                and value["browser_pins"] == checked_pins() and value["browser_revision"] == record["browser_revision"]
                and value["original_build_receipt_sha256"] == record["receipt_sha256"]
                and digest(receipt) == record["receipt_sha256"] and digest(overlay) == record["overlay_sha256"]
                and baseline["outputs"] == record["outputs"])
        for name, pin in checked_pins()["files"].items():
            path = root / name
            require(path.stat().st_size == pin["bytes"] and digest(path) == pin["sha256"])
        plugin_sha = record["plugin_container_sha256"]
    else:
        require(value["version"] == 1 and value["kind"] == "local-native-firefox-core-trial"
                and value["native_rebuild"] is False and value["original_build_receipt_sha256"] == BASE_RECEIPT_SHA
                and digest(receipt) == BASE_RECEIPT_SHA and value["javascript_overlay"]["original_sha256"] == BEFORE_CONTROLLER
                and value["javascript_overlay"]["runtime_sha256"] == AFTER_CONTROLLER)
        plugin_sha = PLUGIN_SHA
    for name, sha in baseline["outputs"].items():
        require(digest(root / "build/firefox-native" / Path(name).name) == sha)
    require(digest(root / "build/firefox-native/plugin-container") == plugin_sha
            and digest(root / "build/firefox-native/browser/modules" / CONTROLLER) == AFTER_CONTROLLER)
    require(value["files"] == inventory(root))
    return value


def admit(root, expected_manifest=None):
    manifest = root / "native-bundle.json"
    if expected_manifest is not None:
        require(digest(manifest) == expected_manifest)
    value = validate(root)
    require((value["kind"] == "source-built-native-firefox-core-trial") == (expected_manifest is not None))
    return value


def pack(root, archive, expected_manifest=None):
    root, archive = canonical(root), canonical(archive)
    admit(root, expected_manifest)
    require(archive.parent == root.parent and not archive.exists()
            and not (root / "build/proofs").exists())
    with archive.open("xb") as output:
        with tarfile.open(fileobj=output, mode="w:gz", compresslevel=1) as bundle:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    require(not path.is_symlink())
                    bundle.add(path, arcname=str(path.relative_to(root)), recursive=False)
    require(archive.stat().st_size <= MAX_BYTES)
    return dict(path=str(archive), bytes=archive.stat().st_size, sha256=digest(archive))


def provision(archive, sha256, expected_manifest=None):
    require(socket.gethostname() == "volparossa-alpha" and os.getuid() != 0
            and subprocess.check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
            and not GUEST_ROOT.exists() and not GUEST_ROOT.is_symlink()
            and archive.is_file() and not archive.is_symlink()
            and archive.stat().st_size <= MAX_BYTES and digest(archive) == sha256)
    GUEST_ROOT.mkdir(mode=0o755)
    total, names = 0, set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            name = PurePosixPath(member.name)
            total += member.size
            require(member.isfile() and not name.is_absolute() and ".." not in name.parts
                    and member.name not in names and total <= MAX_BYTES and len(names) < 20000
                    and not member.mode & 0o6000)
            names.add(member.name)
            path = GUEST_ROOT / member.name
            path.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(member) as source, path.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            path.chmod(0o555 if member.mode & 0o111 else 0o444)
    record = admit(GUEST_ROOT, expected_manifest)
    for directory, _, _ in os.walk(GUEST_ROOT):
        Path(directory).chmod(0o555)
    return dict(provisioned=True, browser_revision=record["browser_revision"], archive_sha256=sha256,
                manifest_sha256=digest(GUEST_ROOT / "native-bundle.json"))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("export")
    for name in ("browser-checkout", "native-build", "output"):
        create.add_argument("--" + name, type=Path, required=True)
    create.add_argument("--source-built", action="store_true")
    check = sub.add_parser("verify")
    check.add_argument("root", type=Path)
    archive = sub.add_parser("pack")
    archive.add_argument("root", type=Path)
    archive.add_argument("archive", type=Path)
    guest = sub.add_parser("provision")
    guest.add_argument("archive", type=Path)
    guest.add_argument("sha256")
    for operation in (check, archive, guest):
        operation.add_argument("--source-manifest-sha256")
    args = parser.parse_args()
    if args.command == "export":
        print(json.dumps(export(args.browser_checkout, args.native_build, args.output, source_built=args.source_built)))
    elif args.command == "verify":
        value = admit(args.root, args.source_manifest_sha256)
        print(json.dumps(dict(verified=True, files=len(value["files"]))))
    elif args.command == "pack":
        print(json.dumps(pack(args.root, args.archive, args.source_manifest_sha256)))
    else:
        print(json.dumps(provision(args.archive, args.sha256, args.source_manifest_sha256)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("BROWSER_NATIVE_RUNTIME_FAILED", file=sys.stderr)
        raise SystemExit(1) from None
