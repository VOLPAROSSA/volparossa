#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the pinned VSCodium workbench in a private mount and network namespace."""
import json
from pathlib import Path
import pwd
import runpy
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PROPOSAL = runpy.run_path(str(HERE / "agent-cooperative-code-proposal.py"))
require = PROPOSAL["require"]
PACKAGE_BYTES = PROPOSAL["EDITOR_BYTES"]
PACKAGE_SHA = PROPOSAL["EDITOR_SHA256"]
UNIT = "volparossa-alpha-cooperative-code.service"


def prepare(work, temporary, code):
    # Authenticate the very copy dpkg-deb will consume in the root-owned staging directory.
    package = temporary / "editor.deb"
    original = code / "runtime/editor.deb"
    uid = pwd.getpwnam("volparossa").pw_uid
    info = PROPOSAL["OLD"]["checked_file"](original, uid, PACKAGE_BYTES)
    require(info.st_size == PACKAGE_BYTES, "release size")
    with original.open("rb") as source, package.open("xb") as output:
        shutil.copyfileobj(source, output, 1048576)
    require(package.stat().st_size == PACKAGE_BYTES and PROPOSAL["digest"](package) == PACKAGE_SHA, "release digest")
    unpacked = temporary / "release"
    subprocess.run(["/usr/bin/dpkg-deb", "-x", package, unpacked], check=True, timeout=90)
    package.unlink()
    release = unpacked / "usr/share/codium"
    pin = PROPOSAL["read"](HERE / "agent-native-editor-pins.json")["editor"]
    binary = PROPOSAL["digest"](release / "codium")
    product = json.loads((release / "resources/app/product.json").read_bytes())
    require(binary == pin["binary_sha256"] and product["commit"] == pin["declared_source_commit"]
            and product["nameShort"] == "VSCodium", "VSCodium release identity")
    PROPOSAL["write"](work / "agent-cooperative-code-proposal-editor.json", dict(version=1, product=product["nameShort"],
        release=pin["version"], source_commit=product["commit"], binary_sha256=binary,
        package_bytes=PACKAGE_BYTES, package_sha256=PACKAGE_SHA))
    return release


def service(root, code, release, owner_socket):
    # The root-owned topology runs with umask 077. The ordinary editor must
    # traverse the empty system mount parents. The staged data and private
    # socket retain their same-owner access modes on their own bind mounts.
    for name in (".", "usr", "etc", "etc/fonts", "proc", "sys", "dev", "run", "tmp", "workbench",
                 "opt", "opt/volparossa-editor", "opt/volparossa-code"):
        directory = root / name
        directory.mkdir(exist_ok=True)
        directory.chmod(0o755)
    for name in ("bin", "sbin", "lib", "lib64"):
        (root / name).symlink_to("usr/" + name)
    for name in ("etc/passwd", "etc/group", "etc/ld.so.cache", "opt/volparossa-node"):
        (root / name).touch()
    (code / "projects/public.sock").touch(mode=0o600, exist_ok=False)
    readonly = ["/usr", "/etc/passwd", "/etc/group", "/etc/ld.so.cache", "/etc/fonts",
                f"{code}/code:/opt/volparossa-code", f"{release}:/opt/volparossa-editor",
                f"{code}/runtime/node:/opt/volparossa-node", f"{owner_socket}:/workbench/public.sock"]
    # This root already belongs exclusively to this invocation. On ext4,
    # systemd 257 creates the fallback RootEphemeral copy under the unit's
    # umask, leaving its root untraversable by the editor user.
    props = ["User=volparossa", "Group=volparossa", "UMask=0077", "NoNewPrivileges=yes", "CapabilityBoundingSet=",
             "AmbientCapabilities=", "PrivateNetwork=yes", "PrivateDevices=yes", "ProtectProc=invisible",
             "ProtectSystem=strict", "ReadOnlyPaths=/sys", "ProtectControlGroups=yes", "MountAPIVFS=yes",
             "TemporaryFileSystem=/tmp:mode=1777", "KillMode=control-group", "TimeoutStopSec=20s", "RuntimeMaxSec=2520s",
             "MemoryMax=3G", "MemorySwapMax=0", f"RootDirectory={root}", "WorkingDirectory=/workbench",
             "BindReadOnlyPaths=" + " ".join(readonly), f"BindPaths={code}/projects:/workbench", "ReadWritePaths=/workbench"]
    return ["/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--unit=" + UNIT, "--service-type=exec",
            *("--property=" + prop for prop in props), "--", "/opt/volparossa-node",
            "/opt/volparossa-code/scripts/public_peer_editor_ui.cjs", "--execute", "--yes"]


def main(work):
    PROPOSAL["JOBS"]["guest_work"](work)
    code, state = PROPOSAL["paths"](work)
    manifest = PROPOSAL["read"](work / "agent-cooperative-code-proposal-provision.json")["manifest"]
    PROPOSAL["bundle_manifest"](manifest)
    require(manifest.get("frontend") == "vscodium", "selected VSCodium bundle")
    with tempfile.TemporaryDirectory(prefix="public-code-editor-", dir=work) as staging:
        temporary = Path(staging)
        release = prepare(work, temporary, code)
        root = temporary / "root"
        return subprocess.run(service(root, code, release, state.parent / "public.sock"), check=False).returncode


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(64)
    raise SystemExit(main(Path(sys.argv[1])))
