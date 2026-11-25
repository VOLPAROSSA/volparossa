#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Run the pinned VSCodium workbench in a private mount and network namespace."""
import json
import os
from pathlib import Path
import pwd
import runpy
import shutil
import subprocess
import sys
import tempfile
import time

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


def service(root, code, release, owner_socket, planner_socket=None):
    # The root-owned topology runs with umask 077. The ordinary editor must
    # traverse the empty system mount parents. The staged data and private
    # socket retain their same-owner access modes on their own bind mounts.
    for name in (".", "usr", "etc", "etc/fonts", "proc", "sys", "dev", "run", "tmp", "var", "var/lib", "workbench",
                 "opt", "opt/volparossa-editor", "opt/volparossa-code"):
        directory = root / name
        directory.mkdir(exist_ok=True)
        directory.chmod(0o755)
    for name in ("bin", "sbin", "lib", "lib64"):
        (root / name).symlink_to("usr/" + name)
    # The driver and extension verify that a project is distinct from the
    # canonical account home. Both see the same session-owned private home.
    (root / "var/lib/volparossa").symlink_to("/workbench/session/home")
    for name in ("etc/passwd", "etc/group", "etc/ld.so.cache", "opt/volparossa-node"):
        (root / name).touch()
    (code / "projects/public.sock").touch(mode=0o600, exist_ok=False)
    readonly = ["/usr", "/etc/passwd", "/etc/group", "/etc/ld.so.cache", "/etc/fonts",
                f"{code}/code:/opt/volparossa-code", f"{release}:/opt/volparossa-editor",
                f"{code}/runtime/node:/opt/volparossa-node", f"{owner_socket}:/workbench/public.sock"]
    driver = "public_peer_editor_ui.cjs"
    if planner_socket is not None:
        runtime = root / "opt/volparossa-runtime"
        runtime.mkdir()
        runtime.chmod(0o755)
        (code / "projects/private.sock").touch(mode=0o600, exist_ok=False)
        readonly.append(f"{planner_socket}:/workbench/private.sock")
        for asset in ("opencode", "build-report.json"):
            (runtime / asset).touch()
            readonly.append(f"{code}/runtime/{asset}:/opt/volparossa-runtime/{asset}")
        driver = "public_peer_planner_ui.cjs"
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
            f"/opt/volparossa-code/scripts/{driver}", "--execute", "--yes"]


def private_workers(group, weights, seen):
    # Inspect only this dedicated service's cgroup. No conversation or model output is opened.
    for candidate in group.read_text().splitlines():
        process = Path("/proc") / candidate
        try:
            with (process / "cmdline").open("rb") as stream:
                if not stream.read(32).startswith(b"/runtime/bin/python3\0-I\0-c\0"):
                    continue
            identity = PROPOSAL["JOBS"]["identity"](int(candidate))
            key = (identity["pid"], identity["start_ticks"])
            if key in seen:
                continue
            model = process / "root/model/model.safetensors"
            require(os.path.samefile(weights, model), "planner model identity")
            mounts = {row.split()[4]: row.split()[5].split(",") for row in (process / "mountinfo").read_text().splitlines()}
            interfaces = [row.split(":")[0].strip() for row in (process / "net/dev").read_text().splitlines()[2:]]
            require(all("ro" in mounts.get(name, []) for name in ("/runtime", "/model")) and interfaces == ["lo"]
                    and os.readlink(process / "ns/net") != os.readlink("/proc/self/ns/net")
                    and (process / "cgroup").read_text().strip() == "0::/system.slice/" + group.parent.name,
                    "local planner worker scope")
            if PROPOSAL["JOBS"]["alive"](identity):
                yield key
        except (FileNotFoundError, ProcessLookupError):
            continue


def run_planner(work, state, command):
    weights = work / "agent-jobs-user/provision/model/model.safetensors"
    fingerprint = PROPOSAL["digest"](weights)
    require(fingerprint == PROPOSAL["MODEL"]["base_weights"]["sha256"], "planner weights")
    group = Path("/sys/fs/cgroup/system.slice/volparossa-alpha-workbench-planner.service/cgroup.procs")
    seen, before, after = set(), set(), set()
    with subprocess.Popen(command) as editor:
        while editor.poll() is None:
            for key in private_workers(group, weights, seen):
                require(len(seen) < 128, "planner worker bound")
                if not PROPOSAL["BROWSER"]["task_roots"](state):
                    before.add(key)
                if any(state.glob("*/execution/receipt-*.json")):
                    after.add(key)
                seen.add(key)
            time.sleep(0.2)
    ended = not any(PROPOSAL["JOBS"]["alive"](dict(pid=pid, start_ticks=ticks)) for pid, ticks in seen)
    PROPOSAL["write"](work / "agent-cooperative-code-proposal-planner.json",
        dict(version=1, model_profile=PROPOSAL["PROFILE"], weights_sha256=fingerprint, observed_workers=len(seen),
             before_public_task=len(before), after_peer_receipt=len(after), observed_workers_ended=ended))
    return editor.returncode


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
        if manifest.get("planner") == "local_opencode":
            socket = work / "agent-jobs-user/local-planner/private.sock"
            return run_planner(work, state, service(root, code, release, state.parent / "public.sock", socket))
        return subprocess.run(service(root, code, release, state.parent / "public.sock"), check=False).returncode


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(64)
    raise SystemExit(main(Path(sys.argv[1])))
