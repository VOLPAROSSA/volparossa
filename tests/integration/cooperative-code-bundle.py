#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Transfer only the reviewed Code fixture inventory; never execute its inputs."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tarfile

CHECK = runpy.run_path(str(Path(__file__).with_name("agent-cooperative-code.py")))
require = CHECK["require"]
LIMIT = 341 * 1048576


def file_info(path, maximum):
    info = path.lstat()
    require(path.is_absolute() and path.resolve(strict=True) == path
            and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.geteuid() and not info.st_mode & 0o6022
            and 0 < info.st_size <= maximum, "unsafe bundle input")
    return info


def manifest(raw, expected):
    require(CHECK["hex64"](expected) and 0 < len(raw) <= 65536
            and hashlib.sha256(raw).hexdigest() == expected, "bundle manifest changed")
    value = json.loads(raw)
    CHECK["bundle_manifest"](value)
    return value


def capture(root, archive, expected):
    file_info(root / "INPUTS.json", 65536)
    raw = (root / "INPUTS.json").read_bytes()
    selected = manifest(raw, expected)
    require(archive.is_absolute() and archive.resolve() == archive
            and not archive.exists() and not archive.is_symlink(), "new archive required")
    with archive.open("xb") as output, tarfile.open(fileobj=output, mode="w") as bundle:
        for name in ("INPUTS.json", *sorted(selected["files"])):
            record = selected["files"].get(name, dict(bytes=len(raw), sha256=expected, mode=0o600))
            info = file_info(root / name, record["bytes"])
            require(info.st_size == record["bytes"] and stat.S_IMODE(info.st_mode) == record["mode"],
                    "bundle size or mode changed")
            header = tarfile.TarInfo(name)
            header.size, header.mode = record["bytes"], record["mode"]
            with (root / name).open("rb") as source:
                # Hash the exact bytes consumed by tar rather than a separate read.
                class CheckedReader:
                    def __init__(self):
                        self.hash = hashlib.sha256()

                    def read(self, count):
                        data = source.read(count)
                        self.hash.update(data)
                        return data

                reader = CheckedReader()
                bundle.addfile(header, reader)
                require(reader.hash.hexdigest() == record["sha256"] and not source.read(1), "bundle bytes changed")
    archive.chmod(0o600)
    require(archive.stat().st_size <= LIMIT, "archive too large")


def unpack(archive, root, expected):
    file_info(archive, LIMIT)
    require(root.is_absolute() and root.resolve() == root
            and not root.exists() and not root.is_symlink(), "new bundle directory required")
    with tarfile.open(archive, mode="r:") as bundle:
        first = bundle.next()
        require(first is not None and first.name == "INPUTS.json" and first.isfile()
                and not first.pax_headers and first.mode == 0o600 and 0 < first.size <= 65536,
                "manifest must be first")
        raw = bundle.extractfile(first).read(65537)
        selected = manifest(raw, expected)
        root.mkdir(mode=0o700)
        seen = set()
        while member := bundle.next():
            require(member.name in selected["files"] and member.name not in seen and member.isfile()
                    and not member.pax_headers, "unexpected archive entry")
            record = selected["files"][member.name]
            require(member.size == record["bytes"] and member.mode == record["mode"], "archive metadata changed")
            target = root / member.name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with bundle.extractfile(member) as source, target.open("xb") as output:
                while data := source.read(65536):
                    output.write(data)
                    digest.update(data)
            target.chmod(record["mode"])
            require(target.stat().st_size == record["bytes"] and digest.hexdigest() == record["sha256"],
                    "archive bytes changed")
            seen.add(member.name)
        require(seen == set(selected["files"]), "incomplete archive")
        # A partial directory deliberately has no accepted manifest.
        with (root / "INPUTS.json").open("xb") as output:
            output.write(raw)
        (root / "INPUTS.json").chmod(0o600)


def main():
    require(len(sys.argv) == 5 and sys.argv[1] in ("capture", "unpack"), "explicit transfer arguments required")
    action, first, second, expected = sys.argv[1:]
    (capture if action == "capture" else unpack)(Path(first), Path(second), expected)
    print(json.dumps(dict(version=1, transferred=True, action=action, manifest_sha256=expected,
                         runtime_executed=False, peer_execution_proven=False)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        print('{"transferred":false,"failure":"bundle_transfer_rejected"}')
        raise SystemExit(1)
