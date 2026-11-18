#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fixed Browser filter-trial inputs; hash, transfer and check without executing them.

The independently retained INPUTS.json hash is transfer authority, not permission
to run Firefox. Capture neither imports Browser scripts nor rewrites signed XPIs.
Only the separate reviewed guest hook may execute the verified fixture.
"""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

KIND = "volparossa-browser-filter-delivery-inputs"
STAGE = "build/firefox-filter-runtime/"
OUTPUT = "build/filter-delivery"
SCRIPTS = frozenset(("smoke_filter_delivery", "smoke_ubo_actor", "smoke_filter_selection",
    "smoke_filter_broker", "smoke_privacy", "smoke_consent", "smoke_browser_startup",
    "smoke_compute_model", "stage_firefox", "bundle_extensions", "consent_fixture"))
MODULES = ("Owner", "Journal", "Selection", "Actor", "ActorContract",
    "VolparossaFilterSelectionParent", "VolparossaFilterSelectionChild", "Contract",
    "Frame", "Clock", "Session", "Gecko", "AssetChannel", "AssetRedirect")
SOURCE_FILES = frozenset({*("scripts/" + name + ".py" for name in SCRIPTS),
    *("integration/filters/" + name + ".sys.mjs" for name in MODULES),
    "tests/fixtures/filter_delivery.sys.mjs", "defaults/privacy.json", "defaults/extensions.lock.json"})
# Exact retained Debian ESR stage, including all untouched extension packages/notices.
# A new runtime layout requires review of this allowlist, not recursive adoption.
RUNTIME_FILES = frozenset((
    "application.ini", "browser/chrome/icons/default/default128.png",
    "browser/chrome/icons/default/default16.png", "browser/chrome/icons/default/default32.png",
    "browser/chrome/icons/default/default48.png", "browser/chrome/icons/default/default64.png",
    "browser/defaults/preferences/debugger.js", "browser/defaults/preferences/firefox-branding.js",
    "browser/defaults/preferences/firefox.js", "browser/defaults/preferences/vendor.js",
    "browser/defaults/syspref/firefox-esr.js", "browser/extensions/langpack-nl@firefox-esr.mozilla.org.xpi",
    "browser/omni.ja", "crashhelper", "crashreporter", "defaults/pref/channel-prefs.js",
    "defaults/pref/volparossa-autoconfig.js", "dependentlibs.list", "distribution/extensions.lock.json",
    "distribution/extensions/ATBC@EasonWong.xpi", "distribution/extensions/gdpr@cavi.au.dk.xpi",
    "distribution/extensions/jid1-BoFifL9Vbdl2zQ@jetpack.xpi",
    "distribution/extensions/uBlock0@raymondhill.net.xpi",
    "distribution/licenses/Adaptive-Tab-Bar-Colour-MIT.txt", "distribution/licenses/Consent-O-Matic-MIT.txt",
    "firefox-bin", "firefox-esr", "fonts/TwemojiMozilla.ttf", "glxtest",
    "gmp-clearkey/0.1/libclearkey.so", "gmp-clearkey/0.1/manifest.json",
    "libfreeblpriv3.so", "libgkcodecs.so", "liblgpllibs.so", "libmozavcodec.so", "libmozavutil.so",
    "libmozgtk.so", "libmozsandbox.so", "libmozsqlite3.so", "libmozwayland.so", "libnss3.so",
    "libnssutil3.so", "libsmime3.so", "libsoftokn3.so", "libssl3.so", "libxul.so", "omni.ja",
    "pingsender", "platform.ini", "vaapitest", "volparossa-staging.json", "volparossa.cfg"))
EXECUTABLES = frozenset(STAGE + name for name in
    ("firefox-esr", "firefox-bin", "crashhelper", "crashreporter", "glxtest", "vaapitest", "pingsender"))
FILES = SOURCE_FILES | frozenset(STAGE + name for name in RUNTIME_FILES)
MAX_FILES = 128
MAX_MANIFEST = 65536
MAX_SOURCE = 1048576
MAX_FILE = 256 * 1048576
MAX_TOTAL = 384 * 1048576
MAX_ARCHIVE = 385 * 1048576


def require(condition):
    if not condition:
        raise ValueError("browser_filter_bundle_rejected")


def hex64(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def mode(name):
    return 0o700 if name in EXECUTABLES else 0o600


def bound(name):
    return MAX_FILE if name.startswith(STAGE) else MAX_SOURCE


def canonical(path, exists=True):
    require(path.is_absolute() and path != Path("/") and path.resolve(strict=exists) == path)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def safe_info(path, maximum, *, normalized=None):
    canonical(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in (0, os.geteuid())
            and not info.st_mode & 0o7002 and 0 < info.st_size <= maximum)
    # The retained workspace stage has 0664 XPI/config files. Accept only the
    # invoking owner's own group, then remove group access in the copied tree.
    require(not info.st_mode & 0o020 or (info.st_uid == os.geteuid() and info.st_gid == os.getegid()))
    if normalized is not None:
        require(stat.S_IMODE(info.st_mode) == normalized)
    return info


def open_checked(path, maximum, *, normalized=None):
    info = safe_info(path, maximum, normalized=normalized)
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb")
    try:
        require(identity(os.fstat(stream.fileno())) == identity(info))
    except BaseException:
        stream.close()
        raise
    return stream, info


def fingerprint(path, maximum, *, normalized=None):
    source, before = open_checked(path, maximum, normalized=normalized)
    with source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        require(identity(os.fstat(source.fileno())) == identity(before))
    require(identity(path.lstat()) == identity(before))
    return dict(bytes=before.st_size, sha256=digest)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def manifest(raw, expected):
    require(hex64(expected) and 0 < len(raw) <= MAX_MANIFEST
            and hashlib.sha256(raw).hexdigest() == expected)
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    require(type(value) is dict and set(value) == {"version", "kind", "files"}
            and type(value["version"]) is int and value["version"] == 1 and value["kind"] == KIND
            and type(value["files"]) is dict and set(value["files"]) == FILES
            and len(value["files"]) <= MAX_FILES and encode(value) == raw)
    total = 0
    for name, record in value["files"].items():
        require(type(record) is dict and set(record) == {"bytes", "mode", "sha256"}
                and type(record["bytes"]) is int and 0 < record["bytes"] <= bound(name)
                and type(record["mode"]) is int and record["mode"] == mode(name)
                and hex64(record["sha256"]))
        total += record["bytes"]
    require(total <= MAX_TOTAL)
    return value


def directories(files):
    return {str(parent) for name in files for parent in Path(name).parents if parent != Path(".")}


def inventory_tree(root, files, *, allow_output=False, normalized=False):
    canonical(root)
    wanted_dirs = directories(files)
    pending, seen = [(root, "")], set()
    count = 0
    while pending:
        directory, relative = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o7002)
        if normalized:
            require(stat.S_IMODE(info.st_mode) == 0o700)
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= MAX_FILES * 4)
                name = relative + entry.name
                if allow_output and name == OUTPUT:
                    # Private runtime outputs are outside this input inventory.
                    require(entry.is_dir(follow_symlinks=False))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    require(name in wanted_dirs)
                    pending.append((Path(entry.path), name + "/"))
                else:
                    require(name in files and entry.is_file(follow_symlinks=False))
                    seen.add(name)
    require(seen == set(files))


def python_closure(root):
    """Parse the fixed reviewed closure; never import or evaluate its contents."""
    edges = {}
    for name in sorted(SCRIPTS):
        source, info = open_checked(root / "scripts" / (name + ".py"), MAX_SOURCE)
        with source:
            raw = source.read(MAX_SOURCE + 1)
            require(len(raw) == info.st_size and identity(os.fstat(source.fileno())) == identity(info))
        local = set()
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node, ast.Import):
                imports = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                require(node.level == 0 and node.module is not None)
                imports = [node.module.split(".")[0]]
            else:
                continue
            for imported in imports:
                require(imported in SCRIPTS or imported in sys.stdlib_module_names)
                if imported in SCRIPTS:
                    local.add(imported)
        edges[name] = local
    reached, pending = set(), ["smoke_filter_delivery"]
    while pending:
        name = pending.pop()
        if name not in reached:
            reached.add(name)
            pending.extend(edges[name])
    require(reached == SCRIPTS)


def header(name, size, permissions):
    entry = tarfile.TarInfo(name)
    entry.size, entry.mode = size, permissions
    return entry.tobuf(format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict")


def new_path(path):
    canonical(path, exists=False)
    canonical(path.parent)
    require(not path.exists() and not path.is_symlink())


def capture(root, stage, archive):
    canonical(root)
    inventory_tree(stage, RUNTIME_FILES)
    python_closure(root)
    selected = {}
    for name in sorted(FILES):
        source = stage / name[len(STAGE):] if name.startswith(STAGE) else root / name
        selected[name] = dict(**fingerprint(source, bound(name)), mode=mode(name))
        if name in EXECUTABLES:
            require(source.stat().st_mode & 0o100)
    raw = encode(dict(version=1, kind=KIND, files=selected))
    expected = hashlib.sha256(raw).hexdigest()
    manifest(raw, expected)
    new_path(archive)
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        for name in ("INPUTS.json", *sorted(FILES)):
            record = selected.get(name, dict(bytes=len(raw), mode=0o600, sha256=expected))
            output.write(header(name, record["bytes"], record["mode"]))
            if name == "INPUTS.json":
                source, before = io.BytesIO(raw), None
            else:
                path = stage / name[len(STAGE):] if name.startswith(STAGE) else root / name
                source, before = open_checked(path, record["bytes"])
                require(before.st_size == record["bytes"])
            with source:
                digest, remaining = hashlib.sha256(), record["bytes"]
                while remaining:
                    chunk = source.read(min(65536, remaining))
                    require(bool(chunk))
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                require(not source.read(1) and digest.hexdigest() == record["sha256"])
                if before is not None:
                    require(identity(os.fstat(source.fileno())) == identity(before))
            output.write(b"\0" * (-record["bytes"] % 512))
        output.write(b"\0" * 1024)
        output.flush()
        os.fsync(output.fileno())
    return checked_archive(archive, expected)


def read_exact(source, length):
    raw = source.read(length)
    require(len(raw) == length)
    return raw


def read_header(source, name, record):
    require(read_exact(source, 512) == header(name, record["bytes"], record["mode"]))


def checked_archive(archive, expected, root=None):
    source, before = open_checked(archive, MAX_ARCHIVE)
    require(hex64(expected) and before.st_size % 512 == 0)
    with source:
        first = read_exact(source, 512)
        entry = tarfile.TarInfo.frombuf(first, "utf-8", "strict")
        require(entry.name == "INPUTS.json" and entry.type == tarfile.REGTYPE
                and 0 < entry.size <= MAX_MANIFEST and first == header("INPUTS.json", entry.size, 0o600))
        raw = read_exact(source, entry.size)
        require(read_exact(source, -entry.size % 512) == b"\0" * (-entry.size % 512))
        selected = manifest(raw, expected)
        if root is not None:
            new_path(root)
            root.mkdir(mode=0o700)
        for name, record in sorted(selected["files"].items()):
            read_header(source, name, record)
            target = None
            try:
                if root is not None:
                    path = root / name
                    directory = root
                    for part in Path(name).parts[:-1]:
                        directory /= part
                        directory.mkdir(mode=0o700, exist_ok=True)
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    target = os.fdopen(fd, "wb")
                digest, remaining = hashlib.sha256(), record["bytes"]
                while remaining:
                    chunk = read_exact(source, min(65536, remaining))
                    digest.update(chunk)
                    if target is not None:
                        target.write(chunk)
                    remaining -= len(chunk)
                require(digest.hexdigest() == record["sha256"])
                require(read_exact(source, -record["bytes"] % 512) == b"\0" * (-record["bytes"] % 512))
                if target is not None:
                    target.flush()
                    os.fchmod(target.fileno(), record["mode"])
            finally:
                if target is not None:
                    target.close()
        # No hidden PAX/GNU entries, appended tar, nonzero padding or trailing payload.
        require(read_exact(source, 1024) == b"\0" * 1024 and not source.read(1))
        require(identity(os.fstat(source.fileno())) == identity(before))
        source.seek(0)
        archive_hash = hashlib.file_digest(source, "sha256").hexdigest()
        require(identity(os.fstat(source.fileno())) == identity(before))
    if root is not None:
        # A failed/partial unpack never carries the accepted manifest marker.
        fd = os.open(root / "INPUTS.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
    return dict(manifest_sha256=expected, archive_sha256=archive_hash,
                files=len(selected["files"]), bytes=sum(item["bytes"] for item in selected["files"].values()))


def verify_tree(root, expected):
    source, before = open_checked(root / "INPUTS.json", MAX_MANIFEST, normalized=0o600)
    with source:
        raw = source.read(MAX_MANIFEST + 1)
        require(identity(os.fstat(source.fileno())) == identity(before))
    selected = manifest(raw, expected)
    inventory_tree(root, FILES | {"INPUTS.json"}, allow_output=True, normalized=True)
    for name, record in selected["files"].items():
        actual = fingerprint(root / name, record["bytes"], normalized=record["mode"])
        require(actual == {key: record[key] for key in ("bytes", "sha256")})
    return dict(manifest_sha256=expected, files=len(FILES), private_output_inspected=False)


def main():
    require(len(sys.argv) >= 2)
    action = sys.argv[1]
    if action in ("capture", "unpack"):
        require(len(sys.argv) == 5)
        first, second = map(Path, sys.argv[2:4])
        result = capture(first, second, Path(sys.argv[4])) if action == "capture" else checked_archive(first, sys.argv[4], second)
    else:
        require(action in ("verify", "verify-tree") and len(sys.argv) == 4)
        result = (checked_archive if action == "verify" else verify_tree)(Path(sys.argv[2]), sys.argv[3])
    print(json.dumps(dict(version=1, action=action, transferred=True, runtime_executed=False, **result), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, tarfile.TarError, UnicodeError):
        print('{"transferred":false,"failure":"browser_filter_bundle_rejected","runtime_executed":false}')
        raise SystemExit(1)
