#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Test only the source-reviewed decoder bytes in an offline disposable Debian VM.

The checked-in admission record, never a caller-provided hash, selects inputs.
The outer runner binds expected_commit to its verified source archive. This is
neither a release authorization nor a Weather origin/core/browser proof.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

RECORD = Path(__file__).resolve().parents[1] / "helper/weather-decoder-abi-v1.json"
DECODER = "eccodes-build/bin/grib_ls"
PROBE = "probe.grib2"
RECEIPT = "hosted-build-receipt.json"
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 160 * 1024**2, 64
MAX_LOG, TOTAL_SECONDS, COMMAND_SECONDS = 65536, 120, 30
LOGS = {"elf.log", "sandbox.log", "version.log", "decode-first.log", "decode-last.log"}
SANDBOX_DECODER, SANDBOX_PROBE = "/case/bin/grib_ls", "/case/probe.grib2"
ENV = {"LANG": "C.UTF-8", "RUST_LOG": "off"}
SCOPE = dict(disposable_abi_test_only=True, production_decoder_authorized=False,
             origin_acquisition_proven=False, core_delivery_proven=False, browser_proven=False)
SOURCE_COMMIT = "a45bc6e0df7756826fe7158cf0faf5146b9d6d2b"
SOURCE_FILES = {
    "scripts/prepare_hosted_decoder_environment.py": dict(bytes=34153, sha256="d1aa95db3bedac4143a6cfbbea7eb5e2caf751e29ba279cfa506873074e21815"),
    "scripts/prepare_hosted_decoder.py": dict(bytes=37718, sha256="8672ca01c52ecd3c5bc11e94396f926e492d95f33b86fa4c40774a9993446a51"),
    "scripts/build_eccodes.py": dict(bytes=11634, sha256="5bcb6d58b34e5b45647feae836bfd086ff0adce0e30487430f5c50941f579827"),
    "third_party/eccodes-sources.json": dict(bytes=2087, sha256="f136020562a6ff0d2a83b948189c31f839afb8a00ea87565469f38640fb0dc86"),
}
SOURCE_GUEST = Path("/home/vpci/weather-decoder-source")
ENVIRONMENT_RECORD = Path(__file__).resolve().parents[1] / "helper/weather-source-build-environment-v1.json"
SOURCE_BUILD_ROOT = SOURCE_GUEST / "build/hosted-decoder-cold"
SOURCE_PAYLOAD_ROOT = SOURCE_GUEST / "build/hosted-payload-cold"
SOURCE_PAYLOAD_NAMES = {"build-manifest.json", "eccodes-build/bin/grib_ls", "eccodes-build/bin/grib_filter",
    "eccodes-build/bin/codes_info", "prefix/lib/libaec.a", "probe.grib2", "ecbuild-source/LICENSE",
    "ecbuild-source/NOTICE", "ecbuild-source/COPYING", "libaec-source/LICENSE.txt", "eccodes-source/LICENSE",
    "eccodes-source/NOTICE", "eccodes-source/COPYING", "eccodes-source/third_party/expected/COPYING"}
SOURCE_BUILD_EXPORTS = {"source-build-report.json": 65536, "build-manifest.json": 1024**2,
    "payload-manifest.json": 1024**2, "capture-source-toolchain.log": 1024**2,
    "build-source.log": 1024**2, "stage-source-payload.log": 1024**2, "readback-report.json": 1024**2}
INVENTORY_ROOT = Path("/home/vpci/weather-decoder-environment")
INVENTORY_PHASE = Path("/home/vpci/guest-phase.txt")
INVENTORY_EXPORTS = {
    "candidate.json": 32 * 1024**2, "base-files.json": 32 * 1024**2,
    "before.tsv": 2 * 1024**2, "after.tsv": 2 * 1024**2,
    "resolver.log": 1024**2, "apt-update.log": 1024**2, "apt-install.log": 1024**2,
    "inventory-commands.json": 65536, "source-binding.json": 65536, "inventory-report.json": 65536,
    "debian.InRelease": 256 * 1024, "debian-security.InRelease": 256 * 1024,
}
INVENTORY_PUBLIC_EXPORTS = dict(INVENTORY_EXPORTS, **{
    "inventory-export.json": 65536, "inventory-vm-cleanup.json": 65536,
    "vm-console.log": 131072, "qemu.stderr": 131072, "current-phase": 128, "guest-exit-status": 16,
    "vm-incomplete.json": 65536})


class Interrupted(Exception):
    pass


class CleanupUnconfirmed(Exception):
    pass


def require(condition, code="ABI_INPUT_REJECTED"):
    if not condition:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def hex_value(value, count=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(count) + "}", value) is not None


def member(name):
    return type(name) is str and len(name) <= 240 and all(
        re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,79}", part) and part not in (".", "..")
        for part in name.split("/"))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, maximum, *, parent=None, allow_empty=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o7022
                and (0 <= before.st_size if allow_empty else 0 < before.st_size) and before.st_size <= maximum)
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)))
        return bytes(raw)
    finally:
        os.close(fd)


def validate_record(value):
    require(type(value) is dict and set(value) == {
        "schema", "kind", "scope", "weather_commit", "hosted_run", "files", "evidence"})
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == "volparossa-weather-decoder-abi-admission"
            and value["scope"] == "disposable-debian13-abi-only" and hex_value(value["weather_commit"], 40))
    run = value["hosted_run"]
    require(type(run) is dict and set(run) == {"id", "attempt"}
            and all(type(v) is int and 0 < v < 2**53 for v in run.values()))
    files = value["files"]
    require(type(files) is dict and {DECODER, PROBE, RECEIPT} <= files.keys() and len(files) <= MAX_FILES)
    total = 0
    for name, item in files.items():
        require(member(name) and type(item) is dict and set(item) == {"bytes", "sha256"}
                and type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_FILE and hex_value(item["sha256"]))
        require(not any(name.startswith(other + "/") for other in files))
        total += item["bytes"]
    require(total <= MAX_TOTAL)
    evidence = value["evidence"]
    require(type(evidence) is dict and set(evidence) == {"artifacts", "receipts"})
    require(type(evidence["artifacts"]) is dict and set(evidence["artifacts"]) == {"decoder", "provenance"})
    for item in evidence["artifacts"].values():
        require(type(item) is dict and set(item) == {"id", "sha256"}
                and type(item["id"]) is int and 0 < item["id"] < 2**53 and hex_value(item["sha256"]))
    require(type(evidence["receipts"]) is dict and 1 <= len(evidence["receipts"]) <= MAX_FILES
            and all(member(name) and hex_value(sha) for name, sha in evidence["receipts"].items()))
    return value


def admission():
    # An absent/unreviewed record fails closed, including during host staging.
    raw = read_file(RECORD, 65536)
    return validate_record(decode(raw)), digest(raw)


def directory(path, *, parent=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(fd)
        require(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o7022)
        return fd
    except BaseException:
        os.close(fd)
        raise


def inventory(root, expected):
    require(root.is_absolute() and root.resolve() == root and root != Path("/"))
    expected_directories = {str(Path(name).parent) for name in expected}
    expected_directories |= {str(parent) for name in expected for parent in Path(name).parents}
    files, count = {}, 0
    def visit(fd, prefix):
        nonlocal count
        for name in sorted(os.listdir(fd)):
            count += 1
            require(count <= MAX_FILES * 6)
            relative = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                require(relative in expected_directories)
                child = directory(name, parent=fd)
                try:
                    visit(child, relative + "/")
                finally:
                    os.close(child)
            else:
                require(relative in expected)
                raw = read_file(name, expected[relative]["bytes"], parent=fd)
                require(len(raw) == expected[relative]["bytes"] and digest(raw) == expected[relative]["sha256"])
                files[relative] = raw
    fd = directory(root)
    try:
        visit(fd, "")
    finally:
        os.close(fd)
    require(files.keys() == expected.keys())
    return files


def verify_inputs(root):
    record, record_sha = admission()
    files = inventory(root, record["files"])
    receipt = decode(files[RECEIPT])
    require(type(receipt) is dict and type(receipt.get("schema")) is int and receipt["schema"] == 1
            and receipt.get("kind") == "volparossa-hosted-decoder-build"
            and receipt.get("compiled") is True and receipt.get("tests_passed") is True
            and receipt.get("scope", {}).get("decoder_authorized") is False)
    for name in (DECODER, PROBE):
        matches = [item for item in receipt.get("artifacts", []) if item.get("path") == name]
        require(matches == [dict(path=name, **record["files"][name])])
    return record, record_sha, files


def fresh_directory(path):
    require(path.is_absolute() and path.parent.resolve() == path.parent and path.name not in ("", ".", ".."))
    fd = directory(path.parent)
    try:
        os.mkdir(path.name, 0o700, dir_fd=fd)
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as stream:
        stream.write(raw)


def stage_inputs(source, destination):
    record, record_sha, files = verify_inputs(source)
    require(not destination.is_relative_to(source))
    fresh_directory(destination)
    created = []
    try:
        for name, raw in files.items():
            path = destination/name
            parent = destination
            for part in Path(name).parts[:-1]:
                parent /= part
                parent.mkdir(mode=0o700, exist_ok=True)
            write_new(path, raw, 0o400)
            created.append(path)
        require(inventory(destination, record["files"]) == files)
    except BaseException:
        for path in reversed(created): path.unlink()
        for path in sorted({p for name in files for p in (destination/name).parents if p.is_relative_to(destination)},
                           key=lambda p: len(p.parts), reverse=True):
            if path.exists(): path.rmdir()
        raise
    return dict(schema=1, kind="weather-decoder-abi-staged", admission_sha256=record_sha,
                files=len(files), runtime_executed=False)


def guest_boundary(commit):
    require(hex_value(commit, 40), "ABI_SOURCE_COMMIT_INVALID")
    require(os.getuid() == os.geteuid() != 0 and socket.gethostname() == "volparossa-alpha"
            and os.uname().machine == "x86_64", "ABI_DISPOSABLE_GUEST_REQUIRED")
    virtual = subprocess.run(["/usr/bin/systemd-detect-virt", "--vm"], env=ENV, capture_output=True, timeout=2, check=False)
    require(virtual.returncode == 0 and virtual.stdout.strip() == b"kvm", "ABI_KVM_REQUIRED")
    raw = read_file(Path("/etc/os-release").resolve(), 16384)
    values = {}
    for line in raw.decode().splitlines():
        match = re.fullmatch(r'(ID|VERSION_ID)=(?:"([^"\n]*)"|([^"\n]*))', line)
        if match:
            require(match[1] not in values)
            values[match[1]] = match[2] if match[2] is not None else match[3]
    require(values == {"ID": "debian", "VERSION_ID": "13"}, "ABI_DEBIAN13_REQUIRED")
    names = {"libc6", "libstdc++6", "libgcc-s1", "libc-bin", "bubblewrap", "binutils", "util-linux", "python3"}
    result = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${Package} ${Version}\n", *sorted(names)],
                            env=ENV, capture_output=True, timeout=2, check=False)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 4096, "ABI_PACKAGES_UNAVAILABLE")
    packages = {}
    for line in result.stdout.decode().splitlines():
        name, version = line.split(" ")
        require(name in names and name not in packages and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,96}", version))
        packages[name] = version
    require(packages.keys() == names)
    return dict(os_id="debian", version_id="13", architecture="x86_64", kernel=os.uname().release,
                os_release_sha256=digest(raw), packages=packages)


def sandbox(scratch, command):
    return ["/usr/bin/bwrap", "--die-with-parent", "--unshare-net", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--new-session", "--tmpfs", "/", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--dir", "/etc", "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache", "--proc", "/proc",
        "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/case", "--dir", "/case/bin", "--dir", "/work",
        "--ro-bind", str(scratch/"decoder/grib_ls"), SANDBOX_DECODER,
        "--ro-bind", str(scratch/"probe.grib2"), SANDBOX_PROBE, "--chdir", "/work", "--",
        "/usr/bin/prlimit", "--as=536870912", "--cpu=20", "--fsize=1048576", "--nofile=64", "--", *command]


PREFLIGHT = r'''
import json, os
from pathlib import Path
s = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.geteuid() != 0 and int(s['CapEff'].strip(),16) == int(s['CapPrm'].strip(),16) == 0
assert s['NoNewPrivs'].strip() == '1'
interfaces = [line.split(':')[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
assert interfaces == ['lo']
assert not any(Path(p).exists() for p in ('/home','/root','/build','/etc/resolv.conf','/case/lib','/definitions'))
assert sorted(p.name for p in Path('/case/bin').iterdir()) == ['grib_ls']
assert sorted(p.name for p in Path('/case').iterdir()) == ['bin','probe.grib2']
print(json.dumps(dict(uid=os.geteuid(),network_namespace=os.readlink('/proc/self/ns/net'),isolated=True)))
'''


class Commands:
    def __init__(self, maximum=MAX_LOG, environment=None):
        self.drained = True
        self.maximum = maximum
        self.environment = ENV if environment is None else environment
        self.output_stream = None

    def run(self, argv, deadline):
        require(time.monotonic() < deadline, "ABI_DEADLINE")
        child, raw = None, bytearray()
        try:
            child = subprocess.Popen(argv, env=self.environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "ABI_DEADLINE")
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fd, min(65536, self.maximum + 1 - len(raw)))
                        if not chunk: selector.unregister(key.fileobj)
                        raw.extend(chunk)
                        require(len(raw) <= self.maximum, "ABI_OUTPUT_BOUND")
                        if self.output_stream is not None:
                            self.output_stream.write(chunk)
            status = child.wait(timeout=max(0.001, deadline-time.monotonic()))
            return status, bytes(raw)
        finally:
            if child is not None:
                try:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait(timeout=2)
                    child.stdout.close()
                    try: os.killpg(child.pid, 0)
                    except ProcessLookupError: pass
                    else: raise CleanupUnconfirmed()
                except (OSError, subprocess.SubprocessError, Interrupted, KeyboardInterrupt, CleanupUnconfirmed) as error:
                    self.drained = False
                    raise CleanupUnconfirmed() from error


def validate_point(raw, latitude, longitude, expected):
    value = decode(raw)
    require(type(value) is list and len(value) == 1, "ABI_DECODE_INVALID")
    item = value[0]
    require(item["keys"] == dict(edition=2, packingType="grid_ccsds", bitsPerValue=16, numberOfPoints=496)
            and item["method"] == "nearest" and len(item["neighbours"]) == 1, "ABI_DECODE_INVALID")
    point = item["neighbours"][0]
    require(point["distance_unit"] == "km", "ABI_DECODE_INVALID")
    for key, expected_value in (("latitude", latitude), ("longitude", longitude), ("value", expected), ("distance", 0)):
        require(type(point[key]) in (int, float) and math.isfinite(point[key]) and point[key] == expected_value,
                "ABI_DECODE_INVALID")


def execute(inputs, output, commit):
    guest = guest_boundary(commit)
    record, record_sha, files = verify_inputs(inputs)
    require(not output.is_relative_to(inputs) and not inputs.is_relative_to(output))
    fresh_directory(output)
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    commands = Commands()
    report = dict(schema_version=1, kind="weather-decoder-abi", source_commit=commit,
        admission_sha256=record_sha, weather_commit=record["weather_commit"], hosted_run=record["hosted_run"],
        guest=guest, success=False, phase="prepare", blocker=None, scope=dict(SCOPE),
        inputs={name: record["files"][name] for name in (DECODER, PROBE, RECEIPT)},
        checks=dict(inputs_verified=True, elf_inspected=False, sandbox_isolated=False, version=False,
                    first_point=False, last_point=False, relocated_lone_decoder=False),
        cleanup=dict(process_drain_confirmed=False, scratch_removed=False), logs={})
    scratch = None
    try:
        scratch = Path(tempfile.mkdtemp(prefix=".abi-", dir=output))
        (scratch/"decoder").mkdir(mode=0o700)
        write_new(scratch/"decoder/grib_ls", files[DECODER], 0o500)
        write_new(scratch/"probe.grib2", files[PROBE], 0o400)
        binary = files[DECODER]
        require(len(binary) >= 64 and binary[:7] == b"\x7fELF\x02\x01\x01"
                and struct.unpack_from("<H", binary, 16)[0] in (2, 3)
                and struct.unpack_from("<H", binary, 18)[0] == 62, "ABI_ELF_INVALID")
        def step(name, argv):
            report["phase"] = name
            status, raw = commands.run(sandbox(scratch, argv), min(deadline, time.monotonic()+COMMAND_SECONDS))
            log = name + ".log"
            require(log in LOGS)
            write_new(output/log, raw)
            report["logs"][log] = dict(bytes=len(raw), sha256=digest(raw), exit_status=status)
            require(status == 0, "ABI_COMMAND_FAILED")
            return raw
        probe = decode(step("sandbox", ["/usr/bin/python3", "-c", PREFLIGHT]))
        require(type(probe) is dict and set(probe) == {"uid", "network_namespace", "isolated"}
                and type(probe["uid"]) is int and probe["uid"] == os.geteuid() and probe["isolated"] is True
                and re.fullmatch(r"net:\[[0-9]+\]", probe["network_namespace"])
                and probe["network_namespace"] != os.readlink("/proc/self/ns/net"), "ABI_SANDBOX_INVALID")
        report["checks"]["sandbox_isolated"] = True
        step("elf", ["/usr/bin/readelf", "--wide", "--file-header", "--program-headers", "--dynamic",
                     "--version-info", "--notes", SANDBOX_DECODER])
        report["checks"]["elf_inspected"] = True
        require(step("version", [SANDBOX_DECODER, "-V"]).strip() == b"ecCodes Version 2.44.0", "ABI_VERSION_INVALID")
        report["checks"]["version"] = True
        for name, latitude, longitude, expected in (("first", 60, 0, 0), ("last", 0, 30, 495)):
            raw = step("decode-"+name, [SANDBOX_DECODER, "-j", "-l", f"{latitude},{longitude},1", "-p",
                       "edition:i,packingType:s,bitsPerValue:i,numberOfPoints:i", SANDBOX_PROBE])
            validate_point(raw, latitude, longitude, expected)
            report["checks"][name+"_point"] = True
        require(digest(read_file(scratch/"decoder/grib_ls", MAX_FILE)) == record["files"][DECODER]["sha256"])
        require(digest(read_file(scratch/"probe.grib2", MAX_FILE)) == record["files"][PROBE]["sha256"])
        report["checks"]["relocated_lone_decoder"] = True
        report["phase"] = "complete"
        report["success"] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, Interrupted, KeyboardInterrupt, CleanupUnconfirmed) as error:
        report["blocker"] = ("cleanup-unconfirmed" if isinstance(error, CleanupUnconfirmed) else
                             "interrupted" if isinstance(error, (Interrupted, KeyboardInterrupt)) else "validation-or-command-failed")
    finally:
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            report["cleanup"]["process_drain_confirmed"] = commands.drained
            if commands.drained:
                try:
                    if scratch is not None:
                        for path in (scratch/"decoder/grib_ls", scratch/"probe.grib2"):
                            if path.exists(): path.unlink()
                        (scratch/"decoder").rmdir()
                        scratch.rmdir()
                    report["cleanup"]["scratch_removed"] = True
                except OSError:
                    report["blocker"] = "cleanup-failed"
            report["success"] = report["success"] and all(report["cleanup"].values())
            report["elapsed_ms"] = max(0, int((time.monotonic()-started)*1000))
            write_new(output/"report.json", (json.dumps(report, sort_keys=True)+"\n").encode())
        finally:
            for sig, handler in previous.items(): signal.signal(sig, handler)
    return report


def source_checkout(root):
    require(root.is_absolute() and root.resolve() == root, "SOURCE_CHECKOUT_PATH")
    result = subprocess.run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"],
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, capture_output=True, timeout=5, check=True)
    require(result.stdout == (SOURCE_COMMIT + "\n").encode(), "SOURCE_COMMIT_MISMATCH")
    return source_files(root)


def source_files(root):
    # Only these four reviewed source files cross into the guest. No recursive
    # checkout copy, private audit directory, binary, lock or receipt is input.
    files = {}
    for name, expected in SOURCE_FILES.items():
        path = root / name
        require(path.resolve() == path, "SOURCE_PATH_ALIAS")
        raw = read_file(path, expected["bytes"])
        require(len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], "SOURCE_FILE_MISMATCH")
        files[name] = raw
    return files


def stage_source(source, destination):
    files = source_checkout(source)
    fresh_directory(destination)
    for name, raw in files.items():
        (destination / name).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(destination / name, raw, 0o400)
    require(inventory(destination, SOURCE_FILES) == files, "SOURCE_STAGE_MISMATCH")
    return dict(schema=1, kind="weather-decoder-source-staged", weather_commit=SOURCE_COMMIT,
                files=SOURCE_FILES, admitted=False, compiled=False)


def load_source_lock(helper):
    raw = read_file(ENVIRONMENT_RECORD, 32 * 1024**2)
    return helper["validate_record"](decode(raw), True), digest(raw)


def source_helper(root):
    source_files(root)
    return runpy.run_path(str(root / "scripts/prepare_hosted_decoder_environment.py"))


def source_archives(root):
    files = source_files(root)
    return decode(files["third_party/eccodes-sources.json"])["sources"]


class SourceRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        raise ValueError("SOURCE_ARCHIVE_REDIRECT_REJECTED")


def fetch_source_archives(root):
    source_checkout(root)
    load_source_lock(source_helper(root))  # Fail before any download without the reviewed fixed lock.
    destination = root / "build/source-archives"
    destination.parent.mkdir(mode=0o700, exist_ok=True)
    fresh_directory(destination)
    opener = urllib.request.build_opener(SourceRedirect(), urllib.request.ProxyHandler({}))
    for item in source_archives(root):
        # The URL/length/hash originate only in the fixed source-pin JSON above.
        with opener.open(item["url"], timeout=30) as response:
            raw = response.read(item["bytes"] + 1)
        require(len(raw) == item["bytes"] and digest(raw) == item["sha256"], "SOURCE_ARCHIVE_MISMATCH")
        write_new(destination / item["archive"], raw, 0o400)
    return dict(admitted=False, compiled=False, sources=3)


def build_source_files(root):
    expected = dict(SOURCE_FILES)
    for item in source_archives(root):
        expected["archives/" + item["archive"]] = dict(bytes=item["bytes"], sha256=item["sha256"])
    return expected


def stage_build_source(source, destination):
    load_source_lock(source_helper(source))
    stage_source(source, destination)
    (destination / "archives").mkdir(mode=0o700)
    for item in source_archives(source):
        raw = read_file(source / "build/source-archives" / item["archive"], item["bytes"])
        require(len(raw) == item["bytes"] and digest(raw) == item["sha256"], "SOURCE_ARCHIVE_MISMATCH")
        write_new(destination / "archives" / item["archive"], raw, 0o400)
    inventory(destination, build_source_files(destination))
    return dict(admitted=False, compiled=False, sources_verified=True)


class SnapshotRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, expected_sha256=None):
        super().__init__()
        require(expected_sha256 is None or hex_value(expected_sha256), "SNAPSHOT_DIGEST_PIN")
        self.expected_sha256 = expected_sha256

    def redirect_request(self, request, response, code, message, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        original = urllib.parse.urlsplit(request.full_url)
        basename = Path(original.path).name
        # Snapshot percent-encodes literal '+' in Debian package filenames.
        # Admit only that exact spelling, never general URL decoding (which
        # could hide separators, traversal, or a different package name).
        filenames = (basename, basename.replace("+", "%2B"))
        require(parsed.scheme == "https" and parsed.netloc == "snapshot.debian.org"
                and not parsed.query and not parsed.fragment
                and (any(re.fullmatch(r"/file/[0-9a-f]{40}/" + re.escape(name), parsed.path)
                         for name in filenames)
                     or (self.expected_sha256 is not None and
                         re.fullmatch(r"/file/[0-9a-f]{40}/" + self.expected_sha256, parsed.path))),
                "SNAPSHOT_REDIRECT_REJECTED")
        return super().redirect_request(request, response, code, message, headers, newurl)


def snapshot_fetch(url, path, maximum, deadline, expected_sha256=None):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.netloc == "snapshot.debian.org"
            and parsed.path.startswith("/archive/") and not parsed.query and not parsed.fragment,
            "SNAPSHOT_URL_REJECTED")
    remaining = min(90, deadline - time.monotonic())
    require(remaining > 0, "INVENTORY_DEADLINE")
    opener = urllib.request.build_opener(SnapshotRedirect(expected_sha256), urllib.request.ProxyHandler({}))
    total, checksum = 0, hashlib.sha256()
    with opener.open(url, timeout=min(30, remaining)) as response, \
            os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        while True:
            require(time.monotonic() < deadline, "INVENTORY_DEADLINE")
            chunk = response.read(min(65536, maximum + 1 - total))
            if not chunk: break
            total += len(chunk)
            require(total <= maximum, "SNAPSHOT_SIZE_BOUND")
            checksum.update(chunk)
            stream.write(chunk)
    require(total > 0, "SNAPSHOT_EMPTY")
    if expected_sha256 is not None:
        require(total == maximum and checksum.hexdigest() == expected_sha256, "SNAPSHOT_DIGEST")


def inventory_boundary(commit):
    require(hex_value(commit, 40) and os.getuid() == os.geteuid() != 0
            and socket.gethostname() == "volparossa-alpha" and os.uname().machine == "x86_64",
            "INVENTORY_DISPOSABLE_GUEST_REQUIRED")
    result = subprocess.run(["/usr/bin/systemd-detect-virt", "--vm"], capture_output=True,
                            env=ENV, timeout=2, check=True)
    require(result.stdout.strip() == b"kvm", "INVENTORY_KVM_REQUIRED")
    raw = read_file(Path("/etc/os-release").resolve(), 16384)
    require(re.search(br'^ID=(?:"debian"|debian)$', raw, re.M)
            and re.search(br'^VERSION_ID="13"$', raw, re.M), "INVENTORY_DEBIAN13_REQUIRED")


def inventory_apt_options(root, helper):
    # Override every source/list/cache path; never alter the image's /etc/apt.
    return [*helper["APT_OPTIONS"], "-o", "Dir::Etc::sourcelist=" + str(root / "sources.list"),
        "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::State::lists=" + str(root / "apt-lists"),
        "-o", "Dir::Cache::archives=" + str(root / "apt-cache"), "-o", "Dir::Cache::pkgcache=",
        "-o", "Dir::Cache::srcpkgcache=", "-o", "APT::Get::List-Cleanup=0",
        "-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
        "-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::https::Verify-Peer=true",
        "-o", "Acquire::https::Verify-Host=true"]


def inventory_failure(error, action, phase):
    # Only fixed phase/action labels, exception class and machine error codes
    # leave this boundary. Never print arbitrary exception messages or URLs.
    code = str(error)
    value = dict(kind="weather-source-inventory-failure", admitted=False, compiled=False,
                 action=action, phase=phase, exception=type(error).__name__,
                 code=code if re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) else "SOURCE_INPUT_INVENTORY_FAILED")
    for name, attribute in (("errno", "errno"), ("exit_status", "returncode"), ("http_status", "code")):
        item = getattr(error, attribute, None)
        if type(item) is int and -4096 <= item <= 4096:
            value[name] = item
    print(json.dumps(value, sort_keys=True), file=sys.stderr)
    return value


def source_inventory(commit, build_mode=False):
    inventory_boundary(commit)
    source_files(SOURCE_GUEST)
    helper = runpy.run_path(str(SOURCE_GUEST / "scripts/prepare_hosted_decoder_environment.py"))
    lock, lock_sha = load_source_lock(helper) if build_mode else (None, None)
    root = INVENTORY_ROOT
    fresh_directory(root)
    (root / "debs").mkdir(mode=0o700)
    for name in ("apt-cache", "apt-lists"):
        (root / name).mkdir(mode=0o700)
        (root / name / "partial").mkdir(mode=0o700)
    report = dict(schema=1, kind="weather-decoder-source-input-inventory", admitted=False,
        compiled=False, success=False, core_commit=commit, weather_commit=SOURCE_COMMIT,
        phase="base-image", scope=helper["SCOPE"], commands=[], blocker=None)
    write_new(root / "source-binding.json", json.dumps(dict(core_commit=commit, weather_commit=SOURCE_COMMIT,
        files=SOURCE_FILES), sort_keys=True).encode() + b"\n")
    deadline = time.monotonic() + 840
    commands = Commands(maximum=1024**2, environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
    def phase(name):
        report["phase"] = name
        INVENTORY_PHASE.write_text("weather-source-" + name + "\n")
    def command(name, argv, seconds=180):
        report["commands"].append(dict(log=name, argv=argv))
        with os.fdopen(os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
            commands.output_stream = stream
            try:
                code, raw = commands.run(argv, min(deadline, time.monotonic() + seconds))
                if stream.tell() == 0:
                    stream.write(raw)
            finally:
                commands.output_stream = None
                if stream.tell() == 0:
                    stream.write(b"(no output)\n")
        require(code == 0, "INVENTORY_COMMAND_FAILED")
        return raw
    try:
        before = command("before.tsv", ["/usr/bin/dpkg-query", "--show", "--showformat=" + helper["STATUS_FORMAT"]], 20)
        helper["inventory"](before)
        helper["capture_base"](root)
        repositories = {}
        for name, pin in helper["REPOSITORIES"].items():
            phase(name + "-inrelease-fetch")
            snapshot_fetch(pin["inrelease_url"], root / (name + ".InRelease"), pin["inrelease_bytes"], deadline)
            phase(name + "-inrelease-verify")
            repositories[name] = helper["verify_release"](root / (name + ".InRelease"), name)
            if build_mode:
                require(repositories[name] == lock["repositories"][name], "LOCKED_REPOSITORY_MISMATCH")
            index_url = pin["archive_url"] + "dists/" + pin["codename"] + "/" + helper["INDEX_PATH"]
            phase(name + "-index-fetch")
            snapshot_fetch(index_url, root / (name + ".Packages.xz"), repositories[name]["index"]["bytes"],
                           deadline, repositories[name]["index"]["sha256"])
            # Consume the stream now, before trusting APT or resolving packages.
            phase(name + "-index-verify")
            for _record in helper["index_records"](root / (name + ".Packages.xz"), repositories[name]["index"]):
                pass
        sources = ''.join("deb [arch=amd64 signed-by=" + str(helper["KEYRING"]) + "] " + pin["archive_url"] +
                          " " + pin["codename"] + " main\n" for pin in helper["REPOSITORIES"].values())
        write_new(root / "sources.list", sources.encode())
        options = inventory_apt_options(root, helper)
        sudo = ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "180s",
                "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get"]
        phase("resolve")
        if build_mode:
            require(helper["inventory"](before) == lock["before"], "BASE_INVENTORY_MISMATCH")
            selected = helper["package_delta"](lock["before"], lock["after"])
        else:
            command("apt-update.log", [*sudo, *options, "update"], 190)
            resolver = command("resolver.log", ["/usr/bin/apt-get", *options, "--simulate", "install", *helper["ROOT_PACKAGES"]], 60)
            selected = helper["resolver_inventory"](resolver)
        packages = helper["indexed_packages"](root, selected, repositories)
        phase("verify-debs")
        for package in packages:
            pin = helper["REPOSITORIES"][package["repository"]]
            snapshot_fetch(pin["archive_url"] + package["filename"], root / "debs" / Path(package["filename"]).name,
                           package["bytes"], deadline, package["sha256"])
        # Every archive and payload member is verified before apt can install it.
        helper["verified_packages"](root, selected, repositories)
        if build_mode:
            require(helper["verify_locked_inputs"](root)["environment_lock_sha256"] == lock_sha, "ENVIRONMENT_LOCK_CHANGED")
        phase("install")
        paths = [str(root / "debs" / Path(package["filename"]).name) for package in packages]
        require(paths, "INVENTORY_EMPTY_INSTALL")
        command("apt-install.log", [*sudo, *options, "--no-download", "install", *paths], 190)
        command("after.tsv", ["/usr/bin/dpkg-query", "--show", "--showformat=" + helper["STATUS_FORMAT"]], 20)
        phase("candidate")
        if build_mode:
            require(helper["check_environment"]()["environment_lock_sha256"] == lock_sha, "ENVIRONMENT_LOCK_CHANGED")
            report.update(success=True, environment_lock_sha256=lock_sha, environment_prepared=True)
        else:
            value = helper["validate_record"](helper["candidate"](root), False)
            helper["write_candidate_file"](root / "candidate.json", helper["canonical"](value))
            report.update(success=True, candidate_sha256=digest(helper["canonical"](value)))
        phase("complete")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, Interrupted, CleanupUnconfirmed) as error:
        report["blocker"] = "SOURCE_INPUT_INVENTORY_FAILED"
        report["failure"] = inventory_failure(error, "source-input-inventory", report["phase"])
        raise
    finally:
        # Keep original bounded logs even on failure; only this closed metadata
        # projection is exported by the existing guest finalizer.
        write_new(root / "inventory-commands.json", json.dumps(report["commands"], sort_keys=True).encode() + b"\n")
        write_new(root / "inventory-report.json", json.dumps(report, sort_keys=True).encode() + b"\n")
    return report


def export_inventory(output):
    fresh_directory(output)
    total = 0
    files = {}
    for name, maximum in INVENTORY_EXPORTS.items():
        path = INVENTORY_ROOT / name
        if not path.exists() and not path.is_symlink(): continue
        raw = read_file(path, maximum)
        total += len(raw)
        require(total <= 72 * 1024**2 and not re.search(br"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", raw),
                "INVENTORY_EXPORT_BOUND")
        if name.endswith('.json'): decode(raw)
        write_new(output / name, raw)
        files[name] = dict(bytes=len(raw), sha256=digest(raw))
    require("inventory-report.json" in files, "INVENTORY_REPORT_MISSING")
    write_new(output / "inventory-export.json", json.dumps(dict(schema=1, admitted=False, files=files), sort_keys=True).encode() + b"\n")
    return dict(admitted=False, files=len(files), bytes=total)


def source_builder(root):
    source_files(root)
    return runpy.run_path(str(root / "scripts/prepare_hosted_decoder.py"))


def source_cold_build(commit):
    inventory_boundary(commit)
    inventory(SOURCE_GUEST, build_source_files(SOURCE_GUEST))
    helper = source_helper(SOURCE_GUEST)
    _lock, lock_sha = load_source_lock(helper)
    report = dict(schema=1, kind="weather-decoder-source-cold-build", admitted=False, compiled=False,
        success=False, core_commit=commit, weather_commit=SOURCE_COMMIT, environment_lock_sha256=lock_sha,
        phase="environment", blocker=None)
    deadline = time.monotonic() + 2280
    try:
        source_inventory(commit, build_mode=True)
        commands = Commands(maximum=1024**2, environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"})
        script = str(SOURCE_GUEST / "scripts/prepare_hosted_decoder.py")
        toolchain = SOURCE_GUEST / "build/hosted-toolchain-cold"
        for action, arguments in [
            ("capture-source-toolchain", ["--output-dir", str(toolchain)]),
            ("build-source", ["--archives", str(SOURCE_GUEST / "archives"), "--output", str(SOURCE_BUILD_ROOT),
                              "--toolchain-manifest", str(toolchain / "toolchain.json")]),
            ("stage-source-payload", ["--build-output", str(SOURCE_BUILD_ROOT), "--output", str(SOURCE_PAYLOAD_ROOT)])]:
            report["phase"] = action
            INVENTORY_PHASE.write_text("weather-source-" + action + "\n")
            with os.fdopen(os.open(INVENTORY_ROOT / (action + ".log"),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
                commands.output_stream = stream
                try:
                    code, raw = commands.run(["/usr/bin/python3", "-B", script, action, *arguments], deadline)
                finally:
                    commands.output_stream = None
                    if stream.tell() == 0: stream.write(b"(no output)\n")
            require(code == 0, "SOURCE_BUILD_COMMAND_FAILED")
        source_payload_manifest_bytes()
        report.update(success=True, compiled=True, phase="complete")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, Interrupted, CleanupUnconfirmed) as error:
        report["blocker"] = "SOURCE_BUILD_FAILED"
        report["failure"] = inventory_failure(error, "source-build", report["phase"])
        raise
    finally:
        if INVENTORY_ROOT.is_dir():
            write_new(INVENTORY_ROOT / "source-build-report.json", json.dumps(report, sort_keys=True).encode() + b"\n")
    return report


def source_payload_manifest_bytes():
    _lock, lock_sha = load_source_lock(source_helper(SOURCE_GUEST))
    builder = source_builder(SOURCE_GUEST)
    raw = read_file(SOURCE_BUILD_ROOT / "payload-manifest.json", 1024**2)
    value = builder["validate_payload_manifest"](decode(raw), lock_sha)
    builder["verify_source_payload_tree"](SOURCE_PAYLOAD_ROOT, value, lock_sha)
    return raw


def source_payload_member(name):
    _lock, lock_sha = load_source_lock(source_helper(SOURCE_GUEST))
    builder = source_builder(SOURCE_GUEST)
    value = builder["validate_payload_manifest"](decode(read_file(SOURCE_BUILD_ROOT / "payload-manifest.json", 1024**2)), lock_sha)
    require(name in value["files"] and member(name), "SOURCE_PAYLOAD_MEMBER")
    expected = value["files"][name]
    path = SOURCE_PAYLOAD_ROOT / name
    require(path.resolve() == path and stat.S_IMODE(path.stat().st_mode) == expected["mode"], "SOURCE_PAYLOAD_MEMBER")
    raw = read_file(path, expected["bytes"])
    require(len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], "SOURCE_PAYLOAD_BYTES")
    return raw


def source_ssh(run_directory):
    require(run_directory.is_absolute() and run_directory.resolve() == run_directory
            and re.fullmatch(r'weather-decoder-abi-kvm\.[A-Za-z0-9]{6}', run_directory.name), "SOURCE_READBACK_DIRECTORY")
    info = run_directory.lstat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "SOURCE_READBACK_DIRECTORY")
    for name in ("guest-key", "known-hosts"):
        info = (run_directory / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, "SOURCE_READBACK_IDENTITY")
    argv = ["/usr/bin/ssh", "-F", "/dev/null", "-i", str(run_directory / "guest-key"), "-p", "22223"]
    for option in ("BatchMode=yes", "ConnectTimeout=5", "ClearAllForwardings=yes", "ControlMaster=no",
        "ForwardAgent=no", "GlobalKnownHostsFile=/dev/null", "HostKeyAlgorithms=ssh-ed25519", "IdentitiesOnly=yes",
        "IdentityAgent=none", "KbdInteractiveAuthentication=no", "PasswordAuthentication=no", "ProxyCommand=none",
        "ProxyJump=none", "RequestTTY=no", "StrictHostKeyChecking=yes", "Tunnel=no",
        "UserKnownHostsFile=" + str(run_directory / "known-hosts")):
        argv += ["-o", option]
    return argv + ["vpci@127.0.0.1", "/usr/bin/python3", "-B", "/home/vpci/source/tests/integration/weather-decoder-abi.py"]


def readback_source_payload(source, run_directory, output):
    source_checkout(source)
    _lock, lock_sha = load_source_lock(source_helper(source))
    builder = source_builder(source)
    ssh = source_ssh(run_directory)
    commands = Commands(maximum=1024**2)
    deadline = time.monotonic() + 240
    code, raw = commands.run([*ssh, "source-payload-manifest"], deadline)
    require(code == 0, "SOURCE_READBACK_FAILED")
    manifest = builder["validate_payload_manifest"](decode(raw), lock_sha)
    fresh_directory(output)
    for name, expected in sorted(manifest["files"].items()):
        commands.maximum = expected["bytes"]
        code, data = commands.run([*ssh, "source-payload-member", name], deadline)
        require(code == 0 and len(data) == expected["bytes"] and digest(data) == expected["sha256"], "SOURCE_READBACK_BYTES")
        destination = output / name
        parent = output
        for part in Path(name).parts[:-1]:
            parent /= part
            parent.mkdir(mode=0o700, exist_ok=True)
        write_new(destination, data, expected["mode"])
    commands.maximum = 1024**2
    code, after = commands.run([*ssh, "source-payload-manifest"], deadline)
    require(code == 0 and after == raw, "SOURCE_READBACK_CHANGED")
    checked = builder["verify_source_payload_tree"](output, manifest, lock_sha)
    return dict(checked, schema=1, kind="weather-source-payload-readback",
                environment_lock_sha256=lock_sha, payload_manifest_sha256=digest(raw))


def source_build_export_spec(builder):
    names = {"version-" + name + ".log" for name in builder["VERSION_ARGS"]}
    names |= {"resolve-" + name.replace('_', '-') + ".log" for name, *_ in builder["COMPILER_PROGRAMS"]}
    names |= {name + ".log" for name, _ in builder["commands"]({name: {"path": "/unused"} for name in builder["TOOLS"]})}
    exports = dict(SOURCE_BUILD_EXPORTS)
    for prefix in ("native-", "toolchain-"):
        exports.update({prefix + name: 16 * 1024**2 for name in names})
    exports.update({"native-hosted-build-receipt.json": 1024**2, "toolchain-toolchain.json": 1024**2,
                    "toolchain-source-toolchain-receipt.json": 1024**2})
    return exports


def export_source_build(output):
    result = export_inventory(output)
    # Only the fixed producer's log names are considered, never its native tree.
    builder = source_builder(SOURCE_GUEST)
    total = result["bytes"]
    for name, maximum in source_build_export_spec(builder).items():
        if name.startswith('native-'):
            path = SOURCE_BUILD_ROOT / name.removeprefix('native-')
        elif name.startswith('toolchain-'):
            path = SOURCE_GUEST / 'build/hosted-toolchain-cold' / name.removeprefix('toolchain-')
        elif name in ('build-manifest.json', 'payload-manifest.json'):
            path = SOURCE_BUILD_ROOT / name
        else:
            path = INVENTORY_ROOT / name
        if not path.exists() and not path.is_symlink(): continue
        raw = read_file(path, maximum, allow_empty=name.endswith('.log'))
        total += len(raw)
        require(total <= 128 * 1024**2 and not re.search(br"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", raw), "SOURCE_BUILD_EXPORT_BOUND")
        if name.endswith('.json'): decode(raw)
        write_new(output / name, raw)
    return dict(admitted=False, bytes=total, binaries_exported=False)


def stage_inventory_public(source, output, extra_exports=None):
    require(source.is_absolute() and source.resolve() == source and not output.is_relative_to(source),
            "INVENTORY_PUBLIC_PATH")
    fresh_directory(output)
    files, total = {}, 0
    for name, maximum in dict(INVENTORY_PUBLIC_EXPORTS, **(extra_exports or {})).items():
        path = source / name
        if not path.exists() and not path.is_symlink(): continue
        try:
            # QEMU commonly has an empty stderr file on a quiet boot. Empty
            # plain runner logs are evidence; JSON/status inputs stay nonempty.
            raw = read_file(path, maximum, allow_empty=name in {"qemu.stderr", "vm-console.log"} or
                            (extra_exports is not None and name.endswith('.log')))
            total += len(raw)
            require(total <= (128 if extra_exports is not None else 73) * 1024**2
                    and not re.search(br"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", raw),
                    "INVENTORY_PUBLIC_BOUND")
            if name.endswith('.json'): decode(raw)
            write_new(output / name, raw)
        except (OSError, ValueError) as error:
            inventory_failure(error, "stage-inventory-public", name)
            raise
        files[name] = dict(bytes=len(raw), sha256=digest(raw))
    require(files, "INVENTORY_PUBLIC_EMPTY")
    write_new(output / "inventory-public-export.json", json.dumps(dict(schema=1, admitted=False,
              compiled=None if extra_exports is not None else False, files=files), sort_keys=True).encode() + b"\n")
    return dict(admitted=False, compiled=None if extra_exports is not None else False, files=len(files), bytes=total)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    verify = commands.add_parser("verify-inputs"); verify.add_argument("directory", type=Path)
    stage = commands.add_parser("stage-inputs")
    stage.add_argument("source", type=Path); stage.add_argument("destination", type=Path)
    run = commands.add_parser("execute")
    for name in ("inputs", "output"): run.add_argument("--"+name, required=True, type=Path)
    run.add_argument("--expected-commit", required=True)
    commands.add_parser("source-info")
    source_stage = commands.add_parser("stage-source")
    source_stage.add_argument("source", type=Path); source_stage.add_argument("destination", type=Path)
    source_verify = commands.add_parser("verify-source")
    source_verify.add_argument("directory", type=Path)
    source_run = commands.add_parser("source-input-inventory")
    source_run.add_argument("--expected-commit", required=True)
    source_export = commands.add_parser("export-source-inventory")
    source_export.add_argument("output", type=Path)
    public_export = commands.add_parser("stage-inventory-public")
    public_export.add_argument("source", type=Path); public_export.add_argument("output", type=Path)
    for name in ("verify-environment-lock", "fetch-source-archives"):
        commands.add_parser(name).add_argument("source", type=Path)
    build_stage = commands.add_parser("stage-build-source")
    build_stage.add_argument("source", type=Path); build_stage.add_argument("destination", type=Path)
    commands.add_parser("verify-build-source").add_argument("directory", type=Path)
    commands.add_parser("source-build").add_argument("--expected-commit", required=True)
    commands.add_parser("export-source-build").add_argument("output", type=Path)
    commands.add_parser("source-payload-manifest")
    commands.add_parser("source-payload-member").add_argument("name")
    commands.add_parser("source-build-export-names")
    readback = commands.add_parser("readback-source-payload")
    for name in ("source", "run-directory", "output"):
        readback.add_argument("--" + name, required=True, type=Path)
    build_public = commands.add_parser("stage-source-build-public")
    for name in ("source", "output", "weather"):
        build_public.add_argument(name, type=Path)
    args = parser.parse_args()
    def interrupted(_sig, _frame): raise Interrupted()
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        if args.action == "verify-inputs":
            record, sha, files = verify_inputs(args.directory)
            value = dict(schema=1, kind="weather-decoder-abi-inputs", admission_sha256=sha,
                         files=len(files), weather_commit=record["weather_commit"], runtime_executed=False)
        elif args.action == "stage-inputs": value = stage_inputs(args.source, args.destination)
        elif args.action == "source-info": value = dict(weather_commit=SOURCE_COMMIT, files=SOURCE_FILES, admitted=False)
        elif args.action == "stage-source": value = stage_source(args.source, args.destination)
        elif args.action == "verify-source":
            inventory(args.directory, SOURCE_FILES)
            value = dict(admitted=False, source_verified=True, weather_commit=SOURCE_COMMIT)
        elif args.action == "source-input-inventory": value = source_inventory(args.expected_commit)
        elif args.action == "export-source-inventory": value = export_inventory(args.output)
        elif args.action == "stage-inventory-public": value = stage_inventory_public(args.source, args.output)
        elif args.action == "verify-environment-lock":
            source_checkout(args.source)
            _lock, lock_sha = load_source_lock(source_helper(args.source))
            value = dict(admitted=False, environment_lock_sha256=lock_sha, compiled=False)
        elif args.action == "fetch-source-archives": value = fetch_source_archives(args.source)
        elif args.action == "stage-build-source": value = stage_build_source(args.source, args.destination)
        elif args.action == "verify-build-source":
            inventory(args.directory, build_source_files(args.directory))
            value = dict(admitted=False, compiled=False, source_archives_verified=True)
        elif args.action == "source-build": value = source_cold_build(args.expected_commit)
        elif args.action == "export-source-build": value = export_source_build(args.output)
        elif args.action == "source-payload-manifest":
            sys.stdout.buffer.write(source_payload_manifest_bytes()); return 0
        elif args.action == "source-payload-member":
            sys.stdout.buffer.write(source_payload_member(args.name)); return 0
        elif args.action == "source-build-export-names":
            print('\n'.join(sorted(set(INVENTORY_PUBLIC_EXPORTS) | set(source_build_export_spec(source_builder(SOURCE_GUEST))))))
            return 0
        elif args.action == "readback-source-payload": value = readback_source_payload(args.source, args.run_directory, args.output)
        elif args.action == "stage-source-build-public":
            source_checkout(args.weather)
            value = stage_inventory_public(args.source, args.output, source_build_export_spec(source_builder(args.weather)))
        else: value = execute(args.inputs, args.output, args.expected_commit)
        print(json.dumps(value, sort_keys=True))
        return 0 if value.get("success", True) else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, Interrupted, CleanupUnconfirmed):
        print("WEATHER_DECODER_ABI_REJECTED", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
