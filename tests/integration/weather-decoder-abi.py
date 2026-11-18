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
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

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


def read_file(path, maximum, *, parent=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o7022
                and 0 < before.st_size <= maximum)
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
    def __init__(self):
        self.drained = True

    def run(self, argv, deadline):
        require(time.monotonic() < deadline, "ABI_DEADLINE")
        child, raw = None, bytearray()
        try:
            child = subprocess.Popen(argv, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "ABI_DEADLINE")
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fd, min(65536, MAX_LOG + 1 - len(raw)))
                        if not chunk: selector.unregister(key.fileobj)
                        raw.extend(chunk)
                        require(len(raw) <= MAX_LOG, "ABI_OUTPUT_BOUND")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    verify = commands.add_parser("verify-inputs"); verify.add_argument("directory", type=Path)
    stage = commands.add_parser("stage-inputs")
    stage.add_argument("source", type=Path); stage.add_argument("destination", type=Path)
    run = commands.add_parser("execute")
    for name in ("inputs", "output"): run.add_argument("--"+name, required=True, type=Path)
    run.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    def interrupted(_sig, _frame): raise Interrupted()
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        if args.action == "verify-inputs":
            record, sha, files = verify_inputs(args.directory)
            value = dict(schema=1, kind="weather-decoder-abi-inputs", admission_sha256=sha,
                         files=len(files), weather_commit=record["weather_commit"], runtime_executed=False)
        elif args.action == "stage-inputs": value = stage_inputs(args.source, args.destination)
        else: value = execute(args.inputs, args.output, args.expected_commit)
        print(json.dumps(value, sort_keys=True))
        return 0 if value.get("success", True) else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, Interrupted):
        print("WEATHER_DECODER_ABI_REJECTED", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
