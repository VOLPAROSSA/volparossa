#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real private resolver guest proof; never run DNS or mount changes on the host."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import selectors
import signal
import socket
import struct
import subprocess
import tempfile
import time


WORKER = Path("/usr/libexec/volparossa-dns-worker")
CASES = ("signed", "unsigned", "bogus", "timeout", "cancel")
DIAGNOSTIC_NAMES = {"signed": b"iana.org", "bogus": b"dnssec-failed.org"}
NATIVE_MAGIC = b"VPDNS002"
NATIVE_MAX_REPLY = 44 + 253 + 16 * 16 + 4096


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def identity(pid):
    """Return exact process lifetime, never treat a zombie as completed reaping."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "start": int(fields[19]), "state": fields[0],
                "ppid": int(fields[1])}
    except FileNotFoundError:
        return None


def stop_owned_worker(process):
    deadline = time.monotonic() + 0.4
    while time.monotonic() < deadline and process.poll() is None:
        for task in Path(f"/proc/{process.pid}/task").iterdir():
            try:
                children = (task / "children").read_text().split()
            except FileNotFoundError:
                continue
            for child in children:
                pid = int(child)
                before = identity(pid)
                if before is None or before["ppid"] != process.pid:
                    continue
                try:
                    executable = Path(f"/proc/{pid}/exe").readlink()
                    if executable != WORKER:
                        continue
                    handle = os.pidfd_open(pid)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                try:
                    after = identity(pid)
                    require(after is not None and after["start"] == before["start"],
                            "WORKER_IDENTITY_CHANGED")
                    signal.pidfd_send_signal(handle, signal.SIGSTOP)
                    return before, handle
                except BaseException:
                    os.close(handle)
                    raise
        time.sleep(0.002)
    raise RuntimeError("OWNED_NATIVE_WORKER_NOT_OBSERVED")


def run_case(probe, case):
    account = pwd.getpwnam("vpci")
    process = subprocess.Popen(
        [str(probe), case], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, user=account.pw_uid, group=account.pw_gid,
        extra_groups=[], env={"PATH": "/usr/bin:/bin",
                             "VOLPAROSSA_PRIVATE_DNS_PARENT_MNTNS":
                             os.environ["VOLPAROSSA_PRIVATE_DNS_PARENT_MNTNS"]})
    held = None
    handle = None
    completed = False
    try:
        if case in ("timeout", "cancel"):
            held, handle = stop_owned_worker(process)
        with selectors.DefaultSelector() as readable:
            readable.register(process.stdout, selectors.EVENT_READ)
            require(readable.select(timeout=7), f"PROBE_{case.upper()}_NO_RESULT")
            line = process.stdout.readline(4097)
        require(line.endswith(b"\n") and len(line) <= 4096, f"PROBE_{case.upper()}_NO_RESULT")
        result = json.loads(line)
        require(result.get("case") == case, "CASE_MISMATCH")
        # Child disappearance must be observed while the actual caller remains
        # alive, not explained by its later PDEATHSIG/process-exit cleanup.
        require(process.poll() is None, "CALLER_EXITED_BEFORE_CLEANUP_OBSERVATION")
        if held:
            remaining = identity(held["pid"])
            require(remaining is None or remaining["start"] != held["start"],
                    "OWNED_NATIVE_WORKER_NOT_REAPED")
            result["native_worker_stopped"] = True
            result["native_worker_reaped"] = True
        process.stdin.write(b"\x01")
        process.stdin.flush()
        stdout, stderr = process.communicate(timeout=2)
        require(not stdout and len(stderr) <= 4096, "PROBE_OUTPUT_BOUND")
        result["probe_exit_code"] = process.returncode
        if process.returncode != 0:
            result["case_passed"] = False
            result["fixture_error"] = f"PROBE_{case.upper()}_FAILED"
        completed = True
        return result
    finally:
        # Exceptional fixture cleanup is not counted as production cleanup proof.
        if not completed and handle is not None:
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if handle is not None:
            os.close(handle)


def diagnostic_cases(cases):
    return [case for case in DIAGNOSTIC_NAMES if cases.get(case, {}).get("case_passed") is False
            and cases[case].get("error") == "Unavailable"]


def native_reply_length(header, name, nonce):
    """Diagnostic decoding only, not DNSSEC validation or usable answer authority."""
    require(len(header) == 44 and header[:8] == NATIVE_MAGIC
            and header[16:32] == nonce and header[32:36] == b"\0" * 4
            and struct.unpack("!H", header[40:42])[0] == 1
            and struct.unpack("!H", header[42:44])[0] == len(name), "NATIVE_FRAME_SCOPE")
    status, secure = header[8:10]
    count = struct.unpack("!H", header[10:12])[0]
    ttl = struct.unpack("!I", header[12:16])[0]
    packet_bytes = struct.unpack("!I", header[36:40])[0]
    require(status <= 4 and secure <= 1 and count <= 16 and packet_bytes <= 4096,
            "NATIVE_FRAME_BOUNDS")
    if status == 0:
        require(count > 0 and ttl > 0, "NATIVE_FRAME_POSITIVE")
    else:
        require(secure == count == ttl == packet_bytes == 0, "NATIVE_FRAME_ERROR_FIELDS")
    return 44 + len(name) + count * 4 + packet_bytes


def native_reply_summary(frame, name, nonce):
    require(44 <= len(frame) <= NATIVE_MAX_REPLY, "NATIVE_FRAME_BOUNDS")
    require(native_reply_length(frame[:44], name, nonce) == len(frame)
            and frame[44:44 + len(name)] == name, "NATIVE_FRAME_BINDING")
    return dict(native_status=("positive", "unavailable", "nxdomain", "nodata", "bogus")[frame[8]],
                native_secure_flag=bool(frame[9]), address_count=struct.unpack("!H", frame[10:12])[0],
                ttl_seconds=struct.unpack("!I", frame[12:16])[0],
                raw_packet_bytes=struct.unpack("!I", frame[36:40])[0])


def run_native_diagnostic(case):
    """One fresh native context, only after the ordinary case failed Unavailable.

    This extra guest-only observation never changes the normal 5s caller/500ms
    cleanup bounds, validates no DNSSEC proof and cannot make acceptance pass.
    """
    require(case in DIAGNOSTIC_NAMES, "NATIVE_DIAGNOSTIC_CASE")
    name, nonce = DIAGNOSTIC_NAMES[case], os.urandom(16)
    request = NATIVE_MAGIC + struct.pack("!HHI", 1, len(name), 0) + nonce + name
    account = pwd.getpwnam("vpci")
    result = dict(case=case, acceptance_evidence=False, independent_dnssec_proof=False,
                  max_seconds=30, native_worker_reaped=False, reply_complete=False,
                  outcome="process_error")
    started = time.monotonic()
    deadline = started + 30
    process = None
    try:
        process = subprocess.Popen([str(WORKER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, user=account.pw_uid, group=account.pw_gid,
                                   extra_groups=[], env={}, close_fds=True)
        process.stdin.write(request)
        process.stdin.close()
        frame = bytearray()
        with selectors.DefaultSelector() as readable:
            readable.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not readable.select(timeout=remaining):
                    result["outcome"] = "timeout_after_reply" if result["reply_complete"] else "no_result_timeout"
                    break
                chunk = os.read(process.stdout.fileno(), NATIVE_MAX_REPLY + 1 - len(frame))
                if not chunk:
                    if not result["reply_complete"]:
                        result["outcome"] = "early_eof"
                        break
                    process.wait(timeout=max(.001, deadline - time.monotonic()))
                    result["outcome"] = "native_reply" if process.returncode == 0 else "process_error"
                    break
                frame.extend(chunk)
                require(len(frame) <= NATIVE_MAX_REPLY, "NATIVE_FRAME_BOUNDS")
                if len(frame) >= 44:
                    length = native_reply_length(frame[:44], name, nonce)
                    require(len(frame) <= length, "NATIVE_FRAME_TRAILING")
                    if len(frame) == length:
                        result.update(native_reply_summary(frame, name, nonce), reply_complete=True,
                                      primary_reply_elapsed_ms=round((time.monotonic() - started) * 1000))
    except RuntimeError:
        result["outcome"] = "protocol_error"
    except subprocess.TimeoutExpired:
        result["outcome"] = "timeout_after_reply" if result["reply_complete"] else "no_result_timeout"
    except (OSError, ValueError, subprocess.SubprocessError):
        result["outcome"] = "process_error"
    finally:
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
                result["native_worker_reaped"] = True
                result["native_exit_code"] = process.returncode
            except subprocess.TimeoutExpired:
                result["outcome"] = "cleanup_unconfirmed"
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    pipe.close()
    return result


def validate(report, revision):
    require(report.get("schema") == 2 and report.get("source_revision") == revision,
            "REPORT_REVISION")
    require(report.get("success") is True and report.get("failure") is None, "PROOF_FAILED")
    require(report.get("report_kind") == "private-unbound-public-adapter"
            and report.get("native_package_version") == "1.26.1-0+deb13u1", "NATIVE_PROVENANCE")
    for label in ("worker_sha256", "root_key_sha256", "root_hints_sha256"):
        digest = report.get(label, "")
        require(isinstance(digest, str) and len(digest) == 64
                and all(char in "0123456789abcdef" for char in digest), "PROVENANCE_DIGEST")
    require(report.get("normal_client_route_proven") is False
            and report.get("reciprocal_client_exit_proven") is False
            and report.get("shared_dns_proof_proven") is False, "SCOPE_OVERCLAIM")
    cases = report.get("cases", {})
    require(set(cases) == set(CASES), "CASES_MISSING")
    for case in CASES:
        require(cases[case].get("os_sentinel") is True
                and cases[case].get("case") == case, "OS_SENTINEL_MISSING")
        require(cases[case].get("case_passed") is True
                and cases[case].get("probe_exit_code") == 0, "ACTUAL_CASE_FAILED")
    for case, secure in (("signed", True), ("unsigned", False)):
        result = cases[case]
        require(result.get("verdict") == "positive" and result.get("dnssec_secure") is secure
                and result.get("ttl_seconds", 0) > 0 and result.get("address_count", 0) > 0
                and result.get("shareable_proof") is secure, "NATIVE_VERDICT_MISSING")
    signed = cases["signed"]
    require(signed.get("source") == "independently_validated"
            and signed.get("local_cache_reuse") is True
            and signed.get("cache_ttl_not_extended") is True
            and signed.get("proof_policy_bound") is True
            and report.get("native_cache_linkage_proven") is True, "NATIVE_CACHE_LINKAGE_MISSING")
    require(cases["unsigned"].get("source") == "private_unbound", "UNSIGNED_SOURCE_CHANGED")
    require(cases["bogus"].get("verdict") == "bogus", "BOGUS_NOT_REJECTED")
    for case in ("timeout", "cancel"):
        require(cases[case].get("native_worker_stopped") is True
                and cases[case].get("native_worker_reaped") is True, "CHILD_CLEANUP_MISSING")
    require(cases["timeout"].get("verdict") == "unavailable"
            and cases["timeout"].get("elapsed_ms", 10_000) <= 5_500
            and cases["cancel"].get("verdict") == "cancelled", "DEADLINE_RESULT")
    require(report.get("guest_hosts_unchanged") is True, "HOSTS_CHANGED")


def execute(probe, output, revision):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha", "GUEST_ONLY")
    require(subprocess.check_output(["systemd-detect-virt"]).strip() == b"kvm", "KVM_ONLY")
    require(os.readlink("/proc/self/ns/mnt") !=
            os.environ.get("VOLPAROSSA_PRIVATE_DNS_PARENT_MNTNS"), "PRIVATE_MOUNT_REQUIRED")
    require(probe == Path("/home/vpci/target/debug/examples/private-unbound-proof")
            and probe.is_file() and len(revision) == 40
            and all(char in "0123456789abcdef" for char in revision), "FIXED_PROBE_REQUIRED")
    report = {"schema": 2, "source_revision": revision, "success": False,
              "report_kind": "private-unbound-public-adapter",
              "native_package_version": subprocess.check_output(
                  ["dpkg-query", "-W", "-f=${Version}", "libunbound8"]).decode().strip(),
              "normal_client_route_proven": False, "reciprocal_client_exit_proven": False,
              "shared_dns_proof_proven": False, "native_cache_linkage_proven": False,
              "cases": {}, "failure": None}
    for label, path in (("worker", WORKER), ("root_key", Path("/usr/share/dns/root.key")),
                        ("root_hints", Path("/usr/share/dns/root.hints"))):
        report[label + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    original_hosts = hashlib.sha256(Path("/etc/hosts").read_bytes()).hexdigest()
    mounted = False
    try:
        with tempfile.TemporaryDirectory(prefix="volparossa-dns-proof-", dir="/run") as temporary:
            sentinel = Path(temporary) / "hosts"
            sentinel.write_text("127.0.0.1 localhost\n"
                                "93.184.216.34 iana.org neverssl.com dnssec-failed.org\n")
            sentinel.chmod(0o644)
            subprocess.run(["mount", "--bind", str(sentinel), "/etc/hosts"], check=True)
            mounted = True
            for case in CASES:
                started = time.monotonic()
                try:
                    result = run_case(probe, case)
                except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
                    result = {"case": case, "case_passed": False,
                              "elapsed_ms": round((time.monotonic() - started) * 1000),
                              "fixture_error": str(error) if isinstance(error, RuntimeError)
                              else type(error).__name__}
                report["cases"][case] = result
                if result.get("case_passed") is not True and report["failure"] is None:
                    report["failure"] = result.get("fixture_error", f"PROBE_{case.upper()}_UNEXPECTED_RESULT")
            report["native_cache_linkage_proven"] = report["cases"]["signed"].get("case_passed") is True
            # Run after every unchanged ordinary case so these separate cold
            # contexts cannot warm or replace any acceptance observation.
            selected = diagnostic_cases(report["cases"])
            if selected:
                report["diagnostics"] = dict(acceptance_evidence=False,
                    scope="fixed-question native primary timing only; no production deadline or proof substitution",
                    cases={case: run_native_diagnostic(case) for case in selected})
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        # Fixed fixture errors only; no worker stderr or question output is retained.
        report["failure"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        if mounted:
            subprocess.run(["umount", "/etc/hosts"], check=True)
        report["guest_hosts_unchanged"] = (
            original_hosts == hashlib.sha256(Path("/etc/hosts").read_bytes()).hexdigest())
        report["success"] = report["failure"] is None
        try:
            validate(report, revision)
        except RuntimeError as error:
            report["success"] = False
            if report["failure"] is None:
                report["failure"] = str(error)
        output.write_text(json.dumps(report, indent=2) + "\n")
    validate(report, revision)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    run = subparsers.add_parser("execute")
    run.add_argument("probe", type=Path)
    run.add_argument("output", type=Path)
    run.add_argument("revision")
    check = subparsers.add_parser("report")
    check.add_argument("output", type=Path)
    check.add_argument("revision")
    args = parser.parse_args()
    if args.action == "execute":
        execute(args.probe, args.output, args.revision)
    else:
        validate(json.loads(args.output.read_text()), args.revision)


if __name__ == "__main__":
    main()
