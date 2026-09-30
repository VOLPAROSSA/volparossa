#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Optional real package-lifecycle extension; execution is disposable Debian KVM only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import tempfile
import time

AGENT = "volparossa-agent.service"
WORKER = Path("/usr/libexec/volparossa-dns-worker")
CONFIG = Path("/etc/volparossa/config.yaml")
UNIT = Path("/usr/lib/systemd/system/volparossa-agent.service")
PROBE_UNIT = "volparossa-private-dns-package-probe.service"
DEVIATIONS = ["source-built resolver example replaces agent ExecStart",
              "probe executable staged in a root-owned temporary /usr/libexec directory", "Type=oneshot",
              "Restart=no", "no helper/native Wants", "synthetic hosts bind read-only",
              "fixed observer ACK on stdin; bounded synthetic result on stdout",
              "bounded startup stderr classified before owned temporary cleanup",
              "no full agent DNS-query claim"]
PROBE_OUTPUT_BOUND = 16384


def require(value, code):
    if not value:
        raise RuntimeError(code)


def run(*args, check=True, **kwargs):
    return subprocess.run(args, check=check, capture_output=True, timeout=40, **kwargs)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def property_value(unit, key):
    return run("systemctl", "show", unit, "--property=" + key, "--value").stdout.decode().strip()


def parse_roles(data):
    require(len(data) <= 256, "ROLE_STATUS_BOUND")
    lines = data.decode().splitlines()
    require(len(lines) == 3, "ROLE_STATUS_SHAPE")
    result = {}
    for line in lines:
        match = re.fullmatch(r"(client|relay|exit): (true|false)", line)
        require(match is not None and match[1] not in result, "ROLE_STATUS_SHAPE")
        result[match[1]] = match[2] == "true"
    return result


def role_status():
    return parse_roles(run("/usr/bin/volparossa", "role", "show").stdout)


def wait_roles_off():
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            roles = role_status()
            if all(roles.get(role) is False for role in ("client", "relay", "exit")):
                return
        except (subprocess.SubprocessError, OSError, ValueError):
            pass
        time.sleep(.1)
    raise RuntimeError("PACKAGED_ROLES_OFF_NOT_READY")


def exit_config(original):
    changes = {"  operator_id: null": "  operator_id: private-dns-package-fixture",
               "  advertised_asn: 0": "  advertised_asn: 64512",
               "  advertised_ipv4_prefix: null": '  advertised_ipv4_prefix: "44.12.34.0/24"',
               "  exit: false": "  exit: true",
               "  exit_upload_limit_mbps: 0": "  exit_upload_limit_mbps: 10",
               "  exit_download_limit_mbps: 0": "  exit_download_limit_mbps: 10",
               "  maximum_exit_sessions: 0": "  maximum_exit_sessions: 1"}
    text = original.decode()
    for before, after in changes.items():
        require(text.splitlines().count(before) == 1, "EXIT_FIXTURE_CONFIG_SHAPE")
        text = text.replace(before + "\n", after + "\n")
    return text.encode()


def missing_assets_start():
    original = CONFIG.read_bytes()
    directory = Path("/run/systemd/system/volparossa-agent.service.d")
    dropin = directory / "90-private-dns-package-proof.conf"
    require(not directory.exists() and not directory.is_symlink(), "EXISTING_AGENT_DROPIN")
    directory.mkdir(mode=0o755)
    try:
        run("systemctl", "stop", AGENT)
        dropin.write_text("[Service]\nRestart=no\nInaccessiblePaths=/usr/libexec/volparossa-dns-worker\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "start", AGENT)
        wait_roles_off()
        # This is the installed production config with only explicit fixture Exit
        # prerequisites; no development policy keys or network participation occur.
        run("systemctl", "stop", AGENT)
        CONFIG.write_bytes(exit_config(original))
        run("runuser", "-u", "volparossa", "--", "/usr/bin/volparossa", "config", "validate")
        run("systemctl", "start", AGENT, check=False)
        invocation = property_value(AGENT, "InvocationID")
        require(re.fullmatch(r"[0-9a-f]{32}", invocation) is not None
                and invocation != "0" * 32, "AGENT_INVOCATION_MISSING")
        deadline = time.monotonic() + 15
        while property_value(AGENT, "ActiveState") not in ("failed", "inactive"):
            require(time.monotonic() < deadline, "MISSING_WORKER_EXIT_NOT_REJECTED")
            time.sleep(.1)
        require(property_value(AGENT, "ExecMainStatus") == "1", "WRONG_EXIT_START_FAILURE")
        entries = run("journalctl", "--no-pager", "-o", "json", "-n", "32",
                      "_SYSTEMD_INVOCATION_ID=" + invocation).stdout
        require(len(entries) <= 131072, "JOURNAL_BOUND")
        codes = []
        for line in entries.splitlines():
            message = json.loads(line).get("MESSAGE", "")
            try:
                codes.append(json.loads(message).get("fields", {}).get("diagnostic_code"))
            except (ValueError, TypeError):
                pass
        require("DNS_PRIVATE_WORKER_UNAVAILABLE" in codes, "WRONG_MISSING_ASSET_DIAGNOSTIC")
        return dict(roles_off_without_worker_started=True, effective_exit_without_worker_rejected=True,
                    diagnostic_code="DNS_PRIVATE_WORKER_UNAVAILABLE", actual_packaged_agent=True,
                    worker_hidden_only_in_agent_mount=True)
    finally:
        run("systemctl", "stop", AGENT, check=False)
        CONFIG.write_bytes(original)
        if dropin.exists():
            dropin.unlink()
        directory.rmdir()
        run("systemctl", "daemon-reload")
        run("systemctl", "reset-failed", AGENT, check=False)
        run("systemctl", "start", AGENT)
        wait_roles_off()


def probe_unit(source, directory, executable, marker, parent):
    result = []
    for line in source.splitlines():
        if line.startswith("Wants="):
            continue
        if line.startswith("Description="):
            line = "Description=" + marker
        elif line == "Type=simple":
            line = "Type=oneshot"
        elif line.startswith("ExecStart="):
            line = f"ExecStart={executable} signed"
        elif line.startswith("Restart="):
            line = "Restart=no"
        elif line == "[Install]":
            result += [f"Environment=VOLPAROSSA_PRIVATE_DNS_PARENT_MNTNS={parent}",
                       f"BindReadOnlyPaths={directory}/hosts:/etc/hosts",
                       f"StandardInput=file:{directory}/ack", f"StandardOutput=file:{directory}/result",
                       f"StandardError=file:{directory}/stderr", ""]
            break
        result.append(line)
    return "\n".join(result) + "\n"


def executable_preflight(source, executable, runtime, diagnostics):
    # /run is for data, not an executable location. Keep its mount flag as
    # diagnostic evidence without assuming that it explains older 203/EXEC runs.
    # Both paths are fixed-parent, probe-owned guest temporary directories.
    diagnostics.update(
        executable_mount_noexec=bool(os.statvfs(executable).f_flag & os.ST_NOEXEC),
        runtime_mount_noexec=bool(os.statvfs(runtime).f_flag & os.ST_NOEXEC),
        executable_source_bound=digest(executable) == digest(source),
        executable_readable_by_agent=run("runuser", "-u", "volparossa", "--", "/usr/bin/test",
                                        "-r", str(executable), check=False).returncode == 0,
        executable_traversable_by_agent=run("runuser", "-u", "volparossa", "--", "/usr/bin/test",
                                           "-x", str(executable), check=False).returncode == 0,
    )
    require(not diagnostics["executable_mount_noexec"] and diagnostics["executable_source_bound"]
            and diagnostics["executable_readable_by_agent"]
            and diagnostics["executable_traversable_by_agent"], "PROBE_EXECUTABLE_PREFLIGHT_FAILED")


def process_identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return (pid, int(fields[19]), int(fields[1]))
    except FileNotFoundError:
        return None


def unit_diagnostics(data):
    """Keep fixed manager result categories and numeric status, never journal text."""
    require(len(data) <= 4096, "SANDBOX_STATUS_BOUND")
    fields = {}
    for line in data.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        require(separator and key in ("Result", "ExecMainCode", "ExecMainStatus", "ActiveState")
                and key not in fields, "SANDBOX_STATUS_SHAPE")
        fields[key] = value
    require(set(fields) == {"Result", "ExecMainCode", "ExecMainStatus", "ActiveState"}, "SANDBOX_STATUS_SHAPE")
    for key in ("ExecMainCode", "ExecMainStatus"):
        require(re.fullmatch(r"[0-9]{1,3}", fields[key]) is not None
                and 0 <= int(fields[key]) <= 255, "SANDBOX_STATUS_SHAPE")
    result = fields["Result"]
    state = fields["ActiveState"]
    return dict(available=True, exec_main_code=int(fields["ExecMainCode"]),
                exec_main_status=int(fields["ExecMainStatus"]),
                result=result if result in ("success", "exit-code", "signal", "core-dump", "timeout",
                    "start-limit-hit", "resources", "protocol", "watchdog", "oom-kill", "exec-condition") else "other",
                active_state=state if state in ("active", "inactive", "failed", "activating",
                    "deactivating", "reloading", "maintenance", "refreshing") else "other")


def stderr_diagnostics(data):
    """The example uses fixed guard errors; unknown content is never copied into the report."""
    if len(data) > PROBE_OUTPUT_BOUND:
        return dict(present=True, category="OUTPUT_BOUND", bounded=False)
    categories = (
        (b"explicit disposable mount namespace required", "PARENT_NAMESPACE_MARKER_MISSING"),
        (b"disposable guest or private resolver assets unavailable", "DISPOSABLE_OR_ASSETS_GUARD"),
        (b"isolated OS-positive fallback sentinel missing", "OS_SENTINEL_GUARD"),
        (b"observer did not confirm the live caller cleanup boundary", "OBSERVER_ACK_REJECTED"),
        (b"failed to fill whole buffer", "OBSERVER_ACK_EOF"),
        (b"Permission denied", "PERMISSION_DENIED"),
        (b"Operation not permitted", "OPERATION_NOT_PERMITTED"),
        (b"error while loading shared libraries", "DYNAMIC_LOADER"),
        (b"No such file or directory", "FILE_NOT_FOUND"),
    )
    category = next((code for marker, code in categories if marker in data),
                    "UNCLASSIFIED" if data else "EMPTY")
    return dict(present=bool(data), bytes=len(data), bounded=True, category=category)


def result_diagnostics(data):
    if len(data) > PROBE_OUTPUT_BOUND:
        return dict(present=True, category="OUTPUT_BOUND", bounded=False)
    if not data:
        return dict(present=False, category="EMPTY", bounded=True)
    try:
        result = json.loads(data)
    except (ValueError, UnicodeError):
        return dict(present=True, category="INVALID_JSON", bounded=True)
    if not isinstance(result, dict) or result.get("case") != "signed":
        return dict(present=True, category="INVALID_CASE", bounded=True)
    kept = dict(present=True, category="SIGNED_RESULT", bounded=True)
    for key in ("case_passed", "dnssec_secure", "os_sentinel", "shareable_proof", "local_cache_reuse",
                "cache_ttl_not_extended", "proof_policy_bound"):
        if type(result.get(key)) is bool:
            kept[key] = result[key]
    for key, maximum in (("elapsed_ms", 35000), ("ttl_seconds", 2**32 - 1), ("address_count", 256)):
        if type(result.get(key)) is int and 0 <= result[key] <= maximum:
            kept[key] = result[key]
    for key, allowed in (
        ("source", ("independently_validated", "private_unbound", "unexpected_source")),
        ("verdict", ("positive", "unavailable", "bogus", "error")),
        ("error", ("InvalidQuestion", "InvalidScope", "InvalidProof", "Unavailable", "NameNotFound",
                   "NoData", "Bogus", "CleanupUnconfirmed")),
    ):
        if result.get(key) in allowed:
            kept[key] = result[key]
    return kept


def retain_sandbox_diagnostics(directory, observed, started_at, diagnostics):
    # Run before systemctl stop/reset and before TemporaryDirectory deletes the raw files.
    diagnostics.update(worker_observed=observed is not None,
                       elapsed_ms=min(120000, max(0, round((time.monotonic() - started_at) * 1000))))
    try:
        data = run("systemctl", "show", PROBE_UNIT,
                   "--property=Result,ExecMainCode,ExecMainStatus,ActiveState").stdout
        diagnostics["manager"] = unit_diagnostics(data)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        diagnostics["manager"] = dict(available=False, category="STATUS_UNAVAILABLE")
    for name, classify in (("result", result_diagnostics), ("stderr", stderr_diagnostics)):
        try:
            file = directory / name
            require(not file.is_symlink() and file.is_file(), "OUTPUT_NOT_REGULAR")
            with file.open("rb") as source:
                diagnostics[name] = classify(source.read(PROBE_OUTPUT_BOUND + 1))
        except (RuntimeError, OSError, ValueError):
            diagnostics[name] = dict(present=False, category="OUTPUT_UNAVAILABLE")


def sandbox_probe(probe, diagnostics):
    account = pwd.getpwnam("volparossa")
    target = Path("/run/systemd/system") / PROBE_UNIT
    require(not target.exists() and not target.is_symlink(), "EXISTING_PROBE_UNIT")
    marker = "volparossa-private-dns-" + os.urandom(16).hex()
    observed = None
    started = False
    started_at = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="private-dns-package-", dir="/run/volparossa") as temporary, \
            tempfile.TemporaryDirectory(prefix="volparossa-private-dns-probe-", dir="/usr/libexec") as staged:
        directory = Path(temporary)
        executable_directory = Path(staged)
        os.chown(directory, 0, account.pw_gid)
        directory.chmod(0o750)
        os.chown(executable_directory, 0, account.pw_gid)
        executable_directory.chmod(0o750)
        executable = executable_directory / "probe"
        shutil.copyfile(probe, executable)
        executable.chmod(0o755)
        executable_preflight(probe, executable, directory, diagnostics)
        (directory / "ack").write_bytes(b"\1")
        (directory / "hosts").write_text("127.0.0.1 localhost\n93.184.216.34 iana.org\n")
        for name in ("ack", "hosts"):
            (directory / name).chmod(0o644)
        definition = probe_unit(UNIT.read_text(), directory, executable, marker, os.readlink("/proc/self/ns/mnt"))
        target.write_text(definition)
        try:
            run("systemctl", "daemon-reload")
            pending = subprocess.Popen(["systemctl", "start", PROBE_UNIT],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            started = True
            deadline = time.monotonic() + 35
            try:
                while pending.poll() is None:
                    require(time.monotonic() < deadline, "SANDBOX_PROBE_TIMEOUT")
                    parent = property_value(PROBE_UNIT, "MainPID")
                    if parent.isdecimal() and int(parent):
                        for task in Path(f"/proc/{parent}/task").glob("*"):
                            try:
                                children = (task / "children").read_text().split()
                                for child in children:
                                    if Path(f"/proc/{child}/exe").readlink() != WORKER:
                                        continue
                                    identity = process_identity(int(child))
                                    uid_line = next(line for line in Path(f"/proc/{child}/status").read_text().splitlines()
                                                    if line.startswith("Uid:"))
                                    require(set(map(int, uid_line.split()[1:])) == {account.pw_uid}
                                            and identity is not None and identity[2] == int(parent),
                                            "SANDBOX_WORKER_IDENTITY")
                                    observed = identity
                            except FileNotFoundError:
                                continue
                    time.sleep(.01)
                require(pending.returncode == 0 and property_value(PROBE_UNIT, "ExecMainStatus") == "0",
                        "SANDBOX_PROBE_FAILED")
            finally:
                if pending.poll() is None:
                    pending.kill()
                pending.wait(timeout=5)
                diagnostics["start_command_status"] = pending.returncode
            require(observed is not None, "SANDBOX_WORKER_NOT_OBSERVED_REAPED")
            remaining = process_identity(observed[0])
            require(remaining is None or remaining[:2] != observed[:2], "SANDBOX_WORKER_NOT_REAPED")
            result = directory / "result"
            require(result.stat().st_size <= 16384, "SANDBOX_RESULT_BOUND")
            reply = json.loads(result.read_bytes())
            require(reply.get("case_passed") is True and reply.get("case") == "signed"
                    and reply.get("source") == "independently_validated"
                    and reply.get("shareable_proof") is True and reply.get("local_cache_reuse") is True,
                    "SANDBOX_REAL_DNS_PROOF_FAILED")
            return dict(native_worker_observed=True, worker_same_agent_uid=True, worker_reaped=True,
                        independent_dnssec_proof=True, local_cache_reuse=True,
                        full_agent_dns_query=False, deviations=DEVIATIONS)
        finally:
            retain_sandbox_diagnostics(directory, observed, started_at, diagnostics)
            if started:
                require(property_value(PROBE_UNIT, "Description") == marker, "PROBE_UNIT_OWNER_CHANGED")
                run("systemctl", "stop", PROBE_UNIT)
                require(property_value(PROBE_UNIT, "MainPID") == "0", "PROBE_UNIT_NOT_STOPPED")
                run("systemctl", "reset-failed", PROBE_UNIT, check=False)
            require(target.read_text() == definition, "PROBE_UNIT_FILE_CHANGED")
            target.unlink()
            run("systemctl", "daemon-reload")


def validate(report, revision):
    require(report.get("schema") == 1 and report.get("source_revision") == revision,
            "PACKAGE_PROOF_REVISION")
    require(report.get("success") is True and report.get("failure") is None, "PACKAGE_PROOF_FAILED")
    require(report.get("report_kind") == "private-unbound-package"
            and report.get("build_profile") == "development-staged"
            and report.get("release_build_proven") is False, "PACKAGE_BUILD_SCOPE")
    for key in ("core_sha256", "companion_sha256", "worker_sha256", "agent_unit_sha256", "probe_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", report.get(key, "")) is not None, "PACKAGE_PROVENANCE")
    require(report.get("source_binary_binding") is True and report.get("default_private_roles_off") is True
            and report.get("mandatory_companion_no_cycle") is True
            and report.get("installed_units_unchanged") is True
            and report.get("fixture_config_restored") is True, "PACKAGE_CONFIGURATION")
    startup = report.get("startup", {})
    require(all(startup.get(key) is True for key in ("roles_off_without_worker_started",
            "effective_exit_without_worker_rejected", "actual_packaged_agent", "worker_hidden_only_in_agent_mount"))
            and startup.get("diagnostic_code") == "DNS_PRIVATE_WORKER_UNAVAILABLE", "PACKAGE_STARTUP")
    sandbox = report.get("sandbox", {})
    require(all(sandbox.get(key) is True for key in ("native_worker_observed", "worker_same_agent_uid",
            "worker_reaped", "independent_dnssec_proof", "local_cache_reuse"))
            and sandbox.get("full_agent_dns_query") is False and sandbox.get("deviations") == DEVIATIONS,
            "PACKAGE_SANDBOX_SCOPE")


def execute(probe, package, output, revision):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha"
            and run("systemd-detect-virt").stdout.strip() == b"kvm", "DISPOSABLE_GUEST_ONLY")
    require(probe == Path("/home/vpci/target/debug/examples/private-unbound-proof")
            and re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "FIXED_SOURCE_PROBE")
    report = dict(schema=1, report_kind="private-unbound-package", source_revision=revision,
                  build_profile="development-staged", release_build_proven=False,
                  success=False, failure=None)
    original, original_unit = CONFIG.read_bytes(), UNIT.read_bytes()
    try:
        metadata = json.loads(Path("/usr/share/doc/volparossa/development-build.json").read_bytes())
        require(metadata.get("source_revision") == revision
                and metadata.get("build_profile") == "development-staged", "BUILD_BINDING_MISSING")
        for label, installed, built in (
            ("cli", "/usr/bin/volparossa", "/home/vpci/target/debug/volparossa"),
            ("agent", "/usr/bin/volparossa-agent", "/home/vpci/target/debug/volparossa-agent"),
            ("helper", "/usr/libexec/volparossa/volparossa-helper", "/home/vpci/target/debug/volparossa-helper"),
            ("native", "/usr/libexec/volparossa/volparossa-mpquic", "/home/vpci/volparossa-mpquic")):
            require(digest(installed) == digest(built) == metadata["binaries"][label], "BINARY_BINDING_CHANGED")
        version = run("dpkg-deb", "-f", str(package), "Version").stdout.decode().strip()
        companion = Path(f"/home/vpci/source/dist/volparossa-private-dns-worker_{version}_amd64.deb")
        require(run("dpkg-query", "-W", "-f=${Version}", "volparossa-private-dns-worker").stdout.decode() == version,
                "COMPANION_NOT_INSTALLED")
        dependencies = run("dpkg-deb", "-f", str(package), "Depends").stdout.decode()
        worker_deps = run("dpkg-deb", "-f", str(companion), "Depends").stdout.decode().strip()
        require(f"volparossa-private-dns-worker (= {version})" in dependencies
                and worker_deps == "libunbound8 (>= 1.26.1), dns-root-data", "DEPENDENCY_GRAPH")
        require(digest(WORKER) == digest("/home/vpci/source/native/volparossa-dns-worker/build/volparossa-dns-worker"),
                "WORKER_SOURCE_BUILD_BINDING")
        text = original.decode()
        require(re.search(r"roles:\n  client: false\n  relay: false\n  exit: false\n", text)
                and "    mode: unbound_private\n" in text, "PACKAGED_DEFAULT_NOT_PRIVATE_INERT")
        wait_roles_off()
        report.update(source_binary_binding=True, default_private_roles_off=True,
                      mandatory_companion_no_cycle=True, core_sha256=digest(package),
                      companion_sha256=digest(companion), worker_sha256=digest(WORKER),
                      agent_unit_sha256=digest(UNIT), probe_sha256=digest(probe))
        report["startup"] = missing_assets_start()
        report["sandbox_diagnostics"] = {}
        report["sandbox"] = sandbox_probe(probe, report["sandbox_diagnostics"])
        report["installed_units_unchanged"] = UNIT.read_bytes() == original_unit
        report["fixture_config_restored"] = CONFIG.read_bytes() == original
        report["success"] = True
        validate(report, revision)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        report["success"] = False
        report["failure"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        for field, path, before in (("installed_units_unchanged", UNIT, original_unit),
                                    ("fixture_config_restored", CONFIG, original)):
            try:
                report[field] = path.read_bytes() == before
            except OSError:
                report[field] = False
        output.write_text(json.dumps(report, indent=2) + "\n")
    validate(report, revision)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    command = sub.add_parser("execute")
    for name in ("probe", "package", "output"):
        command.add_argument(name, type=Path)
    command.add_argument("revision")
    command = sub.add_parser("report")
    command.add_argument("path", type=Path)
    command.add_argument("revision")
    args = parser.parse_args()
    if args.operation == "execute":
        execute(args.probe, args.package, args.output, args.revision)
    else:
        validate(json.loads(args.path.read_bytes()), args.revision)
