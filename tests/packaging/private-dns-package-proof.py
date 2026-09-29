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
DEVIATIONS = ["source-built resolver example replaces agent ExecStart", "Type=oneshot",
              "Restart=no", "no helper/native Wants", "synthetic hosts bind read-only",
              "fixed observer ACK on stdin; bounded synthetic result on stdout",
              "no full agent DNS-query claim"]


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


def probe_unit(source, directory, marker, parent):
    result = []
    for line in source.splitlines():
        if line.startswith("Wants="):
            continue
        if line.startswith("Description="):
            line = "Description=" + marker
        elif line == "Type=simple":
            line = "Type=oneshot"
        elif line.startswith("ExecStart="):
            line = f"ExecStart={directory}/probe signed"
        elif line.startswith("Restart="):
            line = "Restart=no"
        elif line == "[Install]":
            result += [f"Environment=VOLPAROSSA_PRIVATE_DNS_PARENT_MNTNS={parent}",
                       f"BindReadOnlyPaths={directory}/hosts:/etc/hosts",
                       f"StandardInput=file:{directory}/ack", f"StandardOutput=file:{directory}/result",
                       "StandardError=null", ""]
            break
        result.append(line)
    return "\n".join(result) + "\n"


def process_identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return (pid, int(fields[19]), int(fields[1]))
    except FileNotFoundError:
        return None


def sandbox_probe(probe):
    account = pwd.getpwnam("volparossa")
    target = Path("/run/systemd/system") / PROBE_UNIT
    require(not target.exists() and not target.is_symlink(), "EXISTING_PROBE_UNIT")
    marker = "volparossa-private-dns-" + os.urandom(16).hex()
    observed = None
    started = False
    with tempfile.TemporaryDirectory(prefix="private-dns-package-", dir="/run/volparossa") as temporary:
        directory = Path(temporary)
        os.chown(directory, 0, account.pw_gid)
        directory.chmod(0o750)
        shutil.copyfile(probe, directory / "probe")
        (directory / "probe").chmod(0o755)
        (directory / "ack").write_bytes(b"\1")
        (directory / "hosts").write_text("127.0.0.1 localhost\n93.184.216.34 iana.org\n")
        for name in ("ack", "hosts"):
            (directory / name).chmod(0o644)
        definition = probe_unit(UNIT.read_text(), directory, marker, os.readlink("/proc/self/ns/mnt"))
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
        report["sandbox"] = sandbox_probe(probe)
        report["installed_units_unchanged"] = UNIT.read_bytes() == original_unit
        report["fixture_config_restored"] = CONFIG.read_bytes() == original
        report["success"] = True
        validate(report, revision)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        report["success"] = False
        report["failure"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
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
