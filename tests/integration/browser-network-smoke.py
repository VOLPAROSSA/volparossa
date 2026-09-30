#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable real Gecko/gateway/MPTCP proof; no direct fallback or full-browser claim."""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import socket
import ssl
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
MPTCP = runpy.run_path(str(HERE / "mptcp-growth-smoke.py"))
COMMON = MPTCP["COMMON"]
read, require, command = MPTCP["read"], MPTCP["require"], MPTCP["command"]
PREFIX = "browser-network"
BODY_BYTES = 32 * 1024 * 1024
HOST = "destination.volparossa.test"
PORT = 18443
ROLES = ("client", "relay0", "relay1", "relay2", "exit")
PHASES = ("first", "second")
EXPORT_NAMES = (
    f"{PREFIX}-smoke.json", f"{PREFIX}-evidence.json", f"{PREFIX}-provision.json",
    f"{PREFIX}-browser.json", f"{PREFIX}-origin.json", f"{PREFIX}-isolation.json",
    f"{PREFIX}-driver.json",
    f"{PREFIX}-detach.json", f"{PREFIX}-private-cleanup.json",
    *(f"{PREFIX}-{phase}-{part}.json" for phase in PHASES for part in ("baseline", "progress")),
    *(f"{PREFIX}-{phase}-privacy-{role}.json" for phase in PHASES for role in ROLES),
)
DRIVER_PHASES = frozenset((
    "wrapper-start", "runtime-validation", "isolated-home", "wrapper-launch", "child-validation",
    "grant-validation", "profile-init", "browser-start", "marionette-connect", "marionette-session",
    "script-start", "import", "attach-a", "attach-b", "wrong-scope", "request-a", "request-b",
    "detach-a", "finish-b", "result-validation", "browser-stop", "complete",
))
DRIVER_ERRORS = frozenset((
    "OS_ERROR", "CHECK_FAILED", "SUBPROCESS_FAILED", "RUNTIME_FAILED", "SCRIPT_FAILED",
    "invalid_contract", "invalid_scope", "scope_unavailable", "invalid_channel",
    "unsupported_runtime", "unavailable", "request_failed", "detached",
))


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="ascii")
    path.chmod(0o600)


def driver_diagnostic(status, stderr):
    """Export only fixed driver stages, errno and classified local stderr signals."""
    result = dict(version=1, status_available=False, status=None, stderr_available=False,
                  stderr_truncated=False, stderr_signals={})
    if status.is_file() and not status.is_symlink():
        require(status.stat().st_size <= 2048, "driver status exceeds bound")
        value = read(status)
        require(set(value) == {"version", "kind", "phase", "error_code", "errno", "child_exit_code"}
            and value["version"] == 1 and value["kind"] == "real-gecko-core-gateway-driver-status"
            and value["phase"] in DRIVER_PHASES
            and (value["error_code"] is None or value["error_code"] in DRIVER_ERRORS)
            and (value["errno"] is None or type(value["errno"]) is int and 0 < value["errno"] < 4096)
            and (value["child_exit_code"] is None or type(value["child_exit_code"]) is int
                 and -255 <= value["child_exit_code"] <= 255), "driver status is not closed metadata")
        result.update(status_available=True, status=value)
    if stderr.is_file() and not stderr.is_symlink():
        with stderr.open("rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode), "driver stderr is not a regular file")
            source.seek(max(0, info.st_size - 16384))
            raw = source.read(16384).lower()
        result.update(stderr_available=True, stderr_truncated=info.st_size > 16384,
            stderr_signals={name: any(pattern in raw for pattern in patterns) for name, patterns in {
                "module_missing": (b"modulenotfounderror:",),
                "permission_denied": (b"permission denied",),
                "read_only_filesystem": (b"read-only file system",),
                "namespace_setup": (b"creating new namespace", b"failed to make / slave", b"setting up uid map"),
                "working_directory": (b"can't chdir", b"chdir base_path", b"chdir /", b"fchdir to oldroot"),
                "mount_setup": (b"can't bind mount", b"can't mount", b"mounting proc", b"creating mount point"),
                "driver_failed": (b"core network browser driver failed",),
                "traceback": (b"traceback (most recent call last):",),
            }.items()})
    return result


def block(run_id):
    require(re.fullmatch(r"[a-f0-9]{32}", run_id), "invalid synthetic run identity")
    seed = b"volparossa-browser-network:" + bytes.fromhex(run_id)
    return (seed * (65536 // len(seed) + 1))[:65536]


def body_hash(run_id):
    return hashlib.sha256(block(run_id) * (BODY_BYTES // 65536)).hexdigest()


def wait_file(path, seconds=60):
    end = time.monotonic() + seconds
    while not path.exists():
        require(time.monotonic() < end, "bounded fixture gate unavailable")
        time.sleep(.05)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 4096,
            "invalid fixture gate")


def seed(root, run_id):
    require(not root.exists() and not root.is_symlink(), "fixture origin already exists")
    root.mkdir(mode=0o700)
    # Test trust exists only in the disposable browser profile; never disable TLS verification.
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=VOLPAROSSA disposable browser test CA", "-keyout", str(root / "ca.key"),
        "-out", str(root / "ca.pem"), "-addext", "basicConstraints=critical,CA:TRUE"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={HOST}",
        "-keyout", str(root / "origin.key"), "-out", str(root / "origin.csr")],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    (root / "extensions").write_text(f"subjectAltName=DNS:{HOST}\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n", encoding="ascii")
    subprocess.run(["openssl", "x509", "-req", "-in", str(root / "origin.csr"), "-CA", str(root / "ca.pem"),
        "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "extensions"),
        "-out", str(root / "origin.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    write(root / "object.json", dict(bytes=BODY_BYTES, sha256=body_hash(run_id), run_id=run_id))


def origin(root, gates, run_id, report):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(root / "origin.pem", root / "origin.key")
    tls.set_alpn_protocols(["http/1.1"])
    requests = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("47.163.4.2", PORT))
        listener.listen(2)
        listener.settimeout(90)
        write(gates / "origin.ready", dict(version=1, ready=True))
        for phase in PHASES:
            accepted, address = listener.accept()
            require(address[0] == "47.163.4.1", "origin did not observe selected Exit only")
            with tls.wrap_socket(accepted, server_side=True) as stream:
                stream.settimeout(30)
                header = bytearray()
                while not header.endswith(b"\r\n\r\n") and len(header) < 8192:
                    chunk = stream.recv(1)
                    require(chunk, "origin request incomplete")
                    header.extend(chunk)
                lines = header.decode("ascii").split("\r\n")
                require(lines[0] == f"GET /{phase}.bin HTTP/1.1", "unexpected origin request")
                fields = [line.split(":", 1) for line in lines[1:] if line]
                require(all(len(row) == 2 for row in fields), "invalid origin headers")
                headers = {key.lower(): value.strip() for key, value in fields}
                require(headers.get("host") == f"{HOST}:{PORT}"
                    and not any(key in headers for key in ("proxy-authorization", "proxy-connection"))
                    and not any("bearer " in value.lower() for value in headers.values()),
                    "proxy capability escaped to origin")
                write(gates / f"{phase}.ready", dict(version=1, ready=True))
                wait_file(gates / f"{phase}.release")
                stream.sendall((f"HTTP/1.1 200 OK\r\nContent-Length: {BODY_BYTES}\r\n"
                    "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").encode())
                data = block(run_id)
                for index in range(BODY_BYTES // len(data)):
                    stream.sendall(data)
                    if index + 1 == BODY_BYTES // len(data) // 2:
                        write(gates / f"{phase}.progress-ready", dict(version=1, ready=True))
                        wait_file(gates / f"{phase}.continue")
                requests.append(dict(phase=phase, bytes=BODY_BYTES, sha256=body_hash(run_id),
                    peer_is_exit=True, proxy_credentials_absent=True, tls_version=stream.version(),
                    alpn=stream.selected_alpn_protocol()))
                write(report, dict(version=1, run_id=run_id, complete=len(requests) == 2, requests=requests))


def helper_members(role):
    unit = f"volparossa-alpha-helper@{role}.service"
    group = command(["systemctl", "show", "--property=ControlGroup", "--value", unit]).strip()
    require(group.startswith("/system.slice/") and ".." not in group, "wrong helper cgroup")
    pids = set()
    for file in (Path("/sys/fs/cgroup") / group[1:]).rglob("cgroup.procs"):
        pids.update(int(pid) for pid in file.read_text().split())
    require(0 < len(pids) <= 128, "helper process bound")
    result, seen = [], set()
    for pid in sorted(pids):
        try:
            namespace = str(Path(f"/proc/{pid}/ns/net").stat().st_ino)
            if namespace in seen:
                continue
            seen.add(namespace)
            ticks = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
            result.append(dict(unit=unit, pid=pid, start_ticks=ticks, netns=namespace))
        except FileNotFoundError:
            continue
    return result


def native_owner(role, diagnostics=None):
    matches = []
    for owner in helper_members(role):
        prefix = ["nsenter", "-t", str(owner["pid"]), "-n"]
        selector = "( sport = :44443 )" if role == "exit" else "( dport = :44443 )"
        raw = dict(meta=command([*prefix, "ss", "-HOnMie", selector]),
                   tcp=command([*prefix, "ss", "-HOntie", selector]))
        if not raw["meta"].strip():
            continue
        if diagnostics is not None and len(diagnostics) < 4:
            # Fixed synthetic-network socket metadata only; never application/grant bytes.
            diagnostics.append(dict(owner=dict(owner), raw={key: text[:4096] for key, text in raw.items()},
                diagnostic_only=True, raw_truncated=any(len(text) > 4096 for text in raw.values())))
        metas = MPTCP["socket_rows"](raw["meta"], ("ESTAB", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK"))
        if not any(row["state"] == "ESTAB" for row in metas):
            continue
        require(len(MPTCP["socket_rows"](raw["meta"])) == 1, "ambiguous app flow in worker")
        links = json.loads(command([*prefix, "ip", "-j", "-6", "address", "show"]))
        layout, paths = [], []
        for row in MPTCP["socket_rows"](raw["tcp"]):
            local, remote = ipaddress.IPv6Address(row["local"][0]), ipaddress.IPv6Address(row["remote"][0])
            segments = local.exploded.split(":")
            path_id = int(segments[5], 16)
            require(segments[:3] == ["fd76", "6f6c", "7061"] and 1 <= path_id <= 8
                and int(local) & 65535 == (4 if role == "exit" else 1)
                and int(remote) == (int(local) & ~65535) + (1 if role == "exit" else 4),
                "subflow left actual one-relay overlay pair")
            matched = [link for link in links if str(local) in {item["local"] for item in link["addr_info"]}]
            require(len(matched) == 1, "subflow address lacks one owned interface")
            link = matched[0]
            output = command([*prefix, "wg", "show", link["ifname"], "endpoints"]).splitlines()
            require(len(output) == 1 and len(output[0].split()) == 2, "invalid owned WireGuard endpoint")
            physical = output[0].split()[1]
            host, port = physical.rsplit(":", 1)
            require(host in MPTCP["RELAY_IPS"] and 0 < int(port) <= 65535, "unselected relay endpoint")
            paths.append(dict(path_id=path_id, relay_node=MPTCP["RELAY_IPS"][host],
                interface=link["ifname"], ifindex=link["ifindex"], endpoint=physical))
            layout.append(dict(path_id=path_id, **{
                f"{role}_address": str(local), f"{role}_interface": link["ifname"],
                f"{'client' if role == 'exit' else 'exit'}_address": str(remote)}))
        owner["paths"] = sorted(paths, key=lambda row: row["path_id"])
        matches.append(dict(owner=owner, raw=raw, kernel=MPTCP["kernel_sample"](raw, dict(paths=layout), role)))
    require(len(matches) == 1, "one attributable active app worker required")
    return matches[0]


def sample(output=None):
    value = dict(started_monotonic_ns=time.monotonic_ns())
    for role in ("client", "exit"):
        diagnostics = []
        try:
            value[role] = native_owner(role, diagnostics)
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
            if output is not None:
                write(output, dict(observation_complete=False, failed_role=role,
                    fixed_error="native_owner_not_verified", candidates=diagnostics))
            raise
    value["observed_monotonic_ns"] = time.monotonic_ns()
    validate_sample(value)
    return value


def validate_sample(value):
    bindings = []
    for role in ("client", "exit"):
        entry = value[role]
        paths = entry["owner"]["paths"]
        require(entry["owner"]["unit"] == f"volparossa-alpha-helper@{role}.service"
            and type(entry["owner"]["pid"]) is int and entry["owner"]["pid"] > 1
            and re.fullmatch(r"[1-9][0-9]*", entry["owner"]["netns"])
            and re.fullmatch(r"[1-9][0-9]*", entry["owner"]["start_ticks"])
            and len(paths) == 2 and len({row["relay_node"] for row in paths}) == 2,
            "two distinct committed native relay paths required")
        require({row["path_id"] for row in paths} == {row["path_id"] for row in entry["kernel"]["subflows"]}
            and len({row["interface"] for row in paths}) == len({row["ifindex"] for row in paths}) == 2,
            "subflow/interface binding differs")
        for path in paths:
            address, port = path["endpoint"].rsplit(":", 1)
            require(MPTCP["RELAY_IPS"].get(address) == path["relay_node"] and 0 < int(port) <= 65535
                and 1 <= path["path_id"] <= 8 and path["ifindex"] > 0
                and re.fullmatch(r"[A-Za-z0-9]{1,15}", path["interface"]), "invalid owned relay interface")
        layout = [dict(path_id=row["path_id"], **{f"{role}_address": row["local"][0],
            f"{role}_interface": next(path["interface"] for path in paths if path["path_id"] == row["path_id"]),
            f"{'client' if role == 'exit' else 'exit'}_address": row["remote"][0]})
            for row in entry["kernel"]["subflows"]]
        require(entry["kernel"] == MPTCP["kernel_sample"](entry["raw"], dict(paths=layout), role),
            "raw kernel data disagrees with projection")
        bindings.append({row["path_id"]: row["relay_node"] for row in paths})
    require(bindings[0] == bindings[1], "Client/Exit used different physical relays")
    client, exit_side = value["client"]["kernel"], value["exit"]["kernel"]
    require(client["local"] == exit_side["remote"] and client["remote"] == exit_side["local"],
            "different original MPTCP sockets")
    for left, right in zip(client["subflows"], exit_side["subflows"], strict=True):
        require(left["local"] == right["remote"] and left["remote"] == right["local"]
            and left["local_id"] == right["remote_id"] and left["remote_id"] == right["local_id"],
            "subflow mirrored tuple/ID mismatch")
        # Same exact Linux MP_CAPABLE/accepted-JOIN zero-token forms as the existing growth checker.
        for role, own, peer, row in (("client", client, exit_side, left), ("exit", exit_side, client, right)):
            initial = (row["local_id"] == row["remote_id"] == 0 and "M" in row["flags"]
                and "J" not in row["flags"] and row["local"] == own["local"] and row["remote"] == own["remote"])
            accepted = role == "exit" and "J" in row["flags"] and "j" not in row["flags"] and row["local_id"] > 0 and row["remote_id"] > 0
            require(int(row["remote_token"], 16) == int(peer["token"], 16)
                or int(row["remote_token"], 16) == 0 and (initial or accepted), "subflow peer token mismatch")


def detached(before):
    result = dict(version=1, independent=True, client=False, exit=False)
    for role in ("client", "exit"):
        old = before[role]["owner"]["netns"]
        result[role] = all(owner["netns"] != old for owner in helper_members(role))
    require(result["client"] and result["exit"], "detached app namespace remains live")
    return result


def evidence(root):
    phases = []
    for phase in PHASES:
        before, after = (read(root / f"{PREFIX}-{phase}-{name}.json") for name in ("baseline", "progress"))
        validate_sample(before)
        validate_sample(after)
        MPTCP["progress"](before, after, 2)
        for role in ("client", "exit"):
            require(before[role]["owner"] == after[role]["owner"], "worker incarnation changed")
        relays = {row["relay_node"] for row in before["client"]["owner"]["paths"]}
        captures = {role: read(root / f"{PREFIX}-{phase}-privacy-{role}.json") for role in ROLES}
        COMMON["privacy"](captures, False, (set(ROLES[1:4]) - relays).pop())
        phases.append(dict(phase=phase, baseline=before, progress=after, privacy=captures))
    result = dict(version=1, phases=phases, browser=read(root / f"{PREFIX}-browser.json"),
        origin=read(root / f"{PREFIX}-origin.json"), detach=read(root / f"{PREFIX}-detach.json"),
        isolation=read(root / f"{PREFIX}-isolation.json"), provision=read(root / f"{PREFIX}-provision.json"))
    validate_browser(result)
    for role in ("client", "exit"):
        require(phases[0]["baseline"][role]["owner"]["netns"] != phases[1]["baseline"][role]["owner"]["netns"],
                "attachments share a route-owner namespace")
    return result


def validate_browser(evidence):
    provision = runpy.run_path(str(HERE / "browser-network-provision.py"))["pins"]()
    require(evidence["provision"] == provision, "browser source provenance differs")
    browser = evidence["browser"]
    require(browser["version"] == 1 and browser["kind"] == "real-gecko-core-gateway-driver"
        and browser["passed"] is True and browser["runtime_version"] == provision["runtime"]["version"]
        and browser["runtime_source_stamp"] == provision["runtime"]["source_stamp"]
        and browser["module_sha256"] == provision["files"]["integration/VolparossaNetwork.sys.mjs"]["sha256"]
        and browser["script_sha256"] == provision["files"]["scripts/smoke_network_core.py"]["sha256"]
        and browser["expected_bytes"] == BODY_BYTES and browser["overlay_kernel_proof_external"] is True
        and browser["expected_sha256"] == body_hash(evidence["origin"]["run_id"])
        and browser["full_browser_killswitch"] is False and browser["firefox157_build_proven"] is False
        and browser["cleanup"] == dict(browser_exited=True, profile_removed=True), "actual pinned browser proof missing")
    result = browser["result"]
    require(set(result) == {"independent_attachments", "wrong_scope_blocked", "a", "b", "a_detached", "b_survives_a_detach"}
        and all(result[key] is True for key in ("independent_attachments", "wrong_scope_blocked", "a_detached", "b_survives_a_detach"))
        and result["a"] == result["b"] == dict(bytes=BODY_BYTES, sha256_verified=True), "browser lifecycle/hash failed")
    isolation = evidence["isolation"]
    require(isolation["user_uid"] == 985 and isolation["client_namespace"] is True
        and isolation["outside_parent_namespace"] is True and isolation["all_capabilities_dropped"] is True
        and isolation["no_new_privileges"] is True and browser["namespace"] == isolation["netns"],
        "browser is not the observed capless Client application")
    require(isolation["fixture_loopback_only_uid_guard"] is True, "fixture application containment missing")


def validate_uid_guard(guard, uid):
    rules = [row["rule"]["expr"] for row in guard["nftables"] if "rule" in row]
    # `nft -n -j` requests NUMERIC_ALL, including NUMERIC_SYMBOL: nf_proto's
    # IPv6 constant is the Linux NFPROTO_IPV6 integer 10, not the text "ipv6".
    # Keep the exact two rules/UID/address/verdicts; do not loosen containment.
    expected = [[{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": uid}},
        {"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "127.0.0.1"}}, {"drop": None}],
        [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": uid}},
        {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": 10}}, {"drop": None}]]
    chains = [row["chain"] for row in guard["nftables"] if "chain" in row]
    require(rules == expected and len(chains) == 1 and all(chains[0][key] == value for key, value in
        dict(family="inet", table="vpbrowser", name="output", type="filter", hook="output", prio=-5, policy="accept").items()),
        "disposable application egress guard differs")


def isolation(pid, parent_namespace, client_namespace, uid, gid, group, output=None):
    helper = runpy.run_path(str(HERE / "content-provider-https-smoke.py"))
    stage, process_verified = "process_boundary", False
    try:
        # The observed PID initially execs ip/setpriv before reaching the capless driver.
        end = time.monotonic() + 5
        while True:
            try:
                result = helper["process_boundary"](pid, parent_namespace, client_namespace, uid, gid, group)
                break
            except (ValueError, OSError):
                require(time.monotonic() < end, "capless application did not reach its owned namespace")
                time.sleep(.05)
        process_verified = True
        result["netns"] = client_namespace
        stage = "guard_readback"
        guard = json.loads(command(["nsenter", "-t", str(pid), "-n", "nft", "-n", "-j", "list", "table", "inet", "vpbrowser"]))
        stage = "guard_validation"
        validate_uid_guard(guard, uid)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        if output is not None:
            # Closed facts only; never argv/environment, grants or browser output.
            write(output, dict(observation_complete=False, failed_stage=stage,
                process_boundary_verified=process_verified, fixture_loopback_only_uid_guard=False))
        raise
    result["fixture_loopback_only_uid_guard"] = True
    return result


def cleanup(work, runtime, report):
    require(os.getuid() == 0 and socket.gethostname() == "volparossa-alpha"
        and subprocess.check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
        and runtime == Path("/home/vpci/browser-network-runtime") and not runtime.is_symlink()
        and work.parent == Path("/opt") and re.fullmatch(r"va\.[a-f0-9]{32}\.[A-Za-z0-9]{6}", work.name)
        and work.resolve() == work and work.is_dir(), "invalid disposable cleanup owner")
    for target, uid in ((work / "client-fixtures/browser-network", 985),
                        (work / "destination/browser-network-origin", None),
                        (work / "destination/browser-network-gates", None), (runtime, None)):
        if target.exists():
            info = target.lstat()
            require(stat.S_ISDIR(info.st_mode) and not target.is_symlink()
                and (uid is None or info.st_uid == uid), "cleanup target changed")
            shutil.rmtree(target)
    write(report, dict(private_files_removed=True))


def validate_report(path, revision):
    report = read(path)
    require(report["source_revision"] == revision and re.fullmatch(r"[0-9a-f]{40}", revision)
        and report["report_kind"] == "volparossa-browser-network" and report["success"] is True,
        "browser network proof failed")
    rebuilt = evidence(path.parent)
    require(rebuilt == report["network"], "archived kernel/capture bindings differ")
    require(rebuilt["browser"]["core_revision"] == revision, "browser used another core revision")
    require(report["cleanup"] == dict(complete=True, remaining_owned_objects=0)
        and report["host_state"]["unchanged"] is True
        and report["full_browser_killswitch_claimed"] is False
        and report["http3_claimed"] is False and report["direct_fallback"] is False,
        "scope or cleanup incorrect")
    for when in ("before", "after"):
        actual = hashlib.sha256((path.parent / f"host-state-{when}.json").read_bytes()).hexdigest()
        require(actual == report["host_state"][f"{when}_sha256"], "host snapshot binding differs")
    require(read(path.parent / f"{PREFIX}-private-cleanup.json") == dict(private_files_removed=True),
        "private grant/profile cleanup unconfirmed")
    # Browser report/schema is checked against the exact pinned harness in provision validation.
    require(rebuilt["origin"]["complete"] is True and len(rebuilt["origin"]["requests"]) == 2,
        "two real TLS origin transfers missing")
    for request in rebuilt["origin"]["requests"]:
        require(request["bytes"] == BODY_BYTES and request["peer_is_exit"] is True
            and request["sha256"] == body_hash(rebuilt["origin"]["run_id"])
            and request["proxy_credentials_absent"] is True and request["tls_version"] == "TLSv1.3"
            and request["alpn"] == "http/1.1", "origin TLS or secret boundary failed")
    require([row["phase"] for row in rebuilt["origin"]["requests"]] == list(PHASES), "origin phase ordering differs")
    require(rebuilt["detach"] == dict(version=1, independent=True, client=True, exit=True),
            "first attachment cleanup not independently observed")
    return report


def main():
    action = sys.argv[1]
    if action == "export-names":
        print("\n".join(EXPORT_NAMES))
    elif action == "hash":
        print(body_hash(sys.argv[2]))
    elif action == "seed":
        seed(Path(sys.argv[2]), sys.argv[3])
    elif action == "origin":
        origin(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], Path(sys.argv[5]))
    elif action == "sample":
        output = Path(sys.argv[2])
        write(output, sample(output))
    elif action == "progress":
        before, after = read(Path(sys.argv[2])), read(Path(sys.argv[3]))
        validate_sample(before); validate_sample(after); MPTCP["progress"](before, after, 2)
    elif action == "detached":
        write(Path(sys.argv[3]), detached(read(Path(sys.argv[2]))))
    elif action == "isolation":
        output = Path(sys.argv[8])
        write(output, isolation(int(sys.argv[2]), sys.argv[3], sys.argv[4], *map(int, sys.argv[5:8]), output=output))
    elif action == "cleanup":
        cleanup(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
    elif action == "driver-diagnostic":
        write(Path(sys.argv[4]), driver_diagnostic(Path(sys.argv[2]), Path(sys.argv[3])))
    elif action == "evidence":
        write(Path(sys.argv[3]), evidence(Path(sys.argv[2])))
    elif action == "report":
        validate_report(Path(sys.argv[2]), sys.argv[3])
    else:
        raise ValueError("unknown browser fixture operation")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("BROWSER_NETWORK_CHECK_FAILED", file=sys.stderr)
        raise SystemExit(1)
