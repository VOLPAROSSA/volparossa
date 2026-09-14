#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Same-flow kernel MPTCP growth evidence; socket ACK octets are not application goodput."""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

COMMON = runpy.run_path(str(Path(__file__).with_name("mpquic-growth-smoke.py")))
read, require, text = COMMON["read"], COMMON["require"], COMMON["text"]
PREFIX = "mptcp-growth"
BODY_BYTES = 32 * 1024 * 1024
MIN_DELTA = 65536
RELAY_IPS = {"42.158.0.1": "relay0", "44.160.1.1": "relay1", "45.161.2.1": "relay2"}


def command(args):
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=5)
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 4096, "kernel diagnostic exceeds bound")
    return result.stdout


def selected(value, peers):
    snapshot = COMMON["paths"](value)
    rows = snapshot["paths"]
    require(len(rows) == 2 and all(row["state"] == 1 and row["user_bytes"] == 0
            and row["acked_transport_bytes"] == row["smoothed_rtt_us"] == 0 for row in rows)
            and {row["exit_peer_id"] for row in rows} == {peers["exit"]}
            and {row["relay_peer_id"] for row in rows} <= {peers[f"relay{i}"] for i in range(3)},
            "need two initial Reachable MPTCP paths, not claimed live CLI counters")
    snapshot["source"] = "initial committed selection only; kernel measurements prove data"
    return snapshot


def endpoint(value):
    match = re.fullmatch(r"\[([0-9a-fA-F:]+)(?:%[A-Za-z0-9]+)?\]:(\d+)", value)
    require(match is not None, "expected exact IPv6 overlay socket endpoint")
    address, port = match.groups()
    require(0 < int(port) <= 65535, "invalid TCP port")
    return str(ipaddress.IPv6Address(address)), int(port)


def socket_rows(value, states=("ESTAB",)):
    require(len(value) <= 65536, "socket dump exceeds bound")
    rows = []
    for line in value.splitlines():
        fields = line.split()
        require(len(fields) >= 6 and fields[0] in states, "unexpected socket dump state/format")
        local, remote = endpoint(fields[3]), endpoint(fields[4])
        cookie = re.search(r"\bsk:([0-9a-f]+)\b", line)
        require(cookie is not None and int(cookie[1], 16) != 0, "missing kernel socket lifetime cookie")
        rows.append(dict(local=local, remote=remote, cookie=cookie[1], state=fields[0], line=line))
    require(len(rows) <= 8, "excessive current socket rows")
    return rows


def kernel_sample(raw, layout, role):
    # The ordinary application's request-side SHUT_WR is intentionally propagated. Its
    # MPTCP meta socket may be half closed while the download's TCP subflows stay ESTAB.
    states = ("ESTAB", "CLOSE-WAIT") if role == "exit" else ("ESTAB", "FIN-WAIT-1", "FIN-WAIT-2")
    meta = socket_rows(raw["meta"], states)
    require(len(meta) == 1, "one unchanged application MPTCP socket required")
    meta = meta[0]
    token = re.search(r"\btoken:([0-9a-f]+)(?:\s|$)", meta["line"])
    require(token is not None and int(token[1], 16) != 0
            and "fallback" not in meta["line"].lower(), "missing genuine MPTCP token or fallback")
    direction = "exit" if role == "exit" else "client"
    other = "client" if role == "exit" else "exit"
    records = []
    for row in socket_rows(raw["tcp"]):
        match = re.search(r"tcp-ulp-mptcp\s+flags:(?P<flags>\S+)\s+"
                          r"token:(?P<remote>[0-9a-f]+)\(id:(?P<remote_id>\d+)\)/"
                          r"(?P<local>[0-9a-f]+)\(id:(?P<local_id>\d+)\)", row["line"])
        require(match is not None and int(match["local"], 16) == int(token[1], 16)
                and all(int(match[key]) <= 255 for key in ("local_id", "remote_id")),
                "TCP row is not a subflow of the exact MPTCP meta socket")
        path = next((path for path in layout["paths"] if
                     row["local"][0] == path[f"{direction}_address"]
                     and row["remote"][0] == path[f"{other}_address"]), None)
        require(path is not None and (row["local"] if role == "exit" else row["remote"])[1] == 44443,
                "subflow left exact selected overlay/Exit listener")
        counters = {}
        for name in ("bytes_acked", "bytes_received", "data_segs_out"):
            found = re.search(rf"\b{name}:(\d+)\b", row["line"])
            counters[name] = int(found[1]) if found else 0
            require(counters[name] < 2**64, "kernel counter overflow")
        retrans = re.search(r"\bretrans:(\d+)/(\d+)\b", row["line"])
        counters["total_retrans"] = int(retrans[2]) if retrans else 0
        records.append(dict(path_id=path["path_id"], local=list(row["local"]), remote=list(row["remote"]),
                            cookie=row["cookie"], flags=match["flags"], remote_token=match["remote"],
                            remote_id=int(match["remote_id"]), local_id=int(match["local_id"]), **counters))
    require(2 <= len(records) <= 3 and len({row["path_id"] for row in records}) == len(records)
            and len({row["cookie"] for row in records}) == len(records), "ambiguous/incomplete subflow set")
    return dict(token=token[1], cookie=meta["cookie"], local=list(meta["local"]), remote=list(meta["remote"]),
                subflows=sorted(records, key=lambda row: row["path_id"]))


def owner_namespaces(layout):
    result = {}
    for role in ("client", "exit"):
        unit = f"volparossa-alpha-helper@{role}.service"
        group = command(["systemctl", "show", "--property=ControlGroup", "--value", unit]).strip()
        require(group.startswith("/system.slice/") and ".." not in group, "wrong helper cgroup")
        pids = set()
        for file in (Path("/sys/fs/cgroup") / group[1:]).rglob("cgroup.procs"):
            pids.update(int(pid) for pid in file.read_text().split())
        require(0 < len(pids) <= 128, "unbounded/missing helper process tree")
        matches, seen = [], set()
        for pid in sorted(pids):
            try:
                namespace = str(Path(f"/proc/{pid}/ns/net").stat().st_ino)
                if namespace in seen:
                    continue
                seen.add(namespace)
                links = json.loads(command(["nsenter", "-t", str(pid), "-n", "ip", "-j", "-6", "address", "show"]))
                expected = {path[f"{role}_interface"]: path[f"{role}_address"] for path in layout["paths"]}
                actual = {link["ifname"]: link for link in links}
                if not expected.keys() <= actual.keys():
                    continue
                require(all(address in {a["local"] for a in actual[name]["addr_info"]}
                            for name, address in expected.items()), "wrong route namespace overlay")
                paths = []
                for path in layout["paths"]:
                    name = path[f"{role}_interface"]
                    # Never record WG keys: endpoints only supply exact physical relay bindings.
                    output = command(["nsenter", "-t", str(pid), "-n", "wg", "show", name, "endpoints"])
                    lines = output.splitlines()
                    require(len(lines) == 1 and len(lines[0].split()) == 2, "ambiguous WireGuard peer")
                    physical = lines[0].split()[1]
                    address, port = physical.rsplit(":", 1)
                    require(address in RELAY_IPS and 0 < int(port) <= 65535, "unselected physical relay endpoint")
                    paths.append(dict(path_id=path["path_id"], interface=name,
                                      ifindex=actual[name]["ifindex"], relay_node=RELAY_IPS[address], endpoint=physical))
                stat = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
                matches.append(dict(unit=unit, cgroup=group, pid=pid, start_ticks=stat[19],
                                    netns=namespace, paths=paths))
            except FileNotFoundError:
                continue
        require(len(matches) == 1, "exactly one helper-owned route namespace required")
        result[role] = matches[0]
    return result


def sample(owners, layout):
    result = dict(started_monotonic_ns=time.monotonic_ns())
    for role, owner in owners.items():
        pid = owner["pid"]
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        require(stat[19] == owner["start_ticks"] and str(Path(f"/proc/{pid}/ns/net").stat().st_ino) == owner["netns"],
                "helper namespace owner lifetime changed")
        prefix = ["nsenter", "-t", str(pid), "-n", "ss"]
        selector = "( sport = :44443 )" if role == "exit" else "( dport = :44443 )"
        raw = {"meta": command([*prefix, "-HOnMie", selector]),
               "tcp": command([*prefix, "-HOntie", selector])}
        result[role] = dict(raw=raw)
        try:
            result[role]["kernel"] = kernel_sample(raw, layout, role)
        except ValueError as error:
            # Export failed raw kernel observations too, so a VM failure is diagnosable
            # without a second run or pretending incomplete observations were proof.
            result[role]["error"] = str(error)
    result["observed_monotonic_ns"] = time.monotonic_ns()
    return result


def progress(before, after, count):
    require(after["started_monotonic_ns"] > before["observed_monotonic_ns"], "overlapping/unordered kernel snapshots")
    for role, field in (("exit", "bytes_acked"), ("client", "bytes_received")):
        old, new = before[role]["kernel"], after[role]["kernel"]
        require(all(old[key] == new[key] for key in ("token", "cookie", "local", "remote")),
                "new application/socket substituted for original MPTCP flow")
        current = {row["path_id"]: row for row in new["subflows"]}
        require(len(old["subflows"]) == len(current) == count, "wrong simultaneous subflow count")
        for row in old["subflows"]:
            now = current.get(row["path_id"])
            require(now is not None and all(row[key] == now[key] for key in
                    ("cookie", "local", "remote", "remote_token", "local_id", "remote_id"))
                    and now[field] - row[field] >= MIN_DELTA, "every same-lifetime subflow needs fresh bulk progress")


def payload_hash(run_id):
    require(re.fullmatch(r"[0-9a-f]{32}", run_id) is not None, "invalid run identity")
    seed = b"volparossa-download:a04:" + bytes.fromhex(run_id)
    block = (seed * (65536 // len(seed) + 1))[:65536]
    return hashlib.sha256(block * (BODY_BYTES // len(block))).hexdigest()


def validate(e):
    selection, layout, owners, peers = e["selection"], e["layout"], e["owners"], e["expected_peers"]
    require(e["success"] is True and layout["context"] == selection["route_context_id"]
            and len(layout["paths"]) == 3 and {p["path_id"] for p in layout["paths"]} == {1, 2, 3}, "wrong original route layout")
    for role in ("client", "exit"):
        require(owners[role]["unit"] == f"volparossa-alpha-helper@{role}.service"
                and {p["relay_node"] for p in owners[role]["paths"]} == {"relay0", "relay1", "relay2"}, "three distinct owned relay paths missing")
        for path in owners[role]["paths"]:
            original = next(p for p in layout["paths"] if p["path_id"] == path["path_id"])
            require(path["interface"] == original[f"{role}_interface"] and path["ifindex"] > 0
                    and RELAY_IPS[path["endpoint"].split(":")[0]] == path["relay_node"], "kernel interface/peer binding differs")
    require({p["path_id"]: p["relay_node"] for p in owners["client"]["paths"]}
            == {p["path_id"]: p["relay_node"] for p in owners["exit"]["paths"]}, "Client and Exit bind different relays")
    initial_ids = {p["path_id"] for p in selection["paths"]}
    for path in selection["paths"]:
        node = next(p["relay_node"] for p in owners["exit"]["paths"] if p["path_id"] == path["path_id"])
        require(path["relay_peer_id"] == peers[node], "initial CLI identity differs from owned WG peer")
    for name in ("baseline", "before_loss", "expanded", "expanded_progress"):
        snapshot = e[name]
        for role in ("client", "exit"):
            require(snapshot[role]["kernel"] == kernel_sample(snapshot[role]["raw"], layout, role), "kernel projection differs from raw ss")
        client, exit_side = snapshot["client"]["kernel"], snapshot["exit"]["kernel"]
        require({p["path_id"] for p in client["subflows"]} == {p["path_id"] for p in exit_side["subflows"]}, "subflow mirrors disagree")
        for row in client["subflows"]:
            mirror = next(p for p in exit_side["subflows"] if p["path_id"] == row["path_id"])
            require(row["local"] == mirror["remote"] and row["remote"] == mirror["local"]
                    and row["local_id"] == mirror["remote_id"] and row["remote_id"] == mirror["local_id"],
                    "not the same mirrored MPTCP flow")
            for role, own, peer, subflow in (("client", client, exit_side, row), ("exit", exit_side, client, mirror)):
                remote_token = int(subflow["remote_token"], 16)
                # Actual Linux ss also reports a zero remote token on an accepted JOIN
                # (Exit flags Jec), unlike the initiating Client JOIN (Jjec). In both
                # cases the second token above binds the exact own meta socket. Reversed
                # tuples and IDs bind both observations; nonzero tokens must match peers.
                initial = (subflow["local_id"] == subflow["remote_id"] == 0
                           and "M" in subflow["flags"] and "J" not in subflow["flags"]
                           and subflow["local"] == own["local"] and subflow["remote"] == own["remote"])
                accepted_join = (role == "exit" and "J" in subflow["flags"] and "j" not in subflow["flags"]
                                 and subflow["local_id"] > 0 and subflow["remote_id"] > 0)
                require(remote_token == int(peer["token"], 16)
                        or (remote_token == 0 and (initial or accepted_join)),
                        "subflow remote token does not match its peer or exact kernel MP_CAPABLE/accepted-JOIN form")
    require({p["path_id"] for p in e["baseline"]["exit"]["kernel"]["subflows"]} == initial_ids, "initial socket not exact active subset")
    progress(e["baseline"], e["before_loss"], 2)
    progress(e["expanded"], e["expanded_progress"], 3)
    require(e["before_loss"]["observed_monotonic_ns"] < e["expanded"]["started_monotonic_ns"], "growth predates injection")
    for role in ("client", "exit"):
        require(all(e["before_loss"][role]["kernel"][key] == e["expanded"][role]["kernel"][key]
                    for key in ("token", "cookie", "local", "remote")), "growth switched application flow")
        current = {row["path_id"]: row for row in e["expanded"][role]["kernel"]["subflows"]}
        for old in e["before_loss"][role]["kernel"]["subflows"]:
            new = current[old["path_id"]]
            require(all(old[key] == new[key] for key in
                    ("cookie", "local", "remote", "remote_token", "local_id", "remote_id"))
                    and all(old[key] <= new[key] for key in ("bytes_acked", "bytes_received", "total_retrans")),
                    "growth replaced an original subflow or reset its counters")
    injection = e["injection"]
    node = next(p["relay_node"] for p in owners["exit"]["paths"] if p["path_id"] == injection["path_id"])
    require(injection["path_id"] in initial_ids and injection["relay_node"] == node
            and injection["interface"] == f"xr{node[-1]}" and injection["namespace_role"] == "exit"
            and injection["loss_percent"] == 15, "loss is not the original selected download leg")
    for stage in ("before", "during", "after"):
        COMMON["qdisc"](injection[stage], stage == "during")
    require(injection["during"][0]["drops"] > 0, "loss configured but no actual drops")
    require(set(e["rate_limits"]) == {"relay0", "relay1", "relay2"}, "bounded download profile missing")
    for phases in e["rate_limits"].values():
        COMMON["qdisc"](phases["before"], False)
        COMMON["qdisc"](phases["after"], False)
        require(len(phases["during"]) == 1 and phases["during"][0]["kind"] == "tbf"
                and phases["during"][0]["handle"] == "7a02:" and phases["during"][0]["root"] is True
                and phases["during"][0]["options"]["rate"] == 1000000,
                "download profile is not the fixed 8Mbps per owned relay leg")
    old = next(p for p in e["before_loss"]["exit"]["kernel"]["subflows"] if p["path_id"] == injection["path_id"])
    new = next(p for p in e["expanded_progress"]["exit"]["kernel"]["subflows"] if p["path_id"] == injection["path_id"])
    require(new["cookie"] == old["cookie"] and new["total_retrans"] > old["total_retrans"], "actual selected TCP retransmissions missing")
    warm = next(p["relay_node"] for p in owners["exit"]["paths"] if p["path_id"] not in initial_ids)
    for phase in ("initial", "expanded"):
        COMMON["privacy"](e["privacy"][phase], phase == "expanded", warm)
    for receipt in (e["client"], e["server"]):
        require(receipt["case"] == PREFIX and receipt["attempt"] == 0
                and receipt["response_bytes"] == BODY_BYTES and receipt["response_sha256"] == payload_hash(e["run_id"]), "incomplete/substituted application payload")
    request = b"volparossa-mptcp-growth:" + bytes.fromhex(e["run_id"]) + bytes(4)
    require(e["client"]["request_bytes"] == e["server"]["request_bytes"] == len(request)
            and e["client"]["request_sha256"] == e["server"]["request_sha256"] == hashlib.sha256(request).hexdigest()
            and e["server"]["source"]["ip"] == "47.163.4.1" and e["server"]["listen"] == dict(ip="47.163.4.2", port=18080)
            and 0 < e["server"]["source"]["port"] <= 65535
            # The ordinary application uses the helper's exact parent ingress veth,
            # not the Client's public underlay address (kernel.rs parent ingress tuple).
            and e["client"]["application"]["ip"] == "169.254.240.1"
            and 0 < e["client"]["application"]["port"] <= 65535
            and e["client"]["destination"] == e["server"]["listen"], "normal request/destination/Exit source not preserved")
    require(e["client"]["completed_monotonic_ns"] - e["client"]["first_byte_monotonic_ns"]
            == e["client"]["duration_ns"] > 0, "application download timing missing")
    require(e["cleanup"] == dict(client_exit_status=0, route_disconnected=True, active_contexts=0,
            paths_empty=True, loss_removed=True, rate_limits_removed=True), "incomplete flow/route/qdisc cleanup")


def build_evidence(work):
    work = Path(work)
    result = {key: read(work / f"{PREFIX}-{suffix}.json") for key, suffix in (
        ("selection", "selection"), ("layout", "layout"), ("owners", "owners"), ("baseline", "baseline"),
        ("before_loss", "before-loss"), ("expanded", "expanded"), ("expanded_progress", "expanded-progress"),
        ("injection", "injection"), ("client", "client"), ("server", "server"), ("cleanup", "cleanup"))}
    result.update(success=True, run_id=read(work / f"{PREFIX}-run.json")["run_id"],
                  expected_peers=read(work / "a01-expected-peers.json"),
                  privacy={phase: {role: read(work / f"{PREFIX}-{phase}-privacy-{role}.json")
                                   for role in COMMON["ROLES"]} for phase in ("initial", "expanded")},
                  rate_limits={f"relay{i}": {stage: json.loads(text(work / f"{PREFIX}-rate-{i}-{stage}.json"))
                                            for stage in ("before", "during", "after")} for i in range(3)})
    parsed = selected(text(work / f"{PREFIX}-selection.txt"), result["expected_peers"])
    require(parsed["paths"] == result["selection"]["paths"] and parsed["route_context_id"] == result["selection"]["route_context_id"], "selection differs from raw CLI")
    require("connected: false" in text(work / f"{PREFIX}-final-status.txt").splitlines()
            and "active contexts: 0" in text(work / f"{PREFIX}-final-status.txt").splitlines()
            and text(work / f"{PREFIX}-final-paths.txt") == "", "route was not disconnected")
    for stage in ("before", "during", "after"):
        result["injection"][stage] = json.loads(text(work / f"{PREFIX}-qdisc-{stage}.json"))
    validate(result)
    return result


def report(path, revision):
    value = read(path)
    require(value["schema_version"] == 1 and value["report_kind"] == "volparossa-mptcp-growth-runtime" and value["source_revision"] == revision
            and re.fullmatch(r"[0-9a-f]{40}", revision) and value["success"] is True
            and value["phase"] == "mptcp-growth-complete" and value["observed_blocker"] in (None, "NONE")
            and value["cleanup"] == dict(complete=True, remaining_owned_objects=0), "wrong source or failed parent cleanup")
    host = value["host_state"]
    require(host["success"] is True and host["unchanged"] is True
            and host["before_sha256"] == host["after_sha256"], "host changed")
    for stage in ("before", "after"):
        file = path.parent / f"host-state-{stage}.json"
        require(not file.is_symlink() and file.stat().st_size <= 8 * 1024 * 1024
                and hashlib.sha256(file.read_bytes()).hexdigest() == host[f"{stage}_sha256"], "raw host hash mismatch")
    rebuilt = build_evidence(path.parent)
    require(value["transfer"] == rebuilt and value["run_id"] == rebuilt["run_id"]
            and read(path.parent / f"{PREFIX}-evidence.json") == rebuilt, "raw evidence differs from report")


def main(args):
    if len(args) == 3 and args[0] == "report":
        report(Path(args[1]), args[2])
        return
    if len(args) == 4 and args[0] == "select":
        result = selected(text(Path(args[1])), read(Path(args[2])))
    elif len(args) == 3 and args[0] == "owners":
        result = owner_namespaces(read(Path(args[1])))
    elif len(args) == 4 and args[0] == "sample":
        result = sample(read(Path(args[1])), read(Path(args[2])))
    elif len(args) == 4 and args[0] == "progress":
        require(args[3] in ("2", "3"), "invalid progress count")
        progress(read(Path(args[1])), read(Path(args[2])), int(args[3]))
        return
    elif len(args) == 3 and args[0] == "evidence":
        result = build_evidence(Path(args[1]))
    else:
        raise ValueError("usage: select PATHS PEERS OUT | owners LAYOUT OUT | sample OWNERS LAYOUT OUT | progress BEFORE AFTER 2|3 | evidence WORK OUT | report REPORT SHA")
    Path(args[-1]).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    if args[0] == "sample":
        require(all("kernel" in result[role] for role in ("client", "exit")),
                "complete exact-flow kernel snapshot unavailable; raw diagnostics retained")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"MPTCP growth proof unavailable: {error}", file=sys.stderr)
        sys.exit(1)
