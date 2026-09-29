#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Same-meta-socket fresh eligible Relay refill; independent from old warm-growth reports."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("mptcp_growth_reader", Path(__file__).with_name("mptcp-growth-smoke.py"))
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
# This instance only: reuse exact raw ss/namespace readers, not the old scenario's acceptance.
G.RELAY_IPS = {**G.RELAY_IPS, "49.165.5.1": "relay4"}
read, text, require = G.read, G.text, G.require
PREFIX = "mptcp-refill"
ACCEPTANCE_VERSION = 3
BODY_BYTES = 256 * 1024 * 1024
ORIGINAL_RELAYS = {"relay0", "relay1", "relay2", "relay3"}
ROLES = ("client", "relay0", "relay1", "relay2", "relay3", "relay4", "exit")
CLOSING_STATES = ("FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "CLOSING", "LAST-ACK")
LIFETIME_FIELDS = ("cookie", "local", "remote", "local_id", "remote_id", "remote_token")


def exit_endpoints(raw, layout):
    """Bounded iproute2 generic-netlink dump, independently scoped to the Exit namespace."""
    require(len(raw) <= 65536, "endpoint dump exceeds bound")
    rows = json.loads(raw)
    require(type(rows) is list and len(rows) <= 8, "invalid endpoint dump")
    result = []
    for row in rows:
        require(type(row) is dict and {"address", "id", "signal", "dev"} <= set(row)
                and set(row) <= {"address", "id", "signal", "dev", "port"}
                and type(row["id"]) is int and 1 <= row["id"] <= 255
                and row["signal"] is True and row.get("port", 0) in (0, 44443),
                "unexpected Exit MPTCP endpoint fields or flags")
        path = next((p for p in layout["paths"] if row["address"] == p["exit_address"]
                     and row["dev"] == p["exit_interface"]), None)
        require(path is not None, "endpoint escaped owned route layout")
        result.append(dict(path_id=path["path_id"], **row))
    require(len({r["path_id"] for r in result}) == len(result)
            and len({r["id"] for r in result}) == len(result), "ambiguous Exit endpoint identities")
    return sorted(result, key=lambda row: row["path_id"])


def kernel_sample(raw, layout, role, anchor=None, warm=None):
    """Keep closing residues typed; never silently discard malformed/foreign socket rows."""
    states = ("ESTAB", "CLOSE-WAIT") if role == "exit" else ("ESTAB", "FIN-WAIT-1", "FIN-WAIT-2")
    meta = G.socket_rows(raw["meta"], states)
    require(len(meta) == 1, "one unchanged application MPTCP socket required")
    meta = meta[0]
    token = re.search(r"\btoken:([0-9a-f]+)(?:\s|$)", meta["line"])
    require(token is not None and int(token[1], 16) != 0 and "fallback" not in meta["line"].lower(),
            "missing genuine MPTCP token or fallback")
    result = dict(token=token[1], cookie=meta["cookie"], local=list(meta["local"]), remote=list(meta["remote"]))
    if anchor is not None:
        require(all(result[k] == anchor[k] for k in ("token", "cookie", "local", "remote")),
                "original warm anchor meta socket was replaced")
    active, closing = [], []
    for row in G.socket_rows(raw["tcp"], ("ESTAB", *CLOSING_STATES)):
        record = dict(G.subflow_record(row, layout, role, token[1]), state=row["state"])
        if row["state"] == "ESTAB":
            active.append(record)
        else:
            prior = next((p for p in anchor["subflows"] if p["path_id"] == warm), None) if anchor else None
            require(prior is not None and record["path_id"] == warm
                    and all(prior[k] == record[k] for k in LIFETIME_FIELDS),
                    "closing row is not the exact previously productive warm socket")
            closing.append(record)
    rows = active + closing
    require(2 <= len(active) <= 4 and len(rows) <= 4 and len(closing) <= 1
            and len({r["path_id"] for r in rows}) == len(rows)
            and len({r["cookie"] for r in rows}) == len(rows), "ambiguous/incomplete refill subflow set")
    result.update(subflows=sorted(active, key=lambda row: row["path_id"]),
                  closing_subflows=sorted(closing, key=lambda row: row["path_id"]))
    if role == "exit":
        result["endpoints"] = exit_endpoints(raw["endpoints"], layout)
    return result


def sample(owners, layout, anchor=None, warm=None):
    result = dict(started_monotonic_ns=time.monotonic_ns())
    for role, owner in owners.items():
        pid = owner["pid"]
        def same_owner():
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
            require(fields[19] == owner["start_ticks"]
                    and str(Path(f"/proc/{pid}/ns/net").stat().st_ino) == owner["netns"],
                    "helper namespace owner lifetime changed")
        same_owner()
        prefix = ["nsenter", "-t", str(pid), "-n"]
        selector = "( sport = :44443 )" if role == "exit" else "( dport = :44443 )"
        raw = dict(meta=G.command([*prefix, "ss", "-HOnMie", selector]),
                   tcp=G.command([*prefix, "ss", "-HOntie", selector]))
        if role == "exit":
            raw["endpoints"] = G.command([*prefix, "ip", "-j", "mptcp", "endpoint", "show"])
        same_owner()
        result[role] = dict(raw=raw)
        try:
            result[role]["kernel"] = kernel_sample(raw, layout, role,
                anchor[role]["kernel"] if anchor else None, warm)
        except (ValueError, KeyError, TypeError) as error:
            result[role]["error"] = str(error)
    result["observed_monotonic_ns"] = time.monotonic_ns()
    return result


def warm_record(sample, role, warm):
    kernel = sample[role]["kernel"]
    return next((p for p in kernel["subflows"] + kernel["closing_subflows"] if p["path_id"] == warm), None)


def retirement_candidate(anchor, current, layout, warm):
    stable(anchor, current)
    for role in ("client", "exit"):
        require(anchor[role]["kernel"] == kernel_sample(anchor[role]["raw"], layout, role),
                "warm anchor differs from original raw evidence")
        require(current[role]["kernel"] == kernel_sample(current[role]["raw"], layout, role, anchor[role]["kernel"], warm),
                "retirement projection differs from raw kernel evidence")
        old, new = warm_record(anchor, role, warm), warm_record(current, role, warm)
        require(old is not None and old["state"] == "ESTAB", "warm path was never established")
        if new is not None:
            require(all(old[k] == new[k] for k in LIFETIME_FIELDS), "warm residue changed socket identity")
    prior = next((p for p in anchor["exit"]["kernel"]["endpoints"] if p["path_id"] == warm), None)
    require(prior is not None and prior["id"] == warm_record(anchor, "exit", warm)["local_id"],
            "warm endpoint was not independently observed before retirement")
    endpoints = current["exit"]["kernel"]["endpoints"]
    require(all(p["path_id"] != warm and p["id"] != prior["id"] for p in endpoints)
            and all(p in endpoints for p in anchor["exit"]["kernel"]["endpoints"] if p["path_id"] != warm),
            "warm Exit endpoint not withdrawn or another live endpoint removed")
    require(all(p["path_id"] != warm for p in current["exit"]["kernel"]["subflows"]),
            "warm Exit subflow is still established")


def retired(anchor, before, after, layout, warm, healthy):
    retirement_candidate(anchor, before, layout, warm)
    retirement_candidate(anchor, after, layout, warm)
    require(after["started_monotonic_ns"] - before["observed_monotonic_ns"] >= 10_000_000_000,
            "warm withdrawal lacks sustained observation interval")
    progress_path(before, after, healthy)
    for role, counter in (("client", "bytes_received"), ("exit", "bytes_acked")):
        old, new = warm_record(before, role, warm), warm_record(after, role, warm)
        if new is not None:
            require(old is not None and all(old[k] == new[k] for k in LIFETIME_FIELDS)
                    and old[counter] == new[counter], "withdrawn warm path resumed useful progress or reappeared")


def selected(value, peers):
    # Four eligible relays permit any three data relays plus one distinct control relay.
    # Growth's historical {R0,R1,R2} acceptance is intentionally not changed.
    snapshot = G.COMMON["paths"](value)
    rows = snapshot["paths"]
    require(len(rows) == 2 and all(row["state"] == 1 and row["user_bytes"] == 0
            and row["acked_transport_bytes"] == row["smoothed_rtt_us"] == 0 for row in rows)
            and {row["exit_peer_id"] for row in rows} == {peers["exit"]}
            and len({row["relay_peer_id"] for row in rows}) == 2
            and {row["relay_peer_id"] for row in rows} <= {peers[node] for node in ORIGINAL_RELAYS},
            "need two distinct initial Reachable paths from R0-R3, never the fresh R4")
    snapshot["source"] = "initial committed selection only; kernel measurements prove data"
    return snapshot


def original_relays(owners):
    require(set(owners) == {"client", "exit"}, "original endpoint owner coverage invalid")
    mappings = []
    for role in ("client", "exit"):
        owner = owners[role]
        rows = owner["paths"]
        require(owner["unit"] == f"volparossa-alpha-helper@{role}.service"
                and len(rows) == 3 and {p["path_id"] for p in rows} == {1, 2, 3}
                and len({p["relay_node"] for p in rows}) == 3
                and {p["relay_node"] for p in rows} <= ORIGINAL_RELAYS,
                "need three distinct original relays from R0-R3; fresh R4 must be absent")
        mappings.append({p["path_id"]: p["relay_node"] for p in rows})
    require(mappings[0] == mappings[1], "original Client and Exit bind different relays")
    return set(mappings[0].values())


def stable(before, after):
    require(before["observed_monotonic_ns"] < after["started_monotonic_ns"], "snapshots overlap")
    for role in ("client", "exit"):
        old, new = before[role]["kernel"], after[role]["kernel"]
        require(all(old[key] == new[key] for key in ("token", "cookie", "local", "remote")),
                "original application MPTCP meta socket was replaced")
        for row in old["subflows"]:
            current = next((p for p in new["subflows"] if p["path_id"] == row["path_id"]), None)
            if current is not None:
                require(all(current[k] == row[k] for k in ("cookie", "local", "remote", "local_id", "remote_id")),
                        "retained subflow was replaced")


def progress_path(before, after, path):
    stable(before, after)
    for role, field in (("client", "bytes_received"), ("exit", "bytes_acked")):
        old = next((p for p in before[role]["kernel"]["subflows"] if p["path_id"] == path), None)
        new = next((p for p in after[role]["kernel"]["subflows"] if p["path_id"] == path), None)
        require(old is not None and new is not None and new[field] - old[field] >= 65536,
                "same-lifetime path has no substantial fresh payload progress")


def layout_valid(layout, count):
    require(len(layout["paths"]) == count and {p["path_id"] for p in layout["paths"]} == set(range(1, count + 1)),
            "wrong bounded route layout")


def validate(e):
    require(e.get("acceptance_version") == ACCEPTANCE_VERSION, "wrong refill acceptance version")
    original = original_relays(e["owners_initial"])
    layout_valid(e["layout_initial"], 3)
    layout_valid(e["layout_refilled"], 4)
    require(e["layout_initial"]["context"] == e["selection"]["route_context_id"]
            == e["layout_refilled"]["context"], "route context changed")
    initial = {p["path_id"] for p in e["selection"]["paths"]}
    require(len(initial) == 2 and initial <= {1, 2, 3}, "initial paths invalid")
    warm = ({1, 2, 3} - initial).pop()
    risky = e["injection"]["risky_path"]
    require(risky in initial and e["injection"]["warm_path"] == warm,
            "impairment escaped original owned paths")
    for role in ("client", "exit"):
        old, new = e["owners_initial"][role], e["owners_refilled"][role]
        require(old["unit"] == f"volparossa-alpha-helper@{role}.service" and len(old["paths"]) == 3,
                "initial helper owner or original path count invalid")
        require(all(old[k] == new[k] for k in ("unit", "cgroup", "pid", "start_ticks", "netns")),
                "original helper namespace owner replaced")
        require(len(new["paths"]) == 4 and next(p for p in new["paths"] if p["path_id"] == 4)["relay_node"] == "relay4",
                "new path does not terminate on independently contributed R4")
        for path in new["paths"]:
            layout = next(p for p in e["layout_refilled"]["paths"] if p["path_id"] == path["path_id"])
            require(path["interface"] == layout[f"{role}_interface"] and path["ifindex"] > 0
                    and G.RELAY_IPS.get(path["endpoint"].split(":")[0]) == path["relay_node"],
                    "kernel interface or physical relay peer differs from route layout")
        for path in old["paths"]:
            require(path == next(p for p in new["paths"] if p["path_id"] == path["path_id"]),
                    "extension altered an existing WG interface, peer or ifindex")
    require({p["path_id"]: p["relay_node"] for p in e["owners_refilled"]["client"]["paths"]}
            == {p["path_id"]: p["relay_node"] for p in e["owners_refilled"]["exit"]["paths"]},
            "Client and Exit bind different relays")
    for path in e["selection"]["paths"]:
        node = next(p["relay_node"] for p in e["owners_initial"]["exit"]["paths"] if p["path_id"] == path["path_id"])
        require(path["relay_peer_id"] == e["expected_peers"][node], "initial CLI identity differs from physical WG peer")
    stages = ("baseline", "initial_progress", "warm", "warm_progress", "retiring", "retired", "refilled", "refilled_progress")
    for index, name in enumerate(stages):
        sample = e[name]
        layout = e["layout_refilled"] if name.startswith("refilled") else e["layout_initial"]
        for role in ("client", "exit"):
            anchor = e["warm_progress"][role]["kernel"] if index >= 4 else None
            require(sample[role]["kernel"] == kernel_sample(sample[role]["raw"], layout, role, anchor, warm),
                    "projected kernel evidence differs from original ss")
        client, exit_side = sample["client"]["kernel"], sample["exit"]["kernel"]
        client_ids = {p["path_id"] for p in client["subflows"]}
        exit_ids = {p["path_id"] for p in exit_side["subflows"]}
        require(client_ids == exit_ids if index < 4 else
                client_ids - {warm} == exit_ids and warm not in exit_ids,
                "live subflow mismatch beyond the exact withdrawn warm residue")
        if index >= 4:
            retirement_candidate(e["warm_progress"], sample, layout, warm)
        for row in client["subflows"]:
            if index >= 4 and row["path_id"] == warm:
                continue  # Retained and independently anchored, never claimed live at Exit.
            mirror = next(p for p in exit_side["subflows"] if p["path_id"] == row["path_id"])
            require(row["local"] == mirror["remote"] and row["remote"] == mirror["local"]
                    and row["local_id"] == mirror["remote_id"] and row["remote_id"] == mirror["local_id"],
                    "mirrored subflow tuple or ID mismatch")
            for role, own, peer, subflow in (("client", client, exit_side, row), ("exit", exit_side, client, mirror)):
                initial_socket = (subflow["local_id"] == subflow["remote_id"] == 0
                                  and "M" in subflow["flags"] and "J" not in subflow["flags"]
                                  and subflow["local"] == own["local"] and subflow["remote"] == own["remote"])
                accepted_join = (role == "exit" and "J" in subflow["flags"] and "j" not in subflow["flags"]
                                 and subflow["local_id"] > 0 and subflow["remote_id"] > 0)
                token = int(subflow["remote_token"], 16)
                require(token == int(peer["token"], 16) or (token == 0 and (initial_socket or accepted_join)),
                        "subflow does not identify the same peer MPTCP meta socket")
        if index:
            stable(e[stages[index - 1]], sample)
    require({p["path_id"] for p in e["baseline"]["client"]["kernel"]["subflows"]} == initial,
            "initial socket differs from initial active subset")
    G.progress(e["baseline"], e["initial_progress"], 2)
    G.progress(e["warm"], e["warm_progress"], 3)
    retired(e["warm_progress"], e["retiring"], e["retired"], e["layout_initial"], warm, next(iter(initial - {risky})))
    require(e["retired"]["observed_monotonic_ns"] < e["exposure"]["started_monotonic_ns"]
            < e["refilled"]["started_monotonic_ns"], "R4 became eligible before warm exhaustion")
    require(e["retired"]["started_monotonic_ns"] - e["warm_progress"]["observed_monotonic_ns"] >= 10_000_000_000,
            "old warm path lacks a real retirement interval")
    require(e["exposure"]["relay_peer_id"] == e["expected_peers"]["relay4"]
            and e["exposure"]["capacity_before_mbps"] == 1 and e["exposure"]["capacity_after_mbps"] == 32
            and e["exposure"]["helper_pid_before"] == e["exposure"]["helper_pid_after"] > 0
            and e["exposure"]["agent_pid_before"] != e["exposure"]["agent_pid_after"] > 0,
            "R4 capacity exposure replaced identity/helper or is not the declared transition")
    progress_path(e["refilled"], e["refilled_progress"], 4)
    progress_path(e["refilled"], e["refilled_progress"], next(iter(initial - {risky})))
    for key, path in (("risky", risky), ("warm", warm)):
        node = next(p["relay_node"] for p in e["owners_initial"]["exit"]["paths"] if p["path_id"] == path)
        require(e["injection"][f"{key}_interface"] == f"xr{node[-1]}", "foreign impairment interface")
        before, during, after = (e["qdiscs"][key][s] for s in ("before", "during", "after"))
        G.COMMON["qdisc"](before, False)
        G.COMMON["qdisc"](after, False)
        require(len(during) == 1 and during[0]["kind"] == "netem" and during[0]["root"] is True
                and during[0]["handle"] == ("7b01:" if key == "risky" else "7b02:")
                and during[0]["drops"] > 0 and abs(during[0]["options"]["loss-random"]["loss"] - 1) < 0.000001,
                "missing actual owned 100percent impairment drops")
    require(set(e["rate_limits"]) == ORIGINAL_RELAYS | {"relay4"}, "download profile missing")
    for phases in e["rate_limits"].values():
        for stage in ("before", "after"):
            G.COMMON["qdisc"](phases[stage], False)
        require(len(phases["during"]) == 1 and phases["during"][0]["kind"] == "tbf"
                and phases["during"][0]["handle"] == "7b03:"
                and phases["during"][0]["options"]["rate"] == 1000000, "not fixed 8Mbps download leg")
    for phase in ("initial", "expanded"):
        captures = e["privacy"][phase]
        require(set(captures) == set(ROLES), "physical observer coverage incomplete")
        for role, capture in captures.items():
            G.COMMON["drained"](capture, allow_empty=role == "relay4" and phase == "initial")
            require(capture["capture_role"] == role and capture["unexpected_outer_packets"] == 0
                    and capture["direct_client_exit_packets"] == 0
                    and capture["expected_link_down_notifications"] == 0, "privacy boundary violated")
            if role.startswith("relay"):
                require(capture["internet_destination_outer_packets"] == 0
                        and set(capture["interfaces"]) == {f"r{role[-1]}c", f"r{role[-1]}x", "underlay"},
                        "relay capture lacks full physical coverage or exposes destination")
        require(captures["client"]["internet_destination_outer_packets"] == 0, "direct destination traffic")
        require(captures["exit"]["client_public_packets"] == 0
                and captures["exit"]["outbound_client_discovery_attempt_packets"] == 0
                and set(captures["client"]["interfaces"]) == {"cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cb1", "cb2", "underlay"}
                and set(captures["exit"]["interfaces"]) == {"xr0", "xr1", "xr2", "xr3", "xr4", "xr5", "xd", "underlay"},
                "Client/Exit physical privacy coverage incomplete")
        if phase == "expanded":
            r4 = captures["relay4"]
            require(r4["client_leg_wireguard_data_datagrams"] > 16 and r4["exit_leg_wireguard_data_datagrams"] > 16
                    and captures["client"]["relay4_wireguard_data_datagrams"] > 16
                    and captures["exit"]["relay4_wireguard_data_datagrams"] > 16, "both fresh R4 WG legs lack real data")
        else:
            for node in original:
                require(captures[node]["client_leg_wireguard_data_datagrams"] > 16
                        and captures[node]["exit_leg_wireguard_data_datagrams"] > 16
                        and captures["client"][f"{node}_wireguard_data_datagrams"] > 16
                        and captures["exit"][f"{node}_wireguard_data_datagrams"] > 16,
                        "both original selected WG legs lack real data")
    seed = b"volparossa-download:a04:" + bytes.fromhex(e["run_id"])
    block = (seed * (65536 // len(seed) + 1))[:65536]
    digest = hashlib.sha256()
    for _ in range(BODY_BYTES // len(block)):
        digest.update(block)
    request = b"volparossa-mptcp-refill:" + bytes.fromhex(e["run_id"]) + bytes(4)
    for receipt in (e["client"], e["server"]):
        require(receipt["case"] == PREFIX and receipt["attempt"] == 0
                and receipt["response_bytes"] == BODY_BYTES and receipt["response_sha256"] == digest.hexdigest()
                and receipt["request_bytes"] == len(request)
                and receipt["request_sha256"] == hashlib.sha256(request).hexdigest(), "incomplete original application payload")
    require(e["server"]["source"]["ip"] == "47.163.4.1"
            and e["server"]["listen"] == dict(ip="47.163.4.2", port=18080)
            and 0 < e["server"]["source"]["port"] <= 65535
            and e["client"]["application"]["ip"] == "169.254.240.1"
            and 0 < e["client"]["application"]["port"] <= 65535
            and e["client"]["destination"] == e["server"]["listen"], "normal protected ingress/egress bypassed")
    require(e["client"]["completed_monotonic_ns"] - e["client"]["first_byte_monotonic_ns"]
            == e["client"]["duration_ns"] > 0
            and e["client"]["first_byte_monotonic_ns"] < e["initial_progress"]["observed_monotonic_ns"]
            < e["refilled_progress"]["observed_monotonic_ns"] < e["client"]["completed_monotonic_ns"],
            "fresh path observation was not during the same application download")
    require(e["cleanup"] == dict(application_complete=True, route_disconnected=True, owned_qdiscs_removed=True),
            "flow/qdisc cleanup incomplete")


def build(work):
    work = Path(work)
    keys = ("selection", "layout_initial", "layout_refilled", "owners_initial", "owners_refilled", "baseline",
            "initial_progress", "warm", "warm_progress", "retiring", "retired", "refilled", "refilled_progress", "injection",
            "exposure", "client", "server", "cleanup")
    e = {key: read(work / f"{PREFIX}-{key.replace('_', '-')}.json") for key in keys}
    e.update(success=True, acceptance_version=ACCEPTANCE_VERSION,
             run_id=read(work / f"{PREFIX}-run.json")["run_id"], expected_peers=read(work / "a01-expected-peers.json"),
             qdiscs={key: {stage: json.loads(text(work / f"{PREFIX}-{key}-{stage}.json")) for stage in ("before", "during", "after")}
                     for key in ("risky", "warm")},
             rate_limits={f"relay{i}": {s: json.loads(text(work / f"{PREFIX}-rate-{i}-{s}.json")) for s in ("before", "during", "after")}
                          for i in (0, 1, 2, 3, 4)},
             privacy={phase: {role: read(work / f"{PREFIX}-{phase}-privacy-{role}.json") for role in ROLES}
                      for phase in ("initial", "expanded")})
    raw = selected(text(work / f"{PREFIX}-selection.txt"), e["expected_peers"])
    for phase, capacity in (("before", 1), ("after", 32)):
        config = text(work / f"{PREFIX}-r4-config-{phase}.yaml")
        require(re.findall(r"^  relay_(?:upload|download)_limit_mbps: (\d+)$", config, re.M) == [str(capacity)] * 2,
                "retained R4 configuration does not match capacity exposure")
    require(raw["paths"] == e["selection"]["paths"] and raw["route_context_id"] == e["selection"]["route_context_id"],
            "selection differs from raw CLI")
    require("connected: false" in text(work / f"{PREFIX}-final-status.txt").splitlines()
            and "active contexts: 0" in text(work / f"{PREFIX}-final-status.txt").splitlines()
            and text(work / f"{PREFIX}-final-paths.txt") == "", "final route still present")
    validate(e)
    return e


def main(args):
    if len(args) == 4 and args[0] == "select":
        result = selected(text(Path(args[1])), read(Path(args[2])))
    elif len(args) == 2 and args[0] == "original-relays":
        original_relays(read(Path(args[1]))); return
    elif len(args) == 3 and args[0] == "owners":
        result = G.owner_namespaces(read(Path(args[1])))
    elif len(args) == 4 and args[0] == "sample":
        result = sample(read(Path(args[1])), read(Path(args[2])))
    elif len(args) == 6 and args[0] == "sample":
        result = sample(read(Path(args[1])), read(Path(args[2])), read(Path(args[3])), int(args[4]))
    elif len(args) == 5 and args[0] == "retirement-candidate":
        retirement_candidate(read(Path(args[1])), read(Path(args[2])), read(Path(args[3])), int(args[4])); return
    elif len(args) == 7 and args[0] == "retired":
        retired(read(Path(args[1])), read(Path(args[2])), read(Path(args[3])), read(Path(args[4])), int(args[5]), int(args[6])); return
    elif len(args) == 4 and args[0] == "progress":
        G.progress(read(Path(args[1])), read(Path(args[2])), int(args[3])); return
    elif len(args) == 4 and args[0] == "path-progress":
        progress_path(read(Path(args[1])), read(Path(args[2])), int(args[3])); return
    elif len(args) == 3 and args[0] == "evidence":
        result = build(args[1])
    elif len(args) == 3 and args[0] == "report":
        path = Path(args[1]); report = read(path)
        require(re.fullmatch(r"[0-9a-f]{40}", args[2]) and report["source_revision"] == args[2]
                and report["schema_version"] == 1 and report["report_kind"] == "volparossa-mptcp-refill-runtime"
                and report.get("acceptance_version") == ACCEPTANCE_VERSION
                and report["success"] is True and report["phase"] == "mptcp-refill-complete"
                and report["cleanup"] == dict(complete=True, remaining_owned_objects=0)
                and report["observed_blocker"] in (None, "NONE"), "wrong source or failed cleanup")
        host = report["host_state"]
        require(host["success"] is True and host["unchanged"] is True
                and host["before_sha256"] == host["after_sha256"], "host changed")
        for stage in ("before", "after"):
            file = path.parent / f"host-state-{stage}.json"
            require(not file.is_symlink() and file.stat().st_size <= 8388608
                    and hashlib.sha256(file.read_bytes()).hexdigest() == host[f"{stage}_sha256"], "host evidence hash differs")
        e = build(path.parent)
        require(report["transfer"] == e == read(path.parent / f"{PREFIX}-evidence.json")
                and report["run_id"] == e["run_id"], "report differs from original evidence"); return
    else:
        raise ValueError("usage: select PATHS PEERS OUT | original-relays OWNERS | owners LAYOUT OUT | sample OWNERS LAYOUT [WARM_ANCHOR WARM_ID] OUT | retirement-candidate ANCHOR CURRENT LAYOUT WARM_ID | retired ANCHOR BEFORE AFTER LAYOUT WARM_ID HEALTHY_ID | progress BEFORE AFTER COUNT | path-progress BEFORE AFTER PATH | evidence WORK OUT | report REPORT SHA")
    Path(args[-1]).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    if args[0] == "sample":
        require(all("kernel" in result[r] for r in ("client", "exit")), "incomplete raw kernel snapshot retained")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"MPTCP refill proof unavailable: {error}", file=sys.stderr)
        sys.exit(1)
