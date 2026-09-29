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

spec = importlib.util.spec_from_file_location("mptcp_growth_reader", Path(__file__).with_name("mptcp-growth-smoke.py"))
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
# This instance only: reuse exact raw ss/namespace readers, not the old scenario's acceptance.
G.RELAY_IPS = {**G.RELAY_IPS, "49.165.5.1": "relay4"}
read, text, require = G.read, G.text, G.require
PREFIX = "mptcp-refill"
BODY_BYTES = 256 * 1024 * 1024
ROLES = ("client", "relay0", "relay1", "relay2", "relay4", "exit")


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
        require({p["relay_node"] for p in old["paths"]} == {"relay0", "relay1", "relay2"},
                "fresh Relay was present in initial owned path set")
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
    stages = ("baseline", "initial_progress", "warm", "warm_progress", "retired", "refilled", "refilled_progress")
    for index, name in enumerate(stages):
        sample = e[name]
        layout = e["layout_refilled"] if name.startswith("refilled") else e["layout_initial"]
        for role in ("client", "exit"):
            require(sample[role]["kernel"] == G.kernel_sample(sample[role]["raw"], layout, role),
                    "projected kernel evidence differs from original ss")
        client, exit_side = sample["client"]["kernel"], sample["exit"]["kernel"]
        require({p["path_id"] for p in client["subflows"]} == {p["path_id"] for p in exit_side["subflows"]},
                "both endpoints do not see the same subflows")
        for row in client["subflows"]:
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
    require(all(warm not in {p["path_id"] for p in e["retired"][role]["kernel"]["subflows"]}
                for role in ("client", "exit")), "old warm subflow was not retired before refill")
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
    require(set(e["rate_limits"]) == {"relay0", "relay1", "relay2", "relay4"}, "download profile missing")
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
            "initial_progress", "warm", "warm_progress", "retired", "refilled", "refilled_progress", "injection",
            "exposure", "client", "server", "cleanup")
    e = {key: read(work / f"{PREFIX}-{key.replace('_', '-')}.json") for key in keys}
    e.update(success=True, run_id=read(work / f"{PREFIX}-run.json")["run_id"], expected_peers=read(work / "a01-expected-peers.json"),
             qdiscs={key: {stage: json.loads(text(work / f"{PREFIX}-{key}-{stage}.json")) for stage in ("before", "during", "after")}
                     for key in ("risky", "warm")},
             rate_limits={f"relay{i}": {s: json.loads(text(work / f"{PREFIX}-rate-{i}-{s}.json")) for s in ("before", "during", "after")}
                          for i in (0, 1, 2, 4)},
             privacy={phase: {role: read(work / f"{PREFIX}-{phase}-privacy-{role}.json") for role in ROLES}
                      for phase in ("initial", "expanded")})
    raw = G.selected(text(work / f"{PREFIX}-selection.txt"), e["expected_peers"])
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
        result = G.selected(text(Path(args[1])), read(Path(args[2])))
    elif len(args) == 3 and args[0] == "owners":
        result = G.owner_namespaces(read(Path(args[1])))
    elif len(args) == 4 and args[0] == "sample":
        result = G.sample(read(Path(args[1])), read(Path(args[2])))
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
        raise ValueError("usage: select PATHS PEERS OUT | owners LAYOUT OUT | sample OWNERS LAYOUT OUT | progress BEFORE AFTER COUNT | path-progress BEFORE AFTER PATH | evidence WORK OUT | report REPORT SHA")
    Path(args[-1]).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    if args[0] == "sample":
        require(all("kernel" in result[r] for r in ("client", "exit")), "incomplete raw kernel snapshot retained")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"MPTCP refill proof unavailable: {error}", file=sys.stderr)
        sys.exit(1)
