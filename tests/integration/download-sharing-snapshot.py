#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only, exact-worker receive/sender observations inside the disposable KVM fixture."""

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


MAX_JSON = 2 * 1024 * 1024
LABEL = re.compile(r"(?:baseline|idle|owner|recovery|expiry)-(?:before|after)|stopped-(?:before|after)|cleanup")


def read_json(path):
    if path.is_symlink() or path.stat().st_size > MAX_JSON:
        raise ValueError("unsafe bounded snapshot input")
    return json.loads(path.read_text(encoding="ascii"))


def command(arguments, descriptor=None, json_output=True):
    result = subprocess.run(arguments, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=3,
                            pass_fds=() if descriptor is None else (descriptor,))
    if len(result.stdout) > MAX_JSON or len(result.stderr) > 16384:
        raise ValueError("diagnostic output bound")
    text = result.stdout.decode("ascii")
    return json.loads(text) if json_output else text.strip()


def diagnostic(namespace, arguments):
    return command(["ip", "netns", "exec", namespace, *arguments])


def number(value):
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        raise ValueError("invalid kernel counter")
    return value


def counter(record):
    required = ("bytes", "packets", "drops", "overlimits", "backlog")
    return {field: number(record[field]) for field in required}


def sender_queue(records, path_id):
    root_handle = f"{0x6000 + 2 * path_id:x}:"
    leaf_handle = f"{0x6001 + 2 * path_id:x}:"
    roots = [row for row in records if row.get("handle") == root_handle
             and row.get("kind") == "tbf" and row.get("root") is True]
    leaves = [row for row in records if row.get("handle") == leaf_handle
              and row.get("kind") == "fq_codel" and row.get("parent") == root_handle + "1"]
    if len(records) != 2 or len(roots) != 1 or len(leaves) != 1:
        raise ValueError("exact owned sender queue tree unavailable")
    limit = number(leaves[0].get("options", {}).get("memory_limit"))
    if not 1 <= limit <= 131072:
        raise ValueError("sender queue memory bound unavailable")
    return counter(roots[0]), limit


def gate_interface(ruleset, context, path_id, links):
    expected = f"vpd_{context}_{path_id}"
    tables = [entry["table"] for entry in ruleset["nftables"] if "table" in entry
              and entry["table"].get("name") == expected]
    if not tables:
        return None
    if len(tables) != 1 or tables[0].get("family") != "netdev":
        raise ValueError("ambiguous exact route gate")
    family = tables[0]["family"]
    chains = [entry["chain"] for entry in ruleset["nftables"] if "chain" in entry
              and entry["chain"].get("table") == expected]
    rules = [entry["rule"] for entry in ruleset["nftables"] if "rule" in entry
             and entry["rule"].get("table") == expected]
    if len(chains) != 1 or not 1 <= len(rules) <= 2:
        raise ValueError("incomplete route gate")
    chain = chains[0]
    if (chain.get("family") != family or chain.get("hook") != "egress"
            or chain.get("name") != "egress" or chain.get("prio") != 0):
        raise ValueError("unexpected route gate hook")
    names = []
    indices = []
    for rule in rules:
        if rule.get("family") != family or rule.get("chain") != chain.get("name"):
            raise ValueError("mixed route gate rules")
        matches = [item["match"] for item in rule["expr"] if "match" in item]
        for key, target in (("oifname", names), ("oif", indices)):
            matched = [match["right"] for match in matches
                       if match.get("left") == {"meta": {"key": key}} and match.get("op") == "=="]
            if len(matched) != 1:
                raise ValueError("missing exact output interface match")
            target.extend(matched)
    devices = chain.get("dev", chain.get("devices"))
    if isinstance(devices, str):
        devices = [devices]
    if not isinstance(devices, list) or len(devices) != 1:
        raise ValueError("ambiguous egress gate device")
    names.extend(devices)
    if not names or len(set(names)) != 1:
        raise ValueError("inconsistent route gate interface names")
    name = names[0]
    found = [link for link in links if link.get("ifname") == name]
    if len(found) != 1:
        raise ValueError("gate has no exact kernel interface")
    link = found[0]
    alias = link.get("ifalias", "")
    if (link.get("linkinfo", {}).get("info_kind") != "wireguard"
            or not re.fullmatch(rf"vpe{path_id:x}[0-9a-f]{{8}}", name)
            or not re.fullmatch(r"volparossa:wireguard:ownership-v1:" + re.escape(name) + r":[0-9a-f]{64}", alias)
            or any(index not in (link["ifindex"], name) for index in indices)):
        raise ValueError("gate does not bind the owned Exit WireGuard endpoint")
    return {"interface": name, "ifindex": number(link["ifindex"]), "mtu": number(link["mtu"]),
            "ownership_alias": alias, "gate_table": expected, "gate_family": family}


def process_identity(pid):
    proc = Path(f"/proc/{pid}")
    stat = (proc / "stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
    return stat[19], (proc / "cgroup").read_text(encoding="ascii")


def worker_snapshot(exit_namespace, binaries, selection):
    unit = "volparossa-alpha-helper@exit.service"
    cgroup = command(["systemctl", "show", "--property=ControlGroup", "--value", unit], json_output=False)
    if not cgroup.startswith("/system.slice/") or ".." in cgroup.split("/"):
        raise ValueError("unexpected helper cgroup")
    root = Path("/sys/fs/cgroup" + cgroup)
    pids = set()
    for index, entry in enumerate(root.rglob("cgroup.procs")):
        if index >= 128:
            raise ValueError("helper cgroup bound")
        pids.update(int(value) for value in entry.read_text(encoding="ascii").split())
        if len(pids) > 128:
            raise ValueError("helper process bound")
    parent = os.stat(f"/run/netns/{exit_namespace}")
    outer = os.stat("/proc/self/ns/net")
    prohibited = {(parent.st_dev, parent.st_ino), (outer.st_dev, outer.st_ino)}
    snapshots = []
    for pid in sorted(pids):
        proc = Path(f"/proc/{pid}")
        try:
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            continue
        if b"--internal-worker-v3" not in argv:
            continue
        if (proc / "exe").resolve(strict=True) != (binaries / "volparossa-helper").resolve(strict=True):
            raise ValueError("helper worker executable mismatch")
        identity = process_identity(pid)
        observed_cgroups = [line.split(":", 2)[2] for line in identity[1].splitlines()]
        if not any(value == cgroup or value.startswith(cgroup + "/") for value in observed_cgroups):
            raise ValueError("worker left its helper cgroup")
        descriptor = os.open(proc / "ns/net", os.O_RDONLY | os.O_CLOEXEC)
        try:
            pinned = os.fstat(descriptor)
            if (pinned.st_dev, pinned.st_ino) in prohibited:
                raise ValueError("worker is not in an isolated route namespace")
            prefix = ["nsenter", f"--net=/proc/self/fd/{descriptor}", "--"]
            rules = command([*prefix, "nft", "-j", "list", "ruleset"], descriptor)
            links = command([*prefix, "ip", "-j", "-details", "link", "show"], descriptor)
            bound = gate_interface(rules, selection["route_context_id"], selection["path_id"], links)
            if bound is None:
                continue
            qdiscs = command([*prefix, "tc", "-s", "-j", "qdisc", "show", "dev", bound["interface"]], descriptor)
            queue, limit = sender_queue(qdiscs, selection["path_id"])
            if process_identity(pid) != identity:
                raise ValueError("worker identity changed during observation")
            current = os.stat(proc / "ns/net")
            if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise ValueError("worker namespace changed during observation")
            snapshots.append({"sender_identity": {**bound, "pid": pid, "start_ticks": identity[0],
                              "namespace_device": pinned.st_dev, "namespace_inode": pinned.st_ino},
                              "sender_queue": queue, "sender_maximum_queued_bytes": limit,
                              "sender_qdiscs": qdiscs})
        finally:
            os.close(descriptor)
    if len(snapshots) != 1:
        raise ValueError("exact selected Exit sender worker unavailable or ambiguous")
    return snapshots[0]


def receive_snapshot(namespace, cleanup):
    links = diagnostic(namespace, ["ip", "-s", "-j", "link", "show", "dev", "down0"])
    if len(links) != 1:
        raise ValueError("exact receiving interface unavailable")
    rules = diagnostic(namespace, ["nft", "-j", "list", "ruleset"])
    tables = [row["table"] for row in rules["nftables"] if "table" in row
              and re.fullmatch(r"vprx_[0-9a-f]{24}", row["table"].get("name", ""))]
    if len(tables) != (0 if cleanup else 1):
        raise ValueError("receive accounting table count mismatch")
    stats = links[0].get("stats64", links[0].get("stats"))["rx"]
    result = {"receiver_ifindex": number(links[0]["ifindex"]),
              "receiver_physical_rx_bytes": number(stats["bytes"]),
              "accounting_removed": not tables, "receiver_ruleset": rules}
    if cleanup:
        return result
    table = tables[0]
    chains = [row["chain"] for row in rules["nftables"] if "chain" in row
              and row["chain"].get("table") == table["name"]]
    if (table.get("family") != "netdev" or len(chains) != 1
            or chains[0].get("hook") != "ingress"
            or chains[0].get("dev", chains[0].get("devices")) not in ("down0", ["down0"])):
        raise ValueError("counter is not on the selected NETDEV ingress")
    matched = [row["rule"] for row in rules["nftables"] if "rule" in row
               and row["rule"].get("table") == table["name"]]
    totals = [row for row in matched if len(row["expr"]) == 1 and "counter" in row["expr"][0]]
    if len(totals) != 1 or not 1 <= len(matched) <= 129:
        raise ValueError("exact TOTAL rule or bounded managed counters unavailable")
    result["receiver_total_bytes"] = number(totals[0]["expr"][0]["counter"]["bytes"])
    result["receiver_total_packets"] = number(totals[0]["expr"][0]["counter"]["packets"])
    result["receiver_managed_rules"] = [row for row in matched if row is not totals[0]]
    return result


def main():
    if len(sys.argv) != 8:
        raise ValueError("snapshot argument count")
    work, run_id, relay_ns, fanout_ns, exit_ns, binaries, label = sys.argv[1:]
    work, binaries = Path(work), Path(binaries)
    if (os.geteuid() != 0 or socket.gethostname() != "volparossa-alpha"
            or not re.fullmatch(r"[0-9a-f]{32}", run_id) or not LABEL.fullmatch(label)
            or work.is_symlink() or work.parent != Path("/opt")
            or not work.name.startswith(f"va.{run_id}.")):
        raise ValueError("not an explicitly disposable fixture snapshot")
    if command(["systemd-detect-virt"], json_output=False) != "kvm":
        raise ValueError("snapshot requires disposable KVM")
    selection = read_json(work / "download-sharing-selection.json")
    if (selection.get("relay_node") not in ("relay0", "relay2")
            or not re.fullmatch(r"[0-9a-f]{32}", selection.get("route_context_id", ""))
            or not 1 <= number(selection.get("path_id")) <= 8):
        raise ValueError("invalid selected route")
    expected_relay = "r0" if selection["relay_node"] == "relay0" else "r2"
    prefix = f"va-{run_id[:8]}"
    if (relay_ns != f"{prefix}-{expected_relay}" or fanout_ns != f"{prefix}-b1"
            or exit_ns != f"{prefix}-x"):
        raise ValueError("snapshot namespace is outside this exact fixture")
    result = {"schema_version": 1, "run_id": run_id, "label": label,
              "monotonic_ns": time.monotonic_ns(), "selection": selection}
    result.update(receive_snapshot(relay_ns, label == "cleanup"))
    if label == "cleanup":
        result["receiver_cleanup"] = [
            {"relay_node": node, **receive_snapshot(f"{prefix}-{suffix}", True)}
            for node, suffix in (("relay0", "r0"), ("relay2", "r2"))]
        result["accounting_removed"] = all(row["accounting_removed"] for row in result["receiver_cleanup"])
    if label != "cleanup":
        result.update(worker_snapshot(exit_ns, binaries, selection))
        device = "d0" if selection["relay_node"] == "relay0" else "d2"
        result["physical_qdiscs"] = diagnostic(fanout_ns, ["tc", "-s", "-j", "qdisc", "show", "dev", device])
        physical = [queue for queue in result["physical_qdiscs"]
                    if queue.get("kind") == "tbf" and queue.get("root") is True]
        if len(physical) != 1:
            raise ValueError("exact physical receiving-link bottleneck unavailable")
        result["physical_queue"] = counter(physical[0])
    destination = work / f"download-sharing-{label}.json"
    with destination.open("x", encoding="ascii") as output:
        json.dump(result, output, sort_keys=True)
        output.write("\n")


if __name__ == "__main__":
    main()
