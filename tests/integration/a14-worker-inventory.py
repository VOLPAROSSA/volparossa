#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only A14 worker classification from bounded, pinned-namespace kernel snapshots."""

import json
from pathlib import Path
import re
import sys


def load(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 262144:
        raise ValueError("unbounded A14 inventory input")
    return json.loads(path.read_text(encoding="ascii"))


def rows(path, maximum):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 1048576:
        raise ValueError("unbounded A14 inventory rows")
    lines = path.read_text(encoding="ascii").splitlines()
    if len(lines) > maximum:
        raise ValueError("too many A14 inventory rows")
    return [json.loads(line) for line in lines]


def interfaces(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise ValueError("invalid bounded network snapshot")
    names = set()
    for link in value:
        if link.get("ifname") in names or not isinstance(link.get("ifindex"), int) or link["ifindex"] <= 0:
            raise ValueError("duplicate or invalid kernel interface")
        names.add(link.get("ifname"))
    return [link for link in value if link.get("ifname") != "lo"]


def kind(link):
    return link.get("linkinfo", {}).get("info_kind")


def has_address(link, address):
    return any(item.get("family") == "inet" and item.get("local") == address
               and item.get("prefixlen") == 30 for item in link.get("addr_info", []))


def classify(parent_snapshot, worker_snapshot):
    parent_links, worker_links = interfaces(parent_snapshot), interfaces(worker_snapshot)
    ingress = [link for link in worker_links if re.fullmatch(r"vpiw[0-9a-f]{8}", link["ifname"])]
    if ingress:
        if len(ingress) != 1 or len(worker_links) != 1:
            raise ValueError("ambiguous or mixed ingress/route worker")
        worker = ingress[0]
        parent_name = "vpih" + worker["ifname"][4:]
        parents = [link for link in parent_links if link["ifname"] == parent_name]
        if len(parents) != 1:
            raise ValueError("ingress worker has no exact same-runtime parent endpoint")
        parent = parents[0]
        if (kind(parent) != "veth" or kind(worker) != "veth"
                or parent.get("link_index") != worker["ifindex"]
                or worker.get("link_index") != parent["ifindex"]
                or not has_address(parent, "169.254.240.1")
                or not has_address(worker, "169.254.240.2")):
            raise ValueError("ingress reciprocal-veth or fixed address provenance mismatch")
        return {"ownership_class": "live_client_ingress", "durable_descriptors_required": 0,
                "ownership_provenance": {"parent_interface": parent_name,
                    "worker_interface": worker["ifname"], "parent_ifindex": parent["ifindex"],
                    "worker_ifindex": worker["ifindex"], "reciprocal_veth_indices": True,
                    "parent_address": "169.254.240.1/30", "worker_address": "169.254.240.2/30"}}
    if not worker_links or len(worker_links) > 16:
        raise ValueError("worker has no bounded owned route interfaces")
    proven = []
    for link in worker_links:
        name = link["ifname"]
        prefix = "volparossa:wireguard:ownership-v1:" + name + ":"
        alias = link.get("ifalias", "")
        if (kind(link) != "wireguard" or not re.fullmatch(r"vp[a-z0-9]{1,13}", name)
                or not alias.startswith(prefix) or not re.fullmatch(r"[0-9a-f]{64}", alias[len(prefix):])):
            raise ValueError("unclassified worker or invalid exact WireGuard ownership alias")
        proven.append({"interface": name, "ifindex": link["ifindex"], "ownership_alias": alias})
    return {"ownership_class": "durable_route", "durable_descriptors_required": 2,
            "ownership_provenance": {"wireguard_interfaces": proven}}


def summarize(workers, helpers):
    if not isinstance(workers, list) or not 1 <= len(workers) <= 128 or len(helpers) != 11:
        raise ValueError("invalid bounded A14 worker/helper inventory")
    identities = [(worker["network_namespace_device"], worker["network_namespace_inode"]) for worker in workers]
    if len(set(identities)) != len(identities):
        raise ValueError("multiple worker processes share one supposedly isolated namespace")
    coverage = []
    helper_units = set()
    for helper in helpers:
        unit = helper["helper_unit"]
        if unit in helper_units:
            raise ValueError("duplicate helper unit")
        helper_units.add(unit)
        owned = [worker for worker in workers if worker["helper_unit"] == unit]
        routes = sum(worker["ownership_class"] == "durable_route" for worker in owned)
        ingress = sum(worker["ownership_class"] == "live_client_ingress" for worker in owned)
        if routes + ingress != len(owned) or ingress > 1:
            raise ValueError("unclassified or duplicate ingress worker")
        required = routes * 2
        observed = helper["fdstore_descriptors"]
        if not isinstance(observed, int) or not required <= observed <= 4096:
            raise ValueError("helper descriptor store does not cover its proven route workers")
        coverage.append({**helper, "durable_route_namespace_count": routes,
                         "live_ingress_namespace_count": ingress, "required_durable_descriptors": required})
    if any(worker["helper_unit"] not in helper_units for worker in workers):
        raise ValueError("worker has no observed helper ownership")
    return {"schema_version": 1, "worker_process_count": len(workers),
            "worker_network_namespace_count": len(identities),
            "durable_route_namespace_count": sum(row["durable_route_namespace_count"] for row in coverage),
            "live_ingress_namespace_count": sum(row["live_ingress_namespace_count"] for row in coverage),
            "helper_fdstore_descriptors": sum(row["fdstore_descriptors"] for row in coverage),
            "helper_custody_coverage": coverage, "worker_network_namespaces": workers}


if __name__ == "__main__":
    action, *args = sys.argv[1:]
    if action == "classify":
        node, unit, pid, device, inode, parent_path, worker_path = args
        result = {"node": node, "helper_unit": unit, "worker_pid_before": int(pid),
                  "network_namespace_device": int(device), "network_namespace_inode": int(inode),
                  **classify(load(parent_path), load(worker_path))}
    elif action == "summarize":
        workers = rows(args[0], 128)
        helpers = rows(args[1], 11)
        result = summarize(workers, helpers)
    else:
        raise ValueError("unknown inventory operation")
    print(json.dumps(result, sort_keys=True))
