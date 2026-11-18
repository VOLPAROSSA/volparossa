#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe the disposable repair agent's kernel mDNS memberships before its unit stops."""

import json
import os
from pathlib import Path
import re
import runpy
import socket
import subprocess
import sys
import time

CAPTURE = runpy.run_path(str(Path(__file__).with_name("content-replication-capture.py")))
GROUP = "224.0.0.251"
SYSCTL = Path("/proc/sys/net/ipv4")


def joined_interfaces(table):
    # /proc/net/igmp displays IPv4 groups as native-endian hexadecimal words.
    group_word = f"{int.from_bytes(socket.inet_aton(GROUP), sys.byteorder):08X}"
    joined = {}
    interface = None
    lines = table.splitlines()
    if not lines or lines[0].split()[:2] != ["Idx", "Device"]:
        raise ValueError("unexpected kernel IGMP membership table")
    for line in lines[1:]:
        header = re.fullmatch(r"\s*(\d+)\s+(\S+?)\s*:\s*\d+\s+V[123]\s*", line)
        if header:
            interface = (header[2], int(header[1]))
        else:
            fields = line.split()
            if not interface or len(fields) != 4 or not re.fullmatch(r"[0-9A-Fa-f]{8}", fields[0]):
                raise ValueError("unexpected kernel IGMP membership row")
            if fields[0].upper() == group_word and int(fields[1]) > 0:
                joined[interface[0]] = interface[1]
    return joined


def namespace_identity(pid):
    ns = os.stat(f"/proc/{pid}/ns/net")
    return f"{ns.st_dev}:{ns.st_ino}"


def snapshot(node, pid, expected_namespace):
    if node not in ("relay4", "relay5") or pid <= 0:
        raise ValueError("expected a live repair holder or receiver")
    if namespace_identity("self") != expected_namespace or namespace_identity(pid) != expected_namespace:
        raise ValueError("membership observer and live agent must share the named namespace")
    links = json.loads(subprocess.run(["ip", "-j", "-4", "address", "show"], check=True,
                                      timeout=5, stdout=subprocess.PIPE).stdout)
    joined = joined_interfaces(Path("/proc/net/igmp").read_text(encoding="ascii"))
    observed = {}
    for link in links:
        name = link["ifname"]
        assigned = CAPTURE["MDNS_INTERFACE_ADDRESSES"].get((node, name))
        if not assigned or joined.get(name) != link["ifindex"]:
            continue
        label = node + (".public" if name == "underlay" else "." + name)
        sources = [address["local"] for address in link["addr_info"] if address["family"] == "inet"
                   and address["local"] in assigned and CAPTURE["FIXTURE_ADDRESS_LABELS"].get(address["local"]) == label]
        if len(sources) != 1:
            raise ValueError("joined physical fixture interface lacks its unique assigned node address")
        interval = int((SYSCTL / "conf" / name / "igmpv3_unsolicited_report_interval").read_text(encoding="ascii"))
        observed[name] = dict(source=sources[0], interval_ms=interval)
    robustness = int((SYSCTL / "igmp_qrv").read_text(encoding="ascii"))
    if namespace_identity(pid) != expected_namespace:
        raise ValueError("agent namespace changed while reading memberships")
    return dict(pid_before=pid, network_namespace_identity=expected_namespace, group=GROUP,
                robustness=robustness, interfaces=observed, observed_ns=time.monotonic_ns())


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: content-repair-memberships.py NODE MAIN_PID NAMESPACE_DEVICE:INODE")
    print(json.dumps(snapshot(sys.argv[1], int(sys.argv[2]), sys.argv[3]), sort_keys=True))
