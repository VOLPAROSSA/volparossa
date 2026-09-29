#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Owned Internet TAPs in four existing disposable KVM namespaces only.

slirp4netns lifecycle/options: https://github.com/rootless-containers/slirp4netns/blob/v1.2.3/slirp4netns.1.md
No host bridge, forwarding, DNS change, listener/API socket or firewall exemption.
"""
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

NODES = ("client", "relay0", "relay2", "exit")
TAP = "dnsup0"
CIDR = "10.242.93.0/24"
ADDRESS = "10.242.93.100"
GATEWAY = "10.242.93.2"
TABLE = "vpa_private_dns_fixture"
FILTER = """table inet vpa_private_dns_fixture {
 chain output { type filter hook output priority 10; policy accept;
  oifname "dnsup0" meta l4proto != { tcp, udp } drop
  oifname "dnsup0" th dport != 53 drop
 }
 chain input { type filter hook input priority 10; policy accept;
  iifname "dnsup0" ct state != established drop
  iifname "dnsup0" meta l4proto != { tcp, udp } drop
  iifname "dnsup0" th sport != 53 drop
 }
 chain forward { type filter hook forward priority 10; policy accept;
  iifname "dnsup0" drop
  oifname "dnsup0" drop
 }
}
"""
running = True


def require(condition):
    if not condition:
        raise ValueError("private DNS uplink ownership check failed")


def command(*args):
    return subprocess.check_output(args, text=True, timeout=10, stderr=subprocess.DEVNULL)


def write(path, value):
    temporary = path.with_suffix(".new")
    with temporary.open("w", encoding="ascii") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def guard(work, namespaces):
    require(os.geteuid() == 0 and command("hostname").strip() == "volparossa-alpha"
            and command("systemd-detect-virt").strip() == "kvm")
    require(work.is_absolute() and work.resolve() == work and work.parent == Path("/opt")
            and re.fullmatch(r"va\.[0-9a-f]{32}\.[A-Za-z0-9]{6}", work.name))
    require(len(namespaces) == 4 and len(set(namespaces)) == 4)
    parent = Path("/proc/self/ns/net").stat().st_ino
    identities = []
    for namespace in namespaces:
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", namespace))
        path = Path("/run/netns") / namespace
        require(path.is_file() and path.stat().st_ino != parent)
        identities.append(path.stat().st_ino)
    require(len(set(identities)) == 4)


def default_routes(namespace):
    return json.loads(command("ip", "-n", namespace, "-j", "route", "show", "default"))


def execute(work, namespaces):
    guard(work, namespaces)
    states, failures = [], []
    os.umask(0o077)
    try:
        for node, namespace in zip(NODES, namespaces):
            original = default_routes(namespace)
            require(len(original) == 1 and original[0].get("dev") == "underlay"
                    and original[0].get("dst") == "default" and "gateway" not in original[0])
            require(not any(row["ifname"] == TAP for row in json.loads(command("ip", "-n", namespace, "-j", "link"))))
            ready_r, ready_w = os.pipe()
            exit_r, exit_w = os.pipe()
            state = dict(node=node, namespace=namespace, original=original, changed=False, filter=False,
                         child=None, exit_fd=exit_w)
            states.append(state)
            try:
                tables = json.loads(command("ip", "netns", "exec", namespace, "nft", "-j", "list", "tables"))
                require(not any(row.get("table", {}).get("name") == TABLE for row in tables["nftables"]))
                # DROP-only fixture containment: synthetic peer /32 probes must never
                # reach the real Internet through these newly independent uplinks.
                # No UID exception or ACCEPT rule bypasses the product ingress/policy.
                subprocess.run(["ip", "netns", "exec", namespace, "nft", "-f", "-"], input=FILTER,
                               text=True, check=True, timeout=5)
                state["filter"] = True
                with (work / f"reciprocity-private-dns-uplink-{node}.log").open("xb") as log:
                    state["child"] = subprocess.Popen([
                        "slirp4netns", "--netns-type=path", "--disable-host-loopback", "--disable-dns",
                        "--enable-sandbox", "--enable-seccomp", "--cidr=" + CIDR, "--mtu=1500",
                        f"--ready-fd={ready_w}", f"--exit-fd={exit_r}",
                        "/run/netns/" + namespace, TAP,
                    ], pass_fds=(ready_w, exit_r), stdout=log, stderr=subprocess.STDOUT)
                os.close(ready_w)
                ready_w = None
                os.close(exit_r)
                exit_r = None
                require(select.select([ready_r], [], [], 5)[0] and os.read(ready_r, 2) == b"1")
                require(state["child"].poll() is None)
                links = json.loads(command("ip", "-n", namespace, "-j", "link", "show", "dev", TAP))
                require(len(links) == 1 and links[0]["ifname"] == TAP)
                state["ifindex"] = links[0]["ifindex"]
                command("ip", "-n", namespace, "addr", "add", ADDRESS + "/24", "dev", TAP)
                command("ip", "-n", namespace, "link", "set", "dev", TAP, "up")
                command("ip", "-n", namespace, "route", "replace", "default", "via", GATEWAY,
                        "dev", TAP, "src", ADDRESS)
                state["changed"] = True
            finally:
                for fd in (ready_r, ready_w, exit_r):
                    if fd is not None:
                        os.close(fd)
        write(work / "reciprocity-private-dns-uplinks-ready.json", dict(version=1, nodes=[
            dict(node=s["node"], namespace=s["namespace"], slirp_pid=s["child"].pid,
                 tap=TAP, ifindex=s["ifindex"], address=ADDRESS, gateway=GATEWAY,
                 builtin_dns=False, host_loopback=False, drop_only_fixture_containment=True) for s in states]))
        deadline = time.monotonic() + 900
        while running and time.monotonic() < deadline:
            require(all(s["child"].poll() is None for s in states))
            time.sleep(.1)
        require(not running)
    finally:
        for state in reversed(states):
            namespace, child = state["namespace"], state["child"]
            try:
                if state["changed"]:
                    current = default_routes(namespace)
                    require(len(current) == 1 and current[0].get("dev") == TAP
                            and current[0].get("gateway") == GATEWAY)
                    command("ip", "-n", namespace, "route", "replace", "default", "dev", "underlay", "scope", "global")
                os.close(state["exit_fd"])
                state["exit_fd"] = None
                if child is not None:
                    child.wait(timeout=5)
                    require(child.returncode == 0)
                require(not any(row["ifname"] == TAP for row in json.loads(command("ip", "-n", namespace, "-j", "link"))))
                require(default_routes(namespace) == state["original"])
                if state["filter"]:
                    command("ip", "netns", "exec", namespace, "nft", "delete", "table", "inet", TABLE)
                    state["filter"] = False
            except (OSError, ValueError, subprocess.SubprocessError):
                failures.append(state["node"])
            finally:
                if state["exit_fd"] is not None:
                    os.close(state["exit_fd"])
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
                    failures.append(state["node"])
        write(work / "reciprocity-private-dns-uplinks-cleanup.json", dict(version=1,
            complete=not failures, restored_nodes=[s["node"] for s in states if s["node"] not in failures],
            failed_nodes=sorted(set(failures)), owned_slirp_processes_reaped=all(
                s["child"] is None or s["child"].poll() is not None for s in states)))
    require(not failures)


def stop(*_args):
    global running
    running = False


if __name__ == "__main__":
    require(len(sys.argv) == 6)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    execute(Path(sys.argv[1]), sys.argv[2:])
