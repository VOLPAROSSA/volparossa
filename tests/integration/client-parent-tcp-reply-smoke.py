#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Reproduce kernel replies entering parent TPROXY before a trusted listener accepts.

The old parent rules reproduce RED. GREEN loads the actual helper-encoded batch
from the Rust regression. No substitute product rules are used for GREEN.
All sockets, veths and nftables live in disposable anonymous network namespaces.
"""

import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import time

SCRIPT = str(Path(__file__).resolve())
IP, NFT = "/usr/bin/ip", "/usr/sbin/nft"
UID = 987
PROVIDER, PEER = "198.18.0.1", "198.18.0.2"
PAYLOAD, REPLY = bytes(260), b"verified-tcp-reply"
LABEL_BITS = " ".join(f"ct label set {3 + 8 * index}" for index in range(16))
CONNMARK = "0x56504b52"
ENCODER = os.environ.get("VOLPAROSSA_REPLY_ENCODER")


def run(*args, text=None):
    try:
        return subprocess.check_output(args, input=text, text=True, stderr=subprocess.PIPE, timeout=5)
    except subprocess.CalledProcessError as error:
        # Only fixed diagnostic commands/fixtures, never user secrets.
        raise RuntimeError(error.stderr[:4096]) from error


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def receive(process, seconds=6):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(seconds):
            raise RuntimeError("bounded child response timeout")
    line = process.stdout.readline(8193)
    if not line or len(line) > 8192:
        raise RuntimeError("missing or oversized child response")
    return json.loads(line)


def command(process, operation):
    process.stdin.write(operation + "\n")
    process.stdin.flush()


def capless():
    # Called by re-exec only after all five capability sets have been removed.
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    assert os.getuid() == UID and os.getgid() == UID
    assert all(int(status[key], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    assert int(status["NoNewPrivs"]) == 1
    return dict(uid=UID, gid=UID, all_capabilities_zero=True, no_new_privileges=True,
                netns=os.readlink("/proc/self/ns/net"))


def drop_and_exec(mode, *args, pass_fds=()):
    # gid_map has setgroups=deny; retain only namespace-mapped existing groups.
    return subprocess.Popen(
        ["/usr/bin/setpriv", "--keep-groups", "--inh-caps=-all", "--ambient-caps=-all",
         "--bounding-set=-all", "--no-new-privs", "--", sys.executable, "-B", SCRIPT, mode, *args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, pass_fds=pass_fds)


def bootstrap(role):
    emit(dict(pid=os.getpid(), netns=os.readlink("/proc/self/ns/net")))
    assert sys.stdin.readline().strip() == "configure"
    run(IP, "link", "set", "lo", "up")
    device = "outside" if role == "peer" else "vpiw"
    address = PEER + "/30" if role == "peer" else "169.254.240.2/30"
    run(IP, "addr", "add", address, "dev", device)
    run(IP, "link", "set", device, "up")
    if role == "peer":
        child = drop_and_exec("--peer")
    else:
        run(IP, "route", "add", "default", "via", "169.254.240.1")
        run(IP, "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100")
        run(IP, "rule", "add", "fwmark", "0x56501001", "lookup", "100")
        run(NFT, "-f", "-", text="""
table inet diagnostic_worker {
 chain input {
  type filter hook prerouting priority mangle; policy drop;
  iifname != "vpiw" accept
  meta mark 0x56501001 accept
  meta nfproto ipv4 meta l4proto tcp tproxy ip to :39001 meta mark set 0x56501001 accept
 }
}
""")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT before dropping capabilities.
        listener.bind(("0.0.0.0", 39001))
        listener.listen(8)
        child = drop_and_exec("--worker", str(listener.fileno()), pass_fds=(listener.fileno(),))
        listener.close()
    emit(receive(child))
    try:
        for line in sys.stdin:
            operation = line.strip()
            command(child, operation)
            emit(receive(child))
            if operation == "stop":
                break
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=2)


def endpoint(role, *args):
    boundary = capless()
    emit(dict(ready=True, boundary=boundary))
    if role == "--original":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.bind((PROVIDER, 18082))
            stream.settimeout(0.5)
            try:
                stream.connect((PEER, 18081))
            except OSError:
                pass
        emit(dict(original_attempted=True, boundary=boundary))
        return
    if role == "--worker":
        # Keep the genuine transparent listener alive: stray ACKs are handled by TCP.
        listener = socket.socket(fileno=int(args[0]))
        assert sys.stdin.readline().strip() == "stop"
        listener.close()
        emit(dict(stopped=True))
        return
    for line in sys.stdin:
        operation = line.strip()
        if operation == "stop":
            emit(dict(stopped=True))
            break
        assert operation == "exchange"
        result = dict(boundary=boundary, connected=False, reply_verified=False)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.settimeout(2)
            try:
                stream.connect((PROVIDER, 18080))
                result["connected"] = True
                stream.sendall(PAYLOAD)
                result["reply_verified"] = stream.recv(256) == REPLY
            except (OSError, TimeoutError) as error:
                result["error_kind"] = type(error).__name__
        emit(result)


def server():
    boundary = capless()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 1)
        listener.bind((PROVIDER, 18080))
        listener.listen(8)
        listener.settimeout(3)
        emit(dict(ready=True, boundary=boundary))
        assert sys.stdin.readline().strip() == "exchange"
        time.sleep(0.4)  # Deliberate test-only pre-accept window; never a product scheduler change.
        result = dict(boundary=boundary, accepted=False, payload_verified=False)
        try:
            stream, _ = listener.accept()
            with stream:
                result["accepted"] = True
                stream.settimeout(2)
                received = bytearray()
                while len(received) < len(PAYLOAD):
                    chunk = stream.recv(len(PAYLOAD) - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
                result["payload_verified"] = bytes(received) == PAYLOAD
                if result["payload_verified"]:
                    stream.sendall(REPLY)
        except (OSError, TimeoutError) as error:
            result["error_kind"] = type(error).__name__
        emit(result)


def counters():
    state = json.loads(run(NFT, "-j", "list", "table", "inet", "diagnostic_observer"))
    result = {}
    for item in state["nftables"]:
        rule = item.get("rule", {})
        if "comment" in rule:
            result[rule["comment"]] = next(expr["counter"]["packets"]
                                          for expr in rule["expr"] if "counter" in expr)
    return result


def install_parent():
    # Exact relevant production order from helper/worker_v3/client_ingress_policy.rs:
    # known marks, loopback/owned veth, trusted agent socket UID, then IPv4 steering.
    run(IP, "route", "add", "default", "via", "169.254.240.2", "dev", "vpih", "table", "101")
    run(IP, "rule", "add", "priority", "9999", "fwmark", "0x56501002", "lookup", "101")
    Path("/proc/sys/net/ipv4/conf/vpih/src_valid_mark").write_text("1\n")
    run(NFT, "-f", "-", text="""
table inet diagnostic_parent {
 chain output {
  type route hook output priority mangle; policy drop;
  meta mark {0x56501002, 0x56501004, 0x56501001, 0x56503001, 0x56501003} accept
  oifname "lo" accept
  oifname "vpih" accept
  meta skuid 987 accept
  meta nfproto ipv4 meta mark set 0x56501002 accept
  meta nfproto ipv6 meta mark set 0x56501004 accept
 }
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  iifname "vpih" meta nfproto ipv4 meta mark set 0x56501002 accept
 }
}
table inet diagnostic_observer {
 chain before {
  type filter hook output priority -151; policy accept;
  ip saddr 198.18.0.1 ip daddr 198.18.0.2 tcp sport 18080 counter comment "reply_before"
  ip saddr 198.18.0.1 ip daddr 198.18.0.2 tcp sport 18080 meta skuid 987 counter comment "reply_with_socket_uid"
  ip saddr 198.18.0.1 ip daddr 198.18.0.2 tcp sport 18080 tcp flags & (syn | ack) == (syn | ack) counter comment "synack_before"
 }
 chain after {
  type filter hook output priority -149; policy accept;
  ip saddr 198.18.0.1 ip daddr 198.18.0.2 tcp sport 18080 meta mark 0x56501002 counter comment "reply_steered"
  ip saddr 198.18.0.1 ip daddr 198.18.0.2 tcp sport 18080 meta mark 0x56501002 tcp flags & rst == rst counter comment "reset_steered"
  ip saddr 198.18.0.1 ip daddr 198.18.0.2 tcp sport 18080 meta mark 0x56501002 tcp flags & ack == ack counter comment "ack_steered"
 }
}
""")


def corrected_parent(trusted_uid, old_table):
    run(NFT, "delete", "table", "inet", old_table)
    if ENCODER:
        environment = dict(os.environ, VOLPAROSSA_REPLY_ENCODE=f"{socket.if_nametoindex('vpih')},{socket.if_nametoindex('lo')},{trusted_uid}")
        encoded = subprocess.check_output(
            [ENCODER, "worker_v3::client_ingress_policy::tests::parent_output_steering_is_one_atomic_fail_closed_batch",
             "--exact", "--nocapture"], env=environment, text=True, timeout=5)
        batch = bytes.fromhex(next(line.removeprefix("TCP_REPLY_BATCH=") for line in encoded.splitlines()
                                   if line.startswith("TCP_REPLY_BATCH=")))
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as netlink:
            netlink.settimeout(3)
            netlink.bind((0, 0))
            netlink.sendto(batch, (0, 0))
            acknowledged = set()
            while len(acknowledged) < 22:
                packet = netlink.recv(16384)
                offset = 0
                while offset < len(packet):
                    length, kind, _, sequence, _ = struct.unpack_from("=IHHII", packet, offset)
                    assert length >= 20 and offset + length <= len(packet) and kind == 2
                    error = struct.unpack_from("=i", packet, offset + 16)[0]
                    assert error == 0, f"actual helper nft batch rejected: {error}"
                    acknowledged.add(sequence)
                    offset += (length + 3) & ~3
        return "vpo_08080808080808080808080808080808"
    raise RuntimeError("run through the Rust helper test so GREEN uses its actual encoded policy")


def isolated(parent_namespace):
    assert os.readlink("/proc/self/ns/net") != parent_namespace and os.getuid() == UID
    children = []
    try:
        nodes = {}
        for role in ("peer", "worker"):
            process = subprocess.Popen(["/usr/bin/unshare", "--net", "--", sys.executable, "-B",
                                        SCRIPT, "--bootstrap", role],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
            children.append(process)
            nodes[role] = (process, receive(process))
        run(IP, "link", "set", "lo", "up")
        for role, device, opposite, address in (
            ("peer", "physical", "outside", PROVIDER + "/30"),
            ("worker", "vpih", "vpiw", "169.254.240.1/30"),
        ):
            run(IP, "link", "add", device, "type", "veth", "peer", "name", opposite)
            run(IP, "link", "set", opposite, "netns", str(nodes[role][1]["pid"]))
            run(IP, "addr", "add", address, "dev", device)
            run(IP, "link", "set", device, "up")
            command(nodes[role][0], "configure")
            nodes[role][1]["endpoint"] = receive(nodes[role][0])
        cases, table = {}, "diagnostic_parent"
        for case in ("control", "parent_steering", "corrected", "wrong_uid"):
            if case == "parent_steering":
                install_parent()
            elif case in ("corrected", "wrong_uid"):
                table = corrected_parent(UID if case == "corrected" else UID + 1, table)
            before = counters() if case != "control" else {}
            provider = drop_and_exec("--server")
            children.append(provider)
            ready = receive(provider)
            assert ready["boundary"]["all_capabilities_zero"]
            command(provider, "exchange")
            command(nodes["peer"][0], "exchange")
            peer = receive(nodes["peer"][0])
            result = receive(provider)
            assert provider.wait(timeout=2) == 0
            cases[case] = dict(peer=peer, provider=result)
            if before:
                after = counters()
                cases[case]["packet_counters"] = {key: after[key] - value for key, value in before.items()}
        observed = cases["parent_steering"]["packet_counters"]
        control, failure = cases["control"], cases["parent_steering"]
        assert control["peer"]["reply_verified"] and control["provider"]["payload_verified"]
        assert failure["peer"]["connected"] and not failure["peer"]["reply_verified"]
        assert observed["reply_steered"] > 0 and observed["ack_steered"] > 0
        assert observed["reply_before"] > observed["reply_with_socket_uid"] >= 1
        assert cases["corrected"]["peer"]["reply_verified"]
        assert cases["corrected"]["provider"]["payload_verified"]
        assert cases["corrected"]["packet_counters"]["ack_steered"] == 0
        assert not cases["wrong_uid"]["peer"]["reply_verified"]
        assert cases["wrong_uid"]["packet_counters"]["reply_steered"] > 0
        # Test-only fault injection: even an exact mark+runtime label cannot
        # exempt the ORIGINAL direction. This table is never product policy.
        run(NFT, "-f", "-", text=f"""
table inet diagnostic_injection {{
 chain before {{
  type filter hook output priority -151; policy accept;
  ip saddr {PROVIDER} ip daddr {PEER} tcp sport 18082 tcp dport 18081 ct direction original {LABEL_BITS} ct mark set {CONNMARK} counter comment "original_seeded"
 }}
 chain after {{
  type filter hook output priority -149; policy accept;
  ip saddr {PROVIDER} ip daddr {PEER} tcp sport 18082 tcp dport 18081 ct direction original ct mark {CONNMARK} meta mark 0x56501002 counter comment "original_still_steered"
 }}
 chain stale_before {{
  type filter hook prerouting priority -151; policy accept;
  ip saddr {PEER} ip daddr {PROVIDER} tcp dport 18080 tcp flags & (syn | ack) == syn ct direction original {LABEL_BITS} ct mark set {CONNMARK} counter comment "stale_syn_seeded"
 }}
 chain stale_after {{
  type filter hook prerouting priority -149; policy accept;
  ip saddr {PEER} ip daddr {PROVIDER} tcp dport 18080 tcp flags & (syn | ack) == syn ct direction original ct mark 0 counter comment "stale_syn_cleared"
 }}
}}
""")
        original = drop_and_exec("--original")
        children.append(original)
        assert receive(original)["boundary"]["all_capabilities_zero"]
        assert receive(original)["original_attempted"] and original.wait(timeout=2) == 0
        provider = drop_and_exec("--server")
        children.append(provider)
        assert receive(provider)["boundary"]["all_capabilities_zero"]
        command(provider, "exchange")
        command(nodes["peer"][0], "exchange")
        assert not receive(nodes["peer"][0])["reply_verified"]
        receive(provider)
        assert provider.wait(timeout=2) == 0
        injected = json.loads(run(NFT, "-j", "list", "table", "inet", "diagnostic_injection"))
        injection_counts = {item["rule"]["comment"]: next(expr["counter"]["packets"] for expr in item["rule"]["expr"] if "counter" in expr)
                            for item in injected["nftables"] if "comment" in item.get("rule", {})}
        assert injection_counts["original_seeded"] > 0 and injection_counts["original_still_steered"] > 0
        assert injection_counts["stale_syn_seeded"] > 0
        assert injection_counts["stale_syn_seeded"] == injection_counts["stale_syn_cleared"]
        for process, _ in nodes.values():
            command(process, "stop")
            assert receive(process) == dict(stopped=True)
            assert process.wait(timeout=2) == 0
        emit(dict(defect_reproduced=True, corrected_reply_verified=True,
                  actual_helper_encoded_rules=bool(ENCODER), wrong_uid_refused=True,
                  original_direction_refused=True, original_counters=injection_counts,
                  new_syn_revoked_stale_authority=True,
                  same_capless_uid=UID, kernel=os.uname().release,
                  cases=cases, packet_counters=observed))
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Changes: anonymous user/mount/PID/network namespaces only; two veth pairs, "
              "fixed nft parent/TProxy rules and counters; UID987 capless server/peer; "
              "0.4s test-only delayed accept; kernel namespace teardown removes all state.", flush=True)
        parent = os.readlink("/proc/self/ns/net")
        dns_before = hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest()
        host_links = run(IP, "-o", "link", "show")
        result = subprocess.run(
            ["/usr/bin/timeout", "--kill-after=2s", "25s", "/usr/bin/unshare", "--user",
             "--map-user=987", "--map-group=987", "--keep-caps", "--net", "--pid", "--fork",
             "--kill-child=KILL", "--mount-proc", "--", sys.executable, "-B", SCRIPT, "--isolated", parent],
            check=False, timeout=30)
        assert os.readlink("/proc/self/ns/net") == parent and run(IP, "-o", "link", "show") == host_links
        assert hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest() == dns_before
        emit(dict(namespace_tree_reaped=True, host_links_dns_unchanged=True, exit_status=result.returncode))
        raise SystemExit(result.returncode)
    elif sys.argv[1] == "--isolated":
        isolated(sys.argv[2])
    elif sys.argv[1] == "--bootstrap":
        bootstrap(sys.argv[2])
    elif sys.argv[1] == "--server":
        server()
    else:
        endpoint(*sys.argv[1:])
