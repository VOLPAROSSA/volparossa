#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real application DNS inside the existing four-node reciprocal UDP window."""
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


DNS = load("dns-cache-smoke.py", "reciprocal_dns_application")
CAPTURE = load("reciprocity-private-dns-capture.py", "reciprocal_private_capture")
UPLINK = load("reciprocity-private-dns-uplink.py", "reciprocal_dns_uplink")
NODES = UPLINK.NODES
SCOPE = "four unchanged all-role agents and concurrent native UDP flows; protected one-relay application DNS, private native recursion and independently validated local reuse; not all DNS cases or default-private rollout"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def command(*args, timeout=20):
    return subprocess.check_output(args, text=True, timeout=timeout, stderr=subprocess.DEVNULL)


def read(path):
    return DNS.read(path)


def write(path, value):
    UPLINK.write(path, value)


def identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rindex(") ") + 2:].split()
    return dict(pid=pid, start_ticks=int(fields[19]), parent_pid=int(fields[1]))


def alive(member):
    try:
        return identity(member["pid"])["start_ticks"] == member["start_ticks"]
    except (FileNotFoundError, ProcessLookupError):
        return False


def native_children(agent):
    result = []
    tasks = list(Path(f"/proc/{agent['pid']}/task").iterdir())
    require(len(tasks) <= 128, "PRIVATE_DNS_AGENT_THREAD_BOUND")
    children = set()
    for task in tasks:
        try:
            text = (task / "children").read_text()
        except FileNotFoundError:
            continue
        require(len(text) <= 8192, "PRIVATE_DNS_CHILD_BOUND")
        children.update(int(value) for value in text.split())
    require(len(children) <= 64, "PRIVATE_DNS_CHILD_BOUND")
    for pid in children:
        try:
            if os.readlink(f"/proc/{pid}/exe") != "/usr/libexec/volparossa-dns-worker":
                continue
            member = identity(pid)
            status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
            uids = [int(value) for value in status["Uid"].split()]
            pipes = [os.readlink(f"/proc/{pid}/fd/{number}") for number in (0, 1)]
            require(member["parent_pid"] == agent["pid"] and uids == [agent["uid"]] * 4
                    and Path(f"/proc/{pid}/ns/net").stat().st_ino == agent["netns_inode"]
                    and int(status["CapEff"], 16) == 0 and status["NoNewPrivs"].strip() == "1"
                    and all(re.fullmatch(r"pipe:\[[0-9]+\]", value) for value in pipes)
                    and pipes[0] != pipes[1], "PRIVATE_DNS_WORKER_SCOPE")
            result.append(dict(**member, uid=agent["uid"], netns_inode=agent["netns_inode"],
                               inherited_private_pipes=True, effective_capabilities=0, no_new_privileges=True))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def selection(text, peers, original_context):
    rows = [line for line in text.splitlines() if line and not line.startswith("context=" + original_context + " ")]
    require(len(rows) == 1, "PRIVATE_DNS_ROUTE_COUNT")
    match = re.fullmatch(r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) state=1 rtt_us=0 bytes=0(?: acked_transport_bytes=0)?", rows[0])
    require(match is not None, "PRIVATE_DNS_ROUTE_SHAPE")
    context, path, relay, exit_peer = match.groups()
    reverse = {peers[node]: node for node in NODES}
    require(context != "0" * 32 and relay in reverse and exit_peer in reverse
            and len({peers["client"], relay, exit_peer}) == 3, "PRIVATE_DNS_ROUTE_IDENTITIES")
    return dict(route_context_id=context, path_id=int(path), relay_peer_id=relay,
                relay_node=reverse[relay], exit_peer_id=exit_peer, exit_node=reverse[exit_peer])


def wait_selection(paths, peers, original_context):
    # Connect admission and status publication are asynchronous. Wait only while
    # the exact original native UDP context is the sole published route; do not
    # retry admission, discard another selected Exit or tolerate a malformed row.
    deadline = time.monotonic() + 5
    while True:
        text = paths()
        rows = [line for line in text.splitlines() if line]
        if any(not line.startswith("context=" + original_context + " ") for line in rows):
            return selection(text, peers, original_context)
        require(CAPTURE.BASE.parse_path(text)["route_context_id"] == original_context,
                "PRIVATE_DNS_ORIGINAL_ROUTE_MISSING")
        require(time.monotonic() < deadline, "PRIVATE_DNS_ROUTE_PUBLICATION_TIMEOUT")
        time.sleep(.05)


def complete_capture(value, node, phase):
    interfaces = {*CAPTURE.NODES[node]["interfaces"], UPLINK.TAP}
    require(value["node"] == node and value["phase"] == phase and value["complete"] is True
            and value["truncated"] is False and value["packet_socket_drops"] == 0
            and value["forbidden_packets"] == value["plaintext_dns_packets"] == value["plaintext_echo_packets"]
                == value["direct_client_exit_packets"] == value["malformed_packets"] == 0
            and set(value["interfaces"]) == set(value["interface_statistics"]) == interfaces,
            "PRIVATE_DNS_CAPTURE_INCOMPLETE")
    for stats in value["interface_statistics"].values():
        require(stats["intake_stopped"] and stats["drained"] and stats["packet_socket_drops"] == 0
                and stats["packet_socket_packets"] == stats["observed_frames"], "PRIVATE_DNS_CAPTURE_DRAIN")


def validate_phase(value, phase):
    require(value["phase"] == phase and value["application"]["name"] == "iana.org"
            and value["application"]["family"] == "A"
            and value["application"]["addresses"] and value["application"]["ad_used_as_proof"] is False,
            "PRIVATE_DNS_APPLICATION")
    selected = value["selected"]
    require(selected["exit_node"] in NODES and selected["exit_node"] != "client"
            and selected["relay_node"] in NODES
            and len({"client", selected["relay_node"], selected["exit_node"]}) == 3,
            "PRIVATE_DNS_SELECTED_SCOPE")
    metric = "upstream_validated" if phase == "warm" else "local_validated"
    for node in NODES:
        for source in ("upstream_validated", "local_validated", "peer_validated", "trusted_fallback"):
            expected = int(node == selected["exit_node"] and source == metric)
            require(DNS.delta(value["metrics_before"][node], value["metrics_after"][node], source) == expected,
                    "PRIVATE_DNS_SOURCE_MISMATCH")
        capture = value["captures"][node]
        complete_capture(capture, node, phase)
        requests, responses = capture["recursive_request_packets"], capture["recursive_response_packets"]
        if phase == "warm" and node == selected["exit_node"]:
            require(requests > 0 and responses > 0 and capture["recursive_response_payload_bytes"] > 0,
                    "PRIVATE_DNS_RECURSION_MISSING")
        else:
            require(requests == responses == 0, "PRIVATE_DNS_UNEXPECTED_RECURSION")
    require(value["route_retired"] is True and value["native_workers_reaped"] is True,
            "PRIVATE_DNS_OWNERSHIP_NOT_RELEASED")
    if phase == "warm":
        require(1 <= len(value["workers"]) <= 2 and all(
            member["uid"] == value["exit_agent"]["uid"]
            and member["parent_pid"] == value["exit_agent"]["pid"]
            and member["netns_inode"] == value["exit_agent"]["netns_inode"]
            and member["inherited_private_pipes"] and member["effective_capabilities"] == 0
            and member["no_new_privileges"] for member in value["workers"]), "PRIVATE_DNS_NATIVE_WORKER_UNOBSERVED")
    else:
        require(value["workers"] == [], "PRIVATE_DNS_LOCAL_REUSE_SPAWNED_WORKER")


def check_report(value, revision):
    require(value["version"] == 1 and value["report_kind"] == "volparossa-reciprocity-private-dns"
            and value["source_revision"] == revision and value["scope"] == SCOPE and value["success"] is True,
            "PRIVATE_DNS_REPORT_SCOPE")
    evidence = value["evidence"]
    require(evidence["success"] is True and evidence["same_agents"] is True
            and evidence["same_udp_contexts"] is True and value["reciprocity"]["success"] is True
            and value["reciprocity"]["source_revision"] == revision
            and value["cleanup"]["complete"] is True and value["cleanup"]["remaining_owned_objects"] == 0
            and value["host_state"]["unchanged"] is True
            and value["uplinks_cleanup"]["complete"] is True
            and value["uplinks_cleanup"]["owned_slirp_processes_reaped"] is True
            and set(value["uplinks_cleanup"]["restored_nodes"]) == set(NODES), "PRIVATE_DNS_REPORT_CLEANUP")
    for phase in ("warm", "local"):
        validate_phase(evidence[phase], phase)
        require(evidence[phase]["exit_agent"] == evidence["agents_before"][evidence[phase]["selected"]["exit_node"]],
                "PRIVATE_DNS_WORKER_AGENT_BINDING")
    require(evidence["agents_before"] == evidence["agents_after"]
            and set(evidence["agents_before"]) == set(NODES)
            and evidence["udp_contexts_before"] == evidence["udp_contexts_after"]
            and evidence["udp_contexts_before"] == {flow["client_node"]: flow["route_context_id"]
                for flow in value["reciprocity"]["flows"]}, "PRIVATE_DNS_ORIGINAL_CONTEXTS")
    for node in value["reciprocity"]["nodes"]:
        member = evidence["agents_before"][node["node"]]
        require(member["pid"] == node["agent_pid_before"] == node["agent_pid_after"]
                and node["roles"] == dict(client=True, relay=True, exit=True), "PRIVATE_DNS_RECIPROCAL_AGENT_BINDING")
    require(evidence["warm"]["selected"]["exit_peer_id"] == evidence["local"]["selected"]["exit_peer_id"]
            and evidence["warm"]["application"]["addresses"] == evidence["local"]["application"]["addresses"],
            "PRIVATE_DNS_LOCAL_REUSE_SCOPE")
    start, end = evidence["started_ns"], evidence["completed_ns"]
    require(start < end and all(flow["application"]["first_echo_ns"] <= start < end
            <= flow["application"]["last_echo_ns"] for flow in value["reciprocity"]["flows"]),
            "PRIVATE_DNS_NOT_WITHIN_CONCURRENT_UDP")


def run(work, binary, uid, gid, namespaces):
    UPLINK.guard(work, namespaces)
    require(binary.is_absolute() and binary.is_file(), "PRIVATE_DNS_CLI")
    peers = read(work / "a01-expected-peers.json")
    node_ns = dict(zip(NODES, namespaces))
    parent = os.readlink("/proc/self/ns/net")
    env = dict(os.environ, VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS=parent)

    def cli(node, *args):
        return command(str(binary), "--control-socket", str(work / f"runtime-{node}/control/agent.sock"), *args)

    def agents():
        values = {}
        for node in NODES:
            pid = int(command("systemctl", "show", "--property=MainPID", "--value", f"volparossa-alpha-agent@{node}.service"))
            member = identity(pid)
            roles = cli(node, "role", "show")
            require(all(f"{role}: true" in roles.splitlines() for role in ("client", "relay", "exit")), "PRIVATE_DNS_COMBINED_ROLES")
            member.update(uid=Path(f"/proc/{pid}").stat().st_uid, netns_inode=Path(f"/proc/{pid}/ns/net").stat().st_ino)
            require(member["uid"] != 0 and member["netns_inode"] == (Path("/run/netns") / node_ns[node]).stat().st_ino,
                    "PRIVATE_DNS_AGENT_SCOPE")
            values[node] = member
        return values

    def metrics():
        return {node: json.loads(subprocess.check_output(["ip", "netns", "exec", node_ns[node],
            sys.executable, "-B", str(HERE / "dns-cache-smoke.py"), "metrics"], env=env, timeout=4)) for node in NODES}

    before = agents()
    original = {node: CAPTURE.BASE.parse_path((work / f"reciprocity-paths-{node}.txt").read_text())["route_context_id"] for node in NODES}
    result = dict(success=False, started_ns=time.monotonic_ns(), agents_before=before, udp_contexts_before=original)
    write(work / "reciprocity-private-dns-evidence.json", result)
    for phase in ("warm", "local"):
        cli("client", "connect", "--transport", "protected-dns")
        selected = wait_selection(lambda: cli("client", "paths"), peers, original["client"])
        if phase == "local":
            require(selected["exit_peer_id"] == result["warm"]["selected"]["exit_peer_id"], "PRIVATE_DNS_REUSE_EXIT_CHANGED")
        layout = dict(phase=phase, exit_node=selected["exit_node"], relays={selected["relay_node"]: CAPTURE.NODES[selected["relay_node"]]["public"]}, run_id=work.name.split(".")[1])
        prefix = work / f"reciprocity-private-dns-{phase}"
        layout_path = Path(str(prefix) + "-layout.json")
        write(layout_path, layout)
        observers, workers, application = [], {}, None
        data = dict(phase=phase, selected=selected, exit_agent=before[selected["exit_node"]], workers=[])
        try:
            for node in NODES:
                output = Path(str(prefix) + f"-capture-{node}.json")
                ready = Path(str(prefix) + f"-capture-{node}.ready")
                with Path(str(prefix) + f"-capture-{node}.log").open("xb") as log:
                    child = subprocess.Popen(["ip", "netns", "exec", node_ns[node], sys.executable, "-B",
                        str(HERE / "reciprocity-private-dns-capture.py"), "capture", str(layout_path), str(output), str(ready),
                        node, "--max-seconds", "40", *CAPTURE.NODES[node]["interfaces"], UPLINK.TAP], stdout=log, stderr=subprocess.STDOUT)
                observers.append(child)
                deadline = time.monotonic() + 3
                while not ready.is_file():
                    require(child.poll() is None and time.monotonic() < deadline, "PRIVATE_DNS_CAPTURE_START")
                    time.sleep(.02)
            data["metrics_before"] = metrics()
            with Path(str(prefix) + "-application.json").open("xb") as output, Path(str(prefix) + "-application.err").open("xb") as errors:
                application = subprocess.Popen(["ip", "netns", "exec", node_ns["client"], "setpriv",
                    f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                    "--bounding-set=-all", "--no-new-privs", "--", sys.executable, "-B",
                    str(HERE / "dns-cache-smoke.py"), "query", "iana.org", "A"], env=env, stdout=output, stderr=errors)
                deadline = time.monotonic() + 31
                while application.poll() is None:
                    require(time.monotonic() < deadline, "PRIVATE_DNS_APPLICATION_TIMEOUT")
                    for member in native_children(data["exit_agent"]):
                        workers[member["pid"], member["start_ticks"]] = member
                    require(len(workers) <= 2, "PRIVATE_DNS_NATIVE_CHILD_BOUND")
                    time.sleep(.01)
                require(application.returncode == 0, "PRIVATE_DNS_APPLICATION_FAILED")
            data["application"] = read(Path(str(prefix) + "-application.json"))
            data["workers"] = list(workers.values())
            data["native_workers_reaped"] = all(not alive(member) for member in workers.values())
            data["metrics_after"] = metrics()
        finally:
            if application is not None and application.poll() is None:
                application.terminate()
                try:
                    application.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    application.kill()
                    application.wait(timeout=3)
            stopped = True
            for child in observers:
                if child.poll() is None:
                    child.terminate()
            for child in observers:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
                stopped = stopped and child.returncode == 0
            data["workers"] = list(workers.values())
            result[phase] = data
            write(work / "reciprocity-private-dns-evidence.json", result)
            require(stopped, "PRIVATE_DNS_CAPTURE_STOP")
        data["captures"] = {node: read(Path(str(prefix) + f"-capture-{node}.json")) for node in NODES}
        deadline = time.monotonic() + 5
        while selected["route_context_id"] in cli("client", "paths") and time.monotonic() < deadline:
            time.sleep(.05)
        data["route_retired"] = selected["route_context_id"] not in cli("client", "paths")
        result[phase] = data
        write(work / "reciprocity-private-dns-evidence.json", result)
        validate_phase(data, phase)
    result.update(agents_after=agents(), completed_ns=time.monotonic_ns())
    result["same_agents"] = result["agents_after"] == before
    result["udp_contexts_after"] = {node: CAPTURE.BASE.parse_path(cli(node, "paths"))["route_context_id"] for node in NODES}
    result["same_udp_contexts"] = result["udp_contexts_after"] == original
    require(result["same_agents"] and result["same_udp_contexts"], "PRIVATE_DNS_RECIPROCAL_LIFETIME_CHANGED")
    result["success"] = True
    write(work / "reciprocity-private-dns-evidence.json", result)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "check":
        check_report(read(Path(sys.argv[2])), sys.argv[3])
    else:
        def interrupted(*_args):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
        require(len(sys.argv) == 10 and sys.argv[1] == "run", "PRIVATE_DNS_ARGUMENTS")
        try:
            run(Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), sys.argv[6:])
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            # Export only a fixed fixture class, never stderr, a command, a raw
            # packet or the native resolver's private pipe contents.
            path = Path(sys.argv[2]) / "reciprocity-private-dns-evidence.json"
            evidence = read(path) if path.is_file() else {"success": False}
            code = str(error) if re.fullmatch(r"PRIVATE_DNS_[A-Z_]+", str(error)) else (
                "PRIVATE_DNS_SUBPROCESS_TIMEOUT" if isinstance(error, subprocess.TimeoutExpired)
                else "PRIVATE_DNS_OBSERVER_FAILED")
            evidence.update(success=False, failure_code=code)
            write(path, evidence)
            raise
