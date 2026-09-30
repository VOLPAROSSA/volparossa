#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real application DNS inside the existing four-node reciprocal UDP window."""
import importlib.util
from contextlib import contextmanager
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


def checkpoint(work, result, stage):
    # Preserve already measured facts before later observer/cleanup failures. This is
    # never success: the complete phase, privacy and retirement gates still run below.
    result["observation_stage"] = stage
    write(work / "reciprocity-private-dns-evidence.json", result)


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


def selection(text, peers, original_context, previous=None, received_bytes=0):
    rows = [line for line in text.splitlines() if line and not line.startswith("context=" + original_context + " ")]
    require(len(rows) == 1, "PRIVATE_DNS_ROUTE_COUNT")
    match = re.fullmatch(r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) state=([1-3]) rtt_us=0 bytes=([0-9]+)(?: acked_transport_bytes=0)?", rows[0])
    require(match is not None, "PRIVATE_DNS_ROUTE_SHAPE")
    context, path, relay, exit_peer, state, count = match.groups()
    reverse = {peers[node]: node for node in NODES}
    require(context != "0" * 32 and relay in reverse and exit_peer in reverse
            and len({peers["client"], relay, exit_peer}) == 3, "PRIVATE_DNS_ROUTE_IDENTITIES")
    result = dict(route_context_id=context, path_id=int(path), relay_peer_id=relay,
                  relay_node=reverse[relay], exit_peer_id=exit_peer, exit_node=reverse[exit_peer],
                  state=int(state), reported_bytes=int(count))
    if previous is None:
        require(result["state"] == 1 and result["reported_bytes"] == 0, "PRIVATE_DNS_ROUTE_SHAPE")
    else:
        require(0 < received_bytes <= 8192
                and result == dict(previous, state=3, reported_bytes=received_bytes),
                "PRIVATE_DNS_REUSED_ROUTE_CHANGED")
    return result


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


def dns_context_present(text, original_context, selected_context, response_bytes, *, require_original=True):
    rows = [line for line in text.splitlines() if line]
    original = [line for line in rows if line.startswith("context=" + original_context + " ")]
    require((len(original) == 1 or not require_original and not original)
            and all(CAPTURE.BASE.parse_path(row)["route_context_id"] == original_context for row in original),
            "PRIVATE_DNS_ORIGINAL_ROUTE_MISSING")
    other = [line for line in rows if line not in original]
    if not other:
        return False
    require(len(other) == 1 and re.fullmatch(
        r"context=" + selected_context + r" path=[1-8] relay=\S+ exit=\S+ state=3 rtt_us=0 bytes="
        + str(response_bytes) + r"(?: acked_transport_bytes=0)?", other[0]) is not None,
        "PRIVATE_DNS_RETAINED_ROUTE_SHAPE")
    return True


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


def wait_idle_retirement(paths, original, selected, response_bytes, deadline, result, save):
    observation = dict(completed_status_reads=0, status_timeouts=0, context_present=None)
    result["idle_cleanup_observation"] = observation
    save()
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "PRIVATE_DNS_IDLE_RETIREMENT_TIMEOUT")
        started = time.monotonic()
        try:
            text = paths(min(2, remaining))
        except subprocess.TimeoutExpired:
            # A missing observation is not evidence of an absent route. Retry only
            # inside the original total cleanup budget, retaining the failure count.
            observation["status_timeouts"] += 1
            observation["context_present"] = None
        else:
            observation["completed_status_reads"] += 1
            observation["context_present"] = dns_context_present(
                text, original, selected, response_bytes, require_original=False)
        observed = time.monotonic()
        observation["last_status_elapsed_ms"] = int((observed - started) * 1000)
        save()
        require(observed <= deadline, "PRIVATE_DNS_IDLE_RETIREMENT_TIMEOUT")
        if observation["context_present"] is False:
            return observed
        time.sleep(.05)


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
    application = value["application"]
    socket_identity = application["application_socket"]
    require(application["application_protocol"] == "UDP"
            and application["request_sequence"] == (1 if phase == "warm" else 2)
            and 12 <= application["response_bytes"] <= 4096
            and socket_identity["pid"] > 0 and socket_identity["cookie"] > 0
            and socket_identity["bound_ip"] == "0.0.0.0" and 0 < socket_identity["bound_port"] <= 65535
            and application["resolver"] == application["response_source"] == {"ip": "9.9.9.9", "port": 53}
            and value["selected_after"] == dict(selected, state=3,
                reported_bytes=selected["reported_bytes"] + application["response_bytes"]),
            "PRIVATE_DNS_SAME_SOCKET_SEQUENCE")
    require((selected["state"] == 1 and selected["reported_bytes"] == 0) if phase == "warm"
            else (selected["state"] == 3 and 12 <= selected["reported_bytes"] <= 4096),
            "PRIVATE_DNS_ACTUAL_CUMULATIVE_BYTES")
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
        elif phase == "local" and node == selected["exit_node"]:
            # Closing the native worker does not drain packets already in the
            # recursive uplink. These remain counted, not used as answer evidence
            # or attributed to a particular earlier request without a packet match.
            require(requests == 0 and responses >= 0
                    and value["residual_unattributed_dns_response_packets"] == responses,
                    "PRIVATE_DNS_UNEXPECTED_RECURSION")
        else:
            require(requests == responses == 0, "PRIVATE_DNS_UNEXPECTED_RECURSION")
    require(value["route_retired"] is True and value["native_workers_reaped"] is True,
            "PRIVATE_DNS_OWNERSHIP_NOT_RELEASED")
    retirement = value["retirement"]
    require(retirement["mode"] == "shared_association_idle" and retirement["configured_idle_ms"] == 30_000
            and retirement["route_context_id"] == selected["route_context_id"]
            and retirement["after_request_sequence"] == 2
            and retirement["present_after_response"] is True
            and retirement["within_concurrent_window"] is False
            and retirement["within_original_lifetime"] is True
            and 29_000 <= retirement["observed_after_response_ms"] <= 35_000,
            "PRIVATE_DNS_IDLE_RETIREMENT_NOT_OBSERVED")
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
    warm, local = evidence["warm"], evidence["local"]
    require(warm["selected_after"] == local["selected"]
            and warm["application"]["application_socket"] == local["application"]["application_socket"]
            and warm["application"]["addresses"] == local["application"]["addresses"]
            and evidence["application_reaped"] is True
            and evidence["shared_association_idle"] == warm["retirement"] == local["retirement"],
            "PRIVATE_DNS_LOCAL_REUSE_SCOPE")
    require(evidence["post_dns_echo_confirmed"] is True
            and evidence["completed_ns"] < evidence["echo_stop_requested_ns"]
            < evidence["idle_cleanup_completed_ns"], "PRIVATE_DNS_CONCURRENT_WINDOW_BOUNDARY")
    start, end = evidence["started_ns"], evidence["completed_ns"]
    require(start < end and all(flow["application"]["first_echo_ns"] <= start < end
            <= flow["application"]["last_echo_ns"] for flow in value["reciprocity"]["flows"]),
            "PRIVATE_DNS_NOT_WITHIN_CONCURRENT_UDP")


@contextmanager
def repeat_application(work, uid, gid, namespace, env):
    """One owned process/socket, reaped even when a capture or first question fails."""
    directory = work / "client-fixtures/reciprocity-dns-repeat"
    directory.mkdir(mode=0o700)
    os.chown(directory, uid, gid)
    application = None
    try:
        with (work / "reciprocity-private-dns-pair.out").open("xb") as output, \
             (work / "reciprocity-private-dns-pair.err").open("xb") as errors:
            application = subprocess.Popen(["ip", "netns", "exec", namespace, "setpriv",
                f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                "--bounding-set=-all", "--no-new-privs", "--", sys.executable, "-B",
                str(HERE / "dns-cache-smoke.py"), "query-repeat", "iana.org", str(directory)],
                env=env, stdout=output, stderr=errors)
        deadline = time.monotonic() + 3
        while not (directory / "ready.json").is_file():
            require(application.poll() is None and time.monotonic() < deadline,
                    "PRIVATE_DNS_APPLICATION_START_TIMEOUT")
            time.sleep(.02)
        ready = read(directory / "ready.json")
        require(ready["pid"] == application.pid and ready["cookie"] > 0
                and 0 < ready["bound_port"] <= 65535, "PRIVATE_DNS_APPLICATION_SOCKET")
        yield application, directory, ready
    finally:
        if application is not None:
            if application.poll() is None:
                application.terminate()
            try:
                application.wait(timeout=3)
            except subprocess.TimeoutExpired:
                application.kill()
                application.wait(timeout=3)


def run(work, binary, uid, gid, namespaces):
    UPLINK.guard(work, namespaces)
    require(binary.is_absolute() and binary.is_file(), "PRIVATE_DNS_CLI")
    peers = read(work / "a01-expected-peers.json")
    node_ns = dict(zip(NODES, namespaces))
    parent = os.readlink("/proc/self/ns/net")
    env = dict(os.environ, VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS=parent)

    def cli(node, *args, timeout=20):
        return command(str(binary), "--control-socket", str(work / f"runtime-{node}/control/agent.sock"), *args,
                       timeout=timeout)

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
    # Use the ordinary existing connect allowance, once. A paired application is
    # started only after real readiness, so its 30s trigger wait cannot consume admission.
    cli("client", "connect", "--transport", "protected-dns", timeout=75)
    initial_selection = wait_selection(lambda: cli("client", "paths"), peers, original["client"])
    received_bytes = 0
    with repeat_application(work, uid, gid, node_ns["client"], env) as (application, directory, socket_identity):
        for sequence, phase in enumerate(("warm", "local"), 1):
            selected = initial_selection if phase == "warm" else selection(cli("client", "paths", timeout=2),
                peers, original["client"], initial_selection, received_bytes)
            layout = dict(phase=phase, exit_node=selected["exit_node"],
                relays={selected["relay_node"]: CAPTURE.NODES[selected["relay_node"]]["public"]},
                run_id=work.name.split(".")[1])
            prefix = work / f"reciprocity-private-dns-{phase}"
            layout_path = Path(str(prefix) + "-layout.json")
            write(layout_path, layout)
            observers, workers = [], {}
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
                if phase == "warm":
                    # Original signed authorization is created only after this trigger.
                    original_lifetime_bound = time.monotonic() + 60
                (directory / (phase + ".go")).touch(exist_ok=False)
                output = directory / (phase + ".json")
                deadline = time.monotonic() + 31
                while not output.is_file():
                    require((application.poll() is None or output.is_file()) and time.monotonic() < deadline,
                            "PRIVATE_DNS_APPLICATION_TIMEOUT")
                    for member in native_children(data["exit_agent"]):
                        workers[member["pid"], member["start_ticks"]] = member
                    require(len(workers) <= 2, "PRIVATE_DNS_NATIVE_CHILD_BOUND")
                    time.sleep(.01)
                response_observed_at = time.monotonic()
                data["application"] = read(output)
                require(data["application"]["application_socket"] == socket_identity
                        and data["application"]["request_sequence"] == sequence,
                        "PRIVATE_DNS_APPLICATION_SOCKET_CHANGED")
                write(Path(str(prefix) + "-application.json"), data["application"])
                received_bytes += data["application"]["response_bytes"]
                paths = cli("client", "paths", timeout=2)
                require(dns_context_present(paths, original["client"],
                    selected["route_context_id"], received_bytes), "PRIVATE_DNS_NOT_RETAINED_AFTER_RESPONSE")
                data["selected_after"] = selection(paths, peers, original["client"],
                    initial_selection, received_bytes)
                data["native_workers_reaped"] = all(not alive(member) for member in workers.values())
                data["metrics_after"] = metrics()
            finally:
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
            if phase == "local":
                data["residual_unattributed_dns_response_packets"] = data["captures"][selected["exit_node"]]["recursive_response_packets"]
            checkpoint(work, result, phase + "_captures_complete")
        require(application.wait(timeout=3) == 0, "PRIVATE_DNS_APPLICATION_FAILED")
        result["application_reaped"] = True
        checkpoint(work, result, "application_reaped")

    # All DNS work and identity snapshots must still lie inside the original
    # native flow lifetime. Natural association cleanup is measured separately.
    result["agents_after"] = agents()
    result["same_agents"] = result["agents_after"] == before
    checkpoint(work, result, "agents_after")
    after = {}
    for node in NODES:
        paths = cli(node, "paths", timeout=2)
        if node == "client":
            require(dns_context_present(paths, original[node], initial_selection["route_context_id"],
                received_bytes), "PRIVATE_DNS_LOCAL_ROUTE_MISSING")
            paths = "\n".join(row for row in paths.splitlines()
                if row.startswith("context=" + original[node] + " "))
        after[node] = CAPTURE.BASE.parse_path(paths)["route_context_id"]
    result["udp_contexts_after"] = after
    result["same_udp_contexts"] = after == original
    require(result["same_agents"] and result["same_udp_contexts"], "PRIVATE_DNS_RECIPROCAL_LIFETIME_CHANGED")
    result["completed_ns"] = time.monotonic_ns()
    checkpoint(work, result, "concurrent_window_complete")
    time.sleep(.5)
    result["echo_stop_requested_ns"] = time.monotonic_ns()
    (work / "reciprocity-app/stop").write_text("stop\n", encoding="ascii")
    echo_deadline = time.monotonic() + 3
    for node in NODES:
        output = work / f"reciprocity-app/{node}.json"
        while not output.is_file():
            require(time.monotonic() < echo_deadline, "PRIVATE_DNS_POST_DNS_ECHO_REPORT_TIMEOUT")
            time.sleep(.02)
        echo = read(output)
        require(echo["success"] is True and echo["last_echo_ns"] >= result["completed_ns"],
                "PRIVATE_DNS_POST_DNS_ECHO_MISSING")
    result["post_dns_echo_confirmed"] = True
    checkpoint(work, result, "post_dns_echo_confirmed")

    # Both phase reports reference ONE real retirement, after sequence 2. No
    # disconnect IPC, fresh route lottery, second idle wait or fabricated zero bytes.
    deadline = min(response_observed_at + 35, original_lifetime_bound)
    retired_at = wait_idle_retirement(
        lambda timeout: cli("client", "paths", timeout=timeout), original["client"],
        initial_selection["route_context_id"], received_bytes, deadline, result,
        lambda: checkpoint(work, result, "idle_cleanup_observation"))
    retirement = dict(mode="shared_association_idle", configured_idle_ms=30_000,
        route_context_id=initial_selection["route_context_id"], after_request_sequence=2,
        present_after_response=True, within_concurrent_window=False,
        observed_after_response_ms=int((retired_at - response_observed_at) * 1000),
        within_original_lifetime=retired_at <= original_lifetime_bound)
    result["shared_association_idle"] = retirement
    for phase in ("warm", "local"):
        result[phase].update(route_retired=True, retirement=retirement)
        validate_phase(result[phase], phase)
    result["idle_cleanup_completed_ns"] = time.monotonic_ns()
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
