#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Separate late-provider availability proof; never a concurrency/speed substitute."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import signal
import socket
import stat
import subprocess
import sys
import time

BASE = runpy.run_path(str(Path(__file__).with_name("content-provider-https-smoke.py")))
require, read, ROLES = BASE["require"], BASE["read"], BASE["ROLES"]
PREFIX = "content-provider-late-recovery"
NODES = ("relay4", "relay5")
TABLE = "vpa_content_late_gate"
LIMIT = 262144
GATE_NS = 6_000_000_000
PREPARE_NS = 30_000_000_000
BYTES = 2097275
SHA = hashlib.sha256(b"".join(bytes([16+i])*262144 for i in range(8)) + bytes([25])*123).hexdigest()
EVENTS = ("CONTENT_DISCOVERY_COMPLETED", "CONTENT_DISCOVERY_RECEIVED_OFFERS", "CONTENT_DISCOVERY_RECEIVED_EMPTY",
    "CONTENT_PROVIDER_QUERY_STARTED", "CONTENT_PROVIDER_OFFER_VERIFIED")
FAILURE_STAGES = ("readiness", "gate-install", "gate-inspect", "fetch-start", "first-snapshot", "activate-b",
    "gate-release", "fetch-wait", "final-snapshot", "output")
FAILURE_CATEGORIES = ("command-failed", "timeout", "interrupted", "os-error", "invalid-evidence")


class FixtureCommandError(ValueError):
    def __init__(self, returncode):
        super().__init__("bounded fixture command failed")
        self.returncode = returncode


class ReadinessCleanupError(OSError):
    pass


def failure_evidence(stage, error):
    category, code = "invalid-evidence", None
    if isinstance(error, FixtureCommandError): category, code = "command-failed", error.returncode
    elif isinstance(error, subprocess.TimeoutExpired): category = "timeout"
    elif isinstance(error, InterruptedError): category = "interrupted"
    elif isinstance(error, OSError): category = "os-error"
    value = dict(schema_version=1, kind="content-provider-late-recovery-failure", success=False,
        stage=stage, category=category, command_exit_code=code)
    validate_failure(value)
    return value


def validate_failure(value):
    require(set(value) == {"schema_version", "kind", "success", "stage", "category", "command_exit_code"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["kind"] == "content-provider-late-recovery-failure" and value["success"] is False
        and value["stage"] in FAILURE_STAGES and value["category"] in FAILURE_CATEGORIES,
        "invalid fixture failure diagnostic")
    code = value["command_exit_code"]
    require((value["category"] == "command-failed" and type(code) is int and -255 <= code <= 255 and code != 0)
        or (value["category"] != "command-failed" and code is None), "invalid command failure status")


def path(work, suffix, extension="json"):
    return work / f"{PREFIX}-{suffix}.{extension}"


def write(target, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    require(len(raw) <= LIMIT, "evidence too large")
    with target.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw)


def private_read(target):
    require(target.resolve() == target and not target.is_symlink(), "unsafe private record")
    info = target.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= LIMIT, "wrong private record owner")
    return read(target)


def guest(work):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha"
        and work.is_absolute() and work.resolve() == work and work.parent == Path("/opt")
        and work.name.startswith("va.") and work.is_dir() and work.stat().st_uid == 0, "disposable guest required")
    result = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, timeout=3, check=False)
    require(result.returncode == 0 and result.stdout.strip() == b"kvm", "KVM guest required")


def namespace(work, expected=None):
    record = private_read(work / "helper-record-relay4.json")
    name = record["network_namespace"]
    require(record["node"] == "relay4" and record["unit"] == "volparossa-alpha-helper@relay4.service"
        and re.fullmatch(r"va-[0-9a-f]{8}-r4", name), "wrong provider namespace")
    info = os.stat(f"/run/netns/{name}")
    identity = f"{info.st_dev}:{info.st_ino}"
    require(identity == record["network_namespace_identity"]
        and (expected is None or expected == dict(name=name, identity=identity)), "namespace replaced")
    return dict(name=name, identity=identity)


def command(args, deadline, input_data=None):
    remaining = (deadline-time.monotonic_ns()) / 1e9
    require(remaining > 0, "fixture deadline exceeded")
    result = subprocess.run(args, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=min(remaining, 2), check=False)
    if result.returncode != 0: raise FixtureCommandError(result.returncode)
    require(len(result.stdout) <= LIMIT, "bounded fixture command output too large")
    return result.stdout


def gate_rules():
    return (f"table inet {TABLE} {{ chain input {{ type filter hook input priority -30; policy accept; "
        'iifname "r4x" ip saddr 46.162.3.1 ip daddr 49.165.5.1 tcp dport 18080 counter drop; }\n}\n').encode()


def validate_gate(value):
    entries = value["nftables"]
    require(len(entries) == 4, "unexpected gate objects")
    table = [item["table"] for item in entries if "table" in item]
    chains = [item["chain"] for item in entries if "chain" in item]
    rules = [item["rule"] for item in entries if "rule" in item]
    require(len(table) == len(chains) == len(rules) == 1
        and table[0]["family"] == "inet" and table[0]["name"] == TABLE
        and chains[0]["family"] == "inet" and chains[0]["table"] == TABLE and chains[0]["name"] == "input"
        and chains[0]["type"] == "filter" and chains[0]["hook"] == "input"
        and chains[0]["prio"] == -30 and chains[0]["policy"] == "accept"
        and rules[0]["family"] == "inet" and rules[0]["table"] == TABLE and rules[0]["chain"] == "input",
        "gate escaped exact input table")
    expressions = rules[0]["expr"]
    expected = [dict(match=dict(op="==", left=dict(meta=dict(key="iifname")), right="r4x")),
        *[dict(match=dict(op="==", left=dict(payload=dict(protocol="ip", field=field)), right=address))
            for field, address in (("saddr", "46.162.3.1"), ("daddr", "49.165.5.1"))],
        dict(match=dict(op="==", left=dict(payload=dict(protocol="tcp", field="dport")), right=18080))]
    require(len(expressions) == 6 and expressions[:4] == expected and expressions[5] == {"drop": None}
        and set(expressions[4]) == {"counter"}
        and set(expressions[4]["counter"]) == {"packets", "bytes"}
        and all(type(value) is int and value >= 0 for value in expressions[4]["counter"].values()), "wrong gate rule")


def remove_gate(work, guest_checked=False):
    record = path(work, "gate", "state")
    if not record.exists() and not record.is_symlink(): return
    if not guest_checked: guest(work)
    state = private_read(record); ns = namespace(work, state["namespace"])
    base = ["ip", "netns", "exec", ns["name"], "nft"]
    # Listing all table names lets absence be distinguished from command failure.
    deadline = time.monotonic_ns() + 2_000_000_000
    tables = json.loads(command(base + ["-j", "list", "tables"], deadline))
    present = any(row.get("table", {}).get("family") == "inet" and row.get("table", {}).get("name") == TABLE
        for row in tables["nftables"])
    if present:
        snapshot = json.loads(command(base + ["-j", "list", "table", "inet", TABLE], deadline))
        validate_gate(snapshot)
        command(base + ["delete", "table", "inet", TABLE], deadline)


def process_identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return dict(pid=pid, start_ticks=int(fields[19]))


def stop_fetch(work, suffix="fetch"):
    record = path(work, suffix, "state")
    if not record.exists() and not record.is_symlink(): return
    guest(work); identity = private_read(record)
    require(set(identity) == {"pid", "start_ticks"} and all(type(v) is int and v > 1 for v in identity.values()),
        "wrong fetch process record")
    try: descriptor = os.pidfd_open(identity["pid"])
    except ProcessLookupError: return
    try:
        require(process_identity(identity["pid"]) == identity, "fetch PID reused")
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        poll = select.poll(); poll.register(descriptor, select.POLLIN)
        if not poll.poll(1000):
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            require(poll.poll(1000), "owned fetch did not terminate")
    except ProcessLookupError: pass
    finally: os.close(descriptor)


def cleanup(work):
    # Gate release must not wait for child termination near the connect deadline.
    try: remove_gate(work)
    finally:
        try: stop_fetch(work)
        finally: stop_fetch(work, "readiness-process")


def event_rows(raw, baseline):
    require(len(raw) <= LIMIT, "event snapshot too large")
    rows = []
    lines = raw.decode("ascii").splitlines()
    require(len(lines) <= 400, "event ring bound exceeded")
    stamps = []
    for line in lines:
        fields = line.split()
        if not fields or not fields[0].isdigit(): continue
        timestamp = int(fields[0]); stamps.append(timestamp)
        if timestamp <= baseline or len(fields) < 3 or not fields[2].startswith("event="): continue
        code = fields[2][6:]
        if code in EVENTS: rows.append(dict(unix_ms=timestamp, event=code))
    require(not (len(lines) == 400 and stamps and min(stamps) > baseline), "event ring lost interval")
    return rows


def count(rows, code): return sum(row["event"] == code for row in rows)


def discovery_reply(value):
    require(type(value) is dict and set(value) == {"schema_version", "kind", "control_relay_peer_id", "providers"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["kind"] == "content-provider-discovery-readiness"
        and type(value["control_relay_peer_id"]) is str and 0 < len(value["control_relay_peer_id"]) <= 128
        and type(value["providers"]) is list and len(value["providers"]) <= 16, "invalid readiness reply")
    peers = set()
    for offer in value["providers"]:
        require(type(offer) is dict and set(offer) == {"peer_id", "offer_expires_unix_seconds"}
            and type(offer["peer_id"]) is str and 0 < len(offer["peer_id"]) <= 128
            and offer["peer_id"] not in peers and type(offer["offer_expires_unix_seconds"]) is int
            and 0 < offer["offer_expires_unix_seconds"] < 2**64, "invalid readiness offer")
        peers.add(offer["peer_id"])
    return value


def readiness_paths(raw, selected):
    rows = raw.decode("ascii").splitlines()
    require(0 < len(rows) <= 8, "wrong readiness paths")
    observed = []
    for row in rows:
        match = re.fullmatch(r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) "
            r"state=[0-9]+ rtt_us=[0-9]+ bytes=[0-9]+ acked_transport_bytes=[0-9]+", row)
        require(match is not None, "invalid readiness path row")
        context, ident, relay, exit_peer = match.groups()
        require(context == selected["route_context_id"] and exit_peer == selected["exact_selected_exit"], "readiness route changed")
        observed.append((int(ident), relay))
    expected = [(row["path_id"], row["relay_peer_id"]) for row in selected["paths"]]
    require(sorted(observed) == sorted(expected), "readiness path selection changed")


def readiness_request(work, executable, args, deadline):
    """One owned typed helper; termination closes its actual agent socket (EOF)."""
    remaining = (deadline-time.monotonic_ns()) / 1e9
    require(remaining > 0, "readiness deadline exceeded")
    process = subprocess.Popen([str(executable), "discover-providers", *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        # Replaced only after the previous owned child has been reaped.
        record = path(work, "readiness-process", "state")
        if record.exists():
            private_read(record); record.unlink()
        write(record, process_identity(process.pid))
        remaining = (deadline-time.monotonic_ns()) / 1e9
        if remaining <= 0: raise subprocess.TimeoutExpired("readiness", 0)
        stdout, _ = process.communicate(timeout=remaining)
        if process.returncode: raise FixtureCommandError(process.returncode)
        require(len(stdout) <= 8192, "oversized readiness reply")
        return discovery_reply(json.loads(stdout))
    finally:
        try:
            if process.poll() is None:
                try: process.kill(); process.wait(timeout=2)
                except (OSError, subprocess.SubprocessError) as error:
                    raise ReadinessCleanupError("readiness child cleanup unconfirmed") from error
        finally:
            if process.stdout is not None: process.stdout.close()


def validate_readiness(value, publication, layout, selected, peers, *, successful=True):
    require(type(value) is dict and set(value) == {"schema_version", "kind", "success", "scope", "started_ns",
        "completed_ns", "event_baseline_unix_ms", "completed_unix_ms", "route_context_id", "manifest_id",
        "control_relay_peer_id", "attempts", "checks", "failure", "events"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["kind"] == "content-provider-late-readiness"
        and value["scope"] == "warm-control-plane-cold-content-cache" and type(value["success"]) is bool,
        "invalid readiness record")
    require(all(type(value[k]) is int and value[k] > 0 for k in
        ("started_ns", "completed_ns", "event_baseline_unix_ms", "completed_unix_ms"))
        and value["completed_ns"] >= value["started_ns"]
        and value["completed_unix_ms"] >= value["event_baseline_unix_ms"]
        and value["route_context_id"] == selected["route_context_id"]
        and value["manifest_id"] == publication["manifest_id"]
        and value["control_relay_peer_id"] == layout["control_relay_peer_id"], "readiness binding changed")
    attempts = value["attempts"]
    require(type(attempts) is list and len(attempts) <= 2, "readiness request count exceeded")
    previous = value["started_ns"]
    for attempt in attempts:
        require(set(attempt) == {"started_ns", "completed_ns", "response", "failure"}
            and all(type(attempt[k]) is int for k in ("started_ns", "completed_ns"))
            and previous <= attempt["started_ns"] <= attempt["completed_ns"] <= value["completed_ns"], "readiness attempt ordering")
        previous = attempt["completed_ns"]
        require((attempt["response"] is None) != (attempt["failure"] is None), "ambiguous readiness attempt")
        if attempt["response"] is not None: discovery_reply(attempt["response"])
        else: validate_failure(attempt["failure"])
    require(set(value["checks"]) == {"route_unchanged", "b_not_serving", "cold_cache", "children_reaped"}
        and all(type(item) is bool for item in value["checks"].values()), "invalid readiness checks")
    if value["failure"] is not None: validate_failure(value["failure"])
    events = value["events"]
    require(events is None or type(events) is dict and set(events) == {"client", "broker"}, "invalid readiness events")
    if events is not None:
        for rows in events.values():
            require(type(rows) is list and len(rows) <= 400 and all(set(row) == {"unix_ms", "event"}
                and type(row["unix_ms"]) is int and row["unix_ms"] > value["event_baseline_unix_ms"]
                and row["unix_ms"] <= value["completed_unix_ms"]
                and row["event"] in EVENTS for row in rows), "invalid preparation event")
    if successful or value["success"]:
        require(value["success"] and value["failure"] is None and 1 <= len(attempts) <= 2
            and all(value["checks"].values()) and value["completed_ns"]-value["started_ns"] <= PREPARE_NS
            and events is not None, "readiness prerequisite failed")
        found = discovery_reply(attempts[-1]["response"])
        require(found["control_relay_peer_id"] == layout["control_relay_peer_id"]
            and len(found["providers"]) == 1 and found["providers"][0]["peer_id"] == peers["relay4"]
            and found["providers"][0]["offer_expires_unix_seconds"]*1000 > value["completed_unix_ms"],
            "A signed offer not ready through selected broker")
        require(all(item["failure"] is None for item in attempts)
            and all(item["response"]["control_relay_peer_id"] == layout["control_relay_peer_id"] for item in attempts)
            and all(not item["response"]["providers"] for item in attempts[:-1])
            and count(events["client"], EVENTS[0]) == count(events["broker"], EVENTS[3]) == len(attempts)
            and count(events["client"], EVENTS[1]) == 1
            and count(events["client"], EVENTS[2]) == len(attempts)-1
            and 1 <= count(events["broker"], EVENTS[4]) <= 16*len(attempts),
            "preparation did not retain real completed discovery")


def prepare(work, binary, executable):
    guest(work)
    require(executable.resolve() == executable and executable.is_file() and binary.resolve() == binary
        and binary.is_file(), "unsafe readiness executable")
    publication, layout, selected, peers = (read(path(work, name)) for name in ("publication", "layout", "selection", "peers"))
    broker = next(node for node in ("relay0", "relay1", "relay2") if peers[node] == layout["control_relay_peer_id"])
    native = work / "state-client/content-late-recovery"
    started = time.monotonic_ns(); deadline = started + PREPARE_NS
    value = dict(schema_version=1, kind="content-provider-late-readiness", success=False,
        scope="warm-control-plane-cold-content-cache", started_ns=started, completed_ns=started,
        event_baseline_unix_ms=time.time_ns()//1000000, completed_unix_ms=time.time_ns()//1000000,
        route_context_id=selected["route_context_id"], manifest_id=publication["manifest_id"],
        control_relay_peer_id=layout["control_relay_peer_id"], attempts=[], events=None, failure=None,
        checks=dict(route_unchanged=False, b_not_serving=False, cold_cache=False, children_reaped=True))
    def cli(node, *args): return [str(binary), "--control-socket", str(work / f"runtime-{node}/control/agent.sock"), *args]
    def check_scope():
        readiness_paths(command(cli("client", "paths"), deadline), selected)
        status = json.loads(command(cli("client", "content", "status"), deadline))
        require(status["control_relay_peer_id"] == layout["control_relay_peer_id"], "readiness broker changed")
        status = json.loads(command(cli("relay5", "content", "status"), deadline))
        require(status["serving"] is False and status["publications"] == 0, "B served before late activation")
        require(all(not (native / name).exists() and not (native / name).is_symlink() for name in ("cache", "object.bin")), "readiness warmed cache")
    def snapshot():
        return {label: event_rows(command(cli(node, "logs", "--limit", "400"), deadline), value["event_baseline_unix_ms"])
            for label, node in (("client", "client"), ("broker", broker))}
    def interrupted(_signal, _frame): raise InterruptedError("preparation interrupted")
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        time.sleep(0.002)  # Cross only the event clock tick, not a readiness delay.
        check_scope()
        for _ in range(2):
            attempt = dict(started_ns=time.monotonic_ns(), completed_ns=0, response=None, failure=None)
            value["attempts"].append(attempt)
            try:
                attempt["response"] = readiness_request(work, executable, [str(work / "runtime-client/control/agent.sock"),
                    str(native / "manifest.bin"), publication["publisher_hex"]], deadline)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                attempt["failure"] = failure_evidence("readiness", error)
                raise
            finally: attempt["completed_ns"] = time.monotonic_ns()
            found = attempt["response"]
            require(found["control_relay_peer_id"] == layout["control_relay_peer_id"], "readiness broker changed")
            value["events"] = snapshot()
            if found["providers"]: break
        check_scope()
        value["checks"].update(route_unchanged=True, b_not_serving=True, cold_cache=True)
        value["events"] = snapshot()
        value.update(success=True, completed_ns=time.monotonic_ns(), completed_unix_ms=time.time_ns()//1000000)
        validate_readiness(value, publication, layout, selected, peers)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        value.update(success=False, failure=failure_evidence("readiness", error))
        if isinstance(error, ReadinessCleanupError): value["checks"]["children_reaped"] = False
        if time.monotonic_ns() < deadline:
            try: value["events"] = snapshot()
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError): pass
        raise
    finally:
        # Preserve the exact successful decision time already checked against
        # the deadline. Disk retention is not another discovery attempt.
        if not value["success"]:
            value.update(completed_ns=time.monotonic_ns(), completed_unix_ms=time.time_ns()//1000000)
        try: write(path(work, "readiness"), value)
        finally:
            for sig, handler in handlers.items(): signal.signal(sig, handler)


def checked_readiness(work, publication, layout, peers):
    value = private_read(path(work, "readiness"))
    validate_readiness(value, publication, layout, read(path(work, "selection")), peers)
    return value


def first_snapshot(snapshot):
    return (count(snapshot["client"], EVENTS[0]) == count(snapshot["client"], EVENTS[1]) == 1
        and count(snapshot["client"], EVENTS[2]) == 0
        and count(snapshot["broker"], EVENTS[3]) == count(snapshot["broker"], EVENTS[4]) == 1)


def run(work, binary, provider_namespace):
    guest(work); ns = namespace(work)
    require(ns["name"] == provider_namespace and binary.resolve() == binary and binary.is_file(), "wrong executable/namespace")
    layout, peers, publication = (read(path(work, name)) for name in ("layout", "peers", "publication"))
    preparation = checked_readiness(work, publication, layout, peers)
    control = [node for node in ("relay0", "relay1", "relay2") if peers[node] == layout["control_relay_peer_id"]]
    require(len(control) == 1 and layout["provider_nodes"] == list(NODES), "wrong control/provider layout")
    native = work / "state-client/content-late-recovery"
    require(all(not (native / name).exists() and not (native / name).is_symlink()
        for name in ("cache", "object.bin")), "not cold")
    def cli(node, *args): return [str(binary), "--control-socket", str(work / f"runtime-{node}/control/agent.sock"), *args]
    def snapshot(baseline, deadline):
        return {label: event_rows(command(cli(node, "logs", "--limit", "400"), deadline), baseline)
            for label, node in (("client", "client"), ("broker", control[0]))}
    baseline = time.time_ns() // 1000000
    if baseline <= preparation["completed_unix_ms"]:
        time.sleep(0.002); baseline = time.time_ns() // 1000000
    require(baseline > preparation["completed_unix_ms"], "preparation overlaps measured interval")
    time.sleep(0.002)  # Only cross the event clock tick, never wait for provider readiness.
    tables = json.loads(command(["ip", "netns", "exec", ns["name"], "nft", "-j", "list", "tables"],
        time.monotonic_ns()+2_000_000_000))
    require(not any(row.get("table", {}).get("family") == "inet" and row.get("table", {}).get("name") == TABLE
        for row in tables["nftables"]), "gate table collision")
    gate_start = time.monotonic_ns(); deadline = gate_start + GATE_NS
    write(path(work, "gate", "state"), dict(namespace=ns))
    process, success = None, False
    stage = "gate-install"
    def interrupted(_signal, _frame): raise InterruptedError("fixture interrupted")
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        command(["ip", "netns", "exec", ns["name"], "nft", "-f", "-"], deadline, gate_rules())
        stage = "gate-inspect"
        installed = json.loads(command(["ip", "netns", "exec", ns["name"], "nft", "-j", "list", "table", "inet", TABLE], deadline))
        validate_gate(installed); write(path(work, "gate-installed"), installed)
        stage = "fetch-start"
        started = time.monotonic_ns()
        with path(work, "fetch").open("xb") as stdout, path(work, "fetch", "err").open("xb") as stderr:
            os.fchmod(stdout.fileno(), 0o600); os.fchmod(stderr.fileno(), 0o600)
            process = subprocess.Popen(cli("client", "content", "fetch", "--manifest", str(native / "manifest.bin"),
                "--publisher-key", publication["publisher_hex"], "--cache", str(native / "cache"),
                "--output", str(native / "object.bin")), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            write(path(work, "fetch", "state"), process_identity(process.pid))
            stage = "first-snapshot"
            while True:
                require(process.poll() is None, "fetch ended before late activation")
                initial = snapshot(baseline, deadline)
                require(count(initial["client"], EVENTS[0]) <= 1, "first snapshot already passed")
                if first_snapshot(initial): break
                # Discovery, activation and release share the same six-second
                # deadline; reserving two seconds here rejected valid DHT replies
                # before that deadline. Slow later commands still fail closed.
                require(time.monotonic_ns() < deadline, "first snapshot not available within gate budget")
                time.sleep(0.02)
            observed = time.monotonic_ns()
            write(path(work, "first-snapshot"), initial)
            stage = "activate-b"
            activated = time.monotonic_ns()
            serve = json.loads(command(cli("relay5", "content", "serve", "--manifest", str(native / "manifest.bin"),
                "--publisher-key", publication["publisher_hex"], "--cache", str(work / "state-relay5/content-late-recovery/cache"),
                "--bind", "50.166.6.1:18080", "--advertised-hostname", "provider-b.volparossa.test"), deadline))
            require(serve["serving"] is True and serve["publications"] == 1 and serve["replication_enabled"] is False,
                "late service did not acknowledge registration")
            acknowledged = time.monotonic_ns(); write(path(work, "relay5-serve"), serve)
            stage = "gate-release"
            command(["ip", "netns", "exec", ns["name"], "nft", "delete", "table", "inet", TABLE], deadline)
            released = time.monotonic_ns(); require(released <= deadline, "gate exceeded six seconds")
            stage = "fetch-wait"
            status = process.wait(timeout=max(0.001, (started+300_000_000_000-time.monotonic_ns())/1e9))
            if status != 0: raise FixtureCommandError(status)
        completed = time.monotonic_ns()
        stage = "final-snapshot"
        final = snapshot(baseline, time.monotonic_ns()+5_000_000_000)
        write(path(work, "final-snapshot"), final)
        stage = "output"
        output = native / "object.bin"
        require(output.is_file() and not output.is_symlink() and output.stat().st_size == BYTES, "wrong output")
        write(path(work, "object"), dict(bytes=output.stat().st_size, sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
            event_baseline_unix_ms=baseline, gate_started_ns=gate_start, fetch_started_ns=started,
            first_snapshot_observed_ns=observed, late_activation_started_ns=activated,
            late_activation_acknowledged_ns=acknowledged, gate_released_ns=released, fetch_completed_ns=completed,
            cold_cache=True, consumer_provider_hints=False, origin_fallback=False))
        success = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Retain only fixed classifications before cleanup can raise a second error.
        # No arbitrary command, path, exception text or child stderr is exported.
        write(path(work, "failure"), failure_evidence(stage, error))
        raise
    finally:
        gate_removed = False
        try:
            # Already checked the guest before installation. Revalidate only the
            # exact root intent/namespace now: bounded release precedes reaping.
            remove_gate(work, guest_checked=True); gate_removed = True
        finally:
            try:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=2)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)
                write(path(work, "run-cleanup"), dict(fetch_reaped=process is None or process.poll() is not None,
                    gate_removed=gate_removed, operation_completed=success))
            finally:
                for sig, handler in handlers.items(): signal.signal(sig, handler)


def validate(value, *, historical=False):
    require(value["success"] is True and type(value["schema_version"]) is int
        and value["schema_version"] == (1 if historical else 2)
        and value["concurrent_provider_overlap_claimed"] is False, "wrong late-recovery scope")
    publication, output, fetch = (value[k] for k in ("publication", "output", "fetch"))
    require(publication["report_kind"] == "volparossa-content-late-provider-seed"
        and publication["name"] == "disposable-late-native-publication"
        and publication["bytes"] == fetch["bytes"] == output["bytes"] == BYTES
        and publication["object_sha256"] == output["sha256"] == SHA
        and publication["chunks"] == fetch["chunks"] == 9
        and publication["replica_a_chunks"] == 5 and publication["replica_b_chunks"] == 4
        and publication["replica_a_bytes"] == 1048699 and publication["replica_b_bytes"] == 1048576
        and publication["publisher_removed"] is True and publication["publisher_private_key_persisted"] is False
        and publication["recipient_encrypted"] is False, "fresh complementary publication not proven")
    peers, layout = value["expected_peers"], value["layout"]
    control = [node for node in ("relay0", "relay1", "relay2") if peers[node] == layout["control_relay_peer_id"]]
    require(len(control) == 1 and layout["provider_nodes"] == list(NODES)
        and all(value[k]["control_relay_peer_id"] == layout["control_relay_peer_id"] for k in ("status_before", "status_after", "fetch"))
        and fetch["operation"] == "native_content" and fetch["providers_used"] == len(fetch["provider_peer_ids"]) == 2
        and set(fetch["provider_peer_ids"]) == {peers[node] for node in NODES}
        and fetch["peer_bytes"] == BYTES and fetch["origin_body_bytes"] == fetch["origin_range_requests"] == 0
        and fetch["origin_authenticated"] is False, "real independent protected suppliers not proven")
    before, live = value["selected_before"], value["selected_route"]
    require(before["route_context_id"] == live["route_context_id"] != value["previous_context"]
        and before["benchmark_slots"] == live["benchmark_slots"] and before["transport"] == "mptcp", "route changed or not fresh")
    if historical:
        require("readiness" not in value, "historical recovery cannot claim readiness")
    else:
        validate_readiness(value["readiness"], publication, layout, before, peers)
        require(value["readiness"]["completed_ns"] <= output["gate_started_ns"]
            and value["readiness"]["completed_unix_ms"] < output["event_baseline_unix_ms"],
            "readiness overlaps measured recovery")
    BASE["validate_path"](value, peers, list(NODES), False)
    for node, size in zip(NODES, (1048699, 1048576)):
        require(size <= value["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"] <= size+131072,
            "provider shard traffic inconsistent")
    validate_gate(value["gate"])
    require(first_snapshot(value["first_snapshot"]), "first generic snapshot was not one verified offer")
    final = value["final_snapshot"]
    # Snapshots need not repeat A: one verified A followed by one verified B is
    # sufficient. The activation, exact useful suppliers and shard/hash checks
    # independently prove recovery; an offer count alone never proves a new peer.
    require(2 <= count(final["client"], EVENTS[0]) <= 3 and count(final["client"], EVENTS[1]) >= 2
        and 2 <= count(final["broker"], EVENTS[3]) <= 3 and 2 <= count(final["broker"], EVENTS[4]) <= 48,
        "bounded genuine rediscovery not proven")
    for label in ("client", "broker"):
        require(final[label][:len(value["first_snapshot"][label])] == value["first_snapshot"][label], "snapshot lineage changed")
        require(all(row["event"] in EVENTS and type(row["unix_ms"]) is int
            and row["unix_ms"] > output["event_baseline_unix_ms"] for row in final[label]), "invalid event interval")
    times = [output[k] for k in ("gate_started_ns", "fetch_started_ns", "first_snapshot_observed_ns",
        "late_activation_started_ns", "late_activation_acknowledged_ns", "gate_released_ns", "fetch_completed_ns")]
    require(all(type(v) is int and v > 0 for v in times) and times == sorted(times)
        and times[5]-times[0] <= GATE_NS and 0 < times[-1]-times[1] <= 300_000_000_000
        and output["cold_cache"] is True and output["consumer_provider_hints"] is False and output["origin_fallback"] is False,
        "activation ordering or absolute gate/transfer bound violated")
    for node in NODES:
        records = value["providers"][node]
        require(records["before"]["serving"] is False and records["before"]["publications"] == 0
            and records["serve"]["serving"] is True and records["serve"]["publications"] == 1
            and records["serve"]["replication_enabled"] is False
            and records["stop"]["serving"] is False and records["stop"]["publications"] == 0, "provider lifecycle incomplete")
    require(value["run_cleanup"] == dict(fetch_reaped=True, gate_removed=True, operation_completed=True)
        and value["cleanup"] == dict(route_disconnected=True, active_contexts=0, paths_empty=True,
            client_output_removed=True, client_manifest_removed=True, client_mount_isolated=True), "cleanup/isolation incomplete")
    validate_control(value, control[0])


def validate_control(value, broker):
    capture, routes = value["control_underlay"]["capture"], value["control_underlay"]["routes"]
    pairs = {f"lc{i}": [BASE["PUBLIC_IPS"][broker], BASE["PUBLIC_IPS"][node]] for i, node in enumerate(NODES)}
    require(capture["capture_role"] == "content-control" and capture["content_provider_mode"] is True
        and capture["content_control_pairs"] == pairs and set(capture["interfaces"]) == set(pairs)
        and set(capture["content_control_packets"]) == set(pairs)
        and capture["unexpected_provider_control_packets"] == capture["unexpected_provider_application_packets"] == 0
        and all(value == 0 for counters in capture["provider_application"].values() for value in counters.values()),
        "unexpected control-link traffic")
    BASE["validate_drained"](capture)
    for i, node in enumerate(NODES):
        require(all(capture["content_control_packets"][f"lc{i}"][key] > 0 for key in ("inbound", "outbound")), "missing control traffic")
        for direction, dev, gateway, source, destination in (
                ("out", f"lc{i}", f"10.241.{86+i}.2", BASE["PUBLIC_IPS"][broker], BASE["PUBLIC_IPS"][node]),
                ("back", f"lp{i}", f"10.241.{86+i}.1", BASE["PUBLIC_IPS"][node], BASE["PUBLIC_IPS"][broker])):
            rows = routes[node][direction]
            require(len(rows) == 1 and all(rows[0].get(k) == v for k, v in
                dict(dev=dev, gateway=gateway, prefsrc=source, dst=destination).items()), "wrong dedicated control route")


def build_evidence(work):
    value = {key: read(path(work, suffix)) for key, suffix in (("publication", "publication"), ("layout", "layout"),
        ("status_before", "status-before"), ("status_after", "status-after"), ("fetch", "fetch"), ("output", "object"),
        ("selected_before", "selection"), ("selected_route", "live-selection"), ("cleanup", "cleanup"),
        ("first_snapshot", "first-snapshot"), ("final_snapshot", "final-snapshot"), ("gate", "gate-installed"), ("run_cleanup", "run-cleanup"),
        ("readiness", "readiness"))}
    value.update(schema_version=2, success=True, concurrent_provider_overlap_claimed=False,
        expected_peers=read(work / "a01-expected-peers.json"),
        previous_context=read(work / "content-provider-adaptive-selection.json")["route_context_id"],
        providers={node: {op: read(path(work, f"{node}-{op}")) for op in ("before", "serve", "stop")} for node in NODES},
        privacy={role: read(path(work, f"privacy-{role}")) for role in ROLES},
        control_underlay=dict(capture=read(path(work, "control-privacy")), routes={node: {direction:
            json.loads(path(work, f"control-{node}-{direction}").read_text()) for direction in ("out", "back")} for node in NODES}))
    status = path(work, "final-status", "txt").read_text().splitlines()
    require("connected: false" in status and "active contexts: 0" in status
        and path(work, "final-paths", "txt").read_text() == "", "route still active")
    validate(value); return value


def main():
    action, *args = sys.argv[1:]
    if action == "run" and len(args) == 3: run(Path(args[0]), Path(args[1]), args[2])
    elif action == "prepare" and len(args) == 3: prepare(*(Path(arg) for arg in args))
    elif action == "cleanup" and len(args) == 1: cleanup(Path(args[0]))
    elif action == "evidence" and len(args) == 2: write(Path(args[1]), build_evidence(Path(args[0])))
    else: raise ValueError("invalid late recovery action")


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("late-provider fixture failed closed", file=sys.stderr); raise SystemExit(1)
