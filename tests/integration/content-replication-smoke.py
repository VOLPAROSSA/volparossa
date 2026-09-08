#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact-source P/Q uptake, explicit reopen and re-serving; not general spare-capacity proof."""

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
import struct
import sys
import time

CAPTURE = runpy.run_path(str(Path(__file__).with_name("content-replication-capture.py")))
P_BYTES, Q_BYTES = 524609, 524411
P_SHA = "507a1f72e20863b91dbd92265ad6d58499cc16fab5a9d753676c56bbe87cb836"
Q_SHA = "22da54d461a4bfef4e32682d16db4771dd1a810e032aebbc669618259601326a"
ROLES = ("receiver", "relay-a", "relay-b", "exit", "provider")
RELAY_NODES = {"relay0", "relay1", "relay2"}
PHYSICAL_INTERFACES = {
    "client": {"underlay", "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cb1", "cb2"},
    "relay0": {"underlay", "r0c", "r0b1", "r0b2", "r0x", "r0x2", "r0a", "rp0"},
    "relay1": {"underlay", "r1c", "r1b1", "r1b2", "r1x", "r1a", "rp1"},
    "relay2": {"underlay", "r2c", "r2b1", "r2b2", "r2x", "r2a", "rp2"},
    "relay4": {"underlay", "r4c", "r4b1", "r4b2", "r4x", "ar0", "ar1", "ar2"},
    "relay5": {"underlay", "r5c", "r5b1", "r5b2", "r5x", "pr0", "pr1", "pr2"},
    "exit": {"underlay", "xr0", "xr1", "xr2", "xr3", "xr4", "xr5", "xd"},
}
SCOPE = ("full_c03_claimed", "full_c04_claimed", "speed_improvement_claimed",
         "browser_integration_claimed", "full_alpha_acceptance_claimed")
ISOLATION = ("replicator_cannot_read_original_cache", "consumer_cannot_read_either_cache",
             "reserve_manifest_not_supplied_to_replicator", "replica_cache_initially_absent",
             "final_cache_initially_absent", "original_listener_absent_before_final_fetch",
             "replica_listener_absent_before_reopen", "replica_reopened_after_original_shutdown")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    with Path(path).open("rb") as source:
        data = source.read(2 * 1024 * 1024 + 1)
    require(len(data) <= 2 * 1024 * 1024, "oversized evidence")
    return json.loads(data)


def publication_module():
    # The early capless owner probe deliberately stages only this file and CAPTURE.
    # Additional publication helpers are needed only by the final evidence checker.
    return runpy.run_path(str(Path(__file__).with_name("content-contribution-publish-smoke.py")))


def configure_automatic(path):
    """Append only the explicit disposable R4 consent; preserve its existing role/budget config."""
    metadata = path.lstat()
    require(path.is_absolute() and path.name == "config-relay4.yaml"
            and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 16384,
            "unexpected disposable configuration")
    text = path.read_text(encoding="ascii")
    require(not re.search(r"(?m)^content_contribution:", text), "contribution already configured")
    for section, fields in (("roles", ("client", "relay")),
                            ("sharing", ("enabled",)), ("download_sharing", ("enabled",))):
        blocks = re.findall(r"(?m)^" + section + r":\n((?:[ \t].*\n)+)", text)
        require(len(blocks) == 1 and all(re.search(r"(?m)^  " + field + r": true$", blocks[0])
                                       for field in fields), "missing explicit role/sharing consent")
    cache = path.parent / "state-relay4" / "content" / "automatic-replicas"
    require(not cache.exists() and not cache.is_symlink(), "automatic cache must start absent")
    config = dict(enabled=True, bind_address="49.165.5.1:18080",
                  advertised_hostname="provider-a.volparossa.test", cache=str(cache),
                  quota_bytes=67108864, max_entries=256, min_free_bytes=268435456,
                  max_bytes=1048576, max_chunks=4)
    # JSON scalars are valid YAML. Only this known private fixture file is changed, in place.
    with path.open("a", encoding="ascii") as target:
        target.write("\ncontent_contribution:\n")
        for key, value in config.items():
            target.write(f"  {key}: {json.dumps(value)}\n")
    return dict(content_contribution=config, relay_enabled=True, sharing_enabled=True,
                download_sharing_enabled=True, cache_initially_absent=True)


def automatic_cache(path):
    """Private cache/journal metadata only, never exported chunks or publisher keys."""
    metadata = path.lstat()
    require(path.is_absolute() and path.name == "automatic-replicas"
            and stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700,
            "unsafe automatic cache")
    journal = path / ".volparossa-replicas-v1"
    record = dict(device=metadata.st_dev, inode=metadata.st_ino, uid=metadata.st_uid,
                  gid=metadata.st_gid, mode=stat.S_IMODE(metadata.st_mode), journal_sha256=None,
                  journal_bytes=0)
    if journal.exists() or journal.is_symlink():
        entry = journal.lstat()
        require(stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1
                and stat.S_IMODE(entry.st_mode) == 0o600 and entry.st_uid == metadata.st_uid
                and entry.st_gid == metadata.st_gid and 0 < entry.st_size <= 8 * 1024 * 1024,
                "unsafe replica journal")
        record.update(journal_sha256=hashlib.sha256(journal.read_bytes()).hexdigest(),
                      journal_bytes=entry.st_size)
    return record


def owner_process(mode, work, cache, run_id):
    """Disposable capless owner traffic and metadata-only observation, not a product API."""
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    require(os.getuid() != 0 and int(status["CapEff"].strip(), 16) == 0
            and int(status["CapBnd"].strip(), 16) == 0 and status["NoNewPrivs"].strip() == "1",
            "owner process must run unprivileged and capless")
    identity = dict(uid=os.getuid(), gid=os.getgid(), pid=os.getpid(),
                    netns=os.stat("/proc/self/ns/net").st_ino, cap_eff=0, cap_bnd=0, no_new_privs=True)
    packet_prefix = b"VPC04OWN" + hashlib.sha256(run_id.encode("ascii")).digest()[:16]
    record = dict(mode=mode, complete=False, identity=identity, packets=0, bytes=0)
    running = True

    def stop(*_args):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    deadline = time.monotonic() + 45
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as transport:
        source = mode == "owner-source"
        transport.bind(("10.241.90.1" if source else "10.241.90.2", 19004))
        transport.setblocking(False)
        record["socket_priority"] = transport.getsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY)
        require(record["socket_priority"] == 0, "owner socket must not use contribution priority")
        (work / "content-replication-owner" / f"{mode}.ready").write_text("ready\n")
        try:
            if source:
                # Only fixture-known names and sizes are observed, never cache payload/key reads.
                expected = [(hashlib.sha256(bytes([value]) * length).hexdigest(), length)
                            for value, length in ((ord("q"), 262144), (ord("r"), 262144), (ord("s"), 123))]
                observed = {}

                def observe():
                    for index, (name, length) in enumerate(expected):
                        if str(index) in observed:
                            continue
                        try:
                            metadata = (cache / name).lstat()
                        except FileNotFoundError:
                            continue
                        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                                and metadata.st_nlink == 1 and metadata.st_size == length,
                                "unexpected fixture cache entry")
                        observed[str(index)] = dict(at_ns=time.monotonic_ns(), bytes=length)

                while running and not observed and time.monotonic() < deadline:
                    observe()
                    time.sleep(0.002)
                require(running and "0" in observed and "2" not in observed,
                        "remaining replica credit opportunity not observed")
                record["chunks"] = observed
                record["owner_start_ns"] = time.monotonic_ns()
                until = time.monotonic() + 3
                while running and time.monotonic() < until:
                    packet = packet_prefix + struct.pack("!Q", record["packets"]) + bytes(1168)
                    require(transport.sendto(packet, ("10.241.90.2", 19004)) == 1200, "owner send truncated")
                    record["packets"] += 1
                    record["bytes"] += len(packet)
                    observe()
                    # Fixture offered load only: never delay or alter the product stream.
                    time.sleep(0.00125)
                record["owner_end_ns"] = time.monotonic_ns()
                while running and len(observed) != 3 and time.monotonic() < deadline:
                    observe()
                    time.sleep(0.002)
                require(running and len(observed) == 3, "same-session replica resume missing")
                record["complete"] = True
            else:
                transport.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                while time.monotonic() < deadline:
                    readable, _, _ = select.select([transport], [], [], 0.05 if running else 0)
                    if not readable:
                        if not running:
                            record.update(complete=True, drained=True)
                            break
                        continue
                    packet, peer = transport.recvfrom(1201)
                    require(peer == ("10.241.90.1", 19004) and len(packet) == 1200
                            and packet[:24] == packet_prefix and packet[32:] == bytes(1168)
                            and struct.unpack("!Q", packet[24:32])[0] == record["packets"],
                            "owner payload/source/order mismatch")
                    at = time.monotonic_ns()
                    record.setdefault("first_packet_ns", at)
                    record["last_packet_ns"] = at
                    record["packets"] += 1
                    record["bytes"] += len(packet)
                require(record["complete"], "owner receiver was not stopped and drained")
        finally:
            transport.close()
            record["socket_closed"] = True
            # stdout is an already-open root-owned report file; no writable agent state is shared.
            print(json.dumps(record, sort_keys=True), flush=True)


def validate_contention(evidence):
    source, sink = evidence["owner_source"], evidence["owner_sink"]
    isolation = evidence["owner_isolation"]
    for item, node in ((source, "relay4"), (sink, "relay0")):
        require(item["complete"] is True and item["socket_closed"] is True
                and item["socket_priority"] == 0 and item["identity"]["cap_eff"] == item["identity"]["cap_bnd"] == 0
                and item["identity"]["no_new_privs"] is True
                and item["identity"]["uid"] == isolation["uid"] != 0
                and item["identity"]["gid"] == isolation["gid"]
                and item["identity"]["netns"] == isolation[node] != isolation["parent"],
                "owner traffic was not capless in the exact disposable namespace")
    require(source["identity"]["netns"] != sink["identity"]["netns"]
            and source["identity"]["pid"] != sink["identity"]["pid"] and sink["drained"] is True
            and source["packets"] == sink["packets"] >= 1000
            and source["bytes"] == sink["bytes"] == source["packets"] * 1200,
            "independent owner payload or full drain missing")
    start, end, chunks = source["owner_start_ns"], source["owner_end_ns"], source["chunks"]
    require(3_000_000_000 <= end - start < 4_000_000_000
            and sink["last_packet_ns"] - sink["first_packet_ns"] >= 2_500_000_000
            and set(chunks) == {"0", "1", "2"}
            and [chunks[str(index)]["bytes"] for index in range(3)] == [262144, 262144, 123]
            and chunks["0"]["at_ns"] <= start < chunks["2"]["at_ns"]
            and end < chunks["2"]["at_ns"] < chunks["0"]["at_ns"] + 15_000_000_000
            and source["bytes"] * 8 * 1_000_000_000 / (end - start) > 2_000_000,
            "owner load, withheld remaining chunk or bounded actual resume missing")
    require(evidence["owner_cleanup"] == {"complete": True, "remaining_processes": 0},
            "owner fixture processes survived cleanup")
    captures = evidence["phases"]["uptake"]["captures"]
    require(captures["receiver"]["owner_fixture_payload_bytes"] == source["bytes"],
            "actual configured ar0 owner traffic not physically observed")
    for role in ("provider", "exit"):
        timeline = captures[role]["provider_payload_timeline"]
        require(0 < len(timeline) <= 4096 and all(set(row) == {"at_ns", "flow", "bytes"}
                and 0 <= row["flow"] < 16 and row["bytes"] > 0 for row in timeline),
                "bounded actual provider flow observations missing")
        # Identify the flow carrying the post-owner Q tail. No new connection may impersonate resume.
        flows = {row["flow"] for row in timeline}
        matches = []
        for flow in flows:
            rows = [row for row in timeline if row["flow"] == flow]
            before = sum(row["bytes"] for row in rows if row["at_ns"] <= start)
            during = [row for row in rows if start < row["at_ns"] < end]
            after = sum(row["bytes"] for row in rows if end <= row["at_ns"])
            last_active = max([start, *(row["at_ns"] for row in during)])
            if before >= 262144 and after >= 123 and end - last_active >= 1_000_000_000 \
                    and sum(row["bytes"] for row in during) <= 262144 + 16384:
                matches.append(flow)
        require(len(matches) == 1, "same provider flow did not yield (one in-flight chunk allowed) and resume")


def validate_route(route, peers):
    paths, slots = route["paths"], route["benchmark_slots"]
    selected_relays = {slot["relay_node"] for slot in slots}
    require(route["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and re.fullmatch(r"[0-9a-f]{32}", route["route_context_id"])
            and len(selected_relays) == 2 and selected_relays <= RELAY_NODES
            and [slot["relay_peer_id"] for slot in slots] == [path["relay_peer_id"] for path in paths]
            and all(slot["relay_peer_id"] == peers[slot["relay_node"]] for slot in slots)
            and {path["relay_peer_id"] for path in paths} == {peers[node] for node in selected_relays}
            and all(path["exit_peer_id"] == peers["exit"]
                    and path["route_context_id"] == route["route_context_id"] for path in paths),
            "actual same-Exit two-relay MPTCP route not proven")


def validate_capture(capture, layout, node):
    require(capture["capture_role"] == capture["node"] == node and capture["phase"] == layout["phase"]
            and capture["schema_version"] == 1 and capture["complete"] is True
            and capture["truncated"] is False and capture["observed_frames"] > 0
            and capture["packet_socket_drops"] == 0 and capture["forbidden_packets"] == 0
            and capture["malformed_packets"] == 0 and capture["direct_client_exit_packets"] == 0
            and capture["direct_provider_packets"] == 0,
            "incomplete physical capture or forbidden direct/plain traffic")
    statistics = capture["interface_statistics"]
    require(set(statistics) == set(capture["interfaces"]) == PHYSICAL_INTERFACES[node]
            and len(statistics) == len(capture["interfaces"])
            and all(re.fullmatch(r"underlay|[a-z][a-z0-9]{1,5}", interface)
                    and not interface.startswith("vp") and interface != "lo" for interface in statistics)
            and sum(row["observed_frames"] for row in statistics.values()) == capture["observed_frames"]
            and all(row["intake_stopped"] is True and row["drained"] is True
                    and row["packet_socket_drops"] == 0
                    and row["packet_socket_packets"] == row["observed_frames"]
                    and 4194304 <= row["receive_buffer_bytes"] <= 8388608 for row in statistics.values()),
            "physical packet intake not stopped and drained exactly")


def validate_phase(phase, name, peers, minimum_bytes=None):
    layout = phase["layout"]
    CAPTURE["validate_layout"](layout)
    relays = sorted(layout["relays"])
    require(layout["phase"] == name and set(relays) ==
            {slot["relay_node"] for slot in phase["route"]["benchmark_slots"]},
            "phase or selected relay capture substitution")
    validate_route(phase["route"], peers)
    captures = phase["captures"]
    require(set(captures) == set(ROLES), "five-role capture coverage incomplete")
    for role, capture in captures.items():
        node = (layout["client"]["node"] if role == "receiver" else
                layout["provider"]["node"] if role == "provider" else
                relays[0] if role == "relay-a" else relays[1] if role == "relay-b" else role)
        validate_capture(capture, layout, node)
    for slot, relay in zip(("relay-a", "relay-b"), relays):
        require(captures[slot]["client_leg_wireguard_data_datagrams"] > 16
                and captures[slot]["exit_leg_wireguard_data_datagrams"] > 16
                and captures["receiver"][f"{relay}_client_leg_wireguard_data_datagrams"] > 16
                and captures["exit"][f"{relay}_exit_leg_wireguard_data_datagrams"] > 16,
                "both physical WireGuard legs on both paths did not carry data")
    if minimum_bytes is None:
        minimum_bytes = P_BYTES + Q_BYTES if name == "uptake" else Q_BYTES
    for role in ("exit", "provider"):
        require(captures[role]["provider_request_packets"] > 0
                and captures[role]["provider_response_packets"] > 0
                and captures[role]["provider_response_payload_bytes"] >= minimum_bytes,
                "actual Exit-to-provider request/response payload missing")
    for role in ("receiver", "relay-a", "relay-b"):
        require(captures[role]["provider_request_packets"] == 0
                and captures[role]["provider_response_packets"] == 0
                and captures[role]["provider_response_payload_bytes"] == 0,
                "provider application bytes escaped the protected path")


def validate_fetch(receipt, count, chunks, provider, control):
    require(receipt["bytes"] == receipt["peer_bytes"] == count and receipt["chunks"] == chunks
            and receipt["providers_used"] == 1 and receipt["provider_peer_ids"] == [provider]
            and receipt["control_relay_peer_id"] in control
            and receipt["origin_authenticated"] is False and receipt["origin_body_bytes"] == 0
            and receipt["origin_range_requests"] == 0,
            "exact independent provider, payload count or control lineage missing")


def validate_automatic(evidence):
    automatic, peers = evidence["automatic_contribution"], evidence["expected_peers"]
    configuration = automatic["config"]
    config = configuration["content_contribution"]
    cache = Path(config["cache"])
    require(cache.is_absolute() and cache.parts[-3:] ==
            ("state-relay4", "content", "automatic-replicas"), "wrong automatic cache path")
    expected = dict(enabled=True, bind_address="49.165.5.1:18080",
                    advertised_hostname="provider-a.volparossa.test", cache=str(cache),
                    quota_bytes=67108864, max_entries=256, min_free_bytes=268435456,
                    max_bytes=1048576, max_chunks=4)
    require(config == expected and all(configuration[field] is True for field in
            ("relay_enabled", "sharing_enabled", "download_sharing_enabled", "cache_initially_absent")),
            "explicit bounded automatic contribution consent missing")
    for name, count in (("before", 0), ("after", 1), ("restored", 1)):
        status = automatic[name]
        require(status["serving"] is True and status["replication_enabled"] is True
                and status["publications"] == status["replica_publications"] == count
                and status["replica_chunks"] == count * 3 and status["replica_bytes"] == count * P_BYTES,
                "empty startup, automatic P storage or journal restoration missing")
    for name in ("origin_stop", "stop"):
        require(automatic[name]["serving"] is False and automatic[name]["publications"] == 0,
                "automatic phase service did not stop")
    require(automatic["origin_offline"] == evidence["origin_offline"], "original provider remains online")
    startup, restart = automatic["startup"], automatic["restart"]
    for record in (startup, restart):
        require(record["unit"] == "volparossa-alpha-agent@relay4.service"
                and record["active_state"] == "active" and record["executable_verified"] is True
                and isinstance(record["pid_before"], int) and isinstance(record["pid_after"], int)
                and record["pid_before"] > 0 and record["pid_after"] > 0
                and record["pid_before"] != record["pid_after"]
                and re.fullmatch(r"[0-9]+:[0-9]+", record["network_namespace_identity"]),
                "actual owned R4 agent restart missing")
    require(startup["pid_after"] == restart["pid_before"]
            and startup["network_namespace_identity"] == restart["network_namespace_identity"],
            "automatic agent or namespace substituted across restart")
    empty, before, after = (automatic[name] for name in ("cache_empty", "cache_before", "cache_after"))
    require(before == after and before["journal_bytes"] > 0
            and re.fullmatch(r"[0-9a-f]{64}", before["journal_sha256"]),
            "original owned replica journal not preserved across restart")
    require(all(empty[field] == before[field] for field in ("device", "inode", "uid", "gid", "mode"))
            and before["mode"] == 0o700 and before["inode"] > 0 and before["uid"] > 0,
            "automatic contribution cache replaced or not private")
    output = automatic["output"]
    require(output["manual_serve_used_on_replicator"] is False
            and all(output[field] is True for field in
                    ("download_cache_initially_absent", "consumer_cache_initially_absent",
                     "replicator_cannot_read_original_cache", "consumer_cannot_read_either_cache",
                     "replicator_restarted_after_original_shutdown"))
            and all(output[field] == dict(bytes=P_BYTES, sha256=P_SHA) for field in ("foreground", "final")),
            "automatic P transfer, isolation or original hash not proven")
    control = {peers[node] for node in RELAY_NODES}
    contexts = {phase["route"]["route_context_id"] for phase in evidence["phases"].values()}
    for phase, receipt_name, provider in (("uptake", "foreground_fetch", "relay5"),
                                         ("reserve-fetch", "final_fetch", "relay4")):
        record, receipt = automatic["phases"][phase], automatic[receipt_name]
        validate_phase(record, phase, peers, P_BYTES)
        validate_fetch(receipt, P_BYTES, 3, peers[provider], control)
        require(receipt["control_relay_peer_id"] not in
                {slot["relay_peer_id"] for slot in record["route"]["benchmark_slots"]},
                "automatic control relay overlaps data relay")
        require(record["route"]["route_context_id"] not in contexts, "automatic transfer reused old route")
        contexts.add(record["route"]["route_context_id"])
    require(automatic["contribution_events"] >= 1, "no actual automatic contribution completion event")


def validate_evidence(evidence):
    require(evidence["success"] is True, "incomplete transfer")
    seed, peers, output = evidence["publication"], evidence["expected_peers"], evidence["output"]
    require(seed["publisher_removed"] is True and seed["publisher_private_key_persisted"] is False
            and seed["replicator_seeded"] is False, "initial publisher/replicator isolation missing")
    for label, field, size, chunks, digest in (("p", "foreground", P_BYTES, 3, P_SHA),
                                              ("q", "reserve", Q_BYTES, 3, Q_SHA)):
        item = seed[field]
        require(item["label"] == label and item["bytes"] == item["seeded_cache_bytes"] == size
                and item["chunks"] == item["seeded_cache_entries"] == chunks
                and item["object_sha256"] == output[field]["sha256"] == digest
                and output[field]["bytes"] == size
                and item["publisher_removed"] is True and item["publisher_private_key_persisted"] is False
                and re.fullmatch(r"[0-9a-f]{64}", item["publisher_hex"])
                and re.fullmatch(r"[0-9a-f]{64}", item["manifest_id"]), "P/Q publication substitution")
    require(seed["foreground"]["publisher_hex"] == seed["reserve"]["publisher_hex"]
            and seed["foreground"]["manifest_id"] != seed["reserve"]["manifest_id"]
            and all(output[field] is True for field in ISOLATION), "cross-publication trust or isolation missing")
    control = {peers[node] for node in RELAY_NODES}
    require(len({peers[node] for node in ("client", "relay0", "relay1", "relay2", "relay4", "relay5", "exit")}) == 7,
            "fixture identities are not independent")
    validate_fetch(evidence["warm_fetch"], P_BYTES, 3, peers["relay5"], control)
    validate_fetch(evidence["foreground_fetch"], P_BYTES, 3, peers["relay5"], control)
    validate_fetch(evidence["final_fetch"], Q_BYTES, 3, peers["relay4"], control)
    before, after = evidence["before"], evidence["after"]
    require(before["serving"] is True and before["replication_enabled"] is True
            and before["replica_chunks"] == before["replica_bytes"] == before["replica_publications"] == 0
            and after["serving"] is True and after["replication_enabled"] is True
            and after["replica_chunks"] == 3 and after["replica_bytes"] == Q_BYTES
            and after["replica_publications"] == 1 and after["publications"] == 2
            and before["control_relay_peer_id"] == after["control_relay_peer_id"]
            == evidence["foreground_fetch"]["control_relay_peer_id"],
            "actual bounded new Q storage/registration after foreground P not proven")
    for record in (evidence["origin_stop"], evidence["replica_pause"], evidence["replica_stop"]):
        require(record["serving"] is False and record["publications"] == 0,
                "service withdrawal incomplete")
    resumed = evidence["replica_resume"]
    require(evidence["replica_pause"]["replication_enabled"] is False
            and resumed["serving"] is True and resumed["replication_enabled"] is True
            and resumed["publications"] == 2 and resumed["replica_publications"] == 1
            and resumed["replica_chunks"] == 3 and resumed["replica_bytes"] == Q_BYTES,
            "explicitly recreated service did not restore original Q registration and chunks")
    require(evidence["origin_offline"] == dict(unit="volparossa-alpha-agent@relay5.service",
            active_state="inactive", main_pid=0, listener_absent=True),
            "original provider agent was not stopped before final retrieval")
    for phase in ("uptake", "reserve-fetch"):
        validate_phase(evidence["phases"][phase], phase, peers)
        selected = evidence["phases"][phase]["route"]
        receipt = evidence["foreground_fetch"] if phase == "uptake" else evidence["final_fetch"]
        require(receipt["control_relay_peer_id"] not in
                {slot["relay_peer_id"] for slot in selected["benchmark_slots"]},
                "control relay was substituted by one of the two data relays")
    require(evidence["phases"]["uptake"]["route"]["route_context_id"] !=
            evidence["phases"]["reserve-fetch"]["route"]["route_context_id"],
            "independent consumer reused another node's route authority")
    events = evidence["events"]
    require(events["replica_chunks_available"] >= 1 and events["exit_mptcp_flows_completed"] >= 4
            and events["replicator_forwarded_discovery"] >= 2 and events["consumer_forwarded_discovery"] >= 1,
            "native replica registration, genuine MPTCP completion or forwarded discovery missing")
    validate_contention(evidence)
    validate_automatic(evidence)
    public = evidence["public_publication"]
    publication = publication_module()
    require(public["publish"]["publisher_key_hex"] != seed["foreground"]["publisher_hex"],
            "ordinary publisher reused the earlier fixture's signing identity")
    publication["validate_evidence"](public, evidence["automatic_contribution"], peers)
    validate_phase(public["phase"], "reserve-fetch", peers, publication["BYTES"])
    receipt = public["application"]["final"]
    validate_fetch(receipt, publication["BYTES"], 9, peers["relay4"], {peers[node] for node in RELAY_NODES})
    require(receipt["control_relay_peer_id"] not in
            {slot["relay_peer_id"] for slot in public["phase"]["route"]["benchmark_slots"]},
            "public publication control relay overlaps a carrying data relay")
    old_phases = (*evidence["phases"].values(), *evidence["automatic_contribution"]["phases"].values())
    require(public["phase"]["route"]["route_context_id"] not in
            {phase["route"]["route_context_id"] for phase in old_phases}, "public fetch reused an earlier route")


def build_evidence(work):
    mapping = {"publication": "publication", "output": "output", "warm_fetch": "warm-fetch",
               "foreground_fetch": "foreground-fetch", "final_fetch": "final-fetch",
               "before": "before", "after": "after", "origin_stop": "origin-stop",
               "origin_offline": "origin-offline", "replica_stop": "replica-stop",
               "replica_pause": "replica-pause", "replica_resume": "replica-resume",
               "owner_source": "owner-source", "owner_sink": "owner-sink",
               "owner_isolation": "owner-isolation", "owner_cleanup": "owner-cleanup"}
    evidence = {key: read(work / f"content-replication-{suffix}.json") for key, suffix in mapping.items()}
    evidence.update(success=True, expected_peers=read(work / "a01-expected-peers.json"), phases={})
    for phase, route in (("uptake", "uptake"), ("reserve-fetch", "final")):
        evidence["phases"][phase] = dict(layout=read(work / f"content-replication-{phase}-layout.json"),
            route=read(work / f"content-replication-{route}-live-selection.json"),
            captures={role: read(work / f"content-replication-{phase}-{role}.json") for role in ROLES})
    def event_count(node, event):
        with (work / f"content-replication-legacy-logs-{node}.txt").open("rb") as source:
            data = source.read(2 * 1024 * 1024 + 1)
        require(len(data) <= 2 * 1024 * 1024, "oversized event log")
        return len(re.findall(rb"(?m)^\d+\s+\S+\s+event=" + event.encode("ascii") + rb"(?:\s|$)", data))
    evidence["events"] = dict(replica_chunks_available=event_count("relay4", "CONTENT_REPLICATION_CHUNKS_AVAILABLE"),
        exit_mptcp_flows_completed=event_count("exit", "MPTCP_EXIT_FLOW_COMPLETED"),
        replicator_forwarded_discovery=event_count("relay4", "CONTENT_DISCOVERY_COMPLETED"),
        consumer_forwarded_discovery=event_count("client", "CONTENT_DISCOVERY_COMPLETED"))
    require((work / "content-replication-origin-listeners.txt").stat().st_size == 0,
            "original provider listener remains")
    require((work / "content-replication-paused-listeners.txt").stat().st_size == 0,
            "replica listener survived explicit service stop")
    fields = ("config", "before", "after", "restored", "startup", "restart", "cache-empty",
              "cache-before", "cache-after", "origin-stop", "origin-offline", "stop", "output",
              "foreground-fetch", "final-fetch")
    automatic = {field.replace("-", "_"): read(work / f"content-replication-automatic-{field}.json")
                 for field in fields}
    automatic["phases"] = {}
    for phase, route in (("uptake", "uptake"), ("reserve-fetch", "final")):
        prefix = "content-replication-automatic-" + phase
        automatic["phases"][phase] = dict(layout=read(work / f"{prefix}-layout.json"),
            route=read(work / f"content-replication-automatic-{route}-live-selection.json"),
            captures={role: read(work / f"{prefix}-{role}.json") for role in ROLES})
    with (work / "content-replication-automatic-uptake-events.txt").open("rb") as source:
        events = source.read(2 * 1024 * 1024 + 1)
    require(len(events) <= 2 * 1024 * 1024, "oversized automatic event log")
    automatic["contribution_events"] = len(re.findall(
        rb"(?m)^\d+\s+\S+\s+event=CONTENT_CONTRIBUTION_CHUNKS_AVAILABLE(?:\s|$)", events))
    require((work / "content-replication-automatic-origin-listeners.txt").stat().st_size == 0,
            "original provider listener survives automatic contribution phase")
    evidence["automatic_contribution"] = automatic
    evidence["public_publication"] = publication_module()["build_evidence"](work)
    validate_evidence(evidence)
    return evidence


def validate_report(report, revision):
    require(report["report_kind"] == "volparossa-content-replication" and report["source_revision"] == revision
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision)
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["cleanup"] == {"complete": True, "remaining_owned_objects": 0}
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"]
            and re.fullmatch(r"[0-9a-f]{64}", report["host_state"]["before_sha256"])
            and all(report[flag] is False for flag in SCOPE), "wrong revision, cleanup, host state or scope")
    validate_evidence(report["transfer"])


if __name__ == "__main__":
    try:
        if len(sys.argv) == 5 and sys.argv[1] in ("owner-source", "owner-sink"):
            owner_process(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
            raise SystemExit(0)
        if len(sys.argv) != 4:
            raise ValueError("usage: evidence WORK OUTPUT | report REPORT REVISION")
        if sys.argv[1] == "evidence":
            result = build_evidence(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as target:
                json.dump(result, target, sort_keys=True, separators=(",", ":"))
        elif sys.argv[1] == "report":
            validate_report(read(sys.argv[2]), sys.argv[3])
        elif sys.argv[1] in ("configure-automatic", "automatic-cache"):
            function = configure_automatic if sys.argv[1] == "configure-automatic" else automatic_cache
            result = function(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as target:
                json.dump(result, target, sort_keys=True, separators=(",", ":"))
        else:
            raise ValueError("unknown command")
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"content replication evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
