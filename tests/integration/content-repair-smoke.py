#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-bound autonomous public-journal repair; seeded setup is not network placement."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

SITE = runpy.run_path(str(Path(__file__).with_name("content-provider-site-smoke.py")))
SHARED = runpy.run_path(str(Path(__file__).with_name("content-replication-smoke.py")))
read, require = SHARED["read"], SHARED["require"]
CHUNK = 262144
PAYLOAD = b"".join(bytes([value]) * CHUNK for value in (17, 59, 101))
SHA = hashlib.sha256(PAYLOAD).hexdigest()
CHUNK_HASHES = tuple(hashlib.sha256(bytes([value]) * CHUNK).hexdigest() for value in (17, 59, 101))
RELAYS = {"relay0", "relay1", "relay2"}
UPTAKE_ROLES = ("receiver", "relay0", "relay1", "relay2", "exit", "provider")


def bounded(path, maximum):
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    require(len(value) <= maximum, "oversized fixture file")
    return value


def owned_file(path, uid, gid, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and metadata.st_uid == uid and metadata.st_gid == gid
                and 0 < metadata.st_size <= maximum, "unsafe owned fixture file")
        data = source.read(maximum + 1)
        require(len(data) == metadata.st_size <= maximum, "fixture changed or exceeded bound")
        return data


def cache_snapshot(path):
    path = Path(path)
    require(path.is_absolute() and path.name == "repair-cache"
            and path.parent.name in ("state-relay4", "state-relay5"), "unexpected repair cache path")
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == os.geteuid(), "cache is not an owned private directory")
    owner = os.open(path / ".volparossa-owner-v1", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = os.fstat(owner)
        require(stat.S_ISREG(marker.st_mode) and marker.st_nlink == 1
                and marker.st_uid == metadata.st_uid and marker.st_gid == metadata.st_gid
                and stat.S_IMODE(marker.st_mode) == 0o600 and marker.st_size == 60,
                "invalid locked owner marker")
        names = {item.name for item in path.iterdir()}
        required = {".volparossa-owner-v1", ".volparossa-index-v1", ".volparossa-replicas-v1"}
        require(required <= names and names <= required | set(CHUNK_HASHES),
                "unexpected files, staging transaction or absent journal")
        journal = owned_file(path / ".volparossa-replicas-v1", metadata.st_uid, metadata.st_gid, 8 * 1024 * 1024)
        index = owned_file(path / ".volparossa-index-v1", metadata.st_uid, metadata.st_gid, 8192)
        chunks = sorted(names & set(CHUNK_HASHES))
        for name in chunks:
            value = owned_file(path / name, metadata.st_uid, metadata.st_gid, CHUNK)
            require(len(value) == CHUNK and hashlib.sha256(value).hexdigest() == name,
                    "fixture chunk content/hash differs")
        return dict(device=metadata.st_dev, inode=metadata.st_ino, uid=metadata.st_uid,
                    gid=metadata.st_gid, mode=stat.S_IMODE(metadata.st_mode),
                    journal_sha256=hashlib.sha256(journal).hexdigest(), journal_bytes=len(journal),
                    index_sha256=hashlib.sha256(index).hexdigest(), chunks=chunks,
                    bytes=len(chunks) * CHUNK, chunk_hashes_verified=True, cache_owner_locked=True)
    finally:
        os.close(owner)


def output_snapshot(path):
    path = Path(path)
    require(path.is_absolute() and path.name == "repair-output.bin"
            and path.parent.name == "content" and path.parent.parent.name == "state-client",
            "unexpected consumer output path")
    metadata = path.lstat()
    data = owned_file(path, metadata.st_uid, metadata.st_gid, len(PAYLOAD))
    require(data == PAYLOAD, "fresh consumer did not reconstruct original fixture")
    return dict(bytes=len(data), sha256=SHA, mode="0600", path=str(path))


def remove_site_acquisition(state):
    state = Path(state)
    require(state.is_absolute() and state.name == "state-relay4", "unexpected site acquisition root")
    SITE["private"](state, True)
    cache, output = state / "site-acquisition-cache", state / "site-acquired.vps"
    meta = SITE["private"](cache, True)
    bundle = owned_file(output, meta.st_uid, meta.st_gid, SITE["BUNDLE_BYTES"])
    digest = hashlib.sha256(bundle).hexdigest()
    require(len(bundle) == SITE["BUNDLE_BYTES"] and digest == SITE["BUNDLE_SHA256"], "wrong acquired site output")
    hashes = {hashlib.sha256(bundle[offset:offset + CHUNK]).hexdigest()
              for offset in range(0, len(bundle), CHUNK)}
    metadata = {".volparossa-owner-v1", ".volparossa-index-v1",
                ".volparossa-name-revisions-v1", ".volparossa-named-manifests-v1"}
    owner = os.open(cache / ".volparossa-owner-v1", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        # The just-completed contribution may still be releasing the source store.
        # The capless guest helper already runs under a bounded timeout.
        fcntl.flock(owner, fcntl.LOCK_EX)
        entries = list(cache.iterdir())
        names = {entry.name for entry in entries}
        require(hashes | {".volparossa-owner-v1", ".volparossa-index-v1"} <= names <= hashes | metadata,
                "unexpected acquisition cache contents")
        for entry in entries:
            data = owned_file(entry, meta.st_uid, meta.st_gid, CHUNK)
            require(entry.name in metadata or hashlib.sha256(data).hexdigest() == entry.name,
                    "wrong acquisition cache chunk")
        for entry in entries:
            entry.unlink()
        cache.rmdir()
        output.unlink()
    finally:
        os.close(owner)
    return dict(temporary_output_removed=True, temporary_cache_removed=True, bytes=len(bundle), sha256=digest)


def validate_cache(snapshot, chunks):
    require(snapshot["mode"] == 0o700 and snapshot["uid"] > 0 and snapshot["inode"] > 0
            and snapshot["chunks"] == sorted(chunks) and snapshot["bytes"] == len(chunks) * CHUNK
            and snapshot["chunk_hashes_verified"] is True and snapshot["cache_owner_locked"] is True
            and snapshot["journal_bytes"] > 0
            and all(re.fullmatch(r"[0-9a-f]{64}", snapshot[name])
                    for name in ("journal_sha256", "index_sha256")), "invalid owned fixture cache snapshot")


def validate_restart_memberships(layout, stopped, restarted):
    memberships = layout["restart_memberships"]
    cap = SHARED["CAPTURE"]
    require(set(memberships) == {"relay4", "relay5"}, "missing original mDNS namespace observations")
    for node, observation in memberships.items():
        require(observation == stopped[node]["restart_membership"]
                and observation["pid_before"] == restarted[node]["pid_before"]
                and observation["network_namespace_identity"] == restarted[node]["network_namespace_identity"]
                and observation["group"] == "224.0.0.251" and 1 <= observation["robustness"] <= 7
                and 0 < observation["observed_ns"] <= observation["stop_started_ns"] <= observation["stop_completed_ns"],
                "mDNS observation is not bound to the original stopped service or its network namespace")
        for iface, row in observation["interfaces"].items():
            source = row["source"]
            label = node + "." + ("public" if iface == "underlay" else iface)
            require(iface in SHARED["PHYSICAL_INTERFACES"][node] and 1 <= row["interval_ms"] <= 10000
                    and source in cap["MDNS_INTERFACE_ADDRESSES"].get((node, iface), ())
                    and cap["FIXTURE_ADDRESS_LABELS"].get(source) == label, "mDNS observation used another source link")


def validate_repair_leaves(capture, layout, node):
    cap = SHARED["CAPTURE"]
    labels = {label: address for address, label in cap["FIXTURE_ADDRESS_LABELS"].items()}
    total = 0
    for key, row in capture["repair_mdns_leaves"].items():
        header = row["header"]
        iface, label = header["interface"], header["source"]
        require(key == iface + "/" + label and iface in capture["interfaces"] and label in labels,
                "mDNS leave sample has no matching physical capture link")
        address = labels[label]
        require(header == dict(interface=iface, source=label, destination="igmpv3.multicast",
                ip_version=4, protocol=2, igmp=dict(parse="complete", type=34, bytes=16, checksum_valid=True,
                ttl=1, router_alert_only=True, record_count=1, records=[dict(type=3, auxiliary_words=0,
                source_count=0, group="mdns.multicast")])) and row["first_ns"] <= row["last_ns"]
                and all(cap["witnessed_repair_leave"](layout, node, iface, address, row[field])
                        for field in ("first_ns", "last_ns")), "unwitnessed, late or unrelated mDNS leave")
        owner = label.partition(".")[0]
        require(0 < row["packets"] <= layout["restart_memberships"][owner]["robustness"],
                "mDNS leaves exceeded the observed kernel retransmission budget")
        total += row["packets"]
    require(total == capture["repair_mdns_leave_packets"] <= capture["mdns_membership_packets"]
            <= capture["control_packets"], "missing or unaccounted mDNS leave observations")


def validate_uptake(phase, peers):
    layout, route, captures = phase["layout"], phase["route"], phase["captures"]
    SHARED["CAPTURE"]["validate_layout"](layout)
    SHARED["validate_route"](route, peers)
    selected = {slot["relay_node"] for slot in route["benchmark_slots"]}
    require(layout["phase"] == "repair-uptake" and set(layout["relays"]) == RELAYS
            and set(captures) == set(UPTAKE_ROLES), "pre-route candidate capture coverage missing")
    for role, capture in captures.items():
        node = "relay4" if role == "receiver" else "relay5" if role == "provider" else role
        SHARED["validate_capture"](capture, layout, node)
        validate_repair_leaves(capture, layout, node)
    for relay in RELAYS:
        counts = (captures[relay]["client_leg_wireguard_data_datagrams"],
                  captures[relay]["exit_leg_wireguard_data_datagrams"],
                  captures["receiver"][f"{relay}_client_leg_wireguard_data_datagrams"],
                  captures["exit"][f"{relay}_exit_leg_wireguard_data_datagrams"])
        require(all(value > 16 for value in counts) if relay in selected else all(value == 0 for value in counts),
                "post-repair selected pair does not match actually carrying candidate legs")
    for role in ("exit", "provider"):
        capture = captures[role]
        require(capture["provider_request_packets"] > 0 and capture["provider_response_packets"] > 0
                and capture["provider_response_payload_bytes"] >= 2 * CHUNK,
                "missing actual protected repair provider response")
    for role in ("receiver", *RELAYS):
        require(all(captures[role][field] == 0 for field in ("provider_request_packets",
                "provider_response_packets", "provider_response_payload_bytes")),
                "repair provider content bypassed the encrypted one-relay path")


def validate_evidence(evidence):
    seed, peers = evidence["publication"], evidence["expected_peers"]
    require(evidence["success"] is True and seed["report_kind"] == "volparossa-public-repair-seed"
            and seed["bytes"] == 3 * CHUNK and seed["chunks"] == 3 and seed["object_sha256"] == SHA
            and seed["holder_chunks"] == 3 and seed["receiver_chunks"] == 1
            and seed["receiver_bytes"] == CHUNK and seed["missing_chunks"] == 2
            and seed["missing_bytes"] == 2 * CHUNK
            and seed["publisher_removed"] is True and seed["publisher_private_key_persisted"] is False
            and seed["initial_placement_over_network"] is False
            and re.fullmatch(r"[0-9a-f]{64}", seed["publisher_hex"])
            and re.fullmatch(r"[0-9a-f]{64}", seed["manifest_id"])
            and seed["expires_unix_seconds"] - seed["created_unix_seconds"] == 7200,
            "original healthy partial-journal setup missing or overstated")
    for status in evidence["before"].values():
        require(status["serving"] is True and status["replication_enabled"] is True
                and status["publications"] == status["replica_publications"] == 0
                and status["replica_chunks"] == status["replica_bytes"] == 0,
                "configured receivers did not start empty")
    require(set(evidence["before"]) == {"relay4", "relay5"}, "initial node statuses missing")
    caches = evidence["caches"]
    validate_cache(caches["seeded_holder"], CHUNK_HASHES)
    validate_cache(caches["seeded_receiver"], CHUNK_HASHES[:1])
    validate_cache(caches["repaired_receiver"], CHUNK_HASHES)
    before, after = caches["seeded_receiver"], caches["repaired_receiver"]
    require(all(before[key] == after[key] for key in ("device", "inode", "uid", "gid", "mode"))
            and before["journal_sha256"] != after["journal_sha256"],
            "repair replaced receiver ownership or failed to journal new references")
    status = evidence["receiver_status"]
    require(status["serving"] is True and status["replication_enabled"] is True
            and status["publications"] == status["replica_publications"] == 1
            and status["replica_chunks"] == 3 and status["replica_bytes"] == 3 * CHUNK,
            "repaired publication is not actually registered")
    validate_restart_memberships(evidence["uptake"]["layout"], evidence["stopped"], evidence["restarted"])
    validate_uptake(evidence["uptake"], peers)
    SHARED["validate_phase"](evidence["final"], "reserve-fetch", peers, 3 * CHUNK)
    require(evidence["uptake"]["route"]["route_context_id"] != evidence["final"]["route"]["route_context_id"],
            "fresh consumer reused the receiver route")
    fetch, output = evidence["fetch"], evidence["output"]
    require(fetch["operation"] == "named_content_download" and fetch["publisher_key"] == seed["publisher_hex"]
            and fetch["name"] == "disposable-public-repair" and fetch["revision"] == 1
            and fetch["manifest_id"] == seed["manifest_id"]
            and fetch["publication_expires_unix_seconds"] == seed["expires_unix_seconds"]
            and fetch["bytes"] == fetch["peer_bytes"] == output["bytes"] == 3 * CHUNK
            and fetch["sha256"] == output["sha256"] == SHA and fetch["chunks"] == 3
            and fetch["providers_used"] == 1 and fetch["provider_peer_ids"] == [peers["relay4"]]
            and fetch["control_relay_peer_id"] in {peers[node] for node in RELAYS}
            and fetch["control_relay_peer_id"] not in {slot["relay_peer_id"] for slot in evidence["final"]["route"]["benchmark_slots"]}
            and fetch["origin_authenticated"] is False and fetch["origin_body_bytes"] == 0
            and fetch["origin_range_requests"] == 0 and fetch["globally_latest"] is False
            and output["mode"] == "0600", "fresh consumer did not retrieve the same object solely from repaired B")
    for node, label in (("relay4", "seeded_receiver"), ("relay5", "seeded_holder")):
        stopped, restarted = evidence["stopped"][node], evidence["restarted"][node]
        cache = caches[label]
        identity = f'{cache["device"]}:{cache["inode"]}'
        require(stopped["unit"] == restarted["unit"] == f"volparossa-alpha-agent@{node}.service"
                and stopped["pid_before"] == restarted["pid_before"] > 0
                and restarted["pid_after"] > 0 and restarted["pid_after"] != restarted["pid_before"]
                and stopped["main_pid"] == 0 and stopped["active_state"] == "inactive"
                and stopped["unit_collected"] is True and stopped["listener_absent"] is True
                and restarted["active_state"] == "active" and restarted["executable_verified"] is True
                and restarted["original_cache_identity_preserved"] is True
                and stopped["cache_identity"] == restarted["cache_identity"] == identity
                and re.fullmatch(r"[0-9]+:[0-9]+", restarted["network_namespace_identity"]),
                "actual provider restart with original owned cache not established")
    offline = evidence["holder_offline"]
    require(offline["unit"] == "volparossa-alpha-agent@relay5.service"
            and offline["pid_before"] == evidence["restarted"]["relay5"]["pid_after"]
            and offline["main_pid"] == 0 and offline["active_state"] == "inactive"
            and offline["unit_collected"] is True and offline["listener_absent"] is True,
            "initial complete holder remained available")
    isolation = evidence["isolation"]
    require(isolation["consumer_uid"] == before["uid"] > 0 and isolation["consumer_gid"] == before["gid"]
            and all(isolation[field] is True for field in (
                "capabilities_dropped", "client_mount_positive_control", "receiver_mount_positive_control",
                "client_cannot_read_holder_cache", "client_cannot_read_receiver_cache",
                "receiver_cannot_read_holder_cache", "publisher_seed_inaccessible", "fresh_consumer_cache",
                "fetch_input_is_publisher_and_name_only")), "actual account/mount/content isolation missing")
    startup = evidence["startup"]
    require(startup["event_baseline_unix_ms"] > 0 and startup["captures_ready_before_restart"] is True
            and startup["initial_active_contexts"] == 0 and startup["foreground_fetch_issued"] is False
            and startup["manual_connect_issued"] is False and startup["initial_placement_over_network"] is False
            and startup["publisher_source_and_key_removed_by_fixture"] is True
            and evidence["receiver_initially_disconnected"] is True,
            "repair was manually triggered or used preexisting receiver route/source")
    require(evidence["events"]["repair_complete"] >= 1
            and evidence["events"]["exit_mptcp_completed"] >= 2,
            "actual repair or MPTCP/TLS flow-completion event missing")

    require("offline_site" in evidence, "independent publisher-offline site evidence missing")
    validate_offline_site(evidence["offline_site"], peers, offline)


def validate_offline_site(site, peers, stopped):
    expected, publication = site["input"], site["publish"]
    size = SITE["BUNDLE_BYTES"]
    require(expected["name"] == SITE["NAME"] and expected["content_type"] == SITE["CONTENT_TYPE"]
            and expected["assets"] == SITE["inventory"]() and expected["bundle_bytes"] == size
            and expected["bundle_sha256"] == SITE["BUNDLE_SHA256"], "site fixture changed")
    require(publication["operation"] == "content_publish" and publication["network_publication"] is True
            and publication["serving"] is True and publication["name"] == expected["name"]
            and publication["content_type"] == expected["content_type"]
            and publication["revision"] == 1 and publication["bytes"] == size and publication["chunks"] == 9
            and publication["publisher_key_hex"] == expected["publisher_key"]
            and re.fullmatch(r"[0-9a-f]{64}", expected["publisher_key"])
            and re.fullmatch(r"[0-9a-f]{64}", publication["manifest_id"])
            and site["source_removed"] == dict(publisher_files_removed=True, source_cache_removed=True,
                                               manifest_removed=True), "site publisher or source cleanup unverified")
    boundary = site["boundary"]
    require([boundary[key] for key in ("publisher_node", "holder_node", "reader_node")] == ["relay5", "relay4", "client"]
            and len({peers["client"], peers["relay4"], peers["relay5"]}) == 3
            and boundary["publisher_pid"] == stopped["pid_before"] and stopped["listener_absent"] is True
            and 0 < boundary["publisher_absent_from_unix_seconds"] <= boundary["publisher_absent_through_unix_seconds"]
                < publication["expires_unix_seconds"]
            and boundary["pid_listener_and_unit_absent_before_and_after"] is True
            and boundary["fresh_client_cache"] is True
            and Path(boundary["agent_cache"]).parts[-2:] == ("state-client", "offline-publisher-site-cache")
            and site["cleanup"] == dict(user_directory_removed=True), "publisher shutdown or fresh consumer unverified")
    holder = site["holder"]
    require(holder["serving"] is True and holder["replication_enabled"] is True
            and holder["replica_publications"] == holder["publications"] == 2
            and holder["replica_chunks"] == 12 and holder["replica_bytes"] == 3 * CHUNK + size,
            "independent holder did not register the complete site")
    require(site["acquisition_removed"] == dict(temporary_output_removed=True, temporary_cache_removed=True,
            bytes=size, sha256=expected["bundle_sha256"]), "holder acquisition scratch remained")
    acquisition, app = site["acquire"], site["viewer"]
    require(acquisition["operation"] == "named_content_download"
            and acquisition["publisher_key"] == expected["publisher_key"] and acquisition["name"] == expected["name"]
            and acquisition["revision"] == 1 and acquisition["manifest_id"] == publication["manifest_id"]
            and acquisition["publication_expires_unix_seconds"] == publication["expires_unix_seconds"]
            and acquisition["sha256"] == expected["bundle_sha256"] and acquisition["cache_only"] is False,
            "holder acquired a different site")
    for phase, kind, supplier, receipt in ((site["uptake"], "uptake", "relay5", acquisition),
                                           (site["view"], "reserve-fetch", "relay4", app["ready"])):
        SHARED["validate_phase"](phase, kind, peers, size)
        control = {peers[node] for node in RELAYS} - {slot["relay_peer_id"] for slot in phase["route"]["benchmark_slots"]}
        require(phase["layout"]["provider"]["node"] == supplier, "wrong protected site provider")
        SHARED["validate_fetch"](receipt, size, 9, peers[supplier], control)
    require(site["uptake"]["route"]["route_context_id"] != site["view"]["route"]["route_context_id"],
            "holder and reader reused the same route")
    SITE["validate_application"](dict(input=expected, publish=publication, expected_peers=peers, isolation=boundary,
        layout=dict(provider_nodes=["relay4"], control_relay_peer_id=app["ready"]["control_relay_peer_id"])),
        app, {publication["manifest_id"]}, False)


def event_count(path, code, baseline):
    value = bounded(path, 2 * 1024 * 1024)
    return sum(int(timestamp) >= baseline for timestamp in re.findall(
        rb"(?m)^(\d+)\s+\S+\s+event=" + code.encode("ascii") + rb"(?:\s|$)", value))


def build_evidence(work):
    prefix = "content-repair-"
    result = dict(success=True, expected_peers=read(work / "a01-expected-peers.json"))
    for key, suffix in (("publication", "publication"), ("receiver_status", "receiver-status"),
                        ("holder_offline", "holder-offline"), ("fetch", "final-fetch"),
                        ("output", "final-output"), ("isolation", "isolation"), ("startup", "startup")):
        result[key] = read(work / f"{prefix}{suffix}.json")
    result["before"] = {node: read(work / f"{prefix}before-{node}.json") for node in ("relay4", "relay5")}
    for phase in ("stopped", "restarted"):
        result[phase] = {node: read(work / f"{prefix}{phase}-{node}.json") for node in ("relay4", "relay5")}
    status = bounded(work / f"{prefix}receiver-before-status.txt", 32768).splitlines()
    result["receiver_initially_disconnected"] = b"connected: false" in status and b"active contexts: 0" in status
    result["caches"] = {name.replace("-", "_"): read(work / f"{prefix}{name}-cache.json")
                        for name in ("seeded-holder", "seeded-receiver", "repaired-receiver")}
    result["uptake"] = dict(layout=read(work / f"{prefix}uptake-layout.json"),
        route=read(work / f"{prefix}repaired-live-selection.json"),
        captures={role: read(work / f"{prefix}uptake-{role}.json") for role in UPTAKE_ROLES})
    result["final"] = dict(layout=read(work / f"{prefix}final-fetch-layout.json"),
        route=read(work / f"{prefix}final-live-selection.json"),
        captures={role: read(work / f"{prefix}final-fetch-{role}.json") for role in SHARED["ROLES"]})
    site = {key: read(work / f"{prefix}site-{suffix}.json") for key, suffix in (
        ("input", "public-input"), ("publish", "publish"), ("source_removed", "source-removed"),
        ("acquire", "acquire"), ("acquisition_removed", "acquisition-removed"), ("holder", "holder"), ("viewer", "viewer"), ("cleanup", "viewer-cleanup"),
        ("boundary", "boundary"))}
    for phase in ("uptake", "view"):
        site[phase] = dict(layout=read(work / f"{prefix}site-{phase}-layout.json"),
            route=read(work / f"{prefix}site-{phase}-live-selection.json"),
            captures={role: read(work / f"{prefix}site-{phase}-{role}.json") for role in SHARED["ROLES"]})
    result["offline_site"] = site
    baseline = result["startup"]["event_baseline_unix_ms"]
    result["events"] = dict(repair_complete=event_count(work / f"{prefix}receiver-events.txt", "CONTENT_REPAIR_COMPLETE", baseline),
                           exit_mptcp_completed=event_count(work / f"{prefix}exit-events.txt", "MPTCP_EXIT_FLOW_COMPLETED", baseline))
    validate_evidence(result)
    return result


def validate_report(report, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report["source_revision"] == revision
            and report["report_kind"] == "volparossa-content-repair" and report["schema_version"] == 2
            and report["publisher_offline_site_verified"] is True
            and report["success"] is True and report["runner_exit_status"] == 0
            and report["phase"] == "content-repair-complete" and report["observed_blocker"] is None
            and report["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"]
            and all(report[field] is False for field in ("initial_placement_over_network",
                "independent_publisher_node_offline_claimed", "future_availability_guaranteed", "full_alpha_acceptance_claimed")),
            "exact-source completed repair/cleanup or truthful scope missing")
    validate_evidence(report["repair"])


def main(args):
    require(len(args) == 3, "usage: cache|output|evidence|report INPUT OUTPUT_OR_REVISION; remove-site-acquisition STATE -")
    command, source, destination = args
    if command == "cache":
        result = cache_snapshot(source)
    elif command == "output":
        result = output_snapshot(source)
    elif command == "remove-site-acquisition":
        require(destination == "-", "site cleanup writes only its public receipt to stdout")
        print(json.dumps(remove_site_acquisition(source), sort_keys=True))
        return
    elif command == "evidence":
        result = build_evidence(Path(source))
    elif command == "report":
        validate_report(read(source), destination)
        print(json.dumps(dict(success=True, report_kind="volparossa-content-repair")))
        return
    else:
        raise ValueError("unknown repair command")
    Path(destination).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"public repair evidence rejected: {error}", file=sys.stderr)
        sys.exit(1)
