#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact public filter export over the existing protected path; no browser activation."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).parent
SITE = runpy.run_path(str(HERE / "content-provider-site-smoke.py"))
HTTPS = SITE["HTTPS"]
read, require, ROLES = SITE["read"], SITE["require"], SITE["ROLES"]
private, write_new = SITE["private"], SITE["write_new"]
NAME = "disposable-public-domain-filters"
TEXT = b"[Adblock Plus 2.0]\n||ads.example.test^\n||tracker.example.test^\n"
SHA = hashlib.sha256(TEXT).hexdigest()
FILES = {"filters.txt", "manifest.pb", "delivery-receipt.json", "snapshot.json"}


def initialize(root):
    private(root, True)
    require(root.name == "filter-publisher" and not list(root.iterdir()), "publisher not fresh")
    write_new(root / "filters.txt", TEXT)
    write_new(root / "passphrase", os.urandom(48).hex().encode() + b"\n")
    return dict(name=NAME, content_type="text/plain", bytes=len(TEXT), sha256=SHA, rules=2)


def cleanup(root, publisher):
    """Validate all exact disposable entries before removing any; never adopt agent caches."""
    require(root.name == ("filter-publisher" if publisher else "filter-viewer")
            and not root.is_symlink(), "wrong cleanup root")
    if not root.exists():
        return dict(directory_removed=True, files_removed=True)
    private(root, True)
    allowed = {"identity.key", "passphrase", "filters.txt", "manifest.bin", "source-cache"} if publisher else {
        "expected.json", "cold", "warm"}
    entries = list(root.iterdir())
    require({p.name for p in entries} <= allowed, "unknown fixture entry")
    files, directories, total = [], [], 0
    for entry in entries:
        if entry.name in {"source-cache", "cold", "warm"}:
            private(entry, True)
            children = list(entry.iterdir())
            require(len(children) <= 16, "cleanup entry bound")
            for child in children:
                require((re.fullmatch(r"[0-9a-f]{64}", child.name) or child.name in {
                    ".volparossa-owner-v1", ".volparossa-index-v1"}) if publisher else child.name in FILES,
                    "unknown nested fixture entry")
                total += private(child).st_size
                files.append(child)
            directories.append(entry)
        else:
            if entry.name == "expected.json":
                metadata = entry.lstat()
                require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o400
                        and metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid(),
                        "unsafe expected metadata")
            else:
                metadata = private(entry)
            total += metadata.st_size
            files.append(entry)
    require(total <= 2 * 1024 * 1024, "cleanup byte bound")
    for entry in files:
        entry.unlink()
    for entry in directories:
        entry.rmdir()
    root.rmdir()
    return dict(directory_removed=True, files_removed=True)


def consume(arguments, warm):
    binary, control, cache, directory, parent_ns, client_ns, uid, gid, group = arguments
    boundary = HTTPS["process_boundary"]("self", parent_ns, client_ns, int(uid), int(gid), int(group))
    root = Path(directory)
    private(root, True)
    require({p.name for p in root.iterdir()} == ({"expected.json", "cold"} if warm else {"expected.json"}),
            "consumer root not exact")
    expected = read(root / "expected.json")
    output = root / ("warm" if warm else "cold")
    command = [binary, "--control-socket", control, "content", "filter-snapshot", "--publisher-key",
               expected["publisher_key"], "--name", NAME, "--manifest-id", expected["manifest_id"],
               "--authorize-filter-publisher", "--public-content", "--cache", cache,
               "--min-free-bytes", "0", "--output", str(output)]
    if warm:
        command.append("--reuse-cache")
    before = SITE["local_snapshot"](binary, control) if warm else None
    started, deadline = time.monotonic_ns(), time.monotonic() + 110
    # Inherit the inspected capless UID/GID/groups/netns/NoNewPrivs unchanged. This short
    # command may exit before /proc can be sampled; do not claim a live child inspection.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=0,
                               env=dict(os.environ, TMPDIR=str(root)))
    previous = {}
    def interrupted(_signum, _frame):
        raise ValueError("filter operation interrupted")
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, interrupted)
        report = HTTPS["bounded_json_line"](process.stdout, deadline)
        require(process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0
                and process.stdout.read(1) == b"", "filter command failed or emitted extra output")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        process.stdout.close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    private(output, True)
    require({p.name for p in output.iterdir()} == FILES, "snapshot files differ")
    for file in output.iterdir():
        require(private(file).st_size <= 16384, "snapshot file exceeds tiny fixture bound")
    require((output / "filters.txt").read_bytes() == TEXT, "filter bytes changed")
    require(read(output / "snapshot.json") == report, "stdout and persisted snapshot differ")
    manifest_hash = hashlib.sha256((output / "manifest.pb").read_bytes()).hexdigest()
    require(manifest_hash == expected["manifest_id"], "manifest differs from independently selected envelope")
    receipt = read(output / "delivery-receipt.json")
    completed = int(time.time())
    require(completed < report["expires_unix_seconds"], "export expired before observation")
    after = SITE["local_snapshot"](binary, control) if warm else None
    require({p.name for p in root.iterdir()} == ({"expected.json", "cold", "warm"} if warm else {
        "expected.json", "cold"}), "private staging files remain")
    return dict(report=report, receipt=receipt, manifest_sha256=manifest_hash,
                output_sha256=SHA, output_bytes=len(TEXT), output_modes="0700/0600",
                consumer=boundary, cli_boundary_inherited=True, elapsed_ns=time.monotonic_ns()-started,
                observed_unix_seconds=completed, agent_cache=cache, reuse_cache=warm,
                before=before, after=after, private_staging_removed=True,
                browser_engine_executed=False)


def validate_application(evidence, app, warm):
    expected, publish = evidence["input"], evidence["publish"]
    report, receipt = app["report"], app["receipt"]
    require(app["reuse_cache"] is warm and app["output_modes"] == "0700/0600"
            and app["manifest_sha256"] == expected["manifest_id"]
            and app["output_sha256"] == SHA and app["output_bytes"] == len(TEXT)
            and 0 < app["elapsed_ns"] <= 120_000_000_000
            and app["agent_cache"] == evidence["isolation"]["agent_cache"]
            and app["private_staging_removed"] is True and app["browser_engine_executed"] is False
            and app["cli_boundary_inherited"] is True, "filter export or execution boundary differs")
    boundary, isolation = app["consumer"], evidence["isolation"]
    require(boundary["user_uid"] == isolation["user_uid"] == 985
            and boundary["user_gid"] == isolation["user_gid"]
            and boundary["control_gid"] == isolation["control_gid"]
            and all(boundary[k] is True for k in ("client_namespace", "outside_parent_namespace",
                "all_capabilities_dropped", "no_new_privileges")), "consumer boundary missing")
    require(report["version"] == 1 and report["operation"] == "content_filter_snapshot"
            and report["visibility"] == "public" and report["grammar"] == "ubo-domain-block-v1"
            and report["rules"] == 2 and report["delivery_receipt_file"] == "delivery-receipt.json"
            and all(report[k] is False for k in ("globally_latest", "delivery_receipt_is_signed_attestation",
                "browser_configuration_changed", "subscription_installed"))
            and 0 < report["verified_at_unix_seconds"] <= app["observed_unix_seconds"]
            < report["expires_unix_seconds"] == publish["expires_unix_seconds"], "snapshot scope or original expiry changed")
    for value in (report, receipt):
        require(value["publisher_key"] == expected["publisher_key"] and value["name"] == NAME
                and value["manifest_id"] == expected["manifest_id"] and value["revision"] == 1
                and value["sha256"] == SHA and value["bytes"] == len(TEXT), "selected filter identity changed")
    providers = receipt["provider_peer_ids"]
    allowed = {evidence["expected_peers"][n] for n in evidence["layout"]["provider_nodes"]}
    require(isinstance(providers, list) and len(providers) == len(set(providers))
            and (not providers if warm else 1 <= len(providers) <= 2 and set(providers) <= allowed)
            and receipt["operation"] == "named_content_download" and receipt["chunks"] == 1
            and receipt["providers_used"] == len(providers)
            and receipt["peer_bytes"] == (0 if warm else len(TEXT))
            and receipt["control_relay_peer_id"] == ("" if warm else evidence["layout"]["control_relay_peer_id"])
            and receipt["publication_expires_unix_seconds"] == publish["expires_unix_seconds"]
            and receipt["origin_body_bytes"] == receipt["origin_range_requests"] == 0
            and receipt["local_delivery"] is True and receipt["output_mode"] == "0600"
            and all(receipt[k] is False for k in ("ownership_changed", "origin_authenticated", "globally_latest", "cache_only")),
            "actual filter source accounting differs; reuse is not cache-only mode")


def validate_packets(evidence, phase, warm):
    peers, layout = evidence["expected_peers"], evidence["layout"]
    captures = phase["privacy"]
    require(set(captures) == set(ROLES), "physical capture coverage incomplete")
    actual = set(phase["application"]["receipt"]["provider_peer_ids"])
    for role, capture in captures.items():
        HTTPS["validate_drained"](capture, allow_empty=True)
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and all(capture[k] == 0 for k in ("unexpected_outer_packets", "expected_link_down_notifications",
                    "unexpected_provider_application_packets", "direct_client_exit_packets"))
                and set(capture["provider_application"]) == set(HTTPS["CANDIDATES"]), "filter privacy failure")
        require((capture["client_public_packets"] == capture["outbound_client_discovery_attempt_packets"] == 0)
                if role == "exit" else capture["internet_destination_outer_packets"] == 0,
                "forbidden Client or destination visibility")
        if warm:
            require(capture["client_leg_wireguard_data_datagrams"] == capture["exit_leg_wireguard_data_datagrams"] == 0,
                    "warm filter emitted protected data")
        for node, counters in capture["provider_application"].items():
            if not warm and role == "exit" and node in layout["provider_nodes"]:
                if peers[node] in actual:
                    require(counters["request_packets"] > 0 and counters["response_packets"] > 0
                            and counters["response_payload_bytes"] >= len(TEXT), "actual provider lacks captured payload")
            else:
                require(all(value == 0 for value in counters.values()), "filter application escaped its exact provider path")
    control = next(node for node in HTTPS["PUBLIC_IPS"] if peers[node] == layout["control_relay_peer_id"])
    HTTPS["validate_control"](phase["control_privacy"], control, layout["provider_nodes"], False,
                              require_contacts=not warm)


def validate(evidence):
    expected, publish, isolation = evidence["input"], evidence["publish"], evidence["isolation"]
    require(evidence["success"] is True and expected["name"] == NAME and expected["content_type"] == "text/plain"
            and expected["bytes"] == len(TEXT) and expected["sha256"] == SHA and expected["rules"] == 2
            and re.fullmatch(r"[0-9a-f]{64}", expected["publisher_key"])
            and re.fullmatch(r"[0-9a-f]{64}", expected["manifest_id"])
            and publish["operation"] == "offline_content_publish" and publish["network_publication"] is False
            and publish["publisher_key_hex"] == expected["publisher_key"] and publish["bytes"] == len(TEXT)
            and publish["chunks"] == 1, "not the independent ordinary filter publication")
    nodes, peers = evidence["layout"]["provider_nodes"], evidence["expected_peers"]
    require(len(nodes) == len(set(nodes)) == 2 and set(nodes) <= set(HTTPS["CANDIDATES"])
            and set(evidence["imports"]) == set(evidence["serves"]) == set(nodes), "provider coverage incomplete")
    for node in nodes:
        imported, served = evidence["imports"][node], evidence["serves"][node]
        require(imported["operation"] == "content_import" and imported["complete"] is True
                and imported["manifest_id"] == expected["manifest_id"] and imported["content_bytes"] == len(TEXT)
                and imported["public_content"] is True
                and all(imported[k] is False for k in ("ownership_changed", "network_transfer", "origin_authenticated"))
                and served["serving"] is True and served["publications"] == 3
                and served["replication_enabled"] is False, "filter import/name serving differs")
    require(len({v["agent_cache"] for v in evidence["imports"].values()}) == 2
            and isolation["user_uid"] != isolation["agent_uid"] and isolation["control_gid"] != isolation["agent_gid"]
            and isolation["cache_modes"] == "0700"
            and isolation["cache_identity_before"] == isolation["cache_identity_after"]
            and re.fullmatch(r"[0-9]+:[1-9][0-9]*", isolation["cache_identity_before"])
            and all(isolation[k] is True for k in ("fresh_client_cache", "agent_mount_positive_control",
                "client_cannot_read_provider_caches", "agent_cannot_read_user_directory", "user_cannot_read_agent_caches",
                "publisher_sources_removed_before_fetch", "selection_pinned_before_fetch"))
            and evidence["publisher_cleanup"] == evidence["cleanup"] == dict(directory_removed=True, files_removed=True),
            "cache identity, trust isolation or cleanup missing")
    route = evidence["selected_route"]
    paths, slots = route["paths"], route["benchmark_slots"]
    require(route["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and route["route_context_id"] == isolation["route_context_id"]
            and re.fullmatch(r"[0-9a-f]{32}", route["route_context_id"])
            and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == route["route_context_id"] for p in paths)
            and [s["relay_peer_id"] for s in slots] == [p["relay_peer_id"] for p in paths]
            and all(s["relay_node"] in ROLES[1:4] and peers[s["relay_node"]] == s["relay_peer_id"] for s in slots)
            and {peers[n] for n in nodes}.isdisjoint({peers["client"], peers["exit"], evidence["layout"]["control_relay_peer_id"]}
                | {p["relay_peer_id"] for p in paths}), "filter escaped the existing protected route")
    for name, warm in (("cold", False), ("warm", True)):
        validate_application(evidence, evidence[name]["application"], warm)
        validate_packets(evidence, evidence[name], warm)
    require(any(evidence["cold"]["privacy"][s["relay_node"]]["client_leg_wireguard_data_datagrams"] > 0
                and evidence["cold"]["privacy"][s["relay_node"]]["exit_leg_wireguard_data_datagrams"] > 0 for s in slots),
            "cold filter lacks any complete protected WireGuard leg pair")
    # Tiny one-chunk filter traffic is NOT a new claim of two-subflow bulk aggregation.
    warm = evidence["warm"]["application"]
    for snapshot in (warm["before"], warm["after"]):
        SITE["validate_disconnected"](snapshot)
    baseline = warm["before"]["observed_unix_ms"]
    records = []
    for line in warm["after"]["logs"].splitlines():
        fields = line.split()
        require(len(fields) >= 3 and fields[0].isdigit() and fields[2].startswith("event="), "invalid closed log")
        records.append((int(fields[0]), fields[2][6:]))
    require(records and min(stamp for stamp, _ in records) <= baseline <= warm["after"]["observed_unix_ms"]
            and not any(stamp >= baseline and event.startswith(("CONTENT_DISCOVERY_", "CONTENT_PROVIDER_"))
                        for stamp, event in records), "warm reuse lost log coverage or started discovery")


def build_evidence(work):
    evidence = {key: read(work / f"content-provider-filter-{suffix}.json") for key, suffix in (
        ("input", "input"), ("publish", "publish"), ("isolation", "isolation"),
        ("publisher_cleanup", "publisher-cleanup"), ("cleanup", "cleanup"), ("selected_route", "selection"))}
    evidence.update(success=True, layout=read(work / "content-provider-layout.json"),
                    expected_peers=read(work / "a01-expected-peers.json"))
    for key, suffix in (("imports", "import"), ("serves", "serve")):
        evidence[key] = {node: read(work / f"content-provider-filter-{node}-{suffix}.json")
                         for node in evidence["layout"]["provider_nodes"]}
    for phase in ("cold", "warm"):
        prefix = f"content-provider-filter-{phase}"
        evidence[phase] = dict(application=read(work / f"{prefix}-consumer.json"),
            control_privacy=read(work / f"{prefix}-control.json"),
            privacy={role: read(work / f"{prefix}-privacy-{role}.json") for role in ROLES})
    validate(evidence)
    return evidence


if __name__ == "__main__":
    try:
        operation, *arguments = sys.argv[1:]
        if operation == "init":
            result = initialize(Path(arguments[0]))
        elif operation in ("publisher-cleanup", "user-cleanup"):
            result = cleanup(Path(arguments[0]), operation == "publisher-cleanup")
        elif operation in ("cold", "warm"):
            result = consume(arguments, operation == "warm")
        elif operation == "evidence":
            result = build_evidence(Path(arguments[0]))
        else:
            raise ValueError("unsupported fixture operation")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"filter fixture rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
