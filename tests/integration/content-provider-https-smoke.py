#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Normal CLI/browser-HTTP provider evidence, not a GUI, speed or full C02/C08 acceptance.

The enclosing native-provider report owns exact-source and final host/guest cleanup checks.
This checker requires both peer-assisted phases, the ordinary origin reference and two
cold product source-strategy phases, each with independently drained physical captures.
"""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

COMMON = runpy.run_path(str(Path(__file__).with_name("content-network-smoke.py")))
read, require, ROLES = COMMON["read"], COMMON["require"], COMMON["ROLES"]
BYTES, SHA = COMMON["OBJECT_BYTES"], COMMON["FIXTURE_PLAINTEXT_SHA256"]
CANDIDATES = ("relay4", "relay5", "relay3")
PUBLIC_IPS = dict(relay0="42.158.0.1", relay1="44.160.1.1", relay2="45.161.2.1",
                  relay3="48.164.4.1", relay4="49.165.5.1", relay5="50.166.6.1")
RANGES = ((262144, 524287), (786432, 1048575),
          (1310720, 1572863), (1835008, 2097151))
RANGE_BYTES = 262144
DIGEST_CASES = ("digest-origin-only", "digest-peers-first")
LIMITED_CASES = ("limited-origin-only", "limited-peers-first", "limited-auto")
CONSUMER_CASES = ("complete", "missing", "baseline", "origin-only", "auto", *DIGEST_CASES, *LIMITED_CASES)
REPR_DIGEST = "sha-256=:rdByTY2+aEB9VEwkcUEocyopxIgM/zDSg7GtqTYuN2c=:"


def process_boundary(pid, parent_namespace, client_namespace, uid, gid, control_gid):
    """Inspect real inherited credentials, not successful setpriv exit status alone."""
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    namespace = os.readlink(f"/proc/{pid}/ns/net")
    capabilities = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    require(namespace == client_namespace != parent_namespace
            and uid == 985 and all(int(value) == uid for value in status["Uid"].split())
            and all(int(value) == gid for value in status["Gid"].split())
            and {int(value) for value in status["Groups"].split()} == {control_gid}
            and all(int(status[key], 16) == 0 for key in capabilities)
            and int(status["NoNewPrivs"]) == 1,
            "consumer is not the exact capless Client-namespace operator")
    return dict(user_uid=uid, user_gid=gid, control_gid=control_gid,
                client_namespace=True, outside_parent_namespace=True,
                all_capabilities_dropped=True, no_new_privileges=True)


def bounded_json_line(stream, deadline):
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while len(data) < 16384:
            require(selector.select(max(0, deadline - time.monotonic())), "CLI receipt timeout")
            byte = os.read(stream.fileno(), 1)
            require(byte, "CLI ended without its receipt")
            if byte == b"\n":
                return json.loads(data)
            data.extend(byte)
    raise ValueError("oversized CLI receipt")


def browser_http_get(ready, output, deadline):
    url = urlsplit(ready["download_url"])
    require(url.scheme == "http" and url.hostname == "127.0.0.1"
            and url.username is None and url.password is None and url.port is not None
            and url.netloc == f"127.0.0.1:{url.port}"
            and re.fullmatch(r"/[0-9a-f]{64}", url.path) and not url.query and not url.fragment
            and time.time() < ready["expires_unix_seconds"] <= time.time() + 301,
            "browser readiness lacks a live exact loopback single-use URL")
    started = time.monotonic_ns()
    digest, count = hashlib.sha256(), 0
    connection = http.client.HTTPConnection("127.0.0.1", url.port, timeout=5)
    try:
        connection.request("GET", url.path)
        response = connection.getresponse()
        require(response.status == 200 and response.getheader("Content-Length") == str(BYTES)
                and response.getheader("Content-Type") == "application/octet-stream"
                and response.getheader("Content-Disposition")
                    == 'attachment; filename="volparossa-download.bin"'
                and response.getheader("Cache-Control") == "no-store"
                and response.getheader("X-Content-Type-Options") == "nosniff",
                "browser HTTP attachment headers differ from the authenticated object")
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as target:
            while chunk := response.read(65536):
                require(time.monotonic() < deadline and count + len(chunk) <= BYTES,
                        "browser body exceeded time or exact object bound")
                target.write(chunk)
                digest.update(chunk)
                count += len(chunk)
            target.flush()
            os.fsync(target.fileno())
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        connection.close()
    require(count == BYTES and digest.hexdigest() == SHA
            and time.time() < ready["expires_unix_seconds"],
            "browser HTTP output hash, length or original deadline invalid")
    try:
        repeated = socket.create_connection(("127.0.0.1", url.port), timeout=2)
    except ConnectionRefusedError:
        pass
    else:
        repeated.close()
        raise ValueError("single-use listener still accepts a second connection")
    return dict(status=200, bytes=count, sha256=digest.hexdigest(), attachment=True,
                octet_stream=True, no_store=True, nosniff=True, loopback_only=True,
                single_use_listener_closed=True, completed_before_expiry=True,
                elapsed_ns=time.monotonic_ns() - started)


def inspect_spool(user_directory, uid, gid):
    spools = list(user_directory.glob("volparossa-browser-*"))
    require(len(spools) == 1, "expected exactly one private browser spool")
    directory = spools[0].lstat()
    require(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700
            and directory.st_uid == uid and directory.st_gid == gid, "unsafe browser spool directory")
    files = list(spools[0].iterdir())
    require(len(files) == 1, "browser spool is not the bounded single-object storage")
    metadata = files[0].lstat()
    require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_uid == uid and metadata.st_gid == gid and metadata.st_size == BYTES,
            "unsafe or incomplete private browser spool")
    return spools[0]


def consumer_command(case, binary, control, cache, user_directory, output):
    """Pin existing peer evidence explicitly; the ordinary reference is not an auto request."""
    require(case in CONSUMER_CASES, "unknown HTTPS consumer phase")
    if case == "baseline":
        return [binary, "origin-baseline", str(user_directory), "47.163.4.2:18443",
                str(user_directory / "origin.pem"), str(output)]
    command = [binary, "--control-socket", control, "content",
               "browser-download" if case == "complete" else "fetch-https",
               "--url", "https://destination.volparossa.test:18443/asset.bin",
               "--ca-file", str(user_directory / "origin.pem"), "--cache", cache,
               "--source-strategy", case.split("-", 1)[1] if case in (*DIGEST_CASES, *LIMITED_CASES)
                   else case if case in ("origin-only", "auto") else "peers-first"]
    command.extend(["--origin-digest"] if case in (*DIGEST_CASES, *LIMITED_CASES)
                   else ["--metadata-path", "/.well-known/volparossa/content/asset"])
    if case != "complete":
        command.extend(["--local-output", str(output)])
    return command


def consume(arguments):
    """Called only after the enclosing disposable harness enters CLIENT and drops privileges."""
    case, binary, control, cache, user_path, parent_ns, client_ns, uid, gid, control_gid = arguments
    require(case in CONSUMER_CASES, "unknown HTTPS consumer phase")
    uid, gid, control_gid = int(uid), int(gid), int(control_gid)
    boundary = process_boundary("self", parent_ns, client_ns, uid, gid, control_gid)
    user_directory = Path(user_path)
    output = user_directory / ("origin-baseline.json" if case == "baseline" else f"{case}-object.bin")
    require(not output.exists() and not output.is_symlink()
            and not list(user_directory.glob("volparossa-browser-*"))
            and not list(user_directory.glob("volparossa-origin-baseline-*")), "consumer storage is not fresh")
    command = consumer_command(case, binary, control, cache, user_directory, output)
    started, deadline = time.monotonic_ns(), time.monotonic() + 110
    started_unix_ms = time.time_ns() // 1_000_000
    process = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=0,
                               env=dict(os.environ, TMPDIR=str(user_directory)))
    previous = {}
    def interrupted(_signum, _frame):
        raise ValueError("HTTPS application consumer interrupted")
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, interrupted)
        cli_boundary = process_boundary(process.pid, parent_ns, client_ns, uid, gid, control_gid)
        first = bounded_json_line(process.stdout, deadline)
        report = dict(final=first, consumer=boundary, cli=cli_boundary)
        if case != "baseline":
            report["requested_source_strategy"] = command[command.index("--source-strategy") + 1]
            report["requested_origin_digest"] = "--origin-digest" in command
        if case == "baseline":
            require(first["network_namespace"] == client_ns and first["effective_uid"] == uid
                    and read(output) == first, "baseline report differs from actual isolated fixture process")
            report["reported_client_namespace"] = True
        if case == "complete":
            require(first["operation"] == "browser_download_ready" and first["bytes"] == BYTES
                    and first["sha256"] == SHA and first["origin_authenticated"] is True,
                    "expected complete origin-authenticated browser readiness")
            ready_elapsed = time.monotonic_ns() - started
            spool = inspect_spool(user_directory, uid, gid)
            report["http"] = browser_http_get(first, output, deadline)
            final = bounded_json_line(process.stdout, deadline)
            require(final["operation"] == "browser_content_download"
                    and final["private_spool_removed"] is True,
                    "browser CLI did not confirm completed delivery and cleanup")
            report.update(final=final, ready={key: value for key, value in first.items()
                                            if key != "download_url"},
                          private_spool=dict(directory_mode="0700", file_mode="0600",
                                             observed_complete=True, removed=not spool.exists()),
                          ready_elapsed_ns=ready_elapsed, browser_engine_executed=False)
        require(process.wait(timeout=max(0.1, deadline - time.monotonic())) == 0
                and process.stdout.read(1) == b"", "CLI failed or emitted unexpected trailing data")
        finished = time.monotonic_ns()
        report.update(elapsed_ns=finished - started, started_monotonic_ns=started,
                      completed_monotonic_ns=finished, started_unix_ms=started_unix_ms,
                      completed_unix_ms=time.time_ns() // 1_000_000)
        require(not list(user_directory.glob("volparossa-browser-*"))
                and not list(user_directory.glob("volparossa-origin-baseline-*")),
                "private application spool remained")
        return report
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


def origin_exit_source(source):
    # The destination-facing xd link differs from the Exit's provider/relay underlay.
    return isinstance(source, str) and bool(re.fullmatch(r"47\.163\.4\.1:[0-9]{1,5}", source)) \
        and 0 < int(source.rsplit(":", 1)[1]) <= 65535


def validate_drained(capture, allow_empty=False):
    statistics = capture["interface_statistics"]
    require(capture["truncated"] is False and capture["observed_frames"] >= (0 if allow_empty else 1)
            and capture["packet_socket_drops"] == 0 and len(capture["interfaces"]) > 0
            and len(set(capture["interfaces"])) == len(capture["interfaces"])
            and set(statistics) == set(capture["interfaces"])
            and sum(s["observed_frames"] for s in statistics.values()) == capture["observed_frames"]
            and all(s["intake_stopped"] is True and s["packet_socket_drops"] == 0
                    and s["packet_socket_packets"] == s["observed_frames"]
                    for s in statistics.values()),
            "capture truncated, dropped, still accepting intake or not completely drained")


def validate_control(capture, control_node, provider_nodes, missing, require_contacts=True):
    pairs = {f"cp{i}": [PUBLIC_IPS[control_node], PUBLIC_IPS[node]]
             for i, node in enumerate(provider_nodes)}
    require(capture["capture_role"] == "content-control"
            and capture["content_provider_mode"] is True
            and capture["content_control_pairs"] == pairs
            and set(capture["interfaces"]) == set(pairs)
            and set(capture["content_control_packets"]) == set(pairs)
            and capture["unexpected_provider_control_packets"] == 0
            and capture["unexpected_provider_application_packets"] == 0
            and set(capture["provider_application"]) == set(CANDIDATES)
            and all(value == 0 for counters in capture["provider_application"].values()
                    for value in counters.values()),
            "exact generic-control links carried unexpected control or application traffic")
    validate_drained(capture, allow_empty=not require_contacts)
    # The withdrawn provider may legitimately receive no second-phase service query.
    for interface in (("cp0",) if missing else ("cp0", "cp1")) if require_contacts else ():
        counters = capture["content_control_packets"][interface]
        require(counters["inbound"] > 0 and counters["outbound"] > 0,
                "active provider lacks bidirectional authenticated-control traffic")


def validate_path(phase, peers, provider_nodes, missing, origin_only=False, useful_peer_bytes=None):
    selected = phase["selected_route"]
    paths, slots = selected["paths"], selected["benchmark_slots"]
    provider_peers = {peers[node] for node in provider_nodes}
    require(selected["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and re.fullmatch(r"[0-9a-f]{32}", selected["route_context_id"])
            and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [s["relay_peer_id"] for s in slots] == [p["relay_peer_id"] for p in paths]
            and not provider_peers.intersection({peers["client"], peers["exit"]}
                                               | {p["relay_peer_id"] for p in paths}),
            "same-Exit two-Relay MPTCP route or independent provider nodes not proven")
    nodes = [s["relay_node"] for s in slots]
    require(len(set(nodes)) == 2 and all(node in ROLES[1:4] for node in nodes)
            and all(peers[s["relay_node"]] == s["relay_peer_id"] for s in slots),
            "selected relay node identity does not match its captured WireGuard legs")
    privacy = phase["privacy"]
    require(set(privacy) == set(ROLES), "five-role physical privacy coverage incomplete")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and capture["unexpected_provider_application_packets"] == 0,
                "physical capture observed unexpected outer or provider traffic")
        validate_drained(capture)
        require(set(capture["provider_application"]) == set(CANDIDATES),
                "provider application capture coverage incomplete")
    require(privacy["client"]["direct_client_exit_packets"] == 0
            and privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == 0
            and privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[r]["internet_destination_outer_packets"] == 0 for r in ROLES[1:4]),
            "original Client/Relay/Exit privacy boundary violated")
    for node in nodes:
        require(privacy[node]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[node]["exit_leg_wireguard_data_datagrams"] > 16,
                "selected physical WireGuard legs did not both carry genuine data")
    active = [] if origin_only else provider_nodes[:1] if missing else provider_nodes
    for node in CANDIDATES:
        application = privacy["exit"]["provider_application"][node]
        if useful_peer_bytes is not None:
            useful = useful_peer_bytes if node == provider_nodes[0] else 0
            require(application["response_payload_bytes"] >= useful
                    and application["response_payload_bytes"] <= useful + 65536,
                    "strategy provider traffic exceeds useful bytes plus bounded protocol overhead")
            if useful:
                require(application["request_packets"] > 0 and application["response_packets"] > 0,
                        "strategy provider useful bytes lack a real protected exchange")
            elif origin_only or node != provider_nodes[0]:
                require(application["response_payload_bytes"] == 0
                        and application.get("request_payload_bytes", 0) == 0,
                        "explicit origin-only used provider payload")
        elif origin_only:
            # Prior completed provider sockets may still exchange ACK/FIN; those are not
            # downloaded object bytes. This observer currently has no request-payload field.
            require(application["response_payload_bytes"] == 0
                    and application.get("request_payload_bytes", 0) == 0,
                    "origin-only reference received or requested provider payload")
        elif node in active:
            require(application["request_packets"] > 0 and application["response_packets"] > 0
                    and application["response_payload_bytes"] >= (1048699 if missing else 1048576),
                    "active independent provider did not return its useful payload to the Exit")
        else:
            require(all(value == 0 for value in application.values()),
                    "withdrawn or unselected provider received application traffic")
        for role in ROLES[:-1]:
            require(all(value == 0 for value in privacy[role]["provider_application"][node].values()),
                    "provider application data escaped its protected path")


def validate_local_output(phase):
    fetch, output = phase["fetch"], phase["output"]
    require(fetch["origin_authority_persisted"] is False
            and fetch["sha256"] == output["sha256"] == SHA
            and output["path"] != output["agent_cache"]
            and output["user_uid"] == 985 and output["agent_uid"] > 0
            and output["user_uid"] != output["agent_uid"]
            and output["control_gid"] > 0 and output["control_gid"] != output["agent_gid"]
            and output["output_mode"] == "0600" and output["directory_mode"] == "0700"
            and output["agent_cache_mode"] == "0700"
            and all(output[key] is True for key in (
                "local_output_initially_absent", "no_clobber_verified", "no_clobber_rejected_before_network",
                "agent_mount_positive_control", "agent_cannot_read_user_output_directory"))
            and phase["status"]["serving"] is False
            and phase["status"]["control_relay_peer_id"] == fetch["control_relay_peer_id"],
            "same-operation HTTPS result was not delivered privately to the actual user account")


def validate_application(phase, browser, source_strategy="peers-first"):
    application, fetch, output = phase["application"], phase["fetch"], phase["output"]
    require(application["final"] == fetch and 0 < application["elapsed_ns"] <= 120_000_000_000
            and application["requested_source_strategy"] == source_strategy,
            "application receipt differs from real CLI result or lacks bounded monotone timing")
    for key in ("consumer", "cli"):
        boundary = application[key]
        require(boundary["user_uid"] == output["user_uid"] == 985
                and boundary["control_gid"] == output["control_gid"]
                and boundary["user_gid"] > 0
                and all(boundary[flag] is True for flag in (
                    "client_namespace", "outside_parent_namespace",
                    "all_capabilities_dropped", "no_new_privileges")),
                "HTTP application or CLI ran outside the capless Client operator boundary")
    require(application["consumer"] == application["cli"], "CLI/application credentials differ")
    if not browser:
        require(fetch["operation"] == "https_content_download" and fetch["local_delivery"] is True
                and fetch["output_mode"] == "0600" and fetch["ownership_changed"] is False
                and fetch["local_output"] == output["path"]
                and fetch["cache"] == output["agent_cache"]
                and "http" not in application and "ready" not in application,
                "missing-range phase is not the ordinary HTTPS local-output command")
        return
    ready, http, spool = application["ready"], application["http"], application["private_spool"]
    require(fetch["operation"] == "browser_content_download"
            and ready["operation"] == "browser_download_ready"
            and fetch["private_spool_removed"] is True
            and ready["expires_unix_seconds"] > 0 and "download_url" not in ready
            and all(key not in fetch for key in ("local_delivery", "local_output", "cache"))
            and {key: value for key, value in ready.items()
                 if key not in ("operation", "expires_unix_seconds")}
                == {key: value for key, value in fetch.items()
                    if key not in ("operation", "private_spool_removed")}
            and fetch["authentication_scope"] == "cooperative-origin"
            and fetch["https_origin_privileges"] is False and fetch["single_use"] is True
            and application["browser_engine_executed"] is False,
            "browser receipt is relabelled, mismatched or claims an unexecuted browser engine")
    require(http["status"] == 200 and http["bytes"] == fetch["bytes"] == BYTES
            and http["sha256"] == fetch["sha256"] == SHA
            and all(http[flag] is True for flag in ("attachment", "octet_stream", "no_store",
                "nosniff", "loopback_only", "single_use_listener_closed", "completed_before_expiry"))
            and 0 < application["ready_elapsed_ns"] < application["elapsed_ns"]
            and 0 < http["elapsed_ns"] <= application["elapsed_ns"] - application["ready_elapsed_ns"]
            and spool == dict(directory_mode="0700", file_mode="0600", observed_complete=True, removed=True),
            "actual single-use HTTP delivery, elapsed timing or private spool cleanup not proven")


def validate_baseline(baseline, cases, peers, provider_nodes):
    application = baseline["application"]
    reference, ingress = application["final"], baseline["ingress"]
    boundary = application["consumer"]
    require(boundary == application["cli"] and boundary["user_uid"] == reference["effective_uid"] == 985
            and boundary["control_gid"] == cases["complete"]["output"]["control_gid"]
            and all(boundary[flag] is True for flag in ("client_namespace", "outside_parent_namespace",
                "all_capabilities_dropped", "no_new_privileges"))
            and application["reported_client_namespace"] is True
            and re.fullmatch(r"net:\[[0-9]+\]", reference["network_namespace"])
            and reference["pid"] > 0,
            "origin-only reference did not run in the same capless Client operator namespace")
    require(reference["report_kind"] == "volparossa-https-origin-baseline"
            and "requested_source_strategy" not in application
            and reference["bytes"] == reference["origin_body_bytes"] == BYTES
            and reference["object_sha256"] == SHA and reference["chunks"] == 9
            and reference["peer_bytes"] == 0
            and reference["metadata_requests"] == reference["body_requests"] == 1
            and reference["origin_authenticated"] is True and reference["origin_authority_persisted"] is False
            and reference["reference_cache_initially_empty"] is True
            and reference["private_spool_removed"] is True and reference["output_mode"] == "0600"
            and reference["application_socket"] == "ordinary_tcp_transparent_ingress",
            "reference skipped origin authority, used cache/peers or retained a private spool")
    stages = [reference[key] for key in ("metadata_elapsed_ns", "body_elapsed_ns", "reconstruct_elapsed_ns")]
    require(all(value > 0 for value in stages)
            and sum(stages) <= reference["total_elapsed_ns"] <= application["elapsed_ns"] <= 120_000_000_000
            and ingress["client_before"] >= 0 and ingress["exit_before"] >= 0
            and ingress["client_after"] - ingress["client_before"] >= 2
            and ingress["exit_after"] - ingress["exit_before"] >= 2
            and baseline["selected_route"]["route_context_id"]
                == cases["complete"]["selected_route"]["route_context_id"],
            "reference timing, fresh ingress/Exit completions or unchanged route not proven")
    validate_path(baseline, peers, provider_nodes, missing=False, origin_only=True)


def measured_comparison(cases, baseline):
    """Descriptive single sequential sample; neither ordering nor a speedup is a pass condition."""
    browser, missing = (cases[key]["application"] for key in ("complete", "missing"))
    reference = baseline["application"]
    return dict(reference="same-overlay-origin-only", samples_per_case=1, speedup_required=False,
        reference_kind="ordinary-application-not-product-source-selector",
        browser_source_strategy=browser["requested_source_strategy"],
        missing_source_strategy=missing["requested_source_strategy"],
        browser_ready_elapsed_ns=browser["ready_elapsed_ns"],
        browser_http_elapsed_ns=browser["http"]["elapsed_ns"],
        browser_command_elapsed_ns=browser["elapsed_ns"],
        missing_command_elapsed_ns=missing["elapsed_ns"],
        origin_command_elapsed_ns=reference["elapsed_ns"],
        origin_to_browser_ready_ratio=reference["elapsed_ns"] / browser["ready_elapsed_ns"],
        origin_to_browser_command_ratio=reference["elapsed_ns"] / browser["elapsed_ns"],
        origin_to_missing_command_ratio=reference["elapsed_ns"] / missing["elapsed_ns"])


def strategy_comparison(cases):
    return dict(reference="product-origin-only", samples_per_case=1, speedup_required=False,
        origin_to_auto_command_ratio=cases["origin-only"]["application"]["elapsed_ns"]
            / cases["auto"]["application"]["elapsed_ns"],
        measurements={name: dict(requested_source_strategy=name,
            command_elapsed_ns=phase["application"]["elapsed_ns"],
            peer_bytes=phase["fetch"]["peer_bytes"],
            origin_body_bytes=phase["fetch"]["origin_body_bytes"],
            origin_range_requests=phase["fetch"]["origin_range_requests"],
            providers_used=phase["fetch"]["providers_used"])
            for name, phase in cases.items()})


def validate_strategy_origin(records, phase, metadata_bytes, available_peer):
    """Exact per-command origin ranges, with no overlap or unaccounted body race."""
    fetch = phase["fetch"]
    require(len(records) == 1 + fetch["origin_range_requests"] and 1 <= len(records) <= 10,
            "strategy origin request count differs from actual receipt")
    metadata = records[0]
    require(metadata["kind"] == "metadata" and metadata["payload_bytes"] == metadata_bytes
            and metadata["status"] == 200 and all(metadata[key] is None for key in
                ("range_start", "range_end", "range_total")), "strategy origin authority missing")
    covered = set()
    for record in records[1:]:
        if record["kind"] == "body":
            require(record["status"] == 200 and len(records) == 2
                    and all(record[key] is None for key in ("range_start", "range_end", "range_total")),
                    "full origin response was raced with ranges")
            start, end = 0, BYTES - 1
        else:
            require(record["kind"] == "body_range" and record["status"] == 206
                    and record["range_total"] == BYTES, "invalid strategy range response")
            start, end = record["range_start"], record["range_end"]
        require(0 <= start <= end < BYTES and start % RANGE_BYTES == 0
                and (end == BYTES - 1 or (end + 1) % RANGE_BYTES == 0)
                and record["payload_bytes"] == end - start + 1, "strategy body is not exact verified chunks")
        chunks = set(range(start // RANGE_BYTES, end // RANGE_BYTES + 1))
        require(not covered.intersection(chunks), "duplicate origin body bytes")
        covered.update(chunks)
    peer_chunks = set(range(9)) - covered
    require(peer_chunks <= {0, 2, 4, 6, 8}
            and fetch["peer_bytes"] == sum(min(RANGE_BYTES, BYTES - chunk * RANGE_BYTES) for chunk in peer_chunks)
            and fetch["origin_body_bytes"] == sum(record["payload_bytes"] for record in records[1:])
            and fetch["peer_bytes"] + fetch["origin_body_bytes"] == BYTES
            and fetch["provider_peer_ids"] == ([available_peer] if peer_chunks else [])
            and fetch["providers_used"] == bool(peer_chunks),
            "strategy source accounting duplicates data or invents unavailable peer chunks")


def validate_strategies(evidence, records, control_node):
    cases, old = evidence["source_strategy_cases"], evidence["cases"]
    require(set(cases) == {"origin-only", "auto"}, "both cold product source strategies required")
    peers, nodes = evidence["expected_peers"], evidence["layout"]["provider_nodes"]
    offset = 8
    for mode in ("origin-only", "auto"):
        phase = cases[mode]
        fetch, output = phase["fetch"], phase["output"]
        require(fetch["bytes"] == output["bytes"] == BYTES and fetch["chunks"] == 9
                and fetch["origin_authenticated"] is True
                and fetch["control_relay_peer_id"] == evidence["layout"]["control_relay_peer_id"]
                and output["client_cache_initially_absent"] is True
                and output["client_mount_cannot_read_origin"] is True
                and phase["selected_route"]["route_context_id"] == old["complete"]["selected_route"]["route_context_id"],
                "strategy did not authenticate the exact cold object over the retained route")
        if mode == "origin-only":
            require(fetch["peer_bytes"] == 0 and fetch["origin_body_bytes"] == BYTES,
                    "explicit origin-only selected peers")
        count = 1 + fetch["origin_range_requests"]
        validate_strategy_origin(records[offset:offset + count], phase,
            evidence["publication"]["metadata_bytes"], peers[nodes[0]])
        offset += count
        validate_local_output(phase)
        validate_application(phase, browser=False, source_strategy=mode)
        validate_path(phase, peers, nodes, missing=True, origin_only=mode == "origin-only",
                      useful_peer_bytes=fetch["peer_bytes"])
        validate_control(phase["control"], control_node, nodes, missing=True, require_contacts=False)
    require(offset == len(records), "unaccounted origin requests outside product phases")
    all_outputs = [phase["output"] for phase in (*old.values(), *cases.values())]
    require(len({out["path"] for out in all_outputs}) == len(all_outputs)
            and len({out["agent_cache"] for out in all_outputs}) == len(all_outputs),
            "source comparison reused another phase's output or cache")
    require(evidence["source_strategy_comparison"] == strategy_comparison(cases),
            "product comparison is not actual single-sample time and source accounting")


def validate_digest_indexes(evidence):
    """Bind independent signed indexes to a real registry reset and the unchanged partial cache."""
    indexes = evidence["digest_provider_indexes"]
    publication, binding = indexes["publication"], indexes["binding"]
    original, independent = publication["original"], publication["independent"]
    native = evidence["native_publication"]
    node = evidence["layout"]["provider_nodes"][1]
    layout = [dict(sha256=hashlib.sha256(bytes([65 + index]) * RANGE_BYTES).hexdigest(), bytes=RANGE_BYTES)
              for index in range(8)] + [dict(sha256=hashlib.sha256(b"Z" * 123).hexdigest(), bytes=123)]
    require(publication["report_kind"] == "volparossa-https-independent-index"
            and original["manifest_id"] == native["manifest_id"]
            and original["publisher_hex"] == native["publisher_hex"]
            and re.fullmatch(r"[0-9a-f]{64}", independent["manifest_id"])
            and re.fullmatch(r"[0-9a-f]{64}", independent["publisher_hex"])
            and independent["manifest_id"] != original["manifest_id"]
            and independent["publisher_hex"] != original["publisher_hex"]
            and original["chunks"] == independent["chunks"] == layout
            and original["object_sha256"] == independent["object_sha256"] == SHA
            and original["bytes"] == independent["bytes"] == BYTES
            and original["content_type"] == independent["content_type"] == "application/octet-stream"
            and original["name"] == independent["name"] == "disposable-native-network-publication"
            and original["revision"] == independent["revision"] == 1
            and 0 < original["created_unix_seconds"] == independent["created_unix_seconds"]
                <= publication["checked_unix_seconds"] <= binding["registered_unix_seconds"]
                < original["expires_unix_seconds"] == independent["expires_unix_seconds"]
            and publication["publisher_private_key_persisted"] is False
            and publication["temporary_full_copy_removed"] is True,
            "different original indexes, identical public layout or unchanged live expiry not proven")
    cache = publication["cache_before"]
    require(cache == publication["cache_after"] and cache["path"] == binding["cache"]
            and cache["device"] > 0 and cache["inode"] > 0
            and cache["entries"] == 4 and cache["bytes"] == 4 * RANGE_BYTES
            and cache["chunk_ids"] == [chunk["sha256"] for chunk in layout[1::2]]
            and Path(cache["path"]).parts[-3:] == (f"state-{node}", "content", "cache")
            and Path(binding["manifest_path"]) == Path(cache["path"]).parent / "digest-index" / "manifest.bin"
            and binding["provider_node"] == node
            and binding["provider_peer_id"] == evidence["expected_peers"][node]
            and binding["publisher_hex"] == independent["publisher_hex"]
            and binding["manifest_file_sha256"] == independent["manifest_id"]
            and binding["original_manifest_file_sha256"] == original["manifest_id"]
            and binding["bind_address"] == f"{PUBLIC_IPS[node]}:18080"
            and binding["advertised_hostname"] == {
                "relay4":"provider-a.volparossa.test", "relay5":"provider-b.volparossa.test",
                "relay3":"provider-c.volparossa.test"}[node]
            and binding["replacement_phase"] == "after-digest-origin-only"
            and indexes["a_status"]["serving"] is True and indexes["a_status"]["publications"] == 1
            and indexes["a_status"]["replication_enabled"] is False
            and indexes["b_stop"]["serving"] is False and indexes["b_stop"]["publications"] == 0
            and indexes["b_serve"]["serving"] is True and indexes["b_serve"]["publications"] == 1,
            "independent B index was not exclusively registered over its unchanged four-chunk cache")
    return {original["manifest_id"], independent["manifest_id"]}


def validate_digest_cases(evidence, records, control_node):
    """Fresh origin HEAD, no descriptor, then either one full GET or two independent indexes."""
    original_ids = validate_digest_indexes(evidence)
    cases = evidence["origin_digest_cases"]
    require(set(cases) == set(DIGEST_CASES), "both cold origin-digest cases required")
    require(len(records) == 3 and [record["kind"] for record in records]
            == ["digest_head", "body", "digest_head"],
            "digest cases did not issue exactly HEAD+GET then HEAD without origin body")
    for index, record in enumerate(records):
        head = index != 1
        require(record["method"] == ("HEAD" if head else "GET")
                and record["payload_bytes"] == (0 if head else BYTES)
                and record["content_length"] == BYTES and record["status"] == 200
                and record["representation_digest"] == REPR_DIGEST
                and record["object_sha256"] == SHA
                and all(record[key] is None for key in ("range_start", "range_end", "range_total")),
                "digest HEAD or ordinary GET represented another body, range or digest")
    for name in DIGEST_CASES:
        from_origin = name == "digest-origin-only"
        validate_digest_phase(evidence, cases[name], from_origin, name.removeprefix("digest-"), control_node, original_ids)
    all_phases = (*evidence["cases"].values(), *evidence["source_strategy_cases"].values(), *cases.values(),
                  *evidence["limited_uplink"]["cases"].values())
    require(len({phase["output"]["path"] for phase in all_phases}) == len(all_phases)
            and len({phase["output"]["agent_cache"] for phase in all_phases}) == len(all_phases),
            "digest phases reused an earlier output or agent cache")


def validate_digest_phase(evidence, phase, from_origin, strategy, control_node, original_ids):
    peers, nodes = evidence["expected_peers"], evidence["layout"]["provider_nodes"]
    fetch, output, application = phase["fetch"], phase["output"], phase["application"]
    require(fetch["bytes"] == output["bytes"] == BYTES and fetch["chunks"] == 9
                and fetch["origin_authenticated"] is True
                and fetch["authentication_scope"] == "origin-repr-digest"
                and fetch["origin_digest"] is True
                and application["requested_origin_digest"] is True
                and re.fullmatch(r"[0-9a-f]{64}", fetch["transport_manifest_id"])
                and fetch["peer_bytes"] == (0 if from_origin else BYTES)
                and fetch["origin_body_bytes"] == (BYTES if from_origin else 0)
                and fetch["origin_range_requests"] == 0
                and fetch["providers_used"] == (0 if from_origin else 2)
                and len(fetch["provider_peer_ids"]) == (0 if from_origin else 2)
                and set(fetch["provider_peer_ids"]) == (set() if from_origin else {peers[node] for node in nodes})
                and fetch["control_relay_peer_id"] == evidence["layout"]["control_relay_peer_id"]
                and output["client_cache_initially_absent"] is True
                and output["client_mount_cannot_read_origin"] is True
                and phase["selected_route"]["route_context_id"]
                    == evidence["cases"]["complete"]["selected_route"]["route_context_id"],
                "digest CLI authority, exact body accounting or cold protected route not proven")
    if not from_origin:
        require(fetch["transport_manifest_id"] in original_ids,
                "digest peer lookup did not retain either provider's original envelope")
    validate_local_output(phase)
    validate_application(phase, browser=False, source_strategy=strategy)
    validate_path(phase, peers, nodes, missing=False, origin_only=from_origin)
    validate_control(phase["control"], control_node, nodes, missing=False, require_contacts=not from_origin)


def limited_comparison(cases):
    origin = cases["limited-origin-only"]["application"]["elapsed_ns"]
    automatic = cases["limited-auto"]["application"]["elapsed_ns"]
    return dict(reference="product-origin-only-fixed-4mbit-origin-uplink", samples_per_case=1,
        complete_command_duration=True, rate_tuned_after_measurement=False,
        origin_to_auto_command_ratio=origin / automatic, benefit_passed=automatic < origin,
        measurements={name: dict(command_elapsed_ns=phase["application"]["elapsed_ns"],
            peer_bytes=phase["fetch"]["peer_bytes"], origin_body_bytes=phase["fetch"]["origin_body_bytes"],
            providers_used=phase["fetch"]["providers_used"]) for name, phase in cases.items()})


def tbf(qdiscs):
    require(len(qdiscs) == 1 and qdiscs[0]["kind"] == "tbf" and qdiscs[0]["handle"] == "804:"
            and qdiscs[0]["root"] is True and qdiscs[0]["options"]["rate"] == 500000
            and qdiscs[0]["options"]["burst"] == 131072 and qdiscs[0]["options"]["lat"] == 250000
            and qdiscs[0]["bytes"] >= 0 and qdiscs[0]["drops"] >= 0, "wrong fixed TBF or missing actual counters")
    return qdiscs[0]


def validate_limited(evidence, records, control_node):
    value = evidence["limited_uplink"]
    profile, cases = value["profile"], value["cases"]
    require(set(cases) == set(LIMITED_CASES)
            and profile["profile"] == "fixed-origin-uplink-4mbit" and profile["interface"] == "dx"
            and profile["origin_address"] == "47.163.4.2" and profile["handle"] == "804:"
            and profile["rate_bits_per_second"] == 4000000 and profile["burst_bytes"] == 131072
            and profile["queue_latency_ms"] == 250
            and re.fullmatch(r"net:\[[0-9]+\]", profile["namespace"])
            and profile["namespace"] != profile["parent_namespace"]
            and profile["application_sleeps"] is False and profile["adaptive_rate"] is False
            and 0 < profile["window_ns"] == profile["completed_monotonic_ns"] - profile["started_monotonic_ns"]
                < 60_000_000_000, "wrong network condition or expired common cost window")
    for name in ("before", "after"):
        qdiscs = value["qdisc_" + name]
        require(len(qdiscs) == 1 and qdiscs[0]["kind"] == "noqueue" and qdiscs[0]["root"] is True,
                "origin link was not initially unshaped or its owned limiter survived cleanup")
    require([record["kind"] for record in records] == ["digest_head", "body", "digest_head", "digest_head"],
            "limited cases require exactly fresh HEAD+GET, HEAD, HEAD with no fallback body")
    for index, record in enumerate(records):
        body = index == 1
        require(record["method"] == ("GET" if body else "HEAD") and record["status"] == 200
                and record["payload_bytes"] == (BYTES if body else 0) and record["content_length"] == BYTES
                and record["representation_digest"] == REPR_DIGEST and record["object_sha256"] == SHA
                and all(record[key] is None for key in ("range_start", "range_end", "range_total")),
                "limited origin altered TLS-authorized representation or duplicated payload")
    ids = validate_digest_indexes(evidence)
    expiry = evidence["digest_provider_indexes"]["publication"]["original"]["expires_unix_seconds"]
    last_clock, last_bytes, options = profile["started_monotonic_ns"], 0, None
    for name in LIMITED_CASES:
        phase = cases[name]
        strategy = name.removeprefix("limited-")
        validate_digest_phase(evidence, phase, strategy == "origin-only", strategy, control_node, ids)
        app = phase["application"]
        require(last_clock <= app["started_monotonic_ns"] < app["completed_monotonic_ns"]
                <= profile["completed_monotonic_ns"]
                and app["elapsed_ns"] == app["completed_monotonic_ns"] - app["started_monotonic_ns"]
                and 0 < app["started_unix_ms"] <= app["completed_unix_ms"] < expiry * 1000,
                "commands overlap, exceeded the common window or renewed the transport expiry")
        last_clock = app["completed_monotonic_ns"]
        for position in ("before", "after"):
            current = tbf(phase["qdisc_" + position])
            require(current["bytes"] >= last_bytes and (options is None or current["options"] == options),
                    "origin limiter was reset or tuned between comparisons")
            options, last_bytes = current["options"], current["bytes"]
        fresh = phase["source_events"]
        expected = {"origin-only":"CONTENT_HTTPS_SOURCE_EXPLICIT_ORIGIN",
                    "peers-first":"CONTENT_HTTPS_SOURCE_EXPLICIT_PEERS",
                    "auto":"CONTENT_HTTPS_SOURCE_MEASURED_PEERS"}[strategy]
        require(len(fresh) == 1 and fresh[0]["event"] == expected
                and app["started_unix_ms"] <= fresh[0]["unix_ms"] <= app["completed_unix_ms"],
                "current source-choice event is absent, historical or disagrees with actual command")
    final = tbf(value["qdisc_final"])
    require(final["options"] == options and final["bytes"] >= last_bytes >= BYTES,
            "actual origin response did not pass through the unchanged measured limiter")
    require(value["comparison"] == limited_comparison(cases), "invented benefit or command timing ratio")


def source_events(work, prefix):
    def lines(suffix):
        with (work / f"{prefix}-events-{suffix}.txt").open("rb") as source:
            data = source.read(2 * 1024 * 1024 + 1)
        require(len(data) <= 2 * 1024 * 1024, "oversized bounded event ring")
        return set(data.decode("utf-8").splitlines())
    before = lines("before")
    events = []
    for line in sorted(lines("after") - before):
        found = re.match(r"([0-9]+)\s+.*?\bevent=(CONTENT_HTTPS_SOURCE_[A-Z_]+)(?:\s|$)", line)
        if found:
            events.append(dict(unix_ms=int(found[1]), event=found[2]))
    return events


def validate_evidence(evidence):
    publication, original = evidence["publication"], evidence["native_publication"]
    require(evidence["success"] is True
            and publication["bytes"] == original["bytes"] == BYTES
            and publication["object_sha256"] == original["object_sha256"] == SHA
            and publication["chunks"] == original["chunks"] == 9
            and publication["publisher_hex"] == original["publisher_hex"]
            and re.fullmatch(r"[0-9a-f]{64}", publication["publisher_hex"])
            and publication["manifest_id"] == original["manifest_id"]
            and re.fullmatch(r"[0-9a-f]{64}", publication["manifest_id"])
            and publication["existing_publication_reused"] is True
            and publication["publisher_private_key_persisted"] is False
            and original["publisher_private_key_persisted"] is False
            and original["publisher_removed"] is True
            and original["replica_a_chunks"] == 5 and original["replica_b_chunks"] == 4
            and 0 < publication["metadata_bytes"] <= 81920,
            "origin did not authorize the exact independently existing publisher-offline object")
    peers, layout = evidence["expected_peers"], evidence["layout"]
    control, provider_nodes = layout["control_relay_peer_id"], layout["provider_nodes"]
    require(control in {peers[node] for node in PUBLIC_IPS}
            and provider_nodes == [node for node in CANDIDATES if peers[node] != control][:2]
            and len({peers[node] for node in provider_nodes}) == 2,
            "provider layout or distinct current control Relay invalid")
    control_node = next(node for node in PUBLIC_IPS if peers[node] == control)
    withdrawal, stop = evidence["withdrawal"], evidence["missing_provider_stop"]
    require(withdrawal["provider_node"] == provider_nodes[1]
            and withdrawal["provider_peer_id"] == peers[provider_nodes[1]]
            and stop["serving"] is False and stop["publications"] == 0,
            "the second actual provider was not explicitly withdrawn before missing retrieval")
    origin, raw_records = evidence["origin"], evidence["origin"]["connections"]
    # Digest phases run after complete; B's independent index replaces only its registration.
    # Keep every raw record; validate their exact slice independently, never ignore extras.
    digest_records = raw_records[1:4]
    limited_records = raw_records[4:8]
    records = raw_records[:1] + raw_records[8:]
    require(origin["pid"] > 0 and 19 <= len(raw_records) <= 31
            and origin["request_limit"] == 31 and origin["stop_requested"] is True
            and origin["listener_closed"] is True and origin["inflight_drained"] is True
            and [r["kind"] for r in records[:8]] == ["metadata"] * 2 + ["body_range"] * 4 + ["metadata", "body"]
            and [r["payload_bytes"] for r in records[:8]]
                == [publication["metadata_bytes"]] * 2 + [RANGE_BYTES] * 4 + [publication["metadata_bytes"], BYTES]
            and all(r["tls13"] is True and r["alpn_http11"] is True
                    and origin_exit_source(r["source"]) for r in raw_records),
            "three actual origin HTTPS metadata sessions, four ranges and one full reference body not proven")
    require(all(r["status"] == 200 and r["range_start"] is None and r["range_end"] is None
                and r["range_total"] is None for r in records[:2])
            and all(r["status"] == 206 and r["range_start"] == start and r["range_end"] == end
                    and r["range_total"] == BYTES
                    for r, (start, end) in zip(records[2:6], RANGES, strict=True))
            and all(r["status"] == 200 and r["range_start"] is None and r["range_end"] is None
                    and r["range_total"] is None for r in records[6:8]),
            "origin returned wrong missing-chunk ranges or a forbidden full-body substitute")
    cases = evidence["cases"]
    require(set(cases) == {"complete", "missing"}, "both fresh-cache HTTPS retrieval cases required")
    for name, phase in cases.items():
        missing = name == "missing"
        fetch, output = phase["fetch"], phase["output"]
        active = provider_nodes[:1] if missing else provider_nodes
        require(fetch["bytes"] == output["bytes"] == BYTES and output["sha256"] == SHA
                and fetch["chunks"] == 9 and fetch["origin_authenticated"] is True
                and fetch["peer_bytes"] == (1048699 if missing else BYTES)
                and fetch["origin_body_bytes"] == (1048576 if missing else 0)
                and fetch["origin_range_requests"] == (4 if missing else 0)
                and fetch["providers_used"] == len(active)
                and len(fetch["provider_peer_ids"]) == len(active)
                and set(fetch["provider_peer_ids"]) == {peers[node] for node in active}
                and fetch["control_relay_peer_id"] == control
                and output["client_cache_initially_absent"] is True
                and output["client_mount_cannot_read_origin"] is True,
                "normal CLI did not authenticate/reconstruct the expected peer-plus-origin bytes")
        validate_local_output(phase)
        validate_application(phase, browser=not missing)
        validate_path(phase, peers, provider_nodes, missing)
        validate_control(phase["control"], control_node, provider_nodes, missing)
    require(cases["complete"]["selected_route"]["route_context_id"]
                == cases["missing"]["selected_route"]["route_context_id"],
            "HTTPS cases changed the carrying route context")
    validate_baseline(evidence["origin_baseline"], cases, peers, provider_nodes)
    require(evidence["comparison"] == measured_comparison(cases, evidence["origin_baseline"]),
            "reported comparison is not the actual single-sample monotone timing ratio")
    validate_strategies(evidence, records, control_node)
    validate_digest_cases(evidence, digest_records, control_node)
    validate_limited(evidence, limited_records, control_node)
    require(evidence["user_cleanup"] == dict(user_outputs_removed=True,
            explicit_fixture_ca_removed=True, user_directory_removed=True),
            "temporary user outputs and explicit public CA were not cleaned up")


def build_evidence(work):
    cases = {}
    for name in ("complete", "missing", "origin-only", "auto", *DIGEST_CASES, *LIMITED_CASES):
        prefix = f"content-provider-https-{name}"
        cases[name] = dict(
            fetch=read(work / f"{prefix}-fetch.json"),
            application=read(work / f"{prefix}-consumer.json"),
            status=read(work / f"{prefix}-status.json"),
            output=read(work / f"{prefix}-output.json"),
            selected_route=read(work / f"{prefix}-live-selection.json"),
            privacy={role: read(work / f"{prefix}-privacy-{role}.json") for role in ROLES},
            control=read(work / f"{prefix}-control.json"))
    strategies = {mode: cases.pop(mode) for mode in ("origin-only", "auto")}
    digests = {mode: cases.pop(mode) for mode in DIGEST_CASES}
    limited = {mode: cases.pop(mode) for mode in LIMITED_CASES}
    for mode, phase in limited.items():
        prefix = f"content-provider-https-{mode}"
        phase.update(source_events=source_events(work, prefix),
            qdisc_before=read(work / f"{prefix}-qdisc-before.json"),
            qdisc_after=read(work / f"{prefix}-qdisc-after.json"))
    evidence = dict(success=True, cases=cases, source_strategy_cases=strategies,
        origin_digest_cases=digests,
        limited_uplink=dict(cases=limited, comparison=limited_comparison(limited),
            profile=read(work / "content-provider-https-limited-profile.json"),
            **{"qdisc_" + position: read(work / f"content-provider-https-limited-qdisc-{position}.json")
               for position in ("before", "after", "final")}),
        digest_provider_indexes={key: read(work / f"content-provider-https-index-{suffix}.json")
            for key, suffix in (("publication", "publication"), ("binding", "binding"),
                                ("a_status", "a-status"), ("b_stop", "b-stop"), ("b_serve", "b-serve"))},
        source_strategy_comparison=strategy_comparison(strategies),
        publication=read(work / "content-provider-https-publication.json"),
        native_publication=read(work / "content-provider-publication.json"),
        layout=read(work / "content-provider-layout.json"),
        expected_peers=read(work / "a01-expected-peers.json"),
        origin=read(work / "content-provider-https-origin.json"),
        user_cleanup=read(work / "content-provider-https-user-cleanup.json"),
        missing_provider_stop=read(work / "content-provider-https-provider-stop.json"),
        withdrawal=read(work / "content-provider-https-withdrawal.json"))
    prefix = "content-provider-https-baseline"
    baseline = dict(application=read(work / f"{prefix}-consumer.json"),
        ingress=read(work / f"{prefix}-ingress.json"),
        selected_route=read(work / f"{prefix}-live-selection.json"),
        privacy={role: read(work / f"{prefix}-privacy-{role}.json") for role in ROLES})
    evidence.update(origin_baseline=baseline, comparison=measured_comparison(cases, baseline))
    validate_evidence(evidence)
    return evidence


if __name__ == "__main__":
    try:
        if len(sys.argv) == 12 and sys.argv[1] == "consume":
            json.dump(consume(sys.argv[2:]), sys.stdout, sort_keys=True, separators=(",", ":"))
            sys.stdout.write("\n")
        elif len(sys.argv) == 4 and sys.argv[1] == "evidence":
            evidence = build_evidence(Path(sys.argv[2]))
            with Path(sys.argv[3]).open("x", encoding="ascii") as target:
                json.dump(evidence, target, sort_keys=True, separators=(",", ":"))
        else:
            raise ValueError("expected evidence WORK OUTPUT or bounded consume arguments")
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError,
            http.client.HTTPException) as error:
        raise SystemExit(f"HTTPS provider evidence rejected: {error}") from error
