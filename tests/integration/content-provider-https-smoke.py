#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Normal CLI/browser-HTTP provider evidence, not a GUI, speed or full C02/C08 acceptance.

The enclosing native-provider report owns exact-source and final host/guest cleanup checks.
This checker requires both HTTPS phases and their independently drained physical captures.
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


def consume(arguments):
    """Called only after the enclosing disposable harness enters CLIENT and drops privileges."""
    case, binary, control, cache, user_path, parent_ns, client_ns, uid, gid, control_gid = arguments
    require(case in ("complete", "missing"), "unknown HTTPS consumer phase")
    uid, gid, control_gid = int(uid), int(gid), int(control_gid)
    boundary = process_boundary("self", parent_ns, client_ns, uid, gid, control_gid)
    user_directory = Path(user_path)
    output = user_directory / f"{case}-object.bin"
    require(not output.exists() and not output.is_symlink()
            and not list(user_directory.glob("volparossa-browser-*")), "consumer storage is not fresh")
    command = [binary, "--control-socket", control, "content",
               "browser-download" if case == "complete" else "fetch-https",
               "--url", "https://destination.volparossa.test:18443/asset.bin",
               "--metadata-path", "/.well-known/volparossa/content/asset",
               "--ca-file", str(user_directory / "origin.pem"), "--cache", cache]
    if case == "missing":
        command.extend(["--local-output", str(output)])
    started, deadline = time.monotonic_ns(), time.monotonic() + 110
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
        report["elapsed_ns"] = time.monotonic_ns() - started
        require(not list(user_directory.glob("volparossa-browser-*")), "private browser spool remained")
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


def validate_drained(capture):
    statistics = capture["interface_statistics"]
    require(capture["truncated"] is False and capture["observed_frames"] > 0
            and capture["packet_socket_drops"] == 0 and len(capture["interfaces"]) > 0
            and len(set(capture["interfaces"])) == len(capture["interfaces"])
            and set(statistics) == set(capture["interfaces"])
            and sum(s["observed_frames"] for s in statistics.values()) == capture["observed_frames"]
            and all(s["intake_stopped"] is True and s["packet_socket_drops"] == 0
                    and s["packet_socket_packets"] == s["observed_frames"]
                    for s in statistics.values()),
            "capture truncated, dropped, still accepting intake or not completely drained")


def validate_control(capture, control_node, provider_nodes, missing):
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
    validate_drained(capture)
    # The withdrawn provider may legitimately receive no second-phase service query.
    for interface in ("cp0",) if missing else ("cp0", "cp1"):
        counters = capture["content_control_packets"][interface]
        require(counters["inbound"] > 0 and counters["outbound"] > 0,
                "active provider lacks bidirectional authenticated-control traffic")


def validate_path(phase, peers, provider_nodes, missing):
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
    active = provider_nodes[:1] if missing else provider_nodes
    for node in CANDIDATES:
        application = privacy["exit"]["provider_application"][node]
        if node in active:
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


def validate_application(phase, browser):
    application, fetch, output = phase["application"], phase["fetch"], phase["output"]
    require(application["final"] == fetch and 0 < application["elapsed_ns"] <= 120_000_000_000,
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
    origin, records = evidence["origin"], evidence["origin"]["connections"]
    require(origin["pid"] > 0 and len(records) == 6
            and [r["kind"] for r in records] == ["metadata"] * 2 + ["body_range"] * 4
            and [r["payload_bytes"] for r in records]
                == [publication["metadata_bytes"]] * 2 + [RANGE_BYTES] * 4
            and all(r["tls13"] is True and r["alpn_http11"] is True
                    and origin_exit_source(r["source"]) for r in records),
            "two genuine origin HTTPS metadata sessions and four body ranges not proven")
    require(all(r["status"] == 200 and r["range_start"] is None and r["range_end"] is None
                and r["range_total"] is None for r in records[:2])
            and all(r["status"] == 206 and r["range_start"] == start and r["range_end"] == end
                    and r["range_total"] == BYTES
                    for r, (start, end) in zip(records[2:], RANGES, strict=True)),
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
    require(evidence["user_cleanup"] == dict(user_outputs_removed=True,
            explicit_fixture_ca_removed=True, user_directory_removed=True),
            "temporary user outputs and explicit public CA were not cleaned up")


def build_evidence(work):
    cases = {}
    for name in ("complete", "missing"):
        prefix = f"content-provider-https-{name}"
        cases[name] = dict(
            fetch=read(work / f"{prefix}-fetch.json"),
            application=read(work / f"{prefix}-consumer.json"),
            status=read(work / f"{prefix}-status.json"),
            output=read(work / f"{prefix}-output.json"),
            selected_route=read(work / f"{prefix}-live-selection.json"),
            privacy={role: read(work / f"{prefix}-privacy-{role}.json") for role in ROLES},
            control=read(work / f"{prefix}-control.json"))
    evidence = dict(success=True, cases=cases,
        publication=read(work / "content-provider-https-publication.json"),
        native_publication=read(work / "content-provider-publication.json"),
        layout=read(work / "content-provider-layout.json"),
        expected_peers=read(work / "a01-expected-peers.json"),
        origin=read(work / "content-provider-https-origin.json"),
        user_cleanup=read(work / "content-provider-https-user-cleanup.json"),
        missing_provider_stop=read(work / "content-provider-https-provider-stop.json"),
        withdrawal=read(work / "content-provider-https-withdrawal.json"))
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
