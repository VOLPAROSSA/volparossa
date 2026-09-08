#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Ordinary signed native-site CLI and HTTP proof; no browser engine or HTTPS origin claim."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import runpy
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

HERE = Path(__file__).parent
COMMON = runpy.run_path(str(HERE / "content-network-smoke.py"))
HTTPS = runpy.run_path(str(HERE / "content-provider-https-smoke.py"))
read, require, ROLES = COMMON["read"], COMMON["require"], COMMON["ROLES"]
NAME = "disposable-native-static-site"
CONTENT_TYPE = "application/vnd.volparossa.site.v1"
CANDIDATES = HTTPS["CANDIDATES"]
# Canonical ordinary `content site pack` over the four exact assets below.
BUNDLE_BYTES = 2097628
BUNDLE_SHA256 = "5e3012170ca5335e4f8b7e419fda3ae4ddf59e7603eeabb6a9c2544ea6088a04"


def assets():
    return {
        "/index.html": ("text/html", b"<!doctype html><link rel=stylesheet href=/main.css?v=1>"
                        b"<h1>Native replica site</h1><script src=/main.js></script>"
                        b"<a href=/media.bin>Public range fixture</a>"),
        "/main.css": ("text/css", b"h1{color:green}"),
        "/main.js": ("text/javascript", b"document.title='Native replica site';"),
        # Independent chunks, not repeated blocks; binary byte-range semantics, not video decoding.
        "/media.bin": ("application/octet-stream",
                       hashlib.shake_256(b"volparossa-native-site-public-range-v1").digest(2097275)),
    }


def inventory():
    return {path: dict(content_type=kind, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            for path, (kind, data) in assets().items()}


def private(path, directory=False):
    metadata = path.lstat()
    require((stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
            and stat.S_IMODE(metadata.st_mode) == (0o700 if directory else 0o600)
            and metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid(),
            "fixture ownership or private mode changed")
    return metadata


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def initialize(path):
    require(path.name == "site-publisher" and not list(path.iterdir()), "publisher root is not fresh")
    private(path, True)
    (path / "assets").mkdir(mode=0o700)
    for name, (_, data) in assets().items():
        write_new(path / "assets" / name[1:], data)
    write_new(path / "passphrase", os.urandom(48).hex().encode() + b"\n")
    return dict(name=NAME, content_type=CONTENT_TYPE, assets=inventory())


def remove_publisher(path):
    """Validate every exact disposable entry before unlinking; never adopt or sweep agent caches."""
    require(path.name == "site-publisher" and not path.is_symlink(), "unexpected publisher root")
    if not path.exists():
        return dict(publisher_files_removed=True, source_cache_removed=True, manifest_removed=True)
    private(path, True)
    allowed = {"identity.key", "passphrase", "bundle.bin", "manifest.bin", "assets", "source-cache"}
    entries = list(path.iterdir())
    require({entry.name for entry in entries} <= allowed, "unknown publisher entry")
    files, directories, total = [], [], 0
    for entry in entries:
        if entry.name in ("assets", "source-cache"):
            private(entry, True)
            children = list(entry.iterdir())
            require(len(children) <= 32, "publisher cache exceeded fixture bound")
            for child in children:
                valid = child.name in {name[1:] for name in assets()} if entry.name == "assets" else (
                    re.fullmatch(r"[0-9a-f]{64}", child.name) or child.name in {
                        ".volparossa-owner-v1", ".volparossa-index-v1"})
                require(valid, "unknown file in disposable publisher directory")
                total += private(child).st_size
                files.append(child)
            directories.append(entry)
        else:
            total += private(entry).st_size
            files.append(entry)
    require(total <= 8 * 1024 * 1024, "publisher removal byte bound exceeded")
    for entry in files:
        entry.unlink()
    for entry in directories:
        entry.rmdir()
    path.rmdir()
    return dict(publisher_files_removed=True, source_cache_removed=True, manifest_removed=True)


def remove_user(path):
    require(path.name == "site-viewer" and not path.is_symlink(), "unexpected viewer root")
    if path.exists():
        private(path, True)
        entries = list(path.iterdir())
        require({entry.name for entry in entries} <= {"expected.json"}, "private viewer spool remained after process exit")
        for entry in entries:
            metadata = entry.lstat()
            require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o400
                    and metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid(), "unexpected viewer metadata file")
            entry.unlink()
        path.rmdir()
    return dict(user_directory_removed=True)


def http_request(port, host, method, path, extra=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers={"Host": host, **(extra or {})})
        response = connection.getresponse()
        data = response.read(3 * 1024 * 1024 + 1)
        require(len(data) <= 3 * 1024 * 1024 and response.read(1) == b"", "HTTP body exceeded bound")
        csp = response.getheader("Content-Security-Policy", "")
        require(response.getheader("Cache-Control") == "no-store"
                and response.getheader("X-Content-Type-Options") == "nosniff"
                and response.getheader("Referrer-Policy") == "no-referrer"
                and "sandbox allow-scripts allow-downloads" in csp and "allow-same-origin" not in csp
                and response.getheader("Access-Control-Allow-Origin") == "*"
                and response.getheader("Access-Control-Allow-Credentials") is None,
                "site HTTP isolation headers absent")
        return dict(status=response.status, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                    content_type=response.getheader("Content-Type"),
                    content_length=response.getheader("Content-Length"),
                    content_range=response.getheader("Content-Range"), security_headers_verified=True)
    finally:
        connection.close()


def consume(arguments):
    binary, control, cache, directory, parent_ns, client_ns, uid, gid, group = arguments
    uid, gid, group = int(uid), int(gid), int(group)
    boundary = HTTPS["process_boundary"]("self", parent_ns, client_ns, uid, gid, group)
    directory = Path(directory)
    private(directory, True)
    expected = read(directory / "expected.json")
    require({entry.name for entry in directory.iterdir()} == {"expected.json"}, "viewer directory not fresh")
    command = [binary, "--control-socket", control, "content", "site", "open",
               "--publisher-key", expected["publisher_key"], "--name", NAME, "--min-revision", "1",
               "--cache", cache, "--min-free-bytes", "0", "--lifetime-seconds", "90"]
    started, deadline = time.monotonic_ns(), time.monotonic() + 110
    process = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=0,
                               env=dict(os.environ, TMPDIR=str(directory)))
    previous = {}
    def interrupted(_signum, _frame):
        raise ValueError("site application interrupted")
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, interrupted)
        cli = HTTPS["process_boundary"](process.pid, parent_ns, client_ns, uid, gid, group)
        ready = HTTPS["bounded_json_line"](process.stdout, deadline)
        require(ready["operation"] == "native_site_ready"
                and ready["bytes"] == expected["bundle_bytes"] and ready["sha256"] == expected["bundle_sha256"]
                and ready["publisher_key"] == expected["publisher_key"] and ready["name"] == NAME,
                "site Ready did not authenticate the exact ordinary publication")
        url = urlsplit(ready["site_url"])
        require(url.scheme == "http" and url.path == "/" and not url.query and not url.fragment
                and url.username is None and url.password is None and url.port is not None
                and re.fullmatch(r"vp[0-9a-f]{32}\.localhost", url.hostname or "")
                and url.netloc == f"{url.hostname}:{url.port}", "site URL is not an exact private localhost host")
        spools = list(directory.glob("volparossa-site-*"))
        require(len(spools) == 1, "expected one native site spool")
        private(spools[0], True)
        files = list(spools[0].iterdir())
        require(len(files) == 1 and private(files[0]).st_size == ready["bytes"], "site spool incomplete")
        results = {}
        for path, (_, data) in assets().items():
            target = "/" if path == "/index.html" else path + "?v=1" if path == "/main.css" else path
            result = http_request(url.port, url.netloc, "GET", target)
            require(result["status"] == 200 and result["bytes"] == len(data)
                    and result["sha256"] == hashlib.sha256(data).hexdigest(), "site asset changed")
            results[path] = result
        head = http_request(url.port, url.netloc, "HEAD", "/media.bin")
        partial = http_request(url.port, url.netloc, "GET", "/media.bin", {"Range": "bytes=101-4196"})
        rejected = {"host": http_request(url.port, "unrelated.localhost", "GET", "/")["status"],
                    "traversal": http_request(url.port, url.netloc, "GET", "/../index.html")["status"]}
        require(time.time() < ready["expires_unix_seconds"], "HTTP outlived native authority")
        process.send_signal(signal.SIGTERM)
        final = HTTPS["bounded_json_line"](process.stdout, min(deadline, time.monotonic() + 5))
        require(process.wait(timeout=5) == 0 and process.stdout.read(1) == b"", "site did not stop cleanly")
        require(final["operation"] == "native_site_closed" and final["reason"] == "terminated"
                and final["private_spool_removed"] is True and not spools[0].exists(), "site SIGTERM cleanup incomplete")
        try:
            repeated = socket.create_connection(("127.0.0.1", url.port), timeout=2)
        except ConnectionRefusedError:
            pass
        else:
            repeated.close()
            raise ValueError("site listener survived SIGTERM")
        require({entry.name for entry in directory.iterdir()} == {"expected.json"}, "viewer left private files")
        return dict(consumer=boundary, cli=cli, ready={k: v for k, v in ready.items() if k != "site_url"},
                    final={k: v for k, v in final.items() if k != "site_url"}, assets=results,
                    head=head, byte_range=partial, rejected=rejected, elapsed_ns=time.monotonic_ns()-started,
                    no_manifest_argument=True, browser_engine_executed=False, sigterm_cleanup=True,
                    listener_closed=True, private_spool_removed=True, spool_modes="0700/0600")
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


def validate_path(evidence):
    selected, peers, layout = evidence["selected_route"], evidence["expected_peers"], evidence["layout"]
    paths, slots, nodes = selected["paths"], selected["benchmark_slots"], layout["provider_nodes"]
    require(selected["transport"] == "mptcp" and len(paths) == len(slots) == 2
            and selected["route_context_id"] == evidence["isolation"]["route_context_id"]
            and re.fullmatch(r"[0-9a-f]{32}", selected["route_context_id"])
            and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [s["relay_peer_id"] for s in slots] == [p["relay_peer_id"] for p in paths]
            and {peers[n] for n in nodes}.isdisjoint({peers["client"], peers["exit"], layout["control_relay_peer_id"]}
                                                   | {p["relay_peer_id"] for p in paths}),
            "site lacks the original two-relay route or distinct content providers")
    privacy = evidence["privacy"]
    require(set(privacy) == set(ROLES), "site physical capture coverage incomplete")
    for role, capture in privacy.items():
        HTTPS["validate_drained"](capture)
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and all(capture[key] == 0 for key in ("unexpected_outer_packets", "expected_link_down_notifications",
                    "unexpected_provider_application_packets", "direct_client_exit_packets"))
                and set(capture["provider_application"]) == set(CANDIDATES), "site physical privacy failure")
        if role == "exit":
            require(capture["client_public_packets"] == capture["outbound_client_discovery_attempt_packets"] == 0,
                    "Exit learned forbidden Client traffic")
        else:
            require(capture["internet_destination_outer_packets"] == 0, "direct destination packet")
        for node, values in capture["provider_application"].items():
            if role == "exit" and node in nodes:
                require(values["request_packets"] > 0 and values["response_packets"] > 0
                        and values["response_payload_bytes"] > 0, "selected site provider carried no payload")
            else:
                require(all(value == 0 for value in values.values()), "site application escaped exact provider tuple")
    for slot in slots:
        role = slot["relay_node"]
        require(role in ROLES[1:4] and peers[role] == slot["relay_peer_id"]
                and privacy[role]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[role]["exit_leg_wireguard_data_datagrams"] > 16, "both selected WG legs lack actual data")
    require(sum(privacy["exit"]["provider_application"][node]["response_payload_bytes"] for node in nodes)
            >= evidence["input"]["bundle_bytes"], "provider capture lacks full site payload")
    control_node = next(node for node in HTTPS["PUBLIC_IPS"] if peers[node] == layout["control_relay_peer_id"])
    HTTPS["validate_control"](evidence["control_privacy"], control_node, nodes, False)


def validate_evidence(evidence):
    expected, app, publication = evidence["input"], evidence["application"], evidence["publish"]
    ready, final = app["ready"], app["final"]
    peers, layout, isolation = evidence["expected_peers"], evidence["layout"], evidence["isolation"]
    nodes = layout["provider_nodes"]
    require(evidence["success"] is True and len(nodes) == len(set(nodes)) == 2
            and set(nodes) <= set(CANDIDATES) and expected["assets"] == inventory()
            and expected["name"] == NAME and expected["content_type"] == CONTENT_TYPE
            and expected["bundle_bytes"] == BUNDLE_BYTES
            and expected["bundle_sha256"] == BUNDLE_SHA256, "invalid canonical site fixture")
    require(evidence["pack"]["operation"] == "site_pack" and evidence["pack"]["assets"] == 4
            and evidence["pack"]["bytes"] == expected["bundle_bytes"] == publication["bytes"]
            and evidence["pack"]["content_type"] == CONTENT_TYPE and evidence["pack"]["network_published"] is False
            and publication["operation"] == "offline_content_publish" and publication["network_publication"] is False
            and publication["publisher_key_hex"] == expected["publisher_key"]
            and re.fullmatch(r"[0-9a-f]{64}", expected["publisher_key"]), "site did not use normal pack/publish CLI")
    require(set(evidence["imports"]) == set(evidence["serves"]) == set(nodes), "two site providers not registered")
    manifests = set()
    caches = set()
    for node in nodes:
        imported, served = evidence["imports"][node], evidence["serves"][node]
        require(re.fullmatch(r"[0-9a-f]{64}", imported["manifest_id"]), "invalid signed site manifest ID")
        manifests.add(imported["manifest_id"])
        caches.add(imported["agent_cache"])
        require(imported["operation"] == "content_import" and imported["complete"] is True
                and imported["content_bytes"] == expected["bundle_bytes"] and imported["public_content"] is True
                and imported["ownership_changed"] is False and imported["network_transfer"] is False
                and imported["origin_authenticated"] is False and served["serving"] is True
                and served["publications"] == 2 and served["replication_enabled"] is False,
                "ordinary public import or explicit name serving missing")
    require(len(manifests) == 1 and len(caches) == 2 and ready["manifest_id"] in manifests,
            "site manifest or independent cache identity differs")
    for receipt, operation in ((ready, "native_site_ready"), (final, "native_site_closed")):
        require(receipt["operation"] == operation and receipt["publisher_key"] == expected["publisher_key"]
                and receipt["name"] == NAME and receipt["revision"] == 1 and receipt["assets"] == 4
                and receipt["bytes"] == receipt["peer_bytes"] == expected["bundle_bytes"]
                and receipt["chunks"] == publication["chunks"] == 9
                and receipt["sha256"] == expected["bundle_sha256"] and receipt["manifest_id"] in manifests
                and receipt["providers_used"] == 2 and set(receipt["provider_peer_ids"]) == {peers[n] for n in nodes}
                and len(receipt["provider_peer_ids"]) == 2
                and receipt["control_relay_peer_id"] == layout["control_relay_peer_id"]
                and all(receipt[key] is True for key in ("native_publisher_authenticated", "static_only", "local_delivery"))
                and all(receipt[key] is False for key in ("origin_authenticated", "https_origin_authenticated",
                    "globally_latest", "automatic_browser_open", "ownership_changed"))
                and "site_url" not in receipt, "site was not verified and fetched over both real providers")
    require(final["reason"] == "terminated" and final["private_spool_removed"] is True
            and ready["expires_unix_seconds"] == final["expires_unix_seconds"] <= publication["expires_unix_seconds"],
            "viewer renewed authority or failed SIGTERM")
    for key in ("consumer", "cli"):
        boundary = app[key]
        require(boundary["user_uid"] == isolation["user_uid"] == 985
                and boundary["user_gid"] == isolation["user_gid"]
                and boundary["control_gid"] == isolation["control_gid"]
                and all(boundary[flag] is True for flag in ("client_namespace", "outside_parent_namespace",
                    "all_capabilities_dropped", "no_new_privileges")), "site user process boundary missing")
    require(app["consumer"] == app["cli"] and 0 < app["elapsed_ns"] <= 120_000_000_000
            and all(app[key] is True for key in ("no_manifest_argument", "sigterm_cleanup", "listener_closed", "private_spool_removed"))
            and app["browser_engine_executed"] is False and app["spool_modes"] == "0700/0600",
            "site HTTP is not a bounded ordinary user operation")
    require(set(app["assets"]) == set(expected["assets"]), "site asset coverage incomplete")
    for path, value in app["assets"].items():
        require(value["status"] == 200 and value["security_headers_verified"] is True
                and all(value[key] == expected["assets"][path][key] for key in ("bytes", "sha256", "content_type"))
                and value["content_length"] == str(value["bytes"]), "HTTP asset hash/type/length changed")
    media = assets()["/media.bin"][1]
    require(app["head"]["status"] == 200 and app["head"]["bytes"] == 0
            and app["head"]["content_length"] == str(len(media))
            and app["head"]["security_headers_verified"] is True
            and app["byte_range"]["status"] == 206 and app["byte_range"]["bytes"] == 4096
            and app["byte_range"]["content_length"] == "4096"
            and app["byte_range"]["security_headers_verified"] is True
            and app["byte_range"]["sha256"] == hashlib.sha256(media[101:4197]).hexdigest()
            and app["byte_range"]["content_range"] == f"bytes 101-4196/{len(media)}"
            and app["rejected"] == dict(host=400, traversal=404), "HEAD, actual byte range or Host/path rejection failed")
    require(isolation["user_uid"] != isolation["agent_uid"]
            and isolation["control_gid"] != isolation["agent_gid"]
            and isolation["cache_modes"] == "0700"
            and all(isolation[key] is True for key in ("fresh_client_cache", "agent_mount_positive_control",
                "client_cannot_read_provider_caches", "agent_cannot_read_user_directory",
                "user_cannot_read_agent_caches", "publisher_process_exited_before_fetch"))
            and isolation["publisher_node_offline_claimed"] is False
            and evidence["publisher_cleanup"] == dict(publisher_files_removed=True, source_cache_removed=True, manifest_removed=True)
            and evidence["cleanup"] == dict(user_directory_removed=True), "site publisher/consumer isolation or cleanup absent")
    validate_path(evidence)


def build_evidence(work):
    evidence = {key: read(work / f"content-provider-site-{suffix}.json") for key, suffix in (
        ("input", "input"), ("pack", "pack"), ("publish", "publish"), ("application", "consumer"),
        ("isolation", "isolation"), ("publisher_cleanup", "publisher-cleanup"), ("cleanup", "cleanup"),
        ("selected_route", "selection"), ("control_privacy", "control"))}
    layout = read(work / "content-provider-layout.json")
    evidence.update(success=True, layout=layout, expected_peers=read(work / "a01-expected-peers.json"),
                    imports={node: read(work / f"content-provider-site-{node}-import.json") for node in layout["provider_nodes"]},
                    serves={node: read(work / f"content-provider-site-{node}-serve.json") for node in layout["provider_nodes"]},
                    privacy={role: read(work / f"content-provider-site-privacy-{role}.json") for role in ROLES})
    validate_evidence(evidence)
    return evidence


def main(arguments):
    operation, *arguments = arguments
    if operation == "init":
        result = initialize(Path(arguments[0]))
    elif operation == "publisher-cleanup":
        result = remove_publisher(Path(arguments[0]))
    elif operation == "consume":
        result = consume(arguments)
    elif operation == "user-cleanup":
        result = remove_user(Path(arguments[0]))
    elif operation == "evidence":
        result = build_evidence(Path(arguments[0]))
    else:
        raise ValueError("unknown native site proof operation")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        print(f"native site proof failed: {error}", file=sys.stderr)
        sys.exit(1)
