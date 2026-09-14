#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Ordinary explicit publication, configured-cache restart and independent native name fetch.

Reuses the static-site bytes and existing process boundary; this is not a browser-engine test.
"""

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

SITE = runpy.run_path(str(Path(__file__).with_name("content-provider-site-smoke.py")))
require, read = SITE["require"], SITE["read"]
BYTES, SHA = SITE["BUNDLE_BYTES"], SITE["BUNDLE_SHA256"]


def chunks(path):
    owner = path.lstat()
    require(stat.S_ISDIR(owner.st_mode) and stat.S_IMODE(owner.st_mode) == 0o700, "unsafe owned cache")
    entries = list(path.iterdir())
    require(len(entries) <= 260, "cache snapshot exceeds configured bound")
    result = {}
    for entry in entries:
        metadata = entry.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and (metadata.st_uid, metadata.st_gid) == (owner.st_uid, owner.st_gid), "unsafe cache entry")
        if re.fullmatch(r"[0-9a-f]{64}", entry.name):
            require(0 < metadata.st_size <= 262144, "oversized chunk")
            require(hashlib.sha256(entry.read_bytes()).hexdigest() == entry.name, "wrong cached chunk hash")
            result[entry.name] = metadata.st_size
        else:
            require(entry.name in {".volparossa-owner-v1", ".volparossa-index-v1", ".volparossa-replicas-v1"},
                    "unknown cache metadata or unfinished writer")
    require(sum(result.values()) <= 67108864, "cache exceeds configured byte bound")
    return result


def snapshot(path):
    require(path.name == "automatic-replicas" and path.parts[-3:-1] == ("state-relay4", "content"),
            "not the configured disposable R4 cache")
    cached = chunks(path)
    require(not list(path.parent.glob(".volparossa-publication-*")), "publication staging survives final admission")
    owner = path.lstat()
    journal = path / ".volparossa-replicas-v1"
    require(0 < journal.stat().st_size <= 8 * 1024 * 1024, "missing or oversized replica journal")
    return dict(device=owner.st_dev, inode=owner.st_ino, uid=owner.st_uid, gid=owner.st_gid,
                mode=stat.S_IMODE(owner.st_mode), journal_sha256=hashlib.sha256(journal.read_bytes()).hexdigest(),
                journal_bytes=journal.stat().st_size, chunks=cached, staging_absent=True)


def publication_input(path):
    require(path.name == "site-publisher", "wrong publisher root")
    SITE["private"](path, True)
    bundle, manifest = path / "bundle.bin", path / "manifest.bin"
    require(SITE["private"](bundle).st_size == BYTES and SITE["private"](manifest).st_size <= 65536,
            "unexpected site bundle or manifest size")
    require(hashlib.sha256(bundle.read_bytes()).hexdigest() == SHA, "not the canonical static-site bundle")
    source = chunks(path / "source-cache")
    require(len(source) == 9 and sum(source.values()) == BYTES, "site has missing or duplicate source chunks")
    return dict(name=SITE["NAME"], content_type=SITE["CONTENT_TYPE"], assets=SITE["inventory"](),
                bytes=BYTES, sha256=SHA, manifest_id=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                source_chunks=source, source_cache=str(path / "source-cache"))


def remove_user(path):
    require(path.name == "site-viewer" and not path.is_symlink(), "unexpected consumer root")
    if path.exists():
        SITE["private"](path, True)
        entries = list(path.iterdir())
        require(len(entries) <= 3, "unexpected consumer entries")
        total = 0
        for entry in entries:
            metadata = entry.lstat()
            mode = 0o400 if entry.name == "expected.json" else 0o600
            require(entry.name in {"expected.json", "received.bin"} or re.fullmatch(r"\.tmp[A-Za-z0-9]{6}", entry.name),
                    "unknown consumer file; no broad cleanup")
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    and stat.S_IMODE(metadata.st_mode) == mode
                    and (metadata.st_uid, metadata.st_gid) == (os.getuid(), os.getgid()), "unsafe consumer file")
            total += metadata.st_size
        require(total <= 2 * BYTES + 65536, "consumer cleanup exceeded exact output/partial bound")
        for entry in entries:
            entry.unlink()
        path.rmdir()
    return dict(user_directory_removed=True)


def consume(arguments):
    binary, control, cache, directory, parent, namespace, uid, gid, group = arguments
    uid, gid, group = int(uid), int(gid), int(group)
    directory = Path(directory)
    boundary = SITE["HTTPS"]["process_boundary"]("self", parent, namespace, uid, gid, group)
    SITE["private"](directory, True)
    require({entry.name for entry in directory.iterdir()} == {"expected.json"}, "consumer directory is not fresh")
    expected = read(directory / "expected.json")
    output = directory / "received.bin"
    command = [binary, "--control-socket", control, "content", "fetch-name",
               "--publisher-key", expected["publisher_key"], "--name", SITE["NAME"], "--min-revision", "1",
               "--cache", cache, "--local-output", str(output), "--min-free-bytes", "0"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=0,
                               env=dict(os.environ, TMPDIR=str(directory)))
    previous = {}
    def interrupted(_signal, _frame):
        raise ValueError("publication consumer interrupted")
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, interrupted)
        cli = SITE["HTTPS"]["process_boundary"](process.pid, parent, namespace, uid, gid, group)
        final = SITE["HTTPS"]["bounded_json_line"](process.stdout, time.monotonic() + 110)
        require(process.wait(timeout=5) == 0 and process.stdout.read(1) == b"", "named CLI failed or had trailing output")
        metadata = SITE["private"](output)
        require(metadata.st_size == BYTES and hashlib.sha256(output.read_bytes()).hexdigest() == SHA,
                "independent output is not the complete original site bundle")
        require(final["manifest_id"] == expected["manifest_id"]
                and final["publication_expires_unix_seconds"] == expected["expires_unix_seconds"],
                "named fetch substituted or renewed the original publication")
        return dict(final=final, consumer=boundary, cli=cli, bytes=metadata.st_size, sha256=SHA,
                    output_mode="0600", no_manifest_argument=True, browser_engine_executed=False)
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


def validate_evidence(value, automatic, peers):
    original, published = value["input"], value["publish"]
    require(original["name"] == SITE["NAME"] and original["content_type"] == SITE["CONTENT_TYPE"]
            and original["assets"] == SITE["inventory"]() and original["bytes"] == published["bytes"] == BYTES
            and original["sha256"] == SHA and len(original["source_chunks"]) == 9
            and sum(original["source_chunks"].values()) == BYTES
            and all(re.fullmatch(r"[0-9a-f]{64}", key) and 0 < size <= 262144 for key, size in original["source_chunks"].items())
            and value["pack"]["operation"] == "site_pack" and value["pack"]["assets"] == 4
            and value["pack"]["bytes"] == BYTES and value["pack"]["content_type"] == SITE["CONTENT_TYPE"]
            and value["pack"]["network_published"] is False, "normal static-site pack/source mismatch")
    require(published["operation"] == "content_publish" and published["network_publication"] is True
            and published["serving"] is True and published["publications"] == 2 and published["chunks"] == 9
            and published["manifest_id"] == original["manifest_id"]
            and re.fullmatch(r"[0-9a-f]{64}", published["manifest_id"])
            and re.fullmatch(r"[0-9a-f]{64}", published["publisher_key_hex"])
            and published["cache"] == original["source_cache"]
            and all(published[key] is False for key in ("private_keys_transferred", "ownership_changed", "origin_authenticated")),
            "explicit complete configured-service publication was not acknowledged")
    initial, before, after = (value[name] for name in ("cache_initial", "cache_before", "cache_after"))
    for field in ("device", "inode", "uid", "gid", "mode"):
        require(initial[field] == before[field] == after[field] == automatic["cache_after"][field], "configured cache replaced")
    require(initial["mode"] == 0o700 and initial["uid"] > 0 and initial["inode"] > 0
            and initial["staging_absent"] is True and before["staging_absent"] is True
            and initial["journal_sha256"] == automatic["cache_after"]["journal_sha256"]
            and len(initial["chunks"]) == 3 and sum(initial["chunks"].values()) == 524609
            and not set(initial["chunks"]).intersection(original["source_chunks"])
            and before == after and before["chunks"] == dict(initial["chunks"], **original["source_chunks"])
            and before["journal_bytes"] > 0 and re.fullmatch(r"[0-9a-f]{64}", before["journal_sha256"])
            and before["journal_sha256"] != initial["journal_sha256"], "complete durable publication or original P lost at restart")
    for name, count, size, chunks_count in (("before", 1, 524609, 3), ("after", 2, 524609 + BYTES, 12),
                                           ("restored", 2, 524609 + BYTES, 12)):
        status = value[name]
        require(status["serving"] is True and status["replication_enabled"] is True
                and status["publications"] == status["replica_publications"] == count
                and status["replica_bytes"] == size and status["replica_chunks"] == chunks_count,
                "actual configured complete registry/status missing")
    prior = automatic["restart"]
    for name in ("startup", "restart"):
        current = value[name]
        require(current["unit"] == prior["unit"] == "volparossa-alpha-agent@relay4.service"
                and current["active_state"] == "active" and current["executable_verified"] is True
                and current["pid_before"] == prior["pid_after"] > 0
                and current["pid_after"] > 0 and current["pid_after"] != current["pid_before"]
                and current["network_namespace_identity"] == prior["network_namespace_identity"], "wrong actual restart lineage")
        prior = current
    app, isolation = value["application"], value["isolation"]
    final = app["final"]
    require(final["operation"] == "named_content_download" and final["publisher_key"] == published["publisher_key_hex"]
            and final["name"] == SITE["NAME"] and final["revision"] == 1
            and final["manifest_id"] == published["manifest_id"]
            and final["publication_expires_unix_seconds"] == published["expires_unix_seconds"] > 0
            and final["sha256"] == app["sha256"] == SHA and final["bytes"] == app["bytes"] == BYTES
            and final["cache_only"] is False and final["globally_latest"] is False
            and app["no_manifest_argument"] is True and app["browser_engine_executed"] is False
            and app["output_mode"] == "0600", "independent named output did not retain original signature/expiry")
    for boundary in (app["consumer"], app["cli"]):
        require(boundary["user_uid"] == isolation["user_uid"] == 985
                and boundary["user_gid"] == isolation["user_gid"] and boundary["control_gid"] == isolation["control_gid"]
                and all(boundary[key] is True for key in ("client_namespace", "outside_parent_namespace",
                    "all_capabilities_dropped", "no_new_privileges")), "consumer not the ordinary isolated user")
    require(isolation["agent_uid"] == initial["uid"] != isolation["user_uid"]
            and isolation["agent_gid"] == initial["gid"] != isolation["control_gid"]
            and all(isolation[key] is True for key in ("fresh_client_cache", "agent_mount_positive_control",
                "client_cannot_read_provider_cache", "agent_cannot_read_user_source", "user_cannot_read_agent_cache",
                "publisher_process_exited_before_fetch")) and isolation["publisher_node_offline_claimed"] is False
            and value["publisher_cleanup"] == dict(publisher_files_removed=True, source_cache_removed=True, manifest_removed=True)
            and value["cleanup"] == dict(user_directory_removed=True)
            and value["stop"]["serving"] is False and value["stop"]["publications"] == 0,
            "publisher removal, UID isolation or final service cleanup missing")


def build_evidence(work):
    fields = ("input", "pack", "publish", "before", "after", "restored", "cache-initial", "cache-before",
              "cache-after", "publisher-cleanup", "cleanup", "application", "isolation", "stop")
    value = {name.replace("-", "_"): read(work / f"content-replication-publication-{name}.json") for name in fields}
    for name in ("startup", "restart"):
        value[name] = read(work / f"content-replication-automatic-publication-{name}.json")
    prefix = "content-replication-publication-fetch"
    value["phase"] = dict(layout=read(work / f"{prefix}-layout.json"),
        route=read(work / "content-replication-publication-final-live-selection.json"),
        captures={role: read(work / f"{prefix}-{role}.json") for role in ("receiver", "relay-a", "relay-b", "exit", "provider")})
    return value


if __name__ == "__main__":
    try:
        operation, *arguments = sys.argv[1:]
        if operation == "init": result = SITE["initialize"](Path(arguments[0]))
        elif operation == "publisher-cleanup": result = SITE["remove_publisher"](Path(arguments[0]))
        elif operation == "user-cleanup": result = remove_user(Path(arguments[0]))
        elif operation == "input": result = publication_input(Path(arguments[0]))
        elif operation == "cache": result = snapshot(Path(arguments[0]))
        elif operation == "consume": result = consume(arguments)
        else: raise ValueError("unknown public contribution proof operation")
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        print(f"public contribution proof failed: {error}", file=sys.stderr)
        sys.exit(1)
