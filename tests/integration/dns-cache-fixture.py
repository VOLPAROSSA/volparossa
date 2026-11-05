#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded public DNS wire recording/replay; NOT a DNSSEC cryptographic validator.

The literal DoH URL supplies public data only. The production ExitResolver must
independently verify both families against its unchanged built-in root anchors.
Replay changes only the transaction ID and decreasing TTLs, never signed RDATA.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

SOURCE_URL = "https://dns.google/dns-query"
CANDIDATE = "iana.org"
QUESTIONS = ((CANDIDATE, 1), (CANDIDATE, 28), (CANDIDATE, 48),
             (CANDIDATE, 43), ("org", 48), ("org", 43), (".", 48))
MAX_WIRE = 4096
MAX_RECORDING = 128 * 1024
MAX_SECONDS = 120
MAX_COLLECTION_SECONDS = 120
MAX_COLLECTION_ROUNDS = 3
MIN_REPLAY_REMAINING_MS = 60_000
TYPE_NAMES = {1: "A", 28: "AAAA", 43: "DS", 48: "DNSKEY"}


class FixtureError(ValueError):
    """Only locally authored fixture diagnostics, never raw remote/parser text."""


def require(condition, reason):
    if not condition:
        raise FixtureError(reason)


def name_wire(name):
    if name == ".":
        return b"\0"
    labels = name.encode("ascii").split(b".")
    require(all(0 < len(label) <= 63 for label in labels), "invalid fixture name")
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\0"


def read_name(data, offset):
    labels, visited = [], set()
    next_offset = None
    for _ in range(128):
        require(0 <= offset < len(data) and offset not in visited, "DNS name bounds/cycle")
        visited.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            require(offset + 1 < len(data), "short DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            require(pointer < offset, "non-backward DNS pointer")
            if next_offset is None:
                next_offset = offset + 2
            offset = pointer
        elif length == 0:
            name = ".".join(labels) or "."
            require(len(name) <= 253, "long DNS name")
            return name, offset + 1 if next_offset is None else next_offset
        else:
            require(length <= 63 and offset + 1 + length <= len(data), "short DNS label")
            label = data[offset + 1:offset + 1 + length].decode("ascii")
            require(re.fullmatch(r"[A-Za-z0-9_-]+", label) is not None, "invalid DNS label")
            labels.append(label.lower())
            offset += length + 1
    raise FixtureError("DNS name depth")


def parse_question(data):
    require(12 <= len(data) <= MAX_WIRE, "DNS wire size")
    header = struct.unpack_from("!6H", data)
    require(header[2] == 1, "DNS question count")
    name, end = read_name(data, 12)
    require(end + 4 <= len(data), "short DNS question")
    kind, dns_class = struct.unpack_from("!HH", data, end)
    require(dns_class == 1 and (name, kind) in QUESTIONS, "question outside fixed fixture")
    return header, (name, kind), end + 4


def inspect_response(data, expected, now_ms):
    header, question, offset = parse_question(data)
    _, flags, _, answers, authority, additionals = header
    require(question == expected, "substituted DNS question")
    require(flags & 0x8000 and not flags & 0x7A0F, "DNS response status/opcode/truncation")
    require(1 <= answers <= 32 and authority == 0 and additionals <= 1, "DNS section bounds")
    ttl_offsets, signatures, addresses = [], [], []
    answer_count = 0
    for index in range(answers + additionals):
        owner, offset = read_name(data, offset)
        require(offset + 10 <= len(data), "short DNS record")
        kind, dns_class, ttl, length = struct.unpack_from("!HHIH", data, offset)
        ttl_offset = offset + 4
        begin, end = offset + 10, offset + 10 + length
        require(end <= len(data), "short DNS rdata")
        if index >= answers:
            # EDNS OPT is transport metadata, not an answer or authentication proof.
            require(owner == "." and kind == 41 and length <= 512, "unexpected additional")
        else:
            require(owner == question[0] and dns_class == 1 and ttl > 0, "DNS owner/class/TTL")
            ttl_offsets.append((ttl_offset, ttl))
            if kind == 46:
                require(length >= 19 and len(signatures) < 4, "RRSIG bounds")
                covered, algorithm, labels, original_ttl, expires, begins, key_tag = \
                    struct.unpack_from("!HBBIIIH", data, begin)
                signer, signature_offset = read_name(data, begin + 18)
                require(covered == question[1] and labels == (0 if owner == "." else len(owner.split("."))),
                        "RRSIG type/wildcard")
                require(signer == "." or owner == signer or owner.endswith("." + signer), "RRSIG signer scope")
                require(0 < end - signature_offset <= 1024 and original_ttl > 0, "RRSIG length/TTL")
                require(begins * 1000 <= now_ms < expires * 1000, "RRSIG outside real wall clock")
                signatures.append({"algorithm": algorithm, "key_tag": key_tag,
                                   "inception_unix_ms": begins * 1000,
                                   "expires_at_unix_ms": expires * 1000})
            else:
                require(kind == question[1], "unexpected record type/CNAME")
                answer_count += 1
                if kind in (1, 28):
                    require(length == (4 if kind == 1 else 16), "address length")
                    address = ipaddress.ip_address(data[begin:end])
                    require(address.is_global, "non-public positive answer")
                    addresses.append(str(address))
                elif kind == 48:
                    require(4 < length <= 1028 and data[begin + 2] == 3, "DNSKEY bounds")
                elif kind == 43:
                    require(4 < length <= 68, "DS bounds")
        offset = end
    require(offset == len(data) and answer_count > 0 and signatures, "incomplete signed answer")
    return {"ttl_offsets": ttl_offsets, "signatures": signatures,
            "addresses": sorted(set(addresses)),
            "minimum_ttl_seconds": min(ttl for _, ttl in ttl_offsets),
            "signature_expiry_unix_ms": min(sig["expires_at_unix_ms"] for sig in signatures)}


def query_wire(name, kind, query_id):
    # DO requests actual RRSIGs. CD avoids depending on the resolver's AD verdict.
    header = struct.pack("!6H", query_id, 0x0110, 1, 0, 0, 1)
    question = name_wire(name) + struct.pack("!HH", kind, 1)
    opt = b"\0" + struct.pack("!HHIH", 41, MAX_WIRE, 0x8000, 0)
    return header + question + opt


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise FixtureError("fixture DoH redirect refused")


def fetch_wire(question, remaining):
    query_id = secrets.randbelow(65536)
    encoded = base64.urlsafe_b64encode(query_wire(*question, query_id)).rstrip(b"=").decode("ascii")
    request = urllib.request.Request(SOURCE_URL + "?dns=" + encoded,
                                     headers={"Accept": "application/dns-message"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=min(10, remaining)) as response:
        require(response.status == 200 and response.headers.get_content_type() == "application/dns-message",
                "unexpected DoH response")
        data = response.read(MAX_WIRE + 1)
    require(12 <= len(data) <= MAX_WIRE and struct.unpack_from("!H", data)[0] == query_id, "DoH size/id")
    return data


def write_new(path, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    require(len(data) <= MAX_RECORDING, "fixture JSON bounds")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        output.write(data)


def read_bounded(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "fixture input not regular")
        raw = source.read(MAX_RECORDING + 1)
    require(len(raw) <= MAX_RECORDING, "fixture JSON size")
    return raw


def read_json(path):
    return json.loads(read_bounded(path))


def record_expiry(record):
    return min(record["received_at_unix_ms"] + record["minimum_ttl_seconds"] * 1000,
               record["signature_expiry_unix_ms"])


def collect(root):
    require(root.is_absolute() and not root.exists(), "recording must be a new absolute directory")
    deadline = time.monotonic() + MAX_COLLECTION_SECONDS
    collected = {}
    for attempt in range(MAX_COLLECTION_ROUNDS):
        for question in QUESTIONS:
            previous = collected.get(question)
            if previous and record_expiry(previous) - int(time.time() * 1000) >= MIN_REPLAY_REMAINING_MS:
                continue
            remaining = deadline - time.monotonic()
            require(remaining > 0, "fixture collection deadline")
            try:
                data = fetch_wire(question, remaining)
                received = int(time.time() * 1000)
                inspected = inspect_response(data, question, received)
            except FixtureError as error:
                # These are the fixed public test questions, not browsing or remote error text.
                raise FixtureError(f"collect {question[0]} {TYPE_NAMES[question[1]]}: {error}") from None
            collected[question] = {"name": question[0], "type": question[1], "wire_hex": data.hex(),
                        "sha256": hashlib.sha256(data).hexdigest(), "received_at_unix_ms": received,
                        "minimum_ttl_seconds": inspected["minimum_ttl_seconds"],
                        "signature_expiry_unix_ms": inspected["signature_expiry_unix_ms"]}
        now = int(time.time() * 1000)
        require(time.monotonic() <= deadline, "fixture collection deadline")
        records = [collected[question] for question in QUESTIONS]
        expires = min(map(record_expiry, records))
        if expires - now >= MIN_REPLAY_REMAINING_MS:
            break
        weakest = min(records, key=record_expiry)
        reason = ("insufficient original TTL for fixture: " + weakest["name"] + " "
                  + TYPE_NAMES[weakest["type"]] + f" remaining_ms={max(0, expires - now)}")
        require(attempt + 1 < MAX_COLLECTION_ROUNDS, reason)
        # A public recursive resolver can legitimately return a nearly expired cached RRset.
        # Wait for those original records to expire before re-fetching just the short-lived
        # fixed questions. Never edit/renew a recorded TTL, signature, receive time or anchor.
        stale = [record for record in records if record_expiry(record) - now < MIN_REPLAY_REMAINING_MS]
        delay = max(0, max(map(record_expiry, stale)) - now) / 1000 + 0.05
        require(delay < deadline - time.monotonic(), reason)
        wake = time.monotonic() + delay
        while time.monotonic() < wake:
            time.sleep(max(0, min(1, wake - time.monotonic())))
    root.mkdir(mode=0o700)
    write_new(root / "recording.json", {"schema_version": 1, "source_url": SOURCE_URL,
              "candidate_name": CANDIDATE, "validation": "shape-and-time-only",
              "expires_at_unix_ms": expires, "records": records})
    for kind, label in ((1, "a"), (28, "aaaa")):
        chosen = [record for record in records if record["type"] not in (1, 28) or record["type"] == kind]
        write_new(root / (label + "-proof.json"), {"question": {"name": CANDIDATE, "type": TYPE_NAMES[kind]},
                  "messages": [record["wire_hex"] for record in chosen], "expires_at_unix_ms": expires})
    print(json.dumps({"recorded": True, "cryptographically_verified": False,
                      "records": len(records), "expires_at_unix_ms": expires}))


def load_recording(root, now_ms):
    index = read_json(root / "recording.json")
    require(index.get("schema_version") == 1 and index.get("source_url") == SOURCE_URL
            and index.get("candidate_name") == CANDIDATE
            and index.get("validation") == "shape-and-time-only", "recording provenance")
    records = index.get("records")
    require(isinstance(records, list) and len(records) == len(QUESTIONS), "recording count")
    result = {}
    earliest_expiry = 2**64 - 1
    for record in records:
        question = record["name"], record["type"]
        require(question in QUESTIONS and question not in result, "recording duplicate/question")
        require(isinstance(record["wire_hex"], str) and len(record["wire_hex"]) <= MAX_WIRE * 2,
                "recording wire size")
        data = bytes.fromhex(record["wire_hex"])
        require(hashlib.sha256(data).hexdigest() == record["sha256"], "recording hash")
        received = record["received_at_unix_ms"]
        require(type(received) is int and received <= now_ms, "recording future receive time")
        inspected = inspect_response(data, question, now_ms)
        require(record["minimum_ttl_seconds"] == inspected["minimum_ttl_seconds"]
                and record["signature_expiry_unix_ms"] == inspected["signature_expiry_unix_ms"],
                "recording summary mismatch")
        expiry = min(received + inspected["minimum_ttl_seconds"] * 1000,
                     inspected["signature_expiry_unix_ms"])
        earliest_expiry = min(earliest_expiry, expiry)
        require(expiry > now_ms, "recording expired")
        result[question] = (data, received, inspected)
    require(index["expires_at_unix_ms"] == earliest_expiry and set(result) == set(QUESTIONS),
            "recording expiry/coverage")
    return result


def replay_response(request, records, now_ms, elapsed_ms=0):
    header, question, _ = parse_question(request)
    require(not header[1] & 0xFA0F and header[3:5] == (0, 0) and header[5] <= 1,
            "unsupported fixture request")
    data, received, inspected = records[question]
    age_seconds = math.ceil(max(now_ms - received, elapsed_ms) / 1000)
    require(now_ms < inspected["signature_expiry_unix_ms"], "signature expired during replay")
    response = bytearray(data)
    struct.pack_into("!H", response, 0, header[0])
    # A fixture never offers AD as a substitute for independent root validation.
    struct.pack_into("!H", response, 2, struct.unpack_from("!H", response, 2)[0] & ~0x0020)
    for offset, original_ttl in inspected["ttl_offsets"]:
        require(original_ttl > age_seconds, "TTL expired during replay")
        struct.pack_into("!I", response, offset, original_ttl - age_seconds)
    return bytes(response), question


def require_isolated():
    parent = os.environ.get("VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS", "")
    require(re.fullmatch(r"net:\[[0-9]+\]", parent) is not None
            and os.readlink("/proc/self/ns/net") != parent, "explicit isolated netns required")


def recv_exact(connection, length):
    require(0 < length <= MAX_WIRE, "TCP DNS frame bound")
    data = bytearray()
    while len(data) < length:
        part = connection.recv(length - len(data))
        require(part, "short TCP DNS frame")
        data.extend(part)
    return bytes(data)


def serve(root, listen, report, ready, maximum_seconds):
    require_isolated()
    require(root.is_absolute() and report.is_absolute() and ready.is_absolute(), "absolute fixture paths required")
    host, port_text = listen.rsplit(":", 1)
    require(host in ("127.0.0.1", "47.163.4.2", "52.168.8.2"), "fixture listener address")
    port = int(port_text)
    require(0 < port <= 65535 and (host == "127.0.0.1" or port == 53), "fixture listener port")
    require(1 <= maximum_seconds <= MAX_SECONDS and not report.exists() and not ready.exists(),
            "fixture output/deadline")
    loaded_at_ms, started = int(time.time() * 1000), time.monotonic()
    records = load_recording(root, loaded_at_ms)
    counts = {name + ":" + TYPE_NAMES[kind]: 0 for name, kind in QUESTIONS}
    stopped, failures, connections = [False], 0, 0
    signal.signal(signal.SIGTERM, lambda *_: stopped.__setitem__(0, True))
    signal.signal(signal.SIGINT, lambda *_: stopped.__setitem__(0, True))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        # Consecutive bounded fixture phases reopen this exact isolated endpoint;
        # previous accepted TCP sockets may still be in TIME_WAIT. Never share a live listener.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(8)
        listener.settimeout(0.1)
        write_new(ready, {"ready": True, "listen": {"ip": host, "port": port}, "pid": os.getpid()})
        while not stopped[0] and time.monotonic() - started < maximum_seconds and connections < 128:
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            connections += 1
            try:
                with connection:
                    connection.settimeout(min(2, max(0.01, maximum_seconds - (time.monotonic() - started))))
                    length = struct.unpack("!H", recv_exact(connection, 2))[0]
                    request = recv_exact(connection, length)
                    monotone_now = loaded_at_ms + int((time.monotonic() - started) * 1000)
                    response, question = replay_response(request, records, max(int(time.time() * 1000), monotone_now))
                    connection.sendall(struct.pack("!H", len(response)) + response)
                    counts[question[0] + ":" + TYPE_NAMES[question[1]]] += 1
            except (OSError, ValueError, struct.error):
                failures += 1
    write_new(report, {"schema_version": 1, "listener_closed": True,
              "cryptographically_verified": False, "connections": connections,
              "responses": counts, "rejected": failures, "bounded_stop": True})


def validate_core(root, output):
    """Require the independently executed Rust core result, never infer crypto from AD."""
    records = load_recording(root, int(time.time() * 1000))
    with os.fdopen(os.open(output / "core.jsonl", os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "core evidence not regular")
        data = source.read(16385)
    require(len(data) <= 16384, "core evidence size")
    answers = [json.loads(line) for line in data.splitlines()]
    require(len(answers) == 2 and {answer["family"] for answer in answers} == {"A", "AAAA"},
            "both genuine core families required")
    for answer in answers:
        require(answer["schema"] == 1 and answer["source"] == "UpstreamValidated"
                and answer["local_reuse"] is True and answer["builtin_anchors"] is True,
                "genuine root validation/local reuse absent")
        kind = 1 if answer["family"] == "A" else 28
        _, received, expected = records[(CANDIDATE, kind)]
        answer_expiry = min(received + expected["minimum_ttl_seconds"] * 1000,
                            expected["signature_expiry_unix_ms"])
        require(sorted(answer["addresses"]) == expected["addresses"] and answer["ttl_seconds"] > 0
                and int(time.time() * 1000) < answer["expires_at_ms"] <= answer_expiry
                and re.fullmatch(r"[0-9a-f]{64}", answer["proof_sha256"]), "core result binding")
    replay = read_json(output / "replay.json")
    require(replay.get("listener_closed") is True and replay.get("bounded_stop") is True
            and replay.get("rejected") == 0 and 2 <= replay.get("connections", 0) <= 128,
            "replay completion")
    counts = replay["responses"]
    require(set(counts) == {name + ":" + TYPE_NAMES[kind] for name, kind in QUESTIONS}
            and counts[CANDIDATE + ":A"] == 1 and counts[CANDIDATE + ":AAAA"] == 1,
            "local reuse issued a second address query")
    write_new(output / "proof.json", {"schema_version": 1, "success": True,
              "scope": "builtin-anchor-collector-and-local-cache-only",
              "peer_cache_proven": False, "normal_client_route_proven": False,
              "candidate_name": CANDIDATE, "source_url": SOURCE_URL,
              "recording_sha256": hashlib.sha256(read_bounded(root / "recording.json")).hexdigest(),
              "core": answers, "replay": replay})


# Recovery is a separate, explicitly selected fixture protocol. No production
# endpoint/command is accepted over this private channel, and no query is sent on it.
RECOVERY_FRAMES = (b"DNS_CACHE_RECOVERY_V1 WARM_READY\n",
                   b"DNS_CACHE_RECOVERY_V1 OUTAGE_CHECKED\n",
                   b"DNS_CACHE_RECOVERY_V1 PROBE_COMPLETE\n")
RECOVERY_ACKS = (b"DNS_CACHE_RECOVERY_V1 UPSTREAM_DOWN\n",
                 b"DNS_CACHE_RECOVERY_V1 UPSTREAM_RESTORED\n")
COUNT_KEYS = {"local_validated", "peer_validated", "upstream_validated", "trusted_fallback"}
RECOVERY_COUNTS = {
    "warm_counts": dict(local_validated=2, peer_validated=0, upstream_validated=2, trusted_fallback=0),
    "cold_outage_counts": dict.fromkeys(COUNT_KEYS, 0),
    "recovered_counts": dict(local_validated=0, peer_validated=0, upstream_validated=2, trusted_fallback=0),
}


def remaining(deadline):
    seconds = deadline - time.monotonic()
    require(seconds > 0, "recovery total deadline")
    return seconds


def receive_phase(connection, expected, deadline):
    """Exactly one finite frame; timeout/EOF/order are fatal, never inferred success."""
    frame = bytearray()
    for _ in range(128):
        connection.settimeout(remaining(deadline))
        byte = connection.recv(1)
        require(byte, "recovery phase EOF")
        frame.extend(byte)
        if byte == b"\n":
            require(bytes(frame) == expected, "recovery phase mismatch")
            return
    raise FixtureError("recovery phase frame bound")


def send_phase(connection, frame, deadline):
    require(frame in RECOVERY_ACKS, "recovery acknowledgement outside protocol")
    connection.settimeout(remaining(deadline))
    connection.sendall(frame)


def join_child(child, deadline, *, stop=False):
    """Only owned Popen handles; signal before reap, never reuse a numeric PID."""
    if stop and child.poll() is None:
        child.terminate()
    try:
        return child.wait(timeout=min(0.5, remaining(deadline)))
    except (subprocess.TimeoutExpired, FixtureError):
        if child.poll() is None:
            child.kill()
        return child.wait(timeout=max(0, deadline - time.monotonic()))


def wait_ready(path, child, deadline):
    while not path.exists():
        require(child.poll() is None, "recovery replay exited before ready")
        time.sleep(min(0.02, remaining(deadline)))
    ready = read_json(path)
    require(ready == {"ready": True, "listen": {"ip": "127.0.0.1", "port": 1053}, "pid": child.pid}
            and child.poll() is None, "recovery replay readiness binding")


def accept_probe(listener, probe, deadline):
    while True:
        require(probe.poll() is None, "recovery probe exited before handshake")
        listener.settimeout(min(0.05, remaining(deadline)))
        try:
            return listener.accept()[0]
        except socket.timeout:
            continue


def validate_replay(report):
    replay = read_json(report)
    require(set(replay) == {"schema_version", "listener_closed", "cryptographically_verified",
                           "connections", "responses", "rejected", "bounded_stop"}
            and type(replay["schema_version"]) is int and replay["schema_version"] == 1
            and replay["listener_closed"] is True and replay["bounded_stop"] is True
            and replay["cryptographically_verified"] is False
            and type(replay["rejected"]) is int and replay["rejected"] == 0
            and type(replay["connections"]) is int and 2 <= replay["connections"] <= 128,
            "recovery replay completion")
    counts = replay["responses"]
    require(isinstance(counts, dict)
            and set(counts) == {name + ":" + TYPE_NAMES[kind] for name, kind in QUESTIONS}
            and all(type(value) is int and 0 < value <= 128 for value in counts.values())
            and sum(counts.values()) == replay["connections"]
            and counts[CANDIDATE + ":A"] == 1 and counts[CANDIDATE + ":AAAA"] == 1,
            "recovery replay question accounting")
    return replay


def validate_recovery(root, output, children, recording_hash):
    """Called only after successful phase transitions and all three child joins.

    This gate binds actual Rust source/TTL/proof/address observations to the same
    original public recording. It does not turn shape checks into crypto proof.
    """
    require(isinstance(children, dict)
            and set(children) == {"probe_joined", "first_replay_joined", "second_replay_joined", "listeners_closed"}
            and all(value is True for value in children.values()), "recovery child cleanup")
    records = load_recording(root, int(time.time() * 1000))
    require(hashlib.sha256(read_bounded(root / "recording.json")).hexdigest() == recording_hash,
            "recovery recording changed")
    rows = [json.loads(line) for line in read_bounded(output / "core.jsonl").splitlines()]
    require(len(rows) == 3, "recovery core row count")
    answers, accounting = rows[:2], rows[2]
    require(all(isinstance(answer, dict) for answer in answers)
            and {answer.get("family") for answer in answers} == {"A", "AAAA"}, "recovery family coverage")
    for answer in answers:
        require(set(answer) == {"schema", "family", "builtin_anchors", "cold_outage_error", "warm", "outage", "recovered"}
                and type(answer["schema"]) is int and answer["schema"] == 2
                and answer["builtin_anchors"] is True and answer["cold_outage_error"] is True,
                "recovery core validation absent")
        _, received, expected = records[(CANDIDATE, 1 if answer["family"] == "A" else 28)]
        # Bind every retained proof to its six original signed RRsets, not just
        # the positive address TTL. The other address family is not in this proof.
        kind = 1 if answer["family"] == "A" else 28
        expiry = min(min(stamp + inspected["minimum_ttl_seconds"] * 1000,
                         inspected["signature_expiry_unix_ms"])
                     for (_, rrtype), (_, stamp, inspected) in records.items()
                     if rrtype not in (1, 28) or rrtype == kind)
        for phase, source in (("warm", "UpstreamValidated"), ("outage", "LocalValidated"),
                              ("recovered", "UpstreamValidated")):
            observed = answer[phase]
            require(isinstance(observed, dict) and set(observed) == {
                "source", "ttl_seconds", "expires_at_ms", "proof_sha256", "addresses"}, "recovery observation shape")
            require(observed["source"] == source and type(observed["ttl_seconds"]) is int
                    and 0 < observed["ttl_seconds"] <= expected["minimum_ttl_seconds"]
                    and type(observed["expires_at_ms"]) is int
                    and int(time.time() * 1000) < observed["expires_at_ms"] <= expiry
                    and isinstance(observed["proof_sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", observed["proof_sha256"]) is not None
                    and isinstance(observed["addresses"], list)
                    and all(isinstance(address, str) for address in observed["addresses"])
                    and sorted(observed["addresses"]) == expected["addresses"], "recovery observation binding")
        require(answer["outage"]["ttl_seconds"] <= answer["warm"]["ttl_seconds"]
                and answer["recovered"]["ttl_seconds"] <= answer["warm"]["ttl_seconds"], "recovery TTL renewed")
    require(isinstance(accounting, dict) and set(accounting) == {"schema", "accounting"}
            and type(accounting["schema"]) is int and accounting["schema"] == 2
            and isinstance(accounting["accounting"], dict)
            and set(accounting["accounting"]) == set(RECOVERY_COUNTS), "recovery accounting shape")
    for phase, expected in RECOVERY_COUNTS.items():
        counts = accounting["accounting"][phase]
        require(isinstance(counts, dict) and set(counts) == COUNT_KEYS
                and all(type(value) is int for value in counts.values()) and counts == expected,
                "recovery source accounting")
    replays = {phase: validate_replay(output / (phase + "-replay.json")) for phase in ("first", "second")}
    write_new(output / "proof.json", {
        "schema_version": 2, "success": True,
        "scope": "builtin-anchor-collector-and-local-cache-only",
        "peer_cache_proven": False, "normal_client_route_proven": False, "natural_expiry_proven": False,
        "candidate_name": CANDIDATE, "source_url": SOURCE_URL, "recording_sha256": recording_hash,
        "core": answers, "replay": replays,
        "recovery": dict(warm_upstream_validated=True, upstream_stopped_before_outage=True,
                         outage_local_validated=True, cold_outage_failed_closed=True,
                         same_cold_resolver_recovered=True, same_recording_replayed=True,
                         **accounting["accounting"], children=children, phase_count=3)})


def exercise_recovery(root, binary, output):
    """Own all test children; one original budget, no renewed TTL or fixture fetch.

    SIGINT/TERM and every failure enter the same bounded join path. The namespace
    timeout remains the outer containment backstop, not a cleanup-success claim.
    """
    require_isolated()
    started = time.monotonic()
    deadline, cleanup_deadline = started + 35, started + 39
    require(root.is_absolute() and binary.is_absolute() and output.is_absolute(), "absolute recovery paths required")
    metadata = output.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == os.getuid(), "private recovery output required")
    for entry in output.iterdir():
        info = entry.lstat()
        require(entry.name in {"namespace.stdout", "namespace.stderr"} and stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
                and info.st_nlink == 1, "fresh recovery output required")
    metadata = binary.lstat()
    require(stat.S_ISREG(metadata.st_mode) and os.access(binary, os.X_OK), "recovery probe executable required")
    load_recording(root, int(time.time() * 1000))
    recording_hash = hashlib.sha256(read_bounded(root / "recording.json")).hexdigest()
    socket_path = output / "phase.sock"
    require(len(os.fsencode(socket_path)) < 104 and not socket_path.exists(), "recovery socket path bound")
    children, handles, joined = [], [], set()
    previous = {kind: signal.getsignal(kind) for kind in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    def cancel(*_):
        raise FixtureError("recovery interrupted")
    for kind in previous:
        signal.signal(kind, cancel)
    listener, connection = None, None
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        def spawn(argv, label):
            stdout = open(output / (label + ".stdout"), "xb")
            handles.append(stdout)
            stderr = open(output / (label + ".stderr"), "xb")
            handles.append(stderr)
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True)
            children.append(child)
            return child
        def replay(phase):
            require(hashlib.sha256(read_bounded(root / "recording.json")).hexdigest() == recording_hash,
                    "recovery recording changed")
            child = spawn([sys.executable, "-B", str(Path(__file__).resolve()), "serve", str(root),
                           "127.0.0.1:1053", str(output / (phase + "-replay.json")),
                           str(output / (phase + "-ready.json")), "--max-seconds", "30"], phase)
            wait_ready(output / (phase + "-ready.json"), child, deadline)
            return child
        first = replay("first")
        # Probe stdout is exactly three finite typed rows, never private query data.
        core = open(output / "core.jsonl", "xb")
        handles.append(core)
        error = open(output / "core.stderr", "xb")
        handles.append(error)
        probe = subprocess.Popen([str(binary), "--cache-recovery", "127.0.0.1:1053", CANDIDATE,
                                  str(socket_path), str(os.getpid())], stdin=subprocess.DEVNULL,
                                 stdout=core, stderr=error, close_fds=True)
        children.append(probe)
        connection = accept_probe(listener, probe, deadline)
        pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid == probe.pid and uid == os.getuid(), "recovery probe identity")
        for index, frame in enumerate(RECOVERY_FRAMES):
            receive_phase(connection, frame, deadline)
            if index == 0:
                require(join_child(first, deadline, stop=True) == 0, "first replay did not stop cleanly")
                joined.add(first)
                validate_replay(output / "first-replay.json")
                send_phase(connection, RECOVERY_ACKS[0], deadline)
            elif index == 1:
                second = replay("second")
                send_phase(connection, RECOVERY_ACKS[1], deadline)
        connection.settimeout(remaining(deadline))
        require(connection.recv(1) == b"", "recovery phase trailing bytes")
        require(probe.wait(timeout=remaining(deadline)) == 0, "recovery probe failed")
        joined.add(probe)
        require(join_child(second, deadline, stop=True) == 0, "second replay did not stop cleanly")
        joined.add(second)
        validate_replay(output / "second-replay.json")
        connection.close()
        connection = None
        listener.close()
        listener = None
        socket_path.unlink()
        for handle in handles:
            handle.close()
        remaining(deadline)
    finally:
        primary = sys.exc_info()[0] is not None
        # Repeated cancellation cannot interrupt the mandatory bounded reap attempt.
        for kind in previous:
            signal.signal(kind, signal.SIG_IGN)
        cleanup_ok = True
        for child in children:
            if child in joined:
                continue
            try:
                join_child(child, cleanup_deadline, stop=True)
                joined.add(child)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                cleanup_ok = False
        for resource in (connection, listener, *handles):
            if resource is not None:
                try:
                    resource.close()
                except OSError:
                    cleanup_ok = False
        if len(joined) == len(children):
            try:
                socket_path.unlink(missing_ok=True)
            except OSError:
                cleanup_ok = False
        for kind, handler in previous.items():
            signal.signal(kind, handler)
        if not primary:
            require(cleanup_ok, "recovery cleanup unconfirmed")
    remaining(deadline)
    validate_recovery(root, output, dict(probe_joined=True, first_replay_joined=True,
                                        second_replay_joined=True, listeners_closed=True), recording_hash)


def failure_summary(error):
    summary = "DNS fixture failed: " + type(error).__name__
    if isinstance(error, FixtureError):
        summary += ": " + str(error)
    elif isinstance(error, urllib.error.HTTPError):
        summary += ": status " + str(error.code)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("root", type=Path)
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("root", type=Path)
    serve_parser.add_argument("listen")
    serve_parser.add_argument("report", type=Path)
    serve_parser.add_argument("ready", type=Path)
    serve_parser.add_argument("--max-seconds", type=int, default=60)
    validate_parser = sub.add_parser("validate-core")
    validate_parser.add_argument("root", type=Path)
    validate_parser.add_argument("output", type=Path)
    recovery_parser = sub.add_parser("exercise-recovery")
    recovery_parser.add_argument("root", type=Path)
    recovery_parser.add_argument("binary", type=Path)
    recovery_parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.mode == "collect":
        collect(args.root)
    elif args.mode == "serve":
        serve(args.root, args.listen, args.report, args.ready, args.max_seconds)
    elif args.mode == "validate-core":
        validate_core(args.root, args.output)
    else:
        exercise_recovery(args.root, args.binary, args.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, struct.error, urllib.error.URLError, subprocess.SubprocessError) as error:
        raise SystemExit(failure_summary(error)) from None
