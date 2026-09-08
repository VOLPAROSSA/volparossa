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


def collect(root):
    require(root.is_absolute() and not root.exists(), "recording must be a new absolute directory")
    deadline = time.monotonic() + 60
    records = []
    for question in QUESTIONS:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "fixture collection deadline")
        try:
            data = fetch_wire(question, remaining)
            received = int(time.time() * 1000)
            inspected = inspect_response(data, question, received)
        except FixtureError as error:
            # These are the fixed public test questions, not browsing or remote error text.
            raise FixtureError(f"collect {question[0]} {TYPE_NAMES[question[1]]}: {error}") from None
        records.append({"name": question[0], "type": question[1], "wire_hex": data.hex(),
                        "sha256": hashlib.sha256(data).hexdigest(), "received_at_unix_ms": received,
                        "minimum_ttl_seconds": inspected["minimum_ttl_seconds"],
                        "signature_expiry_unix_ms": inspected["signature_expiry_unix_ms"]})
    expires = min(min(record["received_at_unix_ms"] + record["minimum_ttl_seconds"] * 1000,
                      record["signature_expiry_unix_ms"]) for record in records)
    require(expires - int(time.time() * 1000) >= 60_000, "insufficient original TTL for fixture")
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
    args = parser.parse_args()
    if args.mode == "collect":
        collect(args.root)
    elif args.mode == "serve":
        serve(args.root, args.listen, args.report, args.ready, args.max_seconds)
    else:
        validate_core(args.root, args.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, struct.error, urllib.error.URLError) as error:
        raise SystemExit(failure_summary(error)) from None
