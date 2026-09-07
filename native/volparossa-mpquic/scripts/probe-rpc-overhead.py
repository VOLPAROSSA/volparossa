#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure real empty-runtime AF_UNIX RPCs, not MPQUIC datapath throughput.

No IP sockets, network changes, privileges, or third-party Python packages.
The caller supplies a previously source-built daemon and workspace temp parent.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def blob(field, value):
    return varint((field << 3) | 2) + varint(len(value)) + value


def decode(data):
    offset = 0

    def integer():
        nonlocal offset
        result = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError("truncated response")
            byte = data[offset]
            offset += 1
            result |= (byte & 127) << shift
            if not byte & 128:
                return result
        raise ValueError("overlong response integer")

    result = {}
    while offset < len(data):
        key = integer()
        field, kind = key >> 3, key & 7
        if field == 0 or field in result:
            raise ValueError("invalid response field")
        if kind == 0:
            value = integer()
        elif kind == 2:
            length = integer()
            if length > len(data) - offset:
                raise ValueError("truncated response bytes")
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError("unexpected response wire type")
        result[field] = value
    return result


def receive(stream, length):
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise ValueError("early response EOF")
        result.extend(chunk)
    return bytes(result)


def exchange(path, target, operation, nested, expected_result):
    nonce = os.urandom(16)
    request = (b"\x08\x06" + blob(2, nonce)
               + (blob(3, target) if operation != 18 else b"") + blob(operation, nested))
    length = len(request).to_bytes(4, "big")
    digest = hashlib.sha256(b"VOLPAROSSA-MPQUIC-REQUEST-V6\0" + length + request).digest()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(str(path))
        _, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid():
            raise ValueError("wrong daemon UID")
        stream.sendall(bytes(32))
        stream.sendall(length + request)
        stream.shutdown(socket.SHUT_WR)
        size = int.from_bytes(receive(stream, 4), "big")
        if not 0 < size <= 4096:
            raise ValueError("unbounded response")
        response = decode(receive(stream, size))
        if stream.recv(1):
            raise ValueError("trailing response")
    identity = decode(response[7])
    if (response[1] != 6 or response[2] != nonce or response[8] != digest
            or response.get(3, 0) != expected_result or identity[1] != 1
            or len(identity[2]) != 32 or not any(identity[2])
            or (operation != 18 and identity[2] != target)):
        raise ValueError("response correlation failed")
    return identity[2]


def probe(binary, parent, count, enabled):
    with tempfile.TemporaryDirectory(prefix="rpc.", dir=parent) as temporary:
        path = Path(temporary) / "s"
        if len(os.fsencode(path)) >= 108:
            raise ValueError("workspace temporary socket path is too long")
        environment = {**os.environ, "VMP_RPC_TIMING": "1" if enabled else "0"}
        process = subprocess.Popen([binary, "--mode", "client", "--socket", str(path)],
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not path.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("daemon did not create its owned socket")
                time.sleep(0.005)
            target = exchange(path, bytes(32), 18, b"\x08\x01", 0)
            started = time.perf_counter_ns()
            for _ in range(count):
                # Real runtime validates each digest/nonce/instance and performs
                # GetStatus; the nonexistent context MUST remain NotFound.
                exchange(path, target, 14, blob(1, bytes([65]) * 16), 3)
            duration = time.perf_counter_ns() - started
        finally:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise
        if process.returncode != 0 or stdout or path.exists():
            raise RuntimeError("daemon did not stop and clean its owned socket")
        reports = []
        for line in stderr.decode().splitlines():
            if enabled and line == "NATIVE_RPC_REJECT op=14 result=3 cause=SESSION_NOT_FOUND":
                continue
            if not line.startswith("NATIVE_RPC_TIMING "):
                raise RuntimeError("unexpected daemon diagnostic")
            reports.append(json.loads(line.removeprefix("NATIVE_RPC_TIMING ")))
        if enabled:
            if not reports or not reports[-1]["final"] or reports[-1]["accepted"] != count + 1:
                raise ValueError("missing final timing counts")
        elif reports:
            raise ValueError("timing emitted without opt-in")
        return {"timing_enabled": enabled, "requests": count, "duration_ns": duration,
                "requests_per_second": count * 1e9 / duration,
                "daemon_timing": reports[-1] if reports else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("daemon", type=Path)
    parser.add_argument("workspace_temporary_parent", type=Path)
    parser.add_argument("--requests", type=int, default=5000)
    args = parser.parse_args()
    if not 100 <= args.requests <= 20000:
        parser.error("requests must be between 100 and 20000")
    for path in (args.daemon, args.workspace_temporary_parent):
        if not path.is_absolute() or path.is_symlink():
            parser.error("supply absolute, non-symlink workspace paths")
    print(json.dumps({"scope": "empty_native_runtime_rpc_only_not_datapath",
                      "samples": [probe(str(args.daemon), args.workspace_temporary_parent,
                                        args.requests, enabled) for enabled in (False, True)]}))


if __name__ == "__main__":
    main()
