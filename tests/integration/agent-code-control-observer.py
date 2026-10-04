#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable-fixture IPC observation barrier; never a core/model substitute.

Forward original frames byte for byte. Hold only the actual completed discovery
response until the parent has drained discovery captures and started job captures.
No public source, model text, raw frames or credentials are persisted here.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct

CONTROL_MAX = 256 * 1024
REQUEST_MAX = 2 * 1024 * 1024
RESPONSE_MAX = 64 * 1024
MAX_CONNECTIONS = 4096
PROFILE = b"qwen3-0.6b-v1"


def require(value):
    if not value:
        raise ValueError("closed observer contract")


def fields(raw):
    """Strict bounded subset of protobuf; unknown/duplicate fields fail closed."""
    require(isinstance(raw, bytes) and len(raw) <= CONTROL_MAX)
    index, result = 0, {}

    def varint():
        nonlocal index
        value = 0
        for shift in range(0, 70, 7):
            require(index < len(raw))
            byte = raw[index]; index += 1
            require(shift < 63 or byte <= 1)
            value |= (byte & 127) << shift
            if byte < 128:
                require(shift == 0 or byte != 0)
                return value
        raise ValueError("closed observer contract")

    while index < len(raw):
        tag = varint(); key, wire = tag >> 3, tag & 7
        require(key > 0 and key not in result and len(result) < 32)
        if wire == 0:
            result[key] = varint()
        else:
            require(wire == 2)
            length = varint(); require(length <= len(raw) - index)
            result[key] = raw[index:index + length]; index += length
    return result


def object_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value); value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON")))
    require(type(value) is dict)
    return value


async def frame(reader, maximum):
    prefix = await reader.readexactly(4)
    length = int.from_bytes(prefix, "big")
    require(0 < length <= maximum)
    return prefix + await reader.readexactly(length)


async def forward(writer, raw):
    writer.write(raw)
    await writer.drain()


def control(raw, request_id, payload, code):
    value = fields(raw[4:])
    require(set(value) <= {1, 2, 3, 4, payload} and {1, 2, 4, payload} <= set(value)
        and value[1] == 2 and value[2] == request_id and value.get(3, 0) == 0
        and value[4] == code)
    return value[payload]


class Observer:
    def __init__(self, upstream, directory, publisher, uid, release_owner=0):
        self.upstream, self.directory, self.publisher, self.uid = str(upstream), directory, publisher, uid
        self.release_owner = release_owner
        self.stop = asyncio.Event()
        self.active, self.tasks = 0, set()
        self.discovery = None
        self.released = False
        self.selected = None
        self.binding = None
        self.failure = None
        self.operations = dict(capabilities=0, submit=0, poll=0, cancel=0)
        self.completed = 0
        self.connections = 0

    def write(self, name, value):
        raw = json.dumps(value, sort_keys=True).encode()
        require(len(raw) <= 4096)
        target = self.directory / name
        require(not target.exists() and not target.is_symlink())
        temporary = self.directory / (name + ".tmp")
        with temporary.open("xb") as file:
            file.write(raw)
        temporary.replace(target)

    def summary(self):
        return dict(version=1, purpose="original_control_frame_phase_observation", failure=self.failure,
            discovery=self.discovery, discovery_response_released=self.released,
            selected_provider_key=self.selected.hex() if self.selected else None,
            operations=self.operations, completed_exchanges=self.completed, connections=self.connections,
            active_connections=self.active, byte_preserving=True, responses_generated=False)

    async def handle(self, reader, writer):
        task = asyncio.current_task(); self.tasks.add(task)
        upstream, counted = None, False
        try:
            self.connections += 1
            require(self.connections <= MAX_CONNECTIONS and self.active < 4 and self.failure is None)
            credentials = writer.get_extra_info("socket").getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            require(struct.unpack("3i", credentials)[1] == self.uid)
            self.active += 1
            counted = True
            # This is an observation ceiling, not a renewed core request/job deadline.
            async with asyncio.timeout(155):
                original = await frame(reader, CONTROL_MAX)
                request = fields(original[4:])
                require(request.get(1) == 2 and isinstance(request.get(2), bytes) and len(request[2]) == 16)
                require(set(request) in ({1, 2, 34}, {1, 2, 33}))
                if 34 in request:
                    require(self.discovery is None and self.selected is None and self.active == 1)
                    query = fields(request[34])
                    require(query == {1:self.publisher, 6:1, 7:1, 8:PROFILE, 10:1})
                else:
                    require(self.released and fields(request[33]) == {1:self.selected})
                remote, upstream = await asyncio.open_unix_connection(self.upstream)
                await forward(upstream, original)
                response = await frame(remote, CONTROL_MAX)
                if 34 in request:
                    payload = fields(control(response, request[2], 25, b"COMPUTE_DISCOVERED"))
                    require(set(payload) == {1})
                    provider = fields(payload[1]); require(set(provider) == {1, 2} and len(provider[1]) == 32)
                    caps = object_json(provider[2]); require(caps.get("code_proposal_v6") is True)
                    self.selected = provider[1]
                    self.discovery = dict(request_sha256=hashlib.sha256(original).hexdigest(),
                        response_sha256=hashlib.sha256(response).hexdigest(), public_code_v6_only=True,
                        minimum=1, maximum=1, selected_count=1, task_requests_before_release=0)
                    self.write("discovery-ready.json", self.summary())
                    # Parent drains both discovery observers before creating this fresh file.
                    async with asyncio.timeout(30):
                        while not (self.directory / "release").exists():
                            if self.stop.is_set():
                                self.failure = self.failure or "active_on_stop"
                                raise ValueError("closed observer contract")
                            await asyncio.sleep(0.02)
                    release = self.directory / "release"
                    info = release.lstat()
                    require(stat.S_ISREG(info.st_mode) and not release.is_symlink() and info.st_nlink == 1
                        and info.st_uid == self.release_owner and stat.S_IMODE(info.st_mode) == 0o444
                        and info.st_size == 8 and release.read_bytes() == b"release\n")
                    self.released = True
                    await forward(writer, response)
                else:
                    ready = fields(control(response, request[2], 24, b"COMPUTE_RPC_READY"))
                    require(set(ready) == {1, 2} and ready[1] == self.selected and len(ready[2]) == 32)
                    await forward(writer, response)
                    rpc = await frame(reader, REQUEST_MAX)
                    value = object_json(rpc[4:])
                    require(set(value) == {"version", "request_id", "requester_key", "operation"}
                        and value["version"] == 1 and value["requester_key"] == ready[2].hex())
                    operation = value["operation"]
                    require(type(operation) is dict and operation.get("operation") in self.operations)
                    name = operation["operation"]
                    require(set(operation) == ({"operation"} if name == "capabilities" else {"operation", "value"}))
                    if name == "submit":
                        binding = operation["value"]["binding"]
                        require(self.binding is None or self.binding == binding)
                        self.binding = binding
                    elif name in {"poll", "cancel"}:
                        require(self.binding is not None and operation["value"] == self.binding)
                    self.operations[name] += 1
                    await forward(upstream, rpc)
                    answer = await frame(remote, RESPONSE_MAX)
                    result = object_json(answer[4:])
                    require(set(result) == {"version", "request_id", "outcome"} and result["version"] == 1
                        and result["request_id"] == value["request_id"])
                    await forward(writer, answer)
                    final = await frame(remote, CONTROL_MAX)
                    require(control(final, request[2], 10, b"COMPUTE_RPC_OK") == b"")
                    await forward(writer, final)
                self.completed += 1
        except (ValueError, KeyError, TypeError, UnicodeError, RecursionError, json.JSONDecodeError):
            self.failure = self.failure or "invalid_frame"; self.stop.set()
        except TimeoutError:
            self.failure = self.failure or "observation_deadline"; self.stop.set()
        except (OSError, asyncio.IncompleteReadError):
            self.failure = self.failure or "transport_error"; self.stop.set()
        finally:
            if upstream is not None:
                upstream.close()
                with contextlib.suppress(OSError): await upstream.wait_closed()
            writer.close()
            with contextlib.suppress(OSError): await writer.wait_closed()
            if counted: self.active -= 1
            self.tasks.discard(task)

    async def serve(self, path):
        require(not path.exists() and not path.is_symlink())
        server = await asyncio.start_unix_server(self.handle, path=str(path), limit=CONTROL_MAX)
        path.chmod(0o600)
        try:
            async with server:
                await self.stop.wait()
            if self.tasks:
                self.failure = self.failure or "active_on_stop"
                for task in list(self.tasks): task.cancel()
                await asyncio.gather(*list(self.tasks), return_exceptions=True)
        finally:
            path.unlink(missing_ok=True)
            self.write("control-observer.json", self.summary())


async def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--publisher", required=True)
    args = parser.parse_args()
    require(os.getuid() != 0 and socket.gethostname() == "volparossa-alpha")
    publisher = bytes.fromhex(args.publisher); require(len(publisher) == 32)
    info = args.directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
        and args.directory.resolve() == args.directory and args.socket.parent == args.directory)
    observer = Observer(args.upstream, args.directory, publisher, os.getuid())
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT): loop.add_signal_handler(signum, observer.stop.set)
    async with asyncio.timeout(2700):
        await observer.serve(args.socket)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (ValueError, OSError, TimeoutError):
        raise SystemExit("closed fixture control observation failed") from None
