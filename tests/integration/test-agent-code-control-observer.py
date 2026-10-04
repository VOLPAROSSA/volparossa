#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real Unix socket/barrier contracts with synthetic frames, not model evidence."""
import asyncio
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

C = runpy.run_path(str(Path(__file__).with_name("agent-code-control-observer.py")))
PUBLISHER, PROVIDER, REQUESTER, ID = b"p" * 32, b"k" * 32, b"r" * 32, b"i" * 16


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128); value >>= 7
    return bytes(result + bytes([value]))


def proto(value):
    return b"".join(varint(key << 3 | (0 if type(item) is int else 2)) +
        (varint(item) if type(item) is int else varint(len(item)) + item) for key, item in value.items())


def frame(raw):
    return len(raw).to_bytes(4, "big") + raw


def request(operation, body):
    return frame(proto({1:2, 2:ID, operation:proto(body)}))


def response(payload, body, code):
    return frame(proto({1:2, 2:ID, 4:code, payload:body}))


DISCOVER = request(34, {1:PUBLISHER, 6:1, 7:1, 8:C["PROFILE"], 10:1})
DISCOVERED = response(25, proto({1:proto({1:PROVIDER, 2:b'{"code_proposal_v6":true}'})}), b"COMPUTE_DISCOVERED")
REMOTE = request(33, {1:PROVIDER})
READY = response(24, proto({1:PROVIDER, 2:REQUESTER}), b"COMPUTE_RPC_READY")
DONE = response(10, b"", b"COMPUTE_RPC_OK")


class ControlObserver(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.seen = []
        self.remote_reply = DISCOVERED
        self.server = await asyncio.start_unix_server(self.upstream, str(self.root / "upstream"))
        # Unit sockets use the current uid as the synthetic parent. The guest
        # executable does not expose this override and requires root-owned release.
        self.observer = C["Observer"](self.root / "upstream", self.root, PUBLISHER, os.getuid(), release_owner=os.getuid())
        self.running = asyncio.create_task(self.observer.serve(self.root / "observe"))
        await self.wait_for(lambda: (self.root / "observe").exists())

    async def asyncTearDown(self):
        self.observer.stop.set()
        await asyncio.wait_for(self.running, 2)
        self.server.close(); await self.server.wait_closed()
        self.temp.cleanup()

    async def wait_for(self, predicate):
        async with asyncio.timeout(2):
            while not predicate(): await asyncio.sleep(0.001)

    async def upstream(self, reader, writer):
        try:
            original = await C["frame"](reader, C["CONTROL_MAX"]); self.seen.append(original)
            if 34 in C["fields"](original[4:]):
                await C["forward"](writer, self.remote_reply)
            else:
                await C["forward"](writer, READY)
                rpc = await C["frame"](reader, C["REQUEST_MAX"]); self.seen.append(rpc)
                answer = frame(json.dumps(dict(version=1, request_id="f" * 32,
                    outcome=dict(outcome="error", value="busy")), separators=(",", ":")).encode())
                await C["forward"](writer, answer)
                await C["forward"](writer, DONE)
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close(); await writer.wait_closed()

    async def connect(self):
        return await asyncio.open_unix_connection(str(self.root / "observe"))

    async def discover(self):
        reader, writer = await self.connect(); await C["forward"](writer, DISCOVER)
        await self.wait_for(lambda: (self.root / "discovery-ready.json").exists())
        self.assertEqual(self.seen, [DISCOVER])
        self.assertFalse(self.observer.released)
        with self.assertRaises(TimeoutError): await asyncio.wait_for(reader.read(1), 0.02)
        (self.root / "release").write_bytes(b"release\n")
        (self.root / "release").chmod(0o444)
        self.assertEqual(await C["frame"](reader, C["CONTROL_MAX"]), DISCOVERED)
        writer.close(); await writer.wait_closed()
        await self.wait_for(lambda: self.observer.active == 0)

    async def test_actual_response_is_held_then_forwarded_byte_for_byte(self):
        await self.discover()
        self.assertEqual(self.observer.discovery["task_requests_before_release"], 0)
        self.assertEqual(self.observer.selected, PROVIDER)
        reader, writer = await self.connect(); await C["forward"](writer, REMOTE)
        self.assertEqual(await C["frame"](reader, C["CONTROL_MAX"]), READY)
        raw = frame(b'{"version":1,"request_id":"' + b'f'*32 + b'","requester_key":"' + REQUESTER.hex().encode()
            + b'","operation":{"operation":"capabilities"}}')
        await C["forward"](writer, raw)
        answer = await C["frame"](reader, C["RESPONSE_MAX"])
        self.assertEqual(json.loads(answer[4:])["outcome"]["outcome"], "error")
        self.assertEqual(await C["frame"](reader, C["CONTROL_MAX"]), DONE)
        writer.close(); await writer.wait_closed()
        await self.wait_for(lambda: self.observer.active == 0)
        self.assertEqual(self.seen, [DISCOVER, REMOTE, raw])
        self.assertEqual(self.observer.completed, 2)
        self.assertIsNone(self.observer.failure)

    async def test_remote_before_discovery_or_capture_release_is_refused(self):
        reader, writer = await self.connect(); await C["forward"](writer, REMOTE)
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [])
        self.assertEqual(self.observer.failure, "invalid_frame")

    async def test_unselected_provider_is_not_forwarded(self):
        await self.discover()
        reader, writer = await self.connect()
        await C["forward"](writer, request(33, {1:b"x" * 32}))
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [DISCOVER])
        self.assertEqual(self.observer.failure, "invalid_frame")

    async def test_unknown_operation_is_not_forwarded(self):
        reader, writer = await self.connect(); await C["forward"](writer, request(14, {}))
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [])

    async def rpc(self, operation):
        reader, writer = await self.connect(); await C["forward"](writer, REMOTE)
        self.assertEqual(await C["frame"](reader, C["CONTROL_MAX"]), READY)
        raw = frame(json.dumps(dict(version=1, request_id="f"*32, requester_key=REQUESTER.hex(),
            operation=operation), separators=(",", ":")).encode())
        await C["forward"](writer, raw)
        return reader, writer, raw

    async def test_submit_and_original_binding_poll_are_unmodified_changed_binding_is_refused(self):
        await self.discover()
        binding = dict(job_id="a"*32, dataset_sha256="b"*64)
        for operation in (dict(operation="submit", value=dict(binding=binding)), dict(operation="poll", value=binding)):
            reader, writer, raw = await self.rpc(operation)
            self.assertEqual(json.loads((await C["frame"](reader, C["RESPONSE_MAX"]))[4:])["outcome"]["outcome"], "error")
            self.assertEqual(await C["frame"](reader, C["CONTROL_MAX"]), DONE)
            writer.close(); await writer.wait_closed()
            await self.wait_for(lambda: self.observer.active == 0)
            self.assertEqual(self.seen[-1], raw)
        before = len(self.seen)
        reader, writer, _ = await self.rpc(dict(operation="poll", value=dict(binding, job_id="c"*32)))
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(len(self.seen), before + 1)  # Only the unchanged Remote/Ready handshake.
        self.assertEqual(self.observer.failure, "invalid_frame")

    async def test_peer_uid_is_closed(self):
        self.observer.uid = os.getuid() + 1
        reader, writer = await self.connect()
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [])
        self.assertEqual(self.observer.active, 0)

    async def test_connection_ceiling_is_closed(self):
        self.observer.connections = C["MAX_CONNECTIONS"]
        reader, writer = await self.connect()
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [])
        self.assertEqual(self.observer.failure, "invalid_frame")

    async def test_stop_during_held_response_does_not_invent_reply_or_claim_cleanup(self):
        reader, writer = await self.connect(); await C["forward"](writer, DISCOVER)
        await self.wait_for(lambda: (self.root / "discovery-ready.json").exists())
        self.observer.stop.set(); await asyncio.wait_for(self.running, 2)
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        report = json.loads((self.root / "control-observer.json").read_text())
        self.assertEqual(report["failure"], "active_on_stop")
        self.assertFalse(report["discovery_response_released"])
        self.assertFalse(report["responses_generated"])

    async def test_oversized_frame_rejected_before_body_or_upstream(self):
        reader, writer = await self.connect()
        await C["forward"](writer, (C["CONTROL_MAX"] + 1).to_bytes(4, "big"))
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [])

    async def test_mismatched_original_response_is_not_rewritten(self):
        self.remote_reply = response(25, proto({1:proto({1:PROVIDER, 2:b'{"code_proposal_v6":false}'})}), b"COMPUTE_DISCOVERED")
        reader, writer = await self.connect(); await C["forward"](writer, DISCOVER)
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertEqual(self.seen, [DISCOVER])
        self.assertFalse((self.root / "discovery-ready.json").exists())

    async def test_unprivileged_release_cannot_impersonate_parent(self):
        self.assertEqual(C["Observer"]("unused", self.root, PUBLISHER, os.getuid()).release_owner, 0)
        self.observer.release_owner = os.getuid() + 1
        reader, writer = await self.connect(); await C["forward"](writer, DISCOVER)
        await self.wait_for(lambda: (self.root / "discovery-ready.json").exists())
        (self.root / "release").write_bytes(b"release\n"); (self.root / "release").chmod(0o444)
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertFalse(self.observer.released)
        self.assertEqual(self.observer.failure, "invalid_frame")

    async def test_writable_release_cannot_end_capture_barrier(self):
        reader, writer = await self.connect(); await C["forward"](writer, DISCOVER)
        await self.wait_for(lambda: (self.root / "discovery-ready.json").exists())
        (self.root / "release").write_bytes(b"release\n"); (self.root / "release").chmod(0o600)
        self.assertEqual(await reader.read(), b"")
        writer.close(); await writer.wait_closed()
        self.assertFalse(self.observer.released)

    async def test_duplicate_and_unknown_protobuf_fields_are_refused(self):
        for raw in (b'\x08\x02\x08\x02', b'\x0f\x02', b'\x08\x80\x00', b'\x0a\xff'):
            with self.assertRaises(ValueError): C["fields"](raw)
        for raw in (b'{"operation":1,"operation":2}', b'{"number":NaN}'):
            with self.assertRaises(ValueError): C["object_json"](raw)


if __name__ == "__main__": unittest.main()
