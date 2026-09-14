#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded real-socket checks; every packet is inside a disposable user/net namespace."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.dont_write_bytecode = True


def fixture():
    source = Path(__file__).with_name("download-sharing-smoke.py")
    spec = importlib.util.spec_from_file_location("download_socket_fixture", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def namespace_identity():
    value = os.stat("/proc/self/ns/net")
    return f"{value.st_dev}:{value.st_ino}"


def kernel_stop_check(module):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, \
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as observer:
        sink.bind(("127.0.0.1", 0))
        sink.settimeout(1)
        sender.bind(("127.0.0.1", 0))
        observer.setblocking(False)
        payload = b"disposable-download-capture-stop"

        def send(count):
            for _ in range(count):
                sender.sendto(payload, sink.getsockname())
                received, source = sink.recvfrom(2048)
                assert received == payload and source == sender.getsockname()

        send(8)
        assert not select.select([observer], [], [], .02)[0], "protocol0 captured wildcard traffic"
        assert struct.unpack("II", observer.getsockopt(263, 6, 8)) == (0, 0)
        observer.bind(("lo", 3))
        send(32)
        # Use the actual unchanged fixture implementation; do not replace socket operations.
        module.stop_intake(observer)
        send(32)
        frames, deadline = 0, time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                observer.recv(65535)
                frames += 1
            except BlockingIOError:
                break
        else:
            raise AssertionError("finite pre-stop queue did not drain")
        packets, drops = struct.unpack("II", observer.getsockopt(263, 6, 8))
        assert frames == 64, (frames, packets, drops)  # loopback RX and TX for each real datagram
        assert packets == frames and drops == 0
        send(8)
        assert not select.select([observer], [], [], .02)[0], "new intake survived RET0"
        assert struct.unpack("II", observer.getsockopt(263, 6, 8)) == (0, 0)
        return {"frames": frames, "packets": packets, "drops": drops,
                "protocol0_quiet": True, "post_stop_quiet": True,
                "force_buffer_tested": False}


def application_check(module):
    run_id = "31" * 16
    with tempfile.TemporaryDirectory(prefix="volparossa-download-socket-") as raw:
        directory = Path(raw)
        # Namespace-local fixture addresses only; this tests the application's exact echo/hash,
        # not a VPN, signed route, helper, Internet source or owner-priority datapath.
        module.BASE.NODES["client"]["public"] = "127.0.0.1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as port:
            port.bind(("127.0.0.1", 0))
            module.BASE.DESTINATION = port.getsockname()
        (directory / "phase").write_text("waiting", encoding="ascii")
        failures = []

        def run(mode):
            try:
                module.application(directory, run_id, mode)
            except BaseException as error:
                failures.append(error)

        threads = []
        try:
            for mode in ("server", "client"):
                thread = threading.Thread(target=run, args=(mode,), daemon=True)
                threads.append(thread)
                thread.start()
                deadline = time.monotonic() + 2
                while not (directory / f"{mode}.ready").exists():
                    assert time.monotonic() < deadline and not failures, failures
                    time.sleep(.005)
            (directory / "phase").write_text("idle", encoding="ascii")
            deadline = time.monotonic() + 2
            while True:
                live = json.loads((directory / "client.live.json").read_text(encoding="ascii"))
                if live["phases"]["idle"]["received"] >= 16:
                    break
                assert time.monotonic() < deadline and not failures, failures
                time.sleep(.005)
            (directory / "phase").write_text("done", encoding="ascii")
            for thread in threads:
                thread.join(2)
                assert not thread.is_alive(), "application did not stop"
            assert not failures, failures
            records = [json.loads((directory / f"{mode}.json").read_text(encoding="ascii"))
                       for mode in ("client", "server")]
            digest = hashlib.sha256(module.payload_for(run_id)).hexdigest()
            assert all(record["completed"] and record["sha256"] == digest for record in records)
            assert records[0]["phases"]["idle"]["received"] >= 16
            return {"received": records[0]["phases"]["idle"]["received"], "sha256": digest}
        finally:
            module.stop()
            for thread in threads:
                thread.join(2)


def kernel_child(parent_namespace):
    assert namespace_identity() != parent_namespace, "refuse host namespace networking"
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=2)
    module = fixture()
    print(json.dumps({"capture": kernel_stop_check(module), "application": application_check(module)}))


class RealDownloadSocketTest(unittest.TestCase):
    def test_real_disposable_stop_drain_and_application_echo(self):
        before = namespace_identity()
        result = subprocess.run(
            ["unshare", "-Urn", sys.executable, "-B", str(Path(__file__).resolve()),
             "--kernel-child", before], capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(namespace_identity(), before)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["capture"]["frames"], 64)
        self.assertEqual(evidence["capture"]["drops"], 0)
        self.assertTrue(evidence["capture"]["protocol0_quiet"])
        self.assertTrue(evidence["capture"]["post_stop_quiet"])
        self.assertFalse(evidence["capture"]["force_buffer_tested"])
        self.assertGreaterEqual(evidence["application"]["received"], 16)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--kernel-child":
        kernel_child(sys.argv[2])
    else:
        unittest.main()
