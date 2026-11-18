#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real private Unix IO and owned Python children; no SSH, VM, root or Android.

Synthetic responses prove transport bounds/cleanup only. They cannot establish
source acquisition, protected core routes, cache custody or installed-app use.
"""
import importlib.util
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("weather_android_tunnel", HERE / "weather-android-tunnel.py")
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)
BODY = '{"temperature":0,"description":"soleil ☀"}\n'.encode()
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + BODY)


def command(source):
    return [sys.executable, "-B", "-c", source]


def responder(response=RESPONSE):
    return command("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(" + repr(response) + ")")


def live_process(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return False
    return text.rsplit(") ", 1)[1].split()[0] != "Z"


class TunnelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-tunnel-")
        self.root = Path(self.temp.name)
        self.parent = self.root / "socket"
        self.parent.mkdir(mode=0o700)
        self.path = self.parent / "core-api.sock"

    def tearDown(self):
        self.temp.cleanup()

    def exchange(self, supplied, seconds=2):
        return T.exchange(supplied, T.canonical_request(T.ROUTES[0]), time.monotonic() + seconds)

    def run_server(self, *, notify=None, supplied=None, observe_responses=False, diagnostic=None):
        ready = threading.Event()
        outcome = {}

        def started():
            if notify:
                notify()
            ready.set()

        def run():
            try:
                outcome["result"] = T.serve(self.path, supplied or responder(), lifetime=5, notify=started,
                                            observe_responses=observe_responses, diagnostic=diagnostic)
            except BaseException as error:
                outcome["error"] = error
                ready.set()

        thread = threading.Thread(target=run)
        thread.start()
        self.addCleanup(thread.join, 6)
        self.assertTrue(ready.wait(3), "bounded listener readiness")
        return thread, outcome

    def fetch(self, route, *, path=None, raw=None):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3)
            client.connect(str(path or self.path))
            client.sendall(raw or T.canonical_request(route))
            reply = bytearray()
            while True:
                block = client.recv(65536)
                if not block:
                    return bytes(reply)
                reply.extend(block)
                self.assertLessEqual(len(reply), T.MAX_RESPONSE)

    def diagnostic_failure(self, *, supplied=None, observe_responses=False, diagnostic=None):
        diagnostic = diagnostic or T.TunnelDiagnostic()
        diagnostic.active = True
        thread, outcome = self.run_server(supplied=supplied, observe_responses=observe_responses,
            diagnostic=diagnostic)
        self.assertEqual(self.fetch(T.ROUTES[0]), b"")
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("result", outcome)
        self.assertIn("error", outcome)
        return diagnostic, outcome

    def test_diagnostic_distinguishes_original_503_before_response_observer_rejection(self):
        response = RESPONSE.replace(b"200 OK", b"503 Service Unavailable")
        diagnostic, outcome = self.diagnostic_failure(supplied=responder(response), observe_responses=True)
        self.assertIsInstance(outcome["error"], ValueError)
        value = diagnostic.record()
        self.assertEqual(value["primary"], dict(phase="response-observe", reason="response-rejected",
            product="weather", ordinal=1, completed=0, requests=dict(weather=1, air_quality=0),
            ssh_status=0, http_status="503"))
        self.assertEqual(value["cleanup"], dict(exchange_child_joined=True, socket_removed=True))
        self.assertFalse(value["success"]); self.assertFalse(value["joined_core_acceptance"])

    def test_diagnostic_keeps_original_child_status_and_no_private_child_output(self):
        child = command("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(" + repr(RESPONSE)
            + ");sys.stderr.write('PRIVATE-key-https://private.invalid/');sys.exit(7)")
        diagnostic, _ = self.diagnostic_failure(supplied=child)
        value = diagnostic.record()
        self.assertEqual((value["primary"]["phase"], value["primary"]["reason"], value["primary"]["ssh_status"]),
            ("exchange-join", "child-failed", 7))
        self.assertEqual(value["primary"]["http_status"], "200")
        self.assertTrue(value["cleanup"]["exchange_child_joined"])
        self.assertNotIn("PRIVATE", json.dumps(value)); self.assertNotIn("private.invalid", json.dumps(value))

    def test_diagnostic_capture_fault_does_not_mask_failure_or_skip_cleanup(self):
        diagnostic = T.TunnelDiagnostic()
        with patch.object(diagnostic, "capture", side_effect=ValueError("PRIVATE-error")):
            diagnostic, outcome = self.diagnostic_failure(diagnostic=diagnostic, observe_responses=True)
        self.assertIsInstance(outcome["error"], ValueError)
        self.assertIsNone(diagnostic.primary)
        self.assertEqual(diagnostic.cleanup, dict(exchange_child_joined=True, socket_removed=True))
        output = io.StringIO()
        with redirect_stdout(output): T.emit_diagnostic(diagnostic)
        self.assertEqual(output.getvalue(), "")

    def test_primary_child_failure_survives_interrupted_exchange_cleanup(self):
        original = T.stop_child
        def interrupted(child):
            original(child)
            raise T.TunnelInterrupted("PRIVATE-cleanup")
        child = command("import sys;sys.stdin.buffer.read();sys.exit(9)")
        with patch.object(T, "stop_child", side_effect=interrupted):
            diagnostic, outcome = self.diagnostic_failure(supplied=child)
        self.assertIsInstance(outcome["error"], T.TunnelInterrupted)
        value = diagnostic.record()
        self.assertEqual((value["primary"]["reason"], value["primary"]["ssh_status"]), ("child-failed", 9))
        self.assertEqual(value["cleanup"], dict(exchange_child_joined=False, socket_removed=True))

    def test_primary_response_failure_survives_interrupted_socket_cleanup(self):
        original = Path.unlink
        def interrupted(path, *args, **kwargs):
            if path == self.path: raise T.TunnelInterrupted("PRIVATE-socket-cleanup")
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", interrupted):
            diagnostic, outcome = self.diagnostic_failure(observe_responses=True)
        self.assertIsInstance(outcome["error"], T.TunnelInterrupted)
        value = diagnostic.record()
        self.assertEqual((value["primary"]["phase"], value["primary"]["reason"]),
            ("response-observe", "response-rejected"))
        self.assertEqual(value["cleanup"], dict(exchange_child_joined=True, socket_removed=False))
        self.assertTrue(self.path.is_socket())

    def test_diagnostic_early_exchange_guard_has_no_invented_child_or_status(self):
        diagnostic = T.TunnelDiagnostic(); diagnostic.admitted(T.ROUTES[0], 1)
        with patch.object(T.subprocess, "Popen", side_effect=AssertionError("must not spawn")):
            try:
                T.exchange(responder(), T.canonical_request(T.ROUTES[0]), time.monotonic() - 1,
                    diagnostic=diagnostic)
            except ValueError as error: diagnostic.capture(error)
        value = diagnostic.record()
        self.assertEqual((value["primary"]["phase"], value["primary"]["reason"]),
            ("exchange-spawn", "guard-rejected"))
        self.assertIsNone(value["primary"]["ssh_status"])
        self.assertIsNone(value["primary"]["http_status"])
        self.assertEqual(value["cleanup"], dict(exchange_child_joined=None, socket_removed=None))

    def test_diagnostic_exact_schema_and_phase_counter_status_scope(self):
        diagnostic, _ = self.diagnostic_failure(observe_responses=True)
        valid = diagnostic.record()
        changes = [lambda value: value.update(extra="PRIVATE"), lambda value: value.update(schema=True),
            lambda value: value.update(success=True), lambda value: value.update(joined_core_acceptance=True),
            lambda value: value["primary"].update(phase="PRIVATE"), lambda value: value["primary"].update(reason="PRIVATE"),
            lambda value: value["primary"].update(product="PRIVATE"), lambda value: value["primary"].update(ordinal=True),
            lambda value: value["primary"].update(ordinal=2), lambda value: value["primary"].update(completed=2),
            lambda value: value["primary"].update(completed=True), lambda value: value["primary"]["requests"].update(weather=4),
            lambda value: value["primary"]["requests"].update(weather=True), lambda value: value["primary"].update(ssh_status=True),
            lambda value: value["primary"].update(ssh_status=-256), lambda value: value["primary"].update(http_status="PRIVATE"),
            lambda value: value["primary"].update(http_status=503), lambda value: value["primary"].update(reason="child-failed"),
            lambda value: value["primary"].update(phase="request-limit"), lambda value: value["primary"].update(phase="accept"),
            lambda value: value["cleanup"].update(socket_removed=1), lambda value: value["cleanup"].update(vm_removed=True)]
        for change in changes:
            candidate = json.loads(json.dumps(valid)); change(candidate)
            with self.assertRaises((ValueError, TypeError)): T.validate_diagnostic(candidate)
        for key in valid:
            candidate = dict(valid); candidate.pop(key)
            with self.assertRaises(ValueError): T.validate_diagnostic(candidate)

    def test_marker_bound_includes_prefix_and_lf_and_exception_text_is_never_retained(self):
        diagnostic = T.TunnelDiagnostic(); diagnostic.active = True; diagnostic.phase("admission")
        diagnostic.capture(ValueError("PRIVATE-key-https://private.invalid/path"))
        output = io.StringIO()
        with redirect_stdout(output): T.emit_diagnostic(diagnostic)
        marker = output.getvalue()
        self.assertTrue(marker.startswith(T.PREFIX)); self.assertEqual(len(marker.splitlines()), 1)
        self.assertTrue(marker.endswith("\n")); self.assertNotIn("PRIVATE", marker); self.assertNotIn("private.invalid", marker)
        value = json.loads(marker[len(T.PREFIX):])
        with patch.object(T, "MAX_DIAGNOSTIC_BYTES", len(marker.encode()) - 1), self.assertRaises(ValueError):
            T.validate_diagnostic(value)
        with patch.object(T, "MAX_DIAGNOSTIC_BYTES", len(marker.encode())):
            self.assertEqual(T.validate_diagnostic(value), value)
        self.assertIsNone(value["primary"]["product"]); self.assertIsNone(value["primary"]["ssh_status"])

    def test_http_status_observation_is_only_a_fixed_allowlist_not_the_reason_or_body(self):
        for raw, expected in [(b"HTTP/1.1 503 PRIVATE\r\n\r\nPRIVATE", "503"),
            (b"HTTP/1.1 418 PRIVATE", "other"), (b"HTTP/1.0 200 OK", "invalid"), (b"PRIVATE", "invalid")]:
            diagnostic = T.TunnelDiagnostic(); diagnostic.http(raw)
            self.assertEqual(diagnostic.facts["http_status"], expected)
            self.assertNotIn("PRIVATE", json.dumps(diagnostic.facts))

    def test_unobserved_facts_stay_null_and_partial_observation_is_not_guessed(self):
        diagnostic = T.TunnelDiagnostic(); diagnostic.active = True
        diagnostic.capture(RuntimeError("PRIVATE-unknown"))
        value = diagnostic.record()
        self.assertEqual(value["primary"], dict(phase=None, reason=None, product=None, ordinal=None,
            completed=0, requests=dict(weather=0, air_quality=0), ssh_status=None, http_status=None))
        self.assertEqual(value["cleanup"], dict(exchange_child_joined=None, socket_removed=None))
        # An interrupt between quota admission and the next phase observation
        # leaves an incomplete combination. Do not infer the missing phase.
        diagnostic = T.TunnelDiagnostic(); diagnostic.active = True
        diagnostic.phase("request-limit"); diagnostic.admitted(T.ROUTES[0], 1)
        diagnostic.capture(T.TunnelInterrupted("PRIVATE-between-observations"))
        with self.assertRaises(ValueError): diagnostic.record()
        output = io.StringIO()
        with redirect_stdout(output): T.emit_diagnostic(diagnostic)
        self.assertEqual(output.getvalue(), "")

    def test_host_cli_admission_failure_emits_only_one_closed_marker_and_original_exit(self):
        result = subprocess.run([sys.executable, "-B", str(HERE / "weather-android-tunnel.py"), "host",
            "--socket", "/PRIVATE/socket", "--ssh-key", "/PRIVATE/key", "--known-hosts", "/PRIVATE/hosts"],
            env={"PATH": "/usr/bin:/bin", "GITHUB_ACTIONS": "false"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=3, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"weather_android_tunnel_failed\n")
        self.assertLessEqual(len(result.stdout), T.MAX_DIAGNOSTIC_BYTES)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertTrue(result.stdout.startswith(T.PREFIX.encode()))
        self.assertNotIn(b"PRIVATE", result.stdout)
        value = json.loads(result.stdout[len(T.PREFIX):])
        self.assertEqual(T.validate_diagnostic(value)["primary"]["phase"], "admission")

    def test_parser_admits_only_fixed_bodyless_get_and_drops_non_authority_headers(self):
        for route in T.ROUTES:
            raw = T.canonical_request(route)
            self.assertEqual(T.request_path(raw), route)
            extra = raw[:-2] + b"Accept: application/json\r\nX-Ignored: discarded\r\nContent-Length: 0\r\n\r\n"
            self.assertEqual(T.request_path(extra), route)
            self.assertEqual(T.canonical_request(T.request_path(extra)), raw)

    def test_standalone_guest_module_has_no_host_evidence_dependency(self):
        # Loading a copied helper is inert: no root guest/host CLI or networking.
        # The production guest installs this exact name without sibling modules.
        installed = self.root / Path(T.GUEST_HELPER).name
        installed.write_bytes((HERE / "weather-android-tunnel.py").read_bytes())
        self.assertFalse((installed.parent / "weather-android-evidence.py").exists())
        module = runpy.run_path(str(installed))
        self.assertEqual(module["canonical_request"](T.ROUTES[0]), T.canonical_request(T.ROUTES[0]))

    def test_parser_rejects_other_methods_urls_bodies_credentials_and_duplicate_headers(self):
        good = T.canonical_request(T.ROUTES[0])
        candidates = [b"", good[:-1], good + b"body", good + good, good.decode(),
            good.replace(b"GET ", b"POST ", 1), good.replace(b"HTTP/1.1", b"HTTP/1.0"),
            good.replace(T.ROUTES[0].encode(), b"http://127.0.0.1:43210" + T.ROUTES[0].encode()),
            good.replace(T.ROUTES[0].encode(), b"/api/volparossa/%66orecast"),
            good.replace(T.ROUTES[0].encode(), T.ROUTES[0].encode() + b"?latitude=1"),
            good.replace(b"Host: 127.0.0.1:43210", b"Host: localhost:43210"),
            good.replace(b"Origin: http://", b"Origin: https://"),
            good.replace(b"Origin:", b" Origin:"), good.replace(b"Host:", b"Host :"),
            good.replace(b"Host:", b"H\xffst:"),
            b"a" * (T.MAX_REQUEST + 1)]
        for header in (b"Host: 127.0.0.1:43210", b"origin: http://127.0.0.1:43210",
                       b"Authorization: secret", b"Cookie: secret", b"Proxy-Authorization: secret",
                       b"Transfer-Encoding: chunked", b"Expect: 100-continue", b"Content-Length: 1",
                       b"X: bad\x00value", b"X: bad\x7fvalue", b"Bad_Name: value"):
            candidates.append(good[:-2] + header + b"\r\n\r\n")
        for raw in candidates:
            with self.subTest(raw=repr(raw)[:70]):
                with self.assertRaises((ValueError, UnicodeError, AttributeError, TypeError)):
                    T.request_path(raw)

    def test_receive_bounds_fragmentation_and_canonicalizes_without_retaining_extra_headers(self):
        good = T.canonical_request(T.ROUTES[1])
        extra = good[:-2] + b"X-Ignored: discarded\r\n\r\n"
        left, right = socket.socketpair()
        with left, right:
            def send_parts():
                for offset in range(0, len(extra), 17):
                    right.sendall(extra[offset:offset + 17])
                    time.sleep(.002)
            writer = threading.Thread(target=send_parts)
            writer.start()
            try:
                self.assertEqual(T.receive_request(left, time.monotonic() + 2), good)
            finally:
                writer.join(2)
        for bad in (good + b"unexpected body", b"a" * (T.MAX_REQUEST + 1)):
            left, right = socket.socketpair()
            with left, right:
                right.sendall(bad)
                right.shutdown(socket.SHUT_WR)
                with self.assertRaises((ValueError, OSError)):
                    T.receive_request(left, time.monotonic() + 2)

    def test_exchange_preserves_original_utf8_header_and_body_bytes(self):
        self.assertEqual(self.exchange(responder()), RESPONSE)

    def test_explicit_response_observer_binds_all_six_original_bodies_without_changing_bytes(self):
        proof = __import__("runpy").run_path(str(HERE / "test-weather-android-evidence.py"))
        weather, air = proof["http"]("weather", 1), proof["http"]("air_quality", 1)
        child = command("import sys;raw=sys.stdin.buffer.read();sys.stdout.buffer.write("
            + repr(air) + " if b'/air-quality ' in raw else " + repr(weather) + ")")
        diagnostic = T.TunnelDiagnostic(); diagnostic.active = True
        thread, outcome = self.run_server(supplied=child, observe_responses=True, diagnostic=diagnostic)
        for ordinal in (1, 2, 3):
            for route, expected in zip(T.ROUTES, (weather, air)):
                self.assertEqual(self.fetch(route), expected)
        thread.join(3)
        self.assertNotIn("error", outcome)
        result = outcome["result"]
        self.assertEqual(result["schema"], 6); self.assertEqual(len(result["responses"]), 6)
        for index, item in enumerate(result["responses"]):
            self.assertEqual(item["ordinal"], index // 2 + 1)
            self.assertFalse(item["joined_core_acceptance"])
        self.assertTrue(result["cleanup_confirmed"])
        self.assertNotIn('"forecast":', json.dumps(result))
        self.assertIsNone(diagnostic.primary)
        self.assertEqual(diagnostic.facts["completed"], 6)
        self.assertEqual(diagnostic.facts["requests"], dict(weather=3, air_quality=3))
        output = io.StringIO()
        with redirect_stdout(output): T.emit_diagnostic(diagnostic)
        self.assertEqual(output.getvalue(), "")

    def test_explicit_response_observer_rejects_unbound_json_without_forwarding(self):
        thread, outcome = self.run_server(observe_responses=True)
        self.assertEqual(self.fetch(T.ROUTES[0]), b"")
        thread.join(3)
        self.assertIsInstance(outcome.get("error"), (ValueError, KeyError))
        self.assertFalse(self.path.exists())

    def test_exchange_rejects_nonzero_exit_incomplete_header_and_oversized_stdout(self):
        for child in [command("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(" + repr(RESPONSE) + ");sys.exit(7)"),
                      responder(b"not http"), responder(b"HTTP/1.1 200 OK\r\n"),
                      responder(b"HTTP/1.1 200 OK\r\n\r\n" + b"a" * T.MAX_RESPONSE)]:
            with self.subTest(child=child[-1][:50]), self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
                self.exchange(child)

    def test_exchange_deadline_terminates_owned_child(self):
        marker = self.root / "pid.json"
        child = command("import os,time,json;from pathlib import Path;Path(" + repr(str(marker))
                        + ").write_text(json.dumps({'pid':os.getpid()}));time.sleep(20)")
        diagnostic = T.TunnelDiagnostic(); diagnostic.admitted(T.ROUTES[0], 1)
        with self.assertRaises((TimeoutError, subprocess.TimeoutExpired)):
            T.exchange(child, T.canonical_request(T.ROUTES[0]), time.monotonic() + .3, diagnostic=diagnostic)
        if marker.exists():
            self.assertFalse(live_process(json.loads(marker.read_text())["pid"]))
        value = diagnostic.record()
        self.assertEqual((value["primary"]["phase"], value["primary"]["reason"]), ("exchange-read", "deadline"))
        self.assertIsNone(value["primary"]["ssh_status"])
        self.assertIsNone(value["primary"]["http_status"])
        self.assertEqual(value["cleanup"], dict(exchange_child_joined=True, socket_removed=None))

    def test_bounded_guest_input_reader_requires_eof_before_original_deadline(self):
        good = T.canonical_request(T.ROUTES[0])
        for payload, accepted in ((good, True), (b"x" * (T.MAX_REQUEST + 1), False)):
            read_fd, write_fd = os.pipe()
            with os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as writer:
                writer.write(payload)
                writer.close()
                if accepted:
                    self.assertEqual(T.read_until_eof(reader, T.MAX_REQUEST, time.monotonic() + 2), good)
                else:
                    with self.assertRaises(ValueError):
                        T.read_until_eof(reader, T.MAX_REQUEST, time.monotonic() + 2)
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as writer:
            writer.write(good)
            writer.flush()
            with self.assertRaises(TimeoutError):
                T.read_until_eof(reader, T.MAX_REQUEST, time.monotonic() + .05)
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as writer:
            writer.write(good)
            writer.close()
            with self.assertRaises(TimeoutError):
                T.read_until_eof(reader, T.MAX_REQUEST, time.monotonic() - 1)

    def test_exited_leader_cannot_leave_same_group_descendant_after_deadline(self):
        marker = self.root / "descendant.json"
        child = command("import os,time,json;from pathlib import Path\n"
                        "if os.fork(): os._exit(0)\n"
                        "Path(" + repr(str(marker)) + ").write_text(json.dumps({'pid':os.getpid()}))\n"
                        "time.sleep(20)\n")
        descendant = None
        try:
            with self.assertRaises((TimeoutError, subprocess.TimeoutExpired)):
                self.exchange(child, seconds=.3)
            self.assertTrue(marker.exists(), "descendant actually started")
            descendant = json.loads(marker.read_text())["pid"]
            self.assertFalse(live_process(descendant), "owned descendant survives direct leader exit")
        finally:
            if descendant is None and marker.exists():
                descendant = json.loads(marker.read_text())["pid"]
            if descendant and live_process(descendant):
                os.kill(descendant, signal.SIGKILL)

    def test_serve_forwards_three_of_each_and_removes_only_owned_socket(self):
        thread, outcome = self.run_server()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        sibling = self.parent / "later-unrelated-file"
        sibling.write_bytes(b"preserve me")
        for _ in range(3):
            for route in T.ROUTES:
                self.assertEqual(self.fetch(route), RESPONSE)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", outcome)
        report = outcome["result"]
        self.assertEqual(report["completed"], 6)
        self.assertEqual(report["requests"], dict.fromkeys(T.ROUTES, 3))
        self.assertTrue(report["original_response_bytes"])
        self.assertFalse(report["joined_core_acceptance"])
        self.assertTrue(report["cleanup_confirmed"])
        self.assertEqual(list(self.parent.iterdir()), [sibling])
        self.assertEqual(sibling.read_bytes(), b"preserve me")

    def test_signal_during_active_exchange_joins_child_and_removes_owned_socket(self):
        marker = self.root / "signal-child.json"
        supplied = command("import os,time,json;from pathlib import Path;Path(" + repr(str(marker))
                           + ").write_text(json.dumps({'pid':os.getpid()}));time.sleep(20)")
        # Invoke only pure serve(), not the root-only guest or hosted-only CLI.
        # The wrapper installs the same interrupt exception used by the CLI.
        source = ("import runpy,signal;from pathlib import Path\n"
                  "m=runpy.run_path(" + repr(str(HERE / "weather-android-tunnel.py")) + ")\n"
                  "def interrupted(*_):\n print('SIGNAL',flush=True)\n raise m['TunnelInterrupted']('synthetic interruption')\n"
                  "signal.signal(signal.SIGTERM,interrupted)\n"
                  "try:\n m['serve'](Path(" + repr(str(self.path)) + ")," + repr(supplied)
                  + ",lifetime=5,notify=lambda:print('READY',flush=True))\n"
                  "except m['TunnelInterrupted']: print('INTERRUPTED',flush=True)\n")
        runner = subprocess.Popen(command(source), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, start_new_session=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(runner.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(3))
                self.assertEqual(runner.stdout.readline(), b"READY\n")
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(3)
                client.connect(str(self.path))
                client.sendall(T.canonical_request(T.ROUTES[0]))
                until = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < until:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), "actual exchange child reached")
                child_pid = json.loads(marker.read_text())["pid"]
                self.assertTrue(live_process(child_pid))
                runner.send_signal(signal.SIGTERM)
                stdout, stderr = runner.communicate(timeout=5)
                self.assertEqual(runner.returncode, 0, stderr.decode())
                self.assertEqual(stdout, b"SIGNAL\nINTERRUPTED\n")
                self.assertEqual(stderr, b"")
                self.assertFalse(live_process(child_pid))
                self.assertFalse(self.path.exists())
        finally:
            if runner.poll() is None:
                runner.kill()
            runner.communicate(timeout=3)
            if marker.exists():
                child_pid = json.loads(marker.read_text())["pid"]
                if live_process(child_pid):
                    os.kill(child_pid, signal.SIGKILL)

    def test_client_disconnect_cancels_and_joins_exchange_without_waiting_full_lifetime(self):
        marker = self.root / "disconnect-child.json"
        supplied = command("import os,time,json;from pathlib import Path;Path(" + repr(str(marker))
                           + ").write_text(json.dumps({'pid':os.getpid()}));time.sleep(20)")
        diagnostic = T.TunnelDiagnostic()
        thread, outcome = self.run_server(supplied=supplied, diagnostic=diagnostic)
        child_pid = None
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(self.path))
                client.sendall(T.canonical_request(T.ROUTES[0]))
                until = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < until:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), "actual exchange child reached")
                child_pid = json.loads(marker.read_text())["pid"]
            thread.join(2)
            self.assertFalse(thread.is_alive(), "disconnect retained the live exchange")
            self.assertIsInstance(outcome.get("error"), BrokenPipeError)
            self.assertFalse(live_process(child_pid))
            self.assertFalse(self.path.exists())
            value = diagnostic.record()
            self.assertEqual((value["primary"]["phase"], value["primary"]["reason"]),
                ("exchange-client", "client-disconnected"))
            self.assertIsNone(value["primary"]["ssh_status"])
            self.assertIsNone(value["primary"]["http_status"])
            self.assertEqual(value["cleanup"], dict(exchange_child_joined=True, socket_removed=True))
        finally:
            if child_pid and live_process(child_pid):
                os.kill(child_pid, signal.SIGKILL)

    def test_hold_open_retains_same_socket_after_six_requests_until_owner_signal(self):
        source = ("import runpy,signal,json;from pathlib import Path\n"
                  "m=runpy.run_path(" + repr(str(HERE / "weather-android-tunnel.py")) + ")\n"
                  "def interrupted(*_): raise m['TunnelInterrupted']('synthetic interruption')\n"
                  "signal.signal(signal.SIGTERM,interrupted)\n"
                  "result=m['serve'](Path(" + repr(str(self.path)) + ")," + repr(responder())
                  + ",lifetime=5,hold_open=True,notify=lambda:print('READY',flush=True))\n"
                  "print(json.dumps(result),flush=True)\n")
        runner = subprocess.Popen(command(source), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, start_new_session=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(runner.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(3))
                self.assertEqual(runner.stdout.readline(), b"READY\n")
            identity = self.path.stat()
            for _ in range(3):
                for route in T.ROUTES:
                    self.assertEqual(self.fetch(route), RESPONSE)
            self.assertIsNone(runner.poll())
            self.assertEqual((self.path.stat().st_dev, self.path.stat().st_ino),
                             (identity.st_dev, identity.st_ino))
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            runner.send_signal(signal.SIGTERM)
            stdout, stderr = runner.communicate(timeout=5)
            self.assertEqual(runner.returncode, 0, stderr.decode())
            value = json.loads(stdout)
            self.assertEqual(value["completed"], 6)
            self.assertEqual(value["requests"], dict.fromkeys(T.ROUTES, 3))
            self.assertTrue(value["cleanup_confirmed"])
            self.assertFalse(value["joined_core_acceptance"])
            self.assertFalse(self.path.exists())
            self.assertEqual(stderr, b"")
        finally:
            if runner.poll() is None:
                runner.kill()
            runner.communicate(timeout=3)

    def test_hold_open_rejects_seventh_request_and_invalid_mode(self):
        for value in (1, "yes", None):
            with self.assertRaises(ValueError):
                T.serve(self.path, responder(), hold_open=value)
        ready, outcome = threading.Event(), {}
        def run():
            try:
                outcome["result"] = T.serve(self.path, responder(), lifetime=5, hold_open=True, notify=ready.set)
            except BaseException as error:
                outcome["error"] = error
        thread = threading.Thread(target=run)
        thread.start()
        self.addCleanup(thread.join, 6)
        self.assertTrue(ready.wait(3))
        for _ in range(3):
            for route in T.ROUTES:
                self.assertEqual(self.fetch(route), RESPONSE)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect(str(self.path))
            self.assertEqual(client.recv(1), b"")
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(outcome.get("error"), ValueError)
        self.assertNotIn("result", outcome)
        self.assertFalse(self.path.exists())

    def test_custom_signal_exception_is_not_swallowed_as_selector_eintr(self):
        self.assertFalse(issubclass(T.TunnelInterrupted, InterruptedError))
        self.assertFalse(issubclass(T.TunnelInterrupted, OSError))

    def test_ready_eof_after_deadline_cannot_complete_request_reader(self):
        left, right = os.pipe()
        original_read, original_clock = os.read, time.monotonic
        offset = [0]
        def read(fd, length):
            value = original_read(fd, length)
            if fd == left and not value:
                offset[0] = 10
            return value
        with os.fdopen(left, "rb") as reader, os.fdopen(right, "wb") as writer:
            writer.write(T.canonical_request(T.ROUTES[0]))
            writer.close()
            deadline = original_clock() + 2
            with patch.object(T, "time", SimpleNamespace(monotonic=lambda: original_clock() + offset[0])), \
                    patch.object(T.os, "read", side_effect=read), self.assertRaises(TimeoutError):
                T.read_until_eof(reader, T.MAX_REQUEST, deadline)

    def test_completed_child_with_late_eof_cannot_be_accepted_after_deadline(self):
        original_read, original_clock, original_spawn = os.read, time.monotonic, subprocess.Popen
        owned, offset = {}, [0]
        def spawn(*args, **kwargs):
            child = original_spawn(*args, **kwargs)
            owned["child"] = child
            return child
        def read(fd, length):
            value = original_read(fd, length)
            child = owned.get("child")
            if child is not None and fd == child.stdout.fileno() and not value:
                # The child genuinely finished; emulate scheduling delay at EOF,
                # not an earlier timeout that could conceal a missing final gate.
                self.assertEqual(child.wait(timeout=2), 0)
                offset[0] = 10
            return value
        deadline = original_clock() + 2
        diagnostic = T.TunnelDiagnostic(); diagnostic.admitted(T.ROUTES[0], 1)
        with patch.object(T, "time", SimpleNamespace(monotonic=lambda: original_clock() + offset[0], sleep=time.sleep)), \
                patch.object(T.subprocess, "Popen", side_effect=spawn), patch.object(T.os, "read", side_effect=read), \
                self.assertRaises(TimeoutError):
            T.exchange(responder(), T.canonical_request(T.ROUTES[0]), deadline, diagnostic=diagnostic)
        value = diagnostic.record()
        self.assertEqual((value["primary"]["phase"], value["primary"]["reason"]), ("exchange-deadline", "deadline"))
        self.assertEqual((value["primary"]["ssh_status"], value["primary"]["http_status"]), (0, "200"))
        self.assertTrue(value["cleanup"]["exchange_child_joined"])

    def test_forward_response_copies_exact_bytes_and_restores_prior_pipe_flags(self):
        for blocking in (False, True):
            upstream, source = socket.socketpair()
            read_fd, write_fd = os.pipe()
            with upstream, source, os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as sink:
                os.set_blocking(sink.fileno(), blocking)
                source.sendall(RESPONSE)
                source.shutdown(socket.SHUT_WR)
                T.forward_response(upstream, sink, time.monotonic() + 2)
                self.assertEqual(os.get_blocking(sink.fileno()), blocking)
                sink.close()
                self.assertEqual(reader.read(), RESPONSE)

    def test_full_response_pipe_has_deadline_and_restores_blocking_mode(self):
        upstream, source = socket.socketpair()
        read_fd, write_fd = os.pipe()
        with upstream, source, os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as sink:
            os.set_blocking(write_fd, False)
            filled = 0
            while True:
                try:
                    filled += os.write(write_fd, b"x" * 4096)
                    self.assertLessEqual(filled, 1024 * 1024)
                except BlockingIOError:
                    break
            self.assertGreater(filled, 0)
            os.set_blocking(write_fd, True)
            source.sendall(RESPONSE)
            source.shutdown(socket.SHUT_WR)
            with self.assertRaises(TimeoutError):
                T.forward_response(upstream, sink, time.monotonic() + .05)
            self.assertTrue(os.get_blocking(write_fd))

    def test_response_reader_disappearance_aborts_even_when_upstream_is_idle(self):
        upstream, source = socket.socketpair()
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        with upstream, source, os.fdopen(write_fd, "wb") as sink:
            with self.assertRaises(BrokenPipeError):
                T.forward_response(upstream, sink, time.monotonic() + 2)
            self.assertTrue(os.get_blocking(write_fd))

    def test_response_reader_disappearance_during_pipe_backpressure_aborts_and_restores_flags(self):
        upstream, source = socket.socketpair()
        read_fd, write_fd = os.pipe()
        with upstream, source, os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as sink:
            os.set_blocking(write_fd, False)
            filled = 0
            while True:
                try:
                    filled += os.write(write_fd, b"x" * 4096)
                    self.assertLessEqual(filled, 1024 * 1024)
                except BlockingIOError:
                    break
            os.set_blocking(write_fd, True)
            source.sendall(RESPONSE)
            source.shutdown(socket.SHUT_WR)
            def disconnect():
                time.sleep(.05)
                reader.close()
            thread = threading.Thread(target=disconnect)
            thread.start()
            try:
                with self.assertRaises(BrokenPipeError):
                    T.forward_response(upstream, sink, time.monotonic() + 2)
            finally:
                thread.join(2)
            self.assertTrue(os.get_blocking(write_fd))

    def test_fourth_same_product_is_not_forwarded(self):
        thread, outcome = self.run_server()
        for _ in range(3):
            self.assertEqual(self.fetch(T.ROUTES[0]), RESPONSE)
        self.assertEqual(self.fetch(T.ROUTES[0]), b"")
        thread.join(2)
        self.assertIsInstance(outcome.get("error"), ValueError)
        self.assertFalse(self.path.exists())

    def test_parent_scope_wrong_name_existing_entries_or_symlink_are_not_adopted(self):
        for mode in (0o750, 0o770, 0o1700):
            self.parent.chmod(mode)
            with self.assertRaises(ValueError):
                T.serve(self.path, responder(), lifetime=1)
            self.assertEqual(stat.S_IMODE(self.parent.stat().st_mode), mode)
        self.parent.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.parent, target_is_directory=True)
        for path in (alias / self.path.name, self.parent / "other.sock", self.root / "missing/core-api.sock"):
            with self.assertRaises((ValueError, OSError)):
                T.serve(path, responder(), lifetime=1)
        self.path.symlink_to(self.root / "missing")
        with self.assertRaises(ValueError):
            T.serve(self.path, responder(), lifetime=1)
        self.assertTrue(self.path.is_symlink())
        self.path.unlink()
        self.path.write_bytes(b"existing socket-name file")
        with self.assertRaises(ValueError):
            T.serve(self.path, responder(), lifetime=1)
        self.assertEqual(self.path.read_bytes(), b"existing socket-name file")

    def test_socket_replacement_is_preserved_and_cannot_claim_cleanup(self):
        original = self.parent / "moved.sock"
        def replace():
            self.path.rename(original)
            self.path.write_bytes(b"unrelated replacement")
        thread, outcome = self.run_server(notify=replace)
        for _ in range(3):
            for route in T.ROUTES:
                self.assertEqual(self.fetch(route, path=original), RESPONSE)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.path.read_bytes(), b"unrelated replacement")
        self.assertTrue(original.is_socket())
        self.assertFalse(outcome.get("result", {}).get("cleanup_confirmed", True))

    def test_parent_replacement_is_preserved_and_cannot_claim_cleanup(self):
        moved = self.root / "moved"
        def replace():
            self.parent.rename(moved)
            self.parent.mkdir(mode=0o700)
            self.path.write_bytes(b"unrelated replacement parent")
        thread, outcome = self.run_server(notify=replace)
        for _ in range(3):
            for route in T.ROUTES:
                self.assertEqual(self.fetch(route, path=moved / self.path.name), RESPONSE)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.path.read_bytes(), b"unrelated replacement parent")
        self.assertFalse(outcome.get("result", {}).get("cleanup_confirmed", True))

    def test_ssh_argv_is_pinned_and_never_uses_caller_forwarding_or_guest_paths(self):
        key, hosts = self.root / "key", self.root / "known-hosts"
        for path in (key, hosts):
            path.write_bytes(b"synthetic fixture only")
            path.chmod(0o600)
        argv = T.ssh_command(key, hosts)
        self.assertEqual(argv[0], "/usr/bin/ssh")
        for option in ("IdentityAgent=none", "IdentitiesOnly=yes", "BatchMode=yes",
                       "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null",
                       "ProxyCommand=none", "ProxyJump=none", "ClearAllForwardings=yes"):
            self.assertIn(option, argv)
        self.assertEqual(argv[-7:], ["vpci@127.0.0.1", "/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", T.GUEST_HELPER, "guest"])
        key.chmod(0o644)
        with self.assertRaises(ValueError):
            T.ssh_command(key, hosts)


if __name__ == "__main__":
    unittest.main()
