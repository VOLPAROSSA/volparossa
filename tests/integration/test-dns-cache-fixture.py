#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Socket-free fixture checks; synthetic signatures never claim DNSSEC proof."""
import contextlib
import copy
import importlib.util
import io
import ipaddress
import json
import os
import signal
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("dns_cache_fixture", Path(__file__).with_name("dns-cache-fixture.py"))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def synthetic_response(question, now_ms, *, signed=True, owner=None, ttl=300):
    """Only wire shape is plausible; these placeholder signature bytes cannot verify."""
    name, kind = question
    owner = name if owner is None else owner
    if kind == 1:
        data = ipaddress.ip_address("1.1.1.1").packed
    elif kind == 28:
        data = ipaddress.ip_address("2606:4700:4700::1111").packed
    elif kind == 48:
        data = struct.pack("!HBB", 257, 3, 8) + bytes(128)
    else:
        data = struct.pack("!HBB", 20326, 8, 2) + bytes(32)

    def record(kind, data):
        return FIXTURE.name_wire(owner) + struct.pack("!HHIH", kind, 1, ttl, len(data)) + data

    records = record(kind, data)
    if signed:
        signature = struct.pack("!HBBIIIH", kind, 8, 0 if owner == "." else len(owner.split(".")),
                                300, now_ms // 1000 + 3600, now_ms // 1000 - 60, 20326)
        signature += FIXTURE.name_wire(name) + bytes(64)
        records += record(46, signature)
    return struct.pack("!6H", 321, 0x81A0, 1, 2 if signed else 1, 0, 0) \
        + FIXTURE.name_wire(name) + struct.pack("!HH", kind, 1) + records


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="volparossa-dns-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.now = int(time.time() * 1000)

    def recording(self):
        root = self.parent / "recording"
        with mock.patch.object(FIXTURE, "fetch_wire", side_effect=lambda question, _: synthetic_response(question, self.now)), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            FIXTURE.collect(root)
        self.assertFalse(json.loads(output.getvalue())["cryptographically_verified"])
        return root

    def test_failure_keeps_fixed_shape_reason_but_not_raw_remote_text(self):
        with mock.patch.object(FIXTURE, "fetch_wire", return_value=b"short"):
            with self.assertRaises(FIXTURE.FixtureError) as raised:
                FIXTURE.collect(self.parent / "failed")
        self.assertEqual(FIXTURE.failure_summary(raised.exception),
                         "DNS fixture failed: FixtureError: collect iana.org A: DNS wire size")
        for error in (ValueError("remote secret text"), OSError("private path"),
                      KeyError("remote key")):
            self.assertEqual(FIXTURE.failure_summary(error),
                             "DNS fixture failed: " + type(error).__name__)
        self.assertFalse((self.parent / "failed").exists())

    def test_collection_refreshes_expiring_public_records_without_renewing_old_bytes(self):
        now = [self.now / 1000]
        calls = []
        question = FIXTURE.QUESTIONS[0]
        def fetch(current, remaining):
            self.assertGreater(remaining, 0)
            calls.append(current)
            return synthetic_response(current, int(now[0] * 1000), ttl=5 if len(calls) == 1 else 300)
        def advance(seconds):
            self.assertGreaterEqual(seconds, 0)
            self.assertLessEqual(seconds, 1)
            now[0] += seconds
        root = self.parent / "fresh"
        with mock.patch.object(FIXTURE.time, "time", side_effect=lambda: now[0]), \
                mock.patch.object(FIXTURE.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(FIXTURE.time, "sleep", side_effect=advance), \
                mock.patch.object(FIXTURE, "fetch_wire", side_effect=fetch), \
                contextlib.redirect_stdout(io.StringIO()):
            FIXTURE.collect(root)
        self.assertEqual(calls, list(FIXTURE.QUESTIONS) + [question])
        self.assertGreaterEqual(now[0] * 1000, self.now + 5000)
        recording = FIXTURE.read_json(root / "recording.json")
        fresh = recording["records"][0]
        self.assertGreaterEqual(fresh["received_at_unix_ms"], self.now + 5000)
        for prior in recording["records"][1:]:
            self.assertEqual(prior["received_at_unix_ms"], self.now)
            self.assertEqual(prior["minimum_ttl_seconds"], 300)
        self.assertEqual(recording["expires_at_unix_ms"], self.now + 300_000)
        FIXTURE.load_recording(root, int(now[0] * 1000))

    def test_collection_refresh_has_fixed_round_budget_and_never_accepts_short_ttl(self):
        now = [self.now / 1000]
        def advance(seconds):
            now[0] += seconds
        root = self.parent / "short"
        with mock.patch.object(FIXTURE.time, "time", side_effect=lambda: now[0]), \
                mock.patch.object(FIXTURE.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(FIXTURE.time, "sleep", side_effect=advance), \
                mock.patch.object(FIXTURE, "fetch_wire", side_effect=lambda q, _: \
                    synthetic_response(q, int(now[0] * 1000), ttl=50)) as fetch:
            with self.assertRaisesRegex(FIXTURE.FixtureError, "insufficient original TTL for fixture"):
                FIXTURE.collect(root)
        self.assertEqual(fetch.call_count, len(FIXTURE.QUESTIONS) * FIXTURE.MAX_COLLECTION_ROUNDS)
        self.assertLess(now[0] - self.now / 1000, FIXTURE.MAX_COLLECTION_SECONDS)
        self.assertFalse(root.exists())

    def test_shape_ad_alone_substitution_and_real_time_are_not_proof(self):
        for question in FIXTURE.QUESTIONS:
            wire = synthetic_response(question, self.now)
            parsed = FIXTURE.inspect_response(wire, question, self.now)
            self.assertTrue(parsed["signatures"])
            with self.assertRaises(ValueError):
                FIXTURE.inspect_response(synthetic_response(question, self.now, signed=False), question, self.now)
            with self.assertRaises(ValueError):
                FIXTURE.inspect_response(synthetic_response(question, self.now, owner="different.example"), question, self.now)
            with self.assertRaises(ValueError):
                FIXTURE.inspect_response(wire, question, self.now + 3_601_000)
        with self.assertRaises(ValueError):
            FIXTURE.read_name(b"\xc0\0", 0)

    def test_replay_only_changes_id_ad_and_decreasing_ttls(self):
        root = self.recording()
        records = FIXTURE.load_recording(root, self.now + 2000)
        question = FIXTURE.CANDIDATE, 1
        old, received, parsed = records[question]
        new, answer_question = FIXTURE.replay_response(FIXTURE.query_wire(*question, 987), records,
                                                      received + 2000)
        self.assertEqual(answer_question, question)
        self.assertEqual(struct.unpack_from("!H", new)[0], 987)
        self.assertFalse(struct.unpack_from("!H", new, 2)[0] & 0x20)
        allowed = {0, 1, 2, 3}
        for offset, ttl in parsed["ttl_offsets"]:
            allowed.update(range(offset, offset + 4))
            self.assertEqual(struct.unpack_from("!I", new, offset)[0], ttl - 2)
        self.assertTrue(all(a == b for i, (a, b) in enumerate(zip(old, new)) if i not in allowed))
        newer, _ = FIXTURE.replay_response(FIXTURE.query_wire(*question, 987), records,
                                           received + 1000, elapsed_ms=4000)
        self.assertTrue(all(struct.unpack_from("!I", newer, offset)[0] == ttl - 4
                            for offset, ttl in parsed["ttl_offsets"]))
        with self.assertRaises(ValueError):
            FIXTURE.replay_response(FIXTURE.query_wire(*question, 987), records, received + 300_000)

    def test_recording_provenance_hash_and_expiry_cannot_be_renewed(self):
        root = self.recording()
        index = FIXTURE.read_json(root / "recording.json")
        self.assertEqual(len(index["records"]), 7)
        self.assertEqual(len(FIXTURE.read_json(root / "a-proof.json")["messages"]), 6)
        self.assertEqual(len(FIXTURE.read_json(root / "aaaa-proof.json")["messages"]), 6)
        for mutation in ("hash", "expiry", "received", "source"):
            changed = copy.deepcopy(index)
            if mutation == "hash":
                changed["records"][0]["sha256"] = "0" * 64
            elif mutation == "expiry":
                changed["expires_at_unix_ms"] += 1
            elif mutation == "received":
                changed["records"][0]["received_at_unix_ms"] += 60_000
            else:
                changed["source_url"] = "https://unconfigured.example/dns-query"
            with mock.patch.object(FIXTURE, "read_json", return_value=changed):
                with self.assertRaises(ValueError):
                    FIXTURE.load_recording(root, int(time.time() * 1000))
        with self.assertRaises(ValueError):
            FIXTURE.load_recording(root, self.now + 301_000)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                FIXTURE.require_isolated()
        with mock.patch.dict(os.environ, {"VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS": os.readlink("/proc/self/ns/net")}):
            with self.assertRaises(ValueError):
                FIXTURE.require_isolated()

    def test_core_gate_rejects_fallback_missing_family_and_fake_local_hit(self):
        root = self.recording()
        records = FIXTURE.load_recording(root, int(time.time() * 1000))
        answers = []
        for kind, family in ((1, "A"), (28, "AAAA")):
            _, received, parsed = records[(FIXTURE.CANDIDATE, kind)]
            answers.append({"schema": 1, "family": family, "source": "UpstreamValidated",
                            "local_reuse": True, "builtin_anchors": True, "ttl_seconds": 200,
                            "expires_at_ms": received + 200_000, "proof_sha256": "a" * 64,
                            "addresses": parsed["addresses"]})
        replay = {"listener_closed": True, "bounded_stop": True, "connections": 12, "rejected": 0,
                  "responses": {name + ":" + FIXTURE.TYPE_NAMES[kind]: 1 for name, kind in FIXTURE.QUESTIONS}}
        for index, mutation in enumerate(("valid-synthetic-gate", "fallback", "one-family", "custom-anchor", "query-again")):
            output = self.parent / ("output-" + str(index))
            output.mkdir()
            changed_answers, changed_replay = copy.deepcopy(answers), copy.deepcopy(replay)
            if mutation == "fallback":
                changed_answers[0]["source"] = "TrustedFallback"
            elif mutation == "one-family":
                changed_answers.pop()
            elif mutation == "custom-anchor":
                changed_answers[0]["builtin_anchors"] = False
            elif mutation == "query-again":
                changed_replay["responses"][FIXTURE.CANDIDATE + ":A"] = 2
            (output / "core.jsonl").write_text("\n".join(map(json.dumps, changed_answers)) + "\n")
            FIXTURE.write_new(output / "replay.json", changed_replay)
            if index == 0:
                FIXTURE.validate_core(root, output)
                proof = FIXTURE.read_json(output / "proof.json")
                self.assertFalse(proof["peer_cache_proven"])
                self.assertFalse(proof["normal_client_route_proven"])
            else:
                with self.assertRaises(ValueError):
                    FIXTURE.validate_core(root, output)
                self.assertFalse((output / "proof.json").exists())


class RecoveryTests(unittest.TestCase):
    """Synthetic gate/ownership tests; actual DNSSEC remains the hosted Rust proof."""

    setUp = FixtureTests.setUp
    recording = FixtureTests.recording

    def evidence(self, root, output):
        records = FIXTURE.load_recording(root, int(time.time() * 1000))
        rows = []
        for kind, family in ((1, "A"), (28, "AAAA")):
            _, received, expected = records[(FIXTURE.CANDIDATE, kind)]
            row = dict(schema=2, family=family, builtin_anchors=True, cold_outage_error=True)
            for phase, source, ttl in (("warm", "UpstreamValidated", 200), ("outage", "LocalValidated", 199),
                                       ("recovered", "UpstreamValidated", 198)):
                row[phase] = dict(source=source, ttl_seconds=ttl, expires_at_ms=received + 200_000,
                                  proof_sha256="a" * 64, addresses=expected["addresses"])
            rows.append(row)
        rows.append(dict(schema=2, accounting=copy.deepcopy(FIXTURE.RECOVERY_COUNTS)))
        report = dict(schema_version=1, listener_closed=True, bounded_stop=True, cryptographically_verified=False,
                      connections=len(FIXTURE.QUESTIONS), rejected=0,
                      responses={name + ":" + FIXTURE.TYPE_NAMES[kind]: 1 for name, kind in FIXTURE.QUESTIONS})
        return rows, report

    def gate(self, root, output, rows, report, *, children=None, digest=None):
        (output / "core.jsonl").write_text("\n".join(map(json.dumps, rows)) + "\n")
        for phase in ("first", "second"):
            FIXTURE.write_new(output / (phase + "-replay.json"), report)
        FIXTURE.validate_recovery(root, output,
            children if children is not None else dict(probe_joined=True, first_replay_joined=True,
                                                      second_replay_joined=True, listeners_closed=True),
            digest if digest is not None else FIXTURE.hashlib.sha256(
                FIXTURE.read_bounded(root / "recording.json")).hexdigest())

    def test_recovery_gate_binds_both_families_original_recording_and_false_scope_claims(self):
        root, output = self.recording(), self.parent / "recovery"
        output.mkdir()
        self.gate(root, output, *self.evidence(root, output))
        proof = FIXTURE.read_json(output / "proof.json")
        self.assertEqual(proof["schema_version"], 2)
        self.assertEqual([row["family"] for row in proof["core"]], ["A", "AAAA"])
        for key in ("natural_expiry_proven", "peer_cache_proven", "normal_client_route_proven"):
            self.assertIs(proof[key], False)
        self.assertEqual(proof["recovery"]["warm_counts"], FIXTURE.RECOVERY_COUNTS["warm_counts"])
        self.assertEqual(proof["recovery"]["phase_count"], 3)

    def test_recovery_gate_rejects_source_ttl_address_schema_accounting_and_cleanup_mutation(self):
        root = self.recording()
        mutations = ("family", "anchor", "cold-success", "source", "ttl", "expiry", "address", "hash",
                     "extra", "schema-bool", "counter-bool", "fallback", "cleanup", "recording", "replay")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                output = self.parent / ("case-" + mutation)
                output.mkdir()
                rows, report = self.evidence(root, output)
                children, digest = None, None
                if mutation == "family": rows[1]["family"] = "A"
                elif mutation == "anchor": rows[0]["builtin_anchors"] = False
                elif mutation == "cold-success": rows[0]["cold_outage_error"] = False
                elif mutation == "source": rows[0]["outage"]["source"] = "UpstreamValidated"
                elif mutation == "ttl": rows[0]["recovered"]["ttl_seconds"] = 201
                elif mutation == "expiry": rows[0]["outage"]["expires_at_ms"] = self.now + 301_000
                elif mutation == "address": rows[0]["warm"]["addresses"] = ["8.8.8.8"]
                elif mutation == "hash": rows[0]["recovered"]["proof_sha256"] = "private-text"
                elif mutation == "extra": rows[0]["private_query"] = "must refuse"
                elif mutation == "schema-bool": rows[0]["schema"] = True
                elif mutation == "counter-bool": rows[2]["accounting"]["cold_outage_counts"]["local_validated"] = False
                elif mutation == "fallback": rows[2]["accounting"]["recovered_counts"]["trusted_fallback"] = 1
                elif mutation == "cleanup": children = dict(probe_joined=False)
                elif mutation == "recording": digest = "0" * 64
                else: report["responses"]["iana.org:A"] = 2
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.gate(root, output, rows, report, children=children, digest=digest)
                self.assertFalse((output / "proof.json").exists())

    def test_recovery_phase_accepts_only_exact_order_and_bounded_frames(self):
        for expected in FIXTURE.RECOVERY_FRAMES:
            connection = mock.Mock()
            connection.recv.side_effect = [bytes([byte]) for byte in expected]
            FIXTURE.receive_phase(connection, expected, time.monotonic() + 1)
            self.assertTrue(all(call.args[0] > 0 for call in connection.settimeout.call_args_list))
        for raw in (FIXTURE.RECOVERY_FRAMES[1], b"unknown\n", b"x" * 128, b"partial"):
            connection = mock.Mock()
            connection.recv.side_effect = [bytes([byte]) for byte in raw] + [b""]
            with self.assertRaises(FIXTURE.FixtureError):
                FIXTURE.receive_phase(connection, FIXTURE.RECOVERY_FRAMES[0], time.monotonic() + 1)
            self.assertLessEqual(connection.recv.call_count, 128)

    def test_recovery_phase_timeout_eof_and_ack_errors_preserve_original(self):
        error = TimeoutError("not retained in summary")
        connection = mock.Mock()
        connection.recv.side_effect = error
        with self.assertRaises(TimeoutError) as raised:
            FIXTURE.receive_phase(connection, FIXTURE.RECOVERY_FRAMES[0], time.monotonic() + 1)
        self.assertIs(raised.exception, error)
        self.assertEqual(FIXTURE.failure_summary(error), "DNS fixture failed: TimeoutError")
        connection.reset_mock(side_effect=True)
        connection.recv.return_value = b""
        with self.assertRaisesRegex(FIXTURE.FixtureError, "phase EOF"):
            FIXTURE.receive_phase(connection, FIXTURE.RECOVERY_FRAMES[0], time.monotonic() + 1)
        with self.assertRaises(FIXTURE.FixtureError):
            FIXTURE.send_phase(connection, b"untrusted command\n", time.monotonic() + 1)
        connection.sendall.assert_not_called()
        with self.assertRaisesRegex(FIXTURE.FixtureError, "total deadline"):
            FIXTURE.receive_phase(connection, FIXTURE.RECOVERY_FRAMES[0], time.monotonic() - 1)

    def test_recovery_early_exit_prevents_readiness_or_handshake_success(self):
        child = mock.Mock(pid=102)
        child.poll.return_value = 7
        with self.assertRaisesRegex(FIXTURE.FixtureError, "exited before ready"):
            FIXTURE.wait_ready(self.parent / "absent", child, time.monotonic() + 1)
        listener = mock.Mock()
        with self.assertRaisesRegex(FIXTURE.FixtureError, "exited before handshake"):
            FIXTURE.accept_probe(listener, child, time.monotonic() + 1)
        listener.accept.assert_not_called()

    def test_recovery_join_escalates_only_owned_handle_and_never_renews_deadline(self):
        child = mock.Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("fixed", 0.5), 0]
        deadline = time.monotonic() + 1
        self.assertEqual(FIXTURE.join_child(child, deadline, stop=True), 0)
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertLessEqual(child.wait.call_args_list[0].kwargs["timeout"], 0.5)
        self.assertLessEqual(child.wait.call_args_list[1].kwargs["timeout"], 1)
        child.reset_mock(side_effect=True)
        child.poll.return_value = 0
        child.wait.return_value = 0
        FIXTURE.join_child(child, deadline, stop=True)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def controlled_exercise(self, *, bad_frame=False, bad_peer=False, early_exit=False, cleanup_error=False, phase_error=None, cancel=False):
        root = self.recording()
        output = self.parent / "exercise"
        output.mkdir(mode=0o700)
        binary = self.parent / "probe"
        binary.write_bytes(b"fixture source is never executed by these unit tests")
        binary.chmod(0o700)
        rows, report = self.evidence(root, output)
        events, children = [], []
        connection, listener = mock.Mock(), mock.Mock()
        frames = b"".join(FIXTURE.RECOVERY_FRAMES)
        if bad_frame: frames = b"wrong\n"
        connection.recv.side_effect = [bytes([byte]) for byte in frames] + [b""]
        if phase_error is not None:
            connection.recv.side_effect = phase_error
        elif cancel:
            connection.recv.side_effect = lambda _: signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        def bind(path): Path(path).touch(mode=0o600)
        listener.bind.side_effect = bind
        listener.accept.return_value = (connection, None)
        def popen(argv, **kwargs):
            label = "probe" if argv[0] == str(binary) else ("first" if not children else "second")
            child = mock.Mock(pid=100 + len(children))
            child.poll.return_value = 7 if label == "probe" and early_exit else None
            def wait(**_):
                events.append(label + "-joined")
                child.poll.return_value = 0
                if cleanup_error: raise OSError("private cleanup detail")
                return 0
            child.wait.side_effect = wait
            child.terminate.side_effect = lambda: events.append(label + "-stop")
            children.append(child)
            if label != "probe":
                FIXTURE.write_new(Path(argv[6]), report)
                FIXTURE.write_new(Path(argv[7]), dict(ready=True, listen=dict(ip="127.0.0.1", port=1053), pid=child.pid))
                events.append(label + "-ready")
            else:
                kwargs["stdout"].write(("\n".join(map(json.dumps, rows)) + "\n").encode())
                kwargs["stdout"].flush()
                connection.getsockopt.return_value = struct.pack("3i", child.pid + int(bad_peer), os.getuid(), os.getgid())
            return child
        connection.sendall.side_effect = lambda frame: events.append(frame)
        patches = (mock.patch.object(FIXTURE, "require_isolated"),
                   mock.patch.object(FIXTURE.socket, "socket", return_value=listener),
                   mock.patch.object(FIXTURE.subprocess, "Popen", side_effect=popen))
        with patches[0], patches[1], patches[2]:
            if bad_frame or bad_peer or early_exit or phase_error is not None or cancel:
                with self.assertRaises(type(phase_error) if phase_error is not None else FIXTURE.FixtureError) as raised:
                    FIXTURE.exercise_recovery(root, binary, output)
                if phase_error is not None:
                    self.assertIs(raised.exception, phase_error)
                else:
                    self.assertNotIn("private", str(raised.exception))
                self.assertFalse((output / "proof.json").exists())
            else:
                FIXTURE.exercise_recovery(root, binary, output)
        listener.close.assert_called_once_with()
        if not early_exit:
            connection.close.assert_called_once_with()
        return output, events, children

    def test_recovery_coordinator_joins_before_acks_and_success_and_closes_channel(self):
        output, events, children = self.controlled_exercise()
        self.assertLess(events.index("first-joined"), events.index(FIXTURE.RECOVERY_ACKS[0]))
        self.assertLess(events.index("second-ready"), events.index(FIXTURE.RECOVERY_ACKS[1]))
        self.assertIn("probe-joined", events)
        self.assertIn("second-joined", events)
        self.assertTrue((output / "proof.json").is_file())
        self.assertFalse((output / "phase.sock").exists())
        self.assertEqual(len(children), 3)
        self.assertTrue(all(child.wait.called for child in children))

    def test_recovery_coordinator_failure_reaps_every_started_child_without_success(self):
        _, events, children = self.controlled_exercise(bad_frame=True)
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.wait.called for child in children))
        self.assertNotIn(FIXTURE.RECOVERY_ACKS[0], events)

    def test_recovery_coordinator_peer_identity_fails_closed(self):
        self.controlled_exercise(bad_peer=True)

    def test_recovery_coordinator_early_exit_fails_closed(self):
        self.controlled_exercise(early_exit=True)

    def test_recovery_coordinator_timeout_preserves_primary_and_reaps_children(self):
        failure = TimeoutError("private socket detail")
        output, _, children = self.controlled_exercise(phase_error=failure)
        self.assertFalse((output / "proof.json").exists())
        self.assertTrue(all(child.wait.called for child in children))
        self.assertEqual(FIXTURE.failure_summary(failure), "DNS fixture failed: TimeoutError")

    def test_recovery_coordinator_cancellation_reaps_children_and_restores_handlers(self):
        handlers = {kind: signal.getsignal(kind) for kind in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        output, _, children = self.controlled_exercise(cancel=True)
        self.assertFalse((output / "proof.json").exists())
        self.assertTrue(all(child.wait.called for child in children))
        self.assertEqual(handlers, {kind: signal.getsignal(kind) for kind in handlers})

    def test_recovery_cleanup_failure_does_not_mask_primary_phase_error(self):
        output, events, children = self.controlled_exercise(bad_frame=True, cleanup_error=True)
        self.assertFalse((output / "proof.json").exists())
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.wait.called for child in children))



if __name__ == "__main__":
    unittest.main()
