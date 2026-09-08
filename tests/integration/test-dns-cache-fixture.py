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
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("dns_cache_fixture", Path(__file__).with_name("dns-cache-fixture.py"))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def synthetic_response(question, now_ms, *, signed=True, owner=None):
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
        return FIXTURE.name_wire(owner) + struct.pack("!HHIH", kind, 1, 300, len(data)) + data

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


if __name__ == "__main__":
    unittest.main()
