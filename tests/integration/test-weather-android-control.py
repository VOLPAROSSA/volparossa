#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Temporary owned files and inert Unix sockets; no root, SDK, VM or network."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import stat
import sys
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
C = runpy.run_path(str(HERE / "weather-android-control.py"))
G = C["publish"].__globals__
A = runpy.run_path(str(HERE / "weather-android-api.py"))
AG = A["validate_record"].__globals__
F = runpy.run_path(str(HERE / "test-weather-android-delivery.py"))


class RootController(unittest.TestCase):
    def setUp(self):
        self.fixture = F["AndroidPreparation"]("test_only_configuration_and_private_empty_directories_are_created")
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.work, self.layout = self.fixture.work, self.fixture.layout
        self.prepared = self.fixture.run_prepare()
        self.prepared_raw = C["encode"](self.prepared)
        self.prepared_sha = C["digest"](self.prepared_raw)
        self.fixture.save(self.work / "weather-android-delivery-prepared.json", self.prepared_raw)
        self.fixture.save(self.layout["viewer"] / "prepared.json", self.prepared_raw, 0o400)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.socket.close)
        self.socket.bind(str(self.layout["socket"]))
        self.layout["socket"].chmod(0o600)
        self.state = self.work / "controller"
        d = dict(F["A"]); d.update(F["G"])
        for seam in (patch.dict(AG, D=d), patch.dict(G, ROOT_UID=os.getuid(), WORKER_UID=os.getuid(), STATE=self.state,
                accounts=lambda group: (os.getuid(), os.getgid()),
                work_directory=lambda path: C["owned"](path, 0o755, directory=True),
                api_module=lambda work: dict(A, D=d))):
            seam.start(); self.addCleanup(seam.stop)
        self.expiry = int(time.time()) + 700
        info = self.layout["socket"].lstat()
        self.ready = dict(schema=6, kind="weather-android-api-ready", profile="android-protected-core-v6",
            manifest_sha256=self.fixture.digest, prepared_sha256=self.prepared_sha,
            config_sha256=self.prepared["config_sha256"], core_sha256=self.prepared["core_sha256"],
            socket=dict(device=info.st_dev, inode=info.st_ino, user_uid=os.getuid(), mode="0600"),
            started_at_ms=int(time.time() * 1000) - 10, ready_at_ms=int(time.time() * 1000), expires_at=self.expiry,
            cold_caches_absent=True, helper_requests=0, joined_delivery_proven=False)
        self.save_ready()

    def save_ready(self, raw=None):
        self.fixture.save(self.work / "weather-android-delivery-api.jsonl", raw or C["encode"](self.ready))

    def publish(self):
        return C["publish"](self.work, self.fixture.digest, self.prepared["core_sha256"],
            self.prepared_sha, self.fixture.gid, self.expiry)

    def test_publish_read_finalize_remove_never_fetches_or_claims_delivery(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no process allowed")):
            result = self.publish()
            self.assertEqual(set(self.state.iterdir()), {self.state / name for name in C["FILES"]})
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
            for path in self.state.iterdir(): self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(result["helper_requests"], 0)
            self.assertFalse(result["joined_delivery_proven"])
            self.assertEqual(C["read_ready"]()["prepared_sha256"], self.prepared_sha)
            for forbidden in (str(self.work), "control_gid", "socket", "publisher_key", "provider_peer_ids"):
                self.assertNotIn('"' + forbidden + '"', json.dumps(result))
            self.assertNotIn(str(self.work), json.dumps(result))
            old_umask = os.umask(0o077)
            try: finalized = C["finalize"]()
            finally: os.umask(old_umask)
            marker = self.work / "weather-android-api-finalize.json"
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o444)
            self.assertEqual(json.loads(marker.read_bytes()), dict(schema=6, action="finalize", prepared_sha256=self.prepared_sha))
            self.assertEqual(C["finalize"](), finalized)
            self.assertTrue(C["remove"](self.work, self.prepared_sha)["controller_removed"])
            self.assertTrue(C["remove"](self.work, self.prepared_sha)["controller_removed"])
            self.assertFalse(self.state.exists())
            self.assertEqual(list(self.layout["proof"].iterdir()), [])
            self.assertTrue(self.layout["viewer"].exists())

    def test_shared_deadline_counts_down_and_expired_state_cannot_finalize(self):
        self.publish()
        with patch("time.time", return_value=self.expiry - 12):
            result = C["read_ready"]()
            self.assertEqual(result["remaining_seconds"], 12)
            self.assertEqual(result["deadline_unix_seconds"], self.expiry)
        with patch("time.time", return_value=self.expiry):
            with self.assertRaises(ValueError): C["read_ready"]()
            with self.assertRaises(ValueError): C["finalize"]()
        self.assertFalse((self.work / "weather-android-api-finalize.json").exists())

    def test_incomplete_extra_or_wrong_api_record_never_publishes_endpoint(self):
        for raw in (C["encode"](self.ready)[:-1], C["encode"](self.ready) * 2,
                b'{"schema":6,"kind":"weather-android-api-rejected","success":false}\n'):
            with self.subTest(raw=raw[:30]):
                self.save_ready(raw)
                with self.assertRaises((ValueError, KeyError)): self.publish()
                self.assertFalse(self.state.exists())

    def test_ready_binding_mismatch_rejected(self):
        original = copy.deepcopy(self.ready)
        for field in ("manifest_sha256", "core_sha256", "prepared_sha256", "config_sha256"):
            self.ready = copy.deepcopy(original); self.ready[field] = "f" * 64; self.save_ready()
            with self.subTest(field=field), self.assertRaises(ValueError): self.publish()
            self.assertFalse(self.state.exists())

    def test_wrong_socket_identity_or_permissions_rejected(self):
        self.ready["socket"]["inode"] += 1; self.save_ready()
        with self.assertRaises(ValueError): self.publish()
        self.ready["socket"]["inode"] -= 1; self.save_ready()
        self.layout["socket"].chmod(0o660)
        with self.assertRaises(ValueError): self.publish()
        self.assertFalse(self.state.exists())

    def test_prefetched_cache_or_proof_rejected(self):
        cache = self.layout["cache_parent"] / "weather-cache"
        cache.mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.publish()
        cache.rmdir()
        self.fixture.save(self.layout["proof"] / "weather-1.receipt.json", b'{}\n')
        with self.assertRaises(ValueError): self.publish()
        self.assertFalse(self.state.exists())

    def test_prepared_bytes_are_bound_and_not_just_parsed_json(self):
        self.fixture.save(self.layout["viewer"] / "prepared.json", self.prepared_raw + b' ', 0o400)
        with self.assertRaises(ValueError): self.publish()
        self.assertFalse(self.state.exists())

    def test_existing_controller_is_never_overwritten_or_removed_without_ownership(self):
        self.state.mkdir(mode=0o700)
        marker = self.state / "foreign"; marker.write_text("preserve")
        with self.assertRaises(ValueError): self.publish()
        with self.assertRaises(ValueError): C["remove"](self.work, self.prepared_sha)
        self.assertEqual(marker.read_text(), "preserve")

    def test_foreign_child_blocks_cleanup_before_any_owned_file_is_deleted(self):
        self.publish(); marker = self.state / "foreign"; marker.write_text("preserve")
        with self.assertRaises(ValueError): C["remove"](self.work, self.prepared_sha)
        for name in C["FILES"]: self.assertTrue((self.state / name).exists())

    def test_replaced_controller_or_file_preserved(self):
        self.publish()
        target = self.state / "endpoint.json"
        old = self.state / "original-endpoint"; target.rename(old)
        self.fixture.save(target, old.read_bytes())
        old.rename(self.work / "preserved-endpoint")
        with self.assertRaises(ValueError): C["remove"](self.work, self.prepared_sha)
        with self.assertRaises(ValueError): C["read_ready"]()
        self.assertTrue(target.exists())
        self.state.rename(self.work / "original-controller")
        self.state.mkdir(mode=0o700)
        with self.assertRaises(ValueError): C["remove"](self.work, self.prepared_sha)
        self.assertTrue(self.state.exists())

    def test_conflicting_finalize_marker_is_not_changed(self):
        self.publish(); marker = self.work / "weather-android-api-finalize.json"
        self.fixture.save(marker, b'{}\n', 0o444)
        with self.assertRaises(ValueError): C["finalize"]()
        self.assertEqual(marker.read_bytes(), b'{}\n')

    def test_partial_publish_rolls_back_only_created_entries(self):
        real = C["write"]
        def fail_endpoint(path, raw, mode=0o600):
            if path.name == "endpoint.json": raise OSError("inert injected failure")
            return real(path, raw, mode)
        with patch.dict(G, write=fail_endpoint), self.assertRaises(OSError): self.publish()
        self.assertFalse(self.state.exists())
        self.assertFalse((self.work / C["OWNER_NAME"]).exists())

    def test_write_failure_after_inode_creation_cannot_report_controller_removed(self):
        real = C["write"]
        def fail_after_creating_endpoint(path, raw, mode=0o600):
            if path.name == "endpoint.json":
                real(path, b'{"incomplete":', mode)
                raise OSError("inert failure before returning created inode")
            return real(path, raw, mode)
        with patch.dict(G, write=fail_after_creating_endpoint), self.assertRaises(OSError): self.publish()
        # No ownership receipt was returned for this inode. Keep it visible as
        # incomplete cleanup rather than unlinking an unrecorded replacement.
        self.assertEqual((self.state / "endpoint.json").read_bytes(), b'{"incomplete":')
        self.assertFalse((self.work / C["OWNER_NAME"]).exists())
        with self.assertRaises(ValueError): C["remove"](self.work, self.prepared_sha)
        self.assertTrue(self.state.exists())

    def test_unknown_arguments_cannot_select_path_or_operation(self):
        for args in (("read-ready", "/tmp/arbitrary"), ("finalize", "command"), ("run", "anything")):
            with patch.object(sys, "argv", ["control", *args]), self.assertRaises(ValueError): C["main"]()
        self.assertFalse(self.state.exists())

    def test_duplicate_json_and_symlinks_are_rejected(self):
        with self.assertRaises(ValueError): C["parse"](b'{"schema":6,"schema":6}')
        self.publish()
        target = self.state / "endpoint.json"; target.rename(self.work / "original")
        target.symlink_to(self.work / "original")
        with self.assertRaises(ValueError): C["read_ready"]()
        with self.assertRaises(ValueError): C["remove"](self.work, self.prepared_sha)
        self.assertTrue(target.is_symlink())


if __name__ == "__main__": unittest.main()
