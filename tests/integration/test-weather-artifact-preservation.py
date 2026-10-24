#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert synthetic archive/provenance checks; no runtime or live GitHub trial."""

import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import signal
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("preserve_weather", ROOT / "scripts/preserve-weather-artifacts.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
NOW = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)
LATER = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)


def zip_bytes(members, padded=None):
    stream = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        warnings.simplefilter("ignore", UserWarning)
        for name, data in members:
            archive.writestr(name, data)
    if padded:
        remaining = padded - len(stream.getvalue())
        with zipfile.ZipFile(stream, "a") as archive:
            archive.comment = b"p" * remaining
    return stream.getvalue()


def save(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def metadata(pin):
    base = "https://api.github.com/repos/" + pin["repository"] + "/actions/"
    return {
        "artifact": {"id": pin["id"], "name": pin["name"], "size_in_bytes": pin["bytes"],
                     "url": base + "artifacts/" + str(pin["id"]),
                     "archive_download_url": base + "artifacts/" + str(pin["id"]) + "/zip",
                     "digest": "sha256:" + pin["sha256"], "expired": False,
                     "created_at": "2026-10-12T06:56:05Z", "updated_at": "2026-10-12T06:56:05Z",
                     "expires_at": "2026-10-26T06:56:05Z",
                     "workflow_run": {"id": pin["run_id"], "head_sha": pin["commit"],
                                      "repository_id": 123, "head_repository_id": 123}},
        "run": {"id": pin["run_id"], "head_sha": pin["commit"], "run_attempt": 1,
                "status": "completed", "conclusion": "success",
                "created_at": "2026-10-12T06:50:00Z", "updated_at": "2026-10-12T06:57:00Z",
                "url": base + "runs/" + str(pin["run_id"]),
                "repository": {"id": 123, "full_name": pin["repository"]},
                "head_repository": {"id": 123, "full_name": pin["repository"]}}}


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="weather-preservation-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.store_path = self.base / "archive"
        self.store = P.Store(self.store_path, create=True)
        self.addCleanup(self.store.close)
        self.pins = {}
        for index in range(1, 7):
            raw = zip_bytes([(f"file{index}.txt", f"payload{index}".encode())])
            self.pins[str(index)] = self.pin(index, raw)
            save(self.store_path / "blobs" / (P.sha256(raw) + ".zip"), raw)
        self.receipts = {f"receipt/{index}.json": P.sha256(f"receipt{index}".encode())
                         for index in range(11)}
        raw = zip_bytes([(name, f"receipt{index}".encode())
                         for index, name in enumerate(self.receipts)], padded=35901)
        self.assertEqual(len(raw), 35901)
        self.pins["7"] = self.pin(7, raw)
        self.pins["7"]["name"] = "hosted-input-provenance-" + self.pins["2"]["commit"]
        save(self.store_path / "blobs" / (P.sha256(raw) + ".zip"), raw)
        for name, ids in zip(P.ADMISSIONS[:3], ((1, 2, 3, 4), (1, 2, 5, 6), (1, 2))):
            record = {"artifacts": {str(i): self.pins[str(i)] for i in ids}}
            save(self.root / name, P.encoded(record))
        abi = {"evidence": {"artifacts": {
            "decoder": {k: self.pins["2"][k] for k in ("id", "sha256")},
            "provenance": {k: self.pins["7"][k] for k in ("id", "sha256")}}, "receipts": self.receipts},
            "weather_commit": self.pins["2"]["commit"], "hosted_run": {"id": 42, "attempt": 1}}
        save(self.root / P.ADMISSIONS[-1], P.encoded(abi))
        self.responses = {"/user": {"id": 99}}
        for key, pin in self.pins.items():
            base = "/repos/" + pin["repository"] + "/actions/"
            values = metadata(pin)
            self.responses[base + "artifacts/" + key] = values["artifact"]
            self.responses[base + "runs/" + str(pin["run_id"])] = values["run"]

    @staticmethod
    def pin(index, raw):
        return {"id": index, "bytes": len(raw), "sha256": P.sha256(raw),
                "name": f"artifact-{index}", "repository": "VOLPAROSSA/volparossa-weather",
                "commit": "a" * 40, "run_id": 42}

    def capture(self):
        with mock.patch.object(P, "utcnow", return_value=NOW), \
                mock.patch.object(P, "gh_json", side_effect=lambda endpoint: copy.deepcopy(self.responses[endpoint])) as get, \
                mock.patch.object(P, "gh_get", side_effect=AssertionError("preseed must avoid downloads")):
            result = P.capture(self.root, self.store)
        return result, get

    def verify(self, anchor):
        with mock.patch.object(P, "utcnow", return_value=LATER), \
                mock.patch.object(P, "gh_json", side_effect=AssertionError("offline verification used network")), \
                mock.patch.object(P, "gh_get", side_effect=AssertionError("offline verification used network")), \
                mock.patch.object(P.subprocess, "Popen", side_effect=AssertionError("offline subprocess")):
            return P.verify(self.root, self.store, anchor)

    def rewrite_manifest(self, transform):
        path = self.store_path / "manifest.json"
        record = json.loads(path.read_bytes())
        transform(record)
        raw = P.encoded(record)
        path.write_bytes(raw)
        return P.sha256(raw)

    def inspect(self, raw, receipts=None):
        path = self.base / "input.zip"
        save(path, raw)
        with path.open("rb") as source:
            return P.inspect_zip(source.fileno(), {"bytes": len(raw), "sha256": P.sha256(raw)}, receipts)

    def test_checked_in_pins_are_seven_and_include_eleven_receipts(self):
        snapshots, pins, receipts, provenance = P.load_admissions(ROOT)
        self.assertEqual(len(snapshots), 4)
        self.assertEqual(len(pins), 7)
        self.assertEqual(sum(p["bytes"] for p in pins.values()), 319070901)
        self.assertEqual(provenance, "11732430773")
        self.assertEqual(len(receipts), 11)

    def test_capture_reuses_blobs_queries_fresh_metadata_and_verifies_after_expiry_offline(self):
        result, get = self.capture()
        self.assertEqual(get.call_count, 15)
        verified = self.verify(result["manifest_sha256"])
        for flag, value in P.FLAGS.items():
            self.assertIs(verified[flag], value)
        self.assertEqual(verified["artifacts"], 7)
        manifest = json.loads((self.store_path / "manifest.json").read_bytes())
        self.assertEqual(manifest["artifacts"]["7"]["inspection"]["abi_receipts_checked"], 11)
        for path in self.store_path.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        with self.assertRaises(P.Rejected):
            self.capture()

    def test_metadata_identity_source_run_attempt_and_success_fail_closed(self):
        pin = self.pins["2"]
        cases = [
            ("artifact", "id", 999), ("artifact", "name", "other"),
            ("artifact", "size_in_bytes", pin["bytes"] + 1), ("artifact", "digest", "sha256:" + "0" * 64),
            ("artifact", "url", "https://example.test/a"), ("artifact", "archive_download_url", "https://example.test/b"),
            ("artifact", "expired", True), ("artifact", "expired", 0),
            ("run", "head_sha", "b" * 40), ("run", "id", 43),
            ("run", "run_attempt", 2), ("run", "run_attempt", True),
            ("run", "conclusion", "failure"), ("run", "status", "in_progress"),
            ("run", "url", "https://example.test/run"),
            ("run", "repository", {"id": 123, "full_name": "OTHER/repo"}),
            ("run", "head_repository", {"id": 456, "full_name": pin["repository"]}),
            ("artifact", "workflow_run", {"id": 42, "head_sha": "b" * 40, "repository_id": 123, "head_repository_id": 123}),
        ]
        for section, key, value in cases:
            with self.subTest(section=section, key=key, value=value):
                values = metadata(pin)
                values[section][key] = value
                with self.assertRaises(P.Rejected):
                    P.validate_metadata(pin, values, NOW)

    def test_capture_date_expiry_and_future_dates_fail_closed(self):
        cases = [("artifact", "expires_at", "2026-10-23T12:00:00Z"),
                 ("artifact", "expires_at", "2026-10-22T00:00:00Z"),
                 ("artifact", "created_at", "2026-10-24T00:00:00Z"),
                 ("artifact", "updated_at", "2026-10-24T00:00:00Z"),
                 ("run", "updated_at", "2026-10-24T00:00:00Z"),
                 ("run", "created_at", "2026-10-24T00:00:00Z"),
                 ("artifact", "expires_at", "2026-10-26T00:00:00")]
        for section, key, value in cases:
            with self.subTest(section=section, key=key):
                values = metadata(self.pins["2"])
                values[section][key] = value
                with self.assertRaises(P.Rejected):
                    P.validate_metadata(self.pins["2"], values, NOW)

    def test_expired_preseeded_capture_is_rejected_without_manifest(self):
        for endpoint, value in self.responses.items():
            if "/artifacts/" in endpoint:
                value["expired"] = True
        with self.assertRaises(P.Rejected):
            self.capture()
        self.assertFalse((self.store_path / "manifest.json").exists())
        self.assertFalse((self.store_path / "capture.lock").exists())

    def test_changed_manifest_requires_external_anchor(self):
        result, _ = self.capture()
        self.rewrite_manifest(lambda m: m.update(captured_at="2026-10-24T00:00:00Z"))
        with self.assertRaisesRegex(P.Rejected, "external anchor"):
            self.verify(result["manifest_sha256"])

    def test_changed_metadata_is_rejected_even_with_recomputed_manifest_hash(self):
        self.capture()
        anchor = self.rewrite_manifest(lambda m: m["artifacts"]["2"]["metadata"]["run"].update(run_attempt=2))
        with self.assertRaisesRegex(P.Rejected, "attempt"):
            self.verify(anchor)

    def test_changed_pin_is_rejected_even_with_recomputed_manifest_hash(self):
        self.capture()
        anchor = self.rewrite_manifest(lambda m: m["artifacts"]["2"]["pin"].update(sha256="0" * 64))
        with self.assertRaisesRegex(P.Rejected, "pin differs"):
            self.verify(anchor)

    def test_changed_admission_snapshot_is_rejected(self):
        result, _ = self.capture()
        path = self.store_path / "admissions" / Path(P.ADMISSIONS[0]).name
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(P.Rejected, "snapshot"):
            self.verify(result["manifest_sha256"])

    def test_changed_current_admission_is_rejected(self):
        result, _ = self.capture()
        path = self.root / P.ADMISSIONS[0]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(P.Rejected, "admission hashes"):
            self.verify(result["manifest_sha256"])

    def test_changed_blob_digest_or_length_is_rejected(self):
        result, _ = self.capture()
        path = self.store_path / "blobs" / (self.pins["2"]["sha256"] + ".zip")
        raw = path.read_bytes()
        path.write_bytes(b"x" + raw[1:])
        with self.assertRaisesRegex(P.Rejected, "SHA-256"):
            self.verify(result["manifest_sha256"])
        path.write_bytes(raw + b"x")
        with self.assertRaisesRegex(P.Rejected, "size differs"):
            self.verify(result["manifest_sha256"])

    def test_future_capture_and_false_authority_claim_rejected(self):
        self.capture()
        anchor = self.rewrite_manifest(lambda m: m.update(captured_at="2030-01-01T00:00:00Z"))
        with self.assertRaisesRegex(P.Rejected, "future capture"):
            self.verify(anchor)
        anchor = self.rewrite_manifest(lambda m: m.update(captured_at=P.stamp(NOW), runtime_executed=True))
        with self.assertRaisesRegex(P.Rejected, "historical-only"):
            self.verify(anchor)

    def test_unsafe_zip_paths_duplicates_and_file_directory_collision(self):
        for name in ("../escape", "/absolute", "a/../../escape", "a\\escape", "C:evil", "a//b", "a/./b", "./dot", ".", "a//"):
            with self.subTest(name=name), self.assertRaises(P.Rejected):
                self.inspect(zip_bytes([(name, b"a")]))
        for members in ([('same', b'a'), ('same', b'b')], [('a', b'a'), ('a/b', b'b')],
                        [('a/', b''), ('a', b'a')]):
            with self.subTest(members=members), self.assertRaises(P.Rejected):
                self.inspect(zip_bytes(members))

    def test_symlinks_special_files_and_encryption_are_rejected(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR):
            info = zipfile.ZipInfo("special")
            info.create_system = 3
            info.external_attr = (kind | 0o600) << 16
            with self.subTest(kind=kind), self.assertRaises(P.Rejected):
                self.inspect(zip_bytes([(info, b"target")]))
        raw = bytearray(zip_bytes([("file", b"data")]))
        local, central = raw.index(b"PK\x03\x04"), raw.index(b"PK\x01\x02")
        raw[local + 6] |= 1
        raw[central + 8] |= 1
        with self.assertRaisesRegex(P.Rejected, "encrypted"):
            self.inspect(bytes(raw))

    def test_malformed_and_crc_corrupt_zip_rejected(self):
        with self.assertRaises(P.Rejected):
            self.inspect(b"not a ZIP")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("file", b"some payload to corrupt")
        raw = bytearray(stream.getvalue())
        # Change the local compressed bytes; give inspect the new full-ZIP hash
        # so only its member read/CRC validation can detect the corruption.
        raw[34] ^= 0xFF
        with self.assertRaises((zipfile.BadZipFile, RuntimeError, OSError)):
            self.inspect(bytes(raw))

    def test_zip_member_total_and_count_caps(self):
        raw = zip_bytes([("one", b"abcd"), ("two", b"efgh")])
        for limit, value in (("MAX_MEMBER", 3), ("MAX_EXPANDED", 7), ("MAX_MEMBERS", 1)):
            with self.subTest(limit=limit), mock.patch.object(P, limit, value), self.assertRaises(P.Rejected):
                self.inspect(raw)

    def test_receipt_missing_and_wrong_hash_rejected(self):
        raw = zip_bytes([("receipt", b"content")])
        self.assertEqual(self.inspect(raw, {"receipt": P.sha256(b"content")})["abi_receipts_checked"], 1)
        for receipts in ({"receipt": "0" * 64}, {"missing": P.sha256(b"content")}):
            with self.subTest(receipts=receipts), self.assertRaises(P.Rejected):
                self.inspect(raw, receipts)

    def test_private_store_symlink_hardlink_permissions_and_overwrite(self):
        target = self.base / "target"
        save(target, b"secret")
        (self.store_path / "evil").symlink_to(target)
        with self.assertRaises(OSError):
            self.store.read("evil")
        os.link(target, self.store_path / "hardlink")
        with self.assertRaises(P.Rejected):
            self.store.read("hardlink")
        self.store.write("existing", b"first")
        with self.assertRaises(FileExistsError):
            self.store.write("existing", b"replacement")
        self.assertEqual(self.store.read("existing"), b"first")
        (self.store_path / "existing").chmod(0o644)
        with self.assertRaises(P.Rejected):
            self.store.read("existing")
        alias = self.base / "alias"
        alias.symlink_to(self.store_path, target_is_directory=True)
        with self.assertRaises(OSError):
            P.Store(alias)

    def test_fifo_store_and_admission_reads_reject_without_blocking(self):
        fifo = self.store_path / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(P.Rejected):
            self.store.read("fifo")
        path = self.root / P.ADMISSIONS[0]
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(P.Rejected):
            P.load_admissions(self.root)

    def test_capture_rejects_expiry_during_operation(self):
        expired = dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc)
        with mock.patch.object(P, "utcnow", side_effect=[NOW] * 8 + [expired]), \
                mock.patch.object(P, "gh_json", side_effect=lambda e: copy.deepcopy(self.responses[e])):
            with self.assertRaisesRegex(P.Rejected, "expired at capture"):
                P.capture(self.root, self.store)
        self.assertFalse((self.store_path / "manifest.json").exists())
        self.assertEqual(list((self.store_path / "admissions").iterdir()), [])

    def test_failed_download_cleans_only_new_blob(self):
        pin = self.pins["2"]
        path = self.store_path / "blobs" / (pin["sha256"] + ".zip")
        path.unlink()

        def failed_download(endpoint, target, maximum):
            target.write(b"partial")
            raise P.Rejected("download failed")

        with mock.patch.object(P, "utcnow", return_value=NOW), \
                mock.patch.object(P, "gh_json", side_effect=lambda e: copy.deepcopy(self.responses[e])), \
                mock.patch.object(P, "gh_get", side_effect=failed_download):
            with self.assertRaisesRegex(P.Rejected, "download failed"):
                P.capture(self.root, self.store)
        self.assertFalse(path.exists())
        self.assertEqual(len(list((self.store_path / "blobs").iterdir())), 6)
        self.assertFalse((self.store_path / "manifest.json").exists())
        self.assertFalse((self.store_path / "capture.lock").exists())

    def test_gh_get_bounds_size_time_auth_arguments_and_debug_environment(self):
        real_popen = subprocess.Popen
        processes = []

        def fake_gh(code):
            def start(arguments, **kwargs):
                self.assertEqual(arguments, ["gh", "api", "--hostname", "github.com", "--method", "GET", "/test"])
                self.assertNotIn("GH_DEBUG", kwargs["env"])
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                process = real_popen([sys.executable, "-c", code], **kwargs)
                processes.append(process)
                return process
            return start

        with mock.patch.dict(os.environ, {"GH_DEBUG": "api"}):
            with mock.patch.object(P.subprocess, "Popen", side_effect=fake_gh("print('ok')")):
                target = io.BytesIO()
                P.gh_get("/test", target, 3)
                self.assertEqual(target.getvalue(), b"ok\n")
            with mock.patch.object(P.subprocess, "Popen", side_effect=fake_gh("print('oversize')")):
                with self.assertRaisesRegex(P.Rejected, "size cap"):
                    P.gh_get("/test", io.BytesIO(), 3)
            with mock.patch.object(P.subprocess, "Popen", side_effect=fake_gh("import time; time.sleep(2)")):
                with self.assertRaisesRegex(P.Rejected, "timeout"):
                    P.gh_get("/test", io.BytesIO(), 100, timeout=0.03)
        self.assertTrue(all(process.poll() is not None for process in processes))

    def test_atomic_publication_failure_removes_partial_and_preserves_existing(self):
        real_fsync = os.fsync
        for failure_call in (1, 2):
            calls = 0

            def fail_fsync(fd):
                nonlocal calls
                calls += 1
                if calls == failure_call:
                    raise OSError("injected finalization failure")
                return real_fsync(fd)

            with self.subTest(failure_call=failure_call), \
                    mock.patch.object(P.os, "fsync", side_effect=fail_fsync):
                with self.assertRaisesRegex(OSError, "injected"):
                    self.store.write("new", b"complete bytes")
            self.assertFalse((self.store_path / "new").exists())
            self.assertFalse(list(self.store_path.glob(".pending-*")))
        self.store.write("new", b"original")
        with self.assertRaises(FileExistsError):
            self.store.write("new", b"replacement")
        self.assertEqual(self.store.read("new"), b"original")
        self.assertEqual((self.store_path / "new").stat().st_nlink, 1)
        self.assertFalse(list(self.store_path.glob(".pending-*")))

    def test_final_manifest_failure_rolls_back_snapshots_and_allows_retry(self):
        real_write = self.store.write

        def fail_manifest(name, raw, section=None):
            if name == "manifest.json":
                raise OSError("injected manifest failure")
            return real_write(name, raw, section)

        with mock.patch.object(self.store, "write", side_effect=fail_manifest):
            with self.assertRaisesRegex(OSError, "injected"):
                self.capture()
        self.assertFalse((self.store_path / "manifest.json").exists())
        self.assertFalse((self.store_path / "capture.lock").exists())
        self.assertEqual(list((self.store_path / "admissions").iterdir()), [])
        self.assertEqual(len(list((self.store_path / "blobs").iterdir())), 7)
        result, _ = self.capture()
        self.verify(result["manifest_sha256"])

    def test_pending_signal_at_final_publication_rolls_back_without_anchor(self):
        real_write = self.store.write
        previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
        signal.signal(signal.SIGTERM, P.interrupted)

        def signal_after_manifest(name, raw, section=None):
            result = real_write(name, raw, section)
            if name == "manifest.json":
                os.kill(os.getpid(), signal.SIGTERM)
            return result

        try:
            with mock.patch.object(self.store, "write", side_effect=signal_after_manifest):
                with self.assertRaisesRegex(P.Rejected, "interrupted"):
                    self.capture()
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
        self.assertFalse((self.store_path / "manifest.json").exists())
        self.assertFalse((self.store_path / "capture.lock").exists())
        self.assertEqual(list((self.store_path / "admissions").iterdir()), [])
        self.assertFalse(list(self.store_path.rglob(".pending-*")))
        result, _ = self.capture()
        self.verify(result["manifest_sha256"])

    def test_cli_signals_reap_gh_and_remove_partial_blob_lock_and_manifest(self):
        pin = self.pins["2"]
        blob = self.store_path / "blobs" / (pin["sha256"] + ".zip")
        blob.unlink()
        marker = self.base / "downloader.pid"
        responses_path = self.base / "responses.json"
        responses = copy.deepcopy(self.responses)
        actual = P.utcnow()
        for endpoint, value in responses.items():
            if "/artifacts/" in endpoint:
                value.update(created_at=P.stamp(actual - dt.timedelta(days=2)),
                             updated_at=P.stamp(actual - dt.timedelta(days=2)),
                             expires_at=P.stamp(actual + dt.timedelta(days=7)))
            if "/runs/" in endpoint:
                value.update(created_at=P.stamp(actual - dt.timedelta(days=3)),
                             updated_at=P.stamp(actual - dt.timedelta(days=1)))
        save(responses_path, P.encoded(responses))
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        fake_gh = bin_dir / "gh"
        code = ("#!" + sys.executable + "\n"
                "import json, os, pathlib, sys, time\n"
                "endpoint = sys.argv[-1]\n"
                "if endpoint.endswith('/zip'):\n"
                "    os.write(1, b'partial archive')\n"
                f"    pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\n"
                "    time.sleep(30)\n"
                "else:\n"
                "    print(json.dumps(json.loads("
                f"pathlib.Path({str(responses_path)!r}).read_bytes())[endpoint]))\n")
        save(fake_gh, code.encode(), 0o700)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
        for number in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=number):
                marker.unlink(missing_ok=True)
                process = subprocess.Popen([sys.executable, str(ROOT / "scripts/preserve-weather-artifacts.py"),
                                            "capture", "--store", str(self.store_path),
                                            "--repo-root", str(self.root)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(marker.exists(), "fake download never started")
                    child_pid = int(marker.read_text())
                    process.send_signal(number)
                    output, error = process.communicate(timeout=3)
                    self.assertEqual(process.returncode, 1, error.decode())
                    self.assertIn(b"interrupted", error)
                    self.assertEqual(output, b"")
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                    self.assertFalse(blob.exists())
                    self.assertFalse((self.store_path / "capture.lock").exists())
                    self.assertFalse((self.store_path / "manifest.json").exists())
                    self.assertEqual(list((self.store_path / "admissions").iterdir()), [])
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=3)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(P.Rejected):
            P.parse_json(b'{"id": 1, "id": 2}')


if __name__ == "__main__":
    unittest.main()
