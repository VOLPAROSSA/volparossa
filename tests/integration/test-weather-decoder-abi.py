#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure fixtures/inert Python children only: never execute a decoder or bwrap."""
import copy
import json
import os
from pathlib import Path
import runpy
import signal
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

H = runpy.run_path(str(Path(__file__).with_name("weather-decoder-abi.py")))
G = H["execute"].__globals__


def point(latitude=60, longitude=0, value=0):
    return [dict(keys=dict(edition=2, packingType="grid_ccsds", bitsPerValue=16, numberOfPoints=496),
                 method="nearest", neighbours=[dict(latitude=latitude, longitude=longitude, value=value,
                                                     distance=0, distance_unit="km")])]


def fixture(root):
    binary = bytearray(64)
    binary[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", binary, 16, 3, 62)
    files = {H["DECODER"]: bytes(binary), H["PROBE"]: b"synthetic probe", "LICENSE": b"synthetic license"}
    entries = {name: dict(bytes=len(raw), sha256=H["digest"](raw)) for name, raw in files.items()}
    receipt = dict(schema=1, kind="volparossa-hosted-decoder-build", compiled=True, tests_passed=True,
                   scope=dict(decoder_authorized=False), artifacts=[dict(path=name, **item) for name, item in entries.items()])
    files[H["RECEIPT"]] = json.dumps(receipt).encode()
    record = dict(schema=1, kind="volparossa-weather-decoder-abi-admission", scope="disposable-debian13-abi-only",
        weather_commit="b"*40, hosted_run=dict(id=1, attempt=1),
        files={name: dict(bytes=len(raw), sha256=H["digest"](raw)) for name, raw in files.items()},
        evidence=dict(artifacts={name: dict(id=1, sha256="c"*64) for name in ("decoder", "provenance")},
                      receipts={"retained/receipt.json": "d"*64}))
    root.mkdir(mode=0o700)
    for name, raw in files.items():
        path = root/name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in path.parents:
            if parent.is_relative_to(root): parent.chmod(0o700)
        path.write_bytes(raw); path.chmod(0o600)
    return record, files


class ABI(unittest.TestCase):
    def test_record_is_closed_test_only_and_has_no_caller_execution_selector(self):
        with tempfile.TemporaryDirectory() as temporary:
            record, _ = fixture(Path(temporary)/"inputs")
            self.assertEqual(H["validate_record"](record), record)
            for mutate in (
                lambda v: v.update(command=["sh"]), lambda v: v.update(scope="production"),
                lambda v: v.update(schema=True), lambda v: v["hosted_run"].update(attempt=0),
                lambda v: v["files"].update({"../escape": dict(bytes=1, sha256="a"*64)}),
                lambda v: v["files"].update({"/absolute": dict(bytes=1, sha256="a"*64)}),
                lambda v: v["files"].update({"eccodes-build": dict(bytes=1, sha256="a"*64)}),
                lambda v: v["files"][H["DECODER"]].update(bytes=True),
                lambda v: v["evidence"]["artifacts"]["decoder"].update(sha256="x"*64)):
                changed = copy.deepcopy(record); mutate(changed)
                with self.assertRaises(ValueError): H["validate_record"](changed)
        with self.assertRaises(ValueError): H["decode"](b'{"schema":1,"schema":1}')

    def test_absent_admission_never_accepts_caller_bytes(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(G, RECORD=Path(temporary)/"absent"):
            with self.assertRaises(FileNotFoundError): H["verify_inputs"](Path(temporary))

    def test_exact_files_are_verified_and_staged_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, files = fixture(root/"inputs")
            with patch.dict(G, admission=lambda: (record, "a"*64)), \
                    patch.object(subprocess, "Popen", side_effect=AssertionError("must not execute")):
                result = H["stage_inputs"](root/"inputs", root/"staged")
                self.assertEqual(result["files"], len(files)); self.assertFalse(result["runtime_executed"])
                self.assertEqual(H["verify_inputs"](root/"staged")[2], files)
                self.assertEqual((root/"staged").stat().st_mode & 0o777, 0o700)
                for name in files: self.assertEqual((root/"staged"/name).stat().st_mode & 0o777, 0o400)
                with self.assertRaises(FileExistsError): H["stage_inputs"](root/"inputs", root/"staged")
                with self.assertRaises(ValueError): H["stage_inputs"](root/"inputs", root/"inputs/nested")

    def test_tampered_extra_and_unsafe_members_fail_before_staging(self):
        for mutation in ("bytes", "extra", "directory", "link", "hardlink", "writable", "fifo"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = root/"inputs"; record, _ = fixture(source)
                target = source/H["PROBE"]
                if mutation == "bytes": target.write_bytes(b"tampered")
                elif mutation == "extra": (source/"extra").write_bytes(b"extra")
                elif mutation == "directory": (source/"empty-extra").mkdir()
                elif mutation == "link": target.unlink(); target.symlink_to(source/"LICENSE")
                elif mutation == "hardlink": os.link(target, root/"outside")
                elif mutation == "writable": target.chmod(0o666)
                elif mutation == "fifo": target.unlink(); os.mkfifo(target, 0o600)
                with patch.dict(G, admission=lambda: (record, "a"*64)):
                    with self.assertRaises((OSError, ValueError)): H["stage_inputs"](source, root/"staged")
                self.assertFalse((root/"staged").exists())

    def test_receipt_cannot_authorize_different_probe_or_release_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); record, files = fixture(root/"inputs")
            receipt = json.loads(files[H["RECEIPT"]]); receipt["artifacts"][0]["sha256"] = "0"*64
            raw = json.dumps(receipt).encode(); (root/"inputs"/H["RECEIPT"]).write_bytes(raw)
            record["files"][H["RECEIPT"]] = dict(bytes=len(raw), sha256=H["digest"](raw))
            with patch.dict(G, admission=lambda: (record, "a"*64)):
                with self.assertRaises(ValueError): H["verify_inputs"](root/"inputs")

    def test_sandbox_is_offline_readonly_and_rpath_sibling_is_absent(self):
        argv = H["sandbox"](Path("/private/scratch"), [H["SANDBOX_DECODER"], "-V"])
        for flag in ("--unshare-net", "--unshare-pid", "--die-with-parent", "--new-session"):
            self.assertIn(flag, argv)
        self.assertNotIn("--bind", argv)
        self.assertNotIn("/etc", [argv[i+1] for i, item in enumerate(argv) if item == "--ro-bind"])
        self.assertIn("/case/bin/grib_ls", argv); self.assertNotIn("/case/lib", argv)
        self.assertEqual(argv[-2:], ["/case/bin/grib_ls", "-V"])
        self.assertIn("--as=536870912", argv); self.assertIn("--cpu=20", argv)
        self.assertIn("'/case/lib'", H["PREFLIGHT"])
        self.assertNotIn("LD_LIBRARY_PATH", H["ENV"])

    def test_boundary_rejects_host_root_non_kvm_and_other_distribution(self):
        with patch.object(os, "getuid", return_value=0), patch.object(os, "geteuid", return_value=0), \
                patch.object(subprocess, "run", side_effect=AssertionError("no child")):
            with self.assertRaisesRegex(ValueError, "ABI_DISPOSABLE_GUEST_REQUIRED"): H["guest_boundary"]("a"*40)
        with patch.object(os, "getuid", return_value=1000), patch.object(os, "geteuid", return_value=1000), \
                patch.object(H["socket"], "gethostname", return_value="volparossa-alpha"), \
                patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"qemu\n")):
            with self.assertRaisesRegex(ValueError, "ABI_KVM_REQUIRED"): H["guest_boundary"]("a"*40)
        with patch.object(os, "getuid", return_value=1000), patch.object(os, "geteuid", return_value=1000), \
                patch.object(H["socket"], "gethostname", return_value="volparossa-alpha"), \
                patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"kvm\n")), \
                patch.dict(G, read_file=lambda *_args: b'ID=ubuntu\nVERSION_ID="24.04"\n'):
            with self.assertRaisesRegex(ValueError, "ABI_DEBIAN13_REQUIRED"): H["guest_boundary"]("a"*40)

    def test_point_requires_exact_native_nonconstant_values(self):
        H["validate_point"](json.dumps(point()), 60, 0, 0)
        H["validate_point"](json.dumps(point(0, 30, 495)), 0, 30, 495)
        for mutate in (lambda p: p[0]["keys"].update(bitsPerValue=0),
                       lambda p: p[0]["neighbours"][0].update(value=False),
                       lambda p: p[0]["neighbours"][0].update(value=float("nan")),
                       lambda p: p[0]["neighbours"][0].update(distance=1),
                       lambda p: p[0].update(method="interpolated")):
            value = point(); mutate(value)
            with self.assertRaises(ValueError): H["validate_point"](json.dumps(value), 60, 0, 0)

    def simulated_execute(self, root, failure=None):
        record, _ = fixture(root/"inputs")
        calls = []
        class Commands:
            drained = True
            def run(self, argv, deadline):
                calls.append(argv)
                if failure == "cleanup": self.drained = False; raise H["CleanupUnconfirmed"]()
                if failure == "interrupt": raise H["Interrupted"]()
                if "-c" in argv:
                    return 0, json.dumps(dict(uid=os.geteuid(), network_namespace="net:[0]", isolated=True)).encode()
                if "/usr/bin/readelf" in argv: return 0, b"synthetic ELF metadata\n"
                if "-V" in argv: return (1, b"loader failure\n") if failure == "version" else (0, b"ecCodes Version 2.44.0\n")
                values = point() if "60,0,1" in argv else point(0, 30, 495)
                return 0, json.dumps(values).encode()
        with patch.dict(G, admission=lambda: (record, "a"*64), Commands=Commands, guest_boundary=lambda _commit: {"test": True}):
            report = H["execute"](root/"inputs", root/"output", "f"*40)
        return report, calls

    def test_execution_reports_exact_probes_and_removes_private_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report, calls = self.simulated_execute(root)
            self.assertTrue(report["success"]); self.assertEqual(report["phase"], "complete")
            self.assertTrue(all(report["checks"].values())); self.assertTrue(all(report["cleanup"].values()))
            self.assertFalse(report["scope"]["production_decoder_authorized"])
            self.assertEqual(set(report["logs"]), H["LOGS"])
            self.assertEqual({p.name for p in (root/"output").iterdir()}, H["LOGS"] | {"report.json"})
            self.assertEqual(len(calls), 5)

    def test_failed_or_interrupted_execution_never_claims_success(self):
        for failure in ("version", "interrupt", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); report, _ = self.simulated_execute(root, failure)
                self.assertFalse(report["success"])
                self.assertEqual(all(report["cleanup"].values()), failure != "cleanup")
                self.assertEqual(any(p.name.startswith(".abi-") for p in (root/"output").iterdir()), failure == "cleanup")
                if failure == "version": self.assertEqual(report["logs"]["version.log"]["exit_status"], 1)

    def test_real_inert_process_success_timeout_and_output_bound(self):
        owner = H["Commands"]()
        status, raw = owner.run([sys.executable, "-c", "print('inert')"], time.monotonic()+2)
        self.assertEqual((status, raw), (0, b"inert\n")); self.assertTrue(owner.drained)
        for code, seconds, error in (("import time; time.sleep(5)", .05, "ABI_DEADLINE"),
                                    ("print('x'*70000)", 2, "ABI_OUTPUT_BOUND")):
            with self.assertRaisesRegex(ValueError, error): owner.run([sys.executable, "-c", code], time.monotonic()+seconds)
            self.assertTrue(owner.drained)

    def test_interrupt_during_cleanup_is_never_confirmed_drained(self):
        child = Mock(pid=99999)
        child.wait.side_effect = [0, H["Interrupted"]()]
        selector = Mock(); selector.__enter__ = Mock(return_value=selector); selector.__exit__ = Mock(return_value=False)
        selector.get_map.return_value = {}
        owner = H["Commands"]()
        with patch.object(subprocess, "Popen", return_value=child), patch.object(H["selectors"], "DefaultSelector", return_value=selector), \
                patch.object(os, "killpg"):
            with self.assertRaises(H["CleanupUnconfirmed"]): owner.run(["inert"], time.monotonic()+2)
        self.assertFalse(owner.drained)


if __name__ == "__main__":
    unittest.main()
