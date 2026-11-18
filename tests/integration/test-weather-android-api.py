#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Owned inert Python children/Unix sockets only; no Node, SDK or live core.

These lifecycle tests do not use a forecast provider substitute as delivery
evidence. The fake child only exercises process/socket ownership and handshake.
Guest identities and source pins are explicit test seams over private fixtures.
"""
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import selectors
import signal
import stat
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
A = runpy.run_path(str(HERE / "weather-android-api.py"))
G = A["serve"].__globals__
F = runpy.run_path(str(HERE / "test-weather-android-delivery.py"))
FAKE = r'''
import json, os, signal, socket, sys, time
from pathlib import Path
path, mode = Path(sys.argv[1]), sys.argv[2]
if mode == 'exit':
    sys.stderr.write('PRIVATE-RAW-CHILD-ERROR /private/path?q=secret\n'); sys.exit(3)
if mode == 'stderr-overflow':
    sys.stderr.write('S' * 20000); sys.stderr.flush()
if mode == 'stdout-overflow':
    sys.stdout.write('S' * 6000); sys.stdout.flush()
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(str(path)); sock.listen(1); path.chmod(0o666 if mode == 'unsafe-mode' else 0o600)
original = path.stat()
def stop(signum, frame):
    if mode == 'ignore-term': return
    if mode == 'slow-term': time.sleep(2.05)
    if mode == 'stdout-on-stop': sys.stdout.write('unexpected trailing output\n'); sys.stdout.flush()
    if mode == 'stderr-on-stop':
        try: os.write(2, b'S' * 20000)
        except BrokenPipeError: pass
    if mode == 'term-error': sys.stderr.write('PRIVATE-STOP-ERROR\n')
    if mode != 'leave-socket' and path.exists():
        current = path.lstat()
        if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino): path.unlink()
    sock.close(); sys.exit(2 if mode == 'term-error' else 0)
signal.signal(signal.SIGTERM, stop)
if mode == 'orphan':
    child = os.fork()
    if child == 0:
        os.setsid(); signal.signal(signal.SIGTERM, signal.SIG_IGN)
        while True: time.sleep(0.05)
if mode not in ('no-ready', 'stdout-overflow', 'stderr-overflow'):
    ready = {'listening': 'http://127.0.0.1:43210', 'transport':'unix', 'scope':'fixed-public-community-forecast'}
    if mode == 'wrong-ready': ready['listening'] = 'http://127.0.0.1:8788'
    sys.stdout.write(json.dumps(ready) + '\n'); sys.stdout.flush()
while True: time.sleep(0.02)
'''


class ApiLifecycle(unittest.TestCase):
    def setUp(self):
        self.fixture = F["AndroidPreparation"]("test_only_configuration_and_private_empty_directories_are_created")
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.report = self.fixture.run_prepare()
        self.work, self.layout = self.fixture.work, self.fixture.layout
        self.prepared_raw = F["B"]["encode"](self.report)
        self.fixture.save(self.layout["viewer"] / "prepared.json", self.prepared_raw, 0o400)
        self.prepared_sha = hashlib.sha256(self.prepared_raw).hexdigest()
        d = dict(F["A"]); d.update(F["G"])
        self.seams = patch.dict(G, D=d, B=d["B"], P=d["P"], ROOT_UID=os.getuid(),
            STARTUP_SECONDS=0.25, TERM_SECONDS=0.25, KILL_SECONDS=1)
        self.seams.start(); self.addCleanup(self.seams.stop)
        self.records = []
        self.state = None

    def preflight(self, expires=None):
        return A["preflight"](self.work, self.fixture.digest, self.prepared_sha,
            "net:[111]", "net:[222]", self.fixture.gid, expires or int(time.time()) + 300)

    def marker(self, *, sha=None, mode=0o444, extra=None):
        value = dict(schema=6, action="finalize", prepared_sha256=sha or self.prepared_sha)
        if extra: value.update(extra)
        self.fixture.save(self.work / "weather-android-api-finalize.json", json.dumps(value).encode(), mode)

    def run_lifecycle(self, mode="normal", ready=None, state=None):
        self.state = self.preflight() if state is None else state
        def notify(record):
            A["validate_record"](record)
            self.records.append(record)
            if record["kind"] == "weather-android-api-ready":
                if ready is None: self.marker()
                else: ready(record)
        with patch.dict(G, command=lambda selected: [sys.executable, "-B", "-u", "-c", FAKE,
                str(selected["layout"]["socket"]), mode]):
            result = A["serve"](self.state, notify)
        self.assertEqual(Path(f"/proc/self/task/{os.getpid()}/children").read_text().strip(), "")
        return result

    def test_exact_fixed_node_command_has_paired_flags_and_no_prefetch(self):
        state = self.preflight(); command = A["command"](state)
        self.assertEqual(command, [str(self.layout["source"] / "runtime/node"), "--max-old-space-size=256",
            str(self.layout["source"] / "volparossa-weather/scripts/serve-provider.mjs"),
            "--config", str(self.layout["config"]), "--socket", str(self.layout["socket"]),
            "--proof-profile", "android-protected-core-v6", "--private-receipt-directory", str(self.layout["proof"])])
        self.assertFalse(self.layout["socket"].exists())
        self.assertEqual(list(self.layout["proof"].iterdir()), [])

    def test_normal_finalize_joins_child_and_only_reports_lifecycle(self):
        # A listening fake socket accepts no requests; any probe would be visible
        # as a stuck requester. Production command selection is checked above.
        result = self.run_lifecycle()
        self.assertTrue(result["success"])
        self.assertEqual(result["reason"], "finalized")
        self.assertEqual(len(self.records), 2)
        ready = self.records[0]
        self.assertTrue(ready["cold_caches_absent"])
        self.assertEqual(ready["socket"]["mode"], "0600")
        self.assertFalse(self.layout["socket"].exists())
        self.assertEqual(result["exit_status"], 0)
        self.assertEqual(result["retained_files"], 0)
        self.assertEqual(result["cleanup"], dict(child_reaped=True, descendants_reaped=True,
            forced_kill=False, drain_checked=True, inputs_and_private_directories_checked=True))
        self.assertEqual(result["helper_requests"], 0)
        self.assertFalse(result["native_android_proven"] or result["joined_delivery_proven"])
        self.assertEqual(list(self.layout["cache_parent"].iterdir()), [])
        self.assertEqual((self.layout["viewer"] / "prepared.json").read_bytes(), self.prepared_raw)
        self.assertGreaterEqual(self.fixture.boundary.call_count, 6)

    def test_child_raw_errors_and_paths_never_enter_public_records(self):
        result = self.run_lifecycle("exit")
        self.assertFalse(result["success"]); self.assertFalse(result["ready"])
        self.assertEqual(result["reason"], "child-exited"); self.assertEqual(result["exit_status"], 3)
        self.assertGreater(result["stderr_bytes"], 0)
        encoded = json.dumps(self.records)
        for private in ("PRIVATE", "secret", "/private/path", str(self.work), "publisher_key"):
            self.assertNotIn(private, encoded)

    def test_child_spawn_failure_restores_subreaper_and_leaves_no_resources(self):
        state = self.preflight()
        with patch("subprocess.Popen", side_effect=OSError("PRIVATE failed executable")):
            result = A["serve"](state, self.records.append)
        self.assertFalse(result["success"]); self.assertIsNone(result["exit_status"])
        self.assertTrue(result["cleanup"]["descendants_reaped"])
        self.assertNotIn("PRIVATE", json.dumps(self.records))

    def test_stdout_and_stderr_are_bounded_even_when_child_keeps_running(self):
        for mode, key, bound in (("stdout-overflow", "stdout_bytes", A["STDOUT_LIMIT"]),
                ("stderr-overflow", "stderr_bytes", A["STDERR_LIMIT"])):
            with self.subTest(mode=mode):
                self.records.clear()
                result = self.run_lifecycle(mode)
                self.assertFalse(result["success"])
                self.assertEqual(result["reason"], "output-limit")
                self.assertEqual(result[key], bound + 1)
                self.assertTrue(result["cleanup"]["descendants_reaped"])

    def test_startup_without_ready_record_times_out_and_joins(self):
        result = self.run_lifecycle("no-ready")
        self.assertEqual(result["reason"], "startup-timeout")
        self.assertFalse(result["ready"])
        self.assertTrue(result["cleanup"]["descendants_reaped"])

    def test_wrong_ready_origin_or_socket_mode_is_rejected(self):
        for mode in ("wrong-ready", "unsafe-mode"):
            with self.subTest(mode=mode):
                self.records.clear(); result = self.run_lifecycle(mode)
                self.assertFalse(result["success"] or result["ready"])
                self.assertTrue(result["cleanup"]["descendants_reaped"])

    def test_deadline_is_abort_without_finalize(self):
        state = self.preflight()
        state["expires_at"] = int(time.time()) + 2
        result = self.run_lifecycle(ready=lambda _: None, state=state)
        self.assertEqual(result["reason"], "deadline")
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["descendants_reaped"])

    def test_finalization_after_publication_deadline_is_not_success(self):
        state = self.preflight(); state["expires_at"] = int(time.time()) + 2
        with patch.dict(G, TERM_SECONDS=3): result = self.run_lifecycle("slow-term", state=state)
        self.assertFalse(result["success"])
        self.assertEqual(result["reason"], "deadline")
        self.assertEqual(result["exit_status"], 0)
        self.assertTrue(result["cleanup"]["descendants_reaped"])
        self.assertFalse(self.layout["socket"].exists())

    def test_ownership_check_error_during_stop_cannot_skip_known_child_kill(self):
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int(); self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        with patch.object(A["Child"], "orphans", side_effect=OSError("inert ownership failure")):
            result = self.run_lifecycle("ignore-term")
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_status"], -signal.SIGKILL)
        self.assertTrue(result["cleanup"]["child_reaped"])
        self.assertFalse(result["cleanup"]["descendants_reaped"] or result["cleanup"]["drain_checked"])
        # This negative seam intentionally prevents confirmation/restoration.
        # The owned child is gone, and only the test restores its prior state.
        self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def test_blocked_owner_cancellation_mask_is_rejected_before_launch(self):
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
        try:
            with self.assertRaises(ValueError): A["Child"]()
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def test_signal_style_interruption_is_not_finalize(self):
        def interrupt(_): raise A["ApiInterrupted"]("owner abort")
        result = self.run_lifecycle(ready=interrupt)
        self.assertEqual(result["reason"], "interrupted")
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["descendants_reaped"])
        self.assertFalse((self.work / "weather-android-api-finalize.json").exists())

    def test_actual_owner_term_during_spawn_is_deferred_until_child_is_owned(self):
        def interrupt(_signum, _frame): raise A["ApiInterrupted"]("owner cancellation")
        previous = signal.signal(signal.SIGTERM, interrupt)
        real_spawn = subprocess.Popen
        def cancel_spawn(*args, **kwargs):
            process = real_spawn(*args, **kwargs)
            # Cancellation after the child has written must not lose its pipe
            # registrations when the pending signal is delivered to the owner.
            if not select.select([process.stdout], [], [], 2)[0]:
                process.kill(); process.wait(timeout=2)
                process.stdout.close(); process.stderr.close()
                raise OSError("inert child did not become ready")
            os.kill(os.getpid(), signal.SIGTERM)
            return process
        try:
            with patch("subprocess.Popen", side_effect=cancel_spawn): result = self.run_lifecycle()
        finally: signal.signal(signal.SIGTERM, previous)
        self.assertEqual(result["reason"], "interrupted")
        self.assertFalse(result["success"] or result["ready"])
        self.assertTrue(result["cleanup"]["child_reaped"] and result["cleanup"]["descendants_reaped"])
        self.assertTrue(result["cleanup"]["drain_checked"])
        self.assertGreater(result["stdout_bytes"], 0)
        self.assertNotIn(signal.SIGTERM, signal.pthread_sigmask(signal.SIG_BLOCK, []))

    def test_actual_term_in_blocking_selector_is_not_swallowed_as_eintr(self):
        ready, armed, interrupted_in_selector = False, False, []
        real_pump = A["Child"].pump
        state = self.preflight(); state["expires_at"] = int(time.time()) + 3
        def on_ready(_):
            nonlocal ready
            ready = True
        def interrupt(_signum, frame):
            while frame is not None:
                if frame.f_code.co_filename == selectors.__file__ and frame.f_code.co_name == "select":
                    interrupted_in_selector.append(True)
                    break
                frame = frame.f_back
            raise A["ApiInterrupted"]("owner cancellation")
        def alarm(_signum, _frame):
            os.kill(os.getpid(), signal.SIGTERM)
        def pump(owner, wait=0.05, cleanup=False):
            nonlocal armed
            if ready and not armed and not cleanup:
                armed = True
                signal.setitimer(signal.ITIMER_REAL, 0.05)
                wait = 1
            return real_pump(owner, wait, cleanup)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        previous = {sig: signal.signal(sig, handler) for sig, handler in
            ((signal.SIGTERM, interrupt), (signal.SIGALRM, alarm))}
        started = time.monotonic()
        try:
            with patch.object(A["Child"], "pump", pump):
                result = self.run_lifecycle(ready=on_ready, state=state)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for sig, handler in previous.items(): signal.signal(sig, handler)
        self.assertEqual(interrupted_in_selector, [True])
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(result["reason"], "interrupted")
        self.assertFalse(result["success"] or result["cleanup"]["forced_kill"])
        self.assertTrue(result["cleanup"]["child_reaped"] and result["cleanup"]["descendants_reaped"])
        self.assertTrue(result["cleanup"]["drain_checked"])
        self.assertFalse(self.layout["socket"].exists())
        self.assertFalse((self.work / "weather-android-api-finalize.json").exists())

    def test_actual_term_at_preflight_uses_closed_top_level_rejection(self):
        script = r'''
import os, runpy, signal, sys
path = sys.argv[1]
sys.argv = [path, "serve", "/inert/no-work", "a" * 64, "b" * 64, "net:[1]", "net:[2]", "1", "1"]
def interrupt_at_preflight(frame, event, _arg):
    if event == "call" and frame.f_code.co_filename == path and frame.f_code.co_name == "preflight":
        sys.settrace(None)
        os.kill(os.getpid(), signal.SIGTERM)
    return interrupt_at_preflight
sys.settrace(interrupt_at_preflight)
runpy.run_path(path, run_name="__main__")
'''
        result = subprocess.run([sys.executable, "-B", "-c", script, str(HERE / "weather-android-api.py")],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), dict(schema=6, kind="weather-android-api-rejected", success=False))
        self.assertEqual(result.stderr, b"")

    def test_term_ignoring_child_is_killed_and_not_reported_as_success(self):
        result = self.run_lifecycle("ignore-term")
        self.assertFalse(result["success"])
        self.assertEqual(result["exit_status"], -signal.SIGKILL)
        self.assertTrue(result["cleanup"]["forced_kill"])
        self.assertTrue(result["cleanup"]["child_reaped"] and result["cleanup"]["descendants_reaped"])
        self.assertTrue(self.layout["socket"].exists())  # no invented server cleanup

    def test_detached_orphan_is_owned_killed_and_reaped(self):
        result = self.run_lifecycle("orphan")
        self.assertFalse(result["success"])
        self.assertEqual(result["reason"], "cleanup-unconfirmed")
        self.assertTrue(result["cleanup"]["forced_kill"])
        self.assertTrue(result["cleanup"]["descendants_reaped"])
        self.assertFalse(self.layout["socket"].exists())

    def test_server_cleanup_error_and_socket_leftover_are_not_hidden(self):
        for mode in ("term-error", "leave-socket"):
            with self.subTest(mode=mode):
                self.records.clear(); result = self.run_lifecycle(mode)
                self.assertFalse(result["success"])
                self.assertEqual(result["reason"], "cleanup-unconfirmed")
                self.assertTrue(result["cleanup"]["descendants_reaped"])
                (self.work / "weather-android-api-finalize.json").unlink()
                if self.layout["socket"].exists(): self.layout["socket"].unlink()

    def test_shutdown_only_stdout_is_drained_and_rejects_even_exit_zero(self):
        result = self.run_lifecycle("stdout-on-stop")
        self.assertEqual(result["exit_status"], 0)
        self.assertFalse(result["success"])
        self.assertEqual(result["reason"], "cleanup-unconfirmed")
        self.assertTrue(result["cleanup"]["child_reaped"] and result["cleanup"]["descendants_reaped"])
        self.assertTrue(result["cleanup"]["drain_checked"])
        self.assertGreater(result["stdout_bytes"], len(json.dumps(A["READY"]).encode()) + 1)
        self.assertNotIn("unexpected trailing", json.dumps(self.records))

    def test_shutdown_only_stderr_overflow_is_detected_even_exit_zero(self):
        result = self.run_lifecycle("stderr-on-stop")
        self.assertEqual(result["exit_status"], 0)
        self.assertFalse(result["success"])
        self.assertEqual(result["reason"], "cleanup-unconfirmed")
        self.assertEqual(result["stderr_bytes"], A["STDERR_LIMIT"] + 1)
        self.assertTrue(result["cleanup"]["child_reaped"] and result["cleanup"]["descendants_reaped"])
        self.assertFalse(result["cleanup"]["drain_checked"])
        self.assertFalse(self.layout["socket"].exists())

    def test_private_receipts_are_preserved_not_interpreted_as_delivery(self):
        retained = self.layout["proof"] / "weather-1.receipt.json"
        def keep(_):
            self.fixture.save(retained, b"synthetic partial receipt")
            self.marker()
        result = self.run_lifecycle(ready=keep)
        self.assertTrue(result["success"])
        self.assertEqual(result["retained_files"], 1)
        self.assertEqual(retained.read_bytes(), b"synthetic partial receipt")
        self.assertFalse(result["joined_delivery_proven"])

    def test_foreign_proof_content_is_preserved_and_fails_cleanup_check(self):
        retained = self.layout["proof"] / "private-key"
        def keep(_):
            self.fixture.save(retained, b"private sentinel")
            self.marker()
        result = self.run_lifecycle(ready=keep)
        self.assertFalse(result["success"])
        self.assertFalse(result["cleanup"]["inputs_and_private_directories_checked"])
        self.assertEqual(retained.read_bytes(), b"private sentinel")

    def test_replacement_socket_is_never_deleted_by_owner(self):
        original = self.work / "original-socket"
        def replace(_):
            self.layout["socket"].rename(original)
            self.fixture.save(self.layout["socket"], b"foreign replacement")
        result = self.run_lifecycle(ready=replace)
        self.assertFalse(result["success"])
        self.assertEqual(self.layout["socket"].read_bytes(), b"foreign replacement")
        self.assertTrue(result["cleanup"]["descendants_reaped"])

    def test_wrong_finalize_hash_extra_field_or_mode_cannot_authorize_success(self):
        for kwargs in ({"sha": "f" * 64}, {"mode": 0o600}, {"extra": {"permit": True}}):
            with self.subTest(kwargs=kwargs):
                self.records.clear()
                result = self.run_lifecycle(ready=lambda _: self.marker(**kwargs))
                self.assertFalse(result["success"])
                self.assertEqual(result["reason"], "rejected")
                (self.work / "weather-android-api-finalize.json").unlink()

    def test_changed_boundary_before_launch_and_at_finalize_is_rejected(self):
        state = self.preflight()
        previous = G["D"]["boundary"]
        def reject(*_): raise ValueError("changed UID/group/netns")
        with patch.dict(G["D"], boundary=reject):
            result = self.run_lifecycle(state=state)
        self.assertFalse(result["success"] or result["ready"])
        self.assertIsNone(result["exit_status"])
        def changed(_):
            G["D"]["boundary"] = reject
            self.marker()
        try: result = self.run_lifecycle(ready=changed)
        finally: G["D"]["boundary"] = previous
        self.assertFalse(result["success"])
        self.assertTrue(result["cleanup"]["descendants_reaped"])

    def test_changed_config_at_finish_fails_without_restoring_it(self):
        def changed(_):
            self.fixture.save(self.layout["config"], b"{\"changed\":true}\n")
            self.marker()
        result = self.run_lifecycle(ready=changed)
        self.assertFalse(result["success"])
        self.assertEqual(json.loads(self.layout["config"].read_bytes()), dict(changed=True))

    def test_preflight_rejects_bad_hashes_modes_expiries_and_existing_finalize(self):
        for expiry in (1, True, int(time.time()) + 841, int(time.time()) + 700):
            with self.subTest(expiry=expiry), self.assertRaises(ValueError): self.preflight(expiry)
        with self.assertRaises(ValueError): A["preflight"](self.work, self.fixture.digest, "f" * 64,
            "net:[111]", "net:[222]", self.fixture.gid, int(time.time()) + 300)
        prepared = self.layout["viewer"] / "prepared.json"
        prepared.chmod(0o600)
        with self.assertRaises(ValueError): self.preflight()
        prepared.chmod(0o400)
        self.marker()
        with self.assertRaises(ValueError): self.preflight()
        self.assertFalse(self.layout["socket"].exists())

    def test_preflight_binds_prepared_selection_config_and_core_bytes(self):
        for path in (self.layout["config"], self.layout["viewer"] / "selection.json", self.layout["binary"]):
            original, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            self.fixture.save(path, original + b" ", mode)
            with self.subTest(path=path.name), self.assertRaises(ValueError): self.preflight()
            self.fixture.save(path, original, mode)

    def test_preflight_refuses_prior_cache_or_proof_even_with_valid_prepare(self):
        path = self.layout["cache_parent"] / "weather-cache"
        path.mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.preflight()
        path.rmdir()
        self.fixture.save(self.layout["proof"] / "weather-1.receipt.json", b"prior receipt")
        with self.assertRaises(ValueError): self.preflight()
        self.assertFalse(self.layout["socket"].exists())

    def test_no_prefetch_cache_guard_runs_again_before_ready(self):
        path = self.layout["cache_parent"] / "weather-cache"
        real = A["ready_socket"]
        def changed(state):
            result = real(state); path.mkdir(mode=0o700); return result
        with patch.dict(G, ready_socket=changed): result = self.run_lifecycle()
        self.assertFalse(result["ready"] or result["success"])
        self.assertTrue(path.is_dir())

    def test_closed_record_validator_refuses_claims_extra_fields_and_bad_types(self):
        self.run_lifecycle()
        for original in self.records:
            for key, value in (("schema", True), ("helper_requests", 1), ("joined_delivery_proven", True),
                    ("prepared_sha256", "bad"), ("profile", "other"), ("private_path", "/private")):
                record = copy.deepcopy(original); record[key] = value
                with self.subTest(kind=original["kind"], key=key), self.assertRaises(ValueError): A["validate_record"](record)
        final = copy.deepcopy(self.records[-1]); final["cleanup"]["forced_kill"] = True
        with self.assertRaises(ValueError): A["validate_record"](final)

    def test_subreaper_state_is_restored_and_signals_are_preserved(self):
        libc = ctypes.CDLL(None, use_errno=True)
        before = ctypes.c_int(); self.assertEqual(libc.prctl(37, ctypes.byref(before), 0, 0, 0), 0)
        handlers = {sig: signal.getsignal(sig) for sig in A["SIGNALS"]}
        self.run_lifecycle()
        after = ctypes.c_int(); self.assertEqual(libc.prctl(37, ctypes.byref(after), 0, 0, 0), 0)
        self.assertEqual(before.value, after.value)
        self.assertEqual(handlers, {sig: signal.getsignal(sig) for sig in A["SIGNALS"]})


if __name__ == "__main__": unittest.main()
