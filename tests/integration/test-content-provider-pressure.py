#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Offline fake-clock/process tests. Never fork load workers or stress the host."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
C = runpy.run_path(str(HERE / "content-provider-pressure.py"))
G = C["coordinate"].__globals__


def seed():
    return dict(report_kind="volparossa-content-adaptive-provider-seed",
                object_sha256=C["OBJECT_SHA"], bytes=60*262144, chunks=60,
                publisher_removed=True, publisher_private_key_persisted=False,
                recipient_encrypted=False, manifest_id="a"*64, publisher_hex="b"*64,
                created_unix_seconds=1000, expires_unix_seconds=4600,
                **{f"replica_{label}_{kind}": value for label in "abc"
                   for kind, value in (("chunks", 20), ("bytes", 20*262144))})


def binding():
    return {key: seed()[key] for key in ("manifest_id", "publisher_hex", "object_sha256")}


def psi(**changes):
    return dict(dict.fromkeys(("cpu", "memory", "io"), "below_threshold"), **changes)


class Clock:
    def __init__(self):
        self.now = 1_000_000_000

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        if seconds < 0:
            raise AssertionError("negative sleep")
        self.now += round(seconds * 1e9)


class Observer:
    def __init__(self, values=(3,)):
        self.values = iter(values)
        self.last = 0

    def sample(self):
        self.last = next(self.values, self.last)
        return self.last


class Workers:
    def __init__(self):
        self.started = 0
        self.reaped = 0
        self.trace = []
        self.codes = []

    def start(self, deadline):
        self.trace.append(("start", deadline))
        self.started = 2

    def alive(self):
        return True

    def stop(self):
        self.trace.append(("stop",))
        self.reaped = self.started
        self.codes = [0] * self.started

    def receipt(self):
        return dict(spawned=self.started, ready=self.started, reaped=self.reaped,
                    forced_kills=0, exit_codes=self.codes)


def run(*, observer=None, workers=None, clock=None, sampler=None, memory=lambda: True):
    observer, workers, clock = observer or Observer(), workers or Workers(), clock or Clock()
    observations = iter([psi(), psi(cpu="pressured")])
    if sampler is None:
        def sampler():
            return next(observations, psi(cpu="pressured"))
    result = C["coordinate"](observer, workers, clock=clock, sleep=clock.sleep,
                             sampler=sampler, memory=memory)
    result["publication"] = binding()
    C["validate"](result)
    return result, workers


class LifecycleTests(unittest.TestCase):
    def test_real_trigger_precedes_load_and_receipt_never_claims_transfer(self):
        result, workers = run(observer=Observer([0, 1, 2, 3]))
        self.assertTrue(result["success"])
        self.assertEqual(result["verified_bytes"], 786432)
        self.assertEqual(result["trigger_ns"]-result["started_ns"], 600_000_000)
        self.assertGreaterEqual(result["load_started_ns"], result["trigger_ns"])
        self.assertGreaterEqual(result["first_pressure_ns"], result["load_started_ns"])
        self.assertEqual(result["initial_observation"], psi())
        self.assertEqual(result["load_stopped_ns"]-result["load_started_ns"], C["ACTIVE_NS"])
        self.assertEqual(result["samples"], 45)
        self.assertEqual(result["cleanup"]["reaped"], 2)
        self.assertEqual([step[0] for step in workers.trace], ["start", "stop"])
        self.assertFalse(result["scope"]["continuation_claimed"])
        self.assertFalse(result["scope"]["transfer_completion_claimed"])

    def test_no_three_chunks_never_starts_load_or_resets_30s(self):
        result, workers = run(observer=Observer([2]))
        self.assertEqual(result["status"], "trigger-timeout")
        self.assertEqual(result["completed_ns"]-result["started_ns"], C["WAIT_NS"])
        self.assertEqual(workers.trace, [("stop",)])
        self.assertIsNone(result["load_started_ns"])

    def test_slow_final_sample_cannot_trigger_after_original_deadline(self):
        clock = Clock()
        observer = Observer()
        def sample():
            clock.now += C["WAIT_NS"]
            return 3
        observer.sample = sample
        result, workers = run(observer=observer, clock=clock)
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(workers.started, 0)

    def test_absent_or_unrelated_pressure_is_not_success(self):
        for observation, expected in ((psi(), "pressure-missing"),
                                      (psi(io="pressured"), "resource-unavailable"),
                                      (psi(cpu="unavailable"), "resource-unavailable")):
            with self.subTest(observation=observation):
                samples = iter([psi(), observation])
                result, workers = run(sampler=lambda: next(samples, observation))
                self.assertEqual(result["status"], expected)
                self.assertEqual(workers.reaped, 2)
                self.assertFalse(result["success"])

    def test_preexisting_pressure_and_memory_shortfall_never_start_load(self):
        result, workers = run(sampler=lambda: psi(cpu="pressured"))
        self.assertEqual(result["status"], "resource-unavailable")
        self.assertEqual(workers.started, 0)
        result, workers = run(memory=lambda: False)
        self.assertFalse(result["success"])
        self.assertEqual(workers.started, 0)

    def test_failed_second_spawn_and_interrupt_always_reap_first(self):
        for error in (OSError("closed"), InterruptedError()):
            with self.subTest(error=type(error).__name__):
                workers = Workers()
                def start(_deadline):
                    workers.started = 1
                    raise error
                workers.start = start
                result, _ = run(workers=workers)
                self.assertEqual(result["status"], "interrupted" if isinstance(error, InterruptedError) else "invalid")
                self.assertEqual(result["cleanup"]["reaped"], 1)

    def test_no_new_deadline_after_worker_setup(self):
        clock, workers = Clock(), Workers()
        original = workers.start
        def start(deadline):
            original(deadline)
            clock.now += 8_000_000_000
        workers.start = start
        result, _ = run(clock=clock, workers=workers)
        self.assertEqual(result["samples"], 5)
        self.assertEqual(result["load_stopped_ns"]-result["load_started_ns"], C["ACTIVE_NS"])

    def test_preload_decision_and_receipt_share_original_deadline_sample(self):
        class BoundaryClock(Clock):
            tick_next = False
            def __call__(self):
                sampled = self.now
                if self.tick_next:
                    self.now += 1
                    self.tick_next = False
                return sampled
        for delta in (-1, 0):
            with self.subTest(delta=delta):
                clock = BoundaryClock()
                start = clock.now
                calls = 0
                def memory():
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        clock.now = start + C["WAIT_NS"] + delta
                        clock.tick_next = True
                    return True
                result, workers = run(clock=clock, memory=memory)
                if delta == -1:
                    self.assertTrue(result["success"])
                    self.assertEqual(result["load_started_ns"], start+C["WAIT_NS"]-1)
                else:
                    self.assertFalse(result["success"])
                    self.assertIsNone(result["load_started_ns"])
                    self.assertEqual(workers.started, 0)

    def test_delayed_pressure_sample_after_active_deadline_cannot_count(self):
        clock = Clock()
        calls = 0
        def sample():
            nonlocal calls
            calls += 1
            if calls == 1: return psi()
            clock.now += C["ACTIVE_NS"]
            return psi(cpu="pressured")
        result, _ = run(clock=clock, sampler=sample)
        self.assertEqual(result["status"], "pressure-missing")
        self.assertIsNone(result["first_pressure_ns"])
        self.assertFalse(result["cpu_pressure_observed"])

    def test_cleanup_timeout_and_failed_child_cannot_report_success(self):
        for kind in ("late", "failed", "exception"):
            with self.subTest(kind=kind):
                clock, workers = Clock(), Workers()
                original = workers.stop
                def stop():
                    original()
                    if kind == "late": clock.now += 2_000_000_000
                    if kind == "failed": workers.codes = [0, 1]
                    if kind == "exception": raise OSError("cleanup")
                workers.stop = stop
                result, _ = run(clock=clock, workers=workers)
                self.assertFalse(result["success"])
                self.assertEqual(result["status"], "load-failed" if kind == "failed" else "cleanup-failed")

    def test_closed_schema_rejects_invented_claims_and_unreaped_success(self):
        result, _ = run()
        changes = [lambda r: r.update(url="private"), lambda r: r.update(schema_version=True),
                   lambda r: r["scope"].update(continuation_claimed=True),
                   lambda r: r.update(cpu_pressure_observed=False),
                   lambda r: r["cleanup"].update(reaped=1),
                   lambda r: r.update(trigger_ns=r["started_ns"]+C["WAIT_NS"]),
                   lambda r: r.update(load_stopped_ns=r["load_started_ns"]+C["LOAD_NS"]+1)]
        for change in changes:
            value = copy.deepcopy(result)
            change(value)
            with self.assertRaises((ValueError, TypeError)):
                C["validate"](value)
        self.assertLess(len(json.dumps(result)), C["MAX_REPORT"])

    def test_receipt_rejects_late_load_and_pressure_after_child_drain(self):
        result, _ = run()
        late = copy.deepcopy(result)
        for key in ("load_started_ns", "load_stopped_ns", "first_pressure_ns", "completed_ns"):
            late[key] += C["WAIT_NS"]
        with self.assertRaises(ValueError): C["validate"](late)
        after_drain = copy.deepcopy(result)
        after_drain["load_stopped_ns"] = result["load_started_ns"] + 1_000_000_000
        after_drain["first_pressure_ns"] = result["load_started_ns"] + 2_000_000_000
        with self.assertRaises(ValueError): C["validate"](after_drain)


class FileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pressure-fixture-unit-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.uid = os.geteuid()
        self.root = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.root)
        (self.work / "state-client").mkdir(mode=0o700)
        self.parent = self.work / "state-client/content-adaptive-pressure"
        self.parent.mkdir(mode=0o700)

    def write(self, path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def observer(self):
        observer = C["CacheObserver"](self.root, self.uid)
        self.addCleanup(observer.close)
        return observer

    def test_seed_binding_is_actual_A_B_C_vector_and_rejects_alternatives(self):
        source = (HERE.parents[1]/"crates/volparossa-content/examples/content-acceptance-fixture/adaptive.rs").read_text()
        self.assertIn("(b'A'..b'A' + 60)", source)
        self.assertIn("caches[index % 3].put_verified", source)
        self.assertIn(C["OBJECT_SHA"], source)
        self.assertEqual(C["CHUNKS"], tuple(hashlib.sha256(bytes([65+i])*262144).hexdigest() for i in range(3)))
        path = self.work / "content-provider-adaptive-publication.json"
        self.write(path, json.dumps(seed()).encode())
        self.assertEqual(C["publication"](self.root, self.uid, now=1001), binding())
        for key, value in (("object_sha256", "0"*64), ("chunks", 9), ("replica_c_chunks", 19),
                           ("publisher_removed", False), ("expires_unix_seconds", 999)):
            broken = seed(); broken[key] = value
            self.write(path, json.dumps(broken).encode())
            with self.assertRaises(ValueError):
                C["publication"](self.root, self.uid, now=1001)

    def test_cold_initial_state_real_complete_hashes_no_writes_or_store_lock(self):
        watcher = self.observer()
        self.assertEqual(watcher.sample(), 0)
        cache = self.parent / "cache"; cache.mkdir(mode=0o700)
        for i, name in enumerate(C["CHUNKS"]):
            self.write(cache/name, bytes([65+i])*262144)
            self.assertEqual(watcher.sample(), i+1)
        self.assertEqual(sorted(p.name for p in cache.iterdir()), sorted(C["CHUNKS"]))
        with self.assertRaises(ValueError):
            C["CacheObserver"](self.root, self.uid)

    def test_wrong_hash_size_symlink_hardlink_fifo_and_mode_fail_closed(self):
        watcher = self.observer()
        cache = self.parent / "cache"; cache.mkdir(mode=0o700)
        chunk = cache/C["CHUNKS"][0]
        for kind in ("hash", "size", "symlink", "hardlink", "fifo", "mode"):
            with self.subTest(kind=kind):
                if kind == "symlink": chunk.symlink_to("missing")
                elif kind == "fifo": os.mkfifo(chunk, 0o600)
                else:
                    self.write(chunk, b"B"*262144 if kind == "hash" else b"A"*(262143 if kind == "size" else 262144))
                    if kind == "hardlink": os.link(chunk, cache/"alias")
                    if kind == "mode": chunk.chmod(0o644)
                with self.assertRaises((OSError, ValueError)):
                    watcher.sample()
                chunk.unlink()
                if (cache/"alias").exists(): (cache/"alias").unlink()

    def test_directory_replacement_and_symlink_rejected(self):
        watcher = self.observer()
        cache = self.parent / "cache"; cache.mkdir(mode=0o700)
        self.assertEqual(watcher.sample(), 0)
        cache.rename(self.parent/"old")
        cache.mkdir(mode=0o700)
        with self.assertRaises(ValueError): watcher.sample()
        cache.rmdir(); cache.symlink_to("old", target_is_directory=True)
        with self.assertRaises(OSError): watcher.sample()

    def test_same_descriptor_read_detects_in_place_change_and_closes(self):
        target = self.work/"public"
        self.write(target, b"abc")
        actual = os.read
        descriptors = []
        def mutate(fd, count):
            descriptors.append(fd)
            data = actual(fd, count)
            if data:
                target.write_bytes(b"xyz")
                os.utime(target, ns=(1, 1))
            return data
        with patch.object(G["os"], "read", side_effect=mutate):
            with self.assertRaises(ValueError): C["file_bytes"](self.root, "public", self.uid, 3)
        with self.assertRaises(OSError): os.fstat(descriptors[0])

    def test_closed_receipt_is_private_exclusive_and_no_raw_paths(self):
        result, _ = run()
        name = C["PREFIX"]+"-controller.json"
        C["write_record"](self.root, name, result)
        data = C["file_bytes"](self.root, name, self.uid, C["MAX_REPORT"])
        self.assertEqual(json.loads(data), result)
        self.assertNotIn(str(self.work).encode(), data)
        with self.assertRaises(FileExistsError): C["write_record"](self.root, name, result)

    def test_publication_exposes_only_complete_json_and_cleans_failed_stage(self):
        result, _ = run()
        name = C["PREFIX"]+"-controller.json"
        actual = C["publish"]
        def inspect(parent, temporary, final):
            self.assertFalse((self.work/final).exists())
            self.assertEqual(json.loads(C["file_bytes"](parent, temporary, self.uid, C["MAX_REPORT"])), result)
            actual(parent, temporary, final)
        with patch.dict(G, {"publish": inspect}): C["write_record"](self.root, name, result)
        self.assertEqual(json.loads((self.work/name).read_bytes()), result)
        self.assertFalse((self.work/("."+name+".part")).exists())
        ready = C["PREFIX"]+"-ready.json"
        with patch.dict(G, {"publish": Mock(side_effect=OSError("simulated"))}):
            with self.assertRaises(OSError): C["write_record"](self.root, ready, {})
        self.assertFalse((self.work/ready).exists())
        self.assertFalse((self.work/("."+ready+".part")).exists())


class ProcessContractTests(unittest.TestCase):
    def test_host_guard_rejects_before_any_fork(self):
        with patch.object(G["os"], "fork", side_effect=AssertionError("must never fork")), \
                patch.object(G["os"], "geteuid", return_value=1000):
            with self.assertRaises(ValueError): C["guest"](Path("/tmp/not-a-guest"))
        with patch.dict(G, {"observe": Mock(side_effect=AssertionError("no worker CLI"))}):
            self.assertEqual(C["main"](["script", "load", "1"]), 1)

    def test_actual_owned_child_reap_only_signals_unreaped_children(self):
        workers = C["Workers"](types.SimpleNamespace(pw_uid=985, pw_gid=985))
        workers.children = {11: None, 12: None}; workers.ready = 2
        responses = {11: [(11, 0)], 12: [(0, 0), (12, signal.SIGTERM)]}
        def waitpid(pid, flags): return responses[pid].pop(0)
        with patch.object(G["os"], "waitpid", side_effect=waitpid), \
                patch.object(G["os"], "kill") as kill, \
                patch.object(G["time"], "sleep"):
            workers.stop()
        kill.assert_called_once_with(12, signal.SIGTERM)
        self.assertEqual(workers.receipt()["reaped"], 2)

    def test_failed_handshake_keeps_exact_child_owned_for_cleanup(self):
        workers = C["Workers"](types.SimpleNamespace(pw_uid=985, pw_gid=985))
        with patch.object(G["os"], "fork", return_value=12345), \
                patch.object(G["select"], "select", return_value=([], [], [])), \
                patch.object(G["time"], "monotonic_ns", return_value=1):
            with self.assertRaises(ValueError): workers.start(10_000_000_000)
        self.assertEqual(workers.children, {12345: None})
        self.assertEqual(workers.ready, 0)

    def test_fork_cancellation_cannot_precede_child_ownership(self):
        workers = C["Workers"](types.SimpleNamespace(pw_uid=985, pw_gid=985))
        calls = []
        def mask(how, value):
            calls.append((how, value))
            if how == signal.SIG_SETMASK:
                self.assertEqual(workers.children, {12345: None})
                raise InterruptedError()
            self.assertEqual(value, {signal.SIGTERM, signal.SIGINT})
            return {signal.SIGUSR1}
        with patch.object(G["os"], "fork", return_value=12345), \
                patch.object(G["signal"], "pthread_sigmask", side_effect=mask), \
                patch.object(G["time"], "monotonic_ns", return_value=1):
            with self.assertRaises(InterruptedError): workers.start(10_000_000_000)
        self.assertEqual(calls[-1], (signal.SIG_SETMASK, {signal.SIGUSR1}))
        self.assertEqual(workers.ready, 0)

    def test_child_sandbox_restores_parent_death_signal_after_uid_drop(self):
        # Run setup with every process-mutating operation mocked and a clock
        # already past the loop deadline after its acknowledgement: zero load.
        events = []
        libc = types.SimpleNamespace(prctl=lambda option, arg, *_: events.append(("prctl", option, arg)) or 0)
        status = "".join(f"{key}:\t0000000000000000\n" for key in
                         ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")) + "NoNewPrivs:\t1\n"
        names = ("setsid", "umask", "setgroups", "setresgid", "setresuid", "sched_setaffinity",
                 "dup2", "closerange", "close", "write")
        patches = [patch.object(G["os"], name, side_effect=lambda *args, n=name: events.append((n, *args)))
                   for name in names]
        for item in patches: item.start()
        try:
            with patch.object(G["ctypes"], "CDLL", return_value=libc), \
                    patch.object(G["os"], "getppid", return_value=123), \
                    patch.object(G["os"], "getresuid", return_value=(985,)*3), \
                    patch.object(G["os"], "getresgid", return_value=(985,)*3), \
                    patch.object(G["os"], "getgroups", return_value=[]), \
                    patch.object(G["os"], "sched_getaffinity", return_value={1}), \
                    patch.object(G["os"], "open", return_value=4), \
                    patch.object(G["signal"], "signal"), \
                    patch.object(G["signal"], "pthread_sigmask", side_effect=lambda *args: events.append(("sigmask", *args))), \
                    patch.object(G["resource"], "setrlimit") as limit, \
                    patch.object(G["resource"], "getrlimit", return_value=(1024, 1024)), \
                    patch.object(G["Path"], "read_text", return_value=status), \
                    patch.object(G["time"], "monotonic_ns", side_effect=[0, 100]):
                C["child"](1, 100, 123, 985, 985, 9, {signal.SIGUSR1})
                self.assertGreaterEqual(limit.call_count, 5)
        finally:
            for item in reversed(patches): item.stop()
        death = [i for i, event in enumerate(events) if event == ("prctl", 1, signal.SIGKILL)]
        uid = events.index(("setresuid", 985, 985, 985))
        self.assertEqual(len(death), 2)
        self.assertLess(death[0], uid); self.assertGreater(death[1], uid)
        self.assertGreater(events.index(("sigmask", signal.SIG_SETMASK, {signal.SIGUSR1})), death[0])
        self.assertIn(("prctl", 38, 1), events)
        self.assertIn(("write", 3, b"1"), events)


if __name__ == "__main__":
    unittest.main()
