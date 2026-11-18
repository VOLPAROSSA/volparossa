#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert profile-6 preparation tests, not Android/core/network acceptance.

Only owned temporary files and an unlistened local Unix socket are made. Guest
identity/namespace boundaries are explicitly mocked for positive fixtures; the
real boundary is tested separately for rejection on this ordinary process.
No fixture binary, SDK, subprocess, provider server or origin request executes.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

A = runpy.run_path(str(Path(__file__).with_name("weather-android-delivery.py")))
G = A["prepare"].__globals__
B = A["B"]
MANIFEST = B["manifest"].__globals__


class AndroidPreparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wa-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.layout = A["paths"](self.work)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.work.chmod(0o755)
        for path, mode in ((self.work / "bin", 0o755), (self.work / "client-fixtures", 0o700),
                (self.layout["viewer"], 0o700), (self.work / "runtime-client", 0o750),
                (self.layout["control"].parent, 0o750), (self.layout["cache_parent"], 0o710)):
            path.mkdir(mode=mode); path.chmod(mode)
        self.save(self.layout["binary"], b"inert binary; never execute\n", 0o555)
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.control.close)
        self.control.bind(str(self.layout["control"]))
        self.layout["control"].chmod(0o660)
        self.selection = dict(schema=2, products={})
        for index, (key, product) in enumerate(A["P"]["PRODUCTS"].items()):
            self.selection["products"][key] = dict(publication=dict(publisher_key="a" * 64,
                name=product["name"], revision=1, manifest_id=str(index + 1) * 64,
                sha256=str(index + 3) * 64, bytes=4000 + index,
                expires_unix_seconds=int(time.time()) + 600),
                query=A["P"]["fixed_query"](key, "2026-10-10T00:00:00.000Z"))
        self.selection_raw = B["encode"](self.selection)
        self.save(self.layout["viewer"] / "selection.json", self.selection_raw, 0o400)
        self.make_source()
        self.boundary = unittest.mock.Mock(return_value={})
        self.seams = patch.dict(G, ROOT_UID=self.uid, WORKER_UID=self.uid,
            accounts=lambda group: (self.uid, self.gid), boundary=self.boundary,
            validate_work=lambda path, gid: A["owned"](path, stat.S_ISDIR, 0o755, self.uid, gid))
        self.seams.start(); self.addCleanup(self.seams.stop)

    @staticmethod
    def save(path, raw, mode=0o600):
        # These paths belong only to this test's disposable fixture. Mutating
        # an intentionally frozen input requires restoring its owner's write bit.
        if path.exists(): path.chmod(0o600)
        path.write_bytes(raw); path.chmod(mode)

    def make_source(self):
        raw = b"inert source; never execute\n"
        digest = hashlib.sha256(raw).hexdigest()
        self.pin = patch.dict(MANIFEST, NODE_SHA=digest, DECODER_SHA_V4=digest, PIN_SHA=digest, BUILD_SHA_V4=digest)
        self.pin.start(); self.addCleanup(self.pin.stop)
        files = {name: dict(bytes=len(raw), sha256=digest, mode=B["mode"](name)) for name in B["FIXED_V6"]}
        self.admission = patch.dict(MANIFEST, public_android_admission=lambda:
            dict(files={name: {key: item[key] for key in ("bytes", "sha256")} for name, item in files.items()}))
        self.admission.start(); self.addCleanup(self.admission.stop)
        source = self.layout["source"]
        for name, item in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.save(path, raw, item["mode"])
        raw_manifest = B["encode"](dict(version=6, kind=B["KIND"], files=files))
        self.digest = hashlib.sha256(raw_manifest).hexdigest()
        self.save(source / "INPUTS.json", raw_manifest, 0o400)
        for path in (source, *(p for p in source.rglob("*") if p.is_dir())): path.chmod(0o500)

    def run_prepare(self):
        return A["prepare"](self.work, self.digest, "net:[111]", "net:[222]", self.gid)

    def pristine(self):
        self.assertEqual({p.name for p in self.layout["viewer"].iterdir()}, {"selection.json"})
        self.assertEqual((self.layout["viewer"] / "selection.json").read_bytes(), self.selection_raw)

    def test_only_configuration_and_private_empty_directories_are_created(self):
        # Assert even the imported legacy download/run utility cannot be used.
        with patch("subprocess.Popen", side_effect=AssertionError("no process allowed")), \
                patch.dict(A["P"], run=lambda *a: self.fail("no legacy runner allowed")):
            report = self.run_prepare()
        self.boundary.assert_called_once_with("net:[111]", "net:[222]", self.gid)
        A["validate_prepared"](report)
        self.assertEqual({p.name for p in self.layout["viewer"].iterdir()},
            {"selection.json", "config.json", "scratch", "socket", "proof"})
        for key in A["DIRECTORIES"]:
            path = self.layout["viewer"] / key
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(list(path.iterdir()), [])
        self.assertEqual(list(self.layout["cache_parent"].iterdir()), [])
        self.assertFalse(self.layout["socket"].exists())
        self.assertEqual(stat.S_IMODE(self.layout["config"].stat().st_mode), 0o600)
        self.assertEqual(report["selection_sha256"], hashlib.sha256(self.selection_raw).hexdigest())
        self.assertEqual(report["config_sha256"], hashlib.sha256(self.layout["config"].read_bytes()).hexdigest())
        self.assertEqual(report["core_sha256"], hashlib.sha256(self.layout["binary"].read_bytes()).hexdigest())
        self.assertEqual(report["manifest_sha256"], self.digest)
        for key in ("runtime_executed", "forecast_prefetched", "native_android_proven", "joined_delivery_proven"):
            self.assertIs(report[key], False)
        encoded = json.dumps(report)
        for forbidden in (str(self.work), "latitude", "longitude", "publisher_key", "provider_peer_ids", "forecast.json"):
            self.assertNotIn(forbidden, encoded)

    def test_exact_production_configuration_preserves_both_queries_and_publications(self):
        self.run_prepare()
        config = json.loads(self.layout["config"].read_bytes())
        self.assertEqual(set(config), {"core", "variables", "airQuality"})
        self.assertEqual(config["variables"], A["P"]["V1"]["VARIABLES"])
        self.assertEqual(config["airQuality"]["variables"], ["pm2_5", "pm10"])
        for key, core in (("weather", config["core"]), ("air_quality", config["airQuality"]["core"])):
            selected = self.selection["products"][key]
            self.assertEqual(core, dict(mode="core-cache", executable=str(self.layout["binary"]),
                controlSocket=str(self.layout["control"]),
                cache=str(self.layout["cache_parent"] / A["P"]["product"](key)["cache"]),
                scratchParent=str(self.layout["scratch"]), publisherKey=selected["publication"]["publisher_key"],
                name=selected["publication"]["name"], minRevision=1, query=selected["query"], cacheMode="create-or-open"))
        self.assertNotEqual(config["core"]["cache"], config["airQuality"]["core"]["cache"])

    def test_standard_work_paths_and_tunnel_basename_fit_socket_bound(self):
        work = Path("/opt/va." + "a" * 32 + ".ABC123")
        layout = A["paths"](work)
        self.assertEqual(layout["socket"].name, "core-api.sock")
        self.assertLess(len(os.fsencode(layout["socket"])), 104)
        self.assertNotEqual(layout["proof"], layout["socket"].parent)
        self.assertNotIn("state-client", str(layout["cache_parent"]))

    def test_manifest_digest_tree_and_exact_profile_must_match_before_writes(self):
        with self.assertRaises(ValueError): A["prepare"](self.work, "f" * 64, "net:[111]", "net:[222]", self.gid)
        self.pristine()
        source = self.layout["source"] / "volparossa-weather/src/provider-core.mjs"
        self.save(source, b"different inert module\n", 0o400)
        with self.assertRaises(ValueError): self.run_prepare()
        self.pristine()

    def test_historical_manifest_cannot_enter_prepare(self):
        real = B["manifest"]
        def old_manifest(raw, digest):
            result = real(raw, digest); result["version"] = 5; return result
        with patch.dict(B, manifest=old_manifest), self.assertRaises(ValueError): self.run_prepare()
        self.pristine()

    def test_boundary_failure_precedes_filesystem_additions(self):
        self.boundary.side_effect = ValueError("not the protected worker")
        with self.assertRaises(ValueError): self.run_prepare()
        self.pristine()

    def test_existing_cache_or_dangling_symlink_is_not_adopted(self):
        for key in A["P"]["PRODUCTS"]:
            path = self.layout["cache_parent"] / A["P"]["product"](key)["cache"]
            for symlink in (False, True):
                if symlink: path.symlink_to(self.work / "missing")
                else: path.mkdir(mode=0o700)
                try:
                    with self.subTest(key=key, symlink=symlink), self.assertRaises(ValueError): self.run_prepare()
                    self.pristine()
                finally:
                    if symlink: path.unlink()
                    else: path.rmdir()

    def test_unsearchable_or_wrong_mode_cache_parent_is_not_absent_cache(self):
        for mode in (0o700, 0o750, 0o770, 0o777):
            self.layout["cache_parent"].chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError): self.run_prepare()
            self.pristine()
        self.layout["cache_parent"].chmod(0o710)
        with patch.dict(G, absent=lambda _: (_ for _ in ()).throw(PermissionError("no search"))), self.assertRaises(PermissionError):
            self.run_prepare()
        self.pristine()

    def test_missing_cache_parent_is_never_created(self):
        self.layout["cache_parent"].rmdir()
        with self.assertRaises(FileNotFoundError): self.run_prepare()
        self.assertFalse(self.layout["cache_parent"].exists())
        self.pristine()

    def test_binaries_and_sockets_require_exact_kind_mode_and_identity(self):
        for name, modes in (("binary", (0o755, 0o555)), ("control", (0o600, 0o660))):
            path = self.layout[name]; bad, good = modes
            path.chmod(bad)
            with self.subTest(name=name), self.assertRaises(ValueError): self.run_prepare()
            self.pristine(); path.chmod(good)
        saved = self.work / "control-saved.sock"
        self.layout["control"].rename(saved)
        self.save(self.layout["control"], b"not a socket", 0o660)
        with self.assertRaises(ValueError): self.run_prepare()
        self.pristine()

    def test_symlink_and_hardlinked_selection_and_binary_are_rejected(self):
        for path in (self.layout["binary"], self.layout["viewer"] / "selection.json"):
            saved = self.work / "saved-input"
            path.rename(saved); path.symlink_to(saved)
            with self.subTest(path=path.name, kind="symlink"), self.assertRaises(ValueError): self.run_prepare()
            self.pristine_if_selection_saved(path, saved)
            path.unlink(); saved.rename(path)
            os.link(path, saved)
            with self.subTest(path=path.name, kind="hardlink"), self.assertRaises(ValueError): self.run_prepare()
            saved.unlink()

    def pristine_if_selection_saved(self, path, saved):
        self.assertEqual({p.name for p in self.layout["viewer"].iterdir()}, {"selection.json"})
        self.assertEqual((saved if path.name == "selection.json" else self.layout["viewer"] / "selection.json").read_bytes(),
            self.selection_raw)

    def test_expired_mutated_or_extra_selection_is_rejected_before_writes(self):
        candidates = []
        for key in A["P"]["PRODUCTS"]:
            for field, value in (("name", "private-mail"), ("expires_unix_seconds", 1)):
                selected = copy.deepcopy(self.selection); selected["products"][key]["publication"][field] = value
                candidates.append(selected)
        selected = copy.deepcopy(self.selection); selected["products"]["weather"]["query"]["latitude"] = 51
        candidates.append(selected)
        selected = copy.deepcopy(self.selection); selected["forecast"] = "forbidden"; candidates.append(selected)
        for selected in candidates:
            self.save(self.layout["viewer"] / "selection.json", B["encode"](selected), 0o400)
            with self.assertRaises(ValueError): self.run_prepare()
            self.assertEqual({p.name for p in self.layout["viewer"].iterdir()}, {"selection.json"})

    def test_duplicate_selection_keys_are_rejected(self):
        self.save(self.layout["viewer"] / "selection.json", self.selection_raw.rstrip()[:-1] + b',"schema":2}\n', 0o400)
        with self.assertRaises(ValueError): self.run_prepare()

    def test_existing_viewer_content_and_repeat_prepare_are_not_overwritten(self):
        self.save(self.layout["viewer"] / "forecast.json", b"original forecast must not enter viewer")
        with self.assertRaises(ValueError): self.run_prepare()
        (self.layout["viewer"] / "forecast.json").unlink()
        self.run_prepare()
        before = self.layout["config"].read_bytes()
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual(self.layout["config"].read_bytes(), before)

    def test_all_partial_creation_steps_rollback_without_touching_inputs(self):
        directory, file = A["Additions"].directory, A["Additions"].file
        for failure in (*A["DIRECTORIES"], "config.json"):
            def after_directory(owner, name):
                directory(owner, name)
                if name == failure: raise InterruptedError("injected interruption")
            def after_file(owner, name, raw):
                file(owner, name, raw)
                if name == failure: raise InterruptedError("injected interruption")
            with self.subTest(failure=failure), patch.object(A["Additions"], "directory", after_directory), \
                    patch.object(A["Additions"], "file", after_file), self.assertRaises(InterruptedError):
                self.run_prepare()
            self.pristine()
            self.assertEqual(list(self.layout["cache_parent"].iterdir()), [])

    def test_partial_write_and_zero_write_are_cleaned(self):
        write = os.write
        for zero in (False, True):
            calls = 0
            def partial(fd, raw):
                nonlocal calls
                calls += 1
                if zero: return 0
                if calls == 1: return write(fd, raw[:3])
                raise OSError("injected disk failure")
            with self.subTest(zero=zero), patch("os.write", partial), self.assertRaises((OSError, ValueError)):
                self.run_prepare()
            self.pristine()

    def test_post_creation_input_mutation_rolls_back_only_additions(self):
        file = A["Additions"].file
        def mutate(owner, name, raw):
            file(owner, name, raw)
            self.save(self.layout["binary"], b"changed inert binary", 0o555)
        with patch.object(A["Additions"], "file", mutate), self.assertRaises(ValueError): self.run_prepare()
        self.pristine()

    def test_late_selection_change_rolls_back_without_restoring_caller_input(self):
        file = A["Additions"].file
        changed = copy.deepcopy(self.selection)
        changed["products"]["weather"]["publication"]["sha256"] = "f" * 64
        raw_changed = B["encode"](changed)
        def mutate(owner, name, raw):
            file(owner, name, raw)
            self.save(self.layout["viewer"] / "selection.json", raw_changed, 0o400)
        with patch.object(A["Additions"], "file", mutate), self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual({p.name for p in self.layout["viewer"].iterdir()}, {"selection.json"})
        self.assertEqual((self.layout["viewer"] / "selection.json").read_bytes(), raw_changed)

    def test_late_control_or_cache_parent_change_is_rejected(self):
        file = A["Additions"].file
        for key, bad, good in (("control", 0o600, 0o660), ("cache_parent", 0o750, 0o710)):
            def mutate(owner, name, raw):
                file(owner, name, raw); self.layout[key].chmod(bad)
            with self.subTest(key=key), patch.object(A["Additions"], "file", mutate), self.assertRaises(ValueError):
                self.run_prepare()
            self.pristine()
            self.assertEqual(stat.S_IMODE(self.layout[key].stat().st_mode), bad)
            self.layout[key].chmod(good)

    def test_oversized_config_is_rejected_before_creation(self):
        with patch.dict(G, configuration=lambda *_: {"overflow": "x" * (A["MAX_CONFIG"] + 1)}), self.assertRaises(ValueError):
            self.run_prepare()
        self.pristine()

    def test_late_cache_creation_is_rejected_and_not_deleted(self):
        file = A["Additions"].file
        path = self.layout["cache_parent"] / "weather-cache"
        def mutate(owner, name, raw):
            file(owner, name, raw); path.mkdir(mode=0o700)
        with patch.object(A["Additions"], "file", mutate), self.assertRaises(ValueError): self.run_prepare()
        self.pristine(); self.assertTrue(path.is_dir())

    def test_late_expiry_is_not_renewed(self):
        file = A["Additions"].file
        now = int(time.time()); clock = [now]
        def expire(owner, name, raw):
            file(owner, name, raw); clock[0] = now + 1000
        with patch.object(A["Additions"], "file", expire), patch("time.time", lambda: clock[0]), self.assertRaises(ValueError):
            self.run_prepare()
        self.pristine()

    def test_replaced_addition_survives_and_cleanup_failure_is_explicit(self):
        file = A["Additions"].file
        def replace(owner, name, raw):
            file(owner, name, raw)
            self.layout["config"].rename(self.work / "retained-original")
            self.save(self.layout["config"], b"foreign replacement")
            raise ValueError("initial failure")
        with patch.object(A["Additions"], "file", replace), self.assertRaises(A["PreparationCleanupUnconfirmed"]):
            self.run_prepare()
        self.assertEqual(self.layout["config"].read_bytes(), b"foreign replacement")
        self.assertTrue(all(not self.layout["viewer"].joinpath(name).exists() for name in A["DIRECTORIES"]))

    def test_foreign_child_is_not_recursively_removed(self):
        directory = A["Additions"].directory
        def populate(owner, name):
            directory(owner, name)
            self.save(self.layout["viewer"] / name / "foreign", b"foreign data")
            raise ValueError("initial failure")
        with patch.object(A["Additions"], "directory", populate), self.assertRaises(A["PreparationCleanupUnconfirmed"]):
            self.run_prepare()
        self.assertEqual((self.layout["scratch"] / "foreign").read_bytes(), b"foreign data")

    def test_renamed_viewer_cleanup_uses_original_pinned_directory_only(self):
        file = A["Additions"].file
        original = self.work / "original-viewer"
        def rename(owner, name, raw):
            file(owner, name, raw)
            self.layout["viewer"].rename(original)
            self.layout["viewer"].mkdir(mode=0o700)
            self.save(self.layout["viewer"] / "config.json", b"foreign replacement")
        with patch.object(A["Additions"], "file", rename), self.assertRaises(ValueError): self.run_prepare()
        self.assertEqual({p.name for p in original.iterdir()}, {"selection.json"})
        self.assertEqual(self.layout["config"].read_bytes(), b"foreign replacement")

    def test_agent_cache_parent_and_state_are_never_modified(self):
        state = self.work / "state-client"; state.mkdir(mode=0o700)
        self.save(state / "identity.key", b"inert private sentinel")
        before = (A["B"]["identity"](self.layout["cache_parent"].stat()), (state / "identity.key").read_bytes())
        self.run_prepare()
        self.assertEqual(before, (A["B"]["identity"](self.layout["cache_parent"].stat()), (state / "identity.key").read_bytes()))

    def test_closed_report_refuses_extra_claims_and_false_types(self):
        report = self.run_prepare()
        for field, value in (("schema", True), ("prepared", 1), ("native_android_proven", True),
                ("runtime_executed", True), ("forecast_prefetched", True), ("joined_delivery_proven", True),
                ("profile", "android"), ("config_sha256", "invalid"), ("manifest_sha256", "f" * 63)):
            invalid = dict(report); invalid[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): A["validate_prepared"](invalid)
        with self.assertRaises(ValueError): A["validate_prepared"](dict(report, raw_forecast={}))


class WorkerGuards(unittest.TestCase):
    def test_real_worker_boundary_rejects_ordinary_test_process(self):
        with self.assertRaises(ValueError): A["boundary"]("net:[111]", "net:[222]", 12345)

    def test_accounts_are_resolved_not_hardcoded_and_control_group_is_separate(self):
        agent = SimpleNamespace(pw_uid=912, pw_gid=913)
        worker = SimpleNamespace(pw_uid=985, pw_gid=914)
        with patch("pwd.getpwnam", side_effect=lambda name: agent if name == "volparossa" else worker), \
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=915)):
            self.assertEqual(A["accounts"](915), (912, 913))
            for group in (0, True, 65536, 913, 914):
                with self.subTest(group=group), self.assertRaises(ValueError): A["accounts"](group)
            agent.pw_uid = 985
            with self.assertRaises(ValueError): A["accounts"](915)

    def test_nonfixed_work_root_is_rejected_without_changing_anything(self):
        for work in (Path("/"), Path("/tmp/test"), Path("/opt/va.short.ABC123"),
                Path("/opt/vu.ABC123"), Path("/opt/va." + "a" * 32 + ".ABC123/subdir")):
            with self.subTest(work=work), self.assertRaises(ValueError): A["validate_work"](work, 913)

    def test_main_accepts_only_explicit_prepare_and_passes_exact_arguments(self):
        args = ["driver", "prepare", "/opt/va." + "a" * 32 + ".ABC123", "b" * 64, "net:[111]", "net:[222]", "915"]
        runner = unittest.mock.Mock(return_value={"prepared": False})
        with patch.dict(G, prepare=runner), patch("sys.argv", args), patch("builtins.print"):
            A["main"]()
        runner.assert_called_once_with(Path(args[2]), "b" * 64, "net:[111]", "net:[222]", 915)
        for action in ("serve", "cold", "download", "prepare-v5", "cleanup"):
            with self.subTest(action=action), patch("sys.argv", ["driver", action, *args[2:]]), self.assertRaises(ValueError):
                A["main"]()


if __name__ == "__main__": unittest.main()
