#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise runner argument/path/resource contracts without a VM or network."""
import os
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
RUNNERS = ("run-alpha-topology-vm.sh", "kvm-alpha-topology.sh")
BUNDLE = "--weather-client-bundle"
DIGEST = "--weather-client-manifest-sha256"
SHA = "b" * 64


class WeatherRunner(unittest.TestCase):
    def call(self, runner, *args, env=None):
        return subprocess.run(["/bin/sh", str(HERE / runner), *args],
                              capture_output=True, timeout=5, env=env)

    def test_runners_require_the_joined_runtime_profile_not_only_valid_archive(self):
        for runner, calls in (("run-alpha-topology-vm.sh", 3), ("kvm-alpha-topology.sh", 2)):
            source = (HERE / runner).read_text()
            verifier_lines = [line for line in source.splitlines()
                              if 'weather-client-bundle.py" verify' in line or 'weather-client-bundle.py verify' in line]
            self.assertEqual(len(verifier_lines), calls)
            self.assertTrue(all(" verify-runtime " in line for line in verifier_lines))

    def required(self, runner, scenario="content-provider"):
        args = ["--execute", "--yes", "--scenario", scenario,
                "--output", "/unread/output", "--expected-commit", "a" * 40,
                "--mpquic", "/unread/native"]
        if runner.startswith("run-"):
            args += ["--image", "/unread/image"]
        else:
            args += ["--source", "/unread/source", "--bin", "/unread/bin"]
        return args

    def test_shells_and_unselected_preview_remain_inert(self):
        for runner in RUNNERS:
            subprocess.run(["/bin/sh", "-n", str(HERE / runner)], check=True, timeout=5)
            env = dict(os.environ, weather_client_bundle="/unread/bundle",
                       weather_client_manifest_sha256=SHA)
            result = self.call(runner, "--preview", "--scenario", "content-provider", env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"PREVIEW ONLY", result.stdout)
            self.assertNotIn(b"Additional proof:", result.stdout)

    def test_explicit_pair_and_no_preview_or_duplicate_authority(self):
        for runner in RUNNERS:
            for flag in (BUNDLE, DIGEST):
                for value in (None, "", "/unread"):
                    args = [flag] + ([] if value is None else [value])
                    self.assertEqual(self.call(runner, "--preview", *args).returncode, 64)
                self.assertEqual(self.call(runner, *self.required(runner),
                                          flag, "one", flag, "two").returncode, 64)
            cases = ([BUNDLE, "/unread/bundle"], [DIGEST, SHA],
                     [BUNDLE, "relative", DIGEST, SHA],
                     [BUNDLE, "/unread/../bundle", DIGEST, SHA],
                     [BUNDLE, "/unread/bundle", DIGEST, "g" * 64],
                     [BUNDLE, "/unread/bundle", DIGEST, "b" * 63],
                     [BUNDLE, "/unread/bundle", DIGEST, SHA,
                      "--browser-filter-bundle", "/unread/browser",
                      "--browser-filter-manifest-sha256", SHA])
            for args in cases:
                with self.subTest(runner=runner, args=args):
                    self.assertEqual(self.call(runner, *self.required(runner), *args).returncode, 64)
            self.assertEqual(self.call(runner, *self.required(runner, "content"),
                                      BUNDLE, "/unread/bundle", DIGEST, SHA).returncode, 64)

    def test_weather_scratch_is_private_disk_sibling_not_exported_evidence(self):
        source = (HERE / RUNNERS[0]).read_text()
        fragment = source.split("RUN_DIRECTORY_PARENT=/tmp\n", 1)[1].split("QEMU_PID=\n", 1)[0]
        prefix = ("set -eu\nscenario=content-provider\nbrowser_filter_bundle=\n"
                  "weather_client_bundle=/selected/weather\noutput_directory=$1\nRUN_DIRECTORY_PARENT=/tmp\n")
        with tempfile.TemporaryDirectory(prefix="weather-runner-test-", dir=HERE) as temporary:
            parent = Path(temporary).resolve()
            output = parent / "evidence"
            output.mkdir()
            result = subprocess.run(["/bin/sh", "-c", prefix + fragment + 'printf "%s\\n" "$RUN_DIRECTORY"\n',
                                     "fixture", str(output)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            scratch = Path(result.stdout.decode().strip())
            self.assertEqual(scratch.parent, parent)
            self.assertTrue(scratch.name.startswith("weather-client-kvm."))
            self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
            self.assertEqual(list(output.iterdir()), [])
            for filesystem in ("tmpfs", "ramfs"):
                stub = 'stat() { printf "%s\\n" "' + filesystem + '"; }\n'
                result = subprocess.run(["/bin/sh", "-c", prefix + stub + fragment,
                                         "fixture", str(output)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 69, result.stderr)

    def test_weather_uses_same_four_gib_guest_and_two_gib_host_reserve(self):
        source = (HERE / RUNNERS[0]).read_text()
        memory = "guest_memory_for_scenario() {\n" + source.split("guest_memory_for_scenario() {\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        gate = "guest_memory_mib=$(guest_memory_for_scenario)\n" + source.split("guest_memory_mib=$(guest_memory_for_scenario)\n", 1)[1].split("qemu_usernet=", 1)[0]
        script = ("set -eu\nscenario=content-provider\nbrowser_filter_bundle=\nweather_client_bundle=/selected\n"
                  'fixture_available=$1\nawk() { printf "%s\\n" "$fixture_available"; }\n' + memory + gate +
                  'printf "%s:%s\\n" "$guest_memory_mib" "$runner_reserve_mib"\n')
        for available, expected in ((6144 * 1024 - 1, 69), (6144 * 1024, 0), ("unknown", 69)):
            result = subprocess.run(["/bin/sh", "-c", script, "fixture", str(available)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertEqual(result.stdout.decode().strip(), "4096:2048")

    def test_guest_discriminator_binds_only_weather_arguments(self):
        source = (HERE / RUNNERS[0]).read_text()
        guest = source.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
        fragment = guest[guest.index("expected_commit=$1"):guest.index("cd /home/vpci")]
        script = "set -eu\n" + fragment + 'printf "%s:%s:%s\\n" "$scenario" "$browser_filter_manifest_sha256" "$weather_client_manifest_sha256"\n'
        base = ["a" * 40, SHA, SHA, "none", "content-provider"]
        for suffix, expected in ((["weather-client", SHA, SHA], 0), (["unknown", SHA, SHA], 64),
                                 (["weather-client", "none", SHA], 64), (["weather-client", SHA], 64)):
            result = subprocess.run(["/bin/sh", "-c", script, "fixture", *base, *suffix], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertEqual(result.stdout.decode().strip(), "content-provider:none:" + SHA)

    def test_control_observer_accepts_only_the_one_new_weather_prefix(self):
        source = (HERE / "content-provider-smoke.sh").read_text()
        body = source.split("content_provider_start_control_observer() {\n", 1)[1].split("\n}\n", 1)[0]
        function = "content_provider_start_control_observer() {\n" + body + "\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            script = ("set -eu\nWORK=$1\nPROVIDER_CONTROL_PID=\nprovider_control_ns=fixture\n"
                      "provider_control_ips=fixture\nip() { :; }\nwait_observer() { :; }\n" + function +
                      'content_provider_start_control_observer "$2"\n')
            for name, expected in (("weather-client-delivery-control", 0),
                                   ("content-provider-control-privacy", 0),
                                   ("weather-client-other", 1),
                                   ("weather-client-delivery-control-extra", 1),
                                   ("../weather-client-delivery-control", 1)):
                result = subprocess.run(["/bin/sh", "-c", script, "fixture", temporary, name],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_failed_weather_export_retains_safe_general_artifacts_and_failure_status(self):
        source = (HERE / "kvm-alpha-topology.sh").read_text()
        body = source.split("\ncopy_artifacts() {\n", 1)[1].split("\n}\n", 1)[0]
        function = "copy_artifacts() {\n" + body + "\n}\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            work = root / "work"
            work.mkdir()
            for name in ("host-state-before.json", "host-state-after.json", "a15-evidence.json"):
                (work / name).write_bytes(b'{"safe":true}\n')
            (work / "status-client.txt").write_bytes(b"connected: false\n")
            for name in ("weather-products-delivery-acquisition.err", "forecast.json", "config.json"):
                (work / name).write_bytes(b"PRIVATE CANARY")
            (work / "logs-client.txt").symlink_to(work / "config.json")
            for scenario in ("content-provider", "browser-network"):
                for export_status in (0, 1):
                    with self.subTest(scenario=scenario, export_status=export_status):
                        output = root / f"output-{scenario}-{export_status}"
                        output.mkdir()
                        script = "set -eu\n" + function + '''
WORK=$1
output_directory=$2
OUTPUT_UID=$3
OUTPUT_GID=$4
scenario=$5
protected_quote=no
weather_client_bundle=/selected
browser_filter_bundle=
weather_client_delivery_copy_artifacts() { return "$6"; }
if copy_artifacts; then actual=0; else actual=$?; fi
printf '%s\\n' "$actual"
'''
                        # A shell function has its own positional arguments.
                        script = script.replace('return "$6"', f"return {export_status}")
                        result = subprocess.run(["/bin/sh", "-c", script, "fixture", str(work), str(output),
                                                 str(os.getuid()), str(os.getgid()), scenario],
                                                capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.decode().strip(), str(export_status))
                        expected = {"host-state-before.json", "host-state-after.json", "a15-evidence.json"}
                        if scenario == "content-provider": expected.add("status-client.txt")
                        self.assertEqual({path.name for path in output.iterdir()}, expected)
                        for path in output.iterdir():
                            self.assertEqual(path.read_bytes(), (work / path.name).read_bytes())
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (os.getuid(), os.getgid()))
                            self.assertNotIn(b"PRIVATE CANARY", path.read_bytes())


class WeatherEmergencyExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (HERE / RUNNERS[0]).read_text()
        body = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        cls.api = {"__name__": "inert_weather_collector"}
        exec(compile(body, "weather-collector", "exec"), cls.api)

    def test_products_helper_requires_complete_root_owned_closure_without_v1_fallback(self):
        self.assertIn("weather-source-observer.mjs", self.api["WEATHER_PRODUCTS_HELPERS"])
        self.assertNotIn("weather-source-observer.mjs", self.api["WEATHER_CLIENT_HELPERS"])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            directory = work / "bin"
            directory.mkdir()
            for name in self.api["WEATHER_PRODUCTS_HELPERS"]:
                path = directory / name
                path.write_text("raise RuntimeError('inert; must not execute')\n")
                path.chmod(0o555)
            original = Path.lstat
            bad_path, fault = None, {}

            def fixture_stat(path):
                actual = original(path)
                # Simulate trusted root staging without requiring root, mounts,
                # chown, or changing the host. The selected fault stays real to
                # the production closure checker.
                values = dict(st_mode=actual.st_mode & ~0o022, st_uid=0,
                              st_nlink=actual.st_nlink, st_size=actual.st_size)
                if path == bad_path:
                    values.update(fault)
                return SimpleNamespace(**values)

            with patch.object(Path, "lstat", fixture_stat):
                self.assertEqual(self.api["weather_client_helper"](work), directory / "weather-products-delivery.py")
                for name in self.api["WEATHER_PRODUCTS_HELPERS"]:
                    bad_path = directory / name
                    for fault in (dict(st_uid=1000), dict(st_nlink=2),
                                  dict(st_mode=stat.S_IFREG | 0o666), dict(st_size=262145),
                                  dict(st_mode=stat.S_IFLNK | 0o555)):
                        with self.subTest(name=name, fault=fault):
                            self.assertIsNone(self.api["weather_client_helper"](work))
                bad_path, fault = None, {}
                observer = directory / "weather-source-observer.mjs"
                observer.unlink()
                self.assertIsNone(self.api["weather_client_helper"](work))
                observer.write_text("// inert fixture\n")
                observer.chmod(0o555)
                products = directory / "weather-products-delivery.py"
                products.unlink()
                self.assertEqual(self.api["weather_client_helper"](work), directory / "weather-client-delivery.py")
                products.symlink_to("missing-products-driver")
                self.assertIsNone(self.api["weather_client_helper"](work))

    def test_optional_v5_admission_is_checked_as_immutable_helper_not_exported(self):
        name = self.api["WEATHER_PRODUCTS_V5_ADMISSION"]
        self.assertEqual(name, "weather-public-overmorrow-v5.json")
        self.assertNotIn(name, self.api["WEATHER_PRODUCTS_HELPERS"])
        self.assertNotIn(name, self.api["WEATHER_PRODUCTS_NAMES"])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve(); directory = work / "bin"; directory.mkdir()
            for helper in self.api["WEATHER_PRODUCTS_HELPERS"]:
                (directory / helper).write_text("inert fixture\n")
            admission = directory / name
            original = Path.lstat
            fault = {}
            def fixture_stat(path):
                actual = original(path)
                values = dict(st_mode=actual.st_mode & ~0o022, st_uid=0,
                    st_nlink=actual.st_nlink, st_size=actual.st_size)
                if path == admission: values.update(fault)
                return SimpleNamespace(**values)
            with patch.object(Path, "lstat", fixture_stat):
                # Legacy export never needs an absent future record.
                self.assertEqual(self.api["weather_client_helper"](work), directory / "weather-products-delivery.py")
                admission.write_text("inert fixture, not an admission record\n")
                self.assertEqual(self.api["weather_client_helper"](work), directory / "weather-products-delivery.py")
                for fault in (dict(st_uid=1000), dict(st_nlink=2), dict(st_size=262145),
                        dict(st_mode=stat.S_IFREG | 0o666), dict(st_mode=stat.S_IFLNK | 0o555)):
                    with self.subTest(fault=fault):
                        self.assertIsNone(self.api["weather_client_helper"](work))
                fault = {}
                admission.unlink(); admission.symlink_to("missing-admission")
                self.assertIsNone(self.api["weather_client_helper"](work))

    def test_products_candidate_allowlist_never_exports_private_or_other_profile_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "output"
            target.mkdir()

            def inert_copy(command, **kwargs):
                self.assertEqual(command[4:6], ["copy-artifacts", str(root)])
                copied = Path(command[6])
                for name in self.api["WEATHER_CLIENT_NAMES"] | self.api["WEATHER_PRODUCTS_NAMES"] | {
                        "weather-products-delivery-config.json", "forecast.json", "private.log",
                        "weather-origin-http.json", "air-quality-origin-http.json", "weather-source-observer.mjs"}:
                    (copied / name).write_text("{}")

            with patch.object(self.api["subprocess"], "run", inert_copy):
                candidates = self.api["weather_client_candidates"](root, "work-1",
                    root / "weather-products-delivery.py", target)
            self.assertEqual({name for _, name in candidates},
                             {"work-1/" + name for name in self.api["WEATHER_PRODUCTS_NAMES"]})
            with patch.object(self.api["subprocess"], "run", side_effect=AssertionError("must not execute")):
                self.assertEqual(self.api["weather_client_candidates"](root, "work-1", root / "unknown.py", target), [])

    def test_products_failure_candidates_require_completed_closed_export(self):
        for outcome in ("success", "rejected", "missing-status", "bad-status", "float-schema", "unsafe-status", "missing-file",
                        "duplicate-status-key", "signal", "timeout", "oserror", "invalid-marker"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                target = root / "output"
                target.mkdir()
                marker = root / "weather-products-delivery-acquisition-failure.json"
                # The immutable helper must validate even a dangling symlink;
                # selection must never silently fall back to the success path.
                marker.symlink_to("missing-marker")

                def inert_copy(command, **kwargs):
                    self.assertEqual(command[4:6], ["copy-failure-artifacts", str(root)])
                    self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                    copied = Path(command[6])
                    if outcome != "invalid-marker":
                        exported = ["acquisition-failure", "tree-before", "input-cleanup"]
                        for suffix in exported:
                            path = copied / f"weather-products-delivery-{suffix}.json"
                            path.write_text('{"inert":true}')
                            path.chmod(0o600)
                        (copied / "forecast.json").write_text("PRIVATE CANARY")
                        (copied / "weather-products-delivery-acquisition.err").write_text("PRIVATE CANARY")
                        rejected = ["acquisition"] if outcome == "rejected" else []
                        status = dict(schema=2, kind="weather-products-failure-export", complete=True,
                                      success=not rejected, exported=exported, rejected=rejected)
                        if outcome == "bad-status": status["private"] = "PRIVATE CANARY"
                        if outcome == "float-schema": status["schema"] = 2.0
                        if outcome != "missing-status":
                            path = copied / "weather-products-delivery-export-status.json"
                            raw = json.dumps(status)
                            if outcome == "duplicate-status-key": raw = '{"schema":2,' + raw[1:]
                            path.write_text(raw)
                            path.chmod(0o644 if outcome == "unsafe-status" else 0o600)
                        if outcome == "missing-file":
                            (copied / "weather-products-delivery-input-cleanup.json").unlink()
                    if outcome == "timeout": raise subprocess.TimeoutExpired(command, 3)
                    if outcome == "oserror": raise OSError("inert")
                    if outcome in {"rejected", "missing-status", "invalid-marker", "signal"}:
                        raise subprocess.CalledProcessError(-15 if outcome == "signal" else 1, command)

                with patch.object(self.api["subprocess"], "run", inert_copy):
                    candidates = self.api["weather_client_candidates"](root, "work-1",
                        root / "weather-products-delivery.py", target)
                expected = ({"work-1/" + name for name in self.api["WEATHER_PRODUCTS_FAILURE_NAMES"]}
                            if outcome in {"success", "rejected"} else set())
                self.assertEqual({name for _, name in candidates}, expected)
                self.assertFalse(any(b"PRIVATE CANARY" in path.read_bytes() for path, _ in candidates))

    def acquisition(self):
        return dict(schema=1, success=True, origin_https=True, acquisition_outside_overlay=True,
                    upstream_signature_attested=False, synthetic_weather=False,
                    forecast_sha256=SHA, forecast_bytes=6000, decoder_sha256=SHA,
                    fields=[dict(lead_hours=step, parameter=parameter,
                                 index_sha256=SHA, field_sha256=SHA)
                            for step in (3, 9, 24) for parameter in ("2t", "10u", "10v")])

    def products_acquisition(self):
        return dict(schema=2, success=True, origin_https=True, acquisition_outside_overlay=True,
                    upstream_signature_attested=False, synthetic_weather=False, synthetic_air_quality=False,
                    independent_product_runs=True,
                    decoder_sha256="3a3b64581e6922db4287445f217f993f6967dea5fcc45ff66944b0bc883408f4",
                    products={name: dict(forecast_sha256=SHA, forecast_bytes=6000,
                        fields=[dict(lead_hours=step, parameter=parameter,
                                     index_sha256=SHA, field_sha256=SHA)
                                for step in steps for parameter in parameters])
                              for name, steps, parameters in (
                                  ("weather", (3, 9, 24, 48), ("2t", "10u", "10v", "tp")),
                                  ("air_quality", (3, 6, 12, 24, 48), ("PMTF", "PMTC")))})

    def collect(self, raw, limit=None, published=None, late_invalid=False, products=False,
                failure_marker=None, invalid_cleanup=False):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = "weather-products-delivery" if products else "weather-client-delivery"
            base = Path(temporary).resolve()
            home, opt, proc, cgroups = (base / name for name in ("home", "opt", "proc", "cgroups"))
            for directory in (home, opt, proc, cgroups):
                directory.mkdir()
            (home / "alpha-output").mkdir()
            if published is not None:
                early = home / "alpha-output" / (prefix + "-cold-evidence.json")
                early.write_bytes(published)
                early.chmod(0o600)
            work = opt / ("va." + "a" * 32 + ".ABC123")
            work.mkdir()
            source = work / (prefix + "-acquisition.json")
            source.write_bytes(raw)
            source.chmod(0o600)
            if failure_marker is not None:
                values = {"acquisition-failure": failure_marker,
                          "tree-before": dict(version=1, action="verify-tree", manifest_sha256=SHA,
                                              files=193, runtime_executed=False),
                          "input-cleanup": ({"private": "PRIVATE CANARY"} if invalid_cleanup else
                                            dict(directory_removed=True, files_removed=True))}
                for suffix, value in values.items():
                    path = work / f"{prefix}-{suffix}.json"
                    path.write_text(json.dumps(value))
                    path.chmod(0o600)
            if late_invalid:
                invalid = work / (prefix + "-evidence.json")
                invalid.write_text('{"unknown":"PRIVATE CANARY"}')
                invalid.chmod(0o600)
            for name in ("weather-client-delivery-cold-consumer.json", "weather-client-delivery-input.json",
                         "weather-client-delivery.err", "forecast.json", "config.json",
                         "weather-products-delivery-input.json", "weather-products-delivery-air_quality-cold-consumer.json",
                         "weather-products-delivery.err", "air-quality.json"):
                (work / name).write_text("PRIVATE CANARY")
            overrides = {"weather_client_helper": lambda root: HERE / (prefix + ".py")}
            if limit is not None:
                overrides["FILE_LIMIT"] = limit
            # Bypass only root-owned staging in this unprivileged inert test.
            # Actual production JSON validation and collector still execute.
            with patch.dict(self.api, overrides):
                archive = self.api["collect"](home, opt, "a" * 40, "content-provider", 124, cgroups, proc)
            with tarfile.open(archive, "r:gz") as bundle:
                return {item.name: bundle.extractfile(item).read() for item in bundle.getmembers()}

    def test_valid_receipt_survives_exactly_but_never_claims_vm_success(self):
        raw = json.dumps(self.acquisition(), indent=2).encode() + b"\n"
        files = self.collect(raw)
        self.assertEqual(files["work-1/weather-client-delivery-acquisition.json"], raw)
        summary = json.loads(files["vm-incomplete.json"])
        self.assertFalse(summary["success"])
        self.assertEqual(summary["cleanup"], {"complete": False, "verified": False})
        self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))

    def test_products_valid_receipt_survives_exactly_without_inventing_joined_success(self):
        raw = json.dumps(self.products_acquisition(), indent=2).encode() + b"\n"
        files = self.collect(raw, products=True)
        self.assertEqual(files["work-1/weather-products-delivery-acquisition.json"], raw)
        self.assertFalse(json.loads(files["vm-incomplete.json"])["success"])
        self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))
        self.assertFalse(any("weather-client-delivery" in name for name in files))

    def test_products_dedicated_failure_exports_survive_real_helper_and_invalid_sibling(self):
        diagnostic = dict(schema=2, kind="weather-products-acquisition-diagnostic", success=False,
                          stage="weather-run", product="weather", failure="check-or-execution-failed")
        marker = dict(schema=2, kind="weather-products-acquisition-failure", success=False,
                      command_exit_status=1, diagnostic_state="valid", diagnostic=diagnostic)
        cases = ((marker, False), (marker, True),
                 (dict(marker, command_exit_status=124, diagnostic_state="missing", diagnostic=None), False))
        for value, invalid_cleanup in cases:
            with self.subTest(state=value["diagnostic_state"], invalid_cleanup=invalid_cleanup):
                files = self.collect(json.dumps(diagnostic).encode(), products=True,
                                     failure_marker=value, invalid_cleanup=invalid_cleanup)
                prefix = "work-1/weather-products-delivery-"
                self.assertEqual(json.loads(files[prefix + "acquisition-failure.json"]), value)
                self.assertIn(prefix + "tree-before.json", files)
                self.assertEqual(prefix + "input-cleanup.json" in files, not invalid_cleanup)
                status = json.loads(files[prefix + "export-status.json"])
                expected_rejected = (["acquisition"] if value["diagnostic_state"] != "valid" else [])
                if invalid_cleanup: expected_rejected.append("input-cleanup")
                self.assertEqual(status["rejected"], expected_rejected)
                self.assertEqual(status["success"], not expected_rejected)
                self.assertTrue(status["complete"])
                self.assertNotIn(prefix + "acquisition.json", files)
                self.assertFalse(json.loads(files["vm-incomplete.json"])["success"])
                self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))
        malformed = dict(marker, private="PRIVATE CANARY")
        files = self.collect(json.dumps(diagnostic).encode(), products=True, failure_marker=malformed)
        self.assertFalse(any("weather-products-delivery" in name for name in files))
        files = self.collect(json.dumps(diagnostic).encode(), products=True, failure_marker=marker, limit=64)
        self.assertEqual({name for name in files if "weather-products-delivery" in name},
                         {"work-1/weather-products-delivery-input-cleanup.json"})
        self.assertEqual(json.loads(files["work-1/weather-products-delivery-input-cleanup.json"]),
                         dict(directory_removed=True, files_removed=True))

    def test_products_export_rejects_unknown_private_duplicate_and_mixed_source_data(self):
        valid = self.products_acquisition()
        wrong_field = self.products_acquisition()
        wrong_field["products"]["air_quality"]["fields"][0]["parameter"] = "2t"
        bad = [b"not json", json.dumps(dict(valid, prompt="PRIVATE CANARY")).encode(),
               b'{"schema":"PRIVATE CANARY",' + json.dumps(valid).encode()[1:],
               json.dumps(dict(valid, synthetic_air_quality=True)).encode(),
               json.dumps(dict(valid, decoder_sha256="PRIVATE CANARY")).encode(),
               json.dumps(wrong_field).encode()]
        for raw in bad:
            with self.subTest(raw=raw[:50]):
                files = self.collect(raw, products=True)
                self.assertNotIn("work-1/weather-products-delivery-acquisition.json", files)
                self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))
        files = self.collect(json.dumps(valid).encode(), products=True, limit=64)
        self.assertFalse(any("weather-products-delivery" in name for name in files))
        files = self.collect(json.dumps(valid).encode(), products=True, late_invalid=True)
        self.assertFalse(any("weather-products-delivery" in name for name in files))

    def test_private_unknown_duplicate_and_malformed_json_do_not_escape(self):
        valid = self.acquisition()
        bad = [b"not json", json.dumps(dict(valid, prompt="PRIVATE CANARY")).encode(),
               b'{"schema":"PRIVATE CANARY",' + json.dumps(valid).encode()[1:],
               json.dumps(dict(valid, forecast_sha256="PRIVATE CANARY")).encode()]
        for raw in bad:
            with self.subTest(raw=raw[:30]):
                files = self.collect(raw)
                self.assertNotIn("work-1/weather-client-delivery-acquisition.json", files)
                self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))

    def test_verified_json_is_not_exported_as_an_unverifiable_tail(self):
        files = self.collect(json.dumps(self.acquisition()).encode(), limit=64)
        self.assertFalse(any("weather-client-delivery" in name for name in files))

    def test_previously_published_cold_proof_survives_later_invalid_ui_without_success_claim(self):
        cold = dict(schema=1, success=True, kind="volparossa-weather-protected-cold",
            bundle_manifest_sha256=SHA, core_sha256=SHA, forecast_sha256=SHA,
            forecast_bytes=6000, manifest_id=SHA, cold_receipt_sha256=SHA,
            decoder_sha256="3a3b64581e6922db4287445f217f993f6967dea5fcc45ff66944b0bc883408f4",
            acquired_fields=9,
            protected_cold=dict(peer_bytes=6000, providers_used=2, origin_body_bytes=0,
                origin_range_requests=0, privacy_captures_validated=True),
            scope=dict(actual_acquisition=True, acquisition_outside_overlay=True,
                same_publication_joined=True, protected_cold_transfer=True, actual_drizzli_ui=False,
                actual_http_bridge=False, actual_ui_refresh=False, end_to_end_proven=False,
                browser_triggered_cold_fetch=False, two_subflow_bulk_aggregation=False,
                upstream_signature_attested=False, production_service_complete=False),
            cleanup=dict(publisher_sources_removed_before_fetch=True))
        raw = json.dumps(cold, indent=2).encode() + b"\n"
        files = self.collect(json.dumps(self.acquisition()).encode(), published=raw, late_invalid=True)
        self.assertEqual(files["published/weather-client-delivery-cold-evidence.json"], raw)
        self.assertNotIn("work-1/weather-client-delivery-evidence.json", files)
        self.assertNotIn("work-1/weather-client-delivery-acquisition.json", files)
        self.assertFalse(json.loads(files["vm-incomplete.json"])["success"])
        self.assertFalse(any(b"PRIVATE CANARY" in data for data in files.values()))
        for invalid in (dict(cold, prompt="PRIVATE CANARY"),
                        dict(cold, scope=dict(cold["scope"], end_to_end_proven=True))):
            files = self.collect(b"invalid", published=json.dumps(invalid).encode(), late_invalid=True)
            self.assertFalse(any("weather-client-delivery" in name for name in files))


if __name__ == "__main__":
    unittest.main()
