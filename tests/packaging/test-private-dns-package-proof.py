#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure package proof contract checks; no package install, daemon or DNS query."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
SPEC = importlib.util.spec_from_file_location("package_dns", HERE / "private-dns-package-proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)
REVISION = "a" * 40


def synthetic_report():
    result = dict(schema=1, report_kind="private-unbound-package", source_revision=REVISION,
                  build_profile="development-staged", release_build_proven=False,
                  success=True, failure=None, source_binary_binding=True,
                  default_private_roles_off=True, mandatory_companion_no_cycle=True,
                  installed_units_unchanged=True, fixture_config_restored=True)
    for key in ("core_sha256", "companion_sha256", "worker_sha256", "agent_unit_sha256", "probe_sha256"):
        result[key] = "b" * 64
    result["startup"] = dict(roles_off_without_worker_started=True,
        effective_exit_without_worker_rejected=True, diagnostic_code="DNS_PRIVATE_WORKER_UNAVAILABLE",
        actual_packaged_agent=True, worker_hidden_only_in_agent_mount=True,
        native_roles_off_restored=True, helper_lifetime_preserved=True)
    result["sandbox"] = dict(native_worker_observed=True, worker_same_agent_uid=True,
        worker_reaped=True, independent_dnssec_proof=True, local_cache_reuse=True,
        full_agent_dns_query=False, deviations=PROOF.DEVIATIONS)
    return result


class PackageProofContract(unittest.TestCase):
    def test_role_status_uses_actual_cli_text_not_assumed_json(self):
        self.assertEqual(PROOF.parse_roles(b"client: false\nrelay: false\nexit: false\n"),
                         dict(client=False, relay=False, exit=False))
        self.assertTrue(PROOF.parse_roles(b"client: false\nrelay: false\nexit: true\n")["exit"])
        for invalid in (b"{}", b"client: false\nrelay: false\nclient: false\n",
                        b"client: false\nrelay: false\nexit: unknown\n", b"x" * 257):
            with self.assertRaises(RuntimeError):
                PROOF.parse_roles(invalid)

    def test_roles_off_wait_retries_nonzero_startup_then_accepts_complete_reply(self):
        # The real CLI exits nonzero on unavailable/rejected local control; only
        # an accepted typed Roles response prints these three complete lines.
        transient = subprocess.CalledProcessError(1, ["volparossa", "role", "show"])
        ready = subprocess.CompletedProcess([], 0, b"client: false\nrelay: false\nexit: false\n")
        with mock.patch.object(PROOF, "run", side_effect=[transient, ready]) as command, \
                mock.patch.object(PROOF.time, "monotonic", side_effect=[0, 0, .1]), \
                mock.patch.object(PROOF.time, "sleep") as sleep:
            PROOF.wait_roles_off()
        self.assertEqual(command.call_count, 2)
        sleep.assert_called_once_with(.1)

    def test_roles_off_wait_does_not_retry_successful_malformed_reply(self):
        malformed = subprocess.CompletedProcess([], 0, b"ok\n")
        with mock.patch.object(PROOF, "run", return_value=malformed) as command, \
                mock.patch.object(PROOF.time, "monotonic", side_effect=[0, 0]), \
                mock.patch.object(PROOF.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "ROLE_STATUS_SHAPE"):
                PROOF.wait_roles_off()
        command.assert_called_once_with("/usr/bin/volparossa", "role", "show")
        sleep.assert_not_called()

    def test_complete_development_scope_and_negative_evidence(self):
        report = synthetic_report()
        PROOF.validate(report, REVISION)
        for field, value in (("source_revision", "c" * 40), ("build_profile", "release"),
                             ("release_build_proven", True), ("worker_sha256", "not-a-hash"),
                             ("source_binary_binding", False), ("default_private_roles_off", False),
                             ("mandatory_companion_no_cycle", False), ("fixture_config_restored", False),
                             ("installed_units_unchanged", False), ("success", False)):
            changed = copy.deepcopy(report)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                PROOF.validate(changed, REVISION)
        for group, field, value in (("startup", "actual_packaged_agent", False),
                                   ("startup", "roles_off_without_worker_started", False),
                                   ("startup", "native_roles_off_restored", False),
                                   ("startup", "helper_lifetime_preserved", False),
                                   ("startup", "diagnostic_code", "POLICY_LOAD_FAILED"),
                                   ("sandbox", "worker_reaped", False),
                                   ("sandbox", "native_worker_observed", False),
                                   ("sandbox", "worker_same_agent_uid", False),
                                   ("sandbox", "independent_dnssec_proof", False),
                                   ("sandbox", "full_agent_dns_query", True),
                                   ("sandbox", "deviations", [])):
            changed = copy.deepcopy(report)
            changed[group][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                PROOF.validate(changed, REVISION)

    def test_native_roles_off_requires_successful_exit_and_absent_sockets(self):
        expected = dict(ActiveState="inactive", Result="success", MainPID="0",
                        ExecMainCode="1", ExecMainStatus="0")
        with tempfile.TemporaryDirectory() as temporary:
            socket = Path(temporary) / "native.sock"
            with mock.patch.object(PROOF, "NATIVE_SOCKETS", (socket,)), \
                    mock.patch.object(PROOF, "property_value", side_effect=lambda unit, key: expected[key]):
                self.assertTrue(PROOF.native_roles_off_idle())
                socket.touch()
                self.assertFalse(PROOF.native_roles_off_idle())
                socket.unlink()
                socket.symlink_to(Path(temporary) / "absent")
                self.assertFalse(PROOF.native_roles_off_idle())
                socket.unlink()
                for key, value in (("ActiveState", "active"), ("Result", "exit-code"),
                                   ("MainPID", "303"), ("ExecMainCode", "2"), ("ExecMainStatus", "203")):
                    previous, expected[key] = expected[key], value
                    self.assertFalse(PROOF.native_roles_off_idle(), key)
                    expected[key] = previous

    def test_missing_assets_restores_native_dependency_on_success_and_probe_failure(self):
        original = (ROOT / "config/examples/default.yaml").read_bytes()
        for missing_diagnostic in (False, True):
            with self.subTest(missing_diagnostic=missing_diagnostic), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config, dropins, native_socket = root / "config", root / "dropins", root / "native.sock"
                config.write_bytes(original)
                state = {
                    PROOF.HELPER: dict(ActiveState="active", MainPID="101"),
                    PROOF.AGENT: dict(ActiveState="active", MainPID="202", InvocationID="a" * 32),
                    PROOF.NATIVE: dict(ActiveState="inactive", Result="success", MainPID="0",
                                       ExecMainCode="1", ExecMainStatus="0"),
                }
                starts, stops = [], []

                def command(*args, **kwargs):
                    output = b""
                    if args[:2] == ("systemctl", "stop"):
                        stops.append((args[2:], config.read_bytes()))
                        for service in args[2:]:
                            state[service].update(ActiveState="inactive", MainPID="0")
                            if service == PROOF.NATIVE:
                                native_socket.unlink(missing_ok=True)
                    elif args[:3] == ("systemctl", "start", PROOF.AGENT):
                        exit_on = b"  exit: true\n" in config.read_bytes()
                        starts.append(exit_on)
                        # Model real Wants semantics: starting an agent does not
                        # restart/retire an already active native dependency.
                        if state[PROOF.NATIVE]["ActiveState"] != "active":
                            if exit_on:
                                state[PROOF.NATIVE].update(ActiveState="active", MainPID="303")
                                native_socket.touch()
                            else:
                                state[PROOF.NATIVE].update(ActiveState="inactive", MainPID="0",
                                    Result="success", ExecMainCode="1", ExecMainStatus="0")
                        state[PROOF.AGENT].update(ActiveState="failed" if exit_on else "active",
                            MainPID="0" if exit_on else "202", ExecMainStatus="1" if exit_on else "0")
                    elif args[0] == "journalctl":
                        diagnostic = "OTHER_DIAGNOSTIC" if missing_diagnostic else "DNS_PRIVATE_WORKER_UNAVAILABLE"
                        output = json.dumps({"MESSAGE": json.dumps({"fields": {
                            "diagnostic_code": diagnostic}})}).encode()
                    return subprocess.CompletedProcess(args, 0, output)

                def roles():
                    self.assertEqual(state[PROOF.AGENT]["ActiveState"], "active")
                    self.assertEqual(config.read_bytes(), original)

                with mock.patch.object(PROOF, "CONFIG", config), \
                        mock.patch.object(PROOF, "AGENT_DROPINS", dropins), \
                        mock.patch.object(PROOF, "NATIVE_SOCKETS", (native_socket,)), \
                        mock.patch.object(PROOF, "property_value", side_effect=lambda unit, key: state[unit][key]), \
                        mock.patch.object(PROOF, "run", side_effect=command), \
                        mock.patch.object(PROOF, "wait_roles_off", side_effect=roles):
                    if missing_diagnostic:
                        with self.assertRaisesRegex(RuntimeError, "WRONG_MISSING_ASSET_DIAGNOSTIC"):
                            PROOF.missing_assets_start()
                    else:
                        result = PROOF.missing_assets_start()
                        self.assertTrue(result["native_roles_off_restored"])
                        self.assertTrue(result["helper_lifetime_preserved"])
                    self.assertTrue(PROOF.native_roles_off_idle())
                self.assertEqual(starts, [False, True, False])
                self.assertEqual(stops[-1][0], (PROOF.AGENT, PROOF.NATIVE))
                self.assertIn(b"  exit: true\n", stops[-1][1])
                self.assertEqual(config.read_bytes(), original)
                self.assertFalse(dropins.exists())
                self.assertEqual(state[PROOF.HELPER], dict(ActiveState="active", MainPID="101"))

    def test_probe_derives_all_shipped_sandbox_settings_without_relaxation(self):
        source = (ROOT / "packaging/systemd/volparossa-agent.service").read_text()
        unit = PROOF.probe_unit(source, "/run/volparossa/proof", "/usr/libexec/owned-proof/probe",
                               "owned-proof", "mnt:[123]")
        service = source.split("[Service]\n", 1)[1].split("[Install]", 1)[0]
        for line in service.splitlines():
            if line and not line.startswith(("Type=", "ExecStart=", "Restart=")):
                self.assertIn(line, unit)
        self.assertIn("ExecStart=/usr/libexec/owned-proof/probe signed", unit)
        self.assertNotIn("ExecStart=/run/", unit)
        self.assertIn("Type=oneshot", unit)
        self.assertIn("Restart=no", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("User=volparossa", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        self.assertIn("BindReadOnlyPaths=/run/volparossa/proof/hosts:/etc/hosts", unit)
        self.assertIn("StandardError=file:/run/volparossa/proof/stderr", unit)
        self.assertNotIn("StandardError=null", unit)
        self.assertNotIn("Wants=", unit)
        self.assertNotIn("WantedBy=", unit)

    def test_executable_preflight_distinguishes_mount_and_agent_access_without_running_probe(self):
        source, executable, runtime = Path("source"), Path("staged"), Path("runtime")
        for noexec, read_status, exec_status, source_match in (
            (False, 0, 0, True), (True, 0, 0, True), (False, 1, 0, True),
            (False, 0, 1, True), (False, 0, 0, False),
        ):
            diagnostics = {}
            with self.subTest(noexec=noexec, read_status=read_status, exec_status=exec_status,
                              source_match=source_match), \
                    mock.patch.object(PROOF.os, "statvfs", side_effect=[
                        SimpleNamespace(f_flag=PROOF.os.ST_NOEXEC if noexec else 0),
                        SimpleNamespace(f_flag=PROOF.os.ST_NOEXEC)]), \
                    mock.patch.object(PROOF, "digest", side_effect=["a", "a" if source_match else "b"]), \
                    mock.patch.object(PROOF, "run", side_effect=[
                        subprocess.CompletedProcess([], read_status),
                        subprocess.CompletedProcess([], exec_status)]) as command:
                if noexec or read_status or exec_status or not source_match:
                    with self.assertRaisesRegex(RuntimeError, "PROBE_EXECUTABLE_PREFLIGHT_FAILED"):
                        PROOF.executable_preflight(source, executable, runtime, diagnostics)
                else:
                    PROOF.executable_preflight(source, executable, runtime, diagnostics)
            self.assertEqual(diagnostics["executable_mount_noexec"], noexec)
            self.assertTrue(diagnostics["runtime_mount_noexec"])
            self.assertEqual(diagnostics["executable_readable_by_agent"], read_status == 0)
            self.assertEqual(diagnostics["executable_traversable_by_agent"], exec_status == 0)
            self.assertEqual(diagnostics["executable_source_bound"], source_match)
            self.assertEqual(command.call_args_list, [
                mock.call("runuser", "-u", "volparossa", "--", "/usr/bin/test", "-r", "staged", check=False),
                mock.call("runuser", "-u", "volparossa", "--", "/usr/bin/test", "-x", "staged", check=False)])

    def test_sandbox_failure_keeps_fixed_status_and_guard_without_raw_private_text(self):
        raw = b"Result=exit-code\nExecMainCode=1\nExecMainStatus=203\nActiveState=failed\n"
        outcome = subprocess.CompletedProcess([], 0, raw)
        diagnostics = {}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "stderr").write_bytes(
                b'Error: "disposable guest or private resolver assets unavailable"\n'
                b"never export private.invalid/path?q=secret\n")
            (directory / "result").write_bytes(b"")
            with mock.patch.object(PROOF, "run", return_value=outcome), \
                    mock.patch.object(PROOF.time, "monotonic", return_value=2.125):
                PROOF.retain_sandbox_diagnostics(directory, None, 1, diagnostics)
        self.assertEqual(diagnostics["manager"]["exec_main_status"], 203)
        self.assertEqual(diagnostics["manager"]["result"], "exit-code")
        self.assertEqual(diagnostics["stderr"]["category"], "DISPOSABLE_OR_ASSETS_GUARD")
        self.assertEqual(diagnostics["result"]["category"], "EMPTY")
        self.assertEqual(diagnostics["elapsed_ms"], 1125)
        self.assertFalse(diagnostics["worker_observed"])
        self.assertNotIn("private.invalid", json.dumps(diagnostics))
        self.assertNotIn("secret", json.dumps(diagnostics))
        for invalid in (raw + raw, b"x" * 4097, raw.replace(b"203", b"999"),
                        raw.replace(b"ExecMainCode=1\n", b"")):
            with self.subTest(invalid=invalid[:30]), self.assertRaises(RuntimeError):
                PROOF.unit_diagnostics(invalid)

    def test_probe_result_projection_is_bounded_closed_and_never_confuses_dns_with_startup(self):
        raw = json.dumps(dict(case="signed", case_passed=False, verdict="unavailable",
            error="Unavailable", elapsed_ms=5001, private_url="https://private.invalid/secret",
            unknown_reply="must not export", ttl_seconds=-1)).encode()
        kept = PROOF.result_diagnostics(raw)
        self.assertEqual(kept["category"], "SIGNED_RESULT")
        self.assertEqual(kept["error"], "Unavailable")
        self.assertEqual(kept["elapsed_ms"], 5001)
        self.assertFalse(kept["case_passed"])
        self.assertNotIn("private", json.dumps(kept))
        self.assertNotIn("ttl_seconds", kept)
        self.assertEqual(PROOF.stderr_diagnostics(b"unclassified private.invalid")["category"], "UNCLASSIFIED")
        for parser in (PROOF.stderr_diagnostics, PROOF.result_diagnostics):
            self.assertEqual(parser(b"x" * 16385)["category"], "OUTPUT_BOUND")
        self.assertEqual(PROOF.result_diagnostics(b"not JSON")["category"], "INVALID_JSON")
        self.assertEqual(PROOF.result_diagnostics(b'{"case":"unknown"}')["category"], "INVALID_CASE")

    def test_exit_fixture_changes_only_explicit_configuration_prerequisites(self):
        original = (ROOT / "config/examples/default.yaml").read_bytes()
        changed = PROOF.exit_config(original)
        self.assertIn(b"  client: false\n  relay: false\n  exit: true\n", changed)
        self.assertIn(b"runtime_mode: production\n", changed)
        self.assertIn(b"  reject_ech: true\n", changed)
        self.assertIn(b"  fail_closed: true\n", changed)
        self.assertIn(b"    mode: unbound_private\n", changed)
        with self.assertRaises(RuntimeError):
            PROOF.exit_config(original.replace(b"  exit: false", b"  exit: true"))

    def test_packaging_graph_and_source_built_guest_wiring(self):
        control = (ROOT / "packaging/debian/control.binary.in").read_text()
        companion = (ROOT / "packaging/build-private-dns-worker-deb.sh").read_text()
        self.assertIn("volparossa-private-dns-worker (= @VERSION@)", control)
        self.assertIn("'Depends: libunbound8 (>= 1.26.1), dns-root-data'", companion)
        self.assertNotIn("Depends: volparossa", companion)
        guest = (ROOT / "tests/integration/private-unbound-vm-guest.sh").read_text()
        self.assertIn("packaging/build-private-dns-worker-deb.sh --build", guest)
        self.assertIn("--stage-built /home/vpci/target/debug /home/vpci/volparossa-mpquic", guest)
        self.assertIn("--private-dns-probe /home/vpci/target/debug/examples/private-unbound-proof", guest)
        self.assertNotIn("sudo -n install -m 0755 native/volparossa-dns-worker", guest)
        host = (ROOT / "tests/integration/run-alpha-topology-vm.sh").read_text()
        self.assertIn('[ "$scenario" != alpha ] || set -- --provision-only', host)
        self.assertIn('"private-unbound-package.json", "private-unbound-package-lifecycle.json"', host)
        self.assertIn("private-unbound-package.json private-unbound-package-lifecycle.json; do", host)
        workflow = (ROOT / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("tests/packaging/private-dns-package-proof.py report", workflow)
        self.assertIn("tests/packaging/test-private-dns-package-proof.py", workflow)


if __name__ == "__main__":
    unittest.main()
