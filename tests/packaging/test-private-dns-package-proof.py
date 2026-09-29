#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure package proof contract checks; no package install, daemon or DNS query."""

import copy
import importlib.util
from pathlib import Path
import subprocess
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
        actual_packaged_agent=True, worker_hidden_only_in_agent_mount=True)
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

    def test_probe_derives_all_shipped_sandbox_settings_without_relaxation(self):
        source = (ROOT / "packaging/systemd/volparossa-agent.service").read_text()
        unit = PROOF.probe_unit(source, "/run/volparossa/proof", "owned-proof", "mnt:[123]")
        service = source.split("[Service]\n", 1)[1].split("[Install]", 1)[0]
        for line in service.splitlines():
            if line and not line.startswith(("Type=", "ExecStart=", "Restart=")):
                self.assertIn(line, unit)
        self.assertIn("ExecStart=/run/volparossa/proof/probe signed", unit)
        self.assertIn("Type=oneshot", unit)
        self.assertIn("Restart=no", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("User=volparossa", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        self.assertIn("BindReadOnlyPaths=/run/volparossa/proof/hosts:/etc/hosts", unit)
        self.assertNotIn("Wants=", unit)
        self.assertNotIn("WantedBy=", unit)

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
