#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure evidence/closed-export checks; these never constitute live browser/MPTCP proof."""

import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "browser-network-smoke.py"))
PRIOR = runpy.run_path(str(HERE / "test-mptcp-growth-smoke.py"))
PROVISION = runpy.run_path(str(HERE / "browser-network-provision.py"))
DIAGNOSTICS = runpy.run_path(str(HERE / "test-alpha-vm-diagnostics.py"))["MODULE"]
REVISION = "c" * 40


def numeric_uid_guard():
    return {"nftables": [
        {"chain": dict(family="inet", table="vpbrowser", name="output", type="filter",
                       hook="output", prio=-5, policy="accept")},
        {"rule": {"expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 985}},
            {"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                       "right": "127.0.0.1"}}, {"drop": None}]}},
        {"rule": {"expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 985}},
            {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": 10}},
            {"drop": None}]}},
    ]}


def fixture(root):
    prior = PRIOR["fixture"]()
    run_id = "b" * 32
    size, digest = CHECK["BODY_BYTES"], CHECK["body_hash"](run_id)
    provision = PROVISION["pins"]()
    write = CHECK["write"]
    for stage, phase in enumerate(CHECK["PHASES"]):
        layout = dict(paths=[dict(path_id=i, client_address=f"fd76:6f6c:7061:1:{stage+1}:{i}:1:1",
            exit_address=f"fd76:6f6c:7061:1:{stage+1}:{i}:1:4", client_interface=f"vpc{i}", exit_interface=f"vpx{i}") for i in (1, 2)])
        for step, name in enumerate(("baseline", "progress")):
            value = dict(started_monotonic_ns=10 * (stage * 2 + step) + 1,
                observed_monotonic_ns=10 * (stage * 2 + step) + 2)
            for index, role in enumerate(("client", "exit")):
                entry = PRIOR["raw_snapshot"](layout, role, 2, 1000 + step * 100000)
                entry["raw"]["meta"] = entry["raw"]["meta"].replace("FIN-WAIT-2", "ESTAB").replace("CLOSE-WAIT", "ESTAB")
                entry["kernel"] = CHECK["MPTCP"]["kernel_sample"](entry["raw"], layout, role)
                entry["owner"] = dict(unit=f"volparossa-alpha-helper@{role}.service", pid=1000 + stage * 2 + index,
                    start_ticks="123", netns=str(100 + stage * 2 + index), paths=copy.deepcopy(prior["owners"][role]["paths"][:2]))
                value[role] = entry
            write(root / f"browser-network-{phase}-{name}.json", value)
        for role, capture in prior["privacy"]["initial"].items():
            write(root / f"browser-network-{phase}-privacy-{role}.json", capture)
    browser = dict(version=1, kind="real-gecko-core-gateway-driver", passed=True, core_revision=REVISION,
        runtime_version=provision["runtime"]["version"], runtime_source_stamp=provision["runtime"]["source_stamp"],
        module_sha256=provision["files"]["integration/VolparossaNetwork.sys.mjs"]["sha256"],
        script_sha256=provision["files"]["scripts/smoke_network_core.py"]["sha256"], expected_bytes=size,
        expected_sha256=digest, overlay_kernel_proof_external=True, full_browser_killswitch=False,
        firefox157_build_proven=False, namespace="net:[99]", cleanup=dict(browser_exited=True, profile_removed=True),
        socket_access=dict(path_type_verified=True, socket_parent_owner_group_match=True,
            peer_uid_matches_socket=True, unix_connect_verified=True, capability_sent=False),
        control_namespace=dict(scope="client-control-directory", original_socket_inode_preserved=True,
            original_parent_inode_preserved=True, read_only=True, grant_unmodified=True),
        result=dict(independent_attachments=True, wrong_scope_blocked=True, a=dict(bytes=size, sha256_verified=True),
            b=dict(bytes=size, sha256_verified=True), a_detached=True, b_survives_a_detach=True))
    origin = dict(version=1, run_id=run_id, complete=True, requests=[dict(phase=phase, bytes=size, sha256=digest,
        peer_is_exit=True, proxy_credentials_absent=True, tls_version="TLSv1.3", alpn="http/1.1") for phase in CHECK["PHASES"]])
    for name, value in dict(browser=browser, origin=origin, provision=provision,
        detach=dict(version=1, independent=True, client=True, exit=True),
        isolation=dict(user_uid=985, client_namespace=True, outside_parent_namespace=True,
            all_capabilities_dropped=True, no_new_privileges=True, netns="net:[99]", fixture_loopback_only_uid_guard=True),
        **{"private-cleanup": dict(private_files_removed=True)}).items():
        write(root / f"browser-network-{name}.json", value)
    host = b'{"fixture":"unchanged"}\n'
    for when in ("before", "after"):
        (root / f"host-state-{when}.json").write_bytes(host)
    evidence = CHECK["evidence"](root)
    report = dict(source_revision=REVISION, report_kind="volparossa-browser-network", success=True, network=evidence,
        cleanup=dict(complete=True, remaining_owned_objects=0), full_browser_killswitch_claimed=False,
        http3_claimed=False, direct_fallback=False, host_state=dict(unchanged=True,
            before_sha256=hashlib.sha256(host).hexdigest(), after_sha256=hashlib.sha256(host).hexdigest()))
    write(root / "browser-network-smoke.json", report)
    return report


class BrowserNetworkEvidence(unittest.TestCase):
    def test_attachment_substage_and_nsresult_are_closed_original_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "status.json"
            value = dict(version=1, kind="real-gecko-core-gateway-driver-status", phase="attach-a",
                error_code="unavailable", errno=None, child_exit_code=1,
                attachment=dict(stage="bootstrap-eof", nsresult=0x804B000D))
            CHECK["write"](status, value)
            self.assertEqual(CHECK["driver_diagnostic"](status, root / "absent")["status"], value)
            for detail in (dict(stage="secret path", nsresult=None),
                           dict(stage="bootstrap-timeout", nsresult=True),
                           dict(stage="bootstrap-write", nsresult=1 << 32),
                           dict(stage="bootstrap-write", nsresult=1, capability="secret")):
                value["attachment"] = detail
                CHECK["write"](status, value)
                with self.assertRaises(ValueError):
                    CHECK["driver_diagnostic"](status, root / "absent")

    def test_numeric_nft_guard_keeps_exact_uid_protocol_and_drop_scope(self):
        guard = numeric_uid_guard()
        CHECK["validate_uid_guard"](guard, 985)
        for value in ("ipv6", 2, True, None):
            invalid = copy.deepcopy(guard)
            invalid["nftables"][2]["rule"]["expr"][1]["match"]["right"] = value
            with self.assertRaises(ValueError):
                CHECK["validate_uid_guard"](invalid, 985)
        # A weaker address restriction, different application or extra accept
        # must not become valid merely because nfproto serialization is fixed.
        invalid = copy.deepcopy(guard)
        invalid["nftables"][1]["rule"]["expr"][1]["match"]["right"] = "127.0.0.0/8"
        with self.assertRaises(ValueError):
            CHECK["validate_uid_guard"](invalid, 985)
        with self.assertRaises(ValueError):
            CHECK["validate_uid_guard"](guard, 987)
        guard["nftables"][2]["rule"]["expr"][-1] = {"accept": None}
        with self.assertRaises(ValueError):
            CHECK["validate_uid_guard"](guard, 985)

    def test_isolation_failure_retains_closed_stage_not_sensitive_output(self):
        guard = numeric_uid_guard()
        guard["nftables"][2]["rule"]["expr"][1]["match"]["right"] = "ipv6"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "browser-network-isolation.json"
            helper = {"process_boundary": lambda *args: {"client_namespace": True}}
            with patch.object(CHECK["runpy"], "run_path", return_value=helper), \
                 patch.dict(CHECK["isolation"].__globals__, {"command": lambda _args: json.dumps(guard)}):
                with self.assertRaises(ValueError):
                    CHECK["isolation"](123, "net:[1]", "net:[2]", 985, 985, 987, output)
            self.assertEqual(CHECK["read"](output), dict(observation_complete=False,
                failed_stage="guard_validation", process_boundary_verified=True,
                fixture_loopback_only_uid_guard=False))

    def test_two_independent_native_owners_source_hash_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = fixture(root)
            self.assertEqual(CHECK["validate_report"](root / "browser-network-smoke.json", REVISION), report)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](root / "browser-network-smoke.json", "d" * 40)

    def test_original_namespace_mapping_proof_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = fixture(root)
            for field in ("original_socket_inode_preserved", "original_parent_inode_preserved", "read_only", "grant_unmodified"):
                invalid = copy.deepcopy(report)
                invalid["network"]["browser"]["control_namespace"][field] = False
                with self.assertRaises(ValueError):
                    CHECK["validate_browser"](invalid["network"])

    def test_one_noncarrying_path_or_foreign_flow_token_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = fixture(root)
            original = report["network"]["phases"][0]
            before, after = original["baseline"], copy.deepcopy(original["progress"])
            after["client"]["kernel"]["subflows"][1]["bytes_received"] = 1000
            with self.assertRaises(ValueError):
                CHECK["MPTCP"]["progress"](before, after, 2)
            before = copy.deepcopy(before)
            before["client"]["raw"]["tcp"] = before["client"]["raw"]["tcp"].replace("def456(id:3)", "deadbeef(id:3)")
            with self.assertRaises(ValueError):
                CHECK["validate_sample"](before)

    def test_private_boundary_browser_hash_and_drop_gates_remain_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = fixture(root)
            evidence = copy.deepcopy(report["network"])
            evidence["browser"]["expected_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                CHECK["validate_browser"](evidence)
            capture = root / "browser-network-second-privacy-client.json"
            value = CHECK["read"](capture)
            value["packet_socket_drops"] = 1
            CHECK["write"](capture, value)
            with self.assertRaises(ValueError):
                CHECK["evidence"](root)

    def test_real_ss_zones_stay_bound_to_observed_worker_interfaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = fixture(root)
            sample = report["network"]["phases"][0]["baseline"]
            for role in ("client", "exit"):
                entry = sample[role]
                rows = []
                for line, path in zip(entry["raw"]["tcp"].splitlines(), entry["owner"]["paths"], strict=True):
                    rows.append(line.replace("]:", "]%" + path["interface"] + ":"))
                entry["raw"]["tcp"] = "\n".join(rows) + "\n"
            CHECK["validate_sample"](sample)
            sample["client"]["raw"]["tcp"] = sample["client"]["raw"]["tcp"].replace("%vpc2:", "%foreign2:")
            with self.assertRaises(ValueError):
                CHECK["validate_sample"](sample)

    def test_fixture_pin_and_closed_names_do_not_allow_secret_files(self):
        names = CHECK["EXPORT_NAMES"]
        self.assertEqual(len(set(names)), 23)
        self.assertTrue(all(name.startswith("browser-network-") and name.endswith(".json") for name in names))
        self.assertFalse(any(word in name for name in names for word in ("grant", "key", "profile", ".log")))
        with tempfile.TemporaryDirectory() as temporary:
            pins = PROVISION["pins"]()
            pins["revision"] = None
            path = Path(temporary) / "pins.json"
            path.write_text(json.dumps(pins))
            with patch.dict(PROVISION["pins"].__globals__, {"PINS": path}), self.assertRaises(ValueError):
                PROVISION["pins"]()

    def test_driver_diagnostics_exclude_raw_stderr_and_unknown_status_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status, stderr = root / "status.json", root / "driver.err"
            value = dict(version=1, kind="real-gecko-core-gateway-driver-status", phase="grant-validation",
                error_code="OS_ERROR", errno=13, child_exit_code=1)
            CHECK["write"](status, value)
            stderr.write_text("Permission denied: /private/grant secret-canary-value\n")
            result = CHECK["driver_diagnostic"](status, stderr)
            self.assertEqual(result["status"], value)
            self.assertTrue(result["stderr_signals"]["permission_denied"])
            self.assertFalse(result["stderr_signals"]["working_directory"])
            self.assertFalse(result["stderr_signals"]["mount_setup"])
            self.assertNotIn("secret-canary", json.dumps(result))
            self.assertNotIn("/private", json.dumps(result))
            for message, signal in (("bwrap: Can't chdir to /private/check-out: Permission denied", "working_directory"),
                                    ("bwrap: Can't bind mount /private/secret: Permission denied", "mount_setup")):
                stderr.write_text(message)
                classified = CHECK["driver_diagnostic"](status, stderr)
                self.assertTrue(classified["stderr_signals"][signal])
                self.assertNotIn("/private", json.dumps(classified))
            value["capability"] = "secret-canary-value"
            CHECK["write"](status, value)
            with self.assertRaises(ValueError):
                CHECK["driver_diagnostic"](status, stderr)

    def test_bwrap_failure_operation_is_closed_without_exporting_its_private_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stderr = root / "driver.err"
            cases = {
                "source_lookup": "Can't find source path /private/source",
                "destination_lookup": 'Unable to open destination O_PATH fd "/private/destination"',
                "directory_creation": "Can't mkdir parents for /private/destination",
                "file_creation": "Can't create file /private/destination",
                "readonly_remount": "Can't remount readonly on /private/home",
                "mount_application": "Unable to mount source on destination",
                "exec": "execvp /private/python",
                "identity_mapping": "setting up gid map",
                "security_setup": "prctl(PR_SET_NO_NEW_PRIVS) failed",
                "proc_access": "Can't open /proc/self/mountinfo",
                "root_pivot": "pivot_root(/private/newroot)",
                "path_access": "Can't reopen /private/file",
                "permission_change": "Can't chmod 0700 /private/file",
            }
            for name, message in cases.items():
                with self.subTest(operation=name):
                    stderr.write_text(f"bwrap: {message}: Permission denied secret-canary\n")
                    result = CHECK["driver_diagnostic"](root / "missing-status", stderr)
                    self.assertEqual({key for key, present in result["bwrap_operations"].items() if present}, {name})
                    self.assertFalse(result["bwrap_operation_unknown"])
                    self.assertTrue(result["stderr_signals"]["permission_denied"])
                    self.assertNotIn("/private", json.dumps(result))
                    self.assertNotIn("secret-canary", json.dumps(result))
            stderr.write_text("unrelated application log: bwrap: execvp /private/python: Permission denied\n")
            result = CHECK["driver_diagnostic"](root / "missing-status", stderr)
            self.assertFalse(any(result["bwrap_operations"].values()))
            self.assertFalse(result["bwrap_operation_unknown"])
            stderr.write_text("bwrap: Unknown operation on /private/file secret-canary: Permission denied\n")
            result = CHECK["driver_diagnostic"](root / "missing-status", stderr)
            self.assertTrue(result["bwrap_operation_unknown"])
            self.assertFalse(any(result["bwrap_operations"].values()))
            self.assertNotIn("/private", json.dumps(result))
            self.assertNotIn("secret-canary", json.dumps(result))

    def test_bwrap_directory_target_is_exact_closed_and_never_exports_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stderr = root / "driver.err"
            home, work = Path("/owned/private-home"), Path("/owned/private-work")
            cases = {
                "browser_home": str(home), "browser_appdata": str(home / ".mozilla"),
                "browser_work": str(work), "temporary_directory": "/tmp",
                "proc_directory": "/proc", "device_directory": "/dev", "filesystem_root": "/",
                "unknown": "/unrecognized/secret-canary",
            }
            for name, destination in cases.items():
                for prefix in ("", "newroot", "/newroot"):
                    with self.subTest(target=name, newroot=prefix):
                        stderr.write_text(f"bwrap: Can't mkdir parents for {prefix}{destination}: Permission denied\n")
                        result = CHECK["driver_diagnostic"](root / "absent", stderr, home, work)
                        self.assertEqual({key for key, value in result["bwrap_directory_targets"].items() if value}, {name})
                        self.assertTrue(result["bwrap_operations"]["directory_creation"])
                        self.assertNotIn("/owned", json.dumps(result))
                        self.assertNotIn("secret-canary", json.dumps(result))
            for name in ("newroot", "oldroot", "proc"):
                stderr.write_text(f"bwrap: Creating {name} failed: Permission denied\n")
                result = CHECK["driver_diagnostic"](root / "absent", stderr, home, work)
                self.assertEqual({key for key, value in result["bwrap_directory_targets"].items() if value}, {"sandbox_" + name})
            for destination in (str(home) + "-other", str(work) + "/unrecognized", str(home) + "/../other"):
                stderr.write_text(f"bwrap: Can't mkdir parents for {destination}: Permission denied\n")
                result = CHECK["driver_diagnostic"](root / "absent", stderr, home, work)
                self.assertEqual({key for key, value in result["bwrap_directory_targets"].items() if value}, {"unknown"})

    def test_actual_incomplete_collector_excludes_unlisted_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest, opt = root / "guest", root / "opt"
            work = opt / ("va." + "a" * 32 + ".ABCdef")
            work.mkdir(parents=True)
            (guest / "alpha-output").mkdir(parents=True)
            (work / "browser-network-browser.json").write_text('{"passed":false}\n')
            large = json.dumps(dict(synthetic_parser_test="x" * 200000)).encode()
            (work / "browser-network-evidence.json").write_bytes(large)
            for name in ("grant.json", "owner.json", "browser-network-browser.log", "content-private.json", "agent-client.log"):
                (work / name).write_text("private fixture canary, must never export\n")
            result = subprocess.CompletedProcess([], 0, ("\n".join(CHECK["EXPORT_NAMES"]) + "\n").encode(), b"")
            with patch.object(DIAGNOSTICS["subprocess"], "run", return_value=result):
                archive = DIAGNOSTICS["collect"](guest, opt, REVISION, "browser-network", 124, root / "cgroups", root / "proc")
            with tarfile.open(archive) as bundle:
                files = {member.name: bundle.extractfile(member).read() for member in bundle.getmembers()}
            self.assertEqual(files["work-1/browser-network-evidence.json"], large)
            self.assertIn("work-1/browser-network-browser.json", files)
            self.assertFalse(any(word in name for name in files for word in ("grant", "owner.json", ".log", "content-private")))
            self.assertFalse(json.loads(files["vm-incomplete.json"])["success"])


if __name__ == "__main__":
    unittest.main()
