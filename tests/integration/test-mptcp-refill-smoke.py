#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic checker regressions only: these are NOT fresh-relay runtime evidence."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

C = runpy.run_path(str(Path(__file__).with_name("mptcp-refill-smoke.py")))
OLD = runpy.run_path(str(Path(__file__).with_name("test-mptcp-growth-smoke.py")))


def fixture():
    old = OLD["fixture"]()
    e = {k: copy.deepcopy(old[k]) for k in ("run_id", "expected_peers", "selection", "client", "server")}
    e["expected_peers"]["relay4"] = "peer4"
    e["expected_peers"]["relay3"] = "peer3"
    e["success"] = True
    e["acceptance_version"] = C["ACCEPTANCE_VERSION"]
    e["layout_initial"] = old["layout"]
    e["layout_refilled"] = copy.deepcopy(old["layout"])
    p = dict(path_id=4, client_address="fd42:1:4::1", exit_address="fd42:1:4::3", client_interface="vpc4", exit_interface="vpx4")
    e["layout_refilled"]["paths"].append(p)
    e["owners_initial"] = old["owners"]
    e["owners_refilled"] = copy.deepcopy(old["owners"])
    for role in ("client", "exit"):
        e["owners_refilled"][role]["paths"].append(dict(path_id=4, interface=p[f"{role}_interface"], ifindex=5,
            relay_node="relay4", endpoint="49.165.5.1:41001"))
    for i, stage in enumerate(("baseline", "initial_progress", "warm", "warm_progress", "retiring", "retired", "refilled", "refilled_progress")):
        ids = [1, 2] if i < 2 or stage in ("retiring", "retired") else [1, 2, 3] if i < 4 else [1, 2, 4]
        layout = dict(e["layout_refilled"], paths=[p for p in e["layout_refilled"]["paths"] if p["path_id"] in ids])
        e[stage] = dict(started_monotonic_ns=i * 20_000_000_000 + 1,
            observed_monotonic_ns=i * 20_000_000_000 + 2,
            **{role: OLD["raw_snapshot"](layout, role, len(ids), i * 100000, 20 if i > 1 else 0)
               for role in ("client", "exit")})
        e[stage]["exit"]["raw"]["endpoints"] = json.dumps([
            dict(address=p["exit_address"], id=p["path_id"] + 1, dev=p["exit_interface"], signal=True)
            for p in layout["paths"] if p["path_id"] != 1])
        reproject(e, stage)
    e["exposure"] = dict(relay_peer_id="peer4", capacity_before_mbps=1, capacity_after_mbps=32,
        started_monotonic_ns=e["retired"]["observed_monotonic_ns"] + 1, helper_pid_before=30, helper_pid_after=30,
        agent_pid_before=20, agent_pid_after=21)
    e["injection"] = dict(risky_path=1, warm_path=3, risky_interface="xr0", warm_interface="xr2", namespace_role="exit",
        initial_loss_percent=15, final_loss_percent=100)
    e["qdiscs"] = {key: dict(before=[dict(kind="noqueue", handle="0:")],
        during=[dict(kind="netem", handle=handle, root=True, drops=10, options={"loss-random": {"loss": 1}})],
        after=[dict(kind="noqueue", handle="0:")]) for key, handle in (("risky", "7b01:"), ("warm", "7b02:"))}
    e["rate_limits"] = copy.deepcopy(old["rate_limits"])
    e["rate_limits"]["relay3"] = copy.deepcopy(e["rate_limits"]["relay0"])
    e["rate_limits"]["relay4"] = copy.deepcopy(e["rate_limits"]["relay0"])
    for phases in e["rate_limits"].values():
        phases["during"][0]["handle"] = "7b03:"
    e["privacy"] = old["privacy"]
    for phase in ("initial", "expanded"):
        for number in (3, 4):
            additional = copy.deepcopy(e["privacy"][phase]["relay0"])
            additional.update(capture_role=f"relay{number}", interfaces=[f"r{number}c", f"r{number}x", "underlay"])
            additional["interface_statistics"] = {k.replace("r0", f"r{number}"): v
                                                  for k, v in additional["interface_statistics"].items()}
            e["privacy"][phase][f"relay{number}"] = additional
        for role in ("client", "exit"):
            for number in range(4):
                e["privacy"][phase][role][f"relay{number}_wireguard_data_datagrams"] = 100
            e["privacy"][phase][role]["relay4_wireguard_data_datagrams"] = 100 if phase == "expanded" else 0
    seed = b"volparossa-download:a04:" + bytes.fromhex(e["run_id"])
    block = (seed * (65536 // len(seed) + 1))[:65536]
    digest = hashlib.sha256()
    for _ in range(C["BODY_BYTES"] // len(block)):
        digest.update(block)
    request = b"volparossa-mptcp-refill:" + bytes.fromhex(e["run_id"]) + bytes(4)
    for role in ("client", "server"):
        e[role].update(case="mptcp-refill", response_bytes=C["BODY_BYTES"], response_sha256=digest.hexdigest(),
            request_bytes=len(request), request_sha256=hashlib.sha256(request).hexdigest())
    e["client"].update(first_byte_monotonic_ns=3, completed_monotonic_ns=180_000_000_003,
                       duration_ns=180_000_000_000)
    e["cleanup"] = dict(application_complete=True, route_disconnected=True, owned_qdiscs_removed=True)
    return e


def reproject(e, stage):
    layout = e["layout_refilled"] if stage.startswith("refilled") else e["layout_initial"]
    for role in ("client", "exit"):
        anchor = e["warm_progress"][role]["kernel"] if stage in ("retiring", "retired", "refilled", "refilled_progress") else None
        e[stage][role]["kernel"] = C["kernel_sample"](e[stage][role]["raw"], layout, role, anchor, 3)


def closing_residue(e, state="FIN-WAIT-1"):
    for stage in ("retiring", "retired", "refilled", "refilled_progress"):
        for role in ("client", "exit"):
            line = next(line for line in e["warm_progress"][role]["raw"]["tcp"].splitlines() if "fd42:1:3:" in line)
            if role == "exit":
                line = line.replace("ESTAB", state, 1)
            e[stage][role]["raw"]["tcp"] += line + "\n"
        reproject(e, stage)


def raw_files(e):
    prefix = C["PREFIX"]
    keys = ("selection", "layout_initial", "layout_refilled", "owners_initial", "owners_refilled", "baseline",
            "initial_progress", "warm", "warm_progress", "retiring", "retired", "refilled", "refilled_progress", "injection",
            "exposure", "client", "server", "cleanup")
    files = {f"{prefix}-{key.replace('_', '-')}.json": e[key] for key in keys}
    files[f"{prefix}-selection.txt"] = "".join(
        f"context={p['route_context_id']} path={p['path_id']} relay={p['relay_peer_id']} "
        f"exit={p['exit_peer_id']} state={p['state']} rtt_us={p['smoothed_rtt_us']} "
        f"bytes={p['user_bytes']} acked_transport_bytes={p['acked_transport_bytes']}\n"
        for p in e["selection"]["paths"])
    for phase, captures in e["privacy"].items():
        for role, capture in captures.items():
            files[f"{prefix}-{phase}-privacy-{role}.json"] = capture
    for phase in ("before", "during", "after"):
        for key in ("risky", "warm"):
            files[f"{prefix}-{key}-{phase}.json"] = e["qdiscs"][key][phase]
        for node, phases in e["rate_limits"].items():
            files[f"{prefix}-rate-{node[-1]}-{phase}.json"] = phases[phase]
    for phase, capacity in (("before", 1), ("after", 32)):
        files[f"{prefix}-r4-config-{phase}.yaml"] = (
            f"relay:\n  relay_upload_limit_mbps: {capacity}\n  relay_download_limit_mbps: {capacity}\n")
    files.update({f"{prefix}-run.json": dict(run_id=e["run_id"]), "a01-expected-peers.json": e["expected_peers"],
        f"{prefix}-evidence.json": e, f"{prefix}-final-status.txt": "connected: false\nactive contexts: 0\n",
        f"{prefix}-final-paths.txt": ""})
    return files


class RefillEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = fixture()

    def test_valid_synthetic_schema_not_runtime_evidence(self):
        C["validate"](self.evidence)

    def test_userspace_bound_subflows_keep_refill_lifetime_and_fourth_path_gates(self):
        evidence = copy.deepcopy(self.evidence)
        for stage in ("baseline", "initial_progress", "warm", "warm_progress", "retiring", "retired",
                      "refilled", "refilled_progress"):
            layout = evidence["layout_refilled"] if stage.startswith("refilled") else evidence["layout_initial"]
            for role in ("client", "exit"):
                raw = evidence[stage][role]["raw"]
                for path in layout["paths"]:
                    raw["tcp"] = raw["tcp"].replace(f"[{path[f'{role}_address']}]:",
                        f"[{path[f'{role}_address']}]%{path[f'{role}_interface']}:")
            reproject(evidence, stage)
        C["validate"](evidence)
        evidence["refilled_progress"]["client"]["raw"]["tcp"] = evidence["refilled_progress"]["client"]["raw"]["tcp"].replace(
            "%vpc4:", "%vpc3:")
        with self.assertRaisesRegex(ValueError, "zone differs from exact owned path"):
            reproject(evidence, "refilled_progress")

    def test_fixed_kernel_mib_projection_rejects_ambiguous_or_invalid_counters(self):
        names = list(C["MPTCP_DIAGNOSTIC_COUNTERS"])
        raw = "TcpExt: Ignored\nTcpExt: 9\nMPTcpExt: " + " ".join(names + ["UnrelatedField"]) + "\n"
        raw += "MPTcpExt: " + " ".join(map(str, range(len(names) + 1))) + "\n"
        expected = dict(zip(names, range(len(names))))
        self.assertEqual(C["mptcp_counters"](raw), expected)
        for invalid in (raw + raw, raw.replace(names[1], names[0]), raw.replace(names[0], "Missing"),
                        raw.replace("MPTcpExt: 0 ", "MPTcpExt: -1 "),
                        raw.replace("MPTcpExt: 0 ", f"MPTcpExt: {2**64} "), "x" * 65537):
            with self.subTest(invalid=invalid[:50]), self.assertRaises(ValueError):
                C["mptcp_counters"](invalid)

    def test_warm_diagnostics_retain_short_announcement_and_bounded_transitions(self):
        history = None
        for i in range(40):
            sample = copy.deepcopy(self.evidence["baseline"])
            sample.update(started_monotonic_ns=i * 10 + 1, observed_monotonic_ns=i * 10 + 2)
            for role in ("client", "exit"):
                sample[role]["diagnostics"] = dict(available=True, counters={"AddAddrTx": i})
            if i == 1:
                sample["exit"]["kernel"]["endpoints"].append(dict(path_id=3))
            history = C["warm_diagnostics"](history, sample, 3)
        self.assertEqual(history["samples"], 40)
        self.assertEqual(len(history["transitions"]), 32)
        self.assertEqual(history["omitted_transitions"], 8)
        self.assertEqual(history["first_endpoint_present"]["started_monotonic_ns"], 11)
        self.assertEqual(history["first_endpoint_withdrawn"]["started_monotonic_ns"], 21)
        self.assertEqual(history["last"]["started_monotonic_ns"], 391)
        with self.assertRaisesRegex(ValueError, "overlapping"):
            C["warm_diagnostics"](history, sample, 3)
        with self.assertRaisesRegex(ValueError, "history"):
            C["warm_diagnostics"](dict(history, samples=450), sample, 3)

    def test_exact_closing_warm_and_blackholed_client_residue_do_not_hide_fresh_r4_bytes(self):
        for state in C["CLOSING_STATES"]:
            with self.subTest(state=state):
                e = copy.deepcopy(self.evidence)
                closing_residue(e, state)
                C["validate"](e)
                self.assertEqual(len(e["refilled"]["client"]["kernel"]["subflows"]), 4)
                self.assertEqual(e["retired"]["exit"]["kernel"]["closing_subflows"][0]["state"], state)
                # Historical growth still rejects non-ESTAB TCP rows; only refill
                # receives independently proven endpoint withdrawal semantics.
                with self.assertRaisesRegex(ValueError, "unexpected socket dump"):
                    C["G"].kernel_sample(e["retired"]["exit"]["raw"], e["layout_initial"], "exit")

    def test_closing_residue_requires_exact_old_lifetime_and_never_ignores_malformed_rows(self):
        e = copy.deepcopy(self.evidence)
        closing_residue(e)
        raw = e["retired"]["exit"]["raw"]
        for old, new in (("sk:b13", "sk:ffff"), ("FIN-WAIT-1", "SYN-SENT"),
                         ("fd42:1:3::3", "fd42:1:99::3"), ("def456(id:4)", "def456(id:9)")):
            changed = dict(raw, tcp=raw["tcp"].replace(old, new))
            with self.assertRaises(ValueError):
                C["kernel_sample"](changed, e["layout_initial"], "exit", e["warm_progress"]["exit"]["kernel"], 3)
        with self.assertRaises(ValueError):
            C["kernel_sample"](dict(raw, tcp=raw["tcp"] + "malformed\n"), e["layout_initial"], "exit",
                                e["warm_progress"]["exit"]["kernel"], 3)

    def test_endpoint_withdrawal_no_progress_and_healthy_flow_are_independent_requirements(self):
        e = copy.deepcopy(self.evidence)
        closing_residue(e)
        changes = (
            lambda x: x["retired"]["exit"]["raw"].update(endpoints=x["warm_progress"]["exit"]["raw"]["endpoints"]),
            lambda x: x["retired"]["exit"]["raw"].update(endpoints="[]"),
            lambda x: x["retired"]["exit"]["raw"].update(tcp=x["retired"]["exit"]["raw"]["tcp"].replace("FIN-WAIT-1", "ESTAB")),
            lambda x: x["retired"]["client"]["raw"].update(tcp=x["retired"]["client"]["raw"]["tcp"].replace("bytes_received:300000", "bytes_received:300001")),
            lambda x: x["retired"]["client"]["raw"].update(tcp=x["retired"]["client"]["raw"]["tcp"].replace("bytes_received:500000", "bytes_received:400000")),
            lambda x: x["retired"].update(started_monotonic_ns=x["retiring"]["observed_monotonic_ns"] + 1),
        )
        for change in changes:
            altered = copy.deepcopy(e)
            change(altered)
            with self.assertRaises(ValueError):
                reproject(altered, "retired")
                C["validate"](altered)

    def test_any_three_distinct_original_relays_including_r3_active_or_warm_are_accepted(self):
        addresses = {node: address for address, node in C["G"].RELAY_IPS.items()}
        for numbers in ((0, 1, 2), (0, 1, 3), (0, 2, 3), (1, 2, 3), (3, 1, 2), (0, 3, 2)):
            with self.subTest(numbers=numbers):
                evidence = copy.deepcopy(self.evidence)
                for snapshot in ("owners_initial", "owners_refilled"):
                    for role in ("client", "exit"):
                        for row in evidence[snapshot][role]["paths"][:3]:
                            node = f"relay{numbers[row['path_id'] - 1]}"
                            row.update(relay_node=node, endpoint=f"{addresses[node]}:41001")
                for row in evidence["selection"]["paths"]:
                    row["relay_peer_id"] = evidence["expected_peers"][f"relay{numbers[row['path_id'] - 1]}"]
                evidence["injection"].update(risky_interface=f"xr{numbers[0]}", warm_interface=f"xr{numbers[2]}")
                C["validate"](evidence)
                source = raw_files(evidence)["mptcp-refill-selection.txt"]
                self.assertEqual(C["selected"](source, evidence["expected_peers"])["paths"], evidence["selection"]["paths"])

    def test_fresh_r4_is_never_accepted_initially_or_replaced_by_r3(self):
        for snapshot, index, node, address in (("owners_initial", 2, "relay4", "49.165.5.1"),
                                             ("owners_refilled", 3, "relay3", "48.164.4.1"),
                                             ("owners_initial", 2, "relay0", "42.158.0.1")):
            evidence = copy.deepcopy(self.evidence)
            for role in ("client", "exit"):
                evidence[snapshot][role]["paths"][index].update(relay_node=node, endpoint=f"{address}:41001")
            with self.assertRaises(ValueError):
                C["validate"](evidence)
        evidence = copy.deepcopy(self.evidence)
        evidence["selection"]["paths"][0]["relay_peer_id"] = evidence["expected_peers"]["relay4"]
        with self.assertRaises(ValueError):
            C["selected"](raw_files(evidence)["mptcp-refill-selection.txt"], evidence["expected_peers"])

    def test_r3_capture_rate_and_acceptance_version_cannot_be_omitted(self):
        for mutate in (
            lambda e: e["privacy"]["initial"].pop("relay3"),
            lambda e: e["privacy"]["expanded"]["relay3"].update(interfaces=["r3c", "underlay"]),
            lambda e: e["rate_limits"].pop("relay3"),
            lambda e: e.update(acceptance_version=1),
            lambda e: e.pop("acceptance_version"),
        ):
            evidence = copy.deepcopy(self.evidence)
            mutate(evidence)
            with self.assertRaises(ValueError):
                C["validate"](evidence)

    def test_selected_r3_needs_payload_on_both_physical_wg_legs(self):
        evidence = copy.deepcopy(self.evidence)
        for snapshot in ("owners_initial", "owners_refilled"):
            for role in ("client", "exit"):
                evidence[snapshot][role]["paths"][2].update(relay_node="relay3", endpoint="48.164.4.1:41001")
        evidence["injection"]["warm_interface"] = "xr3"
        for capture, counter in (("relay3", "client_leg_wireguard_data_datagrams"),
                                 ("relay3", "exit_leg_wireguard_data_datagrams"),
                                 ("client", "relay3_wireguard_data_datagrams"),
                                 ("exit", "relay3_wireguard_data_datagrams")):
            changed = copy.deepcopy(evidence)
            changed["privacy"]["initial"][capture][counter] = 0
            with self.assertRaisesRegex(ValueError, "original selected WG legs"):
                C["validate"](changed)

    def test_shell_preserves_exact_selection_stage_failure(self):
        # Source definitions only and replace selection before calling run. The terminating
        # fail stub ensures no network/application function can execute in this unit test.
        script = str(Path(__file__).with_name("mptcp-refill-smoke.sh"))
        for suffix in ("CONNECT_UNAVAILABLE", "SELECTION_INVALID", "OWNER_EVIDENCE_UNAVAILABLE",
                       "ORIGINAL_RELAY_SET_INVALID"):
            blocker = f"MPTCP_REFILL_{suffix}"
            result = subprocess.run(["sh", "-c", '''
                . "$1"
                expected=$2
                mptcp_refill_select() { mref_selection_blocker=$expected; return 1; }
                fail() { printf '%s\\n' "$1"; exit 77; }
                mptcp_refill_run
            ''', "refill-selection-test", script, blocker], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 77, result.stderr)
            self.assertEqual(result.stdout.strip(), blocker)

    def test_raw_rebuild_and_source_bound_report(self):
        e = self.evidence
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for name, value in raw_files(e).items():
                (work / name).write_text(value if isinstance(value, str) else json.dumps(value), encoding="ascii")
            self.assertEqual(C["build"](work), e)
            host = b'{"links":[],"routes":[]}\n'
            for phase in ("before", "after"):
                (work / f"host-state-{phase}.json").write_bytes(host)
            revision = "c" * 40
            report = dict(schema_version=1, acceptance_version=C["ACCEPTANCE_VERSION"],
                report_kind="volparossa-mptcp-refill-runtime", source_revision=revision,
                run_id=e["run_id"], success=True, phase="mptcp-refill-complete", observed_blocker="NONE", transfer=e,
                cleanup=dict(complete=True, remaining_owned_objects=0),
                host_state=dict(success=True, unchanged=True, before_sha256=hashlib.sha256(host).hexdigest(),
                                after_sha256=hashlib.sha256(host).hexdigest()))
            path = work / "mptcp-refill-smoke.json"
            path.write_text(json.dumps(report), encoding="ascii")
            C["main"](["report", str(path), revision])
            with self.assertRaises(ValueError):
                C["main"](["report", str(path), "d" * 40])
            (work / "mptcp-refill-r4-config-before.yaml").write_text(
                "relay:\n  relay_upload_limit_mbps: 32\n  relay_download_limit_mbps: 32\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "capacity exposure"):
                C["main"](["report", str(path), revision])

    def test_rejects_replaced_socket_preselected_relay_missing_progress_and_unsafe_cleanup(self):
        for mutate in (
            lambda e: e["refilled"]["client"]["kernel"].update(cookie="ffff"),
            lambda e: e["owners_initial"]["exit"]["paths"][2].update(relay_node="relay4"),
            lambda e: e["owners_refilled"]["client"].update(netns="new"),
            lambda e: e["exposure"].update(started_monotonic_ns=1),
            lambda e: e["exposure"].update(helper_pid_after=31),
            lambda e: e["owners_refilled"]["client"]["paths"][3].update(endpoint="49.165.6.1:41001"),
            lambda e: e["client"].update(response_bytes=32 * 1024 * 1024),
            lambda e: e["privacy"]["expanded"]["relay4"].update(exit_leg_wireguard_data_datagrams=0),
            lambda e: e["qdiscs"]["warm"]["during"][0].update(drops=0),
            lambda e: e["cleanup"].update(owned_qdiscs_removed=False),
        ):
            e = copy.deepcopy(self.evidence)
            mutate(e)
            with self.assertRaises(ValueError):
                C["validate"](e)

    def test_rejects_no_new_data_despite_real_looking_fourth_tuple(self):
        e = copy.deepcopy(self.evidence)
        for role in ("client", "exit"):
            sample = e["refilled_progress"][role]
            sample["raw"]["tcp"] = "\n".join(line.replace("700000", "600000") if "fd42:1:4:" in line else line
                                             for line in sample["raw"]["tcp"].splitlines()) + "\n"
        reproject(e, "refilled_progress")
        with self.assertRaisesRegex(ValueError, "substantial fresh payload"):
            C["validate"](e)


if __name__ == "__main__":
    unittest.main()
