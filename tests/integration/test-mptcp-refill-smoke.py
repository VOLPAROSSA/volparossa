#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic checker regressions only: these are NOT fresh-relay runtime evidence."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

C = runpy.run_path(str(Path(__file__).with_name("mptcp-refill-smoke.py")))
OLD = runpy.run_path(str(Path(__file__).with_name("test-mptcp-growth-smoke.py")))


def fixture():
    old = OLD["fixture"]()
    e = {k: copy.deepcopy(old[k]) for k in ("run_id", "expected_peers", "selection", "client", "server")}
    e["expected_peers"]["relay4"] = "peer4"
    e["success"] = True
    e["layout_initial"] = old["layout"]
    e["layout_refilled"] = copy.deepcopy(old["layout"])
    p = dict(path_id=4, client_address="fd42:1:4::1", exit_address="fd42:1:4::3", client_interface="vpc4", exit_interface="vpx4")
    e["layout_refilled"]["paths"].append(p)
    e["owners_initial"] = old["owners"]
    e["owners_refilled"] = copy.deepcopy(old["owners"])
    for role in ("client", "exit"):
        e["owners_refilled"][role]["paths"].append(dict(path_id=4, interface=p[f"{role}_interface"], ifindex=5,
            relay_node="relay4", endpoint="49.165.5.1:41001"))
    for i, stage in enumerate(("baseline", "initial_progress", "warm", "warm_progress", "retired", "refilled", "refilled_progress")):
        ids = [1, 2] if i < 2 or stage == "retired" else [1, 2, 3] if i < 4 else [1, 2, 4]
        layout = dict(e["layout_refilled"], paths=[p for p in e["layout_refilled"]["paths"] if p["path_id"] in ids])
        e[stage] = dict(started_monotonic_ns=i * 20_000_000_000 + 1,
            observed_monotonic_ns=i * 20_000_000_000 + 2,
            **{role: OLD["raw_snapshot"](layout, role, len(ids), i * 100000, 20 if i > 1 else 0)
               for role in ("client", "exit")})
    e["exposure"] = dict(relay_peer_id="peer4", capacity_before_mbps=1, capacity_after_mbps=32,
        started_monotonic_ns=e["retired"]["observed_monotonic_ns"] + 1, helper_pid_before=30, helper_pid_after=30,
        agent_pid_before=20, agent_pid_after=21)
    e["injection"] = dict(risky_path=1, warm_path=3, risky_interface="xr0", warm_interface="xr2", namespace_role="exit",
        initial_loss_percent=15, final_loss_percent=100)
    e["qdiscs"] = {key: dict(before=[dict(kind="noqueue", handle="0:")],
        during=[dict(kind="netem", handle=handle, root=True, drops=10, options={"loss-random": {"loss": 1}})],
        after=[dict(kind="noqueue", handle="0:")]) for key, handle in (("risky", "7b01:"), ("warm", "7b02:"))}
    e["rate_limits"] = copy.deepcopy(old["rate_limits"])
    e["rate_limits"]["relay4"] = copy.deepcopy(e["rate_limits"]["relay0"])
    for phases in e["rate_limits"].values():
        phases["during"][0]["handle"] = "7b03:"
    e["privacy"] = old["privacy"]
    for phase in ("initial", "expanded"):
        fourth = copy.deepcopy(e["privacy"][phase]["relay0"])
        fourth.update(capture_role="relay4", interfaces=["r4c", "r4x", "underlay"])
        fourth["interface_statistics"] = {k.replace("r0", "r4"): v for k, v in fourth["interface_statistics"].items()}
        e["privacy"][phase]["relay4"] = fourth
        for role in ("client", "exit"):
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
    e["client"].update(first_byte_monotonic_ns=3, completed_monotonic_ns=140_000_000_003,
                       duration_ns=140_000_000_000)
    e["cleanup"] = dict(application_complete=True, route_disconnected=True, owned_qdiscs_removed=True)
    return e


def raw_files(e):
    prefix = C["PREFIX"]
    keys = ("selection", "layout_initial", "layout_refilled", "owners_initial", "owners_refilled", "baseline",
            "initial_progress", "warm", "warm_progress", "retired", "refilled", "refilled_progress", "injection",
            "exposure", "client", "server", "cleanup")
    files = {f"{prefix}-{key.replace('_', '-')}.json": e[key] for key in keys}
    files[f"{prefix}-selection.txt"] = OLD["raw_files"](OLD["fixture"]())["mptcp-growth-selection.txt"]
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
            report = dict(schema_version=1, report_kind="volparossa-mptcp-refill-runtime", source_revision=revision,
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
            sample["raw"]["tcp"] = "\n".join(line.replace("600000", "500000") if "fd42:1:4:" in line else line
                                             for line in sample["raw"]["tcp"].splitlines()) + "\n"
            sample["kernel"] = C["G"].kernel_sample(sample["raw"], e["layout_refilled"], role)
        with self.assertRaisesRegex(ValueError, "substantial fresh payload"):
            C["validate"](e)


if __name__ == "__main__":
    unittest.main()
