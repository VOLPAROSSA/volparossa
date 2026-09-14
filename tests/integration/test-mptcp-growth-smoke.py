#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic parser/checker regressions, never evidence that live MPTCP grew."""

import copy
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

CHECK = runpy.run_path(str(Path(__file__).with_name("mptcp-growth-smoke.py")))
OTHER = runpy.run_path(str(Path(__file__).with_name("test-mpquic-growth-smoke.py")))


def raw_snapshot(layout, role, count, amount, retrans=0):
    own, peer = ("abc123", "def456") if role == "client" else ("def456", "abc123")
    cookie = "a1" if role == "client" else "b1"
    opposite = "exit" if role == "client" else "client"
    rows = []
    for path in layout["paths"][:count]:
        pid = path["path_id"]
        port, remote_port = (40000 + pid, 44443) if role == "client" else (44443, 40000 + pid)
        local = f"[{path[f'{role}_address']}]:{port}"
        remote = f"[{path[f'{opposite}_address']}]:{remote_port}"
        remote_token = "0000" if pid == 1 else peer
        local_id, remote_id = ((0, 0) if pid == 1 else
                               (pid, pid + 1) if role == "client" else (pid + 1, pid))
        flags = "Mec" if pid == 1 else ("Jjec" if role == "client" else "Jec")
        rows.append(f"ESTAB 0 0 {local} {remote} uid:1000 ino:1 sk:{cookie}{pid} "
                    f"bytes_acked:{amount} bytes_received:{amount} data_segs_out:{amount // 1000} "
                    f"retrans:0/{retrans if pid == 1 else 0} tcp-ulp-mptcp flags:{flags} "
                    f"token:{remote_token}(id:{remote_id})/{own}(id:{local_id})\n")
    state = "FIN-WAIT-2" if role == "client" else "CLOSE-WAIT"
    first = rows[0].split()
    raw = dict(meta=f"{state} 0 0 {first[3]} {first[4]} uid:1000 ino:1 sk:{cookie} token:{own}\n",
               tcp="".join(rows))
    return dict(raw=raw, kernel=CHECK["kernel_sample"](raw, layout, role))


def fixture():
    other = OTHER["fixture"]()
    layout = dict(context="a" * 32, paths=[dict(path_id=i,
        client_address=f"fd42:1:{i}::1", exit_address=f"fd42:1:{i}::3",
        client_interface=f"vpc{i}", exit_interface=f"vpx{i}") for i in range(1, 4)])
    selection = copy.deepcopy(other["selection"])
    selection["paths"] = selection["paths"][:2]
    for row in selection["paths"]:
        row.update(state=1, smoothed_rtt_us=0)
    selection["source"] = "initial committed selection only; kernel measurements prove data"
    snapshots = {}
    for stage, name in enumerate(("baseline", "before_loss", "expanded", "expanded_progress")):
        snapshots[name] = dict(started_monotonic_ns=stage * 10 + 1, observed_monotonic_ns=stage * 10 + 2,
            **{role: raw_snapshot(layout, role, 2 if stage < 2 else 3, stage * 100000,
                                 0 if stage < 2 else 20) for role in ("client", "exit")})
    owners = {role: dict(unit=f"volparossa-alpha-helper@{role}.service", cgroup="/system.slice/test",
        pid=1000 + index, start_ticks="10", netns="30", paths=[dict(path_id=p["path_id"],
            interface=p[f"{role}_interface"], ifindex=p["path_id"] + 1, relay_node=f"relay{i}",
            endpoint=f"{list(CHECK['RELAY_IPS'])[i]}:41001") for i, p in enumerate(layout["paths"])])
        for index, role in enumerate(("client", "exit"))}
    request = b"volparossa-mptcp-growth:" + bytes.fromhex(other["run_id"]) + bytes(4)
    common = dict(case="mptcp-growth", attempt=0, request_bytes=len(request),
        response_bytes=CHECK["BODY_BYTES"], request_sha256=hashlib.sha256(request).hexdigest(),
        response_sha256=CHECK["payload_hash"](other["run_id"]))
    injection = copy.deepcopy(other["injection"])
    injection.update(interface="xr0", namespace_role="exit")
    rates = {f"relay{i}": dict(before=[dict(kind="noqueue", handle="0:")],
        during=[dict(kind="tbf", handle="7a02:", root=True, options=dict(rate=1000000))],
        after=[dict(kind="noqueue", handle="0:")]) for i in range(3)}
    return dict(success=True, run_id=other["run_id"], expected_peers=other["expected_peers"],
        selection=selection, layout=layout, owners=owners, **snapshots, injection=injection,
        privacy=other["privacy"], rate_limits=rates,
        client=dict(common, application=dict(ip="43.159.1.1", port=40001),
                    destination=dict(ip="47.163.4.2", port=18080),
                    first_byte_monotonic_ns=12, completed_monotonic_ns=50, duration_ns=38),
        server=dict(common, source=dict(ip="47.163.4.1", port=41000),
                    listen=dict(ip="47.163.4.2", port=18080)),
        cleanup=dict(client_exit_status=0, route_disconnected=True, active_contexts=0,
                     paths_empty=True, loss_removed=True, rate_limits_removed=True))


def raw_files(evidence):
    prefix = "mptcp-growth"
    files = {f"{prefix}-{suffix}.json": evidence[key] for key, suffix in (
        ("selection", "selection"), ("layout", "layout"), ("owners", "owners"), ("baseline", "baseline"),
        ("before_loss", "before-loss"), ("expanded", "expanded"), ("expanded_progress", "expanded-progress"),
        ("injection", "injection"), ("client", "client"), ("server", "server"), ("cleanup", "cleanup"))}
    files[f"{prefix}-selection.txt"] = "".join(
        f"context={r['route_context_id']} path={r['path_id']} relay={r['relay_peer_id']} exit={r['exit_peer_id']} "
        f"state={r['state']} rtt_us={r['smoothed_rtt_us']} bytes={r['user_bytes']} "
        f"acked_transport_bytes={r['acked_transport_bytes']}\n" for r in evidence["selection"]["paths"])
    for phase, captures in evidence["privacy"].items():
        for role, capture in captures.items():
            files[f"{prefix}-{phase}-privacy-{role}.json"] = capture
    for stage in ("before", "during", "after"):
        files[f"{prefix}-qdisc-{stage}.json"] = evidence["injection"][stage]
        for node, phases in evidence["rate_limits"].items():
            files[f"{prefix}-rate-{node[-1]}-{stage}.json"] = phases[stage]
    files.update({f"{prefix}-run.json": dict(run_id=evidence["run_id"]),
        "a01-expected-peers.json": evidence["expected_peers"], f"{prefix}-evidence.json": evidence,
        f"{prefix}-final-status.txt": "connected: false\nactive contexts: 0\n",
        f"{prefix}-final-paths.txt": ""})
    return files


class MptcpGrowthEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = fixture()

    def test_raw_rebuild_and_source_bound_report(self):
        evidence = copy.deepcopy(self.evidence)
        CHECK["validate"](evidence)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for name, value in raw_files(evidence).items():
                (work / name).write_text(value if isinstance(value, str) else json.dumps(value), encoding="ascii")
            self.assertEqual(CHECK["build_evidence"](work), evidence)
            host = b'{"links":[],"routes":[]}\n'
            for stage in ("before", "after"):
                (work / f"host-state-{stage}.json").write_bytes(host)
            revision = "c" * 40
            report = dict(schema_version=1, report_kind="volparossa-mptcp-growth-runtime",
                source_revision=revision, run_id=evidence["run_id"], success=True,
                phase="mptcp-growth-complete", observed_blocker="NONE", transfer=evidence,
                cleanup=dict(complete=True, remaining_owned_objects=0),
                host_state=dict(success=True, unchanged=True, before_sha256=hashlib.sha256(host).hexdigest(),
                                after_sha256=hashlib.sha256(host).hexdigest()))
            path = work / "mptcp-growth-smoke.json"
            path.write_text(json.dumps(report), encoding="ascii")
            CHECK["report"](path, revision)
            with self.assertRaises(ValueError):
                CHECK["report"](path, "d" * 40)
            altered = copy.deepcopy(evidence["expanded_progress"])
            altered["client"]["raw"]["tcp"] = "ESTAB invalid\n"
            (work / "mptcp-growth-expanded-progress.json").write_text(json.dumps(altered), encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["report"](path, revision)

    def test_same_flow_lifetime_progress_all_three_and_ownership_are_required(self):
        for mutation in (
            lambda e: e["expanded_progress"]["client"]["kernel"]["subflows"][2].update(bytes_received=200000),
            lambda e: e["expanded"]["exit"]["kernel"].update(cookie="aabb"),
            lambda e: e["expanded"]["client"]["kernel"]["subflows"][1].update(cookie="aabb"),
            lambda e: e["owners"]["exit"]["paths"][2].update(relay_node="relay1"),
            lambda e: e["injection"].update(namespace_role="relay", interface="r0x"),
            lambda e: e["injection"]["during"][0].update(drops=0),
            lambda e: e["rate_limits"]["relay0"]["during"][0]["options"].update(rate=8000000),
            lambda e: e["rate_limits"]["relay1"]["after"][0].update(kind="tbf"),
            lambda e: e["client"].update(response_sha256="0" * 64),
            lambda e: e["privacy"]["expanded"]["relay2"].update(exit_leg_wireguard_data_datagrams=0),
            lambda e: e["privacy"]["expanded"]["client"].update(direct_client_exit_packets=1),
            lambda e: e["cleanup"].update(rate_limits_removed=False)):
            evidence = copy.deepcopy(self.evidence)
            mutation(evidence)
            with self.assertRaises(ValueError):
                CHECK["validate"](evidence)

    def test_initial_mp_capable_zero_remote_token_only_on_original_tuple(self):
        evidence = copy.deepcopy(self.evidence)
        CHECK["validate"](evidence)
        for role in ("client",):
            altered = copy.deepcopy(evidence)
            snapshot = altered["expanded"][role]
            remote = "def456" if role == "client" else "abc123"
            snapshot["raw"]["tcp"] = snapshot["raw"]["tcp"].replace(f"token:{remote}(id:3)", "token:0000(id:3)")
            snapshot["kernel"] = CHECK["kernel_sample"](snapshot["raw"], altered["layout"], role)
            with self.assertRaises(ValueError):
                CHECK["validate"](altered)

    def test_accepted_exit_join_zero_remote_token_binds_exact_mirrored_ids(self):
        evidence = copy.deepcopy(self.evidence)
        for stage in ("baseline", "before_loss", "expanded", "expanded_progress"):
            snapshot = evidence[stage]["exit"]
            for path in (2, 3):
                snapshot["raw"]["tcp"] = snapshot["raw"]["tcp"].replace(
                    f"token:abc123(id:{path})", f"token:0000(id:{path})")
            snapshot["kernel"] = CHECK["kernel_sample"](snapshot["raw"], evidence["layout"], "exit")
        CHECK["validate"](evidence)
        for replacement in ("flags:Jjec", "flags:Mec"):
            altered = copy.deepcopy(evidence)
            snapshot = altered["expanded"]["exit"]
            snapshot["raw"]["tcp"] = snapshot["raw"]["tcp"].replace("flags:Jec", replacement)
            snapshot["kernel"] = CHECK["kernel_sample"](snapshot["raw"], altered["layout"], "exit")
            with self.assertRaises(ValueError):
                CHECK["validate"](altered)
        altered = copy.deepcopy(evidence)
        snapshot = altered["expanded"]["exit"]
        snapshot["raw"]["tcp"] = snapshot["raw"]["tcp"].replace("token:0000(id:3)", "token:0000(id:4)")
        snapshot["kernel"] = CHECK["kernel_sample"](snapshot["raw"], altered["layout"], "exit")
        with self.assertRaises(ValueError):
            CHECK["validate"](altered)

    def test_halfclosed_meta_and_absent_zero_fields_are_not_tcp_fallback(self):
        for role in ("client", "exit"):
            raw = copy.deepcopy(self.evidence["baseline"][role]["raw"])
            raw["tcp"] = raw["tcp"].replace("bytes_acked:0 ", "").replace("bytes_received:0 ", "")
            projected = CHECK["kernel_sample"](raw, self.evidence["layout"], role)
            self.assertTrue(all(row["bytes_acked"] == row["bytes_received"] == 0 for row in projected["subflows"]))
            for key, replacement in (("meta", raw["meta"] + " fallback"),
                                     ("tcp", raw["tcp"].replace("tcp-ulp-mptcp", "tcp-ulp-other")),
                                     ("tcp", raw["tcp"].replace("ESTAB", "TIME-WAIT"))):
                invalid = dict(raw)
                invalid[key] = replacement
                with self.assertRaises(ValueError):
                    CHECK["kernel_sample"](invalid, self.evidence["layout"], role)

    def test_kernel_growth_window_rejects_original_subflow_restart(self):
        evidence = copy.deepcopy(self.evidence)
        for stage in ("expanded", "expanded_progress"):
            snapshot = evidence[stage]["client"]
            snapshot["raw"]["tcp"] = snapshot["raw"]["tcp"].replace("sk:a12", "sk:ffff")
            snapshot["kernel"] = CHECK["kernel_sample"](snapshot["raw"], evidence["layout"], "client")
        with self.assertRaisesRegex(ValueError, "replaced an original subflow"):
            CHECK["validate"](evidence)


if __name__ == "__main__":
    unittest.main()
