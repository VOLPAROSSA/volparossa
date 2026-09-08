#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic checker tests, not evidence that native paths carried actual traffic."""

import copy
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

CHECK = runpy.run_path(str(Path(__file__).with_name("mpquic-growth-smoke.py")))


def fixture():
    peers = {node: f"peer-{node}" for node in CHECK["ROLES"]}
    context = "a" * 32
    snapshots = []
    for stage in range(5):
        rows = [dict(route_context_id=context, path_id=i + 1, relay_peer_id=peers[f"relay{i}"],
                     exit_peer_id=peers["exit"], state=4 if i == 2 and stage < 2 else 3,
                     smoothed_rtt_us=0 if i == 2 and stage < 2 else 10000,
                     native_acked_bytes=0 if i == 2 and stage < 2 else stage * 100000)
                for i in range(3)]
        snapshots.append(dict(route_context_id=context, paths=rows, observed_monotonic_ns=stage + 1))
    captures = {}
    for role in CHECK["ROLES"]:
        interfaces = ([f"cr{i}" for i in range(6)] + ["cb1", "cb2", "underlay"] if role == "client"
                      else [f"xr{i}" for i in range(6)] + ["xd", "underlay"] if role == "exit"
                      else [f"r{role[-1]}c", f"r{role[-1]}x", "underlay"])
        captures[role] = dict(capture_role=role, truncated=False, packet_socket_drops=0,
            interfaces=interfaces, observed_frames=len(interfaces) * 100,
            interface_statistics={name: dict(observed_frames=100, packet_socket_packets=100,
                packet_socket_drops=0, intake_stopped=True) for name in interfaces},
            unexpected_outer_packets=0, expected_link_down_notifications=0,
            internet_destination_outer_packets=0, direct_client_exit_packets=0,
            client_public_packets=0, outbound_client_discovery_attempt_packets=0,
            client_leg_wireguard_data_datagrams=50, exit_leg_wireguard_data_datagrams=50)
    run = "b" * 32
    common = dict(schema_version=1, case="mpquic-growth", protocol="HTTP/3", http_version="HTTP/3",
        negotiated_alpn="h3", hostname="destination.volparossa.test", request_bytes=CHECK["BODY_BYTES"],
        response_bytes=CHECK["BODY_BYTES"], request_sha256=CHECK["payload_hash"](run, "request"),
        response_sha256=CHECK["payload_hash"](run, "response"))
    return dict(success=True, run_id=run, expected_peers=peers,
        **dict(zip(("selection", "before_loss", "expanded", "expanded_progress", "after_restore"), snapshots)),
        privacy=dict(initial=copy.deepcopy(captures), expanded=copy.deepcopy(captures)),
        injection=dict(relay_node="relay0", interface="r0x", path_id=1, loss_percent=15,
            before=[dict(kind="noqueue", handle="0:")], after=[dict(kind="noqueue", handle="0:")],
            during=[dict(kind="netem", handle="7a01:", drops=100,
                         options={"loss-random": dict(loss=0.15, correlation=0), "limit": 1000})]),
        client=dict(common, application=dict(ip="43.159.1.1", port=52008),
            destination=dict(ip="47.163.4.2", port=443), transfer_elapsed_ns=100000,
            response_duration_ns=50000, endpoint_drain_completed=True, endpoint_drain_budget_ms=5000),
        server=dict(common, source=dict(ip="47.163.4.1", port=41000), listen=dict(ip="47.163.4.2", port=443),
            peer_completion_observed=True, release_observed=False),
        cleanup=dict(client_exit_status=0, server_exit_status=0, route_disconnected=True,
                     active_contexts=0, paths_empty=True, loss_removed=True))


def raw_files(evidence):
    prefix = "mpquic-growth"
    files = {f"{prefix}-{suffix}.json": evidence[key] for key, suffix in (
        ("selection", "selection"), ("before_loss", "before-loss"), ("expanded", "expanded"),
        ("expanded_progress", "expanded-progress"), ("after_restore", "after-restore"),
        ("client", "client"), ("server", "server"), ("cleanup", "cleanup"), ("injection", "injection"))}
    for key, suffix in (("selection", "selection"), ("before_loss", "before-loss"),
                        ("expanded", "expanded"), ("expanded_progress", "expanded-progress"),
                        ("after_restore", "after-restore")):
        files[f"{prefix}-{suffix}.txt"] = "".join(
            f"context={row['route_context_id']} path={row['path_id']} relay={row['relay_peer_id']} "
            f"exit={row['exit_peer_id']} state={row['state']} rtt_us={row['smoothed_rtt_us']} "
            f"bytes={row['native_acked_bytes']}\n" for row in evidence[key]["paths"])
    for phase, captures in evidence["privacy"].items():
        for role, capture in captures.items():
            files[f"{prefix}-{phase}-privacy-{role}.json"] = capture
    for stage in ("before", "during", "after"):
        files[f"{prefix}-qdisc-{stage}.json"] = evidence["injection"][stage]
    files[f"{prefix}-run.json"] = dict(run_id=evidence["run_id"])
    files["a01-expected-peers.json"] = evidence["expected_peers"]
    files[f"{prefix}-final-status.txt"] = "connected: false\nactive contexts: 0\n"
    files[f"{prefix}-final-paths.txt"] = ""
    files[f"{prefix}-evidence.json"] = evidence
    return files


class GrowthEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = fixture()

    def test_exact_32mib_flow_growth_and_source_bound_raw_rebuild(self):
        evidence = copy.deepcopy(self.evidence)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for name, value in raw_files(evidence).items():
                (work / name).write_text(value if isinstance(value, str) else json.dumps(value), encoding="ascii")
            self.assertEqual(CHECK["build_evidence"](work), evidence)
            host = b'{"links":[],"routes":[]}\n'
            for stage in ("before", "after"):
                (work / f"host-state-{stage}.json").write_bytes(host)
            revision = "c" * 40
            report = dict(schema_version=1, report_kind="volparossa-mpquic-growth-runtime",
                source_revision=revision, run_id=evidence["run_id"], success=True,
                phase="mpquic-growth-complete", observed_blocker="NONE", transfer=evidence,
                cleanup=dict(complete=True, remaining_owned_objects=0),
                host_state=dict(success=True, unchanged=True, before_sha256=hashlib.sha256(host).hexdigest(),
                                after_sha256=hashlib.sha256(host).hexdigest()))
            path = work / "mpquic-growth-smoke.json"
            path.write_text(json.dumps(report), encoding="ascii")
            CHECK["validate_report"](path, revision)
            with self.assertRaises(ValueError):
                CHECK["validate_report"](path, "d" * 40)
            (work / "mpquic-growth-expanded-progress.txt").write_text("bad\n", encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["validate_report"](path, revision)

    def test_only_initial_reserved_backup_may_be_silent(self):
        evidence = copy.deepcopy(self.evidence)
        silent = evidence["privacy"]["initial"]["relay2"]
        for key in ("observed_frames", "client_leg_wireguard_data_datagrams", "exit_leg_wireguard_data_datagrams"):
            silent[key] = 0
        for row in silent["interface_statistics"].values():
            row.update(observed_frames=0, packet_socket_packets=0)
        CHECK["validate"](evidence)
        for phase, role in (("initial", "relay0"), ("expanded", "relay2")):
            altered = copy.deepcopy(evidence)
            altered["privacy"][phase][role] = dict(copy.deepcopy(silent), capture_role=role)
            with self.assertRaises(ValueError):
                CHECK["validate"](altered)

    def test_nominal_ids_stale_bytes_loss_config_and_app_close_cannot_substitute(self):
        for mutation in (
                lambda e: e["expanded"]["paths"][2].update(state=4),
                lambda e: e["expanded_progress"]["paths"][2].update(native_acked_bytes=200000),
                lambda e: e["before_loss"]["paths"][0].update(native_acked_bytes=0),
                lambda e: e["expanded_progress"]["paths"][2].update(relay_peer_id="wrong-peer"),
                lambda e: e["injection"]["during"][0].update(drops=0),
                lambda e: e["injection"]["during"][0]["options"].update(delay=dict(delay=0.1)),
                lambda e: e["injection"].update(path_id=3),
                lambda e: e["server"].update(peer_completion_observed=False),
                lambda e: e["server"].update(release_observed=True),
                lambda e: e["client"].update(response_sha256="0" * 64),
                lambda e: e["privacy"]["expanded"]["relay2"].update(exit_leg_wireguard_data_datagrams=16),
                lambda e: e["privacy"]["initial"]["client"].update(direct_client_exit_packets=1),
                lambda e: e["cleanup"].update(loss_removed=False)):
            evidence = copy.deepcopy(self.evidence)
            mutation(evidence)
            with self.assertRaises(ValueError):
                CHECK["validate"](evidence)


if __name__ == "__main__":
    unittest.main()
