#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure exact-identity/counter and actual workflow predicate checks; no network queries."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


DIRECTORY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("snapshot", DIRECTORY / "download-sharing-snapshot.py")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class SnapshotTests(unittest.TestCase):
    def test_exact_context_gate_and_pinned_link(self):
        context, name = "ab" * 16, "vpe112345678"
        table = "vpd_" + context + "_1"
        expression = lambda key, value: {"match": {"left": {"meta": {"key": key}}, "op": "==", "right": value}}
        nft = {"nftables": [
            {"table": {"family": "netdev", "name": table}},
            {"chain": {"family": "netdev", "table": table, "name": "egress", "hook": "egress", "prio": 0, "dev": name}},
            {"rule": {"family": "netdev", "table": table, "chain": "egress", "expr": [
                expression("oif", 7), expression("oifname", name), {"counter": {"bytes": 0, "packets": 0}}, {"drop": None}]}}]}
        link = {"ifname": name, "ifindex": 7, "mtu": 1420, "linkinfo": {"info_kind": "wireguard"},
                "ifalias": "volparossa:wireguard:ownership-v1:" + name + ":" + "cd" * 32}
        bound = SNAPSHOT.gate_interface(nft, context, 1, [link])
        self.assertEqual(bound["interface"], name)
        self.assertIsNone(SNAPSHOT.gate_interface(nft, "cd" * 16, 1, [link]))
        for changed in [dict(link, ifindex=8), dict(link, ifalias="foreign"), dict(link, linkinfo={"info_kind": "veth"})]:
            with self.assertRaises(ValueError):
                SNAPSHOT.gate_interface(nft, context, 1, [changed])
        old_gate = copy.deepcopy(nft)
        old_gate["nftables"][0]["table"]["family"] = "inet"
        with self.assertRaises(ValueError):
            SNAPSHOT.gate_interface(old_gate, context, 1, [link])

    def test_real_queue_counters_and_bound_are_not_fabricated(self):
        counters = {"bytes": 1028, "packets": 1, "drops": 0, "overlimits": 2, "backlog": 0}
        rows = [{"kind": "tbf", "root": True, "handle": "6002:", **counters},
                {"kind": "fq_codel", "handle": "6003:", "parent": "6002:1", "options": {"memory_limit": 65536}}]
        self.assertEqual(SNAPSHOT.sender_queue(rows, 1), (counters, 65536))
        with self.assertRaises(ValueError):
            SNAPSHOT.sender_queue(rows, 2)
        del rows[0]["bytes"]
        with self.assertRaises(KeyError):
            SNAPSHOT.sender_queue(rows, 1)

    def test_workflow_requires_separate_live_download_evidence(self):
        workflow = (DIRECTORY.parent.parent / ".github/workflows/alpha-topology.yml").read_text()
        block = workflow.split("- name: Require real shared-downlink owner-priority evidence", 1)[1].split("\n      - name:", 1)[0]
        predicate = block.split("jq -e --arg revision \"$GITHUB_SHA\" '", 1)[1].split("' \"$VOLPAROSSA_ALPHA_OUTPUT/download-sharing-smoke.json\"", 1)[0]
        def run(record):
            return subprocess.run(["jq", "-e", "--arg", "revision", "a" * 40, predicate], input=json.dumps(record),
                                  text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode
        windows = {name: {"receiver_wire_mbps": 10, "sender_queue_mbps": 3,
                         "owner_application_mbps": 10, "contribution_application_mbps": 3}
                   for name in ("baseline", "idle", "owner", "recovery", "expiry")}
        windows["owner"]["contribution_application_mbps"] = 1
        record = {"report_kind": "volparossa-owner-priority-downlink", "source_revision": "a" * 40, "success": True,
                  "windows": windows, "flow": {"same_route_context": True, "wireguard_both_legs": [1, 2, 3, 4]},
                  "expiry": {"refresh_paused": True, "drained_tail_bytes": 100, "bounded_tail_bytes": 200,
                             "contribution_after_expiry_bytes": 0}, "privacy": {"complete": True, "drops": 0},
                  "cleanup": {"complete": True, "remaining_owned_objects": 0, "accounting_removed": True},
                  "host_state": {"unchanged": True}}
        self.assertEqual(run(record), 0)
        for field, value in (("report_kind", "volparossa-owner-priority-uplink"), ("success", False),
                             ("cleanup", {"complete": False, "remaining_owned_objects": 1, "accounting_removed": False}),
                             ("expiry", {"refresh_paused": True, "drained_tail_bytes": 300, "bounded_tail_bytes": 200,
                                         "contribution_after_expiry_bytes": 1})):
            self.assertNotEqual(run({**record, field: value}), 0)


if __name__ == "__main__":
    unittest.main()
