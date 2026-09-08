#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure namespace-ownership classification; no networking or live A14 claim."""

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("inventory", HERE / "a14-worker-inventory.py")
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


def link(name, index, peer, address):
    return {"ifname": name, "ifindex": index, "link_index": peer,
            "linkinfo": {"info_kind": "veth"},
            "addr_info": [{"family": "inet", "local": address, "prefixlen": 30}]}


class WorkerClassification(unittest.TestCase):
    def setUp(self):
        self.parent = [link("vpih1d7ceb15", 3, 2, "169.254.240.1")]
        self.ingress = [link("vpiw1d7ceb15", 2, 3, "169.254.240.2")]
        self.route = [{"ifname": "vpc1abcde123", "ifindex": 2,
                       "linkinfo": {"info_kind": "wireguard"},
                       "ifalias": "volparossa:wireguard:ownership-v1:vpc1abcde123:" + "a" * 64}]

    def test_exact_ingress_pair_is_distinct_from_durable_route(self):
        ingress = INVENTORY.classify(self.parent, self.ingress)
        route = INVENTORY.classify(self.parent, self.route)
        self.assertEqual((ingress["ownership_class"], ingress["durable_descriptors_required"]),
                         ("live_client_ingress", 0))
        self.assertTrue(ingress["ownership_provenance"]["reciprocal_veth_indices"])
        self.assertEqual((route["ownership_class"], route["durable_descriptors_required"]),
                         ("durable_route", 2))

    def test_names_alone_wrong_pair_and_mixed_workers_are_rejected(self):
        for field, value in (("link_index", 8), ("ifname", "vpihffffffff"),
                             ("linkinfo", {"info_kind": "dummy"}), ("addr_info", [])):
            parent = copy.deepcopy(self.parent)
            parent[0][field] = value
            with self.assertRaises(ValueError, msg=field):
                INVENTORY.classify(parent, self.ingress)
        with self.assertRaises(ValueError):
            INVENTORY.classify(self.parent, self.ingress + self.route)
        with self.assertRaises(ValueError):
            INVENTORY.classify(self.parent, [{"ifname": "lo", "ifindex": 1}])
        route = copy.deepcopy(self.route)
        route[0]["ifalias"] = route[0]["ifalias"].replace("vpc1abcde123:", "vpc1ffffffff:")
        with self.assertRaises(ValueError):
            INVENTORY.classify(self.parent, route)

    def test_nineteen_namespaces_need_thirty_six_route_descriptors_not_thirty_eight(self):
        ingress = INVENTORY.classify(self.parent, self.ingress)
        route = INVENTORY.classify(self.parent, self.route)
        helpers = [{"helper_unit": f"helper{index}", "fdstore_descriptors": 0} for index in range(11)]
        helpers[0]["fdstore_descriptors"], helpers[1]["fdstore_descriptors"] = 2, 34
        workers = [{"helper_unit": "helper0", "worker_pid_before": 14076,
                    "network_namespace_device": 4, "network_namespace_inode": 3062, **ingress}]
        for index in range(18):
            workers.append({"helper_unit": "helper0" if index == 0 else "helper1",
                            "worker_pid_before": 27000 + index, "network_namespace_device": 4,
                            "network_namespace_inode": 4000 + index, **route})
        summary = INVENTORY.summarize(workers, helpers)
        self.assertEqual((summary["worker_network_namespace_count"], summary["durable_route_namespace_count"],
                          summary["live_ingress_namespace_count"], summary["helper_fdstore_descriptors"]),
                         (19, 18, 1, 36))
        self.assertEqual(summary["worker_network_namespaces"], workers)  # No cleanup target dropped.
        # Another helper cannot conceal this helper's missing custody even when totals match.
        helpers[0]["fdstore_descriptors"], helpers[1]["fdstore_descriptors"] = 0, 36
        with self.assertRaises(ValueError):
            INVENTORY.summarize(workers, helpers)


if __name__ == "__main__":
    unittest.main()
