#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert fixture contracts: no Go download/build, KVM, namespaces or network."""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("transaction-abci-smoke.py")
SPEC = importlib.util.spec_from_file_location("transaction_abci_fixture", SOURCE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class FixtureContracts(unittest.TestCase):
    def test_preview_is_inert(self):
        with patch.object(FIXTURE, "parse_args", return_value=argparse.Namespace(inside=False, execute=False)), \
                patch.object(FIXTURE.subprocess, "Popen", side_effect=AssertionError("no child")), \
                patch("builtins.print"):
            self.assertEqual(FIXTURE.main(), 0)

    def test_explicit_confirmation_required(self):
        with patch.object(FIXTURE, "parse_args", return_value=argparse.Namespace(inside=False, execute=True, yes=False)), \
                patch.object(FIXTURE, "execute", side_effect=AssertionError("no execution")), \
                patch("builtins.print"):
            with self.assertRaisesRegex(FIXTURE.TrialFailure, "explicit_confirmation_required"):
                FIXTURE.main()

    def test_namespace_commands_never_create_parent_network_objects(self):
        prefix = "vptx-0123456789ab"
        commands = FIXTURE.network_plan(prefix)
        names = FIXTURE.namespace_names(prefix)
        self.assertEqual(len(names), 5)
        self.assertEqual(commands[:5], [["ip", "netns", "add", name] for name in names])
        for command in commands[5:]:
            self.assertEqual(command[:2], ["ip", "-n"])
            self.assertIn(command[2], names)
            self.assertNotIn("default", command)
        veths = [command for command in commands if "veth" in command]
        self.assertEqual(len(veths), 4)
        for command in veths:
            self.assertEqual(command[2], names[0])
            self.assertIn(command[-1], names[1:])

    def test_namespace_prefix_closed(self):
        for value in ("vptx-../root", "vptx-ABCDEF123456", "", "root", "vptx-1234", None):
            with self.subTest(value=value), self.assertRaises((FIXTURE.TrialFailure, TypeError)):
                FIXTURE.namespace_names(value)

    def test_partition_cuts_both_directions_including_established_replies(self):
        for left, right in (([0, 1, 2], [3]), ([0, 1], [2, 3])):
            rules = FIXTURE.partition_rules(left, right).decode()
            self.assertEqual(rules.count("counter drop"), 2)
            self.assertIn("table bridge vptx", rules)
            self.assertIn("hook forward", rules)
            self.assertNotIn("dport", rules)
            self.assertNotIn("sport", rules)
            self.assertNotIn("ct state", rules)
            self.assertNotIn("10.77.0.1,", rules)
            for address in FIXTURE.NODES:
                self.assertEqual(rules.count(address), 2)

    def test_partition_requires_complete_disjoint_membership(self):
        for left, right in (([], [0, 1, 2, 3]), ([0], [1, 2]), ([0, 1], [1, 2, 3]), ([0, 1], [2, 4])):
            with self.subTest(left=left, right=right), self.assertRaises(FIXTURE.TrialFailure):
                FIXTURE.partition_rules(left, right)

    def test_nested_chain_has_required_nft_statement_separator(self):
        # nftables 1.1.3 parser_bison.y: a nested chain's closing brace must
        # be followed by NEWLINE or SEMICOLON before the table closes.
        for left, right in (([0, 1, 2], [3]), ([0, 1], [2, 3])):
            rules = FIXTURE.partition_rules(left, right)
            self.assertEqual(rules.splitlines()[-2:], [b"}", b"}"])
            self.assertTrue(rules.endswith(b"}\n}\n"))
            self.assertNotIn(b"} }", rules)

    def test_partition_operations_are_fixed_and_fail_with_closed_tags(self):
        commands = {
            "install": ["nft", "-f", "-"],
            "list": ["nft", "-j", "list", "table", "bridge", "vptx"],
            "remove": ["nft", "delete", "table", "bridge", "vptx"],
        }
        for operation, command in commands.items():
            data = b"inert rules" if operation == "install" else None
            with patch.object(FIXTURE, "checked", return_value=b"inert") as checked:
                self.assertEqual(FIXTURE.partition_command(operation, data), b"inert")
                checked.assert_called_once_with(command, input_bytes=data)
            for error in (FIXTURE.TrialFailure("command_failed"), OSError("private path"),
                          subprocess.TimeoutExpired("private argv", 15)):
                with self.subTest(operation=operation, error=type(error)), \
                        patch.object(FIXTURE, "checked", side_effect=error):
                    with self.assertRaises(FIXTURE.TrialFailure) as raised:
                        FIXTURE.partition_command(operation, data)
                    self.assertEqual(str(raised.exception), "partition_" + operation + "_failed")
        for operation, data in (("flush", None), ("install", None), ("list", b"private"),
                                ("remove", b"private")):
            with patch.object(FIXTURE, "checked", side_effect=AssertionError("no command")), \
                    self.assertRaisesRegex(FIXTURE.TrialFailure, "partition_command_contract"):
                FIXTURE.partition_command(operation, data)

    def test_cut_and_heal_preserve_two_positive_packet_counters(self):
        trial = FIXTURE.Trial(argparse.Namespace(work="/var/tmp/inert-not-created"))
        with patch.object(FIXTURE, "partition_command") as command:
            trial.cut([0, 1, 2], [3])
            command.assert_called_once_with("install", FIXTURE.partition_rules([0, 1, 2], [3]))
        for counts in ([3, 4], [0, 4], [3], [True, 4]):
            value = {"nftables": [{"rule": {"expr": [{"counter": {"packets": n}}]}} for n in counts]}
            with patch.object(FIXTURE, "partition_command", return_value=json.dumps(value).encode()) as command:
                if counts == [3, 4]:
                    self.assertEqual(trial.heal(), counts)
                    self.assertEqual([call.args[0] for call in command.call_args_list], ["list", "remove"])
                else:
                    with self.assertRaisesRegex(FIXTURE.TrialFailure, "partition_no_packet_evidence"):
                        trial.heal()
                    command.assert_called_once_with("list")

    def test_lifetime_diagnostics_do_not_export_values_or_change_raw_hashes(self):
        address = [{"ifname": "inert-private-name", "addr_info": [{"local": "2001:db8::1",
                    "prefixlen": 64, "valid_life_time": 900, "preferred_life_time": 600}]}]
        route = [{"dst": "2001:db8::/64", "gateway": "fe80::1", "expires": 900, "metric": 1024}]
        before, after = {}, {}
        for label, value in (("addresses", address), ("routes6", route)):
            changed = copy.deepcopy(value)
            entry = changed[0]["addr_info"][0] if label == "addresses" else changed[0]
            entry["valid_life_time" if label == "addresses" else "expires"] -= 10
            raw, later = json.dumps(value).encode(), json.dumps(changed).encode()
            before[label] = FIXTURE.parent_lifetime_summary(label, raw)
            after[label] = FIXTURE.parent_lifetime_summary(label, later)
            self.assertNotEqual(hashlib.sha256(raw).hexdigest(), hashlib.sha256(later).hexdigest())
        diagnostic = FIXTURE.parent_lifetime_diagnostics(before, after)
        for value in diagnostic.values():
            self.assertTrue(value["parsed"])
            self.assertTrue(value["structure_equal"])
            self.assertTrue(value["lifetime_fields_only_changed"])
            self.assertFalse(value["lifetime_values_equal"])
            self.assertEqual(set(value), {"parsed", "structure_equal", "lifetime_values_equal",
                             "lifetime_fields_only_changed", "lifetime_fields_before", "lifetime_fields_after"})
            self.assertTrue(all(type(field) in (bool, int) for field in value.values()))
        encoded = json.dumps(diagnostic)
        for private in ("2001:db8", "fe80", "inert-private-name", "900", "600"):
            self.assertNotIn(private, encoded)

    def test_lifetime_diagnostics_preserve_all_other_fields_and_field_presence(self):
        originals = {
            "addresses": [{"ifname": "inert", "addr_info": [{"local": "2001:db8::1", "prefixlen": 64,
                "valid_life_time": 900, "preferred_life_time": 600, "unknown_future_field": 1}]}],
            "routes6": [{"dst": "2001:db8::/64", "gateway": "fe80::1", "expires": 900, "metric": 1024}],
        }
        for label, original in originals.items():
            left = FIXTURE.parent_lifetime_summary(label, json.dumps(original).encode())
            modifications = ({"local": "2001:db8::2"}, {"prefixlen": 48}, {"unknown_future_field": 2}) \
                if label == "addresses" else ({"gateway": "fe80::2"}, {"metric": 1025}, {"unknown": True})
            for fields in modifications:
                changed = copy.deepcopy(original)
                entry = changed[0]["addr_info"][0] if label == "addresses" else changed[0]
                entry.update(fields)
                right = FIXTURE.parent_lifetime_summary(label, json.dumps(changed).encode())
                value = FIXTURE.parent_lifetime_diagnostics({label: left}, {label: right})[label]
                self.assertTrue(value["parsed"])
                self.assertFalse(value["structure_equal"])
                self.assertFalse(value["lifetime_fields_only_changed"])
            changed = copy.deepcopy(original)
            entry = changed[0]["addr_info"][0] if label == "addresses" else changed[0]
            del entry["valid_life_time" if label == "addresses" else "expires"]
            right = FIXTURE.parent_lifetime_summary(label, json.dumps(changed).encode())
            self.assertFalse(FIXTURE.parent_lifetime_diagnostics({label: left}, {label: right})[label]["structure_equal"])
            self.assertTrue(FIXTURE.parent_lifetime_diagnostics({label: left}, {label: left})[label]["lifetime_values_equal"])

    def test_lifetime_parser_is_bounded_and_malformed_data_is_unclassified(self):
        invalid = (b"{", b"{}", b"[1]", b"[{\"addr_info\":1}]", b"[{\"addr_info\":[],\"addr_info\":[]}]",
                   b"[" * 2000, b" " * (FIXTURE.RPC_LIMIT + 1), json.dumps([{}] * 257).encode(),
                   json.dumps([{"addr_info": [{}] * 257}]).encode(),
                   json.dumps([{"addr_info": [{"valid_life_time": 1, "preferred_life_time": 1}] * 256}] * 3).encode())
        for raw in invalid:
            with self.subTest(raw_size=len(raw)):
                self.assertIsNone(FIXTURE.parent_lifetime_summary("addresses", raw))
        for bad in (-1, True, 1.5, 4294967296, "private", None):
            self.assertIsNone(FIXTURE.parent_lifetime_summary("routes6", json.dumps([{"expires": bad}]).encode()))
        self.assertIsNone(FIXTURE.parent_lifetime_summary("routes6", b'[{"unrelated":NaN}]'))
        self.assertIsNone(FIXTURE.parent_lifetime_summary("unknown", b"[]"))
        diagnostic = FIXTURE.parent_lifetime_diagnostics({"addresses": None}, {})
        self.assertTrue(all(value["parsed"] is False and value["lifetime_fields_only_changed"] is False
                            for value in diagnostic.values()))

    def test_parent_snapshot_retains_exact_raw_hashes_with_optional_diagnostics(self):
        def observed(command):
            if command == ["ip", "-j", "address"]:
                return b'[{"addr_info":[{"valid_life_time":900}]}]\n'
            if command == ["ip", "-j", "-6", "route", "show", "table", "all"]:
                return b'[{"expires":900}]\n'
            return b"inert unchanged snapshot bytes\n"
        diagnostic = {}
        with patch.object(FIXTURE, "checked", side_effect=observed), \
                patch.object(FIXTURE.Path, "read_bytes", return_value=b"inert file bytes"):
            raw_only = FIXTURE.parent_snapshot()
            with_diagnostics = FIXTURE.parent_snapshot(diagnostic)
        self.assertEqual(raw_only, with_diagnostics)
        self.assertEqual(raw_only["addresses"], hashlib.sha256(observed(["ip", "-j", "address"])).hexdigest())
        self.assertEqual(set(diagnostic), {"addresses", "routes6"})
        self.assertTrue(all(value is not None for value in diagnostic.values()))

    def test_toml_only_exact_section_key_is_replaced(self):
        text = 'laddr = "base"\n[rpc]\nladdr = "rpc"\n[p2p]\nladdr = "p2p"\n'
        actual = FIXTURE.replace_toml(text, "rpc", "laddr", "tcp://10.77.0.10:26657")
        self.assertIn('laddr = "base"', actual)
        self.assertIn('laddr = "p2p"', actual)
        self.assertIn('laddr = "tcp://10.77.0.10:26657"', actual)

    def test_upstream_key_missing_or_ambiguous_fails(self):
        for text in ('[rpc]\nother = 1\n', '[rpc]\nladdr = "a"\nladdr = "b"\n'):
            with self.assertRaisesRegex(FIXTURE.TrialFailure, "upstream_config_contract"):
                FIXTURE.replace_toml(text, "rpc", "laddr", "new")

    def test_build_receipt_requires_exact_source_toolchain_and_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            comet, adapter = root / "comet", root / "adapter"
            comet.write_bytes(b"inert comet bytes")
            adapter.write_bytes(b"inert rust bytes")
            receipt = {
                "schema": 1, "source_commit": "a" * 40, "comet_source": FIXTURE.COMET_COMMIT,
                "compiler": FIXTURE.GO_VERSION, "compiler_archive_sha256": FIXTURE.GO_SHA256,
                "compiler_license_sha256": FIXTURE.GO_LICENSE_SHA256,
                "source_built_engine": True, "compiler_auto_upgrade": False,
                "go_mod_sha256": "b" * 64, "go_sum_sha256": "c" * 64,
                "comet_sha256": hashlib.sha256(comet.read_bytes()).hexdigest(),
                "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
            }
            FIXTURE.verify_build(receipt, "a" * 40, comet, adapter)
            for name, wrong in (("source_commit", "d" * 40), ("comet_source", "f" * 40),
                                ("compiler_auto_upgrade", True), ("source_built_engine", False),
                                ("compiler", "go1.25.0"), ("compiler_archive_sha256", "e" * 64),
                                ("compiler_license_sha256", "0" * 64), ("comet_sha256", "0" * 64),
                                ("go_mod_sha256", "not-a-hash")):
                with self.subTest(name=name), self.assertRaises(FIXTURE.TrialFailure):
                    FIXTURE.verify_build({**receipt, name: wrong}, "a" * 40, comet, adapter)
            adapter.write_bytes(b"changed")
            with self.assertRaisesRegex(FIXTURE.TrialFailure, "binary_digest"):
                FIXTURE.verify_build(receipt, "a" * 40, comet, adapter)

    def test_boolean_acceptance_alone_is_not_completion(self):
        self.assertFalse(FIXTURE.inner_complete({"acceptance": True}))
        value = {"schema": 1, "unit": "TEST", "comet_source": FIXTURE.COMET_COMMIT,
                 "compiler": FIXTURE.GO_VERSION, "acceptance": True, "processes_reaped": True,
                 "phase": "crash_replay", "checkpoints": {phase: {} for phase in FIXTURE.PHASES if phase != "cleanup"}}
        self.assertTrue(FIXTURE.inner_complete(value))
        for phase in value["checkpoints"]:
            changed = {**value, "checkpoints": {key: entry for key, entry in value["checkpoints"].items() if key != phase}}
            self.assertFalse(FIXTURE.inner_complete(changed))
        self.assertFalse(FIXTURE.inner_complete({**value, "processes_reaped": False}))
        self.assertFalse(FIXTURE.inner_complete({**value, "failure": "anything"}))

    def test_rpc_disables_ambient_proxy_and_bounds_response(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return None
            def read(self, amount):
                self.amount = amount
                return b'{"jsonrpc":"2.0","id":1,"result":{"okay":true}}'
        response = Response()
        with patch.object(FIXTURE.urllib.request, "build_opener") as builder:
            builder.return_value.open.return_value = response
            self.assertEqual(FIXTURE.rpc(0, "status"), {"okay": True})
            self.assertEqual(builder.call_args.args[0].proxies, {})
            self.assertEqual(response.amount, FIXTURE.RPC_LIMIT + 1)
            request = builder.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, "http://10.77.0.10:26657")
            self.assertEqual(builder.return_value.open.call_args.kwargs["timeout"], 2)

    def test_info_uses_actual_test_unit_and_denies_finality_claim(self):
        value = {"unit": FIXTURE.TEST_UNIT, "height": 2, "app_hash": "a" * 64,
                 "ledger_id": "b" * 64, "consensus_certificate": False}
        with patch.object(FIXTURE, "query", return_value=value):
            self.assertEqual(FIXTURE.info(0), value)
        for field, invalid in (("unit", "TEST"), ("height", True), ("consensus_certificate", True), ("app_hash", "bad")):
            with patch.object(FIXTURE, "query", return_value={**value, field: invalid}), self.assertRaises(FIXTURE.TrialFailure):
                FIXTURE.info(0)

    def test_actual_small_child_output_limit_and_nonzero_are_closed(self):
        self.assertEqual(FIXTURE.checked([sys.executable, "-c", "print('okay')"]), b"okay\n")
        with self.assertRaisesRegex(FIXTURE.TrialFailure, "command_failed"):
            FIXTURE.checked([sys.executable, "-c", "import sys; print('private detail',file=sys.stderr); sys.exit(9)"])
        with self.assertRaisesRegex(FIXTURE.TrialFailure, "command_output_limit"):
            FIXTURE.checked([sys.executable, "-c", "import sys; sys.stdout.write('x'*262145)"])

    def test_actual_inert_child_timeout_is_reaped(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            FIXTURE.checked([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)

    def test_trial_scope_does_not_claim_byzantine_or_real_money(self):
        plan = FIXTURE.plan()
        self.assertFalse(plan["execute_default"])
        self.assertEqual(plan["validators"], 4)
        self.assertIn("Byzantine equivocation", plan["does_not_prove"])
        self.assertIn("real money or securities", plan["does_not_prove"])

    def test_retry_parser_requires_new_blocks_and_matching_execution_digests(self):
        trial = FIXTURE.Trial(argparse.Namespace(work="/var/tmp/inert-not-created"))
        commands = [b"inert reserve parser bytes", b"inert commit parser bytes"]
        trial.wait = lambda predicate: predicate()
        def fake_rpc(_node, method, params=None):
            if method == "status":
                return {"sync_info": {"latest_block_height": "12"}}
            self.assertIn(method, ("block", "block_results"))
            height = int(params["height"])
            self.assertGreater(height, 10)
            command = commands[height - 11]
            if method == "block":
                return {"block": {"header": {"height": str(height)},
                                  "data": {"txs": [base64.b64encode(command).decode()]}}}
            return {"height": str(height), "txs_results": [
                {"code": 0, "data": base64.b64encode(hashlib.sha256(command).digest()).decode()}]}
        with patch.object(FIXTURE, "rpc", side_effect=fake_rpc):
            self.assertEqual(trial.committed_retries_after(commands, 10), [11, 12])
            self.assertFalse(trial.committed_retries_after(commands, 12))
        for wrong in ({"code": 7, "data": ""}, {"code": 0, "data": base64.b64encode(b"wrong").decode()}):
            def bad_rpc(node, method, params=None):
                value = fake_rpc(node, method, params)
                if method == "block_results":
                    value["txs_results"] = [wrong]
                return value
            with patch.object(FIXTURE, "rpc", side_effect=bad_rpc), self.assertRaises(FIXTURE.TrialFailure):
                trial.committed_retries_after(commands, 10)

    def test_reopened_receipts_compare_every_node_not_only_balance(self):
        trial = FIXTURE.Trial(argparse.Namespace(work="/var/tmp/inert-not-created"))
        receipts = [{"operation_id": "a" * 64, "sequence": 1}, {"operation_id": "b" * 64, "sequence": 2}]
        def query(node, path, operation):
            self.assertEqual(path, "/test/operation")
            return next(receipt for receipt in receipts if receipt["operation_id"] == operation.hex())
        with patch.object(FIXTURE, "query", side_effect=query) as probe:
            self.assertTrue(trial.same_receipts(receipts))
            self.assertEqual(probe.call_count, 8)
        def changed(node, path, operation):
            value = query(node, path, operation)
            return {**value, "sequence": 999} if node == 3 else value
        with patch.object(FIXTURE, "query", side_effect=changed):
            self.assertFalse(trial.same_receipts(receipts))

    def test_guest_toolchain_remains_pinned_and_resource_bounded(self):
        shell = SOURCE.with_name("transaction-abci-vm-guest.sh").read_text()
        for expected in (FIXTURE.COMET_COMMIT, FIXTURE.GO_SHA256, FIXTURE.GO_LICENSE_SHA256,
                         "GOTOOLCHAIN=local", "-mod=readonly", "MemoryMax=3G", "MemoryMax=2G",
                         "MemorySwapMax=0", "RuntimeMaxSec=1300", "RuntimeMaxSec=600",
                         "sha256sum --check --strict", "git diff --exit-code -- go.mod go.sum"):
            self.assertIn(expected, shell)
        self.assertNotIn("curl |", shell)
        self.assertNotIn("go install", shell)


if __name__ == "__main__":
    unittest.main()
