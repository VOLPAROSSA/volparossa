#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert contracts only: no native executable, namespace, daemon or VM is run."""
import copy
import ast
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
CHECK = runpy.run_path(str(HERE / "private-storage-deposit-sequence-smoke.py"))
OLD = runpy.run_path(str(HERE / "test-private-storage-fragments-smoke.py"))
WIRING = runpy.run_path(str(HERE / "test-private-storage-fragments-wiring.py"))
KEYS = [str(i) * 64 for i in (1, 2, 3)]


def diagnostic(index, operation="reserve"):
    return dict(version=9, omitted_failures=0, failures=[dict(fragment_index=None, copy_index=index,
        operation=operation, stage="agent_ready", category="agent_rejected", agent_code="CONTENT_UNAVAILABLE",
        agent_detail=dict(stage="tls_handshake", deadline_scope="none", tls_failure="handshake_deadline",
            stream_failure=None, challenge=None, flow_acquire=None), agent_outcome=None)])


def completed():
    return dict(success=True, completed_deposits=10, attempted_deposits=10,
        target_ordinal=10, target_provider="B", target_reserve_nominal_flow=28,
        target_reserve_receipt_confirmed=True, target_deposit_committed=True,
        failure=None, owner_verified_committed_receipts=10, deleted_copies=10,
        unknown_reservation=False, remote_cleanup_complete=True, cli_children_joined=True)


def evidence_fixture():
    previous = OLD["fixture"]()
    selected = previous["network"]["finish"]["selected_route"]
    selected["exact_selected_exit"] = previous["expected_peers"]["exit"]
    for index, path in enumerate(selected["paths"]):
        path["path_id"] = f"fixture-path-{index}"
    previous["layout"]["route_scope"] = dict(exit_peer_id=selected["exact_selected_exit"],
        paths=[{key: path[key] for key in ("path_id", "relay_peer_id")} for path in selected["paths"]])
    previous["network"]["finish"]["gates"]["exit_mptcp_tls_completed"] = 40
    return dict(success=True, scope=CHECK["SCOPE"].copy(), sequence=completed(),
        prepare=dict(success=True, order=[CHECK["LABELS"][p] for p in CHECK["ORDER"]],
            lengths=list(CHECK["LENGTHS"]), owner_distinct_from_providers=True, owner_secrets_exported=False,
            provider_payload_limits=list(CHECK["TOTALS"]), provider_lease_limits=[4, 4, 2]),
        private_cleanup=dict(owner_private_files_removed=True, owner_directory_removed=True),
        deleted_usage=[dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
        isolation=previous["isolation"], layout=previous["layout"],
        expected_peers=previous["expected_peers"], network=previous["network"]["finish"])


def write_evidence_fixture(work):
    value = evidence_fixture()
    prefix = CHECK["PREFIX"]
    files = {f"{prefix}-{name}.json": value[name] for name in
        ("prepare", "sequence", "private_cleanup", "isolation", "layout", "deleted_usage")}
    files.update({"a01-expected-peers.json": value["expected_peers"],
        f"{prefix}-live-selection.json": value["network"]["selected_route"],
        f"content-provider-adaptive-{prefix}-control.json": value["network"]["control_privacy"],
        f"{prefix}-gates.json": value["network"]["gates"]})
    files.update({f"{prefix}-privacy-{role}.json": value["network"]["privacy"][role]
        for role in CHECK["FRAG"]["ROLES"]})
    for name, content in files.items():
        (work / name).write_text(json.dumps(content), encoding="ascii")
    return value


class DepositSequence(unittest.TestCase):
    def fake_cli(self, root, failure=None, reserved=False, timeout_operation=None):
        calls = []
        def invoke(binary, socket, args, raw=False, expected=0, failure_observer=None):
            self.assertEqual(binary, "inert-fixture-cli")
            self.assertEqual(expected, 0)
            calls.append(args)
            if args[0] == "init":
                CHECK["create"](root / "identity.key", b"inert test identity, not a real key")
                return None
            if args[:2] == ["content", "recipient-key"]:
                return dict(identity_public_key_hex="9" * 64)
            if args[2] == "grant":
                CHECK["create"](Path(args[args.index("--output") + 1]), b"inert grant")
                return dict(grant_written=True, max_payload_bytes=args[args.index("--max-payload-bytes") + 1],
                    max_leases=args[args.index("--max-leases") + 1], reserved_bytes=0, network_contribution_credit=False)
            operation = args[3] if args[2] == "--tls-close-diagnostics-v9" else args[2]
            self.assertIn(operation, ("create", "deposit", "delete"))
            state = Path(args[args.index("--state") + 1])
            pair = int(state.name.split("-")[1])
            length = CHECK["LENGTHS"][pair * 2]
            providers = [KEYS[p] for p in CHECK["ORDER"][pair * 2:pair * 2 + 2]]
            if operation == "create":
                self.assertEqual([args[i + 1] for i, a in enumerate(args) if a == "--provider-key"], providers)
                state.mkdir(mode=0o700)
                CHECK["create"](state / "replicas.json", b"{}")
                for local in range(2):
                    index = pair * 2 + local
                    directory = state / f"copy-{local}"
                    directory.mkdir(mode=0o700)
                    value = dict(ciphertext_bytes=length, sha256=list(hashlib.sha256(CHECK["data"](length, pair)).digest()),
                        lease=None, last_stored_bytes=0, last_state=None)
                    CHECK["create"](directory / "archive.json", json.dumps(value).encode())
                return dict(logical_ciphertext_bytes=length, physical_payload_charge_upper_bound=0,
                    copies=[dict(provider_key=key) for key in providers])
            if operation == "deposit":
                self.assertNotIn("--resume", args)
                self.assertIn("--tls-close-diagnostics-v9", args)
                self.assertLess(length, 262144)
                self.assertEqual(Path(args[args.index("--input") + 1]).read_bytes(), CHECK["data"](length, pair))
                for local in range(2):
                    index = pair * 2 + local
                    path = state / f"copy-{local}" / "archive.json"
                    value = json.loads(path.read_text())
                    value.update(lease=None if index == failure and not reserved else f"inert-lease-{index}",
                        last_stored_bytes=0 if index == failure else length,
                        last_state=(1 if reserved else None) if index == failure else 3)
                    path.write_text(json.dumps(value))
            else:
                key = args[args.index("--provider-key") + 1]
                local = providers.index(key)
                path = state / f"copy-{local}" / "archive.json"
                value = json.loads(path.read_text())
                self.assertIsNotNone(value["lease"])
                value.update(last_state=5, last_stored_bytes=0)
                path.write_text(json.dumps(value))
            copies = []
            for local, key in enumerate(providers):
                value = json.loads((state / f"copy-{local}" / "archive.json").read_text())
                copies.append(dict(provider_key=key,
                    charge={3: "committed", 5: "deleted"}.get(value["last_state"], "uncertain")))
            report = dict(operation=f"private_storage_replicas_{operation}", logical_ciphertext_bytes=length,
                distinct_provider_identities=2, copies=copies, operation_complete=True, read_consumes_archive=False,
                expired_copies_remain_charged=True, metadata_overhead_measured=False, independent_failure_domains_proven=False,
                network_contribution_credit=False, automatic_repair=False, committed_payload_bytes=2 * length,
                physical_payload_charge_upper_bound=2 * length,
                deposit_diagnostics=dict(version=9, omitted_failures=0, failures=[]))
            if operation == "delete":
                report["deleted_provider_key"] = args[args.index("--provider-key") + 1]
            if operation == "deposit" and failure in (pair * 2, pair * 2 + 1):
                report.update(operation_complete=False, deposit_diagnostics=diagnostic(failure % 2, "append" if reserved else "reserve"))
                failure_observer(1, json.dumps(report).encode(), b"PRIVATE-STDERR-MUST-NOT-ESCAPE")
                if timeout_operation == operation:
                    raise subprocess.TimeoutExpired("private command must not be exported", 5)
                raise ValueError("private replica CLI operation failed")
            if timeout_operation == operation and failure is None:
                raise subprocess.TimeoutExpired("private command must not be exported", 5)
            return report
        return invoke, calls

    def sequence(self, failure=None, reserved=False, timeout_operation=None):
        with tempfile.TemporaryDirectory(prefix="vp-sequence-contract-") as temporary:
            root = Path(temporary) / "private-storage-user"
            root.mkdir(mode=0o700)
            invoke, calls = self.fake_cli(root, failure, reserved, timeout_operation)
            with mock.patch.dict(CHECK["run"].__globals__, invoke=invoke):
                prepared = CHECK["prepare"](root, "inert-fixture-cli", "client", ["A", "B", "C"], KEYS)
                result = CHECK["run"](root, "inert-fixture-cli", "client", KEYS)
            self.assertEqual(prepared["order"], list("ABBCCAABAB"))
            self.assertEqual(prepared["provider_payload_limits"], [799146, 799146, 399574])
            CHECK["cleanup"](str(root))
            self.assertFalse(root.exists())
            return result, calls

    def test_exact_short_sequence_real_command_contract_and_cleanup(self):
        result, calls = self.sequence()
        CHECK["validate_result"](result)
        operations = [args[3] if args[2].startswith("--") else args[2]
                      for args in calls if args[:2] == ["storage", "replicas"]]
        self.assertEqual(operations, ["create"] * 5 + ["deposit"] * 5 + ["delete"] * 10)
        self.assertEqual(9 * 3 + 1, result["target_reserve_nominal_flow"])
        self.assertEqual(len({hashlib.sha256(CHECK["data"](CHECK["LENGTHS"][2 * p], p)).digest() for p in range(5)}), 5)

    def test_tenth_reserve_unknown_does_not_become_false_cleanup_or_tls_claim(self):
        result, _ = self.sequence(failure=9)
        self.assertFalse(result["success"])
        self.assertEqual(result["completed_deposits"], 9)
        self.assertEqual(result["deleted_copies"], 9)
        self.assertEqual(result["failure"], dict(pair_ordinal=5, diagnostics_state="observed", diagnostics=diagnostic(1)))
        self.assertFalse(result["remote_cleanup_complete"])
        self.assertTrue(result["unknown_reservation"])
        self.assertNotIn("PRIVATE-STDERR", json.dumps(result))
        self.assertIsNone(result["failure"]["diagnostics"]["failures"][0]["fragment_index"])
        with self.assertRaises(ValueError):
            CHECK["validate_result"](result)

    def test_after_reserve_failure_still_deletes_the_confirmed_tenth_lease(self):
        result, _ = self.sequence(failure=9, reserved=True)
        self.assertFalse(result["success"])
        self.assertTrue(result["target_reserve_receipt_confirmed"])
        self.assertTrue(result["remote_cleanup_complete"])
        self.assertEqual(result["deleted_copies"], 10)
        self.assertEqual(result["failure"]["diagnostics"]["failures"][0]["operation"], "append")

    def test_ambiguous_subprocess_join_is_not_reported_as_joined(self):
        result, _ = self.sequence(failure=9, reserved=True, timeout_operation="deposit")
        self.assertFalse(result["success"])
        self.assertFalse(result["cli_children_joined"])
        self.assertTrue(result["remote_cleanup_complete"])
        self.assertEqual(result["failure"], dict(pair_ordinal=5, diagnostics_state="observed",
            diagnostics=diagnostic(1, "append")))
        self.assertNotIn("private command", json.dumps(result))
        result, _ = self.sequence(timeout_operation="delete")
        self.assertFalse(result["success"])
        self.assertFalse(result["cli_children_joined"])
        self.assertFalse(result["remote_cleanup_complete"])
        self.assertEqual(result["completed_deposits"], 10)
        self.assertIsNone(result["failure"])

    def test_reused_validator_is_ast_identical_and_replica_adapter_is_closed(self):
        def nodes(path):
            result = {}
            for node in ast.parse(path.read_text()).body:
                name = node.name if isinstance(node, ast.FunctionDef) else node.targets[0].id if (
                    isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)) else None
                if name:
                    result[name] = ast.dump(node, include_attributes=False)
            return result
        original = nodes(HERE / "storage-consumer-maintenance-smoke.py")
        adapted = nodes(HERE / "private-storage-deposit-sequence-smoke.py")
        for name in ("count", "keys", "OUTCOME_PHASES", "FLOW_HELPER_REASONS", "FLOW_PAIRS",
                     "validate_flow_acquire", "validate_agent_outcome", "validate_deposit_diagnostics"):
            self.assertEqual(original[name], adapted[name], name)
        for index in (0, 1):
            value = diagnostic(index)
            self.assertEqual(CHECK["closed_diagnostic"](value), value)
            self.assertIsNone(value["failures"][0]["fragment_index"])
        for mutation in (
            lambda v: v.update(version=8), lambda v: v.update(secret="must reject"),
            lambda v: v["failures"][0].update(copy_index=2),
            lambda v: v["failures"][0].update(fragment_index=0),
            lambda v: v["failures"][0]["agent_detail"].update(arbitrary_error="private"),
            lambda v: v["failures"].append(copy.deepcopy(v["failures"][0])),
        ):
            value = diagnostic(1)
            mutation(value)
            with self.assertRaises((ValueError, KeyError)):
                CHECK["closed_diagnostic"](value)
        raw = b'{"operation":"private_storage_replicas_deposit","operation":"private_storage_replicas_deposit"}'
        with self.assertRaises(ValueError):
            CHECK["failure_report"](raw, 4)

    def test_cleanup_checks_entire_tree_before_deleting_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="vp-sequence-cleanup-") as temporary:
            root = Path(temporary) / "private-storage-user"
            root.mkdir(mode=0o700)
            CHECK["create"](root / "identity.key", b"private")
            (root / "grant-0.bin").symlink_to(root / "identity.key")
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(root))
            self.assertEqual((root / "identity.key").read_bytes(), b"private")
            (root / "grant-0.bin").unlink()
            CHECK["cleanup"](str(root))
            CHECK["cleanup"](str(root))

    def test_interrupted_prepare_staging_cleanup_is_bounded_and_owned(self):
        with tempfile.TemporaryDirectory(prefix="vp-sequence-staging-") as temporary:
            root = Path(temporary) / "private-storage-user"
            root.mkdir(mode=0o700)
            CHECK["create"](root / ".tmpKey123", b"interrupted private key write")
            staged = root / ".replicas-Stage123"
            staged.mkdir(mode=0o700)
            CHECK["create"](staged / ".tmpManifest1", b"partial manifest")
            directory = staged / "copy-0"
            directory.mkdir(mode=0o700)
            CHECK["create"](directory / "archive.json", b"partial archive")
            CHECK["create"](directory / ".tmpJournal1", b"partial journal")
            bad = staged / "copy-1"
            bad.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(root))
            self.assertTrue((root / ".tmpKey123").exists())
            bad.chmod(0o700)
            extra = root / ".replicas-Extra123"
            extra.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                CHECK["cleanup"](str(root))
            self.assertTrue((directory / "archive.json").exists())
            extra.rmdir()
            CHECK["cleanup"](str(root))
            self.assertFalse(root.exists())
            CHECK["cleanup"](str(root))

    def test_evidence_rejects_route_changes_missing_receipts_bypass_and_partial_cleanup(self):
        value = evidence_fixture()
        CHECK["validate_evidence"](value)
        mutations = [
            lambda v: v["scope"].update(full_consumer_acceptance=True),
            lambda v: v["sequence"].update(owner_verified_committed_receipts=9),
            lambda v: v["sequence"].update(target_reserve_receipt_confirmed=False),
            lambda v: v["network"]["gates"].update(exit_mptcp_tls_completed=39),
            lambda v: v["layout"]["route_scope"]["paths"][0].update(path_id="replaced"),
            lambda v: v["network"]["privacy"]["client"].update(direct_client_exit_packets=1),
            lambda v: v["deleted_usage"][0].update(leases=1),
        ]
        for mutation in mutations:
            bad = copy.deepcopy(value)
            mutation(bad)
            with self.assertRaises((ValueError, KeyError)):
                CHECK["validate_evidence"](bad)

    def test_evidence_assembles_real_sidecar_files_with_three_provider_usage_array(self):
        with tempfile.TemporaryDirectory(prefix="vp-sequence-evidence-") as temporary:
            work = Path(temporary)
            expected = write_evidence_fixture(work)
            self.assertEqual(CHECK["evidence"](work), expected)
            usage = work / f"{CHECK['PREFIX']}-deleted_usage.json"
            # Other evidence must remain object-shaped; only usage uses the
            # existing three-provider array reader, not a relaxed shared reader.
            with self.assertRaisesRegex(ValueError, "evidence must be an object"):
                CHECK["read"](usage)

    def test_evidence_rejects_malformed_and_nonzero_usage_sidecars(self):
        zero = dict(reserved_bytes=0, committed_bytes=0, leases=0)
        invalid = [None, zero, [], [zero] * 2, [zero] * 4, [zero, zero, None],
            [zero, zero, dict(reserved_bytes=0, committed_bytes=0)],
            [zero, zero, dict(zero, extra=0)]]
        for counter in zero:
            for count in (1, -1, True, 0.0, "0", 2**64):
                invalid.append([zero, zero, dict(zero, **{counter: count})])
        with tempfile.TemporaryDirectory(prefix="vp-sequence-usage-") as temporary:
            work = Path(temporary)
            write_evidence_fixture(work)
            usage = work / f"{CHECK['PREFIX']}-deleted_usage.json"
            for value in invalid:
                with self.subTest(value=value):
                    usage.write_text(json.dumps(value), encoding="ascii")
                    with self.assertRaises(ValueError):
                        CHECK["evidence"](work)
            usage.write_text("[malformed JSON", encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["evidence"](work)

    def test_evidence_usage_file_bound_and_regular_file_checks(self):
        with tempfile.TemporaryDirectory(prefix="vp-sequence-usage-file-") as temporary:
            work = Path(temporary)
            expected = write_evidence_fixture(work)
            usage = work / f"{CHECK['PREFIX']}-deleted_usage.json"
            text = usage.read_text(encoding="ascii")
            usage.write_text(text.ljust(2048), encoding="ascii")
            self.assertEqual(CHECK["evidence"](work), expected)
            usage.write_text(text.ljust(2049), encoding="ascii")
            with self.assertRaises(ValueError):
                CHECK["evidence"](work)
            usage.unlink()
            with self.assertRaises(ValueError):
                CHECK["evidence"](work)
            usage.mkdir()
            with self.assertRaises(ValueError):
                CHECK["evidence"](work)
            usage.rmdir()
            target = work / "inert-usage-target.json"
            target.write_text(text, encoding="ascii")
            usage.symlink_to(target)
            with self.assertRaises(ValueError):
                CHECK["evidence"](work)
            self.assertEqual(target.read_text(encoding="ascii"), text)

    def test_preview_selection_does_not_run_other_storage_lifecycles(self):
        scenario = "private-storage-deposit-sequence"
        for script in ("kvm-alpha-topology.sh", "run-alpha-topology-vm.sh"):
            for first, last in ((scenario, "private-storage-peer"), ("private-storage-maintenance", scenario)):
                result = subprocess.run(["sh", str(HERE / script), "--preview", "--scenario", first,
                    "--scenario", last], capture_output=True, text=True, check=True, timeout=10)
                self.assertIn("PREVIEW ONLY", result.stdout)
                self.assertIn(last, result.stdout.lower())
                self.assertNotIn(first, result.stdout.lower())

    def test_optional_dispatch_defaults_off_and_preserves_existing_lifecycles(self):
        guest = (HERE / "kvm-alpha-topology.sh").read_text()
        start = guest.index('if [ "$private_storage_maintenance" = yes ]; then\n    private_storage_maintenance_run')
        dispatch = guest[start:guest.index('\nif [ "$private_storage_handoff"', start)]
        script = r'''
set -eu
private_storage_maintenance_run() { printf '%s\n' maintenance; }
private_storage_sequence_run() { printf '%s\n' sequence; }
private_storage_fragments_run() { printf '%s\n' fragments; }
''' + dispatch + "\nprintf '%s\\n' fallthrough\n"
        for sequence in (None, "no", "yes"):
            for maintenance in ("no", "yes"):
                for fragments in ("no", "yes"):
                    with self.subTest(sequence=sequence, maintenance=maintenance, fragments=fragments):
                        environment = dict(PATH=os.defpath, private_storage_maintenance=maintenance,
                            private_storage_fragments=fragments)
                        if sequence is not None:
                            environment["private_storage_deposit_sequence"] = sequence
                        result = subprocess.run(["sh", "-c", script], env=environment,
                            capture_output=True, text=True, check=True, timeout=5)
                        expected = ("maintenance" if maintenance == "yes" else "sequence" if sequence == "yes"
                            else "fragments" if fragments == "yes" else "fallthrough")
                        self.assertEqual(result.stdout, expected + "\n")
                        self.assertEqual(result.stderr, "")

    def test_closed_export_and_explicit_scenario_source_gate(self):
        names = set(CHECK["EXPORT_NAMES"])
        diagnostics = WIRING["diagnostics"]()
        self.assertEqual(names, diagnostics["SEQUENCE_NAMES"])
        self.assertEqual(len(names), len(CHECK["EXPORT_NAMES"]))
        self.assertTrue(all("/" not in name and name.endswith(".json") for name in names))
        self.assertFalse(any(token in name for name in names for token in ("key", "grant", "journal", ".bin")))
        shell = (HERE / "private-storage-deposit-sequence-smoke.sh").read_text()
        self.assertEqual(shell.count("benchmark_select_route "), 1)
        for forbidden in ("private_storage_fragments_run", "private_storage_maintenance_run", "gpg", "--resume"):
            self.assertNotIn(forbidden, shell)
        guest = (HERE / "kvm-alpha-topology.sh").read_text()
        self.assertIn("private-storage-deposit-sequence) scenario=content-custody; private_storage_deposit_sequence=yes;", guest)
        self.assertLess(guest.index("    private_storage_sequence_run\n"), guest.index("    content_custody_run\n"))
        workflow = (HERE.parents[1] / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("refs/heads/test/storage-real-route-deposit-sequence", workflow)
        self.assertIn("3ab2f6cb9476623234191a7b416934960538ef9d", workflow)
        self.assertIn("set(changed) == allowed", workflow)
        self.assertIn("private-storage-deposit-sequence-smoke.py report", workflow)
        self.assertIn("env.VOLPAROSSA_ALPHA_SCENARIO != 'private-storage-deposit-sequence'", workflow)


def selection_diagnostic():
    return dict(schema_version=1, stage='connect', reason='CONNECT_REJECTED',
        last_connect_reason='NO_ELIGIBLE_PATHS', connect_exit_status=1,
        attempts=1, retries=0, redraws=0, path_polls=0, path_status=None)


class InitialRouteSelection(unittest.TestCase):
    def test_first_selection_projection_is_frozen_before_later_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / f"{CHECK['PREFIX']}-route-diagnostic.json"
            initial = selection_diagnostic()
            source.write_text(json.dumps(initial))
            observed = CHECK['initial_route_selection'](work, capture=True)
            self.assertEqual(observed, dict(schema_version=1, status='observed', route=initial))
            frozen = work / CHECK['INITIAL_ROUTE_SELECTION']
            self.assertEqual(frozen.stat().st_mode & 0o777, 0o600)
            source.write_text(json.dumps(dict(initial, stage='complete', reason='SELECTED',
                last_connect_reason='CONNECTED', connect_exit_status=0, path_status=0)))
            self.assertEqual(CHECK['initial_route_selection'](work, capture=True), observed)
            self.assertEqual(CHECK['initial_route_selection'](work), observed)
            self.assertNotIn(frozen.name, CHECK['EXPORT_NAMES'])

    def test_absent_first_observation_cannot_be_replaced_by_later_success(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            missing = CHECK['initial_route_selection'](work, capture=True)
            self.assertEqual(missing, dict(schema_version=1, status='missing', route=None))
            (work / f"{CHECK['PREFIX']}-route-diagnostic.json").write_text(json.dumps(selection_diagnostic()))
            self.assertEqual(CHECK['initial_route_selection'](work, capture=True), missing)

    def test_missing_invalid_and_oversized_private_input_never_exports_untyped_data(self):
        bad_inputs = [b'PRIVATE URL=https://private.example token=secret',
            json.dumps(dict(selection_diagnostic(), private='secret')).encode(),
            json.dumps(dict(selection_diagnostic(), reason='PRIVATE secret')).encode(),
            json.dumps(dict(selection_diagnostic(), attempts=True)).encode(),
            json.dumps(dict(selection_diagnostic(), path_status=256)).encode(),
            json.dumps(dict(selection_diagnostic(), retries=1)).encode(),
            b' ' * (CHECK['ROUTE_DIAGNOSTIC_LIMIT'] + 1), b'[' * 2000 + b']' * 2000]
        for raw in bad_inputs:
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / f"{CHECK['PREFIX']}-route-diagnostic.json").write_bytes(raw)
                projection = CHECK['initial_route_selection'](work, capture=True)
                self.assertEqual(projection, dict(schema_version=1, status='invalid', route=None))
                encoded = json.dumps(projection)
                self.assertNotIn('secret', encoded)
                self.assertNotIn('PRIVATE', encoded)
                self.assertNotIn('private.example', encoded)
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(CHECK['initial_route_selection'](directory),
                dict(schema_version=1, status='missing', route=None))

    def test_symlink_or_nonregular_diagnostics_are_not_followed_or_read(self):
        for kind in ('symlink', 'directory', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                source = work / f"{CHECK['PREFIX']}-route-diagnostic.json"
                if kind == 'symlink':
                    private = work / 'private-file'
                    private.write_text('PRIVATE-MUST-NOT-EXPORT')
                    source.symlink_to(private)
                elif kind == 'directory':
                    source.mkdir()
                else:
                    os.mkfifo(source)
                self.assertEqual(CHECK['initial_route_selection'](work, capture=True),
                    dict(schema_version=1, status='invalid', route=None))

    def test_metadata_status_is_closed_and_does_not_replace_report_acceptance(self):
        valid = dict(schema_version=1, status='observed', route=selection_diagnostic())
        CHECK['validate_initial_route_selection'](valid)
        for bad in (dict(valid, extra='PRIVATE'), dict(valid, status='guessed'),
                dict(valid, schema_version=True), dict(valid, status='missing')):
            with self.assertRaises(ValueError):
                CHECK['validate_initial_route_selection'](bad)
        for status in ('observed', 'missing', 'invalid'):
            value = dict(schema_version=1, status=status,
                route=selection_diagnostic() if status == 'observed' else None)
            CHECK['validate_initial_route_selection'](value)
            # Valid diagnostic metadata cannot make a failed storage report acceptable.
            report = dict(source_revision='a' * 40, schema_version=1,
                report_kind=f"volparossa-{CHECK['PREFIX']}", success=False,
                runner_exit_status=1, phase=f"{CHECK['PREFIX']}-prepare",
                observed_blocker='SEQUENCE_ROUTE_UNAVAILABLE', storage=None,
                cleanup=dict(complete=True, remaining_owned_objects=0),
                host_state=dict(unchanged=True), initial_route_selection=value)
            with self.assertRaises(ValueError):
                CHECK['validate_report'](report, 'a' * 40)


if __name__ == "__main__":
    unittest.main()
