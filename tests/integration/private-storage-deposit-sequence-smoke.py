#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Core-only real-route deposit prefix; not application or full Storage acceptance.

The opaque public fixture is not encrypted user data. Production CLI commands
own keys, verify signed receipts and retain journals; this driver never creates
transport sockets or substitutes its own storage protocol implementation.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FRAG = runpy.run_path(str(HERE / "private-storage-fragments-smoke.py"))
PEER = runpy.run_path(str(HERE / "private-storage-peer-smoke.py"))
require, read = PEER["require"], PEER["read"]
private_root, private_file, create = PEER["private_root"], PEER["private_file"], PEER["create"]
invoke, unlock = FRAG["BASE"]["invoke"], PEER["unlock"]
PREFIX = "private-storage-deposit-sequence"
NODES = ("relay4", "relay5", "relay3")
ORDER = (0, 1, 1, 2, 2, 0, 0, 1, 0, 1)
LENGTHS = (199787,) * 6 + (199785, 199785, 199787, 199787)
LABELS = ("A", "B", "C")
TOTALS = tuple(sum(n for i, n in enumerate(LENGTHS) if ORDER[i] == p) for p in range(3))
SCOPE = dict(core_only=True, synthetic_opaque_bytes=True, fresh_route=True,
             full_consumer_acceptance=False, original_failure_reproduced=False,
             encryption_proven=False, maintenance_repair_proven=False)
SUMMARY = ("smoke", "evidence", "prepare", "sequence", "private_cleanup", "isolation",
           "layout", "deleted_usage", "live-selection", "gates")
EXPORT_NAMES = ("a01-expected-peers.json", *(f"{PREFIX}-{n}.json" for n in SUMMARY),
                f"content-provider-adaptive-{PREFIX}-control.json",
                *(f"{PREFIX}-privacy-{role}.json" for role in FRAG["ROLES"]))


# These validator bodies/constants are copied verbatim from the reviewed consumer
# fixture; inert tests require AST equivalence. No application provisioner is imported.
def count(value, low, high):
    return type(value) is int and low <= value <= high

def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'closed_fields')

OUTCOME_PHASES = ('ready_write', 'local_request_read', 'local_request_verify', 'local_payload_read',
    'local_payload_verify', 'admission', 'remote_request_verify', 'remote_request_write', 'remote_payload_write',
    'remote_receipt_read', 'remote_receipt_verify', 'remote_payload_read', 'remote_payload_verify',
    'local_receipt_write', 'local_payload_write', 'provider_tls_close', 'transport_tls_close',
    'final_route_check', 'final_grant_check', 'final_lifetime_check', 'terminal_write')

FLOW_HELPER_REASONS = {'helper_kernel', 'helper_capacity', 'helper_unavailable', 'helper_not_found',
    'helper_cleanup_incomplete', 'helper_other_rejection', 'helper_timeout', 'helper_io',
    'helper_validation', 'helper_authority', 'helper_correlation', 'helper_runtime_changed'}

FLOW_PAIRS = {'source_port': {'entropy'},
    'retirement_drain': {'unconfirmed', 'io'} | (FLOW_HELPER_REASONS - {'helper_not_found'}),
    'material': {'metadata', 'topology'},
    'slot_reservation': {'unconfirmed', 'local_capacity', 'local_unavailable'},
    'helper_acquire': FLOW_HELPER_REASONS, 'descriptor_clone': {'io'},
    'descriptor_adoption': {'metadata', 'io'}, 'flow_metadata': {'metadata'}}

def validate_flow_acquire(value):
    keys(value, ('rounds', 'first', 'last'))
    require(count(value['rounds'], 1, 8), 'deposit_diagnostics')
    for endpoint in (value['first'], value['last']):
        keys(endpoint, ('stage', 'reason'))
        require(type(endpoint['stage']) is str and type(endpoint['reason']) is str
            and endpoint['reason'] in FLOW_PAIRS.get(endpoint['stage'], ()), 'deposit_diagnostics')
    require(value['rounds'] != 1 or value['first'] == value['last'], 'deposit_diagnostics')

def validate_agent_outcome(value, stage, version=4, operation=None):
    if value is None:
        return
    keys(value, ('status', 'detail', *(('append_timing',) if version in (7, 8, 9) else ()),
        *(('tls_close_failure',) if version == 9 else ())))
    require(stage in ('wire_receipt', 'agent_terminal', 'deadline')
        and value['status'] in ('observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout'), 'deposit_diagnostics')
    if value['status'] != 'observed':
        require(value['detail'] is None, 'deposit_diagnostics')
        if version in (7, 8, 9):
            require(value['append_timing'] is None, 'deposit_diagnostics')
        if version == 9:
            require(value['tls_close_failure'] is None, 'deposit_diagnostics')
        return
    detail = value['detail']
    keys(detail, ('phase', 'category', 'deadline_scope'))
    require(detail['phase'] in OUTCOME_PHASES
        and detail['category'] in ('io', 'auth', 'invalid', 'busy', 'store', 'expired', 'entropy', 'timeout', 'policy', 'unavailable', 'cancelled')
        and detail['deadline_scope'] in ('none', 'operation', 'exchange', 'bridge', 'remote_wire')
        and ((detail['category'] == 'timeout') == (detail['deadline_scope'] != 'none'))
        and (detail['deadline_scope'] != 'bridge' or detail['phase'] in OUTCOME_PHASES[1:15])
        and (detail['deadline_scope'] != 'remote_wire' or detail['phase'] in OUTCOME_PHASES[6:13]), 'deposit_diagnostics')
    if version in (7, 8, 9) and value['append_timing'] is not None:
        timing = value['append_timing']
        keys(timing, ('before_payload', 'in_payload_write_flush', 'in_receipt_read'))
        buckets = ('under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
            '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s')
        require(operation == 'append' and detail['phase'] in ('remote_payload_write', 'remote_receipt_read')
            and timing['before_payload'] in buckets and timing['in_payload_write_flush'] in buckets
            and (timing['in_receipt_read'] is None if detail['phase'] == 'remote_payload_write'
                else timing['in_receipt_read'] in buckets), 'deposit_diagnostics')
    if version == 9:
        require(value['tls_close_failure'] is None or (
            value['tls_close_failure'] in ('shutdown_io', 'read_io', 'trailing_data', 'internal_deadline')
            and detail['phase'] == 'transport_tls_close' and detail['category'] == 'unavailable'
            and detail['deadline_scope'] == 'none' and value['append_timing'] is None), 'deposit_diagnostics')

def validate_deposit_diagnostics(value, version=1):
    require(type(version) is int and version in (1, 2, 3, 4, 5, 6, 7, 8, 9), 'deposit_diagnostics')
    keys(value, ('version', 'failures', 'omitted_failures'))
    require(type(value['version']) is int and value['version'] == version
        and type(value['omitted_failures']) is int and value['omitted_failures'] == 0
        and type(value['failures']) is list and len(value['failures']) <= 8, 'deposit_diagnostics')
    seen = set()
    for failure in value['failures']:
        keys(failure, ('fragment_index', 'copy_index', 'operation', 'stage', 'category', 'agent_code',
            *(('agent_detail',) if version >= 2 else ()), *(('agent_outcome',) if version >= 4 else ())))
        require(count(failure['fragment_index'], 0, 3) and count(failure['copy_index'], 0, 1)
            and failure['operation'] in ('prepare', 'reserve', 'progress', 'append', 'finalize', 'renew', 'read_range', 'delete')
            and failure['stage'] in ('journal_open', 'authorization', 'agent_ready', 'challenge', 'signed_request',
                'wire_receipt', 'agent_terminal', 'accounting', 'local_input', 'receipt_validation', 'journal_save', 'deadline', 'unknown')
            and failure['category'] in ('io', 'timeout', 'protocol', 'agent_rejected', 'invalid', 'busy', 'store', 'unknown')
            and (failure['agent_code'] in ('CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY', 'unknown')
                if failure['category'] == 'agent_rejected' else failure['agent_code'] is None), 'deposit_diagnostics')
        if version >= 2 and failure['agent_detail'] is not None:
            detail = failure['agent_detail']
            keys(detail, ('stage', 'deadline_scope', *(('tls_failure',) if version >= 3 else ()),
                *(('stream_failure',) if version >= 5 else ()), *(('challenge',) if version >= 6 else ()),
                *(('flow_acquire',) if version >= 8 else ())))
            require(failure['stage'] == 'agent_ready' and failure['category'] == 'agent_rejected'
                and failure['agent_code'] in ('CONTENT_INVALID', 'CONTENT_UNAVAILABLE', 'CONTENT_BUSY', 'CONTENT_POLICY')
                and detail['stage'] in ('unobserved', 'route_connect', 'control_selection', 'provider_lookup',
                    'provider_cardinality', 'offer_validity', 'stream_open', 'tls_handshake', 'challenge')
                and detail['deadline_scope'] in ('none', 'operation', 'exchange')
                and (detail['stage'] != 'unobserved' or detail['deadline_scope'] == 'operation')
                and (detail['deadline_scope'] != 'exchange' or detail['stage'] in ('stream_open', 'tls_handshake', 'challenge'))
                and (detail['deadline_scope'] == 'none' or failure['agent_code'] == 'CONTENT_UNAVAILABLE'), 'deposit_diagnostics')
            if version >= 3:
                require(detail['tls_failure'] is None or (
                    detail['tls_failure'] in ('offer', 'configuration', 'handshake_deadline', 'authentication', 'tls_other', 'io')
                    and detail['stage'] == 'tls_handshake' and detail['deadline_scope'] == 'none'
                    and failure['agent_code'] == 'CONTENT_UNAVAILABLE'), 'deposit_diagnostics')
            if version >= 5:
                require(detail['stream_failure'] is None or (
                    detail['stream_failure'] in ('policy', 'route_state', 'route_material', 'flow_acquire',
                        'transport_certificate', 'transport_tls', 'initial_paths', 'open_tcp_write',
                        'subflow_readiness', 'stream_attachment')
                    and detail['stage'] == 'stream_open' and detail['deadline_scope'] == 'none'
                    and detail['tls_failure'] is None and failure['agent_code'] == 'CONTENT_UNAVAILABLE'),
                    'deposit_diagnostics')
            if version >= 6 and detail['challenge'] is not None:
                challenge = detail['challenge']
                keys(challenge, ('phase', 'before_challenge', 'in_challenge'))
                buckets = ('under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
                    '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s')
                require(challenge['phase'] in ('selector_write_flush', 'grant_write_flush', 'challenge_read_verify')
                    and challenge['before_challenge'] in buckets and challenge['in_challenge'] in buckets
                    and detail['stage'] == 'challenge' and detail['tls_failure'] is None
                    and detail['stream_failure'] is None and failure['agent_code'] == 'CONTENT_UNAVAILABLE',
                    'deposit_diagnostics')
            if version >= 8 and detail['flow_acquire'] is not None:
                validate_flow_acquire(detail['flow_acquire'])
                require(detail['stage'] == 'stream_open' and detail['deadline_scope'] == 'none'
                    and detail['stream_failure'] == 'flow_acquire' and detail['tls_failure'] is None
                    and detail['challenge'] is None and failure['agent_code'] == 'CONTENT_UNAVAILABLE',
                    'deposit_diagnostics')
        if version >= 4:
            validate_agent_outcome(failure['agent_outcome'], failure['stage'], version, failure['operation'])
        identity = (failure['fragment_index'], failure['copy_index'])
        require(identity not in seen, 'deposit_diagnostics')
        seen.add(identity)

def data(length, pair):
    require(type(pair) is int and 0 <= pair < 5, "invalid fixture pair")
    return (bytes((value + 37 * pair) % 256 for value in range(256)) * ((length + 255) // 256))[:length]


def existing(root, pair):
    return ["--state", root / f"set-{pair}", *unlock(root)]


def journal(root, index):
    path = root / f"set-{index // 2}" / f"copy-{index % 2}" / "archive.json"
    require(private_file(path).st_size <= 16384, "journal exceeds bound")
    value = json.loads(path.read_text())
    require(value["ciphertext_bytes"] == LENGTHS[index]
            and value["sha256"] == list(hashlib.sha256(data(LENGTHS[index], index // 2)).digest()),
            "journal geometry changed")
    return value


def prepare(root, binary, client, providers, keys):
    require(not list(root.iterdir()), "owner directory not empty")
    require(len(set(keys)) == 3 and all(re.fullmatch(r"[0-9a-f]{64}", key) for key in keys),
            "provider identities not distinct")
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner not in keys, "owner overlaps provider")
    for pair in range(5):
        create(root / f"input-{pair}.bin", data(LENGTHS[2 * pair], pair))
    for p, (provider, key) in enumerate(zip(providers, keys)):
        leases = ORDER.count(p)
        granted = invoke(binary, provider, ["storage", "peer", "grant", "--provider-key", key,
            "--owner-key", owner, "--max-payload-bytes", TOTALS[p], "--max-leases", leases,
            "--max-retention-seconds", 1800, "--lifetime-seconds", 1800,
            "--output", root / f"grant-{p}.bin"])
        require(granted["grant_written"] is True and granted["max_payload_bytes"] == TOTALS[p]
                and granted["max_leases"] == leases and granted["reserved_bytes"] == 0
                and granted["network_contribution_credit"] is False, "bounded grant missing")
    for pair in range(5):
        length = LENGTHS[2 * pair]
        p, q = ORDER[2 * pair:2 * pair + 2]
        created = invoke(binary, client, ["storage", "replicas", "create", *existing(root, pair),
            "--provider-key", keys[p], "--grant", root / f"grant-{p}.bin",
            "--provider-key", keys[q], "--grant", root / f"grant-{q}.bin",
            "--input", root / f"input-{pair}.bin", "--sha256", hashlib.sha256(data(length, pair)).hexdigest(),
            "--already-encrypted", "--lifetime-seconds", 900])
        require(created["physical_payload_charge_upper_bound"] == 0
                and created["logical_ciphertext_bytes"] == length
                and [c["provider_key"] for c in created["copies"]] == [keys[p], keys[q]],
                "replica preparation changed placement or charged storage")
    return dict(success=True, order=[LABELS[p] for p in ORDER], lengths=list(LENGTHS),
                owner_distinct_from_providers=True, owner_secrets_exported=False,
                provider_payload_limits=list(TOTALS), provider_lease_limits=[4, 4, 2])


def closed_diagnostic(value):
    require(type(value) is dict and type(value.get("failures")) is list, "invalid diagnostic")
    require(all(type(f) is dict and f.get("fragment_index", "missing") is None
                for f in value["failures"]), "replica diagnostic must not claim a fragment index")
    validation = copy.deepcopy(value)
    for failure in validation["failures"]:
        failure["fragment_index"] = 0
    # Only the private validation copy gets the consumer parser's fragment slot.
    # Export retains the original null and an independent fixed pair ordinal.
    validate_deposit_diagnostics(validation, 9)
    return copy.deepcopy(value)


def unique_json(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, "duplicate JSON key")
        value[name] = item
    return value


def failure_report(raw, pair):
    require(type(raw) is bytes and 0 < len(raw) <= 16384 and type(pair) is int and 0 <= pair < 5,
            "invalid diagnostic envelope")
    value = json.loads(raw, object_pairs_hook=unique_json)
    require(value["operation"] == "private_storage_replicas_deposit"
            and value["operation_complete"] is False, "wrong diagnostic operation")
    diagnostic = closed_diagnostic(value["deposit_diagnostics"])
    require(1 <= len(diagnostic["failures"]) <= 2, "missing copy failure")
    return dict(pair_ordinal=pair + 1, diagnostics_state="observed", diagnostics=diagnostic)


def valid_pair_receipt(value, operation, pair, provider_keys):
    require(value["operation"] == f"private_storage_replicas_{operation}"
            and value["logical_ciphertext_bytes"] == LENGTHS[2 * pair]
            and value["distinct_provider_identities"] == 2
            and [c["provider_key"] for c in value["copies"]]
                == [provider_keys[p] for p in ORDER[2 * pair:2 * pair + 2]]
            and value["operation_complete"] is True and value["read_consumes_archive"] is False
            and value["expired_copies_remain_charged"] is True
            and all(value[field] is False for field in ("metadata_overhead_measured",
                "independent_failure_domains_proven", "network_contribution_credit", "automatic_repair")),
            "incomplete replica receipt")
    if operation == "deposit":
        require([c["charge"] for c in value["copies"]] == ["committed", "committed"]
                and value["committed_payload_bytes"] == 2 * LENGTHS[2 * pair]
                and value["physical_payload_charge_upper_bound"] == 2 * LENGTHS[2 * pair],
                "committed pair accounting missing")
        require(closed_diagnostic(value["deposit_diagnostics"])["failures"] == [], "success contains failures")


def sequence_result():
    return dict(success=False, completed_deposits=0, attempted_deposits=0,
        target_ordinal=10, target_provider="B", target_reserve_nominal_flow=28,
        target_reserve_receipt_confirmed=False, target_deposit_committed=False,
        failure=None, owner_verified_committed_receipts=0, deleted_copies=0,
        unknown_reservation=False, remote_cleanup_complete=False, cli_children_joined=True)
def deposit_pairs(root, binary, client, keys, result, identities, pairs):
    """Fixture phases only; every operation remains the unchanged production CLI."""
    for pair in pairs:
        result["attempted_deposits"] = 2 * pair + 2
        failure = dict(pair_ordinal=pair + 1, diagnostics_state="unavailable", diagnostics=None)
        def observe(_status, stdout, _stderr):
            nonlocal failure
            try:
                failure = failure_report(stdout, pair)
            except (KeyError, TypeError, ValueError):
                failure = dict(pair_ordinal=pair + 1, diagnostics_state="invalid", diagnostics=None)
        pair_ok = False
        try:
            value = invoke(binary, client, ["storage", "replicas", "--tls-close-diagnostics-v9", "deposit",
                *existing(root, pair), "--input", root / f"input-{pair}.bin", "--already-encrypted"],
                failure_observer=observe)
            valid_pair_receipt(value, "deposit", pair, keys)
            pair_ok = True
        except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
            result["failure"] = failure
            # The shared invocation helper may fail while joining after
            # termination. Do not claim a joined child from that ambiguity.
            if isinstance(error, (OSError, subprocess.SubprocessError)):
                result["cli_children_joined"] = False
        for index in range(2 * pair, 2 * pair + 2):
            try:
                retained = journal(root, index)
                confirmed = retained["lease"] is not None
                committed = confirmed and retained["last_state"] == 3
                if committed:
                    identity = (keys[ORDER[index]], retained["lease"])
                    require(identity not in identities and retained["last_stored_bytes"] == LENGTHS[index],
                            "fresh committed lease missing")
                    identities.add(identity)
                    result["completed_deposits"] += 1
                    result["owner_verified_committed_receipts"] += 1
                if index == 9:
                    result["target_reserve_receipt_confirmed"] = confirmed
                    result["target_deposit_committed"] = committed
                if not confirmed:
                    result["unknown_reservation"] = True
            except (KeyError, TypeError, ValueError, OSError):
                result["unknown_reservation"] = True
                pair_ok = False
        if not pair_ok:
            break


def delete_copies(root, binary, client, keys, result):
    cleanup_ok = not result["unknown_reservation"]
    for index in range(result["attempted_deposits"]):
        try:
            retained = journal(root, index)
            if retained["lease"] is None:
                cleanup_ok = False
                continue
            value = invoke(binary, client, ["storage", "replicas", "delete", *existing(root, index // 2),
                "--provider-key", keys[ORDER[index]]])
            valid_pair_receipt(value, "delete", index // 2, keys)
            require(value["copies"][index % 2]["charge"] == "deleted"
                    and value["deleted_provider_key"] == keys[ORDER[index]], "copy deletion unconfirmed")
            result["deleted_copies"] += 1
        except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
            cleanup_ok = False
            if isinstance(error, (OSError, subprocess.SubprocessError)):
                result["cli_children_joined"] = False
    result["remote_cleanup_complete"] = cleanup_ok


def run(root, binary, client, keys):
    result = sequence_result()
    try:
        deposit_pairs(root, binary, client, keys, result, set(), range(5))
    finally:
        delete_copies(root, binary, client, keys, result)
    result["success"] = (result["completed_deposits"] == result["deleted_copies"] == 10
        and result["failure"] is None and result["remote_cleanup_complete"] and result["cli_children_joined"])
    return result


def cleanup(path):
    root = private_root(path, missing=True)
    files, directories = [], []
    if root.exists():
        allowed = {"identity.key", "passphrase", "grant-0.bin", "grant-1.bin", "grant-2.bin",
                   *(f"input-{pair}.bin" for pair in range(5))}
        def directory(path):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_uid == os.geteuid(), "unsafe replica directory")
        children = list(root.iterdir())
        require(len(children) <= 22, "private cleanup exceeded root entry bound")
        # Sequential create can leave one unpublished set and atomic key/grant
        # writes can leave temporary files after an interrupted CLI process.
        require(sum(bool(re.fullmatch(r"\.replicas-[A-Za-z0-9]+", child.name)) for child in children) <= 1,
                "private cleanup exceeded staging bound")
        for child in children:
            if re.fullmatch(r"set-[0-4]|\.replicas-[A-Za-z0-9]+", child.name):
                directory(child)
                entries = list(child.iterdir())
                require(len(entries) <= 6, "unexpected replica entries")
                for entry in entries:
                    if entry.name in ("copy-0", "copy-1"):
                        directory(entry)
                        children = list(entry.iterdir())
                        require(len(children) <= 4 and all(e.name == "archive.json"
                            or re.fullmatch(r"\.tmp[A-Za-z0-9]+", e.name) for e in children),
                            "unexpected journal entry")
                        files.extend(children)
                        directories.append(entry)
                    else:
                        require(entry.name == "replicas.json" or re.fullmatch(r"\.tmp[A-Za-z0-9]+", entry.name),
                                "unexpected replica entry")
                        files.append(entry)
                directories.append(child)
            else:
                require(child.name in allowed or re.fullmatch(r"\.tmp[A-Za-z0-9]+", child.name),
                        "unexpected owner file")
                files.append(child)
        require(len(directories) <= 18 and len(files) <= 90, "private cleanup exceeded tree bound")
        for path in files:
            private_file(path)
        for path in files:
            path.unlink()
        for path in directories:
            path.rmdir()
        root.rmdir()
    return dict(owner_private_files_removed=True, owner_directory_removed=True)


def validate_result(value):
    require(value == dict(success=True, completed_deposits=10, attempted_deposits=10,
        target_ordinal=10, target_provider="B", target_reserve_nominal_flow=28,
        target_reserve_receipt_confirmed=True, target_deposit_committed=True,
        failure=None, owner_verified_committed_receipts=10, deleted_copies=10,
        unknown_reservation=False, remote_cleanup_complete=True, cli_children_joined=True),
        "deposit sequence or logical cleanup incomplete")


def validate_evidence(value):
    require(value["scope"] == SCOPE and value["success"] is True, "scope changed")
    validate_result(value["sequence"])
    validate_owner_evidence(value)
    # Reuse the generic three-provider/no-withdrawal network checks, not the
    # fragments lifecycle claim. Our independent completion bound is 40 flows.
    FRAG["validate_network"](value["network"], value["expected_peers"], value["layout"], "finish")
    FRAG["validate_flow_gates"](value["network"]["gates"], 40)
    selected = value["network"]["selected_route"]
    require(value["layout"]["route_scope"] == dict(exit_peer_id=selected["exact_selected_exit"],
        paths=[{key: path[key] for key in ("path_id", "relay_peer_id")} for path in selected["paths"]]),
        "selected exit or original path identities changed")


def validate_owner_evidence(value):
    require(value["prepare"] == dict(success=True, order=[LABELS[p] for p in ORDER], lengths=list(LENGTHS),
        owner_distinct_from_providers=True, owner_secrets_exported=False,
        provider_payload_limits=list(TOTALS), provider_lease_limits=[4, 4, 2]), "preparation changed")
    require(value["private_cleanup"] == dict(owner_private_files_removed=True, owner_directory_removed=True)
            and value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
            "private or remote cleanup incomplete")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
            and isolation["control_gid"] != isolation["agent_gid"]
            and all(isolation[name] is True for name in ("agent_cannot_read_user_state",
                "client_cannot_read_any_provider_store", "agent_mount_positive_control",
                "all_provider_keys_match_independent_fixture_peers", "three_provider_namespaces_distinct")),
            "owner/provider isolation missing")


def evidence(work):
    value = {name: read(work / f"{PREFIX}-{name}.json") for name in
             ("prepare", "sequence", "private_cleanup", "isolation", "layout")}
    value["deleted_usage"] = FRAG["read_usage"](work / f"{PREFIX}-deleted_usage.json")
    value.update(success=True, scope=SCOPE, expected_peers=read(work / "a01-expected-peers.json"))
    value["network"] = dict(selected_route=read(work / f"{PREFIX}-live-selection.json"),
        privacy={role: read(work / f"{PREFIX}-privacy-{role}.json") for role in FRAG["ROLES"]},
        control_privacy=read(work / f"content-provider-adaptive-{PREFIX}-control.json"),
        gates=read(work / f"{PREFIX}-gates.json"))
    validate_evidence(value)
    return value


INITIAL_ROUTE_SELECTION = f"{PREFIX}-initial-route-selection.private"
ROUTE_DIAGNOSTIC_LIMIT = 4096


def validate_initial_route_selection(value):
    require(type(value) is dict and set(value) == {'schema_version', 'status', 'route'}
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['status'] in ('observed', 'missing', 'invalid'), 'initial route diagnostic shape')
    if value['status'] == 'observed':
        # Reuse the existing closed selection schema and fixed Connect-code allowlist.
        # This is a root-side projection, never imported by the unprivileged driver.
        maintenance = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
        maintenance['validate_selection_route'](value['route'])
    else:
        require(value['route'] is None, 'initial route diagnostic absent data')


def bounded_route_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= ROUTE_DIAGNOSTIC_LIMIT,
            'initial route diagnostic bound')
        raw = stream.read(ROUTE_DIAGNOSTIC_LIMIT + 1)
    require(len(raw) <= ROUTE_DIAGNOSTIC_LIMIT, 'initial route diagnostic bound')
    return json.loads(raw)


def initial_route_selection(work, *, capture=False):
    """Freeze the first selector outcome; never export raw diagnostics or replace it later."""
    work = Path(work)
    target = work / INITIAL_ROUTE_SELECTION
    absent = dict(schema_version=1, status='missing', route=None)
    if not capture:
        try:
            value = bounded_route_json(target)
            validate_initial_route_selection(value)
            return value
        except FileNotFoundError:
            return absent
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            return dict(schema_version=1, status='invalid', route=None)
    try:
        route = bounded_route_json(work / f'{PREFIX}-route-diagnostic.json')
        value = dict(schema_version=1, status='observed', route=route)
        validate_initial_route_selection(value)
    except FileNotFoundError:
        value = absent
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        value = dict(schema_version=1, status='invalid', route=None)
    try:
        # Exclusive creation binds this to the first selection attempt only. A later
        # benchmark helper invocation cannot replace that observation with its result.
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, separators=(',', ':'))
            stream.write('\n')
    except OSError:
        pass
    return initial_route_selection(work)


def validate_report(value, revision):
    if 'initial_route_selection' in value:
        validate_initial_route_selection(value['initial_route_selection'])
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision
            and value["schema_version"] == 1 and value["report_kind"] == f"volparossa-{PREFIX}"
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["phase"] == f"{PREFIX}-complete" and value["observed_blocker"] is None
            and value["cleanup"]["complete"] is True and value["cleanup"]["remaining_owned_objects"] == 0
            and value["host_state"]["unchanged"] is True, "source/cleanup report incomplete")
    validate_evidence(value["storage"])


def main(args):
    if args == ["export-names"]:
        print("\n".join(EXPORT_NAMES)); return 0
    if len(args) == 2 and args[0] in ('initial-route-selection', 'capture-initial-route-selection'):
        print(json.dumps(initial_route_selection(args[1], capture=args[0].startswith('capture-')),
            separators=(',', ':')))
        return 0
    if args[0] == "prepare" and len(args) == 10:
        result = prepare(private_root(args[1]), args[2], args[3], args[4:7], args[7:10])
    elif args[0] == "run" and len(args) == 7:
        result = run(private_root(args[1]), args[2], args[3], args[4:7])
    elif args[0] == "cleanup" and len(args) == 2:
        result = cleanup(args[1])
    elif args[0] == "evidence" and len(args) == 3:
        result = evidence(Path(args[1]))
        Path(args[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif args[0] == "report" and len(args) == 3:
        validate_report(read(Path(args[1])), args[2])
        result = dict(success=True, report_kind=f"volparossa-{PREFIX}")
    else:
        raise ValueError("unknown deposit sequence command")
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("success", True) else 1


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("deposit sequence interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        sys.exit(main(sys.argv[1:]))
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        print("deposit sequence failed; private diagnostics not exported", file=sys.stderr)
        sys.exit(1)
