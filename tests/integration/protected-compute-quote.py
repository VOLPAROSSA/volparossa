#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted quote-exchange software evidence, not confidential execution acceptance.

Require the original appraisal and guest-lifecycle evidence from this exact
source first. Only synthetic firmware responses are used by these Rust tests;
neither their logs nor this receipt contain a real hardware report.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location('quote_guest', Path(__file__).with_name('protected-compute-guest.py'))
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
P = G.P
PREFIX = 'provider::compute::quote::tests::'
TESTS = tuple(PREFIX + name for name in (
    'quote_signed_purpose_rejects_compute_and_cross_stream_replay',
    'quote_registry_coexists_with_public_compute_without_fallback',
    'quote_requires_live_supervisor_and_exact_local_requester_grant',
    'quote_binary_frames_are_strict_bounded_and_request_bound',
    'quote_delivery_retains_owned_key_until_original_expiry',
    'quote_write_failure_erases_collected_key_and_releases_owner_slot',
    'quote_cancellation_keeps_process_permit_until_firmware_really_returns',
    'quote_detach_and_late_firmware_result_cannot_publish_or_retain',
    'quote_failed_authority_recheck_revokes_retained_evidence',
    'quote_replay_and_nonrefundable_attempts_are_finite',
    'quote_pending_drop_before_supervisor_poll_revokes_attachment',
    'quote_owned_owner_drop_cancels_surviving_session_without_key_access',
))
ARGV = ['cargo', 'test', '--locked', '--offline', '-p',
    'volparossa-content', '--lib', PREFIX, '--', '--test-threads=1']
SCOPE = dict(signed_quote_exchange_software_tests=True, synthetic_reports=True,
    successful_firmware_quote=False, hardware_attestation=False, full_appraisal=False,
    production_route_execution=False, worker_admission=False,
    private_input_release=False, protected_execution=False)
EXPORTS = ('tests.log', 'tests.json', 'report.json')


def verify_command(value):
    """Accept only the exact successful owned-process receipt in this profile."""
    P.require(type(value) is dict and set(value) == {
        'exit_status', 'capture_error', 'leader_joined', 'cleanup_scope', 'elapsed_ms'},
        'quote_command_receipt')
    P.require(type(value['exit_status']) is int and value['exit_status'] == 0
        and value['capture_error'] is None and value['leader_joined'] is True
        and type(value['cleanup_scope']) is str
        and value['cleanup_scope'] == 'owned-process-group-not-a-setsid-proof-sandbox'
        and type(value['elapsed_ms']) is int and value['elapsed_ms'] >= 0,
        'quote_command_receipt')


def verify_tests(raw):
    text = raw.decode('utf-8')
    observed = re.findall(r'^test (\S+) \.\.\. (\S+)[ \t]*$', text, re.M)
    P.require(len(observed) == len(TESTS) and set(observed) == {(name, 'ok') for name in TESTS}, 'quote_exact_tests')
    P.require(len(re.findall(r'^running 12 tests\s*$', text, re.M)) == 1, 'quote_tests_not_executed')
    results = re.findall(r'^test result: (.+)$', text, re.M)
    P.require(len(results) == 1 and re.fullmatch(r'ok\. 12 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\s*', results[0]), 'quote_test_summary')
    return dict(names=list(TESTS), passed=12, failed=0, ignored=0, scope=SCOPE)


def prerequisite(work):
    source, appraisal, files = G.verify_evidence(work)
    raw = P.read(work / 'guest-evidence/report.json', P.MAX_LOCK)
    expected = dict(schema_version=1, kind='core-guest-software-evidence',
        source=source, prerequisite=appraisal, files=files, passed=True, scope=G.SCOPE)
    P.require(G.same_json(json.loads(raw), expected), 'quote_prerequisite_report')
    return source, P.digest(raw)


def directory(work):
    path = work / 'quote-evidence'
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    P.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700, 'quote_evidence_directory')
    return path


def execute(work):
    source, base = prerequisite(work)
    path = directory(work)
    outcome = P.run(ARGV, path / 'tests.log', 300)
    raw = P.read(path / 'tests.log', P.MAX_LOG)
    value = dict(schema_version=1, kind='core-quote-software-tests', source=source,
        prerequisite=base, scope=SCOPE, argv=ARGV, command=outcome,
        log=P.digest(raw), passed=False)
    try:
        verify_command(outcome)
        P.require(G.same_json(prerequisite(work), (source, base)), 'quote_source_changed')
        value['tests'] = verify_tests(raw)
        value['passed'] = True
    finally:
        P.record(path / 'tests.json', value)


def verify_evidence(work):
    source, base = prerequisite(work)
    path = work / 'quote-evidence'
    raw = P.read(path / 'tests.log', P.MAX_LOG)
    stage_raw = P.read(path / 'tests.json', P.MAX_LOCK)
    stage = json.loads(stage_raw)
    P.require(set(stage) == {'schema_version', 'kind', 'source', 'prerequisite', 'scope',
        'argv', 'command', 'log', 'passed', 'tests'}, 'quote_stage_shape')
    expected = dict(schema_version=1, kind='core-quote-software-tests', source=source,
        prerequisite=base, scope=SCOPE, argv=ARGV, command=stage['command'],
        log=P.digest(raw), tests=verify_tests(raw), passed=True)
    P.require(G.same_json(stage, expected), 'quote_stage_binding')
    verify_command(stage['command'])
    return source, base, {'tests.log': P.digest(raw), 'tests.json': P.digest(stage_raw)}


def receipt(work):
    path = directory(work)
    source, base, files, passed = None, None, {}, False
    try:
        source, base, files = verify_evidence(work)
        passed = True
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        pass  # Retain original bounded failure output; never substitute successful evidence.
    P.record(path / 'report.json', dict(schema_version=1, kind='core-quote-software-evidence',
        source=source, prerequisite=base, files=files, passed=passed, scope=SCOPE))
    P.require(passed, 'quote_software_trial_incomplete')


def main(args):
    P.require(len(args) == 1 and args[0] in ('test', 'receipt'), 'quote_fixed_command')
    P.hosted()
    P.require(os.environ.get('GITHUB_REF') == 'refs/heads/feature/protected-compute-quote-exchange', 'quote_branch_only')
    P.install_signals()
    work = P.workdir()
    P.cargo_env(work)
    (execute if args[0] == 'test' else receipt)(work)


if __name__ == '__main__':
    main(sys.argv[1:])
