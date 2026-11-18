#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted guest software lifecycle tests, never hardware or private-task acceptance.

Reuse the committed-lock/source/process checks and all 52 prerequisite appraisal
tests. Keep this separate evidence profile from the unchanged historical receipts.
The Rust tests use explicitly synthetic reports; no successful firmware claim is
inferred from a compiling Linux device call.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location('guest_admission', Path(__file__).with_name('protected-compute-admission.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
PREFIX = 'provider::compute::guest::tests::'
TESTS = tuple(PREFIX + name for name in (
    'guest_owner_limits_are_local_bounded_and_nondefault',
    'guest_request_reuses_exact_challenge_v2_encoding',
    'guest_request_rejects_unknown_noncanonical_and_oversized_bytes',
    'guest_begin_enforces_both_clocks_and_challenge_window',
    'guest_capacity_and_attempts_remain_owned_until_drop',
    'guest_replay_stays_rejected_after_cancel_and_failure',
    'guest_keys_are_generated_fresh',
    'guest_cancel_erases_key_before_or_after_collection',
    'guest_owner_cancel_invalidates_current_and_future_sessions',
    'guest_inflight_cancel_retains_slot_until_firmware_returns',
    'guest_expiry_during_collection_rejects_and_erases',
    'guest_report_preserves_bytes_and_refuses_unsupported_versions',
    'guest_report_refuses_wrong_lengths_vmpl_and_report_data',
    'guest_response_enforces_canonical_binding_and_bounds',
    'guest_firmware_errors_have_no_quote_or_fallback',
    'guest_quote_wire_roundtrip_does_not_create_verified_evidence',
))
ARGV = ['cargo', 'test', '--locked', '--offline', '-p',
    'volparossa-content', '--lib', PREFIX, '--', '--test-threads=1']
SCOPE = dict(software_lifecycle_tests=True, synthetic_reports=True,
    successful_firmware_quote=False, hardware_attestation=False, full_appraisal=False,
    worker_admission=False, private_input_release=False, protected_execution=False)
EXPORTS = ('tests.log', 'tests.json', 'report.json')


def same_json(value, expected):
    """Compare JSON values without Python's bool/int/float equality aliases."""
    options = dict(sort_keys=True, separators=(',', ':'), allow_nan=False)
    return json.dumps(value, **options) == json.dumps(expected, **options)


def verify_tests(raw):
    text = raw.decode('utf-8')
    observed = re.findall(r'^test (\S+) \.\.\. (\S+)[ \t]*$', text, re.M)
    P.require(len(observed) == len(TESTS) and set(observed) == {(name, 'ok') for name in TESTS}, 'guest_exact_tests')
    P.require(len(re.findall(r'^running 16 tests\s*$', text, re.M)) == 1, 'guest_tests_not_executed')
    results = re.findall(r'^test result: (.+)$', text, re.M)
    P.require(len(results) == 1 and re.fullmatch(r'ok\. 16 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\s*', results[0]), 'guest_test_summary')
    return dict(names=list(TESTS), passed=16, failed=0, ignored=0, scope=SCOPE)


def prerequisite(work):
    records, files = {}, {}
    for name in P.EXPORTS:
        if name == 'report.json':
            continue
        raw = P.read(work / 'evidence' / name, P.MAX_LOG if name.endswith('.log') else P.MAX_LOCK)
        files[name] = P.digest(raw)
        if name.endswith('.json'):
            records[name] = json.loads(raw)
    P.verify_evidence(work, records, files, local_policy=True)
    raw = P.read(work / 'evidence/report.json', P.MAX_LOCK)
    expected = P.envelope('core-attestation-public-tests', local_policy=True,
        source=records['source.json']['source'], files=files, passed=True,
        stages={name: True for name in ('resolution.json', 'resolved-metadata.json', 'tests.json', 'clippy.json')},
        scope=P.SCOPE)
    P.require(same_json(json.loads(raw), expected), 'guest_prerequisite_report')
    return records['source.json']['source'], P.digest(raw)


def directory(work):
    path = work / 'guest-evidence'
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    P.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700, 'guest_evidence_directory')
    return path


def execute(work):
    source, base = prerequisite(work)
    path = directory(work)
    outcome = P.run(ARGV, path / 'tests.log', 300)
    raw = P.read(path / 'tests.log', P.MAX_LOG)
    value = dict(schema_version=1, kind='core-guest-software-tests', source=source,
        prerequisite=base, scope=SCOPE, argv=ARGV, command=outcome,
        log=P.digest(raw), passed=False)
    try:
        P.command_ok(outcome)
        P.require(same_json(prerequisite(work), (source, base)), 'guest_source_changed')
        value['tests'] = verify_tests(raw)
        value['passed'] = True
    finally:
        P.record(path / 'tests.json', value)


def verify_evidence(work):
    source, base = prerequisite(work)
    path = work / 'guest-evidence'
    raw = P.read(path / 'tests.log', P.MAX_LOG)
    stage_raw = P.read(path / 'tests.json', P.MAX_LOCK)
    stage = json.loads(stage_raw)
    P.require(set(stage) == {'schema_version', 'kind', 'source', 'prerequisite', 'scope',
        'argv', 'command', 'log', 'passed', 'tests'}, 'guest_stage_shape')
    expected = dict(schema_version=1, kind='core-guest-software-tests', source=source,
        prerequisite=base, scope=SCOPE, argv=ARGV, command=stage['command'],
        log=P.digest(raw), tests=verify_tests(raw), passed=True)
    P.require(same_json(stage, expected), 'guest_stage_binding')
    P.command_ok(stage['command'])
    return source, base, {'tests.log': P.digest(raw), 'tests.json': P.digest(stage_raw)}


def receipt(work):
    path = directory(work)
    source, base, files, passed = None, None, {}, False
    try:
        source, base, files = verify_evidence(work)
        passed = True
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        # Original bounded stage files are still exported on failure. No synthetic
        # replacement log or claimed firmware success fills missing evidence.
        pass
    P.record(path / 'report.json', dict(schema_version=1, kind='core-guest-software-evidence',
        source=source, prerequisite=base, files=files, passed=passed, scope=SCOPE))
    P.require(passed, 'guest_software_trial_incomplete')


def main(args):
    P.require(len(args) == 1 and args[0] in ('test', 'receipt'), 'guest_fixed_command')
    P.hosted()
    P.require(os.environ.get('GITHUB_REF') in ('refs/heads/feature/protected-compute-guest',
        'refs/heads/feature/protected-compute-quote-exchange'), 'guest_branch_only')
    P.install_signals()
    work = P.workdir()
    P.cargo_env(work)
    (execute if args[0] == 'test' else receipt)(work)


if __name__ == '__main__':
    main(sys.argv[1:])
