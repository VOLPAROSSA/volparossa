#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real owner CLI/core maintenance over the existing disposable protected topology."""
import base64
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
import threading
import time

F = runpy.run_path(str(Path(__file__).with_name('private-storage-fragments-smoke.py')))
SAMPLER = runpy.run_path(str(Path(__file__).with_name('private-storage-log-sampler.py')))
CONSUMERS = runpy.run_path(str(Path(__file__).with_name('storage-consumer-maintenance-evidence.py')))
read, require = F['read'], F['require']
private_root, private_file, create, invoke, unlock = (F[key] for key in
    ('private_root', 'private_file', 'create', 'invoke', 'unlock'))
BYTES, CHUNK, LENGTHS, SHA = (F[key] for key in ('BYTES', 'CHUNK', 'LENGTHS', 'SHA'))
A_BYTES = F['PROVIDER_BYTES'][0]
FG = b'VOLPAROSSA independent foreground fixture'.ljust(64, b'.')
MAX_CHARGE = 2 * BYTES + A_BYTES
# This is the existing enclosing timeout, not a new per-stage allowance. The
# coordinator alone may spend 30s starting the daemon, 60s on inventory and
# 600s selecting its protected route before it publishes ready.json.
LIFECYCLE_SECONDS = 1800
# Closed parsing limits, not grants or a prediction of daemon tick timing.
# Keep the unchanged 256KiB owner-output bound while allowing ordinary turns
# during coordinator preparation. Later repair/retirement adds at most 12+4.
MAX_LIFECYCLE_CURSOR = 128
MAX_CURSOR = MAX_LIFECYCLE_CURSOR + 12 + 4
EXPORT_NAMES = tuple(name for name in F['EXPORT_NAMES'] if name not in
    ('private-storage-fragments-smoke.json', 'private-storage-fragments-evidence.json')) + (
    'private-storage-maintenance-smoke.json', 'private-storage-maintenance-evidence.json',
    'private-storage-maintenance-lifecycle.json',
    'private-storage-maintenance-lifecycle-failure.json',
    'private-storage-maintenance-route-diagnostic.json',
    'private-storage-maintenance-provider-events.json',
    'private-storage-provider-activity.json',
    'private-storage-fixture-correlation.json',
    'private-storage-maintenance-inventory.json',
    'private-storage-maintenance-supervisor.json',
    'private-storage-fragments-lifecycle-live-selection.json',
    'private-storage-fragments-lifecycle-gates.json',
    *(f'private-storage-fragments-{name}-layout.json' for name in ('upload', 'lifecycle', 'restore', 'finish')),
    'content-provider-adaptive-private-storage-fragments-lifecycle-control.json',
    *(f'private-storage-fragments-lifecycle-privacy-{role}.json' for role in F['ROLES']))
EXPORT_NAMES = tuple(dict.fromkeys((*EXPORT_NAMES, *CONSUMERS['EXPORT_NAMES'])))
SCOPE_FALSE = ('independent_failure_domains_proven', 'network_contribution_credit',
    'archive_encryption_proven', 'automatic_archive_discovery', 'automatic_grant_refresh',
    'contribution_resize_proven', 'full_alpha_acceptance_claimed')
STAGE = 'not_started'
TURN_DIAGNOSTIC = None
RETIREMENT_DIAGNOSTIC = None
RETIREMENT_TURNS = []
REPAIR_DIAGNOSTIC = None
REPAIR_TURNS = []
SAMPLER_DIAGNOSTIC = {}
LIFECYCLE_DIAGNOSTIC = None
UPLOAD_DIAGNOSTIC = None
UPLOAD_OPERATIONS = ('create', 'deposit', 'progress', 'redeposit', 'renew', 'status', 'foreground_seed')
SUPERVISOR_STAGES = ('bind_slots', 'control_query', 'control_match', 'broker_validated',
    'control_snapshot', 'control_validate_before', 'control_rebind',
    'control_verified', 'route_scope',
    'start_observers', 'ready_payload', 'publish_ready', 'join_owner',
    'lifecycle_receipt', 'finish_observers', 'coordinator_cleanup')
LIFECYCLE_STAGES = ('checkpoint_before', 'spawn_owner', 'await_working', 'await_core_loss',
    'verify_retained', 'await_coordinator', 'validate_coordinator', 'start_sampler',
    'await_resumed_turn', 'stop_owner', 'verify_pause', 'fresh_owner_turn',
    'reconcile_progress', 'validate_flow_coverage', 'publish_result')
CHECKPOINT_STAGES = ('enrolled', 'owner_locked', 'waiting_for_core', 'working', 'paused',
    'enrollment_expired', 'core_unavailable', 'core_turn_revoked', 'turn_completed', 'retry_pending')
BASELINE_REASONS = ('pending_handoff', 'unconfirmed', 'expired', 'accounting', 'identity',
    'geometry', 'scope', 'live_source_exhausted', 'malformed', 'unknown')
FAILURE_CODES = {
    'maintenance checkpoint scope': 'checkpoint_scope',
    'core turn not observed': 'turn_not_observed',
    'independent foreground operation not acknowledged': 'foreground_receipt',
    'bounded owner output': 'owner_output_bound',
    'owner process exit': 'owner_exit',
    'cursor did not resume exactly one turn': 'cursor_mismatch',
    'owner EOF was not during an admitted turn': 'owner_eof_stage',
    'foreground did not revoke the core turn': 'foreground_revoke_stage',
    'maintenance did not complete a core turn': 'turn_stage',
    'replacement set incomplete before retirement': 'retirement_initial_counts',
    'placement journal exceeds bound': 'placement_journal_bound',
    'unbounded retirement readbacks': 'retirement_readbacks',
    'duplicate replacement after restart': 'retirement_duplicate_placement',
    'signed replacement identities changed': 'retirement_identity',
    'source retirement unconfirmed': 'retirement_pending_or_charge',
    'private replica CLI operation failed': 'cli_exit',
    'replica diagnostics exceeded fixture bound': 'cli_output_bound',
    'owner lifecycle deadline': 'lifecycle_deadline',
    'lifecycle initial cursor': 'lifecycle_initial_cursor',
    'core loss changed charged custody': 'lifecycle_charge_changed',
    'core loss changed fragment count': 'lifecycle_fragment_count_changed',
    'core loss changed copy count': 'lifecycle_copy_count_changed',
    'core loss changed placement count': 'lifecycle_placement_count_changed',
    'core loss retained intent invalid': 'lifecycle_retained_intent_invalid',
    'retained intent changed after core restart': 'lifecycle_retained_intent_changed',
    'core loss changed enrollment': 'lifecycle_enrollment_changed',
    'invalid fixture coordinator reply': 'lifecycle_coordinator_invalid',
    'SIGTERM did not persist pause': 'lifecycle_pause_missing',
    'enrollment changed across core restart': 'lifecycle_enrollment_changed',
    'resume cursor changed': 'lifecycle_cursor_changed',
    'restart charge reconciliation': 'lifecycle_reconciliation',
    'owner output not drained': 'owner_output_not_drained',
    'pre-withdrawal custody not reconciled': 'baseline_custody',
    'pre-withdrawal replacement binding': 'baseline_identity',
    'pre-withdrawal repair exhausted withdrawal case': 'baseline_no_live_a',
    'signed replacement identities changed after withdrawal': 'repair_identity',
    'bounded repair turns incomplete': 'repair_turns_exhausted',
    'new replacement readbacks incomplete': 'repair_readbacks',
    'durable scan cursor did not rotate': 'repair_cursor',
    'unbounded replacements per turn': 'repair_turn_bound',
    'offline original charge lost or enrollment exceeded': 'repair_charge',
    'replacement custody or accounting incomplete': 'repair_custody',
    'fragment reconstruction geometry changed': 'repair_geometry',
    'effective replacement placement': 'repair_placement',
    'replacement identity projection': 'repair_identity',
    'replacement scope changed': 'repair_scope',
}
PRESELECTION_REASON_CODES = (
    'PRESELECTION_SAMPLE_NO_EXIT', 'PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS',
    'PRESELECTION_SAMPLE_INVALID_POLICY', 'PRESELECTION_SAMPLE_INVALID_SNAPSHOT',
    'PRESELECTION_SAMPLE_ENTROPY',
)
ROUTE_CONNECT_CODES = ('NOT_STARTED', 'CONNECTED', 'UNRECOGNIZED',
    'CLIENT_ROLE_DISABLED', 'POLICY_UNAVAILABLE', 'CLIENT_ROUTE_PROFILE_INVALID',
    'CONNECT_ALREADY_IN_PROGRESS', 'PRESELECTION_UNAVAILABLE', 'NO_ELIGIBLE_PATHS',
    'NATIVE_PERMIT_UNAVAILABLE', 'NATIVE_RELAY_READY_UNAVAILABLE', 'NATIVE_HELPER_PREPARE_UNAVAILABLE',
    'NATIVE_PROBE_AUTHORIZE_UNAVAILABLE', 'NATIVE_HELPER_ACTIVATE_UNAVAILABLE',
    'NATIVE_PROBE_START_UNAVAILABLE', 'NATIVE_HELPER_COMMIT_UNAVAILABLE', 'NATIVE_PROBE_PROOF_UNAVAILABLE',
    'NATIVE_SAMPLER_RETIREMENT_UNAVAILABLE', 'NATIVE_REMOTE_RETIREMENT_UNAVAILABLE',
    'NATIVE_TRANSPORT_IDENTITY_UNAVAILABLE', 'ROUTE_ADMISSION_UNAVAILABLE',
    'MPTCP_EXIT_LISTENER_SIGNAL_UNAVAILABLE', 'TRANSPORT_RUNTIME_UNAVAILABLE',
    'UDP_EXIT_SESSION_SIGNAL_UNAVAILABLE', 'UDP_INGRESS_UNAVAILABLE')

PROVIDER_EVENTS_NAME = 'private-storage-maintenance-provider-events.json'
PROVIDER_EVENT_ROLES = {'client': 'client', **{f'control_relay{i}': f'relay{i}' for i in range(3)},
    **{f'provider_relay{i}': f'relay{i}' for i in range(3, 6)}}
# Existing closed product events only. Several events can describe one failed
# exchange; these counts are never numbers of failed requests or causal proof.
PROVIDER_EVENT_CODES = (
    'CONTENT_PROVIDER_REGISTERED', 'CONTENT_PROVIDER_WITHDRAWN',
    'CONTENT_PROVIDER_REGISTRATION_EXPIRED', 'CONTENT_PROVIDER_REGISTRATION_RETRY_PENDING',
    'CONTENT_PROVIDER_REGISTRATION_RECOVERED', 'CONTENT_PROVIDER_REGISTRATION_FAILED',
    'CONTENT_PROVIDER_REGISTRY_TIMEOUT', 'CONTENT_PROVIDER_SELECTOR_MISSING',
    'CONTENT_PROVIDER_SELECTOR_UNAVAILABLE', 'CONTENT_PROVIDER_SELECTOR_IO',
    'CONTENT_PROVIDER_SELECTOR_TIMEOUT', 'CONTENT_PROVIDER_SELECTOR_PROTOCOL', 'CONTENT_PROVIDER_REJECTED',
    'CONTENT_DISCOVERY_COMMAND_RECEIVED', 'CONTENT_DISCOVERY_REQUEST_DISPATCHED',
    'CONTENT_DISCOVERY_COMPLETED', 'CONTENT_DISCOVERY_RECEIVED_EMPTY', 'CONTENT_DISCOVERY_RECEIVED_OFFERS',
    'CONTENT_DISCOVERY_CONTROL_CONNECTION_LOST', 'CONTENT_DISCOVERY_RESPONSE_AUTHORITY_REJECTED',
    'CONTENT_DISCOVERY_RESPONSE_TARGETS_UNAVAILABLE', 'CONTENT_DISCOVERY_RESPONSE_OFFER_REJECTED',
    'CONTENT_DISCOVERY_RESPONSE_REJECTED', 'CONTENT_DISCOVERY_DIAL_FAILED',
    'CONTENT_DISCOVERY_RPC_TIMED_OUT', 'CONTENT_DISCOVERY_CONNECTION_CLOSED',
    'CONTENT_DISCOVERY_PROTOCOL_UNSUPPORTED', 'CONTENT_DISCOVERY_RPC_IO_FAILED',
    'CONTENT_DISCOVERY_RELAY_NONCE_INVALID', 'CONTENT_DISCOVERY_RELAY_SERVICE_UNAVAILABLE',
    'CONTENT_DISCOVERY_RELAY_AUTHORITY_UNAVAILABLE', 'CONTENT_DISCOVERY_RELAY_SELF_REJECTED',
    'CONTENT_DISCOVERY_RELAY_CONNECTION_INVALID', 'CONTENT_DISCOVERY_RELAY_QUEUE_FULL',
    'CONTENT_DISCOVERY_RELAY_REPLAY_FULL', 'CONTENT_DISCOVERY_RELAY_REPLAY_REJECTED',
    'CONTENT_DISCOVERY_RELAY_QUERY_REJECTED', 'CONTENT_DISCOVERY_LIMIT_INVALID',
    'CONTENT_DISCOVERY_CALLER_CLOSED', 'CONTENT_DISCOVERY_CLIENT_ROLE_REJECTED',
    'CONTENT_DISCOVERY_CLIENT_QUEUE_FULL', 'CONTENT_DISCOVERY_CONTROL_MISSING',
    'CONTENT_DISCOVERY_CONTROL_SELF_REJECTED', 'CONTENT_DISCOVERY_CONTROL_EXPIRED',
    'CONTENT_DISCOVERY_CONTROL_LIFETIME_SHORT', 'CONTENT_DISCOVERY_CONNECTION_REGISTRY_POISONED',
    'CONTENT_DISCOVERY_CONNECTION_ABSENT', 'CONTENT_DISCOVERY_CONNECTION_NO_DIRECT',
    'CONTENT_DISCOVERY_REQUEST_REJECTED', 'CONTENT_DISCOVERY_LOCAL_DEADLINE',
    'CONTENT_EXACT_LOOKUP_STARTED', 'CONTENT_EXACT_LOOKUP_FINISHED',
    'CONTENT_EXACT_ADDRESS_QUERY_STARTED', 'CONTENT_EXACT_ADDRESS_UNAVAILABLE',
    'CONTENT_EXACT_RESOLVED_REQUEST_SENT',
)
PROVIDER_EVENT_PHASES = ('private-storage-fragments-upload', 'private-storage-maintenance-lifecycle',
    'private-storage-fragments-restore', 'private-storage-fragments-finish',
    'storage-consumer-publish', 'storage-consumer-exercise', 'storage-consumer-finish', 'unknown')
STORAGE_FAILURE_PREFIX = 'CONTENT_PROVIDER_STORAGE_V1_'
STORAGE_FAILURE_OPERATIONS = ('UNKNOWN', 'RESERVE', 'APPEND', 'PROGRESS', 'FINALIZE',
    'READ_RANGE', 'RENEW', 'DELETE')
STORAGE_FAILURE_PHASES = ('GRANT', 'CHALLENGE', 'REQUEST', 'PAYLOAD', 'DISK_ADMISSION',
    'BACKEND', 'RECEIPT', 'RESPONSE_PAYLOAD')
STORAGE_FAILURE_CATEGORIES = ('IO', 'AUTH', 'INVALID', 'BUSY', 'STORE', 'TIMEOUT',
    'DATABASE', 'INTEGRITY', 'EXPIRED', 'OWNERSHIP', 'CONFLICT', 'DELETED', 'QUOTA',
    'NOT_FOUND', 'NOT_COMMITTED', 'ENTROPY')
MAX_STORAGE_FAILURE_TUPLES = 32
APPEND_PAYLOAD_IO_PREFIX = 'CONTENT_PROVIDER_STORAGE_V2_APPEND__'
APPEND_PAYLOAD_IO_BOUNDARIES = ('PAYLOAD_HEADER', 'PAYLOAD_BODY')
APPEND_PAYLOAD_IO_KINDS = ('UNEXPECTED_EOF', 'TIMED_OUT', 'CONNECTION_RESET', 'BROKEN_PIPE',
    'INVALID_DATA', 'INTERRUPTED', 'OTHER')
MAX_APPEND_PAYLOAD_IO_TUPLES = len(APPEND_PAYLOAD_IO_BOUNDARIES) * len(APPEND_PAYLOAD_IO_KINDS)


def append_payload_io_code(code):
    if type(code) is not str or len(code) > 96 or not code.startswith(APPEND_PAYLOAD_IO_PREFIX):
        return False
    parts = code[len(APPEND_PAYLOAD_IO_PREFIX):].split('__')
    return (len(parts) == 2 and parts[0] in APPEND_PAYLOAD_IO_BOUNDARIES
        and parts[1] in APPEND_PAYLOAD_IO_KINDS)


def storage_failure_code(code):
    # One closed event preserves its tuple. Separate counts of operation, phase
    # and category would invent correlations between unrelated exchanges.
    if type(code) is not str or len(code) > 96 or not code.startswith(STORAGE_FAILURE_PREFIX):
        return False
    parts = code[len(STORAGE_FAILURE_PREFIX):].split('__')
    if len(parts) != 3:
        return False
    operation, phase, category = parts
    return (operation in STORAGE_FAILURE_OPERATIONS and phase in STORAGE_FAILURE_PHASES
        and category in STORAGE_FAILURE_CATEGORIES
        and (operation == 'UNKNOWN') == (phase in ('GRANT', 'CHALLENGE', 'REQUEST'))
        and (phase != 'RESPONSE_PAYLOAD' or operation == 'READ_RANGE'))


def validate_provider_events(value):
    require(type(value) is dict and set(value) == {'version', 'kind', 'scope', 'acceptance_evidence',
        'causal_attribution', 'event_absence_proven', 'phase', 'baseline_state', 'roles'}
        and type(value['version']) is int and value['version'] in (1, 2, 3)
        and value['kind'] == 'private-storage-maintenance-provider-events'
        and value['scope'] == 'pre_agent_stop_snapshot_may_include_owner_cleanup'
        and all(value[key] is False for key in ('acceptance_evidence', 'causal_attribution', 'event_absence_proven'))
        and value['phase'] in PROVIDER_EVENT_PHASES and value['baseline_state'] in ('valid', 'absent', 'invalid')
        and type(value['roles']) is dict and set(value['roles']) == set(PROVIDER_EVENT_ROLES), 'provider event shape')
    counters = ('records', 'fresh_records', 'stale_records', 'unrecognized_event_records')
    observations = (*counters, 'counts', 'window_covers_baseline', 'ring_at_capacity')
    if value['version'] >= 2:
        observations += ('storage_failures', 'omitted_storage_failure_records')
    if value['version'] == 3:
        observations += ('append_payload_io_failures',)
    for row in value['roles'].values():
        require(type(row) is dict and set(row) == {'state', 'query_exit_status', *observations}
            and row['state'] in ('observed', 'unqueried', 'capture_invalid', 'query_failed',
                'baseline_unavailable', 'absent', 'invalid', 'clock_invalid'), 'provider event role')
        status = row['query_exit_status']
        if row['state'] in ('unqueried', 'capture_invalid'):
            require(status is None, 'provider event capture absent')
        else:
            require(type(status) is int and 0 <= status <= 255
                and (status != 0) == (row['state'] == 'query_failed'), 'provider event capture status')
        if status == 0:
            require((value['baseline_state'] != 'valid') == (row['state'] == 'baseline_unavailable'),
                'provider event baseline binding')
        if row['state'] != 'observed':
            require(all(row[key] is None for key in observations), 'provider event missing counts')
            continue
        require(value['baseline_state'] == 'valid'
            and all(type(row[key]) is int and 0 <= row[key] <= 400 for key in counters)
            and row['records'] == row['fresh_records'] + row['stale_records']
            and type(row['counts']) is dict and set(row['counts']) == set(PROVIDER_EVENT_CODES)
            and all(type(n) is int and 0 <= n <= 400 for n in row['counts'].values())
            and sum(row['counts'].values()) + row['unrecognized_event_records'] <= row['fresh_records']
            and type(row['window_covers_baseline']) is bool
            and row['window_covers_baseline'] == (row['stale_records'] > 0)
            and type(row['ring_at_capacity']) is bool
            and row['ring_at_capacity'] == (row['records'] == 400), 'provider event bounds')
        if value['version'] >= 2:
            storage = row['storage_failures']
            omitted = row['omitted_storage_failure_records']
            require(type(storage) is dict and len(storage) <= MAX_STORAGE_FAILURE_TUPLES
                and all(storage_failure_code(code) and type(n) is int and 1 <= n <= 400
                    for code, n in storage.items())
                and type(omitted) is int and 0 <= omitted <= 400
                and (omitted == 0 or len(storage) == MAX_STORAGE_FAILURE_TUPLES)
                and sum(row['counts'].values()) + row['unrecognized_event_records']
                    + sum(storage.values()) + omitted <= row['fresh_records'], 'provider storage event bounds')
        if value['version'] == 3:
            payload = row['append_payload_io_failures']
            require(type(payload) is dict and len(payload) <= MAX_APPEND_PAYLOAD_IO_TUPLES
                and all(append_payload_io_code(code) and type(n) is int and 1 <= n <= 400
                    for code, n in payload.items())
                and sum(row['counts'].values()) + row['unrecognized_event_records']
                    + sum(row['storage_failures'].values()) + row['omitted_storage_failure_records']
                    + sum(payload.values()) <= row['fresh_records'], 'provider append payload io bounds')
    return value


def provider_events(work, phase, raw_baseline, *, version=2):
    require(type(version) is int and version in (2, 3), 'provider event export version')
    now_ms = time.time_ns() // 1_000_000
    baseline = None
    baseline_state = 'absent' if raw_baseline in ('', '0') else 'invalid'
    if re.fullmatch(r'[1-9][0-9]{0,19}', raw_baseline) and int(raw_baseline) <= now_ms:
        baseline, baseline_state = int(raw_baseline), 'valid'
    roles = {}
    for role, node in PROVIDER_EVENT_ROLES.items():
        row = dict(state='unqueried', query_exit_status=None, records=None, fresh_records=None,
            stale_records=None, unrecognized_event_records=None, counts=None,
            window_covers_baseline=None, ring_at_capacity=None,
            storage_failures=None, omitted_storage_failure_records=None)
        if version == 3:
            row['append_payload_io_failures'] = None
        roles[role] = row
        try:
            raw = closed_diagnostic_text(work / f'logs-{node}-cleanup-status.private', 4)
            require(re.fullmatch(r'(0|[1-9][0-9]{0,2})\n', raw) is not None
                and int(raw) <= 255, 'provider event capture status')
            row['query_exit_status'] = int(raw)
        except FileNotFoundError:
            continue
        except (OSError, ValueError, UnicodeError):
            row['state'] = 'capture_invalid'
            continue
        if row['query_exit_status'] != 0:
            row['state'] = 'query_failed'
            continue
        if baseline is None:
            row['state'] = 'baseline_unavailable'
            continue
        try:
            lines = closed_diagnostic_text(work / f'logs-{node}.txt', 131072).splitlines()
            require(len(lines) <= 400, 'provider event ring bound')
            counts = dict.fromkeys(PROVIDER_EVENT_CODES, 0)
            storage, omitted = {}, 0
            payload = {}
            stale, unknown, previous = 0, 0, 0
            for line in lines:
                match = re.fullmatch(r'([0-9]{1,20})\tlevel=([0-9])\tevent=([A-Z0-9_]{1,96})'
                    r'\tsession=[0-9a-f]{0,64}\tpath=(?:-|[0-9]{1,10})', line)
                require(match is not None, 'provider event record')
                stamp = int(match[1])
                if not 0 < stamp <= now_ms or stamp < previous:
                    row['state'] = 'clock_invalid'
                    break
                previous = stamp
                if stamp <= baseline:
                    stale += 1
                elif match[3] in counts:
                    counts[match[3]] += 1
                elif storage_failure_code(match[3]):
                    code = match[3]
                    if code in storage or len(storage) < MAX_STORAGE_FAILURE_TUPLES:
                        storage[code] = storage.get(code, 0) + 1
                    else:
                        omitted += 1
                elif version == 3 and append_payload_io_code(match[3]):
                    code = match[3]
                    payload[code] = payload.get(code, 0) + 1
                elif match[3].startswith(('CONTENT_PROVIDER_', 'CONTENT_DISCOVERY_', 'CONTENT_EXACT_', 'CONTENT_LOOKUP_')):
                    unknown += 1
            else:
                row.update(state='observed', records=len(lines), fresh_records=len(lines) - stale,
                    stale_records=stale, unrecognized_event_records=unknown, counts=counts,
                    window_covers_baseline=stale > 0, ring_at_capacity=len(lines) == 400,
                    storage_failures=storage, omitted_storage_failure_records=omitted)
                if version == 3:
                    row['append_payload_io_failures'] = payload
        except FileNotFoundError:
            row['state'] = 'absent'
        except (OSError, ValueError, UnicodeError):
            row['state'] = 'invalid'
    return validate_provider_events(dict(version=version, kind='private-storage-maintenance-provider-events',
        scope='pre_agent_stop_snapshot_may_include_owner_cleanup', acceptance_evidence=False,
        causal_attribution=False, event_absence_proven=False,
        phase=phase if phase in PROVIDER_EVENT_PHASES else 'unknown', baseline_state=baseline_state, roles=roles))


def provider_events_file(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate provider event key')
            value[key] = item
        return value
    return validate_provider_events(json.loads(closed_diagnostic_text(path, 65536), object_pairs_hook=unique))


def export_provider_events(work, phase, baseline, *, version=2):
    # Optional sidecar in the existing diagnostic process. Never let even an
    # unexpected projection/publication error replace the route or primary error.
    target, part = work / PROVIDER_EVENTS_NAME, work / 'maintenance-provider-events.part'
    try:
        target.unlink(missing_ok=True)
        value = provider_events(work, phase, baseline, version=version)
        data = (json.dumps(value, sort_keys=True) + '\n').encode('ascii')
        require(len(data) <= 65536, 'provider event output bound')
        descriptor = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
        os.replace(part, target)
    except BaseException:
        try:
            part.unlink(missing_ok=True)
        except OSError:
            pass


def validate_selection_route(value):
    require(type(value) is dict and set(value) == {'schema_version', 'stage', 'reason',
        'last_connect_reason', 'connect_exit_status', 'attempts', 'retries', 'redraws',
        'path_polls', 'path_status'}, 'route diagnostic shape')
    reasons = {'initialize': ('STARTED',),
        'budget': ('DEADLINE_EXHAUSTED', 'DRAWS_EXHAUSTED', 'ATTEMPTS_EXHAUSTED'),
        'paths': ('SELECTION_RECORD_FAILED', 'PATHS_EMPTY', 'PATHS_INVALID_OR_QUERY_FAILED'),
        'complete': ('SELECTED',), 'disconnect': ('DISCONNECT_FAILED',),
        'connect': ('CONNECT_TIMEOUT', 'CONNECT_REJECTED', 'CONNECT_TRANSIENT')}
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and type(value['stage']) is str and value['stage'] in reasons
        and value['reason'] in reasons[value['stage']]
        and value['last_connect_reason'] in ROUTE_CONNECT_CODES, 'route diagnostic category')
    for name, maximum in (('attempts', 360), ('retries', 359), ('redraws', 32), ('path_polls', 100)):
        require(type(value[name]) is int and 0 <= value[name] <= maximum, 'route diagnostic bound')
    require(value['retries'] == max(0, value['attempts'] - 1), 'route diagnostic attempts')
    for name in ('connect_exit_status', 'path_status'):
        require(value[name] is None or type(value[name]) is int and 0 <= value[name] <= 255,
            'route diagnostic process status')


def validate_preselection_diagnostic(value):
    counters = ('records', 'fresh_records', 'stale_records', 'later_records', 'unrecognized_reason_records')
    require(type(value) is dict and set(value) == {'version', 'state', 'observed_reason',
        'uncertainty', 'scope', 'limit', 'counts', 'window_covers_baseline', *counters}
        and type(value['version']) is int and value['version'] == 1
        and type(value['limit']) is int and value['limit'] == 400
        and value['scope'] == 'selection_window_not_last_attempt_proof', 'preselection diagnostic shape')
    if value['records'] is None:
        require(all(value[name] is None for name in counters)
            and value['counts'] is None and value['window_covers_baseline'] is None,
            'preselection missing observation')
    else:
        require(all(type(value[name]) is int and 0 <= value[name] <= 400 for name in counters)
            and type(value['counts']) is dict and set(value['counts']) == set(PRESELECTION_REASON_CODES)
            and all(type(count) is int and 0 <= count <= 400 for count in value['counts'].values())
            and type(value['window_covers_baseline']) is bool
            and value['records'] == sum(value[name] for name in ('fresh_records', 'stale_records', 'later_records'))
            and sum(value['counts'].values()) + value['unrecognized_reason_records'] <= value['fresh_records'],
            'preselection diagnostic counts')
    if value['state'] == 'known':
        require(value['counts'] is not None and value['records'] < 400
            and value['uncertainty'] is None and value['unrecognized_reason_records'] == 0
            and [code for code, count in value['counts'].items() if count] == [value['observed_reason']],
            'preselection known reason')
    else:
        require(value['state'] == 'unknown' and value['observed_reason'] == 'unknown'
            and value['uncertainty'] in ('absent_baseline', 'invalid_baseline', 'absent_window_end',
                'invalid_window_end', 'absent', 'clock_regression', 'ring_at_capacity', 'unrecognized',
                'ambiguous', 'no_fresh_signal', 'invalid'), 'preselection uncertainty')


def validate_route_diagnostic(value):
    require(type(value) is dict and set(value) == {'version', 'kind', 'scope', 'route_state',
        'route', 'preselection', 'acceptance_evidence', 'selection_phase'} and type(value['version']) is int
        and value['version'] == 1 and value['kind'] == 'private-storage-maintenance-route-diagnostic'
        and value['scope'] == 'last_selection_window_not_failure_cause'
        and value['acceptance_evidence'] is False
        and value['selection_phase'] in ('initial', 'reconnect', 'unknown'), 'maintenance route diagnostic shape')
    if value['route_state'] == 'observed':
        validate_selection_route(value['route'])
    else:
        require(value['route_state'] in ('absent', 'invalid') and value['route'] is None,
            'maintenance route observation')
    validate_preselection_diagnostic(value['preselection'])


def route_diagnostic(work):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate route diagnostic key')
            result[key] = value
        return result

    value = dict(version=1, kind='private-storage-maintenance-route-diagnostic',
        scope='last_selection_window_not_failure_cause', acceptance_evidence=False,
        selection_phase='unknown', route_state='absent', route=None,
        preselection=closed_preselection_events(work / 'logs-client.txt',
            work / 'private-storage-maintenance-selection-start.private',
            work / 'private-storage-maintenance-selection-end.private'))
    try:
        phase = closed_diagnostic_text(work / 'private-storage-maintenance-selection-phase.private', 32)
        if phase in ('initial\n', 'reconnect\n'):
            value['selection_phase'] = phase.strip()
    except (OSError, ValueError, UnicodeError):
        pass
    try:
        route = json.loads(closed_diagnostic_text(
            work / 'private-storage-maintenance-selection-route-diagnostic.json', 2048), object_pairs_hook=unique)
        validate_selection_route(route)
        value.update(route_state='observed', route=route)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError, TypeError):
        value['route_state'] = 'invalid'
    validate_route_diagnostic(value)
    return value


def closed_diagnostic_text(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(),
            'invalid private diagnostic file')
        data = stream.read(maximum + 1)
        require(len(data) <= maximum, 'private diagnostic size')
    return data.decode('ascii')


def inventory_file(path, status):
    # Reuse the existing closed four-role inventory contract. This observation
    # is neither Connect success nor protected-route acceptance evidence.
    require(status in ('0', '1'), 'inventory command status')
    helper = runpy.run_path(str(Path(__file__).with_name('content-provider-readiness.py')))
    value = json.loads(closed_diagnostic_text(path, 8192), object_pairs_hook=helper['unique_pairs'])
    helper['closed_record'](value)
    require(value['ready'] == (status == '0'), 'inventory result differs from command status')
    return value


def validate_supervisor(value):
    require(type(value) is dict and set(value) == {'version', 'kind', 'stage', 'outcome',
        'exit_status', 'control_relay_relation', 'acceptance_evidence'}
        and type(value['version']) is int and value['version'] == 1
        and value['kind'] == 'private-storage-maintenance-supervisor'
        and value['stage'] in SUPERVISOR_STAGES
        and value['control_relay_relation'] in ('same', 'different', 'empty', 'unobserved')
        and value['acceptance_evidence'] is False, 'invalid supervisor diagnostic')
    status = value['exit_status']
    require(value['outcome'] == 'pending' and status is None
        or value['outcome'] == 'failed' and type(status) is int and 1 <= status <= 255
        or value['outcome'] == 'complete' and type(status) is int and status == 0
            and value['stage'] == 'coordinator_cleanup', 'invalid supervisor outcome')
    return value


def supervisor_record(stage, outcome, status, relation):
    require(status == 'null' or re.fullmatch(r'0|[1-9][0-9]{0,2}', status) is not None,
        'invalid supervisor exit status')
    return validate_supervisor(dict(version=1, kind='private-storage-maintenance-supervisor',
        stage=stage, outcome=outcome, exit_status=None if status == 'null' else int(status),
        control_relay_relation=relation, acceptance_evidence=False))


def supervisor_file(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate supervisor key')
            result[key] = value
        return result
    return validate_supervisor(json.loads(closed_diagnostic_text(path, 1024), object_pairs_hook=unique))


def closed_preselection_events(path, baseline_path, end_path):
    # Reuse the closed cooperative-browser event-ring grammar, but exclude all
    # records outside this selection's private start/end wall-clock bounds. These
    # are event counts in a selection window, not attribution to its final attempt.
    value = dict(version=1, state='unknown', observed_reason='unknown', uncertainty='absent_baseline',
        scope='selection_window_not_last_attempt_proof', limit=400, records=None,
        fresh_records=None, stale_records=None, later_records=None, counts=None, unrecognized_reason_records=None,
        window_covers_baseline=None)
    captured_at_ms = time.time_ns() // 1_000_000
    try:
        raw_baseline = closed_diagnostic_text(baseline_path, 32)
        require(re.fullmatch(r'[0-9]{1,20}\n', raw_baseline) is not None, 'invalid selection baseline')
        baseline = int(raw_baseline)
        require(0 < baseline <= captured_at_ms, 'invalid selection clock')
    except FileNotFoundError:
        return value
    except (OSError, ValueError, UnicodeError):
        value['uncertainty'] = 'invalid_baseline'
        return value
    value['uncertainty'] = 'absent_window_end'
    try:
        raw_end = closed_diagnostic_text(end_path, 32)
        require(re.fullmatch(r'[0-9]{1,20}\n', raw_end) is not None, 'invalid selection end')
        selection_end = int(raw_end)
        require(baseline <= selection_end <= captured_at_ms, 'invalid selection clock')
    except FileNotFoundError:
        return value
    except (OSError, ValueError, UnicodeError):
        value['uncertainty'] = 'invalid_window_end'
        return value
    value['uncertainty'] = 'absent'
    try:
        lines = closed_diagnostic_text(path, 131072).splitlines()
        require(len(lines) <= 400, 'preselection event ring exceeded')
        counts = dict.fromkeys(PRESELECTION_REASON_CODES, 0)
        fresh, stale, later, unrecognized, previous = 0, 0, 0, 0, 0
        first = None
        for line in lines:
            match = re.fullmatch(r'([0-9]{1,20})\tlevel=([0-9])\tevent=([A-Z0-9_]{1,96})'
                r'\tsession=[0-9a-f]{0,64}\tpath=(?:-|[0-9]{1,10})', line)
            require(match is not None, 'invalid bounded preselection event record')
            timestamp = int(match[1])
            require(timestamp > 0, 'invalid event clock')
            if timestamp < previous or timestamp > captured_at_ms:
                value['uncertainty'] = 'clock_regression'
                return value
            previous = timestamp
            if first is None:
                first = timestamp
            if timestamp <= baseline:
                stale += 1
                continue
            if timestamp > selection_end:
                later += 1
                continue
            fresh += 1
            if match[3] in counts:
                counts[match[3]] += 1
            elif match[3].startswith('PRESELECTION_SAMPLE_'):
                unrecognized += 1
        value.update(records=len(lines), fresh_records=fresh, stale_records=stale, later_records=later, counts=counts,
            unrecognized_reason_records=unrecognized,
            window_covers_baseline=first is not None and first <= baseline)
        observed = [code for code, count in counts.items() if count]
        if len(lines) == 400:
            value['uncertainty'] = 'ring_at_capacity'
        elif unrecognized:
            value['uncertainty'] = 'unrecognized'
        elif len(observed) > 1:
            value['uncertainty'] = 'ambiguous'
        elif not observed:
            value['uncertainty'] = 'no_fresh_signal'
        else:
            value.update(state='known', observed_reason=observed[0], uncertainty=None)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError):
        value['uncertainty'] = 'invalid'
    return value


class FixtureInterrupted(InterruptedError):
    """The fixture's own TERM handler, not an arbitrary OS read/write failure."""


def interrupted(_signal, _frame):
    raise FixtureInterrupted('fixture interrupted')


def failure_code(error):
    # Exact fixed messages only; never export arbitrary exception strings or CLI output.
    if isinstance(error, FixtureInterrupted):
        return 'termination_signal'
    if isinstance(error, subprocess.TimeoutExpired):
        return 'cli_timeout'
    if isinstance(error, subprocess.SubprocessError):
        return 'cli_process'
    if isinstance(error, OSError):
        return 'local_io'
    return FAILURE_CODES.get(str(error), 'unclassified')


def bounded_count(value, maximum):
    return value if type(value) is int and 0 <= value <= maximum else None


def turn_checkpoint(value):
    value = value if isinstance(value, dict) else {}
    TURN_DIAGNOSTIC['cursor_after'] = bounded_count(value.get('turns'), MAX_CURSOR)
    stage = value.get('stage')
    TURN_DIAGNOSTIC['checkpoint_stage'] = stage if stage in (
        'enrolled', 'owner_locked', 'working', 'paused', 'enrollment_expired',
        'core_unavailable', 'core_turn_revoked', 'turn_completed', 'retry_pending') else None
    detail = value.get('detail')
    stage = detail.get('maintenance_stage') if isinstance(detail, dict) else None
    TURN_DIAGNOSTIC['maintenance_stage'] = stage if stage in (
        'observed', 'maintained', 'charge_limit', 'grant_refresh_required') else None


def retirement_counts(value, turn):
    global RETIREMENT_DIAGNOSTIC
    value = value if isinstance(value, dict) else {}
    RETIREMENT_DIAGNOSTIC = dict(turn=bounded_count(turn, 4),
        pending_retirements=bounded_count(value.get('pending_retirements'), 4),
        placement_authorizations=bounded_count(value.get('placement_authorizations'), 4),
        retained_copy_records=bounded_count(value.get('retained_copy_records'), 12))


def renewal_outcomes(value):
    """Only fixed engine outcomes; at most three retained copies in this fixture."""
    if not isinstance(value, list) or len(value) > 3:
        return None
    return [item if item in ('retiring_not_renewed', 'explicitly_deleted',
        'unavailable_or_grant_invalid', 'unknown_reservation_use_deposit_retry',
        'unconfirmed_retained', 'renewal_outside_original_grant',
        'existing_retention_sufficient', 'confirmed') else None for item in value]


def handoff_outcomes(value):
    """One admitted handoff per turn, without keys, archive IDs or free-form errors."""
    if not isinstance(value, list) or len(value) > 1:
        return None
    result = []
    for item in value:
        item = item if isinstance(item, dict) else {}
        stage = item.get('handoff_stage')
        result.append(dict(index=bounded_count(item.get('index'), len(LENGTHS) - 1),
            handoff_stage=stage if stage in ('complete', 'survivor_unavailable',
                'replacement_upload_pending', 'replacement_verification_pending',
                'replacement_retention_insufficient', 'source_delete_unconfirmed') else None,
            resumed_signed_intent=item.get('resumed_signed_intent')
                if type(item.get('resumed_signed_intent')) is bool else None,
            replacement_verified_this_pass=item.get('replacement_verified_this_pass')
                if type(item.get('replacement_verified_this_pass')) is bool else None,
            operation_complete=item.get('operation_complete')
                if type(item.get('operation_complete')) is bool else None))
    return result


def retirement_turn(value, turn, *, target=None, maximum=4):
    """Project existing owner checkpoint fields, never the private checkpoint itself."""
    target = RETIREMENT_TURNS if target is None else target
    if type(turn) is not int or not 1 <= turn <= maximum or len(target) >= maximum:
        return
    value = value if isinstance(value, dict) else {}
    detail = value.get('detail')
    detail = detail if isinstance(detail, dict) else {}
    refresh = detail.get('refresh')
    refresh = refresh if isinstance(refresh, dict) else {}
    stage = detail.get('repair_stage')
    maintenance = detail.get('maintenance_stage')
    target.append(dict(turn=turn, cursor=bounded_count(value.get('turns'), MAX_CURSOR),
        maintenance_stage=maintenance if maintenance in (
            'observed', 'maintained', 'charge_limit', 'grant_refresh_required') else None,
        repair_stage=stage if stage in ('complete', 'repair_pending', 'pass_limit',
            'pending_grant_unavailable', 'no_eligible_candidate', 'pending_handoff',
            'retirement_pending') else None,
        attempted_handoffs=bounded_count(detail.get('attempted_handoffs'), 1),
        freshly_verified_replacements=bounded_count(detail.get('freshly_verified_replacements'), 1),
        pending_retirements=bounded_count(detail.get('pending_retirements'), 4),
        physical_payload_charge_upper_bound=bounded_count(
            detail.get('physical_payload_charge_upper_bound'), MAX_CHARGE),
        fragment_outcomes=handoff_outcomes(detail.get('fragment_outcomes')),
        refresh=dict(fragment_index=bounded_count(refresh.get('fragment_index'), len(LENGTHS) - 1),
            renewal=refresh.get('renewal') if type(refresh.get('renewal')) is bool else None,
            operation_complete=refresh.get('operation_complete')
                if type(refresh.get('operation_complete')) is bool else None,
            copy_outcomes=renewal_outcomes(refresh.get('copy_outcomes')))))


def failure_receipt(error):
    if LIFECYCLE_DIAGNOSTIC is not None:
        return dict(version=3, success=False, kind='private-storage-maintenance-lifecycle-failure',
            code='sampler_failure' if isinstance(error, SAMPLER['SamplerFailure']) else failure_code(error),
            **LIFECYCLE_DIAGNOSTIC, sampler=SAMPLER_DIAGNOSTIC or None)
    upload = UPLOAD_DIAGNOSTIC if STAGE == 'upload' else None
    return dict(version=3 if upload is not None else 2, success=False,
        kind='private-storage-maintenance-failure', stage=STAGE,
        code='sampler_failure' if isinstance(error, SAMPLER['SamplerFailure']) else failure_code(error),
        turn=TURN_DIAGNOSTIC, retirement=RETIREMENT_DIAGNOSTIC,
        retirement_turns=RETIREMENT_TURNS, repair=REPAIR_DIAGNOSTIC, repair_turns=REPAIR_TURNS,
        sampler=SAMPLER_DIAGNOSTIC or None, **(dict(upload=upload) if upload is not None else {}))


def upload_observation(operation, exit_status=None, stdout=None, stderr=None):
    """Project only this failed call; never return raw reports, identities or errors."""
    require(operation in UPLOAD_OPERATIONS, 'invalid upload operation')
    applicable = operation in ('deposit', 'redeposit')
    value = dict(operation=operation, exit_status=exit_status if type(exit_status) is int
        and -128 <= exit_status <= 255 else None,
        stdout_state='unavailable' if stdout is None else 'bounded' if len(stdout) <= 16384 else 'oversize',
        stderr_state='unavailable' if stderr is None else 'bounded' if len(stderr) <= 16384 else 'oversize',
        deposit_diagnostics_state='unavailable' if applicable else 'not_applicable',
        deposit_diagnostics=None)
    if not applicable or stdout is None:
        return value
    value['deposit_diagnostics_state'] = 'invalid'
    if value['stdout_state'] != 'bounded' or value['stderr_state'] == 'oversize':
        return value
    try:
        # Reject duplicate keys too: this is a diagnostic projection, not a
        # second interpretation of ambiguous externally controlled JSON.
        def unique(pairs):
            result = {}
            for key, child in pairs:
                require(key not in result, 'duplicate upload field')
                result[key] = child
            return result

        report = json.loads(stdout, object_pairs_hook=unique)
        require(type(report) is dict
            and report.get('operation') == 'private_storage_fragments_deposit'
            and report.get('operation_complete') is False
            and type(report.get('fragment_count')) is int and report['fragment_count'] == 4
            and type(report.get('copies_per_fragment')) is int and report['copies_per_fragment'] == 2,
            'upload report binding')
        if 'deposit_diagnostics' not in report:
            value['deposit_diagnostics_state'] = 'missing'
            return value
        diagnostic = report['deposit_diagnostics']
        require(type(diagnostic) is dict, 'invalid deposit diagnostics')
        CONSUMERS['APP']['validate_deposit_diagnostics'](diagnostic, diagnostic.get('version'))
        value.update(deposit_diagnostics_state='observed', deposit_diagnostics=diagnostic)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        pass
    return value


def upload_invoke(operation, binary, socket, arguments, **options):
    global UPLOAD_DIAGNOSTIC
    # Assign before spawn/communicate, so timeout or local I/O cannot inherit
    # the preceding call's label or receipt. Observer lifetime is one call.
    UPLOAD_DIAGNOSTIC = upload_observation(operation)

    def failed(status, stdout, stderr):
        global UPLOAD_DIAGNOSTIC
        UPLOAD_DIAGNOSTIC = upload_observation(operation, status, stdout, stderr)

    return invoke(binary, socket, arguments, failure_observer=failed, **options)


def validate_lifecycle_failure(value):
    """Reject rather than copy unknown fields from even fixture-owned output."""
    require(isinstance(value, dict) and type(value.get('version')) is int
        and value['version'] in (1, 2, 3), 'invalid lifecycle failure')
    fields = {'version', 'success', 'kind', 'code', 'stage',
        'cursor_before', 'cursor_last', 'checkpoint_stage', 'owner_exit_status', 'owner_joined',
        'cleanup_error', 'sampler'}
    if value['version'] >= 2:
        fields.add('retained_status')
    if value['version'] == 3:
        fields.update(('retained_status_scope', 'reconcile_status', 'fresh_turn_detail', 'baseline_reason'))
    require(set(value) == fields, 'invalid lifecycle failure')
    codes = set(FAILURE_CODES.values()) | {'cli_timeout', 'cli_process', 'local_io', 'unclassified',
        'sampler_failure', 'termination_signal'}
    require(value['success'] is False
        and value['kind'] == 'private-storage-maintenance-lifecycle-failure'
        and value['stage'] in LIFECYCLE_STAGES and value['code'] in codes, 'invalid lifecycle failure')
    for key in ('cursor_before', 'cursor_last'):
        require(value[key] is None or type(value[key]) is int and 0 <= value[key] <= MAX_LIFECYCLE_CURSOR,
            'invalid lifecycle failure')
    require(value['checkpoint_stage'] is None or value['checkpoint_stage'] in CHECKPOINT_STAGES,
        'invalid lifecycle failure')
    require(value['owner_exit_status'] is None or type(value['owner_exit_status']) is int
        and -128 <= value['owner_exit_status'] <= 255, 'invalid lifecycle failure')
    require(type(value['owner_joined']) is bool and (value['cleanup_error'] is None
        or value['cleanup_error'] in codes), 'invalid lifecycle failure')
    if value['version'] >= 2 and value['retained_status'] is not None:
        validate_retained_status(value['retained_status'])
    if value['version'] == 3:
        require(value['retained_status_scope'] == 'core_loss'
            and (value['baseline_reason'] is None or type(value['baseline_reason']) is str
                and value['baseline_reason'] in BASELINE_REASONS), 'invalid lifecycle reconciliation')
        if value['reconcile_status'] is not None:
            validate_reconcile_status(value['reconcile_status'])
        if value['fresh_turn_detail'] is not None:
            validate_fresh_turn_detail(value['fresh_turn_detail'])
        require(len(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()) <= 8192,
            'invalid lifecycle failure bound')
    sampler = value['sampler']
    if sampler is not None:
        fields = {'phase', 'operation', 'code', 'samples', 'completed', 'failed'}
        require(isinstance(sampler, dict) and fields <= set(sampler)
            and set(sampler) <= fields | {'route_mismatch', 'paths_process', 'route_comparison'}, 'invalid lifecycle sampler')
        require(sampler['phase'] in ('initial', 'sampling', 'final_drain')
            and sampler['operation'] in ('route_query', 'route_scope', 'exit_log_query', 'coverage', 'completion')
            and sampler['code'] in ('timeout', 'process', 'local_io', 'invalid', 'deadline'), 'invalid lifecycle sampler')
        for name, maximum in (('samples', SAMPLER['MAX_SAMPLES']),
                ('completed', SAMPLER['MAX_SAMPLES'] * SAMPLER['LIMIT']),
                ('failed', SAMPLER['MAX_SAMPLES'] * SAMPLER['LIMIT'])):
            require(type(sampler[name]) is int and 0 <= sampler[name] <= maximum, 'invalid lifecycle sampler')
        if 'route_mismatch' in sampler:
            require(sampler['route_mismatch'] in ('reply_bound', 'line_format', 'path_state', 'zero_context',
                'exit_changed', 'context_count', 'path_count', 'path_ids_changed', 'relays_changed'), 'invalid lifecycle sampler')
        if 'paths_process' in sampler:
            paths = sampler['paths_process']
            require(isinstance(paths, dict) and set(paths) == {'exit_status', 'diagnostic', 'stderr_state'}
                and (paths['exit_status'] is None or type(paths['exit_status']) is int and -128 <= paths['exit_status'] <= 255)
                and paths['diagnostic'] in ('UNRECOGNIZED', 'CLIENT_ROUTE_BUSY', 'MPQUIC_PATH_STATUS_UNAVAILABLE')
                and paths['stderr_state'] in ('unavailable', 'oversize', 'bounded'), 'invalid lifecycle sampler')
        if 'route_comparison' in sampler:
            comparison = sampler['route_comparison']
            require(sampler['operation'] == 'route_scope' and sampler['code'] == 'invalid'
                and sampler.get('route_mismatch') == 'relays_changed'
                and isinstance(comparison, dict)
                and set(comparison) == {'context_relation', 'relay_set_relation'}
                and comparison['context_relation'] in ('same', 'changed', 'unobserved')
                and comparison['relay_set_relation'] in ('same', 'changed'), 'invalid lifecycle sampler')
    return value


def lifecycle_failure_file(path):
    return validate_lifecycle_failure(json.loads(closed_diagnostic_text(path, 8192)))


OWNER_TEST_PREFIX = 'storage::peer::replicas::fragments::maintenance::tests::'
OWNER_REQUIRED_TESTS = {
    'enrollment_signature_private_mode_and_restart_cursor_are_retained',
    'owner_maintenance_renews_repairs_one_copy_and_retains_uncertain_charge_across_restart',
    'three_provider_maintenance_retires_all_originals_with_exact_candidate_grants',
    'service::owner_loop_reconnects_without_reenrollment_and_preserves_restart_cursor',
    'service::shutdown_during_reconnect_keeps_authority_and_retained_charge_for_restart',
    'service::expired_enrollment_never_reconnects_or_advances_work',
    'service::live_turn_loss_reconnects_and_reconciles_original_journals_without_new_leases',
    'service::finite_authority_expires_while_waiting_for_core_response_and_closes_connection',
    'expiry::expired_cap_cannot_plan_and_foreground_expiry_is_unchanged',
    'expiry::expired_during_challenge_does_not_sign_any_new_operation',
    'expiry::signing_does_not_rewrite_over_cap_retained_reserve_or_renew',
    'expiry::delayed_progress_renewal_keeps_original_signed_enrollment_expiry',
    'expiry::repair_after_delayed_refresh_keeps_original_signed_enrollment_expiry',
}


def owner_test_output(stream, diagnostic=None):
    """Bound actual libtest stdout; require executed named passes, not a --list."""
    data = stream.read(65537)
    if diagnostic is not None:
        # Preserve ordinary synthetic unit-test diagnostics, never owner runtime
        # output. This is bounded CI logging, not an artifact or passing receipt.
        suffix = b'\nOWNER_TEST_OUTPUT_LIMIT_EXCEEDED\n' if len(data) > 65536 else b''
        diagnostic.write(data[:65536 - len(suffix)] + suffix)
        diagnostic.flush()
    require(len(data) <= 65536, 'owner test output bound')
    text = data.decode('utf-8')
    rows = re.findall(r'^test ([a-zA-Z0-9_:]+) \.\.\. (ok|FAILED|ignored)$', text, re.M)
    require(0 < len(rows) <= 256 and len({name for name, _ in rows}) == len(rows)
        and all(name.startswith(OWNER_TEST_PREFIX) and result == 'ok' for name, result in rows)
        and {OWNER_TEST_PREFIX + name for name in OWNER_REQUIRED_TESTS} <= {name for name, _ in rows},
        'required owner tests did not execute')
    summaries = re.findall(r'^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; '
        r'[0-9]+ filtered out; finished in [0-9.]+s$', text, re.M)
    require(summaries == [str(len(rows))], 'owner test result mismatch')
    return dict(version=1, kind='executed-owner-maintenance-tests', passed=len(rows),
        required_passed=len(OWNER_REQUIRED_TESTS), failed=0, ignored=0)


def private_json(path, maximum=32768):
    require(private_file(path).st_size <= maximum, 'private record bound')
    return json.loads(path.read_bytes())


def existing(root):
    return F['existing'](root)


def status(root, binary, client, *, budget=None):
    return invoke(binary, client, ['storage', 'fragments', 'status', '--state', root / 'fragment-set'],
        deadline=180 if budget is None else budget.remaining(180))


def checkpoint(root, binary, client, *, budget=None):
    value = invoke(binary, client, ['storage', 'fragments', 'maintenance', 'status',
        '--enrollment', root / 'maintenance'], deadline=180 if budget is None else budget.remaining(180))
    require(value['version'] == 1 and value['scope'] == 'owner-private-maintenance'
        and type(value['turns']) is int and 0 <= value['turns'] <= MAX_CURSOR
        and value['core_coordinated'] is True and value['new_network_node'] is False
        and value['automatic_grant_refresh'] is False and value['private_key_exported'] is False,
        'maintenance checkpoint scope')
    return value


def peer_args(root, key):
    return ['--state', root / 'foreground', '--provider-key', key, *unlock(root)]


def run_turn(root, binary, client, key_b, interrupt=None, *, budget=None):
    """One real daemon-issued turn; no owner-side scheduler or direct provider socket."""
    global TURN_DIAGNOSTIC
    TURN_DIAGNOSTIC = dict(substage='checkpoint_before', cursor_before=None, cursor_after=None,
        worker_exit_status=None, checkpoint_stage=None, maintenance_stage=None, cleanup_error=None)
    before = checkpoint(root, binary, client, budget=budget)['turns']
    TURN_DIAGNOSTIC.update(cursor_before=before, substage='spawn_owner')
    process = subprocess.Popen([binary, '--control-socket', client, 'storage', 'fragments',
        'maintenance', 'serve', '--enrollment', str(root / 'maintenance'), '--maximum-turns', '1',
        *map(str, unlock(root))], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    owner_failed = False
    try:
        if interrupt:
            TURN_DIAGNOSTIC['substage'] = 'await_working'
            deadline = time.monotonic() + 100
            while True:
                current = private_json(root / 'maintenance/checkpoint.json')
                turn_checkpoint(current)
                if current['turns'] == before + 1 and current['stage'] == 'working':
                    break
                require(process.poll() is None and time.monotonic() < deadline, 'core turn not observed')
                time.sleep(0.02)
            if interrupt == 'eof':
                # Kill only the exact fixture-owned CLI. Its live Unix connections close;
                # the subsequent fresh core turn proves release of the retained slot/lane.
                process.kill()
            else:
                require(interrupt == 'foreground', 'unknown interruption')
                TURN_DIAGNOSTIC['substage'] = 'foreground_operation'
                foreground = invoke(binary, client, ['storage', 'peer', 'progress', *peer_args(root, key_b)])
                require(foreground['committed'] is True and foreground['stored_bytes'] == len(FG),
                    'independent foreground operation not acknowledged')
        TURN_DIAGNOSTIC['substage'] = 'join_owner'
        stdout, stderr = process.communicate(timeout=650 if budget is None else budget.remaining(650))
        TURN_DIAGNOSTIC['worker_exit_status'] = process.returncode if -128 <= process.returncode <= 255 else None
        TURN_DIAGNOSTIC['substage'] = 'validate_owner_exit'
        require(len(stdout) <= 32768 and len(stderr) <= 16384, 'bounded owner output')
        require(process.returncode == (-signal.SIGKILL if interrupt == 'eof' else 0), 'owner process exit')
        TURN_DIAGNOSTIC['substage'] = 'checkpoint_after'
        result = checkpoint(root, binary, client, budget=budget)
        turn_checkpoint(result)
        TURN_DIAGNOSTIC['substage'] = 'validate_cursor_and_stage'
        require(result['turns'] == before + 1, 'cursor did not resume exactly one turn')
        if interrupt == 'eof':
            require(result['stage'] == 'working', 'owner EOF was not during an admitted turn')
        elif interrupt == 'foreground':
            require(result['stage'] == 'core_turn_revoked', 'foreground did not revoke the core turn')
        else:
            require(result['stage'] == 'turn_completed' and result['detail']['maintenance_stage'] in
                ('observed', 'maintained'), 'maintenance did not complete a core turn')
        return result
    except BaseException:
        owner_failed = True
        raise
    finally:
        try:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as error:
            TURN_DIAGNOSTIC['cleanup_error'] = failure_code(error)
            if not owner_failed:
                raise


class OwnerProcess:
    """Own and drain the real finite-enrollment CLI; never export private output."""
    LIMIT = 262144

    def __init__(self, command):
        self.buffers = [bytearray(), bytearray()]
        self.overflow = [False, False]
        self.lock = threading.Lock()
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.threads = []
        try:
            for index, stream in enumerate((self.process.stdout, self.process.stderr)):
                thread = threading.Thread(target=self._drain, args=(index, stream))
                thread.start()
                self.threads.append(thread)
        except BaseException:
            self.close()
            raise

    def _drain(self, index, stream):
        try:
            with stream:
                while chunk := stream.read1(4096):
                    with self.lock:
                        available = self.LIMIT - len(self.buffers[index])
                        self.buffers[index].extend(chunk[:available])
                        self.overflow[index] |= len(chunk) > available
        except OSError:
            self.overflow[index] = True

    def reports(self):
        with self.lock:
            require(not any(self.overflow), 'bounded owner output')
            data = bytes(self.buffers[0])
        rows = data.split(b'\n')[:-1]
        require(len(rows) <= MAX_LIFECYCLE_CURSOR, 'bounded owner output')
        return [json.loads(row) for row in rows if row]

    def stop(self):
        self.process.send_signal(signal.SIGTERM)
        require(self.process.wait(timeout=10) == 0, 'owner process exit')
        self.join()

    def join(self):
        for thread in self.threads:
            thread.join(timeout=5)
            require(not thread.is_alive(), 'owner output not drained')
        require(not any(self.overflow), 'bounded owner output')

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.join()


class LifecycleBudget:
    """One original signed expiry and monotonic fixture deadline, never renewed."""
    def __init__(self, expires):
        require(type(expires) is int and expires > 0, 'invalid lifecycle enrollment expiry')
        self.expires = expires
        self.deadline = time.monotonic() + min(LIFECYCLE_SECONDS, max(0, expires - time.time()))

    def remaining(self, maximum):
        # Recheck wall time as well: a forward clock change cannot enlarge the
        # original signed authorization; rollback cannot extend the monotonic cap.
        remaining = min(maximum, self.deadline - time.monotonic(), self.expires - time.time())
        require(remaining > 0, 'owner lifecycle deadline')
        return remaining


def wait_owner(owner, predicate, seconds=180, *, budget=None):
    deadline = time.monotonic() + (seconds if budget is None else budget.remaining(seconds))
    while time.monotonic() < deadline:
        if budget is not None:
            budget.remaining(seconds)
        require(owner.process.poll() is None, 'owner process exit')
        value = predicate()
        if value:
            if budget is not None:
                budget.remaining(seconds)
            return value
        time.sleep(.05)
    raise ValueError('owner lifecycle deadline')


CHARGE_STATES = ('unattempted', 'reserved', 'committed', 'uncertain', 'deleted', 'unknown')
RETAINED_BYTES = ('physical_payload_charge_upper_bound', 'reserved_payload_bytes',
    'committed_payload_bytes', 'uncertain_payload_bytes')


def retained_status_diagnostic(value, now):
    """Project one existing status response, never journals, keys or lease IDs.

    Missing/malformed details remain unknown; no remote availability is inferred
    from locally retained expiries. Limits only bound diagnostics, not acceptance.
    """
    is_object = isinstance(value, dict)
    value = value if is_object else {}
    result = {key: bounded_count(value.get(key), 2**64 - 1) for key in RETAINED_BYTES}
    result.update(fragment_count=None, copy_counts=None,
        placement_field_present='placement_authorizations' in value if is_object else None,
        placement_authorizations=bounded_count(value.get('placement_authorizations', 0), 4096) if is_object else None,
        charge_states=None, retained_expiries=None)
    fragments = value.get('fragments')
    if not isinstance(fragments, list) or len(fragments) > 64:
        return result
    result['fragment_count'] = len(fragments)
    copies = [item.get('copies') if isinstance(item, dict) else None for item in fragments]
    result['copy_counts'] = [len(items) if isinstance(items, list) and len(items) <= 64 else None
        for items in copies]
    if None in result['copy_counts']:
        return result
    charges = dict.fromkeys(CHARGE_STATES, 0)
    expiries = dict.fromkeys(('expired', 'unexpired', 'unknown'), 0)
    for items in copies:
        for item in items:
            item = item if isinstance(item, dict) else {}
            charge = item.get('charge')
            charges[charge if type(charge) is str and charge in CHARGE_STATES else 'unknown'] += 1
            expiry = bounded_count(item.get('last_confirmed_expiry'), 2**64 - 1)
            state = ('unknown' if not expiry or type(now) is not int or now < 0
                else 'unexpired' if expiry > now else 'expired')
            expiries[state] += 1
    result.update(charge_states=charges, retained_expiries=expiries)
    return result


def validate_retained_status(value):
    fields = set(RETAINED_BYTES) | {'fragment_count', 'copy_counts', 'placement_field_present',
        'placement_authorizations', 'charge_states', 'retained_expiries'}
    require(isinstance(value, dict) and set(value) == fields, 'invalid retained status diagnostic')
    for name in RETAINED_BYTES + ('fragment_count', 'placement_authorizations'):
        maximum = 64 if name == 'fragment_count' else 4096 if name == 'placement_authorizations' else 2**64 - 1
        require(value[name] is None or bounded_count(value[name], maximum) == value[name]
            and type(value[name]) is int, 'invalid retained status diagnostic')
    require(value['placement_field_present'] is None or type(value['placement_field_present']) is bool,
        'invalid retained status diagnostic')
    counts = value['copy_counts']
    require(counts is None and value['fragment_count'] is None or isinstance(counts, list)
        and len(counts) == value['fragment_count'] and all(count is None or type(count) is int
            and 0 <= count <= 64 for count in counts), 'invalid retained status diagnostic')
    total = sum(counts) if counts is not None and None not in counts else None
    for key, keys in (('charge_states', CHARGE_STATES), ('retained_expiries', ('expired', 'unexpired', 'unknown'))):
        detail = value[key]
        require(detail is None if total is None else isinstance(detail, dict) and set(detail) == set(keys)
            and all(type(count) is int and 0 <= count <= 4096 for count in detail.values())
            and sum(detail.values()) == total, 'invalid retained status diagnostic')


def reconcile_status_diagnostic(value, now):
    """The later progress response, separate from the core-loss observation."""
    value = value if type(value) is dict else {}
    return dict(status=retained_status_diagnostic(value, now),
        pending_retirements=bounded_count(value.get('pending_retirements'), 4096),
        retained_copy_records=bounded_count(value.get('retained_copy_records'), 4096),
        fully_redundant_from_retained_receipts=value.get('fully_redundant_from_retained_receipts')
            if type(value.get('fully_redundant_from_retained_receipts')) is bool else None,
        fragments_with_confirmed_unexpired_copy=bounded_count(value.get('fragments_with_confirmed_unexpired_copy'), 64))


def validate_reconcile_status(value):
    require(type(value) is dict and set(value) == {'status', 'pending_retirements', 'retained_copy_records',
        'fully_redundant_from_retained_receipts', 'fragments_with_confirmed_unexpired_copy'},
        'invalid lifecycle reconciliation')
    validate_retained_status(value['status'])
    for name, maximum in (('pending_retirements', 4096), ('retained_copy_records', 4096),
            ('fragments_with_confirmed_unexpired_copy', 64)):
        require(value[name] is None or type(value[name]) is int and 0 <= value[name] <= maximum,
            'invalid lifecycle reconciliation')
    require(value['fully_redundant_from_retained_receipts'] is None
        or type(value['fully_redundant_from_retained_receipts']) is bool, 'invalid lifecycle reconciliation')


def fresh_turn_diagnostic(value):
    # Reuse the existing bounded turn projection; relative turn=1 is this one
    # already completed fresh process, not another operation or retry.
    rows = []
    retirement_turn(value, 1, target=rows, maximum=1)
    result = rows[0]
    del result['turn']
    stage = value.get('stage') if type(value) is dict else None
    result['checkpoint_stage'] = stage if type(stage) is str and stage in CHECKPOINT_STAGES else None
    return result


def validate_fresh_turn_detail(value):
    require(type(value) is dict and set(value) == {'cursor', 'checkpoint_stage', 'maintenance_stage',
        'repair_stage', 'attempted_handoffs', 'freshly_verified_replacements', 'pending_retirements',
        'physical_payload_charge_upper_bound', 'fragment_outcomes', 'refresh'}, 'invalid fresh lifecycle turn')
    # Projection is idempotent only for the closed original domains/bounds.
    reconstructed = dict(turns=value['cursor'], stage=value['checkpoint_stage'],
        detail={key: item for key, item in value.items() if key not in ('cursor', 'checkpoint_stage')})
    require(json.dumps(value, sort_keys=True, allow_nan=False)
        == json.dumps(fresh_turn_diagnostic(reconstructed), sort_keys=True, allow_nan=False),
        'invalid fresh lifecycle turn')


def observe_lifecycle(name, projector, *arguments):
    """Best effort over already available values; never mask a trial failure."""
    if LIFECYCLE_DIAGNOSTIC is None:
        return
    try:
        LIFECYCLE_DIAGNOSTIC[name] = projector(*arguments)
    except (KeyError, TypeError, ValueError, OverflowError):
        LIFECYCLE_DIAGNOSTIC[name] = None


def retained_during_core_loss(retained):
    """Historical counter-only contract; current lifecycle uses the bound check below."""
    if LIFECYCLE_DIAGNOSTIC is not None:
        LIFECYCLE_DIAGNOSTIC['retained_status'] = retained_status_diagnostic(retained, int(time.time()))
    # Original placements have the unchanged v1 report shape: v2-only repair
    # history fields do not exist until the first signed replacement is retained.
    require(retained['physical_payload_charge_upper_bound'] == 2 * BYTES, 'core loss changed charged custody')
    require(len(retained['fragments']) == 4, 'core loss changed fragment count')
    require(all(len(fragment['copies']) == 2 for fragment in retained['fragments']), 'core loss changed copy count')
    require(retained.get('placement_authorizations', 0) == 0, 'core loss changed placement count')


RETAINED_INTENT_FILE = 'lifecycle-retained-intent.json'
INTENT_IDENTITY_FIELDS = ('version', 'provider_key', 'owner_key', 'grant_hex', 'archive_id',
    'ciphertext_bytes', 'sha256', 'requested_expiry')


def retained_intent_binding(root, entry):
    # Renew changes last_expiry, not requested_expiry. Rust's signed-placement
    # open also requires the initial requested_expiry to remain byte-identical.
    journal = private_json(root / 'fragment-set/fragment-0000/copy-2/archive.json', 16384)
    initial = entry['handoff']['initial_journal']
    require(all(journal[key] == initial[key] for key in INTENT_IDENTITY_FIELDS),
        'retained intent changed after core restart')
    return dict(authorization_sha256=identity_sha(entry),
        initial_identity_sha256=identity_sha({key: journal[key] for key in INTENT_IDENTITY_FIELDS}))


def retained_intent_continuity(root):
    """Private hash continuity only; the preceding real CLI authenticates signed state."""
    binding = private_json(root / RETAINED_INTENT_FILE, 2048)
    require(set(binding) == {'version', 'pending'} and type(binding['version']) is int
        and binding['version'] == 1, 'retained intent changed after core restart')
    pending = binding['pending']
    if pending is None:
        return
    require(type(pending) is dict and set(pending) == {'authorization_sha256', 'initial_identity_sha256'}
        and all(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) for digest in pending.values()),
        'retained intent changed after core restart')
    entries = private_json(root / 'fragment-set/placement-authorizations.json', 1048576)['authority']['placements']
    require(type(entries) is list and 1 <= len(entries) <= 3
        and sum(entry['fragment'] == 0 for entry in entries) == 1,
        'retained intent changed after core restart')
    entry = next(entry for entry in entries if entry['fragment'] == 0)
    require(retained_intent_binding(root, entry) == pending, 'retained intent changed after core restart')


def retained_current_during_core_loss(root, retained, keys, enrollment):
    """Preserve all original custody; admit only the first signed, unattempted A→C intent.

    Status opens and verifies the actual Rust signed root/placement/child binding;
    this Python check narrows that authority to the unchanged fixture enrollment.
    It does not implement signature verification or infer remote availability.
    """
    if LIFECYCLE_DIAGNOSTIC is not None:
        LIFECYCLE_DIAGNOSTIC['retained_status'] = retained_status_diagnostic(retained, int(time.time()))
    F['check_identity'](root)
    require(closed_diagnostic_text(root / 'maintenance/enrollment.json', 32768).encode() == enrollment,
        'core loss changed enrollment')
    en = json.loads(enrollment)['enrollment']
    original_raw = closed_diagnostic_text(root / 'fragment-set/fragments.json', 1048576).encode()
    original = json.loads(original_raw)['manifest']
    now = int(time.time())
    grants = []
    for label in 'bc':
        path = root / f'grant-{label}.bin'
        require(private_file(path).st_size <= 2048, 'core loss retained intent invalid')
        grants.append(path.read_bytes().hex())
    require(en['version'] == 1 and en['created'] <= now < en['expires']
        and en['owner'] == original['owner_key'] and bytes(en['source']).hex() == keys[0]
        and [bytes(key).hex() for key in en['providers']] == list(keys[1:]) and en['grants'] == grants
        and bytes(en['root']).hex() == hashlib.sha256(original_raw).hexdigest()
        and en['maximum_charged'] == MAX_CHARGE,
        'core loss retained intent invalid')
    require(retained['operation'] == 'private_storage_fragments_status'
        and retained['owner_signature_verified'] is True
        and retained['logical_ciphertext_bytes'] == BYTES and retained['copies_per_fragment'] == 2,
        'core loss retained intent invalid')
    require(len(retained['fragments']) == retained['fragment_count'] == 4, 'core loss changed fragment count')
    pending = retained.get('placement_authorizations', 0)
    require(type(pending) is int and pending in (0, 1), 'core loss changed placement count')
    charges, providers = dict(committed=0, uncertain=0), [0, 0, 0]
    for index, fragment in enumerate(retained['fragments']):
        require(fragment['index'] == index and fragment['offset'] == sum(LENGTHS[:index])
            and fragment['ciphertext_bytes'] == LENGTHS[index], 'core loss changed fragment count')
        require(len(fragment['copies']) == 2 + (pending if index == 0 else 0), 'core loss changed copy count')
        for copy_index, copy in enumerate(fragment['copies'][:2]):
            provider = (index + copy_index) % 3
            require(copy['provider_key'] == keys[provider] and copy['charge'] in charges
                and copy['last_confirmed_state'] == 'Committed'
                and copy['last_confirmed_stored_bytes'] == LENGTHS[index]
                and copy['last_confirmed_expiry'] > now, 'core loss changed charged custody')
            charges[copy['charge']] += LENGTHS[index]
            providers[provider] += LENGTHS[index]
    require(retained['reserved_payload_bytes'] == 0
        and all(retained[name + '_payload_bytes'] == count for name, count in charges.items())
        and retained['physical_payload_charge_upper_bound'] == sum(charges.values()) == 2 * BYTES
        and retained['providers'] == [dict(provider_key=key, physical_payload_charge_upper_bound=count)
            for key, count in zip(keys, providers)], 'core loss changed charged custody')
    authority = root / 'fragment-set/placement-authorizations.json'
    if not pending:
        require(not authority.exists() and not authority.is_symlink(), 'core loss retained intent invalid')
        return dict(version=1, pending=None)
    require(retained.get('report_version') == 2 and retained.get('retained_copy_records') == 9
        and retained.get('pending_retirements') == 1 and retained.get('desired_copies_per_fragment') == 2
        and retained.get('replacement_overhead_included') is True, 'core loss retained intent invalid')
    signed = private_json(authority, 1048576)
    entries = signed['authority']['placements']
    require(signed['authority']['root_sha256'] == en['root'] and type(entries) is list and len(entries) == 1,
        'core loss retained intent invalid')
    entry = entries[0]
    intent = entry['handoff']
    initial = intent['initial_journal']
    child = private_json(root / 'fragment-set/fragment-0000/replicas.json')
    journal = private_json(root / 'fragment-set/fragment-0000/copy-2/archive.json', 16384)
    source = private_json(root / 'fragment-set/fragment-0000/copy-0/archive.json', 16384)
    original_archives = [copy['archive_id'] for fragment in original['fragments'] for copy in fragment['copies']]
    require(entry['fragment'] == 0 and intent['from'] == 0 and intent['to'] == 2
        and intent['phase'] == 'copying' and child['handoff'] == intent
        and len(child['copies']) == 3 and child['copies'][2] == dict(provider_key=initial['provider_key'],
            archive_id=initial['archive_id'], grant_sha256=list(hashlib.sha256(bytes.fromhex(grants[1])).digest()),
            charge='unattempted')
        and journal == initial and initial['version'] == 1
        and bytes(initial['provider_key']).hex() == keys[2] and initial['owner_key'] == en['owner']
        and len(initial['archive_id']) == 32 and any(initial['archive_id'])
        and initial['archive_id'] not in original_archives
        and initial['grant_hex'] == grants[1] and initial['ciphertext_bytes'] == LENGTHS[0]
        and initial['sha256'] == original['fragments'][0]['sha256']
        and en['created'] < initial['requested_expiry'] <= en['expires']
        and initial['requested_expiry'] >= max(source['requested_expiry'], source['last_expiry'])
        and initial['lease'] is None and initial['last_state'] is None
        and initial['last_stored_bytes'] == initial['last_expiry'] == 0,
        'core loss retained intent invalid')
    require(retained['fragments'][0]['copies'][2] == dict(provider_key=keys[2], charge='unattempted',
        last_confirmed_state=None, last_confirmed_stored_bytes=0, last_confirmed_expiry=0),
        'core loss retained intent invalid')
    return dict(version=1, pending=retained_intent_binding(root, entry))


def lifecycle(root, binary, client, keys):
    """A fixed external VM supervisor alone controls the core service."""
    global LIFECYCLE_DIAGNOSTIC
    LIFECYCLE_DIAGNOSTIC = dict(stage='checkpoint_before', cursor_before=None, cursor_last=None,
        checkpoint_stage=None, owner_exit_status=None, owner_joined=False, cleanup_error=None, retained_status=None,
        retained_status_scope='core_loss', reconcile_status=None, fresh_turn_detail=None, baseline_reason=None)
    enrollment = (root / 'maintenance/enrollment.json').read_bytes()
    budget = LifecycleBudget(json.loads(enrollment)['enrollment']['expires'])

    def observed_checkpoint():
        value = checkpoint(root, binary, client, budget=budget)
        LIFECYCLE_DIAGNOSTIC['cursor_last'] = bounded_count(value.get('turns'), MAX_LIFECYCLE_CURSOR)
        stage = value.get('stage')
        LIFECYCLE_DIAGNOSTIC['checkpoint_stage'] = stage if stage in CHECKPOINT_STAGES else None
        return value

    before = observed_checkpoint()['turns']
    LIFECYCLE_DIAGNOSTIC['cursor_before'] = before
    require(before == 3, 'lifecycle initial cursor')
    LIFECYCLE_DIAGNOSTIC['stage'] = 'spawn_owner'
    # Normal serve remains bounded by the same signed expiry and outer 1800s
    # fixture. An eight-turn trial cap could expire before supervisor readiness.
    owner = OwnerProcess([binary, '--control-socket', client, 'storage', 'fragments',
        'maintenance', 'serve', '--enrollment', str(root / 'maintenance'),
        *map(str, unlock(root))])
    owner_failed = False
    try:
        LIFECYCLE_DIAGNOSTIC['stage'] = 'await_working'
        working = wait_owner(owner, lambda: (v if (v := observed_checkpoint())['stage'] == 'working'
            and v['turns'] > before else None), budget=budget)
        create(root / 'lifecycle-working.json', b'{"ready":true}')
        LIFECYCLE_DIAGNOSTIC['stage'] = 'await_core_loss'
        lost = wait_owner(owner, lambda: (v if (v := observed_checkpoint())['stage'] == 'core_unavailable'
            and v['turns'] >= working['turns'] else None), budget=budget)
        LIFECYCLE_DIAGNOSTIC['stage'] = 'verify_retained'
        retained = status(root, binary, client, budget=budget)
        binding = retained_current_during_core_loss(root, retained, keys, enrollment)
        create(root / RETAINED_INTENT_FILE, json.dumps(binding, sort_keys=True).encode())
        F['check_identity'](root)
        require((root / 'maintenance/enrollment.json').read_bytes() == enrollment,
            'core loss changed enrollment')
        create(root / 'lifecycle-unavailable.json', b'{"ready":true}')
        # This is read-only coordination, not execution authority. The immutable
        # root-owned reply binds only the actual new fixture route and baseline.
        coordinator = Path(client).parents[2] / 'maintenance-coordinator'
        ready = coordinator / 'ready.json'
        LIFECYCLE_DIAGNOSTIC['stage'] = 'await_coordinator'
        wait_owner(owner, ready.exists, LIFECYCLE_SECONDS, budget=budget)
        LIFECYCLE_DIAGNOSTIC['stage'] = 'validate_coordinator'
        info = ready.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o640 and info.st_size <= 8192,
            'invalid fixture coordinator reply')
        control = read(ready)
        require(set(control) == {'baseline', 'scope'}, 'invalid fixture coordinator reply')
        SAMPLER['validate_route_scope'](control['scope'])
        exit_socket = Path(client).parents[2] / 'runtime-exit/control/agent.sock'
        after_ready = observed_checkpoint()['turns']
        LIFECYCLE_DIAGNOSTIC['stage'] = 'start_sampler'
        with SAMPLER['capture'](binary, exit_socket, control['baseline'], 1,
                client=Path(client), scope=control['scope'], diagnostic=SAMPLER_DIAGNOSTIC) as coverage:
            LIFECYCLE_DIAGNOSTIC['stage'] = 'await_resumed_turn'
            resumed = wait_owner(owner, lambda: next((v for v in owner.reports()
                if v['stage'] == 'turn_completed' and v['turns'] > after_ready), None), 650, budget=budget)
            LIFECYCLE_DIAGNOSTIC['stage'] = 'stop_owner'
            owner.stop()
            LIFECYCLE_DIAGNOSTIC['stage'] = 'verify_pause'
            paused = observed_checkpoint()
            require(paused['stage'] == 'paused' and paused['turns'] >= resumed['turns'],
                'SIGTERM did not persist pause')
            require((root / 'maintenance/enrollment.json').read_bytes() == enrollment,
                'enrollment changed across core restart')
            # Fresh process reconciles the original journals; no new enrollment.
            LIFECYCLE_DIAGNOSTIC['stage'] = 'fresh_owner_turn'
            restarted = run_turn(root, binary, client, keys[1], budget=budget)
            observe_lifecycle('fresh_turn_detail', fresh_turn_diagnostic, restarted)
            require(restarted['turns'] == paused['turns'] + 1, 'resume cursor changed')
            LIFECYCLE_DIAGNOSTIC['stage'] = 'reconcile_progress'
            current = invoke(binary, client, ['storage', 'fragments', 'progress', *existing(root)],
                deadline=budget.remaining(180))
            observe_lifecycle('reconcile_status', reconcile_status_diagnostic, current, int(time.time()))
            F['check_identity'](root)
            retained_intent_continuity(root)
            try:
                baseline = pre_withdrawal(root, current, keys)
            except (ValueError, KeyError, TypeError) as error:
                observe_lifecycle('baseline_reason', baseline_failure_reason, error)
                raise
            LIFECYCLE_DIAGNOSTIC['stage'] = 'validate_flow_coverage'
        gates = coverage.report(joined=coverage.joined)
        SAMPLER['validate_summary'](gates, control['baseline'], 1)
        create(root / 'flow-lifecycle.json', json.dumps(gates, sort_keys=True).encode())
        result = dict(cursor_before=before, cursor_at_core_loss=lost['turns'],
            cursor_after_reconnect=resumed['turns'], cursor_at_pause=paused['turns'],
            cursor_after_resume=restarted['turns'], same_owner_survived_core_loss=True,
            charge_retained_during_core_loss=True, journal_identity_retained_during_core_loss=True,
            core_unavailable_observed=True, fresh_core_turn_completed=True,
            sigterm_exit_zero=True, paused_checkpoint_retained=True,
            new_owner_process_resumed=True, enrollment_unchanged=True,
            original_identities_retained=True, physical_payload_charge=2 * BYTES,
            uncertainty_reconciled=True, owner_process_joined=True, pre_withdrawal=baseline)
        # Sampler finalization can consume time after the last owner operation;
        # it must not turn an expired trial into a successful lifecycle receipt.
        budget.remaining(LIFECYCLE_SECONDS)
        LIFECYCLE_DIAGNOSTIC['stage'] = 'publish_result'
        create(root / 'lifecycle-result.json', json.dumps(result, sort_keys=True).encode())
        return result
    except BaseException:
        owner_failed = True
        raise
    finally:
        try:
            owner.close()
            LIFECYCLE_DIAGNOSTIC['owner_joined'] = owner.process.poll() is not None
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            LIFECYCLE_DIAGNOSTIC['cleanup_error'] = failure_code(error)
            if not owner_failed:
                raise
        finally:
            code = owner.process.poll()
            LIFECYCLE_DIAGNOSTIC['owner_exit_status'] = code if type(code) is int and -128 <= code <= 255 else None


def prepare(root, binary, client, provider_a, provider_b, provider_c, key_a, key_b, key_c):
    global STAGE
    STAGE = 'prepare'
    keys = (key_a, key_b, key_c)
    require(not list(root.iterdir()) and len(set(keys)) == 3, 'fresh owner and providers required')
    create(root / 'input.bin', F['FIXTURE'])
    create(root / 'foreground.bin', FG)
    create(root / 'passphrase', base64.b64encode(os.urandom(48)) + b'\n')
    invoke(binary, client, ['init', *unlock(root)], raw=True)
    owner = invoke(binary, client, ['content', 'recipient-key', *unlock(root)])['identity_public_key_hex']
    require(re.fullmatch('[0-9a-f]{64}', owner) and owner not in keys, 'distinct owner required')
    for label, control, key in zip('abc', (provider_a, provider_b, provider_c), keys):
        grant = invoke(binary, control, ['storage', 'peer', 'grant', '--provider-key', key,
            '--owner-key', owner, '--max-payload-bytes', BYTES, '--max-leases', 4,
            '--max-retention-seconds', 7200, '--lifetime-seconds', 7200,
            '--output', root / f'grant-{label}.bin'])
        require(grant['grant_written'] is True and grant['max_payload_bytes'] == BYTES
            and grant['max_leases'] == 4 and grant['reserved_bytes'] == 0
            and grant['network_contribution_credit'] is False, 'bounded provider grant')
    grant = invoke(binary, provider_b, ['storage', 'peer', 'grant', '--provider-key', key_b,
        '--owner-key', owner, '--max-payload-bytes', len(FG), '--max-leases', 1,
        '--max-retention-seconds', 7200, '--lifetime-seconds', 7200,
        '--output', root / 'foreground-grant.bin'])
    require(grant['grant_written'] is True and grant['max_payload_bytes'] == len(FG)
        and grant['max_leases'] == 1, 'independent foreground grant')
    return dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, fragment_lengths=list(LENGTHS),
        providers=3, copies_per_fragment=2, grant_payload_bytes=[BYTES] * 3, grant_max_leases=[4] * 3,
        independent_foreground_bytes=len(FG), owner_distinct_from_all_providers=True, owner_secrets_exported=False)


def upload(root, binary, client, keys):
    global STAGE, UPLOAD_DIAGNOSTIC
    STAGE = 'upload'
    UPLOAD_DIAGNOSTIC = None
    # Existing real foreground deposit/retry/renew/progress, immutable identity checks,
    # and deletion of the original local bytes. Grants reserve no extra physical bytes.
    uploaded = F['upload'](root, binary, client, keys, invoke_operation=upload_invoke)
    foreground = upload_invoke('foreground_seed', binary, client, ['storage', 'peer', 'deposit', *peer_args(root, keys[1]),
        '--grant', root / 'foreground-grant.bin', '--input', root / 'foreground.bin',
        '--sha256', hashlib.sha256(FG).hexdigest(), '--already-encrypted', '--lifetime-seconds', 5400])
    require(foreground['committed'] is True and foreground['stored_bytes'] == len(FG), 'foreground seed')
    (root / 'foreground.bin').unlink()
    UPLOAD_DIAGNOSTIC = None
    STAGE = 'enroll'
    arguments = ['storage', 'fragments', 'maintenance', 'enroll', '--enrollment', root / 'maintenance',
        '--state', root / 'fragment-set', '--from-provider-key', keys[0], '--authorization-seconds', 6000,
        '--lifetime-seconds', 5400, '--renew-before-seconds', 7200,
        '--maximum-charged-bytes', MAX_CHARGE, '--maximum-turn-bytes', 8 * 1024 * 1024, *unlock(root)]
    for label, key in zip('bc', keys[1:]):
        arguments += ['--provider-key', key, '--grant', root / f'grant-{label}.bin']
    enrolled = invoke(binary, client, arguments)
    require(enrolled['stage'] == 'enrolled' and enrolled['turns'] == 0, 'enrollment failed')
    before = status(root, binary, client)
    STAGE = 'renew'
    renewal = run_turn(root, binary, client, keys[1])
    refresh = renewal['detail']['refresh']
    require(refresh == dict(fragment_index=0, renewal=True, operation_complete=True,
            copy_outcomes=['confirmed', 'confirmed'])
        and type(refresh['fragment_index']) is int
        and refresh['renewal'] is True and refresh['operation_complete'] is True,
        'real rotating renewal not observed')
    after = status(root, binary, client)
    for old, new in zip(before['fragments'][0]['copies'], after['fragments'][0]['copies']):
        require(new['last_confirmed_expiry'] > old['last_confirmed_expiry'] + 1000,
            'provider did not extend the actual lease')
    STAGE = 'owner_eof'
    eof = run_turn(root, binary, client, keys[1], 'eof')
    STAGE = 'foreground'
    revoked = run_turn(root, binary, client, keys[1], 'foreground')
    require((renewal['turns'], eof['turns'], revoked['turns']) == (1, 2, 3), 'restart cursor reset')
    STAGE = 'reconcile_cancelled_turns'
    # Interruption can leave an honest uncertain renewal/progress journal even
    # when the provider kept its committed copy. Reconcile actual receipts; never
    # infer a confirmed owner state merely from killing the requesting process.
    F['validate_cli'](invoke(binary, client, ['storage', 'fragments', 'progress', *existing(root)], deadline=900),
        'progress', keys, 'committed')
    F['check_identity'](root)
    return dict(uploaded, core_renewal_confirmed=True, renewal_fragment_index=0,
        owner_eof_during_admitted_turn=True, subsequent_core_turn_proves_lane_released=True,
        independent_foreground_progress_confirmed=True, foreground_turn_revoked=True,
        cursor_before_restart=2, cursor_after_restart=3, cancelled_turns_reconciled=True, enrollment_owner_private=True)


def identity_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def replacement_identities(root, value, keys, retired, *, withdrawn):
    """Hash exact core-validated signed intents and acknowledged target identities.

    The preceding real CLI status/progress verifies parent signatures and child
    binding. This read-only projection neither signs nor substitutes that check.
    """
    expected = (0, 2, 3) if withdrawn else retired
    path = root / 'fragment-set/placement-authorizations.json'
    entries = json.loads(closed_diagnostic_text(path, 1048576))['authority']['placements'] if path.exists() else []
    require(isinstance(entries, list) and len(entries) == len(expected)
        and sorted(entry['fragment'] for entry in entries) == list(expected), 'pre-withdrawal replacement binding')
    result = []
    identity_fields = ('provider_key', 'owner_key', 'grant_hex', 'archive_id', 'ciphertext_bytes', 'sha256')
    for entry in sorted(entries, key=lambda item: item['fragment']):
        index, intent = entry['fragment'], entry['handoff']
        directory = root / f'fragment-set/fragment-{index:04}'
        child = json.loads(closed_diagnostic_text(directory / 'replicas.json', 32768))['handoff']
        journal = json.loads(closed_diagnostic_text(directory / 'copy-2/archive.json', 16384))
        phase = 'complete' if index in retired else 'delete_pending'
        require(intent['phase'] == 'copying' and intent['from'] == (0 if index in (0, 3) else 1)
            and intent['to'] == 2 and child == dict(intent, phase=phase)
            and all(journal[key] == intent['initial_journal'][key] for key in identity_fields)
            and bytes(journal['provider_key']).hex() == keys[2 if index in (0, 3) else 1]
            and journal['ciphertext_bytes'] == LENGTHS[index] and journal['lease'] is not None,
            'pre-withdrawal replacement binding')
        result.append(dict(fragment=index, authorization_sha256=identity_sha(entry),
            copy_identity_sha256=identity_sha({key: journal[key] for key in (*identity_fields, 'lease')})))
    return result


def validate_identity_projection(value, indexes):
    require(isinstance(value, list) and len(value) == len(indexes), 'replacement identity projection')
    for item, index in zip(value, indexes):
        require(isinstance(item, dict) and set(item) == {'fragment', 'authorization_sha256', 'copy_identity_sha256'}
            and type(item['fragment']) is int and item['fragment'] == index
            and all(isinstance(item[key], str) and re.fullmatch('[0-9a-f]{64}', item[key])
                for key in ('authorization_sha256', 'copy_identity_sha256')), 'replacement identity projection')


def validate_baseline(value):
    require(isinstance(value, dict) and set(value) == {'version', 'retired_original_a', 'replacement_identities',
        'physical_payload_charge', 'pending_retirements', 'retained_copy_records'}, 'pre-withdrawal custody not reconciled')
    retired = value['retired_original_a']
    require(isinstance(retired, list) and len(retired) <= 2
        and all(type(index) is int and index in (0, 2, 3) for index in retired)
        and retired == sorted(set(retired)), 'pre-withdrawal repair exhausted withdrawal case')
    require(type(value['version']) is int and value['version'] == 1
        and type(value['physical_payload_charge']) is int and value['physical_payload_charge'] == 2 * BYTES
        and type(value['pending_retirements']) is int and value['pending_retirements'] == 0
        and type(value['retained_copy_records']) is int and value['retained_copy_records'] == 8 + len(retired),
        'pre-withdrawal custody not reconciled')
    validate_identity_projection(value['replacement_identities'], retired)
    return retired


def custody_usage(retired, *, withdrawn):
    result = [dict(reserved_bytes=0, committed_bytes=0, leases=0) for _ in range(3)]
    for index, size in enumerate(LENGTHS):
        providers = [(index + copy) % 3 for copy in range(2)]
        if index in retired:
            providers.remove(0)
        if index in retired or withdrawn and index != 1:
            providers.append(2 if index in (0, 3) else 1)
        for provider in providers:
            result[provider]['committed_bytes'] += size
            result[provider]['leases'] += 1
    result[1]['committed_bytes'] += len(FG)
    result[1]['leases'] += 1
    return result


class CustodyFailure(ValueError):
    """Same historical error text, with a closed failing-predicate category."""
    def __init__(self, message, reason):
        super().__init__(message)
        self.reason = reason


def baseline_failure_reason(error):
    cause = error.__cause__ if error.__cause__ is not None else error
    if isinstance(cause, CustodyFailure):
        return cause.reason if cause.reason in BASELINE_REASONS else 'unknown'
    if isinstance(cause, (KeyError, TypeError)):
        return 'malformed'
    return {'baseline_identity': 'identity', 'baseline_no_live_a': 'live_source_exhausted'}.get(
        failure_code(error), 'unknown')


def validate_custody(value, keys, retired, *, withdrawn):
    replacements = 3 if withdrawn else len(retired)
    uncertain_bytes = sum(LENGTHS[index] for index in (0, 2, 3) if index not in retired) if withdrawn else 0
    usage = custody_usage(retired, withdrawn=withdrawn)
    def check(condition, message, reason):
        if not condition:
            if reason == 'placement':
                pending = value.get('pending_retirements', 0)
                reason = ('pending_handoff' if type(pending) is int and pending > 0
                    and pending != (3 - len(retired) if withdrawn else 0) else 'identity')
            raise CustodyFailure(message, reason)

    # Keep the original conjunct order, defaults, comparisons and error text.
    # Splitting the guards only identifies which predicate actually rejected
    # the retained report; it neither repairs nor reinterprets that report.
    message = 'replacement custody or accounting incomplete'
    check(value['owner_signature_verified'] is True and value.get('report_version', 2 if not replacements else None) == 2,
        message, 'identity')
    check(value['logical_ciphertext_bytes'] == BYTES and value['fragment_count'] == 4
        and value['copies_per_fragment'] == value.get('desired_copies_per_fragment', 2 if not replacements else None) == 2,
        message, 'geometry')
    check(value.get('placement_authorizations', 0) == replacements and value.get('retained_copy_records', 8) == 8 + replacements
        and value.get('pending_retirements', 0) == (3 - len(retired) if withdrawn else 0), message, 'placement')
    check(value.get('replacement_overhead_included', not replacements) is True
        and value['uncertain_payload_bytes'] == uncertain_bytes and value['committed_payload_bytes'] == 2 * BYTES
        and value['reserved_payload_bytes'] == 0 and value['physical_payload_charge_upper_bound'] == 2 * BYTES + uncertain_bytes,
        message, 'accounting')
    check(value['fully_redundant_from_retained_receipts'] is True
        and value['fragments_with_confirmed_unexpired_copy'] == 4, message, 'unconfirmed')
    check(value['providers'] == [dict(provider_key=key, physical_payload_charge_upper_bound=size)
            for key, size in zip(keys, (usage[0]['committed_bytes'], usage[1]['committed_bytes'] - len(FG),
                usage[2]['committed_bytes']))], message, 'accounting')
    check(all(value[key] is False for key in ('read_consumes_archive', 'metadata_overhead_measured',
        'current_remote_availability_proven', 'independent_failure_domains_proven',
        'network_contribution_credit', 'erasure_coding')), 'replacement scope changed', 'scope')
    check(len(value['fragments']) == 4, 'fragment reconstruction geometry changed', 'geometry')
    for index, fragment in enumerate(value['fragments']):
        check(fragment['index'] == index and fragment['offset'] == sum(LENGTHS[:index])
            and fragment['ciphertext_bytes'] == LENGTHS[index], 'fragment reconstruction geometry changed', 'geometry')
        check(fragment['confirmed_unexpired_copies'] == 2, 'fragment reconstruction geometry changed', 'unconfirmed')
        providers = [(index + copy) % 3 for copy in range(2)]
        if index in retired or withdrawn and index != 1:
            providers.append(2 if index in (0, 3) else 1)
        check(len(fragment['copies']) == len(providers), 'effective replacement placement', 'geometry')
        for copy, provider in zip(fragment['copies'], providers):
            charge = ('deleted' if index in retired else 'uncertain' if withdrawn else 'committed') if provider == 0 else 'committed'
            check(copy['provider_key'] == keys[provider], 'effective replacement placement', 'identity')
            check(copy['charge'] == charge and copy['last_confirmed_state'] == ('Deleted' if charge == 'deleted' else 'Committed'),
                'effective replacement placement', 'unconfirmed')
            check(copy['last_confirmed_stored_bytes'] == (0 if charge == 'deleted' else LENGTHS[index]),
                'effective replacement placement', 'accounting')
            check(copy['last_confirmed_expiry'] == 0 if charge == 'deleted' else copy['last_confirmed_expiry'] > int(time.time()),
                'effective replacement placement', 'expired')


def pre_withdrawal(root, value, keys):
    retired = [fragment['index'] for fragment in value['fragments']
        if any(copy['provider_key'] == keys[0] and copy['charge'] == 'deleted' for copy in fragment['copies'])]
    require(len(retired) <= 2, 'pre-withdrawal repair exhausted withdrawal case')
    try:
        validate_custody(value, keys, retired, withdrawn=False)
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError('pre-withdrawal custody not reconciled') from error
    result = dict(version=1, retired_original_a=retired,
        replacement_identities=replacement_identities(root, value, keys, retired, withdrawn=False),
        physical_payload_charge=2 * BYTES, pending_retirements=0, retained_copy_records=8 + len(retired))
    validate_baseline(result)
    return result


def validate_repaired(value, keys, baseline):
    validate_custody(value, keys, validate_baseline(baseline), withdrawn=True)


def repaired(value, keys, baseline):
    # Retained healthy receipts alone do not prove every withdrawn A copy has a
    # replacement. Three explicit signed intents must reach verified retirement.
    if not (value.get('placement_authorizations') == 3 and value.get('pending_retirements') == 3 - len(baseline['retired_original_a'])
            and value.get('retained_copy_records') == 11 and value['fully_redundant_from_retained_receipts']):
        return False
    validate_repaired(value, keys, baseline)
    return True


def staged_files_absent(root):
    F['staged_files_absent'](root)
    require(not any(path.name.startswith(('.handoff-', '.replicas-', '.fragments-'))
        for path in (root / 'fragment-set').rglob('*')), 'handoff staging remains')


def restore(root, binary, client, keys):
    global STAGE, REPAIR_DIAGNOSTIC, REPAIR_TURNS
    STAGE = 'repair'
    REPAIR_TURNS = []
    require(not (root / 'input.bin').exists(), 'original bytes still present')
    begin = checkpoint(root, binary, client)['turns']
    lifecycle_result = read(root / 'lifecycle-result.json')
    baseline = lifecycle_result['pre_withdrawal']
    retired = validate_baseline(baseline)
    require(begin == lifecycle_result['cursor_after_resume'],
        'cursor lost before provider withdrawal')
    fresh, turns = set(), 0
    REPAIR_DIAGNOSTIC = dict(pre_withdrawal=baseline, latest_status=None, verified_new_fragment_indexes=[])
    for _ in range(12):
        previous = status(root, binary, client)
        REPAIR_DIAGNOSTIC['latest_status'] = retained_status_diagnostic(previous, int(time.time()))
        previous_charge = previous['physical_payload_charge_upper_bound']
        turn = run_turn(root, binary, client, keys[1])
        turns += 1
        retirement_turn(turn, turns, target=REPAIR_TURNS, maximum=12)
        detail = turn['detail']
        require(detail['refresh']['fragment_index'] == (turn['turns'] - 1) % 4,
            'durable scan cursor did not rotate')
        replacement = detail.get('freshly_verified_replacements', 0)
        require(type(replacement) is int and 0 <= replacement <= 1, 'unbounded replacements per turn')
        if 'fragment_outcomes' not in detail:
            require(detail.get('maintenance_stage') == 'observed' and replacement == 0,
                'new replacement readbacks incomplete')
        outcomes = handoff_outcomes(detail.get('fragment_outcomes', []))
        require(outcomes is not None and sum(item['replacement_verified_this_pass'] is True
            for item in outcomes) == replacement, 'new replacement readbacks incomplete')
        for item in outcomes:
            if item['replacement_verified_this_pass'] is True:
                require(item['index'] in (0, 2, 3) and item['index'] not in retired,
                    'new replacement readbacks incomplete')
                fresh.add(item['index'])
        REPAIR_DIAGNOSTIC['verified_new_fragment_indexes'] = sorted(fresh)
        value = status(root, binary, client)
        REPAIR_DIAGNOSTIC['latest_status'] = retained_status_diagnostic(value, int(time.time()))
        require(previous_charge <= value['physical_payload_charge_upper_bound'] <= MAX_CHARGE,
            'offline original charge lost or enrollment exceeded')
        F['check_identity'](root)
        if repaired(value, keys, baseline):
            break
    else:
        raise ValueError('bounded repair turns incomplete')
    require(fresh == set((0, 2, 3)) - set(retired), 'new replacement readbacks incomplete')
    identities = replacement_identities(root, value, keys, retired, withdrawn=True)
    retained_intent_continuity(root)
    require(all(entry in identities for entry in baseline['replacement_identities']),
        'signed replacement identities changed after withdrawal')
    # A fresh CLI process reloads the same journals before each restore: no parent
    # holds an archive or a hidden in-memory replacement map on behalf of these reads.
    STAGE = 'restore'
    for number in (1, 2):
        path = root / f'restore-{number}.bin'
        value = invoke(binary, client, ['storage', 'fragments', 'restore', *existing(root), '--output', path], deadline=900)
        validate_repaired(value, keys, baseline)
        require(value['restored'] is True and value['whole_archive_sha256_verified'] is True
            and all(entry['restored'] is True and entry['provider_key'] in keys[1:]
                for entry in value['fragment_outcomes']), 'replacement-only reconstruction failed')
        require(private_file(path).st_size == BYTES and hashlib.sha256(path.read_bytes()).hexdigest() == SHA,
            'restored bytes differ')
        F['check_identity'](root)
        retained_intent_continuity(root)
        require(replacement_identities(root, value, keys, retired, withdrawn=True) == identities,
            'signed replacement identities changed after withdrawal')
    invoke(binary, client, ['storage', 'fragments', 'restore', *existing(root), '--output', root / 'restore-1.bin'], expected=1)
    require(hashlib.sha256((root / 'restore-1.bin').read_bytes()).hexdigest() == SHA, 'restore clobbered output')
    staged_files_absent(root)
    return dict(restores=2, source_absent=True, owner_worker_starts=turns, scan_cursor_before=begin,
        scan_cursor_after=checkpoint(root, binary, client)['turns'], fresh_verified_replacements=len(fresh),
        pre_withdrawal_verified_replacements=len(retired), post_withdrawal_verified_fragment_indexes=sorted(fresh),
        replacement_identities=identities,
        retained_copy_records=11, pending_retirements=3 - len(retired),
        physical_payload_charge=2 * BYTES + sum(LENGTHS[index] for index in fresh),
        uncertain_payload_charge=sum(LENGTHS[index] for index in fresh), survivor_provider_indexes=[1, 2], uniform_target_copies=2,
        whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
        original_identities_retained=True, staging_removed=True)


def validate_retirement_progress(before, value, detail):
    # A completed retirement freshly reads back its existing replacement. That is
    # not a new placement; compare actual retained identities/counts instead.
    fresh = detail.get('freshly_verified_replacements', 0)
    require(type(fresh) is int and 0 <= fresh <= 1, 'unbounded retirement readbacks')
    require(value['placement_authorizations'] == before['placement_authorizations']
        and value['retained_copy_records'] == before['retained_copy_records'],
        'duplicate replacement after restart')


def finish(root, binary, client, keys):
    global STAGE, RETIREMENT_TURNS
    STAGE = 'retirement'
    RETIREMENT_TURNS = []
    turns = 0
    before = status(root, binary, client)
    retained_intent_continuity(root)
    retirement_counts(before, 0)
    require(before['placement_authorizations'] == 3 and before['retained_copy_records'] == 11,
        'replacement set incomplete before retirement')
    placements = root / 'fragment-set' / 'placement-authorizations.json'
    require(private_file(placements).st_size <= 1048576, 'placement journal exceeds bound')
    original_placements = placements.read_bytes()
    for _ in range(4):
        turn = run_turn(root, binary, client, keys[1])
        turns += 1
        retirement_turn(turn, turns)
        value = status(root, binary, client)
        retirement_counts(value, turns)
        validate_retirement_progress(before, value, turn['detail'])
        require(placements.read_bytes() == original_placements, 'signed replacement identities changed')
        if value['pending_retirements'] == 0:
            break
    require(value['pending_retirements'] == 0 and value['placement_authorizations'] == 3
        and value['physical_payload_charge_upper_bound'] == 2 * BYTES
        and value['uncertain_payload_bytes'] == 0, 'source retirement unconfirmed')
    STAGE = 'delete'
    for _ in range(2):
        deleted = invoke(binary, client, ['storage', 'fragments', 'delete', *existing(root)], deadline=900)
        require(deleted['operation_complete'] is True and deleted['physical_payload_charge_upper_bound'] == 0
            and deleted['placement_authorizations'] == 3 and deleted['retained_copy_records'] == 11
            and sum(len(fragment['copies']) for fragment in deleted['fragments']) == 11
            and all(copy['charge'] == 'deleted' for fragment in deleted['fragments'] for copy in fragment['copies']),
            'all retained copies must be explicitly deleted')
        F['check_identity'](root)
        retained_intent_continuity(root)
    foreground = invoke(binary, client, ['storage', 'peer', 'delete', *peer_args(root, keys[1])])
    require(foreground['state'] == 'Deleted', 'foreground copy not deleted')
    staged_files_absent(root)
    return dict(owner_worker_starts=turns, pending_retirements=0, duplicate_replacements=0,
        acknowledged_source_retirement=True, all_eleven_copies_deleted=True, foreground_copy_deleted=True,
        delete_retry_idempotent=True, original_identities_retained=True, final_payload_charge=0, staging_removed=True)


def cleanup(path):
    root = private_root(path, missing=True)
    files, directories = [], []
    if root.exists():
        def visit(directory, depth):
            require(depth <= 4, 'cleanup depth')
            entries = list(directory.iterdir())
            require(len(entries) <= 24, 'cleanup entries')
            for child in entries:
                info = child.lstat()
                if stat.S_ISDIR(info.st_mode):
                    allowed = ((depth == 0 and (child.name in ('fragment-set', 'maintenance', 'foreground')
                            or re.fullmatch(r'\.fragments-[A-Za-z0-9]+', child.name)))
                        or (depth == 1 and (re.fullmatch('fragment-000[0-3]', child.name)
                            or re.fullmatch(r'\.(?:replicas|fragment-transfer)-[A-Za-z0-9]+', child.name)))
                        or (depth == 2 and (child.name in ('copy-0', 'copy-1', 'copy-2')
                            or re.fullmatch(r'\.handoff-(?:journal|transfer)-[A-Za-z0-9]+', child.name)))
                        or (depth == 3 and directory.name.startswith('.handoff-journal-') and child.name == 'copy'))
                    require(allowed and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
                        'unexpected cleanup directory')
                    visit(child, depth + 1)
                    directories.append(child)
                else:
                    allowed = ((depth == 0 and child.name in F['FILES'] | {'foreground.bin', 'foreground-grant.bin',
                            'flow-upload.json', 'flow-restore.json', 'flow-finish.json', 'flow-lifecycle.json',
                            'flow-consumer-publish.json', 'flow-consumer-exercise.json', 'flow-consumer-finish.json',
                            'lifecycle-working.json', 'lifecycle-unavailable.json', 'lifecycle-result.json', RETAINED_INTENT_FILE})
                        or (depth == 1 and child.name in ('fragments.json', 'placement-authorizations.json',
                            'enrollment.json', 'checkpoint.json', 'archive.json'))
                        or (depth == 2 and child.name in ('replicas.json', 'restored-fragment'))
                        or (depth == 3 and (child.name == 'archive.json'
                            or (directory.name.startswith('.handoff-transfer-')
                                and re.fullmatch('survivor-[0-2]', child.name))))
                        or (depth == 4 and directory.name == 'copy' and child.name == 'archive.json')
                        or re.fullmatch(r'\.tmp[A-Za-z0-9]+', child.name))
                    require(allowed, 'unexpected cleanup file')
                    private_file(child)
                    files.append(child)
        visit(root, 0)
        require(len(files) <= 96 and len(directories) <= 32, 'cleanup total bound')
        for entry in files:
            entry.unlink()
        for entry in directories:
            entry.rmdir()
        root.rmdir()
    return dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        fragment_metadata_removed=True, input_and_outputs_removed=True, fragment_staging_removed=True,
        enrollment_checkpoint_removed=True, foreground_journal_removed=True, user_directory_removed=True)


def validate_lifecycle(value, *, historical=False):
    cursor_keys = ('cursor_before', 'cursor_at_core_loss', 'cursor_after_reconnect',
        'cursor_at_pause', 'cursor_after_resume')
    flags = ('same_owner_survived_core_loss', 'core_unavailable_observed', 'fresh_core_turn_completed',
        'charge_retained_during_core_loss', 'journal_identity_retained_during_core_loss',
        'sigterm_exit_zero', 'paused_checkpoint_retained', 'new_owner_process_resumed',
        'enrollment_unchanged', 'original_identities_retained', 'uncertainty_reconciled',
        'owner_process_joined', 'guest_core_pid_changed', 'guest_core_namespace_preserved')
    fields = {*cursor_keys, *flags, 'physical_payload_charge'}
    if not historical:
        fields.add('pre_withdrawal')
        validate_baseline(value.get('pre_withdrawal'))
    require(set(value) == fields,
        'lifecycle receipt fields')
    require(all(type(value[key]) is int for key in cursor_keys)
        and value['cursor_before'] == 3
        and 3 < value['cursor_at_core_loss'] < value['cursor_after_reconnect']
        <= value['cursor_at_pause'] < value['cursor_after_resume'] <= MAX_LIFECYCLE_CURSOR
        and value['cursor_after_resume'] == value['cursor_at_pause'] + 1
        and all(value[key] is True for key in flags)
        and type(value['physical_payload_charge']) is int
        and value['physical_payload_charge'] == 2 * BYTES, 'lifecycle evidence incomplete')


def validate_evidence(value, *, historical=False, previous=False):
    require(not (historical and previous), 'ambiguous historical profile')
    require(value['success'] is True and all(value[key] is False for key in SCOPE_FALSE), 'scope overstated')
    require(value['prepare'] == dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, fragment_lengths=list(LENGTHS),
        providers=3, copies_per_fragment=2, grant_payload_bytes=[BYTES] * 3, grant_max_leases=[4] * 3,
        independent_foreground_bytes=len(FG), owner_distinct_from_all_providers=True, owner_secrets_exported=False),
        'provider grant proof missing')
    expected_upload = dict(fragment_count=4, copies_per_fragment=2, committed_fragment_copies=8,
        logical_ciphertext_bytes=BYTES, physical_payload_charge=2 * BYTES, owner_signature_verified=True,
        fresh_process_progress=True, committed_retry_same_identities=True, renewal_confirmed_by_progress=True,
        source_removed_before_restore=True, staging_removed=True, core_renewal_confirmed=True,
        renewal_fragment_index=0, owner_eof_during_admitted_turn=True,
        subsequent_core_turn_proves_lane_released=True, independent_foreground_progress_confirmed=True,
        foreground_turn_revoked=True, cursor_before_restart=2, cursor_after_restart=3,
        cancelled_turns_reconciled=True, enrollment_owner_private=True)
    require(value['upload'] == expected_upload, 'core renewal/revocation/restart proof missing')
    validate_lifecycle(value['lifecycle'], historical=historical)
    baseline = value['lifecycle'].get('pre_withdrawal')
    retired = [] if historical else validate_baseline(baseline)
    remaining = sorted(set((0, 2, 3)) - set(retired))
    uncertain = sum(LENGTHS[index] for index in remaining)
    resume_cursor = value['lifecycle']['cursor_after_resume']
    restored = value['restore']
    extra = {}
    if not historical:
        validate_identity_projection(restored.get('replacement_identities'), (0, 2, 3))
        require(all(entry in restored['replacement_identities'] for entry in baseline['replacement_identities']),
            'signed replacement identities changed after withdrawal')
        extra = dict(pre_withdrawal_verified_replacements=len(retired),
            post_withdrawal_verified_fragment_indexes=remaining, replacement_identities=restored['replacement_identities'])
    require(type(restored['owner_worker_starts']) is int and 1 <= restored['owner_worker_starts'] <= 12
        and restored == dict(restores=2, source_absent=True, owner_worker_starts=restored['owner_worker_starts'],
            scan_cursor_before=resume_cursor, scan_cursor_after=resume_cursor + restored['owner_worker_starts'], fresh_verified_replacements=len(remaining),
            retained_copy_records=11, pending_retirements=len(remaining), physical_payload_charge=2 * BYTES + uncertain,
            uncertain_payload_charge=uncertain, survivor_provider_indexes=[1, 2], uniform_target_copies=2,
            whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
            original_identities_retained=True, staging_removed=True, **extra), 'actual repair and restored custody missing')
    finished = value['finish']
    require(type(finished['owner_worker_starts']) is int and 1 <= finished['owner_worker_starts'] <= 4
        and finished == dict(owner_worker_starts=finished['owner_worker_starts'], pending_retirements=0,
            duplicate_replacements=0, acknowledged_source_retirement=True, all_eleven_copies_deleted=True,
            foreground_copy_deleted=True, delete_retry_idempotent=True, original_identities_retained=True,
            final_payload_charge=0, staging_removed=True), 'retirement/deletion missing')
    require(value['withdrawal'] == dict(first_provider_stopped_before_restore=True, first_store_retained=True,
        other_two_providers_serving=True, same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True, agent_restart_claimed=False), 'provider withdrawal not observed')
    require(value['uploaded_usage'] == custody_usage(retired, withdrawn=False)
        and value['restored_usage'] == custody_usage(retired, withdrawn=True)
        and value['deleted_usage'] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
        'actual provider store accounting differs')
    require(value['private_cleanup'] == dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        fragment_metadata_removed=True, input_and_outputs_removed=True, fragment_staging_removed=True,
        enrollment_checkpoint_removed=True, foreground_journal_removed=True, user_directory_removed=True),
        'private cleanup incomplete')
    isolation = value['isolation']
    require(isolation['user_uid'] > 0 and isolation['user_uid'] != isolation['agent_uid']
        and isolation['control_gid'] != isolation['agent_gid']
        and all(isolation[key] is True for key in ('agent_cannot_read_user_state',
            'client_cannot_read_any_provider_store', 'agent_mount_positive_control',
            'all_provider_keys_match_independent_fixture_peers', 'three_provider_namespaces_distinct')),
        'private owner/provider isolation missing')
    require(set(value['network']) == {*F['PHASES'], 'lifecycle'}, 'network phase missing')
    current_layout, transition_sha = value['layout'], None
    if not (historical or previous):
        current_layout = CONSUMERS['validate_control_transition'](value['control_transition'],
            value['expected_peers'], value['layout'])
        transition_sha = hashlib.sha256(CONSUMERS['canonical'](value['control_transition'])).hexdigest()
    else:
        require('control_transition' not in value, 'historical transition not admitted')
    for name, phase in value['network'].items():
        layout = dict(value['layout'] if name == 'upload' else current_layout)
        if transition_sha is not None:
            CONSUMERS['keys'](phase['layout'], ('route_scope',) if name == 'upload'
                else ('route_scope', 'control_transition_sha256'))
            if name != 'upload':
                require(phase['layout']['control_transition_sha256'] == transition_sha,
                    'maintenance phase transition differs')
            require(phase['layout']['route_scope'] == phase['gates']['exit_route_scope'],
                'maintenance phase scope differs')
        if name != 'upload':
            layout['route_scope'] = phase['gates']['exit_route_scope']
        F['validate_network'](phase, value['expected_peers'], layout, name,
            maintenance_contexts=True, minimum=1 if name == 'lifecycle' else None)


def evidence(work):
    usage_names = ('uploaded_usage', 'restored_usage', 'deleted_usage')
    value = {name: read(work / f'private-storage-fragments-{name}.json')
        for name in F['SUMMARY_NAMES'] if name not in ('smoke', 'evidence', *usage_names)}
    for name in usage_names:
        value[name] = F['read_usage'](work / f'private-storage-fragments-{name}.json')
    value.update(success=True, expected_peers=read(work / 'a01-expected-peers.json'), **dict.fromkeys(SCOPE_FALSE, False))
    value['lifecycle'] = read(work / 'private-storage-maintenance-lifecycle.json')
    value['control_transition'] = CONSUMERS['read_control_transition'](work)
    value['network'] = {name: dict(layout=read(work / f'private-storage-fragments-{name}-layout.json'),
        selected_route=read(work / f'private-storage-fragments-{name}-live-selection.json'),
        privacy={role: read(work / f'private-storage-fragments-{name}-privacy-{role}.json') for role in F['ROLES']},
        control_privacy=read(work / f'content-provider-adaptive-private-storage-fragments-{name}-control.json'),
        gates=read(work / f'private-storage-fragments-{name}-gates.json')) for name in (*F['PHASES'], 'lifecycle')}
    validate_evidence(value)
    return value


def validate_report(report, revision, *, historical=False, previous=False, stream_profile=False,
        challenge_profile=False, append_profile=False, flow_profile=False):
    # Historical v2 reports describe only the original opaque fixture. They
    # remain inspectable, but never satisfy the current combined CLI gate.
    require(type(flow_profile) is bool
        and not (flow_profile and (historical or previous or stream_profile or challenge_profile or append_profile))
        and type(append_profile) is bool
        and not (append_profile and (historical or previous or stream_profile or challenge_profile))
        and type(challenge_profile) is bool and not (challenge_profile and (historical or previous or stream_profile))
        and type(stream_profile) is bool and not (stream_profile and (historical or previous))
        and not (historical and previous) and re.fullmatch('[0-9a-f]{40}', revision) and report['source_revision'] == revision
        and type(report['schema_version']) is int
        and report['schema_version'] == (8 if flow_profile else 7 if append_profile else 2 if historical else 3 if previous else 6 if challenge_profile else 5 if stream_profile else 4)
        and report['report_kind'] == 'volparossa-private-storage-maintenance'
        and report['success'] is True and report['runner_exit_status'] == 0
        and report['phase'] == 'private-storage-maintenance-complete' and report['observed_blocker'] is None
        and report['cleanup'] == dict(complete=True, remaining_owned_objects=0)
        and report['host_state']['unchanged'] is True, 'source-bound cleanup missing')
    validate_evidence(report['maintenance'], historical=historical, previous=previous)
    if not historical:
        CONSUMERS['validate_evidence'](report['consumers'], previous=previous)
        require((report['consumers']['schema_version'] == 6) == stream_profile
            and (report['consumers']['provision']['version'] == 6) == stream_profile,
            'consumer_stream_source_profile')
        require((report['consumers']['schema_version'] == 7) == challenge_profile
            and (report['consumers']['provision']['version'] == 7) == challenge_profile,
            'consumer_challenge_source_profile')
        require((report['consumers']['schema_version'] == 8) == append_profile
            and (report['consumers']['provision']['version'] == 8) == append_profile,
            'consumer_append_source_profile')
        require((report['consumers']['schema_version'] == 9) == flow_profile
            and (report['consumers']['provision']['version'] == 9) == flow_profile,
            'consumer_flow_source_profile')
        require(all(report['maintenance'][name] == report['consumers'][name]
            for name in ('expected_peers', 'layout', 'isolation', *(() if previous else ('control_transition',))))
            and report['maintenance']['deleted_usage'] == report['consumers']['initial_usage'],
            'consumer continuation does not match original topology')


def main(args):
    if len(args) == 4 and args[0] == 'control-transition-check':
        CONSUMERS['read_control_transition'](Path(args[1]), path=Path(args[2]), stage=args[3]); return
    if len(args) == 5 and args[0] == 'supervisor-record':
        print(json.dumps(supervisor_record(*args[1:]), sort_keys=True)); return
    if len(args) == 2 and args[0] == 'supervisor-check':
        supervisor_file(Path(args[1])); return
    if len(args) == 3 and args[0] == 'inventory-check':
        inventory_file(Path(args[1]), args[2]); return
    if len(args) in (2, 4) and args[0] == 'route-diagnostic':
        if len(args) == 4:
            export_provider_events(Path(args[1]), args[2], args[3])
        print(json.dumps(route_diagnostic(Path(args[1])), sort_keys=True)); return
    if len(args) == 4 and args[0] == 'route-diagnostic-v3':
        export_provider_events(Path(args[1]), args[2], args[3], version=3)
        print(json.dumps(route_diagnostic(Path(args[1])), sort_keys=True)); return
    if len(args) == 2 and args[0] == 'route-diagnostic-check':
        validate_route_diagnostic(read(Path(args[1]))); return
    if len(args) == 2 and args[0] == 'provider-events-check':
        provider_events_file(Path(args[1])); return
    if args == ['owner-test-output']:
        print(json.dumps(owner_test_output(sys.stdin.buffer, sys.stderr.buffer), sort_keys=True))
        return
    if len(args) == 2 and args[0] == 'lifecycle-failure':
        print(json.dumps(lifecycle_failure_file(Path(args[1])), sort_keys=True))
        return
    if len(args) == 3 and args[0] == 'lifecycle-check':
        require(args[2] in ('working', 'unavailable'), 'unknown lifecycle marker')
        marker = private_root(args[1]) / f'lifecycle-{args[2]}.json'
        require(private_file(marker).st_size <= 64 and read(marker) == {'ready': True},
            'lifecycle marker missing')
        return
    if args == ['export-names']:
        print('\n'.join(EXPORT_NAMES)); return
    if len(args) == 2 and args[0] == 'export-names':
        names = list(EXPORT_NAMES)
        try:
            provider_events_file(Path(args[1]) / PROVIDER_EVENTS_NAME)
        except BaseException:
            names.remove(PROVIDER_EVENTS_NAME)
        try:
            activity = runpy.run_path(str(Path(__file__).with_name('storage-provider-activity-sampler.py')))
            path = Path(args[1]) / activity['NAME']
            value = activity['decode'](closed_diagnostic_text(path, activity['MAX_BYTES']).encode(), activity['MAX_BYTES'])
            activity['validate'](value)
        except Exception:
            names.remove('private-storage-provider-activity.json')
        try:
            correlation = runpy.run_path(str(Path(__file__).with_name('storage-fixture-correlation-sampler.py')))
            path = Path(args[1]) / correlation['NAME']
            value = correlation['decode'](closed_diagnostic_text(path, correlation['MAX_BYTES']).encode(), correlation['MAX_BYTES'])
            correlation['validate'](value)
        except Exception:
            names.remove('private-storage-fixture-correlation.json')
        print('\n'.join(names)); return
    if len(args) == 2 and args[0] == 'preselection-diagnostic':
        work = Path(args[1])
        print(json.dumps(closed_preselection_events(work / 'logs-client.txt',
            work / 'private-storage-maintenance-selection-start.private',
            work / 'private-storage-maintenance-selection-end.private'), sort_keys=True))
        return
    if len(args) == 3 and args[0] in ('report', 'report-consumer-v4', 'report-consumer-v5', 'report-consumer-v6', 'report-consumer-v7', 'report-consumer-v8', 'report-consumer-v9'):
        report = read(Path(args[1]))
        validate_report(report, args[2], stream_profile=args[0] == 'report-consumer-v6',
            challenge_profile=args[0] == 'report-consumer-v7', append_profile=args[0] == 'report-consumer-v8',
            flow_profile=args[0] == 'report-consumer-v9')
        if args[0] in ('report-consumer-v4', 'report-consumer-v5', 'report-consumer-v6', 'report-consumer-v7', 'report-consumer-v8', 'report-consumer-v9'):
            # Current hosted acceptance is generation-specific; keep the
            # original report command available for exact historical replay.
            consumer = report['consumers']
            version = {'report-consumer-v4': 4, 'report-consumer-v5': 5, 'report-consumer-v6': 6, 'report-consumer-v7': 7, 'report-consumer-v8': 8, 'report-consumer-v9': 9}[args[0]]
            require(type(consumer['schema_version']) is int and consumer['schema_version'] == version
                and type(consumer['provision']['version']) is int and consumer['provision']['version'] == version,
                'consumer_current_source_profile')
        return
    if len(args) == 3 and args[0] == 'evidence':
        result = evidence(Path(args[1]))
        Path(args[2]).write_text(json.dumps(result, sort_keys=True) + '\n')
        return
    if len(args) == 10 and args[0] == 'prepare':
        result = prepare(private_root(args[1]), *args[2:])
    elif len(args) == 7 and args[0] == 'lifecycle':
        result = lifecycle(private_root(args[1]), args[2], args[3], args[4:])
    elif len(args) == 7 and args[0] in ('upload', 'restore', 'finish'):
        root = private_root(args[1])
        socket = Path(args[3])
        require(socket.parts[-3:] == ('runtime-client', 'control', 'agent.sock'), 'fixture client socket differs')
        exit_socket = socket.parents[2] / 'runtime-exit/control/agent.sock'
        baseline = int(os.environ['STORAGE_PROOF_BASELINE_MS'])
        scope = json.loads(os.environ['STORAGE_PROOF_ROUTE_SCOPE'])
        SAMPLER['validate_route_scope'](scope)
        with SAMPLER['capture'](args[2], exit_socket, baseline, F['PHASES'][args[0]],
                client=socket, scope=scope, diagnostic=SAMPLER_DIAGNOSTIC) as coverage:
            result = {'upload': upload, 'restore': restore, 'finish': finish}[args[0]](
                root, args[2], args[3], args[4:])
        summary = coverage.report(joined=coverage.joined)
        SAMPLER['validate_summary'](summary, baseline, F['PHASES'][args[0]])
        create(root / f'flow-{args[0]}.json', json.dumps(summary, sort_keys=True).encode())
    elif len(args) == 2 and args[0] == 'cleanup':
        result = cleanup(args[1])
    else:
        raise ValueError('fixture invocation')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(failure_receipt(error)))
        sys.exit(1)
