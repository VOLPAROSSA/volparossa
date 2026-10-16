#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""New Image/Cloud maintenance profile, solely in the disposable protected VM."""
import base64
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / 'private-storage-fragments-smoke.py'))
SAMPLER = runpy.run_path(str(HERE / 'private-storage-log-sampler.py'))
ACTIVITY = runpy.run_path(str(HERE / 'storage-provider-activity-sampler.py'))
CORRELATION = runpy.run_path(str(HERE / 'storage-fixture-correlation-sampler.py'))
FIXTURE_CORRELATION = False
PROVISIONER = runpy.run_path(str(HERE / 'storage-consumer-maintenance-provision.py'))
NODE = Path('/opt/volparossa-node/bin/node')
PROVISION = Path('/opt/volparossa-storage-consumers/provision.json')
PHASES = ('prepare', 'publish', 'exercise', 'finish')
# One protected connection per successful private-storage remote operation:
# publish: 2 apps * 8 copies * (Reserve + one Append + Finalize), plus
# Cloud catalog materialization's 4 * (Progress + ReadRange).
# exercise: two complete 4-fragment reads; repair/renewal adds further flows.
# finish: one Delete for each of the 11 retained copies in each application.
FLOW_MINIMUM = dict(publish=56, exercise=16, finish=22)
PHASE_SECONDS = 1800
WORK_SECONDS = 1740  # Keep shutdown/final sampler drain inside the phase bound.
MAX_REPORT = 16384
MAX_CIPHER = 1024 ** 2
PLAIN_BYTES = 786433
SCOPE = dict(synthetic_inputs=True, private_keys_exported=False, automatic_grant_refresh=False,
    immich_running_proven=False, opencloud_account_server_proven=False,
    protected_routes_independently_proven=False, provider_cleanup_independently_proven=False)
STAGES = {'phase_start', *(f'{app}_{step}' for app in ('image', 'cloud')
    for step in ('encrypt', 'publish', 'enroll', 'authority', 'repair', 'joined', 'delete')),
    'cloud_catalog', 'image_foreground_restore', 'image_decrypt', 'cloud_start', 'cloud_authenticated_read'}
FAILURE_CODES = {'phase_deadline', 'authority_expired', 'authority_changed', 'retained_binding',
    'foreground_observation_missing', 'storage_result', 'repair_charge', 'delete_charge', 'publish_charge',
    'retention_identity', 'retention_geometry', 'checkpoint', 'child_cleanup', 'owner_join', 'image_restore',
    'image_decrypt', 'plaintext_mismatch', 'cloud_size', 'cloud_body', 'cloud_plaintext_cleanup', 'authorization',
    'cipher_identity', 'cipher_receipt', 'snapshot_crypto', 'publish_operation', 'enrollment_policy', 'enrollment',
    'fragment_geometry', 'catalog_creation', 'configuration', 'input_changed', 'private_file', 'private_directory',
    'application_failed'}
CATALOG_FAILURE_CODES = {'catalog_materialization_failed', 'catalog_restore_validation',
    'catalog_metadata_validation', 'catalog_selection_validation', 'catalog_plaintext_validation',
    'catalog_file_version_changed', 'catalog_receipt_validation', 'catalog_crypto_timeout',
    'catalog_crypto_unavailable', 'catalog_crypto_failed', 'catalog_crypto_report_invalid',
    'catalog_cleanup_failed', 'catalog_stage_changed', 'catalog_cancelled'}
CANCELLED = False
PROFILE_VERSION = 1
NETWORK_VERSION = 1


class NodePhaseFailure(ValueError):
    def __init__(self, value, report_hash, provision):
        super().__init__('node_phase_failed')
        # Only an already validated, closed original report is retained here.
        self.report = dict(version=1, kind='storage-consumer-maintenance-orchestration',
            phase=value['phase'], passed=False, code='node_phase_failed', cleanup_confirmed=False,
            node=value, node_report_sha256=report_hash, provision_sha256=provision, node_joined=True)


class NetworkPhaseFailure(ValueError):
    def __init__(self, phase, diagnostic):
        sampler = runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py'))
        sampler['validate_diagnostic'](diagnostic)
        super().__init__('network_observation_failed')
        self.report = dict(version=2, kind='storage-consumer-maintenance-orchestration', phase=phase,
            passed=False, code='network_observation_failed', cleanup_confirmed=False,
            network_version=2, sampler=dict(diagnostic))


def require(value, code='consumer_contract'):
    if not value:
        raise ValueError(code)


def count(value, low, high):
    return type(value) is int and low <= value <= high


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'closed_fields')


def file_bytes(path, maximum, public=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum
            and before.st_uid == (0 if public else os.geteuid())
            and (before.st_mode & 0o022 == 0 if public else stat.S_IMODE(before.st_mode) == 0o600), 'file_boundary')
        data = stream.read(maximum + 1)
        after, named = os.fstat(stream.fileno()), Path(path).lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(named, key)
            for key in fields), 'file_changed')
    return data


def private_json(path, maximum=MAX_REPORT):
    return json.loads(file_bytes(path, maximum))


def write_json(path, value):
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    require(len(data) <= MAX_REPORT, 'report_bound')
    BASE['create'](path, data)


def private_directory(path):
    info = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(), 'private_directory')
    return info


def owner_root(raw, missing=False):
    path = Path(raw)
    require(re.fullmatch(r'/opt/va\.[a-f0-9]{32}\.[A-Za-z0-9]{6}/u/m', str(path))
        and not path.is_symlink(), 'owner_root')
    if missing and not path.exists():
        return path
    private_directory(path)
    return path


def guard():
    require(sys.platform == 'linux' and os.geteuid() != 0 and socket.gethostname() == 'volparossa-alpha', 'guest_only')


def digest_public(path, record):
    # Stream the 126MB pinned runtime instead of allocating it as a JSON/input buffer.
    require(type(record) is dict and set(record) == {'bytes', 'sha256'}
        and count(record['bytes'], 1, 160 * 1024**2) and re.fullmatch('[a-f0-9]{64}', record['sha256']), 'pin')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            and before.st_mode & 0o022 == 0 and before.st_size == record['bytes']
            and Path(path).resolve() == Path(path), 'public_file')
        digest, size = hashlib.sha256(), 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            require(size <= record['bytes'], 'public_file_changed')
            digest.update(chunk)
        after, named = os.fstat(stream.fileno()), Path(path).lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(size == record['bytes'] and digest.hexdigest() == record['sha256']
            and all(getattr(before, key) == getattr(after, key) == getattr(named, key) for key in fields), 'public_file_changed')


def tools():
    pins = PROVISIONER['load_pins'](PROFILE_VERSION)
    raw = file_bytes(PROVISION, 65536, public=True)
    value = json.loads(raw)
    require(type(value['version']) is int and value['version'] == PROFILE_VERSION
        and value['kind'] == 'storage-consumer-maintenance-runtime-provision'
        and value['success'] is True and value['pins'] == pins
        and value['pins_sha256'] == hashlib.sha256(PROVISIONER['pins_path'](PROFILE_VERSION).read_bytes()).hexdigest()
        and all(value[key] is True for key in ('guest_only', 'source_files_verified', 'runtime_files_verified',
            'shared_adapter_verified', 'original_licenses_retained'))
        and all(value[key] is False for key in ('storage_enrollment_created', 'peer_storage_proven',
            'application_restore_proven', 'sdk_or_browser_provisioned', 'immich_or_opencloud_server_started')), 'provision')
    for name, source in pins['sources'].items():
        for relative, record in source['files'].items():
            digest_public(Path('/opt') / ('volparossa-' + name) / relative, record)
    for relative, record in pins['runtime']['files'].items():
        digest_public(NODE.parent.parent / relative, record)
    require(set(value['tools']) == {'gpg', 'gpg-agent', 'gpgconf', 'tar'}, 'tools')
    for name, record in value['tools'].items():
        digest_public(Path('/usr/bin') / name, {key: record[key] for key in ('bytes', 'sha256')})
    driver = HERE / 'storage-consumer-maintenance.mjs'
    file_bytes(driver, 131072, public=True)
    return hashlib.sha256(raw).hexdigest()


def fixture_hash(name):
    output = bytearray()
    for offset in range(0, PLAIN_BYTES, 32):
        output.extend(hashlib.sha256(f'VOLPAROSSA storage consumer {name} {offset}'.encode()).digest())
    return hashlib.sha256(output[:PLAIN_BYTES]).hexdigest()


def geometry(size):
    require(count(size, 16, MAX_CIPHER), 'cipher_size')
    fragment = (size + 3) // 4
    lengths = [fragment] * 3 + [size - 3 * fragment]
    require(min(lengths) > 0 and max(lengths) <= 262144, 'geometry')
    return fragment, lengths, lengths[0] + lengths[2] + lengths[3]


ACCOUNTING = {'logical_ciphertext_bytes', 'committed_payload_bytes', 'uncertain_payload_bytes',
    'physical_payload_charge_upper_bound', 'fragment_count', 'copies_per_fragment', 'retained_copy_records', 'pending_retirements'}
LIFECYCLE = {'observed_old_owner_absent_while_foreground_active', 'observed_paused_checkpoint_during_foreground',
    'fresh_owner_observed_after_foreground', 'cursor_before', 'cursor_after', 'cursor_advanced',
    'exact_join_before_spawn_measured', 'confirmed_retention_advanced_after_resume',
    'confirmed_copy_retentions_advanced', 'completed_turn_observed'}


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
    keys(value, ('status', 'detail', *(('append_timing',) if version in (7, 8) else ())))
    require(stage in ('wire_receipt', 'agent_terminal', 'deadline')
        and value['status'] in ('observed', 'missing', 'pending', 'expired', 'query_failed', 'query_timeout'), 'deposit_diagnostics')
    if value['status'] != 'observed':
        require(value['detail'] is None, 'deposit_diagnostics')
        if version in (7, 8):
            require(value['append_timing'] is None, 'deposit_diagnostics')
        return
    detail = value['detail']
    keys(detail, ('phase', 'category', 'deadline_scope'))
    require(detail['phase'] in OUTCOME_PHASES
        and detail['category'] in ('io', 'auth', 'invalid', 'busy', 'store', 'expired', 'entropy', 'timeout', 'policy', 'unavailable', 'cancelled')
        and detail['deadline_scope'] in ('none', 'operation', 'exchange', 'bridge', 'remote_wire')
        and ((detail['category'] == 'timeout') == (detail['deadline_scope'] != 'none'))
        and (detail['deadline_scope'] != 'bridge' or detail['phase'] in OUTCOME_PHASES[1:15])
        and (detail['deadline_scope'] != 'remote_wire' or detail['phase'] in OUTCOME_PHASES[6:13]), 'deposit_diagnostics')
    if version in (7, 8) and value['append_timing'] is not None:
        timing = value['append_timing']
        keys(timing, ('before_payload', 'in_payload_write_flush', 'in_receipt_read'))
        buckets = ('under_1s', '1_to_5s', '5_to_15s', '15_to_30s',
            '30_to_60s', '60_to_90s', '90_to_120s', 'at_least_120s')
        require(operation == 'append' and detail['phase'] in ('remote_payload_write', 'remote_receipt_read')
            and timing['before_payload'] in buckets and timing['in_payload_write_flush'] in buckets
            and (timing['in_receipt_read'] is None if detail['phase'] == 'remote_payload_write'
                else timing['in_receipt_read'] in buckets), 'deposit_diagnostics')


def validate_deposit_diagnostics(value, version=1):
    require(type(version) is int and version in (1, 2, 3, 4, 5, 6, 7, 8), 'deposit_diagnostics')
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
                *(('flow_acquire',) if version == 8 else ())))
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
            if version == 8 and detail['flow_acquire'] is not None:
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


def validate_node_report(value, phase, provision, prepared=None, *, profile_version=None):
    require(phase in PHASES and type(value) is dict and type(value.get('passed')) is bool, 'node_report')
    expected_version = 1
    if not value['passed']:
        fields = ('version', 'kind', 'phase', 'passed', 'provision_sha256', 'stage', 'code', 'cleanup_confirmed')
        if 'publish_observation' in value:
            fields += ('publish_observation',)
            observed = value['publish_observation']
            require(type(observed) is dict and type(observed.get('version')) is int
                and observed['version'] in (1, 2, 3, 4, 5, 6, 7, 8, 9), 'publish_profile')
            observation_version = observed['version']
            diagnostic = observation_version >= 2
            expected_version = observation_version + 1
            require(profile_version is None or observation_version == profile_version, 'publish_profile')
            keys(observed, ('version', 'app', 'operation', 'status', 'code', 'local_process_joined',
                'core_report_present', 'core_operation_complete',
                *(('deposit_diagnostics_state', 'deposit_diagnostics') if diagnostic else ())))
            require(type(observed['version']) is int and observed['version'] == observation_version
                and observed['app'] in ('image', 'cloud') and observed['operation'] in ('create', 'deposit')
                and phase == 'publish' and value['stage'] == observed['app'] + '_publish'
                and value['code'] in ('publish_operation', 'phase_deadline'), 'publish_observation')
            require(observed['status'] in ('complete', 'incomplete', 'failed', 'cancelled', 'timed_out', 'unknown')
                and observed['code'] in ('ok', 'retained_operation_incomplete', 'invalid_core_report', 'core_failed',
                    'cancelled', 'timed_out', 'report_too_large', 'restore_verification_failed', 'unknown')
                and type(observed['core_report_present']) is bool
                and all(observed[key] is None or type(observed[key]) is bool
                    for key in ('local_process_joined', 'core_operation_complete'))
                and (observed['core_report_present'] or observed['core_operation_complete'] is None)
                and (diagnostic or not (observed['status'] == 'complete' and observed['local_process_joined'] is True)),
                'publish_observation')
            if diagnostic:
                state, deposit = observed['deposit_diagnostics_state'], observed['deposit_diagnostics']
                require(state in ('observed', 'missing', 'invalid', 'not_applicable')
                    and (state == 'not_applicable') == (observed['operation'] == 'create'), 'deposit_diagnostics')
                if state == 'observed':
                    validate_deposit_diagnostics(deposit, observation_version - 1)
                    require(observed['core_report_present'] and observed['core_operation_complete'] in (True, False)
                        and (observed['core_operation_complete'] is False or not deposit['failures']), 'deposit_diagnostics')
                else:
                    require(deposit is None, 'deposit_diagnostics')
                require(not (observed['status'] == 'complete' and observed['local_process_joined'] is True)
                    or (observed['operation'] == 'deposit' and state in ('missing', 'invalid')), 'deposit_diagnostics')
        lifecycle = 'publish_cleanup' in value
        if lifecycle:
            fields += ('publish_cleanup',)
            cleanup = value['publish_cleanup']
            keys(cleanup, ('app', 'state'))
            lifecycle_profile = 9 if type(value['version']) is int and value['version'] == 11 else 8
            require(phase == 'publish' and profile_version in (None, lifecycle_profile)
                and cleanup['app'] in ('image', 'cloud') and cleanup['state'] in ('complete', 'failed'),
                'publish_cleanup')
            app = cleanup['app']
            stages = {f'{app}_{step}' for step in ('publish', 'enroll', 'policy_read', 'core_close')}
            if app == 'cloud':
                stages |= {'cloud_catalog_prepare', 'cloud_catalog_create', 'cloud_catalog_validate'}
            require(value['stage'] in stages and value['code'] in
                FAILURE_CODES | CATALOG_FAILURE_CODES | {'core_close_failed'}, 'publish_lifecycle')
            if 'publish_observation' in value:
                require(value['publish_observation']['version'] == lifecycle_profile
                    and value['publish_observation']['app'] == app, 'publish_lifecycle')
            if value['code'] in CATALOG_FAILURE_CODES:
                require(value['stage'] == 'cloud_catalog_create', 'publish_lifecycle')
            if value['stage'].endswith('_core_close') or value['code'] == 'core_close_failed':
                require(value['stage'] == f'{app}_core_close' and cleanup['state'] == 'failed'
                    and value['code'] in ('core_close_failed', 'phase_deadline'), 'publish_lifecycle')
            expected_version = lifecycle_profile + 2
        keys(value, fields)
        require((lifecycle or (value['stage'] in STAGES and value['code'] in FAILURE_CODES))
            and value['cleanup_confirmed'] is False, 'failure_report')
    else:
        keys(value, ('version', 'kind', 'phase', 'passed', 'provision_sha256', 'image', 'cloud', 'scope'))
        keys(value['scope'], SCOPE)
        require(all(value['scope'][key] is expected for key, expected in SCOPE.items()), 'scope')
    require(type(value['version']) is int and value['version'] == expected_version
        and value['kind'] == 'storage-consumer-maintenance' and value['phase'] == phase
        and value['provision_sha256'] == provision, 'node_identity')
    if not value['passed']:
        return value
    for name in ('image', 'cloud'):
        app = value[name]
        if phase == 'prepare':
            keys(app, ('cipher_bytes', 'cipher_sha256', 'application_encryption'))
            geometry(app['cipher_bytes'])
            require(re.fullmatch('[a-f0-9]{64}', app['cipher_sha256']) and app['application_encryption'] == 'OpenPGP-AES256', 'cipher')
            continue
        require(prepared is not None and prepared['passed'] is True, 'prepared')
        size = prepared[name]['cipher_bytes']
        _, _, withdrawn_charge = geometry(size)
        extras = ({'cipher_sha256', 'enrollment_created', 'maintenance_started', 'original_journals_bound'} if phase == 'publish' else
            LIFECYCLE | {'cipher_cache_removed_before_read', 'plaintext_sha256', 'plaintext_bytes',
                'original_enrollment_and_journals_retained', 'owner_joined'} | ({'application_decryption_verified',
                    'quiesced_sql_dump_restored'} if name == 'image' else {'authenticated_get_body_verified', 'wrong_token_status'})
            if phase == 'exercise' else {'all_retained_copies_delete_acknowledged', 'owner_joined',
                'provider_usage_independently_checked', 'private_fixture_removed'})
        keys(app, ACCOUNTING | extras)
        require(all(count(app[k], 0, 3 * MAX_CIPHER) for k in ACCOUNTING), 'accounting_type')
        require(app['logical_ciphertext_bytes'] == size and app['fragment_count'] == 4 and app['copies_per_fragment'] == 2, 'geometry')
        charge = 0 if phase == 'finish' else 2 * size
        uncertain = withdrawn_charge if phase == 'exercise' else 0
        require(app['committed_payload_bytes'] == charge and app['uncertain_payload_bytes'] == uncertain
            and app['physical_payload_charge_upper_bound'] == charge + uncertain
            and app['retained_copy_records'] == (8 if phase == 'publish' else 11)
            and app['pending_retirements'] == (0 if phase == 'publish' else 3), 'charge')
        if phase == 'publish':
            require(app['cipher_sha256'] == prepared[name]['cipher_sha256'] and app['enrollment_created'] is True
                and app['original_journals_bound'] is True and app['maintenance_started'] is False, 'publication')
        elif phase == 'exercise':
            require(count(app['cursor_before'], 1, 4095) and count(app['cursor_after'], app['cursor_before'] + 1, 4096)
                and count(app['confirmed_copy_retentions_advanced'], 1, 8) and app['exact_join_before_spawn_measured'] is False
                and app['completed_turn_observed'] is False and app['plaintext_bytes'] == PLAIN_BYTES
                and app['plaintext_sha256'] == fixture_hash(name), 'lifecycle')
            true_fields = extras - {'cursor_before', 'cursor_after', 'confirmed_copy_retentions_advanced',
                'exact_join_before_spawn_measured', 'completed_turn_observed', 'plaintext_bytes', 'plaintext_sha256', 'wrong_token_status'}
            require(all(app[k] is True for k in true_fields), 'lifecycle_flags')
            if name == 'cloud':
                require(type(app['wrong_token_status']) is int and app['wrong_token_status'] == 401, 'negative_auth')
        else:
            require(app['all_retained_copies_delete_acknowledged'] is True and app['owner_joined'] is True
                and app['provider_usage_independently_checked'] is False and app['private_fixture_removed'] is False, 'cleanup_scope')
    return value


def run_child(command, deadline, *, limit=MAX_REPORT):
    """Bounded pipes, actual child join, graceful Node-owned descendant shutdown.

    A forced kill or undrained inherited pipe is failure, never a cleanup proof.
    No raw stdout/stderr escapes this private reader on failure.
    """
    require(not CANCELLED and time.monotonic() < deadline, 'deadline')
    process = subprocess.Popen(list(map(str, command)), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
    selector = None
    output, errors = bytearray(), bytearray()
    stopped, forced, stop_at, exited_at, sent = None, False, None, None, None

    def group_alive():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def send(signum):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass

    try:
        selector = selectors.DefaultSelector()
        for stream, target in ((process.stdout, output), (process.stderr, errors)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, target)
        while selector.get_map() or process.poll() is None or group_alive():
            now = time.monotonic()
            if stopped is None and (CANCELLED or now >= deadline):
                stopped, stop_at = 'deadline', now
            if stopped is not None and group_alive():
                signum = signal.SIGKILL if now - stop_at >= 20 else signal.SIGTERM
                forced |= signum == signal.SIGKILL
                if sent != signum:
                    send(signum)
                    sent = signum
            if stopped is not None and now - stop_at >= 25:
                break
            for event, _ in selector.select(.05):
                chunk = os.read(event.fd, 4096)
                if not chunk:
                    selector.unregister(event.fileobj)
                    event.fileobj.close()
                    continue
                target = event.data
                room = limit + 1 - len(target)
                if room > 0:
                    target.extend(chunk[:room])
                if len(target) > limit and stopped is None:
                    stopped, stop_at = 'output_bound', time.monotonic()
            # Allow ordinary buffered bytes and EOF to drain after the leader
            # exits. A descendant retaining pipes/the owned group beyond that
            # short grace is failure, not an inferred successful child join.
            if process.poll() is not None:
                exited_at = now if exited_at is None else exited_at
                if (selector.get_map() or group_alive()) and now - exited_at >= 1 and stopped is None:
                    stopped, stop_at = 'pipe_not_joined', now
        joined = process.poll() is not None and not selector.get_map() and not group_alive()
        require(joined and not forced and stopped is None, stopped or 'child_join')
        require(process.returncode in (0, 1), 'child_exit')
        return process.returncode, bytes(output), bytes(errors)
    finally:
        if process.poll() is None or group_alive():
            send(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                send(signal.SIGKILL)
                process.wait(timeout=5)
            if group_alive():
                send(signal.SIGKILL)
        for stream in (process.stdout, process.stderr):
            stream.close()
        if selector is not None:
            selector.close()
        process.wait(timeout=1)


def core(binary, control, arguments, deadline, raw=False):
    status, stdout, _ = run_child([binary, '--control-socket', control, *arguments], min(deadline, time.monotonic() + 180))
    require(status == 0, 'core_command')
    return None if raw else json.loads(stdout)


def validate_locations(root, binary, client, providers=None):
    work = root.parents[1]
    binary, client = Path(binary), Path(client)
    require(binary.is_absolute() and binary.resolve() == binary, 'binary_path')
    info = binary.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0
        and info.st_mode & 0o111 and info.st_nlink == 1, 'binary_path')
    require(client == work / 'runtime-client/control/agent.sock' and stat.S_ISSOCK(client.lstat().st_mode), 'client_socket')
    if providers is not None:
        require([Path(p) for p in providers] == [work / f'runtime-{name}/control/agent.sock' for name in ('relay4', 'relay5', 'relay3')]
            and all(stat.S_ISSOCK(Path(p).lstat().st_mode) for p in providers), 'provider_socket')
    return binary, client


def node_phase(root, phase, provision, deadline):
    command = [NODE, HERE / 'storage-consumer-maintenance.mjs', phase, root]
    if PROFILE_VERSION in (2, 3, 4, 5, 6, 7, 8, 9):
        command += ['--profile-version', str(PROFILE_VERSION)]
    status, output, _ = run_child(command, deadline)
    value = json.loads(output)
    prepared = None if phase == 'prepare' else private_json(root / 'storage-consumer-prepare.json')
    if prepared is not None:
        validate_node_report(prepared, 'prepare', provision)
    validate_node_report(value, phase, provision, prepared, profile_version=PROFILE_VERSION)
    require(status == (0 if value['passed'] else 1), 'node_exit')
    retained = file_bytes(root / f'storage-consumer-{phase}.json', MAX_REPORT)
    require(json.loads(retained) == value, 'retained_node_report')
    report_hash = hashlib.sha256(retained).hexdigest()
    if not value['passed']:
        raise NodePhaseFailure(value, report_hash, provision)
    return value, report_hash


def prepare(root, binary, client, providers, provider_keys, provision, deadline):
    require(not list(root.iterdir()) and len(set(provider_keys)) == 3
        and all(re.fullmatch('[a-f0-9]{64}', key) for key in provider_keys), 'fresh_authority')
    binary, client = validate_locations(root, binary, client, providers)
    value, report_hash = node_phase(root, 'prepare', provision, deadline)
    owners, authorities = set(), {}
    for name in ('image', 'cloud'):
        app, size = root / name, value[name]['cipher_bytes']
        private_directory(app)
        BASE['create'](app / 'passphrase', base64.b64encode(os.urandom(48)) + b'\n')
        core(binary, client, ['init', *BASE['unlock'](app)], deadline, raw=True)
        owner = core(binary, client, ['content', 'recipient-key', *BASE['unlock'](app)], deadline)['identity_public_key_hex']
        require(re.fullmatch('[a-f0-9]{64}', owner) and owner not in provider_keys and owner not in owners, 'fresh_owner')
        owners.add(owner)
        for label, provider, key in zip('abc', providers, provider_keys):
            grant = core(binary, provider, ['storage', 'peer', 'grant', '--provider-key', key,
                '--owner-key', owner, '--max-payload-bytes', size, '--max-leases', 4,
                '--max-retention-seconds', 7200, '--lifetime-seconds', 7200,
                '--output', app / f'grant-{label}.bin'], deadline)
            keys(grant, ('operation', 'grant_written', 'max_payload_bytes', 'max_leases',
                'expires_unix_seconds', 'reserved_bytes', 'network_contribution_credit'))
            require(grant['operation'] == 'private_storage_peer_grant' and grant['grant_written'] is True
                and grant['max_payload_bytes'] == size and grant['max_leases'] == 4
                and grant['reserved_bytes'] == 0 and grant['network_contribution_credit'] is False
                and count(grant['expires_unix_seconds'], int(time.time()) + 7000, int(time.time()) + 7201), 'grant_scope')
            file_bytes(app / f'grant-{label}.bin', 2048)
        selected = [dict(key=key, grant=str(app / f'grant-{label}.bin')) for label, key in zip('abc', provider_keys)]
        config = dict(version=1, coreBinary=str(binary), controlSocket=str(client), identity=str(app / 'identity.key'),
            passphraseFile=str(app / 'passphrase'), stateDirectory=str(app / 'archive'), providers=selected,
            fragmentBytes=geometry(size)[0], lifetimeSeconds=1800, deadlineMs=1800000)
        if PROFILE_VERSION == 8:
            config['appendDiagnosticsV7'] = True
        elif PROFILE_VERSION == 9:
            config['flowAcquireDiagnosticsV8'] = True
        policy = dict(enrollment=str(app / 'maintenance'), fromProviderKey=provider_keys[0], providers=selected[1:],
            authorizationSeconds=6000, lifetimeSeconds=3600, renewBeforeSeconds=7200,
            maximumChargedBytes=3 * size, maximumTurnBytes=8388608)
        write_json(app / 'storage.json', config)
        write_json(app / 'maintenance-policy.json', policy)
        authorities[name] = dict(fresh_owner_created=True, owner_distinct_from_providers=True,
            grant_payload_bytes=[size] * 3, grant_max_leases=[4] * 3, grant_retention_seconds=7200,
            grant_lifetime_seconds=7200, reserved_credit=0, enrollment_created=False,
            policy_authorization_seconds=6000, policy_lifetime_seconds=3600, policy_maximum_charge=3 * size,
            automatic_grant_refresh=False)
    return dict(version=1, kind='storage-consumer-maintenance-orchestration', phase='prepare', passed=True,
        node=value, node_report_sha256=report_hash, provision_sha256=provision, node_joined=True,
        authority=authorities, protected_flow_proven=False)


def phase(root, selected, exit_socket, flow_root, provision, deadline):
    image = private_json(root / 'image/storage.json')
    cloud = private_json(root / 'cloud/storage.json')
    require(image['coreBinary'] == cloud['coreBinary'] and image['controlSocket'] == cloud['controlSocket'], 'shared_core')
    binary, client = validate_locations(root, image['coreBinary'], image['controlSocket'])
    correlation = CORRELATION['capture'](binary, root.parents[1], root, selected) if (
        FIXTURE_CORRELATION and PROFILE_VERSION == 9 and NETWORK_VERSION == 2) else nullcontext()
    # Fix the original application/network/deadline outcome before optional
    # diagnostic shutdown. Its query/disarm latency is not acceptance authority.
    with correlation:
        return phase_with_core(root, selected, exit_socket, flow_root, provision, deadline, binary, client)


def phase_with_core(root, selected, exit_socket, flow_root, provision, deadline, binary, client):
    require(Path(exit_socket) == root.parents[1] / 'runtime-exit/control/agent.sock'
        and Path(flow_root) == root.parents[1] / 'client-fixtures/private-storage-user', 'flow_locations')
    private_directory(Path(flow_root))
    baseline_text = os.environ['STORAGE_PROOF_BASELINE_MS']
    scope_text = os.environ['STORAGE_PROOF_ROUTE_POLICY' if NETWORK_VERSION == 2 else 'STORAGE_PROOF_ROUTE_SCOPE']
    require(re.fullmatch('[0-9]{1,20}', baseline_text) and len(scope_text) <= 4096, 'flow_scope')
    baseline, scope = int(baseline_text), json.loads(scope_text)
    sampler = SAMPLER if NETWORK_VERSION == 1 else runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py'))
    sampler['validate_route_scope' if NETWORK_VERSION == 1 else 'validate_policy'](scope)
    extra = {}
    if NETWORK_VERSION == 2:
        underlay_sha = os.environ['STORAGE_PROOF_UNDERLAY_SHA256']
        require(re.fullmatch('[0-9a-f]{64}', underlay_sha) is not None, 'flow_underlay')
        extra = dict(network_version=2, control_underlay_sha256=underlay_sha)
    require(0 < baseline <= int(time.time() * 1000), 'flow_baseline')
    minimum, diagnostic = FLOW_MINIMUM[selected], {}
    sampler_failure = sampler['SamplerFailure'] if NETWORK_VERSION == 1 else sampler['OLD']['SamplerFailure']
    activity = ACTIVITY['capture'](binary, root.parents[1], root, selected) if (
        PROFILE_VERSION in (7, 8, 9) and NETWORK_VERSION == 2) else nullcontext()
    try:
        with activity, sampler['capture'](
                binary, Path(exit_socket), baseline, minimum, client=client,
                **{('scope' if NETWORK_VERSION == 1 else 'policy'): scope}, diagnostic=diagnostic) as coverage:
            value, report_hash = node_phase(root, selected, provision, deadline)
    except sampler_failure:
        if NETWORK_VERSION == 2: raise NetworkPhaseFailure(selected, diagnostic) from None
        raise
    summary = coverage.report(joined=coverage.joined)
    sampler['validate_summary'](summary, baseline, minimum)
    require(summary['exit_log_sampling_version'] == (3 if NETWORK_VERSION == 2 else 2)
        and not CANCELLED and time.monotonic() < deadline + 30, 'phase_deadline')
    write_json(Path(flow_root) / f'flow-consumer-{selected}.json', summary)
    return dict(version=NETWORK_VERSION, kind='storage-consumer-maintenance-orchestration', phase=selected, passed=True,
        node=value, node_report_sha256=report_hash, provision_sha256=provision, node_joined=True,
        protected_flow_proven=True, minimum_protected_completions=minimum, sampler_joined=True,
        remote_cleanup_independently_proven=False, **extra)


def proc_bytes(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, 'proc_bound')
    return data


def no_fixture_processes(root):
    prefix = os.fsencode(root)
    count_seen = 0
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdecimal() or int(entry.name) == os.getpid():
                continue
            count_seen += 1
            require(count_seen <= 4096, 'proc_bound')
            try:
                if entry.stat(follow_symlinks=False).st_uid != os.geteuid():
                    continue
                arguments = proc_bytes(Path(entry.path) / 'cmdline', 32768).split(b'\0')
                require(not any(arg == prefix or arg.startswith(prefix + b'/') for arg in arguments), 'fixture_process_active')
            except (FileNotFoundError, ProcessLookupError):
                continue


def cleanup_tree(root):
    """Only the fresh private app tree: reject links/devices/unknown top-levels.

    This does not send Delete, clear provider accounting or claim remote cleanup.
    An uncertain process must first be stopped by the owning guest supervisor.
    """
    files, directories, total = [], [], 0
    original = private_directory(root)
    top_files = {'consumer-binding.json', *(f'storage-consumer-{p}.json' for p in PHASES),
        *(ACTIVITY['private_name'](phase) for phase in ACTIVITY['PHASES']),
        *(CORRELATION['private_name'](phase) for phase in CORRELATION['PHASES'])}

    def visit(path, depth):
        nonlocal total
        require(depth <= 8, 'cleanup_depth')
        with os.scandir(path) as entries:
            for entry in entries:
                require(len(files) + len(directories) < 512 and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', entry.name), 'cleanup_bound')
                current = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                require(info.st_uid == os.geteuid() and info.st_dev == original.st_dev, 'cleanup_owner')
                if stat.S_ISDIR(info.st_mode):
                    require(stat.S_IMODE(info.st_mode) == 0o700 and (depth or entry.name in ('image', 'cloud')), 'cleanup_directory')
                    directories.append((current, info))
                    visit(current, depth + 1)
                else:
                    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                        and info.st_size <= 2 * MAX_CIPHER and (depth or entry.name in top_files), 'cleanup_file')
                    total += info.st_size
                    require(total <= 32 * MAX_CIPHER, 'cleanup_bytes')
                    files.append((current, info))
    visit(root, 0)
    # No operation is removed before validating the complete owned inventory.
    for path, original_info in [*files, *directories, (root, original)]:
        info = path.lstat()
        require(all(getattr(info, k) == getattr(original_info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink')),
            'cleanup_changed')
    for path, _ in files:
        path.unlink()
    for path, _ in reversed(directories):
        path.rmdir()
    root.rmdir()
    return len(files), len(directories) + 1


def cleanup(root):
    no_fixture_processes(root)
    files, directories = cleanup_tree(root) if root.exists() else (0, 0)
    require(not root.exists() and not root.is_symlink(), 'cleanup_incomplete')
    return dict(version=1, kind='storage-consumer-maintenance-cleanup', passed=True, local_fixture_removed=True,
        no_owned_fixture_process_observed=True, removed_files=files, removed_directories=directories,
        remote_cleanup_confirmed=False, provider_usage_proven=False)


def main(arguments):
    global PROFILE_VERSION, NETWORK_VERSION, FIXTURE_CORRELATION
    PROFILE_VERSION = 1
    NETWORK_VERSION = 1
    FIXTURE_CORRELATION = bool(arguments and arguments[-1] == '--fixture-correlation')
    if FIXTURE_CORRELATION:
        arguments = arguments[:-1]
    if len(arguments) >= 2 and arguments[-2:] == ['--network-version', '2']:
        NETWORK_VERSION = 2
        arguments = arguments[:-2]
    if len(arguments) >= 2 and arguments[-2] == '--profile-version' and arguments[-1] in ('2', '3', '4', '5', '6', '7', '8', '9'):
        PROFILE_VERSION = int(arguments[-1])
        arguments = arguments[:-2]
    require(not FIXTURE_CORRELATION or (PROFILE_VERSION == 9 and NETWORK_VERSION == 2
        and arguments and arguments[0] in CORRELATION['PHASES']), 'fixture_correlation_scope')
    if len(arguments) == 2 and arguments[0] == 'flow-minimum':
        require(arguments[1] in FLOW_MINIMUM, 'phase')
        print(FLOW_MINIMUM[arguments[1]])
        return
    guard()
    os.umask(0o077)
    require(len(arguments) >= 2, 'arguments')
    selected = arguments[0]
    root = owner_root(arguments[1], missing=selected == 'cleanup')
    if selected == 'cleanup' and len(arguments) == 2:
        result = cleanup(root)
    else:
        deadline = time.monotonic() + WORK_SECONDS
        provision = tools()
        if selected == 'prepare' and len(arguments) == 10:
            result = prepare(root, arguments[2], arguments[3], arguments[4:7], arguments[7:10], provision, deadline)
        else:
            require(selected in FLOW_MINIMUM and len(arguments) == 4, 'arguments')
            result = phase(root, selected, arguments[2], arguments[3], provision, deadline)
    require(len(json.dumps(result).encode()) <= MAX_REPORT, 'report_bound')
    print(json.dumps(result, sort_keys=True))


def failure_report(arguments):
    # Closed failure goes to the same public stdout file as success. No private
    # exception, command, source path, ciphertext or owner identifier escapes.
    selected = arguments[0] if arguments and arguments[0] in (*PHASES, 'cleanup') else 'invalid'
    return dict(version=1, kind='storage-consumer-maintenance-orchestration', phase=selected,
        passed=False, code='orchestration_failed', cleanup_confirmed=False)


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        global CANCELLED
        CANCELLED = True
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        # The original node phase report remains private and independently
        # allowlisted; never replace it with a fabricated successful wrapper.
        print(json.dumps(error.report if isinstance(error, (NodePhaseFailure, NetworkPhaseFailure)) else failure_report(sys.argv[1:]), sort_keys=True))
        sys.exit(1)
