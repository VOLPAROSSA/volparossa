#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Separate, finite real Cloud upload continuation in the disposable guest.

Reuse only the existing bounded child runner and independent route sampler.
Neither the original consumer profile nor its authority/pins are rewritten.
"""
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
import time

HERE = Path(__file__).resolve().parent
OLD = runpy.run_path(str(HERE / 'storage-consumer-maintenance-smoke.py'))
PROVISIONER = runpy.run_path(str(HERE / 'cloud-upload-maintenance-provision.py'))
BASE, SAMPLER = OLD['BASE'], OLD['SAMPLER']
require, keys, count = (OLD[name] for name in ('require', 'keys', 'count'))
file_bytes, private_json, write_json, private_directory = (
    OLD[name] for name in ('file_bytes', 'private_json', 'write_json', 'private_directory'))
run_child, core = OLD['run_child'], OLD['core']
NODE, PROVISION = OLD['NODE'], PROVISIONER['RECEIPT'] / 'provision.json'
MAX_REPORT, MAX_CIPHER, PLAIN_BYTES = OLD['MAX_REPORT'], OLD['MAX_CIPHER'], OLD['PLAIN_BYTES']
FRAGMENT = 262144
PHASES = ('prepare', 'upload', 'exercise', 'finish')
FLOW_MINIMUM = dict(upload=24, exercise=16, finish=11)
WORK_SECONDS = OLD['WORK_SECONDS']
PROFILE_VERSION = 1
SCOPE = dict(synthetic_inputs=True, protected_routes_independently_proven=False,
    provider_cleanup_independently_proven=False, automatic_grant_refresh=False,
    private_keys_exported=False, opencloud_account_server_proven=False, io_ordering_measured=False)
ACCOUNTING = OLD['ACCOUNTING']
COMMON = {'cipher_bytes', 'cipher_sha256', 'plaintext_bytes', 'plaintext_sha256', 'fragment_bytes', 'authority'}
AUTHORITY = {'expires_at', 'maximum_charged_bytes', 'intent_sha256', 'enrollment_sha256', 'config_sha256', 'root_sha256'}


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def fixture_hash():
    output = bytearray()
    for offset in range(0, PLAIN_BYTES, 32):
        output.extend(hashlib.sha256(f'VOLPAROSSA cloud upload {offset}'.encode()).digest())
    return hashlib.sha256(output[:PLAIN_BYTES]).hexdigest()


def geometry(size):
    require(count(size, 3 * FRAGMENT + 1, MAX_CIPHER), 'cipher_geometry')
    return [FRAGMENT] * 3 + [size - 3 * FRAGMENT]


def identities(value, indexes):
    require(type(value) is list and len(value) == len(indexes), 'replacement_identities')
    for record, index in zip(value, indexes):
        keys(record, ('fragment', 'authorization_sha256', 'copy_identity_sha256'))
        require(type(record['fragment']) is int and record['fragment'] == index
            and sha(record['authorization_sha256']) and sha(record['copy_identity_sha256']), 'replacement_identity')


def baseline(value, size):
    keys(value, ('version', 'retired_original_a', 'replacement_identities',
        'physical_payload_charge', 'pending_retirements', 'retained_copy_records'))
    retired = value['retired_original_a']
    require(type(retired) is list and len(retired) <= 2 and all(type(i) is int and i in (0, 2, 3) for i in retired)
        and retired == sorted(set(retired)), 'withdrawal_requires_live_a')
    require(type(value['version']) is int and value['version'] == 1
        and type(value['physical_payload_charge']) is int and value['physical_payload_charge'] == 2 * size
        and type(value['pending_retirements']) is int and value['pending_retirements'] == 0
        and type(value['retained_copy_records']) is int and value['retained_copy_records'] == 8 + len(retired), 'custody_baseline')
    identities(value['replacement_identities'], retired)
    return retired


def flow_minimum(phase, uploaded=None):
    require(phase in FLOW_MINIMUM, 'phase')
    if phase == 'finish':
        require(uploaded is not None and uploaded.get('passed') is True, 'upload_baseline_required')
        # Production Delete skips already-confirmed Deleted records. All eleven
        # records must end Deleted, but only the others send a new request.
        return 11 - len(baseline(uploaded['baseline'], uploaded['cipher_bytes']))
    return FLOW_MINIMUM[phase]


def validate_node_report(value, phase, provision, uploaded=None):
    require(phase in PHASES and type(value) is dict and type(value.get('passed')) is bool, 'node_report')
    require(type(value.get('version')) is int and value['version'] == 1
        and value.get('kind') == 'cloud-upload-maintenance' and value.get('phase') == phase
        and value.get('provision_sha256') == provision and sha(provision), 'node_identity')
    envelope = {'version', 'kind', 'phase', 'passed', 'provision_sha256'}
    if not value['passed']:
        keys(value, envelope | {'stage', 'code', 'cleanup_confirmed'})
        # Codes are deliberately a fixed vocabulary; updated with the driver,
        # never exported from exception strings, command output or private paths.
        require(value['stage'] in FAILURE_STAGES and value['code'] in FAILURE_CODES
            and value['cleanup_confirmed'] is False, 'failure_report')
        return value
    additions = ({'plaintext_bytes', 'plaintext_sha256', 'catalog_files', 'catalog_encrypted'} if phase == 'prepare' else
        COMMON | {'baseline', 'accounting', 'http_put_status', 'wrong_token_status', 'automatic_enrollment',
            'ready_observed', 'owned_session_observed', 'ordering_source_enforced', 'io_ordering_measured', 'owner_joined'}
        if phase == 'upload' else COMMON | {'baseline', 'repair_replacement_identities', 'new_replacements_after_withdrawal',
            'accounting', 'reads', 'service_restarted_between_reads', 'original_authority_and_journals_retained'}
        if phase == 'exercise' else COMMON | {'accounting', 'all_retained_copies_delete_acknowledged',
            'owner_joined', 'private_fixture_removed'})
    keys(value, envelope | additions | {'scope'})
    keys(value['scope'], SCOPE)
    require(all(value['scope'][key] is expected for key, expected in SCOPE.items()), 'scope')
    require(type(value['plaintext_bytes']) is int and value['plaintext_bytes'] == PLAIN_BYTES
        and value['plaintext_sha256'] == fixture_hash(), 'original_plaintext')
    if phase == 'prepare':
        require(type(value['catalog_files']) is int and value['catalog_files'] == 0
            and value['catalog_encrypted'] is True, 'encrypted_empty_catalog')
        return value
    size = value['cipher_bytes']
    lengths = geometry(size)
    require(sha(value['cipher_sha256']) and type(value['fragment_bytes']) is int
        and value['fragment_bytes'] == FRAGMENT, 'cipher_identity')
    authority = value['authority']
    keys(authority, AUTHORITY)
    require(count(authority['expires_at'], 1, 2**53 - 1) and type(authority['maximum_charged_bytes']) is int
        and authority['maximum_charged_bytes'] == 3 * MAX_CIPHER
        and all(sha(authority[k]) for k in AUTHORITY - {'expires_at', 'maximum_charged_bytes'}), 'authority')
    if phase == 'upload':
        retired = baseline(value['baseline'], size)
    else:
        require(uploaded is not None and uploaded['passed'] is True and all(value[k] == uploaded[k] for k in COMMON), 'retained_object')
        retired = baseline(uploaded['baseline'], size)
    charge = 0 if phase == 'finish' else 2 * size
    uncertain = sum(lengths[i] for i in (0, 2, 3) if i not in retired) if phase == 'exercise' else 0
    account = value['accounting']
    keys(account, ACCOUNTING)
    require(all(count(account[k], 0, 3 * MAX_CIPHER) for k in ACCOUNTING)
        and account == dict(logical_ciphertext_bytes=size, committed_payload_bytes=charge,
            uncertain_payload_bytes=uncertain, physical_payload_charge_upper_bound=charge + uncertain,
            fragment_count=4, copies_per_fragment=2, retained_copy_records=8 + len(retired) if phase == 'upload' else 11,
            pending_retirements=0 if phase == 'upload' else 3 - len(retired)), 'custody_accounting')
    if phase == 'upload':
        require(type(value['http_put_status']) is int and value['http_put_status'] == 201
            and type(value['wrong_token_status']) is int and value['wrong_token_status'] == 401
            and all(value[k] is True for k in ('automatic_enrollment', 'ready_observed', 'owned_session_observed',
                'ordering_source_enforced', 'owner_joined')) and value['io_ordering_measured'] is False, 'automatic_upload')
    elif phase == 'exercise':
        require(value['baseline'] == uploaded['baseline'], 'baseline_changed')
        identities(value['repair_replacement_identities'], (0, 2, 3))
        require(all(item in value['repair_replacement_identities'] for item in uploaded['baseline']['replacement_identities'])
            and type(value['new_replacements_after_withdrawal']) is int
            and value['new_replacements_after_withdrawal'] == 3 - len(retired)
            and value['service_restarted_between_reads'] is True
            and value['original_authority_and_journals_retained'] is True, 'post_withdrawal_repair')
        require(type(value['reads']) is list and len(value['reads']) == 2, 'cold_reads')
        for read in value['reads']:
            keys(read, ('authenticated_get_body_verified', 'cipher_cache_absent_before_read', 'plaintext_bytes',
                'plaintext_sha256', 'wrong_token_status', 'owned_session_observed', 'owner_joined'))
            require(all(read[k] is True for k in ('authenticated_get_body_verified', 'cipher_cache_absent_before_read',
                'owned_session_observed', 'owner_joined')) and type(read['plaintext_bytes']) is int
                and read['plaintext_bytes'] == PLAIN_BYTES and read['plaintext_sha256'] == fixture_hash()
                and type(read['wrong_token_status']) is int and read['wrong_token_status'] == 401, 'cold_authenticated_read')
    else:
        require(value['all_retained_copies_delete_acknowledged'] is True and value['owner_joined'] is True
            and value['private_fixture_removed'] is False, 'delete_scope')
    return value


# Kept closed and separate from the historical driver's vocabulary.
FAILURE_STAGES = {'phase_start', 'prepare_catalog', 'upload_start', 'upload_put', 'upload_close', 'upload_baseline',
    'exercise_binding', 'exercise_restart', 'exercise_repair', 'exercise_second_get', 'exercise_first_get', 'finish_delete'}
FAILURE_CODES = {'phase_deadline', 'authority_expired', 'authority_changed', 'private_file', 'private_directory',
    'input_changed', 'configuration', 'catalog_creation', 'cipher_identity', 'fragment_geometry', 'object_set',
    'enrollment', 'ready', 'owner_session', 'owner_join', 'http_status', 'http_body', 'storage_result',
    'baseline', 'custody', 'replacement_identity', 'journal_identity', 'plaintext_cleanup', 'previous_phase',
    'cli_failed', 'application_failed'}


class NodePhaseFailure(ValueError):
    def __init__(self, node, report_sha, provision):
        super().__init__('node_phase_failed')
        self.report = dict(version=1, kind='cloud-upload-maintenance-orchestration', phase=node['phase'],
            passed=False, code='node_phase_failed', cleanup_confirmed=False, node=node,
            node_report_sha256=report_sha, provision_sha256=provision, node_joined=True)


class NetworkPhaseFailure(ValueError):
    def __init__(self, phase, diagnostic):
        require(phase in FLOW_MINIMUM, 'network_phase')
        sampler = runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py'))
        sampler['validate_diagnostic'](diagnostic)
        super().__init__('network_observation_failed')
        self.report = dict(version=2, kind='cloud-upload-maintenance-orchestration', phase=phase,
            passed=False, code='network_observation_failed', cleanup_confirmed=False,
            network_version=2, sampler=dict(diagnostic))


def owner_root(raw, missing=False):
    path = Path(raw)
    require(re.fullmatch(r'/opt/va\.[a-f0-9]{32}\.[A-Za-z0-9]{6}/u/a', str(path))
        and not path.is_symlink(), 'owner_root')
    if not (missing and not path.exists()):
        private_directory(path)
    return path


def tools():
    pins = PROVISIONER['load_pins'](PROFILE_VERSION)
    raw = file_bytes(PROVISION, 65536, public=True)
    value = json.loads(raw)
    PROVISIONER['validate_provision'](value)
    require(value['version'] == PROFILE_VERSION, 'provision_profile')
    for name, source in pins['sources'].items():
        for relative, record in source['files'].items():
            OLD['digest_public'](PROVISIONER['SOURCES'][name] / relative, record)
    for relative, record in pins['runtime']['files'].items():
        OLD['digest_public'](NODE.parent.parent / relative, record)
    for name, record in value['tools'].items():
        OLD['digest_public'](Path('/usr/bin') / name, {k: record[k] for k in ('bytes', 'sha256')})
    file_bytes(HERE / 'cloud-upload-maintenance.mjs', 131072, public=True)
    return hashlib.sha256(raw).hexdigest()


def node_phase(root, phase, provision, deadline):
    arguments = [NODE, HERE / 'cloud-upload-maintenance.mjs', phase, root]
    if PROFILE_VERSION in (2, 3, 4, 5, 6):
        arguments += ['--profile-version', str(PROFILE_VERSION)]
    status, output, _ = run_child(arguments, deadline)
    value = json.loads(output)
    uploaded = private_json(root / 'cloud-upload-upload.json') if phase in ('exercise', 'finish') else None
    if uploaded is not None:
        validate_node_report(uploaded, 'upload', provision)
    validate_node_report(value, phase, provision, uploaded)
    require(status == (0 if value['passed'] else 1), 'node_exit')
    raw = file_bytes(root / f'cloud-upload-{phase}.json', MAX_REPORT)
    require(json.loads(raw) == value, 'retained_node_report')
    report_sha = hashlib.sha256(raw).hexdigest()
    if not value['passed']:
        raise NodePhaseFailure(value, report_sha, provision)
    return value, report_sha


def envelope(phase, node, node_sha, provision, **extra):
    return dict(version=1, kind='cloud-upload-maintenance-orchestration', phase=phase, passed=True,
        node=node, node_report_sha256=node_sha, provision_sha256=provision, node_joined=True, **extra)


def prepare(root, binary, client, providers, provider_keys, provision, deadline):
    require(not list(root.iterdir()) and len(set(provider_keys)) == 3
        and all(sha(key) for key in provider_keys), 'fresh_authority')
    binary, client = OLD['validate_locations'](root, binary, client, providers)
    node, report_sha = node_phase(root, 'prepare', provision, deadline)
    BASE['create'](root / 'passphrase', base64.b64encode(os.urandom(48)) + b'\n')
    core(binary, client, ['init', *BASE['unlock'](root)], deadline, raw=True)
    owner = core(binary, client, ['content', 'recipient-key', *BASE['unlock'](root)], deadline)['identity_public_key_hex']
    require(sha(owner) and owner not in provider_keys, 'fresh_owner')
    for label, provider, key in zip('abc', providers, provider_keys):
        grant = core(binary, provider, ['storage', 'peer', 'grant', '--provider-key', key, '--owner-key', owner,
            '--max-payload-bytes', MAX_CIPHER, '--max-leases', 4, '--max-retention-seconds', 7200,
            '--lifetime-seconds', 7200, '--output', root / f'grant-{label}.bin'], deadline)
        keys(grant, ('operation', 'grant_written', 'max_payload_bytes', 'max_leases',
            'expires_unix_seconds', 'reserved_bytes', 'network_contribution_credit'))
        require(grant['operation'] == 'private_storage_peer_grant' and grant['grant_written'] is True
            and type(grant['max_payload_bytes']) is int and grant['max_payload_bytes'] == MAX_CIPHER
            and type(grant['max_leases']) is int and grant['max_leases'] == 4
            and type(grant['reserved_bytes']) is int and grant['reserved_bytes'] == 0
            and grant['network_contribution_credit'] is False
            and count(grant['expires_unix_seconds'], int(time.time()) + 7000, int(time.time()) + 7201), 'grant_scope')
        file_bytes(root / f'grant-{label}.bin', 2048)
    selected = [dict(key=key, grant=str(root / f'grant-{label}.bin')) for label, key in zip('abc', provider_keys)]
    storage = dict(version=1, coreBinary=str(binary), controlSocket=str(client), identity=str(root / 'identity.key'),
        passphraseFile=str(root / 'passphrase'), providers=selected, fragmentBytes=FRAGMENT,
        lifetimeSeconds=1800, deadlineMs=1800000)
    if PROFILE_VERSION == 4:
        storage['appendDiagnosticsV7'] = True
    elif PROFILE_VERSION == 5:
        storage['flowAcquireDiagnosticsV8'] = True
    elif PROFILE_VERSION == 6:
        storage['tlsCloseDiagnosticsV9'] = True
    expires = int(time.time()) + 6000
    policy = dict(version=2, expiresAt=expires, maxSessions=1, maxChargedBytes=3 * MAX_CIPHER,
        perArchiveMaxChargedBytes=3 * MAX_CIPHER, fromProviderKey=provider_keys[0], lifetimeSeconds=3600,
        renewBeforeSeconds=7200, maximumTurnBytes=8388608, existing=[])
    service = dict(version=1, catalog=str(root / 'catalog'), workDirectory=str(root / 'work'),
        bearerToken=base64.b64encode(os.urandom(48)).decode(),
        ownerUploads=dict(directory=str(root / 'uploads'), space='Uploads', storageConfig=str(root / 'storage-template.json')),
        storageMaintenance=policy, maxOpenBytes=MAX_CIPHER, requestTimeoutMs=1800000, maxConcurrent=2)
    write_json(root / 'storage-template.json', storage)
    write_json(root / 'service.json', service)
    authority = dict(fresh_owner_created=True, owner_distinct_from_providers=True,
        grant_payload_bytes=[MAX_CIPHER] * 3, grant_max_leases=[4] * 3,
        grant_retention_seconds=7200, grant_lifetime_seconds=7200, reserved_credit=0,
        enrollment_created=False, automatic_grant_refresh=False, policy_expires_at=expires,
        policy_lifetime_seconds=3600, policy_maximum_charge=3 * MAX_CIPHER, policy_max_sessions=1,
        service_config_sha256=hashlib.sha256(file_bytes(root / 'service.json', MAX_REPORT)).hexdigest(),
        storage_template_sha256=hashlib.sha256(file_bytes(root / 'storage-template.json', MAX_REPORT)).hexdigest())
    result = envelope('prepare', node, report_sha, provision, authority=authority, protected_flow_proven=False)
    write_json(root / 'cloud-upload-prepared.json', result)
    return result


def phase(root, selected, exit_socket, flow_root, provision, deadline, *, network_version=1):
    require(type(network_version) is int and network_version in (1, 2), 'network_version')
    prepared = private_json(root / 'cloud-upload-prepared.json')
    require(prepared['provision_sha256'] == provision and prepared['phase'] == 'prepare'
        and prepared['passed'] is True, 'prepared_binding')
    authority = prepared['authority']
    for filename, field in (('service.json', 'service_config_sha256'), ('storage-template.json', 'storage_template_sha256')):
        require(hashlib.sha256(file_bytes(root / filename, MAX_REPORT)).hexdigest() == authority[field], 'configuration_changed')
    storage = private_json(root / 'storage-template.json')
    binary, client = OLD['validate_locations'](root, storage['coreBinary'], storage['controlSocket'])
    work = root.parents[1]
    require(Path(exit_socket) == work / 'runtime-exit/control/agent.sock'
        and Path(flow_root) == work / 'client-fixtures/private-storage-user', 'flow_locations')
    private_directory(Path(flow_root))
    variable = 'STORAGE_PROOF_ROUTE_POLICY' if network_version == 2 else 'STORAGE_PROOF_ROUTE_SCOPE'
    baseline_text, scope_text = os.environ['STORAGE_PROOF_BASELINE_MS'], os.environ[variable]
    require(re.fullmatch('[0-9]{1,20}', baseline_text) and len(scope_text) <= 4096, 'flow_scope')
    start, scope = int(baseline_text), json.loads(scope_text)
    sampler = runpy.run_path(str(HERE / 'storage-consumer-route-sampler.py')) if network_version == 2 else SAMPLER
    sampler['validate_policy' if network_version == 2 else 'validate_route_scope'](scope)
    extra = {}
    if network_version == 2:
        underlay = os.environ['STORAGE_PROOF_UNDERLAY_SHA256']
        require(sha(underlay), 'control_underlay_hash')
        extra = dict(network_version=2, control_underlay_sha256=underlay)
    require(0 < start <= int(time.time() * 1000), 'flow_baseline')
    uploaded = private_json(root / 'cloud-upload-upload.json') if selected == 'finish' else None
    if uploaded is not None:
        validate_node_report(uploaded, 'upload', provision)
    minimum = flow_minimum(selected, uploaded)
    diagnostic = {}
    sampler_failure = sampler['OLD']['SamplerFailure'] if network_version == 2 else sampler['SamplerFailure']
    try:
        with sampler['capture'](binary, Path(exit_socket), start, minimum, client=client,
                **{'policy' if network_version == 2 else 'scope': scope}, diagnostic=diagnostic) as coverage:
            node, report_sha = node_phase(root, selected, provision, deadline)
    except sampler_failure:
        if network_version == 2:
            raise NetworkPhaseFailure(selected, diagnostic) from None
        raise
    require(node['authority']['expires_at'] == authority['policy_expires_at'], 'absolute_authority_changed')
    summary = coverage.report(joined=coverage.joined)
    sampler['validate_summary'](summary, start, minimum)
    require(summary['exit_log_sampling_version'] == (3 if network_version == 2 else 2)
        and not run_child.__globals__['CANCELLED']
        and time.monotonic() < deadline + 30, 'phase_deadline')
    write_json(Path(flow_root) / f'flow-cloud-upload-{selected}.json', summary)
    result = envelope(selected, node, report_sha, provision, protected_flow_proven=True,
        minimum_protected_completions=minimum, sampler_joined=True, remote_cleanup_independently_proven=False, **extra)
    if network_version == 2:
        result['version'] = 2
    return result


def cleanup_tree(root):
    """Validate the complete exact owned tree before deleting local files only."""
    files, directories, total = [], [], 0
    original = private_directory(root)
    top = {'plaintext.bin', 'selection.json', 'identity.key', 'passphrase', 'storage-template.json', 'service.json',
        'cloud-upload-binding.json', 'cloud-upload-prepared.json', *(f'grant-{c}.bin' for c in 'abc'),
        *(f'cloud-upload-{p}.json' for p in PHASES)}

    def visit(path, depth):
        nonlocal total
        require(depth <= 12, 'cleanup_depth')
        with os.scandir(path) as entries:
            for entry in entries:
                require(len(files) + len(directories) < 512 and re.fullmatch('[A-Za-z0-9_.-]{1,128}', entry.name), 'cleanup_bound')
                current, info = Path(entry.path), entry.stat(follow_symlinks=False)
                require(info.st_uid == os.geteuid() and info.st_dev == original.st_dev, 'cleanup_owner')
                if stat.S_ISDIR(info.st_mode):
                    require(stat.S_IMODE(info.st_mode) == 0o700 and (depth or entry.name in ('catalog', 'uploads', 'work')), 'cleanup_directory')
                    directories.append((current, info))
                    visit(current, depth + 1)
                else:
                    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                        and info.st_size <= 2 * MAX_CIPHER and (depth or entry.name in top), 'cleanup_file')
                    total += info.st_size
                    require(total <= 32 * MAX_CIPHER, 'cleanup_bytes')
                    files.append((current, info))
    visit(root, 0)
    for path, before in [*files, *directories, (root, original)]:
        now = path.lstat()
        require(all(getattr(before, k) == getattr(now, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink')), 'cleanup_changed')
    for path, _ in files:
        path.unlink()
    for path, _ in reversed(directories):
        path.rmdir()
    root.rmdir()
    return len(files), len(directories) + 1


def cleanup(root):
    OLD['no_fixture_processes'](root)
    files, directories = cleanup_tree(root) if root.exists() else (0, 0)
    require(not root.exists() and not root.is_symlink(), 'cleanup_incomplete')
    return dict(version=1, kind='cloud-upload-maintenance-cleanup', passed=True, local_fixture_removed=True,
        no_owned_fixture_process_observed=True, removed_files=files, removed_directories=directories,
        remote_cleanup_confirmed=False, provider_usage_proven=False)


def main(arguments):
    global PROFILE_VERSION
    PROFILE_VERSION = 1
    network_version = 1
    if len(arguments) >= 2 and arguments[-2] == '--network-version':
        require(arguments[-1] == '2', 'network_version')
        network_version, arguments = 2, arguments[:-2]
    if len(arguments) >= 2 and arguments[-2] == '--profile-version':
        require(arguments[-1] in ('2', '3', '4', '5', '6'), 'profile_version')
        PROFILE_VERSION, arguments = int(arguments[-1]), arguments[:-2]
    if len(arguments) == 3 and arguments[0] == 'flow-minimum':
        OLD['guard']()
        root = owner_root(arguments[2])
        uploaded = private_json(root / 'cloud-upload-upload.json') if arguments[1] == 'finish' else None
        if uploaded is not None:
            validate_node_report(uploaded, 'upload', uploaded['provision_sha256'])
        print(flow_minimum(arguments[1], uploaded))
        return
    OLD['guard']()
    os.umask(0o077)
    require(len(arguments) >= 2, 'arguments')
    selected, root = arguments[0], owner_root(arguments[1], missing=arguments[0] == 'cleanup')
    if selected == 'cleanup' and len(arguments) == 2:
        result = cleanup(root)
    else:
        deadline, provision = time.monotonic() + WORK_SECONDS, tools()
        if selected == 'prepare' and len(arguments) == 10:
            result = prepare(root, arguments[2], arguments[3], arguments[4:7], arguments[7:10], provision, deadline)
        else:
            require(selected in FLOW_MINIMUM and len(arguments) == 4, 'arguments')
            result = phase(root, selected, arguments[2], arguments[3], provision, deadline,
                network_version=network_version)
    require(len(json.dumps(result).encode()) <= MAX_REPORT, 'report_bound')
    print(json.dumps(result, sort_keys=True))


def failure_report(arguments):
    selected = arguments[0] if arguments and arguments[0] in (*PHASES, 'cleanup') else 'invalid'
    return dict(version=1, kind='cloud-upload-maintenance-orchestration', phase=selected,
        passed=False, code='orchestration_failed', cleanup_confirmed=False)


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        run_child.__globals__['CANCELLED'] = True
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps(error.report if isinstance(error, (NodePhaseFailure, NetworkPhaseFailure))
            else failure_report(sys.argv[1:]), sort_keys=True))
        sys.exit(1)
