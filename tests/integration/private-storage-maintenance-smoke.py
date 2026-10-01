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
import time

F = runpy.run_path(str(Path(__file__).with_name('private-storage-fragments-smoke.py')))
SAMPLER = runpy.run_path(str(Path(__file__).with_name('private-storage-log-sampler.py')))
read, require = F['read'], F['require']
private_root, private_file, create, invoke, unlock = (F[key] for key in
    ('private_root', 'private_file', 'create', 'invoke', 'unlock'))
BYTES, CHUNK, LENGTHS, SHA = (F[key] for key in ('BYTES', 'CHUNK', 'LENGTHS', 'SHA'))
A_BYTES = F['PROVIDER_BYTES'][0]
FG = b'VOLPAROSSA independent foreground fixture'.ljust(64, b'.')
MAX_CHARGE = 2 * BYTES + A_BYTES
ADAPTIVE = False
OFFLINE = 0
SURVIVORS = (1, 2)
FOREGROUND = 1
NAME = 'private-storage-maintenance'
EXPORT_NAMES = tuple(name for name in F['EXPORT_NAMES'] if name not in
    ('private-storage-fragments-smoke.json', 'private-storage-fragments-evidence.json')) + (
    'private-storage-maintenance-smoke.json', 'private-storage-maintenance-evidence.json')
SCOPE_FALSE = ('independent_failure_domains_proven', 'network_contribution_credit',
    'archive_encryption_proven', 'automatic_archive_discovery', 'automatic_grant_refresh',
    'contribution_resize_proven', 'full_alpha_acceptance_claimed')
STAGE = 'not_started'


def configure_adaptive():
    """Explicit separate scenario; the original fixed-A v1 fixture stays available."""
    global ADAPTIVE, OFFLINE, SURVIVORS, FOREGROUND, NAME, EXPORT_NAMES
    ADAPTIVE, OFFLINE, SURVIVORS, FOREGROUND = True, 1, (0, 2), 0
    NAME = 'private-storage-adaptive-maintenance'
    EXPORT_NAMES = tuple(name.replace('private-storage-maintenance-', NAME + '-') for name in EXPORT_NAMES)


def private_json(path, maximum=32768):
    require(private_file(path).st_size <= maximum, 'private record bound')
    return json.loads(path.read_bytes())


def existing(root):
    return F['existing'](root)


def status(root, binary, client):
    return invoke(binary, client, ['storage', 'fragments', 'status', '--state', root / 'fragment-set'])


def checkpoint(root, binary, client, enrollment='maintenance'):
    value = invoke(binary, client, ['storage', 'fragments', 'maintenance', 'status',
        '--enrollment', root / enrollment])
    require(value['version'] == 1 and value['scope'] == 'owner-private-maintenance'
        and type(value['turns']) is int and 0 <= value['turns'] <= 32
        and value['core_coordinated'] is True and value['new_network_node'] is False
        and value['automatic_grant_refresh'] is False and value['private_key_exported'] is False,
        'maintenance checkpoint scope')
    return value


def peer_args(root, key):
    return ['--state', root / 'foreground', '--provider-key', key, *unlock(root)]


def run_turn(root, binary, client, key_b, interrupt=None, enrollment='maintenance'):
    """One real daemon-issued turn; no owner-side scheduler or direct provider socket."""
    before = checkpoint(root, binary, client, enrollment)['turns']
    process = subprocess.Popen([binary, '--control-socket', client, 'storage', 'fragments',
        'maintenance', 'serve', '--enrollment', str(root / enrollment), '--maximum-turns', '1',
        *map(str, unlock(root))], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if interrupt:
            deadline = time.monotonic() + 100
            while True:
                current = private_json(root / enrollment / 'checkpoint.json')
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
                foreground = invoke(binary, client, ['storage', 'peer', 'progress', *peer_args(root, key_b)])
                require(foreground['committed'] is True and foreground['stored_bytes'] == len(FG),
                    'independent foreground operation not acknowledged')
        stdout, stderr = process.communicate(timeout=650)
        require(len(stdout) <= 32768 and len(stderr) <= 16384, 'bounded owner output')
        require(process.returncode == (-signal.SIGKILL if interrupt == 'eof' else 0), 'owner process exit')
        result = checkpoint(root, binary, client, enrollment)
        require(result['turns'] == before + 1, 'cursor did not resume exactly one turn')
        if interrupt == 'eof':
            require(result['stage'] == 'working', 'owner EOF was not during an admitted turn')
        elif interrupt == 'foreground':
            require(result['stage'] == 'core_turn_revoked', 'foreground did not revoke the core turn')
        else:
            require(result['stage'] == 'turn_completed' and result['detail']['maintenance_stage'] in
                ('observed', 'maintained'), 'maintenance did not complete a core turn')
        return result
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


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
    foreground_control = (provider_a, provider_b, provider_c)[FOREGROUND]
    grant = invoke(binary, foreground_control, ['storage', 'peer', 'grant', '--provider-key', keys[FOREGROUND],
        '--owner-key', owner, '--max-payload-bytes', len(FG), '--max-leases', 1,
        '--max-retention-seconds', 7200, '--lifetime-seconds', 7200,
        '--output', root / 'foreground-grant.bin'])
    require(grant['grant_written'] is True and grant['max_payload_bytes'] == len(FG)
        and grant['max_leases'] == 1, 'independent foreground grant')
    return dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, fragment_lengths=list(LENGTHS),
        providers=3, copies_per_fragment=2, grant_payload_bytes=[BYTES] * 3, grant_max_leases=[4] * 3,
        independent_foreground_bytes=len(FG), owner_distinct_from_all_providers=True, owner_secrets_exported=False)


def upload(root, binary, client, keys):
    global STAGE
    STAGE = 'upload'
    # Existing real foreground deposit/retry/renew/progress, immutable identity checks,
    # and deletion of the original local bytes. Grants reserve no extra physical bytes.
    uploaded = F['upload'](root, binary, client, keys)
    foreground = invoke(binary, client, ['storage', 'peer', 'deposit', *peer_args(root, keys[FOREGROUND]),
        '--grant', root / 'foreground-grant.bin', '--input', root / 'foreground.bin',
        '--sha256', hashlib.sha256(FG).hexdigest(), '--already-encrypted', '--lifetime-seconds', 5400])
    require(foreground['committed'] is True and foreground['stored_bytes'] == len(FG), 'foreground seed')
    (root / 'foreground.bin').unlink()
    STAGE = 'enroll'
    arguments = ['storage', 'fragments', 'maintenance', 'enroll', '--enrollment', root / 'maintenance',
        '--state', root / 'fragment-set', '--from-provider-key', keys[0], '--authorization-seconds', 6000,
        '--lifetime-seconds', 5400, '--renew-before-seconds', 7200,
        '--maximum-charged-bytes', MAX_CHARGE, '--maximum-turn-bytes', 8 * 1024 * 1024, *unlock(root)]
    for label, key in zip('bc', keys[1:]):
        arguments += ['--provider-key', key, '--grant', root / f'grant-{label}.bin']
    enrolled = invoke(binary, client, arguments)
    require(enrolled['stage'] == 'enrolled' and enrolled['turns'] == 0, 'enrollment failed')
    record = private_json(root / 'maintenance/enrollment.json')['enrollment']
    require(record['version'] == 1 and 'repair_sources' not in record and record['source'] == list(bytes.fromhex(keys[0])),
        'original fixed-A v1 authority changed')
    if ADAPTIVE:
        # Preserve the real v1 enrollment unchanged as a negative control. Its
        # separately retained cursor will later observe B's failure without repair.
        (root / 'maintenance').rename(root / 'maintenance-fixed-a')
        arguments += ['--from-provider-key', keys[1], '--from-provider-key', keys[2],
            '--provider-key', keys[0], '--grant', root / 'grant-a.bin']
        enrolled = invoke(binary, client, arguments)
        require(enrolled['stage'] == 'enrolled' and enrolled['turns'] == 0, 'adaptive enrollment failed')
        record = private_json(root / 'maintenance/enrollment.json')['enrollment']
        require(record['version'] == 2 and record['repair_sources'] == sorted(list(bytes.fromhex(key)) for key in keys),
            'explicit signed source set differs')
    before = status(root, binary, client)
    STAGE = 'renew'
    renewal = run_turn(root, binary, client, keys[FOREGROUND])
    require(renewal['detail']['refresh'] == dict(fragment_index=0, renewal=True, operation_complete=True),
        'real rotating renewal not observed')
    after = status(root, binary, client)
    for old, new in zip(before['fragments'][0]['copies'], after['fragments'][0]['copies']):
        require(new['last_confirmed_expiry'] > old['last_confirmed_expiry'] + 1000,
            'provider did not extend the actual lease')
    STAGE = 'owner_eof'
    eof = run_turn(root, binary, client, keys[FOREGROUND], 'eof')
    STAGE = 'foreground'
    revoked = run_turn(root, binary, client, keys[FOREGROUND], 'foreground')
    require((renewal['turns'], eof['turns'], revoked['turns']) == (1, 2, 3), 'restart cursor reset')
    STAGE = 'reconcile_cancelled_turns'
    # Interruption can leave an honest uncertain renewal/progress journal even
    # when the provider kept its committed copy. Reconcile actual receipts; never
    # infer a confirmed owner state merely from killing the requesting process.
    F['validate_cli'](invoke(binary, client, ['storage', 'fragments', 'progress', *existing(root)], deadline=900),
        'progress', keys, 'committed')
    F['check_identity'](root)
    return dict(uploaded, **(dict(enrollment_version=2, authorized_source_indexes=[0, 1, 2],
        fixed_a_v1_enrollment_preserved=True) if ADAPTIVE else {}),
        core_renewal_confirmed=True, renewal_fragment_index=0,
        owner_eof_during_admitted_turn=True, subsequent_core_turn_proves_lane_released=True,
        independent_foreground_progress_confirmed=True, foreground_turn_revoked=True,
        cursor_before_restart=2, cursor_after_restart=3, cancelled_turns_reconciled=True, enrollment_owner_private=True)


def validate_repaired(value, keys):
    require(value['owner_signature_verified'] is True and value['report_version'] == 2
        and value['logical_ciphertext_bytes'] == BYTES and value['fragment_count'] == 4
        and value['copies_per_fragment'] == value['desired_copies_per_fragment'] == 2
        and value['placement_authorizations'] == 3 and value['retained_copy_records'] == 11
        and value['pending_retirements'] == 3 and value['replacement_overhead_included'] is True
        and value['uncertain_payload_bytes'] == A_BYTES and value['committed_payload_bytes'] == 2 * BYTES
        and value['reserved_payload_bytes'] == 0 and value['physical_payload_charge_upper_bound'] == MAX_CHARGE
        and value['fully_redundant_from_retained_receipts'] is True
        and value['fragments_with_confirmed_unexpired_copy'] == 4
        and value['providers'] == [dict(provider_key=key, physical_payload_charge_upper_bound=size)
            for index, key in enumerate(keys) for size in (A_BYTES if index == OFFLINE else BYTES,)],
        'replacement custody or accounting incomplete')
    require(all(value[key] is False for key in ('read_consumes_archive', 'metadata_overhead_measured',
        'current_remote_availability_proven', 'independent_failure_domains_proven',
        'network_contribution_credit', 'erasure_coding')), 'replacement scope changed')
    for index, fragment in enumerate(value['fragments']):
        require(fragment['index'] == index and fragment['offset'] == sum(LENGTHS[:index])
            and fragment['ciphertext_bytes'] == LENGTHS[index] and fragment['confirmed_unexpired_copies'] == 2,
            'fragment reconstruction geometry changed')
        committed = [copy for copy in fragment['copies'] if copy['charge'] == 'committed']
        uncertain = [copy for copy in fragment['copies'] if copy['charge'] == 'uncertain']
        require(len(committed) == 2 and {copy['provider_key'] for copy in committed} == {keys[i] for i in SURVIVORS}
            and len(uncertain) == (0 if index == (2 if ADAPTIVE else 1) else 1)
            and all(copy['provider_key'] == keys[OFFLINE] for copy in uncertain)
            and len(fragment['copies']) == len(committed) + len(uncertain), 'effective replacement placement')


def repaired(value, keys):
    # Retained healthy receipts alone do not prove every withdrawn A copy has a
    # replacement. Three explicit signed intents must reach verified retirement.
    if not (value.get('placement_authorizations') == 3 and value.get('pending_retirements') == 3
            and value.get('retained_copy_records') == 11 and value['fully_redundant_from_retained_receipts']):
        return False
    validate_repaired(value, keys)
    return True


def staged_files_absent(root):
    F['staged_files_absent'](root)
    require(not any(path.name.startswith(('.handoff-', '.replicas-', '.fragments-'))
        for path in (root / 'fragment-set').rglob('*')), 'handoff staging remains')


def restore(root, binary, client, keys):
    global STAGE
    STAGE = 'repair'
    require(not (root / 'input.bin').exists(), 'original bytes still present')
    begin = checkpoint(root, binary, client)['turns']
    require(begin == 3, 'initial restart cursor differs')
    baseline = {}
    if ADAPTIVE:
        STAGE = 'fixed_a_negative_control'
        original = status(root, binary, client)
        control = run_turn(root, binary, client, keys[FOREGROUND], enrollment='maintenance-fixed-a')
        observed = status(root, binary, client)
        require(control['turns'] == 1 and control['detail']['maintenance_stage'] == 'observed'
            and control['detail']['refresh']['fragment_index'] == 0
            and control['detail']['refresh']['operation_complete'] is False
            and original['placement_authorizations'] == observed['placement_authorizations'] == 0
            and observed['physical_payload_charge_upper_bound'] == 2 * BYTES
            and any(copy['provider_key'] == keys[1] and copy['charge'] == 'uncertain'
                for copy in observed['fragments'][0]['copies']), 'fixed-A baseline repaired B or did not observe it')
        baseline = dict(fixed_a_v1_turn_observed_b_failure=True, fixed_a_v1_new_placements=0,
            fixed_a_v1_physical_payload_charge=2 * BYTES, selected_source_provider_index=1)
    STAGE = 'repair'
    fresh, turns = 0, 0
    for _ in range(12):
        previous = status(root, binary, client)
        previous_charge = previous['physical_payload_charge_upper_bound']
        turn = run_turn(root, binary, client, keys[FOREGROUND])
        turns += 1
        detail = turn['detail']
        require(detail['refresh']['fragment_index'] == (turn['turns'] - 1) % 4,
            'durable scan cursor did not rotate')
        replacement = detail.get('freshly_verified_replacements', 0)
        require(type(replacement) is int and 0 <= replacement <= 1, 'unbounded replacements per turn')
        if ADAPTIVE and detail.get('attempted_handoffs', 0):
            require(detail['repair_scope'] == 'explicit_sources_observed_copy'
                and detail['selected_source_provider'] == keys[1]
                and detail['selected_fragment_index'] in (0, 1, 3)
                and detail['attempted_handoffs'] <= 1, 'adaptive repair did not select an exact B copy')
        fresh += replacement
        value = status(root, binary, client)
        require(previous_charge <= value['physical_payload_charge_upper_bound'] <= MAX_CHARGE,
            'offline original charge lost or enrollment exceeded')
        F['check_identity'](root)
        if repaired(value, keys):
            break
    else:
        raise ValueError('bounded repair turns incomplete')
    require(fresh == 3, 'three fresh replacement readbacks not observed')
    # A fresh CLI process reloads the same journals before each restore: no parent
    # holds an archive or a hidden in-memory replacement map on behalf of these reads.
    STAGE = 'restore'
    for number in (1, 2):
        path = root / f'restore-{number}.bin'
        value = invoke(binary, client, ['storage', 'fragments', 'restore', *existing(root), '--output', path], deadline=900)
        validate_repaired(value, keys)
        require(value['restored'] is True and value['whole_archive_sha256_verified'] is True
            and all(entry['restored'] is True and entry['provider_key'] in {keys[i] for i in SURVIVORS}
                for entry in value['fragment_outcomes']), 'replacement-only reconstruction failed')
        require(private_file(path).st_size == BYTES and hashlib.sha256(path.read_bytes()).hexdigest() == SHA,
            'restored bytes differ')
        F['check_identity'](root)
    invoke(binary, client, ['storage', 'fragments', 'restore', *existing(root), '--output', root / 'restore-1.bin'], expected=1)
    require(hashlib.sha256((root / 'restore-1.bin').read_bytes()).hexdigest() == SHA, 'restore clobbered output')
    staged_files_absent(root)
    return dict(baseline, restores=2, source_absent=True, owner_worker_starts=turns, scan_cursor_before=begin,
        scan_cursor_after=checkpoint(root, binary, client)['turns'], fresh_verified_replacements=fresh,
        retained_copy_records=11, pending_retirements=3, physical_payload_charge=MAX_CHARGE,
        uncertain_payload_charge=A_BYTES, survivor_provider_indexes=list(SURVIVORS), uniform_target_copies=2,
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
    global STAGE
    STAGE = 'retirement'
    turns = 0
    before = status(root, binary, client)
    require(before['placement_authorizations'] == 3 and before['retained_copy_records'] == 11,
        'replacement set incomplete before retirement')
    placements = root / 'fragment-set' / 'placement-authorizations.json'
    require(private_file(placements).st_size <= 1048576, 'placement journal exceeds bound')
    original_placements = placements.read_bytes()
    for _ in range(4):
        turn = run_turn(root, binary, client, keys[FOREGROUND])
        turns += 1
        value = status(root, binary, client)
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
            and all(copy['charge'] == 'deleted' for fragment in deleted['fragments'] for copy in fragment['copies']),
            'all retained copies must be explicitly deleted')
        F['check_identity'](root)
    foreground = invoke(binary, client, ['storage', 'peer', 'delete', *peer_args(root, keys[FOREGROUND])])
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
                    allowed = ((depth == 0 and (child.name in ('fragment-set', 'maintenance', 'maintenance-fixed-a', 'foreground')
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
                            'flow-upload.json', 'flow-restore.json', 'flow-finish.json'})
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


def validate_evidence(value):
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
    if ADAPTIVE:
        expected_upload.update(enrollment_version=2, authorized_source_indexes=[0, 1, 2],
            fixed_a_v1_enrollment_preserved=True)
    require(value['upload'] == expected_upload, 'core renewal/revocation/restart proof missing')
    restored = value['restore']
    require(type(restored['owner_worker_starts']) is int and 1 <= restored['owner_worker_starts'] <= 12
        and restored == dict(**(dict(fixed_a_v1_turn_observed_b_failure=True, fixed_a_v1_new_placements=0,
                fixed_a_v1_physical_payload_charge=2 * BYTES, selected_source_provider_index=1) if ADAPTIVE else {}),
            restores=2, source_absent=True, owner_worker_starts=restored['owner_worker_starts'],
            scan_cursor_before=3, scan_cursor_after=3 + restored['owner_worker_starts'], fresh_verified_replacements=3,
            retained_copy_records=11, pending_retirements=3, physical_payload_charge=MAX_CHARGE,
            uncertain_payload_charge=A_BYTES, survivor_provider_indexes=list(SURVIVORS), uniform_target_copies=2,
            whole_archive_sha256_verified=True, reads_nonconsuming=True, existing_output_preserved=True,
            original_identities_retained=True, staging_removed=True), 'actual repair and restored custody missing')
    finished = value['finish']
    require(type(finished['owner_worker_starts']) is int and 1 <= finished['owner_worker_starts'] <= 4
        and finished == dict(owner_worker_starts=finished['owner_worker_starts'], pending_retirements=0,
            duplicate_replacements=0, acknowledged_source_retirement=True, all_eleven_copies_deleted=True,
            foreground_copy_deleted=True, delete_retry_idempotent=True, original_identities_retained=True,
            final_payload_charge=0, staging_removed=True), 'retirement/deletion missing')
    withdrawal = (dict(withdrawn_provider_index=1, withdrawn_provider_node='relay5',
        withdrawn_provider_stopped_before_restore=True, withdrawn_store_retained=True) if ADAPTIVE else
        dict(first_provider_stopped_before_restore=True, first_store_retained=True))
    require(value['withdrawal'] == dict(withdrawal,
        other_two_providers_serving=True, same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True, agent_restart_claimed=False), 'provider withdrawal not observed')
    require(value['uploaded_usage'] == [dict(reserved_bytes=0, committed_bytes=size, leases=count)
        for index, (size, count) in enumerate(zip(F['PROVIDER_BYTES'], F['PROVIDER_LEASES']))
        for size, count in ((size + (len(FG) if index == FOREGROUND else 0), count + int(index == FOREGROUND)),)]
        and value['restored_usage'] == [dict(reserved_bytes=0, committed_bytes=size, leases=count)
        for index in range(3)
        for size, count in (((A_BYTES if index == OFFLINE else BYTES) + (len(FG) if index == FOREGROUND else 0),
                            (3 if index == OFFLINE else 4) + int(index == FOREGROUND)),)]
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
    require(set(value['network']) == set(F['PHASES']), 'network phase missing')
    for name, phase in value['network'].items():
        F['validate_network'](phase, value['expected_peers'], value['layout'], name,
            withdrawn_index=OFFLINE, maintenance_contexts=True)


def evidence(work):
    usage_names = ('uploaded_usage', 'restored_usage', 'deleted_usage')
    value = {name: read(work / f'private-storage-fragments-{name}.json')
        for name in F['SUMMARY_NAMES'] if name not in ('smoke', 'evidence', *usage_names)}
    for name in usage_names:
        value[name] = F['read_usage'](work / f'private-storage-fragments-{name}.json')
    value.update(success=True, expected_peers=read(work / 'a01-expected-peers.json'), **dict.fromkeys(SCOPE_FALSE, False))
    value['network'] = {name: dict(selected_route=read(work / f'private-storage-fragments-{name}-live-selection.json'),
        privacy={role: read(work / f'private-storage-fragments-{name}-privacy-{role}.json') for role in F['ROLES']},
        control_privacy=read(work / f'content-provider-adaptive-private-storage-fragments-{name}-control.json'),
        gates=read(work / f'private-storage-fragments-{name}-gates.json')) for name in F['PHASES']}
    validate_evidence(value)
    return value


def validate_report(report, revision):
    require(re.fullmatch('[0-9a-f]{40}', revision) and report['source_revision'] == revision
        and report['schema_version'] == 1 and report['report_kind'] == 'volparossa-' + NAME
        and report['success'] is True and report['runner_exit_status'] == 0
        and report['phase'] == NAME + '-complete' and report['observed_blocker'] is None
        and report['cleanup'] == dict(complete=True, remaining_owned_objects=0)
        and report['host_state']['unchanged'] is True, 'source-bound cleanup missing')
    validate_evidence(report['maintenance'])


def main(args):
    if args == ['export-names']:
        print('\n'.join(EXPORT_NAMES)); return
    if len(args) == 3 and args[0] == 'report':
        validate_report(read(Path(args[1])), args[2]); return
    if len(args) == 3 and args[0] == 'evidence':
        result = evidence(Path(args[1]))
        Path(args[2]).write_text(json.dumps(result, sort_keys=True) + '\n')
        return
    if len(args) == 10 and args[0] == 'prepare':
        result = prepare(private_root(args[1]), *args[2:])
    elif len(args) == 7 and args[0] in ('upload', 'restore', 'finish'):
        root = private_root(args[1])
        socket = Path(args[3])
        require(socket.parts[-3:] == ('runtime-client', 'control', 'agent.sock'), 'fixture client socket differs')
        exit_socket = socket.parents[2] / 'runtime-exit/control/agent.sock'
        baseline = int(os.environ['STORAGE_PROOF_BASELINE_MS'])
        scope = json.loads(os.environ['STORAGE_PROOF_ROUTE_SCOPE'])
        SAMPLER['validate_route_scope'](scope)
        with SAMPLER['capture'](args[2], exit_socket, baseline, F['PHASES'][args[0]], client=socket, scope=scope) as coverage:
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
    def interrupted(_signal, _frame):
        raise InterruptedError('fixture interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps(dict(version=1, success=False, kind='private-storage-maintenance-failure', stage=STAGE)))
        sys.exit(1)
