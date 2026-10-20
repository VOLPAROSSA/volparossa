#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable hosted verification of the committed lock and public core tests.

No hardware access, worker admission, private task release or local Cargo entrypoint.
Schemas 1/2 retain fourteen-test replay and schema 3 its twenty-two-test endorsement
profile, and schema 4 its twenty-eight certificate-algorithm tests. Schema 5
also checks the fixed Milan path and authentic ARK CRL in forty tests. None of
these profiles supplies full appraisal, worker admission or private execution.
Hosted schema 6 adds explicit owner-local policy comparisons in fifty-two tests.
"""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REV = 'a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5'
SEV_SOURCE = 'git+https://github.com/virtee/sev?rev=' + REV + '#' + REV
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
# Exact published x509-cert 0.2.5 selects der derive/flagset; pinned sev also
# enables x509's default pem feature. These only add the three optional edges
# declared by the existing der 0.7.10, never update that package or old edges.
# New package versions remain resolver output, not independent prior admission.
DER = ('der', '0.7.10', REGISTRY)
DER_FEATURE_EDGES = {'der_derive': (0, 7, 2), 'flagset': (0, 4, 3), 'pem-rfc7468': (0, 7, 0)}
# Exact feature edges selected by the verifier's crypto dependencies. The first
# three targets already exist; num-bigint-dig additionally enables lazy_static's
# spin_no_std feature. Only the exact observed target identities are admitted.
EXACT_FEATURE_EDGES = {
    ('digest', '0.10.7', REGISTRY): (('const-oid', '0.9.6', REGISTRY),
        '9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292'),
    ('num-traits', '0.2.19', REGISTRY): (('libm', '0.2.16', REGISTRY),
        '071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841'),
    ('generic-array', '0.14.7', REGISTRY): (('zeroize', '1.9.1', REGISTRY),
        '85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a'),
    ('lazy_static', '1.5.0', REGISTRY): (('spin', '0.9.9', REGISTRY),
        'bbd2bcb4c963f2ddae06a2efc7e9f3591312473c50c6685e1f298068316e66fe'),
}
FEATURE_PROVENANCE = dict(
    x509_manifest='https://docs.rs/crate/x509-cert/0.2.5/source/Cargo.toml',
    x509_crate_sha256='1301e935010a701ae5f8655edc0ad17c44bad3ac5ce8c39185f75453b720ae94',
    der_manifest='https://docs.rs/crate/der/0.7.10/source/Cargo.toml',
    der_manifest_sha256='ab115a95d89b2a7da3cd8264684f74f905322331db94ec7044511ad87d1cf331',
    der_crate_sha256='e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb',
    rsa_manifest='https://github.com/RustCrypto/RSA/blob/v0.9.10/Cargo.toml',
    digest_manifest='https://docs.rs/crate/digest/0.10.7/source/Cargo.toml',
    digest_manifest_sha256='f0cc2fc18c6e7f3533658b9e59d71b55e641e7d8226e5d1b915a5e7c0a1d3f36',
    num_traits_manifest='https://docs.rs/crate/num-traits/0.2.19/source/Cargo.toml',
    num_traits_manifest_sha256='dd701a0da6cce7e6e047cc944b2330f3c5e48cd64329e10942ea7d9299d435be',
    generic_array_archive='https://static.crates.io/crates/generic-array/generic-array-0.14.7.crate',
    generic_array_manifest_sha256='4b5daed75505275d11f4854dd9172f910da61d9856ca2936d95e2e6e0c9040e4',
    elliptic_curve_archive='https://static.crates.io/crates/elliptic-curve/elliptic-curve-0.13.8.crate',
    elliptic_curve_manifest_sha256='ae28aa3db758a5b18bf9e4b1253082b2503067f41be65e0bf3dc89917fda3f76',
    lazy_static_archive='https://static.crates.io/crates/lazy_static/lazy_static-1.5.0.crate',
    lazy_static_manifest_sha256='7556429fefb497526c5abdaa2c36d8ce4eb86c23d72763eb396652b9eaffc210',
    num_bigint_archive='https://static.crates.io/crates/num-bigint-dig/num-bigint-dig-0.8.6.crate',
    num_bigint_manifest_sha256='04a7ed71706ef6637f12982772ee3772074df403647e74c4c5830fc823555257',
    sev_manifest='https://github.com/virtee/sev/blob/' + REV + '/Cargo.toml')
PREFIX = 'provider::compute::attestation::tests::'
TESTS = tuple(PREFIX + name for name in (
    'upstream_public_fixtures_and_reference_roots_match_source_pins',
    'real_public_signatures_return_only_incomplete_facts',
    'signed_report_or_certificate_tampering_is_rejected_by_actual_crypto',
    'exact_received_framing_version_and_reserved_bytes_are_required',
    'unsupported_key_policy_platform_and_certificate_shapes_fail_closed',
    'actual_public_report_cannot_bind_to_fresh_owner_even_with_matching_measurement',
    'synthetic_binding_positive_is_explicitly_not_full_appraisal_or_release',
    'fresh_nonce_owner_policy_and_proposed_key_are_all_bound',
    'measurement_svn_debug_migration_and_each_certificate_time_are_checked',
    'delayed_expired_rollback_and_cancelled_bindings_cannot_succeed',
    'pending_slots_release_but_attempts_never_refund_on_drop_cancel_or_failure',
    'owner_bounds_expire_without_rebasing_challenge_or_attempt_budget',
    'public_binding_codec_rejects_unknown_duplicate_noncanonical_and_oversize',
    'public_signature_binding_entrypoint_consumes_its_attempt_without_release',
))
ENDORSEMENT_TESTS = TESTS + tuple(PREFIX + name for name in (
    'endorsement_public_fixture_binds_all_milan_claims',
    'endorsement_requires_complete_unique_noncritical_known_extensions',
    'endorsement_integer_der_and_ranges_are_canonical',
    'endorsement_product_version_and_raw_hwid_are_not_interchangeable',
    'endorsement_tcb_uses_exact_reported_component_order',
    'endorsement_mismatched_chip_or_each_spl_is_rejected',
    'endorsement_mutation_cannot_bypass_signature_verification',
    'endorsement_consistency_never_clears_remaining_appraisal',
))
CERTIFICATE_PROFILE_TESTS = ENDORSEMENT_TESTS + tuple(PREFIX + name for name in (
    'certificate_profile_public_chain_and_report_keep_incomplete_facts',
    'certificate_profile_outer_algorithm_mutations_are_rejected_with_signed_bytes_unchanged',
    'certificate_profile_synthetic_pss_parameters_are_closed',
    'certificate_profile_synthetic_inner_outer_mismatch_is_rejected',
    'certificate_profile_synthetic_spki_requires_p384_byte_aligned_point',
    'certificate_profile_preserves_signature_and_session_gates',
))
COLLATERAL_PREFIX = 'provider::compute::attestation::collateral::tests::'
COLLATERAL_TESTS = CERTIFICATE_PROFILE_TESTS + tuple(COLLATERAL_PREFIX + name for name in (
    'public_signed_milan_crl_and_complete_path_are_actually_verified',
    'real_crl_signature_rejects_signed_body_signature_and_wrong_key_mutations',
    'crl_framing_is_bounded_canonical_and_byte_aligned',
    'authenticated_crl_validity_is_inclusive_start_exclusive_end',
    'synthetic_path_issuer_versions_unique_ids_and_leaf_identity_are_closed',
    'synthetic_ca_constraints_usage_identifiers_and_extensions_are_closed',
    'synthetic_crl_scope_issuer_authority_and_critical_extensions_fail_closed',
    'synthetic_revocation_entries_cannot_hide_ask_or_change_issuer_scope',
    'authentic_collateral_cannot_make_historical_report_fresh',
    'synthetic_bound_expiry_never_exceeds_crl_or_certificate',
    'synthetic_collateral_expiry_and_cancel_are_rechecked_before_binding',
    'synthetic_profile_acceptance_never_substitutes_for_real_crl_signature',
))
LOCAL_POLICY_TESTS = COLLATERAL_TESTS + tuple(PREFIX + name for name in (
    'local_policy_public_fixture_obeys_explicit_fixture_only_floor',
    'local_policy_each_tcb_stage_and_component_enforces_its_floor',
    'local_policy_synthetic_component_order_is_not_lexicographic',
    'local_policy_synthetic_smt_permission_and_state_are_distinct',
    'local_policy_synthetic_measurement_svn_debug_and_migration',
    'local_policy_invalid_configuration_is_rejected',
    'local_policy_signed_mutation_cannot_bypass_crypto',
    'local_policy_challenge_binds_every_policy_field',
    'local_policy_old_or_noncanonical_challenges_are_rejected',
    'local_policy_synthetic_rejection_consumes_one_attempt',
    'local_policy_synthetic_owner_and_collateral_bounds',
    'local_policy_synthetic_success_preserves_appraisal_obligations',
))
MAX_LOCK = 1024 * 1024
MAX_LOG = 2 * 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024
SCOPE = dict(public_inputs_only=True, hardware_attestation=False, full_appraisal=False,
    worker_admission=False, private_input_release=False, protected_execution=False,
    os_network_sandbox=False)
EXPORTS = ('source.json', 'original-Cargo.lock', 'effective-Cargo.lock', 'Cargo.lock.diff',
    'resolution.json', 'resolved-metadata.json', 'tests.json', 'clippy.json', 'report.json',
    'rustc.txt', 'cargo.txt', 'resolve.log', 'metadata.log', 'tests.log', 'clippy.log')
# Retain the established export names. In schemas 2–6 both lock snapshots are the
# committed bytes, the diff is empty, and resolution.json records a locked fetch.
LOCK_POLICY = 'committed-lock-unchanged'


def evidence_schema(*, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    require(type(historical) is bool and type(endorsement) is bool
        and type(certificate_profile) is bool and type(collateral) is bool and type(local_policy) is bool
        and sum((historical, endorsement, certificate_profile, collateral, local_policy)) <= 1, 'evidence_profile')
    return 6 if local_policy else 5 if collateral else 4 if certificate_profile else 3 if endorsement else 1 if historical else 2


def envelope(kind, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False, **fields):
    value = dict(schema_version=evidence_schema(historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy), kind=kind, **fields)
    if not historical:
        value['lock_policy'] = LOCK_POLICY
    return value


def source_receipt(selected, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    return envelope('core-attestation-source', historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy,
        source=selected, scope=SCOPE, tests_executed=False)


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def stable_file(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_nlink, info.st_mode,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == os.getuid() and not before.st_mode & 0o022, 'input_file')
        require(before.st_size <= maximum, 'input_bound')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) <= maximum and stable_file(before) == stable_file(after)
            and stable_file(os.stat(path, follow_symlinks=False)) == stable_file(after), 'input_changed')
        return raw


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def record(path, value):
    write(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def git(*args):
    raw = subprocess.check_output(['git', '-c', 'core.filemode=true', '-C', str(ROOT), *args], timeout=15)
    require(len(raw) <= MAX_LOCK, 'git_bound')
    return raw


def source(*, effective=False, collateral=False, local_policy=False):
    head = git('rev-parse', 'HEAD').decode('ascii').strip()
    require(re.fullmatch('[0-9a-f]{40}', head) and head == os.environ['GITHUB_SHA'], 'source_commit')
    flags = git('ls-files', '-v', '-z').split(b'\0')
    require(flags[-1] == b'' and all(value.startswith(b'H ') for value in flags[:-1]), 'source_index_flags')
    status = git('status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching')
    require(status in ((b'', b' M Cargo.lock\0') if effective else (b'',)), 'source_changed')
    require(not git('diff', '--no-ext-diff', '--no-textconv', '--summary', 'HEAD', '--'), 'source_mode')
    manifest = tomllib.loads(read(ROOT / 'Cargo.toml', 32768).decode())
    selected = manifest['workspace']['dependencies']['sev']
    require(selected == {'version': '=8.0.0', 'git': 'https://github.com/virtee/sev', 'rev': REV,
        'default-features': False, 'features': ['snp', 'crypto_nossl']}, 'sev_selection')
    require(manifest['workspace']['dependencies']['x509-cert'] ==
        {'version': '=0.2.5', 'default-features': False, 'features': ['std']}, 'x509_selection')
    content = tomllib.loads(read(ROOT / 'crates/volparossa-content/Cargo.toml', 32768).decode())
    require(content['dependencies']['sev'] == {'workspace': True}
        and content['dependencies']['x509-cert'] == {'workspace': True}, 'content_selection')
    if collateral or local_policy:
        require(manifest['workspace']['dependencies']['rsa'] ==
            {'version': '=0.9.10', 'default-features': False, 'features': ['std']}
            and content['dependencies']['rsa'] == {'workspace': True}, 'rsa_selection')
    original = git('show', 'HEAD:Cargo.lock')
    if not effective:
        require(read(ROOT / 'Cargo.lock', MAX_LOCK) == original, 'original_lock')
    return dict(commit=head, tree=git('rev-parse', 'HEAD^{tree}').decode('ascii').strip(),
        original_lock=digest(original), sev_revision=REV), original


def package_key(package):
    return package['name'], package['version'], package.get('source', '')


def lock_graph(raw):
    require(len(raw) <= MAX_LOCK, 'lock_bound')
    value = tomllib.loads(raw.decode('utf-8'))
    require(set(value) == {'version', 'package'} and value['version'] == 4
        and type(value['package']) is list and 1 <= len(value['package']) <= 1024, 'lock_schema')
    packages = {}
    for package in value['package']:
        require({'name', 'version'} <= set(package)
            <= {'name', 'version', 'source', 'checksum', 'dependencies'}, 'package_schema')
        key = package_key(package)
        require(key not in packages and all(type(field) is str for field in key)
            and re.fullmatch('[A-Za-z0-9_-]{1,100}', key[0])
            and re.fullmatch('[0-9A-Za-z.+-]{1,100}', key[1]) and len(key[2]) <= 512, 'package_identity')
        if 'checksum' in package:
            require(re.fullmatch('[a-f0-9]{64}', package['checksum']), 'package_checksum')
        packages[key] = package
    edges = {}
    for key, package in packages.items():
        deps = package.get('dependencies', [])
        require(type(deps) is list and len(deps) <= 256, 'dependency_bound')
        resolved = []
        for dep in deps:
            require(type(dep) is str and len(dep) <= 750, 'dependency_encoding')
            match = re.fullmatch(r'([A-Za-z0-9_-]+)(?: ([0-9A-Za-z.+-]+))?(?: \(([^)]+)\))?', dep)
            require(match is not None, 'dependency_encoding')
            name, version, origin = match.groups()
            candidates = [candidate for candidate in packages if candidate[0] == name
                and (version is None or candidate[1] == version)
                and (origin is None or candidate[2] == origin)]
            require(len(candidates) == 1, 'dependency_resolution')
            resolved.append(candidates[0])
        require(len(set(resolved)) == len(resolved), 'duplicate_dependency')
        edges[key] = set(resolved)
    return packages, edges


def lock_delta(original, effective):
    old, old_edges = lock_graph(original)
    new, new_edges = lock_graph(effective)
    content = ('volparossa-content', '0.1.0', '')
    direct = {('sev', '8.0.0', SEV_SOURCE), ('x509-cert', '0.2.5', REGISTRY)}
    require(content in old and set(old) <= set(new) and direct <= set(new), 'existing_package_removed_or_changed')
    feature_edges = set()
    exact_edges = {}
    if DER in old:
        require(old[DER]['checksum'] == FEATURE_PROVENANCE['der_crate_sha256'], 'der_source')
        for name, minimum in DER_FEATURE_EDGES.items():
            candidates = []
            for key in new:
                if key[0] == name and key[2] == REGISTRY and re.fullmatch(r'0\.[0-9]{1,3}\.[0-9]{1,5}', key[1]):
                    version = tuple(int(part) for part in key[1].split('.'))
                    if version[:2] == minimum[:2] and version >= minimum:
                        candidates.append(key)
            require(len(candidates) == 1, 'der_feature_dependency')
            feature_edges.add(candidates[0])
    for parent, (target, checksum) in EXACT_FEATURE_EDGES.items():
        if parent in old:
            require(old[parent]['checksum'] == checksum and target in new, 'exact_feature_source')
            exact_edges[parent] = target
    for key, package in old.items():
        require({k: v for k, v in package.items() if k != 'dependencies'} ==
            {k: v for k, v in new[key].items() if k != 'dependencies'}, 'existing_package_metadata_changed')
        expected = old_edges[key] | direct if key == content else old_edges[key]
        if key == DER:
            expected = expected | feature_edges
        if key in exact_edges:
            expected = expected | {exact_edges[key]}
        require(new_edges[key] == expected, 'existing_dependency_changed')
    added = set(new) - set(old)
    require(1 <= len(added) <= 128 and direct <= added, 'new_dependency_bound')
    reached, todo = set(), list(direct)
    while todo:
        key = todo.pop()
        if key not in reached:
            reached.add(key)
            todo.extend(new_edges[key])
    require(added <= reached, 'unrelated_new_package')
    for key in added:
        require(key[2] == REGISTRY or key == ('sev', '8.0.0', SEV_SOURCE), 'new_dependency_source')
        require(key[2] != REGISTRY or 'checksum' in new[key], 'new_registry_checksum')
    return dict(original=digest(original), effective=digest(effective),
        original_packages=len(old), added_packages=[dict(name=key[0], version=key[1], source=key[2],
            checksum=new[key].get('checksum')) for key in sorted(added)],
        existing_package_versions_unchanged=True, original_dependency_edges_retained=True,
        unlisted_existing_dependency_edges_unchanged=True,
        feature_edge_package='der@0.7.10', feature_edge_provenance=FEATURE_PROVENANCE,
        added_feature_edges=[dict(name=key[0], version=key[1], source=key[2]) for key in sorted(feature_edges)],
        exact_feature_edges=[dict(parent_name=parent[0], parent_version=parent[1],
            target_name=target[0], target_version=target[1], source=REGISTRY)
            for parent, target in sorted(exact_edges.items())],
        changed_direct_package='volparossa-content', new_direct_dependencies=['sev', 'x509-cert'])


class MetadataPolicyError(ValueError):
    """A closed policy code plus already bounded public facts, never raw metadata."""

    def __init__(self, code, projection):
        super().__init__(code)
        self.projection = projection


def metadata_projection(raw, effective, *, collateral=False, local_policy=False):
    require(len(raw) <= MAX_METADATA, 'metadata_bound')
    data = json.loads(raw)
    packages, edges = lock_graph(effective)
    require(data.get('version') == 1 and isinstance(data.get('resolve'), dict), 'metadata_schema')
    require(type(data.get('packages')) is list and 1 <= len(data['packages']) <= 1024
        and type(data['resolve'].get('nodes')) is list and len(data['resolve']['nodes']) <= 1024,
        'metadata_schema')
    identities, nodes = {}, {}
    for package in data['packages']:
        key = (package['name'], package['version'], package.get('source') or '')
        identity = package.get('id')
        require(key in packages and type(identity) is str and 1 <= len(identity) <= 2048
            and identity not in identities, 'metadata_package')
        identities[identity] = key
    for node in data['resolve']['nodes']:
        identity = node.get('id')
        require(type(identity) is str and identity in identities and identity not in nodes,
            'metadata_node')
        nodes[identity] = node
    selected = []
    for package in data['packages']:
        key = identities[package['id']]
        if key[0] in ('sev', 'x509-cert'):
            require(package['id'] in nodes, 'metadata_selection')
            features = nodes[package['id']]['features']
            require(type(features) is list and len(features) <= 32
                and all(type(x) is str and re.fullmatch('[A-Za-z0-9_+-]{1,80}', x) for x in features)
                and len(set(features)) == len(features), 'metadata_features')
            require(package['license'] is None or (type(package['license']) is str
                and re.fullmatch('[A-Za-z0-9 .+()-]{1,128}', package['license'])), 'metadata_license')
            require(package['rust_version'] is None or (type(package['rust_version']) is str
                and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?', package['rust_version'])),
                'metadata_rust_version')
            selected.append(dict(name=key[0], version=key[1], source=key[2],
                license=package['license'], rust_version=package['rust_version'], features=sorted(features)))
            if key[0] == 'sev':
                dependencies = nodes[package['id']].get('deps')
                require(type(dependencies) is list and len(dependencies) <= 256, 'metadata_dependencies')
                observed, seen = [], set()
                for dependency in dependencies:
                    identity = dependency.get('pkg')
                    require(type(identity) is str and identity in identities and identity in nodes
                        and identity not in seen, 'metadata_dependency')
                    seen.add(identity)
                    target = identities[identity]
                    require(target in edges[key], 'metadata_dependency_lock')
                    kinds = dependency.get('dep_kinds')
                    require(type(kinds) is list and 1 <= len(kinds) <= 16
                        and all(type(kind) is dict and kind.get('kind') in (None, 'build', 'dev')
                            and 'kind' in kind and 'target' in kind for kind in kinds), 'metadata_dependency_kind')
                    # Package IDs and cfg/path strings stay private. Only an actual
                    # unconditional normal edge under its expected library name counts.
                    observed.append(dict(name=target[0], version=target[1], source=target[2],
                        normal=any(kind['kind'] is None and kind['target'] is None for kind in kinds),
                        unrenamed=dependency.get('name') == target[0].replace('-', '_')))
                selected[-1]['dependencies'] = sorted(observed, key=lambda item: (item['name'], item['version'], item['source']))
    require(len(selected) == 2, 'metadata_selection')
    projection = dict(raw_metadata=digest(raw), selected_packages=selected,
        format='cargo-metadata-1-public-projection', local_paths_exported=False)
    sev = next(value for value in selected if value['name'] == 'sev')
    # Pinned sev uses dep:p384/dep:rsa/dep:sha2/dep:x509-cert, which suppress
    # implicit dependency-named features. Check named features and edges separately.
    if not (sev['source'] == SEV_SOURCE and sev['version'] == '8.0.0'
            and set(sev['features']) == {'snp', 'crypto_nossl'}):
        raise MetadataPolicyError('actual_sev_features', projection)
    for name in ('p384', 'rsa', 'sha2', 'x509-cert'):
        targets = [item for item in sev['dependencies'] if item['name'] == name]
        if not (len(targets) == 1 and targets[0]['source'] == REGISTRY
                and targets[0]['normal'] and targets[0]['unrenamed']):
            raise MetadataPolicyError('actual_sev_dependencies', projection)
    if collateral or local_policy:
        projection['public_crl_verifier'] = collateral_metadata(identities, nodes, packages, edges)
    return projection


def collateral_metadata(identities, nodes, packages, edges):
    """Exact additional public-only edge; no dependency IDs or local paths exported."""
    selected = ('rsa', '0.9.10', REGISTRY)
    checksum = 'b8573f03f5883dcaebdfcf4725caa1ecb9c15b2ef50c43a07b816e06799bb12d'
    parents = {('sev', '8.0.0', SEV_SOURCE), ('volparossa-content', '0.1.0', '')}
    require(selected in packages and packages[selected]['checksum'] == checksum, 'rsa_lock_identity')
    require({key for key, targets in edges.items() if selected in targets} == parents, 'rsa_lock_parents')
    found = [identity for identity, key in identities.items() if key == selected]
    require(len(found) == 1 and found[0] in nodes, 'rsa_metadata_identity')
    identity = found[0]
    features = nodes[identity].get('features')
    require(type(features) is list and sorted(features) == ['default', 'pem', 'std', 'u64_digit'], 'rsa_metadata_features')
    incoming = []
    for parent_id, node in nodes.items():
        require(node.get('dependencies', []).count(identity) ==
            sum(edge.get('pkg') == identity for edge in node.get('deps', [])), 'rsa_metadata_hidden_edge')
        for edge in node.get('deps', []):
            if edge.get('pkg') == identity:
                require(edge.get('name') == 'rsa' and edge.get('dep_kinds') == [dict(kind=None, target=None)]
                    and node.get('dependencies', []).count(identity) == 1, 'rsa_metadata_edge')
                incoming.append(identities[parent_id])
    require(len(incoming) == 2 and set(incoming) == parents, 'rsa_metadata_parents')
    return dict(name=selected[0], version=selected[1], source=selected[2], checksum=checksum,
        features=sorted(features), direct_caller='volparossa-content', purpose='public-ARK-CRL-PSS-SHA384-verification-only')


def verify_tests(raw, *, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    evidence_schema(endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    names = LOCAL_POLICY_TESTS if local_policy else COLLATERAL_TESTS if collateral else CERTIFICATE_PROFILE_TESTS if certificate_profile else ENDORSEMENT_TESTS if endorsement else TESTS
    count = len(names)
    text = raw.decode('utf-8')
    observed = re.findall(r'^test (\S+) \.\.\. (\S+)[ \t]*$', text, re.M)
    require(len(observed) == count and set(observed) == {(name, 'ok') for name in names}, 'exact_tests')
    require(len(re.findall(r'^running ' + str(count) + r' tests\s*$', text, re.M)) == 1, 'tests_not_executed')
    results = re.findall(r'^test result: (.+)$', text, re.M)
    require(len(results) == 1 and re.fullmatch(r'ok\. ' + str(count)
        + r' passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\s*', results[0]), 'test_summary')
    return dict(names=list(names), passed=count, failed=0, ignored=0,
        scope='public signed fixture and explicit owner-local comparisons; separately synthetic policy and session state; no current vendor mitigation, hardware or admission proof'
            if local_policy else 'public report, certificate path and signed ARK CRL fixtures; synthetic negative profile and binding-state tests; no fresh hardware report or full appraisal'
            if collateral else 'public crypto, certificate algorithm profile and endorsement consistency fixtures and explicitly synthetic structure and binding-state unit tests'
            if certificate_profile else 'public crypto and endorsement consistency fixtures and explicitly synthetic binding-state unit tests'
            if endorsement else 'public crypto fixtures and explicitly synthetic binding-state unit tests')


def hosted():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
        and os.environ.get('GITHUB_REPOSITORY') == 'VOLPAROSSA/volparossa'
        and os.environ.get('GITHUB_WORKFLOW') == 'Protected compute core evidence'
        and os.environ.get('GITHUB_REF') in ('refs/heads/feature/protected-compute-admission',
            'refs/heads/feature/protected-compute-endorsement',
            'refs/heads/feature/protected-compute-cert-profile', 'refs/heads/feature/protected-compute-collateral',
            'refs/heads/feature/protected-compute-local-policy', 'refs/heads/feature/protected-compute-guest',
            'refs/heads/feature/protected-compute-quote-exchange')
        and os.getuid() != 0, 'disposable_branch_only')


def workdir():
    base = Path(os.environ['RUNNER_TEMP'])
    require(base.is_absolute() and base.resolve() == base and base.is_dir(), 'runner_temp')
    path = base / 'volparossa-protected-compute-admission'
    require(not path.resolve().is_relative_to(ROOT.resolve()), 'work_outside_checkout')
    return path


class RunInterrupted(BaseException):
    """Not OSError/EINTR: selectors must not silently restart cancellation."""


def install_signals():
    def stop(_signum, _frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise RunInterrupted()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)


def run(argv, output, seconds, *, stdout=None):
    """One bounded fixed Cargo/tool command; stderr remains public build output."""
    start = time.monotonic()
    child = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE if stdout else subprocess.STDOUT, start_new_session=True)
    code, reason, joined = None, None, False
    streams = {}
    selector = None
    try:
        selector = selectors.DefaultSelector()
        for pipe, path, limit in ((child.stdout, stdout or output, MAX_METADATA if stdout else MAX_LOG),
                *(([(child.stderr, output, MAX_LOG)]) if stdout else [])):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            streams[pipe] = [os.fdopen(fd, 'wb'), limit, 0]
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() - start >= seconds:
                raise TimeoutError('command_deadline')
            for key, _ in selector.select(0.2):
                raw = os.read(key.fileobj.fileno(), 8192)
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                target, maximum, count = streams[key.fileobj]
                target.write(raw[:max(0, maximum - count)])
                streams[key.fileobj][2] += len(raw)
                require(count + len(raw) <= maximum, 'command_output_bound')
        code = child.wait(timeout=max(0.1, seconds - (time.monotonic() - start)))
    except RunInterrupted:
        reason = 'command_interrupted'
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, ValueError) else 'command_io_or_deadline'
    finally:
        # The process group was created here; drain it even if its leader exited
        # while a compiler still holds a pipe. This is not a setsid-proof sandbox.
        try:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
                joined = True
            except subprocess.TimeoutExpired:
                pass
            # Also terminate children in our group if its leader exited first.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            joined = True
        except (OSError, subprocess.TimeoutExpired, RunInterrupted):
            reason = reason or 'command_cleanup_unconfirmed'
        for target, _, _ in streams.values():
            try:
                target.close()
            except (OSError, RunInterrupted):
                reason = reason or 'command_output_close_failed'
        for resource in (child.stdout, child.stderr, selector):
            if resource is not None:
                try:
                    resource.close()
                except (OSError, RunInterrupted):
                    reason = reason or 'command_output_close_failed'
    return dict(exit_status=code if code is not None else child.returncode,
        capture_error=reason, leader_joined=joined,
        cleanup_scope='owned-process-group-not-a-setsid-proof-sandbox',
        elapsed_ms=int((time.monotonic() - start) * 1000))


def command_ok(outcome):
    require(outcome['exit_status'] == 0 and outcome['capture_error'] is None
        and outcome['leader_joined'] is True, 'command_failed')


def cargo_env(work):
    os.environ.update(CARGO_HOME=str(work / 'cargo-home'), CARGO_TARGET_DIR=str(work / 'target'),
        CARGO_BUILD_JOBS='2', CARGO_TERM_COLOR='never', CARGO_INCREMENTAL='0',
        RUSTUP_TOOLCHAIN='1.85.0')
    os.environ.pop('CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS', None)


def check_effective(work):
    """Historical schema 1 lock-delta replay only; not the current source gate."""
    selected, original = source(effective=True)
    require(read(work / 'evidence/original-Cargo.lock', MAX_LOCK) == original, 'original_lock_retained')
    effective = read(ROOT / 'Cargo.lock', MAX_LOCK)
    require(effective == read(work / 'evidence/effective-Cargo.lock', MAX_LOCK), 'effective_lock_changed')
    lock_delta(original, effective)
    return selected


def check_committed(work, *, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    selected, original = source(collateral=collateral, local_policy=local_policy)
    evidence = work / 'evidence'
    require(read(evidence / 'original-Cargo.lock', MAX_LOCK) == original, 'original_lock_retained')
    require(json.loads(read(evidence / 'source.json', MAX_LOCK)) == source_receipt(selected, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy),
        'source_receipt')
    return selected, original


def locked_fetch_receipt(selected, original, effective, outcome, log, *, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    return envelope('core-attestation-committed-lock-fetch', endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy, source=selected,
        command=outcome, original=digest(original), effective=digest(effective), scope=SCOPE,
        log=digest(log), tests_executed=False, committed_lock_unchanged=original == effective,
        passed=False)


def check_lock(work, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    evidence_schema(historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    if historical:
        return check_effective(work)
    selected, original = check_committed(work, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    evidence = work / 'evidence'
    effective = read(evidence / 'effective-Cargo.lock', MAX_LOCK)
    require(original == effective, 'committed_lock_changed')
    require(read(evidence / 'Cargo.lock.diff', MAX_LOCK) == b'', 'lock_diff_changed')
    value = json.loads(read(evidence / 'resolution.json', MAX_LOCK))
    expected = locked_fetch_receipt(selected, original, effective, value['command'],
        read(evidence / 'resolve.log', MAX_LOG), endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    expected['passed'] = True
    require(value == expected, 'locked_fetch_required')
    command_ok(value['command'])
    return selected


def toolchain_version(raw, tool):
    text = raw.decode('ascii')
    require(text.startswith(tool + ' 1.85.0 ')
        and '\nrelease: 1.85.0\n' in '\n' + text + '\n', 'toolchain_version')


def prepare(work, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    evidence_schema(historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    selected, original = source(collateral=collateral, local_policy=local_policy)
    work.mkdir(mode=0o700)
    evidence = work / 'evidence'
    evidence.mkdir(mode=0o700)
    write(evidence / 'original-Cargo.lock', original)
    record(evidence / 'source.json', source_receipt(selected, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy))
    for tool in ('rustc', 'cargo'):
        outcome = run([tool, '+1.85.0', '--version', '--verbose'], evidence / (tool + '.txt'), 30)
        command_ok(outcome)
        toolchain_version(read(evidence / (tool + '.txt'), 32768), tool)


def fetch(work, *, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    selected, original = check_committed(work, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    evidence = work / 'evidence'
    outcome = run(['cargo', '+1.85.0', 'fetch', '--locked', '--manifest-path', str(ROOT / 'Cargo.toml')],
        evidence / 'resolve.log', 300)
    effective = read(ROOT / 'Cargo.lock', MAX_LOCK)
    write(evidence / 'effective-Cargo.lock', effective)
    diff = ''.join(difflib.unified_diff(original.decode().splitlines(True), effective.decode().splitlines(True),
        fromfile='original-Cargo.lock', tofile='effective-Cargo.lock')).encode()
    require(len(diff) <= MAX_LOCK, 'lock_diff_bound')
    write(evidence / 'Cargo.lock.diff', diff)
    result = locked_fetch_receipt(selected, original, effective, outcome,
        read(evidence / 'resolve.log', MAX_LOG), endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    try:
        command_ok(outcome)
        require(original == effective, 'committed_lock_changed')
        check_committed(work, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        result['passed'] = True
    except ValueError as error:
        result['error'] = str(error)
        raise
    finally:
        record(evidence / 'resolution.json', result)


def metadata(work, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    selected = check_lock(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    evidence = work / 'evidence'
    outcome = run(['cargo', '+1.85.0', 'metadata', '--locked', '--offline', '--format-version', '1',
        '--filter-platform', 'x86_64-unknown-linux-gnu'], evidence / 'metadata.log', 120,
        stdout=work / 'metadata.json')
    result = envelope('core-attestation-resolved-metadata', historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy, source=selected,
        command=outcome, log=digest(read(evidence / 'metadata.log', MAX_LOG)), passed=False, scope=SCOPE)
    try:
        command_ok(outcome)
        result['projection'] = metadata_projection(read(work / 'metadata.json', MAX_METADATA),
            read(ROOT / 'Cargo.lock', MAX_LOCK), collateral=collateral, local_policy=local_policy)
        check_lock(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        result['passed'] = True
    except MetadataPolicyError as error:
        result['projection'] = error.projection
        result['error'] = str(error)
        raise
    finally:
        record(evidence / 'resolved-metadata.json', result)


def check_metadata(work, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    value = json.loads(read(work / 'evidence/resolved-metadata.json', MAX_LOCK))
    require(value['passed'] is True and value['scope'] == SCOPE, 'metadata_required')
    require(value['schema_version'] == evidence_schema(historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        and value['kind'] == 'core-attestation-resolved-metadata', 'metadata_schema')
    if not historical:
        require(value['lock_policy'] == LOCK_POLICY and value['source'] == check_lock(work, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy),
            'metadata_source')
    command_ok(value['command'])
    require(value['projection'] == metadata_projection(read(work / 'metadata.json', MAX_METADATA),
        read(ROOT / 'Cargo.lock', MAX_LOCK), collateral=collateral, local_policy=local_policy), 'metadata_changed')
    return value


def execute(work, phase, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    selected = check_lock(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    check_metadata(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    argv = ['cargo', '+1.85.0']
    if phase == 'test':
        argv += ['test', '--locked', '--offline', '-p', 'volparossa-content', '--lib',
            'provider::compute::attestation::' if collateral or local_policy else PREFIX,
            '--', '--test-threads=1']
        name, deadline = 'tests', 1200
    else:
        require(phase == 'clippy', 'phase')
        tests = json.loads(read(work / 'evidence/tests.json', 32768))
        require(tests['passed'] is True, 'tests_required')
        if not historical:
            require(tests['schema_version'] == evidence_schema(endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy) and tests['lock_policy'] == LOCK_POLICY
                and tests['source'] == selected and tests['scope'] == SCOPE
                and tests['tests'] == verify_tests(read(work / 'evidence/tests.log', MAX_LOG), endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy),
                'tests_receipt')
            command_ok(tests['command'])
        argv += ['clippy', '--locked', '--offline', '-p', 'volparossa-content', '--lib', '--tests', '--', '-D', 'warnings']
        name, deadline = 'clippy', 600
    evidence = work / 'evidence'
    outcome = run(argv, evidence / (name + '.log'), deadline)
    result = envelope('core-attestation-' + name, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy, command=outcome,
        source=selected, log=digest(read(evidence / (name + '.log'), MAX_LOG)), passed=False, scope=SCOPE)
    try:
        command_ok(outcome)
        check_lock(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        if phase == 'test':
            result['tests'] = verify_tests(read(evidence / 'tests.log', MAX_LOG), endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        result['passed'] = True
    except ValueError as error:
        result['error'] = str(error)
        raise
    finally:
        record(evidence / (name + '.json'), result)


def verify_evidence(work, records, files, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    """Reconstruct success from retained original bytes, not a caller's pass flag."""
    evidence = work / 'evidence'
    require(set(files) == set(EXPORTS) - {'report.json'}, 'evidence_closure')
    selected = check_lock(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    require(records['source.json'] == source_receipt(selected, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy), 'source_receipt')
    original = read(evidence / 'original-Cargo.lock', MAX_LOCK)
    effective = read(evidence / 'effective-Cargo.lock', MAX_LOCK)
    resolution = records['resolution.json']
    require(resolution['original'] == digest(original) and resolution['effective'] == digest(effective)
        and resolution['tests_executed'] is False, 'resolution_receipt')
    if historical:
        require(resolution['delta'] == lock_delta(original, effective), 'resolution_receipt')
    else:
        expected = locked_fetch_receipt(selected, original, effective, resolution['command'],
            read(evidence / 'resolve.log', MAX_LOG), endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        expected['passed'] = True
        require(resolution == expected and original == effective, 'locked_fetch_receipt')
    expected_diff = ''.join(difflib.unified_diff(original.decode().splitlines(True), effective.decode().splitlines(True),
        fromfile='original-Cargo.lock', tofile='effective-Cargo.lock')).encode()
    require(read(evidence / 'Cargo.lock.diff', MAX_LOCK) == expected_diff, 'lock_diff_changed')
    require(check_metadata(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy) == records['resolved-metadata.json'], 'metadata_receipt')
    for name, log in (('resolution', 'resolve'), ('resolved-metadata', 'metadata'),
            ('tests', 'tests'), ('clippy', 'clippy')):
        value = records[name + '.json']
        require(value['passed'] is True and value['scope'] == SCOPE and value['source'] == selected,
            'stage_receipt')
        if not historical:
            kind = 'core-attestation-committed-lock-fetch' if name == 'resolution' else 'core-attestation-' + name
            require(value['schema_version'] == evidence_schema(endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy) and value['lock_policy'] == LOCK_POLICY
                and value['kind'] == kind, 'stage_schema')
            if name != 'resolution':  # The complete locked-fetch shape was checked above.
                keys = {'schema_version', 'kind', 'lock_policy', 'source', 'command', 'log', 'passed', 'scope'}
                keys |= {'projection'} if name == 'resolved-metadata' else {'tests'} if name == 'tests' else set()
                require(set(value) == keys, 'stage_schema')
        command_ok(value['command'])
        require(value['log'] == files[log + '.log'], 'stage_log_changed')
    require(records['tests.json']['tests'] == verify_tests(read(evidence / 'tests.log', MAX_LOG), endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy), 'tests_receipt')
    for tool in ('rustc', 'cargo'):
        toolchain_version(read(evidence / (tool + '.txt'), 32768), tool)


def receipt(work, *, historical=False, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    evidence_schema(historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
    evidence = work / 'evidence'
    records, files = {}, {}
    for name in EXPORTS:
        if name != 'report.json' and (evidence / name).exists():
            maximum = MAX_LOG if name.endswith('.log') else MAX_LOCK
            raw = read(evidence / name, maximum)
            files[name] = digest(raw)
            if name.endswith('.json'):
                records[name] = json.loads(raw)
    successful = False
    try:
        verify_evidence(work, records, files, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        successful = True
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        pass  # Keep original stage/log evidence; missing or inconsistent is not success.
    record(evidence / 'report.json', envelope('core-attestation-public-tests', historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy,
        source=records.get('source.json', {}).get('source'), files=files, passed=successful,
        stages={name: records.get(name, {}).get('passed') for name in
            ('resolution.json', 'resolved-metadata.json', 'tests.json', 'clippy.json')},
        scope=SCOPE))
    require(successful, 'incomplete_or_failed_public_test_trial')


def main(args):
    require(len(args) == 1 and args[0] in ('prepare', 'fetch', 'metadata', 'test', 'clippy', 'receipt'), 'fixed_command')
    hosted()
    install_signals()
    work = workdir()
    cargo_env(work)
    if args[0] == 'prepare':
        prepare(work, local_policy=True)
    elif args[0] in ('test', 'clippy'):
        execute(work, args[0], local_policy=True)
    else:
        globals()[args[0]](work, local_policy=True)


if __name__ == '__main__':
    main(sys.argv[1:])
