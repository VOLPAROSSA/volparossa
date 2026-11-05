#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert contracts: tiny Git/text fixtures and Python children, never Cargo."""
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('admission_probe', Path(__file__).with_name('protected-compute-admission.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
WORKFLOW = P.ROOT / '.github/workflows/protected-compute-admission.yml'


def package(name, version='1.0.0', dependencies=(), source=P.REGISTRY):
    value = dict(name=name, version=version, dependencies=list(dependencies))
    if source:
        value['source'] = source
        if source == P.REGISTRY:
            value['checksum'] = 'a' * 64
    return value


def fixture_packages():
    old = [package('volparossa-content', '0.1.0', ['base'], ''), package('base')]
    new = copy.deepcopy(old)
    new[0]['dependencies'] += ['sev', 'x509-cert']
    new += [package('sev', '8.0.0', ['x509-cert', 'crypto'], P.SEV_SOURCE),
        package('x509-cert', '0.2.5', ['crypto']), package('crypto')]
    return old, new


def verifier_packages():
    old, new = fixture_packages()
    new[2]['dependencies'] += ['p384', 'rsa', 'sha2']
    new += [package('p384', '0.13.1'), package('rsa', '0.9.10'), package('sha2', '0.10.9')]
    return old, new


def lock(packages):
    value = 'version = 4\n'
    for item in packages:
        value += '\n[[package]]\n' + ''.join(key + ' = ' + json.dumps(val) + '\n' for key, val in item.items())
    return value.encode()


def tool_outcome(code=0, error=None):
    return dict(exit_status=code, capture_error=error, leader_joined=True,
        cleanup_scope='owned-process-group-not-a-setsid-proof-sandbox', elapsed_ms=1)


def test_log(*, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    names = P.LOCAL_POLICY_TESTS if local_policy else P.COLLATERAL_TESTS if collateral else P.CERTIFICATE_PROFILE_TESTS if certificate_profile else P.ENDORSEMENT_TESTS if endorsement else P.TESTS
    return (f'running {len(names)} tests\n' + ''.join('test ' + name + ' ... ok\n' for name in names)
        + f'\ntest result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.1s\n').encode()


def metadata_fixture(packages):
    """Source-shaped synthetic metadata, not the failed runner's unretained array."""
    _, edges = P.lock_graph(lock(packages))
    identities = {P.package_key(item): 'fixture-id-' + str(i) for i, item in enumerate(packages)}
    result, nodes = [], []
    for i, item in enumerate(packages):
        identity = 'fixture-id-' + str(i)
        result.append(dict(id=identity, name=item['name'], version=item['version'],
            source=item.get('source'), license='Apache-2.0 OR MIT', rust_version='1.99.1',
            manifest_path='/private/not-exported/Cargo.toml',
            features={'snp': [], 'crypto_nossl': ['dep:p384', 'dep:rsa', 'dep:sha2', 'dep:x509-cert']}
                if item['name'] == 'sev' else {}))
        dependencies = sorted(edges[P.package_key(item)])
        nodes.append(dict(id=identity, features=['snp', 'crypto_nossl'] if item['name'] == 'sev'
            else ['default', 'pem', 'std', 'u64_digit'] if item['name'] == 'rsa' else ['std'],
            dependencies=[identities[key] for key in dependencies],
            deps=[dict(name=key[0].replace('-', '_'), pkg=identities[key],
                dep_kinds=[dict(kind=None, target=None)]) for key in dependencies]))
    return dict(version=1, packages=result, resolve=dict(nodes=nodes))


def git(root, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
        '-c', 'user.name=Inert fixture', '-c', 'user.email=fixture@example.invalid', '-C', str(root), *args],
        timeout=10).decode().strip()


@contextmanager
def source_fixture(*, committed=False, collateral=False, local_policy=False):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / 'source'
        root.mkdir()
        (root / 'crates/volparossa-content').mkdir(parents=True)
        for name in ('Cargo.toml', 'crates/volparossa-content/Cargo.toml'):
            (root / name).write_bytes((P.ROOT / name).read_bytes())
            (root / name).chmod(0o600)
        old, new = verifier_packages()
        if collateral or local_policy:
            new[0]['dependencies'].append('rsa')
            next(item for item in new if item['name'] == 'rsa')['checksum'] = 'b8573f03f5883dcaebdfcf4725caa1ecb9c15b2ef50c43a07b816e06799bb12d'
        (root / 'Cargo.lock').write_bytes(lock(new if committed else old))
        (root / 'Cargo.lock').chmod(0o600)
        (root / 'other.rs').write_text('public synthetic source\n')
        (root / '.gitignore').write_text('ignored-output\n')
        git(root, 'init', '-q')
        git(root, 'add', '--all')
        git(root, 'commit', '-qm', 'inert public source fixture')
        commit = git(root, 'rev-parse', 'HEAD')
        with patch.object(P, 'ROOT', root), patch.dict(os.environ, {'GITHUB_SHA': commit}):
            yield root, Path(tmp) / 'work', old, new


def public_trial_fixture(root, work, new, *, historical=True, endorsement=False, certificate_profile=False, collateral=False, local_policy=False):
    """Execute orchestration with synthetic public Cargo outputs, never Cargo."""
    def fake_run(argv, output, _deadline, *, stdout=None):
        if argv[1] == '--version':
            version = '1.99.1' if historical else '1.89.0'
            P.write(output, (argv[0] + ' ' + version + ' (inert)\nrelease: ' + version + '\n').encode())
        elif argv[1] == 'fetch':
            assert '--locked' in argv
            P.write(output, b'Fetched synthetic committed dependencies\n')
        elif argv[1] == 'metadata':
            assert argv == ['cargo', 'metadata', '--locked', '--offline',
                '--format-version', '1', '--filter-platform', 'x86_64-unknown-linux-gnu']
            P.write(stdout, json.dumps(metadata_fixture(new)).encode())
            P.write(output, b'')
        elif argv[1] == 'test':
            assert argv == ['cargo', 'test', '--locked', '--offline', '-p',
                'volparossa-content', '--lib', 'provider::compute::attestation::' if collateral or local_policy else P.PREFIX,
                '--', '--test-threads=1']
            P.write(output, test_log(endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy))
        elif argv[1] == 'clippy':
            P.write(output, b'Finished synthetic inert Clippy\n')
        else:
            raise AssertionError(argv)
        return tool_outcome()
    with patch.object(P, 'run', side_effect=fake_run):
        P.prepare(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        if historical:
            # Reconstruct schema 1 from inert original bytes, not an executable
            # resolver fallback. Actual historical artifacts stay unchanged.
            evidence = work / 'evidence'
            original = P.read(evidence / 'original-Cargo.lock', P.MAX_LOCK)
            selected, _ = P.source()
            effective = lock(new)
            (root / 'Cargo.lock').write_bytes(effective)
            P.write(evidence / 'effective-Cargo.lock', effective)
            P.write(evidence / 'resolve.log', b'Historical synthetic resolver log\n')
            diff = ''.join(P.difflib.unified_diff(original.decode().splitlines(True), effective.decode().splitlines(True),
                fromfile='original-Cargo.lock', tofile='effective-Cargo.lock')).encode()
            P.write(evidence / 'Cargo.lock.diff', diff)
            P.record(evidence / 'resolution.json', dict(schema_version=1,
                kind='core-attestation-lock-preparation', source=selected, command=tool_outcome(),
                original=P.digest(original), effective=P.digest(effective), scope=P.SCOPE,
                log=P.digest(P.read(evidence / 'resolve.log', P.MAX_LOG)), tests_executed=False,
                delta=P.lock_delta(original, effective), passed=True))
        else:
            P.fetch(work, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        P.metadata(work, historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        P.execute(work, 'test', historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)
        P.execute(work, 'clippy', historical=historical, endorsement=endorsement, certificate_profile=certificate_profile, collateral=collateral, local_policy=local_policy)


def prepare_fixture(work):
    def fake_run(argv, output, _deadline):
        P.write(output, (argv[0] + ' 1.89.0 (inert)\nrelease: 1.89.0\n').encode())
        return tool_outcome()
    with patch.object(P, 'run', side_effect=fake_run):
        P.prepare(work)


class ProbeContracts(unittest.TestCase):
    def test_current_and_historical_compiler_profiles_are_closed(self):
        for tool in ('rustc', 'cargo'):
            current = (tool + ' 1.89.0 (inert)\nrelease: 1.89.0\n').encode()
            historical = (tool + ' 1.99.1 (inert)\nrelease: 1.99.1\n').encode()
            P.toolchain_version(current, tool)
            P.toolchain_version(historical, tool, historical=True)
            with self.assertRaises(ValueError): P.toolchain_version(historical, tool)
            with self.assertRaises(ValueError): P.toolchain_version(current, tool, historical=True)

    def test_minimal_resolver_delta_preserves_original_packages_and_edges(self):
        old, new = fixture_packages()
        value = P.lock_delta(lock(old), lock(new))
        self.assertEqual(value['original_packages'], 2)
        self.assertEqual(len(value['added_packages']), 3)
        self.assertTrue(value['original_dependency_edges_retained'])
        self.assertTrue(value['unlisted_existing_dependency_edges_unchanged'])
        self.assertEqual(value['new_direct_dependencies'], ['sev', 'x509-cert'])

    def test_exact_der_feature_edges_follow_published_x509_and_sev_manifests_only(self):
        old, new = fixture_packages()
        der = package('der', '0.7.10', ['base'])
        der['checksum'] = P.FEATURE_PROVENANCE['der_crate_sha256']
        old.append(copy.deepcopy(der)); new.append(copy.deepcopy(der))
        new[3]['dependencies'].append('der')
        new[-1]['dependencies'] += ['der_derive', 'flagset', 'pem-rfc7468']
        new += [package('der_derive', '0.7.3'), package('flagset', '0.4.7'), package('pem-rfc7468', '0.7.0')]
        result = P.lock_delta(lock(old), lock(new))
        self.assertEqual([x['name'] for x in result['added_feature_edges']], ['der_derive', 'flagset', 'pem-rfc7468'])
        self.assertEqual(result['feature_edge_provenance'], P.FEATURE_PROVENANCE)
        for kind in ('unlisted', 'missing', 'removed_old', 'other_parent', 'too_old', 'new_minor', 'prerelease', 'source', 'checksum'):
            changed = copy.deepcopy(new)
            if kind == 'unlisted': changed[5]['dependencies'].append('crypto')
            elif kind == 'missing': changed[5]['dependencies'].remove('flagset')
            elif kind == 'removed_old': changed[5]['dependencies'].remove('base')
            elif kind == 'other_parent': changed[1]['dependencies'].append('flagset')
            elif kind == 'too_old': changed[6]['version'] = '0.7.1'
            elif kind == 'new_minor': changed[6]['version'] = '0.8.0'
            elif kind == 'prerelease': changed[6]['version'] = '0.7.3-rc.1'
            elif kind == 'source': changed[6]['source'] = P.SEV_SOURCE
            else: changed[5]['checksum'] = 'f' * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(changed))

    def test_semantic_disambiguation_is_not_an_existing_dependency_update(self):
        old, new = fixture_packages()
        new.append(package('base', '2.0.0'))
        new[0]['dependencies'][0] = 'base 1.0.0'
        new[-2]['dependencies'].append('base 2.0.0')
        self.assertEqual(len(P.lock_delta(lock(old), lock(new))['added_packages']), 4)

    def test_crypto_feature_edges_only_use_exact_selected_targets(self):
        old, new = fixture_packages()
        for parent, (target, checksum) in P.EXACT_FEATURE_EDGES.items():
            pkg = package(parent[0], parent[1], ['base']); pkg['checksum'] = checksum
            old += [pkg, package(target[0], target[1])]
            new += [copy.deepcopy(pkg), package(target[0], target[1])]
            new[-2]['dependencies'].append(target[0])
        result = P.lock_delta(lock(old), lock(new))
        self.assertEqual(len(result['exact_feature_edges']), 4)
        for kind in ('missing', 'extra', 'wrong_parent', 'changed_target', 'changed_parent'):
            changed = copy.deepcopy(new)
            if kind == 'missing': changed[5]['dependencies'].remove('const-oid')
            elif kind == 'extra': changed[5]['dependencies'].append('crypto')
            elif kind == 'wrong_parent': changed[1]['dependencies'].append('const-oid')
            elif kind == 'changed_target': changed[6]['version'] = '0.9.7'
            else: changed[5]['checksum'] = 'f' * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(changed))

    def test_new_spin_feature_target_requires_exact_identity_and_verifier_closure(self):
        old, new = fixture_packages()
        parent = ('lazy_static', '1.5.0', P.REGISTRY)
        target, checksum = P.EXACT_FEATURE_EDGES[parent]
        pkg = package(parent[0], parent[1]); pkg['checksum'] = checksum
        old.append(copy.deepcopy(pkg)); new.append(copy.deepcopy(pkg))
        new[-1]['dependencies'].append('spin')
        new[3]['dependencies'].append('lazy_static')
        new.append(package(target[0], target[1]))
        self.assertEqual(P.lock_delta(lock(old), lock(new))['exact_feature_edges'][0]['target_version'], '0.9.9')
        for kind in ('version', 'source', 'missing_checksum', 'unrelated', 'wrong_parent'):
            changed = copy.deepcopy(new)
            if kind == 'version': changed[-1]['version'] = '0.9.10'
            elif kind == 'source': changed[-1]['source'] = P.SEV_SOURCE
            elif kind == 'missing_checksum': del changed[-1]['checksum']
            elif kind == 'unrelated': changed[3]['dependencies'].remove('lazy_static')
            else: changed[1]['dependencies'].append('spin')
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(changed))

    def test_existing_versions_checksums_dependencies_and_removed_packages_fail(self):
        old, good = fixture_packages()
        mutations = []
        for kind in ('version', 'checksum', 'extra_edge', 'remove_edge', 'removed', 'metadata'):
            new = copy.deepcopy(good)
            if kind == 'version': new[1]['version'] = '1.0.1'
            elif kind == 'checksum': new[1]['checksum'] = 'b' * 64
            elif kind == 'extra_edge': new[1]['dependencies'] = ['crypto']
            elif kind == 'remove_edge': new[0]['dependencies'].remove('base')
            elif kind == 'removed': new.pop(1)
            else: new[1]['replacement'] = 'unchecked'
            mutations.append(new)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(value))

    def test_unrelated_unchecked_or_wrong_new_dependencies_fail(self):
        old, good = fixture_packages()
        for kind in ('extra', 'git', 'revision', 'checksum', 'path', 'x509', 'extra_direct'):
            new = copy.deepcopy(good)
            if kind == 'extra': new.append(package('unrelated'))
            elif kind == 'git': new[-1]['source'] = 'git+https://untrusted.invalid/example#' + 'f' * 40
            elif kind == 'revision': new[2]['source'] = P.SEV_SOURCE.replace(P.REV, 'f' * 40)
            elif kind == 'checksum': del new[-1]['checksum']
            elif kind == 'path': del new[-1]['source']; del new[-1]['checksum']
            elif kind == 'x509': new[3]['version'] = '0.2.6'
            else: new[0]['dependencies'].append('crypto')
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.lock_delta(lock(old), lock(new))

    def test_malformed_ambiguous_duplicate_and_unbounded_lock_is_rejected(self):
        old, good = fixture_packages()
        bad = []
        duplicate = copy.deepcopy(good); duplicate.append(copy.deepcopy(good[-1])); bad.append(duplicate)
        dangling = copy.deepcopy(good); dangling[-1]['dependencies'] = ['missing']; bad.append(dangling)
        repeated = copy.deepcopy(good); repeated[-1]['dependencies'] = ['base', 'base']; bad.append(repeated)
        ambiguous = copy.deepcopy(good); ambiguous.append(package('base', '2.0.0')); bad.append(ambiguous)
        for value in bad:
            with self.assertRaises(ValueError): P.lock_delta(lock(old), lock(value))
        for raw in (b'bad', b'version=3\n', b'x' * (P.MAX_LOCK + 1)):
            with self.assertRaises(ValueError): P.lock_graph(raw)

    def test_metadata_checks_actual_features_and_removes_paths(self):
        _, new = verifier_packages()
        original = metadata_fixture(new)
        projected = P.metadata_projection(json.dumps(original).encode(), lock(new))
        self.assertNotIn('/private/', json.dumps(projected))
        self.assertNotIn('fixture-id-', json.dumps(projected))
        self.assertFalse(projected['local_paths_exported'])
        sev = next(item for item in projected['selected_packages'] if item['name'] == 'sev')
        self.assertEqual(sev['features'], ['crypto_nossl', 'snp'])
        self.assertTrue(all(item['normal'] and item['unrenamed'] for item in sev['dependencies']))
        self.assertTrue({'p384', 'rsa', 'sha2', 'x509-cert'} <= {item['name'] for item in sev['dependencies']})
        for features in (['snp'], ['crypto_nossl'], ['snp', 'crypto_nossl', 'openssl'],
                ['snp', 'crypto_nossl', 'default'], ['snp', 'crypto_nossl', 'sev'],
                ['snp', 'crypto_nossl', 'hw_tests'], ['snp', 'crypto_nossl', 'dangerous_hw_tests'],
                ['snp', 'crypto_nossl', 'p384', 'rsa', 'sha2', 'x509-cert']):
            bad = copy.deepcopy(original)
            bad['resolve']['nodes'][2]['features'] = features
            with self.assertRaisesRegex(P.MetadataPolicyError, 'actual_sev_features') as caught:
                P.metadata_projection(json.dumps(bad).encode(), lock(new))
            observed = next(item for item in caught.exception.projection['selected_packages'] if item['name'] == 'sev')
            self.assertEqual(observed['features'], sorted(features))

    def test_metadata_requires_actual_normal_crypto_edges_bound_to_resolved_ids_and_lock(self):
        _, new = verifier_packages()
        original = metadata_fixture(new)
        for name in ('p384', 'rsa', 'sha2', 'x509-cert'):
            for kind in ('missing', 'unresolved', 'node_missing', 'wrong_target', 'wrong_lock_edge',
                    'build_only', 'dev_only', 'conditional', 'renamed', 'duplicate'):
                bad = copy.deepcopy(original)
                dependencies = bad['resolve']['nodes'][2]['deps']
                edge = next(item for item in dependencies if item['name'] == name.replace('-', '_'))
                if kind == 'missing': dependencies.remove(edge)
                elif kind == 'unresolved': edge['pkg'] = '/private/unresolved-id'
                elif kind == 'node_missing':
                    bad['resolve']['nodes'] = [node for node in bad['resolve']['nodes'] if node['id'] != edge['pkg']]
                elif kind == 'wrong_target': edge['pkg'] = 'fixture-id-4'  # Another locked package, not this dependency.
                elif kind == 'wrong_lock_edge': edge['pkg'] = 'fixture-id-1'  # Resolved, but not a sev lock edge.
                elif kind == 'build_only': edge['dep_kinds'][0]['kind'] = 'build'
                elif kind == 'dev_only': edge['dep_kinds'][0]['kind'] = 'dev'
                elif kind == 'conditional': edge['dep_kinds'][0]['target'] = 'cfg(private_not_exported)'
                elif kind == 'renamed': edge['name'] = 'private_not_exported'
                else: dependencies.append(copy.deepcopy(edge))
                with self.subTest(name=name, kind=kind), self.assertRaises(ValueError) as caught:
                    P.metadata_projection(json.dumps(bad).encode(), lock(new))
                if isinstance(caught.exception, P.MetadataPolicyError):
                    self.assertNotIn('private', json.dumps(caught.exception.projection))

    def test_metadata_projection_rejects_path_bearing_or_ambiguous_public_fields(self):
        _, new = verifier_packages()
        original = metadata_fixture(new)
        for kind in ('features', 'duplicate_feature', 'license', 'rust_version', 'duplicate_node', 'duplicate_id'):
            bad = copy.deepcopy(original)
            if kind == 'features': bad['resolve']['nodes'][2]['features'].append('/private/feature')
            elif kind == 'duplicate_feature': bad['resolve']['nodes'][2]['features'].append('snp')
            elif kind in ('license', 'rust_version'): bad['packages'][2][kind] = '/private/field'
            elif kind == 'duplicate_node': bad['resolve']['nodes'].append(copy.deepcopy(bad['resolve']['nodes'][2]))
            else: bad['packages'].append(copy.deepcopy(bad['packages'][2]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.metadata_projection(json.dumps(bad).encode(), lock(new))

    def test_exact_test_selection_and_skips_cannot_be_relabelled(self):
        raw = test_log()
        self.assertEqual(P.verify_tests(raw)['passed'], 14)
        first = ('test ' + P.TESTS[0] + ' ... ok\n').encode()
        for bad in (raw.replace(first, b''), raw + first, raw.replace(first, first.replace(b'ok', b'ignored')),
                raw.replace(first, first.replace(b'ok', b'FAILED')), raw.replace(b'14 passed', b'13 passed'),
                raw.replace(b'0 ignored', b'1 ignored'), raw.replace(b'running 14', b'running 0'), b'build passed\n'):
            with self.assertRaises(ValueError): P.verify_tests(bad)

    def test_source_allows_only_unstaged_effective_lock_with_original_head_retained(self):
        with source_fixture() as (root, _, old, new):
            value, original = P.source()
            self.assertEqual(original, lock(old))
            (root / 'Cargo.lock').write_bytes(lock(new))
            P.source(effective=True)
            with self.assertRaisesRegex(ValueError, 'source_changed'): P.source()
            git(root, 'add', '--', 'Cargo.lock')
            with self.assertRaisesRegex(ValueError, 'source_changed'): P.source(effective=True)

    def test_source_requires_exact_sev_version_alongside_git_revision(self):
        for version in (None, '*', '8.0.0', '^8.0.0', '=8.0.1'):
            with source_fixture() as (root, _, _, _), self.subTest(version=version):
                path = root / 'Cargo.toml'
                original = path.read_text()
                selected = 'sev = { version = "=8.0.0", '
                self.assertIn(selected, original)
                replacement = 'sev = { ' if version is None else f'sev = {{ version = "{version}", '
                path.write_text(original.replace(selected, replacement))
                git(root, 'add', '--', 'Cargo.toml')
                git(root, 'commit', '-qm', 'inert SEV version mutation')
                with patch.dict(os.environ, {'GITHUB_SHA': git(root, 'rev-parse', 'HEAD')}):
                    with self.assertRaisesRegex(ValueError, 'sev_selection'):
                        P.source()

    def test_source_rejects_extra_changes_hidden_changes_modes_and_wrong_head(self):
        for kind in ('source', 'untracked', 'ignored', 'assume', 'mode', 'head'):
            with source_fixture() as (root, _, _, _), self.subTest(kind=kind):
                if kind == 'head':
                    with patch.dict(os.environ, {'GITHUB_SHA': 'f' * 40}), self.assertRaises(ValueError): P.source()
                    continue
                if kind == 'mode': (root / 'other.rs').chmod(0o700)
                elif kind == 'assume': git(root, 'update-index', '--assume-unchanged', 'other.rs')
                else: (root / ('ignored-output' if kind == 'ignored' else 'extra' if kind == 'untracked' else 'other.rs')).write_text('changed')
                with self.assertRaises(ValueError): P.source(effective=True)

    def test_failed_locked_fetch_retains_bytes_and_failure_receipt_and_blocks_metadata(self):
        with source_fixture(committed=True) as (root, work, _, new):
            prepare_fixture(work)
            def fake_run(argv, output, deadline):
                self.assertEqual(argv, ['cargo', 'fetch', '--locked', '--manifest-path', str(root / 'Cargo.toml')])
                self.assertEqual(deadline, 300)
                P.write(output, b'public locked fetch failed\n')
                return tool_outcome(101)
            with patch.object(P, 'run', side_effect=fake_run), self.assertRaisesRegex(ValueError, 'command_failed'):
                P.fetch(work)
            self.assertEqual(P.read(work / 'evidence/effective-Cargo.lock', P.MAX_LOCK), lock(new))
            receipt = json.loads(P.read(work / 'evidence/resolution.json', P.MAX_LOCK))
            self.assertFalse(receipt['passed']); self.assertFalse(receipt['tests_executed'])
            self.assertEqual(receipt['command']['exit_status'], 101)
            self.assertTrue(receipt['committed_lock_unchanged'])
            self.assertEqual(receipt['schema_version'], 2)
            self.assertEqual(P.read(work / 'evidence/Cargo.lock.diff', P.MAX_LOCK), b'')
            with patch.object(P, 'run') as native, self.assertRaisesRegex(ValueError, 'locked_fetch_required'):
                P.metadata(work)
            native.assert_not_called()

    def test_even_successful_fetch_cannot_change_committed_lock_or_resolve_again(self):
        with source_fixture(committed=True) as (root, work, _, new):
            prepare_fixture(work)
            original = lock(new)
            new[1]['checksum'] = 'b' * 64
            def fake_run(_argv, output, _deadline):
                (root / 'Cargo.lock').write_bytes(lock(new)); P.write(output, b'Locking candidate\n')
                return tool_outcome()
            with patch.object(P, 'run', side_effect=fake_run) as runner, self.assertRaisesRegex(ValueError, 'committed_lock_changed'):
                P.fetch(work)
            self.assertEqual(runner.call_count, 1)
            value = json.loads(P.read(work / 'evidence/resolution.json', P.MAX_LOCK))
            self.assertFalse(value['passed']); self.assertFalse(value['committed_lock_unchanged'])
            self.assertNotIn('delta', value)
            self.assertEqual(P.read(work / 'evidence/original-Cargo.lock', P.MAX_LOCK), original)
            self.assertEqual(P.read(work / 'evidence/effective-Cargo.lock', P.MAX_LOCK), lock(new))
            self.assertTrue(P.read(work / 'evidence/Cargo.lock.diff', P.MAX_LOCK))

    def test_prepare_is_new_only_and_does_not_relabel_cryptographic_success(self):
        with source_fixture() as (_, work, old, _):
            def fake_run(argv, output, _deadline):
                P.write(output, (argv[0] + ' 1.89.0 (inert)\nrelease: 1.89.0\n').encode())
                return tool_outcome()
            with patch.object(P, 'run', side_effect=fake_run): P.prepare(work)
            record = json.loads(P.read(work / 'evidence/source.json', P.MAX_LOCK))
            self.assertFalse(record['tests_executed']); self.assertNotIn('passed', record)
            self.assertEqual(P.read(work / 'evidence/original-Cargo.lock', P.MAX_LOCK), lock(old))
            with self.assertRaises(FileExistsError): P.prepare(work)

    def test_fixed_test_and_clippy_commands_remain_locked_offline_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); (work / 'evidence').mkdir()
            P.record(work / 'evidence/resolved-metadata.json', {})
            def fake_run(argv, output, deadline):
                self.assertEqual(argv[:2], ['cargo', 'test' if output.name == 'tests.log' else 'clippy'])
                self.assertIn('--locked', argv); self.assertIn('--offline', argv)
                self.assertIn('volparossa-content', argv)
                if output.name == 'tests.log':
                    self.assertEqual(argv[-3:], [P.PREFIX, '--', '--test-threads=1'])
                    self.assertEqual(deadline, 1200); P.write(output, test_log())
                else:
                    self.assertEqual(argv[-3:], ['--', '-D', 'warnings'])
                    self.assertEqual(deadline, 600); P.write(output, b'Finished\n')
                return tool_outcome()
            with patch.object(P, 'check_lock', return_value={}), patch.object(P, 'check_metadata'), \
                    patch.object(P, 'run', side_effect=fake_run):
                P.execute(work, 'test'); P.execute(work, 'clippy')

    def test_failed_test_log_cannot_pass_even_with_all_successful_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); (work / 'evidence').mkdir(); P.record(work / 'evidence/resolved-metadata.json', {})
            def fake_run(_argv, output, _deadline): P.write(output, test_log()); return tool_outcome(101)
            with patch.object(P, 'check_lock', return_value={}), patch.object(P, 'check_metadata'), \
                    patch.object(P, 'run', side_effect=fake_run), self.assertRaises(ValueError):
                P.execute(work, 'test')
            self.assertFalse(json.loads(P.read(work / 'evidence/tests.json', 32768))['passed'])

    def test_receipt_requires_every_actual_stage_not_only_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); (work / 'evidence').mkdir()
            P.record(work / 'evidence/source.json', {'source': {'commit': 'a' * 40}})
            P.record(work / 'evidence/resolution.json', {'passed': True})
            with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work)
            value = json.loads(P.read(work / 'evidence/report.json', P.MAX_LOCK))
            self.assertFalse(value['passed']); self.assertIsNone(value['stages']['tests.json'])
            self.assertEqual(value['scope'], P.SCOPE)

    def test_complete_synthetic_orchestration_reconstructs_exact_receipt(self):
        with source_fixture() as (root, work, _, new):
            public_trial_fixture(root, work, new)
            P.receipt(work, historical=True)
            value = json.loads(P.read(work / 'evidence/report.json', P.MAX_LOCK))
            self.assertTrue(value['passed'])
            self.assertEqual(set(value['files']), set(P.EXPORTS) - {'report.json'})
            self.assertEqual(value['source']['commit'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(value['stages'], {key: True for key in (
                'resolution.json', 'resolved-metadata.json', 'tests.json', 'clippy.json')})
            self.assertFalse(value['scope']['protected_execution'])

    def test_committed_trial_keeps_exact_bytes_and_schema_two_without_delta_claim(self):
        with source_fixture(committed=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False)
            P.receipt(work)
            evidence = work / 'evidence'
            report = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
            self.assertTrue(report['passed'])
            self.assertEqual(report['schema_version'], 2)
            self.assertEqual(report['lock_policy'], 'committed-lock-unchanged')
            self.assertEqual(set(report['files']), set(P.EXPORTS) - {'report.json'})
            self.assertEqual(report['source']['commit'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(report['source']['tree'], git(root, 'rev-parse', 'HEAD^{tree}'))
            self.assertEqual(report['source']['original_lock'], P.digest(lock(new)))
            self.assertEqual(P.read(root / 'Cargo.lock', P.MAX_LOCK), lock(new))
            for name in ('original-Cargo.lock', 'effective-Cargo.lock'):
                self.assertEqual(P.read(evidence / name, P.MAX_LOCK), lock(new))
            self.assertEqual(P.read(evidence / 'Cargo.lock.diff', P.MAX_LOCK), b'')
            self.assertEqual(git(root, 'status', '--porcelain'), '')
            fetch = json.loads(P.read(evidence / 'resolution.json', P.MAX_LOCK))
            self.assertEqual(fetch['kind'], 'core-attestation-committed-lock-fetch')
            self.assertTrue(fetch['committed_lock_unchanged'])
            self.assertFalse(fetch['tests_executed'])
            self.assertNotIn('delta', fetch)
            self.assertNotIn('added_packages', json.dumps(fetch))
            for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy'):
                value = json.loads(P.read(evidence / (name + '.json'), P.MAX_LOCK))
                self.assertEqual(value['schema_version'], 2)
                self.assertEqual(value['lock_policy'], P.LOCK_POLICY)
                self.assertEqual(value['source'], report['source'])
                self.assertEqual(value['scope'], P.SCOPE)
            tests = json.loads(P.read(evidence / 'tests.json', P.MAX_LOCK))
            self.assertEqual(tests['tests']['names'], list(P.TESTS))
            self.assertEqual(tests['tests']['passed'], 14)
            self.assertFalse(report['scope']['protected_execution'])

    def test_historical_trial_requires_explicit_replay_and_cannot_enter_current_commands(self):
        with source_fixture() as (root, work, _, new):
            public_trial_fixture(root, work, new)
            with patch.object(P, 'run') as native:
                for action in (P.fetch, P.metadata, lambda work: P.execute(work, 'test')):
                    with self.assertRaises(ValueError): action(work)
                native.assert_not_called()
            with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work)
            report = json.loads(P.read(work / 'evidence/report.json', P.MAX_LOCK))
            self.assertFalse(report['passed']); self.assertEqual(report['schema_version'], 2)
            # Replay the original schema 1 bytes explicitly, without rewriting them.
            records, files = {}, {}
            for name in P.EXPORTS:
                if name == 'report.json': continue
                raw = P.read(work / 'evidence' / name, P.MAX_LOG if name.endswith('.log') else P.MAX_LOCK)
                files[name] = P.digest(raw)
                if name.endswith('.json'): records[name] = json.loads(raw)
            P.verify_evidence(work, records, files, historical=True)
            with self.assertRaises(ValueError): P.verify_evidence(work, records, files)

    def test_schema_three_binds_twenty_two_tests_without_promoting_appraisal(self):
        with source_fixture(committed=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False, endorsement=True)
            P.receipt(work, endorsement=True)
            evidence = work / 'evidence'
            report = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
            self.assertTrue(report['passed'])
            self.assertEqual(report['schema_version'], 3)
            self.assertEqual(report['lock_policy'], P.LOCK_POLICY)
            self.assertEqual(set(report['files']), set(P.EXPORTS) - {'report.json'})
            self.assertEqual(report['source']['commit'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(report['source']['tree'], git(root, 'rev-parse', 'HEAD^{tree}'))
            for name in ('original-Cargo.lock', 'effective-Cargo.lock'):
                self.assertEqual(P.read(evidence / name, P.MAX_LOCK), lock(new))
            self.assertEqual(P.read(evidence / 'Cargo.lock.diff', P.MAX_LOCK), b'')
            self.assertEqual(git(root, 'status', '--porcelain'), '')
            for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy'):
                value = json.loads(P.read(evidence / (name + '.json'), P.MAX_LOCK))
                self.assertEqual(value['schema_version'], 3)
                self.assertEqual(value['source'], report['source'])
                self.assertEqual(value['scope'], P.SCOPE)
            tests = json.loads(P.read(evidence / 'tests.json', P.MAX_LOCK))['tests']
            self.assertEqual(tests, P.verify_tests(P.read(evidence / 'tests.log', P.MAX_LOG), endorsement=True))
            self.assertEqual(tests['names'], list(P.ENDORSEMENT_TESTS))
            self.assertEqual(tests['passed'], 22)
            self.assertEqual(P.ENDORSEMENT_TESTS[:14], P.TESTS)
            self.assertEqual(len(set(P.ENDORSEMENT_TESTS)), 22)
            self.assertEqual({k for k, v in report['scope'].items() if v}, {'public_inputs_only'})

    def test_schema_three_exact_tests_reject_old_missing_extra_ignored_and_false_counts(self):
        raw = test_log(endorsement=True)
        first = ('test ' + P.ENDORSEMENT_TESTS[-1] + ' ... ok\n').encode()
        for bad in (test_log(), raw.replace(first, b''), raw + first,
                raw.replace(first, first.replace(b'ok', b'ignored')),
                raw.replace(first, first.replace(b'ok', b'FAILED')),
                raw.replace(first, first.replace(b'endorsement_', b'unrelated_')),
                raw.replace(b'22 passed', b'14 passed'), raw.replace(b'0 ignored', b'1 ignored'),
                raw.replace(b'running 22', b'running 14'), b'build passed\n'):
            with self.subTest(bad=bad[-100:]), self.assertRaises(ValueError):
                P.verify_tests(bad, endorsement=True)
        with self.assertRaises(ValueError): P.verify_tests(raw)
        self.assertEqual(P.verify_tests(test_log())['passed'], 14)

    def test_schema_two_replay_is_not_implicitly_upgraded_to_endorsement(self):
        with source_fixture(committed=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False)
            evidence = work / 'evidence'
            original = {name: (evidence / name).read_bytes() for name in P.EXPORTS if name != 'report.json'}
            with patch.object(P, 'run') as native:
                for action in (lambda: P.fetch(work, endorsement=True),
                        lambda: P.metadata(work, endorsement=True),
                        lambda: P.execute(work, 'test', endorsement=True)):
                    with self.assertRaises(ValueError): action()
                native.assert_not_called()
            with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, endorsement=True)
            failed = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
            self.assertFalse(failed['passed']); self.assertEqual(failed['schema_version'], 3)
            self.assertEqual(original, {name: (evidence / name).read_bytes() for name in original})
            records = {name: json.loads(raw) for name, raw in original.items() if name.endswith('.json')}
            P.verify_evidence(work, records, {name: P.digest(raw) for name, raw in original.items()})
            self.assertEqual(records['tests.json']['schema_version'], 2)

    def test_schema_three_rejects_cross_schema_receipts_and_old_testset_relabelling(self):
        for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy', 'old_tests'):
            with source_fixture(committed=True) as (root, work, _, new), self.subTest(name=name):
                public_trial_fixture(root, work, new, historical=False, endorsement=True)
                evidence = work / 'evidence'
                path = evidence / ('tests.json' if name == 'old_tests' else name + '.json')
                value = json.loads(P.read(path, P.MAX_LOCK))
                if name == 'old_tests':
                    (evidence / 'tests.log').write_bytes(test_log())
                    value['tests'] = P.verify_tests(test_log())
                    value['log'] = P.digest(test_log())
                else:
                    value['schema_version'] = 2
                path.write_text(json.dumps(value))
                if name == 'old_tests':
                    with patch.object(P, 'run') as native, self.assertRaises(ValueError):
                        P.execute(work, 'clippy', endorsement=True)
                    native.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, endorsement=True)
                failed = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(failed['passed']); self.assertEqual(failed['schema_version'], 3)

    def test_schema_four_binds_twenty_eight_tests_without_promoting_appraisal(self):
        with source_fixture(committed=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False, certificate_profile=True)
            P.receipt(work, certificate_profile=True)
            evidence = work / 'evidence'
            report = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
            self.assertTrue(report['passed'])
            self.assertEqual(report['schema_version'], 4)
            self.assertEqual(report['lock_policy'], P.LOCK_POLICY)
            self.assertEqual(set(report['files']), set(P.EXPORTS) - {'report.json'})
            self.assertEqual(report['source']['commit'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(report['source']['tree'], git(root, 'rev-parse', 'HEAD^{tree}'))
            for name in ('original-Cargo.lock', 'effective-Cargo.lock'):
                self.assertEqual(P.read(evidence / name, P.MAX_LOCK), lock(new))
            self.assertEqual(P.read(evidence / 'Cargo.lock.diff', P.MAX_LOCK), b'')
            self.assertEqual(git(root, 'status', '--porcelain'), '')
            for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy'):
                value = json.loads(P.read(evidence / (name + '.json'), P.MAX_LOCK))
                self.assertEqual(value['schema_version'], 4)
                self.assertEqual(value['source'], report['source'])
                self.assertEqual(value['scope'], P.SCOPE)
            tests = json.loads(P.read(evidence / 'tests.json', P.MAX_LOCK))['tests']
            self.assertEqual(tests, P.verify_tests(P.read(evidence / 'tests.log', P.MAX_LOG), certificate_profile=True))
            self.assertEqual(tests['names'], list(P.CERTIFICATE_PROFILE_TESTS))
            self.assertEqual(tests['passed'], 28)
            self.assertEqual(P.CERTIFICATE_PROFILE_TESTS[:22], P.ENDORSEMENT_TESTS)
            self.assertEqual(len(set(P.CERTIFICATE_PROFILE_TESTS)), 28)
            self.assertEqual({k for k, v in report['scope'].items() if v}, {'public_inputs_only'})

    def test_schema_four_exact_tests_reject_old_missing_extra_ignored_and_false_counts(self):
        raw = test_log(certificate_profile=True)
        first = ('test ' + P.CERTIFICATE_PROFILE_TESTS[-1] + ' ... ok\n').encode()
        for bad in (test_log(), test_log(endorsement=True), raw.replace(first, b''), raw + first,
                raw.replace(first, first.replace(b'ok', b'ignored')),
                raw.replace(first, first.replace(b'ok', b'FAILED')),
                raw.replace(first, first.replace(b'certificate_profile_', b'unrelated_')),
                raw.replace(b'28 passed', b'14 passed'), raw.replace(b'0 ignored', b'1 ignored'),
                raw.replace(b'running 28', b'running 14'), b'build passed\n'):
            with self.subTest(bad=bad[-100:]), self.assertRaises(ValueError):
                P.verify_tests(bad, certificate_profile=True)
        with self.assertRaises(ValueError): P.verify_tests(raw)
        self.assertEqual(P.verify_tests(test_log())['passed'], 14)

    def test_schema_four_rejects_cross_schema_receipts_and_old_testset_relabelling(self):
        for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy', 'old_tests'):
            with source_fixture(committed=True) as (root, work, _, new), self.subTest(name=name):
                public_trial_fixture(root, work, new, historical=False, certificate_profile=True)
                evidence = work / 'evidence'
                path = evidence / ('tests.json' if name == 'old_tests' else name + '.json')
                value = json.loads(P.read(path, P.MAX_LOCK))
                if name == 'old_tests':
                    (evidence / 'tests.log').write_bytes(test_log(endorsement=True))
                    value['tests'] = P.verify_tests(test_log(endorsement=True), endorsement=True)
                    value['log'] = P.digest(test_log(endorsement=True))
                else:
                    value['schema_version'] = 3
                path.write_text(json.dumps(value))
                if name == 'old_tests':
                    with patch.object(P, 'run') as native, self.assertRaises(ValueError):
                        P.execute(work, 'clippy', certificate_profile=True)
                    native.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, certificate_profile=True)
                failed = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(failed['passed']); self.assertEqual(failed['schema_version'], 4)

    def test_all_legacy_profiles_replay_without_implicit_certificate_upgrade(self):
        for options in (dict(historical=True), {}, dict(endorsement=True)):
            with source_fixture(committed=not options.get('historical', False)) as (root, work, _, new), self.subTest(options=options):
                public_trial_fixture(root, work, new, historical=options.get('historical', False),
                    endorsement=options.get('endorsement', False))
                evidence = work / 'evidence'
                original = {name: (evidence / name).read_bytes() for name in P.EXPORTS if name != 'report.json'}
                with patch.object(P, 'run') as native:
                    for action in (P.fetch, P.metadata, lambda work, **kw: P.execute(work, 'test', **kw)):
                        with self.assertRaises(ValueError): action(work, certificate_profile=True)
                    native.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, certificate_profile=True)
                failed = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(failed['passed']); self.assertEqual(failed['schema_version'], 4)
                self.assertEqual(original, {name: (evidence / name).read_bytes() for name in original})
                records = {name: json.loads(data) for name, data in original.items() if name.endswith('.json')}
                P.verify_evidence(work, records, {name: P.digest(data) for name, data in original.items()}, **options)

    def test_certificate_profile_is_explicit_boolean_and_mutually_exclusive(self):
        for options in (dict(certificate_profile=1), dict(certificate_profile='true'),
                dict(certificate_profile=None), dict(certificate_profile=True, endorsement=True),
                dict(certificate_profile=True, historical=True),
                dict(certificate_profile=True, endorsement=True, historical=True)):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'evidence_profile'):
                P.envelope('inert', **options)
        self.assertEqual(P.evidence_schema(), 2)
        self.assertEqual(P.evidence_schema(historical=True), 1)
        self.assertEqual(P.evidence_schema(endorsement=True), 3)
        self.assertEqual(P.evidence_schema(certificate_profile=True), 4)

    def test_certificate_evidence_cannot_be_relabelled_as_an_older_profile(self):
        with source_fixture(committed=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False, certificate_profile=True)
            evidence = work / 'evidence'
            original = {name: (evidence / name).read_bytes() for name in P.EXPORTS if name != 'report.json'}
            records = {name: json.loads(data) for name, data in original.items() if name.endswith('.json')}
            files = {name: P.digest(data) for name, data in original.items()}
            for options in ({}, dict(historical=True), dict(endorsement=True)):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    P.verify_evidence(work, records, files, **options)
            P.verify_evidence(work, records, files, certificate_profile=True)

    def test_schema_five_binds_forty_tests_and_direct_public_crl_edge(self):
        with source_fixture(committed=True, collateral=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False, collateral=True)
            P.receipt(work, collateral=True)
            evidence = work / 'evidence'
            report = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
            self.assertTrue(report['passed']); self.assertEqual(report['schema_version'], 5)
            self.assertEqual(report['lock_policy'], P.LOCK_POLICY)
            self.assertEqual(set(report['files']), set(P.EXPORTS) - {'report.json'})
            self.assertEqual(report['source']['commit'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(report['source']['tree'], git(root, 'rev-parse', 'HEAD^{tree}'))
            for name in ('original-Cargo.lock', 'effective-Cargo.lock'):
                self.assertEqual(P.read(evidence / name, P.MAX_LOCK), lock(new))
            self.assertEqual(P.read(evidence / 'Cargo.lock.diff', P.MAX_LOCK), b'')
            self.assertEqual(git(root, 'status', '--porcelain'), '')
            for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy'):
                value = json.loads(P.read(evidence / (name + '.json'), P.MAX_LOCK))
                self.assertEqual(value['schema_version'], 5)
                self.assertEqual(value['source'], report['source'])
                self.assertEqual(value['scope'], P.SCOPE)
            tests = json.loads(P.read(evidence / 'tests.json', P.MAX_LOCK))['tests']
            self.assertEqual(tests, P.verify_tests(P.read(evidence / 'tests.log', P.MAX_LOG), collateral=True))
            self.assertEqual(tests['names'], list(P.COLLATERAL_TESTS)); self.assertEqual(tests['passed'], 40)
            self.assertEqual(P.COLLATERAL_TESTS[:28], P.CERTIFICATE_PROFILE_TESTS)
            self.assertEqual(len(set(P.COLLATERAL_TESTS)), 40)
            projection = json.loads(P.read(evidence / 'resolved-metadata.json', P.MAX_LOCK))['projection']
            self.assertEqual(projection['public_crl_verifier']['direct_caller'], 'volparossa-content')
            self.assertEqual(projection['public_crl_verifier']['version'], '0.9.10')
            self.assertNotIn('/private/', json.dumps(projection))
            self.assertNotIn('fixture-id-', json.dumps(projection))
            self.assertEqual({k for k, v in report['scope'].items() if v}, {'public_inputs_only'})

    def test_schema_five_exact_test_names_reject_older_and_fabricated_summaries(self):
        raw = test_log(collateral=True)
        first = ('test ' + P.COLLATERAL_TESTS[-1] + ' ... ok\n').encode()
        for bad in (test_log(), test_log(endorsement=True), test_log(certificate_profile=True),
                raw.replace(first, b''), raw + first, raw.replace(first, first.replace(b'ok', b'ignored')),
                raw.replace(first, first.replace(b'ok', b'FAILED')),
                raw.replace(first, first.replace(b'collateral::tests', b'unrelated::tests')),
                raw.replace(b'40 passed', b'28 passed'), raw.replace(b'0 ignored', b'1 ignored'),
                raw.replace(b'running 40', b'running 28'), b'build passed\n'):
            with self.subTest(bad=bad[-100:]), self.assertRaises(ValueError):
                P.verify_tests(bad, collateral=True)
        for options in ({}, dict(endorsement=True), dict(certificate_profile=True)):
            with self.assertRaises(ValueError): P.verify_tests(raw, **options)

    def test_schema_five_rejects_cross_schema_receipts_and_old_test_relabelling(self):
        for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy', 'old_tests'):
            with source_fixture(committed=True, collateral=True) as (root, work, _, new), self.subTest(name=name):
                public_trial_fixture(root, work, new, historical=False, collateral=True)
                evidence = work / 'evidence'
                path = evidence / ('tests.json' if name == 'old_tests' else name + '.json')
                value = json.loads(P.read(path, P.MAX_LOCK))
                if name == 'old_tests':
                    (evidence / 'tests.log').write_bytes(test_log(certificate_profile=True))
                    value['tests'] = P.verify_tests(test_log(certificate_profile=True), certificate_profile=True)
                    value['log'] = P.digest(test_log(certificate_profile=True))
                else: value['schema_version'] = 4
                path.write_text(json.dumps(value))
                if name == 'old_tests':
                    with patch.object(P, 'run') as native, self.assertRaises(ValueError):
                        P.execute(work, 'clippy', collateral=True)
                    native.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, collateral=True)
                failed = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(failed['passed']); self.assertEqual(failed['schema_version'], 5)

    def test_schemas_one_through_four_replay_without_implicit_collateral_upgrade(self):
        for options in (dict(historical=True), {}, dict(endorsement=True), dict(certificate_profile=True)):
            with source_fixture(committed=not options.get('historical', False)) as (root, work, _, new), self.subTest(options=options):
                public_trial_fixture(root, work, new, historical=options.get('historical', False),
                    endorsement=options.get('endorsement', False), certificate_profile=options.get('certificate_profile', False))
                evidence = work / 'evidence'
                original = {name: (evidence / name).read_bytes() for name in P.EXPORTS if name != 'report.json'}
                with patch.object(P, 'run') as native:
                    for action in (P.fetch, P.metadata, lambda work, **kw: P.execute(work, 'test', **kw)):
                        with self.assertRaises(ValueError): action(work, collateral=True)
                    native.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, collateral=True)
                failed = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(failed['passed']); self.assertEqual(failed['schema_version'], 5)
                self.assertEqual(original, {name: (evidence / name).read_bytes() for name in original})
                records = {name: json.loads(data) for name, data in original.items() if name.endswith('.json')}
                P.verify_evidence(work, records, {name: P.digest(data) for name, data in original.items()}, **options)

    def test_collateral_profile_is_explicit_boolean_mutually_exclusive_and_not_downgradable(self):
        for options in (dict(collateral=1), dict(collateral='true'), dict(collateral=None),
                dict(collateral=True, endorsement=True), dict(collateral=True, historical=True),
                dict(collateral=True, certificate_profile=True)):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'evidence_profile'):
                P.envelope('inert', **options)
        self.assertEqual(P.evidence_schema(collateral=True), 5)
        with source_fixture(committed=True, collateral=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False, collateral=True)
            evidence = work / 'evidence'
            original = {name: (evidence / name).read_bytes() for name in P.EXPORTS if name != 'report.json'}
            records = {name: json.loads(data) for name, data in original.items() if name.endswith('.json')}
            files = {name: P.digest(data) for name, data in original.items()}
            for options in ({}, dict(historical=True), dict(endorsement=True), dict(certificate_profile=True)):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    P.verify_evidence(work, records, files, **options)
            P.verify_evidence(work, records, files, collateral=True)

    def test_collateral_metadata_requires_exact_public_rsa_edge_features_and_checksum(self):
        with source_fixture(committed=True, collateral=True) as (_root, _work, _, new):
            original = metadata_fixture(new)
            good = P.metadata_projection(json.dumps(original).encode(), lock(new), collateral=True)
            self.assertIn('public_crl_verifier', good)
            for change in ('missing', 'alias', 'dev', 'target', 'extra', 'hidden', 'hidden_parent', 'features', 'version', 'checksum'):
                value = copy.deepcopy(original)
                packages = copy.deepcopy(new)
                content = value['resolve']['nodes'][0]
                direct = next(edge for edge in content['deps'] if edge['name'] == 'rsa')
                identity = direct['pkg']
                if change == 'missing': content['deps'].remove(direct)
                elif change == 'alias': direct['name'] = 'renamed'
                elif change == 'dev': direct['dep_kinds'][0]['kind'] = 'dev'
                elif change == 'target': direct['dep_kinds'][0]['target'] = 'cfg(unix)'
                elif change == 'extra': content['deps'].append(copy.deepcopy(direct))
                elif change == 'hidden': content['dependencies'].remove(identity)
                elif change == 'hidden_parent': value['resolve']['nodes'][1]['dependencies'].append(identity)
                elif change == 'features': next(node for node in value['resolve']['nodes'] if node['id'] == identity)['features'].append('hazmat')
                elif change == 'version': next(item for item in value['packages'] if item['id'] == identity)['version'] = '0.9.9'
                else: next(item for item in packages if item['name'] == 'rsa')['checksum'] = '0' * 64
                with self.subTest(change=change), self.assertRaises(ValueError):
                    P.metadata_projection(json.dumps(value).encode(), lock(packages), collateral=True)

    def test_schema_five_executor_selects_entire_attestation_namespace(self):
        with source_fixture(committed=True, collateral=True) as (root, work, _, new):
            with patch.object(P, 'run', wraps=P.run) as native:
                # Inner fixture overrides run with inert outputs; never execute Cargo.
                public_trial_fixture(root, work, new, historical=False, collateral=True)
                native.assert_not_called()
            source = Path(P.__file__).read_text()
            self.assertIn("'provider::compute::attestation::' if collateral or local_policy else PREFIX", source)

    def test_schema_six_binds_fifty_two_tests_complete_source_and_unchanged_scope(self):
        with source_fixture(committed=True, local_policy=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False, local_policy=True)
            P.receipt(work, local_policy=True)
            evidence = work / 'evidence'
            report = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
            self.assertTrue(report['passed']); self.assertEqual(report['schema_version'], 6)
            self.assertEqual(report['lock_policy'], P.LOCK_POLICY)
            self.assertEqual(report['source']['commit'], git(root, 'rev-parse', 'HEAD'))
            self.assertEqual(report['source']['tree'], git(root, 'rev-parse', 'HEAD^{tree}'))
            self.assertEqual(set(report['files']), set(P.EXPORTS) - {'report.json'})
            self.assertEqual({key for key, value in report['scope'].items() if value}, {'public_inputs_only'})
            for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy'):
                value = json.loads(P.read(evidence / (name + '.json'), P.MAX_LOCK))
                self.assertEqual(value['schema_version'], 6)
                self.assertEqual(value['source'], report['source'])
                self.assertEqual(value['scope'], P.SCOPE)
            tests = json.loads(P.read(evidence / 'tests.json', P.MAX_LOCK))['tests']
            self.assertEqual(tests, P.verify_tests(test_log(local_policy=True), local_policy=True))
            self.assertEqual(tests['passed'], 52); self.assertEqual(tests['names'], list(P.LOCAL_POLICY_TESTS))
            self.assertEqual(P.LOCAL_POLICY_TESTS[:40], P.COLLATERAL_TESTS)
            self.assertEqual(len(set(P.LOCAL_POLICY_TESTS)), 52)
            for name in ('original-Cargo.lock', 'effective-Cargo.lock'):
                self.assertEqual(P.read(evidence / name, P.MAX_LOCK), lock(new))
            self.assertEqual(P.read(evidence / 'Cargo.lock.diff', P.MAX_LOCK), b'')
            self.assertEqual(git(root, 'status', '--porcelain'), '')

    def test_schema_six_exact_tests_reject_older_missing_extra_ignored_and_bad_summary(self):
        raw = test_log(local_policy=True)
        first = ('test ' + P.LOCAL_POLICY_TESTS[-1] + ' ... ok\n').encode()
        for bad in (test_log(), test_log(endorsement=True), test_log(certificate_profile=True),
                test_log(collateral=True), raw.replace(first, b''), raw + first,
                raw.replace(first, first.replace(b'ok', b'ignored')),
                raw.replace(first, first.replace(b'ok', b'FAILED')),
                raw.replace(first, first.replace(b'local_policy_', b'unrelated_')),
                raw.replace(b'52 passed', b'40 passed'), raw.replace(b'0 ignored', b'1 ignored'),
                raw.replace(b'running 52', b'running 40'), b'build passed\n'):
            with self.subTest(bad=bad[-100:]), self.assertRaises(ValueError):
                P.verify_tests(bad, local_policy=True)
        for options in ({}, dict(endorsement=True), dict(certificate_profile=True), dict(collateral=True)):
            with self.assertRaises(ValueError): P.verify_tests(raw, **options)

    def test_schema_six_rejects_cross_schema_receipts_and_relabelled_forty_test_logs(self):
        for name in ('source', 'resolution', 'resolved-metadata', 'tests', 'clippy', 'old_tests'):
            with source_fixture(committed=True, local_policy=True) as (root, work, _, new), self.subTest(name=name):
                public_trial_fixture(root, work, new, historical=False, local_policy=True)
                evidence = work / 'evidence'
                path = evidence / ('tests.json' if name == 'old_tests' else name + '.json')
                value = json.loads(P.read(path, P.MAX_LOCK))
                if name == 'old_tests':
                    (evidence / 'tests.log').write_bytes(test_log(collateral=True))
                    value['tests'] = P.verify_tests(test_log(collateral=True), collateral=True)
                    value['log'] = P.digest(test_log(collateral=True))
                else: value['schema_version'] = 5
                path.write_text(json.dumps(value))
                if name == 'old_tests':
                    with patch.object(P, 'run') as native, self.assertRaises(ValueError):
                        P.execute(work, 'clippy', local_policy=True)
                    native.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, local_policy=True)
                failed = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(failed['passed']); self.assertEqual(failed['schema_version'], 6)

    def test_schemas_one_through_five_replay_without_implicit_local_policy_upgrade(self):
        for options in (dict(historical=True), {}, dict(endorsement=True), dict(certificate_profile=True), dict(collateral=True)):
            with source_fixture(committed=not options.get('historical', False), collateral=options.get('collateral', False)) as (root, work, _, new), self.subTest(options=options):
                public_trial_fixture(root, work, new, historical=options.get('historical', False),
                    endorsement=options.get('endorsement', False), certificate_profile=options.get('certificate_profile', False),
                    collateral=options.get('collateral', False))
                evidence = work / 'evidence'
                original = {name: (evidence / name).read_bytes() for name in P.EXPORTS if name != 'report.json'}
                with patch.object(P, 'run') as native:
                    for action in (P.fetch, P.metadata, lambda work, **kw: P.execute(work, 'test', **kw)):
                        with self.assertRaises(ValueError): action(work, local_policy=True)
                    native.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work, local_policy=True)
                self.assertEqual(original, {name: (evidence / name).read_bytes() for name in original})
                records = {name: json.loads(data) for name, data in original.items() if name.endswith('.json')}
                P.verify_evidence(work, records, {name: P.digest(data) for name, data in original.items()}, **options)

    def test_local_policy_profile_requires_explicit_exclusive_boolean_and_no_downgrade(self):
        for options in (dict(local_policy=1), dict(local_policy=None), dict(local_policy='true'),
                *(dict(local_policy=True, **{key: True}) for key in ('historical', 'endorsement', 'certificate_profile', 'collateral'))):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'evidence_profile'):
                P.envelope('inert', **options)
        self.assertEqual(P.evidence_schema(local_policy=True), 6)
        with source_fixture(committed=True, local_policy=True) as (root, work, _, new):
            public_trial_fixture(root, work, new, historical=False, local_policy=True)
            evidence = work / 'evidence'
            original = {name: (evidence / name).read_bytes() for name in P.EXPORTS if name != 'report.json'}
            records = {name: json.loads(data) for name, data in original.items() if name.endswith('.json')}
            files = {name: P.digest(data) for name, data in original.items()}
            for options in ({}, dict(historical=True), dict(endorsement=True), dict(certificate_profile=True), dict(collateral=True)):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    P.verify_evidence(work, records, files, **options)
            P.verify_evidence(work, records, files, local_policy=True)

    def test_local_policy_keeps_actual_public_crl_metadata_and_source_gates(self):
        with source_fixture(committed=True, local_policy=True) as (_root, _work, _, new):
            original = metadata_fixture(new)
            good = P.metadata_projection(json.dumps(original).encode(), lock(new), local_policy=True)
            self.assertEqual(good, P.metadata_projection(json.dumps(original).encode(), lock(new), collateral=True))
            for change in ('missing', 'features'):
                value = copy.deepcopy(original)
                content = value['resolve']['nodes'][0]
                direct = next(edge for edge in content['deps'] if edge['name'] == 'rsa')
                if change == 'missing': content['deps'].remove(direct)
                else: next(node for node in value['resolve']['nodes'] if node['id'] == direct['pkg'])['features'].append('hazmat')
                with self.assertRaises(ValueError):
                    P.metadata_projection(json.dumps(value).encode(), lock(new), local_policy=True)
            self.assertNotIn('/private/', json.dumps(good))
            self.assertNotIn('fixture-id-', json.dumps(good))

    def test_hosted_cli_always_selects_schema_six_and_cannot_request_replay(self):
        for phase in ('prepare', 'fetch', 'metadata', 'test', 'clippy', 'receipt'):
            entry = 'execute' if phase in ('test', 'clippy') else phase
            with self.subTest(phase=phase), patch.object(P, 'hosted'), patch.object(P, 'install_signals'), \
                    patch.object(P, 'workdir', return_value=Path('/inert/work')), patch.object(P, 'cargo_env'), \
                    patch.object(P, entry) as action:
                P.main([phase])
                args = (Path('/inert/work'), phase) if entry == 'execute' else (Path('/inert/work'),)
                action.assert_called_once_with(*args, local_policy=True)
        for historical, endorsement in ((True, True), (1, False), (False, 'true')):
            with self.assertRaisesRegex(ValueError, 'evidence_profile'):
                P.envelope('inert', historical=historical, endorsement=endorsement)

    def test_hosted_branch_gate_keeps_exact_seven_branches_only(self):
        env = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
            GITHUB_REPOSITORY='VOLPAROSSA/volparossa', GITHUB_WORKFLOW='Protected compute core evidence')
        for branch in ('feature/protected-compute-admission', 'feature/protected-compute-endorsement',
                'feature/protected-compute-cert-profile', 'feature/protected-compute-collateral', 'feature/protected-compute-local-policy', 'feature/protected-compute-guest', 'feature/protected-compute-quote-exchange', 'main', 'feature/protected-compute-quote-exchange-other', 'feature/protected-compute-guest-other', 'feature/protected-compute-local-policy-other', 'feature/protected-compute-collateral-other', 'feature/protected-compute-cert-profile-other', 'feature/protected-compute-endorsement-other'):
            with patch.dict(os.environ, dict(env, GITHUB_REF='refs/heads/' + branch)), patch.object(P.os, 'getuid', return_value=1000):
                if branch in ('feature/protected-compute-admission', 'feature/protected-compute-endorsement',
                        'feature/protected-compute-cert-profile', 'feature/protected-compute-collateral', 'feature/protected-compute-local-policy', 'feature/protected-compute-guest', 'feature/protected-compute-quote-exchange'):
                    P.hosted()
                else:
                    with self.assertRaisesRegex(ValueError, 'disposable_branch_only'): P.hosted()

    def test_locked_fetch_binds_original_source_receipt_before_any_cargo(self):
        for kind in ('original', 'source', 'commit', 'tree', 'schema', 'lock_hash', 'sev', 'scope', 'unknown'):
            with source_fixture(committed=True) as (root, work, _, _), self.subTest(kind=kind):
                prepare_fixture(work)
                evidence = work / 'evidence'
                if kind == 'original': (evidence / 'original-Cargo.lock').write_bytes(b'changed')
                elif kind == 'source': (root / 'other.rs').write_text('changed')
                else:
                    path = evidence / 'source.json'; value = json.loads(path.read_bytes())
                    if kind in ('commit', 'tree'): value['source'][kind] = 'f' * 40
                    elif kind == 'schema': value['schema_version'] = 1
                    elif kind == 'lock_hash': value['source']['original_lock']['sha256'] = 'f' * 64
                    elif kind == 'sev': value['source']['sev_revision'] = 'f' * 40
                    elif kind == 'scope': value['scope']['private_input_release'] = True
                    else: value['unknown'] = 'not admitted'
                    path.write_text(json.dumps(value))
                with patch.object(P, 'run') as native, self.assertRaises(ValueError): P.fetch(work)
                native.assert_not_called()

    def test_locked_fetch_rechecks_source_after_success_and_never_falls_back(self):
        with source_fixture(committed=True) as (root, work, _, _):
            prepare_fixture(work)
            def fake_run(argv, output, _deadline):
                self.assertIn('--locked', argv)
                (root / 'other.rs').write_text('changed during fetch')
                P.write(output, b'Downloaded public dependencies\n')
                return tool_outcome()
            with patch.object(P, 'run', side_effect=fake_run) as runner, self.assertRaisesRegex(ValueError, 'source_changed'):
                P.fetch(work)
            self.assertEqual(runner.call_count, 1)
            value = json.loads(P.read(work / 'evidence/resolution.json', P.MAX_LOCK))
            self.assertFalse(value['passed']); self.assertEqual(value['error'], 'source_changed')

    def test_locked_fetch_exit_capture_and_join_must_all_succeed(self):
        for kind in ('exit', 'capture', 'join'):
            with source_fixture(committed=True) as (_, work, _, _), self.subTest(kind=kind):
                prepare_fixture(work)
                outcome = tool_outcome()
                if kind == 'exit': outcome['exit_status'] = 101
                elif kind == 'capture': outcome['capture_error'] = 'command_io_or_deadline'
                else: outcome['leader_joined'] = False
                def fake_run(_argv, output, _deadline):
                    P.write(output, b'Finished\n'); return outcome
                with patch.object(P, 'run', side_effect=fake_run) as runner, self.assertRaisesRegex(ValueError, 'command_failed'):
                    P.fetch(work)
                self.assertEqual(runner.call_count, 1)
                value = json.loads(P.read(work / 'evidence/resolution.json', P.MAX_LOCK))
                self.assertEqual(value['command'], outcome); self.assertFalse(value['passed'])
                with patch.object(P, 'run') as native, self.assertRaises(ValueError): P.metadata(work)
                native.assert_not_called()

    def test_current_report_rejects_tampered_snapshots_stages_and_historical_relabel(self):
        for kind in ('original', 'effective', 'workspace', 'source', 'delta', 'historical',
                'policy', 'exit', 'metadata_features', 'tests', 'log', 'diff', 'scope', 'unknown'):
            with source_fixture(committed=True) as (root, work, _, new), self.subTest(kind=kind):
                public_trial_fixture(root, work, new, historical=False)
                evidence = work / 'evidence'
                if kind in ('original', 'effective'):
                    (evidence / (kind + '-Cargo.lock')).write_bytes(lock(new) + b'\n')
                elif kind == 'workspace': (root / 'Cargo.lock').write_bytes(lock(new) + b'\n')
                elif kind == 'source': (root / 'other.rs').write_text('changed')
                elif kind == 'metadata_features':
                    value = metadata_fixture(new); value['resolve']['nodes'][2]['features'].append('openssl')
                    (work / 'metadata.json').write_text(json.dumps(value))
                elif kind == 'tests': (evidence / 'tests.log').write_bytes(test_log().replace(b'14 passed', b'13 passed'))
                elif kind == 'log': (evidence / 'resolve.log').write_bytes(b'changed')
                elif kind == 'diff': (evidence / 'Cargo.lock.diff').write_bytes(b'not empty')
                else:
                    path = evidence / ('resolution.json' if kind == 'delta' else 'clippy.json')
                    value = json.loads(path.read_bytes())
                    if kind == 'delta': value['delta'] = {'added_packages': []}
                    elif kind == 'historical': value['schema_version'] = 1
                    elif kind == 'policy': value['lock_policy'] = 'new resolution'
                    elif kind == 'exit': value['command']['exit_status'] = 101
                    elif kind == 'unknown': value['unknown'] = 'not admitted'
                    else: value['scope']['protected_execution'] = True
                    path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, 'incomplete'): P.receipt(work)
                value = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(value['passed']); self.assertEqual(value['schema_version'], 2)

    def test_current_cli_has_no_historical_or_unlocked_resolver_and_clears_fallback_env(self):
        with patch.object(P, 'hosted') as gate, patch.object(P, 'run') as native:
            for args in (['resolve'], ['fetch', '--historical'], ['historical'], ['--historical', 'receipt']):
                with self.assertRaisesRegex(ValueError, 'fixed_command'): P.main(args)
            gate.assert_not_called(); native.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,
                {'CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS': 'fallback'}):
            P.cargo_env(Path(tmp))
            self.assertNotIn('CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS', os.environ)
            self.assertEqual(os.environ['CARGO_BUILD_JOBS'], '2')
            self.assertEqual(os.environ['RUSTUP_TOOLCHAIN'], '1.89.0')

    def test_pass_flags_cannot_override_changed_logs_source_lock_metadata_or_exit(self):
        for kind in ('log', 'source', 'lock', 'metadata', 'exit', 'tool', 'diff', 'ignored', 'scope'):
            with source_fixture() as (root, work, _, new), self.subTest(kind=kind):
                public_trial_fixture(root, work, new)
                evidence = work / 'evidence'
                if kind == 'log': (evidence / 'tests.log').write_bytes(test_log() + b'changed\n')
                elif kind == 'source': (root / 'other.rs').write_text('changed')
                elif kind == 'lock': (root / 'Cargo.lock').write_bytes(lock(new) + b'\n')
                elif kind == 'metadata':
                    raw = metadata_fixture(new); raw['resolve']['nodes'][2]['features'] += ['openssl']
                    (work / 'metadata.json').write_text(json.dumps(raw))
                elif kind == 'tool': (evidence / 'cargo.txt').write_text('cargo 1.86.0\nrelease: 1.86.0\n')
                elif kind == 'diff': (evidence / 'Cargo.lock.diff').write_text('not the observed delta')
                elif kind == 'ignored': (root / 'ignored-output').write_text('unexpected build output')
                else:
                    path = evidence / 'clippy.json'; record = json.loads(path.read_bytes())
                    if kind == 'exit': record['command']['exit_status'] = 101
                    else: record['scope']['protected_execution'] = True
                    path.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    P.receipt(work, historical=True)
                value = json.loads(P.read(evidence / 'report.json', P.MAX_LOCK))
                self.assertFalse(value['passed'])

    def test_failed_metadata_keeps_exit_and_blocks_test_execution(self):
        with source_fixture() as (root, work, old, new):
            (work / 'evidence').mkdir(parents=True)
            P.write(work / 'evidence/original-Cargo.lock', lock(old))
            P.write(work / 'evidence/effective-Cargo.lock', lock(new))
            (root / 'Cargo.lock').write_bytes(lock(new))
            def fake_run(argv, output, deadline, *, stdout):
                self.assertEqual(argv, ['cargo', 'metadata', '--locked', '--offline',
                    '--format-version', '1', '--filter-platform', 'x86_64-unknown-linux-gnu'])
                self.assertEqual(deadline, 120)
                P.write(stdout, b''); P.write(output, b'public inert metadata error\n')
                return tool_outcome(101)
            with patch.object(P, 'run', side_effect=fake_run), self.assertRaisesRegex(ValueError, 'command_failed'):
                P.metadata(work, historical=True)
            value = json.loads(P.read(work / 'evidence/resolved-metadata.json', P.MAX_LOCK))
            self.assertFalse(value['passed']); self.assertEqual(value['command']['exit_status'], 101)
            with patch.object(P, 'run') as native, self.assertRaisesRegex(ValueError, 'metadata_required'):
                P.execute(work, 'test', historical=True)
            native.assert_not_called()

    def test_metadata_policy_failure_retains_only_bounded_public_observations_and_blocks_tests(self):
        for kind in ('features', 'dependency'):
            with source_fixture() as (root, work, old, new), self.subTest(kind=kind):
                (work / 'evidence').mkdir(parents=True)
                P.write(work / 'evidence/original-Cargo.lock', lock(old))
                P.write(work / 'evidence/effective-Cargo.lock', lock(new))
                (root / 'Cargo.lock').write_bytes(lock(new))
                observed = metadata_fixture(new)
                if kind == 'features': observed['resolve']['nodes'][2]['features'].append('openssl')
                else:
                    node = observed['resolve']['nodes'][2]
                    node['deps'] = [edge for edge in node['deps'] if edge['name'] != 'p384']
                def fake_run(_argv, output, _deadline, *, stdout):
                    P.write(stdout, json.dumps(observed).encode()); P.write(output, b'')
                    return tool_outcome()
                with patch.object(P, 'run', side_effect=fake_run), self.assertRaises(P.MetadataPolicyError):
                    P.metadata(work, historical=True)
                raw = P.read(work / 'evidence/resolved-metadata.json', P.MAX_LOCK)
                value = json.loads(raw)
                self.assertFalse(value['passed']); self.assertEqual(value['command']['exit_status'], 0)
                self.assertEqual(value['error'], 'actual_sev_features' if kind == 'features' else 'actual_sev_dependencies')
                self.assertEqual(value['projection']['raw_metadata'], P.digest(json.dumps(observed).encode()))
                self.assertLess(len(raw), 8192)
                for secret in (b'/private/', b'fixture-id-', b'cfg(', b'manifest_path'):
                    self.assertNotIn(secret, raw)
                self.assertEqual(value['scope'], P.SCOPE)
                with patch.object(P, 'run') as native, self.assertRaisesRegex(ValueError, 'metadata_required'):
                    P.execute(work, 'test', historical=True)
                native.assert_not_called()

    def test_capture_runs_only_inert_python_and_preserves_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'output'
            result = P.run([sys.executable, '-c', 'print("public inert child");raise SystemExit(7)'], log, 5)
            self.assertEqual(result['exit_status'], 7); self.assertIsNone(result['capture_error'])
            self.assertTrue(result['leader_joined']); self.assertEqual(P.read(log, 1024), b'public inert child\n')

    def test_real_inert_timeout_and_output_bound_join_owned_leader(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            result = P.run([sys.executable, '-c', 'import time;time.sleep(20)'], base / 'timeout', 0.02)
            self.assertTrue(result['leader_joined']); self.assertEqual(result['capture_error'], 'command_io_or_deadline')
            with patch.object(P, 'MAX_LOG', 16):
                result = P.run([sys.executable, '-c', 'print("X"*128)'], base / 'overflow', 5)
            self.assertTrue(result['leader_joined']); self.assertEqual(result['capture_error'], 'command_output_bound')
            self.assertEqual((base / 'overflow').stat().st_size, 16)

    def test_injected_cancellation_unwinds_inert_child_and_remains_failure(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(P.selectors.DefaultSelector, 'select', side_effect=P.RunInterrupted):
            result = P.run([sys.executable, '-c', 'import time;time.sleep(20)'], Path(tmp) / 'cancel', 5)
            self.assertEqual(result['capture_error'], 'command_interrupted'); self.assertTrue(result['leader_joined'])
            with self.assertRaises(ValueError): P.command_ok(result)

    def test_selector_setup_failure_still_joins_real_owned_python_child(self):
        children = []
        real_popen = subprocess.Popen
        def started(*args, **kwargs):
            child = real_popen(*args, **kwargs); children.append(child); return child
        with tempfile.TemporaryDirectory() as tmp, patch.object(P.subprocess, 'Popen', side_effect=started), \
                patch.object(P.selectors, 'DefaultSelector', side_effect=OSError('inert descriptor exhaustion')):
            result = P.run([sys.executable, '-c', 'import time;time.sleep(20)'], Path(tmp) / 'setup', 5)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(result['leader_joined'])
        self.assertEqual(result['capture_error'], 'command_io_or_deadline')
        with self.assertRaises(ValueError): P.command_ok(result)

    def test_no_local_or_arbitrary_command_native_entrypoint(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(P, 'run') as native:
            for args in (['resolve'], ['test'], ['clippy'], ['arbitrary']):
                with self.assertRaises(ValueError): P.main(args)
            native.assert_not_called()

    def test_same_fd_inputs_reject_symlink_fifo_writable_hardlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); regular = base / 'input'; P.write(regular, b'1234')
            link = base / 'link'; link.symlink_to(regular)
            fifo = base / 'fifo'; os.mkfifo(fifo)
            for path, maximum in ((link, 4), (fifo, 4), (regular, 3)):
                with self.assertRaises((OSError, ValueError)): P.read(path, maximum)
            regular.chmod(0o666)
            with self.assertRaises(ValueError): P.read(regular, 4)
            regular.chmod(0o600); os.link(regular, base / 'hardlink')
            with self.assertRaises(ValueError): P.read(regular, 4)

    def test_workflow_has_exact_branch_source_and_export_closure(self):
        raw = WORKFLOW.read_text()
        self.assertIn('branches: [feature/protected-compute-admission, feature/protected-compute-endorsement, feature/protected-compute-cert-profile, feature/protected-compute-collateral, feature/protected-compute-local-policy, feature/protected-compute-guest, feature/protected-compute-quote-exchange]', raw)
        self.assertIn("if: github.ref == 'refs/heads/feature/protected-compute-admission' || github.ref == 'refs/heads/feature/protected-compute-endorsement' || github.ref == 'refs/heads/feature/protected-compute-cert-profile'", raw)
        self.assertIn('Execute exactly fifty-two core evidence tests offline', raw)
        self.assertIn('cancel-in-progress: false', raw)
        self.assertIn('timeout-minutes: 45', raw)
        self.assertIn('persist-credentials: false', raw)
        self.assertIn('python3 -B scripts/provision-rust189.py runner', raw)
        observed = re.findall(r'\$\{\{ runner.temp \}\}/volparossa-protected-compute-admission/evidence/(\S+)', raw)
        self.assertEqual(tuple(observed), P.EXPORTS)
        self.assertNotIn('cargo update', raw); self.assertNotIn('generate-lockfile', raw)
        self.assertNotIn('GITHUB_ENV', raw); self.assertNotIn('pull_request:', raw)
        self.assertIn('protected-compute-admission.py fetch', raw)
        self.assertNotIn('protected-compute-admission.py resolve', raw)
        code = Path(P.__file__).read_text()
        self.assertNotIn("'update'", code); self.assertNotIn("'generate-lockfile'", code)
        source = (P.ROOT / 'crates/volparossa-content/src/provider/compute/attestation/tests.rs').read_text()
        names = re.findall(r'#\[test\]\s+fn (\w+)\(', source)
        self.assertEqual(set(P.CERTIFICATE_PROFILE_TESTS), {P.PREFIX + name for name in names})
        self.assertEqual(len(names), 28)
        collateral_source = (P.ROOT / 'crates/volparossa-content/src/provider/compute/attestation/collateral_tests.rs').read_text()
        new_names = re.findall(r'#\[test\]\s+fn (\w+)\(', collateral_source)
        self.assertEqual(set(P.COLLATERAL_TESTS), {P.PREFIX + name for name in names}
            | {P.COLLATERAL_PREFIX + name for name in new_names})
        self.assertEqual(len(new_names), 12)
        policy_source = (P.ROOT / 'crates/volparossa-content/src/provider/compute/attestation/policy_tests.rs').read_text()
        policy_names = re.findall(r'#\[test\]\s+fn (\w+)\(', policy_source)
        self.assertEqual(len(policy_names), 12)
        self.assertIn('include!("policy_tests.rs");', source)
        self.assertEqual(set(P.LOCAL_POLICY_TESTS), set(P.COLLATERAL_TESTS)
            | {P.PREFIX + name for name in policy_names})


if __name__ == '__main__':
    unittest.main()
