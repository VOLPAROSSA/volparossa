#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One fixed-candidate hosted compile-only proof; never Quality/runtime acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import tomllib
import traceback

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('resolver_helpers', ROOT / 'scripts/run-f04-security-resolver.py')
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
FIXTURE = 'third_party/rust/ctutils-current-regressions'
LOCKS = {'Cargo.lock': 'dc36ac2cb87ce457083126f3b5d48ad2df5e65a8bccc1191c758e54bda193860',
         'fuzz/Cargo.lock': '782afbad801efd26c7045a6c0aab175eaa8888b42718c9e2baa6d836cfc37663',
         FIXTURE + '/Cargo.lock': '62056d2a906a912e8150b584c4cbf0b255e5cd79e6bdef140bb1f8a6656c104c'}
UPDATES = (('cfg-if', '1.0.5', '1.0.4'), ('cpufeatures', '0.3.1', '0.3.0'),
           ('hybrid-array', '0.4.15', '0.4.14'), ('libc', '0.2.191', '0.2.189'),
           ('syn', '3.0.9', '3.0.3'), ('unicode-ident', '1.0.27', '1.0.24'))
PROOF_INPUTS = ('scripts/run-f04-source-validation.py', 'scripts/test-f04-source-validation.py',
                'scripts/run-f04-security-resolver.py', 'scripts/provision-rust189.py',
                'scripts/rust189-components.json', '.github/workflows/f04-p03f-collapse.yml')


def admit(initial=False):
    env = os.environ
    candidate = env.get('CANDIDATE', '')
    if (os.geteuid() == 0 or not re.fullmatch('[0-9a-f]{40}', candidate) or set(candidate) == {'0'}
            or any(env.get(k) != v for k, v in dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
               RUNNER_OS='Linux', RUNNER_ARCH='X64', GITHUB_REPOSITORY='VOLPAROSSA/volparossa',
               GITHUB_REF='refs/heads/proof/p03f-f04-collapse-corrected-20261027').items())
            or not env.get('GITHUB_SHA') or env.get('GITHUB_SHA') != env.get('GITHUB_WORKFLOW_SHA')):
        raise ValueError('requires exact non-placeholder candidate and unprivileged hosted proof branch')
    workspace, temporary = Path(env['GITHUB_WORKSPACE']), Path(env['RUNNER_TEMP'])
    if workspace != ROOT or any(not p.is_absolute() or not p.is_dir() or p.is_symlink() for p in (workspace, temporary)):
        raise ValueError('invalid proof/temporary roots')
    source = workspace / 'source'
    if source.is_symlink() or H.git(source, 'rev-parse', 'HEAD').decode().strip() != candidate:
        raise ValueError('candidate checkout mismatch')
    if H.git(workspace, 'rev-parse', 'HEAD').decode().strip() != env['GITHUB_WORKFLOW_SHA']:
        raise ValueError('proof checkout mismatch')
    if H.git(workspace, 'status', '--porcelain', '--untracked-files=all', '--', '.github', 'scripts'):
        raise ValueError('proof code is dirty')
    if initial:
        if H.git(source, 'status', '--porcelain', '--untracked-files=all'):
            raise ValueError('candidate is not clean')
        for name, digest in LOCKS.items():
            if H.sha((source / name).read_bytes()) != digest:
                raise ValueError('initial lock mismatch: ' + name)
        for name in ('scripts/provision-rust189.py', 'scripts/rust189-components.json'):
            if (source / name).read_bytes() != (ROOT / name).read_bytes():
                raise ValueError('candidate compiler authority differs from fixed proof: ' + name)
        for key, value in env.items():
            if value and (key in {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER'} or key.endswith('_RUSTFLAGS')):
                raise ValueError('unreviewed compiler override')
    return source, temporary, workspace / 'evidence'


def prepare():
    source, temporary, evidence = admit(initial=True)
    if evidence.exists() or (temporary / 'f04-source-validation-private').exists():
        raise ValueError('fresh validation context required')
    evidence.mkdir(mode=0o700)
    H.write_json(evidence / 'source-index-before.json', H.source_index(source))
    H.snapshot_locks(source, evidence, 'before')
    H.write_json(evidence / 'source.json', dict(candidate=os.environ['CANDIDATE'],
        candidate_tree=H.git(source, 'rev-parse', 'HEAD^{tree}').decode().strip(),
        source_index_before_sha256=H.sha((evidence / 'source-index-before.json').read_bytes()),
        deadline_monotonic=time.monotonic() + 40 * 60,
        proof=os.environ['GITHUB_WORKFLOW_SHA'], run_id=os.environ['GITHUB_RUN_ID'],
        run_attempt=os.environ['GITHUB_RUN_ATTEMPT'], initial_lock_sha256=LOCKS,
        proof_sha256={name: H.sha((ROOT / name).read_bytes()) for name in PROOF_INPUTS},
        candidate_compiler_sha256={name: H.sha((source / name).read_bytes()) for name in ('scripts/provision-rust189.py', 'scripts/rust189-components.json')},
        scope='committed candidate compile only; fixture lock resolution and reversible formatting',
        runtime_acceptance=False, security_acceptance=False, quality_acceptance=False))
    (evidence / 'source-index.git').write_bytes(H.git(source, 'ls-files', '-s'))


def stable_source(source, before):
    after = H.source_index(source)
    changes = H.changed_paths(before, after)
    unexpected = [name for name in changes if name != FIXTURE + '/Cargo.lock']
    if unexpected:
        raise ValueError('unexpected candidate mutation: ' + repr(unexpected))
    for name, digest in LOCKS.items():
        if name != FIXTURE + '/Cargo.lock' and H.sha((source / name).read_bytes()) != digest:
            raise ValueError('root/fuzz lock changed')
    return after


def expected_recipe():
    return [dict(name=name, before=before, after=after,
                 command=['cargo', 'update', '--manifest-path', FIXTURE + '/Cargo.toml', '-p', name + '@' + before, '--precise', after])
            for name, before, after in UPDATES]


def update_fixture(source, evidence, runner):
    recipe_path = source / 'scripts/ctutils-current-rust189-lock-recipe.json'
    recipe = json.loads(recipe_path.read_text())
    if (recipe['updates'] != expected_recipe() or recipe['initial_lock_sha256'] != LOCKS[FIXTURE + '/Cargo.lock']
            or recipe['manifest_sha256'] != H.sha((source / FIXTURE / 'Cargo.toml').read_bytes())
            or recipe['compiler_profile'] != 'rust-1.89.0-20250807'):
        raise ValueError('fixture recipe differs from fixed six-update scope')
    H.write_json(evidence / 'fixture-recipe.json', recipe)
    for update in expected_recipe():
        lock = tomllib.loads((source / FIXTURE / 'Cargo.lock').read_text())['package']
        matches = [p for p in lock if p['name'] == update['name'] and p['version'] == update['before']]
        if len(matches) != 1 or matches[0].get('source') != H.REGISTRY:
            raise ValueError('fixture precise precursor missing or ambiguous: ' + update['name'])
        runner.command('fixture-update-' + update['name'], update['command'][1:], timeout=120)
    lock = tomllib.loads((source / FIXTURE / 'Cargo.lock').read_text())['package']
    for name, before, after in UPDATES:
        # Some names also have a retained older major; reject the retired exact
        # precursor and require exactly one fixed replacement registry identity.
        if any(p['name'] == name and p['version'] == before for p in lock) or sum(p['name'] == name and p['version'] == after and p.get('source') == H.REGISTRY for p in lock) != 1:
            raise ValueError('fixture precise replacement mismatch: ' + name)


def feature_report(root, fixture):
    def graph(metadata):
        nodes = {node['id']: node for node in metadata['resolve']['nodes']}
        return {(p['name'], p['version'], p['source']): dict(id=p['id'], features=sorted(nodes[p['id']]['features']))
                for p in metadata['packages']}
    a, b = graph(root), graph(fixture)
    shared = sorted(a.keys() & b.keys(), key=str)
    critical = []
    for name in ('ctutils', 'crypto-bigint', 'p384', 'hmac', 'poly1305', 'sha2'):
        selected = [key for key in b if key[0] == name]
        if len(selected) != 1 or selected[0] not in a:
            raise ValueError('critical fixture/root identity mismatch: ' + name)
        key = selected[0]
        critical.append(dict(identity=key, root=a[key]['features'], fixture=b[key]['features']))
    return dict(scope='fixture consumer/codegen graph; not an exact Core binary', critical_crypto=critical,
        shared=[dict(identity=key, root=a[key], fixture=b[key]) for key in shared],
        residual_feature_differences=[dict(identity=key, root=a[key]['features'], fixture=b[key]['features'])
                                      for key in shared if a[key]['features'] != b[key]['features']],
        root_only=sorted(a.keys()-b.keys(), key=str), fixture_only=sorted(b.keys()-a.keys(), key=str),
        runtime_acceptance=False, codegen_acceptance=False)


def first_party_rust(name):
    return name.endswith('.rs') and (name.startswith('crates/') or name.startswith('fuzz/') or name.startswith(FIXTURE + '/'))


def format_capture(source, evidence, runner, before):
    format_commands_passed = False
    try:
        runner.command('format-root', ['fmt', '--all'])
        runner.command('format-fuzz', ['fmt', '--manifest-path', 'fuzz/Cargo.toml', '--all'])
        runner.command('format-fixture', ['fmt', '--manifest-path', FIXTURE + '/Cargo.toml', '-p', 'volparossa-ctutils-regressions'])
        format_commands_passed = True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if not runner.records[-1]['cleanup_confirmed']:
            raise
    finally:
        if any(not record['cleanup_confirmed'] for record in runner.records):
            H.write_json(evidence / 'format.json', dict(needs_formatting=True,
                formatter_scope_blocker=True, format_commands_passed=False,
                committed_source_restored=False, cleanup_unconfirmed=True,
                reason='retain private/source context; no rollback while owned children may write'))
            raise runner.provision.CleanupUnconfirmed('formatter cleanup unconfirmed; rollback and strict compile forbidden')
        # Capture every tracked change except the intentionally resolved fixture
        # lock, then reverse those exact bytes even if formatting failed.
        names = H.git(source, 'diff', '--name-only', '--', '.', ':(exclude)' + FIXTURE + '/Cargo.lock').decode().splitlines()
        patch = H.git(source, 'diff', '--binary', '--', '.', ':(exclude)' + FIXTURE + '/Cargo.lock')
        (evidence / 'format-all.patch').write_bytes(patch)
        first_party = [name for name in names if first_party_rust(name)]
        vendor = [name for name in names if name.startswith('third_party/rust/vendor/') and name.endswith('.rs')]
        unexpected = [name for name in names if name not in first_party and name not in vendor]
        for label, selected in [('firstparty-format.patch', first_party), ('vendor-format.patch', vendor), ('unexpected-format.patch', unexpected)]:
            (evidence / label).write_bytes(H.git(source, 'diff', '--binary', '--', *selected) if selected else b'')
        H.write_json(evidence / 'format.json', dict(needs_formatting=bool(patch), changed_paths=names,
            first_party_paths=first_party, vendor_paths=vendor, unexpected_paths=unexpected,
            formatter_scope_blocker=bool(vendor or unexpected), format_commands_passed=format_commands_passed,
            patch_sha256=H.sha(patch), committed_source_restored=False, formatter_green_claim=False,
            vendor_patch_authorized_for_application=False))
        if patch:
            subprocess.run(['git', '-C', str(source), 'apply', '--reverse', '--check', '-'], input=patch, check=True, timeout=30)
            subprocess.run(['git', '-C', str(source), 'apply', '--reverse', '-'], input=patch, check=True, timeout=30)
        stable_source(source, before)
        record = json.loads((evidence / 'format.json').read_text())
        record['committed_source_restored'] = True
        H.write_json(evidence / 'format.json', record)
        # Scope blockers fail the final proof, but restored-source independent
        # strict diagnostics must still run. Vendor patches are never accepted.


def run():
    source, temporary, evidence = admit(initial=True)
    before = json.loads((evidence / 'source-index-before.json').read_text())
    private = temporary / 'f04-source-validation-private'
    private.mkdir(mode=0o700)
    (private / 'tmp').mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('compiler189', source / 'scripts/provision-rust189.py')
    provision = importlib.util.module_from_spec(spec); spec.loader.exec_module(provision)
    prefix = temporary / 'volparossa-rust-1.89.0'
    authority = dict(pre=dict(accepted=False), post=dict(accepted=False, reason='not attempted'))
    runner = H.Runner(source, evidence, prefix, private, provision)
    runner.deadline = min(float(json.loads((evidence / 'source.json').read_text())['deadline_monotonic']), time.monotonic() + 40 * 60)
    completed = False
    try:
        receipt = (prefix / 'receipt.json').read_bytes()
        (evidence / 'compiler-receipt.json').write_bytes(receipt)
        H.compiler_authority(provision, prefix, receipt, authority['pre'])
        update_fixture(source, evidence, runner)
        stable_source(source, before)
        for label, manifest, full in [('root-default', 'Cargo.toml', False), ('root-full', 'Cargo.toml', True),
                                      ('fuzz', 'fuzz/Cargo.toml', False), ('fixture', FIXTURE + '/Cargo.toml', False)]:
            if label != 'root-full':
                runner.command(label + '-fetch', ['fetch', '--locked', '--manifest-path', manifest], timeout=180)
            runner.command(label + '-metadata', ['metadata', '--locked', '--offline', '--format-version', '1', '--manifest-path', manifest] + (['--all-features'] if full else []))
        def metadata(label):
            return json.loads((evidence / (label + '-metadata.stdout')).read_text())
        H.metadata_checks(metadata('fixture'), source, fixture=True)
        H.write_json(evidence / 'fixture-root-default-features.json', feature_report(metadata('root-default'), metadata('fixture')))
        H.write_json(evidence / 'fixture-root-full-features.json', feature_report(metadata('root-full'), metadata('fixture')))
        for label, arguments in [('sev-scope', ['scripts/check-sev-p384-scope.py', str(evidence / 'root-full-metadata.stdout'), str(evidence / 'fuzz-metadata.stdout')]),
                                 ('rsa-scope', ['scripts/check-public-rsa-scope.py', str(evidence / 'root-full-metadata.stdout'), str(evidence / 'fuzz-metadata.stdout'), str(evidence / 'temporary-root-deny.toml')]),
                                 ('vendor-guards', ['scripts/check-rust-dependencies.sh', '--verify-vendor-only']),
                                 ('inert-sev-guard', ['scripts/test-sev-p384-scope.py']), ('inert-rsa-guard', ['scripts/test-public-rsa-scope.py']),
                                 ('inert-ctutils-guard', ['scripts/test-ctutils-scope.py'])]:
            command = (['sh'] if arguments[0].endswith('.sh') else [sys.executable, '-B']) + arguments
            runner.command(label, command, cargo=False)
        stable_source(source, before)
        # Proves every root lock byte/package block, including all nine retained
        # historical entries, was accepted by locked Cargo without any rewrite.
        H.write_json(evidence / 'locked-inputs.json', dict(root_and_fuzz_unchanged=True,
            root_sha256=H.sha((source / 'Cargo.lock').read_bytes()),
            root_packages=tomllib.loads((source / 'Cargo.lock').read_text())['package'],
            locked_fetch_metadata_accepted=True, fixture_sha256=H.sha((source / FIXTURE / 'Cargo.lock').read_bytes())))
        format_capture(source, evidence, runner, before)
        for label, arguments, timeout in [
            ('strict-root', ['clippy', '--keep-going', '--locked', '--offline', '--workspace', '--all-targets', '--all-features', '--message-format=json', '--', '-D', 'warnings'], 1080),
            ('strict-fuzz', ['clippy', '--keep-going', '--locked', '--offline', '--manifest-path', 'fuzz/Cargo.toml', '--all-targets', '--message-format=json', '--', '-D', 'warnings'], 480)]:
            stable_source(source, before)
            try:
                runner.command(label, arguments, timeout=timeout)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # Independent strict commands; failure is never suppressed in
                # the final proof result, and unsafe group cleanup propagates.
                if not runner.records[-1]['cleanup_confirmed']:
                    raise
        completed = True
    except BaseException:
        (evidence / 'failure.log').write_text(traceback.format_exc())
        raise
    finally:
        safe = all(record['cleanup_confirmed'] for record in runner.records)
        if safe and authority['pre']['accepted']:
            try:
                H.compiler_authority(provision, prefix, (prefix / 'receipt.json').read_bytes(), authority['post'])
                if authority['post']['receipt_sha256'] != authority['pre']['receipt_sha256']:
                    authority['post']['accepted'] = False
                    raise ValueError('compiler receipt changed')
            except BaseException:
                (evidence / 'post-authority-failure.log').write_text(traceback.format_exc())
        else:
            authority['post']['reason'] = 'not accepted: pre-authority or owned process-group cleanup unconfirmed'
        H.write_json(evidence / 'compiler-authority.json', authority)
        H.write_json(evidence / 'source-index-after.json', H.source_index(source))
        H.snapshot_locks(source, evidence, 'after')
        delta_checked = False
        try:
            original, original_edges = H.lock_graph((evidence / 'before-2-Cargo.lock').read_bytes())
            resolved, resolved_edges = H.lock_graph((source / FIXTURE / 'Cargo.lock').read_bytes())
            H.write_json(evidence / 'fixture-lock-delta.json', dict(
                removed=[original[key] for key in sorted(original.keys() - resolved.keys())],
                added=[resolved[key] for key in sorted(resolved.keys() - original.keys())],
                modified=[dict(identity=key, before=original[key], after=resolved[key])
                          for key in sorted(original.keys() & resolved.keys()) if original[key] != resolved[key]],
                removed_edges=sorted(original_edges - resolved_edges), added_edges=sorted(resolved_edges - original_edges)))
            delta_checked = True
        except BaseException:
            (evidence / 'fixture-lock-delta-failure.log').write_text(traceback.format_exc())
        H.write_json(evidence / 'execution.json', dict(completed=completed, cleanup_confirmed=safe, fixture_delta_checked=delta_checked,
            private_context_retained=str(private), compiler_authority_accepted=authority['pre']['accepted'] and authority['post']['accepted'],
            changed_paths=H.changed_paths(before, H.source_index(source))))


def strict_result(log, status):
    diagnostics, first_errors, finished, malformed = set(), [], [], []
    error_count = 0
    for number, line in enumerate(log.splitlines(), 1):
        try: item = json.loads(line)
        except json.JSONDecodeError:
            malformed.append(number); continue
        if item.get('reason') == 'build-finished': finished.append(item['success'])
        if item.get('reason') != 'compiler-message': continue
        message = item['message']; code = (message.get('code') or {}).get('code')
        if message['level'] == 'error': error_count += 1
        if message['level'] == 'error' and (code is None or re.fullmatch(r'E[0-9]{4}', code)):
            first_errors.append(message)
        if code and message['level'] in ('error', 'warning'):
            diagnostics.update((code, span['file_name'], span['line_start']) for span in message['spans'] if span['is_primary'])
    return dict(exit_status=status, build_finished=finished, unique_primary_diagnostics=sorted(diagnostics),
        first_compiler_errors=first_errors[:20], compiler_error_count=len(first_errors), error_count=error_count, malformed_json_lines=malformed,
        passed=status == 0 and finished == [True] and not malformed and error_count == 0)


def summarize():
    source, temporary, evidence = admit()
    def read(name, fallback):
        path = evidence / name
        return json.loads(path.read_text()) if path.exists() else fallback
    binding = read('source.json', {})
    commands = read('commands.json', [])
    results = {}
    for label in ('strict-root', 'strict-fuzz'):
        command = next((c for c in commands if c['label'] == label), {})
        path = evidence / (label + '.stdout')
        results[label] = strict_result(path.read_text() if path.exists() else '', command.get('exit_status'))
    execution = read('execution.json', {})
    locked = read('locked-inputs.json', {})
    locks_unchanged_after_compile = bool(locked) and all(
        H.sha((source / name).read_bytes()) == (locked.get('fixture_sha256') if name == FIXTURE + '/Cargo.lock' else digest)
        for name, digest in LOCKS.items())
    changes = execution.get('changed_paths', ['execution not completed'])
    proof_unchanged = (set(binding.get('proof_sha256', {})) == set(PROOF_INPUTS)
        and binding.get('candidate') == os.environ['CANDIDATE']
        and binding.get('proof') == os.environ['GITHUB_WORKFLOW_SHA']
        and binding.get('candidate_tree') == H.git(source, 'rev-parse', 'HEAD^{tree}').decode().strip()
        and binding.get('source_index_before_sha256') == H.sha((evidence / 'source-index-before.json').read_bytes())
        and all(H.sha((ROOT / name).read_bytes()) == digest for name, digest in binding.get('proof_sha256', {}).items()))
    summary = dict(binding, execution=execution, strict=results, formatting=read('format.json', {}),
        proof_unchanged=proof_unchanged, locks_unchanged_after_compile=locks_unchanged_after_compile, compile_only=True, quality_acceptance=False, security_acceptance=False, runtime_acceptance=False)
    summary['passed'] = (proof_unchanged and locks_unchanged_after_compile and execution.get('completed') and execution.get('cleanup_confirmed')
        and execution.get('compiler_authority_accepted') and execution.get('fixture_delta_checked') and all(name == FIXTURE + '/Cargo.lock' for name in changes)
        and summary['formatting'].get('format_commands_passed') and summary['formatting'].get('committed_source_restored')
        and not summary['formatting'].get('formatter_scope_blocker', True)
        and all(result['passed'] for result in results.values()))
    summary['needs_formatting'] = summary['formatting'].get('needs_formatting', True)
    summary['formatter_scope_blocker'] = summary['formatting'].get('formatter_scope_blocker', True)
    summary['ready_for_quality'] = bool(summary['passed'] and not summary['formatting'].get('needs_formatting', True))
    H.write_json(evidence / 'validation-summary.json', summary)
    H.write_json(evidence / 'artifact-sha256.json', {p.name: H.sha(p.read_bytes()) for p in sorted(evidence.iterdir()) if p.is_file() and p.name != 'artifact-sha256.json'})
    if not summary['passed']:
        raise ValueError('source validation incomplete or strict Clippy failed; original evidence retained')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, H.interrupted)
    signal.signal(signal.SIGINT, H.interrupted)
    if len(sys.argv) != 2 or sys.argv[1] not in ('prepare', 'run', 'summarize'):
        raise SystemExit('usage: run-f04-source-validation.py prepare|run|summarize')
    globals()[sys.argv[1]]()
