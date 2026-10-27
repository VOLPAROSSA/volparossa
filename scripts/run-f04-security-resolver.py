#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Resolve only the fixed reviewed F04 source on a disposable hosted runner.

No compilation, tests, audit, advisory waiver, or security/runtime acceptance.
Original locks and failures remain evidence; unknown root/fuzz changes fail closed.
"""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import tomllib
import traceback

SOURCE = '96a0584ad985e8c404f8dd2a232e439971ca3d8d'
FIXTURE = 'third_party/rust/ctutils-current-regressions'
LOCKS = ('Cargo.lock', 'fuzz/Cargo.lock', FIXTURE + '/Cargo.lock')
ORIGINAL = {'Cargo.lock': '1ed913b2cc64690d0c3bbb3c484071f72cd1c202a6372f608d13c8c99bc2fb8b',
            'fuzz/Cargo.lock': '3b28c49468ac9096621405acdf685b7216d00b4ced8642d666a86f14b0ba4159'}
ALLOW = set('crypto-bigint p384 ecdsa elliptic-curve primeorder primefield ctutils sev base16ct sec1 spki pkcs8 der signature ff group rfc6979 serdect hex-literal cpubits base64ct pem-rfc7468 const-oid hybrid-array digest hmac hkdf sha2 crypto-common rand_core subtle zeroize'.split())
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def admit():
    env = os.environ
    if (os.geteuid() == 0 or env.get('GITHUB_ACTIONS') != 'true'
            or env.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or env.get('RUNNER_OS') != 'Linux' or env.get('RUNNER_ARCH') != 'X64'
            or env.get('GITHUB_REPOSITORY') != 'VOLPAROSSA/volparossa'
            or env.get('GITHUB_REF') != 'refs/heads/proof/p03f-f04-collapse-corrected-20261027'
            or not env.get('GITHUB_WORKFLOW_SHA')
            or env.get('GITHUB_WORKFLOW_SHA') != env.get('GITHUB_SHA')):
        raise ValueError('requires unprivileged fixed proof branch on disposable hosted amd64 runner')
    workspace = Path(env['GITHUB_WORKSPACE'])
    temporary = Path(env['RUNNER_TEMP'])
    if any(not p.is_absolute() or not p.is_dir() or p.is_symlink() for p in (workspace, temporary)):
        raise ValueError('unsafe hosted workspace or temporary root')
    source = workspace / 'security-source'
    if source.is_symlink() or not source.is_dir():
        raise ValueError('fixed security checkout missing')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != SOURCE:
        raise ValueError('security source revision changed')
    if git(workspace, 'rev-parse', 'HEAD').decode().strip() != env['GITHUB_WORKFLOW_SHA']:
        raise ValueError('proof checkout revision changed')
    if git(source, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('security source is not clean')
    for path, digest in ORIGINAL.items():
        if sha((source / path).read_bytes()) != digest:
            raise ValueError('original C11 lock changed: ' + path)
    if (source / LOCKS[2]).exists():
        raise ValueError('new fixture unexpectedly has an existing lock')
    if any(value for key, value in env.items() if key in {
            'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC_WRAPPER',
            'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WRAPPER',
            'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER'} or key.endswith('_RUSTFLAGS')):
        raise ValueError('unreviewed Cargo/compiler override')
    return workspace, source, temporary


def source_index(root):
    """All source files, including ignored files; exclude only checkout administration."""
    result = {}
    for parent, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != '.git')
        for name in [*dirs, *sorted(names)]:
            path = Path(parent) / name
            if path.name == '.git':
                continue
            mode = path.lstat().st_mode
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(mode):
                result[relative] = dict(kind='symlink', target=os.readlink(path), mode=stat.S_IMODE(mode))
            elif stat.S_ISREG(mode):
                result[relative] = dict(kind='file', sha256=sha(path.read_bytes()), mode=stat.S_IMODE(mode))
    return result


def changed_paths(before, after):
    return sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))


def snapshot_locks(source, evidence, label):
    records = {}
    for index, name in enumerate(LOCKS):
        path = source / name
        records[name] = dict(exists=path.exists())
        if path.exists():
            raw = path.read_bytes()
            (evidence / f'{label}-{index}-Cargo.lock').write_bytes(raw)
            records[name]['sha256'] = sha(raw)
    write_json(evidence / f'{label}-locks.json', records)


def package_id(package):
    return (package['name'], package['version'], package.get('source', 'path'))


def lock_graph(raw):
    packages = tomllib.loads(raw.decode())['package']
    ids = {package_id(package): package for package in packages}
    if len(ids) != len(packages):
        raise ValueError('duplicate lock package identity')
    edges = set()
    for identity, package in ids.items():
        for dependency in package.get('dependencies', []):
            match = re.fullmatch(r'([^ ]+)(?: ([^ ]+))?(?: [(](.*)[)])?', dependency)
            if match is None:
                raise ValueError('unexpected lock dependency format: ' + dependency)
            name, version, origin = match.groups()
            matches = [key for key in ids if key[0] == name and (version is None or key[1] == version)
                       and (origin is None or key[2] == origin)]
            if len(matches) != 1:
                raise ValueError('ambiguous lock edge: ' + dependency)
            edges.add((identity, matches[0]))
    return ids, edges


def graph_delta(before, after):
    old, old_edges = lock_graph(before)
    new, new_edges = lock_graph(after)
    changed = sorted(key for key in old.keys() & new.keys() if old[key] != new[key])
    removed, added = sorted(old.keys() - new.keys()), sorted(new.keys() - old.keys())
    removed_edges, added_edges = sorted(old_edges - new_edges), sorted(new_edges - old_edges)
    # Cargo may qualify an unchanged parent's dependency string after adding a
    # second child version. Compare resolved edges rather than treating that
    # harmless representation change as a new unrelated package.
    changed_content = [key for key in changed if
                       {k: v for k, v in old[key].items() if k != 'dependencies'} !=
                       {k: v for k, v in new[key].items() if k != 'dependencies'}]
    names = {key[0] for key in [*changed_content, *removed, *added]}
    # An unchanged parent may point to an updated child. Any changed endpoint
    # must belong to the reviewed closure; unrelated changes remain fatal.
    unknown_edges = [edge for edge in [*removed_edges, *added_edges]
                     if edge[0][0] not in ALLOW and edge[1][0] not in ALLOW]
    return dict(removed=[old[key] for key in removed], added=[new[key] for key in added],
                modified=[dict(identity=key, before=old[key], after=new[key]) for key in changed],
                removed_edges=removed_edges, added_edges=added_edges,
                unknown_package_names=sorted(names - ALLOW), unknown_edges=unknown_edges)


def checked_selection(lock, name, allowed):
    matches = [p for p in tomllib.loads(lock.read_text())['package'] if p['name'] == name]
    # The fixture's direct local .5 may coexist temporarily with bigint's
    # registry .6. This sole reviewed precursor pair can be unified by Cargo.
    if name == 'ctutils' and len(matches) == 2:
        identities = {(p['version'], p.get('source')) for p in matches}
        if identities == {('0.4.5', None), ('0.4.6', REGISTRY)} and {'0.4.5', '0.4.6'} <= allowed:
            return 'ctutils@0.4.6'
        raise ValueError('unexpected duplicate ctutils precise precursor')
    if len(matches) != 1 or matches[0]['version'] not in allowed:
        raise ValueError('unexpected current package for precise selection: ' + name)
    package = matches[0]
    if name == 'ctutils' and package.get('source') != (REGISTRY if package['version'] == '0.4.6' else None):
        raise ValueError('unexpected ctutils precise precursor source')
    if name == 'crypto-bigint' and package.get('source') != REGISTRY:
        raise ValueError('unexpected crypto-bigint precise precursor source')
    return name + '@' + package['version']


class Runner:
    def __init__(self, source, evidence, compiler, private, provision):
        self.source, self.evidence, self.provision = source, evidence, provision
        self.cargo = str(compiler / 'bin/cargo')
        self.env = dict(os.environ, PATH=str(compiler / 'bin') + ':' + os.environ['PATH'],
                        RUSTC=str(compiler / 'bin/rustc'), RUSTDOC=str(compiler / 'bin/rustdoc'),
                        CARGO_HOME=str(private / 'cargo-home'), CARGO_TARGET_DIR=str(private / 'target'),
                        TMPDIR=str(private / 'tmp'), CARGO_BUILD_JOBS='2', CARGO_TERM_COLOR='never')
        self.records = []
        self.deadline = time.monotonic() + 18 * 60

    def command(self, label, arguments, timeout=120, cargo=True):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('resolver total command budget exhausted')
        timeout = min(timeout, remaining)
        command = ([self.cargo] if cargo else []) + arguments
        record = dict(label=label, command=command, cwd=str(self.source), timeout_seconds=timeout,
                      started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      cleanup_confirmed=False, exit_status=None,
                      compiler_environment={key: self.env[key] for key in ('PATH', 'RUSTC', 'RUSTDOC', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'TMPDIR')})
        self.records.append(record)
        write_json(self.evidence / 'commands.json', self.records)
        child = None
        try:
            with (self.evidence / (label + '.stdout')).open('wb') as stdout, (self.evidence / (label + '.stderr')).open('wb') as stderr:
                child = subprocess.Popen(command, cwd=self.source, env=self.env, stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    result = self.provision.wait_for_leader(child, timeout)
                    record['exit_status'] = result.si_status if result.si_code == os.CLD_EXITED else -result.si_status
                finally:
                    # The owned unreaped leader pins PGID identity. Never nest
                    # the provisioner inside this process group.
                    self.provision.finish_group(child)
                    record['cleanup_confirmed'] = True
            if record['exit_status'] != 0:
                raise subprocess.CalledProcessError(record['exit_status'], command)
        except BaseException as error:
            record['failure'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            record['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            write_json(self.evidence / 'commands.json', self.records)

    def pin(self, label, manifest, name, allowed, desired):
        lock = self.source / Path(manifest).with_name('Cargo.lock')
        precursor = dict(manifest=manifest, name=name, desired=desired, allowed_versions=sorted(allowed),
                         packages=[p for p in tomllib.loads(lock.read_text())['package'] if p['name'] == name])
        write_json(self.evidence / (label + '-precursor.json'), precursor)
        selection = checked_selection(lock, name, allowed)
        precursor['selected'] = selection
        write_json(self.evidence / (label + '-precursor.json'), precursor)
        self.command(label, ['update', '--manifest-path', manifest, '-p', selection, '--precise', desired])


def metadata_checks(value, source, fixture=False):
    packages = value['packages']
    for name, version, path in [('ctutils', '0.4.5', 'third_party/rust/vendor/ctutils-0.4.5/Cargo.toml')]:
        matches = [p for p in packages if p['name'] == name]
        if len(matches) != 1 or matches[0]['version'] != version or matches[0]['source'] is not None or matches[0]['manifest_path'] != str(source / path):
            raise ValueError('fixed current path package changed: ' + name)
    if fixture:
        for name, version in [('crypto-bigint', '0.7.9'), ('p384', '0.14.0')]:
            matches = [p for p in packages if p['name'] == name]
            if len(matches) != 1 or matches[0]['version'] != version or matches[0]['source'] != REGISTRY:
                raise ValueError('fixture current crypto pin changed: ' + name)
        if any(p['source'] not in (None, REGISTRY) for p in packages):
            raise ValueError('fixture unexpected remote source')
        local = {p['name'] for p in packages if p['source'] is None}
        if local != {'ctutils', 'volparossa-ctutils-regressions'}:
            raise ValueError('fixture unexpected path package')


def compiler_authority(provision, prefix, receipt_raw, record):
    """Authenticate installed bytes before observing executable identities."""
    record.update(accepted=False, receipt_sha256=sha(receipt_raw),
                  payload_verified=False, observations_match=False)
    receipt = json.loads(receipt_raw)
    provision.validate_receipt(receipt)
    record['receipt_validated'] = True
    metadata = provision.pins()
    record['component_authority_sha256'] = sha(json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode())
    provision.verify_payload(prefix, metadata)  # Must precede every observation.
    record['payload_verified'] = True
    # Bind the actual executable bytes as well as authenticated archive authority.
    record['executable_sha256'] = {name: sha((prefix / 'bin' / name).read_bytes())
                                   for name in ('rustc', 'cargo', 'rustdoc', 'clippy-driver', 'rustfmt')}
    observations = provision.observe(prefix)
    record['observed_versions'] = observations
    record['observations_sha256'] = sha(json.dumps(observations, sort_keys=True, separators=(',', ':')).encode())
    if observations != receipt['observed_versions']:
        raise ValueError('authenticated compiler observations changed from receipt')
    record['observations_match'] = True
    record['accepted'] = True


def interrupted(number, frame):
    raise InterruptedError('received signal ' + str(number))


def main():
    workspace, source, temporary = admit()  # Before filesystem/network/process effects.
    evidence = workspace / 'security-evidence'
    private = workspace / '.security-resolver-private'
    if evidence.exists() or private.exists():
        raise ValueError('fresh private resolver/evidence directories required')
    evidence.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    (private / 'tmp').mkdir(mode=0o700)
    before = source_index(source)
    write_json(evidence / 'source-index-before.json', before)
    snapshot_locks(source, evidence, 'before')
    binding = dict(source=SOURCE, tree=git(source, 'rev-parse', 'HEAD^{tree}').decode().strip(),
                   proof=os.environ['GITHUB_WORKFLOW_SHA'], run_id=os.environ['GITHUB_RUN_ID'],
                   run_attempt=os.environ['GITHUB_RUN_ATTEMPT'], original_lock_sha256=ORIGINAL,
                   resolver_sha256=sha(Path(__file__).read_bytes()),
                   scope='source/lock resolver only; no compilation, tests or audit',
                   runtime_acceptance=False, security_acceptance=False)
    write_json(evidence / 'source.json', binding)
    (evidence / 'source-index.git').write_bytes(git(source, 'ls-files', '-s'))
    compiler = temporary / 'volparossa-rust-1.99.1'
    runner = None
    success = False
    authority = dict(pre=dict(accepted=False), post=dict(accepted=False, reason='not attempted; resolution must first complete with confirmed cleanup'))
    try:
        spec = importlib.util.spec_from_file_location('provision199', workspace / 'scripts/provision-rust199.py')
        provision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(provision)
        receipt = (compiler / 'receipt.json').read_bytes()
        (evidence / 'compiler-receipt.json').write_bytes(receipt)
        compiler_authority(provision, compiler, receipt, authority['pre'])
        runner = Runner(source, evidence, compiler, private, provision)
        runner.command('cargo-version', ['--version', '--verbose'])
        runner.command('rustc-version', [str(compiler / 'bin/rustc'), '-Vv'], cargo=False)
        runner.command('root-update-sev', ['update', '-p', 'sev'])
        runner.pin('root-pin-crypto-bigint', 'Cargo.toml', 'crypto-bigint', {'0.7.8', '0.7.9', '0.7.10'}, '0.7.9')
        runner.pin('root-pin-ctutils', 'Cargo.toml', 'ctutils', {'0.4.4', '0.4.5', '0.4.6'}, '0.4.5')
        runner.pin('fuzz-pin-ctutils', 'fuzz/Cargo.toml', 'ctutils', {'0.4.4', '0.4.5', '0.4.6'}, '0.4.5')
        runner.command('fixture-generate-lockfile', ['generate-lockfile', '--manifest-path', FIXTURE + '/Cargo.toml'])
        runner.pin('fixture-pin-crypto-bigint', FIXTURE + '/Cargo.toml', 'crypto-bigint', {'0.7.9'}, '0.7.9')
        runner.pin('fixture-pin-ctutils', FIXTURE + '/Cargo.toml', 'ctutils', {'0.4.4', '0.4.5', '0.4.6'}, '0.4.5')
        for label, manifest in [('root', 'Cargo.toml'), ('fuzz', 'fuzz/Cargo.toml'), ('fixture', FIXTURE + '/Cargo.toml')]:
            runner.command(label + '-fetch', ['fetch', '--locked', '--manifest-path', manifest])
            for features in (False, True):
                runner.command(label + ('-full' if features else '-default') + '-metadata',
                               ['metadata', '--format-version', '1', '--locked', '--offline', '--manifest-path', manifest]
                               + (['--all-features'] if features else []))
        root_metadata = evidence / 'root-full-metadata.stdout'
        fuzz_metadata = evidence / 'fuzz-full-metadata.stdout'
        for label in ('root', 'fuzz', 'fixture'):
            metadata_checks(json.loads((evidence / (label + '-full-metadata.stdout')).read_text()), source, label == 'fixture')
        runner.command('sev-p384-scope', [sys.executable, '-B', str(source / 'scripts/check-sev-p384-scope.py'), str(root_metadata), str(fuzz_metadata)], cargo=False)
        runner.command('public-rsa-scope', [sys.executable, '-B', str(source / 'scripts/check-public-rsa-scope.py'), str(root_metadata), str(fuzz_metadata), str(evidence / 'temporary-root-deny.toml')], cargo=False)
        if not all(record['cleanup_confirmed'] for record in runner.records):
            raise ValueError('cleanup unconfirmed; post compiler execution forbidden')
        authority['post'] = dict(accepted=False)
        compiler_authority(provision, compiler, (compiler / 'receipt.json').read_bytes(), authority['post'])
        if authority['post']['receipt_sha256'] != authority['pre']['receipt_sha256']:
            authority['post']['accepted'] = False
            raise ValueError('compiler receipt changed during resolution')
        success = True
    except BaseException:
        (evidence / 'failure.log').write_text(traceback.format_exc())
        raise
    finally:
        write_json(evidence / 'compiler-authority.json', authority)
        after = source_index(source)
        write_json(evidence / 'source-index-after.json', after)
        snapshot_locks(source, evidence, 'after')
        changed = changed_paths(before, after)
        deltas = {}
        delta_errors = []
        for index, name in enumerate(LOCKS[:2]):
            try:
                deltas[name] = graph_delta((evidence / f'before-{index}-Cargo.lock').read_bytes(), (source / name).read_bytes())
            except BaseException as error:
                delta_errors.append(name + ': ' + repr(error))
        if (source / LOCKS[2]).exists():
            try:
                packages, edges = lock_graph((source / LOCKS[2]).read_bytes())
                deltas[LOCKS[2]] = dict(classification='new fixture initial graph; source-only, no execution',
                                      packages=list(packages.values()), edges=sorted(edges))
            except BaseException as error:
                delta_errors.append(LOCKS[2] + ': ' + repr(error))
        write_json(evidence / 'lock-graph-delta.json', deltas)
        cleanup = runner is not None and all(record['cleanup_confirmed'] for record in runner.records)
        unknown = [name for name in changed if name not in LOCKS]
        graph_unknown = any(d.get('unknown_package_names') or d.get('unknown_edges') for d in deltas.values())
        compiler_accepted = authority['pre']['accepted'] and authority['post']['accepted']
        summary = dict(binding, resolver_completed=success, cleanup_confirmed=cleanup,
                       compiler_authority=authority, compiler_authority_accepted=compiler_accepted,
                       private_directory_retained=str(private), changed_paths=changed,
                       unexpected_changed_paths=unknown, graph_delta_errors=delta_errors,
                       unknown_root_fuzz_delta=graph_unknown,
                       resolved_inputs_ready=success and compiler_accepted and cleanup and not unknown and not graph_unknown and not delta_errors)
        write_json(evidence / 'resolver-summary.json', summary)
        write_json(evidence / 'artifact-sha256.json', {path.name: sha(path.read_bytes()) for path in sorted(evidence.iterdir()) if path.is_file() and path.name != 'artifact-sha256.json'})
        if not summary['resolved_inputs_ready']:
            raise ValueError('resolution incomplete or unexpected mutation/delta; preserve all evidence and private files')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    main()
