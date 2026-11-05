#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert source/auth/config and caller-order contracts; never executes Cargo."""
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

P = runpy.run_path(str(Path(__file__).with_name('cargo-source-policy.py')))
G = P['activate'].__globals__
ROOT = P['ROOT']


class PublicSources(unittest.TestCase):
    def test_current_manifests_locks_and_exact_local_patches_are_admitted(self):
        inputs = P['repository_sources']()
        self.assertIn('Cargo.lock', inputs)
        self.assertIn('fuzz/Cargo.lock', inputs)
        self.assertIn('third_party/rust/ctutils-current-regressions/Cargo.lock', inputs)

    def test_lock_sources_reject_git_alternate_missing_checksum_and_malformed(self):
        base = 'version = 4\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n'
        good = base+'source = "'+P['REGISTRY']+'"\nchecksum = "'+'a'*64+'"\n'
        P['lock_sources'](good.encode())
        for raw in (good.replace(P['REGISTRY'], 'git+ssh://private/value'),
                    good.replace(P['REGISTRY'], 'registry+https://alternate.invalid/index'),
                    good.replace('checksum', 'missing'), good.replace('a'*64, 'short'), 'bad TOML'):
            with self.subTest(raw=raw[:20]), self.assertRaises(P['PolicyError']):
                P['lock_sources'](raw.encode())

    def test_manifest_sources_reject_configured_registry_git_and_untrusted_patches(self):
        for value in ({'dependencies': {'x': {'registry': 'alternate'}}},
                      {'target': {'cfg(unix)': {'dependencies': {'x': {'git': 'ssh://private'}}}}},
                      {'patch': {'crates-io': {'x': {'git': 'https://private'}}}},
                      {'patch': {'https://private': {'x': {'path': '.'}}}},
                      {'workspace': {'members': ['unknown-member']}},
                      {'dependencies': {'x': {'path': 'unreviewed-hidden-directory'}}},
                      {'replace': {}}):
            with self.subTest(value=value), self.assertRaises(P['PolicyError']):
                P['manifest_sources'](value, ROOT)

    def test_rejected_environment_values_are_not_read_or_printed(self):
        class Secret:
            def __str__(self): raise AssertionError('secret was read')
        for name in ('CARGO_REGISTRY_TOKEN', 'CARGO_REGISTRIES_OTHER_INDEX',
                     'CARGO_REGISTRIES_CRATES_IO_PROTOCOL', 'CARGO_SOURCE_CRATES_IO_REPLACE_WITH',
                     'CARGO_CREDENTIAL_PROVIDER', 'CARGO_CONFIG', 'CARGO_ALIAS_FETCH',
                     'CARGO_HTTP_PROXY', 'CARGO_NET_GIT_FETCH_WITH_CLI', 'SSH_AUTH_SOCK',
                     'GIT_CONFIG_COUNT', 'HTTPS_PROXY', 'RUSTUP_TOOLCHAIN', 'CARGO_UNKNOWN'):
            with self.subTest(name=name), self.assertRaises(P['PolicyError']) as error:
                P['check_environment']({name: Secret()})
            self.assertEqual(str(error.exception), 'CARGO_PUBLIC_SOURCE_POLICY_V1=environment')

    def test_ambient_configs_credentials_and_symlinks_rejected_without_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cwd = root/'child'; cwd.mkdir()
            home = root/'account'; home.mkdir(); (home/'.cargo').mkdir()
            env = {'HOME': str(home)}
            for file in (root/'.cargo/config', root/'.cargo/config.toml',
                         home/'.cargo/config', home/'.cargo/credentials',
                         home/'.cargo/credentials.toml', home/'.netrc'):
                file.parent.mkdir(exist_ok=True)
                for symlink in (False, True):
                    file.symlink_to(root/'absent-private') if symlink else file.write_text('secret must not be read')
                    with patch.object(Path, 'read_bytes', side_effect=AssertionError('secret')), \
                         patch.object(Path, 'read_text', side_effect=AssertionError('secret')):
                        with self.assertRaises(P['PolicyError']): P['check_discovery'](cwd, env)
                    file.unlink()

    def test_fresh_home_own_origin_reuse_and_context_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); account = parent/'account'; account.mkdir()
            env = {'HOME': str(account)}
            with patch.dict(G, runtime=lambda *_: parent, repository_sources=lambda: {'locked': 'a'*64}):
                active = P['activate']('runner', env=env, cwd=parent)
                home = Path(active['CARGO_HOME'])
                self.assertEqual(home.stat().st_mode & 0o777, 0o700)
                self.assertEqual((home/'config.toml').read_bytes(), P['CONFIG'])
                self.assertFalse(json.loads((home/P['MARKER']).read_text())['cargo_binary_patched'])
                self.assertEqual(P['activate']('runner', env=active, cwd=parent, reuse=True), active)
                with self.assertRaises(P['PolicyError']): P['activate']('runner', env=active, cwd=parent)
                child = P['activate']('runner', env=active, home=parent/'nested', cwd=parent)
                self.assertNotEqual(active['CARGO_HOME'], child['CARGO_HOME'])
                # A changed config is never silently reset, sanitized or reused.
                (home/'config.toml').write_text('alternate secret config')
                with self.assertRaises(P['PolicyError']): P['validate_active'](parent, active)

    def test_context_owner_mode_links_and_source_binding_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); account=parent/'account';account.mkdir()
            with patch.dict(G, runtime=lambda *_: parent, repository_sources=lambda: {'lock': 'a'}):
                active=P['activate']('runner', env={'HOME':str(account)}, cwd=parent)
                home=Path(active['CARGO_HOME'])
                home.chmod(0o755)
                with self.assertRaises(P['PolicyError']):P['validate_active'](parent,active)
                home.chmod(0o700)
                marker=home/P['MARKER']; raw=marker.read_bytes(); marker.unlink();marker.symlink_to(parent/'absent')
                with self.assertRaises(P['PolicyError']):P['validate_active'](parent,active)
                marker.unlink();marker.write_bytes(raw);marker.chmod(0o600)
                with patch.dict(G,repository_sources=lambda:{'lock':'changed'}), self.assertRaises(P['PolicyError']):
                    P['validate_active'](parent,active)

    def test_public_scope_sidecar_binds_profile_hashes_without_environment_or_config_values(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);account=parent/'account';account.mkdir()
            with patch.dict(G,runtime=lambda *_:parent,repository_sources=lambda:{'Cargo.lock':'a'*64}):
                active=P['activate']('runner',env={'HOME':str(account),'CARGO_TERM_COLOR':'always'},cwd=parent)
                output=parent/'cargo-source-policy.json'
                value=P['write_scope'](active,output,cwd=parent)
                self.assertEqual(value,P['digest'](output.read_bytes()))
                record=json.loads(output.read_text())
                self.assertFalse(record['cargo_binary_patched'])
                self.assertFalse(record['registry_authentication'])
                self.assertFalse(record['ssh_sources'])
                self.assertEqual(record['config_sha256'],P['digest'](P['CONFIG']))
                self.assertEqual(len(record['origin_sha256']),64)
                self.assertNotIn(str(parent),output.read_text())
                self.assertNotIn('CARGO_TERM_COLOR',output.read_text())
                self.assertLess(output.stat().st_size,65536)
                self.assertEqual(output.stat().st_mode & 0o777,0o600)
                self.assertEqual(P['write_scope'](active,output,cwd=parent),value)
                output.write_text('unexpected existing data')
                with self.assertRaises(P['PolicyError']):P['write_scope'](active,output,cwd=parent)

    def test_no_host_admission_or_dynamic_source_arguments(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(P['PolicyError']):
            P['activate']('runner')
        for option in ('--config=private', '--config', '--registry', '--git=https://private',
                       '--index=ssh://private', '--path=/private', '-Zsomething'):
            with self.subTest(option=option), self.assertRaises(P['PolicyError']):
                P['check_command'](['fetch', option])
        P['check_command'](['test','--locked','--offline','--','--exact'])

    def test_location_requires_owned_hosted_temp_or_exact_existing_kvm_account(self):
        with tempfile.TemporaryDirectory() as directory:
            env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_TEMP':directory}
            self.assertEqual(P['runtime']('runner',env),Path(directory))
            with patch.object(P['os'],'geteuid',return_value=0), self.assertRaises(P['PolicyError']):
                P['runtime']('runner',env)
        for mode,account in (('guest','volparossa'),('alpha-guest','vpci')):
            def content(path):
                return 'systemd\n' if str(path)=='/proc/1/comm' else 'ID=debian\nVERSION_ID="13"\n'
            with patch.object(P['os'],'geteuid',return_value=1000), \
                 patch.object(Path,'home',return_value=Path('/home')/account), \
                 patch.object(Path,'read_text',content), patch.object(Path,'resolve',lambda path:path), \
                 patch.object(Path,'is_dir',return_value=True), patch.object(Path,'is_symlink',return_value=False), \
                 patch.object(Path,'stat',return_value=SimpleNamespace(st_uid=1000,st_mode=0o40755)), \
                 patch.object(P['subprocess'],'check_output',return_value='kvm\n') as query:
                self.assertEqual(P['runtime'](mode,{}),Path('/home')/account/'.local')
                query.assert_called_once_with(['systemd-detect-virt'],text=True)
                query.return_value='docker\n'
                with self.assertRaises(P['PolicyError']):P['runtime'](mode,{})

    def test_compiler_environment_cannot_select_an_unreviewed_executable(self):
        env={'HOME':'/account','RUNNER_TEMP':'/runner'}
        for key in ('RUSTC','RUSTDOC','CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER','CARGO_AUDIT'):
            with self.subTest(key=key), self.assertRaises(P['PolicyError']):
                P['check_environment'](dict(env,**{key:'/untrusted/executable'}))
        P['check_environment'](dict(env,RUSTC='/runner/volparossa-rust-1.89.0/bin/rustc',
            RUSTDOC='/runner/volparossa-rust-1.89.0/bin/rustdoc',CARGO_BUILD_JOBS='2',
            CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER='/runner/volparossa-rust-1.89.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld'))

    def test_offline_diagnostic_only_admits_its_fixed_resolver_leaf_and_checked_ancestry(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);account=parent/'account';account.mkdir()
            with patch.dict(G,runtime=lambda *_:parent,repository_sources=lambda:{'lock':'a'}):
                active=P['activate']('runner',env={'HOME':str(account)},cwd=parent)
                with tempfile.TemporaryDirectory(prefix='volparossa-lock-diagnostic-',dir=parent) as temporary:
                    scratch=Path(temporary);cwd=scratch/'third_party/rust/backport-regressions'
                    (cwd/'.cargo').mkdir(mode=0o700,parents=True)
                    config=cwd/'.cargo/config.toml';config.write_bytes(P['BACKPORT_CONFIG'])
                    for name in ('Cargo.toml','Cargo.lock'):
                        shutil.copyfile(ROOT/'third_party/rust/backport-regressions'/name,cwd/name)
                    for name in ('hickory-proto-0.25.2','hickory-resolver-0.25.2','libp2p-yamux-0.47.0','time-0.3.41'):
                        relative=Path('third_party/rust/vendor')/name/'Cargo.toml'
                        (scratch/relative).parent.mkdir(parents=True)
                        shutil.copyfile(ROOT/relative,scratch/relative)
                    self.assertEqual(P['validate_diagnostic'](cwd,active),active)
                    config.write_bytes(b'unknown private config')
                    with self.assertRaises(P['PolicyError']):P['validate_diagnostic'](cwd,active)
                    config.write_bytes(P['BACKPORT_CONFIG'])
                    (scratch/'.cargo').mkdir();unknown=scratch/'.cargo/config.toml'
                    unknown.write_text('unknown must not be read')
                    original=Path.read_bytes
                    def read(path):
                        if path==unknown:raise AssertionError('unknown ancestor config was read')
                        return original(path)
                    with patch.object(Path,'read_bytes',read), self.assertRaises(P['PolicyError']):
                        P['validate_diagnostic'](cwd,active)

    def test_exact_tool_archive_and_bundled_graph_checked_before_install(self):
        manifest=b'[package]\nname="fixture"\nversion="1.0.0"\n'
        lock=b'version=4\n[[package]]\nname="fixture"\nversion="1.0.0"\n'
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w:gz') as archive:
            for name,data in (('Cargo.toml',manifest),('Cargo.lock',lock)):
                item=tarfile.TarInfo('fixture-1.0.0/'+name);item.size=len(data);archive.addfile(item,io.BytesIO(data))
        data=raw.getvalue(); pins=('1.0.0',P['digest'](data),P['digest'](manifest),P['digest'](lock))
        with patch.dict(G,TOOL_PINS={'fixture':pins}):
            P['verify_tool_archive']('fixture',data)
            with self.assertRaises(P['PolicyError']):P['verify_tool_archive']('fixture',data+b'bad')
        for name in ('cargo-deny','cargo-audit'):
            self.assertEqual(len(P['TOOL_PINS'][name]),4)

    def test_derived_deny_home_has_only_own_config_and_bound_origin_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);account=parent/'account';account.mkdir()
            with patch.dict(G,runtime=lambda *_:parent,repository_sources=lambda:{'lock':'a'}):
                active=P['activate']('runner',env={'HOME':str(account)},cwd=parent)
                (Path(active['CARGO_HOME'])/'registry').mkdir()
                owned=parent/'volparossa-rustsec.ABC123';owned.mkdir(mode=0o700)
                destination=owned/'cargo-home'
                # Use the real source validation but an inert discovery cwd.
                with patch.dict(G,ROOT=parent):P['derive_deny_home'](destination,active)
                self.assertEqual((destination/'config.toml').read_bytes(),P['CONFIG'])
                self.assertTrue((destination/'registry').is_symlink())
                self.assertFalse((destination/'git').exists())
                with self.assertRaises(P['PolicyError']):P['derive_deny_home'](destination,active)

    def test_all_current189_callers_export_fixed_home_in_same_shell(self):
        git_export='export '+' '.join(name+'='+value for name,value in P['GIT_ENV'].items())
        count=0
        for path in (ROOT/'.github/workflows').glob('*.yml'):
            lines=path.read_text().splitlines()
            for index,line in enumerate(lines):
                if 'python3 -B ' in line and 'scripts/provision-rust189.py runner' in line:
                    self.assertEqual(lines[index+1].strip(),'export CARGO_HOME="$RUNNER_TEMP/volparossa-cargo-public-v1"',path)
                    self.assertEqual(lines[index+2].strip(),git_export,path)
                    count+=1
        self.assertEqual(count,20)
        helper=(ROOT/'tests/helper/run-helper-boundary-evidence-vm.sh').read_text()
        self.assertTrue(('python3 -B scripts/provision-rust189.py guest\n'
                         'export CARGO_HOME=/home/volparossa/.local/volparossa-cargo-public-v1\n'+git_export) in helper)
        self.assertTrue(('export CARGO_HOME=/home/volparossa/.local/volparossa-cargo-public-v1\n'
                         +git_export+'\npython3 -B scripts/provision-rust189.py guest-check') in helper)
        alpha=(ROOT/'tests/integration/run-alpha-topology-vm.sh').read_text()
        self.assertTrue(('python3 -B scripts/provision-rust189.py alpha-guest\n'
                         '    export CARGO_HOME=/home/vpci/.local/volparossa-cargo-public-v1\n    '+git_export) in alpha)
        audit=(ROOT/'scripts/quality-audit-tools.py').read_text()
        self.assertLess(audit.index("POLICY['audit_tool'](name)"),audit.index('"cargo", "install"'))
        self.assertIn('"--registry", "crates-io", name',audit)
        provision=(ROOT/'scripts/provision-rust189.py').read_text()
        self.assertLess(provision.index("POLICY['activate'](mode)"),provision.index('observed_versions=observe(prefix, cargo_env)'))

    def test_git_process_controls_are_exported_to_same_shell_children_and_bound_on_reuse(self):
        block='export '+' '.join(name+'='+value for name,value in P['GIT_ENV'].items())
        code='import json,os;print(json.dumps({name:os.environ[name] for name in '+repr(list(P['GIT_ENV']))+'}))'
        result=subprocess.run(['sh','-eu','-c',block+'\nexec python3 -c "$1"','fixture',code],
                              capture_output=True,text=True,check=True)
        self.assertEqual(json.loads(result.stdout),P['GIT_ENV'])
        self.assertTrue(P['tomllib'].loads(P['CONFIG'].decode())['net']['git-fetch-with-cli'])
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);account=parent/'account';account.mkdir()
            with patch.dict(G,runtime=lambda *_:parent,repository_sources=lambda:{'lock':'a'}):
                active=P['activate']('runner',env={'HOME':str(account)},cwd=parent)
                for name in P['GIT_ENV']:
                    modified=dict(active);modified.pop(name)
                    with self.subTest(name=name), self.assertRaises(P['PolicyError']):
                        P['validate_active'](parent,modified)
                for name in ('GIT_CONFIG_GLOBAL','GIT_CONFIG_COUNT','GIT_ASKPASS','SSH_ASKPASS','GIT_SSH_COMMAND'):
                    with self.subTest(name=name), self.assertRaises(P['PolicyError']):
                        P['activate']('runner',env={'HOME':str(account),name:'/untrusted'},cwd=parent,home=parent/'other')

    def test_scope_artifact_paths_are_fixed_and_do_not_publish_cargo_homes(self):
        raw=(ROOT/'.github/workflows/quality.yml').read_text()
        for name in ('cargo-source-policy.json','cargo-source-policy-cargo-deny.json','cargo-source-policy-cargo-audit.json',
                     'ctutils-proof/cargo-source-policy.json','zbus-upstream-proof/cargo-source-policy.json'):
            self.assertTrue('${{ runner.temp }}/'+name in raw,name)
        self.assertFalse('volparossa-cargo-public-v1/**' in raw)
        dps=(ROOT/'.github/workflows/dps-native-quality.yml').read_text()
        self.assertTrue('install -m 0600 "$RUNNER_TEMP/cargo-source-policy.json" dps-native-evidence/cargo-source-policy.json' in dps)
        self.assertTrue('            dps-native-evidence/cargo-source-policy.json' in dps)


if __name__=='__main__':unittest.main()
