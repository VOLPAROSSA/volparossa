#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Authenticated fixed-endpoint protocol simulations; no real hosted continuity."""
import copy
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('archive_fixtures',Path(__file__).with_name('test-weather-release-archive.py'))
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
A=F.A


class ReleaseProtocol(unittest.TestCase):
    def check(self, values, lock=None):
        A.validate_release(lock or F.admitted(),*values,A.P.timestamp('2026-11-01T00:00:00Z'))

    def test_production_metadata_validator_projects_only_authority_fields(self):
        values=F.release_fixture(F.admitted());self.check(values)
        for part in values[:3]: part['unrelated_mutable_notes']='ignored metadata'
        values[1]['target_commitish']='mutable-branch'
        for part in values[3]: part['download_count']=100
        self.check(values)

    def test_release_repository_tag_and_all_asset_negative_cases(self):
        failures=[(0,'id',True),(0,'id',23),(0,'full_name','other/repo'),(1,'id',True),
            (1,'id',23),(1,'draft',True),(1,'draft',None),(1,'immutable',False),
            (1,'immutable',None),(1,'prerelease',False),(1,'tag_name','latest'),
            (1,'published_at','2099-01-01T00:00:00Z'),(1,'published_at',None),
            (2,'ref','refs/tags/'+A.TAG+'-prefix'),(2,'object',dict(type='commit',sha='b'*40)),
            (2,'object',dict(type='tag',sha=A.COMMIT))]
        for section,key,value in failures:
            values=F.release_fixture(F.admitted());values[section][key]=value
            with self.subTest(section=section,key=key,value=value),self.assertRaises((A.Rejected,TypeError)):
                self.check(values)
        for section,key in ((1,'immutable'),(1,'published_at'),(2,'object')):
            values=F.release_fixture(F.admitted());del values[section][key]
            with self.assertRaises((A.Rejected,KeyError)):self.check(values)
        for key,value in [('id',True),('id',-1),('id',2**63),('id',999),('name','other.zip'),
            ('size',True),('size',1.0),('size',-1),('size',1),('digest','sha256:'+'b'*64),('state','new')]:
            values=F.release_fixture(F.admitted());values[3][0][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(A.Rejected):self.check(values)
        for change in ('missing','extra','duplicate'):
            values=F.release_fixture(F.admitted())
            if change=='missing':values[3].pop()
            elif change=='extra':values[3].append(copy.deepcopy(values[3][0]))
            else:values[3][1]['id']=values[3][0]['id']
            with self.subTest(change=change),self.assertRaises(A.Rejected):self.check(values)

    def test_simulated_after_expiry_uses_only_release_endpoints_and_capture_time(self):
        fixture=F.Fixture()
        with tempfile.TemporaryDirectory() as temporary, fixture.active(), \
                patch.object(A.P,'utcnow',return_value=A.P.timestamp('2026-11-01T00:00:00Z')):
            report=A.fetch(fixture.lock,'android-v6',Path(temporary)/'inputs',fixture)
        self.assertEqual(report['captured_at'],'2026-10-23T00:01:00Z')
        self.assertTrue(report['verified_at'].startswith('2026-11-01'))
        self.assertEqual(len(fixture.calls),11) # 4 metadata, 5 small objects, 2 ZIPs
        self.assertTrue(all('/actions/' not in call for call in fixture.calls))
        self.assertTrue(all(call in A.api_paths(fixture.lock) for call in fixture.calls))

    def test_invalid_release_metadata_rejects_before_any_asset_bytes_or_output(self):
        for changed in ('immutable', 'asset-digest', 'tag-target'):
            fixture=F.Fixture()
            if changed=='immutable':fixture.responses[A.BASE+'/releases/21']['immutable']=False
            if changed=='asset-digest':fixture.responses[A.BASE+'/releases/21/assets?per_page=100&page=1'][0]['digest']='sha256:'+'f'*64
            if changed=='tag-target':fixture.responses[A.BASE+'/git/ref/tags/'+A.TAG]['object']['sha']='b'*40
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as temporary,fixture.active():
                output=Path(temporary)/'inputs'
                with self.assertRaises(A.Rejected):A.fetch(fixture.lock,'android-v6',output,fixture)
                self.assertEqual(len(fixture.calls),4)
                self.assertFalse(any('/releases/assets/' in call for call in fixture.calls))
                self.assertFalse(output.exists())

    def test_signal_during_download_cleans_owned_output(self):
        fixture=F.Fixture();original=fixture.get
        def interrupted(endpoint,target,maximum,binary=False):
            if endpoint.endswith('/'+str(fixture.lock['assets']['decoder']['id'])):
                signal.raise_signal(signal.SIGTERM)
            original(endpoint,target,maximum,binary)
        fixture.get=interrupted
        previous={n:signal.signal(n,A.P.interrupted) for n in (signal.SIGTERM,signal.SIGINT)}
        try:
            with tempfile.TemporaryDirectory() as temporary,fixture.active():
                output=Path(temporary)/'inputs'
                with self.assertRaises(A.Rejected):A.fetch(fixture.lock,'decoder-abi',output,fixture)
                self.assertFalse(output.exists())
        finally:
            for number,handler in previous.items():signal.signal(number,handler)


class DownloaderProtocol(unittest.TestCase):
    def subprocess_fixture(self, code, endpoint=None, maximum=20, timeout=2, token='fixture-secret'):
        original=subprocess.Popen;calls=[];processes=[]
        def launch(command,**kwargs):
            calls.append((command,kwargs))
            process=original([sys.executable,'-c',code],**kwargs);processes.append(process)
            return process
        env=dict(GH_TOKEN=token,GH_DEBUG='api',GH_HOST='evil.test',GH_CONFIG_DIR='/unsafe',
                 GITHUB_TOKEN='unrelated-secret',GH_ENTERPRISE_TOKEN='other-secret')
        target=io.BytesIO();transport=A.Transport(F.admitted())
        with patch.dict(os.environ,env),patch.object(A.subprocess,'Popen',side_effect=launch):
            try:transport.get(endpoint or A.BASE,target,maximum,binary=True,timeout=timeout)
            finally:
                self.assertTrue(all(p.poll() is not None and p.stdout.closed for p in processes))
        return calls,target.getvalue()

    def test_exact_authenticated_gh_get_binary_header_and_sanitized_environment(self):
        calls,raw=self.subprocess_fixture('import sys;sys.stdout.buffer.write(b"fixture")')
        self.assertEqual(raw,b'fixture');command,kwargs=calls[0]
        self.assertEqual(command,['gh','api','--hostname','github.com','--method','GET','--header',
                                  'Accept: application/octet-stream',A.BASE])
        self.assertEqual(kwargs['env']['GH_TOKEN'],'fixture-secret')
        self.assertEqual(kwargs['env']['GH_PROMPT_DISABLED'],'1')
        self.assertTrue(kwargs['start_new_session'])
        self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
        for key in ('GH_DEBUG','GH_HOST','GH_CONFIG_DIR','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN'):
            self.assertNotIn(key,kwargs['env'])
        self.assertNotIn('fixture-secret',' '.join(command))

    def test_no_token_no_process_and_no_arbitrary_host_actions_latest_or_url(self):
        for token in ('','bad\nvalue'):
            with self.subTest(token=repr(token)),self.assertRaises(A.Rejected):
                self.subprocess_fixture('raise Exception()',token=token)
        for endpoint in ('https://evil.test/',A.BASE+'/actions/artifacts/1/zip',
                A.BASE+'/releases/latest','//api.github.com'+A.BASE,A.BASE+'/releases/assets/999999'):
            with self.subTest(endpoint=endpoint),self.assertRaises(A.Rejected):
                self.subprocess_fixture('raise Exception()',endpoint=endpoint)

    def test_oversize_stderr_failure_and_timeout_reap_child_without_sensitive_error(self):
        for code,maximum,timeout in (
            ('import sys;sys.stdout.write("x"*21)',20,2),
            ('import sys;sys.stderr.write("fixture-secret");sys.exit(3)',20,2),
            ('import time;time.sleep(30)',20,.05)):
            with self.subTest(code=code),self.assertRaises(A.Rejected) as rejected:
                self.subprocess_fixture(code,maximum=maximum,timeout=timeout)
            self.assertNotIn('fixture-secret',str(rejected.exception))

    def test_closed_stdout_stalled_process_times_out_and_is_reaped(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.subprocess_fixture('import os,time;os.close(1);time.sleep(30)',timeout=.05)

    def test_timeout_terminates_descendant_process_group(self):
        # The process reports its fixture child PID; no gh or downloaded program runs.
        code='import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);print(p.pid,flush=True);time.sleep(30)'
        original=subprocess.Popen;processes=[];target=io.BytesIO()
        def launch(command,**kwargs):
            p=original([sys.executable,'-c',code],**kwargs);processes.append(p);return p
        with patch.dict(os.environ,GH_TOKEN='fixture'),patch.object(A.subprocess,'Popen',side_effect=launch):
            with self.assertRaises(A.Rejected):A.Transport(F.admitted()).get(A.BASE,target,100,timeout=.15)
        self.assertIsNotNone(processes[0].poll());self.assertTrue(processes[0].stdout.closed)
        child=int(target.getvalue().strip())
        state=Path('/proc')/str(child)/'stat'
        # A terminated grandchild can briefly remain an init-owned zombie.
        if state.exists():self.assertIn(state.read_text().split()[2],('Z','X'))


if __name__=='__main__':unittest.main()
