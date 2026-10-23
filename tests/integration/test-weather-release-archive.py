#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert archive schema/byte/extraction fixtures; no real release availability claim."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('archive_consumer', ROOT / 'scripts/fetch-weather-archive.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def admitted():
    lock = A.read_lock()
    lock.update(state='admitted', blocked_reason=None)
    lock['release'].update(id=21, repository_id=22, tag_object=dict(type='commit', sha=A.COMMIT))
    for index, pin in enumerate(lock['assets'].values(), 100):
        pin['id'] = index
    return lock


def release_fixture(lock):
    return [dict(id=lock['release']['repository_id'], full_name=A.REPOSITORY),
        dict(id=lock['release']['id'], tag_name=A.TAG, draft=False, immutable=True,
             prerelease=True, published_at='2026-10-23T00:00:00Z'),
        dict(ref='refs/tags/' + A.TAG, object=dict(type='commit', sha=A.COMMIT)),
        [dict(id=p['id'], name=p['name'], size=p['bytes'], digest='sha256:' + p['sha256'], state='uploaded')
            for p in lock['assets'].values()]]


def zip_bytes(members=None):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw, mode in members or [('dir/NOTICE', b'Original notice\n', stat.S_IFREG | 0o755)]:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, raw)
    return stream.getvalue()


class Fixture:
    """Only in-process tests replace context. Product CLI has no fixture authority."""
    def __init__(self, members=None):
        self.lock = admitted()
        records, snapshots, pins, receipts, provenance = A.context()
        records, pins = copy.deepcopy(records), copy.deepcopy(pins)
        raw_zip = zip_bytes(members)
        self.blobs = {}
        entries = {}
        for role, record in records.items():
            if record['origin'] is None:
                continue
            key = str(record['origin']['artifact_id'])
            pin = pins[key]
            pin.update(bytes=len(raw_zip), sha256=A.P.sha256(raw_zip))
            record.update(name=pin['sha256'] + '.zip', bytes=pin['bytes'], sha256=pin['sha256'])
            origin = record['origin']
            base = 'https://api.github.com/repos/' + pin['repository'] + '/actions/'
            metadata = dict(artifact=dict(id=pin['id'], name=pin['name'], size_in_bytes=pin['bytes'],
                url=base+'artifacts/'+key, archive_download_url=base+'artifacts/'+key+'/zip',
                expired=False, digest='sha256:'+pin['sha256'], created_at='2026-10-12T01:00:01Z',
                updated_at='2026-10-12T01:00:02Z', expires_at='2026-10-26T00:00:00Z',
                workflow_run=dict(id=pin['run_id'], repository_id=9, head_repository_id=9, head_sha=pin['commit'])),
                run=dict(id=pin['run_id'], head_sha=pin['commit'], run_attempt=1, status='completed', conclusion='success',
                    created_at='2026-10-12T01:00:00Z', updated_at='2026-10-12T01:00:03Z',
                    url=base+'runs/'+str(pin['run_id']), repository=dict(id=9, full_name=pin['repository']),
                    head_repository=dict(id=9, full_name=pin['repository'])))
            entries[key] = dict(pin=pin, metadata=metadata,
                inspection=dict(members=1, expanded_bytes=len(b'Original notice\n'), abi_receipts_checked=0))
            self.blobs[role] = raw_zip
        manifest = dict(schema=A.P.SCHEMA, capture_started_at='2026-10-23T00:00:00Z',
            captured_at='2026-10-23T00:01:00Z', admissions={k:A.P.sha256(v) for k,v in snapshots.items()},
            artifacts=entries, **A.P.FLAGS)
        raw = A.P.encoded(manifest)
        records['preservation-manifest'].update(bytes=len(raw), sha256=A.P.sha256(raw))
        self.blobs['preservation-manifest'] = raw
        for role, (path, _) in A.SNAPSHOTS.items():
            self.blobs[role] = snapshots[path]
        for role, record in records.items():
            self.lock['assets'][role] = {**record, 'id': self.lock['assets'][role]['id']}
        self.context = (records, snapshots, pins, receipts, provenance)
        self.responses = dict(zip((A.BASE, A.BASE+'/releases/21', A.BASE+'/git/ref/tags/'+A.TAG,
            A.BASE+'/releases/21/assets?per_page=100&page=1'), release_fixture(self.lock)))
        self.calls = []
        self.fail_role = None
        self.corrupt = None

    def json(self, endpoint):
        self.calls.append(endpoint)
        if '/actions/' in endpoint or endpoint not in self.responses:
            raise AssertionError('unexpected transport authority')
        return copy.deepcopy(self.responses[endpoint])

    def get(self, endpoint, target, maximum, binary=False):
        self.calls.append(endpoint)
        roles = {A.BASE+'/releases/assets/'+str(p['id']): role for role,p in self.lock['assets'].items()}
        assert endpoint in roles and binary
        role = roles[endpoint]
        if self.fail_role == role:
            raise A.Rejected('fixture transport interruption')
        raw = self.blobs[role]
        if self.corrupt == role:
            raw = raw[:-1] + bytes([raw[-1] ^ 1])
        assert len(raw) <= maximum
        target.write(raw)

    def active(self):
        return patch.object(A, 'context', return_value=self.context)


class ArchiveAdmission(unittest.TestCase):
    def test_checked_in_blocked_schema_and_real_known_pins(self):
        lock = A.read_lock()
        self.assertFalse(A.validate(lock)['eligible'])
        self.assertEqual(len(lock['assets']), 12)
        self.assertEqual(lock['assets']['preservation-manifest']['bytes'], 15987)
        self.assertEqual(lock['assets']['preservation-manifest']['sha256'], A.MANIFEST_SHA)
        self.assertTrue(A.validate(admitted())['eligible'])

    def test_strict_union_types_scope_sets_and_fixed_pins(self):
        cases = [('schema', True), ('schema', 1.0), ('state', 'ready'), ('scope', 'production'),
                 ('blocked_reason', None), ('historical_core_commit', 'b'*40)]
        for key, value in cases:
            lock = A.read_lock(); lock[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(A.Rejected): A.validate(lock)
        for state in ('blocked', 'admitted'):
            for key in ('id', 'repository_id'):
                for value in (True, -1, 0, 2**63, '123'):
                    lock = A.read_lock() if state == 'blocked' else admitted()
                    lock['release'][key] = value
                    with self.subTest(state=state,key=key,value=value), self.assertRaises(A.Rejected): A.validate(lock)
            for key in ('id','name','bytes','sha256','origin','admission_path'):
                lock = A.read_lock() if state == 'blocked' else admitted()
                lock['assets']['decoder'][key] = True
                with self.subTest(state=state,key=key), self.assertRaises(A.Rejected): A.validate(lock)
        for change in ('extra', 'missing', 'duplicate-id', 'tag-object', 'repository'):
            lock = admitted()
            if change == 'extra': lock['assets']['extra'] = lock['assets']['decoder']
            if change == 'missing': del lock['assets']['decoder-provenance']
            if change == 'duplicate-id': lock['assets']['abi']['id'] = lock['assets']['decoder']['id']
            if change == 'tag-object': lock['release']['tag_object']['type'] = 'tag'
            if change == 'repository': lock['release']['repository'] = 'other/repo'
            with self.subTest(change=change), self.assertRaises(A.Rejected): A.validate(lock)
        with self.assertRaises(A.Rejected): A.P.parse_json(b'{"schema":1,"schema":1}')
        records, *rest = A.context()
        records['decoder']['bytes'] += 1
        with patch.object(A, 'context', return_value=(records,*rest)), self.assertRaises(A.Rejected):
            A.validate(admitted())

    def test_blocked_fetch_rejects_before_network_output_or_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(A.subprocess,'Popen', side_effect=AssertionError('process')):
            output = Path(temporary)/'absent'
            fixture = Fixture()
            with self.assertRaises(A.Rejected): A.fetch(A.read_lock(),'decoder-abi',output,fixture)
            self.assertEqual(fixture.calls,[])
            self.assertFalse(output.exists())
        result = subprocess.run([sys.executable,'-B',str(ROOT/'scripts/fetch-weather-archive.py'),'validate'],
                                capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(json.loads(result.stdout)['eligible'])
        for flag in ('--allow-blocked','--repo-root','--lock','--hostname','--url'):
            result = subprocess.run([sys.executable,'-B',str(ROOT/'scripts/fetch-weather-archive.py'),'fetch',
                '--consumer','decoder-abi','--output','/uncreated/archive',flag,'x'],capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0)


class ArchiveExtraction(unittest.TestCase):
    def test_all_four_role_mappings_actual_bytes_private_modes_and_no_execution(self):
        for consumer, mapping in A.CONSUMERS.items():
            fixture = Fixture()
            with self.subTest(consumer=consumer), tempfile.TemporaryDirectory() as temporary, fixture.active(), \
                    patch.object(A.subprocess,'Popen',side_effect=AssertionError('archive execution')):
                output = Path(temporary)/'inputs'
                report = A.fetch(fixture.lock,consumer,output,fixture)
                self.assertEqual(set(p.name for p in output.iterdir()), set(mapping)|{'provenance'})
                self.assertEqual(report['runtime_executed'],False)
                self.assertEqual(report['received_zips'].keys(),set(mapping.values()))
                self.assertFalse(report['current_origin_acquisition_proven'])
                self.assertFalse(report['joined_delivery_proven'])
                self.assertEqual(json.loads((output/'provenance/archive-report.json').read_bytes()),report)
                self.assertNotIn(str(output),json.dumps(report))
                for path in [output,*output.rglob('*')]:
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700 if path.is_dir() else 0o600)
                for directory in mapping:
                    self.assertEqual((output/directory/'dir/NOTICE').read_bytes(),b'Original notice\n')
                self.assertTrue(all('/actions/' not in call for call in fixture.calls))

    def test_bad_bytes_and_transport_failure_cleanup_no_success(self):
        for role in ('preservation-manifest','snapshot-android-v6','decoder','abi'):
            for failure in ('corrupt','fail_role'):
                fixture = Fixture(); setattr(fixture,failure,role)
                with self.subTest(role=role,failure=failure), tempfile.TemporaryDirectory() as temporary, fixture.active():
                    output=Path(temporary)/'inputs'
                    with self.assertRaises(A.Rejected): A.fetch(fixture.lock,'android-v6',output,fixture)
                    self.assertFalse(output.exists())

    def test_refuses_preexisting_symlink_insecure_parent_or_partial_root(self):
        for failure in ('existing','symlink','unsafe-parent','partial'):
            fixture = Fixture()
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, fixture.active():
                parent=Path(temporary); output=parent/'inputs'
                if failure in ('existing','partial'): output.mkdir(); (output/'preserved').write_bytes(b'keep')
                if failure=='symlink': output.symlink_to(parent,target_is_directory=True)
                if failure=='unsafe-parent': parent.chmod(0o777)
                with self.assertRaises((A.Rejected,OSError)): A.fetch(fixture.lock,'decoder-abi',output,fixture)
                if failure in ('existing','partial'): self.assertEqual((output/'preserved').read_bytes(),b'keep')
                parent.chmod(0o700)

    def test_actual_inspector_rejects_unsafe_paths_collisions_links_crc_and_caps(self):
        cases = [[(name,b'x',stat.S_IFREG|0o600)] for name in
            ('../outside','/absolute','x//y','x\\y','x/./y','x\x00y','x\x7fy')]
        cases += [[('link',b'/etc/passwd',stat.S_IFLNK|0o777)], [('pipe',b'',stat.S_IFIFO|0o600)],
            [('same',b'1',stat.S_IFREG|0o600),('same',b'2',stat.S_IFREG|0o600)],
            [('x',b'1',stat.S_IFREG|0o600),('x/y',b'2',stat.S_IFREG|0o600)]]
        for members in cases:
            fixture = Fixture(members)
            with self.subTest(members=members), tempfile.TemporaryDirectory() as temporary, fixture.active():
                output=Path(temporary)/'inputs'
                with self.assertRaises((A.Rejected,zipfile.BadZipFile)): A.fetch(fixture.lock,'decoder-abi',output,fixture)
                self.assertFalse(output.exists())
        for limit in ('MAX_MEMBERS','MAX_MEMBER','MAX_EXPANDED','MAX_ZIP'):
            fixture=Fixture()
            with tempfile.TemporaryDirectory() as temporary, fixture.active(), patch.object(A.P,limit,0):
                with self.assertRaises(A.Rejected): A.fetch(fixture.lock,'decoder-abi',Path(temporary)/'inputs',fixture)

    def test_inspector_checks_actual_crc_and_cleanup_on_extraction_interruption(self):
        fixture=Fixture()
        with tempfile.TemporaryDirectory() as temporary, fixture.active(), patch.object(A,'extract',side_effect=A.Rejected('interrupted')):
            output=Path(temporary)/'inputs'
            with self.assertRaises(A.Rejected): A.fetch(fixture.lock,'decoder-abi',output,fixture)
            self.assertFalse(output.exists())
        raw=bytearray(zip_bytes()); raw[40]^=1
        with tempfile.TemporaryFile() as stream:
            stream.write(raw);stream.flush()
            with self.assertRaises((A.Rejected,zipfile.BadZipFile)):
                A.P.inspect_zip(stream.fileno(),dict(bytes=len(raw),sha256=A.P.sha256(raw)))


if __name__=='__main__': unittest.main()
