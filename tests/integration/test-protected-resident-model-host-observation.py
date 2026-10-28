#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure byte/metadata fixtures and mocked reads; never capture development-host state."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name('protected-resident-model-host-observation.py')
SPEC = importlib.util.spec_from_file_location('resident_host_observation',SOURCE)
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def route(**changes):
    fields = dict(destination='0'*32,destination_prefix='00',source='0'*32,source_prefix='00',
        gateway='0'*32,metric='00000001',reference='00000001',use='00000000',flags='00000001',device='lo')
    fields.update(changes)
    fields['device'] = fields['device'].rjust(8)
    return ('{destination} {destination_prefix} {source} {source_prefix} {gateway} {metric} '
        '{reference} {use} {flags} {device}\n').format(**fields).encode()


def kernel(release='7.0.0-1017-azure',**changes):
    fields = dict(sysname='Linux',release=release,version='PRIVATE_BUILD_CANARY',machine='x86_64',
        nodename='PRIVATE_HOSTNAME_CANARY')
    fields.update(changes)
    return types.SimpleNamespace(**fields)


class HostObservation(unittest.TestCase):
    def capture(self,raw=None,*,identity=None,ipv4=b'PRIVATE_IPV4_192.0.2.3',resolver=b'PRIVATE_RESOLVER_203.0.113.2'):
        data = {'/proc/net/route':ipv4,'/proc/net/ipv6_route':route() if raw is None else raw,'/etc/resolv.conf':resolver}
        streams = {}
        def path(name):
            stream = mock.Mock()
            value = data[name]
            stream.read.side_effect = value if isinstance(value,Exception) else None
            stream.read.return_value = value
            streams[name] = stream
            opened = mock.MagicMock()
            opened.__enter__.return_value = stream
            return types.SimpleNamespace(open=mock.Mock(return_value=opened))
        with mock.patch.object(H,'Path',side_effect=path) as paths, \
             mock.patch.object(H.os,'uname',return_value=identity or kernel()) as uname:
            snapshot = H.capture()
        self.assertEqual(paths.call_count,3)
        self.assertEqual({call.args[0] for call in paths.call_args_list},set(data))
        uname.assert_called_once_with()
        for stream in streams.values(): stream.read.assert_called_once_with(H.FILE_BYTES+1)
        return snapshot

    def test_same_reads_supply_legacy_raw_and_projection_hashes_without_private_bytes(self):
        snapshot = self.capture()
        H.validate(snapshot)
        self.assertTrue(H.complete(snapshot))
        self.assertEqual(H.hashes(snapshot)['/proc/net/ipv6_route'],hashlib.sha256(route()).hexdigest())
        self.assertEqual(snapshot['ipv6']['raw'],snapshot['files']['ipv6_routes']['fingerprint'])
        text = json.dumps(snapshot)
        for private in ('PRIVATE_', '192.0.2.3','203.0.113.2',route().decode(), 'nodename'):
            self.assertNotIn(private,text)
        self.assertLess(len(text),8192)

    def test_reference_only_is_diagnostic_and_raw_equality_remains_false(self):
        for release,profile in (('6.8.0-1-generic','linux-6.8-native-seq-v1'),
            ('6.8.0-10-azure','linux-6.8-native-seq-v1'),
            ('6.17.0-1022-azure','linux-6.17-azure-native-seq-v1'),
            ('7.0.0-1017-azure','linux-7.0-azure-native-seq-v1')):
            before = self.capture(identity=kernel(release))
            after = self.capture(route(reference='00000002'),identity=kernel(release))
            self.assertEqual(before['renderer']['profile'],profile)
            comparison = H.compare(before,after)
            self.assertEqual(comparison['classification'],'REFERENCE_METADATA_ONLY')
            self.assertFalse(comparison['raw_equal'])
            self.assertFalse(comparison['acceptance_evidence'])
            self.assertNotEqual(H.hashes(before),H.hashes(after))
            self.assertEqual(before['ipv6']['metadata']['non_refcount'],after['ipv6']['metadata']['non_refcount'])

    def test_identical_supported_snapshots_and_empty_route_tables(self):
        for raw in (b'',route(),route()+route()):
            before = self.capture(raw)
            comparison = H.compare(before,self.capture(raw))
            self.assertEqual(comparison['classification'],'UNCHANGED')
            self.assertTrue(comparison['raw_equal'])
            self.assertEqual(before['ipv6']['metadata']['row_count'],raw.count(b'\n'))

    def test_each_nonreference_field_and_row_order_count_stay_significant(self):
        before = self.capture()
        for field,value in dict(destination='1'*32,destination_prefix='40',source='2'*32,source_prefix='01',
            gateway='3'*32,metric='00000002',use='00000001',flags='00000002',device='eth0').items():
            with self.subTest(field=field):
                comparison = H.compare(before,self.capture(route(**{field:value})))
                self.assertEqual(comparison['classification'],'NON_REFCOUNT_DIFFERENCE')
                self.assertFalse(comparison['raw_equal'])
        other = route(metric='00000002')
        for left,right in ((route()+other,other+route()),(route(),route()+route()),(route()+route(),route())):
            self.assertEqual(H.compare(self.capture(left),self.capture(right))['classification'],'NON_REFCOUNT_DIFFERENCE')

    def test_reference_swaps_in_identical_nonreference_rows_never_establish_route_identity(self):
        row,other = route(),route(reference='00000002')
        comparison = H.compare(self.capture(row+other),self.capture(other+row))
        self.assertEqual(comparison['classification'],'REFERENCE_METADATA_ONLY')
        self.assertFalse(comparison['raw_equal'])
        self.assertEqual(set(comparison),{'schema','diagnostic_only','acceptance_evidence','classification',
            'raw_equal','changed','renderer_equal','ipv6'})

    def test_ipv4_and_resolver_changes_are_retained_even_with_unchanged_ipv6(self):
        before = self.capture()
        for label,options in (('ipv4_routes',dict(ipv4=b'changed')),('resolver',dict(resolver=b'changed'))):
            comparison = H.compare(before,self.capture(**options))
            self.assertEqual(comparison['classification'],'OTHER_COMPONENT_DIFFERENCE')
            self.assertTrue(comparison['changed'][label])
            self.assertFalse(comparison['raw_equal'])
            self.assertEqual(comparison['ipv6']['classification'],'UNCHANGED')

    def test_unknown_row_fields_widths_whitespace_and_prefixes_fail_diagnostic_closed(self):
        raw = route()
        for malformed in (b'\n',raw.rstrip(b'\n'),raw+b'UNKNOWN_PRIVATE_ROW\n',raw.replace(b' ',b'\t',1),
            route(destination_prefix='81'),route(source_prefix='ff'),route(reference='1'),
            route(reference='FFFFFFFF'),route(device='..'),route(device='x'*16),raw.replace(b'\n',b' \n')):
            with self.subTest(raw=malformed):
                snapshot = self.capture(malformed)
                comparison = H.compare(snapshot,snapshot)
                self.assertEqual(comparison['classification'],'PARSE_REJECTED')
                self.assertFalse(comparison['ipv6']['metadata_valid'])
                self.assertIsNone(snapshot['ipv6']['metadata']['non_refcount'])
                self.assertNotIn('UNKNOWN_PRIVATE',json.dumps(snapshot))

    def test_parse_bounds_keep_raw_hash_without_truncated_success(self):
        maximum = H.ipv6_route_snapshot(route()*H.IPV6_ROUTE_ROWS)
        self.assertEqual(maximum['metadata']['row_count'],H.IPV6_ROUTE_ROWS)
        rejected = H.ipv6_route_snapshot(route()*(H.IPV6_ROUTE_ROWS+1))
        self.assertEqual(rejected['metadata']['error'],'IPV6_ROUTE_ROW_BOUND')
        for value in (None,True,'PRIVATE',bytearray(b'PRIVATE'),b'x'*(H.IPV6_ROUTE_BYTES+1)):
            with self.assertRaises(ValueError): H.ipv6_route_snapshot(value)
        snapshot = self.capture(b'x'*(H.FILE_BYTES+1))
        self.assertFalse(H.complete(snapshot))
        self.assertIsNone(H.hashes(snapshot)['/proc/net/ipv6_route'])
        self.assertEqual(H.compare(snapshot,snapshot)['classification'],'CAPTURE_UNAVAILABLE')
        self.assertIsNone(H.compare(snapshot,snapshot)['raw_equal'])

    def test_each_read_failure_is_explicit_and_never_an_empty_hash(self):
        for label,options in (('ipv4_routes',dict(ipv4=OSError('PRIVATE_READ_ERROR'))),
            ('ipv6_routes',dict(raw=OSError('PRIVATE_READ_ERROR'))),
            ('resolver',dict(resolver=OSError('PRIVATE_READ_ERROR')))):
            snapshot = self.capture(**options)
            self.assertEqual(snapshot['files'][label],dict(state='unavailable',error='READ_FAILED',fingerprint=None))
            self.assertFalse(H.complete(snapshot))
            self.assertIsNone(H.hashes(snapshot)[H.FILES[label]])
            comparison = H.compare(snapshot,snapshot)
            self.assertIsNone(comparison['raw_equal'])
            self.assertIsNone(comparison['changed'][label])
            self.assertNotIn('PRIVATE_READ_ERROR',json.dumps(snapshot))

    def test_nearby_and_crossed_profiles_are_not_supported(self):
        for identity in (kernel('7.0.1-1-azure'),kernel('7.0.0-1-generic'),kernel('6.17.0-1-generic'),
            kernel('6.17.1-1-azure'),kernel('6.8.1-1-azure'),kernel('6.8.0-1234567-azure'),
            kernel('7.0.0-1-azure',sysname='Other'),kernel('7.0.0-1-azure',machine='aarch64')):
            snapshot = self.capture(identity=identity)
            self.assertEqual(snapshot['renderer']['state'],'unsupported')
            self.assertIsNone(snapshot['renderer']['profile'])
            self.assertEqual(H.compare(snapshot,snapshot)['classification'],'RENDERER_UNSUPPORTED')
            self.assertIsNone(H.compare(snapshot,snapshot)['ipv6'])
        snapshot = self.capture()
        snapshot['renderer']['profile'] = 'linux-6.17-azure-native-seq-v1'
        self.assertEqual(H.compare(snapshot,snapshot)['classification'],'METADATA_REJECTED')

    def test_kernel_build_text_is_hashed_and_changed_identity_never_qualifies_reference_only(self):
        before = self.capture()
        after = self.capture(route(reference='00000002'),identity=kernel(version='OTHER_PRIVATE_BUILD'))
        comparison = H.compare(before,after)
        self.assertEqual(comparison['classification'],'KERNEL_IDENTITY_DIFFERENCE')
        self.assertFalse(comparison['renderer_equal'])
        self.assertIsNone(comparison['ipv6'])
        self.assertNotIn('OTHER_PRIVATE_BUILD',json.dumps(after))

    def test_identity_errors_are_closed_and_do_not_become_supported(self):
        for identity in (kernel(version=''),kernel(release='x'*129),kernel(sysname='x'*17),
            kernel(machine='x'*33),kernel(version='x'*257),kernel(version='private\nline'),kernel(version=True)):
            snapshot = self.capture(identity=identity)
            self.assertEqual(snapshot['renderer'],dict(state='unavailable',profile=None,kernel=None,error='KERNEL_IDENTITY_INVALID'))
            self.assertEqual(H.compare(snapshot,snapshot)['classification'],'RENDERER_UNSUPPORTED')
        with mock.patch.object(H.os,'uname',side_effect=OSError('PRIVATE_UNAME_ERROR')):
            self.assertEqual(H.renderer(),dict(state='unavailable',profile=None,kernel=None,error='KERNEL_CAPTURE_FAILED'))

    def test_unknown_missing_boolean_and_inconsistent_metadata_are_rejected(self):
        before = self.capture()
        cases = []
        for container,key in (((), 'unknown'),(('files',),'unknown'),(('files','resolver'),'unknown'),
            (('renderer',),'unknown'),(('renderer','kernel'),'unknown'),(('ipv6',),'unknown'),
            (('ipv6','metadata'),'unknown')):
            value = copy.deepcopy(before); current=value
            for part in container: current=current[part]
            current[key] = True; cases.append(value)
        for key in before:
            value=copy.deepcopy(before);del value[key];cases.append(value)
        for path in (('schema',),('ipv6','metadata','schema'),('ipv6','metadata','row_count'),
            ('files','resolver','fingerprint','bytes')):
            value=copy.deepcopy(before);current=value
            for part in path[:-1]:current=current[part]
            current[path[-1]]=True;cases.append(value)
        value=copy.deepcopy(before);value['ipv6']['raw']['sha256']='f'*64;cases.append(value)
        for value in cases:
            comparison = H.compare(before,value)
            self.assertEqual(comparison['classification'],'METADATA_REJECTED')
            self.assertIsNone(comparison['raw_equal'])
            self.assertTrue(all(item is None for item in comparison['changed'].values()))


    def test_configuration_checkpoint_admits_only_supported_exact_or_reference_only(self):
        for release in ('6.8.0-1-generic','6.8.0-10-azure','6.17.0-1022-azure','7.0.0-1017-azure'):
            for raw in (b'',route(),route()+route()):
                before=self.capture(raw,identity=kernel(release))
                value=H.configuration_checkpoint(before,copy.deepcopy(before))
                self.assertEqual(value,dict(version=1,mode='supported_ipv6_reference_metadata_v1',
                    eligible=True,classification='UNCHANGED',raw_equal=True))
            before=self.capture(route()+route(),identity=kernel(release))
            after=self.capture(route(reference='00000002')+route(reference='00000003'),identity=kernel(release))
            value=H.configuration_checkpoint(before,after)
            self.assertTrue(value['eligible']);self.assertFalse(value['raw_equal'])
            self.assertEqual(value['classification'],'REFERENCE_METADATA_ONLY')
            self.assertFalse(H.compare(before,after)['acceptance_evidence'])
            self.assertFalse(H.compare(before,after)['raw_equal'])
            self.assertNotEqual(H.hashes(before),H.hashes(after))
            for private in ('PRIVATE','192.0.2.3','203.0.113.2','device','release'):
                self.assertNotIn(private,json.dumps(value))

    def test_configuration_checkpoint_rejects_every_nonreference_change_order_count_and_other_file(self):
        before=self.capture()
        for field,value in dict(destination='1'*32,destination_prefix='40',source='2'*32,source_prefix='01',
            gateway='3'*32,metric='00000002',use='00000001',flags='00000002',device='eth0').items():
            self.assertFalse(H.configuration_checkpoint(before,self.capture(route(**{field:value})))['eligible'])
        other=route(metric='00000002')
        for left,right in ((route()+other,other+route()),(route(),route()+route()),(route()+route(),route()),(b'',route())):
            self.assertFalse(H.configuration_checkpoint(self.capture(left),self.capture(right))['eligible'])
        for kwargs in (dict(ipv4=b'changed'),dict(resolver=b'changed')):
            self.assertFalse(H.configuration_checkpoint(before,self.capture(**kwargs))['eligible'])

    def test_configuration_checkpoint_rejects_unknown_crossed_and_full_renderer_changes_even_raw_equal(self):
        before=self.capture(identity=kernel('6.17.0-1022-azure'))
        for identity in (kernel('6.17.1-1-azure'),kernel('6.17.0-1-generic'),kernel('7.0.0-1-azure'),
            kernel('6.17.0-1023-azure'),kernel('6.17.0-1022-azure',version='OTHER'),
            kernel('6.17.0-1022-azure',machine='aarch64'),kernel('6.17.0-1022-azure',sysname='Other')):
            after=self.capture(identity=identity)
            self.assertEqual(H.hashes(before),H.hashes(after))
            self.assertFalse(H.configuration_checkpoint(before,after)['eligible'])
        for release in ('UNKNOWN','7.0.0-1-generic'):
            snapshot=self.capture(identity=kernel(release))
            self.assertFalse(H.configuration_checkpoint(snapshot,snapshot)['eligible'])
        crossed=copy.deepcopy(before);crossed['renderer']['profile']='linux-7.0-azure-native-seq-v1'
        self.assertFalse(H.configuration_checkpoint(crossed,crossed)['eligible'])

    def test_configuration_checkpoint_rejects_missing_extra_bool_and_inconsistent_fingerprints(self):
        before=self.capture();variants=[None,True,[],{},'PRIVATE_ERROR']
        containers=[(),('files',),('renderer',),('renderer','kernel'),('ipv6',),('ipv6','metadata')]
        containers += [('files',name) for name in H.FILES]
        containers += [('files',name,'fingerprint') for name in H.FILES]
        containers += [('ipv6',name) for name in ('raw',)]
        containers += [('ipv6','metadata',name) for name in ('non_refcount','reference_metadata')]
        for path in containers:
            for operation in ('missing','extra'):
                value=copy.deepcopy(before);target=value
                for key in path:target=target[key]
                if operation=='missing':del target[next(iter(target))]
                else:target['PRIVATE_EXTRA']=True
                variants.append(value)
        for path,new in ((('schema',),True),(('ipv6','metadata','schema'),True),
            (('ipv6','metadata','row_count'),True),(('ipv6','metadata','row_count'),0),
            (('ipv6','metadata','reference_metadata','bytes'),1),
            (('ipv6','metadata','non_refcount','bytes'),0),(('files','resolver','fingerprint','bytes'),True)):
            value=copy.deepcopy(before);target=value
            for key in path[:-1]:target=target[key]
            target[path[-1]]=new;variants.append(value)
        for value in variants:
            for left,right in ((before,value),(value,before)):
                result=H.configuration_checkpoint(left,right)
                self.assertFalse(result['eligible']);self.assertNotIn('PRIVATE',json.dumps(result))

    def test_configuration_checkpoint_rejects_parse_capture_raw_only_and_empty_inconsistency(self):
        before=self.capture()
        for raw in (b'PRIVATE_BAD_ROW',route(destination_prefix='81'),route()*(H.IPV6_ROUTE_ROWS+1),
                    OSError('PRIVATE_CAPTURE_ERROR'),b'x'*(H.FILE_BYTES+1)):
            after=self.capture(raw)
            self.assertFalse(H.configuration_checkpoint(after,after)['eligible'])
        for kwargs in (dict(ipv4=OSError('PRIVATE_READ_ERROR')),dict(resolver=OSError('PRIVATE_READ_ERROR'))):
            after=self.capture(**kwargs)
            self.assertFalse(H.configuration_checkpoint(before,after)['eligible'])
        changed=copy.deepcopy(before)
        changed['ipv6']['raw']['sha256']='f'*64
        changed['files']['ipv6_routes']['fingerprint']['sha256']='f'*64
        self.assertEqual(H.compare(before,changed)['classification'],'RAW_DIFFERENCE')
        self.assertFalse(H.configuration_checkpoint(before,changed)['eligible'])
        empty=self.capture(b'');empty['ipv6']['metadata']['non_refcount']['sha256']='f'*64
        self.assertFalse(H.configuration_checkpoint(empty,empty)['eligible'])



class SourceBindings(unittest.TestCase):
    def test_reused_pure_bodies_and_exact_renderer_profiles_remain_bound(self):
        # Exact source slices from Map hosted.py blob d7e8015f8a0aa26e946e97890adb1259c43167fa,
        # file SHA-256 6cc55f6d28ebe56e7b097e58c4cd0eb9737c46d04e69ce4c53ccb84875ea8b96.
        # ast.dump's empty-field rendering differs between Python 3.12 and 3.13.
        # Bind bytes instead; exclude only the snapshot's adapted docstring expression.
        expected = {'ipv6_route_snapshot':'8fe2a7f986e941e6a770e07fb84d97db4f3c76099ee41478d694caeaefb26c52',
            'ipv6_route_comparison':'dcd6a1bcb19d3bffafedcaf01de833c67a924358ad37befa43b295334edd59bf'}
        def source_digest(raw,name):
            functions = [n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name==name]
            self.assertEqual(len(functions),1)
            node = functions[0]
            rows = raw.splitlines(keepends=True)
            start = min([node.lineno]+[decorator.lineno for decorator in node.decorator_list])-1
            if name=='ipv6_route_snapshot':
                doc = node.body[0]
                self.assertTrue(isinstance(doc,ast.Expr) and isinstance(doc.value,ast.Constant)
                    and type(doc.value.value) is str)
                # Keep the exact prefix/suffix bytes, including any code after the string.
                bound = (b''.join(rows[start:doc.lineno-1])+rows[doc.lineno-1][:doc.col_offset]
                    +rows[doc.end_lineno-1][doc.end_col_offset:]+b''.join(rows[doc.end_lineno:node.end_lineno]))
            else:
                bound = b''.join(rows[start:node.end_lineno])
            return hashlib.sha256(bound).hexdigest()
        raw = SOURCE.read_bytes()
        for name,digest in expected.items():
            self.assertEqual(source_digest(raw,name),digest)
        contextual = raw.replace(b'Hash one bounded proc snapshot;',b'Contextual wording only;',1)
        self.assertNotEqual(contextual,raw)
        self.assertEqual(source_digest(contextual,'ipv6_route_snapshot'),expected['ipv6_route_snapshot'])
        mutations = (
            ('ipv6_route_snapshot',b'len(rows) <= IPV6_ROUTE_ROWS',b'len(rows) < IPV6_ROUTE_ROWS'),
            ('ipv6_route_snapshot',b'def ipv6_route_snapshot(raw):',b'def ipv6_route_snapshot(raw=None):'),
            ('ipv6_route_snapshot',b'match.span("reference")',b'match.span("device")'),
            ('ipv6_route_snapshot',b'def ipv6_route_snapshot(raw):',b'@changed\ndef ipv6_route_snapshot(raw):'),
            ('ipv6_route_snapshot',b'    """\n    require(type(raw)',b'    """; changed()\n    require(type(raw)'),
            ('ipv6_route_comparison',b'before["raw"] != after["raw"]',b'before["raw"] == after["raw"]'),
            ('ipv6_route_comparison',b'"REFERENCE_METADATA_ONLY"',b'"UNCHANGED"'),
            ('ipv6_route_comparison',b'if valid else None',b'if valid else False'),
            ('ipv6_route_comparison',b'Closed fingerprints only;',b'Changed comparison docstring;'))
        for name,before,after in mutations:
            with self.subTest(function=name,mutation=before):
                node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name==name)
                rows=raw.splitlines(keepends=True)
                prefix=b''.join(rows[:node.lineno-1]);body=b''.join(rows[node.lineno-1:node.end_lineno]);suffix=b''.join(rows[node.end_lineno:])
                self.assertEqual(body.count(before),1)
                self.assertNotEqual(source_digest(prefix+body.replace(before,after,1)+suffix,name),expected[name])
        self.assertEqual(H.IPV6_ROUTE_RENDERER_PROFILES,{
            'linux-6.8-native-seq-v1':r'6\.8\.0-[0-9]{1,6}-(?:generic|azure)',
            'linux-6.17-azure-native-seq-v1':r'6\.17\.0-[0-9]{1,6}-azure',
            'linux-7.0-azure-native-seq-v1':r'7\.0\.0-[0-9]{1,6}-azure'})

    def test_source_gate_keeps_six_paths_dependencies_and_no_actual_trial_authority(self):
        for branch,scope in (('refs/heads/fix/model-host-observation-20261022','host_observation_scope'),
            ('refs/heads/fix/resident-host-config-20261023','host_configuration_scope')):
            self.check_source_gate(branch,scope)

    def check_source_gate(self,branch,scope):
        import textwrap
        workflow = (SOURCE.parents[2]/'.github/workflows/protected-resident-model.yml').read_text()
        code = textwrap.dedent(workflow.split("python3 -B - <<'PY'\n",1)[1].split('\n          PY',1)[0])
        branch = branch
        gate = next(n for n in ast.parse(code).body if isinstance(n,ast.If) and repr(branch) in ast.unparse(n.test))
        compiled = compile(ast.Module(body=[gate],type_ignores=[]),'inert-host-observation-source-gate','exec')
        allowed = {'.github/workflows/protected-resident-model.yml','THIRD_PARTY_LICENSES.md',
            'tests/integration/protected-resident-model-run.py','tests/integration/test-protected-resident-model-run.py',
            'tests/integration/protected-resident-model-host-observation.py',
            'tests/integration/test-protected-resident-model-host-observation.py'}
        original = workflow.encode()
        for defect in (None,'missing','extra','duplicate','dependency','actual-job','ancestry'):
            changed = sorted(allowed)
            if defect=='missing':changed.pop()
            if defect=='extra':changed.append('unrelated.rs')
            if defect=='duplicate':changed[-1]=changed[0]
            def git(*args):
                if args[0]=='diff':return '\n'.join(changed)
                if args[0]=='rev-parse':return 'different' if defect=='dependency' and args[1]=='HEAD:Cargo.lock' else 'same'
                self.fail(args)
            namespace = dict(os=types.SimpleNamespace(environ={'GITHUB_REF':branch}),git=git,hashlib=hashlib,
                subprocess=types.SimpleNamespace(check_output=lambda _:original,
                    run=mock.Mock(side_effect=AssertionError('ancestry') if defect=='ancestry' else None)),
                pathlib=types.SimpleNamespace(Path=lambda _:types.SimpleNamespace(
                    read_bytes=lambda:original+(b'changed' if defect=='actual-job' else b''))))
            if defect:
                with self.assertRaises(AssertionError,msg=defect):exec(compiled,namespace)
            else:
                exec(compiled,namespace)
                self.assertEqual(set(namespace[scope]['source_blobs']),allowed)
                self.assertEqual(len(namespace[scope]['dependency_blobs']),17)
                self.assertTrue(namespace[scope]['source_contracts_only'])
                self.assertEqual(namespace[scope]['base_commit'],
                    'ce438c27df80cdba46e990b157b3e5c52e94543c' if scope=='host_configuration_scope'
                    else 'e4824ae3c9a3f606a6013540461f5d148e3a76b6')
                if scope=='host_configuration_scope':
                    self.assertEqual(namespace[scope]['checkpoint_mode'],'supported_ipv6_reference_metadata_v1')
                    self.assertNotIn('strict_raw_equality_unchanged',namespace[scope])
                self.assertFalse(namespace[scope]['historical_cause_proven'])
                self.assertFalse(namespace[scope]['actual_model_execution'])
        for job in ('contracts','public-model'):
            condition = workflow.split('\n  '+job+':\n',1)[1].split('    if: >-\n',1)[1].split('\n    runs-on:',1)[0]
            expression = ' '.join(condition.splitlines()).replace('&&',' and ').replace('||',' or ').strip()
            for event in ('push','pull_request','workflow_dispatch'):
                for scenario in ('source-contracts','public-model'):
                    context = dict(github=types.SimpleNamespace(repository='VOLPAROSSA/volparossa',ref=branch,event_name=event),
                        inputs=types.SimpleNamespace(scenario=scenario))
                    self.assertEqual(eval(expression,context),job=='contracts' and event=='workflow_dispatch' and scenario=='source-contracts')


if __name__ == '__main__':
    unittest.main()
