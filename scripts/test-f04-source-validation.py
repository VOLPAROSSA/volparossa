#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert source proof fixtures: no Cargo/Rust/native execution."""
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('validation', Path(__file__).with_name('run-f04-source-validation.py'))
V = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(V)


def diagnostic(code='E0308', level='error'):
    return dict(reason='compiler-message', message=dict(level=level, code=dict(code=code) if code else None,
        message='inert', spans=[dict(file_name='crates/inert.rs', line_start=12, is_primary=True)]))


class ValidationTests(unittest.TestCase):
    def test_placeholder_and_host_rejected_before_git_or_writes(self):
        with patch.dict(os.environ, dict(CANDIDATE='0'*40), clear=True), patch.object(V.H, 'git', side_effect=AssertionError('early git')):
            with self.assertRaises(ValueError): V.admit(initial=True)

    def test_strict_only_accepts_actual_zero_exit_and_finished_success(self):
        good=json.dumps(dict(reason='build-finished', success=True))+'\n'
        self.assertTrue(V.strict_result(good,0)['passed'])
        for log,status in [(good,101),('',0),(good+'INVALID',0),(json.dumps(dict(reason='build-finished',success=False)),0),
                           (json.dumps(diagnostic('clippy::inert'))+'\n'+good,0)]:
            with self.subTest(log=log,status=status): self.assertFalse(V.strict_result(log,status)['passed'])

    def test_compiler_errors_and_primary_lints_remain_distinct(self):
        log='\n'.join(json.dumps(item) for item in [diagnostic(),diagnostic(),diagnostic('clippy::inert'),dict(reason='build-finished',success=False)])
        result=V.strict_result(log,101)
        self.assertEqual(result['compiler_error_count'],2)
        self.assertEqual(result['error_count'],3)
        self.assertEqual(len(result['unique_primary_diagnostics']),2)
        self.assertEqual(result['first_compiler_errors'][0]['code']['code'],'E0308')

    def test_preparer_never_nests_full_provision_process_group_tests(self):
        # The unchanged 17+17 profile controls are independently evidenced and
        # remain in normal Quality. Their real descendant groups must never be
        # nested under this preparer's owned Runner process group.
        self.assertNotIn('test-provision-rust189.py', inspect.getsource(V.run))
        self.assertNotIn('test-provision-rust199.py', inspect.getsource(V.run))
        source = inspect.getsource(V.run)
        self.assertIn('H.compiler_authority', source)
        self.assertIn("authority['pre']", source)
        self.assertIn("authority['post']", source)

    def test_recipe_is_exact_fixture_only_six_precise_updates(self):
        recipe=V.expected_recipe()
        self.assertEqual(len(recipe),6)
        self.assertEqual([p['after'] for p in recipe],['1.0.4','0.3.0','0.4.14','0.2.189','3.0.3','1.0.24'])
        for update in recipe:
            self.assertEqual(update['command'][:4],['cargo','update','--manifest-path',V.FIXTURE+'/Cargo.toml'])
            self.assertEqual(update['command'][-2:],['--precise',update['after']])

    def test_mutation_scope_never_accepts_root_or_fuzz_lock_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            path=root/'Cargo.lock';path.write_text('fixed')
            before=V.H.source_index(root)
            path.write_text('mutated')
            with self.assertRaisesRegex(ValueError,'unexpected candidate mutation'):V.stable_source(root,before)

    def test_format_scope_classification(self):
        for name in ('crates/a/src/lib.rs','fuzz/fuzz_targets/parser.rs',V.FIXTURE+'/src/lib.rs'):
            self.assertTrue(V.first_party_rust(name))
        for name in ('third_party/rust/vendor/ctutils-0.4.5/src/lib.rs','Cargo.toml','crates/a/LICENSE','../outside.rs'):
            self.assertFalse(V.first_party_rust(name))

    def test_real_git_format_rollback_separates_vendor_and_firstparty(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'source';root.mkdir();evidence=Path(directory)/'evidence';evidence.mkdir()
            names=['crates/a/src/lib.rs','third_party/rust/vendor/ctutils-0.4.5/src/lib.rs','third_party/rust/vendor/sev-8.0.0/LICENSE']
            for name in names:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('original\n')
            for args in [('init','-q'),('add','--all'),('-c','user.name=Inert','-c','user.email=inert@example.invalid','commit','-qm','inert source')]:
                subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True)
            before=V.H.source_index(root)
            calls=[]
            def command(label,args):
                calls.append(label)
                if label=='format-root':
                    for name in names:(root/name).write_text('formatted\n')
            runner=types.SimpleNamespace(command=command,records=[])
            def stable(source,index):
                self.assertEqual(V.H.source_index(source),index)
            with patch.object(V,'stable_source',side_effect=stable):V.format_capture(root,evidence,runner,before)
            record=json.loads((evidence/'format.json').read_text())
            self.assertTrue(record['committed_source_restored'])
            self.assertTrue(record['formatter_scope_blocker'])
            self.assertTrue(record['needs_formatting'])
            self.assertEqual(len(calls),3)
            self.assertIn('crates/a/src/lib.rs',(evidence/'firstparty-format.patch').read_text())
            self.assertNotIn('vendor/',(evidence/'firstparty-format.patch').read_text())
            self.assertIn('ctutils-0.4.5',(evidence/'vendor-format.patch').read_text())
            self.assertIn('LICENSE',(evidence/'unexpected-format.patch').read_text())
            self.assertEqual(V.H.source_index(root),before)

    def test_unconfirmed_format_cleanup_forbids_rollback(self):
        class CleanupUnconfirmed(RuntimeError): pass
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);evidence=root/'evidence';evidence.mkdir()
            def command(*args):raise CleanupUnconfirmed('inert live descendant')
            runner=types.SimpleNamespace(command=command,records=[dict(cleanup_confirmed=False)],
                                         provision=types.SimpleNamespace(CleanupUnconfirmed=CleanupUnconfirmed))
            with patch.object(V.H,'git',side_effect=AssertionError('unsafe source access')):
                with self.assertRaises(CleanupUnconfirmed):V.format_capture(root,evidence,runner,{})
            record=json.loads((evidence/'format.json').read_text())
            self.assertTrue(record['cleanup_unconfirmed'])
            self.assertFalse(record['committed_source_restored'])

    def test_feature_report_is_not_core_binary_equivalence(self):
        def metadata(extra):
            names=('ctutils','crypto-bigint','p384','hmac','poly1305','sha2')
            return dict(packages=[dict(name=name,version='fixed',source=V.H.REGISTRY,id=name) for name in names],
                        resolve=dict(nodes=[dict(id=name,features=['base']+extra) for name in names]))
        report=V.feature_report(metadata(['root-only']),metadata([]))
        self.assertEqual(len(report['critical_crypto']),6)
        self.assertEqual(len(report['residual_feature_differences']),6)
        self.assertFalse(report['runtime_acceptance'])
        self.assertIn('not an exact Core binary',report['scope'])


if __name__=='__main__':unittest.main()
