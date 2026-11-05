#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert Cargo resolve-ID closure and collector contract tests; no Cargo."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from notice_test_fixtures import graph_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('notice_closure', ROOT / 'packaging/cargo-notice-closure.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def package(identifier):
    return dict(id=identifier, name=identifier, version='1.0.0', license='MIT',
                source='registry+https://github.com/rust-lang/crates.io-index',
                license_file=None, manifest_path='/fixture/' + identifier + '/Cargo.toml')


class ClosureTests(unittest.TestCase):
    def fixture(self):
        return graph_fixture([package('reachable opaque ID')])

    def test_unreachable_definition_and_node_are_excluded(self):
        metadata = self.fixture()
        metadata['packages'].append(package('unreachable'))
        # Cargo may retain package definitions outside its filtered resolve graph.
        self.assertNotIn('unreachable', {p['id'] for p in MODULE.select_closure(metadata)['packages']})
        metadata['resolve']['nodes'].append(dict(id='unreachable', dependencies=[], deps=[]))
        self.assertNotIn('unreachable', {n['id'] for n in MODULE.select_closure(metadata)['resolve']['nodes']})

    def test_all_workspace_roots_and_transitive_edges_are_retained(self):
        metadata = self.fixture()
        root = copy.deepcopy(metadata['packages'][0])
        root['id'] = 'second root'
        metadata['workspace_members'].append(root['id'])
        metadata['packages'].extend([root, package('transitive')])
        metadata['resolve']['nodes'].extend([
            dict(id='second root', dependencies=['transitive'], deps=[dict(pkg='transitive')]),
            dict(id='transitive', dependencies=['second root'], deps=[dict(pkg='second root')])])
        self.assertEqual({p['id'] for p in MODULE.select_closure(metadata)['packages']},
                         {p['id'] for p in metadata['packages']})

    def test_malformed_graphs_fail_closed(self):
        original = self.fixture()
        mutations = []
        def add(label, mutation):
            value = copy.deepcopy(original)
            mutation(value)
            mutations.append((label, value))
        add('missing resolve', lambda m: m.pop('resolve'))
        add('missing roots', lambda m: m.pop('workspace_members'))
        add('empty roots', lambda m: m.update(workspace_members=[]))
        add('duplicate roots', lambda m: m['workspace_members'].append(m['workspace_members'][0]))
        add('missing root source', lambda m: m['packages'][0].pop('source'))
        add('registry root', lambda m: m['packages'][0].update(source='registry+unreviewed'))
        add('unknown root', lambda m: m['workspace_members'].append('unknown'))
        add('duplicate package', lambda m: m['packages'].append(m['packages'][0]))
        add('missing package ID', lambda m: m['packages'][1].pop('id'))
        add('invalid package ID', lambda m: m['packages'][1].update(id=123))
        add('control in ID', lambda m: m['packages'][1].update(id='bad\nID'))
        add('duplicate node', lambda m: m['resolve']['nodes'].append(m['resolve']['nodes'][0]))
        add('missing reachable node', lambda m: m['resolve']['nodes'].pop())
        add('missing reachable package', lambda m: m['packages'].pop())
        add('missing dependencies', lambda m: m['resolve']['nodes'][0].pop('dependencies'))
        add('missing named edges', lambda m: m['resolve']['nodes'][0].pop('deps'))
        add('inconsistent edges', lambda m: m['resolve']['nodes'][0].update(deps=[]))
        add('unknown reachable dependency', lambda m: m['resolve']['nodes'][0].update(
            dependencies=['unknown'], deps=[dict(pkg='unknown')]))
        add('duplicate edge', lambda m: m['resolve']['nodes'][0]['dependencies'].append('reachable opaque ID'))
        add('foreign resolve root', lambda m: m['resolve'].update(root='reachable opaque ID'))
        for label, value in mutations:
            with self.subTest(label=label), self.assertRaises(MODULE.InvalidGraph):
                MODULE.select_closure(value)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(MODULE.InvalidGraph):
            json.loads('{"packages":[],"packages":[]}', object_pairs_hook=MODULE.no_duplicate_keys)

    def test_unreachable_missing_notice_excluded_reachable_missing_notice_fails(self):
        with tempfile.TemporaryDirectory(prefix='notice-closure-') as temporary:
            base = Path(temporary)
            packages = []
            for name in ('included', 'missing-notice'):
                directory = base / name
                directory.mkdir()
                selected = package(name)
                selected['manifest_path'] = str(directory / 'Cargo.toml')
                packages.append(selected)
                if name == 'included':
                    (directory / 'LICENSE').write_bytes(b'original notice fixture\n')
            metadata = graph_fixture(packages[:1])
            metadata['packages'].append(packages[1])
            for reachable in (False, True):
                if reachable:
                    metadata = graph_fixture(packages)
                source = base / 'metadata.json'
                source.write_text(json.dumps(metadata))
                destination = base / ('reachable' if reachable else 'unreachable')
                result = subprocess.run(['sh', str(ROOT / 'packaging/collect-cargo-licenses.sh'),
                                         str(source), str(destination)], text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, not reachable, result.stderr)
                if reachable:
                    self.assertIn('no distributable top-level license/notice file: missing-notice', result.stderr)
                else:
                    self.assertFalse((destination / 'missing-notice-1.0.0').exists())
                    self.assertIn('included\t1.0.0', (destination / 'DEPENDENCIES.tsv').read_text())

    def test_debian_consumer_preserves_complete_matching_feature_target_graph(self):
        source = (ROOT / 'packaging/build-deb.sh').read_text()
        notice_step = source[source.index('metadata_file=$staging_parent/cargo-metadata.json'):]
        self.assertIn('cargo metadata --locked --offline --all-features', notice_step)
        self.assertIn('--filter-platform x86_64-unknown-linux-gnu --format-version 1 > "$metadata_file"', notice_step)
        self.assertIn('cargo build --locked --release --workspace --all-features', source)
        self.assertNotIn('release_packages', notice_step)
        self.assertNotIn('cargo tree', notice_step)
        self.assertNotIn('.packages |=', notice_step)


if __name__ == '__main__':
    unittest.main()
