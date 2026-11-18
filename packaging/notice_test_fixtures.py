# SPDX-License-Identifier: GPL-3.0-only
"""Complete synthetic Cargo graph for focused notice-collector fixtures only."""


def graph_fixture(packages):
    root_id = 'synthetic notice workspace 0.0.0'
    root = dict(id=root_id, name='notice-test-workspace', version='0.0.0',
                source=None, license='GPL-3.0-only', license_file=None,
                manifest_path='/synthetic-notice-workspace/Cargo.toml')
    ids = [p['id'] for p in packages]
    nodes = [dict(id=root_id, dependencies=ids,
                  deps=[dict(name='fixture_' + str(i), pkg=value, dep_kinds=[])
                        for i, value in enumerate(ids)], features=[])]
    nodes.extend(dict(id=value, dependencies=[], deps=[], features=[]) for value in ids)
    return dict(packages=[root] + packages, workspace_members=[root_id],
                resolve=dict(root=None, nodes=nodes))
