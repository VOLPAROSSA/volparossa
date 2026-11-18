#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Select Cargo's resolve-ID closure from every workspace member.

Package IDs are opaque. Cargo has already selected features and target edges;
this helper never interprets cfg expressions, package names, or target triples.
"""
import json
from pathlib import Path
import sys


class InvalidGraph(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise InvalidGraph(reason)


def identifier(value):
    require(isinstance(value, str) and bool(value) and
            not any(ord(c) < 32 or ord(c) == 127 for c in value), 'invalid opaque package ID')
    return value


def unique_ids(values):
    require(isinstance(values, list), 'package IDs must be an array')
    result = [identifier(value) for value in values]
    require(len(result) == len(set(result)), 'duplicate package ID')
    return result


def definitions(values, label):
    require(isinstance(values, list), label + ' must be an array')
    result = {}
    for value in values:
        require(isinstance(value, dict) and 'id' in value, label + ' missing ID')
        key = identifier(value['id'])
        require(key not in result, 'duplicate ' + label + ' ID')
        result[key] = value
    return result


def select_closure(metadata):
    require(isinstance(metadata, dict), 'metadata must be an object')
    packages = definitions(metadata.get('packages'), 'package')
    roots = unique_ids(metadata.get('workspace_members'))
    require(bool(roots), 'workspace roots must not be empty')
    resolve = metadata.get('resolve')
    require(isinstance(resolve, dict), 'complete Cargo resolve graph required')
    nodes = definitions(resolve.get('nodes'), 'resolve node')
    for root in roots:
        require(root in packages and root in nodes, 'workspace root definition missing')
        require('source' in packages[root] and packages[root]['source'] is None,
                'workspace root must be a local package')
    for key, node in nodes.items():
        require(key in packages, 'resolve node package definition missing')
        dependencies = unique_ids(node.get('dependencies'))
        deps = node.get('deps')
        require(isinstance(deps, list), 'complete named dependency edges required')
        named = set()
        for dep in deps:
            require(isinstance(dep, dict) and 'pkg' in dep, 'named dependency missing package ID')
            named.add(identifier(dep['pkg']))
        require(named == set(dependencies), 'dependency edge representations disagree')
        require(all(dep in packages and dep in nodes for dep in dependencies),
                'dependency definition missing')
    root = resolve.get('root')
    require(root is None or identifier(root) in roots, 'resolve root is not a workspace member')
    reached = set()
    pending = list(roots)
    while pending:
        key = pending.pop()
        if key not in reached:
            reached.add(key)
            pending.extend(nodes[key]['dependencies'])
    return dict(metadata, packages=[p for p in metadata['packages'] if p['id'] in reached],
                resolve=dict(resolve, nodes=[n for n in resolve['nodes'] if n['id'] in reached]))


def no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON object key')
        value[key] = item
    return value


def main():
    try:
        require(len(sys.argv) == 2, 'usage: cargo-notice-closure.py METADATA.json')
        metadata = json.loads(Path(sys.argv[1]).read_text(), object_pairs_hook=no_duplicate_keys)
        selected = select_closure(metadata)
        print(json.dumps(selected))
    except (InvalidGraph, OSError, ValueError) as error:
        print('Invalid Cargo notice graph: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
