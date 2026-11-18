#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify an observed source build of the pinned Browser, including its built-in controller."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


CORE_PINS = Path(__file__).with_name('browser-native-pins.json')
BROWSER = 'c3311ebedcc02dc45ff9c9822cee62f091609f86'
FIREFOX = '47c5f402c8d3a5369f1fb1b6cd61b0bb92725af1'
TREE = '4a1d6e73d48bc5888e4da37d655b360a14db18db'
PATCH = '6d87eb3a00275caad042f10e8ebfe14c579a45bb40dab6f4461822cf5e5dffc1'
RUST_REPORT = 'f994b853cae209236bd522735903f66a4a01f5cc8c04632d36aa45449ca367ac'
CONTROLLER = 'VolparossaBrowserNetwork.sys.mjs'
CONTROLLER_SHA = 'fcc7eb622a1ff54e13e7ed40d5625e44f155c03b71fc0af9867bca6334379228'
SOURCE_PREFIX = 'browser/components/genai/'
MODULES = ('VolparossaCompute.sys.mjs', 'VolparossaComputePanel.sys.mjs',
           'VolparossaNetwork.sys.mjs', CONTROLLER)
ASSETS = (*MODULES, 'volparossa-compute.css')
OUTPUTS = {f'obj/dist/bin/{name}' for name in ('firefox', 'libxul.so', 'xpcshell')}


def require(value, description):
    if not value:
        raise ValueError(f'native Browser source build differs: {description}')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def sha_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path):
    require(path.resolve(strict=True) == path and stat.S_ISREG(path.stat().st_mode), 'nonregular input')
    return path


def git(root, *arguments):
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-c', 'core.fsmonitor=false',
        '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', *arguments], cwd=root, env={'PATH': os.defpath, 'LC_ALL': 'C',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0',
        'GIT_NO_LAZY_FETCH': '1'})


def changed_paths(root):
    result = git(root, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--name-only', '-z', 'HEAD')
    result += git(root, 'ls-files', '--others', '--exclude-standard', '-z')
    return set(filter(None, os.fsdecode(result).split('\0')))


def validate_record(record):
    """Validate the portable, path-free provenance returned by validate_build."""
    fixed = dict(kind='native-firefox-source-build', browser_revision=BROWSER, firefox_revision=FIREFOX,
                 firefox_tree=TREE, native_patch_sha256=PATCH, rust_report_sha256=RUST_REPORT,
                 controller_sha256=CONTROLLER_SHA)
    hashes = ('receipt_sha256', 'overlay_sha256', 'plugin_container_sha256')
    require(isinstance(record, dict) and set(record) == set(fixed) | set(hashes) | {'outputs'}
            and all(record[key] == value for key, value in fixed.items()), 'record identity')
    outputs = record['outputs']
    require(isinstance(outputs, dict) and set(outputs) == OUTPUTS, 'native output names')
    for value in [*(record[key] for key in hashes), *outputs.values()]:
        require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'SHA-256')
    return record


def expected_overlay(browser, source):
    """Replay the pinned offline producer transformations on exact pristine Git objects."""
    with tempfile.TemporaryDirectory() as temp:
        pristine = Path(temp)
        for name in ('firefox-source.json', 'firefox-network-ech.json'):
            original = json.loads((browser / 'patches' / name).read_bytes())
            require(original['upstream_revision'] == FIREFOX, 'overlay upstream')
            for relative, expected in original['upstream_sha256'].items():
                data = git(source, 'cat-file', 'blob', f'{FIREFOX}:{relative}')
                require(sha(data) == expected, 'upstream input digest')
                destination = pristine / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        # A fresh isolated interpreter imports only from the pinned producer and its reviewed dependencies.
        command = ('import hashlib, json, pathlib, sys; sys.path.insert(0, sys.argv[1]); '
                   'import native_build; print(json.dumps({k: hashlib.sha256(v).hexdigest() '
                   'for k, v in native_build.overlay_files(pathlib.Path(sys.argv[2])).items()}))')
        result = subprocess.check_output([sys.executable, '-I', '-B', '-c', command,
                                         str(browser / 'scripts'), str(pristine)])
    return json.loads(result)


def validate_checkout(browser, source):
    require(git(browser, 'rev-parse', 'HEAD').decode().strip() == BROWSER and not changed_paths(browser),
            'Browser checkout')
    require(git(source, 'rev-parse', 'HEAD', 'HEAD^{tree}').decode().splitlines() == [FIREFOX, TREE],
            'Firefox commit and tree')
    pins = json.loads(CORE_PINS.read_bytes())
    require(pins['revision'] == BROWSER, 'Core Browser pin')
    for name, record in pins['files'].items():
        path = regular(browser / name)
        require(path.stat().st_size == record['bytes'] and sha_file(path) == record['sha256'], 'Browser input')
    integration = {}
    for name in ASSETS:
        data = git(browser, 'cat-file', 'blob', f'{BROWSER}:integration/{name}')
        require(regular(browser / 'integration' / name).read_bytes() == data, 'Browser integration input')
        integration[name] = sha(data)
    return integration


def binary_digest(build, name):
    path = (build / name).resolve(strict=True)
    require(path.is_relative_to(build / 'obj') and stat.S_ISREG(path.stat().st_mode), 'native output path')
    with path.open('rb') as stream:
        header = stream.read(20)
    require(header[:6] == b'\x7fELF\x02\x01' and header[16:18] in (b'\x02\x00', b'\x03\x00')
            and header[18:20] == b'\x3e\x00', 'native x86-64 ELF output')
    return sha_file(path)


def validate_build(browser, build):
    """Check the real producer receipt, checkout, staged source, compiled outputs and installed modules."""
    browser, build = Path(browser).absolute(), Path(build).absolute()
    source = build / 'source'
    require(all(path.is_dir() and path == path.resolve(strict=True) for path in (browser, build, source))
            and (browser / 'build') in build.parents, 'build root')
    integration = validate_checkout(browser, source)
    native_pins = json.loads(regular(browser / 'patches/firefox-native-build.json').read_bytes())
    require(native_pins['source']['revision'] == FIREFOX and native_pins['source']['tree'] == TREE
            and native_pins['reused_rust']['report_sha256'] == RUST_REPORT, 'compiler or upstream pins')
    for tool in native_pins['toolchains']:
        archive = regular(build / 'downloads' / (tool['name'] + '.tar.zst'))
        require(archive.stat().st_size == tool['bytes'] and sha_file(archive) == tool['sha256'],
                'compiler archive')
    receipt = regular(build / 'build-result.json').read_bytes()
    report = json.loads(receipt)
    require(report['source'] == native_pins['source'] and report['version'] == 1 and report['jobs'] == 2
            and report['native_build_requested'] is True and report['native_build_proven'] is True
            and report['native_ech_wire_proven'] is False and report['build_network_disabled'] is True
            and report['system_installation'] is False and report['output'] == str(build), 'producer receipt')

    overlay = regular(build / 'overlay.json').read_bytes()
    transformed = expected_overlay(browser, source)
    require(report['overlay'] == json.loads(overlay) == dict(revision=FIREFOX, native_patch_sha256=PATCH,
            files=transformed, integration=integration), 'complete reviewed source transformations')
    require(changed_paths(source) == set(transformed), 'unexpected modified Firefox source')
    for name, expected in transformed.items():
        require(sha_file(regular(source / name)) == expected, 'transformed source bytes')
    for name in MODULES:
        installed = build / 'obj/dist/bin/browser/modules' / name
        original = source / SOURCE_PREFIX / name
        require(installed.resolve(strict=True) == original and transformed[SOURCE_PREFIX + name] == integration[name],
                'installed Browser module')

    require(isinstance(report['outputs'], dict) and set(report['outputs']) == OUTPUTS, 'compiled output inventory')
    outputs = {name: binary_digest(build, name) for name in sorted(OUTPUTS)}
    require(outputs == report['outputs'], 'compiled output digest')
    return validate_record(dict(kind='native-firefox-source-build', browser_revision=BROWSER,
        firefox_revision=FIREFOX, firefox_tree=TREE, native_patch_sha256=PATCH, rust_report_sha256=RUST_REPORT,
        receipt_sha256=sha(receipt), overlay_sha256=sha(overlay), controller_sha256=integration[CONTROLLER],
        outputs=outputs, plugin_container_sha256=binary_digest(build, 'obj/dist/bin/plugin-container')))
