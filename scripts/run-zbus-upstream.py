#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Original zbus tests in an isolated hosted-only graph; no product feature change."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE = runpy.run_path(str(ROOT / 'scripts/run-ctutils-hosted.py'))
SHA = 'fcff5faa63a63d5b81051740f7382017f10b3440b3f401d97f0cf0b3b39c62d9'
LOCK_SHA = '251467a1767ef3aeeced3a709169792c1395962148fa57254f9329803481cb9f'
VCS = dict(git=dict(sha1='90b4de2d6fa7d7f5b0cb8dd955709d3e765fd2b2'), path_in_vcs='zbus')
FEATURES = 'tokio,proxy,p2p'
TESTS = tuple('message::builder::tests::' + name for name in ('strings','typed_values','a_later_valid_call_keeps_the_first_error','raw')) + (
    'message::tests::test',) + tuple('connection::builder::tests::' + name for name in (
    'strings','typed_values','a_later_valid_call_keeps_the_first_error')) + tuple(
    'proxy::method_flags_tests::' + name for name in ('method_flags_convert_to_header_flags',
    'method_flags_convert_from_borrowed_value','method_flags_signature_and_debug')) + tuple(
    'connection::handshake::tests::' + name for name in ('handshake','holding_sockets'))


def admission(env, revision):
    if (env.get('GITHUB_ACTIONS') != 'true' or env.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or env.get('GITHUB_REPOSITORY') != 'VOLPAROSSA/volparossa'
            or env.get('RUNNER_OS') != 'Linux' or env.get('RUNNER_ARCH') != 'X64'
            or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or not re.fullmatch('[0-9a-f]{40}', revision)
            or any(env.get(k) != revision for k in ('GITHUB_SHA','GITHUB_WORKFLOW_SHA','ZBUS_CORE_REVISION'))):
        raise ValueError('requires exact assigned hosted zbus source')


def original_files(raw, lock):
    selected = [x for x in lock['package'] if x['name'] == 'zbus']
    if len(selected) != 1 or selected[0]['version'] != '6.1.0' or selected[0]['checksum'] != SHA:
        raise ValueError('root zbus lock binding')
    if not 0 < len(raw) <= 4 * 1024**2 or hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original zbus archive checksum')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as source: expanded=source.read(16 * 1024**2 + 1)
    if len(expanded)>16*1024**2: raise ValueError('zbus archive bound')
    files={}
    with tarfile.open(fileobj=io.BytesIO(expanded),mode='r:') as archive:
        for entry in archive:
            path=Path(entry.name)
            if (not entry.isfile() or entry.linkname or path.is_absolute() or '..' in path.parts
                    or path.parts[0]!='zbus-6.1.0' or str(path) in files or len(files)>=1024):
                raise ValueError('unsafe zbus member')
            files[str(path)]=archive.extractfile(entry).read()
    if (hashlib.sha256(files['zbus-6.1.0/Cargo.lock']).hexdigest()!=LOCK_SHA
            or json.loads(files['zbus-6.1.0/.cargo_vcs_info.json'])!=VCS):
        raise ValueError('original zbus VCS/lock')
    return files


def selected_inventory(text):
    names=re.findall(r'^([^\n]+): test$',text,re.M)
    if len(names)!=len(set(names)) or not set(TESTS)<=set(names):
        raise ValueError('selected original upstream tests absent or cfg-disabled')
    return names


def execute():
    revision=NATIVE['subprocess'].check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    admission(os.environ,revision)
    if os.getuid()==0: raise ValueError('zbus proof must be unprivileged')
    temporary=Path(os.environ['RUNNER_TEMP'])
    output=temporary/'zbus-upstream-proof';output.mkdir(mode=0o700)
    private=temporary/'zbus-upstream-private';private.mkdir(mode=0o700)
    receipt=dict(schema=1,revision=revision,archive_sha256=SHA,original_lock_sha256=LOCK_SHA,
        vcs=VCS,features=FEATURES,selected_tests=TESTS,success=False,production_p2p_proven=False,
        product_features='tokio,proxy',service_enabled=False,default_rt_enabled=False)
    safe=True
    env=dict(os.environ,CARGO_HOME=str(private/'cargo-home'),CARGO_TARGET_DIR=str(private/'target'))
    previous={n:signal.signal(n,NATIVE['interrupted']) for n in (signal.SIGINT,signal.SIGTERM)}
    try:
        with urllib.request.urlopen('https://static.crates.io/crates/zbus/zbus-6.1.0.crate',timeout=60) as response:
            raw=response.read(4*1024**2+1)
        files=original_files(raw,tomllib.loads((ROOT/'Cargo.lock').read_text()))
        for name,data in files.items():
            path=private/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as stream:stream.write(data)
        source=private/'zbus-6.1.0'
        def run(args,log,timeout):
            nonlocal safe
            with log.open('ab') as stream:
                safe=False
                try:
                    NATIVE['run_owned'](args,cwd=source,env=env,stream=stream,timeout=timeout)
                except NATIVE['GROUP']['CleanupUnconfirmed']:
                    raise
                except BaseException:
                    safe=True;raise
                safe=True
            if log.stat().st_size>16*1024**2:raise ValueError('upstream zbus diagnostic bound')
        cargo=['cargo']
        run(cargo+['fetch','--locked'],output/'zbus-upstream-fetch.log',300)
        command=cargo+['test','--locked','--offline','--lib','--no-default-features','--features',FEATURES]
        listing=output/'zbus-upstream-inventory.log'
        run(command+['--','--list'],listing,600)
        receipt['observed_inventory']=selected_inventory(listing.read_text())
        for name in TESTS:
            # Exactly one named test must actually pass; filtered or zero-test success fails.
            log=output/'one-test.log'
            run(command+[name,'--','--exact','--test-threads=1'],log,90)
            text=log.read_text()
            if not re.search(r'^test '+re.escape(name)+r' \.\.\. ok$',text,re.M) or not re.search(
                    r'^test result: ok\. 1 passed; 0 failed; 0 ignored;',text,re.M):
                raise ValueError('original upstream test did not execute')
            with (output/'zbus-upstream-tests.log').open('ab') as stream:stream.write(log.read_bytes())
            log.unlink()
        if any((private/name).read_bytes()!=data for name,data in files.items()):
            raise ValueError('original upstream source/lock changed')
        receipt.update(success=True,tests_passed=len(TESTS))
    finally:
        for number,handler in previous.items():signal.signal(number,handler)
        receipt['process_group_cleanup_confirmed']=safe
        receipt['private_graph_removed']=False
        if safe:
            shutil.rmtree(private);receipt['private_graph_removed']=True
        (output/'zbus-upstream-source.log').write_text(json.dumps(receipt,sort_keys=True)+'\n')


if __name__=='__main__':execute()
