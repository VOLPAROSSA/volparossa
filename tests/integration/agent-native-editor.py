#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual disposable editor UI -> native app-server -> private core/Qwen trial."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
ROOT = Path('/home/vpci/native-editor')
UI = ROOT / 'ui'
PROJECT = UI / 'editor-ui-project-01'
OUTPUT = Path('/home/vpci/alpha-output')
CODE = Path('/home/vpci/code')
RUNTIME = Path('/opt/volparossa-codex-runtime')
EDITOR = Path('/opt/volparossa-editor')
NODE = ROOT / 'runtime/bin/node'
CORE_UNIT = 'volparossa-native-editor-core.service'
EDITOR_UNIT = 'volparossa-native-editor-ui.service'
GIB = 1024 ** 3
CORE_MEMORY, EDITOR_MEMORY = 5 * GIB, 2 * GIB
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
SCOPE = ('actual pinned VSCodium keyboard/mouse UI, native Codex app-server and private '
         'Qwen3-0.6B read/edit/test of one disposable owner-selected project; not general '
         'coding quality, private peer execution, an editor source build or hard-4GiB execution')
EXPORT_NAMES = {'agent-native-editor-smoke.json', 'host-state-before.json', 'host-state-after.json',
                'current-phase', 'guest-exit-status', 'runner.stdout', 'runner.stderr'}
FIXTURE_NAMES = ('agent-native-editor.py', 'agent-native-editor.sh', 'agent-native-editor-pins.json',
                 'native-editor-runtime.py', 'agent-native-coding.py', 'agent-private-conversation.py',
                 'agent-private-conversation-pins.json', 'agent-training-smoke.py')
UI_FAILURES = {'guest_required', 'arguments', 'project_scope', 'output_scope', 'editor_unavailable',
               'cdp_failed', 'ui_unrecognized', 'ui_bound', 'deadline', 'command_refused',
               'editor_failed', 'fixture_failed', 'cleanup_unconfirmed', 'startup_not_ready',
               'palette_unavailable', 'startup_dialog'}
UI_PHASES = {'prepare', 'editor-connect', 'task-input', 'consent', 'native-turn',
             'independent-check', 'complete'}
ORIGINAL_SHA = hashlib.sha256(b'def add(a, b):\n    return a - b\n').hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path, maximum=262144):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'bounded regular report')
    return json.loads(path.read_bytes())


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, allow_nan=False, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def verify_inputs(revision):
    bundle = module('native-editor-runtime')
    target = RUNTIME / 'NATIVE_EDITOR_BUNDLE.json'
    receipt = read(target, bundle.MAX_MANIFEST)
    authority = bundle.authority(revision)
    require(set(receipt) == set(authority) | {'files'}
            and {key: receipt[key] for key in authority} == authority, 'bundle authority')
    bundle.validate_inventory(receipt['files'])
    roots = {'code': CODE, 'runtime': RUNTIME, 'editor': EDITOR}
    for name, row in receipt['files'].items():
        parts = bundle.safe_name(name).parts
        path = roots[parts[0]].joinpath(*parts[1:])
        info = path.lstat()
        require(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
                and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == row['mode']
                and info.st_size == row['bytes'] and digest(path) == row['sha256'], 'staged input differs')
    validator = runpy.run_path(str(CODE / 'scripts/smoke_native_coding.py'))
    provenance = validator['verified_build'](str(RUNTIME / 'BUILD_REPORT.json'),
        RUNTIME / 'runtime/codex-app-server', authority['native']['binary_sha256'])
    require(provenance['source_revision'] == authority['native']['source_revision']
            and provenance['report_sha256'] == authority['native']['build_report_sha256'], 'native source build')
    return dict(authority, receipt_sha256=digest(target), inventory_files=len(receipt['files']))


def ui_receipt(value):
    """Closed projection; no commands, prompts, generated text or private path export."""
    booleans = {'passed', 'start_clicked', 'read', 'edit', 'test', 'independent_test_passed',
        'ui_result_shown', 'runtime_cleanup_confirmed_by_ui', 'cdp_closed', 'synthetic_model',
        'private_peer_execution_claimed', 'general_coding_quality_claimed', 'guest_cleanup_owned_by_parent'}
    require(type(value) is dict and set(value) == booleans | {'version', 'kind', 'phase', 'failure',
        'approved_commands', 'declined_commands', 'native_commands_observed', 'before_sha256', 'after_sha256',
        'startup'},
        'UI report fields')
    require(type(value['version']) is int and value['version'] == 2
        and value['kind'] == 'native-editor-ui-smoke' and value['phase'] in UI_PHASES
        and value['failure'] in UI_FAILURES | {None}
        and all(type(value[key]) is bool for key in booleans), 'UI report values')
    startup = value['startup']
    startup_flags = {'document_ready', 'workbench_ready', 'dialog_seen', 'palette_seen'}
    require(type(startup) is dict and set(startup) == startup_flags | {'palette_attempts'}
        and all(type(startup[key]) is bool for key in startup_flags)
        and type(startup['palette_attempts']) is int and 0 <= startup['palette_attempts'] <= 8,
        'UI startup report')
    for key in ('approved_commands', 'declined_commands', 'native_commands_observed'):
        require(type(value[key]) is int and 0 <= value[key] <= 16, 'UI count')
    require(value['before_sha256'] == ORIGINAL_SHA
        and (value['after_sha256'] is None or re.fullmatch('[0-9a-f]{64}', value['after_sha256']))
        and not any(value[key] for key in ('synthetic_model', 'private_peer_execution_claimed',
                                         'general_coding_quality_claimed'))
        and value['guest_cleanup_owned_by_parent'], 'UI proof scope')
    if value['passed']:
        require(value['phase'] == 'complete' and value['failure'] is None
            and all(startup[key] for key in ('document_ready', 'workbench_ready', 'palette_seen'))
            and not startup['dialog_seen'] and startup['palette_attempts'] >= 1
            and all(value[key] for key in ('start_clicked', 'read', 'edit', 'test', 'independent_test_passed',
                'ui_result_shown', 'runtime_cleanup_confirmed_by_ui', 'cdp_closed'))
            and 3 <= value['approved_commands'] == value['native_commands_observed'] <= 8
            and value['declined_commands'] == 0 and value['after_sha256'] not in (None, ORIGINAL_SHA),
            'UI read/edit/test unproven')
    return value


def lifecycle(value):
    flags = {'editor_started', 'workbench_seen', 'driver_joined', 'editor_joined',
             'ctrl_q_sent', 'forced_stop', 'isolated_network', 'host_display_used'}
    require(type(value) is dict and set(value) == flags | {'version', 'phase', 'editor_exit', 'driver_exit'}
        and type(value['version']) is int and value['version'] == 1
        and value['phase'] in ('guard', 'prepare', 'editor-start', 'editor-ready', 'ui-driver', 'complete')
        and all(type(value[key]) is bool for key in flags), 'editor lifecycle shape')
    for key in ('editor_exit', 'driver_exit'):
        require(value[key] is None or type(value[key]) is int and -255 <= value[key] <= 255, 'editor exit')
    require(not value['host_display_used'], 'host display forbidden')
    return value


def private_root(path):
    info = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private directory')


def sandbox_command(parent_net):
    """Only public runtime inputs, fixture UI files and the exact owner core socket."""
    home = pwd.getpwuid(os.getuid()).pw_dir
    command = ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-user',
        '--uid', str(os.getuid()), '--gid', str(os.getgid()), '--unshare-net', '--unshare-pid',
        '--unshare-ipc', '--unshare-uts', '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr',
        '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--dir', '/etc', '--ro-bind', '/etc/passwd', '/etc/passwd', '--ro-bind', '/etc/group', '/etc/group',
        '--ro-bind', '/etc/ld.so.cache', '/etc/ld.so.cache', '--ro-bind', '/etc/fonts', '/etc/fonts',
        '--tmpfs', '/tmp', '--dir', '/run', '--dir', home, '--proc', '/proc', '--dev', '/dev',
        '--ro-bind', '/sys/devices/virtual/dmi/id', '/sys/devices/virtual/dmi/id',
        '--ro-bind', '/sys/class/dmi/id', '/sys/class/dmi/id',
        '--perms', '0700', '--dir', str(ROOT), '--bind', str(UI), str(UI),
        '--ro-bind', str(ROOT / 'private.sock'), str(ROOT / 'private.sock'),
        '--ro-bind', str(ROOT / 'runtime'), str(ROOT / 'runtime'),
        '--ro-bind', str(CODE), str(CODE), '--ro-bind', str(RUNTIME), str(RUNTIME),
        '--ro-bind', str(EDITOR), str(EDITOR),
        '--ro-bind', str(HERE / 'agent-native-editor.py'), '/editor-trial.py',
        '--chdir', str(UI), '--clearenv', '--setenv', 'PATH', ENV['PATH'], '--setenv', 'LANG', ENV['LANG'],
        '--', '/usr/bin/python3', '-B', '/editor-trial.py', 'inside', parent_net]
    return command


def editor_command():
    return [str(EDITOR / 'codium'), '--new-window', '--ozone-platform=headless', '--disable-gpu',
        '--disable-updates', '--disable-telemetry', '--disable-crash-reporter', '--locale=en',
        '--user-data-dir=' + str(UI / 'profile'), '--extensions-dir=' + str(UI / 'extensions'),
        '--extensionDevelopmentPath=' + str(CODE), '--skip-welcome', '--skip-release-notes',
        '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222', str(PROJECT)]


def cdp_command(quit_editor=False):
    # These are actual CDP input events, not VS Code API calls or rewritten DOM.
    code = "const {connect}=require(process.argv[1]);(async()=>{const c=await connect('http://127.0.0.1:9222');try{"
    if quit_editor:
        code += "await c.key('q','KeyQ',81,2);"
    code += "}finally{await c.close();}})().catch(()=>{process.exitCode=1;});"
    return [str(NODE), '-e', code, str(CODE / 'scripts/smoke_editor_ui.cjs')]


def joined_group(process):
    if process is None:
        return True
    if process.poll() is None:
        return False
    try:
        os.killpg(process.pid, 0)
        return False
    except ProcessLookupError:
        return True


def stop_group(process):
    if process is None:
        return True
    for kind in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, kind)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        if joined_group(process):
            return True
    return joined_group(process)


def inside(parent_net):
    # Independent guard before preparing any project or connecting/inserting UI text.
    require(os.getuid() == os.geteuid() != 0 and pwd.getpwuid(os.getuid()).pw_name == 'vpci'
        and socket.gethostname() == 'volparossa-alpha'
        and subprocess.check_output(['/usr/bin/systemd-detect-virt', '--vm'], env=ENV, timeout=5).strip() == b'kvm',
        'disposable guest only')
    require(os.readlink('/proc/self/ns/net') != parent_net
        and {name for _, name in socket.if_nameindex()} <= {'lo'}
        and set(os.environ) <= {'PATH', 'LANG', 'PWD', 'LC_CTYPE'}
        and os.environ.get('PWD', str(UI)) == str(UI), 'editor isolation')
    caps = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
                if line.startswith('CapEff:'))
    require(int(caps, 16) == 0, 'editor capabilities')
    private_root(UI)
    observed = dict(version=1, phase='guard', editor_started=False, workbench_seen=False,
        driver_joined=True, editor_joined=True, ctrl_q_sent=False, forced_stop=False,
        isolated_network=True, host_display_used=False, editor_exit=None, driver_exit=None)
    editor, driver = None, None
    try:
        observed['phase'] = 'prepare'
        for path in (PROJECT, UI / 'profile', UI / 'extensions', UI / 'profile/User'):
            path.mkdir(mode=0o700)
        subprocess.run([str(NODE), str(CODE / 'scripts/smoke_editor_ui.cjs'), '--prepare-project',
            '--execute', '--yes', '--project', str(PROJECT), '--output', str(UI / 'prepare.json')],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15, env=ENV)
        require(read(UI / 'prepare.json')['passed'] is True, 'project preparation')
        config = read(UI / 'runtime-config.json', 32768)
        write(UI / 'profile/User/settings.json', {
            'window.dialogStyle': 'custom', 'workbench.startupEditor': 'none',
            'telemetry.telemetryLevel': 'off', 'update.mode': 'none',
            'extensions.autoCheckUpdates': False, 'extensions.autoUpdate': False,
            # This new, synthetic fixture directory is explicitly selected by the owner.
            # No developer/editor trust settings are changed outside the disposable profile.
            'security.workspace.trust.enabled': False,
            'volparossaCode.privateSocket': str(ROOT / 'private.sock'),
            'volparossaCode.nativeRuntime': config,
        })
        observed['phase'] = 'editor-start'
        with (UI / 'editor.log').open('xb') as log:
            editor = subprocess.Popen(editor_command(), env=ENV, stdout=log, stderr=log, start_new_session=True)
        observed['editor_started'] = True
        observed['phase'] = 'editor-ready'
        deadline = time.monotonic() + 50
        while editor.poll() is None and time.monotonic() < deadline:
            result = subprocess.run(cdp_command(), env=ENV, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=20)
            if result.returncode == 0:
                observed['workbench_seen'] = True
                break
            time.sleep(0.25)
        require(observed['workbench_seen'], 'editor workbench unavailable')
        observed['phase'] = 'ui-driver'
        with (UI / 'driver.log').open('xb') as log:
            driver = subprocess.Popen([str(NODE), str(CODE / 'scripts/smoke_editor_ui.cjs'),
                '--execute', '--yes', '--cdp', 'http://127.0.0.1:9222', '--project', str(PROJECT),
                '--output', str(UI / 'result.json'), '--timeout-seconds', '2400'],
                env=ENV, stdout=log, stderr=log, start_new_session=True)
            observed['driver_exit'] = driver.wait(timeout=2430)
        require(observed['driver_exit'] == 0 and ui_receipt(read(UI / 'result.json'))['passed'], 'actual UI task failed')
        observed['phase'] = 'complete'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass  # Only the closed phase/exit and reviewed UI receipt leave this private directory.
    finally:
        observed['driver_joined'] = stop_group(driver)
        if driver is not None:
            observed['driver_exit'] = driver.returncode
        if editor is not None and editor.poll() is None:
            try:
                quit_result = subprocess.run(cdp_command(True), env=ENV, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=20)
                observed['ctrl_q_sent'] = quit_result.returncode == 0
                editor.wait(timeout=15)
            except (OSError, subprocess.SubprocessError):
                pass
        if not joined_group(editor):
            observed['forced_stop'] = True
        observed['editor_joined'] = stop_group(editor)
        observed['editor_exit'] = editor.returncode if editor is not None else None
        write(UI / 'lifecycle.json', lifecycle(observed))
    return 0 if (observed['phase'] == 'complete' and observed['ctrl_q_sent']
        and observed['editor_exit'] == 0 and not observed['forced_stop']
        and observed['editor_joined'] and observed['driver_joined']) else 1


def unit(name, *args, check=True):
    require(name in (CORE_UNIT, EDITOR_UNIT), 'unit scope')
    return subprocess.run(['sudo', '-n', 'systemctl', *args, name],
                          capture_output=True, text=True, timeout=15, check=check)


def properties(name):
    result = unit(name, 'show', '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,Result,ExecMainStatus', check=False)
    require(result.returncode in (0, 1) and len(result.stdout) <= 8192, 'unit observation')
    value = dict(row.split('=', 1) for row in result.stdout.splitlines() if '=' in row)
    require(value.get('LoadState') in ('loaded', 'not-found'), 'unit unavailable')
    return value


def group_path(name):
    require(name in (CORE_UNIT, EDITOR_UNIT), 'cgroup scope')
    return Path('/sys/fs/cgroup/system.slice') / name


def memory(name):
    group = group_path(name)
    events = dict(row.split() for row in (group / 'memory.events').read_text().splitlines())
    value = {key: int((group / field).read_text()) for key, field in (
        ('maximum', 'memory.max'), ('swap', 'memory.swap.max'), ('current', 'memory.current'), ('peak', 'memory.peak'))}
    return dict(value, oom=int(events['oom']), oom_kill=int(events['oom_kill']))


def cgroup_empty(name):
    group = group_path(name)
    return not group.exists() or all(not path.read_text().strip() for path in group.rglob('cgroup.procs'))


def start_unit(name, command, limit, lifetime, log, diagnostics=False):
    args = ['sudo', '-n', 'systemd-run', '--quiet', '--unit=' + name,
        '--property=Type=exec', '--property=RemainAfterExit=yes', '--property=User=vpci', '--property=Group=vpci',
        '--property=WorkingDirectory=/home/vpci/source', '--property=MemoryMax=' + str(limit),
        '--property=MemorySwapMax=0', '--property=TasksMax=256', '--property=KillMode=control-group',
        '--property=RuntimeMaxSec=' + str(lifetime), '--property=TimeoutStopSec=15',
        '--property=NoNewPrivileges=yes', '--property=PrivateNetwork=yes',
        '--property=StandardOutput=append:' + str(log), '--property=StandardError=append:' + str(log)]
    if diagnostics:
        args += ['--setenv=RUST_LOG=off,volparossa::compute::private_diagnostic=debug', '--setenv=NO_COLOR=1']
    subprocess.run([*args, *command], check=True, timeout=15, capture_output=True)


def check_report(value, revision):
    require(value['report_kind'] == 'volparossa-agent-native-editor' and value['proof_version'] == 1
        and value['source_revision'] == revision and re.fullmatch('[0-9a-f]{40}', revision)
        and value['scope'] == SCOPE and value['success'] is True and value['phase'] == 'complete', 'incomplete proof')
    require(value['ui']['passed'] is True and ui_receipt(value['ui'])
        and value['inputs_unchanged'] is True and value['service_clean_stop'] is True
        and value['units_naturally_empty'] == dict(core=True, editor=True)
        and not value.get('diagnostic_invalid'), 'actual execution')
    observed = lifecycle(value['editor_lifecycle'])
    require(observed['phase'] == 'complete' and observed['editor_exit'] == observed['driver_exit'] == 0
        and all(observed[key] for key in ('editor_started', 'workbench_seen', 'driver_joined', 'editor_joined',
                                         'ctrl_q_sent', 'isolated_network'))
        and not observed['forced_stop'], 'editor cleanup unproven')
    require(all(value[key] is False for key in ('raw_input_exported', 'raw_model_output_exported',
        'private_peer_execution_proven', 'general_coding_quality_proven', 'editor_source_build_proven')),
        'unsupported claim')
    bundle = module('native-editor-runtime')
    authority = bundle.authority(revision)
    proof = value['bundle']
    require(set(proof) == set(authority) | {'receipt_sha256', 'inventory_files'}
        and {key: proof[key] for key in authority} == authority
        and re.fullmatch('[0-9a-f]{64}', proof['receipt_sha256'])
        and type(proof['inventory_files']) is int and 0 < proof['inventory_files'] < 10000, 'bundle proof')
    native = module('agent-native-coding')
    require(value['node_provision'] == native.PRIVATE.pins()['runtime']
            and value['model_provision'] == native.model_provenance(), 'model/Node provenance')
    for key, limit in (('core_memory', CORE_MEMORY), ('editor_memory', EDITOR_MEMORY)):
        report = value[key]
        require(set(report) == {'maximum', 'swap', 'current', 'peak', 'oom', 'oom_kill'}
            and all(type(count) is int for count in report.values())
            and report['maximum'] == limit and report['swap'] == report['oom'] == report['oom_kill'] == 0
            and 0 <= report['current'] <= report['peak'] <= limit, 'resource proof')
    require(value['cleanup'] == dict(provision_joined=True, core_stopped=True, editor_stopped=True,
        core_cgroup_empty=True, editor_cgroup_empty=True, observed_lifetimes_ended=True, private_root_removed=True)
        and value['host_state_unchanged'] is True
        and value['host_state_hashes']['before'] == value['host_state_hashes']['after'], 'cleanup proof')
    require(value['fixture_hashes'] == {name: digest(HERE / name) for name in FIXTURE_NAMES}, 'fixture identity')


def execute(output, revision):
    native = module('agent-native-coding')
    private, train = native.PRIVATE, native.TRAIN
    private.guard()
    require(output == OUTPUT and re.fullmatch('[0-9a-f]{40}', revision), 'exact invocation')
    require(not ROOT.exists() and not ROOT.is_symlink()
            and all(properties(name)['LoadState'] == 'not-found' for name in (CORE_UNIT, EDITOR_UNIT)), 'existing trial')
    available = dict(row.split(':', 1) for row in Path('/proc/meminfo').read_text().splitlines())
    require(int(available['MemAvailable'].split()[0]) * 1024 >= 7 * GIB, 'guest memory preflight')
    before = train['snapshot']()
    write(output / 'host-state-before.json', before)
    result = dict(report_kind='volparossa-agent-native-editor', proof_version=1, source_revision=revision,
        scope=SCOPE, success=False, phase='guard', raw_input_exported=False, raw_model_output_exported=False,
        private_peer_execution_proven=False, general_coding_quality_proven=False, editor_source_build_proven=False)
    ROOT.mkdir(mode=0o700)
    (ROOT / 'work').mkdir(mode=0o700)
    UI.mkdir(mode=0o700)
    provision, created, members = None, set(), {}
    try:
        result['phase'] = 'runtime-verification'
        result['bundle'] = verify_inputs(revision)
        require(shutil.disk_usage(ROOT).free >= 6 * GIB, 'disk preflight')
        result['phase'] = 'node-provision'
        node = private.pins()['runtime']
        private.fetch(node['url'], ROOT / 'node.tar.xz', node)
        with tarfile.open(ROOT / 'node.tar.xz', 'r:xz') as archive:
            private.extract_node(archive, ROOT / 'runtime', node['files'])
        result['node_provision'] = node
        pin = result['bundle']['native']
        write(UI / 'runtime-config.json', dict(version=1, appServer=str(RUNTIME / 'runtime/codex-app-server'),
            appServerSha256=pin['binary_sha256'], buildReport=str(RUNTIME / 'BUILD_REPORT.json'),
            node=str(NODE), nodeSha256=node['files']['bin/node']['sha256'], upstreamPrompt=str(RUNTIME / 'prompt.md')))
        result['phase'] = 'model-provision'
        with (ROOT / 'provision.log').open('xb') as log:
            provision = subprocess.Popen([sys.executable, '-B', str(private.ML / 'provision.py'),
                '--execute', '--yes', '--disposable-guest', '--model-profile', private.PROFILE,
                '--root', str(ROOT / 'ml'), '--budget-bytes', str(5 * GIB)],
                stdout=log, stderr=log, start_new_session=True)
            require(provision.wait(timeout=1850) == 0, 'model provision')
        observed, expected = read(ROOT / 'ml/provision-report.json'), native.model_provenance()
        require(observed['success'] is True and observed['training_performed'] is False
            and observed['runtime_autofetch_enabled'] is False
            and {key: observed[key] for key in expected} == expected, 'model identity')
        result['model_provision'] = expected
        result['phase'] = 'service-start'
        (ROOT / 'service.log').touch(mode=0o600)
        created.add(CORE_UNIT)
        start_unit(CORE_UNIT, [str(private.CLI), 'compute', 'private-serve', '--socket', str(ROOT / 'private.sock'),
            '--work-parent', str(ROOT / 'work'), '--runtime-root', str(ROOT / 'ml/venv'),
            '--model-root', str(ROOT / 'ml/model'), '--model-profile', private.PROFILE,
            '--threads', '2', '--max-seconds', '600', '--execute'], CORE_MEMORY, 2700, ROOT / 'service.log', True)
        for _ in range(100):
            if (ROOT / 'private.sock').exists():
                break
            time.sleep(0.1)
        core = properties(CORE_UNIT)
        require(int(core['MainPID']) > 0 and core['ActiveState'] == 'active'
            and core['ControlGroup'] == '/system.slice/' + CORE_UNIT
            and (ROOT / 'private.sock').is_socket(), 'core launch')
        core_before = memory(CORE_UNIT)
        require(core_before['maximum'] - core_before['current'] >= 9 * GIB // 2, 'core admission headroom')
        result['phase'] = 'editor-ui'
        (ROOT / 'editor-unit.log').touch(mode=0o600)
        created.add(EDITOR_UNIT)
        start_unit(EDITOR_UNIT, sandbox_command(os.readlink('/proc/self/ns/net')),
                   EDITOR_MEMORY, 2550, ROOT / 'editor-unit.log')
        deadline = time.monotonic() + 2570
        while True:
            for name in (CORE_UNIT, EDITOR_UNIT):
                info = properties(name)
                pid = int(info.get('MainPID', '0'))
                if pid:
                    for member in [train['identity'](pid), *train['descendants'](pid)]:
                        members[(member['pid'], member['start_ticks'])] = member
            require(len(members) <= 4096, 'process lifetime bound')
            editor = properties(EDITOR_UNIT)
            if editor.get('MainPID') == '0':
                break
            require(time.monotonic() < deadline, 'editor lifetime')
            time.sleep(0.5)
        if (UI / 'result.json').exists():
            result['ui'] = ui_receipt(read(UI / 'result.json', 16384))
        if (UI / 'lifecycle.json').exists():
            result['editor_lifecycle'] = lifecycle(read(UI / 'lifecycle.json', 4096))
        require(editor['Result'] == 'success' and editor['ExecMainStatus'] == '0'
            and result['ui']['passed'] and result['editor_lifecycle']['phase'] == 'complete', 'editor trial failed')
        result['units_naturally_empty'] = dict(editor=cgroup_empty(EDITOR_UNIT))
        require(result['units_naturally_empty']['editor'], 'editor descendants remain before stop')
        require(not list((ROOT / 'work').iterdir()), 'private work remains')
        require(verify_inputs(revision) == result['bundle']
                and digest(NODE) == node['files']['bin/node']['sha256'], 'inputs changed')
        result['inputs_unchanged'] = True
        result['phase'] = 'service-stop'
        unit(CORE_UNIT, 'kill', '--kill-whom=main', '--signal=SIGINT')
        for _ in range(100):
            core = properties(CORE_UNIT)
            if core.get('MainPID') == '0':
                break
            time.sleep(0.1)
        require(core['ActiveState'] == 'active' and core['SubState'] == 'exited'
            and core['Result'] == 'success' and core['ExecMainStatus'] == '0'
            and not (ROOT / 'private.sock').exists(), 'core clean stop')
        result['units_naturally_empty']['core'] = cgroup_empty(CORE_UNIT)
        require(result['units_naturally_empty']['core'], 'core descendants remain before stop')
        result['service_clean_stop'] = True
        result['phase'] = 'complete'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result['failure_code'] = 'phase_failed'
    finally:
        provision_joined = private.stop_client(provision)
        stopped = {}
        for name, key in ((CORE_UNIT, 'core'), (EDITOR_UNIT, 'editor')):
            if group_path(name).exists():
                try:
                    result[key + '_memory'] = memory(name)
                except (OSError, ValueError, KeyError):
                    result['diagnostic_invalid'] = True
            if name in created:
                unit(name, 'stop', check=False)
                state = properties(name)
                stopped[key] = state['LoadState'] == 'not-found' or state.get('ActiveState') in ('inactive', 'failed')
                unit(name, 'reset-failed', check=False)
            else:
                stopped[key] = True
        try:
            result['service_diagnostic'] = private.service_diagnostic(ROOT / 'service.log')
            result['editor_launcher'] = private.closed_log(ROOT / 'editor-unit.log')
        except (OSError, ValueError, KeyError, TypeError):
            result['diagnostic_invalid'] = True
        ended = not any(train['alive'](member) for member in members.values())
        result['cleanup'] = dict(provision_joined=provision_joined, core_stopped=stopped['core'],
            editor_stopped=stopped['editor'], core_cgroup_empty=cgroup_empty(CORE_UNIT),
            editor_cgroup_empty=cgroup_empty(EDITOR_UNIT), observed_lifetimes_ended=ended)
        if all(result['cleanup'].values()):
            private_root(ROOT)
            shutil.rmtree(ROOT)  # Only the newly-created exact guest fixture, after both cgroups joined.
        result['cleanup']['private_root_removed'] = not ROOT.exists()
        after = train['snapshot']()
        write(output / 'host-state-after.json', after)
        result['host_state_unchanged'] = before == after
        result['host_state_hashes'] = {when: digest(output / f'host-state-{when}.json') for when in ('before', 'after')}
        result['fixture_hashes'] = {name: digest(HERE / name) for name in FIXTURE_NAMES}
        result['success'] = result['phase'] == 'complete' and all(result['cleanup'].values()) and before == after
        if result['success']:
            try:
                require(not result.get('diagnostic_invalid'), 'invalid diagnostic')
                check_report(result, revision)
            except (OSError, ValueError, KeyError, TypeError):
                result['success'], result['failure_code'] = False, 'proof_validation_failed'
        write(output / 'agent-native-editor-smoke.json', result)
    return 0 if result['success'] else 1


def main():
    if len(sys.argv) == 3 and sys.argv[1] == 'inside':
        return inside(sys.argv[2])
    if len(sys.argv) == 5 and sys.argv[1] == 'execute' and sys.argv[4] == '--yes':
        return execute(Path(sys.argv[2]), sys.argv[3])
    if len(sys.argv) == 4 and sys.argv[1] == 'report':
        path = Path(sys.argv[2])
        value = read(path)
        check_report(value, sys.argv[3])
        for when in ('before', 'after'):
            require(digest(path.parent / f'host-state-{when}.json') == value['host_state_hashes'][when], 'snapshot identity')
        for entry in path.parent.iterdir():
            require(entry.name in EXPORT_NAMES | {'vm-console.log'} and entry.is_file() and not entry.is_symlink()
                and entry.stat().st_size <= (16 * 1024**2 if entry.name == 'vm-console.log' else 262144), 'export bound')
        print('NATIVE_EDITOR_COMPONENT_PROOF_OK')
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == 'export-names':
        print('\n'.join(sorted(EXPORT_NAMES)))
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == 'failure':
        output, revision, phase = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
        require(output == OUTPUT and re.fullmatch('[0-9a-f]{40}', revision)
            and phase in ('guest-packages', 'cli-build', 'native-editor'), 'failure invocation')
        write(output / 'agent-native-editor-smoke.json', dict(report_kind='volparossa-agent-native-editor',
            proof_version=1, source_revision=revision, scope=SCOPE, success=False, phase=phase,
            failure_code='guest_phase_incomplete'))
        return 1
    return 64


if __name__ == '__main__':
    os.umask(0o077)
    def interrupted(_kind, _frame):
        raise InterruptedError('trial_interrupted')
    for kind in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(kind, interrupted)
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('native_editor_fixture_failed', file=sys.stderr)
        raise SystemExit(1)
