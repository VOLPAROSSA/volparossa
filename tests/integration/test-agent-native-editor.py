#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure admission/evidence contracts, not an editor, native model or VM proof."""
import copy
from pathlib import Path
import runpy
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
FIX = runpy.run_path(str(HERE / 'agent-native-editor.py'))


def ui():
    return dict(version=2, kind='native-editor-ui-smoke', passed=True, phase='complete', failure=None,
        start_clicked=True, approved_commands=3, declined_commands=0, native_commands_observed=3,
        read=True, edit=True, test=True, independent_test_passed=True, ui_result_shown=True,
        runtime_cleanup_confirmed_by_ui=True, cdp_closed=True, before_sha256=FIX['ORIGINAL_SHA'],
        after_sha256='b' * 64, synthetic_model=False, private_peer_execution_claimed=False,
        general_coding_quality_claimed=False, guest_cleanup_owned_by_parent=True,
        startup=dict(document_ready=True, workbench_ready=True, dialog_seen=False,
                     palette_attempts=1, palette_seen=True))


def synthetic_report():
    bundle = FIX['module']('native-editor-runtime')
    native = FIX['module']('agent-native-coding')
    return dict(report_kind='volparossa-agent-native-editor', proof_version=1, source_revision='a' * 40,
        scope=FIX['SCOPE'], success=True, phase='complete', ui=ui(), inputs_unchanged=True,
        service_clean_stop=True, units_naturally_empty=dict(core=True, editor=True),
        editor_lifecycle=dict(version=1, phase='complete', editor_started=True,
            workbench_seen=True, driver_joined=True, editor_joined=True, ctrl_q_sent=True, forced_stop=False,
            isolated_network=True, host_display_used=False, editor_exit=0, driver_exit=0),
        raw_input_exported=False, raw_model_output_exported=False, private_peer_execution_proven=False,
        general_coding_quality_proven=False, editor_source_build_proven=False,
        bundle=dict(bundle.authority('a' * 40), receipt_sha256='1' * 64, inventory_files=4096),
        node_provision=native.PRIVATE.pins()['runtime'], model_provision=native.model_provenance(),
        core_memory=dict(maximum=FIX['CORE_MEMORY'], swap=0, current=100, peak=200, oom=0, oom_kill=0),
        editor_memory=dict(maximum=FIX['EDITOR_MEMORY'], swap=0, current=100, peak=200, oom=0, oom_kill=0),
        cleanup=dict(provision_joined=True, core_stopped=True, editor_stopped=True, core_cgroup_empty=True,
            editor_cgroup_empty=True, observed_lifetimes_ended=True, private_root_removed=True),
        host_state_unchanged=True, host_state_hashes=dict(before='2' * 64, after='2' * 64),
        fixture_hashes={name: FIX['digest'](HERE / name) for name in FIX['FIXTURE_NAMES']})


class NativeEditorContracts(unittest.TestCase):
    def test_ui_requires_actual_approved_read_edit_test_and_independent_bytes(self):
        FIX['ui_receipt'](ui())
        for changes in ({'read': False}, {'edit': False}, {'test': False}, {'independent_test_passed': False},
                        {'approved_commands': 2}, {'native_commands_observed': 4}, {'declined_commands': 1},
                        {'after_sha256': FIX['ORIGINAL_SHA']}, {'after_sha256': None},
                        {'runtime_cleanup_confirmed_by_ui': False}, {'cdp_closed': False},
                        {'synthetic_model': True}, {'private_peer_execution_claimed': True},
                        {'prompt': 'PRIVATE_SENTINEL'}, {'failure': 'PRIVATE_SENTINEL'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                FIX['ui_receipt'](dict(ui(), **changes))

    def test_bounded_ui_failure_is_preserved_not_promoted_to_success(self):
        value = dict(ui(), passed=False, phase='native-turn', failure='command_refused',
            test=False, ui_result_shown=False, runtime_cleanup_confirmed_by_ui=False)
        self.assertEqual(FIX['ui_receipt'](value), value)
        with self.assertRaises(ValueError):
            FIX['ui_receipt'](dict(value, native_commands_observed=True))

    def test_startup_metadata_is_closed_and_readiness_is_not_task_success(self):
        for change in ({'document_ready': False}, {'workbench_ready': False},
                       {'dialog_seen': True}, {'palette_seen': False}, {'palette_attempts': 0},
                       {'palette_attempts': True}, {'palette_attempts': 9},
                       {'dialog_text': 'PRIVATE_SENTINEL'}):
            value = ui()
            value['startup'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                FIX['ui_receipt'](value)
        with self.assertRaises(ValueError):
            FIX['ui_receipt'](dict(ui(), version=1))
        for reason in ('startup_not_ready', 'palette_unavailable', 'startup_dialog'):
            value = dict(ui(), passed=False, phase='editor-connect', failure=reason,
                start_clicked=False, approved_commands=0, native_commands_observed=0,
                read=False, edit=False, test=False, independent_test_passed=False,
                ui_result_shown=False, runtime_cleanup_confirmed_by_ui=False)
            value['startup'].update(document_ready=False, workbench_ready=False,
                                    palette_seen=False, palette_attempts=0,
                                    dialog_seen=reason == 'startup_dialog')
            self.assertEqual(FIX['ui_receipt'](value), value)

    def test_report_requires_both_cgroups_real_ui_and_full_cleanup(self):
        value = synthetic_report()
        FIX['check_report'](value, 'a' * 40)
        for branch, key, bad in (
            ('editor_lifecycle', 'forced_stop', True), ('editor_lifecycle', 'ctrl_q_sent', False),
            ('editor_lifecycle', 'editor_exit', -15), ('editor_lifecycle', 'driver_exit', 1),
            ('editor_lifecycle', 'host_display_used', True), ('editor_lifecycle', 'isolated_network', False),
            ('cleanup', 'editor_cgroup_empty', False), ('cleanup', 'core_cgroup_empty', False),
            ('cleanup', 'observed_lifetimes_ended', False), ('cleanup', 'private_root_removed', False),
            ('units_naturally_empty', 'core', False), ('units_naturally_empty', 'editor', False),
            ('core_memory', 'oom_kill', 1), ('editor_memory', 'swap', 1),
            ('bundle', 'code_revision', 'b' * 40), ('bundle', 'existing_runtime_reused', False)):
            changed = copy.deepcopy(value)
            changed[branch][key] = bad
            with self.subTest(branch=branch, key=key), self.assertRaises(ValueError):
                FIX['check_report'](changed, 'a' * 40)

    def test_sparse_mounts_do_not_expose_owner_home_or_model_store(self):
        command = FIX['sandbox_command']('net:[123]')
        mounts = []
        for index, word in enumerate(command):
            if word in ('--bind', '--ro-bind'):
                mounts.append((word, command[index + 1], command[index + 2]))
        self.assertEqual([row for row in mounts if row[0] == '--bind'],
                         [('--bind', str(FIX['UI']), str(FIX['UI']))])
        self.assertNotIn(('--ro-bind', str(FIX['ROOT']), str(FIX['ROOT'])), mounts)
        self.assertFalse(any(source in ('/home', '/home/vpci', str(FIX['ROOT'] / 'ml'))
                             for _, source, _ in mounts))
        for name in ('CODE', 'RUNTIME', 'EDITOR'):
            self.assertIn(('--ro-bind', str(FIX[name]), str(FIX[name])), mounts)
        self.assertIn(('--ro-bind', str(FIX['ROOT'] / 'private.sock'), str(FIX['ROOT'] / 'private.sock')), mounts)
        for flag in ('--unshare-net', '--unshare-pid', '--unshare-ipc', '--unshare-uts', '--clearenv'):
            self.assertIn(flag, command)
        self.assertNotIn('HOME', command)
        self.assertNotIn('CODEX_HOME', command)
        self.assertFalse(FIX['PROJECT'].is_relative_to(FIX['CODE']))

    def test_editor_is_headless_and_exit_is_real_keyboard_not_api_substitution(self):
        command = FIX['editor_command']()
        self.assertIn('--ozone-platform=headless', command)
        self.assertNotIn('--no-sandbox', command)
        self.assertIn('--remote-debugging-address=127.0.0.1', command)
        self.assertEqual(command[-1], str(FIX['PROJECT']))
        quit_command = FIX['cdp_command'](True)
        self.assertIn("await c.key('q','KeyQ',81,2)", quit_command[2])
        self.assertNotIn('executeCommand', quit_command[2])
        self.assertNotIn('TASK', quit_command[2])
        self.assertEqual(quit_command[-1], str(FIX['CODE'] / 'scripts/smoke_editor_ui.cjs'))

    def test_preview_and_export_are_inert_and_closed(self):
        process = subprocess.run(['sh', str(HERE / 'agent-native-editor.sh'), '--preview'],
                                 capture_output=True, text=True, timeout=5, check=True)
        self.assertIn('PREVIEW ONLY', process.stdout)
        self.assertIn('2700s lifetime', process.stdout)
        exported = subprocess.check_output(['python3', '-B', str(HERE / 'agent-native-editor.py'),
                                           'export-names'], text=True, timeout=5)
        self.assertEqual(set(exported.splitlines()), FIX['EXPORT_NAMES'])
        self.assertEqual(len(FIX['EXPORT_NAMES']), 7)
        self.assertFalse(any(name.endswith('.log') for name in FIX['EXPORT_NAMES']))


if __name__ == '__main__':
    unittest.main()
