#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Narrow UI fixture boundaries; no browser execution or storage success claim."""
from pathlib import Path
import json
import os
import runpy
import shutil
import signal
import socket
import unittest

HERE = Path(__file__).parent
UI = runpy.run_path(str(HERE / 'cloud-private-file-ui.py'))
CHECK = runpy.run_path(str(HERE / 'cloud-private-file-smoke.py'))


class OriginalUIBoundary(unittest.TestCase):
    def test_closed_nested_failure_survives_real_child_exit_without_private_output(self):
        # Actual Node -> Python subprocess boundary; synthetic failure, no browser
        # or peer proof. The same production fixture helpers propagate the record.
        node = os.environ.get('VOLPAROSSA_TEST_NODE') or shutil.which('node')
        if not node:
            self.skipTest('Node is required for the actual diagnostic subprocess check')
        script = '''
          const {closedUIFailure} = await import(process.argv[1]);
          const ui = closedUIFailure(process.argv[2], {code: 5, signal: null});
          process.stderr.write('PRIVATE_SENTINEL_NOT_EXPORTED');
          console.log(JSON.stringify({success:false, kind:'cloud-private-file-sdk-failure',
            stage:'original_files_ui', ui}));
          process.exitCode = 7;
        '''
        for change, expected in (({}, 'unlock'), ({'stage': 'PRIVATE_SENTINEL_NOT_EXPORTED'}, 'unreported'),
                                 ({'private': 'PRIVATE_SENTINEL_NOT_EXPORTED'}, 'unreported')):
            child = dict(success=False, kind='cloud-private-file-ui-failure', stage='unlock')
            child.update(change)
            with self.subTest(change=tuple(change)):
                with self.assertRaises(ValueError):
                    CHECK['sdk_process_json']([node, '--input-type=module', '-e', script,
                        (HERE / 'cloud-private-file-sdk.mjs').resolve().as_uri(), json.dumps(child)], deadline=10)
                record = CHECK['sdk_process_json'].__globals__['SDK_FAILURE']
                self.assertEqual(record, dict(stage='original_files_ui', exit_status=7, signal=None,
                    ui=dict(stage=expected, exit_status=5, signal=None)))
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps(record))
        killed = CHECK['closed_sdk_failure'](b'private raw output', -signal.SIGKILL)
        self.assertEqual(killed, dict(stage='unreported', exit_status=None, signal='SIGKILL', ui=None))

    def test_real_protocol_frame_and_eof_are_bounded(self):
        for data, expected in ((b'2:{}', {}), (b'6:[1,2', None), (b'99999999:', None)):
            left, right = socket.socketpair()
            with self.subTest(data=data), left, right:
                right.sendall(data)
                right.shutdown(socket.SHUT_WR)
                if expected is None:
                    with self.assertRaises(ValueError):
                        UI['read_frame'](left)
                else:
                    self.assertEqual(UI['read_frame'](left), expected)

    def test_only_exact_loopback_service_and_private_stdin_token(self):
        value = dict(origin='http://127.0.0.1:35431', bearerToken='a' * 43,
                     expectedBytes=786433, expectedSha256='1' * 64)
        self.assertEqual(UI['settings'](value), value)
        for update in (dict(origin='https://example.com'), dict(origin='http://127.0.0.1:99999'),
                       dict(bearerToken='x\n' * 22), dict(expectedBytes=True), dict(expectedSha256='bad')):
            with self.assertRaises(ValueError):
                UI['settings'](dict(value, **update))

    def test_browser_sees_only_its_new_profile_and_original_runtime(self):
        command = UI['command'](Path('/private-owner/cloud-ui-fixture'))
        self.assertIn('--clearenv', command)
        self.assertIn('/opt/volparossa-cloud/build/firefox-esr', command)
        self.assertNotIn('/private-owner', command)
        self.assertNotIn('/opt/volparossa-cloud', command)
        source = (HERE / 'cloud-private-file-ui.py').read_text()
        self.assertIn("sys.stdin.buffer.read(4097)", source)
        self.assertIn("'.oc-modal-body-actions-confirm'", source)
        self.assertIn('/#/files/spaces/project/synthetic-owner', source)
        self.assertNotIn('/project/Selected', source)
        for forbidden in ('web-ui-fixture.mjs', 'synthetic_page_debug', 'synthetic_ui_errors', 'browser.log'):
            self.assertNotIn(forbidden, source)
        parent = (HERE / 'cloud-private-file-sdk.mjs').read_text()
        self.assertIn('ui = await originalUI(root, origin, token, content)', parent)
        self.assertIn('webDist: `${SOURCE}/build/web-ui`', parent)


if __name__ == '__main__':
    unittest.main()
