#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Static/source-wiring checks only; never imply hosted archive availability."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT=Path(__file__).resolve().parents[2]
WORKFLOWS={
    'weather-decoder-abi':'decoder-abi',
    'weather-products-delivery':'drizzli-v4',
    'weather-overmorrow-delivery':'overmorrow-v5',
    'weather-android-delivery':'android-v6',
}
FULL='if: ${{ !inputs.archive_inputs_only }}'


def steps(source):
    return re.split(r'(?=^      - (?:name:|uses:))',source,flags=re.M)[1:]


class ArchiveWorkflowWiring(unittest.TestCase):
    def test_all_four_fixed_routes_and_default_false_input_scope(self):
        for filename,consumer in WORKFLOWS.items():
            source=(ROOT/'.github/workflows'/ (filename+'.yml')).read_text()
            with self.subTest(workflow=filename):
                self.assertRegex(source,r'workflow_dispatch:\n    inputs:\n      archive_inputs_only:\n        description: [^\n]+\n        type: boolean\n        default: false\n')
                self.assertIn("name: ${{ inputs.archive_inputs_only && 'Archive inputs only (no runtime acceptance)' || 'Full runtime trial' }}",source)
                self.assertEqual(source.count('scripts/fetch-weather-archive.py fetch --consumer '+consumer+' --output "$inputs"'),1)
                for guard in ('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
                              'test -z "$(git status --short --untracked-files=all)"'):
                    self.assertIn(guard,source)
                fetch=next(s for s in steps(source) if s.startswith('      - name: Verify fixed historical'))
                self.assertNotIn('if:',fetch)
                self.assertIn('GH_TOKEN: ${{ github.token }}',fetch)
                for forbidden in ('/actions/','gh run download','releases/latest','allow-blocked','continue-on-error','|| true'):
                    self.assertNotIn(forbidden,fetch)
                self.assertNotIn('actions: read',source)
                self.assertIn('  contents: read',source)
                self.assertNotIn('pull_request:',source)
                self.assertNotIn('schedule:',source)
                for test in ('test-weather-release-archive.py','test-weather-release-archive-protocol.py',
                             'test-weather-release-archive-wiring.py'):
                    self.assertLess(source.index('python3 -B tests/integration/'+test),source.index('scripts/fetch-weather-archive.py fetch'))

    def test_fetch_precedes_every_resource_install_and_runtime_with_full_route_guards(self):
        expensive=('apt-get','qemu-system-x86_64 -accel','test -c /dev/kvm','COMBINED_RESOURCES',
            'fetch-upstream.sh','build-upstream.sh','curl --fail','capture-v4','capture-v5','capture-v6',
            'prepare_hosted_android_ci.py','setfacl','tests/integration/weather-android-owner.py ','run-alpha-topology-vm.sh" --execute',
            'content-provider-smoke.py report','JOINED_EVIDENCE','FINAL_SOURCE_PREFLIGHT')
        for filename in WORKFLOWS:
            source=(ROOT/'.github/workflows'/(filename+'.yml')).read_text()
            fetch_index=source.index('- name: Verify fixed historical release archive inputs')
            for step in steps(source):
                if any(token in step for token in expensive):
                    with self.subTest(workflow=filename,step=step.splitlines()[0]):
                        self.assertGreater(source.index(step),fetch_index)
                        self.assertIn('!inputs.archive_inputs_only',step.split('        run: |',1)[0])
                        self.assertNotIn('if: inputs.archive_inputs_only',step)
            if filename=='weather-decoder-abi':
                fetch=next(s for s in steps(source) if 'name: Verify fixed historical' in s)
                self.assertIn('weather-decoder-abi.py verify-inputs "$inputs/decoder"',fetch)
                self.assertLess(source.index('verify-inputs "$inputs/decoder"'),source.index('- name: Install VM tools'))
                initialize=next(s for s in steps(source) if 'name: Initialize private ABI runtime output' in s)
                self.assertIn(FULL,initialize)
                self.assertIn('VOLPAROSSA_ABI_OUTPUT=',initialize)
                self.assertNotIn('apt-get',initialize)
                install=next(s for s in steps(source) if 'name: Install VM tools' in s)
                self.assertNotIn('VOLPAROSSA_ABI_OUTPUT=',install)
                self.assertLess(source.index(initialize),source.index(install))
            else:
                self.assertNotIn('install -d -m 0700 "$inputs"',source)

    def test_all_summaries_uploads_and_always_cleanup_keep_distinct_scope(self):
        for filename in WORKFLOWS:
            source=(ROOT/'.github/workflows'/(filename+'.yml')).read_text()
            for step in steps(source):
                if 'actions/upload-artifact@' in step or 'GITHUB_STEP_SUMMARY' in step:
                    if 'name: Retain archive input verification only' in step or 'name: State archive input verification scope' in step:
                        self.assertIn('if: success() && inputs.archive_inputs_only',step)
                        if 'actions/upload-artifact@' in step:
                            self.assertIn('path: ${{ env.WEATHER_ARCHIVE_INPUTS }}/provenance/archive-report.json',step)
                            self.assertIn('if-no-files-found: error',step)
                            for forbidden in ('*.json','.zip','.tar','/decoder','/abi','/assets','/proof'):
                                self.assertNotIn(forbidden,step)
                        else:
                            self.assertIn('runtime_executed: false',step)
                            self.assertIn('No current origin acquisition, joined delivery, mobile release or network datapath acceptance.',step)
                    else:
                        self.assertIn('!inputs.archive_inputs_only',step)
                if 'if:' in step and 'always()' in step:
                    self.assertIn('!inputs.archive_inputs_only',step.split('        run: |')[0])
            self.assertNotIn('upload-artifact@',next(s for s in steps(source) if 'name: Verify fixed historical' in s))

    def test_blocked_cli_fails_with_no_network_output_or_success_report(self):
        helper=ROOT/'scripts/fetch-weather-archive.py'
        lock=json.loads((ROOT/'tests/helper/weather-release-archive-v1.json').read_bytes())
        self.assertEqual(lock['state'],'blocked')
        self.assertEqual(lock['blocked_reason'],'redistribution-review-incomplete')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for consumer in WORKFLOWS.values():
                output=root/consumer
                result=subprocess.run(['python3','-B',str(helper),'fetch','--consumer',consumer,'--output',str(output)],
                    capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin','GH_TOKEN':'never-disclosed-fixture'})
                self.assertEqual(result.returncode,1)
                self.assertEqual(result.stdout,b'')
                self.assertIn(b'archive blocked: redistribution-review-incomplete',result.stderr)
                self.assertNotIn(b'never-disclosed-fixture',result.stderr)
                self.assertFalse(output.exists())

    def test_every_yaml_run_body_is_shell_syntax_only(self):
        for filename in WORKFLOWS:
            source=(ROOT/'.github/workflows'/(filename+'.yml')).read_text()
            scripts=re.findall(r'^        run: \|\n((?:(?:^          .*|^)$\n?)*)',source,re.M)
            self.assertGreaterEqual(len(scripts),7)
            for index,script in enumerate(scripts):
                result=subprocess.run(['/bin/bash','-n'],input=textwrap.dedent(script),text=True,capture_output=True,timeout=5)
                self.assertEqual(result.returncode,0,(filename,index,result.stderr))


if __name__=='__main__':unittest.main()
