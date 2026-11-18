#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert execution of pressure shell control flow; no network, load or signals."""
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "content-provider-pressure-smoke.sh"

# Keep the production jq expressions and functions, but replace every boundary
# that could change networking or signal/wait for a real process. The shell
# mock accepts only the fixture's exact namespace/interface/operation tuples.
MOCKS = r'''
R3=ns3; R4=ns4; R5=ns5
SHAPED3=no; SHAPED4=no; SHAPED5=no
FAIL_ADD=; FAIL_DELETE=; WRONG_KIND=; SAME_NAMESPACE=
readlink() {
    [ "$*" = /proc/self/ns/net ] || return 93
    printf 'net:[parent]\n'
}
ip() {
    printf 'ip %s\n' "$*" >> "$CALLS"
    [ "$1" = netns ] && [ "$2" = exec ] || return 93
    mock_ns=$3
    case $mock_ns in
        ns3) mock_dev=r3x; mock_shaped=$SHAPED3 ;;
        ns4) mock_dev=r4x; mock_shaped=$SHAPED4 ;;
        ns5) mock_dev=r5x; mock_shaped=$SHAPED5 ;;
        *) return 93 ;;
    esac
    shift 3
    if [ "$*" = 'readlink /proc/self/ns/net' ]; then
        if [ "$mock_ns" = "$SAME_NAMESPACE" ]; then
            printf 'net:[parent]\n'
        else
            printf 'net:[%s]\n' "$mock_ns"
        fi
    elif [ "$*" = "tc -j qdisc show dev $mock_dev" ]; then
        if [ "$mock_ns" = "$WRONG_KIND" ]; then
            printf '[{"kind":"fq_codel","handle":"884:","root":true}]\n'
        elif [ "$mock_shaped" = yes ]; then
            printf '[{"kind":"tbf","handle":"884:","root":true,"options":{"rate":250000}}]\n'
        else
            printf '[{"kind":"noqueue","handle":"0:","root":true}]\n'
        fi
    elif [ "$*" = "tc qdisc add dev $mock_dev root handle 884: tbf rate 2mbit burst 128kb latency 250ms" ]; then
        [ "$mock_ns" != "$FAIL_ADD" ] || return 1
        case $mock_ns in ns3) SHAPED3=yes ;; ns4) SHAPED4=yes ;; ns5) SHAPED5=yes ;; esac
    elif [ "$*" = "tc qdisc del dev $mock_dev root handle 884:" ]; then
        [ "$mock_ns" != "$FAIL_DELETE" ] || return 1
        case $mock_ns in ns3) SHAPED3=no ;; ns4) SHAPED4=no ;; ns5) SHAPED5=no ;; esac
    else
        return 93
    fi
}
kill() { printf 'kill %s\n' "$*" >> "$CALLS"; return 1; }
wait() { printf 'wait %s\n' "$*" >> "$CALLS"; return 127; }
'''


class PressureShell(unittest.TestCase):
    def shell(self, body):
        with tempfile.TemporaryDirectory(prefix="pressure-shell-") as directory:
            work = Path(directory)
            calls = work / "calls"
            calls.touch(mode=0o600)
            script = 'WORK=$1\nCALLS=$2\n. "$3"\n' + MOCKS + '\n' + body
            result = subprocess.run(["sh", "-eu", "-c", script, "pressure-shell",
                                     str(work), str(calls), str(SCRIPT)],
                                    capture_output=True, timeout=3, check=False)
            recorded = calls.read_text().splitlines()
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            return result.stdout.decode(), recorded

    def test_shape_fixed_profile_and_restore_exact_owned_devices(self):
        _, calls = self.shell('''
content_provider_pressure_shape
[ "$CONTENT_PROVIDER_PRESSURE_R3_OWNED:$CONTENT_PROVIDER_PRESSURE_R4_OWNED:$CONTENT_PROVIDER_PRESSURE_R5_OWNED" = yes:yes:yes ]
jq -e '.rate_bits_per_second == 2000000 and .burst_bytes == 131072 and .queue_latency_ms == 250' "$WORK/content-provider-pressure-qdisc-profile.json" >/dev/null
content_provider_pressure_cleanup
[ "$CONTENT_PROVIDER_PRESSURE_R3_OWNED:$CONTENT_PROVIDER_PRESSURE_R4_OWNED:$CONTENT_PROVIDER_PRESSURE_R5_OWNED" = no:no:no ]
content_provider_pressure_cleanup
''')
        adds = [line for line in calls if "qdisc add" in line]
        deletes = [line for line in calls if "qdisc del" in line]
        self.assertEqual(len(adds), 3)
        self.assertEqual(deletes, [f"ip netns exec ns{n} tc qdisc del dev r{n}x root handle 884:"
                                   for n in (3, 4, 5)])

    def test_partial_add_failure_restores_only_successfully_owned_qdisc(self):
        _, calls = self.shell('''
FAIL_ADD=ns4
if content_provider_pressure_shape; then exit 90; fi
[ "$CONTENT_PROVIDER_PRESSURE_R3_OWNED" = yes ]
[ "${CONTENT_PROVIDER_PRESSURE_R4_OWNED:-no}:${CONTENT_PROVIDER_PRESSURE_R5_OWNED:-no}" = no:no ]
content_provider_pressure_cleanup
[ "$CONTENT_PROVIDER_PRESSURE_R3_OWNED" = no ]
''')
        self.assertEqual([line for line in calls if "qdisc del" in line],
                         ["ip netns exec ns3 tc qdisc del dev r3x root handle 884:"])
        self.assertFalse(any("ns5 tc qdisc add" in line for line in calls))

    def test_existing_qdisc_or_parent_namespace_prevents_all_mutations(self):
        for setting in ("WRONG_KIND=ns5", "SAME_NAMESPACE=ns5",
                        "CONTENT_PROVIDER_PRESSURE_R5_OWNED=yes"):
            with self.subTest(setting=setting):
                _, calls = self.shell(setting + '\nif content_provider_pressure_shape; then exit 90; fi\n')
                self.assertFalse(any("qdisc add" in line or "qdisc del" in line for line in calls))

    def test_replaced_qdisc_is_not_deleted_and_other_owned_links_still_restore(self):
        _, calls = self.shell('''
content_provider_pressure_shape
WRONG_KIND=ns4
if content_provider_pressure_cleanup; then exit 90; fi
[ "$CONTENT_PROVIDER_PRESSURE_R3_OWNED:$CONTENT_PROVIDER_PRESSURE_R4_OWNED:$CONTENT_PROVIDER_PRESSURE_R5_OWNED" = no:yes:no ]
''')
        self.assertEqual([line for line in calls if "qdisc del" in line],
                         [f"ip netns exec ns{n} tc qdisc del dev r{n}x root handle 884:" for n in (3, 5)])

    def test_failed_delete_keeps_owned_flag_and_remains_retryable(self):
        _, calls = self.shell('''
content_provider_pressure_shape
FAIL_DELETE=ns4
if content_provider_pressure_cleanup; then exit 90; fi
[ "$CONTENT_PROVIDER_PRESSURE_R3_OWNED:$CONTENT_PROVIDER_PRESSURE_R4_OWNED:$CONTENT_PROVIDER_PRESSURE_R5_OWNED" = no:yes:no ]
FAIL_DELETE=
content_provider_pressure_cleanup
[ "$CONTENT_PROVIDER_PRESSURE_R4_OWNED" = no ]
''')
        self.assertEqual([line for line in calls if "qdisc del" in line],
                         [f"ip netns exec ns{n} tc qdisc del dev r{n}x root handle 884:" for n in (3, 4, 5, 4)])

    def test_cleanup_reaps_exact_supervisors_before_network_restore_even_on_failed_wait(self):
        _, calls = self.shell('''
content_provider_pressure_shape
CONTENT_PROVIDER_PRESSURE_FETCH_PID=730001
CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID=730002
content_provider_pressure_cleanup
[ -z "$CONTENT_PROVIDER_PRESSURE_FETCH_PID$CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID" ]
content_provider_pressure_cleanup
''')
        lifecycle = [line for line in calls if line.startswith(("kill ", "wait ")) or "qdisc del" in line]
        self.assertEqual(lifecycle, ["kill -TERM 730001", "wait 730001", "kill -TERM 730002", "wait 730002"]
                         + [f"ip netns exec ns{n} tc qdisc del dev r{n}x root handle 884:" for n in (3, 4, 5)])

    def test_provider_original_manifest_and_diagnostic_deadlines_keep_phase_order(self):
        source = SCRIPT.read_text()
        flow = source.split("content_provider_pressure_run() {", 1)[1]
        steps = [
            'content stop >"$WORK/$pp_prefix-$pp_provider-reset.json"',
            'content serve --manifest "$adaptive_manifest"',
            '"$WORK/bin/content-provider-pressure.py" observe "$WORK"',
            'ready "$WORK"',
            'content_provider_pressure_shape || fail',
            'content_provider_worker_budget_capture mark pressure',
            'content fetch --manifest "$adaptive_manifest"',
            'wait "$CONTENT_PROVIDER_PRESSURE_FETCH_PID"',
            'pp_completed_mono=',
            'content_provider_worker_budget_capture finish pressure',
            'content_provider_worker_budget_capture pending pressure',
            'wait "$CONTENT_PROVIDER_PRESSURE_CONTROLLER_PID"',
            'benchmark_capture_paths "$pp_prefix-live"',
            'content_provider_pressure_cleanup || fail',
            'evidence "$WORK"',
        ]
        offsets = [flow.index(step) for step in steps]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('timeout --signal=TERM --kill-after=5s 45s python3 -B', flow)
        self.assertIn('timeout --signal=TERM --kill-after=5s 120s "$binary_directory/volparossa"', flow)
        self.assertIn('content_provider_worker_budget_capture pending pressure\n        fail CONTENT_PROVIDER_PRESSURE_FETCH_FAILED', flow)
        self.assertNotIn('rm -r', source)


if __name__ == "__main__":
    unittest.main()
