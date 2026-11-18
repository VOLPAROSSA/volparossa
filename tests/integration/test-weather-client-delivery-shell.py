#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert shell contracts: no real /nonexistent, VM, browser or network use."""
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "weather-client-delivery.sh"


class WeatherShell(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="weather-shell-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "account-home"
        # Rebind every occurrence in memory before sourcing. All shell file
        # mutations are then restricted to this test's temporary directory.
        self.source = SOURCE.read_text().replace("/nonexistent", str(self.home)).replace("systemd-detect-virt", "test_virt")
        self.assertNotIn("/nonexistent", self.source)

    def call(self, body, **extra):
        environment = dict(PATH="/usr/bin:/bin", TEST_HOME_PATH=str(self.home),
            TEST_VIRT="kvm", TEST_HOME_MODE="755", WORK=str(self.root),
            WORKER_UID="985", site_control_gid="987")
        environment.update(extra)
        mocks = r'''
id() { printf '0\n'; }
test_virt() { printf '%s\n' "$TEST_VIRT"; }
sed() { printf 'systemd\n'; }
getent() { printf 'fixture:x:985:987::%s:/usr/sbin/nologin\n' "$TEST_HOME_PATH"; }
stat() {
    if [ "$2" = '%u:%g:%a' ]; then printf '0:0:%s\n' "$TEST_HOME_MODE";
    else /usr/bin/stat "$@"; fi
}
'''
        return subprocess.run(["/bin/sh", "-s"], input="set -eu\n" + self.source + mocks + body,
            text=True, capture_output=True, env=environment, timeout=5)

    def require_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_syntax_and_no_source_side_effects(self):
        subprocess.run(["/bin/sh", "-n", str(SOURCE)], check=True, timeout=5)
        self.require_success(self.call(":"))
        self.assertFalse(self.home.exists())

    def test_created_home_is_removed_and_cleanup_idempotent(self):
        self.require_success(self.call('''
weather_client_home_prepare
[ "$WEATHER_CLIENT_HOME_CREATED" = yes ]
[ -n "$WEATHER_CLIENT_HOME_IDENTITY" ]
weather_client_home_cleanup
weather_client_home_cleanup
[ "$WEATHER_CLIENT_HOME_CREATED" = no ]
'''))
        self.assertFalse(self.home.exists())

    def test_existing_home_is_preserved_despite_inherited_ownership(self):
        self.home.mkdir(mode=0o755)
        identity = f"{self.home.stat().st_dev}:{self.home.stat().st_ino}"
        self.require_success(self.call('''
[ "$WEATHER_CLIENT_HOME_CREATED" = no ]
[ -z "$WEATHER_CLIENT_HOME_IDENTITY" ]
weather_client_home_prepare
weather_client_home_cleanup
''', WEATHER_CLIENT_HOME_CREATED="yes", WEATHER_CLIENT_HOME_IDENTITY=identity))
        self.assertTrue(self.home.is_dir())

    def test_non_kvm_refuses_creation(self):
        result = self.call("weather_client_home_prepare", TEST_VIRT="none")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.home.exists())

    def test_unsafe_existing_homes_rejected_without_mutation(self):
        for kind in ("file", "symlink", "nonempty", "mode"):
            with self.subTest(kind=kind):
                if kind == "file": self.home.touch()
                elif kind == "symlink": self.home.symlink_to(self.root)
                else:
                    self.home.mkdir(mode=0o755)
                    if kind == "nonempty": (self.home / "retain").touch()
                result = self.call("weather_client_home_prepare", TEST_HOME_MODE="777" if kind == "mode" else "755")
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.home.exists())
                if kind in ("file", "symlink"): self.home.unlink()
                else:
                    if kind == "nonempty": (self.home / "retain").unlink()
                    self.home.rmdir()

    def test_replaced_inode_is_not_removed(self):
        self.require_success(self.call('''
weather_client_home_prepare
mv -- "$TEST_HOME_PATH" "$WORK/original"
mkdir -m 0755 -- "$TEST_HOME_PATH"
if weather_client_home_cleanup; then exit 90; fi
[ "$WEATHER_CLIENT_HOME_CREATED" = yes ]
'''))
        self.assertTrue(self.home.is_dir())
        self.assertTrue((self.root / "original").is_dir())

    def test_nonempty_created_home_refuses_until_empty(self):
        self.require_success(self.call('''
weather_client_home_prepare
touch -- "$TEST_HOME_PATH/retained"
if weather_client_home_cleanup; then exit 90; fi
[ -f "$TEST_HOME_PATH/retained" ]
rm -- "$TEST_HOME_PATH/retained"
weather_client_home_cleanup
'''))
        self.assertFalse(self.home.exists())

    def test_cleanup_attempts_every_owned_resource_after_failure(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-client-delivery.py").touch()
        self.require_success(self.call('''
weather_client_home_prepare
weather_client_private() {
    printf '%s\n' "$1" >> "$WORK/calls"
    [ "$1" != publisher-cleanup ]
}
if weather_client_delivery_cleanup; then exit 90; fi
[ "$WEATHER_CLIENT_HOME_CREATED" = no ]
'''))
        self.assertFalse(self.home.exists())
        self.assertEqual((self.root / "calls").read_text().splitlines(), ["publisher-cleanup", "user-cleanup"])

    def test_runtime_arguments_boundaries_and_receipt_order(self):
        source = SOURCE.read_text()
        self.assertNotIn("env HOME=", source)
        self.assertNotIn('--groups=', source)
        self.assertIn('--lifetime-seconds 900', source)
        self.assertIn('.publications == 4', source)
        self.assertIn('-- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1', source)
        for limit in ("400s", "200s", "270s"):
            self.assertIn(f'--kill-after=10s {limit}', source)
        run = source.split("weather_client_delivery_run() {", 1)[1]
        self.assertLess(run.index('"$WORK/weather-client-delivery-manifest.json"'), run.index('chown -R'))
        self.assertLess(run.index('publisher-cleanup "$weather_publisher"'), run.index('PHASE=weather-client-delivery-cold'))
        self.assertLess(run.index('content_provider_stop_control_observer'), run.index(' cold-evidence "$WORK"'))
        self.assertLess(run.index('weather-client-delivery-cache-before.json'), run.index(' cold-evidence "$WORK"'))
        self.assertLess(run.index(' cold-evidence "$WORK"'), run.index('weather_client_private prepare'))
        self.assertLess(run.index(' copy-cold-evidence "$WORK"'), run.index('weather_client_private prepare'))
        self.assertLess(run.index(' cold-evidence "$WORK"'), run.index('PHASE=weather-client-delivery-browser'))
        self.assertLess(run.index(' retain "$WORK"'), run.index('weather_client_delivery_cleanup'))
        self.assertLess(run.index('weather_client_delivery_cleanup'), run.index(' evidence "$WORK"'))
        self.assertIn('weather-client-delivery-tree-before.json', run)
        self.assertIn('weather-client-delivery-tree-after.json', run)

    def test_cold_evidence_is_preserved_before_prepare_and_failure_prevents_browser_preparation(self):
        run = SOURCE.read_text().split('weather_client_delivery_run() {', 1)[1]
        segment = run[run.index('    PHASE=weather-client-delivery-cold-verify'):
                      run.index('    PHASE=weather-client-delivery-browser')]
        for status in (0, 1):
            with self.subTest(cold_validation_status=status):
                result = self.call('''
weather_client_manifest_sha256=inert-manifest
weather_core_sha256=inert-core
weather_client_directory=$WORK/inert-source
weather_viewer=$WORK/inert-viewer
weather_cache=$WORK/inert-cache
binary_directory=$WORK/inert-bin
output_directory=$WORK/inert-output
OUTPUT_UID=985
OUTPUT_GID=987
python3() {
    case "$3" in cold-evidence|copy-cold-evidence) ;; *) exit 90 ;; esac
    printf '%s\n' "$3" >> "$WORK/calls"
    printf '{"inert_test_only":true}\n'
    if [ "$3" = cold-evidence ]; then return "$TEST_COLD_STATUS"; fi
}
weather_client_private() {
    [ "$1" = prepare ] || exit 91
    [ -s "$WORK/weather-client-delivery-cold-evidence.json" ] || exit 92
    printf 'prepare\n' >> "$WORK/calls"
}
fail() { printf '%s\n' "$1" >&2; exit 77; }
''' + segment, TEST_COLD_STATUS=str(status))
                self.assertEqual(result.returncode, 0 if status == 0 else 77, result.stderr)
                self.assertEqual((self.root / 'calls').read_text().splitlines(),
                                 ['cold-evidence', 'copy-cold-evidence', 'prepare'] if status == 0 else ['cold-evidence'])
                if status: self.assertIn('WEATHER_CLIENT_COLD_EVIDENCE_INVALID', result.stderr)
                (self.root / 'calls').unlink()

    def test_interrupt_retains_before_cleanup_and_keeps_attempting_on_error(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-client-delivery.py").touch()
        output = self.root / "client-fixtures/weather-viewer/browser-output"
        output.mkdir(parents=True)
        (output / "report.json").touch()
        for result in (0, 1):
            with self.subTest(retain_result=result):
                self.require_success(self.call('''
weather_client_home_prepare
python3() { printf 'retain\n' >> "$WORK/calls"; return "$TEST_RETAIN_STATUS"; }
weather_client_private() { printf '%s\n' "$1" >> "$WORK/calls"; }
status=0
weather_client_delivery_cleanup || status=$?
[ "$status" -eq "$TEST_RETAIN_STATUS" ]
[ "$WEATHER_CLIENT_HOME_CREATED" = no ]
''', TEST_RETAIN_STATUS=str(result)))
                self.assertFalse(self.home.exists())
                self.assertEqual((self.root / "calls").read_text().splitlines(),
                    ["retain", "publisher-cleanup", "user-cleanup"])
                (self.root / "calls").unlink()

    def test_already_retained_report_is_not_replaced(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-client-delivery.py").touch()
        output = self.root / "client-fixtures/weather-viewer/browser-output"
        output.mkdir(parents=True)
        (output / "report.json").touch()
        retained = self.root / "weather-client-delivery-original-report.json"
        retained.write_bytes(b'original')
        self.require_success(self.call('''
python3() { exit 90; }
weather_client_private() { printf '%s\n' "$1" >> "$WORK/calls"; }
weather_client_delivery_cleanup
'''))
        self.assertEqual(retained.read_bytes(), b'original')
        self.assertEqual((self.root / "calls").read_text().splitlines(), ["publisher-cleanup", "user-cleanup"])


if __name__ == "__main__":
    unittest.main()
