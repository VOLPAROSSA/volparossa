#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert two-product dispatch, timing and cleanup contracts; no network or VM."""
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "weather-products-delivery.sh"
LEGACY = HERE / "weather-client-delivery.sh"


class ProductsShell(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="weather-products-shell-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def call(self, body, source=None):
        return subprocess.run(["/bin/sh", "-s"], input="set -eu\n" +
            (SOURCE.read_text() if source is None else source) + "\n" + body,
            text=True, capture_output=True, timeout=5,
            env=dict(PATH="/usr/bin:/bin", WORK=str(self.root), site_control_gid="987"))

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_syntax_and_inert_sourcing(self):
        subprocess.run(["/bin/sh", "-n", str(SOURCE)], check=True, timeout=5)
        self.ok(self.call(":"))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_source_observer_is_staged_root_readonly_before_untrusted_acquisition(self):
        source = SOURCE.read_text()
        staging = "    for weather_script in " + source.split("    for weather_script in ", 1)[1].split(
            "    install -o root -g root -m 0600", 1)[0]
        for version in (2, 3, 4, 5):
            result = self.call('''
source_directory=/verified-core
weather_profile_version=VERSION
install() { printf '%s\\n' "$*"; }
fail() { exit 99; }
'''.replace("VERSION", str(version)) + staging)
            self.ok(result)
            expected = f"-o root -g root -m 0555 /verified-core/tests/integration/weather-source-observer.mjs {self.root}/bin/weather-source-observer.mjs"
            self.assertEqual(result.stdout.splitlines().count(expected), 1)
            admission = "weather-public-overmorrow-v5.json"
            calls = [line for line in result.stdout.splitlines() if admission in line]
            self.assertEqual(calls, [f"-o root -g root -m 0555 /verified-core/tests/integration/{admission} {self.root}/bin/{admission}"]
                if version == 5 else [])
        self.assertLess(source.index(staging), source.index("PHASE=weather-products-delivery-acquire"))

    def test_missing_v5_admission_fails_before_unpack_without_blocking_older_profiles(self):
        source = SOURCE.read_text()
        staging = "    for weather_script in " + source.split("    for weather_script in ", 1)[1].split(
            "    install -o root -g root -m 0600", 1)[0]
        for version in (2, 3, 4, 5):
            result = self.call('''
source_directory=/verified-core
weather_profile_version=VERSION
install() { case "$*" in *weather-public-overmorrow-v5.json*) return 1;; *) return 0;; esac; }
fail() { printf '%s\n' "$1" >&2; exit 77; }
'''.replace("VERSION", str(version)) + staging + "\nprintf 'unpack-next\\n'\n")
            self.assertEqual(result.returncode, 77 if version == 5 else 0, result.stderr)
            self.assertEqual(result.stdout, "" if version == 5 else "unpack-next\n")
            self.assertEqual(result.stderr, "WEATHER_PRODUCTS_DRIVER_UNAVAILABLE\n" if version == 5 else "")

    def test_closed_independent_product_mapping(self):
        result = self.call('''
for kind in weather air_quality; do
    weather_products_select "$kind"
    printf '%s %s %s %s %s %s\n' "$weather_product" "$weather_product_file" \
        "$weather_product_manifest" "$weather_product_source_cache" "$weather_publications" "$weather_product_prefix"
done
if weather_products_select arbitrary; then exit 90; fi
''')
        self.ok(result)
        self.assertEqual(result.stdout.splitlines(), [
            "weather forecast.json manifest.bin source-cache 4 weather-products-delivery-weather",
            "air_quality air-quality.json air-quality-manifest.bin air-quality-source-cache 5 weather-products-delivery-air-quality",
        ])

    def test_single_deadline_caps_commands_and_refuses_expired_stage(self):
        self.ok(self.call('''
date() { printf '1000\n'; }
[ "$(weather_products_remaining 120)" = 120 ]
WEATHER_PRODUCTS_DEADLINE=1840
[ "$(weather_products_remaining 120)" = 120 ]
WEATHER_PRODUCTS_DEADLINE=1031
[ "$(weather_products_remaining 200)" = 31 ]
[ "$(weather_products_remaining 270)" = 31 ]
WEATHER_PRODUCTS_DEADLINE=1000
if weather_products_remaining 200; then exit 90; fi
WEATHER_PRODUCTS_DEADLINE=999
if weather_products_remaining 270; then exit 90; fi
'''))

    def test_cleanup_retains_before_all_independent_attempts(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-products-delivery.py").touch()
        output = self.root / "client-fixtures/weather-viewer/browser-output"
        output.mkdir(parents=True)
        (output / "report.json").touch()
        self.ok(self.call('''
python3() { printf 'retain\n' >> "$WORK/calls"; return 1; }
weather_products_private() { printf '%s\n' "$1" >> "$WORK/calls"; return 1; }
weather_client_home_cleanup() { printf 'home\n' >> "$WORK/calls"; }
if weather_client_delivery_cleanup; then exit 90; fi
'''))
        self.assertEqual((self.root / "calls").read_text().splitlines(),
                         ["retain", "publisher-cleanup", "user-cleanup", "home"])

    def test_already_retained_report_not_replaced(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-products-delivery.py").touch()
        retained = self.root / "weather-products-delivery-original-report.json"
        retained.write_bytes(b"retained")
        self.ok(self.call('''
python3() { exit 90; }
weather_products_private() { :; }
weather_client_home_cleanup() { :; }
weather_client_delivery_cleanup
'''))
        self.assertEqual(retained.read_bytes(), b"retained")

    def test_acquisition_failure_is_retained_before_fail_without_entering_publication(self):
        source = SOURCE.read_text()
        fragment = "    PHASE=weather-products-delivery-acquire\n" + source.split(
            "    PHASE=weather-products-delivery-acquire\n", 1)[1].split(
            "    WEATHER_PRODUCTS_DEADLINE=", 1)[0]
        for status, retain_status in ((1, 0), (124, 0), (137, 0), (1, 1), (0, 0)):
            with self.subTest(status=status, retain_status=retain_status):
                result = self.call('''
umask 077
weather_client_directory=$WORK/source
weather_client_manifest_sha256=inert
weather_publisher=$WORK/publisher
WORKER_UID=985
site_parent_ns=net:[1]
site_client_ns=net:[2]
timeout() { printf '{"success":false}\n'; return STATUS; }
python3() {
    [ "$*" = "-B $WORK/bin/weather-products-delivery.py retain-acquisition-failure $WORK STATUS" ] || exit 90
    printf 'retained:STATUS\n'
    printf 'STATUS\n' > "$WORK/retained-status"
    return RETAIN_STATUS
}
fail() { printf '%s %s\n' "$PHASE" "$1" >&2; exit 77; }
'''.replace("RETAIN_STATUS", str(retain_status)).replace("STATUS", str(status)) +
                    fragment + '\nprintf "publication-next\\n"\n')
                if status:
                    expected = "WEATHER_PRODUCTS_ACQUISITION_DIAGNOSTIC_FAILED" if retain_status else "WEATHER_PRODUCTS_ACQUISITION_FAILED"
                    self.assertEqual(result.returncode, 77, result.stderr)
                    self.assertEqual(result.stderr.strip(), "weather-products-delivery-acquire " + expected)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual((self.root / "retained-status").read_text().strip(), str(status))
                    marker = self.root / "weather-products-delivery-acquisition-failure.json"
                    self.assertEqual(marker.read_text(), f"retained:{status}\n")
                    self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
                    marker.unlink()
                    (self.root / "retained-status").unlink()
                else:
                    self.ok(result)
                    self.assertEqual(result.stdout, "publication-next\n")
                    self.assertFalse((self.root / "retained-status").exists())

    def test_failure_marker_selects_only_dedicated_closed_export(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/weather-products-delivery.py").touch()
        marker = self.root / "weather-products-delivery-acquisition-failure.json"
        for kind in ("absent", "regular", "symlink"):
            with self.subTest(kind=kind):
                if kind == "regular": marker.write_text("untrusted fixture marker")
                elif kind == "symlink": marker.symlink_to("missing-target")
                result = self.call('''
output_directory=$WORK/output
OUTPUT_UID=1000
OUTPUT_GID=1000
python3() {
    printf '%s\n' "$*" > "$WORK/export-call"
    return 1
}
if weather_client_delivery_copy_artifacts; then exit 90; fi
''')
                self.ok(result)
                action = "copy-artifacts" if kind == "absent" else "copy-failure-artifacts"
                self.assertEqual((self.root / "export-call").read_text().strip(),
                    f"-B {self.root}/bin/weather-products-delivery.py {action} {self.root} {self.root}/output 1000 1000")
                if kind != "absent": marker.unlink()

    def test_verified_closed_dispatch_before_any_v1_work(self):
        source = LEGACY.read_text()
        head = source.split("weather_client_delivery_run() {", 1)[1].split("    PHASE=weather-client-delivery-prepare", 1)[0]
        helper_root = self.root / "tests/integration"
        helper_root.mkdir(parents=True)
        (helper_root / "weather-products-delivery.sh").write_text(
            'weather_products_delivery_run() { printf "v%s\\n" "$weather_profile_version"; }\n')
        for version in (1, 2, 3, 4, 5, 6, 7, "2", "3", "4", "5", "6", True):
            with self.subTest(version=version, value_type=type(version)):
                import json
                value = json.dumps({"bundle_version": version})
                result = self.call('''
source_directory=$WORK
weather_client_bundle=inert
weather_client_manifest_sha256=inert
stat() { printf '0\\n'; }
python3() { printf '%s\n' 'JSON'; }
fail() { exit 77; }
run_selected
'''.replace("JSON", value), source=source + "\nrun_selected() {\n" + head + '\nprintf "v1\\n"\n}\n')
                self.assertEqual(result.returncode, 0 if type(version) is int and version in (1, 2, 3, 4, 5, 6) else 77)
                if result.returncode == 0: self.assertEqual(result.stdout, f"v{version}\n")
        self.assertLess(head.index("weather_client_runtime_profile"), head.index(".bundle_version"))
        self.assertLess(head.index(".bundle_version"), head.index('            . "$source_directory'))

    def test_profile_owner_boundary_and_helper_failure_are_fail_closed(self):
        source = LEGACY.read_text()
        head = source.split("weather_client_delivery_run() {", 1)[1].split("    PHASE=weather-client-delivery-prepare", 1)[0]
        helper_root = self.root / "tests/integration"
        helper_root.mkdir(parents=True)
        (helper_root / "weather-products-delivery.sh").write_text(
            'weather_products_delivery_run() { printf "v%s\\n" "$weather_profile_version"; }\n')
        scenarios = (("root", 0, 0, 0), ("vpci", 1000, 0, 0), ("other", 985, 0, 77),
                     ("stat-failure", 1000, 0, 77), ("missing-account", 1000, 0, 77),
                     ("runuser-failure", 1000, 0, 77), ("helper-failure", 0, 1, 77),
                     ("helper-failure", 1000, 1, 77))
        for version in (1, 2, 3, 4, 5):
            for scenario, owner, helper_status, expected_status in scenarios:
                with self.subTest(version=version, scenario=scenario, owner=owner):
                    result = self.call('''
source_directory=$WORK
weather_client_bundle=$WORK/inert.tar
weather_client_manifest_sha256=inert-digest
PHASE=content-provider-filter-cold
test_scenario=SCENARIO
test_owner=OWNER
test_effective_uid=0
stat() {
    [ "$*" = "-Lc %u $weather_client_bundle" ] || exit 90
    [ "$test_scenario" != stat-failure ] || return 1
    printf '%s\n' "$test_owner"
}
id() {
    [ "$*" = '-u vpci' ] || exit 91
    [ "$test_scenario" != missing-account ] || return 1
    printf '1000\n'
}
python3() {
    [ "$*" = "-B $source_directory/tests/integration/weather-client-bundle.py runtime-version $weather_client_bundle $weather_client_manifest_sha256" ] || exit 92
    printf 'python:%s\n' "$test_effective_uid" >> "$WORK/profile-calls"
    # The real parser accepts root-owned or invoking-owner files, not a
    # vpci-owned input merely because the invoking process has root access.
    [ "$test_owner" = 0 ] || [ "$test_owner" = "$test_effective_uid" ] || return 93
    printf '{"bundle_version":VERSION}\n'
    return HELPER_STATUS
}
runuser() {
    [ "$1 $2 $3" = '-u vpci --' ] || exit 94
    printf 'runuser\n' >> "$WORK/profile-calls"
    [ "$test_scenario" != runuser-failure ] || return 1
    shift 3
    test_effective_uid=1000
    "$@"
}
fail() { printf '%s %s\n' "$PHASE" "$1" >&2; exit 77; }
run_selected
'''.replace("SCENARIO", scenario).replace("OWNER", str(owner))
                        .replace("VERSION", str(version)).replace("HELPER_STATUS", str(helper_status)),
                        source=source + "\nrun_selected() {\n" + head + '\nprintf "v1\\n"\n}\n')
                    self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
                    if expected_status:
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(result.stderr.strip(),
                            "weather-client-delivery-profile WEATHER_CLIENT_PROFILE_INVALID")
                    else:
                        self.assertEqual(result.stdout, f"v{version}\n")
                    calls = self.root / "profile-calls"
                    observed = calls.read_text().splitlines() if calls.exists() else []
                    expected = [] if scenario in ("other", "stat-failure", "missing-account") else (
                        ["runuser"] if scenario == "runuser-failure" else
                        ["python:0"] if owner == 0 else ["runuser", "python:1000"])
                    self.assertEqual(observed, expected)
                    if calls.exists(): calls.unlink()

    def test_two_product_driver_paths_are_closed_and_keep_the_same_deadline(self):
        source = SOURCE.read_text()
        head = source.split("weather_products_delivery_run() {", 1)[1].split(
            "    PHASE=weather-products-delivery-prepare", 1)[0]
        helper_root = self.root / "tests/integration"
        helper_root.mkdir(parents=True)
        (helper_root / "weather-android-delivery.sh").write_text(
            'weather_android_delivery_run() { printf "android-only\\n"; }\n')
        for version in ("2", "3", "4", "5", "6", "1", "7", "", "../../../arbitrary"):
            with self.subTest(version=version):
                result = self.call('''
weather_client_bundle=inert
weather_client_manifest_sha256=inert
source_directory=$WORK
weather_profile_version='VERSION'
fail() { exit 77; }
run_selected
'''.replace("VERSION", version), source=source + "\nrun_selected() {\n" + head +
                    '\nprintf "%s\\n" "$weather_products_driver"\n}\n')
                if version in ("2", "3", "4", "5"):
                    self.ok(result)
                    consumer = "overmorrow" if version in ("3", "5") else "drizzli"
                    self.assertEqual(result.stdout.strip(), f"integrations/{consumer}/smoke_core_browser.py")
                elif version == "6":
                    self.ok(result)
                    self.assertEqual(result.stdout, "\n")  # No browser/cold driver selected.
                else: self.assertEqual(result.returncode, 77)
        self.assertIn('"$WORK/state-client/air-quality-cache" "$weather_profile_version"', source)
        self.assertIn('python3 -B "$weather_client_directory/volparossa-weather/$weather_products_driver"', source)
        self.assertEqual(source.count('weather_products_remaining 270'), 1)

    def test_browser_version_argument_is_fixed_and_only_added_for_v5(self):
        source = SOURCE.read_text()
        browser = "    PHASE=weather-products-delivery-browser\n" + source.split(
            "    PHASE=weather-products-delivery-browser\n", 1)[1].split(
            "    PHASE=weather-products-delivery-verify\n", 1)[0]
        for version in (2, 3, 4, 5):
            result = self.call('''
weather_profile_version=VERSION
weather_client_directory=/verified-client
weather_client_manifest_sha256=inert
weather_products_driver=integrations/CONSUMER/smoke_core_browser.py
weather_viewer=/private-viewer
site_parent_ns=net:[1]
site_client_ns=net:[2]
WORKER_UID=985
CLIENT=isolated-client
weather_products_remaining() { printf '270\n'; }
timeout() { printf '%s\n' "$@" > "$WORK/browser-args"; }
fail() { exit 99; }
set -- --bundle-version 999 arbitrary-caller-argument
'''.replace("VERSION", str(version)).replace("CONSUMER", "overmorrow" if version in (3, 5) else "drizzli") + browser)
            self.ok(result)
            args = (self.root / "browser-args").read_text().splitlines()
            self.assertEqual(args[:3], ["--signal=TERM", "--kill-after=30s", "270s"])
            self.assertIn("--clear-groups", args)
            self.assertIn("--bounding-set=-all", args)
            self.assertIn("--no-new-privs", args)
            self.assertNotIn("arbitrary-caller-argument", args)
            self.assertNotIn("999", args)
            if version == 5:
                self.assertEqual(args[-2:], ["--bundle-version", "5"])
                self.assertEqual(args.count("--bundle-version"), 1)
            else:
                self.assertNotIn("--bundle-version", args)
                self.assertEqual(args[-2:], ["--control-gid", "987"])

    def test_publication_cleanup_independent_captures_and_retained_proof_order(self):
        source = SOURCE.read_text()
        run = source.split("weather_products_delivery_run() {", 1)[1]
        self.assertLess(run.index(' acquire \\'), run.index('WEATHER_PRODUCTS_DEADLINE='))
        self.assertLess(run.index('WEATHER_PRODUCTS_DEADLINE='), run.index(' content publish'))
        self.assertLess(run.index('weather-products-delivery-manifest.json'), run.index('chown -R'))
        self.assertLess(run.index('publisher-cleanup "$weather_publisher"'), run.index('PHASE=weather-products-delivery-cold-'))
        self.assertIn('cold "$weather_product"', run)
        self.assertIn('start_privacy_observers "$weather_product_prefix-privacy"', run)
        self.assertIn('content_provider_start_control_observer "$weather_product_prefix-control"', run)
        self.assertLess(run.index('content_provider_stop_control_observer'), run.index(' cold-evidence "$WORK"'))
        self.assertLess(run.index(' copy-cold-evidence "$WORK"'), run.index(' prepare "$weather_client_directory"'))
        self.assertLess(run.index(' retain "$WORK"'), run.index('weather_client_delivery_cleanup'))
        self.assertLess(run.index('weather_client_delivery_cleanup'), run.index(' evidence "$WORK"'))
        self.assertIn('--lifetime-seconds 900', run)
        self.assertIn('WEATHER_PRODUCTS_DEADLINE=$(($(date +%s) + 840))', run)
        for maximum in (120, 200, 40, 270): self.assertIn(f'weather_products_remaining {maximum}', source)
        self.assertEqual(source.count('--kill-after=30s'), 4)
        self.assertNotIn('--kill-after=10s', source)
        self.assertNotIn('env HOME=', source)
        self.assertNotIn('--groups=', source)

    def test_observers_accept_only_exact_new_product_prefixes(self):
        control = (HERE / "content-provider-smoke.sh").read_text()
        privacy = (HERE / "kvm-alpha-topology.sh").read_text()
        for suffix in ("weather", "air-quality"):
            self.assertIn(f"weather-products-delivery-{suffix}-control", control)
            self.assertIn(f"weather-products-delivery-{suffix}-privacy", privacy)
        self.assertNotIn('weather-products-*', control)
        self.assertNotIn('weather-products-*', privacy)


if __name__ == "__main__":
    unittest.main()
