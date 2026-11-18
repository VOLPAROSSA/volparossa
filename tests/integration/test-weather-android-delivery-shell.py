#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert profile-6 shell wiring. All privileged/provider commands are mocks.

The only live child is an ordinary short-lived shell waiting on a fixture file;
these tests cannot establish Android, provider or network delivery.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "weather-android-delivery.sh"
PRODUCTS = HERE / "weather-products-delivery.sh"
LEGACY = HERE / "weather-client-delivery.sh"
TOPOLOGY = HERE / "kvm-alpha-topology.sh"


def shell_function(source, name):
    start = source.index(f"{name}() {{\n")
    return source[start:source.index("\n}\n", start) + 3]


class AndroidShell(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="weather-android-shell-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.libexec = self.work / "libexec"; self.libexec.mkdir(mode=0o755)
        for name in ("bin", "viewer"):
            (self.work / name).mkdir(mode=0o700)
        for name in ("weather-android-control.py", "weather-android-evidence.py", "weather-products-delivery.py"):
            (self.work / "bin" / name).write_text("inert; never executed\n")
        self.source = (LEGACY.read_text() + "\n" + SOURCE.read_text()).replace(
            "/usr/local/libexec", str(self.libexec)).replace("systemd-detect-virt", "test_virt")

    def call(self, body, *, source=None, extra=None, seconds=6):
        environment = dict(PATH="/usr/bin:/bin", WORK=str(self.work), WORKER_UID="985", AGENT_UID="986", AGENT_GID="986",
            site_control_gid="987", CLIENT="owned-client", site_parent_ns="net:[111]", site_client_ns="net:[222]",
            weather_profile_version="6", weather_publisher=str(self.work / "publisher"),
            weather_viewer=str(self.work / "viewer"), WEATHER_PRODUCTS_DEADLINE="1840",
            weather_core_sha256="c" * 64, weather_client_manifest_sha256="a" * 64,
            TEST_LIBEXEC=str(self.libexec), TEST_FAILURE="", TEST_REMAINING="840", TEST_PROFILE="6",
            TEST_CONTROL_GID="987", TEST_CACHE_UID="986", weather_client_bundle="/verified/inputs.tar")
        environment.update(extra or {})
        return subprocess.run(["/bin/sh", "-s"], input="set -eu\n" + (self.source if source is None else source) + "\n" + body,
            text=True, capture_output=True, timeout=seconds, env=environment)

    def good(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_syntax_and_sourcing_have_no_effects(self):
        for path in (SOURCE, LEGACY):
            subprocess.run(["/bin/sh", "-n", str(path)], check=True, timeout=5)
        before = set(self.work.rglob("*"))
        self.good(self.call('[ -z "$WEATHER_AGENT_PROFILE_VERSION$WEATHER_ANDROID_CACHE_IDENTITY" ]',
            extra=dict(WEATHER_AGENT_PROFILE_VERSION="6", WEATHER_ANDROID_CACHE_IDENTITY="untrusted")))
        self.assertEqual(before, set(self.work.rglob("*")))

    def test_v6_dispatch_has_no_browser_or_cold_branch(self):
        source = PRODUCTS.read_text()
        branch = source[source.index('    if [ "$weather_profile_version" = 6 ]; then\n        # The installed'):]
        branch = branch[:branch.index("    for weather_kind in weather air_quality; do")]
        for version in (2, 3, 4, 5, 6):
            result = self.call('''
weather_profile_version=VERSION
weather_android_delivery_run() { printf 'android\n'; }
dispatch() {
BRANCH
printf 'legacy\n'
}
dispatch
'''.replace("VERSION", str(version)).replace("BRANCH", branch), source="")
            self.good(result)
            self.assertEqual(result.stdout, "android\n" if version == 6 else "legacy\n")
        self.assertLess(source.index(branch), source.index("PHASE=weather-products-delivery-cold-$weather_product_path"))
        self.assertGreater(source.index(branch), source.index("fail WEATHER_PRODUCTS_PUBLISHER_FILES_REMAIN"))
        self.assertIn("2|3|4|5|6)", LEGACY.read_text())

    def test_v6_only_stages_extra_closed_helpers(self):
        source = PRODUCTS.read_text()
        staging = "    for weather_script in " + source.split("    for weather_script in ", 1)[1].split(
            "    install -o root -g root -m 0600", 1)[0]
        for version in (2, 3, 4, 5, 6):
            result = self.call('''
source_directory=/verified-core
weather_profile_version=VERSION
install() { printf '%s\n' "$*"; }
fail() { exit 97; }
'''.replace("VERSION", str(version)) + staging, source="")
            self.good(result)
            for name in ("weather-public-android-v6.json", "weather-android-delivery.py", "weather-android-api.py",
                    "weather-android-control.py", "weather-android-evidence.py"):
                calls = [line for line in result.stdout.splitlines() if name in line]
                self.assertEqual(len(calls), 1 if version == 6 else 0)

    def test_normal_guest_lifecycle_orders_actual_get_window_and_required_evidence(self):
        self.good(self.call(self.mocks() + "weather_android_delivery_run\nweather_client_delivery_cleanup\n"))
        calls = (self.work / "calls").read_text().splitlines()
        self.assertLess(calls.index("cache-parent-staged"), calls.index("prepare"))
        self.assertEqual(calls.count("cache-parent-staged"), 1)
        self.assertLess(calls.index("prepare"), calls.index("privacy-start"))
        self.assertLess(calls.index("privacy-start"), calls.index("api-serve"))
        self.assertLess(calls.index("api-serve"), calls.index("controller-publish"))
        self.assertLess(calls.index("controller-publish"), calls.index("paths"))
        self.assertLess(calls.index("paths"), calls.index("privacy-stop"))
        self.assertLess(calls.index("privacy-stop"), calls.index("evidence-guest"))
        self.assertLess(calls.index("evidence-guest"), calls.index("controller-remove"))
        self.assertEqual(calls.count("api-serve"), 1)
        self.assertTrue((self.work / "weather-android-delivery-evidence.json").is_file())
        self.assertFalse((self.libexec / "volparossa-weather-android-control.py").exists())
        self.assertTrue((self.work / "viewer/prepared.json").exists())
        self.assertEqual(list((self.work / "weather-android-cache").iterdir()), [])

    def test_closed_guest_exit_mapping_never_copies_arbitrary_input(self):
        stages = ("BOUNDARY", "SOURCE", "PREPARED", "SELECTION", "CONFIGURATION",
            "API_LIFECYCLE", "API_PRIVATE_CLEANUP", "RECEIPT_CUSTODY", "RECEIPT_SHAPE",
            "RECEIPT_TIMING", "RECEIPT_PUBLICATION", "RECEIPT_COUNTERS", "ACQUISITION",
            "TOPOLOGY_INPUTS", "CACHE_CUSTODY", "PUBLICATION_FILES", "PACKET_CONTROL_ROUTE",
            "PUBLISHER_CLEANUP", "SOURCE_SNAPSHOT", "EXPORT_SHAPE")
        expected = {status: "WEATHER_ANDROID_EVIDENCE_" + stage + "_INVALID"
            for status, stage in enumerate(stages, 20)}
        expected.update({124: "WEATHER_ANDROID_EVIDENCE_TIMEOUT", 125: "WEATHER_ANDROID_EVIDENCE_INTERRUPTED"})
        expected.update({status: "WEATHER_ANDROID_EVIDENCE_SIGNAL" for status in (129, 130, 143, 192)})
        expected.update({status: "WEATHER_ANDROID_EVIDENCE_INVALID"
            for status in (0, 1, 19, 40, 126, 127, 128, 193, 255, "PRIVATE-CANARY/secret")})
        for status, literal in expected.items():
            with self.subTest(status=status):
                result = self.call('fail() { printf "%s\\n" "$1"; exit 77; }\n'
                    'weather_android_evidence_failure "$STATUS"\n', extra=dict(STATUS=str(status)))
                self.assertEqual(result.returncode, 77)
                self.assertEqual(result.stdout, literal + "\n")
                self.assertEqual(result.stderr, "")

    def test_specific_guest_rejection_still_exits_and_cleans_up_once(self):
        result = self.call(self.mocks() + "weather_android_delivery_run\nprintf 'invalid-success\\n'\n",
            extra=dict(TEST_FAILURE="evidence", TEST_EVIDENCE_STATUS="28"))
        self.assertEqual(result.returncode, 77)
        self.assertIn("WEATHER_ANDROID_EVIDENCE_RECEIPT_SHAPE_INVALID", result.stderr)
        self.assertNotIn("invalid-success", result.stdout)
        calls = (self.work / "calls").read_text().splitlines()
        self.assertEqual(calls.count("evidence-guest"), 1)
        self.assertLess(calls.index("privacy-stop"), calls.index("evidence-guest"))
        self.assertIn("controller-remove", calls)
        self.assertIn("publisher-cleanup", calls)
        self.assertFalse((self.work / "weather-android-delivery-evidence.json").read_bytes())

    def test_guest_evidence_failure_is_not_promoted_to_success(self):
        result = self.call(self.mocks() + "weather_android_delivery_run\n", extra=dict(TEST_FAILURE="evidence"))
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("WEATHER_ANDROID_EVIDENCE_INVALID", result.stderr)
        calls = (self.work / "calls").read_text().splitlines()
        self.assertIn("evidence-guest", calls)
        self.assertIn("controller-remove", calls)

    def test_insufficient_remaining_budget_starts_no_api_or_capture(self):
        result = self.call(self.mocks() + "weather_android_delivery_run\n", extra=dict(TEST_REMAINING="599"))
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("WEATHER_ANDROID_TRIAL_BUDGET_INSUFFICIENT", result.stderr)
        calls = (self.work / "calls").read_text().splitlines()
        self.assertNotIn("api-serve", calls); self.assertNotIn("privacy-start", calls)

    def test_existing_cache_or_controller_is_preserved(self):
        for kind in ("cache", "controller"):
            target = self.work / "weather-android-cache" if kind == "cache" else self.libexec / "volparossa-weather-android-control.py"
            if kind == "cache": target.mkdir(mode=0o700)
            else: target.write_text("preserve")
            result = self.call(self.mocks() + "weather_android_delivery_run\n")
            self.assertEqual(result.returncode, 77, result.stderr)
            self.assertTrue(target.exists())
            if kind == "cache": target.rmdir()
            else: self.assertEqual(target.read_text(), "preserve")

    def test_cache_parent_replacement_or_permission_change_prevents_delivery(self):
        for change in ("missing", "replaced", "symlink", "mode", "owner", "group", "identity"):
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir=self.work) as directory:
                path = Path(directory)
                (path / "bin").mkdir()
                result = self.call(self.mocks() + self.change_parent(change) + "weather_android_delivery_run\n",
                    extra=dict(WORK=directory, weather_publisher=str(path / "publisher")))
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn("WEATHER_ANDROID_CACHE_PARENT_CHANGED", result.stderr)
                calls = (path / "calls").read_text().splitlines()
                self.assertNotIn("prepare", calls)
                self.assertNotIn("api-serve", calls)

    def test_early_cache_prepare_rejects_wrong_profile_identity_and_existing_paths(self):
        cases = ({"TEST_PROFILE": value} for value in ("failed", "0", "7", '"6"', "null", "true", "{}"))
        cases = [*cases, *({"TEST_CONTROL_GID": value} for value in ("", "0", "986", "65536", "private")),
            {"WORKER_UID": "984"}, {"AGENT_UID": "985"}, {"TEST_ROOT_UID": "1000"},
            {"TEST_VIRT": "none"}, {"TEST_CACHE_UID": "999"}]
        for extra in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory(dir=self.work) as directory:
                result = self.call(self.mocks(prepare=False) +
                    "weather_client_agent_cache_prepare || exit 77\nprintf 'unexpected-success\\n'\n",
                    extra=dict(WORK=directory, **extra))
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertNotIn("unexpected-success", result.stdout)
        for kind in ("directory", "file", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.work) as directory:
                target = Path(directory) / "weather-android-cache"
                if kind == "directory": target.mkdir(mode=0o710)
                elif kind == "file": target.write_text("preserve")
                else:
                    target.symlink_to(Path(directory) / "absent")
                    # Make a relatime update eligible without sleeping. The
                    # shell's -e check follows this dangling link; that read can
                    # update its atime even though preparation rejects it.
                    os.utime(target, ns=(1, target.lstat().st_mtime_ns), follow_symlinks=False)
                before = target.lstat()
                result = self.call(self.mocks(prepare=False) +
                    "weather_client_agent_cache_prepare || exit 77\n", extra=dict(WORK=directory))
                self.assertEqual(result.returncode, 77, result.stderr)
                after = target.lstat()
                # Read access time is not a no-clobber invariant. Keep inode,
                # ownership, permissions and nanosecond modification/change
                # times strict, and verify the original content separately.
                for field in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                        "st_size", "st_mtime_ns", "st_ctime_ns"):
                    self.assertEqual(getattr(after, field), getattr(before, field), field)
                if kind == "directory": self.assertEqual(list(target.iterdir()), [])
                elif kind == "file": self.assertEqual(target.read_bytes(), b"preserve")
                else: self.assertEqual(target.readlink(), Path(directory) / "absent")
                self.assertFalse((Path(directory) / "install.args").exists())

    def test_client_sandbox_allows_only_exact_profile6_cache_parent(self):
        topology = TOPOLOGY.read_text()
        launch = shell_function(topology, "launch_agent").replace("systemd-run", "test_systemd_run")
        prepare = 'if [ -n "$weather_client_bundle" ]; then\n    weather_client_agent_cache_prepare || fail WEATHER_CLIENT_AGENT_CACHE_PREPARE_FAILED\nfi\n'
        self.assertIn(prepare + 'launch_agent client "$CLIENT"', topology)
        nodes = ("client", "bootstrap1", "relay0", "relay3", "relay4", "relay5", "exit")
        cases = [(version, node, "content-provider", True) for version in range(1, 7) for node in nodes]
        cases += [(6, "client", "content-provider", False), (6, "client", "browser-network", True)]
        for version, node, scenario, bundle in cases:
            with self.subTest(version=version, node=node, scenario=scenario, bundle=bundle), \
                    tempfile.TemporaryDirectory(dir=self.work) as directory:
                body = self.mocks(prepare=False) + self.launch_mocks() + launch + "\n" + prepare
                if not bundle:
                    # Even a forged profile variable cannot widen a non-Weather unit.
                    body += "WEATHER_AGENT_PROFILE_VERSION=6\nWEATHER_ANDROID_CACHE_IDENTITY=untrusted\n"
                body += f"launch_agent {node} fixture-namespace\n"
                result = self.call(body, extra=dict(WORK=directory, TEST_PROFILE=str(version),
                    scenario=scenario, weather_client_bundle="/verified/inputs.tar" if bundle else ""))
                self.good(result)
                arguments = (Path(directory) / "unit.args").read_text().splitlines()
                writable = [value for value in arguments if value.startswith("--property=ReadWritePaths=")]
                expected = f"--property=ReadWritePaths={directory}/state-{node}"
                additional = version == 6 and node == "client" and scenario == "content-provider" and bundle
                if additional: expected += f" {directory}/weather-android-cache"
                self.assertEqual(writable, [expected])
                for value in ("ProtectSystem=strict", "User=volparossa", "Group=volparossa",
                        "SupplementaryGroups=volparossa-users", "NoNewPrivileges=yes", "PrivateMounts=yes",
                        "CapabilityBoundingSet=", "AmbientCapabilities="):
                    self.assertIn("--property=" + value, arguments)
                if scenario == "content-provider" and node == "client":
                    self.assertIn(f"--property=InaccessiblePaths={directory}/state-relay3 {directory}/state-relay4 "
                        f"{directory}/state-relay5 {directory}/content-provider-seed", arguments)
                calls = (Path(directory) / "calls").read_text().splitlines()
                parent = Path(directory) / "weather-android-cache"
                if version == 6 and bundle:
                    self.assertLess(calls.index("cache-parent-staged"), calls.index("agent-launch"))
                    self.assertEqual(list(parent.iterdir()), [])
                    self.assertEqual(parent.stat().st_mode & 0o777, 0o710)
                    self.assertIn(f"-d -o 986 -g 987 -m 0710 {parent}",
                        (Path(directory) / "install.args").read_text().splitlines())
                else: self.assertFalse(parent.exists())

    def test_cache_parent_changes_prevent_client_service_launch(self):
        launch = shell_function(TOPOLOGY.read_text(), "launch_agent").replace("systemd-run", "test_systemd_run")
        for change in ("missing", "replaced", "symlink", "mode", "owner", "group", "identity"):
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir=self.work) as directory:
                result = self.call(self.mocks() + self.launch_mocks() + launch + "\n" +
                    self.change_parent(change) + "launch_agent client fixture-namespace\n",
                    extra=dict(WORK=directory, scenario="content-provider"))
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn("WEATHER_ANDROID_CACHE_PARENT_CHANGED", result.stderr)
                self.assertFalse((Path(directory) / "unit.args").exists())

    def test_additional_writable_mount_does_not_leak_to_next_node(self):
        launch = shell_function(TOPOLOGY.read_text(), "launch_agent").replace("systemd-run", "test_systemd_run")
        self.good(self.call(self.mocks() + self.launch_mocks() + launch + "\n" +
            "launch_agent client fixture-client\nlaunch_agent relay0 fixture-relay\nlaunch_agent exit fixture-exit\n",
            extra=dict(scenario="content-provider")))
        for node in ("client", "relay0", "exit"):
            arguments = (self.work / f"unit-{node}.args").read_text().splitlines()
            writable = [value for value in arguments if value.startswith("--property=ReadWritePaths=")]
            expected = f"--property=ReadWritePaths={self.work}/state-{node}"
            if node == "client": expected += f" {self.work}/weather-android-cache"
            self.assertEqual(writable, [expected])

    @staticmethod
    def change_parent(change):
        return {
            "missing": '/usr/bin/rmdir "$WORK/weather-android-cache"\n',
            "replaced": '/usr/bin/mv "$WORK/weather-android-cache" "$WORK/original-cache"\n'
                '/usr/bin/mkdir -m 0710 "$WORK/weather-android-cache"\n',
            "symlink": '/usr/bin/mv "$WORK/weather-android-cache" "$WORK/original-cache"\n'
                '/usr/bin/ln -s "$WORK/original-cache" "$WORK/weather-android-cache"\n',
            "mode": '/usr/bin/chmod 0700 "$WORK/weather-android-cache"\n',
            "owner": 'TEST_CACHE_UID=999\n',
            "group": 'TEST_CONTROL_GID=999\n',
            "identity": 'WEATHER_ANDROID_CACHE_IDENTITY=\n',
        }[change]

    @staticmethod
    def launch_mocks():
        return r'''
AGENT_UNITS=
binary_directory=/verified/bin
wifi_link=no
agent_train_loop=no
agent_active_recovery=no
agent_adapter_aggregation=no
agent_autonomous_aggregation=no
agent_policy_assessment=no
unit_load_state() { printf 'not-found\n'; }
chown() { :; }
chmod() { :; }
test_systemd_run() {
    record agent-launch
    printf '%s\n' "$@" > "$WORK/unit.args"
    printf '%s\n' "$@" > "$WORK/unit-$node.args"
}
'''

    def test_cleanup_attempts_independent_resources_without_browser_private_delete(self):
        result = self.call('''
weather_android_stop_api() { printf 'api\n'; return 1; }
weather_android_stop_observers() { printf 'observers\n'; return 1; }
weather_android_controller_cleanup() { printf 'controller\n'; return 1; }
weather_products_private() { printf '%s\n' "$1" >> "$WORK/calls"; return 1; }
weather_client_home_cleanup() { exit 88; }
if weather_client_delivery_cleanup; then exit 90; fi
''')
        self.good(result)
        self.assertEqual(result.stdout.splitlines(), ["api", "observers", "controller"])
        self.assertEqual((self.work / "calls").read_text(), "publisher-cleanup\n")

    def test_recycled_or_missing_pid_is_never_signalled(self):
        self.good(self.call('''
WEATHER_ANDROID_API_PID=1
WEATHER_ANDROID_API_IDENTITY=original
weather_android_process_identity() { printf 'replacement\n'; }
kill() { exit 89; }
wait() { return 1; }
if weather_android_stop_api; then exit 90; fi
[ "$WEATHER_ANDROID_API_JOINED" = yes ]
'''))

    def test_unknown_or_live_process_is_not_unboundedly_waited(self):
        for state in ("initial-identity-missing", "probe-failed", "still-alive"):
            with self.subTest(state=state):
                self.good(self.call('''
WEATHER_ANDROID_API_PID=12345
WEATHER_ANDROID_API_IDENTITY=original
case STATE in
    initial-identity-missing) WEATHER_ANDROID_API_IDENTITY= ;;
    probe-failed) weather_android_process_identity() { return 2; } ;;
    still-alive) weather_android_process_identity() { printf 'original\\n'; } ;;
esac
wait() { exit 89; }
if weather_android_join_api; then exit 90; fi
[ "$WEATHER_ANDROID_API_JOINED" = no ]
'''.replace("STATE", state)))

    def test_inconclusive_process_probe_preserves_cleanup_failure(self):
        self.good(self.call('''
WEATHER_ANDROID_API_PID=12345
WEATHER_ANDROID_API_IDENTITY=original
weather_android_process_identity() { return 2; }
kill() { exit 89; }
wait() { exit 90; }
if weather_android_stop_api; then exit 91; fi
[ "$WEATHER_ANDROID_API_JOINED" = no ]
'''))

    def test_worker_boundary_original_deadline_and_export_contract_are_fixed(self):
        source = SOURCE.read_text()
        serve = source[source.index('    ip netns exec "$CLIENT" setpriv'):source.index('    WEATHER_ANDROID_API_PID=$!')]
        for fragment in ('--reuid="$WORKER_UID"', '--regid="$site_control_gid"', '--clear-groups',
                '--inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs',
                '"$WEATHER_PRODUCTS_DEADLINE"', '"$WORK/bin/weather-android-api.py" serve'):
            self.assertIn(fragment, serve)
        for forbidden in (" curl ", " wget ", " cold ", " prewarm", "user-cleanup", "smoke_core_browser.py"):
            # Comments explain the deliberate absence; executable lines do not.
            executable = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
            self.assertNotIn(forbidden, executable)
        self.assertIn('"$WORK/bin/weather-android-evidence.py" guest "$WORK" "$weather_client_manifest_sha256"', source)
        self.assertIn('"$WORK/bin/weather-android-evidence.py" copy-artifacts "$WORK"', source)

    @staticmethod
    def mocks(prepare=True):
        source = r'''
record() { printf '%s\n' "$1" >> "$WORK/calls"; }
id() { printf '%s\n' "${TEST_ROOT_UID:-0}"; }
test_virt() { printf '%s\n' "${TEST_VIRT:-kvm}"; }
getent() { printf 'volparossa-users:x:%s:\n' "$TEST_CONTROL_GID"; }
weather_client_runtime_profile() {
    [ "$TEST_PROFILE" != failed ] || return 1
    printf '{"bundle_version":%s}\n' "$TEST_PROFILE"
}
date() { printf '1000\n'; }
stat() {
    if [ "$3" = "$WORK/weather-android-cache" ]; then
        case $2 in
            '%u:%g:%a') /usr/bin/stat -Lc "$TEST_CACHE_UID:$TEST_CONTROL_GID:%a" "$3" ;;
            '%d:%i:%u:%g:%a') /usr/bin/stat -Lc "%d:%i:$TEST_CACHE_UID:$TEST_CONTROL_GID:%a" "$3" ;;
            *) /usr/bin/stat "$@" ;;
        esac
    elif [ "$2" = '%u:%g:%a' ]; then printf '0:0:755\n';
    else /usr/bin/stat "$@"; fi
}
fail() { printf '%s\n' "$1" >&2; exit 77; }
weather_products_remaining() {
    if [ "$1" = 840 ]; then printf '%s\n' "$TEST_REMAINING"; else printf '%s\n' "$1"; fi
}
install() {
    printf '%s\n' "$*" >> "$WORK/install.args"
    directory=no; mode=0710; previous=
    for value do
        [ "$value" != -d ] || directory=yes
        [ "$previous" != -m ] || mode=$value
        previous=$value; target=$value
    done
    if [ "$directory" = yes ]; then
        /usr/bin/mkdir -m "$mode" -- "$target"
        [ "$target" != "$WORK/weather-android-cache" ] || record cache-parent-staged
    else
        previous=
        for value do source=$previous; previous=$value; done
        /usr/bin/install -m 0400 -- "$source" "$target"
    fi
}
timeout() { record prepare; printf '{"inert_prepare":true}\n'; }
start_privacy_observers() { record privacy-start; }
content_provider_start_control_observer() { record control-start; }
stop_privacy_observers() { record privacy-stop; }
content_provider_stop_control_observer() { record control-stop; }
benchmark_capture_paths() { record paths; }
weather_client_verify_tree() { record tree-after; printf '{"inert_tree":true}\n'; }
weather_products_private() { record "$1"; printf '{"inert_cleanup":true}\n'; }
ip() {
    record api-serve
    printf '{"inert_ready":true}\n'
    while [ ! -f "$WORK/inert-finalize" ]; do /usr/bin/sleep 0.01; done
    printf '{"inert_final":true}\n'
}
python3() {
    case "$2:$3" in
        */weather-android-control.py:publish)
            record controller-publish; /usr/bin/touch "$WORK/inert-finalize"; printf '{"inert_published":true}\n' ;;
        */weather-android-control.py:remove)
            record controller-remove; printf '{"inert_removed":true}\n' ;;
        */weather-android-evidence.py:guest)
            record evidence-guest; [ "$TEST_FAILURE" != evidence ] || return "${TEST_EVIDENCE_STATUS:-1}"; printf '{"inert_evidence":true}\n' ;;
        *) return 98 ;;
    esac
}
trap 'weather_client_delivery_cleanup || true' EXIT
'''
        if prepare:
            source += "weather_client_agent_cache_prepare || fail WEATHER_CLIENT_AGENT_CACHE_PREPARE_FAILED\n"
        return source


if __name__ == "__main__": unittest.main()
