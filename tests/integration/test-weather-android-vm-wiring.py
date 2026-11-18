#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Execute inert VM-runner wiring; never start QEMU, SSH, SDK or a build.

Extracted shell blocks are the actual runner source. Process launch boundaries
are recording functions; diagnostic JSON still passes the real closed validator.
These fixtures are not evidence of an Android/core runtime or network datapath.
"""
import copy
import json
import os
from pathlib import Path
import runpy
import shlex
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run-alpha-topology-vm.sh"
SHA = "b" * 64
COMMIT = "a" * 40
SUMMARY = "weather-android-delivery-evidence.json"
FIXTURES = runpy.run_path(str(HERE / "test-weather-android-evidence.py"))
E = FIXTURES["E"]
D = runpy.run_path(str(HERE / "weather-android-inner-diagnostic.py"))


def source():
    return RUNNER.read_text()


def shell(script, *args):
    return subprocess.run(["/bin/sh", "-c", script, "inert-wiring", *map(str, args)],
        capture_output=True, timeout=10)


def function(name):
    return name + "() {\n" + source().split(name + "() {\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"


class ArgumentsAndResources(unittest.TestCase):
    def required(self, scenario="content-provider", bundle=True):
        result = ["--execute", "--yes", "--scenario", scenario, "--output", "/unread/output",
            "--expected-commit", COMMIT, "--image", "/unread/image", "--mpquic", "/unread/native"]
        if bundle: result += ["--weather-client-bundle", "/unread/bundle", "--weather-client-manifest-sha256", SHA]
        return result

    def call(self, *args, env=None):
        return subprocess.run(["/bin/sh", str(RUNNER), *args], capture_output=True, timeout=5, env=env)

    def test_new_source_argument_is_explicit_canonical_paired_and_not_preview_authority(self):
        flag = "--weather-android-source"
        cases = [["--preview", flag, "/unread/source"], [*self.required(), flag],
            [*self.required(), flag, ""], [*self.required(), flag, "/unread/source", flag, "/other"],
            [*self.required(bundle=False), flag, "/unread/source"],
            [*self.required("content"), flag, "/unread/source"]]
        for path in ("relative", "/", "/unread/", "/unread//source", "/unread/../source",
                "/unread/./source", "/unread/..", "/unread/.", "/unread/line\nsource", "/unread/\tsource"):
            cases.append([*self.required(), flag, path])
        for args in cases:
            with self.subTest(args=args):
                result = self.call(*args)
                self.assertEqual(result.returncode, 64, result.stderr)
        env = dict(os.environ, weather_android_source="/unread/inherited", weather_client_version="6")
        result = self.call("--preview", "--scenario", "content-provider", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"PREVIEW ONLY", result.stdout)

    def test_legacy_profiles_keep_six_gib_total_android_requires_ten_before_launch(self):
        gate = "guest_memory_mib=$(guest_memory_for_scenario)\n" + source().split(
            "guest_memory_mib=$(guest_memory_for_scenario)\n", 1)[1].split("qemu_usernet=", 1)[0]
        script = ("set -eu\nscenario=content-provider\nweather_client_version=$1\nfixture_available=$2\n"
            'awk() { printf "%s\\n" "$fixture_available"; }\n' + function("guest_memory_for_scenario") + gate +
            'printf "%s:%s\\n" "$guest_memory_mib" "$runner_reserve_mib"\n')
        for profile in ("", "1", "2", "3", "4", "5", "6"):
            reserve = 6144 if profile == "6" else 2048
            required = (4096 + reserve) * 1024
            for available, expected in ((required - 1, 69), (required, 0), ("unknown", 69)):
                with self.subTest(profile=profile, available=available):
                    result = shell(script, profile, available)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected == 0: self.assertEqual(result.stdout.decode().strip(), f"4096:{reserve}")
        self.assertLess(source().index("guest_memory_mib=$(guest_memory_for_scenario)"),
            source().index("\nqemu-system-x86_64 \\\n"))

    def test_preflight_dispatch_uses_admitted_commit_only_for_android(self):
        fragment = "weather_client_version=$(python3" + source().split("weather_client_version=$(python3", 1)[1].split(
            "    printf '%s\\n' 'Additional proof: public model HTTPS acquisition", 1)[0]
        script = ("set -eu\nfixture_profile=$1\nweather_android_source=$2\nHERE=$3\nexpected_commit=$4\n"
            "WEATHER_CLIENT_ARCHIVE=/inert/archive\nWEATHER_CLIENT_MANIFEST_SHA256=$5\noutput_directory=/inert/output\n"
            "RUN_DIRECTORY=/inert/weather-client-kvm.ABCDEF\n"
            '''python3() {
    if [ "$3" = runtime-version ]; then printf '{"bundle_version":%s}\\n' "$fixture_profile"
    else printf '%s\\n' "$@"; fi
}
''' + fragment)
        weather_commit = json.loads((HERE / "weather-public-android-v6.json").read_bytes())["sources"]["weather"]["commit"]
        for version in range(1, 7):
            for selected in ("", "/inert/prepared-weather"):
                with self.subTest(version=version, selected=selected):
                    result = shell(script, version, selected, HERE, COMMIT, SHA)
                    expected = 0 if (version == 6) == bool(selected) else 64
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected == 0 and version == 6:
                        self.assertEqual(result.stdout.decode().splitlines(), ["-B", str(HERE / "weather-android-owner.py"),
                            "preflight", "--weather-root", selected, "--core-commit", COMMIT, "--weather-commit", weather_commit,
                            "--kvm-output", "/inert/output", "--kvm-baseline", "/inert/weather-client-kvm.ABCDEF/kvm-before-vm.json"])
                    else: self.assertEqual(result.stdout, b"")


class DispatchAndStaging(unittest.TestCase):
    def test_guest_stages_only_the_fixed_root_owned_api_tunnel_for_six(self):
        guest = source().split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
        fragment = "weather_guest_profile=$(python3" + guest.split("weather_guest_profile=$(python3", 1)[1].split("\nfi\n", 1)[0]
        script = '''set -eu
fixture_profile=$1
weather_client_manifest_sha256=inert
python3() { printf '{"bundle_version":%s}\\n' "$fixture_profile"; }
sudo() { printf 'sudo'; printf ' <%s>' "$@"; printf '\\n'; }
test() { printf 'test'; printf ' <%s>' "$@"; printf '\\n'; }
''' + fragment
        fixed = "/usr/local/libexec/volparossa-weather-android-tunnel.py"
        for version in range(1, 7):
            result = shell(script, version)
            self.assertEqual(result.returncode, 0, result.stderr)
            if version != 6: self.assertEqual(result.stdout, b""); continue
            self.assertEqual(result.stdout.decode().splitlines(), [
                "sudo <-n> <install> <-d> <-o> <root> <-g> <root> <-m> <0755> </usr/local/libexec>",
                f"test <!> <-e> <{fixed}>", f"test <!> <-L> <{fixed}>",
                "sudo <-n> <install> <-o> <root> <-g> <root> <-m> <0555> "
                f"<tests/integration/weather-android-tunnel.py> <{fixed}>"])

    def test_real_dispatch_writes_exact_private_config_and_retains_legacy_driver(self):
        fragment = "case $scenario in\n    content-provider)\n" + source().split(
            "case $scenario in\n    content-provider)\n", 1)[1].split("\nGUEST_STATUS=$?", 1)[0]
        with tempfile.TemporaryDirectory(prefix="android-vm-wiring-", dir=HERE) as temporary:
            root = Path(temporary).resolve()
            for version in range(1, 7):
                work = root / str(version); work.mkdir()
                script = '''set -eu
umask 077
weather_client_version=$1
RUN_DIRECTORY=$2
HERE=$3
scenario=content-provider
weather_client_bundle=/inert/bundle
browser_filter_bundle=
driver_time_bound=2400s
expected_commit=$4
weather_android_commit=$4
weather_android_source=/inert/prepared-weather
output_directory=/inert/output
SOURCE_SHA256=$5
MPQUIC_SHA256=$5
PACKAGE_SHA256=none
WEATHER_CLIENT_ARCHIVE_SHA256=$5
WEATHER_CLIENT_MANIFEST_SHA256=$5
python3() { printf 'python3\\n'; printf '%s\\n' "$@"; }
ssh_bounded() { printf 'ssh_bounded\\n'; printf '%s\\n' "$@"; }
''' + fragment
                result = shell(script, version, work, HERE, COMMIT, SHA)
                self.assertEqual(result.returncode, 0, result.stderr)
                config = work / "android-owner-input.json"
                if version != 6:
                    self.assertFalse(config.exists())
                    self.assertEqual(result.stdout.decode().splitlines(), ["ssh_bounded", "2400s", "/home/vpci/guest-driver.sh",
                        COMMIT, SHA, SHA, "none", "content-provider", "weather-client", SHA, SHA])
                    continue
                self.assertEqual(result.stdout.decode().splitlines(), ["python3", "-B", str(HERE / "weather-android-owner.py"),
                    "run", "--config", str(config)])
                self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
                self.assertEqual(json.loads(config.read_bytes()), dict(schema=6, core_commit=COMMIT, weather_commit=COMMIT,
                    weather_root="/inert/prepared-weather", run_directory=str(work), output_directory="/inert/output",
                    source_sha256=SHA, mpquic_sha256=SHA, package_sha256="none", weather_archive_sha256=SHA,
                    weather_manifest_sha256=SHA))

    def test_join_runs_only_after_retrieval_and_cannot_mask_failure(self):
        text = source()
        fragment = text.split('tar -C "$output_directory" -xzf "$RUN_DIRECTORY/alpha-output.tar.gz"\n', 1)[1].split(
            "if grep -aERq", 1)[0]
        for profile, guest_status, join_status, expected in (("5", 0, 0, 0), ("6", 1, 0, 1),
                ("6", 0, 0, 0), ("6", 0, 1, 1)):
            script = '''set -eu
weather_client_version=$1
GUEST_STATUS=$2
fixture_join_status=$3
HERE=/inert/helpers
WEATHER_ANDROID_CONFIG=/inert/private/android-owner-input.json
python3() { printf 'join-called\\n'; return "$fixture_join_status"; }
''' + fragment + 'printf "status=%s\\n" "$GUEST_STATUS"\n'
            result = shell(script, profile, guest_status, join_status)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(b"join-called" in result.stdout, profile == "6" and guest_status == 0)
            self.assertTrue(result.stdout.endswith(f"status={expected}\n".encode()))
        self.assertLess(text.index('tar -C "$output_directory" -xzf "$RUN_DIRECTORY/alpha-output.tar.gz"'),
            text.index('weather-android-owner.py" join'))

    def test_background_owner_keeps_its_exit_status_and_clears_only_after_wait(self):
        start = '            python3 -B "$HERE/weather-android-owner.py" run --config "$WEATHER_ANDROID_CONFIG" &\n'
        fragment = start + source().split(start, 1)[1].split('        elif [ -n "$weather_client_bundle" ]; then', 1)[0]
        for status in (0, 17, 143):
            with self.subTest(status=status):
                script = '''set -u
fixture_status=$1
HERE=/inert/helpers
WEATHER_ANDROID_CONFIG=/inert/private/input.json
WEATHER_ANDROID_OWNER_PID=
python3() { return "$fixture_status"; }
''' + fragment + '''
observed=$?
printf '%s:%s\\n' "$observed" "$WEATHER_ANDROID_OWNER_PID"
'''
                result = shell(script, status)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode().strip(), f"{status}:")


class CleanupReceipt(unittest.TestCase):
    def exercise(self, *, profile="6", fail_status=0, keep=False, existing=False, blank_commit=False, inner=False):
        with tempfile.TemporaryDirectory(prefix="android-vm-cleanup-", dir=HERE) as temporary:
            root = Path(temporary).resolve()
            work = root / "weather-client-kvm.ABC123"; work.mkdir(mode=0o700)
            (work / "guest-key").write_text("INERT PRIVATE CANARY")
            output = root / "evidence"; output.mkdir(mode=0o700)
            receipt = output / "weather-android-vm-cleanup.json"
            if existing: receipt.write_bytes(b"existing-owned-receipt\n")
            if inner:
                observation = D["receipt"](dict(core_commit=COMMIT, weather_commit=D["WEATHER_COMMIT"],
                    run_id="123", run_attempt="1"), dict.fromkeys(D["INPUTS"], dict(state="absent", facts=None)))
                inner_raw = D["encoded"](observation)
                (output / D["NAME"]).write_bytes(inner_raw)
            script = '''set -eu
umask 077
scenario=content-provider
RUN_DIRECTORY_PARENT=$1
RUN_DIRECTORY=$1/weather-client-kvm.ABC123
RUN_DIRECTORY_PREFIX=weather-client-kvm
output_directory=$1/evidence
weather_client_version=$2
expected_commit=$3
weather_android_commit=$4
WEATHER_CLIENT_MANIFEST_SHA256=$5
QEMU_PID=
QEMU_BIRTH=
QEMU_STOP_ATTEMPTED=no
QEMU_STARTED=no
QEMU_JOINED=no
WEATHER_ANDROID_OWNER_PID=
FINISHED=no
''' + function("stop_qemu_child") + function("cleanup")
            if keep: script += "rm() { :; }\n"
            script += 'trap cleanup EXIT\nexit "$6"\n'
            result = shell(script, root, profile, COMMIT, "" if blank_commit else COMMIT, SHA, fail_status)
            if inner: self.assertEqual((output / D["NAME"]).read_bytes(), inner_raw)
            return result, receipt.read_bytes() if receipt.exists() else None, work.exists(), list(output.iterdir())

    def test_cleanup_record_is_closed_after_private_state_removal_not_acceptance(self):
        for failure in (0, 64, 143):
            result, raw, remains, files = self.exercise(fail_status=failure)
            self.assertEqual(result.returncode, failure, result.stderr)
            self.assertFalse(remains)
            self.assertEqual([path.name for path in files], ["weather-android-vm-cleanup.json"])
            self.assertEqual(json.loads(raw), dict(schema=6, kind="weather-android-vm-cleanup", core_commit=COMMIT,
                weather_commit=COMMIT, manifest_sha256=SHA, driver_finished=False, qemu_started=False, qemu_joined=False,
                private_guest_state_removed=True, owner_exit_status=failure, joined_core_acceptance=False))
            self.assertNotIn(b"PRIVATE CANARY", raw)

    def test_failed_removal_cannot_report_cleanup_success_or_replace_owned_record(self):
        result, raw, remains, _ = self.exercise(keep=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(remains)
        self.assertFalse(json.loads(raw)["private_guest_state_removed"])
        self.assertEqual(json.loads(raw)["owner_exit_status"], 1)
        result, raw, remains, _ = self.exercise(existing=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(remains)
        self.assertEqual(raw, b"existing-owned-receipt\n")

    def test_optional_host_diagnostic_survives_vm_cleanup_without_becoming_acceptance(self):
        result, raw, remains, files = self.exercise(fail_status=1, inner=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(remains)
        self.assertEqual({path.name for path in files}, {D["NAME"], "weather-android-vm-cleanup.json"})
        self.assertFalse(json.loads(raw)["joined_core_acceptance"])
        self.assertEqual(json.loads(raw)["owner_exit_status"], 1)

    def test_early_profile_six_failure_has_initialized_identity_and_legacy_no_new_record(self):
        initial = source().split("guest_memory_for_scenario()", 1)[0]
        initialized = shell(initial + 'printf "%s:%s" "$weather_android_commit" "$weather_client_version"')
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        self.assertEqual(initialized.stdout, b":")
        result, raw, remains, _ = self.exercise(fail_status=64, blank_commit=True)
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertFalse(remains)
        self.assertEqual(json.loads(raw)["weather_commit"], "")
        self.assertFalse(json.loads(raw)["joined_core_acceptance"])
        for version in map(str, range(1, 6)):
            result, raw, remains, _ = self.exercise(profile=version)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(raw); self.assertFalse(remains)

    def test_bounded_stop_sets_join_only_after_confirmation_and_reap_or_retains_private_state(self):
        for original in (0, 17, 143):
            for confirmed in (False, True):
                for normal in (False, True):
                    with self.subTest(original=original, confirmed=confirmed, normal=normal), \
                            tempfile.TemporaryDirectory(prefix="android-vm-confirmation-", dir=HERE) as temporary:
                        parent = Path(temporary).resolve()
                        work = parent / "weather-client-kvm.ABC123"; work.mkdir(mode=0o700)
                        (work / "guest-key").write_text("INERT PRIVATE CANARY")
                        output = parent / "evidence"; output.mkdir(mode=0o700)
                        script = '''set -eu
umask 077
scenario=content-provider
RUN_DIRECTORY_PARENT=$1
RUN_DIRECTORY=$1/weather-client-kvm.ABC123
RUN_DIRECTORY_PREFIX=weather-client-kvm
output_directory=$1/evidence
HERE=/inert/source
weather_client_version=6
expected_commit=$2
weather_android_commit=$2
WEATHER_CLIENT_MANIFEST_SHA256=$3
QEMU_PID=123
QEMU_BIRTH=456
QEMU_STOP_ATTEMPTED=no
QEMU_STARTED=yes
QEMU_JOINED=no
WEATHER_ANDROID_OWNER_PID=
FINISHED=no
GUEST_STATUS=$4
fixture_stop_status=$5
timeout() { printf 'confirmed-boundary:%s\\n' "$QEMU_JOINED" >>"$RUN_DIRECTORY_PARENT/events"; return "$fixture_stop_status"; }
wait() { printf 'reap:%s\\n' "$QEMU_JOINED" >>"$RUN_DIRECTORY_PARENT/events"; return 0; }
''' + function("stop_qemu_child") + function("cleanup") + '''
trap cleanup EXIT
if [ "$6" = yes ]; then
    if ! stop_qemu_child normal; then [ "$GUEST_STATUS" -ne 0 ] || GUEST_STATUS=1; fi
fi
exit "$GUEST_STATUS"
'''
                        result = shell(script, parent, COMMIT, SHA, original, 0 if confirmed else 1,
                            "yes" if normal else "no")
                        expected = original if confirmed else original or 1
                        self.assertEqual(result.returncode, expected, result.stderr)
                        events = (parent / "events").read_text().splitlines()
                        self.assertEqual(events, ["confirmed-boundary:no"] + (["reap:no"] if confirmed else []))
                        receipt = json.loads((output / "weather-android-vm-cleanup.json").read_bytes())
                        self.assertIs(receipt["qemu_joined"], confirmed)
                        self.assertIs(receipt["private_guest_state_removed"], confirmed)
                        self.assertEqual(receipt["owner_exit_status"], expected)
                        self.assertFalse(receipt["joined_core_acceptance"])
                        self.assertEqual(work.exists(), not confirmed)
                        if not confirmed:
                            self.assertEqual((work / "guest-key").read_text(), "INERT PRIVATE CANARY")
                        self.assertNotIn("PRIVATE CANARY", json.dumps(receipt))
        self.assertEqual(source().count("QEMU_JOINED=yes"), 1)

    def test_cleanup_joins_live_and_already_exited_owned_children_before_removing_state(self):
        # A harmless child exercises the actual trap, including its already-
        # exited branch. It is not QEMU and does not start any guest/network.
        # Isolate the fixture process group so a regression cannot leak it.
        with tempfile.TemporaryDirectory(prefix="android-vm-child-", dir=HERE) as temporary:
            root = Path(temporary).resolve()
            for child_state in ("live", "exited"):
                with self.subTest(child_state=child_state):
                    parent = root / child_state; parent.mkdir()
                    work = parent / "weather-client-kvm.ABC123"; work.mkdir(mode=0o700)
                    output = parent / "evidence"; output.mkdir(mode=0o700)
                    (work / "guest-key").write_text("INERT PRIVATE CANARY")
                    script = '''set -eu
umask 077
scenario=content-provider
RUN_DIRECTORY_PARENT=$1
RUN_DIRECTORY=$1/weather-client-kvm.ABC123
RUN_DIRECTORY_PREFIX=weather-client-kvm
output_directory=$1/evidence
weather_client_version=6
expected_commit=$2
weather_android_commit=$2
WEATHER_CLIENT_MANIFEST_SHA256=$3
HERE=$5
QEMU_PID=
QEMU_BIRTH=
QEMU_STOP_ATTEMPTED=no
QEMU_STARTED=yes
QEMU_JOINED=no
WEATHER_ANDROID_OWNER_PID=
FINISHED=no
''' + function("stop_qemu_child") + function("cleanup") + '''
trap cleanup EXIT
sleep 30 </dev/null >/dev/null 2>&1 &
QEMU_PID=$!
QEMU_BIRTH=$(python3 -B -c 'import runpy,sys; print(runpy.run_path(sys.argv[1])["identity"](int(sys.argv[2]))[1])' "$HERE/qemu-child-lifecycle.py" "$QEMU_PID")
printf '%s\\n' "$QEMU_PID"
if [ "$4" = exited ]; then kill -TERM "$QEMU_PID"; wait "$QEMU_PID" || true; fi
exit 143
'''
                    process = subprocess.Popen(["/bin/sh", "-c", script, "inert-child-cleanup",
                        str(parent), COMMIT, SHA, child_state, str(HERE)], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, start_new_session=True)
                    try:
                        stdout, stderr = process.communicate(timeout=10)
                        self.assertEqual(process.returncode, 143, stderr)
                        child = int(stdout.strip())
                        with self.assertRaises(ProcessLookupError): os.kill(child, 0)
                        self.assertFalse(work.exists())
                        value = json.loads((output / "weather-android-vm-cleanup.json").read_bytes())
                        self.assertTrue(value["qemu_started"])
                        self.assertTrue(value["qemu_joined"])
                        self.assertTrue(value["private_guest_state_removed"])
                        self.assertEqual(value["owner_exit_status"], 143)
                        self.assertFalse(value["joined_core_acceptance"])
                    finally:
                        try: os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        process.communicate(timeout=5)

    def test_shell_only_term_reaches_owner_before_guest_and_private_state_cleanup(self):
        fragment = "case $scenario in\n    content-provider)\n" + source().split(
            "case $scenario in\n    content-provider)\n", 1)[1].split("\nGUEST_STATUS=$?", 1)[0]
        owner = '''import json, os, signal
from pathlib import Path
root = Path(os.environ['fixture_parent'])
def stop(*_):
    os.kill(int(os.environ['QEMU_PID']), 0)
    assert (root / 'weather-client-kvm.ABC123/guest-key').read_text() == 'INERT PRIVATE CANARY'
    (root / 'owner-stopped.json').write_text(json.dumps({'owner': os.getpid(), 'guest_alive': True, 'private_state_present': True}))
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
(root / 'owner-ready.json').write_text(json.dumps({'owner': os.getpid(), 'guest': int(os.environ['QEMU_PID'])}))
while True: signal.pause()
'''
        with tempfile.TemporaryDirectory(prefix="android-vm-owner-term-", dir=HERE) as temporary:
            parent = Path(temporary).resolve()
            work = parent / "weather-client-kvm.ABC123"; work.mkdir(mode=0o700)
            output = parent / "evidence"; output.mkdir(mode=0o700)
            (work / "guest-key").write_text("INERT PRIVATE CANARY")
            script = '''set -eu
umask 077
fixture_parent=$1
RUN_DIRECTORY_PARENT=$1
RUN_DIRECTORY=$1/weather-client-kvm.ABC123
RUN_DIRECTORY_PREFIX=weather-client-kvm
output_directory=$1/evidence
HERE=$2
expected_commit=$3
weather_android_commit=$3
SOURCE_SHA256=$4
MPQUIC_SHA256=$4
WEATHER_CLIENT_ARCHIVE_SHA256=$4
WEATHER_CLIENT_MANIFEST_SHA256=$4
fixture_owner_code=$5
PACKAGE_SHA256=none
weather_client_version=6
weather_android_source=/inert/prepared-weather
scenario=content-provider
QEMU_PID=
QEMU_BIRTH=
QEMU_STOP_ATTEMPTED=no
QEMU_STARTED=yes
QEMU_JOINED=no
WEATHER_ANDROID_OWNER_PID=
FINISHED=no
''' + function("stop_qemu_child") + function("cleanup") + '''
trap cleanup EXIT
trap 'exit 143' TERM
sleep 30 </dev/null >/dev/null 2>&1 &
QEMU_PID=$!
QEMU_BIRTH=$(python3 -B -c 'import runpy,sys; print(runpy.run_path(sys.argv[1])["identity"](int(sys.argv[2]))[1])' "$HERE/qemu-child-lifecycle.py" "$QEMU_PID")
export QEMU_PID fixture_parent
python3() {
    test "$#" = 5 && test "$1" = -B && test "$3" = run && test "$4" = --config
    test "$2" = "$HERE/weather-android-owner.py" && test -f "$5"
    exec /usr/bin/python3 -B -c "$fixture_owner_code"
}
set +e
''' + fragment + '\nexit "$?"\n'
            process = subprocess.Popen(["/bin/sh", "-c", script, "inert-owner-term", str(parent),
                str(HERE), COMMIT, SHA, owner], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True)
            try:
                ready_path = parent / "owner-ready.json"
                until = time.monotonic() + 3
                while not ready_path.exists():
                    if process.poll() is not None or time.monotonic() >= until:
                        self.fail("inert owner did not become ready")
                    time.sleep(0.01)
                # The marker is written by a tiny process, but publication can
                # overlap the read. Only complete JSON is readiness evidence.
                while True:
                    try: ready = json.loads(ready_path.read_bytes()); break
                    except json.JSONDecodeError:
                        if time.monotonic() >= until: raise
                        time.sleep(0.01)
                os.kill(process.pid, signal.SIGTERM)  # Deliberately not killpg.
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143, stderr)
                for child in ready.values():
                    with self.assertRaises(ProcessLookupError): os.kill(child, 0)
                self.assertEqual(json.loads((parent / "owner-stopped.json").read_bytes()),
                    dict(owner=ready["owner"], guest_alive=True, private_state_present=True))
                self.assertFalse(work.exists())
                receipt = json.loads((output / "weather-android-vm-cleanup.json").read_bytes())
                self.assertEqual(receipt["owner_exit_status"], 143)
                self.assertTrue(receipt["qemu_joined"])
                self.assertTrue(receipt["private_guest_state_removed"])
                self.assertFalse(receipt["joined_core_acceptance"])
            finally:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.communicate(timeout=5)

    def test_already_exited_owner_is_reaped_without_changing_original_failure(self):
        with tempfile.TemporaryDirectory(prefix="android-vm-owner-exited-", dir=HERE) as temporary:
            parent = Path(temporary).resolve()
            work = parent / "weather-client-kvm.ABC123"; work.mkdir(mode=0o700)
            output = parent / "evidence"; output.mkdir(mode=0o700)
            script = '''set -eu
umask 077
scenario=content-provider
RUN_DIRECTORY_PARENT=$1
RUN_DIRECTORY=$1/weather-client-kvm.ABC123
RUN_DIRECTORY_PREFIX=weather-client-kvm
output_directory=$1/evidence
weather_client_version=6
expected_commit=$2
weather_android_commit=$2
WEATHER_CLIENT_MANIFEST_SHA256=$3
QEMU_PID=
QEMU_BIRTH=
QEMU_STOP_ATTEMPTED=no
QEMU_STARTED=no
QEMU_JOINED=no
FINISHED=no
''' + function("stop_qemu_child") + function("cleanup") + '''
trap cleanup EXIT
/bin/sh -c 'exit 17' </dev/null >/dev/null 2>&1 &
WEATHER_ANDROID_OWNER_PID=$!
wait "$WEATHER_ANDROID_OWNER_PID" || true
printf '%s\\n' "$WEATHER_ANDROID_OWNER_PID"
exit 64
'''
            result = shell(script, parent, COMMIT, SHA)
            self.assertEqual(result.returncode, 64, result.stderr)
            with self.assertRaises(ProcessLookupError): os.kill(int(result.stdout.strip()), 0)
            self.assertFalse(work.exists())
            receipt = json.loads((output / "weather-android-vm-cleanup.json").read_bytes())
            self.assertEqual(receipt["owner_exit_status"], 64)
            self.assertTrue(receipt["private_guest_state_removed"])
            self.assertFalse(receipt["qemu_started"])
            self.assertFalse(receipt["joined_core_acceptance"])


class ClosedEmergencyExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        body = source().split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        cls.api = {"__name__": "inert_android_vm_collector"}
        exec(compile(body, "inert-vm-diagnostics", "exec"), cls.api)

    def test_android_helper_requires_immutable_complete_closure_no_legacy_fallback(self):
        self.assertEqual(self.api["WEATHER_ANDROID_NAMES"], {SUMMARY})
        self.assertNotIn("weather-android-owner.py", self.api["WEATHER_ANDROID_HELPERS"])
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve(); directory = work / "bin"; directory.mkdir()
            for name in self.api["WEATHER_ANDROID_HELPERS"]:
                (directory / name).write_text("inert; not executable\n")
            original = Path.lstat
            bad, fault = None, {}
            def root_owned(path):
                actual = original(path)
                values = dict(st_mode=actual.st_mode & ~0o022, st_uid=0, st_nlink=actual.st_nlink, st_size=actual.st_size)
                if path == bad: values.update(fault)
                return SimpleNamespace(**values)
            with patch.object(Path, "lstat", root_owned):
                self.assertEqual(self.api["weather_client_helper"](work), directory / "weather-android-evidence.py")
                for name in self.api["WEATHER_ANDROID_HELPERS"]:
                    bad = directory / name
                    for fault in (dict(st_uid=1000), dict(st_nlink=2), dict(st_mode=stat.S_IFREG | 0o666),
                            dict(st_size=262145), dict(st_mode=stat.S_IFLNK | 0o555)):
                        with self.subTest(name=name, fault=fault):
                            self.assertIsNone(self.api["weather_client_helper"](work))
                bad, fault = None, {}
                helper = directory / "weather-android-evidence.py"
                helper.unlink(); helper.symlink_to("missing-android-helper")
                self.assertIsNone(self.api["weather_client_helper"](work))
                helper.unlink()
                self.assertEqual(self.api["weather_client_helper"](work), directory / "weather-products-delivery.py")

    def collect(self, value, *, limit=None):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            home, opt, proc, cgroups = (base / name for name in ("home", "opt", "proc", "cgroups"))
            for path in (home, opt, proc, cgroups): path.mkdir()
            (home / "alpha-output").mkdir()
            work = opt / ("va." + "a" * 32 + ".ABC123"); work.mkdir()
            raw = (json.dumps(value, indent=2) + "\n").encode()
            (work / SUMMARY).write_bytes(raw); (work / SUMMARY).chmod(0o600)
            for name in ("weather-android-delivery-config.json", "weather-android-delivery-input.json", "weather-android-api.log",
                    "weather-android-lifecycle.json", "weather-1.receipt.json", "forecast.json", "air-quality.json",
                    "weather-products-delivery-cold-evidence.json", "weather-client-delivery-acquisition.json"):
                (work / name).write_text("PRIVATE CANARY")
            real_read = E["private_bytes"]
            copy_globals = E["copy_artifacts"].__globals__
            def inert_helper(command, **kwargs):
                self.assertEqual(command[:6], ["/usr/bin/python3", "-I", "-B", str(HERE / "weather-android-evidence.py"),
                    "copy-artifacts", command[5]])
                self.assertEqual(kwargs["timeout"], 3)
                # Model only disposable root staging. Run the actual stable
                # reader, exact JSON validator and copy helper as this user.
                with patch.object(os, "geteuid", return_value=0), patch.dict(copy_globals,
                        private_bytes=lambda path, size, uid: real_read(path, size, os.getuid())):
                    try: E["copy_artifacts"](Path(command[5]), Path(command[6]), os.getuid(), os.getgid())
                    except (ValueError, OSError): raise subprocess.CalledProcessError(1, command) from None
            overrides = {"weather_client_helper": lambda root: HERE / "weather-android-evidence.py"}
            if limit is not None: overrides["FILE_LIMIT"] = limit
            with patch.dict(self.api, overrides), patch.object(self.api["subprocess"], "run", inert_helper):
                archive = self.api["collect"](home, opt, COMMIT, "content-provider", 124, cgroups, proc)
            with tarfile.open(archive, "r:gz") as bundle:
                files = {item.name: bundle.extractfile(item).read() for item in bundle.getmembers()}
            return files, raw

    def test_actual_closed_validator_preserves_original_summary_no_private_or_success_claims(self):
        files, raw = self.collect(FIXTURES["guest_summary"]())
        self.assertEqual(files["work-1/" + SUMMARY], raw)
        self.assertEqual(set(files), {"work-1/" + SUMMARY, "vm-incomplete.json"})
        self.assertFalse(json.loads(files["vm-incomplete.json"])["success"])
        self.assertFalse(any(b"PRIVATE CANARY" in value for value in files.values()))
        exported = json.loads(files["work-1/" + SUMMARY])
        for key in ("native_android_proven", "joined_core_acceptance", "expiry_proven", "private_receipts_exported"):
            self.assertFalse(exported[key])

    def test_closed_export_rejects_extra_fields_unverified_claims_and_truncated_summary(self):
        original = FIXTURES["guest_summary"]()
        for field, value in (("private_path", "PRIVATE CANARY"), ("native_android_proven", True),
                ("captures_validated", False), ("joined_core_acceptance", True)):
            changed = copy.deepcopy(original); changed[field] = value
            with self.subTest(field=field):
                files, _ = self.collect(changed)
                self.assertEqual(set(files), {"vm-incomplete.json"})
        files, _ = self.collect(original, limit=10)
        self.assertEqual(set(files), {"vm-incomplete.json"})


if __name__ == "__main__":
    unittest.main()
