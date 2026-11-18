#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the exact runner's inert ABI wiring; never execute admitted binaries."""
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run-alpha-topology-vm.sh"
SOURCE = RUNNER.read_text()
SCENARIO = "weather-decoder-abi"
GUEST = SOURCE.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split("\nGUEST_DRIVER_SCRIPT\n", 1)[0]
NAMES = {"report.json", "elf.log", "sandbox.log", "version.log", "decode-first.log",
         "decode-last.log", "current-phase", "guest-exit-status"}


def shell(script, *args):
    return subprocess.run(["/bin/sh", "-c", script, "fixture", *map(str, args)],
                          capture_output=True, timeout=5)


class AbiRunnerWiring(unittest.TestCase):
    def call(self, *args, env=None):
        return subprocess.run(["/bin/sh", str(RUNNER), *args], capture_output=True, timeout=5, env=env)

    def required(self, scenario=SCENARIO):
        return ["--execute", "--yes", "--scenario", scenario, "--image", "/unread/image",
                "--output", "/unread/output", "--expected-commit", "a" * 40]

    def test_preview_ignores_ambient_inputs_and_never_requires_a_vm(self):
        subprocess.run(["/bin/sh", "-n", str(RUNNER)], check=True, timeout=5)
        result = self.call("--preview", "--scenario", SCENARIO,
                           env=dict(os.environ, decoder_abi_inputs="/ambient/untrusted"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"PREVIEW ONLY", result.stdout)
        self.assertIn(b"496-point CCSDS", result.stdout)
        self.assertIn(b"no core build", result.stdout)
        self.assertIn(b"4096 MiB", result.stdout)

    def test_invalid_input_authority_fails_before_host_operations(self):
        for value in (None, "", "relative", "/", "/inputs/", "/inputs/../outside", "/a//b", "/a/./b", "/a\nb"):
            args = [] if value is None else ["--decoder-abi-inputs", value]
            with self.subTest(value=value):
                self.assertEqual(self.call(*self.required(), *args).returncode, 64)
        self.assertEqual(self.call(*self.required(), "--decoder-abi-inputs").returncode, 64)
        self.assertEqual(self.call(*self.required(), "--decoder-abi-inputs", "/a",
                                  "--decoder-abi-inputs", "/b").returncode, 64)
        self.assertEqual(self.call("--preview", "--scenario", SCENARIO,
                                  "--decoder-abi-inputs", "/a").returncode, 64)
        # There is deliberately no caller-supplied checksum/profile authority.
        self.assertEqual(self.call(*self.required(), "--decoder-sha256", "b" * 64).returncode, 64)

    def test_no_cross_scenario_or_native_authority(self):
        for scenario in ("content-provider", "transaction-abci", "agent-private-task"):
            self.assertEqual(self.call(*self.required(scenario), "--decoder-abi-inputs", "/a").returncode, 64)
        for flag in ("--mpquic", "--package", "--native-runtime", "--code-bundle", "--code-manifest-sha256",
                     "--browser-filter-bundle", "--weather-client-bundle", "--weather-client-manifest-sha256"):
            with self.subTest(flag=flag):
                self.assertEqual(self.call(*self.required(), "--decoder-abi-inputs", "/a", flag, "/b").returncode, 64)

    def test_private_source_verified_snapshot_and_failure_propagation(self):
        fragment = "DECODER_ABI_DIRECTORY=" + SOURCE.split("DECODER_ABI_DIRECTORY=", 1)[1].split("\nOVERLAY=", 1)[0]
        script = '''set -eu
scenario=weather-decoder-abi
HERE=/reviewed/source
RUN_DIRECTORY=/private/owned
decoder_abi_inputs=/original/artifact
calls=0
fail_at=$1
python3() {
    calls=$((calls + 1))
    printf '%s:%s:%s\n' "$3" "$4" "${5:-}"
    [ "$calls" -ne "$fail_at" ] || return 23
}
''' + fragment
        for failed, count, expected in ((0, 3, 0), (1, 1, 23), (2, 2, 23), (3, 3, 23)):
            result = shell(script, failed)
            self.assertEqual(result.returncode, expected, result.stderr)
            lines = result.stdout.decode().splitlines()
            self.assertEqual(len(lines), count)
            self.assertEqual(lines[0], "verify-inputs:/original/artifact:")
            if count >= 2:
                self.assertEqual(lines[1], "stage-inputs:/original/artifact:/private/owned/weather-decoder-inputs")
            if count == 3:
                self.assertEqual(lines[2], "verify-inputs:/private/owned/weather-decoder-inputs:")

    def test_original_guest_size_and_explicit_host_reserve(self):
        memory = "guest_memory_for_scenario() {\n" + SOURCE.split("guest_memory_for_scenario() {\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        gate = "guest_memory_mib=$(guest_memory_for_scenario)\n" + SOURCE.split("guest_memory_mib=$(guest_memory_for_scenario)\n", 1)[1].split("qemu_usernet=", 1)[0]
        script = ('set -eu\nscenario=weather-decoder-abi\nfixture_available=$1\n'
                  'awk() { printf "%s\\n" "$fixture_available"; }\n' + memory + gate +
                  'printf "%s:%s\\n" "$guest_memory_mib" "$runner_reserve_mib"\n')
        for available, expected in ((6144 * 1024 - 1, 69), (6144 * 1024, 0), ("unknown", 69)):
            result = shell(script, available)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertEqual(result.stdout.strip(), b"4096:2048")

    def test_scratch_is_private_disk_sibling_and_not_evidence(self):
        fragment = "RUN_DIRECTORY_PARENT=/tmp\n" + SOURCE.split("RUN_DIRECTORY_PARENT=/tmp\n", 1)[1].split("QEMU_PID=\n", 1)[0]
        with tempfile.TemporaryDirectory(prefix="decoder-wiring-", dir=HERE) as temporary:
            output = Path(temporary) / "evidence"
            output.mkdir()
            script = ('set -eu\nscenario=weather-decoder-abi\noutput_directory=$1\n' + fragment +
                      'printf "%s\\n" "$RUN_DIRECTORY"\n')
            result = shell(script, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            scratch = Path(result.stdout.decode().strip())
            self.assertEqual(scratch.parent, output.parent)
            self.assertTrue(scratch.name.startswith("weather-decoder-abi-kvm."))
            self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o700)
            self.assertEqual(list(output.iterdir()), [])
            for filesystem in ("tmpfs", "ramfs"):
                rejected = shell('stat() { printf "%s\\n" "' + filesystem + '"; }\n' + script, output)
                self.assertEqual(rejected.returncode, 69, rejected.stderr)

    def test_guest_branch_precedes_all_native_and_cargo_execution(self):
        branch = GUEST.split('if [ "$scenario" = weather-decoder-abi ]; then\n', 1)[1].split('if [ "$scenario" = agent-native-editor ]; then', 1)[0]
        self.assertLess(GUEST.index('weather-decoder-abi ]; then'), GUEST.index('cargo build'))
        self.assertLess(GUEST.index('weather-decoder-abi ]; then'), GUEST.index('./volparossa-mpquic --api-version'))
        self.assertIn('test "$(systemd-detect-virt --vm)" = kvm', branch)
        self.assertIn('test "$(id -u)" -ne 0', branch)
        self.assertIn('test "$(dpkg --print-architecture)" = amd64', branch)
        self.assertIn('weather-decoder-abi.py verify-inputs /home/vpci/weather-decoder-inputs', branch)
        self.assertIn('--yes --no-install-recommends python3 bubblewrap binutils util-linux libc6 libstdc++6', branch)
        self.assertIn('150s python3 -B tests/integration/weather-decoder-abi.py execute', branch)
        self.assertNotIn('sudo -n python3', branch)
        self.assertNotIn('cargo', branch)
        self.assertTrue(branch.endswith('    exit 0\nfi\n'))

    def test_only_private_snapshot_uses_pinned_ssh_copy(self):
        body = SOURCE.split('scp_decoder_abi_inputs() {\n', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('"$DECODER_ABI_DIRECTORY"', body)
        self.assertNotIn('"$decoder_abi_inputs"', body)
        self.assertIn('StrictHostKeyChecking=yes', body)
        self.assertIn('ForwardAgent=no', body)
        self.assertIn('IdentityAgent=none', body)
        self.assertIn('600s scp -r', body)
        self.assertIn('test ! -e /home/vpci/weather-decoder-inputs', body)
        self.assertIn('test ! -L /home/vpci/weather-decoder-inputs', body)

    def test_workspace_tools_keep_the_existing_verifier_and_no_fallback(self):
        block = 'if [ -n "$host_tools_directory" ]; then\n' + SOURCE.split(
            'if [ -n "$host_tools_directory" ]; then\n', 1)[1].split('\nfi\n', 1)[0] + '\nfi\n'
        script = '''set -eu
scenario=$1
host_tools_directory=/verified/workspace-tools
python3() { printf '%s\n' "$*"; return 0; }
''' + block
        for scenario, expected in ((SCENARIO, 0), ("content-provider", 0), ("transaction-abci", 64)):
            result = shell(script, scenario)
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected == 0:
                self.assertIn(b'browser-native-tools.py --verify --output /verified/workspace-tools', result.stdout)
        failed = shell(script.replace('return 0', 'return 23'), SCENARIO)
        self.assertEqual(failed.returncode, 23, failed.stderr)


class AbiFinalization(unittest.TestCase):
    def run_finalizer(self, *, status=0, report=True, fault=None):
        temporary = tempfile.TemporaryDirectory(prefix="decoder-finalize-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        output = root / "alpha-output"
        output.mkdir(mode=0o700)
        for name in NAMES - {"current-phase", "guest-exit-status"}:
            if name != "report.json" or report:
                (output / name).write_bytes(b'{"synthetic":true}\n')
        (output / "private-unrelated").write_bytes(b"DO NOT EXPORT")
        (root / "guest-phase.txt").write_text("weather-decoder-offline\n")
        if fault == "oversize":
            (output / "elf.log").write_bytes(b"x" * 65537)
        elif fault == "symlink":
            (output / "elf.log").unlink()
            (output / "elf.log").symlink_to(output / "private-unrelated")
        elif fault == "hardlink":
            (output / "elf.log").unlink()
            os.link(output / "private-unrelated", output / "elf.log")
        function = 'decoder_abi_finalize() {\n' + GUEST.split('decoder_abi_finalize() {\n', 1)[1].split('\n    }\n', 1)[0] + '\n}\n'
        function = function.replace('/home/vpci/', str(root) + '/')
        result = shell('decoder_abi_output=$1\n' + function + '\n(exit "$2")\ndecoder_abi_finalize\n', output, status)
        return result, root

    def test_success_exports_only_bounded_expected_files(self):
        result, root = self.run_finalizer()
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(root / "alpha-output.tar.gz") as archive:
            self.assertEqual(set(archive.getnames()), NAMES)
            self.assertEqual(archive.extractfile("guest-exit-status").read(), b"0\n")
            self.assertTrue(all(member.isfile() and member.mode == 0o600 for member in archive.getmembers()))

    def test_original_failure_and_missing_report_never_succeed(self):
        for status, report, expected in ((23, True, 23), (23, False, 23), (0, False, 1)):
            result, root = self.run_finalizer(status=status, report=report)
            self.assertEqual(result.returncode, expected, result.stderr)
            with tarfile.open(root / "alpha-output.tar.gz") as archive:
                self.assertEqual(archive.extractfile("guest-exit-status").read(), f"{expected}\n".encode())

    def test_bad_export_members_fail_closed(self):
        for fault in ("oversize", "symlink", "hardlink"):
            result, root = self.run_finalizer(fault=fault)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "alpha-output.tar.gz").exists())

    def test_emergency_export_does_not_fall_through_to_raw_logs(self):
        body = SOURCE.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        api = {"__name__": "inert_abi_collector"}
        exec(compile(body, "abi-collector", "exec"), api)
        with tempfile.TemporaryDirectory(prefix="decoder-emergency-") as temporary:
            root = Path(temporary)
            home, opt = root / "home", root / "opt"
            home.mkdir(); opt.mkdir()
            output = home / "alpha-output"
            output.mkdir()
            (home / "guest-phase.txt").write_text("weather-decoder-offline\n")
            (home / "cargo-build.log").write_bytes(b"PRIVATE")
            for name in NAMES | {"runner.stderr", "content-provider-smoke.json", "private-state"}:
                (output / name).write_bytes(b'{}\n')
            path = api["collect"](home, opt, "a" * 40, SCENARIO, 1,
                                  cgroups=root / "absent-cgroups", proc=root / "absent-proc")
            with tarfile.open(path) as archive:
                self.assertEqual(set(archive.getnames()), {"driver/guest-phase.txt", "vm-incomplete.json",
                                                          *("published/" + name for name in NAMES)})


if __name__ == "__main__":
    unittest.main()
