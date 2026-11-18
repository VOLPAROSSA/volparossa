#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert shell/export wiring; never starts a VM, firmware call or network."""
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SHELL = HERE / "protected-quote-route.sh"
HOST = HERE / "run-alpha-topology-vm.sh"
GUEST = HERE / "kvm-alpha-topology.sh"


class Wiring(unittest.TestCase):
    def test_preview_is_scoped_and_reset_does_not_leak(self):
        for path in (HOST, GUEST):
            result = subprocess.run(["sh", str(path), "--preview", "--scenario", "protected-quote"],
                capture_output=True, text=True, timeout=5, check=True)
            self.assertIn("PREVIEW ONLY", result.stdout)
            self.assertIn("no", result.stdout)
            self.assertIn("firmware", result.stdout)
            self.assertNotIn("disjoint caches", result.stdout)
            later = subprocess.run(["sh", str(path), "--preview", "--scenario", "protected-quote",
                "--scenario", "content-provider"], capture_output=True, text=True, timeout=5, check=True)
            self.assertNotIn("Protected-quote:", later.stdout)
            self.assertNotIn("protected-quote route refusal plan:", later.stdout)

    def test_real_three_case_calls_and_authority_are_fixed(self):
        source = SHELL.read_text()
        self.assertEqual(source.count("protected_quote_case wrong ||"), 1)
        self.assertEqual(source.count("protected_quote_case device-unavailable ||"), 1)
        self.assertEqual(source.count("protected_quote_case repeat ||"), 1)
        self.assertIn('--max-seconds 600 --max-attempts 1', source)
        self.assertIn('protected_quote_attach wrong "$quote_wrong_key"', source)
        self.assertIn('protected_quote_attach valid "$quote_requester_key"', source)
        self.assertIn('nsenter --target "$quote_provider_pid" --mount -- test ! -e /dev/sev-guest', source)
        self.assertIn('nsenter --target "$quote_provider_pid" --mount -- test ! -L /dev/sev-guest', source)
        self.assertNotIn("seed-providers", source)
        self.assertNotIn("TestReportSource", source)
        self.assertNotIn("compute run", source)
        self.assertIn("client_log_baseline_ms", source)
        self.assertIn("client_event_count_after", source)

    def test_public_inputs_belong_to_the_capless_quote_caller(self):
        source = SHELL.read_text()
        start = source.index('    python3 -B "$source_directory/tests/integration/protected-quote-route.py"')
        end = source.index('    PHASE=protected-quote-route\n', start)
        stage = source[start:end]
        # Run the real pinned-fixture preparation and staging block, but never
        # change a host UID/GID. The chown double records the exact fixed targets.
        script = '''set -eu
fail() { exit 71; }
chown() { printf '%s\\n' "$@" >"$TRACE"; return "$OWNER_STATUS"; }
''' + stage + '\nprintf "ready\\n"\n'
        guard = (ROOT / "crates/volparossa/src/compute.rs").read_text()
        guard = guard.split("fn read_file(", 1)[1].split("\nfn runtime_lease(", 1)[0]
        self.assertIn("info.uid() == nix::unistd::geteuid().as_raw()", guard)
        self.assertIn('--reuid="$WORKER_UID" --regid="$WORKER_GID"', source)
        for owner_status in (0, 1):
            with self.subTest(owner_status=owner_status), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                trace = work / "owner-argv"
                env = dict(os.environ, WORK=directory, source_directory=str(ROOT),
                    WORKER_UID="9876", WORKER_GID="9877", TRACE=str(trace),
                    OWNER_STATUS=str(owner_status))
                result = subprocess.run(["sh", "-c", script], env=env,
                    capture_output=True, timeout=5)
                self.assertTrue(trace.is_file(), "the CLI rejects root-owned inputs even if readable")
                paths = [work / "protected-quote-inputs" / name
                    for name in ("policy.json", "vcek.der", "vendor.crl")]
                self.assertEqual(trace.read_text().splitlines(), ["9876:9877", *map(str, paths)])
                # The non-privileged double must not change the real test owner.
                self.assertTrue(all(path.stat().st_uid == os.geteuid() for path in paths))
                if owner_status:
                    self.assertEqual(result.returncode, 71)
                    self.assertEqual(result.stdout, b"")
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, b"ready\n")
                    self.assertEqual((work / "protected-quote-inputs").stat().st_mode & 0o777, 0o755)
                    self.assertTrue(all(path.stat().st_mode & 0o777 == 0o400 for path in paths))
                    self.assertEqual((work / "protected-quote-inputs.json").stat().st_mode & 0o777, 0o600)

    def test_quote_preflight_does_not_require_unbuilt_unrelated_examples(self):
        text = GUEST.read_text()
        start = text.index('if [ "$scenario" = content-provider ]; then\n    for provider_fixture')
        end = text.index('\nif [ "$scenario" = content-https ]; then', start)
        block = text[start:end]
        self.assertNotIn("content-acceptance-fixture", SHELL.read_text())
        self.assertNotIn("https-content-acceptance-fixture", SHELL.read_text())
        with tempfile.TemporaryDirectory() as directory:
            binaries = Path(directory) / "examples"
            binaries.mkdir()
            env = dict(os.environ, scenario="content-provider", source_directory=str(ROOT),
                binary_directory=directory)

            def run(selected, **overrides):
                return subprocess.run(["sh", "-eu", "-c", block],
                    env=dict(env, protected_quote=selected, **overrides),
                    capture_output=True, timeout=5)

            # The actual quote driver builds neither unrelated example. This
            # executes the original preflight block, not a duplicated predicate.
            self.assertEqual(run("yes").returncode, 0)
            self.assertEqual(run("no").returncode, 69)
            for name in ("content-acceptance-fixture", "https-content-acceptance-fixture"):
                self.assertEqual(run("no").returncode, 69)
                path = binaries / name
                path.write_bytes(b"inert-never-executed\n")
                path.chmod(0o700)
            self.assertEqual(run("no").returncode, 0)
            # Quote still requires the existing provider source fixtures.
            self.assertEqual(run("yes", source_directory=directory).returncode, 69)

    def test_all_scenarios_stage_exactly_the_examples_the_guest_driver_builds(self):
        host, guest = HOST.read_text(), GUEST.read_text()
        start = host.index('if [ "$scenario" = content ] || [ "$scenario" = content-message ] || [ "$scenario" = content-provider ]')
        end = host.index('\nif [ "$scenario" = uplink-link ]; then', start)
        builds = host[start:end]
        # Redirect only the fixed private build log into the inert temporary
        # directory. The cargo function records argv and never invokes a compiler.
        builds = builds.replace('/home/vpci/cargo-build.log', '"$TRACE"')
        start = guest.index('if [ "$scenario" = content ] || [ "$scenario" = content-message ] || [ "$scenario" = content-provider ]',
            guest.index('for staged_executable in'))
        end = guest.index('\nif [ "$scenario" = content-provider ]; then', start)
        stages = guest[start:end]
        declared = re.search(r'case \$scenario in (weather-decoder-abi\|alpha\|[^\n]+?)\) ;;', host)
        self.assertIsNotNone(declared)
        scenarios = declared.group(1).split('|')
        self.assertEqual(len(scenarios), len(set(scenarios)))
        self.assertIn('protected-quote', scenarios)
        content = {'content', 'content-message', 'content-provider', 'content-replication', 'content-repair'}
        https = {'content-https', 'content-provider'}
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / 'builds'
            for selected in scenarios:
                with self.subTest(scenario=selected):
                    expected = []
                    if selected in content:
                        expected.append('content-acceptance-fixture')
                    if selected in https:
                        expected.append('https-content-acceptance-fixture')
                    trace.write_bytes(b'')
                    env = dict(os.environ, scenario=selected, TRACE=str(trace),
                        binary_directory='/inert/bin', WORK='/inert/work', AGENT_GID='999',
                        protected_quote='yes' if selected == 'protected-quote' else 'no')
                    built = subprocess.run(['sh', '-eu', '-c',
                        'cargo() { printf "%s\\n" "$@"; }\n' + builds],
                        env=env, capture_output=True, timeout=5)
                    self.assertEqual(built.returncode, 0, built.stderr)
                    self.assertEqual([line for line in trace.read_text().splitlines()
                        if line.endswith('-acceptance-fixture')], expected)
                    staged = subprocess.run(['sh', '-eu', '-c',
                        'install() { for arg do case "$arg" in /inert/bin/examples/*) printf "%s\\n" "${arg##*/}" ;; esac; done; }\n' + stages],
                        env=dict(env, scenario='content-provider' if selected == 'protected-quote' else selected),
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(staged.returncode, 0, staged.stderr)
                    self.assertEqual(staged.stdout.splitlines(), expected)

    def case(self, name, status, failures, output):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, WORK=directory, CASE=name, CASE_STATUS=str(status),
                CASE_FAILURES=str(failures), CASE_OUTPUT=output, quote_provider_key="a" * 64)
            script = '''set -eu
. "$1"
capture_product_logs() { :; }
client_log_baseline_ms() { printf '100\\n'; }
client_event_count_after() { test "$1" = 100; test "$2" = QUOTE_SIGNED_EXCHANGE_FAILED; printf '%s\\n' "$CASE_FAILURES"; }
protected_quote_cli() { printf '%s' "$CASE_OUTPUT"; return "$CASE_STATUS"; }
protected_quote_case "$CASE"
'''
            result = subprocess.run(["sh", "-c", script, "inert-case", str(SHELL)], env=env,
                capture_output=True, timeout=5)
            gate = Path(directory) / f"protected-quote-{name}-gate.json"
            receipt = json.loads(gate.read_bytes()) if gate.exists() else None
            recorded_status = (Path(directory) / f"protected-quote-{name}.status").read_text().strip()
            return result.returncode, receipt, recorded_status

    def test_denial_requires_original_stage_and_empty_stdout(self):
        for name in ("wrong", "repeat"):
            with self.subTest(name=name):
                code, gate, status = self.case(name, 1, 1, "")
                self.assertEqual(code, 0)
                self.assertEqual(status, "1")
                self.assertEqual(gate, dict(exit_status=1, stdout_empty=True,
                    signed_exchange_failures_before=0, signed_exchange_failures_after=1))
                for exit_status, count, output in ((1, 0, ""), (1, 2, ""), (1, 1, "{}"),
                                                 (0, 1, ""), (124, 1, ""), (137, 1, "")):
                    code, gate, recorded = self.case(name, exit_status, count, output)
                    self.assertNotEqual(code, 0)
                    self.assertIsNone(gate)
                    self.assertEqual(recorded, str(exit_status))

    def test_refusal_requires_nonempty_stdout_exit_one_and_no_exchange_failure(self):
        code, gate, _ = self.case("device-unavailable", 1, 0, '{"not_yet_validated":"fixture"}')
        self.assertEqual(code, 0)
        self.assertFalse(gate["stdout_empty"])
        # The separate real collector validates the exact JSON; shell success
        # at this point is not a report, hardware claim or accepted outcome.
        for status, failures, output in ((0, 0, "{}"), (1, 1, "{}"), (1, 0, ""), (124, 0, "{}")):
            code, gate, _ = self.case("device-unavailable", status, failures, output)
            self.assertNotEqual(code, 0)
            self.assertIsNone(gate)

    def test_closed_guest_archive_excludes_private_and_host_receipt(self):
        source = HOST.read_text()
        start = source.index('if [ "$scenario" = protected-quote ]; then\n    # Only the fixed closed guest')
        end = source.index('\nelif [ "$scenario" = agent-cooperative-browser ]', start)
        block = source[start:end] + "\nfi\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "alpha-output"
            output.mkdir()
            block = block.replace("/home/vpci", str(root))
            for name, data in (("protected-quote-route.json", b'{"closed":true}\n'),
                               ("private.key", b"PRIVATE-CANARY"),
                               ("protected-quote-vm-cleanup.json", b"forged guest hostreceipt"),
                               ("runner.stderr", b"RAW-CANARY")):
                (output / name).write_bytes(data)
            subprocess.run(["sh", "-eu", "-c", block], env=dict(os.environ, scenario="protected-quote"),
                capture_output=True, check=True, timeout=5)
            with tarfile.open(root / "alpha-output.tar.gz") as archive:
                self.assertEqual(archive.getnames(), ["protected-quote-route.json"])
                self.assertEqual(archive.extractfile("protected-quote-route.json").read(), b'{"closed":true}\n')
            (output / "protected-quote-route.json").write_bytes(b"x" * 262145)
            denied = subprocess.run(["sh", "-eu", "-c", block], env=dict(os.environ, scenario="protected-quote"),
                capture_output=True, timeout=5)
            self.assertNotEqual(denied.returncode, 0)

    def test_host_cleanup_only_after_confirmed_stop_and_scratch_removal(self):
        text = HOST.read_text()
        cleanup = text[text.index("cleanup() {"):text.index("trap cleanup EXIT")]
        position = cleanup.index('if [ "$scenario" = protected-quote ]; then')
        self.assertLess(cleanup.index("stop_qemu_child abort"), position)
        self.assertLess(cleanup.index('rm -rf --one-file-system -- "$RUN_DIRECTORY"'), position)
        self.assertIn('qemu_joined:($joined == "yes")', cleanup[position:])
        self.assertIn("set -C", cleanup[position:])
        self.assertIn('[ ! -e "$RUN_DIRECTORY" ] && [ ! -L "$RUN_DIRECTORY" ]', cleanup[position:])

    def test_quote_never_enters_general_artifact_export(self):
        source = GUEST.read_text()
        body = source.split("\ncopy_artifacts() {\n", 1)[1].split("\n}\n", 1)[0]
        script = "set -eu\nprotected_quote=yes\ncopy_artifacts() {\n" + body + "\n}\ncopy_artifacts\n"
        # Other scenario globals deliberately remain unset under nounset: the
        # quote branch must return before any generic exporter can run.
        result = subprocess.run(["sh", "-c", script], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_workflow_separate_exact_export_and_both_gates(self):
        text = (ROOT / ".github/workflows/alpha-topology.yml").read_text()
        self.assertIn("          - protected-quote\n", text)
        start = text.index("      - name: Upload closed protected quote refusal evidence")
        stop = text.index("      - name: Upload bounded topology diagnostics", start)
        block = text[start:stop]
        self.assertEqual(block.count("${{ env.VOLPAROSSA_ALPHA_OUTPUT }}/"), 2)
        self.assertIn("/protected-quote-route.json", block)
        self.assertIn("/protected-quote-vm-cleanup.json", block)
        self.assertNotIn("*", block)
        self.assertNotIn("stderr", block)
        self.assertIn("protected-quote-route.py report", text)
        self.assertIn("protected-quote-route.py vm-report", text)
        self.assertIn("test-protected-quote-route-wiring.py", (HERE / "test-kvm-alpha-topology-contract.sh").read_text())

    def test_host_receipt_retains_unknown_join_and_does_not_overwrite(self):
        source = HOST.read_text()
        start = source.index('    if [ "$scenario" = protected-quote ]; then\n        quote_private_removed=false')
        end = source.index('\n    exit "$status"', start)
        block = source[start:end] + '\nexit "$status"\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scratch = root / "private"
            scratch.mkdir()
            env = dict(os.environ, scenario="protected-quote", RUN_DIRECTORY=str(scratch),
                output_directory=directory, expected_commit="a" * 40, QEMU_STARTED="yes",
                QEMU_JOINED="no", status="42")
            result = subprocess.run(["sh", "-c", block], env=env, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 42)
            receipt = root / "protected-quote-vm-cleanup.json"
            self.assertEqual(json.loads(receipt.read_bytes()), dict(schema_version=1,
                source_revision="a" * 40, qemu_started=True, qemu_joined=False,
                private_guest_state_removed=False))
            original = receipt.read_bytes()
            scratch.rmdir()
            result = subprocess.run(["sh", "-c", block], env=dict(env, status="0", QEMU_JOINED="yes"),
                capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(receipt.read_bytes(), original)

    def test_real_emergency_collector_keeps_only_complete_closed_report(self):
        source = HOST.read_text()
        collector = source.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split("\nGUEST_DIAGNOSTICS_PYTHON\n", 1)[0]
        self.assertIn('"content-provider", "protected-quote",', collector)
        module = {"__name__": "inert_quote_fixture"}
        exec(compile(collector, str(HOST) + ":diagnostics", "exec"), module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home, opt = root / "home", root / "opt"
            home.mkdir(); opt.mkdir()
            output = home / "alpha-output"
            output.mkdir()
            (output / "protected-quote-route.json").write_text('{"success":false}\n')
            for name in ("runner.stderr", "identity.key", "protected-quote-device-unavailable.json"):
                (output / name).write_text("PRIVATE-CANARY")
            archive = module["collect"](home, opt, "a" * 40, "protected-quote", 1, root / "cgroups", root / "proc")
            with tarfile.open(archive) as bundle:
                self.assertEqual(set(bundle.getnames()), {"published/protected-quote-route.json", "vm-incomplete.json"})
                self.assertFalse(any(b"PRIVATE-CANARY" in bundle.extractfile(m).read() for m in bundle.getmembers()))
            (output / "protected-quote-route.json").write_bytes(b"x" * 262145)
            archive = module["collect"](home, opt, "a" * 40, "protected-quote", 1, root / "cgroups", root / "proc")
            with tarfile.open(archive) as bundle:
                self.assertEqual(bundle.getnames(), ["vm-incomplete.json"])

    def test_dispatch_and_finalizer_precede_legacy_provider_sequence(self):
        text = GUEST.read_text()
        self.assertIn("protected-quote) scenario=content-provider; protected_quote=yes", text)
        self.assertIn('if [ "$protected_quote" = yes ]; then protected_quote_route_run\n    else content_provider_run; fi', text)
        self.assertLess(text.index('protected_quote_route_finalize_report "$original_status"'),
            text.index('content_provider_finalize_report "$original_status"'))
        source = SHELL.read_text()
        self.assertLess(source.index("stop_privacy_observers ||"), source.index('evidence "$WORK" "$expected_commit"'))
        self.assertLess(source.index("benchmark_disconnect_route protected-quote"), source.index('evidence "$WORK" "$expected_commit"'))


if __name__ == "__main__":
    unittest.main()
