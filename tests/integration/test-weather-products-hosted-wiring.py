#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert hosted workflow contracts; no network, runtime, compiler or VM."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/weather-products-delivery.yml"
SOURCE = WORKFLOW.read_text()


def embedded(name):
    start, end = "# BEGIN " + name, "# END " + name
    assert SOURCE.count(start) == SOURCE.count(end) == 1
    return textwrap.dedent(SOURCE.split(start, 1)[1].split(end, 1)[0])


class HostedWeatherWiring(unittest.TestCase):
    def test_only_explicit_bounded_hosted_execution(self):
        self.assertIn("  workflow_dispatch:\n", SOURCE)
        self.assertIn("    branches: [feature/weather-v4-public]", SOURCE)
        trigger = SOURCE.split("  push:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertNotIn("main", trigger)
        self.assertNotIn("**", trigger)
        self.assertNotIn("docs/", trigger)
        self.assertNotIn("  pull_request:", SOURCE)
        self.assertNotIn("  schedule:", SOURCE)
        self.assertIn("    runs-on: ubuntu-24.04", SOURCE)
        self.assertIn("    timeout-minutes: 120", SOURCE)
        self.assertIn("  cancel-in-progress: false", SOURCE)
        self.assertIn("contents: read", SOURCE)
        self.assertIn("actions: read", SOURCE)
        self.assertNotIn("secrets.", SOURCE)
        self.assertNotIn("continue-on-error:", SOURCE)
        self.assertNotIn("--retry", SOURCE)

    def test_all_actions_pinned_and_sources_use_admission_not_mutable_branches(self):
        actions = re.findall(r"uses: ([^\s]+)", SOURCE)
        self.assertEqual(len(actions), 4)
        self.assertTrue(all(re.fullmatch(r"actions/(?:checkout|upload-artifact)@[0-9a-f]{40}", value)
                            for value in actions))
        self.assertEqual(SOURCE.count("persist-credentials: false"), 3)
        self.assertIn(".sources.weather.commit", SOURCE)
        self.assertIn(".sources.browser.commit", SOURCE)
        self.assertIn("ref: ${{ env.WEATHER_SOURCE_COMMIT }}", SOURCE)
        self.assertIn("ref: ${{ env.BROWSER_SOURCE_COMMIT }}", SOURCE)
        self.assertNotIn("ref: main", SOURCE)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', SOURCE)
        self.assertIn('test "$(git -C .cache/weather-public-source rev-parse HEAD)" = "$WEATHER_SOURCE_COMMIT"', SOURCE)

    def test_auxiliary_checkout_paths_are_covered_by_existing_gitignore(self):
        paths = re.findall(r"(?m)^          path: ([.a-zA-Z0-9_/-]+)$", SOURCE)
        self.assertEqual(paths, [".cache/weather-public-source", ".cache/browser-public-source"])
        ignored = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"],
                                 input="\n".join(paths) + "\n", cwd=ROOT, text=True,
                                 capture_output=True, timeout=5)
        self.assertEqual(ignored.returncode, 0, ignored.stderr)
        self.assertEqual(ignored.stdout.splitlines(), paths)
        # These former checkout destinations were not ignored: they introduced
        # untracked nested repositories before the immutable VM source guard.
        old = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"],
                             input="build/weather-public-source\nbuild/browser-public-source\n",
                             cwd=ROOT, text=True, capture_output=True, timeout=5)
        self.assertEqual(old.returncode, 1, old.stderr)
        self.assertEqual(old.stdout, "")

    def test_last_source_preflight_is_fail_closed_and_diagnostics_are_bounded(self):
        source = embedded("FINAL_SOURCE_PREFLIGHT")
        block = SOURCE.split("- name: Run actual protected", 1)[1].split("- name: Require current aggregate", 1)[0]
        self.assertLess(block.index("# END FINAL_SOURCE_PREFLIGHT"), block.index("sudo -n --"))
        for status in (b"", b"?? unexpected-public-path\n", b"?? " + b"x" * 10000 + b"\n"):
            stderr = io.StringIO()
            with self.subTest(size=len(status)), patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
                    patch("subprocess.check_output", side_effect=[b"a" * 40 + b"\n", status]) as check, \
                    patch.object(sys, "stderr", stderr):
                if status:
                    with self.assertRaises(SystemExit) as failure:
                        exec(compile(source, "FINAL_SOURCE_PREFLIGHT", "exec"), {})
                    self.assertEqual(failure.exception.code, 64)
                    self.assertIn("source worktree must be clean", stderr.getvalue())
                    self.assertLessEqual(len(stderr.getvalue()), 8300)
                    self.assertEqual("status output truncated" in stderr.getvalue(), len(status) > 8192)
                else:
                    exec(compile(source, "FINAL_SOURCE_PREFLIGHT", "exec"), {})
                    self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(check.call_args_list[-1].args[0], [
                    "git", "-c", "core.quotePath=true", "status", "--porcelain=v1",
                    "--untracked-files=normal", "--ignore-submodules=none"])
        for outputs in ([b"b" * 40 + b"\n"], subprocess.CalledProcessError(128, "git")):
            with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), \
                    patch("subprocess.check_output", side_effect=outputs):
                with self.assertRaises((AssertionError, subprocess.CalledProcessError)):
                    exec(compile(source, "FINAL_SOURCE_PREFLIGHT", "exec"), {})

    def test_runner_original_clean_source_guard_is_preserved(self):
        runner = (ROOT / "tests/integration/run-alpha-topology-vm.sh").read_text()
        guard = '''[ -z "$(GIT_OPTIONAL_LOCKS=0 git -C "$REPOSITORY" status --porcelain=v1 \\
    --untracked-files=normal --ignore-submodules=none)" ] \\
    || { printf '%s\\n' 'source worktree must be clean' >&2; exit 64; }'''
        self.assertEqual(runner.count(guard), 1)

    def metadata(self):
        pin = dict(repository="VOLPAROSSA/volparossa-weather", run_id=101, commit="a" * 40,
                   id=202, name="hosted-weather-client-assets-unadmitted-" + "a" * 40,
                   sha256="b" * 64, bytes=1234)
        run = dict(id=101, run_attempt=1, head_sha="a" * 40, status="completed", conclusion="success")
        artifact = dict(id=202, name=pin["name"], size_in_bytes=1234, digest="sha256:" + "b" * 64,
                        expired=False, workflow_run=dict(id=101, head_sha="a" * 40))
        return pin, run, artifact

    def check_metadata(self, pin, run, artifact):
        with tempfile.TemporaryDirectory(prefix="weather-hosted-wiring-") as temporary:
            root = Path(temporary)
            for path, value in (("record.json", dict(artifacts=dict(assets=pin))),
                                ("assets-run.json", run), ("assets-artifact.json", artifact)):
                (root / path).write_text(json.dumps(value))
            return subprocess.run([sys.executable, "-B", "-", str(root / "record.json"), "assets", str(root)],
                                  input=embedded("PUBLIC_ARTIFACT_METADATA"), text=True,
                                  capture_output=True, timeout=5)

    def test_actual_metadata_guard_rejects_stale_or_different_artifacts(self):
        pin, run, artifact = self.metadata()
        self.assertEqual(self.check_metadata(pin, run, artifact).returncode, 0)
        for section, key, value in (
            ("run", "run_attempt", 2), ("run", "head_sha", "c" * 40),
            ("run", "status", "in_progress"), ("run", "conclusion", "failure"),
            ("run", "id", 999), ("artifact", "id", 999),
            ("artifact", "name", "latest-assets"), ("artifact", "size_in_bytes", 1235),
            ("artifact", "digest", "sha256:" + "c" * 64), ("artifact", "expired", True),
            ("pin", "repository", "untrusted/volparossa-weather"),
            ("pin", "bytes", 256 * 1024**2 + 1), ("pin", "name", "../outside"),
        ):
            with self.subTest(section=section, key=key):
                values = dict(zip(("pin", "run", "artifact"), copy.deepcopy((pin, run, artifact))))
                values[section][key] = value
                self.assertNotEqual(self.check_metadata(**values).returncode, 0)
        for key, value in (("id", 999), ("head_sha", "c" * 40)):
            changed = copy.deepcopy(artifact)
            changed["workflow_run"][key] = value
            self.assertNotEqual(self.check_metadata(pin, run, changed).returncode, 0)

    def test_four_public_inputs_are_verified_before_download_and_capture(self):
        self.assertIn("for kind in assets proof decoder abi; do", SOURCE)
        self.assertIn('gh api "repos/$repository/actions/runs/$run_id"', SOURCE)
        self.assertIn('gh api "repos/$repository/actions/artifacts/$artifact_id"', SOURCE)
        self.assertLess(SOURCE.index("# END PUBLIC_ARTIFACT_METADATA"), SOURCE.index('gh run download "$run_id"'))
        self.assertIn('--repo "$repository" --name "$artifact_name" --dir "$WEATHER_INPUTS/$kind"', SOURCE)
        self.assertIn('test ! -e "$WEATHER_INPUTS/$kind"', SOURCE)
        self.assertIn("weather-public-drizzli-v4.json", SOURCE)
        self.assertNotIn(".codex/", SOURCE)
        self.assertNotIn(".git/ci-evidence", SOURCE)

    def test_capture_is_inert_and_seven_path_contract_is_exact(self):
        block = SOURCE.split("- name: Capture and fully verify v4", 1)[1].split("- name: Install tools", 1)[0]
        normalized = block.replace("\\\n", " ")
        call = re.search(r"weather-client-bundle.py capture-v4\s+(.+?) >", normalized).group(1)
        paths = re.findall(r'"([^"]+)"', call)
        self.assertEqual(paths, ["$GITHUB_WORKSPACE/.cache/weather-public-source",
                                 "$GITHUB_WORKSPACE/.cache/browser-public-source",
                                 "$WEATHER_INPUTS/assets", "$WEATHER_INPUTS/proof", "$WEATHER_INPUTS/decoder",
                                 "$WEATHER_INPUTS/abi", "$archive"])
        self.assertIn('verify-runtime "$archive" "$manifest"', block)
        self.assertIn('runtime-version "$archive" "$manifest"', block)
        self.assertIn(".bundle_version == 4 and .runtime_executed == false", block)
        for forbidden in ("grib_ls --", "firefox-esr --", "npm ci", "node --"):
            self.assertNotIn(forbidden, SOURCE)

    def test_real_content_provider_execution_cannot_stop_at_admission(self):
        block = SOURCE.split("- name: Run actual protected", 1)[1].split("- name: Require current aggregate", 1)[0]
        self.assertIn("set -euo pipefail", block)
        self.assertIn("--scenario content-provider", block)
        self.assertIn('--weather-client-bundle "$WEATHER_ARCHIVE"', block)
        self.assertIn('--weather-client-manifest-sha256 "$WEATHER_MANIFEST"', block)
        self.assertIn('--output "$WEATHER_OUTPUT" --expected-commit "$GITHUB_SHA"', block)
        self.assertIn("--clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all", block)
        self.assertIn("--no-new-privs --reset-env", block)
        self.assertIn("content-provider-smoke.py report", SOURCE)
        self.assertNotIn("historical-report", SOURCE)
        proof = embedded("JOINED_EVIDENCE")
        self.assertIn('checker["validate_export"](suffix, values[suffix])', proof)
        self.assertIn('evidence["schema"] == cold["schema"] == browser["schema"] == acquisition["schema"] == 4', proof)
        self.assertIn('evidence["products"] == cold["products"]', proof)
        self.assertIn('hashlib.sha256(raw["original-report"]).hexdigest()', proof)
        self.assertIn('browser["scope"]["synthetic_weather"] is False', proof)
        self.assertIn('browser["scope"]["synthetic_air_quality"] is False', proof)
        self.assertIn('all(browser["cleanup"].values()) and all(browser["outer_cleanup"].values())', proof)

    def joined_fixture(self):
        products, acquisition_products, observed_products = {}, {}, {}
        for index, key in enumerate(("weather", "air_quality")):
            product = dict(forecast_sha256=str(index + 1) * 64, forecast_bytes=100 + index,
                           manifest_id="m" * 64, cold_receipt_sha256="c" * 64, acquired_fields=2)
            products[key] = product
            acquisition_products[key] = dict(forecast_sha256=product["forecast_sha256"],
                                             forecast_bytes=product["forecast_bytes"], fields=[{}, {}])
            observed_products[key] = dict(expected={field: product[field] for field in
                ("forecast_sha256", "manifest_id", "cold_receipt_sha256")},
                checks=dict(initial_dom_display_sha256="d" * 64, refresh_dom_display_sha256="d" * 64,
                            browser_api_requests=2, provider_requests_checked=1,
                            **{field: True for field in ("initial_dom_matches_cold_publication",
                               "refresh_dom_matches_cold_publication", "exact_native_times_and_values",
                               "explicit_missing_capabilities", "no_external_resources", "source_attribution")}))
            observed_products[key]["expected"]["display_sha256"] = "d" * 64
        browser = dict(schema=4, passed=True, phase="complete", source=dict(bundle_manifest_sha256="a" * 64),
                       expected=dict(core_sha256="b" * 64), products=observed_products,
                       scope=dict(synthetic_weather=False, synthetic_air_quality=False),
                       cleanup=dict(clean=True), outer_cleanup=dict(clean=True))
        cold = dict(schema=4, bundle_manifest_sha256="a" * 64, core_sha256="b" * 64,
                    decoder_sha256="e" * 64, products=products)
        evidence = dict(cold, success=True, scope=dict(end_to_end_proven=True))
        return {"original-report": browser, "evidence": evidence, "cold-evidence": cold,
                "acquisition": dict(schema=4, decoder_sha256="e" * 64, products=acquisition_products),
                "tree-before": dict(manifest_sha256="a" * 64), "tree-after": dict(manifest_sha256="a" * 64),
                "cache-before": dict(private=True), "cache-after": dict(private=True),
                "input-cleanup": dict(directory_removed=True, files_removed=True)}

    def check_joined_links(self, values):
        # The real helper separately owns closed-schema tests. Mock only that
        # validator here to exercise this workflow's cross-receipt bindings.
        calls = []
        checker = {"validate_export": lambda suffix, value: calls.append(suffix),
                   "B": {"B": {"unique_pairs": dict}}}
        with tempfile.TemporaryDirectory(prefix="weather-joined-links-") as temporary:
            root = Path(temporary)
            browser_raw = json.dumps(values["original-report"]).encode()
            values["evidence"]["browser_report_sha256"] = hashlib.sha256(browser_raw).hexdigest()
            for suffix, value in values.items():
                path = root / ("weather-products-delivery-" + suffix + ".json")
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            with patch("runpy.run_path", return_value=checker), patch.object(sys, "argv", ["check", str(root), "a" * 64]):
                exec(compile(embedded("JOINED_EVIDENCE"), "JOINED_EVIDENCE", "exec"), {})
        self.assertEqual(set(calls), set(values))

    def test_executable_joined_guard_binds_acquisition_and_each_native_ui_product(self):
        self.check_joined_links(self.joined_fixture())
        for receipt, path, replacement in (
            ("acquisition", ("schema",), 2),
            ("acquisition", ("decoder_sha256",), "f" * 64),
            ("acquisition", ("products", "weather", "forecast_sha256"), "f" * 64),
            ("acquisition", ("products", "air_quality", "forecast_bytes"), 999),
            ("acquisition", ("products", "weather", "fields"), [{}]),
            ("original-report", ("products", "weather", "expected", "manifest_id"), "f" * 64),
            ("original-report", ("products", "air_quality", "checks", "refresh_dom_matches_cold_publication"), False),
            ("original-report", ("products", "weather", "checks", "refresh_dom_display_sha256"), "f" * 64),
            ("original-report", ("passed",), False),
            ("original-report", ("scope", "synthetic_air_quality"), True),
        ):
            with self.subTest(receipt=receipt, path=path):
                values = self.joined_fixture()
                target = values[receipt]
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = replacement
                with self.assertRaises(AssertionError):
                    self.check_joined_links(values)

    def test_inputs_profiles_and_unbounded_source_artifacts_are_not_exported(self):
        export = SOURCE.split("- name: Retain bounded original evidence", 1)[1].split("- name: State exact scope", 1)[0]
        self.assertIn("if: always() && env.WEATHER_OUTPUT != ''", export)
        self.assertIn("${{ env.WEATHER_OUTPUT }}", export)
        self.assertIn("${{ env.WEATHER_INPUTS }}/provenance/*.json", export)
        for forbidden in ("weather-client-v4.tar", ".cache/weather-public-source", ".cache/browser-public-source",
                          "${{ env.WEATHER_INPUTS }}/assets", "${{ env.WEATHER_INPUTS }}/decoder", "profile"):
            self.assertNotIn(forbidden, export.split("path: |", 1)[1])
        self.assertIn("without automatic retry", SOURCE)
        self.assertIn("Origin HTTPS acquisition is outside the overlay", SOURCE)

    def test_embedded_shell_and_python_are_valid_without_execution(self):
        blocks = re.findall(r"(?m)^        run: \|\n((?:          .*\n|\n)+)", SOURCE)
        self.assertEqual(len(blocks), 9)
        for i, block in enumerate(blocks):
            with self.subTest(block=i):
                result = subprocess.run(["bash", "-n"], input=textwrap.dedent(block),
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("PUBLIC_ARTIFACT_METADATA", "FINAL_SOURCE_PREFLIGHT", "JOINED_EVIDENCE"):
            compile(embedded(name), name, "exec")


if __name__ == "__main__":
    unittest.main()
