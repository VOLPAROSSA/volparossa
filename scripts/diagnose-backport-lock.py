#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Failure-only, non-building lock reconciliation on the disposable CI runner.

Only four named public diagnostic files may leave the temporary copy. Cargo's
output, registry state, credentials and source trees are never exported.
"""

import argparse
import difflib
import hashlib
import json
import os
import runpy
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib


LIMIT = 1024 * 1024
TIMEOUT = 120
HARNESS = Path("third_party/rust/backport-regressions")
HARNESS_FILES = (
    "Cargo.toml", "Cargo.lock", ".cargo/config.toml", "src/lib.rs", "src/resolver.rs",
)
VENDORS = (
    "hickory-proto-0.25.2", "hickory-resolver-0.25.2",
    "libp2p-yamux-0.47.0", "time-0.3.41",
)
REGISTRY_LOCKS = (Path("Cargo.lock"), Path("fuzz/Cargo.lock"), HARNESS / "Cargo.lock")
EXPORTS = {"before.Cargo.lock", "after.Cargo.lock", "Cargo.lock.diff", "status.json"}
POLICY = runpy.run_path(str(Path(__file__).with_name('cargo-source-policy.py')))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_file(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError("invalid bounded input")
    data = path.read_bytes()
    if len(data) > LIMIT:
        raise ValueError("oversized input")
    return data


def locked_registry(lock):
    """Existing registry versions/checksums may not be upgraded by diagnostics."""
    return {
        (p["name"], p["version"], p["source"]): p.get("checksum")
        for p in tomllib.loads(lock.decode("utf-8"))["package"]
        if p.get("source", "").startswith("registry+")
    }


def copy_inputs(repository, temporary):
    for relative in HARNESS_FILES:
        source = repository / HARNESS / relative
        data = bounded_file(source)
        destination = temporary / HARNESS / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes(data)
    for name in VENDORS:
        source = repository / "third_party/rust/vendor" / name
        if not source.is_dir() or source.is_symlink():
            raise ValueError("invalid vendor input")
        if any(path.is_symlink() for path in source.rglob("*")):
            raise ValueError("symlink in vendor input")
        shutil.copytree(source, temporary / "third_party/rust/vendor" / name)


def diagnose(repository, output, fetch_status, run=subprocess.run):
    if type(fetch_status) is not int or not 1 <= fetch_status <= 255:
        raise ValueError("original failure status required")
    repository = repository.resolve(strict=True)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    status = {
        "schema_version": 1,
        "kind": "standalone-backport-lock-diagnostic",
        "acceptance_evidence": False,
        "original_fetch_status": fetch_status,
        "source_verification": "not_run",
        "normalization": "not_run",
        "normalization_exit_status": None,
        "workspace_locks_unchanged": False,
        "existing_registry_pins_preserved": None,
        "before_sha256": None,
        "after_sha256": None,
        "diff_sha256": None,
    }
    original_locks = None
    try:
        original_locks = {str(path): bounded_file(repository / path) for path in REGISTRY_LOCKS}
        before = original_locks[str(HARNESS / "Cargo.lock")]
        (output / "before.Cargo.lock").write_bytes(before)
        status["before_sha256"] = digest(before)
        verification = run(
            ["sh", "scripts/check-rust-dependencies.sh", "--verify-vendor-only"],
            cwd=repository, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=TIMEOUT, check=False,
        )
        if verification.returncode != 0:
            status["source_verification"] = "failed"
            return status
        status["source_verification"] = "verified"
        with tempfile.TemporaryDirectory(prefix="volparossa-lock-diagnostic-") as directory:
            temporary = Path(directory)
            copy_inputs(repository, temporary)
            environment = os.environ.copy()
            environment = POLICY['validate_diagnostic'](temporary / HARNESS, environment)
            environment["CARGO_NET_OFFLINE"] = "true"
            environment["RUSTUP_AUTO_INSTALL"] = "0"
            # run requires the already installed toolchain; update performs no builds.
            # --workspace retains existing registry pins, adding only required nodes.
            status["normalization"] = "running"
            result = run(
                ["rustup", "run", "1.85.0", "cargo", "update", "--offline", "--workspace"],
                cwd=temporary / HARNESS, env=environment,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=TIMEOUT, check=False,
            )
            status["normalization_exit_status"] = result.returncode
            status["normalization"] = "resolved" if result.returncode == 0 else "failed"
            after = bounded_file(temporary / HARNESS / "Cargo.lock")
            original_registry = locked_registry(before)
            updated_registry = locked_registry(after)
            pins_preserved = all(
                key in updated_registry and updated_registry[key] == value
                for key, value in original_registry.items()
            )
            status["existing_registry_pins_preserved"] = pins_preserved
            if not pins_preserved:
                status["normalization"] = "registry_pins_changed"
            difference = "".join(difflib.unified_diff(
                before.decode("utf-8").splitlines(keepends=True),
                after.decode("utf-8").splitlines(keepends=True),
                fromfile="before.Cargo.lock", tofile="after.Cargo.lock",
            )).encode("utf-8")
            if len(difference) > LIMIT:
                status["normalization"] = "diff_oversized"
                return status
            (output / "after.Cargo.lock").write_bytes(after)
            (output / "Cargo.lock.diff").write_bytes(difference)
            status["after_sha256"] = digest(after)
            status["diff_sha256"] = digest(difference)
    except subprocess.TimeoutExpired:
        if status["source_verification"] == "not_run":
            status["source_verification"] = "timed_out"
        else:
            status["normalization"] = "timed_out"
    except (OSError, ValueError, KeyError, UnicodeError):
        status["normalization"] = "diagnostic_input_error"
    finally:
        if original_locks is not None:
            try:
                status["workspace_locks_unchanged"] = all(
                    bounded_file(repository / path) == data for path, data in original_locks.items()
                )
            except (OSError, ValueError):
                status["workspace_locks_unchanged"] = False
        (output / "status.json").write_text(json.dumps(status, sort_keys=True) + "\n", encoding="ascii")
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch-status", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and hasattr(os, "geteuid") and os.geteuid() != 0
    ):
        parser.error("diagnostics require a non-root Linux GitHub-hosted runner")
    diagnose(Path(__file__).resolve().parents[1], args.output, args.fetch_status)


if __name__ == "__main__":
    main()
