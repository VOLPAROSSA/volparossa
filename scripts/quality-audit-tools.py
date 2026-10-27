#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Optional cache for this workflow's own pinned source-built audit tools.

The receipt detects corruption and recipe drift; GitHub's branch isolation and
main-push-only saves supply provenance. This is not a signed binary attestation.
No Cargo home, advisory database, audit result or repository artifact is cached.
"""

import hashlib
import json
import os
import runpy
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time


TOOLS = {"cargo-deny": ("1.88.0", "0.18.6"), "cargo-audit": ("1.85.0", "0.22.1")}
MAX_BYTES = 128 * 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
FILES = {"bin", "receipt.json"}
POLICY = runpy.run_path(str(Path(__file__).with_name('cargo-source-policy.py')))


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def recipe():
    return {
        "schema": 1, "platform": "ubuntu-24.04-X64", "tools": TOOLS,
        "helper_sha256": digest(Path(__file__)),
        "rust_toolchain_sha256": digest(Path("rust-toolchain.toml")),
        "workflow_sha256": digest(Path(".github/workflows/quality.yml")),
        "cargo_source_policy_sha256": digest(Path(__file__).with_name('cargo-source-policy.py')),
    }


def cache_key(expected):
    raw = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    return "quality-audit-tools-v1-" + hashlib.sha256(raw).hexdigest()


def require(condition):
    if not condition:
        raise ValueError("invalid audit-tool cache")


def regular_file(path, limit, executable=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    require(info.st_uid == os.getuid() and 0 < info.st_size <= limit)
    require(stat.S_IMODE(info.st_mode) == (0o755 if executable else 0o600))
    return info.st_size


def validate(root, expected, trusted=True):
    # Check the entire closed inventory and every digest before executing a tool.
    require(stat.S_ISDIR(root.lstat().st_mode) and {p.name for p in root.iterdir()} == FILES)
    binaries = root / "bin"
    require(stat.S_ISDIR(binaries.lstat().st_mode))
    require({p.name for p in binaries.iterdir()} == set(TOOLS))
    total = regular_file(root / "receipt.json", MAX_RECEIPT_BYTES)
    receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
    require(set(receipt) == {"recipe", "producer", "files"})
    # JSON normalizes the tool version tuples into lists.
    require(receipt["recipe"] == json.loads(json.dumps(expected)))
    producer = receipt["producer"]
    require(set(producer) == {"event", "ref", "source"})
    require(isinstance(producer["source"], str) and len(producer["source"]) == 40
            and all(c in "0123456789abcdef" for c in producer["source"]))
    if trusted:
        require(producer["event"] == "push" and producer["ref"] == "refs/heads/main")
    require(set(receipt["files"]) == set(TOOLS))
    for name in TOOLS:
        size = regular_file(binaries / name, MAX_BYTES // 2, executable=True)
        total += size
        require(receipt["files"][name] == {"bytes": size, "sha256": digest(binaries / name)})
    require(total <= MAX_BYTES)
    return total


def versions(root, run=subprocess.run):
    for name, (_, version) in TOOLS.items():
        result = run([str(root / "bin" / name), "--version"], check=True,
                     capture_output=True, text=True, timeout=10)
        require(result.stdout.strip() == name + " " + version)


def remove_candidate(root):
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        root.unlink()
    elif root.exists():
        shutil.rmtree(root)


def source_build(root, expected, run=subprocess.run):
    remove_candidate(root)
    # Cargo's installation metadata and all compiler intermediates stay outside
    # the cache. A failed command propagates; it cannot become a cache success.
    with tempfile.TemporaryDirectory(prefix="audit-tools-build-", dir=root.parent) as directory:
        staging = Path(directory) / "install"
        for name, (compiler, version) in TOOLS.items():
            cargo_env = POLICY['activate']('runner', home=Path(directory)/('cargo-home-'+name))
            POLICY['audit_tool'](name)  # Exact public crate + bundled canonical lock, before Cargo.
            POLICY['write_scope'](cargo_env, root.parent/('cargo-source-policy-'+name+'.json'), tool=name)
            run(["rustup", "toolchain", "install", compiler, "--profile", "minimal"], check=True, env=cargo_env)
            rustc = run(["rustup", "which", "--toolchain", compiler, "rustc"],
                        check=True, capture_output=True, text=True, env=cargo_env).stdout.strip()
            require(Path(rustc).is_absolute())
            # Core's verified compiler prefix precedes rustup shims on PATH.
            # Bind both the tool Cargo and its child rustc to their own recipe.
            run(["rustup", "run", compiler, "cargo", "install", "--locked", "--root", str(staging),
                 "--version", "=" + version, "--registry", "crates-io", name], check=True,
                env=dict(cargo_env, RUSTC=rustc))
        (root / "bin").mkdir(parents=True, mode=0o700)
        for name in TOOLS:
            shutil.copyfile(staging / "bin" / name, root / "bin" / name)
            (root / "bin" / name).chmod(0o755)
    receipt = {
        "recipe": expected,
        "producer": {"event": os.environ["GITHUB_EVENT_NAME"], "ref": os.environ["GITHUB_REF"],
                     "source": os.environ["GITHUB_SHA"]},
        "files": {name: {"bytes": (root / "bin" / name).stat().st_size,
                         "sha256": digest(root / "bin" / name)} for name in TOOLS},
    }
    (root / "receipt.json").write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    (root / "receipt.json").chmod(0o600)
    validate(root, expected, trusted=False)
    versions(root, run)


def install(root, expected, exact_hit, run=subprocess.run):
    outcome = "miss"
    if exact_hit:
        try:
            size = validate(root, expected)
            versions(root, run)
            return "hit", size
        except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
            # Never expose cached output or use a rejected binary as a fallback.
            outcome = "invalid"
    source_build(root, expected, run)
    return outcome + "-source-built", validate(root, expected, trusted=False)


def probe(root, expected, exact_hit, run=subprocess.run):
    # Measurement only: every failure propagates; there is no build/save path.
    require(exact_hit)
    size = validate(root, expected)
    versions(root, run)
    return "hit", size


def output(name, value):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        stream.write(name + "=" + str(value) + "\n")


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in {"prepare", "install", "save-check", "probe"})
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64")
    require(os.environ.get("ImageOS") == "ubuntu24"
            and os.environ.get("GITHUB_REPOSITORY") == "VOLPAROSSA/volparossa")
    root = Path(os.environ["RUNNER_TEMP"]) / "quality-audit-tools"
    expected = recipe()
    key = cache_key(expected)
    if sys.argv[1] == "prepare":
        require(not root.exists() and not root.is_symlink())
        output("key", key)
        output("path", root)
        return
    require(os.environ.get("AUDIT_CACHE_KEY") == key)
    if sys.argv[1] == "save-check":
        require(os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_REF"] == "refs/heads/main")
        validate(root, expected)
        versions(root)
        output("cacheable", "true")
        return
    started = time.monotonic()
    is_probe = sys.argv[1] == "probe"
    if is_probe:
        require(os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch" and os.environ["GITHUB_REF"] == "refs/heads/main")
    operation = probe if is_probe else install
    outcome, size = operation(root, expected, os.environ.get("AUDIT_CACHE_EXACT_HIT") == "true")
    elapsed = round(time.monotonic() - started, 3)
    if not is_probe:
        output("source-built", str(outcome != "hit").lower())
        with Path(os.environ["GITHUB_PATH"]).open("a", encoding="utf-8") as stream:
            stream.write(str(root / "bin") + "\n")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
        stream.write("### Pinned audit-tool cache\n\n"
                     f"- Scope: {'read-only warm-cache probe; no Quality gates run' if is_probe else 'Quality tool preparation'}.\n"
                     f"- Outcome: `{outcome}`; payload: {size} / {MAX_BYTES} bytes.\n"
                     f"- Validation/source-build time: {elapsed}s (restore time is a separate action step).\n"
                     f"- Exact recipe key: `{key}`.\n"
                     "- Only successful main Quality runs may publish this cache.\n")


if __name__ == "__main__":
    main()
