#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable hosted-only compatibility and codegen capture; manual review remains required."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
COMPILERS = ("1.85.0", "1.87.0", "1.99.1")
TARGETS = ("x86_64-unknown-linux-gnu", "i686-unknown-linux-musl")
FEATURES = ((), ("alloc",), ("subtle",), ("alloc", "subtle"))
RELEASE = {"codegen-units": 1, "lto": "thin", "opt-level": 3, "panic": "abort", "strip": "debuginfo"}
SYMBOLS = tuple("ct_mask_" + t for t in ("u8", "u16", "u32", "u64", "u128")) + tuple(
    "ct_select_" + t for t in ("u8", "u16", "u32", "u64", "u128", "i64")) + (
    "ct_lt_u128", "ct_le_u128", "ct_trait_lt_u128", "ct_trait_gt_u128",
    "ct_digest_output_eq", "ct_poly1305_verify")


def admission(env, revision):
    if env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("requires an explicitly assigned disposable GitHub-hosted runner")
    if re.fullmatch("[0-9a-f]{40}", revision) is None or revision != env.get("GITHUB_SHA") or revision != env.get("CTUTILS_CORE_REVISION"):
        raise ValueError("exact workflow/source revision mismatch")


def artifact_files(output):
    """Only the explicit upload payload; no source trees, binaries or Cargo homes."""
    candidates = [output / "receipt.json", output / "REVIEW_REQUIRED.md"]
    candidates.extend(output.glob("*.log"))
    for directory in output.glob("codegen-*"):
        if directory.is_symlink():
            raise ValueError("codegen evidence directory must not be a symlink")
        if directory.is_dir():
            candidates.extend(directory.glob("*.s"))
            candidates.extend(directory.glob("*.ll"))
    selected = []
    for path in candidates:
        if path.name.startswith("."):
            continue  # Match upload-artifact's default hidden-file exclusion.
        if path.is_symlink():
            raise ValueError("published evidence must not be a symlink")
        if path.is_file():
            selected.append(path)
    return sorted(set(selected))


def execute(output):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    admission(os.environ, revision)  # Before any installation, fetch or compilation.
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    receipt = dict(schema=1, revision=revision, functional_tests_passed=False,
                   codegen_review="required", constant_time_proven=False, commands=commands)
    env = os.environ.copy()
    env["CARGO_HOME"] = str(output.parent / "ctutils-cargo-home")
    env["TMPDIR"] = str(output.parent / "ctutils-tmp")
    Path(env["TMPDIR"]).mkdir(exist_ok=True)

    def run(command, label, *, custom_env=None, tests=False):
        log = output / (label + ".log")
        commands.append(dict(command=list(map(str, command)), label=label))
        with log.open("w") as stream:
            subprocess.run(command, cwd=ROOT, env=custom_env or env, check=True,
                           stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
        if tests and not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", log.read_text()):
            raise ValueError("positive test execution missing: " + label)
        print(label + ": passed", flush=True)

    try:
        run(["python3", "-B", "scripts/test-ctutils-scope.py"], "source-scope")
        run(["sh", "scripts/check-rust-dependencies.sh", "--verify-vendor-only"], "vendor-reconstruction")
        # Official, checked-in original crate for the unmodified 1.87 reference.
        archive = ROOT / "third_party/rust/sources/ctutils-0.4.4.crate"
        if hashlib.sha256(archive.read_bytes()).hexdigest() != "12218662ccac37d9714f2191252553d67585b97df8c839cbe49e0bde278dc865":
            raise ValueError("original archive checksum mismatch")
        reference = output / "reference"
        reference.mkdir()
        with tarfile.open(archive) as source:
            # Known archive paths, normal files only; never extract links or other objects.
            for member in source.getmembers():
                path = Path(member.name)
                if not member.isfile() or path.is_absolute() or ".." in path.parts or path.parts[0] != "ctutils-0.4.4":
                    raise ValueError("invalid official archive entry")
                destination = reference / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.extractfile(member).read())
        fixture = ROOT / "third_party/rust/ctutils-regressions"
        reference_fixture = reference / "fixture"
        shutil.copytree(fixture, reference_fixture)
        manifest = reference_fixture / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace("../vendor/ctutils-0.4.4", str(reference / "ctutils-0.4.4")))

        for compiler in COMPILERS:
            compiler_env = env.copy()
            if compiler == "1.99.1":
                run(["python3", "-B", "scripts/provision-rust199.py", "runner"], "install-" + compiler)
                prefix = Path(os.environ["RUNNER_TEMP"]) / "volparossa-rust-1.99.1"
                compiler_env.update(PATH=str(prefix / "bin") + os.pathsep + env["PATH"],
                                    RUSTC=str(prefix / "bin/rustc"), RUSTDOC=str(prefix / "bin/rustdoc"))
                receipt["current_compiler"] = json.loads((prefix / "receipt.json").read_text())
                rustc = [str(prefix / "bin/rustc")]
                cargo = [str(prefix / "bin/cargo")]
            else:
                run(["rustup", "toolchain", "install", compiler, "--profile", "minimal",
                     "--target", ",".join(TARGETS)], "install-" + compiler)
                rustc, cargo = ["rustc", "+" + compiler], ["cargo", "+" + compiler]
            run(rustc + ["--version", "--verbose"], "compiler-" + compiler, custom_env=compiler_env)
            sysroot = subprocess.check_output(rustc + ["--print", "sysroot"], env=compiler_env, text=True).strip()
            linker = Path(sysroot) / "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
            if not linker.is_file():
                raise ValueError("pinned compiler's bundled rust-lld unavailable")
            base = ROOT / "third_party/rust/vendor/ctutils-0.4.4" if compiler != "1.87.0" else reference / "ctutils-0.4.4"
            harness = fixture if compiler != "1.87.0" else reference_fixture
            for package, package_path in (("upstream", base), ("consumers", harness)):
                run(cargo + ["fetch", "--locked", "--manifest-path", str(package_path / "Cargo.toml")],
                    "fetch-" + compiler + "-" + package, custom_env=compiler_env)
            for target in TARGETS:
                tag = compiler + "-" + target
                target_dir = output.parent / ("ctutils-target-" + tag)
                build_env = dict(compiler_env, CARGO_TARGET_DIR=str(target_dir),
                                 CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER=str(linker),
                                 PROPTEST_CASES="1024")
                for features in FEATURES:
                    command = cargo + ["test", "--manifest-path", str(base / "Cargo.toml"),
                               "--locked", "--offline", "--target", target, "--no-default-features"]
                    if features:
                        command += ["--features", ",".join(features)]
                    run(command, "upstream-" + tag + "-" + ("-".join(features) or "no-std"), custom_env=build_env, tests=True)
                run(cargo + ["test", "--manifest-path", str(harness / "Cargo.toml"),
                     "--locked", "--offline", "--target", target], "consumers-" + tag, custom_env=build_env, tests=True)
                run(cargo + ["rustc", "--manifest-path", str(harness / "Cargo.toml"),
                     "--locked", "--offline", "--release", "--target", target,
                     "--bin", "volparossa-ctutils-regressions", "--", "--emit=asm,llvm-ir,link"],
                    "release-" + tag, custom_env=build_env)
                binary = target_dir / target / "release/volparossa-ctutils-regressions"
                run([str(binary)], "release-smoke-" + tag, custom_env=build_env)
                run(["objdump", "-d", "--no-show-raw-insn", "--demangle", str(binary)], "linked-disassembly-" + tag)
                run(["nm", "--defined-only", str(binary)], "linked-symbols-" + tag)
                symbols = (output / ("linked-symbols-" + tag + ".log")).read_text()
                if any(re.search(r"\b" + symbol + r"$", symbols, re.MULTILINE) is None for symbol in SYMBOLS):
                    raise ValueError("a required linked review entrypoint is absent")
                codegen = output / ("codegen-" + tag)
                codegen.mkdir()
                for pattern in ("*.s", "*.ll"):
                    files = list((target_dir / target / "release/deps").glob(pattern))
                    if not files:
                        raise ValueError("expected compiler codegen output missing")
                    for path in files:
                        if path.stat().st_size > 64 * 1024 * 1024:
                            raise ValueError("oversized codegen output")
                        shutil.copyfile(path, codegen / path.name)

        # Actual Core HPKE callsites, not the codegen harness alone.
        run(cargo + ["fetch", "--locked"], "fetch-core", custom_env=compiler_env)
        for target in TARGETS:
            build_env = dict(compiler_env,
                CARGO_TARGET_DIR=str(output.parent / ("ctutils-core-target-" + target)),
                CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER=str(linker))
            for package, test_filter, label in (
                    ("volparossa-protocol", "native_route_credential", "route-credentials"),
                    ("volparossa-content", "private_message", "private-messages")):
                run(cargo + ["test", "--locked", "--offline", "--target", target,
                    "-p", package, test_filter], "core-hpke-" + label + "-" + target,
                    custom_env=build_env, tests=True)
        receipt["functional_tests_passed"] = True
    finally:
        receipt["profile"] = RELEASE
        receipt["review_entrypoints"] = SYMBOLS
        (output / "REVIEW_REQUIRED.md").write_text(
            "Functional execution is separate from constant-time acceptance. Review adapted Rust 1.85/1.99.1 "
            "and unmodified Rust 1.87 linked assembly/LLVM for every named secret-input entrypoint, "
            "including digest and universal-hash consumers, on both targets with opt-level3/thinLTO/one "
            "codegen unit. Check secret-dependent control flow and dataflow, not merely branch counts. "
            "This capture is not BINSEC or a universal cryptographic proof. Record findings and exact "
            "compiler/target/artifact hashes before accepting the adaptation. Hosted Quality audits "
            "are still required; known unmaintained advisories remain open.\n")
        receipt["artifacts"] = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in artifact_files(output) if p.name != "receipt.json"}
        receipt["published_files"] = ["receipt.json", *receipt["artifacts"]]
        receipt["receipt_self_hash_excluded"] = True
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: run-ctutils-hosted.py NEW_EVIDENCE_DIRECTORY")
    execute(Path(sys.argv[1]).resolve())
