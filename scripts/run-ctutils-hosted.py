#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable hosted-only compatibility and codegen capture; manual review remains required."""
import hashlib
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import re
import runpy
import signal
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
COMPILERS = ("1.99.1",)
TARGETS = ("x86_64-unknown-linux-gnu", "i686-unknown-linux-musl")
GROUP = runpy.run_path(str(ROOT / 'scripts/provision-rust199.py'))
MUSL = runpy.run_path(str(ROOT / 'scripts/prepare-musl-i386.py'))
FEATURES = ((), ("alloc",), ("subtle",), ("alloc", "subtle"))
RELEASE = {"codegen-units": 1, "lto": "thin", "opt-level": 3, "panic": "abort", "strip": "debuginfo"}
SYMBOLS = tuple("ct_mask_" + t for t in ("u8", "u16", "u32", "u64", "u128")) + tuple(
    "ct_select_" + t for t in ("u8", "u16", "u32", "u64", "u128", "i64")) + (
    "ct_lt_u128", "ct_le_u128", "ct_trait_lt_u128", "ct_trait_gt_u128",
    "ct_digest_output_eq", "ct_poly1305_verify",
    "ct_borrow_u32", "ct_borrow_u64", "ct_addback_u32", "ct_addback_u64",
    "ct_leading_zeros_u32", "ct_trailing_zeros_u32",
    "ct_leading_zeros_u64", "ct_trailing_zeros_u64", "ct_p384_verify",
    "ct_overflowing_add_u64", "ct_overflowing_add_u128")


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


def fixture_lock(path):
    packages = tomllib.loads(path.read_text())["package"]
    for name, version in (("ctutils", "0.4.5"), ("crypto-bigint", "0.7.9"), ("p384", "0.14.0")):
        matches = [package for package in packages if package["name"] == name]
        if len(matches) != 1 or matches[0]["version"] != version:
            raise ValueError("current fixture dependency mismatch: " + name)
        if name == "ctutils" and "source" in matches[0]:
            raise ValueError("fixture ctutils must use reviewed local source")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def remove_private(path, safe):
    """Never remove scratch while owned children may remain or follow a substituted link."""
    if path.is_symlink():
        return False
    if not path.exists():
        return True
    if not safe:
        return False
    try:
        shutil.rmtree(path)
    except OSError:
        return False
    return True


def run_owned(command, *, cwd, env, stream, timeout):
    """Use the already reviewed leader/group identity and cleanup contract."""
    child = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                             stderr=subprocess.STDOUT, start_new_session=True)
    try:
        result = GROUP['wait_for_leader'](child, timeout)
    finally:
        GROUP['finish_group'](child)
    if result.si_code != os.CLD_EXITED or result.si_status != 0:
        raise subprocess.CalledProcessError(result.si_status, command)


@contextmanager
def provision_log(stream):
    """Capture the in-process provisioner and inherited installer output without a wrapper process."""
    sys.stdout.flush()
    sys.stderr.flush()
    saved = {fd: os.dup(fd) for fd in (1, 2)}
    try:
        for fd in saved:
            os.dup2(stream.fileno(), fd)
        with redirect_stdout(stream), redirect_stderr(stream):
            yield
    finally:
        stream.flush()
        for fd, original in saved.items():
            os.dup2(original, fd)
            os.close(original)


def interrupted(_number, _frame):
    raise InterruptedError('hosted native proof interrupted')


def execute(output):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    admission(os.environ, revision)  # Before any installation, fetch or compilation.
    temporary = Path(os.environ["RUNNER_TEMP"])
    if (not temporary.is_absolute() or temporary.resolve() != temporary
            or temporary.is_relative_to(ROOT) or output.parent != temporary
            or output.is_symlink()):
        raise ValueError("proof output must be a fresh direct child of canonical runner temporary root outside checkout")
    output.mkdir(mode=0o700, exist_ok=False)
    commands = []
    receipt = dict(schema=1, revision=revision, functional_tests_passed=False,
                   codegen_review="required", constant_time_proven=False, commands=commands)
    private = output.parent / (output.name + "-private")
    if private.exists() or private.is_symlink():
        raise ValueError("private proof prefix already exists")
    env = os.environ.copy()
    env["CARGO_HOME"] = str(private / "cargo-home")
    env["TMPDIR"] = str(private / "tmp")

    musl_prefix = Path(os.environ['RUNNER_TEMP']) / 'ctutils-musl-i386'
    if musl_prefix.exists() or musl_prefix.is_symlink():
        raise ValueError('musl input prefix already exists')
    private_created = False
    group_cleanup_confirmed = True
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}

    def run(command, label, *, custom_env=None, tests=False):
        nonlocal group_cleanup_confirmed
        log = output / (label + ".log")
        commands.append(dict(command=list(map(str, command)), label=label))
        with log.open("w") as stream:
            group_cleanup_confirmed = False
            try:
                run_owned(command, cwd=ROOT, env=custom_env or env, stream=stream, timeout=1800)
            except GROUP['CleanupUnconfirmed']:
                raise
            except BaseException:
                group_cleanup_confirmed = True
                raise
            group_cleanup_confirmed = True
        if tests and not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", log.read_text()):
            raise ValueError("positive test execution missing: " + label)
        if tests:
            receipt.setdefault("test_results", {})[label] = {
                "summaries": re.findall(r"test result: .*", log.read_text()),
                "names": re.findall(r"^test (.+) \.\.\. ok$", log.read_text(), re.MULTILINE)}
            if "sev-public-signatures" in label and (
                    "provider::compute::attestation::tests::real_public_signatures_return_only_incomplete_facts"
                    not in receipt["test_results"][label]["names"]):
                raise ValueError("required real SEV public-signature test did not execute")
        print(label + ": passed", flush=True)

    try:
        receipt["fixture_lock_sha256"] = fixture_lock(ROOT / "third_party/rust/ctutils-current-regressions/Cargo.lock")
        private.mkdir(mode=0o700)
        private_created = True
        Path(env["TMPDIR"]).mkdir(mode=0o700)
        receipt['musl_input'] = MUSL['prepare'](musl_prefix, output, run)
        run(["python3", "-B", "scripts/test-ctutils-scope.py"], "source-scope")
        run(["sh", "scripts/check-rust-dependencies.sh", "--verify-vendor-only"], "vendor-reconstruction")
        # Private exact copy keeps the official crate and its upstream lock untouched.
        base = private / "upstream-ctutils-0.4.5"
        shutil.copytree(ROOT / "third_party/rust/vendor/ctutils-0.4.5", base)
        harness = ROOT / "third_party/rust/ctutils-current-regressions"
        receipt["source_inputs"] = {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in (ROOT / "third_party/rust/vendor/ctutils-0.4.5", harness)
            for path in sorted(directory.rglob("*")) if path.is_file()}

        for compiler in COMPILERS:
            compiler_env = env.copy()
            provisioning = dict(operation="in-process provision('runner')", label="install-" + compiler,
                                passed=False)
            commands.append(provisioning)
            with (output / ("install-" + compiler + ".log")).open("w") as stream:
                with provision_log(stream):
                    group_cleanup_confirmed = False
                    try:
                        rust_prefix = GROUP['provision']('runner')
                    except GROUP['CleanupUnconfirmed']:
                        raise
                    except BaseException:
                        group_cleanup_confirmed = True
                        raise
                    group_cleanup_confirmed = True
            provisioning["passed"] = True
            print("install-" + compiler + ": passed", flush=True)
            compiler_env.update(PATH=str(rust_prefix / "bin") + os.pathsep + env["PATH"],
                                RUSTC=str(rust_prefix / "bin/rustc"), RUSTDOC=str(rust_prefix / "bin/rustdoc"))
            receipt["current_compiler"] = json.loads((rust_prefix / "receipt.json").read_text())
            rustc = [str(rust_prefix / "bin/rustc")]
            cargo = [str(rust_prefix / "bin/cargo")]
            run(rustc + ["--version", "--verbose"], "compiler-" + compiler, custom_env=compiler_env)
            sysroot = subprocess.check_output(rustc + ["--print", "sysroot"], env=compiler_env, text=True).strip()
            linker = Path(sysroot) / "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
            if not linker.is_file():
                raise ValueError("pinned compiler's bundled rust-lld unavailable")
            for package, package_path in (("upstream", base), ("consumers", harness)):
                run(cargo + ["fetch", "--locked", "--manifest-path", str(package_path / "Cargo.toml")],
                    "fetch-" + compiler + "-" + package, custom_env=compiler_env)
            for target in TARGETS:
                tag = compiler + "-" + target
                target_dir = private / ("ctutils-target-" + tag)
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
                     "--lib", "--", "--emit=asm,llvm-ir"],
                    "library-codegen-" + tag, custom_env=build_env)
                run(cargo + ["rustc", "--manifest-path", str(harness / "Cargo.toml"),
                     "--locked", "--offline", "--release", "--target", target,
                     "--bin", "volparossa-ctutils-regressions", "--", "--emit=asm,llvm-ir,link"],
                    "release-" + tag, custom_env=build_env)
                binary = target_dir / target / "release/volparossa-ctutils-regressions"
                receipt.setdefault("linked_binary_sha256", {})[tag] = hashlib.sha256(binary.read_bytes()).hexdigest()
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
                CARGO_TARGET_DIR=str(private / ("ctutils-core-target-" + target)),
                CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER=str(linker))
            if target == 'i686-unknown-linux-musl':
                build_env['CC_i686_unknown_linux_musl'] = str(musl_prefix / 'musl-gcc')
            for package, test_filter, label in (
                    ("volparossa-protocol", "native_route_credential", "route-credentials"),
                    ("volparossa-content", "private_message", "private-messages"),
                    ("volparossa-content", "provider::compute::attestation::tests::", "sev-public-signatures")):
                run(cargo + ["test", "--locked", "--offline", "--target", target,
                    "-p", package, test_filter], "core-hpke-" + label + "-" + target,
                    custom_env=build_env, tests=True)
        receipt["functional_tests_passed"] = True
    except BaseException as error:
        receipt["failure"] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        for number, handler in previous.items(): signal.signal(number, handler)
        receipt['process_group_cleanup_confirmed'] = group_cleanup_confirmed
        if not group_cleanup_confirmed:
            receipt['retained_prefixes'] = [str(private), str(musl_prefix),
                str(temporary / "volparossa-rust-1.99.1")]
            receipt['retained_compiler_staging_candidates'] = [
                str(path) for path in sorted(temporary.glob("rust199-components-*"))]
        receipt['musl_input_removed'] = remove_private(musl_prefix, group_cleanup_confirmed)
        receipt['private_graph_removed'] = (not private_created or remove_private(private, group_cleanup_confirmed))
        if not receipt['musl_input_removed'] or not receipt['private_graph_removed']:
            receipt['functional_tests_passed'] = False
        receipt["profile"] = RELEASE
        receipt["review_entrypoints"] = SYMBOLS
        (output / "REVIEW_REQUIRED.md").write_text(
            "Functional execution is separate from constant-time acceptance. Review Rust 1.99.1 "
            "ctutils 0.4.5 linked assembly/LLVM for every named secret-input entrypoint on both targets "
            "with opt-level3/thinLTO/one codegen unit, especially borrow and masked add-back, zero "
            "counts, digest and universal-hash consumers. P384 verification uses public inputs; inspect "
            "its linked crypto-bigint path separately. Check control flow and dataflow, not merely branch "
            "counts. Historical 0.4.4 compiler results are retained and are not rerun here. This capture "
            "is not a formal or universal cryptographic proof. Record findings and exact artifact hashes.\n")
        receipt["artifacts"] = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in artifact_files(output) if p.name != "receipt.json"}
        receipt["published_files"] = ["receipt.json", *receipt["artifacts"]]
        receipt["receipt_self_hash_excluded"] = True
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if (not receipt['musl_input_removed'] or not receipt['private_graph_removed']) and 'failure' not in receipt:
            raise ValueError('proof cleanup unconfirmed; retaining private scratch')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: run-ctutils-hosted.py NEW_EVIDENCE_DIRECTORY")
    execute(Path(sys.argv[1]).resolve())
