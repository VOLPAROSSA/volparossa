#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fixed C11 compiler comparison; capped diagnostics are never acceptance."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE = "c11d97f4265834218500ba7ec7e2aff1e66c55db"
TREE = "ceb06c7b636b6c50430d00d66563a1f3a7f0404f"
PROFILES = ("1.89.0", "1.99.1")
VARIANTS = ("strict", "diagnostic-NON-ACCEPTANCE")
LOCKS = {"Cargo.lock": "1ed913b2cc64690d0c3bbb3c484071f72cd1c202a6372f608d13c8c99bc2fb8b",
         "fuzz/Cargo.lock": "3b28c49468ac9096621405acdf685b7216d00b4ced8642d666a86f14b0ba4159"}
ATOMIC = {
    "crates/volparossa-agent/src/content/storage_maintenance.rs": 1,
    "crates/volparossa-content/src/provider/compute/attestation/session.rs": 2,
    "crates/volparossa-helper/src/ownership_journal/actor.rs": 2,
    "crates/volparossa-metrics/src/lib.rs": 1,
    "crates/volparossa-udp/src/dns/resolver.rs": 1,
    "crates/volparossa-udp/src/endpoint.rs": 1,
}
DURATIONS = (
    "crates/volparossa-content/src/origin_https.rs",
    "crates/volparossa-content/src/provider.rs",
    "crates/volparossa-content/src/provider/custody/session.rs",
    "crates/volparossa-content/src/transfer.rs",
)
DECLARATIONS = {"Cargo.toml": (b'rust-version = "1.99.1"', b'rust-version = "1.89.0"'),
                "fuzz/Cargo.toml": (b'rust-version = "1.99.1"', b'rust-version = "1.89.0"'),
                "rust-toolchain.toml": (b'channel = "1.99.1"', b'channel = "1.89.0"')}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def location():
    env = os.environ
    if (env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or env.get("RUNNER_OS") != "Linux" or env.get("RUNNER_ARCH") != "X64"
            or env.get("GITHUB_REPOSITORY") != "VOLPAROSSA/volparossa"
            or env.get("GITHUB_REF") != "refs/heads/proof/p03f-f04-collapse-corrected-20261027"
            or env.get("GITHUB_WORKFLOW_SHA") != env.get("GITHUB_SHA")):
        raise ValueError("requires exact proof branch on disposable hosted amd64 runner")
    workspace = Path(env["GITHUB_WORKSPACE"])
    if not workspace.is_absolute() or workspace.is_symlink():
        raise ValueError("invalid hosted workspace")
    if any(value for name, value in env.items() if name in {
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "CLIPPY_CONF_DIR"} or name.endswith("_RUSTFLAGS")):
        raise ValueError("compiler or lint overrides are not part of this comparison")
    return workspace / "source", workspace / "evidence"


def compatibility_changes(originals):
    expected = set(ATOMIC) | set(DURATIONS) | set(DECLARATIONS)
    if set(originals) != expected:
        raise ValueError("compatibility input paths changed")
    changed = {}
    for name, raw in originals.items():
        if name in ATOMIC:
            old, new, count = b".try_update(", b".fetch_update(", ATOMIC[name]
        elif name in DURATIONS:
            old, new, count = b"Duration::from_mins(15)", b"Duration::from_secs(900)", 1
        else:
            old, new = DECLARATIONS[name]
            count = 1
        if raw.count(old) != count:
            raise ValueError("compatibility input occurrence changed: " + name)
        changed[name] = raw.replace(old, new)
    return changed


def check_source(root, record):
    if git(root, "rev-parse", "HEAD").decode().strip() != SOURCE:
        raise ValueError("source revision changed")
    patch = git(root, "diff", "--binary", "--no-ext-diff")
    if digest(patch) != record["compatibility_patch_sha256"]:
        raise ValueError("working source differs from the exact compatibility patch")
    if digest(git(root, "ls-files", "-s")) != record["original_index_sha256"]:
        raise ValueError("source index changed")
    if git(root, "ls-files", "--others", "--exclude-standard").strip():
        raise ValueError("untracked source files appeared")
    for name, expected in LOCKS.items():
        if digest((root / name).read_bytes()) != expected:
            raise ValueError("original C11 lock changed: " + name)
    for name, expected in record["compatible_file_sha256"].items():
        if digest((root / name).read_bytes()) != expected:
            raise ValueError("compatible source file changed: " + name)


def prepare():
    root, evidence = location()
    if (git(root, "rev-parse", "HEAD").decode().strip() != SOURCE
            or git(root, "rev-parse", "HEAD^{tree}").decode().strip() != TREE
            or git(root, "status", "--porcelain", "--untracked-files=all").strip()):
        raise ValueError("source is not clean exact C11")
    evidence.mkdir()
    index = git(root, "ls-files", "-s")
    (evidence / "original-tracked-source-index.txt").write_bytes(index)
    originals = {name: git(root, "show", SOURCE + ":" + name)
                 for name in set(ATOMIC) | set(DURATIONS) | set(DECLARATIONS)}
    for name, raw in originals.items():
        if (root / name).read_bytes() != raw:
            raise ValueError("original compatibility input changed")
    for name, expected in LOCKS.items():
        raw = (root / name).read_bytes()
        if digest(raw) != expected:
            raise ValueError("original lock identity changed")
        (evidence / name.replace("/", "-")).write_bytes(raw)
    changed = compatibility_changes(originals)
    for name, raw in changed.items():
        (root / name).write_bytes(raw)
    patch = git(root, "diff", "--binary", "--no-ext-diff")
    (evidence / "compatibility.patch").write_bytes(patch)
    record = dict(source=SOURCE, original_tree=TREE,
        proof_workflow_commit=os.environ["GITHUB_WORKFLOW_SHA"],
        run_id=os.environ["GITHUB_RUN_ID"], run_attempt=os.environ["GITHUB_RUN_ATTEMPT"],
        original_index_sha256=digest(index), compatibility_patch_sha256=digest(patch),
        compatible_file_sha256={name: digest(raw) for name, raw in changed.items()},
        original_file_sha256={name: digest(raw) for name, raw in originals.items()},
        compatible_source_id=digest(index + b"\0" + patch), lock_sha256=LOCKS,
        atomic_alias_sites=[dict(path=name, line=number) for name in ATOMIC
            for number, line in enumerate(changed[name].decode().splitlines(), 1) if ".fetch_update(" in line],
        profiles=PROFILES, variants=VARIANTS, build_jobs=2, quality_acceptance=False,
        runtime_acceptance=False, security_acceptance=False, rust185_comparison=False,
        scope="paired minimum-compiler probe on one exact C11 compatibility source; no lint cleanup")
    write_json(evidence / "source.json", record)
    check_source(root, record)


def compiler(profile):
    if profile not in PROFILES:
        raise ValueError("unreviewed compiler profile")
    number = "189" if profile == "1.89.0" else "199"
    path = Path(__file__).with_name("provision-rust" + number + ".py")
    spec = importlib.util.spec_from_file_location("compiler_" + number, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(profile):
    root, evidence = location()
    record = json.loads((evidence / "source.json").read_text())
    module = compiler(profile)
    prefix = module.location("runner", os.environ)
    receipt = json.loads((prefix / "receipt.json").read_text())
    module.validate_receipt(receipt)
    module.verify_payload(prefix, module.pins())
    observed = module.observe(prefix)
    if observed != receipt["observed_versions"]:
        raise ValueError("compiler observations differ from authenticated provisioning receipt")
    destination = evidence / profile
    destination.mkdir()
    write_json(destination / "observed-compiler.json", observed)
    (destination / "compiler-receipt.json").write_bytes((prefix / "receipt.json").read_bytes())
    target = Path(os.environ["RUNNER_TEMP"]) / ("f04-census-target-" + profile)
    if target.exists() or target.is_symlink():
        raise ValueError("fresh compiler-specific target already exists")
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2",
               RUSTC=str(prefix / "bin/rustc"), RUSTDOC=str(prefix / "bin/rustdoc"),
               PATH=str(prefix / "bin") + os.pathsep + os.environ["PATH"])
    results = {}
    for variant in VARIANTS:
        check_source(root, record)
        command = [str(prefix / "bin/cargo"), "clippy", "--keep-going", "--locked", "--offline",
                   "--workspace", "--all-targets", "--all-features", "--message-format=json", "--", "-D", "warnings"]
        if variant != "strict":
            command += ["--cap-lints=warn"]
        item = dict(command=command, compiler_profile=profile, target=str(target),
            compatible_source_id=record["compatible_source_id"], lock_sha256=LOCKS,
            timeout_seconds=720, kill_after_seconds=30,
            started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            classification="STRICT COMMAND" if variant == "strict" else "NON-ACCEPTANCE: capped enumeration only")
        write_json(destination / (variant + "-command.json"), item)
        with (destination / (variant + ".jsonl")).open("w") as stdout, (destination / (variant + "-stderr.log")).open("w") as stderr:
            status = subprocess.run(["timeout", "--signal=TERM", "--kill-after=30s", "12m", *command],
                cwd=root, env=env, stdout=stdout, stderr=stderr, check=False).returncode
        (destination / (variant + "-exit.txt")).write_text(str(status) + "\n")
        check_source(root, record)
        item.update(exit_status=status, source_unchanged=True,
                    finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        results[variant] = item
        write_json(destination / "execution-status.json", results)
    module.verify_payload(prefix, module.pins())
    if module.observe(prefix) != observed:
        raise ValueError("compiler observations changed during census")
    write_json(destination / "profile-integrity.json", dict(profile=profile,
        compatible_source_id=record["compatible_source_id"], lock_sha256=LOCKS,
        payload_verified_before_after=True, observations_identical_before_after=True,
        source_verified_before_after_each_variant=True))


def parse(log, status):
    diagnostics, errors, finished, malformed = set(), [], [], []
    for number, line in enumerate(log.splitlines(), 1):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            malformed.append(number)
            continue
        if item.get("reason") == "build-finished":
            finished.append(item.get("success"))
        if item.get("reason") != "compiler-message":
            continue
        message = item["message"]
        code = (message.get("code") or {}).get("code")
        if message["level"] == "error":
            errors.append(dict(code=code, message=message["message"], spans=message["spans"]))
        if code and message["level"] in ("warning", "error"):
            for span in message["spans"]:
                if span["is_primary"]:
                    diagnostics.add((code, span["file_name"], span["line_start"]))
    compiler_errors = [error for error in errors if error["code"] is None or re.fullmatch(r"E[0-9]{4}", error["code"])]
    complete = status == 0 and finished == [True] and not malformed and not errors
    strict_valid = complete or (status == 101 and finished == [False] and not malformed
                               and not compiler_errors and bool(diagnostics))
    return dict(exit_status=status, build_finished=finished, complete=complete,
        strict_valid=strict_valid, strict_green_observed=complete,
        unique_primary_diagnostics=[dict(code=c, path=p, line=n) for c, p, n in sorted(diagnostics)],
        unique_primary_count=len(diagnostics), errors=errors, compiler_errors=compiler_errors,
        first_compiler_error=compiler_errors[0] if compiler_errors else None,
        malformed_json_lines=malformed)


def summarize():
    root, evidence = location()
    evidence.mkdir(exist_ok=True)
    source_path = evidence / "source.json"
    record = json.loads(source_path.read_text()) if source_path.exists() else None
    source_unchanged = False
    try:
        if record:
            check_source(root, record)
            source_unchanged = True
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        (evidence / "source-validation-error.txt").write_text(str(error) + "\n")
    profiles = {}
    integrity = {}
    for profile in PROFILES:
        marker = evidence / profile / "profile-integrity.json"
        identity = json.loads(marker.read_text()) if marker.exists() else {}
        integrity[profile] = (record is not None and identity == dict(profile=profile,
            compatible_source_id=record["compatible_source_id"], lock_sha256=LOCKS,
            payload_verified_before_after=True, observations_identical_before_after=True,
            source_verified_before_after_each_variant=True))
        variants = {}
        for variant in VARIANTS:
            folder = evidence / profile
            log = folder / (variant + ".jsonl")
            status = folder / (variant + "-exit.txt")
            if not log.exists() or not status.exists():
                variants[variant] = dict(complete=False, strict_valid=False, reason="command not completed")
                continue
            result = parse(log.read_text(), int(status.read_text()))
            result["classification"] = "STRICT COMMAND" if variant == "strict" else "NON-ACCEPTANCE: capped warnings cannot establish Quality success"
            if variant != "strict":
                result["strict_green_observed"] = False
            sites = {(s["path"], s["line"]) for s in record["atomic_alias_sites"]} if record else set()
            result["compatibility_alias_deprecations"] = [d for d in result["unique_primary_diagnostics"]
                if d["code"] == "deprecated" and any(d["path"].endswith(path) and d["line"] == line for path, line in sites)]
            result["expected_compatibility_alias_deprecations"] = 8 if profile == "1.99.1" else 0
            result["compatibility_aliases_accounted_for"] = (len(result["compatibility_alias_deprecations"]) ==
                result["expected_compatibility_alias_deprecations"])
            variants[variant] = result
        profiles[profile] = variants
    complete = source_unchanged and all(integrity.values()) and all(v["strict"].get("strict_valid") and
        v["diagnostic-NON-ACCEPTANCE"].get("complete") and
        v["diagnostic-NON-ACCEPTANCE"].get("compatibility_aliases_accounted_for") for v in profiles.values())
    summary = dict(scope="paired exact-source full root workspace compiler census", profiles=profiles,
        compatible_source_unchanged=source_unchanged, comparison_complete=complete,
        compiler_integrity_before_after=integrity,
        quality_acceptance=False, runtime_acceptance=False, security_acceptance=False,
        rust185_comparison=False, original_source=SOURCE,
        compatible_source_id=record["compatible_source_id"] if record else None)
    write_json(evidence / "census-summary.json", summary)
    write_json(evidence / "artifact-sha256.json", {str(p.relative_to(evidence)): digest(p.read_bytes())
        for p in sorted(evidence.rglob("*")) if p.is_file() and p.name != "artifact-sha256.json"})
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as output:
        output.write("## NON-ACCEPTANCE: paired compiler census\n\nNo Quality, security, Rust 1.85 or runtime acceptance.\n\n")
        for profile, variants in profiles.items():
            for variant, result in variants.items():
                output.write(f"- {profile} {variant}: exit {result.get('exit_status')}, primary diagnostics {result.get('unique_primary_count', 0)}, complete {result.get('complete', False)}\n")
    if not complete:
        raise SystemExit("comparison incomplete: preserve first compiler errors and all failure evidence")


if __name__ == "__main__":
    if sys.argv[1:] == ["prepare"]:
        prepare()
    elif len(sys.argv) == 3 and sys.argv[1] == "run":
        run(sys.argv[2])
    elif sys.argv[1:] == ["summarize"]:
        summarize()
    else:
        raise SystemExit("usage: run-f04-compiler-comparison.py prepare|run <1.89.0|1.99.1>|summarize")
