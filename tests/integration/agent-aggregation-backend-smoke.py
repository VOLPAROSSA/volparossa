#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Guest-only real CPU algebra oracle; NOT three trained peers or B05 acceptance.

Use the already provisioned 135M JOBS runtime, as its unprivileged owner, in an
existing private network namespace containing only lo. This script installs or
downloads nothing and changes no network/mount configuration. The outer runner
owns the disposable /opt/va.* tree and its cleanup. No base model is instantiated.
"""

import argparse
import hashlib
import importlib.metadata
import io
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace


SCRIPT = "tests/integration/agent-aggregation-backend-smoke.py"
TRAIN = "tests/integration/agent-training-smoke.py"
WORKER = "workers/volparossa-ml/worker.py"
KERNEL = "workers/volparossa-ml/adapter_aggregation.py"
PINS = "workers/volparossa-ml/model-pins.json"
LOCK = "workers/volparossa-ml/requirements.lock"
SOURCES = (SCRIPT, TRAIN, WORKER, KERNEL, PINS, LOCK)
SOURCE_RECEIPT = "aggregation-source-receipt.json"
GUEST_SOURCE = Path("/home/vpci/source")
SCOPE = "real pinned CPU tensor algebra and adapter serialization on synthetic public inputs; not trained-peer integration or B05 acceptance"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def bounded(path, maximum=2 * 1024 * 1024):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum,
            "INVALID_REGULAR_FILE")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "FILE_CHANGED")
    return raw


def plain(path):
    require(path.is_absolute() and path.resolve(strict=True) == path,
            "NONCANONICAL_PATH")
    require(not any(part.is_symlink() for part in (path, *path.parents)), "SYMLINK_PATH")
    return path


def source_request(source, commit):
    require(source == GUEST_SOURCE and re.fullmatch(r"[0-9a-f]{40}", commit),
            "UNEXPECTED_GUEST_SOURCE_OR_COMMIT")


def source_provenance(source, commit):
    source_request(source, commit)
    plain(source)
    receipt_path = plain(source / SOURCE_RECEIPT)
    info = receipt_path.lstat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o444,
            "ROOT_OWNED_SOURCE_RECEIPT_REQUIRED")
    receipt = json.loads(bounded(receipt_path))
    require(receipt["version"] == 1 and receipt["source_commit"] == commit
            and receipt["archive_commit"] == commit and receipt["source_files"].keys() == set(SOURCES)
            and re.fullmatch(r"[0-9a-f]{64}", receipt["archive"]["sha256"]),
            "SOURCE_ARCHIVE_RECEIPT_MISMATCH")
    return receipt


def verified_sources(source, commit):
    receipt = source_provenance(source, commit)
    result = {}
    for name in SOURCES:
        path = plain(source / name)
        require(path.lstat().st_uid == 0 and stat.S_IMODE(path.lstat().st_mode) == 0o444,
                "ROOT_OWNED_STAGED_SOURCE_REQUIRED")
        actual = bounded(path)
        require(identity(actual) == receipt["source_files"][name], "SOURCE_BYTES_DIFFER_FROM_ARCHIVE")
        result[name] = actual
    require(bounded(Path(__file__).resolve()) == result[SCRIPT], "EXECUTING_SCRIPT_DIFFERS")
    return result


def archive_sources(raw, commit):
    # git archive stores the exact archived commit in the global pax header.
    # The existing VM driver independently SHA256-verifies this same archive.
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        require(archive.pax_headers.get("comment") == commit, "ARCHIVE_COMMIT_MISMATCH")
        result = {}
        for name in SOURCES:
            member = archive.getmember("source/" + name)
            require(member.isfile() and 0 < member.size <= 2 * 1024 * 1024, "INVALID_ARCHIVED_SOURCE")
            with archive.extractfile(member) as stream:
                result[name] = stream.read(2 * 1024 * 1024 + 1)
            require(len(result[name]) == member.size, "ARCHIVED_SOURCE_CHANGED")
        return result


def stage(args):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha", "ROOT_GUEST_STAGING_REQUIRED")
    source_request(args.source_root, args.source_commit)
    source = plain(args.source_root)
    module(bounded(source / TRAIN), source / TRAIN).guest_guard(root=True)
    require(args.work.parent == Path("/opt") and args.work.name.startswith("va."), "WRONG_TOPOLOGY_ROOT")
    plain(args.work)
    require(args.work.lstat().st_uid == 0 and (args.work / "bin").lstat().st_uid == 0,
            "ROOT_OWNED_TOPOLOGY_REQUIRED")
    raw_archive = bounded(plain(source.parent / "source.tar.gz"), maximum=512 * 1024 * 1024)
    originals = archive_sources(raw_archive, args.source_commit)
    require(all(bounded(plain(source / name)) == raw for name, raw in originals.items()),
            "SOURCE_BYTES_DIFFER_FROM_ARCHIVE")
    receipt = {"version": 1, "source_commit": args.source_commit, "archive_commit": args.source_commit,
               "archive": identity(raw_archive), "source_files": {name: identity(raw) for name, raw in originals.items()},
               "scope": "root caller checked original git-archive members; VM driver binds archive SHA256"}
    target = args.work / "bin" / "aggregation-source"
    require(not os.path.lexists(target), "SOURCE_STAGE_ALREADY_EXISTS")
    target.mkdir(mode=0o755)
    for name, raw in originals.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o444)
        for directory in (path.parent, *path.parent.parents):
            if not directory.is_relative_to(target):
                break
            directory.chmod(0o555)
    write(target / SOURCE_RECEIPT, receipt)
    (target / SOURCE_RECEIPT).chmod(0o444)
    print(json.dumps(receipt))


def module(raw, path):
    # Only fixed same-commit source bytes, never a peer-selected module/path.
    namespace = {"__name__": "aggregation_smoke_source", "__file__": str(path)}
    exec(compile(raw, str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)


def guest_admission(work, source, commit, guest_host_netns):
    # Cheap host rejection precedes even source-module loading and any writes.
    require(os.geteuid() != 0 and socket.gethostname() == "volparossa-alpha",
            "DEDICATED_UNPRIVILEGED_GUEST_REQUIRED")
    sources = verified_sources(source, commit)
    module(sources[TRAIN], source / TRAIN).guest_guard(root=False)
    require(work.parent == Path("/opt") and work.name.startswith("va."), "WRONG_TOPOLOGY_ROOT")
    plain(work)
    require(stat.S_ISDIR(work.lstat().st_mode), "WRONG_TOPOLOGY_ROOT")
    # The caller creates isolation, not this script. Offline env alone is not proof.
    # Unprivileged processes cannot generally read root PID1's namespace link.
    # The already authorized root runner supplies that exact original identity.
    require(type(guest_host_netns) is str and re.fullmatch(r"net:\[[0-9]+\]", guest_host_netns)
            and os.readlink("/proc/self/ns/net") != guest_host_netns
            and {name for _, name in socket.if_nameindex()} == {"lo"},
            "EXISTING_NETWORK_ISOLATION_REQUIRED")
    return sources


def private(path):
    plain(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_OWNED_DIRECTORY_REQUIRED")
    return path


def provision(work, sources):
    root = private(work / "agent-jobs-user" / "provision")
    runtime = private(root / "venv")
    pins = json.loads(sources[PINS])
    report = json.loads(bounded(root / "provision-report.json"))
    require(report.get("success") is True and report.get("model_id") == pins["model_id"]
            and report.get("revision") == pins["revision"]
            and report.get("model_profile", "smollm2-135m-v1") == "smollm2-135m-v1"
            and report.get("runtime_root") == str(runtime)
            and report.get("model_root") == str(root / "model")
            and report.get("runtime_autofetch_enabled") is False,
            "EXISTING_PINNED_135M_PROVISION_REQUIRED")
    for name, original, report_key in (("model-pins.json", sources[PINS], "model_pins_sha256"),
                                       ("requirements.lock", sources[LOCK], "requirements_sha256")):
        require(bounded(root / name) == original
                and report[report_key] == identity(original)["sha256"], "PROVISION_PINS_MISMATCH")
    return runtime, pins, identity(bounded(root / "provision-report.json"))


def write(path, value):
    raw = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(0o600)


def fixed_config(worker):
    return {"base_model_name_or_path": worker.MODEL_ID, "revision": worker.MODEL_REVISION,
            "peft_type": "LORA", "task_type": "CAUSAL_LM", "r": 4, "lora_alpha": 8,
            "lora_dropout": 0.0, "bias": "none", "inference_mode": True,
            "target_modules": ["q_proj", "v_proj"]}


def cohort(torch, save_file, worker, root, case, check):
    root.mkdir(mode=0o700)
    inputs = []
    for index in range(3):
        check()
        directory = root / str(index)
        directory.mkdir(mode=0o700)
        weights = {}
        for layer in range(30):
            for name, width in (("q_proj", 576), ("v_proj", 192)):
                a = torch.zeros((4, 576), dtype=torch.float32)
                b = torch.zeros((width, 4), dtype=torch.float32)
                support = ((0, 1, 2, 3), (0, 1, 4, 5), (2, 3, 4, 5))[index] if case == "rank6" else range(4)
                for row, diagonal in enumerate(support):
                    a[row, diagonal] = 1.0
                    b[diagonal, row] = (6.0 - diagonal) / 2.0
                if case == "gauge" and index == 1:
                    a *= 2.0
                    b /= 2.0
                elif case == "gauge" and index == 2:
                    b *= 1048576.0  # Finite outlier; not an adversarial-resilience claim.
                prefix = f"base_model.model.model.layers.{layer}.self_attn.{name}.lora_"
                weights[prefix + "A.weight"], weights[prefix + "B.weight"] = a, b
        write(directory / "adapter_config.json", fixed_config(worker))
        (directory / "README.md").write_text(
            f"# Synthetic public numeric fixture {case}/{index}\n\n"
            "GPL-3.0-only. Fixed arithmetic, not trained weights or user data.\n")
        save_file(weights, str(directory / "adapter_model.safetensors"), metadata={"format": "pt"})
        for path in directory.iterdir():
            path.chmod(0o600)
        inputs.append(directory)
    return inputs


def hashes(inputs, worker, job):
    return [worker.prepare_adapter(str(path), job)[1] for path in inputs]


def near(actual, expected, code, absolute=1e-5):
    require(type(actual) is float and math.isfinite(actual)
            and math.isclose(actual, expected, rel_tol=2e-6, abs_tol=absolute), code)


def exercise(torch, load_file, save_file, worker, kernel, root, case, check):
    inputs = cohort(torch, save_file, worker, root / (case + "-inputs"), case, check)
    job = root / (case + "-job")
    job.mkdir(mode=0o700)
    before = hashes(inputs, worker, job)
    if case == "gauge":
        first = load_file(str(inputs[0] / "adapter_model.safetensors"), device="cpu")
        second = load_file(str(inputs[1] / "adapter_model.safetensors"), device="cpu")
        for name in first:
            require(not torch.equal(first[name], second[name]), "GAUGE_FACTORS_NOT_DISTINCT")
        for name in (name for name in first if name.endswith("A.weight")):
            b = name.removesuffix("A.weight") + "B.weight"
            require(torch.equal(2 * first[b] @ first[name], 2 * second[b] @ second[name]),
                    "GAUGE_EFFECTIVE_DELTAS_DIFFER")
        del first, second
    steps = []
    def progress(phase, step):
        require(phase == "checkpoint", "UNEXPECTED_KERNEL_PHASE")
        steps.append(step)
        check()
    result = kernel.aggregate(torch, load_file, save_file, inputs, job / "adapter", check, progress)
    require(steps == list(range(61)) and result["combined_modules"] == 60
            and result["updates_completed"] == 0 and result["rank"] == 4,
            "INCOMPLETE_REAL_AGGREGATION")
    output_hashes = worker.prepare_adapter(str(job / "adapter"), job, owned_checkpoint=True)[1]
    require(result["input_files"] == before == hashes(inputs, worker, job), "ORIGINAL_INPUTS_CHANGED")
    require(result["artifacts"] == [{"relative_path": "adapter/" + name, **output_hashes[name]}
                                    for name in sorted(output_hashes)], "OUTPUT_HASHES_DIFFER")
    output = load_file(str(job / "adapter" / "adapter_model.safetensors"), device="cpu")
    require(output.keys() == worker.adapter_shapes().keys() and len(output) == 120, "INCOMPLETE_SAVED_TENSORS")
    maximum_error, residual = 0.0, 0.0
    for layer in range(30):
        for name, width in (("q_proj", 576), ("v_proj", 192)):
            check()
            prefix = f"base_model.model.model.layers.{layer}.self_attn.{name}.lora_"
            actual = 2 * output[prefix + "B.weight"].double() @ output[prefix + "A.weight"].double()
            expected = torch.zeros((width, 576), dtype=torch.float64)
            target = torch.zeros_like(expected)
            for diagonal in range(4):
                expected[diagonal, diagonal] = 6.0 - diagonal
            for diagonal in range(6 if case == "rank6" else 4):
                target[diagonal, diagonal] = 6.0 - diagonal
            require(torch.allclose(actual, expected, rtol=2e-6, atol=1e-5), "INCORRECT_EFFECTIVE_OUTPUT_DELTA")
            maximum_error = max(maximum_error, (actual - expected).abs().max().item())
            residual = math.hypot(residual, torch.linalg.vector_norm(actual - target).item())
    expected_target = math.sqrt(60 * (91 if case == "rank6" else 86))
    expected_residual = math.sqrt(300) if case == "rank6" else 0.0
    metrics = result["metrics"]
    near(metrics["target_frobenius_norm"], expected_target, "INCORRECT_TARGET_NORM")
    near(metrics["rank4_residual_frobenius_norm"], expected_residual, "INCORRECT_RANK4_RESIDUAL")
    near(metrics["stored_fp32_residual_frobenius_norm"], residual, "INCORRECT_STORED_RESIDUAL")
    near(residual, expected_residual, "INCORRECT_SAVED_PROJECTION", absolute=1e-4)
    return inputs, {"case": case, "synthetic_public_inputs": True, "trained_inputs": False,
                    "input_files": before, "output_files": output_hashes, "kernel": result,
                    "independent_oracle": {"modules": 60, "saved_tensors": len(output),
                        "median_rank": 6 if case == "rank6" else 4,
                        "expected_target_norm": expected_target, "expected_rank4_residual": expected_residual,
                        "measured_saved_residual": residual, "maximum_effective_delta_error": maximum_error}}


def cancellation(torch, load_file, save_file, worker, kernel, root, inputs, check):
    class Cancelled(Exception):
        pass
    job = root / "cancel-job"
    job.mkdir(mode=0o700)
    before = hashes(inputs, worker, job)
    steps = []
    def cancel_check():
        check()
        if steps and steps[-1] == 1:
            raise Cancelled()
    def progress(phase, step):
        require(phase == "checkpoint", "UNEXPECTED_KERNEL_PHASE")
        steps.append(step)
    try:
        kernel.aggregate(torch, load_file, save_file, inputs, job / "adapter", cancel_check, progress)
    except Cancelled:
        pass
    else:
        raise ValueError("CANCELLATION_NOT_OBSERVED")
    require(steps == [0, 1] and not os.path.lexists(job / "adapter")
            and hashes(inputs, worker, job) == before, "CANCELLED_CANDIDATE_OR_INPUT_CHANGED")
    return {"after_real_modules": 1, "input_files": before, "candidate_exists": False,
            "original_inputs_unchanged": True, "scope": "kernel callback cancellation, not supervisor kill/reap proof"}


def backend(args, sources, runtime, pins, provision_hash):
    require(Path(sys.prefix) == runtime and sys.flags.isolated and sys.flags.dont_write_bytecode,
            "EXPLICIT_ISOLATED_PINNED_RUNTIME_REQUIRED")
    root = private(args.work / "agent-jobs-user" / "aggregation-backend")
    require({p.name for p in root.iterdir()} == {"tmp", "cache"}, "BACKEND_DIRECTORY_NOT_FRESH")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CPU, (args.max_seconds, args.max_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (6 * 1024**3, 6 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    deadline = time.monotonic() + args.max_seconds
    def check():
        require(time.monotonic() < deadline, "BACKEND_DEADLINE")
    for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
        require(os.environ.get(key) == str(args.threads), "PREIMPORT_THREAD_GUARD_MISSING")
    worker = module(sources[WORKER], args.source_root / WORKER)
    kernel = module(sources[KERNEL], args.source_root / KERNEL)
    worker.configure_offline()
    expected_versions = {item["name"]: item["version"] for item in pins["wheels"]
                         if item["name"] in ("torch", "transformers", "peft", "safetensors")}
    require(len(expected_versions) == 4, "BACKEND_PINS_MISSING")
    actual_versions = {name: importlib.metadata.version(name) for name in expected_versions}
    require(actual_versions == expected_versions, "BACKEND_VERSION_MISMATCH")
    # First native imports occur here, after every guest/isolation/limit guard.
    torch, _, _, _ = worker.load_backend(args.threads, SimpleNamespace(check=check))
    from safetensors.torch import load_file, save_file
    require(torch.get_num_threads() == args.threads and torch.get_num_interop_threads() == 1,
            "BACKEND_THREAD_LIMIT_MISMATCH")
    inputs, gauge = exercise(torch, load_file, save_file, worker, kernel, root, "gauge", check)
    _, rank6 = exercise(torch, load_file, save_file, worker, kernel, root, "rank6", check)
    cancelled = cancellation(torch, load_file, save_file, worker, kernel, root, inputs, check)
    report = {"version": 1, "status": "pass", "scope": SCOPE, "source_commit": args.source_commit,
              "source_files": {name: identity(raw) for name, raw in sources.items()},
              "archive_provenance": source_provenance(args.source_root, args.source_commit),
              "provision_report": provision_hash, "backend_versions": actual_versions,
              "model_id": pins["model_id"], "model_revision": pins["revision"],
              "threads": args.threads, "max_seconds": args.max_seconds,
              "caller_guest_host_netns": args.guest_host_netns,
              "execution_netns": os.readlink("/proc/self/ns/net"),
              "elapsed_seconds": args.max_seconds - (deadline - time.monotonic()),
              "gauge_and_outlier": gauge, "rank_truncation": rank6, "cancellation": cancelled,
              "model_weights_loaded": False, "optimizer_updates": 0, "trained_peer_exchange_proven": False,
              "model_quality_proven": False, "b05_complete": False,
              "production_worker_sandbox_proven": False, "network_isolation": "inherited private namespace; lo only"}
    check()
    write(root / "report.json", report)


def execute(args):
    require(1 <= args.threads <= 2 and 1 <= args.max_seconds <= 600, "INVALID_RESOURCE_BUDGET")
    sources = guest_admission(args.work, args.source_root, args.source_commit, args.guest_host_netns)
    runtime, pins, provision_hash = provision(args.work, sources)
    if args.backend_child:
        backend(args, sources, runtime, pins, provision_hash)
        return
    # The stdlib-only parent imposes a real wall-clock deadline even in a native call.
    # WORK itself is root-owned 0755; only the existing JOBS owner tree is writable.
    root = private(args.work / "agent-jobs-user") / "aggregation-backend"
    require(not os.path.lexists(root), "OUTPUT_ALREADY_EXISTS")
    root.mkdir(mode=0o700)
    for name in ("tmp", "cache"):
        (root / name).mkdir(mode=0o700)
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                   "TMPDIR": str(root / "tmp"), "HF_HOME": str(root / "cache"),
                   "XDG_CACHE_HOME": str(root / "cache"), "HF_HUB_OFFLINE": "1",
                   "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1",
                   "OMP_NUM_THREADS": str(args.threads), "MKL_NUM_THREADS": str(args.threads),
                   "OPENBLAS_NUM_THREADS": str(args.threads)}
    command = [str(runtime / "bin/python3"), "-I", "-B", str(args.source_root / SCRIPT),
               "--execute", "--backend-child", "--work", str(args.work),
               "--source-root", str(args.source_root), "--source-commit", args.source_commit,
               "--guest-host-netns", args.guest_host_netns,
               "--threads", str(args.threads), "--max-seconds", str(args.max_seconds)]
    child = subprocess.Popen(command, env=environment, cwd=root, start_new_session=True)
    try:
        require(child.wait(timeout=args.max_seconds) == 0, "BACKEND_PROOF_FAILED")
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
    report = json.loads(bounded(root / "report.json"))
    require(report["status"] == "pass" and report["source_commit"] == args.source_commit,
            "MISSING_OR_WRONG_BACKEND_REPORT")
    print(json.dumps({"status": "pass", "scope": SCOPE, "report": str(root / "report.json"),
                      "report_file": identity(bounded(root / "report.json"))}))


def self_test():
    # No temp files, subprocesses, source imports or numerical backend on the host.
    from unittest import mock
    for source, commit in ((Path("/tmp/source"), "a" * 40), (GUEST_SOURCE, "bad"),
                            (GUEST_SOURCE / "..", "a" * 40)):
        try:
            source_request(source, commit)
        except ValueError:
            pass
        else:
            raise ValueError("SOURCE_GUARD_SELF_TEST_FAILED")
    source_request(GUEST_SOURCE, "a" * 40)
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz", format=tarfile.PAX_FORMAT,
                      pax_headers={"comment": "a" * 40}) as archive:
        for name in SOURCES:
            item = tarfile.TarInfo("source/" + name)
            item.size = 5
            archive.addfile(item, io.BytesIO(b"inert"))
    require(archive_sources(archive_bytes.getvalue(), "a" * 40) == {name: b"inert" for name in SOURCES},
            "ARCHIVE_SOURCE_SELF_TEST_FAILED")
    try:
        archive_sources(archive_bytes.getvalue(), "b" * 40)
    except ValueError as error:
        require(str(error) == "ARCHIVE_COMMIT_MISMATCH", "WRONG_ARCHIVE_REJECTION")
    else:
        raise ValueError("WRONG_ARCHIVE_COMMIT_ACCEPTED")
    for uid, host in ((0, "volparossa-alpha"), (1000, "developer-host")):
        with mock.patch("os.geteuid", return_value=uid), mock.patch("socket.gethostname", return_value=host), \
                mock.patch(__name__ + ".verified_sources", side_effect=AssertionError("source loaded on host")):
            try:
                guest_admission(Path("/opt/va.inert"), GUEST_SOURCE, "a" * 40, "net:[123]")
            except ValueError as error:
                require(str(error) == "DEDICATED_UNPRIVILEGED_GUEST_REQUIRED", "WRONG_GUARD_REJECTION")
            else:
                raise ValueError("HOST_GUARD_SELF_TEST_FAILED")
    require(not any(name in sys.modules for name in ("torch", "safetensors", "peft", "transformers")),
            "BACKEND_IMPORTED_BY_SELF_TEST")
    print(json.dumps({"status": "pass", "scope": "inert admission checks only; no numeric evidence",
                      "source_rejections": 3, "guest_rejections_before_source_load": 2,
                      "archive_source_members": 6, "wrong_archive_commit_rejected": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--stage", action="store_true", help="root guest: verify archive and stage fixed read-only sources")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--backend-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--guest-host-netns", help="root runner's original readlink /proc/1/ns/net value")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--max-seconds", type=int, default=600)
    args = parser.parse_args()
    try:
        if args.self_test:
            require(not args.execute and not args.backend_child and not args.stage, "SELF_TEST_EXECUTION_CONFLICT")
            self_test()
        elif args.stage:
            require(not args.execute and not args.backend_child and args.work is not None
                    and args.source_root is not None and args.source_commit is not None,
                    "EXPLICIT_ROOT_STAGING_ARGUMENTS_REQUIRED")
            stage(args)
        elif args.execute:
            require(args.work is not None and args.source_root is not None
                    and args.source_commit is not None and args.guest_host_netns is not None,
                    "EXPLICIT_GUEST_PATHS_COMMIT_AND_HOST_NETNS_REQUIRED")
            execute(args)
        else:
            require(not args.backend_child, "BACKEND_CHILD_REQUIRES_EXECUTE")
            print(json.dumps({"mode": "preview", "scope": SCOPE, "changes": "new owned guest proof directory only",
                              "requires": "unprivileged dedicated KVM, pinned 135M JOBS provision, existing isolated lo-only netns",
                              "max_seconds": 600, "max_threads": 2, "backend_loaded": False}))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "fail", "scope": SCOPE, "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
