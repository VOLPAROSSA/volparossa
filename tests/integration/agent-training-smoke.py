#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One real CPU LoRA job and read-only kernel observations, not distributed AI."""

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ML = REPO / "workers/volparossa-ml"
WEIGHT_HASH = "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c"
MODEL_REVISION = "83212e1e2b3cfd6958f3707877bb878945dea8ee"
HASH = re.compile(r"[0-9a-f]{64}")
SCOPE = "one isolated CPU LoRA worker on explicit public project data; not distributed training or improved answer quality"
ARTIFACTS = {"adapter/adapter_config.json", "adapter/adapter_model.safetensors", "adapter/README.md"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
    path.chmod(0o600)


def read(path, maximum=262144):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum, "invalid bounded report file")
    return json.loads(path.read_bytes())


def file_hash(path, maximum):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "invalid artifact file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"bytes": info.st_size, "sha256": digest.hexdigest()}


def public_dataset(revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "invalid source revision")
    context = "Every parallel path uses exactly one distinct relay between the same client and exit."
    context2 = "The normal client dataplane never connects directly to an exit."
    # Contexts are literal, revision-bound public README statements, not private user data.
    text = (REPO / "README.md").read_text().replace("\n", " ")
    require(context in text and context2.lower() in text.lower(), "public fixture source text changed")
    return {
        "version": 1, "visibility": "public", "license": "GPL-3.0-only", "source_revision": revision,
        "train": [
            {"question": "How many relays does one parallel path use?", "answer": "Exactly one distinct relay.", "context": context},
            {"question": "May the normal client dataplane connect directly to an exit?", "answer": "No.", "context": context2},
        ],
        "heldout": [{"question": "Is a direct client-to-exit dataplane connection normal?", "answer": "No.", "context": context2}],
        "inference": [{"question": "How many relays are in each parallel path?", "context": context}],
    }


def guest_guard(root=False):
    require(socket.gethostname() == "volparossa-alpha", "not the dedicated VM")
    require(subprocess.check_output(["systemd-detect-virt"], text=True).strip() == "kvm", "not KVM")
    require((os.geteuid() == 0) == root, "incorrect guest privilege for phase")
    require(REPO == Path("/home/vpci/source"), "unexpected guest source")


def snapshot():
    result = {}
    for family in ("-4", "-6"):
        for kind in ("route", "rule"):
            args = ["ip", "-j", family, kind, "show"]
            if kind == "route":
                args.extend(["table", "all"])
            values = json.loads(subprocess.check_output(args, text=True))
            for item in values:
                item.pop("expires", None)
            result[family + kind] = sorted(values, key=lambda x: json.dumps(x, sort_keys=True))
    firewall = json.loads(subprocess.check_output(["sudo", "-n", "nft", "--stateless", "-j", "list", "ruleset"], text=True))
    result["firewall"] = [x for x in firewall["nftables"] if "metainfo" not in x]
    result["dns_sha256"] = hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest()
    result["dns_path"] = str(Path("/etc/resolv.conf").resolve())
    result["namespaces"] = subprocess.check_output(["ip", "netns", "list"], text=True).splitlines()
    result["ip_forward"] = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    return result


def process_record(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw.rsplit(")", 1)[1].split()
    return {"pid": pid, "start_ticks": int(fields[19])}, int(fields[1])


def identity(pid):
    return process_record(pid)[0]


def descendants(pid):
    # Linux assigns children to the spawning thread, not necessarily the thread-group
    # leader. Tokio therefore requires all-task traversal, still only below this owner.
    maximum_processes, maximum_threads, maximum_children_bytes = 32, 128, 4096
    try:
        owner = identity(pid)
    except FileNotFoundError:
        return []
    pending, seen, result = [owner], {(pid, owner["start_ticks"])}, []
    while pending:
        expected = pending.pop()
        current = expected["pid"]
        try:
            if identity(current) != expected:
                continue
            children = set()
            for count, task in enumerate(Path(f"/proc/{current}/task").iterdir(), 1):
                require(count <= maximum_threads, "owned process thread observation limit")
                try:
                    with (task / "children").open("rb") as stream:
                        raw = stream.read(maximum_children_bytes + 1)
                    require(len(raw) <= maximum_children_bytes, "owned process child-list limit")
                    children.update(int(value) for value in raw.split())
                    require(len(children) < maximum_processes, "owned descendant process limit")
                except FileNotFoundError:
                    continue  # A completed thread is not evidence for another process.
            if identity(current) != expected:
                continue
            result.append(expected)
            for child in sorted(children):
                try:
                    record, parent = process_record(child)
                except FileNotFoundError:
                    continue
                token = (child, record["start_ticks"])
                if parent != current or token in seen:
                    continue
                require(len(seen) < maximum_processes, "owned descendant process limit")
                seen.add(token)
                pending.append(record)
        except FileNotFoundError:
            continue
    return result


def observe(cli_pid, output, provision, dataset, canary):
    guest_guard(root=True)
    initial = identity(cli_pid)
    cli_owner = Path(f"/proc/{cli_pid}").stat()
    require(cli_owner.st_uid == output.parent.stat().st_uid != 0, "observer output/CLI owner mismatch")
    for _ in range(600):
        require(identity(cli_pid) == initial, "CLI disappeared before observing worker")
        family = descendants(cli_pid)
        for member in family:
            pid = member["pid"]
            proc = Path(f"/proc/{pid}")
            try:
                args = (proc / "cmdline").read_bytes().split(b"\0")
                if not args or args[0] != b"/runtime/bin/python3":
                    continue
                root = proc / "root"
                namespaces = {name: os.readlink(proc / "ns" / name) for name in ("net", "pid", "ipc", "mnt")}
                guest_namespaces = {name: os.readlink(Path("/proc/self/ns") / name) for name in namespaces}
                require(all(namespaces[k] != guest_namespaces[k] for k in namespaces), "worker namespace shared with guest")
                devices = [line.split(":", 1)[0].strip() for line in (proc / "net/dev").read_text().splitlines()[2:]]
                require(devices == ["lo"], "worker has an external network device")
                require(len((proc / "net/route").read_text().splitlines()) == 1, "worker has an IPv4 route")
                mounts = {}
                for line in (proc / "mountinfo").read_text().splitlines():
                    parts = line.split()
                    if parts[4] in ("/runtime", "/model", "/dataset.json", "/output"):
                        mounts[parts[4]] = parts[5].split(",")
                require(all("ro" in mounts.get(p, []) for p in ("/runtime", "/model", "/dataset.json")), "worker input mount writable")
                require("rw" in mounts.get("/output", []), "worker output mount missing")
                exact = {}
                for mounted, original in (("model/model.safetensors", provision / "model/model.safetensors"),
                                          ("runtime/pyvenv.cfg", provision / "venv/pyvenv.cfg"),
                                          ("dataset.json", dataset)):
                    a, b = (root / mounted).stat(), original.stat()
                    exact[mounted] = [a.st_dev, a.st_ino] == [b.st_dev, b.st_ino]
                require(all(exact.values()), "worker mounts do not reference the actual supplied files")
                require(not (root / "home").exists() and not (root / "root").exists()
                        and not (root / str(canary).lstrip("/")).exists(), "host-home/private canary visible")
                status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
                require(int(status["CapEff"].strip(), 16) == 0, "worker retained capabilities")
                result = {"observed": True, "cli": initial, "worker": member, "owned_processes": family,
                          "namespaces": namespaces, "guest_namespaces": guest_namespaces,
                          "network_devices": devices, "ipv4_routes": [], "mounts": mounts,
                          "exact_input_inodes": exact, "host_home_visible": False,
                          "outside_canary_visible": False, "effective_capabilities": 0}
                write(output, result)
                os.chown(output, cli_owner.st_uid, cli_owner.st_gid)
                return
            except FileNotFoundError:
                continue
        time.sleep(0.1)
    raise ValueError("actual isolated Python worker was not observed")


def check_generation(output, require_eos=False):
    """Current-source worker contract; an old report without metadata proves no EOS."""
    generation = output.get("generation")
    require(type(generation) is dict and set(generation) == {"version", "stop_reason", "max_new_tokens"}
            and type(generation["version"]) is int and generation["version"] == 1
            and type(generation["max_new_tokens"]) is int and generation["max_new_tokens"] == 64
            and generation["stop_reason"] in ("eos", "token_limit")
            and type(output["generated_tokens"]) is int and 1 <= output["generated_tokens"] <= 64
            and (generation["stop_reason"] != "token_limit" or output["generated_tokens"] == 64),
            "ordinary generation end metadata is missing or invalid")
    require(not require_eos or generation["stop_reason"] == "eos", "token-limited answer is not a complete parent")
    return generation


def check_worker(worker, revision):
    require(worker.get("status") == "ok" and worker.get("mode") == "train"
            and worker.get("device") == "cpu" and worker.get("threads") == 2, "real CPU training result missing")
    require(worker["backend_versions"]["torch"] == "2.14.0+cpu"
            and worker["backend_versions"]["transformers"] == "5.16.1"
            and worker["backend_versions"]["peft"] == "0.20.0", "wrong pinned backend")
    require(worker.get("updates_completed") == 8, "eight optimizer updates not completed")
    losses = worker["training_losses"]
    require(len(losses) == 8 and all(type(x) in (int, float) and math.isfinite(x) and x > 0 for x in losses), "actual finite training losses missing")
    require(worker["model"]["id"] == "HuggingFaceTB/SmolLM2-135M-Instruct"
            and worker["model"]["revision"] == MODEL_REVISION
            and worker["model"]["files"]["model.safetensors"] == {"bytes": 269060552, "sha256": WEIGHT_HASH}, "wrong original model")
    require(worker["dataset"]["source_revision"] == revision and worker["dataset"]["visibility"] == "public"
            and worker["dataset"]["license"] == "GPL-3.0-only"
            and worker["dataset"]["training_examples"] == 2
            and worker["dataset"]["heldout_examples"] == 1, "unbound or private dataset")
    for field in ("base_before", "base_after", "reloaded_base", "adapter_before", "adapter_after", "reloaded_adapter"):
        require(HASH.fullmatch(worker[field]["sha256"]) and worker[field]["parameters"] > 0, "invalid parameter evidence")
    require(worker["base_before"] == worker["base_after"] == worker["reloaded_base"], "base parameters changed")
    require(worker["adapter_after"] == worker["reloaded_adapter"]
            and worker["adapter_before"]["sha256"] != worker["adapter_after"]["sha256"]
            and worker["adapter_before"]["parameters"] == worker["adapter_after"]["parameters"] == 230400,
            "adapter was unchanged or not genuinely reloaded")
    require(all(worker.get(x) is True for x in ("base_weights_unchanged", "adapter_weights_changed", "checkpoint_reloaded")), "training/reload status incomplete")
    for field in ("baseline_evaluation", "adapted_evaluation", "reloaded_evaluation"):
        require(math.isfinite(worker[field]["loss"]) and worker[field]["loss"] > 0
                and worker[field]["target_tokens"] > 0, "heldout evaluation missing")
    require(math.isclose(worker["adapted_evaluation"]["loss"], worker["reloaded_evaluation"]["loss"], rel_tol=1e-5, abs_tol=1e-6), "reload evaluation mismatch")
    require(len(worker["artifacts"]) == 3 and {x["relative_path"] for x in worker["artifacts"]} == ARTIFACTS, "checkpoint artifacts missing")
    require(worker.get("better_answers_claimed") is False and worker.get("distributed_training_claimed") is False
            and worker.get("network_policy_changed") is False, "unsupported scope claim")
    supervisor = worker["supervisor"]
    require(supervisor["sandbox"] == "bubblewrap-private-user-net-pid-ipc-mount"
            and supervisor["network_access"] is False and supervisor["gpu_access"] is False
            and supervisor["child_reaped"] is True and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"],
            "supervisor isolation/accounting/cleanup incomplete")


def check_isolation(observation):
    require(observation["observed"] is True and observation["network_devices"] == ["lo"]
            and observation["ipv4_routes"] == [] and observation["effective_capabilities"] == 0,
            "actual network isolation not observed")
    require(all(observation["namespaces"][x] != observation["guest_namespaces"][x] for x in ("net", "pid", "ipc", "mnt")), "shared namespace")
    require(observation["host_home_visible"] is False and observation["outside_canary_visible"] is False,
            "host home exposed")
    require(all(observation["exact_input_inodes"].values()) and len(observation["exact_input_inodes"]) == 3,
            "wrong actual worker inputs")
    require(all("ro" in observation["mounts"][p] for p in ("/runtime", "/model", "/dataset.json")), "writable input")


def check_report(report, revision):
    require(report["report_kind"] == "volparossa-isolated-agent-training"
            and report["source_revision"] == revision and report["success"] is True, "incomplete source-bound training report")
    require(report["scope"] == SCOPE and report["full_alpha_claimed"] is False, "unsupported alpha claim")
    check_worker(report["worker"], revision)
    check_isolation(report["isolation"])
    require(report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
            and report["host_state"]["unchanged"] is True
            and report["host_state"]["before_sha256"] == report["host_state"]["after_sha256"], "cleanup or guest network baseline not restored")
    require(report["on_disk_model_before"] == report["on_disk_model_after"] == {"bytes": 269060552, "sha256": WEIGHT_HASH}, "on-disk base changed")
    require(report["actual_artifacts"] == report["worker"]["artifacts"], "actual saved adapter hashes differ")
    require(report["provision"]["success"] is True and report["provision"]["installed_wheels"] == 38
            and report["provision"]["download_bytes"] == 523040250
            and report["provision"]["training_performed"] is False, "unverified provisioning")


def check_bundle(path, revision):
    report = read(path)
    check_report(report, revision)
    output = path.parent
    require(read(output / "agent-training-worker.json") == report["worker"]
            and read(output / "agent-training-isolation.json") == report["isolation"]
            and read(output / "agent-training-provision.json") == report["provision"], "raw evidence differs from report")
    dataset = output / "agent-training-public-dataset.json"
    require(read(dataset) == public_dataset(revision)
            and file_hash(dataset, 1048576)["sha256"] == report["worker"]["dataset"]["sha256"],
            "original public dataset differs from training input")
    pins = read(ML / "model-pins.json")
    expected = {x["path"]: {"bytes": x["bytes"], "sha256": x["sha256"]} for x in pins["files"]}
    require(report["worker"]["model"]["files"] == expected, "model assets differ from trusted source pins")
    require(report["provision"]["model_pins_sha256"] == file_hash(ML / "model-pins.json", 262144)["sha256"],
            "provisioning used different trusted pins")
    for artifact in report["actual_artifacts"]:
        exported = output / ("agent-training-" + artifact["relative_path"].replace("/", "-"))
        require(file_hash(exported, 4 * 1024 ** 2) == {k: artifact[k] for k in ("bytes", "sha256")},
                "retained checkpoint artifact bytes differ")
    for when in ("before", "after"):
        require(file_hash(output / f"host-state-{when}.json", 1048576)["sha256"]
                == report["host_state"][f"{when}_sha256"], "raw guest state snapshot differs")


def alive(member):
    try:
        return identity(member["pid"]) == member
    except FileNotFoundError:
        return False


def execute(output, revision, owner_priority=False):
    guest_guard()
    provision, jobs = Path("/home/vpci/ml-provision"), Path("/home/vpci/ml-jobs")
    require(not provision.exists() and not jobs.exists(), "guest fixture root already exists")
    jobs.mkdir(mode=0o700)
    before = snapshot()
    write(output / "host-state-before.json", before)
    result = {"report_kind": "volparossa-isolated-agent-training", "source_revision": revision,
              "success": False, "scope": SCOPE, "full_alpha_claimed": False,
              "cleanup": {"complete": False, "remaining_owned_objects": 1}, "phase": "provision"}
    process, observer, pressure = None, None, None
    try:
        with (output / "agent-training-provision.log").open("w") as log:
            subprocess.run([sys.executable, "-B", str(ML / "provision.py"), "--execute", "--yes",
                            "--disposable-guest", "--root", str(provision), "--budget-bytes", str(3 * 1024 ** 3)],
                           stdout=log, stderr=subprocess.STDOUT, timeout=1850, check=True)
        result["provision"] = read(provision / "provision-report.json")
        write(output / "agent-training-provision.json", result["provision"])
        dataset = jobs / "public-dataset.json"
        write(dataset, public_dataset(revision))
        shutil.copyfile(dataset, output / "agent-training-public-dataset.json")
        canary = jobs / "outside-private-canary"
        canary.write_text("Public isolation fixture; not an actual private key.\n")
        canary.chmod(0o600)
        model_file = provision / "model/model.safetensors"
        result["on_disk_model_before"] = file_hash(model_file, 269060552)
        result["phase"] = "train-and-observe"
        job = jobs / "train"
        with (output / "agent-training-worker.json").open("w") as stdout, \
                (output / "agent-training-worker.stderr").open("w") as stderr:
            process = subprocess.Popen(["/home/vpci/target/debug/volparossa", "compute", "run", "--mode", "train",
                                        "--runtime-root", str(provision / "venv"), "--model-root", str(provision / "model"),
                                        "--dataset", str(dataset), "--output", str(job), "--steps", "8", "--threads", "2",
                                        "--max-seconds", "600", "--execute"]
                                       + (["--spare-capacity"] if owner_priority else []), stdout=stdout, stderr=stderr)
            with (output / "agent-training-observer.stderr").open("w") as diagnostics:
                observer = subprocess.Popen(["sudo", "-n", sys.executable, "-B", str(Path(__file__).resolve()), "observe",
                                             str(process.pid), str(output / "agent-training-isolation.json"),
                                             str(provision), str(dataset), str(canary)], stderr=diagnostics)
                require(observer.wait(timeout=70) == 0, "actual worker isolation observation failed")
            result["isolation"] = read(output / "agent-training-isolation.json")
            check_isolation(result["isolation"])
            if owner_priority:
                with (output / "agent-owner-priority-pressure.stderr").open("w") as diagnostics:
                    pressure = subprocess.Popen(["sudo", "-n", sys.executable, "-B",
                        str(Path(__file__).with_name("agent-owner-priority-smoke.py")), "pressure", str(output)],
                        stderr=diagnostics)
                    require(pressure.wait(timeout=120) == 0, "actual owner-pressure pause/resume observation failed")
            require(process.wait(timeout=610) == 0, "real training CLI failed")
        worker = read(output / "agent-training-worker.json")
        check_worker(worker, revision)
        require(worker["dataset"]["sha256"] == file_hash(dataset, 1048576)["sha256"], "dataset bytes not bound")
        result["worker"] = worker
        result["actual_artifacts"] = []
        for artifact in worker["artifacts"]:
            actual = {"relative_path": artifact["relative_path"], **file_hash(job / artifact["relative_path"], 4 * 1024 ** 2)}
            require(actual == artifact, "saved artifact hash mismatch")
            result["actual_artifacts"].append(actual)
            destination = output / ("agent-training-" + artifact["relative_path"].replace("/", "-"))
            shutil.copyfile(job / artifact["relative_path"], destination)
            destination.chmod(0o600)
        result["on_disk_model_after"] = file_hash(model_file, 269060552)
        result["phase"] = "cleanup"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result["observed_blocker"] = str(error)[:1024]
    finally:
        for child in (pressure, observer, process):
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        members = list(result.get("isolation", {}).get("owned_processes", []))
        pressure_path = output / "agent-owner-priority-pressure.json"
        if owner_priority and pressure_path.is_file():
            members += read(pressure_path).get("pressure_processes", [])
        remaining = sum(alive(member) for member in members)
        # These two exact roots were required absent and created only for this guest job.
        for owned in (provision, jobs):
            if owned.exists():
                require(owned.is_dir() and not owned.is_symlink() and owned.stat().st_uid == os.getuid(), "owned root changed")
                shutil.rmtree(owned)
        remaining += sum(path.exists() for path in (provision, jobs))
        result["cleanup"] = {"complete": remaining == 0, "remaining_owned_objects": remaining,
                             "guest_model_and_job_roots_removed": True, "observed_worker_lifetimes_ended": remaining == 0}
        after = snapshot()
        write(output / "host-state-after.json", after)
        result["host_state"] = {"unchanged": before == after,
                                "before_sha256": file_hash(output / "host-state-before.json", 1048576)["sha256"],
                                "after_sha256": file_hash(output / "host-state-after.json", 1048576)["sha256"]}
        result["success"] = "observed_blocker" not in result and remaining == 0 and before == after
        if result["success"]:
            result["phase"] = "complete"
            check_report(result, revision)
        write(output / "agent-training-smoke.json", result)
    return 0 if result["success"] else 1


def self_test():
    # These are checker tests only, never claimed as model execution evidence.
    data = public_dataset("a" * 40)
    require(data["train"][0]["question"] != data["heldout"][0]["question"], "heldout overlaps training")
    observation = {"observed": True, "network_devices": ["lo"], "ipv4_routes": [], "effective_capabilities": 0,
                   "namespaces": dict.fromkeys(("net", "pid", "ipc", "mnt"), "separate"),
                   "guest_namespaces": dict.fromkeys(("net", "pid", "ipc", "mnt"), "guest"),
                   "host_home_visible": False, "outside_canary_visible": False,
                   "exact_input_inodes": {"a": True, "b": True, "c": True},
                   "mounts": dict.fromkeys(("/runtime", "/model", "/dataset.json"), ["ro"])}
    check_isolation(observation)
    for field, bad in (("network_devices", ["lo", "eth0"]), ("ipv4_routes", ["default"]),
                       ("effective_capabilities", 1), ("host_home_visible", True)):
        changed = copy.deepcopy(observation)
        changed[field] = bad
        try:
            check_isolation(changed)
        except ValueError:
            continue
        raise AssertionError("invalid isolation accepted: " + field)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "plain"
        path.write_bytes(b"public")
        require(file_hash(path, 6)["bytes"] == 6, "artifact hash")
        link = Path(directory) / "symlink"
        link.symlink_to(path)
        try:
            file_hash(link, 6)
        except ValueError:
            pass
        else:
            raise AssertionError("symlink artifact accepted")
    print("agent-training checker self-tests PASS (synthetic checker inputs only)")


def main():
    if sys.argv[1:] == ["self-test"]:
        self_test()
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "execute":
        return execute(Path(sys.argv[2]), sys.argv[3])
    if len(sys.argv) == 7 and sys.argv[1] == "observe":
        observe(int(sys.argv[2]), *(Path(x) for x in sys.argv[3:]))
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "report":
        report = Path(sys.argv[2])
        check_bundle(report, sys.argv[3])
        print("real isolated CPU training report PASS")
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "failure":
        write(Path(sys.argv[2]) / "agent-training-smoke.json", {
            "report_kind": "volparossa-isolated-agent-training", "source_revision": sys.argv[3],
            "success": False, "scope": SCOPE, "full_alpha_claimed": False,
            "phase": sys.argv[4], "observed_blocker": "GUEST_PHASE_INCOMPLETE",
            "cleanup": {"complete": False, "remaining_owned_objects": None},
            "host_state": {"unchanged": None},
        })
        return 1
    raise ValueError("usage: self-test | execute OUTPUT REVISION | report REPORT REVISION")


if __name__ == "__main__":
    raise SystemExit(main())
