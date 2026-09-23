#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One actual, public, source-grounded 1.7B inference; semantic review is separate."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
TRAIN = runpy.run_path(str(HERE / "agent-training-smoke.py"))
read, write, require = TRAIN["read"], TRAIN["write"], TRAIN["require"]
NAME = "agent-reasoning"
PROFILE = "smollm2-1.7b-v1"
BUDGET = 5 * 1024**3
CLI = "/home/vpci/target/debug/volparossa"
COMPARISON_REVISION = "c4bd2745dbf32f172586bede0aeb632abf2945b0"
COMPARISON_RUN = 35868855324
QUESTION = "Which route meets the stated privacy constraints, why, and what further evidence is needed before comparing performance?"
# Literal original public graph fixture. No answer is added to the inference prompt.
SOURCE = (b"Synthetic public routing case.\n"
    b"Required path: client -> one relay -> exit -> destination.\n"
    b"A relay may know the client and exit, but not the Internet destination.\n"
    b"An exit may know the destination and relay, but not the client's public address.\n"
    b"Route A uses client -> relay -> exit -> destination.\n"
    b"Route B uses client -> exit -> destination; the exit sees the client's public address.\n"
    b"No throughput, latency or failure measurements are provided.\n")
SCOPE = ("One explicitly provisioned, isolated CPU SmolLM2-1.7B BF16 worker answers the original public routing question. "
    "The same worker also evaluates one separately labelled literal heldout fact, without training. "
    "Original source, input, raw answer/report, sampled CPU/RSS and cleanup are retained. "
    "Execution and EOS are not semantic correctness, distributed reasoning or full alpha.")


def digest(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def pins():
    value = read(TRAIN["ML"] / "model-pins.json")
    value.update(read(TRAIN["ML"] / "model-pins-1.7b.json"))
    return value


def dataset(revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "invalid source revision")
    # The ordinary v1 public contract requires a heldout row. Its literal source
    # fact is evaluated separately, never included as an answer in the inference.
    return dict(version=1, visibility="public", license="GPL-3.0-only", source_revision=revision,
        train=[], heldout=[dict(question="What is the required path?",
            answer="client -> one relay -> exit -> destination.", context=SOURCE.decode())],
        inference=[dict(question=QUESTION, context=SOURCE.decode())])


def semantic_review(answer):
    return dict(status="pending_independent_review", model_answer_correctness_proven=False,
        comparison_run=COMPARISON_RUN, comparison_revision=COMPARISON_REVISION,
        comparison_scope="same original source and question, not the same model/pipeline or a controlled benchmark",
        source=digest(SOURCE), question=QUESTION, answer=copy.deepcopy(answer),
        criteria=["Route A has the required client-relay-exit-destination shape; this is not proof of actual privacy enforcement.",
            "Route B violates the required relay boundary and exposes the client's public address to the exit.",
            "A relay may learn client and exit, not the Internet destination; an exit may learn relay and destination, not the client public address.",
            "No performance comparison is established: throughput, latency and failure measurements are absent."],
        rubric_supplied_to_model=False, automatic_semantic_pass=False)


def check_provision(value):
    selected = pins()
    require(value["success"] is True and value["model_profile"] == PROFILE
        and value["model_id"] == selected["model_id"] and value["revision"] == selected["revision"]
        and value["installed_wheels"] == len(selected["wheels"]) == 38
        and value["download_bytes"] == sum(x["bytes"] for k in ("files", "wheels") for x in selected[k])
        and value["budget_bytes"] == BUDGET and value["training_performed"] is False
        and value["runtime_autofetch_enabled"] is False
        and value["model_pins_sha256"] == digest((json.dumps(selected, indent=2) + "\n").encode())["sha256"],
        "provision not bound to exact explicit profile")


def check_worker(value, revision, raw_dataset):
    selected = pins()
    expected_files = {x["path"]: {k: x[k] for k in ("bytes", "sha256")} for x in selected["files"]}
    require(value["status"] == "ok" and value["mode"] == "infer" and value["device"] == "cpu"
        and value["threads"] == 2 and value["updates_completed"] == 0 and value["artifacts"] == []
        and value["model"] == dict(id=selected["model_id"], revision=selected["revision"], files=expected_files)
        and value["model_parameter_dtype"] == "bfloat16"
        and value["answer_prompt_revision"] == "public-source-parts-v1",
        "not actual fixed BF16 public inference with the selected answer instruction")
    require(value["dataset"]["sha256"] == digest(raw_dataset)["sha256"]
        and value["dataset"]["bytes"] == len(raw_dataset) and value["dataset"]["source_revision"] == revision
        and value["dataset"]["visibility"] == "public" and value["dataset"]["training_examples"] == 0
        and value["dataset"]["inference_examples"] == 1, "wrong original public dataset")
    require(value["backend_versions"] == dict(torch="2.14.0+cpu", transformers="5.16.1", peft="0.20.0"), "wrong backend")
    require(value["better_answers_claimed"] is False and value["distributed_training_claimed"] is False
        and value["network_policy_changed"] is False, "unsupported model claim")
    require(len(value["outputs"]) == 1, "not exactly one answer")
    answer = value["outputs"][0]
    require(answer["sample_index"] == 0 and answer["text_truncated"] is False
        and type(answer["text"]) is str and 0 < len(answer["text"].encode()) <= 4096
        and type(answer["generated_tokens"]) is int and 1 <= answer["generated_tokens"] <= 256
        and answer["generation"] == dict(version=1, stop_reason="eos", max_new_tokens=256, model_profile=PROFILE),
        "inference did not produce an original complete EOS answer")
    supervisor = value["supervisor"]
    require(supervisor["sandbox"] == "bubblewrap-private-user-net-pid-ipc-mount"
        and supervisor["network_access"] is False and supervisor["gpu_access"] is False
        and supervisor["child_reaped"] is True and supervisor["deadline_seconds"] == 600
        and supervisor["pause_extends_deadline"] is False
        and supervisor["rss_limit_bytes"] == 5 * 1024**3
        and 0 < supervisor["max_observed_rss_bytes"] <= supervisor["rss_limit_bytes"], "worker budget/isolation differs")
    require(type(value["elapsed_ms"]) is int and 0 < value["elapsed_ms"] < 600000, "worker original deadline exceeded")


def parse_address_space(limit_text):
    require(type(limit_text) is str and limit_text.isascii() and 0 < len(limit_text) <= 16384
        and "\0" not in limit_text, "invalid bounded proc limits text")
    rows = [line for line in limit_text.splitlines()
        if re.match(r"Max[ \t]+address[ \t]+space(?:[ \t]|$)", line)]
    require(len(rows) == 1, "missing or duplicate address-space row")
    # /proc/limits pads the units column too. Permit horizontal whitespace only;
    # neither another line nor a non-byte/unlimited limit supplies numeric proof.
    row = re.fullmatch(r"Max[ \t]+address[ \t]+space[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+bytes[ \t]*", rows[0])
    require(row is not None, "invalid numeric address-space row")
    return dict(soft_bytes=int(row[1]), hard_bytes=int(row[2]), units="bytes")


def check_limits(value, worker):
    require(value["version"] == 1 and value["worker"] == worker
        and value["worker_before"] == value["worker_after"] == worker,
        "address-space observation changed worker identity")
    raw = value["proc_limits_text"].encode("ascii")
    require(value["proc_limits"] == digest(raw) and value["parse_error"] is None
        and value["address_space"] == parse_address_space(value["proc_limits_text"]),
        "original proc limits differ from parsed evidence")
    require(value["address_space"] == dict(soft_bytes=10 * 1024**3, hard_bytes=10 * 1024**3, units="bytes"),
        "actual reasoning address-space limit differs")


def observe(pid, output, provision, original, canary):
    TRAIN["observe"](pid, output / f"{NAME}-isolation.json", provision, original, canary)
    worker = read(output / f"{NAME}-isolation.json")["worker"]
    before = TRAIN["identity"](worker["pid"])
    raw_limits = Path(f"/proc/{worker['pid']}/limits").read_bytes()
    after = TRAIN["identity"](worker["pid"])
    limit_text = raw_limits.decode("ascii")
    observation = dict(version=1, worker=worker, worker_before=before, worker_after=after,
        proc_limits_text=limit_text, proc_limits=digest(raw_limits), address_space=None, parse_error=None)
    try:
        observation["address_space"] = parse_address_space(limit_text)
    except ValueError:
        observation["parse_error"] = "invalid_address_space_row"
    path = output / f"{NAME}-limits.json"
    write(path, observation)
    info = original.stat()
    os.chown(path, info.st_uid, info.st_gid)
    # Retain original text and actual parsed values before any mismatch can stop us.
    check_limits(observation, worker)
    address = observation["address_space"]
    samples, first, last, peak = 0, None, None, 0
    deadline = time.monotonic() + 610
    while TRAIN["alive"](worker):
        require(time.monotonic() < deadline, "observer process lifetime exceeded")
        try:
            fields = Path(f"/proc/{worker['pid']}/stat").read_text().rsplit(")", 1)[1].split()
            require(int(fields[19]) == worker["start_ticks"], "observed worker identity changed")
            sample = dict(user_ticks=int(fields[11]), system_ticks=int(fields[12]))
            peak = max(peak, int(fields[21]) * os.sysconf("SC_PAGE_SIZE"))
            first = first or sample
            last = sample
            samples += 1
        except FileNotFoundError:
            break
        time.sleep(0.5)
    require(samples > 0, "actual worker CPU not observed")
    path = output / f"{NAME}-cpu.json"
    write(path, dict(worker=worker, samples=samples, clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
        first=first, last=last, sampled_peak_rss_bytes=peak, sample_interval_ms=500,
        address_space_soft_bytes=address["soft_bytes"], address_space_hard_bytes=address["hard_bytes"],
        complete_lifetime_cpu_claimed=False, worker_lifetime_ended=not TRAIN["alive"](worker)))
    info = original.stat()
    os.chown(path, info.st_uid, info.st_gid)


def check_report(value, revision):
    require(value["report_kind"] == "volparossa-agent-reasoning" and value["source_revision"] == revision
        and value["scope"] == SCOPE and value["success"] is True and value["execution_complete"] is True
        and value["model_answer_correctness_proven"] is False and value["full_alpha_claimed"] is False,
        "incomplete execution or unsupported quality claim")
    raw = bytes.fromhex(value["dataset_hex"])
    require(json.loads(raw) == dataset(revision) and value["source_hex"] == SOURCE.hex()
        and len(SOURCE) == 444, "original source or question changed")
    check_provision(value["provision"])
    check_worker(value["worker"], revision, raw)
    TRAIN["check_isolation"](value["isolation"])
    check_limits(value["limits"], value["isolation"]["worker"])
    require(value["semantic_review"] == semantic_review(value["worker"]["outputs"][0]), "semantic review misrepresented")
    cpu = value["cpu"]
    require(cpu["worker"] == value["isolation"]["worker"] and 1 <= cpu["samples"] <= 1221
        and cpu["clock_ticks_per_second"] > 0 and cpu["sample_interval_ms"] == 500
        and cpu["last"]["user_ticks"] >= cpu["first"]["user_ticks"]
        and cpu["last"]["system_ticks"] >= cpu["first"]["system_ticks"]
        and cpu["sampled_peak_rss_bytes"] > 0 and cpu["complete_lifetime_cpu_claimed"] is False
        and cpu["address_space_soft_bytes"] == cpu["address_space_hard_bytes"] == 10 * 1024**3
        and cpu["worker_lifetime_ended"] is True, "CPU observation invalid")
    weights = next(x for x in pins()["files"] if x["path"] == "model.safetensors")
    require(value["model_before"] == value["model_after"] == {k: weights[k] for k in ("bytes", "sha256")}, "original weights changed")
    require(value["cleanup"] == dict(complete=True, remaining_owned_objects=0, fallback_signals_used=False)
        and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"], "cleanup failed")


def check_bundle(path, revision):
    value = read(path, 1048576)
    check_report(value, revision)
    for field in ("worker", "provision", "isolation", "limits", "cpu", "semantic_review"):
        require(read(path.parent / f"{NAME}-{field}.json", 1048576) == value[field], "original report differs")
    require((path.parent / f"{NAME}-source.txt").read_bytes() == SOURCE
        and (path.parent / f"{NAME}-dataset.json").read_bytes().hex() == value["dataset_hex"]
        and read(path.parent / f"{NAME}-answer.json") == value["worker"]["outputs"][0], "original input/answer differs")
    for when in ("before", "after"):
        require(TRAIN["file_hash"](path.parent / f"host-state-{when}.json", 1048576)["sha256"]
            == value["host_state"][f"{when}_sha256"], "original guest state differs")


def execute(output, revision):
    TRAIN["guest_guard"]()
    require(output == Path("/home/vpci/alpha-output"), "wrong guest output")
    provision, jobs = Path("/home/vpci/reasoning-ml-provision"), Path("/home/vpci/reasoning-ml-jobs")
    require(not any(p.exists() or p.is_symlink() for p in (provision, jobs)), "fixture roots already exist")
    jobs.mkdir(mode=0o700)
    before = TRAIN["snapshot"]()
    write(output / "host-state-before.json", before)
    result = dict(report_kind="volparossa-agent-reasoning", source_revision=revision, scope=SCOPE,
        success=False, execution_complete=False, model_answer_correctness_proven=False,
        full_alpha_claimed=False, phase="provision", source_hex=SOURCE.hex())
    process, observer, members, fallback = None, None, [], False
    try:
        with (output / f"{NAME}-provision.log").open("x") as log:
            subprocess.run([sys.executable, "-B", str(TRAIN["ML"] / "provision.py"), "--execute", "--yes",
                "--disposable-guest", "--model-profile", PROFILE, "--root", str(provision),
                "--budget-bytes", str(BUDGET)], stdout=log, stderr=subprocess.STDOUT, timeout=2400, check=True)
        result["provision"] = read(provision / "provision-report.json")
        write(output / f"{NAME}-provision.json", result["provision"])
        check_provision(result["provision"])
        original = jobs / "public-dataset.json"
        write(original, dataset(revision))
        result["dataset_hex"] = original.read_bytes().hex()
        shutil.copyfile(original, output / f"{NAME}-dataset.json")
        with (output / f"{NAME}-source.txt").open("xb") as stream:
            stream.write(SOURCE)
        canary = jobs / "outside-canary"
        with canary.open("x") as stream:
            stream.write("Synthetic isolation marker; not a private key.\n")
        weights = next(x for x in pins()["files"] if x["path"] == "model.safetensors")
        model_file = provision / "model/model.safetensors"
        result["model_before"] = TRAIN["file_hash"](model_file, weights["bytes"])
        result["phase"] = "infer-and-observe"
        with (output / f"{NAME}-worker.json").open("x") as stdout, (output / f"{NAME}-worker.stderr").open("x") as stderr:
            process = subprocess.Popen([CLI, "compute", "run", "--mode", "infer", "--runtime-root", str(provision / "venv"),
                "--model-root", str(provision / "model"), "--model-profile", PROFILE, "--dataset", str(original),
                "--output", str(jobs / "infer"), "--steps", "1", "--threads", "2", "--max-seconds", "600", "--execute"],
                stdout=stdout, stderr=stderr)
            with (output / f"{NAME}-observer.stderr").open("x") as diagnostics:
                observer = subprocess.Popen(["sudo", "-n", sys.executable, "-B", str(Path(__file__).resolve()), "observe",
                    str(process.pid), str(output), str(provision), str(original), str(canary)], stderr=diagnostics)
                code = process.wait(timeout=610)
                observation_code = observer.wait(timeout=75)
        # Preserve original nonzero/token-limited reports before any success check.
        result["worker"] = read(output / f"{NAME}-worker.json", 1048576)
        if result["worker"].get("outputs"):
            answer = result["worker"]["outputs"][0]
            write(output / f"{NAME}-answer.json", answer)
            result["semantic_review"] = semantic_review(answer)
            write(output / f"{NAME}-semantic_review.json", result["semantic_review"])
        if (output / f"{NAME}-limits.json").is_file():
            result["limits"] = read(output / f"{NAME}-limits.json")
        require(code == 0 and observation_code == 0, "inference or observer did not complete")
        for field in ("isolation", "cpu"):
            result[field] = read(output / f"{NAME}-{field}.json")
        members = list(result["isolation"]["owned_processes"])
        require(original.read_bytes().hex() == result["dataset_hex"], "original dataset changed")
        check_worker(result["worker"], revision, original.read_bytes())
        result["model_after"] = TRAIN["file_hash"](model_file, weights["bytes"])
        result["execution_complete"] = True
        result["phase"] = "cleanup"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["observed_blocker"] = str(error)[:1024]
    finally:
        if process is not None and process.poll() is None:
            members += TRAIN["descendants"](process.pid)
        for child in (process, observer):
            if child is not None and child.poll() is None:
                fallback = True
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        isolated = output / f"{NAME}-isolation.json"
        if isolated.is_file():
            members += read(isolated).get("owned_processes", [])
        remaining = sum(TRAIN["alive"](member) for member in members)
        if remaining == 0:
            for owned in (provision, jobs):
                if owned.exists():
                    info = owned.lstat()
                    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "owned cleanup root changed")
                    shutil.rmtree(owned)
        remaining += sum(p.exists() for p in (provision, jobs))
        result["cleanup"] = dict(complete=remaining == 0, remaining_owned_objects=remaining, fallback_signals_used=fallback)
        after = TRAIN["snapshot"]()
        write(output / "host-state-after.json", after)
        result["host_state"] = dict(unchanged=before == after,
            before_sha256=TRAIN["file_hash"](output / "host-state-before.json", 1048576)["sha256"],
            after_sha256=TRAIN["file_hash"](output / "host-state-after.json", 1048576)["sha256"])
        result["success"] = "observed_blocker" not in result and remaining == 0 and not fallback and before == after
        if result["success"]:
            try:
                check_report(result, revision)
                result["phase"] = "complete"
            except (ValueError, KeyError, TypeError) as error:
                result["success"] = False
                result["observed_blocker"] = str(error)[:1024]
        write(output / f"{NAME}-smoke.json", result)
    return 0 if result["success"] else 1


def self_test():
    expected = dict(soft_bytes=10 * 1024**3, hard_bytes=10 * 1024**3, units="bytes")
    worker_identity = dict(pid=123, start_ticks=456)  # Pure parser fixture, not a process observation.
    for raw_row in (
        "Max address space 10737418240 10737418240 bytes\n",
        "Max address space         10737418240          10737418240          bytes     \n",
        "Max\taddress\tspace\t10737418240\t10737418240\tbytes\t \n",
    ):
        require(parse_address_space(raw_row) == expected, "padded proc numeric row rejected")
        limits = dict(version=1, worker=worker_identity, worker_before=worker_identity, worker_after=worker_identity,
            proc_limits_text=raw_row, proc_limits=digest(raw_row.encode()), address_space=expected, parse_error=None)
        check_limits(limits, worker_identity)
    for invalid in (
        "Max open files 128 128 files\n", "Max address space unlimited unlimited bytes\n",
        "Max address space 10737418240 10737418240 kbytes\n",
        "Max address space 10737418240 10737418240 bytes ignored\n",
        "Max address space 10737418240\n10737418240 bytes\n",
        raw_row + raw_row,
    ):
        try:
            parse_address_space(invalid)
        except ValueError:
            continue
        raise AssertionError("invalid proc address-space row accepted")
    for soft, hard in ((0, 10 * 1024**3), (10 * 1024**3, 6 * 1024**3), (11 * 1024**3, 11 * 1024**3)):
        changed = copy.deepcopy(limits)
        changed["proc_limits_text"] = f"Max address space {soft} {hard} bytes     \n"
        changed["proc_limits"] = digest(changed["proc_limits_text"].encode())
        changed["address_space"] = parse_address_space(changed["proc_limits_text"])
        try:
            check_limits(changed, worker_identity)
        except ValueError:
            continue
        raise AssertionError("a non-10GiB actual limit was accepted")
    for field, value in (("worker_after", dict(pid=123, start_ticks=457)),
                        ("proc_limits", dict(bytes=1, sha256="0" * 64)),
                        ("address_space", dict(soft_bytes=1, hard_bytes=1, units="bytes"))):
        changed = copy.deepcopy(limits)
        changed[field] = value
        try:
            check_limits(changed, worker_identity)
        except ValueError:
            continue
        raise AssertionError("changed original limits or worker identity accepted")
    historical = runpy.run_path(str(HERE / "agent-model-planning-smoke.py"))
    require(historical["GRAPH_SOURCE"] == SOURCE and historical["GRAPH_QUESTION"] == QUESTION and len(SOURCE) == 444,
        "comparison original changed")
    value = dataset("a" * 40)
    require(value["train"] == [] and value["inference"] == [dict(question=QUESTION, context=SOURCE.decode())], "prompt changed")
    for text in ("Route B is private because the exit sees the client's public address.", "Route A fits the required path."):
        review = semantic_review(dict(text=text))
        require(review["status"] == "pending_independent_review" and review["automatic_semantic_pass"] is False
            and review["model_answer_correctness_proven"] is False and review["answer"]["text"] == text,
            "unreviewed text became semantic PASS")
    require(sum(x["bytes"] for k in ("files", "wheels") for x in pins()[k]) < BUDGET, "explicit provision budget too small")
    selected = pins()
    raw = json.dumps(value).encode()
    worker = dict(status="ok", mode="infer", device="cpu", threads=2, updates_completed=0, artifacts=[],
        model=dict(id=selected["model_id"], revision=selected["revision"],
            files={x["path"]: {k: x[k] for k in ("bytes", "sha256")} for x in selected["files"]}),
        model_parameter_dtype="bfloat16", answer_prompt_revision="public-source-parts-v1",
        dataset=dict(**digest(raw), source_revision="a" * 40,
            visibility="public", training_examples=0, inference_examples=1),
        backend_versions=dict(torch="2.14.0+cpu", transformers="5.16.1", peft="0.20.0"),
        better_answers_claimed=False, distributed_training_claimed=False, network_policy_changed=False,
        outputs=[dict(sample_index=0, text="Synthetic checker test, not a model answer.", text_truncated=False,
            generated_tokens=10, generation=dict(version=1, stop_reason="eos", max_new_tokens=256, model_profile=PROFILE))],
        supervisor=dict(sandbox="bubblewrap-private-user-net-pid-ipc-mount", network_access=False, gpu_access=False,
            child_reaped=True, deadline_seconds=600, pause_extends_deadline=False,
            max_observed_rss_bytes=4 * 1024**3, rss_limit_bytes=5 * 1024**3), elapsed_ms=1000)
    check_worker(worker, "a" * 40, raw)
    mutations = [lambda x: x.update(model_parameter_dtype="float32"),
        lambda x: x.update(answer_prompt_revision="unknown"),
        lambda x: x["supervisor"].update(rss_limit_bytes=6 * 1024**3),
        lambda x: x["supervisor"].update(deadline_seconds=1200),
        lambda x: x["outputs"][0]["generation"].update(stop_reason="token_limit"),
        lambda x: x["outputs"][0]["generation"].update(model_profile="smollm2-360m-v1"),
        lambda x: x["dataset"].update(sha256="0" * 64), lambda x: x["model"].update(revision="0" * 40),
        lambda x: x.update(updates_completed=1), lambda x: x.update(better_answers_claimed=True)]
    for mutate in mutations:
        wrong = copy.deepcopy(worker)
        mutate(wrong)
        try:
            check_worker(wrong, "a" * 40, raw)
        except ValueError:
            continue
        raise AssertionError("altered inference identity/budget/claim accepted")
    print("reasoning strict padded limits/original identity, source/question, prompt revision, separate semantic review, budget and ten evidence mutations PASS; no model executed")


def main(args):
    if args == ["self-test"]:
        self_test()
    elif len(args) == 3 and args[0] == "execute":
        return execute(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "report":
        check_bundle(Path(args[1]), args[2])
    elif len(args) == 6 and args[0] == "observe":
        observe(int(args[1]), *(Path(x) for x in args[2:]))
    elif len(args) == 4 and args[0] == "failure":
        write(Path(args[1]) / f"{NAME}-smoke.json", dict(report_kind="volparossa-agent-reasoning",
            source_revision=args[2], success=False, phase=args[3], observed_blocker="guest_phase_failed"))
    else:
        return 64
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
