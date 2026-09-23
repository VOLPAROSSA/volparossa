#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Disposable, explicit public DAG: actual peer receipts, not answer-quality claims."""
import copy
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
COLL = runpy.run_path(str(HERE / "agent-public-collection-smoke.py"))
DOC, JOBS, SYNTH, CUSTODY = (COLL[k] for k in ("DOC", "JOBS", "SYNTH", "CUSTODY"))
read, write, require, sha, encoded = (COLL[k] for k in ("read", "write", "require", "sha", "encoded"))
ATTEMPT = COLL["ATTEMPT"]
MODEL, MODEL_ID = COLL["MODEL_FINGERPRINT"], COLL["MODEL_IDENTITY"]
PREFIX = "agent-task-graph"
PLAN = dict(version=1, nodes=[
    dict(id="requirements", question="Name one requirement.", depends_on=[]),
    dict(id="risks", question="Name one risk.", depends_on=[]),
    dict(id="compare", question="Compare these findings briefly.", depends_on=["requirements", "risks"]),
    dict(id="refine", question="Refine this finding briefly.", depends_on=["compare"])], output="refine")
KIND = "volparossa-explicit-public-task-graph"
SCOPE = ("One literal public README excerpt, two distinct source questions sharing the exact original signed "
    "manifest, two overlapping isolated executors in one shared ready queue, an exact two-package partial "
    "boundary, then real dependent comparison and single-parent refinement jobs. Every executed row is "
    "observed and reconstructed from retained receipts and signed inputs. Completed offline resume retains "
    "the same files without original input, task plan, brokers or route. Not automatic task planning, "
    "model-answer quality, semantic completeness, private offload, external actions, full B03 or full alpha.")
HANDLE = re.compile(r"node-([0-9]{4})/(?:synthesis/level-([0-9]{2})-group-([0-9]{4})/)?"
    r"package-([0-9]{4})/" + ATTEMPT + r"/job-([0-3])\.json")


def root_path(work):
    return work / "state-client/compute-source/public-task-graph"


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def prepare(work):
    require(JOBS["TRAIN"]["socket"].gethostname() == "volparossa-alpha"
        and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
        and os.geteuid() != 0 and work.parent == Path("/opt") and work.name.startswith("va.")
        and not work.is_symlink() and HERE == work / "bin", "wrong installed guest graph helper")
    for path in (Path(__file__), HERE / "graph-source-README.md"):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222,
            "graph helper/source not root-installed read-only")
    source = JOBS["private"](work / "state-client/compute-source", "compute-source")
    original = (HERE / "graph-source-README.md").read_bytes()
    selected = original[:128].decode("utf-8", errors="ignore").encode()
    require(124 <= len(selected) <= 128 and original.startswith(selected), "not a literal public UTF-8 prefix")
    target = source / "graph-input.txt"
    with target.open("xb") as stream:
        stream.write(selected)
    target.chmod(0o600)
    write(source / "graph-task-plan.json", PLAN)
    own = (source / "graph-model/model.safetensors").stat()
    peer = (work / "agent-jobs-user/provision/model/model.safetensors").stat()
    require((own.st_dev, own.st_ino) != (peer.st_dev, peer.st_ino)
        and JOBS["file_hash"](source / "graph-model/model.safetensors", 269060552) == MODEL_ID["base_weights"],
        "owner tokenizer model is not independent pinned copy")
    print(json.dumps(dict(source="README.md", original_repository_sha256=sha(original),
        excerpt_hex=selected.hex(), excerpt_sha256=sha(selected), excerpt_bytes=len(selected), plan=PLAN,
        input_inode=[target.stat().st_dev, target.stat().st_ino],
        owner_model_inode=[own.st_dev, own.st_ino], peer_model_inode=[peer.st_dev, peer.st_ino],
        private_copies_no_hardlinks=True)))


def snapshot(root):
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not root.is_symlink() and info.st_uid != 0
        and stat.S_IMODE(info.st_mode) == 0o700, "wrong owned graph directory")
    result, count, total = {}, 0, 0
    for directory, children, files in os.walk(root, topdown=True, followlinks=False):
        count += len(children) + len(files)
        require(count <= 2048, "unbounded retained graph tree")
        kept = []
        for name in sorted(children):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            item = path.lstat()
            require(stat.S_ISDIR(item.st_mode) and not path.is_symlink() and item.st_uid == info.st_uid
                and stat.S_IMODE(item.st_mode) == 0o700, "unsafe graph child directory")
            if re.fullmatch(r"node-[0-9]{4}/(?:synthesis/level-[0-9]{2}-group-[0-9]{4}/)?publication-cache", relative):
                continue  # Never export mutable cache metadata/chunks or any key/model directories.
            require(re.fullmatch(r"node-000[0-3](?:/(?:synthesis|level-[0-9]{2}-group-[0-9]{4}|"
                r"package-[0-9]{4}|work|attempt-[0-9]{4}|tokenizer(?:-attempt-[0-9]{4})?))*", relative),
                "unexpected private graph directory")
            kept.append(name)
        children[:] = kept
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            item = path.lstat()
            require(stat.S_ISREG(item.st_mode) and not path.is_symlink() and item.st_uid == info.st_uid
                and item.st_nlink == 1 and stat.S_IMODE(item.st_mode) == 0o600
                and item.st_size <= 16 * 1048576 and (name.endswith(".json") or name in
                ("source.txt", "source.manifest", "dataset.manifest", "manifest.bin", ".task.lock", ".workflow.lock")),
                "unexpected or unsafe retained public graph file")
            raw = path.read_bytes()
            require(len(raw) == item.st_size and (raw or name in (".task.lock", ".workflow.lock")), "changed/empty retained file")
            total += len(raw)
            require(total <= 32 * 1048576, "graph evidence exceeds bound")
            result[relative] = dict(bytes=len(raw), sha256=sha(raw), inode=[item.st_dev, item.st_ino])
    require("graph.json" in result and "graph-plan.json" in result
        and not any("attempt-0001" in name for name in result), "missing graph authority or unexpected retries")
    return result


def observe(work, launcher, phase):
    JOBS["guest_work"](work)
    require(phase in ("partial", "result"), "wrong graph observation phase")
    owner = JOBS["identity"](launcher)
    layout = read(work / "agent-jobs-layout.json")
    brokers = {node: JOBS["identity"](JOBS["broker_pid"](node)) for node in layout["provider_nodes"]}
    root = root_path(work)
    observed, seen, started = [], set(), time.monotonic()
    if phase == "result":
        seen = {w["handle"]["binding"]["job_id"] for w in read(record(work, "partial-observation"))["workers"]}
    while JOBS["alive"](owner) and time.monotonic() - started < 1800:
        paths = sorted(root.glob("node-????/package-????/work/package-0000/attempt-0000/job-?.json"))
        paths += sorted(root.glob("node-????/synthesis/level-??-group-????/package-????/work/package-0000/attempt-0000/job-?.json"))
        require(len(paths) <= 64, "graph actual worker bound exceeded")
        active = []
        first = time.monotonic_ns()
        for path in paths:
            relative = path.relative_to(root).as_posix()
            match = HANDLE.fullmatch(relative)
            require(match is not None, "unexpected graph handle path")
            try:
                handle = read(path)
            except (OSError, json.JSONDecodeError):
                continue
            identifier = handle["binding"]["job_id"]
            if identifier in seen:
                continue
            node = next((n for n in brokers if layout["provider_keys"][n] == handle["provider_key"]), None)
            require(node is not None and handle["binding"]["row_indices"] == [int(match[5])], "unknown peer or non-singleton graph job")
            current = JOBS["worker_snapshot"](work, node, brokers[node], handle["binding"]["dataset_sha256"])
            if current and JOBS["alive"](current["worker"]):
                item = dict(graph_node=int(match[1]), level=int(match[2] or 0), handle_path=relative,
                    handle=handle, handle_file=JOBS["file_hash"](path,16384), worker=current,
                    first_monotonic_ns=first, last_monotonic_ns=time.monotonic_ns(),
                    alive_before_and_after=JOBS["alive"](current["worker"]))
                require(item["alive_before_and_after"], "worker disappeared during observation")
                active.append(item)
        if phase == "partial" and not observed:
            # Keep polling both original singleton handles until overlap is measured.
            if len(active) != 2 or not all(JOBS["alive"](w["worker"]["worker"]) for w in active):
                time.sleep(0.025)
                continue
            overlap = dict(workers=[w["worker"] for w in active], both_alive_before_and_after=True,
                first_monotonic_ns=first, last_monotonic_ns=time.monotonic_ns())
            JOBS["check_overlap"](overlap)
            write(work / "agent-jobs-observation.json", overlap)
        for item in active:
            write(record(work, f"{phase}-worker-{len(observed):04d}"), item)
            observed.append(item)
            seen.add(item["handle"]["binding"]["job_id"])
        time.sleep(0.025)
    require(not JOBS["alive"](owner) and observed, "graph owner/real worker observation incomplete")
    require({w["graph_node"] for w in observed} == ({0,1} if phase == "partial" else {2,3}),
        "wrong actual graph stages executed")
    write(record(work, f"{phase}-observation"), dict(owner=owner, owner_reaped=True, workers=observed))


def collect(work, phase):
    JOBS["guest_work"](work)
    require(phase in ("partial", "result"), "wrong graph collection phase")
    root = root_path(work)
    selected = snapshot(root)
    raw = {n:(root / n).read_bytes().hex() for n in selected}
    require(all(sha(bytes.fromhex(raw[n])) == v["sha256"] for n,v in selected.items()), "graph changed during snapshot")
    if phase == "partial":
        value = read(record(work, "partial"))
        check_partial(value)
        require(all(not HANDLE.fullmatch(n) or n.startswith(("node-0000/", "node-0001/")) for n in selected)
            and len([n for n in selected if HANDLE.fullmatch(n)]) == 2, "dependent job crossed exact initial package budget")
    write(record(work, f"{phase}-files"), dict(snapshot=selected, raw=raw))


def check_partial(value):
    require(value["version"] == 2 and value["operation"] == "compute_public_task_graph" and value["complete"] is False
        and value["execution_complete"] is False and value["answer_complete"] is False
        and value["semantic_completeness_proven"] is False
        and value["rounds_this_invocation"] == 2 and value["plan"] == PLAN and value["output"] is None
        and value["interrupted"] is False and [n["complete"] for n in value["nodes"]] == [True,True,False,False]
        and [n["status"] for n in value["nodes"]] == ["complete","complete","pending","awaiting_dependencies"],
        "initial invocation did not stop at the exact two-leaf budget")


def remove_inputs(work):
    JOBS["guest_work"](work)
    source = work / "state-client/compute-source"
    original = read(record(work, "input"))
    targets = [source / "graph-input.txt", source / "graph-task-plan.json"]
    for path in targets:
        item = path.lstat()
        require(stat.S_ISREG(item.st_mode) and item.st_uid == source.stat().st_uid != 0
            and item.st_nlink == 1 and stat.S_IMODE(item.st_mode) == 0o600, "original fixture input ownership changed")
    require(targets[0].read_bytes().hex() == original["excerpt_hex"] and read(targets[1]) == PLAN
        and [targets[0].stat().st_dev,targets[0].stat().st_ino] == original["input_inode"], "original fixture input changed")
    print("Disposable guest only: remove these owned fixture inputs before completed resume: " + ", ".join(map(str,targets)), flush=True)
    for path in targets:
        path.unlink()
    write(record(work, "inputs-removed"), dict(original_input_absent=True, original_plan_absent=True,
        removed=[str(p.relative_to(work)) for p in targets], retained_graph_plan=(root_path(work)/"graph-plan.json").is_file()))


def stopped(work, resumed=False):
    JOBS["guest_work"](work)
    workers = [w["worker"] for phase in ("partial","result") for w in read(record(work,f"{phase}-observation"))["workers"]]
    require(all(not JOBS["alive"](p) for w in workers for p in w["owned_processes"]), "observed graph process remains")
    for worker in read(work / "agent-jobs-observation.json")["workers"]:
        require(not JOBS["alive"](worker["broker"]), "original peer broker remains available")
        state = JOBS["subprocess"].check_output(["systemctl", "show", "--property=ActiveState", "--value",
            f"volparossa-alpha-compute@{worker['node']}.service"], text=True).strip()
        require(state in ("inactive", "failed"), "peer broker unit remains active")
    source = work / "state-client/compute-source"
    require(not (source/"graph-input.txt").exists() and not (source/"graph-task-plan.json").exists(), "offline resume used originals")
    value = dict(all_owned_processes_ended=True, brokers_stopped=True, original_input_absent=True, original_plan_absent=True)
    if resumed:
        value["snapshot"] = snapshot(root_path(work))
        require(value["snapshot"] == read(record(work,"result-files"),64*1048576)["snapshot"], "completed offline resume changed retained graph")
    write(record(work,"resumed" if resumed else "stopped"),value)


def manifest(raw, data, authority, name, profile):
    result = DOC["manifest"](raw,data,authority,name,profile)
    fields=CUSTODY["fields"];envelope=fields(raw,65536);body=fields(envelope[1],65536)
    COLL["verify_signature"](envelope[1],envelope[2],body[2],b"VOLPAROSSA/native-content-manifest/v1\0")
    return result


def original_source_identity(source):
    require(type(source) is bytes and 0<len(source)<=4096 and b"\0" not in source
        and source.decode("utf-8").encode("utf-8")==source,"invalid complete original synthesis source")
    return dict(original_source_sha256=sha(source),original_source_bytes=len(source))


def check_original_source_identity(value,source):
    require(all(value.get(key)==expected for key,expected in original_source_identity(source).items()),
        "original synthesis source identity changed")


def planner(raw, prefix, source, question, synthesis=False, model_profile="smollm2-135m-v1",original_source=None):
    selected=JOBS["TRAIN"]["inference_profile"](model_profile)
    model=selected["model"];limit=selected["prompt_tokens"]
    load=lambda name:json.loads(raw[prefix+name])
    plan=load("document-plan.json")
    require(plan["version"]==1 and plan["source_bytes"]==len(source) and plan["source_sha256"]==sha(source)
        and plan["question_sha256"]==sha(question.encode()) and plan["model_id"]==model["model_id"]
        and plan["model_revision"]==model["model_revision"] and plan["tokenizer_sha256"]==DOC["TOKENIZER"]
        and plan["prompt_limit"]==limit and plan.get("synthesis",False) is synthesis
        and 1<=len(plan["parts"])<=128,"wrong actual tokenizer plan")
    end=0
    for part in plan["parts"]:
        require(type(part["start"]) is int and type(part["end"]) is int and part["start"]==end
            and 0<part["end"]-part["start"]<=4096 and part["end"]<=len(source)
            and type(part["prompt_tokens"]) is int and 1<=part["prompt_tokens"]<=limit,"invalid byte-complete bounded tokenizer range")
        source[part["start"]:part["end"]].decode();end=part["end"]
    require(end==len(source),"tokenizer omitted original input")
    expected=dict(version=1)
    if model_profile!="smollm2-135m-v1":expected["model_profile"]=model_profile
    expected.update(visibility="public",license="GPL-3.0-only",document=source.decode(),question=question)
    if synthesis:expected["synthesis"]=True
    if original_source is not None:
        require(synthesis and model_profile=="smollm2-360m-v1","grounded tokenizer profile changed")
        check_original_source_identity(plan,original_source)
        expected["original_source"]=original_source.decode()
    require(load("planner-input.json")==expected and raw[prefix+"planner-input.json"]==encoded(expected),
        "tokenizer got another instruction/context/profile")
    report=load("tokenizer-report.json")
    require(report["mode"]=="plan_document" and report["status"]=="ok" and report["device"]=="cpu"
        and report["model_weights_loaded"] is False and report["updates_completed"]==0
        and "outputs" not in report and "baseline_evaluation" not in report
        and report["dataset"]["sha256"]==sha(raw[prefix+"planner-input.json"])
        and load("tokenizer/report.json").items()<=report.items() and load("tokenizer/document-plan.json")==plan
        and report["artifacts"]==[dict(relative_path="document-plan.json",bytes=len(raw[prefix+"tokenizer/document-plan.json"]),
            sha256=sha(raw[prefix+"tokenizer/document-plan.json"]))],"tokenizer artifact is not bound to actual worker report")
    DOC["check_supervisor"](report)
    if original_source is not None:
        require(report["dataset"].get("version")==1 and report["dataset"].get("synthesis") is True,
            "grounded tokenizer dataset mode changed")
        check_original_source_identity(report["dataset"],original_source)
    return plan


def shared_queue(batch, required):
    # report_ready_many preserves the existing single-package ready queue when
    # there are no other package leases; that truthful report has no shared flag.
    if required:
        require(batch.get("shared_package_slots") is True, "independent packages did not share one provider registry")
    else:
        require("shared_package_slots" not in batch or batch["shared_package_slots"] is True,
            "invalid singleton ready queue scope")


def package(raw,prefix,data,manifest_id,authority,question,layout,executed,response_bytes,node_index,level,shared,
            model_profile="smollm2-135m-v1",original_source=None):
    selected=JOBS["TRAIN"]["inference_profile"](model_profile)
    model,fingerprint=selected["model"],selected["fingerprint"]
    load=lambda name:json.loads(raw[prefix+"/"+name])
    task=dict(kind="answer_public_question_v1",question=question)
    if original_source is not None or data["version"]==5:
        require(original_source is not None and level>0 and model_profile=="smollm2-360m-v1"
            and data["version"]==5 and data.get("original_source")==original_source.decode(),
            "grounded peer dataset omitted or changed the complete original source")
        original_source_identity(original_source)
    require(load("dataset.json")==data and raw[prefix+"/dataset.json"]==encoded(data),"signed task rows changed")
    require(raw[prefix+"/work/package-0000/dataset.json"]==raw[prefix+"/dataset.json"]
        and raw[prefix+"/work/package-0000/manifest.bin"]==raw[prefix+"/dataset.manifest"],"workflow source changed")
    workflow=load("work/workflow.json")
    require(workflow["scheduling"]=="ready_rows_v1" and workflow["provider_keys"]==authority["provider_keys"]
        and workflow.get("model_fingerprint")==authority.get("model_fingerprint")
        and workflow["packages"]==[dict(publisher_key=authority["publisher_key"],manifest_id=manifest_id,
            dataset_sha256=sha(raw[prefix+"/dataset.json"]),rows=len(data["inference"]),task=task)],"workflow changed task/source")
    batch=load(ATTEMPT+"/result.json");queue=load(ATTEMPT+"/queue-plan.json")
    require(batch["operation"]=="compute_ready_queue" and batch["complete"] is True and batch["scheduling"]=="ready_rows_v1"
        and batch["dataset_manifest_id"]==manifest_id and batch["task"]==task and batch["never_submitted_rows"]==[]
        and len(batch["jobs"])==len(batch["outputs"])==len(data["inference"]),"ready package incomplete")
    shared_queue(batch,shared)
    require(queue["version"]==1 and queue["scheduling"]=="ready_rows_v1" and queue["publisher_key"]==authority["publisher_key"]
        and queue["dataset_manifest_id"]==manifest_id and queue["dataset_sha256"]==sha(raw[prefix+"/dataset.json"])
        and queue["source_expires_unix_seconds"]==authority["expires_at_unix_seconds"]
        and queue["model_fingerprint"]==fingerprint and queue["task"]==task and queue["provider_keys"]==authority["provider_keys"]
        and queue["ready_rows"]==list(range(len(data["inference"]))) and queue["pending_job_ids"]==[],"queue changed instruction/model/source/expiry")
    answers=[]
    for row in range(len(data["inference"])):
        handle=load(ATTEMPT+f"/job-{row}.json");binding=handle["binding"];caps=handle["capabilities"];identifier=binding["job_id"]
        node=next((n for n,k in layout["provider_keys"].items() if k==handle["provider_key"]),None)
        require(node is not None and identifier not in executed and re.fullmatch(r"[0-9a-f]{32}",identifier)
            and binding["dataset_manifest_id"]==manifest_id and binding["row_indices"]==[row] and binding["task"]==task
            and binding["expires_unix_seconds"]<=authority["expires_at_unix_seconds"]
            and caps["model_fingerprint"]==binding["model_fingerprint"]==fingerprint and caps["model"]==model
            and caps["public_inference_only"] is True and caps["runtime_slots"]==1 and caps["max_threads"]==2
            and (model_profile=="smollm2-135m-v1" or caps["max_rows"]==1)
            and caps["task_derivation_v1"] is True and caps["derived_inference_v3" if level else "document_inference_v2"] is True,
            "singleton task/lease/executor changed")
        selected=copy.deepcopy(data);selected["inference"]=[selected["inference"][row]];selected_raw=encoded(selected)
        require(binding["dataset_sha256"]==sha(selected_raw),"worker received another row")
        receipt=load(ATTEMPT+f"/receipt-{identifier}.json");status=receipt["status"]
        part=next(p for p in batch["jobs"] if p["handle"]==handle)
        require(receipt["version"]==1 and receipt["handle"]==handle and status["binding"]==binding
            and status["state"]==part["state"]=="complete" and part["new_submission"] is True
            and status["report_sha256"]==part["report_sha256"]==sha(status["report_json"].encode()),"receipt/result correlation differs")
        actual=json.loads(status["report_json"])
        require(actual["mode"]=="infer" and actual["status"]=="ok" and actual["device"]=="cpu" and actual["threads"]==2
            and actual["updates_completed"]==0 and actual["dataset"]["version"]==data["version"]
            and actual["dataset"]["sha256"]==sha(selected_raw) and actual["dataset"]["source_manifest_sha256"]==authority["source_manifest_id"]
            and actual["baseline_evaluation"] is None and len(actual["outputs"])==1
            and actual["model"]["id"]==model["model_id"] and actual["model"]["revision"]==model["model_revision"]
            and actual["model"]["files"]["model.safetensors"]==model["base_weights"],"real inference result missing")
        DOC["check_supervisor"](actual)
        if original_source is not None:
            check_original_source_identity(actual["dataset"],original_source)
        if model_profile!="smollm2-135m-v1":
            require(caps["max_job_seconds"]==600 and actual["supervisor"]["rss_limit_bytes"]==3*1024**3,
                "selected profile changed the existing worker resource bounds")
        output=actual["outputs"][0]
        require(batch["outputs"][row]==dict(sample_index=row,provider_key=handle["provider_key"],job_id=identifier,text=output["text"],
            **SYNTH["generation_fields"](output,model_profile=model_profile)),"joined output changed")
        context=data["inference"][row]
        start=context["start"] if not level else min(i["source_start"] for i in context["inputs"])
        end=context["end"] if not level else max(i["source_end"] for i in context["inputs"])
        answers.append(SYNTH["answer"](output,handle,status,manifest_id,start,end,0,model_profile=model_profile))
        executed[identifier]=dict(handle=handle,raw=selected_raw,node=node,graph_node=node_index,level=level,
            path=prefix+"/"+ATTEMPT+f"/job-{row}.json")
        response_bytes[node]+=len(status["report_json"].encode())
    return answers


def check_graph_summary(value, source_id, expiry, providers, answers, rounds, complete=True):
    require(value["version"]==2 and value["operation"]=="compute_public_task_graph" and value["complete"] is complete
        and value["execution_complete"] is complete and value["answer_complete"] is complete
        and value["semantic_completeness_proven"] is False
        and value["plan"]==PLAN and value["plan_sha256"]==sha(encoded(PLAN)) and value["source_manifest_id"]==source_id
        and value["source_expires_unix_seconds"]==expiry and value["provider_keys"]==providers
        and value["rounds_this_invocation"]==rounds and value["interrupted"] is False
        and value["scheduling"]=="shared_ready_dependency_queue_v1"
        and all(value[k] is False for k in ("private_data_supported","automatic_task_planning","external_actions_supported",
            "model_answer_correctness_proven","full_b03_claimed")),"graph result identity/scope changed")
    for index,node in enumerate(PLAN["nodes"]):
        actual=value["nodes"][index]
        require(all(actual[k]==node[k] for k in ("id","question","depends_on"))
            and actual["answer"]==answers.get(node["id"])
            and actual["execution_complete"] is (node["id"] in answers),"graph node answer/instruction changed")
    if complete:
        require(len(value["nodes"])==4 and all(n["complete"] is True and n["status"]=="complete" for n in value["nodes"])
            and value["output"]==answers["refine"],"graph output is not original final receipt")
    else:
        check_partial(value)


def check(value,revision):
    require(value["source_revision"]==revision,"wrong graph source revision")
    provision=value["provision"]
    require(provision["success"] is True and provision["installed_wheels"]==38 and provision["download_bytes"]==523040250
        and provision["training_performed"] is False,"unverified pinned guest model provision")
    raw={n:bytes.fromhex(v) for n,v in value["result-files"]["raw"].items()}
    saved=value["result-files"]["snapshot"]
    require(set(raw)==set(saved) and sum(map(len,raw.values()))<=32*1048576,"graph public export differs")
    require(all(saved[n]["bytes"]==len(b) and saved[n]["sha256"]==sha(b) for n,b in raw.items()),"graph raw-file hashes differ")
    load=lambda name:json.loads(raw[name])
    original=value["input"];source=bytes.fromhex(original["excerpt_hex"])
    require(original["source"]=="README.md" and original["plan"]==PLAN and 124<=len(source)<=128
        and original["excerpt_bytes"]==len(source) and original["excerpt_sha256"]==sha(source),"source/task selection changed")
    require(load("graph-plan.json")==PLAN and raw["graph-plan.json"]==encoded(PLAN),"retained owner task plan changed")
    graph=load("graph.json")
    require(graph==dict(version=1,plan_sha256=sha(encoded(PLAN)),leaves=[dict(node=i,enrollment_sha256=sha(raw[f"node-{i:04d}/document.json"])) for i in (0,1)]),"graph leaf enrollment pins changed")
    partial=value["partial-files"]
    for name,item in partial["snapshot"].items():
        if name in ("graph-plan.json","graph.json") or name.startswith(("node-0000/","node-0001/")):
            require(saved.get(name)==item and raw[name].hex()==partial["raw"][name],"completed initial leaf history changed on resume")
    require({n for n in partial["snapshot"] if HANDLE.fullmatch(n)}=={
        f"node-{i:04d}/package-0000/{ATTEMPT}/job-0.json" for i in (0,1)},"dependent execution bypassed initial package budget")
    JOBS["check_overlap"](value["overlap"])
    layout=value["layout"];workers={w["node"]:w for w in value["overlap"]["workers"]}
    require(set(workers)==set(layout["provider_nodes"])
        and all(CUSTODY["peer_key"](value["peers"][n])==k for n,k in layout["provider_keys"].items())
        and layout["control_relay_peer_id"] not in {value["peers"][n] for n in workers}
        and original["private_copies_no_hardlinks"] is True and original["owner_model_inode"]!=original["peer_model_inode"]
        and all(w["input_inodes"]["model/model.safetensors"]==original["peer_model_inode"] for w in workers.values()),"actual peer/model isolation differs")
    authority=load("node-0000/document.json");source_manifest=raw["node-0000/source.manifest"]
    source_id=manifest(source_manifest,source,authority,"document-source","text/plain")
    require(source_id==authority["source_manifest_id"] and authority["expires_at_unix_seconds"]-authority["selected_at_unix_seconds"]==7200,
        "original shared source authority changed")
    DOC["selected_providers"](authority,layout)
    executed,response_bytes,answers={},dict.fromkeys(workers,0),{}
    for index in (0,1):
        prefix=f"node-{index:04d}/";enrollment=load(prefix+"document.json");question=PLAN["nodes"][index]["question"]
        plan=planner(raw,prefix,source,question)
        require(len(plan["parts"])==1 and len(enrollment["packages"])==1 and raw[prefix+"source.txt"]==source
            and raw[prefix+"source.manifest"]==source_manifest and enrollment["version"]==1
            and enrollment["scheduling"]=="ready_rows_v1" and enrollment["synthesize"] is True
            and enrollment["source_sha256"]==sha(source) and enrollment["source_bytes"]==len(source)
            and enrollment["plan_sha256"]==sha(raw[prefix+"document-plan.json"]) and enrollment["public_question"]==question
            and enrollment["license"]=="GPL-3.0-only" and enrollment["publisher_key"]==value["publish"]["publisher_key_hex"]
            and all(enrollment.get(k)==authority.get(k) for k in ("publisher_key","provider_keys","source_manifest_id",
                "model_fingerprint","selected_at_unix_seconds","expires_at_unix_seconds")),"leaf did not share exact source authority")
        data=dict(version=2,visibility="public",license="GPL-3.0-only",source_manifest_hex=source_manifest.hex(),
            inference=[dict(question=question,context=source.decode(),start=0,end=len(source))])
        package_prefix=prefix+"package-0000"
        identity=manifest(raw[package_prefix+"/dataset.manifest"],raw[package_prefix+"/dataset.json"],enrollment,"document-package-0000",DOC["PROFILE"])
        require(enrollment["packages"]==[dict(manifest_id=identity,dataset_sha256=sha(encoded(data)),first_part=0,rows=1)],"leaf source package mapping changed")
        produced=package(raw,package_prefix,data,identity,enrollment,question,layout,executed,response_bytes,index,0,True)
        answers[PLAN["nodes"][index]["id"]]=produced[0]
        leaf=load(prefix+"result.json")
        require(leaf["complete"] is True and leaf["synthesized_answer"]==produced[0] and leaf["synthesis"]["levels"]==[],"single source answer was replaced")
    initial_answers=dict(answers)
    rounds=0
    for index in (2,3):
        node=PLAN["nodes"][index];question=node["question"];prefix=f"node-{index:04d}"
        result=load(prefix+"/result.json");parents=[answers[name] for name in node["depends_on"]]
        require(raw[prefix+"/source.manifest"]==source_manifest and result["operation"]=="compute_graph_dependency"
            and result["public_question"]==question and result["source_manifest_id"]==source_id
            and result["graph_node"]==dict(node,plan_sha256=sha(encoded(PLAN))),"dependent node changed source/task")
        levels=result["synthesis"]["levels"]
        require(1<=len(levels)<=16,"dependent instruction was passed through without executing")
        for number,level in enumerate(levels,1):
            require(level["level"]==number and level["complete"] is True
                and level["execution_complete"] is True and level["answer_complete"] is True and level["parents"]==len(parents)
                and len(level["groups"])==(len(parents)+63)//64,"derived stage lost original parents")
            following=[]
            for group_index,group in enumerate(level["groups"]):
                group_prefix=prefix+f"/synthesis/level-{number:02d}-group-{group_index:04d}"
                previous=parents[group_index*64:group_index*64+64]
                require(raw[group_prefix+"/parents.json"]==encoded(previous),"dependent input is not original parent receipts")
                saved_group=load(group_prefix+"/group.json")
                require(saved_group["version"]==1 and saved_group["level"]==number and saved_group["parent_offset"]==group_index*64
                    and saved_group["parents_sha256"]==sha(encoded(previous)) and saved_group["source_manifest_id"]==source_id
                    and authority["selected_at_unix_seconds"]<=saved_group["created_at_unix_seconds"]<authority["expires_at_unix_seconds"],"derived source time renewed")
                combined,rows=SYNTH["expected_rows"](previous,load(group_prefix+"/document-plan.json")["parts"],question,group_index*64)
                planner(raw,group_prefix+"/",combined,question,True)
                require(group==dict(group=group_index,parents=len(previous),complete=True,parts=len(rows),input_sha256=sha(combined)),"derived group accounting differs")
                for p in range((len(rows)+3)//4):
                    package_prefix=group_prefix+f"/package-{p:04d}"
                    data=dict(version=3,visibility="public",license="GPL-3.0-only",source_manifest_hex=source_manifest.hex(),
                        level=number,claim_scope=SYNTH["CLAIM"],inference=rows[p*4:p*4+4])
                    original=dict(authority,selected_at_unix_seconds=saved_group["created_at_unix_seconds"])
                    identity=manifest(raw[package_prefix+"/dataset.manifest"],raw[package_prefix+"/dataset.json"],original,
                        f"derived-l{number:02d}-g{group_index:04d}-p{p:04d}",SYNTH["PROFILE"])
                    following.extend(package(raw,package_prefix,data,identity,authority,question,layout,executed,response_bytes,index,number,len(rows)>4))
                    rounds+=1
            require(level["outputs"]==len(following) and (number==1 or len(following)<len(parents))
                and level["answers"]==following and level["generation_limit_reached"] is any(SYNTH["generation_limited"](a) for a in following)
                and load(prefix+f"/synthesis/level-{number:02d}-result.json")==level,"derived receipts/levels changed")
            parents=following
        require(len(parents)==1 and result["version"]==2 and result["complete"] is True
            and result["execution_complete"] is True and result["answer_complete"] is True and result["synthesized_answer"]==parents[0]
            and result["synthesis"]["complete"] is True and result["synthesis"]["claim_scope"]==SYNTH["CLAIM"]
            and result["synthesis"]["model_answer_correctness_proven"] is False
            and result["synthesis"]["semantic_completeness_proven"] is False,"dependent output or scope changed")
        answers[node["id"]]=parents[0]
    require(2<=rounds<=8 and len({a["job_id"] for a in answers.values()})==4,"single-parent refinement reused its parent job")
    for phase,count,complete,expected in (("partial",2,False,initial_answers),("result",rounds,True,answers),("resume",0,True,answers)):
        check_graph_summary(value[phase],source_id,authority["expires_at_unix_seconds"],authority["provider_keys"],expected,count,complete)
    require(load("result.json")==value["result"],"retained graph summary changed on completed resume")
    require({n for n in raw if HANDLE.fullmatch(n)}=={x["path"] for x in executed.values()},"extra copied/unverified graph jobs")
    observed,processes=set(),[]
    for phase in ("partial","result"):
        observation=value[phase+"-observation"]
        require(observation["owner_reaped"] is True,"owner not reaped")
        for item in observation["workers"]:
            handle,worker=item["handle"],item["worker"];identifier=handle["binding"]["job_id"]
            require(identifier in executed and identifier not in observed,"unknown/duplicated actual worker")
            actual=executed[identifier];base=workers[actual["node"]]
            require(item["graph_node"]==actual["graph_node"] and item["level"]==actual["level"]
                and handle==actual["handle"] and item["handle_path"]==actual["path"]
                and item["handle_file"]=={k:saved[actual["path"]][k] for k in ("bytes","sha256")}
                and worker["dataset_json"].encode()==actual["raw"] and worker["dataset_file"]["sha256"]==sha(actual["raw"])
                and all(worker[k]==base[k] for k in ("node","broker","service","node_namespace","runtime_lock_inode"))
                and worker["worker"] not in processes and item["alive_before_and_after"] is True
                and item["first_monotonic_ns"]<item["last_monotonic_ns"],"actual worker task/process lineage missing")
            require(worker["runtime_lock_held"] is True and worker["network_devices"]==["lo"] and worker["ipv4_routes"]==[]
                and worker["effective_capabilities"]==0 and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
                and all("ro" in worker["mounts"][p] for p in ("/runtime","/model","/dataset.json"))
                and all(worker["worker_namespaces"][k]!=worker["guest_namespaces"][k] for k in ("net","pid","ipc","mnt"))
                and worker["worker_namespaces"]["net"]!=worker["node_namespace"],"actual graph worker isolation missing")
            observed.add(identifier);processes.append(worker["worker"])
    require(observed==set(executed),"not every actual derived/source job was observed")
    require(value["inputs-removed"]["original_input_absent"] is True and value["inputs-removed"]["original_plan_absent"] is True
        and value["inputs-removed"]["retained_graph_plan"] is True
        and all(value[phase][k] is True for phase in ("stopped","resumed") for k in
            ("all_owned_processes_ended","brokers_stopped","original_input_absent","original_plan_absent"))
        and value["resumed"]["snapshot"]==saved,"original-free offline retained history unproven")
    CUSTODY["validate_path"](value["path"],value["peers"],layout,"inspect")
    application=value["path"]["privacy"]["exit"]["provider_application"]
    require(all(application[n]["request_packets"]>0 and application[n]["response_payload_bytes"]>=size for n,size in response_bytes.items())
        and all(value["cleanup"].values()),"protected complete reports or cleanup missing")


def evidence(work,revision):
    JOBS["guest_work"](work)
    value={name:read(record(work,name),64*1048576) for name in ("input","partial","partial-files","partial-observation",
        "result","result-files","result-observation","resume","inputs-removed","stopped","resumed")}
    value.update({name:read(work/f"agent-jobs-{name}.json") for name in ("provision","publish","layout")})
    value.update(source_revision=revision,overlap=read(work/"agent-jobs-observation.json"),peers=read(work/"a01-expected-peers.json"),
        cleanup=read(work/"agent-jobs-private-cleanup.json"),path=dict(selected_route=read(work/"content-custody-fetch-live-selection.json"),
        privacy={r:read(work/f"content-custody-fetch-privacy-{r}.json") for r in CUSTODY["ROLES"]},
        control_privacy=read(work/"content-provider-custody-fetch-control.json"),gates=read(work/"content-custody-fetch-gates.json")))
    check(value,revision);write(record(work,"evidence"),value)


def finalize(work,revision,status,complete,remaining,phase,blocker):
    path=record(work,"evidence");value=read(path,64*1048576) if path.is_file() else None
    host=read(work/"a15-evidence.json") if (work/"a15-evidence.json").is_file() else {}
    write(record(work,"smoke"),dict(report_kind=KIND,source_revision=revision,scope=SCOPE,
        success=status==0 and complete and remaining==0 and value is not None,runner_exit_status=status,phase=phase,
        observed_blocker=None if blocker=="NONE" else blocker,evidence=value,cleanup=dict(complete=complete,remaining_owned_objects=remaining),host_state=host,
        automatic_task_planning=False,model_answer_correctness_proven=False,full_b03_claimed=False,full_alpha_claimed=False))


def report(value,revision):
    require(value["report_kind"]==KIND and value["source_revision"]==revision and value["scope"]==SCOPE
        and value["success"] is True and value["runner_exit_status"]==0 and value["observed_blocker"] is None
        and value["cleanup"]==dict(complete=True,remaining_owned_objects=0) and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"]==value["host_state"]["after_sha256"]
        and all(value[k] is False for k in ("automatic_task_planning","model_answer_correctness_proven","full_b03_claimed","full_alpha_claimed")),
        "graph/cleanup/host proof incomplete")
    check(value["evidence"],revision)


def self_test():
    # Inert schema/budget/lineage controls; these are not simulated execution evidence.
    shared_queue(dict(shared_package_slots=True),True)
    shared_queue(dict(shared_package_slots=True),False)
    shared_queue({},False)
    for batch,required in (({},True),(dict(shared_package_slots=False),True),(dict(shared_package_slots=False),False)):
        try:shared_queue(batch,required)
        except ValueError:pass
        else:raise AssertionError("missing/false shared package scope accepted")
    partial=dict(version=2,operation="compute_public_task_graph",complete=False,rounds_this_invocation=2,
        execution_complete=False,answer_complete=False,semantic_completeness_proven=False,
        plan=copy.deepcopy(PLAN),output=None,interrupted=False,nodes=[dict(complete=i<2,
            status=("complete" if i<2 else "pending" if i==2 else "awaiting_dependencies")) for i in range(4)])
    check_partial(partial)
    for change in (dict(rounds_this_invocation=3),dict(complete=True),dict(output={}),dict(interrupted=True)):
        try:check_partial(dict(partial,**change))
        except ValueError:pass
        else:raise AssertionError("wrong partial graph boundary accepted")
    changed=copy.deepcopy(partial);changed["nodes"][2]["complete"]=True
    try:check_partial(changed)
    except ValueError:pass
    else:raise AssertionError("dependent work accepted before resume")
    assert HANDLE.fullmatch(f"node-0003/synthesis/level-01-group-0000/package-0000/{ATTEMPT}/job-0.json")
    assert not HANDLE.fullmatch("node-0003/secret.key")
    parent=dict(text="Inert test parent",provider_key="a"*64,job_id="b"*32,report_sha256="c"*64,
        package_manifest_id="d"*64,model_fingerprint=MODEL,output_index=0,source_start=0,source_end=128,
        generated_tokens=4,text_truncated=False,generation=dict(version=1,stop_reason="eos",max_new_tokens=64))
    combined=(parent["text"]+"\n").encode()
    source,rows=SYNTH["expected_rows"]([parent],[dict(start=0,end=len(combined))],PLAN["nodes"][3]["question"],0)
    assert source==combined and rows[0]["question"]==PLAN["nodes"][3]["question"] and rows[0]["inputs"][0]["job_id"]==parent["job_id"]
    assert "generation" not in rows[0]["inputs"][0]  # Retained result metadata does not change signed derived-input schema.
    assert rows[0]["question"]!=PLAN["nodes"][2]["question"]
    # These minimal values exercise the final schema only; no receipt/worker is invented.
    answers={n["id"]:dict(job_id=str(i)*32) for i,n in enumerate(PLAN["nodes"],1)}
    complete=dict(version=2,operation="compute_public_task_graph",complete=True,plan=copy.deepcopy(PLAN),
        execution_complete=True,answer_complete=True,semantic_completeness_proven=False,
        plan_sha256=sha(encoded(PLAN)),source_manifest_id="a"*64,source_expires_unix_seconds=7200,
        provider_keys=["b"*64,"c"*64],rounds_this_invocation=3,interrupted=False,
        scheduling="shared_ready_dependency_queue_v1",private_data_supported=False,
        automatic_task_planning=False,external_actions_supported=False,model_answer_correctness_proven=False,
        full_b03_claimed=False,output=answers["refine"],nodes=[dict(n,complete=True,execution_complete=True,status="complete",answer_status="eos",answer=answers[n["id"]]) for n in PLAN["nodes"]])
    check_graph_summary(complete,"a"*64,7200,["b"*64,"c"*64],answers,3)
    check_graph_summary(dict(complete,rounds_this_invocation=0),"a"*64,7200,["b"*64,"c"*64],answers,0)
    for change in (dict(automatic_task_planning=True),dict(rounds_this_invocation=0),dict(source_expires_unix_seconds=7201),
                   dict(output=answers["compare"]),dict(private_data_supported=True),
                   dict(scheduling="shared_source_queue_then_ordered_dependency_frontiers")):
        try:check_graph_summary(dict(complete,**change),"a"*64,7200,["b"*64,"c"*64],answers,3)
        except ValueError:pass
        else:raise AssertionError("changed graph summary accepted")
    print("public graph partial-budget and single-parent instruction/lineage pure controls PASS; no model, tokenizer or network executed")


def main(args):
    command=args[0]
    if command=="self-test":self_test()
    elif command=="prepare":prepare(Path(args[1]))
    elif command=="observe":observe(Path(args[1]),int(args[2]),args[3])
    elif command=="collect":collect(Path(args[1]),args[2])
    elif command=="remove-inputs":remove_inputs(Path(args[1]))
    elif command=="stopped":stopped(Path(args[1]))
    elif command=="resumed":stopped(Path(args[1]),True)
    elif command=="evidence":evidence(Path(args[1]),args[2])
    elif command=="finalize":finalize(Path(args[1]),args[2],int(args[3]),args[4]=="true",int(args[5]),args[6],args[7])
    elif command=="report":report(read(Path(args[1]),64*1048576),args[2])
    else:raise ValueError("unknown fixed public graph fixture command")


if __name__=="__main__":
    main(sys.argv[1:])
