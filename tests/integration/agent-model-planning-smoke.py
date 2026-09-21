#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual bounded model-proposed public fork/join tasks; no answer-quality claim."""
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
GRAPH = runpy.run_path(str(HERE / "agent-task-graph-smoke.py"))
DOC, JOBS, SYNTH, CUSTODY = (GRAPH[k] for k in ("DOC", "JOBS", "SYNTH", "CUSTODY"))
TRAIN = JOBS["TRAIN"]
read, write, require, sha, encoded = (GRAPH[k] for k in ("read", "write", "require", "sha", "encoded"))
ATTEMPT, MODEL, MODEL_ID = (GRAPH[k] for k in ("ATTEMPT", "MODEL", "MODEL_ID"))
PREFIX = "agent-model-planning"
STRATEGY = "model_questions_scaffold_recovery_v2"
QUESTION = "What requirements and risks does this project describe?"
KIND = "volparossa-bounded-model-public-task-planning"
SCOPE = ("One actual isolated pinned-model owner generates two public subquestions from a goal, "
    "with only their JSON structure supplied locally and at most four charged attempts within 384 generated tokens, "
    "without seeing the source contents. The exact proposal is enrolled against one signed public README "
    "excerpt, then actual protected peers execute its source questions and an exact original-question join. "
    "Every peer execution and the separate owner planner are observed. Original-free completed offline "
    "resume neither replans nor changes retained graph, planner or receipts. Not decomposition/answer "
    "quality, semantic completeness, private offload, model-selected tools, open-ended autonomy, full B03 or full alpha.")
HANDLE = GRAPH["HANDLE"]


def root_path(work):
    return work / "state-client/compute-source/model-planning"


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def prepare(work):
    require(TRAIN["socket"].gethostname() == "volparossa-alpha"
        and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
        and os.geteuid() != 0 and work.parent == Path("/opt") and work.name.startswith("va.")
        and not work.is_symlink() and HERE == work / "bin", "wrong installed guest model-planning helper")
    for path in (Path(__file__), HERE / "model-planning-source-README.md"):
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o222,
            "planner helper/source not root-installed read-only")
    source=JOBS["private"](work / "state-client/compute-source", "compute-source")
    original=(HERE / "model-planning-source-README.md").read_bytes()
    excerpt=original[:128].decode("utf-8", errors="ignore").encode()
    require(124<=len(excerpt)<=128 and original.startswith(excerpt), "not a literal UTF-8 public source prefix")
    path=source / "model-planning-input.txt"
    with path.open("xb") as stream:
        stream.write(excerpt)
    path.chmod(0o600)
    with (source / "model-planning-canary").open("xb") as stream:
        stream.write(b"Public isolation canary, not a private key.\n")
    (source / "model-planning-canary").chmod(0o600)
    owner=source / "planner-provision/model/model.safetensors"
    peer=work / "agent-jobs-user/provision/model/model.safetensors"
    own,remote=owner.stat(),peer.stat()
    require((own.st_dev,own.st_ino)!=(remote.st_dev,remote.st_ino)
        and JOBS["file_hash"](owner,269060552)==MODEL_ID["base_weights"],"planner is not an independent pinned copy")
    print(json.dumps(dict(source="README.md", original_repository_sha256=sha(original),
        excerpt_hex=excerpt.hex(), excerpt_sha256=sha(excerpt), excerpt_bytes=len(excerpt), question=QUESTION,
        input_inode=[path.stat().st_dev,path.stat().st_ino], owner_model_inode=[own.st_dev,own.st_ino],
        peer_model_inode=[remote.st_dev,remote.st_ino], private_copies_no_hardlinks=True, supplied_task_plan=False)))


def snapshot(root):
    owner=root.lstat()
    require(stat.S_ISDIR(owner.st_mode) and not root.is_symlink() and owner.st_uid!=0
        and stat.S_IMODE(owner.st_mode)==0o700,"wrong private planned-graph root")
    result,total,count={},0,0
    for directory,children,files in os.walk(root,topdown=True,followlinks=False):
        count+=len(children)+len(files)
        require(count<=2048,"unbounded planned-graph tree")
        kept=[]
        for name in sorted(children):
            path=Path(directory)/name;relative=path.relative_to(root).as_posix();info=path.lstat()
            require(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid==owner.st_uid
                and stat.S_IMODE(info.st_mode)==0o700,"unsafe planned-graph child directory")
            if re.fullmatch(r"node-[0-9]{4}/(?:synthesis/level-[0-9]{2}-group-[0-9]{4}/)?publication-cache",relative):
                continue
            require(relative=="model-planner" or re.fullmatch(r"node-000[0-4](?:/(?:synthesis|level-[0-9]{2}-group-[0-9]{4}|"
                r"package-[0-9]{4}|work|attempt-[0-9]{4}|tokenizer(?:-attempt-[0-9]{4})?))*",relative),"unexpected private planned-graph directory")
            kept.append(name)
        children[:]=kept
        for name in sorted(files):
            path=Path(directory)/name;relative=path.relative_to(root).as_posix();info=path.lstat()
            require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid==owner.st_uid and info.st_nlink==1
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=16*1048576
                and (name.endswith(".json") or name in ("source.txt","source.manifest","dataset.manifest","manifest.bin",".task.lock",".workflow.lock")),
                "unexpected retained public planning file")
            raw=path.read_bytes();total+=len(raw)
            require(len(raw)==info.st_size and (raw or name in (".task.lock",".workflow.lock")) and total<=32*1048576,"changed/oversized planning history")
            result[relative]=dict(bytes=len(raw),sha256=sha(raw),inode=[info.st_dev,info.st_ino])
    require(all(n in result for n in ("graph.json","graph-plan.json","planner-input.json","planner-report.json","planner-artifact.json"))
        and not any("attempt-0001" in n for n in result),"missing exact planner authority or unexpected retries")
    return result


def observe_planner(work,launcher):
    JOBS["guest_work"](work)
    owner=JOBS["identity"](launcher);source=work/"state-client/compute-source";dataset=root_path(work)/"planner-input.json"
    service_pid=int(JOBS["subprocess"].check_output(["systemctl","show","--property=MainPID","--value",
        "volparossa-alpha-agent@client.service"],text=True))
    service=JOBS["identity"](service_pid);namespace=os.readlink(f"/proc/{service_pid}/ns/net")
    deadline=time.monotonic()+1800
    while JOBS["alive"](owner) and time.monotonic()<deadline:
        if dataset.is_file():
            expected=dataset.stat()
            for cli in TRAIN["descendants"](launcher):
                proc=Path(f"/proc/{cli['pid']}")
                try:
                    if proc.stat().st_uid!=source.stat().st_uid or Path(os.readlink(proc/"exe")).name!="volparossa":
                        continue
                    require(os.readlink(proc/"ns/net")==namespace,"planner CLI outside client namespace")
                    family=TRAIN["descendants"](cli["pid"])
                    for member in family:
                        child=Path(f"/proc/{member['pid']}")
                        args=(child/"cmdline").read_bytes().split(b"\0")
                        if not args or args[0]!=b"/runtime/bin/python3":
                            continue
                        actual=(child/"root/dataset.json").stat()
                        if (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino):
                            continue
                        output=source/"model-planner-isolation.json"
                        TRAIN["observe"](cli["pid"],output,source/"planner-provision",dataset,source/"model-planning-canary")
                        observation=read(output)
                        require(observation["worker"]==member and JOBS["alive"](member) and JOBS["alive"](cli),"planner child changed during observation")
                        metadata=output.lstat()
                        require(metadata.st_uid==source.stat().st_uid!=0 and metadata.st_nlink==1
                            and stat.S_IMODE(metadata.st_mode)==0o600,"planner observation did not retain private owner ownership")
                        lock_path=source/"planner-provision/venv/.volparossa-compute.lock";lock=lock_path.stat()
                        with lock_path.open("rb") as stream:
                            try:
                                fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                            except BlockingIOError:
                                pass
                            else:
                                raise ValueError("planner runtime lease not held")
                        mounted=(child/"root/output").stat();target=(root_path(work)/"model-planner").stat()
                        require((mounted.st_dev,mounted.st_ino)==(target.st_dev,target.st_ino),"planner output mount targets another mode")
                        model_input=(child/"root/model/model.safetensors").stat()
                        write(record(work,"planner-observation"),dict(isolation=observation,launcher=owner,
                            node_lineage=dict(node="client",cli=cli,cli_namespace=namespace,service=service,
                                service_namespace=namespace,worker_network_namespace=observation["namespaces"]["net"]),
                            dataset_file=JOBS["file_hash"](dataset,16384),dataset_inode=[expected.st_dev,expected.st_ino],
                            model_inode=[model_input.st_dev,model_input.st_ino],
                            output_inode=[target.st_dev,target.st_ino],runtime_lock_inode=[lock.st_dev,lock.st_ino],
                            runtime_lock_held=True,alive_before_and_after=True,observed_monotonic_ns=time.monotonic_ns()))
                        return
                except FileNotFoundError:
                    continue
        time.sleep(0.025)
    raise ValueError("actual owner-local PlanTasks worker not observed")


def collect(work,phase):
    JOBS["guest_work"](work)
    require(phase in ("enrolled","result"),"wrong planning snapshot phase")
    root=root_path(work);saved=snapshot(root);raw={n:(root/n).read_bytes().hex() for n in saved}
    require(all(sha(bytes.fromhex(raw[n]))==v["sha256"] for n,v in saved.items()),"planner history changed during snapshot")
    if phase=="enrolled":
        require(not any(HANDLE.fullmatch(n) or "/work/" in n or "/synthesis/" in n for n in saved),"peer work started during planning-only enrollment")
        isolated=read(record(work,"planner-observation"))["isolation"]
        require(all(not JOBS["alive"](p) for p in isolated["owned_processes"]),"owner planner not reaped before enrollment returned")
    write(record(work,phase+"-files"),dict(snapshot=saved,raw=raw))


def collect_failure(work):
    """Retain only validated, text-free failure metadata before private cleanup."""
    JOBS["guest_work"](work)
    root=root_path(work);path=root/"planner-failure.json"
    if not path.exists():return
    owner=root.lstat()
    require(stat.S_ISDIR(owner.st_mode) and owner.st_uid!=0 and stat.S_IMODE(owner.st_mode)==0o700
        and not root.is_symlink(),"invalid private failed-planner root")
    retained={}
    for name in ("planner-failure.json","planner-input.json"):
        selected=root/name;info=selected.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==owner.st_uid and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=16384,"invalid bounded planner diagnostic")
        raw=selected.read_bytes()
        require(len(raw)==info.st_size,"planner diagnostic changed during export")
        retained[name]=raw
    original=read(record(work,"input"));source=bytes.fromhex(original["excerpt_hex"])
    validate_failure(strict_json(retained["planner-failure.json"]),retained["planner-input.json"],source)
    require(not any((root/name).exists() for name in ("graph.json","graph-plan.json","planner-artifact.json")),
        "failure export unexpectedly contains an enrolled plan")
    observation=record(work,"planner-observation")
    if observation.is_file():
        require(all(not JOBS["alive"](p) for p in read(observation)["isolation"]["owned_processes"]),
            "planner diagnostic exported before observed child cleanup")
    for name,raw in retained.items():
        suffix="planner-failure" if name=="planner-failure.json" else "planner-failure-input"
        destination=record(work,suffix)
        with destination.open("xb") as stream:stream.write(raw)
        destination.chmod(0o600)


def observe_peers(work,launcher):
    JOBS["guest_work"](work)
    owner=JOBS["identity"](launcher);root=root_path(work);layout=read(work/"agent-jobs-layout.json")
    plan=read(root/"graph-plan.json");leaf_count=len(plan["nodes"])-1
    brokers={n:JOBS["identity"](JOBS["broker_pid"](n)) for n in layout["provider_nodes"]}
    seen,observed,overlap=set(),[],False;started=time.monotonic()
    while JOBS["alive"](owner) and time.monotonic()-started<1800:
        paths=sorted(root.glob("node-????/package-????/work/package-0000/attempt-0000/job-?.json"))
        paths+=sorted(root.glob("node-????/synthesis/level-??-group-????/package-????/work/package-0000/attempt-0000/job-?.json"))
        require(len(paths)<=96,"planned graph worker bound exceeded")
        current=[];first=time.monotonic_ns()
        for path in paths:
            relative=path.relative_to(root).as_posix();match=HANDLE.fullmatch(relative)
            require(match is not None,"unexpected planned graph handle path")
            try:
                handle=read(path)
            except (OSError,json.JSONDecodeError):
                continue
            identifier=handle["binding"]["job_id"]
            if identifier in seen:continue
            node=next((n for n in brokers if layout["provider_keys"][n]==handle["provider_key"]),None)
            require(node is not None and handle["binding"]["row_indices"]==[int(match[5])],"unknown peer/non-singleton planned job")
            worker=JOBS["worker_snapshot"](work,node,brokers[node],handle["binding"]["dataset_sha256"])
            if worker and JOBS["alive"](worker["worker"]):
                current.append(dict(graph_node=int(match[1]),level=int(match[2] or 0),handle_path=relative,handle=handle,
                    handle_file=JOBS["file_hash"](path,16384),worker=worker,first_monotonic_ns=first,
                    last_monotonic_ns=time.monotonic_ns(),alive_before_and_after=JOBS["alive"](worker["worker"])))
        if not overlap:
            if len(current)!=2 or not all(JOBS["alive"](w["worker"]["worker"]) for w in current):
                time.sleep(0.025);continue
            require(all(w["graph_node"]<leaf_count and w["level"]==0 for w in current),"first observed cohort was not source work")
            value=dict(workers=[w["worker"] for w in current],both_alive_before_and_after=True,
                first_monotonic_ns=first,last_monotonic_ns=time.monotonic_ns())
            JOBS["check_overlap"](value);write(work/"agent-jobs-observation.json",value);overlap=True
        for item in current:
            require(item["alive_before_and_after"],"planned worker disappeared during observation")
            write(record(work,f"worker-{len(observed):04d}"),item)
            observed.append(item);seen.add(item["handle"]["binding"]["job_id"])
        time.sleep(0.025)
    require(not JOBS["alive"](owner) and overlap and {w["graph_node"] for w in observed}==set(range(leaf_count+1)),
        "not every model-derived graph node executed or owner exceeded bound")
    write(record(work,"observation"),dict(owner=owner,owner_reaped=True,workers=observed))


def remove_input(work):
    JOBS["guest_work"](work)
    source=work/"state-client/compute-source";path=source/"model-planning-input.txt";info=path.lstat();original=read(record(work,"input"))
    require(stat.S_ISREG(info.st_mode) and info.st_uid==source.stat().st_uid!=0 and info.st_nlink==1
        and stat.S_IMODE(info.st_mode)==0o600 and [info.st_dev,info.st_ino]==original["input_inode"]
        and path.read_bytes().hex()==original["excerpt_hex"],"original owned planning input changed")
    print("Disposable guest only: remove the exact owned original public input before completed resume: "+str(path),flush=True)
    path.unlink()
    write(record(work,"input-removed"),dict(original_input_absent=True,supplied_task_plan=False,
        removed=str(path.relative_to(work)),retained_model_plan=(root_path(work)/"graph-plan.json").is_file()))


def stopped(work,resumed=False):
    JOBS["guest_work"](work)
    planner=read(record(work,"planner-observation"))["isolation"]
    workers=[w["worker"] for w in read(record(work,"observation"))["workers"]]
    require(all(not JOBS["alive"](p) for w in [planner]+workers for p in w["owned_processes"]),"actual planner/peer process remains")
    for worker in read(work/"agent-jobs-observation.json")["workers"]:
        require(not JOBS["alive"](worker["broker"]),"peer broker remains available")
        state=JOBS["subprocess"].check_output(["systemctl","show","--property=ActiveState","--value",
            f"volparossa-alpha-compute@{worker['node']}.service"],text=True).strip()
        require(state in ("inactive","failed"),"peer broker unit active")
    require(not (work/"state-client/compute-source/model-planning-input.txt").exists(),"offline original input still present")
    value=dict(all_owned_processes_ended=True,brokers_stopped=True,original_input_absent=True)
    if resumed:
        value["snapshot"]=snapshot(root_path(work))
        require(value["snapshot"]==read(record(work,"result-files"),64*1048576)["snapshot"],"offline resume replanned or changed history")
    write(record(work,"resumed" if resumed else "stopped"),value)


def strict_json(raw):
    def pairs(items):
        value={}
        for key,item in items:
            require(key not in value,"duplicate JSON key")
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs)


def questions_plan(artifact):
    require(len(artifact)<=16384,"model question artifact exceeds original bound")
    value=strict_json(artifact)
    require(type(value) is dict and value.keys()=={"version","questions"} and type(value["version"]) is int
        and value["version"]==1 and type(value["questions"]) is list and 2<=len(value["questions"])<=4,"wrong model question artifact")
    seen=set()
    for question in value["questions"]:
        require(type(question) is str and 1<=len(question.encode())<=512 and "\0" not in question
            and question.strip() and question.strip() not in seen,"invalid/non-distinct model-generated question")
        seen.add(question.strip())
    nodes=[dict(id=f"question-{index:02d}",question=q,depends_on=[]) for index,q in enumerate(value["questions"])]
    nodes.append(dict(id="answer",question=QUESTION,depends_on=[n["id"] for n in nodes]))
    return dict(version=1,nodes=nodes,output="answer")


def check_attempts(attempts,questions=None):
    """Validate accounting and identities; rejected text is deliberately not retained."""
    require(type(attempts) is list and len(attempts)<=4,"invalid planner attempt bound")
    accepted,total,maximum,stats=0,0,0,[]
    for number,item in enumerate(attempts,1):
        require(type(item) is dict and item.keys()=={"question_index","attempt","prompt_tokens","generated_tokens",
            "max_new_tokens","stop_reason","accepted","rejection_code","text_bytes","text_sha256"},"invalid attempt fields")
        cap=min(192,384-total)
        require(all(type(item[k]) is int for k in ("question_index","attempt","prompt_tokens","generated_tokens","max_new_tokens","text_bytes"))
            and item["question_index"]==accepted<2 and item["attempt"]==number
            and 1<=item["prompt_tokens"]<=512 and cap>0 and item["max_new_tokens"]==cap
            and 1<=item["generated_tokens"]<=cap and type(item["accepted"]) is bool
            and 0<=item["text_bytes"]<=1048576 and type(item["text_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}",item["text_sha256"]),"attempt budget/order/digest changed")
        total+=item["generated_tokens"];maximum=max(maximum,item["prompt_tokens"])
        if item["accepted"]:
            require(item["rejection_code"] is None and item["generated_tokens"]<cap
                and item["stop_reason"] in ("question_boundary","eos") and 1<=item["text_bytes"]<=512,
                "accepted an incomplete or invalid planner attempt")
            if questions is not None:
                require(accepted<len(questions),"extra accepted question")
                text=questions[accepted]
                require(item["text_bytes"]==len(text.encode()) and item["text_sha256"]==sha(text.encode())
                    and (item["stop_reason"]!="question_boundary" or text.rstrip().endswith("?")),
                    "accepted question text differs from original model artifact")
            stats.append({k:item[k] for k in ("prompt_tokens","generated_tokens","stop_reason")});accepted+=1
        elif item["rejection_code"]=="GENERATION_LIMIT":
            require(item["generated_tokens"]==cap and item["stop_reason"]=="token_limit","uncharged generation limit")
        else:
            require(item["rejection_code"] in ("EMPTY_TEXT","TEXT_TOO_LONG","NUL_TEXT","DUPLICATE_TEXT")
                and item["generated_tokens"]<cap and item["stop_reason"] in ("question_boundary","eos")
                and (item["stop_reason"]!="question_boundary" or item["rejection_code"]=="DUPLICATE_TEXT"),"invalid rejection category")
            if item["rejection_code"]=="TEXT_TOO_LONG":require(item["text_bytes"]>512,"wrong long-text rejection")
            elif item["rejection_code"]=="EMPTY_TEXT":
                require(item["text_bytes"]<=512,"wrong empty-text rejection bound")
                if item["text_bytes"]==0:require(item["text_sha256"]==sha(b""),"wrong empty-text digest")
            else:
                require(1<=item["text_bytes"]<=512,"wrong bounded-text rejection")
                if item["rejection_code"]=="DUPLICATE_TEXT":require(accepted==1,"first question cannot duplicate an accepted question")
    return accepted,total,maximum,stats


def validate_failure(value,input_raw,source):
    expected=dict(version=1,visibility="public",license="GPL-3.0-only",question=QUESTION,source_sha256=sha(source),source_bytes=len(source))
    require(strict_json(input_raw)==expected and input_raw==encoded(expected),"failure input/source changed")
    require(type(value) is dict and value.keys()=={"version","operation","request_id","code","input_sha256",
        "source_sha256","source_bytes","planner_diagnostic","child_reaped","plan_enrolled"}
        and type(value["version"]) is int and value["version"]==1 and value["operation"]=="compute_public_task_planning_failure"
        and type(value["request_id"]) is str and re.fullmatch(r"[0-9a-f]{32}",value["request_id"])
        and type(value["code"]) is str and re.fullmatch(r"[A-Z_]{1,64}",value["code"])
        and value["input_sha256"]==sha(input_raw) and value["source_sha256"]==sha(source)
        and type(value["source_bytes"]) is int and value["source_bytes"]==len(source)
        and value["child_reaped"] is True and value["plan_enrolled"] is False,"uncorrelated or unsafe planner failure metadata")
    diagnostic=value["planner_diagnostic"]
    require(type(diagnostic) is dict and diagnostic.keys()=={"strategy","attempts","incomplete_attempt"}
        and diagnostic["strategy"]==STRATEGY and type(diagnostic["incomplete_attempt"]) is bool,"invalid planner failure diagnostic")
    accepted,total,_,_=check_attempts(diagnostic["attempts"])
    # Accepted questions do not enroll a plan: later model-integrity or artifact
    # I/O checks can still fail. Only an incomplete generation needs another slot.
    require(accepted<=2 and total<=384,"failure exceeds planning budget")
    if diagnostic["incomplete_attempt"]:
        require(accepted<2 and len(diagnostic["attempts"])<4 and total<384,"incomplete attempt was outside original budget")


def check_planning(raw,source):
    load=lambda name:strict_json(raw[name])
    expected=dict(version=1,visibility="public",license="GPL-3.0-only",question=QUESTION,source_sha256=sha(source),source_bytes=len(source))
    require(load("planner-input.json")==expected and raw["planner-input.json"]==encoded(expected),"planner input is not exact goal-only selection")
    require(raw["planner-artifact.json"]==raw["model-planner/task-questions.json"],"original model questions replaced")
    plan=questions_plan(raw["planner-artifact.json"])
    require(load("graph-plan.json")==plan and raw["graph-plan.json"]==encoded(plan),"graph was not derived exactly from actual questions")
    report=load("planner-report.json")
    require(report["mode"]=="plan_tasks" and report["version"]==1 and report["status"]=="ok" and report["kind"]=="result"
        and report["device"]=="cpu" and report["threads"]==2 and report["updates_completed"]==0
        and report["backend_versions"]=={"torch":"2.14.0+cpu","transformers":"5.16.1","peft":"0.20.0"}
        and report["model"]["id"]==DOC["MODEL"] and report["model"]["revision"]==MODEL_ID["model_revision"]
        and report["model"]["files"]["model.safetensors"]==MODEL_ID["base_weights"]
        and report["model_weights_loaded"] is report["goal_only_planning"] is report["base_weights_unchanged"] is True
        and report["base_before"]==report["base_after"] and report["base_before"]["parameters"]>0
        and re.fullmatch(r"[0-9a-f]{64}",report["base_before"]["sha256"])
        and report["generation_limit_reached"] is report["model_answer_correctness_proven"] is False
        and report["planner_stop_reason"]=="two_questions"
        and report["planner_strategy"]==STRATEGY
        and report["planner_structure_generated_by"]=="local_schema"
        and type(report["planner_prompt_tokens"]) is int and 1<=report["planner_prompt_tokens"]<=512
        and type(report["planner_generated_tokens"]) is int and 1<=report["planner_generated_tokens"]<384
        and all(k not in report for k in ("outputs","baseline_evaluation","input_adapter")),"not an actual bounded pinned-model planner result")
    questions=strict_json(raw["planner-artifact.json"])["questions"]
    require(len(questions)==2,"two model-generated questions required")
    accepted,total,maximum,stats=check_attempts(report["planner_attempts"],questions)
    require(accepted==2 and report["planner_question_stats"]==stats and report["planner_prompt_tokens"]==maximum
        and report["planner_generated_tokens"]==total<384,"planner aggregate budget or accepted stages differ")
    require(report["dataset"]==dict(version=1,sha256=sha(raw["planner-input.json"]),bytes=len(raw["planner-input.json"]),
        visibility="public",license="GPL-3.0-only",question_sha256=sha(QUESTION.encode()),source_sha256=sha(source),source_bytes=len(source))
        and report["artifacts"]==[dict(relative_path="task-questions.json",bytes=len(raw["planner-artifact.json"]),sha256=sha(raw["planner-artifact.json"]))]
        and load("model-planner/report.json").items()<=report.items(),"planner report/artifact not tied to exact goal and source")
    DOC["check_supervisor"](report)
    authority=dict(version=1,input_sha256=sha(raw["planner-input.json"]),report_sha256=sha(raw["planner-report.json"]),
        artifact_sha256=sha(raw["planner-artifact.json"]),question=QUESTION,source_sha256=sha(source),source_bytes=len(source))
    require(load("graph.json")["planner"]==authority,"planner authority was not pinned before graph enrollment")
    summary=dict(kind="bounded_model_fork_join_decomposition",authority=authority,goal_only=True,
        source_contents_read_by_planner=False,model_selected_tools=False,decomposition_quality_proven=False)
    return plan,summary


def reduction(raw,prefix,parents,question,authority,source_manifest,layout,executed,response_bytes,node_index,force):
    load=lambda name:json.loads(raw[name]);result=load(prefix+"/result.json");levels=result["synthesis"]["levels"]
    require((1 if force or len(parents)>1 else 0)<=len(levels)<=16,"derived instruction or reduction was omitted")
    rounds=0
    for number,level in enumerate(levels,1):
        require(level["level"]==number and level["complete"] is True and level["parents"]==len(parents)
            and len(level["groups"])==(len(parents)+63)//64,"model-derived stage omitted original parents")
        following=[]
        for group_index,group in enumerate(level["groups"]):
            group_prefix=prefix+f"/synthesis/level-{number:02d}-group-{group_index:04d}"
            previous=parents[group_index*64:group_index*64+64]
            require(raw[group_prefix+"/parents.json"]==encoded(previous),"generated parent results changed")
            saved=load(group_prefix+"/group.json")
            require(saved["version"]==1 and saved["level"]==number and saved["parent_offset"]==group_index*64
                and saved["parents_sha256"]==sha(encoded(previous)) and saved["source_manifest_id"]==authority["source_manifest_id"]
                and authority["selected_at_unix_seconds"]<=saved["created_at_unix_seconds"]<authority["expires_at_unix_seconds"],"model-derived publication renewed source authority")
            combined,rows=SYNTH["expected_rows"](previous,load(group_prefix+"/document-plan.json")["parts"],question,group_index*64)
            GRAPH["planner"](raw,group_prefix+"/",combined,question,True)
            require(group==dict(group=group_index,parents=len(previous),complete=True,parts=len(rows),input_sha256=sha(combined)),"derived group accounting changed")
            for p in range((len(rows)+3)//4):
                package=group_prefix+f"/package-{p:04d}"
                data=dict(version=3,visibility="public",license="GPL-3.0-only",source_manifest_hex=source_manifest.hex(),
                    level=number,claim_scope=SYNTH["CLAIM"],inference=rows[p*4:p*4+4])
                original=dict(authority,selected_at_unix_seconds=saved["created_at_unix_seconds"])
                identity=GRAPH["manifest"](raw[package+"/dataset.manifest"],raw[package+"/dataset.json"],original,
                    f"derived-l{number:02d}-g{group_index:04d}-p{p:04d}",SYNTH["PROFILE"])
                following.extend(GRAPH["package"](raw,package,data,identity,authority,question,layout,executed,response_bytes,node_index,number,len(rows)>4))
                rounds+=1
        require(level["outputs"]==len(following) and ((force and number==1) or len(following)<len(parents))
            and level["answers"]==following and level["generation_limit_reached"] is any(a["generated_tokens"]==64 for a in following)
            and load(prefix+f"/synthesis/level-{number:02d}-result.json")==level,"derived results or reduction changed")
        parents=following
    require(len(parents)==1 and result["complete"] is True and result["synthesized_answer"]==parents[0]
        and result["synthesis"]["complete"] is True and result["synthesis"]["claim_scope"]==SYNTH["CLAIM"]
        and result["synthesis"]["model_answer_correctness_proven"] is False
        and result["synthesis"]["semantic_completeness_proven"] is False,"node final result or scope changed")
    return parents[0],rounds


def check(value,revision):
    require(value["source_revision"]==revision,"wrong model-planning revision")
    provision=value["provision"]
    require(provision["success"] is True and provision["installed_wheels"]==38 and provision["download_bytes"]==523040250
        and provision["training_performed"] is False,"unverified model provision")
    saved=value["result-files"]["snapshot"];raw={n:bytes.fromhex(v) for n,v in value["result-files"]["raw"].items()}
    require(set(saved)==set(raw) and sum(map(len,raw.values()))<=32*1048576
        and all(saved[n]["bytes"]==len(b) and saved[n]["sha256"]==sha(b) for n,b in raw.items()),"retained planning-file hashes differ")
    initial=value["enrolled-files"]
    require(all(saved.get(n)==v and raw[n].hex()==initial["raw"][n] for n,v in initial["snapshot"].items())
        and not any(HANDLE.fullmatch(n) or "/work/" in n or "/synthesis/" in n for n in initial["snapshot"]),"enrolled planner/source files changed or already admitted peers")
    original=value["input"];source=bytes.fromhex(original["excerpt_hex"])
    require(original["source"]=="README.md" and original["question"]==QUESTION and original["supplied_task_plan"] is False
        and 124<=len(source)<=128 and original["excerpt_bytes"]==len(source) and original["excerpt_sha256"]==sha(source),"not exact public source/goal selection")
    plan,planning=check_planning(raw,source);count=len(plan["nodes"])-1;load=lambda name:json.loads(raw[name])
    graph=load("graph.json")
    require(graph["version"]==1 and graph["plan_sha256"]==sha(encoded(plan)) and graph["leaves"]==[
        dict(node=i,enrollment_sha256=sha(raw[f"node-{i:04d}/document.json"])) for i in range(count)],"model-plan leaf pins changed")
    observed=value["planner-observation"];TRAIN["check_isolation"](observed["isolation"])
    require(observed["node_lineage"]["node"]=="client" and observed["node_lineage"]["cli"]==observed["isolation"]["cli"]
        and observed["node_lineage"]["cli_namespace"]==observed["node_lineage"]["service_namespace"]
        and observed["node_lineage"]["worker_network_namespace"]!=observed["node_lineage"]["cli_namespace"]
        and observed["node_lineage"]["worker_network_namespace"]==observed["isolation"]["namespaces"]["net"]
        and observed["dataset_file"]=={k:saved["planner-input.json"][k] for k in ("bytes","sha256")}
        and observed["dataset_inode"]==saved["planner-input.json"]["inode"]
        and observed["model_inode"]==original["owner_model_inode"]
        and observed["runtime_lock_held"] is observed["alive_before_and_after"] is True,"actual owner planner lineage/input missing")
    JOBS["check_overlap"](value["overlap"]);layout=value["layout"];workers={w["node"]:w for w in value["overlap"]["workers"]}
    require(set(workers)==set(layout["provider_nodes"]) and all(CUSTODY["peer_key"](value["peers"][n])==k for n,k in layout["provider_keys"].items())
        and layout["control_relay_peer_id"] not in {value["peers"][n] for n in workers}
        and original["private_copies_no_hardlinks"] is True and original["owner_model_inode"]!=original["peer_model_inode"]
        and all(w["input_inodes"]["model/model.safetensors"]==original["peer_model_inode"] for w in workers.values()),"planner/peer model copies or isolation differ")
    authority=load("node-0000/document.json");source_manifest=raw["node-0000/source.manifest"]
    source_id=GRAPH["manifest"](source_manifest,source,authority,"document-source","text/plain")
    require(source_id==authority["source_manifest_id"] and authority["expires_at_unix_seconds"]-authority["selected_at_unix_seconds"]==7200,"shared original source authority changed")
    DOC["selected_providers"](authority,layout)
    enrollment=value["enrollment"]
    require(enrollment["operation"]=="compute_graph_enrolled" and enrollment["execution_started"] is True
        and enrollment["model_planning_performed"] is enrollment["automatic_task_planning"] is True
        and enrollment["peer_execution_started"] is enrollment["task_complete"] is enrollment["private_data_supported"] is False
        and enrollment["nodes"]==count+1 and enrollment["source_tasks"]==count and enrollment["plan_sha256"]==sha(encoded(plan))
        and enrollment["source_manifest_id"]==source_id and enrollment["provider_keys"]==authority["provider_keys"]
        and enrollment["planning"]==planning,"enrollment did not distinguish real planning from pending peer work")
    executed,response_bytes,answers,rounds={},dict.fromkeys(workers,0),{},0
    for index,node in enumerate(plan["nodes"][:-1]):
        prefix=f"node-{index:04d}";enrolled=load(prefix+"/document.json");question=node["question"]
        tokenized=GRAPH["planner"](raw,prefix+"/",source,question)
        require(raw[prefix+"/source.txt"]==source and raw[prefix+"/source.manifest"]==source_manifest
            and enrolled["scheduling"]=="ready_rows_v1" and enrolled["synthesize"] is True
            and enrolled["source_sha256"]==sha(source) and enrolled["source_bytes"]==len(source)
            and enrolled["plan_sha256"]==sha(raw[prefix+"/document-plan.json"]) and enrolled["public_question"]==question
            and enrolled["license"]=="GPL-3.0-only" and enrolled["publisher_key"]==value["publish"]["publisher_key_hex"]
            and all(enrolled.get(k)==authority.get(k) for k in ("publisher_key","provider_keys","source_manifest_id","model_fingerprint",
                "selected_at_unix_seconds","expires_at_unix_seconds")) and len(enrolled["packages"])==(len(tokenized["parts"])+3)//4,"model leaf task/source changed")
        parents=[]
        for p,selection in enumerate(enrolled["packages"]):
            package=prefix+f"/package-{p:04d}";parts=tokenized["parts"][p*4:p*4+4]
            data=dict(version=2,visibility="public",license="GPL-3.0-only",source_manifest_hex=source_manifest.hex(),
                inference=[dict(question=question,context=source[v["start"]:v["end"]].decode(),start=v["start"],end=v["end"]) for v in parts])
            identity=GRAPH["manifest"](raw[package+"/dataset.manifest"],raw[package+"/dataset.json"],enrolled,f"document-package-{p:04d}",DOC["PROFILE"])
            require(selection==dict(manifest_id=identity,dataset_sha256=sha(encoded(data)),first_part=p*4,rows=len(parts)),"leaf package mapping changed")
            parents.extend(GRAPH["package"](raw,package,data,identity,enrolled,question,layout,executed,response_bytes,index,0,True));rounds+=1
        answer,used=reduction(raw,prefix,parents,question,authority,source_manifest,layout,executed,response_bytes,index,False)
        rounds+=used;answers[node["id"]]=answer
        require(load(prefix+"/result.json")["graph_node"]==dict(node,plan_sha256=sha(encoded(plan))),"leaf graph identity changed")
    node=plan["nodes"][-1];prefix=f"node-{count:04d}";joined=load(prefix+"/result.json")
    require(raw[prefix+"/source.manifest"]==source_manifest and joined["operation"]=="compute_graph_dependency"
        and joined["public_question"]==QUESTION and joined["source_manifest_id"]==source_id
        and joined["graph_node"]==dict(node,plan_sha256=sha(encoded(plan))),"join substituted original question/source")
    answer,used=reduction(raw,prefix,[answers[n] for n in node["depends_on"]],QUESTION,authority,source_manifest,layout,executed,response_bytes,count,True)
    rounds+=used;answers["answer"]=answer
    require(count+1<=rounds<=16 and len({a["job_id"] for a in answers.values()})==count+1,"model join reused a source task")
    for phase,used in (("result",rounds),("resume",0)):
        result=value[phase]
        require(result["operation"]=="compute_public_task_graph" and result["complete"] is True
            and result["plan"]==plan and result["plan_sha256"]==sha(encoded(plan)) and result["source_manifest_id"]==source_id
            and result["source_expires_unix_seconds"]==authority["expires_at_unix_seconds"] and result["provider_keys"]==authority["provider_keys"]
            and result["rounds_this_invocation"]==used and result["interrupted"] is False and result["planning"]==planning
            and result["automatic_task_planning"] is True and result["output"]==answers["answer"] and len(result["nodes"])==count+1
            and all(result[k] is False for k in ("private_data_supported","external_actions_supported","model_answer_correctness_proven","full_b03_claimed")),"planned graph completion/scope changed")
        require(result["nodes"]==[dict(n,complete=True,status="complete",answer=answers[n["id"]]) for n in plan["nodes"]],"planned graph answers changed")
    require(load("result.json")==value["result"] and {n for n in raw if HANDLE.fullmatch(n)}=={v["path"] for v in executed.values()},"extra/unverified planned jobs or replaced completed summary")
    seen,processes=set(),[observed["isolation"]["worker"]]
    require(value["observation"]["owner_reaped"] is True,"peer owner not reaped")
    for item in value["observation"]["workers"]:
        handle,worker=item["handle"],item["worker"];identifier=handle["binding"]["job_id"]
        require(identifier in executed and identifier not in seen,"unknown/duplicate model-derived worker")
        actual=executed[identifier];base=workers[actual["node"]]
        require(item["graph_node"]==actual["graph_node"] and item["level"]==actual["level"] and handle==actual["handle"]
            and item["handle_path"]==actual["path"] and item["handle_file"]=={k:saved[actual["path"]][k] for k in ("bytes","sha256")}
            and worker["dataset_json"].encode()==actual["raw"] and worker["dataset_file"]["sha256"]==sha(actual["raw"])
            and all(worker[k]==base[k] for k in ("node","broker","service","node_namespace","runtime_lock_inode"))
            and worker["worker"] not in processes and item["alive_before_and_after"] is True
            and item["first_monotonic_ns"]<item["last_monotonic_ns"],"actual model-derived input/process lineage missing")
        require(worker["runtime_lock_held"] is True and worker["network_devices"]==["lo"] and worker["ipv4_routes"]==[]
            and worker["effective_capabilities"]==0 and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][p] for p in ("/runtime","/model","/dataset.json"))
            and all(worker["worker_namespaces"][k]!=worker["guest_namespaces"][k] for k in ("net","pid","ipc","mnt"))
            and worker["worker_namespaces"]["net"]!=worker["node_namespace"],"actual worker isolation missing")
        seen.add(identifier);processes.append(worker["worker"])
    require(seen==set(executed),"not every model-derived real peer job observed")
    require(value["input-removed"]["original_input_absent"] is value["input-removed"]["retained_model_plan"] is True
        and value["input-removed"]["supplied_task_plan"] is False
        and all(value[phase][k] is True for phase in ("stopped","resumed") for k in ("all_owned_processes_ended","brokers_stopped","original_input_absent"))
        and value["resumed"]["snapshot"]==saved,"offline original-free unchanged planning history unproven")
    CUSTODY["validate_path"](value["path"],value["peers"],layout,"inspect")
    application=value["path"]["privacy"]["exit"]["provider_application"]
    require(all(application[n]["request_packets"]>0 and application[n]["response_payload_bytes"]>=size for n,size in response_bytes.items())
        and all(value["cleanup"].values()),"protected complete reports or full cleanup missing")


def evidence(work,revision):
    JOBS["guest_work"](work)
    value={name:read(record(work,name),64*1048576) for name in ("input","planner-observation","enrollment","enrolled-files",
        "observation","result","result-files","resume","input-removed","stopped","resumed")}
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
        observed_blocker=None if blocker=="NONE" else blocker,evidence=value,cleanup=dict(complete=complete,remaining_owned_objects=remaining),
        host_state=host,decomposition_quality_proven=False,model_answer_correctness_proven=False,full_b03_claimed=False,full_alpha_claimed=False))


def report(value,revision):
    require(value["report_kind"]==KIND and value["source_revision"]==revision and value["scope"]==SCOPE
        and value["success"] is True and value["runner_exit_status"]==0 and value["observed_blocker"] is None
        and value["cleanup"]==dict(complete=True,remaining_owned_objects=0) and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"]==value["host_state"]["after_sha256"]
        and all(value[k] is False for k in ("decomposition_quality_proven","model_answer_correctness_proven","full_b03_claimed","full_alpha_claimed")),
        "model planning/host cleanup proof incomplete")
    check(value["evidence"],revision)


def self_test():
    # Inert schema/graph reconstruction only, not fabricated model or peer execution.
    for count in (2,3,4):
        questions=[f"Inert question {n}?" for n in range(count)]
        plan=questions_plan(encoded(dict(version=1,questions=questions)))
        assert len(plan["nodes"])==count+1 and [n["question"] for n in plan["nodes"][:-1]]==questions
        assert plan["nodes"][-1]==dict(id="answer",question=QUESTION,depends_on=[f"question-{n:02d}" for n in range(count)])
    for raw in (b'{"version":1,"version":1,"questions":["A?","B?"]}',
                b'{"version":1,"questions":["A?"," A? "]}',b'{"version":true,"questions":["A?","B?"]}',
                b'{"version":1,"questions":["A?"]}',b'{"version":1,"questions":["A?","B?"],"tools":[]}',
                b'```json\n{"version":1,"questions":["A?","B?"]}\n```',
                b'{"version":1,"questions":["A?","B?"]} trailing'):
        try:questions_plan(raw)
        except (ValueError,KeyError):pass
        else:raise AssertionError("invalid/canned/extracted model question shape accepted")
    # Synthetic accounting only: rejected output consumes the same token budget.
    questions=["Inert first question?","Inert second question?"]
    def attempt(index,number,text,tokens,accepted=True,code=None,stop="question_boundary",cap=192):
        return dict(question_index=index,attempt=number,prompt_tokens=80+number,generated_tokens=tokens,max_new_tokens=cap,
            stop_reason=stop,accepted=accepted,rejection_code=code,text_bytes=len(text.encode()),text_sha256=sha(text.encode()))
    attempts=[attempt(0,1,questions[0],20),attempt(1,2,questions[0],18,False,"DUPLICATE_TEXT"),
        attempt(1,3,questions[1],25)]
    accepted,total,maximum,stats=check_attempts(attempts,questions)
    assert (accepted,total,maximum)==(2,63,83) and stats==[{k:attempts[i][k] for k in
        ("prompt_tokens","generated_tokens","stop_reason")} for i in (0,2)]
    # A fully charged rejected attempt leaves a smaller exact allowance later.
    limited=[attempt(0,1,"x",192,False,"GENERATION_LIMIT","token_limit"),
        attempt(0,2,questions[0],20),attempt(1,3,questions[1],25,cap=172)]
    assert check_attempts(limited,questions)[:3]==(2,237,83)
    mutations=(
        lambda a:a[1].update(attempt=1),lambda a:a[1].update(question_index=0),
        lambda a:a[1].update(accepted=True,rejection_code=None),lambda a:a[2].update(text_sha256="0"*64),
        lambda a:a[2].update(text_bytes=1),lambda a:a[0].update(max_new_tokens=191),
        lambda a:a[0].update(generated_tokens=192),lambda a:a[0].update(accepted=1),
        lambda a:a[0].update(prompt_tokens=True),lambda a:a[1].update(rejection_code="NUL_TEXT"),
        lambda a:a[1].update(rejection_code="TEXT_TOO_LONG",stop_reason="eos"),
        lambda a:a[1].update(rejection_code="GENERATION_LIMIT",stop_reason="token_limit"),
        lambda a:a[0].update(rejection_code="DUPLICATE_TEXT",accepted=False),
        lambda a:a[0].update(raw_text="forbidden diagnostic text"))
    for mutate in mutations:
        invalid=copy.deepcopy(attempts);mutate(invalid)
        try:check_attempts(invalid,questions)
        except (ValueError,KeyError):pass
        else:raise AssertionError("invalid recovery attempt metadata accepted")
    input_raw=encoded(dict(version=1,visibility="public",license="GPL-3.0-only",question=QUESTION,source_sha256=sha(b"public"),source_bytes=6))
    failure=dict(version=1,operation="compute_public_task_planning_failure",request_id="a"*32,
        code="TASK_PLAN_GENERATION_LIMIT_REACHED",input_sha256=sha(input_raw),source_sha256=sha(b"public"),source_bytes=6,
        planner_diagnostic=dict(strategy=STRATEGY,attempts=[attempt(0,1,"x",192,False,"GENERATION_LIMIT","token_limit"),
            attempt(0,2,"y",192,False,"GENERATION_LIMIT","token_limit")],incomplete_attempt=False),
        child_reaped=True,plan_enrolled=False)
    validate_failure(failure,input_raw,b"public")
    after_generation=copy.deepcopy(failure)
    after_generation["code"]="BASE_WEIGHTS_CHANGED"
    after_generation["planner_diagnostic"]["attempts"]=attempts
    validate_failure(after_generation,input_raw,b"public")
    failure_mutations=(lambda f:f.update(child_reaped=False),lambda f:f.update(plan_enrolled=True),
        lambda f:f.update(input_sha256="b"*64),lambda f:f.update(source_bytes=7),
        lambda f:f.update(request_id="BAD"),lambda f:f.update(code="raw failed text"),
        lambda f:f["planner_diagnostic"].update(incomplete_attempt=True),
        lambda f:f["planner_diagnostic"].update(raw_text="not exported"),
        lambda f:f["planner_diagnostic"].update(attempts=attempts,incomplete_attempt=True))
    for mutate in failure_mutations:
        invalid=copy.deepcopy(failure);mutate(invalid)
        try:validate_failure(invalid,input_raw,b"public")
        except (ValueError,KeyError):pass
        else:raise AssertionError("invalid/non-reaped planner failure accepted")
    print("model-planning proposal, recovery accounting and failure export controls PASS; no tokenizer/model/network executed")


def main(args):
    command=args[0]
    if command=="self-test":self_test()
    elif command=="prepare":prepare(Path(args[1]))
    elif command=="observe-planner":observe_planner(Path(args[1]),int(args[2]))
    elif command=="observe-peers":observe_peers(Path(args[1]),int(args[2]))
    elif command=="collect":collect(Path(args[1]),args[2])
    elif command=="collect-failure":collect_failure(Path(args[1]))
    elif command=="remove-input":remove_input(Path(args[1]))
    elif command=="stopped":stopped(Path(args[1]))
    elif command=="resumed":stopped(Path(args[1]),True)
    elif command=="evidence":evidence(Path(args[1]),args[2])
    elif command=="finalize":finalize(Path(args[1]),args[2],int(args[3]),args[4]=="true",int(args[5]),args[6],args[7])
    elif command=="report":report(read(Path(args[1]),64*1048576),args[2])
    else:raise ValueError("unknown fixed model-planning fixture command")


if __name__=="__main__":
    main(sys.argv[1:])
