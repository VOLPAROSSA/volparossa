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
ATTEMPT = GRAPH["ATTEMPT"]
MODEL_PROFILE = "smollm2-360m-v1"
SELECTED_MODEL = TRAIN["inference_profile"](MODEL_PROFILE)
MODEL, MODEL_ID = SELECTED_MODEL["fingerprint"], SELECTED_MODEL["model"]
PREFIX = "agent-model-planning"
STRATEGY = "model_questions_source_recovery_v4"
DECODER = {"implementation": "lm-format-enforcer", "version": "0.11.3", "adapter_version": 1,
           "schema_version": 3, "dependencies": {"interegular": "0.3.3", "pydantic": "1.10.24"}}
QUESTION = "What requirements and risks does this project describe?"
PLAN_REQUIREMENT = "dependent_analysis_v1"
GRAPH_QUESTION = "Which route meets the stated privacy constraints, why, and what further evidence is needed before comparing performance?"
GRAPH_SOURCE = (b"Synthetic public routing case.\n"
    b"Required path: client -> one relay -> exit -> destination.\n"
    b"A relay may know the client and exit, but not the Internet destination.\n"
    b"An exit may know the destination and relay, but not the client's public address.\n"
    b"Route A uses client -> relay -> exit -> destination.\n"
    b"Route B uses client -> exit -> destination; the exit sees the client's public address.\n"
    b"No throughput, latency or failure measurements are provided.\n")
KIND = "volparossa-bounded-model-public-task-planning"
SCOPE = ("One actual isolated pinned SmolLM2-360M owner generates two public subquestions from a goal and "
    "an exact bounded public source prefix, "
    "with only their JSON structure supplied locally and at most four charged attempts within 384 generated tokens, "
    "without silently trimming or repairing model output. The exact proposal is enrolled against one signed "
    "complete public README introduction, then actual protected peers execute its source questions and an exact original-question join. "
    "Every peer execution and the separate owner planner are observed. Original-free completed offline "
    "resume neither replans nor changes retained graph, planner or receipts. Not decomposition/answer "
    "quality, semantic completeness, private offload, model-selected tools, open-ended autonomy, full B03 or full alpha.")
HANDLE = GRAPH["HANDLE"]
TASK_GRAPH = False


def select_task_graph():
    global TASK_GRAPH, PREFIX, STRATEGY, KIND, SCOPE, QUESTION
    TASK_GRAPH = True
    PREFIX = "agent-model-task-graph"
    STRATEGY = "model_task_graph_constrained_v2"
    QUESTION = GRAPH_QUESTION
    KIND = "volparossa-bounded-model-selected-dependent-public-task-graph"
    SCOPE = ("One actual isolated pinned SmolLM2-360M owner generates an exact raw public task graph from "
        "a synthetic public routing case with explicit privacy facts and absent performance measurements, "
        "under the explicit dependent_analysis_v1 requirement, choosing at least two tasks and one internal dependency "
        "within four attempts and 384 total generated tokens, with pinned JSON-constrained decoding. "
        "Local translation adds only stable IDs and an exact "
        "original-question terminal join over model-selected sinks. Actual protected peer jobs consume EOS-complete "
        "parents bound byte-for-byte to their original receipts; original-free completed offline resume preserves planner and receipts. "
        "This is a new fixture contract, not a reinterpretation of historical failed runs. No required parallel shape, "
        "simultaneous-worker claim, task repair, canned fallback, semantic quality, private offload, model-selected tools, "
        "open-ended autonomy, full B03 or full alpha.")


def root_path(work):
    return work / "state-client/compute-source/model-planning"


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def public_intro(original):
    marker=b"[Network]("
    end=original.find(marker)
    require(0<end<=1024 and original.startswith(b"# VOLPAROSSA\n")
        and original[:end].endswith(b"\n\n"),"complete bounded README introduction missing")
    excerpt=original[:end]
    require(excerpt.decode("utf-8").encode()==excerpt and b"\0" not in excerpt,
        "README introduction is not exact public UTF-8")
    return excerpt


def planning_input(source):
    text=source[:1024].decode("utf-8",errors="ignore")
    prefix=text.encode()
    require(source.decode("utf-8").encode()==source and 1<=len(source)<=1048576
        and prefix and b"\0" not in prefix,"invalid original public planner source")
    selected=dict(version=3 if TASK_GRAPH else 2,model_profile=MODEL_PROFILE,visibility="public",license="GPL-3.0-only",question=QUESTION,
        source_sha256=sha(source),source_bytes=len(source),
        source_excerpt=dict(start=0,end=len(prefix),text=text,sha256=sha(prefix)))
    if TASK_GRAPH:selected["plan_requirement"]=PLAN_REQUIREMENT
    return selected


def check_public_input(original,source):
    require(original["question"]==QUESTION and original["supplied_task_plan"] is False
        and 1<=len(source)<=1024 and original["excerpt_bytes"]==len(source)
        and original["excerpt_sha256"]==sha(source)
        and original["excerpt_range"]==dict(start=0,end=len(source)),"public source/goal selection changed")
    if TASK_GRAPH:
        require(source==GRAPH_SOURCE and original["source"]=="synthetic-public-routing-case-v1"
            and original["fixture_contract"]==PLAN_REQUIREMENT and original["synthetic_test_data"] is True
            and original["original_source_sha256"]==sha(GRAPH_SOURCE)
            and original["excerpt_selection"]=="complete_synthetic_public_routing_case",
            "not the explicit complete synthetic dependent-analysis case")
    else:
        require(original["source"]=="README.md"
            and original["excerpt_selection"]=="complete_intro_before_network_navigation"
            and public_intro(source+b"[Network](")==source,"not exact complete public introduction/goal selection")


def prepare(work):
    require(TRAIN["socket"].gethostname() == "volparossa-alpha"
        and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
        and os.geteuid() != 0 and work.parent == Path("/opt") and work.name.startswith("va.")
        and not work.is_symlink() and HERE == work / "bin", "wrong installed guest model-planning helper")
    installed=(Path(__file__),) if TASK_GRAPH else (Path(__file__), HERE / "model-planning-source-README.md")
    for path in installed:
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o222,
            "planner helper/source not root-installed read-only")
    source=JOBS["private"](work / "state-client/compute-source", "compute-source")
    original=GRAPH_SOURCE if TASK_GRAPH else (HERE / "model-planning-source-README.md").read_bytes()
    excerpt=original if TASK_GRAPH else public_intro(original)
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
        and JOBS["file_hash"](owner,MODEL_ID["base_weights"]["bytes"])==MODEL_ID["base_weights"],"planner is not an independent pinned copy")
    selected=dict(source="README.md", original_repository_sha256=sha(original),
        excerpt_hex=excerpt.hex(), excerpt_sha256=sha(excerpt), excerpt_bytes=len(excerpt), question=QUESTION,
        excerpt_range=dict(start=0,end=len(excerpt)),excerpt_selection="complete_intro_before_network_navigation",
        input_inode=[path.stat().st_dev,path.stat().st_ino], owner_model_inode=[own.st_dev,own.st_ino],
        peer_model_inode=[remote.st_dev,remote.st_ino], private_copies_no_hardlinks=True, supplied_task_plan=False)
    if TASK_GRAPH:
        del selected["original_repository_sha256"]
        selected.update(source="synthetic-public-routing-case-v1",original_source_sha256=sha(original),
            fixture_contract=PLAN_REQUIREMENT,synthetic_test_data=True,
            excerpt_selection="complete_synthetic_public_routing_case")
    check_public_input(selected,excerpt)
    print(json.dumps(selected))


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
        if not overlap and not TASK_GRAPH:
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
        if TASK_GRAPH and observed:
            # All actually observed workers are retained for ordinary cleanup;
            # serial graphs do not assert simultaneous independent execution.
            write(work/"agent-jobs-observation.json",dict(workers=[w["worker"] for w in observed],
                simultaneous_execution_claimed=False))
        time.sleep(0.025)
    require(not JOBS["alive"](owner) and (overlap or TASK_GRAPH) and {w["graph_node"] for w in observed}==set(range(leaf_count+1)),
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
        and value["version"]==2 and type(value["questions"]) is list and 2<=len(value["questions"])<=4,"wrong model question artifact")
    seen=set()
    for question in value["questions"]:
        require(type(question) is str and 1<=len(question.encode())<=512 and "\0" not in question
            and question.rstrip().endswith("?") and question.strip() not in seen
            and question.encode()!=QUESTION.encode(),"invalid/non-distinct or exact goal-copy model-generated question")
        seen.add(question.strip())
    nodes=[dict(id=f"question-{index:02d}",question=q,depends_on=[]) for index,q in enumerate(value["questions"])]
    nodes.append(dict(id="answer",question=QUESTION,depends_on=[n["id"] for n in nodes]))
    return dict(version=1,nodes=nodes,output="answer")


def model_graph_plan(artifact,require_edge=True):
    require(0<len(artifact)<=16384,"model graph artifact bound")
    value=strict_json(artifact)
    require(type(value) is dict and value.keys()=={"version","tasks"} and type(value["version"]) is int
        and value["version"]==3 and type(value["tasks"]) is list and 1<=len(value["tasks"])<=4,"model graph schema")
    seen,consumed,nodes=set(),set(),[]
    for index,task in enumerate(value["tasks"]):
        require(type(task) is dict and task.keys()=={"question","depends_on"},"model task fields")
        question=task["question"];deps=task["depends_on"]
        require(type(question) is str and 1<=len(question.encode())<=512 and "\0" not in question
            and question.rstrip().endswith("?") and question.strip() not in seen
            and question.encode()!=QUESTION.encode(),"model graph question invalid/duplicate/goal-copy")
        require(type(deps) is list and all(type(n) is int and 0<=n<index for n in deps)
            and len(set(deps))==len(deps),"model graph dependencies invalid")
        seen.add(question.strip());consumed.update(deps)
        nodes.append(dict(id=f"question-{index:02d}",question=question,depends_on=[f"question-{n:02d}" for n in deps]))
    if require_edge:
        require(len(nodes)>=2 and consumed,"model selected no internal dependency; valid product shape is not this graph proof")
    nodes.append(dict(id="answer",question=QUESTION,
        depends_on=[node["id"] for index,node in enumerate(nodes) if index not in consumed]))
    return dict(version=1,nodes=nodes,output="answer")


def check_graph_attempts(attempts,artifact=None):
    require(type(attempts) is list and len(attempts)<=4,"graph attempt bound")
    accepted,total,maximum=0,0,0
    for number,item in enumerate(attempts,1):
        require(type(item) is dict and item.keys()=={"attempt","prompt_tokens","generated_tokens",
            "max_new_tokens","stop_reason","accepted","rejection_code","text_bytes","text_sha256"},"graph attempt fields")
        cap=384-total
        require(accepted==0 and all(type(item[k]) is int for k in
            ("attempt","prompt_tokens","generated_tokens","max_new_tokens","text_bytes"))
            and item["attempt"]==number and 1<=item["prompt_tokens"]<=512 and cap>0
            and item["max_new_tokens"]==cap and 1<=item["generated_tokens"]<=cap
            and type(item["accepted"]) is bool and 0<=item["text_bytes"]<=1048576
            and type(item["text_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",item["text_sha256"]),"graph attempt order/budget/hash")
        total+=item["generated_tokens"];maximum=max(maximum,item["prompt_tokens"])
        if item["accepted"]:
            require(item["rejection_code"] is None and item["stop_reason"] in ("graph_boundary","eos")
                and 1<=item["text_bytes"]<=16384,"invalid graph acceptance")
            if artifact is not None:
                require(item["text_bytes"]==len(artifact) and item["text_sha256"]==sha(artifact),"raw model graph artifact replaced")
            accepted+=1
        elif item["rejection_code"]=="GENERATION_LIMIT":
            require(item["stop_reason"]=="token_limit" and item["generated_tokens"]==cap,"graph limit not fully charged")
        else:
            require((item["rejection_code"]=="INVALID_JSON" and item["stop_reason"]=="eos" and item["text_bytes"]<=16384)
                or (item["rejection_code"]=="INVALID_GRAPH" and item["stop_reason"] in ("eos","graph_boundary"))
                or (item["rejection_code"] in {"GRAPH_FIELDS", "GRAPH_TASK_COUNT", "GRAPH_TASK_FIELDS",
                    "GRAPH_QUESTION_TEXT", "GRAPH_QUESTION_FORM", "GRAPH_GOAL_COPY", "GRAPH_DUPLICATE_QUESTION",
                    "GRAPH_DEPENDENCIES", "GRAPH_DEPENDENCY_REQUIRED"} and 1<=item["text_bytes"]<=16384
                    and item["stop_reason"] in ("eos","graph_boundary"))
                or (item["rejection_code"]=="GRAPH_OUTPUT_TOO_LARGE" and item["stop_reason"]=="eos"
                    and item["text_bytes"]>16384),"graph rejection category")
    return accepted,total,maximum,[]


def check_attempts(attempts,questions=None,goal=QUESTION):
    """Validate accounting and identities; rejected text is deliberately not retained."""
    require(type(attempts) is list and len(attempts)<=4,"invalid planner attempt bound")
    goal_bytes=goal.encode();goal_sha=sha(goal_bytes)
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
                and item["stop_reason"] in ("question_boundary","eos") and 1<=item["text_bytes"]<=512
                and (item["text_bytes"],item["text_sha256"])!=(len(goal_bytes),goal_sha),
                "accepted an incomplete or invalid planner attempt")
            if questions is not None:
                require(accepted<len(questions),"extra accepted question")
                text=questions[accepted]
                require(item["text_bytes"]==len(text.encode()) and item["text_sha256"]==sha(text.encode())
                    and text.rstrip().endswith("?") and text.encode()!=goal_bytes,
                    "accepted question text differs from original model artifact")
            stats.append({k:item[k] for k in ("prompt_tokens","generated_tokens","stop_reason")});accepted+=1
        elif item["rejection_code"]=="GENERATION_LIMIT":
            require(item["generated_tokens"]==cap and item["stop_reason"]=="token_limit","uncharged generation limit")
        else:
            require(item["rejection_code"] in ("EMPTY_TEXT","TEXT_TOO_LONG","NUL_TEXT","DUPLICATE_TEXT","NOT_A_QUESTION","GOAL_COPY")
                and item["generated_tokens"]<cap and item["stop_reason"] in ("question_boundary","eos")
                and (item["stop_reason"]!="question_boundary" or item["rejection_code"] in ("DUPLICATE_TEXT","GOAL_COPY")),"invalid rejection category")
            if item["rejection_code"]=="TEXT_TOO_LONG":require(item["text_bytes"]>512,"wrong long-text rejection")
            elif item["rejection_code"]=="EMPTY_TEXT":
                require(item["text_bytes"]<=512,"wrong empty-text rejection bound")
                if item["text_bytes"]==0:require(item["text_sha256"]==sha(b""),"wrong empty-text digest")
            else:
                require(1<=item["text_bytes"]<=512,"wrong bounded-text rejection")
                if item["rejection_code"]=="DUPLICATE_TEXT":require(accepted==1,"first question cannot duplicate an accepted question")
                elif item["rejection_code"]=="GOAL_COPY":
                    require(item["text_bytes"]==len(goal_bytes) and item["text_sha256"]==goal_sha,
                        "goal-copy rejection is not bound to the exact original public question")
    return accepted,total,maximum,stats


def validate_failure(value,input_raw,source):
    expected=planning_input(source)
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
    fields={"strategy","attempts","incomplete_attempt"} | ({"planner_decoder"} if TASK_GRAPH else set())
    require(type(diagnostic) is dict and diagnostic.keys()==fields
        and diagnostic["strategy"]==STRATEGY and type(diagnostic["incomplete_attempt"]) is bool,"invalid planner failure diagnostic")
    if TASK_GRAPH:
        require(diagnostic["planner_decoder"]==DECODER,"unbound graph decoder diagnostic")
    accepted,total,_,_=(check_graph_attempts(diagnostic["attempts"]) if TASK_GRAPH else
        check_attempts(diagnostic["attempts"],goal=expected["question"]))
    # Accepted questions do not enroll a plan: later model-integrity or artifact
    # I/O checks can still fail. Only an incomplete generation needs another slot.
    accepted_bound=1 if TASK_GRAPH else 2
    require(accepted<=accepted_bound and total<=384,"failure exceeds planning budget")
    if diagnostic["incomplete_attempt"]:
        require(accepted<accepted_bound and len(diagnostic["attempts"])<4 and total<384,"incomplete attempt was outside original budget")


def check_planning(raw,source):
    load=lambda name:strict_json(raw[name])
    expected=planning_input(source)
    excerpt=expected["source_excerpt"]
    coverage={k:excerpt[k] for k in ("start","end","sha256")}
    complete=excerpt["end"]==len(source)
    require(load("planner-input.json")==expected and raw["planner-input.json"]==encoded(expected),"planner input is not exact source-grounded selection")
    artifact_name="task-graph.json" if TASK_GRAPH else "task-questions.json"
    require(raw["planner-artifact.json"]==raw["model-planner/"+artifact_name],"original model proposal replaced")
    plan=(model_graph_plan if TASK_GRAPH else questions_plan)(raw["planner-artifact.json"])
    require(load("graph-plan.json")==plan and raw["graph-plan.json"]==encoded(plan),"graph was not derived exactly from actual questions")
    report=load("planner-report.json")
    require(report["mode"]=="plan_tasks" and report["version"]==1 and report["status"]=="ok" and report["kind"]=="result"
        and report["device"]=="cpu" and report["threads"]==2 and report["updates_completed"]==0
        and report["backend_versions"]=={"torch":"2.14.0+cpu","transformers":"5.16.1","peft":"0.20.0"}
        and report["model"]["id"]==MODEL_ID["model_id"] and report["model"]["revision"]==MODEL_ID["model_revision"]
        and report["model"]["files"]["model.safetensors"]==MODEL_ID["base_weights"]
        and report["model_weights_loaded"] is report["source_contents_read_by_planner"] is report["base_weights_unchanged"] is True
        and report["goal_only_planning"] is False and report["source_excerpt_complete"] is complete
        and report["base_before"]==report["base_after"] and report["base_before"]["parameters"]>0
        and re.fullmatch(r"[0-9a-f]{64}",report["base_before"]["sha256"])
        and report["generation_limit_reached"] is report["model_answer_correctness_proven"] is False
        and report["planner_stop_reason"]==("task_graph" if TASK_GRAPH else "two_questions")
        and report["planner_strategy"]==STRATEGY
        and report["planner_structure_generated_by"]==("model" if TASK_GRAPH else "local_schema")
        and type(report["planner_prompt_tokens"]) is int and 1<=report["planner_prompt_tokens"]<=512
        and type(report["planner_generated_tokens"]) is int and 1<=report["planner_generated_tokens"]<=(384 if TASK_GRAPH else 383)
        and all(k not in report for k in ("outputs","baseline_evaluation","input_adapter")),"not an actual bounded pinned-model planner result")
    if TASK_GRAPH:
        require(report.get("planner_decoder")==DECODER,"unbound actual graph decoder")
        accepted,total,maximum,_=check_graph_attempts(report["planner_attempts"],raw["planner-artifact.json"])
        require(accepted==1 and "planner_question_stats" not in report
            and report["planner_task_count"]==len(plan["nodes"])-1
            and report["planner_dependency_count"]==sum(len(n["depends_on"]) for n in plan["nodes"][:-1]),"graph structure/accounting mismatch")
    else:
        questions=strict_json(raw["planner-artifact.json"])["questions"]
        require(len(questions)==2,"two model-generated questions required")
        accepted,total,maximum,stats=check_attempts(report["planner_attempts"],questions,goal=expected["question"])
        require(accepted==2 and report["planner_question_stats"]==stats and total<384,"planner accepted stages differ")
    require(report["planner_prompt_tokens"]==maximum and report["planner_generated_tokens"]==total,"planner aggregate budget differs")
    descriptor=dict(version=expected["version"],sha256=sha(raw["planner-input.json"]),bytes=len(raw["planner-input.json"]),
        visibility="public",license="GPL-3.0-only",question_sha256=sha(QUESTION.encode()),source_sha256=sha(source),source_bytes=len(source),
        source_excerpt=dict(coverage,bytes=excerpt["end"]))
    if TASK_GRAPH:descriptor["plan_requirement"]=PLAN_REQUIREMENT
    require(report["dataset"]==descriptor
        and report["artifacts"]==[dict(relative_path=artifact_name,bytes=len(raw["planner-artifact.json"]),sha256=sha(raw["planner-artifact.json"]))]
        and load("model-planner/report.json").items()<=report.items(),"planner report/artifact not tied to exact goal and source")
    DOC["check_supervisor"](report)
    require(report["supervisor"]["rss_limit_bytes"]==3*1024**3,"planner changed its memory limit")
    authority=dict(version=expected["version"],input_sha256=sha(raw["planner-input.json"]),report_sha256=sha(raw["planner-report.json"]),
        artifact_sha256=sha(raw["planner-artifact.json"]),question=QUESTION,source_sha256=sha(source),source_bytes=len(source),source_excerpt=coverage)
    require(load("graph.json")["planner"]==authority,"planner authority was not pinned before graph enrollment")
    summary=dict(kind="bounded_model_fork_join_decomposition",authority=authority,goal_only=False,
        source_contents_read_by_planner=True,source_excerpt_complete=complete,source_coverage=coverage,
        model_selected_tools=False,decomposition_quality_proven=False)
    if TASK_GRAPH:
        summary.update(kind="bounded_model_task_graph_decomposition",model_selected_task_count=True,
            model_selected_dependencies=True,terminal_question_from_user=True)
    return plan,summary


def reduction(raw,prefix,parents,question,authority,source_manifest,layout,executed,response_bytes,node_index,force):
    load=lambda name:json.loads(raw[name]);result=load(prefix+"/result.json");levels=result["synthesis"]["levels"]
    require((1 if force or len(parents)>1 else 0)<=len(levels)<=16,"derived instruction or reduction was omitted")
    rounds=0
    for number,level in enumerate(levels,1):
        require(level["level"]==number and level["complete"] is True
            and level["execution_complete"] is True and level["answer_complete"] is True and level["parents"]==len(parents)
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
            GRAPH["planner"](raw,group_prefix+"/",combined,question,True,model_profile=MODEL_PROFILE)
            require(group==dict(group=group_index,parents=len(previous),complete=True,parts=len(rows),input_sha256=sha(combined)),"derived group accounting changed")
            for p in range((len(rows)+3)//4):
                package=group_prefix+f"/package-{p:04d}"
                data=dict(version=3,visibility="public",license="GPL-3.0-only",source_manifest_hex=source_manifest.hex(),
                    level=number,claim_scope=SYNTH["CLAIM"],model_profile=MODEL_PROFILE,inference=rows[p*4:p*4+4])
                original=dict(authority,selected_at_unix_seconds=saved["created_at_unix_seconds"])
                identity=GRAPH["manifest"](raw[package+"/dataset.manifest"],raw[package+"/dataset.json"],original,
                    f"derived-l{number:02d}-g{group_index:04d}-p{p:04d}",SYNTH["PROFILE"])
                following.extend(GRAPH["package"](raw,package,data,identity,authority,question,layout,executed,response_bytes,node_index,number,len(rows)>4,
                    model_profile=MODEL_PROFILE))
                rounds+=1
        require(level["outputs"]==len(following) and ((force and number==1) or len(following)<len(parents))
            and level["answers"]==following and level["generation_limit_reached"] is any(SYNTH["generation_limited"](a,model_profile=MODEL_PROFILE) for a in following)
            and load(prefix+f"/synthesis/level-{number:02d}-result.json")==level,"derived results or reduction changed")
        parents=following
    require(len(parents)==1 and result["version"]==2 and result["complete"] is True
        and result["execution_complete"] is True and result["answer_complete"] is True and result["synthesized_answer"]==parents[0]
        and result["synthesis"]["complete"] is True and result["synthesis"]["claim_scope"]==SYNTH["CLAIM"]
        and result["synthesis"]["model_answer_correctness_proven"] is False
        and result["synthesis"]["semantic_completeness_proven"] is False,"node final result or scope changed")
    return parents[0],rounds


def provision_pins():
    pin_root=HERE/"ml" if (HERE/"ml").is_dir() else HERE.parent.parent/"workers/volparossa-ml"
    pins=read(pin_root/"model-pins.json");pins.update(read(pin_root/"model-pins-360m.json"))
    lock=(pin_root/"requirements.lock").read_bytes()
    if TASK_GRAPH:
        extra=read(pin_root/"graph-decoder-pins.json")
        require(extra["format_version"]==1 and extra["decoder"]==DECODER and len(extra["wheels"])==3,
            "unexpected decoder provision pins")
        pins["wheels"]+=extra["wheels"]
        pins["task_graph_decoder"]=extra["decoder"]
        lock+=(b"" if lock.endswith(b"\n") else b"\n")+(pin_root/"graph-decoder-requirements.lock").read_bytes()
    return pins,lock


def check_provision(provision):
    pins,lock=provision_pins()
    weights=next(item for item in pins["files"] if item["path"]=="model.safetensors")
    require(pins["model_id"]==MODEL_ID["model_id"] and pins["revision"]==MODEL_ID["model_revision"]
        and {key:weights[key] for key in ("bytes","sha256")}==MODEL_ID["base_weights"],"selected provision pins changed")
    require(provision["success"] is True and provision["installed_wheels"]==len(pins["wheels"])==(41 if TASK_GRAPH else 38)
        and provision["model_profile"]==MODEL_PROFILE and provision["model_id"]==MODEL_ID["model_id"]
        and provision["revision"]==MODEL_ID["model_revision"]
        and provision["download_bytes"]==sum(item["bytes"] for item in pins["files"]+pins["wheels"])==(977891538 if TASK_GRAPH else 977655758)
        and provision["model_pins_sha256"]==sha((json.dumps(pins,indent=2)+"\n").encode())
        and provision["requirements_sha256"]==sha(lock)
        and provision["budget_bytes"]==3*1024**3 and provision["runtime_autofetch_enabled"] is False
        and provision["training_performed"] is False,"unverified selected-model provision")
    require(provision.get("task_graph_decoder")== (DECODER if TASK_GRAPH else None),"unverified decoder provision")


def check(value,revision):
    require(value["source_revision"]==revision,"wrong model-planning revision")
    check_provision(value["provision"])
    saved=value["result-files"]["snapshot"];raw={n:bytes.fromhex(v) for n,v in value["result-files"]["raw"].items()}
    require(set(saved)==set(raw) and sum(map(len,raw.values()))<=32*1048576
        and all(saved[n]["bytes"]==len(b) and saved[n]["sha256"]==sha(b) for n,b in raw.items()),"retained planning-file hashes differ")
    initial=value["enrolled-files"]
    require(all(saved.get(n)==v and raw[n].hex()==initial["raw"][n] for n,v in initial["snapshot"].items())
        and not any(HANDLE.fullmatch(n) or "/work/" in n or "/synthesis/" in n for n in initial["snapshot"]),"enrolled planner/source files changed or already admitted peers")
    original=value["input"];source=bytes.fromhex(original["excerpt_hex"])
    check_public_input(original,source)
    plan,planning=check_planning(raw,source);count=len(plan["nodes"])-1;load=lambda name:json.loads(raw[name])
    source_indices=[i for i,node in enumerate(plan["nodes"]) if not node["depends_on"]]
    graph=load("graph.json")
    require(graph["version"]==1 and graph["plan_sha256"]==sha(encoded(plan)) and graph["leaves"]==[
        dict(node=i,enrollment_sha256=sha(raw[f"node-{i:04d}/document.json"])) for i in source_indices],"model-plan leaf pins changed")
    observed=value["planner-observation"];TRAIN["check_isolation"](observed["isolation"])
    require(observed["node_lineage"]["node"]=="client" and observed["node_lineage"]["cli"]==observed["isolation"]["cli"]
        and observed["node_lineage"]["cli_namespace"]==observed["node_lineage"]["service_namespace"]
        and observed["node_lineage"]["worker_network_namespace"]!=observed["node_lineage"]["cli_namespace"]
        and observed["node_lineage"]["worker_network_namespace"]==observed["isolation"]["namespaces"]["net"]
        and observed["dataset_file"]=={k:saved["planner-input.json"][k] for k in ("bytes","sha256")}
        and observed["dataset_inode"]==saved["planner-input.json"]["inode"]
        and observed["model_inode"]==original["owner_model_inode"]
        and observed["runtime_lock_held"] is observed["alive_before_and_after"] is True,"actual owner planner lineage/input missing")
    if TASK_GRAPH:
        require(value["overlap"].get("simultaneous_execution_claimed") is False
            and value["overlap"]["workers"]==[w["worker"] for w in value["observation"]["workers"]],"graph worker cleanup lineage differs")
    else:JOBS["check_overlap"](value["overlap"])
    layout=value["layout"];workers={w["node"]:w for w in value["overlap"]["workers"]}
    require((bool(workers) and set(workers)<=set(layout["provider_nodes"]) if TASK_GRAPH else set(workers)==set(layout["provider_nodes"]))
        and all(CUSTODY["peer_key"](value["peers"][n])==k for n,k in layout["provider_keys"].items())
        and layout["control_relay_peer_id"] not in {value["peers"][n] for n in workers}
        and original["private_copies_no_hardlinks"] is True and original["owner_model_inode"]!=original["peer_model_inode"]
        and all(w["input_inodes"]["model/model.safetensors"]==original["peer_model_inode"] for w in workers.values()),"planner/peer model copies or isolation differ")
    authority=load("node-0000/document.json");source_manifest=raw["node-0000/source.manifest"]
    source_id=GRAPH["manifest"](source_manifest,source,authority,"document-source","text/plain")
    require(source_id==authority["source_manifest_id"] and authority["model_fingerprint"]==MODEL
        and authority["expires_at_unix_seconds"]-authority["selected_at_unix_seconds"]==7200,"shared original source/model authority changed")
    DOC["selected_providers"](authority,layout)
    enrollment=value["enrollment"]
    require(enrollment["operation"]=="compute_graph_enrolled" and enrollment["execution_started"] is True
        and enrollment["model_planning_performed"] is enrollment["automatic_task_planning"] is True
        and enrollment["peer_execution_started"] is enrollment["task_complete"] is enrollment["private_data_supported"] is False
        and enrollment["nodes"]==count+1 and enrollment["source_tasks"]==len(source_indices) and enrollment["plan_sha256"]==sha(encoded(plan))
        and enrollment["source_manifest_id"]==source_id and enrollment["provider_keys"]==authority["provider_keys"]
        and enrollment["planning"]==planning,"enrollment did not distinguish real planning from pending peer work")
    executed,response_bytes,answers,rounds={},dict.fromkeys(workers,0),{},0
    for index,node in enumerate(plan["nodes"]):
        prefix=f"node-{index:04d}";question=node["question"]
        if node["depends_on"]:
            joined=load(prefix+"/result.json")
            require(raw[prefix+"/source.manifest"]==source_manifest and joined["operation"]=="compute_graph_dependency"
                and joined["public_question"]==question and joined["source_manifest_id"]==source_id
                and joined["graph_node"]==dict(node,plan_sha256=sha(encoded(plan))),"dependency substituted original instruction/source")
            answer,used=reduction(raw,prefix,[answers[n] for n in node["depends_on"]],question,authority,
                source_manifest,layout,executed,response_bytes,index,True)
            rounds+=used;answers[node["id"]]=answer
            continue
        enrolled=load(prefix+"/document.json")
        tokenized=GRAPH["planner"](raw,prefix+"/",source,question,model_profile=MODEL_PROFILE)
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
            parents.extend(GRAPH["package"](raw,package,data,identity,enrolled,question,layout,executed,response_bytes,index,0,True,
                model_profile=MODEL_PROFILE));rounds+=1
        answer,used=reduction(raw,prefix,parents,question,authority,source_manifest,layout,executed,response_bytes,index,False)
        rounds+=used;answers[node["id"]]=answer
        require(load(prefix+"/result.json")["graph_node"]==dict(node,plan_sha256=sha(encoded(plan))),"leaf graph identity changed")
    require(count+1<=rounds<=16 and len({a["job_id"] for a in answers.values()})==count+1,"model join reused a source task")
    for phase,used in (("result",rounds),("resume",0)):
        result=value[phase]
        require(result["version"]==2 and result["operation"]=="compute_public_task_graph" and result["complete"] is True
            and result["execution_complete"] is True and result["answer_complete"] is True and result["semantic_completeness_proven"] is False
            and result["plan"]==plan and result["plan_sha256"]==sha(encoded(plan)) and result["source_manifest_id"]==source_id
            and result["source_expires_unix_seconds"]==authority["expires_at_unix_seconds"] and result["provider_keys"]==authority["provider_keys"]
            and result["rounds_this_invocation"]==used and result["interrupted"] is False and result["planning"]==planning
            and result["scheduling"]=="shared_ready_dependency_queue_v1"
            and result["automatic_task_planning"] is True and result["output"]==answers["answer"] and len(result["nodes"])==count+1
            and all(result[k] is False for k in ("private_data_supported","external_actions_supported","model_answer_correctness_proven","full_b03_claimed")),"planned graph completion/scope changed")
        require(result["nodes"]==[dict(n,complete=True,execution_complete=True,status="complete",answer_status="eos",answer=answers[n["id"]]) for n in plan["nodes"]],"planned graph answers changed")
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
    result=dict(report_kind=KIND,source_revision=revision,scope=SCOPE,
        success=status==0 and complete and remaining==0 and value is not None,runner_exit_status=status,phase=phase,
        observed_blocker=None if blocker=="NONE" else blocker,evidence=value,cleanup=dict(complete=complete,remaining_owned_objects=remaining),
        host_state=host,decomposition_quality_proven=False,model_answer_correctness_proven=False,full_b03_claimed=False,full_alpha_claimed=False)
    if TASK_GRAPH:result["fixture_contract"]=PLAN_REQUIREMENT
    write(record(work,"smoke"),result)


def report(value,revision):
    if TASK_GRAPH:require(value.get("fixture_contract")==PLAN_REQUIREMENT,"historical fixture is not dependent-analysis proof")
    require(value["report_kind"]==KIND and value["source_revision"]==revision and value["scope"]==SCOPE
        and value["success"] is True and value["runner_exit_status"]==0 and value["observed_blocker"] is None
        and value["cleanup"]==dict(complete=True,remaining_owned_objects=0) and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"]==value["host_state"]["after_sha256"]
        and all(value[k] is False for k in ("decomposition_quality_proven","model_answer_correctness_proven","full_b03_claimed","full_alpha_claimed")),
        "model planning/host cleanup proof incomplete")
    check(value["evidence"],revision)


def profile_self_test():
    # Only inert provenance/report values: this exercises both checker branches,
    # never a tokenizer, model, worker or signed publication.
    pins,lock=provision_pins()
    provision=dict(success=True,installed_wheels=len(pins["wheels"]),model_profile=MODEL_PROFILE,model_id=MODEL_ID["model_id"],
        revision=MODEL_ID["model_revision"],download_bytes=sum(x["bytes"] for k in ("files","wheels") for x in pins[k]),budget_bytes=3*1024**3,
        model_pins_sha256=sha((json.dumps(pins,indent=2)+"\n").encode()),
        requirements_sha256=sha(lock),
        runtime_autofetch_enabled=False,training_performed=False)
    if TASK_GRAPH:
        provision["task_graph_decoder"]=DECODER
    check_provision(provision)
    for changed in (dict(model_profile="smollm2-135m-v1"),dict(download_bytes=523040250),
                    dict(model_pins_sha256="0"*64),dict(budget_bytes=4*1024**3)):
        try:check_provision(dict(provision,**changed))
        except ValueError:pass
        else:raise AssertionError("wrong-profile or unpinned provision accepted")
    for profile in ("smollm2-135m-v1",MODEL_PROFILE):
        selected=TRAIN["inference_profile"](profile);model=selected["model"]
        source=b"Inert public source.";question="Inert question?"
        inp=dict(version=1)
        if profile==MODEL_PROFILE:inp["model_profile"]=profile
        inp.update(visibility="public",license="GPL-3.0-only",document=source.decode(),question=question)
        plan=dict(version=1,source_bytes=len(source),source_sha256=sha(source),question_sha256=sha(question.encode()),
            model_id=model["model_id"],model_revision=model["model_revision"],tokenizer_sha256=DOC["TOKENIZER"],
            prompt_limit=selected["prompt_tokens"],parts=[dict(start=0,end=len(source),prompt_tokens=selected["prompt_tokens"])])
        supervisor=dict(child_reaped=True,network_access=False,gpu_access=False,max_observed_rss_bytes=1,rss_limit_bytes=3*1024**3)
        report=dict(mode="plan_document",status="ok",device="cpu",model_weights_loaded=False,updates_completed=0,
            dataset=dict(sha256=sha(encoded(inp))),supervisor=supervisor,
            artifacts=[dict(relative_path="document-plan.json",bytes=len(encoded(plan)),sha256=sha(encoded(plan)))])
        raw={"planner-input.json":encoded(inp),"document-plan.json":encoded(plan),"tokenizer/document-plan.json":encoded(plan),
            "tokenizer-report.json":encoded(report),"tokenizer/report.json":encoded(report)}
        assert GRAPH["planner"](raw,"",source,question,model_profile=profile)==plan
        other=MODEL_PROFILE if profile!=MODEL_PROFILE else "smollm2-135m-v1"
        try:GRAPH["planner"](raw,"",source,question,model_profile=other)
        except ValueError:pass
        else:raise AssertionError("tokenizer accepted the other model profile")
        generation=dict(version=1,stop_reason="eos",max_new_tokens=selected["new_tokens"])
        if profile==MODEL_PROFILE:generation["model_profile"]=profile
        output=dict(sample_index=0,text="Inert bounded answer.",generated_tokens=selected["new_tokens"],
            text_truncated=False,generation=generation)
        handle=dict(provider_key="a"*64,binding=dict(job_id="b"*32,model_fingerprint=selected["fingerprint"]))
        status=dict(report_sha256="c"*64)
        actual=SYNTH["answer"](output,handle,status,"d"*64,0,len(source),0,model_profile=profile)
        assert actual["generation"]==generation and not SYNTH["generation_limited"](actual,model_profile=profile)
        assert SYNTH["generation_fields"](output,annotated=True,model_profile=profile)["answer_complete"] is True
        for mutation in (lambda x:x["generation"].update(stop_reason="token_limit"),
            lambda x:x.update(text="\\"*selected["wire_bytes"]),lambda x:x.update(text_truncated=True),
            lambda x:x["generation"].update(model_profile=other)):
            invalid=copy.deepcopy(output);mutation(invalid)
            try:SYNTH["answer"](invalid,handle,status,"d"*64,0,len(source),0,model_profile=profile)
            except ValueError:pass
            else:raise AssertionError("incomplete/wrong-profile or escaped-oversized parent accepted")


def self_test():
    # Inert schema/graph reconstruction only, not fabricated model or peer execution.
    profile_self_test()
    intro=b"# VOLPAROSSA\n\nPublic introduction.\n\n"
    assert public_intro(intro+b"[Network](#network)\n")==intro
    for original in (intro,b"wrong\n\n[Network](",intro.rstrip()+b"[Network](",b"# VOLPAROSSA\n"+b"x"*1024+b"\n\n[Network]("):
        try:public_intro(original)
        except ValueError:pass
        else:raise AssertionError("incomplete/nonliteral source introduction accepted")
    source=("a"*1023+"é"+"rest").encode()
    selected=planning_input(source)
    assert selected["version"]==2 and selected["source_sha256"]==sha(source) and selected["model_profile"]==MODEL_PROFILE
    assert selected["source_excerpt"]==dict(start=0,end=1023,text="a"*1023,sha256=sha(b"a"*1023))
    assert planning_input(intro)["source_excerpt"]["end"]==len(intro)
    for count in (2,3,4):
        questions=[f"Inert question {n}?" for n in range(count)]
        plan=questions_plan(encoded(dict(version=2,questions=questions)))
        assert len(plan["nodes"])==count+1 and [n["question"] for n in plan["nodes"][:-1]]==questions
        assert plan["nodes"][-1]==dict(id="answer",question=QUESTION,depends_on=[f"question-{n:02d}" for n in range(count)])
    for raw in (b'{"version":2,"version":2,"questions":["A?","B?"]}',
                b'{"version":2,"questions":["A?"," A? "]}',b'{"version":true,"questions":["A?","B?"]}',
                b'{"version":2,"questions":["A?"]}',b'{"version":2,"questions":["A?","B?"],"tools":[]}',
                b'```json\n{"version":2,"questions":["A?","B?"]}\n```',
                b'{"version":2,"questions":["A?","B?"]} trailing',
                b'{"version":1,"questions":["A?","B?"]}',
                b'{"version":2,"questions":["A?","This is not a question."]}',
                encoded(dict(version=2,questions=[QUESTION,"Another question?"]))):
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
    question_form=[attempt(0,1,"A declarative model response.",22,False,"NOT_A_QUESTION","eos"),
        attempt(0,2,questions[0],20,stop="eos"),attempt(1,3,questions[1],25)]
    assert check_attempts(question_form,questions)[:3]==(2,67,83)
    for stop in ("question_boundary","eos"):
        copied=[attempt(0,1,QUESTION,20,False,"GOAL_COPY",stop),
            attempt(0,2,questions[0],20),attempt(1,3,questions[1],25)]
        assert check_attempts(copied,questions)[:3]==(2,65,83)
        # The same rejection is valid after the first accepted question too.
        second_copy=[attempt(0,1,questions[0],20),attempt(1,2,QUESTION,20,False,"GOAL_COPY",stop),
            attempt(1,3,questions[1],25)]
        assert check_attempts(second_copy,questions)[:3]==(2,65,83)
        for changed in (dict(text_sha256="f"*64),dict(text_bytes=len(QUESTION.encode())+1),
                        dict(accepted=True,rejection_code=None),dict(stop_reason="token_limit")):
            invalid=copy.deepcopy(copied);invalid[0].update(changed)
            try:check_attempts(invalid)
            except ValueError:pass
            else:raise AssertionError("unbound or accepted goal-copy metadata accepted")
        try:check_attempts([attempt(0,1,QUESTION,20,stop=stop)],[QUESTION])
        except ValueError:pass
        else:raise AssertionError("exact original goal accepted as a subquestion")
    # Exact UTF-8 equality only: do not silently normalize or rewrite output.
    variant=QUESTION+" "
    assert check_attempts([attempt(0,1,variant,20)],[variant])[0]==1
    assert questions_plan(encoded(dict(version=2,questions=[variant,questions[1]])))["nodes"][0]["question"]==variant
    for invalid in (
        [attempt(0,1,"A declarative model response.",22,True,None,"eos")],
        [attempt(0,1,"A question?",22,False,"NOT_A_QUESTION","question_boundary")],
        [attempt(0,1,"",22,False,"NOT_A_QUESTION","eos")]):
        try:check_attempts(invalid,["A declarative model response."])
        except ValueError:pass
        else:raise AssertionError("non-question accepted or wrong rejection framing")
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
    input_raw=encoded(planning_input(b"public"))
    failure=dict(version=1,operation="compute_public_task_planning_failure",request_id="a"*32,
        code="TASK_PLAN_GENERATION_LIMIT_REACHED",input_sha256=sha(input_raw),source_sha256=sha(b"public"),source_bytes=6,
        planner_diagnostic=dict(strategy=STRATEGY,attempts=[attempt(0,1,"x",192,False,"GENERATION_LIMIT","token_limit"),
            attempt(0,2,"y",192,False,"GENERATION_LIMIT","token_limit")],incomplete_attempt=False),
        child_reaped=True,plan_enrolled=False)
    validate_failure(failure,input_raw,b"public")
    copy_failure=copy.deepcopy(failure)
    copy_failure["code"]="TASK_PLAN_QUESTION_ONE_GOAL_COPY"
    copy_failure["planner_diagnostic"]["attempts"]=[attempt(0,1,QUESTION,20,False,"GOAL_COPY")]
    validate_failure(copy_failure,input_raw,b"public")
    old_strategy=copy.deepcopy(copy_failure)
    old_strategy["planner_diagnostic"]["strategy"]="model_questions_source_recovery_v3"
    try:validate_failure(old_strategy,input_raw,b"public")
    except ValueError:pass
    else:raise AssertionError("historical strategy accepted as a new v4 execution")
    for mutate in (
        lambda value:value.update(version=1),
        lambda value:value.pop("model_profile"),
        lambda value:value.update(model_profile="smollm2-135m-v1"),
        lambda value:value["source_excerpt"].update(text="changed"),
        lambda value:value["source_excerpt"].update(start=1),
        lambda value:value["source_excerpt"].update(end=5),
        lambda value:value["source_excerpt"].update(sha256="f"*64)):
        changed=strict_json(input_raw);mutate(changed)
        try:validate_failure(failure,encoded(changed),b"public")
        except ValueError:pass
        else:raise AssertionError("changed source prefix was accepted")
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
    print("source-grounded model-planning v4 proposal, exact goal-copy rejection, recovery accounting and failure export controls PASS; no tokenizer/model/network executed")


def graph_self_test():
    # Pure schema, exact-byte retention and accounting. No generated task is
    # supplied to the live planner by this test or the execution helper.
    profile_self_test()
    source=GRAPH_SOURCE
    selected=planning_input(source)
    assert selected["version"]==3 and selected["plan_requirement"]==PLAN_REQUIREMENT
    assert selected["source_excerpt"]["text"].encode()==source and len(source)<=1024
    original=dict(source="synthetic-public-routing-case-v1",fixture_contract=PLAN_REQUIREMENT,
        synthetic_test_data=True,original_source_sha256=sha(source),question=GRAPH_QUESTION,
        supplied_task_plan=False,excerpt_bytes=len(source),excerpt_sha256=sha(source),
        excerpt_range=dict(start=0,end=len(source)),excerpt_selection="complete_synthetic_public_routing_case")
    check_public_input(original,source)
    for mutation in (dict(source="README.md"),dict(fixture_contract="historical"),
                     dict(question="What requirements and risks does this project describe?"),
                     dict(synthetic_test_data=False),dict(original_source_sha256="f"*64)):
        try:check_public_input(dict(original,**mutation),source)
        except ValueError:pass
        else:raise AssertionError("changed source/goal or old proof accepted as dependent analysis")
    artifact=encoded(dict(version=3,tasks=[dict(question="Which requirements?",depends_on=[]),
        dict(question="Which risks affect those requirements?",depends_on=[0]),
        dict(question="Which other constraints?",depends_on=[])]))
    plan=model_graph_plan(artifact)
    assert len(plan["nodes"])==4 and plan["nodes"][1]["depends_on"]==["question-00"]
    assert plan["nodes"][-1]==dict(id="answer",question=QUESTION,depends_on=["question-01","question-02"])
    def attempt(number,raw,tokens,cap=384,accepted=True,code=None,stop="graph_boundary"):
        return dict(attempt=number,prompt_tokens=128,generated_tokens=tokens,max_new_tokens=cap,
            accepted=accepted,rejection_code=code,stop_reason=stop,text_bytes=len(raw),text_sha256=sha(raw))
    for stop in ("graph_boundary","eos"):
        assert check_graph_attempts([attempt(1,artifact,384,stop=stop)],artifact)[:3]==(1,384,128)
    attempts=[attempt(1,b'not JSON',24,accepted=False,code="INVALID_JSON",stop="eos"),
        attempt(2,artifact,120,cap=360)]
    assert check_graph_attempts(attempts,artifact)[:3]==(1,144,128)
    # Inert report/source binding, deliberately not proof of a real model run.
    selected=planning_input(source);input_raw=encoded(selected)
    excerpt=selected["source_excerpt"];coverage={k:excerpt[k] for k in ("start","end","sha256")}
    report=dict(mode="plan_tasks",version=1,status="ok",kind="result",device="cpu",threads=2,updates_completed=0,
        backend_versions={"torch":"2.14.0+cpu","transformers":"5.16.1","peft":"0.20.0"},
        model=dict(id=MODEL_ID["model_id"],revision=MODEL_ID["model_revision"],files={"model.safetensors":MODEL_ID["base_weights"]}),
        model_weights_loaded=True,source_contents_read_by_planner=True,base_weights_unchanged=True,
        goal_only_planning=False,source_excerpt_complete=True,base_before=dict(parameters=1,sha256="a"*64),
        base_after=dict(parameters=1,sha256="a"*64),generation_limit_reached=False,model_answer_correctness_proven=False,
        planner_stop_reason="task_graph",planner_strategy=STRATEGY,planner_structure_generated_by="model",planner_decoder=DECODER,
        planner_prompt_tokens=128,planner_generated_tokens=144,planner_attempts=attempts,planner_task_count=3,planner_dependency_count=1,
        dataset=dict(version=3,sha256=sha(input_raw),bytes=len(input_raw),visibility="public",license="GPL-3.0-only",
            question_sha256=sha(QUESTION.encode()),source_sha256=sha(source),source_bytes=len(source),
            source_excerpt=dict(coverage,bytes=len(source)),plan_requirement=PLAN_REQUIREMENT),
        artifacts=[dict(relative_path="task-graph.json",bytes=len(artifact),sha256=sha(artifact))],
        supervisor=dict(child_reaped=True,network_access=False,gpu_access=False,max_observed_rss_bytes=1,rss_limit_bytes=3*1024**3))
    raw={"planner-input.json":input_raw,"planner-artifact.json":artifact,"model-planner/task-graph.json":artifact,
        "graph-plan.json":encoded(plan),"planner-report.json":encoded(report),"model-planner/report.json":encoded(report)}
    authority=dict(version=3,input_sha256=sha(input_raw),report_sha256=sha(raw["planner-report.json"]),
        artifact_sha256=sha(artifact),question=QUESTION,source_sha256=sha(source),source_bytes=len(source),source_excerpt=coverage)
    raw["graph.json"]=encoded(dict(planner=authority))
    actual,summary=check_planning(raw,source)
    assert actual==plan and summary["authority"]==authority and summary["model_selected_dependencies"] is True
    for name in ("planner-artifact.json","model-planner/task-graph.json","graph-plan.json","planner-input.json"):
        changed=dict(raw);changed[name]+=b" "
        try:check_planning(changed,source)
        except ValueError:pass
        else:raise AssertionError("modified retained model/source/graph bytes accepted")
    changed=dict(raw);changed_report=copy.deepcopy(report)
    del changed_report["dataset"]["plan_requirement"]
    changed["planner-report.json"]=encoded(changed_report)
    try:check_planning(changed,source)
    except ValueError:pass
    else:raise AssertionError("missing requested structure descriptor accepted")
    independent=encoded(dict(version=3,tasks=[dict(question="First?",depends_on=[]),dict(question="Second?",depends_on=[])]))
    rejected=[attempt(1,independent,20,accepted=False,code="GRAPH_DEPENDENCY_REQUIRED",stop="eos"),
        attempt(2,artifact,120,cap=364)]
    assert check_graph_attempts(rejected,artifact)[:3]==(1,140,128)
    for change in (lambda a:a[1].update(max_new_tokens=384),lambda a:a[1].update(text_sha256="0"*64),
        lambda a:a[0].update(stop_reason="graph_boundary"),lambda a:a[1].update(question_index=0),
        lambda a:a.append(attempt(3,artifact,1)),lambda a:a[1].update(stop_reason="token_limit")):
        invalid=copy.deepcopy(attempts);change(invalid)
        try:check_graph_attempts(invalid,artifact)
        except ValueError:pass
        else:raise AssertionError("invalid model graph accounting accepted")
    for tasks in ([dict(question="One?",depends_on=[])],
        [dict(question="One?",depends_on=[]),dict(question="Two?",depends_on=[])],
        [dict(question=QUESTION,depends_on=[]),dict(question="Two?",depends_on=[0])],
        [dict(question="One?",depends_on=[0]),dict(question="Two?",depends_on=[0])],
        [dict(question="One?",depends_on=[]),dict(question="Two?",depends_on=[0,0])],
        [dict(question="One?",depends_on=[]),dict(question="Two?",depends_on=[True])],
        [dict(question="One?",depends_on=[]),dict(question=" One? ",depends_on=[0])]):
        try:model_graph_plan(encoded(dict(version=3,tasks=tasks)))
        except ValueError:pass
        else:raise AssertionError("invalid graph or non-edge fixture proof accepted")
    for raw in (encoded(dict(version=2,questions=["One?","Two?"])),b'```json\n'+artifact+b'\n```',
        artifact+b' trailing',b'{"version":3,"version":3,"tasks":[]}'):
        try:model_graph_plan(raw)
        except ValueError:pass
        else:raise AssertionError("old, extracted or duplicate-key graph accepted")
    input_raw=encoded(planning_input(source))
    failure=dict(version=1,operation="compute_public_task_planning_failure",request_id="a"*32,
        code="TASK_GRAPH_GENERATION_LIMIT",input_sha256=sha(input_raw),source_sha256=sha(source),source_bytes=len(source),
        planner_diagnostic=dict(strategy=STRATEGY,planner_decoder=DECODER,attempts=[attempt(1,b'partial',384,accepted=False,
            code="GENERATION_LIMIT",stop="token_limit")],incomplete_attempt=False),child_reaped=True,plan_enrolled=False)
    validate_failure(failure,input_raw,source)
    failure["planner_diagnostic"]["incomplete_attempt"]=True
    try:validate_failure(failure,input_raw,source)
    except ValueError:pass
    else:raise AssertionError("extra generation after original budget accepted")
    print("dependent_analysis_v1 synthetic public routing case, exact graph/input/parent-contract controls PASS; no model/network executed")


def main(args):
    if args and args[0]=="--task-graph":
        select_task_graph();args=args[1:]
    command=args[0]
    if command=="self-test":graph_self_test() if TASK_GRAPH else self_test()
    elif command=="prepare":prepare(Path(args[1]))
    elif command=="observe-planner":observe_planner(Path(args[1]),int(args[2]))
    elif command=="observe-peers":observe_peers(Path(args[1]),int(args[2]))
    elif command=="collect":collect(Path(args[1]),args[2])
    elif command=="collect-failure":collect_failure(Path(args[1]))
    elif command=="check-enrollment":
        work=Path(args[1]);saved=read(record(work,"enrolled-files"),64*1048576)
        check_planning({name:bytes.fromhex(raw) for name,raw in saved["raw"].items()},
            bytes.fromhex(read(record(work,"input"))["excerpt_hex"]))
    elif command=="remove-input":remove_input(Path(args[1]))
    elif command=="stopped":stopped(Path(args[1]))
    elif command=="resumed":stopped(Path(args[1]),True)
    elif command=="evidence":evidence(Path(args[1]),args[2])
    elif command=="finalize":finalize(Path(args[1]),args[2],int(args[3]),args[4]=="true",int(args[5]),args[6],args[7])
    elif command=="report":report(read(Path(args[1]),64*1048576),args[2])
    else:raise ValueError("unknown fixed model-planning fixture command")


if __name__=="__main__":
    main(sys.argv[1:])
