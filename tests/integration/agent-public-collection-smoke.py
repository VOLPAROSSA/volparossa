#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real public source compilation, singleton peer execution and source-byte provenance."""
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
DOC = runpy.run_path(str(HERE / "agent-public-document-smoke.py"))
JOBS, SYNTH, CUSTODY = DOC["JOBS"], DOC["SYNTHESIS"], DOC["CUSTODY"]
read, write, require, sha = DOC["read"], DOC["write"], DOC["require"], DOC["sha"]
encoded = SYNTH["encoded"]
PREFIX = "agent-public-collection"
LABELS = ("README.md", "docs/PROTOCOL.md", "docs/DECENTRALIZED_AGENTS.md")
ATTEMPT = "work/package-0000/attempt-0000"
QUESTION = DOC["QUESTION"]
TASK = DOC["TASK"]
MODEL_IDENTITY = dict(model_id=DOC["MODEL"],model_revision=JOBS["TRAIN"]["MODEL_REVISION"],
    base_weights=dict(bytes=269060552,sha256=JOBS["TRAIN"]["WEIGHT_HASH"]),adapter_files=None)
MODEL_FINGERPRINT = sha(encoded(MODEL_IDENTITY))
KIND = "volparossa-public-source-collection"
PROVENANCE = "owner_compilation_exact_byte_intersections_not_source_publisher_or_model_attestation"
SCOPE = ("three explicit public repository excerpts, an owner-signed compilation and exact original-byte ledger; "
    "real pinned tokenizer and two actual isolated peers execute singleton ready rows and at least two real "
    "synthesis levels over protected paths; completed resume needs no original files, brokers or route and "
    "retains exact receipts. Not authentication by original source publishers, semantic citations, answer "
    "correctness, private computation, automatic source discovery, full B03 or full alpha.")


def root_path(work):
    return work / "state-client/compute-source/public-collection"


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def source_input(work, index):
    return work / f"state-client/compute-source/collection-input-{index}.txt"


def prepare(work):
    require(JOBS["TRAIN"]["socket"].gethostname() == "volparossa-alpha"
        and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
        and os.geteuid() != 0 and work.parent == Path("/opt") and work.name.startswith("va.")
        and not work.is_symlink() and HERE == work / "bin", "wrong installed guest collection helper")
    helper = Path(__file__).lstat()
    require(stat.S_ISREG(helper.st_mode) and helper.st_uid == 0 and not helper.st_mode & 0o222,
            "collection helper not root-installed read-only")
    source = JOBS["private"](work / "state-client/compute-source", "compute-source")
    inputs, plan = [], []
    for index,label in enumerate(LABELS):
        path = HERE / f"collection-source-{index}.md"
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid == 0
            and not info.st_mode & 0o222 and 768 <= info.st_size <= 1048576, "public staged source differs")
        raw = path.read_bytes()
        selected = raw[:768].decode("utf-8",errors="ignore").encode()
        require(764 <= len(selected) <= 768 and raw.startswith(selected) and selected.strip(), "not a literal UTF-8 source prefix")
        target = source_input(work,index)
        with target.open("xb") as stream: stream.write(selected)
        target.chmod(0o600)
        item = target.stat()
        inputs.append(dict(label=label,original_repository_sha256=sha(raw),excerpt_hex=selected.hex(),
            excerpt_sha256=sha(selected),excerpt_bytes=len(selected),input_inode=[item.st_dev,item.st_ino]))
        plan.append(dict(label=label,input=str(target)))
    write(source / "collection-source-plan.json",dict(version=1,sources=plan))
    owner_model = source / "collection-model/model.safetensors"
    peer_model = work / "agent-jobs-user/provision/model/model.safetensors"
    own,peer = owner_model.stat(),peer_model.stat()
    require((own.st_dev,own.st_ino) != (peer.st_dev,peer.st_ino)
        and JOBS["file_hash"](owner_model,269060552) == dict(bytes=269060552,sha256=JOBS["TRAIN"]["WEIGHT_HASH"]),
        "owner tokenizer model is not the independent pinned copy")
    print(json.dumps(dict(inputs=inputs,source_plan=plan,owner_model_inode=[own.st_dev,own.st_ino],
                         peer_model_inode=[peer.st_dev,peer.st_ino],private_copies_no_hardlinks=True)))


def enrolled(work):
    JOBS["guest_work"](work)
    root = root_path(work)
    enrollment = read(root / "document.json")
    DOC["check_enrollment_result"](read(record(work,"enrollment")),dict(enrollment,model_fingerprint=enrollment.get("model_fingerprint")))
    DOC["selected_providers"](enrollment,read(work / "agent-jobs-layout.json"))
    require(enrollment["scheduling"] == "ready_rows_v1" and enrollment["synthesize"] is True
        and len(enrollment["packages"]) >= 2 and (root / "collection.json").is_file()
        and not (root / "synthesis").exists()
        and all(not (root / f"package-{n:04d}/work").exists() for n in range(len(enrollment["packages"]))),
        "collection enrollment lacks multiple ready packages or already started jobs")
    write(record(work,"enrolled"),dict(snapshot=DOC["snapshot"](root),no_peer_work=True,owner_returned=True))


def observe(work, launcher):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](launcher)
    root = root_path(work)
    JOBS["observe"](work)
    overlap = read(work / "agent-jobs-observation.json")
    layout = read(work / "agent-jobs-layout.json")
    brokers = {w["node"]:w["broker"] for w in overlap["workers"]}
    observed, seen, started = [], set(), time.monotonic()
    while JOBS["alive"](owner) and time.monotonic()-started < 1800:
        paths = sorted(root.glob("package-????/work/package-0000/attempt-0000/job-?.json"))
        paths += sorted(root.glob("synthesis/level-??-group-????/package-????/work/package-0000/attempt-0000/job-?.json"))
        require(len(paths) <= 128,"collection worker observation bound")
        for path in paths:
            relative = path.relative_to(root).as_posix()
            match = re.fullmatch(r"(?:synthesis/level-([0-9]{2})-group-([0-9]{4})/)?package-([0-9]{4})/"+ATTEMPT+r"/job-([0-3])\.json",relative)
            require(match is not None,"unexpected actual collection handle")
            try:
                handle = read(path)
            except (OSError,json.JSONDecodeError):
                continue
            identifier = handle["binding"]["job_id"]
            if identifier in seen: continue
            node = next((n for n in brokers if layout["provider_keys"][n] == handle["provider_key"]),None)
            require(node is not None and handle["binding"]["row_indices"] == [int(match[4])],"unknown peer or non-singleton collection job")
            first = time.monotonic_ns()
            current = JOBS["worker_snapshot"](work,node,brokers[node],handle["binding"]["dataset_sha256"])
            if current and JOBS["alive"](current["worker"]):
                item = dict(level=int(match[1] or 0),group=int(match[2] or 0),package=int(match[3]),handle_path=relative,
                    handle=handle,handle_file=JOBS["file_hash"](path,16384),worker=current,
                    first_monotonic_ns=first,last_monotonic_ns=time.monotonic_ns(),alive_before_and_after=JOBS["alive"](current["worker"]))
                require(item["alive_before_and_after"],"worker disappeared during collection observation")
                write(record(work,f"worker-{len(observed):04d}"),item)
                observed.append(item);seen.add(identifier)
        time.sleep(0.025)
    require(not JOBS["alive"](owner),"collection owner exceeded fixture bound")
    result = read(record(work,"result"),32*1048576)
    levels = result.get("synthesis",{}).get("levels",[])
    require(result["complete"] is True and len(levels) >= 2 and all(l["complete"] is True for l in levels),
            "actual collection did not complete at least two synthesis levels")
    require({x["level"] for x in observed} == {0}|{l["level"] for l in levels},"actual workers not observed at every stage")
    write(record(work,"observation"),dict(owner=owner,owner_reaped=True,workers=observed))


def collect(work):
    JOBS["guest_work"](work)
    root = root_path(work)
    snapshot = DOC["snapshot"](root)
    raw = {name:(root/name).read_bytes().hex() for name in snapshot}
    require(all(sha(bytes.fromhex(raw[n])) == value["sha256"] for n,value in snapshot.items()),"collection changed during capture")
    write(record(work,"files"),dict(snapshot=snapshot,raw=raw))


def remove_inputs(work):
    JOBS["guest_work"](work)
    inputs = read(record(work,"input"))["inputs"]
    source = work / "state-client/compute-source"
    uid = source.stat().st_uid
    targets = []
    for index,item in enumerate(inputs):
        path = source_input(work,index);info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid != 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and [info.st_dev,info.st_ino] == item["input_inode"]
            and path.read_bytes().hex() == item["excerpt_hex"],"original input identity changed before fixture removal")
        targets.append(path)
    plan = source / "collection-source-plan.json"
    info=plan.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
        and read(plan) == dict(version=1,sources=read(record(work,"input"))["source_plan"]),"source plan changed")
    targets.append(plan)
    print("Disposable guest only: remove these four explicitly owned fixture inputs before completed resume: "+", ".join(map(str,targets)),flush=True)
    for path in targets: path.unlink()
    write(record(work,"inputs-removed"),dict(original_inputs_absent=True,source_plan_absent=True,
        removed=[str(p.relative_to(work)) for p in targets],signed_compilation_retained=(root_path(work)/"source.txt").is_file()))


def stopped(work, resumed=False):
    JOBS["guest_work"](work)
    original=read(work / "agent-jobs-observation.json")["workers"]
    observed=read(record(work,"observation"))["workers"]
    require(all(not JOBS["alive"](p) for w in original+[i["worker"] for i in observed] for p in w["owned_processes"]),
            "observed collection process remains")
    require(all(not source_input(work,i).exists() for i in range(3))
        and not (work/"state-client/compute-source/collection-source-plan.json").exists(),"resume used original inputs")
    value=dict(all_owned_processes_ended=True,original_inputs_absent=True,source_plan_absent=True)
    if resumed:
        value["snapshot"]=DOC["snapshot"](root_path(work))
        require(value["snapshot"]==read(record(work,"files"),64*1048576)["snapshot"],"completed resume changed retained files")
    write(record(work,"resumed" if resumed else "stopped"),value)


def compile_expected(inputs):
    raw=b"";sources=[]
    def append(part):
        nonlocal raw
        start=len(raw);raw+=part
        return dict(start=start,end=len(raw))
    for index,item in enumerate(inputs):
        content=bytes.fromhex(item["excerpt_hex"])
        marker="VOLPAROSSA owner-published public source collection v1\n" if index==0 else ""
        header=f"{marker}\n--- VOLPAROSSA source {index+1} ---\nlabel: {json.dumps(item['label'],ensure_ascii=False)}\nsha256: {sha(content)}\nbytes: {len(content)}\n\n"
        sources.append(dict(label=item["label"],sha256=sha(content),bytes=len(content),header=append(header.encode()),
            content=append(content),separator=append(f"\n--- END VOLPAROSSA source {index+1} ---\n".encode())))
    return raw,dict(version=1,document_sha256=sha(raw),document_bytes=len(raw),sources=sources)


def provenance(ledger,start,end):
    original,synthetic=[],[]
    for index,item in enumerate(ledger["sources"]):
        for kind in ("header","content","separator"):
            part=item[kind];left=max(start,part["start"]);right=min(end,part["end"])
            if left>=right:continue
            document_range=dict(start=left,end=right)
            if kind=="content":
                original.append(dict(source_index=index,label=item["label"],sha256=item["sha256"],source_bytes=item["bytes"],
                    source_range=dict(start=left-part["start"],end=right-part["start"]),document_range=document_range))
            else:synthetic.append(dict(source_index=index,kind=kind,document_range=document_range))
    return dict(units="utf8_bytes",range=dict(start=start,end=end),original_sources=original,synthetic_ranges=synthetic,
        semantic_citation=False,claim_scope=PROVENANCE)


def check_plan(plan,source,synthesis=False):
    require(plan["version"]==1 and plan["source_bytes"]==len(source) and plan["source_sha256"]==sha(source)
        and plan["question_sha256"]==sha(QUESTION.encode()) and plan["model_id"]==DOC["MODEL"]
        and plan["model_revision"]==JOBS["TRAIN"]["MODEL_REVISION"] and plan["tokenizer_sha256"]==DOC["TOKENIZER"]
        and plan["prompt_limit"]==192 and plan.get("synthesis",False) is synthesis
        and 1<=len(plan["parts"])<=128,"invalid actual tokenizer plan")
    end=0
    for part in plan["parts"]:
        require(type(part["start"]) is int and type(part["end"]) is int and part["start"]==end
            and 0<part["end"]-part["start"]<=4096 and part["end"]<=len(source)
            and type(part["prompt_tokens"]) is int and 1<=part["prompt_tokens"]<=192,"tokenizer skipped source bytes or exceeded limit")
        source[part["start"]:part["end"]].decode();end=part["end"]
    require(end==len(source),"tokenizer omitted compilation tail")


def check_planner(raw,prefix,source,synthesis=False):
    load=lambda name:json.loads(raw[prefix+name])
    plan=load("document-plan.json");check_plan(plan,source,synthesis)
    expected=dict(version=1,visibility="public",license="GPL-3.0-only",document=source.decode(),question=QUESTION)
    if synthesis:expected["synthesis"]=True
    require(load("planner-input.json")==expected,"planner input differs")
    report=load("tokenizer-report.json")
    require(report["mode"]=="plan_document" and report["status"]=="ok" and report["device"]=="cpu"
        and report["model_weights_loaded"] is False and report["updates_completed"]==0
        and "outputs" not in report and "baseline_evaluation" not in report
        and report["dataset"]["sha256"]==sha(raw[prefix+"planner-input.json"])
        and load("tokenizer/report.json").items()<=report.items()
        and load("tokenizer/document-plan.json")==plan and report["artifacts"]==[dict(relative_path="document-plan.json",
            bytes=len(raw[prefix+"tokenizer/document-plan.json"]),sha256=sha(raw[prefix+"tokenizer/document-plan.json"]))],"actual tokenizer execution unbound")
    DOC["check_supervisor"](report)
    return plan


def check_package(raw,prefix,data,manifest_id,enrollment,layout,executed,response_bytes,level):
    load=lambda name:json.loads(raw[prefix+"/"+name])
    require(load("dataset.json")==data,"retained dataset differs from exact source rows")
    require(raw[prefix+"/work/package-0000/dataset.json"]==raw[prefix+"/dataset.json"]
        and raw[prefix+"/work/package-0000/manifest.bin"]==raw[prefix+"/dataset.manifest"],"workflow source changed")
    workflow=load("work/workflow.json")
    require(workflow["scheduling"]=="ready_rows_v1" and workflow["provider_keys"]==enrollment["provider_keys"]
        and workflow.get("model_fingerprint")==enrollment.get("model_fingerprint")
        and workflow["packages"]==[dict(publisher_key=enrollment["publisher_key"],manifest_id=manifest_id,
            dataset_sha256=sha(raw[prefix+"/dataset.json"]),rows=len(data["inference"]),task=TASK)],"package workflow rebound")
    batch=load(ATTEMPT+"/result.json");queue=load(ATTEMPT+"/queue-plan.json")
    require(batch["operation"]=="compute_ready_queue" and batch["complete"] is True and batch["scheduling"]=="ready_rows_v1"
        and batch["dataset_manifest_id"]==manifest_id and batch["task"]==TASK and batch["never_submitted_rows"]==[]
        and len(batch["jobs"])==len(batch["outputs"])==len(data["inference"]),"ready package incomplete")
    require(queue["version"]==1 and queue["scheduling"]=="ready_rows_v1" and queue["publisher_key"]==enrollment["publisher_key"]
        and queue["dataset_manifest_id"]==manifest_id and queue["dataset_sha256"]==sha(raw[prefix+"/dataset.json"])
        and queue["source_expires_unix_seconds"]==enrollment["expires_at_unix_seconds"]
        and queue["model_fingerprint"]==MODEL_FINGERPRINT and queue["task"]==TASK
        and queue["provider_keys"]==enrollment["provider_keys"] and queue["ready_rows"]==list(range(len(data["inference"])))
        and queue["pending_job_ids"]==[],"ready package plan changed source/model/expiry")
    answers=[]
    for row in range(len(data["inference"])):
        handle=load(ATTEMPT+f"/job-{row}.json");binding=handle["binding"];caps=handle["capabilities"]
        identifier=binding["job_id"]
        node=next((n for n,k in layout["provider_keys"].items() if k==handle["provider_key"]),None)
        require(node is not None and identifier not in executed and re.fullmatch(r"[0-9a-f]{32}",identifier)
            and binding["dataset_manifest_id"]==manifest_id and binding["row_indices"]==[row] and binding["task"]==TASK
            and binding["expires_unix_seconds"]<=enrollment["expires_at_unix_seconds"]
            and caps["model_fingerprint"]==binding["model_fingerprint"]==MODEL_FINGERPRINT
            and caps["model"]==MODEL_IDENTITY
            and caps["public_inference_only"] is True and caps["runtime_slots"]==1 and caps["max_threads"]==2
            and caps["task_derivation_v1"] is True and caps["derived_inference_v3" if level else "document_inference_v2"] is True,
            "singleton source/model/peer/lease changed")
        derived=copy.deepcopy(data);derived["inference"]=[derived["inference"][row]];derived_raw=encoded(derived)
        require(binding["dataset_sha256"]==sha(derived_raw),"worker got different source row")
        receipt=load(ATTEMPT+f"/receipt-{identifier}.json");status=receipt["status"]
        part=next(p for p in batch["jobs"] if p["handle"]==handle)
        require(receipt["version"]==1 and receipt["handle"]==handle and status["binding"]==binding
            and status["state"]==part["state"]=="complete" and part["new_submission"] is True
            and status["report_sha256"]==part["report_sha256"]==sha(status["report_json"].encode()),"unbound original receipt")
        actual=json.loads(status["report_json"])
        require(actual["mode"]=="infer" and actual["status"]=="ok" and actual["device"]=="cpu" and actual["threads"]==2
            and actual["updates_completed"]==0 and actual["dataset"]["version"]==data["version"]
            and actual["dataset"]["sha256"]==sha(derived_raw) and actual["dataset"]["source_manifest_sha256"]==enrollment["source_manifest_id"]
            and actual["baseline_evaluation"] is None and len(actual["outputs"])==1
            and actual["model"]["files"]["model.safetensors"]==caps["model"]["base_weights"],"real inference report missing")
        DOC["check_supervisor"](actual)
        output=actual["outputs"][0]
        require(batch["outputs"][row]==dict(sample_index=row,provider_key=handle["provider_key"],job_id=identifier,text=output["text"]),"joined answer differs")
        context=data["inference"][row]
        start=context["start"] if level==0 else min(i["source_start"] for i in context["inputs"])
        end=context["end"] if level==0 else max(i["source_end"] for i in context["inputs"])
        answers.append(SYNTH["answer"](output,handle,status,manifest_id,start,end,0))
        executed[identifier]=dict(handle=handle,raw=derived_raw,node=node,level=level,path=prefix+"/"+ATTEMPT+f"/job-{row}.json")
        response_bytes[node]+=len(status["report_json"].encode())
    return answers


def check_collection_binding(value,raw,enrollment):
    inputs=value["input"]["inputs"]
    require(len(inputs)==3 and [i["label"] for i in inputs]==list(LABELS)
        and all(764<=i["excerpt_bytes"]<=768 and i["excerpt_bytes"]==len(bytes.fromhex(i["excerpt_hex"]))
            and i["excerpt_sha256"]==sha(bytes.fromhex(i["excerpt_hex"])) for i in inputs),"original public source excerpts changed")
    source,ledger=compile_expected(inputs)
    require(raw["source.txt"]==source and json.loads(raw["collection.json"])==ledger
        and raw["collection.json"]==encoded(ledger) and enrollment["collection_sha256"]==sha(encoded(ledger)),
        "signed compilation and exact ledger disagree")
    expected=dict(ledger=ledger,ledger_sha256=sha(encoded(ledger)),publication_scope="owner_authorized_public_compilation",
        original_publishers_authenticated=False,common_license="GPL-3.0-only",source_files_needed_for_resume=False,semantic_citations_proven=False)
    require(value["result"]["source_collection"]==expected and value["resume"]["source_collection"]==expected,
            "collection source identity/authorization scope changed")
    return source,ledger


def check(value,revision):
    require(value["source_revision"]==revision,"wrong collection source snapshot")
    provision=value["provision"]
    require(provision["success"] is True and provision["installed_wheels"]==38
        and provision["download_bytes"]==523040250 and provision["training_performed"] is False,"not pinned explicit guest provision")
    files=value["files"];raw={n:bytes.fromhex(v) for n,v in files["raw"].items()}
    require(set(raw)==set(files["snapshot"]) and sum(map(len,raw.values()))<=32*1048576,"collection export scope differs")
    for name,data in raw.items():
        require(files["snapshot"][name]["bytes"]==len(data) and files["snapshot"][name]["sha256"]==sha(data),"retained file changed")
    load=lambda name:json.loads(raw[name])
    enrollment=load("document.json")
    source,ledger=check_collection_binding(value,raw,enrollment)
    plan=check_planner(raw,"",source)
    require(enrollment["version"]==1 and enrollment["scheduling"]=="ready_rows_v1" and enrollment["synthesize"] is True
        and enrollment["source_sha256"]==sha(source) and enrollment["source_bytes"]==len(source)
        and enrollment["plan_sha256"]==sha(raw["document-plan.json"]) and enrollment["public_question"]==QUESTION
        and enrollment["license"]=="GPL-3.0-only" and enrollment["publisher_key"]==value["publish"]["publisher_key_hex"]
        and enrollment.get("model_fingerprint") is None and len(enrollment["packages"])==(len(plan["parts"])+3)//4>=2,
        "collection enrollment scope changed")
    source_id=DOC["manifest"](raw["source.manifest"],source,enrollment,"document-source","text/plain")
    require(source_id==enrollment["source_manifest_id"],"signed source compilation differs")
    DOC["selected_providers"](enrollment,value["layout"])
    DOC["check_enrollment_result"](value["enrollment"],dict(enrollment,model_fingerprint=None))
    require(value["enrolled"]["no_peer_work"] is True and value["enrolled"]["owner_returned"] is True
        and all(item==files["snapshot"].get(name) for name,item in value["enrolled"]["snapshot"].items()),"pre-job enrollment changed")
    JOBS["check_overlap"](value["overlap"])
    workers={w["node"]:w for w in value["overlap"]["workers"]};layout=value["layout"]
    require(set(workers)==set(layout["provider_nodes"])
        and all(CUSTODY["peer_key"](value["peers"][n])==k for n,k in layout["provider_keys"].items())
        and layout["control_relay_peer_id"] not in {value["peers"][n] for n in workers}
        and value["input"]["private_copies_no_hardlinks"] is True
        and value["input"]["owner_model_inode"]!=value["input"]["peer_model_inode"]
        and all(w["input_inodes"]["model/model.safetensors"]==value["input"]["peer_model_inode"] for w in workers.values()),
        "actual worker/provider/model-copy lineage differs")
    executed,response_bytes,answers,parents={},dict.fromkeys(workers,0),[],[]
    for index,package in enumerate(enrollment["packages"]):
        prefix=f"package-{index:04d}"
        ranges=plan["parts"][index*4:index*4+4]
        data=dict(version=2,visibility="public",license="GPL-3.0-only",source_manifest_hex=raw["source.manifest"].hex(),
            inference=[dict(question=QUESTION,context=source[p["start"]:p["end"]].decode(),start=p["start"],end=p["end"]) for p in ranges])
        manifest=DOC["manifest"](raw[prefix+"/dataset.manifest"],raw[prefix+"/dataset.json"],enrollment,f"document-package-{index:04d}",DOC["PROFILE"])
        require(package["manifest_id"]==manifest and package["dataset_sha256"]==sha(raw[prefix+"/dataset.json"])
            and package["first_part"]==index*4 and package["rows"]==len(ranges),"fragment package mapping changed")
        produced=check_package(raw,prefix,data,manifest,enrollment,layout,executed,response_bytes,0)
        batch=load(prefix+"/"+ATTEMPT+"/result.json")
        require(batch["shared_package_slots"] is True,"fragment sources did not share one provider registry")
        for row,(part,answer) in enumerate(zip(ranges,produced)):
            answers.append(dict(source_part=index*4+row,start=part["start"],end=part["end"],
                context_sha256=sha(source[part["start"]:part["end"]]),package_manifest_id=manifest,
                **{key:answer[key] for key in ("text","provider_key","job_id","report_sha256")},
                source_provenance=provenance(ledger,part["start"],part["end"])))
        parents.extend(produced)
    result,resume=value["result"],value["resume"]
    require(result["answers"]==resume["answers"]==answers,"fragment output/source provenance differs")
    levels=result["synthesis"]["levels"]
    require(2<=len(levels)<=16,"no actual multi-level synthesis")
    rounds=len(enrollment["packages"])
    for number,level in enumerate(levels,1):
        require(level["level"]==number and level["complete"] is True and level["parents"]==len(parents)
            and len(parents)>1 and len(level["groups"])==(len(parents)+63)//64,"synthesis skipped parent level")
        following=[]
        for group_index,group in enumerate(level["groups"]):
            prefix=f"synthesis/level-{number:02d}-group-{group_index:04d}"
            previous=parents[group_index*64:group_index*64+64]
            require(raw[prefix+"/parents.json"]==encoded(previous),"synthesis changed prior real results")
            saved=load(prefix+"/group.json")
            require(saved["version"]==1 and saved["level"]==number and saved["parent_offset"]==group_index*64
                and saved["parents_sha256"]==sha(encoded(previous)) and saved["source_manifest_id"]==source_id
                and enrollment["selected_at_unix_seconds"]<=saved["created_at_unix_seconds"]<enrollment["expires_at_unix_seconds"],
                "synthesis source authority changed")
            combined,rows=SYNTH["expected_rows"](previous,load(prefix+"/document-plan.json")["parts"],QUESTION,group_index*64)
            check_planner(raw,prefix+"/",combined,True)
            require(group==dict(group=group_index,parents=len(previous),complete=True,parts=len(rows),input_sha256=sha(combined)),"group accounting changed")
            for p in range((len(rows)+3)//4):
                package_prefix=prefix+f"/package-{p:04d}"
                data=dict(version=3,visibility="public",license="GPL-3.0-only",source_manifest_hex=raw["source.manifest"].hex(),
                    level=number,claim_scope=SYNTH["CLAIM"],inference=rows[p*4:p*4+4])
                authority=dict(enrollment,selected_at_unix_seconds=saved["created_at_unix_seconds"])
                manifest=DOC["manifest"](raw[package_prefix+"/dataset.manifest"],raw[package_prefix+"/dataset.json"],authority,
                    f"derived-l{number:02d}-g{group_index:04d}-p{p:04d}",SYNTH["PROFILE"])
                following.extend(check_package(raw,package_prefix,data,manifest,enrollment,layout,executed,response_bytes,number));rounds+=1
        require(level["outputs"]==len(following)<len(parents) and level["answers"]==following
            and level["generation_limit_reached"] is any(a["generated_tokens"]==64 for a in following)
            and load(f"synthesis/level-{number:02d}-result.json")==level,"synthesis changed exact results or failed reduction")
        parents=following
    require(len(parents)==1,"final synthesis did not reduce to one answer")
    final=dict(parents[0],source_provenance=provenance(ledger,parents[0]["source_start"],parents[0]["source_end"]))
    require(result["synthesized_answer"]==resume["synthesized_answer"]==final
        and result["synthesis"]==resume["synthesis"] and result["synthesis"]["complete"] is True
        and result["synthesis"]["claim_scope"]==SYNTH["CLAIM"]
        and result["synthesis"]["model_answer_correctness_proven"] is False
        and result["synthesis"]["semantic_completeness_proven"] is False,"final result or epistemic scope differs")
    for item,used in ((result,rounds),(resume,0)):
        DOC["check_result"](item,enrollment,plan,answers,True,used,True)
    expected_paths={item["path"] for item in executed.values()}
    require({name for name in raw if re.search(r"/attempt-[0-9]+/job-[0-9]+\.json$",name)}==expected_paths
        and not any("attempt-0001" in name for name in raw),"extra/retried/copied work in collection")
    observation=value["observation"]
    require(observation["owner_reaped"] is True,"collection owner not reaped")
    observed_ids,processes=set(),[]
    for item in observation["workers"]:
        handle,worker=item["handle"],item["worker"];identifier=handle["binding"]["job_id"]
        require(identifier in executed and identifier not in observed_ids,"unknown/duplicate observed job")
        actual=executed[identifier];base=workers[actual["node"]]
        require(handle==actual["handle"] and item["level"]==actual["level"] and item["handle_path"]==actual["path"]
            and item["handle_file"]=={k:files["snapshot"][actual["path"]][k] for k in ("bytes","sha256")}
            and worker["dataset_json"].encode()==actual["raw"] and worker["dataset_file"]["sha256"]==sha(actual["raw"])
            and all(worker[k]==base[k] for k in ("node","broker","service","node_namespace","runtime_lock_inode"))
            and worker["worker"] not in processes and item["alive_before_and_after"] is True
            and item["first_monotonic_ns"]<item["last_monotonic_ns"],"worker source/process lineage missing")
        require(worker["runtime_lock_held"] is True and worker["network_devices"]==["lo"] and worker["ipv4_routes"]==[]
            and worker["effective_capabilities"]==0 and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][p] for p in ("/runtime","/model","/dataset.json"))
            and all(worker["worker_namespaces"][k]!=worker["guest_namespaces"][k] for k in ("net","pid","ipc","mnt"))
            and worker["worker_namespaces"]["net"]!=worker["node_namespace"],"observed worker isolation missing")
        observed_ids.add(identifier);processes.append(worker["worker"])
    require(observed_ids==set(executed),"not every actual fragment/synthesis job was observed")
    require(value["inputs-removed"]["original_inputs_absent"] is True and value["inputs-removed"]["source_plan_absent"] is True
        and value["inputs-removed"]["signed_compilation_retained"] is True
        and all(value[phase][k] is True for phase in ("stopped","resumed") for k in
            ("all_owned_processes_ended","original_inputs_absent","source_plan_absent"))
        and value["resumed"]["snapshot"]==files["snapshot"],"offline original-file-free resume unproven")
    CUSTODY["validate_path"](value["path"],value["peers"],layout,"inspect")
    application=value["path"]["privacy"]["exit"]["provider_application"]
    require(all(application[n]["request_packets"]>0 and application[n]["response_payload_bytes"]>=size for n,size in response_bytes.items())
        and all(value["cleanup"].values()),"protected complete reports/cleanup missing")


def evidence(work,revision):
    JOBS["guest_work"](work)
    value={name:read(record(work,name),64*1048576) for name in
        ("input","enrollment","enrolled","observation","files","result","resume","inputs-removed","stopped","resumed")}
    value.update({name:read(work/f"agent-jobs-{name}.json") for name in ("provision","publish","layout")})
    value.update(source_revision=revision,overlap=read(work/"agent-jobs-observation.json"),
        peers=read(work/"a01-expected-peers.json"),cleanup=read(work/"agent-jobs-private-cleanup.json"),
        path=dict(selected_route=read(work/"content-custody-fetch-live-selection.json"),
        privacy={r:read(work/f"content-custody-fetch-privacy-{r}.json") for r in CUSTODY["ROLES"]},
        control_privacy=read(work/"content-provider-custody-fetch-control.json"),gates=read(work/"content-custody-fetch-gates.json")))
    check(value,revision);write(record(work,"evidence"),value)


def finalize(work,revision,status,complete,remaining,phase,blocker):
    path=record(work,"evidence");value=read(path,64*1048576) if path.is_file() else None
    host=read(work/"a15-evidence.json") if (work/"a15-evidence.json").is_file() else {}
    write(record(work,"smoke"),dict(report_kind=KIND,source_revision=revision,scope=SCOPE,
        success=status==0 and complete and remaining==0 and value is not None,runner_exit_status=status,phase=phase,
        observed_blocker=None if blocker=="NONE" else blocker,evidence=value,cleanup=dict(complete=complete,remaining_owned_objects=remaining),host_state=host,
        original_publishers_authenticated=False,semantic_citations_proven=False,full_b03_claimed=False,full_alpha_claimed=False))


def report(value,revision):
    require(value["report_kind"]==KIND and value["source_revision"]==revision and value["scope"]==SCOPE
        and value["success"] is True and value["runner_exit_status"]==0 and value["observed_blocker"] is None
        and value["cleanup"]==dict(complete=True,remaining_owned_objects=0) and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"]==value["host_state"]["after_sha256"]
        and all(value[k] is False for k in ("original_publishers_authenticated","semantic_citations_proven","full_b03_claimed","full_alpha_claimed")),
        "collection/cleanup/host proof incomplete")
    check(value["evidence"],revision)


def self_test():
    # Pure schema/byte-map controls only, never invented execution evidence.
    fragment=("Public protocol fixture. "*40).encode()[:768]
    inputs=[dict(label=label,excerpt_hex=fragment.hex(),excerpt_sha256=sha(fragment),excerpt_bytes=len(fragment)) for label in LABELS]
    source,ledger=compile_expected(inputs)
    collection=dict(ledger=ledger,ledger_sha256=sha(encoded(ledger)),publication_scope="owner_authorized_public_compilation",
        original_publishers_authenticated=False,common_license="GPL-3.0-only",source_files_needed_for_resume=False,semantic_citations_proven=False)
    value=dict(input=dict(inputs=inputs),result=dict(source_collection=collection),resume=dict(source_collection=copy.deepcopy(collection)))
    raw={"source.txt":source,"collection.json":encoded(ledger)};enrollment=dict(collection_sha256=sha(encoded(ledger)))
    assert check_collection_binding(value,raw,enrollment)==(source,ledger)
    for index,item in enumerate(ledger["sources"]):
        direct=provenance(ledger,item["content"]["start"],item["content"]["end"])
        assert len(direct["original_sources"])==1 and direct["original_sources"][0]["source_index"]==index and not direct["synthetic_ranges"]
        header=provenance(ledger,item["header"]["start"],item["header"]["end"])
        assert not header["original_sources"] and header["synthetic_ranges"][0]["kind"]=="header"
    full=provenance(ledger,0,len(source));assert len(full["original_sources"])==3 and len(full["synthetic_ranges"])==6
    assert full["semantic_citation"] is False
    variants=[]
    changed=copy.deepcopy(value);changed["result"]["source_collection"]["original_publishers_authenticated"]=True;variants.append((changed,raw,enrollment))
    changed=copy.deepcopy(value);changed["resume"]["source_collection"]["ledger_sha256"]="0"*64;variants.append((changed,raw,enrollment))
    changed=copy.deepcopy(value);changed["input"]["inputs"][1]["label"]="another source";variants.append((changed,raw,enrollment))
    variants.append((value,dict(raw,**{"source.txt":source+b"extra"}),enrollment))
    changed=copy.deepcopy(ledger);changed["sources"][0]["content"]["end"]+=1
    variants.append((value,dict(raw,**{"collection.json":encoded(changed)}),enrollment))
    variants.append((value,raw,dict(collection_sha256="0"*64)))
    for item,data,selection in variants:
        try:check_collection_binding(item,data,selection)
        except (ValueError,KeyError):pass
        else:raise AssertionError("changed collection accepted")
    print("collection exact compilation/ledger/provenance pure checks PASS; no tokenizer, model or network executed")


def main(args):
    command=args[0]
    if command=="self-test":self_test()
    elif command=="prepare":prepare(Path(args[1]))
    elif command=="enrolled":enrolled(Path(args[1]))
    elif command=="observe":observe(Path(args[1]),int(args[2]))
    elif command=="collect":collect(Path(args[1]))
    elif command=="remove-inputs":remove_inputs(Path(args[1]))
    elif command=="stopped":stopped(Path(args[1]))
    elif command=="resumed":stopped(Path(args[1]),True)
    elif command=="evidence":evidence(Path(args[1]),args[2])
    elif command=="finalize":finalize(Path(args[1]),args[2],int(args[3]),args[4]=="true",int(args[5]),args[6],args[7])
    elif command=="report":report(read(Path(args[1]),64*1048576),args[2])
    else:raise ValueError("unknown fixed collection fixture command")


if __name__=="__main__":
    main(sys.argv[1:])
