#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real public source compilation, singleton peer execution and source-byte provenance."""
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tempfile
import time
from types import SimpleNamespace

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
NETWORK_SCOPE = SCOPE + (" Additionally one local and two independently selected native publications: "
    "one actual preferred-cache hit and one protected missing-source download; exact original signatures, "
    "native identities and unextended expiry retained. Publisher signatures do not authenticate original authors.")


def root_path(work):
    return work / "state-client/compute-source/public-collection"


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def source_input(work, index):
    return work / f"state-client/compute-source/collection-input-{index}.txt"


def prepare(work, network=False):
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
    if not network:
        write(source / "collection-source-plan.json",dict(version=1,sources=plan))
    owner_model = source / "collection-model/model.safetensors"
    peer_model = work / "agent-jobs-user/provision/model/model.safetensors"
    own,peer = owner_model.stat(),peer_model.stat()
    require((own.st_dev,own.st_ino) != (peer.st_dev,peer.st_ino)
        and JOBS["file_hash"](owner_model,269060552) == dict(bytes=269060552,sha256=JOBS["TRAIN"]["WEIGHT_HASH"]),
        "owner tokenizer model is not the independent pinned copy")
    print(json.dumps(dict(inputs=inputs,source_plan=plan,owner_model_inode=[own.st_dev,own.st_ino],
                         peer_model_inode=[peer.st_dev,peer.st_ino],private_copies_no_hardlinks=True)))


def verify_signature(body, signature, publisher, domain):
    # Public-key-only verifier using the existing native signing domain; no private key,
    # model execution or third-party Python cryptography package is involved.
    with tempfile.TemporaryDirectory(prefix="volparossa-public-signature-") as name:
        directory=Path(name)
        (directory/"key.der").write_bytes(bytes.fromhex("302a300506032b6570032100")+publisher)
        (directory/"message.bin").write_bytes(domain+body)
        (directory/"signature.bin").write_bytes(signature)
        verified=JOBS["subprocess"].run(["openssl","pkeyutl","-verify","-pubin","-keyform","DER",
            "-inkey",str(directory/"key.der"),"-rawin","-in",str(directory/"message.bin"),
            "-sigfile",str(directory/"signature.bin")],capture_output=True,timeout=5,check=False)
        require(verified.returncode==0,"original Ed25519 signature failed")


def native_manifest(manifest, text, selection):
    """Independently inspect canonical bytes and verify the original Ed25519 signature."""
    fields=CUSTODY["fields"]
    envelope=fields(manifest,65536);body=fields(envelope[1],65536);payload=fields(body[8],65536)
    require(set(envelope)=={1,2} and len(envelope[2])==64 and set(body)==set(range(1,9))
        and body[1]==body[6]==1 and body[2].hex()==selection["publisher_key"]
        and len(body[2])==len(body[5])==32 and 0<body[3]<body[4]
        and body[4]-body[3]==7200 and body[7].hex()==sha(body[8])
        and sha(manifest)==selection["manifest_id"],"original native manifest identity/expiry differs")
    require(set(payload)==set(range(1,7)) and payload[1].decode()==selection["name"]
        and payload[2]==1 and payload[3]==b"text/plain" and payload[4]==len(text)
        and payload[6].hex()==sha(text),"signed original public text differs")
    require(fields(payload[5],128)=={1:bytes.fromhex(sha(text)),2:len(text)},"native chunk differs")
    verify_signature(envelope[1],envelope[2],body[2],b"VOLPAROSSA/native-content-manifest/v1\0")
    return dict(created=body[3],expires=body[4],sha256=sha(text),bytes=len(text))


def network_plan(work):
    JOBS["guest_work"](work)
    source=work/"state-client/compute-source";owner=source.stat()
    inputs=read(record(work,"input"))
    selected=[dict(label=LABELS[0],input=str(source_input(work,0)))];publications=[]
    for index in (1,2):
        published=read(record(work,f"network-publish-{index}"))
        path=source/f"collection-native-{index}.pb";info=path.lstat();manifest=path.read_bytes()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==owner.st_uid!=0 and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=65536,"native source manifest ownership differs")
        selection=dict(publisher_key=published["publisher_key_hex"],name=f"disposable-collection-source-{index}",manifest_id=sha(manifest))
        text=bytes.fromhex(inputs["inputs"][index]["excerpt_hex"])
        authority=native_manifest(manifest,text,selection)
        require(selection["publisher_key"]!=read(work/"agent-jobs-publish.json")["publisher_key_hex"]
            and published["name"]==selection["name"] and published["manifest_id"]==selection["manifest_id"]
            and published["expires_unix_seconds"]==authority["expires"],"native and compilation publisher were conflated")
        selected.append(dict(label=LABELS[index],native=selection))
        publications.append(dict(source_index=index,selection=selection,manifest_hex=manifest.hex(),**authority))
    require(publications[0]["selection"]["publisher_key"]==publications[1]["selection"]["publisher_key"]
        and publications[0]["sha256"]!=publications[1]["sha256"],"native source identity/content collapsed")
    plan=dict(version=2,sources=selected)
    path=source/"collection-source-plan.json"
    write(path,plan)
    os.chown(path,owner.st_uid,owner.st_gid)
    write(record(work,"network-plan"),dict(source_plan=plan,publications=publications,plan_sha256=sha(path.read_bytes())))


def cache_before(work):
    JOBS["guest_work"](work)
    catalog=runpy.run_path(str(HERE/"agent-train-loop-catalog.py"))
    path=work/"state-client/compute-source/collection-source-cache"
    metadata=path.lstat();source=path.parent.stat()
    require(stat.S_ISDIR(metadata.st_mode) and not path.is_symlink() and metadata.st_uid==source.st_uid!=0
        and stat.S_IMODE(metadata.st_mode)==0o700,"wrong native consumer cache")
    publications=read(record(work,"network-plan"))["publications"]
    hit,miss=(p["sha256"] for p in publications)
    for name,maximum in ((".volparossa-owner-v1",60),(".volparossa-index-v1",catalog["MAX_INDEX"])):
        info=(path/name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==metadata.st_uid
            and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=maximum,"unsafe bounded native cache metadata")
    with (path/".volparossa-owner-v1").open("rb") as owner:
        fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        owner_bytes=owner.read(61);index=(path/".volparossa-index-v1").read_bytes()
        count=catalog["index_absent"](owner_bytes,index,metadata,miss)
        hit_path=path/hit;hit_info=hit_path.lstat()
        require(count==1 and stat.S_ISREG(hit_info.st_mode) and hit_info.st_uid==metadata.st_uid
            and hit_info.st_nlink==1 and stat.S_IMODE(hit_info.st_mode)==0o600
            and JOBS["file_hash"](hit_path,768)==dict(bytes=publications[0]["bytes"],sha256=hit)
            and not (path/miss).exists() and not (path/miss).is_symlink()
            and not (path/".volparossa-index-next-v1").exists()
            and not (path/".volparossa-chunk-next-v1").exists(),"native warm/cold split absent")
        require(index[44:76].hex()==hit,"only warmed source must be indexed")
        write(record(work,"network-cache-before"),dict(cache=dict(device=metadata.st_dev,inode=metadata.st_ino,uid=metadata.st_uid),
            owner_hex=owner_bytes.hex(),index_hex=index.hex(),hit_sha256=hit,miss_sha256=miss,
            hit_present=True,miss_absent=True,lock_acquired=True,observed_unix_seconds=int(time.time())))


def enrolled(work, network=False):
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
    require(read(root/"collection.json")["version"]==(2 if network else 1)
        and (root/"native-source-proofs.json").exists() is network,"enrollment changed local/native mode")
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


def remove_inputs(work, network=False):
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
    expected_plan=read(record(work,"network-plan"))["source_plan"] if network else dict(version=1,sources=read(record(work,"input"))["source_plan"])
    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
        and read(plan) == expected_plan,"source plan changed")
    targets.append(plan)
    if network:
        warmed=source/"collection-warmed-1.txt";info=warmed.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and warmed.read_bytes().hex()==inputs[1]["excerpt_hex"],"warmup output changed")
        targets.append(warmed)
    print("Disposable guest only: remove these explicitly owned fixture inputs before completed resume: "+", ".join(map(str,targets)),flush=True)
    for path in targets: path.unlink()
    write(record(work,"inputs-removed"),dict(original_inputs_absent=True,source_plan_absent=True,
        removed=[str(p.relative_to(work)) for p in targets],signed_compilation_retained=(root_path(work)/"source.txt").is_file()))


def stopped(work, resumed=False, network=False):
    JOBS["guest_work"](work)
    original=read(work / "agent-jobs-observation.json")["workers"]
    observed=read(record(work,"observation"))["workers"]
    require(all(not JOBS["alive"](p) for w in original+[i["worker"] for i in observed] for p in w["owned_processes"]),
            "observed collection process remains")
    require(all(not source_input(work,i).exists() for i in range(3))
        and not (work/"state-client/compute-source/collection-source-plan.json").exists(),"resume used original inputs")
    if network:require(not (work/"state-client/compute-source/collection-warmed-1.txt").exists(),"resume used warmed original file")
    value=dict(all_owned_processes_ended=True,original_inputs_absent=True,source_plan_absent=True)
    if resumed:
        value["snapshot"]=DOC["snapshot"](root_path(work))
        require(value["snapshot"]==read(record(work,"files"),64*1048576)["snapshot"],"completed resume changed retained files")
    write(record(work,"resumed" if resumed else "stopped"),value)


def compile_expected(inputs, native=None):
    native=native or {}
    version=2 if native else 1
    raw=b"";sources=[]
    def append(part):
        nonlocal raw
        start=len(raw);raw+=part
        return dict(start=start,end=len(raw))
    for index,item in enumerate(inputs):
        content=bytes.fromhex(item["excerpt_hex"])
        marker=f"VOLPAROSSA owner-published public source collection v{version}\n" if index==0 else ""
        identity="native: "+encoded(native[index]).decode()+"\n" if index in native else ""
        header=f"{marker}\n--- VOLPAROSSA source {index+1} ---\nlabel: {json.dumps(item['label'],ensure_ascii=False)}\nsha256: {sha(content)}\nbytes: {len(content)}\n{identity}\n"
        source=dict(label=item["label"],sha256=sha(content),bytes=len(content),header=append(header.encode()),
            content=append(content),separator=append(f"\n--- END VOLPAROSSA source {index+1} ---\n".encode()))
        if index in native:source["native"]=native[index]
        sources.append(source)
    return raw,dict(version=version,document_sha256=sha(raw),document_bytes=len(raw),sources=sources)


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


def check_collection_binding(value,raw,enrollment,network=False):
    inputs=value["input"]["inputs"]
    require(len(inputs)==3 and [i["label"] for i in inputs]==list(LABELS)
        and all(764<=i["excerpt_bytes"]<=768 and i["excerpt_bytes"]==len(bytes.fromhex(i["excerpt_hex"]))
            and i["excerpt_sha256"]==sha(bytes.fromhex(i["excerpt_hex"])) for i in inputs),"original public source excerpts changed")
    require(("network" in value) is network,"wrong requested local/native fixture variant")
    native={}
    if network:
        plan=value["network"]["plan"]["source_plan"]
        require(plan["version"]==2 and len(plan["sources"])==3
            and value["network"]["plan"]["plan_sha256"]==sha((json.dumps(plan,indent=2,allow_nan=False)+"\n").encode())
            and plan["sources"][0]==value["input"]["source_plan"][0]
            and all(set(plan["sources"][i])=={"label","native"} and plan["sources"][i]["label"]==LABELS[i] for i in (1,2)),
            "native collection changed explicitly selected plan")
        native={i:plan["sources"][i]["native"] for i in (1,2)}
    source,ledger=compile_expected(inputs,native)
    require(raw["source.txt"]==source and json.loads(raw["collection.json"])==ledger
        and raw["collection.json"]==encoded(ledger) and enrollment["collection_sha256"]==sha(encoded(ledger)),
        "signed compilation and exact ledger disagree")
    expected=dict(ledger=ledger,ledger_sha256=sha(encoded(ledger)),publication_scope="owner_authorized_public_compilation",
        original_publishers_authenticated=False,common_license="GPL-3.0-only",source_files_needed_for_resume=False,semantic_citations_proven=False)
    if network:
        proofs=json.loads(raw["native-source-proofs.json"])
        require(raw["native-source-proofs.json"]==encoded(proofs)
            and enrollment["native_source_proofs_sha256"]==sha(raw["native-source-proofs.json"]),"original native proof pin changed")
        expected.update(native_publications=proofs,publication_signatures_verified=True,source_selection_uses_cache_inventory=False,
            source_proofs_sha256=enrollment["native_source_proofs_sha256"],compilation_expires_unix_seconds=enrollment["expires_at_unix_seconds"])
    else:
        require("native-source-proofs.json" not in raw and enrollment.get("native_source_proofs_sha256") is None,
            "legacy collection unexpectedly contains native-source claims")
    require(value["result"]["source_collection"]==expected and value["resume"]["source_collection"]==expected,
            "collection source identity/authorization scope changed")
    return source,ledger


def check_named_receipt(receipt, selection, authority, peers, layout, provider, hit=False):
    require(receipt["operation"]=="named_content_download" and receipt["publisher_key"]==selection["publisher_key"]
        and receipt["name"]==selection["name"] and receipt["revision"]==1 and receipt["manifest_id"]==selection["manifest_id"]
        and receipt["publication_expires_unix_seconds"]==authority["expires"] and receipt["sha256"]==authority["sha256"]
        and receipt["bytes"]==authority["bytes"] and receipt["chunks"]==1
        and receipt["local_delivery"] is True and receipt["output_mode"]=="0600" and receipt["cache_only"] is False
        and all(receipt[k] is False for k in ("ownership_changed","origin_authenticated","globally_latest"))
        and receipt["origin_body_bytes"]==receipt["origin_range_requests"]==0,"native same-operation receipt changed source/scope")
    if hit:
        require(receipt["peer_bytes"]==receipt["providers_used"]==0 and receipt["provider_peer_ids"]==[]
            and receipt["control_relay_peer_id"]=="","preferred cache hit performed network retrieval")
    else:
        require(receipt["peer_bytes"]==authority["bytes"] and receipt["providers_used"]==1
            and receipt["provider_peer_ids"]==[peers[provider]]
            and receipt["control_relay_peer_id"]==layout["control_relay_peer_id"],"selected missing public source not fetched from protected provider")


def check_native_deposit(receipt, selection, authority, provider_key):
    require(receipt["operation"]=="content_custody_deposit" and receipt["manifest_id"]==selection["manifest_id"]
        and receipt["publisher_key_hex"]==selection["publisher_key"] and receipt["object_bytes"]==authority["bytes"]
        and receipt["original_expiry_unix_seconds"]==authority["expires"] and receipt["requested_providers"]==1
        and receipt["failed_providers"]==0 and receipt["confirmed_complete_providers"]==1 and receipt["complete"] is True
        and len(receipt["observations"])==1 and all(receipt[k] is False for k in
            ("private_keys_transferred","direct_provider_dial","origin_authenticated","future_availability_guaranteed")),
        "native custody deposit did not complete exactly one real provider")
    observed=receipt["observations"][0]
    require(observed["provider_key_hex"]==provider_key and observed["agent_handoff_complete"] is True
        and observed["error"] is None and observed["state"]=="complete" and observed["unique_chunks"]==1
        and observed["object_bytes"]==authority["bytes"] and observed["original_expiry_unix_seconds"]==authority["expires"],
        "native custody observation unbound")
    fields=CUSTODY["fields"];envelope=fields(bytes.fromhex(observed["signed_receipt_hex"]),2048)
    body=fields(envelope[1],2048);payload=fields(body[8],1024)
    require(set(envelope)=={1,2} and len(envelope[2])==64 and set(body)==set(range(1,9))
        and body[1]==1 and body[6]==3 and body[2].hex()==provider_key and len(body[5])==32
        and 0<body[4]-body[3]<=900 and body[4]<=authority["expires"] and body[7].hex()==sha(body[8])
        and set(payload)==set(range(1,12))-{5} and payload[6]==2
        and all(len(payload[k])==32 for k in (1,2,3,4,7,8))
        and payload[3]==body[2] and payload[4].hex()==selection["publisher_key"]
        and payload[7].hex()==selection["manifest_id"] and payload[8].hex()==authority["sha256"]
        and payload[9]==authority["bytes"] and payload[10]==1 and payload[11]==authority["expires"],"original signed custody receipt differs")
    verify_signature(envelope[1],envelope[2],body[2],b"VOLPAROSSA/public-custody/v1\0")


def check_native_sources(value,raw,enrollment):
    network=value["network"];layout=value["layout"];peers=value["peers"]
    inputs=value["input"]["inputs"];selected=network["plan"]["source_plan"]["sources"]
    originals=network["plan"]["publications"];proofs=json.loads(raw["native-source-proofs.json"])
    require(proofs["version"]==1 and [p["source_index"] for p in proofs["sources"]]==[1,2]
        and len(originals)==len(network["publications"])==len(network["deposits"])==2,
        "missing/duplicated native original publication proofs")
    catalog=runpy.run_path(str(HERE/"agent-train-loop-catalog.py"))
    before=network["cache_before"];cache=before["cache"]
    index=bytes.fromhex(before["index_hex"]);owner=bytes.fromhex(before["owner_hex"])
    hit,miss=(inputs[i]["excerpt_sha256"] for i in (1,2))
    require(before["hit_sha256"]==hit and before["miss_sha256"]==miss and hit!=miss
        and before["hit_present"] is before["miss_absent"] is before["lock_acquired"] is True
        and cache["uid"]>0 and catalog["index_absent"](owner,index,SimpleNamespace(st_dev=cache["device"],st_ino=cache["inode"],st_uid=cache["uid"]),miss)==1
        and index[44:76].hex()==hit and int.from_bytes(index[76:80],"little")==inputs[1]["excerpt_bytes"],
        "original consumer cache did not contain exactly selected source1 and exclude source2")
    response_bytes=dict.fromkeys(layout["provider_nodes"],0)
    for offset,source_index in enumerate((1,2)):
        selection=selected[source_index]["native"];original=originals[offset];proof=proofs["sources"][offset]
        require(set(selection)=={"publisher_key","name","manifest_id"} and selection["name"]==f"disposable-collection-source-{source_index}"
            and selection["publisher_key"]!=enrollment["publisher_key"] and selection==original["selection"]==proof["selection"]
            and original["source_index"]==proof["source_index"]==source_index
            and original["manifest_hex"]==proof["signed_manifest_hex"],"independently selected original source changed")
        text=bytes.fromhex(inputs[source_index]["excerpt_hex"])
        authority=native_manifest(bytes.fromhex(original["manifest_hex"]),text,selection)
        require(all(original[k]==authority[k] for k in authority) and proof["expires"]==authority["expires"]
            and proof["bytes"]==authority["bytes"] and proof["sha256"]==authority["sha256"]
            and authority["created"]<=before["observed_unix_seconds"]<=proof["verified_at"]<=enrollment["selected_at_unix_seconds"]
            and enrollment["selected_at_unix_seconds"]<enrollment["expires_at_unix_seconds"]<=proof["expires"],"source authority was renewed or original bytes changed")
        publication=network["publications"][offset]
        require(publication["operation"]=="offline_content_publish" and publication["network_publication"] is False
            and publication["publisher_key_hex"]==selection["publisher_key"] and publication["manifest_id"]==selection["manifest_id"]
            and publication["name"]==selection["name"] and publication["revision"]==1 and publication["content_type"]=="text/plain"
            and publication["bytes"]==len(text) and publication["chunks"]==1 and publication["expires_unix_seconds"]==authority["expires"],
            "native original publication mismatch")
        provider=layout["provider_nodes"][offset]
        check_native_deposit(network["deposits"][offset],selection,authority,layout["provider_keys"][provider])
        check_named_receipt(proof["receipt"],selection,authority,peers,layout,provider,hit=source_index==1)
        if source_index==1:
            check_named_receipt(network["warm"],selection,authority,peers,layout,provider)
        response_bytes[provider]+=len(text)
    require(originals[0]["selection"]["publisher_key"]==originals[1]["selection"]["publisher_key"],"native fixture publisher changed")
    removed=value["inputs-removed"]["removed"]
    require("state-client/compute-source/collection-warmed-1.txt" in removed,"warmup original was not removed before offline resume")
    return response_bytes


def check(value,revision,network=False):
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
    source,ledger=check_collection_binding(value,raw,enrollment,network)
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
    if network:
        for node,size in check_native_sources(value,raw,enrollment).items():response_bytes[node]+=size
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


def evidence(work,revision,network=False):
    JOBS["guest_work"](work)
    value={name:read(record(work,name),64*1048576) for name in
        ("input","enrollment","enrolled","observation","files","result","resume","inputs-removed","stopped","resumed")}
    value.update({name:read(work/f"agent-jobs-{name}.json") for name in ("provision","publish","layout")})
    value.update(source_revision=revision,overlap=read(work/"agent-jobs-observation.json"),
        peers=read(work/"a01-expected-peers.json"),cleanup=read(work/"agent-jobs-private-cleanup.json"),
        path=dict(selected_route=read(work/"content-custody-fetch-live-selection.json"),
        privacy={r:read(work/f"content-custody-fetch-privacy-{r}.json") for r in CUSTODY["ROLES"]},
        control_privacy=read(work/"content-provider-custody-fetch-control.json"),gates=read(work/"content-custody-fetch-gates.json")))
    if network:
        value["network"]=dict(plan=read(record(work,"network-plan")),cache_before=read(record(work,"network-cache-before")),
            warm=read(record(work,"network-warm")),publications=[read(record(work,f"network-publish-{i}")) for i in (1,2)],
            deposits=[read(record(work,f"network-deposit-{i}")) for i in (1,2)])
    check(value,revision,network);write(record(work,"evidence"),value)


def finalize(work,revision,status,complete,remaining,phase,blocker,network=False):
    path=record(work,"evidence");value=read(path,64*1048576) if path.is_file() else None
    host=read(work/"a15-evidence.json") if (work/"a15-evidence.json").is_file() else {}
    write(record(work,"smoke"),dict(report_kind=KIND,source_revision=revision,scope=NETWORK_SCOPE if network else SCOPE,
        success=status==0 and complete and remaining==0 and value is not None,runner_exit_status=status,phase=phase,
        observed_blocker=None if blocker=="NONE" else blocker,evidence=value,cleanup=dict(complete=complete,remaining_owned_objects=remaining),host_state=host,
        original_publishers_authenticated=False,semantic_citations_proven=False,full_b03_claimed=False,full_alpha_claimed=False))


def report(value,revision,network=False):
    require(value["report_kind"]==KIND and value["source_revision"]==revision and value["scope"]==(NETWORK_SCOPE if network else SCOPE)
        and value["success"] is True and value["runner_exit_status"]==0 and value["observed_blocker"] is None
        and value["cleanup"]==dict(complete=True,remaining_owned_objects=0) and value["host_state"]["unchanged"] is True
        and value["host_state"]["before_sha256"]==value["host_state"]["after_sha256"]
        and all(value[k] is False for k in ("original_publishers_authenticated","semantic_citations_proven","full_b03_claimed","full_alpha_claimed")),
        "collection/cleanup/host proof incomplete")
    check(value["evidence"],revision,network)


def self_test(network=False):
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
    if network:
        selections={i:dict(publisher_key="ab"*32,name=f"source-{i}",manifest_id=str(i)*64) for i in (1,2)}
        native, native_ledger=compile_expected(inputs,selections)
        assert native_ledger["version"]==2 and native!=source and "native" not in native_ledger["sources"][0]
        assert [native_ledger["sources"][i]["native"] for i in (1,2)]==list(selections.values())
        assert all(b"native: "+encoded(selection)+b"\n" in native for selection in selections.values())
        for field,replacement in (("publisher_key","cd"*32),("name","other"),("manifest_id","ff"*32)):
            changed=copy.deepcopy(selections);changed[1][field]=replacement
            changed_source,changed_ledger=compile_expected(inputs,changed)
            assert sha(changed_source)!=sha(native) and encoded(changed_ledger)!=encoded(native_ledger)
        try:check_collection_binding(value,raw,enrollment,True)
        except ValueError:pass
        else:raise AssertionError("network verifier accepted local-only evidence")
        selected=selections[1];authority=dict(expires=900,sha256="ef"*32,bytes=768)
        peers=dict(a="firstPeer",b="secondPeer");layout=dict(control_relay_peer_id="controlPeer")
        receipt=dict(operation="named_content_download",publisher_key=selected["publisher_key"],name=selected["name"],
            revision=1,manifest_id=selected["manifest_id"],publication_expires_unix_seconds=900,sha256=authority["sha256"],
            bytes=768,chunks=1,local_delivery=True,output_mode="0600",cache_only=False,ownership_changed=False,
            origin_authenticated=False,globally_latest=False,origin_body_bytes=0,origin_range_requests=0,
            peer_bytes=768,providers_used=1,provider_peer_ids=[peers["a"]],control_relay_peer_id=layout["control_relay_peer_id"])
        check_named_receipt(receipt,selected,authority,peers,layout,"a")
        cached=dict(receipt,peer_bytes=0,providers_used=0,provider_peer_ids=[],control_relay_peer_id="")
        check_named_receipt(cached,selected,authority,peers,layout,"a",True)
        for item,is_hit in ((receipt,True),(cached,False),(dict(receipt,origin_authenticated=True),False),
                            (dict(receipt,publication_expires_unix_seconds=901),False),
                            (dict(receipt,manifest_id="ff"*32),False),(dict(receipt,provider_peer_ids=[peers["b"]]),False)):
            try:check_named_receipt(item,selected,authority,peers,layout,"a",is_hit)
            except ValueError:pass
            else:raise AssertionError("wrong cache/miss/source receipt accepted")
        # Inert crypto API control, not a fabricated worker/network execution report.
        with tempfile.TemporaryDirectory(prefix="volparossa-fixture-signature-") as name:
            directory=Path(name);key=directory/"key.pem";public=directory/"public.der";message=directory/"message";signature=directory/"signature"
            domain=b"VOLPAROSSA/native-content-manifest/v1\0";body=b"inert verifier API control"
            message.write_bytes(domain+body)
            for command in (["openssl","genpkey","-algorithm","ED25519","-out",str(key)],
                ["openssl","pkey","-in",str(key),"-pubout","-outform","DER","-out",str(public)],
                ["openssl","pkeyutl","-sign","-inkey",str(key),"-rawin","-in",str(message),"-out",str(signature)]):
                JOBS["subprocess"].run(command,check=True,capture_output=True,timeout=5)
            raw_key=public.read_bytes();require(raw_key[:12]==bytes.fromhex("302a300506032b6570032100") and len(raw_key)==44,"wrong Ed25519 public DER")
            verify_signature(body,signature.read_bytes(),raw_key[12:],domain)
            try:verify_signature(body+b"changed",signature.read_bytes(),raw_key[12:],domain)
            except ValueError:pass
            else:raise AssertionError("changed signed bytes accepted")
        print("network-mode exact native selection/header binding and local-v1 rejection controls PASS; no acquisition or inference executed")
    print("collection exact compilation/ledger/provenance pure checks PASS; no tokenizer, model or network executed")


def main(args):
    network=args[-1]=="--network"
    if network:args=args[:-1]
    command=args[0]
    if command=="self-test":self_test(network)
    elif command=="prepare":prepare(Path(args[1]),network)
    elif command=="network-plan" and network:network_plan(Path(args[1]))
    elif command=="cache-before" and network:cache_before(Path(args[1]))
    elif command=="enrolled":enrolled(Path(args[1]),network)
    elif command=="observe":observe(Path(args[1]),int(args[2]))
    elif command=="collect":collect(Path(args[1]))
    elif command=="remove-inputs":remove_inputs(Path(args[1]),network)
    elif command=="stopped":stopped(Path(args[1]),network=network)
    elif command=="resumed":stopped(Path(args[1]),True,network)
    elif command=="evidence":evidence(Path(args[1]),args[2],network)
    elif command=="finalize":finalize(Path(args[1]),args[2],int(args[3]),args[4]=="true",int(args[5]),args[6],args[7],network)
    elif command=="report":report(read(Path(args[1]),64*1048576),args[2],network)
    else:raise ValueError("unknown fixed collection fixture command")


if __name__=="__main__":
    main(sys.argv[1:])
