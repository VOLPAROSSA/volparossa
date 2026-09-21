#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Guest-only ready dependency proof; pause is fixture orchestration, not product behavior."""
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
GRAPH = runpy.run_path(str(HERE / "agent-task-graph-smoke.py"))
READY = runpy.run_path(str(HERE / "agent-jobs-ready-queue-smoke.py"))
COLL, DOC, JOBS, SYNTH, CUSTODY = (GRAPH[k] for k in ("COLL", "DOC", "JOBS", "SYNTH", "CUSTODY"))
read, write, require, sha, encoded = (GRAPH[k] for k in ("read", "write", "require", "sha", "encoded"))
ATTEMPT = GRAPH["ATTEMPT"]
MODEL_PROFILE = "smollm2-360m-v1"
SELECTED_MODEL = JOBS["TRAIN"]["inference_profile"](MODEL_PROFILE)
MODEL, MODEL_ID = SELECTED_MODEL["fingerprint"], SELECTED_MODEL["model"]
HANDLE = GRAPH["HANDLE"]
PREFIX = "agent-ready-dag"
KIND = "volparossa-public-ready-dependency-queue"
PLAN = dict(version=1, nodes=[
    dict(id="a", question="Name one requirement.", depends_on=[]),
    dict(id="b", question="Name one risk.", depends_on=[]),
    dict(id="c", question="Refine this requirement briefly.", depends_on=["a"]),
    dict(id="d", question="Refine this risk briefly.", depends_on=["b"]),
    dict(id="e", question="Combine these findings briefly.", depends_on=["c", "d"])], output="e")
SCOPE = ("One literal public README excerpt and an explicit five-node DAG: A and B are source tasks, "
    "C depends only on A, D only on B, and E joins C and D. A disposable B-only private CPU PSI floor "
    "elicits a recorded cooperative Pause acknowledgement from the original live B worker, which "
    "retains its original live lease while A finishes and real C workers execute and complete on the "
    "freed broker under the same owner. Then B continues and D/E finish. All executed jobs, original "
    "signed inputs, retained receipts, protected paths and original-free offline resume are checked. "
    "The explicit pinned 360M profile must finish every answer with real EOS, not a token-limit stop. "
    "Not automatic planning, answer quality, semantic completeness, private offload, external actions, "
    "full B03 or full alpha. The CPU floor is an explicitly recorded fixture stimulus, not a measurement "
    "of actual CPU load. Exact unmount restores real PSI and the normal owner quiet hold before Resume.")


def pressure():
    # Only root observer commands use this helper; installed public-input preparation
    # and historical source-specific report checkers do not import it eagerly.
    return runpy.run_path(str(HERE / "agent-ready-dag-pressure.py"))


def root_path(work):
    return work / "state-client/compute-source/ready-dag"


def record(work, name):
    return work / f"{PREFIX}-{name}.json"


def broker_log(work,node):
    require(node in JOBS["NODES"],"unexpected ready-DAG broker log")
    path=work/f"agent-jobs-{node}-broker.err"
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not info.st_mode&0o022
            and info.st_uid in (0,(work/f"state-{node}/compute").stat().st_uid)
            and info.st_size<=65536,"unsafe or oversized broker startup log")
        raw=os.read(descriptor,65537)
        require(len(raw)<=65536,"broker startup log exceeded bound")
    finally:os.close(descriptor)
    return dict(inode=[info.st_dev,info.st_ino],uid=info.st_uid,mode=stat.S_IMODE(info.st_mode),
        bytes=len(raw),sha256=sha(raw),hex=raw.hex())


def fresh_brokers(work):
    JOBS["guest_work"](work)
    require(not root_path(work).exists(),"ready-DAG owner was already enrolled")
    layout=read(work/"agent-jobs-layout.json");entries={}
    for node in layout["provider_nodes"]:
        value=broker_log(work,node)
        require(value["bytes"]==0,"broker already contains historical worker progress")
        entries[node]=dict(broker=JOBS["identity"](JOBS["broker_pid"](node)),log=value)
    write(record(work,"fresh-brokers"),dict(entries=entries,monotonic_ns=time.monotonic_ns()))


def startup_ack(raw):
    """Only the first worker of a recorded-empty, identity-pinned broker qualifies."""
    require(len(raw)<=65536,"oversized startup prefix")
    if not raw or not raw.endswith(b"\n"):return None
    acknowledged=0;last_action=None;preparing=0;baseline=0;phase_echo=None
    for line in raw.decode("ascii").splitlines():
        ack=re.fullmatch(r"compute owner_ack phase=(paused|resumed) sequence=([0-9]+) step=([0-9]+) elapsed_ms=([0-9]+)",line)
        if ack:
            require(phase_echo is None and int(ack[2])==acknowledged+1 and int(ack[3])==0
                and int(ack[4])<600000,"uncorrelated startup owner ACK")
            acknowledged+=1;last_action=ack[1];phase_echo=last_action
        elif line in ("compute phase=paused","compute phase=resumed"):
            require(phase_echo==line.split("=",1)[1],"unpaired startup owner ACK")
            phase_echo=None
        elif line=="compute phase=preparing":
            require(phase_echo is None and acknowledged>0 and preparing==baseline==0,"historical worker startup")
            preparing=1
        elif line=="compute phase=baseline":
            require(phase_echo is None and preparing==1 and baseline==0,"historical worker baseline")
            baseline=1
        else:raise ValueError("unexpected prior or completed broker work")
    if baseline!=1 or phase_echo is not None or last_action!="resumed":return None
    return dict(acknowledged_sequence=acknowledged,last_action=last_action,baseline_observed=True)


def next_ack(log, previous, sequence, action, allow_trailing=False):
    """Bind the next paired ACK to the same original broker-log byte prefix."""
    require(all(log[k]==previous[k] for k in ("inode","uid","mode")),"original B broker log replaced")
    raw=bytes.fromhex(log["hex"]);prior=bytes.fromhex(previous["hex"])
    require(raw.startswith(prior) and log["bytes"]==len(raw) and log["sha256"]==sha(raw),"B ACK prefix changed")
    suffix=raw[len(prior):]
    matched=re.match(rb"compute owner_ack phase=(paused|resumed) sequence=([0-9]+) step=([0-9]+) elapsed_ms=([0-9]+)\ncompute phase=(paused|resumed)\n",suffix)
    if matched is None:
        require(suffix.count(b"\n")<2,"unexpected progress before B owner ACK")
        return None
    require(matched[1].decode()==matched[5].decode()==action and int(matched[2])==sequence
        and int(matched[3])==0 and int(matched[4])<600000
        and (allow_trailing or matched.end()==len(suffix)),"uncorrelated B owner ACK")
    prefix=raw[:len(prior)+matched.end()]
    return dict(acknowledgement=dict(sequence=sequence,action=action,step=0,elapsed_ms=int(matched[4])),
        log=dict(log,bytes=len(prefix),sha256=sha(prefix),hex=prefix.hex()))


def wait_ack(work, plan, previous, sequence, action, timeout):
    deadline=min(time.monotonic()+timeout,time.monotonic()+plan["slow"]["handle"]["binding"]["expires_unix_seconds"]-time.time())
    while time.monotonic()<deadline:
        require(JOBS["alive"](plan["owner"]),"original graph owner ended before B ACK")
        value=next_ack(broker_log(work,plan["startup"]["node"]),previous,sequence,action,action=="resumed")
        if value is not None:return value
        require(JOBS["alive"](plan["slow"]["worker"]["worker"]),"original B worker ended before ACK")
        time.sleep(0.025)
    raise ValueError("original B did not acknowledge owner control within the existing lease")


def prepare(work):
    require(JOBS["TRAIN"]["socket"].gethostname() == "volparossa-alpha"
        and JOBS["subprocess"].check_output(["systemd-detect-virt"], text=True).strip() == "kvm"
        and os.geteuid() != 0 and work.parent == Path("/opt") and work.name.startswith("va.")
        and not work.is_symlink() and HERE == work / "bin", "wrong installed ready-DAG guest helper")
    for path in (Path(__file__), HERE / "ready-dag-source-README.md"):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222,
            "ready-DAG helper/source not root-installed read-only")
    source = JOBS["private"](work / "state-client/compute-source", "compute-source")
    original = (HERE / "ready-dag-source-README.md").read_bytes()
    selected = original[:128].decode("utf-8", errors="ignore").encode()
    require(124 <= len(selected) <= 128 and original.startswith(selected), "not a literal public UTF-8 prefix")
    target = source / "ready-dag-input.txt"
    with target.open("xb") as stream:
        stream.write(selected)
    target.chmod(0o600)
    write(source / "ready-dag-task-plan.json", PLAN)
    own = (source / "ready-dag-model/model.safetensors").stat()
    peer = (work / "agent-jobs-user/provision/model/model.safetensors").stat()
    require((own.st_dev, own.st_ino) != (peer.st_dev, peer.st_ino)
        and JOBS["file_hash"](source / "ready-dag-model/model.safetensors", MODEL_ID["base_weights"]["bytes"]) == MODEL_ID["base_weights"],
        "owner tokenizer model is not independent pinned copy")
    print(json.dumps(dict(source="README.md", original_repository_sha256=sha(original), plan=PLAN,
        excerpt_hex=selected.hex(), excerpt_sha256=sha(selected), excerpt_bytes=len(selected),
        input_inode=[target.stat().st_dev, target.stat().st_ino],
        owner_model_inode=[own.st_dev, own.st_ino], peer_model_inode=[peer.st_dev, peer.st_ino],
        private_copies_no_hardlinks=True)))


def snapshot(root):
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not root.is_symlink() and info.st_uid != 0
        and stat.S_IMODE(info.st_mode) == 0o700, "wrong owned ready-DAG directory")
    result, count, total = {}, 0, 0
    for directory, children, files in os.walk(root, topdown=True, followlinks=False):
        count += len(children) + len(files)
        require(count <= 2048, "unbounded ready-DAG retained tree")
        kept = []
        for name in sorted(children):
            path = Path(directory) / name; relative = path.relative_to(root).as_posix(); item = path.lstat()
            require(stat.S_ISDIR(item.st_mode) and not path.is_symlink() and item.st_uid == info.st_uid
                and stat.S_IMODE(item.st_mode) == 0o700, "unsafe ready-DAG directory")
            if re.fullmatch(r"node-000[0-4]/(?:synthesis/level-[0-9]{2}-group-[0-9]{4}/)?publication-cache", relative):
                continue
            require(re.fullmatch(r"node-000[0-4](?:/(?:synthesis|level-[0-9]{2}-group-[0-9]{4}|"
                r"package-[0-9]{4}|work|attempt-[0-9]{4}|tokenizer(?:-attempt-[0-9]{4})?))*", relative),
                "unexpected private ready-DAG directory")
            kept.append(name)
        children[:] = kept
        for name in sorted(files):
            path = Path(directory) / name; item = path.lstat(); relative = path.relative_to(root).as_posix()
            require(stat.S_ISREG(item.st_mode) and not path.is_symlink() and item.st_uid == info.st_uid
                and item.st_nlink == 1 and stat.S_IMODE(item.st_mode) == 0o600 and item.st_size <= 16*1048576
                and (name.endswith(".json") or name in ("source.txt", "source.manifest", "dataset.manifest", "manifest.bin",
                    ".task.lock", ".workflow.lock")), "unexpected retained ready-DAG file")
            raw = path.read_bytes(); total += len(raw)
            require(len(raw) == item.st_size and (raw or name in (".task.lock", ".workflow.lock"))
                and total <= 32*1048576, "changed/empty/oversized ready-DAG evidence")
            result[relative] = dict(bytes=len(raw), sha256=sha(raw), inode=[item.st_dev, item.st_ino])
    require("graph.json" in result and "graph-plan.json" in result
        and not any("attempt-0001" in name for name in result), "missing graph authority or unexpected retry")
    return result


def collect(work, phase):
    JOBS["guest_work"](work)
    require(phase in ("ready", "result"), "wrong ready-DAG snapshot phase")
    if phase == "result":
        output = work / f"{PREFIX}-output.jsonl"
        require(0 < output.stat().st_size <= 16*1048576, "ready-DAG stdout bound")
        values = [json.loads(line) for line in output.read_bytes().splitlines()]
        require(1 <= len(values) <= 512 and all(v.get("operation") == "compute_workflow_progress" for v in values[:-1])
            and values[-1].get("operation") == "compute_public_task_graph", "unexpected ready-DAG stdout records")
        write(record(work,"result"),values[-1])
    root = root_path(work); saved = snapshot(root); raw = {n:(root/n).read_bytes().hex() for n in saved}
    require(all(sha(bytes.fromhex(raw[n])) == item["sha256"] for n,item in saved.items()), "ready-DAG changed during snapshot")
    write(record(work, phase+"-files"), dict(snapshot=saved, raw=raw))


def failure_snapshot(root):
    """Best-effort live diagnostic, never accepted by the successful proof checker.

    Unlike snapshot(), this retains retry attempts. Descriptor-relative traversal
    never follows links; per-file and directory before/after metadata expose
    observed concurrent changes, but do not prove a coherent or quiescent tree.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(root, flags | os.O_DIRECTORY)
    info = os.fstat(descriptor)
    saved, raw_files, directories = {}, {}, {}
    count, total = 0, 0

    def stamp(value):
        return dict(inode=[value.st_dev, value.st_ino], uid=value.st_uid,
            mode=stat.S_IMODE(value.st_mode), bytes=value.st_size,
            links=value.st_nlink, mtime_ns=value.st_mtime_ns, ctime_ns=value.st_ctime_ns)

    def owned_directory(value):
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == info.st_uid
            and value.st_uid != 0 and stat.S_IMODE(value.st_mode) == 0o700,
            "unsafe ready-DAG diagnostic directory")

    def visit(fd, prefix):
        nonlocal count, total
        before = os.fstat(fd); owned_directory(before)
        names = sorted(os.listdir(fd))
        count += len(names)
        require(count <= 2048, "unbounded ready-DAG diagnostic tree")
        for name in names:
            relative = f"{prefix}/{name}" if prefix else name
            try:
                item = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                saved[relative] = dict(observed_changed=True, unavailable="disappeared_before_open")
                continue
            if stat.S_ISDIR(item.st_mode):
                owned_directory(item)
                if re.fullmatch(r"node-000[0-4]/(?:synthesis/level-[0-9]{2}-group-[0-9]{4}/)?publication-cache", relative):
                    continue
                require(re.fullmatch(r"node-000[0-4](?:/(?:synthesis|level-[0-9]{2}-group-[0-9]{4}|"
                    r"package-[0-9]{4}|work|attempt-[0-9]{4}|tokenizer(?:-attempt-[0-9]{4})?))*", relative)
                    and relative.count("/") <= 12, "unexpected ready-DAG diagnostic directory")
                child = os.open(name, flags | os.O_DIRECTORY, dir_fd=fd)
                try:
                    require(stamp(os.fstat(child)) == stamp(item), "changed diagnostic directory before open")
                    visit(child, relative)
                finally:
                    os.close(child)
                continue
            require(stat.S_ISREG(item.st_mode) and item.st_uid == info.st_uid
                and item.st_nlink == 1 and stat.S_IMODE(item.st_mode) == 0o600
                and item.st_size <= 16*1048576
                and (name.endswith(".json") or name in ("source.txt", "source.manifest", "dataset.manifest",
                    "manifest.bin", ".task.lock", ".workflow.lock")), "unsafe ready-DAG diagnostic file")
            child = os.open(name, flags, dir_fd=fd)
            try:
                opened = os.fstat(child)
                require(stamp(opened) == stamp(item) and opened.st_nlink == 1,
                    "changed diagnostic file before open")
                with os.fdopen(os.dup(child), "rb") as stream:
                    raw = stream.read(16*1048576+1)
                after = os.fstat(child)
                total += len(raw)
                require(len(raw) <= 16*1048576 and total <= 32*1048576,
                    "oversized ready-DAG diagnostic evidence")
                changed = stamp(after) != stamp(opened) or len(raw) != opened.st_size
                try:
                    current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    changed = changed or stamp(current) != stamp(after)
                except FileNotFoundError:
                    changed = True
                require(raw or changed or name in (".task.lock", ".workflow.lock"),
                    "empty ready-DAG diagnostic file")
                saved[relative] = dict(bytes=len(raw), sha256=sha(raw), before=stamp(opened),
                    after=stamp(after), observed_changed=changed)
                raw_files[relative] = raw.hex()
            finally:
                os.close(child)
        after = os.fstat(fd)
        directories[prefix or "."] = dict(before=stamp(before), after=stamp(after),
            observed_changed=stamp(before) != stamp(after) or names != sorted(os.listdir(fd)))

    try:
        owned_directory(info)
        # An exact fixture plan is required even for diagnostic-only raw export.
        # No other dataset directory, runtime, model, key or cache is traversed.
        visit(descriptor, "")
        require("graph-plan.json" in raw_files and json.loads(bytes.fromhex(raw_files["graph-plan.json"])) == PLAN,
            "diagnostic graph is not the explicit public README fixture")
    finally:
        os.close(descriptor)
    return dict(schema_version=1, report_kind="volparossa-ready-dag-failure-files",
        diagnostic_only=True, success=False, coherent_snapshot_proven=False, quiescence_proven=False,
        retries_allowed_for_diagnostics_only=True, raw_bytes=total, entries_seen=count,
        observed_concurrent_changes=any(v["observed_changed"] for v in (*saved.values(), *directories.values())),
        snapshot=saved, directories=directories, raw=raw_files)


def collect_failure(work, phase):
    JOBS["guest_work"](work)
    require(phase in ("pause", "observe-ready"), "wrong ready-DAG failure diagnostic phase")
    public = read(record(work, "input"))
    source = work/"bin/ready-dag-source-README.md"
    info = source.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222
        and info.st_nlink == 1 and info.st_size <= 16*1048576,
        "failure diagnostic README is not a bounded root-installed source")
    original = source.read_bytes()
    excerpt = bytes.fromhex(public["excerpt_hex"])
    require(public["source"] == "README.md" and public["plan"] == PLAN
        and public["original_repository_sha256"] == sha(original)
        and 124 <= len(excerpt) <= 128 and original.startswith(excerpt)
        and public["excerpt_sha256"] == sha(excerpt) and public["excerpt_bytes"] == len(excerpt),
        "failure diagnostic source is not the prepared public README excerpt")
    value = failure_snapshot(root_path(work))
    value.update(failed_observer=phase, public_input_sha256=sha(excerpt), monotonic_ns=time.monotonic_ns())
    require(len(json.dumps(value, indent=2).encode())+1 <= 64*1048576,
        "serialized ready-DAG failure diagnostic exceeded report bound")
    write(record(work, "failure-files"), value)


def active_workers(work, brokers, seen):
    root = root_path(work); layout = read(work / "agent-jobs-layout.json")
    paths = sorted(root.glob("node-????/package-????/work/package-0000/attempt-0000/job-?.json"))
    paths += sorted(root.glob("node-????/synthesis/level-??-group-????/package-????/work/package-0000/attempt-0000/job-?.json"))
    require(len(paths) <= 96, "ready-DAG actual job bound exceeded")
    active = []; first = time.monotonic_ns()
    for path in paths:
        relative = path.relative_to(root).as_posix(); match = HANDLE.fullmatch(relative)
        require(match is not None and int(match[1]) < 5, "unexpected ready-DAG handle path")
        try:
            handle = read(path)
        except (OSError, json.JSONDecodeError):
            continue
        if handle["binding"]["job_id"] in seen:
            continue
        node = next((n for n in brokers if layout["provider_keys"][n] == handle["provider_key"]), None)
        require(node is not None and handle["binding"]["row_indices"] == [int(match[5])], "unknown peer/non-singleton DAG job")
        worker = JOBS["worker_snapshot"](work, node, brokers[node], handle["binding"]["dataset_sha256"])
        if worker and JOBS["alive"](worker["worker"]):
            item = dict(graph_node=int(match[1]), level=int(match[2] or 0), handle_path=relative, handle=handle,
                handle_file=JOBS["file_hash"](path,16384), worker=worker, first_monotonic_ns=first,
                last_monotonic_ns=time.monotonic_ns(), alive_before_and_after=JOBS["alive"](worker["worker"]))
            require(item["alive_before_and_after"], "ready-DAG worker disappeared during observation")
            active.append(item)
    return active


def pause(work, launcher):
    JOBS["guest_work"](work)
    owner = JOBS["identity"](launcher); layout = read(work / "agent-jobs-layout.json")
    brokers = {n:JOBS["identity"](JOBS["broker_pid"](n)) for n in layout["provider_nodes"]}
    fresh=read(record(work,"fresh-brokers"))
    require({n:v["broker"] for n,v in fresh["entries"].items()}==brokers,"fresh broker identity changed")
    deadline = time.monotonic()+300
    while JOBS["alive"](owner) and time.monotonic() < deadline:
        active = active_workers(work, brokers, set())
        if len(active) != 2 or {x["graph_node"] for x in active} != {0,1} or not all(JOBS["alive"](x["worker"]["worker"]) for x in active):
            time.sleep(0.025); continue
        active.sort(key=lambda x:x["graph_node"])
        node=active[1]["worker"]["node"];log=broker_log(work,node);empty=fresh["entries"][node]["log"]
        require(all(log[k]==empty[k] for k in ("inode","uid","mode")),"original broker log replaced")
        acknowledgement=startup_ack(bytes.fromhex(log["hex"]))
        if acknowledgement is None:
            time.sleep(0.025);continue
        for index in (0,1):
            plan = read(root_path(work)/f"node-{index:04d}/document-plan.json")
            require(len(plan["parts"]) == 1 and active[index]["level"] == 0, "initial source task did not tokenize to one actual row")
        overlap = dict(workers=[x["worker"] for x in active], both_alive_before_and_after=True,
            first_monotonic_ns=min(x["first_monotonic_ns"] for x in active), last_monotonic_ns=time.monotonic_ns())
        JOBS["check_overlap"](overlap); write(work/"agent-jobs-observation.json",overlap)
        plan = dict(owner=owner, brokers=brokers, initial=active, slow=active[1], fast=active[0],
            method="cooperative-cpu-pressure-floor", fixture_only=True,
            startup=dict(node=node,log=log,acknowledgement=acknowledgement,
                handle=active[1]["handle"],worker=active[1]["worker"]["worker"]))
        write(record(work,"pause-plan"),plan)
        member = active[1]["worker"]["worker"]
        require(JOBS["alive"](active[0]["worker"]["worker"]),"A ended before B pressure injection")
        injected=pressure()["install"](work,brokers,node)
        acknowledged=wait_ack(work,plan,log,acknowledgement["acknowledged_sequence"]+1,"paused",15)
        require(JOBS["alive"](member) and not READY["stopped"](member),"B did not remain live and cooperatively paused")
        write(record(work,"paused"),dict(plan=plan,cooperatively_paused=True,worker_alive=True,
            worker_not_signal_stopped=True,fast_alive_at_injection=True,pressure=injected,**acknowledged,
            boottime_ns=JOBS["boot_ns"](),monotonic_ns=time.monotonic_ns(),unix_seconds=int(time.time())))
        return
    raise ValueError("two actual source workers did not overlap before pause")


def observe_ready(work):
    JOBS["guest_work"](work)
    plan = read(record(work,"pause-plan")); slow = plan["slow"]; original = slow["handle"];paused=read(record(work,"paused"))
    seen = {x["handle"]["binding"]["job_id"] for x in plan["initial"]}; observed=[]
    deadline = min(time.monotonic()+540,time.monotonic()+original["binding"]["expires_unix_seconds"]-time.time()-15)
    while time.monotonic() < deadline:
        require(JOBS["alive"](plan["owner"]) and JOBS["alive"](slow["worker"]["worker"])
            and not READY["stopped"](slow["worker"]["worker"])
            and broker_log(work,plan["startup"]["node"])==paused["log"], "original B worker or owner ended/resumed")
        for item in active_workers(work,plan["brokers"],seen):
            require(item["graph_node"] == 2 and item["handle"]["provider_key"] == plan["fast"]["handle"]["provider_key"],
                "unready dependency or wrong broker ran while B was paused")
            write(record(work,f"ready-worker-{len(observed):04d}"),item)
            observed.append(item); seen.add(item["handle"]["binding"]["job_id"])
        path = root_path(work)/"node-0002/result.json"
        try:
            result = read(path) if path.is_file() else None
            if result and result.get("complete") is True:
                require(observed and not JOBS["alive"](plan["fast"]["worker"]["worker"])
                    and not (root_path(work)/slow["handle_path"]).with_name(f"receipt-{original['binding']['job_id']}.json").exists(),
                    "C completed without an observed new worker or B retained its receipt too early")
                collect(work,"ready")
                write(record(work,"ready"),dict(owner=plan["owner"],workers=observed,c_result=result,
                    slow_cooperatively_paused=True,slow_worker_alive=JOBS["alive"](slow["worker"]["worker"]),
                    slow_receipt_absent=True,acknowledgement=paused["acknowledgement"],
                    pressure=pressure()["inspect"](work,paused["pressure"]["plan"]),
                    same_owner_alive=JOBS["alive"](plan["owner"]),boottime_ns=JOBS["boot_ns"](),unix_seconds=int(time.time())))
                return
        except (FileNotFoundError,json.JSONDecodeError):
            pass
        time.sleep(0.025)
    raise ValueError("ready C did not complete before paused B's original lease expired")


def continue_worker(work, cleanup=False):
    JOBS["guest_work"](work)
    path=record(work,"pause-plan")
    if cleanup and not path.is_file(): return
    plan=read(path); member=plan["slow"]["worker"]["worker"]
    if cleanup:
        pressure()["release"](work,cleanup=True)
        return
    status=read(record(work,"running-status")); original=plan["slow"]["handle"]; ready=read(record(work,"ready"));paused=read(record(work,"paused"))
    require(status["state"]=="running" and status["binding"]==original["binding"]
        and status["report_json"] is None and status["report_sha256"] is None
        and JOBS["alive"](member) and not READY["stopped"](member) and JOBS["alive"](plan["owner"])
        and broker_log(work,plan["startup"]["node"])==paused["log"]
        and ready["unix_seconds"]<=int(time.time())<original["binding"]["expires_unix_seconds"],
        "original B no longer has its exact protected Running status and live lease")
    restored=pressure()["release"](work)
    acknowledged=wait_ack(work,plan,paused["log"],paused["acknowledgement"]["sequence"]+1,"resumed",120)
    write(record(work,"continued"),dict(worker=member,owner=plan["owner"],method="cooperative-cpu-pressure-floor",
        pressure=restored,**acknowledged,
        original_status=status,original_handle=original,boottime_ns=JOBS["boot_ns"](),unix_seconds=int(time.time()),
        same_owner_alive=JOBS["alive"](plan["owner"])))


def observe_rest(work):
    JOBS["guest_work"](work)
    plan=read(record(work,"pause-plan")); prior=plan["initial"]+read(record(work,"ready"))["workers"]
    observed=[];seen={x["handle"]["binding"]["job_id"] for x in prior};deadline=time.monotonic()+1200
    while JOBS["alive"](plan["owner"]) and time.monotonic()<deadline:
        for item in active_workers(work,plan["brokers"],seen):
            require(item["graph_node"] in (3,4),"unexpected extra source/C job after B continued")
            write(record(work,f"result-worker-{len(observed):04d}"),item)
            observed.append(item);seen.add(item["handle"]["binding"]["job_id"])
        time.sleep(0.025)
    require(not JOBS["alive"](plan["owner"]) and {x["graph_node"] for x in observed}=={3,4},"D/E worker observation incomplete")
    write(record(work,"observation"),dict(owner=plan["owner"],owner_reaped=True,workers=prior+observed))


def remove_inputs(work):
    JOBS["guest_work"](work)
    source=work/"state-client/compute-source"; original=read(record(work,"input"))
    targets=[source/"ready-dag-input.txt",source/"ready-dag-task-plan.json"]
    for path in targets:
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==source.stat().st_uid!=0 and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600,"owned original input changed")
    require(targets[0].read_bytes().hex()==original["excerpt_hex"] and read(targets[1])==PLAN
        and [targets[0].stat().st_dev,targets[0].stat().st_ino]==original["input_inode"],"original ready-DAG inputs changed")
    print("Disposable guest only: remove exact owned original input and plan: "+", ".join(map(str,targets)),flush=True)
    for path in targets:path.unlink()
    write(record(work,"inputs-removed"),dict(original_input_absent=True,original_plan_absent=True,
        removed=[str(p.relative_to(work)) for p in targets],retained_graph_plan=(root_path(work)/"graph-plan.json").is_file()))


def stopped(work,resumed=False):
    JOBS["guest_work"](work)
    workers=[x["worker"] for x in read(record(work,"observation"))["workers"]]
    require(all(not JOBS["alive"](p) for worker in workers for p in worker["owned_processes"]),"observed ready-DAG process remains")
    for worker in read(work/"agent-jobs-observation.json")["workers"]:
        require(not JOBS["alive"](worker["broker"]),"peer broker remains")
        state=JOBS["subprocess"].check_output(["systemctl","show","--property=ActiveState","--value",
            f"volparossa-alpha-compute@{worker['node']}.service"],text=True).strip()
        require(state in ("inactive","failed"),"peer broker unit remains active")
    source=work/"state-client/compute-source"
    require(not (source/"ready-dag-input.txt").exists() and not (source/"ready-dag-task-plan.json").exists(),"offline originals remain")
    result=dict(all_owned_processes_ended=True,brokers_stopped=True,original_input_absent=True,original_plan_absent=True)
    if resumed:
        result["snapshot"]=snapshot(root_path(work))
        require(result["snapshot"]==read(record(work,"result-files"),64*1048576)["snapshot"],"offline resume changed retained graph")
    write(record(work,"resumed" if resumed else "stopped"),result)


def check_progress(value,raw,executed,answers):
    plan,paused,ready,continued=(value[k] for k in ("pause-plan","paused","ready","continued"))
    require(plan["fixture_only"] is True and plan["method"]=="cooperative-cpu-pressure-floor"
        and paused["plan"]==plan and paused["cooperatively_paused"] is True and paused["worker_alive"] is True
        and paused["worker_not_signal_stopped"] is True and paused["fast_alive_at_injection"] is True,
        "pause was not exact recorded fixture-only action")
    slow,fast=plan["slow"],plan["fast"]; original=slow["handle"]
    require(slow["graph_node"]==1 and fast["graph_node"]==0 and plan["initial"]==[fast,slow]
        and slow["handle"]["provider_key"]!=fast["handle"]["provider_key"]
        and all(x["handle"]==executed[x["handle"]["binding"]["job_id"]]["handle"] for x in plan["initial"]),"paused another source job")
    require(ready["owner"]==continued["owner"]==plan["owner"] and ready["same_owner_alive"] is True
        and ready["slow_cooperatively_paused"] is True and ready["slow_worker_alive"] is True and ready["slow_receipt_absent"] is True
        and paused["boottime_ns"]<ready["boottime_ns"]<=continued["boottime_ns"]
        and paused["unix_seconds"]<=ready["unix_seconds"]<=continued["unix_seconds"]<original["binding"]["expires_unix_seconds"],
        "C did not finish under the same owner before B resumed within original lease")
    require(ready["workers"] and all(x["graph_node"]==2 and x["handle"]["provider_key"]==fast["handle"]["provider_key"]
        and x["first_monotonic_ns"]>=paused["monotonic_ns"] for x in ready["workers"]),"C did not use the free broker")
    require(ready["c_result"]["complete"] is True and ready["c_result"]["synthesized_answer"]==answers["c"]
        and continued["original_handle"]==original and continued["worker"]==slow["worker"]["worker"]
        and continued["method"]=="cooperative-cpu-pressure-floor" and continued["same_owner_alive"] is True,
        "C completion or exact B continuation differs")
    status=continued["original_status"]
    require(status==value["running-status"] and status["state"]=="running" and status["binding"]==original["binding"]
        and status["report_json"] is None and status["report_sha256"] is None,"missing original protected Running status")
    prior=value["ready-files"]
    require(set(prior["raw"])==set(prior["snapshot"]),"incomplete ready-boundary snapshot")
    for name,item in prior["snapshot"].items():
        require(item["sha256"]==sha(bytes.fromhex(prior["raw"][name])) and item["bytes"]==len(bytes.fromhex(prior["raw"][name])),
            "ready-boundary retained bytes changed")
        if name in ("graph.json","graph-plan.json") or name.startswith(("node-0000/","node-0002/")) or HANDLE.fullmatch(name):
            final=value["result-files"]["snapshot"].get(name)
            # Live scans may republish these identical complete node summaries.
            # Only their inode is mutable here; all receipts/inputs remain exact,
            # and completed offline replay still compares the whole tree strictly.
            retained=(final==item if name not in ("node-0000/result.json","node-0002/result.json")
                else final is not None and all(final[k]==item[k] for k in ("bytes","sha256")))
            require(retained and raw[name].hex()==prior["raw"][name],
                "completed A/C or original handles changed after B continued")
    require(not any(HANDLE.fullmatch(name) and name.startswith(("node-0003/","node-0004/")) for name in prior["snapshot"])
        and not any(name.endswith(f"receipt-{original['binding']['job_id']}.json") for name in prior["snapshot"]),
        "unready D/E or B completion preceded the dependency boundary")


def check_pressure(value,raw):
    plan,paused,ready,continued=(value[k] for k in ("pause-plan","paused","ready","continued"))
    initial=plan["startup"]["acknowledgement"]["acknowledged_sequence"]
    require(next_ack(paused["log"],plan["startup"]["log"],initial+1,"paused")==
        {k:paused[k] for k in ("log","acknowledgement")}
        and next_ack(continued["log"],paused["log"],initial+2,"resumed")==
        {k:continued[k] for k in ("log","acknowledgement")}
        and ready["acknowledgement"]==paused["acknowledgement"],"exact original B Pause/Resume ACKs missing")
    pressure()["validate"](paused["pressure"],ready["pressure"],continued["pressure"])
    injected=paused["pressure"]["plan"]
    require(injected["slow"]==plan["startup"]["node"] and
        {n:v["process"] for n,v in injected["brokers"].items()}==plan["brokers"]
        and paused["pressure"]["installed"]["boottime_ns"]<=paused["boottime_ns"]
        and ready["pressure"]["boottime_ns"]<=ready["boottime_ns"]<=continued["pressure"]["boottime_ns"]
        and continued["boottime_ns"]-continued["pressure"]["unmount_started_boottime_ns"]>=5_000_000_000,
        "CPU floor/owner identity or real quiet-hold ordering differs")
    handle=plan["slow"]["handle"];receipt_path=str(Path(plan["slow"]["handle_path"]).with_name(f"receipt-{handle['binding']['job_id']}.json"))
    actual=json.loads(json.loads(raw[receipt_path])["status"]["report_json"])
    control=actual["owner_control"];pause_ack=paused["acknowledgement"];resume_ack=continued["acknowledgement"]
    require(control["enabled"] is True and control["records_received"]==control["last_sequence"]>=initial+2
        and control["pause_count"]>=1 and control["resume_count"]>=2
        and resume_ack["elapsed_ms"]>pause_ack["elapsed_ms"]
        and control["paused_ms"]>=resume_ack["elapsed_ms"]-pause_ack["elapsed_ms"]-1,
        "actual terminal worker report does not retain the observed cooperative pause")


def check_startup(value):
    fresh=value["fresh-brokers"];plan=value["pause-plan"];slow=plan["slow"];startup=plan["startup"]
    require(set(fresh["entries"])==set(value["layout"]["provider_nodes"])
        and {n:v["broker"] for n,v in fresh["entries"].items()}==plan["brokers"]
        and startup["node"]==slow["worker"]["node"] and startup["handle"]==slow["handle"]
        and startup["worker"]==slow["worker"]["worker"]
        and fresh["monotonic_ns"]<min(x["first_monotonic_ns"] for x in plan["initial"]),
        "startup evidence is not from the original B execution")
    for entry in fresh["entries"].values():
        require(entry["log"]["bytes"]==0 and entry["log"]["hex"]=="" and entry["log"]["sha256"]==sha(b""),
            "historical broker ACK accepted")
    log=startup["log"];empty=fresh["entries"][startup["node"]]["log"];raw=bytes.fromhex(log["hex"])
    require(all(log[k]==empty[k] for k in ("inode","uid","mode")) and log["bytes"]==len(raw)
        and log["sha256"]==sha(raw) and startup["acknowledgement"]==startup_ack(raw)
        and startup["acknowledgement"] is not None,"first B startup ACK/baseline was not retained")


def check_summary(value,authority,answers,rounds):
    require(value["version"]==2 and value["operation"]=="compute_public_task_graph" and value["complete"] is True
        and value["execution_complete"] is True and value["answer_complete"] is True
        and value["semantic_completeness_proven"] is False
        and value["plan"]==PLAN and value["plan_sha256"]==sha(encoded(PLAN)) and value["nodes"]==[
            dict(node,complete=True,execution_complete=True,status="complete",answer_status="eos",answer=answers[node["id"]]) for node in PLAN["nodes"]]
        and value["output"]==answers["e"] and value["source_manifest_id"]==authority["source_manifest_id"]
        and value["source_expires_unix_seconds"]==authority["expires_at_unix_seconds"]
        and value["provider_keys"]==authority["provider_keys"] and value["rounds_this_invocation"]==rounds
        and value["scheduling"]=="shared_ready_dependency_queue_v1" and value["interrupted"] is False
        and all(value[k] is False for k in ("private_data_supported","automatic_task_planning","external_actions_supported",
            "model_answer_correctness_proven","full_b03_claimed")),"ready-DAG completion identity/receipt/scope changed")


def check_provision(provision):
    pin_root=HERE/"ml" if (HERE/"ml").is_dir() else HERE.parent.parent/"workers/volparossa-ml"
    pins=read(pin_root/"model-pins.json");pins.update(read(pin_root/"model-pins-360m.json"))
    weights=next(item for item in pins["files"] if item["path"]=="model.safetensors")
    require(pins["model_id"]==MODEL_ID["model_id"] and pins["revision"]==MODEL_ID["model_revision"]
        and {key:weights[key] for key in ("bytes","sha256")}==MODEL_ID["base_weights"],"selected provision pins changed")
    require(provision["success"] is True and provision["installed_wheels"]==len(pins["wheels"])==38
        and provision["model_profile"]==MODEL_PROFILE and provision["model_id"]==MODEL_ID["model_id"]
        and provision["revision"]==MODEL_ID["model_revision"]
        and provision["download_bytes"]==sum(item["bytes"] for item in pins["files"]+pins["wheels"])==977655758
        and provision["model_pins_sha256"]==sha((json.dumps(pins,indent=2)+"\n").encode())
        and provision["requirements_sha256"]==sha((pin_root/"requirements.lock").read_bytes())
        and provision["budget_bytes"]==3*1024**3 and provision["runtime_autofetch_enabled"] is False
        and provision["training_performed"] is False,"unverified selected-model provision")


def check(value,revision):
    require(value["source_revision"]==revision,"wrong ready-DAG revision")
    check_provision(value["provision"])
    raw={n:bytes.fromhex(v) for n,v in value["result-files"]["raw"].items()};saved=value["result-files"]["snapshot"]
    require(set(raw)==set(saved) and sum(map(len,raw.values()))<=32*1048576
        and all(saved[n]["bytes"]==len(b) and saved[n]["sha256"]==sha(b) for n,b in raw.items()),"retained graph raw hashes differ")
    load=lambda name:json.loads(raw[name]);original=value["input"];source=bytes.fromhex(original["excerpt_hex"])
    require(original["source"]=="README.md" and original["plan"]==PLAN and 124<=len(source)<=128
        and original["excerpt_bytes"]==len(source) and original["excerpt_sha256"]==sha(source)
        and raw["graph-plan.json"]==encoded(PLAN),"original source/plan changed")
    require(load("graph.json")==dict(version=1,plan_sha256=sha(encoded(PLAN)),leaves=[
        dict(node=i,enrollment_sha256=sha(raw[f"node-{i:04d}/document.json"])) for i in (0,1)]),"graph source enrollment pins changed")
    JOBS["check_overlap"](value["overlap"])
    layout=value["layout"];workers={w["node"]:w for w in value["overlap"]["workers"]}
    require(set(workers)==set(layout["provider_nodes"])
        and all(CUSTODY["peer_key"](value["peers"][n])==k for n,k in layout["provider_keys"].items())
        and layout["control_relay_peer_id"] not in {value["peers"][n] for n in workers}
        and original["private_copies_no_hardlinks"] is True and original["owner_model_inode"]!=original["peer_model_inode"]
        and all(w["input_inodes"]["model/model.safetensors"]==original["peer_model_inode"] for w in workers.values()),"actual peer/model lineage differs")
    authority=load("node-0000/document.json");manifest=raw["node-0000/source.manifest"]
    source_id=GRAPH["manifest"](manifest,source,authority,"document-source","text/plain")
    require(source_id==authority["source_manifest_id"] and authority["model_fingerprint"]==MODEL
        and authority["expires_at_unix_seconds"]-authority["selected_at_unix_seconds"]==7200,
        "source validity renewed")
    DOC["selected_providers"](authority,layout)
    executed,response_bytes,answers={},dict.fromkeys(workers,0),{};rounds=0
    for index in (0,1):
        prefix=f"node-{index:04d}/";enrollment=load(prefix+"document.json");question=PLAN["nodes"][index]["question"]
        plan=GRAPH["planner"](raw,prefix,source,question,model_profile=MODEL_PROFILE)
        require(len(plan["parts"])==1 and raw[prefix+"source.txt"]==source and raw[prefix+"source.manifest"]==manifest
            and enrollment["version"]==1 and enrollment["scheduling"]=="ready_rows_v1" and enrollment["synthesize"] is True
            and enrollment["source_sha256"]==sha(source) and enrollment["source_bytes"]==len(source)
            and enrollment["plan_sha256"]==sha(raw[prefix+"document-plan.json"]) and enrollment["public_question"]==question
            and enrollment["license"]=="GPL-3.0-only" and enrollment["publisher_key"]==value["publish"]["publisher_key_hex"]
            and all(enrollment.get(k)==authority.get(k) for k in ("publisher_key","provider_keys","source_manifest_id",
                "model_fingerprint","selected_at_unix_seconds","expires_at_unix_seconds")),"source task authority changed")
        data=dict(version=2,visibility="public",license="GPL-3.0-only",source_manifest_hex=manifest.hex(),
            inference=[dict(question=question,context=source.decode(),start=0,end=len(source))])
        package=prefix+"package-0000"
        identity=GRAPH["manifest"](raw[package+"/dataset.manifest"],raw[package+"/dataset.json"],authority,"document-package-0000",DOC["PROFILE"])
        require(enrollment["packages"]==[dict(manifest_id=identity,dataset_sha256=sha(encoded(data)),first_part=0,rows=1)],"source package mapping differs")
        produced=GRAPH["package"](raw,package,data,identity,authority,question,layout,executed,response_bytes,index,0,True,model_profile=MODEL_PROFILE)
        answers[PLAN["nodes"][index]["id"]]=produced[0];rounds+=1
        result=load(prefix+"result.json")
        require(result["version"]==2 and result["complete"] is True and result["execution_complete"] is True
            and result["answer_complete"] is True and result["semantic_completeness_proven"] is False
            and result["synthesized_answer"]==produced[0] and result["synthesis"]["levels"]==[],"source answer replaced")
    for index in (2,3,4):
        node=PLAN["nodes"][index];question=node["question"];prefix=f"node-{index:04d}";result=load(prefix+"/result.json")
        parents=[answers[name] for name in node["depends_on"]]
        require(raw[prefix+"/source.manifest"]==manifest and result["version"]==2 and result["operation"]=="compute_graph_dependency"
            and result["execution_complete"] is True and result["answer_complete"] is True
            and result["semantic_completeness_proven"] is False
            and result["public_question"]==question and result["source_manifest_id"]==source_id
            and result["graph_node"]==dict(node,plan_sha256=sha(encoded(PLAN))),"dependent task/source changed")
        levels=result["synthesis"]["levels"];require(1<=len(levels)<=16,"dependency skipped its own instruction")
        for number,level in enumerate(levels,1):
            require(level["level"]==number and level["complete"] is True
                and level["execution_complete"] is True and level["answer_complete"] is True and level["parents"]==len(parents)
                and len(level["groups"])==(len(parents)+63)//64,"reduction lost parents")
            following=[]
            for group_index,group in enumerate(level["groups"]):
                group_prefix=prefix+f"/synthesis/level-{number:02d}-group-{group_index:04d}"
                previous=parents[group_index*64:group_index*64+64];stored=load(group_prefix+"/group.json")
                require(raw[group_prefix+"/parents.json"]==encoded(previous) and stored["version"]==1
                    and stored["level"]==number and stored["parent_offset"]==group_index*64
                    and stored["parents_sha256"]==sha(encoded(previous)) and stored["source_manifest_id"]==source_id
                    and authority["selected_at_unix_seconds"]<=stored["created_at_unix_seconds"]<authority["expires_at_unix_seconds"],
                    "derived exact parent receipts/expiry changed")
                combined,rows=SYNTH["expected_rows"](previous,load(group_prefix+"/document-plan.json")["parts"],question,group_index*64)
                GRAPH["planner"](raw,group_prefix+"/",combined,question,True,model_profile=MODEL_PROFILE)
                require(group==dict(group=group_index,parents=len(previous),complete=True,parts=len(rows),input_sha256=sha(combined)),"group accounting changed")
                for p in range((len(rows)+3)//4):
                    package=group_prefix+f"/package-{p:04d}"
                    data=dict(version=3,visibility="public",license="GPL-3.0-only",source_manifest_hex=manifest.hex(),
                        level=number,claim_scope=SYNTH["CLAIM"],model_profile=MODEL_PROFILE,inference=rows[p*4:p*4+4])
                    selected=dict(authority,selected_at_unix_seconds=stored["created_at_unix_seconds"])
                    identity=GRAPH["manifest"](raw[package+"/dataset.manifest"],raw[package+"/dataset.json"],selected,
                        f"derived-l{number:02d}-g{group_index:04d}-p{p:04d}",SYNTH["PROFILE"])
                    following.extend(GRAPH["package"](raw,package,data,identity,authority,question,layout,executed,response_bytes,index,number,True,model_profile=MODEL_PROFILE));rounds+=1
            require(level["outputs"]==len(following) and (number==1 or len(following)<len(parents))
                and level["answers"]==following and level["generation_limit_reached"] is any(
                    SYNTH["generation_limited"](a,model_profile=MODEL_PROFILE) for a in following)
                and load(prefix+f"/synthesis/level-{number:02d}-result.json")==level,"derived level output changed")
            parents=following
        require(len(parents)==1 and result["complete"] is True and result["synthesized_answer"]==parents[0]
            and result["synthesis"]["complete"] is True and result["synthesis"]["claim_scope"]==SYNTH["CLAIM"]
            and result["synthesis"]["model_answer_correctness_proven"] is False and result["synthesis"]["semantic_completeness_proven"] is False,
            "dependent result or scope changed")
        answers[node["id"]]=parents[0]
    require(5<=rounds<=32 and len({answer["job_id"] for answer in answers.values()})==5,"DAG instruction reused another node's job")
    check_summary(value["result"],authority,answers,rounds);check_summary(value["resume"],authority,answers,0)
    require(load("result.json")==value["result"] and {n for n in raw if HANDLE.fullmatch(n)}=={x["path"] for x in executed.values()},"extra or changed graph work")
    observation=value["observation"];require(observation["owner_reaped"] is True,"owner not reaped")
    observed=set();processes=[]
    for item in observation["workers"]:
        handle,worker=item["handle"],item["worker"];identifier=handle["binding"]["job_id"]
        require(identifier in executed and identifier not in observed,"unknown/duplicate actual DAG worker")
        actual=executed[identifier];base=workers[actual["node"]]
        require(item["graph_node"]==actual["graph_node"] and item["level"]==actual["level"] and handle==actual["handle"]
            and item["handle_path"]==actual["path"] and item["handle_file"]=={k:saved[actual["path"]][k] for k in ("bytes","sha256")}
            and worker["dataset_json"].encode()==actual["raw"] and worker["dataset_file"]["sha256"]==sha(actual["raw"])
            and all(worker[k]==base[k] for k in ("node","broker","service","node_namespace","runtime_lock_inode"))
            and worker["worker"] not in processes and item["alive_before_and_after"] is True
            and item["first_monotonic_ns"]<item["last_monotonic_ns"],"actual worker/receipt lineage missing")
        require(worker["runtime_lock_held"] is True and worker["network_devices"]==["lo"] and worker["ipv4_routes"]==[]
            and worker["effective_capabilities"]==0 and worker["host_home_visible"] is False and worker["other_node_state_hidden"] is True
            and all("ro" in worker["mounts"][p] for p in ("/runtime","/model","/dataset.json"))
            and all(worker["worker_namespaces"][k]!=worker["guest_namespaces"][k] for k in ("net","pid","ipc","mnt"))
            and worker["worker_namespaces"]["net"]!=worker["node_namespace"],"actual DAG worker isolation missing")
        observed.add(identifier);processes.append(worker["worker"])
    require(observed==set(executed),"not every DAG worker was observed")
    check_startup(value);check_progress(value,raw,executed,answers);check_pressure(value,raw)
    require(value["inputs-removed"]["original_input_absent"] is True and value["inputs-removed"]["original_plan_absent"] is True
        and value["inputs-removed"]["retained_graph_plan"] is True
        and all(value[phase][k] is True for phase in ("stopped","resumed") for k in
            ("all_owned_processes_ended","brokers_stopped","original_input_absent","original_plan_absent"))
        and value["resumed"]["snapshot"]==saved,"original-free immutable offline resume missing")
    CUSTODY["validate_path"](value["path"],value["peers"],layout,"inspect")
    application=value["path"]["privacy"]["exit"]["provider_application"]
    require(all(application[n]["request_packets"]>0 and application[n]["response_payload_bytes"]>=size for n,size in response_bytes.items())
        and all(value["cleanup"].values()),"protected actual reports or cleanup missing")


def evidence(work,revision):
    JOBS["guest_work"](work)
    names=("input","fresh-brokers","pause-plan","paused","ready","ready-files","running-status","continued",
        "result","result-files","observation","resume","inputs-removed","stopped","resumed")
    value={name:read(record(work,name),64*1048576) for name in names}
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
        "ready-DAG/cleanup/host proof incomplete")
    check(value["evidence"],revision)


def failure_snapshot_self_test():
    import contextlib
    import tempfile
    from unittest.mock import patch

    with tempfile.TemporaryDirectory(prefix="ready-dag-diagnostic-") as directory:
        root = Path(directory)
        write(root/"graph-plan.json", PLAN)
        write(root/"graph.json", dict(fixture="inert"))
        attempt = root/"node-0000/package-0000/work/package-0000/attempt-0001"
        attempt.mkdir(parents=True)
        for path in (attempt, *attempt.parents):
            if path == root.parent:
                break
            path.chmod(0o700)
        target = attempt/"job-0.json"
        write(target, dict(job_id="inert", state="unconfirmed"))
        receipt = attempt/"receipt-0.json"
        write(receipt, dict(status="failed", reason="inert retained diagnostic"))
        result = failure_snapshot(root)
        assert result["diagnostic_only"] and not result["success"]
        assert not result["coherent_snapshot_proven"] and not result["quiescence_proven"]
        assert not result["observed_concurrent_changes"]
        assert result["raw"][target.relative_to(root).as_posix()] == target.read_bytes().hex()
        assert result["raw"][receipt.relative_to(root).as_posix()] == receipt.read_bytes().hex()
        try:
            snapshot(root)
        except ValueError:
            pass
        else:
            raise AssertionError("success snapshot accepted a diagnostic retry")

        # A real in-place mutation after read must be visible, without claiming
        # that unchanged files form an atomic snapshot of the running workflow.
        original_fdopen = os.fdopen
        target_inode = target.stat().st_ino
        @contextlib.contextmanager
        def mutating_fdopen(fd, mode):
            with original_fdopen(fd, mode) as stream:
                class Reader:
                    def read(self, maximum):
                        value = stream.read(maximum)
                        if os.fstat(stream.fileno()).st_ino == target_inode:
                            with target.open("ab") as output:
                                output.write(b" ")
                        return value
                yield Reader()
        with patch.object(os, "fdopen", mutating_fdopen):
            changed = failure_snapshot(root)
        assert changed["observed_concurrent_changes"]
        assert changed["snapshot"][target.relative_to(root).as_posix()]["observed_changed"]
        assert not changed["coherent_snapshot_proven"]

        def rejected():
            try:
                failure_snapshot(root)
            except (ValueError, OSError):
                return
            raise AssertionError("unsafe ready-DAG diagnostic accepted")
        target.chmod(0o644); rejected(); target.chmod(0o600)
        attempt.chmod(0o755); rejected(); attempt.chmod(0o700)
        target.rename(attempt/"unexpected.bin"); rejected(); (attempt/"unexpected.bin").rename(target)
        link = attempt/"linked.json"
        link.symlink_to(target); rejected(); link.unlink()
        os.link(target, link); rejected(); link.unlink()
        invalid = root/"unrelated-dataset"
        invalid.mkdir(mode=0o700); rejected(); invalid.rmdir()
        oversized = attempt/"oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(16*1048576+1)
        oversized.chmod(0o600); rejected(); oversized.unlink()
        (root/"graph-plan.json").write_text('{"version":1,"nodes":[]}')
        rejected()
    print("ready-DAG diagnostic retry/receipt retention, concurrent-change detection and seven unsafe controls PASS")


def self_test():
    failure_snapshot_self_test()
    # Inert summary/identity controls only. No model, namespace, network or signal.
    startup=(b"compute owner_ack phase=resumed sequence=1 step=0 elapsed_ms=0\n"
        b"compute phase=resumed\ncompute phase=preparing\ncompute phase=baseline\n")
    assert startup_ack(startup)==dict(acknowledged_sequence=1,last_action="resumed",baseline_observed=True)
    assert startup_ack(b"") is None and startup_ack(startup[:-1]) is None
    assert startup_ack(startup.rsplit(b"compute phase=baseline",1)[0]) is None
    for invalid in (startup.replace(b"sequence=1",b"sequence=2"),startup.replace(b"step=0",b"step=1"),
        startup+b"compute phase=complete\n",startup+b"compute phase=baseline\n",
        startup.replace(b"compute phase=resumed\n",b"compute phase=paused\n"),
        b"compute phase=baseline\n"+startup):
        try:startup_ack(invalid)
        except ValueError:pass
        else:raise AssertionError("historical or uncorrelated startup ACK accepted")
    def log_of(raw):
        return dict(inode=[1,2],uid=1,mode=0o600,bytes=len(raw),sha256=sha(raw),hex=raw.hex())
    pause_suffix=b"compute owner_ack phase=paused sequence=2 step=0 elapsed_ms=100\ncompute phase=paused\n"
    resume_suffix=b"compute owner_ack phase=resumed sequence=3 step=0 elapsed_ms=10100\ncompute phase=resumed\n"
    startup_log=log_of(startup); paused_log=log_of(startup+pause_suffix)
    assert next_ack(paused_log,startup_log,2,"paused")["acknowledgement"]==dict(sequence=2,action="paused",step=0,elapsed_ms=100)
    resumed_log=log_of(startup+pause_suffix+resume_suffix)
    assert next_ack(resumed_log,paused_log,3,"resumed")["acknowledgement"]["elapsed_ms"]==10100
    assert next_ack(log_of(startup+pause_suffix[:12]),startup_log,2,"paused") is None
    assert next_ack(log_of(bytes.fromhex(resumed_log["hex"])+b"compute phase=complete\n"),paused_log,3,"resumed",True)["log"]==resumed_log
    for invalid in (dict(paused_log,inode=[5,6]),log_of(startup+pause_suffix.replace(b"sequence=2",b"sequence=3")),
        log_of(startup+pause_suffix.replace(b"step=0",b"step=1")),log_of(startup+pause_suffix.replace(b"elapsed_ms=100",b"elapsed_ms=600000")),
        log_of(startup+pause_suffix.replace(b"compute phase=paused",b"compute phase=resumed")),
        log_of(startup+pause_suffix+resume_suffix),dict(paused_log,sha256="0"*64)):
        try:next_ack(invalid,startup_log,2,"paused")
        except ValueError:pass
        else:raise AssertionError("uncorrelated cooperative ACK accepted")
    authority=dict(source_manifest_id="a"*64,expires_at_unix_seconds=7200,provider_keys=["b"*64,"c"*64])
    answers={n["id"]:dict(job_id=str(i)*32) for i,n in enumerate(PLAN["nodes"],1)}
    value=dict(version=2,operation="compute_public_task_graph",complete=True,execution_complete=True,answer_complete=True,
        semantic_completeness_proven=False,plan=copy.deepcopy(PLAN),
        plan_sha256=sha(encoded(PLAN)),nodes=[dict(n,complete=True,execution_complete=True,status="complete",answer_status="eos",answer=answers[n["id"]]) for n in PLAN["nodes"]],
        output=answers["e"],source_manifest_id=authority["source_manifest_id"],source_expires_unix_seconds=7200,
        provider_keys=authority["provider_keys"],rounds_this_invocation=5,scheduling="shared_ready_dependency_queue_v1",interrupted=False,
        private_data_supported=False,automatic_task_planning=False,external_actions_supported=False,model_answer_correctness_proven=False,full_b03_claimed=False)
    check_summary(value,authority,answers,5)
    for changes in (dict(scheduling="shared_source_queue_then_ordered_dependency_frontiers"),dict(rounds_this_invocation=0),
                    dict(output=answers["c"]),dict(complete=False),dict(automatic_task_planning=True),dict(source_expires_unix_seconds=7201),
                    dict(version=1),dict(execution_complete=False),dict(answer_complete=False),dict(semantic_completeness_proven=True)):
        try:check_summary(dict(value,**changes),authority,answers,5)
        except ValueError:pass
        else:raise AssertionError("wrong ready-DAG result accepted")
    pin_root=HERE.parent.parent/"workers/volparossa-ml"
    pins=read(pin_root/"model-pins.json");pins.update(read(pin_root/"model-pins-360m.json"))
    provision=dict(success=True,installed_wheels=38,model_profile=MODEL_PROFILE,model_id=MODEL_ID["model_id"],
        revision=MODEL_ID["model_revision"],download_bytes=977655758,budget_bytes=3*1024**3,
        model_pins_sha256=sha((json.dumps(pins,indent=2)+"\n").encode()),
        requirements_sha256=sha((pin_root/"requirements.lock").read_bytes()),
        runtime_autofetch_enabled=False,training_performed=False)
    check_provision(provision)
    for changed in (dict(model_profile="smollm2-135m-v1"),dict(download_bytes=523040250),
                    dict(model_pins_sha256="0"*64),dict(budget_bytes=4*1024**3)):
        try:check_provision(dict(provision,**changed))
        except ValueError:pass
        else:raise AssertionError("wrong-profile or unpinned provision accepted")
    generation=dict(version=1,stop_reason="eos",max_new_tokens=256,model_profile=MODEL_PROFILE)
    output=dict(text="Inert complete answer.",generated_tokens=256,text_truncated=False,generation=generation)
    assert SYNTH["generation_fields"](output,annotated=True,model_profile=MODEL_PROFILE)["answer_status"]=="eos"
    assert not SYNTH["generation_limited"](output,model_profile=MODEL_PROFILE)
    for changed in (dict(generation=dict(generation,stop_reason="token_limit")),dict(text_truncated=True),
                    dict(generation=dict(version=1,stop_reason="eos",max_new_tokens=64)),dict(text="")):
        try:SYNTH["generation_fields"](dict(output,**changed),annotated=True,model_profile=MODEL_PROFILE)
        except ValueError:pass
        else:raise AssertionError("incomplete or wrong-profile dependency answer accepted")
    assert HANDLE.fullmatch(f"node-0004/synthesis/level-01-group-0000/package-0000/{ATTEMPT}/job-0.json")
    # Synthetic metadata exercises the actual ordering/lease validator, not process proof.
    owner=dict(pid=100,start_ticks=1)
    fast=dict(graph_node=0,handle=dict(provider_key="a",binding=dict(job_id="a",expires_unix_seconds=600)),
        worker=dict(worker=dict(pid=101,start_ticks=2)))
    slow=dict(graph_node=1,handle=dict(provider_key="b",binding=dict(job_id="b",expires_unix_seconds=600)),
        worker=dict(worker=dict(pid=102,start_ticks=3)))
    plan=dict(fixture_only=True,method="cooperative-cpu-pressure-floor",owner=owner,initial=[fast,slow],fast=fast,slow=slow)
    status=dict(state="running",binding=slow["handle"]["binding"],report_json=None,report_sha256=None)
    child=dict(graph_node=2,handle=dict(provider_key="a"),first_monotonic_ns=21)
    progress={"pause-plan":plan,"paused":dict(plan=plan,cooperatively_paused=True,worker_alive=True,
        worker_not_signal_stopped=True,fast_alive_at_injection=True,
        boottime_ns=1000,monotonic_ns=20,unix_seconds=100),
        "ready":dict(owner=owner,same_owner_alive=True,slow_cooperatively_paused=True,slow_worker_alive=True,slow_receipt_absent=True,
            boottime_ns=2000,unix_seconds=200,workers=[child],c_result=dict(complete=True,synthesized_answer=answers["c"])),
        "continued":dict(owner=owner,boottime_ns=3000,unix_seconds=300,original_handle=slow["handle"],
            worker=slow["worker"]["worker"],method="cooperative-cpu-pressure-floor",same_owner_alive=True,original_status=status),
        "running-status":status,"ready-files":dict(raw={},snapshot={}),"result-files":dict(snapshot={})}
    executed={"a":dict(handle=fast["handle"]),"b":dict(handle=slow["handle"])}
    check_progress(progress,{},executed,answers)
    mutations=(
        lambda p:p["ready"].update(slow_cooperatively_paused=False),
        lambda p:p["ready"].update(same_owner_alive=False),
        lambda p:p["ready"].update(unix_seconds=601),
        lambda p:p["continued"].update(unix_seconds=600),
        lambda p:p["ready"]["workers"][0].update(graph_node=3),
        lambda p:p["ready"]["workers"][0]["handle"].update(provider_key="b"),
        lambda p:p["ready"]["workers"][0].update(first_monotonic_ns=19),
        lambda p:p["running-status"].update(state="complete"),
        lambda p:p["ready"]["c_result"].update(complete=False))
    for mutate in mutations:
        invalid=copy.deepcopy(progress);mutate(invalid)
        try:check_progress(invalid,{},executed,answers)
        except ValueError:pass
        else:raise AssertionError("invalid paused-worker dependency boundary accepted")
    injected,held,restored=pressure()["self_test"]()
    # Exercise the complete ACK/mount/quiet-hold/terminal-report join using inert records.
    flow=copy.deepcopy(progress);pause_ack=next_ack(paused_log,startup_log,2,"paused")
    resume_ack=next_ack(resumed_log,paused_log,3,"resumed")
    flow["pause-plan"]["startup"]=dict(node="b",log=startup_log,acknowledgement=startup_ack(startup))
    flow["pause-plan"]["brokers"]={name:item["process"] for name,item in injected["plan"]["brokers"].items()}
    flow["pause-plan"]["slow"]["handle_path"]="node-0001/job-0.json"
    flow["paused"].update(pause_ack,pressure=injected,boottime_ns=2)
    flow["ready"].update(acknowledgement=pause_ack["acknowledgement"],pressure=held,boottime_ns=3)
    flow["continued"].update(resume_ack,pressure=restored,boottime_ns=5_000_000_004)
    worker_report=dict(owner_control=dict(enabled=True,records_received=3,last_sequence=3,
        pause_count=1,resume_count=2,paused_ms=10000))
    receipt=encoded(dict(status=dict(report_json=json.dumps(worker_report))))
    check_pressure(flow,{"node-0001/receipt-b.json":receipt})
    for mutate in (
        lambda p:p["ready"]["acknowledgement"].update(sequence=3),
        lambda p:p["continued"].update(boottime_ns=5_000_000_003),
        lambda p:p["pause-plan"]["startup"].update(node="a"),
        lambda p:p["continued"]["pressure"].update(source_removed=False)):
        invalid=copy.deepcopy(flow);mutate(invalid)
        try:check_pressure(invalid,{"node-0001/receipt-b.json":receipt})
        except ValueError:pass
        else:raise AssertionError("unbound control/mount/quiet-hold accepted")
    worker_report["owner_control"]["paused_ms"]=0
    try:check_pressure(flow,{"node-0001/receipt-b.json":encoded(dict(status=dict(report_json=json.dumps(worker_report))))})
    except ValueError:pass
    else:raise AssertionError("worker result omitted observed pause")
    print("ready-DAG startup/cooperative ACK, selected-profile/EOS, schema/identity and ordering controls PASS; no model, network or signal executed")


def main(args):
    command=args[0]
    if command=="self-test":self_test()
    elif command=="prepare":prepare(Path(args[1]))
    elif command=="fresh-brokers":fresh_brokers(Path(args[1]))
    elif command=="pause":pause(Path(args[1]),int(args[2]))
    elif command=="observe-ready":observe_ready(Path(args[1]))
    elif command=="continue-worker":continue_worker(Path(args[1]))
    elif command=="cleanup-worker":continue_worker(Path(args[1]),True)
    elif command=="observe-rest":observe_rest(Path(args[1]))
    elif command=="collect":collect(Path(args[1]),args[2])
    elif command=="collect-failure":collect_failure(Path(args[1]),args[2])
    elif command=="remove-inputs":remove_inputs(Path(args[1]))
    elif command=="stopped":stopped(Path(args[1]))
    elif command=="resumed":stopped(Path(args[1]),True)
    elif command=="evidence":evidence(Path(args[1]),args[2])
    elif command=="finalize":finalize(Path(args[1]),args[2],int(args[3]),args[4]=="true",int(args[5]),args[6],args[7])
    elif command=="report":report(read(Path(args[1]),64*1048576),args[2])
    else:raise ValueError("unknown ready-DAG fixture command")


if __name__=="__main__":main(sys.argv[1:])
