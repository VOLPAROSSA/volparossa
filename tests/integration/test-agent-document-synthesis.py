#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic evidence-parser tests only; no tokenizer/model/signature execution proof."""

import copy
import hashlib
import json
from pathlib import Path
import runpy

HERE = Path(__file__).resolve().parent
DOC = runpy.run_path(str(HERE / "agent-public-document-smoke.py"))
SYN = DOC["SYNTHESIS"]
sha, encoded = SYN["sha"], SYN["encoded"]
ATTEMPT = SYN["ATTEMPT"]
WIRE = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["wire"]


def snapshots(value, raw):
    previous = value["files"]["snapshot"]
    value["files"]["raw"] = {name: data.hex() for name, data in raw.items()}
    value["files"]["snapshot"] = {name: {"bytes": len(data), "sha256": sha(data),
        "inode": previous.get(name, {}).get("inode", [1, index + 5000])} for index, (name, data) in enumerate(raw.items())}
    value["first_files"]["snapshot"] = {name.removeprefix("package-0000/"): item
        for name, item in value["files"]["snapshot"].items() if name.startswith("package-0000/")}
    value["resumed"]["snapshot"] = copy.deepcopy(value["files"]["snapshot"])
    value["admission"]["handles"] = [{key: value["files"]["snapshot"][f"package-0000/{ATTEMPT}/job-{n}.json"][key]
                                     for key in ("bytes", "sha256")} for n in (0, 1)]


def fixture():
    value = DOC["contract_fixture"]()
    for index, worker in enumerate(value["observation"]["workers"]):
        worker["service"] = dict(pid=8000 + index, start_ticks=7000 + index)
    raw = {name: bytes.fromhex(data) for name, data in value["files"]["raw"].items()}
    load = lambda name: json.loads(raw[name])
    save = lambda name, data: raw.update({name: encoded(data)})
    enrollment = load("document.json")
    enrollment["synthesize"] = True
    save("document.json", enrollment)
    parents, templates, reports = [], [], []
    for index in range(2):
        prefix = f"package-{index:04}/{ATTEMPT}"
        batch = load(prefix + "/result.json")
        ordered = []
        for slot, part in enumerate(batch["jobs"]):
            handle = part["handle"]
            receipt_name = prefix + f"/receipt-{handle['binding']['job_id']}.json"
            receipt = load(receipt_name)
            status = receipt["status"]
            report = json.loads(status["report_json"])
            for local, output in enumerate(report["outputs"]):
                output.update(sample_index=local, generated_tokens=12, text_truncated=False)
            status.update(report_json=encoded(report).decode(), report_sha256=sha(encoded(report)))
            part["report_sha256"] = status["report_sha256"]
            save(receipt_name, receipt)
            if index == 0:
                value["statuses"][slot] = copy.deepcopy(status)
                templates.append(copy.deepcopy(handle))
                reports.append(copy.deepcopy(report))
            for local, row in enumerate(handle["binding"]["row_indices"]):
                position = index * 4 + row
                for result in ("first", "result", "resume"):
                    for answer in value[result]["answers"]:
                        if answer["source_part"] == position:
                            answer["report_sha256"] = status["report_sha256"]
                source_range = load("document-plan.json")["parts"][position]
                ordered.append((position, SYN["answer"](report["outputs"][local], handle, status,
                    batch["dataset_manifest_id"], source_range["start"], source_range["end"], local)))
        parents.extend(answer for _, answer in sorted(ordered))
        save(prefix + "/result.json", batch)

    def manifest(body, name):
        payload = WIRE({1: name.encode(), 2: 1, 3: SYN["PROFILE"].encode(), 4: len(body),
                        5: WIRE({1: hashlib.sha256(body).digest(), 2: len(body)}), 6: hashlib.sha256(body).digest()})
        envelope = WIRE({1: 1, 2: bytes.fromhex(enrollment["publisher_key"]), 3: 1100, 4: 3000,
                         5: b"n" * 32, 6: 1, 7: hashlib.sha256(payload).digest(), 8: payload})
        return WIRE({1: envelope, 2: b"s" * 64})

    levels, observed = [], []
    for number, count in ((1, 2), (2, 1)):
        prefix = f"synthesis/level-{number:02}-group-0000"
        text = "".join(parent["text"] + "\n" for parent in parents).encode()
        parts = [{"start": n * len(text) // count, "end": (n + 1) * len(text) // count,
                  "prompt_tokens": 170} for n in range(count)]
        _, rows = SYN["expected_rows"](parents, parts, DOC["QUESTION"], 0)
        save(prefix + "/parents.json", parents)
        save(prefix + "/group.json", dict(version=1, level=number, parent_offset=0,
            parents_sha256=sha(encoded(parents)), source_manifest_id=enrollment["source_manifest_id"], created_at_unix_seconds=1100))
        plan = dict(version=1, source_sha256=sha(text), source_bytes=len(text), question_sha256=sha(DOC["QUESTION"].encode()),
            model_id=DOC["MODEL"], model_revision=DOC["TRAIN"]["MODEL_REVISION"], tokenizer_sha256=DOC["TOKENIZER"],
            prompt_limit=192, parts=parts, synthesis=True)
        save(prefix + "/document-plan.json", plan)
        save(prefix + "/planner-input.json", dict(version=1, visibility="public", license="GPL-3.0-only",
            document=text.decode(), question=DOC["QUESTION"], synthesis=True))
        save(prefix + "/tokenizer/document-plan.json", plan)
        planner = dict(mode="plan_document", status="ok", device="cpu", model_weights_loaded=False, updates_completed=0,
            dataset=dict(sha256=sha(raw[prefix + "/planner-input.json"]), synthesis=True),
            artifacts=[dict(relative_path="document-plan.json", bytes=len(encoded(plan)), sha256=sha(encoded(plan)))])
        save(prefix + "/tokenizer/report.json", planner)
        planner["supervisor"] = copy.deepcopy(reports[0]["supervisor"])
        save(prefix + "/tokenizer-report.json", planner)
        package = prefix + "/package-0000"
        data = dict(version=3, visibility="public", license="GPL-3.0-only", source_manifest_hex=raw["source.manifest"].hex(),
            level=number, claim_scope=SYN["CLAIM"], inference=rows)
        save(package + "/dataset.json", data)
        raw[package + "/dataset.manifest"] = manifest(encoded(data), f"derived-l{number:02}-g0000-p0000")
        manifest_id = sha(raw[package + "/dataset.manifest"])
        raw[package + "/work/package-0000/dataset.json"] = encoded(data)
        raw[package + "/work/package-0000/manifest.bin"] = raw[package + "/dataset.manifest"]
        batch = dict(operation="compute_distribute", complete=True, dataset_manifest_id=manifest_id,
                     task=DOC["TASK"], provider_count=count, jobs=[], outputs=[None] * count)
        following = []
        for slot in range(count):
            handle = copy.deepcopy(templates[slot])
            handle["capabilities"]["derived_inference_v3"] = True
            derived = copy.deepcopy(data)
            derived["inference"] = [rows[slot]]
            binding = handle["binding"]
            binding.update(job_id=f"{number * 10 + slot:032x}", dataset_manifest_id=manifest_id,
                           dataset_sha256=sha(encoded(derived)), row_indices=[slot])
            actual = copy.deepcopy(reports[slot])
            actual["dataset"] = dict(version=3, level=number, sha256=sha(encoded(derived)),
                                     source_manifest_sha256=enrollment["source_manifest_id"])
            actual["outputs"] = [dict(sample_index=0, text=f"synthetic reduction {number}/{slot}", generated_tokens=12, text_truncated=False)]
            status = dict(binding=binding, state="complete", report_json=encoded(actual).decode(), report_sha256=sha(encoded(actual)))
            batch["jobs"].append(dict(handle=handle, state="complete", report_sha256=status["report_sha256"]))
            batch["outputs"][slot] = dict(sample_index=slot, provider_key=handle["provider_key"],
                job_id=binding["job_id"], text=actual["outputs"][0]["text"])
            attempt = package + "/" + ATTEMPT
            path = attempt + f"/job-{slot}.json"
            save(path, handle)
            save(attempt + f"/receipt-{binding['job_id']}.json", dict(version=1, handle=handle, status=status))
            inputs = rows[slot]["inputs"]
            following.append(SYN["answer"](actual["outputs"][0], handle, status, manifest_id,
                min(row["source_start"] for row in inputs), max(row["source_end"] for row in inputs), 0))
            worker = copy.deepcopy(value["observation"]["workers"][slot])
            worker["worker"] = dict(pid=10000 + number * 10 + slot, start_ticks=20000 + number * 10 + slot)
            worker.update(dataset_json=encoded(derived).decode(), dataset_file=dict(bytes=len(encoded(derived)), sha256=sha(encoded(derived))))
            worker["owned_processes"] = [worker["worker"]]
            observed.append(dict(level=number, group=0, package=0, handle_path=path, handle=handle,
                handle_file=dict(bytes=len(encoded(handle)), sha256=sha(encoded(handle))), worker=worker,
                first_monotonic_ns=2000, last_monotonic_ns=2100, alive_before_and_after=True))
        save(package + "/" + ATTEMPT + "/result.json", batch)
        level = dict(level=number, complete=True, parents=len(parents), outputs=len(following),
            groups=[dict(group=0, parents=len(parents), complete=True, parts=count, input_sha256=sha(text))],
            answers=following, generation_limit_reached=False)
        save(f"synthesis/level-{number:02}-result.json", level)
        levels.append(level)
        parents = following
    value["synthesis_observation"] = dict(owner=dict(pid=9000, start_ticks=9000), owner_reaped=True, workers=observed)
    value["first"]["joining"] = "awaiting_fragments_before_peer_synthesis"
    for key in ("result", "resume"):
        value[key].update(joining="hierarchical_peer_synthesis", synthesized_answer=parents[0],
            synthesis=dict(complete=True, levels=levels, generation_limit_reached=False, claim_scope=SYN["CLAIM"],
                           model_answer_correctness_proven=False, semantic_completeness_proven=False))
    value["result"]["rounds_this_invocation"] = 3
    for key in ("stopped", "resumed"):
        value[key].update(synthesis_workers_ended=True, synthesis_worker_identities=[item["worker"]["worker"] for item in observed])
    snapshots(value, raw)
    return value, raw


def main():
    original, raw = fixture()
    DOC["check_evidence"](original, "a" * 40)
    mutations = [
        lambda value: value["result"]["synthesis"]["levels"].pop(),
        lambda value: value["result"]["synthesized_answer"].update(text="invented final answer"),
        lambda value: value["resume"]["synthesis"].update(semantic_completeness_proven=True),
        lambda value: value["synthesis_observation"]["workers"][-1]["worker"].update(network_devices=["eth0"]),
        lambda value: value["synthesis_observation"]["workers"][-1]["handle"]["capabilities"].update(derived_inference_v3=False),
        lambda value: value["resumed"].update(synthesis_workers_ended=False),
    ]
    for mutate in mutations:
        invalid = copy.deepcopy(original)
        mutate(invalid)
        try:
            DOC["check_evidence"](invalid, "a" * 40)
        except (ValueError, KeyError):
            pass
        else:
            raise AssertionError("invalid synthesized output/provenance/isolation/cleanup accepted")
    for relative, mutate in (
        ("synthesis/level-01-group-0000/parents.json", lambda data: data[0].update(report_sha256="0" * 64)),
        ("synthesis/level-02-group-0000/document-plan.json", lambda data: data["parts"][0].update(prompt_tokens=193)),
        ("synthesis/level-01-group-0000/package-0000/dataset.json", lambda data: data["inference"][0]["inputs"][0].update(piece_start=1)),
    ):
        invalid, changed = copy.deepcopy(original), copy.deepcopy(raw)
        data = json.loads(changed[relative])
        mutate(data)
        changed[relative] = encoded(data)
        snapshots(invalid, changed)
        try:
            DOC["check_evidence"](invalid, "a" * 40)
        except (ValueError, KeyError):
            pass
        else:
            raise AssertionError("changed retained parent/prompt/source bytes accepted")
    output = dict(sample_index=0, text="bounded", generated_tokens=64, text_truncated=False)
    handle = original["synthesis_observation"]["workers"][0]["handle"]
    SYN["answer"](output, handle, dict(report_sha256="a" * 64), "b" * 64, 0, 1, 0)
    for field, wrong in (("text_truncated", True), ("generated_tokens", 65), ("sample_index", 1), ("text", "")):
        invalid = dict(output, **{field: wrong})
        try:
            SYN["answer"](invalid, handle, dict(report_sha256="a" * 64), "b" * 64, 0, 1, 0)
        except ValueError:
            pass
        else:
            raise AssertionError("wire-truncated or invalid generated output accepted")
    print("synthetic 6→2→1 receipt/range/isolation/resume parser checks passed; no model, tokenizer or network executed")


if __name__ == "__main__":
    main()
