#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Public catalog fixture helpers. Pure tests are not model or overlay evidence."""

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import struct
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ART = runpy.run_path(str(HERE / "agent-artifact-smoke.py"))
TRAIN = ART["TRAIN"]
read, write, require = (ART[key] for key in ("read", "write", "require"))
CATALOG_NAME = "disposable-agent-source-catalog"
CATALOG_TYPE = "application/vnd.volparossa.agent-source-catalog.v1+json"
DATASET_TYPE = "application/vnd.volparossa.agent-dataset.v1+json"
MAX_INDEX = 44 + 65536 * 36 + 32


def digest(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def public_bytes(path, maximum, empty=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and (empty or info.st_size > 0)
            and info.st_size <= maximum, "public fixture input ownership/type/bound differs")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "public fixture input changed during read")
    return raw


def catalog_body(rows):
    return dict(version=1, visibility="public", purpose="agent_training", dataset_profile=DATASET_TYPE,
                license="GPL-3.0-only", sources=rows)


def check_catalog(value, revision):
    require(value == catalog_body(value.get("sources")) and type(value["version"]) is int
            and isinstance(value["sources"], list) and type(revision) is int
            and len(value["sources"]) == revision and revision in (1, 2), "wrong fixture catalog profile")
    for index, entry in enumerate(value["sources"]):
        require(set(entry) == {"name", "revision", "manifest_id"}
                and entry["name"] == ("disposable-agent-dataset" if index == 0 else "disposable-agent-dataset-next")
                and type(entry["revision"]) is int and entry["revision"] == 1
                and isinstance(entry["manifest_id"], str) and TRAIN["HASH"].fullmatch(entry["manifest_id"])
                and entry["manifest_id"] != "0" * 64, "wrong exact fixture dataset identity")


def catalog_input(path, publisher, number):
    root, number = ART["private_root"](path), int(number)
    require(TRAIN["HASH"].fullmatch(publisher) and number in (1, 2), "wrong catalog publisher/revision")
    if number == 1:
        rows = [dict(name="disposable-agent-dataset", revision=1,
                     manifest_id=digest(public_bytes(root / "dataset.pb", 65536))["sha256"])]
    else:
        previous = json.loads(public_bytes(root / "catalog-1.json", 65536))
        check_catalog(previous, 1)
        rows = previous["sources"] + [dict(name="disposable-agent-dataset-next", revision=1,
            manifest_id=digest(public_bytes(root / "dataset-next.pb", 65536))["sha256"])]
    value = catalog_body(rows)
    check_catalog(value, number)
    write(root / f"catalog-{number}.json", value)
    return dict(version=1, publisher_key=publisher, catalog_revision=number, sources=rows,
                body=digest(public_bytes(root / f"catalog-{number}.json", 65536)))


def next_dataset(revision, source):
    require(len(revision) == 40 and all(char in "0123456789abcdef" for char in revision), "invalid public source revision")
    privacy = ("A global timing observer may correlate this low-latency traffic; colluding relay/exit operators "
               "and local root remain important threats.")
    participation = "Installation leaves participation off until explicitly configured."
    text = source.replace("\n", " ")
    require(privacy in text and participation in text, "normative public README context changed")
    return dict(version=1, visibility="public", license="GPL-3.0-only", source_revision=revision,
        train=[dict(question="Who may correlate VOLPAROSSA's low-latency traffic?", context=privacy,
                    answer="A global timing observer."),
               dict(question="When does installed VOLPAROSSA begin participating?", context=participation,
                    answer="Only after explicit configuration.")],
        heldout=[dict(question="Is participation automatically active upon installation?", context=participation, answer="No.")],
        inference=[dict(question="What privacy limitation does this public text describe?", context=privacy)])


def new_source(path, revision):
    root = ART["private_root"](path)
    ready = public_bytes(root / "loop-first-worker.ready", 0, empty=True)
    raw = public_bytes(root / "loop-1-isolation.raw.json", 262144)
    observation = json.loads(raw)
    TRAIN["check_isolation"](observation)
    worker = observation["worker"]
    require(observation["node_lineage"]["node"] == "relay4" and TRAIN["alive"](worker),
            "late dataset was not created during the actual first R4 worker")
    value = next_dataset(revision, (HERE / "agent-artifact-README.md").read_text())
    validation = root / "loop/validation-input/dataset.json"
    if validation.exists():
        selected = read(validation)
        normalize = lambda text: " ".join(text.split()).lower()
        questions = {normalize(row["question"]) for row in selected["heldout"] + selected["inference"]}
        require(all(normalize(row["question"]) not in questions for row in value["train"]),
                "late training questions overlap the explicitly selected validation set")
    write(root / "dataset-next.json", value)
    require(TRAIN["alive"](worker), "first actual worker ended before late-source creation finished")
    result = dict(version=1, source_revision=revision, created_unix_seconds=int(time.time()),
        created_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME), first_worker=worker,
        first_worker_ready=digest(ready), first_worker_isolation=digest(raw),
        dataset=digest(public_bytes(root / "dataset-next.json", 262144)), first_worker_alive=True)
    write(root / "catalog-late-source.json", result)
    return result


def publication(raw, encoded, publisher, name, revision, content_type):
    fields = ART["CUSTODY"]["fields"]
    envelope = fields(encoded, 65536)
    body = fields(envelope[1], 65536)
    payload = fields(body[8], 65536)
    chunk = fields(payload[5], 128)
    require(set(envelope) == {1, 2} and len(envelope[2]) == 64 and body[1] == body[6] == 1
            and body[2].hex() == publisher and len(body[5]) == 32 and 0 < body[3] < body[4]
            and body[7] == hashlib.sha256(body[8]).digest(), "original public envelope binding differs")
    require(0 < len(raw) <= 262144 and payload[1] == name.encode() and payload[2] == revision
            and payload[3] == content_type.encode() and payload[4] == len(raw)
            and payload[6] == chunk[1] == hashlib.sha256(raw).digest() and chunk[2] == len(raw),
            "original public single-chunk object differs")
    return dict(name=name, revision=revision, created_unix_seconds=body[3], expires_unix_seconds=body[4],
                manifest=digest(encoded), manifest_hex=encoded.hex(), body=digest(raw), body_hex=raw.hex())


def original(path, publisher, number):
    root, number = ART["private_root"](path), int(number)
    require(TRAIN["HASH"].fullmatch(publisher) and number in (1, 2), "wrong original catalog request")
    raw = public_bytes(root / f"catalog-{number}.json", 65536)
    catalog = publication(raw, public_bytes(root / f"catalog-{number}.pb", 65536), publisher,
                          CATALOG_NAME, number, CATALOG_TYPE)
    catalog["sources"] = json.loads(raw)["sources"]
    result = dict(version=1, publisher_key=publisher, catalog_revision=number, catalog=catalog, dataset_next=None)
    if number == 2:
        result["dataset_next"] = publication(public_bytes(root / "dataset-next.json", 262144),
            public_bytes(root / "dataset-next.pb", 65536), publisher, "disposable-agent-dataset-next", 1, DATASET_TYPE)
    check_original(result, publisher)
    return result


def check_original(value, publisher):
    require(value["version"] == 1 and value["publisher_key"] == publisher, "catalog publisher export changed")
    number, catalog = value["catalog_revision"], value["catalog"]
    raw, encoded = bytes.fromhex(catalog["body_hex"]), bytes.fromhex(catalog["manifest_hex"])
    parsed = json.loads(raw)
    check_catalog(parsed, number)
    expected = publication(raw, encoded, publisher, CATALOG_NAME, number, CATALOG_TYPE)
    require(catalog == dict(expected, sources=parsed["sources"]), "catalog export changed original bytes")
    if number == 1:
        require(value["dataset_next"] is None, "later dataset already included in first export")
    else:
        data = value["dataset_next"]
        require(data == publication(bytes.fromhex(data["body_hex"]), bytes.fromhex(data["manifest_hex"]), publisher,
                    "disposable-agent-dataset-next", 1, DATASET_TYPE)
                and catalog["sources"][1]["manifest_id"] == data["manifest"]["sha256"], "later catalog relabelled its dataset")


def index_absent(owner, index, metadata, target):
    expected = b"VPCC0001" + owner[8:40] + struct.pack("<QQI", metadata.st_dev, metadata.st_ino, metadata.st_uid)
    require(len(owner) == 60 and owner == expected, "native cache ownership marker differs")
    require(76 <= len(index) <= MAX_INDEX and index[:8] == b"VPCI0001" and index[8:40] == owner[8:40],
            "native cache index header differs")
    count = int.from_bytes(index[40:44], "little")
    require(count <= 65536 and len(index) == 76 + count * 36
            and hashlib.sha256(index[:-32]).digest() == index[-32:], "native index count/checksum differs")
    hashes = set()
    for offset in range(44, len(index) - 32, 36):
        identity = index[offset:offset + 32].hex()
        length = int.from_bytes(index[offset + 32:offset + 36], "little")
        require(identity not in hashes and 0 < length <= 262144, "invalid native cache index entry")
        hashes.add(identity)
    require(target not in hashes, "later source already exists in the real cache index")
    return count


def cold(path, target):
    path = Path(path)
    require(TRAIN["HASH"].fullmatch(target) and path.is_absolute() and path.name == "agent-loop-cache"
            and path.parent.name == "state-relay4", "wrong cold cache/target identity")
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_uid == os.getuid(), "cold cache is not this caller's owned private store")
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owner_fd = None
    try:
        require(os.fstat(directory).st_ino == metadata.st_ino and os.fstat(directory).st_dev == metadata.st_dev,
                "cache directory changed")
        owner_fd = os.open(".volparossa-owner-v1", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def bounded(fd, maximum):
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == metadata.st_uid
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= maximum, "invalid native cache metadata file")
            with os.fdopen(os.dup(fd), "rb") as stream:
                raw = stream.read(maximum + 1)
            require(len(raw) == info.st_size, "native cache metadata changed")
            return raw
        owner = bounded(owner_fd, 60)
        index_fd = os.open(".volparossa-index-v1", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            index = bounded(index_fd, MAX_INDEX)
        finally:
            os.close(index_fd)
        count = index_absent(owner, index, metadata, target)
        for name in (target, ".volparossa-index-next-v1", ".volparossa-chunk-next-v1"):
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("later source or unfinished cache transaction already present")
        return dict(version=1, dataset_sha256=target, observed_unix_seconds=int(time.time()),
            observed_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            cache=dict(device=metadata.st_dev, inode=metadata.st_ino, uid=metadata.st_uid),
            owner=digest(owner), index=digest(index), indexed_entries=count, target_index_absent=True,
            target_file_absent=True, nonblocking_lock_acquired=True, payload_read=False)
    finally:
        if owner_fd is not None:
            os.close(owner_fd)
        os.close(directory)


def check_late(value, original_two, observation):
    require(value["version"] == observation["version"] == 1 and value["first_worker_alive"] is True
            and value["first_worker_ready"] == digest(b"") and value["first_worker_isolation"]["bytes"] > 0
            and value["dataset"] == original_two["dataset_next"]["body"]
            and value["dataset"]["sha256"] == observation["dataset_sha256"]
            and 0 < value["created_boottime_ns"] <= observation["observed_boottime_ns"]
            and 0 < value["created_unix_seconds"] <= observation["observed_unix_seconds"]
            and observation["target_index_absent"] is observation["target_file_absent"] is observation["nonblocking_lock_acquired"] is True
            and observation["payload_read"] is False, "late source timing or real cold-cache evidence differs")


def self_test():
    # Synthetic metadata only; no model, process signal, network or real training occurs.
    value = catalog_body([dict(name="disposable-agent-dataset", revision=1, manifest_id="ab" * 32)])
    check_catalog(value, 1)
    wire = runpy.run_path(str(HERE / "test-content-custody-smoke.py"))["wire"]
    raw = json.dumps(value).encode()
    payload = wire({1:CATALOG_NAME.encode(), 2:1, 3:CATALOG_TYPE.encode(), 4:len(raw),
        5:wire({1:hashlib.sha256(raw).digest(), 2:len(raw)}), 6:hashlib.sha256(raw).digest()})
    encoded = wire({1:wire({1:1, 2:b"p" * 32, 3:100, 4:900, 5:b"n" * 32, 6:1,
        7:hashlib.sha256(payload).digest(), 8:payload}), 2:b"s" * 64})
    original_one = dict(version=1, publisher_key=(b"p" * 32).hex(), catalog_revision=1,
        catalog=dict(publication(raw, encoded, (b"p" * 32).hex(), CATALOG_NAME, 1, CATALOG_TYPE), sources=value["sources"]),
        dataset_next=None)
    check_original(original_one, (b"p" * 32).hex())
    changed = copy.deepcopy(original_one)
    changed["catalog"]["expires_unix_seconds"] += 1
    try:
        check_original(changed, (b"p" * 32).hex())
    except ValueError:
        pass
    else:
        raise AssertionError("original expiry substitution accepted")
    for field, bad in (("visibility", "private"), ("purpose", "anything"), ("license", "unknown")):
        wrong = copy.deepcopy(value)
        wrong[field] = bad
        try:
            check_catalog(wrong, 1)
        except ValueError:
            continue
        raise AssertionError("invalid catalog profile accepted")
    source = next_dataset("a" * 40, (HERE.parent.parent / "README.md").read_text())
    assert len(source["train"]) == 2 and source["train"][0]["question"] != source["heldout"][0]["question"]
    with tempfile.TemporaryDirectory(prefix="catalog-cache-parser-") as temporary:
        cache = Path(temporary) / "state-relay4/agent-loop-cache"
        cache.mkdir(parents=True, mode=0o700)
        metadata = cache.stat()
        owner = b"VPCC0001" + b"x" * 32 + struct.pack("<QQI", metadata.st_dev, metadata.st_ino, metadata.st_uid)
        index = b"VPCI0001" + b"x" * 32 + (0).to_bytes(4, "little")
        index += hashlib.sha256(index).digest()
        for name, raw in ((".volparossa-owner-v1", owner), (".volparossa-index-v1", index)):
            (cache / name).write_bytes(raw)
            (cache / name).chmod(0o600)
        proof = cold(cache, "ab" * 32)
        assert proof["indexed_entries"] == 0 and proof["payload_read"] is False
        (cache / ("ab" * 32)).touch(mode=0o600)
        try:
            cold(cache, "ab" * 32)
        except ValueError:
            pass
        else:
            raise AssertionError("present cold target accepted")
        for wrong in (index[:-1] + b"!", index + b"x"):
            try:
                index_absent(owner, wrong, metadata, "ab" * 32)
            except ValueError:
                continue
            raise AssertionError("invalid index accepted")
    late = dict(version=1, first_worker_alive=True, first_worker_ready=digest(b""), first_worker_isolation=digest(b"synthetic"),
                dataset=digest(b"public"), created_boottime_ns=10, created_unix_seconds=1)
    original_two = dict(dataset_next=dict(body=digest(b"public")))
    proof.update(dataset_sha256=digest(b"public")["sha256"], observed_boottime_ns=11, observed_unix_seconds=2)
    check_late(late, original_two, proof)
    for field, bad in (("created_boottime_ns", 12), ("first_worker_alive", False), ("dataset", digest(b"changed"))):
        changed = dict(late, **{field:bad})
        try:
            check_late(changed, original_two, proof)
        except ValueError:
            continue
        raise AssertionError("invalid late-source timing accepted")
    print("catalog public-source/profile, late timing and owned locked cold-index tests PASS; synthetic only")


def main():
    args = sys.argv[1:]
    if args == ["self-test"]:
        self_test()
        return
    if len(args) == 4 and args[0] == "catalog-input":
        result = catalog_input(*args[1:])
    elif len(args) == 3 and args[0] == "new-source":
        result = new_source(*args[1:])
    elif len(args) == 4 and args[0] == "original":
        result = original(*args[1:])
    elif len(args) == 3 and args[0] == "cold":
        result = cold(*args[1:])
    else:
        raise ValueError("usage: catalog-input ROOT KEY 1|2 | new-source ROOT SHA | original ROOT KEY 1|2 | cold CACHE SHA | self-test")
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()
