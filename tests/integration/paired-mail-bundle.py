#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fetch the original Mail Actions ZIP, pin every application input, stage the private guest."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
REPO = "VOLPAROSSA/volparossa-mail"
PINS = json.loads((HERE / "paired-mail-pins.json").read_bytes())
RUNTIME = "mail-custody-runtime.tar.gz"
RECEIPT = "paired-mail-supply.json"
NATIVE = "node_modules/@signalapp/libsignal-client/prebuilds/linux-x64/@signalapp+libsignal-client.node"
NODE = "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def api(path, output=None):
    result = subprocess.run(["gh","api","repos/" + REPO + "/" + path], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdout=output or subprocess.PIPE, timeout=240, check=True)
    if output is None:
        return json.loads(result.stdout)


def retrieve(destination):
    pin = PINS["actions"]
    run = api("actions/runs/" + str(pin["run_id"]))
    artifact = api("actions/artifacts/" + str(pin["artifact_id"]))
    require(run["path"] == ".github/workflows/native-owner-inbox.yml" and run["status"] == "completed" and
            run["conclusion"] == "success" and run["head_sha"] == PINS["mail_revision"] and
            run["run_attempt"] == pin["attempt"] and run["head_repository"]["full_name"] == REPO, "wrong producer workflow")
    require(artifact["workflow_run"]["id"] == pin["run_id"] and artifact["workflow_run"]["head_sha"] == PINS["mail_revision"]
            and artifact["name"] == f"mail-custody-runtime-{pin['run_id']}-{pin['attempt']}" and
            artifact["digest"] == "sha256:"+pin["zip_sha256"] and artifact["size_in_bytes"] == pin["zip_bytes"]
            and not artifact["expired"], "wrong producer artifact")
    parts = destination.parent
    with tempfile.TemporaryDirectory(dir=parts) as scratch:
        tmp = Path(scratch)
        original = tmp / "original.zip"
        with original.open("xb") as out:
            api("actions/artifacts/" + str(pin["artifact_id"]) + "/zip", out)
        require(original.stat().st_size == pin["zip_bytes"] and digest(original) == pin["zip_sha256"], "original ZIP mismatch")
        with zipfile.ZipFile(original) as zipped:
            require(zipped.namelist() == [RUNTIME] and 0 < zipped.getinfo(RUNTIME).file_size <= 160_000_000,
                    "unexpected original ZIP inventory")
            with zipped.open(RUNTIME) as source, (tmp/RUNTIME).open("xb") as target:
                shutil.copyfileobj(source, target)
        require(digest(tmp/RUNTIME) == pin["runtime_sha256"], "runtime digest mismatch")
        with tarfile.open(tmp/"transfer.tar","w") as bundle:
            bundle.add(tmp/RUNTIME, arcname=RUNTIME)
            for name, sha in PINS["source_files"].items():
                url = f"https://raw.githubusercontent.com/{REPO}/{PINS['mail_revision']}/{name}"
                with urllib.request.urlopen(url, timeout=30) as response:
                    raw = response.read(512*1024)
                require(hashlib.sha256(raw).hexdigest() == sha, "selected Mail source mismatch")
                member = tarfile.TarInfo("source/"+name)
                member.size=len(raw)
                member.mode=0o444
                bundle.addfile(member, io.BytesIO(raw))
        # Never replace a previous receipt or publish a partially written transfer.
        os.link(tmp/"transfer.tar",destination)
    print(json.dumps(dict(mail_revision=PINS["mail_revision"], **pin), sort_keys=True))


def inspect_runtime(path, target):
    with tarfile.open(path,"r|gz") as archive:
        observed, elf, manifest = {}, set(), None
        for member in archive:
            name = member.name
            p = Path(name)
            require(member.isfile() and name == p.as_posix() and not p.is_absolute() and ".." not in p.parts
                    and name not in observed and len(observed) < 3000 and member.size < 500_000_000, "invalid runtime entry")
            source = archive.extractfile(member)
            if name == "runtime.json":
                require(manifest is None and member.size < 2_000_000, "invalid runtime manifest")
                manifest = json.load(source)
                continue
            first = source.read(4)
            if first == b"\x7fELF":
                elf.add(name)
            hasher = hashlib.sha256(first)
            selected = name.startswith(("bin/","node_modules/"))
            output = None
            try:
                if selected:
                    dest = target/name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    output = dest.open("xb")
                    output.write(first)
                while chunk := source.read(1 << 20):
                    hasher.update(chunk)
                    if output:
                        output.write(chunk)
            finally:
                if output:
                    output.close()
            observed[name] = dict(bytes=member.size, sha256=hasher.hexdigest())
            if selected:
                dest.chmod(0o555 if name.startswith("bin/") else 0o444)
        require(manifest and manifest["schema"] == 1 and manifest["files"] == observed and
                manifest["mail_revision"] == PINS["mail_revision"] and
                manifest["compiled_receipt_sha256"] == PINS["actions"]["compiled_receipt_sha256"] and
                manifest["peer_receipt_sha256"] == PINS["actions"]["peer_receipt_sha256"], "runtime provenance mismatch")
        require(elf == {"bin/node", "bin/stalwart", NATIVE} and observed["bin/node"]["sha256"] == NODE and
                observed["bin/stalwart"]["sha256"] == PINS["actions"]["stalwart_sha256"] and
                observed[NATIVE]["sha256"] == PINS["actions"]["libsignal_sha256"], "unexpected executable inventory")
        return dict(files=len(observed)+1, native_binaries={n:observed[n]["sha256"] for n in sorted(elf)})


def stage(transfer, destination):
    require(not destination.exists(), "fresh guest staging target required")
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        scratch=Path(tmp)
        staging=scratch/"stage"
        staging.mkdir()
        with tarfile.open(transfer,"r:") as archive:
            names=[RUNTIME, *("source/"+n for n in PINS["source_files"])]
            require(archive.getnames()==names and all(m.isfile() for m in archive.getmembers()), "unexpected guest transfer")
            for member in archive:
                source = archive.extractfile(member)
                if member.name == RUNTIME:
                    require(0 < member.size <= 160_000_000, "wrong guest runtime size")
                    with (scratch/RUNTIME).open("xb") as out:
                        shutil.copyfileobj(source,out)
                    require(digest(scratch/RUNTIME)==PINS["actions"]["runtime_sha256"],"guest runtime digest")
                else:
                    require(member.size < 512*1024, "unexpected application source size")
                    raw=source.read()
                    require(hashlib.sha256(raw).hexdigest()==PINS["source_files"][member.name[7:]],"guest source mismatch")
                    path=staging/member.name
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(raw)
                    path.chmod(0o444)
        (staging/"source/integration/signal-mail/node_modules").mkdir()
        report=inspect_runtime(scratch/RUNTIME, staging/"runtime")
        (staging/RECEIPT).write_text(json.dumps(dict(mail_revision=PINS["mail_revision"],runtime_bytes=(scratch/RUNTIME).stat().st_size,**PINS["actions"],**report),sort_keys=True)+"\n")
        for directory, _, _ in os.walk(staging):
            Path(directory).chmod(0o755)
        staging.rename(destination)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("fetch").add_argument("output",type=Path)
    guest=sub.add_parser("stage")
    guest.add_argument("transfer",type=Path)
    guest.add_argument("destination",type=Path)
    args=parser.parse_args()
    if args.operation=="fetch":
        retrieve(args.output)
    else:
        stage(args.transfer,args.destination)
