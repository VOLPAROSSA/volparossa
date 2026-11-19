#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a disposable owner's restored signed release for a later independent contribution."""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile

SITE = runpy.run_path(str(Path(__file__).with_name("content-provider-site-smoke.py")))
NAME, CONTENT_TYPE = SITE["NAME"], SITE["CONTENT_TYPE"]
require, private = SITE["require"], SITE["private"]
SITE_BYTES, SITE_SHA = SITE["BUNDLE_BYTES"], SITE["BUNDLE_SHA256"]


def digest(path, maximum):
    meta = private(path)
    require(meta.st_nlink == 1 and 0 < meta.st_size <= maximum, "unexpected owner file size or link count")
    digest_value = hashlib.sha256()
    observed = 0
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        while block := stream.read(65536):
            observed += len(block)
            require(observed <= meta.st_size, "owner file grew")
            digest_value.update(block)
    require(observed == meta.st_size, "owner file changed")
    return digest_value.hexdigest()


def content(cli, work, *args):
    result = subprocess.run([cli, "--control-socket", "absent.sock", "content", *args],
                            cwd=work, env={"HOME": str(work), "LC_ALL": "C", "PATH": os.defpath},
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
    require(result.returncode == 0, f"offline owner command failed ({args[0]})")
    require(len(result.stdout) <= 32768, "oversized owner command receipt")
    return json.loads(result.stdout)


def publish(cli, work, key, revision, bundle, manifest, bundle_sha):
    args = ["publish", "--input", bundle, "--expected-input-sha256", bundle_sha,
            "--expected-publisher-key", key, "--cache", "owner-cache", "--manifest", manifest,
            "--identity", "identity.key", "--passphrase-file", "passphrase", "--content-type", CONTENT_TYPE,
            "--name", NAME, "--revision", str(revision), "--lifetime-seconds", "7200", "--min-free-bytes", "0"]
    if revision > 1:
        args.append("--reuse-cache")
    result = content(cli, work, *args)
    manifest_id = digest(work / manifest, 65536)
    size = bundle.stat().st_size
    require(result["operation"] == "offline_content_publish" and result["network_publication"] is False
            and result["manifest_id"] == manifest_id and result["publisher_key_hex"] == key
            and result["name"] == NAME and result["content_type"] == CONTENT_TYPE
            and result["revision"] == revision and result["bytes"] == size
            and result["chunks"] == (size + SITE["CHUNK_BYTES"] - 1) // SITE["CHUNK_BYTES"]
            and type(result["expires_unix_seconds"]) is int and result["expires_unix_seconds"] > 0,
            "signed owner publication differs from reviewed release")
    return dict(manifest_id=manifest_id, revision=revision, bundle_sha256=bundle_sha,
                expires_unix_seconds=result["expires_unix_seconds"])


def restore_owner(cli, work, original):
    identity = content(cli, work, "recipient-key", "--identity", "identity.key", "--passphrase-file", "passphrase")
    key = identity["identity_public_key_hex"]
    require(identity["operation"] == "message_recipient_key" and re.fullmatch(r"[0-9a-f]{64}", key)
            and identity["private_key_exported"] is False and identity["network_publication"] is False,
            "owner identity not established")
    source = publish(cli, work, key, 1, original, "source.pb", SITE_SHA)

    html = work / "assets" / "index.html"
    previous_html = html.read_bytes()
    require(previous_html == SITE["assets"]()["/index.html"][1], "unexpected initial site HTML")
    html.write_bytes(previous_html.replace(b"<h1>Native replica site</h1>", b"<h1>Second edition</h1>"))
    current_path = work / "current.vps"
    packed = content(cli, work, "site", "pack", "--directory", "assets", "--output", current_path, "--review-receipt")
    current_sha = digest(current_path, SITE_BYTES + 1024)
    require(packed["operation"] == "site_pack_preparation" and packed["asset_count"] == 4
            and packed["bundle_sha256"] == current_sha != SITE_SHA, "second site edition was not distinct")
    current = publish(cli, work, key, 2, current_path, "current.pb", current_sha)
    candidate = publish(cli, work, key, 3, original, "candidate.pb", SITE_SHA)
    require(len({edition["manifest_id"] for edition in (source, current, candidate)}) == 3,
            "owner releases must have different manifest identities")
    for secret in ("identity.key", "passphrase"):
        (work / secret).unlink()

    restore = content(cli, work, "site", "restore", "--cache", "owner-cache", "--publisher-key", key, "--name", NAME,
                      "--source-manifest", "source.pb", "--expected-source-id", source["manifest_id"],
                      "--current-manifest", "current.pb", "--expected-current-id", current["manifest_id"],
                      "--candidate-manifest", "candidate.pb", "--expected-candidate-id", candidate["manifest_id"],
                      "--min-free-bytes", "0", "--initialize-from-reviewed-current")
    require(restore == dict(schema_version=1, operation="local_site_restore", base="reviewed_initial_current",
            state="activated", publisher_key=key, name=NAME, source_manifest_id=source["manifest_id"], source_revision=1,
            previous_manifest_id=current["manifest_id"], previous_revision=2, manifest_id=candidate["manifest_id"],
            revision=3, bundle_sha256=SITE_SHA, bundle_bytes=SITE_BYTES, expires_unix_seconds=candidate["expires_unix_seconds"],
            predecessor_observed_in_this_operation=True, network_publication=False, globally_latest=False),
            "local restore did not activate the exact successor")
    assembled = content(cli, work, "assemble", "--manifest", "candidate.pb", "--publisher-key", key,
                        "--cache", "owner-cache", "--output", "restored.vps", "--min-free-bytes", "0")
    require(assembled["operation"] == "offline_content_assemble" and assembled["network_retrieval"] is False
            and assembled["publisher_key_hex"] == key and assembled["bytes"] == SITE_BYTES
            and digest(work / "restored.vps", SITE_BYTES) == SITE_SHA, "restored bytes differ from revision one")
    return dict(restore=restore, source=source, current=current, candidate=candidate, restored_bytes_verified=True)


def prepare(cli, root):
    require(root.is_absolute() and root.name == "site-publisher", "unexpected owner fixture root")
    private(root, True)
    require({entry.name for entry in root.iterdir()} == {"bundle.bin", "assets", "identity.key", "passphrase"},
            "owner fixture does not contain exactly the generated inputs")
    private(root / "assets", True)
    expected_assets = SITE["inventory"]()
    require({entry.name for entry in (root / "assets").iterdir()} == {name[1:] for name in expected_assets},
            "unexpected owner assets")
    for name, expected in expected_assets.items():
        require(digest(root / "assets" / name[1:], expected["bytes"]) == expected["sha256"], "unexpected asset hash")
    for secret in ("identity.key", "passphrase"):
        require(private(root / secret).st_nlink == 1, "unexpected linked signing input")
    original = root / "bundle.bin"
    require(digest(original, SITE_BYTES) == SITE_SHA, "unexpected original site bundle")
    with tempfile.TemporaryDirectory(dir=root, prefix="owner-") as temporary:
        work = Path(temporary)
        for name in ("identity.key", "passphrase", "assets"):
            (root / name).rename(work / name)
        evidence = restore_owner(cli, work, original)
        os.link(work / "candidate.pb", root / "manifest.bin")
    require({entry.name for entry in root.iterdir()} == {"bundle.bin", "manifest.bin"}
            and digest(root / "manifest.bin", 65536) == evidence["candidate"]["manifest_id"],
            "owner handoff contains unexpected state")
    return dict(evidence, owner_state_removed=True)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3, "usage: content-repair-site-restore.py CLI SITE_PUBLISHER")
        print(json.dumps(prepare(sys.argv[1], Path(sys.argv[2])), sort_keys=True))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(f"disposable owner restore rejected: {error}")
