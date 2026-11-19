#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bind one private Studio export to its same-run public, signed topology inputs."""
import hashlib
import json
import os
from html.parser import HTMLParser
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urljoin

SILEX = "672efed69dda04c0a1e968859239e042f00d9538"
NAME = "public-silex-signed-recovery-fixture"
MAX_BUNDLE = 32 * 1024 * 1024
CHUNK = 262144
CHART = "/assets/studio-topology.png"
MEDIA = {".html": "text/html", ".css": "text/css", ".js": "text/javascript",
         ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".svg": "image/svg+xml"}
KEYS = set(("schema kind run_id run_attempt core_revision studio_revision silex_revision asset_count assets "
            "bundle_bytes bundle_sha256 chunk_count manifest_id publisher_key name revision "
            "publication_expires_unix_seconds zip_sha256").split())

def check(condition):
    if not condition:
        raise ValueError("Studio handoff identity, bytes, geometry or ownership differed")

def digest(value):
    return hashlib.sha256(value).hexdigest()

def read_owned(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        st = os.fstat(descriptor)
        check(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1
              and st.st_uid == os.getuid() and 0 < st.st_size <= maximum)
        data = source.read(maximum + 1)
        check(len(data) == st.st_size)
        return data

def validate(evidence):
    check(type(evidence) is dict and set(evidence) == KEYS and type(evidence["schema"]) is int
          and evidence["schema"] == 1 and evidence["kind"] == "silex-topology-handoff"
          and evidence["name"] == NAME and evidence["silex_revision"] == SILEX)
    for key in ("publisher_key", "bundle_sha256", "manifest_id", "zip_sha256"):
        check(re.fullmatch(r"[0-9a-f]{64}", evidence[key]))
    for key in ("core_revision", "studio_revision"):
        check(re.fullmatch(r"[0-9a-f]{40}", evidence[key]))
    for key in ("run_id", "run_attempt"):
        check(re.fullmatch(r"[1-9][0-9]{0,19}", evidence[key]))
    for key in ("bundle_bytes", "chunk_count", "asset_count", "revision", "publication_expires_unix_seconds"):
        check(type(evidence[key]) is int and evidence[key] > 0)
    size = evidence["bundle_bytes"]
    rows = evidence["assets"]
    check(size <= MAX_BUNDLE and evidence["chunk_count"] == (size + CHUNK - 1) // CHUNK
          and evidence["chunk_count"] > 1 and evidence["revision"] == 1 and isinstance(rows, list)
          and 1 <= len(rows) == evidence["asset_count"] <= 256)
    paths = []
    for row in rows:
        check(set(row) == {"path", "bytes", "sha256"} and type(row["bytes"]) is int
              and 0 <= row["bytes"] <= 3 * 1024 * 1024 and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]))
        path = row["path"]
        check(len(path) <= 1024 and re.fullmatch(r"(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+", path)
              and Path(path).suffix in MEDIA)
        paths.append(path)
    check(paths == sorted(set(paths)) and {"/index.html", "/studio-export.html"} <= set(paths)
          and any(p.endswith(".css") for p in paths)
          and any(row["path"] == CHART and row["bytes"] > CHUNK for row in rows))

class ImageReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chart = False

    def handle_starttag(self, tag, attrs):
        if tag == "img":
            src = dict(attrs).get("src")
            if src and urljoin("http://fixture.invalid/studio-export.html", src) == "http://fixture.invalid" + CHART:
                self.chart = True


def admit(directory, expected_sha, revision, context=()):
    directory = Path(directory)
    st = directory.lstat()
    check(directory.resolve() == directory and stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
          and st.st_uid == os.getuid() and set(os.listdir(directory)) == {"evidence.json", "manifest.bin", "site.vps"})
    raw = read_owned(directory / "evidence.json", 65536)
    check(digest(raw) == expected_sha)
    evidence = json.loads(raw)
    validate(evidence)
    check(evidence["core_revision"] == revision and (not context or
          tuple(evidence[k] for k in ("run_id", "run_attempt", "studio_revision")) == tuple(context)))
    bundle = read_owned(directory / "site.vps", MAX_BUNDLE)
    check(digest(read_owned(directory / "manifest.bin", 65536)) == evidence["manifest_id"]
          and digest(bundle) == evidence["bundle_sha256"] and len(bundle) == evidence["bundle_bytes"])
    # Core's canonical site bundle has a four-byte big-endian index length,
    # then the index, then the complete asset bodies in sorted path order.
    offset = 4 + int.from_bytes(bundle[:4], "big")
    rows = evidence["assets"]
    sample = max(rows, key=lambda row: row["bytes"])["path"]
    inventory = {}
    for row in rows:
        path, length = row["path"], row["bytes"]
        asset = bundle[offset:offset + length]
        check(len(asset) == length and digest(asset) == row["sha256"])
        if path == CHART:
            check(asset[:16] == b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"
                  and int.from_bytes(asset[16:20], "big") == 1024 and int.from_bytes(asset[20:24], "big") == 768)
        if path == "/studio-export.html":
            images = ImageReferences()
            images.feed(asset.decode("utf-8"))
            images.close()
            check(images.chart)
        inventory[path] = dict(bytes=length, sha256=row["sha256"], content_type=MEDIA[Path(path).suffix])
        if path == sample:
            check(length > 1)
            start = min(101, length // 2)
            end = min(start + 4096, length)
            byte_range = dict(path=path, start=start, end=end-1, sha256=digest(asset[start:end]))
        offset += length
    check(offset == len(bundle))
    return dict(name=NAME, content_type="application/vnd.volparossa.site.v1", assets=inventory,
                publisher_key=evidence["publisher_key"], bundle_bytes=len(bundle), bundle_sha256=digest(bundle),
                chunks=evidence["chunk_count"], byte_range=byte_range, studio_handoff=evidence,
                studio_evidence_sha256=expected_sha)

if __name__ == "__main__":
    if len(sys.argv) not in (4, 7):
        raise SystemExit("usage: DIRECTORY EVIDENCE_SHA256 CORE_REVISION [RUN_ID ATTEMPT STUDIO_REVISION]")
    print(json.dumps(admit(*sys.argv[1:4], sys.argv[4:]), sort_keys=True))
