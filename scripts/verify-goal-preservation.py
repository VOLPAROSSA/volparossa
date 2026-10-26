#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify immutable requirement sources and effective scope references.

This is an inert repository check, not a semantic completeness or implementation
acceptance proof. No attachments, network access, native builds or writes are
needed. --git-revision reads only blobs from the specified full commit identity.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
MAX_DOCUMENT = 4 * 1024 * 1024
GOAL = "docs/development/GOAL.md"
ARCHIVE = "docs/development/DPS_GOAL_20261021.md"
CONSOLIDATED = "docs/development/DPS_REQUIREMENTS.md"
SOURCE_GOAL = "docs/development/GOAL_SOURCE_20261023.md"
SOURCE_DPS = "docs/development/DPS_REQUIREMENTS_SOURCE_20261023.md"
SOURCE_STUDIO = "docs/development/STUDIO_HOSTING_REQUIREMENTS_SOURCE_20261023.md"
SOURCE_HASHES = {
    SOURCE_GOAL: "302af13b29e0cc1ce9ac09889669ff3866a233403134aca3bf6c25f6ce091393",
    SOURCE_DPS: "abe2b6643a52ea5d579ce8cd4ab7a143fb1a43dd4504cce034a70bd454211c59",
    SOURCE_STUDIO: "4e3d92e240b32b3208829e02f46dd038bc0d15349795e0cf2c983a9f333b6d93",
}
PROMPT = "docs/development/PURSUING_GOAL.md"
STUDIO = "docs/development/STUDIO_HOSTING_REQUIREMENTS.md"
STUDIO_SHA = "a9fc3d875a48083720941aa74d1c00c506038f7550bbe983e6f0e91e2fe2dc50"
PRE_STUDIO_SHA = "d8155106a231be9863be613e03594ca2838c8d57bbe9ddfcd00a32d27e758a40"
ORIGINAL_SHA = "2bebaf9e27860115e64f5b93f50cc1e5bc17d34b22c45fe83106d200b86b54c7"
PREFIX_SHA = "d746ce39c645a226cf85b426a2ea9991f43bba4e2bacca4c6f53865d71bfe287"
ARCHIVE_SHA = "df3ec2bab02272138e2713159959c925097780d49f73c805a11cbdc049bfc56b"
CONTINUATION_SHA = "26cca9ea1854ddb59920457275c5e852a646f226058f26dced5564bdf9313d6d"
MAP = b"### Map\n"


class VerificationError(ValueError):
    """A bounded, content-free verification diagnostic."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def git_bytes(root, arguments, maximum=MAX_DOCUMENT):
    """Run only fixed read operations; bound both streams and the child lifetime."""
    environment = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
                       GIT_NO_LAZY_FETCH="1")
    process = subprocess.Popen(
        ["git", "--no-pager", "--no-replace-objects", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment,
    )
    streams = selectors.DefaultSelector()
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + 10
    try:
        streams.register(process.stdout, selectors.EVENT_READ, output)
        streams.register(process.stderr, selectors.EVENT_READ, errors)
        while streams.get_map():
            require(time.monotonic() < deadline, "git read exceeded 10-second deadline")
            for key, _event in streams.select(0.1):
                block = os.read(key.fd, 65536)
                if not block:
                    streams.unregister(key.fileobj)
                    continue
                key.data.extend(block)
                require(len(key.data) <= (maximum if key.data is output else 16384),
                        "git read exceeded byte bound")
        require(process.wait(timeout=2) == 0, "git cannot read the requested committed object")
        return bytes(output)
    finally:
        streams.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        process.stdout.close()
        process.stderr.close()


def read_document(root, name, revision):
    if revision is not None:
        return git_bytes(root, ["show", revision + ":" + name])
    path = root / name
    require(path.resolve(strict=True).is_relative_to(root), name + ": path escapes repository")
    with path.open("rb") as stream:
        raw = stream.read(MAX_DOCUMENT + 1)
    require(len(raw) <= MAX_DOCUMENT, name + ": document exceeds 4-MiB bound")
    return raw


def extract(raw, label):
    """Remove precisely the marker-line LF and one closing-marker delimiter LF."""
    begin = ("<!-- BEGIN " + label + " -->").encode("ascii")
    end = ("<!-- END " + label + " -->").encode("ascii")
    require(raw.count(begin) == 1 and raw.count(end) == 1,
            label + ": expected exactly one BEGIN and one END marker")
    first, last = raw.index(begin), raw.index(end)
    start = first + len(begin)
    require(first == 0 or raw[first - 1:first] == b"\n", label + ": BEGIN is not a marker line")
    require(raw[start:start + 1] == b"\n", label + ": BEGIN must end with one LF")
    require(last > start and raw[last - 1:last] == b"\n",
            label + ": missing closing-marker LF delimiter or reversed markers")
    require(raw[last + len(end):last + len(end) + 1] in (b"", b"\n"),
            label + ": END is not a marker line")
    return raw[start + 1:last - 1]


def digest(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def references(raw, names):
    """Check literal document references only, without asserting their semantics."""
    text = raw.decode("utf-8")
    missing = [name for name in names if name not in text]
    require(not missing, "missing explicit references: " + ", ".join(missing))


def verify(root, revision=None):
    result = dict(version=2, source="committed-blobs" if revision else "worktree",
                  git_revision=revision, success=False,
                  scope="source-byte-preservation-and-active-references-only",
                  checks={}, payloads={}, errors=[])

    def check(name, operation):
        try:
            value = operation()
        except (VerificationError, OSError, UnicodeError, subprocess.SubprocessError) as error:
            result["checks"][name] = False
            # File contents, git stderr and external exception text never enter JSON.
            reason = str(error) if isinstance(error, VerificationError) else type(error).__name__
            result["errors"].append(dict(check=name, reason=reason))
            return None
        result["checks"][name] = True
        return value

    if revision is not None:
        check("exact_commit_object", lambda: require(
            git_bytes(root, ["cat-file", "-t", revision], 64) == b"commit\n",
            "--git-revision must identify a commit object, not a tag/tree/blob"))
        # Successful require returns None, so use the recorded check outcome.
        if not result["checks"]["exact_commit_object"]:
            return result

    documents = {}
    for path in (GOAL, CONSOLIDATED, STUDIO, PROMPT, ARCHIVE, *SOURCE_HASHES):
        value = check("read:" + path, lambda path=path: read_document(root, path, revision))
        if value is not None:
            documents[path] = value

    for path, expected in SOURCE_HASHES.items():
        check("source_snapshot:" + path, lambda path=path, expected=expected: require(
            path in documents and hashlib.sha256(documents[path]).hexdigest() == expected,
            path + ": complete source snapshot differs from preserved bytes"))

    def payload(name, path, label, size=None, sha=None):
        require(path in documents, path + ": document unavailable")
        raw = extract(documents[path], label)
        actual = digest(raw)
        result["payloads"][name] = actual
        require(size is None or actual["bytes"] == size,
                name + ": payload length differs from preserved value")
        require(sha is None or actual["sha256"] == sha,
                name + ": payload SHA-256 differs from preserved value")
        return raw

    check("original_goal_payload", lambda: payload("original_goal", SOURCE_GOAL, "ORIGINAL GOAL", 26125, ORIGINAL_SHA))
    first = check("received_dps_payload", lambda: payload("received_dps", ARCHIVE, "RECEIVED DPS GOAL", 10495, ARCHIVE_SHA))
    continuation = check("dps_continuation_payload", lambda: payload("dps_continuation", ARCHIVE, "DPS CONTINUATION", 4375, CONTINUATION_SHA))
    consolidated = check("consolidated_dps_markers", lambda: payload("consolidated_dps", SOURCE_DPS, "CONSOLIDATED DPS REQUIREMENTS"))
    check("studio_hosting_payload", lambda: payload(
        "studio_hosting", SOURCE_STUDIO, "STUDIO HOSTING REQUIREMENTS", 18793, STUDIO_SHA))

    def pre_studio_prefix():
        require(SOURCE_GOAL in documents, "goal source unavailable")
        raw = documents[SOURCE_GOAL][:33913]
        result["payloads"]["complete_pre_studio_goal"] = digest(raw)
        require(len(raw) == 33913 and hashlib.sha256(raw).hexdigest() == PRE_STUDIO_SHA,
                "first 33913 GOAL bytes differ from the complete pre-Studio goal")
    check("complete_pre_studio_goal_preserved", pre_studio_prefix)

    def original_prefix():
        require(SOURCE_GOAL in documents, "goal source unavailable")
        raw = documents[SOURCE_GOAL][:30249]
        result["payloads"]["original_goal_with_amendments_prefix"] = digest(raw)
        require(len(raw) == 30249 and hashlib.sha256(raw).hexdigest() == PREFIX_SHA,
                "first 30249 GOAL bytes differ from the preserved amended goal")
        metadata = documents[SOURCE_GOAL].split(b"<!-- BEGIN ORIGINAL GOAL -->", 1)[0]
        require(ORIGINAL_SHA.encode("ascii") in metadata,
                "original goal SHA-256 missing from provenance metadata")
    check("goal_prefix_and_original_hash_metadata", original_prefix)

    def dps_equality():
        require(first is not None and continuation is not None and consolidated is not None,
                "verified DPS archives and consolidated payload are required")
        require(first.count(MAP) == 1, "first DPS archive must contain exactly one Map heading")
        require(continuation.startswith(MAP), "DPS continuation must begin with Map heading")
        expected = first[:first.index(MAP)] + continuation
        result["payloads"]["expected_consolidated_dps"] = digest(expected)
        require(consolidated == expected,
                "consolidated DPS differs from archive pre-Map prefix plus entire continuation")
        require(consolidated.count(MAP) == 1, "consolidated DPS must contain exactly one Map heading")
    check("exact_dps_consolidation_and_single_map", dps_equality)

    def goal_reference():
        require(GOAL in documents, "GOAL document unavailable")
        references(documents[GOAL], ("DPS_REQUIREMENTS.md",))
    check("goal_references_consolidated_dps", goal_reference)
    check("goal_references_studio_hosting", lambda: references(
        documents.get(GOAL, b""), ("STUDIO_HOSTING_REQUIREMENTS.md",)))

    for active, snapshot in ((GOAL, SOURCE_GOAL), (CONSOLIDATED, SOURCE_DPS),
                             (STUDIO, SOURCE_STUDIO)):
        check("effective_requirement_source:" + active,
              lambda active=active, snapshot=snapshot: references(
                  documents.get(active, b""), (Path(snapshot).name,)))

    def prompt_references():
        require(PROMPT in documents, "PURSUING_GOAL document unavailable")
        references(documents[PROMPT], ("GOAL.md", "AGENTS.md", "IMPLEMENTATION_STATUS.md",
                                      "CODEX_WORKFLOW.md", "DPS_REQUIREMENTS.md",
                                      "STUDIO_HOSTING_REQUIREMENTS.md"))
        text = documents[PROMPT].decode("utf-8")
        phrase = r"\b(?:(?:all|every)\s+(?:(?:earlier|previous|agreed|subsequent|later)\s+)*(?:amendments?|clarifications?)|alle\s+(?:(?:eerdere|latere|afgesproken|bestaande)\s+)*(?:aanvullingen|verduidelijkingen|wijzigingen))\b"
        require(re.search(phrase, text, re.IGNORECASE),
                "resume prompt must explicitly retain all amendments/clarifications")
        require(re.search(r"\bDPS\b", text), "resume prompt must explicitly name DPS")
        require(re.search(r"\bStudio\b", text) and re.search(r"\bhosting\b", text, re.IGNORECASE),
                "resume prompt must explicitly name Studio and hosting")
    check("resume_prompt_explicit_scope_and_references", prompt_references)
    result["success"] = all(result["checks"].values())
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-revision", metavar="FULL40HEX",
                        help="verify only immutable blobs at this full commit identity")
    args = parser.parse_args(argv)
    revision = args.git_revision
    if revision is not None and not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        print(json.dumps(dict(version=2, success=False, errors=[dict(
            check="git_revision_argument", reason="expected exactly 40 hexadecimal characters")]), sort_keys=True))
        return 2
    result = verify(ROOT, revision.lower() if revision else None)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
