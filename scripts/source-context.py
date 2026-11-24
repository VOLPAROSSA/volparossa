#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Locate a literal in committed text with a paginated, version-bound Git index."""

import argparse
import json
import os
from pathlib import PurePosixPath
import subprocess
import sys


def git(repo, *args, allowed=(0,), revision=None):
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="", LC_ALL="C")
    if revision:
        env["GIT_ATTR_SOURCE"] = revision
    result = subprocess.run(
        ["git", "--no-replace-objects", "--literal-pathspecs", "-C", repo, *args],
        capture_output=True, env=env,
    )
    # Even with other matches, Git may report an unreadable blob on stderr.
    if result.returncode not in allowed or result.stderr:
        raise ValueError(os.fsdecode(result.stderr).strip() or f"git exited {result.returncode}")
    return result.stdout


def source_context(args):
    repo = os.fsdecode(git(args.repo, "rev-parse", "--show-toplevel").removesuffix(b"\n"))
    revision = git(repo, "rev-parse", "--verify", "--end-of-options",
                   args.rev + "^{commit}").decode("ascii").strip()
    raw = git(repo, "grep", "--no-color", "--no-recurse-submodules", "--no-textconv",
              "-I", "-z", "-c", "-F", "-e", args.term, revision, "--", *args.paths,
              allowed=(0, 1), revision=revision)
    # Git separates the path from its count with NUL. A path may contain newlines.
    counts = {}
    prefix = (revision + ":").encode("ascii")
    start = 0
    while start < len(raw):
        end_path = raw.index(b"\0", start)
        end_count = raw.index(b"\n", end_path + 1)
        name = raw[start:end_path]
        if not name.startswith(prefix):
            raise ValueError("unexpected git grep path")
        path = os.fsdecode(name[len(prefix):])
        counts[path] = int(raw[end_path + 1:end_count])
        start = end_count + 1

    ordered = sorted(counts, key=lambda p: (-counts[p], os.fsencode(p)))
    page = ordered[args.offset:args.offset + args.limit]
    instructions = {"AGENTS.md"}
    for path in page:
        instructions.update(str(parent / "AGENTS.md") for parent in PurePosixPath(path).parents)
    tree = git(repo, "ls-tree", "--full-tree", "-z", revision, "--", *sorted(instructions | set(page)))
    blobs = {}
    for entry in tree.split(b"\0"):
        if entry:
            metadata, path = entry.split(b"\t", 1)
            _, object_type, oid = metadata.split()
            if object_type == b"blob":
                blobs[os.fsdecode(path)] = oid.decode("ascii")
    end = args.offset + len(page)
    return {
        "commit": revision, "term": args.term, "paths": args.paths,
        "total_files": len(counts), "total_matching_lines": sum(counts.values()),
        "offset": args.offset, "next_offset": end if end < len(counts) else None,
        "instructions": {p: blobs[p] for p in sorted(instructions) if p in blobs},
        "files": [{"path": p, "blob": blobs[p], "matching_lines": counts[p]} for p in page],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="checkout to search (default: current checkout)")
    parser.add_argument("--rev", default="HEAD", help="committed revision (default: HEAD)")
    parser.add_argument("--limit", type=int, default=12, help="files per page, 1 to 100 (default: 12)")
    parser.add_argument("--offset", type=int, default=0, help="start at this file in the same query")
    parser.add_argument("term", help="single, case-sensitive fixed string")
    parser.add_argument("paths", nargs="*", help="literal files or directories relative to the repository root")
    args = parser.parse_args()
    if not args.term or "\n" in args.term or "\r" in args.term:
        parser.error("term must be a single nonempty line")
    if args.offset < 0 or not 1 <= args.limit <= 100:
        parser.error("offset must be nonnegative and limit between 1 and 100")
    if any(not p or PurePosixPath(p).is_absolute() or ".." in PurePosixPath(p).parts for p in args.paths):
        parser.error("paths must be relative to the repository root")
    try:
        print(json.dumps(source_context(args), separators=(",", ":")))
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
