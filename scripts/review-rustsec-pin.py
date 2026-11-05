#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only official RustSec pin comparison; never applies a candidate update."""

import datetime
import difflib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/quality.yml"
ORIGIN = "https://github.com/RustSec/advisory-db.git"
API = "https://api.github.com/repos/RustSec/advisory-db/commits/"
PIN = re.compile(r"^  RUSTSEC_ADVISORY_DB_REVISION: ([0-9a-f]{40})$", re.MULTILINE)
SHA = re.compile(r"[0-9a-f]{40}")
MAX_RESPONSE = 2 * 1024 * 1024


def fetch_commit(revision):
    request = urllib.request.Request(API + revision, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "VOLPAROSSA-RustSec-review",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.url.startswith(API.lower()) and not response.url.startswith(API):
            # GitHub may canonicalize the organization name to lowercase.
            raise ValueError("unexpected API redirect")
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("oversized API response")
    return json.loads(raw)


def commit_metadata(data, expected):
    if data["sha"] != expected or SHA.fullmatch(expected) is None:
        raise ValueError("API and Git commit identity disagree")
    date = data["commit"]["committer"]["date"]
    parsed = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc)
    if parsed > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5):
        raise ValueError("future commit date")
    verification = data["commit"]["verification"]
    if type(verification["verified"]) is not bool:
        raise ValueError("invalid verification metadata")
    # API-reported verification is evidence metadata, not local signature verification.
    return date, verification["verified"]


def compare(source, fetch=fetch_commit, run=subprocess.run):
    matches = list(PIN.finditer(source))
    if len(matches) != 1:
        raise ValueError("expected one exact immutable Quality pin")
    current = matches[0].group(1)
    result = run(["git", "ls-remote", "--exit-code", ORIGIN, "refs/heads/main"],
                 check=True, capture_output=True, text=True, timeout=30)
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[1] != "refs/heads/main" or SHA.fullmatch(fields[0]) is None:
        raise ValueError("invalid official Git ref response")
    latest = fields[0]
    # Resolve main independently through the API; fail if main moves between observations.
    new_date, verified = commit_metadata(fetch("main"), latest)
    old_date, _ = commit_metadata(fetch(current), current)
    changed = current != latest
    updated = source[:matches[0].start(1)] + latest + source[matches[0].end(1):]
    patch = "".join(difflib.unified_diff(source.splitlines(keepends=True),
                                      updated.splitlines(keepends=True),
                                      fromfile="a/" + WORKFLOW, tofile="b/" + WORKFLOW))
    summary = (
        "## RustSec database pin review\n\n"
        f"Pinned: `{current}` ({old_date}).\n\n"
        f"Official main: `{latest}` ({new_date}).\n\n"
        f"GitHub API reports signature verified: `{str(verified).lower()}`; "
        "no local signature verification was performed.\n\n"
        f"[Official commit](https://github.com/RustSec/advisory-db/commit/{latest}) · "
        f"[Changes](https://github.com/RustSec/advisory-db/compare/{current}...{latest})\n\n"
        "This comparison is not an advisory scan. Review database changes, apply the candidate "
        "in a normal PR, and run hosted Quality's offline cargo-deny/cargo-audit and existing "
        "vendor/RSA scope checks. New vulnerabilities must be remediated, not ignored.\n\n"
    )
    summary += "Review required; candidate patch (not applied):\n\n```diff\n" + patch + "```\n" if changed else "Pin matches official main.\n"
    return changed, summary


def main():
    changed, summary = compare((ROOT / WORKFLOW).read_text())
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
    return 1 if changed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"RustSec pin comparison failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(2)
