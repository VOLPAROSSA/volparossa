#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Validate acceptance-report structure plus security-critical semantic invariants.
set -eu

usage() {
    printf '%s\n' 'usage: tests/integration/validate-report.sh REPORT.json' >&2
}

[ "$#" -eq 1 ] || { usage; exit 64; }
report=$1
command -v jq >/dev/null 2>&1 || {
    printf '%s\n' 'jq is required to validate acceptance reports' >&2
    exit 69
}
if [ ! -f "$report" ] || [ ! -r "$report" ]; then
    printf 'acceptance report is not a readable regular file: %s\n' "$report" >&2
    exit 66
fi

jq -e '
    def exact_case_ids:
        map(.id) == [
            "A01", "A02", "A03", "A04", "A05",
            "A06", "A07", "A08", "A09", "A10",
            "A11", "A12", "A13", "A14", "A15"
        ];
    def valid_digest:
        . == null or (type == "string" and test("^[0-9a-f]{64}$"));
    def valid_evidence:
        type == "object"
        and (.id | type == "string" and length > 0 and length <= 128)
        and (.kind | IN("counter", "capture", "command", "digest", "measurement", "state"))
        and (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
        and (.path | type == "string" and length > 0 and length <= 512)
        and (.path | startswith("/") | not)
        and (.path | split("/") | index("..") | not)
        and (.check | type == "string" and length > 0 and length <= 512);
    .schema_version == 1
    and .report_kind == "acceptance"
    and (.suite | IN("all", "mptcp", "mpquic"))
    and (.source_revision == null
         or (.source_revision | type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$")))
    and (.execution.requested_mode | IN("PREVIEW", "EXECUTE"))
    and (.execution.attempted | type == "boolean")
    and (.execution.completed | type == "boolean")
    and (.execution.topology_created | type == "boolean")
    and (.execution.blockers | type == "array")
    and (.host_state.captured | type == "boolean")
    and (.host_state.before_digest | valid_digest)
    and (.host_state.after_digest | valid_digest)
    and (.host_state.unchanged == null or (.host_state.unchanged | type == "boolean"))
    and (.cases | type == "array" and length == 15 and exact_case_ids)
    and all(.cases[];
        (.selected | type == "boolean")
        and (.result | IN("PASS", "FAIL", "SKIPPED", "ERROR"))
        and (.evidence | type == "array")
        and (if .selected == false
             then .result == "SKIPPED" and (.evidence | length == 0)
             else true end)
        and all(.evidence[]; valid_evidence)
        and (if .result == "PASS"
             then (.evidence | length > 0) and .reason == null
             else (.reason | type == "object"
                   and (.code | type == "string" and length > 0)
                   and (.message | type == "string" and length > 0))
             end))
    and (.cleanup.attempted | type == "boolean")
    and (.cleanup.complete == null or (.cleanup.complete | type == "boolean"))
    and (.cleanup.remaining_owned_objects == null
         or (.cleanup.remaining_owned_objects | type == "number" and . >= 0 and floor == .))
    and (.overall | IN("PASS", "FAIL", "BLOCKED", "ERROR"))
    and (if .overall == "BLOCKED"
         then (.execution.blockers | length > 0)
         else true end)
    and (if .execution.attempted == false
         then .execution.completed == false
              and .execution.topology_created == false
              and .host_state.captured == false
              and .host_state.before_digest == null
              and .host_state.after_digest == null
              and .host_state.unchanged == null
              and .cleanup.attempted == false
              and .cleanup.complete == null
              and .cleanup.remaining_owned_objects == null
              and all(.cases[]; .result == "SKIPPED")
         else true end)
    and ((.cases[] | select(.id == "A14")) as $case
         | if $case.result == "PASS"
           then .cleanup.attempted == true and .cleanup.complete == true
                and .cleanup.remaining_owned_objects == 0
           else true end)
    and ((.cases[] | select(.id == "A15")) as $case
         | if $case.result == "PASS"
           then .host_state.captured == true
                and .host_state.unchanged == true
           else true end)
    and (if .overall == "PASS"
         then .execution.attempted == true
              and .execution.completed == true
              and .host_state.captured == true
              and .host_state.unchanged == true
              and .cleanup.attempted == true
              and .cleanup.complete == true
              and .cleanup.remaining_owned_objects == 0
              and all(.cases[]; .result == "PASS")
         else true
         end)
' "$report" >/dev/null
