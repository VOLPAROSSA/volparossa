#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Validate acceptance-report structure, semantic invariants, and evidence digests.
set -eu
umask 077

usage() {
    printf '%s\n' 'usage: tests/integration/validate-report.sh REPORT.json' >&2
}

[ "$#" -eq 1 ] || { usage; exit 64; }
report=$1
for command_name in jq realpath sha256sum wc; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf '%s is required to validate acceptance reports\n' "$command_name" >&2
        exit 69
    }
done
if [ ! -f "$report" ] || [ ! -r "$report" ] || [ -L "$report" ]; then
    printf 'acceptance report is not a readable regular non-symlink file: %s\n' "$report" >&2
    exit 66
fi
report_size=$(wc -c <"$report")
if [ "$report_size" -gt 1048576 ]; then
    printf 'acceptance report exceeds the 1 MiB bound: %s\n' "$report" >&2
    exit 65
fi

jq -e '
    def exact_keys($expected):
        (keys | sort) == ($expected | sort);
    def safe_text($minimum; $maximum):
        type == "string"
        and length >= $minimum
        and length <= $maximum
        and (test("[\u0000-\u001f\u007f-\u009f]") | not);
    def valid_code:
        type == "string" and test("^[A-Z][A-Z0-9_]{0,63}$");
    def valid_digest:
        type == "string" and test("^[0-9a-f]{64}$");
    def valid_revision:
        type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$");
    def days_in_month($year; $month):
        if ($month | IN(1, 3, 5, 7, 8, 10, 12)) then 31
        elif ($month | IN(4, 6, 9, 11)) then 30
        elif $month == 2 and ($year % 400 == 0 or ($year % 4 == 0 and $year % 100 != 0)) then 29
        elif $month == 2 then 28
        else 0
        end;
    def valid_timestamp:
        type == "string"
        and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
        and (
            capture("^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})Z$")
            | (.year | tonumber) as $year
            | (.month | tonumber) as $month
            | (.day | tonumber) as $day
            | (.hour | tonumber) as $hour
            | (.minute | tonumber) as $minute
            | (.second | tonumber) as $second
            | $year >= 1
              and $month >= 1 and $month <= 12
              and $day >= 1 and $day <= days_in_month($year; $month)
              and $hour <= 23 and $minute <= 59 and $second <= 59
        );
    def valid_reason:
        type == "object"
        and exact_keys(["code", "message"])
        and (.code | valid_code)
        and (.message | safe_text(1; 512));
    def safe_component:
        length > 0
        and . != "."
        and . != ".."
        and test("^[A-Za-z0-9._-]+$");
    def valid_path:
        type == "string"
        and length >= 1
        and length <= 512
        and (startswith("/") | not)
        and (contains("\\") | not)
        and (split("/") | all(.[]; safe_component));
    def valid_evidence:
        type == "object"
        and exact_keys(["check", "id", "kind", "path", "sha256"])
        and (.id | type == "string" and test("^[A-Za-z0-9_.:-]{1,128}$"))
        and (.kind | IN("counter", "capture", "command", "digest", "measurement", "state"))
        and (.sha256 | valid_digest)
        and (.path | valid_path)
        and (.check | safe_text(1; 512));
    def selected_ids($suite):
        if $suite == "all" then
            ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "A11", "A12", "A13", "A14", "A15"]
        elif $suite == "mptcp" then
            ["A02", "A03", "A04", "A14", "A15"]
        else
            ["A06", "A07", "A14", "A15"]
        end;
    def blocker_matches($blockers; $case):
        any($blockers[]; .code == $case.reason.code);
    def valid_case($blockers):
        type == "object"
        and exact_keys(["evidence", "id", "reason", "result", "selected"])
        and (.selected | type == "boolean")
        and (.result | IN("PASS", "FAIL", "SKIPPED", "ERROR"))
        and (.evidence | type == "array" and length <= 32 and all(.[]; valid_evidence))
        and (if .selected == false then
                 .result == "SKIPPED"
                 and (.reason | valid_reason and .code == "NOT_SELECTED")
                 and (.evidence | length == 0)
             elif .result == "PASS" then
                 .reason == null and (.evidence | length >= 1)
             elif .result == "FAIL" then
                 (.reason | valid_reason)
                 and (.evidence | length >= 1)
             elif .result == "SKIPPED" then
                 (.reason | valid_reason)
                 and blocker_matches($blockers; .)
             else
                 (.reason | valid_reason)
             end);
    def contains_check($case; $check):
        any($case.evidence[]; .check == $check);
    def host_consistent:
        if .captured then
            (.before_digest | valid_digest)
            and (.after_digest | valid_digest)
            and (.unchanged | type == "boolean")
            and (.unchanged == (.before_digest == .after_digest))
        else
            .before_digest == null and .after_digest == null and .unchanged == null
        end;
    def cleanup_consistent:
        if .attempted == false then
            .complete == null and .remaining_owned_objects == null
        elif .complete == true then
            .remaining_owned_objects == 0
        elif .complete == false then
            (.remaining_owned_objects | type == "number" and floor == . and . >= 1)
        else
            .complete == null and .remaining_owned_objects == null
        end;
    def selected_has($result):
        any(.cases[]; .selected and .result == $result);
    def post_attempt_indeterminate:
        (.execution.attempted and (.host_state.captured | not))
        or (.execution.topology_created
            and ((.cleanup.attempted | not) or .cleanup.complete == null));
    def derived_overall:
        if selected_has("ERROR") or post_attempt_indeterminate then "ERROR"
        elif selected_has("FAIL")
             or (.host_state.captured and (.host_state.unchanged | not))
             or (.cleanup.attempted and .cleanup.complete == false) then "FAIL"
        elif .suite != "all"
             or selected_has("SKIPPED")
             or (.execution.blockers | length > 0)
             or (.execution.completed | not)
             or (.execution.topology_created | not) then "BLOCKED"
        else "PASS"
        end;

    . as $report
    | type == "object"
    and exact_keys(["cases", "cleanup", "environment", "execution", "finished_at", "generated_at", "host_state", "overall", "report_kind", "schema_version", "source_revision", "started_at", "suite"])
    and .schema_version == 1
    and .report_kind == "acceptance"
    and (.suite | IN("all", "mptcp", "mpquic"))
    and (.source_revision == null or (.source_revision | valid_revision))
    and (.generated_at == null or (.generated_at | valid_timestamp))
    and (.started_at == null or (.started_at | valid_timestamp))
    and (.finished_at == null or (.finished_at | valid_timestamp))
    and (.execution | type == "object" and exact_keys(["attempted", "blockers", "completed", "requested_mode", "topology_created"]))
    and (.execution.requested_mode | IN("PREVIEW", "EXECUTE"))
    and (.execution.attempted | type == "boolean")
    and (.execution.completed | type == "boolean")
    and (.execution.topology_created | type == "boolean")
    and (.execution.blockers | type == "array" and length <= 32 and all(.[]; valid_reason))
    and (([.execution.blockers[].code] | length) == ([.execution.blockers[].code] | unique | length))
    and (.environment | type == "object" and exact_keys(["architecture", "debian_version", "kernel", "native_revisions", "rustc"]))
    and (.environment.debian_version == null or (.environment.debian_version | safe_text(1; 64)))
    and (.environment.architecture == null or (.environment.architecture | safe_text(1; 64)))
    and (.environment.kernel == null or (.environment.kernel | safe_text(1; 256)))
    and (.environment.rustc == null or (.environment.rustc | safe_text(1; 256)))
    and (.environment.native_revisions | type == "object" and length <= 32)
    and (all(.environment.native_revisions | keys[]; test("^[A-Za-z0-9_.+-]{1,64}$")))
    and (all(.environment.native_revisions[]; valid_revision))
    and (.host_state | type == "object" and exact_keys(["after_digest", "before_digest", "captured", "unchanged"]) and host_consistent)
    and (.cases | type == "array" and length == 15)
    and ([.cases[].id] == ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "A11", "A12", "A13", "A14", "A15"])
    and ([.cases[] | select(.selected) | .id] == selected_ids(.suite))
    and (all(.cases[]; valid_case($report.execution.blockers)))
    and (([.cases[].evidence[].id] | length) == ([.cases[].evidence[].id] | unique | length))
    and (.cleanup | type == "object" and exact_keys(["attempted", "complete", "remaining_owned_objects"]))
    and (.cleanup.attempted | type == "boolean")
    and (.cleanup | cleanup_consistent)
    and (.overall | IN("PASS", "FAIL", "BLOCKED", "ERROR"))
    and (if .execution.requested_mode == "PREVIEW" then (.execution.attempted | not) else true end)
    and (if .execution.attempted then
             .execution.requested_mode == "EXECUTE"
             and (.source_revision | valid_revision)
             and (.generated_at | valid_timestamp)
             and (.started_at | valid_timestamp)
             and (.finished_at | valid_timestamp)
             and .started_at <= .finished_at
             and .finished_at <= .generated_at
             and .environment.debian_version == "13"
             and .environment.architecture == "amd64"
             and (.environment.kernel | safe_text(1; 256))
             and (.environment.rustc | safe_text(1; 256))
         else
             (.execution.completed | not)
             and (.execution.topology_created | not)
             and (.host_state.captured | not)
             and (.cleanup.attempted | not)
             and all(.cases[]; .result == "SKIPPED")
         end)
    and (if .execution.completed or .execution.topology_created then .execution.attempted else true end)
    and (if .execution.completed then .execution.topology_created else true end)
    and (if (.execution.topology_created | not)
         then all(.cases[] | select(.selected); .result == "SKIPPED" or .result == "ERROR")
         else true end)
    and (if .overall == "BLOCKED" then (.execution.blockers | length > 0) else true end)
    and (if .suite != "all" and (all(.cases[] | select(.selected); .result == "PASS"))
         then any(.execution.blockers[]; .code == "PARTIAL_SUITE") else true end)
    and (.cases[13] as $a14
         | if $a14.result == "PASS" then
               .cleanup.attempted and .cleanup.complete == true and .cleanup.remaining_owned_objects == 0
               and contains_check($a14; "FORCED_AGENT_CRASH_CLEANUP")
               and contains_check($a14; "FORCED_HELPER_CRASH_CLEANUP")
               and contains_check($a14; "FORCED_NATIVE_CRASH_CLEANUP")
               and contains_check($a14; "OWNED_OBJECTS_ABSENT")
           else true end)
    and (if .cleanup.attempted and .cleanup.complete == false
         then .cases[13].result == "FAIL" else true end)
    and (.cases[14] as $a15
         | if $a15.result == "PASS" then
               .host_state.captured and .host_state.unchanged == true
               and .host_state.before_digest == .host_state.after_digest
               and any($a15.evidence[]; .id == "a15.host_before" and .kind == "digest" and .sha256 == $report.host_state.before_digest)
               and any($a15.evidence[]; .id == "a15.host_after" and .kind == "digest" and .sha256 == $report.host_state.after_digest)
           else true end)
    and (if .host_state.captured and .host_state.unchanged == false
         then .cases[14].result == "FAIL" else true end)
    and .overall == derived_overall
' "$report" >/dev/null

report_directory=$(CDPATH='' cd -- "$(dirname -- "$report")" && pwd -P)
evidence_records=$(jq -r '.cases[].evidence[] | [.path, .sha256] | @tsv' "$report")
tab=$(printf '\t')
while IFS="$tab" read -r evidence_path expected_digest; do
    [ -n "$evidence_path" ] || continue
    cursor=$report_directory
    old_ifs=$IFS
    IFS=/
    # Path components are already restricted by the semantic validator.
    # shellcheck disable=SC2086
    set -- $evidence_path
    IFS=$old_ifs
    for component do
        cursor=$cursor/$component
        if [ -L "$cursor" ]; then
            printf 'acceptance evidence traverses a symlink: %s\n' "$evidence_path" >&2
            exit 1
        fi
    done
    if [ ! -f "$cursor" ] || [ ! -r "$cursor" ]; then
        printf 'acceptance evidence is not a readable regular file: %s\n' "$evidence_path" >&2
        exit 1
    fi
    canonical_evidence=$(realpath -e -- "$cursor")
    case $canonical_evidence in
        "$report_directory"/*) ;;
        *)
            printf 'acceptance evidence escapes the report directory: %s\n' "$evidence_path" >&2
            exit 1
            ;;
    esac
    actual_digest=$(sha256sum -- "$canonical_evidence" | awk '{print $1}')
    if [ "$actual_digest" != "$expected_digest" ]; then
        printf 'acceptance evidence digest mismatch: %s\n' "$evidence_path" >&2
        exit 1
    fi
done <<EOF
$evidence_records
EOF
