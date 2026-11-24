#!/usr/bin/env bash
# Inspect one hosted attempt. Exit status describes retrieval, not test success.
set -euo pipefail
if [[ $# != 3 || ! $1 =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ || ! $2 =~ ^[1-9][0-9]*$ || ! $3 =~ ^[1-9][0-9]*$ ]]; then
  echo 'Usage: ci-run-summary.sh OWNER/REPO RUN_ID ATTEMPT' >&2
  exit 2
fi
# The REST attempt endpoint works with older gh releases and binds reruns explicitly.
repo="repos/$1/actions"
endpoint="$repo/runs/$2/attempts/$3"
run=$(gh api "$endpoint" | jq -ce --arg id "$2" --arg attempt "$3" '
  if (.id | tostring) != $id or (.run_attempt | tostring) != $attempt
  then error("unexpected run or attempt") else . end
  | {url: (.html_url + "/attempts/" + $attempt), attempt: .run_attempt,
     workflow_id, event, headSha: .head_sha, status, conclusion: (.conclusion // ""),
     run_started_at, updated_at}')
workflow=$(gh api "$repo/workflows/$(jq -r '.workflow_id' <<<"$run")" --jq .name)
# Keep the raw paginated job JSON on stdin. Large runs can exceed shell argument limits.
summary=$(gh api --paginate "$endpoint/jobs?per_page=100" |
  jq -ces --argjson run "$run" --arg workflow "$workflow" '
    def seconds($start; $end):
      try ((($end | fromdateiso8601) - ($start | fromdateiso8601) | select(. >= 0)) // null)
      catch null;
    if length == 0 then error("missing jobs response") else . end
    | [.[] | .jobs[] | {id, name, status, conclusion: (.conclusion // ""),
        elapsed_s: (if .status == "completed" and .conclusion != "skipped"
                    then seconds(.started_at; .completed_at) else null end),
        steps: ([.steps[]? | (.conclusion // .status)]
                | group_by(.) | map({key: .[0], value: length}) | from_entries),
        inspect: [.steps[]? | select(.conclusion != "success" and .conclusion != "skipped")
                  | {number, name, status, conclusion: (.conclusion // "")}]}] as $jobs
    | $run | {url, attempt, workflow: $workflow, workflow_id, event, headSha, status, conclusion,
       elapsed_s: (if .status == "completed" then seconds(.run_started_at; .updated_at) else null end),
       jobs: $jobs}')
printf '%s\n' "$summary"
