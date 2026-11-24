#!/usr/bin/env bash
# Inspect one hosted attempt. Exit status describes retrieval, not test success.
set -euo pipefail
if [[ $# != 3 || ! $1 =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ || ! $2 =~ ^[1-9][0-9]*$ || ! $3 =~ ^[1-9][0-9]*$ ]]; then
  echo 'Usage: ci-run-summary.sh OWNER/REPO RUN_ID ATTEMPT' >&2
  exit 2
fi
# Keep gh's paginated job lookup, the attempt link and each job ID. Never fetch logs.
gh run view "$2" --repo "$1" --attempt "$3" \
  --json url,attempt,workflowName,workflowDatabaseId,event,headSha,status,conclusion,startedAt,updatedAt,jobs |
  jq -ce --arg attempt "$3" '
    def seconds($start; $end):
      try ((($end | fromdateiso8601) - ($start | fromdateiso8601) | select(. >= 0)) // null)
      catch null;
    if (.attempt | tostring) != $attempt then error("unexpected run attempt") else . end
    | {url, attempt, workflow: .workflowName, workflow_id: .workflowDatabaseId, event, headSha, status, conclusion,
       elapsed_s: (if .status == "completed" then seconds(.startedAt; .updatedAt) else null end),
       jobs: [.jobs[] | {id: .databaseId, name, status, conclusion,
         elapsed_s: (if .status == "completed" and .conclusion != "skipped"
                     then seconds(.startedAt; .completedAt) else null end),
         steps: ([.steps[] | (.conclusion | select(. != "")) // .status]
                 | group_by(.) | map({key: .[0], value: length}) | from_entries),
         inspect: [.steps[] | select(.conclusion != "success" and .conclusion != "skipped")
                   | {number, name, status, conclusion}]}]}'
