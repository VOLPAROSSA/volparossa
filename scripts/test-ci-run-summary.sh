#!/usr/bin/env bash
# Exercise the normal entry point with a local gh fixture and the real jq.
set -euo pipefail
script="$(dirname "$0")/ci-run-summary.sh"
# Exported fixture invoked by the child Bash process.
# shellcheck disable=SC2317
gh() {
  [[ "$1 $2 $3 $4 $5 $6 $7 $8" == 'run view 10 --repo example/project --attempt 2 --json' ]] || return 42
  cat
}
export -f gh
data='{"url":"https://github.com/example/project/actions/runs/10/attempts/2","attempt":2,
"event":"pull_request","status":"completed","conclusion":"failure","headSha":"revision",
"startedAt":"2026-10-01T00:00:00Z","updatedAt":"2026-10-01T00:00:15Z",
"jobs":[{"databaseId":90,"status":"completed","conclusion":"failure",
"startedAt":"2026-10-01T00:00:03Z","completedAt":"2026-10-01T00:00:14Z",
"steps":[{"number":1,"conclusion":"success"},{"number":2,"name":"check","conclusion":"failure"},
{"number":3,"conclusion":"skipped"}]},{"status":"completed","conclusion":"skipped","steps":[]}]}'
summary=$(bash "$script" example/project 10 2 <<<"$data")
jq -e '.conclusion == "failure" and .attempt == 2 and .elapsed_s == 15 and
  .jobs[0].elapsed_s == 11 and .jobs[0].id == 90 and
  .jobs[0].steps == {failure:1, skipped:1, success:1} and
  [.jobs[0].inspect[].number] == [2] and .jobs[1].elapsed_s == null' <<<"$summary" >/dev/null
pending=$(jq '.status="in_progress" | .conclusion="" | .jobs[0].status="in_progress"
  | .jobs[0].steps=[{number:1,status:"in_progress",conclusion:""}]' <<<"$data")
bash "$script" example/project 10 2 <<<"$pending" |
  jq -e '.elapsed_s == null and .jobs[0].elapsed_s == null and
    .jobs[0].steps.in_progress == 1 and .jobs[0].inspect[0].status == "in_progress"' >/dev/null
if bash "$script" example/project 10 2 <<< '{"attempt":1}' 2>/dev/null; then exit 1; fi
gh() { return 42; }
export -f gh
if bash "$script" example/project 10 2; then exit 1; fi
