#!/usr/bin/env bash
# Exercise the normal entry point with a local gh fixture and the real jq.
set -euo pipefail
script="$(dirname "$0")/ci-run-summary.sh"
export run='{"html_url":"https://github.com/example/project/actions/runs/10","id":10,"run_attempt":2,
"workflow_id":5,"head_sha":"revision","event":"pull_request","status":"completed","conclusion":"failure",
"run_started_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:15Z"}'
export pages='{"jobs":[{"id":90,"status":"completed","conclusion":"failure",
"started_at":"2026-10-01T00:00:03Z","completed_at":"2026-10-01T00:00:14Z",
"steps":[{"number":1,"conclusion":"success"},{"number":2,"name":"check","conclusion":"failure"},
{"number":3,"conclusion":"skipped"}]}]}
{"jobs":[{"id":91,"status":"completed","conclusion":"skipped","steps":[]}]}'
# Exported fixture invoked by the child Bash process.
# shellcheck disable=SC2317
gh() {
  case "$*" in
    'api repos/example/project/actions/runs/10/attempts/2') printf '%s\n' "$run" ;;
    'api repos/example/project/actions/workflows/5 --jq .name') echo Quality ;;
    'api --paginate repos/example/project/actions/runs/10/attempts/2/jobs?per_page=100')
      printf '%s\n' "$pages"
      return "${jobs_exit:-0}" ;;
    *) return 42 ;;
  esac
}
export -f gh
summary=$(bash "$script" example/project 10 2)
jq -e '.conclusion == "failure" and .attempt == 2 and .elapsed_s == 15 and
  .url == "https://github.com/example/project/actions/runs/10/attempts/2" and
  .workflow == "Quality" and .workflow_id == 5 and .headSha == "revision" and
  .jobs[0].elapsed_s == 11 and [.jobs[].id] == [90,91] and
  .jobs[0].steps == {failure:1, skipped:1, success:1} and
  [.jobs[0].inspect[].number] == [2] and .jobs[1].elapsed_s == null' <<<"$summary" >/dev/null
run=$(jq '.status="in_progress" | .conclusion=null' <<<"$run")
pages='{"jobs":[{"id":90,"status":"in_progress","conclusion":null,
"steps":[{"number":1,"status":"in_progress","conclusion":null}]}]}'
bash "$script" example/project 10 2 |
  jq -e '.elapsed_s == null and .conclusion == "" and .jobs[0].elapsed_s == null and
    .jobs[0].steps.in_progress == 1 and .jobs[0].inspect[0].status == "in_progress"' >/dev/null
if summary=$(jobs_exit=42 bash "$script" example/project 10 2); then exit 1; fi
test -z "$summary"
run=$(jq '.run_attempt=1' <<<"$run")
if bash "$script" example/project 10 2 2>/dev/null; then exit 1; fi
