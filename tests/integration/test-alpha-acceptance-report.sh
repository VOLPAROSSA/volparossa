#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Exercise successful conversion and fail-closed evidence binding without privileges.
set -eu

export LC_ALL=C
umask 077
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPOSITORY=$(CDPATH='' cd -- "$HERE/../.." && pwd -P)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/volparossa-alpha-report-test.XXXXXX")
case $WORK in */volparossa-alpha-report-test.??????) ;; *) exit 69 ;; esac
cleanup() {
    rm -rf --one-file-system -- "$WORK"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for acceptance_id in A01 A02 A03 A04 A05 A06 A07 A08 A09 A10 A11 A12 A13 A14; do
    evidence_name=$(printf '%s' "$acceptance_id" | tr 'A' 'a')-evidence.json
    jq -S -c -n --arg acceptance_id "$acceptance_id" \
        '{schema_version:1,acceptance_id:$acceptance_id,success:true}' \
        >"$WORK/$evidence_name"
done
jq -S -c -n '{host_state:"unchanged"}' >"$WORK/host-state-before.json"
install -m 0600 "$WORK/host-state-before.json" "$WORK/host-state-after.json"
host_sha256=$(sha256sum "$WORK/host-state-before.json" | awk '{print $1}')
jq -S -c -n --arg digest "$host_sha256" \
    '{schema_version:1,acceptance_id:"A15",success:true,
      before_sha256:$digest,after_sha256:$digest,unchanged:true}' \
    >"$WORK/a15-evidence.json"

jq -S -s '
  map({key:(.acceptance_id | ascii_downcase),value:.}) | from_entries
' "$WORK"/a??-evidence.json >"$WORK/evidence.json"
native_revisions=$(jq -ce '
  [.components[] | select(.commit? != null) | {key:.name,value:.commit}] |
  from_entries
' "$REPOSITORY/third_party/upstream.lock.json")
jq -S -c -n --slurpfile evidence "$WORK/evidence.json" \
    --argjson native_revisions "$native_revisions" '
  ($evidence[0]) as $e |
  def passed($id): {requested:true,succeeded:true,exit_status:0,evidence:$e[$id]};
  {
    schema_version:1,
    report_kind:"volparossa-alpha-kvm-topology",
    source_revision:"1111111111111111111111111111111111111111",
    run_id:"22222222222222222222222222222222",
    started_at:"2026-09-03T10:00:00Z",
    finished_at:"2026-09-03T10:10:00Z",
    environment:{debian_version:"13",architecture:"amd64",
      kernel:"6.12.0-test-amd64",rustc:"rustc 1.85.0 (test)",
      native_revisions:$native_revisions},
    last_phase:"a15-complete",
    topology:{ready:true,direct_client_exit_adjacency:false,
      client_exit_route_absent:true},
    production_helpers:{ready:true},
    native_mpquic:{ready:true,api_version:6},
    agents_ready:true,
    destination_ready:true,
    client_connect:{requested:true,succeeded:true,exit_status:0,
      observed_blocker:"NONE"},
    a01_bootstrap_resilience:passed("a01"),
    a02_transparent_tcp:passed("a02"),
    a03_mptcp_aggregation:passed("a03"),
    a04_mptcp_relay_failover:passed("a04"),
    a05_udp_echo:passed("a05"),
    a06_http3_mpquic:passed("a06"),
    a07_http3_relay_failover:passed("a07"),
    a08_allowed_destination:passed("a08"),
    a09_forbidden_destinations:passed("a09"),
    a10_unverifiable_ech:passed("a10"),
    a11_relay_outer_privacy:passed("a11"),
    a12_exit_source_privacy:passed("a12"),
    a13_no_direct_client_exit:passed("a13"),
    a14_forced_crash_cleanup:passed("a14"),
    a15_host_state_unchanged:passed("a15"),
    cleanup:{complete:true,remaining_namespaces:0,
      remaining_owned_objects:0,remaining_units:0},
    runner_exit_status:0
  }
' >"$WORK/report.json"

"$HERE/generate-alpha-acceptance-report.sh" \
    "$WORK/report.json" "$WORK/acceptance-report.json" \
    >"$WORK/generator.stdout"
[ "$(wc -l <"$WORK/generator.stdout")" -eq 1 ]
jq -e 'type == "object" and .report_kind == "acceptance"' \
    "$WORK/generator.stdout" >/dev/null
cmp -s "$WORK/generator.stdout" "$WORK/acceptance-report.json"
"$HERE/validate-report.sh" "$WORK/acceptance-report.json"
jq -e '
  .source_revision == "1111111111111111111111111111111111111111" and
  .overall == "PASS" and .suite == "all" and
  ([.cases[].id] == ["A01","A02","A03","A04","A05","A06","A07",
    "A08","A09","A10","A11","A12","A13","A14","A15"]) and
  all(.cases[]; .selected and .result == "PASS") and
  ([.cases[13].evidence[].check] | sort) == ([
    "FORCED_AGENT_CRASH_CLEANUP","FORCED_HELPER_CRASH_CLEANUP",
    "FORCED_NATIVE_CRASH_CLEANUP","OWNED_OBJECTS_ABSENT"] | sort) and
  [.cases[14].evidence[].id] == ["a15.host_before","a15.host_after"]
' "$WORK/acceptance-report.json" >/dev/null

rm -f -- "$WORK/acceptance-report.json"
jq '.a06_http3_mpquic.evidence.success = false' "$WORK/report.json" \
    >"$WORK/report-tampered.json"
mv -- "$WORK/report-tampered.json" "$WORK/report.json"
if "$HERE/generate-alpha-acceptance-report.sh" \
    "$WORK/report.json" "$WORK/acceptance-report.json" >/dev/null 2>&1; then
    printf '%s\n' 'tampered detailed evidence produced a normative PASS report' >&2
    exit 1
fi
[ ! -e "$WORK/acceptance-report.json" ]

printf '%s\n' 'alpha normative acceptance-report conversion passed'
