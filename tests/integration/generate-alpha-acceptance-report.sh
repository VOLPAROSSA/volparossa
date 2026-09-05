#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Convert one successful detailed alpha-KVM report into the normative,
# content-addressed A01--A15 acceptance-report contract.
set -eu

export LC_ALL=C
umask 077

usage() {
    printf '%s\n' \
        'usage: tests/integration/generate-alpha-acceptance-report.sh' \
        '       DETAIL.json ACCEPTANCE.json' >&2
}

[ "$#" -eq 2 ] || { usage; exit 64; }
detailed_report=$1
acceptance_report=$2

for command_name in awk basename cat date dirname jq mktemp mv realpath rm sha256sum wc; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'required acceptance-report command unavailable: %s\n' \
            "$command_name" >&2
        exit 69
    }
done

if [ ! -f "$detailed_report" ] || [ ! -r "$detailed_report" ] \
    || [ -L "$detailed_report" ]; then
    printf 'detailed report is not a readable regular non-symlink file: %s\n' \
        "$detailed_report" >&2
    exit 66
fi
if [ -e "$acceptance_report" ] || [ -L "$acceptance_report" ]; then
    printf 'refusing to replace acceptance report: %s\n' "$acceptance_report" >&2
    exit 66
fi

detailed_report=$(realpath -e -- "$detailed_report")
report_directory=$(dirname -- "$detailed_report")
acceptance_directory=$(realpath -e -- "$(dirname -- "$acceptance_report")")
[ "$report_directory" = "$acceptance_directory" ] || {
    printf '%s\n' 'detailed and normative reports must share one evidence directory' >&2
    exit 64
}
acceptance_report=$acceptance_directory/$(basename -- "$acceptance_report")

detailed_size=$(wc -c <"$detailed_report")
[ "$detailed_size" -le 1048576 ] || {
    printf '%s\n' 'detailed report exceeds the 1 MiB conversion bound' >&2
    exit 65
}

jq -e '
  def passed:
    .requested == true and .succeeded == true and .exit_status == 0 and
    (.evidence | type == "object") and .evidence.success == true;
  .schema_version == 1 and
  .report_kind == "volparossa-alpha-kvm-topology" and
  (.source_revision | type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$")) and
  (.run_id | type == "string" and test("^[0-9a-f]{32}$")) and
  .last_phase == "a15-complete" and
  .runner_exit_status == 0 and
  .topology.ready == true and
  .topology.direct_client_exit_adjacency == false and
  .topology.client_exit_route_absent == true and
  .production_helpers.ready == true and
  .native_mpquic.ready == true and
  .native_mpquic.api_version == 6 and
  .agents_ready == true and
  .destination_ready == true and
  .client_connect.requested == true and
  .client_connect.succeeded == true and
  .client_connect.exit_status == 0 and
  .client_connect.observed_blocker == "NONE" and
  ([
    .a01_bootstrap_resilience,
    .a02_transparent_tcp,
    .a03_mptcp_aggregation,
    .a04_mptcp_relay_failover,
    .a05_udp_echo,
    .a06_http3_mpquic,
    .a07_http3_relay_failover,
    .a08_allowed_destination,
    .a09_forbidden_destinations,
    .a10_unverifiable_ech,
    .a11_relay_outer_privacy,
    .a12_exit_source_privacy,
    .a13_no_direct_client_exit,
    .a14_forced_crash_cleanup,
    .a15_host_state_unchanged
  ] | all(.[]; passed)) and
  .cleanup == {
    "complete": true,
    "remaining_namespaces": 0,
    "remaining_owned_objects": 0,
    "remaining_units": 0
  }
' "$detailed_report" >/dev/null || {
    printf '%s\n' 'detailed report is not a complete successful A01--A15 run' >&2
    exit 1
}

while IFS='|' read -r report_key evidence_file acceptance_id; do
    evidence_path=$report_directory/$evidence_file
    if [ ! -f "$evidence_path" ] || [ ! -r "$evidence_path" ] \
        || [ -L "$evidence_path" ]; then
        printf 'acceptance evidence is not a readable regular file: %s\n' \
            "$evidence_file" >&2
        exit 1
    fi
    jq -e --arg key "$report_key" --arg acceptance_id "$acceptance_id" \
        --slurpfile evidence "$evidence_path" '
          .[$key].evidence == $evidence[0] and
          $evidence[0].schema_version == 1 and
          $evidence[0].acceptance_id == $acceptance_id and
          $evidence[0].success == true
        ' "$detailed_report" >/dev/null || {
        printf 'standalone evidence does not match detailed report: %s\n' \
            "$evidence_file" >&2
        exit 1
    }
done <<'EOF'
a01_bootstrap_resilience|a01-evidence.json|A01
a02_transparent_tcp|a02-evidence.json|A02
a03_mptcp_aggregation|a03-evidence.json|A03
a04_mptcp_relay_failover|a04-evidence.json|A04
a05_udp_echo|a05-evidence.json|A05
a06_http3_mpquic|a06-evidence.json|A06
a07_http3_relay_failover|a07-evidence.json|A07
a08_allowed_destination|a08-evidence.json|A08
a09_forbidden_destinations|a09-evidence.json|A09
a10_unverifiable_ech|a10-evidence.json|A10
a11_relay_outer_privacy|a11-evidence.json|A11
a12_exit_source_privacy|a12-evidence.json|A12
a13_no_direct_client_exit|a13-evidence.json|A13
a14_forced_crash_cleanup|a14-evidence.json|A14
a15_host_state_unchanged|a15-evidence.json|A15
EOF

host_before=$report_directory/host-state-before.json
host_after=$report_directory/host-state-after.json
for host_evidence in "$host_before" "$host_after"; do
    if [ ! -f "$host_evidence" ] || [ ! -r "$host_evidence" ] \
        || [ -L "$host_evidence" ]; then
        printf 'host-state evidence is unavailable: %s\n' "$host_evidence" >&2
        exit 1
    fi
done
host_before_sha256=$(sha256sum -- "$host_before" | awk '{print $1}')
host_after_sha256=$(sha256sum -- "$host_after" | awk '{print $1}')
[ "$host_before_sha256" = "$host_after_sha256" ] || {
    printf '%s\n' 'host-state evidence changed during the alpha run' >&2
    exit 1
}
jq -e --arg before "$host_before_sha256" --arg after "$host_after_sha256" '
  .a15_host_state_unchanged.evidence.before_sha256 == $before and
  .a15_host_state_unchanged.evidence.after_sha256 == $after and
  .a15_host_state_unchanged.evidence.unchanged == true
' "$detailed_report" >/dev/null || {
    printf '%s\n' 'A15 evidence is not bound to the retained host-state files' >&2
    exit 1
}

repository=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
upstream_lock=$repository/third_party/upstream.lock.json
if [ ! -f "$upstream_lock" ] || [ ! -r "$upstream_lock" ] \
    || [ -L "$upstream_lock" ]; then
    printf '%s\n' 'native upstream lock is unavailable' >&2
    exit 69
fi
native_revisions=$(jq -ce '
  [.components[] | select(.commit? != null) |
    {key:.name,value:.commit}] | from_entries as $revisions |
  if ($revisions | keys | sort) == ["boringssl","lwip","mqvpn","xquic"] and
     all($revisions[]; test("^[0-9a-f]{40}([0-9a-f]{24})?$"))
  then $revisions else error("invalid native revision lock") end
' "$upstream_lock")

source_revision=$(jq -er '.source_revision' "$detailed_report")
started_at=$(jq -er '.started_at' "$detailed_report")
finished_at=$(jq -er '.finished_at' "$detailed_report")
debian_version=$(jq -er '.environment.debian_version' "$detailed_report")
architecture=$(jq -er '.environment.architecture' "$detailed_report")
kernel=$(jq -er '.environment.kernel' "$detailed_report")
rustc_version=$(jq -er '.environment.rustc' "$detailed_report")
jq -e --argjson native_revisions "$native_revisions" '
  .environment.debian_version == "13" and
  .environment.architecture == "amd64" and
  (.environment.kernel | type == "string" and length > 0) and
  (.environment.rustc | type == "string" and length > 0) and
  .environment.native_revisions == $native_revisions
' "$detailed_report" >/dev/null || {
    printf '%s\n' 'detailed report environment does not match the locked source' >&2
    exit 1
}

a01_sha256=$(sha256sum "$report_directory/a01-evidence.json" | awk '{print $1}')
a02_sha256=$(sha256sum "$report_directory/a02-evidence.json" | awk '{print $1}')
a03_sha256=$(sha256sum "$report_directory/a03-evidence.json" | awk '{print $1}')
a04_sha256=$(sha256sum "$report_directory/a04-evidence.json" | awk '{print $1}')
a05_sha256=$(sha256sum "$report_directory/a05-evidence.json" | awk '{print $1}')
a06_sha256=$(sha256sum "$report_directory/a06-evidence.json" | awk '{print $1}')
a07_sha256=$(sha256sum "$report_directory/a07-evidence.json" | awk '{print $1}')
a08_sha256=$(sha256sum "$report_directory/a08-evidence.json" | awk '{print $1}')
a09_sha256=$(sha256sum "$report_directory/a09-evidence.json" | awk '{print $1}')
a10_sha256=$(sha256sum "$report_directory/a10-evidence.json" | awk '{print $1}')
a11_sha256=$(sha256sum "$report_directory/a11-evidence.json" | awk '{print $1}')
a12_sha256=$(sha256sum "$report_directory/a12-evidence.json" | awk '{print $1}')
a13_sha256=$(sha256sum "$report_directory/a13-evidence.json" | awk '{print $1}')
a14_sha256=$(sha256sum "$report_directory/a14-evidence.json" | awk '{print $1}')
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

temporary_report=$(mktemp "$acceptance_directory/.acceptance-report.XXXXXX")
published_report=
cleanup() {
    [ -z "${temporary_report:-}" ] || rm -f -- "$temporary_report"
    [ -z "${published_report:-}" ] || rm -f -- "$published_report"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

jq -S -c -n \
    --arg source_revision "$source_revision" \
    --arg generated_at "$generated_at" \
    --arg started_at "$started_at" \
    --arg finished_at "$finished_at" \
    --arg debian_version "$debian_version" \
    --arg architecture "$architecture" \
    --arg kernel "$kernel" \
    --arg rustc "$rustc_version" \
    --argjson native_revisions "$native_revisions" \
    --arg host_before "$host_before_sha256" \
    --arg host_after "$host_after_sha256" \
    --arg a01 "$a01_sha256" --arg a02 "$a02_sha256" \
    --arg a03 "$a03_sha256" --arg a04 "$a04_sha256" \
    --arg a05 "$a05_sha256" --arg a06 "$a06_sha256" \
    --arg a07 "$a07_sha256" --arg a08 "$a08_sha256" \
    --arg a09 "$a09_sha256" --arg a10 "$a10_sha256" \
    --arg a11 "$a11_sha256" --arg a12 "$a12_sha256" \
    --arg a13 "$a13_sha256" --arg a14 "$a14_sha256" '
  def evidence($id;$kind;$sha256;$path;$check):
    {id:$id,kind:$kind,sha256:$sha256,path:$path,check:$check};
  def passed($id;$evidence):
    {id:$id,selected:true,result:"PASS",reason:null,evidence:$evidence};
  {
    schema_version:1,
    report_kind:"acceptance",
    suite:"all",
    source_revision:$source_revision,
    generated_at:$generated_at,
    started_at:$started_at,
    finished_at:$finished_at,
    execution:{requested_mode:"EXECUTE",attempted:true,completed:true,
      topology_created:true,blockers:[]},
    environment:{debian_version:$debian_version,architecture:$architecture,
      kernel:$kernel,rustc:$rustc,native_revisions:$native_revisions},
    host_state:{captured:true,before_digest:$host_before,
      after_digest:$host_after,unchanged:true},
    cases:[
      passed("A01";[evidence("a01.bootstrap_resilience";"state";$a01;
        "a01-evidence.json";"BOOTSTRAP_LOSS_DISCOVERY_CONTINUED")]),
      passed("A02";[evidence("a02.transparent_mptcp";"capture";$a02;
        "a02-evidence.json";"MPTCP_TWO_DATA_CARRYING_SUBFLOWS")]),
      passed("A03";[evidence("a03.aggregation";"measurement";$a03;
        "a03-evidence.json";"MPTCP_CONSTRAINED_AGGREGATION")]),
      passed("A04";[evidence("a04.relay_failover";"capture";$a04;
        "a04-evidence.json";"MPTCP_RELAY_FAILOVER")]),
      passed("A05";[evidence("a05.single_relay_udp";"capture";$a05;
        "a05-evidence.json";"SINGLE_RELAY_UDP_NO_DIRECT_EXIT")]),
      passed("A06";[evidence("a06.http3_mpquic";"capture";$a06;
        "a06-evidence.json";"MPQUIC_TWO_DATA_CARRYING_PATHS")]),
      passed("A07";[evidence("a07.relay_failover";"capture";$a07;
        "a07-evidence.json";"MPQUIC_RELAY_FAILOVER")]),
      passed("A08";[evidence("a08.allowed_destination";"state";$a08;
        "a08-evidence.json";"ALLOWED_DESTINATION_POLICY")]),
      passed("A09";[evidence("a09.denials";"state";$a09;
        "a09-evidence.json";"FORBIDDEN_DESTINATIONS_DENIED")]),
      passed("A10";[evidence("a10.ech_denial";"state";$a10;
        "a10-evidence.json";"UNVERIFIABLE_ECH_DENIED")]),
      passed("A11";[evidence("a11.relay_privacy";"capture";$a11;
        "a11-evidence.json";"RELAY_OUTER_PRIVACY")]),
      passed("A12";[evidence("a12.exit_privacy";"capture";$a12;
        "a12-evidence.json";"EXIT_SOURCE_PRIVACY")]),
      passed("A13";[evidence("a13.no_direct_exit";"capture";$a13;
        "a13-evidence.json";"NO_DIRECT_CLIENT_EXIT")]),
      passed("A14";[
        evidence("a14.agent_crashes";"state";$a14;"a14-evidence.json";
          "FORCED_AGENT_CRASH_CLEANUP"),
        evidence("a14.helper_crashes";"state";$a14;"a14-evidence.json";
          "FORCED_HELPER_CRASH_CLEANUP"),
        evidence("a14.native_crashes";"state";$a14;"a14-evidence.json";
          "FORCED_NATIVE_CRASH_CLEANUP"),
        evidence("a14.owned_objects";"state";$a14;"a14-evidence.json";
          "OWNED_OBJECTS_ABSENT")
      ]),
      passed("A15";[
        evidence("a15.host_before";"digest";$host_before;
          "host-state-before.json";"HOST_STATE_BEFORE"),
        evidence("a15.host_after";"digest";$host_after;
          "host-state-after.json";"HOST_STATE_AFTER")
      ])
    ],
    cleanup:{attempted:true,complete:true,remaining_owned_objects:0},
    overall:"PASS"
  }
' >"$temporary_report"

"$repository/tests/integration/validate-report.sh" "$temporary_report"
published_report=$acceptance_report
mv -- "$temporary_report" "$acceptance_report"
temporary_report=
cat "$acceptance_report"
published_report=
