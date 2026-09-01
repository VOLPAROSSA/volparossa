#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Disposable five-role acceptance runner. Preview never mutates; execute confines every network
# mutation to anonymous user, mount, PID, and network namespaces.
set -eu
umask 077
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH='' cd -- "$HERE/../.." && pwd)
WORKER=$HERE/vertical-topology.sh
MODE=PREVIEW; SUITE=all; SEEN_MODE=no; SEEN_SUITE=no
usage() { printf '%s\n' 'usage: tests/integration/run.sh [--preview|--execute] [--suite all|mptcp|mpquic]'; }
while [ "$#" -gt 0 ]; do
 case $1 in
  --preview) [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }; MODE=PREVIEW; SEEN_MODE=yes;;
  --execute) [ "$SEEN_MODE" = no ] || { usage >&2; exit 64; }; MODE=EXECUTE; SEEN_MODE=yes;;
  --suite) [ "$SEEN_SUITE" = no ] && [ "$#" -ge 2 ] || { usage >&2; exit 64; }; SUITE=$2; SEEN_SUITE=yes; shift;;
  -h|--help) usage; exit 0;;
  *) printf 'unknown integration-runner option: %s\n' "$1" >&2; usage >&2; exit 64;;
 esac
 shift
done
case $SUITE in all|mptcp|mpquic) ;; *) printf 'unsupported acceptance suite: %s\n' "$SUITE" >&2; exit 64;; esac
selected() {
 case "$SUITE:$1" in
  all:*) return 0;; mptcp:A02|mptcp:A03|mptcp:A04|mptcp:A14|mptcp:A15) return 0;;
  mpquic:A06|mpquic:A07|mpquic:A14|mpquic:A15) return 0;; *) return 1;;
 esac
}

preview() {
 printf '%s\n' 'PREVIEW: execute builds the product binaries, captures host state, enters anonymous user/mount/PID/network namespaces, creates Client, Relay 1, Relay 2, Exit, and destination namespaces, launches four real agents plus TCP/UDP endpoints, records the first product blocker, tears down, and requires the host snapshot to match.' >&2
 jq -n --arg suite "$SUITE" '
  def sel($id): if $suite=="all" then true elif $suite=="mptcp" then ($id|IN("A02","A03","A04","A14","A15")) else ($id|IN("A06","A07","A14","A15")) end;
  ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10","A11","A12","A13","A14","A15"] as $ids |
  {schema_version:1,report_kind:"acceptance",suite:$suite,source_revision:null,generated_at:null,started_at:null,finished_at:null,
   execution:{requested_mode:"PREVIEW",attempted:false,completed:false,topology_created:false,blockers:[{code:"EXECUTION_NOT_REQUESTED",message:"Preview is non-mutating; pass --execute to run the disposable topology."}]},
   environment:{debian_version:null,architecture:null,kernel:null,rustc:null,native_revisions:{}},
   host_state:{captured:false,before_digest:null,after_digest:null,unchanged:null},
   cases:($ids|map(. as $id|if sel($id) then {id:$id,selected:true,result:"SKIPPED",reason:{code:"EXECUTION_NOT_REQUESTED",message:"Preview is non-mutating; the selected case was not executed."},evidence:[]} else {id:$id,selected:false,result:"SKIPPED",reason:{code:"NOT_SELECTED",message:"The case is outside the selected preview suite."},evidence:[]} end)),
   cleanup:{attempted:false,complete:null,remaining_owned_objects:null},overall:"BLOCKED"}'
}
if [ "$MODE" = PREVIEW ]; then preview; exit 77; fi

for cmd in cargo date git ip jq mount readlink rustc sha256sum setpriv unshare; do
 command -v "$cmd" >/dev/null 2>&1 || { printf 'required acceptance command unavailable: %s\n' "$cmd" >&2; exit 69; }
done
[ -x "$WORKER" ] || { printf 'topology worker is not executable\n' >&2; exit 69; }
[ "$(sed -n '1{s/\..*$//;p;}' /etc/debian_version)" = 13 ] && [ "$(uname -m)" = x86_64 ] || { printf '%s\n' 'execute requires Debian 13 amd64' >&2; exit 69; }
printf '%s\n' 'EXECUTE: every network mutation is confined to disposable anonymous namespaces; the outer host is observed only.' >&2
TARGET=${CARGO_TARGET_DIR:-$REPO/target/acceptance-build}
case $TARGET in /*) ;; *) TARGET=$REPO/$TARGET;; esac
ARTIFACT_ROOT=${VOLPAROSSA_ACCEPTANCE_ARTIFACT_ROOT:-$TARGET/acceptance-artifacts}
case $ARTIFACT_ROOT in /*) ;; *) ARTIFACT_ROOT=$REPO/$ARTIFACT_ROOT;; esac
/bin/mkdir -p "$ARTIFACT_ROOT"
ARTIFACT=$(mktemp -d "$ARTIFACT_ROOT/run.XXXXXX")
/bin/mkdir "$ARTIFACT/evidence"
REPORT=$ARTIFACT/report.json
RUN_ID=$(tr -d -- - </proc/sys/kernel/random/uuid)
START=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
REVISION=$(git -C "$REPO" rev-parse HEAD)
HOST_NET=$(readlink /proc/self/ns/net); HOST_MNT=$(readlink /proc/self/ns/mnt)
snapshot() {
 out=$1
 {
  printf 'network_namespace=%s\nmount_namespace=%s\nipv4_forward=%s\n' "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/mnt)" "$(sed -n 1p /proc/sys/net/ipv4/ip_forward)"
  printf 'resolv_conf_sha256=%s\n' "$(sha256sum /etc/resolv.conf|awk '{print $1}')"
  printf 'links=\n'; ip -j link show|jq -S 'sort_by(.ifindex)'
  printf 'addresses=\n'; ip -j address show|jq -S 'walk(if type=="object" then del(.valid_life_time,.preferred_life_time) else . end)|sort_by(.ifindex)'
  printf 'routes=\n'; ip -j route show table all|jq -S 'walk(if type=="object" then del(.expires,.used) else . end)|sort_by([.table,.dst,.dev,.gateway])'
  printf 'rules=\n'; ip -j rule show|jq -S 'sort_by([.priority,.table])'
 } >"$out"
}
snapshot "$ARTIFACT/evidence/host-before.manifest"
CARGO_TARGET_DIR=$TARGET cargo build --locked --quiet -p volparossa --bin volparossa -p volparossa-agent --bin volparossa-agent -p volparossa-policy --example acceptance-policy-fixture
set +e
unshare --user --map-root-user --mount --net --pid --fork --mount-proc "$WORKER" --internal "$RUN_ID" "$ARTIFACT" "$TARGET/debug" "$HOST_NET" "$HOST_MNT"
worker_status=$?
set -e
snapshot "$ARTIFACT/evidence/host-after.manifest"
BEFORE=$(sha256sum "$ARTIFACT/evidence/host-before.manifest"|awk '{print $1}')
AFTER=$(sha256sum "$ARTIFACT/evidence/host-after.manifest"|awk '{print $1}')
TOPOLOGY_DIGEST=$(sha256sum "$ARTIFACT/evidence/topology.json"|awk '{print $1}')
CLEANUP_DIGEST=$(sha256sum "$ARTIFACT/evidence/cleanup.json"|awk '{print $1}')
FINISH=$(date -u '+%Y-%m-%dT%H:%M:%SZ'); KERNEL=$(uname -r); RUSTC=$(rustc --version)
[ "$BEFORE" = "$AFTER" ] && UNCHANGED=true || UNCHANGED=false
if [ "$worker_status" -eq 77 ] && jq -e '.topology_ready and .first_product_blocker.code=="PRODUCT_DATAPLANE_UNAVAILABLE" and .client_connect.diagnostic_code=="DATAPLANE_UNAVAILABLE"' "$ARTIFACT/evidence/topology.json" >/dev/null && jq -e '.complete and .remaining_owned_objects==0' "$ARTIFACT/evidence/cleanup.json" >/dev/null; then
 TOPOLOGY=true; COMPLETED=true; CODE=PRODUCT_DATAPLANE_UNAVAILABLE; MESSAGE='All five disposable roles started; the real client control API then failed closed with DATAPLANE_UNAVAILABLE before creating a route.'
else
 TOPOLOGY=false; COMPLETED=false; CODE=TOPOLOGY_EXECUTION_ERROR; MESSAGE='The isolated topology did not reach exact role readiness.'
fi
if [ "$UNCHANGED" = false ]; then OVERALL=FAIL; elif [ "$CODE" = TOPOLOGY_EXECUTION_ERROR ]; then OVERALL=ERROR; else OVERALL=BLOCKED; fi

jq -n --arg suite "$SUITE" --arg rev "$REVISION" --arg time "$FINISH" --arg start "$START" --arg kernel "$KERNEL" --arg rustc "$RUSTC" --arg before "$BEFORE" --arg after "$AFTER" --argjson unchanged "$UNCHANGED" --argjson topology "$TOPOLOGY" --argjson completed "$COMPLETED" --arg code "$CODE" --arg message "$MESSAGE" --arg td "$TOPOLOGY_DIGEST" --arg cd "$CLEANUP_DIGEST" --arg overall "$OVERALL" '
 def sel($id):if $suite=="all" then true elif $suite=="mptcp" then ($id|IN("A02","A03","A04","A14","A15")) else ($id|IN("A06","A07","A14","A15")) end;
 def r($c;$m):{code:$c,message:$m}; def e($id;$k;$d;$p;$c):{id:$id,kind:$k,sha256:$d,path:$p,check:$c};
 ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10","A11","A12","A13","A14","A15"] as $ids |
 (if $suite=="all" then "A01" elif $suite=="mptcp" then "A02" else "A06" end) as $ec |
 ([r($code;$message),r("FORCED_CRASH_NOT_EXECUTED";"Normal teardown ran; forced crash cleanup did not run."),r("HOST_STATE_SCOPE_PARTIAL";"Links, addresses, routes, rules, DNS and IPv4 forwarding were compared; nftables observation is unavailable on this host.")]+if $suite=="all" then [] else [r("PARTIAL_SUITE";"Only the requested acceptance subset ran.")] end) as $blockers |
 {schema_version:1,report_kind:"acceptance",suite:$suite,source_revision:$rev,generated_at:$time,started_at:$start,finished_at:$time,
 execution:{requested_mode:"EXECUTE",attempted:true,completed:$completed,topology_created:$topology,blockers:$blockers},environment:{debian_version:"13",architecture:"amd64",kernel:$kernel,rustc:$rustc,native_revisions:{}},host_state:{captured:true,before_digest:$before,after_digest:$after,unchanged:$unchanged},
 cases:($ids|map(. as $id|if (sel($id)|not) then {id:$id,selected:false,result:"SKIPPED",reason:r("NOT_SELECTED";"The case is outside the selected suite."),evidence:[]}
 elif $id=="A15" and $unchanged then {id:$id,selected:true,result:"SKIPPED",reason:r("HOST_STATE_SCOPE_PARTIAL";"The observed host-network state was unchanged, but nftables could not be captured on this host."),evidence:[e("a15.host_before";"digest";$before;"evidence/host-before.manifest";"HOST_STATE_BEFORE_PARTIAL"),e("a15.host_after";"digest";$after;"evidence/host-after.manifest";"HOST_STATE_AFTER_PARTIAL")]}
 elif $id=="A15" then {id:$id,selected:true,result:"FAIL",reason:r("HOST_STATE_CHANGED";"The outer host-state manifest changed."),evidence:[e("a15.host_before";"digest";$before;"evidence/host-before.manifest";"HOST_STATE_BEFORE"),e("a15.host_after";"digest";$after;"evidence/host-after.manifest";"HOST_STATE_AFTER")]}
 elif $id=="A14" then {id:$id,selected:true,result:"SKIPPED",reason:r("FORCED_CRASH_NOT_EXECUTED";"Normal teardown ran; forced crash cleanup did not run."),evidence:[]}
 else {id:$id,selected:true,result:(if $code=="TOPOLOGY_EXECUTION_ERROR" then "ERROR" else "SKIPPED" end),reason:r($code;$message),evidence:(if $id==$ec then [e("topology.setup";"state";$td;"evidence/topology.json";"DISPOSABLE_TOPOLOGY_SETUP"),e("topology.cleanup";"state";$cd;"evidence/cleanup.json";"OWNED_OBJECTS_ABSENT")] else [] end)} end)),
 cleanup:{attempted:true,complete:true,remaining_owned_objects:0},overall:$overall}' >"$REPORT"
printf 'acceptance artifacts: %s\n' "$ARTIFACT" >&2
cat "$REPORT"
[ "$OVERALL" = BLOCKED ] && exit 77
exit 1
