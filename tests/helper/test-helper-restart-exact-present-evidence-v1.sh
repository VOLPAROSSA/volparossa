#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Adversarial tests for the canonical singleton ExactPresent restart evidence contract.
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
validator=$here/validate-helper-restart-exact-present-evidence-v1.sh
fixture=$here/fixtures/helper-restart-exact-present-evidence-v1.pass.json
tmp=$(mktemp -d /tmp/volparossa-restart-evidence-test.XXXXXX)
case $tmp in /tmp/volparossa-restart-evidence-test.??????) ;; *) exit 1 ;; esac
trap 'rm -rf --one-file-system -- "$tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

counter=0
expect() {
    wanted=$1; shift; counter=$((counter + 1))
    set +e
    "$@" >"$tmp/out.$counter" 2>"$tmp/err.$counter"
    got=$?
    set -e
    [ "$got" -eq "$wanted" ] || { sed -n '1,80p' "$tmp/err.$counter" >&2; exit 1; }
}
reject() {
    name=$1; filter=$2
    jq -S -c "$filter" "$fixture" >"$tmp/$name.json"
    expect 1 "$validator" "$tmp/$name.json"
}

sh -n "$validator"
jq -e . "$here/helper-restart-exact-present-evidence-v1.schema.json" >/dev/null
expect 0 "$validator" "$fixture"
[ ! -s "$tmp/out.$counter" ] && [ ! -s "$tmp/err.$counter" ] || exit 1

reject extra-top '.unexpected=true'
reject missing-top 'del(.restart)'
reject wrong-kind '.report_kind="mixed"'
reject dirty-source '.observed_source.worktree_clean=false'
reject zero-hash '.observed_artifact_hashes.restart_observer_sha256=("0"*64)'
reject missing-launcher-hash 'del(.observed_artifact_hashes.restart_launcher_sha256)'
reject extra-hash '.observed_artifact_hashes.extra=("a"*64)'
reject wrong-vm '.environment.virtualization="container"'
reject same-invocation '.invocation_ids[1]=.invocation_ids[0]'
reject target-count-zero '.restart.initial.target_count=0'
reject target-count-mixed '.restart.initial.target_count=2'
reject target-role '.restart.initial.target_role="Relay"'
reject missing-initial-role 'del(.restart.initial.target_role)'
reject phase '.restart.initial.journal_phase_before_crash="MayOwnCustody"'
reject custody-count '.restart.initial.fdstore_before_crash=1'
reject custody-unbound '.restart.initial.fdstore_exact_identity_bound=false'
reject worker-not-cleaned '.restart.initial.worker_kernel_cleanup_confirmed=false'
reject soft-signal '.restart.crash.signal="SIGTERM"'
reject wrong-result '.restart.crash.unit_result="success"'
reject wrong-code '.restart.crash.exec_main_code="exited"'
reject wrong-status '.restart.crash.exec_main_status=0'
reject failed-not-retained '.restart.crash.failed_unit_retained=false'
reject crash-fdstore-lost '.restart.crash.fdstore_after_crash=0'
reject crash-identity-lost '.restart.crash.fdstore_exact_identity_preserved=false'
reject inherited-count '.restart.resumed.inherited_descriptor_count=1'
reject wrong-disposition '.restart.resumed.target_disposition="MayOwn"'
reject early-socket '.restart.resumed.new_socket_published_before_settlement=true'
reject manager-before-not-two '.restart.resumed.manager_fdstore_before_removal=1'
reject manager-before-missing 'del(.restart.resumed.manager_fdstore_before_removal)'
reject manager-not-empty '.restart.resumed.manager_fdstore_after_removal=1'
reject wrong-startup-call \
    '.restart.resumed.startup_removal_call="systemd_fdstore::remove_current_process_custody"'
reject wrong-origin '.restart.resumed.journal_absent_origin="NeverDispatched"'
reject unstable-journal '.restart.resumed.journal_stable_read_count=1'
reject next-present '.restart.resumed.journal_temporary_entry_absent=false'
reject no-new-socket '.restart.resumed.new_socket_published_after_settlement=false'
reject still-loaded '.restart.resumed.unit_load_state_after_retirement="loaded"'
reject mixed-overclaim '.scope.cleanup_confirmed_mixed_restart=true'
reject generic-overclaim '.scope.restart_recovery=true'
reject mayown-overclaim '.scope.may_own_recovery=true'
reject cleanup-overclaim '.scope.cleanup_owned=true'
reject datapath-overclaim '.scope.datapath=true'
reject acceptance-overclaim '.scope.acceptance_a01_a15=true'
reject narrow-negative '.scope.cleanup_confirmed_exact_present_singleton=false'
reject digest-mismatch '.enumerated_host_state.after_sha256=("a"*64)'
reject failed-check '.checks[0].result="FAIL"'
reject missing-check '.checks=.checks[0:19]'
reject renamed-check '.checks[10].id="GENERIC_RESTART"'
reject reversed-confirmed '.restart.initial.cleanup_confirmed_at="2026-08-30T11:59:59Z"'
reject crash-before-confirmed '.restart.crash.crashed_at=.started_at'
reject settled-before-restart '.restart.resumed.settled_at=.restart.crash.crashed_at'

jq -S . "$fixture" >"$tmp/pretty.json"; expect 1 "$validator" "$tmp/pretty.json"
tr -d '\n' <"$fixture" >"$tmp/no-lf.json"; expect 1 "$validator" "$tmp/no-lf.json"
awk '{print; print}' "$fixture" >"$tmp/two.json"; expect 1 "$validator" "$tmp/two.json"
awk 'BEGIN {for(i=0;i<32769;i++) printf "x"}' >"$tmp/large.json"; expect 1 "$validator" "$tmp/large.json"
ln -s "$fixture" "$tmp/link.json"; expect 66 "$validator" "$tmp/link.json"
cp "$fixture" "$tmp/hardlink-source.json"
ln "$tmp/hardlink-source.json" "$tmp/hardlink.json"
expect 1 "$validator" "$tmp/hardlink.json"
expect 66 "$validator" "$tmp"
expect 66 "$validator" "$tmp/missing.json"
expect 64 "$validator"

printf '%s\n' 'PASS: singleton ExactPresent restart evidence rejected every adversarial mutation.'
