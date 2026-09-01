#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Validate one canonical, PASS-only singleton ExactPresent restart evidence v1 record.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
    printf '%s\n' \
        'usage: tests/helper/validate-helper-restart-exact-present-evidence-v1.sh REPORT.json' >&2
}

invalid() {
    printf 'invalid helper restart ExactPresent evidence v1: %s\n' "$1" >&2
    exit 1
}

if [ "$#" -ne 1 ]; then
    usage
    exit 64
fi

report=$1
if [ ! -f "$report" ] || [ -L "$report" ]; then
    printf '%s\n' 'restart evidence must be one regular, non-symlink file' >&2
    exit 66
fi
for command_name in cmp jq stat; do
    command -v "$command_name" >/dev/null 2>&1 \
        || { printf 'required validator tool is unavailable: %s\n' "$command_name" >&2; exit 69; }
done
[ "$(stat -Lc '%F' -- "$report" 2>/dev/null || true)" = 'regular file' ] \
    || invalid 'input is not a regular file'
[ "$(stat -Lc '%h' -- "$report" 2>/dev/null || true)" = 1 ] \
    || invalid 'input must have exactly one hard link'
report_size=$(stat -Lc '%s' -- "$report" 2>/dev/null) \
    || invalid 'input size is unavailable'
case $report_size in ''|*[!0-9]*) invalid 'input size is invalid' ;; esac
if [ "$report_size" -lt 1 ] || [ "$report_size" -gt 32768 ]; then
    invalid 'input must contain between 1 and 32768 bytes'
fi
jq -e -s 'length == 1' "$report" >/dev/null 2>&1 \
    || invalid 'input is not one valid JSON value'
jq -S -c . "$report" | cmp -s - "$report" \
    || invalid 'input is not the exact LF-terminated one-line jq -S -c encoding'

jq -e '
  def exact_keys($expected): type == "object" and keys == ($expected | sort);
  def sha256: type == "string" and test("^[0-9a-f]{64}$") and (test("^0+$") | not);
  def revision: type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$") and (test("^0+$") | not);
  def invocation: type == "string" and test("^[0-9a-f]{32}$") and (test("^0+$") | not);
  def kernel: type == "string" and length >= 1 and length <= 128
    and test("^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$");
  def utc_epoch:
    if type == "string"
       and test("^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
    then . as $value | try (fromdateiso8601 as $epoch
      | if ($epoch | todateiso8601) == $value then $epoch else null end) catch null
    else null end;
  def checks: [
    "OBSERVED_SOURCE_TREE_CLEAN",
    "OBSERVED_ARTIFACT_HASHES",
    "DEBIAN_13_AMD64_X86_64_SYSTEMD_257_VM",
    "INITIAL_INVOCATION_BOUND",
    "INITIAL_ARGUMENTLESS_PRODUCTION_BOUNDARY",
    "SINGLETON_WORKER_KERNEL_CLEANUP_CONFIRMED",
    "SINGLETON_CLEANUP_CONFIRMED_EXACT_CUSTODY",
    "FORCED_HELPER_SIGKILL_OBSERVED",
    "SYSTEMD_FDSTORE_EXACT_CUSTODY_PRESERVED_AFTER_CRASH",
    "RESTART_DISTINCT_ARGUMENTLESS_INVOCATION_BOUND",
    "RESTART_INHERITED_SINGLETON_EXACT_PRESENT",
    "RESTART_SOCKET_UNPUBLISHED_BEFORE_SETTLEMENT",
    "RESTART_STARTUP_REMOVAL_CALL_OBSERVED",
    "RESTART_FDSTORE_ZERO_AFTER_STABLE_EMPTY_OBSERVATION",
    "RESTART_JOURNAL_ABSENT_RECOVERED_MAY_OWN",
    "RESTART_SOCKET_PUBLISHED_AFTER_SETTLEMENT",
    "RESTART_RETIRED_UNIT_NOT_FOUND",
    "RETIREMENT_LOCK_RELEASED",
    "RETIREMENT_SOCKET_ABSENT",
    "ENUMERATED_HOST_STATE_EQUAL_AT_FENCES"
  ];
  def records: ["production_runtime_path","accounts","namespaces","mounts","resolver",
    "sysctls","links","addresses","routes","rules","nexthops","qdiscs","nftables",
    "wireguard","legacy_ipv4_firewall","legacy_ipv6_firewall"];
  . as $r
  | exact_keys(["checks","enumerated_host_state","environment","finished_at","generated_at",
      "invocation_ids","observed_artifact_hashes","observed_source","overall","report_kind",
      "restart","retirement","schema_version","scope","started_at"])
  and .schema_version == 1
  and .report_kind == "volparossa-helper-restart-exact-present-evidence"
  and (.observed_source | exact_keys(["commit_sha","worktree_clean"])
      and (.commit_sha | revision) and .worktree_clean == true)
  and (.observed_artifact_hashes
      | exact_keys(["debugger_sha256","production_ipc_probe_sha256",
          "production_ipc_unit_hook_sha256","restart_launcher_sha256","restart_observer_sha256",
          "volparossa_helper_sha256"])
      and all(.[]; sha256))
  and (.environment | exact_keys(["debian_version","dpkg_architecture","kernel_release",
      "machine","systemd_version","virtualization"])
      and .debian_version == "13" and .dpkg_architecture == "amd64"
      and (.kernel_release | kernel) and .machine == "x86_64"
      and .systemd_version == 257 and .virtualization == "vm")
  and (($r.started_at | utc_epoch) as $started
      | ($r.restart.initial.cleanup_confirmed_at | utc_epoch) as $confirmed
      | ($r.restart.crash.crashed_at | utc_epoch) as $crashed
      | ($r.restart.resumed.restarted_at | utc_epoch) as $restarted
      | ($r.restart.resumed.settled_at | utc_epoch) as $settled
      | ($r.finished_at | utc_epoch) as $finished
      | ($r.generated_at | utc_epoch) as $generated
      | all([$started,$confirmed,$crashed,$restarted,$settled,$finished,$generated][]; . != null)
      and $started <= $confirmed and $confirmed <= $crashed and $crashed <= $restarted
      and $restarted <= $settled and $settled <= $finished and $finished <= $generated)
  and (.invocation_ids | type == "array" and length == 2
      and all(.[]; invocation) and .[0] != .[1])
  and (.restart | exact_keys(["crash","initial","resumed"])
      and (.initial | exact_keys(["argumentless","cleanup_confirmed_at",
          "fdstore_before_crash","fdstore_exact_identity_bound",
          "journal_phase_before_crash","target_count","target_role",
          "worker_kernel_cleanup_confirmed"])
        and .argumentless == true
        and .target_count == 1 and .target_role == "Client"
        and .worker_kernel_cleanup_confirmed == true
        and .journal_phase_before_crash == "CleanupConfirmed"
        and .fdstore_before_crash == 2 and .fdstore_exact_identity_bound == true)
      and (.crash | exact_keys(["crashed_at","exec_main_code","exec_main_status",
          "failed_unit_retained","fdstore_after_crash","fdstore_exact_identity_preserved",
          "signal","unit_result"])
        and .signal == "SIGKILL" and .unit_result == "signal"
        and .exec_main_code == "killed" and .exec_main_status == 9
        and .failed_unit_retained == true and .fdstore_after_crash == 2
        and .fdstore_exact_identity_preserved == true)
      and (.resumed | exact_keys(["argumentless","inherited_descriptor_count",
          "journal_absent_origin","journal_phase_after_settlement","journal_stable_read_count",
          "journal_temporary_entry_absent","manager_fdstore_after_removal",
          "manager_fdstore_before_removal","new_socket_published_after_settlement",
          "new_socket_published_before_settlement","restarted_at","settled_at",
          "startup_removal_call","target_count","target_disposition","target_phase",
          "unit_load_state_after_retirement"])
        and .argumentless == true and .inherited_descriptor_count == 2
        and .target_count == 1 and .target_phase == "CleanupConfirmed"
        and .target_disposition == "ExactPresent" and .manager_fdstore_before_removal == 2
        and .new_socket_published_before_settlement == false
        and .manager_fdstore_after_removal == 0
        and .startup_removal_call == "systemd_fdstore::remove_restart_custody"
        and .journal_phase_after_settlement == "Absent"
        and .journal_absent_origin == "RecoveredMayOwn"
        and .journal_stable_read_count == 2 and .journal_temporary_entry_absent == true
        and .new_socket_published_after_settlement == true
        and .unit_load_state_after_retirement == "not-found"))
  and (.retirement | exact_keys(["journal_settled_absent","lock_released","socket_absent"])
      and .journal_settled_absent == true and .lock_released == true and .socket_absent == true)
  and (.enumerated_host_state | exact_keys(["after_sha256","before_sha256",
      "equal_at_fences","records"])
      and (.after_sha256 | sha256) and (.before_sha256 | sha256)
      and .after_sha256 == .before_sha256 and .equal_at_fences == true
      and .records == records)
  and (.scope | exact_keys(["acceptance_a01_a15","cleanup_confirmed_exact_present_singleton",
      "cleanup_confirmed_mixed_restart","cleanup_owned","datapath","forced_helper_crash",
      "helper_boundary_only","installed_package","may_own_recovery","restart_recovery"])
      and .acceptance_a01_a15 == false
      and .cleanup_confirmed_exact_present_singleton == true
      and .cleanup_confirmed_mixed_restart == false
      and .cleanup_owned == false and .datapath == false
      and .forced_helper_crash == true and .helper_boundary_only == true
      and .installed_package == false and .may_own_recovery == false
      and .restart_recovery == false)
  and (.checks | type == "array" and length == 20 and [.[].id] == checks
      and all(.[]; exact_keys(["id","result"]) and .result == "PASS"))
  and .overall == "PASS"
' "$report" >/dev/null 2>&1 \
    || invalid 'the exact, bounded, PASS-only singleton contract is not satisfied'
