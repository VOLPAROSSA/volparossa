#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Validate one canonical PASS-only singleton MayOwnCustody Relay restart record.
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

invalid() {
    printf 'invalid helper restart MayOwnCustody Relay evidence v1: %s\n' "$1" >&2
    exit 1
}

[ "$#" -eq 1 ] || exit 64
report=$1
[ -f "$report" ] && [ ! -L "$report" ] || exit 66
for command_name in cmp jq stat; do
    command -v "$command_name" >/dev/null 2>&1 || exit 69
done
[ "$(stat -Lc '%F:%h' -- "$report" 2>/dev/null || true)" = 'regular file:1' ] \
    || invalid 'input identity is invalid'
report_size=$(stat -Lc '%s' -- "$report") || invalid 'input size is unavailable'
case $report_size in ''|*[!0-9]*) invalid 'input size is invalid' ;; esac
if [ "$report_size" -lt 1 ] || [ "$report_size" -gt 32768 ]; then
    invalid 'input size is outside the bound'
fi
jq -e -s 'length == 1' "$report" >/dev/null 2>&1 \
    || invalid 'input is not one JSON value'
jq -S -c . "$report" | cmp -s - "$report" \
    || invalid 'input is not canonical LF-terminated jq encoding'

jq -e '
  def exact_keys($expected): type == "object" and keys == ($expected | sort);
  def sha256: type == "string" and test("^[0-9a-f]{64}$") and (test("^0+$") | not);
  def revision: type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$")
    and (test("^0+$") | not);
  def invocation: type == "string" and test("^[0-9a-f]{32}$")
    and (test("^0+$") | not);
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
    "SINGLETON_RELAY_MAY_OWN_CUSTODY_EXACT_PRESENT",
    "FIRST_CRASH_AT_PUBLISHED_TERMINAL_GUARD",
    "FIRST_FORCED_HELPER_SIGKILL_OBSERVED",
    "FIRST_SYSTEMD_FDSTORE_EXACT_CUSTODY_PRESERVED",
    "SECOND_DISTINCT_ARGUMENTLESS_INVOCATION_BOUND",
    "SECOND_INHERITED_SINGLETON_MAY_OWN_EXACT_PRESENT",
    "REAPER_CLEANUP_EVIDENCE_REACHED_JOURNAL_BOUNDARY",
    "SECOND_FORCED_HELPER_SIGKILL_OBSERVED",
    "SECOND_SYSTEMD_FDSTORE_EXACT_CUSTODY_PRESERVED",
    "THIRD_DISTINCT_ARGUMENTLESS_INVOCATION_BOUND",
    "THIRD_INHERITED_SINGLETON_MAY_OWN_EXACT_PRESENT",
    "CLEANUP_CONFIRMED_BEFORE_MANAGER_REMOVAL",
    "STARTUP_REMOVAL_CALL_OBSERVED",
    "MANAGER_FDSTORE_ZERO_AFTER_REMOVAL",
    "JOURNAL_ABSENT_RECOVERED_MAY_OWN",
    "SOCKET_PUBLISHED_ONLY_AFTER_SETTLEMENT",
    "RECOVERED_UNIT_RETIRED_NOT_FOUND",
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
  and .report_kind == "volparossa-helper-restart-may-own-custody-relay-evidence"
  and (.observed_source | exact_keys(["commit_sha","worktree_clean"])
      and (.commit_sha | revision) and .worktree_clean == true)
  and (.observed_artifact_hashes
      | exact_keys(["debugger_sha256","may_own_observer_sha256",
          "production_ipc_probe_sha256","production_ipc_unit_hook_sha256",
          "volparossa_helper_sha256"])
      and all(.[]; sha256))
  and (.environment | exact_keys(["debian_version","dpkg_architecture","kernel_release",
      "machine","systemd_version","virtualization"])
      and .debian_version == "13" and .dpkg_architecture == "amd64"
      and (.kernel_release | kernel) and .machine == "x86_64"
      and .systemd_version == 257 and .virtualization == "vm")
  and (($r.started_at | utc_epoch) as $started
      | ($r.restart.initial.publication_observed_at | utc_epoch) as $published
      | ($r.restart.crashes[0].crashed_at | utc_epoch) as $crash_one
      | ($r.restart.crashes[1].boundary_observed_at | utc_epoch) as $confirmed
      | ($r.restart.crashes[1].crashed_at | utc_epoch) as $crash_two
      | ($r.restart.recovered.removal_observed_at | utc_epoch) as $removal
      | ($r.restart.recovered.settled_at | utc_epoch) as $settled
      | ($r.finished_at | utc_epoch) as $finished
      | ($r.generated_at | utc_epoch) as $generated
      | all([$started,$published,$crash_one,$confirmed,$crash_two,$removal,$settled,
          $finished,$generated][]; . != null)
      and $started <= $published and $published <= $crash_one
      and $crash_one <= $confirmed and $confirmed <= $crash_two
      and $crash_two <= $removal and $removal <= $settled
      and $settled <= $finished and $finished <= $generated)
  and (.invocation_ids | type == "array" and length == 3 and all(.[]; invocation)
      and .[0] != .[1] and .[0] != .[2] and .[1] != .[2])
  and (.restart | exact_keys(["crashes","initial","recovered"])
      and (.initial | exact_keys(["argumentless","manager_fdstore_count",
          "publication_boundary","publication_observed_at","target_count",
          "target_disposition","target_phase","target_role"])
        and .argumentless == true and .target_count == 1 and .target_role == "Relay"
        and .target_phase == "MayOwnCustody" and .target_disposition == "ExactPresent"
        and .manager_fdstore_count == 2
        and .publication_boundary ==
          "worker_v3::DurableCustodyPublicationTerminalGuard::retain_published")
      and (.crashes | type == "array" and length == 2
        and (.[0] | exact_keys(["boundary","crashed_at","exec_main_code",
            "exec_main_status","journal_phase_after_crash","manager_fdstore_after_crash",
            "sequence","signal","unit_result"])
          and .sequence == 1
          and .boundary == "worker_v3::DurableCustodyPublicationTerminalGuard::retain_published"
          and .signal == "SIGKILL" and .unit_result == "signal"
          and .exec_main_code == 2 and .exec_main_status == 9
          and .manager_fdstore_after_crash == 2
          and .journal_phase_after_crash == "MayOwnCustody")
        and (.[1] | exact_keys(["boundary","boundary_observed_at","crashed_at",
            "exec_main_code","exec_main_status","journal_phase_after_crash",
            "manager_fdstore_after_crash","sequence","signal","unit_result"])
          and .sequence == 2
          and .boundary ==
            "ownership_journal::actor::DurableOwnershipStartup::confirm_single_restart_cleanup"
          and .signal == "SIGKILL" and .unit_result == "signal"
          and .exec_main_code == 2 and .exec_main_status == 9
          and .manager_fdstore_after_crash == 2
          and .journal_phase_after_crash == "MayOwnCustody"))
      and (.recovered | exact_keys(["argumentless","cleanup_confirmed_before_removal",
          "inherited_descriptor_count","journal_absent_origin","journal_phase_after_settlement",
          "manager_fdstore_after_removal","new_socket_published_after_settlement",
          "new_socket_published_before_settlement","removal_boundary","removal_observed_at",
          "settled_at","target_count","target_role","unit_load_state_after_retirement"])
        and .argumentless == true and .target_count == 1 and .target_role == "Relay"
        and .inherited_descriptor_count == 2
        and .cleanup_confirmed_before_removal == true
        and .removal_boundary == "systemd_fdstore::remove_restart_custody"
        and .manager_fdstore_after_removal == 0
        and .journal_phase_after_settlement == "Absent"
        and .journal_absent_origin == "RecoveredMayOwn"
        and .new_socket_published_before_settlement == false
        and .new_socket_published_after_settlement == true
        and .unit_load_state_after_retirement == "not-found"))
  and (.retirement | exact_keys(["journal_settled_absent","lock_released","socket_absent"])
      and all(.[]; . == true))
  and (.enumerated_host_state | exact_keys(["after_sha256","before_sha256",
      "equal_at_fences","records"])
      and (.after_sha256 | sha256) and (.before_sha256 | sha256)
      and .after_sha256 == .before_sha256 and .equal_at_fences == true
      and .records == records)
  and (.scope | exact_keys(["acceptance_a01_a15","cleanup_owned",
      "forced_helper_crash_count","general_restart_recovery","helper_boundary_only",
      "installed_package","may_own_custody_exact_present_singleton_relay",
      "usable_datapath"])
      and .acceptance_a01_a15 == false and .cleanup_owned == false
      and .forced_helper_crash_count == 2 and .general_restart_recovery == false
      and .helper_boundary_only == true and .installed_package == false
      and .may_own_custody_exact_present_singleton_relay == true
      and .usable_datapath == false)
  and (.checks | type == "array" and length == 25 and [.[].id] == checks
      and all(.[]; exact_keys(["id","result"]) and .result == "PASS"))
  and .overall == "PASS"
' "$report" >/dev/null 2>&1 \
    || invalid 'the exact bounded singleton contract is not satisfied'
