#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Validate one canonical, PASS-only helper-boundary evidence v1 record.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

usage() {
    printf '%s\n' \
        'usage: tests/helper/validate-helper-boundary-evidence-v1.sh REPORT.json' >&2
}

invalid() {
    printf 'invalid helper-boundary evidence v1: %s\n' "$1" >&2
    exit 1
}

if [ "$#" -ne 1 ]; then
    usage
    exit 64
fi

report=$1
if [ ! -f "$report" ] || [ -L "$report" ]; then
    printf '%s\n' 'helper-boundary evidence must be one regular, non-symlink file' >&2
    exit 66
fi

for command_name in cmp jq stat; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'required validator tool is unavailable: %s\n' "$command_name" >&2
        exit 69
    fi
done

report_kind=$(stat -Lc '%F' -- "$report" 2>/dev/null) \
    || invalid 'input metadata is unavailable'
[ "$report_kind" = 'regular file' ] || invalid 'input is not a regular file'
report_size=$(stat -Lc '%s' -- "$report" 2>/dev/null) \
    || invalid 'input size is unavailable'
case $report_size in
    ''|*[!0-9]*) invalid 'input size is invalid' ;;
esac
if [ "$report_size" -eq 0 ] || [ "$report_size" -gt 32768 ]; then
    invalid 'input must contain between 1 and 32768 bytes'
fi

if ! jq -e -s 'length == 1' "$report" >/dev/null 2>&1; then
    invalid 'input is not one valid JSON value'
fi
if ! jq -S -c . "$report" | cmp -s - "$report"; then
    invalid 'input is not the exact LF-terminated one-line jq -S -c encoding'
fi

if ! jq -e '
    def exact_keys($expected):
        type == "object" and keys == ($expected | sort);
    def valid_sha256:
        type == "string"
        and test("^[0-9a-f]{64}$")
        and (test("^0+$") | not);
    def valid_source_revision:
        type == "string"
        and test("^([0-9a-f]{40}|[0-9a-f]{64})$")
        and (test("^0+$") | not);
    def valid_invocation_id:
        type == "string"
        and test("^[0-9a-f]{32}$")
        and (test("^0+$") | not);
    def valid_kernel_release:
        type == "string"
        and length >= 1
        and length <= 128
        and test("^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$");
    def utc_epoch:
        if type == "string"
            and test("^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$")
        then . as $timestamp
            | try (fromdateiso8601 as $epoch
                | if ($epoch | todateiso8601) == $timestamp
                  then $epoch
                  else null
                  end)
              catch null
        else null
        end;
    def expected_check_ids:
        [
          "OBSERVED_SOURCE_TREE_CLEAN",
          "OBSERVED_ARTIFACT_HASHES",
          "DEBIAN_13_AMD64_X86_64_SYSTEMD_257_VM",
          "WORKER_INVOCATION_BOUND",
          "WORKER_LIVE_IDENTITY",
          "WORKER_FDSTORE_TWO_BEFORE_RETIREMENT",
          "WORKER_RETIRED_UNIT_NOT_FOUND",
          "PRODUCTION_DISTINCT_INVOCATION_BOUND",
          "PRODUCTION_ARGUMENTLESS",
          "PRODUCTION_IPC_BOUNDARY",
          "PRODUCTION_FDSTORE_ZERO_AT_IDLE_OBSERVATION",
          "PRODUCTION_FDSTORE_EXACT_CUSTODY_DURING_ACTIVE_CYCLES",
          "PRODUCTION_FDSTORE_ZERO_AFTER_SETTLED_CYCLES",
          "PRODUCTION_RETIRED_UNIT_NOT_FOUND",
          "RETIREMENT_JOURNAL_SETTLED_ABSENT",
          "RETIREMENT_LOCK_RELEASED",
          "RETIREMENT_SOCKET_ABSENT",
          "ENUMERATED_HOST_STATE_EQUAL_AT_FENCES"
        ];
    def expected_host_state_records:
        [
          "production_runtime_path",
          "accounts",
          "namespaces",
          "mounts",
          "resolver",
          "sysctls",
          "links",
          "addresses",
          "routes",
          "rules",
          "nexthops",
          "qdiscs",
          "nftables",
          "wireguard",
          "legacy_ipv4_firewall",
          "legacy_ipv6_firewall"
        ];

    . as $report
    | exact_keys([
        "checks",
        "enumerated_host_state",
        "environment",
        "finished_at",
        "generated_at",
        "invocation_ids",
        "observed_artifact_hashes",
        "observed_source",
        "overall",
        "production",
        "report_kind",
        "retirement",
        "schema_version",
        "scope",
        "started_at",
        "worker"
      ])
    and (.schema_version == 1)
    and (.report_kind == "volparossa-helper-boundary-evidence")
    and (.observed_source
        | exact_keys(["commit_sha", "worktree_clean"])
        and (.commit_sha | valid_source_revision)
        and .worktree_clean == true)
    and (.observed_artifact_hashes
        | exact_keys([
            "production_ipc_probe_sha256",
            "production_ipc_unit_hook_sha256",
            "volparossa_helper_sha256"
          ])
        and all(.[]; valid_sha256))
    and (.environment
        | exact_keys([
            "debian_version",
            "dpkg_architecture",
            "kernel_release",
            "machine",
            "systemd_version",
            "virtualization"
          ])
        and .debian_version == "13"
        and .dpkg_architecture == "amd64"
        and (.kernel_release | valid_kernel_release)
        and .machine == "x86_64"
        and .systemd_version == 257
        and .virtualization == "vm")
    and (($report.started_at | utc_epoch) as $started
        | ($report.finished_at | utc_epoch) as $finished
        | ($report.generated_at | utc_epoch) as $generated
        | $started != null
        and $finished != null
        and $generated != null
        and $started <= $finished
        and $finished <= $generated)
    and (.invocation_ids
        | type == "array"
        and length == 2
        and all(.[]; valid_invocation_id)
        and .[0] != .[1])
    and (.worker
        | exact_keys([
            "fdstore_before_retirement",
            "unit_load_state_after_retirement"
          ])
        and .fdstore_before_retirement == 2
        and .unit_load_state_after_retirement == "not-found")
    and (.production
        | exact_keys([
            "argumentless",
            "fdstore_active_cycle_counts",
            "fdstore_exact_identity_bound",
            "fdstore_idle_observation",
            "fdstore_settled_cycle_counts",
            "unit_load_state_after_retirement"
          ])
        and .argumentless == true
        and .fdstore_active_cycle_counts == [2, 2, 2]
        and .fdstore_exact_identity_bound == true
        and .fdstore_idle_observation == 0
        and .fdstore_settled_cycle_counts == [0, 0, 0]
        and .unit_load_state_after_retirement == "not-found")
    and (.retirement
        | exact_keys(["journal_settled_absent", "lock_released", "socket_absent"])
        and .journal_settled_absent == true
        and .lock_released == true
        and .socket_absent == true)
    and (.enumerated_host_state
        | exact_keys(["after_sha256", "before_sha256", "equal_at_fences", "records"])
        and (.after_sha256 | valid_sha256)
        and (.before_sha256 | valid_sha256)
        and .after_sha256 == .before_sha256
        and .equal_at_fences == true
        and .records == expected_host_state_records)
    and (.scope
        | exact_keys([
            "acceptance_a01_a15",
            "cleanup_owned",
            "datapath",
            "helper_boundary_only",
            "installed_package",
            "restart_recovery"
          ])
        and .acceptance_a01_a15 == false
        and .cleanup_owned == false
        and .datapath == false
        and .helper_boundary_only == true
        and .installed_package == false
        and .restart_recovery == false)
    and (.checks
        | type == "array"
        and length == 18
        and [.[].id] == expected_check_ids
        and all(.[];
            exact_keys(["id", "result"])
            and .result == "PASS"))
    and (.overall == "PASS")
' "$report" >/dev/null 2>&1; then
    invalid 'the exact, bounded, PASS-only evidence contract is not satisfied'
fi
