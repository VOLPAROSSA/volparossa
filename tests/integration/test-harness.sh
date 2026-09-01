#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Static and preview-only regressions for the privileged harness contract.
set -eu

SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_DIRECTORY=$(CDPATH='' cd -- "$SCRIPT_DIRECTORY/../.." && pwd)
TEMPORARY_DIRECTORY=$(mktemp -d /tmp/volparossa-harness-test.XXXXXX)
case "$TEMPORARY_DIRECTORY" in
    /tmp/volparossa-harness-test.??????) ;;
    *)
        printf 'unsafe harness test directory: %s\n' "$TEMPORARY_DIRECTORY" >&2
        exit 1
        ;;
esac
cleanup() {
    /bin/rm -r -- "$TEMPORARY_DIRECTORY"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

counter=0
LAST_OUTPUT=
LAST_ERROR=
expect_status() {
    expected=$1
    shift
    counter=$((counter + 1))
    LAST_OUTPUT=$TEMPORARY_DIRECTORY/output.$counter
    LAST_ERROR=$TEMPORARY_DIRECTORY/error.$counter
    set +e
    "$@" >"$LAST_OUTPUT" 2>"$LAST_ERROR"
    actual=$?
    set -e
    if [ "$actual" -ne "$expected" ]; then
        printf 'expected exit %s, got %s: %s\n' "$expected" "$actual" "$*" >&2
        sed -n '1,80p' "$LAST_ERROR" >&2
        exit 1
    fi
}

assert_selected_ids() {
    report=$1
    expected=$2
    actual=$(jq -r '[.cases[] | select(.selected) | .id] | join(",")' "$report")
    if [ "$actual" != "$expected" ]; then
        printf 'selected case mismatch: expected %s, got %s\n' "$expected" "$actual" >&2
        exit 1
    fi
}

command -v jq >/dev/null 2>&1 || {
    printf '%s\n' 'jq is required for harness regression tests' >&2
    exit 69
}

for script_path in \
    tests/helper/lib/live-worker-proof-capture.sh \
    tests/helper/lib/production-ipc-unit-hook.sh \
    tests/helper/lib/restart-exact-present-observer.sh \
    tests/helper/lib/restart-may-own-relay-observer.sh \
    tests/helper/require-live-worker-identity-proof.sh \
    tests/helper/run-helper-boundary-evidence-vm.sh \
    tests/helper/test-helper-boundary-evidence-v1.sh \
    tests/helper/test-helper-boundary-vm-contract.sh \
    tests/helper/test-helper-boundary-vm-environment-v1.sh \
    tests/helper/test-helper-restart-exact-present-evidence-v1.sh \
    tests/helper/test-helper-restart-kvm-contract.sh \
    tests/helper/test-helper-restart-may-own-kvm-contract.sh \
    tests/helper/test-helper-restart-service-shape-contract.sh \
    tests/helper/test-helper-restart-vm-environment-v1.sh \
    tests/helper/test-live-worker-identity-contract.sh \
    tests/helper/test-production-ipc-busctl-parser.sh \
    tests/helper/test-qemu-pidfd-supervisor.sh \
    tests/helper/validate-helper-boundary-evidence-v1.sh \
    tests/helper/validate-helper-boundary-vm-environment-v1.sh \
    tests/helper/validate-helper-restart-exact-present-evidence-v1.sh \
    tests/helper/validate-helper-restart-may-own-custody-relay-evidence-v1.sh \
    tests/helper/validate-helper-restart-may-own-custody-relay-vm-environment-v1.sh \
    tests/helper/validate-helper-restart-vm-environment-v1.sh \
    tests/integration/run.sh \
    tests/integration/validate-report.sh \
    tests/netns/run-topology.sh \
    tests/netns/run-benchmarks.sh \
    tests/netns/test-lifecycle-contract.sh \
    tests/netns/topology.sh \
    tests/netns/lib/lifecycle-contract.sh \
    packaging/build-deb.sh \
    packaging/collect-cargo-licenses.sh \
    packaging/debian/postinst \
    packaging/debian/prerm \
    packaging/debian/postrm \
    scripts/bootstrap-debian13-dev.sh \
    scripts/check-system.sh \
    scripts/cleanup-network.sh \
    scripts/run-fuzz.sh
do
    sh -n "$REPOSITORY_DIRECTORY/$script_path"
done
jq -e . "$REPOSITORY_DIRECTORY/tests/integration/acceptance-report.schema.json" >/dev/null
jq -e . "$REPOSITORY_DIRECTORY/tests/helper/helper-boundary-evidence-v1.schema.json" >/dev/null
jq -e . "$REPOSITORY_DIRECTORY/tests/helper/helper-restart-exact-present-evidence-v1.schema.json" >/dev/null
jq -e . "$REPOSITORY_DIRECTORY/tests/helper/helper-restart-may-own-custody-relay-evidence-v1.schema.json" >/dev/null
jq -e . "$REPOSITORY_DIRECTORY/tests/helper/helper-restart-may-own-custody-relay-vm-environment-v1.schema.json" >/dev/null
jq -e . "$REPOSITORY_DIRECTORY/tests/helper/helper-restart-vm-environment-v1.schema.json" >/dev/null
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-boundary-evidence-v1.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-boundary-vm-contract.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-boundary-vm-environment-v1.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-restart-exact-present-evidence-v1.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-restart-kvm-contract.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-restart-may-own-kvm-contract.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-restart-service-shape-contract.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-helper-restart-vm-environment-v1.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-live-worker-identity-contract.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-production-ipc-busctl-parser.sh"
"$REPOSITORY_DIRECTORY/tests/helper/test-qemu-pidfd-supervisor.sh"

/bin/mkdir "$TEMPORARY_DIRECTORY/bin"
MUTATION_MARKER=$TEMPORARY_DIRECTORY/mutation-attempt
export VOLPAROSSA_MUTATION_MARKER="$MUTATION_MARKER"
for command_name in \
    cargo chmod chown cp dpkg-deb install ip ln mkdir mktemp modprobe mount mv nft nsenter rm \
    rmdir setpriv sudo sysctl systemctl systemd-run tc touch truncate umount unshare wg
do
    shim=$TEMPORARY_DIRECTORY/bin/$command_name
    # Variables expand in the generated shim, not in this harness.
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'printf "%s\\n" "$0" >>"$VOLPAROSSA_MUTATION_MARKER"' \
        'exit 99' >"$shim"
    /bin/chmod 0755 "$shim"
done
PATH=$TEMPORARY_DIRECTORY/bin:$PATH
export PATH

expect_status 77 "$REPOSITORY_DIRECTORY/tests/integration/run.sh" --preview --suite all
all_report=$LAST_OUTPUT
"$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$all_report"
jq -e '
    .overall == "BLOCKED"
    and .execution.attempted == false
    and .execution.topology_created == false
    and all(.cases[]; .selected == true and .result == "SKIPPED")
    and ([.cases[].result] | index("PASS") | not)
' "$all_report" >/dev/null

expect_status 77 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --preview --only mptcp
mptcp_report=$LAST_OUTPUT
"$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$mptcp_report"
assert_selected_ids "$mptcp_report" 'A02,A03,A04,A14,A15'

expect_status 77 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --preview --only mpquic
mpquic_report=$LAST_OUTPUT
"$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$mpquic_report"
assert_selected_ids "$mpquic_report" 'A06,A07,A14,A15'

expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --execute --only all
expect_status 77 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --execute --only all --yes
jq -e '.overall == "BLOCKED" and .execution.requested_mode == "EXECUTE"' "$LAST_OUTPUT" >/dev/null

expect_status 77 "$REPOSITORY_DIRECTORY/tests/netns/run-benchmarks.sh" --preview
jq -e '
    .report_kind == "benchmark"
    and .overall == "BLOCKED"
    and .attempted == false
    and (.measurements | length == 15)
    and all(.measurements[]; .result == "SKIPPED")
' "$LAST_OUTPUT" >/dev/null

expect_status 77 "$REPOSITORY_DIRECTORY/tests/netns/topology.sh" --cleanup
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/topology.sh" --run -- arbitrary-command
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --only
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --only unsupported
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --preview --execute
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --execute --yes --yes
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --preview --yes
expect_status 64 "$REPOSITORY_DIRECTORY/tests/integration/run.sh" --suite
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-benchmarks.sh" --preview --execute

expect_status 0 "$REPOSITORY_DIRECTORY/packaging/build-deb.sh" --preview
grep -F 'PREVIEW ONLY: no build or package output was written.' "$LAST_OUTPUT" >/dev/null
expect_status 77 "$REPOSITORY_DIRECTORY/packaging/build-deb.sh" --build

/bin/mkdir "$TEMPORARY_DIRECTORY/evidence"
printf '%s\n' 'synthetic acceptance evidence' >"$TEMPORARY_DIRECTORY/evidence/proof.txt"
proof_digest=$(sha256sum "$TEMPORARY_DIRECTORY/evidence/proof.txt" | awk '{print $1}')
valid_all_report=$TEMPORARY_DIRECTORY/valid-all-pass.json
jq --arg digest "$proof_digest" '
    def evidence($id; $kind; $check):
        {
            id: $id,
            kind: $kind,
            sha256: $digest,
            path: "evidence/proof.txt",
            check: $check
        };
    .source_revision = ("1" * 40)
    | .generated_at = "2026-08-23T12:00:02Z"
    | .started_at = "2026-08-23T12:00:00Z"
    | .finished_at = "2026-08-23T12:00:01Z"
    | .execution = {
        requested_mode: "EXECUTE",
        attempted: true,
        completed: true,
        topology_created: true,
        blockers: []
      }
    | .environment = {
        debian_version: "13",
        architecture: "amd64",
        kernel: "6.12.0-test-amd64",
        rustc: "rustc 1.85.0",
        native_revisions: {}
      }
    | .host_state = {
        captured: true,
        before_digest: $digest,
        after_digest: $digest,
        unchanged: true
      }
    | .cleanup = {
        attempted: true,
        complete: true,
        remaining_owned_objects: 0
      }
    | .cases |= map(
        . as $case
        | .selected = true
        | .result = "PASS"
        | .reason = null
        | if .id == "A14" then
              .evidence = [
                  evidence("a14.agent"; "state"; "FORCED_AGENT_CRASH_CLEANUP"),
                  evidence("a14.helper"; "state"; "FORCED_HELPER_CRASH_CLEANUP"),
                  evidence("a14.native"; "state"; "FORCED_NATIVE_CRASH_CLEANUP"),
                  evidence("a14.absent"; "state"; "OWNED_OBJECTS_ABSENT")
              ]
          elif .id == "A15" then
              .evidence = [
                  evidence("a15.host_before"; "digest"; "HOST_STATE_BEFORE"),
                  evidence("a15.host_after"; "digest"; "HOST_STATE_AFTER")
              ]
          else
              .evidence = [
                  evidence((($case.id | ascii_downcase) + ".proof"); "state"; "CASE_ASSERTION")
              ]
          end
      )
    | .overall = "PASS"
' "$all_report" >"$valid_all_report"
expect_status 0 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$valid_all_report"

lifecycle_only_report=$TEMPORARY_DIRECTORY/valid-lifecycle-only.json
jq '
    .execution = {
        requested_mode: "EXECUTE",
        attempted: true,
        completed: true,
        topology_created: true,
        blockers: [
          {"code":"LIFECYCLE_ONLY","message":"Only the isolated lifecycle ran."},
          {"code":"FORCED_CRASH_NOT_EXECUTED","message":"Forced crash cleanup did not run."}
        ]
      }
    | .cases |= map(
        if .id == "A14" then
            .result = "SKIPPED"
            | .reason = {
                "code":"FORCED_CRASH_NOT_EXECUTED",
                "message":"Forced crash cleanup did not run."
              }
            | .evidence = []
        elif .id == "A15" then .
        else
            .result = "SKIPPED"
            | .reason = {
                "code":"LIFECYCLE_ONLY",
                "message":"Only the isolated lifecycle ran."
              }
            | .evidence = []
        end
      )
    | .overall = "BLOCKED"
' "$valid_all_report" >"$lifecycle_only_report"
expect_status 0 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" \
    "$lifecycle_only_report"
jq -e '
    .overall == "BLOCKED"
    and .cases[13].result == "SKIPPED"
    and .cases[13].reason.code == "FORCED_CRASH_NOT_EXECUTED"
    and .cases[14].result == "PASS"
    and all(.cases[0:13][]; .result == "SKIPPED" and .reason.code == "LIFECYCLE_ONLY")
' "$lifecycle_only_report" >/dev/null

valid_mptcp_report=$TEMPORARY_DIRECTORY/valid-mptcp-partial.json
jq '
    .suite = "mptcp"
    | .execution.blockers = [
        {"code":"PARTIAL_SUITE","message":"Only the MPTCP acceptance subset was selected."}
      ]
    | .cases |= map(
        if (.id | IN("A02", "A03", "A04", "A14", "A15")) then .
        else
            .selected = false
            | .result = "SKIPPED"
            | .reason = {"code":"NOT_SELECTED","message":"The case is outside the selected suite."}
            | .evidence = []
        end
      )
    | .overall = "BLOCKED"
' "$valid_all_report" >"$valid_mptcp_report"
expect_status 0 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$valid_mptcp_report"
assert_selected_ids "$valid_mptcp_report" 'A02,A03,A04,A14,A15'

valid_partial_failure_report=$TEMPORARY_DIRECTORY/valid-mptcp-failure.json
jq '
    .cases[1].result = "FAIL"
    | .cases[1].reason = {"code":"ASSERTION_FAILED","message":"The selected assertion failed."}
    | .overall = "FAIL"
' "$valid_mptcp_report" >"$valid_partial_failure_report"
expect_status 0 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" \
    "$valid_partial_failure_report"

valid_mpquic_report=$TEMPORARY_DIRECTORY/valid-mpquic-partial.json
jq '
    .suite = "mpquic"
    | .execution.blockers = [
        {"code":"PARTIAL_SUITE","message":"Only the MPQUIC acceptance subset was selected."}
      ]
    | .cases |= map(
        if (.id | IN("A06", "A07", "A14", "A15")) then .
        else
            .selected = false
            | .result = "SKIPPED"
            | .reason = {"code":"NOT_SELECTED","message":"The case is outside the selected suite."}
            | .evidence = []
        end
      )
    | .overall = "BLOCKED"
' "$valid_all_report" >"$valid_mpquic_report"
expect_status 0 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$valid_mpquic_report"
assert_selected_ids "$valid_mpquic_report" 'A06,A07,A14,A15'

valid_indeterminate_report=$TEMPORARY_DIRECTORY/valid-indeterminate-error.json
jq '
    .execution = {
        requested_mode: "EXECUTE",
        attempted: true,
        completed: false,
        topology_created: false,
        blockers: [
          {"code":"HOST_CAPTURE_UNAVAILABLE","message":"Host state could not be captured."}
        ]
      }
    | .host_state = {
        captured: false,
        before_digest: null,
        after_digest: null,
        unchanged: null
      }
    | .cleanup = {
        attempted: false,
        complete: null,
        remaining_owned_objects: null
      }
    | .cases |= map(
        .result = "SKIPPED"
        | .reason = {"code":"HOST_CAPTURE_UNAVAILABLE","message":"The case could not run safely."}
        | .evidence = []
      )
    | .overall = "ERROR"
' "$valid_all_report" >"$valid_indeterminate_report"
expect_status 0 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" \
    "$valid_indeterminate_report"

invalid_report=$TEMPORARY_DIRECTORY/invalid-report.json
jq '.unexpected = true' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.host_state.after_digest = ("2" * 64)' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.host_state.after_digest = ("2" * 64) | .host_state.unchanged = false | .overall = "FAIL"' \
    "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq 'del(.cases[14].evidence[1])' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq 'del(.cases[13].evidence[2])' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.cleanup.complete = false | .cleanup.remaining_owned_objects = 1 | .overall = "FAIL"' \
    "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.cases[1].evidence[0].id = .cases[0].evidence[0].id' \
    "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.finished_at = "2026-08-23T11:59:59Z"' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.generated_at = "2023-02-29T12:00:02Z"' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.execution.blockers = [
        {"code":"DUPLICATE","message":"First blocker."},
        {"code":"DUPLICATE","message":"Second blocker."}
    ] | .overall = "BLOCKED"' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq '.cases[0].evidence[0].sha256 = ("0" * 64)' "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
jq --arg digest "$proof_digest" '
    .cases[0] = {
        id: "A01",
        selected: true,
        result: "PASS",
        reason: null,
        evidence: [{
            id: "a01.invalid_pass",
            kind: "state",
            sha256: $digest,
            path: "evidence/proof.txt",
            check: "CASE_ASSERTION"
        }]
      }
' "$valid_indeterminate_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
/bin/ln -s proof.txt "$TEMPORARY_DIRECTORY/evidence/symlink.txt"
jq '.cases[0].evidence[0].path = "evidence/symlink.txt"' \
    "$valid_all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
/bin/ln -s "$valid_all_report" "$TEMPORARY_DIRECTORY/report-symlink.json"
expect_status 66 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" \
    "$TEMPORARY_DIRECTORY/report-symlink.json"
sed -n 's|^[[:space:]]*\(\./[^[:space:]]*\).*|\1|p' "$REPOSITORY_DIRECTORY/justfile" | \
    while IFS= read -r recipe_target; do
        if [ ! -e "$REPOSITORY_DIRECTORY/${recipe_target#./}" ]; then
            printf 'missing relative just recipe target: %s\n' "$recipe_target" >&2
            exit 1
        fi
    done

grep -F './tests/integration/run.sh --preview --suite all' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F './tests/netns/run-topology.sh --preview --only all' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F './tests/netns/run-topology.sh --preview --only mptcp' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F './tests/netns/run-topology.sh --preview --only mpquic' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F './tests/netns/test-lifecycle-contract.sh' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F './tests/netns/run-benchmarks.sh --preview' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F './packaging/build-deb.sh --preview' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F './packaging/build-deb.sh --build' "$REPOSITORY_DIRECTORY/justfile" >/dev/null
grep -F "' \"\$metadata_file\" | LC_ALL=C sort > \"\$package_list\"" \
    "$REPOSITORY_DIRECTORY/packaging/collect-cargo-licenses.sh" >/dev/null
grep -F 'LoadCredentialEncrypted=identity-passphrase:/etc/credstore.encrypted/identity-passphrase' \
    "$REPOSITORY_DIRECTORY/packaging/systemd/volparossa-agent.service" >/dev/null
grep -F 'ConditionFileIsExecutable=/usr/libexec/volparossa/volparossa-mpquic-launch' \
    "$REPOSITORY_DIRECTORY/packaging/systemd/volparossa-mpquic.service" >/dev/null
grep -F 'ExecStart=/usr/libexec/volparossa/volparossa-mpquic-launch' \
    "$REPOSITORY_DIRECTORY/packaging/systemd/volparossa-mpquic.service" >/dev/null

for retired_mutator in \
    'ip netns add' \
    'ip netns del' \
    'ip link add' \
    'nft add table' \
    'policy accept'
do
    if grep -F "$retired_mutator" "$REPOSITORY_DIRECTORY/tests/netns/topology.sh" >/dev/null; then
        printf 'dormant topology mutator survived removal: %s\n' "$retired_mutator" >&2
        exit 1
    fi
done
if grep -E 'VOLPAROSSA_[A-Z_]*(COMMAND|BACKEND|DRIVER|CHILD)' \
    "$REPOSITORY_DIRECTORY/tests/netns/"*.sh \
    "$REPOSITORY_DIRECTORY/tests/netns/lib/"*.sh >/dev/null; then
    printf '%s\n' 'a public topology script accepts a runtime implementation override' >&2
    exit 1
fi
if grep -E '(^|[;&|[:space:]])eval([;&|[:space:]]|$)' \
    "$REPOSITORY_DIRECTORY/tests/netns/"*.sh \
    "$REPOSITORY_DIRECTORY/tests/netns/lib/"*.sh >/dev/null; then
    printf '%s\n' 'a public topology script contains eval' >&2
    exit 1
fi

if [ -e "$MUTATION_MARKER" ]; then
    printf '%s\n' 'a preview/refusal path invoked a host-mutating command:' >&2
    sed -n '1,80p' "$MUTATION_MARKER" >&2
    exit 1
fi

printf '%s\n' 'PASS: harness previews/refusals are syntactically valid, machine-readable, blocked, and non-mutating.'
