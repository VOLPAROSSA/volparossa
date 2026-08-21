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
    tests/integration/run.sh \
    tests/integration/validate-report.sh \
    tests/netns/run-topology.sh \
    tests/netns/run-benchmarks.sh \
    tests/netns/topology.sh \
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

/bin/mkdir "$TEMPORARY_DIRECTORY/bin"
MUTATION_MARKER=$TEMPORARY_DIRECTORY/mutation-attempt
export VOLPAROSSA_MUTATION_MARKER="$MUTATION_MARKER"
for command_name in cargo dpkg-deb install ip nft rm sudo sysctl tc touch wg; do
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

expect_status 77 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --execute --only all
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
expect_status 77 "$REPOSITORY_DIRECTORY/tests/netns/topology.sh" --run -- arbitrary-command
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --only
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --only unsupported
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-topology.sh" --preview --execute
expect_status 64 "$REPOSITORY_DIRECTORY/tests/integration/run.sh" --suite
expect_status 64 "$REPOSITORY_DIRECTORY/tests/netns/run-benchmarks.sh" --preview --execute

expect_status 0 "$REPOSITORY_DIRECTORY/packaging/build-deb.sh" --preview
grep -F 'PREVIEW ONLY: no build or package output was written.' "$LAST_OUTPUT" >/dev/null
expect_status 77 "$REPOSITORY_DIRECTORY/packaging/build-deb.sh" --build

invalid_report=$TEMPORARY_DIRECTORY/invalid-pass.json
jq '
    .overall = "PASS"
    | .execution.attempted = true
    | .execution.completed = true
    | .host_state.captured = true
    | .host_state.unchanged = true
    | .cleanup.attempted = true
    | .cleanup.complete = true
    | .cleanup.remaining_owned_objects = 0
' "$all_report" >"$invalid_report"
expect_status 1 "$REPOSITORY_DIRECTORY/tests/integration/validate-report.sh" "$invalid_report"
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

if [ -e "$MUTATION_MARKER" ]; then
    printf '%s\n' 'a preview/refusal path invoked a host-mutating command:' >&2
    sed -n '1,80p' "$MUTATION_MARKER" >&2
    exit 1
fi

printf '%s\n' 'PASS: harness previews/refusals are syntactically valid, machine-readable, blocked, and non-mutating.'
