#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced by the disposable content-mailbox topology after the independent receiver test.
# shellcheck disable=SC2154,SC2034

signal_mailbox_cleanup() {
    if [ -n "${SIGNAL_MAILBOX_PARENT_MODE:-}" ]; then
        chmod "$SIGNAL_MAILBOX_PARENT_MODE" /home/vpci || return 1
        SIGNAL_MAILBOX_PARENT_MODE=
    fi
    if [ -n "${SIGNAL_MAILBOX_PRIVATE:-}" ]; then
        [ "$SIGNAL_MAILBOX_PRIVATE" = "$WORK/client-fixtures/mailbox/desktop" ] || return 1
        [ ! -L "$SIGNAL_MAILBOX_PRIVATE" ] && [ "$(stat -Lc '%d:%i:%a:%u:%g' "$SIGNAL_MAILBOX_PRIVATE")" = "$SIGNAL_MAILBOX_PRIVATE_STAT" ] || return 1
        # A terminated runner can leave its single private TemporaryDirectory. The worker
        # may remove only that child beneath the exact fixture root; rmtree never follows links.
        setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups --inh-caps=-all --ambient-caps=-all \
            --bounding-set=-all --no-new-privs -- python3 -I -B - "$SIGNAL_MAILBOX_PRIVATE" <<'PYTHON' || return 1
import os, re, shutil, stat, sys
assert shutil.rmtree.avoids_symlink_attacks
fd = os.open(sys.argv[1], os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    names = os.listdir(fd)
    if len(names) > 1:
        raise ValueError("unexpected native state")
    for name in names:
        state = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not re.fullmatch(r"native-[a-z0-9_]{8}", name) or not stat.S_ISDIR(state.st_mode) or state.st_uid != os.getuid():
            raise ValueError("unexpected native state")
        shutil.rmtree(name, dir_fd=fd)
finally:
    os.close(fd)
PYTHON
        rmdir "$SIGNAL_MAILBOX_PRIVATE" || return 1
        SIGNAL_MAILBOX_PRIVATE=
    fi
}

signal_mailbox_stage_cli() {
    # The single-user Desktop namespace maps only the worker. Give its read-only
    # CLI mount a mapped owner. Its source directory stays outside the Desktop.
    signal_cli="$WORK/bin/signal-mailbox-volparossa"
    [ ! -e "$signal_cli" ] && [ ! -L "$signal_cli" ] || return 1
    install -o "$WORKER_UID" -g "$WORKER_GID" -m 0500 "$binary_directory/volparossa" "$signal_cli" \
        && cmp -s "$binary_directory/volparossa" "$signal_cli"
}

signal_mailbox_run() {
    PHASE=signal-mailbox-native
    signal_private=$mailbox_user/desktop
    [ ! -e "$signal_private" ] && [ ! -L "$signal_private" ] || fail SIGNAL_MAILBOX_PRIVATE_ROOT_EXISTS
    install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$signal_private"
    SIGNAL_MAILBOX_PRIVATE_STAT=$(stat -Lc '%d:%i:%a:%u:%g' "$signal_private")
    SIGNAL_MAILBOX_PRIVATE=$signal_private
    [ -d /home/vpci ] && [ ! -L /home/vpci ] || fail SIGNAL_MAILBOX_RUNTIME_PARENT_INVALID
    SIGNAL_MAILBOX_PARENT_MODE=$(stat -Lc '%a' /home/vpci)
    chmod o+x /home/vpci || fail SIGNAL_MAILBOX_RUNTIME_TRAVERSAL_FAILED
    # The agent's positive mount-isolation probe already excludes the entire mailbox_user tree.
    # Run the provisioning of the two app identities and the complete native case inside this phase.
    install -o root -g root -m 0444 /home/vpci/signal-backup-runtime/provision.json "$WORK/bin/signal-mailbox-runtime.json"
    signal_mailbox_stage_cli || fail SIGNAL_MAILBOX_CLI_STAGING_FAILED
    install -o root -g root -m 0555 "$source_directory/tests/integration/signal-mailbox-native.py" \
        "$WORK/bin/signal-mailbox-native.py"
    install -o root -g root -m 0444 "$source_directory/tests/integration/signal-mailbox-pins.json" \
        "$WORK/bin/signal-mailbox-pins.json"
    for native_mode in desktop worker; do
        content_mailbox_phase_start "$native_mode"
        if [ "$native_mode" = desktop ]; then signal_report=signal-mailbox-native.json
        else signal_report=signal-mailbox-worker.json; fi
        timeout --signal=TERM --kill-after=10s 650s ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
            --groups="$mailbox_control_gid" --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- python3 -I -B "$WORK/bin/signal-mailbox-native.py" "$signal_private" "$signal_cli" \
            "$WORK/runtime-client/control/agent.sock" "$native_mode" "$mailbox_key_a" "$mailbox_key_b" \
            >"$WORK/$signal_report" || fail SIGNAL_MAILBOX_NATIVE_NOT_PROVEN
        content_mailbox_phase_finish 12
    done
    signal_mailbox_cleanup || fail SIGNAL_MAILBOX_PRIVATE_CLEANUP_FAILED
}

signal_mailbox_finalize_report() {
    signal_status=$1
    # Only these bounded public counters/receipts can leave the guest.
    for signal_name in $(python3 -I -B "$source_directory/tests/integration/signal-mailbox-smoke.py" export-names); do
        case $signal_name in signal-mailbox-smoke.json|content-mailbox-smoke.json) continue ;; esac
        if [ -f "$WORK/$signal_name" ] && [ ! -L "$WORK/$signal_name" ]; then
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/$signal_name" "$output_directory/$signal_name" || return 1
        fi
    done
    python3 -I -B "$source_directory/tests/integration/signal-mailbox-smoke.py" assemble "$output_directory" \
        "$expected_commit" "$signal_status" "$OBSERVED_BLOCKER" >"$WORK/signal-mailbox-report.part" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/signal-mailbox-report.part" \
        "$output_directory/signal-mailbox-smoke.json" || return 1
    python3 -I -B "$source_directory/tests/integration/signal-mailbox-smoke.py" report \
        "$output_directory/signal-mailbox-smoke.json" "$expected_commit"
}
