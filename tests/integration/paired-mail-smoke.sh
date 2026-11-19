#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only in the explicitly selected disposable paired Mail guest.
# shellcheck disable=SC2154,SC2034

paired_mail_cleanup() {
    [ -n "${PAIRED_MAIL_PRIVATE:-}" ] || return 0
    [ "$PAIRED_MAIL_PRIVATE" = "$WORK/client-fixtures/mailbox/paired" ] && [ ! -L "$PAIRED_MAIL_PRIVATE" ] \
        && [ "$(stat -Lc '%d:%i:%a:%u:%g' "$PAIRED_MAIL_PRIVATE")" = "$PAIRED_MAIL_PRIVATE_STAT" ] || return 1
    setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" --clear-groups --inh-caps=-all --ambient-caps=-all \
        --bounding-set=-all --no-new-privs -- python3 -I -B - "$PAIRED_MAIL_PRIVATE" <<'PYTHON' || return 1
import os, shutil, stat, sys
assert shutil.rmtree.avoids_symlink_attacks
fd = os.open(sys.argv[1], os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for name in os.listdir(fd):
        item = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if name not in {"app","store","providers"} or item.st_uid != os.getuid() or not stat.S_ISDIR(item.st_mode):
            raise ValueError("unexpected paired Mail state")
        shutil.rmtree(name, dir_fd=fd)
finally:
    os.close(fd)
PYTHON
    rmdir "$PAIRED_MAIL_PRIVATE" || return 1
    PAIRED_MAIL_PRIVATE=
}

paired_mail_stage() {
    paired_phase=$1
    [ "$(stat -Lc '%g' "$WORK/runtime-client/control/agent.sock")" = "$mailbox_control_gid" ] || fail PAIRED_MAIL_SOCKET_GROUP_INVALID
    if [ "$paired_phase" = send ]; then
        paired_private=$mailbox_user/paired
        [ ! -e "$paired_private" ] && [ ! -L "$paired_private" ] || fail PAIRED_MAIL_STATE_EXISTS
        install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$paired_private"
        PAIRED_MAIL_PRIVATE_STAT=$(stat -Lc '%d:%i:%a:%u:%g' "$paired_private")
        PAIRED_MAIL_PRIVATE=$paired_private
        signal_mailbox_stage_cli || fail PAIRED_MAIL_CLI_STAGING_FAILED
        for paired_program in paired-mail-guest.py paired-mail-sandbox.py signal-mailbox-native.py; do
            install -o root -g root -m 0444 "$source_directory/tests/integration/$paired_program" "$WORK/bin/$paired_program"
        done
        paired_count=6
    else
        [ "$paired_phase" = receive ] || fail PAIRED_MAIL_PHASE_INVALID
        paired_count=7
    fi
    PHASE=paired-mail-$paired_phase
    content_mailbox_phase_start "paired-$paired_phase"
    timeout --signal=TERM --kill-after=10s 800s ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" \
        --regid="$WORKER_GID" --groups="$mailbox_control_gid" --inh-caps=-all --ambient-caps=-all \
        --bounding-set=-all --no-new-privs -- python3 -I -B "$WORK/bin/paired-mail-sandbox.py" \
        "$paired_phase" "$PAIRED_MAIL_PRIVATE" "$signal_cli" "$WORK/runtime-client/control/agent.sock" \
        "$mailbox_key_a" "$mailbox_key_b" >"$WORK/paired-mail-$paired_phase.json" || fail PAIRED_MAIL_APPLICATION_FAILED
    content_mailbox_phase_finish "$paired_count"
    if [ "$paired_phase" = receive ]; then paired_mail_cleanup || fail PAIRED_MAIL_CLEANUP_FAILED; fi
}

paired_mail_finalize() {
    paired_status=$1
    paired_verifier=$source_directory/tests/integration/paired-mail-smoke.py
    if [ -f /var/tmp/volparossa-paired-mail-runtime/paired-mail-supply.json ]; then
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 /var/tmp/volparossa-paired-mail-runtime/paired-mail-supply.json \
            "$output_directory/paired-mail-supply.json" || return 1
    fi
    for paired_name in $(python3 -I -B "$paired_verifier" export-names); do
        case $paired_name in paired-mail-smoke.json|content-mailbox-smoke.json) continue ;; esac
        if [ -f "$WORK/$paired_name" ] && [ ! -L "$WORK/$paired_name" ]; then
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/$paired_name" "$output_directory/$paired_name" || return 1
        fi
    done
    python3 -I -B "$paired_verifier" assemble "$output_directory" "$expected_commit" "$paired_status" "$OBSERVED_BLOCKER" \
        >"$WORK/paired-mail-report.part" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/paired-mail-report.part" "$output_directory/paired-mail-smoke.json" || return 1
    python3 -I -B "$paired_verifier" report "$output_directory/paired-mail-smoke.json" "$expected_commit"
}
