#!/bin/sh
# Bounded cargo-fuzz entry point for every supported externally controlled parser.
set -eu

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$1" >&2
        exit 69
    }
}

require_positive_integer() {
    case $2 in
        ''|*[!0-9]*|0)
            printf '%s must be a positive integer\n' "$1" >&2
            exit 64
            ;;
    esac
}

require_command cargo
require_command rustc
if ! cargo fuzz --help >/dev/null 2>&1; then
    printf '%s\n' 'cargo-fuzz is required; install the Debian-packaged or audited cargo-fuzz tool first' >&2
    exit 69
fi

SECONDS_PER_TARGET=${VOLPAROSSA_FUZZ_SECONDS_PER_TARGET:-30}
MAX_INPUT_BYTES=${VOLPAROSSA_FUZZ_MAX_INPUT_BYTES:-524289}
require_positive_integer VOLPAROSSA_FUZZ_SECONDS_PER_TARGET "$SECONDS_PER_TARGET"
require_positive_integer VOLPAROSSA_FUZZ_MAX_INPUT_BYTES "$MAX_INPUT_BYTES"
SANITIZER=${VOLPAROSSA_FUZZ_SANITIZER:-auto}
case $SANITIZER in
    auto)
        case $(rustc --version) in
            *nightly*) SANITIZER=address ;;
            *)
                SANITIZER=none
                printf '%s\n' 'stable rustc detected: coverage fuzzing enabled without Rust ASan; native ASan remains a separate gate' >&2
                ;;
        esac
        ;;
    address|none) ;;
    *) printf '%s\n' 'VOLPAROSSA_FUZZ_SANITIZER must be auto, address, or none' >&2; exit 64 ;;
esac


TARGETS='node_advertisement
policy_manifest
control_plane
advertisement_v3
forwarding_v3
datapath_relay_v3
tcp_open
udp_authorization
quic_classification
tls_client_hello
quic_initial'

printf 'VOLPAROSSA fuzz gate: %s seconds per target, %s-byte maximum input, sanitizer=%s\n' \
    "$SECONDS_PER_TARGET" "$MAX_INPUT_BYTES" "$SANITIZER"
printf '%s\n' "$TARGETS" | while read -r target; do
    [ -n "$target" ] || continue
    printf 'fuzzing %s\n' "$target"
    cargo fuzz run --sanitizer "$SANITIZER" "$target" -- \
        "-max_total_time=$SECONDS_PER_TARGET" \
        "-max_len=$MAX_INPUT_BYTES" \
        -rss_limit_mb=2048 \
        -timeout=10
done
