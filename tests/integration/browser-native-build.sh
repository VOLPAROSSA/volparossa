#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Build public inputs in a runner-owned directory and keep only the private
# runtime archive and source attestation for this job's KVM consumer.
set -euo pipefail
umask 077
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
test "${RUNNER_OS:-}" = Linux
test "${VOLPAROSSA_NATIVE_BROWSER_SOURCE:-}" = true
test "$(id -u)" -ne 0
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ && "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]]
scratch=/opt/volparossa-native-browser-build
private="$RUNNER_TEMP/native-browser-handoff"
exported="$GITHUB_WORKSPACE/build/native-firefox-source-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
archive="$exported.tar.gz"
browser="$scratch/browser"
mail="$scratch/mail"
build="$browser/build/native-firefox-157"
rust_stage="$mail/build/stalwart-rust-1.98.1"
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
browser_revision=c3311ebedcc02dc45ff9c9822cee62f091609f86
mail_revision=92dac0280ab741000199f342876644341c83f127

public_checkout() {
    local component=$1 revision=$2 destination=$3
    git -c core.hooksPath=/dev/null init --quiet "$destination"
    git -C "$destination" -c credential.helper= -c core.hooksPath=/dev/null \
        fetch --depth=1 --no-tags --no-recurse-submodules "https://github.com/VOLPAROSSA/$component.git" "$revision"
    git -C "$destination" -c core.hooksPath=/dev/null checkout --quiet --detach FETCH_HEAD
    test "$(git -C "$destination" rev-parse HEAD)" = "$revision"
}

case ${1:-} in
    prepare)
        for path in "$private" "$exported" "$archive"; do test ! -e "$path" && test ! -L "$path"; done
        test -d "$scratch" && test ! -L "$scratch" && test "$(stat -c '%u:%a' "$scratch")" = "$(id -u):700"
        test -z "$(ls -A "$scratch")"
        mkdir -- "$private"
        printf '%s\n' "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" > "$scratch/.owner"
        public_checkout volparossa-browser "$browser_revision" "$browser"
        public_checkout volparossa-mail "$mail_revision" "$mail"
        mkdir -p "$mail/build" "$browser/build"
        python3 -B "$mail/scripts/prepare_stalwart_toolchain.py" --fetch --output "$rust_stage"
        printf '%s  %s\n' f994b853cae209236bd522735903f66a4a01f5cc8c04632d36aa45449ca367ac "$rust_stage/TOOLCHAIN_REPORT.json" | sha256sum --check
        python3 -B "$browser/scripts/native_build.py" --fetch --output "$build"
        ;;
    compile)
        test "$(cat "$scratch/.owner")" = "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
        python3 -B "$browser/scripts/native_build.py" --build --output "$build" --rust-stage "$rust_stage"
        ;;
    export)
        test "$(cat "$scratch/.owner")" = "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
        mkdir -p "$GITHUB_WORKSPACE/build"
        python3 -B "$here/browser-native-runtime.py" export --source-built \
            --browser-checkout "$browser" --native-build "$build" --output "$exported"
        python3 -B "$here/browser-native-runtime.py" pack "$exported" "$archive" \
            --source-manifest-sha256 "$(sha256sum "$exported/native-bundle.json" | cut -d' ' -f1)"
        mv -T -- "$archive" "$private/firefox.tar.gz"
        jq --arg sha "$(sha256sum "$exported/native-bundle.json" | cut -d' ' -f1)" \
            --arg archive "$(sha256sum "$private/firefox.tar.gz" | cut -d' ' -f1)" --arg core "$GITHUB_SHA" \
            '{source_build,core_revision:$core,bundle_sha256:$sha,archive_sha256:$archive}' \
            "$exported/native-bundle.json" > "$private/expected.json"
        printf '%s\n' "VOLPAROSSA_BROWSER_NATIVE_BUNDLE=$private/firefox.tar.gz" >> "$GITHUB_ENV"
        ;;
    clean-build)
        test "$(cat "$scratch/.owner")" = "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
        # Only remove the fresh output reserved by this run. Keep the handoff
        # outside the run's build tree until the guest and its verifier finish.
        rm -rf --one-file-system -- "$exported" "$archive" "$browser" "$mail"
        rm -- "$scratch/.owner"
        sudo -n rmdir -- "$scratch"
        test ! -e "$exported" && test ! -e "$archive" && test ! -e "$scratch"
        ;;
    *) exit 64 ;;
esac
