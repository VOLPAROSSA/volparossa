#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Build one reviewed Bank example in the opted-in disposable runner. Export only its digest.
set -euo pipefail
umask 077
[[ $GITHUB_ACTIONS == true && $RUNNER_ENVIRONMENT == github-hosted && $(id -u) != 0 ]]
[[ $(git rev-parse HEAD) == "$GITHUB_SHA" && $RUNNER_TEMP == "$(realpath "$RUNNER_TEMP")" ]]
revision=$(cat tests/integration/transaction-abci-bank-revision)
[[ $revision =~ ^[a-f0-9]{40}$ ]]
binary="$RUNNER_TEMP/bank-ordered-authorizer"
[[ ! -e $binary && ! -L $binary ]]
work=$(mktemp -d "$RUNNER_TEMP/bank-ordered-build-XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
git init -q "$work/bank"
git -C "$work/bank" -c transfer.fsckObjects=true fetch --quiet --depth 1 https://github.com/VOLPAROSSA/volparossa-bank.git "$revision"
git -C "$work/bank" checkout -q --detach FETCH_HEAD
[[ $(git -C "$work/bank" rev-parse HEAD) == "$revision" ]]
sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends musl-tools protobuf-compiler
target=x86_64-unknown-linux-musl
rustup toolchain install 1.98.1 --profile minimal --target "$target"
export CARGO_HOME="$work/cargo" CARGO_TARGET_DIR="$work/target" CARGO_BUILD_JOBS=2
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
manifest="$work/bank/paper-payments/Cargo.toml"
cargo +1.98.1 fetch --locked --manifest-path "$manifest" --target "$target"
cargo +1.98.1 build --locked --offline --manifest-path "$manifest" --example ordered_authorizer --target "$target"
git -C "$work/bank" diff --exit-code HEAD --
strip --strip-all -o "$work/authorizer" "$CARGO_TARGET_DIR/$target/debug/examples/ordered_authorizer"
[[ $(stat -c %s "$work/authorizer") -le 33554432 ]]
readelf -hW "$work/authorizer" | grep -F 'Advanced Micro Devices X86-64' >/dev/null
if readelf -lW "$work/authorizer" | grep -w INTERP >/dev/null || readelf -dW "$work/authorizer" | grep -w NEEDED >/dev/null; then
    exit 1
fi
install -m 0500 "$work/authorizer" "$binary"
printf 'sha256=%s\n' "$(sha256sum <"$binary" | cut -d' ' -f1)" >>"$GITHUB_OUTPUT"
