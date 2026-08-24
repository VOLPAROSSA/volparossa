#!/bin/sh
# Run static analysis over every repository-owned shell entry point.
set -eu

export LC_ALL=C

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

if ! command -v shellcheck >/dev/null 2>&1; then
    printf '%s\n' 'shellcheck is required; run scripts/bootstrap-debian13-dev.sh first.' >&2
    exit 127
fi

set -- \
    packaging/test-collect-cargo-licenses.sh \
    packaging/build-deb.sh \
    packaging/collect-cargo-licenses.sh \
    packaging/debian/postinst \
    packaging/debian/postrm \
    packaging/debian/prerm \
    scripts/bootstrap-debian13-dev.sh \
    scripts/check-rust-dependencies.sh \
    scripts/check-shell.sh \
    scripts/check-system.sh \
    scripts/cleanup-network.sh \
    scripts/run-fuzz.sh \
    tests/integration/run.sh \
    tests/integration/test-harness.sh \
    tests/integration/validate-report.sh \
    tests/netns/run-benchmarks.sh \
    tests/netns/run-topology.sh \
    tests/netns/require-bootstrap-ready-proof.sh \
    tests/netns/test-lifecycle-contract.sh \
    tests/netns/topology.sh \
    tests/netns/lib/lifecycle-contract.sh \
    native/volparossa-mpquic/scripts/build-upstream.sh \
    native/volparossa-mpquic/scripts/fetch-upstream.sh \
    native/volparossa-mpquic/scripts/test-sanitized-upstream.sh \
    native/volparossa-mpquic/scripts/verify-upstream.sh

shellcheck "$@"
