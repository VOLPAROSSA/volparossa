set dotenv-load := false
set positional-arguments := true
set shell := ["sh", "-eu", "-c"]

default:
    @just --list

setup:
    ./scripts/bootstrap-debian13-dev.sh

native-build:
    ./native/volparossa-mpquic/scripts/build-upstream.sh

native-sanitize:
    ./native/volparossa-mpquic/scripts/test-sanitized-upstream.sh

build: native-build
    cargo build --locked --workspace --all-features

build-release: native-build
    cargo build --locked --workspace --all-features --release

fmt:
    cargo fmt --all --check

fmt-fix:
    cargo fmt --all

lint:
    ./scripts/check-shell.sh
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
    ./scripts/check-rust-dependencies.sh

test:
    cargo test --locked --workspace --all-features

test-unit:
    cargo test --locked --workspace --all-features --lib

test-integration:
    ./packaging/test-collect-cargo-licenses.sh
    ./tests/netns/test-lifecycle-contract.sh
    ./tests/integration/test-harness.sh
    ./tests/integration/run.sh --preview --suite all

test-package-licenses:
    ./packaging/test-collect-cargo-licenses.sh

test-netns:
    ./tests/netns/run-topology.sh --preview --only all

test-netns-bootstrap-ready-proof:
    cargo build --locked --target x86_64-unknown-linux-gnu \
        --target-dir target/bootstrap-ready-proof -p volparossa-netns-runner
    /usr/bin/setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all \
        ./tests/netns/require-bootstrap-ready-proof.sh

test-mptcp:
    ./tests/netns/run-topology.sh --preview --only mptcp

test-mpquic:
    ./tests/netns/run-topology.sh --preview --only mpquic

fuzz:
    ./scripts/run-fuzz.sh

benchmark:
    ./tests/netns/run-benchmarks.sh --preview

package-deb:
    ./packaging/build-deb.sh --preview

package-deb-build:
    ./packaging/build-deb.sh --build

doctor:
    cargo run --locked -p volparossa -- doctor

demo:
    cargo run --locked -p volparossa -- demo

clean:
    cargo clean

cleanup-network:
    ./scripts/cleanup-network.sh
