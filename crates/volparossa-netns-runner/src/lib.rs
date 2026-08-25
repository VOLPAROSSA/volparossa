//! Fixed bounded isolation supervisor substrate for the disposable acceptance runner.
//!
//! The current executable provisions one fixed re-executed launcher over
//! unnamed inherited IPC, creates anonymous user/mount/network namespaces,
//! selects a pending child-PID namespace behind an outer-owned single-extent
//! UID/GID-mapping barrier, and then proves one exact self-reexecuted namespace
//! PID 1. That PID makes the inherited mount tree recursively private, installs
//! a bounded hardened tmpfs at `/run` and a PID-namespace-bound procfs at
//! `/proc`, retains both while the outer independently verifies them, proves the
//! exact pristine RTNL baseline, pins a stable canonical IPv4-forwarding record,
//! proves empty nftables table/chain/rule/set/object/flowtable dumps bracketed
//! by unchanged generation 1, and emits
//! one namespace-bound `BOOTSTRAP_READY`. After matching that frame to its
//! retained PID-1 pins, the outer issues one canonical `GO`. PID 1 consumes the
//! affine authorization, creates and proves the fixed descriptor-relative
//! private-run roots and two empty namespace slots, creates two distinct network
//! namespaces, and publishes them as run-bound nsfs pins. It joins each visible
//! pin for the full pristine network proof and restores its parent namespace.
//! It creates and exactly proves two fixed down-veth pairs, each through one
//! atomic `RTM_NEWLINK` request. It then installs and exactly proves four fixed
//! `/30` IPv4 addresses plus their four kernel-owned local-table `/32` routes
//! while every veth end remains down. It separately sets and proves IPv6
//! address-generation mode `none` on all four ends. Before activating any
//! veth, it atomically installs and proves the sole run-bound generation-two
//! nftables policy: one `inet` table, one priority-zero `forward` base chain
//! with policy drop, and only the exact A-to-B IPv4 ICMP echo-request and
//! B-to-A echo-reply accept rules. It then activates every end, proves the
//! exact carrier-up links, `noqueue` qdiscs, absence of IPv6 addresses, and
//! kernel-owned local, connected, high-broadcast, and IPv6 multicast routes,
//! and exactly observes the two fixed main-table static endpoint `/32` routes.
//! That policy remains exact while PID 1 directly deletes veth B followed by A
//! as the only route-removal mechanism. All route, address, and pair owners
//! remain armed while the parent and both endpoints are proven byte-exactly
//! equal to their retained enumerated network baselines under generation two.
//! PID 1 deletes only the freshly observed table handle, proves a semantically
//! empty generation three, and repeats the final parent/endpoint proof. Only
//! then are those affine lower owners retired. It ordinarily unmounts nsfs B
//! then A, proves the hidden
//! slots reappeared, rolls every filesystem object back, and reports one
//! internal rollback checkpoint. The
//! outer then independently re-proves empty private mounts before delivering
//! TERM through a retained pidfd. PID 1 consumes it through a fixed `signalfd`
//! before exact PID-1 and launcher reaping. The slice never writes the
//! inherited canonical IPv4-forwarding setting. It produces no packet-capture
//! or probe evidence, ownership manifest, dataplane topology,
//! `TOPOLOGY_READY`, or acceptance evidence; its exact policy and explicit
//! endpoint routes are configuration proof, not production route
//! orchestration or packet-behaviour proof.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod control;
mod evidence;
mod ipc;
mod isolation;
mod mounts;
mod namespace;
mod network;
mod nftables;
mod pid1;
mod process;
mod runner;
mod signals;
mod topology;

pub use process::{INTERNAL_CHILD_ARGUMENT, INTERNAL_PID_ONE_ARGUMENT};
pub use runner::{
    BLOCKED_EXIT_CODE, INTERNAL_ERROR_EXIT_CODE, LifecycleOutcome, RunnerError,
    run_fixed_lifecycle, run_internal_child, run_internal_pid_one,
};
