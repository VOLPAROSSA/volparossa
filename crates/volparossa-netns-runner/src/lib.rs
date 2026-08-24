//! Fixed pre-`GO` isolation supervisor substrate for the disposable acceptance runner.
//!
//! The current executable provisions one fixed re-executed launcher over
//! unnamed inherited IPC, creates anonymous user/mount/network namespaces,
//! selects a pending child-PID namespace behind an outer-owned single-extent
//! UID/GID-mapping barrier, and then proves one exact self-reexecuted namespace
//! PID 1. That PID makes the inherited mount tree recursively private, installs
//! a bounded hardened tmpfs at `/run` and a PID-namespace-bound procfs at
//! `/proc`, and retains both while the outer independently verifies them. A
//! retained pidfd then delivers TERM to PID 1, which consumes it through a fixed
//! `signalfd` and returns one affine observation before exact PID-1 and launcher
//! reaping. The slice deliberately stops before pristine-network proof,
//! `BOOTSTRAP_READY`, and `GO`; it cannot emit acceptance evidence or create
//! network topology.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod control;
mod evidence;
mod ipc;
mod isolation;
mod mounts;
mod namespace;
mod pid1;
mod process;
mod runner;
mod signals;

pub use process::{INTERNAL_CHILD_ARGUMENT, INTERNAL_PID_ONE_ARGUMENT};
pub use runner::{
    BLOCKED_EXIT_CODE, INTERNAL_ERROR_EXIT_CODE, LifecycleOutcome, RunnerError,
    run_fixed_lifecycle, run_internal_child, run_internal_pid_one,
};
