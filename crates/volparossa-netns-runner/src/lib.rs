//! Fixed pre-`GO` isolation supervisor substrate for the disposable acceptance runner.
//!
//! The current executable provisions one fixed re-executed launcher over
//! unnamed inherited IPC, creates anonymous user/mount/network namespaces,
//! selects a pending child-PID namespace behind an outer-owned single-extent
//! UID/GID-mapping barrier, and then proves and reaps one exact self-reexecuted
//! namespace PID 1. It proves that no lifecycle mutation was authorized and
//! deliberately stops before private-mount and `BOOTSTRAP_READY`/`GO`
//! bootstrap. It cannot emit acceptance evidence or create network topology.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod control;
mod evidence;
mod ipc;
mod isolation;
mod namespace;
mod pid1;
mod process;
mod runner;

pub use process::{INTERNAL_CHILD_ARGUMENT, INTERNAL_PID_ONE_ARGUMENT};
pub use runner::{
    BLOCKED_EXIT_CODE, INTERNAL_ERROR_EXIT_CODE, LifecycleOutcome, RunnerError,
    run_fixed_lifecycle, run_internal_child, run_internal_pid_one,
};
