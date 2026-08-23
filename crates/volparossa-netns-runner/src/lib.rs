//! Fixed pre-`GO` isolation supervisor substrate for the disposable acceptance runner.
//!
//! The current executable provisions one fixed re-executed child over unnamed
//! inherited IPC, creates anonymous user/mount/network namespaces behind an
//! outer-owned single-extent ID-mapping barrier, proves that no lifecycle
//! mutation was authorized, and reaps the exact child. It deliberately stops
//! before PID-namespace/PID-1/private-mount bootstrap and reports a blocked
//! outcome. It cannot emit acceptance evidence or create network topology.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod control;
mod evidence;
mod ipc;
mod isolation;
mod namespace;
mod process;
mod runner;

pub use process::INTERNAL_CHILD_ARGUMENT;
pub use runner::{
    BLOCKED_EXIT_CODE, INTERNAL_ERROR_EXIT_CODE, LifecycleOutcome, RunnerError,
    run_fixed_lifecycle, run_internal_child,
};
