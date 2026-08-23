//! Fixed process supervisor substrate for the disposable acceptance runner.
//!
//! The current executable provisions one fixed re-executed child over unnamed
//! inherited IPC, proves that no lifecycle mutation was authorized, and reaps
//! the exact child. It deliberately stops before namespace setup and reports a
//! blocked outcome. It cannot emit acceptance evidence or mutate networking.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod ipc;
mod namespace;
mod process;
mod runner;

pub use process::INTERNAL_CHILD_ARGUMENT;
pub use runner::{
    BLOCKED_EXIT_CODE, INTERNAL_ERROR_EXIT_CODE, LifecycleOutcome, RunnerError,
    run_fixed_lifecycle, run_internal_child,
};
