//! Exact command-line entry point for the disposable lifecycle supervisor.

use std::{env, ffi::OsStr, process::ExitCode};

use volparossa_netns_runner::{
    BLOCKED_EXIT_CODE, INTERNAL_CHILD_ARGUMENT, INTERNAL_ERROR_EXIT_CODE, LifecycleOutcome,
    run_fixed_lifecycle, run_internal_child,
};

const PREVIEW_ARGUMENT: &str = "--preview";
const RUN_ARGUMENT: &str = "--run";
const USAGE_EXIT_CODE: u8 = 64;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let first = arguments.next();
    if arguments.next().is_some() {
        print_usage();
        return ExitCode::from(USAGE_EXIT_CODE);
    }
    match first.as_deref() {
        Some(argument) if argument == OsStr::new(INTERNAL_CHILD_ARGUMENT) => run_internal_child(),
        Some(argument) if argument == OsStr::new(PREVIEW_ARGUMENT) => {
            println!(
                "VOLPAROSSA fixed supervisor preview: inherited IPC and exact child reaping; namespace bootstrap and every network mutation remain blocked."
            );
            ExitCode::SUCCESS
        }
        Some(argument) if argument == OsStr::new(RUN_ARGUMENT) => match run_fixed_lifecycle() {
            Ok(LifecycleOutcome::BlockedBeforeIsolation) => {
                eprintln!(
                    "BLOCKED: fixed child provisioning completed without GO; isolated namespace bootstrap is not implemented."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Err(error) => {
                eprintln!("ERROR: {error}");
                ExitCode::from(INTERNAL_ERROR_EXIT_CODE)
            }
        },
        _ => {
            print_usage();
            ExitCode::from(USAGE_EXIT_CODE)
        }
    }
}

fn print_usage() {
    eprintln!("usage: volparossa-netns-runner --preview|--run");
}
