//! Exact command-line entry point for the disposable lifecycle supervisor.

use std::{env, ffi::OsStr, process::ExitCode};

use volparossa_netns_runner::{
    BLOCKED_EXIT_CODE, INTERNAL_CHILD_ARGUMENT, INTERNAL_ERROR_EXIT_CODE,
    INTERNAL_PID_ONE_ARGUMENT, LifecycleOutcome, run_fixed_lifecycle, run_internal_child,
    run_internal_pid_one,
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
        Some(argument) if argument == OsStr::new(INTERNAL_PID_ONE_ARGUMENT) => {
            run_internal_pid_one()
        }
        Some(argument) if argument == OsStr::new(PREVIEW_ARGUMENT) => {
            println!(
                "VOLPAROSSA fixed supervisor preview: anonymous namespace bootstrap, exact UID/GID mapping, exact self-reexec PID-1 proof, private mounts, fixed pidfd-to-signalfd supervision, the exact new-netns RTNL baseline, and one pinned BOOTSTRAP_READY are implemented; GO, every network-topology mutation, and A14 cleanup evidence remain blocked."
            );
            ExitCode::SUCCESS
        }
        Some(argument) if argument == OsStr::new(RUN_ARGUMENT) => match run_fixed_lifecycle() {
            Ok(LifecycleOutcome::BlockedBeforeIsolation) => {
                eprintln!(
                    "BLOCKED: kernel policy did not permit the fixed anonymous namespace and ID-mapping bootstrap; no GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAfterIsolation) => {
                eprintln!(
                    "BLOCKED: anonymous namespaces were created, but kernel policy did not permit the required outer proof or exact ID mappings; no GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAtPidOneProof) => {
                eprintln!(
                    "BLOCKED: anonymous namespaces and exact ID mappings were verified, but kernel policy hid the required outer PID-1 proof; no GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAtPrivateMountSetup) => {
                eprintln!(
                    "BLOCKED: anonymous namespaces, exact ID mappings, and a self-reexecuted PID 1 were verified, but kernel policy denied the fixed private-mount setup; no BOOTSTRAP_READY or GO was emitted."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedAfterBootstrapReadyProof) => {
                eprintln!(
                    "BLOCKED: the exact new-netns RTNL baseline and one pinned BOOTSTRAP_READY were verified before the fixed pidfd-to-PID1-signalfd TERM, pre-GO EOF, and exact reap; no GO, network-topology mutation, or A14 evidence was produced."
                );
                ExitCode::from(BLOCKED_EXIT_CODE)
            }
            Ok(LifecycleOutcome::BlockedByManagedSignal) => {
                eprintln!(
                    "BLOCKED: a managed outer termination signal triggered bounded fail-closed containment before GO or any network-topology mutation."
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
