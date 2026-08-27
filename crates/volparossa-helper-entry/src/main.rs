//! Root VOLPAROSSA network helper executable.

use std::{ffi::OsString, process::ExitCode};

use volparossa_helper::{
    INTERNAL_NFT_FRONTEND_ARGUMENT, INTERNAL_WORKER_V3_ARGUMENT,
    INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT, run_internal_nft_frontend,
    run_internal_worker_v3_entry, run_internal_worker_v3_live_proof, run_production_server,
};
use volparossa_linux_uapi::take_systemd_listen_fd_set_once;

const LIVE_PROOF_SUCCESS_RECORDS: [&str; 2] = [
    "VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass",
    "VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Invocation {
    Production,
    InternalNftFrontend,
    InternalWorkerV3,
    InternalWorkerV3LiveProof,
}

fn parse_invocation(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, ()> {
    let mut arguments = arguments.into_iter();
    match (arguments.next(), arguments.next()) {
        (Some(argument), None) if argument == INTERNAL_NFT_FRONTEND_ARGUMENT => {
            Ok(Invocation::InternalNftFrontend)
        }
        (Some(argument), None) if argument == INTERNAL_WORKER_V3_ARGUMENT => {
            Ok(Invocation::InternalWorkerV3)
        }
        (Some(argument), None) if argument == INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT => {
            Ok(Invocation::InternalWorkerV3LiveProof)
        }
        (None, None) => Ok(Invocation::Production),
        _ => Err(()),
    }
}

fn main() -> ExitCode {
    let invocation = parse_invocation(std::env::args_os().skip(1));
    match invocation {
        Ok(Invocation::InternalNftFrontend) => {
            if run_internal_nft_frontend().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(Invocation::InternalWorkerV3) => {
            if run_internal_worker_v3_entry() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(Invocation::InternalWorkerV3LiveProof) => {
            if run_internal_worker_v3_live_proof() {
                for record in LIVE_PROOF_SUCCESS_RECORDS {
                    println!("{record}");
                }
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(Invocation::Production) => run_production(),
        Err(()) => ExitCode::FAILURE,
    }
}

fn run_production() -> ExitCode {
    // SAFETY: this is the no-argument executable's first production operation after invocation
    // classification. No tracing subscriber, runtime, worker, callback, signal handler or other
    // thread has been installed, and no code has claimed or mutated systemd's fixed fd range.
    #[expect(
        unsafe_code,
        reason = "the executable entry explicitly owns the systemd post-exec startup contract"
    )]
    let inherited = unsafe { take_systemd_listen_fd_set_once() };
    let Ok(inherited) = inherited else {
        return ExitCode::FAILURE;
    };

    let _ = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    if run_production_server(inherited).is_ok() {
        ExitCode::SUCCESS
    } else {
        tracing::error!(
            diagnostic_code = "HELPER_SHUTDOWN_FAILED",
            "helper stopped unsuccessfully"
        );
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_proof_success_records_are_exact_and_ordered() {
        assert_eq!(
            LIVE_PROOF_SUCCESS_RECORDS,
            [
                "VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass",
                "VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass",
            ]
        );
    }

    #[test]
    fn retired_context_worker_argument_is_not_a_valid_invocation() {
        let retired = ["--internal-context-worker-v1".into()];
        assert_eq!(parse_invocation(retired), Err(()));
        assert_eq!(
            parse_invocation([INTERNAL_NFT_FRONTEND_ARGUMENT.into()]),
            Ok(Invocation::InternalNftFrontend)
        );
        assert_eq!(
            parse_invocation([INTERNAL_WORKER_V3_ARGUMENT.into()]),
            Ok(Invocation::InternalWorkerV3)
        );
        assert_eq!(
            parse_invocation([INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT.into()]),
            Ok(Invocation::InternalWorkerV3LiveProof)
        );
        assert_eq!(
            parse_invocation([
                INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT.into(),
                "unexpected".into(),
            ]),
            Err(())
        );
    }

    #[test]
    fn production_takeover_precedes_tracing_runtime_and_server() {
        let source = include_str!("main.rs");
        let start = source
            .find("fn run_production()")
            .expect("production entry function");
        let end = source[start..]
            .find("#[cfg(test)]")
            .map(|offset| start + offset)
            .expect("end of production entry function");
        let production = &source[start..end];
        let takeover = production
            .find("take_systemd_listen_fd_set_once()")
            .expect("single systemd takeover");
        let tracing = production
            .find("tracing_subscriber::fmt()")
            .expect("tracing initialization");
        let server = production
            .find("run_production_server(inherited)")
            .expect("production server handoff");
        assert_eq!(
            production
                .matches("take_systemd_listen_fd_set_once()")
                .count(),
            1
        );
        assert!(takeover < tracing);
        assert!(tracing < server);
        assert!(!production[..takeover].contains("Builder::"));
        assert!(!production[..takeover].contains("spawn"));
    }
}
