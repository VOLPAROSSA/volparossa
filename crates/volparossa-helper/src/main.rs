//! Root VOLPAROSSA network helper executable.

use std::{ffi::OsString, process::ExitCode};

use volparossa_helper::{
    INTERNAL_NFT_FRONTEND_ARGUMENT, INTERNAL_WORKER_V3_ARGUMENT, bind_production_socket,
    run_internal_nft_frontend, run_internal_worker_v3_entry, run_server,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Invocation {
    Production,
    InternalNftFrontend,
    InternalWorkerV3,
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
        Ok(Invocation::Production) => run_production(),
        Err(()) => ExitCode::FAILURE,
    }
}

fn run_production() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    let Ok(server) = bind_production_socket() else {
        tracing::error!(
            diagnostic_code = "RUNTIME_SECURITY_FAILED",
            "helper startup rejected"
        );
        return ExitCode::FAILURE;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        tracing::error!(
            diagnostic_code = "ASYNC_RUNTIME_FAILED",
            "helper startup rejected"
        );
        return ExitCode::FAILURE;
    };
    if runtime.block_on(run_server(server)).is_ok() {
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
    }
}
