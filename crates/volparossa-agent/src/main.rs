//! `volparossa-agent` executable entry point.

use std::process::ExitCode;

use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use volparossa_agent::{Agent, AgentPaths};

#[tokio::main]
async fn main() -> ExitCode {
    initialize_tracing();
    let paths = match AgentPaths::from_environment() {
        Ok(paths) => paths,
        Err(error) => {
            tracing::error!(diagnostic_code = "PATH_INVALID", error = %error, "agent startup failed");
            return ExitCode::FAILURE;
        }
    };
    let agent = match Agent::load(paths) {
        Ok(agent) => agent,
        Err(error) => {
            tracing::error!(
                diagnostic_code = error.diagnostic_code(),
                "agent startup failed"
            );
            return ExitCode::FAILURE;
        }
    };
    match Box::pin(agent.run_with_shutdown(shutdown_signal())).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(
                diagnostic_code = error.diagnostic_code(),
                "agent stopped with failure"
            );
            ExitCode::FAILURE
        }
    }
}

fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json());
    let _ = subscriber.try_init();
}

async fn shutdown_signal() {
    let terminate = signal(SignalKind::terminate());
    let interrupt = signal(SignalKind::interrupt());
    match (terminate, interrupt) {
        (Ok(mut terminate), Ok(mut interrupt)) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        }
        _ => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}
