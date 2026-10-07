//! Closed read-only advertisement observation. Never reports an established route.

use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use clap::ValueEnum;
use serde_json::{Value, json};
use volparossa_local_control::{
    RouteReadinessOutcome, RouteReadinessRequest, SessionTransport, control_request::Operation,
    control_response::Payload,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Transport {
    Mptcp,
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

pub(crate) async fn run(socket: &Path, _transport: Transport) -> Result<()> {
    let started = now_ms()?;
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        crate::control::request(
            socket,
            Operation::RouteReadiness(RouteReadinessRequest {
                transport: Some(SessionTransport::Mptcp as i32),
            }),
        ),
    )
    .await??;
    ensure!(
        response.diagnostic_code == "ROUTE_ADVERTISEMENT_OBSERVED",
        "unexpected readiness diagnostic"
    );
    let Some(Payload::RouteReadiness(observation)) = response.payload else {
        anyhow::bail!("missing typed readiness observation");
    };
    let report = checked_report(observation, started, now_ms()?)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn checked_report(
    observation: volparossa_local_control::RouteReadinessObservation,
    started: u64,
    completed: u64,
) -> Result<Value> {
    ensure!(
        observation.transport == Some(SessionTransport::Mptcp as i32)
            && started > 0
            && started <= observation.captured_at_unix_ms
            && observation.captured_at_unix_ms <= completed,
        "stale or inconsistent readiness observation"
    );
    let outcome = RouteReadinessOutcome::try_from(observation.outcome)?;
    let code = match outcome {
        RouteReadinessOutcome::EligibleAdvertisementSlate => "eligible_advertisement_slate",
        RouteReadinessOutcome::IncompleteSnapshot => "incomplete_snapshot",
        RouteReadinessOutcome::NoEligibleExitPair => "no_eligible_exit_pair",
        RouteReadinessOutcome::InsufficientDiverseRelays => "insufficient_diverse_relays",
        RouteReadinessOutcome::ObservationUnavailable => "observation_unavailable",
        RouteReadinessOutcome::Unspecified => anyhow::bail!("unspecified readiness outcome"),
    };
    Ok(
        json!({"schema_version":1,"scope":"advertisement_preselection","transport":"mptcp",
        "captured_at_unix_ms":observation.captured_at_unix_ms,"outcome":code,
        "eligible_slate_observed":outcome == RouteReadinessOutcome::EligibleAdvertisementSlate,
        "dataplane_verified":false,"route_selected":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use volparossa_local_control::RouteReadinessObservation;

    #[test]
    fn route_readiness_cli_is_explicit_read_only_mptcp() {
        assert!(
            crate::Cli::try_parse_from(["volparossa", "route-readiness", "--transport", "mptcp"])
                .is_ok()
        );
        for arguments in [
            vec!["volparossa", "route-readiness"],
            vec![
                "volparossa",
                "route-readiness",
                "--transport",
                "single-path-udp",
            ],
            vec![
                "volparossa",
                "route-readiness",
                "--transport",
                "mptcp",
                "--exit",
                "some-peer",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn route_readiness_report_is_closed_fresh_and_non_authoritative() {
        for outcome in 1..=5 {
            let mut observation = RouteReadinessObservation {
                transport: Some(SessionTransport::Mptcp as i32),
                captured_at_unix_ms: 101,
                outcome,
            };
            let value = checked_report(observation, 100, 102).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 8);
            assert_eq!(value["eligible_slate_observed"], outcome == 1);
            assert_eq!(value["dataplane_verified"], false);
            assert_eq!(value["route_selected"], false);
            assert!(checked_report(observation, 102, 103).is_err());
            assert!(checked_report(observation, 99, 100).is_err());
            observation.outcome = 0;
            assert!(checked_report(observation, 100, 102).is_err());
        }
    }
}
