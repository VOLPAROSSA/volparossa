//! Explicit public executor discovery; offers locate workers but never authorize source data.

use std::collections::BTreeSet;

use super::*;

#[derive(Clone, Debug, Default, Args)]
#[group(id = "ComputeExecutorDiscovery")]
pub(super) struct Options {
    /// Find a compatible idle worker group through the current protected route before enrollment.
    #[arg(long, conflicts_with_all = ["provider_key", "resume"])]
    pub(super) discover_peers: bool,
    /// Optional exact base/adapter profile; otherwise select one mutually compatible group.
    #[arg(long, requires = "discover_peers", value_parser = parse_fingerprint)]
    pub(super) model_fingerprint: Option<String>,
    /// Maximum peers enrolled in this task, not a network-wide connection limit.
    #[arg(long, requires = "discover_peers", value_parser = clap::value_parser!(u32).range(2..=4))]
    max_peers: Option<u32>,
}

pub(super) struct Selected {
    pub(super) providers: Vec<VerifyingKey>,
    pub(super) model_fingerprint: String,
}

pub(super) fn parse_fingerprint(value: &str) -> Result<String, String> {
    if rpc::nonzero_hex(value, 64) {
        Ok(value.into())
    } else {
        Err("compute_discovery_model_fingerprint".into())
    }
}

impl Options {
    pub(super) fn query(
        &self,
        publishers: impl IntoIterator<Item = String>,
        task: bool,
        document: bool,
        derived: bool,
    ) -> Result<rpc::EligibilityQuery> {
        let query = rpc::EligibilityQuery {
            publisher_keys: publishers
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            model_fingerprint: self.model_fingerprint.clone(),
            require_task_derivation_v1: task,
            require_document_inference_v2: document,
            require_derived_inference_v3: derived,
        };
        query.validate()?;
        Ok(query)
    }

    pub(super) async fn select(
        &self,
        socket: &Path,
        query: rpc::EligibilityQuery,
        cancelled: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<Selected> {
        ensure!(self.discover_peers, "compute_discovery_not_enabled");
        ensure!(!*cancelled.borrow(), "compute_discovery_cancelled");
        query.validate()?;
        let maximum = self.max_peers.unwrap_or(4);
        let request = volparossa_local_control::ComputeDiscoverRequest {
            publisher_keys: query
                .publisher_keys
                .iter()
                .map(hex::decode)
                .collect::<Result<_, _>>()?,
            model_fingerprint: query.model_fingerprint.clone(),
            require_task_derivation_v1: query.require_task_derivation_v1,
            require_document_inference_v2: query.require_document_inference_v2,
            require_derived_inference_v3: query.require_derived_inference_v3,
            maximum,
        };
        let mut cancellation = cancelled.clone();
        // This query never submits jobs. Dropping it cannot strand remote execution.
        let response = tokio::select! { biased;
            _ = cancellation.changed() => anyhow::bail!("compute_discovery_cancelled"),
            result = timeout(Duration::from_secs(155), crate::control::request(
                socket, Operation::ComputeDiscover(request))) => result.context("compute_discovery_timeout")??,
        };
        let Some(Payload::ComputeDiscovered(found)) = response.payload else {
            anyhow::bail!("compute_discovery_response");
        };
        checked_selection(&found, &query, maximum)
    }
}

fn checked_selection(
    found: &volparossa_local_control::ComputeDiscovered,
    query: &rpc::EligibilityQuery,
    maximum: u32,
) -> Result<Selected> {
    ensure!(
        (2..=maximum as usize).contains(&found.providers.len()),
        "compute_discovery_insufficient_peers"
    );
    let mut providers = Vec::new();
    let mut seen = BTreeSet::new();
    let mut fingerprint = None;
    for provider in &found.providers {
        let key = parse_key(&hex::encode(&provider.provider_key)).map_err(anyhow::Error::msg)?;
        ensure!(
            seen.insert(key.to_bytes()),
            "compute_discovery_duplicate_peer"
        );
        let caps: rpc::Capabilities = serde_json::from_str(&provider.capabilities_json)?;
        validate_profile(&caps)?;
        ensure!(query.matches(&caps), "compute_discovery_ineligible_profile");
        if let Some(expected) = &fingerprint {
            ensure!(
                expected == &caps.model_fingerprint,
                "compute_discovery_mixed_models"
            );
        } else {
            fingerprint = Some(caps.model_fingerprint.clone());
        }
        providers.push(key);
    }
    Ok(Selected {
        providers,
        model_fingerprint: fingerprint.context("compute_discovery_no_model")?,
    })
}

#[cfg(test)]
mod tests;
