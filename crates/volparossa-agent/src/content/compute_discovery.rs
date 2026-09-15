//! Bounded, content-free executor suitability through the existing protected provider route.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use rand_core::{OsRng, RngCore as _};
use tokio::{task::JoinSet, time::timeout};
use volparossa_local_control::{
    ComputeDiscoverRequest, ComputeDiscovered, ComputeDiscoveredProvider, compute as rpc,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{ContentError, ContentRuntime, compute::validate_capabilities, compute_remote, now};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider};

const MAX_CANDIDATES: usize = 16;
const MAX_PROBES: usize = 4;
const PROBE_TIMEOUT: Duration = Duration::from_secs(25);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(150);

impl ContentRuntime {
    pub(crate) async fn compute_discover(
        &self,
        request: &ComputeDiscoverRequest,
        context: &ControlContext,
    ) -> Result<ComputeDiscovered, ContentError> {
        let query = request.eligibility().map_err(|_| ContentError::Invalid)?;
        let maximum = usize::try_from(request.maximum).map_err(|_| ContentError::Invalid)?;
        let _foreground = self.foreground.enter();
        // One absolute window includes route setup, discovery, all probes and final checks.
        // Dropping the bounded JoinSet on expiry aborts only these short network RPCs: no
        // worker is admitted, so there is no remote job lease to lose or silently extend.
        let result = timeout(DISCOVERY_TIMEOUT, async {
            let policy = compute_remote::checked_policy(context, None).await?;
            Box::pin(context.routes.connect_tcp(
                &context.config,
                &context.discovery,
                &context.helper,
            ))
            .await
            .map_err(|_| ContentError::Unavailable)?;
            let control = context
                .routes
                .content_discovery_control()
                .await
                .ok_or(ContentError::Unavailable)?;
            let providers = context
                .discovery
                .discover_content_providers(control, MAX_CANDIDATES)
                .await
                .map_err(|_| ContentError::Unavailable)?;
            let probes = ProbeContext {
                context: context.clone(),
                policy,
                control,
                query,
                signer: Arc::clone(&self.signer),
            };
            let observations = probes.collect(providers).await?;
            let mut eligible = Vec::new();
            for (provider, eligibility) in observations {
                // Offers can expire or the carrying route can change while other probes run.
                compute_remote::checked_route(context, &probes.policy, control, provider.peer_id)
                    .await?;
                eligible.push((
                    *provider.offer.provider_key(),
                    eligibility,
                    provider.offer.validity().expires,
                ));
            }
            compute_remote::checked_policy(context, Some(&probes.policy)).await?;
            let at = now();
            let live = eligible
                .into_iter()
                .filter(|(_, _, expires)| *expires > at)
                .map(|(key, eligibility, _)| (key, eligibility))
                .collect();
            select_pool(&probes.query, live, maximum)
        })
        .await
        .map_err(|_| ContentError::Unavailable)
        .and_then(std::convert::identity);
        if result.is_err() {
            super::content_event(context, "COMPUTE_DISCOVERY_UNAVAILABLE").await;
        }
        result
    }
}

#[derive(Clone)]
struct ProbeContext {
    context: ControlContext,
    policy: VerifiedPolicy,
    control: PeerId,
    query: rpc::EligibilityQuery,
    signer: Arc<SigningKey>,
}

impl ProbeContext {
    async fn collect(
        &self,
        providers: Vec<DiscoveredContentProvider>,
    ) -> Result<Vec<(DiscoveredContentProvider, rpc::Eligibility)>, ContentError> {
        if providers.len() > MAX_CANDIDATES {
            return Err(ContentError::Invalid);
        }
        let mut unique = BTreeMap::new();
        for provider in providers {
            let key = *provider.offer.provider_key();
            if key != self.signer.verifying_key().to_bytes()
                && provider.offer.validity().expires > now()
                && self
                    .context
                    .routes
                    .content_provider_is_distinct(&provider.peer_id)
                    .await
            {
                unique.entry(key).or_insert(provider);
            }
        }
        let mut pending: VecDeque<_> = unique.into_values().collect();
        let mut tasks = JoinSet::new();
        let mut observations = Vec::new();
        loop {
            while tasks.len() < MAX_PROBES {
                let Some(provider) = pending.pop_front() else {
                    break;
                };
                let probe = self.clone();
                // A stalled generic/legacy endpoint must not consume the entire discovery
                // window and discard other suitable observations. No job is admitted here.
                tasks.spawn(async move {
                    timeout(PROBE_TIMEOUT, probe.one(provider))
                        .await
                        .map_err(|_| ContentError::Unavailable)
                        .and_then(std::convert::identity)
                });
            }
            let Some(result) = tasks.join_next().await else {
                break;
            };
            match result {
                Ok(Ok(observation)) => observations.push(observation),
                Ok(Err(_)) => {
                    // Generic CONTENT can mean an ordinary content provider, an old peer,
                    // or a temporarily unavailable broker. No error payload is logged.
                    super::content_event(&self.context, "COMPUTE_ELIGIBILITY_UNAVAILABLE").await;
                }
                Err(_) => return Err(ContentError::Unavailable),
            }
        }
        Ok(observations)
    }

    async fn one(
        &self,
        provider: DiscoveredContentProvider,
    ) -> Result<(DiscoveredContentProvider, rpc::Eligibility), ContentError> {
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| ContentError::Unavailable)?;
        let request = rpc::Request {
            version: rpc::VERSION,
            request_id: hex::encode(nonce),
            requester_key: hex::encode(self.signer.verifying_key().as_bytes()),
            operation: rpc::Operation::Eligibility(self.query.clone()),
        };
        let mut stage = "COMPUTE_ELIGIBILITY_UNAVAILABLE";
        let response = compute_remote::exchange_offer(
            &self.context,
            self.control,
            &provider,
            &self.policy,
            &self.signer,
            &request,
            &mut stage,
        )
        .await?;
        let rpc::Outcome::Eligibility(eligibility) = response.outcome else {
            return Err(ContentError::Unavailable);
        };
        validate_capabilities(&eligibility.capabilities).map_err(|_| ContentError::Invalid)?;
        Ok((provider, eligibility))
    }
}

/// Choose one largest compatible cohort, independent of reply completion order.
/// Ties use ascending model fingerprint and provider key, never a quality/throughput claim.
fn select_pool(
    query: &rpc::EligibilityQuery,
    observations: Vec<([u8; 32], rpc::Eligibility)>,
    maximum: usize,
) -> Result<ComputeDiscovered, ContentError> {
    query.validate().map_err(|_| ContentError::Invalid)?;
    if !(2..=4).contains(&maximum) || observations.len() > MAX_CANDIDATES {
        return Err(ContentError::Invalid);
    }
    let mut cohorts: BTreeMap<String, BTreeMap<[u8; 32], rpc::Capabilities>> = BTreeMap::new();
    for (key, observation) in observations {
        let caps = observation.capabilities;
        if !observation.eligible
            || !query.matches(&caps)
            || validate_capabilities(&caps).is_err()
            || key == [0; 32]
            || ed25519_dalek::VerifyingKey::from_bytes(&key).is_err()
        {
            continue;
        }
        cohorts
            .entry(caps.model_fingerprint.clone())
            .or_default()
            .entry(key)
            .or_insert(caps);
    }
    let mut largest = BTreeMap::new();
    for cohort in cohorts.into_values() {
        if cohort.len() > largest.len() {
            largest = cohort;
        }
    }
    if largest.len() < 2 {
        return Err(ContentError::Unavailable);
    }
    let providers = largest
        .into_iter()
        .take(maximum)
        .map(|(key, caps)| {
            Ok(ComputeDiscoveredProvider {
                provider_key: key.to_vec(),
                capabilities_json: serde_json::to_string(&caps)
                    .map_err(|_| ContentError::Invalid)?,
            })
        })
        .collect::<Result<_, ContentError>>()?;
    Ok(ComputeDiscovered { providers })
}

#[cfg(test)]
mod tests;
