//! Bounded, content-free executor suitability through the existing protected provider route.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use rand_core::{OsRng, RngCore as _};
use tokio::{
    task::JoinSet,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use volparossa_local_control::{
    ComputeDiscoverRequest, ComputeDiscovered, ComputeDiscoveredProvider, compute as rpc,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{ContentError, ContentRuntime, compute::validate_capabilities, compute_remote, now};
use crate::{
    control::ControlContext,
    discovery::{ContentDiscoveryError, DiscoveredContentProvider},
};

const MAX_CANDIDATES: usize = 16;
const MAX_PROBES: usize = 4;
const PROBE_TIMEOUT: Duration = Duration::from_secs(25);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(150);
const READINESS_RETRY: Duration = Duration::from_secs(2);

impl ContentRuntime {
    pub(crate) async fn compute_discover(
        &self,
        request: &ComputeDiscoverRequest,
        context: &ControlContext,
    ) -> Result<ComputeDiscovered, ContentError> {
        let query = request.eligibility().map_err(|_| ContentError::Invalid)?;
        let maximum = usize::try_from(request.maximum).map_err(|_| ContentError::Invalid)?;
        let minimum =
            usize::try_from(request.effective_minimum()).map_err(|_| ContentError::Invalid)?;
        let _foreground = self.foreground.enter();
        // One absolute window includes route setup, discovery, all probes and final checks.
        // Dropping the bounded JoinSet on expiry aborts only these short network RPCs: no
        // worker is admitted, so there is no remote job lease to lose or silently extend.
        let deadline = Instant::now() + DISCOVERY_TIMEOUT;
        let result = timeout_at(deadline, async {
            let policy = compute_remote::checked_policy(context, None).await?;
            super::content_event(context, "COMPUTE_DISCOVERY_ROUTE_SETUP").await;
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
            let probes = ProbeContext {
                context: context.clone(),
                policy,
                control,
                query,
                signer: Arc::clone(&self.signer),
            };
            loop {
                match probes.discover(minimum, maximum).await {
                    Ok(selected) => return Ok(selected),
                    Err(error) => {
                        let Some(retry_at) = readiness_retry_at(&error, Instant::now(), deadline)
                        else {
                            return Err(error);
                        };
                        // Only fresh metadata is queried again. No job is started and no
                        // source, offer, policy or job expiry is renewed by this wait.
                        super::content_event(context, "COMPUTE_DISCOVERY_READINESS_WAIT").await;
                        sleep_until(retry_at).await;
                    }
                }
            }
        })
        .await;
        let result = if let Ok(result) = result {
            result
        } else {
            super::content_event(context, "COMPUTE_DISCOVERY_DEADLINE_EXPIRED").await;
            Err(ContentError::Unavailable)
        };
        if result.is_err() {
            super::content_event(context, "COMPUTE_DISCOVERY_UNAVAILABLE").await;
        }
        result
    }
}

/// Decide from the original absolute window, never from a renewed per-attempt timeout.
fn readiness_retry_at(error: &ContentError, at: Instant, deadline: Instant) -> Option<Instant> {
    if !matches!(error, ContentError::Unavailable | ContentError::Busy) {
        return None;
    }
    let retry_at = at.checked_add(READINESS_RETRY)?;
    (retry_at < deadline).then_some(retry_at)
}

fn discovery_error(error: ContentDiscoveryError) -> ContentError {
    match error {
        ContentDiscoveryError::Invalid => ContentError::Invalid,
        ContentDiscoveryError::Invalidated => ContentError::Policy,
        ContentDiscoveryError::Busy => ContentError::Busy,
        ContentDiscoveryError::Closed
        | ContentDiscoveryError::Timeout
        | ContentDiscoveryError::Unavailable => ContentError::Unavailable,
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
    async fn discover(
        &self,
        minimum: usize,
        maximum: usize,
    ) -> Result<ComputeDiscovered, ContentError> {
        // Retain the original policy and carrying route even while brokers become ready.
        compute_remote::checked_policy(&self.context, Some(&self.policy)).await?;
        if self.context.routes.content_discovery_control().await != Some(self.control) {
            super::content_event(&self.context, "COMPUTE_DISCOVERY_FINAL_ROUTE_UNAVAILABLE").await;
            return Err(ContentError::Policy);
        }
        let providers = match self
            .context
            .discovery
            .discover_content_providers(self.control, MAX_CANDIDATES)
            .await
        {
            Ok(providers) => providers,
            Err(error) => {
                super::content_event(&self.context, "COMPUTE_DISCOVERY_QUERY_FAILED").await;
                return Err(discovery_error(error));
            }
        };
        super::content_event(&self.context, "COMPUTE_DISCOVERY_QUERY_COMPLETE").await;
        let observations = self.collect(providers).await?;
        super::content_event(&self.context, "COMPUTE_DISCOVERY_PROBES_COMPLETE").await;
        for code in eligibility_diagnostics(
            &self.query,
            observations.iter().map(|(_, eligibility)| eligibility),
        )
        .into_iter()
        .flatten()
        {
            super::content_event(&self.context, code).await;
        }
        let mut eligible = Vec::new();
        for (provider, eligibility) in observations {
            // Offers can expire or the carrying route can change while other probes run.
            if let Err(error) = compute_remote::checked_route(
                &self.context,
                &self.policy,
                self.control,
                provider.peer_id,
            )
            .await
            {
                super::content_event(&self.context, "COMPUTE_DISCOVERY_FINAL_ROUTE_UNAVAILABLE")
                    .await;
                return Err(error);
            }
            eligible.push((
                *provider.offer.provider_key(),
                eligibility,
                provider.offer.validity().expires,
            ));
        }
        if let Err(error) = compute_remote::checked_policy(&self.context, Some(&self.policy)).await
        {
            super::content_event(&self.context, "COMPUTE_DISCOVERY_FINAL_POLICY_FAILED").await;
            return Err(error);
        }
        let at = now();
        let live = eligible
            .into_iter()
            .filter(|(_, _, expires)| *expires > at)
            .map(|(key, eligibility, _)| (key, eligibility))
            .collect();
        let selected = select_pool(&self.query, live, minimum, maximum);
        if matches!(selected, Err(ContentError::Unavailable)) {
            super::content_event(&self.context, "COMPUTE_DISCOVERY_NO_COMPATIBLE_POOL").await;
        }
        selected
    }

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
                Ok(Err(ContentError::Unavailable | ContentError::Busy)) => {
                    // Generic CONTENT can mean an ordinary content provider, an old peer,
                    // or a temporarily unavailable broker. No error payload is logged.
                    super::content_event(&self.context, "COMPUTE_ELIGIBILITY_UNAVAILABLE").await;
                }
                Ok(Err(error)) => {
                    super::content_event(&self.context, "COMPUTE_ELIGIBILITY_REJECTED").await;
                    return Err(error);
                }
                Err(_) => return Err(ContentError::Invalid),
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
        let eligibility = eligibility_response(response.outcome)?;
        validate_capabilities(&eligibility.capabilities).map_err(|_| ContentError::Invalid)?;
        Ok((provider, eligibility))
    }
}

/// Aggregate fixed categories only, without retaining which peer or publisher was involved.
/// Declined eligibility is not, by itself, proof of a publisher-trust rejection.
fn eligibility_diagnostics<'a>(
    query: &rpc::EligibilityQuery,
    observations: impl Iterator<Item = &'a rpc::Eligibility>,
) -> [Option<&'static str>; 3] {
    let (mut declined, mut busy, mut mismatch) = (false, false, false);
    for observation in observations {
        declined |= !observation.eligible;
        busy |= !observation.capabilities.accepting_work;
        // Separate model/profile compatibility from transient availability for diagnostics
        // only. Admission and select_pool always inspect the unmodified observation.
        let mut profile = observation.capabilities.clone();
        profile.accepting_work = true;
        mismatch |= !query.matches(&profile);
    }
    [
        declined.then_some("COMPUTE_DISCOVERY_ELIGIBILITY_DECLINED"),
        busy.then_some("COMPUTE_DISCOVERY_PEERS_BUSY"),
        mismatch.then_some("COMPUTE_DISCOVERY_PROFILE_MISMATCH"),
    ]
}

fn eligibility_response(outcome: rpc::Outcome) -> Result<rpc::Eligibility, ContentError> {
    match outcome {
        rpc::Outcome::Eligibility(eligibility) => Ok(eligibility),
        rpc::Outcome::Error(rpc::ErrorCode::Busy) => Err(ContentError::Busy),
        rpc::Outcome::Error(rpc::ErrorCode::Unavailable | rpc::ErrorCode::ModelMismatch) => {
            Err(ContentError::Unavailable)
        }
        // A correlated response of the wrong operation/type or an invalid request must
        // not be turned into a successful-looking readiness wait.
        _ => Err(ContentError::Invalid),
    }
}

/// Choose one largest compatible cohort, independent of reply completion order.
/// Ties use ascending model fingerprint and provider key, never a quality/throughput claim.
fn select_pool(
    query: &rpc::EligibilityQuery,
    observations: Vec<([u8; 32], rpc::Eligibility)>,
    minimum: usize,
    maximum: usize,
) -> Result<ComputeDiscovered, ContentError> {
    query.validate().map_err(|_| ContentError::Invalid)?;
    if !(1..=4).contains(&maximum)
        || !(1..=maximum).contains(&minimum)
        || observations.len() > MAX_CANDIDATES
    {
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
    if largest.len() < minimum {
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
