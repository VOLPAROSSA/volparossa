//! Private-mode source choice from recent completed work, never a per-name history.
//! Only one source is polled at a time; comparison probes replace an ordinary
//! lookup, not background or duplicate requests. This is not a fastest-source guarantee.

use std::{future::Future, sync::Mutex, time::Duration};

use tokio::time::{Instant, timeout_at};

use super::{Cache, DnsResolverError, ValidatedDnsAnswer};

const RECHECK: Duration = Duration::from_secs(30);
const COLD_BUDGET: Duration = Duration::from_millis(50);
const MIN_BUDGET: Duration = Duration::from_millis(20);
const MAX_BUDGET: Duration = Duration::from_millis(500);
const MARGIN: Duration = Duration::from_millis(5);

/// Constant-size, process-local timings only; no policy, question, address or peer IDs.
#[derive(Default)]
pub(super) struct SourceChoice {
    peer_cost: Option<Duration>,
    unbound_cost: Option<Duration>,
    peer_retry_at: Option<Instant>,
    next_comparison: Option<Instant>,
}

impl SourceChoice {
    fn peer_budget(&mut self, now: Instant, permitted: bool) -> Option<Duration> {
        if !permitted || self.peer_retry_at.is_some_and(|retry| retry > now) {
            return None;
        }
        let compare = self.next_comparison.is_none_or(|next| next <= now);
        let prefer_peer = match (self.peer_cost, self.unbound_cost) {
            (Some(peer), Some(unbound)) => peer.saturating_add(MARGIN) < unbound,
            (Some(_), None) => true,
            _ => false,
        };
        if compare {
            // Reserve the next comparison before awaiting anything. Concurrent
            // queries cannot all turn a cold/recovering backend into probes.
            self.next_comparison = Some(now + RECHECK);
            if prefer_peer {
                return None; // One real query measures the otherwise unused fallback.
            }
        } else if !prefer_peer {
            return None;
        }
        Some(self.unbound_cost.map_or(COLD_BUDGET, |cost| {
            cost.saturating_sub(MARGIN).clamp(MIN_BUDGET, MAX_BUDGET)
        }))
    }

    fn peer_completed(&mut self, now: Instant, elapsed: Duration, usable: bool) {
        if usable {
            Self::sample(&mut self.peer_cost, elapsed);
        } else {
            let retry = now + RECHECK;
            self.peer_retry_at = Some(retry);
            self.next_comparison = Some(retry);
        }
    }

    fn sample(previous: &mut Option<Duration>, elapsed: Duration) {
        let elapsed = elapsed.max(Duration::from_millis(1));
        *previous = Some(previous.map_or(elapsed, |old| {
            old.saturating_mul(3).saturating_add(elapsed) / 4
        }));
    }
}

/// Production supplies the complete peer fetch/validation/retention future and
/// the real supervised Unbound future. The latter is not polled (and cannot spawn
/// a worker) until the selected peer attempt has ended or was dropped on timeout.
pub(super) async fn resolve<P, U>(
    cache: &Mutex<Cache>,
    peers_permitted: bool,
    deadline: Instant,
    peer: P,
    unbound: U,
) -> Result<ValidatedDnsAnswer, DnsResolverError>
where
    P: Future<Output = Option<ValidatedDnsAnswer>>,
    U: Future<Output = Result<ValidatedDnsAnswer, DnsResolverError>>,
{
    let started = Instant::now();
    let budget = cache
        .lock()
        .ok()
        .and_then(|mut cache| cache.source_choice.peer_budget(started, peers_permitted));
    if let Some(budget) = budget {
        let peer_deadline = deadline.min(started + budget);
        let answer = timeout_at(peer_deadline, peer).await.ok().flatten();
        let now = Instant::now();
        // Also reject a late ready result: a single crypto/retention poll cannot
        // extend the peer budget merely by returning Ready after its deadline.
        let answer = answer.filter(|_| now < peer_deadline);
        if let Ok(mut cache) = cache.lock() {
            cache
                .source_choice
                .peer_completed(now, now - started, answer.is_some());
        }
        if let Some(answer) = answer {
            return Ok(answer);
        }
    }
    let started = Instant::now();
    // No new timeout/deadline: the actual backend owns its original absolute
    // deadline, two-worker bound, cleanup reserve and quarantine semantics.
    let answer = unbound.await;
    if answer.is_ok()
        || matches!(
            answer,
            Err(DnsResolverError::NameNotFound | DnsResolverError::NoData)
        )
    {
        if let Ok(mut cache) = cache.lock() {
            SourceChoice::sample(&mut cache.source_choice.unbound_cost, started.elapsed());
        }
    }
    answer
}

#[cfg(test)]
mod tests;
