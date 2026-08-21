//! Fixed resource budgets for direct advertisement discovery.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use libp2p::{PeerId, kad, request_response};

pub(crate) const MAX_OUTSTANDING_PROVIDER_QUERIES: usize = 16;
pub(crate) const MAX_OUTSTANDING_ADVERTISEMENT_REQUESTS: usize = 256;
pub(crate) const MAX_TRACKED_ADVERTISEMENT_REQUESTERS: usize = 1_024;

const MIN_INBOUND_REQUEST_INTERVAL: Duration = Duration::from_secs(1);
const INBOUND_REQUEST_ENTRY_TTL: Duration = Duration::from_secs(60);

/// Process-local, strictly bounded discovery bookkeeping.
pub(crate) struct AdvertisementBudgets {
    provider_queries: HashMap<String, kad::QueryId>,
    outbound_requests: HashMap<PeerId, request_response::OutboundRequestId>,
    inbound_requesters: HashMap<PeerId, Instant>,
}

impl AdvertisementBudgets {
    pub(crate) fn new() -> Self {
        Self {
            provider_queries: HashMap::with_capacity(MAX_OUTSTANDING_PROVIDER_QUERIES),
            outbound_requests: HashMap::with_capacity(MAX_OUTSTANDING_ADVERTISEMENT_REQUESTS),
            inbound_requesters: HashMap::with_capacity(MAX_TRACKED_ADVERTISEMENT_REQUESTERS),
        }
    }

    pub(crate) fn provider_query_or_insert(
        &mut self,
        capability_key: &str,
        start: impl FnOnce() -> kad::QueryId,
    ) -> Option<kad::QueryId> {
        if let Some(query_id) = self.provider_queries.get(capability_key) {
            return Some(*query_id);
        }
        if self.provider_queries.len() >= MAX_OUTSTANDING_PROVIDER_QUERIES {
            return None;
        }
        let query_id = start();
        self.provider_queries
            .insert(capability_key.to_owned(), query_id);
        Some(query_id)
    }

    pub(crate) fn finish_provider_query(&mut self, query_id: kad::QueryId) {
        self.provider_queries
            .retain(|_, outstanding| *outstanding != query_id);
    }

    pub(crate) fn outbound_request_or_insert(
        &mut self,
        peer_id: &PeerId,
        start: impl FnOnce() -> request_response::OutboundRequestId,
    ) -> Option<request_response::OutboundRequestId> {
        if let Some(request_id) = self.outbound_requests.get(peer_id) {
            return Some(*request_id);
        }
        if self.outbound_requests.len() >= MAX_OUTSTANDING_ADVERTISEMENT_REQUESTS {
            return None;
        }
        let request_id = start();
        self.outbound_requests.insert(*peer_id, request_id);
        Some(request_id)
    }

    pub(crate) fn finish_outbound_request(
        &mut self,
        peer_id: &PeerId,
        request_id: request_response::OutboundRequestId,
    ) {
        if self.outbound_requests.get(peer_id) == Some(&request_id) {
            self.outbound_requests.remove(peer_id);
        }
    }

    pub(crate) fn allow_inbound_request(&mut self, peer_id: PeerId, now: Instant) -> bool {
        if let Some(last_request) = self.inbound_requesters.get_mut(&peer_id) {
            if now.saturating_duration_since(*last_request) < MIN_INBOUND_REQUEST_INTERVAL {
                return false;
            }
            *last_request = now;
            return true;
        }

        if self.inbound_requesters.len() >= MAX_TRACKED_ADVERTISEMENT_REQUESTERS {
            self.inbound_requesters.retain(|_, last_request| {
                now.saturating_duration_since(*last_request) < INBOUND_REQUEST_ENTRY_TTL
            });
        }
        if self.inbound_requesters.len() >= MAX_TRACKED_ADVERTISEMENT_REQUESTERS {
            return false;
        }
        self.inbound_requesters.insert(peer_id, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use libp2p::identity;

    use super::*;

    fn peer() -> PeerId {
        identity::Keypair::generate_ed25519().public().to_peer_id()
    }

    #[test]
    fn inbound_budget_is_per_peer_rate_limited_and_globally_bounded() {
        let now = Instant::now();
        let mut budgets = AdvertisementBudgets::new();
        let first = peer();
        assert!(budgets.allow_inbound_request(first, now));
        assert!(!budgets.allow_inbound_request(first, now));
        assert!(budgets.allow_inbound_request(first, now + MIN_INBOUND_REQUEST_INTERVAL));

        for _ in 1..MAX_TRACKED_ADVERTISEMENT_REQUESTERS {
            assert!(budgets.allow_inbound_request(peer(), now));
        }
        assert_eq!(
            budgets.inbound_requesters.len(),
            MAX_TRACKED_ADVERTISEMENT_REQUESTERS
        );
        assert!(!budgets.allow_inbound_request(peer(), now));

        let after_expiry = now + INBOUND_REQUEST_ENTRY_TTL + MIN_INBOUND_REQUEST_INTERVAL;
        assert!(budgets.allow_inbound_request(peer(), after_expiry));
        assert_eq!(budgets.inbound_requesters.len(), 1);
    }
}
