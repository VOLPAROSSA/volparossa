//! Request-isolated refresh of enrolled provider identities; no publication or mailbox keys.

use super::{
    BTreeMap, COLLECTION_TIMEOUT, ConnectionId, ContentDiscoveryResponse, ContentProviderOffer,
    ContentServiceRequest, ContentServiceResponse, DiscoveryRuntime, HashMap, HashSet, Instant,
    Libp2pPeerId, MAX_PENDING, OutboundId, RelayWaiter, kad, request_response, unix_millis,
    unix_seconds, verify_provider,
};

type LookupKey = (Libp2pPeerId, [u8; 32]);

#[derive(Default)]
pub(super) struct ExactLookups {
    jobs: HashMap<LookupKey, ExactLookup>,
    queries: HashMap<kad::QueryId, (LookupKey, Libp2pPeerId)>,
    requests: HashMap<OutboundId, (LookupKey, Libp2pPeerId)>,
}

struct ExactLookup {
    waiter: RelayWaiter,
    deadline: Instant,
    remaining: HashSet<Libp2pPeerId>,
    resolved: HashSet<Libp2pPeerId>,
    offers: BTreeMap<Libp2pPeerId, Vec<u8>>,
}

impl ExactLookups {
    pub(super) fn pending(&self) -> usize {
        self.jobs.len() + self.queries.len() + self.requests.len()
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.jobs.values().map(|job| job.deadline).min()
    }
}

impl DiscoveryRuntime {
    pub(super) fn begin_exact_content_lookup(&mut self, waiter: RelayWaiter) {
        let Ok(targets) = waiter.request.target_peers() else {
            return;
        };
        let Ok(nonce) = <[u8; 32]>::try_from(waiter.request.nonce()) else {
            return;
        };
        if targets
            .iter()
            .any(|peer| *peer == waiter.peer || peer == self.service.local_peer_id())
            || self.content.pending() + targets.len() + 1 > MAX_PENDING
        {
            self.send_empty_content_response(&waiter.request, waiter.channel);
            return;
        }
        let key = (waiter.peer, nonce);
        self.content.exact.jobs.insert(
            key,
            ExactLookup {
                waiter,
                deadline: Instant::now() + COLLECTION_TIMEOUT,
                remaining: targets.iter().copied().collect(),
                resolved: HashSet::new(),
                offers: BTreeMap::new(),
            },
        );
        self.content.event("CONTENT_EXACT_LOOKUP_STARTED");
        for peer in targets {
            let resolve = !self.service.content_provider_address_known(&peer);
            self.dispatch_exact_content_provider(key, peer, resolve);
        }
    }

    fn dispatch_exact_content_provider(
        &mut self,
        key: LookupKey,
        peer: Libp2pPeerId,
        resolve: bool,
    ) {
        let Some(job) = self.content.exact.jobs.get_mut(&key) else {
            return;
        };
        if job.deadline <= Instant::now() || self.content.pending() >= MAX_PENDING {
            self.finish_exact_content_peer(key, peer, None);
            return;
        }
        if resolve {
            self.content
                .exact
                .jobs
                .get_mut(&key)
                .expect("retained exact lookup")
                .resolved
                .insert(peer);
            if let Ok(id) = self.service.begin_content_address_lookup(peer) {
                self.content.exact.queries.insert(id, (key, peer));
                self.content.event("CONTENT_EXACT_ADDRESS_QUERY_STARTED");
                return;
            }
        } else if let Ok(id) = self
            .service
            .request_content_service(&peer, ContentServiceRequest::new())
        {
            self.content.exact.requests.insert(id, (key, peer));
            return;
        }
        self.finish_exact_content_peer(key, peer, None);
    }

    pub(super) fn handle_exact_content_query(
        &mut self,
        id: kad::QueryId,
        result: &kad::QueryResult,
        last: bool,
    ) -> bool {
        if !self.content.exact.queries.contains_key(&id) {
            return false;
        }
        if !last {
            return true;
        }
        let Some((key, peer)) = self.content.exact.queries.remove(&id) else {
            return true;
        };
        let request = if let kad::QueryResult::GetClosestPeers(result) = result {
            self.service
                .request_content_service_resolved(id, result, ContentServiceRequest::new())
        } else {
            let _ = self.service.finish_content_address_lookup(id);
            self.finish_exact_content_peer(key, peer, None);
            return true;
        };
        if let Ok(request) = request {
            self.content.exact.requests.insert(request, (key, peer));
            self.content.event("CONTENT_EXACT_RESOLVED_REQUEST_SENT");
        } else {
            self.content.event("CONTENT_EXACT_ADDRESS_UNAVAILABLE");
            self.finish_exact_content_peer(key, peer, None);
        }
        true
    }

    pub(super) fn handle_exact_content_service(
        &mut self,
        event: &request_response::Event<ContentServiceRequest, ContentServiceResponse>,
    ) -> bool {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let Some((key, expected)) = self.content.exact.requests.remove(request_id) else {
                    return false;
                };
                let offer = response.offer().filter(|bytes| {
                    *peer == expected && verify_provider(expected, bytes, unix_seconds()).is_ok()
                });
                self.finish_exact_content_peer(key, expected, offer.map(<[u8]>::to_vec));
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                let Some((key, peer)) = self.content.exact.requests.remove(request_id) else {
                    return false;
                };
                // A remembered address can become stale while a provider is offline. Resolve
                // its exact node ID once within this same original bounded job, not a retry loop.
                let resolve = matches!(error, request_response::OutboundFailure::DialFailure)
                    && self
                        .content
                        .exact
                        .jobs
                        .get(&key)
                        .is_some_and(|job| !job.resolved.contains(&peer));
                if resolve {
                    self.dispatch_exact_content_provider(key, peer, true);
                } else {
                    self.finish_exact_content_peer(key, peer, None);
                }
            }
            _ => return false,
        }
        true
    }

    fn finish_exact_content_peer(
        &mut self,
        key: LookupKey,
        peer: Libp2pPeerId,
        offer: Option<Vec<u8>>,
    ) {
        let Some(job) = self.content.exact.jobs.get_mut(&key) else {
            return;
        };
        if !job.remaining.remove(&peer) {
            return;
        }
        if job.deadline > Instant::now() {
            if let Some(offer) = offer {
                job.offers.insert(peer, offer);
            }
        }
        if job.remaining.is_empty() {
            self.finish_exact_content_lookup(key, true);
        }
    }

    fn finish_exact_content_lookup(&mut self, key: LookupKey, accept: bool) {
        let Some(job) = self.content.exact.jobs.remove(&key) else {
            return;
        };
        let queries: Vec<_> = self
            .content
            .exact
            .queries
            .iter()
            .filter_map(|(id, (owner, _))| (*owner == key).then_some(*id))
            .collect();
        for id in queries {
            self.content.exact.queries.remove(&id);
            let _ = self.service.finish_content_address_lookup(id);
        }
        self.content
            .exact
            .requests
            .retain(|_, (owner, _)| *owner != key);
        if !self
            .service
            .content_control_connection_is_current(&job.waiter.peer, job.waiter.connection)
        {
            return;
        }
        let now = unix_millis();
        let valid = accept
            && job.deadline > Instant::now()
            && self.roles.relay
            && self
                .local_relay_snapshot
                .as_ref()
                .is_some_and(|cap| cap.expires_at_ms > now);
        let offers = if valid {
            job.offers
                .into_iter()
                .filter_map(|(peer, bytes)| {
                    verify_provider(peer, &bytes, unix_seconds()).ok()?;
                    ContentProviderOffer::new(peer, bytes).ok()
                })
                .collect()
        } else {
            Vec::new()
        };
        if let Ok(response) = ContentDiscoveryResponse::new(&job.waiter.request, offers) {
            let _ = self
                .service
                .send_content_discovery_response(job.waiter.channel, response);
        }
        self.content.event("CONTENT_EXACT_LOOKUP_FINISHED");
    }

    pub(super) fn maintain_exact_content(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .content
            .exact
            .jobs
            .iter()
            .filter_map(|(key, job)| (job.deadline <= now).then_some(*key))
            .collect();
        for key in expired {
            self.finish_exact_content_lookup(key, false);
        }
    }

    pub(super) fn close_exact_content_connection(
        &mut self,
        peer: Libp2pPeerId,
        connection: ConnectionId,
    ) {
        let closed: Vec<_> = self
            .content
            .exact
            .jobs
            .iter()
            .filter_map(|(key, job)| {
                (job.waiter.peer == peer && job.waiter.connection == connection).then_some(*key)
            })
            .collect();
        for key in closed {
            self.finish_exact_content_lookup(key, false);
        }
    }

    pub(super) fn invalidate_exact_content(&mut self) {
        let keys: Vec<_> = self.content.exact.jobs.keys().copied().collect();
        for key in keys {
            self.finish_exact_content_lookup(key, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{AdvertisementPayloadHash, DirectRelayCapability};
    use volparossa_discovery::DiscoveryEvent;

    fn isolate() -> bool {
        const MARKER: &str = "VOLPAROSSA_EXACT_CONTENT_PARENT_NETNS";
        if let Some(parent) = std::env::var_os(MARKER) {
            assert_ne!(
                std::fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
                parent
            );
            return false;
        }
        let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/run-isolated-test.sh");
        let status = std::process::Command::new(runner).arg(std::env::current_exe().unwrap())
            .arg("discovery::content::exact::tests::exact_content_lookup_reaches_unknown_provider_through_broker_and_rejects_empty")
            .arg(MARKER).arg("none").status().unwrap();
        assert!(status.success(), "isolated exact lookup failed: {status}");
        true
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one real four-swarm lookup and withdrawal lifecycle"
    )]
    async fn exact_content_lookup_reaches_unknown_provider_through_broker_and_rejects_empty() {
        if isolate() {
            return;
        }
        let (mut client, state, _client_dir) =
            crate::discovery::tests::retirement_runtime_fixture();
        let (mut broker, _, _broker_dir) = crate::discovery::tests::retirement_runtime_fixture();
        let (mut provider, _, _provider_dir) =
            Box::pin(super::super::tests::registered_content_runtime()).await;
        let (mut contact, _, _contact_dir) =
            Box::pin(super::super::tests::registered_content_runtime()).await;
        crate::discovery::tests::connect_runtime_client_to_control(
            &mut client,
            &mut broker.service,
        )
        .await;
        let broker_peer = *broker.service.local_peer_id();
        let provider_peer = *provider.service.local_peer_id();
        let contact_peer = *contact.service.local_peer_id();
        let policy = state.read().await.active_policy(unix_millis()).unwrap();
        let expiry = unix_millis() + 120_000;
        let capability = DirectRelayCapability {
            node_id: broker.local_node_id,
            peer_id: broker_peer,
            public_key: broker.local_public_key,
            advertisement_sequence: 1,
            advertisement_expires_at_ms: expiry,
            advertisement_payload_hash: AdvertisementPayloadHash::for_test(broker.local_node_id),
            policy_version: policy.manifest_version(),
            policy_hash: *policy.policy_hash(),
            policy_expires_at_ms: policy.expires_at_ms(),
            expires_at_ms: expiry.min(policy.expires_at_ms()),
        };
        // The fixture supplies already-verified control authority, as the established route does;
        // real Noise/Yamux connections and production bound RPCs still carry every lookup.
        client.direct_relays.insert(broker_peer, capability.clone());
        broker.local_relay_snapshot = Some(capability);
        broker
            .service
            .add_known_peer(
                contact_peer,
                &contact.config.network.listen_addresses[0].parse().unwrap(),
            )
            .unwrap();
        contact
            .service
            .add_known_peer(
                provider_peer,
                &provider.config.network.listen_addresses[0].parse().unwrap(),
            )
            .unwrap();
        assert!(
            !broker
                .service
                .content_provider_address_known(&provider_peer)
        );
        assert!(
            !client
                .service
                .content_provider_address_known(&provider_peer)
        );
        assert!(!client.service.content_provider_address_known(&contact_peer));
        for withdrawn in [false, true] {
            if withdrawn {
                provider.withdraw_content_registration();
            }
            let targets = if withdrawn {
                vec![provider_peer]
            } else {
                vec![provider_peer, contact_peer]
            };
            let (reply, mut response) = tokio::sync::oneshot::channel();
            client.dispatch_content_discovery(
                broker_peer,
                super::super::ContentDiscoveryRequest::for_peers(&targets).unwrap(),
                reply,
            );
            let result = tokio::time::timeout(std::time::Duration::from_secs(12), async {
                loop {
                    client.maintain_content();
                    broker.maintain_content();
                    tokio::select! {
                        response = &mut response => break response.unwrap(),
                        event = client.service.next_event() => if let DiscoveryEvent::Other(event) = event {
                            if let super::super::SwarmEvent::ConnectionEstablished { peer_id, .. } = &event {
                                assert_eq!(*peer_id, broker_peer, "client never dials a provider");
                            }
                            let _ = client.handle_content_swarm_event(event);
                        },
                        event = broker.service.next_event() => if let DiscoveryEvent::Other(event) = event { let _ = broker.handle_content_swarm_event(event); },
                        event = provider.service.next_event() => if let DiscoveryEvent::Other(event) = event { let _ = provider.handle_content_swarm_event(event); },
                        event = contact.service.next_event() => if let DiscoveryEvent::Other(event) = event { let _ = contact.handle_content_swarm_event(event); },
                    }
                }
            }).await.expect("bounded real broker lookup");
            if withdrawn {
                assert_eq!(
                    result.unwrap_err(),
                    super::super::ContentDiscoveryError::Unavailable
                );
            } else {
                let offers = result.expect("fresh signed offers from both exact peers");
                assert_eq!(
                    offers
                        .iter()
                        .map(|offer| offer.peer_id)
                        .collect::<HashSet<_>>(),
                    targets.into_iter().collect()
                );
                assert!(
                    offers
                        .iter()
                        .all(|offer| offer.offer.validity().expires > unix_seconds())
                );
                assert!(
                    broker
                        .content
                        .events
                        .contains(&"CONTENT_EXACT_RESOLVED_REQUEST_SENT")
                );
                assert!(
                    broker.content.relay.is_none(),
                    "no generic content DHT round substitutes for exact lookup"
                );
            }
            assert!(broker.content.exact.jobs.is_empty());
            assert!(broker.content.exact.requests.is_empty());
            assert!(broker.content.exact.queries.is_empty());
        }
    }
}
