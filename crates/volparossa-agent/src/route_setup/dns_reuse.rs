//! Same-name UDP DNS reuse; one pending request and unchanged signed route ownership.

use super::{
    ClientRouteConnectError, ClientRouteControl, ClientRouteControlState, ClientTransportState,
};
use crate::client_ingress::{DnsIngressIdentity, PolicyAuthorizedDnsIngress};
use std::time::Duration;
use tokio::time::Instant;
use volparossa_policy::VerifiedManifest;
use volparossa_udp::{MAX_DNS_ASSOCIATION_QUERIES, validate_dns_response};

const IDLE: Duration = Duration::from_secs(30);

pub(super) struct ReusableDns {
    identity: DnsIngressIdentity,
    pending: Option<Vec<u8>>,
    requests: u8,
    expires_at_ms: u64,
    absolute_deadline: Instant,
    idle_deadline: Instant,
}

impl ReusableDns {
    pub(super) fn new(
        identity: DnsIngressIdentity,
        request: Vec<u8>,
        expires_at_ms: u64,
        now_ms: u64,
        now: Instant,
    ) -> Self {
        let absolute_deadline = now + Duration::from_millis(expires_at_ms.saturating_sub(now_ms));
        Self {
            identity,
            pending: Some(request),
            requests: 1,
            expires_at_ms,
            absolute_deadline,
            idle_deadline: (now + IDLE).min(absolute_deadline),
        }
    }

    pub(super) fn expired(&self, now_ms: u64, now: Instant) -> bool {
        now_ms >= self.expires_at_ms
            || now >= self.absolute_deadline
            || now >= self.idle_deadline
            || (self.requests == MAX_DNS_ASSOCIATION_QUERIES && self.pending.is_none())
    }

    fn deadline(&self) -> Instant {
        if self.requests == MAX_DNS_ASSOCIATION_QUERIES && self.pending.is_none() {
            Instant::now()
        } else {
            self.absolute_deadline.min(self.idle_deadline)
        }
    }

    fn compatible(&self, ingress: &PolicyAuthorizedDnsIngress, now_ms: u64, now: Instant) -> bool {
        !self.expired(now_ms, now)
            && self.requests < MAX_DNS_ASSOCIATION_QUERIES
            && self.identity == ingress.reuse_identity()
    }

    fn sent(&mut self, request: &[u8], now: Instant) {
        self.pending = Some(request.to_vec());
        self.requests += 1;
        self.idle_deadline = (now + IDLE).min(self.absolute_deadline);
    }

    pub(super) fn accept_response(
        &mut self,
        payload: &[u8],
        now_ms: u64,
        now: Instant,
    ) -> Result<(), ClientRouteConnectError> {
        if self.expired(now_ms, now) {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let request = self
            .pending
            .as_ref()
            .ok_or(ClientRouteConnectError::TransportRuntimeUnavailable)?;
        validate_dns_response(request, payload)
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        self.pending = None;
        self.idle_deadline = (now + IDLE).min(self.absolute_deadline);
        Ok(())
    }
}

impl ClientRouteControl {
    /// Called under the existing DNS transaction lock. A new binding gets a new ordinary
    /// route; it never retargets the retained association or extends its authorization.
    pub(crate) async fn try_send_reusable_dns(
        &self,
        ingress: &PolicyAuthorizedDnsIngress,
        policy: &VerifiedManifest,
    ) -> Result<bool, ClientRouteConnectError> {
        if !ingress.is_current(policy, crate::unix_millis()) {
            return Err(ClientRouteConnectError::UdpIngressUnavailable);
        }
        self.retire_expired_route(crate::unix_millis(), Instant::now())
            .await;
        let mut state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Ok(false);
        };
        let ClientTransportState::UdpActive(active) = &mut established.transport else {
            return Ok(false);
        };
        if let Some(dns) = &mut active.reusable_dns {
            if dns.pending.is_some() {
                return Err(ClientRouteConnectError::Busy);
            }
            if dns.compatible(ingress, crate::unix_millis(), Instant::now()) {
                active
                    .client
                    .send_payload(ingress.dns_payload())
                    .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
                dns.sent(ingress.dns_payload(), Instant::now());
                return Ok(true);
            }
        }
        drop(state);
        self.disconnect_confirmed()
            .await
            .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        Ok(false)
    }

    /// Only retire UDP reuse, so TCP's own one-shot lifecycle is unchanged.
    pub(crate) async fn disconnect_reusable_dns(&self) -> Result<(), ClientRouteConnectError> {
        let retained = matches!(&*self.state.lock().await,
            ClientRouteControlState::Established(established)
            if matches!(&established.transport, ClientTransportState::UdpActive(active) if active.reusable_dns.is_some()));
        if retained {
            self.disconnect_confirmed()
                .await
                .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
        }
        Ok(())
    }

    pub(crate) async fn reusable_dns_retirement_deadline(&self) -> Option<Instant> {
        self.retire_expired_route(crate::unix_millis(), Instant::now())
            .await;
        let state = self.state.lock().await;
        let ClientRouteControlState::Established(established) = &*state else {
            return None;
        };
        let ClientTransportState::UdpActive(active) = &established.transport else {
            return None;
        };
        active.reusable_dns.as_deref().map(ReusableDns::deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
    use volparossa_test_support::verified_development_manifest;

    const NOW: u64 = 1_900_000_000_000;

    fn query(kind: u8, id: u16) -> Vec<u8> {
        let mut raw = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        raw[..2].copy_from_slice(&id.to_be_bytes());
        raw.extend_from_slice(b"\x07allowed\x07example\0");
        raw.extend_from_slice(&[0, kind, 0, 1]);
        raw
    }

    fn response(request: &[u8]) -> Vec<u8> {
        // An actual well-formed empty NOERROR answer; no DNSSEC/network proof is claimed.
        let mut reply = request.to_vec();
        reply[2] |= 0x80;
        reply
    }

    fn policy(extra: bool) -> VerifiedManifest {
        let permission = ProtocolPort::new(TransportProtocol::Udp, 53).unwrap();
        let mut rules =
            vec![DestinationRule::exact_domain("allowed.example", [permission]).unwrap()];
        if extra {
            rules.push(DestinationRule::exact_domain("another.example", [permission]).unwrap());
        }
        verified_development_manifest(NOW, rules).unwrap()
    }

    fn ingress(
        raw: Vec<u8>,
        source: &str,
        resolver: &str,
        policy: &VerifiedManifest,
    ) -> PolicyAuthorizedDnsIngress {
        PolicyAuthorizedDnsIngress::authorize(
            source.parse::<SocketAddr>().unwrap(),
            resolver.parse::<SocketAddr>().unwrap(),
            raw,
            policy,
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn dns_reuse_correlates_a_then_aaaa_and_rejects_changed_owner_or_policy() {
        let policy = policy(false);
        let now = Instant::now();
        let a = ingress(query(1, 1), "192.0.2.10:42000", "9.9.9.9:53", &policy);
        let aaaa = ingress(query(28, 2), "192.0.2.10:42000", "9.9.9.9:53", &policy);
        let mut retained = ReusableDns::new(
            a.reuse_identity(),
            a.dns_payload().to_vec(),
            NOW + 60_000,
            NOW,
            now,
        );
        assert!(
            retained
                .accept_response(&response(aaaa.dns_payload()), NOW + 1, now)
                .is_err()
        );
        assert!(retained.pending.is_some());
        retained
            .accept_response(&response(a.dns_payload()), NOW + 1, now)
            .unwrap();
        assert!(retained.compatible(&aaaa, NOW + 2, now));
        retained.sent(aaaa.dns_payload(), now);
        assert!(
            retained
                .accept_response(&response(a.dns_payload()), NOW + 3, now)
                .is_err()
        );
        retained
            .accept_response(&response(aaaa.dns_payload()), NOW + 3, now)
            .unwrap();
        assert_eq!(retained.requests, 2);
        for (source, resolver) in [
            ("192.0.2.10:42001", "9.9.9.9:53"),
            ("192.0.2.11:42000", "9.9.9.9:53"),
            ("192.0.2.10:42000", "8.8.8.8:53"),
        ] {
            assert!(!retained.compatible(
                &ingress(query(1, 3), source, resolver, &policy),
                NOW + 4,
                now
            ));
        }
        let changed = self::policy(true);
        let next = ingress(query(1, 3), "192.0.2.10:42000", "9.9.9.9:53", &changed);
        assert!(!retained.compatible(&next, NOW + 4, now));
        assert!(!a.is_current(&changed, NOW + 4));
        assert!(!a.is_current(&policy, NOW + 60_000));
    }

    #[test]
    fn dns_reuse_original_expiry_idle_and_request_cap_never_extend() {
        let policy = policy(false);
        let now = Instant::now();
        let a = ingress(query(1, 1), "192.0.2.10:42000", "9.9.9.9:53", &policy);
        let mut retained = ReusableDns::new(
            a.reuse_identity(),
            a.dns_payload().to_vec(),
            NOW + 60_000,
            NOW,
            now,
        );
        assert!(retained.expired(NOW + 30_000, now + IDLE));
        retained
            .accept_response(
                &response(a.dns_payload()),
                NOW + 20_000,
                now + Duration::from_secs(20),
            )
            .unwrap();
        retained.sent(a.dns_payload(), now + Duration::from_secs(40));
        retained
            .accept_response(
                &response(a.dns_payload()),
                NOW + 41_000,
                now + Duration::from_secs(41),
            )
            .unwrap();
        assert_eq!(retained.deadline(), now + Duration::from_secs(60));
        assert!(retained.expired(NOW + 60_000, now + Duration::from_secs(59)));
        assert!(retained.expired(NOW + 50_000, now + Duration::from_secs(60)));
        while retained.requests < MAX_DNS_ASSOCIATION_QUERIES {
            retained.sent(a.dns_payload(), now + Duration::from_secs(42));
            assert!(!retained.expired(NOW + 42_000, now + Duration::from_secs(42)));
            retained
                .accept_response(
                    &response(a.dns_payload()),
                    NOW + 42_000,
                    now + Duration::from_secs(42),
                )
                .unwrap();
        }
        assert!(retained.expired(NOW + 42_000, now + Duration::from_secs(42)));
        assert!(!retained.compatible(&a, NOW + 42_000, now + Duration::from_secs(42)));
    }
}
