//! Process-owned client ingress capabilities.

#![allow(
    dead_code,
    reason = "the adjacent production UDP route actor consumes this complete ingress activation seam"
)]

use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4},
};

use rand_core::{OsRng, RngCore as _};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use volparossa_linux_uapi::{
    IngressSocketFamily as KernelIngressSocketFamily, IngressSocketKind as KernelIngressSocketKind,
    receive_udp_with_original_destination,
};
use volparossa_policy::{PolicyError, TransportProtocol, VerifiedManifest};
use volparossa_protocol::{ReplayCache, TimePolicy};
use volparossa_reservation::{CoordinatorError, ReservationCoordinator};
use volparossa_routing::{PrepareClientIngress, REQUIRED_INGRESS_SOCKETS};
use volparossa_udp::{
    AuthorizedUdpFlow, MAX_UDP_PAYLOAD_BYTES, UdpAuthorizationScope, UdpError,
    VerifiedSingleRelayPath,
};

use crate::{
    helper::{
        AcquiredIngressSocket, ActiveClientIngress, ClientIngressSocketFamily,
        ClientIngressSocketIdentity, ClientIngressSocketKind, HelperClient, HelperClientError,
        PreparedClientIngress,
    },
    unix_seconds,
};

const INGRESS_SETUP_TTL_SECONDS: u64 = 30;
const INGRESS_HARD_TTL_SECONDS: u64 = 15 * 60;
const INGRESS_UDP_IDLE_TIMEOUT_MS: u32 = 30_000;
const INGRESS_UDP_FLOW_TTL_MS: u64 = 60_000;

const IPV4_TRANSPARENT_UDP: ClientIngressSocketIdentity = ClientIngressSocketIdentity::new(
    ClientIngressSocketKind::TransparentUdp,
    ClientIngressSocketFamily::Ipv4,
);

/// Affine owner of the complete activated ingress descriptor set.
pub(crate) struct ClientIngressRuntime {
    helper: HelperClient,
    active: ActiveClientIngress,
}

impl ClientIngressRuntime {
    pub(crate) async fn start(helper: HelperClient) -> Result<Self, ClientIngressRuntimeError> {
        let client_runtime_id = random_runtime_id()?;
        let now = unix_seconds();
        let mut prepared = helper
            .prepare_client_ingress(PrepareClientIngress {
                client_runtime_id: client_runtime_id.to_vec(),
                setup_expires_at_unix: now
                    .checked_add(INGRESS_SETUP_TTL_SECONDS)
                    .ok_or(ClientIngressRuntimeError::Clock)?,
                hard_expires_at_unix: now
                    .checked_add(INGRESS_HARD_TTL_SECONDS)
                    .ok_or(ClientIngressRuntimeError::Clock)?,
            })
            .await
            .map_err(ClientIngressRuntimeError::Prepare)?;

        let identities = prepared.socket_identities().collect::<Vec<_>>();
        let mut sockets = Vec::with_capacity(REQUIRED_INGRESS_SOCKETS);
        for identity in identities {
            match helper.acquire_ingress_socket(&mut prepared, identity).await {
                Ok(socket) => sockets.push(socket),
                Err(error) => {
                    return Err(cleanup_prepared_failure(
                        &helper,
                        &prepared,
                        ClientIngressRuntimeError::Acquire(error),
                    )
                    .await);
                }
            }
        }
        let sockets: [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS] = match sockets.try_into() {
            Ok(sockets) => sockets,
            Err(_sockets) => {
                return Err(cleanup_prepared_failure(
                    &helper,
                    &prepared,
                    ClientIngressRuntimeError::IncompleteDescriptorSet,
                )
                .await);
            }
        };
        let active = match helper.activate_client_ingress(prepared, sockets).await {
            Ok(active) => active,
            Err(failure) => {
                let (error, prepared, _sockets) = failure.into_parts();
                return Err(cleanup_prepared_failure(
                    &helper,
                    &prepared,
                    ClientIngressRuntimeError::Activate(error),
                )
                .await);
            }
        };
        Ok(Self { helper, active })
    }

    /// Try to receive one IPv4 application datagram and bind its immutable destination to policy.
    ///
    /// The descriptor is nonblocking. `WouldBlock` is returned unchanged so an actor can wait for
    /// readiness without inventing a destination. The payload and destination enter the returned
    /// affine value only after exact ORIGDST evidence and the active whitelist both agree.
    pub(crate) fn try_receive_ipv4_udp(
        &self,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<PolicyAuthorizedUdpIngress, ClientIngressUdpError> {
        let socket = self
            .active
            .socket(IPV4_TRANSPARENT_UDP)
            .ok_or(ClientIngressUdpError::DescriptorUnavailable)?;
        let SocketAddr::V4(local) = socket.local_address() else {
            return Err(ClientIngressUdpError::DescriptorUnavailable);
        };
        let mut payload = vec![0_u8; MAX_UDP_PAYLOAD_BYTES];
        let received = receive_udp_with_original_destination(
            &socket.descriptor(),
            KernelIngressSocketKind::TransparentUdp,
            KernelIngressSocketFamily::Ipv4,
            local.port(),
            &mut payload,
        )
        .map_err(ClientIngressUdpError::Receive)?;
        payload.truncate(received.bytes());
        PolicyAuthorizedUdpIngress::authorize(
            received.source(),
            received.original_destination(),
            payload,
            policy,
            now_ms,
        )
    }

    pub(crate) async fn shutdown(self) -> Result<(), ClientIngressRuntimeError> {
        self.helper
            .destroy_active_client_ingress(&self.active)
            .await
            .map(|_| ())
            .map_err(ClientIngressRuntimeError::Destroy)
    }
}

/// One kernel-observed UDP datagram whose exact raw-IP tuple passed the active policy.
///
/// The destination, payload and policy binding are affine and immutable. This is deliberately not
/// yet an [`AuthorizedUdpFlow`]: that type also requires the committed route's ephemeral identity
/// and signature. [`Self::bind_to_route`] performs that second phase without accepting a mutable
/// or caller-substituted destination.
#[must_use = "a policy-authorized ingress datagram must be route-bound or dropped"]
pub(crate) struct PolicyAuthorizedUdpIngress {
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: Vec<u8>,
    policy_hash: [u8; 32],
    expires_at_ms: u64,
}

impl PolicyAuthorizedUdpIngress {
    fn authorize(
        source: SocketAddr,
        destination: SocketAddr,
        payload: Vec<u8>,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<Self, ClientIngressUdpError> {
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
            return Err(ClientIngressUdpError::AddressFamily);
        };
        policy
            .authorize_ip(
                now_ms,
                IpAddr::V4(*destination.ip()),
                TransportProtocol::Udp,
                destination.port(),
            )
            .map_err(ClientIngressUdpError::Policy)?;
        let expires_at_ms = now_ms
            .checked_add(INGRESS_UDP_FLOW_TTL_MS)
            .ok_or(ClientIngressUdpError::Clock)?
            .min(policy.expires_at_ms());
        if expires_at_ms <= now_ms {
            return Err(ClientIngressUdpError::Clock);
        }
        Ok(Self {
            source,
            destination,
            payload,
            policy_hash: *policy.policy_hash(),
            expires_at_ms,
        })
    }

    /// Sign and locally verify the exact ingress tuple against one committed single-relay path.
    ///
    /// The returned flow is the same typed [`AuthorizedUdpFlow`] consumed by the production QUIC
    /// activation seam, accompanied by its canonical client signature and original payload.
    pub(crate) fn bind_to_route(
        self,
        path: &VerifiedSingleRelayPath,
        coordinator: &ReservationCoordinator,
        policy: &VerifiedManifest,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ClientIngressUdpError> {
        if now_ms >= self.expires_at_ms
            || self.policy_hash.ct_eq(policy.policy_hash()).unwrap_u8() != 1
        {
            return Err(ClientIngressUdpError::PolicyBinding);
        }
        let signed_authorization = coordinator
            .sign_udp_ip(
                *path.route_context_id(),
                self.policy_hash,
                IpAddr::V4(*self.destination.ip()),
                self.destination.port(),
                INGRESS_UDP_IDLE_TIMEOUT_MS,
                now_ms,
                self.expires_at_ms.min(path.expires_at_ms()),
            )
            .map_err(ClientIngressUdpError::Sign)?;
        self.bind_signed_to_route(path, policy, signed_authorization, now_ms)
    }

    fn bind_signed_to_route(
        self,
        path: &VerifiedSingleRelayPath,
        policy: &VerifiedManifest,
        signed_authorization: Vec<u8>,
        now_ms: u64,
    ) -> Result<RouteAuthorizedUdpIngress, ClientIngressUdpError> {
        let mut replay = ReplayCache::new(1)
            .map_err(|error| ClientIngressUdpError::Authorization(error.into()))?;
        let flow = UdpAuthorizationScope::new(path, policy)
            .verify(
                &signed_authorization,
                now_ms,
                TimePolicy::default(),
                &mut replay,
            )
            .map_err(ClientIngressUdpError::Authorization)?;
        if !flow.matches_exact_ip_destination(SocketAddr::V4(self.destination)) {
            return Err(ClientIngressUdpError::DestinationBinding);
        }
        Ok(RouteAuthorizedUdpIngress {
            flow,
            signed_authorization,
            source: self.source,
            payload: self.payload,
        })
    }
}

/// Exact inputs needed to activate and seed one production single-relay UDP association.
#[must_use = "a route-authorized ingress datagram must be activated or dropped"]
pub(crate) struct RouteAuthorizedUdpIngress {
    flow: AuthorizedUdpFlow,
    signed_authorization: Vec<u8>,
    source: SocketAddrV4,
    payload: Vec<u8>,
}

impl RouteAuthorizedUdpIngress {
    /// Borrow the immutable flow and its exact canonical signature for QUIC activation.
    pub(crate) fn activation(&self) -> (&AuthorizedUdpFlow, &[u8]) {
        (&self.flow, &self.signed_authorization)
    }

    /// Return the application source tuple needed for reverse datagram delivery.
    pub(crate) const fn source(&self) -> SocketAddrV4 {
        self.source
    }

    /// Borrow the first intercepted payload without exposing a mutable destination tuple.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

async fn cleanup_prepared_failure(
    helper: &HelperClient,
    prepared: &PreparedClientIngress,
    original: ClientIngressRuntimeError,
) -> ClientIngressRuntimeError {
    match helper.destroy_prepared_client_ingress(prepared).await {
        Ok(_) => original,
        Err(error) => ClientIngressRuntimeError::Rollback(error),
    }
}

fn random_runtime_id() -> Result<[u8; 16], ClientIngressRuntimeError> {
    let mut runtime_id = [0; 16];
    OsRng
        .try_fill_bytes(&mut runtime_id)
        .map_err(|_| ClientIngressRuntimeError::Random)?;
    if runtime_id.iter().all(|byte| *byte == 0) {
        return Err(ClientIngressRuntimeError::Random);
    }
    Ok(runtime_id)
}

#[derive(Debug, Error)]
pub(crate) enum ClientIngressRuntimeError {
    #[error("secure client runtime identity generation failed")]
    Random,
    #[error("system clock cannot represent the client ingress deadline")]
    Clock,
    #[error("client ingress prepare failed")]
    Prepare(#[source] HelperClientError),
    #[error("client ingress descriptor acquisition failed")]
    Acquire(#[source] HelperClientError),
    #[error("client ingress descriptor set was incomplete")]
    IncompleteDescriptorSet,
    #[error("client ingress activation failed")]
    Activate(#[source] HelperClientError),
    #[error("client ingress rollback could not be confirmed")]
    Rollback(#[source] HelperClientError),
    #[error("client ingress destruction could not be confirmed")]
    Destroy(#[source] HelperClientError),
}

#[derive(Debug, Error)]
pub(crate) enum ClientIngressUdpError {
    #[error("IPv4 transparent UDP ingress descriptor is unavailable")]
    DescriptorUnavailable,
    #[error("transparent UDP receive failed")]
    Receive(#[source] io::Error),
    #[error("transparent UDP evidence used the wrong address family")]
    AddressFamily,
    #[error("transparent UDP destination was denied by policy")]
    Policy(#[source] PolicyError),
    #[error("transparent UDP authorization lifetime is invalid")]
    Clock,
    #[error("transparent UDP policy binding changed before activation")]
    PolicyBinding,
    #[error("transparent UDP flow signing failed")]
    Sign(#[source] CoordinatorError),
    #[error("transparent UDP route authorization failed")]
    Authorization(#[source] UdpError),
    #[error("signed UDP destination did not match kernel ingress evidence")]
    DestinationBinding,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
    use volparossa_protocol::{
        ReplayCache, TimePolicy, Transport, UdpFlowAuthorization, generate_nonce,
        sign_control_message,
    };
    use volparossa_test_support::{SignedRouteFixture, verified_development_manifest};
    use volparossa_udp::VerifiedSingleRelayPath;

    use super::PolicyAuthorizedUdpIngress;

    #[test]
    fn ipv4_udp_ingress_becomes_one_exact_policy_and_route_bound_flow() {
        const NOW_MS: u64 = 1_900_000_000_000;
        let destination = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        let permission =
            ProtocolPort::new(TransportProtocol::Udp, destination.port()).expect("UDP permission");
        let rule = DestinationRule::exact_ip(destination.ip(), [permission]).expect("IP rule");
        let policy = verified_development_manifest(NOW_MS, vec![rule]).expect("policy");
        let ingress = PolicyAuthorizedUdpIngress::authorize(
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 52_000)),
            destination,
            b"alpha-datagram".to_vec(),
            &policy,
            NOW_MS,
        )
        .expect("policy-authorized ingress");

        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS)
            .expect("single-relay route");
        let mut path_replay = ReplayCache::new(4).expect("path replay");
        let path = VerifiedSingleRelayPath::verify(
            fixture.exit_reservation(),
            &fixture.relay_reservations()[0],
            NOW_MS,
            TimePolicy::default(),
            &mut path_replay,
        )
        .expect("verified path");
        let nonce = generate_nonce();
        let signed = sign_control_message(
            &UdpFlowAuthorization {
                route_context_id: fixture.route_context_id().to_vec(),
                flow_id: vec![7; 16],
                client_ephemeral_id: fixture.client_session_id().to_vec(),
                hostname: String::new(),
                destination_ip: match destination.ip() {
                    IpAddr::V4(address) => address.octets().to_vec(),
                    IpAddr::V6(_) => unreachable!("IPv4 fixture"),
                },
                port: u32::from(destination.port()),
                policy_hash: policy.policy_hash().to_vec(),
                idle_timeout_ms: 30_000,
                timestamp_ms: NOW_MS,
                expires_at_ms: NOW_MS + 60_000,
                nonce: nonce.to_vec(),
            },
            fixture.client_key(),
            NOW_MS,
            NOW_MS + 60_000,
            nonce,
            TimePolicy::default(),
        )
        .expect("signed exact-IP flow");
        let bound = ingress
            .bind_signed_to_route(&path, &policy, signed, NOW_MS)
            .expect("route-bound flow");
        let (flow, signature) = bound.activation();

        assert!(flow.matches_exact_ip_destination(destination));
        assert!(!signature.is_empty());
        assert_eq!(bound.source(), "10.0.0.2:52000".parse().expect("source"));
        assert_eq!(bound.payload(), b"alpha-datagram");
    }
}
