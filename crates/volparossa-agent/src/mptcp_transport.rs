//! Production adoption of helper-owned MPTCP transport capabilities.

use std::{collections::BTreeSet, io, net::SocketAddr};

use sha2::{Digest, Sha256};
use thiserror::Error;
use volparossa_discovery::ExitMptcpSessionSignal as DiscoveryExitMptcpSessionSignal;
use volparossa_mptcp::{MptcpListener, MptcpStream};
use volparossa_routing::{
    AcquireTransportSocket, AddMptcpEndpoint, MptcpEndpointMode, RemoveMptcpEndpoint,
    TransportSocketAddress, TransportSocketKind, WireguardRole,
};
use volparossa_wireguard::{WireGuardError, overlay_addresses};

use crate::helper::{AcquiredTransportSocket, HelperClient, HelperClientError};

/// Route-local Exit listener port shared by the authenticated readiness signal and helper request.
pub(crate) const PRODUCTION_MPTCP_EXIT_PORT: u16 = 44_443;
const MAXIMUM_EXIT_CERTIFICATE_DER_BYTES: usize = 64 * 1_024;

/// A genuinely negotiated client MPTCP stream plus the exact helper-owned selected paths.
pub struct ClientMptcpTransport {
    stream: MptcpStream,
    route_context_id: Vec<u8>,
    context_handle: Vec<u8>,
    active_paths: Vec<u32>,
    certificate_der: Option<Vec<u8>>,
}

/// Endpoint-removal capability retained after the connected MPTCP stream enters TLS.
#[must_use = "active MPTCP endpoints must be removed after the TLS flow"]
pub(crate) struct ClientMptcpEndpointCleanup {
    route_context_id: Vec<u8>,
    context_handle: Vec<u8>,
    active_paths: Vec<u32>,
}

impl ClientMptcpEndpointCleanup {
    pub(crate) async fn shutdown(self, helper: &HelperClient) -> Result<(), MptcpTransportError> {
        remove_paths(
            helper,
            &self.route_context_id,
            &self.context_handle,
            &self.active_paths,
        )
        .await
    }
}

/// Exact Exit listener tuple received through the authenticated route control plane.
///
/// Construction is crate-private so an untrusted local caller cannot turn an arbitrary overlay
/// tuple into transport authority. The production Exit response verifier is the intended owner of
/// this constructor once its wire signal is connected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExitMptcpListenerSignal {
    route_context_id: [u8; 16],
    port: u16,
    selected_path_ids: Vec<u32>,
    certificate_der: Vec<u8>,
}

impl ExitMptcpListenerSignal {
    pub(crate) fn new(
        route_context_id: [u8; 16],
        port: u16,
        paths: impl IntoIterator<Item = u32>,
        certificate_der: Vec<u8>,
    ) -> Result<Self, MptcpTransportError> {
        if port == 0
            || certificate_der.is_empty()
            || certificate_der.len() > MAXIMUM_EXIT_CERTIFICATE_DER_BYTES
        {
            return Err(MptcpTransportError::InvalidMetadata);
        }
        let selected_path_ids = selected_path_ids(paths)?;
        for path_id in &selected_path_ids {
            let path_id =
                u8::try_from(*path_id).map_err(|_| MptcpTransportError::InvalidMetadata)?;
            overlay_addresses(route_context_id, path_id)?;
        }
        Ok(Self {
            route_context_id,
            port,
            selected_path_ids,
            certificate_der,
        })
    }

    /// Convert only a fully validated authenticated discovery readiness signal.
    pub(crate) fn try_from_discovery(
        signal: &DiscoveryExitMptcpSessionSignal,
        expected_certificate_sha256: &[u8],
    ) -> Result<Self, MptcpTransportError> {
        signal
            .validate()
            .map_err(|_| MptcpTransportError::InvalidMetadata)?;
        let route_context_id = signal
            .route_context_id()
            .try_into()
            .map_err(|_| MptcpTransportError::InvalidMetadata)?;
        let port = u16::try_from(signal.listener_port())
            .map_err(|_| MptcpTransportError::InvalidMetadata)?;
        if expected_certificate_sha256.len() != 32
            || Sha256::digest(signal.certificate_der()).as_slice() != expected_certificate_sha256
        {
            return Err(MptcpTransportError::InvalidMetadata);
        }
        Self::new(
            route_context_id,
            port,
            signal.selected_path_ids().iter().copied(),
            signal.certificate_der().to_vec(),
        )
    }

    pub(crate) const fn route_context_id(&self) -> [u8; 16] {
        self.route_context_id
    }

    pub(crate) fn path_id(&self) -> u32 {
        self.selected_path_ids[0]
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn selected_path_ids(&self) -> &[u32] {
        &self.selected_path_ids
    }

    #[allow(
        dead_code,
        reason = "the Client TLS activation consumes these digest-bound roots in the next slice"
    )]
    pub(crate) fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}

impl ClientMptcpTransport {
    /// Acquire and adopt the exact connected MPTCP descriptor for a verified Exit signal.
    ///
    /// The helper creates the socket inside the committed Client route namespace. Both endpoint
    /// addresses are derived from the same route/path overlay, so this operation cannot connect to
    /// an Exit underlay address or bypass the selected Relay.
    pub(crate) async fn acquire_and_activate(
        helper: &HelperClient,
        signal: ExitMptcpListenerSignal,
        context_handle: Vec<u8>,
        local_port: u16,
    ) -> Result<Self, MptcpTransportError> {
        let selected_paths = signal.selected_path_ids.clone();
        let certificate_der = signal.certificate_der.clone();
        let request = client_acquire_request(&signal, context_handle.clone(), local_port)?;
        let acquired = helper.acquire_transport_socket(request).await?;
        let mut transport = Self::activate(
            helper,
            acquired,
            signal.route_context_id.to_vec(),
            context_handle,
            selected_paths,
        )
        .await?;
        transport.certificate_der = Some(certificate_der);
        Ok(transport)
    }

    /// Adopts a committed helper descriptor and registers at least two exact selected paths.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid capability metadata, fewer than two paths, a helper endpoint
    /// refusal, or a descriptor that is not a genuinely negotiated MPTCP stream.
    pub async fn activate(
        helper: &HelperClient,
        acquired: AcquiredTransportSocket,
        route_context_id: Vec<u8>,
        context_handle: Vec<u8>,
        selected_paths: impl IntoIterator<Item = u32>,
    ) -> Result<Self, MptcpTransportError> {
        let paths = selected_path_ids(selected_paths)?;
        let (descriptor, metadata) = acquired.into_parts();
        if metadata.role != WireguardRole::Client as i32
            || metadata.descriptor_kind != TransportSocketKind::MptcpConnected as i32
        {
            return Err(MptcpTransportError::InvalidMetadata);
        }
        let local = socket_address(metadata.local.as_ref())?;
        let remote = socket_address(metadata.remote.as_ref())?;
        let stream = MptcpStream::from_connected_owned_fd(descriptor, local, remote)?;
        let mut active_paths = Vec::with_capacity(paths.len());
        for path_id in paths {
            let request = AddMptcpEndpoint {
                route_context_id: route_context_id.clone(),
                context_handle: context_handle.clone(),
                path_id,
                mode: MptcpEndpointMode::Subflow as i32,
                backup: false,
            };
            if let Err(error) = helper.add_mptcp_endpoint(request).await {
                rollback_paths(helper, &route_context_id, &context_handle, &active_paths).await;
                return Err(MptcpTransportError::Helper(error));
            }
            active_paths.push(path_id);
        }
        stream.require_negotiated()?;
        Ok(Self {
            stream,
            route_context_id,
            context_handle,
            active_paths,
            certificate_der: None,
        })
    }

    /// Borrows the adopted, genuinely negotiated MPTCP stream.
    #[must_use]
    pub const fn stream(&self) -> &MptcpStream {
        &self.stream
    }

    /// Consume the connected stream into TLS while retaining exact endpoint cleanup authority.
    pub(crate) fn into_tls_parts(
        self,
    ) -> Result<(MptcpStream, Vec<u8>, ClientMptcpEndpointCleanup), MptcpTransportError> {
        let certificate_der = self
            .certificate_der
            .ok_or(MptcpTransportError::InvalidMetadata)?;
        Ok((
            self.stream,
            certificate_der,
            ClientMptcpEndpointCleanup {
                route_context_id: self.route_context_id,
                context_handle: self.context_handle,
                active_paths: self.active_paths,
            },
        ))
    }

    /// Removes all selected endpoints before releasing the adopted stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the helper cannot remove an exact owned endpoint.
    pub async fn shutdown(self, helper: &HelperClient) -> Result<(), MptcpTransportError> {
        remove_paths(
            helper,
            &self.route_context_id,
            &self.context_handle,
            &self.active_paths,
        )
        .await
    }
}

/// A helper-owned Exit listener plus its exact MPTCP path announcements.
#[allow(
    dead_code,
    reason = "the standard Exit responder will retain this owner after signalling is connected"
)]
pub(crate) struct ExitMptcpTransport {
    listener: MptcpListener,
    route_context_id: Vec<u8>,
    context_handle: Vec<u8>,
    active_paths: Vec<u32>,
}

#[allow(
    dead_code,
    reason = "the standard Exit responder will retain this owner after signalling is connected"
)]
impl ExitMptcpTransport {
    /// Acquire the real `IPPROTO_MPTCP` listener inside a committed Exit route namespace.
    pub(crate) async fn acquire_and_activate(
        helper: &HelperClient,
        signal: ExitMptcpListenerSignal,
        context_handle: Vec<u8>,
    ) -> Result<Self, MptcpTransportError> {
        let paths = signal.selected_path_ids.clone();
        let request = exit_acquire_request(&signal, context_handle.clone())?;
        let acquired = helper.acquire_transport_socket(request).await?;
        let listener = adopt_exit_listener(acquired)?;
        let mut active_paths = Vec::with_capacity(paths.len());
        for path_id in paths {
            let request = AddMptcpEndpoint {
                route_context_id: signal.route_context_id.to_vec(),
                context_handle: context_handle.clone(),
                path_id,
                mode: MptcpEndpointMode::Signal as i32,
                backup: false,
            };
            if let Err(error) = helper.add_mptcp_endpoint(request).await {
                rollback_paths(
                    helper,
                    &signal.route_context_id,
                    &context_handle,
                    &active_paths,
                )
                .await;
                return Err(MptcpTransportError::Helper(error));
            }
            active_paths.push(path_id);
        }
        Ok(Self {
            listener,
            route_context_id: signal.route_context_id.to_vec(),
            context_handle,
            active_paths,
        })
    }

    /// Borrow the bound real MPTCP listener.
    pub(crate) const fn listener(&self) -> &MptcpListener {
        &self.listener
    }

    /// Remove every exact Exit endpoint before releasing the listener.
    pub(crate) async fn shutdown(self, helper: &HelperClient) -> Result<(), MptcpTransportError> {
        for path_id in self.active_paths.iter().rev().copied() {
            helper
                .remove_mptcp_endpoint(RemoveMptcpEndpoint {
                    route_context_id: self.route_context_id.clone(),
                    context_handle: self.context_handle.clone(),
                    path_id,
                })
                .await?;
        }
        Ok(())
    }
}

/// Adopts an exact committed Exit MPTCP listener capability.
///
/// # Errors
///
/// Returns an error when the capability metadata or adopted listener descriptor is invalid.
pub fn adopt_exit_listener(
    acquired: AcquiredTransportSocket,
) -> Result<MptcpListener, MptcpTransportError> {
    let (descriptor, metadata) = acquired.into_parts();
    if metadata.role != WireguardRole::Exit as i32
        || metadata.descriptor_kind != TransportSocketKind::MptcpListener as i32
        || metadata.remote.is_some()
    {
        return Err(MptcpTransportError::InvalidMetadata);
    }
    let local = socket_address(metadata.local.as_ref())?;
    MptcpListener::from_bound_owned_fd(descriptor, local).map_err(Into::into)
}

async fn rollback_paths(
    helper: &HelperClient,
    route_context_id: &[u8],
    context_handle: &[u8],
    active_paths: &[u32],
) {
    for path_id in active_paths.iter().rev().copied() {
        let _ = helper
            .remove_mptcp_endpoint(RemoveMptcpEndpoint {
                route_context_id: route_context_id.to_vec(),
                context_handle: context_handle.to_vec(),
                path_id,
            })
            .await;
    }
}

async fn remove_paths(
    helper: &HelperClient,
    route_context_id: &[u8],
    context_handle: &[u8],
    active_paths: &[u32],
) -> Result<(), MptcpTransportError> {
    for path_id in active_paths.iter().rev().copied() {
        helper
            .remove_mptcp_endpoint(RemoveMptcpEndpoint {
                route_context_id: route_context_id.to_vec(),
                context_handle: context_handle.to_vec(),
                path_id,
            })
            .await?;
    }
    Ok(())
}

fn socket_address(
    value: Option<&TransportSocketAddress>,
) -> Result<SocketAddr, MptcpTransportError> {
    let value = value.ok_or(MptcpTransportError::InvalidMetadata)?;
    let port = u16::try_from(value.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(MptcpTransportError::InvalidMetadata)?;
    let address = match value.address.as_slice() {
        bytes if bytes.len() == 4 => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| MptcpTransportError::InvalidMetadata)?,
        )),
        bytes if bytes.len() == 16 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| MptcpTransportError::InvalidMetadata)?,
        )),
        _ => return Err(MptcpTransportError::InvalidMetadata),
    };
    if address.is_unspecified() || address.is_multicast() {
        return Err(MptcpTransportError::InvalidMetadata);
    }
    Ok(SocketAddr::new(address, port))
}

fn client_acquire_request(
    signal: &ExitMptcpListenerSignal,
    context_handle: Vec<u8>,
    local_port: u16,
) -> Result<AcquireTransportSocket, MptcpTransportError> {
    if local_port == 0 || local_port == signal.port {
        return Err(MptcpTransportError::InvalidMetadata);
    }
    let path_id =
        u8::try_from(signal.path_id()).map_err(|_| MptcpTransportError::InvalidMetadata)?;
    let addresses = overlay_addresses(signal.route_context_id, path_id)?;
    Ok(AcquireTransportSocket {
        route_context_id: signal.route_context_id.to_vec(),
        context_handle,
        path_id: signal.path_id(),
        role: WireguardRole::Client as i32,
        descriptor_kind: TransportSocketKind::MptcpConnected as i32,
        expected_local: Some(transport_address(addresses.client, local_port)),
        expected_remote: Some(transport_address(addresses.exit, signal.port)),
    })
}

#[allow(
    dead_code,
    reason = "the standard Exit responder calls this through ExitMptcpTransport"
)]
fn exit_acquire_request(
    signal: &ExitMptcpListenerSignal,
    context_handle: Vec<u8>,
) -> Result<AcquireTransportSocket, MptcpTransportError> {
    let path_id =
        u8::try_from(signal.path_id()).map_err(|_| MptcpTransportError::InvalidMetadata)?;
    let addresses = overlay_addresses(signal.route_context_id, path_id)?;
    Ok(AcquireTransportSocket {
        route_context_id: signal.route_context_id.to_vec(),
        context_handle,
        path_id: signal.path_id(),
        role: WireguardRole::Exit as i32,
        descriptor_kind: TransportSocketKind::MptcpListener as i32,
        expected_local: Some(transport_address(addresses.exit, signal.port)),
        expected_remote: None,
    })
}

fn transport_address(address: std::net::Ipv6Addr, port: u16) -> TransportSocketAddress {
    TransportSocketAddress {
        address: address.octets().to_vec(),
        port: u32::from(port),
    }
}

fn selected_path_ids(
    paths: impl IntoIterator<Item = u32>,
) -> Result<Vec<u32>, MptcpTransportError> {
    let paths = paths.into_iter().collect::<BTreeSet<_>>();
    if paths.len() < 2 || paths.iter().any(|path| !(1..=8).contains(path)) {
        return Err(MptcpTransportError::InsufficientPaths);
    }
    Ok(paths.into_iter().collect())
}

/// Failure to adopt or configure a helper-owned MPTCP capability.
#[derive(Debug, Error)]
pub enum MptcpTransportError {
    /// The helper descriptor metadata did not describe the required exact capability.
    #[error("helper MPTCP metadata is invalid")]
    InvalidMetadata,
    /// Fewer than two distinct committed paths were selected.
    #[error("MPTCP requires at least two distinct committed paths")]
    InsufficientPaths,
    /// The privileged helper rejected an exact endpoint mutation.
    #[error("helper MPTCP endpoint operation failed")]
    Helper(#[from] HelperClientError),
    /// The route/path overlay tuple was not canonical.
    #[error("MPTCP overlay scope is invalid")]
    Topology(#[from] WireGuardError),
    /// The kernel rejected adoption or validation of the MPTCP descriptor.
    #[error("kernel rejected the helper-owned MPTCP descriptor")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_paths_are_distinct_bounded_and_canonical() {
        assert_eq!(selected_path_ids([3, 1, 3, 2]).expect("paths"), [1, 2, 3]);
        assert!(selected_path_ids([1]).is_err());
        assert!(selected_path_ids([1, 9]).is_err());
        assert!(selected_path_ids([0, 1]).is_err());
    }

    #[test]
    fn helper_socket_metadata_rejects_unsafe_addresses_and_ports() {
        let valid = TransportSocketAddress {
            address: "fd76:6f6c:7061::1"
                .parse::<std::net::Ipv6Addr>()
                .expect("IPv6")
                .octets()
                .to_vec(),
            port: 44_443,
        };
        assert_eq!(
            socket_address(Some(&valid)).expect("address").port(),
            44_443
        );

        let mut invalid = valid;
        invalid.address = vec![0; 16];
        assert!(socket_address(Some(&invalid)).is_err());
        invalid.address = vec![127, 0, 0, 1];
        invalid.port = 0;
        assert!(socket_address(Some(&invalid)).is_err());
    }

    #[test]
    fn client_and_exit_acquisition_share_one_canonical_listener_signal() {
        let route_context_id = [71; 16];
        let signal = ExitMptcpListenerSignal::new(route_context_id, 44_443, [2, 3], vec![0x30, 1])
            .expect("signal");
        let client = client_acquire_request(&signal, vec![9; 32], 52_001).expect("client");
        let exit = exit_acquire_request(&signal, vec![8; 32]).expect("exit");
        let addresses = overlay_addresses(route_context_id, 2).expect("overlay");

        assert_eq!(client.route_context_id, route_context_id);
        assert_eq!(client.path_id, 2);
        assert_eq!(client.role, WireguardRole::Client as i32);
        assert_eq!(
            client.expected_local,
            Some(transport_address(addresses.client, 52_001))
        );
        assert_eq!(
            client.expected_remote,
            Some(transport_address(addresses.exit, 44_443))
        );
        assert_eq!(exit.route_context_id, route_context_id);
        assert_eq!(exit.path_id, 2);
        assert_eq!(exit.role, WireguardRole::Exit as i32);
        assert_eq!(
            exit.expected_local,
            Some(transport_address(addresses.exit, 44_443))
        );
        assert!(exit.expected_remote.is_none());
    }

    #[test]
    fn listener_signal_and_client_source_port_fail_closed() {
        assert!(ExitMptcpListenerSignal::new([0; 16], 44_443, [1, 2], vec![1]).is_err());
        assert!(ExitMptcpListenerSignal::new([7; 16], 44_443, [0, 1], vec![1]).is_err());
        assert!(ExitMptcpListenerSignal::new([7; 16], 0, [1, 2], vec![1]).is_err());
        let signal =
            ExitMptcpListenerSignal::new([7; 16], 44_443, [1, 2], vec![0x30, 1]).expect("signal");
        assert!(client_acquire_request(&signal, vec![1; 32], 0).is_err());
        assert!(client_acquire_request(&signal, vec![1; 32], 44_443).is_err());
    }

    #[test]
    fn discovery_signal_retains_only_digest_bound_certificate_and_exact_set() {
        let certificate_der = vec![0x30, 0x82, 1, 2, 3];
        let digest = Sha256::digest(&certificate_der);
        let wire = DiscoveryExitMptcpSessionSignal::new(
            [5; 16],
            [7; 16],
            PRODUCTION_MPTCP_EXIT_PORT,
            vec![1, 3],
            certificate_der.clone(),
        )
        .expect("wire signal");
        let local = ExitMptcpListenerSignal::try_from_discovery(&wire, digest.as_slice())
            .expect("digest-bound signal");
        assert_eq!(local.selected_path_ids(), [1, 3]);
        assert_eq!(local.certificate_der(), certificate_der);
        assert!(ExitMptcpListenerSignal::try_from_discovery(&wire, &[9; 32]).is_err());
    }
}
