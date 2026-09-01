//! Production adoption of helper-owned MPTCP transport capabilities.

use std::{collections::BTreeSet, io, net::SocketAddr};

use thiserror::Error;
use volparossa_mptcp::{MptcpListener, MptcpStream};
use volparossa_routing::{
    AddMptcpEndpoint, MptcpEndpointMode, RemoveMptcpEndpoint, TransportSocketAddress,
    TransportSocketKind, WireguardRole,
};

use crate::helper::{AcquiredTransportSocket, HelperClient, HelperClientError};

/// A genuinely negotiated client MPTCP stream plus the exact helper-owned selected paths.
pub struct ClientMptcpTransport {
    stream: MptcpStream,
    route_context_id: Vec<u8>,
    context_handle: Vec<u8>,
    active_paths: Vec<u32>,
}

impl ClientMptcpTransport {
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
        })
    }

    /// Borrows the adopted, genuinely negotiated MPTCP stream.
    #[must_use]
    pub const fn stream(&self) -> &MptcpStream {
        &self.stream
    }

    /// Removes all selected endpoints before releasing the adopted stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the helper cannot remove an exact owned endpoint.
    pub async fn shutdown(self, helper: &HelperClient) -> Result<(), MptcpTransportError> {
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
}
