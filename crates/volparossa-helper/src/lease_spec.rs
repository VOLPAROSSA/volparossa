//! Secret-free, helper-derived identity for one v3 `WireGuard` endpoint lease.

use std::net::Ipv6Addr;

use thiserror::Error;
use volparossa_routing::{ContextRole, WireguardRole};
use volparossa_wireguard::{EndpointRole, interface_name, overlay_prefix};

pub(crate) const DURABLE_WIREGUARD_ALIAS_PREFIX: &str = "volparossa:wireguard:ownership-v1:";
const DURABLE_WIREGUARD_MARKER_HEX_BYTES: usize = 64;

/// A route, path or role did not describe one endpoint in the two-link topology.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid WireGuard lease topology")]
pub(crate) struct LeaseSpecError;

/// Exact local identity derived without an agent-selected key, address, prefix or interface name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireguardLeaseSpec {
    path_id: u8,
    role: i32,
    interface: String,
    local_address: Ipv6Addr,
    peer_address: Ipv6Addr,
}

impl WireguardLeaseSpec {
    /// Derive one local endpoint solely from authenticated route topology.
    pub(crate) fn derive(
        route_context_id: [u8; 16],
        context_role: ContextRole,
        path_id: u32,
        role: i32,
    ) -> Result<Self, LeaseSpecError> {
        let path_id = u8::try_from(path_id).map_err(|_| LeaseSpecError)?;
        let endpoint_role = allowed_endpoint_role(context_role, role).ok_or(LeaseSpecError)?;
        let prefix = overlay_prefix(route_context_id, path_id).map_err(|_| LeaseSpecError)?;
        let (local_host, peer_host): (u16, u16) = match endpoint_role {
            EndpointRole::Client => (1, 2),
            EndpointRole::RelayClient => (2, 1),
            EndpointRole::RelayExit => (3, 4),
            EndpointRole::Exit => (4, 3),
        };
        let mut local = prefix.network().octets();
        local[14..].copy_from_slice(&local_host.to_be_bytes());
        let mut peer = prefix.network().octets();
        peer[14..].copy_from_slice(&peer_host.to_be_bytes());
        let interface =
            interface_name(route_context_id, path_id, endpoint_role).map_err(|_| LeaseSpecError)?;
        if !safe_interface_name(&interface) {
            return Err(LeaseSpecError);
        }
        Ok(Self {
            path_id,
            role,
            interface,
            local_address: Ipv6Addr::from(local),
            peer_address: Ipv6Addr::from(peer),
        })
    }

    /// Context-local path and endpoint role.
    pub(crate) const fn key(&self) -> (u8, i32) {
        (self.path_id, self.role)
    }

    /// Fixed helper-derived interface name.
    pub(crate) fn interface(&self) -> &str {
        &self.interface
    }

    /// Exact locally derived overlay host address.
    pub(crate) const fn local_address(&self) -> Ipv6Addr {
        self.local_address
    }

    /// Exact topology-derived address of the opposite endpoint on this link.
    pub(crate) const fn peer_address(&self) -> Ipv6Addr {
        self.peer_address
    }

    /// Verify one public ownership marker against this exact derived interface.
    ///
    /// The marker is correlation evidence received only over the authenticated private worker
    /// channel. It is not durable journal authority.
    pub(crate) fn matches_ownership_alias(&self, alias: &str) -> bool {
        let Some(suffix) = alias.strip_prefix(DURABLE_WIREGUARD_ALIAS_PREFIX) else {
            return false;
        };
        let Some(digest) = suffix.strip_prefix(self.interface()) else {
            return false;
        };
        let Some(digest) = digest.strip_prefix(':') else {
            return false;
        };
        digest.len() == DURABLE_WIREGUARD_MARKER_HEX_BYTES
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }
}

/// Validate the fixed bounded grammar before a worker has enough context to derive the interface.
pub(crate) fn ownership_alias_has_valid_shape(alias: &str) -> bool {
    let Some(suffix) = alias.strip_prefix(DURABLE_WIREGUARD_ALIAS_PREFIX) else {
        return false;
    };
    let Some((interface, digest)) = suffix.split_once(':') else {
        return false;
    };
    safe_interface_name(interface)
        && digest.len() == DURABLE_WIREGUARD_MARKER_HEX_BYTES
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn allowed_endpoint_role(context: ContextRole, role: i32) -> Option<EndpointRole> {
    match (context, WireguardRole::try_from(role).ok()?) {
        (ContextRole::Client, WireguardRole::Client) => Some(EndpointRole::Client),
        (ContextRole::Relay, WireguardRole::RelayClient) => Some(EndpointRole::RelayClient),
        (ContextRole::Relay, WireguardRole::RelayExit) => Some(EndpointRole::RelayExit),
        (ContextRole::Exit, WireguardRole::Exit) => Some(EndpointRole::Exit),
        _ => None,
    }
}

fn safe_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_exact_and_rejects_cross_role_or_invalid_path() {
        let route = [7; 16];
        let client =
            WireguardLeaseSpec::derive(route, ContextRole::Client, 1, WireguardRole::Client as i32)
                .expect("client lease");
        assert_eq!(client.key(), (1, WireguardRole::Client as i32));
        assert!(client.interface().starts_with("vpc1"));
        assert_eq!(client.local_address().octets()[14..], [0, 1]);
        assert_eq!(client.peer_address().octets()[14..], [0, 2]);

        assert!(
            WireguardLeaseSpec::derive(route, ContextRole::Client, 1, WireguardRole::Exit as i32,)
                .is_err()
        );
        assert!(
            WireguardLeaseSpec::derive(
                route,
                ContextRole::Client,
                0,
                WireguardRole::Client as i32,
            )
            .is_err()
        );
    }

    #[test]
    fn peer_derivation_is_exhaustive_symmetric_and_prefix_bound() {
        let route = [7; 16];
        let cases = [
            (ContextRole::Client, WireguardRole::Client, [0, 1], [0, 2]),
            (
                ContextRole::Relay,
                WireguardRole::RelayClient,
                [0, 2],
                [0, 1],
            ),
            (ContextRole::Relay, WireguardRole::RelayExit, [0, 3], [0, 4]),
            (ContextRole::Exit, WireguardRole::Exit, [0, 4], [0, 3]),
        ];
        let specifications = cases.map(|(context_role, role, local_host, peer_host)| {
            let specification = WireguardLeaseSpec::derive(route, context_role, 1, role as i32)
                .expect("valid endpoint lease");
            let local = specification.local_address().octets();
            let peer = specification.peer_address().octets();
            assert_eq!(local[..14], peer[..14]);
            assert_eq!(local[14..], local_host);
            assert_eq!(peer[14..], peer_host);
            specification
        });

        assert_eq!(
            specifications[0].peer_address(),
            specifications[1].local_address()
        );
        assert_eq!(
            specifications[1].peer_address(),
            specifications[0].local_address()
        );
        assert_eq!(
            specifications[2].peer_address(),
            specifications[3].local_address()
        );
        assert_eq!(
            specifications[3].peer_address(),
            specifications[2].local_address()
        );
    }

    #[test]
    fn ownership_alias_is_bounded_and_bound_to_the_exact_derived_interface() {
        let specification = WireguardLeaseSpec::derive(
            [7; 16],
            ContextRole::Client,
            1,
            WireguardRole::Client as i32,
        )
        .expect("client lease");
        let alias = format!(
            "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{}",
            specification.interface(),
            "ab".repeat(32)
        );
        assert!(ownership_alias_has_valid_shape(&alias));
        assert!(specification.matches_ownership_alias(&alias));

        let substituted = alias.replacen(specification.interface(), "vpc999999999", 1);
        assert!(ownership_alias_has_valid_shape(&substituted));
        assert!(!specification.matches_ownership_alias(&substituted));
        assert!(!ownership_alias_has_valid_shape(&format!(
            "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{}",
            specification.interface(),
            "AB".repeat(32)
        )));
        assert!(!ownership_alias_has_valid_shape(&format!(
            "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{}0",
            specification.interface(),
            "ab".repeat(32)
        )));
    }
}
