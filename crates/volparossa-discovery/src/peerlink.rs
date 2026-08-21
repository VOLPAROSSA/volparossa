use std::{fmt, str::FromStr};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use thiserror::Error;
use url::Url;

/// Maximum textual peerlink size accepted from an untrusted paste/file.
const MAX_PEERLINK_BYTES: usize = 2_048;
const MAX_MULTIADDR_BYTES: usize = 1_024;

/// A user-importable bootstrap contact with no special authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerLink {
    peer_id: PeerId,
    address: Multiaddr,
}

impl PeerLink {
    /// Creates a peerlink after proving any embedded `/p2p` component matches `peer_id`.
    ///
    /// # Errors
    ///
    /// Returns an error when the address is empty or oversized, or when an embedded peer identity
    /// is duplicated, non-terminal, or differs from `peer_id`.
    pub fn new(peer_id: PeerId, address: Multiaddr) -> Result<Self, PeerLinkError> {
        validate_address_peer(&address, &peer_id)?;
        Ok(Self { peer_id, address })
    }

    /// Expected remote identity.
    #[must_use]
    pub const fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Original transport multiaddress without necessarily appending `/p2p`.
    #[must_use]
    pub const fn address(&self) -> &Multiaddr {
        &self.address
    }

    /// Dial address with the expected peer identity appended when absent.
    #[must_use]
    pub fn dial_address(&self) -> Multiaddr {
        let mut address = self.address.clone();
        if !address
            .iter()
            .any(|protocol| matches!(protocol, Protocol::P2p(_)))
        {
            address.push(Protocol::P2p(self.peer_id));
        }
        address
    }
}

impl fmt::Display for PeerLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address_text = self.address.to_string();
        let address = utf8_percent_encode(&address_text, NON_ALPHANUMERIC);
        write!(
            formatter,
            "volparossa://peer/{}?addr={address}",
            self.peer_id
        )
    }
}

impl FromStr for PeerLink {
    type Err = PeerLinkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.len() > MAX_PEERLINK_BYTES || !value.is_ascii() {
            return Err(PeerLinkError::Length);
        }
        let url = Url::parse(value).map_err(|_| PeerLinkError::Syntax)?;
        if url.scheme() != "volparossa"
            || url.host_str() != Some("peer")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(PeerLinkError::Syntax);
        }
        let peer_text = url.path().strip_prefix('/').ok_or(PeerLinkError::Syntax)?;
        if peer_text.is_empty() || peer_text.contains('/') {
            return Err(PeerLinkError::Syntax);
        }
        let peer_id = PeerId::from_str(peer_text).map_err(|_| PeerLinkError::PeerId)?;
        let mut address = None;
        for (key, value) in url.query_pairs() {
            if key != "addr" || address.is_some() || value.len() > 1_024 {
                return Err(PeerLinkError::Query);
            }
            address = Some(Multiaddr::from_str(&value).map_err(|_| PeerLinkError::Multiaddr)?);
        }
        Self::new(peer_id, address.ok_or(PeerLinkError::Query)?)
    }
}

/// Peerlink parse/identity errors.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PeerLinkError {
    /// Link is empty, non-ASCII, or oversized.
    #[error("peerlink length or character set is invalid")]
    Length,
    /// Scheme/authority/path shape is invalid.
    #[error("peerlink syntax is invalid")]
    Syntax,
    /// Peer ID is invalid.
    #[error("peerlink Peer ID is invalid")]
    PeerId,
    /// Exactly one `addr` query parameter is required.
    #[error("peerlink query is invalid")]
    Query,
    /// Multiaddress is invalid.
    #[error("peerlink multiaddress is invalid")]
    Multiaddr,
    /// Multiaddress is empty, oversized, or has an unsafe identity shape.
    #[error("peerlink multiaddress shape is invalid")]
    AddressShape,
    /// Embedded `/p2p` identity disagrees with the path identity.
    #[error("peerlink address identifies a different peer")]
    PeerMismatch,
}

fn validate_address_peer(address: &Multiaddr, expected: &PeerId) -> Result<(), PeerLinkError> {
    if address.iter().next().is_none() || address.to_vec().len() > MAX_MULTIADDR_BYTES {
        return Err(PeerLinkError::AddressShape);
    }
    let address_text = address.to_string();
    let encoded_address = utf8_percent_encode(&address_text, NON_ALPHANUMERIC).to_string();
    let displayed_length = "volparossa://peer/".len()
        + expected.to_string().len()
        + "?addr=".len()
        + encoded_address.len();
    if displayed_length > MAX_PEERLINK_BYTES {
        return Err(PeerLinkError::AddressShape);
    }

    let mut embedded = false;
    let mut protocols = address.iter().peekable();
    while let Some(protocol) = protocols.next() {
        if let Protocol::P2p(peer_id) = protocol {
            if embedded || &peer_id != expected {
                return Err(PeerLinkError::PeerMismatch);
            }
            embedded = true;
            if protocols.peek().is_some() {
                return Err(PeerLinkError::AddressShape);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn peerlink_round_trips_and_dial_address_binds_identity() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let link = PeerLink::new(
            peer,
            "/ip4/192.0.2.10/udp/4001/quic-v1"
                .parse()
                .expect("multiaddr"),
        )
        .expect("peerlink");
        let encoded = link.to_string();
        let decoded: PeerLink = encoded.parse().expect("decode");
        assert_eq!(decoded, link);
        assert!(matches!(
            decoded.dial_address().iter().last(),
            Some(Protocol::P2p(value)) if value == peer
        ));
    }

    #[test]
    fn mismatched_embedded_peer_is_rejected() {
        let expected = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let address: Multiaddr = format!("/ip4/192.0.2.10/tcp/4001/p2p/{other}")
            .parse()
            .expect("multiaddr");
        assert_eq!(
            PeerLink::new(expected, address),
            Err(PeerLinkError::PeerMismatch)
        );
    }

    #[test]
    fn direct_constructor_rejects_empty_oversized_and_nonterminal_identity_addresses() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(
            PeerLink::new(peer, Multiaddr::empty()),
            Err(PeerLinkError::AddressShape)
        );

        let mut oversized = Multiaddr::empty();
        while oversized.to_vec().len() <= MAX_MULTIADDR_BYTES {
            oversized.push(Protocol::P2pCircuit);
        }
        assert_eq!(
            PeerLink::new(peer, oversized),
            Err(PeerLinkError::AddressShape)
        );

        let mut textually_oversized = Multiaddr::empty();
        while textually_oversized.to_string().len() <= MAX_PEERLINK_BYTES {
            textually_oversized.push(Protocol::P2pCircuit);
        }
        assert!(textually_oversized.to_vec().len() <= MAX_MULTIADDR_BYTES);
        assert_eq!(
            PeerLink::new(peer, textually_oversized),
            Err(PeerLinkError::AddressShape)
        );

        let nonterminal: Multiaddr = format!("/ip4/192.0.2.10/tcp/4001/p2p/{peer}/tcp/4002")
            .parse()
            .expect("syntactically valid multiaddr");
        assert_eq!(
            PeerLink::new(peer, nonterminal),
            Err(PeerLinkError::AddressShape)
        );
    }
}
