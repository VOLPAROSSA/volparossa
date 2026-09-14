//! Source selection for authenticated direct LAN QUIC connections.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, Transport,
    core::{
        Endpoint,
        transport::{DialOpts, ListenerId, PortUse, TransportError, TransportEvent},
    },
    identity,
    multiaddr::Protocol,
    quic,
};

pub(super) fn transport(keypair: &identity::Keypair) -> PrivateDirectQuic {
    PrivateDirectQuic(quic::tokio::Transport::new(quic::Config::new(keypair)))
}

/// A private direct-IP dial must let the kernel choose its source, rather than reuse an
/// arbitrary same-family QUIC listener bound to a different local network. Address admission
/// remains with `ScopedBehaviour`; this adapter grants no reachability or provenance authority.
pub(super) struct PrivateDirectQuic(quic::tokio::Transport);

fn dial_options(address: &Multiaddr, mut options: DialOpts) -> DialOpts {
    let mut protocols = address.iter();
    let private = match protocols.next() {
        Some(Protocol::Ip4(ip)) => volparossa_core::is_local_lan_ip(ip.into()),
        Some(Protocol::Ip6(ip)) => volparossa_core::is_local_lan_ip(ip.into()),
        _ => false,
    };
    let direct_quic = matches!(protocols.next(), Some(Protocol::Udp(_)))
        && matches!(protocols.next(), Some(Protocol::QuicV1))
        && match protocols.next() {
            None => true,
            Some(Protocol::P2p(_)) => protocols.next().is_none(),
            _ => false,
        };
    if private && direct_quic && options.role == Endpoint::Dialer {
        // Public/NAT dials, Circuit addresses and the DCUtR Listener role retain reuse.
        // DCUtR's Dialer role to an already-admitted private direct IP uses the new source
        // socket as well; the transport API does not expose which behaviour requested it.
        options.port_use = PortUse::New;
    }
    options
}

impl Transport for PrivateDirectQuic {
    type Output = <quic::tokio::Transport as Transport>::Output;
    type Error = <quic::tokio::Transport as Transport>::Error;
    type ListenerUpgrade = <quic::tokio::Transport as Transport>::ListenerUpgrade;
    type Dial = <quic::tokio::Transport as Transport>::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.0.listen_on(id, address)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.0.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        options: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let options = dial_options(&address, options);
        self.0.dial(address, options)
    }

    fn poll(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.get_mut().0).poll(context)
    }
}

#[cfg(test)]
mod tests;
