//! Private literal discovery endpoints stay on locally assigned LANs.
//!
//! An authenticated peer's Identify message can list interfaces attached to entirely different
//! networks. Neither Identify nor a Kademlia referral makes those interfaces locally reachable.
//! This is pre-dial eligibility only: native datapaths still require their exact authenticated
//! connection lineage and the helper's independent route/ifindex proof.

use std::{
    net::IpAddr,
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    multiaddr::Protocol,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use volparossa_core::is_local_lan_ip;

use crate::{BehaviourEvent, DiscoveryBehaviour};

const MAX_INTERFACE_ADDRESSES: usize = 512;

#[derive(Clone, Copy)]
struct LocalNetwork {
    address: IpAddr,
    mask: IpAddr,
}

impl LocalNetwork {
    fn contains(self, peer: IpAddr) -> bool {
        if peer == self.address || !is_local_lan_ip(self.address) {
            return false;
        }
        match (self.address, self.mask, peer) {
            (IpAddr::V4(local), IpAddr::V4(mask), IpAddr::V4(peer)) => {
                let (local, mask, peer) = (u32::from(local), u32::from(mask), u32::from(peer));
                let prefix = mask.leading_ones();
                prefix > 0
                    && mask.trailing_zeros() + prefix == 32
                    && local & mask == peer & mask
                    && (prefix >= 31 || (peer & !mask != 0 && peer & !mask != !mask))
            }
            (IpAddr::V6(local), IpAddr::V6(mask), IpAddr::V6(peer)) => {
                let (local, mask, peer) = (u128::from(local), u128::from(mask), u128::from(peer));
                let prefix = mask.leading_ones();
                prefix > 0 && mask.trailing_zeros() + prefix == 128 && local & mask == peer & mask
            }
            _ => false,
        }
    }
}

fn literal_private_host(address: &Multiaddr) -> Option<IpAddr> {
    // For circuit addresses the first IP is the transport Relay, not the encapsulated peer.
    let host = match address.iter().next()? {
        Protocol::Ip4(address) => IpAddr::V4(address),
        Protocol::Ip6(address) => IpAddr::V6(address),
        _ => return None,
    };
    is_local_lan_ip(host).then_some(host)
}

fn local_networks() -> Option<Vec<LocalNetwork>> {
    let addresses = getifaddrs().ok()?;
    let mut networks = Vec::new();
    for (count, interface) in addresses.enumerate() {
        if count >= MAX_INTERFACE_ADDRESSES {
            return None;
        }
        // Helper interfaces use the reserved vp prefix. They are overlay routes, never LAN
        // discovery authority. Down, loopback and point-to-point interfaces likewise do not
        // establish an attached LAN. No hostname lookup or parsed networking CLI is involved.
        if !interface.flags.contains(InterfaceFlags::IFF_UP)
            || interface
                .flags
                .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
            || interface.interface_name.starts_with("vp")
        {
            continue;
        }
        let (Some(address), Some(mask)) = (interface.address, interface.netmask) else {
            continue;
        };
        if let (Some(address), Some(mask)) = (address.as_sockaddr_in(), mask.as_sockaddr_in()) {
            networks.push(LocalNetwork {
                address: IpAddr::V4(address.ip()),
                mask: IpAddr::V4(mask.ip()),
            });
        } else if let (Some(address), Some(mask)) =
            (address.as_sockaddr_in6(), mask.as_sockaddr_in6())
        {
            networks.push(LocalNetwork {
                address: IpAddr::V6(address.ip()),
                mask: IpAddr::V6(mask.ip()),
            });
        }
    }
    Some(networks)
}

fn allowed_in(address: &Multiaddr, networks: Option<&[LocalNetwork]>) -> bool {
    literal_private_host(address).is_none_or(|peer| {
        networks.is_some_and(|networks| networks.iter().any(|network| network.contains(peer)))
    })
}

pub(super) fn private_address_is_local(address: &Multiaddr) -> bool {
    literal_private_host(address).is_none_or(|_| allowed_in(address, local_networks().as_deref()))
}

/// Outer wrapper sees the addresses produced by every inner behaviour, including mDNS's own
/// pending-dial address list and Kademlia referrals not yet admitted into the routing table.
/// Keeping the original handlers/events intact preserves exact connection IDs and lineage.
pub(super) struct ScopedBehaviour(pub(super) DiscoveryBehaviour);

impl Deref for ScopedBehaviour {
    type Target = DiscoveryBehaviour;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ScopedBehaviour {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NetworkBehaviour for ScopedBehaviour {
    type ConnectionHandler = <DiscoveryBehaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = BehaviourEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.0.handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.0
            .handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let networks = local_networks();
        // Explicit DialOpts addresses cannot be rewritten through this API. Reject the whole
        // explicit attempt rather than sending any packet to an ineligible private endpoint.
        if addresses
            .iter()
            .any(|address| !allowed_in(address, networks.as_deref()))
        {
            return Err(ConnectionDenied::new(std::io::Error::other(
                "private discovery endpoint is not on an active local LAN",
            )));
        }
        let mut additional = self
            .0
            .handle_pending_outbound_connection(id, peer, addresses, role)?;
        additional.retain(|address| allowed_in(address, networks.as_deref()));
        Ok(additional)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.0
            .handle_established_outbound_connection(id, peer, address, role, port)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        self.0.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.0.on_connection_handler_event(peer, id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.0.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process::Command};

    use super::*;

    fn network(address: &str, mask: &str) -> LocalNetwork {
        LocalNetwork {
            address: address.parse().unwrap(),
            mask: mask.parse().unwrap(),
        }
    }

    #[test]
    fn private_discovery_scope_uses_exact_lan_mask_not_rfc1918_membership() {
        let networks = [network("10.241.11.2", "255.255.255.252")];
        let check = |ip: &str| {
            allowed_in(
                &format!("/ip4/{ip}/udp/41000/quic-v1").parse().unwrap(),
                Some(&networks),
            )
        };
        assert!(check("10.241.11.1"));
        for denied in [
            "10.241.11.0",
            "10.241.11.2",
            "10.241.11.3",
            "10.241.20.1",
            "10.241.42.1",
        ] {
            assert!(!check(denied), "{denied}");
        }
        assert!(check("45.161.2.1"));
        assert!(check("127.0.0.1"));
    }

    #[test]
    fn private_discovery_scope_supports_ula_and_point_to_point_length_lans() {
        let ula = network("fd12:3456::1", "ffff:ffff:ffff:ffff::");
        assert!(ula.contains("fd12:3456::2".parse().unwrap()));
        assert!(!ula.contains("fd12:3457::2".parse().unwrap()));
        assert!(!ula.contains("fd12:3456::1".parse().unwrap()));
        let pair = network("192.168.2.0", "255.255.255.254");
        assert!(pair.contains("192.168.2.1".parse().unwrap()));
        assert!(!network("10.1.1.1", "0.0.0.0").contains("10.2.2.2".parse().unwrap()));
        assert!(!network("10.1.1.1", "255.0.255.0").contains("10.2.1.2".parse().unwrap()));
    }

    #[test]
    fn private_discovery_scope_failure_is_closed_only_for_private_literals() {
        let lan: Multiaddr = "/ip4/10.241.20.1/udp/41000/quic-v1".parse().unwrap();
        let public: Multiaddr = "/ip4/44.160.1.1/udp/41000/quic-v1".parse().unwrap();
        assert!(!allowed_in(&lan, None));
        assert!(allowed_in(&public, None));
        let peer = PeerId::random();
        let other = PeerId::random();
        let circuit = format!("{lan}/p2p/{peer}/p2p-circuit/p2p/{other}")
            .parse()
            .unwrap();
        assert!(!allowed_in(&circuit, None));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one disposable namespace proof keeps host guards, all dial sources and teardown together"
    )]
    fn private_discovery_scope_live_namespace_filters_all_behaviour_addresses() {
        const PARENT: &str = "VOLPAROSSA_DISCOVERY_SCOPE_PARENT_NETNS";
        const TEST: &str = "address_scope::tests::private_discovery_scope_live_namespace_filters_all_behaviour_addresses";
        let namespace = || fs::read_link("/proc/thread-self/ns/net").unwrap();
        let original = namespace();
        let Ok(parent) = env::var(PARENT) else {
            let output = Command::new("/usr/bin/timeout")
                .args([
                    "30",
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                ])
                .arg(env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(PARENT, &original)
                .output()
                .expect("bounded disposable user/netns test");
            assert_eq!(namespace(), original, "host network namespace unchanged");
            if !output.status.success()
                && output
                    .stderr
                    .starts_with(b"unshare: unshare failed: Operation not permitted")
            {
                eprintln!("SKIP: disposable user/netns is unavailable; no host networking changed");
                return;
            }
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("LAN_SCOPE_PROOF"));
            print!("{}", String::from_utf8_lossy(&output.stdout));
            return;
        };
        assert_ne!(original, std::path::Path::new(&parent));
        let ip = |args: &[&str]| {
            assert_ne!(
                namespace(),
                std::path::Path::new(&parent),
                "never mutate host networking"
            );
            let output = Command::new("/usr/bin/ip").args(args).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        ip(&[
            "link", "add", "scope0", "type", "veth", "peer", "name", "scope1",
        ]);
        ip(&["address", "add", "10.241.11.2/30", "dev", "scope0"]);
        ip(&[
            "-6",
            "address",
            "add",
            "fd12:3456::1/64",
            "dev",
            "scope0",
            "nodad",
        ]);
        ip(&["link", "set", "scope0", "up"]);
        ip(&["link", "set", "scope1", "up"]);

        let lan: Multiaddr = "/ip4/10.241.11.1/udp/41000/quic-v1".parse().unwrap();
        let other_lan: Multiaddr = "/ip4/10.241.20.1/udp/41000/quic-v1".parse().unwrap();
        let ula: Multiaddr = "/ip6/fd12:3456::2/udp/41000/quic-v1".parse().unwrap();
        let public: Multiaddr = "/ip4/45.161.2.1/udp/41000/quic-v1".parse().unwrap();
        assert!(private_address_is_local(&lan));
        assert!(private_address_is_local(&ula));
        assert!(!private_address_is_local(&other_lan));

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut service =
                    crate::DiscoveryService::new(libp2p::identity::Keypair::generate_ed25519())
                        .unwrap();
                let peer = PeerId::random();
                assert!(service.add_known_peer(peer, &other_lan).is_err());
                assert!(service.add_known_peer(peer, &lan).is_ok());
                // Bypass admission to model addresses learned internally by Kademlia referrals.
                service
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer, other_lan.clone());
                service
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer, public.clone());
                let addresses = service
                    .swarm
                    .behaviour_mut()
                    .handle_pending_outbound_connection(
                        ConnectionId::new_unchecked(70),
                        Some(peer),
                        &[],
                        Endpoint::Dialer,
                    )
                    .unwrap();
                assert!(
                    addresses
                        .iter()
                        .any(|address| address.iter().next() == lan.iter().next())
                );
                assert!(
                    addresses
                        .iter()
                        .any(|address| address.iter().next() == public.iter().next())
                );
                assert!(
                    addresses
                        .iter()
                        .all(|address| address.iter().next() != other_lan.iter().next())
                );
                // Explicit opts are denied by the outer wrapper before any transport dial starts.
                assert!(
                    service
                        .swarm
                        .dial(other_lan.with_p2p(peer).unwrap())
                        .is_err()
                );
            });
        ip(&["link", "set", "scope0", "down"]);
        assert!(
            !private_address_is_local(&lan),
            "fresh state rejects removed/down LAN"
        );
        ip(&["link", "delete", "scope0"]);
        println!(
            "LAN_SCOPE_PROOF active IPv4/ULA eligible; non-neighbor known/referral/explicit dials rejected; down LAN withdrawn; owned veth removed"
        );
    }
}
