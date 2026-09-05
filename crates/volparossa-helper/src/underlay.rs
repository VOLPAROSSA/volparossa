//! Read-only collection and fail-closed per-lease selection of public or adjacent LAN underlays.
//!
//! The functional-alpha backend uses bounded `NETLINK_ROUTE` snapshots and exact route lookups
//! before preparation, then revalidates LAN bindings before activation. Collection never changes
//! links, addresses, routes, DNS or firewall state.

mod netlink;

pub(crate) use netlink::{collect_consistent_underlays, revalidate_underlay_bindings};

use std::{collections::BTreeMap, net::IpAddr};
use volparossa_routing::{LeasePlan, TraversalEndpointHint, is_public_routable_ip};

/// Evidence attached to an address selected without NAT or reachability inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnderlayEvidence {
    /// The address is a public unicast address assigned to the selected local interface.
    DirectAssigned,
    /// A public IPv4 address observed by every exact control peer in the prepare lineage.
    ObservedUdpPunch,
    /// The exact authenticated adjacent peer has a kernel-proven connected LAN route.
    DirectOnLink,
}

/// Minimal read-only link facts obtained from rtnetlink.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct UnderlayLink {
    pub(crate) ifindex: u32,
    pub(crate) up: bool,
    pub(crate) loopback: bool,
    pub(crate) helper_owned: bool,
}

/// Minimal read-only address facts obtained from rtnetlink.
#[allow(clippy::struct_excessive_bools)] // These are independent kernel address flags.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct UnderlayAddress {
    pub(crate) ifindex: u32,
    pub(crate) address: IpAddr,
    pub(crate) tentative: bool,
    pub(crate) dad_failed: bool,
    pub(crate) deprecated: bool,
    pub(crate) broadcast: bool,
}

/// Address family carried by a decoded rtnetlink route.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum UnderlayFamily {
    Ipv4,
    Ipv6,
}

impl UnderlayFamily {
    const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// Minimal read-only default-route facts obtained from rtnetlink.
#[allow(clippy::struct_excessive_bools)] // These are independent decoded route predicates.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct UnderlayRoute {
    pub(crate) ifindex: u32,
    pub(crate) family: UnderlayFamily,
    pub(crate) default: bool,
    pub(crate) unicast: bool,
    pub(crate) main_table: bool,
    pub(crate) universe_scope: bool,
}

/// One unambiguous directly assigned public endpoint candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnderlayCandidate {
    pub(crate) ifindex: u32,
    pub(crate) address: IpAddr,
    pub(crate) evidence: UnderlayEvidence,
}

pub(crate) type UnderlayBindings = BTreeMap<(u32, i32), UnderlayBinding>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnderlayBinding {
    pub(crate) candidate: UnderlayCandidate,
    pub(crate) on_link: Option<OnLinkBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)] // Every field describes the remote peer, unlike the local candidate.
pub(crate) struct OnLinkBinding {
    pub(crate) peer_address: IpAddr,
    pub(crate) peer_actor_id: [u8; 32],
    pub(crate) peer_peer_id: Vec<u8>,
}

/// A main-table kernel connected route without a gateway or indirect nexthop.
/// IPv4 reports LINK scope; IPv6 reports universe scope for its connected prefixes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ConnectedUnderlayRoute {
    pub(super) ifindex: u32,
    pub(super) network: IpAddr,
    pub(super) prefix_length: u8,
}

fn prefix_contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if (1..=32).contains(&prefix) => {
            let mask = u32::MAX << (32 - prefix);
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if (1..=128).contains(&prefix) => {
            let mask = u128::MAX << (128 - prefix);
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn lan_address(bytes: &[u8]) -> Option<IpAddr> {
    let address = match bytes.len() {
        4 => IpAddr::V4(<[u8; 4]>::try_from(bytes).ok()?.into()),
        16 => IpAddr::V6(<[u8; 16]>::try_from(bytes).ok()?.into()),
        _ => return None,
    };
    volparossa_routing::is_local_lan_ip(address).then_some(address)
}

pub(super) fn select_on_link_underlay(
    links: &[UnderlayLink],
    addresses: &[UnderlayAddress],
    routes: &[ConnectedUnderlayRoute],
    local: IpAddr,
    peer: IpAddr,
) -> Result<UnderlayCandidate, UnderlaySelectionError> {
    if !volparossa_routing::is_local_lan_ip(local)
        || !volparossa_routing::is_local_lan_ip(peer)
        || local == peer
        || UnderlayFamily::of(local) != UnderlayFamily::of(peer)
    {
        return Err(UnderlaySelectionError::NoCandidate);
    }
    let mut candidates = addresses.iter().filter(|address| {
        address.address == local
            && !address.tentative
            && !address.dad_failed
            && !address.deprecated
            && !address.broadcast
            && links
                .iter()
                .filter(|link| {
                    link.ifindex == address.ifindex
                        && link.ifindex != 0
                        && link.up
                        && !link.loopback
                        && !link.helper_owned
                })
                .count()
                == 1
    });
    let address = candidates
        .next()
        .ok_or(UnderlaySelectionError::NoCandidate)?;
    if candidates.next().is_some() {
        return Err(UnderlaySelectionError::Ambiguous);
    }
    // WireGuard's outer UDP socket is not source-bound. An explicit-source route lookup alone
    // cannot prove which alias that socket would choose, so require one usable family source.
    if addresses
        .iter()
        .filter(|other| {
            other.ifindex == address.ifindex
                && UnderlayFamily::of(other.address) == UnderlayFamily::of(local)
                && !other.tentative
                && !other.dad_failed
                && !other.deprecated
                && !other.broadcast
        })
        .count()
        != 1
    {
        return Err(UnderlaySelectionError::Ambiguous);
    }
    let mut connected = routes.iter().filter(|route| {
        prefix_contains(route.network, route.prefix_length, local)
            && prefix_contains(route.network, route.prefix_length, peer)
    });
    let route = connected
        .next()
        .ok_or(UnderlaySelectionError::NoCandidate)?;
    if connected.next().is_some() {
        return Err(UnderlaySelectionError::Ambiguous);
    }
    if route.ifindex != address.ifindex {
        return Err(UnderlaySelectionError::NoCandidate);
    }
    Ok(UnderlayCandidate {
        ifindex: address.ifindex,
        address: local,
        evidence: UnderlayEvidence::DirectOnLink,
    })
}

/// Why no safe automatic underlay choice can be made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnderlaySelectionError {
    NoCandidate,
    Ambiguous,
}

/// Select the preferred directly assigned public address.
///
/// An operator-selected numeric address can be supported later by a root-owned configuration
/// path. This automatic policy deliberately rejects zero or multiple candidates.
///
/// # Errors
///
/// Returns `NoCandidate` if the model contains no candidate with exactly one matching usable
/// default route. Returns `Ambiguous` if more than one address survives.
pub(crate) fn select_direct_underlay(
    links: &[UnderlayLink],
    addresses: &[UnderlayAddress],
    routes: &[UnderlayRoute],
) -> Result<UnderlayCandidate, UnderlaySelectionError> {
    let mut ipv6 = Vec::new();
    let mut ipv4 = Vec::new();
    for address in addresses {
        let eligible_links = links
            .iter()
            .filter(|link| {
                link.ifindex == address.ifindex
                    && link.ifindex != 0
                    && link.up
                    && !link.loopback
                    && !link.helper_owned
            })
            .count();
        if eligible_links != 1 || !eligible_address(address) {
            continue;
        }

        let family = UnderlayFamily::of(address.address);
        let mut defaults = routes.iter().filter(|route| {
            route.family == family
                && route.default
                && route.unicast
                && route.main_table
                && route.universe_scope
                && route.ifindex != 0
        });
        let Some(default) = defaults.next() else {
            continue;
        };
        if defaults.next().is_some() || default.ifindex != address.ifindex {
            continue;
        }

        let candidate = UnderlayCandidate {
            ifindex: address.ifindex,
            address: address.address,
            evidence: UnderlayEvidence::DirectAssigned,
        };
        match candidate.address {
            IpAddr::V6(_) => ipv6.push(candidate),
            IpAddr::V4(_) => ipv4.push(candidate),
        }
    }
    match (ipv6.as_slice(), ipv4.as_slice()) {
        ([candidate], _) | ([], [candidate]) => Ok(*candidate),
        ([], []) => Err(UnderlaySelectionError::NoCandidate),
        _ => Err(UnderlaySelectionError::Ambiguous),
    }
}

/// Select an observed public IPv4 only when every exact lease peer reported the same address and
/// the host has one usable private/default IPv4 underlay on which `WireGuard` can punch.
pub(crate) fn select_observed_punch_underlay(
    links: &[UnderlayLink],
    addresses: &[UnderlayAddress],
    routes: &[UnderlayRoute],
    leases: &[LeasePlan],
    hints: &[TraversalEndpointHint],
) -> Result<UnderlayCandidate, UnderlaySelectionError> {
    if leases.is_empty() || hints.is_empty() {
        return Err(UnderlaySelectionError::NoCandidate);
    }
    let expected = leases
        .iter()
        .map(|lease| (lease.path_id, lease.role))
        .collect::<std::collections::BTreeSet<_>>();
    let mut common = None;
    for identity in expected {
        let mut observed = hints.iter().filter_map(|hint| {
            (hint.path_id == identity.0 && hint.role == identity.1)
                .then(|| observed_ipv4(&hint.observed_address))
                .flatten()
        });
        let Some(address) = observed.next() else {
            return Err(UnderlaySelectionError::NoCandidate);
        };
        if observed.next().is_some() || common.is_some_and(|common| common != address) {
            return Err(UnderlaySelectionError::Ambiguous);
        }
        common = Some(address);
    }
    let public = common.ok_or(UnderlaySelectionError::NoCandidate)?;

    let mut defaults = routes.iter().filter(|route| {
        route.family == UnderlayFamily::Ipv4
            && route.default
            && route.unicast
            && route.main_table
            && route.universe_scope
            && route.ifindex != 0
    });
    let default = defaults.next().ok_or(UnderlaySelectionError::NoCandidate)?;
    if defaults.next().is_some() {
        return Err(UnderlaySelectionError::Ambiguous);
    }
    let mut locals = addresses.iter().filter(|address| {
        address.ifindex == default.ifindex
            && links
                .iter()
                .filter(|link| {
                    link.ifindex == address.ifindex
                        && link.ifindex != 0
                        && link.up
                        && !link.loopback
                        && !link.helper_owned
                })
                .count()
                == 1
            && eligible_punch_address(address)
    });
    let local = locals.next().ok_or(UnderlaySelectionError::NoCandidate)?;
    if locals.next().is_some() {
        return Err(UnderlaySelectionError::Ambiguous);
    }
    Ok(UnderlayCandidate {
        ifindex: local.ifindex,
        address: IpAddr::V4(public),
        evidence: UnderlayEvidence::ObservedUdpPunch,
    })
}

fn observed_ipv4(bytes: &[u8]) -> Option<std::net::Ipv4Addr> {
    let address = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?);
    is_public_routable_ip(IpAddr::V4(address)).then_some(address)
}

fn eligible_punch_address(value: &UnderlayAddress) -> bool {
    if value.ifindex == 0
        || value.tentative
        || value.dad_failed
        || value.deprecated
        || value.broadcast
    {
        return false;
    }
    matches!(value.address, IpAddr::V4(address) if !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast())
}

fn eligible_address(value: &UnderlayAddress) -> bool {
    if value.ifindex == 0
        || value.tentative
        || value.dad_failed
        || value.deprecated
        || value.broadcast
    {
        return false;
    }
    is_public_routable_ip(value.address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_routing::WireguardRole;

    fn link(ifindex: u32) -> UnderlayLink {
        UnderlayLink {
            ifindex,
            up: true,
            loopback: false,
            helper_owned: false,
        }
    }

    fn address(ifindex: u32, value: &str) -> UnderlayAddress {
        UnderlayAddress {
            ifindex,
            address: value.parse().expect("IP address"),
            tentative: false,
            dad_failed: false,
            deprecated: false,
            broadcast: false,
        }
    }

    fn route(ifindex: u32, family: UnderlayFamily) -> UnderlayRoute {
        UnderlayRoute {
            ifindex,
            family,
            default: true,
            unicast: true,
            main_table: true,
            universe_scope: true,
        }
    }

    #[test]
    fn returns_only_one_directly_assigned_candidate() {
        let candidate = select_direct_underlay(
            &[link(7)],
            &[address(7, "8.8.8.8")],
            &[route(7, UnderlayFamily::Ipv4)],
        )
        .expect("one candidate");
        assert_eq!(
            candidate,
            UnderlayCandidate {
                ifindex: 7,
                address: "8.8.8.8".parse().expect("IP"),
                evidence: UnderlayEvidence::DirectAssigned,
            }
        );
    }

    #[test]
    fn rejects_non_public_ipv4_classes() {
        for value in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !eligible_address(&address(7, value)),
                "{value} must fail closed"
            );
        }
    }

    #[test]
    fn rejects_non_public_ipv6_classes_and_address_state() {
        for value in [
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:20::1",
            "2001:db8::1",
            "2002:c000:0204::1",
            "2620:4f:8000::1",
            "3fff::1",
        ] {
            assert!(
                !eligible_address(&address(7, value)),
                "{value} must fail closed"
            );
        }
        assert!(eligible_address(&address(7, "2606:4700:4700::1111")));

        let mut unusable = address(7, "2606:4700:4700::1111");
        unusable.tentative = true;
        assert!(!eligible_address(&unusable));
        unusable.tentative = false;
        unusable.dad_failed = true;
        assert!(!eligible_address(&unusable));
        unusable.dad_failed = false;
        unusable.deprecated = true;
        assert!(!eligible_address(&unusable));
    }

    #[test]
    fn ipv6_special_purpose_prefix_boundaries_are_exact() {
        for value in [
            "2001::",
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db8::",
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
            "2002::",
            "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff::",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(
                !is_public_routable_ip(value.parse().expect("IPv6 address")),
                "{value} must be excluded",
            );
        }

        for value in [
            "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:200::",
            "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db9::",
            "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2003::",
            "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff:1000::",
        ] {
            assert!(
                is_public_routable_ip(value.parse().expect("IPv6 address")),
                "{value} must remain eligible",
            );
        }
    }

    #[test]
    fn rejects_down_loopback_helper_owned_and_broadcast_links() {
        let routes = [route(7, UnderlayFamily::Ipv4)];
        for unusable in [
            UnderlayLink {
                up: false,
                ..link(7)
            },
            UnderlayLink {
                loopback: true,
                ..link(7)
            },
            UnderlayLink {
                helper_owned: true,
                ..link(7)
            },
        ] {
            assert_eq!(
                select_direct_underlay(&[unusable], &[address(7, "8.8.4.4")], &routes),
                Err(UnderlaySelectionError::NoCandidate)
            );
        }

        let mut broadcast = address(7, "8.8.4.4");
        broadcast.broadcast = true;
        assert_eq!(
            select_direct_underlay(&[link(7)], &[broadcast], &routes),
            Err(UnderlaySelectionError::NoCandidate)
        );
    }

    #[test]
    fn requires_one_exact_usable_default_route_on_the_same_interface() {
        let links = [link(7), link(8)];
        let addresses = [address(7, "8.8.8.8")];

        assert_eq!(
            select_direct_underlay(&links, &addresses, &[]),
            Err(UnderlaySelectionError::NoCandidate)
        );
        assert_eq!(
            select_direct_underlay(&links, &addresses, &[route(8, UnderlayFamily::Ipv4)]),
            Err(UnderlaySelectionError::NoCandidate)
        );
        assert_eq!(
            select_direct_underlay(
                &links,
                &addresses,
                &[
                    route(7, UnderlayFamily::Ipv4),
                    route(8, UnderlayFamily::Ipv4),
                ],
            ),
            Err(UnderlaySelectionError::NoCandidate)
        );

        for unusable in [
            UnderlayRoute {
                default: false,
                ..route(7, UnderlayFamily::Ipv4)
            },
            UnderlayRoute {
                unicast: false,
                ..route(7, UnderlayFamily::Ipv4)
            },
            UnderlayRoute {
                main_table: false,
                ..route(7, UnderlayFamily::Ipv4)
            },
            UnderlayRoute {
                universe_scope: false,
                ..route(7, UnderlayFamily::Ipv4)
            },
        ] {
            assert_eq!(
                select_direct_underlay(&links, &addresses, &[unusable]),
                Err(UnderlaySelectionError::NoCandidate)
            );
        }
    }

    #[test]
    fn ipv6_is_preferred_before_public_ipv4() {
        let selected = select_direct_underlay(
            &[link(7)],
            &[address(7, "8.8.8.8"), address(7, "2606:4700:4700::1111")],
            &[
                route(7, UnderlayFamily::Ipv4),
                route(7, UnderlayFamily::Ipv6),
            ],
        )
        .expect("IPv6 candidate");
        assert_eq!(
            selected.address,
            "2606:4700:4700::1111".parse::<IpAddr>().expect("IPv6")
        );
    }

    #[test]
    fn multiple_same_family_addresses_are_ambiguous() {
        assert_eq!(
            select_direct_underlay(
                &[link(7)],
                &[address(7, "8.8.8.8"), address(7, "1.1.1.1")],
                &[route(7, UnderlayFamily::Ipv4)],
            ),
            Err(UnderlaySelectionError::Ambiguous)
        );
    }

    fn lease(path_id: u32, role: WireguardRole) -> LeasePlan {
        LeasePlan {
            path_id,
            role: role as i32,
        }
    }

    fn hint(path_id: u32, role: WireguardRole, address: [u8; 4]) -> TraversalEndpointHint {
        TraversalEndpointHint {
            path_id,
            role: role as i32,
            observer_id: vec![u8::try_from(path_id).expect("path"); 32],
            observer_peer_id: vec![u8::try_from(path_id + 16).expect("path"); 38],
            observed_address: address.to_vec(),
            on_link: None,
        }
    }

    #[test]
    fn on_link_selection_requires_exact_assigned_source_and_unique_connected_geometry() {
        for (local, peer, network, prefix) in [
            ("192.168.42.2", "192.168.42.1", "192.168.42.0", 24),
            ("fd42::2", "fd42::1", "fd42::", 64),
        ] {
            let local: IpAddr = local.parse().expect("local");
            let peer: IpAddr = peer.parse().expect("peer");
            let routes = [ConnectedUnderlayRoute {
                ifindex: 7,
                network: network.parse().expect("prefix"),
                prefix_length: prefix,
            }];
            let addresses = [address(7, &local.to_string())];
            let selected = select_on_link_underlay(&[link(7)], &addresses, &routes, local, peer)
                .expect("LAN needs no default route");
            assert_eq!(selected.evidence, UnderlayEvidence::DirectOnLink);
            assert_eq!(selected.address, local);
            assert!(
                select_on_link_underlay(
                    &[UnderlayLink {
                        helper_owned: true,
                        ..link(7)
                    }],
                    &addresses,
                    &routes,
                    local,
                    peer
                )
                .is_err()
            );
            assert!(select_on_link_underlay(&[link(7)], &addresses, &[], local, peer).is_err());
            assert!(
                select_on_link_underlay(
                    &[link(7)],
                    &addresses,
                    &[routes[0], routes[0]],
                    local,
                    peer
                )
                .is_err()
            );
            assert!(select_on_link_underlay(&[link(7)], &addresses, &routes, peer, local).is_err());
            assert!(
                select_on_link_underlay(&[link(7)], &addresses, &routes, local, local).is_err()
            );
        }
        assert!(
            select_on_link_underlay(
                &[link(7)],
                &[address(7, "10.0.0.2")],
                &[ConnectedUnderlayRoute {
                    ifindex: 7,
                    network: "10.0.0.0".parse().expect("IP"),
                    prefix_length: 24
                }],
                "10.0.0.2".parse().expect("IP"),
                "10.1.0.2".parse().expect("IP")
            )
            .is_err()
        );
        for disallowed in [
            "8.8.8.8",
            "100.64.0.1",
            "169.254.1.1",
            "127.0.0.1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            let address: IpAddr = disallowed.parse().expect("IP");
            let bytes = match address {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            assert!(lan_address(&bytes).is_none());
        }
    }

    #[test]
    fn on_link_rejects_private_or_public_same_family_source_aliases() {
        for (local, peer, network, prefix, aliases) in [
            (
                "192.168.42.2",
                "192.168.42.1",
                "192.168.42.0",
                24,
                ["192.168.42.3", "8.8.8.8"],
            ),
            (
                "fd42::2",
                "fd42::1",
                "fd42::",
                64,
                ["fd42::3", "2606:4700:4700::1111"],
            ),
        ] {
            let routes = [ConnectedUnderlayRoute {
                ifindex: 7,
                network: network.parse().expect("network"),
                prefix_length: prefix,
            }];
            for alias in aliases {
                let addresses = [address(7, local), address(7, alias)];
                assert_eq!(
                    select_on_link_underlay(
                        &[link(7)],
                        &addresses,
                        &routes,
                        local.parse().expect("local"),
                        peer.parse().expect("peer")
                    ),
                    Err(UnderlaySelectionError::Ambiguous)
                );
            }
        }
    }

    #[test]
    fn exact_peer_observations_enable_bounded_ipv4_punch_fallback() {
        let leases = [
            lease(1, WireguardRole::RelayClient),
            lease(1, WireguardRole::RelayExit),
        ];
        let hints = [
            hint(1, WireguardRole::RelayClient, [8, 8, 8, 8]),
            hint(1, WireguardRole::RelayExit, [8, 8, 8, 8]),
        ];
        let selected = select_observed_punch_underlay(
            &[link(7)],
            &[address(7, "192.168.1.40")],
            &[route(7, UnderlayFamily::Ipv4)],
            &leases,
            &hints,
        )
        .expect("punch candidate");
        assert_eq!(
            selected,
            UnderlayCandidate {
                ifindex: 7,
                address: "8.8.8.8".parse().expect("public IPv4"),
                evidence: UnderlayEvidence::ObservedUdpPunch,
            }
        );
    }

    #[test]
    fn punch_fallback_fails_closed_on_incomplete_or_inconsistent_lineage() {
        let leases = [
            lease(1, WireguardRole::RelayClient),
            lease(1, WireguardRole::RelayExit),
        ];
        let local = [address(7, "10.0.0.7")];
        let routes = [route(7, UnderlayFamily::Ipv4)];
        let first = hint(1, WireguardRole::RelayClient, [8, 8, 8, 8]);
        assert_eq!(
            select_observed_punch_underlay(&[link(7)], &local, &routes, &leases, &[first.clone()]),
            Err(UnderlaySelectionError::NoCandidate)
        );
        assert_eq!(
            select_observed_punch_underlay(
                &[link(7)],
                &local,
                &routes,
                &leases,
                &[first, hint(1, WireguardRole::RelayExit, [1, 1, 1, 1]),],
            ),
            Err(UnderlaySelectionError::Ambiguous)
        );
    }

    #[test]
    fn punch_fallback_requires_one_exact_ipv4_default_route() {
        assert_eq!(
            select_observed_punch_underlay(
                &[link(7), link(8)],
                &[address(7, "10.0.0.7")],
                &[
                    route(7, UnderlayFamily::Ipv4),
                    route(8, UnderlayFamily::Ipv4),
                ],
                &[lease(1, WireguardRole::Client)],
                &[hint(1, WireguardRole::Client, [8, 8, 8, 8])],
            ),
            Err(UnderlaySelectionError::Ambiguous)
        );
    }
}
