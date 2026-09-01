//! Read-only collection and fail-closed selection of a directly assigned public underlay address.
//!
//! The functional-alpha production backend uses this collector before its one-lease mutation. It
//! performs only bounded `NETLINK_ROUTE` dumps and never changes links, addresses, routes, DNS or
//! firewall state. Broader multi-path selection remains unavailable.

mod netlink;

pub(crate) use netlink::collect_consistent_underlay;

use std::net::IpAddr;
use volparossa_routing::{LeasePlan, TraversalEndpointHint, is_public_routable_ip};

/// Evidence attached to an address selected without NAT or reachability inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnderlayEvidence {
    /// The address is a public unicast address assigned to the selected local interface.
    DirectAssigned,
    /// A public IPv4 address observed by every exact control peer in the prepare lineage.
    ObservedUdpPunch,
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
