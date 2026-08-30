//! Read-only collection and fail-closed selection of a directly assigned public underlay address.
//!
//! The functional-alpha production backend uses this collector before its one-lease mutation. It
//! performs only bounded `NETLINK_ROUTE` dumps and never changes links, addresses, routes, DNS or
//! firewall state. Broader multi-path selection remains unavailable.

mod netlink;

pub(crate) use netlink::collect_consistent_direct_underlay;

use std::net::IpAddr;
use volparossa_routing::is_public_routable_ip;

/// Evidence attached to an address selected without NAT or reachability inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnderlayEvidence {
    /// The address is a public unicast address assigned to the selected local interface.
    DirectAssigned,
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

/// Select exactly one public address attached to the only usable default route.
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
    let mut selected = None;
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
        if selected.replace(candidate).is_some() {
            return Err(UnderlaySelectionError::Ambiguous);
        }
    }
    selected.ok_or(UnderlaySelectionError::NoCandidate)
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
    fn multiple_addresses_or_families_are_ambiguous() {
        assert_eq!(
            select_direct_underlay(
                &[link(7)],
                &[address(7, "8.8.8.8"), address(7, "1.1.1.1")],
                &[route(7, UnderlayFamily::Ipv4)],
            ),
            Err(UnderlaySelectionError::Ambiguous)
        );
        assert_eq!(
            select_direct_underlay(
                &[link(7)],
                &[address(7, "8.8.8.8"), address(7, "2606:4700:4700::1111"),],
                &[
                    route(7, UnderlayFamily::Ipv4),
                    route(7, UnderlayFamily::Ipv6),
                ],
            ),
            Err(UnderlaySelectionError::Ambiguous)
        );
    }
}
