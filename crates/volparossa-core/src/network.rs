//! Shared fail-closed classification for Internet-facing endpoint addresses.

use crate::{IpFamily, advertisement::ObservedNetworkOrigin};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Canonical network prefix normalized from an untrusted local observation.
///
/// The value retains only an IPv4 /24 or IPv6 /48. It exposes neither its private bytes nor a
/// fabricated representative address and has no serialization representation. Construction alone
/// does not prove that the prefix is public or that its provenance is authentic.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ObservedNetworkPrefix(ObservedNetworkPrefixKind);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum ObservedNetworkPrefixKind {
    Ipv4([u8; 3]),
    Ipv6([u8; 6]),
}

impl ObservedNetworkPrefix {
    /// Retains an exact IPv4 /24 prefix without inventing host bits.
    #[must_use]
    pub const fn ipv4_24(prefix: [u8; 3]) -> Self {
        Self(ObservedNetworkPrefixKind::Ipv4(prefix))
    }

    /// Retains an exact IPv6 /48 prefix without inventing host bits.
    #[must_use]
    pub const fn ipv6_48(prefix: [u8; 6]) -> Self {
        Self(ObservedNetworkPrefixKind::Ipv6(prefix))
    }

    /// Canonicalizes a legacy locally observed address and discards its host suffix.
    #[must_use]
    pub fn from_origin(origin: ObservedNetworkOrigin) -> Self {
        match origin.address {
            IpAddr::V4(address) => {
                let [first, second, third, _] = address.octets();
                Self::ipv4_24([first, second, third])
            }
            IpAddr::V6(address) => {
                let octets = address.octets();
                Self::ipv6_48([
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                ])
            }
        }
    }

    /// Address family represented by this canonical prefix.
    #[must_use]
    pub const fn family(self) -> IpFamily {
        match self.0 {
            ObservedNetworkPrefixKind::Ipv4(_) => IpFamily::Ipv4,
            ObservedNetworkPrefixKind::Ipv6(_) => IpFamily::Ipv6,
        }
    }

    /// Returns whether the normalized prefix is ordinary public-routable unicast.
    #[must_use]
    pub fn is_public_routable(self) -> bool {
        match self.0 {
            ObservedNetworkPrefixKind::Ipv4(prefix) => is_public_routable_ipv4_prefix(prefix),
            ObservedNetworkPrefixKind::Ipv6(prefix) => is_public_routable_ipv6_prefix(prefix),
        }
    }
}

/// Return whether an address is ordinary, publicly routable unicast.
///
/// VOLPAROSSA deliberately excludes every special-purpose block in the IANA
/// IPv4 and IPv6 registries, including globally reachable anycast/service
/// assignments. This conservative predicate is shared by signed control
/// validation, public lease construction and privileged underlay selection.
#[must_use]
pub fn is_public_routable_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_routable_ipv4(address),
        IpAddr::V6(address) => is_public_routable_ipv6(address),
    }
}

fn is_public_routable_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = address.octets();
    is_public_routable_ipv4_prefix([first, second, third])
}

fn is_public_routable_ipv4_prefix([first, second, third]: [u8; 3]) -> bool {
    !(first == 0
        || first == 10
        || first == 127
        || (first == 100 && (64..=127).contains(&second))
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 0 && third == 2)
        || (first == 192 && second == 31 && third == 196)
        || (first == 192 && second == 52 && third == 193)
        || (first == 192 && second == 88 && third == 99)
        || (first == 192 && second == 168)
        || (first == 192 && second == 175 && third == 48)
        || (first == 198 && (second == 18 || second == 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
        || first >= 224)
}

fn is_public_routable_ipv6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    is_public_routable_ipv6_prefix([
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
    ])
}

fn is_public_routable_ipv6_prefix(octets: [u8; 6]) -> bool {
    let ietf_protocol_assignments = octets[0] == 0x20 && octets[1] == 0x01 && octets[2] & 0xfe == 0;
    let documentation_2001_db8 = octets[0..4] == [0x20, 0x01, 0x0d, 0xb8];
    let deprecated_6to4 = octets[0..2] == [0x20, 0x02];
    let documentation_3fff = octets[0] == 0x3f && octets[1] == 0xff && octets[2] & 0xf0 == 0;
    let as112_direct_delegation = octets == [0x26, 0x20, 0x00, 0x4f, 0x80, 0x00];

    // Ordinary global unicast is 2000::/3. Remove every special-purpose
    // sub-prefix in that range; all other IANA special ranges fall outside it.
    (octets[0] & 0xe0) == 0x20
        && !ietf_protocol_assignments
        && !documentation_2001_db8
        && !deprecated_6to4
        && !documentation_3fff
        && !as112_direct_delegation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed_origin(value: &str) -> ObservedNetworkOrigin {
        ObservedNetworkOrigin {
            address: value.parse().expect("observed address"),
        }
    }

    #[test]
    fn observed_prefix_canonicalizes_only_the_family_native_prefix() {
        let ipv4_left = ObservedNetworkPrefix::from_origin(observed_origin("1.2.3.4"));
        let ipv4_same = ObservedNetworkPrefix::from_origin(observed_origin("1.2.3.250"));
        let ipv4_adjacent = ObservedNetworkPrefix::from_origin(observed_origin("1.2.4.4"));
        assert!(ipv4_left == ipv4_same);
        assert!(ipv4_left != ipv4_adjacent);
        assert!(ipv4_left == ObservedNetworkPrefix::ipv4_24([1, 2, 3]));
        assert_eq!(ipv4_left.family(), IpFamily::Ipv4);

        let ipv6_left = ObservedNetworkPrefix::from_origin(observed_origin("2606:4700:4700:1::1"));
        let ipv6_same =
            ObservedNetworkPrefix::from_origin(observed_origin("2606:4700:4700:ffff::2"));
        let ipv6_adjacent =
            ObservedNetworkPrefix::from_origin(observed_origin("2606:4700:4701::1"));
        assert!(ipv6_left == ipv6_same);
        assert!(ipv6_left != ipv6_adjacent);
        assert!(ipv6_left == ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x47, 0x00]));
        assert_eq!(ipv6_left.family(), IpFamily::Ipv6);
        assert!(ipv4_left != ipv6_left);
        assert!(!ObservedNetworkPrefix::ipv4_24([10, 0, 0]).is_public_routable());
        assert!(ObservedNetworkPrefix::ipv4_24([8, 8, 8]).is_public_routable());
        assert!(
            !ObservedNetworkPrefix::ipv6_48([0x20, 0x01, 0x0d, 0xb8, 0, 0]).is_public_routable()
        );
        assert!(
            ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x47, 0x00])
                .is_public_routable()
        );
    }

    #[test]
    fn observed_prefix_publicness_has_exact_full_address_parity() {
        for value in [
            "0.0.0.1",
            "0.0.0.0",
            "1.1.1.1",
            "10.0.0.1",
            "100.63.255.255",
            "100.64.0.1",
            "100.64.0.0",
            "100.127.255.255",
            "100.128.0.0",
            "127.0.0.1",
            "169.254.0.1",
            "172.15.255.255",
            "172.16.0.1",
            "172.16.0.0",
            "172.31.255.255",
            "172.32.0.0",
            "192.0.0.9",
            "192.0.2.1",
            "192.31.195.255",
            "192.31.196.1",
            "192.31.197.0",
            "192.52.193.1",
            "192.88.99.1",
            "192.168.1.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "223.255.255.254",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2000:ffff:ffff::1",
            "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001::",
            "2001:1ff:ffff::1",
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:200::1",
            "2001:200::",
            "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db8::1",
            "2001:db9::1",
            "2001:db9::",
            "2002::1",
            "2003::",
            "2606:4700:4700::1111",
            "2620:4f:8000::1",
            "3fff::1",
            "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff:1000::1",
            "3fff:1000::",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            let address: IpAddr = value.parse().expect("boundary address");
            let prefix = ObservedNetworkPrefix::from_origin(ObservedNetworkOrigin { address });
            let native = match address {
                IpAddr::V4(address) => {
                    let [first, second, third, _] = address.octets();
                    ObservedNetworkPrefix::ipv4_24([first, second, third])
                }
                IpAddr::V6(address) => {
                    let octets = address.octets();
                    ObservedNetworkPrefix::ipv6_48([
                        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                    ])
                }
            };
            assert!(native == prefix);
            assert_eq!(
                prefix.is_public_routable(),
                is_public_routable_ip(address),
                "prefix/full-address classifier mismatch for {value}"
            );
        }
    }

    #[test]
    fn observed_prefix_surface_is_opaque_and_has_no_reconstruction_route() {
        let product = include_str!("network.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("product network source");
        let item_header = product
            .split("/// Canonical network prefix normalized from an untrusted local observation.")
            .nth(1)
            .expect("prefix documentation")
            .split("impl ObservedNetworkPrefix {")
            .next()
            .expect("prefix item header end");
        assert_eq!(
            item_header
                .matches("#[derive(Clone, Copy, Eq, Hash, PartialEq)]")
                .count(),
            2
        );
        assert!(!item_header.contains("Debug"));
        assert!(!item_header.contains("Serialize"));
        assert!(!item_header.contains("Deserialize"));

        let inherent_api = product
            .split("impl ObservedNetworkPrefix {")
            .nth(1)
            .expect("prefix inherent API")
            .split("\n}")
            .next()
            .expect("prefix inherent API end");
        assert_eq!(inherent_api.matches("\n    pub ").count(), 5);
        for required in [
            "pub const fn ipv4_24(",
            "pub const fn ipv6_48(",
            "pub fn from_origin(",
            "pub const fn family(",
            "pub fn is_public_routable(",
        ] {
            assert!(inherent_api.contains(required), "missing API: {required}");
        }
        for forbidden in [
            "impl std::fmt::Debug for ObservedNetworkPrefix",
            "impl Debug for ObservedNetworkPrefix",
            "impl std::fmt::Display for ObservedNetworkPrefix",
            "impl Display for ObservedNetworkPrefix",
            "impl Default for ObservedNetworkPrefix",
            "Serialize for ObservedNetworkPrefix",
            "Deserialize<'de> for ObservedNetworkPrefix",
            "impl From<",
            "impl TryFrom<",
            "impl std::ops::Deref for ObservedNetworkPrefix",
            "impl Deref for ObservedNetworkPrefix",
            "impl std::borrow::Borrow",
            "impl Borrow",
            "impl AsRef",
            "pub fn new(",
            "pub fn as_ref(",
            "pub fn as_bytes(",
            "pub fn into_bytes(",
            "pub fn address(",
            "pub fn to_ip(",
            "pub fn into_parts(",
            "pub fn decompose(",
            "pub fn from_public_ip(",
            "Ipv4Addr::new(",
            "Ipv6Addr::from(",
        ] {
            assert!(!product.contains(forbidden), "leaking surface: {forbidden}");
        }
    }

    #[test]
    fn ipv4_iana_special_purpose_ranges_fail_closed() {
        for value in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.0.1",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.168.1.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !is_public_routable_ip(value.parse().expect("IPv4 address")),
                "{value} must fail closed"
            );
        }
        for value in [
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.31.195.255",
            "192.31.197.0",
            "223.255.255.254",
        ] {
            assert!(
                is_public_routable_ip(value.parse().expect("IPv4 address")),
                "{value} must remain eligible"
            );
        }
    }

    #[test]
    fn ipv6_iana_special_purpose_ranges_fail_closed_at_boundaries() {
        for value in [
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::",
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db8::1",
            "2002::1",
            "2620:4f:8000::1",
            "3fff::1",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(
                !is_public_routable_ip(value.parse().expect("IPv6 address")),
                "{value} must fail closed"
            );
        }
        for value in [
            "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:200::",
            "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db9::",
            "2003::",
            "2606:4700:4700::1111",
            "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "3fff:1000::",
        ] {
            assert!(
                is_public_routable_ip(value.parse().expect("IPv6 address")),
                "{value} must remain eligible"
            );
        }
    }
}
