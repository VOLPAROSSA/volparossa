//! Native, bounded nftables fence for one production Relay path.
//!
//! This module is deliberately private to the authenticated worker.  It opens
//! `NETLINK_NETFILTER` only after an affine namespace authority proves that the
//! calling thread is still in the expected anonymous worker namespace and not
//! in its parent namespace.  It can encode only one fixed `inet` table: two
//! direction-specific `/128` forwarding rules between the exact `RelayClient`
//! and `RelayExit` interfaces, followed by a terminal drop.  Each accept rule is
//! bound to the authenticated reservation expiry and byte rate.  There is no
//! NAT, interface wildcard, prefix-wide forwarding, command, path, subprocess
//! or caller-provided nftables byte stream.
//!
//! Baseline creation, rule activation, rule deactivation and baseline
//! retirement are separate generation-pinned atomic batches.  Every
//! acknowledged or possibly-sent mutation is reconciled through a fresh,
//! bounded, generation-bracketed dump of tables, chains, rules, sets, objects
//! and flowtables.  Before either link exists, the exact context-bound table
//! contains only an empty forward base chain with policy drop.  Activation
//! accepts only the exact zero-counter rule set, deactivation restores that
//! same restrictive baseline with stable table and chain handles, and
//! retirement accepts only complete absence. The authenticated Relay worker
//! owns every affine state transition; an indeterminate mutation terminates
//! that worker so destruction of its anonymous namespace is the only recovery.

use std::{io, marker::PhantomData, net::Ipv6Addr, os::fd::AsFd as _, rc::Rc, time::Duration};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use thiserror::Error;
use volparossa_routing::{ContextRole, MAX_HELPER_PATHS, MAX_HELPER_RATE_MBPS, WireguardRole};

use crate::{
    deadline::HardDeadline,
    lease_spec::WireguardLeaseSpec,
    worker_sandbox::{NetworkNamespaceIdentity, current_network_namespace_identity},
};

const MAX_FENCE_TTL_SECONDS: u64 = 15 * 60;
const BITS_PER_MEGABIT: u64 = 1_000_000;
const BITS_PER_BYTE: u64 = 8;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
const RATE_BURST_BYTES: u32 = 65_535;
const MAX_KERNEL_IFINDEX: u32 = 0x7fff_ffff;
const INTERFACE_NAME_BYTES: usize = libc::IFNAMSIZ;
const TABLE_USERDATA_DOMAIN: &[u8] = b"VOLPAROSSA relay fence identity v2\0";
const TABLE_NAME_PREFIX: &[u8] = b"vpr_";
const FORWARD_CHAIN_NAME: &[u8] = b"forward";
const FILTER_CHAIN_TYPE: &[u8] = b"filter";

const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 512 * 1024;
const MAX_DATAGRAMS: usize = 64;
const MAX_FRAMES: usize = 256;
const MAX_GENERATION_ATTRIBUTES: usize = 3;
const MAX_TABLE_ATTRIBUTES: usize = 7;
const MAX_CHAIN_ATTRIBUTES: usize = 12;
const MAX_HOOK_ATTRIBUTES: usize = 4;
const MAX_RULE_ATTRIBUTES: usize = 11;
const DIRECTION_RULE_EXPRESSIONS: usize = 20;
const TERMINAL_RULE_EXPRESSIONS: usize = 2;
const MAX_RULE_EXPRESSIONS: usize = DIRECTION_RULE_EXPRESSIONS;
const MAX_EXPRESSION_ATTRIBUTES: usize = 2;
const MAX_EXPRESSION_DATA_ATTRIBUTES: usize = 8;
const MAX_COUNTER_ATTRIBUTES: usize = 4;
const MAX_DATA_ATTRIBUTES: usize = 2;
const MAX_VERDICT_ATTRIBUTES: usize = 3;
const MAX_PROCESS_NAME_BYTES: usize = 16;
const MAX_TABLE_NAME_BYTES: usize = 256;
const MAX_TABLE_USERDATA_BYTES: usize = 256;
const MAX_CHAIN_USERDATA_BYTES: usize = 256;
const MAX_RULE_USERDATA_BYTES: usize = 256;
const MAX_COUNTER_BYTES: usize = 64;
const MAX_OBSERVED_TABLES: usize = 2;
const MAX_OBSERVED_CHAINS: usize = 2;
const MAX_OBSERVED_RULES: usize = 4;
const MAX_MUTATION_BATCH_BYTES: usize = 16 * 1024;
const MAX_MUTATION_MESSAGES: usize = 7;
const MAX_MUTATION_ACK_BYTES: usize = 4 * 1024;
const MAX_MUTATION_ACK_DATAGRAMS: usize = 5;
const MAX_MUTATION_ACK_FRAMES: usize = 5;
const RECONCILIATION_TAIL: Duration = Duration::from_secs(1);

const NLMSG_HEADER_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const REQUEST_LEN: usize = NLMSG_HEADER_LEN + NFGENMSG_LEN;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const NLM_F_APPEND: u16 = 0x0800;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_CAPPED: u16 = 0x0100;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWTABLE: u16 = NFNL_SUBSYS_NFTABLES << 8;
const NFT_MSG_GETTABLE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 1;
const NFT_MSG_DELTABLE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 2;
const NFT_MSG_NEWCHAIN: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 3;
const NFT_MSG_GETCHAIN: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 4;
const NFT_MSG_NEWRULE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 6;
const NFT_MSG_GETRULE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 7;
const NFT_MSG_DELRULE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 8;
const NFT_MSG_NEWSET: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 9;
const NFT_MSG_GETSET: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 10;
const NFT_MSG_NEWGEN: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 15;
const NFT_MSG_GETGEN: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 16;
const NFT_MSG_NEWOBJ: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 18;
const NFT_MSG_GETOBJ: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 19;
const NFT_MSG_NEWFLOWTABLE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 22;
const NFT_MSG_GETFLOWTABLE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 23;

const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;

const AF_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_ARP: u8 = 3;
const NFPROTO_NETDEV: u8 = 5;
const NFPROTO_BRIDGE: u8 = 7;
const NFPROTO_IPV6: u8 = 10;
const NFNETLINK_V0: u8 = 0;

const NF_INET_FORWARD: u32 = 2;
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NFT_CHAIN_BASE: u32 = 1;
const NFT_CHAIN_FLAGS: u32 = 0x0007;
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_META_IIF: u32 = 4;
const NFT_META_OIF: u32 = 5;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_TIME_NS: u32 = 30;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_LT: u32 = 2;
const NFT_BYTEORDER_HTON: u32 = 1;
const NFT_LIMIT_PKT_BYTES: u32 = 1;
const IPV6_SOURCE_OFFSET: u32 = 8;
const IPV6_DESTINATION_OFFSET: u32 = 24;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_TABLE_USE: u16 = 3;
const NFTA_TABLE_HANDLE: u16 = 4;
const NFTA_TABLE_PAD: u16 = 5;
const NFTA_TABLE_USERDATA: u16 = 6;
const NFTA_TABLE_OWNER: u16 = 7;
const NFT_TABLE_F_MASK: u32 = 0x0007;

const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_HANDLE: u16 = 2;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_USE: u16 = 6;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_CHAIN_COUNTERS: u16 = 8;
const NFTA_CHAIN_PAD: u16 = 9;
const NFTA_CHAIN_FLAGS: u16 = 10;
const NFTA_CHAIN_ID: u16 = 11;
const NFTA_CHAIN_USERDATA: u16 = 12;

const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_HOOK_DEV: u16 = 3;
const NFTA_HOOK_DEVS: u16 = 4;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_COMPAT: u16 = 5;
const NFTA_RULE_POSITION: u16 = 6;
const NFTA_RULE_USERDATA: u16 = 7;
const NFTA_RULE_PAD: u16 = 8;
const NFTA_RULE_ID: u16 = 9;
const NFTA_RULE_POSITION_ID: u16 = 10;
const NFTA_RULE_CHAIN_ID: u16 = 11;

const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_META_SREG: u16 = 3;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_PAYLOAD_SREG: u16 = 5;
const NFTA_PAYLOAD_CSUM_TYPE: u16 = 6;
const NFTA_PAYLOAD_CSUM_OFFSET: u16 = 7;
const NFTA_PAYLOAD_CSUM_FLAGS: u16 = 8;
const NFTA_BYTEORDER_SREG: u16 = 1;
const NFTA_BYTEORDER_DREG: u16 = 2;
const NFTA_BYTEORDER_OP: u16 = 3;
const NFTA_BYTEORDER_LEN: u16 = 4;
const NFTA_BYTEORDER_SIZE: u16 = 5;
const NFTA_LIMIT_RATE: u16 = 1;
const NFTA_LIMIT_UNIT: u16 = 2;
const NFTA_LIMIT_BURST: u16 = 3;
const NFTA_LIMIT_TYPE: u16 = 4;
const NFTA_LIMIT_FLAGS: u16 = 5;
const NFTA_LIMIT_PAD: u16 = 6;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_COUNTER_BYTES: u16 = 1;
const NFTA_COUNTER_PACKETS: u16 = 2;
const NFTA_COUNTER_PAD: u16 = 3;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_VERDICT_CHAIN: u16 = 2;
const NFTA_VERDICT_CHAIN_ID: u16 = 3;
const NFNL_BATCH_GENID: u16 = 1;
const NFTA_GEN_ID: u16 = 1;
const NFTA_GEN_PROC_PID: u16 = 2;
const NFTA_GEN_PROC_NAME: u16 = 3;

/// Closed failure classes at the native Relay-fence boundary.
#[derive(Debug, Error)]
pub(super) enum RelayFenceError {
    /// The typed reservation did not describe the one fixed Relay topology.
    #[error("invalid Relay fence binding")]
    Invalid,
    /// The reservation is expired or exceeds the worker's bounded setup TTL.
    #[error("Relay fence reservation is expired or too long")]
    Expired,
    /// The calling thread is not in the retained anonymous worker namespace.
    #[error("Relay fence namespace authority does not match the calling thread")]
    Namespace,
    /// A bounded netlink operation failed.
    #[error("Relay fence netlink I/O failed")]
    Io(#[from] io::Error),
    /// The kernel rejected a fixed request.
    #[error("kernel rejected fixed Relay fence request")]
    Kernel(i32),
    /// A reply or encoding was malformed or ambiguous.
    #[error("Relay fence netlink message was malformed or ambiguous")]
    Malformed,
    /// A fixed byte, frame or object bound was exceeded.
    #[error("Relay fence netlink resource bound was exceeded")]
    Limit,
    /// The nftables generation changed during observation.
    #[error("Relay fence observation raced another nftables mutation")]
    Inconsistent,
    /// The namespace contained policy outside the exact Relay fence lineage.
    #[error("nftables state does not equal the exact Relay fence lineage")]
    UnexpectedPolicy,
    /// The stable generation was not the required successor.
    #[error("nftables generation is not the required Relay fence successor")]
    UnexpectedGeneration,
    /// A possibly-sent mutation could not be reconciled conclusively.
    #[error("Relay fence mutation state is indeterminate; destroy the worker namespace")]
    Indeterminate,
}

/// Thread-bound proof that netfilter access remains inside one anonymous worker namespace.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RelayFenceNamespaceAuthority {
    parent: NetworkNamespaceIdentity,
    worker: NetworkNamespaceIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

impl RelayFenceNamespaceAuthority {
    /// Bind current-thread access to the already authenticated sandbox identities.
    pub(super) fn new(
        parent: NetworkNamespaceIdentity,
        worker: NetworkNamespaceIdentity,
    ) -> Result<Self, RelayFenceError> {
        if parent == worker || current_network_namespace_identity().ok() != Some(worker) {
            return Err(RelayFenceError::Namespace);
        }
        Ok(Self {
            parent,
            worker,
            _thread_bound: PhantomData,
        })
    }

    fn verify(&self) -> Result<(), RelayFenceError> {
        if self.parent == self.worker
            || current_network_namespace_identity().ok() != Some(self.worker)
        {
            Err(RelayFenceError::Namespace)
        } else {
            Ok(())
        }
    }
}

/// Context-bound identity known before either Relay `WireGuard` link exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RelayFenceIdentity {
    route_context_id: [u8; 16],
    path_id: u8,
    table_name: Vec<u8>,
}

impl RelayFenceIdentity {
    /// Derive the one bounded table identity admitted for a Relay path.
    pub(super) fn derive(
        route_context_id: [u8; 16],
        path_id: u32,
    ) -> Result<Self, RelayFenceError> {
        if route_context_id.iter().all(|byte| *byte == 0)
            || !(1..=MAX_HELPER_PATHS).contains(&path_id)
        {
            return Err(RelayFenceError::Invalid);
        }
        let path_id = u8::try_from(path_id).map_err(|_| RelayFenceError::Invalid)?;
        Ok(Self {
            route_context_id,
            path_id,
            table_name: table_name(route_context_id, path_id),
        })
    }

    fn canonical_userdata(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TABLE_USERDATA_DOMAIN.len() + 17);
        bytes.extend_from_slice(TABLE_USERDATA_DOMAIN);
        bytes.extend_from_slice(&self.route_context_id);
        bytes.push(self.path_id);
        bytes
    }
}

/// Complete, secret-free policy derived from authenticated Relay reservation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RelayFenceSpec {
    identity: RelayFenceIdentity,
    relay_client_interface: [u8; INTERFACE_NAME_BYTES],
    relay_exit_interface: [u8; INTERFACE_NAME_BYTES],
    relay_client_ifindex: u32,
    relay_exit_ifindex: u32,
    client_address: Ipv6Addr,
    exit_address: Ipv6Addr,
    expires_at_unix_nanos: u64,
    maximum_up_bytes_per_second: u64,
    maximum_down_bytes_per_second: u64,
}

impl RelayFenceSpec {
    /// Derive the only policy accepted for one validated Relay pair.
    #[allow(
        clippy::too_many_arguments,
        reason = "all six active-policy fields are independently bound"
    )]
    pub(super) fn derive(
        identity: &RelayFenceIdentity,
        relay_client_ifindex: u32,
        relay_exit_ifindex: u32,
        maximum_up_mbps: u32,
        maximum_down_mbps: u32,
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<Self, RelayFenceError> {
        if relay_client_ifindex <= 1
            || relay_exit_ifindex <= 1
            || relay_client_ifindex == relay_exit_ifindex
            || relay_client_ifindex > MAX_KERNEL_IFINDEX
            || relay_exit_ifindex > MAX_KERNEL_IFINDEX
            || maximum_up_mbps == 0
            || maximum_down_mbps == 0
            || maximum_up_mbps > MAX_HELPER_RATE_MBPS
            || maximum_down_mbps > MAX_HELPER_RATE_MBPS
        {
            return Err(RelayFenceError::Invalid);
        }
        expires_at_unix
            .checked_sub(now_unix)
            .filter(|seconds| *seconds > 0 && *seconds <= MAX_FENCE_TTL_SECONDS)
            .ok_or(RelayFenceError::Expired)?;
        let expires_at_unix_nanos = expires_at_unix
            .checked_mul(NANOSECONDS_PER_SECOND)
            .ok_or(RelayFenceError::Invalid)?;
        let relay_client = WireguardLeaseSpec::derive(
            identity.route_context_id,
            ContextRole::Relay,
            u32::from(identity.path_id),
            WireguardRole::RelayClient as i32,
        )
        .map_err(|_| RelayFenceError::Invalid)?;
        let relay_exit = WireguardLeaseSpec::derive(
            identity.route_context_id,
            ContextRole::Relay,
            u32::from(identity.path_id),
            WireguardRole::RelayExit as i32,
        )
        .map_err(|_| RelayFenceError::Invalid)?;
        let relay_client_interface = fixed_interface_name(relay_client.interface())?;
        let relay_exit_interface = fixed_interface_name(relay_exit.interface())?;
        let client_address = relay_client.peer_address();
        let exit_address = relay_exit.peer_address();
        let client_local = relay_client.local_address().octets();
        let exit_local = relay_exit.local_address().octets();
        let client = client_address.octets();
        let exit = exit_address.octets();
        if client[..14] != exit[..14]
            || client[..14] != client_local[..14]
            || client[..14] != exit_local[..14]
            || client[14..] != [0, 1]
            || client_local[14..] != [0, 2]
            || exit_local[14..] != [0, 3]
            || exit[14..] != [0, 4]
        {
            return Err(RelayFenceError::Invalid);
        }

        let specification = Self {
            identity: identity.clone(),
            relay_client_interface,
            relay_exit_interface,
            relay_client_ifindex,
            relay_exit_ifindex,
            client_address,
            exit_address,
            expires_at_unix_nanos,
            maximum_up_bytes_per_second: mbps_to_bytes(maximum_up_mbps),
            maximum_down_bytes_per_second: mbps_to_bytes(maximum_down_mbps),
        };
        if specification.identity.canonical_userdata().len() > MAX_TABLE_USERDATA_BYTES {
            return Err(RelayFenceError::Limit);
        }
        Ok(specification)
    }

    fn expected_rule_expressions(&self, index: usize) -> Vec<ObservedExpression> {
        if index == 2 {
            return vec![
                ObservedExpression::Counter(RelayFenceCounter::ZERO),
                ObservedExpression::ImmediateDrop,
            ];
        }
        let direction = match index {
            0 => RelayFenceDirection {
                input_ifindex: self.relay_client_ifindex,
                output_ifindex: self.relay_exit_ifindex,
                input_interface: self.relay_client_interface,
                output_interface: self.relay_exit_interface,
                source: self.client_address,
                destination: self.exit_address,
                rate: self.maximum_up_bytes_per_second,
            },
            1 => RelayFenceDirection {
                input_ifindex: self.relay_exit_ifindex,
                output_ifindex: self.relay_client_ifindex,
                input_interface: self.relay_exit_interface,
                output_interface: self.relay_client_interface,
                source: self.exit_address,
                destination: self.client_address,
                rate: self.maximum_down_bytes_per_second,
            },
            _ => std::process::abort(),
        };
        interface_expressions(direction)
            .into_iter()
            .chain(address_expressions(direction))
            .chain(expiry_expressions(self.expires_at_unix_nanos))
            .chain([
                ObservedExpression::Limit {
                    rate: direction.rate,
                    unit: 1,
                    burst: RATE_BURST_BYTES,
                    kind: NFT_LIMIT_PKT_BYTES,
                    flags: 0,
                },
                ObservedExpression::Counter(RelayFenceCounter::ZERO),
                ObservedExpression::ImmediateAccept,
            ])
            .collect()
    }
}

#[derive(Clone, Copy)]
struct RelayFenceDirection {
    input_ifindex: u32,
    output_ifindex: u32,
    input_interface: [u8; INTERFACE_NAME_BYTES],
    output_interface: [u8; INTERFACE_NAME_BYTES],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    rate: u64,
}

fn interface_expressions(direction: RelayFenceDirection) -> [ObservedExpression; 10] {
    [
        ObservedExpression::Meta {
            destination: NFT_REG_1,
            key: NFT_META_IIF,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: direction.input_ifindex.to_ne_bytes().to_vec(),
        },
        ObservedExpression::Meta {
            destination: NFT_REG_1,
            key: NFT_META_OIF,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: direction.output_ifindex.to_ne_bytes().to_vec(),
        },
        ObservedExpression::Meta {
            destination: NFT_REG_1,
            key: NFT_META_IIFNAME,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: direction.input_interface.to_vec(),
        },
        ObservedExpression::Meta {
            destination: NFT_REG_1,
            key: NFT_META_OIFNAME,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: direction.output_interface.to_vec(),
        },
        ObservedExpression::Meta {
            destination: NFT_REG_1,
            key: NFT_META_NFPROTO,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: vec![NFPROTO_IPV6],
        },
    ]
}

fn address_expressions(direction: RelayFenceDirection) -> [ObservedExpression; 4] {
    [
        ObservedExpression::Payload {
            destination: NFT_REG_1,
            base: NFT_PAYLOAD_NETWORK_HEADER,
            offset: IPV6_SOURCE_OFFSET,
            length: 16,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: direction.source.octets().to_vec(),
        },
        ObservedExpression::Payload {
            destination: NFT_REG_1,
            base: NFT_PAYLOAD_NETWORK_HEADER,
            offset: IPV6_DESTINATION_OFFSET,
            length: 16,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: direction.destination.octets().to_vec(),
        },
    ]
}

fn expiry_expressions(expires_at_unix_nanos: u64) -> [ObservedExpression; 3] {
    [
        ObservedExpression::Meta {
            destination: NFT_REG_1,
            key: NFT_META_TIME_NS,
        },
        ObservedExpression::Byteorder {
            source: NFT_REG_1,
            destination: NFT_REG_1,
            operation: NFT_BYTEORDER_HTON,
            length: 8,
            size: 8,
        },
        ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_LT,
            value: expires_at_unix_nanos.to_be_bytes().to_vec(),
        },
    ]
}

fn fixed_interface_name(name: &str) -> Result<[u8; INTERFACE_NAME_BYTES], RelayFenceError> {
    if name.is_empty()
        || name.len() >= INTERFACE_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(RelayFenceError::Invalid);
    }
    let mut encoded = [0; INTERFACE_NAME_BYTES];
    encoded[..name.len()].copy_from_slice(name.as_bytes());
    Ok(encoded)
}

fn table_name(route_context_id: [u8; 16], path_id: u8) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = Vec::with_capacity(TABLE_NAME_PREFIX.len() + 32 + 3);
    name.extend_from_slice(TABLE_NAME_PREFIX);
    for byte in route_context_id {
        name.push(HEX[usize::from(byte >> 4)]);
        name.push(HEX[usize::from(byte & 0x0f)]);
    }
    name.extend_from_slice(b"_p");
    name.push(HEX[usize::from(path_id)]);
    name
}

fn mbps_to_bytes(rate_mbps: u32) -> u64 {
    u64::from(rate_mbps) * BITS_PER_MEGABIT / BITS_PER_BYTE
}

/// Stable, completely empty nftables ruleset in the authenticated worker namespace.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "the pristine authority is the only authority that may create the Relay baseline"]
pub(super) struct PristineRelayFence {
    generation: u32,
    namespace: RelayFenceNamespaceAuthority,
}

/// Exact context-bound table and empty policy-drop forward chain.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "the restrictive baseline must be activated or retired"]
pub(super) struct RestrictedPolicyDrop {
    journal: RestrictedRelayFenceJournal,
    namespace: RelayFenceNamespaceAuthority,
}

impl RestrictedPolicyDrop {
    /// Borrow the exact pre-link identity used to derive the later active policy.
    pub(super) const fn identity(&self) -> &RelayFenceIdentity {
        &self.journal.identity
    }
}

/// Armed ownership of one exact installed Relay fence.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "an active Relay fence must be verified or deactivated"]
pub(super) struct ActiveRelayFence {
    journal: ActiveRelayFenceJournal,
    namespace: RelayFenceNamespaceAuthority,
}

/// Proof that the exact Relay baseline was deleted and the namespace is empty again.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RetiredRelayFence {
    generation: u32,
    namespace: RelayFenceNamespaceAuthority,
}

/// Namespace authority retained after a mutation could not be reconciled.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "destroy the anonymous worker namespace to resolve indeterminate nftables ownership"]
pub(super) struct IndeterminateRelayFence {
    namespace: RelayFenceNamespaceAuthority,
    identity: RelayFenceIdentity,
}

#[derive(Debug, Eq, PartialEq)]
struct RestrictedRelayFenceJournal {
    identity: RelayFenceIdentity,
    generation: u32,
    handles: BaselineHandles,
}

#[derive(Debug, Eq, PartialEq)]
struct ActiveRelayFenceJournal {
    specification: RelayFenceSpec,
    generation: u32,
    handles: PolicyHandles,
}

/// Authority preserved when baseline creation fails.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum RelayFenceCreateAuthority {
    /// The fixed baseline transaction was proven absent.
    Pristine(PristineRelayFence),
    /// The transaction may exist; namespace destruction is the only safe recovery.
    Indeterminate(IndeterminateRelayFence),
}

/// Authority preserved when rule activation fails.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum RelayFenceActivateAuthority {
    /// The exact restrictive baseline remains installed.
    Restricted(RestrictedPolicyDrop),
    /// The transaction could not be classified safely.
    Indeterminate(IndeterminateRelayFence),
}

/// Authority preserved when rule deactivation fails.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum RelayFenceDeactivateAuthority {
    /// The exact active policy remains installed and owned.
    Active(Box<ActiveRelayFence>),
    /// The transaction could not be classified safely.
    Indeterminate(IndeterminateRelayFence),
}

/// Authority preserved when baseline retirement fails.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum RelayFenceRetireAuthority {
    /// The exact restrictive baseline remains installed.
    Restricted(RestrictedPolicyDrop),
    /// The transaction could not be classified safely.
    Indeterminate(IndeterminateRelayFence),
}

/// Closed failure plus its affine nftables-lineage authority.
#[derive(Debug)]
pub(super) struct RelayFenceLineageFailure<Authority> {
    pub(super) source: RelayFenceError,
    pub(super) authority: Authority,
}

/// Observe one stable, completely empty ruleset before any mutation is possible.
pub(super) fn observe_pristine_relay_fence(
    namespace: RelayFenceNamespaceAuthority,
    deadline: HardDeadline,
) -> Result<PristineRelayFence, RelayFenceLineageFailure<RelayFenceNamespaceAuthority>> {
    if let Err(source) = namespace.verify() {
        return Err(RelayFenceLineageFailure {
            source,
            authority: namespace,
        });
    }
    match observe_stable_ruleset(deadline) {
        Ok(observed) if observed.snapshot.is_empty() => Ok(PristineRelayFence {
            generation: observed.generation,
            namespace,
        }),
        Ok(_) => Err(RelayFenceLineageFailure {
            source: RelayFenceError::UnexpectedPolicy,
            authority: namespace,
        }),
        Err(source) => Err(RelayFenceLineageFailure {
            source,
            authority: namespace,
        }),
    }
}

/// Atomically create and read back the context-bound policy-drop baseline.
pub(super) fn create_relay_fence_baseline(
    pristine: PristineRelayFence,
    identity: RelayFenceIdentity,
    deadline: HardDeadline,
) -> Result<RestrictedPolicyDrop, RelayFenceLineageFailure<RelayFenceCreateAuthority>> {
    let PristineRelayFence {
        generation,
        namespace,
    } = pristine;
    if let Err(source) = namespace.verify() {
        return Err(create_failure_pristine(source, generation, namespace));
    }
    let Some(expected_generation) = generation.checked_add(1) else {
        return Err(create_failure_pristine(
            RelayFenceError::UnexpectedGeneration,
            generation,
            namespace,
        ));
    };
    let transaction = match encode_create_baseline_transaction(&identity, generation) {
        Ok(value) => value,
        Err(source) => return Err(create_failure_pristine(source, generation, namespace)),
    };
    let mutation_deadline = match deadline.before_tail(RECONCILIATION_TAIL) {
        Ok(value) => value,
        Err(error) => return Err(create_failure_pristine(error.into(), generation, namespace)),
    };
    let client = match MutationClient::connect(mutation_deadline) {
        Ok(value) => value,
        Err(source) => return Err(create_failure_pristine(source, generation, namespace)),
    };
    match client.send(&transaction, mutation_deadline) {
        Err(MutationSendFailure::NotSent(source)) => {
            return Err(create_failure_pristine(source, generation, namespace));
        }
        Err(MutationSendFailure::PossiblySent(source)) => {
            return reconcile_create_baseline(
                source,
                generation,
                expected_generation,
                namespace,
                identity,
                deadline,
            );
        }
        Ok(()) => {}
    }
    if let Err(source) = client.receive_acknowledgements(&transaction, mutation_deadline) {
        return reconcile_create_baseline(
            source,
            generation,
            expected_generation,
            namespace,
            identity,
            deadline,
        );
    }
    reconcile_create_baseline(
        RelayFenceError::Indeterminate,
        generation,
        expected_generation,
        namespace,
        identity,
        deadline,
    )
}

/// Atomically add the two exact accepts and terminal drop to one restrictive baseline.
pub(super) fn activate_relay_fence_rules(
    restricted: RestrictedPolicyDrop,
    specification: RelayFenceSpec,
    deadline: HardDeadline,
) -> Result<ActiveRelayFence, RelayFenceLineageFailure<RelayFenceActivateAuthority>> {
    let RestrictedPolicyDrop { journal, namespace } = restricted;
    if let Err(source) = namespace.verify() {
        return Err(activate_failure_restricted(source, journal, namespace));
    }
    if specification.identity != journal.identity {
        return Err(activate_failure_restricted(
            RelayFenceError::Invalid,
            journal,
            namespace,
        ));
    }
    let Some(expected_generation) = journal.generation.checked_add(1) else {
        return Err(activate_failure_restricted(
            RelayFenceError::UnexpectedGeneration,
            journal,
            namespace,
        ));
    };
    let mutation_deadline = match deadline.before_tail(RECONCILIATION_TAIL) {
        Ok(value) => value,
        Err(error) => {
            return Err(activate_failure_restricted(
                error.into(),
                journal,
                namespace,
            ));
        }
    };
    if let Err(source) = verify_restricted_journal(&journal, mutation_deadline) {
        if source_typestate_is_disproven(&source) {
            return Err(indeterminate(
                namespace,
                journal.identity,
                RelayFenceActivateAuthority::Indeterminate,
            ));
        }
        return Err(activate_failure_restricted(source, journal, namespace));
    }
    let transaction = match encode_activate_rules_transaction(&specification, journal.generation) {
        Ok(value) => value,
        Err(source) => return Err(activate_failure_restricted(source, journal, namespace)),
    };
    let client = match MutationClient::connect(mutation_deadline) {
        Ok(value) => value,
        Err(source) => return Err(activate_failure_restricted(source, journal, namespace)),
    };
    match client.send(&transaction, mutation_deadline) {
        Err(MutationSendFailure::NotSent(source)) => {
            return Err(activate_failure_restricted(source, journal, namespace));
        }
        Err(MutationSendFailure::PossiblySent(source)) => {
            return reconcile_activate_rules(
                source,
                journal,
                expected_generation,
                namespace,
                specification,
                deadline,
            );
        }
        Ok(()) => {}
    }
    if let Err(source) = client.receive_acknowledgements(&transaction, mutation_deadline) {
        return reconcile_activate_rules(
            source,
            journal,
            expected_generation,
            namespace,
            specification,
            deadline,
        );
    }
    reconcile_activate_rules(
        RelayFenceError::Indeterminate,
        journal,
        expected_generation,
        namespace,
        specification,
        deadline,
    )
}

/// Re-observe one active policy and return its three mutable counters.
pub(super) fn verify_active_relay_fence(
    active: &ActiveRelayFence,
    deadline: HardDeadline,
) -> Result<RelayFenceCounters, RelayFenceError> {
    active.namespace.verify()?;
    let observed = observe_stable_ruleset(deadline)?;
    if observed.generation != active.journal.generation {
        return Err(RelayFenceError::UnexpectedGeneration);
    }
    let exact = observed
        .snapshot
        .exact_active_observation(&active.journal.specification, false)?;
    if exact.handles != active.journal.handles {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    Ok(exact.counters)
}

/// Atomically remove all active rules while retaining the exact policy-drop baseline.
pub(super) fn deactivate_relay_fence_rules(
    active: ActiveRelayFence,
    deadline: HardDeadline,
) -> Result<RestrictedPolicyDrop, RelayFenceLineageFailure<RelayFenceDeactivateAuthority>> {
    let ActiveRelayFence { journal, namespace } = active;
    if let Err(source) = namespace.verify() {
        return Err(deactivate_failure_active(source, journal, namespace));
    }
    let Some(expected_generation) = journal.generation.checked_add(1) else {
        return Err(deactivate_failure_active(
            RelayFenceError::UnexpectedGeneration,
            journal,
            namespace,
        ));
    };
    let mutation_deadline = match deadline.before_tail(RECONCILIATION_TAIL) {
        Ok(value) => value,
        Err(error) => return Err(deactivate_failure_active(error.into(), journal, namespace)),
    };
    if let Err(source) = verify_active_journal(&journal, mutation_deadline) {
        if source_typestate_is_disproven(&source) {
            return Err(indeterminate(
                namespace,
                journal.specification.identity,
                RelayFenceDeactivateAuthority::Indeterminate,
            ));
        }
        return Err(deactivate_failure_active(source, journal, namespace));
    }
    let transaction = match encode_deactivate_rules_transaction(&journal) {
        Ok(value) => value,
        Err(source) => return Err(deactivate_failure_active(source, journal, namespace)),
    };
    let client = match MutationClient::connect(mutation_deadline) {
        Ok(value) => value,
        Err(source) => return Err(deactivate_failure_active(source, journal, namespace)),
    };
    match client.send(&transaction, mutation_deadline) {
        Err(MutationSendFailure::NotSent(source)) => {
            return Err(deactivate_failure_active(source, journal, namespace));
        }
        Err(MutationSendFailure::PossiblySent(source)) => {
            return reconcile_deactivate_rules(
                source,
                journal,
                expected_generation,
                namespace,
                deadline,
            );
        }
        Ok(()) => {}
    }
    if let Err(source) = client.receive_acknowledgements(&transaction, mutation_deadline) {
        return reconcile_deactivate_rules(
            source,
            journal,
            expected_generation,
            namespace,
            deadline,
        );
    }
    reconcile_deactivate_rules(
        RelayFenceError::Indeterminate,
        journal,
        expected_generation,
        namespace,
        deadline,
    )
}

/// Atomically delete the restrictive baseline and prove complete semantic absence.
pub(super) fn retire_relay_fence_baseline(
    restricted: RestrictedPolicyDrop,
    deadline: HardDeadline,
) -> Result<RetiredRelayFence, RelayFenceLineageFailure<RelayFenceRetireAuthority>> {
    let RestrictedPolicyDrop { journal, namespace } = restricted;
    if let Err(source) = namespace.verify() {
        return Err(retire_failure_restricted(source, journal, namespace));
    }
    let Some(expected_generation) = journal.generation.checked_add(1) else {
        return Err(retire_failure_restricted(
            RelayFenceError::UnexpectedGeneration,
            journal,
            namespace,
        ));
    };
    let mutation_deadline = match deadline.before_tail(RECONCILIATION_TAIL) {
        Ok(value) => value,
        Err(error) => return Err(retire_failure_restricted(error.into(), journal, namespace)),
    };
    if let Err(source) = verify_restricted_journal(&journal, mutation_deadline) {
        if source_typestate_is_disproven(&source) {
            return Err(indeterminate(
                namespace,
                journal.identity,
                RelayFenceRetireAuthority::Indeterminate,
            ));
        }
        return Err(retire_failure_restricted(source, journal, namespace));
    }
    let transaction = match encode_retire_baseline_transaction(&journal) {
        Ok(value) => value,
        Err(source) => return Err(retire_failure_restricted(source, journal, namespace)),
    };
    let client = match MutationClient::connect(mutation_deadline) {
        Ok(value) => value,
        Err(source) => return Err(retire_failure_restricted(source, journal, namespace)),
    };
    match client.send(&transaction, mutation_deadline) {
        Err(MutationSendFailure::NotSent(source)) => {
            return Err(retire_failure_restricted(source, journal, namespace));
        }
        Err(MutationSendFailure::PossiblySent(source)) => {
            return reconcile_retire_baseline(
                source,
                journal,
                expected_generation,
                namespace,
                deadline,
            );
        }
        Ok(()) => {}
    }
    if let Err(source) = client.receive_acknowledgements(&transaction, mutation_deadline) {
        return reconcile_retire_baseline(
            source,
            journal,
            expected_generation,
            namespace,
            deadline,
        );
    }
    reconcile_retire_baseline(
        RelayFenceError::Indeterminate,
        journal,
        expected_generation,
        namespace,
        deadline,
    )
}

fn verify_restricted_journal(
    journal: &RestrictedRelayFenceJournal,
    deadline: HardDeadline,
) -> Result<(), RelayFenceError> {
    let observed = observe_stable_ruleset(deadline)?;
    if observed.generation != journal.generation {
        return Err(RelayFenceError::UnexpectedGeneration);
    }
    if observed
        .snapshot
        .exact_restricted_observation(&journal.identity)?
        .handles
        != journal.handles
    {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    Ok(())
}

fn verify_active_journal(
    journal: &ActiveRelayFenceJournal,
    deadline: HardDeadline,
) -> Result<(), RelayFenceError> {
    let observed = observe_stable_ruleset(deadline)?;
    if observed.generation != journal.generation {
        return Err(RelayFenceError::UnexpectedGeneration);
    }
    if observed
        .snapshot
        .exact_active_observation(&journal.specification, false)?
        .handles
        != journal.handles
    {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    Ok(())
}

fn source_typestate_is_disproven(source: &RelayFenceError) -> bool {
    matches!(
        source,
        RelayFenceError::UnexpectedPolicy | RelayFenceError::UnexpectedGeneration
    )
}

fn create_failure_pristine(
    source: RelayFenceError,
    generation: u32,
    namespace: RelayFenceNamespaceAuthority,
) -> RelayFenceLineageFailure<RelayFenceCreateAuthority> {
    RelayFenceLineageFailure {
        source,
        authority: RelayFenceCreateAuthority::Pristine(PristineRelayFence {
            generation,
            namespace,
        }),
    }
}

fn activate_failure_restricted(
    source: RelayFenceError,
    journal: RestrictedRelayFenceJournal,
    namespace: RelayFenceNamespaceAuthority,
) -> RelayFenceLineageFailure<RelayFenceActivateAuthority> {
    RelayFenceLineageFailure {
        source,
        authority: RelayFenceActivateAuthority::Restricted(RestrictedPolicyDrop {
            journal,
            namespace,
        }),
    }
}

fn deactivate_failure_active(
    source: RelayFenceError,
    journal: ActiveRelayFenceJournal,
    namespace: RelayFenceNamespaceAuthority,
) -> RelayFenceLineageFailure<RelayFenceDeactivateAuthority> {
    RelayFenceLineageFailure {
        source,
        authority: RelayFenceDeactivateAuthority::Active(Box::new(ActiveRelayFence {
            journal,
            namespace,
        })),
    }
}

fn retire_failure_restricted(
    source: RelayFenceError,
    journal: RestrictedRelayFenceJournal,
    namespace: RelayFenceNamespaceAuthority,
) -> RelayFenceLineageFailure<RelayFenceRetireAuthority> {
    RelayFenceLineageFailure {
        source,
        authority: RelayFenceRetireAuthority::Restricted(RestrictedPolicyDrop {
            journal,
            namespace,
        }),
    }
}

fn indeterminate<Authority>(
    namespace: RelayFenceNamespaceAuthority,
    identity: RelayFenceIdentity,
    wrap: impl FnOnce(IndeterminateRelayFence) -> Authority,
) -> RelayFenceLineageFailure<Authority> {
    RelayFenceLineageFailure {
        source: RelayFenceError::Indeterminate,
        authority: wrap(IndeterminateRelayFence {
            namespace,
            identity,
        }),
    }
}

fn reconcile_create_baseline(
    source: RelayFenceError,
    initial_generation: u32,
    expected_generation: u32,
    namespace: RelayFenceNamespaceAuthority,
    identity: RelayFenceIdentity,
    deadline: HardDeadline,
) -> Result<RestrictedPolicyDrop, RelayFenceLineageFailure<RelayFenceCreateAuthority>> {
    let classification = observe_stable_ruleset(deadline)
        .map(|observed| {
            classify_create_baseline(
                &observed,
                initial_generation,
                expected_generation,
                &identity,
            )
        })
        .unwrap_or(AdjacentState::Indeterminate);
    match classification {
        AdjacentState::Source => Err(create_failure_pristine(
            source,
            initial_generation,
            namespace,
        )),
        AdjacentState::Destination(exact) => Ok(RestrictedPolicyDrop {
            journal: RestrictedRelayFenceJournal {
                identity,
                generation: expected_generation,
                handles: exact.handles,
            },
            namespace,
        }),
        AdjacentState::Indeterminate => Err(indeterminate(
            namespace,
            identity,
            RelayFenceCreateAuthority::Indeterminate,
        )),
    }
}

fn reconcile_activate_rules(
    source: RelayFenceError,
    restricted: RestrictedRelayFenceJournal,
    expected_generation: u32,
    namespace: RelayFenceNamespaceAuthority,
    specification: RelayFenceSpec,
    deadline: HardDeadline,
) -> Result<ActiveRelayFence, RelayFenceLineageFailure<RelayFenceActivateAuthority>> {
    let classification = observe_stable_ruleset(deadline)
        .map(|observed| {
            classify_activate_rules(&observed, &restricted, expected_generation, &specification)
        })
        .unwrap_or(AdjacentState::Indeterminate);
    match classification {
        AdjacentState::Source => Err(activate_failure_restricted(source, restricted, namespace)),
        AdjacentState::Destination(exact) => Ok(ActiveRelayFence {
            journal: ActiveRelayFenceJournal {
                specification,
                generation: expected_generation,
                handles: exact.handles,
            },
            namespace,
        }),
        AdjacentState::Indeterminate => Err(indeterminate(
            namespace,
            restricted.identity,
            RelayFenceActivateAuthority::Indeterminate,
        )),
    }
}

fn reconcile_deactivate_rules(
    source: RelayFenceError,
    active: ActiveRelayFenceJournal,
    expected_generation: u32,
    namespace: RelayFenceNamespaceAuthority,
    deadline: HardDeadline,
) -> Result<RestrictedPolicyDrop, RelayFenceLineageFailure<RelayFenceDeactivateAuthority>> {
    let classification = observe_stable_ruleset(deadline)
        .map(|observed| classify_deactivate_rules(&observed, &active, expected_generation))
        .unwrap_or(AdjacentState::Indeterminate);
    match classification {
        AdjacentState::Source => Err(deactivate_failure_active(source, active, namespace)),
        AdjacentState::Destination(exact) => Ok(RestrictedPolicyDrop {
            journal: RestrictedRelayFenceJournal {
                identity: active.specification.identity,
                generation: expected_generation,
                handles: exact.handles,
            },
            namespace,
        }),
        AdjacentState::Indeterminate => Err(indeterminate(
            namespace,
            active.specification.identity,
            RelayFenceDeactivateAuthority::Indeterminate,
        )),
    }
}

fn reconcile_retire_baseline(
    source: RelayFenceError,
    restricted: RestrictedRelayFenceJournal,
    expected_generation: u32,
    namespace: RelayFenceNamespaceAuthority,
    deadline: HardDeadline,
) -> Result<RetiredRelayFence, RelayFenceLineageFailure<RelayFenceRetireAuthority>> {
    let classification = observe_stable_ruleset(deadline)
        .map(|observed| classify_retire_baseline(&observed, &restricted, expected_generation))
        .unwrap_or(AdjacentState::Indeterminate);
    match classification {
        AdjacentState::Source => Err(retire_failure_restricted(source, restricted, namespace)),
        AdjacentState::Destination(()) => Ok(RetiredRelayFence {
            generation: expected_generation,
            namespace,
        }),
        AdjacentState::Indeterminate => Err(indeterminate(
            namespace,
            restricted.identity,
            RelayFenceRetireAuthority::Indeterminate,
        )),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum AdjacentState<Destination> {
    Source,
    Destination(Destination),
    Indeterminate,
}

fn classify_create_baseline(
    observed: &StableRuleset,
    initial_generation: u32,
    expected_generation: u32,
    identity: &RelayFenceIdentity,
) -> AdjacentState<ExactRestrictedObservation> {
    if observed.generation == initial_generation && observed.snapshot.is_empty() {
        AdjacentState::Source
    } else if observed.generation == expected_generation {
        observed
            .snapshot
            .exact_restricted_observation(identity)
            .map(AdjacentState::Destination)
            .unwrap_or(AdjacentState::Indeterminate)
    } else {
        AdjacentState::Indeterminate
    }
}

fn classify_activate_rules(
    observed: &StableRuleset,
    restricted: &RestrictedRelayFenceJournal,
    expected_generation: u32,
    specification: &RelayFenceSpec,
) -> AdjacentState<ExactPolicyObservation> {
    if observed.generation == restricted.generation {
        match observed
            .snapshot
            .exact_restricted_observation(&restricted.identity)
        {
            Ok(exact) if exact.handles == restricted.handles => AdjacentState::Source,
            Ok(_) | Err(_) => AdjacentState::Indeterminate,
        }
    } else if observed.generation == expected_generation {
        match observed
            .snapshot
            .exact_active_observation(specification, true)
        {
            Ok(exact) if exact.handles.baseline == restricted.handles => {
                AdjacentState::Destination(exact)
            }
            Ok(_) | Err(_) => AdjacentState::Indeterminate,
        }
    } else {
        AdjacentState::Indeterminate
    }
}

fn classify_deactivate_rules(
    observed: &StableRuleset,
    active: &ActiveRelayFenceJournal,
    expected_generation: u32,
) -> AdjacentState<ExactRestrictedObservation> {
    if observed.generation == active.generation {
        match observed
            .snapshot
            .exact_active_observation(&active.specification, false)
        {
            Ok(exact) if exact.handles == active.handles => AdjacentState::Source,
            Ok(_) | Err(_) => AdjacentState::Indeterminate,
        }
    } else if observed.generation == expected_generation {
        match observed
            .snapshot
            .exact_restricted_observation(&active.specification.identity)
        {
            Ok(exact) if exact.handles == active.handles.baseline => {
                AdjacentState::Destination(exact)
            }
            Ok(_) | Err(_) => AdjacentState::Indeterminate,
        }
    } else {
        AdjacentState::Indeterminate
    }
}

fn classify_retire_baseline(
    observed: &StableRuleset,
    restricted: &RestrictedRelayFenceJournal,
    expected_generation: u32,
) -> AdjacentState<()> {
    if observed.generation == restricted.generation {
        match observed
            .snapshot
            .exact_restricted_observation(&restricted.identity)
        {
            Ok(exact) if exact.handles == restricted.handles => AdjacentState::Source,
            Ok(_) | Err(_) => AdjacentState::Indeterminate,
        }
    } else if observed.generation == expected_generation && observed.snapshot.is_empty() {
        AdjacentState::Destination(())
    } else {
        AdjacentState::Indeterminate
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BaselineHandles {
    table: u64,
    chain: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyHandles {
    baseline: BaselineHandles,
    rules: [u64; 3],
}

/// Mutable counters observed from the two accepted directions and terminal drop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RelayFenceCounters([RelayFenceCounter; 3]);

impl RelayFenceCounters {
    /// Prove strict packet and byte growth on both permitted directions.
    pub(super) fn both_allowed_directions_grew_since(&self, earlier: &Self) -> bool {
        self.0[..2]
            .iter()
            .zip(&earlier.0[..2])
            .all(|(current, previous)| {
                current.packets > previous.packets && current.bytes > previous.bytes
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelayFenceCounter {
    bytes: u64,
    packets: u64,
}

impl RelayFenceCounter {
    const ZERO: Self = Self {
        bytes: 0,
        packets: 0,
    };
}

#[derive(Debug, Eq, PartialEq)]
struct ExactPolicyObservation {
    handles: PolicyHandles,
    counters: RelayFenceCounters,
}

#[derive(Debug, Eq, PartialEq)]
struct ExactRestrictedObservation {
    handles: BaselineHandles,
}

#[derive(Debug, Eq, PartialEq)]
enum ObservedExpression {
    Meta {
        destination: u32,
        key: u32,
    },
    Compare {
        source: u32,
        operation: u32,
        value: Vec<u8>,
    },
    Payload {
        destination: u32,
        base: u32,
        offset: u32,
        length: u32,
    },
    Byteorder {
        source: u32,
        destination: u32,
        operation: u32,
        length: u32,
        size: u32,
    },
    Limit {
        rate: u64,
        unit: u64,
        burst: u32,
        kind: u32,
        flags: u32,
    },
    Counter(RelayFenceCounter),
    ImmediateAccept,
    ImmediateDrop,
}

#[derive(Debug, Eq, PartialEq)]
struct TableRecord {
    family: u8,
    name: Vec<u8>,
    flags: u32,
    use_count: u32,
    handle: u64,
    pad: bool,
    userdata: Option<Vec<u8>>,
    owner: Option<u32>,
}

#[derive(Debug, Eq, PartialEq)]
struct ChainRecord {
    family: u8,
    table: Vec<u8>,
    name: Vec<u8>,
    handle: u64,
    hook_number: u32,
    hook_priority: i32,
    policy: u32,
    use_count: u32,
    chain_type: Vec<u8>,
    flags: u32,
    counters: Option<Vec<u8>>,
    pad: bool,
    id: Option<u32>,
    userdata: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
struct RuleRecord {
    family: u8,
    table: Vec<u8>,
    chain: Vec<u8>,
    handle: u64,
    position: Option<u64>,
    expressions: Vec<ObservedExpression>,
    userdata: Option<Vec<u8>>,
    pad: bool,
}

#[derive(Default)]
struct RulesetSnapshot {
    tables: Vec<TableRecord>,
    chains: Vec<ChainRecord>,
    rules: Vec<RuleRecord>,
}

impl RulesetSnapshot {
    fn ingest(
        &mut self,
        kind: ObjectKind,
        payload: &[u8],
        expected_generation: u32,
    ) -> Result<(), RelayFenceError> {
        match kind {
            ObjectKind::Table => {
                if self.tables.len() >= MAX_OBSERVED_TABLES {
                    return Err(RelayFenceError::Limit);
                }
                self.tables
                    .push(parse_table_payload(payload, expected_generation)?);
                Ok(())
            }
            ObjectKind::Chain => {
                if self.chains.len() >= MAX_OBSERVED_CHAINS {
                    return Err(RelayFenceError::Limit);
                }
                self.chains
                    .push(parse_chain_payload(payload, expected_generation)?);
                Ok(())
            }
            ObjectKind::Rule => {
                if self.rules.len() >= MAX_OBSERVED_RULES {
                    return Err(RelayFenceError::Limit);
                }
                self.rules
                    .push(parse_rule_payload(payload, expected_generation)?);
                Ok(())
            }
            ObjectKind::Set | ObjectKind::Object | ObjectKind::Flowtable => {
                validate_unexpected_object_header(payload, expected_generation)?;
                Err(RelayFenceError::UnexpectedPolicy)
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.tables.is_empty() && self.chains.is_empty() && self.rules.is_empty()
    }

    fn exact_restricted_observation(
        &self,
        identity: &RelayFenceIdentity,
    ) -> Result<ExactRestrictedObservation, RelayFenceError> {
        if !self.rules.is_empty() {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        Ok(ExactRestrictedObservation {
            handles: self.exact_baseline_handles(identity, 0)?,
        })
    }

    fn exact_active_observation(
        &self,
        specification: &RelayFenceSpec,
        require_zero: bool,
    ) -> Result<ExactPolicyObservation, RelayFenceError> {
        let baseline = self.exact_baseline_handles(&specification.identity, 3)?;
        let [up, down, terminal] = self.rules.as_slice() else {
            return Err(RelayFenceError::UnexpectedPolicy);
        };
        if [up, down, terminal].iter().any(|rule| {
            rule.family != NFPROTO_INET
                || rule.table != specification.identity.table_name
                || rule.chain != FORWARD_CHAIN_NAME
                || rule.handle == 0
                || rule.userdata.is_some()
                || rule.pad
        }) || up.handle == down.handle
            || up.handle == terminal.handle
            || down.handle == terminal.handle
            || up.position.is_some()
            || down.position != Some(up.handle)
            || terminal.position != Some(down.handle)
        {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        let counters = [
            exact_rule_counter(specification, 0, &up.expressions)?,
            exact_rule_counter(specification, 1, &down.expressions)?,
            exact_rule_counter(specification, 2, &terminal.expressions)?,
        ];
        if require_zero && counters != [RelayFenceCounter::ZERO; 3] {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        Ok(ExactPolicyObservation {
            handles: PolicyHandles {
                baseline,
                rules: [up.handle, down.handle, terminal.handle],
            },
            counters: RelayFenceCounters(counters),
        })
    }

    fn exact_baseline_handles(
        &self,
        identity: &RelayFenceIdentity,
        expected_chain_use: u32,
    ) -> Result<BaselineHandles, RelayFenceError> {
        let [table] = self.tables.as_slice() else {
            return Err(RelayFenceError::UnexpectedPolicy);
        };
        if table.family != NFPROTO_INET
            || table.name != identity.table_name
            || table.flags != 0
            || table.use_count != 1
            || table.handle == 0
            || table.pad
            || table.userdata.as_deref() != Some(identity.canonical_userdata().as_slice())
            || table.owner.is_some()
        {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        let [chain] = self.chains.as_slice() else {
            return Err(RelayFenceError::UnexpectedPolicy);
        };
        if chain.family != NFPROTO_INET
            || chain.table != identity.table_name
            || chain.name != FORWARD_CHAIN_NAME
            || chain.handle == 0
            || chain.hook_number != NF_INET_FORWARD
            || chain.hook_priority != 0
            || chain.policy != NF_DROP
            || chain.use_count != expected_chain_use
            || chain.chain_type != FILTER_CHAIN_TYPE
            || chain.flags != NFT_CHAIN_BASE
            || chain.counters.is_some()
            || chain.pad
            || chain.id.is_some()
            || chain.userdata.is_some()
        {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        Ok(BaselineHandles {
            table: table.handle,
            chain: chain.handle,
        })
    }
}

fn exact_rule_counter(
    specification: &RelayFenceSpec,
    index: usize,
    expressions: &[ObservedExpression],
) -> Result<RelayFenceCounter, RelayFenceError> {
    let expected = specification.expected_rule_expressions(index);
    if expressions.len() != expected.len() {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    let counter_index = expressions
        .len()
        .checked_sub(2)
        .ok_or(RelayFenceError::UnexpectedPolicy)?;
    let ObservedExpression::Counter(counter) = expressions[counter_index] else {
        return Err(RelayFenceError::UnexpectedPolicy);
    };
    for (position, (observed, expected)) in expressions.iter().zip(&expected).enumerate() {
        if position != counter_index && observed != expected {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
    }
    Ok(counter)
}

#[derive(Clone, Copy)]
struct MutationRequest {
    header: [u8; NLMSG_HEADER_LEN],
    acknowledgement_required: bool,
}

struct MutationTransaction {
    bytes: Vec<u8>,
    requests: Vec<MutationRequest>,
}

impl MutationTransaction {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            requests: Vec::new(),
        }
    }

    fn push(
        &mut self,
        message_type: u16,
        flags: u16,
        sequence: u32,
        payload: &[u8],
    ) -> Result<(), RelayFenceError> {
        if self.requests.len() >= MAX_MUTATION_MESSAGES {
            return Err(RelayFenceError::Limit);
        }
        let message = encode_mutation_message(message_type, flags, sequence, payload)?;
        if self
            .bytes
            .len()
            .checked_add(message.len())
            .is_none_or(|length| length > MAX_MUTATION_BATCH_BYTES)
        {
            return Err(RelayFenceError::Limit);
        }
        let header = message[..NLMSG_HEADER_LEN]
            .try_into()
            .map_err(|_| RelayFenceError::Malformed)?;
        self.requests.push(MutationRequest {
            header,
            acknowledgement_required: flags & NLM_F_ACK != 0,
        });
        self.bytes.extend(message);
        Ok(())
    }

    fn finish(self, messages: usize, acknowledgements: usize) -> Result<Self, RelayFenceError> {
        if self.requests.len() != messages
            || self
                .requests
                .iter()
                .filter(|request| request.acknowledgement_required)
                .count()
                != acknowledgements
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_MUTATION_BATCH_BYTES
        {
            return Err(RelayFenceError::Malformed);
        }
        Ok(self)
    }
}

fn encode_create_baseline_transaction(
    identity: &RelayFenceIdentity,
    generation: u32,
) -> Result<MutationTransaction, RelayFenceError> {
    let mut transaction = MutationTransaction::new();
    transaction.push(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        &encode_batch_boundary_payload(Some(generation))?,
    )?;

    let mut table = encode_request_nfgen(NFPROTO_INET, 0);
    encode_attribute(
        &mut table,
        NFTA_TABLE_NAME,
        &encode_nul_string(&identity.table_name)?,
    )?;
    encode_attribute(&mut table, NFTA_TABLE_FLAGS, &0_u32.to_be_bytes())?;
    encode_attribute(
        &mut table,
        NFTA_TABLE_USERDATA,
        &identity.canonical_userdata(),
    )?;
    transaction.push(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        2,
        &table,
    )?;

    let mut hook = Vec::new();
    encode_attribute(&mut hook, NFTA_HOOK_HOOKNUM, &NF_INET_FORWARD.to_be_bytes())?;
    encode_attribute(&mut hook, NFTA_HOOK_PRIORITY, &0_i32.to_be_bytes())?;
    let mut chain = encode_request_nfgen(NFPROTO_INET, 0);
    encode_attribute(
        &mut chain,
        NFTA_CHAIN_TABLE,
        &encode_nul_string(&identity.table_name)?,
    )?;
    encode_attribute(
        &mut chain,
        NFTA_CHAIN_NAME,
        &encode_nul_string(FORWARD_CHAIN_NAME)?,
    )?;
    encode_attribute(
        &mut chain,
        NFTA_CHAIN_TYPE,
        &encode_nul_string(FILTER_CHAIN_TYPE)?,
    )?;
    encode_attribute(&mut chain, NFTA_CHAIN_HOOK | NLA_F_NESTED, &hook)?;
    encode_attribute(&mut chain, NFTA_CHAIN_POLICY, &NF_DROP.to_be_bytes())?;
    transaction.push(
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        3,
        &chain,
    )?;

    transaction.push(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        4,
        &encode_batch_boundary_payload(None)?,
    )?;
    transaction.finish(4, 2)
}

fn encode_activate_rules_transaction(
    specification: &RelayFenceSpec,
    generation: u32,
) -> Result<MutationTransaction, RelayFenceError> {
    let mut transaction = MutationTransaction::new();
    transaction.push(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        &encode_batch_boundary_payload(Some(generation))?,
    )?;

    for (sequence, rule_index) in [(2, 0), (3, 1), (4, 2)] {
        let mut rule = encode_request_nfgen(NFPROTO_INET, 0);
        encode_attribute(
            &mut rule,
            NFTA_RULE_TABLE,
            &encode_nul_string(&specification.identity.table_name)?,
        )?;
        encode_attribute(
            &mut rule,
            NFTA_RULE_CHAIN,
            &encode_nul_string(FORWARD_CHAIN_NAME)?,
        )?;
        encode_attribute(
            &mut rule,
            NFTA_RULE_EXPRESSIONS | NLA_F_NESTED,
            &encode_policy_expressions(&specification.expected_rule_expressions(rule_index))?,
        )?;
        transaction.push(
            NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
            sequence,
            &rule,
        )?;
    }
    transaction.push(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        5,
        &encode_batch_boundary_payload(None)?,
    )?;
    transaction.finish(5, 3)
}

fn encode_deactivate_rules_transaction(
    journal: &ActiveRelayFenceJournal,
) -> Result<MutationTransaction, RelayFenceError> {
    if !valid_policy_handles(journal.handles) {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    let mut transaction = MutationTransaction::new();
    transaction.push(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        &encode_batch_boundary_payload(Some(journal.generation))?,
    )?;

    for (sequence, handle) in [
        (2, journal.handles.rules[2]),
        (3, journal.handles.rules[1]),
        (4, journal.handles.rules[0]),
    ] {
        let mut delete = encode_request_nfgen(NFPROTO_INET, 0);
        encode_attribute(
            &mut delete,
            NFTA_RULE_TABLE,
            &encode_nul_string(&journal.specification.identity.table_name)?,
        )?;
        encode_attribute(
            &mut delete,
            NFTA_RULE_CHAIN,
            &encode_nul_string(FORWARD_CHAIN_NAME)?,
        )?;
        encode_attribute(&mut delete, NFTA_RULE_HANDLE, &handle.to_be_bytes())?;
        transaction.push(
            NFT_MSG_DELRULE,
            NLM_F_REQUEST | NLM_F_ACK,
            sequence,
            &delete,
        )?;
    }
    transaction.push(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        5,
        &encode_batch_boundary_payload(None)?,
    )?;
    transaction.finish(5, 3)
}

fn encode_retire_baseline_transaction(
    journal: &RestrictedRelayFenceJournal,
) -> Result<MutationTransaction, RelayFenceError> {
    if journal.handles.table == 0 || journal.handles.chain == 0 {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    let mut transaction = MutationTransaction::new();
    transaction.push(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        &encode_batch_boundary_payload(Some(journal.generation))?,
    )?;
    let mut delete = encode_request_nfgen(NFPROTO_INET, 0);
    encode_attribute(
        &mut delete,
        NFTA_TABLE_HANDLE,
        &journal.handles.table.to_be_bytes(),
    )?;
    transaction.push(NFT_MSG_DELTABLE, NLM_F_REQUEST | NLM_F_ACK, 2, &delete)?;
    transaction.push(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        3,
        &encode_batch_boundary_payload(None)?,
    )?;
    transaction.finish(3, 1)
}

fn valid_policy_handles(handles: PolicyHandles) -> bool {
    handles.baseline.table != 0
        && handles.baseline.chain != 0
        && handles.rules.iter().all(|handle| *handle != 0)
        && handles.rules[0] != handles.rules[1]
        && handles.rules[0] != handles.rules[2]
        && handles.rules[1] != handles.rules[2]
}

fn encode_policy_expressions(
    expressions: &[ObservedExpression],
) -> Result<Vec<u8>, RelayFenceError> {
    if !matches!(
        expressions.len(),
        DIRECTION_RULE_EXPRESSIONS | TERMINAL_RULE_EXPRESSIONS
    ) {
        return Err(RelayFenceError::Malformed);
    }
    let mut encoded = Vec::new();
    for expression in expressions {
        let (name, data) = encode_policy_expression(expression)?;
        let mut element = Vec::new();
        encode_attribute(&mut element, NFTA_EXPR_NAME, &encode_nul_string(name)?)?;
        encode_attribute(&mut element, NFTA_EXPR_DATA | NLA_F_NESTED, &data)?;
        encode_attribute(&mut encoded, NFTA_LIST_ELEM | NLA_F_NESTED, &element)?;
    }
    Ok(encoded)
}

fn encode_policy_expression(
    expression: &ObservedExpression,
) -> Result<(&'static [u8], Vec<u8>), RelayFenceError> {
    match expression {
        ObservedExpression::Meta { destination, key } => {
            let mut data = Vec::new();
            encode_attribute(&mut data, NFTA_META_KEY, &key.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_META_DREG, &destination.to_be_bytes())?;
            Ok((b"meta", data))
        }
        ObservedExpression::Compare {
            source,
            operation,
            value,
        } => {
            if value.is_empty() || value.len() > 16 {
                return Err(RelayFenceError::Malformed);
            }
            let mut nested_value = Vec::new();
            encode_attribute(&mut nested_value, NFTA_DATA_VALUE, value)?;
            let mut data = Vec::new();
            encode_attribute(&mut data, NFTA_CMP_SREG, &source.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_CMP_OP, &operation.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_CMP_DATA | NLA_F_NESTED, &nested_value)?;
            Ok((b"cmp", data))
        }
        ObservedExpression::Payload {
            destination,
            base,
            offset,
            length,
        } => {
            let mut data = Vec::new();
            encode_attribute(&mut data, NFTA_PAYLOAD_DREG, &destination.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_PAYLOAD_BASE, &base.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_PAYLOAD_OFFSET, &offset.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_PAYLOAD_LEN, &length.to_be_bytes())?;
            Ok((b"payload", data))
        }
        ObservedExpression::Byteorder {
            source,
            destination,
            operation,
            length,
            size,
        } => {
            let mut data = Vec::new();
            encode_attribute(&mut data, NFTA_BYTEORDER_SREG, &source.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_BYTEORDER_DREG, &destination.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_BYTEORDER_OP, &operation.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_BYTEORDER_LEN, &length.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_BYTEORDER_SIZE, &size.to_be_bytes())?;
            Ok((b"byteorder", data))
        }
        ObservedExpression::Limit {
            rate,
            unit,
            burst,
            kind,
            flags,
        } => {
            let mut data = Vec::new();
            encode_attribute(&mut data, NFTA_LIMIT_RATE, &rate.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_LIMIT_UNIT, &unit.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_LIMIT_BURST, &burst.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_LIMIT_TYPE, &kind.to_be_bytes())?;
            encode_attribute(&mut data, NFTA_LIMIT_FLAGS, &flags.to_be_bytes())?;
            Ok((b"limit", data))
        }
        ObservedExpression::Counter(counter) => {
            let mut data = Vec::new();
            encode_attribute(&mut data, NFTA_COUNTER_BYTES, &counter.bytes.to_be_bytes())?;
            encode_attribute(
                &mut data,
                NFTA_COUNTER_PACKETS,
                &counter.packets.to_be_bytes(),
            )?;
            Ok((b"counter", data))
        }
        ObservedExpression::ImmediateAccept | ObservedExpression::ImmediateDrop => {
            let code = if matches!(expression, ObservedExpression::ImmediateAccept) {
                NF_ACCEPT
            } else {
                NF_DROP
            };
            encode_immediate_expression(code)
        }
    }
}

fn encode_immediate_expression(code: u32) -> Result<(&'static [u8], Vec<u8>), RelayFenceError> {
    let mut verdict = Vec::new();
    encode_attribute(&mut verdict, NFTA_VERDICT_CODE, &code.to_be_bytes())?;
    let mut nested_verdict = Vec::new();
    encode_attribute(
        &mut nested_verdict,
        NFTA_DATA_VERDICT | NLA_F_NESTED,
        &verdict,
    )?;
    let mut data = Vec::new();
    encode_attribute(
        &mut data,
        NFTA_IMMEDIATE_DREG,
        &NFT_REG_VERDICT.to_be_bytes(),
    )?;
    encode_attribute(
        &mut data,
        NFTA_IMMEDIATE_DATA | NLA_F_NESTED,
        &nested_verdict,
    )?;
    Ok((b"immediate", data))
}

fn encode_batch_boundary_payload(generation: Option<u32>) -> Result<Vec<u8>, RelayFenceError> {
    let mut payload = encode_request_nfgen(AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
    if let Some(generation) = generation {
        encode_attribute(&mut payload, NFNL_BATCH_GENID, &generation.to_be_bytes())?;
    }
    Ok(payload)
}

fn encode_request_nfgen(family: u8, resource_id: u16) -> Vec<u8> {
    let mut payload = vec![family, NFNETLINK_V0];
    payload.extend(resource_id.to_be_bytes());
    payload
}

fn encode_attribute(
    output: &mut Vec<u8>,
    kind: u16,
    payload: &[u8],
) -> Result<(), RelayFenceError> {
    if kind & NLA_TYPE_MASK == 0 {
        return Err(RelayFenceError::Malformed);
    }
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(RelayFenceError::Limit)?;
    let encoded_length = u16::try_from(length).map_err(|_| RelayFenceError::Limit)?;
    let aligned = align4(length)?;
    let new_length = output
        .len()
        .checked_add(aligned)
        .ok_or(RelayFenceError::Limit)?;
    if new_length > MAX_MUTATION_BATCH_BYTES {
        return Err(RelayFenceError::Limit);
    }
    output.extend(encoded_length.to_ne_bytes());
    output.extend(kind.to_ne_bytes());
    output.extend(payload);
    output.resize(new_length, 0);
    Ok(())
}

fn encode_nul_string(value: &[u8]) -> Result<Vec<u8>, RelayFenceError> {
    if value.is_empty() || value.contains(&0) || value.len() >= MAX_TABLE_NAME_BYTES {
        return Err(RelayFenceError::Malformed);
    }
    let mut encoded = Vec::with_capacity(value.len() + 1);
    encoded.extend_from_slice(value);
    encoded.push(0);
    Ok(encoded)
}

fn encode_mutation_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, RelayFenceError> {
    if sequence == 0 || flags & NLM_F_REQUEST == 0 {
        return Err(RelayFenceError::Malformed);
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(RelayFenceError::Limit)?;
    let aligned = align4(length)?;
    if aligned > MAX_MUTATION_BATCH_BYTES {
        return Err(RelayFenceError::Limit);
    }
    let mut message = Vec::with_capacity(aligned);
    message.extend(
        u32::try_from(length)
            .map_err(|_| RelayFenceError::Limit)?
            .to_ne_bytes(),
    );
    message.extend(message_type.to_ne_bytes());
    message.extend(flags.to_ne_bytes());
    message.extend(sequence.to_ne_bytes());
    message.extend(0_u32.to_ne_bytes());
    message.extend(payload);
    message.resize(aligned, 0);
    Ok(message)
}

struct MutationClient {
    socket: Socket,
    local_port: u32,
}

enum MutationSendFailure {
    NotSent(RelayFenceError),
    PossiblySent(RelayFenceError),
}

struct MutationAckState<'a> {
    local_port: u32,
    requests: &'a [MutationRequest],
    acknowledged: Vec<bool>,
}

impl MutationClient {
    fn connect(deadline: HardDeadline) -> Result<Self, RelayFenceError> {
        deadline.ensure_remaining()?;
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.set_netlink_get_strict_chk(true)?;
        socket.set_cap_ack(true)?;
        if !socket.get_cap_ack()? {
            return Err(RelayFenceError::Malformed);
        }
        socket.set_non_blocking(true)?;
        let address = socket.bind_auto()?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(RelayFenceError::Malformed);
        }
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_remaining()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
        })
    }

    fn send(
        &self,
        transaction: &MutationTransaction,
        deadline: HardDeadline,
    ) -> Result<(), MutationSendFailure> {
        if transaction.bytes.is_empty()
            || transaction.bytes.len() > MAX_MUTATION_BATCH_BYTES
            || transaction.requests.is_empty()
            || transaction.requests.len() > MAX_MUTATION_MESSAGES
        {
            return Err(MutationSendFailure::NotSent(RelayFenceError::Limit));
        }
        loop {
            if let Err(error) = deadline.ensure_remaining() {
                return Err(MutationSendFailure::NotSent(error.into()));
            }
            match self.socket.send(&transaction.bytes, 0) {
                Ok(written) if written == transaction.bytes.len() => {
                    return deadline
                        .ensure_remaining()
                        .map_err(RelayFenceError::from)
                        .map_err(MutationSendFailure::PossiblySent);
                }
                Ok(_) => {
                    return Err(MutationSendFailure::PossiblySent(
                        io::Error::new(io::ErrorKind::WriteZero, "short netlink transaction")
                            .into(),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(error) = wait_for_socket(&self.socket, PollFlags::POLLOUT, deadline)
                    {
                        return Err(MutationSendFailure::NotSent(error));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(MutationSendFailure::NotSent(error.into()));
                }
            }
        }
    }

    fn receive_acknowledgements(
        &self,
        transaction: &MutationTransaction,
        deadline: HardDeadline,
    ) -> Result<(), RelayFenceError> {
        let acknowledgement_count = transaction
            .requests
            .iter()
            .filter(|request| request.acknowledgement_required)
            .count();
        if acknowledgement_count == 0 || acknowledgement_count > MAX_MUTATION_ACK_FRAMES {
            return Err(RelayFenceError::Limit);
        }
        let mut state = MutationAckState::new(self.local_port, &transaction.requests);
        let mut budget = CollectionBudget {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_MUTATION_ACK_BYTES,
            max_datagrams: MAX_MUTATION_ACK_DATAGRAMS,
            max_frames: MAX_MUTATION_ACK_FRAMES,
        };
        while !state.is_complete() {
            let (bytes, sender) = receive_bounded(&self.socket, deadline, &budget)?;
            state.ingest(sender, &bytes, &mut budget)?;
        }
        deadline.ensure_remaining()?;
        state.finish()
    }
}

impl<'a> MutationAckState<'a> {
    fn new(local_port: u32, requests: &'a [MutationRequest]) -> Self {
        Self {
            local_port,
            requests,
            acknowledged: vec![false; requests.len()],
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), RelayFenceError> {
        if sender != SocketAddr::new(0, 0) || self.is_complete() {
            return Err(RelayFenceError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), RelayFenceError> {
        if frame.len() != NLMSG_HEADER_LEN + 4 + NLMSG_HEADER_LEN
            || read_ne_u16(frame, 4)? != NLMSG_ERROR
            || read_ne_u16(frame, 6)? != NLM_F_CAPPED
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(RelayFenceError::Malformed);
        }
        let sequence = read_ne_u32(frame, 8)?;
        let embedded = &frame[NLMSG_HEADER_LEN + 4..];
        let Some(index) = self.requests.iter().position(|request| {
            read_ne_u32(&request.header, 8).is_ok_and(|value| value == sequence)
                && embedded == request.header
        }) else {
            return Err(RelayFenceError::Malformed);
        };
        let errno = read_ne_i32(frame, NLMSG_HEADER_LEN)?;
        if errno < 0 {
            return Err(RelayFenceError::Kernel(errno.saturating_abs()));
        }
        if errno != 0
            || !self.requests[index].acknowledgement_required
            || self.acknowledged[index]
            || self.next_acknowledgement() != Some(index)
        {
            return Err(RelayFenceError::Malformed);
        }
        self.acknowledged[index] = true;
        Ok(())
    }

    fn next_acknowledgement(&self) -> Option<usize> {
        self.requests
            .iter()
            .enumerate()
            .find_map(|(index, request)| {
                (request.acknowledgement_required && !self.acknowledged[index]).then_some(index)
            })
    }

    fn is_complete(&self) -> bool {
        self.next_acknowledgement().is_none()
    }

    fn finish(self) -> Result<(), RelayFenceError> {
        if self
            .requests
            .iter()
            .enumerate()
            .all(|(index, request)| self.acknowledged[index] == request.acknowledgement_required)
        {
            Ok(())
        } else {
            Err(RelayFenceError::Malformed)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectKind {
    Table,
    Chain,
    Rule,
    Set,
    Object,
    Flowtable,
}

impl ObjectKind {
    const ALL: [Self; 6] = [
        Self::Table,
        Self::Chain,
        Self::Rule,
        Self::Set,
        Self::Object,
        Self::Flowtable,
    ];

    const fn request_type(self) -> u16 {
        match self {
            Self::Table => NFT_MSG_GETTABLE,
            Self::Chain => NFT_MSG_GETCHAIN,
            Self::Rule => NFT_MSG_GETRULE,
            Self::Set => NFT_MSG_GETSET,
            Self::Object => NFT_MSG_GETOBJ,
            Self::Flowtable => NFT_MSG_GETFLOWTABLE,
        }
    }

    const fn reply_type(self) -> u16 {
        match self {
            Self::Table => NFT_MSG_NEWTABLE,
            Self::Chain => NFT_MSG_NEWCHAIN,
            Self::Rule => NFT_MSG_NEWRULE,
            Self::Set => NFT_MSG_NEWSET,
            Self::Object => NFT_MSG_NEWOBJ,
            Self::Flowtable => NFT_MSG_NEWFLOWTABLE,
        }
    }

    const fn reply_flags(self) -> u16 {
        match self {
            Self::Rule | Self::Object | Self::Flowtable => NLM_F_MULTI | NLM_F_APPEND,
            Self::Table | Self::Chain | Self::Set => NLM_F_MULTI,
        }
    }
}

struct CollectionBudget {
    bytes: usize,
    datagrams: usize,
    frames: usize,
    max_bytes: usize,
    max_datagrams: usize,
    max_frames: usize,
}

impl CollectionBudget {
    const fn production() -> Self {
        Self {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_TOTAL_BYTES,
            max_datagrams: MAX_DATAGRAMS,
            max_frames: MAX_FRAMES,
        }
    }

    fn can_receive(&self, length: usize) -> Result<(), RelayFenceError> {
        if length == 0
            || length > MAX_DATAGRAM_BYTES
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|value| value > self.max_bytes)
            || self.datagrams >= self.max_datagrams
        {
            Err(RelayFenceError::Limit)
        } else {
            Ok(())
        }
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), RelayFenceError> {
        self.can_receive(length)?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or(RelayFenceError::Limit)?;
        self.datagrams = self
            .datagrams
            .checked_add(1)
            .ok_or(RelayFenceError::Limit)?;
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), RelayFenceError> {
        self.frames = self.frames.checked_add(1).ok_or(RelayFenceError::Limit)?;
        if self.frames > self.max_frames {
            return Err(RelayFenceError::Limit);
        }
        Ok(())
    }
}

struct GenerationState {
    sequence: u32,
    local_port: u32,
    request: [u8; REQUEST_LEN],
    reply: Option<u32>,
}

impl GenerationState {
    const fn new(sequence: u32, local_port: u32, request: [u8; REQUEST_LEN]) -> Self {
        Self {
            sequence,
            local_port,
            request,
            reply: None,
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), RelayFenceError> {
        if self.reply.is_some() || sender != SocketAddr::new(0, 0) {
            return Err(RelayFenceError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), RelayFenceError> {
        if self.reply.is_some()
            || read_ne_u32(frame, 8)? != self.sequence
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(RelayFenceError::Malformed);
        }
        let message_type = read_ne_u16(frame, 4)?;
        let flags = read_ne_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        if message_type == NLMSG_OVERRUN {
            return Err(RelayFenceError::Malformed);
        }
        match message_type {
            NFT_MSG_NEWGEN if flags == 0 => {
                self.reply = Some(parse_generation_payload(payload)?);
                Ok(())
            }
            NLMSG_ERROR => Err(parse_request_error(flags, payload, &self.request)?),
            _ => Err(RelayFenceError::Malformed),
        }
    }

    fn finish(self) -> Result<u32, RelayFenceError> {
        self.reply.ok_or(RelayFenceError::Malformed)
    }
}

struct ObjectDumpState<'a> {
    kind: ObjectKind,
    sequence: u32,
    local_port: u32,
    expected_generation: u32,
    request: [u8; REQUEST_LEN],
    snapshot: &'a mut RulesetSnapshot,
    done: bool,
}

impl<'a> ObjectDumpState<'a> {
    const fn new(
        kind: ObjectKind,
        sequence: u32,
        local_port: u32,
        expected_generation: u32,
        request: [u8; REQUEST_LEN],
        snapshot: &'a mut RulesetSnapshot,
    ) -> Self {
        Self {
            kind,
            sequence,
            local_port,
            expected_generation,
            request,
            snapshot,
            done: false,
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), RelayFenceError> {
        if self.done || sender != SocketAddr::new(0, 0) {
            return Err(RelayFenceError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), RelayFenceError> {
        if self.done
            || read_ne_u32(frame, 8)? != self.sequence
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(RelayFenceError::Malformed);
        }
        let message_type = read_ne_u16(frame, 4)?;
        let flags = read_ne_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        match message_type {
            NLMSG_DONE => {
                parse_done(flags, payload)?;
                self.done = true;
                Ok(())
            }
            NLMSG_ERROR => Err(parse_request_error(flags, payload, &self.request)?),
            kind if kind == self.kind.reply_type() && flags == self.kind.reply_flags() => self
                .snapshot
                .ingest(self.kind, payload, self.expected_generation),
            _ => Err(RelayFenceError::Malformed),
        }
    }

    fn finish(self) -> Result<(), RelayFenceError> {
        if self.done {
            Ok(())
        } else {
            Err(RelayFenceError::Malformed)
        }
    }
}

struct NetfilterCollector {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetfilterCollector {
    fn connect(deadline: HardDeadline) -> Result<Self, RelayFenceError> {
        deadline.ensure_remaining()?;
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.set_netlink_get_strict_chk(true)?;
        socket.set_non_blocking(true)?;
        let address = socket.bind_auto()?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(RelayFenceError::Malformed);
        }
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_remaining()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn collect_generation(
        &mut self,
        deadline: HardDeadline,
        budget: &mut CollectionBudget,
    ) -> Result<u32, RelayFenceError> {
        let sequence = self.next_sequence()?;
        let request = encode_generation_request(sequence)?;
        send_bounded(&self.socket, &request, deadline)?;
        let (bytes, sender) = receive_bounded(&self.socket, deadline, budget)?;
        let mut state = GenerationState::new(sequence, self.local_port, request);
        state.ingest(sender, &bytes, budget)?;
        deadline.ensure_remaining()?;
        state.finish()
    }

    fn collect_object_dump(
        &mut self,
        kind: ObjectKind,
        expected_generation: u32,
        snapshot: &mut RulesetSnapshot,
        deadline: HardDeadline,
        budget: &mut CollectionBudget,
    ) -> Result<(), RelayFenceError> {
        let sequence = self.next_sequence()?;
        let request = encode_object_dump_request(kind, sequence)?;
        send_bounded(&self.socket, &request, deadline)?;
        let mut state = ObjectDumpState::new(
            kind,
            sequence,
            self.local_port,
            expected_generation,
            request,
            snapshot,
        );
        while !state.done {
            let (bytes, sender) = receive_bounded(&self.socket, deadline, budget)?;
            state.ingest(sender, &bytes, budget)?;
        }
        deadline.ensure_remaining()?;
        state.finish()
    }

    fn collect_ruleset(
        &mut self,
        expected_generation: u32,
        deadline: HardDeadline,
        budget: &mut CollectionBudget,
    ) -> Result<RulesetSnapshot, RelayFenceError> {
        let mut snapshot = RulesetSnapshot::default();
        for kind in ObjectKind::ALL {
            self.collect_object_dump(kind, expected_generation, &mut snapshot, deadline, budget)?;
        }
        Ok(snapshot)
    }

    fn next_sequence(&mut self) -> Result<u32, RelayFenceError> {
        let sequence = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or(RelayFenceError::Limit)?;
        if sequence == 0 {
            Err(RelayFenceError::Malformed)
        } else {
            Ok(sequence)
        }
    }
}

struct StableRuleset {
    generation: u32,
    snapshot: RulesetSnapshot,
}

fn observe_stable_ruleset(deadline: HardDeadline) -> Result<StableRuleset, RelayFenceError> {
    deadline.ensure_remaining()?;
    let mut collector = NetfilterCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let before = collector.collect_generation(deadline, &mut budget)?;
    let snapshot = collector.collect_ruleset(before, deadline, &mut budget)?;
    let after = collector.collect_generation(deadline, &mut budget)?;
    deadline.ensure_remaining()?;
    if before != after {
        return Err(RelayFenceError::Inconsistent);
    }
    Ok(StableRuleset {
        generation: before,
        snapshot,
    })
}

fn encode_generation_request(sequence: u32) -> Result<[u8; REQUEST_LEN], RelayFenceError> {
    encode_fixed_request(NFT_MSG_GETGEN, NLM_F_REQUEST, sequence)
}

fn encode_object_dump_request(
    kind: ObjectKind,
    sequence: u32,
) -> Result<[u8; REQUEST_LEN], RelayFenceError> {
    encode_fixed_request(kind.request_type(), NLM_F_REQUEST | NLM_F_DUMP, sequence)
}

fn encode_fixed_request(
    message_type: u16,
    flags: u16,
    sequence: u32,
) -> Result<[u8; REQUEST_LEN], RelayFenceError> {
    if sequence == 0 {
        return Err(RelayFenceError::Malformed);
    }
    let mut request = [0; REQUEST_LEN];
    request[..4].copy_from_slice(
        &u32::try_from(REQUEST_LEN)
            .map_err(|_| RelayFenceError::Limit)?
            .to_ne_bytes(),
    );
    request[4..6].copy_from_slice(&message_type.to_ne_bytes());
    request[6..8].copy_from_slice(&flags.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    Ok(request)
}

fn parse_generation_payload(payload: &[u8]) -> Result<u32, RelayFenceError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    if header.family != AF_UNSPEC || header.version != NFNETLINK_V0 {
        return Err(RelayFenceError::Malformed);
    }
    let attributes = parse_attributes(attributes, MAX_GENERATION_ATTRIBUTES)?;
    let mut generation = None;
    let mut process_id = None;
    let mut process_name = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_GEN_ID => set_once(&mut generation, read_exact_be_u32(attribute.payload)?)?,
            NFTA_GEN_PROC_PID => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value == 0 {
                    return Err(RelayFenceError::Malformed);
                }
                set_once(&mut process_id, value)?;
            }
            NFTA_GEN_PROC_NAME => {
                validate_nul_string(attribute.payload, MAX_PROCESS_NAME_BYTES)?;
                set_once(&mut process_name, ())?;
            }
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    let generation = generation.ok_or(RelayFenceError::Malformed)?;
    process_id.ok_or(RelayFenceError::Malformed)?;
    process_name.ok_or(RelayFenceError::Malformed)?;
    if header.resource_id != generation_resource_id(generation) {
        return Err(RelayFenceError::Malformed);
    }
    Ok(generation)
}

fn parse_table_payload(
    payload: &[u8],
    expected_generation: u32,
) -> Result<TableRecord, RelayFenceError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    validate_object_nfgen(header, expected_generation)?;
    let attributes = parse_attributes(attributes, MAX_TABLE_ATTRIBUTES)?;
    let mut name = None;
    let mut flags = None;
    let mut use_count = None;
    let mut handle = None;
    let mut pad = None;
    let mut userdata = None;
    let mut owner = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_TABLE_NAME => set_once(
                &mut name,
                read_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?,
            )?,
            NFTA_TABLE_FLAGS => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value & !NFT_TABLE_F_MASK != 0 {
                    return Err(RelayFenceError::Malformed);
                }
                set_once(&mut flags, value)?;
            }
            NFTA_TABLE_USE => {
                set_once(&mut use_count, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_TABLE_HANDLE => {
                set_once(&mut handle, read_exact_be_u64(attribute.payload)?)?;
            }
            NFTA_TABLE_PAD => {
                if !attribute.payload.is_empty() {
                    return Err(RelayFenceError::Malformed);
                }
                set_once(&mut pad, true)?;
            }
            NFTA_TABLE_USERDATA => {
                if attribute.payload.len() > MAX_TABLE_USERDATA_BYTES {
                    return Err(RelayFenceError::Limit);
                }
                set_once(&mut userdata, attribute.payload.to_vec())?;
            }
            NFTA_TABLE_OWNER => {
                set_once(&mut owner, read_exact_be_u32(attribute.payload)?)?;
            }
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    Ok(TableRecord {
        family: header.family,
        name: name.ok_or(RelayFenceError::Malformed)?,
        flags: flags.ok_or(RelayFenceError::Malformed)?,
        use_count: use_count.ok_or(RelayFenceError::Malformed)?,
        handle: handle.ok_or(RelayFenceError::Malformed)?,
        pad: pad.unwrap_or(false),
        userdata,
        owner,
    })
}

fn parse_chain_payload(
    payload: &[u8],
    expected_generation: u32,
) -> Result<ChainRecord, RelayFenceError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    validate_object_nfgen(header, expected_generation)?;
    let attributes = parse_attributes(attributes, MAX_CHAIN_ATTRIBUTES)?;
    let mut table = None;
    let mut handle = None;
    let mut name = None;
    let mut hook = None;
    let mut policy = None;
    let mut use_count = None;
    let mut chain_type = None;
    let mut counters = None;
    let mut pad = None;
    let mut flags = None;
    let mut id = None;
    let mut userdata = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_CHAIN_TABLE => set_once(
                &mut table,
                read_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?,
            )?,
            NFTA_CHAIN_HANDLE => {
                set_once(&mut handle, read_exact_be_u64(attribute.payload)?)?;
            }
            NFTA_CHAIN_NAME => set_once(
                &mut name,
                read_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?,
            )?,
            NFTA_CHAIN_HOOK => set_once(&mut hook, parse_hook(attribute.payload)?)?,
            NFTA_CHAIN_POLICY => {
                set_once(&mut policy, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_CHAIN_USE => {
                set_once(&mut use_count, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_CHAIN_TYPE => set_once(
                &mut chain_type,
                read_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?,
            )?,
            NFTA_CHAIN_COUNTERS => {
                if attribute.payload.len() > MAX_COUNTER_BYTES {
                    return Err(RelayFenceError::Limit);
                }
                set_once(&mut counters, attribute.payload.to_vec())?;
            }
            NFTA_CHAIN_PAD => {
                if !attribute.payload.is_empty() {
                    return Err(RelayFenceError::Malformed);
                }
                set_once(&mut pad, true)?;
            }
            NFTA_CHAIN_FLAGS => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value & !NFT_CHAIN_FLAGS != 0 {
                    return Err(RelayFenceError::Malformed);
                }
                set_once(&mut flags, value)?;
            }
            NFTA_CHAIN_ID => set_once(&mut id, read_exact_be_u32(attribute.payload)?)?,
            NFTA_CHAIN_USERDATA => {
                if attribute.payload.len() > MAX_CHAIN_USERDATA_BYTES {
                    return Err(RelayFenceError::Limit);
                }
                set_once(&mut userdata, attribute.payload.to_vec())?;
            }
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    let (hook_number, hook_priority) = hook.ok_or(RelayFenceError::Malformed)?;
    Ok(ChainRecord {
        family: header.family,
        table: table.ok_or(RelayFenceError::Malformed)?,
        name: name.ok_or(RelayFenceError::Malformed)?,
        handle: handle.ok_or(RelayFenceError::Malformed)?,
        hook_number,
        hook_priority,
        policy: policy.ok_or(RelayFenceError::Malformed)?,
        use_count: use_count.ok_or(RelayFenceError::Malformed)?,
        chain_type: chain_type.ok_or(RelayFenceError::Malformed)?,
        flags: flags.ok_or(RelayFenceError::Malformed)?,
        counters,
        pad: pad.unwrap_or(false),
        id,
        userdata,
    })
}

fn parse_hook(payload: &[u8]) -> Result<(u32, i32), RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_HOOK_ATTRIBUTES)?;
    let mut hook_number = None;
    let mut priority = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_HOOK_HOOKNUM => {
                set_once(&mut hook_number, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_HOOK_PRIORITY => {
                set_once(&mut priority, read_exact_be_i32(attribute.payload)?)?;
            }
            NFTA_HOOK_DEV | NFTA_HOOK_DEVS => return Err(RelayFenceError::UnexpectedPolicy),
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    Ok((
        hook_number.ok_or(RelayFenceError::Malformed)?,
        priority.ok_or(RelayFenceError::Malformed)?,
    ))
}

fn parse_rule_payload(
    payload: &[u8],
    expected_generation: u32,
) -> Result<RuleRecord, RelayFenceError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    validate_object_nfgen(header, expected_generation)?;
    let attributes = parse_attributes(attributes, MAX_RULE_ATTRIBUTES)?;
    let mut table = None;
    let mut chain = None;
    let mut handle = None;
    let mut expressions = None;
    let mut position = None;
    let mut userdata = None;
    let mut pad = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_RULE_TABLE => set_once(
                &mut table,
                read_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?,
            )?,
            NFTA_RULE_CHAIN => set_once(
                &mut chain,
                read_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?,
            )?,
            NFTA_RULE_HANDLE => {
                set_once(&mut handle, read_exact_be_u64(attribute.payload)?)?;
            }
            NFTA_RULE_EXPRESSIONS => {
                set_once(&mut expressions, parse_expressions(attribute.payload)?)?;
            }
            NFTA_RULE_POSITION => {
                set_once(&mut position, read_exact_be_u64(attribute.payload)?)?;
            }
            NFTA_RULE_USERDATA => {
                if attribute.payload.len() > MAX_RULE_USERDATA_BYTES {
                    return Err(RelayFenceError::Limit);
                }
                set_once(&mut userdata, attribute.payload.to_vec())?;
            }
            NFTA_RULE_PAD => {
                if !attribute.payload.is_empty() {
                    return Err(RelayFenceError::Malformed);
                }
                set_once(&mut pad, true)?;
            }
            NFTA_RULE_COMPAT | NFTA_RULE_ID | NFTA_RULE_POSITION_ID | NFTA_RULE_CHAIN_ID => {
                return Err(RelayFenceError::UnexpectedPolicy);
            }
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    Ok(RuleRecord {
        family: header.family,
        table: table.ok_or(RelayFenceError::Malformed)?,
        chain: chain.ok_or(RelayFenceError::Malformed)?,
        handle: handle.ok_or(RelayFenceError::Malformed)?,
        position,
        expressions: expressions.ok_or(RelayFenceError::Malformed)?,
        userdata,
        pad: pad.unwrap_or(false),
    })
}

fn parse_expressions(payload: &[u8]) -> Result<Vec<ObservedExpression>, RelayFenceError> {
    let elements = parse_attributes(payload, MAX_RULE_EXPRESSIONS)?;
    if !matches!(
        elements.len(),
        DIRECTION_RULE_EXPRESSIONS | TERMINAL_RULE_EXPRESSIONS
    ) {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    let mut expressions = Vec::with_capacity(elements.len());
    for element in elements {
        if element.kind != NFTA_LIST_ELEM || element.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        expressions.push(parse_expression(element.payload)?);
    }
    Ok(expressions)
}

fn parse_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_ATTRIBUTES)?;
    let mut name = None;
    let mut data = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_EXPR_NAME => set_once(
                &mut name,
                read_nul_string(attribute.payload, MAX_PROCESS_NAME_BYTES)?,
            )?,
            NFTA_EXPR_DATA => set_once(&mut data, attribute.payload)?,
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    let data = data.ok_or(RelayFenceError::Malformed)?;
    match name.as_deref().ok_or(RelayFenceError::Malformed)? {
        b"meta" => parse_meta_expression(data),
        b"cmp" => parse_compare_expression(data),
        b"payload" => parse_payload_expression(data),
        b"byteorder" => parse_byteorder_expression(data),
        b"limit" => parse_limit_expression(data),
        b"counter" => parse_counter_expression(data),
        b"immediate" => parse_immediate_expression(data),
        _ => Err(RelayFenceError::UnexpectedPolicy),
    }
}

fn parse_meta_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut destination = None;
    let mut key = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_META_DREG => {
                set_once(&mut destination, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_META_KEY => set_once(&mut key, read_exact_be_u32(attribute.payload)?)?,
            NFTA_META_SREG => return Err(RelayFenceError::UnexpectedPolicy),
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    Ok(ObservedExpression::Meta {
        destination: destination.ok_or(RelayFenceError::Malformed)?,
        key: key.ok_or(RelayFenceError::Malformed)?,
    })
}

fn parse_compare_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut source = None;
    let mut operation = None;
    let mut value = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_CMP_SREG => set_once(&mut source, read_exact_be_u32(attribute.payload)?)?,
            NFTA_CMP_OP => set_once(&mut operation, read_exact_be_u32(attribute.payload)?)?,
            NFTA_CMP_DATA => set_once(&mut value, parse_value_data(attribute.payload)?)?,
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    Ok(ObservedExpression::Compare {
        source: source.ok_or(RelayFenceError::Malformed)?,
        operation: operation.ok_or(RelayFenceError::Malformed)?,
        value: value.ok_or(RelayFenceError::Malformed)?,
    })
}

fn parse_payload_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut destination = None;
    let mut base = None;
    let mut offset = None;
    let mut length = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_PAYLOAD_DREG => {
                set_once(&mut destination, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_PAYLOAD_BASE => {
                set_once(&mut base, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_PAYLOAD_OFFSET => {
                set_once(&mut offset, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_PAYLOAD_LEN => {
                set_once(&mut length, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_PAYLOAD_SREG
            | NFTA_PAYLOAD_CSUM_TYPE
            | NFTA_PAYLOAD_CSUM_OFFSET
            | NFTA_PAYLOAD_CSUM_FLAGS => return Err(RelayFenceError::UnexpectedPolicy),
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    Ok(ObservedExpression::Payload {
        destination: destination.ok_or(RelayFenceError::Malformed)?,
        base: base.ok_or(RelayFenceError::Malformed)?,
        offset: offset.ok_or(RelayFenceError::Malformed)?,
        length: length.ok_or(RelayFenceError::Malformed)?,
    })
}

fn parse_byteorder_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut source = None;
    let mut destination = None;
    let mut operation = None;
    let mut length = None;
    let mut size = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_BYTEORDER_SREG => {
                set_once(&mut source, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_BYTEORDER_DREG => {
                set_once(&mut destination, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_BYTEORDER_OP => {
                set_once(&mut operation, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_BYTEORDER_LEN => {
                set_once(&mut length, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_BYTEORDER_SIZE => {
                set_once(&mut size, read_exact_be_u32(attribute.payload)?)?;
            }
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    Ok(ObservedExpression::Byteorder {
        source: source.ok_or(RelayFenceError::Malformed)?,
        destination: destination.ok_or(RelayFenceError::Malformed)?,
        operation: operation.ok_or(RelayFenceError::Malformed)?,
        length: length.ok_or(RelayFenceError::Malformed)?,
        size: size.ok_or(RelayFenceError::Malformed)?,
    })
}

fn parse_limit_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut index = 0;
    let rate = parse_aligned_u64(&attributes, &mut index, NFTA_LIMIT_RATE, NFTA_LIMIT_PAD)?;
    let unit = parse_aligned_u64(&attributes, &mut index, NFTA_LIMIT_UNIT, NFTA_LIMIT_PAD)?;
    let burst = parse_exact_u32(&attributes, &mut index, NFTA_LIMIT_BURST)?;
    let kind = parse_exact_u32(&attributes, &mut index, NFTA_LIMIT_TYPE)?;
    let flags = parse_exact_u32(&attributes, &mut index, NFTA_LIMIT_FLAGS)?;
    if index != attributes.len() {
        return Err(RelayFenceError::Malformed);
    }
    Ok(ObservedExpression::Limit {
        rate,
        unit,
        burst,
        kind,
        flags,
    })
}

fn parse_counter_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_COUNTER_ATTRIBUTES)?;
    let mut index = 0;
    let bytes = parse_aligned_u64(
        &attributes,
        &mut index,
        NFTA_COUNTER_BYTES,
        NFTA_COUNTER_PAD,
    )?;
    let packets = parse_aligned_u64(
        &attributes,
        &mut index,
        NFTA_COUNTER_PACKETS,
        NFTA_COUNTER_PAD,
    )?;
    if index != attributes.len() {
        return Err(RelayFenceError::Malformed);
    }
    Ok(ObservedExpression::Counter(RelayFenceCounter {
        bytes,
        packets,
    }))
}

fn parse_aligned_u64(
    attributes: &[Attribute<'_>],
    index: &mut usize,
    expected_kind: u16,
    padding_kind: u16,
) -> Result<u64, RelayFenceError> {
    if attributes.get(*index).is_some_and(|attribute| {
        attribute.kind == padding_kind && attribute.flags == 0 && attribute.payload.is_empty()
    }) {
        *index = index.checked_add(1).ok_or(RelayFenceError::Limit)?;
    }
    let attribute = attributes.get(*index).ok_or(RelayFenceError::Malformed)?;
    if attribute.kind != expected_kind || attribute.flags != 0 {
        return Err(RelayFenceError::Malformed);
    }
    *index = index.checked_add(1).ok_or(RelayFenceError::Limit)?;
    read_exact_be_u64(attribute.payload)
}

fn parse_exact_u32(
    attributes: &[Attribute<'_>],
    index: &mut usize,
    expected_kind: u16,
) -> Result<u32, RelayFenceError> {
    let attribute = attributes.get(*index).ok_or(RelayFenceError::Malformed)?;
    if attribute.kind != expected_kind || attribute.flags != 0 {
        return Err(RelayFenceError::Malformed);
    }
    *index = index.checked_add(1).ok_or(RelayFenceError::Limit)?;
    read_exact_be_u32(attribute.payload)
}

fn parse_immediate_expression(payload: &[u8]) -> Result<ObservedExpression, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut destination = None;
    let mut verdict = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_IMMEDIATE_DREG => {
                set_once(&mut destination, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_IMMEDIATE_DATA => {
                set_once(&mut verdict, parse_verdict_data(attribute.payload)?)?;
            }
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    if destination != Some(NFT_REG_VERDICT) {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    match verdict {
        Some(NF_ACCEPT) => Ok(ObservedExpression::ImmediateAccept),
        Some(NF_DROP) => Ok(ObservedExpression::ImmediateDrop),
        _ => Err(RelayFenceError::UnexpectedPolicy),
    }
}

fn parse_value_data(payload: &[u8]) -> Result<Vec<u8>, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_DATA_ATTRIBUTES)?;
    let mut value = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_DATA_VALUE => {
                if !(1..=16).contains(&attribute.payload.len()) {
                    return Err(RelayFenceError::Malformed);
                }
                set_once(&mut value, attribute.payload.to_vec())?;
            }
            NFTA_DATA_VERDICT => return Err(RelayFenceError::UnexpectedPolicy),
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    value.ok_or(RelayFenceError::Malformed)
}

fn parse_verdict_data(payload: &[u8]) -> Result<u32, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_DATA_ATTRIBUTES)?;
    let mut verdict = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_DATA_VERDICT => set_once(&mut verdict, parse_verdict(attribute.payload)?)?,
            NFTA_DATA_VALUE => return Err(RelayFenceError::UnexpectedPolicy),
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    verdict.ok_or(RelayFenceError::Malformed)
}

fn parse_verdict(payload: &[u8]) -> Result<u32, RelayFenceError> {
    let attributes = parse_attributes(payload, MAX_VERDICT_ATTRIBUTES)?;
    let mut code = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        match attribute.kind {
            NFTA_VERDICT_CODE => set_once(&mut code, read_exact_be_u32(attribute.payload)?)?,
            NFTA_VERDICT_CHAIN | NFTA_VERDICT_CHAIN_ID => {
                return Err(RelayFenceError::UnexpectedPolicy);
            }
            _ => return Err(RelayFenceError::Malformed),
        }
    }
    code.ok_or(RelayFenceError::Malformed)
}

fn validate_object_nfgen(
    header: NfgenHeader,
    expected_generation: u32,
) -> Result<(), RelayFenceError> {
    if !matches!(
        header.family,
        NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_ARP | NFPROTO_NETDEV | NFPROTO_BRIDGE | NFPROTO_IPV6
    ) || header.version != NFNETLINK_V0
        || header.resource_id != generation_resource_id(expected_generation)
    {
        return Err(RelayFenceError::Malformed);
    }
    Ok(())
}

fn validate_unexpected_object_header(
    payload: &[u8],
    expected_generation: u32,
) -> Result<(), RelayFenceError> {
    let (header, _) = split_nfgenmsg(payload)?;
    validate_object_nfgen(header, expected_generation)
}

#[derive(Clone, Copy)]
struct NfgenHeader {
    family: u8,
    version: u8,
    resource_id: u16,
}

fn split_nfgenmsg(payload: &[u8]) -> Result<(NfgenHeader, &[u8]), RelayFenceError> {
    let header = payload
        .get(..NFGENMSG_LEN)
        .ok_or(RelayFenceError::Malformed)?;
    Ok((
        NfgenHeader {
            family: header[0],
            version: header[1],
            resource_id: u16::from_be_bytes([header[2], header[3]]),
        },
        &payload[NFGENMSG_LEN..],
    ))
}

#[derive(Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    flags: u16,
    payload: &'a [u8],
}

fn parse_attributes(
    mut bytes: &[u8],
    maximum: usize,
) -> Result<Vec<Attribute<'_>>, RelayFenceError> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(RelayFenceError::Malformed);
        }
        if attributes.len() >= maximum {
            return Err(RelayFenceError::Limit);
        }
        let length = usize::from(read_ne_u16(bytes, 0)?);
        let raw_kind = read_ne_u16(bytes, 2)?;
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(RelayFenceError::Malformed);
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(RelayFenceError::Malformed);
        }
        attributes.push(Attribute {
            kind: raw_kind & NLA_TYPE_MASK,
            flags: raw_kind & !NLA_TYPE_MASK,
            payload: &bytes[ATTRIBUTE_HEADER_LEN..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(attributes)
}

fn walk_datagram(
    bytes: &[u8],
    budget: &mut CollectionBudget,
    mut consume: impl FnMut(&[u8]) -> Result<(), RelayFenceError>,
) -> Result<(), RelayFenceError> {
    budget.record_datagram(bytes.len())?;
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NLMSG_HEADER_LEN {
            return Err(RelayFenceError::Malformed);
        }
        let length =
            usize::try_from(read_ne_u32(remaining, 0)?).map_err(|_| RelayFenceError::Malformed)?;
        let aligned = align4(length)?;
        if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
            return Err(RelayFenceError::Malformed);
        }
        if remaining[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(RelayFenceError::Malformed);
        }
        budget.record_frame()?;
        consume(&remaining[..length])?;
        offset = offset.checked_add(aligned).ok_or(RelayFenceError::Limit)?;
    }
    Ok(())
}

fn parse_done(flags: u16, payload: &[u8]) -> Result<(), RelayFenceError> {
    if flags != NLM_F_MULTI {
        return Err(RelayFenceError::Malformed);
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_ne_i32(bytes, 0)? {
            0 => Ok(()),
            errno if errno < 0 => Err(RelayFenceError::Kernel(errno.saturating_abs())),
            _ => Err(RelayFenceError::Malformed),
        },
        _ => Err(RelayFenceError::Malformed),
    }
}

fn parse_request_error(
    flags: u16,
    payload: &[u8],
    request: &[u8; REQUEST_LEN],
) -> Result<RelayFenceError, RelayFenceError> {
    if flags != 0 || payload.len() != 4 + request.len() {
        return Err(RelayFenceError::Malformed);
    }
    let errno = read_ne_i32(payload, 0)?;
    if payload[4..] != *request {
        return Err(RelayFenceError::Malformed);
    }
    if errno < 0 {
        Ok(RelayFenceError::Kernel(errno.saturating_abs()))
    } else {
        Err(RelayFenceError::Malformed)
    }
}

fn send_bounded(
    socket: &Socket,
    request: &[u8],
    deadline: HardDeadline,
) -> Result<(), RelayFenceError> {
    loop {
        deadline.ensure_remaining()?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => {
                return deadline.ensure_remaining().map_err(Into::into);
            }
            Ok(_) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short netlink write").into());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_socket(socket, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_bounded(
    socket: &Socket,
    deadline: HardDeadline,
    budget: &CollectionBudget,
) -> Result<(Vec<u8>, SocketAddr), RelayFenceError> {
    loop {
        wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
        let mut probe = Vec::new();
        let (length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(RelayFenceError::Malformed);
        }
        budget.can_receive(length)?;
        deadline.ensure_remaining()?;
        let mut bytes = Vec::with_capacity(length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        deadline.ensure_remaining()?;
        if received != length || bytes.len() != received || sender != peek_sender {
            return Err(RelayFenceError::Malformed);
        }
        return Ok((bytes, sender));
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: HardDeadline,
) -> Result<(), RelayFenceError> {
    loop {
        let mut descriptor = [PollFd::new(socket.as_fd(), expected)];
        let timeout =
            PollTimeout::try_from(deadline.remaining()?).map_err(|_| RelayFenceError::Limit)?;
        match poll(&mut descriptor, timeout) {
            Ok(0) => return Err(timeout_error().into()),
            Ok(_) => {
                deadline.ensure_remaining()?;
                let events = descriptor[0].revents().unwrap_or_else(PollFlags::empty);
                if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                    || !events.contains(expected)
                    || !(events - expected).is_empty()
                {
                    return Err(RelayFenceError::Malformed);
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_remaining()?,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32).into()),
        }
    }
}

fn validate_nul_string(bytes: &[u8], maximum: usize) -> Result<(), RelayFenceError> {
    if !(2..=maximum).contains(&bytes.len())
        || bytes.last() != Some(&0)
        || bytes[..bytes.len() - 1].contains(&0)
    {
        return Err(RelayFenceError::Malformed);
    }
    Ok(())
}

fn read_nul_string(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, RelayFenceError> {
    validate_nul_string(bytes, maximum)?;
    Ok(bytes[..bytes.len() - 1].to_vec())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), RelayFenceError> {
    if slot.replace(value).is_some() {
        Err(RelayFenceError::Malformed)
    } else {
        Ok(())
    }
}

fn read_ne_u16(bytes: &[u8], offset: usize) -> Result<u16, RelayFenceError> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or(RelayFenceError::Limit)?)
        .ok_or(RelayFenceError::Malformed)?
        .try_into()
        .map_err(|_| RelayFenceError::Malformed)?;
    Ok(u16::from_ne_bytes(value))
}

fn read_ne_u32(bytes: &[u8], offset: usize) -> Result<u32, RelayFenceError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(RelayFenceError::Limit)?)
        .ok_or(RelayFenceError::Malformed)?
        .try_into()
        .map_err(|_| RelayFenceError::Malformed)?;
    Ok(u32::from_ne_bytes(value))
}

fn read_ne_i32(bytes: &[u8], offset: usize) -> Result<i32, RelayFenceError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(RelayFenceError::Limit)?)
        .ok_or(RelayFenceError::Malformed)?
        .try_into()
        .map_err(|_| RelayFenceError::Malformed)?;
    Ok(i32::from_ne_bytes(value))
}

fn read_exact_be_u32(bytes: &[u8]) -> Result<u32, RelayFenceError> {
    let value = bytes.try_into().map_err(|_| RelayFenceError::Malformed)?;
    Ok(u32::from_be_bytes(value))
}

fn read_exact_be_i32(bytes: &[u8]) -> Result<i32, RelayFenceError> {
    let value = bytes.try_into().map_err(|_| RelayFenceError::Malformed)?;
    Ok(i32::from_be_bytes(value))
}

fn read_exact_be_u64(bytes: &[u8]) -> Result<u64, RelayFenceError> {
    let value = bytes.try_into().map_err(|_| RelayFenceError::Malformed)?;
    Ok(u64::from_be_bytes(value))
}

fn align4(length: usize) -> Result<usize, RelayFenceError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(RelayFenceError::Limit)
}

const fn generation_resource_id(generation: u32) -> u16 {
    let bytes = generation.to_be_bytes();
    u16::from_be_bytes([bytes[2], bytes[3]])
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Relay fence deadline expired")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GENERATION: u32 = 7;
    const TEST_PORT: u32 = 41;
    const BASELINE_HANDLES: BaselineHandles = BaselineHandles {
        table: 11,
        chain: 12,
    };
    const POLICY_HANDLES: PolicyHandles = PolicyHandles {
        baseline: BASELINE_HANDLES,
        rules: [13, 14, 15],
    };

    fn fixture_identity() -> RelayFenceIdentity {
        RelayFenceIdentity::derive([0x5a; 16], 3).expect("fixed Relay fence identity")
    }

    fn fixture_specification() -> RelayFenceSpec {
        RelayFenceSpec::derive(
            &fixture_identity(),
            17,
            29,
            80,
            40,
            1_700_000_900,
            1_700_000_000,
        )
        .expect("fixed active Relay fence")
    }

    fn fixture_restricted_snapshot(identity: &RelayFenceIdentity) -> RulesetSnapshot {
        fixture_snapshot(identity, 0, Vec::new())
    }

    fn fixture_active_snapshot(specification: &RelayFenceSpec) -> RulesetSnapshot {
        let rules = (0_usize..3)
            .map(|index| RuleRecord {
                family: NFPROTO_INET,
                table: specification.identity.table_name.clone(),
                chain: FORWARD_CHAIN_NAME.to_vec(),
                handle: POLICY_HANDLES.rules[index],
                position: index
                    .checked_sub(1)
                    .map(|previous| POLICY_HANDLES.rules[previous]),
                expressions: specification.expected_rule_expressions(index),
                userdata: None,
                pad: false,
            })
            .collect();
        fixture_snapshot(&specification.identity, 3, rules)
    }

    fn fixture_snapshot(
        identity: &RelayFenceIdentity,
        chain_use: u32,
        rules: Vec<RuleRecord>,
    ) -> RulesetSnapshot {
        RulesetSnapshot {
            tables: vec![TableRecord {
                family: NFPROTO_INET,
                name: identity.table_name.clone(),
                flags: 0,
                use_count: 1,
                handle: BASELINE_HANDLES.table,
                pad: false,
                userdata: Some(identity.canonical_userdata()),
                owner: None,
            }],
            chains: vec![ChainRecord {
                family: NFPROTO_INET,
                table: identity.table_name.clone(),
                name: FORWARD_CHAIN_NAME.to_vec(),
                handle: BASELINE_HANDLES.chain,
                hook_number: NF_INET_FORWARD,
                hook_priority: 0,
                policy: NF_DROP,
                use_count: chain_use,
                chain_type: FILTER_CHAIN_TYPE.to_vec(),
                flags: NFT_CHAIN_BASE,
                counters: None,
                pad: false,
                id: None,
                userdata: None,
            }],
            rules,
        }
    }

    fn restricted_journal(generation: u32) -> RestrictedRelayFenceJournal {
        RestrictedRelayFenceJournal {
            identity: fixture_identity(),
            generation,
            handles: BASELINE_HANDLES,
        }
    }

    fn active_journal(generation: u32) -> ActiveRelayFenceJournal {
        ActiveRelayFenceJournal {
            specification: fixture_specification(),
            generation,
            handles: POLICY_HANDLES,
        }
    }

    fn stable(generation: u32, snapshot: RulesetSnapshot) -> StableRuleset {
        StableRuleset {
            generation,
            snapshot,
        }
    }

    fn fixture_namespace_authority() -> RelayFenceNamespaceAuthority {
        RelayFenceNamespaceAuthority {
            parent: NetworkNamespaceIdentity::fixture(1, 1),
            worker: NetworkNamespaceIdentity::fixture(2, 2),
            _thread_bound: PhantomData,
        }
    }

    #[test]
    fn identity_is_context_bound_canonical_and_path_bounded() {
        for path_id in [1, MAX_HELPER_PATHS] {
            let identity =
                RelayFenceIdentity::derive([0x5a; 16], path_id).expect("bounded path identity");
            assert_eq!(u32::from(identity.path_id), path_id);
        }
        for (context, path_id) in [
            ([0; 16], 1),
            ([1; 16], 0),
            ([1; 16], MAX_HELPER_PATHS + 1),
            ([1; 16], u32::MAX),
        ] {
            assert!(matches!(
                RelayFenceIdentity::derive(context, path_id),
                Err(RelayFenceError::Invalid)
            ));
        }

        let identity = fixture_identity();
        let mut expected_table_name = b"vpr_".to_vec();
        expected_table_name.extend_from_slice(&b"5a".repeat(16));
        expected_table_name.extend_from_slice(b"_p3");
        assert_eq!(identity.table_name, expected_table_name);

        let mut expected_userdata = TABLE_USERDATA_DOMAIN.to_vec();
        expected_userdata.extend_from_slice(&[0x5a; 16]);
        expected_userdata.push(3);
        assert_eq!(identity.canonical_userdata(), expected_userdata);
        assert!(expected_userdata.len() < MAX_TABLE_USERDATA_BYTES);
    }

    #[test]
    fn active_derivation_is_exact_and_baseline_needs_no_runtime_fields() {
        let identity = fixture_identity();
        let baseline_userdata = identity.canonical_userdata();
        let specification =
            RelayFenceSpec::derive(&identity, 17, 29, 80, 40, 1_700_000_900, 1_700_000_000)
                .expect("active policy");
        assert_eq!(specification.identity, identity);
        assert_eq!(specification.relay_client_ifindex, 17);
        assert_eq!(specification.relay_exit_ifindex, 29);
        assert_eq!(specification.client_address.octets()[14..], [0, 1]);
        assert_eq!(specification.exit_address.octets()[14..], [0, 4]);
        assert_eq!(specification.maximum_up_bytes_per_second, 10_000_000);
        assert_eq!(specification.maximum_down_bytes_per_second, 5_000_000);
        assert_eq!(
            specification.expires_at_unix_nanos,
            1_700_000_900_000_000_000
        );
        assert_eq!(
            specification.identity.canonical_userdata(),
            baseline_userdata
        );

        let rebound = RelayFenceSpec::derive(
            &specification.identity,
            31,
            37,
            80,
            40,
            1_700_000_900,
            1_700_000_000,
        )
        .expect("fresh interface binding");
        assert_ne!(
            specification.relay_client_ifindex,
            rebound.relay_client_ifindex
        );
        assert_eq!(specification.identity, rebound.identity);

        let restricted = RestrictedPolicyDrop {
            journal: restricted_journal(TEST_GENERATION + 1),
            namespace: fixture_namespace_authority(),
        };
        let from_affine_identity = RelayFenceSpec::derive(
            restricted.identity(),
            41,
            43,
            80,
            40,
            1_700_000_900,
            1_700_000_000,
        )
        .expect("policy from restricted identity");
        assert_eq!(from_affine_identity.identity, *restricted.identity());
    }

    #[test]
    fn counter_proof_requires_packet_and_byte_growth_in_both_allowed_directions() {
        let earlier = RelayFenceCounters([
            RelayFenceCounter {
                bytes: 100,
                packets: 2,
            },
            RelayFenceCounter {
                bytes: 200,
                packets: 3,
            },
            RelayFenceCounter::ZERO,
        ]);
        let mut current = RelayFenceCounters([
            RelayFenceCounter {
                bytes: 101,
                packets: 3,
            },
            RelayFenceCounter {
                bytes: 201,
                packets: 4,
            },
            RelayFenceCounter::ZERO,
        ]);
        assert!(current.both_allowed_directions_grew_since(&earlier));
        current.0[1].bytes = earlier.0[1].bytes;
        assert!(!current.both_allowed_directions_grew_since(&earlier));
    }

    #[test]
    fn active_derivation_rejects_expired_cross_index_or_rate_inputs() {
        let identity = fixture_identity();
        for result in [
            RelayFenceSpec::derive(&identity, 1, 29, 1, 1, 101, 100),
            RelayFenceSpec::derive(&identity, 17, 17, 1, 1, 101, 100),
            RelayFenceSpec::derive(&identity, 17, 29, 0, 1, 101, 100),
            RelayFenceSpec::derive(&identity, 17, 29, MAX_HELPER_RATE_MBPS + 1, 1, 101, 100),
        ] {
            assert!(matches!(result, Err(RelayFenceError::Invalid)));
        }
        for result in [
            RelayFenceSpec::derive(&identity, 17, 29, 1, 1, 100, 100),
            RelayFenceSpec::derive(
                &identity,
                17,
                29,
                1,
                1,
                100 + MAX_FENCE_TTL_SECONDS + 1,
                100,
            ),
        ] {
            assert!(matches!(result, Err(RelayFenceError::Expired)));
        }
    }

    #[test]
    fn direction_rules_bind_both_interfaces_exact_hosts_expiry_and_rates() {
        let specification = fixture_specification();
        assert_eq!(NFT_BYTEORDER_HTON, 1);
        let up = specification.expected_rule_expressions(0);
        let down = specification.expected_rule_expressions(1);
        assert_eq!(up.len(), DIRECTION_RULE_EXPRESSIONS);
        assert_eq!(down.len(), DIRECTION_RULE_EXPRESSIONS);
        assert!(matches!(
            &up[1],
            ObservedExpression::Compare { value, .. }
                if value == &specification.relay_client_ifindex.to_ne_bytes()
        ));
        assert!(matches!(
            &up[3],
            ObservedExpression::Compare { value, .. }
                if value == &specification.relay_exit_ifindex.to_ne_bytes()
        ));
        assert!(matches!(
            &up[11],
            ObservedExpression::Compare { value, .. }
                if value == &specification.client_address.octets()
        ));
        assert!(matches!(
            &up[13],
            ObservedExpression::Compare { value, .. }
                if value == &specification.exit_address.octets()
        ));
        assert!(matches!(
            &up[15],
            ObservedExpression::Byteorder {
                operation: NFT_BYTEORDER_HTON,
                length: 8,
                size: 8,
                ..
            }
        ));
        assert!(matches!(
            &up[16],
            ObservedExpression::Compare {
                operation: NFT_CMP_LT,
                value,
                ..
            } if value == &specification.expires_at_unix_nanos.to_be_bytes()
        ));
        assert!(matches!(
            &up[17],
            ObservedExpression::Limit { rate, kind, .. }
                if *rate == specification.maximum_up_bytes_per_second
                    && *kind == NFT_LIMIT_PKT_BYTES
        ));
        assert!(matches!(
            &down[17],
            ObservedExpression::Limit { rate, .. }
                if *rate == specification.maximum_down_bytes_per_second
        ));
    }

    #[test]
    fn four_transactions_are_atomic_generation_pinned_and_operation_exact() {
        let identity = fixture_identity();
        let specification = fixture_specification();
        let restricted = restricted_journal(TEST_GENERATION + 3);
        let active = active_journal(TEST_GENERATION + 2);
        let transactions = [
            (
                encode_create_baseline_transaction(&identity, TEST_GENERATION)
                    .expect("create baseline transaction"),
                vec![
                    NFNL_MSG_BATCH_BEGIN,
                    NFT_MSG_NEWTABLE,
                    NFT_MSG_NEWCHAIN,
                    NFNL_MSG_BATCH_END,
                ],
                2,
                TEST_GENERATION,
            ),
            (
                encode_activate_rules_transaction(&specification, TEST_GENERATION + 1)
                    .expect("activate rules transaction"),
                vec![
                    NFNL_MSG_BATCH_BEGIN,
                    NFT_MSG_NEWRULE,
                    NFT_MSG_NEWRULE,
                    NFT_MSG_NEWRULE,
                    NFNL_MSG_BATCH_END,
                ],
                3,
                TEST_GENERATION + 1,
            ),
            (
                encode_deactivate_rules_transaction(&active).expect("deactivate rules transaction"),
                vec![
                    NFNL_MSG_BATCH_BEGIN,
                    NFT_MSG_DELRULE,
                    NFT_MSG_DELRULE,
                    NFT_MSG_DELRULE,
                    NFNL_MSG_BATCH_END,
                ],
                3,
                TEST_GENERATION + 2,
            ),
            (
                encode_retire_baseline_transaction(&restricted)
                    .expect("retire baseline transaction"),
                vec![NFNL_MSG_BATCH_BEGIN, NFT_MSG_DELTABLE, NFNL_MSG_BATCH_END],
                1,
                TEST_GENERATION + 3,
            ),
        ];

        for (transaction, expected_types, expected_acks, generation) in transactions {
            assert_eq!(message_types(&transaction), expected_types);
            assert_eq!(
                transaction
                    .requests
                    .iter()
                    .filter(|request| request.acknowledgement_required)
                    .count(),
                expected_acks
            );
            assert_generation_pin(&transaction, generation);
            assert!(transaction.bytes.len() < MAX_MUTATION_BATCH_BYTES);
            assert!(
                !transaction
                    .requests
                    .iter()
                    .any(|request| read_ne_u16(&request.header, 4).ok() == Some(NFT_MSG_NEWSET))
            );
            assert!(!transaction.bytes.windows(3).any(|window| window == b"nat"));
        }
    }

    #[test]
    fn destructive_transactions_bind_exact_observed_handles() {
        let active = active_journal(TEST_GENERATION + 2);
        let deactivation =
            encode_deactivate_rules_transaction(&active).expect("deactivate transaction");
        assert_eq!(
            delete_handles(&deactivation, NFT_MSG_DELRULE, NFTA_RULE_HANDLE),
            vec![15, 14, 13]
        );

        let restricted = restricted_journal(TEST_GENERATION + 3);
        let retirement =
            encode_retire_baseline_transaction(&restricted).expect("retire transaction");
        assert_eq!(
            delete_handles(&retirement, NFT_MSG_DELTABLE, NFTA_TABLE_HANDLE),
            vec![BASELINE_HANDLES.table]
        );
    }

    #[test]
    fn restricted_and_active_readback_are_exact_and_preserve_baseline_handles() {
        let identity = fixture_identity();
        let specification = fixture_specification();
        let restricted = fixture_restricted_snapshot(&identity)
            .exact_restricted_observation(&identity)
            .expect("exact zero-rule baseline");
        assert_eq!(restricted.handles, BASELINE_HANDLES);

        let active_snapshot = fixture_active_snapshot(&specification);
        let active = active_snapshot
            .exact_active_observation(&specification, true)
            .expect("exact zero-counter active policy");
        assert_eq!(active.handles, POLICY_HANDLES);
        assert_eq!(active.handles.baseline, restricted.handles);

        let mut counters = fixture_active_snapshot(&specification);
        counters.rules[0].expressions[DIRECTION_RULE_EXPRESSIONS - 2] =
            ObservedExpression::Counter(RelayFenceCounter {
                bytes: 1_500,
                packets: 3,
            });
        assert!(
            counters
                .exact_active_observation(&specification, false)
                .is_ok()
        );
        assert!(
            counters
                .exact_active_observation(&specification, true)
                .is_err()
        );

        let mut baseline_with_rule = fixture_restricted_snapshot(&identity);
        baseline_with_rule
            .rules
            .push(fixture_active_snapshot(&specification).rules.remove(0));
        let mut wrong_userdata = fixture_restricted_snapshot(&identity);
        wrong_userdata.tables[0].userdata = Some(b"foreign\0".to_vec());
        let mut wrong_chain_use = fixture_restricted_snapshot(&identity);
        wrong_chain_use.chains[0].use_count = 1;
        for substituted in [baseline_with_rule, wrong_userdata, wrong_chain_use] {
            assert!(substituted.exact_restricted_observation(&identity).is_err());
        }

        let mut changed_address = fixture_active_snapshot(&specification);
        changed_address.rules[0].expressions[11] = ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_EQ,
            value: Ipv6Addr::LOCALHOST.octets().to_vec(),
        };
        let mut changed_expiry = fixture_active_snapshot(&specification);
        changed_expiry.rules[1].expressions[16] = ObservedExpression::Compare {
            source: NFT_REG_1,
            operation: NFT_CMP_LT,
            value: 1_u64.to_be_bytes().to_vec(),
        };
        let mut extra_rule = fixture_active_snapshot(&specification);
        let mut duplicate = fixture_active_snapshot(&specification).rules.remove(2);
        duplicate.handle = 16;
        duplicate.position = Some(15);
        extra_rule.rules.push(duplicate);
        for substituted in [changed_address, changed_expiry, extra_rule] {
            assert!(
                substituted
                    .exact_active_observation(&specification, false)
                    .is_err()
            );
        }
    }

    #[test]
    fn creation_reconciles_only_exact_adjacent_states() {
        let identity = fixture_identity();
        let specification = fixture_specification();

        assert!(matches!(
            classify_create_baseline(
                &stable(TEST_GENERATION, RulesetSnapshot::default()),
                TEST_GENERATION,
                TEST_GENERATION + 1,
                &identity,
            ),
            AdjacentState::Source
        ));
        assert!(matches!(
            classify_create_baseline(
                &stable(
                    TEST_GENERATION + 1,
                    fixture_restricted_snapshot(&identity),
                ),
                TEST_GENERATION,
                TEST_GENERATION + 1,
                &identity,
            ),
            AdjacentState::Destination(exact) if exact.handles == BASELINE_HANDLES
        ));
        assert!(matches!(
            classify_create_baseline(
                &stable(TEST_GENERATION + 1, fixture_active_snapshot(&specification)),
                TEST_GENERATION,
                TEST_GENERATION + 1,
                &identity,
            ),
            AdjacentState::Indeterminate
        ));
    }

    #[test]
    fn activation_reconciles_only_exact_adjacent_states_and_handles() {
        let identity = fixture_identity();
        let specification = fixture_specification();
        let restricted = restricted_journal(TEST_GENERATION + 1);

        assert!(matches!(
            classify_activate_rules(
                &stable(
                    restricted.generation,
                    fixture_restricted_snapshot(&identity),
                ),
                &restricted,
                restricted.generation + 1,
                &specification,
            ),
            AdjacentState::Source
        ));
        assert!(matches!(
            classify_activate_rules(
                &stable(
                    restricted.generation + 1,
                    fixture_active_snapshot(&specification),
                ),
                &restricted,
                restricted.generation + 1,
                &specification,
            ),
            AdjacentState::Destination(exact) if exact.handles == POLICY_HANDLES
        ));
        let mut replaced_table = fixture_active_snapshot(&specification);
        replaced_table.tables[0].handle += 100;
        assert!(matches!(
            classify_activate_rules(
                &stable(restricted.generation + 1, replaced_table),
                &restricted,
                restricted.generation + 1,
                &specification,
            ),
            AdjacentState::Indeterminate
        ));
    }

    #[test]
    fn deactivation_and_retirement_reconcile_only_exact_adjacent_states() {
        let identity = fixture_identity();
        let specification = fixture_specification();
        let active = active_journal(TEST_GENERATION + 2);

        assert!(matches!(
            classify_deactivate_rules(
                &stable(active.generation, fixture_active_snapshot(&specification)),
                &active,
                active.generation + 1,
            ),
            AdjacentState::Source
        ));
        assert!(matches!(
            classify_deactivate_rules(
                &stable(
                    active.generation + 1,
                    fixture_restricted_snapshot(&identity),
                ),
                &active,
                active.generation + 1,
            ),
            AdjacentState::Destination(exact) if exact.handles == BASELINE_HANDLES
        ));
        let mut replaced_chain = fixture_restricted_snapshot(&identity);
        replaced_chain.chains[0].handle += 100;
        assert!(matches!(
            classify_deactivate_rules(
                &stable(active.generation + 1, replaced_chain),
                &active,
                active.generation + 1,
            ),
            AdjacentState::Indeterminate
        ));

        let retired_source = restricted_journal(TEST_GENERATION + 3);
        assert!(matches!(
            classify_retire_baseline(
                &stable(
                    retired_source.generation,
                    fixture_restricted_snapshot(&identity),
                ),
                &retired_source,
                retired_source.generation + 1,
            ),
            AdjacentState::Source
        ));
        assert!(matches!(
            classify_retire_baseline(
                &stable(retired_source.generation + 1, RulesetSnapshot::default()),
                &retired_source,
                retired_source.generation + 1,
            ),
            AdjacentState::Destination(())
        ));
        assert!(matches!(
            classify_retire_baseline(
                &stable(
                    retired_source.generation + 2,
                    fixture_restricted_snapshot(&identity),
                ),
                &retired_source,
                retired_source.generation + 1,
            ),
            AdjacentState::Indeterminate
        ));
        assert!(source_typestate_is_disproven(
            &RelayFenceError::UnexpectedPolicy
        ));
        assert!(source_typestate_is_disproven(
            &RelayFenceError::UnexpectedGeneration
        ));
        assert!(!source_typestate_is_disproven(&RelayFenceError::Invalid));
    }

    #[test]
    fn acknowledgement_state_fails_closed_on_reorder_duplicate_or_kernel_error() {
        let transaction =
            encode_activate_rules_transaction(&fixture_specification(), TEST_GENERATION)
                .expect("transaction");
        let acknowledged = transaction
            .requests
            .iter()
            .enumerate()
            .filter_map(|(index, request)| request.acknowledgement_required.then_some(index))
            .collect::<Vec<_>>();

        let mut state = MutationAckState::new(TEST_PORT, &transaction.requests);
        let mut budget = CollectionBudget::production();
        for index in &acknowledged {
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &acknowledgement(TEST_PORT, transaction.requests[*index].header, 0),
                    &mut budget,
                )
                .expect("ordered acknowledgement");
        }
        state.finish().expect("complete ACK set");

        let mut reordered = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            reordered.ingest(
                SocketAddr::new(0, 0),
                &acknowledgement(TEST_PORT, transaction.requests[acknowledged[1]].header, 0),
                &mut CollectionBudget::production(),
            ),
            Err(RelayFenceError::Malformed)
        ));

        let mut rejected = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            rejected.ingest(
                SocketAddr::new(0, 0),
                &acknowledgement(
                    TEST_PORT,
                    transaction.requests[acknowledged[0]].header,
                    -libc::EINVAL,
                ),
                &mut CollectionBudget::production(),
            ),
            Err(RelayFenceError::Kernel(code)) if code == libc::EINVAL
        ));

        let mut duplicated = MutationAckState::new(TEST_PORT, &transaction.requests);
        let first = acknowledgement(TEST_PORT, transaction.requests[acknowledged[0]].header, 0);
        duplicated
            .ingest(
                SocketAddr::new(0, 0),
                &first,
                &mut CollectionBudget::production(),
            )
            .expect("first ACK");
        assert!(matches!(
            duplicated.ingest(
                SocketAddr::new(0, 0),
                &first,
                &mut CollectionBudget::production(),
            ),
            Err(RelayFenceError::Malformed)
        ));
    }

    #[test]
    fn response_parser_rejects_noncanonical_padding_flags_and_budgets() {
        let mut padding = encoded_attribute(NFTA_GEN_PROC_NAME, b"x\0");
        *padding.last_mut().expect("padding byte") = 1;
        assert!(matches!(
            parse_attributes(&padding, 1),
            Err(RelayFenceError::Malformed)
        ));
        let mut attributes = Vec::new();
        for _ in 0..=MAX_GENERATION_ATTRIBUTES {
            attributes.extend(encoded_attribute(NFTA_GEN_ID, &1_u32.to_be_bytes()));
        }
        assert!(matches!(
            parse_attributes(&attributes, MAX_GENERATION_ATTRIBUTES),
            Err(RelayFenceError::Limit)
        ));
        let mut budget = CollectionBudget::production();
        budget.frames = MAX_FRAMES;
        assert!(matches!(budget.record_frame(), Err(RelayFenceError::Limit)));

        let mut canonical_limit = Vec::new();
        canonical_limit.extend(encoded_attribute(NFTA_LIMIT_PAD, &[]));
        canonical_limit.extend(encoded_attribute(NFTA_LIMIT_RATE, &10_u64.to_be_bytes()));
        canonical_limit.extend(encoded_attribute(NFTA_LIMIT_PAD, &[]));
        canonical_limit.extend(encoded_attribute(NFTA_LIMIT_UNIT, &1_u64.to_be_bytes()));
        canonical_limit.extend(encoded_attribute(
            NFTA_LIMIT_BURST,
            &RATE_BURST_BYTES.to_be_bytes(),
        ));
        canonical_limit.extend(encoded_attribute(
            NFTA_LIMIT_TYPE,
            &NFT_LIMIT_PKT_BYTES.to_be_bytes(),
        ));
        canonical_limit.extend(encoded_attribute(NFTA_LIMIT_FLAGS, &0_u32.to_be_bytes()));
        assert!(matches!(
            parse_limit_expression(&canonical_limit),
            Ok(ObservedExpression::Limit {
                rate: 10,
                unit: 1,
                ..
            })
        ));
        let mut reordered = Vec::new();
        reordered.extend(encoded_attribute(NFTA_LIMIT_RATE, &10_u64.to_be_bytes()));
        reordered.extend(encoded_attribute(NFTA_LIMIT_PAD, &[]));
        reordered.extend(canonical_limit.into_iter().skip(16));
        assert!(parse_limit_expression(&reordered).is_err());
    }

    fn message_types(transaction: &MutationTransaction) -> Vec<u16> {
        transaction
            .requests
            .iter()
            .map(|request| read_ne_u16(&request.header, 4).expect("message type"))
            .collect()
    }

    fn assert_generation_pin(transaction: &MutationTransaction, generation: u32) {
        let first_length =
            usize::try_from(read_ne_u32(&transaction.bytes, 0).expect("batch length"))
                .expect("batch length usize");
        let first = &transaction.bytes[..first_length];
        assert_eq!(
            read_ne_u16(first, 4).expect("batch type"),
            NFNL_MSG_BATCH_BEGIN
        );
        let (_, attributes) =
            split_nfgenmsg(&first[NLMSG_HEADER_LEN..]).expect("batch nfgen payload");
        let attributes = parse_attributes(attributes, 1).expect("batch generation attribute");
        let [attribute] = attributes.as_slice() else {
            panic!("one generation attribute")
        };
        assert_eq!(attribute.kind, NFNL_BATCH_GENID);
        assert_eq!(
            read_exact_be_u32(attribute.payload).expect("generation value"),
            generation
        );
    }

    fn delete_handles(
        transaction: &MutationTransaction,
        expected_type: u16,
        handle_attribute: u16,
    ) -> Vec<u64> {
        transaction_frames(transaction)
            .into_iter()
            .filter(|frame| read_ne_u16(frame, 4).ok() == Some(expected_type))
            .map(|frame| {
                let (_, payload) =
                    split_nfgenmsg(&frame[NLMSG_HEADER_LEN..]).expect("delete nfgen payload");
                let attributes =
                    parse_attributes(payload, MAX_RULE_ATTRIBUTES).expect("delete attributes");
                let matching = attributes
                    .iter()
                    .filter(|attribute| attribute.kind == handle_attribute)
                    .collect::<Vec<_>>();
                let [handle] = matching.as_slice() else {
                    panic!("one delete handle")
                };
                read_exact_be_u64(handle.payload).expect("delete handle value")
            })
            .collect()
    }

    fn transaction_frames(transaction: &MutationTransaction) -> Vec<&[u8]> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < transaction.bytes.len() {
            let length = usize::try_from(
                read_ne_u32(&transaction.bytes, offset).expect("transaction frame length"),
            )
            .expect("transaction frame length usize");
            frames.push(&transaction.bytes[offset..offset + length]);
            offset += align4(length).expect("aligned transaction frame");
        }
        assert_eq!(offset, transaction.bytes.len());
        frames
    }

    fn acknowledgement(port: u32, request_header: [u8; NLMSG_HEADER_LEN], errno: i32) -> Vec<u8> {
        let mut frame = Vec::with_capacity(NLMSG_HEADER_LEN + 4 + NLMSG_HEADER_LEN);
        frame.extend(
            u32::try_from(NLMSG_HEADER_LEN + 4 + NLMSG_HEADER_LEN)
                .expect("ACK length")
                .to_ne_bytes(),
        );
        frame.extend(NLMSG_ERROR.to_ne_bytes());
        frame.extend(NLM_F_CAPPED.to_ne_bytes());
        frame.extend(request_header[8..12].iter().copied());
        frame.extend(port.to_ne_bytes());
        frame.extend(errno.to_ne_bytes());
        frame.extend(request_header);
        frame
    }

    fn encoded_attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_attribute(&mut bytes, kind, payload).expect("test attribute");
        bytes
    }
}
