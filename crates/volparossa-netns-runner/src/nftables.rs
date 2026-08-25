//! Bounded observation and mutation of one fixed nftables policy lineage.
//!
//! The collector sends fixed `GETGEN` and all-family table, chain, rule, set,
//! object and flowtable dumps over `NETLINK_NETFILTER`. The writer can perform
//! only two generation-pinned atomic transactions: install the run-bound
//! `inet` forward policy from generation one to two, then delete its exact
//! observed table handle from generation two to semantic-empty generation
//! three. Every possibly-sent request is reconciled through a fresh bounded
//! full-ruleset observation. Installation and packetless runtime verification
//! accept only two counted accepts followed by one counted terminal drop with
//! all three byte and packet counters freshly observed at zero. Deletion is
//! deliberately counter-agnostic because counters are mutable, but still
//! requires the exact active generation, run-bound expectation, full structure
//! and retained table, chain and rule handles. Later packet evidence needs a
//! separate quiescent counter protocol. This module never changes forwarding
//! settings.

use std::{
    io,
    marker::PhantomData,
    os::fd::AsFd,
    rc::Rc,
    time::{Duration, Instant},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use thiserror::Error;
use volparossa_test_support::RunId;

use crate::topology::namespaces::FixedForwardPolicyBinding;

const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 512 * 1024;
const MAX_DATAGRAMS: usize = 64;
const MAX_FRAMES: usize = 256;
const MAX_GENERATION_ATTRIBUTES: usize = 3;
const MAX_TABLE_ATTRIBUTES: usize = 7;
const MAX_CHAIN_ATTRIBUTES: usize = 12;
const MAX_HOOK_ATTRIBUTES: usize = 4;
const MAX_RULE_ATTRIBUTES: usize = 11;
const ACCEPT_RULE_EXPRESSIONS: usize = 16;
const TERMINAL_RULE_EXPRESSIONS: usize = 2;
const ACCEPT_RULE_COUNTER_EXPRESSION: usize = 14;
const TERMINAL_RULE_COUNTER_EXPRESSION: usize = 0;
const MAX_RULE_EXPRESSIONS: usize = ACCEPT_RULE_EXPRESSIONS;
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
const MAX_OBSERVED_RULES: usize = 3;
const MAX_MUTATION_BATCH_BYTES: usize = 4 * 1024;
const MAX_MUTATION_MESSAGES: usize = 7;
const MAX_MUTATION_ACK_BYTES: usize = 4 * 1024;
const MAX_MUTATION_ACK_DATAGRAMS: usize = 5;
const MAX_MUTATION_ACK_FRAMES: usize = 5;
const MUTATION_TIMEOUT: Duration = Duration::from_secs(2);
const RECONCILIATION_TIMEOUT: Duration = Duration::from_secs(2);

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
const INITIAL_GENERATION: u32 = 1;
const ACTIVE_POLICY_GENERATION: u32 = 2;
const RETIRED_POLICY_GENERATION: u32 = 3;
const MAX_KERNEL_IFINDEX: u32 = 0x7fff_ffff;

const NF_INET_FORWARD: u32 = 2;
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NFT_CHAIN_BASE: u32 = 1;
const NFT_CHAIN_FLAGS: u32 = 0x0007;
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_META_IIF: u32 = 4;
const NFT_META_OIF: u32 = 5;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFT_CMP_EQ: u32 = 0;
const IPPROTO_ICMP: u8 = 1;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_CODE_ZERO: u8 = 0;
const IPV4_SOURCE_OFFSET: u32 = 12;
const IPV4_DESTINATION_OFFSET: u32 = 16;
const ICMP_TYPE_CODE_OFFSET: u32 = 0;
const FIXED_ALPHA_ADDRESS: [u8; 4] = [10, 241, 1, 2];
const FIXED_OMEGA_ADDRESS: [u8; 4] = [10, 241, 2, 2];
const FORWARD_CHAIN_NAME: &[u8] = b"forward";
const FILTER_CHAIN_TYPE: &[u8] = b"filter";

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

/// A fixed, non-sensitive nftables-baseline failure.
#[derive(Debug, Error)]
pub(crate) enum NftablesError {
    /// A netlink socket operation or bounded wait failed.
    #[error("nftables proof netlink I/O failed")]
    Io(#[from] io::Error),
    /// The kernel rejected a fixed read-only request.
    #[error("nftables proof netlink request was rejected")]
    Kernel(i32),
    /// A response was malformed, ambiguous, or did not match its request.
    #[error("nftables proof netlink response was malformed or ambiguous")]
    Malformed,
    /// A response or sequence exceeded a fixed resource bound.
    #[error("nftables proof netlink response exceeded its fixed bound")]
    Limit,
    /// The generation changed while the table dump was being observed.
    #[error("nftables generation changed during proof")]
    Inconsistent,
    /// The stable observation was not the initial empty nftables baseline.
    #[error("nftables state is not the initial empty baseline")]
    NotPristine,
    /// A stable ruleset did not equal the one fixed forward policy or semantic-empty successor.
    #[error("nftables state does not equal the expected policy lineage state")]
    UnexpectedPolicy,
    /// A stable ruleset generation was not the exact successor required by the lineage.
    #[error("nftables generation is not the expected policy-lineage successor")]
    UnexpectedGeneration,
}

/// An affine observation of the initial, stable, empty nftables baseline.
///
/// The token is deliberately neither cloneable nor transferable to another
/// thread. A caller can compare it with a fresh observation made under a later
/// composite network-proof deadline.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NftablesBaseline {
    generation: u32,
    _thread_bound: PhantomData<Rc<()>>,
}

/// The sole run-bound `inet` forward policy this observer can recognize.
///
/// The table name is derived from a canonical [`RunId`]. The only variable
/// packet fields are the two distinct live parent-side veth ifindices; all
/// addresses, protocol values, chain properties, verdicts and initial zero
/// counters remain fixed.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FixedForwardPolicyExpectation {
    table_name: Vec<u8>,
    parent_ifindices: [u32; 2],
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedForwardPolicyExpectation {
    /// Derive the exact policy expectation from canonical retained topology.
    pub(crate) fn from_binding(binding: &FixedForwardPolicyBinding) -> Result<Self, NftablesError> {
        Self::from_parts(binding.run_id(), binding.parent_ifindices())
    }

    /// Construct a deliberately caller-selected expectation for parser and
    /// mutation fault-injection tests.
    #[cfg(test)]
    pub(crate) fn for_run(
        run_id: &RunId,
        parent_ifindices: [u32; 2],
    ) -> Result<Self, NftablesError> {
        Self::from_parts(run_id, parent_ifindices)
    }

    fn from_parts(run_id: &RunId, parent_ifindices: [u32; 2]) -> Result<Self, NftablesError> {
        if parent_ifindices[0] <= 1
            || parent_ifindices[1] <= 1
            || parent_ifindices[0] == parent_ifindices[1]
            || parent_ifindices[0] > MAX_KERNEL_IFINDEX
            || parent_ifindices[1] > MAX_KERNEL_IFINDEX
        {
            return Err(NftablesError::Malformed);
        }
        let mut table_name = Vec::with_capacity(4 + run_id.as_str().len());
        table_name.extend_from_slice(b"vpl_");
        table_name.extend_from_slice(run_id.as_str().as_bytes());
        if table_name.is_empty() || table_name.len() >= MAX_TABLE_NAME_BYTES {
            return Err(NftablesError::Limit);
        }
        Ok(Self {
            table_name,
            parent_ifindices,
            _thread_bound: PhantomData,
        })
    }

    fn expected_rule_expressions(&self, index: usize) -> Vec<ObservedExpression> {
        if index == 2 {
            return vec![
                ObservedExpression::Counter(ForwardPolicyCounter::ZERO),
                ObservedExpression::ImmediateDrop,
            ];
        }
        let (input, output, source, destination, icmp_type) = match index {
            0 => (
                self.parent_ifindices[0],
                self.parent_ifindices[1],
                FIXED_ALPHA_ADDRESS,
                FIXED_OMEGA_ADDRESS,
                ICMP_ECHO_REQUEST,
            ),
            1 => (
                self.parent_ifindices[1],
                self.parent_ifindices[0],
                FIXED_OMEGA_ADDRESS,
                FIXED_ALPHA_ADDRESS,
                ICMP_ECHO_REPLY,
            ),
            _ => std::process::abort(),
        };
        vec![
            ObservedExpression::Meta {
                destination: NFT_REG_1,
                key: NFT_META_IIF,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: input.to_ne_bytes().to_vec(),
            },
            ObservedExpression::Meta {
                destination: NFT_REG_1,
                key: NFT_META_OIF,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: output.to_ne_bytes().to_vec(),
            },
            ObservedExpression::Meta {
                destination: NFT_REG_1,
                key: NFT_META_NFPROTO,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: vec![NFPROTO_IPV4],
            },
            ObservedExpression::Meta {
                destination: NFT_REG_1,
                key: NFT_META_L4PROTO,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: vec![IPPROTO_ICMP],
            },
            ObservedExpression::Payload {
                destination: NFT_REG_1,
                base: NFT_PAYLOAD_NETWORK_HEADER,
                offset: IPV4_SOURCE_OFFSET,
                length: 4,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: source.to_vec(),
            },
            ObservedExpression::Payload {
                destination: NFT_REG_1,
                base: NFT_PAYLOAD_NETWORK_HEADER,
                offset: IPV4_DESTINATION_OFFSET,
                length: 4,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: destination.to_vec(),
            },
            ObservedExpression::Payload {
                destination: NFT_REG_1,
                base: NFT_PAYLOAD_TRANSPORT_HEADER,
                offset: ICMP_TYPE_CODE_OFFSET,
                length: 2,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: vec![icmp_type, ICMP_CODE_ZERO],
            },
            ObservedExpression::Counter(ForwardPolicyCounter::ZERO),
            ObservedExpression::ImmediateAccept,
        ]
    }
}

/// Exact observed active-policy state bound to the initial generation-one proof.
#[derive(Debug, Eq, PartialEq)]
struct ActivePolicyJournal {
    expectation: FixedForwardPolicyExpectation,
    initial_generation: u32,
    generation: u32,
    handles: PolicyHandles,
}

/// Armed affine ownership of the exact active policy.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "an active nftables policy must be verified or retired"]
pub(crate) struct ActiveNftablesPolicy {
    journal: Option<ActivePolicyJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Exact semantic-empty successor after deleting the observed policy table.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SemanticallyEmptyNftables {
    expectation: FixedForwardPolicyExpectation,
    generations: [u32; 3],
    _thread_bound: PhantomData<Rc<()>>,
}

#[derive(Debug)]
enum IndeterminatePolicyState {
    Install {
        _initial: NftablesBaseline,
        _expectation: FixedForwardPolicyExpectation,
    },
    Delete {
        _journal: ActivePolicyJournal,
    },
}

/// Armed fail-closed authority after a possibly-sent mutation could not be reconciled.
#[derive(Debug)]
#[must_use = "indeterminate nftables authority cannot be discarded safely"]
pub(crate) struct IndeterminateNftablesPolicy {
    state: Option<IndeterminatePolicyState>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ActiveNftablesPolicy {
    fn from_journal(journal: ActivePolicyJournal) -> Self {
        Self {
            journal: Some(journal),
            _thread_bound: PhantomData,
        }
    }

    fn journal(&self) -> &ActivePolicyJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn into_journal(mut self) -> ActivePolicyJournal {
        self.journal.take().unwrap_or_else(|| std::process::abort())
    }
}

impl Drop for ActiveNftablesPolicy {
    fn drop(&mut self) {
        if self.journal.is_some() {
            std::process::abort();
        }
    }
}

impl IndeterminateNftablesPolicy {
    fn after_install(
        initial: NftablesBaseline,
        expectation: FixedForwardPolicyExpectation,
    ) -> Self {
        Self {
            state: Some(IndeterminatePolicyState::Install {
                _initial: initial,
                _expectation: expectation,
            }),
            _thread_bound: PhantomData,
        }
    }

    fn after_delete(journal: ActivePolicyJournal) -> Self {
        Self {
            state: Some(IndeterminatePolicyState::Delete { _journal: journal }),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for IndeterminateNftablesPolicy {
    fn drop(&mut self) {
        if self.state.is_some() {
            std::process::abort();
        }
    }
}

/// Affine authority returned when policy installation does not complete.
#[derive(Debug)]
pub(crate) enum NftablesInstallAuthority {
    /// A fresh generation-one empty observation proved that nothing was installed.
    Initial(NftablesBaseline, FixedForwardPolicyExpectation),
    /// The possibly-sent transaction could not be classified safely.
    Indeterminate(IndeterminateNftablesPolicy),
}

/// Affine authority returned when exact policy deletion does not complete.
#[derive(Debug)]
pub(crate) enum NftablesDeleteAuthority {
    /// A fresh generation-two readback proved the same active policy and handles.
    Active(ActiveNftablesPolicy),
    /// The possibly-sent transaction could not be classified safely.
    Indeterminate(IndeterminateNftablesPolicy),
}

/// An observation failure that returns its still-affine lineage authority.
#[derive(Debug)]
pub(crate) struct NftablesLineageFailure<Authority> {
    /// The bounded observation failure.
    pub(crate) source: NftablesError,
    /// The input lineage authority, returned without cloning it.
    pub(crate) authority: Authority,
}

impl<Authority> NftablesLineageFailure<Authority> {
    /// Recover both the failure and the unique authority that was not consumed.
    pub(crate) fn into_parts(self) -> (NftablesError, Authority) {
        (self.source, self.authority)
    }
}

/// Return one bounded absolute mutation deadline for higher-level typestates.
pub(crate) fn mutation_deadline() -> Result<Instant, NftablesError> {
    Instant::now()
        .checked_add(MUTATION_TIMEOUT)
        .ok_or(NftablesError::Limit)
}

/// Freshly verify the same stable generation-one empty ruleset.
pub(crate) fn verify_empty_nftables(
    expected: &NftablesBaseline,
    deadline: Instant,
) -> Result<(), NftablesError> {
    let observed = observe_empty_nftables(deadline)?;
    if &observed == expected {
        Ok(())
    } else {
        Err(NftablesError::Inconsistent)
    }
}

/// Consume generation-one lineage, install the exact policy, and prove generation two.
pub(crate) fn install_exact_forward_policy(
    initial: NftablesBaseline,
    expectation: FixedForwardPolicyExpectation,
    deadline: Instant,
) -> Result<ActiveNftablesPolicy, NftablesLineageFailure<NftablesInstallAuthority>> {
    install_policy(initial, expectation, Deadline(deadline))
}

/// Freshly verify generation two, the full exact zero-counter policy, and its retained handles.
///
/// The generation bracket does not make counter values immutable. This
/// packetless lifecycle accepts the authority only when the single bounded
/// dump itself reports every counter at zero.
pub(crate) fn verify_exact_forward_policy(
    active: &ActiveNftablesPolicy,
    deadline: Instant,
) -> Result<(), NftablesError> {
    let journal = active.journal();
    let snapshot = observe_ruleset(deadline, ACTIVE_POLICY_GENERATION)?;
    let observation =
        validate_zero_counter_policy(&snapshot, &journal.expectation, ACTIVE_POLICY_GENERATION)?;
    if observation.generation == journal.generation && observation.handles == journal.handles {
        Ok(())
    } else {
        Err(NftablesError::UnexpectedPolicy)
    }
}

/// Consume active authority and delete its exact table at generation two.
///
/// Mutable counter values do not participate in deletion authority. The fresh
/// preflight still requires the run-bound expectation, full policy structure,
/// and every retained table, chain and rule handle before the table-handle-only
/// transaction can prove semantic-empty generation three.
pub(crate) fn delete_exact_forward_policy(
    active: ActiveNftablesPolicy,
    deadline: Instant,
) -> Result<SemanticallyEmptyNftables, NftablesLineageFailure<NftablesDeleteAuthority>> {
    delete_policy(active, Deadline(deadline))
}

/// Freshly verify semantic emptiness at the exact retired generation.
pub(crate) fn verify_semantically_empty_after_forward_policy(
    retired: &SemanticallyEmptyNftables,
    deadline: Instant,
) -> Result<(), NftablesError> {
    if retired.generations
        != [
            INITIAL_GENERATION,
            ACTIVE_POLICY_GENERATION,
            RETIRED_POLICY_GENERATION,
        ]
    {
        return Err(NftablesError::UnexpectedGeneration);
    }
    let snapshot = observe_ruleset(deadline, RETIRED_POLICY_GENERATION)?;
    if snapshot.is_empty() {
        Ok(())
    } else {
        Err(NftablesError::UnexpectedPolicy)
    }
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
    ) -> Result<(), NftablesError> {
        if self.requests.len() >= MAX_MUTATION_MESSAGES {
            return Err(NftablesError::Limit);
        }
        let message = encode_mutation_message(message_type, flags, sequence, payload)?;
        if self
            .bytes
            .len()
            .checked_add(message.len())
            .is_none_or(|length| length > MAX_MUTATION_BATCH_BYTES)
        {
            return Err(NftablesError::Limit);
        }
        let header = message[..NLMSG_HEADER_LEN]
            .try_into()
            .map_err(|_| NftablesError::Malformed)?;
        self.requests.push(MutationRequest {
            header,
            acknowledgement_required: flags & NLM_F_ACK != 0,
        });
        self.bytes.extend(message);
        Ok(())
    }

    fn finish(self, messages: usize, acknowledgements: usize) -> Result<Self, NftablesError> {
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
            return Err(NftablesError::Malformed);
        }
        Ok(self)
    }
}

fn encode_install_transaction(
    expectation: &FixedForwardPolicyExpectation,
) -> Result<MutationTransaction, NftablesError> {
    let mut transaction = MutationTransaction::new();
    transaction.push(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        &encode_batch_boundary_payload(Some(INITIAL_GENERATION))?,
    )?;

    let mut table = encode_request_nfgen(NFPROTO_INET, 0);
    encode_attribute(
        &mut table,
        NFTA_TABLE_NAME,
        &encode_nul_string(&expectation.table_name)?,
    )?;
    encode_attribute(&mut table, NFTA_TABLE_FLAGS, &0_u32.to_be_bytes())?;
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
        &encode_nul_string(&expectation.table_name)?,
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

    for (sequence, rule_index) in [(4, 0), (5, 1), (6, 2)] {
        let mut rule = encode_request_nfgen(NFPROTO_INET, 0);
        encode_attribute(
            &mut rule,
            NFTA_RULE_TABLE,
            &encode_nul_string(&expectation.table_name)?,
        )?;
        encode_attribute(
            &mut rule,
            NFTA_RULE_CHAIN,
            &encode_nul_string(FORWARD_CHAIN_NAME)?,
        )?;
        encode_attribute(
            &mut rule,
            NFTA_RULE_EXPRESSIONS | NLA_F_NESTED,
            &encode_policy_expressions(&expectation.expected_rule_expressions(rule_index))?,
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
        7,
        &encode_batch_boundary_payload(None)?,
    )?;
    transaction.finish(7, 5)
}

fn encode_delete_transaction(
    journal: &ActivePolicyJournal,
) -> Result<MutationTransaction, NftablesError> {
    if journal.initial_generation != INITIAL_GENERATION
        || journal.generation != ACTIVE_POLICY_GENERATION
        || journal.handles.table == 0
    {
        return Err(NftablesError::UnexpectedPolicy);
    }
    let mut transaction = MutationTransaction::new();
    transaction.push(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        &encode_batch_boundary_payload(Some(ACTIVE_POLICY_GENERATION))?,
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

fn encode_policy_expressions(expressions: &[ObservedExpression]) -> Result<Vec<u8>, NftablesError> {
    if !matches!(
        expressions.len(),
        ACCEPT_RULE_EXPRESSIONS | TERMINAL_RULE_EXPRESSIONS
    ) {
        return Err(NftablesError::Malformed);
    }
    let mut encoded = Vec::new();
    for expression in expressions {
        let (name, data) = match expression {
            ObservedExpression::Meta { destination, key } => {
                let mut data = Vec::new();
                encode_attribute(&mut data, NFTA_META_KEY, &key.to_be_bytes())?;
                encode_attribute(&mut data, NFTA_META_DREG, &destination.to_be_bytes())?;
                (b"meta".as_slice(), data)
            }
            ObservedExpression::Compare {
                source,
                operation,
                value,
            } => {
                let mut nested_value = Vec::new();
                encode_attribute(&mut nested_value, NFTA_DATA_VALUE, value)?;
                let mut data = Vec::new();
                encode_attribute(&mut data, NFTA_CMP_SREG, &source.to_be_bytes())?;
                encode_attribute(&mut data, NFTA_CMP_OP, &operation.to_be_bytes())?;
                encode_attribute(&mut data, NFTA_CMP_DATA | NLA_F_NESTED, &nested_value)?;
                (b"cmp".as_slice(), data)
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
                (b"payload".as_slice(), data)
            }
            ObservedExpression::Counter(counter) => {
                let mut data = Vec::new();
                encode_attribute(&mut data, NFTA_COUNTER_BYTES, &counter.bytes.to_be_bytes())?;
                encode_attribute(
                    &mut data,
                    NFTA_COUNTER_PACKETS,
                    &counter.packets.to_be_bytes(),
                )?;
                (b"counter".as_slice(), data)
            }
            ObservedExpression::ImmediateAccept | ObservedExpression::ImmediateDrop => {
                let code = if matches!(expression, ObservedExpression::ImmediateAccept) {
                    NF_ACCEPT
                } else {
                    NF_DROP
                };
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
                (b"immediate".as_slice(), data)
            }
        };
        let mut element = Vec::new();
        encode_attribute(&mut element, NFTA_EXPR_NAME, &encode_nul_string(name)?)?;
        encode_attribute(&mut element, NFTA_EXPR_DATA | NLA_F_NESTED, &data)?;
        encode_attribute(&mut encoded, NFTA_LIST_ELEM | NLA_F_NESTED, &element)?;
    }
    Ok(encoded)
}

fn encode_batch_boundary_payload(generation: Option<u32>) -> Result<Vec<u8>, NftablesError> {
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

fn encode_attribute(output: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<(), NftablesError> {
    if kind & NLA_TYPE_MASK == 0 {
        return Err(NftablesError::Malformed);
    }
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(NftablesError::Limit)?;
    let encoded_length = u16::try_from(length).map_err(|_| NftablesError::Limit)?;
    let aligned = align4(length)?;
    let new_length = output
        .len()
        .checked_add(aligned)
        .ok_or(NftablesError::Limit)?;
    if new_length > MAX_MUTATION_BATCH_BYTES {
        return Err(NftablesError::Limit);
    }
    output.extend(encoded_length.to_ne_bytes());
    output.extend(kind.to_ne_bytes());
    output.extend(payload);
    output.resize(new_length, 0);
    Ok(())
}

fn encode_nul_string(value: &[u8]) -> Result<Vec<u8>, NftablesError> {
    if value.is_empty() || value.contains(&0) || value.len() >= MAX_TABLE_NAME_BYTES {
        return Err(NftablesError::Malformed);
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
) -> Result<Vec<u8>, NftablesError> {
    if sequence == 0 || flags & NLM_F_REQUEST == 0 {
        return Err(NftablesError::Malformed);
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(NftablesError::Limit)?;
    let aligned = align4(length)?;
    if aligned > MAX_MUTATION_BATCH_BYTES {
        return Err(NftablesError::Limit);
    }
    let mut message = Vec::with_capacity(aligned);
    message.extend(
        u32::try_from(length)
            .map_err(|_| NftablesError::Limit)?
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
    NotSent(NftablesError),
    PossiblySent(NftablesError),
}

struct MutationAckState<'a> {
    local_port: u32,
    requests: &'a [MutationRequest],
    acknowledged: Vec<bool>,
}

impl MutationClient {
    fn connect(deadline: Deadline) -> Result<Self, NftablesError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.set_netlink_get_strict_chk(true)?;
        socket.set_cap_ack(true)?;
        if !socket.get_cap_ack()? {
            return Err(NftablesError::Malformed);
        }
        socket.set_non_blocking(true)?;
        let address = socket.bind_auto()?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(NftablesError::Malformed);
        }
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
        })
    }

    fn send(
        &self,
        transaction: &MutationTransaction,
        deadline: Deadline,
    ) -> Result<(), MutationSendFailure> {
        if transaction.bytes.is_empty()
            || transaction.bytes.len() > MAX_MUTATION_BATCH_BYTES
            || transaction.requests.is_empty()
            || transaction.requests.len() > MAX_MUTATION_MESSAGES
        {
            return Err(MutationSendFailure::NotSent(NftablesError::Limit));
        }
        loop {
            if let Err(error) = deadline.ensure_unexpired() {
                return Err(MutationSendFailure::NotSent(error));
            }
            match self.socket.send(&transaction.bytes, 0) {
                Ok(written) if written == transaction.bytes.len() => {
                    return deadline
                        .ensure_unexpired()
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
        deadline: Deadline,
    ) -> Result<(), NftablesError> {
        let acknowledgement_count = transaction
            .requests
            .iter()
            .filter(|request| request.acknowledgement_required)
            .count();
        if acknowledgement_count == 0 || acknowledgement_count > MAX_MUTATION_ACK_FRAMES {
            return Err(NftablesError::Limit);
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
        deadline.ensure_unexpired()?;
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
    ) -> Result<(), NftablesError> {
        if sender != SocketAddr::new(0, 0) || self.is_complete() {
            return Err(NftablesError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), NftablesError> {
        if frame.len() != NLMSG_HEADER_LEN + 4 + NLMSG_HEADER_LEN
            || read_ne_u16(frame, 4)? != NLMSG_ERROR
            || read_ne_u16(frame, 6)? != NLM_F_CAPPED
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(NftablesError::Malformed);
        }
        let sequence = read_ne_u32(frame, 8)?;
        let embedded = &frame[NLMSG_HEADER_LEN + 4..];
        let Some(index) = self.requests.iter().position(|request| {
            read_ne_u32(&request.header, 8).is_ok_and(|value| value == sequence)
                && embedded == request.header
        }) else {
            return Err(NftablesError::Malformed);
        };
        let errno = read_ne_i32(frame, NLMSG_HEADER_LEN)?;
        if errno < 0 {
            return Err(NftablesError::Kernel(errno.saturating_abs()));
        }
        if errno != 0
            || !self.requests[index].acknowledgement_required
            || self.acknowledged[index]
            || self.next_acknowledgement() != Some(index)
        {
            return Err(NftablesError::Malformed);
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

    fn finish(self) -> Result<(), NftablesError> {
        if self
            .requests
            .iter()
            .enumerate()
            .all(|(index, request)| self.acknowledged[index] == request.acknowledgement_required)
        {
            Ok(())
        } else {
            Err(NftablesError::Malformed)
        }
    }
}

fn reconciliation_deadline() -> Result<Instant, NftablesError> {
    Instant::now()
        .checked_add(RECONCILIATION_TIMEOUT)
        .ok_or(NftablesError::Limit)
}

fn install_failure(
    source: NftablesError,
    authority: NftablesInstallAuthority,
) -> NftablesLineageFailure<NftablesInstallAuthority> {
    NftablesLineageFailure { source, authority }
}

fn delete_failure(
    source: NftablesError,
    authority: NftablesDeleteAuthority,
) -> NftablesLineageFailure<NftablesDeleteAuthority> {
    NftablesLineageFailure { source, authority }
}

fn install_policy(
    initial: NftablesBaseline,
    expectation: FixedForwardPolicyExpectation,
    deadline: Deadline,
) -> Result<ActiveNftablesPolicy, NftablesLineageFailure<NftablesInstallAuthority>> {
    if initial.generation != INITIAL_GENERATION {
        return Err(install_failure(
            NftablesError::UnexpectedGeneration,
            NftablesInstallAuthority::Initial(initial, expectation),
        ));
    }
    if let Err(source) = verify_empty_nftables(&initial, deadline.0) {
        return Err(install_failure(
            source,
            NftablesInstallAuthority::Initial(initial, expectation),
        ));
    }
    let transaction = match encode_install_transaction(&expectation) {
        Ok(transaction) => transaction,
        Err(source) => {
            return Err(install_failure(
                source,
                NftablesInstallAuthority::Initial(initial, expectation),
            ));
        }
    };
    let client = match MutationClient::connect(deadline) {
        Ok(client) => client,
        Err(source) => {
            return Err(install_failure(
                source,
                NftablesInstallAuthority::Initial(initial, expectation),
            ));
        }
    };
    let acknowledgement_source = match client.send(&transaction, deadline) {
        Ok(()) => client
            .receive_acknowledgements(&transaction, deadline)
            .err(),
        Err(MutationSendFailure::NotSent(source)) => {
            return Err(install_failure(
                source,
                NftablesInstallAuthority::Initial(initial, expectation),
            ));
        }
        Err(MutationSendFailure::PossiblySent(source)) => Some(source),
    };
    reconcile_install(initial, expectation, acknowledgement_source)
}

fn reconcile_install(
    initial: NftablesBaseline,
    expectation: FixedForwardPolicyExpectation,
    mutation_source: Option<NftablesError>,
) -> Result<ActiveNftablesPolicy, NftablesLineageFailure<NftablesInstallAuthority>> {
    let deadline = match reconciliation_deadline() {
        Ok(deadline) => deadline,
        Err(source) => {
            return Err(install_failure(
                source,
                NftablesInstallAuthority::Indeterminate(
                    IndeterminateNftablesPolicy::after_install(initial, expectation),
                ),
            ));
        }
    };
    match observe_stable_ruleset(deadline) {
        Ok(observed)
            if observed.generation == INITIAL_GENERATION && observed.snapshot.is_empty() =>
        {
            Err(install_failure(
                mutation_source.unwrap_or(NftablesError::UnexpectedPolicy),
                NftablesInstallAuthority::Initial(initial, expectation),
            ))
        }
        Ok(observed) if observed.generation == ACTIVE_POLICY_GENERATION => {
            match validate_zero_counter_policy(
                &observed.snapshot,
                &expectation,
                observed.generation,
            ) {
                Ok(observation) => Ok(ActiveNftablesPolicy::from_journal(ActivePolicyJournal {
                    expectation,
                    initial_generation: initial.generation,
                    generation: observed.generation,
                    handles: observation.handles,
                })),
                Err(source) => Err(install_failure(
                    source,
                    NftablesInstallAuthority::Indeterminate(
                        IndeterminateNftablesPolicy::after_install(initial, expectation),
                    ),
                )),
            }
        }
        Ok(observed) => Err(install_failure(
            if observed.generation == INITIAL_GENERATION
                || observed.generation == ACTIVE_POLICY_GENERATION
            {
                NftablesError::UnexpectedPolicy
            } else {
                NftablesError::UnexpectedGeneration
            },
            NftablesInstallAuthority::Indeterminate(IndeterminateNftablesPolicy::after_install(
                initial,
                expectation,
            )),
        )),
        Err(source) => Err(install_failure(
            source,
            NftablesInstallAuthority::Indeterminate(IndeterminateNftablesPolicy::after_install(
                initial,
                expectation,
            )),
        )),
    }
}

fn delete_policy(
    active: ActiveNftablesPolicy,
    deadline: Deadline,
) -> Result<SemanticallyEmptyNftables, NftablesLineageFailure<NftablesDeleteAuthority>> {
    let journal = active.journal();
    let preflight = observe_ruleset(deadline.0, ACTIVE_POLICY_GENERATION).and_then(|snapshot| {
        validate_deletion_authority(journal, &snapshot, ACTIVE_POLICY_GENERATION)
    });
    if let Err(source) = preflight {
        return Err(delete_failure(
            source,
            NftablesDeleteAuthority::Active(active),
        ));
    }
    let transaction = match encode_delete_transaction(active.journal()) {
        Ok(transaction) => transaction,
        Err(source) => {
            return Err(delete_failure(
                source,
                NftablesDeleteAuthority::Active(active),
            ));
        }
    };
    let client = match MutationClient::connect(deadline) {
        Ok(client) => client,
        Err(source) => {
            return Err(delete_failure(
                source,
                NftablesDeleteAuthority::Active(active),
            ));
        }
    };
    let acknowledgement_source = match client.send(&transaction, deadline) {
        Ok(()) => client
            .receive_acknowledgements(&transaction, deadline)
            .err(),
        Err(MutationSendFailure::NotSent(source)) => {
            return Err(delete_failure(
                source,
                NftablesDeleteAuthority::Active(active),
            ));
        }
        Err(MutationSendFailure::PossiblySent(source)) => Some(source),
    };
    reconcile_delete(active.into_journal(), acknowledgement_source)
}

fn reconcile_delete(
    journal: ActivePolicyJournal,
    mutation_source: Option<NftablesError>,
) -> Result<SemanticallyEmptyNftables, NftablesLineageFailure<NftablesDeleteAuthority>> {
    let deadline = match reconciliation_deadline() {
        Ok(deadline) => deadline,
        Err(source) => {
            return Err(delete_failure(
                source,
                NftablesDeleteAuthority::Indeterminate(IndeterminateNftablesPolicy::after_delete(
                    journal,
                )),
            ));
        }
    };
    match observe_stable_ruleset(deadline) {
        Ok(observed)
            if observed.generation == RETIRED_POLICY_GENERATION && observed.snapshot.is_empty() =>
        {
            Ok(SemanticallyEmptyNftables {
                expectation: journal.expectation,
                generations: [
                    journal.initial_generation,
                    journal.generation,
                    observed.generation,
                ],
                _thread_bound: PhantomData,
            })
        }
        Ok(observed) if observed.generation == ACTIVE_POLICY_GENERATION => {
            match validate_deletion_authority(&journal, &observed.snapshot, observed.generation) {
                Ok(()) => Err(delete_failure(
                    mutation_source.unwrap_or(NftablesError::UnexpectedPolicy),
                    NftablesDeleteAuthority::Active(ActiveNftablesPolicy::from_journal(journal)),
                )),
                Err(source) => Err(delete_failure(
                    source,
                    NftablesDeleteAuthority::Indeterminate(
                        IndeterminateNftablesPolicy::after_delete(journal),
                    ),
                )),
            }
        }
        Ok(observed) => Err(delete_failure(
            if observed.generation == ACTIVE_POLICY_GENERATION
                || observed.generation == RETIRED_POLICY_GENERATION
            {
                NftablesError::UnexpectedPolicy
            } else {
                NftablesError::UnexpectedGeneration
            },
            NftablesDeleteAuthority::Indeterminate(IndeterminateNftablesPolicy::after_delete(
                journal,
            )),
        )),
        Err(source) => Err(delete_failure(
            source,
            NftablesDeleteAuthority::Indeterminate(IndeterminateNftablesPolicy::after_delete(
                journal,
            )),
        )),
    }
}

fn validate_deletion_authority(
    journal: &ActivePolicyJournal,
    snapshot: &RulesetSnapshot,
    observed_generation: u32,
) -> Result<(), NftablesError> {
    if journal.generation != ACTIVE_POLICY_GENERATION
        || observed_generation != ACTIVE_POLICY_GENERATION
    {
        return Err(NftablesError::UnexpectedGeneration);
    }
    let observation =
        snapshot.exact_policy_observation(&journal.expectation, observed_generation)?;
    if observation.generation != journal.generation || observation.handles != journal.handles {
        return Err(NftablesError::UnexpectedPolicy);
    }
    Ok(())
}

fn validate_zero_counter_policy(
    snapshot: &RulesetSnapshot,
    expectation: &FixedForwardPolicyExpectation,
    observed_generation: u32,
) -> Result<ZeroCounterPolicyObservation, NftablesError> {
    snapshot
        .exact_policy_observation(expectation, observed_generation)?
        .into_zero_counter_observation()
}

/// Observe one stable empty nftables baseline before the supplied deadline.
///
/// The deadline is absolute so a composite network proof can place this
/// collector and its other read-only observations under one time bound.
pub(crate) fn observe_empty_nftables(deadline: Instant) -> Result<NftablesBaseline, NftablesError> {
    let deadline = Deadline(deadline);
    deadline.ensure_unexpired()?;
    let mut collector = NetfilterCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let before = collector.collect_generation(deadline, &mut budget)?;
    let snapshot = collector
        .collect_ruleset(before, deadline, &mut budget)
        .map_err(normalize_pristine_ruleset_error)?;
    let after = collector.collect_generation(deadline, &mut budget)?;
    deadline.ensure_unexpired()?;
    let baseline = classify_observation(before, after)?;
    if snapshot.is_empty() {
        Ok(baseline)
    } else {
        Err(NftablesError::NotPristine)
    }
}

fn normalize_pristine_ruleset_error(error: NftablesError) -> NftablesError {
    match error {
        NftablesError::UnexpectedPolicy => NftablesError::NotPristine,
        other => other,
    }
}

#[derive(Clone, Copy, Debug)]
struct Deadline(Instant);

impl Deadline {
    fn poll_timeout(self) -> Result<PollTimeout, NftablesError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        let millis = remaining.as_millis();
        let rounded = if remaining.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis.checked_add(1).ok_or(NftablesError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| NftablesError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), NftablesError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error().into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestKind {
    Generation,
    #[cfg(test)]
    TableDump,
}

impl RequestKind {
    const fn message_type(self) -> u16 {
        match self {
            Self::Generation => NFT_MSG_GETGEN,
            #[cfg(test)]
            Self::TableDump => NFT_MSG_GETTABLE,
        }
    }

    const fn flags(self) -> u16 {
        match self {
            Self::Generation => NLM_F_REQUEST,
            #[cfg(test)]
            Self::TableDump => NLM_F_REQUEST | NLM_F_DUMP,
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
    Counter(ForwardPolicyCounter),
    ImmediateAccept,
    ImmediateDrop,
}

/// Fixed-width kernel counter values observed on one policy rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ForwardPolicyCounter {
    bytes: u64,
    packets: u64,
}

impl ForwardPolicyCounter {
    const ZERO: Self = Self {
        bytes: 0,
        packets: 0,
    };
}

/// The three typed per-rule counters retained by an exact structural observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ForwardPolicyCounters([ForwardPolicyCounter; 3]);

impl ForwardPolicyCounters {
    const ZERO: Self = Self([ForwardPolicyCounter::ZERO; 3]);
}

#[derive(Default)]
struct RulesetSnapshot {
    tables: Vec<TableRecord>,
    chains: Vec<ChainRecord>,
    rules: Vec<RuleRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyHandles {
    table: u64,
    chain: u64,
    rules: [u64; 3],
}

/// Exact policy structure with the mutable counter profile observed separately.
#[derive(Debug, Eq, PartialEq)]
struct ExactPolicyObservation {
    generation: u32,
    handles: PolicyHandles,
    counters: ForwardPolicyCounters,
}

/// Affine proof that one exact generation-and-handle-bound observation was zero-counter.
#[derive(Debug, Eq, PartialEq)]
struct ZeroCounterPolicyObservation {
    generation: u32,
    handles: PolicyHandles,
    _thread_bound: PhantomData<Rc<()>>,
}

impl ExactPolicyObservation {
    fn into_zero_counter_observation(self) -> Result<ZeroCounterPolicyObservation, NftablesError> {
        if self.generation != ACTIVE_POLICY_GENERATION {
            return Err(NftablesError::UnexpectedGeneration);
        }
        if self.counters != ForwardPolicyCounters::ZERO {
            return Err(NftablesError::UnexpectedPolicy);
        }
        Ok(ZeroCounterPolicyObservation {
            generation: self.generation,
            handles: self.handles,
            _thread_bound: PhantomData,
        })
    }
}

impl RulesetSnapshot {
    fn ingest(
        &mut self,
        kind: ObjectKind,
        payload: &[u8],
        expected_generation: u32,
    ) -> Result<(), NftablesError> {
        match kind {
            ObjectKind::Table => {
                if self.tables.len() >= MAX_OBSERVED_TABLES {
                    return Err(NftablesError::Limit);
                }
                self.tables
                    .push(parse_table_payload(payload, expected_generation)?);
                Ok(())
            }
            ObjectKind::Chain => {
                if self.chains.len() >= MAX_OBSERVED_CHAINS {
                    return Err(NftablesError::Limit);
                }
                self.chains
                    .push(parse_chain_payload(payload, expected_generation)?);
                Ok(())
            }
            ObjectKind::Rule => {
                if self.rules.len() >= MAX_OBSERVED_RULES {
                    return Err(NftablesError::Limit);
                }
                self.rules
                    .push(parse_rule_payload(payload, expected_generation)?);
                Ok(())
            }
            ObjectKind::Set | ObjectKind::Object | ObjectKind::Flowtable => {
                validate_unexpected_object_header(payload, expected_generation)?;
                Err(NftablesError::UnexpectedPolicy)
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.tables.is_empty() && self.chains.is_empty() && self.rules.is_empty()
    }

    fn exact_policy_observation(
        &self,
        expectation: &FixedForwardPolicyExpectation,
        generation: u32,
    ) -> Result<ExactPolicyObservation, NftablesError> {
        let [table] = self.tables.as_slice() else {
            return Err(NftablesError::UnexpectedPolicy);
        };
        if table.family != NFPROTO_INET
            || table.name != expectation.table_name
            || table.flags != 0
            || table.use_count != 1
            || table.handle == 0
            || table.pad
            || table.userdata.is_some()
            || table.owner.is_some()
        {
            return Err(NftablesError::UnexpectedPolicy);
        }

        let [chain] = self.chains.as_slice() else {
            return Err(NftablesError::UnexpectedPolicy);
        };
        if chain.family != NFPROTO_INET
            || chain.table != expectation.table_name
            || chain.name != FORWARD_CHAIN_NAME
            || chain.handle == 0
            || chain.hook_number != NF_INET_FORWARD
            || chain.hook_priority != 0
            || chain.policy != NF_DROP
            || chain.use_count != 3
            || chain.chain_type != FILTER_CHAIN_TYPE
            || chain.flags != NFT_CHAIN_BASE
            || chain.counters.is_some()
            || chain.pad
            || chain.id.is_some()
            || chain.userdata.is_some()
        {
            return Err(NftablesError::UnexpectedPolicy);
        }

        let [alpha, omega, terminal] = self.rules.as_slice() else {
            return Err(NftablesError::UnexpectedPolicy);
        };
        if alpha.family != NFPROTO_INET
            || omega.family != NFPROTO_INET
            || terminal.family != NFPROTO_INET
            || alpha.table != expectation.table_name
            || omega.table != expectation.table_name
            || terminal.table != expectation.table_name
            || alpha.chain != FORWARD_CHAIN_NAME
            || omega.chain != FORWARD_CHAIN_NAME
            || terminal.chain != FORWARD_CHAIN_NAME
            || alpha.handle == 0
            || omega.handle == 0
            || terminal.handle == 0
            || alpha.handle == omega.handle
            || alpha.handle == terminal.handle
            || omega.handle == terminal.handle
            || alpha.position.is_some()
            || omega.position != Some(alpha.handle)
            || terminal.position != Some(omega.handle)
            || alpha.userdata.is_some()
            || omega.userdata.is_some()
            || terminal.userdata.is_some()
            || alpha.pad
            || omega.pad
            || terminal.pad
        {
            return Err(NftablesError::UnexpectedPolicy);
        }
        let counters = [
            exact_rule_counter(expectation, 0, &alpha.expressions)?,
            exact_rule_counter(expectation, 1, &omega.expressions)?,
            exact_rule_counter(expectation, 2, &terminal.expressions)?,
        ];
        Ok(ExactPolicyObservation {
            generation,
            handles: PolicyHandles {
                table: table.handle,
                chain: chain.handle,
                rules: [alpha.handle, omega.handle, terminal.handle],
            },
            counters: ForwardPolicyCounters(counters),
        })
    }
}

fn exact_rule_counter(
    expectation: &FixedForwardPolicyExpectation,
    rule_index: usize,
    expressions: &[ObservedExpression],
) -> Result<ForwardPolicyCounter, NftablesError> {
    let counter_index = match rule_index {
        0 | 1 => ACCEPT_RULE_COUNTER_EXPRESSION,
        2 => TERMINAL_RULE_COUNTER_EXPRESSION,
        _ => return Err(NftablesError::UnexpectedPolicy),
    };
    let Some(ObservedExpression::Counter(counter)) = expressions.get(counter_index) else {
        return Err(NftablesError::UnexpectedPolicy);
    };
    let mut expected = expectation.expected_rule_expressions(rule_index);
    let Some(expected_counter) = expected.get_mut(counter_index) else {
        return Err(NftablesError::UnexpectedPolicy);
    };
    *expected_counter = ObservedExpression::Counter(*counter);
    if expressions != expected {
        return Err(NftablesError::UnexpectedPolicy);
    }
    Ok(*counter)
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

    fn can_receive(&self, length: usize) -> Result<(), NftablesError> {
        if !(NLMSG_HEADER_LEN..=MAX_DATAGRAM_BYTES).contains(&length)
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(NftablesError::Limit);
        }
        Ok(())
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), NftablesError> {
        self.can_receive(length)?;
        self.bytes = self.bytes.checked_add(length).ok_or(NftablesError::Limit)?;
        self.datagrams = self.datagrams.checked_add(1).ok_or(NftablesError::Limit)?;
        if self.datagrams > self.max_datagrams {
            return Err(NftablesError::Limit);
        }
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), NftablesError> {
        self.frames = self.frames.checked_add(1).ok_or(NftablesError::Limit)?;
        if self.frames > self.max_frames {
            return Err(NftablesError::Limit);
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
    ) -> Result<(), NftablesError> {
        if self.reply.is_some() || sender != SocketAddr::new(0, 0) {
            return Err(NftablesError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), NftablesError> {
        if self.reply.is_some()
            || read_ne_u32(frame, 8)? != self.sequence
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(NftablesError::Malformed);
        }
        let message_type = read_ne_u16(frame, 4)?;
        let flags = read_ne_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        if message_type == NLMSG_OVERRUN {
            return Err(NftablesError::Malformed);
        }
        match message_type {
            NFT_MSG_NEWGEN if flags == 0 => {
                self.reply = Some(parse_generation_payload(payload)?);
                Ok(())
            }
            NLMSG_ERROR => Err(parse_request_error(flags, payload, &self.request)?),
            _ => Err(NftablesError::Malformed),
        }
    }

    fn finish(self) -> Result<u32, NftablesError> {
        self.reply.ok_or(NftablesError::Malformed)
    }
}

#[cfg(test)]
struct TableDumpState {
    sequence: u32,
    local_port: u32,
    expected_generation: u32,
    request: [u8; REQUEST_LEN],
    done: bool,
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
    ) -> Result<(), NftablesError> {
        if self.done || sender != SocketAddr::new(0, 0) {
            return Err(NftablesError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), NftablesError> {
        if self.done
            || read_ne_u32(frame, 8)? != self.sequence
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(NftablesError::Malformed);
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
            _ => Err(NftablesError::Malformed),
        }
    }

    fn finish(self) -> Result<(), NftablesError> {
        if self.done {
            Ok(())
        } else {
            Err(NftablesError::Malformed)
        }
    }
}

#[cfg(test)]
impl TableDumpState {
    const fn new(
        sequence: u32,
        local_port: u32,
        expected_generation: u32,
        request: [u8; REQUEST_LEN],
    ) -> Self {
        Self {
            sequence,
            local_port,
            expected_generation,
            request,
            done: false,
        }
    }

    fn ingest(
        &mut self,
        sender: SocketAddr,
        bytes: &[u8],
        budget: &mut CollectionBudget,
    ) -> Result<(), NftablesError> {
        if self.done || sender != SocketAddr::new(0, 0) {
            return Err(NftablesError::Malformed);
        }
        walk_datagram(bytes, budget, |frame| self.ingest_frame(frame))
    }

    fn ingest_frame(&mut self, frame: &[u8]) -> Result<(), NftablesError> {
        if self.done
            || read_ne_u32(frame, 8)? != self.sequence
            || read_ne_u32(frame, 12)? != self.local_port
        {
            return Err(NftablesError::Malformed);
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
            NFT_MSG_NEWTABLE if flags == NLM_F_MULTI => {
                validate_table_payload(payload, self.expected_generation)?;
                Err(NftablesError::NotPristine)
            }
            _ => Err(NftablesError::Malformed),
        }
    }

    fn finish(self) -> Result<(), NftablesError> {
        if self.done {
            Ok(())
        } else {
            Err(NftablesError::Malformed)
        }
    }
}

struct NetfilterCollector {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetfilterCollector {
    fn connect(deadline: Deadline) -> Result<Self, NftablesError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.set_netlink_get_strict_chk(true)?;
        socket.set_non_blocking(true)?;
        let address = socket.bind_auto()?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(NftablesError::Malformed);
        }
        socket.connect(&SocketAddr::new(0, 0))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn collect_generation(
        &mut self,
        deadline: Deadline,
        budget: &mut CollectionBudget,
    ) -> Result<u32, NftablesError> {
        let sequence = self.next_sequence()?;
        let request = encode_request(RequestKind::Generation, sequence)?;
        send_bounded(&self.socket, &request, deadline)?;
        let (bytes, sender) = receive_bounded(&self.socket, deadline, budget)?;
        let mut state = GenerationState::new(sequence, self.local_port, request);
        state.ingest(sender, &bytes, budget)?;
        deadline.ensure_unexpired()?;
        state.finish()
    }

    fn collect_object_dump(
        &mut self,
        kind: ObjectKind,
        expected_generation: u32,
        snapshot: &mut RulesetSnapshot,
        deadline: Deadline,
        budget: &mut CollectionBudget,
    ) -> Result<(), NftablesError> {
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
        deadline.ensure_unexpired()?;
        state.finish()
    }

    fn collect_ruleset(
        &mut self,
        expected_generation: u32,
        deadline: Deadline,
        budget: &mut CollectionBudget,
    ) -> Result<RulesetSnapshot, NftablesError> {
        let mut snapshot = RulesetSnapshot::default();
        for kind in ObjectKind::ALL {
            self.collect_object_dump(kind, expected_generation, &mut snapshot, deadline, budget)?;
        }
        Ok(snapshot)
    }

    fn next_sequence(&mut self) -> Result<u32, NftablesError> {
        let sequence = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or(NftablesError::Limit)?;
        if sequence == 0 {
            Err(NftablesError::Malformed)
        } else {
            Ok(sequence)
        }
    }
}

struct StableRuleset {
    generation: u32,
    snapshot: RulesetSnapshot,
}

fn observe_stable_ruleset(deadline: Instant) -> Result<StableRuleset, NftablesError> {
    let deadline = Deadline(deadline);
    deadline.ensure_unexpired()?;
    let mut collector = NetfilterCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let before = collector.collect_generation(deadline, &mut budget)?;
    let snapshot = collector.collect_ruleset(before, deadline, &mut budget)?;
    let after = collector.collect_generation(deadline, &mut budget)?;
    deadline.ensure_unexpired()?;
    if before != after {
        return Err(NftablesError::Inconsistent);
    }
    Ok(StableRuleset {
        generation: before,
        snapshot,
    })
}

fn observe_ruleset(
    deadline: Instant,
    expected_generation: u32,
) -> Result<RulesetSnapshot, NftablesError> {
    let observed = observe_stable_ruleset(deadline)?;
    if observed.generation != expected_generation {
        return Err(NftablesError::UnexpectedGeneration);
    }
    Ok(observed.snapshot)
}

#[cfg(test)]
fn validate_ruleset_generation(
    before: u32,
    after: u32,
    expected: u32,
) -> Result<(), NftablesError> {
    if before != after {
        return Err(NftablesError::Inconsistent);
    }
    if before != expected {
        return Err(NftablesError::UnexpectedGeneration);
    }
    Ok(())
}

fn classify_observation(before: u32, after: u32) -> Result<NftablesBaseline, NftablesError> {
    if before != after {
        return Err(NftablesError::Inconsistent);
    }
    if before != INITIAL_GENERATION {
        return Err(NftablesError::NotPristine);
    }
    Ok(NftablesBaseline {
        generation: before,
        _thread_bound: PhantomData,
    })
}

fn encode_request(kind: RequestKind, sequence: u32) -> Result<[u8; REQUEST_LEN], NftablesError> {
    if sequence == 0 {
        return Err(NftablesError::Malformed);
    }
    let mut request = [0_u8; REQUEST_LEN];
    request[0..4].copy_from_slice(
        &u32::try_from(REQUEST_LEN)
            .map_err(|_| NftablesError::Limit)?
            .to_ne_bytes(),
    );
    request[4..6].copy_from_slice(&kind.message_type().to_ne_bytes());
    request[6..8].copy_from_slice(&kind.flags().to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    Ok(request)
}

fn encode_object_dump_request(
    kind: ObjectKind,
    sequence: u32,
) -> Result<[u8; REQUEST_LEN], NftablesError> {
    if sequence == 0 {
        return Err(NftablesError::Malformed);
    }
    let mut request = [0_u8; REQUEST_LEN];
    request[0..4].copy_from_slice(
        &u32::try_from(REQUEST_LEN)
            .map_err(|_| NftablesError::Limit)?
            .to_ne_bytes(),
    );
    request[4..6].copy_from_slice(&kind.request_type().to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    Ok(request)
}

fn parse_generation_payload(payload: &[u8]) -> Result<u32, NftablesError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    if header.family != AF_UNSPEC || header.version != NFNETLINK_V0 {
        return Err(NftablesError::Malformed);
    }
    let attributes = parse_attributes(attributes, MAX_GENERATION_ATTRIBUTES)?;
    let mut generation = None;
    let mut process_id = None;
    let mut process_name = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_GEN_ID => set_once(&mut generation, read_exact_be_u32(attribute.payload)?)?,
            NFTA_GEN_PROC_PID => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value == 0 {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut process_id, value)?;
            }
            NFTA_GEN_PROC_NAME => {
                validate_nul_string(attribute.payload, MAX_PROCESS_NAME_BYTES)?;
                set_once(&mut process_name, ())?;
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    let generation = generation.ok_or(NftablesError::Malformed)?;
    process_id.ok_or(NftablesError::Malformed)?;
    process_name.ok_or(NftablesError::Malformed)?;
    if header.resource_id != generation_resource_id(generation) {
        return Err(NftablesError::Malformed);
    }
    Ok(generation)
}

#[cfg(test)]
fn validate_table_payload(payload: &[u8], expected_generation: u32) -> Result<(), NftablesError> {
    parse_table_payload(payload, expected_generation).map(|_| ())
}

fn parse_table_payload(
    payload: &[u8],
    expected_generation: u32,
) -> Result<TableRecord, NftablesError> {
    let (header, attributes) = split_nfgenmsg(payload)?;
    if !matches!(
        header.family,
        NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_ARP | NFPROTO_NETDEV | NFPROTO_BRIDGE | NFPROTO_IPV6
    ) || header.version != NFNETLINK_V0
        || header.resource_id != generation_resource_id(expected_generation)
    {
        return Err(NftablesError::Malformed);
    }
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
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_TABLE_NAME => {
                set_once(
                    &mut name,
                    read_nul_string(attribute.payload, MAX_TABLE_NAME_BYTES)?,
                )?;
            }
            NFTA_TABLE_FLAGS => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value & !NFT_TABLE_F_MASK != 0 {
                    return Err(NftablesError::Malformed);
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
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut pad, true)?;
            }
            NFTA_TABLE_USERDATA => {
                if attribute.payload.len() > MAX_TABLE_USERDATA_BYTES {
                    return Err(NftablesError::Limit);
                }
                set_once(&mut userdata, attribute.payload.to_vec())?;
            }
            NFTA_TABLE_OWNER => {
                set_once(&mut owner, read_exact_be_u32(attribute.payload)?)?;
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    Ok(TableRecord {
        family: header.family,
        name: name.ok_or(NftablesError::Malformed)?,
        flags: flags.ok_or(NftablesError::Malformed)?,
        use_count: use_count.ok_or(NftablesError::Malformed)?,
        handle: handle.ok_or(NftablesError::Malformed)?,
        pad: pad.unwrap_or(false),
        userdata,
        owner,
    })
}

fn parse_chain_payload(
    payload: &[u8],
    expected_generation: u32,
) -> Result<ChainRecord, NftablesError> {
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
            return Err(NftablesError::Malformed);
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
                    return Err(NftablesError::Limit);
                }
                set_once(&mut counters, attribute.payload.to_vec())?;
            }
            NFTA_CHAIN_PAD => {
                if !attribute.payload.is_empty() {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut pad, true)?;
            }
            NFTA_CHAIN_FLAGS => {
                let value = read_exact_be_u32(attribute.payload)?;
                if value & !NFT_CHAIN_FLAGS != 0 {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut flags, value)?;
            }
            NFTA_CHAIN_ID => set_once(&mut id, read_exact_be_u32(attribute.payload)?)?,
            NFTA_CHAIN_USERDATA => {
                if attribute.payload.len() > MAX_CHAIN_USERDATA_BYTES {
                    return Err(NftablesError::Limit);
                }
                set_once(&mut userdata, attribute.payload.to_vec())?;
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    let (hook_number, hook_priority) = hook.ok_or(NftablesError::Malformed)?;
    Ok(ChainRecord {
        family: header.family,
        table: table.ok_or(NftablesError::Malformed)?,
        name: name.ok_or(NftablesError::Malformed)?,
        handle: handle.ok_or(NftablesError::Malformed)?,
        hook_number,
        hook_priority,
        policy: policy.ok_or(NftablesError::Malformed)?,
        use_count: use_count.ok_or(NftablesError::Malformed)?,
        chain_type: chain_type.ok_or(NftablesError::Malformed)?,
        flags: flags.ok_or(NftablesError::Malformed)?,
        counters,
        pad: pad.unwrap_or(false),
        id,
        userdata,
    })
}

fn parse_hook(payload: &[u8]) -> Result<(u32, i32), NftablesError> {
    let attributes = parse_attributes(payload, MAX_HOOK_ATTRIBUTES)?;
    let mut hook_number = None;
    let mut priority = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_HOOK_HOOKNUM => {
                set_once(&mut hook_number, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_HOOK_PRIORITY => {
                set_once(&mut priority, read_exact_be_i32(attribute.payload)?)?;
            }
            NFTA_HOOK_DEV | NFTA_HOOK_DEVS => return Err(NftablesError::UnexpectedPolicy),
            _ => return Err(NftablesError::Malformed),
        }
    }
    Ok((
        hook_number.ok_or(NftablesError::Malformed)?,
        priority.ok_or(NftablesError::Malformed)?,
    ))
}

fn parse_rule_payload(
    payload: &[u8],
    expected_generation: u32,
) -> Result<RuleRecord, NftablesError> {
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
            return Err(NftablesError::Malformed);
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
                    return Err(NftablesError::Limit);
                }
                set_once(&mut userdata, attribute.payload.to_vec())?;
            }
            NFTA_RULE_PAD => {
                if !attribute.payload.is_empty() {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut pad, true)?;
            }
            NFTA_RULE_COMPAT | NFTA_RULE_ID | NFTA_RULE_POSITION_ID | NFTA_RULE_CHAIN_ID => {
                return Err(NftablesError::UnexpectedPolicy);
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    Ok(RuleRecord {
        family: header.family,
        table: table.ok_or(NftablesError::Malformed)?,
        chain: chain.ok_or(NftablesError::Malformed)?,
        handle: handle.ok_or(NftablesError::Malformed)?,
        position,
        expressions: expressions.ok_or(NftablesError::Malformed)?,
        userdata,
        pad: pad.unwrap_or(false),
    })
}

fn parse_expressions(payload: &[u8]) -> Result<Vec<ObservedExpression>, NftablesError> {
    let elements = parse_attributes(payload, MAX_RULE_EXPRESSIONS)?;
    if !matches!(
        elements.len(),
        ACCEPT_RULE_EXPRESSIONS | TERMINAL_RULE_EXPRESSIONS
    ) {
        return Err(NftablesError::UnexpectedPolicy);
    }
    let mut expressions = Vec::with_capacity(elements.len());
    for element in elements {
        if element.kind != NFTA_LIST_ELEM || element.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        expressions.push(parse_expression(element.payload)?);
    }
    Ok(expressions)
}

fn parse_expression(payload: &[u8]) -> Result<ObservedExpression, NftablesError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_ATTRIBUTES)?;
    let mut name = None;
    let mut data = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_EXPR_NAME => set_once(
                &mut name,
                read_nul_string(attribute.payload, MAX_PROCESS_NAME_BYTES)?,
            )?,
            NFTA_EXPR_DATA => set_once(&mut data, attribute.payload)?,
            _ => return Err(NftablesError::Malformed),
        }
    }
    let name = name.ok_or(NftablesError::Malformed)?;
    let data = data.ok_or(NftablesError::Malformed)?;
    match name.as_slice() {
        b"meta" => parse_meta_expression(data),
        b"cmp" => parse_compare_expression(data),
        b"payload" => parse_payload_expression(data),
        b"counter" => parse_counter_expression(data),
        b"immediate" => parse_immediate_expression(data),
        _ => Err(NftablesError::UnexpectedPolicy),
    }
}

fn parse_counter_expression(payload: &[u8]) -> Result<ObservedExpression, NftablesError> {
    let attributes = parse_attributes(payload, MAX_COUNTER_ATTRIBUTES)?;
    let mut index = 0;
    let bytes = parse_counter_value(&attributes, &mut index, NFTA_COUNTER_BYTES)?;
    let packets = parse_counter_value(&attributes, &mut index, NFTA_COUNTER_PACKETS)?;
    if index != attributes.len() {
        return Err(NftablesError::Malformed);
    }
    Ok(ObservedExpression::Counter(ForwardPolicyCounter {
        bytes,
        packets,
    }))
}

fn parse_counter_value(
    attributes: &[Attribute<'_>],
    index: &mut usize,
    expected_kind: u16,
) -> Result<u64, NftablesError> {
    if attributes.get(*index).is_some_and(|attribute| {
        attribute.kind == NFTA_COUNTER_PAD && attribute.flags == 0 && attribute.payload.is_empty()
    }) {
        *index = index.checked_add(1).ok_or(NftablesError::Limit)?;
    }
    let attribute = attributes.get(*index).ok_or(NftablesError::Malformed)?;
    if attribute.kind != expected_kind || attribute.flags != 0 {
        return Err(NftablesError::Malformed);
    }
    *index = index.checked_add(1).ok_or(NftablesError::Limit)?;
    read_exact_be_u64(attribute.payload)
}

fn parse_meta_expression(payload: &[u8]) -> Result<ObservedExpression, NftablesError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut destination = None;
    let mut key = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_META_DREG => {
                set_once(&mut destination, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_META_KEY => set_once(&mut key, read_exact_be_u32(attribute.payload)?)?,
            NFTA_META_SREG => return Err(NftablesError::UnexpectedPolicy),
            _ => return Err(NftablesError::Malformed),
        }
    }
    Ok(ObservedExpression::Meta {
        destination: destination.ok_or(NftablesError::Malformed)?,
        key: key.ok_or(NftablesError::Malformed)?,
    })
}

fn parse_compare_expression(payload: &[u8]) -> Result<ObservedExpression, NftablesError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut source = None;
    let mut operation = None;
    let mut value = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_CMP_SREG => set_once(&mut source, read_exact_be_u32(attribute.payload)?)?,
            NFTA_CMP_OP => set_once(&mut operation, read_exact_be_u32(attribute.payload)?)?,
            NFTA_CMP_DATA => set_once(&mut value, parse_value_data(attribute.payload)?)?,
            _ => return Err(NftablesError::Malformed),
        }
    }
    Ok(ObservedExpression::Compare {
        source: source.ok_or(NftablesError::Malformed)?,
        operation: operation.ok_or(NftablesError::Malformed)?,
        value: value.ok_or(NftablesError::Malformed)?,
    })
}

fn parse_payload_expression(payload: &[u8]) -> Result<ObservedExpression, NftablesError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut destination = None;
    let mut base = None;
    let mut offset = None;
    let mut length = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
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
            | NFTA_PAYLOAD_CSUM_FLAGS => return Err(NftablesError::UnexpectedPolicy),
            _ => return Err(NftablesError::Malformed),
        }
    }
    Ok(ObservedExpression::Payload {
        destination: destination.ok_or(NftablesError::Malformed)?,
        base: base.ok_or(NftablesError::Malformed)?,
        offset: offset.ok_or(NftablesError::Malformed)?,
        length: length.ok_or(NftablesError::Malformed)?,
    })
}

fn parse_immediate_expression(payload: &[u8]) -> Result<ObservedExpression, NftablesError> {
    let attributes = parse_attributes(payload, MAX_EXPRESSION_DATA_ATTRIBUTES)?;
    let mut destination = None;
    let mut verdict = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_IMMEDIATE_DREG => {
                set_once(&mut destination, read_exact_be_u32(attribute.payload)?)?;
            }
            NFTA_IMMEDIATE_DATA => {
                set_once(&mut verdict, parse_verdict_data(attribute.payload)?)?;
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    if destination != Some(NFT_REG_VERDICT) {
        return Err(NftablesError::UnexpectedPolicy);
    }
    match verdict {
        Some(NF_ACCEPT) => Ok(ObservedExpression::ImmediateAccept),
        Some(NF_DROP) => Ok(ObservedExpression::ImmediateDrop),
        _ => Err(NftablesError::UnexpectedPolicy),
    }
}

fn parse_value_data(payload: &[u8]) -> Result<Vec<u8>, NftablesError> {
    let attributes = parse_attributes(payload, MAX_DATA_ATTRIBUTES)?;
    let mut value = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_DATA_VALUE => {
                if !(1..=16).contains(&attribute.payload.len()) {
                    return Err(NftablesError::Malformed);
                }
                set_once(&mut value, attribute.payload.to_vec())?;
            }
            NFTA_DATA_VERDICT => return Err(NftablesError::UnexpectedPolicy),
            _ => return Err(NftablesError::Malformed),
        }
    }
    value.ok_or(NftablesError::Malformed)
}

fn parse_verdict_data(payload: &[u8]) -> Result<u32, NftablesError> {
    let attributes = parse_attributes(payload, MAX_DATA_ATTRIBUTES)?;
    let mut verdict = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_DATA_VERDICT => set_once(&mut verdict, parse_verdict(attribute.payload)?)?,
            NFTA_DATA_VALUE => return Err(NftablesError::UnexpectedPolicy),
            _ => return Err(NftablesError::Malformed),
        }
    }
    verdict.ok_or(NftablesError::Malformed)
}

fn parse_verdict(payload: &[u8]) -> Result<u32, NftablesError> {
    let attributes = parse_attributes(payload, MAX_VERDICT_ATTRIBUTES)?;
    let mut code = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(NftablesError::Malformed);
        }
        match attribute.kind {
            NFTA_VERDICT_CODE => set_once(&mut code, read_exact_be_u32(attribute.payload)?)?,
            NFTA_VERDICT_CHAIN | NFTA_VERDICT_CHAIN_ID => {
                return Err(NftablesError::UnexpectedPolicy);
            }
            _ => return Err(NftablesError::Malformed),
        }
    }
    code.ok_or(NftablesError::Malformed)
}

fn validate_object_nfgen(
    header: NfgenHeader,
    expected_generation: u32,
) -> Result<(), NftablesError> {
    if !matches!(
        header.family,
        NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_ARP | NFPROTO_NETDEV | NFPROTO_BRIDGE | NFPROTO_IPV6
    ) || header.version != NFNETLINK_V0
        || header.resource_id != generation_resource_id(expected_generation)
    {
        return Err(NftablesError::Malformed);
    }
    Ok(())
}

fn validate_unexpected_object_header(
    payload: &[u8],
    expected_generation: u32,
) -> Result<(), NftablesError> {
    let (header, _) = split_nfgenmsg(payload)?;
    validate_object_nfgen(header, expected_generation)
}

#[derive(Clone, Copy)]
struct NfgenHeader {
    family: u8,
    version: u8,
    resource_id: u16,
}

fn split_nfgenmsg(payload: &[u8]) -> Result<(NfgenHeader, &[u8]), NftablesError> {
    let header = payload
        .get(..NFGENMSG_LEN)
        .ok_or(NftablesError::Malformed)?;
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

fn parse_attributes(mut bytes: &[u8], maximum: usize) -> Result<Vec<Attribute<'_>>, NftablesError> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(NftablesError::Malformed);
        }
        if attributes.len() >= maximum {
            return Err(NftablesError::Limit);
        }
        let length = usize::from(read_ne_u16(bytes, 0)?);
        let raw_kind = read_ne_u16(bytes, 2)?;
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(NftablesError::Malformed);
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(NftablesError::Malformed);
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
    mut consume: impl FnMut(&[u8]) -> Result<(), NftablesError>,
) -> Result<(), NftablesError> {
    budget.record_datagram(bytes.len())?;
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NLMSG_HEADER_LEN {
            return Err(NftablesError::Malformed);
        }
        let length =
            usize::try_from(read_ne_u32(remaining, 0)?).map_err(|_| NftablesError::Malformed)?;
        let aligned = align4(length)?;
        if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
            return Err(NftablesError::Malformed);
        }
        if remaining[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(NftablesError::Malformed);
        }
        budget.record_frame()?;
        consume(&remaining[..length])?;
        offset = offset.checked_add(aligned).ok_or(NftablesError::Limit)?;
    }
    Ok(())
}

fn parse_done(flags: u16, payload: &[u8]) -> Result<(), NftablesError> {
    if flags != NLM_F_MULTI {
        return Err(NftablesError::Malformed);
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_ne_i32(bytes, 0)? {
            0 => Ok(()),
            errno if errno < 0 => Err(NftablesError::Kernel(errno.saturating_abs())),
            _ => Err(NftablesError::Malformed),
        },
        _ => Err(NftablesError::Malformed),
    }
}

fn parse_request_error(
    flags: u16,
    payload: &[u8],
    request: &[u8; REQUEST_LEN],
) -> Result<NftablesError, NftablesError> {
    if flags != 0 || payload.len() != 4 + request.len() {
        return Err(NftablesError::Malformed);
    }
    let errno = read_ne_i32(payload, 0)?;
    if payload[4..] != *request {
        return Err(NftablesError::Malformed);
    }
    if errno < 0 {
        Ok(NftablesError::Kernel(errno.saturating_abs()))
    } else {
        Err(NftablesError::Malformed)
    }
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), NftablesError> {
    loop {
        deadline.ensure_unexpired()?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => return deadline.ensure_unexpired(),
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
    deadline: Deadline,
    budget: &CollectionBudget,
) -> Result<(Vec<u8>, SocketAddr), NftablesError> {
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
            return Err(NftablesError::Malformed);
        }
        budget.can_receive(length)?;
        deadline.ensure_unexpired()?;
        let mut bytes = Vec::with_capacity(length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        deadline.ensure_unexpired()?;
        if received != length || bytes.len() != received || sender != peek_sender {
            return Err(NftablesError::Malformed);
        }
        return Ok((bytes, sender));
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), NftablesError> {
    loop {
        let mut descriptor = [PollFd::new(socket.as_fd(), expected)];
        match poll(&mut descriptor, deadline.poll_timeout()?) {
            Ok(0) => return Err(timeout_error().into()),
            Ok(_) => {
                deadline.ensure_unexpired()?;
                let events = descriptor[0].revents().unwrap_or_else(PollFlags::empty);
                if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                    || !events.contains(expected)
                    || !(events - expected).is_empty()
                {
                    return Err(NftablesError::Malformed);
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_unexpired()?,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32).into()),
        }
    }
}

fn validate_nul_string(bytes: &[u8], maximum: usize) -> Result<(), NftablesError> {
    if !(2..=maximum).contains(&bytes.len())
        || bytes.last() != Some(&0)
        || bytes[..bytes.len() - 1].contains(&0)
    {
        return Err(NftablesError::Malformed);
    }
    Ok(())
}

fn read_nul_string(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, NftablesError> {
    validate_nul_string(bytes, maximum)?;
    Ok(bytes[..bytes.len() - 1].to_vec())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), NftablesError> {
    if slot.replace(value).is_some() {
        Err(NftablesError::Malformed)
    } else {
        Ok(())
    }
}

fn read_ne_u16(bytes: &[u8], offset: usize) -> Result<u16, NftablesError> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or(NftablesError::Limit)?)
        .ok_or(NftablesError::Malformed)?
        .try_into()
        .map_err(|_| NftablesError::Malformed)?;
    Ok(u16::from_ne_bytes(value))
}

fn read_ne_u32(bytes: &[u8], offset: usize) -> Result<u32, NftablesError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(NftablesError::Limit)?)
        .ok_or(NftablesError::Malformed)?
        .try_into()
        .map_err(|_| NftablesError::Malformed)?;
    Ok(u32::from_ne_bytes(value))
}

fn read_ne_i32(bytes: &[u8], offset: usize) -> Result<i32, NftablesError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(NftablesError::Limit)?)
        .ok_or(NftablesError::Malformed)?
        .try_into()
        .map_err(|_| NftablesError::Malformed)?;
    Ok(i32::from_ne_bytes(value))
}

fn read_exact_be_u32(bytes: &[u8]) -> Result<u32, NftablesError> {
    let value = bytes.try_into().map_err(|_| NftablesError::Malformed)?;
    Ok(u32::from_be_bytes(value))
}

fn read_exact_be_i32(bytes: &[u8]) -> Result<i32, NftablesError> {
    let value = bytes.try_into().map_err(|_| NftablesError::Malformed)?;
    Ok(i32::from_be_bytes(value))
}

fn read_exact_be_u64(bytes: &[u8]) -> Result<u64, NftablesError> {
    let value = bytes.try_into().map_err(|_| NftablesError::Malformed)?;
    Ok(u64::from_be_bytes(value))
}

fn align4(length: usize) -> Result<usize, NftablesError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(NftablesError::Limit)
}

const fn generation_resource_id(generation: u32) -> u16 {
    let bytes = generation.to_be_bytes();
    u16::from_be_bytes([bytes[2], bytes[3]])
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "nftables proof deadline expired")
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        os::unix::process::ExitStatusExt,
        process::Command,
        time::{Duration, Instant},
    };

    use nix::sched::{CloneFlags, unshare};

    use super::*;

    const LIVE_COLLECTOR_CHILD_ENV: &str = "VOLPAROSSA_NFTABLES_COLLECTOR_CHILD";
    const LIVE_POLICY_CHILD_ENV: &str = "VOLPAROSSA_NFTABLES_POLICY_CHILD";
    const DROP_GUARD_CHILD_ENV: &str = "VOLPAROSSA_NFTABLES_DROP_GUARD_CHILD";
    const TEST_SEQUENCE: u32 = 7;
    const TEST_PORT: u32 = 41;

    #[test]
    fn fixed_requests_have_exact_headers_and_no_attributes() {
        for (kind, expected_type, expected_flags) in [
            (RequestKind::Generation, NFT_MSG_GETGEN, NLM_F_REQUEST),
            (
                RequestKind::TableDump,
                NFT_MSG_GETTABLE,
                NLM_F_REQUEST | NLM_F_DUMP,
            ),
        ] {
            let request = encode_request(kind, TEST_SEQUENCE).expect("fixed request");
            assert_eq!(
                usize::try_from(read_ne_u32(&request, 0).expect("length"))
                    .expect("request length fits"),
                REQUEST_LEN
            );
            assert_eq!(read_ne_u16(&request, 4).expect("type"), expected_type);
            assert_eq!(read_ne_u16(&request, 6).expect("flags"), expected_flags);
            assert_eq!(read_ne_u32(&request, 8).expect("sequence"), TEST_SEQUENCE);
            assert_eq!(read_ne_u32(&request, 12).expect("port"), 0);
            assert_eq!(&request[NLMSG_HEADER_LEN..], &[0; NFGENMSG_LEN]);
        }
        assert!(matches!(
            encode_request(RequestKind::Generation, 0),
            Err(NftablesError::Malformed)
        ));
    }

    #[test]
    fn generation_reply_accepts_exact_attributes_in_any_order() {
        for order in [
            [NFTA_GEN_ID, NFTA_GEN_PROC_PID, NFTA_GEN_PROC_NAME],
            [NFTA_GEN_PROC_NAME, NFTA_GEN_ID, NFTA_GEN_PROC_PID],
        ] {
            let payload = generation_payload(INITIAL_GENERATION, &order);
            let mut state = generation_state();
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE, TEST_PORT, &payload),
                    &mut CollectionBudget::production(),
                )
                .expect("canonical generation reply");
            assert_eq!(state.finish().expect("generation"), INITIAL_GENERATION);
        }
    }

    #[test]
    fn generation_payload_rejects_header_and_attribute_ambiguity() {
        let canonical = generation_payload(
            INITIAL_GENERATION,
            &[NFTA_GEN_ID, NFTA_GEN_PROC_PID, NFTA_GEN_PROC_NAME],
        );
        let mut wrong_family = canonical.clone();
        wrong_family[0] = NFPROTO_IPV4;
        let mut wrong_version = canonical.clone();
        wrong_version[1] = 1;
        let mut wrong_resource = canonical.clone();
        wrong_resource[2..4].copy_from_slice(&2_u16.to_be_bytes());
        let missing_name =
            generation_payload(INITIAL_GENERATION, &[NFTA_GEN_ID, NFTA_GEN_PROC_PID]);
        let duplicate_id = generation_payload(
            INITIAL_GENERATION,
            &[NFTA_GEN_ID, NFTA_GEN_ID, NFTA_GEN_PROC_PID],
        );
        let unknown = generation_payload(INITIAL_GENERATION, &[NFTA_GEN_ID, NFTA_GEN_PROC_PID, 4]);
        let mut flagged = canonical.clone();
        let offset = NFGENMSG_LEN;
        flagged[offset + 2..offset + 4]
            .copy_from_slice(&(NFTA_GEN_ID | NLA_F_NET_BYTEORDER).to_ne_bytes());
        let zero_pid = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &0_u32.to_be_bytes(),
            b"test\0",
        );
        let nonterminated_name = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            b"test",
        );
        let interior_nul_name = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            b"te\0st\0",
        );
        let mut overlong_process_name = vec![b'x'; MAX_PROCESS_NAME_BYTES + 1];
        *overlong_process_name.last_mut().expect("process-name byte") = 0;
        let overlong_name = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            &overlong_process_name,
        );
        let wrong_id_length = generation_payload_with(
            INITIAL_GENERATION,
            &[0, 0, 1],
            &123_u32.to_be_bytes(),
            b"test\0",
        );
        for payload in [
            wrong_family,
            wrong_version,
            wrong_resource,
            missing_name,
            duplicate_id,
            unknown,
            flagged,
            zero_pid,
            nonterminated_name,
            interior_nul_name,
            overlong_name,
            wrong_id_length,
        ] {
            assert!(matches!(
                parse_generation_payload(&payload),
                Err(NftablesError::Malformed | NftablesError::Limit)
            ));
        }
    }

    #[test]
    fn generation_state_rejects_untrusted_envelope_and_extra_frames() {
        let payload = generation_payload(
            INITIAL_GENERATION,
            &[NFTA_GEN_ID, NFTA_GEN_PROC_PID, NFTA_GEN_PROC_NAME],
        );
        let good = netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE, TEST_PORT, &payload);
        let mut doubled = good.clone();
        doubled.extend(&good);
        for (sender, frame) in [
            (SocketAddr::new(9, 0), good.clone()),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE + 1, TEST_PORT, &payload),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NFT_MSG_NEWGEN, 0, TEST_SEQUENCE, TEST_PORT + 1, &payload),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWGEN,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NLMSG_OVERRUN, 0, TEST_SEQUENCE, TEST_PORT, &[]),
            ),
            (SocketAddr::new(0, 0), doubled),
        ] {
            assert!(matches!(
                generation_state().ingest(sender, &frame, &mut CollectionBudget::production()),
                Err(NftablesError::Malformed)
            ));
        }
    }

    #[test]
    fn generation_parser_accepts_its_exact_string_boundary() {
        let mut maximum_process_name = vec![b'x'; MAX_PROCESS_NAME_BYTES];
        *maximum_process_name.last_mut().expect("process-name byte") = 0;
        let payload = generation_payload_with(
            INITIAL_GENERATION,
            &INITIAL_GENERATION.to_be_bytes(),
            &123_u32.to_be_bytes(),
            &maximum_process_name,
        );
        assert_eq!(
            parse_generation_payload(&payload).expect("maximum process name"),
            INITIAL_GENERATION
        );
    }

    #[test]
    fn table_dump_accepts_only_exact_empty_terminal() {
        for payload in [Vec::new(), 0_i32.to_ne_bytes().to_vec()] {
            let mut state = table_state(INITIAL_GENERATION);
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &payload),
                    &mut CollectionBudget::production(),
                )
                .expect("empty table dump");
            state.finish().expect("terminal");
        }
        for (flags, payload) in [
            (0, Vec::new()),
            (NLM_F_MULTI | 0x10, Vec::new()),
            (NLM_F_MULTI | 0x20, Vec::new()),
            (NLM_F_MULTI, 1_i32.to_ne_bytes().to_vec()),
            (NLM_F_MULTI, vec![0; 8]),
        ] {
            let mut state = table_state(INITIAL_GENERATION);
            assert!(
                state
                    .ingest(
                        SocketAddr::new(0, 0),
                        &netlink_frame(NLMSG_DONE, flags, TEST_SEQUENCE, TEST_PORT, &payload,),
                        &mut CollectionBudget::production(),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn any_well_formed_table_is_not_pristine() {
        let payload = table_payload(INITIAL_GENERATION);
        let result = table_state(INITIAL_GENERATION).ingest(
            SocketAddr::new(0, 0),
            &netlink_frame(
                NFT_MSG_NEWTABLE,
                NLM_F_MULTI,
                TEST_SEQUENCE,
                TEST_PORT,
                &payload,
            ),
            &mut CollectionBudget::production(),
        );
        assert!(matches!(result, Err(NftablesError::NotPristine)));
    }

    #[test]
    fn table_dump_rejects_untrusted_envelope_controls_and_trailing_frames() {
        let payload = table_payload(INITIAL_GENERATION);
        let good_table = netlink_frame(
            NFT_MSG_NEWTABLE,
            NLM_F_MULTI,
            TEST_SEQUENCE,
            TEST_PORT,
            &payload,
        );
        let done = netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &[]);
        let mut doubled_done = done.clone();
        doubled_done.extend(&done);
        let mut nonzero_frame_padding =
            netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &[0]);
        *nonzero_frame_padding.last_mut().expect("frame padding") = 1;
        for (sender, frame) in [
            (SocketAddr::new(9, 0), done.clone()),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWTABLE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE + 1,
                    TEST_PORT,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWTABLE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT + 1,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NFT_MSG_NEWTABLE, 0, TEST_SEQUENCE, TEST_PORT, &payload),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NLMSG_OVERRUN, 0, TEST_SEQUENCE, TEST_PORT, &[]),
            ),
            (SocketAddr::new(0, 0), doubled_done),
            (SocketAddr::new(0, 0), nonzero_frame_padding),
        ] {
            assert!(
                table_state(INITIAL_GENERATION)
                    .ingest(sender, &frame, &mut CollectionBudget::production())
                    .is_err()
            );
        }
        assert!(matches!(
            table_state(INITIAL_GENERATION).ingest(
                SocketAddr::new(0, 0),
                &good_table,
                &mut CollectionBudget::production()
            ),
            Err(NftablesError::NotPristine)
        ));
    }

    #[test]
    fn object_dump_rejects_untrusted_envelope_controls() {
        let payload = table_payload(INITIAL_GENERATION);
        let done = netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &[]);
        let mut doubled_done = done.clone();
        doubled_done.extend(&done);
        let mut nonzero_frame_padding =
            netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &[0]);
        *nonzero_frame_padding.last_mut().expect("frame padding") = 1;
        for (sender, frame) in [
            (SocketAddr::new(9, 0), done.clone()),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWTABLE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE + 1,
                    TEST_PORT,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_NEWTABLE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT + 1,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(
                    NFT_MSG_GETTABLE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT,
                    &payload,
                ),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NFT_MSG_NEWTABLE, 0, TEST_SEQUENCE, TEST_PORT, &payload),
            ),
            (
                SocketAddr::new(0, 0),
                netlink_frame(NLMSG_OVERRUN, 0, TEST_SEQUENCE, TEST_PORT, &[]),
            ),
            (SocketAddr::new(0, 0), doubled_done),
            (SocketAddr::new(0, 0), nonzero_frame_padding),
        ] {
            let mut snapshot = RulesetSnapshot::default();
            assert!(matches!(
                object_table_state(&mut snapshot).ingest(
                    sender,
                    &frame,
                    &mut CollectionBudget::production()
                ),
                Err(NftablesError::Malformed)
            ));
        }
    }

    #[test]
    fn object_dump_requires_exact_terminal_and_error_echo() {
        for payload in [Vec::new(), 0_i32.to_ne_bytes().to_vec()] {
            let mut snapshot = RulesetSnapshot::default();
            let mut state = object_table_state(&mut snapshot);
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(NLMSG_DONE, NLM_F_MULTI, TEST_SEQUENCE, TEST_PORT, &payload),
                    &mut CollectionBudget::production(),
                )
                .expect("exact object-dump terminal");
            state.finish().expect("finished object dump");
        }
        for (flags, payload) in [
            (0, Vec::new()),
            (NLM_F_MULTI | 0x10, Vec::new()),
            (NLM_F_MULTI, 1_i32.to_ne_bytes().to_vec()),
            (NLM_F_MULTI, vec![0; 8]),
        ] {
            let mut snapshot = RulesetSnapshot::default();
            assert!(matches!(
                object_table_state(&mut snapshot).ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(NLMSG_DONE, flags, TEST_SEQUENCE, TEST_PORT, &payload,),
                    &mut CollectionBudget::production(),
                ),
                Err(NftablesError::Malformed)
            ));
        }

        let request =
            encode_object_dump_request(ObjectKind::Table, TEST_SEQUENCE).expect("table request");
        let mut error_payload = (-libc::EINVAL).to_ne_bytes().to_vec();
        error_payload.extend(request);
        let mut snapshot = RulesetSnapshot::default();
        assert!(matches!(
            object_table_state(&mut snapshot).ingest(
                SocketAddr::new(0, 0),
                &netlink_frame(
                    NLMSG_ERROR,
                    0,
                    TEST_SEQUENCE,
                    TEST_PORT,
                    &error_payload,
                ),
                &mut CollectionBudget::production(),
            ),
            Err(NftablesError::Kernel(code)) if code == libc::EINVAL
        ));
        error_payload[4] ^= 1;
        let mut snapshot = RulesetSnapshot::default();
        assert!(matches!(
            object_table_state(&mut snapshot).ingest(
                SocketAddr::new(0, 0),
                &netlink_frame(NLMSG_ERROR, 0, TEST_SEQUENCE, TEST_PORT, &error_payload,),
                &mut CollectionBudget::production(),
            ),
            Err(NftablesError::Malformed)
        ));
    }

    #[test]
    fn table_payload_validation_is_exact_and_bounded() {
        let canonical = table_payload(INITIAL_GENERATION);
        validate_table_payload(&canonical, INITIAL_GENERATION).expect("canonical table");
        let mut wrong_family = canonical.clone();
        wrong_family[0] = AF_UNSPEC;
        let mut wrong_version = canonical.clone();
        wrong_version[1] = 1;
        let mut wrong_resource = canonical.clone();
        wrong_resource[2..4].copy_from_slice(&2_u16.to_be_bytes());
        let missing_name = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let duplicate = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_NAME, b"duplicate\0"),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let unknown = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(99, &[]),
            ],
        );
        let mut flagged = canonical.clone();
        let offset = NFGENMSG_LEN;
        flagged[offset + 2..offset + 4]
            .copy_from_slice(&(NFTA_TABLE_NAME | NLA_F_NESTED).to_ne_bytes());
        let bad_flags = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_FLAGS, &8_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let mut overlong_table_name = vec![b'x'; MAX_TABLE_NAME_BYTES + 1];
        *overlong_table_name.last_mut().expect("table-name byte") = 0;
        let overlong_name = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, &overlong_table_name),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
            ],
        );
        let overlong_userdata = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(NFTA_TABLE_USERDATA, &[0; MAX_TABLE_USERDATA_BYTES + 1]),
            ],
        );
        for payload in [
            wrong_family,
            wrong_version,
            wrong_resource,
            missing_name,
            duplicate,
            unknown,
            flagged,
            bad_flags,
            overlong_name,
            overlong_userdata,
        ] {
            assert!(validate_table_payload(&payload, INITIAL_GENERATION).is_err());
        }

        let mut maximum_table_name = vec![b'x'; MAX_TABLE_NAME_BYTES];
        *maximum_table_name.last_mut().expect("table-name byte") = 0;
        let maximums = table_payload_from_attributes(
            INITIAL_GENERATION,
            [
                attribute(NFTA_TABLE_NAME, &maximum_table_name),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(NFTA_TABLE_USERDATA, &[0; MAX_TABLE_USERDATA_BYTES]),
            ],
        );
        validate_table_payload(&maximums, INITIAL_GENERATION).expect("maximum table attributes");
    }

    #[test]
    fn generation_bracket_must_be_initial_and_stable() {
        let baseline = classify_observation(INITIAL_GENERATION, INITIAL_GENERATION)
            .expect("initial generation");
        assert_eq!(baseline.generation, INITIAL_GENERATION);
        assert!(matches!(
            classify_observation(INITIAL_GENERATION, INITIAL_GENERATION + 1),
            Err(NftablesError::Inconsistent)
        ));
        assert!(matches!(
            classify_observation(INITIAL_GENERATION + 1, INITIAL_GENERATION + 1),
            Err(NftablesError::NotPristine)
        ));
    }

    #[test]
    fn error_echo_framing_padding_and_budgets_fail_closed() {
        let request = encode_request(RequestKind::TableDump, TEST_SEQUENCE).expect("table request");
        let mut error_payload = (-libc::EINVAL).to_ne_bytes().to_vec();
        error_payload.extend(request);
        assert!(matches!(
            parse_request_error(0, &error_payload, &request),
            Ok(NftablesError::Kernel(code)) if code == libc::EINVAL
        ));
        error_payload[4] ^= 1;
        assert!(matches!(
            parse_request_error(0, &error_payload, &request),
            Err(NftablesError::Malformed)
        ));

        let mut nonzero_padding = attribute(NFTA_GEN_PROC_NAME, b"x\0");
        *nonzero_padding.last_mut().expect("alignment padding") = 1;
        assert!(matches!(
            parse_attributes(&nonzero_padding, 1),
            Err(NftablesError::Malformed)
        ));
        let mut too_many_attributes = Vec::new();
        for _ in 0..=MAX_GENERATION_ATTRIBUTES {
            too_many_attributes.extend(attribute(1, &[]));
        }
        assert!(matches!(
            parse_attributes(&too_many_attributes, MAX_GENERATION_ATTRIBUTES),
            Err(NftablesError::Limit)
        ));

        let mut bytes = CollectionBudget {
            bytes: MAX_TOTAL_BYTES,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_TOTAL_BYTES,
            max_datagrams: MAX_DATAGRAMS,
            max_frames: MAX_FRAMES,
        };
        assert!(matches!(
            bytes.record_datagram(NLMSG_HEADER_LEN),
            Err(NftablesError::Limit)
        ));
        let mut datagrams = CollectionBudget::production();
        datagrams.datagrams = MAX_DATAGRAMS;
        assert!(matches!(
            datagrams.record_datagram(NLMSG_HEADER_LEN),
            Err(NftablesError::Limit)
        ));
        let mut frames = CollectionBudget::production();
        frames.frames = MAX_FRAMES;
        assert!(matches!(frames.record_frame(), Err(NftablesError::Limit)));
        assert!(matches!(
            CollectionBudget::production().can_receive(MAX_DATAGRAM_BYTES + 1),
            Err(NftablesError::Limit)
        ));
    }

    #[test]
    fn expired_deadline_fails_before_opening_a_socket() {
        assert!(matches!(
            observe_empty_nftables(Instant::now()),
            Err(NftablesError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn collector_observes_real_empty_namespace_without_mutating_it() {
        if env::var_os(LIVE_COLLECTOR_CHILD_ENV).is_some() {
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(2))
                .expect("test deadline");
            let first = observe_empty_nftables(deadline).expect("empty nftables baseline");
            let second = observe_empty_nftables(deadline).expect("stable nftables baseline");
            assert_eq!(first, second);
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg("nftables::tests::collector_observes_real_empty_namespace_without_mutating_it")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_COLLECTOR_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .output()
            .expect("spawn isolated empty-nftables collector test");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live nftables proof: user namespaces denied by policy");
            return;
        }
        assert!(output.status.success(), "isolated nftables proof failed");
    }

    #[test]
    fn production_policy_writer_roundtrips_in_disposable_namespace() {
        if env::var_os(LIVE_POLICY_CHILD_ENV).is_some() {
            unshare(CloneFlags::CLONE_NEWNET)
                .expect("create a second disposable network namespace before mutation");
            let initial_forwarding =
                fs::read("/proc/sys/net/ipv4/ip_forward").expect("read forwarding before policy");
            assert!(
                matches!(initial_forwarding.as_slice(), b"0\n" | b"1\n"),
                "forwarding setting was not canonical"
            );
            let baseline = observe_empty_nftables(mutation_deadline().expect("baseline deadline"))
                .expect("generation-one baseline");
            let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
            let expectation = FixedForwardPolicyExpectation::for_run(&run_id, [2, 3])
                .expect("fixed policy expectation");
            let active = install_exact_forward_policy(
                baseline,
                expectation,
                mutation_deadline().expect("install deadline"),
            )
            .unwrap_or_else(|failure| {
                let (source, authority) = failure.into_parts();
                std::mem::forget(authority);
                panic!("active policy proof: {source:?}");
            });
            assert_eq!(active.journal().initial_generation, INITIAL_GENERATION);
            assert_eq!(active.journal().generation, ACTIVE_POLICY_GENERATION);
            assert_ne!(active.journal().handles.table, 0);
            assert_ne!(active.journal().handles.chain, 0);
            let [alpha, omega, terminal] = active.journal().handles.rules;
            assert!(alpha != omega && alpha != terminal && omega != terminal);
            verify_exact_forward_policy(
                &active,
                mutation_deadline().expect("active verification deadline"),
            )
            .expect("fresh exact active-policy verification");
            assert_eq!(
                fs::read("/proc/sys/net/ipv4/ip_forward").expect("read forwarding with policy"),
                initial_forwarding
            );
            let empty =
                delete_exact_forward_policy(active, mutation_deadline().expect("delete deadline"))
                    .unwrap_or_else(|failure| {
                        let (source, authority) = failure.into_parts();
                        std::mem::forget(authority);
                        panic!("semantic-empty proof: {source:?}");
                    });
            verify_semantically_empty_after_forward_policy(
                &empty,
                mutation_deadline().expect("retired verification deadline"),
            )
            .expect("fresh semantic-empty verification");
            assert_eq!(
                empty.generations,
                [
                    INITIAL_GENERATION,
                    ACTIVE_POLICY_GENERATION,
                    RETIRED_POLICY_GENERATION
                ]
            );
            assert_eq!(
                empty.expectation.table_name,
                b"vpl_0123456789abcdef0123456789abcdef"
            );
            assert_eq!(
                fs::read("/proc/sys/net/ipv4/ip_forward").expect("read forwarding after policy"),
                initial_forwarding
            );
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(executable)
            .arg("--exact")
            .arg("nftables::tests::production_policy_writer_roundtrips_in_disposable_namespace")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(LIVE_POLICY_CHILD_ENV, "1")
            .env("LC_ALL", "C")
            .output()
            .expect("spawn isolated nftables policy roundtrip");
        if unprivileged_user_namespace_policy_denied(
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ) {
            eprintln!("skipped live nftables policy roundtrip: user namespaces denied by policy");
            return;
        }
        assert!(
            output.status.success(),
            "isolated nftables policy roundtrip failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn policy_expectation_is_run_bound_and_ifindices_are_exactly_bounded() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation = FixedForwardPolicyExpectation::for_run(&run_id, [2, MAX_KERNEL_IFINDEX])
            .expect("maximum parent ifindex");
        assert_eq!(
            expectation.table_name,
            b"vpl_0123456789abcdef0123456789abcdef"
        );
        assert_eq!(expectation.parent_ifindices, [2, MAX_KERNEL_IFINDEX]);
        for ifindices in [
            [0, 2],
            [1, 2],
            [2, 2],
            [2, MAX_KERNEL_IFINDEX + 1],
            [MAX_KERNEL_IFINDEX + 1, 2],
        ] {
            assert!(matches!(
                FixedForwardPolicyExpectation::for_run(&run_id, ifindices),
                Err(NftablesError::Malformed)
            ));
        }
    }

    #[test]
    fn production_install_transaction_is_fixed_bounded_and_generation_pinned() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let transaction = encode_install_transaction(&expectation).expect("install transaction");
        let frames = split_test_netlink_frames(&transaction.bytes).expect("transaction frames");

        assert!(transaction.bytes.len() <= MAX_MUTATION_BATCH_BYTES);
        assert_eq!(frames.len(), 7);
        assert_eq!(transaction.requests.len(), 7);
        assert_eq!(
            transaction
                .requests
                .iter()
                .filter(|request| request.acknowledgement_required)
                .count(),
            5
        );
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(
                transaction.requests[index].header,
                frame[..NLMSG_HEADER_LEN]
            );
            assert_eq!(
                read_ne_u32(frame, 8).expect("sequence"),
                u32::try_from(index + 1).expect("test sequence")
            );
            assert_eq!(read_ne_u32(frame, 12).expect("kernel destination"), 0);
        }
        assert_eq!(
            frames
                .iter()
                .map(|frame| read_ne_u16(frame, 4).expect("message type"))
                .collect::<Vec<_>>(),
            [
                NFNL_MSG_BATCH_BEGIN,
                NFT_MSG_NEWTABLE,
                NFT_MSG_NEWCHAIN,
                NFT_MSG_NEWRULE,
                NFT_MSG_NEWRULE,
                NFT_MSG_NEWRULE,
                NFNL_MSG_BATCH_END,
            ]
        );
        assert_eq!(
            read_ne_u16(frames[0], 6).expect("begin flags"),
            NLM_F_REQUEST
        );
        assert_eq!(
            read_ne_u16(frames[1], 6).expect("table flags"),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(
            read_ne_u16(frames[2], 6).expect("chain flags"),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        for rule in &frames[3..=5] {
            assert_eq!(
                read_ne_u16(rule, 6).expect("rule flags"),
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND
            );
        }
        assert_eq!(read_ne_u16(frames[6], 6).expect("end flags"), NLM_F_REQUEST);

        let (begin_header, begin_attributes) =
            split_nfgenmsg(&frames[0][NLMSG_HEADER_LEN..]).expect("begin nfgenmsg");
        assert_eq!(begin_header.family, AF_UNSPEC);
        assert_eq!(begin_header.version, NFNETLINK_V0);
        assert_eq!(begin_header.resource_id, NFNL_SUBSYS_NFTABLES);
        let begin_attributes = parse_attributes(begin_attributes, 1).expect("generation pin");
        assert_eq!(begin_attributes.len(), 1);
        assert_eq!(begin_attributes[0].kind, NFNL_BATCH_GENID);
        assert_eq!(begin_attributes[0].flags, 0);
        assert_eq!(
            read_exact_be_u32(begin_attributes[0].payload).expect("generation"),
            INITIAL_GENERATION
        );

        let (end_header, end_attributes) =
            split_nfgenmsg(&frames[6][NLMSG_HEADER_LEN..]).expect("end nfgenmsg");
        assert_eq!(end_header.family, AF_UNSPEC);
        assert_eq!(end_header.version, NFNETLINK_V0);
        assert_eq!(end_header.resource_id, NFNL_SUBSYS_NFTABLES);
        assert!(end_attributes.is_empty());
    }

    #[test]
    fn production_delete_transaction_is_handle_only_and_generation_pinned() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let table_handle = 0x0102_0304_0506_0708;
        let journal = ActivePolicyJournal {
            expectation,
            initial_generation: INITIAL_GENERATION,
            generation: ACTIVE_POLICY_GENERATION,
            handles: PolicyHandles {
                table: table_handle,
                chain: 2,
                rules: [3, 4, 5],
            },
        };
        let transaction = encode_delete_transaction(&journal).expect("delete transaction");
        let frames = split_test_netlink_frames(&transaction.bytes).expect("transaction frames");

        assert_eq!(frames.len(), 3);
        assert_eq!(transaction.requests.len(), 3);
        assert_eq!(
            read_ne_u16(frames[0], 4).expect("begin"),
            NFNL_MSG_BATCH_BEGIN
        );
        assert_eq!(read_ne_u16(frames[1], 4).expect("delete"), NFT_MSG_DELTABLE);
        assert_eq!(read_ne_u16(frames[2], 4).expect("end"), NFNL_MSG_BATCH_END);
        let (_, begin_attributes) =
            split_nfgenmsg(&frames[0][NLMSG_HEADER_LEN..]).expect("begin nfgenmsg");
        let begin_attributes = parse_attributes(begin_attributes, 1).expect("generation pin");
        assert_eq!(begin_attributes.len(), 1);
        assert_eq!(begin_attributes[0].kind, NFNL_BATCH_GENID);
        assert_eq!(
            read_exact_be_u32(begin_attributes[0].payload).expect("generation"),
            ACTIVE_POLICY_GENERATION
        );

        let (delete_header, delete_attributes) =
            split_nfgenmsg(&frames[1][NLMSG_HEADER_LEN..]).expect("delete nfgenmsg");
        assert_eq!(delete_header.family, NFPROTO_INET);
        assert_eq!(delete_header.version, NFNETLINK_V0);
        assert_eq!(delete_header.resource_id, 0);
        let delete_attributes = parse_attributes(delete_attributes, 1).expect("delete attributes");
        assert_eq!(delete_attributes.len(), 1);
        assert_eq!(delete_attributes[0].kind, NFTA_TABLE_HANDLE);
        assert_eq!(delete_attributes[0].flags, 0);
        assert_eq!(
            read_exact_be_u64(delete_attributes[0].payload).expect("table handle"),
            table_handle
        );
        assert_ne!(delete_attributes[0].kind, NFTA_TABLE_NAME);
    }

    #[test]
    fn mutation_acknowledgements_are_exact_bound_ordered_and_capped() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let transaction = encode_install_transaction(&expectation).expect("install transaction");
        let required = transaction
            .requests
            .iter()
            .enumerate()
            .filter_map(|(index, request)| request.acknowledgement_required.then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(required, [1, 2, 3, 4, 5]);

        let mut state = MutationAckState::new(TEST_PORT, &transaction.requests);
        let mut budget = test_mutation_ack_budget();
        for index in required.iter().copied() {
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &test_capped_ack(&transaction.requests[index].header, TEST_PORT, 0),
                    &mut budget,
                )
                .expect("ordered exact acknowledgement");
        }
        assert!(state.is_complete());
        state.finish().expect("all acknowledgements");

        let mut out_of_order = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            out_of_order.ingest(
                SocketAddr::new(0, 0),
                &test_capped_ack(&transaction.requests[2].header, TEST_PORT, 0),
                &mut test_mutation_ack_budget(),
            ),
            Err(NftablesError::Malformed)
        ));

        let mut positive_begin = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            positive_begin.ingest(
                SocketAddr::new(0, 0),
                &test_capped_ack(&transaction.requests[0].header, TEST_PORT, 0),
                &mut test_mutation_ack_budget(),
            ),
            Err(NftablesError::Malformed)
        ));

        let mut negative_begin = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            negative_begin.ingest(
                SocketAddr::new(0, 0),
                &test_capped_ack(&transaction.requests[0].header, TEST_PORT, -16),
                &mut test_mutation_ack_budget(),
            ),
            Err(NftablesError::Kernel(16))
        ));

        let mut tampered = test_capped_ack(&transaction.requests[1].header, TEST_PORT, 0);
        tampered[NLMSG_HEADER_LEN + 4 + 4] ^= 1;
        let mut tampered_state = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            tampered_state.ingest(
                SocketAddr::new(0, 0),
                &tampered,
                &mut test_mutation_ack_budget(),
            ),
            Err(NftablesError::Malformed)
        ));
    }

    #[test]
    fn mutation_ack_envelope_rejects_every_ambiguity_and_budget_overrun() {
        const NLM_F_ACK_TLVS: u16 = 0x0200;

        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let transaction = encode_install_transaction(&expectation).expect("install transaction");
        let request = transaction.requests[1];
        let canonical = test_capped_ack(&request.header, TEST_PORT, 0);

        let mut wrong_port = canonical.clone();
        wrong_port[12..16].copy_from_slice(&(TEST_PORT + 1).to_ne_bytes());
        let mut wrong_sequence = canonical.clone();
        wrong_sequence[8..12].copy_from_slice(&99_u32.to_ne_bytes());
        let mut wrong_flags = canonical.clone();
        wrong_flags[6..8].copy_from_slice(&0_u16.to_ne_bytes());
        let mut wrong_embedded_header = canonical.clone();
        wrong_embedded_header[NLMSG_HEADER_LEN + 4 + 4] ^= 1;
        let mut unknown_exact_pair = canonical.clone();
        unknown_exact_pair[8..12].copy_from_slice(&99_u32.to_ne_bytes());
        unknown_exact_pair[NLMSG_HEADER_LEN + 4 + 8..NLMSG_HEADER_LEN + 4 + 12]
            .copy_from_slice(&99_u32.to_ne_bytes());
        let mut with_ack_tlv = canonical.clone();
        with_ack_tlv.extend(attribute(1, &[]));
        let with_ack_tlv_length = u32::try_from(with_ack_tlv.len()).expect("test ACK length");
        with_ack_tlv[0..4].copy_from_slice(&with_ack_tlv_length.to_ne_bytes());
        with_ack_tlv[6..8].copy_from_slice(&(NLM_F_CAPPED | NLM_F_ACK_TLVS).to_ne_bytes());
        let mut trailing_datagram_bytes = canonical.clone();
        trailing_datagram_bytes.extend([0; 4]);

        for (case, sender, frame) in [
            (
                "non-kernel sender",
                SocketAddr::new(1, 0),
                canonical.clone(),
            ),
            ("wrong destination port", SocketAddr::new(0, 0), wrong_port),
            (
                "wrong outer sequence",
                SocketAddr::new(0, 0),
                wrong_sequence,
            ),
            ("wrong flags", SocketAddr::new(0, 0), wrong_flags),
            (
                "mismatched embedded header",
                SocketAddr::new(0, 0),
                wrong_embedded_header,
            ),
            (
                "unknown extra acknowledgement",
                SocketAddr::new(0, 0),
                unknown_exact_pair,
            ),
            ("ACK TLV", SocketAddr::new(0, 0), with_ack_tlv),
            (
                "trailing datagram bytes",
                SocketAddr::new(0, 0),
                trailing_datagram_bytes,
            ),
        ] {
            let mut state = MutationAckState::new(TEST_PORT, &transaction.requests);
            assert!(
                matches!(
                    state.ingest(sender, &frame, &mut test_mutation_ack_budget()),
                    Err(NftablesError::Malformed)
                ),
                "ambiguous ACK case was accepted: {case}"
            );
        }
    }

    #[test]
    fn mutation_ack_state_rejects_duplicates_gaps_extras_and_budget_overruns() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let transaction = encode_install_transaction(&expectation).expect("install transaction");
        let canonical = test_capped_ack(&transaction.requests[1].header, TEST_PORT, 0);

        let mut duplicate = MutationAckState::new(TEST_PORT, &transaction.requests);
        duplicate
            .ingest(
                SocketAddr::new(0, 0),
                &canonical,
                &mut test_mutation_ack_budget(),
            )
            .expect("first exact ACK");
        assert!(matches!(
            duplicate.ingest(
                SocketAddr::new(0, 0),
                &canonical,
                &mut test_mutation_ack_budget(),
            ),
            Err(NftablesError::Malformed)
        ));

        let mut missing = MutationAckState::new(TEST_PORT, &transaction.requests);
        for index in [1, 2, 3, 4] {
            missing
                .ingest(
                    SocketAddr::new(0, 0),
                    &test_capped_ack(&transaction.requests[index].header, TEST_PORT, 0),
                    &mut test_mutation_ack_budget(),
                )
                .expect("partial ordered ACKs");
        }
        assert!(matches!(missing.finish(), Err(NftablesError::Malformed)));

        let mut complete = MutationAckState::new(TEST_PORT, &transaction.requests);
        for index in [1, 2, 3, 4, 5] {
            complete
                .ingest(
                    SocketAddr::new(0, 0),
                    &test_capped_ack(&transaction.requests[index].header, TEST_PORT, 0),
                    &mut test_mutation_ack_budget(),
                )
                .expect("complete ordered ACKs");
        }
        assert!(matches!(
            complete.ingest(
                SocketAddr::new(0, 0),
                &canonical,
                &mut test_mutation_ack_budget(),
            ),
            Err(NftablesError::Malformed)
        ));

        let mut byte_budget = test_mutation_ack_budget();
        byte_budget.max_bytes = canonical.len() - 1;
        let mut state = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            state.ingest(SocketAddr::new(0, 0), &canonical, &mut byte_budget),
            Err(NftablesError::Limit)
        ));
        let mut datagram_budget = test_mutation_ack_budget();
        datagram_budget.max_datagrams = 0;
        let mut state = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            state.ingest(SocketAddr::new(0, 0), &canonical, &mut datagram_budget,),
            Err(NftablesError::Limit)
        ));
        let mut frame_budget = test_mutation_ack_budget();
        frame_budget.max_frames = 0;
        let mut state = MutationAckState::new(TEST_PORT, &transaction.requests);
        assert!(matches!(
            state.ingest(SocketAddr::new(0, 0), &canonical, &mut frame_budget),
            Err(NftablesError::Limit)
        ));
    }

    #[test]
    fn active_and_indeterminate_authority_drop_guards_abort() {
        const TEST_NAME: &str =
            "nftables::tests::active_and_indeterminate_authority_drop_guards_abort";

        if let Ok(kind) = env::var(DROP_GUARD_CHILD_ENV) {
            let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
            let expectation =
                FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
            match kind.as_str() {
                "active" => {
                    let _guard =
                        ActiveNftablesPolicy::from_journal(test_active_journal(expectation));
                }
                "indeterminate-install" => {
                    let initial = NftablesBaseline {
                        generation: INITIAL_GENERATION,
                        _thread_bound: PhantomData,
                    };
                    let _guard = IndeterminateNftablesPolicy::after_install(initial, expectation);
                }
                "indeterminate-delete" => {
                    let _guard =
                        IndeterminateNftablesPolicy::after_delete(test_active_journal(expectation));
                }
                _ => panic!("unknown drop-guard child case"),
            }
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        for kind in ["active", "indeterminate-install", "indeterminate-delete"] {
            let output = Command::new(&executable)
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--test-threads=1")
                .arg("--nocapture")
                .env(DROP_GUARD_CHILD_ENV, kind)
                .env("LC_ALL", "C")
                .output()
                .expect("spawn drop-guard child");
            assert_eq!(
                output.status.signal(),
                Some(libc::SIGABRT),
                "{kind} guard did not abort: status={:?} stdout={:?} stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[test]
    fn exact_policy_snapshot_rejects_broadened_nfproto_and_icmp_code() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let snapshot = test_policy_snapshot(&expectation).expect("canonical policy snapshot");
        let observation = snapshot
            .exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION)
            .expect("exact policy");
        assert_eq!(observation.handles.table, 1);
        assert_eq!(observation.handles.chain, 1);
        assert_eq!(observation.handles.rules, [2, 3, 4]);
        assert_eq!(observation.counters, ForwardPolicyCounters::ZERO);

        let mut wrong_nfproto = test_policy_snapshot(&expectation).expect("policy snapshot");
        let ObservedExpression::Compare { value, .. } = &mut wrong_nfproto.rules[0].expressions[5]
        else {
            panic!("nfproto comparison position changed");
        };
        *value = vec![NFPROTO_IPV6];
        assert!(matches!(
            wrong_nfproto.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut missing_nfproto = test_policy_snapshot(&expectation).expect("policy snapshot");
        missing_nfproto.rules[0].expressions.drain(4..=5);
        assert!(matches!(
            missing_nfproto.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut wrong_code = test_policy_snapshot(&expectation).expect("policy snapshot");
        let ObservedExpression::Compare { value, .. } = &mut wrong_code.rules[0].expressions[13]
        else {
            panic!("ICMP type/code comparison position changed");
        };
        *value = vec![ICMP_ECHO_REQUEST, 1];
        assert!(matches!(
            wrong_code.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut missing_code = test_policy_snapshot(&expectation).expect("policy snapshot");
        let ObservedExpression::Compare { value, .. } = &mut missing_code.rules[0].expressions[13]
        else {
            panic!("ICMP type/code comparison position changed");
        };
        *value = vec![ICMP_ECHO_REQUEST];
        assert!(matches!(
            missing_code.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut reordered_expressions =
            test_policy_snapshot(&expectation).expect("policy snapshot");
        reordered_expressions.rules[0].expressions.swap(4, 6);
        assert!(matches!(
            reordered_expressions.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut direct_exit = test_policy_snapshot(&expectation).expect("policy snapshot");
        let ObservedExpression::Compare { value, .. } = &mut direct_exit.rules[0].expressions[3]
        else {
            panic!("output-ifindex comparison position changed");
        };
        *value = 99_u32.to_ne_bytes().to_vec();
        assert!(matches!(
            direct_exit.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));
    }

    #[test]
    fn install_and_runtime_require_generation_bound_zero_counter_evidence() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");

        let zero_snapshot = test_policy_snapshot(&expectation).expect("policy snapshot");
        let zero =
            validate_zero_counter_policy(&zero_snapshot, &expectation, ACTIVE_POLICY_GENERATION)
                .expect("zero-counter evidence");
        assert_eq!(zero.generation, ACTIVE_POLICY_GENERATION);
        assert_eq!(zero.handles.rules, [2, 3, 4]);

        let mutations = [
            (0, ACCEPT_RULE_COUNTER_EXPRESSION, 64, 1),
            (2, TERMINAL_RULE_COUNTER_EXPRESSION, u64::MAX, u64::MAX),
        ];
        for (rule, expression, bytes, packets) in mutations {
            let mut nonzero = test_policy_snapshot(&expectation).expect("policy snapshot");
            nonzero.rules[rule].expressions[expression] =
                ObservedExpression::Counter(ForwardPolicyCounter { bytes, packets });
            let observation = nonzero
                .exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION)
                .expect("counter values do not weaken exact structure");
            assert_eq!(
                observation.counters.0[rule],
                ForwardPolicyCounter { bytes, packets }
            );
            assert!(matches!(
                validate_zero_counter_policy(&nonzero, &expectation, ACTIVE_POLICY_GENERATION),
                Err(NftablesError::UnexpectedPolicy)
            ));
        }

        assert!(matches!(
            validate_zero_counter_policy(&zero_snapshot, &expectation, RETIRED_POLICY_GENERATION),
            Err(NftablesError::UnexpectedGeneration)
        ));

        assert!(matches!(
            exact_rule_counter(&expectation, 3, &[]),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut verdict_before_counter =
            test_policy_snapshot(&expectation).expect("policy snapshot");
        verdict_before_counter.rules[1]
            .expressions
            .swap(ACCEPT_RULE_COUNTER_EXPRESSION, ACCEPT_RULE_EXPRESSIONS - 1);
        assert!(matches!(
            verdict_before_counter.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut broadened_terminal = test_policy_snapshot(&expectation).expect("policy snapshot");
        broadened_terminal.rules[2].expressions[1] = ObservedExpression::ImmediateAccept;
        assert!(matches!(
            broadened_terminal.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut missing_terminal = test_policy_snapshot(&expectation).expect("policy snapshot");
        missing_terminal.rules.pop();
        assert!(matches!(
            missing_terminal.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut wrong_terminal_position =
            test_policy_snapshot(&expectation).expect("policy snapshot");
        wrong_terminal_position.rules[2].position = Some(2);
        assert!(matches!(
            wrong_terminal_position
                .exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut duplicate_handle = test_policy_snapshot(&expectation).expect("policy snapshot");
        duplicate_handle.rules[2].handle = duplicate_handle.rules[1].handle;
        assert!(matches!(
            duplicate_handle.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        for use_count in [2, 4] {
            let mut wrong_use_count = test_policy_snapshot(&expectation).expect("policy snapshot");
            wrong_use_count.chains[0].use_count = use_count;
            assert!(matches!(
                wrong_use_count.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
                Err(NftablesError::UnexpectedPolicy)
            ));
        }

        let mut chain_counter = test_policy_snapshot(&expectation).expect("policy snapshot");
        chain_counter.chains[0].counters = Some(Vec::new());
        assert!(matches!(
            chain_counter.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        for rule in 0..3 {
            let mut zero_handle = test_policy_snapshot(&expectation).expect("policy snapshot");
            zero_handle.rules[rule].handle = 0;
            assert!(matches!(
                zero_handle.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
                Err(NftablesError::UnexpectedPolicy)
            ));
        }
    }

    #[test]
    fn deletion_authority_accepts_nonzero_counters_but_not_structural_drift() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let mut journal = ActivePolicyJournal {
            expectation,
            initial_generation: INITIAL_GENERATION,
            generation: ACTIVE_POLICY_GENERATION,
            handles: PolicyHandles {
                table: 1,
                chain: 1,
                rules: [2, 3, 4],
            },
        };
        let mut nonzero = test_policy_snapshot(&journal.expectation).expect("policy snapshot");
        for rule in 0..2 {
            nonzero.rules[rule].expressions[ACCEPT_RULE_COUNTER_EXPRESSION] =
                ObservedExpression::Counter(ForwardPolicyCounter {
                    bytes: 60,
                    packets: 1,
                });
        }
        nonzero.rules[2].expressions[TERMINAL_RULE_COUNTER_EXPRESSION] =
            ObservedExpression::Counter(ForwardPolicyCounter {
                bytes: u64::MAX,
                packets: u64::MAX,
            });
        validate_deletion_authority(&journal, &nonzero, ACTIVE_POLICY_GENERATION)
            .expect("nonzero counters retain exact deletion authority");

        assert!(matches!(
            validate_deletion_authority(&journal, &nonzero, RETIRED_POLICY_GENERATION),
            Err(NftablesError::UnexpectedGeneration)
        ));

        let canonical_handles = journal.handles;
        journal.generation = RETIRED_POLICY_GENERATION;
        assert!(matches!(
            validate_deletion_authority(&journal, &nonzero, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedGeneration)
        ));
        journal.generation = ACTIVE_POLICY_GENERATION;

        for handle_index in 0..5 {
            journal.handles = canonical_handles;
            match handle_index {
                0 => journal.handles.table += 1,
                1 => journal.handles.chain += 1,
                2..=4 => journal.handles.rules[handle_index - 2] += 10,
                _ => unreachable!(),
            }
            assert!(matches!(
                validate_deletion_authority(&journal, &nonzero, ACTIVE_POLICY_GENERATION),
                Err(NftablesError::UnexpectedPolicy)
            ));
        }
        journal.handles = canonical_handles;

        let wrong_run = RunId::parse("fedcba9876543210fedcba9876543210").expect("other run id");
        journal.expectation =
            FixedForwardPolicyExpectation::for_run(&wrong_run, [3, 5]).expect("wrong run");
        assert!(matches!(
            validate_deletion_authority(&journal, &nonzero, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        journal.expectation = FixedForwardPolicyExpectation::for_run(&run_id, [3, 6])
            .expect("wrong interface lineage");
        assert!(matches!(
            validate_deletion_authority(&journal, &nonzero, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        journal.expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        nonzero.rules[1]
            .expressions
            .swap(ACCEPT_RULE_COUNTER_EXPRESSION, ACCEPT_RULE_EXPRESSIONS - 1);
        assert!(matches!(
            validate_deletion_authority(&journal, &nonzero, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));
    }

    #[test]
    fn policy_expression_parser_is_byte_exact_and_bounded() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let expressions = expectation.expected_rule_expressions(0);
        let dump = encode_test_dump_expressions(&expressions).expect("dump expressions");
        assert_eq!(parse_expressions(&dump).expect("parsed dump"), expressions);

        let outbound = encode_policy_expressions(&expressions).expect("production expressions");
        assert_eq!(
            outbound,
            encode_test_expressions(&expressions).expect("independent outbound fixture")
        );
        assert!(matches!(
            parse_expressions(&outbound),
            Err(NftablesError::Malformed)
        ));

        let terminal = expectation.expected_rule_expressions(2);
        let terminal_dump =
            encode_test_dump_expressions(&terminal).expect("terminal dump expressions");
        assert_eq!(
            parse_expressions(&terminal_dump).expect("parsed terminal dump"),
            terminal
        );
        assert_eq!(
            encode_policy_expressions(&terminal).expect("production terminal expressions"),
            encode_test_expressions(&terminal).expect("independent terminal fixture")
        );

        let mut shortened = dump.clone();
        let mut offset = 0;
        let mut last_offset = 0;
        while offset < shortened.len() {
            last_offset = offset;
            let length = usize::from(read_ne_u16(&shortened, offset).expect("element length"));
            offset += align4(length).expect("aligned element");
        }
        shortened.truncate(last_offset);
        assert!(matches!(
            parse_expressions(&shortened),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut nonzero_padding = dump;
        nonzero_padding[ATTRIBUTE_HEADER_LEN + 9] = 1;
        assert!(matches!(
            parse_expressions(&nonzero_padding),
            Err(NftablesError::Malformed)
        ));
    }

    #[test]
    fn counter_expression_parser_is_typed_ordered_and_bounded() {
        let mut canonical = attribute(NFTA_COUNTER_BYTES, &u64::MAX.to_be_bytes());
        canonical.extend(attribute(NFTA_COUNTER_PACKETS, &7_u64.to_be_bytes()));
        assert_eq!(
            parse_counter_expression(&canonical).expect("typed counter"),
            ObservedExpression::Counter(ForwardPolicyCounter {
                bytes: u64::MAX,
                packets: 7,
            })
        );

        let mut padded = attribute(NFTA_COUNTER_PAD, &[]);
        padded.extend(attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes()));
        padded.extend(attribute(NFTA_COUNTER_PAD, &[]));
        padded.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
        assert_eq!(
            parse_counter_expression(&padded).expect("aligned zero counter"),
            ObservedExpression::Counter(ForwardPolicyCounter::ZERO)
        );

        let mut second_value_padded = attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes());
        second_value_padded.extend(attribute(NFTA_COUNTER_PAD, &[]));
        second_value_padded.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
        assert_eq!(
            parse_counter_expression(&second_value_padded)
                .expect("second aligned zero counter value"),
            ObservedExpression::Counter(ForwardPolicyCounter::ZERO)
        );

        let malformed = [
            attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes()),
            {
                let mut duplicate = attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes());
                duplicate.extend(attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes()));
                duplicate.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
                duplicate
            },
            {
                let mut reversed = attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes());
                reversed.extend(attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes()));
                reversed
            },
            {
                let mut short = attribute(NFTA_COUNTER_BYTES, &0_u32.to_be_bytes());
                short.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
                short
            },
            {
                let mut nonempty_pad = attribute(NFTA_COUNTER_PAD, &[0]);
                nonempty_pad.extend(attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes()));
                nonempty_pad.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
                nonempty_pad
            },
            {
                let mut trailing_pad = attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes());
                trailing_pad.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
                trailing_pad.extend(attribute(NFTA_COUNTER_PAD, &[]));
                trailing_pad
            },
            {
                let mut flagged = attribute(
                    NFTA_COUNTER_BYTES | NLA_F_NET_BYTEORDER,
                    &0_u64.to_be_bytes(),
                );
                flagged.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
                flagged
            },
            {
                let mut unknown = attribute(NFTA_COUNTER_BYTES, &0_u64.to_be_bytes());
                unknown.extend(attribute(NFTA_COUNTER_PACKETS, &0_u64.to_be_bytes()));
                unknown.extend(attribute(4, &[]));
                unknown
            },
        ];
        for payload in malformed {
            assert!(matches!(
                parse_counter_expression(&payload),
                Err(NftablesError::Malformed)
            ));
        }
    }

    #[test]
    fn all_object_dump_requests_and_reply_flags_are_pinned() {
        for kind in ObjectKind::ALL {
            let request = encode_object_dump_request(kind, TEST_SEQUENCE).expect("object dump");
            assert_eq!(read_ne_u16(&request, 4).expect("type"), kind.request_type());
            assert_eq!(
                read_ne_u16(&request, 6).expect("flags"),
                NLM_F_REQUEST | NLM_F_DUMP
            );
            assert_eq!(&request[NLMSG_HEADER_LEN..], &[0; NFGENMSG_LEN]);
            let expected_reply_flags = if matches!(
                kind,
                ObjectKind::Rule | ObjectKind::Object | ObjectKind::Flowtable
            ) {
                NLM_F_MULTI | NLM_F_APPEND
            } else {
                NLM_F_MULTI
            };
            assert_eq!(kind.reply_flags(), expected_reply_flags);
        }
        assert!(matches!(
            encode_object_dump_request(ObjectKind::Table, 0),
            Err(NftablesError::Malformed)
        ));
    }

    #[test]
    fn object_and_flowtable_dumps_require_kernel_append_flag() {
        for kind in [ObjectKind::Object, ObjectKind::Flowtable] {
            let request =
                encode_object_dump_request(kind, TEST_SEQUENCE).expect("object dump request");
            let payload = nfgenmsg(NFPROTO_INET, ACTIVE_POLICY_GENERATION);

            let mut canonical_snapshot = RulesetSnapshot::default();
            let mut canonical = ObjectDumpState::new(
                kind,
                TEST_SEQUENCE,
                TEST_PORT,
                ACTIVE_POLICY_GENERATION,
                request,
                &mut canonical_snapshot,
            );
            assert!(matches!(
                canonical.ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(
                        kind.reply_type(),
                        NLM_F_MULTI | NLM_F_APPEND,
                        TEST_SEQUENCE,
                        TEST_PORT,
                        &payload,
                    ),
                    &mut CollectionBudget::production(),
                ),
                Err(NftablesError::UnexpectedPolicy)
            ));

            let mut rejected_snapshot = RulesetSnapshot::default();
            let mut rejected = ObjectDumpState::new(
                kind,
                TEST_SEQUENCE,
                TEST_PORT,
                ACTIVE_POLICY_GENERATION,
                request,
                &mut rejected_snapshot,
            );
            assert!(matches!(
                rejected.ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(
                        kind.reply_type(),
                        NLM_F_MULTI,
                        TEST_SEQUENCE,
                        TEST_PORT,
                        &payload,
                    ),
                    &mut CollectionBudget::production(),
                ),
                Err(NftablesError::Malformed)
            ));
        }
    }

    #[test]
    fn rule_dump_requires_append_and_exact_position_lineage() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");
        let payload = test_rule_payload(&expectation, 0, 2, None).expect("rule payload");
        let request =
            encode_object_dump_request(ObjectKind::Rule, TEST_SEQUENCE).expect("rule request");
        let mut snapshot = RulesetSnapshot::default();
        {
            let mut state = ObjectDumpState::new(
                ObjectKind::Rule,
                TEST_SEQUENCE,
                TEST_PORT,
                ACTIVE_POLICY_GENERATION,
                request,
                &mut snapshot,
            );
            state
                .ingest(
                    SocketAddr::new(0, 0),
                    &netlink_frame(
                        NFT_MSG_NEWRULE,
                        NLM_F_MULTI | NLM_F_APPEND,
                        TEST_SEQUENCE,
                        TEST_PORT,
                        &payload,
                    ),
                    &mut CollectionBudget::production(),
                )
                .expect("canonical rule reply");
        }
        assert_eq!(snapshot.rules.len(), 1);

        let mut rejected = RulesetSnapshot::default();
        let mut state = ObjectDumpState::new(
            ObjectKind::Rule,
            TEST_SEQUENCE,
            TEST_PORT,
            ACTIVE_POLICY_GENERATION,
            request,
            &mut rejected,
        );
        assert!(matches!(
            state.ingest(
                SocketAddr::new(0, 0),
                &netlink_frame(
                    NFT_MSG_NEWRULE,
                    NLM_F_MULTI,
                    TEST_SEQUENCE,
                    TEST_PORT,
                    &payload,
                ),
                &mut CollectionBudget::production(),
            ),
            Err(NftablesError::Malformed)
        ));

        let mut wrong_position = test_policy_snapshot(&expectation).expect("policy snapshot");
        wrong_position.rules[1].position = Some(99);
        assert!(matches!(
            wrong_position.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));
    }

    #[test]
    fn policy_generation_brackets_require_exact_successors() {
        for generation in [ACTIVE_POLICY_GENERATION, RETIRED_POLICY_GENERATION] {
            validate_ruleset_generation(generation, generation, generation)
                .expect("exact stable generation");
            assert!(matches!(
                validate_ruleset_generation(generation, generation + 1, generation),
                Err(NftablesError::Inconsistent)
            ));
            assert!(matches!(
                validate_ruleset_generation(generation + 1, generation + 1, generation),
                Err(NftablesError::UnexpectedGeneration)
            ));
        }
    }

    #[test]
    fn pristine_boundary_classifies_every_well_formed_extra_object_as_not_pristine() {
        for kind in [ObjectKind::Set, ObjectKind::Object, ObjectKind::Flowtable] {
            let mut snapshot = RulesetSnapshot::default();
            let error = snapshot
                .ingest(
                    kind,
                    &nfgenmsg(NFPROTO_INET, INITIAL_GENERATION),
                    INITIAL_GENERATION,
                )
                .expect_err("an extra object cannot be pristine");
            assert!(matches!(
                normalize_pristine_ruleset_error(error),
                NftablesError::NotPristine
            ));
        }
    }

    #[test]
    fn policy_snapshot_rejects_wrong_chain_order_and_every_extra_object_class() {
        let run_id = RunId::parse("0123456789abcdef0123456789abcdef").expect("fixed run id");
        let expectation =
            FixedForwardPolicyExpectation::for_run(&run_id, [3, 5]).expect("expectation");

        let mut wrong_family = test_policy_snapshot(&expectation).expect("policy snapshot");
        wrong_family.tables[0].family = NFPROTO_IPV4;
        assert!(matches!(
            wrong_family.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut wrong_hook = test_policy_snapshot(&expectation).expect("policy snapshot");
        wrong_hook.chains[0].hook_number = 1;
        assert!(matches!(
            wrong_hook.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut wrong_policy = test_policy_snapshot(&expectation).expect("policy snapshot");
        wrong_policy.chains[0].policy = NF_ACCEPT;
        assert!(matches!(
            wrong_policy.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut reversed = test_policy_snapshot(&expectation).expect("policy snapshot");
        reversed.rules.swap(0, 1);
        assert!(matches!(
            reversed.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut extra_table = test_policy_snapshot(&expectation).expect("policy snapshot");
        extra_table.tables.push(
            parse_table_payload(
                &test_table_payload(&expectation).expect("table payload"),
                ACTIVE_POLICY_GENERATION,
            )
            .expect("table record"),
        );
        assert!(matches!(
            extra_table.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut extra_chain = test_policy_snapshot(&expectation).expect("policy snapshot");
        extra_chain.chains.push(
            parse_chain_payload(
                &test_chain_payload(&expectation).expect("chain payload"),
                ACTIVE_POLICY_GENERATION,
            )
            .expect("chain record"),
        );
        assert!(matches!(
            extra_chain.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        let mut extra_rule = test_policy_snapshot(&expectation).expect("policy snapshot");
        extra_rule.rules.push(
            parse_rule_payload(
                &test_rule_payload(&expectation, 0, 4, None).expect("rule payload"),
                ACTIVE_POLICY_GENERATION,
            )
            .expect("rule record"),
        );
        assert!(matches!(
            extra_rule.exact_policy_observation(&expectation, ACTIVE_POLICY_GENERATION),
            Err(NftablesError::UnexpectedPolicy)
        ));

        for kind in [ObjectKind::Set, ObjectKind::Object, ObjectKind::Flowtable] {
            let mut snapshot = RulesetSnapshot::default();
            let payload = nfgenmsg(NFPROTO_INET, ACTIVE_POLICY_GENERATION);
            assert!(matches!(
                snapshot.ingest(kind, &payload, ACTIVE_POLICY_GENERATION),
                Err(NftablesError::UnexpectedPolicy)
            ));
            let mut wrong_generation = payload;
            wrong_generation[2..4]
                .copy_from_slice(&generation_resource_id(RETIRED_POLICY_GENERATION).to_be_bytes());
            assert!(matches!(
                snapshot.ingest(kind, &wrong_generation, ACTIVE_POLICY_GENERATION),
                Err(NftablesError::Malformed)
            ));
        }
    }

    #[test]
    fn user_namespace_policy_skip_is_exact() {
        for error in [
            b"unshare: unshare failed: Operation not permitted\n".as_slice(),
            b"unshare: write failed /proc/self/uid_map: Operation not permitted\n".as_slice(),
            b"unshare: write failed /proc/self/gid_map: Operation not permitted\n".as_slice(),
        ] {
            assert!(unprivileged_user_namespace_policy_denied(
                Some(1),
                &[],
                error
            ));
            assert!(!unprivileged_user_namespace_policy_denied(
                Some(2),
                &[],
                error
            ));
            assert!(!unprivileged_user_namespace_policy_denied(
                Some(1),
                b"unexpected",
                error
            ));
        }
        assert!(!unprivileged_user_namespace_policy_denied(
            Some(1),
            &[],
            b"unshare: unexpected failure\n"
        ));
    }

    fn generation_state() -> GenerationState {
        let request =
            encode_request(RequestKind::Generation, TEST_SEQUENCE).expect("generation request");
        GenerationState::new(TEST_SEQUENCE, TEST_PORT, request)
    }

    fn table_state(generation: u32) -> TableDumpState {
        let request = encode_request(RequestKind::TableDump, TEST_SEQUENCE).expect("table request");
        TableDumpState::new(TEST_SEQUENCE, TEST_PORT, generation, request)
    }

    fn object_table_state(snapshot: &mut RulesetSnapshot) -> ObjectDumpState<'_> {
        let request =
            encode_object_dump_request(ObjectKind::Table, TEST_SEQUENCE).expect("table request");
        ObjectDumpState::new(
            ObjectKind::Table,
            TEST_SEQUENCE,
            TEST_PORT,
            INITIAL_GENERATION,
            request,
            snapshot,
        )
    }

    fn generation_payload(generation: u32, order: &[u16]) -> Vec<u8> {
        let mut payload = nfgenmsg(AF_UNSPEC, generation);
        for kind in order {
            match *kind {
                NFTA_GEN_ID => payload.extend(attribute(*kind, &generation.to_be_bytes())),
                NFTA_GEN_PROC_PID => {
                    payload.extend(attribute(*kind, &123_u32.to_be_bytes()));
                }
                NFTA_GEN_PROC_NAME => payload.extend(attribute(*kind, b"test\0")),
                _ => payload.extend(attribute(*kind, &[])),
            }
        }
        payload
    }

    fn generation_payload_with(
        generation: u32,
        id: &[u8],
        process_id: &[u8],
        process_name: &[u8],
    ) -> Vec<u8> {
        let mut payload = nfgenmsg(AF_UNSPEC, generation);
        payload.extend(attribute(NFTA_GEN_ID, id));
        payload.extend(attribute(NFTA_GEN_PROC_PID, process_id));
        payload.extend(attribute(NFTA_GEN_PROC_NAME, process_name));
        payload
    }

    fn table_payload(generation: u32) -> Vec<u8> {
        table_payload_from_attributes(
            generation,
            [
                attribute(NFTA_TABLE_NAME, b"baseline\0"),
                attribute(NFTA_TABLE_USE, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()),
                attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()),
                attribute(NFTA_TABLE_PAD, &[]),
                attribute(NFTA_TABLE_USERDATA, &[1, 2]),
                attribute(NFTA_TABLE_OWNER, &123_u32.to_be_bytes()),
            ],
        )
    }

    fn table_payload_from_attributes<const N: usize>(
        generation: u32,
        attributes: [Vec<u8>; N],
    ) -> Vec<u8> {
        let mut payload = nfgenmsg(NFPROTO_IPV4, generation);
        for attribute in attributes {
            payload.extend(attribute);
        }
        payload
    }

    fn nfgenmsg(family: u8, generation: u32) -> Vec<u8> {
        let mut payload = vec![family, NFNETLINK_V0];
        payload.extend(generation_resource_id(generation).to_be_bytes());
        payload
    }

    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = ATTRIBUTE_HEADER_LEN + payload.len();
        let aligned = (length + 3) & !3;
        let mut bytes = Vec::with_capacity(aligned);
        bytes.extend(
            u16::try_from(length)
                .expect("test attribute length")
                .to_ne_bytes(),
        );
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(payload);
        bytes.resize(aligned, 0);
        bytes
    }

    fn netlink_frame(
        message_type: u16,
        flags: u16,
        sequence: u32,
        port: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let aligned = (length + 3) & !3;
        let mut bytes = Vec::with_capacity(aligned);
        bytes.extend(
            u32::try_from(length)
                .expect("test frame length")
                .to_ne_bytes(),
        );
        bytes.extend(message_type.to_ne_bytes());
        bytes.extend(flags.to_ne_bytes());
        bytes.extend(sequence.to_ne_bytes());
        bytes.extend(port.to_ne_bytes());
        bytes.extend(payload);
        bytes.resize(aligned, 0);
        bytes
    }

    fn split_test_netlink_frames(bytes: &[u8]) -> Result<Vec<&[u8]>, NftablesError> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            let length = usize::try_from(read_ne_u32(remaining, 0)?)
                .map_err(|_| NftablesError::Malformed)?;
            let aligned = align4(length)?;
            if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
                return Err(NftablesError::Malformed);
            }
            if remaining[length..aligned].iter().any(|byte| *byte != 0) {
                return Err(NftablesError::Malformed);
            }
            frames.push(&remaining[..length]);
            offset = offset.checked_add(aligned).ok_or(NftablesError::Limit)?;
        }
        Ok(frames)
    }

    fn test_capped_ack(
        request_header: &[u8; NLMSG_HEADER_LEN],
        local_port: u32,
        errno: i32,
    ) -> Vec<u8> {
        let mut payload = errno.to_ne_bytes().to_vec();
        payload.extend(request_header);
        netlink_frame(
            NLMSG_ERROR,
            NLM_F_CAPPED,
            read_ne_u32(request_header, 8).expect("request sequence"),
            local_port,
            &payload,
        )
    }

    fn test_mutation_ack_budget() -> CollectionBudget {
        CollectionBudget {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_MUTATION_ACK_BYTES,
            max_datagrams: MAX_MUTATION_ACK_DATAGRAMS,
            max_frames: MAX_MUTATION_ACK_FRAMES,
        }
    }

    fn test_active_journal(expectation: FixedForwardPolicyExpectation) -> ActivePolicyJournal {
        ActivePolicyJournal {
            expectation,
            initial_generation: INITIAL_GENERATION,
            generation: ACTIVE_POLICY_GENERATION,
            handles: PolicyHandles {
                table: 1,
                chain: 2,
                rules: [3, 4, 5],
            },
        }
    }

    fn test_policy_snapshot(
        expectation: &FixedForwardPolicyExpectation,
    ) -> Result<RulesetSnapshot, NftablesError> {
        let table =
            parse_table_payload(&test_table_payload(expectation)?, ACTIVE_POLICY_GENERATION)?;
        let chain =
            parse_chain_payload(&test_chain_payload(expectation)?, ACTIVE_POLICY_GENERATION)?;
        let alpha = parse_rule_payload(
            &test_rule_payload(expectation, 0, 2, None)?,
            ACTIVE_POLICY_GENERATION,
        )?;
        let omega = parse_rule_payload(
            &test_rule_payload(expectation, 1, 3, Some(2))?,
            ACTIVE_POLICY_GENERATION,
        )?;
        let terminal = parse_rule_payload(
            &test_rule_payload(expectation, 2, 4, Some(3))?,
            ACTIVE_POLICY_GENERATION,
        )?;
        Ok(RulesetSnapshot {
            tables: vec![table],
            chains: vec![chain],
            rules: vec![alpha, omega, terminal],
        })
    }

    fn test_table_payload(
        expectation: &FixedForwardPolicyExpectation,
    ) -> Result<Vec<u8>, NftablesError> {
        let mut payload = nfgenmsg(NFPROTO_INET, ACTIVE_POLICY_GENERATION);
        payload.extend(attribute(
            NFTA_TABLE_NAME,
            &nul_terminated(&expectation.table_name)?,
        ));
        payload.extend(attribute(NFTA_TABLE_USE, &1_u32.to_be_bytes()));
        payload.extend(attribute(NFTA_TABLE_HANDLE, &1_u64.to_be_bytes()));
        payload.extend(attribute(NFTA_TABLE_FLAGS, &0_u32.to_be_bytes()));
        Ok(payload)
    }

    fn test_chain_payload(
        expectation: &FixedForwardPolicyExpectation,
    ) -> Result<Vec<u8>, NftablesError> {
        let mut hook = attribute(NFTA_HOOK_HOOKNUM, &NF_INET_FORWARD.to_be_bytes());
        hook.extend(attribute(NFTA_HOOK_PRIORITY, &0_i32.to_be_bytes()));
        let mut payload = nfgenmsg(NFPROTO_INET, ACTIVE_POLICY_GENERATION);
        payload.extend(attribute(
            NFTA_CHAIN_TABLE,
            &nul_terminated(&expectation.table_name)?,
        ));
        payload.extend(attribute(
            NFTA_CHAIN_NAME,
            &nul_terminated(FORWARD_CHAIN_NAME)?,
        ));
        payload.extend(attribute(NFTA_CHAIN_HANDLE, &1_u64.to_be_bytes()));
        payload.extend(attribute(NFTA_CHAIN_HOOK, &hook));
        payload.extend(attribute(NFTA_CHAIN_POLICY, &NF_DROP.to_be_bytes()));
        payload.extend(attribute(
            NFTA_CHAIN_TYPE,
            &nul_terminated(FILTER_CHAIN_TYPE)?,
        ));
        payload.extend(attribute(NFTA_CHAIN_FLAGS, &NFT_CHAIN_BASE.to_be_bytes()));
        payload.extend(attribute(NFTA_CHAIN_USE, &3_u32.to_be_bytes()));
        Ok(payload)
    }

    fn test_rule_payload(
        expectation: &FixedForwardPolicyExpectation,
        rule_index: usize,
        handle: u64,
        position: Option<u64>,
    ) -> Result<Vec<u8>, NftablesError> {
        let mut payload = nfgenmsg(NFPROTO_INET, ACTIVE_POLICY_GENERATION);
        payload.extend(attribute(
            NFTA_RULE_TABLE,
            &nul_terminated(&expectation.table_name)?,
        ));
        payload.extend(attribute(
            NFTA_RULE_CHAIN,
            &nul_terminated(FORWARD_CHAIN_NAME)?,
        ));
        payload.extend(attribute(NFTA_RULE_HANDLE, &handle.to_be_bytes()));
        if let Some(position) = position {
            payload.extend(attribute(NFTA_RULE_POSITION, &position.to_be_bytes()));
        }
        payload.extend(attribute(
            NFTA_RULE_EXPRESSIONS,
            &encode_test_dump_expressions(&expectation.expected_rule_expressions(rule_index))?,
        ));
        Ok(payload)
    }

    fn encode_test_expressions(
        expressions: &[ObservedExpression],
    ) -> Result<Vec<u8>, NftablesError> {
        encode_test_expressions_with_flags(expressions, NLA_F_NESTED)
    }

    fn encode_test_dump_expressions(
        expressions: &[ObservedExpression],
    ) -> Result<Vec<u8>, NftablesError> {
        encode_test_expressions_with_flags(expressions, 0)
    }

    fn encode_test_expressions_with_flags(
        expressions: &[ObservedExpression],
        nested: u16,
    ) -> Result<Vec<u8>, NftablesError> {
        if !matches!(nested, 0 | NLA_F_NESTED) {
            return Err(NftablesError::Malformed);
        }
        if !matches!(
            expressions.len(),
            ACCEPT_RULE_EXPRESSIONS | TERMINAL_RULE_EXPRESSIONS
        ) {
            return Err(NftablesError::Malformed);
        }
        let mut encoded = Vec::new();
        for expression in expressions {
            let (name, data) = match expression {
                ObservedExpression::Meta { destination, key } => {
                    let mut data = attribute(NFTA_META_KEY, &key.to_be_bytes());
                    data.extend(attribute(NFTA_META_DREG, &destination.to_be_bytes()));
                    (b"meta".as_slice(), data)
                }
                ObservedExpression::Compare {
                    source,
                    operation,
                    value,
                } => {
                    let nested_value = attribute(NFTA_DATA_VALUE, value);
                    let mut data = attribute(NFTA_CMP_SREG, &source.to_be_bytes());
                    data.extend(attribute(NFTA_CMP_OP, &operation.to_be_bytes()));
                    data.extend(attribute(NFTA_CMP_DATA | nested, &nested_value));
                    (b"cmp".as_slice(), data)
                }
                ObservedExpression::Payload {
                    destination,
                    base,
                    offset,
                    length,
                } => {
                    let mut data = attribute(NFTA_PAYLOAD_DREG, &destination.to_be_bytes());
                    data.extend(attribute(NFTA_PAYLOAD_BASE, &base.to_be_bytes()));
                    data.extend(attribute(NFTA_PAYLOAD_OFFSET, &offset.to_be_bytes()));
                    data.extend(attribute(NFTA_PAYLOAD_LEN, &length.to_be_bytes()));
                    (b"payload".as_slice(), data)
                }
                ObservedExpression::Counter(counter) => {
                    let mut data = attribute(NFTA_COUNTER_BYTES, &counter.bytes.to_be_bytes());
                    data.extend(attribute(
                        NFTA_COUNTER_PACKETS,
                        &counter.packets.to_be_bytes(),
                    ));
                    (b"counter".as_slice(), data)
                }
                ObservedExpression::ImmediateAccept | ObservedExpression::ImmediateDrop => {
                    let code = if matches!(expression, ObservedExpression::ImmediateAccept) {
                        NF_ACCEPT
                    } else {
                        NF_DROP
                    };
                    let verdict = attribute(NFTA_VERDICT_CODE, &code.to_be_bytes());
                    let verdict = attribute(NFTA_DATA_VERDICT | nested, &verdict);
                    let mut data = attribute(NFTA_IMMEDIATE_DREG, &NFT_REG_VERDICT.to_be_bytes());
                    data.extend(attribute(NFTA_IMMEDIATE_DATA | nested, &verdict));
                    (b"immediate".as_slice(), data)
                }
            };
            let mut element = attribute(NFTA_EXPR_NAME, &nul_terminated(name)?);
            element.extend(attribute(NFTA_EXPR_DATA | nested, &data));
            encoded.extend(attribute(NFTA_LIST_ELEM | nested, &element));
        }
        Ok(encoded)
    }

    fn nul_terminated(value: &[u8]) -> Result<Vec<u8>, NftablesError> {
        if value.is_empty() || value.contains(&0) || value.len() >= MAX_TABLE_NAME_BYTES {
            return Err(NftablesError::Malformed);
        }
        let mut encoded = Vec::with_capacity(value.len() + 1);
        encoded.extend_from_slice(value);
        encoded.push(0);
        Ok(encoded)
    }

    fn unprivileged_user_namespace_policy_denied(
        status_code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> bool {
        status_code == Some(1)
            && stdout.is_empty()
            && matches!(
                stderr,
                b"unshare: unshare failed: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
            )
    }
}
