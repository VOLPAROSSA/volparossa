//! Fixed nftables policy for one anonymous client-ingress worker namespace.

use std::{io, os::fd::AsFd as _};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use thiserror::Error;

use crate::{
    deadline::HardDeadline,
    kernel::{
        CLIENT_INGRESS_IPV4_MARK, CLIENT_INGRESS_IPV6_MARK, CLIENT_INGRESS_PARENT_IPV4_MARK,
        CLIENT_INGRESS_PARENT_IPV6_MARK, CONTRIBUTION_WIREGUARD_MARK,
    },
};

const TABLE_PREFIX: &[u8] = b"vpi_";
const PARENT_TABLE_PREFIX: &[u8] = b"vpo_";
const TABLE_USERDATA_DOMAIN: &[u8] = b"VOLPAROSSA client ingress v1\0";
const PARENT_TABLE_USERDATA_DOMAIN: &[u8] = b"VOLPAROSSA client output steering v1\0";
const MANGLE_CHAIN: &[u8] = b"prerouting";
const NAT_CHAIN: &[u8] = b"prerouting_nat";
const OUTPUT_CHAIN: &[u8] = b"output";
const FILTER_CHAIN_TYPE: &[u8] = b"filter";
const NAT_CHAIN_TYPE: &[u8] = b"nat";
const ROUTE_CHAIN_TYPE: &[u8] = b"route";

const MAX_BATCH_BYTES: usize = 16 * 1024;
const MAX_BATCH_MESSAGES: usize = 24;
const MAX_ACK_BYTES: usize = 16 * 1024;
const MAX_ACK_DATAGRAMS: usize = 24;
const MAX_ACK_FRAMES: usize = 24;
const NLMSG_HEADER_LEN: usize = 16;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_APPEND: u16 = 0x0800;
const NLM_F_CAPPED: u16 = 0x0100;
const NLMSG_ERROR: u16 = 2;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWTABLE: u16 = NFNL_SUBSYS_NFTABLES << 8;
const NFT_MSG_DELTABLE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 2;
const NFT_MSG_NEWCHAIN: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 3;
const NFT_MSG_NEWRULE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | 6;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;

const AF_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const NFNETLINK_V0: u8 = 0;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_META_MARK: u32 = 3;
const NFT_META_IIF: u32 = 4;
const NFT_META_OIF: u32 = 5;
const NFT_META_SKUID: u32 = 10;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const MANGLE_PRIORITY: i32 = -150;
const NAT_PRIORITY: i32 = -100;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !((1 << 15) | (1 << 14));
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_TABLE_USERDATA: u16 = 6;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
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
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_TPROXY_FAMILY: u16 = 1;
const NFTA_TPROXY_REG_PORT: u16 = 3;
const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;

#[derive(Debug, Error)]
pub(super) enum ClientIngressPolicyError {
    #[error("client ingress nftables I/O failed")]
    Io(#[from] io::Error),
    #[error("client ingress nftables request was rejected")]
    Kernel(i32),
    #[error("client ingress nftables transaction was malformed")]
    Malformed,
    #[error("client ingress nftables transaction exceeded its bound")]
    Limit,
}

/// Fixed dual-stack ingress ports selected by the kernel during Prepare.
#[derive(Clone, Copy)]
pub(super) struct ClientIngressPorts {
    pub(super) ipv4: ClientIngressFamilyPorts,
    pub(super) ipv6: ClientIngressFamilyPorts,
}

#[derive(Clone, Copy)]
pub(super) struct ClientIngressFamilyPorts {
    pub(super) transparent_tcp: u16,
    pub(super) transparent_udp: u16,
    pub(super) dns_tcp: u16,
    pub(super) dns_udp: u16,
}

/// Affine authority for the exact installed table.
pub(super) struct ActiveClientIngressPolicy {
    table_name: Vec<u8>,
}

pub(super) struct ActiveParentClientIngressPolicy {
    table_name: Vec<u8>,
}

pub(super) fn install(
    client_runtime_id: [u8; 16],
    ingress_ifindex: u32,
    ports: ClientIngressPorts,
    deadline: HardDeadline,
) -> Result<ActiveClientIngressPolicy, ClientIngressPolicyError> {
    if ingress_ifindex == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    validate_ports(ports)?;
    let table_name = table_name(client_runtime_id)?;
    let transaction = install_transaction(&table_name, client_runtime_id, ingress_ifindex, ports)?;
    execute(&transaction, deadline)?;
    Ok(ActiveClientIngressPolicy { table_name })
}

#[allow(clippy::needless_pass_by_value)] // Consuming the policy token records affine teardown.
pub(super) fn remove(
    active: ActiveClientIngressPolicy,
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    delete_table(&active.table_name, deadline)
}

pub(super) fn install_parent(
    client_runtime_id: [u8; 16],
    ingress_ifindex: u32,
    loopback_ifindex: u32,
    trusted_agent_uid: u32,
    deadline: HardDeadline,
) -> Result<ActiveParentClientIngressPolicy, ClientIngressPolicyError> {
    if ingress_ifindex == 0 || loopback_ifindex == 0 || trusted_agent_uid == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let table_name = parent_table_name(client_runtime_id)?;
    let transaction = parent_install_transaction(
        &table_name,
        client_runtime_id,
        ingress_ifindex,
        loopback_ifindex,
        trusted_agent_uid,
    )?;
    execute(&transaction, deadline)?;
    Ok(ActiveParentClientIngressPolicy { table_name })
}

pub(super) fn remove_parent(
    active: &ActiveParentClientIngressPolicy,
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    delete_table(&active.table_name, deadline)
}

pub(super) fn cleanup_runtime(
    client_runtime_id: [u8; 16],
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    delete_table(&table_name(client_runtime_id)?, deadline)
}

pub(super) fn cleanup_parent_runtime(
    client_runtime_id: [u8; 16],
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    delete_table(&parent_table_name(client_runtime_id)?, deadline)
}

fn delete_table(table: &[u8], deadline: HardDeadline) -> Result<(), ClientIngressPolicyError> {
    match execute(&delete_transaction(table)?, deadline) {
        Ok(()) | Err(ClientIngressPolicyError::Kernel(libc::ENOENT)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_ports(ports: ClientIngressPorts) -> Result<(), ClientIngressPolicyError> {
    validate_family_ports(ports.ipv4)?;
    validate_family_ports(ports.ipv6)
}

fn validate_family_ports(ports: ClientIngressFamilyPorts) -> Result<(), ClientIngressPolicyError> {
    if ports.transparent_tcp == 0
        || ports.transparent_udp == 0
        || ports.dns_tcp == 0
        || ports.dns_udp == 0
        || ports.transparent_tcp == ports.dns_tcp
        || ports.transparent_udp == ports.dns_udp
    {
        return Err(ClientIngressPolicyError::Malformed);
    }
    Ok(())
}

fn table_name(runtime: [u8; 16]) -> Result<Vec<u8>, ClientIngressPolicyError> {
    derived_table_name(TABLE_PREFIX, runtime)
}

fn parent_table_name(runtime: [u8; 16]) -> Result<Vec<u8>, ClientIngressPolicyError> {
    derived_table_name(PARENT_TABLE_PREFIX, runtime)
}

fn derived_table_name(
    prefix: &[u8],
    runtime: [u8; 16],
) -> Result<Vec<u8>, ClientIngressPolicyError> {
    if runtime.iter().all(|byte| *byte == 0) {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let mut name = Vec::with_capacity(prefix.len() + runtime.len() * 2);
    name.extend_from_slice(prefix);
    for byte in runtime {
        name.push(HEX_DIGITS[usize::from(byte >> 4)]);
        name.push(HEX_DIGITS[usize::from(byte & 0x0f)]);
    }
    Ok(name)
}

#[allow(clippy::too_many_lines)] // One atomic transaction makes the complete dual-stack policy visible together.
fn install_transaction(
    table: &[u8],
    runtime: [u8; 16],
    ingress_ifindex: u32,
    ports: ClientIngressPorts,
) -> Result<Transaction, ClientIngressPolicyError> {
    if ingress_ifindex == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let mut transaction = Transaction::new();
    transaction.push(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 1, &batch_nfgen())?;

    let mut table_payload = nfgen(NFPROTO_INET);
    attr(&mut table_payload, NFTA_TABLE_NAME, &nul(table)?)?;
    attr(&mut table_payload, NFTA_TABLE_FLAGS, &0_u32.to_be_bytes())?;
    let mut userdata = Vec::with_capacity(TABLE_USERDATA_DOMAIN.len() + runtime.len());
    userdata.extend_from_slice(TABLE_USERDATA_DOMAIN);
    userdata.extend_from_slice(&runtime);
    attr(&mut table_payload, NFTA_TABLE_USERDATA, &userdata)?;
    transaction.push(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        2,
        &table_payload,
    )?;
    transaction.push(
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        3,
        &chain(
            table,
            MANGLE_CHAIN,
            FILTER_CHAIN_TYPE,
            NF_INET_PRE_ROUTING,
            MANGLE_PRIORITY,
            NF_DROP,
        )?,
    )?;
    transaction.push(
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        4,
        &chain(
            table,
            NAT_CHAIN,
            NAT_CHAIN_TYPE,
            NF_INET_PRE_ROUTING,
            NAT_PRIORITY,
            NF_ACCEPT,
        )?,
    )?;

    let rules = [
        rule(
            table,
            MANGLE_CHAIN,
            interface_exclusion_expressions(ingress_ifindex)?,
        )?,
        rule(table, MANGLE_CHAIN, mark_exclusion_expressions()?)?,
        rule(
            table,
            MANGLE_CHAIN,
            mark_accept_expressions(CONTRIBUTION_WIREGUARD_MARK)?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            mark_accept_expressions(CLIENT_INGRESS_IPV6_MARK)?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            dns_accept_expressions(NFPROTO_IPV4, IPPROTO_TCP)?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            dns_udp_tproxy_expressions(NFPROTO_IPV4, ports.ipv4.dns_udp, CLIENT_INGRESS_IPV4_MARK)?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            dns_accept_expressions(NFPROTO_IPV6, IPPROTO_TCP)?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            dns_udp_tproxy_expressions(NFPROTO_IPV6, ports.ipv6.dns_udp, CLIENT_INGRESS_IPV6_MARK)?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            tproxy_expressions(
                NFPROTO_IPV4,
                IPPROTO_TCP,
                ports.ipv4.transparent_tcp,
                CLIENT_INGRESS_IPV4_MARK,
            )?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            tproxy_expressions(
                NFPROTO_IPV4,
                IPPROTO_UDP,
                ports.ipv4.transparent_udp,
                CLIENT_INGRESS_IPV4_MARK,
            )?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            tproxy_expressions(
                NFPROTO_IPV6,
                IPPROTO_TCP,
                ports.ipv6.transparent_tcp,
                CLIENT_INGRESS_IPV6_MARK,
            )?,
        )?,
        rule(
            table,
            MANGLE_CHAIN,
            tproxy_expressions(
                NFPROTO_IPV6,
                IPPROTO_UDP,
                ports.ipv6.transparent_udp,
                CLIENT_INGRESS_IPV6_MARK,
            )?,
        )?,
        rule(
            table,
            NAT_CHAIN,
            dns_redirect_expressions(
                ingress_ifindex,
                NFPROTO_IPV4,
                IPPROTO_TCP,
                ports.ipv4.dns_tcp,
            )?,
        )?,
        rule(
            table,
            NAT_CHAIN,
            dns_redirect_expressions(
                ingress_ifindex,
                NFPROTO_IPV6,
                IPPROTO_TCP,
                ports.ipv6.dns_tcp,
            )?,
        )?,
    ];
    for (index, rule) in rules.iter().enumerate() {
        transaction.push(
            NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
            u32::try_from(index + 5).map_err(|_| ClientIngressPolicyError::Limit)?,
            rule,
        )?;
    }
    transaction.push(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 19, &batch_nfgen())?;
    Ok(transaction)
}

fn parent_install_transaction(
    table: &[u8],
    runtime: [u8; 16],
    ingress_ifindex: u32,
    loopback_ifindex: u32,
    trusted_agent_uid: u32,
) -> Result<Transaction, ClientIngressPolicyError> {
    if ingress_ifindex == 0 || loopback_ifindex == 0 || trusted_agent_uid == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let mut transaction = Transaction::new();
    transaction.push(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 1, &batch_nfgen())?;

    let mut table_payload = nfgen(NFPROTO_INET);
    attr(&mut table_payload, NFTA_TABLE_NAME, &nul(table)?)?;
    attr(&mut table_payload, NFTA_TABLE_FLAGS, &0_u32.to_be_bytes())?;
    let mut userdata = Vec::with_capacity(PARENT_TABLE_USERDATA_DOMAIN.len() + runtime.len());
    userdata.extend_from_slice(PARENT_TABLE_USERDATA_DOMAIN);
    userdata.extend_from_slice(&runtime);
    attr(&mut table_payload, NFTA_TABLE_USERDATA, &userdata)?;
    transaction.push(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        2,
        &table_payload,
    )?;
    transaction.push(
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        3,
        &chain(
            table,
            OUTPUT_CHAIN,
            ROUTE_CHAIN_TYPE,
            NF_INET_LOCAL_OUT,
            MANGLE_PRIORITY,
            NF_DROP,
        )?,
    )?;
    let rules = [
        rule(
            table,
            OUTPUT_CHAIN,
            mark_accept_expressions(CLIENT_INGRESS_PARENT_IPV4_MARK)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            mark_accept_expressions(CLIENT_INGRESS_PARENT_IPV6_MARK)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            mark_accept_expressions(CLIENT_INGRESS_IPV4_MARK)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            mark_accept_expressions(CONTRIBUTION_WIREGUARD_MARK)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            mark_accept_expressions(CLIENT_INGRESS_IPV6_MARK)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            output_interface_accept_expressions(loopback_ifindex)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            output_interface_accept_expressions(ingress_ifindex)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            uid_accept_expressions(trusted_agent_uid)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            parent_steering_expressions(NFPROTO_IPV4, CLIENT_INGRESS_PARENT_IPV4_MARK)?,
        )?,
        rule(
            table,
            OUTPUT_CHAIN,
            parent_steering_expressions(NFPROTO_IPV6, CLIENT_INGRESS_PARENT_IPV6_MARK)?,
        )?,
    ];
    for (index, rule) in rules.iter().enumerate() {
        transaction.push(
            NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
            u32::try_from(index + 4).map_err(|_| ClientIngressPolicyError::Limit)?,
            rule,
        )?;
    }
    append_parent_return_path(&mut transaction, table, ingress_ifindex)?;
    transaction.push(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 16, &batch_nfgen())?;
    Ok(transaction)
}

fn append_parent_return_path(
    transaction: &mut Transaction,
    table: &[u8],
    ingress_ifindex: u32,
) -> Result<(), ClientIngressPolicyError> {
    transaction.push(
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        14,
        &chain(
            table,
            MANGLE_CHAIN,
            FILTER_CHAIN_TYPE,
            NF_INET_PRE_ROUTING,
            MANGLE_PRIORITY,
            NF_ACCEPT,
        )?,
    )?;
    transaction.push(
        NFT_MSG_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
        15,
        &rule(
            table,
            MANGLE_CHAIN,
            parent_reply_mark_expressions(ingress_ifindex)?,
        )?,
    )
}

fn parent_reply_mark_expressions(
    ingress_ifindex: u32,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    if ingress_ifindex == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    // A reply crossing namespaces loses its socket mark. Only our owned parent-veth input
    // receives this mark; ordinary host input is unchanged. src_valid_mark on that veth
    // lets strict RPF find the same interface even when the parent has no physical default.
    let mut expressions = vec![
        meta_load(NFT_META_IIF)?,
        compare(NFT_CMP_EQ, &ingress_ifindex.to_ne_bytes())?,
    ];
    expressions.extend(parent_steering_expressions(
        NFPROTO_IPV4,
        CLIENT_INGRESS_PARENT_IPV4_MARK,
    )?);
    Ok(expressions)
}

fn delete_transaction(table: &[u8]) -> Result<Transaction, ClientIngressPolicyError> {
    let mut transaction = Transaction::new();
    transaction.push(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 1, &batch_nfgen())?;
    let mut payload = nfgen(NFPROTO_INET);
    attr(&mut payload, NFTA_TABLE_NAME, &nul(table)?)?;
    transaction.push(NFT_MSG_DELTABLE, NLM_F_REQUEST | NLM_F_ACK, 2, &payload)?;
    transaction.push(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 3, &batch_nfgen())?;
    Ok(transaction)
}

fn chain(
    table: &[u8],
    name: &[u8],
    chain_type: &[u8],
    hook_number: u32,
    priority: i32,
    policy: u32,
) -> Result<Vec<u8>, ClientIngressPolicyError> {
    let mut hook = Vec::new();
    attr(&mut hook, NFTA_HOOK_HOOKNUM, &hook_number.to_be_bytes())?;
    attr(&mut hook, NFTA_HOOK_PRIORITY, &priority.to_be_bytes())?;
    let mut payload = nfgen(NFPROTO_INET);
    attr(&mut payload, NFTA_CHAIN_TABLE, &nul(table)?)?;
    attr(&mut payload, NFTA_CHAIN_NAME, &nul(name)?)?;
    attr(&mut payload, NFTA_CHAIN_TYPE, &nul(chain_type)?)?;
    attr(&mut payload, NFTA_CHAIN_HOOK | NLA_F_NESTED, &hook)?;
    attr(&mut payload, NFTA_CHAIN_POLICY, &policy.to_be_bytes())?;
    Ok(payload)
}

fn rule(
    table: &[u8],
    chain: &[u8],
    expressions: Vec<Expression>,
) -> Result<Vec<u8>, ClientIngressPolicyError> {
    let mut encoded = Vec::new();
    for expression in expressions {
        let mut element = Vec::new();
        attr(&mut element, NFTA_EXPR_NAME, &nul(expression.name)?)?;
        attr(
            &mut element,
            NFTA_EXPR_DATA | NLA_F_NESTED,
            &expression.data,
        )?;
        attr(&mut encoded, NFTA_LIST_ELEM | NLA_F_NESTED, &element)?;
    }
    let mut payload = nfgen(NFPROTO_INET);
    attr(&mut payload, NFTA_RULE_TABLE, &nul(table)?)?;
    attr(&mut payload, NFTA_RULE_CHAIN, &nul(chain)?)?;
    attr(&mut payload, NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, &encoded)?;
    Ok(payload)
}

struct Expression {
    name: &'static [u8],
    data: Vec<u8>,
}

fn mark_exclusion_expressions() -> Result<Vec<Expression>, ClientIngressPolicyError> {
    mark_accept_expressions(CLIENT_INGRESS_IPV4_MARK)
}

fn mark_accept_expressions(mark: u32) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    if mark == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    Ok(vec![
        meta_load(NFT_META_MARK)?,
        compare(NFT_CMP_EQ, &mark.to_ne_bytes())?,
        verdict(NF_ACCEPT)?,
    ])
}

fn output_interface_accept_expressions(
    ifindex: u32,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    if ifindex == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    Ok(vec![
        meta_load(NFT_META_OIF)?,
        compare(NFT_CMP_EQ, &ifindex.to_ne_bytes())?,
        verdict(NF_ACCEPT)?,
    ])
}

fn uid_accept_expressions(uid: u32) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    Ok(vec![
        meta_load(NFT_META_SKUID)?,
        compare(NFT_CMP_EQ, &uid.to_ne_bytes())?,
        verdict(NF_ACCEPT)?,
    ])
}

fn parent_steering_expressions(
    family: u8,
    mark: u32,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    validate_nfproto(family)?;
    if mark == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    Ok(vec![
        meta_load(NFT_META_NFPROTO)?,
        compare(NFT_CMP_EQ, &[family])?,
        immediate_value(&mark.to_ne_bytes())?,
        meta_set(NFT_META_MARK)?,
        verdict(NF_ACCEPT)?,
    ])
}

fn interface_exclusion_expressions(
    ingress_ifindex: u32,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    Ok(vec![
        meta_load(NFT_META_IIF)?,
        compare(NFT_CMP_NEQ, &ingress_ifindex.to_ne_bytes())?,
        verdict(NF_ACCEPT)?,
    ])
}

fn dns_accept_expressions(
    family: u8,
    protocol: u8,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    let mut expressions = protocol_expressions(family, protocol)?;
    expressions.extend(destination_port_expressions(DNS_PORT)?);
    expressions.push(verdict(NF_ACCEPT)?);
    Ok(expressions)
}

fn tproxy_expressions(
    family: u8,
    protocol: u8,
    port: u16,
    mark: u32,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    let mut expressions = protocol_expressions(family, protocol)?;
    expressions.extend(tproxy_delivery_expressions(family, port, mark)?);
    Ok(expressions)
}

fn dns_udp_tproxy_expressions(
    family: u8,
    port: u16,
    mark: u32,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    // UDP ORIGDST ancillary data comes from the received packet headers, not conntrack's
    // pre-NAT tuple. REDIRECT would replace the resolver:53 with our local socket tuple.
    // TPROXY delivers to the dedicated DNS socket without changing the application's resolver tuple.
    let mut expressions = protocol_expressions(family, IPPROTO_UDP)?;
    expressions.extend(destination_port_expressions(DNS_PORT)?);
    expressions.extend(tproxy_delivery_expressions(family, port, mark)?);
    Ok(expressions)
}

fn tproxy_delivery_expressions(
    family: u8,
    port: u16,
    mark: u32,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    if port == 0 || mark == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let mut expressions = vec![immediate_value(&port.to_be_bytes())?];
    let mut tproxy = Vec::new();
    attr(
        &mut tproxy,
        NFTA_TPROXY_FAMILY,
        &u32::from(family).to_be_bytes(),
    )?;
    attr(&mut tproxy, NFTA_TPROXY_REG_PORT, &NFT_REG_1.to_be_bytes())?;
    expressions.push(Expression {
        name: b"tproxy",
        data: tproxy,
    });
    expressions.push(immediate_value(&mark.to_ne_bytes())?);
    expressions.push(meta_set(NFT_META_MARK)?);
    expressions.push(verdict(NF_ACCEPT)?);
    Ok(expressions)
}

fn dns_redirect_expressions(
    ingress_ifindex: u32,
    family: u8,
    protocol: u8,
    port: u16,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    if port == 0 || protocol != IPPROTO_TCP {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let mut expressions = vec![
        meta_load(NFT_META_IIF)?,
        compare(NFT_CMP_EQ, &ingress_ifindex.to_ne_bytes())?,
    ];
    expressions.extend(protocol_expressions(family, protocol)?);
    expressions.extend(destination_port_expressions(DNS_PORT)?);
    expressions.push(immediate_value(&port.to_be_bytes())?);
    let mut redir = Vec::new();
    attr(
        &mut redir,
        NFTA_REDIR_REG_PROTO_MIN,
        &NFT_REG_1.to_be_bytes(),
    )?;
    expressions.push(Expression {
        name: b"redir",
        data: redir,
    });
    expressions.push(verdict(NF_ACCEPT)?);
    Ok(expressions)
}

fn protocol_expressions(
    family: u8,
    protocol: u8,
) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    validate_nfproto(family)?;
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Err(ClientIngressPolicyError::Malformed);
    }
    Ok(vec![
        meta_load(NFT_META_NFPROTO)?,
        compare(NFT_CMP_EQ, &[family])?,
        meta_load(NFT_META_L4PROTO)?,
        compare(NFT_CMP_EQ, &[protocol])?,
    ])
}

fn validate_nfproto(family: u8) -> Result<(), ClientIngressPolicyError> {
    if family != NFPROTO_IPV4 && family != NFPROTO_IPV6 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    Ok(())
}

fn destination_port_expressions(port: u16) -> Result<Vec<Expression>, ClientIngressPolicyError> {
    let mut payload = Vec::new();
    attr(&mut payload, NFTA_PAYLOAD_DREG, &NFT_REG_1.to_be_bytes())?;
    attr(
        &mut payload,
        NFTA_PAYLOAD_BASE,
        &NFT_PAYLOAD_TRANSPORT_HEADER.to_be_bytes(),
    )?;
    attr(&mut payload, NFTA_PAYLOAD_OFFSET, &2_u32.to_be_bytes())?;
    attr(&mut payload, NFTA_PAYLOAD_LEN, &2_u32.to_be_bytes())?;
    Ok(vec![
        Expression {
            name: b"payload",
            data: payload,
        },
        compare(NFT_CMP_EQ, &port.to_be_bytes())?,
    ])
}

fn meta_load(key: u32) -> Result<Expression, ClientIngressPolicyError> {
    let mut data = Vec::new();
    attr(&mut data, NFTA_META_KEY, &key.to_be_bytes())?;
    attr(&mut data, NFTA_META_DREG, &NFT_REG_1.to_be_bytes())?;
    Ok(Expression {
        name: b"meta",
        data,
    })
}

fn meta_set(key: u32) -> Result<Expression, ClientIngressPolicyError> {
    let mut data = Vec::new();
    attr(&mut data, NFTA_META_KEY, &key.to_be_bytes())?;
    attr(&mut data, NFTA_META_SREG, &NFT_REG_1.to_be_bytes())?;
    Ok(Expression {
        name: b"meta",
        data,
    })
}

fn compare(operation: u32, value: &[u8]) -> Result<Expression, ClientIngressPolicyError> {
    if operation != NFT_CMP_EQ && operation != NFT_CMP_NEQ {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let mut nested = Vec::new();
    attr(&mut nested, NFTA_DATA_VALUE, value)?;
    let mut data = Vec::new();
    attr(&mut data, NFTA_CMP_SREG, &NFT_REG_1.to_be_bytes())?;
    attr(&mut data, NFTA_CMP_OP, &operation.to_be_bytes())?;
    attr(&mut data, NFTA_CMP_DATA | NLA_F_NESTED, &nested)?;
    Ok(Expression { name: b"cmp", data })
}

fn immediate_value(value: &[u8]) -> Result<Expression, ClientIngressPolicyError> {
    let mut nested = Vec::new();
    attr(&mut nested, NFTA_DATA_VALUE, value)?;
    let mut data = Vec::new();
    attr(&mut data, NFTA_IMMEDIATE_DREG, &NFT_REG_1.to_be_bytes())?;
    attr(&mut data, NFTA_IMMEDIATE_DATA | NLA_F_NESTED, &nested)?;
    Ok(Expression {
        name: b"immediate",
        data,
    })
}

fn verdict(code: u32) -> Result<Expression, ClientIngressPolicyError> {
    let mut verdict = Vec::new();
    attr(&mut verdict, NFTA_VERDICT_CODE, &code.to_be_bytes())?;
    let mut nested = Vec::new();
    attr(&mut nested, NFTA_DATA_VERDICT | NLA_F_NESTED, &verdict)?;
    let mut data = Vec::new();
    attr(
        &mut data,
        NFTA_IMMEDIATE_DREG,
        &NFT_REG_VERDICT.to_be_bytes(),
    )?;
    attr(&mut data, NFTA_IMMEDIATE_DATA | NLA_F_NESTED, &nested)?;
    Ok(Expression {
        name: b"immediate",
        data,
    })
}

#[derive(Clone, Copy)]
struct Request {
    header: [u8; NLMSG_HEADER_LEN],
    ack: bool,
}

struct Transaction {
    bytes: Vec<u8>,
    requests: Vec<Request>,
}

impl Transaction {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            requests: Vec::new(),
        }
    }

    fn push(
        &mut self,
        kind: u16,
        flags: u16,
        sequence: u32,
        payload: &[u8],
    ) -> Result<(), ClientIngressPolicyError> {
        if self.requests.len() >= MAX_BATCH_MESSAGES {
            return Err(ClientIngressPolicyError::Limit);
        }
        let message = message(kind, flags, sequence, payload)?;
        if self.bytes.len().saturating_add(message.len()) > MAX_BATCH_BYTES {
            return Err(ClientIngressPolicyError::Limit);
        }
        self.requests.push(Request {
            header: message[..NLMSG_HEADER_LEN]
                .try_into()
                .map_err(|_| ClientIngressPolicyError::Malformed)?,
            ack: flags & NLM_F_ACK != 0,
        });
        self.bytes.extend_from_slice(&message);
        Ok(())
    }
}

fn execute(
    transaction: &Transaction,
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    deadline.ensure_remaining()?;
    let mut socket = Socket::new(NETLINK_NETFILTER)?;
    socket.set_netlink_get_strict_chk(true)?;
    socket.set_cap_ack(true)?;
    socket.set_non_blocking(true)?;
    let local = socket.bind_auto()?;
    if local.port_number() == 0 || local.multicast_groups() != 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    socket.connect(&SocketAddr::new(0, 0))?;
    send(&socket, &transaction.bytes, deadline)?;
    receive_acks(
        &socket,
        local.port_number(),
        &transaction.requests,
        deadline,
    )
}

fn send(
    socket: &Socket,
    bytes: &[u8],
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    loop {
        deadline.ensure_remaining()?;
        match socket.send(bytes, 0) {
            Ok(written) if written == bytes.len() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short nft batch").into());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait(socket, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_acks(
    socket: &Socket,
    local_port: u32,
    requests: &[Request],
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    let expected = requests.iter().filter(|request| request.ack).count();
    if expected == 0 || expected > MAX_ACK_FRAMES {
        return Err(ClientIngressPolicyError::Limit);
    }
    let mut acknowledged = vec![false; requests.len()];
    let mut total_bytes = 0_usize;
    let mut datagrams = 0_usize;
    let mut frames = 0_usize;
    while acknowledged
        .iter()
        .zip(requests)
        .any(|(acknowledged, request)| *acknowledged != request.ack)
    {
        if datagrams >= MAX_ACK_DATAGRAMS {
            return Err(ClientIngressPolicyError::Limit);
        }
        wait(socket, PollFlags::POLLIN, deadline)?;
        let mut bytes = vec![0_u8; MAX_ACK_BYTES];
        let (received, sender) = match socket.recv_from(&mut &mut bytes[..], 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if sender != SocketAddr::new(0, 0) || received == 0 {
            return Err(ClientIngressPolicyError::Malformed);
        }
        bytes.truncate(received);
        total_bytes = total_bytes
            .checked_add(received)
            .filter(|value| *value <= MAX_ACK_BYTES)
            .ok_or(ClientIngressPolicyError::Limit)?;
        datagrams += 1;
        let mut offset = 0;
        while offset < bytes.len() {
            frames += 1;
            if frames > MAX_ACK_FRAMES || bytes.len() - offset < NLMSG_HEADER_LEN {
                return Err(ClientIngressPolicyError::Malformed);
            }
            let length = usize::try_from(read_u32(&bytes[offset..], 0)?)
                .map_err(|_| ClientIngressPolicyError::Limit)?;
            if length < NLMSG_HEADER_LEN || offset.saturating_add(length) > bytes.len() {
                return Err(ClientIngressPolicyError::Malformed);
            }
            ingest_ack(
                &bytes[offset..offset + length],
                local_port,
                requests,
                &mut acknowledged,
            )?;
            offset = offset
                .checked_add(align4(length)?)
                .ok_or(ClientIngressPolicyError::Limit)?;
        }
        if offset != bytes.len() {
            return Err(ClientIngressPolicyError::Malformed);
        }
    }
    Ok(())
}

fn ingest_ack(
    frame: &[u8],
    local_port: u32,
    requests: &[Request],
    acknowledged: &mut [bool],
) -> Result<(), ClientIngressPolicyError> {
    if frame.len() != NLMSG_HEADER_LEN + 4 + NLMSG_HEADER_LEN
        || read_u16(frame, 4)? != NLMSG_ERROR
        || read_u16(frame, 6)? != NLM_F_CAPPED
        || read_u32(frame, 12)? != local_port
    {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let sequence = read_u32(frame, 8)?;
    let embedded = &frame[NLMSG_HEADER_LEN + 4..];
    let Some(index) = requests.iter().position(|request| {
        read_u32(&request.header, 8).is_ok_and(|candidate| candidate == sequence)
            && embedded == request.header
    }) else {
        return Err(ClientIngressPolicyError::Malformed);
    };
    let errno = read_i32(frame, NLMSG_HEADER_LEN)?;
    if errno < 0 {
        return Err(ClientIngressPolicyError::Kernel(errno.saturating_abs()));
    }
    if errno != 0 || !requests[index].ack || acknowledged[index] {
        return Err(ClientIngressPolicyError::Malformed);
    }
    acknowledged[index] = true;
    Ok(())
}

fn wait(
    socket: &Socket,
    flags: PollFlags,
    deadline: HardDeadline,
) -> Result<(), ClientIngressPolicyError> {
    loop {
        let mut descriptors = [PollFd::new(socket.as_fd(), flags)];
        let timeout = PollTimeout::try_from(deadline.remaining()?)
            .map_err(|_| ClientIngressPolicyError::Limit)?;
        match poll(&mut descriptors, timeout) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::TimedOut).into()),
            Ok(_) => {
                deadline.ensure_remaining()?;
                let observed = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
                if observed != flags {
                    return Err(ClientIngressPolicyError::Malformed);
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_remaining()?,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32).into()),
        }
    }
}

fn nfgen(family: u8) -> Vec<u8> {
    let mut value = vec![family, NFNETLINK_V0];
    value.extend_from_slice(&0_u16.to_be_bytes());
    value
}

fn batch_nfgen() -> Vec<u8> {
    let mut value = vec![AF_UNSPEC, NFNETLINK_V0];
    value.extend_from_slice(&NFNL_SUBSYS_NFTABLES.to_be_bytes());
    value
}

fn nul(value: &[u8]) -> Result<Vec<u8>, ClientIngressPolicyError> {
    if value.is_empty() || value.contains(&0) || value.len() >= 256 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let mut encoded = Vec::with_capacity(value.len() + 1);
    encoded.extend_from_slice(value);
    encoded.push(0);
    Ok(encoded)
}

fn attr(output: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<(), ClientIngressPolicyError> {
    if kind & NLA_TYPE_MASK == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ClientIngressPolicyError::Limit)?;
    let aligned = align4(length)?;
    let final_length = output
        .len()
        .checked_add(aligned)
        .filter(|length| *length <= MAX_BATCH_BYTES)
        .ok_or(ClientIngressPolicyError::Limit)?;
    output.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| ClientIngressPolicyError::Limit)?
            .to_ne_bytes(),
    );
    output.extend_from_slice(&kind.to_ne_bytes());
    output.extend_from_slice(payload);
    output.resize(final_length, 0);
    Ok(())
}

fn message(
    kind: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, ClientIngressPolicyError> {
    if sequence == 0 || flags & NLM_F_REQUEST == 0 {
        return Err(ClientIngressPolicyError::Malformed);
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ClientIngressPolicyError::Limit)?;
    let aligned = align4(length)?;
    if aligned > MAX_BATCH_BYTES {
        return Err(ClientIngressPolicyError::Limit);
    }
    let mut output = Vec::with_capacity(aligned);
    output.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| ClientIngressPolicyError::Limit)?
            .to_ne_bytes(),
    );
    output.extend_from_slice(&kind.to_ne_bytes());
    output.extend_from_slice(&flags.to_ne_bytes());
    output.extend_from_slice(&sequence.to_ne_bytes());
    output.extend_from_slice(&0_u32.to_ne_bytes());
    output.extend_from_slice(payload);
    output.resize(aligned, 0);
    Ok(output)
}

fn align4(value: usize) -> Result<usize, ClientIngressPolicyError> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(ClientIngressPolicyError::Limit)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ClientIngressPolicyError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_ne_bytes)
        .ok_or(ClientIngressPolicyError::Malformed)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ClientIngressPolicyError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or(ClientIngressPolicyError::Malformed)
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, ClientIngressPolicyError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(i32::from_ne_bytes)
        .ok_or(ClientIngressPolicyError::Malformed)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        env,
        fs::File,
        io::{self, BufReader, Write as _},
        net::UdpSocket,
        os::fd::{AsFd as _, AsRawFd as _, OwnedFd},
        process::{Command, Stdio},
        time::Duration,
    };

    use nix::unistd::{getegid, geteuid};

    use super::*;
    use crate::{
        internal_protocol::{
            AcquireClientIngressReplySocket, AcquireClientIngressSocket, ClientIngressDestroyed,
            DestroyClientIngress, INTERNAL_WORKER_MAGIC, INTERNAL_WORKER_PROTOCOL_VERSION,
            IngressReplySocketReady, IngressSocketReady, InternalIngressAddressFamily,
            InternalIngressSocketKind, InternalSocketAddress, InternalWorkerRequest,
            InternalWorkerResult, internal_worker_request, internal_worker_response,
        },
        kernel::{BirthNamespaceKernel, NamespaceKernel},
        worker_transport::{
            ExpectedUnixCredentials, create_client_ingress_reply_socket,
            create_client_ingress_socket, private_credential_worker_channel,
            receive_credential_worker_request, receive_credential_worker_response,
            send_credential_worker_request, send_credential_worker_response,
        },
    };

    const SMOKE_RUNTIME: [u8; 16] = [0x91; 16];
    const SMOKE_OUTER: &str = "VOLPAROSSA_TEST_INGRESS_OUTPUT_NETNS";
    const SMOKE_WORKER: &str = "VOLPAROSSA_TEST_INGRESS_WORKER_NETNS";
    const SMOKE_TEST: &str = "worker_v3::client_ingress_policy::tests::parent_output_steering_delivers_udp_over_real_veth";
    const SMOKE_PAYLOAD: &[u8] = b"volparossa-real-ingress-udp";
    const SMOKE_SECOND_PAYLOAD: &[u8] = b"volparossa-real-ingress-udp-after-reply";
    const SMOKE_REPLY: &[u8] = b"volparossa-real-ingress-reply";

    #[test]
    fn dual_stack_policy_is_one_atomic_bounded_batch() {
        let transaction = install_transaction(
            &table_name([7; 16]).expect("table"),
            [7; 16],
            9,
            ClientIngressPorts {
                ipv4: ClientIngressFamilyPorts {
                    transparent_tcp: 20_001,
                    transparent_udp: 20_002,
                    dns_tcp: 20_003,
                    dns_udp: 20_004,
                },
                ipv6: ClientIngressFamilyPorts {
                    transparent_tcp: 21_001,
                    transparent_udp: 21_002,
                    dns_tcp: 21_003,
                    dns_udp: 21_004,
                },
            },
        )
        .expect("transaction");
        assert_eq!(transaction.requests.len(), 19);
        assert!(transaction.bytes.len() <= MAX_BATCH_BYTES);
        assert_eq!(
            transaction
                .requests
                .iter()
                .filter(|request| request.ack)
                .count(),
            17
        );
    }

    #[test]
    fn dns_udp_uses_exact_port_tproxy_without_nat_for_both_families() {
        for (family, port, mark) in [
            (NFPROTO_IPV4, 20_004_u16, CLIENT_INGRESS_IPV4_MARK),
            (NFPROTO_IPV6, 21_004_u16, CLIENT_INGRESS_IPV6_MARK),
        ] {
            let expressions =
                dns_udp_tproxy_expressions(family, port, mark).expect("dedicated DNS UDP delivery");
            let expected_protocol = protocol_expressions(family, IPPROTO_UDP).expect("protocol");
            let expected_destination = destination_port_expressions(53).expect("DNS port");
            for (actual, expected) in expressions
                .iter()
                .zip(expected_protocol.iter().chain(&expected_destination))
            {
                assert_eq!(actual.name, expected.name);
                assert_eq!(actual.data, expected.data);
            }
            assert_eq!(
                expressions[6].data,
                immediate_value(&port.to_be_bytes()).unwrap().data
            );
            assert_eq!(expressions[7].name, b"tproxy");
            assert_eq!(
                expressions[8].data,
                immediate_value(&mark.to_ne_bytes()).unwrap().data
            );
            assert_eq!(expressions.len(), 11);
            assert!(
                !expressions
                    .iter()
                    .any(|expression| expression.name == b"redir")
            );
            assert!(dns_redirect_expressions(9, family, IPPROTO_UDP, port).is_err());
        }
    }

    #[test]
    fn ipv6_rules_bind_exact_family_ports_and_marks() {
        let protocol = protocol_expressions(NFPROTO_IPV6, IPPROTO_UDP).expect("IPv6 UDP match");
        let expected_family = compare(NFT_CMP_EQ, &[NFPROTO_IPV6]).expect("family comparison");
        assert_eq!(protocol[1].name, expected_family.name);
        assert_eq!(protocol[1].data, expected_family.data);

        let tproxy =
            tproxy_expressions(NFPROTO_IPV6, IPPROTO_UDP, 24_002, CLIENT_INGRESS_IPV6_MARK)
                .expect("IPv6 TPROXY rule");
        let expected_port = immediate_value(&24_002_u16.to_be_bytes()).expect("port immediate");
        let expected_mark =
            immediate_value(&CLIENT_INGRESS_IPV6_MARK.to_ne_bytes()).expect("mark immediate");
        assert_eq!(tproxy[4].data, expected_port.data);
        assert_eq!(tproxy[6].data, expected_mark.data);

        let redirect = dns_redirect_expressions(9, NFPROTO_IPV6, IPPROTO_TCP, 24_003)
            .expect("IPv6 DNS redirect");
        let expected_dns_port =
            immediate_value(&24_003_u16.to_be_bytes()).expect("DNS port immediate");
        assert_eq!(redirect[8].data, expected_dns_port.data);

        let steering = parent_steering_expressions(NFPROTO_IPV6, CLIENT_INGRESS_PARENT_IPV6_MARK)
            .expect("IPv6 parent steering");
        let expected_parent_mark = immediate_value(&CLIENT_INGRESS_PARENT_IPV6_MARK.to_ne_bytes())
            .expect("parent mark immediate");
        assert_eq!(steering[2].data, expected_parent_mark.data);

        assert!(protocol_expressions(NFPROTO_INET, IPPROTO_UDP).is_err());
        assert!(protocol_expressions(NFPROTO_IPV6, 0).is_err());
    }

    #[test]
    fn parent_output_steering_is_one_atomic_fail_closed_batch() {
        let transaction = parent_install_transaction(
            &parent_table_name([8; 16]).expect("table"),
            [8; 16],
            7,
            1,
            1_001,
        )
        .expect("transaction");
        assert_eq!(transaction.requests.len(), 16);
        assert!(transaction.bytes.len() <= MAX_BATCH_BYTES);
        assert_eq!(
            transaction
                .requests
                .iter()
                .filter(|request| request.ack)
                .count(),
            14
        );
    }

    #[test]
    fn parent_reply_mark_is_limited_to_exact_owned_veth_and_ipv4() {
        assert!(parent_reply_mark_expressions(0).is_err());
        let expressions = parent_reply_mark_expressions(7).expect("reply mark");
        let mut expected = vec![
            meta_load(NFT_META_IIF).unwrap(),
            compare(NFT_CMP_EQ, &7_u32.to_ne_bytes()).unwrap(),
        ];
        expected.extend(
            parent_steering_expressions(NFPROTO_IPV4, CLIENT_INGRESS_PARENT_IPV4_MARK).unwrap(),
        );
        assert_eq!(expressions.len(), expected.len());
        for (actual, expected) in expressions.iter().zip(expected) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.data, expected.data);
        }
    }

    #[test]
    fn parent_output_steering_delivers_udp_over_real_veth() {
        if env::var(SMOKE_WORKER).ok().as_deref() == Some("1") {
            run_worker_smoke_child();
            return;
        }
        if env::var(SMOKE_OUTER).ok().as_deref() != Some("1") {
            let output = Command::new("/usr/bin/timeout")
                .args([
                    "--preserve-status",
                    "--signal=TERM",
                    "--kill-after=2s",
                    "20s",
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                ])
                .arg(env::current_exe().expect("test image"))
                .args(["--exact", SMOKE_TEST, "--nocapture", "--test-threads=1"])
                .env(SMOKE_OUTER, "1")
                .env("LC_ALL", "C")
                .output()
                .expect("launch disposable app namespace");
            if unprivileged_user_namespace_policy_denied(
                output.status.code(),
                &output.stdout,
                &output.stderr,
            ) {
                eprintln!(
                    "skipped live client-ingress veth proof: user namespaces denied by runner policy"
                );
                return;
            }
            assert!(
                output.status.success(),
                "disposable ingress smoke failed\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        run_parent_smoke();
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

    #[test]
    fn disposable_namespace_policy_skip_is_exact_and_fail_closed() {
        let denied =
            b"unshare: write failed /proc/self/uid_map: Operation not permitted\n".as_slice();
        assert!(unprivileged_user_namespace_policy_denied(
            Some(1),
            b"",
            denied
        ));
        assert!(!unprivileged_user_namespace_policy_denied(
            Some(2),
            b"",
            denied
        ));
        assert!(!unprivileged_user_namespace_policy_denied(
            Some(1),
            b"unexpected output\n",
            denied
        ));
        assert!(!unprivileged_user_namespace_policy_denied(
            Some(1),
            b"",
            b"unshare: write failed /proc/self/uid_map: Permission denied\n"
        ));
        assert!(!unprivileged_user_namespace_policy_denied(
            Some(1),
            b"",
            b"unshare: write failed /proc/self/uid_map: Operation not permitted\nextra\n"
        ));
    }

    #[allow(clippy::too_many_lines)] // One disposable topology proves forward and exact reply delivery.
    fn run_parent_smoke() {
        prepare_dummy_underlay();
        let (parent_channel, worker_channel) =
            private_credential_worker_channel().expect("private credential channel");
        let mut child = Command::new("/usr/bin/unshare")
            .arg("--net")
            .arg(env::current_exe().expect("test image"))
            .args(["--exact", SMOKE_TEST, "--nocapture", "--test-threads=1"])
            .env(SMOKE_OUTER, "1")
            .env(SMOKE_WORKER, "1")
            .env(
                "VOLPAROSSA_TEST_INGRESS_PARENT_PID",
                std::process::id().to_string(),
            )
            .env("LC_ALL", "C")
            .stdin(Stdio::from(OwnedFd::from(worker_channel)))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn separate worker namespace");
        let child_pid = child.id();
        let mut child_output = BufReader::new(child.stdout.take().expect("worker stdout"));
        read_worker_line(&mut child_output, "VPI_READY");

        let namespace =
            File::open(format!("/proc/{child_pid}/ns/net")).expect("open exact worker namespace");
        let deadline = HardDeadline::after(Duration::from_secs(3)).expect("setup deadline");
        let mut parent_kernel = BirthNamespaceKernel::connect(deadline).expect("parent rtnetlink");
        let ingress_link = parent_kernel
            .create_client_ingress_veth(SMOKE_RUNTIME, namespace.as_raw_fd(), deadline)
            .expect("create real app-to-worker veth");
        let ports = parse_worker_ports(&read_worker_line(&mut child_output, "VPI_PORTS"));
        let expected_worker = ExpectedUnixCredentials::new(child_pid, 0, 0)
            .expect("worker credentials in disposable user namespace");
        let parent_routing = parent_kernel
            .install_client_ingress_root_smoke_routing(&ingress_link, deadline)
            .expect("install parent marked route");
        let mut parent_policy = install_parent(
            SMOKE_RUNTIME,
            parent_routing.parent_ifindex(),
            parent_routing.loopback_ifindex(),
            1_001,
            deadline,
        )
        .expect("install parent output steering");

        for (kind, local_port, remote) in [
            (
                InternalIngressSocketKind::TransparentUdp,
                ports.ipv4.transparent_udp,
                "198.18.0.42:4242",
            ),
            (
                InternalIngressSocketKind::DnsUdp,
                ports.ipv4.dns_udp,
                "9.9.9.9:53",
            ),
        ] {
            let acquire = ingress_request(
                [0xa1; 16],
                internal_worker_request::Operation::AcquireClientIngressSocket(
                    AcquireClientIngressSocket {
                        client_runtime_id: SMOKE_RUNTIME.to_vec(),
                        descriptor_kind: kind as i32,
                        address_family: InternalIngressAddressFamily::Ipv4 as i32,
                        expected_local: Some(InternalSocketAddress {
                            address: vec![0; 4],
                            port: u32::from(local_port),
                        }),
                    },
                ),
            );
            send_credential_worker_request(&parent_channel, &acquire)
                .expect("request transferred UDP");
            let mut execution =
                receive_credential_worker_response(&parent_channel, &acquire, expected_worker)
                    .expect("credentialed UDP descriptor");
            assert_eq!(execution.response.result, InternalWorkerResult::Ok as i32);
            let transparent_udp = execution.descriptor.take().expect("transparent UDP owner");

            let app = UdpSocket::bind("192.0.2.2:0").expect("bind app underlay address");
            let application = app.local_addr().expect("application tuple");
            let remote = remote.parse().expect("remote tuple");
            app.send_to(SMOKE_PAYLOAD, remote).expect("send app packet");
            let receiver = UdpSocket::from(transparent_udp);
            let mut datagram = [0_u8; 128];
            let metadata = receive_smoke_udp(&receiver, kind, local_port, &mut datagram);
            assert_eq!(metadata.source(), application);
            assert_eq!(metadata.original_destination(), remote);
            assert_eq!(&datagram[..metadata.bytes()], SMOKE_PAYLOAD);

            let reply_request = ingress_request(
                [0xa3; 16],
                internal_worker_request::Operation::AcquireClientIngressReplySocket(
                    AcquireClientIngressReplySocket {
                        client_runtime_id: SMOKE_RUNTIME.to_vec(),
                        remote: Some(internal_socket_address(remote)),
                        application: Some(internal_socket_address(application)),
                    },
                ),
            );
            send_credential_worker_request(&parent_channel, &reply_request)
                .expect("request exact reply descriptor");
            let mut reply_execution = receive_credential_worker_response(
                &parent_channel,
                &reply_request,
                expected_worker,
            )
            .expect("credentialed reply descriptor");
            assert_eq!(
                reply_execution.response.result,
                InternalWorkerResult::Ok as i32
            );
            let reply = UdpSocket::from(
                reply_execution
                    .descriptor
                    .take()
                    .expect("source-bound reply descriptor"),
            );
            prove_offline_reply(
                &app,
                &reply,
                remote,
                ingress_link.parent_name(),
                &mut parent_policy,
                &parent_routing,
            );

            // Keep the reply descriptor alive while proving that Linux TPROXY still sends the next
            // datagram on the exact same four-tuple to the transparent ingress owner. A connected
            // transparent reply socket wins TPROXY's established-flow lookup and silently consumes
            // this packet instead.
            app.send_to(SMOKE_SECOND_PAYLOAD, remote)
                .expect("send second app packet on exact tuple");
            let metadata = receive_smoke_udp(&receiver, kind, local_port, &mut datagram);
            assert_eq!(metadata.source(), application);
            assert_eq!(metadata.original_destination(), remote);
            assert_eq!(&datagram[..metadata.bytes()], SMOKE_SECOND_PAYLOAD);
        }

        remove_parent(&parent_policy, deadline).expect("remove exact parent nft table");
        parent_kernel
            .remove_client_ingress_parent_routing(&parent_routing, deadline)
            .expect("remove exact parent route and rule");
        let destroy = ingress_request(
            [0xa2; 16],
            internal_worker_request::Operation::DestroyClientIngress(DestroyClientIngress {
                client_runtime_id: SMOKE_RUNTIME.to_vec(),
            }),
        );
        send_credential_worker_request(&parent_channel, &destroy).expect("request worker cleanup");
        let destroyed =
            receive_credential_worker_response(&parent_channel, &destroy, expected_worker)
                .expect("worker cleanup response");
        assert_eq!(destroyed.response.result, InternalWorkerResult::Ok as i32);
        parent_kernel
            .delete_client_ingress_veth(&ingress_link, deadline)
            .expect("delete exact veth pair");
        drop(parent_channel);
        assert!(child.wait().expect("wait worker smoke child").success());
    }

    fn prove_offline_reply(
        app: &UdpSocket,
        reply: &UdpSocket,
        remote: std::net::SocketAddr,
        ingress_name: &str,
        parent_policy: &mut ActiveParentClientIngressPolicy,
        routing: &crate::kernel::ClientIngressParentIpv4Routing,
    ) {
        // This runs only inside the existing disposable user+network namespace. No initial
        // namespace sysctl is changed: enforce strict source checks for both proof halves.
        for interface in ["all", ingress_name] {
            std::fs::write(
                format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter"),
                b"1\n",
            )
            .expect("strict RPF in disposable namespace");
        }
        assert_eq!(
            std::fs::read_to_string(format!(
                "/proc/sys/net/ipv4/conf/{ingress_name}/src_valid_mark"
            ))
            .expect("read production-owned source mark")
            .trim(),
            "1",
        );
        run_disposable_ip(&["route", "del", "default", "via", "192.0.2.1", "dev", "vpu0"]);
        let defaults = Command::new("/usr/bin/ip")
            .args(["route", "show", "table", "main", "default"])
            .output()
            .expect("inspect disposable physical routes");
        assert!(defaults.status.success() && defaults.stdout.is_empty());
        assert!(
            !Command::new("/usr/bin/ip")
                .args(["route", "get", &remote.ip().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );

        // Without the exact owned input mark, the real kernel rejects the reply despite its
        // valid local destination. This reproduces the offline failure without disabling RPF.
        let deadline = HardDeadline::after(Duration::from_secs(3)).unwrap();
        remove_parent(parent_policy, deadline).expect("remove owned mark for negative control");
        let drops_before = reverse_path_filter_drops();
        app.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        reply
            .send_to(SMOKE_REPLY, app.local_addr().unwrap())
            .unwrap();
        let mut datagram = [0_u8; 128];
        let error = app
            .recv_from(&mut datagram)
            .expect_err("unmarked offline reply must fail RPF");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert_eq!(reverse_path_filter_drops(), drops_before + 1);

        *parent_policy = install_parent(
            SMOKE_RUNTIME,
            routing.parent_ifindex(),
            routing.loopback_ifindex(),
            1_001,
            deadline,
        )
        .expect("restore exact parent policy");
        app.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        reply
            .send_to(SMOKE_REPLY, app.local_addr().unwrap())
            .unwrap();
        let (length, source) = app
            .recv_from(&mut datagram)
            .expect("offline exact reply under strict RPF");
        assert_eq!(source, remote);
        assert_eq!(&datagram[..length], SMOKE_REPLY);
        assert_eq!(reverse_path_filter_drops(), drops_before + 1);
        run_disposable_ip(&[
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            "vpu0",
            "onlink",
        ]);
    }

    fn reverse_path_filter_drops() -> u64 {
        let counters =
            std::fs::read_to_string("/proc/net/netstat").expect("disposable IP counters");
        let mut lines = counters.lines();
        while let Some(names) = lines.next() {
            let values = lines.next().expect("counter values");
            if let Some(index) = names
                .split_whitespace()
                .position(|name| name == "IPReversePathFilter")
            {
                return values
                    .split_whitespace()
                    .nth(index)
                    .expect("RPF counter")
                    .parse()
                    .unwrap();
            }
        }
        panic!("kernel IPReversePathFilter counter unavailable");
    }

    fn receive_smoke_udp(
        socket: &UdpSocket,
        kind: InternalIngressSocketKind,
        local_port: u16,
        payload: &mut [u8],
    ) -> volparossa_linux_uapi::ReceivedUdpDatagram {
        let mut descriptors = [PollFd::new(socket.as_fd(), PollFlags::POLLIN)];
        assert_eq!(
            poll(&mut descriptors, 2_000_u16).expect("bounded ingress wait"),
            1
        );
        let kind = match kind {
            InternalIngressSocketKind::TransparentUdp => {
                volparossa_linux_uapi::IngressSocketKind::TransparentUdp
            }
            InternalIngressSocketKind::DnsUdp => volparossa_linux_uapi::IngressSocketKind::DnsUdp,
            _ => panic!("UDP smoke kind"),
        };
        volparossa_linux_uapi::receive_udp_with_original_destination(
            socket,
            kind,
            volparossa_linux_uapi::IngressSocketFamily::Ipv4,
            local_port,
            payload,
        )
        .expect("exact application and original destination from transferred ingress socket")
    }

    #[allow(clippy::too_many_lines)] // One disposable process owns setup, proof, and teardown.
    fn run_worker_smoke_child() {
        println!("VPI_READY");
        io::stdout().flush().expect("flush readiness");
        let deadline = HardDeadline::after(Duration::from_secs(5)).expect("worker deadline");
        let mut kernel = NamespaceKernel::connect(deadline).expect("worker rtnetlink");
        kernel.activate_loopback(deadline).expect("worker loopback");
        let ingress_ifindex = loop {
            match kernel.activate_client_ingress_link(SMOKE_RUNTIME, deadline) {
                Ok(ifindex) => break ifindex,
                Err(error) => {
                    if deadline.ensure_remaining().is_err() {
                        let links = Command::new("/usr/bin/ip")
                            .args(["-details", "link", "show"])
                            .output()
                            .expect("inspect worker links");
                        panic!(
                            "veth creation deadline: {error:?}; links: {}",
                            String::from_utf8_lossy(&links.stdout)
                        );
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let mut sockets = BTreeMap::new();
        let mut locals = BTreeMap::new();
        for kind in [
            InternalIngressSocketKind::TransparentTcpListener,
            InternalIngressSocketKind::TransparentUdp,
            InternalIngressSocketKind::DnsTcpListener,
            InternalIngressSocketKind::DnsUdp,
        ] {
            for family in [
                InternalIngressAddressFamily::Ipv4,
                InternalIngressAddressFamily::Ipv6,
            ] {
                let (descriptor, local) = create_client_ingress_socket(kind, family)
                    .expect("create real dual-stack ingress socket");
                sockets.insert((kind, family), descriptor);
                locals.insert((kind, family), local);
            }
        }
        let ports = ClientIngressPorts {
            ipv4: local_family_ports(&locals, InternalIngressAddressFamily::Ipv4),
            ipv6: local_family_ports(&locals, InternalIngressAddressFamily::Ipv6),
        };
        let routing = kernel
            .install_client_ingress_routing(ingress_ifindex, deadline)
            .expect("worker TPROXY route");
        let policy =
            install(SMOKE_RUNTIME, ingress_ifindex, ports, deadline).expect("worker TPROXY policy");
        println!(
            "VPI_PORTS {} {} {} {} {} {} {} {}",
            ports.ipv4.transparent_tcp,
            ports.ipv4.transparent_udp,
            ports.ipv4.dns_tcp,
            ports.ipv4.dns_udp,
            ports.ipv6.transparent_tcp,
            ports.ipv6.transparent_udp,
            ports.ipv6.dns_tcp,
            ports.ipv6.dns_udp,
        );
        io::stdout().flush().expect("flush socket ports");

        let stdin = io::stdin();
        let channel = socket2::Socket::from(
            rustix::io::fcntl_dupfd_cloexec(stdin.as_fd(), 3).expect("duplicate worker channel"),
        );
        let parent_pid = env::var("VOLPAROSSA_TEST_INGRESS_PARENT_PID")
            .expect("parent pid")
            .parse::<u32>()
            .expect("numeric parent pid");
        let expected_parent =
            ExpectedUnixCredentials::new(parent_pid, geteuid().as_raw(), getegid().as_raw())
                .expect("parent credentials");
        for kind in [
            InternalIngressSocketKind::TransparentUdp,
            InternalIngressSocketKind::DnsUdp,
        ] {
            let acquire = receive_credential_worker_request(&channel, expected_parent)
                .expect("receive Acquire")
                .request;
            let expected_local = locals
                .get(&(kind, InternalIngressAddressFamily::Ipv4))
                .cloned()
                .expect("UDP local");
            assert!(matches!(
                acquire.operation.as_ref(),
                Some(internal_worker_request::Operation::AcquireClientIngressSocket(value))
                    if value.client_runtime_id.as_slice() == SMOKE_RUNTIME
                        && value.descriptor_kind == kind as i32
                        && value.address_family == InternalIngressAddressFamily::Ipv4 as i32
                        && value.expected_local.as_ref() == Some(&expected_local)
            ));
            let response = super::super::correlated_response(
                &acquire,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::IngressSocketReady(
                    IngressSocketReady {
                        client_runtime_id: SMOKE_RUNTIME.to_vec(),
                        descriptor_kind: kind as i32,
                        address_family: InternalIngressAddressFamily::Ipv4 as i32,
                        local: Some(expected_local),
                    },
                )),
            )
            .expect("correlated Acquire response");
            let udp = sockets
                .remove(&(kind, InternalIngressAddressFamily::Ipv4))
                .expect("UDP owner");
            send_credential_worker_response(&channel, &acquire, &response, Some(udp))
                .expect("transfer transparent UDP descriptor");

            let reply_request = receive_credential_worker_request(&channel, expected_parent)
                .expect("receive reply Acquire")
                .request;
            let Some(internal_worker_request::Operation::AcquireClientIngressReplySocket(reply)) =
                reply_request.operation.as_ref()
            else {
                panic!("reply Acquire operation");
            };
            assert_eq!(reply.client_runtime_id.as_slice(), SMOKE_RUNTIME);
            let descriptor = create_client_ingress_reply_socket(reply).expect("create exact reply");
            let response = super::super::correlated_response(
                &reply_request,
                InternalWorkerResult::Ok,
                Some(internal_worker_response::Outcome::IngressReplySocketReady(
                    IngressReplySocketReady {
                        client_runtime_id: SMOKE_RUNTIME.to_vec(),
                        remote: reply.remote.clone(),
                        application: reply.application.clone(),
                    },
                )),
            )
            .expect("correlated reply Acquire response");
            send_credential_worker_response(&channel, &reply_request, &response, Some(descriptor))
                .expect("transfer source-bound reply descriptor");
        }

        let destroy = receive_credential_worker_request(&channel, expected_parent)
            .expect("receive Destroy")
            .request;
        assert!(matches!(
            destroy.operation.as_ref(),
            Some(internal_worker_request::Operation::DestroyClientIngress(value))
                if value.client_runtime_id.as_slice() == SMOKE_RUNTIME
        ));
        remove(policy, deadline).expect("remove worker nft table");
        kernel
            .remove_client_ingress_routing(routing, deadline)
            .expect("remove worker TPROXY route");
        let response = super::super::correlated_response(
            &destroy,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::ClientIngressDestroyed(
                ClientIngressDestroyed {
                    client_runtime_id: SMOKE_RUNTIME.to_vec(),
                },
            )),
        )
        .expect("correlated Destroy response");
        send_credential_worker_response(&channel, &destroy, &response, None)
            .expect("send cleanup response");
    }

    fn ingress_request(
        request_id: [u8; 16],
        operation: internal_worker_request::Operation,
    ) -> InternalWorkerRequest {
        InternalWorkerRequest {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: request_id.to_vec(),
            operation: Some(operation),
        }
    }

    fn internal_socket_address(value: std::net::SocketAddr) -> InternalSocketAddress {
        match value {
            std::net::SocketAddr::V4(value) => InternalSocketAddress {
                address: value.ip().octets().to_vec(),
                port: u32::from(value.port()),
            },
            std::net::SocketAddr::V6(_) => panic!("IPv4 smoke tuple"),
        }
    }

    fn local_family_ports(
        locals: &BTreeMap<
            (InternalIngressSocketKind, InternalIngressAddressFamily),
            InternalSocketAddress,
        >,
        family: InternalIngressAddressFamily,
    ) -> ClientIngressFamilyPorts {
        ClientIngressFamilyPorts {
            transparent_tcp: local_port(
                locals,
                InternalIngressSocketKind::TransparentTcpListener,
                family,
            ),
            transparent_udp: local_port(locals, InternalIngressSocketKind::TransparentUdp, family),
            dns_tcp: local_port(locals, InternalIngressSocketKind::DnsTcpListener, family),
            dns_udp: local_port(locals, InternalIngressSocketKind::DnsUdp, family),
        }
    }

    fn local_port(
        locals: &BTreeMap<
            (InternalIngressSocketKind, InternalIngressAddressFamily),
            InternalSocketAddress,
        >,
        kind: InternalIngressSocketKind,
        family: InternalIngressAddressFamily,
    ) -> u16 {
        u16::try_from(locals.get(&(kind, family)).expect("local").port)
            .ok()
            .filter(|port| *port != 0)
            .expect("kernel port")
    }

    fn read_worker_line(reader: &mut impl io::BufRead, prefix: &str) -> String {
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).expect("worker output"), 0);
            if let Some(position) = line.find(prefix) {
                return line[position..].to_owned();
            }
        }
    }

    fn parse_worker_ports(line: &str) -> ClientIngressPorts {
        let values = line
            .split_whitespace()
            .skip(1)
            .map(|value| value.parse::<u16>().expect("numeric port"))
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 8);
        ClientIngressPorts {
            ipv4: ClientIngressFamilyPorts {
                transparent_tcp: values[0],
                transparent_udp: values[1],
                dns_tcp: values[2],
                dns_udp: values[3],
            },
            ipv6: ClientIngressFamilyPorts {
                transparent_tcp: values[4],
                transparent_udp: values[5],
                dns_tcp: values[6],
                dns_udp: values[7],
            },
        }
    }

    fn prepare_dummy_underlay() {
        for arguments in [
            vec!["link", "add", "vpu0", "type", "dummy"],
            vec!["address", "add", "192.0.2.2/24", "dev", "vpu0"],
            vec!["link", "set", "dev", "vpu0", "up"],
            vec![
                "route",
                "add",
                "default",
                "via",
                "192.0.2.1",
                "dev",
                "vpu0",
                "onlink",
            ],
        ] {
            run_disposable_ip(&arguments);
        }
    }

    fn run_disposable_ip(arguments: &[&str]) {
        assert!(
            Command::new("/usr/bin/ip")
                .args(arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run disposable ip setup")
                .success(),
            "failed disposable ip {arguments:?}"
        );
    }
}
