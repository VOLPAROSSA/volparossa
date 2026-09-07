//! Fixed NETDEV counter-only netlink encoding. UAPI: Linux 6.12 `nf_tables.h`.
//! `NFT_TABLE_F_OWNER` without PERSIST confines writes to this socket and releases on close.

use std::collections::BTreeMap;

use netlink_sys::protocols::NETLINK_NETFILTER;

use super::{
    HardDeadline, KernelError, MAX_RECEIVE_TUPLES, ReceiveAccountingConfig, ReceiveCounters,
    ReceiveTuple,
};
use crate::kernel::{
    NetlinkClient, attributes, build_netlink_message, frames, push_attribute,
    push_string_attribute, read_i32, read_u16, read_u32, validate_kernel_header,
    validate_kernel_sender,
};

mod expressions;
pub(super) use expressions::{Expression, expressions};

const FAMILY: u8 = 5;
const NESTED: u16 = 0x8000;
const MASK: u16 = 0x3fff;
const REQUEST: u16 = 1;
const ACK: u16 = 4;
const EXCLUSIVE_CREATE: u16 = 0x600;
const APPEND_CREATE: u16 = 0xc00;
const DUMP: u16 = 0x300;
const NEW_TABLE: u16 = 0xa00;
const GET_TABLE: u16 = 0xa01;
const DELETE_TABLE: u16 = 0xa02;
const NEW_CHAIN: u16 = 0xa03;
const GET_CHAIN: u16 = 0xa04;
const NEW_RULE: u16 = 0xa06;
const GET_RULE: u16 = 0xa07;
const DELETE_RULE: u16 = 0xa08;
const MAX_DUMP_BYTES: usize = 512 * 1024;
const CHAIN: &str = "ingress";
const PRIORITY: i32 = -500;

pub(super) struct Nft {
    client: NetlinkClient,
}

#[derive(Clone, Debug)]
pub(super) struct Rule {
    pub(super) handle: u64,
    pub(super) tag: Vec<u8>,
    pub(super) expressions: Vec<Expression>,
    pub(super) counters: ReceiveCounters,
}

impl Nft {
    pub(super) fn connect(deadline: HardDeadline) -> Result<Self, KernelError> {
        Ok(Self {
            client: NetlinkClient::connect(NETLINK_NETFILTER, deadline)?,
        })
    }

    pub(super) fn install(
        &mut self,
        table: &str,
        config: &ReceiveAccountingConfig,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let mut create = named(1, table)?;
        number(&mut create, 2, 2)?; // NFT_TABLE_F_OWNER, deliberately not PERSIST.
        push_attribute(&mut create, 6, &config.runtime_id)?;
        let mut chain = named(1, table)?;
        push_string_attribute(&mut chain, 3, CHAIN)?;
        let mut hook = Vec::new();
        number(&mut hook, 1, 0)?; // NF_NETDEV_INGRESS.
        push_attribute(&mut hook, 2, &PRIORITY.to_be_bytes())?;
        push_string_attribute(&mut hook, 3, &config.interface_name)?;
        push_attribute(&mut chain, 4 | NESTED, &hook)?;
        number(&mut chain, 5, 1)?; // Base policy accept; no packet verdict expressions.
        push_string_attribute(&mut chain, 7, "filter")?;
        self.batch(
            &[
                (NEW_TABLE, EXCLUSIVE_CREATE, create),
                (NEW_CHAIN, EXCLUSIVE_CREATE, chain),
                (
                    NEW_RULE,
                    APPEND_CREATE,
                    rule_payload(table, b"total", None)?,
                ),
            ],
            deadline,
        )
    }

    pub(super) fn add_tuple(
        &mut self,
        table: &str,
        tuple: &ReceiveTuple,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        self.batch(
            &[(
                NEW_RULE,
                APPEND_CREATE,
                rule_payload(table, &tuple.tag(), Some(tuple))?,
            )],
            deadline,
        )
    }

    pub(super) fn delete_rule(
        &mut self,
        table: &str,
        handle: u64,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let mut payload = named(1, table)?;
        push_string_attribute(&mut payload, 2, CHAIN)?;
        push_attribute(&mut payload, 3, &handle.to_be_bytes())?;
        self.batch(&[(DELETE_RULE, 0, payload)], deadline)
    }

    pub(super) fn delete_table(
        &mut self,
        handle: u64,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let mut payload = header();
        push_attribute(&mut payload, 4, &handle.to_be_bytes())?;
        self.batch(&[(DELETE_TABLE, 0, payload)], deadline)
    }

    pub(super) fn table(
        &mut self,
        name: &str,
        deadline: HardDeadline,
    ) -> Result<Option<Vec<u8>>, KernelError> {
        self.get(GET_TABLE, NEW_TABLE, &named(1, name)?, deadline)
    }

    pub(super) fn verify_table(
        &mut self,
        name: &str,
        config: &ReceiveAccountingConfig,
        deadline: HardDeadline,
    ) -> Result<u64, KernelError> {
        let payload = self.table(name, deadline)?.ok_or(KernelError::Invalid)?;
        let fields = fields(&payload, &[1, 2, 3, 4, 5, 6, 7], &[5])?;
        if string(&fields, 1)? != name || u32_field(&fields, 2)? != 2
            || u32_field(&fields, 3)? != 1 // Exactly our one chain, no extra sets/objects.
            || value(&fields, 6)? != config.runtime_id
            || u32_field(&fields, 7)? != self.client.local_port_id
        {
            return Err(KernelError::Invalid);
        }
        let handle = u64_field(&fields, 4)?;
        if handle == 0 {
            return Err(KernelError::Malformed);
        }
        Ok(handle)
    }

    pub(super) fn verify_chain(
        &mut self,
        table: &str,
        interface: &str,
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        let mut request = named(1, table)?;
        push_string_attribute(&mut request, 3, CHAIN)?;
        let payload = self
            .get(GET_CHAIN, NEW_CHAIN, &request, deadline)?
            .ok_or(KernelError::Invalid)?;
        let fields = fields(&payload, &[1, 2, 3, 4, 5, 6, 7, 9, 10], &[9])?;
        verify_hook(value(&fields, 4)?, interface)?;
        if string(&fields, 1)? != table
            || string(&fields, 3)? != CHAIN
            || string(&fields, 7)? != "filter"
            || u32_field(&fields, 5)? != 1
            || u32_field(&fields, 10)? != 1
            || u64_field(&fields, 2)? == 0
        {
            return Err(KernelError::Invalid);
        }
        Ok(())
    }

    pub(super) fn rules(
        &mut self,
        table: &str,
        deadline: HardDeadline,
    ) -> Result<Vec<Rule>, KernelError> {
        let mut payload = named(1, table)?;
        push_string_attribute(&mut payload, 2, CHAIN)?;
        self.dump(GET_RULE, NEW_RULE, &payload, deadline)?
            .iter()
            .map(|payload| parse_rule(payload, table))
            .collect()
    }

    fn get(
        &mut self,
        request: u16,
        response: u16,
        payload: &[u8],
        deadline: HardDeadline,
    ) -> Result<Option<Vec<u8>>, KernelError> {
        let (reply, sequence) = self.client.request_reply(request, payload, deadline)?;
        validate_kernel_sender(&reply.sender)?;
        let list = frames(&reply.message)?;
        if list.len() != 1 {
            return Err(KernelError::Malformed);
        }
        let frame = list[0];
        if read_u16(frame, 4) == Some(2) {
            match check_ack(frame, sequence, request, self.client.local_port_id) {
                Err(error) if error.is_errno(libc::ENOENT) => return Ok(None),
                Err(error) => return Err(error),
                Ok(()) => return Err(KernelError::Malformed),
            }
        }
        validate_kernel_header(frame, sequence, response, self.client.local_port_id)?;
        Ok(Some(
            frame.get(16..).ok_or(KernelError::Malformed)?.to_vec(),
        ))
    }

    fn dump(
        &mut self,
        request: u16,
        response: u16,
        payload: &[u8],
        deadline: HardDeadline,
    ) -> Result<Vec<Vec<u8>>, KernelError> {
        let sequence = self.client.next_sequence();
        self.client.send(
            &build_netlink_message(request, REQUEST | DUMP, sequence, payload)?,
            deadline,
        )?;
        let mut output = Vec::new();
        let mut total = 0;
        for _ in 0..64 {
            let reply = self.client.receive(deadline)?;
            validate_kernel_sender(&reply.sender)?;
            total += reply.message.len();
            if total > MAX_DUMP_BYTES {
                return Err(KernelError::Malformed);
            }
            for frame in frames(&reply.message)? {
                let kind = read_u16(frame, 4).ok_or(KernelError::Malformed)?;
                validate_kernel_header(frame, sequence, kind, self.client.local_port_id)?;
                if read_u16(frame, 6).is_none_or(|flags| flags & 0x10 != 0) {
                    return Err(KernelError::Malformed);
                }
                if kind == 3 {
                    if frame.len() != 20 || read_i32(frame, 16) != Some(0) {
                        return Err(KernelError::Malformed);
                    }
                    return Ok(output);
                }
                if kind == 2 {
                    check_ack(frame, sequence, request, self.client.local_port_id)?;
                }
                if kind != response || output.len() > MAX_RECEIVE_TUPLES {
                    return Err(KernelError::Malformed);
                }
                output.push(frame.get(16..).ok_or(KernelError::Malformed)?.to_vec());
            }
        }
        Err(KernelError::Malformed)
    }

    fn batch(
        &mut self,
        operations: &[(u16, u16, Vec<u8>)],
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        if operations.is_empty() || operations.len() > 3 {
            return Err(KernelError::Invalid);
        }
        let mut output =
            build_netlink_message(0x10, REQUEST, self.client.next_sequence(), &[0, 0, 0, 10])?;
        let mut pending = BTreeMap::new();
        for (kind, flags, payload) in operations {
            let sequence = self.client.next_sequence();
            pending.insert(sequence, *kind);
            output.extend(build_netlink_message(
                *kind,
                REQUEST | ACK | flags,
                sequence,
                payload,
            )?);
        }
        output.extend(build_netlink_message(
            0x11,
            REQUEST,
            self.client.next_sequence(),
            &[0, 0, 0, 10],
        )?);
        if output.len() > 16 * 1024 {
            return Err(KernelError::Invalid);
        }
        self.client.send(&output, deadline)?;
        for _ in 0..8 {
            let reply = self.client.receive(deadline)?;
            validate_kernel_sender(&reply.sender)?;
            if reply.message.len() > 16 * 1024 {
                return Err(KernelError::Malformed);
            }
            for frame in frames(&reply.message)? {
                let sequence = read_u32(frame, 8).ok_or(KernelError::Malformed)?;
                let kind = pending.remove(&sequence).ok_or(KernelError::Malformed)?;
                check_ack(frame, sequence, kind, self.client.local_port_id)?;
            }
            if pending.is_empty() {
                return Ok(());
            }
        }
        Err(KernelError::Malformed)
    }
}

fn verify_hook(payload: &[u8], interface: &str) -> Result<(), KernelError> {
    let hook = attributes_map(payload, &[1, 2, 3, 4], &[])?;
    if u32_field(&hook, 1)? != 0
        || value(&hook, 2)? != PRIORITY.to_be_bytes()
        || string(&hook, 3)? != interface
    {
        return Err(KernelError::Invalid);
    }
    // Linux also dumps NFTA_HOOK_DEVS beside the legacy single NFTA_HOOK_DEV.
    // Accept only that exact singleton, never an additional receiving interface.
    if let Some(devices) = hook.get(&4) {
        let devices = attributes_map(devices, &[1], &[])?;
        if string(&devices, 1)? != interface {
            return Err(KernelError::Invalid);
        }
    }
    Ok(())
}

fn check_ack(frame: &[u8], sequence: u32, request: u16, port: u32) -> Result<(), KernelError> {
    validate_kernel_header(frame, sequence, 2, port)?;
    if frame.len() < 36
        || read_u16(frame, 24) != Some(request)
        || read_u32(frame, 28) != Some(sequence)
        || read_u32(frame, 32) != Some(0)
    {
        return Err(KernelError::Malformed);
    }
    match read_i32(frame, 16).ok_or(KernelError::Malformed)? {
        0 => Ok(()),
        negative if negative < 0 => Err(KernelError::Errno(negative.saturating_abs())),
        _ => Err(KernelError::Malformed),
    }
}

fn parse_rule(payload: &[u8], table: &str) -> Result<Rule, KernelError> {
    let fields = fields(payload, &[1, 2, 3, 4, 6, 7, 8], &[8])?;
    if string(&fields, 1)? != table || string(&fields, 2)? != CHAIN {
        return Err(KernelError::Invalid);
    }
    let (expressions, counters) = expressions::decode(value(&fields, 4)?)?;
    Ok(Rule {
        handle: u64_field(&fields, 3)?,
        tag: value(&fields, 7)?.to_vec(),
        expressions,
        counters,
    })
}

fn rule_payload(
    table: &str,
    tag: &[u8],
    tuple: Option<&ReceiveTuple>,
) -> Result<Vec<u8>, KernelError> {
    let mut payload = named(1, table)?;
    push_string_attribute(&mut payload, 2, CHAIN)?;
    push_attribute(&mut payload, 7, tag)?;
    push_attribute(
        &mut payload,
        4 | NESTED,
        &expressions::encode(&expressions(tuple))?,
    )?;
    Ok(payload)
}

fn header() -> Vec<u8> {
    vec![FAMILY, 0, 0, 0]
}
fn named(kind: u16, name: &str) -> Result<Vec<u8>, KernelError> {
    let mut result = header();
    push_string_attribute(&mut result, kind, name)?;
    Ok(result)
}
fn number(output: &mut Vec<u8>, kind: u16, value: u32) -> Result<(), KernelError> {
    push_attribute(output, kind, &value.to_be_bytes())
}

type Fields<'a> = BTreeMap<u16, &'a [u8]>;
fn fields<'a>(payload: &'a [u8], allowed: &[u16], pads: &[u16]) -> Result<Fields<'a>, KernelError> {
    if payload.get(..2) != Some(&[FAMILY, 0]) {
        return Err(KernelError::Malformed);
    }
    attributes_map(
        payload.get(4..).ok_or(KernelError::Malformed)?,
        allowed,
        pads,
    )
}
fn attributes_map<'a>(
    bytes: &'a [u8],
    allowed: &[u16],
    pads: &[u16],
) -> Result<Fields<'a>, KernelError> {
    let mut fields = BTreeMap::new();
    let mut padding = 0;
    let attributes = attributes(bytes)?;
    if attributes.len() > allowed.len() + 2 {
        return Err(KernelError::Malformed);
    }
    for (kind, data) in attributes {
        let kind = kind & MASK;
        if !allowed.contains(&kind) {
            return Err(KernelError::Malformed);
        }
        if pads.contains(&kind) {
            padding += 1;
            if !data.is_empty() || padding > 2 {
                return Err(KernelError::Malformed);
            }
        } else if fields.insert(kind, data).is_some() {
            return Err(KernelError::Malformed);
        }
    }
    Ok(fields)
}
fn value<'a>(fields: &Fields<'a>, kind: u16) -> Result<&'a [u8], KernelError> {
    fields.get(&kind).copied().ok_or(KernelError::Malformed)
}
fn u32_field(fields: &Fields<'_>, kind: u16) -> Result<u32, KernelError> {
    Ok(u32::from_be_bytes(
        value(fields, kind)?
            .try_into()
            .map_err(|_| KernelError::Malformed)?,
    ))
}
fn u64_field(fields: &Fields<'_>, kind: u16) -> Result<u64, KernelError> {
    Ok(u64::from_be_bytes(
        value(fields, kind)?
            .try_into()
            .map_err(|_| KernelError::Malformed)?,
    ))
}
fn string<'a>(fields: &Fields<'a>, kind: u16) -> Result<&'a str, KernelError> {
    let bytes = value(fields, kind)?;
    let text = bytes.strip_suffix(&[0]).ok_or(KernelError::Malformed)?;
    if text.is_empty() || text.contains(&0) {
        return Err(KernelError::Malformed);
    }
    std::str::from_utf8(text).map_err(|_| KernelError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::{PRIORITY, number, push_attribute, push_string_attribute, verify_hook};

    #[test]
    fn receive_accounting_kernel_hook_device_list_is_exactly_the_pinned_singleton() {
        let mut hook = Vec::new();
        number(&mut hook, 1, 0).unwrap();
        push_attribute(&mut hook, 2, &PRIORITY.to_be_bytes()).unwrap();
        push_string_attribute(&mut hook, 3, "rx0").unwrap();
        assert!(verify_hook(&hook, "rx0").is_ok());
        let mut devices = Vec::new();
        push_string_attribute(&mut devices, 1, "rx0").unwrap();
        let mut actual_kernel = hook.clone();
        push_attribute(&mut actual_kernel, 4, &devices).unwrap();
        assert!(verify_hook(&actual_kernel, "rx0").is_ok());
        for invalid in [b"foreign\0".as_slice(), b"".as_slice()] {
            let mut entry = Vec::new();
            push_attribute(&mut entry, 1, invalid).unwrap();
            let mut altered = hook.clone();
            push_attribute(&mut altered, 4, &entry).unwrap();
            assert!(verify_hook(&altered, "rx0").is_err());
        }
        push_string_attribute(&mut devices, 1, "another").unwrap();
        push_attribute(&mut hook, 4, &devices).unwrap();
        assert!(verify_hook(&hook, "rx0").is_err());
    }
}
