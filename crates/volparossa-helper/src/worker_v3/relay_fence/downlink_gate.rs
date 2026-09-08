//! Persistent per-owned-Exit-output admission gate, reusing the strict relay NFT codec.
//!
//! This gate is deliberately NOT socket-owned: a killed worker must not remove the expiry
//! predicate while another process or durable FD store still pins its `WireGuard` namespace.
//! It gates admission before the finite sender qdisc; already queued packets form a bounded tail.

#[cfg_attr(
    not(test),
    expect(
        clippy::wildcard_imports,
        reason = "private child reuses the closed NFT codec and UAPI constants"
    )
)]
use super::*;
use crate::ownership_journal::DurableWireguardResource;
use std::fmt::Write as _;

const OUTPUT: &[u8] = b"egress";
const NF_NETDEV_EGRESS: u32 = 1;
const GATE_KEY: [u8; 1] = [NFPROTO_NETDEV];
const DOMAIN: &[u8] = b"VOLPAROSSA adjacent receive gate v1\0";

#[derive(Clone)]
enum Mode {
    Closed,
    Live {
        timeout_ms: u64,
        expires_unix_ns: u64,
    },
}

pub(in crate::worker_v3) struct DownlinkGate {
    namespace: NetworkNamespaceIdentity,
    identity: RelayFenceIdentity,
    interface: [u8; INTERFACE_NAME_BYTES],
    ifindex: u32,
    mode: Mode,
    may_exist: bool,
}

impl DownlinkGate {
    /// Recover only this authenticated resource's gate after its exact `WireGuard` link is absent.
    /// Persistent gates must survive worker socket loss, but must not block the dead-worker reaper.
    pub(in crate::worker_v3) fn cleanup_after_exact_link_absence(
        context: [u8; 16],
        resource: &DurableWireguardResource,
        deadline: HardDeadline,
    ) -> Result<(), RelayFenceError> {
        crate::kernel::NamespaceKernel::connect(deadline)
            .and_then(|mut kernel| kernel.prove_wireguard_absent_v3(resource, deadline))
            .map_err(|_| RelayFenceError::UnexpectedPolicy)?;
        let probe = Self::new(context, resource, 2)?;
        let observed = observe(&probe.identity.table_name, &probe.interface, deadline)?;
        if observed.snapshot.is_empty() {
            return Ok(());
        }
        let [table] = observed.snapshot.tables.as_slice() else {
            return Err(RelayFenceError::UnexpectedPolicy);
        };
        let userdata = table
            .userdata
            .as_ref()
            .ok_or(RelayFenceError::UnexpectedPolicy)?;
        let prefix = probe.userdata();
        let boundary = prefix.len() - 4;
        if userdata.len() != prefix.len() || userdata[..boundary] != prefix[..boundary] {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        let index = u32::from_be_bytes(
            userdata[boundary..]
                .try_into()
                .map_err(|_| RelayFenceError::Malformed)?,
        );
        let mut recovered = Self::new(context, resource, index)?;
        recovered.may_exist = true;
        recovered.remove(deadline)
    }

    pub(in crate::worker_v3) fn new(
        context: [u8; 16],
        resource: &DurableWireguardResource,
        ifindex: u32,
    ) -> Result<Self, RelayFenceError> {
        if resource.key().1 != WireguardRole::Exit as i32 || !(2..=0x7fff_ffff).contains(&ifindex) {
            return Err(RelayFenceError::Invalid);
        }
        let path_id = resource.key().0;
        let mut name = String::from("vpd_");
        for byte in context {
            let _ = write!(name, "{byte:02x}");
        }
        let _ = write!(name, "_{path_id}");
        let table_name = name.into_bytes();
        Ok(Self {
            namespace: current_network_namespace_identity()
                .map_err(|_| RelayFenceError::Namespace)?,
            identity: RelayFenceIdentity {
                route_context_id: context,
                path_id,
                table_name,
            },
            interface: fixed_interface_name(resource.interface())?,
            ifindex,
            mode: Mode::Closed,
            may_exist: false,
        })
    }

    fn userdata(&self) -> Vec<u8> {
        let mut value = DOMAIN.to_vec();
        value.extend_from_slice(&self.identity.route_context_id);
        value.push(self.identity.path_id);
        value.extend_from_slice(&self.ifindex.to_be_bytes());
        value
    }

    fn check_namespace(&self) -> Result<(), RelayFenceError> {
        if current_network_namespace_identity().ok() != Some(self.namespace) {
            return Err(RelayFenceError::Namespace);
        }
        Ok(())
    }

    pub(in crate::worker_v3) fn close(
        &mut self,
        deadline: HardDeadline,
    ) -> Result<(), RelayFenceError> {
        self.replace(Mode::Closed, deadline)
    }

    pub(in crate::worker_v3) fn open(
        &mut self,
        expires_unix_ms: u64,
        expires_boottime_ns: u64,
        deadline: HardDeadline,
    ) -> Result<(), RelayFenceError> {
        // Reserve the complete remaining operation budget, like the existing Relay fence. A
        // late ACK cannot extend the lease and BOOTTIME also charges system suspend time.
        let timeout = super::super::relay_gate_timeout(expires_boottime_ns, deadline)
            .ok_or(RelayFenceError::Expired)?;
        let timeout_ms = u64::try_from(timeout.as_millis())
            .map_err(|_| RelayFenceError::Expired)?
            .checked_sub(10)
            .map(|value| value / 20 * 20)
            .filter(|value| *value > 0 && *value <= 5000)
            .ok_or(RelayFenceError::Expired)?;
        let absolute_expiry = expires_unix_ms
            .checked_mul(1_000_000)
            .ok_or(RelayFenceError::Invalid)?;
        self.replace(
            Mode::Live {
                timeout_ms,
                expires_unix_ns: absolute_expiry,
            },
            deadline,
        )
    }

    fn expressions(&self, allowed: bool, mode: &Mode) -> Vec<ObservedExpression> {
        let mut value = vec![
            ObservedExpression::Meta {
                destination: NFT_REG_1,
                key: NFT_META_OIF,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: self.ifindex.to_ne_bytes().to_vec(),
            },
            ObservedExpression::Meta {
                destination: NFT_REG_1,
                key: NFT_META_OIFNAME,
            },
            ObservedExpression::Compare {
                source: NFT_REG_1,
                operation: NFT_CMP_EQ,
                value: self.interface.to_vec(),
            },
        ];
        if allowed {
            let Mode::Live {
                expires_unix_ns, ..
            } = mode
            else {
                return Vec::new();
            };
            value.extend([
                ObservedExpression::Meta {
                    destination: NFT_REG_1,
                    key: NFT_META_NFPROTO,
                },
                ObservedExpression::Lookup {
                    set: LIVE_SET_NAME.to_vec(),
                    source: NFT_REG_1,
                    flags: 0,
                },
            ]);
            value.extend(expiry_expressions(*expires_unix_ns));
        }
        value.extend([
            ObservedExpression::Counter(RelayFenceCounter::ZERO),
            if allowed {
                ObservedExpression::ImmediateAccept
            } else {
                ObservedExpression::ImmediateDrop
            },
        ]);
        value
    }

    fn verify(&self, snapshot: &RulesetSnapshot) -> Result<Option<u64>, RelayFenceError> {
        if snapshot.is_empty() {
            return Ok(None);
        }
        let [table] = snapshot.tables.as_slice() else {
            return Err(RelayFenceError::UnexpectedPolicy);
        };
        let [chain] = snapshot.chains.as_slice() else {
            return Err(RelayFenceError::UnexpectedPolicy);
        };
        let live = matches!(self.mode, Mode::Live { .. });
        if table.family != NFPROTO_NETDEV
            || table.name != self.identity.table_name
            || table.handle == 0
            || table.flags != 0
            || table.owner.is_some()
            || table.userdata.as_deref() != Some(self.userdata().as_slice())
            || !self.exact_chain(chain, if live { 2 } else { 1 })
            || snapshot.rules.len() != if live { 2 } else { 1 }
            || snapshot.sets.len() != usize::from(live)
        {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        for (index, rule) in snapshot.rules.iter().enumerate() {
            let expected = self.expressions(live && index == 0, &self.mode);
            if rule.family != NFPROTO_NETDEV
                || rule.table != self.identity.table_name
                || rule.chain != OUTPUT
                || rule.handle == 0
                || rule.userdata.is_some()
                || rule.expressions.len() != expected.len()
                || rule
                    .expressions
                    .iter()
                    .zip(&expected)
                    .any(|(actual, expected)| {
                        !matches!(
                            (actual, expected),
                            (
                                ObservedExpression::Counter(_),
                                ObservedExpression::Counter(_)
                            )
                        ) && actual != expected
                    })
            {
                return Err(RelayFenceError::UnexpectedPolicy);
            }
        }
        if let Mode::Live { timeout_ms, .. } = self.mode {
            let set = &snapshot.sets[0];
            if set.family != NFPROTO_NETDEV
                || set.table != self.identity.table_name
                || set.name != LIVE_SET_NAME
                || set.flags != NFT_SET_ALLOWED_FLAGS
                || set.key_type != NFT_DATA_VALUE
                || set.key_length != 1
                || set.size != 1
                || set.handle == 0
                || set.policy != 0
                || set.pad
                || set.timeout_milliseconds.is_some()
                || set.gc_interval.is_some()
                || set.userdata.is_some()
                || snapshot.set_elements.len() > 1
                || snapshot.set_elements.iter().any(|element| {
                    element.table != self.identity.table_name
                        || element.family != NFPROTO_NETDEV
                        || element.set != LIVE_SET_NAME
                        || element.key != GATE_KEY
                        || element.timeout_milliseconds != timeout_ms
                        || element.expiration_milliseconds > timeout_ms
                })
            {
                return Err(RelayFenceError::UnexpectedPolicy);
            }
        } else if !snapshot.set_elements.is_empty() {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        Ok(Some(table.handle))
    }

    fn replace(&mut self, mode: Mode, deadline: HardDeadline) -> Result<(), RelayFenceError> {
        self.check_namespace()?;
        let before = observe(&self.identity.table_name, &self.interface, deadline)?;
        let existing = self.verify(&before.snapshot)?;
        if existing.is_some() != self.may_exist {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        let tx = self.transaction(existing, &mode, before.generation)?;
        let client = MutationClient::connect(deadline)?;
        // Freeze the potentially installed exact owner before dispatch, including lost ACKs.
        self.may_exist = true;
        self.mode = mode;
        client.send(&tx, deadline).map_err(|error| match error {
            MutationSendFailure::NotSent(error) | MutationSendFailure::PossiblySent(error) => error,
        })?;
        client.receive_acknowledgements(&tx, deadline)?;
        let after = observe(&self.identity.table_name, &self.interface, deadline)?;
        if self.verify(&after.snapshot)?.is_none() {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        Ok(())
    }

    fn transaction(
        &self,
        existing: Option<u64>,
        mode: &Mode,
        generation: u32,
    ) -> Result<MutationTransaction, RelayFenceError> {
        let mut tx = MutationTransaction::new();
        tx.push(
            NFNL_MSG_BATCH_BEGIN,
            NLM_F_REQUEST,
            1,
            &encode_batch_boundary_payload(Some(generation))?,
        )?;
        let mut sequence = 2;
        if let Some(handle) = existing {
            let mut payload = encode_request_nfgen(NFPROTO_NETDEV, 0);
            encode_attribute(&mut payload, NFTA_TABLE_HANDLE, &handle.to_be_bytes())?;
            tx.push(
                NFT_MSG_DELTABLE,
                NLM_F_REQUEST | NLM_F_ACK,
                sequence,
                &payload,
            )?;
            sequence += 1;
        }
        let mut table = encode_request_nfgen(NFPROTO_NETDEV, 0);
        encode_attribute(
            &mut table,
            NFTA_TABLE_NAME,
            &encode_nul_string(&self.identity.table_name)?,
        )?;
        encode_attribute(&mut table, NFTA_TABLE_FLAGS, &0_u32.to_be_bytes())?;
        encode_attribute(&mut table, NFTA_TABLE_USERDATA, &self.userdata())?;
        tx.push(
            NFT_MSG_NEWTABLE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            sequence,
            &table,
        )?;
        sequence += 1;
        tx.push(
            NFT_MSG_NEWCHAIN,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            sequence,
            &self.chain()?,
        )?;
        sequence += 1;
        if let Mode::Live { timeout_ms, .. } = mode {
            tx.push(
                NFT_MSG_NEWSET,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                sequence,
                &encode_singleton_live_set(&self.identity, NFPROTO_NETDEV)?,
            )?;
            sequence += 1;
            tx.push(
                NFT_MSG_NEWSETELEM,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                sequence,
                &encode_singleton_live_element(
                    &self.identity,
                    *timeout_ms,
                    NFPROTO_NETDEV,
                    GATE_KEY,
                )?,
            )?;
            sequence += 1;
            tx.push(
                NFT_MSG_NEWRULE,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
                sequence,
                &self.rule(true, mode)?,
            )?;
            sequence += 1;
        }
        tx.push(
            NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
            sequence,
            &self.rule(false, mode)?,
        )?;
        sequence += 1;
        tx.push(
            NFNL_MSG_BATCH_END,
            NLM_F_REQUEST,
            sequence,
            &encode_batch_boundary_payload(None)?,
        )?;
        tx.finish(
            usize::try_from(sequence).map_err(|_| RelayFenceError::Limit)?,
            usize::try_from(sequence - 2).map_err(|_| RelayFenceError::Limit)?,
        )
    }

    fn rule(&self, allowed: bool, mode: &Mode) -> Result<Vec<u8>, RelayFenceError> {
        let expressions = self.expressions(allowed, mode);
        let mut encoded = Vec::new();
        for expression in &expressions {
            let (name, data) = encode_policy_expression(expression)?;
            let mut element = Vec::new();
            encode_attribute(&mut element, NFTA_EXPR_NAME, &encode_nul_string(name)?)?;
            encode_attribute(&mut element, NFTA_EXPR_DATA | NLA_F_NESTED, &data)?;
            encode_attribute(&mut encoded, NFTA_LIST_ELEM | NLA_F_NESTED, &element)?;
        }
        let mut rule = encode_request_nfgen(NFPROTO_NETDEV, 0);
        encode_attribute(
            &mut rule,
            NFTA_RULE_TABLE,
            &encode_nul_string(&self.identity.table_name)?,
        )?;
        encode_attribute(&mut rule, NFTA_RULE_CHAIN, &encode_nul_string(OUTPUT)?)?;
        encode_attribute(&mut rule, NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, &encoded)?;
        Ok(rule)
    }

    pub(in crate::worker_v3) fn remove(
        &mut self,
        deadline: HardDeadline,
    ) -> Result<(), RelayFenceError> {
        self.check_namespace()?;
        let before = observe(&self.identity.table_name, &self.interface, deadline)?;
        if before.snapshot.is_empty() {
            self.may_exist = false;
            return Ok(());
        }
        // Cleanup accepts this owner's immutable table marker even after ambiguous rule replacement.
        let [table] = before.snapshot.tables.as_slice() else {
            return Err(RelayFenceError::UnexpectedPolicy);
        };
        if !self.may_exist
            || table.family != NFPROTO_NETDEV
            || table.name != self.identity.table_name
            || table.handle == 0
            || table.flags != 0
            || table.owner.is_some()
            || table.userdata.as_deref() != Some(self.userdata().as_slice())
        {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        let tx = delete_table(before.generation, table.handle)?;
        let client = MutationClient::connect(deadline)?;
        client.send(&tx, deadline).map_err(|error| match error {
            MutationSendFailure::NotSent(error) | MutationSendFailure::PossiblySent(error) => error,
        })?;
        client.receive_acknowledgements(&tx, deadline)?;
        if !observe(&self.identity.table_name, &self.interface, deadline)?
            .snapshot
            .is_empty()
        {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        self.may_exist = false;
        Ok(())
    }

    fn chain(&self) -> Result<Vec<u8>, RelayFenceError> {
        let mut hook = Vec::new();
        encode_attribute(
            &mut hook,
            NFTA_HOOK_HOOKNUM,
            &NF_NETDEV_EGRESS.to_be_bytes(),
        )?;
        encode_attribute(&mut hook, NFTA_HOOK_PRIORITY, &0_i32.to_be_bytes())?;
        let name = self
            .interface
            .split(|value| *value == 0)
            .next()
            .ok_or(RelayFenceError::Invalid)?;
        encode_attribute(&mut hook, NFTA_HOOK_DEV, &encode_nul_string(name)?)?;
        let mut chain = encode_request_nfgen(NFPROTO_NETDEV, 0);
        encode_attribute(
            &mut chain,
            NFTA_CHAIN_TABLE,
            &encode_nul_string(&self.identity.table_name)?,
        )?;
        encode_attribute(&mut chain, NFTA_CHAIN_NAME, &encode_nul_string(OUTPUT)?)?;
        encode_attribute(
            &mut chain,
            NFTA_CHAIN_TYPE,
            &encode_nul_string(FILTER_CHAIN_TYPE)?,
        )?;
        encode_attribute(&mut chain, NFTA_CHAIN_HOOK | NLA_F_NESTED, &hook)?;
        encode_attribute(&mut chain, NFTA_CHAIN_POLICY, &NF_ACCEPT.to_be_bytes())?;
        Ok(chain)
    }

    fn exact_chain(&self, chain: &ChainRecord, use_count: u32) -> bool {
        chain.family == NFPROTO_NETDEV
            && chain.table == self.identity.table_name
            && chain.name == OUTPUT
            && chain.handle != 0
            && chain.hook_number == NF_NETDEV_EGRESS
            && chain.hook_priority == 0
            && chain.policy == NF_ACCEPT
            && chain.use_count == use_count
            && chain.chain_type == FILTER_CHAIN_TYPE
            && chain.flags == NFT_CHAIN_BASE
            && chain.counters.is_none()
            && !chain.pad
            && chain.id.is_none()
            && chain.userdata.is_none()
    }
}

fn delete_table(generation: u32, handle: u64) -> Result<MutationTransaction, RelayFenceError> {
    let mut tx = MutationTransaction::new();
    tx.push(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        &encode_batch_boundary_payload(Some(generation))?,
    )?;
    let mut payload = encode_request_nfgen(NFPROTO_NETDEV, 0);
    encode_attribute(&mut payload, NFTA_TABLE_HANDLE, &handle.to_be_bytes())?;
    tx.push(NFT_MSG_DELTABLE, NLM_F_REQUEST | NLM_F_ACK, 2, &payload)?;
    tx.push(
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        3,
        &encode_batch_boundary_payload(None)?,
    )?;
    tx.finish(3, 1)
}

/// Filter the bounded complete dump by exact table before applying Relay's small per-table bounds.
/// Never relax the existing Relay collector or accept unrelated rules as sender authority.
fn observe(
    table: &[u8],
    interface: &[u8; 16],
    deadline: HardDeadline,
) -> Result<StableRuleset, RelayFenceError> {
    let mut collector = NetfilterCollector::connect(deadline)?;
    let mut budget = CollectionBudget::production();
    let generation = collector.collect_generation(deadline, &mut budget)?;
    let mut snapshot = RulesetSnapshot::default();
    for kind in ObjectKind::ALL {
        let sequence = collector.next_sequence()?;
        let request = encode_object_dump_request(kind, sequence)?;
        send_bounded(&collector.socket, &request, deadline)?;
        let mut done = false;
        while !done {
            let (bytes, sender) = receive_bounded(&collector.socket, deadline, &budget)?;
            if sender != SocketAddr::new(0, 0) {
                return Err(RelayFenceError::Malformed);
            }
            walk_datagram(&bytes, &mut budget, |frame| {
                if done
                    || read_ne_u32(frame, 8)? != sequence
                    || read_ne_u32(frame, 12)? != collector.local_port
                {
                    return Err(RelayFenceError::Malformed);
                }
                let message = read_ne_u16(frame, 4)?;
                let flags = read_ne_u16(frame, 6)?;
                let payload = &frame[NLMSG_HEADER_LEN..];
                if message == NLMSG_DONE {
                    parse_done(flags, payload)?;
                    done = true;
                    return Ok(());
                }
                if message == NLMSG_ERROR {
                    return Err(parse_request_error(flags, payload, &request)?);
                }
                if message != kind.reply_type() || flags != kind.reply_flags() {
                    return Err(RelayFenceError::Malformed);
                }
                let (header, attributes) = split_nfgenmsg(payload)?;
                validate_object_nfgen(header, generation)?;
                let attributes = parse_attributes(attributes, 32)?;
                let names: Vec<_> = attributes
                    .iter()
                    .filter(|attribute| attribute.kind == 1)
                    .collect();
                let [name] = names.as_slice() else {
                    return Err(RelayFenceError::Malformed);
                };
                if read_nul_string(name.payload, MAX_TABLE_NAME_BYTES)? == table {
                    if matches!(kind, ObjectKind::Chain) {
                        // Validate exact NETDEV hook membership here; the ordinary Relay decoder
                        // deliberately continues rejecting every device-bound hook.
                        if !snapshot.chains.is_empty() {
                            return Err(RelayFenceError::Limit);
                        }
                        snapshot
                            .chains
                            .push(parse_device_chain(payload, generation, interface)?);
                    } else if matches!(kind, ObjectKind::Rule) {
                        if snapshot.rules.len() >= 2 {
                            return Err(RelayFenceError::Limit);
                        }
                        snapshot
                            .rules
                            .push(parse_rule_with_counts(payload, generation, &[6, 11])?);
                    } else {
                        snapshot.ingest(kind, payload, generation)?;
                    }
                }
                Ok(())
            })?;
        }
    }
    if !snapshot.sets.is_empty() {
        let sequence = collector.next_sequence()?;
        let mut request = encode_set_element_dump_request(sequence, table, LIVE_SET_NAME)?;
        // Same bounded set codec/correlation, but this private owner uses NETDEV instead of INET.
        request[NLMSG_HEADER_LEN] = NFPROTO_NETDEV;
        send_bounded(&collector.socket, &request, deadline)?;
        let mut state = SetElementDumpState {
            sequence,
            local_port: collector.local_port,
            expected_generation: generation,
            expected_table: table,
            expected_set: LIVE_SET_NAME,
            request: &request,
            snapshot: &mut snapshot,
            done: false,
        };
        while !state.done {
            let (bytes, sender) = receive_bounded(&collector.socket, deadline, &budget)?;
            state.ingest(sender, &bytes, &mut budget)?;
        }
        state.finish()?;
    }
    if collector.collect_generation(deadline, &mut budget)? != generation {
        return Err(RelayFenceError::Inconsistent);
    }
    Ok(StableRuleset {
        generation,
        snapshot,
    })
}

/// Strip only independently verified exact hook-device attributes before reusing the unchanged
/// strict common chain-field parser. Duplicate, substituted or multiple devices remain errors.
fn parse_device_chain(
    payload: &[u8],
    generation: u32,
    interface: &[u8; 16],
) -> Result<ChainRecord, RelayFenceError> {
    let (header, attrs) = split_nfgenmsg(payload)?;
    if header.family != NFPROTO_NETDEV {
        return Err(RelayFenceError::UnexpectedPolicy);
    }
    let mut projected = payload[..4].to_vec();
    for attribute in parse_attributes(attrs, MAX_CHAIN_ATTRIBUTES)? {
        if attribute.flags != 0 {
            return Err(RelayFenceError::Malformed);
        }
        if attribute.kind != NFTA_CHAIN_HOOK {
            encode_attribute(&mut projected, attribute.kind, attribute.payload)?;
            continue;
        }
        let mut hook = Vec::new();
        let mut dev = false;
        let mut devs = false;
        for field in parse_attributes(attribute.payload, MAX_HOOK_ATTRIBUTES)? {
            if field.flags != 0 {
                return Err(RelayFenceError::Malformed);
            }
            match field.kind {
                NFTA_HOOK_DEV => {
                    if dev
                        || fixed_interface_name(
                            std::str::from_utf8(&read_nul_string(field.payload, 16)?)
                                .map_err(|_| RelayFenceError::Malformed)?,
                        )? != *interface
                    {
                        return Err(RelayFenceError::UnexpectedPolicy);
                    }
                    dev = true;
                }
                NFTA_HOOK_DEVS => {
                    if devs {
                        return Err(RelayFenceError::Malformed);
                    }
                    devs = true;
                    let devices = parse_attributes(field.payload, 1)?;
                    let [device] = devices.as_slice() else {
                        return Err(RelayFenceError::Malformed);
                    };
                    if device.kind != 1
                        || device.flags != 0
                        || fixed_interface_name(
                            std::str::from_utf8(&read_nul_string(device.payload, 16)?)
                                .map_err(|_| RelayFenceError::Malformed)?,
                        )? != *interface
                    {
                        return Err(RelayFenceError::UnexpectedPolicy);
                    }
                }
                _ => encode_attribute(&mut hook, field.kind, field.payload)?,
            }
        }
        if !dev {
            return Err(RelayFenceError::UnexpectedPolicy);
        }
        encode_attribute(&mut projected, NFTA_CHAIN_HOOK, &hook)?;
    }
    parse_chain_payload(&projected, generation)
}
