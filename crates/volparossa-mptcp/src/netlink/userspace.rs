//! Linux 6.12 userspace-PM commands and bounded kernel events.
//!
//! Tokens here are kernel selectors, never authorization. The privileged caller must bind an
//! operation to its issued flow capability, live socket, namespace and committed route lease.
//! Linux continues to own scheduling, congestion control, retransmission and reassembly.

use std::{
    io,
    net::{Ipv6Addr, SocketAddr},
};

use super::{
    CTRL_ATTR_FAMILY_NAME, CTRL_CMD_GETFAMILY, CTRL_VERSION, GENL_HEADER_LEN, GENL_ID_CTRL,
    MAX_REPLY_LEN, MPTCP_PM_ADDR_ATTR_ADDR6, MPTCP_PM_ADDR_ATTR_FAMILY, MPTCP_PM_ADDR_ATTR_ID,
    MPTCP_PM_ADDR_ATTR_PORT, MPTCP_PM_ATTR_ADDR, MPTCP_PM_VERSION, MptcpNetlinkClient,
    NLA_F_NESTED, NLA_TYPE_MASK, NLM_F_REQUEST, NLMSG_HEADER_LEN, attributes, build_message,
    encode_endpoint, netlink_frames, parse_family_id, push_attr, push_attr_unchecked, read_u16,
    read_u32,
};
use crate::{EndpointFlags, MptcpEndpoint, MptcpError};
use netlink_sys::Socket;

const SUBFLOW_CREATE: u8 = 10;
const SUBFLOW_DESTROY: u8 = 11;
const TOKEN: u16 = 4;
const REMOTE_ADDRESS: u16 = 6;
const CTRL_MULTICAST_GROUPS: u16 = 7;
const MAX_EVENTS: usize = 256;
const MAX_EVENT_DATAGRAMS: usize = 64;
// Linux UAPI value, checked against libc below without a narrowing conversion.
const IPV6_FAMILY: u16 = 10;
const _: () = assert!(libc::AF_INET6 == 10);

impl MptcpNetlinkClient {
    /// Request one exact additional subflow; ACK is not establishment or traffic evidence.
    ///
    /// # Errors
    /// Rejects non-client overlay endpoints, cross-path tuples and kernel failures.
    pub fn create_subflow(
        &mut self,
        token: u32,
        local: &MptcpEndpoint,
        remote: SocketAddr,
    ) -> Result<(), MptcpError> {
        local.validate()?;
        if local.flags != EndpointFlags::SUBFLOW || local.listener_port.is_some() {
            return Err(invalid(
                "subflow create requires a selected client endpoint",
            ));
        }
        let local_tuple = SocketAddr::new(local.address, 0);
        validate_pair(local_tuple, remote, false)?;
        let mut payload = Vec::with_capacity(128);
        push_attr(&mut payload, TOKEN, &token.to_ne_bytes())?;
        push_attr(
            &mut payload,
            MPTCP_PM_ATTR_ADDR | NLA_F_NESTED,
            &encode_endpoint(local),
        )?;
        push_attr(
            &mut payload,
            REMOTE_ADDRESS | NLA_F_NESTED,
            &encode_tuple(remote, local.id),
        )?;
        self.request_ack(SUBFLOW_CREATE, &payload)
    }

    /// Destroy only the exact observed additional subflow tuple of a still-pinned meta socket.
    ///
    /// # Errors
    /// Rejects incomplete/cross-path tuples and kernel failures. An absent tuple is not silently
    /// treated as successful cleanup; the caller may separately establish exact absence.
    pub fn destroy_subflow(
        &mut self,
        token: u32,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(), MptcpError> {
        let id = validate_pair(local, remote, true)?;
        let mut payload = Vec::with_capacity(128);
        push_attr(&mut payload, TOKEN, &token.to_ne_bytes())?;
        push_attr(
            &mut payload,
            MPTCP_PM_ATTR_ADDR | NLA_F_NESTED,
            &encode_tuple(local, id),
        )?;
        push_attr(
            &mut payload,
            REMOTE_ADDRESS | NLA_F_NESTED,
            &encode_tuple(remote, id),
        )?;
        self.request_ack(SUBFLOW_DESTROY, &payload)
    }
}

fn validate_pair(
    local: SocketAddr,
    remote: SocketAddr,
    destroying: bool,
) -> Result<u8, MptcpError> {
    let (SocketAddr::V6(local), SocketAddr::V6(remote)) = (local, remote) else {
        return Err(invalid("subflow tuples must be IPv6 overlay addresses"));
    };
    let (left, right) = (local.ip().segments(), remote.ip().segments());
    if left[..3] != [0xfd76, 0x6f6c, 0x7061]
        || left[..7] != right[..7]
        || left[7] != 1
        || right[7] != 4
        || !(1..=8).contains(&left[5])
        || local.scope_id() != 0
        || remote.scope_id() != 0
        || local.flowinfo() != 0
        || remote.flowinfo() != 0
        || remote.port() == 0
        || (destroying && local.port() == 0)
    {
        return Err(invalid(
            "subflow tuples do not name one exact client-to-exit overlay path",
        ));
    }
    u8::try_from(left[5]).map_err(|_| invalid("invalid path identifier"))
}

fn encode_tuple(address: SocketAddr, id: u8) -> Vec<u8> {
    let mut output = Vec::with_capacity(48);
    if let SocketAddr::V6(address) = address {
        push_attr_unchecked(
            &mut output,
            MPTCP_PM_ADDR_ATTR_FAMILY,
            &IPV6_FAMILY.to_ne_bytes(),
        );
        push_attr_unchecked(
            &mut output,
            MPTCP_PM_ADDR_ATTR_ADDR6,
            &address.ip().octets(),
        );
        push_attr_unchecked(&mut output, MPTCP_PM_ADDR_ATTR_ID, &[id]);
        // Command attributes are native-endian u16; Linux pm_parse_addr applies htons.
        // Event SPORT/DPORT attributes, in contrast, are emitted as big-endian values.
        push_attr_unchecked(
            &mut output,
            MPTCP_PM_ADDR_ATTR_PORT,
            &address.port().to_ne_bytes(),
        );
    }
    output
}

/// Closed subset of documented kernel events; events are observations, not route authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MptcpEventKind {
    /// Initial meta socket created.
    Created,
    /// Meta socket completed negotiation.
    Established,
    /// Meta socket closed.
    Closed,
    /// A peer advertised an address; this does not authorize connecting to it.
    Announced,
    /// A peer withdrew an address.
    Removed,
    /// One subflow became established.
    SubflowEstablished,
    /// One subflow closed.
    SubflowClosed,
    /// Subflow priority changed.
    SubflowPriority,
    /// Namespace-local listener notification.
    Listener,
}

/// Sanitized event fields needed for exact owned-flow lifetime tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MptcpEvent {
    /// Documented event kind.
    pub kind: MptcpEventKind,
    /// Kernel selector; absent only for listener notifications.
    pub token: Option<u32>,
    /// Exact tuple when present in the event.
    pub local: Option<SocketAddr>,
    /// Exact tuple when present in the event.
    pub remote: Option<SocketAddr>,
    /// Local endpoint identifier, not a capability.
    pub local_id: Option<u8>,
    /// Peer endpoint identifier, not a capability.
    pub remote_id: Option<u8>,
}

/// One namespace-local multicast socket, opened before creating Client MPTCP sockets.
/// No data socket is retained. Dropping this owner releases the subscription.
pub struct MptcpEventSubscription {
    socket: Socket,
    family_id: u16,
}

impl MptcpEventSubscription {
    /// Resolve and subscribe to the kernel's `mptcp_pm_events` multicast group.
    ///
    /// # Errors
    /// Returns errors for unavailable PM/event support, permission denial or malformed metadata.
    pub fn connect() -> Result<Self, MptcpError> {
        let mut client = MptcpNetlinkClient::connect()?;
        let mut attributes = Vec::new();
        push_attr(&mut attributes, CTRL_ATTR_FAMILY_NAME, b"mptcp_pm\0")?;
        let sequence = client.next_sequence();
        client.send_all(&build_message(
            GENL_ID_CTRL,
            NLM_F_REQUEST,
            sequence,
            CTRL_CMD_GETFAMILY,
            CTRL_VERSION,
            &attributes,
        )?)?;
        let reply = client.receive_bounded()?;
        if parse_family_id(&reply, sequence, client.local_port_id)? != client.family_id {
            return Err(invalid("MPTCP family changed during event subscription"));
        }
        let group = event_group(&reply.message)?;
        client.socket.set_rx_buf_sz(MAX_REPLY_LEN)?;
        client.socket.add_membership(group)?;
        client.socket.set_non_blocking(true)?;
        Ok(Self {
            socket: client.socket,
            family_id: client.family_id,
        })
    }

    /// Drain currently available events with fixed byte/frame/count bounds.
    ///
    /// # Errors
    /// Loss, truncation, an unknown/malformed event, or exceeding the drain bound fails closed;
    /// no incomplete prefix is returned as complete evidence.
    pub fn drain(&self) -> Result<Vec<MptcpEvent>, MptcpError> {
        let mut output = Vec::new();
        let mut buffer = vec![0_u8; MAX_REPLY_LEN];
        for _ in 0..MAX_EVENT_DATAGRAMS {
            let (length, sender) = match self
                .socket
                .recv_from(&mut &mut buffer[..], libc::MSG_DONTWAIT | libc::MSG_TRUNC)
            {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(output),
                Err(error) => return Err(error.into()),
            };
            if sender.port_number() != 0 || !(NLMSG_HEADER_LEN..=MAX_REPLY_LEN).contains(&length) {
                return Err(invalid("invalid or truncated kernel event datagram"));
            }
            for frame in netlink_frames(&buffer[..length])? {
                if output.len() == MAX_EVENTS {
                    return Err(invalid("MPTCP event drain capacity"));
                }
                output.push(parse_event(frame, self.family_id)?);
            }
        }
        Err(invalid("MPTCP event datagram drain capacity"))
    }
}

fn event_group(message: &[u8]) -> Result<u32, MptcpError> {
    let frames = netlink_frames(message)?;
    let [frame] = frames.as_slice() else {
        return Err(invalid("event group frame count"));
    };
    let mut found = None;
    for (kind, payload) in attributes(&frame[NLMSG_HEADER_LEN + GENL_HEADER_LEN..])? {
        if kind & NLA_TYPE_MASK != CTRL_MULTICAST_GROUPS {
            continue;
        }
        for (_, group) in attributes(payload)? {
            let fields = attributes(group)?;
            let name = fields
                .iter()
                .find(|(kind, _)| kind & NLA_TYPE_MASK == 1)
                .map(|(_, bytes)| *bytes);
            if name != Some(b"mptcp_pm_events\0".as_slice()) {
                continue;
            }
            let id = fields
                .iter()
                .find(|(kind, _)| kind & NLA_TYPE_MASK == 2)
                .map(|(_, bytes)| *bytes)
                .filter(|bytes| bytes.len() == 4)
                .ok_or_else(|| invalid("missing event group id"))?;
            let id =
                u32::from_ne_bytes(id.try_into().map_err(|_| invalid("event group id width"))?);
            if id == 0 || found.replace(id).is_some() {
                return Err(invalid("ambiguous event group"));
            }
        }
    }
    found.ok_or_else(|| invalid("kernel MPTCP event group absent"))
}

fn parse_event(frame: &[u8], family: u16) -> Result<MptcpEvent, MptcpError> {
    if frame.len() < NLMSG_HEADER_LEN + GENL_HEADER_LEN
        || read_u16(frame, 4)? != family
        || read_u32(frame, 8)? != 0
        || read_u32(frame, 12)? != 0
        || frame[NLMSG_HEADER_LEN + 1] != MPTCP_PM_VERSION
        || frame[NLMSG_HEADER_LEN + 2..NLMSG_HEADER_LEN + 4] != [0, 0]
    {
        return Err(invalid("uncorrelated kernel MPTCP event"));
    }
    let kind = match frame[NLMSG_HEADER_LEN] {
        1 => MptcpEventKind::Created,
        2 => MptcpEventKind::Established,
        3 => MptcpEventKind::Closed,
        6 => MptcpEventKind::Announced,
        7 => MptcpEventKind::Removed,
        10 => MptcpEventKind::SubflowEstablished,
        11 => MptcpEventKind::SubflowClosed,
        13 => MptcpEventKind::SubflowPriority,
        15 | 16 => MptcpEventKind::Listener,
        _ => return Err(invalid("unknown MPTCP kernel event")),
    };
    let mut fields = [None; 20];
    for (kind, payload) in attributes(&frame[NLMSG_HEADER_LEN + GENL_HEADER_LEN..])? {
        let index = usize::from(kind & NLA_TYPE_MASK);
        if index == 0 || index >= fields.len() || fields[index].replace(payload).is_some() {
            return Err(invalid("duplicate or unknown MPTCP event attribute"));
        }
    }
    let token = fields[1]
        .map(|v| {
            v.try_into()
                .map(u32::from_ne_bytes)
                .map_err(|_| invalid("event token width"))
        })
        .transpose()?;
    if token.is_none() && kind != MptcpEventKind::Listener {
        return Err(invalid("event token missing"));
    }
    let endpoint_id = |index: usize| {
        fields[index]
            .map(|bytes| match bytes {
                [id] => Ok(*id),
                _ => Err(invalid("event endpoint width")),
            })
            .transpose()
    };
    let tuple = |address_index: usize,
                 port_index: usize|
     -> Result<Option<SocketAddr>, MptcpError> {
        match (fields[address_index], fields[port_index]) {
            (Some(bytes), Some(port)) => {
                if fields[2] != Some(&IPV6_FAMILY.to_ne_bytes()[..]) {
                    return Err(invalid("event address family"));
                }
                let address = Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).map_err(|_| invalid("event address width"))?,
                );
                let port =
                    u16::from_be_bytes(port.try_into().map_err(|_| invalid("event port width"))?);
                Ok(Some(SocketAddr::new(address.into(), port)))
            }
            (None, None) => Ok(None),
            // ANNOUNCED may legitimately omit its port; no tuple authority is inferred.
            (Some(_), None) if kind == MptcpEventKind::Announced => Ok(None),
            _ => Err(invalid("partial MPTCP event tuple")),
        }
    };
    Ok(MptcpEvent {
        kind,
        token,
        local: tuple(6, 9)?,
        remote: tuple(8, 10)?,
        local_id: endpoint_id(3)?,
        remote_id: endpoint_id(4)?,
    })
}

fn invalid(message: &str) -> MptcpError {
    MptcpError::Netlink(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subflow_pair_keeps_exact_path_and_command_ports_native_endian() {
        let local: SocketAddr = "[fd76:6f6c:7061:1111:2222:3:4444:1]:45123".parse().unwrap();
        let remote: SocketAddr = "[fd76:6f6c:7061:1111:2222:3:4444:4]:44443".parse().unwrap();
        assert_eq!(validate_pair(local, remote, true).unwrap(), 3);
        let fields = attributes(&encode_tuple(remote, 3))
            .unwrap()
            .into_iter()
            .map(|(kind, bytes)| (kind, bytes.to_vec()))
            .collect::<Vec<_>>();
        assert!(fields.contains(&(MPTCP_PM_ADDR_ATTR_PORT, 44443_u16.to_ne_bytes().to_vec())));
        assert!(
            validate_pair(
                local,
                "[fd76:6f6c:7061:1111:2222:4:4444:4]:44443".parse().unwrap(),
                true
            )
            .is_err()
        );
        assert!(validate_pair(SocketAddr::new(local.ip(), 0), remote, true).is_err());
        assert!(validate_pair(remote, local, false).is_err());
    }

    #[test]
    fn kernel_event_parser_binds_token_tuple_and_rejects_malformed_or_forged_frames() {
        let mut payload = Vec::new();
        push_attr(&mut payload, 1, &123_u32.to_ne_bytes()).unwrap();
        push_attr(&mut payload, 2, &IPV6_FAMILY.to_ne_bytes()).unwrap();
        push_attr(&mut payload, 3, &[3]).unwrap();
        push_attr(&mut payload, 4, &[3]).unwrap();
        for (kind, value) in [
            (6, "fd76:6f6c:7061:1111:2222:3:4444:1"),
            (8, "fd76:6f6c:7061:1111:2222:3:4444:4"),
        ] {
            push_attr(
                &mut payload,
                kind,
                &value.parse::<Ipv6Addr>().unwrap().octets(),
            )
            .unwrap();
        }
        push_attr(&mut payload, 9, &45123_u16.to_be_bytes()).unwrap();
        push_attr(&mut payload, 10, &44443_u16.to_be_bytes()).unwrap();
        let frame = build_message(35, 0, 0, 10, 1, &payload).unwrap();
        let event = parse_event(&frame, 35).unwrap();
        assert_eq!(event.kind, MptcpEventKind::SubflowEstablished);
        assert_eq!(event.token, Some(123));
        assert_eq!(event.local.unwrap().port(), 45123);
        assert_eq!(event.remote.unwrap().port(), 44443);
        assert!(parse_event(&frame, 36).is_err());
        let mut forged = frame.clone();
        forged[12] = 1;
        assert!(parse_event(&forged, 35).is_err());
        push_attr(&mut payload, 1, &123_u32.to_ne_bytes()).unwrap();
        assert!(parse_event(&build_message(35, 0, 0, 10, 1, &payload).unwrap(), 35).is_err());
    }
}
