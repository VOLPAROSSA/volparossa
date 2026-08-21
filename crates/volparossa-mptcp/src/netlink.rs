//! Minimal, bounded encoder for the kernel's documented `mptcp_pm` generic-netlink family.

use std::{io, net::IpAddr};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_GENERIC};

use crate::{MptcpEndpoint, MptcpError, MptcpLimits};

const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_ERROR_CODE_LEN: usize = 4;
const GENL_HEADER_LEN: usize = 4;
const ATTR_HEADER_LEN: usize = 4;
const MAX_REPLY_LEN: usize = 64 * 1024;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_VERSION: u8 = 2;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(3 << 14);

const MPTCP_PM_CMD_ADD_ADDR: u8 = 1;
const MPTCP_PM_CMD_DEL_ADDR: u8 = 2;
const MPTCP_PM_CMD_SET_LIMITS: u8 = 5;
const MPTCP_PM_VERSION: u8 = 1;

const MPTCP_PM_ATTR_ADDR: u16 = 1;
const MPTCP_PM_ATTR_RCV_ADD_ADDRS: u16 = 2;
const MPTCP_PM_ATTR_SUBFLOWS: u16 = 3;

const MPTCP_PM_ADDR_ATTR_FAMILY: u16 = 1;
const MPTCP_PM_ADDR_ATTR_ID: u16 = 2;
const MPTCP_PM_ADDR_ATTR_ADDR4: u16 = 3;
const MPTCP_PM_ADDR_ATTR_ADDR6: u16 = 4;
const MPTCP_PM_ADDR_ATTR_FLAGS: u16 = 6;
const MPTCP_PM_ADDR_ATTR_IF_IDX: u16 = 7;

struct NetlinkReply {
    message: Vec<u8>,
    sender: SocketAddr,
}

/// Synchronous generic-netlink client used from the privileged worker thread.
pub struct MptcpNetlinkClient {
    socket: Socket,
    family_id: u16,
    sequence: u32,
}

impl MptcpNetlinkClient {
    /// Connects to the kernel and resolves the documented `mptcp_pm` family ID.
    ///
    /// # Errors
    ///
    /// Returns an error when the generic-netlink socket cannot be opened or the kernel returns an
    /// invalid family response.
    pub fn connect() -> Result<Self, MptcpError> {
        let mut socket = Socket::new(NETLINK_GENERIC)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        let mut client = Self {
            socket,
            family_id: 0,
            sequence: 1,
        };
        client.family_id = client.resolve_family("mptcp_pm")?;
        Ok(client)
    }

    /// Adds one namespace-local endpoint through `MPTCP_PM_CMD_ADD_ADDR`.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, encoding, transport, or the kernel operation fails.
    pub fn add_endpoint(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
        endpoint.validate()?;
        let address = encode_endpoint(endpoint);
        let mut payload = Vec::with_capacity(address.len() + ATTR_HEADER_LEN);
        push_attr(&mut payload, MPTCP_PM_ATTR_ADDR | NLA_F_NESTED, &address)?;
        self.request_ack(MPTCP_PM_CMD_ADD_ADDR, &payload)
    }

    /// Deletes precisely one endpoint owned by this route context.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, encoding, transport, or the kernel operation fails.
    pub fn delete_endpoint(&mut self, endpoint: &MptcpEndpoint) -> Result<(), MptcpError> {
        endpoint.validate()?;
        let address = encode_endpoint(endpoint);
        let mut payload = Vec::with_capacity(address.len() + ATTR_HEADER_LEN);
        push_attr(&mut payload, MPTCP_PM_ATTR_ADDR | NLA_F_NESTED, &address)?;
        self.request_ack(MPTCP_PM_CMD_DEL_ADDR, &payload)
    }

    /// Applies namespace-local accepted-address and additional-subflow bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, encoding, transport, or the kernel operation fails.
    pub fn set_limits(&mut self, limits: MptcpLimits) -> Result<(), MptcpError> {
        limits.validate()?;
        let mut payload = Vec::with_capacity(16);
        push_attr(
            &mut payload,
            MPTCP_PM_ATTR_RCV_ADD_ADDRS,
            &limits.accepted_addrs.to_ne_bytes(),
        )?;
        push_attr(
            &mut payload,
            MPTCP_PM_ATTR_SUBFLOWS,
            &limits.subflows.to_ne_bytes(),
        )?;
        self.request_ack(MPTCP_PM_CMD_SET_LIMITS, &payload)
    }

    fn resolve_family(&mut self, family_name: &str) -> Result<u16, MptcpError> {
        if family_name.is_empty() || family_name.len() > 64 || family_name.as_bytes().contains(&0) {
            return Err(MptcpError::Invalid(
                "invalid generic-netlink family name".into(),
            ));
        }
        let mut name = family_name.as_bytes().to_vec();
        name.push(0);
        let mut attrs = Vec::with_capacity(name.len() + ATTR_HEADER_LEN);
        push_attr(&mut attrs, CTRL_ATTR_FAMILY_NAME, &name)?;
        let sequence = self.next_sequence();
        let message = build_message(
            GENL_ID_CTRL,
            NLM_F_REQUEST,
            sequence,
            CTRL_CMD_GETFAMILY,
            CTRL_VERSION,
            &attrs,
        )?;
        self.send_all(&message)?;
        let response = self.receive_bounded()?;
        parse_family_id(&response, sequence)
    }

    fn request_ack(&mut self, command: u8, payload: &[u8]) -> Result<(), MptcpError> {
        let sequence = self.next_sequence();
        let message = build_message(
            self.family_id,
            NLM_F_REQUEST | NLM_F_ACK,
            sequence,
            command,
            MPTCP_PM_VERSION,
            payload,
        )?;
        self.send_all(&message)?;
        let response = self.receive_bounded()?;
        parse_ack(&response, sequence, self.family_id)
    }

    fn next_sequence(&mut self) -> u32 {
        let value = self.sequence;
        self.sequence = self.sequence.wrapping_add(1).max(1);
        value
    }

    fn send_all(&self, message: &[u8]) -> Result<(), MptcpError> {
        let sent = self.socket.send(message, 0)?;
        if sent != message.len() {
            return Err(MptcpError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "short generic-netlink write",
            )));
        }
        Ok(())
    }

    fn receive_bounded(&self) -> Result<NetlinkReply, MptcpError> {
        let mut buffer = vec![0_u8; MAX_REPLY_LEN];
        let (received, sender) = self.socket.recv_from(&mut &mut buffer[..], 0)?;
        if !(NLMSG_HEADER_LEN..=MAX_REPLY_LEN).contains(&received) {
            return Err(MptcpError::Netlink("invalid reply length".into()));
        }
        buffer.truncate(received);
        Ok(NetlinkReply {
            message: buffer,
            sender,
        })
    }
}

fn encode_endpoint(endpoint: &MptcpEndpoint) -> Vec<u8> {
    let mut attributes = Vec::with_capacity(64);
    let family = match endpoint.address {
        IpAddr::V4(address) => {
            push_attr_unchecked(&mut attributes, MPTCP_PM_ADDR_ATTR_ADDR4, &address.octets());
            u16::try_from(libc::AF_INET).expect("Linux AF_INET fits in u16")
        }
        IpAddr::V6(address) => {
            push_attr_unchecked(&mut attributes, MPTCP_PM_ADDR_ATTR_ADDR6, &address.octets());
            u16::try_from(libc::AF_INET6).expect("Linux AF_INET6 fits in u16")
        }
    };
    push_attr_unchecked(
        &mut attributes,
        MPTCP_PM_ADDR_ATTR_FAMILY,
        &family.to_ne_bytes(),
    );
    push_attr_unchecked(&mut attributes, MPTCP_PM_ADDR_ATTR_ID, &[endpoint.id]);
    push_attr_unchecked(
        &mut attributes,
        MPTCP_PM_ADDR_ATTR_FLAGS,
        &endpoint.flags.bits().to_ne_bytes(),
    );
    push_attr_unchecked(
        &mut attributes,
        MPTCP_PM_ADDR_ATTR_IF_IDX,
        &endpoint.if_index.to_ne_bytes(),
    );
    attributes
}

fn build_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    command: u8,
    version: u8,
    attrs: &[u8],
) -> Result<Vec<u8>, MptcpError> {
    let length = NLMSG_HEADER_LEN
        .checked_add(GENL_HEADER_LEN)
        .and_then(|value| value.checked_add(attrs.len()))
        .ok_or_else(|| MptcpError::Invalid("generic-netlink message length overflow".into()))?;
    let length_u32 = u32::try_from(length)
        .map_err(|_| MptcpError::Invalid("generic-netlink message is too large".into()))?;
    if length > MAX_REPLY_LEN {
        return Err(MptcpError::Invalid(
            "generic-netlink request exceeds hard limit".into(),
        ));
    }

    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(&length_u32.to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.push(command);
    message.push(version);
    message.extend_from_slice(&0_u16.to_ne_bytes());
    message.extend_from_slice(attrs);
    Ok(message)
}

fn push_attr(buffer: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<(), MptcpError> {
    let length = ATTR_HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| MptcpError::Invalid("netlink attribute length overflow".into()))?;
    let length_u16 = u16::try_from(length)
        .map_err(|_| MptcpError::Invalid("netlink attribute is too large".into()))?;
    buffer.extend_from_slice(&length_u16.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align4(buffer.len()), 0);
    Ok(())
}

fn push_attr_unchecked(buffer: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    // Every caller uses fixed kernel scalar/address widths, so conversion cannot fail.
    push_attr(buffer, kind, payload).expect("fixed-size MPTCP endpoint attribute");
}

fn parse_family_id(reply: &NetlinkReply, expected_sequence: u32) -> Result<u16, MptcpError> {
    validate_kernel_sender(&reply.sender)?;
    let frames = netlink_frames(&reply.message)?;
    if frames.len() != 1 {
        return Err(MptcpError::Netlink(
            "family lookup returned an unexpected frame count".into(),
        ));
    }
    let frame = frames[0];
    if read_u16(frame, 4)? == NLMSG_ERROR {
        return parse_ack(reply, expected_sequence, GENL_ID_CTRL).and(Err(MptcpError::Netlink(
            "family lookup returned an acknowledgement without a family".into(),
        )));
    }
    validate_kernel_header(frame, expected_sequence, GENL_ID_CTRL)?;
    if frame.len() < NLMSG_HEADER_LEN + GENL_HEADER_LEN
        || frame[NLMSG_HEADER_LEN] != CTRL_CMD_NEWFAMILY
        || frame[NLMSG_HEADER_LEN + 1] != CTRL_VERSION
    {
        return Err(MptcpError::Netlink(
            "family lookup returned an invalid generic-netlink header".into(),
        ));
    }
    for (kind, payload) in attributes(&frame[NLMSG_HEADER_LEN + GENL_HEADER_LEN..])? {
        if kind & NLA_TYPE_MASK == CTRL_ATTR_FAMILY_ID && payload.len() == 2 {
            return Ok(u16::from_ne_bytes([payload[0], payload[1]]));
        }
    }
    Err(MptcpError::Netlink(
        "kernel did not return the mptcp_pm family id".into(),
    ))
}

fn parse_ack(
    reply: &NetlinkReply,
    expected_sequence: u32,
    expected_family: u16,
) -> Result<(), MptcpError> {
    validate_kernel_sender(&reply.sender)?;
    let frames = netlink_frames(&reply.message)?;
    if frames.len() != 1 {
        return Err(MptcpError::Netlink(
            "acknowledgement returned an unexpected frame count".into(),
        ));
    }
    let frame = frames[0];
    validate_kernel_header(frame, expected_sequence, NLMSG_ERROR)?;
    let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
    if frame.len() < embedded_offset + NLMSG_HEADER_LEN
        || read_u32(frame, embedded_offset)? < u32::try_from(NLMSG_HEADER_LEN).expect("constant")
        || read_u16(frame, embedded_offset + 4)? != expected_family
        || read_u32(frame, embedded_offset + 8)? != expected_sequence
        || read_u32(frame, embedded_offset + 12)? != 0
    {
        return Err(MptcpError::Netlink(
            "acknowledgement does not match the original request".into(),
        ));
    }
    let errno = i32::from_ne_bytes([
        frame[NLMSG_HEADER_LEN],
        frame[NLMSG_HEADER_LEN + 1],
        frame[NLMSG_HEADER_LEN + 2],
        frame[NLMSG_HEADER_LEN + 3],
    ]);
    if errno == 0 {
        return Ok(());
    }
    Err(MptcpError::Io(io::Error::from_raw_os_error(
        errno.saturating_abs(),
    )))
}

fn validate_kernel_sender(sender: &SocketAddr) -> Result<(), MptcpError> {
    if *sender != SocketAddr::new(0, 0) {
        return Err(MptcpError::Netlink(
            "netlink response did not originate from the kernel".into(),
        ));
    }
    Ok(())
}

fn validate_kernel_header(
    frame: &[u8],
    expected_sequence: u32,
    expected_type: u16,
) -> Result<(), MptcpError> {
    if read_u16(frame, 4)? != expected_type
        || read_u32(frame, 8)? != expected_sequence
        || read_u32(frame, 12)? != 0
    {
        return Err(MptcpError::Netlink(
            "netlink response header is not correlated to the request".into(),
        ));
    }
    Ok(())
}

fn netlink_frames(message: &[u8]) -> Result<Vec<&[u8]>, MptcpError> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < message.len() {
        if message.len() - offset < NLMSG_HEADER_LEN {
            return Err(MptcpError::Netlink("truncated netlink header".into()));
        }
        let length = usize::try_from(read_u32(message, offset)?)
            .map_err(|_| MptcpError::Netlink("netlink length conversion failed".into()))?;
        if length < NLMSG_HEADER_LEN || length > message.len() - offset {
            return Err(MptcpError::Netlink("invalid netlink frame length".into()));
        }
        frames.push(&message[offset..offset + length]);
        offset = offset
            .checked_add(align4(length))
            .ok_or_else(|| MptcpError::Netlink("netlink frame offset overflow".into()))?;
    }
    Ok(frames)
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, MptcpError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTR_HEADER_LEN {
            return Err(MptcpError::Netlink("truncated netlink attribute".into()));
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        if length < ATTR_HEADER_LEN || length > bytes.len() {
            return Err(MptcpError::Netlink(
                "invalid netlink attribute length".into(),
            ));
        }
        result.push((kind, &bytes[ATTR_HEADER_LEN..length]));
        let aligned = align4(length);
        if aligned > bytes.len() {
            return Err(MptcpError::Netlink(
                "truncated netlink attribute padding".into(),
            ));
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, MptcpError> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| MptcpError::Netlink("truncated u16".into()))?;
    Ok(u16::from_ne_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, MptcpError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| MptcpError::Netlink("truncated u32".into()))?;
    Ok(u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

const fn align4(length: usize) -> usize {
    (length + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::EndpointFlags;

    const TEST_SEQUENCE: u32 = 7;
    const TEST_FAMILY: u16 = 0x42;

    fn acknowledgement(errno: i32) -> NetlinkReply {
        let mut message = vec![0_u8; NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN + NLMSG_HEADER_LEN];
        let length = u32::try_from(message.len()).expect("small acknowledgement");
        message[0..4].copy_from_slice(&length.to_ne_bytes());
        message[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        message[8..12].copy_from_slice(&TEST_SEQUENCE.to_ne_bytes());
        message[16..20].copy_from_slice(&errno.to_ne_bytes());
        let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
        let request_length =
            u32::try_from(NLMSG_HEADER_LEN + GENL_HEADER_LEN).expect("small request");
        message[embedded_offset..embedded_offset + 4]
            .copy_from_slice(&request_length.to_ne_bytes());
        message[embedded_offset + 4..embedded_offset + 6]
            .copy_from_slice(&TEST_FAMILY.to_ne_bytes());
        message[embedded_offset + 6..embedded_offset + 8]
            .copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        message[embedded_offset + 8..embedded_offset + 12]
            .copy_from_slice(&TEST_SEQUENCE.to_ne_bytes());
        NetlinkReply {
            message,
            sender: SocketAddr::new(0, 0),
        }
    }

    fn family_reply() -> NetlinkReply {
        let mut attrs = Vec::new();
        push_attr(&mut attrs, CTRL_ATTR_FAMILY_ID, &TEST_FAMILY.to_ne_bytes())
            .expect("family id attribute");
        NetlinkReply {
            message: build_message(
                GENL_ID_CTRL,
                0,
                TEST_SEQUENCE,
                CTRL_CMD_NEWFAMILY,
                CTRL_VERSION,
                &attrs,
            )
            .expect("family response"),
            sender: SocketAddr::new(0, 0),
        }
    }

    #[test]
    fn request_header_and_attribute_lengths_are_self_consistent() {
        let mut attrs = Vec::new();
        push_attr(&mut attrs, CTRL_ATTR_FAMILY_NAME, b"mptcp_pm\0").expect("attribute");
        let message = build_message(
            GENL_ID_CTRL,
            NLM_F_REQUEST,
            7,
            CTRL_CMD_GETFAMILY,
            CTRL_VERSION,
            &attrs,
        )
        .expect("message");
        assert_eq!(
            usize::try_from(read_u32(&message, 0).expect("length")).unwrap(),
            message.len()
        );
        assert_eq!(read_u16(&message, 4).expect("type"), GENL_ID_CTRL);
        assert_eq!(message[16], CTRL_CMD_GETFAMILY);
    }

    #[test]
    fn endpoint_encoding_contains_no_text_or_shell_data() {
        let endpoint = MptcpEndpoint {
            id: 2,
            address: "fd76:6f6c:7061:1111:2222:2:3333:1"
                .parse()
                .expect("address"),
            if_index: 12,
            flags: EndpointFlags::SUBFLOW | EndpointFlags::BACKUP,
        };
        let encoded = encode_endpoint(&endpoint);
        let decoded = attributes(&encoded).expect("attributes");
        assert!(
            decoded
                .iter()
                .any(|(kind, _)| *kind == MPTCP_PM_ADDR_ATTR_ADDR6)
        );
        assert!(decoded.iter().any(|(kind, payload)| {
            *kind == MPTCP_PM_ADDR_ATTR_ID && *payload == [endpoint.id]
        }));
    }

    #[test]
    fn zero_and_negative_ack_are_distinguished() {
        assert!(parse_ack(&acknowledgement(0), TEST_SEQUENCE, TEST_FAMILY).is_ok());
        let failure = parse_ack(&acknowledgement(-libc::EPERM), TEST_SEQUENCE, TEST_FAMILY)
            .expect_err("negative acknowledgement");
        assert!(matches!(
            failure,
            MptcpError::Io(error) if error.raw_os_error() == Some(libc::EPERM)
        ));
    }

    #[test]
    fn acknowledgement_is_bound_to_sequence_family_type_and_kernel_sender() {
        let mut wrong = acknowledgement(0);
        wrong.message[4..6].copy_from_slice(&TEST_FAMILY.to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        wrong.message[8..12].copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        wrong.message[12..16].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        let embedded_offset = NLMSG_HEADER_LEN + NLMSG_ERROR_CODE_LEN;
        wrong.message[embedded_offset + 4..embedded_offset + 6]
            .copy_from_slice(&(TEST_FAMILY + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 8..embedded_offset + 12]
            .copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        wrong.message[embedded_offset + 12..embedded_offset + 16]
            .copy_from_slice(&1_u32.to_ne_bytes());
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        wrong.sender = SocketAddr::new(99, 0);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        wrong.sender = SocketAddr::new(0, 1);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());

        wrong = acknowledgement(0);
        let second = wrong.message.clone();
        wrong.message.extend_from_slice(&second);
        assert!(parse_ack(&wrong, TEST_SEQUENCE, TEST_FAMILY).is_err());
    }

    #[test]
    fn family_lookup_is_bound_to_ctrl_sequence_type_and_kernel_sender() {
        assert_eq!(
            parse_family_id(&family_reply(), TEST_SEQUENCE).expect("family"),
            TEST_FAMILY
        );

        let mut wrong = family_reply();
        wrong.message[8..12].copy_from_slice(&(TEST_SEQUENCE + 1).to_ne_bytes());
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        wrong.message[4..6].copy_from_slice(&TEST_FAMILY.to_ne_bytes());
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        wrong.message[16] = CTRL_CMD_GETFAMILY;
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());

        wrong = family_reply();
        wrong.sender = SocketAddr::new(1, 0);
        assert!(parse_family_id(&wrong, TEST_SEQUENCE).is_err());
    }

    #[test]
    fn malformed_netlink_lengths_fail_closed() {
        assert!(netlink_frames(&[0; 4]).is_err());
        let mut frame = vec![0_u8; NLMSG_HEADER_LEN];
        frame[0..4].copy_from_slice(&2_u32.to_ne_bytes());
        assert!(netlink_frames(&frame).is_err());
    }
}
