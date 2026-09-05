//! Bounded nl80211 UAPI transport. No userspace command execution or channel scanning.

use super::super::{
    GENL_HEADER_LEN, KernelError, NLM_F_REQUEST, NLMSG_ERROR, NLMSG_HEADER_LEN, NetlinkClient,
    attributes, build_netlink_message, frames, parse_ack, read_i32, read_u16, read_u32,
    validate_kernel_header, validate_kernel_sender,
};
use crate::deadline::HardDeadline;

pub(super) const GET_WIPHY: u8 = 1;
pub(super) const NEW_WIPHY: u8 = 3;
pub(super) const GET_INTERFACE: u8 = 5;
pub(super) const NEW_INTERFACE: u8 = 7;
pub(super) const DEL_INTERFACE: u8 = 8;
pub(super) const GET_STATION: u8 = 17;
pub(super) const NEW_STATION: u8 = 19;
pub(super) const GET_MESH_CONFIG: u8 = 28;
pub(super) const JOIN_MESH: u8 = 68;
pub(super) const LEAVE_MESH: u8 = 69;
pub(super) const WIPHY: u16 = 1;
pub(super) const IFINDEX: u16 = 3;
pub(super) const IFNAME: u16 = 4;
pub(super) const IFTYPE: u16 = 5;
pub(super) const MAC: u16 = 6;
pub(super) const STA_INFO: u16 = 21;
pub(super) const WIPHY_BANDS: u16 = 22;
pub(super) const MESH_ID: u16 = 24;
pub(super) const SUPPORTED_IFTYPES: u16 = 32;
pub(super) const MESH_CONFIG: u16 = 35;
pub(super) const WIPHY_FREQ: u16 = 38;
pub(super) const INTERFACE_COMBINATIONS: u16 = 120;
pub(super) const SOFTWARE_IFTYPES: u16 = 121;
pub(super) const CHANNEL_WIDTH: u16 = 159;
pub(super) const CENTER_FREQ1: u16 = 160;
pub(super) const SPLIT_WIPHY_DUMP: u16 = 174;
pub(super) const SOCKET_OWNER: u16 = 204;
pub(super) const MESH_POINT: u32 = 7;
pub(super) const MAX_DUMP_BYTES: usize = 1024 * 1024;
const MAX_DUMP_RECORDS: usize = 512;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_DONE: u16 = 3;

pub(super) type Fields<'a> = Vec<(u16, &'a [u8])>;

pub(super) struct Wireless {
    pub client: NetlinkClient,
    pub family: u16,
}

impl Wireless {
    pub fn connect(deadline: HardDeadline) -> Result<Self, KernelError> {
        let mut client = NetlinkClient::connect(netlink_sys::protocols::NETLINK_GENERIC, deadline)?;
        let family = super::super::resolve_generic_family(&mut client, "nl80211", deadline)?;
        Ok(Self { client, family })
    }

    pub fn ack(
        &mut self,
        command: u8,
        attrs: &[u8],
        deadline: HardDeadline,
    ) -> Result<(), KernelError> {
        self.client
            .request_ack(self.family, 0, &payload(command, attrs), deadline)
    }

    pub fn query(
        &mut self,
        command: u8,
        response: u8,
        attrs: &[u8],
        deadline: HardDeadline,
    ) -> Result<Vec<u8>, KernelError> {
        let (reply, sequence) =
            self.client
                .request_reply(self.family, &payload(command, attrs), deadline)?;
        validate_kernel_sender(&reply.sender)?;
        let messages = frames(&reply.message)?;
        if messages.len() != 1 {
            return Err(KernelError::Malformed);
        }
        let frame = messages[0];
        if read_u16(frame, 4) == Some(NLMSG_ERROR) {
            parse_ack(&reply, sequence, self.family, self.client.local_port_id)?;
            return Err(KernelError::Malformed);
        }
        validate_kernel_header(frame, sequence, self.family, self.client.local_port_id)?;
        let data = generic_attributes(frame, response)?;
        deadline.ensure_remaining()?;
        Ok(data.to_vec())
    }

    pub fn dump(
        &mut self,
        command: u8,
        response: u8,
        attrs: &[u8],
        deadline: HardDeadline,
    ) -> Result<Vec<Vec<u8>>, KernelError> {
        let frames = dump(
            &mut self.client,
            self.family,
            self.family,
            &payload(command, attrs),
            deadline,
        )?;
        frames
            .into_iter()
            .map(|frame| Ok(generic_attributes(&frame, response)?.to_vec()))
            .collect()
    }
}

fn generic_attributes(frame: &[u8], command: u8) -> Result<&[u8], KernelError> {
    if frame.get(NLMSG_HEADER_LEN) != Some(&command)
        || frame.get(NLMSG_HEADER_LEN + 2..NLMSG_HEADER_LEN + GENL_HEADER_LEN) != Some(&[0, 0])
    {
        return Err(KernelError::Malformed);
    }
    frame
        .get(NLMSG_HEADER_LEN + GENL_HEADER_LEN..)
        .ok_or(KernelError::Malformed)
}

fn payload(command: u8, attrs: &[u8]) -> Vec<u8> {
    let mut value = vec![command, 1, 0, 0];
    value.extend_from_slice(attrs);
    value
}

pub(super) fn dump(
    client: &mut NetlinkClient,
    request: u16,
    expected: u16,
    payload: &[u8],
    deadline: HardDeadline,
) -> Result<Vec<Vec<u8>>, KernelError> {
    let sequence = client.next_sequence();
    client.send(
        &build_netlink_message(request, NLM_F_REQUEST | NLM_F_DUMP, sequence, payload)?,
        deadline,
    )?;
    let mut total = 0_usize;
    let mut result = Vec::new();
    loop {
        let reply = client.receive(deadline)?;
        total = total
            .checked_add(reply.message.len())
            .ok_or(KernelError::Malformed)?;
        if total > MAX_DUMP_BYTES {
            return Err(KernelError::Malformed);
        }
        validate_kernel_sender(&reply.sender)?;
        for frame in frames(&reply.message)? {
            let kind = read_u16(frame, 4).ok_or(KernelError::Malformed)?;
            validate_kernel_header(frame, sequence, kind, client.local_port_id)?;
            if read_u16(frame, 6).is_none_or(|flags| flags & NLM_F_DUMP_INTR != 0) {
                return Err(KernelError::Malformed);
            }
            if kind == NLMSG_DONE {
                if read_i32(frame, NLMSG_HEADER_LEN) != Some(0) {
                    return Err(KernelError::Malformed);
                }
                deadline.ensure_remaining()?;
                return Ok(result);
            }
            if kind == NLMSG_ERROR {
                parse_ack(&reply, sequence, request, client.local_port_id)?;
                return Err(KernelError::Malformed);
            }
            if kind != expected || result.len() >= MAX_DUMP_RECORDS {
                return Err(KernelError::Malformed);
            }
            result.push(frame.to_vec());
        }
    }
}

pub(super) fn field<'a>(
    fields: &[(u16, &'a [u8])],
    kind: u16,
) -> Result<Option<&'a [u8]>, KernelError> {
    let mut matches = fields
        .iter()
        .filter(|(key, _)| key & super::super::NLA_TYPE_MASK == kind);
    let value = matches.next().map(|(_, value)| *value);
    if matches.next().is_some() {
        return Err(KernelError::Malformed);
    }
    Ok(value)
}

pub(super) fn required<'a>(fields: &[(u16, &'a [u8])], kind: u16) -> Result<&'a [u8], KernelError> {
    field(fields, kind)?.ok_or(KernelError::Malformed)
}

pub(super) fn number(value: &[u8]) -> Result<u32, KernelError> {
    if value.len() != 4 {
        return Err(KernelError::Malformed);
    }
    read_u32(value, 0).ok_or(KernelError::Malformed)
}

pub(super) fn number_field(fields: &[(u16, &[u8])], kind: u16) -> Result<u32, KernelError> {
    number(required(fields, kind)?)
}

pub(super) fn nested<'a>(fields: &[(u16, &'a [u8])], kind: u16) -> Result<Fields<'a>, KernelError> {
    attributes(required(fields, kind)?)
}
