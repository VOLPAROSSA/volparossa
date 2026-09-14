//! Read-only `MPTCP_FULL_INFO` on an already owned socket.
//!
//! Layouts follow Debian 13 Linux 6.12 `include/uapi/linux/{mptcp,tcp}.h` on amd64.
//! The kernel returns paired subflow IDs/addresses and TCP metrics in one socket operation;
//! tuple reuse alone must never identify the lifetime of a subflow.

use std::{
    collections::BTreeSet,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    os::fd::{AsFd, AsRawFd},
};

use super::{
    MPTCP_INFO_FLAG_FALLBACK, MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED, RawMptcpInfo, SOL_MPTCP,
};

const MPTCP_FULL_INFO: libc::c_int = 4;
// This bounds a read-only observation allocation, not kernel endpoint or connection admission.
const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
// Stable tcp_info prefix through tcpi_data_segs_out; later kernel fields are not interpreted.
const TCP_INFO_PREFIX_BYTES: usize = 160;
const SOCKADDR_STORAGE_BYTES: usize = 128;

/// One kernel-identified TCP subflow of a genuinely negotiated MPTCP socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MptcpSubflowInfo {
    /// Kernel-generated subflow lifetime ID, not a VOLPAROSSA path or endpoint ID.
    pub subflow_id: u32,
    /// Exact local TCP tuple, including IPv6 scope where present.
    pub local: SocketAddr,
    /// Exact remote TCP tuple, including IPv6 scope where present.
    pub remote: SocketAddr,
    /// Linux TCP state (1 is ESTABLISHED); a present record need not be established.
    pub tcp_state: u8,
    /// Cumulative TCP octets acknowledged on this subflow, from `tcpi_bytes_acked`.
    /// Includes protected-stream framing; not unique reassembled MPTCP/application goodput.
    pub bytes_acked: u64,
    /// Cumulative TCP octets received on this subflow, from `tcpi_bytes_received`.
    pub bytes_received: u64,
    /// Currently lost packets from `tcpi_lost`: a gauge, not a monotone counter.
    pub lost_packets: u32,
    /// Cumulative retransmitted segments from `tcpi_total_retrans`.
    pub total_retransmissions: u32,
    /// Cumulative outgoing data segments, excluding pure ACKs, from `tcpi_data_segs_out`.
    pub data_segments_sent: u32,
    /// Smoothed RTT in microseconds; zero means no available RTT sample.
    pub smoothed_rtt_us: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct RawSubflowInfo {
    id: u32,
    padding: u32,
    local: [u8; SOCKADDR_STORAGE_BYTES],
    remote: [u8; SOCKADDR_STORAGE_BYTES],
}

impl RawSubflowInfo {
    const EMPTY: Self = Self {
        id: 0,
        padding: 0,
        local: [0; SOCKADDR_STORAGE_BYTES],
        remote: [0; SOCKADDR_STORAGE_BYTES],
    };
}

#[repr(C)]
#[derive(Default)]
struct RawFullInfo {
    size_tcpinfo_kernel: u32,
    size_tcpinfo_user: u32,
    size_sfinfo_kernel: u32,
    size_sfinfo_user: u32,
    num_subflows: u32,
    size_arrays_user: u32,
    subflow_info: u64,
    tcp_info: u64,
    mptcp_info: RawMptcpInfo,
}

/// Observe exact subflow tuples and TCP metrics without opening a socket or changing its state.
///
/// `maximum_subflows` is the caller's authorized observation bound. The combined array allocation
/// is capped at 64 KiB independently of kernel admission. A socket with more records is rejected,
/// never truncated into a misleading complete set. Records are sorted by kernel subflow ID.
///
/// # Errors
/// Returns the original kernel error when unsupported or not an MPTCP socket. Rejects fallback,
/// incomplete negotiation, incompatible/truncated layouts, excessive records, unknown address
/// families, invalid tuples or duplicate IDs/tuples. No partially filled metrics are returned.
pub fn mptcp_subflow_info<F: AsFd>(
    socket: &F,
    maximum_subflows: usize,
) -> io::Result<Vec<MptcpSubflowInfo>> {
    let count = allocation_bound(maximum_subflows)?;
    let mut addresses = vec![RawSubflowInfo::EMPTY; maximum_subflows];
    let mut metrics = vec![[0_u8; TCP_INFO_PREFIX_BYTES]; maximum_subflows];
    let mut raw = RawFullInfo {
        size_tcpinfo_user: TCP_INFO_PREFIX_BYTES as u32,
        size_sfinfo_user: mem::size_of::<RawSubflowInfo>() as u32,
        size_arrays_user: count,
        subflow_info: addresses.as_mut_ptr() as usize as u64,
        tcp_info: metrics.as_mut_ptr() as usize as u64,
        ..RawFullInfo::default()
    };
    let expected_pointers = (raw.subflow_info, raw.tcp_info);
    let mut length = mem::size_of::<RawFullInfo>() as libc::socklen_t;
    // SAFETY: the amd64 repr(C) header matches linux/mptcp.h. Its input prefix and both pointed-to
    // arrays are initialized and remain uniquely borrowed and immovable during getsockopt. Array
    // lengths/strides exactly describe their bounded allocations. No pointer/field from the reply
    // is dereferenced; returned sizes, counts and layouts are validated before decoding bytes.
    let result = unsafe {
        libc::getsockopt(
            socket.as_fd().as_raw_fd(),
            SOL_MPTCP,
            MPTCP_FULL_INFO,
            std::ptr::from_mut(&mut raw).cast(),
            std::ptr::from_mut(&mut length),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if (raw.subflow_info, raw.tcp_info) != expected_pointers {
        return Err(invalid("MPTCP_FULL_INFO changed array pointers"));
    }
    decode(&raw, length as usize, &addresses, &metrics)
}

fn allocation_bound(count: usize) -> io::Result<u32> {
    let bytes = count.checked_mul(mem::size_of::<RawSubflowInfo>() + TCP_INFO_PREFIX_BYTES);
    if count == 0 || bytes.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MPTCP observation bound exceeds buffer budget",
        ));
    }
    u32::try_from(count).map_err(|_| invalid("invalid MPTCP observation count"))
}

fn decode(
    raw: &RawFullInfo,
    length: usize,
    addresses: &[RawSubflowInfo],
    metrics: &[[u8; TCP_INFO_PREFIX_BYTES]],
) -> io::Result<Vec<MptcpSubflowInfo>> {
    let count = raw.num_subflows as usize;
    if length != mem::size_of::<RawFullInfo>()
        || raw.size_tcpinfo_kernel < TCP_INFO_PREFIX_BYTES as u32
        || raw.size_tcpinfo_user != TCP_INFO_PREFIX_BYTES as u32
        || raw.size_sfinfo_kernel != mem::size_of::<RawSubflowInfo>() as u32
        || raw.size_sfinfo_user != mem::size_of::<RawSubflowInfo>() as u32
        || raw.size_arrays_user as usize != addresses.len()
        || addresses.len() != metrics.len()
        || count == 0
        || count > addresses.len()
    {
        return Err(invalid("incomplete or incompatible MPTCP_FULL_INFO layout"));
    }
    if raw.mptcp_info.mptcpi_flags & MPTCP_INFO_FLAG_FALLBACK != 0
        || raw.mptcp_info.mptcpi_flags & MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED == 0
    {
        return Err(invalid("MPTCP_FULL_INFO lacks genuine negotiation"));
    }
    let mut ids = BTreeSet::new();
    let mut tuples = BTreeSet::new();
    let mut result = Vec::with_capacity(count);
    for (address, tcp) in addresses.iter().zip(metrics).take(count) {
        let local = socket_address(&address.local)?;
        let remote = socket_address(&address.remote)?;
        if !ids.insert(address.id)
            || !tuples.insert((local, remote))
            || local.is_ipv4() != remote.is_ipv4()
            || !(1..=12).contains(&tcp[0])
        {
            return Err(invalid("invalid or ambiguous MPTCP subflow identity/state"));
        }
        result.push(MptcpSubflowInfo {
            subflow_id: address.id,
            local,
            remote,
            tcp_state: tcp[0],
            bytes_acked: u64::from_ne_bytes(tcp[120..128].try_into().expect("fixed TCP prefix")),
            bytes_received: u64::from_ne_bytes(tcp[128..136].try_into().expect("fixed TCP prefix")),
            lost_packets: u32::from_ne_bytes(tcp[32..36].try_into().expect("fixed TCP prefix")),
            total_retransmissions: u32::from_ne_bytes(
                tcp[100..104].try_into().expect("fixed TCP prefix"),
            ),
            data_segments_sent: u32::from_ne_bytes(
                tcp[156..160].try_into().expect("fixed TCP prefix"),
            ),
            smoothed_rtt_us: u32::from_ne_bytes(tcp[68..72].try_into().expect("fixed TCP prefix")),
        });
    }
    result.sort_unstable_by_key(|subflow| subflow.subflow_id);
    Ok(result)
}

fn socket_address(bytes: &[u8; SOCKADDR_STORAGE_BYTES]) -> io::Result<SocketAddr> {
    let family = i32::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let address = match family {
        libc::AF_INET => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            port,
        ),
        libc::AF_INET6 => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).expect("fixed IPv6 address")),
            port,
            u32::from_be_bytes(bytes[4..8].try_into().expect("fixed flow info")),
            u32::from_ne_bytes(bytes[24..28].try_into().expect("fixed scope ID")),
        )),
        _ => return Err(invalid("unsupported MPTCP subflow address family")),
    };
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(invalid("invalid MPTCP subflow tuple"));
    }
    Ok(address)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
