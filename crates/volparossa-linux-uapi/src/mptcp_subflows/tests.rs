use super::*;

fn address(value: &str) -> [u8; SOCKADDR_STORAGE_BYTES] {
    let address: SocketAddr = value.parse().expect("fixture socket address");
    let mut bytes = [0; SOCKADDR_STORAGE_BYTES];
    bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
    match address {
        SocketAddr::V4(address) => {
            bytes[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            bytes[4..8].copy_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            bytes[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            bytes[4..8].copy_from_slice(&address.flowinfo().to_be_bytes());
            bytes[8..24].copy_from_slice(&address.ip().octets());
            bytes[24..28].copy_from_slice(&address.scope_id().to_ne_bytes());
        }
    }
    bytes
}

fn fixture() -> (
    RawFullInfo,
    [RawSubflowInfo; 2],
    [[u8; TCP_INFO_PREFIX_BYTES]; 2],
) {
    let mut raw = RawFullInfo {
        size_tcpinfo_kernel: 248,
        size_tcpinfo_user: TCP_INFO_PREFIX_BYTES as u32,
        size_sfinfo_kernel: mem::size_of::<RawSubflowInfo>() as u32,
        size_sfinfo_user: mem::size_of::<RawSubflowInfo>() as u32,
        num_subflows: 2,
        size_arrays_user: 2,
        ..RawFullInfo::default()
    };
    raw.mptcp_info.mptcpi_flags = MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED;
    let addresses = [
        RawSubflowInfo {
            id: 19,
            local: address("[fe80::1%7]:50123"),
            remote: address("[fe80::2%7]:443"),
            ..RawSubflowInfo::EMPTY
        },
        RawSubflowInfo {
            id: 4,
            local: address("192.0.2.1:50124"),
            remote: address("192.0.2.2:443"),
            ..RawSubflowInfo::EMPTY
        },
    ];
    let mut metrics = [[0; TCP_INFO_PREFIX_BYTES]; 2];
    for tcp in &mut metrics {
        tcp[0] = 1;
        tcp[32..36].copy_from_slice(&3_u32.to_ne_bytes());
        tcp[68..72].copy_from_slice(&12345_u32.to_ne_bytes());
        tcp[100..104].copy_from_slice(&17_u32.to_ne_bytes());
        tcp[120..128].copy_from_slice(&(u64::from(u32::MAX) + 23).to_ne_bytes());
        tcp[128..136].copy_from_slice(&345_u64.to_ne_bytes());
        tcp[156..160].copy_from_slice(&71_u32.to_ne_bytes());
    }
    (raw, addresses, metrics)
}

#[test]
fn full_info_abi_preserves_paired_kernel_ids_tuples_and_tcp_units() {
    assert_eq!(mem::size_of::<RawSubflowInfo>(), 264);
    assert_eq!(mem::align_of::<RawSubflowInfo>(), 8);
    assert_eq!(mem::offset_of!(RawSubflowInfo, local), 8);
    assert_eq!(mem::offset_of!(RawSubflowInfo, remote), 136);
    assert_eq!(mem::size_of::<RawFullInfo>(), 136);
    assert_eq!(mem::offset_of!(RawFullInfo, subflow_info), 24);
    assert_eq!(mem::offset_of!(RawFullInfo, tcp_info), 32);
    assert_eq!(mem::offset_of!(RawFullInfo, mptcp_info), 40);
    let (raw, addresses, metrics) = fixture();
    let result = decode(&raw, 136, &addresses, &metrics).expect("complete snapshot");
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].subflow_id, 4);
    assert_eq!(result[0].local, "192.0.2.1:50124".parse().unwrap());
    assert_eq!(result[0].remote, "192.0.2.2:443".parse().unwrap());
    assert_eq!(result[1].subflow_id, 19);
    assert_eq!(result[1].local, "[fe80::1%7]:50123".parse().unwrap());
    assert_eq!(result[1].remote, "[fe80::2%7]:443".parse().unwrap());
    for item in result {
        assert_eq!(item.tcp_state, 1);
        assert_eq!(item.bytes_acked, u64::from(u32::MAX) + 23);
        assert_eq!(item.bytes_received, 345);
        assert_eq!(item.lost_packets, 3);
        assert_eq!(item.total_retransmissions, 17);
        assert_eq!(item.data_segments_sent, 71);
        assert_eq!(item.smoothed_rtt_us, 12345);
    }
}

#[test]
fn full_info_rejects_incomplete_ambiguous_or_unnegotiated_observations() {
    assert!(allocation_bound(0).is_err());
    assert!(allocation_bound(usize::MAX).is_err());
    assert!(allocation_bound(MAX_OBSERVATION_BYTES / 424 + 1).is_err());
    assert_eq!(allocation_bound(8).unwrap(), 8);
    for change in [
        |raw: &mut RawFullInfo| raw.size_tcpinfo_kernel = 104,
        |raw: &mut RawFullInfo| raw.size_tcpinfo_user = 159,
        |raw: &mut RawFullInfo| raw.size_sfinfo_kernel = 263,
        |raw: &mut RawFullInfo| raw.size_sfinfo_user = 263,
        |raw: &mut RawFullInfo| raw.size_arrays_user = 1,
        |raw: &mut RawFullInfo| raw.num_subflows = 0,
        |raw: &mut RawFullInfo| raw.num_subflows = 3,
        |raw: &mut RawFullInfo| raw.mptcp_info.mptcpi_flags = 0,
        |raw: &mut RawFullInfo| raw.mptcp_info.mptcpi_flags |= MPTCP_INFO_FLAG_FALLBACK,
    ] {
        let (mut raw, addresses, metrics) = fixture();
        change(&mut raw);
        assert!(decode(&raw, 136, &addresses, &metrics).is_err());
    }
    let (raw, addresses, metrics) = fixture();
    assert!(decode(&raw, 135, &addresses, &metrics).is_err());
    assert!(decode(&raw, 136, &addresses, &metrics[..1]).is_err());
    for change in [
        |items: &mut [RawSubflowInfo; 2]| items[1].id = items[0].id,
        |items: &mut [RawSubflowInfo; 2]| {
            items[1].local = items[0].local;
            items[1].remote = items[0].remote;
        },
        |items: &mut [RawSubflowInfo; 2]| items[1].local[0..2].fill(0),
        |items: &mut [RawSubflowInfo; 2]| items[1].local[2..4].fill(0),
        |items: &mut [RawSubflowInfo; 2]| items[1].remote = address("0.0.0.0:443"),
        |items: &mut [RawSubflowInfo; 2]| items[1].remote = address("224.0.0.1:443"),
        |items: &mut [RawSubflowInfo; 2]| items[1].remote = address("[::1]:443"),
    ] {
        let mut changed = addresses;
        change(&mut changed);
        assert!(decode(&raw, 136, &changed, &metrics).is_err());
    }
    let mut changed = metrics;
    changed[1][0] = 13;
    assert!(decode(&raw, 136, &addresses, &changed).is_err());
}
