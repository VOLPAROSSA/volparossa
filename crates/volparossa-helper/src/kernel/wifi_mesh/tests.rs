//! Pure UAPI contracts. These tests must never open a radio socket or mutate host networking.

use super::super::{NLA_F_NESTED, attributes};
use super::netlink::{
    INTERFACE_COMBINATIONS, MAC, STA_INFO, SUPPORTED_IFTYPES, WIPHY_BANDS, field, nested,
    number_field, required,
};
use super::*;

pub(super) fn config() -> WifiMeshConfig {
    WifiMeshConfig {
        parent_interface: "wlan0".into(),
        mesh_id: b"volparossa-test".to_vec(),
        frequency_mhz: 2412,
        local_address: vec![192, 168, 247, 1],
        prefix_len: 24,
        maximum_peers: 8,
        runtime_id: [0x31; 16],
    }
}

#[test]
fn wifi_mesh_bounded_geometry_and_socket_owned_no_forward_join() {
    let config = config();
    validate_config(&config).unwrap();
    let name = interface_name(&config.runtime_id);
    assert_eq!(name, "vw3131313131313");
    assert_eq!(name.len(), 15);
    for invalid in [
        WifiMeshConfig {
            runtime_id: [0; 16],
            ..config.clone()
        },
        WifiMeshConfig {
            parent_interface: "../wlan0".into(),
            ..config.clone()
        },
        WifiMeshConfig {
            mesh_id: vec![b'x'; 33],
            ..config.clone()
        },
        WifiMeshConfig {
            mesh_id: b"bad\nmesh".to_vec(),
            ..config.clone()
        },
        WifiMeshConfig {
            frequency_mhz: 2413,
            ..config.clone()
        },
        WifiMeshConfig {
            maximum_peers: 33,
            ..config.clone()
        },
    ] {
        assert!(validate_config(&invalid).is_err());
    }
    let encoded = create_attributes(0, &name).unwrap();
    let attrs = attributes(&encoded).unwrap();
    assert_eq!(number_field(&attrs, WIPHY).unwrap(), 0);
    assert_eq!(number_field(&attrs, IFTYPE).unwrap(), MESH_POINT);
    assert!(required(&attrs, SOCKET_OWNER).unwrap().is_empty());
    assert!(
        field(&attrs, MESH_ID).unwrap().is_none(),
        "no implicit join while bringing link up"
    );
    let encoded = join_attributes(7, &config).unwrap();
    let attrs = attributes(&encoded).unwrap();
    assert_eq!(number_field(&attrs, IFINDEX).unwrap(), 7);
    assert_eq!(number_field(&attrs, CHANNEL_WIDTH).unwrap(), 1);
    assert_eq!(number_field(&attrs, CENTER_FREQ1).unwrap(), 2412);
    assert_eq!(required(&attrs, MESH_ID).unwrap(), config.mesh_id);
    let mesh = nested(&attrs, MESH_CONFIG).unwrap();
    for key in [14, 17, 19] {
        assert_eq!(required(&mesh, key).unwrap(), [0]);
    }
    assert_eq!(required(&mesh, 6).unwrap(), [1]);
    assert_eq!(required(&mesh, 4).unwrap(), 8_u16.to_ne_bytes());
    observation::verify_mesh_configuration(&encoded, &config).unwrap();
}

fn nest(target: &mut Vec<u8>, kind: u16, value: &[u8]) {
    push_attribute(target, kind | NLA_F_NESTED, value).unwrap();
}

fn radio_record(forbidden: Option<u16>) -> Vec<u8> {
    let mut record = Vec::new();
    push_attribute(&mut record, WIPHY, &0_u32.to_ne_bytes()).unwrap();
    let mut types = Vec::new();
    for kind in [2, 7] {
        push_attribute(&mut types, kind, &[]).unwrap();
    }
    nest(&mut record, SUPPORTED_IFTYPES, &types);
    let mut frequency = Vec::new();
    push_attribute(&mut frequency, 1, &2412_u32.to_ne_bytes()).unwrap();
    if let Some(kind) = forbidden {
        push_attribute(&mut frequency, kind, &[]).unwrap();
    }
    let mut frequencies = Vec::new();
    nest(&mut frequencies, 1, &frequency);
    let mut band = Vec::new();
    nest(&mut band, 1, &frequencies);
    let mut bands = Vec::new();
    nest(&mut bands, 1, &band);
    nest(&mut record, WIPHY_BANDS, &bands);
    let mut limit = Vec::new();
    push_attribute(&mut limit, 1, &2_u32.to_ne_bytes()).unwrap();
    nest(&mut limit, 2, &types);
    let mut limits = Vec::new();
    nest(&mut limits, 1, &limit);
    let mut combination = Vec::new();
    nest(&mut combination, 1, &limits);
    push_attribute(&mut combination, 2, &2_u32.to_ne_bytes()).unwrap();
    push_attribute(&mut combination, 4, &1_u32.to_ne_bytes()).unwrap();
    let mut combinations = Vec::new();
    nest(&mut combinations, 1, &combination);
    nest(&mut record, INTERFACE_COMBINATIONS, &combinations);
    record
}

#[test]
fn wifi_mesh_radio_admission_preserves_managed_channel_and_regulatory_limits() {
    let radio = Radio::parse(&[radio_record(None)], 0, 2412).unwrap();
    radio.admit(&[], 2412).unwrap();
    let station = |frequency| Interface {
        wiphy: 0,
        index: Some(3),
        name: Some("wlan0".into()),
        kind: 2,
        frequency,
    };
    radio.admit(&[station(Some(2412))], 2412).unwrap();
    assert!(radio.admit(&[station(Some(2437))], 2412).is_err());
    assert!(radio.admit(&[station(None)], 2412).is_err());
    assert!(
        radio
            .admit(&[station(Some(2412)), station(Some(2412))], 2412)
            .is_err()
    );
    for forbidden in [2, 3, 5, 16] {
        assert!(Radio::parse(&[radio_record(Some(forbidden))], 0, 2412).is_err());
    }
    assert!(Radio::parse(&[radio_record(None)], 1, 2412).is_err());
    assert!(Radio::parse(&[radio_record(None)], 0, 2437).is_err());
}

fn peer_record(state: u8) -> Vec<u8> {
    let mut record = index_attributes(7).unwrap();
    push_attribute(&mut record, MAC, &[2, 1, 2, 3, 4, 5]).unwrap();
    let mut info = Vec::new();
    push_attribute(&mut info, 6, &[state]).unwrap();
    push_attribute(&mut info, 23, &9_000_000_000_u64.to_ne_bytes()).unwrap();
    push_attribute(&mut info, 24, &8_000_000_000_u64.to_ne_bytes()).unwrap();
    push_attribute(&mut info, 9, &41_u32.to_ne_bytes()).unwrap();
    push_attribute(&mut info, 10, &42_u32.to_ne_bytes()).unwrap();
    nest(&mut record, STA_INFO, &info);
    record
}

#[test]
fn wifi_mesh_peer_snapshot_requires_kernel_established_state_and_real_bounded_counters() {
    assert_eq!(observation::peers(&[], 7, 8).unwrap(), []);
    let peers = observation::peers(&[peer_record(4)], 7, 8).unwrap();
    assert!(peers[0].established);
    assert_eq!(peers[0].rx_bytes, 9_000_000_000);
    assert_eq!(peers[0].tx_bytes, 8_000_000_000);
    assert_eq!(peers[0].rx_packets, 41);
    assert_eq!(peers[0].tx_packets, 42);
    assert!(!observation::peers(&[peer_record(1)], 7, 8).unwrap()[0].established);
    assert!(observation::peers(&[peer_record(7)], 7, 8).is_err());
    assert!(observation::peers(&[peer_record(4)], 8, 8).is_err());
    assert!(observation::peers(&[peer_record(4), peer_record(4)], 7, 8).is_err());
    assert!(observation::peers(&[peer_record(4)], 7, 0).is_err());
}

#[test]
fn wifi_mesh_config_readback_handles_kernel_nested_ifindex_collision() {
    let mut mesh = Vec::new();
    push_attribute(&mut mesh, IFINDEX, &7_u32.to_ne_bytes()).unwrap();
    push_attribute(&mut mesh, 3, &100_u16.to_ne_bytes()).unwrap(); // HOLDING_TIMEOUT, same tag.
    push_attribute(&mut mesh, 4, &8_u16.to_ne_bytes()).unwrap();
    for key in [14, 17, 19] {
        push_attribute(&mut mesh, key, &[0]).unwrap();
    }
    let mut response = Vec::new();
    nest(&mut response, MESH_CONFIG, &mesh);
    observation::verify_mesh_configuration(&response, &config()).unwrap();
    push_attribute(&mut mesh, 19, &[1]).unwrap();
    let mut duplicate = Vec::new();
    nest(&mut duplicate, MESH_CONFIG, &mesh);
    assert!(observation::verify_mesh_configuration(&duplicate, &config()).is_err());
}
