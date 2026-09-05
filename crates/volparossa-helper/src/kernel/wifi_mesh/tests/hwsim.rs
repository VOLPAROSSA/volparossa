//! Opt-in backend proof, invoked only by the guarded disposable-KVM shell fixture.

use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::super::{HardDeadline, MeshOwner, MeshPeer, install};

const ROUNDS: u32 = 128;
const PAYLOAD: usize = 1024;
const PORT: u16 = 44123;

fn deadline() -> HardDeadline {
    HardDeadline::after(Duration::from_secs(8)).expect("bounded kernel transaction")
}

fn peer(owner: &mut MeshOwner) -> Option<MeshPeer> {
    let snapshot = owner
        .inspect(deadline())
        .expect("inspect exact joined mesh");
    assert!(snapshot.joined);
    assert_eq!(snapshot.frequency_mhz, 2412);
    snapshot.peers.into_iter().find(|value| value.established)
}

fn packet(sequence: u32, response: bool) -> Vec<u8> {
    let mut bytes = vec![if response { 0xb9 } else { 0x63 }; PAYLOAD];
    bytes[..4].copy_from_slice(&sequence.to_be_bytes());
    bytes
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
#[ignore = "requires the guarded disposable KVM hwsim fixture; never run on a development host"]
fn disposable_hwsim_mesh_owner() {
    assert_eq!(
        std::env::var("VOLPAROSSA_WIFI_MESH_KVM").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::fs::read_to_string("/etc/hostname").unwrap().trim(),
        "volparossa-alpha"
    );
    assert_eq!(
        std::fs::read_to_string("/run/volparossa-wifi-mesh-kvm")
            .unwrap()
            .trim(),
        "hwsim-only"
    );
    let role = std::env::var("VOLPAROSSA_WIFI_MESH_ROLE").expect("explicit fixture role");
    assert!(matches!(role.as_str(), "a" | "b" | "crash"));
    let parent = std::env::var("VOLPAROSSA_WIFI_MESH_PARENT").expect("exact hwsim parent");
    let driver = std::fs::canonicalize(format!("/sys/class/net/{parent}/device/subsystem"))
        .expect("hwsim virtual device class");
    assert_eq!(
        driver.file_name().and_then(|value| value.to_str()),
        Some("mac80211_hwsim")
    );
    let is_b = role == "b";
    let address = Ipv4Addr::new(192, 168, 247, if is_b { 2 } else { 1 });
    let remote = SocketAddrV4::new(Ipv4Addr::new(192, 168, 247, if is_b { 1 } else { 2 }), PORT);
    let socket = UdpSocket::bind(SocketAddrV4::new(address, PORT));
    // Bind only after the actual kernel provider assigns the local address below.
    assert!(socket.is_err());
    let mut config = super::config();
    config.parent_interface = parent;
    config.local_address = address.octets().to_vec();
    config.runtime_id = [if is_b {
        0x52
    } else if role == "crash" {
        0x53
    } else {
        0x51
    }; 16];
    let mut owner = install(config, deadline()).expect("real nl80211 create/address/join");
    let result = if role == "crash" {
        println!(
            "MESH_CRASH_READY {{\"interface\":\"{}\",\"ifindex\":{}}}",
            owner.interface_name(),
            owner.ifindex()
        );
        std::io::stdout().flush().unwrap();
        // Parent fixture kills this exact process and observes socket-owned kernel auto-deletion.
        std::thread::sleep(Duration::from_secs(60));
        Err("fixture did not terminate the socket owner".to_owned())
    } else {
        exchange(&mut owner, address, remote, is_b, &role)
    };
    let existed = owner.remove(deadline()).expect("exact mesh leave/delete");
    assert!(existed);
    assert!(!owner.remove(deadline()).expect("idempotent retirement"));
    result.expect("bidirectional real mesh UDP");
    println!("MESH_REMOVED {{\"role\":\"{role}\",\"idempotent\":true}}");
}

fn exchange(
    owner: &mut MeshOwner,
    address: Ipv4Addr,
    remote: SocketAddrV4,
    is_b: bool,
    role: &str,
) -> Result<(), String> {
    let socket =
        UdpSocket::bind(SocketAddrV4::new(address, PORT)).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|error| error.to_string())?;
    socket.connect(remote).map_err(|error| error.to_string())?;
    let expires = Instant::now() + Duration::from_secs(20);
    let before = loop {
        if let Some(peer) = peer(owner) {
            break peer;
        }
        if Instant::now() >= expires {
            return Err("no kernel ESTAB peer within 20 seconds".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut sent = Vec::with_capacity(PAYLOAD * ROUNDS as usize);
    let mut received = Vec::with_capacity(PAYLOAD * ROUNDS as usize);
    let mut buffer = [0_u8; PAYLOAD + 1];
    for sequence in 0..ROUNDS {
        if Instant::now() >= expires + Duration::from_secs(15) {
            return Err("whole peering and UDP stage exceeded 35 seconds".into());
        }
        let outgoing = packet(sequence, is_b);
        if !is_b {
            socket.send(&outgoing).map_err(|error| error.to_string())?;
        }
        let size = socket
            .recv(&mut buffer)
            .map_err(|error| error.to_string())?;
        if buffer[..size] != packet(sequence, !is_b) {
            return Err("actual payload/sequence mismatch".into());
        }
        received.extend_from_slice(&buffer[..size]);
        if is_b {
            socket.send(&outgoing).map_err(|error| error.to_string())?;
        }
        sent.extend_from_slice(&outgoing);
    }
    if is_b {
        let size = socket
            .recv(&mut buffer)
            .map_err(|error| error.to_string())?;
        if &buffer[..size] != b"snapshot-ready" {
            return Err("missing snapshot synchronization".into());
        }
    }
    let after = peer(owner).ok_or("established peer disappeared before counters")?;
    if after.rx_bytes <= before.rx_bytes
        || after.tx_bytes <= before.tx_bytes
        || after.rx_packets <= before.rx_packets
        || after.tx_packets <= before.tx_packets
    {
        return Err("kernel peer counters did not increase in both directions".into());
    }
    println!(
        "MESH_RESULT {{\"role\":\"{role}\",\"interface\":\"{}\",\"ifindex\":{},\"wiphy\":{},\"joined\":true,\"established\":true,\"sent_bytes\":{},\"received_bytes\":{},\"sent_sha256\":\"{}\",\"received_sha256\":\"{}\",\"rx_bytes_delta\":{},\"tx_bytes_delta\":{},\"rx_packets_delta\":{},\"tx_packets_delta\":{}}}",
        owner.interface_name(),
        owner.ifindex(),
        owner.wiphy(),
        sent.len(),
        received.len(),
        hash(&sent),
        hash(&received),
        after.rx_bytes - before.rx_bytes,
        after.tx_bytes - before.tx_bytes,
        after.rx_packets - before.rx_packets,
        after.tx_packets - before.tx_packets
    );
    if is_b {
        socket
            .send(b"snapshot-complete")
            .map_err(|error| error.to_string())?;
        std::thread::sleep(Duration::from_millis(200));
    } else {
        socket
            .send(b"snapshot-ready")
            .map_err(|error| error.to_string())?;
        let size = socket
            .recv(&mut buffer)
            .map_err(|error| error.to_string())?;
        if &buffer[..size] != b"snapshot-complete" {
            return Err("peer snapshot incomplete".into());
        }
    }
    Ok(())
}
