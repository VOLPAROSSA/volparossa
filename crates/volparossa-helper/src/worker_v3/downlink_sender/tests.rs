//! Real sender-backend proof, not an end-to-end Client/Relay/Exit application fixture.

use super::{DownlinkGate, DownlinkQueue, HardDeadline};
use crate::{
    kernel::{NamespaceKernel, PreparedWireguardKernelProof, WireguardV3PeerConfiguration},
    lease_spec::WireguardLeaseSpec,
    ownership_journal::DurableWireguardResource,
};
use rustix::time::{ClockId, clock_gettime};
use std::{
    env,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use volparossa_routing::{ContextRole, WireguardRole};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const TEST: &str = "worker_v3::downlink_sender::tests::disposable_owned_wireguard_sender_closes_shapes_expires_and_cleans";
const ROLE: &str = "VOLPAROSSA_DOWNLINK_SENDER_TEST_ROLE";
const ORIGINAL: &str = "VOLPAROSSA_DOWNLINK_SENDER_TEST_PARENT";
const CONTEXT: [u8; 16] = [0x61; 16];

fn deadline() -> HardDeadline {
    HardDeadline::after(Duration::from_secs(2)).unwrap()
}
fn short_deadline() -> HardDeadline {
    HardDeadline::after(Duration::from_millis(300)).unwrap()
}
fn namespace() -> String {
    std::fs::read_link("/proc/thread-self/ns/net")
        .unwrap()
        .to_string_lossy()
        .into_owned()
}
fn ip(args: &[&str]) {
    let out = Command::new("/usr/bin/ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "disposable ip: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn line(reader: &mut impl BufRead, prefix: &str) -> String {
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0, "missing {prefix}");
        if let Some((_, value)) = line.split_once(prefix) {
            return value.trim().into();
        }
    }
}
fn resource(sender: bool) -> DurableWireguardResource {
    let (context_role, role) = if sender {
        (ContextRole::Exit, WireguardRole::Exit)
    } else {
        (ContextRole::Relay, WireguardRole::RelayExit)
    };
    let spec = WireguardLeaseSpec::derive(CONTEXT, context_role, 1, role as i32).unwrap();
    let alias = format!(
        "volparossa:wireguard:ownership-v1:{}:{}",
        spec.interface(),
        "ab".repeat(32)
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    DurableWireguardResource::from_authenticated_worker_binding(
        CONTEXT,
        context_role,
        1,
        role as i32,
        alias,
        now + 30,
        now + 60,
    )
    .unwrap()
}
fn key(sender: bool) -> Zeroizing<[u8; 32]> {
    Zeroizing::new([if sender { 0x14 } else { 0x13 }; 32])
}
fn public(sender: bool) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*key(sender))).as_bytes()
}
fn prepare(
    sender: bool,
    kernel: &mut NamespaceKernel,
    owner: &DurableWireguardResource,
) -> PreparedWireguardKernelProof {
    ip(&["link", "add", owner.interface(), "type", "wireguard"]);
    ip(&[
        "link",
        "set",
        owner.interface(),
        "alias",
        owner.ownership_alias(),
    ]);
    kernel
        .prepare_wireguard_v3(owner, &key(sender), public(sender), deadline())
        .unwrap()
}
fn activate(
    sender: bool,
    kernel: &mut NamespaceKernel,
    owner: &DurableWireguardResource,
    proof: PreparedWireguardKernelProof,
    remote: u16,
) {
    let endpoint: SocketAddr = format!("10.248.70.{}:{remote}", if sender { 2 } else { 1 })
        .parse()
        .unwrap();
    kernel
        .activate_wireguard_v3(
            owner,
            proof.public_key,
            proof.listen_port,
            &WireguardV3PeerConfiguration {
                public_key: public(!sender),
                endpoint,
                allowed_address: owner.peer_address(),
                allowed_prefix_length: 128,
                persistent_keepalive_seconds: 0,
            },
            deadline(),
        )
        .unwrap();
}
fn open(gate: &mut DownlinkGate, duration: Duration) {
    let now = clock_gettime(ClockId::Boottime);
    let boot =
        u64::try_from(now.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(now.tv_nsec).unwrap();
    let unix = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    gate.open(
        unix + u64::try_from(duration.as_millis()).unwrap(),
        boot + u64::try_from(duration.as_nanos()).unwrap(),
        short_deadline(),
    )
    .unwrap();
}

#[test]
fn disposable_owned_wireguard_sender_closes_shapes_expires_and_cleans() {
    match env::var(ROLE).ok().as_deref() {
        Some("sender") => sender(),
        Some("receiver") => receiver(),
        _ => {
            let original = namespace();
            let out = Command::new("/usr/bin/timeout")
                .args([
                    "--kill-after=2s",
                    "20s",
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                ])
                .arg(env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(ROLE, "sender")
                .env(ORIGINAL, &original)
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            assert_eq!(namespace(), original);
            if out.status.code() == Some(1)
                && out.stdout.is_empty()
                && matches!(
                    out.stderr.as_slice(),
                    b"unshare: unshare failed: Operation not permitted\n"
                        | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                        | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
                )
            {
                assert_ne!(
                    env::var("VOLPAROSSA_REQUIRE_DOWNLINK_SENDER_PROOF")
                        .ok()
                        .as_deref(),
                    Some("1")
                );
                eprintln!("SKIP sender backend: pre-child namespace denial");
                return;
            }
            assert!(
                out.status.success(),
                "real sender failure\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            print!("{}", String::from_utf8_lossy(&out.stdout));
        }
    }
}

fn receiver() {
    assert_ne!(namespace(), env::var(ORIGINAL).unwrap());
    println!("PEER_READY");
    std::io::stdout().flush().unwrap();
    let mut input = std::io::stdin().lock();
    let mut request = String::new();
    input.read_line(&mut request).unwrap();
    let remote: u16 = request.trim().parse().unwrap();
    ip(&["link", "set", "lo", "up"]);
    ip(&["addr", "add", "10.248.70.2/30", "dev", "dsp"]);
    ip(&["link", "set", "dsp", "up"]);
    let mut kernel = NamespaceKernel::connect(deadline()).unwrap();
    let owner = resource(false);
    let proof = prepare(false, &mut kernel, &owner);
    // This is a synthetic Relay-side forwarded-inner UDP sink. It is not a normal direct Client→Exit route.
    let forwarded = resource(true).peer_address();
    ip(&[
        "-6",
        "addr",
        "add",
        &format!("{forwarded}/128"),
        "dev",
        "lo",
    ]);
    activate(false, &mut kernel, &owner, proof, remote);
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(forwarded), 28081)).unwrap();
    println!("PEER_PORT {}", proof.listen_port);
    std::io::stdout().flush().unwrap();
    let mut buffer = [0; 2048];
    loop {
        let (length, remote) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(length, 1000);
        assert!(buffer[..length].iter().all(|b| *b == 0x73));
        socket.send_to(&buffer[..length], remote).unwrap();
    }
}

fn exchange(socket: &UdpSocket, duration: Duration) -> u64 {
    let end = Instant::now() + duration;
    let mut count = 0;
    let mut buf = [0; 2048];
    while Instant::now() < end {
        // UDP must remain a usable socket while closed; a policy EPERM would break native transport.
        assert_eq!(socket.send(&[0x73; 1000]).unwrap(), 1000);
        match socket.recv(&mut buf) {
            Ok(length) => {
                assert_eq!(length, 1000);
                assert!(buf[..length].iter().all(|b| *b == 0x73));
                count += 1;
            }
            Err(error) => assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )),
        }
    }
    count
}

fn sender() {
    assert_ne!(namespace(), env::var(ORIGINAL).unwrap());
    let mut peer = ChildGuard(
        Command::new("/usr/bin/unshare")
            .arg("--net")
            .arg(env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(ROLE, "receiver")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(peer.0.stdout.take().unwrap());
    line(&mut output, "PEER_READY");
    ip(&["link", "add", "dss", "type", "veth", "peer", "name", "dsp"]);
    ip(&["link", "set", "dsp", "netns", &peer.0.id().to_string()]);
    ip(&["addr", "add", "10.248.70.1/30", "dev", "dss"]);
    ip(&["link", "set", "dss", "up"]);
    ip(&["link", "set", "lo", "up"]);
    let mut kernel = NamespaceKernel::connect(deadline()).unwrap();
    let owner = resource(true);
    let proof = prepare(true, &mut kernel, &owner);
    let mut gate = DownlinkGate::new(CONTEXT, &owner, proof.ifindex).unwrap();
    gate.close(deadline()).unwrap();
    let mut queue = DownlinkQueue::install(&owner, proof.ifindex, deadline())
        .unwrap_or_else(|failure| panic!("queue install: {:?}", failure.source));
    writeln!(peer.0.stdin.as_mut().unwrap(), "{}", proof.listen_port).unwrap();
    let remote = line(&mut output, "PEER_PORT ").parse().unwrap();
    activate(true, &mut kernel, &owner, proof, remote);
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(owner.local_address()), 0)).unwrap();
    socket
        .connect(SocketAddr::new(IpAddr::V6(owner.peer_address()), 28081))
        .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    assert_eq!(exchange(&socket, Duration::from_millis(150)), 0);
    assert_eq!(queue.inspect(deadline()).unwrap().bytes, 0);
    queue.set_rate(32_000, 2048, deadline()).unwrap();
    open(&mut gate, Duration::from_secs(2));
    let received = exchange(&socket, Duration::from_secs(1));
    let counters = queue.inspect(deadline()).unwrap();
    assert!(received >= 5, "real encrypted echoes: {received}");
    assert!(
        (5000..=36_000).contains(&counters.bytes),
        "finite sender counters: {counters:?}"
    );
    assert!(counters.overlimits > 0);
    // No refresh: the kernel singleton expires independently of this userspace process.
    let _ = exchange(&socket, Duration::from_millis(1500));
    let expired = queue.inspect(deadline()).unwrap();
    assert_eq!(exchange(&socket, Duration::from_millis(250)), 0);
    assert_eq!(queue.inspect(deadline()).unwrap().bytes, expired.bytes);
    gate.close(deadline()).unwrap();
    assert_eq!(exchange(&socket, Duration::from_millis(100)), 0);
    // One actual UDP GSO write represents eight datagrams. The queue's MTU-sized token
    // bucket forces segmentation before charging WireGuard overhead per skb.
    queue.set_rate(256_000, 32768, deadline()).unwrap();
    open(&mut gate, Duration::from_secs(2));
    let before_gso = queue.inspect(deadline()).unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::UdpGsoSegment, &1000).unwrap();
    assert_eq!(socket.send(&[0x73; 8000]).unwrap(), 8000);
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::UdpGsoSegment, &0).unwrap();
    let mut gso_echoes = 0;
    let mut buffer = [0; 2048];
    let end = Instant::now() + Duration::from_secs(1);
    while gso_echoes < 8 && Instant::now() < end {
        if let Ok(length) = socket.recv(&mut buffer) {
            assert_eq!(length, 1000);
            assert!(buffer[..length].iter().all(|b| *b == 0x73));
            gso_echoes += 1;
        }
    }
    assert_eq!(gso_echoes, 8);
    let after_gso = queue.inspect(deadline()).unwrap();
    assert_eq!(after_gso.packets - before_gso.packets, 8);
    assert_eq!(after_gso.bytes - before_gso.bytes, 8 * 1048);
    gate.close(deadline()).unwrap();
    queue.remove(deadline()).unwrap();
    queue.remove(deadline()).unwrap();
    gate.remove(deadline()).unwrap();
    gate.remove(deadline()).unwrap();
    // Simulate lost in-memory gate ownership while the namespace remains pinned. The
    // dead-worker path must refuse removal before exact link absence, then recover only
    // the authenticated context/path marker and retire the persistent table idempotently.
    gate.close(deadline()).unwrap();
    assert!(DownlinkGate::cleanup_after_exact_link_absence(CONTEXT, &owner, deadline()).is_err());
    kernel
        .delete_exact_owned_wireguard_v3(&owner, deadline())
        .unwrap();
    DownlinkGate::cleanup_after_exact_link_absence(CONTEXT, &owner, deadline()).unwrap();
    DownlinkGate::cleanup_after_exact_link_absence(CONTEXT, &owner, deadline()).unwrap();
    gate.remove(deadline()).unwrap();
    println!(
        "SENDER_PROOF echoes={received} inner_bytes={} queued_bound={} gso_echoes={gso_echoes} no_refresh_closed=true exact_cleanup=true",
        counters.bytes,
        queue.maximum_queued_bytes()
    );
}
