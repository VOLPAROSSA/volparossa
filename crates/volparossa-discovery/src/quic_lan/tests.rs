//! Actual authenticated QUIC, only inside two disposable user-owned network namespaces.

use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use futures::StreamExt;
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder, identity, ping, swarm::SwarmEvent};
use tokio::sync::mpsc;

const TEST: &str = "quic_lan::tests::dual_listener_quic_reconnect_uses_connected_lan_source";
const PARENT: &str = "VOLPAROSSA_QUIC_TEST_PARENT_NETNS";
const SERVER: &str = "VOLPAROSSA_QUIC_TEST_SERVER";

#[test]
fn private_direct_quic_changes_only_dialer_source_socket() {
    use libp2p::core::{
        Endpoint,
        transport::{DialOpts, PortUse},
    };

    let peer = PeerId::random();
    for address in [
        "/ip4/10.241.11.2/udp/41000/quic-v1".to_owned(),
        format!("/ip6/fd12:3456::2/udp/41000/quic-v1/p2p/{peer}"),
    ] {
        let address = address.parse().unwrap();
        assert_eq!(
            super::dial_options(
                &address,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                }
            )
            .port_use,
            PortUse::New
        );
        assert_eq!(
            super::dial_options(
                &address,
                DialOpts {
                    role: Endpoint::Listener,
                    port_use: PortUse::Reuse,
                }
            )
            .port_use,
            PortUse::Reuse
        );
    }
    for address in [
        "/ip4/43.159.1.1/udp/41000/quic-v1".to_owned(),
        "/ip6/2606:4700::1/udp/41000/quic-v1".to_owned(),
        "/ip4/127.0.0.1/udp/41000/quic-v1".to_owned(),
        "/ip4/10.241.11.2/tcp/41000".to_owned(),
        format!(
            "/ip4/10.241.11.2/udp/41000/quic-v1/p2p/{peer}/p2p-circuit/p2p/{}",
            PeerId::random()
        ),
    ] {
        for role in [Endpoint::Dialer, Endpoint::Listener] {
            for port_use in [PortUse::New, PortUse::Reuse] {
                let actual =
                    super::dial_options(&address.parse().unwrap(), DialOpts { role, port_use });
                assert_eq!(actual.role, role);
                assert_eq!(actual.port_use, port_use);
            }
        }
    }
}

fn namespace() -> std::path::PathBuf {
    fs::read_link("/proc/thread-self/ns/net").unwrap()
}

fn ip(arguments: &[&str]) {
    assert_ne!(namespace(), Path::new(&env::var(PARENT).unwrap()));
    let output = Command::new("/usr/bin/ip")
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ServerOwner(Child);

impl Drop for ServerOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn swarm() -> Swarm<ping::Behaviour> {
    SwarmBuilder::with_existing_identity(identity::Keypair::generate_ed25519())
        .with_tokio()
        .with_other_transport(super::transport)
        .unwrap()
        .with_behaviour(|_| ping::Behaviour::default())
        .unwrap()
        .build()
}

fn address(ip: &str, port: u16) -> Multiaddr {
    format!("/ip4/{ip}/udp/{port}/quic-v1").parse().unwrap()
}

fn announce(line: &str) {
    println!("{line}");
    std::io::stdout().flush().unwrap();
}

fn run_server() {
    assert_ne!(namespace(), Path::new(&env::var(PARENT).unwrap()));
    announce("QUIC_TEST_NAMESPACE_READY");
    let mut command = String::new();
    std::io::stdin().read_line(&mut command).unwrap();
    assert_eq!(command, "start\n");
    ip(&["link", "set", "lo", "up"]);
    ip(&["address", "add", "10.241.11.2/30", "dev", "qpeer"]);
    ip(&["link", "set", "qpeer", "up"]);
    // Test-only reverse route makes a wrong bound source observable on an authenticated
    // connection, instead of merely timing out. This is not a default or Internet uplink.
    ip(&[
        "route",
        "add",
        "43.159.1.1/32",
        "via",
        "10.241.11.1",
        "dev",
        "qpeer",
    ]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut server = swarm();
            for port in 41_000..41_004 {
                server.listen_on(address("10.241.11.2", port)).unwrap();
            }
            let mut listeners = 0;
            loop {
                match server.select_next_some().await {
                    SwarmEvent::NewListenAddr { .. } => {
                        listeners += 1;
                        if listeners == 4 {
                            announce(&format!("QUIC_TEST_PEER {}", server.local_peer_id()));
                        }
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    } => {
                        announce(&format!(
                            "QUIC_TEST_AUTH {peer_id} {}",
                            endpoint.get_remote_address()
                        ));
                    }
                    SwarmEvent::ListenerClosed { reason, .. } => {
                        panic!("server listener closed: {reason:?}")
                    }
                    _ => {}
                }
            }
        });
}

async fn listen(client: &mut Swarm<ping::Behaviour>, ip: &str) {
    client.listen_on(address(ip, 0)).unwrap();
    loop {
        if matches!(
            client.select_next_some().await,
            SwarmEvent::NewListenAddr { .. }
        ) {
            return;
        }
    }
}

async fn connect(
    client: &mut Swarm<ping::Behaviour>,
    remote: PeerId,
    port: u16,
    lines: &mut mpsc::UnboundedReceiver<String>,
) {
    client
        .dial(address("10.241.11.2", port).with_p2p(remote).unwrap())
        .unwrap();
    let expected_peer = client.local_peer_id().to_string();
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut authenticated = false;
        let mut observed_source = false;
        while !authenticated || !observed_source {
            tokio::select! {
                event = client.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        assert_eq!(peer_id, remote);
                        authenticated = true;
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("LAN dial failed: {error}"),
                    _ => {}
                },
                line = lines.recv() => {
                    let line = line.expect("server output remains live");
                    if let Some(auth) = line.split_once("QUIC_TEST_AUTH ").map(|(_, auth)| auth) {
                        let (peer, endpoint) = auth.split_once(' ').unwrap();
                        assert_eq!(peer, expected_peer);
                        assert!(endpoint.starts_with("/ip4/10.241.11.1/udp/"), "wrong actual source: {endpoint}");
                        observed_source = true;
                    }
                }
            }
        }
    }).await.expect("bounded authenticated LAN reconnect");
}

async fn disconnect(client: &mut Swarm<ping::Behaviour>, peer: PeerId) {
    client.disconnect_peer_id(peer).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if matches!(client.select_next_some().await,
                SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } if peer_id == peer)
            {
                break;
            }
        }
    })
    .await
    .unwrap();
}

fn enter_disposable_namespace() -> bool {
    let original = namespace();
    if env::var_os(PARENT).is_none() {
        let output = Command::new("/usr/bin/timeout")
            .args([
                "60",
                "/usr/bin/unshare",
                "--user",
                "--map-root-user",
                "--net",
            ])
            .arg(env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(PARENT, &original)
            .output()
            .unwrap();
        assert_eq!(namespace(), original, "host network namespace unchanged");
        if output.status.code() == Some(1)
            && output.stdout.is_empty()
            && matches!(
                output.stderr.as_slice(),
                b"unshare: unshare failed: Operation not permitted\n"
                    | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
            )
        {
            assert!(
                env::var_os("VOLPAROSSA_REQUIRE_NETNS_TESTS").is_none(),
                "required namespace unavailable"
            );
            eprintln!("SKIP: outer namespace unavailable; no host networking changed");
            return false;
        }
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return false;
    }
    assert_ne!(original, Path::new(&env::var(PARENT).unwrap()));
    true
}

#[test]
fn dual_listener_quic_reconnect_uses_connected_lan_source() {
    if !enter_disposable_namespace() {
        return;
    }
    eprintln!("QUIC_TEST_CHILD_STARTED");
    if env::var_os(SERVER).is_some() {
        run_server();
        return;
    }
    let mut server = ServerOwner(
        Command::new("/usr/bin/unshare")
            .arg("--net")
            .arg(env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(SERVER, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(server.0.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert!(output.read_line(&mut line).unwrap() > 0);
        if line.contains("QUIC_TEST_NAMESPACE_READY") {
            break;
        }
    }
    ip(&[
        "link", "add", "qlan", "type", "veth", "peer", "name", "qpeer",
    ]);
    ip(&["link", "set", "qpeer", "netns", &server.0.id().to_string()]);
    ip(&["link", "set", "lo", "up"]);
    ip(&["address", "add", "10.241.11.1/30", "dev", "qlan"]);
    ip(&["link", "set", "qlan", "up"]);
    ip(&["link", "add", "qother", "type", "dummy"]);
    ip(&["address", "add", "43.159.1.1/32", "dev", "qother"]);
    ip(&["link", "set", "qother", "up"]);
    server
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"start\n")
        .unwrap();
    let (sender, mut lines) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in output.lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let remote = loop {
                let line = lines.recv().await.unwrap();
                if let Some((_, peer)) = line.split_once("QUIC_TEST_PEER ") {
                    break peer.trim().parse().unwrap();
                }
            };
            let mut client = swarm();
            listen(&mut client, "10.241.11.1").await;
            connect(&mut client, remote, 41_000, &mut lines).await;
            announce("QUIC_TEST_SINGLE_LISTENER_BASELINE_AUTHENTICATED");
            disconnect(&mut client, remote).await;
            listen(&mut client, "43.159.1.1").await;
            ip(&["link", "set", "qlan", "down"]);
            assert!(!crate::address_scope::private_address_is_local(&address(
                "10.241.11.2",
                41_000
            )));
            ip(&["link", "set", "qlan", "up"]);
            for port in 41_000..41_004 {
                connect(&mut client, remote, port, &mut lines).await;
                disconnect(&mut client, remote).await;
            }
        });
    ip(&["link", "delete", "qlan"]);
    ip(&["link", "delete", "qother"]);
    drop(server);
    announce(
        "QUIC_LAN_RECONNECT_PROOF baseline and four dual-listener authenticated reconnects use LAN source; owned links removed",
    );
}
