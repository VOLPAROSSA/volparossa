use std::{
    env,
    io::{BufRead, BufReader, Write},
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::Duration,
};

use super::{
    HardDeadline, MAX_RECEIVE_TUPLES, NETLINK_ROUTE, NetlinkClient, ReceiveAccountingConfig,
    ReceiveCounters, ReceiveTuple, Rule, WireguardRole, install, netlink, validate_new_tuple,
    verify_rules,
};

const LIVE: &str =
    "kernel::receive_accounting::tests::disposable_netdev_exact_tuple_counters_and_cleanup";
const ROLE: &str = "VOLPAROSSA_RECEIVE_COUNTER_TEST_ROLE";
const ORIGINAL: &str = "VOLPAROSSA_RECEIVE_COUNTER_TEST_PARENT";

fn tuple(role: WireguardRole, port: u16) -> ReceiveTuple {
    ReceiveTuple {
        context_id: [1; 16],
        path_id: 1,
        role,
        local: "10.244.8.1:18081".parse().unwrap(),
        remote: format!("10.244.8.2:{port}").parse().unwrap(),
    }
}

fn deadline() -> HardDeadline {
    HardDeadline::after(Duration::from_secs(3)).unwrap()
}

#[test]
fn tuple_authority_is_bounded_and_never_relabels_client_as_contribution() {
    let managed = tuple(WireguardRole::RelayExit, 28081);
    assert!(managed.validate().is_ok());
    let own = tuple(WireguardRole::Client, 28082);
    assert!(own.validate().is_ok());
    assert_eq!(own.role, WireguardRole::Client);
    assert!(validate_new_tuple(std::slice::from_ref(&managed), &own).is_ok());
    for altered in [
        ReceiveTuple {
            context_id: [2; 16],
            ..managed.clone()
        },
        ReceiveTuple {
            remote: "10.244.8.2:28084".parse().unwrap(),
            ..managed.clone()
        },
    ] {
        assert!(validate_new_tuple(std::slice::from_ref(&managed), &altered).is_err());
    }
    assert!(validate_new_tuple(&vec![managed.clone(); MAX_RECEIVE_TUPLES], &own).is_err());
    for invalid in [
        ReceiveTuple {
            role: WireguardRole::Unspecified,
            ..managed.clone()
        },
        ReceiveTuple {
            path_id: 0,
            ..managed.clone()
        },
        ReceiveTuple {
            context_id: [0; 16],
            ..managed.clone()
        },
        ReceiveTuple {
            local: "10.244.8.1:0".parse().unwrap(),
            ..managed.clone()
        },
        ReceiveTuple {
            remote: "[fd00::1]:28081".parse().unwrap(),
            ..managed
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn exact_rules_reject_missing_foreign_or_substituted_tuple_expressions() {
    let tuple = tuple(WireguardRole::RelayExit, 28081);
    let rules = vec![
        Rule {
            handle: 1,
            tag: b"total".to_vec(),
            expressions: netlink::expressions(None),
            counters: ReceiveCounters::default(),
        },
        Rule {
            handle: 2,
            tag: tuple.tag(),
            expressions: netlink::expressions(Some(&tuple)),
            counters: ReceiveCounters {
                bytes: 1028,
                packets: 1,
            },
        },
    ];
    assert!(verify_rules(&rules, std::slice::from_ref(&tuple)).is_ok());
    assert!(verify_rules(&rules[..1], std::slice::from_ref(&tuple)).is_err());
    let mut changed = rules.clone();
    changed[1].expressions = netlink::expressions(Some(&ReceiveTuple {
        remote: "10.244.8.2:28082".parse().unwrap(),
        ..tuple.clone()
    }));
    assert!(verify_rules(&changed, std::slice::from_ref(&tuple)).is_err());
    changed = rules.clone();
    changed[1].tag = b"foreign".to_vec();
    assert!(verify_rules(&changed, std::slice::from_ref(&tuple)).is_err());
    changed = rules;
    changed[1].handle = 1;
    assert!(verify_rules(&changed, &[tuple]).is_err());
}

fn namespace() -> String {
    std::fs::read_link("/proc/thread-self/ns/net")
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn ip(args: &[&str]) {
    let output = Command::new("/usr/bin/ip").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "disposable ip: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn line(reader: &mut impl BufRead, prefix: &str) {
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0, "missing {prefix}");
        if line.contains(prefix) {
            return;
        }
    }
}

#[test]
fn disposable_netdev_exact_tuple_counters_and_cleanup() {
    match env::var(ROLE).ok().as_deref() {
        Some("receiver") => receive(),
        Some("sender") => send(),
        _ => {
            let original = namespace();
            let output = Command::new("/usr/bin/timeout")
                .args([
                    "--kill-after=2s",
                    "20s",
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                ])
                .arg(env::current_exe().unwrap())
                .args(["--exact", LIVE, "--nocapture", "--test-threads=1"])
                .env(ROLE, "receiver")
                .env(ORIGINAL, &original)
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            assert_eq!(namespace(), original);
            if output.status.code() == Some(1)
                && output.stdout.is_empty()
                && matches!(
                    output.stderr.as_slice(),
                    b"unshare: unshare failed: Operation not permitted\n"
                        | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                        | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
                )
            {
                eprintln!("SKIP receive accounting live test: pre-child namespace denial");
                return;
            }
            assert!(
                output.status.success(),
                "real receive accounting failure\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
}

fn send() {
    assert_ne!(namespace(), env::var(ORIGINAL).unwrap());
    println!("RX_READY");
    std::io::stdout().flush().unwrap();
    let mut input = std::io::stdin().lock();
    let mut go = String::new();
    input.read_line(&mut go).unwrap();
    assert_eq!(go, "go\n");
    ip(&["addr", "add", "10.244.8.2/30", "dev", "rxpeer"]);
    ip(&["link", "set", "rxpeer", "up"]);
    let sockets: Vec<_> = (28081..=28083)
        .map(|port| UdpSocket::bind((std::net::Ipv4Addr::new(10, 244, 8, 2), port)).unwrap())
        .collect();
    println!("RX_LISTENING");
    std::io::stdout().flush().unwrap();
    for value in input.lines() {
        let index: usize = value.unwrap().parse().unwrap();
        assert_eq!(
            sockets[index]
                .send_to(&[0x73; 1000], "10.244.8.1:18081")
                .unwrap(),
            1000
        );
    }
}

#[allow(clippy::too_many_lines)] // One finite real namespace lifecycle, including unrelated-owner preservation.
fn receive() {
    assert_ne!(namespace(), env::var(ORIGINAL).unwrap());
    let mut sender = ChildGuard(
        Command::new("/usr/bin/unshare")
            .arg("--net")
            .arg(env::current_exe().unwrap())
            .args(["--exact", LIVE, "--nocapture", "--test-threads=1"])
            .env(ROLE, "sender")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(sender.0.stdout.take().unwrap());
    line(&mut output, "RX_READY");
    ip(&[
        "link", "add", "rx0", "type", "veth", "peer", "name", "rxpeer",
    ]);
    ip(&["link", "set", "rxpeer", "netns", &sender.0.id().to_string()]);
    ip(&["addr", "add", "10.244.8.1/30", "dev", "rx0"]);
    ip(&["link", "set", "rx0", "up"]);
    let mut commands = sender.0.stdin.take().unwrap();
    commands.write_all(b"go\n").unwrap();
    line(&mut output, "RX_LISTENING");
    let socket = UdpSocket::bind("10.244.8.1:18081").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let exchange = |commands: &mut std::process::ChildStdin, index: u8| {
        writeln!(commands, "{index}").unwrap();
        let mut bytes = [0; 1200];
        let (received, remote) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(received, 1000);
        assert_eq!(bytes[..received], [0x73; 1000]);
        assert_eq!(remote.port(), 28081 + u16::from(index));
    };
    let ifindex = NetlinkClient::connect(NETLINK_ROUTE, deadline())
        .unwrap()
        .link_index("rx0", deadline())
        .unwrap();
    let config = ReceiveAccountingConfig {
        runtime_id: [0x73; 16],
        interface_name: "rx0".into(),
        ifindex,
    };
    let mut owner =
        install(config.clone(), deadline()).unwrap_or_else(|failure| panic!("install {failure:?}"));
    let conflict = install(config, deadline())
        .err()
        .expect("never replace a live owner");
    drop(conflict); // Its different socket cannot release the original owner's table.
    let managed = tuple(WireguardRole::RelayExit, 28081);
    let own_client = tuple(WireguardRole::Client, 28082);
    owner.register(managed.clone(), deadline()).unwrap();
    owner.register(own_client, deadline()).unwrap();
    exchange(&mut commands, 2); // Warm neighbour resolution before the measured sample.
    let before = owner.inspect(deadline()).unwrap();
    for index in 0..=2 {
        exchange(&mut commands, index);
    }
    let after = owner.inspect(deadline()).unwrap();
    for (start, end) in before.tuples.iter().zip(&after.tuples) {
        assert_eq!(end.counters.packets - start.counters.packets, 1);
        assert_eq!(end.counters.bytes - start.counters.bytes, 1028);
    }
    assert!(after.total.bytes - before.total.bytes >= 3 * 1028);
    assert!(after.total.packets - before.total.packets >= 3);
    assert_eq!(after.tuples[1].tuple.role, WireguardRole::Client);
    assert!(
        owner
            .unregister(managed.context_id, 1, managed.role, deadline())
            .unwrap()
    );
    assert!(
        !owner
            .unregister(managed.context_id, 1, managed.role, deadline())
            .unwrap()
    );
    exchange(&mut commands, 0);
    let retired = owner.inspect(deadline()).unwrap();
    assert_eq!(retired.tuples.len(), 1);
    assert!(retired.total.bytes >= after.total.bytes + 1028);
    assert!(owner.remove(deadline()).unwrap());
    assert!(!owner.remove(deadline()).unwrap());
    assert!(owner.inspect(deadline()).is_err());
    drop(commands);
    assert!(sender.0.wait().unwrap().success());
    println!("REAL_NETDEV_COUNTERS_PASS same-skb-bytes client-is-owner exact-retirement");
}
