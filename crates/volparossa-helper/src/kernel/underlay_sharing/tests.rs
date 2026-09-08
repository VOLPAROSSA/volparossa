use std::{
    env,
    io::{BufRead, BufReader, Write},
    net::UdpSocket,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use nix::sys::socket::{
    setsockopt,
    sockopt::{Mark, Priority},
};

use super::super::NLA_F_NESTED;
use super::*;

const LIVE_TEST: &str =
    "kernel::underlay_sharing::tests::disposable_veth_owner_priority_and_exact_cleanup";
const CHILD_ROLE: &str = "VOLPAROSSA_SHARING_SMOKE_ROLE";
const PARENT_NS: &str = "VOLPAROSSA_SHARING_SMOKE_PARENT_NS";

mod defaults;

fn config(ifindex: u32) -> SharingConfig {
    SharingConfig {
        egress_ifindex: ifindex,
        total_upload_mbps: 2,
        contribution_upload_mbps: 1,
        runtime_id: [0x81; 16],
    }
}

fn deadline() -> HardDeadline {
    HardDeadline::after(Duration::from_secs(4)).expect("deadline")
}

#[test]
fn explicit_capacities_and_socket_classification_are_bounded() {
    let valid = config(2);
    assert!(valid.validate().is_ok());
    for invalid in [
        SharingConfig {
            egress_ifindex: 1,
            ..valid
        },
        SharingConfig {
            total_upload_mbps: 0,
            ..valid
        },
        SharingConfig {
            contribution_upload_mbps: 3,
            ..valid
        },
        SharingConfig {
            runtime_id: [0; 16],
            ..valid
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    let prio = prio_options();
    assert_eq!(read_u32(&prio, 0), Some(2));
    assert_eq!(prio[4 + CONTRIBUTION_SOCKET_PRIORITY as usize], 1);
    assert!(
        prio[4..]
            .iter()
            .enumerate()
            .all(|(index, band)| *band == u8::from(index == CONTRIBUTION_SOCKET_PRIORITY as usize))
    );
    assert_eq!(
        CONTRIBUTION_MARK_BIT & super::super::CLIENT_INGRESS_IPV4_MARK,
        0
    );
    let tree = specifications(valid, 1500);
    assert_eq!(tree.len(), 5);
    for item in tree {
        assert!(item.encode(2).unwrap().len() < 256);
    }
}

#[test]
fn foreign_qdiscs_and_changed_defaults_are_not_owned() {
    let baseline = TcRecord {
        handle: 0,
        parent: TC_ROOT,
        info: 0,
        kind: "noqueue".to_owned(),
        options: Vec::new(),
        counters: QueueCounters::default(),
        extra_configuration: false,
    };
    assert!(pristine_baseline(std::slice::from_ref(&baseline)).is_ok());
    let mut foreign = baseline.clone();
    foreign.handle = 1 << 16;
    assert!(pristine_baseline(std::slice::from_ref(&foreign)).is_err());
    foreign = baseline.clone();
    foreign.kind = "mq".to_owned();
    assert!(pristine_baseline(std::slice::from_ref(&foreign)).is_err());
    assert!(pristine_baseline(&[baseline.clone(), baseline.clone()]).is_err());
    foreign = baseline.clone();
    foreign.options = vec![1, 2, 3, 4];
    assert!(!baseline.same_configuration(&foreign));
    assert!(pristine_baseline(std::slice::from_ref(&foreign)).is_err());
    foreign.kind = "fq_codel".to_owned();
    assert!(pristine_baseline(std::slice::from_ref(&foreign)).is_err());
}

fn pristine_baseline(records: &[TcRecord]) -> Result<DefaultTree, KernelError> {
    DefaultTree::from_records(
        records,
        LinkGeometry {
            mtu: 1500,
            hardware_type: 1,
            tx_queues: 1,
            tx_queue_length: 1000,
        },
    )
}

#[test]
fn tc_parser_rejects_truncation_and_retains_real_counters() {
    let mut payload = tc_message(2, 0x7100_0000, TC_ROOT, 0);
    push_string_attribute(&mut payload, TCA_KIND, "tbf").unwrap();
    let mut stats = Vec::new();
    let mut basic = 12345_u64.to_ne_bytes().to_vec();
    basic.extend_from_slice(&17_u32.to_ne_bytes());
    push_attribute(&mut stats, 1, &basic).unwrap();
    let queue: Vec<_> = [3_u32, 1200, 5, 0, 7]
        .into_iter()
        .flat_map(u32::to_ne_bytes)
        .collect();
    push_attribute(&mut stats, 3, &queue).unwrap();
    push_attribute(&mut payload, TCA_STATS2 | NLA_F_NESTED, &stats).unwrap();
    let frame = build_netlink_message(RTM_NEWQDISC, 0, 1, &payload).unwrap();
    let record = parse_tc(&frame).unwrap();
    assert_eq!(
        record.counters,
        QueueCounters {
            bytes: 12345,
            packets: 17,
            drops: 5,
            overlimits: 7,
            backlog_bytes: 1200
        }
    );
    for size in 0..frame.len() {
        assert!(parse_tc(&frame[..size]).is_err() || size >= NLMSG_HEADER_LEN + TC_MESSAGE_BYTES);
    }
}

fn namespace_id() -> String {
    let metadata = File::open("/proc/thread-self/ns/net")
        .unwrap()
        .metadata()
        .unwrap();
    format!("{}:{}", metadata.dev(), metadata.ino())
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ip(args: &[&str]) {
    assert_ne!(
        namespace_id(),
        env::var(PARENT_NS).expect("original host namespace"),
        "never mutate host networking"
    );
    let output = Command::new("/usr/bin/ip")
        .args(args)
        .output()
        .expect("ip test diagnostic");
    assert!(
        output.status.success(),
        "disposable ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn wait_line(reader: &mut impl BufRead, prefix: &str) -> String {
    loop {
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).expect("child output") > 0,
            "child closed before {prefix}"
        );
        if let Some(index) = line.find(prefix) {
            return line[index..].to_owned();
        }
    }
}

#[test]
fn disposable_veth_owner_priority_and_exact_cleanup() {
    match env::var(CHILD_ROLE).ok().as_deref() {
        Some("receiver") => receiver(),
        Some("sender") => sender(),
        _ => {
            let original = namespace_id();
            let output = Command::new("/usr/bin/timeout")
                .args([
                    "--signal=TERM",
                    "--kill-after=2s",
                    "25s",
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                ])
                .arg(env::current_exe().unwrap())
                .args(["--exact", LIVE_TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD_ROLE, "sender")
                .env(PARENT_NS, &original)
                .env("LC_ALL", "C")
                .output()
                .expect("disposable user/net namespace");
            assert_eq!(namespace_id(), original);
            if output.status.code() == Some(1)
                && output.stdout.is_empty()
                && matches!(
                    output.stderr.as_slice(),
                    b"unshare: unshare failed: Operation not permitted\n"
                        | b"unshare: write failed /proc/self/uid_map: Operation not permitted\n"
                        | b"unshare: write failed /proc/self/gid_map: Operation not permitted\n"
                )
            {
                eprintln!("SKIP sharing live proof: unprivileged namespaces unavailable");
                return;
            }
            assert!(
                output.status.success(),
                "live sharing failure\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
}

fn receiver() {
    assert_ne!(namespace_id(), env::var(PARENT_NS).unwrap());
    println!("SHARING_READY");
    std::io::stdout().flush().unwrap();
    let mut go = String::new();
    std::io::stdin().read_line(&mut go).unwrap();
    assert_eq!(go, "go\n");
    ip(&["addr", "add", "10.244.1.2/30", "dev", "share1"]);
    ip(&["link", "set", "share1", "up"]);
    let socket = UdpSocket::bind("10.244.1.2:18081").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    println!("SHARING_LISTENING");
    std::io::stdout().flush().unwrap();
    let mut counts = [0_u64; 3];
    let mut buffer = [0_u8; 1200];
    loop {
        let (size, _) = socket.recv_from(&mut buffer).expect("real veth delivery");
        if size == 1 && buffer[0] == 9 {
            break;
        }
        assert_eq!(size, 1000);
        assert!(buffer[0] < 3);
        assert!(buffer[1..size].iter().all(|byte| *byte == 0x6b));
        counts[usize::from(buffer[0])] += size as u64;
    }
    assert!(
        counts.iter().all(|bytes| *bytes > 0),
        "all three real socket classes delivered"
    );
    println!("SHARING_RECEIVED {} {} {}", counts[0], counts[1], counts[2]);
}

fn flow(priority: bool, mark: bool) -> UdpSocket {
    let socket = UdpSocket::bind("10.244.1.1:0").unwrap();
    if priority {
        setsockopt(
            &socket,
            Priority,
            &i32::try_from(CONTRIBUTION_SOCKET_PRIORITY).unwrap(),
        )
        .unwrap();
    }
    if mark {
        setsockopt(&socket, Mark, &CONTRIBUTION_MARK_BIT).unwrap();
    }
    socket.connect("10.244.1.2:18081").unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

fn drive(flows: &[(&UdpSocket, u8)], duration: Duration) {
    let end = Instant::now() + duration;
    while Instant::now() < end {
        for &(socket, tag) in flows {
            let mut payload = [0x6b; 1000];
            payload[0] = tag;
            match socket.send(&payload) {
                Ok(1000) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("send: {other:?}"),
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[allow(clippy::too_many_lines)] // One bounded disposable topology proves kernel class contention and teardown.
fn sender() {
    assert_ne!(namespace_id(), env::var(PARENT_NS).unwrap());
    let mut child = ChildGuard(
        Command::new("/usr/bin/unshare")
            .arg("--net")
            .arg(env::current_exe().unwrap())
            .args(["--exact", LIVE_TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD_ROLE, "receiver")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    wait_line(&mut output, "SHARING_READY");
    // Keep the receiver namespace (and its veth peer) alive until scheduler retirement is proved.
    let _receiver_namespace = File::open(format!("/proc/{}/ns/net", child.0.id())).unwrap();
    ip(&[
        "link", "add", "share0", "type", "veth", "peer", "name", "share1",
    ]);
    ip(&["link", "set", "share1", "netns", &child.0.id().to_string()]);
    ip(&["addr", "add", "10.244.1.1/30", "dev", "share0"]);
    ip(&["link", "set", "share0", "up"]);
    child.0.stdin.take().unwrap().write_all(b"go\n").unwrap();
    wait_line(&mut output, "SHARING_LISTENING");
    let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline()).unwrap();
    let ifindex = route.link_index("share0", deadline()).unwrap();
    let mut owner = install(config(ifindex), deadline()).unwrap_or_else(|failure| {
        if let Some(mut cleanup) = failure.cleanup {
            eprintln!("partial cleanup: {:?}", cleanup.remove(deadline()));
        }
        panic!("install: {:?}", failure.source)
    });
    assert!(
        install(config(ifindex), deadline()).is_err(),
        "foreign preexisting root never replaced"
    );
    let foreground = flow(false, false);
    let background = flow(true, false);
    let marked = flow(false, true);
    // A plain socket priority is usable without a packet mark. Two contribution flows share ONE cap.
    let before = owner.inspect(deadline()).unwrap();
    drive(&[(&background, 1), (&marked, 2)], Duration::from_secs(2));
    thread::sleep(Duration::from_millis(150));
    let idle = owner.inspect(deadline()).unwrap();
    assert!(idle.contribution.bytes - before.contribution.bytes > 150_000);
    assert!(
        idle.contribution.bytes - before.contribution.bytes < 400_000,
        "aggregate contribution exceeds its 1Mbps ceiling"
    );
    let start = Instant::now();
    drive(
        &[(&foreground, 0), (&background, 1), (&marked, 2)],
        Duration::from_secs(2),
    );
    let active = owner.inspect(deadline()).unwrap();
    assert!(
        active.owner.bytes - idle.owner.bytes > 300_000,
        "owner did not receive priority at the 2Mbps bottleneck"
    );
    assert!(
        active.contribution.bytes - idle.contribution.bytes < 150_000,
        "background displaced owner"
    );
    assert!(
        active.total.bytes - idle.total.bytes < 650_000,
        "aggregate exceeded total upload ceiling in {:?}",
        start.elapsed()
    );
    thread::sleep(Duration::from_millis(150));
    drive(&[(&background, 1), (&marked, 2)], Duration::from_secs(2));
    thread::sleep(Duration::from_millis(150));
    let resumed = owner.inspect(deadline()).unwrap();
    assert!(
        resumed.contribution.bytes - active.contribution.bytes > 150_000,
        "contribution failed to recover"
    );
    foreground.send(&[9]).unwrap();
    let received = wait_line(&mut output, "SHARING_RECEIVED");
    assert!(child.0.wait().unwrap().success());
    owner
        .remove(deadline())
        .expect("exact tree removal and baseline restoration");
    owner.remove(deadline()).expect("idempotent exact cleanup");
    assert!(owner.inspect(deadline()).is_err());
    // Every acknowledged prefix is also a possible timeout boundary. Each must be removable
    // without the missing later qdiscs/filter or a broad interface reset.
    for prefix in 1..=owner.specifications.len() {
        owner.removed = false;
        for (index, specification) in owner.specifications[..prefix].iter().enumerate() {
            let flags = if index == 0 {
                NLM_F_CREATE | NLM_F_EXCL
            } else {
                NLM_F_CREATE | NLM_F_REPLACE
            };
            route
                .request_ack(
                    RTM_NEWQDISC,
                    flags,
                    &specification.encode(ifindex).unwrap(),
                    deadline(),
                )
                .unwrap();
        }
        owner
            .remove(deadline())
            .unwrap_or_else(|error| panic!("partial tree {prefix} cleanup: {error}"));
    }
    ip(&["link", "del", "share0"]);
    println!(
        "SHARING_PROOF owner_bytes={} contribution_bytes={} total_bytes={} {received}",
        resumed.owner.bytes, resumed.contribution.bytes, resumed.total.bytes
    );
}
