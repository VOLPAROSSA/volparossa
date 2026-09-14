use super::*;

const DEFAULT_TEST: &str = "kernel::underlay_sharing::tests::defaults::disposable_tap_defaults_restore_single_and_multiqueue";
const DEFAULT_CHILD: &str = "VOLPAROSSA_SHARING_DEFAULT_CHILD";

#[test]
fn kernel_defaults_reject_custom_options_and_restore_duplicate_zero_handles_by_parent() {
    let geometry = LinkGeometry {
        mtu: 1500,
        hardware_type: 1,
        tx_queues: 1,
        tx_queue_length: 500,
    };
    let expected = [
        (1, 4999_u32),
        (2, 10_240),
        (3, 99_999),
        (4, 1),
        (5, 1024),
        (6, 1514),
        (8, 64),
        (9, 33_554_432),
    ];
    let encode = |values: &[(u16, u32)]| {
        let mut bytes = Vec::new();
        for (kind, value) in values {
            push_attribute(&mut bytes, *kind, &value.to_ne_bytes()).unwrap();
        }
        bytes
    };
    let root = TcRecord {
        handle: 0,
        parent: TC_ROOT,
        info: 0,
        kind: "fq_codel".to_owned(),
        options: encode(&expected),
        counters: QueueCounters::default(),
        extra_configuration: false,
    };
    let single = DefaultTree::from_records(std::slice::from_ref(&root), geometry)
        .expect("actual CoDel tick-truncated defaults");
    assert!(single.matches(std::slice::from_ref(&root), geometry));
    assert!(
        DefaultTree::from_records(
            std::slice::from_ref(&root),
            LinkGeometry {
                tx_queue_length: 0,
                ..geometry
            }
        )
        .is_err()
    );
    for index in 0..expected.len() {
        let mut changed = expected;
        changed[index].1 += 1;
        let mut record = root.clone();
        record.options = encode(&changed);
        assert!(DefaultTree::from_records(&[record], geometry).is_err());
    }
    let mut extra = root.clone();
    push_attribute(&mut extra.options, 7, &1000_u32.to_ne_bytes()).unwrap();
    assert!(DefaultTree::from_records(&[extra], geometry).is_err());
    let mut shared = root.clone();
    shared.extra_configuration = true;
    assert!(DefaultTree::from_records(&[shared], geometry).is_err());
    let mut mq = root.clone();
    mq.kind = "mq".to_owned();
    mq.options.clear();
    let mut first = root.clone();
    first.parent = 1;
    let mut second = root;
    second.parent = 2;
    let geometry = LinkGeometry {
        tx_queues: 256,
        ..geometry
    };
    let tree = [mq.clone(), first.clone(), second.clone()];
    let baseline =
        DefaultTree::from_records(&tree, geometry).expect("two active default MQ queues");
    assert!(baseline.matches(&[second.clone(), mq.clone(), first.clone()], geometry));
    assert!(!baseline.matches(&[mq.clone(), first.clone()], geometry));
    second.handle = 0x10000;
    assert!(DefaultTree::from_records(&[mq.clone(), first.clone(), second], geometry).is_err());
    assert!(DefaultTree::from_records(&[mq, first.clone(), first], geometry).is_err());
}

#[test]
fn disposable_tap_defaults_restore_single_and_multiqueue() {
    if env::var_os(DEFAULT_CHILD).is_some() {
        assert_ne!(namespace_id(), env::var(PARENT_NS).unwrap());
        eprintln!(
            "Disposable default-qdisc test: create TAP sharetap0 only in this user/net namespace; configure its private /30 and neighbor, install/remove owned upload tree, verify original fq_codel/mq defaults, close every TAP FD."
        );
        exercise_tap(false);
        exercise_tap(true);
        return;
    }
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
        .args(["--exact", DEFAULT_TEST, "--nocapture", "--test-threads=1"])
        .env(DEFAULT_CHILD, "1")
        .env(PARENT_NS, &original)
        .env("LC_ALL", "C")
        .output()
        .expect("disposable default-qdisc process");
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
        eprintln!("SKIP real default-qdisc proof: user namespaces unavailable");
        return;
    }
    assert!(
        output.status.success(),
        "default-qdisc smoke failed\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

// Test-only TAP endpoint. Python's bounded fcntl wrapper avoids introducing unsafe Rust into
// this crate. This subprocess inherits the already checked disposable user/net namespace.
const TAP_ENDPOINT: &str = r"
import fcntl, os, select, struct, sys
ns = os.stat('/proc/thread-self/ns/net')
assert f'{ns.st_dev}:{ns.st_ino}' != os.environ['VOLPAROSSA_SHARING_SMOKE_PARENT_NS']
multi = sys.argv[1] == '1'
fds = []
try:
    for _ in range(2 if multi else 1):
        fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        fds.append(fd)
        fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH22x', b'sharetap0', 0x1002 | (0x100 if multi else 0)))
    counts = [[0, 0, 0] for _ in fds]
    print('TAP_READY', flush=True)
    while True:
        ready, _, _ = select.select([sys.stdin] + fds, [], [], 1)
        if sys.stdin in ready:
            command = sys.stdin.readline()
            if command == 'stop\n' or not command:
                break
            assert command == 'counts\n'
            print('TAP_COUNTS', *(value for queue in counts for value in queue), flush=True)
        for index, fd in enumerate(fds):
            if fd not in ready:
                continue
            frame = os.read(fd, 4096)
            if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
                continue
            start = 14 + (frame[14] & 15) * 4 + 8
            payload = frame[start:]
            assert len(payload) == 1000 and payload[0] < 3 and payload[1:] == b'k' * 999
            counts[index][payload[0]] += 1000
finally:
    for fd in fds:
        os.close(fd)
";

fn tap_flow(class: u8) -> UdpSocket {
    let socket = UdpSocket::bind("10.244.2.1:0").unwrap();
    if class == 1 {
        setsockopt(&socket, Priority, &1).unwrap();
    }
    if class == 2 {
        setsockopt(&socket, Mark, &CONTRIBUTION_MARK_BIT).unwrap();
    }
    socket.connect("10.244.2.2:18081").unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

#[allow(
    clippy::too_many_lines,
    reason = "one disposable TAP owner proves contention and exact default restoration"
)]
fn exercise_tap(multiqueue: bool) {
    let mut endpoint = ChildGuard(
        Command::new("/usr/bin/python3")
            .args(["-B", "-c", TAP_ENDPOINT, if multiqueue { "1" } else { "0" }])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("disposable TAP endpoint"),
    );
    let mut output = BufReader::new(endpoint.0.stdout.take().unwrap());
    wait_line(&mut output, "TAP_READY");
    ip(&["addr", "add", "10.244.2.1/30", "dev", "sharetap0"]);
    ip(&["link", "set", "sharetap0", "up"]);
    ip(&[
        "neigh",
        "add",
        "10.244.2.2",
        "lladdr",
        "02:00:00:00:00:02",
        "nud",
        "permanent",
        "dev",
        "sharetap0",
    ]);
    let mut route = NetlinkClient::connect(NETLINK_ROUTE, deadline()).unwrap();
    let ifindex = route.link_index("sharetap0", deadline()).unwrap();
    let (_, geometry) = observe_link(&mut route, ifindex, deadline()).unwrap();
    let before = dump(&mut route, RTM_GETQDISC, ifindex, 0, deadline()).unwrap();
    let root = before
        .iter()
        .find(|record| record.parent == TC_ROOT)
        .unwrap();
    assert_eq!(
        root.kind,
        if multiqueue { "mq" } else { "fq_codel" },
        "requires actual kernel defaults"
    );
    assert_eq!(before.len(), if multiqueue { 3 } else { 1 });
    assert!(before.iter().all(|record| record.handle == 0));
    let baseline = DefaultTree::from_records(&before, geometry)
        .unwrap_or_else(|error| panic!("default admission {geometry:?} {before:?}: {error}"));
    if !multiqueue {
        reject_default_filter(&mut route, ifindex, &baseline, geometry);
    }
    let mut owner = install(config(ifindex), deadline()).unwrap_or_else(|failure| {
        if let Some(mut owner) = failure.cleanup {
            owner.remove(deadline()).expect("failed-install cleanup");
        }
        panic!("TAP install: {:?}", failure.source);
    });
    let sockets: Vec<_> = (0..24)
        .map(|index| (tap_flow(index % 3), index % 3))
        .collect();
    let background: Vec<_> = sockets
        .iter()
        .filter(|(_, class)| *class != 0)
        .map(|(socket, class)| (socket, *class))
        .collect();
    let all: Vec<_> = sockets
        .iter()
        .map(|(socket, class)| (socket, *class))
        .collect();
    drive(&background, Duration::from_secs(1));
    let idle = owner.inspect(deadline()).unwrap();
    assert!(idle.contribution.bytes > 70_000 && idle.contribution.bytes < 220_000);
    drive(&all, Duration::from_secs(1));
    let active = owner.inspect(deadline()).unwrap();
    assert!(active.owner.bytes - idle.owner.bytes > 150_000);
    assert!(active.contribution.bytes - idle.contribution.bytes < 100_000);
    assert!(
        active.total.bytes - idle.total.bytes < 370_000,
        "one cap spans all TX queues"
    );
    drive(&background, Duration::from_secs(1));
    thread::sleep(Duration::from_millis(150));
    let recovered = owner.inspect(deadline()).unwrap();
    assert!(recovered.contribution.bytes - active.contribution.bytes > 70_000);
    endpoint
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"counts\n")
        .unwrap();
    let line = wait_line(&mut output, "TAP_COUNTS");
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(|value| value.parse().unwrap())
        .collect();
    assert_eq!(values.len(), if multiqueue { 6 } else { 3 });
    let counts: Vec<&[u64]> = values.chunks_exact(3).collect();
    assert!(
        counts.iter().all(|queue| queue.iter().sum::<u64>() > 0),
        "every attached queue carried real UDP: {counts:?}"
    );
    for class in 0..3 {
        assert!(counts.iter().map(|queue| queue[class]).sum::<u64>() > 0);
    }
    owner
        .remove(deadline())
        .expect("restore exact default tree");
    owner
        .remove(deadline())
        .expect("idempotent default cleanup");
    let restored = dump(&mut route, RTM_GETQDISC, ifindex, 0, deadline()).unwrap();
    assert!(baseline.matches(&restored, geometry));
    println!(
        "SHARING_DEFAULT_PROOF kind={} restored_nodes={} queue_payload_bytes={counts:?} owner_bytes={} contribution_bytes={}",
        root.kind,
        restored.len(),
        recovered.owner.bytes,
        recovered.contribution.bytes
    );
    drop(sockets);
    endpoint
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"stop\n")
        .unwrap();
    assert!(endpoint.0.wait().unwrap().success()); // Final owned TAP FD closes only after restoration.
    assert!(route.link_index("sharetap0", deadline()).is_err());
}

fn reject_default_filter(
    route: &mut NetlinkClient,
    ifindex: u32,
    baseline: &DefaultTree,
    geometry: LinkGeometry,
) {
    route
        .request_ack(
            RTM_NEWTFILTER,
            NLM_F_CREATE | NLM_F_EXCL,
            &filter_request(ifindex, 0).unwrap(),
            deadline(),
        )
        .expect("fixture classifier on default fq_codel");
    let failed = install(config(ifindex), deadline())
        .err()
        .expect("default with foreign filter rejected");
    assert!(failed.cleanup.is_none(), "no mutation before rejection");
    let current = dump(route, RTM_GETQDISC, ifindex, 0, deadline()).unwrap();
    assert!(baseline.matches(&current, geometry));
    assert!(
        !dump(route, RTM_GETTFILTER, ifindex, 0, deadline())
            .unwrap()
            .is_empty()
    );
    route
        .request_ack(45, 0, &filter_request(ifindex, 0).unwrap(), deadline())
        .expect("delete only fixture-owned filter");
    baseline
        .verify_no_filters(route, ifindex, deadline())
        .unwrap();
}
