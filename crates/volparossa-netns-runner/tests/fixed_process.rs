//! Real-process regressions for the fixed bounded isolation-supervisor boundary.

use std::{
    fs,
    net::Shutdown,
    os::fd::OwnedFd,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
    process::{Command, Stdio},
    sync::{Mutex, MutexGuard, PoisonError},
};

use socket2::{Domain, Protocol, Socket, Type};
use tempfile::tempdir;
use volparossa_linux_uapi::{receive_seqpacket_without_fd, send_seqpacket_without_fd};
use volparossa_netns_runner::{INTERNAL_CHILD_ARGUMENT, INTERNAL_PID_ONE_ARGUMENT};
use volparossa_test_support::{LaunchContext, NamespaceIdentity, RunId};

const RUNNER: &str = env!("CARGO_BIN_EXE_volparossa-netns-runner");
const MAXIMUM_HOST_RECORD_BYTES: u64 = 1024 * 1024;
const MAXIMUM_HOST_LINKS: usize = 1024;

// Only the two tests that run the complete mutable topology share this lock;
// rejection and preview coverage remains parallel.
static LIVE_RUNNER_MUTATIONS: Mutex<()> = Mutex::new(());

fn serialize_live_runner_mutations() -> MutexGuard<'static, ()> {
    LIVE_RUNNER_MUTATIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn namespace_identity(name: &str) -> (u64, u64) {
    let metadata = fs::metadata(format!("/proc/self/ns/{name}")).expect("namespace metadata");
    (metadata.dev(), metadata.ino())
}

fn protocol_namespace_identity(name: &str) -> NamespaceIdentity {
    let (device, inode) = namespace_identity(name);
    NamespaceIdentity::new(device, inode).expect("nonzero namespace identity")
}

fn bounded_host_record(path: &str) -> Vec<u8> {
    use std::io::Read as _;

    let file = fs::File::open(path).expect("open host-state record");
    let mut bytes = Vec::new();
    file.take(MAXIMUM_HOST_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .expect("read host-state record");
    assert!(
        !bytes.is_empty()
            && u64::try_from(bytes.len()).expect("record length fits u64")
                <= MAXIMUM_HOST_RECORD_BYTES,
        "host-state record {path} is empty or oversized"
    );
    bytes
}

fn host_link_names() -> Vec<Vec<u8>> {
    let mut names = fs::read_dir("/sys/class/net")
        .expect("read host link set")
        .map(|entry| {
            let entry = entry.expect("read host link entry");
            let name = entry.file_name();
            let bytes = name.as_bytes();
            assert!(!bytes.is_empty() && bytes.len() <= 15 && !bytes.contains(&0));
            bytes.to_vec()
        })
        .collect::<Vec<_>>();
    assert!(names.len() <= MAXIMUM_HOST_LINKS);
    names.sort_unstable();
    assert!(!names.windows(2).any(|pair| pair[0] == pair[1]));
    names
}

fn write_command_shims(directory: &Path, marker: &Path) {
    for name in [
        "ip", "mount", "nft", "nsenter", "sysctl", "umount", "unshare", "wg",
    ] {
        let shim = directory.join(name);
        fs::write(
            &shim,
            format!("#!/bin/sh\nprintf invoked >'{}'\n", marker.display()),
        )
        .expect("write command shim");
        let mut permissions = fs::metadata(&shim).expect("shim metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&shim, permissions).expect("shim permissions");
    }
}

#[test]
fn fixed_run_is_blocked_reaped_and_ignores_command_environment() {
    let _live_runner_guard = serialize_live_runner_mutations();
    let directory = tempdir().expect("temporary shim directory");
    let marker = directory.path().join("invoked");
    write_command_shims(directory.path(), &marker);
    let before = [
        namespace_identity("user"),
        namespace_identity("net"),
        namespace_identity("mnt"),
        namespace_identity("pid"),
        namespace_identity("pid_for_children"),
    ];
    let mountinfo_before = bounded_host_record("/proc/self/mountinfo");
    let ipv4_routes_before = bounded_host_record("/proc/net/route");
    let ipv6_routes_before = bounded_host_record("/proc/net/ipv6_route");
    let ipv4_forwarding_before = bounded_host_record("/proc/sys/net/ipv4/ip_forward");
    let links_before = host_link_names();

    let output = Command::new(RUNNER)
        .arg("--run")
        .env_clear()
        .env("PATH", directory.path())
        .output()
        .expect("run fixed supervisor");

    assert_eq!(
        output.status.code(),
        Some(77),
        "runner returned {:?}; stdout={:?}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        stderr
            == "BLOCKED: one pinned BOOTSTRAP_READY and canonical GO authorized the fixed descriptor-relative private run. PID 1 proved the exact disposable parent/A/B baselines, two run-bound nsfs pins, two fixed veth pairs and four /30 addresses; installed the topology-bound generation-2 parent FORWARD policy before link activation; conditionally enabled only the disposable parent ip_forward record; activated all four ends; installed the two exact static endpoint /32 routes; and installed four exact affine NUD_PERMANENT neighbours with zero probes and zero proxy neighbours. Only structurally valid volatile NDA_CACHEINFO telemetry was excluded from neighbour equality. With those neighbours armed, PID 1 consumed zero-counter policy authority, opened one nonblocking close-on-exec raw ICMPv4 socket inside endpoint A, bound it to eth0 and 10.241.1.2, connected it to 10.241.2.2, and issued exactly one sendmsg with no retry for one 40-byte echo request. The request used the first two canonical run-ID ASCII bytes as its big-endian identifier, sequence 1, and the full 32-byte canonical ASCII run ID as payload. Before the absolute deadline, endpoint A received one exact 60-byte IPv4 echo reply; source, destination, receive interface and IP_PKTINFO, IPv4 and ICMP checksums, identifier, sequence, and full payload all matched. The socket closed before two identical complete generation-bracketed observations proved the request-accept, reply-accept, and terminal-drop counters at exactly packets/bytes 1/60, 1/60, and 0/0. Fresh semantic RTNL observations proved every one of the four veth ends at exactly one RX and one TX packet and 74 RX and TX bytes, with all other parsed link statistics zero, while routes, addresses, qdiscs, four permanent neighbours, zero probes, and zero proxy-neighbour records remained exact. PID 1 removed the neighbours in reverse endpoint B/A then parent B/A order, proved the exact routed state restored without changing the post-echo link telemetry, and re-proved the exact 1/60, 1/60, 0/0 policy-counter profile. It then converted the policy to counter-agnostic cleanup authority, deleted veth B then A, restored the exact original parent ip_forward record, proved pristine parent/endpoints under generation 2, deleted only the observed table handle, proved semantic-empty generation 3, retired lower owners, reversed nsfs/filesystem state, emitted the rollback checkpoint, and completed exact TERM/EOF/reap. The outer host ip_forward record remained byte-identical. This proves one fixed run-bound ICMPv4 echo request/reply exchange, its exact two-accept/zero-drop counter profile, matching four-veth link telemetry, and bounded configuration teardown. It does not prove packet absence, packet-capture privacy, a general VPN datapath, an ownership manifest, network-topology readiness, TOPOLOGY_READY, forced-crash cleanup, A14, A15, or acceptance evidence.\n"
            || stderr
                == "BLOCKED: anonymous namespaces, exact ID mappings, and a self-reexecuted PID 1 were verified, but kernel policy denied the fixed private-mount setup; no BOOTSTRAP_READY or GO was emitted.\n"
            || stderr
                == "BLOCKED: anonymous namespaces and exact ID mappings were verified, but kernel policy hid the required outer PID-1 proof; no GO was emitted.\n"
            || stderr
                == "BLOCKED: kernel policy did not permit the fixed anonymous namespace and ID-mapping bootstrap; no GO was emitted.\n"
            || stderr
                == "BLOCKED: anonymous namespaces were created, but kernel policy did not permit the required outer proof or exact ID mappings; no GO was emitted.\n",
        "unexpected blocked outcome: {stderr:?}"
    );
    assert!(!marker.exists(), "no command shim may be executed");
    assert_eq!(
        before,
        [
            namespace_identity("user"),
            namespace_identity("net"),
            namespace_identity("mnt"),
            namespace_identity("pid"),
            namespace_identity("pid_for_children"),
        ]
    );
    assert_eq!(
        mountinfo_before,
        bounded_host_record("/proc/self/mountinfo")
    );
    assert_eq!(ipv4_routes_before, bounded_host_record("/proc/net/route"));
    assert_eq!(
        ipv6_routes_before,
        bounded_host_record("/proc/net/ipv6_route")
    );
    assert_eq!(
        ipv4_forwarding_before,
        bounded_host_record("/proc/sys/net/ipv4/ip_forward")
    );
    assert_eq!(links_before, host_link_names());
}

#[test]
fn repeated_fixed_runs_preserve_outer_namespace_snapshot() {
    let _live_runner_guard = serialize_live_runner_mutations();
    let before = [
        namespace_identity("user"),
        namespace_identity("net"),
        namespace_identity("mnt"),
        namespace_identity("pid"),
        namespace_identity("pid_for_children"),
    ];
    let mut expected_stderr = None;
    for iteration in 0..8 {
        let output = Command::new(RUNNER)
            .arg("--run")
            .env_clear()
            .output()
            .expect("repeat fixed supervisor");
        assert_eq!(
            output.status.code(),
            Some(77),
            "iteration {iteration} returned {:?}; stdout={:?}; stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        if let Some(expected) = &expected_stderr {
            assert_eq!(
                &output.stderr, expected,
                "iteration {iteration} changed blocked route"
            );
        } else {
            expected_stderr = Some(output.stderr);
        }
    }
    assert_eq!(
        before,
        [
            namespace_identity("user"),
            namespace_identity("net"),
            namespace_identity("mnt"),
            namespace_identity("pid"),
            namespace_identity("pid_for_children"),
        ]
    );
}

#[test]
fn ignored_sigchld_is_rejected_before_any_child_is_spawned() {
    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg("trap '' CHLD\nexec \"$1\" --run")
        .arg("volparossa-sigchld-wrapper")
        .arg(RUNNER)
        .env_clear()
        .output()
        .expect("run with inherited ignored SIGCHLD");

    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "ERROR: fixed child process operation failed: inherited SIGCHLD disposition prevents exact child reaping\n"
    );
}

#[test]
fn ignored_lifecycle_signals_are_rejected_before_any_child_is_spawned() {
    for signal in ["HUP", "INT", "TERM"] {
        let output = Command::new("/bin/bash")
            .arg("-c")
            .arg("trap '' \"$1\"\nexec \"$2\" --run")
            .arg("volparossa-signal-wrapper")
            .arg(signal)
            .arg(RUNNER)
            .env_clear()
            .output()
            .expect("run with inherited ignored lifecycle signal");

        assert_eq!(output.status.code(), Some(70), "ignored {signal}");
        assert!(output.stdout.is_empty(), "ignored {signal}");
        assert_eq!(
            String::from_utf8(output.stderr).expect("UTF-8 stderr"),
            "ERROR: fixed child process operation failed: inherited lifecycle signal disposition is not exactly default\n",
            "ignored {signal}"
        );
    }
}

#[test]
fn preview_and_argument_surface_are_exact() {
    let preview = Command::new(RUNNER)
        .arg("--preview")
        .output()
        .expect("preview");
    assert!(preview.status.success());
    assert_eq!(
        String::from_utf8(preview.stdout).expect("UTF-8 preview"),
        "VOLPAROSSA fixed supervisor preview: the fixed disposable lifecycle now implements anonymous namespace bootstrap, exact ID mappings and PID-1/private-mount proof; pinned BOOTSTRAP_READY/GO; descriptor-relative run roots; two run-bound nsfs pins; two veth pairs; four /30 addresses; IPv6 addrgen NONE; the topology-bound generation-2 parent FORWARD policy; conditional disposable-parent IPv4 forwarding; four-end activation; two static /32 routes; four affine NUD_PERMANENT neighbours; one exact run-bound 40-byte raw ICMPv4 echo request from endpoint A and one exact 60-byte reply; two identical generation-bracketed counter observations at 1/60, 1/60, 0/0; exact four-veth telemetry at one RX and TX packet and 74 RX and TX bytes per end; reverse neighbour removal preserving post-echo telemetry; counter-agnostic link/policy teardown; semantic-empty generation 3; private-run rollback; and exact TERM/EOF/reap. The outer host IPv4-forwarding record remains byte-identical. This is fixed ICMP echo plus bounded rollback evidence; packet absence, packet-capture privacy, a general VPN datapath, an ownership manifest, network-topology readiness, TOPOLOGY_READY, forced-crash cleanup, A14, A15, and acceptance evidence remain unproved.\n"
    );
    assert!(preview.stderr.is_empty());

    for arguments in [vec![], vec!["--run", "extra"], vec!["--unknown"]] {
        let rejected = Command::new(RUNNER)
            .args(arguments)
            .output()
            .expect("rejected invocation");
        assert_eq!(rejected.status.code(), Some(64));
        assert!(rejected.stdout.is_empty());
        assert_eq!(
            String::from_utf8(rejected.stderr).expect("UTF-8 usage"),
            "usage: volparossa-netns-runner --preview|--run\n"
        );
    }
}

#[test]
fn externally_forged_hidden_child_parent_is_rejected() {
    let context = LaunchContext::new(
        RunId::parse("0123456789abcdef0123456789abcdef").expect("run ID"),
        protocol_namespace_identity("net"),
        protocol_namespace_identity("mnt"),
        protocol_namespace_identity("pid"),
    )
    .expect("distinct namespace identities");
    let (provisioning_parent, inherited_provisioning) =
        Socket::pair(Domain::UNIX, Type::SEQPACKET.cloexec(), None::<Protocol>)
            .expect("forged provisioning channel");
    let (_lifecycle_parent, inherited_lifecycle) =
        Socket::pair(Domain::UNIX, Type::SEQPACKET.cloexec(), None::<Protocol>)
            .expect("forged lifecycle channel");
    let (control_parent, inherited_control) =
        Socket::pair(Domain::UNIX, Type::SEQPACKET.cloexec(), None::<Protocol>)
            .expect("forged control channel");
    send_seqpacket_without_fd(
        &provisioning_parent,
        context.encode().expect("context encode").as_bytes(),
    )
    .expect("forged context send");
    provisioning_parent
        .shutdown(Shutdown::Write)
        .expect("finish forged provisioning");
    let inherited_provisioning: OwnedFd = inherited_provisioning.into();
    let inherited_control: OwnedFd = inherited_control.into();
    let inherited_lifecycle: OwnedFd = inherited_lifecycle.into();

    let status = Command::new(RUNNER)
        .arg(INTERNAL_CHILD_ARGUMENT)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited_provisioning))
        .stdout(Stdio::from(inherited_control))
        .stderr(Stdio::from(inherited_lifecycle))
        .status()
        .expect("forged child invocation");
    assert_eq!(status.code(), Some(70));
    assert_eq!(
        receive_seqpacket_without_fd(&control_parent, 4096)
            .expect_err("authentication failure must emit no bootstrap record")
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn pid_one_selector_without_required_namespace_and_channels_is_rejected() {
    let output = Command::new(RUNNER)
        .arg(INTERNAL_PID_ONE_ARGUMENT)
        .env_clear()
        .current_dir("/")
        .output()
        .expect("unprovisioned PID-one-selector invocation");

    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
