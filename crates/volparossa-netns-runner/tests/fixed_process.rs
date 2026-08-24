//! Real-process regressions for the fixed bounded isolation-supervisor boundary.

use std::{
    fs,
    net::Shutdown,
    os::fd::OwnedFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

use socket2::{Domain, Protocol, Socket, Type};
use tempfile::tempdir;
use volparossa_linux_uapi::{receive_seqpacket_without_fd, send_seqpacket_without_fd};
use volparossa_netns_runner::{INTERNAL_CHILD_ARGUMENT, INTERNAL_PID_ONE_ARGUMENT};
use volparossa_test_support::{LaunchContext, NamespaceIdentity, RunId};

const RUNNER: &str = env!("CARGO_BIN_EXE_volparossa-netns-runner");
const MAXIMUM_HOST_RECORD_BYTES: u64 = 1024 * 1024;

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
            == "BLOCKED: one pinned BOOTSTRAP_READY and canonical GO authorized descriptor-relative private-run roots and two empty namespace slots; PID 1 proved and removed every created object in exact reverse order, emitted one rollback-complete checkpoint, and the outer independently re-proved empty private mounts before fixed pidfd-to-PID1-signalfd TERM, post-GO cleanup-required EOF, and exact reap. No namespace pin, network-topology object, TOPOLOGY_READY, A14, A15, or acceptance evidence was produced.\n"
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
}

#[test]
fn repeated_fixed_runs_preserve_outer_namespace_snapshot() {
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
        "VOLPAROSSA fixed supervisor preview: anonymous namespace bootstrap, exact UID/GID mapping, exact self-reexec PID-1 proof, private mounts, fixed pidfd-to-signalfd supervision, the exact new-netns RTNL baseline, a descriptor-anchored stable canonical IPv4 ip_forward value, zero nftables tables bracketed by unchanged generation 1, one pinned BOOTSTRAP_READY, one canonical GO, and descriptor-relative private-run roots and empty namespace slots with exact reverse rollback are implemented; namespace pins, network-topology objects, TOPOLOGY_READY, A14, A15, and acceptance evidence remain blocked.\n"
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
