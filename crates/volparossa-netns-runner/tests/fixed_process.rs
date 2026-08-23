//! Real-process regressions for the fixed, non-mutating supervisor boundary.

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
use volparossa_linux_uapi::send_seqpacket_without_fd;
use volparossa_netns_runner::INTERNAL_CHILD_ARGUMENT;
use volparossa_test_support::{LaunchContext, NamespaceIdentity, RunId};

const RUNNER: &str = env!("CARGO_BIN_EXE_volparossa-netns-runner");

fn namespace_identity(name: &str) -> (u64, u64) {
    let metadata = fs::metadata(format!("/proc/self/ns/{name}")).expect("namespace metadata");
    (metadata.dev(), metadata.ino())
}

fn protocol_namespace_identity(name: &str) -> NamespaceIdentity {
    let (device, inode) = namespace_identity(name);
    NamespaceIdentity::new(device, inode).expect("nonzero namespace identity")
}

fn write_command_shims(directory: &Path, marker: &Path) {
    for name in ["ip", "mount", "nft", "nsenter", "sysctl", "unshare", "wg"] {
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
        namespace_identity("net"),
        namespace_identity("mnt"),
        namespace_identity("pid"),
    ];

    let output = Command::new(RUNNER)
        .arg("--run")
        .env_clear()
        .env("PATH", directory.path())
        .output()
        .expect("run fixed supervisor");

    assert_eq!(output.status.code(), Some(77));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "BLOCKED: fixed child provisioning completed without GO; isolated namespace bootstrap is not implemented.\n"
    );
    assert!(!marker.exists(), "no command shim may be executed");
    assert_eq!(
        before,
        [
            namespace_identity("net"),
            namespace_identity("mnt"),
            namespace_identity("pid"),
        ]
    );
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
        "VOLPAROSSA fixed supervisor preview: inherited IPC and exact child reaping; namespace bootstrap and every network mutation remain blocked.\n"
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
    send_seqpacket_without_fd(
        &provisioning_parent,
        context.encode().expect("context encode").as_bytes(),
    )
    .expect("forged context send");
    provisioning_parent
        .shutdown(Shutdown::Write)
        .expect("finish forged provisioning");
    let inherited_provisioning: OwnedFd = inherited_provisioning.into();
    let inherited_lifecycle: OwnedFd = inherited_lifecycle.into();

    let status = Command::new(RUNNER)
        .arg(INTERNAL_CHILD_ARGUMENT)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited_provisioning))
        .stdout(Stdio::null())
        .stderr(Stdio::from(inherited_lifecycle))
        .status()
        .expect("forged child invocation");
    assert_eq!(status.code(), Some(70));
}
