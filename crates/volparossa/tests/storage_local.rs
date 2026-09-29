// SPDX-License-Identifier: GPL-3.0-only
//! Real, separate CLI processes exercising durable local opaque-blob storage.
//! These synthetic bytes are NOT an actual Signal archive or encrypted-message
//! fixture. These tests prove neither encryption nor remote/network custody.

use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

const CHUNK_BYTES: usize = 256 * 1024;

fn invoke(root: &Path, arguments: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_volparossa"));
    command.current_dir(root).args(["storage", "local"]);
    for (index, argument) in arguments.iter().enumerate() {
        if index > 0 && matches!(arguments[index - 1], "--store" | "--input" | "--output") {
            // Production CLI requires explicit absolute paths; all belong to this fixture.
            command.arg(root.join(argument));
        } else {
            command.arg(argument);
        }
    }
    command
        .stdin(Stdio::null())
        .output()
        .expect("run the real storage CLI in a fresh process")
}

fn successful(root: &Path, arguments: &[&str]) -> Value {
    let output = invoke(root, arguments);
    assert!(
        output.status.success(),
        "storage CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("storage CLI JSON result")
}

fn rejected(root: &Path, arguments: &[&str]) -> Output {
    let output = invoke(root, arguments);
    assert!(
        !output.status.success(),
        "operation unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "failed operation must not advertise a successful JSON result: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    output
}

fn init(root: &Path, capacity: usize) {
    successful(
        root,
        &[
            "init",
            "--store",
            "store",
            "--capacity-bytes",
            &capacity.to_string(),
            "--min-free-bytes",
            "0",
        ],
    );
}

fn status(root: &Path) -> Value {
    successful(root, &["status", "--store", "store"])
}

fn deposit_arguments<'a>(input: &'a str, sha256: &'a str) -> [&'a str; 10] {
    [
        "deposit",
        "--store",
        "store",
        "--input",
        input,
        "--sha256",
        sha256,
        "--lifetime-seconds",
        "300",
        "--already-encrypted",
    ]
}

fn restore_arguments<'a>(lease: &'a str, output: &'a str) -> [&'a str; 7] {
    [
        "restore", "--store", "store", "--lease", lease, "--output", output,
    ]
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn assert_accounting(root: &Path, reserved: usize, committed: usize) -> Value {
    let value = status(root);
    assert_eq!(value["reserved_bytes"], reserved);
    assert_eq!(value["committed_bytes"], committed);
    assert_eq!(value["scope"], "local-provider-only");
    assert_eq!(value["remote_replication"], false);
    assert_eq!(value["network_contribution_verified"], false);
    value["leases"].as_u64().expect("durable lease count");
    value
}

#[test]
fn storage_local_multichunk_restore_survives_source_loss_and_never_consumes_or_overwrites() {
    let directory = tempfile::tempdir().expect("local-storage fixture");
    let root = directory.path();
    // One complete chunk plus a partial second; a small fixture even with the
    // committed copy, SQLite bookkeeping and both restored outputs present.
    let bytes: Vec<u8> = (0..CHUNK_BYTES + 31)
        .map(|index| u8::try_from((index * 73 + index / 257) % 251).unwrap())
        .collect();
    let sha256 = digest(&bytes);
    fs::write(root.join("opaque-input"), &bytes).expect("synthetic opaque bytes");
    init(root, 2 * bytes.len());
    let deposited = successful(root, &deposit_arguments("opaque-input", &sha256));
    let lease = deposited["lease_id"].as_str().expect("opaque lease ID");
    assert!(!hex::decode(lease).expect("hex lease ID").is_empty());
    assert_eq!(deposited["ciphertext_bytes"], bytes.len());
    assert_eq!(deposited["sha256"], sha256);
    let expiry = deposited["expires_at_unix"].as_u64().expect("lease expiry");
    assert_eq!(assert_accounting(root, 0, bytes.len())["leases"], 1);

    fs::remove_file(root.join("opaque-input")).expect("remove only this fixture's source");
    for output in ["restored-first", "restored-second"] {
        successful(root, &restore_arguments(lease, output));
        assert_eq!(
            fs::read(root.join(output)).expect("restored ciphertext"),
            bytes
        );
        assert_accounting(root, 0, bytes.len());
    }
    // A genuinely different pre-existing output must remain untouched, not merely
    // be overwritten by identical restored bytes and look unchanged afterwards.
    fs::write(
        root.join("existing-output"),
        b"do not replace this caller file",
    )
    .expect("no-clobber sentinel");
    rejected(root, &restore_arguments(lease, "existing-output"));
    assert_eq!(
        fs::read(root.join("existing-output")).expect("retained output"),
        b"do not replace this caller file"
    );
    assert_accounting(root, 0, bytes.len());

    let renewed = successful(
        root,
        &[
            "renew",
            "--store",
            "store",
            "--lease",
            lease,
            "--lifetime-seconds",
            "600",
        ],
    );
    assert!(renewed["expires_at_unix"].as_u64().expect("renewed expiry") > expiry);
    assert_accounting(root, 0, bytes.len());
    successful(root, &["delete", "--store", "store", "--lease", lease]);
    assert_eq!(assert_accounting(root, 0, 0)["leases"], 0);
    rejected(root, &restore_arguments(lease, "after-delete"));
    assert!(!root.join("after-delete").exists());
    assert_eq!(
        fs::read(root.join("restored-first")).expect("caller-owned restored file"),
        bytes
    );
}

#[test]
fn storage_local_wrong_hash_never_commits_and_keeps_the_failed_reservation_accounted() {
    let directory = tempfile::tempdir().expect("local-storage hash fixture");
    let root = directory.path();
    init(root, 2 * CHUNK_BYTES);
    let original = b"a pre-existing committed opaque object";
    fs::write(root.join("original"), original).expect("original input");
    let original_receipt = successful(root, &deposit_arguments("original", &digest(original)));
    let lease = original_receipt["lease_id"]
        .as_str()
        .expect("original lease");
    let invalid = vec![0x91; CHUNK_BYTES + 17];
    fs::write(root.join("wrong-hash-input"), &invalid).expect("synthetic opaque object");
    let wrong_hash = hex::encode([0_u8; 32]);
    assert_ne!(digest(&invalid), wrong_hash);
    let failure = rejected(root, &deposit_arguments("wrong-hash-input", &wrong_hash));
    let diagnostic = String::from_utf8(failure.stderr).expect("failed-deposit diagnostic");
    let failed_lease = diagnostic
        .split_once("deposit incomplete; local reservation ")
        .expect("failed deposit identifies the retained reservation for its owner")
        .1
        .split_whitespace()
        .next()
        .expect("failed reservation ID");
    assert!(
        !hex::decode(failed_lease)
            .expect("hex reservation ID")
            .is_empty()
    );
    assert_ne!(failed_lease, lease);
    for _ in 0..2 {
        assert_eq!(
            assert_accounting(root, invalid.len(), original.len())["leases"],
            2
        );
    }
    rejected(root, &restore_arguments(failed_lease, "uncommitted-output"));
    assert!(!root.join("uncommitted-output").exists());
    fs::remove_file(root.join("original")).expect("remove only fixture source");
    successful(root, &restore_arguments(lease, "original-restored"));
    assert_eq!(
        fs::read(root.join("original-restored")).expect("original restored"),
        original
    );
    let delete_failed = ["delete", "--store", "store", "--lease", failed_lease];
    assert_eq!(successful(root, &delete_failed)["removed"], true);
    assert_eq!(assert_accounting(root, 0, original.len())["leases"], 1);
    assert_eq!(successful(root, &delete_failed)["removed"], false);
    assert_accounting(root, 0, original.len());
    successful(root, &["delete", "--store", "store", "--lease", lease]);
    assert_eq!(assert_accounting(root, 0, 0)["leases"], 0);
}

#[test]
fn storage_local_requires_explicit_ciphertext_confirmation_without_reserving_capacity() {
    let directory = tempfile::tempdir().expect("local-storage confirmation fixture");
    let root = directory.path();
    init(root, CHUNK_BYTES);
    let bytes = b"synthetic opaque bytes, not proof of encryption";
    fs::write(root.join("input"), bytes).expect("fixture input");
    let sha256 = digest(bytes);
    let arguments = deposit_arguments("input", &sha256);
    rejected(root, &arguments[..arguments.len() - 1]);
    assert_accounting(root, 0, 0);
    assert_eq!(
        fs::read(root.join("input")).expect("untouched input"),
        bytes
    );
}

#[test]
fn storage_local_quota_rejection_preserves_the_existing_lease_and_ciphertext() {
    let directory = tempfile::tempdir().expect("local-storage quota fixture");
    let root = directory.path();
    let original = vec![0x73; CHUNK_BYTES / 4];
    init(root, original.len() + 31);
    fs::write(root.join("original"), &original).expect("original input");
    let receipt = successful(root, &deposit_arguments("original", &digest(&original)));
    let lease = receipt["lease_id"].as_str().expect("original lease");
    let rejected_bytes = vec![0x29; 32];
    fs::write(root.join("over-quota"), &rejected_bytes).expect("second input");
    rejected(
        root,
        &deposit_arguments("over-quota", &digest(&rejected_bytes)),
    );
    assert_accounting(root, 0, original.len());
    fs::remove_file(root.join("original")).expect("remove only fixture source");
    successful(root, &restore_arguments(lease, "still-restorable"));
    assert_eq!(
        fs::read(root.join("still-restorable")).expect("retained lease bytes"),
        original
    );
    assert_accounting(root, 0, original.len());
}
