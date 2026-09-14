// SPDX-License-Identifier: GPL-3.0-only
//! Separate-process CLI smoke; this does not claim network retrieval or mailbox delivery.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    process::{Command, Output, Stdio},
};

use serde_json::Value;
use volparossa_identity::{IdentityStore, Passphrase};

fn invoke(root: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_volparossa"))
        .current_dir(root)
        .arg("content")
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("run the actual CLI binary in a fresh process")
}

fn successful(root: &Path, arguments: &[&str]) -> Value {
    let output = invoke(root, arguments);
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON result")
}

fn prepare_identities(root: &Path) -> [Vec<u8>; 2] {
    let password = b"temporary CLI process smoke passphrase";
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("passphrase"))
        .expect("strict passphrase file")
        .write_all(password)
        .expect("write fixture passphrase");
    let passphrase = Passphrase::new(password).expect("fixture passphrase");
    for name in ["sender", "recipient"] {
        drop(
            IdentityStore::new(root.join(name))
                .create(&passphrase)
                .expect("create an encrypted fixture identity"),
        );
    }
    ["sender", "recipient"]
        .map(|name| fs::read(root.join(name)).expect("retain original encrypted identity bytes"))
}

fn open_arguments<'a>(identity: &'a str, sender_key: &'a str) -> [&'a str; 15] {
    [
        "open-message",
        "--manifest",
        "manifest.pb",
        "--sender-key",
        sender_key,
        "--identity",
        identity,
        "--passphrase-file",
        "passphrase",
        "--cache",
        "ciphertext",
        "--output",
        "plaintext-output",
        "--min-free-bytes",
        "0",
    ]
}

#[test]
fn private_message_round_trip_uses_fresh_cli_processes_and_preserves_identities() {
    let directory = tempfile::tempdir().expect("private fixture directory");
    let root = directory.path();
    let identities = prepare_identities(root);
    let recipient_args = [
        "recipient-key",
        "--identity",
        "recipient",
        "--passphrase-file",
        "passphrase",
    ];
    let recipient = successful(root, &recipient_args);
    assert_eq!(recipient["private_key_exported"], false);
    assert_eq!(recipient["network_publication"], false);
    assert_eq!(successful(root, &recipient_args), recipient);
    let recipient_key = recipient["recipient_public_key_hex"]
        .as_str()
        .expect("public key");
    let payload = b"A private message crossing actual CLI process lifetimes.\n\0\xff";
    fs::write(root.join("input"), payload).expect("explicit original plaintext");
    let published = successful(
        root,
        &[
            "publish-message",
            "--input",
            "input",
            "--recipient-key",
            recipient_key,
            "--identity",
            "sender",
            "--passphrase-file",
            "passphrase",
            "--cache",
            "ciphertext",
            "--manifest",
            "manifest.pb",
            "--lifetime-seconds",
            "300",
            "--min-free-bytes",
            "0",
        ],
    );
    assert_eq!(published["network_publication"], false);
    let sender_key = published["publisher_key_hex"].as_str().expect("sender key");
    fs::remove_file(root.join("input")).expect("remove only this fixture's original plaintext");
    let wrong_recipient = invoke(root, &open_arguments("sender", sender_key));
    assert!(!wrong_recipient.status.success());
    assert!(wrong_recipient.stdout.is_empty());
    let output_path = root.join("plaintext-output");
    assert!(
        !output_path.exists(),
        "wrong recipient must expose no plaintext"
    );
    let opened = successful(root, &open_arguments("recipient", sender_key));
    assert_eq!(opened["network_retrieval"], false);
    assert_eq!(opened["bytes"], payload.len());
    assert_eq!(fs::read(&output_path).expect("decrypted file"), payload);
    assert_eq!(
        fs::metadata(&output_path)
            .expect("output metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        !invoke(root, &open_arguments("recipient", sender_key))
            .status
            .success()
    );
    assert_eq!(
        fs::read(&output_path).expect("unchanged no-clobber output"),
        payload
    );
    for (name, encrypted) in ["sender", "recipient"].into_iter().zip(identities) {
        assert_eq!(
            fs::read(root.join(name)).expect("identity remains present"),
            encrypted
        );
    }
}
