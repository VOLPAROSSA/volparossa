// SPDX-License-Identifier: GPL-3.0-only
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use ed25519_dalek::VerifyingKey;
use nix::unistd::geteuid;
use sha2::{Digest, Sha256};
use volparossa_content::CHUNK_BYTES;
use volparossa_identity::{IdentityStore, Passphrase};

use super::Result;

pub(super) struct Fixture {
    pub(super) directory: tempfile::TempDir,
    pub(super) socket: PathBuf,
    pub(super) cli: PathBuf,
    pub(super) publisher: VerifyingKey,
    pub(super) bytes: Vec<u8>,
    pub(super) input_hash: [u8; 32],
    pub(super) identity_hash: [u8; 32],
    pub(super) binary_stamp: (u64, u64, u64, i64, i64),
}

impl Fixture {
    pub(super) fn create() -> Result<Self> {
        let directory = tempfile::tempdir().map_err(|_| "fixture_directory")?;
        let root = directory.path();
        for name in ["state", "control", "credentials"] {
            fs::create_dir(root.join(name)).map_err(|_| "fixture_subdirectory")?;
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700))
                .map_err(|_| "fixture_permissions")?;
        }
        let phrase = b"disposable explicitly public native-content fixture passphrase";
        private_file(&root.join("credentials/identity-passphrase"), phrase)?;
        let created = IdentityStore::new(root.join("state/identity.key"))
            .create(&Passphrase::new(phrase).map_err(|_| "fixture_passphrase")?)
            .map_err(|_| "fixture_identity")?;
        let publisher = VerifyingKey::from_bytes(
            &created
                .ed25519_public_key_bytes()
                .map_err(|_| "fixture_public_key")?,
        )
        .map_err(|_| "fixture_public_key")?;
        let identity_hash =
            Sha256::digest(read_private(&root.join("state/identity.key"), 65_536)?).into();
        private_file(&root.join("config.yaml"), b"roles:\n  client: false\n  relay: false\n  exit: false\nnetwork:\n  listen_addresses: [/ip4/127.0.0.1/udp/0/quic-v1]\n  bootstrap_peers: []\nprivacy:\n  metrics_enabled: false\ncontent_contribution:\n  enabled: false\ndns_cache:\n  enabled: false\nsharing:\n  enabled: false\ndownload_sharing:\n  enabled: false\nwifi_mesh:\n  enabled: false\n")?;
        let mut bytes = vec![0x41; CHUNK_BYTES + 137];
        bytes[CHUNK_BYTES..].fill(0x42);
        private_file(&root.join("public-synthetic.bin"), &bytes)?;
        let input_hash = Sha256::digest(&bytes).into();
        let cli = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/volparossa")
            .canonicalize()
            .map_err(|_| "cli_path")?;
        let expected = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .map_err(|_| "workspace_path")?
            .join("target/debug/volparossa");
        if cli != expected {
            return Err("cli_fixed_path");
        }
        let binary_stamp = executable_stamp(&expected)?;
        let socket = root.join("control/agent.sock");
        Ok(Self {
            directory,
            socket,
            cli,
            publisher,
            bytes,
            input_hash,
            identity_hash,
            binary_stamp,
        })
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    pub(super) fn verify_identity_and_binary(&self) -> Result<()> {
        if <[u8; 32]>::from(Sha256::digest(read_private(
            &self.path("state/identity.key"),
            65_536,
        )?)) != self.identity_hash
            || executable_stamp(&self.cli)? != self.binary_stamp
        {
            return Err("fixture_identity_or_binary_changed");
        }
        Ok(())
    }
}

pub(super) fn executable_stamp(path: &Path) -> Result<(u64, u64, u64, i64, i64)> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "cli_metadata")?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o100 == 0
        || metadata.len() == 0
    {
        return Err("cli_permissions");
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    ))
}

pub(super) fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "fixture_file")?;
    file.write_all(bytes).map_err(|_| "fixture_write")
}

pub(super) fn read_private(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "fixture_read")?;
    let metadata = file.metadata().map_err(|_| "fixture_read_metadata")?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > maximum
    {
        return Err("fixture_read_permissions");
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "fixture_read_bytes")?;
    if u64::try_from(bytes.len()).map_err(|_| "fixture_read_bound")? > maximum {
        return Err("fixture_read_bound");
    }
    Ok(bytes)
}

pub(super) fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("unexpected_output_effect"),
    }
}

pub(super) fn cache_stamp(path: &Path) -> Result<(u64, u64, [u8; 32], [u8; 32])> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "cache_metadata")?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("cache_permissions");
    }
    Ok((
        metadata.dev(),
        metadata.ino(),
        Sha256::digest(read_private(&path.join(".volparossa-owner-v1"), 1024)?).into(),
        Sha256::digest(read_private(&path.join(".volparossa-index-v1"), 65_536)?).into(),
    ))
}
