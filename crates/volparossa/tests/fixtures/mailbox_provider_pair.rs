// SPDX-License-Identifier: GPL-3.0-only
//! Isolated local-stream provider pair for external native mailbox consumer tests.
//! Build this example and the normal `volparossa` binary, and mount them side by side.
//! Run `mailbox-provider-pair <empty-private-directory>` in a loopback-only namespace.
//! Keep stdin open until both consumers finish. `ready` appears after four registrations.

#[path = "../support/mailbox_servers.rs"]
mod mailbox_servers;

use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicI32, AtomicUsize},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use nix::unistd::Uid;
use rand_core::OsRng;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::{
    process::Command,
    signal::unix::{SignalKind, signal},
    sync::oneshot,
};
use volparossa_content::mailbox::SignedMailboxGrant;
use volparossa_identity::{IdentityStore, Passphrase};
use zeroize::Zeroizing;

const LIFETIME: Duration = Duration::from_secs(900);

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

struct Participant {
    directory: PathBuf,
    identity: PathBuf,
    passphrase: PathBuf,
    invitation: PathBuf,
    key: VerifyingKey,
}

impl Participant {
    fn create(root: &Path, private: &Path, name: &str) -> Result<Self> {
        let directory = root.join(name);
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let identity = private.join(format!("identity-{name}"));
        let passphrase = private.join(format!("passphrase-{name}"));
        let invitation = private.join(format!("invitation-{name}"));
        let mut random = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *random)?;
        let secret = Zeroizing::new(hex::encode(random.as_slice()));
        private_file(&passphrase, secret.as_bytes())?;
        let account = IdentityStore::new(&identity).create(&Passphrase::new(secret.as_bytes())?)?;
        let key = VerifyingKey::from_bytes(&account.ed25519_public_key_bytes()?)?;
        Ok(Self {
            directory,
            identity,
            passphrase,
            invitation,
            key,
        })
    }

    async fn enroll(
        &self,
        sender: &Self,
        cli: &Path,
        socket: &Path,
        providers: &[Arc<SigningKey>; 2],
    ) -> Result<Grant> {
        let command = |operation: &str| {
            let mut cmd = Command::new(cli);
            cmd.arg("--control-socket")
                .arg(socket)
                .args(["content", "mailbox", operation])
                .arg("--identity")
                .arg(&self.identity)
                .arg("--passphrase-file")
                .arg(&self.passphrase)
                .arg("--invitation")
                .arg(&self.invitation)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            cmd
        };
        let mut invite = command("invite");
        invite
            .arg("--sender-key")
            .arg(hex::encode(sender.key.to_bytes()))
            .arg("--lifetime-seconds")
            .arg(LIFETIME.as_secs().to_string());
        for key in providers {
            invite
                .arg("--provider-key")
                .arg(hex::encode(key.verifying_key().to_bytes()));
        }
        ensure!(
            invite.stdout(Stdio::null()).status().await?.success(),
            "mailbox invitation failed"
        );
        let enrolled = command("enroll").output().await?;
        ensure!(
            enrolled.status.success()
                && serde_json::from_slice::<Value>(&enrolled.stdout)?["registered_providers"] == 2,
            "provider registration incomplete"
        );
        let raw = fs::read(&self.invitation)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let verified = SignedMailboxGrant::decode(&raw)?.verify(&self.key, now)?;
        Ok(Grant {
            hash: hex::encode(Sha256::digest(raw)),
            expires: verified.validity().expires,
        })
    }

    fn publish(
        &self,
        other: &Self,
        receive: &Grant,
        send: &Grant,
        cli: &Path,
        socket: &Path,
    ) -> Result<()> {
        let core = json!({"executable":cli,"socket":socket,"identity":self.identity,"passphrase":self.passphrase,
            "sendInvitation":other.invitation,"receiveInvitation":self.invitation,"remoteOwner":hex::encode(other.key.to_bytes())});
        let grants = json!({"sendGrant":send.hash,"receiveGrant":receive.hash,"expires":(receive.expires.min(send.expires)-1)*1000});
        private_file(
            &self.directory.join("core.json"),
            &serde_json::to_vec(&core)?,
        )?;
        private_file(
            &self.directory.join("grants.json"),
            &serde_json::to_vec(&grants)?,
        )
    }
}
struct Grant {
    hash: String,
    expires: u64,
}

fn require_private_namespace(root: &Path) -> Result<()> {
    let owner = Uid::effective();
    ensure!(
        !owner.is_root() && root.is_absolute() && root.canonicalize()? == root,
        "canonical private directory required"
    );
    let meta = fs::metadata(root)?;
    ensure!(
        meta.is_dir()
            && meta.uid() == owner.as_raw()
            && meta.mode() & 0o7777 == 0o700
            && fs::read_dir(root)?.next().is_none(),
        "empty owned private directory required"
    );
    let links = fs::read_to_string("/proc/net/dev")?;
    let mut names = links
        .lines()
        .filter_map(|row| row.split_once(':').map(|(name, _)| name.trim()));
    ensure!(
        names.next() == Some("lo") && names.next().is_none(),
        "isolated loopback namespace required"
    );
    Ok(())
}

async fn serve(root: &Path, cli: &Path) -> Result<()> {
    let private = tempfile::Builder::new()
        .prefix(".providers-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(root)?;
    let state = private.path();
    let a = Participant::create(root, state, "a")?;
    let b = Participant::create(root, state, "b")?;
    let keys = [
        Arc::new(SigningKey::generate(&mut OsRng)),
        Arc::new(SigningKey::generate(&mut OsRng)),
    ];
    let server = mailbox_servers::start(
        state,
        &keys,
        false,
        Arc::new(AtomicI32::new(0)),
        Arc::new(AtomicUsize::new(0)),
    );
    let socket = state.join("control.sock");
    let first = a.enroll(&b, cli, &socket, &keys).await?;
    let second = b.enroll(&a, cli, &socket, &keys).await?;
    a.publish(&b, &first, &second, cli, &socket)?;
    b.publish(&a, &second, &first, cli, &socket)?;
    private_file(&root.join("ready"), b"ready\n")?;
    server.await?;
    anyhow::bail!("mailbox listener stopped")
}

async fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("expected private directory"))?,
    );
    ensure!(args.next().is_none(), "expected one private directory");
    require_private_namespace(&root)?;
    let cli = std::env::current_exe()?.with_file_name("volparossa");
    ensure!(
        cli.canonicalize()? == cli && cli.is_file(),
        "paired CLI executable required"
    );
    let mut term = signal(SignalKind::terminate())?;
    let (stop, stopped) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = std::io::stdin().read(&mut [0u8; 1]);
        let _ = stop.send(());
    });
    let result = tokio::select! {
        result=serve(&root,&cli) => result,
        _=stopped => Ok(()),
        _=term.recv() => Ok(()),
        _=tokio::signal::ctrl_c() => Ok(()),
        ()=tokio::time::sleep(LIFETIME) => Err(anyhow::anyhow!("mailbox fixture expired")),
    };
    // Only retire the public handles we created. Consumers own their private handoff files.
    for path in [
        "ready",
        "a/core.json",
        "a/grants.json",
        "b/core.json",
        "b/grants.json",
    ] {
        match fs::remove_file(root.join(path)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => (),
        }
    }
    for name in ["a", "b"] {
        match fs::remove_dir(root.join(name)) {
            Err(e)
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                return Err(e.into());
            }
            _ => (),
        }
    }
    result
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    if run().await.is_err() {
        eprintln!("mailbox fixture failed");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
