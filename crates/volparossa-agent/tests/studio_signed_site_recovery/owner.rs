// SPDX-License-Identifier: GPL-3.0-only
//! Disposable owner terminal. The signed CLI retains its normal controlling-terminal path.
use std::{
    fs::File,
    io::{Read, Write},
    process::Stdio,
    time::Duration,
};

use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    pty::openpty,
    sys::termios::{LocalFlags, tcgetattr},
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    process::Command,
    time::sleep,
};
use volparossa_content::site::SiteBundle;

use super::{
    Result,
    fixture::{FIXTURE_PASSPHRASE, Fixture},
    site::{NAME, Packed, now},
};

pub(super) struct OwnerTerminal(AsyncFd<File>);

impl OwnerTerminal {
    pub(super) fn command(fixture: &Fixture) -> Result<(Command, Self)> {
        let pair = openpty(None, None).map_err(|_| "owner_pty")?;
        for fd in [&pair.master, &pair.slave] {
            fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|_| "owner_pty_cloexec")?;
        }
        fcntl(&pair.master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|_| "owner_pty_nonblocking")?;
        let master = AsyncFd::new(File::from(pair.master)).map_err(|_| "owner_pty_async")?;
        // The child inherits our process group and is not its leader, so setsid
        // execs the real CLI in place. stdout and stderr stay independent of /dev/tty.
        let mut command = Command::new("/usr/bin/setsid");
        command
            .args(["--ctty", "--"])
            .arg(&fixture.cli)
            .stdin(Stdio::from(pair.slave));
        Ok((command, Self(master)))
    }

    async fn through(&self, prompt: &str) -> Result<String> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(prompt.as_bytes()) {
            let mut buffer = [0; 4096];
            let count = self
                .0
                .async_io(Interest::READABLE, |mut fd| fd.read(&mut buffer))
                .await
                .map_err(|_| "owner_pty_read")?;
            if count == 0 || bytes.len() + count > 65536 {
                return Err("owner_prompt_bound");
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8(bytes).map_err(|_| "owner_prompt_utf8")
    }

    async fn line(&self, bytes: &[u8]) -> Result<()> {
        let mut line = bytes.to_vec();
        line.push(b'\n');
        let count = self
            .0
            .async_io(Interest::WRITABLE, |mut fd| fd.write(&line))
            .await
            .map_err(|_| "owner_pty_write")?;
        if count != line.len() {
            return Err("owner_pty_short_write");
        }
        Ok(())
    }

    pub(super) async fn authorize(
        &self,
        fixture: &Fixture,
        packed: &Packed,
        lifetime: u64,
    ) -> Result<u64> {
        let digest = hex::encode(packed.sha);
        let confirmation = format!("SIGN {}", &digest[..12]);
        let body = self
            .through(&format!(
                "Type {confirmation} to sign, or press Enter to cancel: "
            ))
            .await?;
        let expires = verify_display(&body, &hex::encode(fixture.publisher.as_bytes()), packed)?;
        if !expires
            .checked_sub(now()?)
            .is_some_and(|seconds| (1..=lifetime).contains(&seconds))
        {
            return Err("owner_expiry_out_of_range");
        }
        for (label, name) in [
            ("Manifest       ", "manifest.pb"),
            ("Cache          ", "source-cache"),
        ] {
            let path = fixture.path(name);
            let line = format!(
                "{label}{}",
                path.as_os_str().as_encoded_bytes().escape_ascii()
            );
            if !body.lines().any(|item| item == line) {
                return Err("owner_output_path");
            }
        }
        self.line(confirmation.as_bytes()).await?;
        self.through("VOLPAROSSA identity passphrase: ").await?;
        // The prompt can be printed just before the password reader disables echo.
        // The caller's single deadline also covers this wait and reaps the child.
        while tcgetattr(self.0.get_ref())
            .map_err(|_| "owner_pty_flags")?
            .local_flags
            .contains(LocalFlags::ECHO)
        {
            sleep(Duration::from_millis(2)).await;
        }
        self.line(FIXTURE_PASSPHRASE).await?;
        Ok(expires)
    }
}

pub(super) fn verify_display(body: &str, publisher: &str, packed: &Packed) -> Result<u64> {
    let lines: Vec<_> = body.lines().collect();
    let expected = [
        format!("Publisher key  {publisher}"),
        format!("Site name      \"{NAME}\""),
        "Revision       1".to_owned(),
        "Cache limits   33554432 bytes, 128 chunks, 67108864 bytes minimum free".to_owned(),
        format!("Bundle SHA-256 {}", hex::encode(packed.sha)),
        format!(
            "{} bytes in the bundle. {} public assets:",
            packed.bytes.len(),
            packed.assets.len()
        ),
    ];
    if !expected.iter().all(|line| lines.contains(&line.as_str())) {
        return Err("owner_display_binding");
    }
    let mut expiries = lines
        .iter()
        .filter_map(|line| line.strip_prefix("Expires at     "));
    let expires = expiries
        .next()
        .and_then(|value| value.strip_suffix(" UTC (Unix seconds)"))
        .and_then(|value| value.parse().ok())
        .ok_or("owner_display_expiry")?;
    if expiries.next().is_some() {
        return Err("owner_display_expiry");
    }
    let bundle = SiteBundle::inspect(&packed.bytes).map_err(|_| "owner_site_index")?;
    let mut displayed = lines.iter().copied().filter(|line| line.starts_with("  "));
    for asset in bundle {
        let row = packed
            .assets
            .iter()
            .find(|row| row["path"].as_str() == Some(asset.path.as_str()))
            .ok_or("owner_zip_asset")?;
        let hash = row["sha256"].as_str().ok_or("owner_zip_digest")?;
        let expected = format!(
            "  {}  {} bytes  {}  {hash}",
            asset.path.escape_default(),
            asset.length,
            asset.content_type
        );
        if row["bytes"].as_u64() != Some(asset.length)
            || displayed.next() != Some(expected.as_str())
        {
            return Err("owner_display_asset");
        }
    }
    if displayed.next().is_some() {
        return Err("owner_display_asset");
    }
    Ok(expires)
}
