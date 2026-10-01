//! Explicit admin grants for the separate, capability-limited browser app socket.

use std::{
    fs::{self, File},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use clap::{Args, Subcommand};
use serde::Serialize;
use volparossa_local_control::{
    BrowserGatewayGrantRequest, BrowserGatewayGranted, control_request::Operation,
    control_response::Payload,
};
use zeroize::Zeroizing;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Authorize one app UID and exact destination; requires the admin control socket.
    Grant(Grant),
}

#[derive(Debug, Args)]
pub(crate) struct Grant {
    /// UID allowed to redeem the one-use capability on the limited app socket.
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..=4_294_967_294))]
    app_uid: u32,
    /// Exact canonical lowercase ASCII DNS hostname, not an IP address or URL.
    #[arg(long, value_parser = parse_hostname)]
    hostname: String,
    /// Exact destination port. The current Exit policy must independently allow it.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=65535))]
    port: u16,
    /// Opaque, app-owned partition identity: 32 bytes encoded as 64 hex characters.
    #[arg(long, value_parser = parse_partition)]
    partition: [u8; 32],
    /// Short-lived grant/attachment expiry, in seconds (at most five minutes).
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u32).range(1..=300))]
    lifetime_seconds: u32,
    /// NEW absolute 0600 JSON file containing a secret, single-use, expiring capability.
    /// Deliver privately to the app; no default file or secret stdout output is used.
    #[arg(long, value_name = "NEW_PRIVATE_FILE")]
    output: PathBuf,
}

fn parse_hostname(value: &str) -> std::result::Result<String, String> {
    let canonical = volparossa_policy::normalize_domain(value)
        .map_err(|_| "expected one canonical DNS hostname, not a URL or IP".to_owned())?;
    if !value.is_ascii() || canonical != value {
        return Err("hostname must already be canonical lowercase ASCII".to_owned());
    }
    Ok(canonical)
}

fn parse_partition(value: &str) -> std::result::Result<[u8; 32], String> {
    let mut partition = [0; 32];
    hex::decode_to_slice(value, &mut partition)
        .map_err(|_| "partition must be exactly 32 bytes of hex".to_owned())?;
    Ok(partition)
}

pub(crate) async fn run(command: Command, socket: &Path) -> Result<()> {
    let Command::Grant(args) = command;
    let report = grant(&args, socket).await?;
    println!("{report}");
    Ok(())
}

async fn grant(args: &Grant, socket: &Path) -> Result<serde_json::Value> {
    require_new_output(&args.output)?;
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        crate::control::request(
            socket,
            Operation::BrowserGatewayGrant(BrowserGatewayGrantRequest {
                app_uid: args.app_uid,
                hostname: args.hostname.clone(),
                port: u32::from(args.port),
                partition: args.partition.to_vec(),
                lifetime_seconds: args.lifetime_seconds,
            }),
        ),
    )
    .await
    .context("browser grant control deadline exceeded")??;
    ensure!(
        response.diagnostic_code == "BROWSER_GATEWAY_GRANTED",
        "unexpected browser grant diagnostic"
    );
    let Some(Payload::BrowserGatewayGranted(mut reply)) = response.payload else {
        anyhow::bail!("missing typed browser grant reply")
    };
    validate_reply(args, &reply, crate::doctor::unix_millis()?)?;
    let capability = Zeroizing::new(std::mem::take(&mut reply.capability));
    let encoded_capability = Zeroizing::new(hex::encode(&*capability));
    let file = GrantFile {
        version: 1,
        app_uid: args.app_uid,
        app_socket: &reply.app_socket,
        capability: &encoded_capability,
        hostname: &reply.hostname,
        port: reply.port,
        partition: hex::encode(&reply.partition),
        expires_at_ms: reply.expires_at_ms,
        overlay_only: true,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&file)?);
    save_new(&args.output, &bytes)?;
    Ok(serde_json::json!({
        "operation": "browser_gateway_grant", "grant_written": true,
        "output": args.output, "single_use": true, "overlay_only": true,
    }))
}

// Deliberately no Debug: the serialized capability belongs only in the explicit file.
#[derive(Serialize)]
struct GrantFile<'a> {
    version: u32,
    app_uid: u32,
    app_socket: &'a str,
    capability: &'a str,
    hostname: &'a str,
    port: u32,
    partition: String,
    expires_at_ms: u64,
    overlay_only: bool,
}

fn validate_reply(args: &Grant, reply: &BrowserGatewayGranted, now: u64) -> Result<()> {
    ensure!(
        reply.hostname == args.hostname
            && reply.port == u32::from(args.port)
            && reply.partition == args.partition
            && reply.capability.len() == 32
            && reply.capability.iter().any(|byte| *byte != 0)
            && reply.expires_at_ms > now
            && reply.expires_at_ms <= now.saturating_add(u64::from(args.lifetime_seconds) * 1000),
        "browser grant differs from requested scope or has expired"
    );
    ensure!(
        !reply.app_socket.is_empty()
            && reply.app_socket.len() < 108
            && !reply.app_socket.bytes().any(|byte| byte.is_ascii_control())
            && Path::new(&reply.app_socket).is_absolute()
            && Path::new(&reply.app_socket)
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "browser grant app socket is not a bounded absolute path"
    );
    Ok(())
}

fn require_new_output(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.file_name().is_some()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "browser grant output must be a new absolute file"
    );
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("cannot inspect browser grant output"),
        Ok(_) => anyhow::bail!("browser grant output already exists"),
    }
    let parent = path
        .parent()
        .context("browser grant output has no parent")?;
    let metadata = fs::symlink_metadata(parent).context("cannot inspect output directory")?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "browser grant output parent must be a real directory"
    );
    Ok(())
}

fn save_new(path: &Path, bytes: &[u8]) -> Result<()> {
    require_new_output(path)?;
    ensure!(bytes.len() <= 4096, "browser grant file exceeds bound");
    let parent = path
        .parent()
        .context("browser grant output has no parent")?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    pending
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    pending.write_all(bytes)?;
    pending.write_all(b"\n")?;
    pending.as_file().sync_all()?;
    pending
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "browser_tests.rs"]
mod tests;
