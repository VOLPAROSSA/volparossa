// SPDX-License-Identifier: GPL-3.0-only
use std::{
    ffi::OsString,
    net::Ipv4Addr,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::TcpStream,
    process::{Child, ChildStdout, Command},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use volparossa_content::VerifiedManifest;

use super::{
    Progress, Result,
    fixture::{Fixture, executable_stamp, private_file, read_private},
    process::{bounded, cli},
    site::Packed,
};

pub(super) fn preview_args(f: &Fixture, key: &str, hash: &str) -> Vec<OsString> {
    vec![
        "site".into(),
        "preview".into(),
        "--input".into(),
        f.path("reconstructed.bundle").into_os_string(),
        "--manifest".into(),
        f.path("manifest.pb").into_os_string(),
        "--publisher-key".into(),
        key.into(),
        "--expected-input-sha256".into(),
        hash.into(),
        "--lifetime-seconds".into(),
        "60".into(),
    ]
}
pub(super) async fn refusals(
    f: &Fixture,
    p: &Progress,
    packed: &Packed,
    work: Instant,
    total: Instant,
) -> Result<()> {
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
    for (key, hash, expected) in [
        (
            hex::encode(wrong.as_bytes()),
            hex::encode(packed.sha),
            b"local site publisher differs from the selected key".as_slice(),
        ),
        (
            hex::encode(f.publisher.as_bytes()),
            hex::encode([0; 32]),
            b"local site reviewed input digest differs".as_slice(),
        ),
    ] {
        let result = cli(f, preview_args(f, &key, &hash), p, work, total, true).await?;
        result.rejection(expected)?;
        p.count(|c| c.cli_rejections += 1);
    }
    Ok(())
}

pub(super) struct Preview {
    child: Option<Child>,
    stdout: Option<BufReader<ChildStdout>>,
    stderr: Option<JoinHandle<Result<Vec<u8>>>>,
    pub(super) port: Option<u16>,
}
impl Preview {
    pub(super) fn new() -> Self {
        Self {
            child: None,
            stdout: None,
            stderr: None,
            port: None,
        }
    }
    pub(super) async fn start(
        &mut self,
        f: &Fixture,
        p: &Progress,
        packed: &Packed,
        manifest: &VerifiedManifest,
        deadline: Instant,
    ) -> Result<Value> {
        if self.child.is_some() || Instant::now() >= deadline {
            return Err("preview_start_state");
        }
        let child = Command::new(&f.cli)
            .arg("--control-socket")
            .arg(&f.socket)
            .arg("content")
            .args(preview_args(
                f,
                &hex::encode(f.publisher.as_bytes()),
                &hex::encode(packed.sha),
            ))
            .env_clear()
            .env("LANG", "C")
            .env("TMPDIR", f.directory.path())
            .current_dir(f.directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "preview_spawn")?;
        self.child = Some(child);
        p.count(|c| c.positive_cli_started += 1);
        let child = self.child.as_mut().ok_or("preview_owner")?;
        self.stdout = Some(BufReader::new(child.stdout.take().ok_or("preview_stdout")?));
        let stderr = child.stderr.take().ok_or("preview_stderr")?;
        self.stderr = Some(tokio::spawn(bounded(stderr)));
        let ready = record(self.stdout.as_mut().ok_or("preview_stdout")?, deadline).await?;
        check_ready(&ready, packed, manifest)?;
        let port = checked_url(ready["site_url"].as_str().ok_or("preview_url")?)?;
        self.port = Some(port);
        Ok(ready)
    }
    pub(super) async fn shutdown(&mut self, p: &Progress, deadline: Instant) -> Result<()> {
        let pid = self
            .child
            .as_ref()
            .and_then(Child::id)
            .ok_or("preview_pid")?;
        kill(
            Pid::from_raw(i32::try_from(pid).map_err(|_| "preview_pid_bound")?),
            Signal::SIGTERM,
        )
        .map_err(|_| "preview_stop")?;
        let closed = record(self.stdout.as_mut().ok_or("preview_stdout")?, deadline).await?;
        if closed["operation"] != "local_site_preview_closed"
            || closed["source_snapshots_discarded"] != true
            || closed["reason"] != "terminated"
        {
            return Err("preview_closed_receipt");
        }
        let status = timeout_at(deadline, self.child.as_mut().ok_or("preview_owner")?.wait())
            .await
            .map_err(|_| "preview_join_deadline")?
            .map_err(|_| "preview_join")?;
        self.child = None;
        p.count(|c| c.positive_cli_joined += 1);
        let mut tail = Vec::new();
        timeout_at(
            deadline,
            self.stdout
                .as_mut()
                .ok_or("preview_stdout")?
                .take(65_537)
                .read_to_end(&mut tail),
        )
        .await
        .map_err(|_| "preview_tail_deadline")?
        .map_err(|_| "preview_tail")?;
        if !status.success() || !tail.is_empty() || !self.stderr_done(deadline).await?.is_empty() {
            return Err("preview_exit");
        }
        self.listener_closed(deadline).await
    }
    pub(super) async fn force_join(&mut self, deadline: Instant) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
            timeout_at(deadline, child.wait())
                .await
                .map_err(|_| "preview_cleanup_deadline")?
                .map_err(|_| "preview_cleanup_join")?;
            self.child = None;
        }
        let _ = self.stderr_done(deadline).await?;
        Ok(())
    }
    async fn stderr_done(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        if let Some(mut task) = self.stderr.take() {
            let result = timeout_at(deadline, &mut task).await;
            if let Ok(result) = result {
                result.map_err(|_| "preview_stderr_join")?
            } else {
                task.abort();
                let _ = task.await;
                Err("preview_stderr_deadline")
            }
        } else {
            Ok(Vec::new())
        }
    }
    async fn listener_closed(&self, deadline: Instant) -> Result<()> {
        let port = self.port.ok_or("preview_port")?;
        match timeout_at(deadline, TcpStream::connect((Ipv4Addr::LOCALHOST, port))).await {
            Ok(Err(_)) => Ok(()),
            _ => Err("preview_listener_not_closed"),
        }
    }
}
async fn record(reader: &mut BufReader<ChildStdout>, deadline: Instant) -> Result<Value> {
    let mut bytes = Vec::new();
    timeout_at(deadline, reader.take(65_537).read_until(b'\n', &mut bytes))
        .await
        .map_err(|_| "preview_record_deadline")?
        .map_err(|_| "preview_record")?;
    if bytes.len() > 65_536 || !bytes.ends_with(b"\n") {
        return Err("preview_record_bound");
    }
    serde_json::from_slice(&bytes).map_err(|_| "preview_record_shape")
}
pub(super) fn checked_url(url: &str) -> Result<u16> {
    let host = url
        .strip_prefix("http://")
        .and_then(|u| u.strip_suffix('/'))
        .ok_or("preview_url")?;
    let (domain, port) = host.rsplit_once(':').ok_or("preview_origin")?;
    let token = domain
        .strip_prefix("vp")
        .and_then(|d| d.strip_suffix(".localhost"))
        .ok_or("preview_host")?;
    if token.len() != 32
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("preview_host");
    }
    let port = port.parse::<u16>().map_err(|_| "preview_port")?;
    if port == 0 || url != format!("http://{domain}:{port}/") {
        return Err("preview_origin");
    }
    Ok(port)
}
fn check_ready(value: &Value, packed: &Packed, manifest: &VerifiedManifest) -> Result<()> {
    if value["operation"] != "local_site_preview_ready"
        || value["source"] != "local_signed_bundle"
        || value["sha256"] != hex::encode(packed.sha)
        || value["manifest_id"] != hex::encode(manifest.manifest_id())
        || value["publisher_key"] != hex::encode(manifest.publisher())
        || value["name"] != manifest.metadata().name
        || value["revision"].as_u64() != Some(manifest.metadata().revision)
        || value["publication_expires_unix_seconds"].as_u64() != Some(manifest.validity().expires)
        || value["bytes"].as_u64() != Some(manifest.length())
        || value["chunks"].as_u64() != u64::try_from(manifest.chunks().len()).ok()
        || value["assets"].as_u64() != u64::try_from(packed.assets.len()).ok()
        || value["expires_unix_seconds"]
            .as_u64()
            .is_none_or(|v| v > manifest.validity().expires)
    {
        return Err("preview_signed_binding");
    }
    for key in [
        "publisher_signature_verified",
        "original_signed_manifest_verified",
        "reviewed_input_sha256_matched",
        "native_publisher_authenticated",
        "static_only",
    ] {
        if value[key] != true {
            return Err("preview_auth_flags");
        }
    }
    for key in [
        "named_lookup_performed",
        "network_retrieval_performed",
        "https_origin_authenticated",
        "origin_authenticated",
        "globally_latest",
        "publisher_name_authority_verified",
        "internet_policy_permission_granted",
        "private_spool_created",
        "input_files_modified",
        "automatic_browser_open",
    ] {
        if value[key] != false {
            return Err("preview_scope_flags");
        }
    }
    for key in [
        "peer_bytes",
        "providers_used",
        "provider_peer_ids",
        "control_relay_peer_id",
        "cache_only",
        "private_spool_removed",
    ] {
        if value.get(key).is_some() {
            return Err("preview_fake_named_accounting");
        }
    }
    Ok(())
}

pub(super) struct Browser {
    child: Option<Child>,
}
impl Browser {
    pub(super) fn new() -> Self {
        Self { child: None }
    }
    pub(super) async fn observe(
        &mut self,
        f: &Fixture,
        ready: &Value,
        packed: &Packed,
        deadline: Instant,
    ) -> Result<Value> {
        let context = f.path("browser-handoff.json");
        let receipt = f.path("browser-receipt.json");
        private_file(&context,&serde_json::to_vec(&serde_json::json!({"schema":1,"url":ready["site_url"],"bundle_sha256":hex::encode(packed.sha),"bundle_bytes":packed.bytes.len(),"assets":packed.assets,"receipt":receipt})).map_err(|_| "browser_handoff")?)?;
        let node = PathBuf::from(std::env::var_os("STUDIO_NODE").ok_or("browser_node")?);
        let observer =
            PathBuf::from(std::env::var_os("STUDIO_VIEWER_OBSERVER").ok_or("browser_observer")?);
        let chrome = std::env::var_os("STUDIO_CHROME").ok_or("browser_chrome")?;
        checked_observer(&node, &observer, Path::new(&chrome))?;
        self.child = Some(
            Command::new(node)
                .arg(observer)
                .arg(context)
                .env_clear()
                .env("STUDIO_CHROME", chrome)
                .env("HOME", f.path("browser-home"))
                .env("XDG_CACHE_HOME", f.path("browser-home/cache"))
                .env("TMPDIR", f.directory.path())
                .env("LANG", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| "browser_spawn")?,
        );
        let status = timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(35)),
            self.child.as_mut().ok_or("browser_owner")?.wait(),
        )
        .await
        .map_err(|_| "browser_deadline")?
        .map_err(|_| "browser_join")?;
        self.child = None;
        if !status.success() {
            return Err("browser_failed");
        }
        let value = serde_json::from_slice(&read_private(&receipt, 4096)?)
            .map_err(|_| "browser_receipt")?;
        verify_receipt(&value, packed)?;
        Ok(value)
    }
    pub(super) async fn force_join(&mut self, deadline: Instant) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
            timeout_at(deadline, child.wait())
                .await
                .map_err(|_| "browser_cleanup_deadline")?
                .map_err(|_| "browser_cleanup_join")?;
            self.child = None;
        }
        Ok(())
    }
}
fn checked_observer(node: &Path, observer: &Path, chrome: &Path) -> Result<()> {
    if !node.is_absolute()
        || node.canonicalize().map_err(|_| "node_path")? != node
        || !observer.is_absolute()
        || observer.file_name() != Some(std::ffi::OsStr::new("browser-viewer.mjs"))
        || !matches!(
            chrome.to_str(),
            Some("/usr/bin/google-chrome" | "/usr/bin/google-chrome-stable")
        )
    {
        return Err("browser_fixed_paths");
    }
    executable_stamp(node)?;
    // Source authentication is owned by the paired controller; this read rejects
    // substituted links and nonregular/writable-by-other-user entrypoints.
    let metadata = std::fs::symlink_metadata(observer).map_err(|_| "observer_metadata")?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 128 * 1024
    {
        return Err("observer_profile");
    }
    Ok(())
}
pub(super) fn verify_receipt(value: &Value, packed: &Packed) -> Result<()> {
    if value.as_object().is_none_or(|v| v.len() != 12)
        || value["schema"] != 1
        || value["status"] != "passed"
        || value["bundle_sha256"] != hex::encode(packed.sha)
        || value["bundle_bytes"].as_u64() != u64::try_from(packed.bytes.len()).ok()
        || value["asset_count"].as_u64() != u64::try_from(packed.assets.len()).ok()
        || value["rendered_http_requests"]
            .as_u64()
            .is_none_or(|n| !(1..=1024).contains(&n))
    {
        return Err("browser_binding");
    }
    for key in [
        "visible_marker",
        "computed_37px",
        "all_assets_verified",
        "security_headers_preserved",
        "independent_browser",
        "browser_closed",
    ] {
        if value[key] != true {
            return Err("browser_observation");
        }
    }
    Ok(())
}
