//! Local static assets authenticated by a native publisher, never an HTTPS origin.
//! The opaque sandbox allows scripts and local media, not cookies, workers, frames,
//! forms, external requests or a dynamic server. No browser is opened automatically.

#[path = "http.rs"]
mod http;

use std::{
    io::{SeekFrom, Write as _},
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use rand_core::{OsRng, RngCore as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncSeekExt as _},
    net::{TcpListener, TcpStream},
    signal::unix::{Signal, SignalKind, signal},
    task::JoinSet,
    time::{Instant, sleep_until, timeout_at},
};
use volparossa_content::{
    MAX_OBJECT_BYTES,
    site::{SITE_CONTENT_TYPE, SiteBundle},
};

use super::Open;
use crate::content::{
    named_download::{self, VerifiedNamedDownload},
    now_seconds,
};

const MAX_CONCURRENT: usize = 8;
const MAX_REQUESTS: usize = 4096;

pub(super) async fn run(args: Open, socket: &Path) -> Result<()> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let directory = tempfile::Builder::new()
        .prefix("volparossa-site-")
        .tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let state = tokio::select! {
        result = prepare(&args, socket, directory.path()) => result?,
        _ = interrupt.recv() => bail!("site preparation interrupted; private spool discarded"),
        _ = terminate.recv() => bail!("site preparation stopped; private spool discarded"),
    };
    // Binding follows both complete publisher-authenticated delivery and canonical site decoding.
    state.check_live()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut token = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut token)
        .context("cannot create private site host")?;
    let host = format!(
        "vp{}.localhost:{}",
        hex::encode(token),
        listener.local_addr()?.port()
    );
    let state = Arc::new(Site { host, ..state });
    let mut report = state.report();
    report["operation"] = "native_site_ready".into();
    report["site_url"] = format!("http://{}/", state.host).into();
    state.check_live()?;
    emit(&report)?;
    let mut tasks = JoinSet::new();
    let result = serve(
        &listener,
        &state,
        &mut tasks,
        &mut interrupt,
        &mut terminate,
    )
    .await;
    // Never remove the private spool while an aborted response task can still own its file.
    drop(listener);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(tasks);
    drop(state);
    directory
        .close()
        .context("cannot remove private site spool")?;
    let outcome = result?;
    report["operation"] = "native_site_closed".into();
    report["private_spool_removed"] = true.into();
    report["reason"] = outcome.reason.into();
    report["completed_http_requests"] = outcome.completed.into();
    report["asset_body_bytes"] = outcome.bytes.into();
    emit(&report)
}

async fn prepare(args: &Open, socket: &Path, parent: &Path) -> Result<Site> {
    let download =
        named_download::prepare(&args.fetch_args(parent.join("site.bundle")), socket, parent)
            .await?;
    if download.manifest().metadata().content_type != SITE_CONTENT_TYPE {
        bail!("named publication is not a native static-site bundle");
    }
    let length = download.manifest().length();
    if length > MAX_OBJECT_BYTES {
        bail!("site exceeds native object limit");
    }
    let mut file = tokio::fs::File::from_std(download.as_file().try_clone()?);
    let mut bytes = Vec::new();
    timeout_at(download.authority_deadline(), async {
        file.seek(SeekFrom::Start(0)).await?;
        file.take(length + 1).read_to_end(&mut bytes).await
    })
    .await
    .context("site expired while reading verified spool")??;
    if u64::try_from(bytes.len())? != length {
        bail!("verified site spool changed length");
    }
    let bundle = SiteBundle::decode(bytes)?;
    download.check_live()?;
    let deadline = download
        .authority_deadline()
        .min(Instant::now() + Duration::from_secs(args.lifetime_seconds));
    let expires = download
        .expires()
        .min(now_seconds()?.saturating_add(args.lifetime_seconds));
    Ok(Site {
        download,
        bundle,
        deadline,
        expires,
        host: String::new(),
    })
}

struct Site {
    download: VerifiedNamedDownload,
    bundle: SiteBundle,
    deadline: Instant,
    expires: u64,
    host: String,
}

impl Site {
    fn check_live(&self) -> Result<()> {
        self.download.check_live()?;
        if Instant::now() >= self.deadline || now_seconds()? >= self.expires {
            bail!("local site lifetime expired");
        }
        Ok(())
    }

    fn report(&self) -> serde_json::Value {
        let mut report = self.download.report();
        report["assets"] = self.bundle.asset_count().into();
        report["expires_unix_seconds"] = self.expires.into();
        report["static_only"] = true.into();
        report["https_origin_authenticated"] = false.into();
        report["native_publisher_authenticated"] = true.into();
        report["automatic_browser_open"] = false.into();
        report
    }
}

#[derive(Default)]
struct Outcome {
    reason: &'static str,
    completed: u64,
    bytes: u64,
}

async fn serve(
    listener: &TcpListener,
    site: &Arc<Site>,
    tasks: &mut JoinSet<Result<u64>>,
    interrupt: &mut Signal,
    terminate: &mut Signal,
) -> Result<Outcome> {
    let mut accepted = 0;
    let mut outcome = Outcome::default();
    let mut clock_check = tokio::time::interval(Duration::from_secs(1));
    outcome.reason = loop {
        if site.check_live().is_err() {
            break "expired";
        }
        if accepted == MAX_REQUESTS && tasks.is_empty() {
            break "request_limit";
        }
        tokio::select! {
            _ = interrupt.recv() => break "interrupted",
            _ = terminate.recv() => break "terminated",
            () = sleep_until(site.deadline) => break "expired",
            _ = clock_check.tick() => {},
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(Ok(bytes))) = result {
                    outcome.completed += 1;
                    outcome.bytes += bytes;
                }
            },
            incoming = listener.accept(), if tasks.len() < MAX_CONCURRENT && accepted < MAX_REQUESTS => {
                let (stream, address) = incoming?;
                accepted += 1;
                if address.ip().is_loopback() {
                    tasks.spawn(response(stream, Arc::clone(site)));
                }
            },
        }
    };
    Ok(outcome)
}

async fn response(mut stream: TcpStream, site: Arc<Site>) -> Result<u64> {
    let deadline = site.deadline.min(Instant::now() + Duration::from_secs(30));
    timeout_at(
        deadline,
        http::serve(&mut stream, &site.bundle, &site.host, deadline, || {
            site.check_live()
        }),
    )
    .await
    .context("site response exceeded its bounded lifetime")?
}

fn emit(report: &serde_json::Value) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, report)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
